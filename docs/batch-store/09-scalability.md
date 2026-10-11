# Scalability Analysis

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Design Targets

| Dimension | Target | Notes |
|-----------|--------|-------|
| Total files | 10,000,000+ | Must scale beyond 10M without degradation |
| Total ISAs | 200+ | Already support ~60, expect growth |
| Total formats | 100+ | Currently ~50, expect growth |
| Single batch run | 1,000,000 files | Must complete in reasonable time (<4 hours) |
| S3 bucket objects | 50,000,000+ | 10M files × ~5 objects each (bin, meta, ref, index amortized, ledger amortized) |
| Concurrent web users | 50+ | Browsing, searching, uploading simultaneously |
| Average file size | 100 KB - 10 MB | Firmware images, executables, object files |

---

## 2. Sharding Strategy

### 2.1 Hash Prefix Fanout

All content-addressed paths use a 2-level hex prefix fanout:

```
sha256/<ab>/<cd>/<full_hash>.{bin,meta.json}
```

Where `<ab>` = first 2 hex chars (256 buckets) and `<cd>` = next 2 hex chars (256 buckets per `<ab>`).

**Total shards**: 256 × 256 = **65,536**.

| Total Files | Avg Files per Shard | Max Files per Shard (99th percentile) |
|-------------|--------------------|-----------------------------------------|
| 100,000 | 1.5 | ~5 |
| 1,000,000 | 15 | ~30 |
| 10,000,000 | 153 | ~200 |
| 100,000,000 | 1,526 | ~1,700 |

At 10M files, each shard contains ~153 objects. S3's `ListObjectsV2` returns up to 1000 keys per call, so listing a single shard requires 1 call. Even at 100M files, each shard has ~1,700 objects — still manageable in 2 paginated calls.

### 2.2 Why 2 Levels, Not 1 or 3?

| Levels | Shards | Files per Shard (10M total) | Directory Objects |
|--------|--------|-----------------------------|-------------------|
| 1 (`<ab>/`) | 256 | 39,062 | 256 |
| 2 (`<ab>/<cd>/`) | 65,536 | 153 | 65,792 |
| 3 (`<ab>/<cd>/<ef>/`) | 16,777,216 | 0.6 (mostly empty) | 16,843,008 |

- **1 level**: Too few shards. At 10M files, 39K files per shard makes listing slow.
- **2 levels**: Sweet spot. 153 files per shard at 10M. Small enough for single-call listing.
- **3 levels**: Too many shards. Most shards are empty at typical corpus sizes, and the intermediate directories waste space in the S3 namespace.

### 2.3 View Tree Cardinality

The classified view tree has 4 levels of dimensions:

```
fmt=<F>/isa=<I>/bits=<B>/endian=<E>/
```

| Level | Max Values | Typical Values |
|-------|-----------|----------------|
| Format | ~55 | 10-20 active |
| ISA | ~60 | 20-40 active |
| Bitwidth | 5 (8, 16, 32, 64, 128) | 2-3 per ISA |
| Endianness | 3 (le, be, bi) | 1-2 per ISA |

**Maximum leaf directories**: 55 × 60 × 5 × 3 = 49,500. But most combinations don't exist (e.g., `fmt=elf/isa=jvm` is impossible). In practice: **200-500 active leaf directories**.

Within each leaf, files are sharded by `<ab>/<cd>/`, so no single leaf directory has more than a few hundred files without the fanout absorbing it.

---

## 3. ListObjectsV2 Performance

S3's `ListObjectsV2` is the primary query mechanism. Its performance characteristics:

| Aspect | Value |
|--------|-------|
| Latency per call | 50-200ms (Hetzner) |
| Max keys per response | 1000 |
| Prefix filtering | Server-side (no client filtering needed) |
| Delimiter-based "directory" listing | Supported (returns CommonPrefixes) |
| Pagination | Via ContinuationToken (stateless) |
| Cost | ~$0.005 per 1000 requests |

### 3.1 Browse Performance

Browsing through the view tree requires 4 ListObjectsV2 calls (one per level) + 1 call for the file listing page. Total: **5 calls, ~250ms-1000ms latency**.

This is independent of corpus size. Whether you have 1000 or 10M files, browsing to a leaf directory takes the same number of calls.

### 3.2 File Listing Performance

Within a leaf directory, files are listed via prefix scan. With fanout sharding, the list call returns shard prefixes (`<ab>/<cd>/`), not individual files. To list actual files, the call uses no delimiter:

```
ListObjectsV2(Prefix="views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/", MaxKeys=100)
```

This returns `.ref` files across all shards, sorted lexicographically. Pagination works via ContinuationToken.

At 100K AArch64 ELF files: 1000 pages of 100 files each. Each page is 1 ListObjectsV2 call.

### 3.3 Full ISA Enumeration Performance

To list all files for a given ISA across all formats:

**Via view tree**: Must paginate across all format leaves. For an ISA present in 5 formats, each with 1 bitwidth and 1 endianness: 5 leaf directories, each potentially paginated. At 100K total files: ~1000 paginated calls.

**Via ISA ledger**: Download all ledger segments for the ISA. At 50K lines/segment, 100K files = 2 segments = **2 GetObject calls** + decompress. This is dramatically faster.

**Recommendation**: Use ledger for bulk enumeration, view tree for interactive browsing.

---

## 4. Ledger Rotation and Sizing

### 4.1 Segment Rotation

Each ledger segment is limited to:
- **50,000 lines** (entries)
- **10 MB uncompressed**

Whichever limit is hit first triggers rotation to a new segment.

### 4.2 Typical Segment Sizes

| Average entry length | Lines per 10 MB | Compressed size (zstd) |
|---------------------|-----------------|----------------------|
| 200 bytes | 50,000 | ~2.0 MB |
| 400 bytes | 25,000 | ~2.5 MB |
| 600 bytes | 16,666 | ~3.0 MB |

Typical entries are ~250-350 bytes (JSON with short paths). So segments hit the 50K line limit before the 10 MB size limit.

### 4.3 Total Ledger Size

| Total Files | Segments (global) | Total Compressed (global) | Total Compressed (all ISA) |
|------------|-------------------|--------------------------|---------------------------|
| 100,000 | 2 | ~4 MB | ~4 MB (overlap) |
| 1,000,000 | 20 | ~40 MB | ~40 MB |
| 10,000,000 | 200 | ~400 MB | ~400 MB |

Global + ISA ledgers approximately double the storage because each entry appears in both. Total ledger storage at 10M files: **~800 MB**.

### 4.4 Ledger Query Performance

To scan the full global ledger at 10M files:
- 200 segments × 1 GetObject each = **200 calls**
- Download 400 MB compressed → decompress to ~1.6 GB
- Parse 10M JSON lines

This is a bulk operation, not interactive. For interactive queries, use the view tree or index shards.

---

## 5. Index Shard Sizing

### 5.1 Per-Entry Size

Each index shard entry is ~200-250 bytes (TSV with full hash, keys, and classification summary).

### 5.2 Total Index Size

| Total Files | Entries per Shard | Shard Size | Total Index Size |
|------------|-------------------|------------|-----------------|
| 100,000 | ~2 | ~400 B | ~15 MB |
| 1,000,000 | ~15 | ~3 KB | ~200 MB |
| 10,000,000 | ~153 | ~30 KB | ~2 GB |
| 100,000,000 | ~1,526 | ~300 KB | ~20 GB |

### 5.3 Index Read Performance

To check if a specific hash exists:
1. Compute shard key from hash: O(1)
2. Download shard: 1 GetObject, 3-300 KB depending on corpus size
3. Binary search within shard (entries are sorted): O(log n)

Total: **1 S3 call, <200ms**.

But for single-hash lookups, `HeadObject` on the binary key is faster (no download, just a 200/404 response). The index is primarily useful for bulk operations (download all shards, build in-memory map).

### 5.4 Index Update Performance

Updating an index shard is a read-modify-write:
1. GetObject the existing shard
2. Parse, insert/remove entries, re-sort
3. PutObject the updated shard

For batch ingestion, this happens once per touched shard at the end of the run. With 1M files across 65K shards, only ~15K-48K shards are touched (depending on hash distribution).

---

## 6. Object Storage Costs

### 6.1 Storage Costs (Hetzner S3)

Hetzner Object Storage pricing (approximate):
- Storage: ~$0.0065/GB/month
- PUT/POST requests: ~$0.005/1000
- GET/HEAD requests: ~$0.004/1000
- Data transfer out: Free (Hetzner, unlike AWS, typically doesn't charge egress within their network)

### 6.2 Cost Projections

| Corpus Size | Binary Storage | Metadata + Views | Index + Ledger | Monthly Storage | Monthly Requests (est.) |
|------------|---------------|-----------------|---------------|----------------|----------------------|
| 100K files (50 GB) | 50 GB | 0.5 GB | 0.02 GB | $0.33 | $0.05 |
| 1M files (500 GB) | 500 GB | 5 GB | 0.25 GB | $3.28 | $0.20 |
| 10M files (5 TB) | 5,000 GB | 50 GB | 2.5 GB | $32.84 | $1.00 |
| 100M files (50 TB) | 50,000 GB | 500 GB | 25 GB | $328.41 | $5.00 |

### 6.3 Deduplication Savings

If the corpus has 20% duplicate files (common for firmware archives that include many copies of shared libraries):
- 1M files → 800K unique → 200K × avg 500 KB = 100 GB saved
- At $0.0065/GB: **$0.65/month saved**

Dedup savings scale linearly with duplicate rate and average file size.

---

## 7. Concurrent Access

### 7.1 Read Concurrency

S3 handles unlimited concurrent reads natively. No coordination required.

### 7.2 Write Concurrency

S3 has last-writer-wins semantics for `PutObject`. This affects:

| Resource | Concurrency Risk | Mitigation |
|----------|-----------------|------------|
| Binary objects | None (CAS: same hash = same content) | Idempotent by design |
| Metadata sidecars | Low (only reclassification overwrites) | Backend serializes reclassify requests per hash |
| View refs | None (PUT is idempotent for same key) | Idempotent |
| Index shards | Medium (read-modify-write) | Backend serializes shard updates per shard key |
| Ledger segments | None (write-once, unique keys per run) | No conflict |
| Stats file | Low (read-modify-write) | Backend serializes stats updates |
| Run manifests | None (unique key per run) | No conflict |

### 7.3 Batch + Web Concurrency

If a batch run is uploading (via rclone) while the web backend is handling user uploads:
- Binary objects: No conflict (CAS)
- Index shards: rclone writes complete new shards; web backend may overwrite them. **Risk**: web backend's shard update may be overwritten by rclone's version (or vice versa). **Mitigation**: Avoid running rclone sync while the web backend is handling uploads. Or: use ETags for compare-and-swap on shard updates (if Hetzner supports conditional PUTs).
- Stats: Same risk as index shards. **Mitigation**: Same — serialize or accept eventual consistency.

**Recommendation**: Run batch ingestion and web uploads sequentially, not concurrently, for index/stats consistency. Binary and metadata objects are safe concurrently.

---

## 8. Performance Bottlenecks

### 8.1 Batch Ingestion

| Bottleneck | Impact | Mitigation |
|-----------|--------|------------|
| Disk I/O (reading input files) | Limits hasher throughput | Memory-map files, use NVMe storage |
| CPU (classification) | Limits classifier throughput | `-j` workers, split hash/classify pools |
| Disk I/O (writing staging) | Limits writer throughput | Single writer thread, sequential writes, NVMe |
| S3 dedup HeadObject | Adds ~100ms latency per file | Use hybrid dedup (batch download index), or skip dedup for first run |

### 8.2 Web UI Browsing

| Bottleneck | Impact | Mitigation |
|-----------|--------|------------|
| ListObjectsV2 latency | ~100-200ms per level | Max 4-5 levels, each is 1 call |
| Ref file batch fetch | 100 GetObject per page | Parallelize with 20-50 concurrent requests |
| Large binary download | Stream latency | Proxy directly from S3, no buffering |

### 8.3 Web Upload

| Bottleneck | Impact | Mitigation |
|-----------|--------|------------|
| Upload bandwidth (browser → backend) | Limits throughput for large files | Show progress bar, chunked upload |
| Classification time | 50-500ms per file depending on size | Acceptable for interactive use |
| S3 PutObject latency | ~100ms per write × 3 writes | Parallelize independent PUTs |

---

## 9. Failure Modes and Recovery

### 9.1 S3 Unavailable

If S3 becomes unavailable:
- **Batch ingestion**: Staging continues locally. Sync retried later.
- **Web browsing**: Returns 503 to users. Auto-retry with backoff.
- **Web upload**: Returns 503. User retries manually.

### 9.2 Corrupted Index Shard

If an index shard is corrupted or missing:
- **Detection**: Parse error when reading shard
- **Recovery**: Rebuild shard by scanning `objects/sha256/<ab>/<cd>/` for all `.meta.json` files in that shard prefix and regenerating the TSV.

### 9.3 Missing Metadata Sidecar

If a `.meta.json` is missing but the `.bin` exists:
- **Detection**: `GetObject` on meta returns 404 but HeadObject on bin returns 200
- **Recovery**: Reclassify the binary (download, classify, re-upload metadata)

### 9.4 Orphaned View Refs

If a `.ref` file points to a non-existent binary:
- **Detection**: `HeadObject` on binary returns 404 when following the ref
- **Recovery**: Delete the orphaned ref. Run an orphan scan periodically.

### 9.5 Ledger Gap

If a ledger segment is missing:
- **Detection**: Sequence number gap (e.g., `000001.jsonl.zst`, `000003.jsonl.zst`, missing `000002`)
- **Impact**: Partial audit trail. The index and view tree are still correct (they're independently maintained).
- **Recovery**: Accept the gap. Ledgers are informational, not the source of truth for file existence.

---

## 10. Future Scaling Considerations

### 10.1 Beyond 100M Files

At 100M files:
- Index shards: ~300 KB each, 65K shards, 20 GB total. Still manageable.
- View tree: Leaf directories may contain thousands of refs. Consider adding a third level of hash fanout within leaves.
- Ledger: ~4 GB compressed. Consider date-based partitioning in addition to run-based.

### 10.2 Compressed/Tiered Storage

For cold data (old runs, rarely accessed ISAs):
- Move to S3 Glacier/Deep Archive equivalent on Hetzner (if available)
- Or use zstd compression on binary objects (with content-encoding header)
- Or separate "hot" and "cold" prefixes with different storage classes

### 10.3 CDN for Downloads

If download traffic grows:
- Put a CDN (Cloudflare, Hetzner CDN) in front of S3 for binary object downloads
- Cache by S3 key (CAS keys are immutable, perfect for caching)
- Set `Cache-Control: public, max-age=31536000, immutable` on binary objects
