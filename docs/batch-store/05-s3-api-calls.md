# S3 API Call Reference

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

This document exhaustively enumerates every S3 API call made by every actor in the system, for every possible interaction. No call is omitted.

---

## 1. S3 API Operations Used

The entire system uses exactly **6 distinct S3 API operations**:

| # | Operation | HTTP Verb | Purpose |
|---|-----------|-----------|---------|
| 1 | `HeadObject` | `HEAD /{key}` | Check object existence, get size/ETag without downloading body |
| 2 | `GetObject` | `GET /{key}` | Download object body |
| 3 | `PutObject` | `PUT /{key}` | Upload object (up to 5 GB single-part) |
| 4 | `CreateMultipartUpload` | `POST /{key}?uploads` | Initiate multipart upload for large objects |
| 5 | `UploadPart` | `PUT /{key}?partNumber={n}&uploadId={id}` | Upload one part of a multipart upload |
| 6 | `CompleteMultipartUpload` | `POST /{key}?uploadId={id}` | Finalize multipart upload |
| 7 | `DeleteObject` | `DELETE /{key}` | Delete a single object |
| 8 | `ListObjectsV2` | `GET /?list-type=2&prefix={p}&delimiter={d}` | List objects/prefixes under a key prefix |

No other S3 operations are used. No S3 Select, no Batch Operations, no lifecycle policies, no S3 Inventory, no object tagging, no ACL operations, no bucket operations.

All operations are Hetzner S3 compatible.

---

## 2. Batch Ingestion: CLI Tool

### 2.1 Pre-Run: Fetch Existing Index for Hybrid Dedup

**When**: `--bucket` is set and the tool uses the hybrid dedup strategy (download all index shards before processing).

| Step | S3 Operation | Key Pattern | Count | Purpose |
|------|-------------|-------------|-------|---------|
| 1 | `ListObjectsV2` | `Prefix=<P>/index/sha256/`, paginated | 1-256 calls (1000 keys/page, 65536 max shards) | Discover all existing index shards |
| 2 | `GetObject` | `<P>/index/sha256/<ab>/<cd>.idx` for each discovered shard | 0-65,536 calls | Download each shard for in-memory lookup |

**Typical**: For a bucket with 1M files, there are ~15,000 non-empty shards. At 1000 keys/page, that's **15 ListObjectsV2 + 15,000 GetObject = 15,015 calls**.

**This step is optional.** If `--bucket` is not set, no pre-run S3 calls are made.

### 2.2 Per-File: Remote Dedup Check

**When**: `--bucket` is set and using per-file dedup (not hybrid).

| Step | S3 Operation | Key | Count per file | Purpose |
|------|-------------|-----|----------------|---------|
| 1 | `HeadObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | 1 | Check if binary already exists in S3 |

**Response interpretation**:
- `200 OK`: File exists. Skip classification. Record as duplicate.
- `404 Not Found`: File is new. Proceed with classification.
- `403 Forbidden` / `5xx`: Log warning, assume new, proceed.

### 2.3 Per-File: No S3 Calls During Classification

Classification is entirely local. Zero S3 calls during the hash, classify, and staging-write phases.

### 2.4 Sync Phase: rclone/s3cmd Upload

After the batch run completes, `rclone sync` uploads the staging directory. For each file in staging:

#### New Binary Object

| Step | S3 Operation | Key | Condition |
|------|-------------|-----|-----------|
| 1a | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | File <= 5 GB and rclone uses single-part |
| 1b | `CreateMultipartUpload` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | File > 5 MB (rclone default cutoff) |
| 1c | `UploadPart` × N | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | One per 5 MB chunk |
| 1d | `CompleteMultipartUpload` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Finalize |

**Calls per binary**: 1 (`PutObject`) for files <= 5 MB, or 2+N for larger files (1 Create + N UploadPart + 1 Complete).

#### Metadata Sidecar

| Step | S3 Operation | Key |
|------|-------------|-----|
| 2 | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` |

Always 1 call (metadata is always small).

#### View Ref File

| Step | S3 Operation | Key |
|------|-------------|-----|
| 3 | `PutObject` | `<P>/views/classified/fmt=<f>/isa=<i>/bits=<b>/endian=<e>/<ab>/<cd>/<hash>__<name>.ref` |
| or | `PutObject` | `<P>/views/ambiguous/reason=<r>/fmt=<f>/<ab>/<cd>/<hash>__<name>.ref` |

Always 1 call (ref files are ~300-500 bytes).

#### Ledger Segments

| Step | S3 Operation | Key |
|------|-------------|-----|
| 4a | `PutObject` | `<P>/ledgers/global/<run_id>/<seq>.jsonl.zst` |
| 4b | `PutObject` | `<P>/ledgers/isa=<isa>/<run_id>/<seq>.jsonl.zst` |

Per-run total: number of global segments + number of ISA segments. For 1M files with 50K lines/segment: ~20 global segments + ~20-100 ISA segments = **~40-120 PutObject calls**.

#### Index Shards

| Step | S3 Operation | Key |
|------|-------------|-----|
| 5 | `PutObject` | `<P>/index/sha256/<ab>/<cd>.idx` |

One per shard touched. For 1M files: ~15,000-48,000 shards updated = **15,000-48,000 PutObject calls**.

#### Run Manifest

| Step | S3 Operation | Key |
|------|-------------|-----|
| 6 | `PutObject` | `<P>/runs/<run_id>.json` |

Always 1 call.

#### Stats File

| Step | S3 Operation | Key |
|------|-------------|-----|
| 7a | `GetObject` | `<P>/stats/current.json` | Fetch existing stats for merge (404 = new) |
| 7b | `PutObject` | `<P>/stats/current.json` | Write updated stats |

Always 2 calls (1 read + 1 write).

#### rclone Existence Checks

rclone performs `HeadObject` or `ListObjectsV2` before uploading to determine if objects are new/changed:

| Step | S3 Operation | Key | Count |
|------|-------------|-----|-------|
| 8 | `HeadObject` or `ListObjectsV2` | Various | 1 per file in staging |

### 2.5 Summary: Total S3 Calls for Batch Ingestion of N Files

| Phase | Calls | Notes |
|-------|-------|-------|
| Pre-run index download (optional) | ~15 + 15,000 | Hybrid dedup only |
| Per-file dedup check (optional) | N × 1 HeadObject | Remote dedup only |
| Classification | 0 | Entirely local |
| Sync: binary objects | N × 1 PutObject (or multipart) | |
| Sync: metadata sidecars | N × 1 PutObject | |
| Sync: view ref files | N × 1 PutObject | |
| Sync: ledger segments | ~40-120 PutObject | |
| Sync: index shards | ~15,000-48,000 PutObject | |
| Sync: run manifest | 1 PutObject | |
| Sync: stats | 1 GetObject + 1 PutObject | |
| Sync: rclone checks | ~N × 1 HeadObject | |

**Grand total for 1M files (no remote dedup)**: ~3,000,000 PutObject + ~1,000,000 HeadObject (rclone checks) + ~50,000 PutObject (shards/ledgers) + 2 (stats) + 1 (manifest) = **~4,050,003 S3 operations**.

**Cost estimate at Hetzner**: S3 PUT/HEAD requests are typically $0.005/1000 requests. 4M requests = **~$20**.

---

## 3. Web UI: Browse Classified Files

All S3 calls are made by the backend API server on behalf of the browser. The browser never contacts S3 directly.

### 3.1 List All Formats (Top-Level Browse)

**User action**: Opens the classified files page.

| # | S3 Operation | Parameters | Response |
|---|-------------|------------|----------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/`, `Delimiter=/`, `MaxKeys=1000` | `CommonPrefixes`: `["fmt=elf/", "fmt=pe/", "fmt=raw/", ...]` |

**Total: 1 call.** Unlikely to paginate (there are ~50 format slugs, well under 1000).

### 3.2 List ISAs Within a Format

**User action**: Clicks on a format (e.g., "ELF").

| # | S3 Operation | Parameters | Response |
|---|-------------|------------|----------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/fmt=elf/`, `Delimiter=/`, `MaxKeys=1000` | `CommonPrefixes`: `["isa=aarch64/", "isa=x86_64/", "isa=arm/", ...]` |

**Total: 1 call.** At most ~60 ISA slugs.

### 3.3 List Bitwidths Within Format + ISA

**User action**: Clicks on an ISA (e.g., "aarch64").

| # | S3 Operation | Parameters | Response |
|---|-------------|------------|----------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/fmt=elf/isa=aarch64/`, `Delimiter=/`, `MaxKeys=1000` | `CommonPrefixes`: `["bits=32/", "bits=64/"]` |

**Total: 1 call.** At most ~5 bitwidth values.

### 3.4 List Endianness Within Format + ISA + Bitwidth

**User action**: Clicks on a bitwidth (e.g., "64-bit").

| # | S3 Operation | Parameters | Response |
|---|-------------|------------|----------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/fmt=elf/isa=aarch64/bits=64/`, `Delimiter=/`, `MaxKeys=1000` | `CommonPrefixes`: `["endian=le/", "endian=be/"]` |

**Total: 1 call.** At most 3 endianness values.

### 3.5 List Files (Leaf Level)

**User action**: Clicks on endianness (e.g., "little-endian") to see file listing.

| # | S3 Operation | Parameters | Response |
|---|-------------|------------|----------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/`, `MaxKeys=100`, optional `ContinuationToken` | `Contents`: list of `.ref` keys |

**Total: 1 call per page.** Pages of 100 items. For a leaf with 10,000 files: 100 calls to paginate through all.

**Optimization**: The backend extracts the original filename and file size from the `.ref` key name and the `Size` field in the ListObjectsV2 response, so no additional calls are needed to render the file list.

### 3.6 Get File Details

**User action**: Clicks on a specific file in the listing.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/<ab>/<cd>/<hash>__<name>.ref` | Get the ref pointer (hash, object key, meta key) |
| 2 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Get full classification metadata |

**Total: 2 calls.** The ref file tells us where to find the metadata.

**Optimization**: If the backend caches ref → meta key mappings (LRU cache, 10K entries), the first `GetObject` can be skipped on cache hit, reducing to 1 call.

### 3.7 Download Binary

**User action**: Clicks "Download" on a file detail view.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Stream binary to browser |

**Total: 1 call.** The backend streams the response body directly to the browser with appropriate `Content-Disposition: attachment; filename="<original_name>"` and `Content-Length` headers.

For large files, the backend may use `Range` headers on `GetObject` for chunked streaming, but this is still logically 1 operation (potentially multiple HTTP requests at the S3 level if range-splitting).

### 3.8 Browse Ambiguous Files

Identical pattern to classified files, but rooted at `views/ambiguous/`:

| User Action | S3 Call |
|-------------|---------|
| List reasons | `ListObjectsV2(Prefix=<P>/views/ambiguous/, Delimiter=/)` → 1 call |
| List formats in reason | `ListObjectsV2(Prefix=<P>/views/ambiguous/reason=low_conf/, Delimiter=/)` → 1 call |
| List files | `ListObjectsV2(Prefix=<P>/views/ambiguous/reason=low_conf/fmt=raw/, MaxKeys=100)` → 1 call/page |
| Get file details | `GetObject` (ref) + `GetObject` (meta) → 2 calls |
| Download binary | `GetObject` (bin) → 1 call |

---

## 4. Web UI: Drag-and-Drop Upload

**User action**: Drags a file onto the upload zone in the browser.

### 4.1 New File (Not in Store)

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `HeadObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Dedup check → 404 (not found) |
| 2 | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Upload binary |
| 3 | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Upload metadata |
| 4 | `PutObject` | `<P>/views/classified/.../<hash>__<name>.ref` or `<P>/views/ambiguous/.../<hash>__<name>.ref` | Create view entry |
| 5 | `GetObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Fetch existing index shard for merge |
| 6 | `PutObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Write updated index shard |
| 7 | `GetObject` | `<P>/ledgers/global/online/<date>.jsonl` | Fetch existing ledger for append (optional batching) |
| 8 | `PutObject` | `<P>/ledgers/global/online/<date>.jsonl` | Write appended ledger |
| 9 | `PutObject` | `<P>/ledgers/isa=<isa>/online/<date>.jsonl` | Write ISA-specific ledger entry |

**Total: 1 HeadObject + 2 GetObject + 5 PutObject = 8 calls.**

**With batching/debouncing** (flush ledger/index every 5 seconds or every 100 files):
- Calls 5-9 are amortized across multiple uploads
- Effective per-file cost: **1 HeadObject + 3 PutObject = 4 calls**

For large binaries (>5 MB), call #2 becomes multipart: `CreateMultipartUpload` + N × `UploadPart` + `CompleteMultipartUpload` = 2+N calls instead of 1.

### 4.2 Duplicate File (Already in Store)

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `HeadObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Dedup check → 200 (exists) |
| 2 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Fetch existing metadata to return to browser |

**Total: 1 HeadObject + 1 GetObject = 2 calls.**

Optionally, if the file was uploaded with a new original name, the backend may update the metadata sidecar to append the new name to `names.original_names`:

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 3 | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Update with new original name |

**Total with name update: 3 calls.**

---

## 5. Search by SHA-256 Hash

**User action**: Enters a SHA-256 hash in the search box.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `HeadObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Existence check |
| 2 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Fetch metadata (if exists) |

**Total: 2 calls** (or 1 if hash not found — HeadObject returns 404, stop).

**Key insight**: No index lookup required. The S3 key is deterministically computable from the hash. This is O(1) constant time regardless of corpus size.

---

## 6. Search by ISA (List All Files for an ISA)

### 6.1 Via View Tree (Small ISA Populations)

For ISAs with relatively few files (<10,000), paginate through the view tree:

| # | S3 Operation | Parameters | Purpose |
|---|-------------|------------|---------|
| 1 | `ListObjectsV2` | `Prefix=<P>/views/classified/`, `Delimiter=/` | Get all format prefixes |
| 2 | For each format: `ListObjectsV2` | `Prefix=<P>/views/classified/fmt=<f>/isa=<target>/`, recursive (no delimiter) | Get all .ref files for target ISA in this format |

**Total: 1 + F calls**, where F is the number of format slugs that contain the target ISA. Typically 1-5 formats per ISA.

### 6.2 Via ISA-Specific Ledger (Large ISA Populations)

For ISAs with many files (>10,000), or for bulk export, use the ledger:

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `ListObjectsV2` | `Prefix=<P>/ledgers/isa=<target>/`, `Delimiter=/` | List all run IDs that contributed files for this ISA |
| 2 | For each run: `ListObjectsV2` | `Prefix=<P>/ledgers/isa=<target>/<run_id>/` | List ledger segments |
| 3 | For each segment: `GetObject` | `<P>/ledgers/isa=<target>/<run_id>/<seq>.jsonl.zst` | Download and decompress |

**Total**: Depends on number of runs and segments. For 100K files across 5 runs with 2 segments each: **1 + 5 + 10 = 16 calls** to enumerate all 100K files.

This is dramatically more efficient than paginating ListObjectsV2 through view refs (which would require 100K/1000 = 100 paginated calls, each with longer latency).

---

## 7. Global Enumeration (List All Files)

### 7.1 Via Global Ledger

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `ListObjectsV2` | `Prefix=<P>/ledgers/global/`, `Delimiter=/` | List all run IDs |
| 2 | For each run: `ListObjectsV2` | `Prefix=<P>/ledgers/global/<run_id>/` | List segments |
| 3 | For each segment: `GetObject` | `<P>/ledgers/global/<run_id>/<seq>.jsonl.zst` | Download |

### 7.2 Via Index Shards

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `ListObjectsV2` | `Prefix=<P>/index/sha256/`, paginated | List all shard files |
| 2 | For each shard: `GetObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Download and parse |

At 1M files: ~15,000 shards, 15 paginated list calls + 15,000 GetObject = **15,015 calls**.

The ledger approach is more efficient for sequential enumeration. The index approach is more efficient for random-access lookups.

---

## 8. Delete a File

**User action**: Clicks "Delete" on a file detail view.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Read metadata to find view_key |
| 2 | `DeleteObject` | `<P>/views/classified/.../<hash>__<name>.ref` or `<P>/views/ambiguous/.../<hash>__<name>.ref` | Delete view ref |
| 3 | `DeleteObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Delete metadata |
| 4 | `DeleteObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Delete binary |
| 5 | `GetObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Fetch index shard |
| 6 | `PutObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Write updated shard (line removed) |
| 7 | `PutObject` | `<P>/ledgers/global/online/<date>.jsonl` | Append delete event to ledger |
| 8 | `PutObject` | `<P>/ledgers/isa=<isa>/online/<date>.jsonl` | Append delete event to ISA ledger |

**Total: 2 GetObject + 3 DeleteObject + 3 PutObject = 8 calls.**

With ledger batching: **2 GetObject + 3 DeleteObject + 1 PutObject = 6 calls.**

---

## 9. Reclassify a File

**User action**: Clicks "Reclassify" on a file detail view, or triggered by a batch reclassification run.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` | Download binary for re-classification |
| 2 | *none (CPU)* | — | Run classifier on downloaded binary |
| 3 | `GetObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Read old metadata (to get old view_key and update history) |
| 4 | `DeleteObject` | Old `<P>/views/classified/...` or `<P>/views/ambiguous/...` | Delete old view ref |
| 5 | `PutObject` | `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` | Write updated metadata (new classification, incremented reclassified_count, appended previous_classifications) |
| 6 | `PutObject` | New `<P>/views/classified/...` or `<P>/views/ambiguous/...` | Create new view ref |
| 7 | `GetObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Fetch index shard |
| 8 | `PutObject` | `<P>/index/sha256/<ab>/<cd>.idx` | Update shard entry |
| 9 | `PutObject` | `<P>/ledgers/global/online/<date>.jsonl` | Append reclassify event |
| 10 | `PutObject` | `<P>/ledgers/isa=<isa>/online/<date>.jsonl` | Append to new ISA ledger |

**Total: 3 GetObject + 1 DeleteObject + 4 PutObject = 8 calls.**

If the classification result is unchanged (same ISA/format/bits/endian), steps 4 and 6 can be skipped (the ref key doesn't change). Step 5 still updates metadata (new confidence, timestamp). **Total: 3 GetObject + 2 PutObject = 5 calls.**

---

## 10. Dashboard / Statistics

**User action**: Loads the dashboard page.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/stats/current.json` | Fetch aggregate statistics |

**Total: 1 call.**

If the dashboard also shows recent runs:

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 2 | `ListObjectsV2` | `Prefix=<P>/runs/`, `MaxKeys=20` | List recent run manifests |
| 3 | `GetObject` × N | `<P>/runs/<run_id>.json` for each | Fetch run details |

**Total: 1 + 1 + N calls** (N = number of runs to display, typically 10-20).

---

## 11. View Run Details

**User action**: Clicks on a specific run in the dashboard.

| # | S3 Operation | Key | Purpose |
|---|-------------|-----|---------|
| 1 | `GetObject` | `<P>/runs/<run_id>.json` | Fetch run manifest |

**Total: 1 call.**

---

## 12. S3 Call Cost Summary

Assuming Hetzner S3 pricing (~$0.005 per 1000 requests for all operation types):

| Scenario | Calls | Estimated Cost |
|----------|-------|---------------|
| Batch ingest 1M files (no dedup) | ~4M | ~$20 |
| Batch ingest 1M files (with remote dedup, 50% hit) | ~2.5M | ~$12.50 |
| Sync upload (rclone) | ~3M | ~$15 |
| Browse to file detail (4 levels + detail) | 6 | <$0.001 |
| Search by hash | 2 | <$0.001 |
| Upload 1 file (web) | 4-8 | <$0.001 |
| Delete 1 file | 6-8 | <$0.001 |
| Reclassify 1 file | 5-8 | <$0.001 |
| Dashboard load | 1-20 | <$0.001 |
| Enumerate all files for 1 ISA (ledger) | 10-50 | <$0.001 |

---

## 13. Error Handling for S3 Calls

| S3 Error | HTTP Status | System Behavior |
|----------|------------|-----------------|
| `NoSuchKey` | 404 | Expected for dedup misses and new shards. Not an error. |
| `AccessDenied` | 403 | Fatal for required operations. Log and abort/retry. |
| `SlowDown` | 503 | Exponential backoff with jitter. Retry up to 5 times. |
| `InternalError` | 500 | Retry with exponential backoff. |
| `ServiceUnavailable` | 503 | Retry with exponential backoff. |
| `RequestTimeout` | 408 | Retry immediately once, then backoff. |
| Network timeout | — | Retry with backoff. Report as transient error. |

All S3 operations implement:
- **Retry**: Up to 5 attempts with exponential backoff (100ms, 200ms, 400ms, 800ms, 1600ms) plus random jitter (0-50ms).
- **Timeout**: 30 seconds for HeadObject/PutObject/DeleteObject, 120 seconds for GetObject (large files), 60 seconds for ListObjectsV2.
- **Idempotency**: All operations are safe to retry (PUT is idempotent by key, DELETE is idempotent, HEAD and GET are read-only, LIST is read-only).
