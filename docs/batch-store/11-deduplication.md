# Deduplication

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Content-Addressed Storage Model

Every binary file in the system is stored at a key derived from its SHA-256 hash:

```
objects/sha256/<first_2_hex>/<next_2_hex>/<full_64_hex>.bin
```

This is a Content-Addressed Storage (CAS) model. The fundamental property is: **two files with the same content produce the same hash, and therefore the same key.** This means:

- If the same firmware image appears in 100 different input directories, it is stored **once**.
- If the same ELF binary is ingested in two separate batch runs, the second run detects the duplicate and skips the copy.
- No coordination between runs is needed — the hash is the coordination mechanism.

---

## 2. SHA-256 Properties

### 2.1 Why SHA-256?

| Property | Value | Relevance |
|----------|-------|-----------|
| Hash size | 256 bits (32 bytes, 64 hex chars) | Compact key, fits in a filename |
| Collision resistance | ~2^128 operations for birthday attack | Effectively collision-free for any practical corpus |
| Speed | ~500 MB/s on modern x86 with SHA-NI | Fast enough for multi-GB firmware images |
| Ubiquity | Supported by every language, every OS, every tool | `sha256sum`, `openssl dgst -sha256`, Python `hashlib`, etc. |
| Standard | NIST FIPS 180-4 | Well-understood security properties |

### 2.2 Why Not SHA-1, MD5, or BLAKE3?

| Hash | Status | Why Not |
|------|--------|---------|
| MD5 | Broken (collisions trivial) | Cannot guarantee content identity |
| SHA-1 | Broken (practical collisions demonstrated) | Cannot guarantee content identity |
| BLAKE3 | Fast, modern, safe | Not as widely supported by existing tools. Could be an option with a `--hash-algo` flag in the future. |
| SHA-512 | Safe | Longer keys (128 hex chars) for no practical benefit |

### 2.3 Collision Risk

With SHA-256, the probability of a collision in a corpus of N files is approximately:

```
P(collision) ≈ N² / (2 × 2^256)
```

| Corpus Size | Collision Probability |
|------------|----------------------|
| 1 million | 4.3 × 10^-66 |
| 1 billion | 4.3 × 10^-60 |
| 1 trillion | 4.3 × 10^-54 |

For all practical purposes, SHA-256 collisions **do not occur**. The system does not implement collision detection or handling.

---

## 3. Dedup Check Strategies

The batch ingestion tool supports three strategies for detecting duplicates, selectable by CLI flags.

### 3.1 Strategy 1: No Dedup Check (Default for First Run)

**CLI flags**: (default, no special flags)

**Behavior**: Every file is hashed, classified, and written to staging. If the same file appears twice in the input directory, it will be processed twice, but the second write overwrites the first with identical content (idempotent).

**S3 calls**: 0 per file.

**Use case**: First-time bulk ingestion of a new corpus. No existing data to check against.

**Downside**: Wasted CPU cycles on duplicate files. For corpora with high duplication (>30%), this is inefficient.

### 3.2 Strategy 2: Local Index Dedup (`--skip-existing`)

**CLI flags**: `--skip-existing`

**Behavior**:
1. At startup, load all existing index shards from the staging directory into memory
2. For each file: hash it, check the in-memory index
3. If found: skip classification and write, record as duplicate
4. If not found: classify, write, add to in-memory index

**S3 calls**: 0 per file.

**Memory usage**: ~30-50 bytes per indexed file. At 10M files: ~300-500 MB.

**Use case**: Incremental runs against the same staging directory. The second run skips all files from the first run.

**Downside**: Only checks against local staging, not against what's already in S3. If staging has been cleaned between runs, this doesn't help.

### 3.3 Strategy 3: Remote S3 Dedup (`--bucket`, `--endpoint`)

**CLI flags**: `--bucket my-bucket --endpoint https://s3.hetzner.com`

**Behavior**: For each file, after hashing, issue `HeadObject` against S3 to check if the binary already exists.

**S3 calls**: 1 `HeadObject` per file.

**Latency**: ~50-200ms per file (network round-trip). With 16 parallel hashers, effective throughput: ~80-320 files/sec.

**Use case**: Ingestion against a live S3 bucket. Avoids re-uploading files that are already in S3.

**Downside**: Network latency. For 1M files, this adds 50K-200K seconds of cumulative latency, but parallelism reduces wall-clock time to ~1-3 hours.

### 3.4 Strategy 4: Hybrid — Pre-Download Index, Local Check

**CLI flags**: `--bucket my-bucket --endpoint https://s3.hetzner.com` with `--prefetch-index`

**Behavior**:
1. Before the run: download all index shards from S3 to the staging directory
2. Load index shards into memory
3. For each file: hash it, check the in-memory index (no S3 call per file)
4. If found: skip, record as duplicate
5. If not found: classify, write

**S3 calls**: 15K-65K `GetObject` calls upfront (one per shard), then 0 per file.

**Latency**: ~5-30 minutes upfront for index download (depending on shard count and network), then zero per-file latency.

**Use case**: Large incremental runs where the S3 bucket already has millions of files. The upfront index download is amortized over many files.

**Downside**: Memory usage for the full index (~300-500 MB at 10M files). Download time at startup.

---

## 4. Dedup Decision Matrix

| Scenario | Recommended Strategy | Why |
|----------|---------------------|-----|
| First-ever ingestion | No dedup | Nothing to check against |
| Second run, same staging dir | `--skip-existing` | Free, fast, local |
| Second run, clean staging dir | `--bucket` (remote) | Must check S3 |
| Large incremental run (>100K files) | Hybrid (`--prefetch-index`) | Amortize index download |
| Small incremental run (<1K files) | `--bucket` (remote) | 1K HeadObject calls are fast |
| CI/CD pipeline (automated) | `--skip-existing` + persistent staging | Keep staging between runs |

---

## 5. Duplicate Handling Behavior

When a duplicate is detected (by any strategy), the following happens:

### 5.1 In Batch Ingestion

| Action | Happens? | Details |
|--------|----------|---------|
| Classification | **Skipped** | No CPU wasted |
| Binary write to staging | **Skipped** | File already exists at same key |
| Metadata write | **Skipped** | Existing metadata is retained |
| View ref write | **Skipped** | Existing ref is retained |
| Ledger entry | **Yes** | Recorded with `action: "duplicate"`, `status: "duplicate"` |
| Index shard update | **Skipped** | Entry already exists |
| TUI counter | **Incremented** | "Duplicate" counter goes up |
| Run manifest count | **Incremented** | `counts.duplicates` goes up |

### 5.2 In Web Upload

| Action | Happens? | Details |
|--------|----------|---------|
| Classification | **Skipped** | Existing metadata returned immediately |
| Binary upload to S3 | **Skipped** | |
| Metadata update | **Maybe** | If the upload has a new `original_name`, the name is appended to `names.original_names` in the existing metadata |
| Ledger entry | **Yes** | Recorded with `action: "duplicate"` |
| API response | `200 OK` | With `"is_duplicate": true` and existing classification data |

### 5.3 Metadata Name Merging

When a duplicate file is seen with a new original name or source path:

```json
// Before (from first ingestion):
{
  "names": {
    "original_names": ["firmware.bin"],
    "original_paths": ["/data/batch-01/firmware.bin"]
  }
}

// After (second ingestion with different name):
{
  "names": {
    "original_names": ["firmware.bin", "rkos"],
    "original_paths": ["/data/batch-01/firmware.bin", "/data/batch-02/rkos"]
  }
}
```

This name merging is only done in web upload mode (where we have live S3 access). In batch staging mode, the metadata is not updated for duplicates — it would require reading, parsing, modifying, and rewriting the metadata JSON, which is more complex. The name merging can be done during a post-processing step or when the file is next accessed via the API.

---

## 6. Re-Ingestion Semantics

### 6.1 Same File, Same Classifier Version

The file is detected as a duplicate. No changes.

### 6.2 Same File, New Classifier Version

If the user wants to reclassify existing files with an improved classifier:

**Batch reclassification**: Use a future `zrax reclassify` command that:
1. Enumerates all files (or files matching a filter) from the ledger/index
2. Downloads each binary from S3
3. Reclassifies with the new classifier
4. Updates metadata, view ref, ledger, and index

**This is NOT triggered by normal re-ingestion.** Normal ingestion with dedup will skip duplicates regardless of classifier version. Reclassification is an explicit, separate operation.

### 6.3 Same Hash, Different Classification (Bug Fix)

If a classifier bug caused a file to be misclassified, reclassification via the API or batch reclassify command will:
1. Download the binary
2. Reclassify
3. Delete the old view ref (wrong ISA path)
4. Create a new view ref (correct ISA path)
5. Update metadata with new classification and reclassification history

The binary itself is never touched (same hash = same content = same key).

---

## 7. Dedup Statistics

The system tracks deduplication statistics at multiple levels:

### 7.1 Per-Run Statistics (Run Manifest)

```json
{
  "counts": {
    "total_input_files": 1003456,
    "processed": 1003456,
    "duplicates": 10234,
    ...
  },
  "storage": {
    "total_bytes_ingested": 235123456789,
    "total_bytes_stored": 198765432100,
    "bytes_saved_by_dedup": 36358024689
  }
}
```

### 7.2 Global Statistics (Stats File)

The `stats/current.json` includes cumulative dedup statistics.

### 7.3 TUI Display

The batch TUI dashboard shows:
- Duplicate count and percentage in the "Classification Results" section
- Dedup savings (bytes saved) if available

---

## 8. Edge Cases

### 8.1 Zero-Length Files

Files with 0 bytes all have the same SHA-256 hash:
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Handling**: The batch tool skips files smaller than `--min-file-size` (default: 4 bytes). Zero-length files are skipped and counted as `skipped` in the run manifest.

### 8.2 Very Large Files

Files larger than `--max-file-size` (default: 1 GB) are skipped to avoid excessive memory usage and processing time.

### 8.3 Symbolic Links

By default, symbolic links are not followed (`--follow-symlinks` is off). If a symlink points to a file that's already been processed, following it would process the same file twice — the dedup mechanism handles this correctly (same content = same hash = same key), but it wastes hashing time.

### 8.4 Hard Links

Hard links are transparent to the tool. If two directory entries point to the same inode, the file is processed twice (once per directory entry) but deduped on hash.

### 8.5 Concurrent Writes to Same Hash

If two workers somehow hash the same file simultaneously (e.g., same file via different symlinks), both will attempt to write the same staging files. Since writes are atomic (temp + rename) and the content is identical, the last writer wins with correct content. No corruption occurs.
