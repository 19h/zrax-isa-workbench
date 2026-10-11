# Local Staging Directory Specification

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Purpose

The batch ingestion tool writes all output to a local staging directory that is an exact mirror of the S3 key layout. This staging directory can then be uploaded to S3 via `rclone sync`, `s3cmd sync`, or any other S3-compatible sync tool.

This separation of concerns provides:
- **Offline processing**: Classification runs entirely locally without S3 access
- **Inspection before upload**: Operators can verify the staging output before pushing to S3
- **Retry safety**: Failed uploads can be retried without re-processing
- **Incremental sync**: Multiple batch runs can write to the same staging directory, and sync only uploads new/changed files
- **Testing**: The staging directory can be used as a mock S3 for integration testing

---

## 2. Directory Structure

The staging directory mirrors the S3 key layout exactly. Given `--output /staging/run-001 --prefix isa-harvester/v1`:

```
/staging/run-001/
└── isa-harvester/
    └── v1/
        ├── objects/
        │   └── sha256/
        │       ├── 00/
        │       │   ├── 01/
        │       │   │   ├── 0001a2b3c4d5...sha256hex.bin
        │       │   │   └── 0001a2b3c4d5...sha256hex.meta.json
        │       │   ├── 02/
        │       │   │   └── ...
        │       │   └── ff/
        │       │       └── ...
        │       ├── 01/
        │       │   └── ...
        │       └── ff/
        │           └── ff/
        │               └── ...
        │
        ├── views/
        │   ├── classified/
        │   │   ├── fmt=elf/
        │   │   │   ├── isa=aarch64/
        │   │   │   │   └── bits=64/
        │   │   │   │       └── endian=le/
        │   │   │   │           └── a1/
        │   │   │   │               └── b2/
        │   │   │   │                   └── a1b2c3d4...sha256.__rkos.ref
        │   │   │   └── isa=x86_64/
        │   │   │       └── bits=64/
        │   │   │           └── endian=le/
        │   │   │               └── ...
        │   │   ├── fmt=pe/
        │   │   │   └── ...
        │   │   └── fmt=raw/
        │   │       └── ...
        │   │
        │   └── ambiguous/
        │       ├── reason=low_conf/
        │       │   └── fmt=raw/
        │       │       └── ...
        │       └── reason=low_margin/
        │           └── ...
        │
        ├── index/
        │   └── sha256/
        │       ├── 00/
        │       │   ├── 00.idx
        │       │   ├── 01.idx
        │       │   └── ...
        │       ├── 01/
        │       │   └── ...
        │       └── ff/
        │           └── ff.idx
        │
        ├── ledgers/
        │   ├── global/
        │   │   └── 20260302T143022Z-batch-001/
        │   │       ├── 000001.jsonl.zst
        │   │       └── 000002.jsonl.zst
        │   │
        │   ├── isa=aarch64/
        │   │   └── 20260302T143022Z-batch-001/
        │   │       └── 000001.jsonl.zst
        │   │
        │   └── isa=x86_64/
        │       └── 20260302T143022Z-batch-001/
        │           └── 000001.jsonl.zst
        │
        ├── runs/
        │   └── 20260302T143022Z-batch-001.json
        │
        └── stats/
            └── current.json
```

---

## 3. File Creation Semantics

### 3.1 Binary Objects (`objects/sha256/.../*.bin`)

- **Created by**: Writer thread in the batch pipeline
- **Source**: The input file is copied byte-for-byte to the staging path
- **Atomicity**: Written to a temporary file first (`<path>.tmp`), then renamed (`rename()`) to the final path. This ensures partial writes are never visible.
- **Dedup**: If the staging file already exists (from a previous run), the write is skipped entirely. The existing file is guaranteed to have the same content (same hash = same content).

### 3.2 Metadata Sidecars (`objects/sha256/.../*.meta.json`)

- **Created by**: Writer thread
- **Source**: JSON serialization of the classification result
- **Atomicity**: Write to `.tmp`, rename
- **Overwrite**: If the file already exists (from a previous run), it is overwritten with the new classification. This allows reclassification to take effect even in staging.

### 3.3 View Refs (`views/.../*.ref`)

- **Created by**: Writer thread
- **Source**: JSON serialization of the ref pointer
- **Atomicity**: Write to `.tmp`, rename
- **Directory creation**: Intermediate directories are created on-demand with `create_dir_all()`

### 3.4 Index Shards (`index/sha256/<ab>/<cd>.idx`)

- **Created by**: Writer thread during flush (end of run or periodic)
- **Source**: In-memory `BTreeMap` serialized to TSV
- **Merge behavior**: If the shard file already exists (from a previous run or pre-downloaded from S3), the existing entries are loaded, merged with new entries, and the combined set is written back. See Section 5 for merge details.
- **Atomicity**: Write to `.tmp`, rename

### 3.5 Ledger Segments (`ledgers/.../*.jsonl.zst`)

- **Created by**: Writer thread during flush (segment rotation or end of run)
- **Source**: In-memory buffer, zstd-compressed
- **Write-once**: Ledger segments are never overwritten. Each run creates new segments with unique sequence numbers under its own run ID directory.
- **Atomicity**: Write to `.tmp`, rename

### 3.6 Run Manifest (`runs/<run_id>.json`)

- **Created by**: Main thread at run start (status: `running`) and updated at run end (status: `completed` or `failed`)
- **Overwrite**: Yes, overwritten from `running` to `completed`

### 3.7 Stats File (`stats/current.json`)

- **Created by**: Main thread at run end
- **Merge behavior**: If the file exists, it is loaded, merged with new counts, and rewritten. If it doesn't exist, a fresh stats document is created.

---

## 4. Disk Space Requirements

### 4.1 Per-File Overhead

| Component | Size | Notes |
|-----------|------|-------|
| Binary copy | Same as input | 1:1 copy of original file |
| Metadata sidecar | 1-10 KB | JSON with classification details |
| View ref | 300-500 bytes | JSON pointer |
| Index entry | 200-250 bytes | TSV line (amortized in shard file) |
| Ledger entry | 250-400 bytes | JSONL line (compressed ~60-80 bytes) |

**Per-file overhead (excluding binary)**: ~2-11 KB

### 4.2 Total Staging Size

| Input Size | Binary Size | Metadata + Views + Index + Ledger | Total Staging |
|-----------|------------|----------------------------------|---------------|
| 100K files (50 GB) | 50 GB | ~0.5 GB | ~50.5 GB |
| 1M files (500 GB) | 500 GB | ~5 GB | ~505 GB |
| 10M files (5 TB) | 5 TB | ~50 GB | ~5.05 TB |

Staging requires approximately **1% overhead** beyond the input data size.

### 4.3 Inode Consumption

Each file in staging consumes one inode. The inode breakdown per classified file:

| Object | Inodes per File | Notes |
|--------|----------------|-------|
| Binary | 1 | |
| Metadata | 1 | |
| View ref | 1 | |
| Index shard | Amortized: 65,536 total | Shared across all files |
| Ledger segment | Amortized: ~20-200 total | Shared across many files |
| Directories | ~10-15 per file | Hash fanout + view tree |

**Total inodes per file**: ~14-18 (including directories)

For 1M files: ~15M inodes. Ensure the staging filesystem has sufficient inode capacity. ext4 default is 1 inode per 16 KB, which gives ~60M inodes per TB. This is sufficient for typical workloads but may need tuning for many small files on small disks.

**Recommendation**: Use XFS or ext4 with `-N` inode count override for dedicated staging volumes.

---

## 5. Index Shard Merge Strategy

When writing index shards, the tool must handle the case where the shard already exists (from a previous run or downloaded from S3).

### 5.1 Merge Algorithm

```
function merge_shard(shard_path, new_entries):
    if file_exists(shard_path):
        existing = parse_tsv(read_file(shard_path))
    else:
        existing = empty_map

    for entry in new_entries:
        existing[entry.sha256] = entry  // insert or update

    sorted = sort_by_key(existing)
    write_tsv(shard_path + ".tmp", sorted)
    rename(shard_path + ".tmp", shard_path)
```

### 5.2 Conflict Resolution

If the same SHA-256 hash exists in both the existing shard and the new entries (e.g., reclassification), the new entry wins (overwrite). This is correct because:
- The binary is the same (same hash = same content)
- The classification may have changed (new classifier version)
- The new entry has the latest classification

### 5.3 Delete Handling

To delete an entry from a shard, the tool reads the shard, removes the entry, and writes back. This is only needed for explicit deletes, not for normal ingestion.

### 5.4 Pre-Download for Hybrid Dedup

Before a batch run, the tool can download all existing index shards from S3 to the staging directory:

```bash
rclone sync hetzner:bucket/isa-harvester/v1/index/ /staging/run-001/isa-harvester/v1/index/ \
  --transfers 32 --checkers 16
```

This populates the staging index with the current S3 state, enabling local dedup checks during classification.

---

## 6. Sync Commands

### 6.1 Full Sync with rclone

```bash
rclone sync /staging/run-001/isa-harvester/v1/ \
  hetzner:my-bucket/isa-harvester/v1/ \
  --transfers 32 \
  --checkers 16 \
  --s3-upload-cutoff 5M \
  --s3-chunk-size 5M \
  --progress \
  --stats 10s \
  --log-file /var/log/rclone-sync.log \
  --log-level INFO
```

**Explanation of flags**:
- `--transfers 32`: Upload 32 files concurrently
- `--checkers 16`: Check 16 files concurrently for existence/modification
- `--s3-upload-cutoff 5M`: Use multipart upload for files > 5 MB
- `--s3-chunk-size 5M`: Multipart chunk size
- `--progress`: Show progress bar
- `--stats 10s`: Print statistics every 10 seconds

### 6.2 Incremental Sync

After a second batch run that adds to the same staging directory:

```bash
rclone sync /staging/run-001/isa-harvester/v1/ \
  hetzner:my-bucket/isa-harvester/v1/ \
  --transfers 32 \
  --checkers 16 \
  --s3-upload-cutoff 5M \
  --s3-chunk-size 5M \
  --progress
```

rclone will:
1. Compare local files to S3 objects by size and modification time (or checksum if configured)
2. Skip unchanged files
3. Upload new files
4. Overwrite changed files (metadata, index shards, stats)

### 6.3 Selective Sync (Objects Only)

To upload only the binary objects and metadata (skip views, index, ledger):

```bash
rclone sync /staging/run-001/isa-harvester/v1/objects/ \
  hetzner:my-bucket/isa-harvester/v1/objects/ \
  --transfers 32 --checkers 16 --progress
```

Then sync views, index, and ledgers separately:

```bash
rclone sync /staging/run-001/isa-harvester/v1/views/ \
  hetzner:my-bucket/isa-harvester/v1/views/ \
  --transfers 64 --checkers 32 --progress

rclone sync /staging/run-001/isa-harvester/v1/index/ \
  hetzner:my-bucket/isa-harvester/v1/index/ \
  --transfers 64 --checkers 32 --progress

rclone sync /staging/run-001/isa-harvester/v1/ledgers/ \
  hetzner:my-bucket/isa-harvester/v1/ledgers/ \
  --transfers 64 --checkers 32 --progress
```

This allows parallel sync of different object types with different concurrency settings (views/index/ledger are small files → higher concurrency).

### 6.4 Dry Run

Preview what would be uploaded without actually uploading:

```bash
rclone sync /staging/run-001/isa-harvester/v1/ \
  hetzner:my-bucket/isa-harvester/v1/ \
  --dry-run --progress
```

### 6.5 s3cmd Alternative

```bash
s3cmd sync /staging/run-001/isa-harvester/v1/ \
  s3://my-bucket/isa-harvester/v1/ \
  --multipart-chunk-size-mb=5 \
  --progress \
  --no-preserve \
  --acl-private
```

### 6.6 AWS CLI Alternative

```bash
aws s3 sync /staging/run-001/isa-harvester/v1/ \
  s3://my-bucket/isa-harvester/v1/ \
  --endpoint-url https://s3.hetzner.com \
  --only-show-errors
```

---

## 7. Cleanup

### 7.1 After Successful Sync

Once the staging directory has been fully synced to S3, it can be deleted:

```bash
rm -rf /staging/run-001/
```

Or kept as a local cache for future incremental runs.

### 7.2 Partial Cleanup

To free disk space while keeping the index (for dedup on future runs):

```bash
# Remove binaries (largest files), keep metadata and index
find /staging/run-001/isa-harvester/v1/objects/ -name '*.bin' -delete

# Or remove only objects, keep everything else
rm -rf /staging/run-001/isa-harvester/v1/objects/
```

### 7.3 Multiple Staging Directories

For separate batch runs:

```bash
# Run 1
zrax batch -i /data/batch-01 -o /staging/run-001
rclone sync /staging/run-001/ hetzner:bucket/isa-harvester/v1/
rm -rf /staging/run-001/

# Run 2
zrax batch -i /data/batch-02 -o /staging/run-002
rclone sync /staging/run-002/ hetzner:bucket/isa-harvester/v1/
rm -rf /staging/run-002/
```

Or accumulate into a single staging directory:

```bash
# Run 1
zrax batch -i /data/batch-01 -o /staging/combined

# Run 2 (adds to same staging)
zrax batch -i /data/batch-02 -o /staging/combined --skip-existing

# Sync everything
rclone sync /staging/combined/ hetzner:bucket/isa-harvester/v1/
```

---

## 8. Filesystem Recommendations

| Requirement | Recommendation |
|------------|---------------|
| Filesystem | XFS or ext4 (XFS preferred for many small files) |
| Inode count | At least 20× expected file count |
| Block size | 4 KB (default) |
| Storage type | NVMe SSD for best throughput |
| Mount options | `noatime,nodiratime` (avoid unnecessary metadata writes) |
| Free space buffer | Keep 10% free for index/ledger writes during processing |
