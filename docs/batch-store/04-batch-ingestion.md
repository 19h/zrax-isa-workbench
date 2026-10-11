# Batch Ingestion Pipeline

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Command-Line Interface

### 1.1 Command Syntax

```
zrax batch [OPTIONS] --input <INPUT_DIR> --output <STAGING_DIR>
```

### 1.2 Required Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--input <DIR>` | `-i` | Input directory containing binary files to classify |
| `--output <DIR>` | `-o` | Output staging directory (will be created if it doesn't exist) |

### 1.3 Optional Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--jobs <N>` | `-j` | CPU core count | Number of parallel worker threads |
| `--prefix <STR>` | | `isa-harvester/v1` | S3 key prefix for all generated keys |
| `--min-confidence <F>` | | `0.30` | Minimum confidence to classify (below this → ambiguous) |
| `--min-margin <F>` | | `0.20` | Minimum margin over runner-up (below this → ambiguous) |
| `--bucket <STR>` | `-b` | none | S3 bucket name for online dedup checks (optional) |
| `--endpoint <URL>` | `-e` | none | S3 endpoint URL (required if `--bucket` is set) |
| `--run-id <STR>` | | auto-generated | Override the run ID (default: `YYYYMMDDTHHMMSSZ-batch-NNN`) |
| `--deep-scan` | | false | Enable deep scan mode (slower, more accurate) |
| `--extensions` | | true | Enable ISA extension detection |
| `--no-extensions` | | | Disable ISA extension detection |
| `--max-file-size <BYTES>` | | 1 GB | Skip files larger than this |
| `--min-file-size <BYTES>` | | 4 | Skip files smaller than this |
| `--follow-symlinks` | | false | Follow symbolic links |
| `--no-tui` | | false | Disable TUI, use simple progress output |
| `--quiet` | `-q` | false | Suppress all output except errors |
| `--verbose` | `-v` | false | Verbose logging |
| `--ledger-segment-max-lines <N>` | | 50000 | Max lines per ledger segment |
| `--ledger-segment-max-bytes <N>` | | 10485760 | Max uncompressed bytes per ledger segment |
| `--skip-existing` | | false | Skip files whose SHA-256 is already in a local index shard (no S3 check) |

### 1.4 Examples

```bash
# Basic usage: classify all files in /data/firmware, output to /staging
zrax batch -i /data/firmware -o /staging/run-001

# Use 32 workers, check S3 for duplicates
zrax batch -i /data/firmware -o /staging/run-001 -j 32 \
  --bucket my-bucket --endpoint https://s3.hetzner.com

# Custom thresholds, no TUI
zrax batch -i /data/firmware -o /staging/run-001 \
  --min-confidence 0.50 --min-margin 0.30 --no-tui

# Skip small files, deep scan mode
zrax batch -i /data/firmware -o /staging/run-001 \
  --min-file-size 64 --deep-scan
```

---

## 2. Pipeline Architecture

### 2.1 Overview

The batch pipeline is a multi-stage concurrent pipeline:

```
                      ┌─────────────┐
                      │  Directory   │
                      │   Walker     │
                      │  (1 thread)  │
                      └──────┬───────┘
                             │ paths (bounded channel)
                             ▼
                      ┌─────────────┐
                      │   Hasher    │
                      │  Pool (j/2) │
                      │   SHA-256   │
                      └──────┬───────┘
                             │ (hash, path, data) (bounded channel)
                             ▼
                      ┌──────────────┐
                      │  Classifier  │
                      │  Pool (j/2)  │
                      │   Detect     │
                      └──────┬───────┘
                             │ (hash, classification, data) (bounded channel)
                             ▼
                      ┌──────────────┐
                      │   Writer     │
                      │  (1 thread)  │
                      │  Staging I/O │
                      └──────┬───────┘
                             │
                             ▼
                      ┌──────────────┐
                      │  TUI Update  │
                      │  (1 thread)  │
                      └──────────────┘
```

### 2.2 Stage Details

#### Stage 1: Directory Walker (1 thread)

- Uses `walkdir` or `jwalk` for recursive directory traversal
- Applies file size filters (`--min-file-size`, `--max-file-size`)
- Applies symlink policy (`--follow-symlinks`)
- Sends `(path, file_size)` tuples into a bounded channel (capacity: `2 * jobs`)
- Reports discovered file count and total bytes to TUI

#### Stage 2: Hasher Pool (`j/2` threads, minimum 1)

Each hasher thread:
1. Receives a `(path, file_size)` from the walker channel
2. Memory-maps the file (or reads into buffer for small files)
3. Computes SHA-256 in a single streaming pass
4. If `--bucket` is set: performs `HeadObject` against S3 for dedup check
5. If `--skip-existing` is set: checks local index shards
6. If duplicate: sends a `DuplicateResult` to the writer (no classification needed)
7. If new: sends `(path, hash, data_ref)` to the classifier channel

**Why j/2?** Hashing is I/O-bound (disk read) and classification is CPU-bound. Splitting the thread pool roughly 50/50 between I/O and CPU work maximizes throughput. The exact split is tunable.

#### Stage 3: Classifier Pool (`j/2` threads, minimum 1)

Each classifier thread:
1. Receives `(path, hash, data_ref)` from the hasher channel
2. Runs the full classification pipeline: format detection → ISA classification → extension detection
3. Applies routing rules (classified vs ambiguous)
4. Constructs the metadata JSON, ref file content, and ledger entry
5. Sends `ClassifiedResult` to the writer channel

This stage is pure CPU work and benefits from maximum parallelism.

#### Stage 4: Writer (1 thread)

The single writer thread serializes all disk I/O to avoid contention:
1. Receives `ClassifiedResult` or `DuplicateResult` from the classifier channel
2. Writes the binary file to staging (`objects/sha256/<ab>/<cd>/<hash>.bin`)
3. Writes the metadata JSON (`objects/sha256/<ab>/<cd>/<hash>.meta.json`)
4. Writes the `.ref` file to the appropriate view path
5. Appends to the in-memory ledger buffer (global + ISA-specific)
6. Appends to the in-memory index shard buffer
7. Flushes ledger segments and index shards to disk when rotation thresholds are reached
8. Updates in-memory statistics counters
9. Sends progress update to TUI

**Why a single writer?** File system writes to different paths don't contend, but ledger/index updates need serialization. A single writer thread simplifies this without being a bottleneck (writing metadata/ref files is microseconds; the pipeline is bottlenecked by classification, not I/O).

#### Stage 5: TUI Update (1 thread)

A dedicated thread renders the terminal UI at ~10 Hz (every 100ms). It reads atomic counters updated by the writer thread. See Section 4 for TUI specification.

### 2.3 Channel Sizing

| Channel | Capacity | Rationale |
|---------|----------|-----------|
| Walker → Hasher | `2 * jobs` | Keep hashers fed without buffering entire directory listing |
| Hasher → Classifier | `2 * jobs` | Allow hashers to continue while classifiers catch up |
| Classifier → Writer | `4 * jobs` | Writer is fast; larger buffer absorbs classification bursts |

### 2.4 Memory Budget

- File data: At most `2 * jobs` files in flight simultaneously (in hasher and classifier stages). Each file is memory-mapped, so RSS depends on OS page cache, not buffer allocation.
- Ledger buffer: Up to `ledger_segment_max_bytes` uncompressed (default 10 MB). Two buffers (global + current ISA).
- Index shard buffer: In-memory map of `HashMap<(u8,u8), BTreeMap<[u8;32], IndexEntry>>`. At 65K shards and ~15 entries each, ~10 MB.
- Statistics: Negligible (~1 KB).

**Total estimated memory usage**: ~30-50 MB + OS page cache for memory-mapped files.

### 2.5 Error Handling

| Error | Behavior |
|-------|----------|
| File read error (permissions, I/O) | Log error, skip file, record in run manifest `errors_summary` |
| Classification error (inconclusive) | Route to ambiguous with `reason=error` |
| SHA-256 collision (astronomically unlikely) | Log critical warning, skip the duplicate |
| S3 dedup check failure (network) | Log warning, assume file is new, proceed with classification |
| Writer disk full | Abort run, write partial run manifest with `status=failed` |
| Worker panic | Catch at thread boundary, log, continue with remaining workers |

---

## 3. Dedup Check Strategies

### 3.1 No Dedup (Default for First Run)

Skip all dedup checks. Every file is classified and written to staging. Fastest for initial bulk ingestion.

### 3.2 Local Index Dedup (`--skip-existing`)

Before classifying, check if the SHA-256 hash exists in any local index shard (from previous staging runs, or downloaded from S3 before the run). This is fast (pure in-memory lookup) and free (no network). Useful for incremental runs against the same staging directory.

### 3.3 S3 Remote Dedup (`--bucket`)

Before classifying, issue `HeadObject` against S3 for each file. This is the most accurate but slowest strategy:
- Adds ~50-200ms latency per file (network round-trip to Hetzner)
- Can be parallelized across hasher threads
- Returns 200 (exists, skip) or 404 (new, proceed)

### 3.4 Hybrid: Download Index, Check Locally

Before the run:
1. Download all index shards from S3 (65K files, ~200 MB total)
2. Load into memory
3. Check each file's hash against the in-memory index

This front-loads ~200 MB of download but eliminates per-file S3 calls. Recommended for large incremental runs.

---

## 4. TUI Dashboard Specification

The TUI uses `ratatui` with `crossterm` backend. It renders a full-screen terminal dashboard.

### 4.1 Layout

```
┌─ Zrax Batch Classifier ─────────────────────────────────────────────┐
│                                                                               │
│  Run: 20260302T143022Z-batch-001    Workers: 16    Elapsed: 01:14:48         │
│  Input: /data/firmware-corpus/batch-42                                        │
│  Output: /staging/batch-42                                                    │
│                                                                               │
├─ Progress ────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Files:    ████████████████████████████░░░░  892,341 / 1,003,456  (88.9%)    │
│  Bytes:    ███████████████████████████░░░░░  218.9 GB / 245.1 GB  (89.3%)    │
│                                                                               │
│  Throughput:  223.4 files/sec    52.4 MB/sec    ETA: 00:08:17                │
│                                                                               │
├─ Classification Results ──────────────────────────────────────────────────────┤
│                                                                               │
│  Classified:  892,341  (88.9%)  ████████████████████████████░░                │
│  Ambiguous:    98,765   (9.8%)  ███░░░░░░░░░░░░░░░░░░░░░░░░░                │
│  Duplicate:    10,234   (1.0%)  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░                │
│  Errors:        2,116   (0.2%)  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░                │
│                                                                               │
├─ Top ISAs ────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  x86_64     234,567  ████████████████████                                     │
│  aarch64    189,012  ████████████████                                         │
│  arm        123,456  ██████████                                               │
│  x86         98,765  ████████                                                 │
│  mips        45,678  ████                                                     │
│  tricore     23,456  ██                                                       │
│  ppc         12,345  █                                                        │
│  riscv64      8,901  █                                                        │
│                                                                               │
├─ Top Formats ─────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ELF        456,789  ████████████████████████                                 │
│  Raw        234,567  ████████████                                             │
│  PE         123,456  ██████                                                   │
│  Mach-O      78,901  ████                                                     │
│  VBF         12,345  █                                                        │
│                                                                               │
├─ Confidence Distribution ─────────────────────────────────────────────────────┤
│                                                                               │
│  High   (>=80%):  678,901  ████████████████████████████                       │
│  Medium (50-79):  156,789  ██████                                             │
│  Low    (30-49):   56,651  ██                                                 │
│  V.Low  (<30%):    98,765  ████  (→ ambiguous)                                │
│                                                                               │
├─ Recent Activity ─────────────────────────────────────────────────────────────┤
│                                                                               │
│  14:30:45  firmware.bin        → elf/aarch64/64/le   87.2%  classified        │
│  14:30:45  bootloader.raw      → raw/arm/32/le       34.1%  ambiguous         │
│  14:30:44  kernel.elf           → elf/x86_64/64/le   99.1%  classified        │
│  14:30:44  unknown.blob         → raw/unknown/0/le   12.3%  ambiguous         │
│  14:30:43  driver.ko            → elf/tricore/32/le  91.5%  classified        │
│                                                                               │
├─ Errors (last 5) ────────────────────────────────────────────────────────────┤
│                                                                               │
│  14:30:42  empty.bin        File too small: expected 4 bytes, got 0           │
│  14:30:38  restricted.fw    Permission denied                                 │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Sections

| Section | Content | Update Rate |
|---------|---------|-------------|
| Header | Run ID, worker count, elapsed time, paths | 1 Hz |
| Progress | File and byte progress bars with counts, throughput, ETA | 10 Hz |
| Classification Results | Counts by status with visual bars | 1 Hz |
| Top ISAs | Top 8 ISAs by count with proportional bars | 1 Hz |
| Top Formats | Top 5 formats by count with proportional bars | 1 Hz |
| Confidence Distribution | Histogram by confidence band | 1 Hz |
| Recent Activity | Last 5 processed files with results | 10 Hz |
| Errors | Last 5 errors | On error |

### 4.3 Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit (graceful shutdown: finish in-progress files, flush buffers) |
| `Ctrl+C` | Abort (immediate: flush what we can, write failed run manifest) |
| `p` | Pause/unpause workers |
| `↑/↓` | Scroll recent activity log |
| `Tab` | Cycle focus between sections |
| `?` | Show help overlay |

### 4.4 Non-TUI Mode (`--no-tui`)

When TUI is disabled, output simple progress lines to stderr:

```
[14:30:45] Processed 1000/1003456 files (0.1%) | 223 files/sec | ETA 01:14:48
[14:30:55] Processed 3234/1003456 files (0.3%) | 223 files/sec | ETA 01:14:38
...
[15:45:10] Completed: 892341 classified, 98765 ambiguous, 10234 duplicate, 2116 errors
```

---

## 5. Staging Directory Output

After a batch run completes, the staging directory contains an exact mirror of the S3 key layout. See [10-local-staging.md](10-local-staging.md) for the complete specification.

### 5.1 Upload to S3

```bash
# Using rclone (recommended)
rclone sync /staging/batch-42/ hetzner:my-bucket/isa-harvester/v1/ \
  --transfers 32 \
  --checkers 16 \
  --s3-upload-cutoff 5M \
  --s3-chunk-size 5M \
  --progress

# Using s3cmd
s3cmd sync /staging/batch-42/ s3://my-bucket/isa-harvester/v1/ \
  --multipart-chunk-size-mb=5 \
  --progress
```

### 5.2 Post-Upload Verification

After upload, verify integrity:

```bash
# Count objects in S3 vs staging
rclone size /staging/batch-42/objects/
rclone size hetzner:my-bucket/isa-harvester/v1/objects/

# Verify run manifest uploaded
rclone cat hetzner:my-bucket/isa-harvester/v1/runs/20260302T143022Z-batch-001.json | jq .status
```

---

## 6. Graceful Shutdown

### 6.1 On `q` (Graceful)

1. Stop accepting new files from the walker
2. Drain all in-flight files through the pipeline (finish hashing, classifying, writing)
3. Flush all ledger buffers to disk
4. Flush all index shard buffers to disk
5. Update the run manifest with final counts and `status: completed`
6. Write the stats file
7. Exit with code 0

### 6.2 On `Ctrl+C` (Abort)

1. Cancel all in-flight operations immediately
2. Flush whatever ledger/index data is in memory (best-effort)
3. Write the run manifest with `status: failed` and partial counts
4. Exit with code 1

### 6.3 On Fatal Error (Disk Full, OOM)

1. Write the run manifest with `status: failed` and partial counts (best-effort)
2. Log the error to stderr
3. Exit with code 2

---

## 7. Incremental Runs

Running the batch tool against a staging directory that already contains data from a previous run:

### 7.1 Default Behavior

The tool writes new objects alongside existing ones. Duplicate hashes produce identical keys and overwrite with identical content (idempotent). Ledger segments from the new run are created with the new run ID, so they don't conflict with previous run's segments.

### 7.2 With `--skip-existing`

The tool loads existing index shards from the staging directory at startup and skips any file whose hash is already present. This avoids re-reading, re-hashing, and re-classifying known files.

### 7.3 Index Shard Merge

When writing index shards, the tool reads the existing shard from staging (if present), merges new entries, and writes back. This ensures the index remains complete across multiple runs.
