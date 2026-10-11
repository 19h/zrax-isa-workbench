# Data Schemas

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

This document defines every data structure stored in S3 by the Zrax Batch Store system.

---

## 1. Metadata Sidecar (`<hash>.meta.json`)

Stored at: `<P>/objects/sha256/<ab>/<cd>/<sha256>.meta.json`

This is the most important document in the system. It is the canonical record of everything known about a classified binary. It is the single source of truth that the web UI, REST API, and any programmatic consumer reads.

### 1.1 Full Schema

```json
{
  "schema_version": 1,

  "identity": {
    "sha256": "a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789",
    "file_size": 1048576,
    "object_key": "objects/sha256/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789.bin"
  },

  "names": {
    "original_names": ["firmware.bin", "rkos"],
    "original_paths": [
      "Firmware/t2026phoneG1/Release/ftab_dump/rkos",
      "batch-input/extracted/firmware.bin"
    ],
    "sanitized_name": "rkos"
  },

  "classification": {
    "format": "elf",
    "format_display": "ELF",
    "format_variant": null,
    "isa": "aarch64",
    "isa_display": "AArch64 (ARM64)",
    "bitwidth": 64,
    "endianness": "little",
    "confidence": 0.872,
    "source": "file_format",
    "variant": {
      "name": "ARMv8.2-A",
      "profile": "Cortex-A76",
      "abi": null
    }
  },

  "candidates": [
    {
      "rank": 1,
      "isa": "aarch64",
      "isa_display": "AArch64 (ARM64)",
      "bitwidth": 64,
      "endianness": "little",
      "raw_score": 1850956,
      "confidence": 0.542
    },
    {
      "rank": 2,
      "isa": "i860",
      "isa_display": "Intel i860",
      "bitwidth": 32,
      "endianness": "little",
      "raw_score": 1213193,
      "confidence": 0.192
    },
    {
      "rank": 3,
      "isa": "arm",
      "isa_display": "ARM (32-bit)",
      "bitwidth": 32,
      "endianness": "little",
      "raw_score": 456789,
      "confidence": 0.071
    }
  ],

  "extensions": [
    {
      "name": "NEON",
      "category": "simd",
      "confidence": 0.95,
      "source": "code_pattern"
    },
    {
      "name": "VFPv4",
      "category": "float",
      "confidence": 0.88,
      "source": "code_pattern"
    }
  ],

  "metadata": [
    {
      "key": "entry_point",
      "value": "0x401000",
      "label": "Entry Point"
    },
    {
      "key": "section_count",
      "value": "12",
      "label": "Sections"
    },
    {
      "key": "flags",
      "value": "0x00000005",
      "label": "Flags"
    }
  ],

  "notes": [
    {
      "level": "info",
      "message": "Detected system register access patterns (MRS/MSR)",
      "context": "aarch64"
    },
    {
      "level": "info",
      "message": "Function prologue/epilogue patterns detected",
      "context": "aarch64"
    }
  ],

  "routing": {
    "status": "classified",
    "view_key": "views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789__rkos.ref",
    "ambiguous_reason": null,
    "confidence_band": "high"
  },

  "provenance": {
    "run_id": "20260302T143022Z-batch-001",
    "classifier_version": "0.1.0",
    "ingested_at": "2026-03-02T14:30:45Z",
    "source_path": "/input/Firmware/t2026phoneG1/Release/ftab_dump/rkos",
    "reclassified_count": 0,
    "previous_classifications": []
  }
}
```

### 1.2 Field Reference

#### `schema_version` (integer, required)

The version of this metadata schema. Current value: `1`. Consumers must check this field and handle unknown versions gracefully.

#### `identity` (object, required)

| Field | Type | Description |
|-------|------|-------------|
| `sha256` | string (64 hex chars) | SHA-256 hash of the binary file |
| `file_size` | integer (bytes) | Size of the binary in bytes |
| `object_key` | string | Relative S3 key of the binary object (relative to prefix) |

#### `names` (object, required)

| Field | Type | Description |
|-------|------|-------------|
| `original_names` | string[] | All original filenames this hash has been seen with (deduplicated, append-only) |
| `original_paths` | string[] | All source paths this hash has been ingested from (deduplicated, append-only) |
| `sanitized_name` | string | The sanitized filename used in `.ref` keys (see [02-s3-key-layout.md](02-s3-key-layout.md) Section 4.3) |

When the same binary is re-ingested with a different original name or path, the new name/path is appended to these arrays (if not already present). The `sanitized_name` uses the first name encountered and does not change.

#### `classification` (object, required)

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Format slug (e.g., `elf`, `pe`, `raw`). See [02-s3-key-layout.md](02-s3-key-layout.md) Section 4.2 |
| `format_display` | string | Human-readable format name (e.g., `ELF`, `PE/COFF`, `Raw`) |
| `format_variant` | string or null | Format sub-variant if applicable (e.g., `ELF64`, `PE32+`) |
| `isa` | string | ISA slug (e.g., `aarch64`, `x86_64`). See [02-s3-key-layout.md](02-s3-key-layout.md) Section 4.1 |
| `isa_display` | string | Human-readable ISA name (e.g., `AArch64 (ARM64)`, `x86-64`) |
| `bitwidth` | integer | Register width: 8, 16, 32, 64, or 128 |
| `endianness` | string | `little`, `big`, or `bi-endian` |
| `confidence` | float (0.0-1.0) | Classification confidence score |
| `source` | string | How classification was determined: `file_format`, `heuristic`, `combined`, `user_specified` |
| `variant` | object or null | Architecture variant/profile/ABI details |

##### `variant` sub-object

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Variant name (e.g., `ARMv8.2-A`, `MIPS32R6`) |
| `profile` | string or null | CPU profile (e.g., `Cortex-A76`, `Cortex-M4`) |
| `abi` | string or null | ABI (e.g., `ELFv2`, `O32`, `EABI`) |

#### `candidates` (array, required)

Array of alternative ISA candidates from heuristic analysis, sorted by raw score descending. May be empty if classification was from format headers only (no heuristic pass).

Each candidate:

| Field | Type | Description |
|-------|------|-------------|
| `rank` | integer | 1-based rank |
| `isa` | string | ISA slug |
| `isa_display` | string | Human-readable ISA name |
| `bitwidth` | integer | Register width |
| `endianness` | string | Byte order |
| `raw_score` | integer | Raw heuristic score |
| `confidence` | float | Normalized confidence for this candidate |

Maximum 10 candidates stored per file.

#### `extensions` (array, required — may be empty)

Detected ISA extensions from code pattern analysis.

Each extension:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Extension name (e.g., `AVX2`, `NEON`, `VFPv4`, `SVE`) |
| `category` | string | Category: `simd`, `float`, `crypto`, `vector`, `virtualization`, `security`, `atomic`, `other` |
| `confidence` | float | Detection confidence (0.0-1.0) |
| `source` | string | Detection source: `code_pattern`, `format_attribute`, `variant_implied` |

#### `metadata` (array, required — may be empty)

Additional metadata extracted from file format headers.

Each entry:

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Metadata key: `entry_point`, `section_count`, `symbol_count`, `code_size`, `flags`, `raw_machine`, or custom |
| `value` | string | String representation of the value |
| `label` | string | Human-readable label |

#### `notes` (array, required — may be empty)

Analysis notes, warnings, and errors.

Each note:

| Field | Type | Description |
|-------|------|-------------|
| `level` | string | `info`, `warning`, or `error` |
| `message` | string | Human-readable message |
| `context` | string or null | What produced this note (e.g., `aarch64`, `elf_parsing`) |

#### `routing` (object, required)

Where this file was routed in the view tree.

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `classified`, `ambiguous`, `duplicate`, `error` |
| `view_key` | string | Relative S3 key of the `.ref` file in the view tree |
| `ambiguous_reason` | string or null | If status is `ambiguous`: `low_conf`, `low_margin`, `error`, `unknown_isa` |
| `confidence_band` | string | `high` (>=0.80), `medium` (0.50-0.79), `low` (0.30-0.49), `very_low` (<0.30) |

#### `provenance` (object, required)

Origin and history tracking.

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | The batch run or online session that ingested this file |
| `classifier_version` | string | Version of the classifier binary used |
| `ingested_at` | string (ISO 8601) | Timestamp of ingestion |
| `source_path` | string | The original source path from the input directory |
| `reclassified_count` | integer | How many times this file has been reclassified |
| `previous_classifications` | array | History of previous ISA/confidence pairs (only populated if reclassified) |

##### `previous_classifications` entries

| Field | Type | Description |
|-------|------|-------------|
| `isa` | string | Previous ISA slug |
| `confidence` | float | Previous confidence |
| `classifier_version` | string | Classifier version that produced this classification |
| `reclassified_at` | string (ISO 8601) | When the reclassification occurred |

---

## 2. Ledger Entry (NDJSON line)

Stored at: `<P>/ledgers/global/<run_id>/<seq>.jsonl.zst` and `<P>/ledgers/isa=<isa>/<run_id>/<seq>.jsonl.zst`

Each line in a ledger segment is a self-contained JSON object:

```json
{
  "ts": "2026-03-02T14:30:45Z",
  "run": "20260302T143022Z-batch-001",
  "sha256": "a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789",
  "size": 1048576,
  "fmt": "elf",
  "isa": "aarch64",
  "bits": 64,
  "endian": "le",
  "conf": 0.872,
  "src": "file_format",
  "status": "classified",
  "amb_reason": null,
  "margin": 0.526,
  "runner_up": "i860",
  "orig_name": "rkos",
  "orig_path": "/input/Firmware/rkos",
  "obj_key": "objects/sha256/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789.bin",
  "meta_key": "objects/sha256/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789.meta.json",
  "view_key": "views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/a1/b2/a1b2c3d4....__rkos.ref",
  "ext": ["NEON", "VFPv4"],
  "cv": "0.1.0",
  "action": "ingest"
}
```

### 2.1 Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string (ISO 8601) | Timestamp of this event |
| `run` | string | Run ID |
| `sha256` | string (64 hex) | File hash |
| `size` | integer | File size in bytes |
| `fmt` | string | Format slug |
| `isa` | string | ISA slug |
| `bits` | integer | Bitwidth |
| `endian` | string | `le`, `be`, or `bi` |
| `conf` | float | Classification confidence |
| `src` | string | Classification source: `file_format`, `heuristic`, `combined` |
| `status` | string | `classified`, `ambiguous`, `duplicate`, `error` |
| `amb_reason` | string or null | Ambiguous reason code |
| `margin` | float | Winner margin over runner-up (0.0 if no runner-up) |
| `runner_up` | string or null | Runner-up ISA slug |
| `orig_name` | string | Original filename |
| `orig_path` | string | Original source path |
| `obj_key` | string | Relative S3 key of binary object |
| `meta_key` | string | Relative S3 key of metadata sidecar |
| `view_key` | string | Relative S3 key of view .ref file |
| `ext` | string[] | Detected extension names |
| `cv` | string | Classifier version |
| `action` | string | Event type: `ingest`, `reclassify`, `delete` |

### 2.2 Actions

| Action | When |
|--------|------|
| `ingest` | New file ingested (batch or online) |
| `reclassify` | Existing file reclassified (new classifier version or manual trigger) |
| `delete` | File deleted from the store |
| `duplicate` | File was already in the store (dedup hit) — only logged to global ledger, not ISA ledger |

### 2.3 Segment Rotation

A new ledger segment is started when any of:
- The current segment reaches 50,000 lines
- The current segment's uncompressed size reaches 10 MB
- The run ends

Sequence numbers are zero-padded 6 digits: `000001`, `000002`, etc.

### 2.4 Compression

Ledger segments are compressed with zstd at level 3. The `.zst` extension is part of the S3 key. Consumers must decompress before parsing.

Typical compression ratio for this JSON structure: 4-6x (a 10 MB uncompressed segment becomes ~2 MB compressed).

---

## 3. Index Shard (`<ab>/<cd>.idx`)

Stored at: `<P>/index/sha256/<ab>/<cd>.idx`

A TSV (tab-separated values) file with one line per object in that shard. No header line.

### 3.1 Format

```
<sha256>\t<object_key>\t<meta_key>\t<format>\t<isa>\t<bits>\t<endian>\t<confidence>\t<status>\t<file_size>\t<ingested_at>
```

### 3.2 Example

```
a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789	objects/sha256/a1/b2/a1b2c3d4...bin	objects/sha256/a1/b2/a1b2c3d4...meta.json	elf	aarch64	64	le	0.872	classified	1048576	2026-03-02T14:30:45Z
f0e1d2c3b4a59687fedcba9876543210fedcba9876543210fedcba9876543210	objects/sha256/f0/e1/f0e1d2c3...bin	objects/sha256/f0/e1/f0e1d2c3...meta.json	raw	arm	32	le	0.451	ambiguous	32768	2026-03-02T14:31:02Z
```

### 3.3 Field Reference

| Column | Type | Description |
|--------|------|-------------|
| 1 | string | SHA-256 hash (64 hex chars) |
| 2 | string | Binary object key (relative to prefix) |
| 3 | string | Metadata key (relative to prefix) |
| 4 | string | Format slug |
| 5 | string | ISA slug |
| 6 | integer | Bitwidth |
| 7 | string | Endianness slug (`le`, `be`, `bi`) |
| 8 | float | Confidence |
| 9 | string | Status: `classified`, `ambiguous`, `error` |
| 10 | integer | File size in bytes |
| 11 | string (ISO 8601) | Ingestion timestamp |

### 3.4 Ordering

Lines within a shard are sorted by SHA-256 hash (lexicographic). This enables binary search for specific hashes when shards are loaded into memory.

### 3.5 Update Semantics

Index shards are updated via read-modify-write:
1. Download the existing shard (`GetObject`, 404 = empty)
2. Parse existing lines into a sorted map
3. Insert/update new entries
4. Remove deleted entries
5. Write the updated shard (`PutObject`)

This is safe because:
- During batch ingestion, only one writer touches each shard (shards are partitioned by hash prefix)
- During online uploads, the backend serializes shard updates via a mutex (or compare-and-swap with ETags if supported)

---

## 4. Run Manifest (`<run_id>.json`)

Stored at: `<P>/runs/<run_id>.json`

### 4.1 Full Schema

```json
{
  "schema_version": 1,
  "run_id": "20260302T143022Z-batch-001",
  "type": "batch",
  "status": "completed",

  "parameters": {
    "input_path": "/data/firmware-corpus/batch-42",
    "staging_path": "/staging/batch-42",
    "prefix": "isa-harvester/v1",
    "jobs": 16,
    "min_confidence": 0.30,
    "min_margin": 0.20,
    "classifier_version": "0.1.0",
    "deep_scan": false,
    "detect_extensions": true
  },

  "timing": {
    "started_at": "2026-03-02T14:30:22Z",
    "completed_at": "2026-03-02T15:45:10Z",
    "duration_seconds": 4488,
    "files_per_second": 223.4,
    "bytes_per_second": 52428800
  },

  "counts": {
    "total_input_files": 1003456,
    "processed": 1003456,
    "classified": 892341,
    "ambiguous": 98765,
    "duplicates": 10234,
    "errors": 2116,
    "skipped": 0
  },

  "storage": {
    "total_bytes_ingested": 235123456789,
    "total_bytes_stored": 198765432100,
    "bytes_saved_by_dedup": 36358024689,
    "objects_created": 993222,
    "metadata_files_created": 993222,
    "ref_files_created": 993222,
    "ledger_segments_global": 21,
    "ledger_segments_isa": 187,
    "index_shards_updated": 48234
  },

  "breakdown_by_status": {
    "classified": 892341,
    "ambiguous_low_conf": 67890,
    "ambiguous_low_margin": 28765,
    "ambiguous_error": 1890,
    "ambiguous_unknown_isa": 220,
    "duplicate": 10234,
    "error": 2116
  },

  "breakdown_by_format": {
    "elf": 456789,
    "pe": 123456,
    "macho": 78901,
    "raw": 234567,
    "vbf": 12345,
    "sgo": 8901,
    "other": 88497
  },

  "breakdown_by_isa": {
    "x86_64": 234567,
    "aarch64": 189012,
    "arm": 123456,
    "x86": 98765,
    "mips": 45678,
    "tricore": 23456,
    "ppc": 12345,
    "other": 165062
  },

  "errors_summary": [
    {
      "error_type": "io_error",
      "count": 1200,
      "example": "Permission denied: /input/restricted/secret.bin"
    },
    {
      "error_type": "file_too_small",
      "count": 916,
      "example": "File too small: expected at least 4 bytes, got 0"
    }
  ]
}
```

### 4.2 Field Reference

#### Top-level

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Schema version (current: 1) |
| `run_id` | string | Unique run identifier |
| `type` | string | `batch` or `online` |
| `status` | string | `running`, `completed`, `failed`, `cancelled` |

#### `parameters`

| Field | Type | Description |
|-------|------|-------------|
| `input_path` | string | Source directory (batch) or `online` |
| `staging_path` | string | Local staging directory |
| `prefix` | string | S3 key prefix |
| `jobs` | integer | Number of parallel workers |
| `min_confidence` | float | Ambiguous threshold |
| `min_margin` | float | Margin threshold |
| `classifier_version` | string | Classifier version |
| `deep_scan` | boolean | Whether deep scan was enabled |
| `detect_extensions` | boolean | Whether extension detection was enabled |

#### `timing`

| Field | Type | Description |
|-------|------|-------------|
| `started_at` | string (ISO 8601) | Run start time |
| `completed_at` | string (ISO 8601) or null | Run end time (null if running) |
| `duration_seconds` | float | Total wall-clock seconds |
| `files_per_second` | float | Average throughput |
| `bytes_per_second` | float | Average throughput in bytes |

#### `counts`

| Field | Type | Description |
|-------|------|-------------|
| `total_input_files` | integer | Files discovered in input |
| `processed` | integer | Files attempted |
| `classified` | integer | Files successfully classified with sufficient confidence |
| `ambiguous` | integer | Files routed to ambiguous |
| `duplicates` | integer | Files already in store (dedup hits) |
| `errors` | integer | Files that failed to process |
| `skipped` | integer | Files skipped (e.g., too small, symlinks) |

---

## 5. Ref File (`.ref`)

Stored at: View tree paths (both classified and ambiguous).

### 5.1 Schema

```json
{
  "sha256": "a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789",
  "object_key": "objects/sha256/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789.bin",
  "meta_key": "objects/sha256/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789.meta.json",
  "original_name": "rkos",
  "file_size": 1048576,
  "ingested_at": "2026-03-02T14:30:45Z"
}
```

### 5.2 Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `sha256` | string (64 hex) | File hash |
| `object_key` | string | Relative S3 key of binary (relative to prefix) |
| `meta_key` | string | Relative S3 key of metadata |
| `original_name` | string | Original filename (unsanitized) |
| `file_size` | integer | File size in bytes |
| `ingested_at` | string (ISO 8601) | When first ingested |

### 5.3 Size

A typical `.ref` file is 300-500 bytes. At 1 million files, total view storage is ~400 MB.

---

## 6. Statistics File (`current.json`)

Stored at: `<P>/stats/current.json`

### 6.1 Schema

```json
{
  "schema_version": 1,
  "last_updated": "2026-03-02T15:45:10Z",
  "last_run_id": "20260302T143022Z-batch-001",

  "totals": {
    "files": 2456789,
    "bytes": 1234567890123,
    "classified": 2234567,
    "ambiguous": 198765,
    "errors": 23457,
    "unique_isas": 47,
    "unique_formats": 23
  },

  "by_format": {
    "elf": { "count": 890123, "bytes": 456789012345 },
    "pe": { "count": 345678, "bytes": 234567890123 },
    "raw": { "count": 567890, "bytes": 345678901234 },
    "macho": { "count": 123456, "bytes": 98765432100 },
    "vbf": { "count": 12345, "bytes": 6789012345 }
  },

  "by_isa": {
    "x86_64": { "count": 567890, "bytes": 345678901234 },
    "aarch64": { "count": 456789, "bytes": 234567890123 },
    "arm": { "count": 345678, "bytes": 123456789012 },
    "x86": { "count": 234567, "bytes": 98765432100 },
    "mips": { "count": 123456, "bytes": 67890123456 },
    "tricore": { "count": 56789, "bytes": 23456789012 }
  },

  "by_status": {
    "classified": 2234567,
    "ambiguous": 198765,
    "error": 23457
  },

  "by_confidence_band": {
    "high": 1890123,
    "medium": 234567,
    "low": 98765,
    "very_low": 11112
  },

  "runs_completed": 42,
  "last_10_runs": [
    {
      "run_id": "20260302T143022Z-batch-001",
      "type": "batch",
      "files": 1003456,
      "duration_seconds": 4488,
      "completed_at": "2026-03-02T15:45:10Z"
    }
  ]
}
```

### 6.2 Update Semantics

After each batch run or periodically during online uploads:
1. `GetObject` the existing `stats/current.json` (404 = start fresh)
2. Merge new counts (add to existing totals, update per-ISA/format counts)
3. `PutObject` the updated stats

This is a read-modify-write and is not concurrency-safe without external coordination. For batch mode this is fine (one writer). For online mode, the backend serializes stats updates.

---

## 7. Schema Versioning

All JSON documents include a `schema_version` field. Rules:
- **Minor additions** (new optional fields): same version, consumers ignore unknown fields
- **Breaking changes** (removed fields, changed types, changed semantics): increment version
- Consumers must check `schema_version` and reject documents with unknown versions
- Old documents are never migrated in-place; they remain readable at their original version
