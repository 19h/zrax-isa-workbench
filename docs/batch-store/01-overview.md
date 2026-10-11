# Zrax Batch Store: Architecture Overview

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Status | Draft |
| Authors | ISA Harvester Team |

---

## 1. What This System Is

The Zrax Batch Store is a scalable, database-free binary classification and storage system. It ingests arbitrary binary files (firmware images, executables, object files, raw code dumps), classifies them by file format and instruction set architecture (ISA), and stores them in an S3-compatible object storage backend with rich metadata, deduplication, and machine-queryable indexes.

The system has three main actors:

1. **CLI Batch Ingestion Tool** — Processes an input directory of binaries in parallel, classifies each file, writes results to a local staging directory that mirrors the S3 key layout, and is then synced to object storage via `rclone` or equivalent.

2. **Web Backend API** — A thin HTTP service that reads from and writes to S3, exposing structured REST endpoints for browsing, searching, uploading, downloading, reclassifying, and deleting classified binaries.

3. **Web UI** — A browser-based interface for employees to browse the classified file tree, view metadata and classification details, download binaries, and drag-and-drop new files for on-demand classification and upload.

---

## 2. Why This Architecture Exists

### 2.1 The Problem

We have a growing corpus of binary files spanning hundreds of ISAs (ARM, AArch64, x86, MIPS, PowerPC, TriCore, RISC-V, AVR, and dozens more) and dozens of file formats (ELF, PE, Mach-O, raw firmware, automotive formats like VBF/FRF/SGO, etc.). We need to:

- Classify every binary by format, ISA, bitwidth, endianness, and confidence level
- Store binaries with full metadata in a way that survives millions of files across hundreds of ISAs
- Allow both batch bulk ingestion and interactive on-demand uploads
- Support fast lookups by SHA-256 hash (existence check), by ISA, by format, and by any combination
- Track every file in append-only audit ledgers
- Deduplicate: never store the same binary twice
- Operate without any external database (no PostgreSQL, no SQLite, no Redis)
- Use S3-compatible object storage as the sole persistence layer (Hetzner S3)
- Support deterministic, high-performance interactions from both machines and humans

### 2.2 Why Not a Database?

Databases add operational complexity (backups, migrations, connection pooling, version upgrades, replication, schema evolution). For this workload — which is fundamentally "write once, read many, append-only audit trail" — S3 provides:

- Infinite horizontal scaling with no shard management
- Built-in durability (11 nines on AWS; comparable on Hetzner)
- No connection limits, no lock contention
- Trivially replicable via `rclone sync`
- Direct cost scaling with stored bytes, not provisioned capacity
- Full disaster recovery by re-syncing the bucket

The trade-off is that S3 has no query language, no secondary indexes, no transactions, and no partial updates. We compensate by designing a deterministic key layout that turns S3's `ListObjectsV2` prefix filtering into an effective hierarchical query engine, and by maintaining append-only ledger files that serve as machine-readable indexes.

### 2.3 Why Content-Addressed Storage (CAS)?

Every binary is stored at a key derived from its SHA-256 hash. This gives us:

- **Automatic deduplication**: If the same firmware image appears in 50 different input batches, it's stored once.
- **Deterministic addressing**: Given a hash, you can compute the exact S3 key without any lookup. `HeadObject` on that key is an O(1) existence check.
- **Immutability**: The binary at a CAS key never changes (same hash = same content). Only metadata can be updated.
- **Reclassification safety**: Re-running the classifier doesn't duplicate storage; it only updates metadata and view references.

### 2.4 Why Separate "Objects" and "Views"?

The storage model separates **canonical data** (the binary and its metadata, stored once by hash) from **classification views** (lightweight pointer files organized by format/ISA/bitwidth/endianness). This separation means:

- The binary is stored exactly once regardless of how it's classified
- Reclassification only requires deleting the old `.ref` pointer and creating a new one (no data movement)
- Multiple views of the same data are cheap (each `.ref` is ~200-500 bytes)
- Browsing by ISA or format uses S3 prefix listing on the view tree, which is fast and paginated
- Bulk enumeration uses ledger files, not view tree traversal

---

## 3. Design Principles

### 3.1 No External Dependencies Beyond S3

The entire state of the system lives in S3. There is no sidecar database, no cache that's required for correctness, no state on the backend server's local disk (beyond ephemeral processing). If you lose the backend server, you can point a new one at the same bucket and it works.

### 3.2 Deterministic Key Derivation

Every S3 key is computable from known inputs:
- Binary key: `objects/sha256/{first2}/{next2}/{full_hash}.bin` — computable from the file's SHA-256
- Metadata key: same path with `.meta.json` suffix
- View key: computable from classification result + hash + original filename
- Index shard: computable from first 4 hex chars of hash

No key requires a lookup to derive. This is critical for O(1) existence checks and for making `rclone sync` work correctly.

### 3.3 Append-Only Audit Trail

Every classification event is recorded in a ledger. Ledgers are never edited, only appended to (by writing new segment files). This provides:
- Full history of what was classified, when, by whom (which run), with what result
- Ability to replay/audit any run
- Cheap "list all files for ISA X" queries by scanning ISA-specific ledger segments

### 3.4 Sharding for Directory Cardinality

S3 doesn't have directories, but `ListObjectsV2` with `Delimiter=/` simulates them. Having millions of objects under a single prefix degrades listing performance. We shard by the first 4 hex characters of the SHA-256 hash (`ab/cd/`), creating up to 65,536 shards, each containing a manageable number of objects.

### 3.5 Minimal S3 API Surface

The system uses only 6 S3 API operations:
- `HeadObject` — existence/dedup checks
- `GetObject` — fetch binary, metadata, ref, ledger, index, stats
- `PutObject` — upload binary, metadata, ref, ledger, index, stats, run manifests
- `CreateMultipartUpload` + `UploadPart` + `CompleteMultipartUpload` — large binary upload (>5MB)
- `DeleteObject` — remove binary, metadata, ref
- `ListObjectsV2` — browse views, list ledger segments, list runs, enumerate shards

No S3 Select, no Batch Operations, no lifecycle policies, no S3 Inventory. Fully compatible with Hetzner S3 and any minimal S3-compatible backend.

### 3.6 Local-First Batch Processing

Batch ingestion produces a local staging directory that is an exact mirror of the S3 key layout. This means:
- Processing is entirely local and parallelizable (no S3 calls during classification, except optional dedup HeadObject)
- Upload is a single `rclone sync` or `s3cmd sync` command
- Failed uploads can be retried without re-processing
- Staging can be inspected before upload

### 3.7 Idempotent Operations

Every operation is safe to retry:
- Uploading the same binary twice produces the same key (CAS)
- Uploading the same metadata twice overwrites with identical content
- Creating the same `.ref` twice is a no-op (same key, same content)
- Ledger appends are keyed by run ID + sequence number, so re-syncing a run doesn't duplicate entries

---

## 4. System Components

### 4.1 Zrax Engine (Existing)

The core classification library (`zrax` crate) that identifies file format and ISA from binary data. Supports 40+ ISAs and 50+ file formats. Produces:
- Primary classification: format, ISA, bitwidth, endianness, confidence, variant
- Candidate list: top N alternative classifications with scores
- Extensions: detected ISA extensions (NEON, AVX2, VFP, etc.)
- Notes: warnings, errors, informational messages
- Metadata: entry points, section counts, flags, etc.

### 4.2 Batch Ingestion CLI (New)

A new subcommand `zrax batch` that:
- Recursively walks an input directory
- Processes files in parallel with `-j` workers (default: CPU core count)
- Computes SHA-256 and classifies each file
- Writes objects, metadata, views, ledgers, and indexes to a local staging directory
- Optionally checks S3 for dedup before processing (requires network)
- Displays a TUI dashboard with progress, throughput, ISA statistics, error counts

### 4.3 Web Backend API (New)

A Rust HTTP service (likely axum or actix-web) that:
- Connects to S3 via aws-sdk-s3 or rusoto
- Exposes REST endpoints for all browsing, search, upload, download, delete, and reclassify operations
- Proxies binary downloads from S3 to browser (no presigned URLs, no direct S3 access from browser)
- Handles drag-and-drop upload: receives file from browser, classifies in-memory, uploads to S3

### 4.4 Web UI (New)

A browser-based interface that:
- Presents the classified file tree: Format > ISA > Bitwidth > Endianness > Files
- Shows classification details, candidates, extensions, notes for each file
- Supports drag-and-drop file upload with live classification feedback
- Shows batch run history and statistics
- Presents ambiguous file bucket separately

---

## 5. Document Index

This documentation set is organized as follows:

| Document | Contents |
|----------|----------|
| [01-overview.md](01-overview.md) | This document. Architecture overview, motivation, design principles. |
| [02-s3-key-layout.md](02-s3-key-layout.md) | Complete S3 key structure specification with examples. |
| [03-schemas.md](03-schemas.md) | All data schemas: metadata JSON, ledger JSONL, index shard TSV, .ref JSON, run manifest JSON, stats JSON. |
| [04-batch-ingestion.md](04-batch-ingestion.md) | CLI batch mode specification: command-line interface, pipeline architecture, worker model, TUI dashboard, local staging. |
| [05-s3-api-calls.md](05-s3-api-calls.md) | Exhaustive enumeration of every S3 API call for every interaction scenario. |
| [06-web-api.md](06-web-api.md) | REST API endpoint specification with request/response formats and S3 call mapping. |
| [07-web-ui-flows.md](07-web-ui-flows.md) | Web UI interaction flows: browsing, upload, download, reclassify, delete, dashboard. |
| [08-ambiguous-routing.md](08-ambiguous-routing.md) | Ambiguous file routing logic: confidence thresholds, margin calculation, routing rules, reason codes. |
| [09-scalability.md](09-scalability.md) | Scalability analysis: sharding strategy, directory cardinality, ledger rotation, performance characteristics, cost model. |
| [10-local-staging.md](10-local-staging.md) | Local staging directory specification, sync commands, index shard merge strategy, incremental sync. |
| [11-deduplication.md](11-deduplication.md) | Content-addressed storage model, dedup check flows, collision handling, re-ingestion semantics. |

---

## 6. Terminology

| Term | Definition |
|------|-----------|
| **CAS** | Content-Addressed Storage. Objects are keyed by their cryptographic hash. |
| **Object** | A canonical binary file stored at its SHA-256-derived key. |
| **Metadata sidecar** | A `.meta.json` file stored alongside each object containing classification results. |
| **View** | A lightweight `.ref` pointer file organized in the classification tree (format/ISA/bits/endian). |
| **Ref file** | A small JSON file in the view tree that points back to the canonical object and metadata. |
| **Ledger** | An append-only NDJSON (newline-delimited JSON) file recording classification events. |
| **Index shard** | A TSV file mapping SHA-256 hashes to object keys, sharded by hash prefix. |
| **Run** | A single batch ingestion execution, identified by a unique run ID. |
| **Run manifest** | A JSON file recording run parameters, timing, and aggregate statistics. |
| **Staging directory** | A local directory that mirrors the exact S3 key layout for offline batch processing. |
| **Ambiguous** | A file whose classification confidence or margin is below threshold. |
| **Confidence** | A 0.0-1.0 score indicating how certain the classifier is about the primary ISA. |
| **Margin** | The ratio `(winner_score - runner_up_score) / runner_up_score`, measuring how decisive the classification is. |
| **Slug** | A filesystem/URL-safe string representation of a format or ISA name. |
| **Fanout** | The 2-level hex prefix sharding (`ab/cd/`) that limits directory cardinality. |
