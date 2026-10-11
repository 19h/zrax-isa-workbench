# Zrax Batch Store - Design Documentation

Specification for Zrax batch classification, storage, and retrieval. The implemented CLI writes local staging files; external tools perform uploads. The S3 API, REST API, hosted browsing interface, reclassification commands, and remote deduplication in these documents describe designs, not implemented services. The browser workbench is the separate, local-file application in `web/`.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 1 | [01-overview.md](01-overview.md) | Architecture overview, motivation, design principles, component descriptions, terminology |
| 2 | [02-s3-key-layout.md](02-s3-key-layout.md) | Complete S3 key structure: objects, views, index, ledgers, runs, stats. Slug derivation rules, fanout sharding, key length analysis, enumeration examples |
| 3 | [03-schemas.md](03-schemas.md) | All data schemas: metadata JSON (`.meta.json`), ledger NDJSON (`.jsonl.zst`), index shard TSV (`.idx`), ref pointer (`.ref`), run manifest, statistics file. Full field-level reference |
| 4 | [04-batch-ingestion.md](04-batch-ingestion.md) | CLI batch mode: command-line interface, pipeline architecture (walker → hasher → classifier → writer), worker model, TUI dashboard layout, staging output, graceful shutdown, incremental runs |
| 5 | [05-s3-api-calls.md](05-s3-api-calls.md) | Exhaustive enumeration of every S3 API call for every interaction: batch ingestion, web browsing, upload, search, delete, reclassify, dashboard. Cost estimates. Error handling |
| 6 | [06-web-api.md](06-web-api.md) | REST API specification: all endpoints, request/response formats, pagination, error codes, S3 call mapping per endpoint |
| 7 | [07-web-ui-flows.md](07-web-ui-flows.md) | Web UI interaction flows with sequence diagrams: dashboard, browse, file detail, download, drag-and-drop upload, reclassify, delete, search, run history |
| 8 | [08-ambiguous-routing.md](08-ambiguous-routing.md) | Ambiguous file routing logic: decision flowchart, threshold rules (confidence, margin, error, unknown ISA), confidence bands, reclassification workflows |
| 9 | [09-scalability.md](09-scalability.md) | Scalability analysis: sharding math, ListObjectsV2 performance, ledger sizing, index sizing, storage costs, concurrency model, failure modes and recovery, future considerations |
| 10 | [10-local-staging.md](10-local-staging.md) | Local staging directory: structure, file creation semantics, atomicity, disk space/inode requirements, index shard merge algorithm, sync commands (rclone/s3cmd/aws-cli), cleanup, filesystem recommendations |
| 11 | [11-deduplication.md](11-deduplication.md) | Content-addressed storage model, SHA-256 properties, four dedup strategies (none, local, remote, hybrid), duplicate handling behavior, re-ingestion semantics, edge cases |

## Quick Reference

### S3 Operations Used

The entire system uses exactly 6 S3 API operations: `HeadObject`, `GetObject`, `PutObject`, `CreateMultipartUpload`+`UploadPart`+`CompleteMultipartUpload`, `DeleteObject`, `ListObjectsV2`. Compatible with all S3-compatible backends including Hetzner.

### Key Layout Summary

```
<prefix>/objects/sha256/<ab>/<cd>/<hash>.bin          # canonical binary
<prefix>/objects/sha256/<ab>/<cd>/<hash>.meta.json    # classification metadata
<prefix>/views/classified/fmt=.../isa=.../bits=.../endian=.../<ab>/<cd>/<hash>__<name>.ref
<prefix>/views/ambiguous/reason=.../fmt=.../<ab>/<cd>/<hash>__<name>.ref
<prefix>/index/sha256/<ab>/<cd>.idx                   # hash lookup shard (TSV)
<prefix>/ledgers/global/<run_id>/<seq>.jsonl.zst      # append-only audit trail
<prefix>/ledgers/isa=<isa>/<run_id>/<seq>.jsonl.zst   # per-ISA audit trail
<prefix>/runs/<run_id>.json                           # run manifest
<prefix>/stats/current.json                           # aggregate statistics
```

### Batch Ingestion Quick Start

```bash
# Classify 1M firmware files in parallel
zrax batch -i /data/firmware -o /staging/run-001 -j 16

# Upload to S3
rclone sync /staging/run-001/ hetzner:bucket/isa-harvester/v1/ --transfers 32 --progress
```
