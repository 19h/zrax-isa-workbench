# Web Backend REST API Specification

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. General Conventions

### 1.1 Base URL

```
https://<host>:<port>/api/v1
```

### 1.2 Content Types

| Direction | Content-Type |
|-----------|-------------|
| Request body (JSON) | `application/json` |
| Request body (upload) | `multipart/form-data` |
| Response body (JSON) | `application/json` |
| Response body (binary download) | `application/octet-stream` |

### 1.3 Pagination

All list endpoints support cursor-based pagination:

| Query Parameter | Type | Description |
|----------------|------|-------------|
| `limit` | integer | Max items per page (default: 100, max: 1000) |
| `cursor` | string | Opaque continuation token from previous response |

Response includes:

```json
{
  "items": [...],
  "next_cursor": "eyJrZXkiOiAiLi4uIn0=",
  "has_more": true,
  "total_estimate": 12345
}
```

The `cursor` is a base64-encoded `ContinuationToken` from S3's `ListObjectsV2`. The `total_estimate` is approximate (from the last stats update, not a live count).

### 1.4 Error Responses

All errors return:

```json
{
  "error": {
    "code": "not_found",
    "message": "File with hash abc123... not found",
    "details": null
  }
}
```

| HTTP Status | Error Code | Description |
|------------|-----------|-------------|
| 400 | `bad_request` | Invalid parameters |
| 404 | `not_found` | Object does not exist |
| 409 | `conflict` | Concurrent modification |
| 413 | `payload_too_large` | Upload exceeds size limit |
| 422 | `unprocessable_entity` | File could not be classified |
| 500 | `internal_error` | Server error |
| 502 | `upstream_error` | S3 backend error |
| 503 | `service_unavailable` | S3 backend unavailable |

---

## 2. Browse Endpoints

### 2.1 List Formats

```
GET /api/v1/browse/formats
```

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/classified/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "formats": [
    {
      "slug": "elf",
      "display_name": "ELF",
      "prefix": "views/classified/fmt=elf/"
    },
    {
      "slug": "pe",
      "display_name": "PE/COFF",
      "prefix": "views/classified/fmt=pe/"
    },
    {
      "slug": "raw",
      "display_name": "Raw",
      "prefix": "views/classified/fmt=raw/"
    }
  ]
}
```

The backend extracts the slug from each `CommonPrefix` (e.g., `fmt=elf/` → `elf`) and maps it to the display name via a static lookup table.

### 2.2 List ISAs Within Format

```
GET /api/v1/browse/formats/{format_slug}/isas
```

**Path Parameters**:
- `format_slug`: Format slug (e.g., `elf`, `pe`, `raw`)

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/classified/fmt=<format_slug>/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "format": "elf",
  "isas": [
    {
      "slug": "aarch64",
      "display_name": "AArch64 (ARM64)",
      "prefix": "views/classified/fmt=elf/isa=aarch64/"
    },
    {
      "slug": "x86_64",
      "display_name": "x86-64 (AMD64)",
      "prefix": "views/classified/fmt=elf/isa=x86_64/"
    }
  ]
}
```

### 2.3 List Bitwidths

```
GET /api/v1/browse/formats/{format_slug}/isas/{isa_slug}/bits
```

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/classified/fmt=<format>/isa=<isa>/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "format": "elf",
  "isa": "aarch64",
  "bitwidths": [
    { "value": 64, "prefix": "views/classified/fmt=elf/isa=aarch64/bits=64/" }
  ]
}
```

### 2.4 List Endianness

```
GET /api/v1/browse/formats/{format_slug}/isas/{isa_slug}/bits/{bitwidth}/endian
```

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/classified/fmt=<format>/isa=<isa>/bits=<bits>/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "format": "elf",
  "isa": "aarch64",
  "bitwidth": 64,
  "endianness": [
    { "slug": "le", "display_name": "Little-endian", "prefix": "..." }
  ]
}
```

### 2.5 List Files (Leaf Level)

```
GET /api/v1/browse/formats/{format_slug}/isas/{isa_slug}/bits/{bitwidth}/endian/{endian_slug}/files?limit=100&cursor=...
```

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/classified/fmt=<f>/isa=<i>/bits=<b>/endian=<e>/`, `MaxKeys=<limit>`, `ContinuationToken=<cursor>`

**Response** `200 OK`:

```json
{
  "format": "elf",
  "isa": "aarch64",
  "bitwidth": 64,
  "endianness": "le",
  "files": [
    {
      "sha256": "a1b2c3d4...",
      "original_name": "rkos",
      "ref_key": "views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/a1/b2/a1b2c3d4....__rkos.ref",
      "size_bytes": 1048576
    }
  ],
  "next_cursor": "...",
  "has_more": true,
  "total_estimate": 12345
}
```

The backend parses the `.ref` filename to extract the SHA-256 hash and original name. The hash is everything before `__`, the name is everything after `__` (minus `.ref`).

### 2.6 List Ambiguous Reasons

```
GET /api/v1/browse/ambiguous/reasons
```

**S3 Calls**: 1 × `ListObjectsV2`

**S3 Parameters**: `Prefix=<P>/views/ambiguous/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "reasons": [
    { "code": "low_conf", "display_name": "Low Confidence", "prefix": "..." },
    { "code": "low_margin", "display_name": "Low Margin", "prefix": "..." },
    { "code": "error", "display_name": "Classification Error", "prefix": "..." },
    { "code": "unknown_isa", "display_name": "Unknown ISA", "prefix": "..." }
  ]
}
```

### 2.7 List Ambiguous Formats

```
GET /api/v1/browse/ambiguous/reasons/{reason_code}/formats
```

**S3 Calls**: 1 × `ListObjectsV2`

**Response**: Same structure as 2.1 but under ambiguous path.

### 2.8 List Ambiguous Files

```
GET /api/v1/browse/ambiguous/reasons/{reason_code}/formats/{format_slug}/files?limit=100&cursor=...
```

**S3 Calls**: 1 × `ListObjectsV2`

**Response**: Same structure as 2.5.

---

## 3. File Endpoints

### 3.1 Get File by SHA-256

```
GET /api/v1/files/{sha256}
```

**Path Parameters**:
- `sha256`: Full 64-character hex SHA-256 hash

**S3 Calls**:
1. `HeadObject` on `<P>/objects/sha256/<ab>/<cd>/<hash>.bin` — existence check
2. `GetObject` on `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json` — fetch metadata

**Response** `200 OK`:

```json
{
  "sha256": "a1b2c3d4...",
  "file_size": 1048576,
  "classification": {
    "format": "elf",
    "format_display": "ELF",
    "isa": "aarch64",
    "isa_display": "AArch64 (ARM64)",
    "bitwidth": 64,
    "endianness": "little",
    "confidence": 0.872,
    "source": "file_format",
    "variant": { "name": "ARMv8.2-A", "profile": "Cortex-A76", "abi": null }
  },
  "candidates": [...],
  "extensions": [...],
  "metadata": [...],
  "notes": [...],
  "names": {
    "original_names": ["rkos"],
    "original_paths": ["Firmware/t2026phoneG1/Release/ftab_dump/rkos"]
  },
  "routing": {
    "status": "classified",
    "view_key": "views/classified/...",
    "ambiguous_reason": null
  },
  "provenance": {
    "run_id": "20260302T143022Z-batch-001",
    "classifier_version": "0.1.0",
    "ingested_at": "2026-03-02T14:30:45Z"
  },
  "download_url": "/api/v1/files/a1b2c3d4.../download"
}
```

**Response** `404 Not Found` if hash not in store.

### 3.2 Check File Existence

```
HEAD /api/v1/files/{sha256}
```

**S3 Calls**: 1 × `HeadObject` on `<P>/objects/sha256/<ab>/<cd>/<hash>.bin`

**Response**:
- `200 OK` with `Content-Length` header (file size) — file exists
- `404 Not Found` — file does not exist

No response body.

### 3.3 Download File Binary

```
GET /api/v1/files/{sha256}/download
```

**S3 Calls**: 1 × `GetObject` on `<P>/objects/sha256/<ab>/<cd>/<hash>.bin`

**Response** `200 OK`:
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="<original_name>"`
- `Content-Length: <file_size>`
- Body: raw binary stream proxied from S3

The backend reads the metadata first (from in-memory cache or S3) to determine the original filename for the `Content-Disposition` header. If no cached metadata is available, a preliminary `GetObject` on the `.meta.json` is required (+1 S3 call).

### 3.4 Upload File

```
POST /api/v1/files/upload
Content-Type: multipart/form-data
```

**Form Fields**:
- `file` (required): The binary file
- `original_name` (optional): Override filename (default: use upload filename)
- `source_path` (optional): Original path for provenance tracking
- `force_reclassify` (optional, boolean): Reclassify even if duplicate

**Processing**:
1. Backend receives entire file into memory/temp buffer
2. Computes SHA-256
3. `HeadObject` dedup check
4. If duplicate and not `force_reclassify`: return existing metadata
5. If new: classify file, upload to S3 (see [05-s3-api-calls.md](05-s3-api-calls.md) Section 4)
6. Return classification result

**S3 Calls** (new file): 1 × `HeadObject` + 3 × `PutObject` + index/ledger amortized = **4-8 calls**

**S3 Calls** (duplicate): 1 × `HeadObject` + 1 × `GetObject` = **2 calls**

**Response** `201 Created` (new file):

```json
{
  "sha256": "a1b2c3d4...",
  "status": "classified",
  "is_duplicate": false,
  "classification": { ... },
  "candidates": [ ... ],
  "extensions": [ ... ],
  "download_url": "/api/v1/files/a1b2c3d4.../download"
}
```

**Response** `200 OK` (duplicate):

```json
{
  "sha256": "a1b2c3d4...",
  "status": "duplicate",
  "is_duplicate": true,
  "classification": { ... },
  "download_url": "/api/v1/files/a1b2c3d4.../download"
}
```

### 3.5 Delete File

```
DELETE /api/v1/files/{sha256}
```

**S3 Calls**: See [05-s3-api-calls.md](05-s3-api-calls.md) Section 8. **6-8 calls.**

**Response** `204 No Content` on success.

**Response** `404 Not Found` if hash not in store.

### 3.6 Reclassify File

```
POST /api/v1/files/{sha256}/reclassify
```

**S3 Calls**: See [05-s3-api-calls.md](05-s3-api-calls.md) Section 9. **5-8 calls.**

**Response** `200 OK`:

```json
{
  "sha256": "a1b2c3d4...",
  "previous": {
    "isa": "arm",
    "confidence": 0.34
  },
  "current": {
    "isa": "aarch64",
    "confidence": 0.87
  },
  "changed": true,
  "reclassified_count": 1
}
```

---

## 4. Ledger Endpoints

### 4.1 List Global Ledger Runs

```
GET /api/v1/ledger/global/runs
```

**S3 Calls**: 1 × `ListObjectsV2` on `<P>/ledgers/global/`, `Delimiter=/`

**Response** `200 OK`:

```json
{
  "runs": [
    { "run_id": "20260302T143022Z-batch-001", "prefix": "ledgers/global/20260302T143022Z-batch-001/" },
    { "run_id": "20260301T091500Z-batch-001", "prefix": "ledgers/global/20260301T091500Z-batch-001/" }
  ]
}
```

### 4.2 List Ledger Segments for a Run

```
GET /api/v1/ledger/global/runs/{run_id}/segments
```

**S3 Calls**: 1 × `ListObjectsV2` on `<P>/ledgers/global/<run_id>/`

**Response** `200 OK`:

```json
{
  "run_id": "20260302T143022Z-batch-001",
  "segments": [
    { "key": "ledgers/global/20260302T143022Z-batch-001/000001.jsonl.zst", "size_bytes": 2345678 },
    { "key": "ledgers/global/20260302T143022Z-batch-001/000002.jsonl.zst", "size_bytes": 1987654 }
  ]
}
```

### 4.3 Download Ledger Segment

```
GET /api/v1/ledger/global/runs/{run_id}/segments/{sequence}
```

**Query Parameters**:
- `format`: `raw` (compressed .zst, default) or `json` (decompressed, parsed to JSON array)

**S3 Calls**: 1 × `GetObject` on `<P>/ledgers/global/<run_id>/<sequence>.jsonl.zst`

**Response** `200 OK`:
- If `format=raw`: Stream compressed data with `Content-Type: application/zstd`
- If `format=json`: Decompress and return JSON array with `Content-Type: application/json`

### 4.4 ISA-Specific Ledger Endpoints

Same pattern as global, under `/api/v1/ledger/isa/{isa_slug}/...`

```
GET /api/v1/ledger/isa/{isa_slug}/runs
GET /api/v1/ledger/isa/{isa_slug}/runs/{run_id}/segments
GET /api/v1/ledger/isa/{isa_slug}/runs/{run_id}/segments/{sequence}
```

---

## 5. Run Endpoints

### 5.1 List Runs

```
GET /api/v1/runs?limit=20&cursor=...
```

**S3 Calls**: 1 × `ListObjectsV2` on `<P>/runs/`, `MaxKeys=<limit>`

**Response** `200 OK`:

```json
{
  "runs": [
    {
      "run_id": "20260302T143022Z-batch-001",
      "type": "batch",
      "status": "completed",
      "files_processed": 1003456,
      "duration_seconds": 4488,
      "completed_at": "2026-03-02T15:45:10Z"
    }
  ],
  "next_cursor": "...",
  "has_more": false
}
```

The backend fetches the first `limit` run manifest keys, then batch-fetches each manifest with `GetObject` to extract summary fields.

**S3 Calls**: 1 × `ListObjectsV2` + N × `GetObject` (one per run manifest).

### 5.2 Get Run Details

```
GET /api/v1/runs/{run_id}
```

**S3 Calls**: 1 × `GetObject` on `<P>/runs/<run_id>.json`

**Response** `200 OK`: Full run manifest JSON (see [03-schemas.md](03-schemas.md) Section 4).

---

## 6. Statistics Endpoint

### 6.1 Get Current Statistics

```
GET /api/v1/stats
```

**S3 Calls**: 1 × `GetObject` on `<P>/stats/current.json`

**Response** `200 OK`: Full statistics JSON (see [03-schemas.md](03-schemas.md) Section 6).

---

## 7. Index Endpoints (Machine-to-Machine)

These endpoints are primarily for programmatic consumers, not the web UI.

### 7.1 List Index Shards

```
GET /api/v1/index/shards?prefix=a1&limit=1000&cursor=...
```

**Query Parameters**:
- `prefix` (optional): Filter shards by first-level prefix (e.g., `a1` lists only `a1/*.idx`)

**S3 Calls**: 1 × `ListObjectsV2` on `<P>/index/sha256/<prefix>/` (or `<P>/index/sha256/` if no prefix)

### 7.2 Download Index Shard

```
GET /api/v1/index/shards/{ab}/{cd}
```

**S3 Calls**: 1 × `GetObject` on `<P>/index/sha256/<ab>/<cd>.idx`

**Response** `200 OK`: Raw TSV content with `Content-Type: text/tab-separated-values`

---

## 8. Health and Readiness

### 8.1 Health Check

```
GET /api/v1/health
```

**S3 Calls**: 0 (returns immediately)

**Response** `200 OK`:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 86400
}
```

### 8.2 Readiness Check

```
GET /api/v1/ready
```

**S3 Calls**: 1 × `HeadObject` on `<P>/stats/current.json` (verify S3 connectivity)

**Response** `200 OK` if S3 is reachable, `503 Service Unavailable` if not.

---

## 9. Complete Endpoint Summary

| Method | Path | S3 Calls | Purpose |
|--------|------|----------|---------|
| `GET` | `/browse/formats` | 1 ListObjectsV2 | List all formats |
| `GET` | `/browse/formats/{fmt}/isas` | 1 ListObjectsV2 | List ISAs in format |
| `GET` | `/browse/formats/{fmt}/isas/{isa}/bits` | 1 ListObjectsV2 | List bitwidths |
| `GET` | `/browse/formats/{fmt}/isas/{isa}/bits/{b}/endian` | 1 ListObjectsV2 | List endianness |
| `GET` | `/browse/formats/{fmt}/isas/{isa}/bits/{b}/endian/{e}/files` | 1 ListObjectsV2 | List files (paginated) |
| `GET` | `/browse/ambiguous/reasons` | 1 ListObjectsV2 | List ambiguous reasons |
| `GET` | `/browse/ambiguous/reasons/{r}/formats` | 1 ListObjectsV2 | List formats in ambiguous reason |
| `GET` | `/browse/ambiguous/reasons/{r}/formats/{f}/files` | 1 ListObjectsV2 | List ambiguous files |
| `GET` | `/files/{sha256}` | 1 HeadObject + 1 GetObject | Get file metadata |
| `HEAD` | `/files/{sha256}` | 1 HeadObject | Check existence |
| `GET` | `/files/{sha256}/download` | 1 GetObject | Download binary |
| `POST` | `/files/upload` | 2-8 (varies) | Upload and classify |
| `DELETE` | `/files/{sha256}` | 6-8 | Delete file |
| `POST` | `/files/{sha256}/reclassify` | 5-8 | Reclassify file |
| `GET` | `/ledger/global/runs` | 1 ListObjectsV2 | List ledger runs |
| `GET` | `/ledger/global/runs/{id}/segments` | 1 ListObjectsV2 | List segments |
| `GET` | `/ledger/global/runs/{id}/segments/{seq}` | 1 GetObject | Download segment |
| `GET` | `/ledger/isa/{isa}/runs` | 1 ListObjectsV2 | ISA ledger runs |
| `GET` | `/ledger/isa/{isa}/runs/{id}/segments` | 1 ListObjectsV2 | ISA segments |
| `GET` | `/ledger/isa/{isa}/runs/{id}/segments/{seq}` | 1 GetObject | ISA segment download |
| `GET` | `/runs` | 1 ListObjectsV2 + N GetObject | List runs |
| `GET` | `/runs/{id}` | 1 GetObject | Get run details |
| `GET` | `/stats` | 1 GetObject | Get statistics |
| `GET` | `/index/shards` | 1 ListObjectsV2 | List index shards |
| `GET` | `/index/shards/{ab}/{cd}` | 1 GetObject | Download shard |
| `GET` | `/health` | 0 | Health check |
| `GET` | `/ready` | 1 HeadObject | Readiness check |
