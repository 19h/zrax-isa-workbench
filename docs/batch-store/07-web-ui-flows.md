# Web UI Interaction Flows

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

This document describes every user-facing flow in the web UI, the backend API calls each flow triggers, and the S3 operations behind them.

---

## 1. Page Structure

The web UI has the following pages:

| Page | URL Pattern | Purpose |
|------|-------------|---------|
| Dashboard | `/` | Statistics overview, recent runs, ISA/format breakdowns |
| Browse Classified | `/browse` | Hierarchical file tree: Format → ISA → Bits → Endian → Files |
| Browse Ambiguous | `/browse/ambiguous` | Ambiguous files: Reason → Format → Files |
| File Detail | `/files/{sha256}` | Full classification details for a single file |
| Upload | `/upload` | Drag-and-drop upload zone |
| Runs | `/runs` | Batch run history |
| Run Detail | `/runs/{run_id}` | Detailed statistics for a single run |

---

## 2. Flow: Dashboard Load

**User action**: Navigates to `/`.

**Sequence**:

```
Browser                   Backend                   S3
  │                         │                        │
  │  GET /api/v1/stats      │                        │
  │ ───────────────────────>│                        │
  │                         │  GetObject             │
  │                         │  stats/current.json    │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │ <───────────────────────│                        │
  │                         │                        │
  │  GET /api/v1/runs       │                        │
  │  ?limit=10              │                        │
  │ ───────────────────────>│                        │
  │                         │  ListObjectsV2         │
  │                         │  Prefix=runs/          │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │                         │  GetObject × 10        │
  │                         │  runs/<id>.json        │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │ <───────────────────────│                        │
```

**S3 calls**: 1 GetObject (stats) + 1 ListObjectsV2 (runs) + 10 GetObject (run manifests) = **12 calls**.

**Dashboard displays**:
- Total files, total bytes, classified/ambiguous/error counts
- Bar chart of top ISAs by count
- Bar chart of top formats by count
- Confidence distribution histogram
- Last 10 runs with summary stats
- Dedup savings (total bytes stored vs total bytes ingested)

---

## 3. Flow: Browse Classified Files

### 3.1 Level 1: Format Selection

**User action**: Clicks "Browse" in navigation.

```
Browser                   Backend                        S3
  │                         │                              │
  │  GET /api/v1/browse/    │                              │
  │  formats                │                              │
  │ ───────────────────────>│                              │
  │                         │  ListObjectsV2               │
  │                         │  Prefix=views/classified/    │
  │                         │  Delimiter=/                 │
  │                         │ ────────────────────────────>│
  │                         │ <────────────────────────────│
  │ <───────────────────────│                              │
```

**S3 calls**: 1.

**UI renders**: Grid of format cards (e.g., "ELF", "PE", "Raw", "Mach-O", "VBF") with counts from `stats/current.json` (cached from dashboard load or separate fetch).

### 3.2 Level 2: ISA Selection

**User action**: Clicks on a format card (e.g., "ELF").

```
Browser                   Backend                                  S3
  │                         │                                        │
  │  GET /api/v1/browse/    │                                        │
  │  formats/elf/isas       │                                        │
  │ ───────────────────────>│                                        │
  │                         │  ListObjectsV2                         │
  │                         │  Prefix=views/classified/fmt=elf/      │
  │                         │  Delimiter=/                           │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │ <───────────────────────│                                        │
```

**S3 calls**: 1.

**UI renders**: Grid of ISA cards (e.g., "AArch64", "x86-64", "ARM", "MIPS") with the ISA display name and icon.

### 3.3 Level 3: Bitwidth Selection

**User action**: Clicks on an ISA card (e.g., "AArch64").

**S3 calls**: 1 ListObjectsV2.

**UI renders**: Buttons for available bitwidths (e.g., "64-bit"). Often only one option; the UI may auto-select and skip to Level 4.

### 3.4 Level 4: Endianness Selection

**User action**: Clicks on a bitwidth (e.g., "64-bit").

**S3 calls**: 1 ListObjectsV2.

**UI renders**: Buttons for available endianness (e.g., "Little-endian"). Often only one option; the UI may auto-select and skip to Level 5.

### 3.5 Level 5: File Listing

**User action**: Reaches the leaf level (format + ISA + bits + endian selected).

**S3 calls**: 1 ListObjectsV2 (first page of 100 files).

**UI renders**: Paginated table with columns:

| Column | Source |
|--------|--------|
| Filename | Extracted from `.ref` key (part after `__`, before `.ref`) |
| SHA-256 (truncated) | Extracted from `.ref` key (part before `__`) |
| File Size | From ListObjectsV2 response `Size` field on the `.ref` object (not useful — ref is tiny). Better: from `.ref` JSON content fetched lazily. |
| Ingested At | From `.ref` JSON content (fetched on hover or bulk-loaded) |

**Optimization for file listing**: The backend can batch-fetch the first page of `.ref` files to populate the size/date columns. This adds 100 × GetObject calls but provides a richer listing. Alternative: embed file size in the `.ref` key name (ugly) or accept the lazy-loading approach.

**Recommended approach**: The backend fetches .ref objects in a parallel batch (100 concurrent GetObject) and returns the enriched file list. This adds **100 GetObject** calls for the first page but provides complete information.

**Total S3 calls for a full browse (format → file listing)**: 4 ListObjectsV2 + 100 GetObject = **104 calls**.

### 3.6 Pagination

**User action**: Clicks "Next Page" in the file listing.

**S3 calls**: 1 ListObjectsV2 (with ContinuationToken) + 100 GetObject (for .ref content) = **101 calls per page**.

---

## 4. Flow: View File Details

**User action**: Clicks on a file in the listing.

```
Browser                   Backend                                   S3
  │                         │                                         │
  │  GET /api/v1/files/     │                                         │
  │  {sha256}               │                                         │
  │ ───────────────────────>│                                         │
  │                         │  HeadObject                             │
  │                         │  objects/sha256/ab/cd/<hash>.bin        │
  │                         │ ───────────────────────────────────────>│
  │                         │ <───────────────────────────────────────│ 200
  │                         │                                         │
  │                         │  GetObject                              │
  │                         │  objects/sha256/ab/cd/<hash>.meta.json  │
  │                         │ ───────────────────────────────────────>│
  │                         │ <───────────────────────────────────────│
  │ <───────────────────────│                                         │
```

**S3 calls**: 1 HeadObject + 1 GetObject = **2 calls**.

**UI renders**:

```
┌─ File Detail ─────────────────────────────────────────────────┐
│                                                                │
│  SHA-256: a1b2c3d4e5f67890abcdef...                           │
│  Size:    1,048,576 bytes (1.0 MB)                            │
│  Names:   rkos, firmware.bin                                   │
│                                                                │
│  ┌─ Classification ──────────────────────────────────────────┐ │
│  │  Format:     ELF                                          │ │
│  │  ISA:        AArch64 (ARM64)                              │ │
│  │  Bitwidth:   64-bit                                       │ │
│  │  Endianness: Little-endian                                │ │
│  │  Confidence: 87.2%  ████████████████████░░░               │ │
│  │  Source:     File Format Headers                          │ │
│  │  Variant:    ARMv8.2-A (Cortex-A76)                       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─ Extensions ──────────────────────────────────────────────┐ │
│  │  NEON     (SIMD)   95.0%                                  │ │
│  │  VFPv4   (Float)  88.0%                                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─ Top Candidates ─────────────────────────────────────────┐  │
│  │  1. aarch64  (64-bit, LE)  score: 1,850,956  54.2%      │  │
│  │  2. i860     (32-bit, LE)  score: 1,213,193  19.2%      │  │
│  │  3. arm      (32-bit, LE)  score:   456,789   7.1%      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌─ Metadata ────────────────────────────────────────────────┐ │
│  │  Entry Point:  0x401000                                   │ │
│  │  Sections:     12                                         │ │
│  │  Flags:        0x00000005                                 │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─ Notes ───────────────────────────────────────────────────┐ │
│  │  [info] Detected system register access patterns          │ │
│  │  [info] Function prologue/epilogue patterns detected      │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌─ Provenance ──────────────────────────────────────────────┐ │
│  │  Run ID:     20260302T143022Z-batch-001                   │ │
│  │  Ingested:   2026-03-02 14:30:45 UTC                      │ │
│  │  Classifier: v0.1.0                                       │ │
│  │  Source:     /input/Firmware/rkos                          │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  [ Download ]  [ Reclassify ]  [ Delete ]                      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## 5. Flow: Download Binary

**User action**: Clicks "Download" on the file detail page.

```
Browser                   Backend                                  S3
  │                         │                                        │
  │  GET /api/v1/files/     │                                        │
  │  {sha256}/download      │                                        │
  │ ───────────────────────>│                                        │
  │                         │  GetObject                             │
  │                         │  objects/sha256/ab/cd/<hash>.bin       │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──── (streaming response) ───────────│
  │ <──── (streaming) ──────│                                        │
```

**S3 calls**: 1 GetObject.

The backend proxies the S3 response stream directly to the browser. It sets:
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="rkos"`
- `Content-Length: 1048576`

The browser initiates a file download with the original filename.

---

## 6. Flow: Drag-and-Drop Upload

### 6.1 User Drags File onto Upload Zone

**User action**: Drags a file from desktop into the browser upload area.

The browser reads the file client-side and sends it to the backend:

```
Browser                   Backend                                  S3
  │                         │                                        │
  │  POST /api/v1/files/    │                                        │
  │  upload                 │                                        │
  │  (multipart/form-data)  │                                        │
  │  file=<binary>          │                                        │
  │ ───────────────────────>│                                        │
  │                         │  ── compute SHA-256 ──                 │
  │                         │                                        │
  │                         │  HeadObject (dedup)                    │
  │                         │  objects/sha256/ab/cd/<hash>.bin       │
  │                         │ ──────────────────────────────────────>│
  │                         │ <─────────────────────────────────────│
```

### 6.2 If Duplicate (HeadObject returns 200)

```
  │                         │  GetObject (existing meta)             │
  │                         │  objects/sha256/ab/cd/<hash>.meta.json │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │ <───────────────────────│                                        │
  │  200 OK                 │                                        │
  │  { "is_duplicate": true,│                                        │
  │    "classification": ...}│                                       │
```

**S3 calls**: 1 HeadObject + 1 GetObject = **2 calls**.

**UI shows**: "This file already exists in the store. Classification: AArch64 (87.2% confidence)" with a link to the existing file detail page.

### 6.3 If New File (HeadObject returns 404)

```
  │                         │  ── classify in-memory ──              │
  │                         │                                        │
  │                         │  PutObject (binary)                    │
  │                         │  objects/sha256/ab/cd/<hash>.bin       │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  PutObject (metadata)                  │
  │                         │  objects/sha256/ab/cd/<hash>.meta.json │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  PutObject (view ref)                  │
  │                         │  views/classified/fmt=.../...ref       │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  (index/ledger update — batched)       │
  │                         │                                        │
  │ <───────────────────────│                                        │
  │  201 Created            │                                        │
  │  { "is_duplicate": false,│                                       │
  │    "status": "classified",│                                      │
  │    "classification": ...}│                                       │
```

**S3 calls**: 1 HeadObject + 3 PutObject + amortized index/ledger = **4-8 calls**.

**UI shows**: Classification result card with format, ISA, confidence, candidates. Animation showing the file being placed into the correct classification folder. Link to the new file detail page.

### 6.4 Upload Progress

For large files, the browser shows a progress bar during upload. The backend receives the full file before processing (no streaming classification). Progress stages shown to user:

1. **Uploading** (0-50%): File transfer from browser to backend
2. **Hashing** (50-55%): SHA-256 computation
3. **Checking** (55-60%): Dedup check
4. **Classifying** (60-90%): Format detection + ISA classification
5. **Storing** (90-100%): Upload to S3

### 6.5 Multiple File Upload

The upload zone supports multiple files (drag multiple or use file picker). Each file is processed sequentially by the backend to avoid overwhelming S3 with concurrent writes. The UI shows a queue:

```
┌─ Upload Queue ─────────────────────────────────────────────┐
│                                                             │
│  ✓  firmware_v1.bin    AArch64 (ELF)   87.2%  classified   │
│  ✓  bootloader.raw     ARM (Raw)       34.1%  ambiguous    │
│  ⟳  kernel.elf         Classifying...  ████████░░  80%     │
│  ○  driver.ko          Queued                               │
│  ○  unknown.blob       Queued                               │
│                                                             │
│  Processed: 2/5    Duplicates: 0    Errors: 0              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Flow: Reclassify File

**User action**: Clicks "Reclassify" on the file detail page.

**UI shows**: Confirmation dialog: "Re-run classification on this file with the current classifier version? This may change the ISA detection and move the file to a different category."

**On confirm**:

```
Browser                   Backend                                  S3
  │                         │                                        │
  │  POST /api/v1/files/    │                                        │
  │  {sha256}/reclassify    │                                        │
  │ ───────────────────────>│                                        │
  │                         │  GetObject (binary)                    │
  │                         │  objects/sha256/ab/cd/<hash>.bin       │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  ── classify in-memory ──              │
  │                         │                                        │
  │                         │  GetObject (old metadata)              │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  DeleteObject (old view ref)           │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  PutObject (new metadata)              │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │                         │  PutObject (new view ref)              │
  │                         │ ──────────────────────────────────────>│
  │                         │ <──────────────────────────────────────│
  │                         │                                        │
  │ <───────────────────────│                                        │
  │  200 OK                 │                                        │
  │  { "changed": true,     │                                        │
  │    "previous": {...},   │                                        │
  │    "current": {...} }   │                                        │
```

**UI shows**: Before/after comparison:

```
┌─ Reclassification Result ─────────────────────────────────────┐
│                                                                │
│  Previous:  ARM (32-bit, LE)    34.1% confidence               │
│  Current:   AArch64 (64-bit, LE)  87.2% confidence            │
│                                                                │
│  Status: Classification changed                                │
│  File moved from: views/ambiguous/... → views/classified/...  │
│                                                                │
│  [ View Updated Details ]                                      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## 8. Flow: Delete File

**User action**: Clicks "Delete" on the file detail page.

**UI shows**: Confirmation dialog: "Permanently delete this file and all associated metadata? This action cannot be undone."

**On confirm**:

```
Browser                   Backend                   S3
  │                         │                        │
  │  DELETE /api/v1/files/  │                        │
  │  {sha256}               │                        │
  │ ───────────────────────>│                        │
  │                         │  (6-8 S3 calls)        │
  │                         │  See §8 of             │
  │                         │  05-s3-api-calls.md    │
  │ <───────────────────────│                        │
  │  204 No Content         │                        │
```

**UI shows**: Success toast: "File deleted successfully." Redirects to the previous browse page.

---

## 9. Flow: Search by Hash

**User action**: Enters a SHA-256 hash in the search bar.

**UI validates**: Hash must be exactly 64 hex characters. Show inline validation error otherwise.

```
Browser                   Backend                   S3
  │                         │                        │
  │  GET /api/v1/files/     │                        │
  │  {sha256}               │                        │
  │ ───────────────────────>│                        │
  │                         │  HeadObject            │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │                         │                        │
  │                         │  GetObject (meta)      │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │ <───────────────────────│                        │
```

**If found**: Redirect to `/files/{sha256}` detail page.

**If not found**: Show "No file found with this hash."

**S3 calls**: 1 HeadObject + 1 GetObject = **2 calls** (or 1 HeadObject if not found).

---

## 10. Flow: Browse Runs

**User action**: Navigates to `/runs`.

```
Browser                   Backend                   S3
  │                         │                        │
  │  GET /api/v1/runs       │                        │
  │  ?limit=20              │                        │
  │ ───────────────────────>│                        │
  │                         │  ListObjectsV2 (runs/) │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │                         │  GetObject × 20        │
  │                         │ ──────────────────────>│
  │                         │ <──────────────────────│
  │ <───────────────────────│                        │
```

**UI renders**: Table of runs:

| Run ID | Type | Status | Files | Duration | Classified | Ambiguous | Errors |
|--------|------|--------|-------|----------|-----------|-----------|--------|
| 20260302T143022Z-batch-001 | Batch | Completed | 1,003,456 | 1h 14m | 892,341 | 98,765 | 2,116 |

**S3 calls**: 1 ListObjectsV2 + 20 GetObject = **21 calls**.

Clicking on a run navigates to `/runs/{run_id}` which shows the full run manifest (1 GetObject).
