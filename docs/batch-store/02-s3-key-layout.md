# S3 Key Layout Specification

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Prefix Convention

All keys in this system live under a configurable root prefix. The default is:

```
isa-harvester/v1/
```

The `v1` component is a schema version. If the key layout changes in a breaking way, the prefix increments to `v2`, allowing migration while old data remains accessible. Throughout this document, `<P>` denotes this prefix.

---

## 2. Complete Key Tree

```
<P>/
├── objects/
│   └── sha256/
│       └── <ab>/
│           └── <cd>/
│               ├── <full_sha256_hex>.bin
│               └── <full_sha256_hex>.meta.json
│
├── views/
│   ├── classified/
│   │   └── fmt=<format_slug>/
│   │       └── isa=<isa_slug>/
│   │           └── bits=<bitwidth>/
│   │               └── endian=<le|be|bi>/
│   │                   └── <ab>/
│   │                       └── <cd>/
│   │                           └── <full_sha256_hex>__<sanitized_name>.ref
│   │
│   └── ambiguous/
│       └── reason=<reason_code>/
│           └── fmt=<format_slug>/
│               └── <ab>/
│                   └── <cd>/
│                       └── <full_sha256_hex>__<sanitized_name>.ref
│
├── index/
│   └── sha256/
│       └── <ab>/
│           └── <cd>.idx
│
├── ledgers/
│   ├── global/
│   │   └── <run_id>/
│   │       └── <sequence_number>.jsonl.zst
│   │
│   └── isa=<isa_slug>/
│       └── <run_id>/
│           └── <sequence_number>.jsonl.zst
│
├── runs/
│   └── <run_id>.json
│
└── stats/
    └── current.json
```

---

## 3. Key Components in Detail

### 3.1 `objects/` — Canonical Binary Storage (Content-Addressed)

This is the single source of truth for all binary data and metadata.

#### Binary Object

```
<P>/objects/sha256/<ab>/<cd>/<full_sha256_hex>.bin
```

- **Content**: The raw binary file bytes, unmodified.
- **Content-Type**: `application/octet-stream`
- **Size**: Varies (1 byte to multi-GB firmware images)
- **Immutability**: Once written, never overwritten (same hash = same content). Safe to cache indefinitely.
- **Example**: `isa-harvester/v1/objects/sha256/a1/b2/a1b2c3d4e5f6...64_hex_chars.bin`

#### Metadata Sidecar

```
<P>/objects/sha256/<ab>/<cd>/<full_sha256_hex>.meta.json
```

- **Content**: JSON document containing full classification results. See [03-schemas.md](03-schemas.md) for schema.
- **Content-Type**: `application/json`
- **Size**: Typically 1-10 KB.
- **Mutability**: May be overwritten on reclassification. The `provenance.reclassified_count` field tracks how many times this has happened.
- **Example**: `isa-harvester/v1/objects/sha256/a1/b2/a1b2c3d4e5f6...64_hex_chars.meta.json`

#### Hash Fanout Sharding

The `<ab>/<cd>` path components are derived from the first 4 hex characters of the SHA-256 hash:

```
SHA-256: a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789
         ^^^^
         ab = "a1"
         cd = "b2"
```

This creates a 2-level fanout of 256 x 256 = 65,536 shards. With 1 million files, each shard contains ~15 objects on average. With 10 million files, ~153 objects per shard. This keeps `ListObjectsV2` responses small and fast for any single shard.

**Why 2 levels?** One level (256 shards) would give ~3900 objects per shard at 1M files — still manageable but less efficient for listing. Three levels would create mostly-empty intermediate directories at typical corpus sizes. Two levels is the sweet spot.

### 3.2 `views/` — Classification Views (Pointer Files)

Views are lightweight `.ref` files organized in a hierarchical tree that enables browsing by classification dimensions.

#### Classified View

```
<P>/views/classified/fmt=<format_slug>/isa=<isa_slug>/bits=<bitwidth>/endian=<endianness>/<ab>/<cd>/<hash>__<name>.ref
```

**Dimension breakdown:**

| Dimension | Key component | Values | Examples |
|-----------|--------------|--------|----------|
| Format | `fmt=<slug>` | All supported file formats, slugified | `fmt=elf`, `fmt=pe`, `fmt=macho`, `fmt=raw`, `fmt=vbf`, `fmt=sgo` |
| ISA | `isa=<slug>` | All supported ISAs from `Isa::Display` | `isa=aarch64`, `isa=x86_64`, `isa=arm`, `isa=tricore`, `isa=ppcvle` |
| Bitwidth | `bits=<N>` | 8, 16, 32, 64, 128 | `bits=32`, `bits=64` |
| Endianness | `endian=<e>` | `le`, `be`, `bi` | `endian=le`, `endian=be` |
| Hash shard | `<ab>/<cd>/` | First 4 hex chars | `a1/b2/` |
| Filename | `<hash>__<name>.ref` | Full hash + sanitized original name | `a1b2c3d4....__firmware.ref` |

**Example complete key:**

```
isa-harvester/v1/views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/a1/b2/a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789__rkos.ref
```

**Ref file content:** See [03-schemas.md](03-schemas.md) Section 5 for the `.ref` JSON schema.

#### Ambiguous View

```
<P>/views/ambiguous/reason=<reason_code>/fmt=<format_slug>/<ab>/<cd>/<hash>__<name>.ref
```

Files routed to the ambiguous view have **fewer** path dimensions than classified files. This is deliberate: an ambiguous file's ISA/bits/endian classification is unreliable, so embedding it in the path would be misleading. The format dimension is retained because format detection (magic bytes, headers) is generally reliable even when ISA heuristics fail.

**Reason codes:**

| Code | Meaning |
|------|---------|
| `low_conf` | Primary ISA confidence below threshold (default: 0.30) |
| `low_margin` | Winner's margin over runner-up below threshold (default: 0.20) |
| `error` | Classification engine returned an error or was inconclusive |
| `unknown_isa` | Detected ISA is `Unknown(n)` |

**Example:**

```
isa-harvester/v1/views/ambiguous/reason=low_conf/fmt=raw/a1/b2/a1b2c3d4....__unknown_blob.ref
```

### 3.3 `index/` — Hash Lookup Shards

```
<P>/index/sha256/<ab>/<cd>.idx
```

Each index shard is a TSV (tab-separated values) file that maps SHA-256 hashes to their object keys and classification summary. This enables bulk enumeration without walking the view tree.

- **Content**: TSV with one line per object. See [03-schemas.md](03-schemas.md) Section 6.
- **Content-Type**: `text/tab-separated-values`
- **Size**: Grows with files in that shard. At ~200 bytes/line and ~15 files/shard at 1M total, ~3 KB/shard.
- **Mutability**: Rewritten on each batch run that touches files in this shard (read-modify-write).

**Example key**: `isa-harvester/v1/index/sha256/a1/b2.idx`

There are at most 65,536 index shards (256 x 256). Total index size at 1 million files: ~200 MB. At 10 million files: ~2 GB.

### 3.4 `ledgers/` — Append-Only Audit Trail

#### Global Ledger

```
<P>/ledgers/global/<run_id>/<sequence>.jsonl.zst
```

One set of segments per batch run. Each segment is a zstd-compressed NDJSON file containing one line per classified file.

- **Sequence numbering**: `000001.jsonl.zst`, `000002.jsonl.zst`, etc. A new segment is started every 50,000 lines or 10 MB uncompressed (whichever comes first).
- **Compression**: zstd level 3 (fast, ~3-5x compression on JSON).
- **Mutability**: Write-once, never modified.

#### ISA-Specific Ledger

```
<P>/ledgers/isa=<isa_slug>/<run_id>/<sequence>.jsonl.zst
```

Same structure as global, but only contains entries for files classified as that ISA. This enables fast "list all files for ISA X" queries without scanning the full global ledger.

**Example keys:**

```
isa-harvester/v1/ledgers/global/20260302T143022Z-batch-001/000001.jsonl.zst
isa-harvester/v1/ledgers/isa=aarch64/20260302T143022Z-batch-001/000001.jsonl.zst
isa-harvester/v1/ledgers/isa=x86_64/20260302T143022Z-batch-001/000001.jsonl.zst
```

### 3.5 `runs/` — Run Manifests

```
<P>/runs/<run_id>.json
```

One manifest per batch ingestion run or online upload session. Contains run parameters, timing, and aggregate statistics.

- **Content**: JSON document. See [03-schemas.md](03-schemas.md) Section 7.
- **Mutability**: Written at run start (status: `running`), overwritten at run end (status: `completed` or `failed`).

**Run ID format**: `YYYYMMDDTHHMMSSZ-<source>-<nnn>`

Examples:
- `20260302T143022Z-batch-001` — First batch run on March 2, 2026
- `20260302T151200Z-online-042` — 42nd online upload session that day

### 3.6 `stats/` — Aggregate Statistics

```
<P>/stats/current.json
```

A single JSON document containing aggregate counts, updated after each run. Used by the dashboard to avoid expensive `ListObjectsV2` counting operations.

- **Content**: See [03-schemas.md](03-schemas.md) Section 8.
- **Mutability**: Overwritten after each run (read-modify-write: fetch existing, merge new counts, write back).

---

## 4. Slug Derivation Rules

All path components must be S3-key-safe. The following slugification rules apply:

### 4.1 ISA Slugs

Derived from the `Isa::Display` implementation, which already produces lowercase strings:

| Isa Variant | Display Output | Slug Used in Key |
|-------------|---------------|-----------------|
| `Isa::X86` | `x86` | `x86` |
| `Isa::X86_64` | `x86_64` | `x86_64` |
| `Isa::Arm` | `arm` | `arm` |
| `Isa::AArch64` | `aarch64` | `aarch64` |
| `Isa::Mips` | `mips` | `mips` |
| `Isa::Mips64` | `mips64` | `mips64` |
| `Isa::Ppc` | `ppc` | `ppc` |
| `Isa::Ppc64` | `ppc64` | `ppc64` |
| `Isa::PpcVle` | `ppcvle` | `ppcvle` |
| `Isa::Sparc` | `sparc` | `sparc` |
| `Isa::Sparc64` | `sparc64` | `sparc64` |
| `Isa::S390x` | `s390x` | `s390x` |
| `Isa::M68k` | `m68k` | `m68k` |
| `Isa::Sh` | `sh` | `sh` |
| `Isa::Alpha` | `alpha` | `alpha` |
| `Isa::Tricore` | `tricore` | `tricore` |
| `Isa::RiscV32` | `riscv32` | `riscv32` |
| `Isa::RiscV64` | `riscv64` | `riscv64` |
| `Isa::Avr` | `avr` | `avr` |
| `Isa::Msp430` | `msp430` | `msp430` |
| `Isa::Hexagon` | `hexagon` | `hexagon` |
| `Isa::Xtensa` | `xtensa` | `xtensa` |
| `Isa::LoongArch64` | `loongarch64` | `loongarch64` |
| `Isa::Blackfin` | `blackfin` | `blackfin` |
| `Isa::Ia64` | `ia64` | `ia64` |
| `Isa::Vax` | `vax` | `vax` |
| `Isa::I860` | `i860` | `i860` |
| `Isa::CellSpu` | `cellspu` | `cellspu` |
| `Isa::Hcs12` | `hcs12` | `hcs12` |
| `Isa::Hc11` | `hc11` | `hc11` |
| `Isa::C166` | `c166` | `c166` |
| `Isa::Rl78` | `rl78` | `rl78` |
| `Isa::V850` | `v850` | `v850` |
| `Isa::Rh850` | `rh850` | `rh850` |
| `Isa::Fr30` | `fr30` | `fr30` |
| `Isa::S12z` | `s12z` | `s12z` |
| `Isa::Jvm` | `jvm` | `jvm` |
| `Isa::Wasm` | `wasm` | `wasm` |
| `Isa::Dalvik` | `dalvik` | `dalvik` |
| `Isa::Unknown(n)` | `unknown(0xNNNN)` | `unknown_0xNNNN` |

For `Unknown` variants, parentheses and `0x` prefix are replaced: `unknown(0x1234)` → `unknown_0x1234`.

### 4.2 Format Slugs

Derived from the `FileFormat` Debug variant name, lowercased, with non-alphanumeric characters removed:

| FileFormat Variant | Slug |
|-------------------|------|
| `Elf` | `elf` |
| `Pe` | `pe` |
| `MachO` | `macho` |
| `MachOFat` | `machofat` |
| `Coff` | `coff` |
| `Xcoff` | `xcoff` |
| `Ecoff` | `ecoff` |
| `Raw` | `raw` |
| `Aout` | `aout` |
| `Plan9Aout` | `plan9aout` |
| `MinixAout` | `minixaout` |
| `Mz` | `mz` |
| `Ne` | `ne` |
| `Le` | `le` |
| `Lx` | `lx` |
| `Com` | `com` |
| `Omf` | `omf` |
| `Pef` | `pef` |
| `IntelHex` | `intelhex` |
| `Srec` | `srec` |
| `TiTxt` | `titxt` |
| `Bflt` | `bflt` |
| `Dxe` | `dxe` |
| `Goff` | `goff` |
| `MvsLoad` | `mvsload` |
| `Som` | `som` |
| `Rsx11` | `rsx11` |
| `Vms` | `vms` |
| `Ieee695` | `ieee695` |
| `Wasm` | `wasm` |
| `JavaClass` | `javaclass` |
| `Dex` | `dex` |
| `Odex` | `odex` |
| `Vdex` | `vdex` |
| `Art` | `art` |
| `LlvmBc` | `llvmbc` |
| `FatElf` | `fatelf` |
| `Archive` | `archive` |
| `WindowsLib` | `windowslib` |
| `Xbe` | `xbe` |
| `Xex` | `xex` |
| `SelfPs3` | `selfps3` |
| `SelfPs4` | `selfps4` |
| `SelfPs5` | `selfps5` |
| `Nso` | `nso` |
| `Nro` | `nro` |
| `Dol` | `dol` |
| `Rel` | `rel` |
| `ZImage` | `zimage` |
| `UImage` | `uimage` |
| `Fit` | `fit` |
| `Dtb` | `dtb` |
| `Ols` | `ols` |
| `Epr` | `epr` |
| `Sgo` | `sgo` |
| `Vbf` | `vbf` |
| `Frf` | `frf` |
| `Bcf` | `bcf` |
| `Sox` | `sox` |

### 4.3 Filename Sanitization

The `<sanitized_name>` component in `.ref` filenames is derived from the original filename:

1. Take the original filename (basename only, no directory components)
2. Replace any character that is not `[a-zA-Z0-9._-]` with `_`
3. Collapse consecutive underscores to a single underscore
4. Truncate to 128 characters maximum
5. If the result is empty, use `unnamed`

Examples:
- `firmware (v2.3).bin` → `firmware__v2.3_.bin` → `firmware_v2.3_.bin`
- `rkos` → `rkos`
- `../../etc/passwd` → `_etc_passwd` → `etc_passwd`

### 4.4 Endianness Slugs

| Endianness | Slug |
|-----------|------|
| `Little` | `le` |
| `Big` | `be` |
| `BiEndian` | `bi` |

### 4.5 Confidence Band Exclusion

Confidence is deliberately **not** included in the key path. Reasons:
- Reclassification with an improved classifier would change confidence, requiring key migration
- Confidence is continuous, so any banding is arbitrary
- Confidence lives in the metadata sidecar where it can be queried without path changes

---

## 5. Key Length Analysis

S3 keys can be up to 1024 bytes. Our worst-case key length:

```
isa-harvester/v1/views/classified/fmt=windowslib/isa=loongarch64/bits=128/endian=bi/ab/cd/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789__some_very_long_original_filename_that_goes_on.ref
```

Breakdown:
- Prefix: ~20 chars
- View path: ~60 chars
- Shard: 6 chars
- Hash: 64 chars
- Separator `__`: 2 chars
- Name: up to 128 chars
- Extension `.ref`: 4 chars
- **Total worst case: ~284 chars** — well within the 1024-byte limit.

---

## 6. Key Enumeration Examples

### "List all formats"
```
ListObjectsV2(Prefix="<P>/views/classified/", Delimiter="/")
→ CommonPrefixes: ["fmt=elf/", "fmt=pe/", "fmt=raw/", "fmt=macho/", ...]
```

### "List all ISAs for ELF format"
```
ListObjectsV2(Prefix="<P>/views/classified/fmt=elf/", Delimiter="/")
→ CommonPrefixes: ["isa=aarch64/", "isa=x86_64/", "isa=arm/", "isa=mips/", ...]
```

### "List all AArch64 ELF 64-bit little-endian files"
```
ListObjectsV2(Prefix="<P>/views/classified/fmt=elf/isa=aarch64/bits=64/endian=le/")
→ Contents: [list of .ref keys]
```

### "Find a specific file by hash"
```
HeadObject(Key="<P>/objects/sha256/a1/b2/a1b2c3d4...bin")
→ 200 (exists) or 404 (not found)
```

### "List all ambiguous files with low confidence"
```
ListObjectsV2(Prefix="<P>/views/ambiguous/reason=low_conf/", Delimiter="/")
→ CommonPrefixes: ["fmt=raw/", "fmt=elf/", ...]
```
