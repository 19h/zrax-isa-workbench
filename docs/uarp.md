# UARP super binaries

UARP stores independent firmware payloads and packed metadata TLVs. The
JSON format ID is `uarp`, displayed as `UARP super binary`.

## Provenance and wire coordinates

The layout is adapted from the user's MIT-licensed
[uarp-dump parser](https://github.com/19h/uarp-dump/blob/1b41607c6805d59b61cb4a8f536153d58b52c866/src/uarp_parser.rs),
revision `1b41607c6805d59b61cb4a8f536153d58b52c866`, package 1.3.0, author
Kenan Sulayman. The requested local checkout was absent; this revision was
fetched from `19h/uarp-dump` and inspected on 2026-10-29. The source names
Apple's `uarpSuperBinaryHeaderEndianSwap`, `uarpPayloadHeaderEndianSwap`
and `uarpProcessTLV` routines as its layout evidence. Those decompilation
results have not been independently reproduced here. License notices are
retained in [third-party-firmware-parsers.txt](third-party-firmware-parsers.txt).

All numeric fields use big-endian 32-bit words. Offsets are absolute file
byte coordinates and sizes are bytes. Role tags retain their raw byte
order. No header field establishes an ISA.

| Header offset | Size (B) | Field |
| --- | ---: | --- |
| `0x00` | 4 | Format version |
| `0x04` | 4 | Header size, exactly 44 |
| `0x08` | 4 | Declared super-binary size |
| `0x0C` | 16 | Version: major, minor, release, build |
| `0x1C` | 4 | Global metadata offset |
| `0x20` | 4 | Global metadata size |
| `0x24` | 4 | Payload-table offset |
| `0x28` | 4 | Payload-table size, a nonzero multiple of 40 |

| Payload-record offset | Size (B) | Field |
| --- | ---: | --- |
| `0x00` | 4 | Record size, exactly 40 |
| `0x04` | 4 | Raw role tag |
| `0x08` | 16 | Version: major, minor, release, build |
| `0x18` | 4 | Payload metadata offset |
| `0x1C` | 4 | Payload metadata size |
| `0x20` | 4 | Payload byte offset |
| `0x24` | 4 | Payload byte size |

Each TLV has an eight-byte header (type, value byte size) followed by the
value without alignment padding. Global and per-payload TLV areas must be
consumed exactly. Metadata displays type, absolute offset, value size and
up to 64 value bytes in hexadecimal. Metadata never reaches ISA analysis.
Signatures and digests are not verified.

## Detection, validation and limits

UARP has no fixed magic. Recognition is weak: the entire image, fixed
header sizes, nonempty payload table, referenced ranges and TLV areas must
validate. A version word alone does not trigger detection. Invalid UARP
passed directly to the parser gives `UARP parse error`; automatic detection
may treat an invalid magic-less image as raw data.

The declared image size bounds every nonempty range, even when the physical
file is larger. Nonempty content cannot alias the super-binary header or
payload table. Empty payloads become metadata placeholders; unused offsets
of empty regions are ignored. Padding after the declared image may contain only zero or `0xFF` bytes.
An appended `bplist00` property list is also supported as an opaque child.
Its trailer, offset table, object extents and references must validate;
its graph is not recursively traversed. The validator follows the wire
layout in Apple's [CFBinaryPList.c, CF-1153.18](https://github.com/apple-oss-distributions/CF/blob/CF-1153.18/CFBinaryPList.c).
Binary property-list members are likewise opaque. CTAB role members are
conservatively opaque pending implementation of their chunked codec; this
policy is based on the observed local assets, not on an authenticated
claim made by the tag.

The parser accepts at most 4096 payloads, 4096 TLVs across all metadata areas
and 256 MiB of aggregate referenced payload and metadata bytes. Overlapping
or repeated references count repeatedly. Ranges use checked arithmetic.
Binary property-list validation is bounded to 65,536 objects and 1,048,576
references per list. The supported property-list subset is `bplist00`
with 1, 2, 4 or 8 B offset/reference widths; other versions and widths are
outside recognition. Duplicate object offsets are rejected. Object offsets are sorted to reject overlaps and
validate bounded extents; dictionary, array and set references must index
existing objects. Cycles cannot recurse because the graph is not followed.
Payload bytes are borrowed, with independent recursive classification
subject to the classifier's existing nesting and decoder limits. For `n`
payloads, `m` TLVs and `t` trailing padding bytes, structural parsing takes
`O(n + m + t + p log p + r)` time and `O(n + m + p)` space,
where `p` is the property-list object count and `r` its reference count; preview lengths are bounded.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| U1 | The fixed header and payload strides are 44 and 40 B | Corrupt either self-described length; direct parsing must fail |
| U2 | Metadata is packed TLV data without alignment gaps | Place a three-byte value immediately before another TLV; both must parse |
| U3 | All nonempty regions lie inside the declared image | Shorten the declared extent while retaining the physical bytes; parsing must fail |
| U4 | Role tags and version words do not establish an ISA | Wrap a Mach-O image under an arbitrary tag; the payload header supplies the ISA |
| U5 | A nonempty table is required for automatic recognition | Supply an otherwise consistent empty header; it must remain unrecognized |
| U7 | CTAB role members may be transformed and must remain opaque | A documented uncompressed CTAB layout could justify selectively decoding it; current fixtures pin opacity |
| U6 | Content does not alias structural headers | Point a nonempty payload into the fixed header or table; parsing must fail |

## Boundaries and adjacent patterns

| Impact | Pattern or boundary |
| --- | --- |
| High | Repeated TLV regions and overlapping payload references amplify work; aggregate budgets count every reference |
| High | Structural validity does not authenticate the asset, its metadata or any nested FTAB manifest |
| Medium | Empty tables, header-only parsing and lenient out-of-bounds recovery from the reference CLI are outside automatic recognition |
| Medium | Nested UARP, FTAB, IMG4 and compressed members follow the same independent-child analysis path |
| Low | Unknown TLV types are preserved as bounded hexadecimal previews without assigning speculative semantics |

## Verification

Synthetic native fixtures document each field in `tests/uarp.rs` and cover
packed TLVs, exact byte ranges, nested FTAB/IM4P, placeholders, malformed
headers and regions, full truncation and mutation sweeps, and resource
limits. `UARP_FIXTURE` enables the explicitly ignored local-firmware test:

```sh
UARP_FIXTURE=/path/to/firmware.uarp cargo test --all-features --locked --test uarp -- --ignored
```

No firmware is committed. A skipped external test is not validation of a
real asset. Execution counts and platforms are recorded after checks finish.

Execution results for 2026-10-29 (macOS AArch64, rustc 1.99.1) are in
[firmware workbench verification](firmware-workbench-verification.md):
7 synthetic native cases and 4 focused browser cases passed; the optional
external test was enabled and passed for three locally supplied assets.
