# Apple FTAB firmware tables

FTAB wraps independently classified firmware components. The file's tag and
generation do not establish an ISA. The JSON format ID is `ftab`, displayed
as `Apple FTAB` in the CLI and both browser interfaces.

## Provenance and layout

The implementation adapts the layout, placeholder handling and diagnostics
from the user's MIT-licensed [ftab-dump parser](https://github.com/19h/ftab-dump/blob/7f10b041d4e9dc6e903c29bd572c5a989fddea68/src/rkos_parser.rs),
revision `7f10b041d4e9dc6e903c29bd572c5a989fddea68` (package 1.6.0, author
Kenan Sulayman). That source derives the layout from Apple's updater
libraries and cross-checks it against idevicerestore's `ftab.h`. The local
source was inspected on 2026-10-29; its firmware-derived conclusions have
not been independently reproduced here.

All numeric fields are little-endian. Every offset is absolute relative to
the start of the FTAB file, in bytes; sizes are also in bytes.

| Header offset | Size (B) | Field |
| --- | ---: | --- |
| `0x00` | 4 | Generation |
| `0x04` | 4 | Valid flag, normally `0xFFFFFFFF` |
| `0x08` | 8 | Boot nonce |
| `0x10` | 4 | Manifest offset |
| `0x14` | 4 | Manifest size |
| `0x18`, `0x1C` | 4 each | Reserved |
| `0x20` | 8 | Exactly `rkosftab` or `RKOSFTAB` |
| `0x28` | 4 | Entry count; zero is valid |
| `0x2C` | 4 | Reserved |
| `0x30` | 16 per entry | File table |

| Entry offset | Size (B) | Field |
| --- | ---: | --- |
| `0x00` | 4 | Role tag; printable ASCII or hexadecimal display |
| `0x04` | 4 | Payload file offset |
| `0x08` | 4 | Payload size |
| `0x0C` | 4 | Reserved |

## Validation and analysis

The eight-byte magic is strong detection evidence even if the count or
file table is truncated. A damaged FTAB produces a format error rather than
raw ISA analysis. Mixed-case variants are not accepted.

The complete header and table must fit before allocation or enumeration.
There are at most 4096 entries and 256 MiB of aggregate referenced payload
and manifest bytes, counting overlaps repeatedly. Ranges use checked
addition, including on wasm32. Nonempty payloads must start after the table
and fit entirely within the file. Trailing bytes after the last occupied
region may only contain `0x00` or `0xFF`. Unreferenced internal gaps are
neither classified nor required to be padding.

Zero-size entries are placeholders: their unused offset need not be in
range, and they appear as metadata rather than code. Nonempty members
become independent children, allowing nested FTAB, IMG4 and recognized
compressed streams to follow the existing recursive container path. The
manifest is always opaque; its signature is not verified. No tag, nonce,
generation, reserved word or valid flag is interpreted as a CPU target.

Duplicate tags, overlapping payloads, manifest overlap, out-of-order
payloads, unaligned offsets, unusual valid flags and nonzero reserved
words produce diagnostics rather than discarding readable data. Overlap
diagnostics track the furthest interval end, preserving witnesses when
one payload contains another. For `n` entries the parser takes
`O(n log n + t)` time and `O(n)` auxiliary space, where `t` is the number
of trailing bytes checked; payloads are borrowed rather than copied.
Recursive classification has its separate decoder and nesting limits.

## Assumption register

| ID | Assumption and dependent behavior | Falsification probe |
| --- | --- | --- |
| F1 | Only the two exact magic values identify this layout | Compare against a documented reader accepting a third magic; mixed-case mutation is rejected in the synthetic suite |
| F2 | Zero-size entries have no payload regardless of offset | Exercise a placeholder with offset `0xFFFFFFFF`; it must produce no code slice |
| F3 | Tags name roles rather than ISAs | Wrap identical bytes under unrelated tags; ISA must continue to come from member bytes |
| F4 | Manifest bytes are authentication metadata | Insert a Mach-O image as the manifest; it must remain opaque and cannot supply the primary ISA |
| F5 | Nonpadding trailing bytes are outside the supported layout | Append a nonpadding byte after the occupied extent; parsing must fail; a documented trailer would require extending this rule |

## Boundaries and adjacent patterns

| Impact | Pattern or boundary |
| --- | --- |
| High | Overlapping entries can repeatedly reference the same bytes; aggregate accounting bounds repeated member analysis |
| High | A manifest containing executable-looking bytes remains opaque and cannot become ISA evidence |
| Medium | Duplicate role tags are preserved in table order; consumers must use member identity or index rather than treating tags as unique keys |
| Medium | Lenient clamping in the reference CLI is not enabled for automatic classification: incomplete payloads produce errors |
| Low | Alignment and reserved-word diagnostics permit inspection of unusual but fully readable images |

## Verification

Synthetic native and browser fixtures are built independently from the wire
layout described above. No third-party firmware or keys are committed.
The native suite covers both magic values, empty tables, placeholders,
manifest opacity, nested FTAB/IM4P, truncations, corrupt counts and ranges,
overlap diagnostics, trailing data, byte mutations and the entry-count
limit. Browser tests cover the source and packaged WASM and workbench
paths. Execution results are recorded after validation; fixture construction
alone is not evidence that these tests passed.

Execution results for 2026-10-29 (macOS AArch64, rustc 1.99.1) are in
[firmware workbench verification](firmware-workbench-verification.md):
8 FTAB integration tests and 4 focused browser cases passed; three real
UARP assets supplied nested FTABs whose member ranges were checked.
