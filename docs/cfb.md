# OLE compound files

`cfb` covers OLE compound files: Windows Installer packages (`.msi`),
legacy Office documents and other structured storage. The format names no
processor. Streams that are a recognized format (in an installer package,
the custom-action DLLs and the cabinets that hold the product's files) are
members classified from their own bytes; the first identified member
supplies the primary ISA.

## Implemented layout

| JSON format ID | Layout (variant) | Recognition and checks | Primary source |
| --- | --- | --- | --- |
| `cfb` | `Compound file` | Strong: the 8-byte signature `D0 CF 11 E0 A1 B1 1A E1`. Major version 3 with 512 B sectors or 4 with 4096 B sectors, byte order mark `0xFFFE`, 64 B mini sectors, mini stream cutoff 4096, no directory sector count in version 3. FAT sectors from the header's 109 DIFAT entries and the DIFAT chain; directory, mini FAT and mini stream chains followed through the FAT; directory tree walked from the root entry | [MS-CFB] v20210407, sections 2.2 to 2.6 |

Windows Installer stream names are packed into the code points
`0x3800`-`0x4840` and unpacked as Wine `dlls/msi/table.c`
(`decode_streamname`) does: `0x3800`-`0x47FF` hold two characters,
`0x4800`-`0x483F` one, `0x4840` marks a table. A root CLSID of
`{000C1084-0000-0000-C000-000000000046}` is reported as a Windows Installer
package.

## Wire units and byte order

All fields are little-endian. Sector `n` starts at `(n + 1) * sector size`:
the header occupies sector -1. Streams of at least 4096 B are chains of
regular sectors; smaller streams are chains of 64 B mini sectors inside the
mini stream, which is the root entry's stream. Member offsets are file
offsets of a stream's first regular sector; mini-stream members have offset
0 because their bytes are not contiguous in the file.

## Validation and resource bounds

- Every sector number is checked against the sectors present; the last
  sector may be cut short and reads as present, but a stream whose chain
  holds fewer bytes than its size is an error.
- A chain (FAT or mini FAT) that meets a sector twice is an error, so a
  loop cannot repeat bytes into a stream.
- The FAT sector count may not exceed the file's sector count; the
  directory chain is read up to 65,536 entries.
- The directory tree is walked iteratively; an entry reached twice is an
  error.
- One stream is extracted up to 64 MiB (67,108,864 B), and at most 256 MiB
  (268,435,456 B) in total; larger streams are counted in a note and not
  extracted.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | Streams that are not a recognized format are data (installer tables, summary information) and are not listed | An installer whose code is stored in an unrecognized wrapper would have no member and an unknown ISA |
| C2 | The first identified member is the primary ISA; other members keep their own | A package mixing x86 and x86-64 custom actions reports the first one; the rest are listed as slices |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Transacted or damaged compound files with free sectors inside chains | A chain that reaches a free sector is an error |
| Property-set streams (`\x05SummaryInformation`) | Not interpreted; listed only if a recognized format |
| Installer table contents | Not decoded; the `Binary` and cabinet streams are classified from their bytes |

## Verification

On 2026-11-04 (macOS, Rust 1.99.1 release build), `tests/cfb.rs` passed (4
tests: members and primary ISA, installer name unpacking, truncation at every
length and corrupt chains, byte mutations). Three Windows Installer packages
of the fw1 corpus (430.5 MiB, 221.3 MiB and 63.4 MiB) were recognized with x86
primary ISAs from their custom-action DLLs; in the two larger packages one
stream each was over 64 MiB, counted and not extracted. No installer package is committed.
