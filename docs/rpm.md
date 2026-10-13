# RPM packages

`src/formats/rpm.rs` and its submodules parse RPM packages into the shared
container model ([compressed streams and the container model](compressed-streams.md)):
the 96-byte lead, the signature header, the main header and the payload,
a cpio archive that is usually compressed. The package names a build
architecture, but no CPU in a form the classifier may use, so the container
leaves its target open; each regular file of the payload that is a
recognized format is a child, classified from its own bytes.

This page also records how Debian packages (`.deb`) are classified: they
are ar archives and need no family of their own.

## Implemented layouts

| JSON format ID | Layout | Components | Primary source |
| --- | --- | --- | --- |
| `rpm` | Lead (magic `ED AB EE DB`), signature header at 96 (header structure, region tag 62, zero-padded to 8 bytes), main header (region tag 63 spanning the header), payload to the declared end; package format v3 (no regions), v4 and v6 (`RPMTAG_RPMFORMAT`), binary and source packages | Regular files of the payload archive in a recognized format (`if_recognized`): newc entries (`070701`, `070702`) named by the entry, or rpm's stripped entries (`07070X`) named and sized by the main header's file table. A payload that cannot be read is one opaque `Payload` component | rpm [`rpm-6.0.0-release`](https://github.com/rpm-software-management/rpm/tree/rpm-6.0.0-release) `docs/manual/format_v4.md`, `format_v6.md`, `format_lead.md`, `format_header.md`, `signatures_digests.md`, `lib/rpmlead.cc`, `lib/header.cc`, `lib/signature.cc`, `lib/package.cc`, `lib/cpio.cc`, `lib/rpmfi.cc`, `lib/rpmte.cc`, `build/pack.cc`, `include/rpm/rpmtag.h`, `include/rpm/rpmcrypto.h`, `rpmio/rpmio.cc`; [LSB 5.0 Core, Generic, section 25.2 "Package File Format"](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/pkgformat.html); zlib [v1.3.1](https://github.com/madler/zlib/blob/v1.3.1/zlib.h) `zlib.h` (`gzread`) |

Detection is strong: the lead magic at 0 and the eight-byte header
structure magic `8E AD E8 01 00 00 00 00` at 96. It runs right before the
magic-bearing compressed streams in `detect_format`; no format above starts
with these bytes, and the families above that probe later offsets would
need their structures inside the signature or header store.

### Lead (96 B)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic `ED AB EE DB` |
| 4 | 1 + 1 | Format version: 3.0 for v3 and v4 packages, 4.0 for v6 |
| 6 | 2 | Type: 0 binary, 1 source |
| 8 | 2 | Architecture number (`rpmrc` `arch_canon`; 0 in packages rpm 4 and 6 write) |
| 10 | 66 | Name-version-release, NUL-terminated |
| 76 | 2 | OS number (0 in packages rpm 4 and 6 write) |
| 78 | 2 | Signature type: 5, header-style |
| 80 | 16 | Reserved |

rpm reads only the magic; the parser reports the other fields as metadata
and notes a signature type other than 5 or a lead type that disagrees with
the main header.

### Header structure

Both headers use it (`format_header.md`; LSB 25.2.2): magic (8), index
entry count `il` (4), data store size `dl` (4), `il` index entries of tag,
type, offset (signed) and count (4 each), then the store. Types 1-9: CHAR,
INT8, INT16, INT32, INT64, STRING, BIN, `STRING_ARRAY`, `I18NSTRING`; integers
are aligned to their size. The checks are rpm's own:

| Check | Source |
| --- | --- |
| Signature: `1 <= il <= 32`, `dl <= 64 MiB`; main: `1 <= il <= 0xFFFF`, `dl <= 0x0FFFFFFF`; `8 + 16 il + dl < 256 MiB` | `hdrblobVerifyLengths`, `headerMaxbytes` |
| A first entry with the region tag is BIN, count 16, and points at a 16-byte trailer in the store that repeats the tag (the signature also accepts 61), type BIN, count 16 and offset `-16 * ril` with `ril <= il`; a first entry with another tag is a legacy header without a region | `hdrblobVerifyRegion` |
| The main header's region spans the whole header (`il == ril`, `dl == rdl`) | `exact_size` in `package.cc` |
| Every other entry: tag at least 100; type 1-9; `1 <= count <= dl`; at most `0xFFFFF` values unless BIN; data offset in the store, at or after the previous entry's data, aligned to the type; the data fits the store (strings NUL-terminated inside it; a STRING has count 1); no overlap with the region trailer | `hdrblobVerifyInfo`, `dataLength` |
| The signature header is followed by zero padding to 8 bytes | `hdrblobRead`; `format_v6.md` ("All padding must consist solely of zero valued bytes") |

A tag the parser reads must have the type the tag table gives it; another
type is an error (rpm type-checks the main header's known tags the same
way, `hdrchkTagType`).

### Payload

| Item | Behavior |
| --- | --- |
| Extent | From the main header's end to the declared end: `RPMSIGTAG_LONGSIZE` or `RPMSIGTAG_SIZE` (header and payload), else `RPMTAG_PAYLOADSIZE` (v6, payload), else the end of the file |
| Format | `RPMTAG_PAYLOADFORMAT` must be `cpio` (the only one `build/pack.cc` writes); another is an opaque payload with a note |
| Compressor | `RPMTAG_PAYLOADCOMPRESSOR` `gzip`, `bzip2`, `xz`, `lzma` or `zstd`; missing means `gzip` (`rpmtePayload`). A gzip payload that starts with a cpio entry is uncompressed (`ufdio` packages), as zlib's `gzread` reads it. Other names are opaque payloads |
| Decoding | `compressed::decode`; a stream that decodes to more than 64 MiB is decoded as its first 64 MiB with `compressed::decode_prefix` and listed up to there. A stream that does not decode is an opaque payload with a note |
| newc entries | `070701`/`070702`, 13 fields of 8 hex digits, the name (1 to 4096 bytes with its NUL, the `rpmcpioHeaderRead` limit), padding to 4 bytes from the start of the archive, the data, padding to 4 bytes |
| Stripped entries | `07070X` and the file index (8 hex digits), padding, the data. The file table supplies the path (`RPMTAG_DIRNAMES[RPMTAG_DIRINDEXES[i]] + RPMTAG_BASENAMES[i]`), mode (`RPMTAG_FILEMODES`) and size (`RPMTAG_LONGFILESIZES`, else `RPMTAG_FILESIZES`); a regular file in a hard-link set (regular, non-ghost files sharing `RPMTAG_FILEDEVICES` and an `RPMTAG_FILEINODES` above 0) carries data only as the set's last member; a symbolic link carries its target |
| End | The newc `TRAILER!!!` entry (or a stripped index `ffffffff`); bytes after it that are not zero are noted |

Members are pushed in archive order. A regular file with data is listed
when its first 4 KiB, and then its whole data, are a recognized format;
its slice keeps the stored payload's range (the file's own range for an
uncompressed payload) and the decoded size. An archive entry that is
truncated or invalid ends the listing with a note; files before it stay
listed.

## Debian packages

A `.deb` (dpkg 1.22.21 `man/deb.pod`) is an ar archive of `debian-binary`,
`control.tar[.gz|.xz|.zst]` and `data.tar[|.gz|.xz|.zst|.bz2|.lzma]`. The
existing families already classify it: `ar` lists each member in a
recognized format, the codec family decodes the compressed member, and the
tar family lists the ELF files in it, so the package's primary ISA comes
from `data.tar`. `debian_packages_reach_the_elf_in_their_data_archive`
checks this for uncompressed, gzip, xz, Zstandard and bzip2 data members.

Two shared changes came out of this check:

- A recognized ar member whose classification fails (a damaged member, a
  stream whose check fails) used to fail the whole archive through `?` in
  `classify_depth`; it is now listed with an unknown ISA and a warning
  (`<member>: ISA unknown (<error>)`), and the other members still report.
- `compressed::decode_prefix` now stops xz streams at the limit, as it
  already did for gzip, Zstandard, bzip2 and LZMA-alone. Before, a
  `data.tar.xz` (or RPM payload, or standalone `.xz`) decoding to more than
  64 MiB failed as a whole.

A `data.tar` larger than 64 MiB decoded still reports no ISA: the tar
family needs a complete archive, and a decoded prefix ends inside a member.

## Wire units and byte order

All offsets and sizes are bytes and every RPM integer is big-endian. Lead
and header byte order is never reported as code byte order; members report
their own. Archive offsets in notes are offsets in the (decoded) payload
archive.

## Validation and resource bounds

- The limits of the header structure table above bound every count before
  anything is allocated; index entries are read only after the whole
  structure fits the file, and each entry's data is measured only after its
  offset is known to start after the previous entry's, so measuring walks
  each store byte at most once.
- A declared end beyond the file is an error (`Truncated package`); bytes
  after a declared end must be `0x00`/`0xFF` padding.
- The payload decodes to at most 64 MiB (`MAX_PAYLOAD`); member copies are
  bounded by the decoded archive. Listing stops at 4096 components and the
  rest are counted. Every archive entry advances the walk by at least its
  14-byte header.
- The file table is validated (one value per file for every per-file tag,
  directory indexes inside `RPMTAG_DIRNAMES`) before a stripped entry is
  read; a table that fails is noted and no files are listed.
- Container nesting is capped at six levels (see
  [compressed streams](compressed-streams.md)).

## Evidence and verification

| Check | Status |
| --- | --- |
| `RPMSIGTAG_SHA256`, `RPMSIGTAG_SHA1` (main header) | Verified; a mismatch is an error |
| `RPMSIGTAG_MD5` (main header and payload) | Verified; a mismatch is an error |
| `RPMTAG_PAYLOADSHA256` (stored payload; when `RPMTAG_PAYLOADSHA256ALGO` is absent or 8), `RPMTAG_PAYLOADSHA512` | Verified; a mismatch is an error |
| `RPMTAG_PAYLOADSHA256ALT`, `RPMTAG_PAYLOADSHA512ALT` (uncompressed payload) | Verified when the payload decoded whole; a mismatch is an error |
| `RPMSIGTAG_SHA3_256`, `RPMTAG_PAYLOADSHA3_256`, `RPMTAG_PAYLOADSHA3_256ALT` | Present, not verified (no SHA-3 implementation in the crate) |
| gzip CRC-32, xz checks, Zstandard checksums, bzip2 CRCs of the payload | Verified by the decoder when the payload decodes whole |
| RSA, DSA, PGP, GPG and `OpenPGP` signatures; IMA and fs-verity file signatures | Present, not verified (need the signer's key) |
| `RPMTAG_FILEDIGESTS` | Present, not verified; the algorithm is named from `RPMTAG_FILEDIGESTALGO` (MD5 when absent) |
| Declared uncompressed sizes (`RPMSIGTAG_LONGARCHIVESIZE`, `RPMSIGTAG_PAYLOADSIZE`, `RPMTAG_PAYLOADSIZEALT`, `RPMTAG_ARCHIVESIZE`) | Compared with the decoded archive; a difference is a note (rpm does not enforce them) |

No package sets a target. `RPMTAG_ARCH`, `RPMTAG_OS` and the lead's
architecture and OS numbers are reported in notes and metadata
(`rpm_arch`, `rpm_os`, `rpm_lead_archnum`, `rpm_lead_osnum`) only: the lead
number is ambiguous (`rpmrc` gives 1 to i386 and x86-64, 2 to Alpha and
SPARC64), `noarch` packages may hold any code, and no primary source maps
the architecture names to instruction sets.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| R1 | Packages rpm 4.x and 6.x write have zero signature padding | `header_structures_are_checked_as_rpm_checks_them`; a real package that fails with "Invalid signature header padding" would falsify it (rpm 4 does not check the pad bytes) |
| R2 | The header digests cover the main header exactly as stored | Checked on the real rpm 4.4.2 package of the verification section (its SHA-1 and MD5 matched) |
| R3 | rpm writes newc payload entries with padding counted from the start of the archive | The real package's 1,211 entries walked without error; the bsdcpio fixture walks to its trailer |
| R4 | Stripped payloads end with a newc `TRAILER!!!` and carry data only in the last member of a hard-link set | From `rpmcpioTrailerWrite`, `rpmfiStat` and `iterReadArchiveNext`; no real v6 or large-file package was available. A real one listing a hard-linked file twice, or ending in "is invalid", would falsify it |
| R5 | `RPMTAG_PAYLOADSHA256` is a `STRING_ARRAY` (rpmtag.h `s[]`), and a `STRING` is accepted as well | A real package whose digest check reports a type error |
| R6 | A missing compressor tag means gzip, and gzip passes an uncompressed cpio through | `payloads_without_a_compressor_tag_read_through_the_gzip_path`; rpm `rpmtePayload`, zlib `gzread` |
| R7 | The header architecture names no ISA | Not used as evidence; `the_header_architecture_is_not_isa_evidence` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| SHA3-256 digests (v6) | Not verified; reported as present |
| OpenPGP and other signatures | Never verified |
| Payload formats other than `cpio` (delta RPMs) | Opaque payload with a note; no primary source for their layout was read (UNCONFIRMED: `drpm` as the delta name) |
| Compressors rpm does not write (`lzip`, ...) | Opaque payload with a note |
| Per-file digests | Not verified |
| Old packages without a header-style signature (lead signature types 0-4, rpm 2.x) | Not recognized: there is no header magic at 96, and rpm 4 cannot read them either |
| Debian `data.tar` decoding to more than 64 MiB | Reported with no ISA (the tar family needs a complete archive) |
| Real samples | One real RPM (rpm 4.4.2, 81 MB, gzip payload of 287 MB, not redistributable) and four real `.deb` files were checked in place; no v6, stripped, xz, zstd or signed RPM was available. None of IDA's test inputs start with the RPM magics |

## Verification

On 2026-10-13 (macOS AArch64, Darwin 27.2), `tests/rpm.rs` (24 tests)
passed, including an every-prefix sweep of a v4 gzip package and a v6
stripped package, single-byte mutation sweeps (0x00, 0xFF, bit flip) of
both with and without digests, bit flips of the stripped archive behind its
compression, a payload that decodes beyond 64 MiB, and Debian packages with
uncompressed, gzip, xz, Zstandard and bzip2 data members; as did the 19
module unit tests. `cargo test --all-features --locked` passed 2,458 tests
with 6 ignored. After `./build-web.sh`, `web/tests/rpm.test.mjs` (4 tests)
passed through `/pkg/`, `/dist/`, `/web/index.html` and
`/dist/index.html`, and `web/tests/compressed.test.mjs` and
`web/tests/archives.test.mjs` (12 tests) still passed. Clippy reports no
new warnings in the touched shared files and only the accepted
`wildcard_imports` for `use super::*;` in the family.

Real files, read in place and not redistributed (`PACKAGE_SAMPLE_DIR`):
one RPM written by rpm 4.4.2 (81 MB, gzip payload of 287 MB, 3,768 files):
lead 3.0, region headers, SHA-1 and MD5 verified, the first 64 MiB of the
payload decoded, 1,211 newc entries walked and 90 files in a recognized
format listed (the i386 ELF tools and a bzip2 archive), primary ISA x86
(32-bit) from the first ELF, in 1.7 s; and four `.deb` files: a
17 MB x86-64 driver package (gzip members; x86-64 from `data.tar.gz`), two
font packages (no ISA, as expected) and a 126 MB arm64 browser
package whose `data.tar.xz` decodes beyond 64 MiB (no ISA; before these
changes the whole package failed with "Decoded payload exceeds 64
MiB"). `IDA_INPUT_DIR` holds no file with the RPM magics, and its three ar
archives classify as before. Behavior on v6, stripped, xz-, Zstandard- or
LZMA-compressed and signed RPMs written by rpm is not verified: no such
package was available, and every such fixture is synthetic.

After integration on the same day, the native suite passed 2,591 tests
with 6 ignored, and IDA's corpus (4,621 files, no RPM packages) classified
as before.
