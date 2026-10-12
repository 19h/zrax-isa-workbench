# Archive containers

`src/formats/archives.rs` and its submodules `zip`, `tar` and `cpio` parse
ZIP, tar and CPIO archives into the shared container model
([compressed streams and the container model](compressed-streams.md)).
None of these formats names an ISA. Each regular-file member is a child
classified on its own bytes and listed only when it is a recognized format,
as `ar` members are (`Classify::IfRecognized`). The first listed member
whose bytes name an ISA supplies the primary result; every listed member is
a slice with its stored file range, and a decoded range when a codec
produced its bytes.

## Implemented layouts

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `zip` | Local headers, central directory (authoritative), end of central directory record found in the last 64 KiB + 22 B, ZIP64 end record and locator, ZIP64 extra fields, data descriptors in all four forms; methods 0 (stored), 8 (deflate), 12 (bzip2), 14 (LZMA), 93 (Zstandard) and 95 (xz) decoded; CRC-32 of every stored or decoded member verified | Strong: `PK\3\4` at offset 0, or the end record at 0 for an empty archive | [PKWARE APPNOTE.TXT 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) (2022-11-01), sections 4.3-4.5, 5.8.8 and Appendix E |
| `tar` | POSIX ustar (`prefix`/`name`), pax extended (`x`) and global (`g`) headers, GNU format with `L`/`K` long names, octal and GNU base-256 numbers, GNU and pax sparse members, every header checksum verified | Strong: `ustar\0` or `ustar  \0` at 257 and a valid header checksum | [POSIX.1-2024 `pax`](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html) (ustar and pax interchange formats); GNU tar 1.35 `src/tar.h`, `src/create.c`, `src/list.c`; libarchive v3.7.4 `tar.5`, `archive_read_support_format_tar.c` |
| `cpio` | newc (`070701`), crc (`070702`, data byte sum verified), odc (`070707`), old binary (`0x71C7`) in both byte orders; `TRAILER!!!`; archives concatenated after NUL padding | Strong for the ASCII magics with a valid first header and name (the first member's data may be cut off, so a truncated archive is a parse error); weak (confidence 0.85) for old binary, which needs every header up to the last trailer and only padding, further archives or a recognized format after it | libarchive v3.7.4 `cpio.5`, `archive_read_support_format_cpio.c`; POSIX.1-2024 `pax` ("cpio Interchange Format"); Linux v6.11 `init/initramfs.c` |

The format variant names the layout: `ZIP archive`, `tar archive`, `CPIO
newc archive`, `CPIO crc archive`, `CPIO odc archive`, `CPIO binary
archive (little-endian)` or `(big-endian)`. The tar summary note names the
dialect (`POSIX ustar`, `pax` or `GNU tar`).

Detection order: the strong checks run after the executable and firmware
formats, right before the magic-bearing compressed streams. Old binary
CPIO runs among the weak layouts, right before zlib and LZMA-alone. A ZIP,
tar or CPIO file that earlier versions reported as raw code is now
reported as an archive.

A gzip-, xz- or Zstandard-compressed archive (a `.tar.gz`, a compressed
initramfs) is a compressed stream whose decoded content is the archive:
the member slices then carry the stored range of the whole stream and a
`gzip` (or other codec) decoded range with the member's offset in the
decoded archive.

## Package labels

ZIP-based packages are labelled from member names only. The label becomes
the variant when no member supplies an ISA, and is always reported in a
note and as `zip_package` metadata. None of them names an ISA; members are
classified on their own bytes like any other ZIP member.

| `zip_package` | Variant | Member names required |
| --- | --- | --- |
| `apk` | Android APK | `AndroidManifest.xml` and `classes.dex` at the root |
| `ipa` | iOS IPA | `Payload/<name>.app/` |
| `nordic_dfu` | Nordic DFU package | `manifest.json` at the root whose `manifest` object names `application`, `bootloader`, `softdevice` or `softdevice_bootloader` |
| `pdx` | ASAM ODX PDX package | `index.xml` at the root and a member with an `.odx` or `.odx-<category>` extension |
| `jar` | Java JAR | `META-INF/MANIFEST.MF` |

The first match in that order wins (an APK also has a JAR manifest). An
APK Signing Block right before the central directory is noted as present
and not verified. The Nordic keys come from nrfutil package output, not a
published specification.

PDX data files are the one case where a member is listed whatever its
format. When the archive has the PDX member names, its ODX-F documents are
read first, and every `EXTERN-FLASHDATA` element's `DATAFILE` names a member
(matched exactly, else ignoring ASCII case; assumption A9). That member is
listed in the coding the document states: `BINARY` data goes straight to the
code model, `INTEL-HEX` and `MOTOROLA-S` records to their parsers, and data
with an `ENCRYPT-COMPRESS-METHOD` or a `USER-DEFINED` format is opaque. A
note names each data file, its flash data element and document, or says
that the package does not hold it. Data files are capped at 4096 per
archive; the documents are decoded with their own extraction budget.

## Wire units and byte order

All offsets and sizes are bytes; slice offsets are stored file offsets.
ZIP fields are little-endian. tar numbers are ASCII octal or big-endian
base-256. newc and crc fields are ASCII hex, odc fields ASCII octal. Old
binary CPIO words use the byte order of the magic; its 32-bit values are
two 16-bit words, most significant first. newc and crc names and data are
padded to 4 bytes and binary ones to 2 bytes, counted from the start of the
file as Linux initramfs counts them. No archive field is a code byte order.

## Validation and resource bounds

- ZIP: the central directory must end exactly at the next end record; the
  declared entry count must fit the directory at 46 B per entry; every
  local header must match its entry's method, encryption and descriptor
  flags and name, and (without a descriptor) its CRC-32 and sizes; a data
  descriptor must match the central directory; local records may not
  overlap (the overlapping-file ZIP bomb) and must end before the central
  directory; only padding may follow the end record. Multi-disk archives
  and central directory encryption (flag bit 13) are errors.
- ZIP members: stored data is classified in place. A compressed member is
  decoded with its declared size as the output limit; a decode failure, a
  size mismatch or a CRC-32 mismatch is noted and the member is not
  classified. Encrypted members (flag bit 0 or method 99), Deflate64 and
  other methods are opaque and listed by name in notes.
- tar: every header checksum is verified (unsigned sum, or the signed sum
  some old writers produced); numeric fields must be octal with only NUL
  or space after the digits, or positive base-256; member data and its
  block padding must lie in the file; pax records must be length-framed.
  The archive ends at the first zero block; further zero blocks belong to
  it; a missing end marker is noted.
- tar hard links store data only in pax interchange archives (after an
  `x` or `g` header); elsewhere their `size` is ignored.
- CPIO: every header field must be digits of its base; names must end
  with NUL; data must lie in the file; each archive must end with
  `TRAILER!!!`. A crc checksum mismatch is noted and the member is not
  classified. A truncated newc, crc or odc archive is a parse error once
  its first header and name are complete.
- After a tar or CPIO archive, the rest of the file must be padding
  (`0x00`/`0xFF`) or a recognized format, which is listed as the component
  `Data after the archive` (a second tar, a compressed initramfs archive).
  Anything else is an error.
- A member is listed only when its first 4 KiB, and then its whole
  contents, are a recognized format.
- Limits (shared container constants): at most 4096 listed members per
  archive; after that, remaining file members are counted, not examined.
  At most 64 MiB decoded per member and 256 MiB decoded per archive; a
  member whose declared size would pass either limit is not decoded and is
  named in a note. Container nesting is limited to six levels. Notes list
  at most eight member names and count the rest.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Member names, ZIP "version made by" and package layouts never name an ISA | `package_layouts_are_labels_and_never_an_isa`: every label yields an unknown ISA with confidence 0; an APK's native library supplies the ISA from its ELF header |
| A2 | The ZIP central directory is authoritative and local headers agree with it | Real Info-ZIP, 7-Zip and Python archives parse; `inconsistent_zip_structure_is_an_error` |
| A3 | ZIP LZMA data is the 4-byte ZIP LZMA header, 5 properties bytes, then raw LZMA that decodes with the central directory size, with or without an end marker | `lzma.zip` from 7-Zip (end marker set) decodes and its CRC-32 verifies |
| A4 | POSIX types 2-6 store no data blocks whatever their `size` field says; hard links (type 1) store `size` bytes of data only after a pax header has made the archive pax interchange format, as libarchive decides | Directory and symbolic link headers with non-zero sizes in `tar_entries_without_data_and_sparse_members_are_counted_not_classified`; ustar and pax hard links in `tar_hard_links_store_data_only_in_pax_archives`; an archive that breaks the rule fails on the next header's checksum |
| A5 | newc alignment counts from the start of the file | Linux initramfs does the same; a concatenated archive starting at an unaligned offset would fail with a missing magic |
| A6 | A 4 KiB prefix is enough to recognize a member | Magic-bearing formats are recognized from their header (`members_larger_than_the_recognition_prefix_are_listed`: a CPIO member whose first file ends past 4 KiB); weak formats that need the whole input (zlib, LZMA-alone, old binary CPIO, structure-only firmware layouts) are not listed when larger than 4 KiB |
| A7 | A PDX package has `index.xml` at the root and at least one `.odx*` member | odxtools loads every `.odx*` member and reads only the catalog's `SHORT-NAME`; a PDX with only auxiliary files would be labelled a plain ZIP |
| A8 | Nordic DFU packages name their images under the `manifest` object of `manifest.json` | Taken from nrfutil package output, not a published specification; a manifest with other keys is not labelled |
| A9 | A `DATAFILE` path names a PDX member by its path inside the archive, exactly or ignoring ASCII case | Read from odxtools 11.7.0 `externflashdata.py`, not from the ASAM schema; `pdx_data_files_are_listed_in_the_coding_their_document_states` matches `CAL.HEX` to `cal.hex`; a package that stores data files under another directory would report them as not in the package |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Deflate64, PPMd, implode and other ZIP methods | Opaque; no decoder in the crate |
| ZIP encryption (traditional, AE-x, strong) | Opaque; never decrypted |
| Self-extracting or prefixed ZIPs, split-archive markers | Not recognized: detection needs `PK\3\4` or an empty archive's end record at offset 0 |
| ZIP data between members (APK Signing Block aside) | Not checked |
| Unix v7 tar (no magic) | Not recognized: without a magic only a checksum would identify it |
| pax global (`g`) records | Framing checked; records not applied |
| GNU sparse and multivolume members, pax sparse 0.x/1.0 | Counted and named in a note; their data is fragments and is not classified |
| afio large ASCII CPIO and PWB binary CPIO | Not recognized; PWB mode bits differ, so PWB regular files would be counted as other entries |
| Nested archives | Each nested archive has its own 256 MiB decode budget; total work is bounded by the six-level nesting limit and the per-archive limits, not by one global budget |
| Member signatures (JAR, APK, IPA) | Not verified |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly 2026-09-05):

- After PDX data files were resolved, `tests/archives.rs` (28 tests,
  including a PDX package built from the documented layout with an
  every-prefix truncation and byte-mutation sweep) and the whole native
  suite (1136 tests, 6 ignored) passed. No real PDX package was tested.

- The unit tests in `src/formats/archives.rs` and its `zip`, `tar` and
  `cpio` submodules (17 tests) and the 27 tests in `tests/archives.rs`
  passed. They include every-prefix truncation sweeps and
  `0x00`/`0xFF`/bit-flip mutation sweeps over the 17 committed archive
  fixtures (plus `initramfs.cpio.gz` for mutations) and four archives built
  from the layouts; the sweeps run without the raw-dump transform search.
- The whole native suite (`cargo test --all-features --locked`) passed:
  544 tests, 6 ignored (none of them archive tests).
- `web/tests/archives.test.mjs` (8 tests) passed through `/pkg/zrax.js`,
  `/dist/zrax.js` and both workbench pages after `./build-web.sh`. The
  whole browser suite (`npm test`) passed 77 of 81 tests; 4 were skipped
  because they need D10 and RX113 firmware that is not in the repository.

Fixtures were written by Info-ZIP Zip 3.0, 7-Zip 26.03, Python 3.14.7,
bsdtar and bsdcpio 3.5.3 (libarchive 3.7.4) and Apple gzip (see
`tests/fixtures/archives/README.md`). The crc CPIO format, big-endian
binary CPIO, GNU base-256 sizes, sparse members, hard links, pax global
headers and the package layouts were tested only with archives built from
the documented layouts, not with real tool output. Real APK, JAR, IPA,
Nordic DFU and PDX packages were not tested, and archives larger than the
extraction limits were tested only through declared sizes.
