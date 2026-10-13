# Microsoft cabinets

`src/formats/cab.rs` and its submodules (`header.rs`, `folder.rs`,
`files.rs`) parse Microsoft cabinet files (`MSCF`, `.cab`, also the
container of `.msu` updates and of many driver packages) into the shared
container model ([compressed streams and the container model](compressed-streams.md)).
The files of a cabinet are the container's children, labeled by their
names; each file whose bytes this cabinet holds is cut from its folder's
uncompressed bytes and listed when it is a recognized format, so PE
drivers and executables, ELF files and nested cabinets are classified by
their own parsers. A cabinet names no CPU: the container target is always
unknown and the primary ISA comes from the first listed file with a known
ISA.

Folders are decoded when they are stored, MSZIP-compressed or
LZX-compressed. LZX is a new codec of the compressed layer
(`src/formats/compressed/lzx.rs`, `Codec::Lzx { window_bits }`), and MSZIP
uses a new compressed-layer primitive, `compressed::inflate_continuing`,
which inflates one raw DEFLATE stream with the bytes already decoded as its
history. Quantum folders are not decoded.

## Implemented layouts

| JSON format ID | Container variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `mscab` | `MSCF cabinet` | CFHEADER (36 B fixed; optional reserve sizes and per-cabinet reserve; optional previous and next cabinet and disk names), CFFOLDER table (`coffCabStart`, `cCFData`, `typeCompress`, per-folder reserve), CFFILE table at `coffFiles` (`cbFile`, `uoffFolderStart`, `iFolder`, `date`, `time`, `attribs`, `szName`), CFDATA blocks (`csum`, `cbData`, `cbUncomp`, per-block reserve, data) | Strong: `MSCF` at 0, `reserved1`, `reserved2` and `reserved3` zero, and `coffFiles` at or after 36 + 8 * `cFolders` and below `cbCabinet`, all in the first 36 bytes | One child per file in a recognized format, labeled with its stored name (`bin\driver.sys`); stored, MSZIP (`CK` + DEFLATE with the history of earlier blocks) and LZX (window 2^15-2^21) folders | Cabinet SDK "Microsoft Cabinet Format"; [MS-MCI]; [MS-PATCH]; libmspack `cabd.c`, `lzxd.c` |

`typeCompress` (Wine `include/fdi.h`, matching libmspack `cab.h`): bits 0-3
are the type (0 stored, 1 MSZIP, 2 Quantum, 3 LZX); bits 8-12 are the LZX
window or Quantum memory in bits; bits 4-7 the Quantum level. Folders of
type 4-15 are reported with their type and not decoded.

Sources, fetched on 2026-10-13:

| Source | Pin | Files and SHA-256 | Used for |
| --- | --- | --- | --- |
| Cabinet SDK documentation, "Microsoft Cabinet Format" (Microsoft Learn, archived), `https://learn.microsoft.com/en-us/previous-versions/bb267310(v=vs.85)` | Page `ms.date` 2007-01-30, `updated_at` 2021-12-02 (© 1997) | HTML `7cb20d747d67a7a97f7cfb0678f76ca3d4e89331912653885819781d75215444` (identical on two fetches) | CFHEADER, CFFOLDER, CFFILE, CFDATA, flags, `iFolder` and `attribs` values, "Checksum Method" (`CSUMCompute` and the split-block rules), "UTF Encoding Method", the sample cabinet, "MSZip Format", "LZX Format" (the original LZX document) |
| [MS-MCI] "Microsoft ZIP (MSZIP) Compression and Decompression Data Structure" | v20161017 (revision 7.3) | `[MS-MCI].pdf` `cb097c434e1cfccb368f0d7e9084ab4d47a65809a2eea94bbf41f9722c1a0343` | MSZIP blocks: `CK`, one or more RFC 1951 blocks ending with a final block, trees discarded, history kept, at most 32 KiB per block |
| [MS-PATCH] "LZX DELTA Compression and Decompression" | v20250819 | `[MS-PATCH].pdf` `ea17466b97c9a9d4e2c815538387bf442fb2393ed29632c6f58b2c47ef1f29fe` | The corrected LZX format: bitstream, block header, uncompressed block padding, aligned offset block layout, tree delta coding, position slots, E8 translation, the "abc" example |
| libmspack | kyz/libmspack commit `55d501976171397ccd5d5a7a1ca7da065b1d9a06` (2026-07-21) | `libmspack/mspack/cabd.c` `3fec20d659b18cfe73f8e18a54e4cb856098f1aa3aa076ff936a79b0b831d7eb`; `cab.h` `3e132b386dd241994a79cb9ad03fc8fa5776ed700d598dfc65caa55152bd61c9`; `lzxd.c` `bc4a14a5938d99cb1e2521a0fcc16fa44e8ea262ab0bc072e3f9003e19c816da`; `lzx.h` `22b1ffa9ddc15aa5fac95d4f4f0c60486f590e55636a17ab94f3ad1b770f907f`; `mszipd.c` `04ba76766f723552df4dc35b455ccdf6f6a795d13a549f68a314a2bae1d277ba`; `readbits.h` `7c849edb9b939b4eb1e9e2b895b7fee3eb19e23d0a1dab87c6c504cf007010ab`; `readhuff.h` `446c7ca1cfb11a80cd1b4e86006abea3f6052059636361ddb1e227f29ccee560` | Block size bounds (`CAB_BLOCKMAX`, `CAB_INPUTMAX`), the checksum's header bytes, LZX folders as one stream of 32 KiB frames, the LZX decoder's behavior where the documents leave a case open (end-of-input padding, run codes past a tree's end, empty length trees) |
| Wine | wine-mirror/wine commit `081042ede6a165a36bf9988350dd584b440d7a3d` (2026-10-12) | `include/fdi.h` `07baf3a1e641cabbf70846ccd9dbe50b46772056a4bcf5828b2585f94fa9e04e` | `typeCompress` masks (`tcompMASK_TYPE`, `tcompMASK_LZX_WINDOW`, Quantum level and memory) |
| osslsigncode | mtrojnar/osslsigncode commit `bf7533deb1311ccd80d241f668ed1a8ca586ea3c` (2026-09-30) | `cab.c` `eb47a4f21d2654b0432863d56fce89338117250dc5d87566995c8a0417ef9840` | The per-cabinet reserve of Authenticode-signed cabinets (`cab_ctx_get`) |

The Open Specifications edition [MS-CAB] is no longer published: on
2026-10-13 the Windows and Office protocol document hosts return 404 for
`MS-CAB`, and learn.microsoft.com has no `ms-cab` page. The archived Cabinet
SDK documentation is Microsoft's own specification and is used instead.

Where the sources disagree:

- The SDK's LZX document has errors that libmspack's `lzxd.c` lists and
  [MS-PATCH] corrects: 1 MiB and 2 MiB windows have 42 and 50 position
  slots (not 40 and 42); every block, uncompressed ones too, has a 24-bit
  size after its 3-bit type; an aligned offset block codes its aligned
  tree *before* the main and length trees and also codes the length tree;
  with exactly 3 footer bits an aligned block reads only the aligned
  symbol; a tree length is `(previous - code) mod 17`, not `+ code`. The
  corrected forms are used.
- The SDK's text for `cbCFData` says the field is absent when
  `cfhdrRESERVE_PRESENT` is set, while the structure and libmspack read all
  three reserve sizes together when it is set; the structure is used.
- The CFDATA checksum's header part: the SDK's code runs `CSUMCompute`
  from `cbData` over `sizeof(CFDATA) - sizeof(csum)` bytes, which with the
  structure's unsized reserve and data arrays is the 4 bytes of `cbData`
  and `cbUncomp`; libmspack computes exactly those 4 bytes. The field text
  ("from CFDATA.cbData through CFDATA.ab[cbData-1]") could be read to
  include the per-block reserve. The 4-byte form is used; with a per-block
  reserve it is not verified on a real cabinet (none was available).
- The SDK requires one or more folders and files; libmspack rejects 0 of
  either. Both are parse errors here.
- libmspack reads the CFFILE table right after the CFFOLDER table and only
  warns when `coffFiles` differs; here `coffFiles` is used, a gap is noted,
  and an offset inside the folder table is a parse error.

## Children and classification

- **Order.** Folders are processed in order and, within a folder, files in
  table order (the SDK orders the table by folder, then offset), so the
  children follow the cabinet. The first child with a known ISA supplies
  the primary ISA; file names never decide how a file is classified.
- **Recognition.** A file is examined only when its folder holds all of its
  bytes in this cabinet. Its first 4 KiB, then its whole contents, must be
  a recognized format (`container::is_recognized`); the file is then
  listed with `if_recognized`. Empty files and files in other formats are
  counted, not listed.
- **Stored folders.** A file inside one CFDATA block is borrowed from the
  input at its exact offset. A file that spans blocks is reassembled with
  transform `CFDATA blocks`; its slice starts at its first byte and runs to
  its last, the CFDATA headers between included.
- **MSZIP folders.** Each block must start with `CK` and inflate, with the
  earlier blocks' output as history, to exactly its `cbUncomp`. The
  transform is `MSZIP`.
- **LZX folders.** The blocks are one LZX stream whose 32 KiB frames are
  the blocks, as libmspack decodes them; every block but the folder's last
  must be 32 KiB, otherwise the folder is not decoded. The transform is
  `LZX`.
- **Stored coordinates of compressed files.** A file's slice starts at the
  data of the CFDATA block that holds its first byte and ends with the data
  of the block that holds its last byte; the decoded range is the file.
- **Checksums.** Every block with a nonzero `csum` is checked; blocks with
  `csum` 0 carry none (the SDK: extractors then skip the check). A folder
  with a mismatch is not decoded, and a note names the first mismatch.
- **Cabinet sets.** Files whose `iFolder` is `0xFFFD`, `0xFFFE` or `0xFFFF`
  are named in notes and not joined. When a file continues from the
  previous cabinet, folder 0 began there, so none of its files is
  extracted; when one continues into the next cabinet, the last folder's
  last block may be split (`cbUncomp` 0) and is not decoded. The
  neighbors' cabinet and disk names, the set ID and the index are noted.
- **Signatures.** A per-cabinet reserve of 20 bytes whose first word is
  0x00100000 and whose next two words name a signature right after
  `cbCabinet` is an Authenticode signature (osslsigncode's layout); it is
  reported as present and not verified, and the cabinet's content then
  ends after it. Any other reserve is application data and only its size
  is reported.
- **Metadata.** `<prefix>_image_size` and one `<prefix>_component_<n>`
  entry per child (from the container model), plus `cab_version`,
  `cab_folders`, `cab_files`, `cab_flags`, `cab_set_id`, `cab_index`,
  `cab_header_reserve` (when not empty), `cab_previous_cabinet` and
  `cab_next_cabinet` (in a set), `cab_folder_<n>` for the first 64
  folders (compression, `typeCompress`, blocks, offset, stored and
  uncompressed sizes),
  `cab_checksums_verified`, `cab_signature_offset` and
  `cab_signature_size` (when signed), `cab_files_listed` and
  `cab_decoded_size`.

## Wire units and byte order

| Structure | Byte order | Units |
| --- | --- | --- |
| CFHEADER, CFFOLDER, CFFILE, CFDATA | Little-endian | Offsets are file offsets in bytes; `uoffFolderStart` and `cbFile` are bytes of the folder's uncompressed data |
| CFDATA checksum | XOR of little-endian 32-bit words, the 1-3 trailing bytes with the first most significant | Over the data, then over `cbData` and `cbUncomp` |
| LZX bitstream | 16-bit little-endian words, bits read most significant first; uncompressed blocks' repeated offsets little-endian 32-bit | 32 KiB frames; window 2^15-2^21 bytes |
| Names | `_A_NAME_IS_UTF` (0x80): UTF-8; otherwise an unspecified code page, shown as UTF-8 with replacement characters for other bytes (and noted) | NUL-terminated, at most 255 bytes |

Header byte order is never reported as code byte order; the files' own
parsers report theirs.

## Validation and resource bounds

- Header: the signature, zero reserved fields, `cbCabinet` of at least
  36 bytes and at most the input's size (a shorter input is `Truncated
  cabinet`), at least one folder and one file, reserve sizes, reserve area
  and neighbor names inside the cabinet, `coffFiles` at or after the end of
  the folder table; anything else is a parse error. A version other than
  1.3, reserved flag bits and a per-cabinet reserve over 60,000 B are
  noted rather than rejected, as libmspack accepts them (it warns about
  the version and the reserve).
- Names: NUL-terminated within 256 bytes and not empty (cabinet names and
  `szName`; disk names may be empty), as libmspack reads them.
- File table: `cFiles` entries must fit in the bytes after `coffFiles` at
  18 bytes or more each before any is read; `iFolder` must name a folder
  or be a continuation value, and a continuation must have the neighbor
  the header names.
- CFDATA: `cCFData` blocks must fit at 8 bytes plus the reserve each; every
  block lies in the cabinet, decodes to at most 32 KiB and stores at most
  38 KiB (libmspack's `CAB_BLOCKMAX` and `CAB_INPUTMAX`); `cbUncomp` 0
  only for the last block of a folder that continues in the next cabinet;
  a stored block's sizes are equal unless it is split across cabinets.
  Two folders' blocks may not overlap.
- Decoding: each folder is decoded at most as far as its last extractable
  file and at most 64 MiB (`MAX_PAYLOAD`); decoded folder bytes and
  reassembled stored files are charged against 256 MiB per cabinet
  (`MAX_EXTRACTED`); files that a limit cuts off are named in a note. At
  most 4096 children are listed (`MAX_COMPONENTS`); the rest are counted.
  Notes list at most 8 names and count the rest; `cab_folder_<n>` metadata
  describes the first 64 folders and a note counts the others. Files are
  grouped by folder in one pass, so the largest tables (65,533 folders,
  65,535 files) parse in linear time.
- LZX: windows of 2^15-2^21 bytes; every Huffman code must be complete
  (only the length tree may be empty); a match may not reach before the
  start of the output or past the window, and may not cross a frame or
  block end; the input may be overread by one 16-bit word of zeros and no
  more (libmspack `read_input`); each token consumes at least one bit, so
  decoding is bounded by the input and the 64 MiB output.
- Data after the cabinet (and its signature) may be padding (noted), a
  recognized format (listed as `Data after the cabinet`), or a parse error.
- Strong detection means a damaged cabinet is a parse error, not raw code.
  Nesting is bounded by the six container levels of `lib.rs`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | `MSCF` with three zero reserved fields and a consistent `coffFiles` starts only cabinets | `detection_needs_zero_reserved_fields_and_a_consistent_files_offset`; none of the 44,391 files of IDA's test inputs (scanned recursively on 2026-10-13) starts with `MSCF` and four zero bytes, so no classification there changes |
| C2 | The CFDATA checksum covers the data and the 4 bytes of `cbData` and `cbUncomp` | The SDK's sample cabinet checksum 0x30A65ABD (`the_sdk_sample_is_detected_and_its_checksum_matches`); all 131 blocks of CrossOver's `winemono-support.cab` verify. A real cabinet with a per-block reserve whose checksums fail would show that the reserve is covered (not verified) |
| C3 | MSZIP blocks may copy from earlier blocks of the folder ([MS-MCI]) | `mszip_folders_decode_with_the_history_of_earlier_blocks`, whose second block copies from the first; 7-Zip 17.05 and bsdtar 3.5.3 extract the same bytes. The real cabinet tested uses no history (no block needs it) |
| C4 | Every CFDATA block of an LZX folder but the last decodes to 32 KiB, and the folder is one stream of frames | libmspack's design note; `lzx_folders_whose_inner_blocks_are_short_are_not_decoded`. A real LZX cabinet with shorter inner blocks would not be decoded (none seen) |
| C5 | The LZX decoder matches the reference decoders | On 2026-10-13: the `MSCompressed` LZX stream of p7zip 17.06's `7-zip.chm` (hhc output, 2^17 window, 98,834 B) decoded per reset interval to the 353,052 B that 7-Zip extracts, byte for byte, consuming each interval exactly; three cabinets built by the test encoder (every block type, repeated offsets, long matches, 17-bit footers in a 2^21 window, E8 translation over 24,438 changed bytes) extract identically with 7-Zip 17.05 and bsdtar 3.5.3 (libarchive 3.7.4) |
| C6 | A cabinet names no CPU | `stored_cabinets_list_recognized_files_by_name_at_their_stored_offsets` checks `target` is `None` |
| C7 | The 20-byte reserve that osslsigncode writes marks an Authenticode signature after `cbCabinet` | `signed_cabinets_report_the_signature_as_not_verified`; the meaning of its first word 0x00100000 is not documented (not verified on a cabinet signed by Microsoft's tools) |
| C8 | Files of folder 0 cannot be extracted when a file continues from the previous cabinet | `cabinet_sets_name_continued_files_and_skip_split_blocks`; their `uoffFolderStart` counts from the folder's start in an earlier cabinet (SDK "CFFOLDER") |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Quantum folders (type 2) | Reported with level and window; not decoded (no primary specification; libmspack `qtmd.c` only) |
| Cabinet sets | Continued files are named in notes, not joined across files |
| Authenticode signatures | Present, not verified |
| `_A_NAME_IS_UTF` names | Decoded as UTF-8; other names' code page is unknown and noted |
| `date`, `time`, `_A_RDONLY`, `_A_HIDDEN`, `_A_SYSTEM`, `_A_ARCH` | Not reported; `_A_EXEC` files are named in a note |
| LZX folders whose inner blocks are not 32 KiB | Not decoded, as libmspack does not decode them |
| LZX DELTA (reference data, chunk-size prefixes, 32 MiB windows) and CHM reset intervals | Not implemented; the codec decodes cabinet LZX only |
| Self-extracting executables and cabinets embedded in other files | Not searched; a cabinet must start at offset 0 |
| Real LZX and signed cabinets | Not tested: none is on this machine or in IDA's corpus; LZX was checked against a CHM stream and the reference decoders (C5) |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node v25.8.1 with Playwright Chromium), `cargo test
--all-features --locked` passed: 2,454 tests, 6 ignored (the
repository's existing ignores), including the 25 tests of `tests/cab.rs`
and the unit tests of `src/formats/cab*` (4), `src/formats/compressed/lzx.rs`
(9) and `inflate_continuing` (1). After `./build-web.sh`,
`web/tests/cab.test.mjs` (4 tests) passed through `/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`, decoding a
stored, an MSZIP and an LZX folder in WebAssembly; the whole browser suite
ran 284 tests, 280 passed and 4 skipped (the existing skips that need D10
and RX113 firmware not in the repository).

`tests/cab.rs` sweeps every prefix of a stored, an MSZIP and an LZX
cabinet (each is a parse error) and every byte of each with 0x00, 0xFF and
a bit flip. All fixtures are synthetic, built in the tests from the
documented layout, with an x86-64 ELF header and the UEFI fixtures' x86-64
PE image as members; LZX streams come from a test encoder
(`tests/support/lzx.rs`) written from [MS-PATCH], whose output 7-Zip and
bsdtar decode identically (assumption C5). With `CAB_SAMPLES_DIR` naming a
directory of links to CrossOver's `winemono-support.cab` (1,395,354 B, one
MSZIP folder, 28 files) and Homebrew's test fixture `container.cab` (95 B,
stored), the gated test passed: all checksums verified, 20 .NET PE files
listed (primary ISA CLR), and the 20 decoded files are byte-identical to
7-Zip's extraction. Without the variable the test is skipped. Real LZX,
Quantum, signed and multi-cabinet sets were not available and are not
verified.

After integration on the same day, the native suite passed 2,510 tests
with 6 ignored, the gated test passed again with `CAB_SAMPLES_DIR` naming
links to CrossOver's `winemono-support.cab` and Homebrew's
`container.cab`, and IDA's corpus (4,621 files, no cabinets) classified as
before.
