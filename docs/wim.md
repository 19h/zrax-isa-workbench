# WIM images

`src/formats/wim.rs` and its submodules (`header.rs`, `lookup.rs`,
`resource.rs`, `metadata.rs`, `xml.rs`, `integrity.rs`, `files.rs`) parse
Windows Imaging Format files into the shared container model
([compressed streams and the container model](compressed-streams.md)):
`.wim` images, the `.swm` parts of split WIMs, and unencrypted `.esd`
files, which are WIMs with solid LZMS resources. The files of every image
are the container's children, labeled `/<image index>/<path>`; each file
in a recognized format is decoded, verified against its SHA-1 and
classified by its own parser, so the PE drivers, boot managers and
executables of a Windows image report their own ISAs. A WIM names no CPU:
the container target is always unknown, and the primary ISA comes from
the first listed file with a known ISA.

Resources are stored, or compressed in chunks with XPRESS, LZX or LZMS.
These are three codecs of the compressed layer:

- `Codec::XpressHuffman` (`src/formats/compressed/xpress.rs`), new: the
  [MS-XCA] LZ77+Huffman format in one 64 KiB block;
- `Codec::LzxWim { window_bits }`, the WIM framing of the cabinet LZX
  decoder (`src/formats/compressed/lzx.rs`);
- `Codec::Lzms` (`src/formats/compressed/lzms.rs`), new.

The canonical Huffman decoder and the 16-bit little-endian bit reader that
LZX already used moved to `src/formats/compressed/huffman.rs`, generalized
over the codec name in their messages and over the bit source, so XPRESS
and LZMS share them; the cabinet LZX decoder's output and errors are
unchanged (see [Verification](#verification)).

## Implemented layouts

| JSON format ID | Container variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `wim` | `WIM image` | 208-byte header (versions 1.13 `0x10D00` and `0xE00`), lookup table of 50-byte entries, image metadata resources (security data, directory entries, stream entries), UTF-16LE XML data, optional integrity table | Strong: `MSWIM\0\0\0` at 0 and header size 208 at 0x08 | One child per data stream in a recognized format: `/<image>/<path>` for a file's contents, `/<image>/<path>:<name>` for a named stream | MSWIM; wimlib v1.14.5 |
| `wim` | `split WIM part` | The same header with a total part count above 1 (`.swm`) | Strong, as above | Part 1: the files whose resources it holds. Later parts: each resource in a recognized format, labeled `resource <sha1>` | MSWIM "Split (Spanned) WIM"; wimlib `split.c` |

Resource encodings:

| Encoding | Where | Decoding | Source |
| --- | --- | --- | --- |
| Stored | Resource flags without `COMPRESSED` | Borrowed from the input; the stored size must equal the size | MSWIM "WIM File Resource" |
| Chunked | `COMPRESSED` resources: a table of `chunks - 1` chunk offsets (4 B each, 8 B above 4 GiB), then the chunks | Each chunk is an independent stream of the header's codec, decoded to the chunk size (the last chunk to the rest); a chunk whose stored size equals its size is stored | MSWIM; wimlib `resource.c` |
| Solid | Version `0xE00`: runs of `SOLID` lookup entries; an entry with uncompressed size `0x1_0000_0000` is a solid resource, the others are files at offsets in the run's uncompressed data | The solid resource's own header (size 8, chunk size 4, format 4: 0 none, 1 XPRESS, 2 LZX, 3 LZMS), one stored size per chunk, the chunks | wimlib `blob_table.c`, `resource.c` (`alt_chunk_table_header_disk`) |
| XPRESS | Header flag `0x20000` (and `0x200000`, see W2) or solid format 1 | 256-byte table of 512 4-bit code lengths, 16-bit little-endian words read MSB first, matches of at least 3 B whose length header 15 adds a byte, and a 16-bit length after a byte of 255 | [MS-XCA] sections 2.1.4.3 and 2.2.4 |
| LZX | Header flag `0x40000` or solid format 2 | Window of the chunk size, at least 2^15 (2^15 to 2^21); no E8 header bit, E8 translation always undone with the translation size 12,000,000 over the chunk; a block size bit (1 means 32,768 B), otherwise 16 bits, and 8 more when the window is 2^16 or larger; no 32 KiB frame realignment | wimlib `lzx_decompress.c`, `lzx_common.c`; 7-Zip `LzxDecoder.cpp` (`_wimMode`) |
| LZMS | Header flag `0x80000` or solid format 3 | Range decoder (forward 16-bit units) and Huffman bitstream (backward 16-bit units); adaptive codes rebuilt every 1,024 or 512 symbols; literal, LZ and delta matches with three-entry repeat queues; the x86 filter undone | wimlib `lzms_decompress.c`, `lzms_common.c`; 7-Zip `LzmsDecoder.cpp` |

Sources, fetched on 2026-10-13:

| ID | Source | Pin | Files and SHA-256 | Used for |
| --- | --- | --- | --- | --- |
| MSWIM | Microsoft, "Windows Imaging File Format (WIM)", Download Center item 13096 | Page version 1.1 of 2024-07-15; document text "Last Updated: October 2007" | `Windows Imaging File Format.rtf` `397772cca016508194d13ac860633b56b4f2f94cbf7476e2112f557ad61cfe0c` | Header, `RESHDR_DISK_SHORT`, lookup table, metadata resource (security data, `DIRENTRY`, `STREAMENTRY`), file resources and chunk tables, integrity table, XML data, split WIMs |
| MS-XCA | [MS-XCA] "Xpress Compression Algorithm" | v20240423 (revision 10.0) | `[MS-XCA].pdf` `e7806b36adc81b75f50bf57559c55420fcaadeb98a0435e8865d2eb3512d5e9e` | XPRESS Huffman: table, bitstream, match encoding, decoding pseudocode (2.2.4) and the encoder's word placement (2.1.4.3) |
| wimlib | ebiggers/wimlib tag v1.14.5, commit `cd5e231c348c255ae5088873b5a66ee0eb96fa07` | `include/wimlib/header.h` `fde17fe304b6f154b2f8398d8c245e077d6c147fb99a3c2c43654fb3af8a73cf`; `resource.h` `27512d0434dfb90491b5c3952f0f9f7ab4e65b3579a43294054ac530b8a90125`; `dentry.h` `387c34a2ed5a5a237f25bec9c0c470d33a92971846e22e67aed7f2b28cf86662`; `inode.h` `94a41658c9d7ab864da3fb804eb16d12c142da9c960485fe95d3916be8da49fd`; `lzx_constants.h` `b25b11d5a9005ab6f2665ebbfcb0290fb2f6823f4ec19a7afb0721ed4ebab000`; `lzms_constants.h` `2cf96fe8040f80f75ca61c65294861aafd38cf40f18ef8082c8d6b59fdd74ed6`; `xpress_constants.h` `aa16a565e96710303f244f3849a1e5a0bee3859c4339c733e29d423fc0881f04`; `src/resource.c` `188feebd2d110da66e540db5f57ee00e4ae58eada9be877bed7b9f4d62fb57fd`; `blob_table.c` `2903517091c356d08fc81f25bf44f8f8b6b42391a50122ea9a155a3a6aad806b`; `metadata_resource.c` `69def3ecd8525517c3e73a0a60579d64304008d2d23d3e587d495f1d891769ea`; `dentry.c` `8956c7b2539f51bef0d725162e2789ce9782acd0bf96bccc6f61d8a030a15036`; `security.c` `79ef186cb1df582b8f23fe160026ccd76f83fbf5cad501684a1a6f850d55decd`; `header.c` `4da5a6df55652c2a8407ad1978bed1a900b0559a794791a3e63833e05e6c7e46`; `wim.c` `fe5980dde9af66e6fbd12a4d9bc95f87226130d525e01adc677ce8f9f4387487`; `xml.c` `e0c4d07c428d5e162116bee4ef5093b517f364d0e12f1ee63cbfc72850024e21`; `integrity.c` `fa349bbf16e296d0c4ed31f6a62b4fc1a2ade0ce695eb6149a928d7279fb481a`; `write.c` `209a91d20531bf984c0fe034005be06adb0274746a9394e34b1042ebffce3ca2`; `xpress_decompress.c` `7e0efb7f3126c1017d6d3b0e7367780238d7a3a71214d19ee2abaeb98fae6db9`; `lzx_decompress.c` `3a2dc58cd3ccf2421c505f263c7a2c09bbfaab10f98a5a43ecd363fae14c9cfd`; `lzx_common.c` `3ffae81b9d1b2f6b506bb20f4b19fa4f21cc392f17b664cb99cd0e0a383a211e`; `lzms_decompress.c` `c2b521c787101cff8102341c1407517e8ac83401b5c2bd8050068fe9b754c00e`; `lzms_common.c` `4c33aad108d2ec5f50323a3a5c82028ff339476081e7c098ed2ee2b1f21c7a24`; `compress_common.c` `a588cccd434c0b7c3849601502b45c6b0a5034315b6e08809fb3272cde51ddae` | Version `0xE00`, the LZMS and `XPRESS_2` flags, chunk size bounds, solid resources, lookup table rules, stream types, the WIM LZX framing, LZMS (which Microsoft does not document), the canonical code construction LZMS rebuilds |
| 7-Zip | ip7z/7zip tag 26.03, commit `0766b733fe3e06dd2a7f9a3cfbf2108ac73abd17` | `CPP/7zip/Archive/Wim/WimIn.cpp` `239c60df65f9f6c9025b0d3c0827103a469e8544d0ea62381b19dd81138d9d5f`; `Compress/XpressDecoder.cpp` `64d77643cebd668a7a4589a28e71ec55f55d7104fa31b3ba1d6d9827583e7e29`; `Compress/LzxDecoder.cpp` `92844d4d58653c746439b79f146128bb8196aca1f9869e43810bffb4341fd5e6`; `Compress/LzmsDecoder.cpp` `20ede485abedef236dceacedcbc494d878837f21f41d40e5a4a091579e0a8b94` | A second reader: chunk size 0 means 32 KiB, directory walks bounded by the resource size; the independent decoder of the fixtures |

## Listing

For each image, in lookup table order, the metadata resource is decoded
whole and its SHA-1 verified, and its directory tree is walked in
pre-order. Stream types are not stored; they are assigned as wimlib's
`assign_stream_types_unencrypted` assigns them: named stream entries are
named data streams, and the entry's main hash (when not zero) and its
unnamed stream entries are, in order, the reparse point data of a reparse
point and the file's contents. An encrypted file's first nonzero unnamed
stream is its EFS raw data.

A first walk of every image collects the resources that data streams
name. Each is then examined once, in the order the resources are stored
(by resource offset, then by offset in a solid resource), so the chunks of
a solid resource are decoded in order: its first 4 KiB must be a
recognized format (`container::is_recognized`), and only then is it
decoded whole, its SHA-1 verified against the lookup table, and its whole
contents checked again. The second walk lists the recognized resources
under their paths. A resource under several paths (hard links, files that
several images share) is decoded once and listed under each path.

A child's offset and stored size are file coordinates: the stored file
for a stored resource, the whole compressed resource for a chunked one,
and the chunks that hold the file for a file in a solid resource. Its
`transform` names the codec (`XPRESS`, `LZX`, `LZMS`). Children follow
image order and directory order, so the files of image 1 decide the
primary ISA.

The header, lookup table, XML data, integrity table and listing are
reported in notes and metadata: `wim_version`, `wim_flags`,
`wim_compression`, `wim_chunk_size`, `wim_guid`, `wim_part`,
`wim_image_count`, `wim_boot_index`, `wim_lookup_entries`,
`wim_file_resources`, `wim_image_<n>_name`, `wim_image_<n>_arch` (for
example `9 (x64)`), `wim_integrity`, `wim_streams_listed`,
`wim_listed_size` and `wim_resources_verified`. The XML architecture is
text: it is never used as the ISA.

## Wire units and byte order

All fields are little-endian. Offsets and sizes are bytes; resource
offsets count from the start of the file, a directory's entry list offset
from the start of its metadata resource, and a file in a solid run from
the start of the run's uncompressed data. A resource header's stored size
is 56 bits (seven bytes) followed by the flag byte. Names are UTF-16LE;
unpaired surrogates become U+FFFD. The integrity table's SHA-1s cover
the bytes from the end of the header (0xD0) to the end of the lookup
table, in chunks of the table's chunk size.

## Validation and resource bounds

- The header must be 208 B with version `0x10D00` or `0xE00`, part number
  1 to the part count, and, when the compression flag is set, one of the
  codec flags (wimlib's order: LZX, XPRESS or `XPRESS_2`, LZMS). Chunk
  sizes are powers of two: XPRESS 4 KiB to 64 KiB, LZX 32 KiB to 2 MiB,
  LZMS 32 KiB to 1 GiB (wimlib `wim_chunk_size_valid`); 0 means 32 KiB.
  These are parse errors, as is a lookup table that is larger than
  256 MiB, lies outside the input or holds an invalid resource or solid
  resource header.
- Lookup entries are skipped as wimlib skips them (zero hash, size 0,
  other parts, repeated hashes, unreferenced metadata, metadata in solid
  resources or in later parts, metadata beyond the header's image count)
  and counted in a note.
- Damaged files, metadata resources and XML data are notes, never errors:
  a file that fails to decode or whose SHA-1 does not match is left out
  and noted under its first path (16 such notes, then a count); an image
  whose metadata does not read or verify is noted and not listed.
- Chunks: a stored size of 0 or above the chunk's size, chunk extents
  outside the resource, and a decoded size other than the chunk's size are
  errors. A chunk above 64 MiB (only LZMS allows one) is not decoded.
- XPRESS: complete prefix codes of at most 15 bits; an extended 16-bit
  length below 15 is invalid ([MS-XCA] 2.2.4). LZX in WIMs: block sizes of
  0 or larger than the rest of the chunk, repeated offsets of 0 in
  uncompressed blocks, and uncompressed blocks past the input are invalid.
  LZMS: chunks of an even size of at least 4 B; codes rebuilt with
  wimlib's length-limited construction (at most 15 bits).
- Directory walks enter at most 64 levels below the root and read at most
  as many entry bytes as the resource holds (7-Zip `DirProcessed`), so a
  loop or overlapping lists stop the walk with a note. Entries with an
  empty, `.`, `..` or NUL-holding name are skipped with their subtrees.
- Files above 64 MiB (`MAX_PAYLOAD`) are not decoded. At most 65,536
  resources are examined, 4,096 children listed (`MAX_COMPONENTS`) and
  256 MiB of recognized files and their repeated listings kept
  (`MAX_EXTRACTED`). A metadata resource may decode to 256 MiB and all of
  them to 1 GiB per walk; XML data is read up to 16 MiB; image names are
  cut at 256 characters and labels at 1,024 bytes (keeping the end). All
  chunk decoding for one WIM stops at 2 GiB; a solid resource keeps one
  decoded chunk for the next read. What a limit leaves out is counted in
  a note.
- Trailing bytes after the last structure the header and the lookup table
  name are noted with their size.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| W1 | A chunk size field of 0 in a compressed WIM means 32 KiB (7-Zip; wimlib rejects it) | A WIM written by WIMGAPI or DISM with the field 0; not verified (no such file was available) |
| W2 | Header flag `0x200000` (`XPRESS_2`, "XPRESS, with small chunk size???" in wimlib) means XPRESS chunks | Decode a WIM that sets it with DISM and with this parser; not verified. No detection depends on it |
| W3 | The WIM LZX framing (no E8 header bit, translation size 12,000,000 per chunk, one-bit default block size, no frames) is wimlib's and 7-Zip's | `lzx.wim` and `solid-lzx.wim` written by the test encoder from that framing pass `7zz t` (7-Zip 26.03) and extract identically (2026-10-13); a WIMGAPI-written LZX WIM was not tested |
| W4 | LZMS as wimlib decodes it is the format WIMGAPI writes | `solid-lzms.wim` (literal, LZ, repeat and delta matches, x86 filter) passes `7zz t` and extracts identically (2026-10-13); a Microsoft ESD was not tested |
| W5 | XPRESS chunks are one [MS-XCA] block of at most 64 KiB, the EOF symbol optional | `xpress.wim` passes `7zz t`, whose decoder requires the EOF symbol (the test encoder writes it); chunks without it decode here, as in wimlib |
| W6 | Solid blob entries carry the blob size in the stored-size field, the offset in the run, and an uncompressed size of 0 (wimlib `write.c`, 7-Zip `IsSolidSmall`) | Both solid fixtures pass `7zz t`; a WIMGAPI ESD was not tested |
| W7 | Image metadata resources belong to images in lookup table order, and the XML `INDEX` numbers images the same way (wimlib) | `images_share_resources_and_decode_each_once` labels by table order; a multi-image DISM capture would show a mismatch as names under the wrong index |
| W8 | Stream types follow wimlib's assignment, so reparse point data and EFS raw data are never taken for file contents | `stored_wims_list_recognized_files_by_path_at_their_stored_offsets` (symbolic link and encrypted file not listed, named stream listed) |
| W9 | Chunk table entries are 4 bytes up to an uncompressed size of `0xFFFFFFFF` and 8 bytes above (wimlib); MSWIM says 8 bytes "for > 4GB" | A resource of exactly 4 GiB; such resources exceed the 64 MiB decoding limit, so only metadata or solid reads could meet the difference |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Pipable WIMs (`WLPWM\0\0\0`, a wimlib extension) | Not recognized |
| WIM versions other than `0x10D00` and `0xE00` (pre-1.13 images, which 7-Zip reads with other header sizes) | `Unsupported WIM version` parse error |
| Encrypted ESDs (`<ESD><ENCRYPTED>` in the XML data) | Opaque, with a note; nothing is decoded (wimlib refuses them too) |
| Split WIMs | Parts are not joined: part 1 lists the files whose resources it holds and counts those in other parts; later parts list their resources by SHA-1 |
| Files above 64 MiB, LZMS chunks above 64 MiB | Not decoded; counted in a note |
| Metadata resources in solid resources | Skipped and counted, as wimlib does |
| Reparse points, EFS-encrypted files | Counted, not examined |
| Security descriptors, timestamps, short names, hard link groups | Not reported; hard links are listed under every path |
| XML data | Only `NAME`, `WINDOWS/ARCH` and `ESD/ENCRYPTED` are read; the document is not validated. No digest covers it, so image names are reported as written |
| Integrity table | Verified when present; it covers the header-to-lookup-table bytes, not the XML data |
| `rhBootMetadata` | Not compared with the boot image's lookup entry |
| Names | Reported as stored: a name that holds `/` or `\` is not split into a path |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly f248f4038
2026-09-05), the 22 tests of `tests/wim.rs` passed: stored, XPRESS, LZX
and LZMS WIMs, solid resources of each codec, shared and repeated
resources, split parts, integrity tables, encrypted-ESD markers, header
errors, damaged files and metadata, directory loops, the component limit,
the committed fixtures, every prefix up to the end of the lookup table
(each an error) of a stored, an XPRESS, an LZX, a solid LZX and a solid
LZMS image, and single-byte mutations (0x00, 0xFF, a bit flip) of every
structure byte and every third file byte of those images without a
panic. One of the 22, `real_wims_from_wim_samples_dir`, ran without
checking anything: `WIM_SAMPLES_DIR` was not set, because no WIM, ESD or
SWM file was found among IDA Pro's test inputs or on this Mac. The unit
tests of the WIM modules (16) and of the XPRESS (6), LZMS (6), shared
Huffman (4) and LZX (10) codecs passed. The browser test
`web/tests/wim.test.mjs` (4 tests: both packaged module paths and both
workbench pages) passed in Playwright Chromium.

The fixtures are synthetic (`tests/fixtures/wim/README.md`): one stored
WIM written by 7-Zip 26.03, and XPRESS, LZX, solid LZX and solid LZMS WIMs
written by the test encoders. 7-Zip 26.03 verified the SHA-1 of every file
of all five and extracted the four synthetic ones identically; that is the
only check by an independent decoder. WIMs written by Microsoft tools
(DISM, WIMGAPI, Windows setup media) were not tested.

The LZX refactor (shared Huffman reader, WIM framing) was checked with a
differential snapshot on 2026-10-13: the cabinet LZX decoder's output
size, consumed bytes and output hash, or its error text, for four
streams of the cabinet LZX test encoder (`tests/support/lzx.rs`:
verbatim, aligned offset, uncompressed and verbatim, and E8 blocks) at
five output limits, every truncation and single-byte mutations (0x00,
0xFF, each bit flip) were identical before and after the change (6,928
lines). The cabinet tests (`tests/cab.rs`) pass unchanged.

After integration on the same day, the native suite passed 2,732 tests
with 6 ignored, and IDA's corpus (4,621 files, no WIM images) classified
as before.
