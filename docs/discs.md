# Console disc images

`src/formats/discs.rs` and its submodules (`gamecube.rs`, `wii.rs`,
`xdvdfs.rs`) parse GameCube and Wii disc images and Xbox / Xbox 360 game
discs in the XDVDFS filesystem into the shared container model
([compressed streams and the container model](compressed-streams.md)). A
disc image is a container whose children are its executables and the files
of its filesystem that are a recognized format, or, on the Wii, its
encrypted partitions. None of these formats names an ISA: the container
target is always unknown, and the ISA comes from the children.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `gamecubedisc` | `GameCube disc image` | Disc header (`boot.bin`, 0x440 B): game code, maker code, disc number, version, title; boot DOL, FST offset, size and maximum size; `bi2.bin` country code at 0x458; apploader header at 0x2440 (date, entry, code size, trailer size); boot DOL header; FST entries and string table | Strong: 0xC2339F3D (big-endian) at 0x1C | `Main executable (DOL)` (classified by the DOL parser); `Apploader` (code and trailer, as code, PowerPC target); FST files that are a recognized format, by path | YAGCD chapter 13; Dolphin `2606` `DiscUtils.*`, `VolumeGC.cpp`, `VolumeDisc.cpp`, `FileSystemGCWii.*`, `DolReader.h`, `Boot_BS2Emu.cpp` |
| `wiidisc` | `Wii disc image` | The same disc header fields; hash and encryption flags at 0x60/0x61; partition information at 0x40000 (four groups of a count and a table offset >> 2); table entries (partition offset >> 2, type); region code at 0x4E000; each partition header's data offset and size (>> 2) at 0x2B8/0x2BC | Strong: 0x5D1C9EA3 (big-endian) at 0x18 | One opaque child per partition, `Partition <group>.<index> (<type>)`, covering header and data | Dolphin `2606` `VolumeWii.*`, `DiscUtils.*`, `VolumeVerifier.cpp`, `Volume.cpp`, `Enums.h` |
| `xboxdvd` | `XDVDFS image` | Game partition at 0 (XISO) | Strong: `MICROSOFT*XBOX*MEDIA` at 0x10000 | Files that are a recognized format (XBE, XEX, ...), by path | extract-xiso `3f5b62cfe68f` `extract-xiso.c`; xdvdfs `6b05af7fba79` `xdvdfs-core`; xenia `1a8068b151bf` `disc_image_device.cc`; XboxDevWiki "XDVDFS" oldid 7031 |
| `xboxdvd` | `XGD1 disc image` | Game partition at 0x18300000 | Strong: the magic at 0x18310000 | As above, offsets in the full image | xdvdfs `XDVDFSOffsets::XGD1`; extract-xiso `XGD1_LSEEK_OFFSET` |
| `xboxdvd` | `XGD2 disc image` | Game partition at 0xFD90000 | Strong: the magic at 0xFDA0000 | As above | xdvdfs `XDVDFSOffsets::XGD2`; extract-xiso `GLOBAL_LSEEK_OFFSET` (added with "XBox 360 iso extraction supported"); xenia `likely_offsets` |
| `xboxdvd` | `XGD3 disc image` | Game partition at 0x2080000 | Strong: the magic at 0x2090000 | As above | xdvdfs `XDVDFSOffsets::XGD3`; extract-xiso `XGD3_LSEEK_OFFSET`; xenia `likely_offsets` |

Sources, fetched on 2026-10-13:

| Source | Pin | Used for |
| --- | --- | --- |
| Dolphin | tag `2606`, commit `6094cfcf7b8fba733b3116fdf3414d51c1c0e4a4`; `Source/Core/DiscIO/DiscUtils.h` SHA-256 `88e3992519ff6d77a3ccddff3ff9d3eb16b5add6e20efea67820b2656be6f046` | Magics, header addresses, offset shift, DOL size, FST layout and validation, apploader loading, partition table and header, partition type names, region codes, detection order |
| YAGCD (Yet Another GameCube Documentation) | <https://www.gc-forever.com/yagcd/chap13.html>, SHA-256 `a07e9c56363d5ade55c1be005ca2432d8a7ae86776901f7c622bfe057ea8f6bd` | Disc header, `bi2.bin`, apploader header, FST entry layout |
| extract-xiso | commit `3f5b62cfe68f000b0e3c8a30104973f3a297948e`, `extract-xiso.c` SHA-256 `b2469f2713281ed571cb3b88e8e7428906f2ec233c62e975ad6a47a476144251` | Volume descriptor, both magics, game partition offsets, directory entry layout, attributes, name rule |
| xdvdfs | commit `6b05af7fba79d567ef8c9698c8702b8d782248b8`; `blockdev/offset.rs` SHA-256 `415ac31d6537d29e2171b2e343e60c9689a8f3ba1f3b1de8265580e6a66a530a` | XGD names of the offsets, little-endian layout, empty slots, `0xFFFF` links, Windows-1252 names |
| xenia | commit `1a8068b151bfd524a13b9cbe99be95d0200760a5`, `disc_image_device.cc` SHA-256 `b920d54c03cd6272e4a3d27f212345ac354e7e090bfff5aff472d066fec2864e` | Entry layout and tree walk, partition offsets |
| XboxDevWiki "XDVDFS" | oldid 7031 (2022-03-06), raw wikitext SHA-256 `d71f729c463ade10c7ccf4c4ef2d9ff5cb1730e2022e5dc2d0d592d00f45b967` | Volume descriptor table, sector size, attribute flags |

## Children and classification

- **GameCube apploader.** The bytes Dolphin's `RunApploader` loads to
  0x81200000 (code size plus trailer size, from 0x2460) form one child,
  classified as raw code (`Classify::Code`). It carries the target PowerPC,
  32-bit, big-endian: `RunApploader` calls `RunFunction(entry)`, which
  single-steps the emulated PowerPC from the apploader's entry point, and
  `SetupMSR` leaves `MSR[LE]` clear. This is the only target the family
  sets, because it is the only one the sources establish. The apploader
  follows the boot DOL, so it supplies the primary ISA only for a disc
  without a recognized DOL; both precede the FST files.
- **GameCube boot DOL.** The DOL at the header's offset forms one child of
  the DOL's size: the end of its last non-empty section. Dolphin's
  `GetBootDOLSize` also counts empty sections' offsets; `DolReader` loads
  only non-empty ones, and only those count here. The child is classified
  from its own bytes, so `console.rs`'s DOL parser reports it as PowerPC.
  Datel discs leave the DOL offset 0; such a disc has no DOL child and a
  note says so.
- **GameCube FST files.** Every file is examined in FST order. A file is
  probed with the first 4 KiB of its bytes, or as a DOL when its first
  0x100 bytes are a DOL header whose sections end inside the file (DOL
  detection checks the whole section table against the file size, so a
  prefix alone never recognizes one). Files that pass are checked in full
  with `container::is_recognized` and listed with `Classify::IfRecognized`
  under their path (`/bin/payload.elf`). Their bytes are stored
  contiguously, so a member is a borrowed slice of the image.
- **Wii partitions.** Every partition is an opaque child: Dolphin decrypts
  partition data with AES and the title key from the partition's ticket,
  and this parser does not. Labels give the group, index and type name
  (`DATA`, `UPDATE`, `CHANNEL`, `INSTALL`, a four-character ID, or the
  number). Notes give each partition's data offset and size. Tickets, TMDs,
  certificate chains and H3 hash tables are not verified.
- **XDVDFS files.** The directory tree is walked from the root table;
  within a table, entries come in tree order (left subtree, entry, right
  subtree), which is name order for tables the tools write. Files are
  probed with their first 4 KiB, checked in full and listed by path
  (`/default.xbe`, `/media/game.xex`); `console.rs` classifies XBE (x86)
  and XEX (PowerPC) members.
- Notes count the files and the listed members and say what was left out:
  files outside a truncated image (with the first), the member and
  extraction limits, files over 64 MiB, and directories past the walk
  limits. Metadata: `<prefix>_files`, plus per layout `gamecube_*` (game
  ID, disc number, version, title, region, apploader date and entry, DOL
  offset and size, FST offset, size and maximum size), `wii_*` (header
  fields, region, partition count) and `xdvdfs_*` (partition offset, root
  sector and size, `FILETIME`).

## Wire units and byte order

| Layout | Byte order | Units |
| --- | --- | --- |
| GameCube | Big-endian | Byte offsets and sizes; FST file offsets are bytes (Dolphin offset shift 0); directory fields are entry indices |
| Wii | Big-endian | Partition table offsets, partition offsets and partition header offsets and sizes are stored divided by 4 (Dolphin `GetOffsetShift` 2) |
| XDVDFS | Little-endian | Start sectors count 2048-byte sectors from the game partition start; sizes are bytes; subtree links count 4-byte units from the start of their table |

Header byte order is never reported as code byte order. The only code byte
order the family states is the apploader's.

## Validation and resource bounds

- GameCube: the image must hold the disc header, `bi2.bin` and the
  apploader header (0x2460 B). The apploader entry may not be 0xFFFFFFFF
  and code plus trailer may not total 0xFFFFFFFF (Dolphin's checks); the
  apploader and the DOL must lie in the image and be at most 64 MiB; a DOL
  with every section empty is an error.
- FST, following Dolphin's `FileSystemGCWii`: size at least 12 B and at
  most 128 MiB; in the image; the root a directory with parent 0; entry
  count at least 1 and `12 * count` within the FST; a final NUL byte;
  every name offset inside the string table; every directory's parent
  index the enclosing directory and its next index after itself and within
  its parent. A size of 0 means no FST (noted). Directories deeper than
  1024 levels are reported as unsupported: the walk keeps every open
  directory on a stack, and Dolphin sets no limit.
- Wii: partition information (0x40020 B) and region data (0x4E004 B) must
  be in the image; every partition table must lie in the image (its count
  is validated against the bytes before the loop); no partition may start
  in the first 0x50000 B (the disc header area of Dolphin's
  `GetBiggestReferencedOffset`); every partition header (0x2C0 B) and data
  range must lie in the image; the data offset must be at least 0x2C0.
- XDVDFS: the descriptor must hold both magics; every directory table
  must lie in the image; each entry offset is visited once per table and
  each table sector once per image, so link cycles are errors; the tables
  walked may not total more bytes than the image; at most 1,048,576
  directory entries (`Unsupported XDVDFS image`); names must not be empty,
  `.`, `..`, or contain `/` or `\` (extract-xiso's rule plus non-empty).
- Members: at most 4096 listed per image; each probe is charged 4 KiB and
  each file checked in full its size against the 256 MiB extraction budget
  before the work happens; files over 64 MiB are not examined; directory
  walks stop at 64 levels or 4096-byte paths.
- Strong detection means a corrupt image is a parse error, not raw code.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| D1 | The Wii magic at 0x18 is checked before the GameCube magic at 0x1C, as in Dolphin's `TryCreateDisc` | An image with both magics reports `wiidisc`; a real GameCube disc has 0 at 0x18 (not verified on real dumps) |
| D2 | The apploader runs on the PowerPC in big-endian mode | `gamecube_classification_takes_each_child_from_its_own_bytes`; on real discs, disassembling the apploader at 0x81200000 as big-endian PowerPC should give a function prologue at the entry (not verified on real dumps) |
| D3 | No Wii partition starts in the first 0x50000 B | Parse the partition table of real dumps; Dolphin's verifier expects UPDATE at 0x50000 and DATA at 0xF800000 (not verified on real dumps) |
| D4 | The XDVDFS game partition starts at 0, 0x18300000, 0xFD90000 or 0x2080000, with the descriptor at sector 32 | `full_disc_images_find_the_game_partition_at_documented_offsets`; xenia also tries 0xFB20 and 0x20600, whose purpose is not documented, so those are not implemented |
| D5 | Real XDVDFS tables have no cycles, do not overlap, and hold fewer than 1,048,576 entries | `xdvdfs_link_cycles_are_parse_errors`; a real image that fails with one of these errors would falsify it (not verified on real dumps) |
| D6 | GameCube FST names may be Shift-JIS (Dolphin decodes them so, with a TODO saying it is unsure); non-ASCII bytes are shown as U+FFFD | Japanese discs list member paths with replacement characters |
| D7 | A DOL inside the FST is found by its header's section table fitting the file | `/bin/extra.dol` in the GameCube fixture is listed and classified as a DOL |
| D8 | An XDVDFS image may also be a valid ISO 9660 volume (extract-xiso writes ECMA-119 descriptors into an XISO's first sectors, and a full XGD image starts with its video partition), so the family is checked before ISO 9660 | `xiso_with_ecma119_descriptors_is_reported_as_xdvdfs` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Wii partition contents (encrypted with AES and the title key) | Not decrypted; partitions are opaque, so Wii DOLs and file systems are not reached, and Wii discs report an unknown ISA |
| Wii discs that disable encryption (byte 0x61 nonzero) | Noted; partition data is still not parsed |
| Compressed or container formats of disc images (GCZ, WIA, RVZ, WBFS, CISO, NKit) | Not recognized |
| Triforce discs (`boot.id`) | Parsed as GameCube discs; Triforce region and maker fields are not read |
| GameCube `bi2.bin` fields other than the country code; debug monitor fields | Not reported |
| Shift-JIS and Windows-1252 decoding | Windows-1252 is decoded for XDVDFS names; Shift-JIS is not decoded |
| The bytes before an XDVDFS game partition in a full disc image | Not parsed |
| `XBOX_DVD_LAYOUT_TOOL_SIG` in sector 33 | Not read (the wiki marks its layout FIXME) |
| Signatures and copy protection (Xbox security sectors, GameCube BCA) | Not present in these layouts or not read; nothing is authenticated |
| Real disc dumps | Not tested: no redistributable dump exists, and none is committed |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node v25.8.1 with Playwright Chromium), `cargo test
--all-features --locked` passed: 1,526 tests, 6 ignored (the repository's
existing ignores), including the 34 tests of `tests/discs.rs` and the 15
unit tests of `src/formats/discs*`. After integration with the partition
table, FAT and ISO 9660 families on the same day, it passed 1,676 tests
with the same 6 ignored, including 35 in `tests/discs.rs`, and IDA's test
corpus (4,621 files, none a console disc image) classified as before. `web/tests/discs.test.mjs` (4 tests)
passed through `/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and
`/dist/index.html` after `./build-web.sh`; the whole browser suite ran 176
tests, 172 passed and 4 skipped (the existing skips that need D10 and RX113
firmware not in the repository). The sweeps cover every prefix of
the GameCube and XISO fixtures, a strided set of Wii prefixes including
every structure boundary, and 0x00, 0xFF and bit-flip mutations of every
structure byte of all three. All fixtures are synthetic, built in the
tests from the documented layouts with an ELF header, PowerPC code and
minimal XBE and XEX headers as payloads; behavior on real disc dumps is
not verified.
