# Xbox 360 STFS packages

`src/formats/stfs.rs` and its submodules (`blocks.rs`, `files.rs`) parse
Xbox 360 XContent packages whose volume is the Secure Transacted File
System (STFS) into the shared container model
([compressed streams and the container model](compressed-streams.md)):
console-signed `CON ` packages (saved games, profiles, caches) and
Microsoft-signed `LIVE` and `PIRS` packages (Marketplace content, title
and system updates). The files of the package are the container's
children, labeled by their paths. An XContent package names no CPU, so the
container target is always unknown; the ISA comes from the files, which
are classified by their own parsers (XEX executables by `console.rs`,
which reports 32-bit big-endian PowerPC).

## Implemented layouts

| JSON format ID | Container variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `xboxstfs` | `Xbox 360 CON package` | `CON ` at 0; console certificate and 128-byte signature (0x004-0x22C); licenses (0x22C); header SHA-1 (0x32C); header size (0x340); metadata (0x344-0x971A: content type, metadata version, content size, media ID, versions, title ID, platform, volume descriptor at 0x379, data files, volume type at 0x3A9, display names, publisher, title name, thumbnails); hash tables and data blocks from the header size rounded up to 4 KiB | Strong: the magic, a header size of 0x971A-0x10000000, the volume descriptor size byte 0x24 and volume type 0 (STFS) or 1 (SVOD) | One child per file that is a recognized format, labeled `/<directory>/.../<name>`; files reassembled from their data blocks | Free60 `STFS.md`; Velocity `XContentHeader.cpp`, `StfsDefinitions.cpp`, `StfsPackage.cpp`, `STFS Notes.txt`; xenia `stfs_xbox.h`, `stfs_container_device.cc` |
| `xboxstfs` | `Xbox 360 LIVE package` | The same with `LIVE` and a 256-byte package signature at 0x004 | Strong: as above | As above | As above |
| `xboxstfs` | `Xbox 360 PIRS package` | The same with `PIRS` | Strong: as above | As above | As above |

A header whose volume type is 1 (SVOD, used for Games on Demand and
original Xbox titles) is recognized with the same checks and reported with
its header notes and metadata, but its data lives in the separate files of
a `.data` directory (xenia `OpenFiles`), so it has no children.

Sources, fetched on 2026-10-13:

| Source | Pin | Files and SHA-256 | Used for |
| --- | --- | --- | --- |
| Free60 wiki "STFS" | Free60Project/wiki commit `32eb31bcb837406b08a45b9e7d3693027ab8d3d1` (2025-10-01) | `docs/System-Software/Formats/STFS.md` `e3cec599470a4c6866d17fb45872d1d134862208907b867b3c316223e52414f6` | Magics, signature areas, metadata offsets, content types, volume descriptor, file listing entries and flags, hash records and statuses, block size |
| Velocity | hetelek/Velocity commit `cf0b84cc8bbfad09c655476c6a3c762836ce1246` (2024-10-31) | `XboxInternals/Stfs/XContentHeader.cpp` `2fbfcf7de69507a363b910449ec833fb417dad2961834cd273fbd5a1aa1ee6c6`; `StfsDefinitions.cpp` `90e32a1c320601d230fbd6c74009475a5cfd3325dad37538191be39a38636f3c`; `StfsPackage.cpp` `f01bfd2a25449d46cb4c71ddf4d31d42bde7ad49eb4068ff5ced86055141bde0`; `StfsConstants.h` `e43cd90d6ecfde9f315c98e5df2518dd1f1e972e4a21cb3a428eba1697ef5fa5`; `STFS Notes.txt` `bcbd8034e31e10eb3c39ca73f4c656e1b3bbb837133d246938584b176bd50d1c` | Header reader and the header SHA-1 range; volume descriptor byte order; block and hash table addressing, active table copies, file table chain, consecutive and chained extraction, rehashing (what each SHA-1 covers); content types; the kernel's header size bounds |
| xenia | xenia-project/xenia commit `95a5c3ee250f80c3b9d139658649d9ffb6db3eec` (2026-02-18) | `src/xenia/vfs/devices/stfs_xbox.h` `e3bfc346cd9c39513e999406cebdb0214c52a82abbc2bb0f35f6337fcfe8ee25`; `stfs_container_device.cc` `58bb786ff43e5386dff05e64bb5dbe89643021cebee1d741b21006563cb4f156`; `stfs_container_device.h` `89306ff3b9da87c4f5344fdf686a072250a1dd2292a4841b84771e9c681292f0` | Structure layouts, the block separation flags (`read_only_format`, `root_active_index`), UTF-16BE display names, block addressing, hash table selection, end of chain, SVOD data files |

Where the sources disagree:

- Free60 calls the display names "UTF-8 string"; xenia (`be<uint16_t>`)
  and Velocity (`ReadWString`) read UTF-16BE with 128 characters per
  locale. UTF-16BE is used, and the first (English) locale is reported.
- Free60's C# block helpers shift block numbers only for `CON` packages
  and force two table copies for a 0xB000 header, and the page marks them
  "may not work perfectly". Velocity and xenia use the same formulas
  driven by the `read_only_format` flag alone; those are used.
- Velocity adds the top table's second-copy offset (`root_active_index`)
  in every package; xenia only in packages with two copies, where a second
  copy exists. xenia's rule is used.
- Content types: the names are Free60's, for the 30 values that Free60 and
  Velocity both list; 0x8000 and 0x90000, listed by only one, are reported
  as unknown.

## Children and classification

- **Files.** The file table is read in table order. Each file with a
  nonzero size is probed with its first data block (4 KiB); a file whose
  prefix is a recognized format is read in full and listed with
  `if_recognized`, so it is classified by its own parser. XEX2 files report
  PowerPC; the first file with a known ISA supplies the container's primary
  ISA. Files that are not a recognized format (saves, images, text) are
  counted, not listed. File names never decide how a file is classified.
- **Paths.** Each entry's directory index names its parent directory entry
  by position (0xFFFF for the root); a label is the chain of directory names
  from the root, `/media/maps/level.xex`.
- **Reassembly.** A file whose entry has the consecutive flag (bit 6 of the
  flags byte) occupies consecutive data blocks from its first block, as
  Velocity extracts it (Velocity writes next block 0 in the records of such
  runs). Any other file follows the next-block numbers of its level-0 hash
  records. A file stored contiguously in the package (no hash table between
  its blocks) is borrowed as it is; any other is reassembled with transform
  `STFS data blocks`, and its slice keeps the stored offset and size of its
  first contiguous run.
- **Hashes.** The header SHA-1 (content ID, 0x32C) is checked over
  0x344 up to the first hash table. The top hash table is checked against
  the volume descriptor's top hash. Every other hash table that is read is
  checked once against its parent record, and every data block that is read
  in full (the file table and the listed files) against its level-0 record.
  Mismatches are reported in notes with the first one named; they never
  remove a file. Blocks that are only probed are not checked. The RSA
  signatures (the `CON ` certificate and signature, the `LIVE`/`PIRS` package
  signature) are reported as present and not verified.
- **Metadata.** `<prefix>_image_size` and one `<prefix>_component_<n>`
  entry per child (from the container model), plus `stfs_content_type`,
  `stfs_metadata_version`, `stfs_title_id`, `stfs_media_id`,
  `stfs_content_size`, `stfs_header_size`, `stfs_content_id`,
  `stfs_display_name`, `stfs_title_name`, `stfs_publisher` (when not empty),
  `stfs_volume_type`; for STFS `stfs_block_separation`,
  `stfs_allocated_blocks`, `stfs_free_blocks`, `stfs_file_table_block`,
  `stfs_file_table_blocks`, `stfs_files`, `stfs_directories`; for SVOD
  `stfs_data_files`.

## Wire units and byte order

| Structure | Byte order | Units |
| --- | --- | --- |
| Header and metadata | Big-endian | Bytes; display names UTF-16BE |
| Volume descriptor | File table block count 16-bit little-endian and first file table block 24-bit little-endian; allocated and free block counts 32-bit big-endian | Data block numbers |
| Hash records (0x18 B) | Next block 24-bit big-endian at 0x15 | Data block numbers |
| File table entries (0x40 B) | Block counts and first block 24-bit little-endian; directory index, size and timestamps big-endian | Data block numbers; size in bytes |

Blocks are 4 KiB. Data block numbers exclude the hash tables. Backing
blocks count 4 KiB slots from the first hash table at the header size
rounded up to 4 KiB. With `copies` = 1 in the read-only format (block
separation bit 0) and 2 otherwise, data block `b` is at backing block
`b + copies * (b / 170 + 1)`, plus `copies * (b / 28900 + 1)` from block 170
on and `copies` more from block 28,900 on. Level-0 tables cover 170 data
blocks, level-1 tables 28,900, the level-2 table 4,913,000. In a two-copy
package the parent record's status bit 0x40 (or, for the top table, block
separation bit 1) selects the active copy. Header byte order is never
reported as code byte order; the members' own parsers report theirs.

## Validation and resource bounds

- Header: the magic, a header size of 0x971A-0x10000000 (the kernel bounds
  Velocity's notes record; 0x971A is xenia's header and metadata size), the
  whole header in the file, a volume descriptor size of 0x24 and a volume
  type of 0 or 1; anything else is a parse error.
- Volume: at most 4,913,000 allocated blocks; the top hash table must lie
  in the file when any block is allocated.
- File table: every block must be allocated, lie in the file and be reached
  once; the chain may not end before the declared block count. At most 1024
  blocks (65,536 entries; directory indices are 16 bits with 0xFFFF for the
  root) are read, and the rest is counted in a note. Within a block, the
  first entry whose name starts with NUL ends the block (xenia; Free60 ends
  the listing with an all-zero entry); entries with name length 0 are
  skipped (Velocity) and counted; a name length above 40 skips the entry.
- Paths: at most 64 directory levels; a directory index that names no
  directory entry, or a loop, skips the file with a note.
- Files: every block must be allocated and lie in the file (whole 4 KiB);
  a chain may not revisit a block or end before the blocks the size needs;
  consecutive runs may not pass the allocated blocks. Chains are followed
  only for files read in full, so a chain costs at most one step per block
  of a file of at most 64 MiB.
- Members: at most 4096 children per container (`MAX_COMPONENTS`); each
  probe is charged 4 KiB and each file read in full its size against the
  256 MiB extraction limit (`MAX_EXTRACTED`); files over 64 MiB
  (`MAX_PAYLOAD`) are not examined; all of these are counted in notes.
  The first 8 problems are named in notes and the rest counted.
- A package ends at its last allocated data block; bytes after it are
  noted and not parsed, and a file shorter than that is noted as truncated
  (its missing files are skipped with a note).
- Strong detection means a damaged package is a parse error, not raw code.
  Nesting is bounded by the six container levels of `lib.rs`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| S1 | Every package has a header size of at least 0x971A and at most 0x10000000 (Velocity's kernel notes; xenia reads 0x971A bytes) | A real package with a smaller header would not be recognized (not verified on real packages) |
| S2 | The volume descriptor size byte is always 0x24 and the volume type 0 or 1 (Free60, Velocity, xenia) | `detection_requires_the_header_structure`; a real package with another value would not be recognized |
| S3 | The block mapping and active-copy rules that Velocity and xenia share are the console's | `two_copy_packages_read_the_active_table_copies` and the geometry unit tests; a real two-copy package whose tables fail their SHA-1 checks would falsify it (not verified on real packages) |
| S4 | Files with the consecutive flag occupy consecutive blocks regardless of their records' next blocks (Velocity `ExtractFile`; xenia always follows the chain) | `live_package_lists_recognized_files_by_path` writes next block 0 for the consecutive file; a real package whose consecutive file is fragmented would read wrong bytes, which its block SHA-1 checks would show |
| S5 | Display names are UTF-16BE (xenia, Velocity), not UTF-8 (Free60) | A real package whose names decode as mojibake would falsify it (not verified on real packages) |
| S6 | Every block of a file is stored in full (4 KiB), so a block cut by truncation makes the file unreadable | `truncated_packages_fail_or_list_only_what_is_present`; a real package whose last block is short would lose its last file |
| S7 | An XContent package is no ISA evidence: the platform byte (2 Xbox 360, 4 PC) names no instruction set | Container results carry no target (`live_package_lists_recognized_files_by_path` checks `target` is `None`) |
| S8 | A header SHA-1 or block SHA-1 mismatch means the bytes changed after hashing, not that the package is something else | `sha1_mismatches_are_reported_and_members_still_listed` keeps the files and reports the mismatch |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| RSA signatures (console certificate and signature, Microsoft package signature) | Present, not verified (no keys) |
| SVOD volumes (`.data` directories, GDF/XSF layouts) | The header is recognized and reported; the data files are not parsed |
| PEC (profile-embedded content), which has no magic | Not recognized |
| Licenses, thumbnails, descriptions, timestamps, metadata version 2 fields (series, season, avatar data), title update installer data after 0x971A | Not reported |
| Hash table `num_blocks` fields and level-0 statuses | Not checked |
| Blocks that are only probed (files not in a recognized format) | Not SHA-1 checked |
| Level-2 packages (more than 28,900 blocks, about 113 MiB) | Implemented from the shared formulas; covered by unit tests of the block mapping only, not by a package fixture |
| Real packages | Not tested: none is redistributable, IDA's test inputs hold none, and no local tool creates them |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node v25.8.1 with Playwright Chromium), `cargo test
--all-features --locked` passed: 2,276 tests, 6 ignored (the repository's
existing ignores), including the 18 tests of `tests/stfs.rs` and the 16
unit tests of `src/formats/stfs*`. After `./build-web.sh`,
`web/tests/stfs.test.mjs` (4 tests) passed through `/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`; the whole
browser suite ran 264 tests, 260 passed and 4 skipped (the existing skips
that need D10 and RX113 firmware not in the repository).
The sweeps cover every 61st prefix of the LIVE fixture and every 4099th of
the CON fixture, plus the prefixes around each block boundary that matters,
and 0x00, 0xFF and bit-flip mutations of every header byte from 0x320 to
0x3B0, of the first file table entries, level-0 and level-1 records, and
of strided bytes of the LIVE, CON and SVOD fixtures. All fixtures are
synthetic, built in the tests from the documented layout with minimal XEX2
headers followed by PowerPC `nop`s as members; behavior on real CON, LIVE
and PIRS packages is not verified.

After integration on the same day, the native suite passed 2,385 tests
with 6 ignored, and IDA's corpus (4,621 files, none an STFS package)
classified as before.
