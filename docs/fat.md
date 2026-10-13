# FAT and exFAT volumes

`src/formats/fat.rs` and its submodules (`bpb.rs`, `table.rs`, `walk.rs`,
`dir.rs`, `exfat.rs`) parse FAT12, FAT16, FAT32 and exFAT volumes into the
shared container model ([compressed streams and the container
model](compressed-streams.md)): the boot sector, the file allocation table,
a directory walk from the root that lists the regular files in a recognized
format as members, and the volume boot code. FAT names no processor for the
files it holds: members are classified from their own bytes. The boot
sector's jump field is an x86 jump into code the PC BIOS runs in real mode,
so that code, when present, is a child with an x86 16-bit target.

Primary sources:

- [FATGEN] Microsoft, "Microsoft Extensible Firmware Initiative FAT32 File
  System Specification. FAT: General Overview of On-Disk Format", version
  1.03, December 6, 2000 (`fatgen103.doc`, 222,720 B, SHA-256
  `b17d66c796d9cd3070adf4ccbc00add5a8b6b6f5491fe8ea949df778fce60172`,
  downloaded 2026-10-13 from `download.microsoft.com`). Sections are cited by
  heading.
- [EXFAT] Microsoft, ["exFAT file system
  specification"](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification),
  Basic Specification revision 1.00, seventh release (26-Aug-2019); page
  dated 2025-07-08. Sections are cited by number.

dosfstools 4.2, mtools 4.0.43 and exfatprogs 1.2.2 with the Linux exfat
driver built the fixtures ([fixture README](../tests/fixtures/fat/README.md));
no rule is taken from them.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- | --- |
| `fat` | `FAT12` | BPB with `BPB_FATSz16`, fixed root directory region, 12-bit FAT entries; fewer than 4,085 clusters | Weak: structure only (see Detection) | Volume boot code; regular files in a recognized format, by path | [FATGEN] "Boot Sector and BPB", "FAT Type Determination" |
| `fat` | `FAT16` | As FAT12 with 16-bit entries; 4,085 to 65,524 clusters | Weak | As FAT12 | [FATGEN] |
| `fat` | `FAT32` | FAT32 BPB (`BPB_FATSz32`, `BPB_RootClus`, `BPB_FSInfo`, `BPB_BkBootSec`), root directory as a cluster chain, 28-bit entries; 65,525 clusters or more | Weak | As FAT12 | [FATGEN] "FAT32 FSInfo Sector Structure and Backup Boot Sector" |
| `fat` (directories) | — | 32-byte short entries; long-name sets (`LDIR_Ord`, `LDIR_Chksum`); `0xE5` deleted and `0x00` end marks; `0x05` for a leading `0xE5` | — | Subdirectories walked; volume labels recorded | [FATGEN] "FAT Directory Structure", "FAT Long Directory Entries", "Validating The Contents of a Directory" |
| `exfat` | `exFAT` | Main and backup boot regions (12 sectors each), one or two FATs of 32-bit entries, cluster heap; File, Stream Extension and File Name entry sets; allocation bitmap, up-case table and volume label in the root | Strong: `"EXFAT   "` at offset 3 | Volume boot code; extended boot sectors holding code; regular files in a recognized format, by path | [EXFAT] 3-8 |

The JSON `format.variant_name` is the layout name. Notes give the geometry
(cluster count and size, sector size, FATs, root directory), truncation or
trailing data, the FAT copy comparison, reserved-entry and `FSInfo` facts,
what the checksums covered, the boot code found, and a walk census with every
problem below the root. Metadata records `fat_bytes_per_sector`,
`fat_cluster_size`, `fat_cluster_count`, `fat_reserved_sectors`,
`fat_fat_count`, `fat_fat_sectors`, `fat_total_sectors`,
`fat_root_entry_count` or `fat_root_cluster`, `fat_media_descriptor`,
`fat_hidden_sectors`, `fat_oem_name`, `fat_volume_serial`,
`fat_volume_label`, `fat_filesystem_type`, `fat_directory_label`,
`fat_fsinfo_free_count`, and for exFAT `exfat_bytes_per_sector`,
`exfat_cluster_size`, `exfat_cluster_count`, `exfat_volume_length`,
`exfat_fat_offset`, `exfat_fat_length`, `exfat_fat_count`,
`exfat_cluster_heap_offset`, `exfat_root_cluster`, `exfat_volume_serial`,
`exfat_partition_offset`, `exfat_percent_in_use` and `exfat_volume_label`;
both record the walk counts (`*_directory_count`, `*_regular_file_count`,
`*_member_count`, `*_deleted_entry_count`) and one `*_component_<n>` entry
per child.

## Detection

FAT12, FAT16 and FAT32 have no magic: the signature `55 AA` at byte 510 is
shared with master boot records, and `BS_FilSysType` is informational
([FATGEN] says so explicitly). `fat::detect_weak` therefore requires, in
this order:

1. at least 512 bytes, a jump field of one of the two allowed forms (`EB rel8
   90` or `E9 rel16`) and the signature `55 AA` at byte 510;
2. `BPB_BytsPerSec` 512, 1024, 2048 or 4096; `BPB_SecPerClus` a power of
   two; `BPB_RsvdSecCnt` not 0; `BPB_NumFATs` 1 or 2; `BPB_Media` 0xF0 or
   0xF8-0xFF; a non-zero total sector count and FAT size;
3. a data region with at least one cluster after the reserved sectors, FATs
   and root directory region;
4. the FAT type by cluster count ("the one and only way that FAT type is
   determined"): fewer than 4,085 clusters is FAT12, fewer than 65,525
   FAT16, otherwise FAT32, and the BPB layout must agree: a FAT32 BPB
   (`BPB_FATSz16` 0) exactly when the count makes the volume FAT32;
5. FAT32: `BPB_FSVer` 0.0 (drivers "must not mount" other versions),
   `BPB_RootClus` in the heap, an existing active FAT when mirroring is off,
   `BPB_RootEntCnt` and `BPB_TotSec16` 0; FAT12/FAT16: `BPB_RootEntCnt` not
   0;
6. a FAT large enough for `CountofClusters + 2` entries;
7. the reserved sectors, FATs and root directory region inside the input,
   and the volume no more than 1 MiB and no more than an eighth of its size
   beyond the input (see the assumption register);
8. FAT[0] holding a media descriptor in its low byte with every other bit
   of the entry set.

The check runs with the other weak checks, just before zlib and LZMA-alone,
and must stay before the MBR partition-table check: a FAT boot sector also
ends in `55 AA`, and its boot code (or the fake partition table `mkfs.fat
--mbr` writes) occupies the partition-table bytes. Detection reads only the
boot sector and FAT[0], so it costs the same for any input size.

exFAT is recognized by its file system name at offset 3 (`fat::detect`, before
the magic-bearing compressed streams), so a damaged exFAT volume is a `FAT
filesystem parse error`. `MustBeZero` covers the bytes of the FAT BPB, so an
exFAT volume never passes the FAT checks.

## Wire units and byte order

| Item | Byte order | Units |
| --- | --- | --- |
| BPB, FSInfo, directory entries, FAT entries | Little-endian | Sector counts of `BPB_BytsPerSec` bytes; clusters of `BPB_SecPerClus` sectors |
| FAT12 entries | Little-endian 16-bit words | Entry `n` is the low (even `n`) or high (odd `n`) 12 bits of the word at `n + n / 2` |
| FAT32 entries | Little-endian | Low 28 bits; the high 4 bits are reserved and ignored |
| Cluster `n` (FAT) | — | File offset `(FirstDataSector + (n - 2) * BPB_SecPerClus) * BPB_BytsPerSec` |
| exFAT boot sector, FAT, entries | Little-endian | Sectors of `1 << BytesPerSectorShift` bytes; clusters of `1 << SectorsPerClusterShift` sectors; cluster `n` at `ClusterHeapOffset + (n - 2) << SectorsPerClusterShift` sectors |
| Long names, exFAT names and labels | UTF-16LE | Characters; unpaired surrogates print as U+FFFD |
| Short names | OEM code page | Bytes outside printable ASCII print as `_`, as [FATGEN] returns untranslatable characters |

## Members

- The walk starts at the root (the FAT12/FAT16 root region, the FAT32
  `BPB_RootClus` chain, the exFAT `FirstClusterOfRootDirectory` chain) and
  descends depth first, subdirectories in entry order. `.` and `..` are
  skipped.
- FAT entries are classified as [FATGEN] "Validating The Contents of a
  Directory" prescribes: `(attr & 0x3F) == 0x0F` is a long entry, otherwise
  `attr & (DIRECTORY | VOLUME_ID)` gives a file, a directory, a volume label
  (root only) or an invalid entry. Short names with a leading space or an
  illegal byte are invalid entries.
- A long-name set must start with `LAST_LONG_ENTRY`, run its ordinals down
  to 1 with one checksum, carry `LDIR_Type` 0 and `LDIR_FstClusLO` 0, end
  right before its short entry, and match `ChkSum` of that short name;
  names stop at the first NUL. Sets that break any rule, and names with a
  control character or one of `" * / : < > ? \ |`, are counted and the short
  name is used.
- exFAT File entry sets must pass `SetChecksum`, hold a Stream Extension
  (`AllocationPossible` set) and `ceil(NameLength / 15)` File Name entries,
  `FirstCluster` 0 exactly when `DataLength` is 0, and `ValidDataLength` at
  most `DataLength`. Benign secondaries are ignored; an unrecognized
  critical secondary makes the set unrecognized. A critical primary entry
  other than File invalidates a subdirectory (none of its members is
  listed) and, in the root, any but the allocation bitmap, up-case table,
  volume label and File entries invalidates the volume ([EXFAT] 8.2).
- A regular file is read up to its first 4 KiB through its chain (or its
  contiguous clusters, exFAT `NoFatChain`); when that prefix is a recognized
  format (`container::is_recognized`) the whole file is read and listed with
  `if_recognized`. Files stored in one run are borrowed at their stored
  offset; others are owned with the transform `FAT cluster chain` or `exFAT
  cluster chain`, and exFAT files whose `ValidDataLength` is below their size
  read as zeros past it (`exFAT valid data length`).
- Deleted entries (FAT `0xE5` short entries, exFAT File entries with `InUse`
  0) are counted and ignored; nothing is undeleted.

## Boot code

The jump field's destination must lie between the end of the boot sector
fields (offset 62 for FAT12/FAT16 with `BS_BootSig` 0x29, else 36; 90 or 64
for FAT32; 120 for exFAT) and the signature. The bytes from there to offset
509 are a child `Volume boot code` with target x86, 16-bit, little-endian,
classified as code, unless the area holds one repeated byte (the zero fill
of most formatters, or the `F4` (`HLT`) fill [EXFAT] 3.1.19 prescribes) or
the code is an idle loop: `CLI`, `HLT` and `NOP` instructions followed by a
jump back into them or onto itself. A jump into the boot parameters (`EB FE
90`, a jump onto itself) or past the area means no boot code. Each case is
noted. exFAT extended boot sectors 1-8 that hold anything but one repeated
byte are further code children without a target, since [EXFAT] 3.2 lets
firmware of any processor run them.

The boot code child comes after the members, so the first recognized
member supplies the primary ISA, and the boot code (x86 16-bit, a
documented role: the jump field is defined as an x86 branch) does only when
no member is recognized. Formatters write an x86 boot stub onto volumes
meant for any device, so the stub says nothing about the code the volume
carries.

## Checksums

- FAT: long-name checksums are checked against their short names; FAT has
  no metadata checksums. The FAT copies are compared over the entries of the
  heap and the result is noted; FAT 1 is used unless FAT32 mirroring is off.
  The FAT32 `FSInfo` signatures are checked; its free count and next-free
  cluster are hints and reported as not verified. The FAT32 backup boot
  sector is compared with sector 0.
- exFAT: the main boot checksum (sectors 0-10, skipping `VolumeFlags` and
  `PercentInUse`) must match every word of sector 11, otherwise the volume
  is an error. The backup region's checksum is verified and the region
  compared with the main one; extended boot signatures are checked; every
  entry set read passes `SetChecksum`; the first up-case table's
  `TableChecksum` is verified. `NameHash` (it needs the up-case table) and
  the allocation bitmap are not verified.

## Validation and resource bounds

- Every read is bounds-checked; sizes and offsets are computed in `u64` with
  checked or saturating arithmetic before they are converted to `usize`.
- Cluster chains stop at an end mark, at a free, bad or reserved entry, at a
  cluster already in the chain (a loop), or at the clusters the file size
  needs; a chain longer than its file is counted. exFAT allows only
  `0xFFFFFFFF` as an end mark.
- Each cluster can be read as a directory once per walk: a directory loop or
  two directories sharing clusters stop at the first shared cluster, so
  directory chains cost at most one step per cluster and per entry.
  Directories are capped at 2 MiB (65,536 entries, [FATGEN]) for FAT and
  256 MiB ([EXFAT] 7.6.7) for exFAT.
- Members are limited to 64 MiB each (`MAX_PAYLOAD`) and 256 MiB in all
  (`MAX_EXTRACTED`, charged before a file is read so that late failures
  count); at most 4096 members are listed and 65,536 regular files
  examined; directories deeper than 64 levels are not walked; at most 16
  problems are listed and the rest counted.
- Damage below the root (bad chains, invalid entries) skips that entry with
  a note. An unreadable FAT32 root directory is a note; an unreadable exFAT
  root directory, or one without its allocation bitmaps and exactly one
  up-case table, is an error.

## Truncated volumes

A volume whose `BPB_TotSec16`/`BPB_TotSec32` ([FATGEN] "Boot Sector and
BPB") or `VolumeLength` ([EXFAT] 3.1.5) exceeds the input is read as a
truncated volume. Containers decode at most 64 MiB of a component
(`MAX_PAYLOAD`), so a larger volume in a disk image, virtual disk or
compressed stream reaches the parser cut.

- Detection is unchanged. FAT12, FAT16 and FAT32 have no magic, and weak
  detection still accepts at most 1 MiB and an eighth of the volume missing
  ([FATGEN] calls a volume larger than its media "seriously damaged or
  malformed"); a volume cut shorter is not recognized by `detect_format`.
  `parse_container` called with the layout parses it at any length. exFAT
  carries its name and is recognized and parsed at any length.
- FAT12/16/32 need the reserved sectors, the FATs and (FAT12/16) the root
  directory region, as before ("Truncated volume: the reserved sectors,
  FATs and root directory need ..."). exFAT needs its main boot region, its
  active FAT and the root directory clusters that hold the allocation
  bitmap and up-case table entries; without the FAT or those entries the
  error is `Truncated volume: S B declared, P B present`.
- Cluster numbers are still checked against the declared cluster count.
  Every cluster of the heap lies inside the volume, so a cluster past the
  end of the input is absent, never an error.
- Directory clusters past the end of the input are skipped (the
  directory's present clusters are still read) and counted: "N directory
  clusters lie past the X present; their entries were not read".
- A regular file is listed only when all of its clusters are present.
  Others are counted: "N regular files were not listed: file data lies
  partly or wholly past the X present". An exFAT up-case table past the end
  is noted as not verified.
- A note states "Volume truncated: X of Y present; files are listed only
  when all of their data is present" (this replaces the former "Truncated
  dump: ..." note of a slightly short volume).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| F1 | Every FAT volume worth recognizing has the `55 AA` signature, an allowed jump form and FAT[0] with its media byte; [FATGEN] requires all three | DOS 1.x and some Atari ST floppies lack the signature or jump: they are not recognized (left to later checks or raw) |
| F2 | Weak detection: a dump may miss at most 1 MiB and an eighth of its declared volume; the bound is ours, [FATGEN] calls any shortfall malformed | `truncated_dumps_and_trailing_data_are_noted`; a firmware image trimmed after its last used cluster is not recognized, and neither is the first 64 MiB of a larger FAT volume that a container decoded |
| F3 | Data after the declared volume is not part of it and is noted, not an error: [FATGEN] says a volume smaller than its media is "nothing whatsoever wrong" | A FAT volume followed by another partition's data is still FAT; a non-FAT image whose first sector happens to validate would also be accepted |
| F4 | A FAT32 BPB on fewer than 65,525 clusters (as `mkfs.fat -F 32` writes on small volumes) is not FAT: the cluster count makes it FAT16 by [FATGEN]'s only rule, and its FAT does not have that layout | `bpb_layouts_that_disagree_with_the_cluster_count_are_not_fat`; such volumes are left to later checks |
| F5 | `DIR_NTRes` is not looked at ([FATGEN]: "never modify or look at it"), so names the Windows NT case flags lower-case are listed upper-case | The mtools fixtures list `/PAYLOAD.ELF` for `payload.elf` |
| F6 | The jump destination is where the boot code starts, and an idle loop or a single repeated byte there is no code; the idle-loop pattern is ours | `boot_code_stubs_are_not_classified`; a boot sector whose code lies before its jump target is not extracted |
| F7 | The exFAT up-case table follows its FAT chain, as [EXFAT] 7.2.3 says (the allocation bitmap is not read) | The exfatprogs fixture chains its two up-case clusters; an image that stores the table contiguously without FAT entries gets the note "Up-case table checksum not verified" with the chain defect |
| F8 | A truncated volume is a prefix of the whole volume | `prefixes_are_truncated_volumes_that_never_claim_missing_bytes` checks every member of each sampled prefix of the FAT12, FAT16 and exFAT fixtures against the whole parse; not tested on a real cut partition |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Members of archives and filesystems | `container::is_recognized` sees only a member's first 4 KiB, which holds no complete FAT volume beyond a few KiB, so FAT images inside archives and other filesystems are not listed (exFAT images are, by their name) |
| Partitioned disk images | Not handled here: a volume must start at offset 0 (MBR and GPT are another family) |
| FAT volumes without `55 AA`, DOS 1.x FAT without a BPB, Atari ST variants | Not recognized |
| VFAT case flags in `DIR_NTRes`, OEM code pages | Not used; non-ASCII short-name bytes print as `_` |
| Boot code in sectors after sector 0 (the FAT32 boot record's further sectors, `BPB_BkBootSec` copies) | Not extracted |
| FSInfo free count, exFAT allocation bitmap, `NameHash` | Reported or skipped, not verified |
| TexFAT (two FATs and bitmaps), Windows CE security descriptors, vendor extensions | Benign entries are skipped; the active FAT follows `ActiveFat` |
| Deleted files | Counted, never recovered |
| FAT volumes with more than two FATs | Not recognized (`BPB_NumFATs` 1 or 2) |
| A FAT12/16/32 volume missing more than 1 MiB or an eighth (the first 64 MiB of a larger partition in a DMG, virtual disk or compressed stream) | Not recognized: weak detection is unchanged. Parsed as a truncated volume when `parse_container` is called with its layout. exFAT is read at any length |
| Truncated volumes | Files whose clusters are all present are listed, the rest counted; files in directory clusters past the end are not known, only those clusters are counted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/fat.rs` (28 tests) and the 19 unit tests in `src/formats/fat.rs` and
`src/formats/fat/` passed, within a full `cargo test --all-features
--locked` run of 1,524 passing tests with 6 ignored. The integration tests
use four tool-built fixtures (FAT12, FAT16 and FAT32 from mkfs.fat 4.2 and
mtools 4.0.43, exFAT from exfatprogs 1.2.2 and the Linux 7.0.14 exfat
driver; members compared byte for byte with the source tree rebuilt in the
test), synthetic volumes built in the test from the [FATGEN] layouts
(cluster-count boundaries 4,084 / 4,085 and 65,524 / 65,525, 1 KiB and
4 KiB sectors, BPB disagreements, long-name damage, loops and cross-links,
broken chains, 70 nested directories, boot-code stubs, truncated dumps, the
extraction limits), exFAT corruptions with recomputed boot and set
checksums, a parse of every prefix of the FAT12 fixture and of every
4,093rd prefix of the FAT16 and exFAT fixtures, and mutations (`0x00`,
`0xFF`, bit flip) of the boot sectors, FATs, directories and sampled bytes
of all four fixtures. `web/tests/fat.test.mjs` (4 tests) passed through
`/pkg/` and `/dist/` and in both workbench pages, within a full browser run
of 172 passing tests with 4 skipped (D10 and RX113 firmware not in the
repository).

Not verified: volumes from Windows, macOS or camera formatters (no such
images were used), sectors other than 512 B on tool-built volumes (1 KiB
and 4 KiB sectors are covered by synthetic volumes only), FAT32 volumes with
mirroring disabled other than in the synthetic test, TexFAT volumes, and how
any operating system mounts the volumes the reader rejects or accepts.

Truncated volumes, on 2026-10-13 (macOS 27.2 AArch64, rustc
1.100.0-nightly `f248f4038`): `tests/fat.rs` (29 tests) and the 19 unit
tests in `src/formats/fat.rs` and `src/formats/fat/` passed within `cargo
test --all-features --locked` (2,425 passed, 6 ignored). The sweep checks
that weak detection of every prefix of the FAT12 fixture still needs all
but an eighth of the volume, and parses the FAT12 and FAT16 fixtures with
their layout and the exFAT fixture at every prefix up to the end of their
metadata (exFAT: the root directory cluster) and every 4,093rd prefix and
the prefixes around each sector boundary after it: each lacks the metadata
and is an error, or is a truncated volume whose members are byte-identical
to the whole volume's and lie inside the prefix. Synthetic volumes cover a
file and a directory cluster past the end. `web/tests/fat.test.mjs`
(4 tests) passed through `/pkg/` and `/dist/`. A differential snapshot
against the previous commit over the four fixtures (1,449,169 inputs: the
whole volumes, every prefix of the FAT12 fixture and of the first 64 KiB of
the others, then sampled prefixes, and single-byte mutations) changed
1,049,364 outcomes, all of prefixes whose volume exceeds them: old
"Truncated volume" errors that are now truncated volumes, and the
slightly short dumps that weak detection accepts, whose note changed from
"Truncated dump: ..." to "Volume truncated: ...". Mutations did not change.
Not verified: a real FAT or exFAT volume cut by a container.
