# Partition tables

`src/formats/partitions.rs` and its submodules (`mbr.rs`, `gpt.rs`,
`apm.rs`) parse PC master boot records with their extended boot record
(EBR) chains, GUID Partition Tables and Apple Partition Maps into the
shared container model ([compressed streams and the container
model](compressed-streams.md)). A partition table names no processor for
its partitions: the container result has an unknown ISA with confidence 0,
each partition is a child classified from its own bytes, and a partition is
listed only when those bytes are a recognized format (a filesystem, a boot
image, an archive). Partition type names, including the ones that name an
architecture (`Linux root (ARM-64)`), are never ISA evidence.

## Primary sources

| Source | Used for |
| --- | --- |
| UEFI Specification 2.10 (August 2022), chapter 5: section 5.2.1 and Tables 5.1-5.2 (legacy MBR), 5.2.2 (OS types `0xEF`, `0xEE`), 5.2.3 and Tables 5.3-5.4 (protective MBR), 5.3.1 (GPT layout), 5.3.2 and Table 5.5 (GPT header and validity tests), 5.3.3 and Tables 5.6-5.8 (entries, type GUIDs, attributes); read from `uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html` (Wayback snapshot `20260918003715`) | MBR and GPT layouts and rules |
| BIOS Boot Specification 1.01 (Compaq, Phoenix, Intel; 1996-01-11), section 6.5.1 | The boot sector runs at `0000:7C00h` with the INT 13h drive number in `DL`: real-mode x86 |
| Inside Macintosh: Devices (Apple, 1994), chapter 3 "SCSI Manager": "The Structure of Block Devices", "Driver Descriptor Record", "Partition Map Entry Record" (`developer.apple.com/library/archive/documentation/mac/Devices/Devices-121.html`, `-125.html`, `-126.html`) | APM layout, the map stride, the processor field |
| util-linux v2.40.2: `libblkid/src/partitions/dos.c` (`probe_dos_pt`, `parse_dos_extended`), `gpt.c`, `mac.c`; `libblkid/src/superblocks/vfat.c` (`fat_valid_superblock`), `exfat.c`, `ntfs.c`; `include/pt-mbr.h`, `pt-mbr-partnames.h`, `pt-gpt-partnames.h` | How an MBR is told from a FAT, exFAT or NTFS boot sector; type names |
| Linux v6.11: `block/partitions/msdos.c` (`msdos_partition`, `parse_extended`, `is_extended_partition`), `efi.c` (`is_gpt_valid`, `is_pmbr_valid`, `pmbr_part_valid`, `efi_crc32`), `mac.c`, `mac.h` | EBR walk, protective-MBR test, CRC-32 variant, APM stride |
| GRUB 2.12: `include/grub/gpt_partition.h` (`GRUB_GPT_PARTITION_TYPE_BIOS_BOOT`) and `docs/grub.texi` node "BIOS installation", heading "GPT" | The BIOS boot partition holds GRUB's embedded core image |

Field-by-field notes with offsets and sources were kept while researching;
anything not confirmed from these sources is listed under the assumption
register and known boundaries below.

## Implemented layouts

| JSON format ID | Layout | Recognition | Children | Architecture evidence |
| --- | --- | --- | --- | --- |
| `mbr` | LBA 0: 440 B bootstrap code, disk signature (440), four 16-byte records (446: boot indicator, CHS, OS type, CHS, start LBA, size), `55 AA` (510); EBR chains of extended partitions (`0x05`, `0x0F`, `0x85`) | Weak, last among the weak disk-image checks (see Detection) | Each used non-extended primary record, then each logical partition (numbered from 5), then `MBR bootstrap code` when the 440 B are not all zeros | Bootstrap code: x86, 16-bit, target set by the container (UEFI Table 5.1 "x86 code", BIOS Boot Specification 6.5.1). Partitions: their own bytes |
| `gpt` | Protective MBR at LBA 0, header at LBA 1 for 512- or 4096-byte blocks, entry array, backup array and header at the end | Strong: `EFI PART` at 0x200 or 0x1000; also reached from a protective MBR | Each used entry in table order, then `MBR bootstrap code` of the protective MBR when not all zeros | Bootstrap code as for `mbr`. GRUB BIOS boot partition (`21686148-6449-6E6F-744E-656564454649`): classified as code with no named ISA, so the code model decides. Other partitions: their own bytes |
| `applepartitionmap` | Driver descriptor record in block 0 (`ER`, `sbBlkSize`, `sbBlkCount`, drivers), one 512 B map entry per block of `sbBlkSize` from block 1 | Strong: `ER`, a power-of-two block size of at least 512 B, and a `PM` (or old `TS`) entry at block 1 whose map size the entries present agree on | Each entry's partition except `Apple_partition_map` (the map) and `Apple_Free`; an entry's boot code (`pmLgBootStart`, `pmBootSize`) as code | Boot code: `pmProcessor` `68000`, `68020`, `68030` or `68040` names a 680x0, so the target is M68k (32-bit, big-endian) with that variant; other strings leave the ISA to the code model |

Labels: MBR partitions are `Partition <n> (<type name>, type 0x<id>[, active])`,
GPT entries `Partition <n> "<name>" (<type name or GUID>)` and APM entries
`Partition <n> "<pmPartName>" (<pmParType>)`; APM boot code adds ` boot
code`. `format.variant_name` is `MBR`, `GPT` or `Apple Partition Map`.

Notes give the table summary (records or entries in use, block size, CRC
results), the bootstrap code, the protective or hybrid MBR, the backup GPT
header, extended partition chains, APM drivers and boot code, and every
partition that could not be listed. Metadata: `partitions_mbr_disk_signature`,
`partitions_mbr_partition_<n>` (type and sectors), `partitions_gpt_disk_guid`,
`partitions_gpt_block_size`, `partitions_gpt_entry_count`,
`partitions_gpt_entry_size`, `partitions_gpt_usable_lbas`,
`partitions_gpt_alternate_lba`, `partitions_gpt_entry_<n>` (type and unique
GUID, LBAs, attributes), `partitions_apm_block_size`,
`partitions_apm_block_count`, `partitions_apm_entry_<n>`, plus the generated
`partitions_image_size` and `partitions_component_<n>` entries.

## Detection

- **GPT** (strong, in the magic-bearing block before the compressed
  streams): `EFI PART` at LBA 1 for 512- or 4096-byte blocks, unless LBA 0
  holds a legacy MBR with partitions and no `0xEE` record. That GPT is stale
  (UEFI 5.3.2 describes legacy software reformatting a GPT disk), Linux
  (`is_pmbr_valid`) and libblkid (`is_pmbr_valid`) ignore it, and the MBR is
  reported with a note.
- **APM** (strong, same block): see the table above. A text file starting
  with `ER` fails the block size test.
- **MBR** (weak, right before the zlib and LZMA-alone weak checks, so last
  among the weak checks for disk images): `55 AA` at 510; every boot
  indicator `0x00` or `0x80` (libblkid, Linux); at least one record in use
  (`OSType` and `SizeInLBA` nonzero, UEFI 5.2.1); every used record starting
  at sector 1 or later and inside the input; no two used records
  overlapping (UEFI 5.2.1); and the sector is not a volume boot record: no
  `NTFS    ` or `EXFAT   ` OEM name at 3, and no FAT BIOS parameter block
  as libblkid's `fat_valid_superblock` accepts it (bytes per sector a power
  of two in 512-4096, sectors per cluster a power of two, reserved sectors
  and FAT count nonzero, media `0xF0` or `0xF8`-`0xFF`). FAT, exFAT and
  NTFS volumes therefore keep their boot sector. A record of type `0xEE`
  starting at LBA 1 makes the input a GPT (a protective MBR whose header the
  strong check did not find); any other `0xEE` record rejects the MBR, as
  libblkid and Linux do.

ISO 9660 images that are also bootable disks (isohybrid) carry an MBR, and
often a GPT, next to `CD001` at 0x8001; ISO detection should run before
these checks so such an image reports the ISO.

## Wire units and byte order

| Table | Byte order | Units |
| --- | --- | --- |
| MBR, EBR | Little-endian | Sectors of 512 B, assumed: the table does not record a sector size (libblkid and Linux scale by the device's sector size, which a file does not have). Primary records count from LBA 0; logical records from their EBR; links from the start of the primary extended partition |
| GPT | Little-endian; GUIDs as `EFI_GUID` (first three fields little-endian) | LBAs of the block size whose LBA 1 holds the header (512 or 4096 B); `EndingLBA` inclusive |
| APM | Big-endian | Blocks of `sbBlkSize` bytes for `pmPyPartStart`, `pmPartBlkCnt`, `pmLgBootStart`; `ddSize` in 512 B blocks; `pmBootSize` in bytes |

Child offsets and sizes are file bytes. The GPT header CRC is the IEEE
802.3 CRC-32 (`checksum::crc32`, the `efi_crc32` of Linux) over
`HeaderSize` bytes with the CRC field zeroed; the entry array CRC covers
`NumberOfPartitionEntries * SizeOfPartitionEntry` bytes.

## Validation and resource bounds

- MBR: the detection rules above are parse errors when `parse_container`
  is called directly. EBR walk (Linux `parse_extended`): data records are
  read from all four slots, records 3 and 4 only when they fit inside the
  extended partition; a logical record at offset 0 (its own EBR) or
  overlapping a listed partition is skipped with a note; the first extended
  record with a nonzero size and offset links to the next EBR. The walk
  stops at the last link, at an EBR beyond the file or without `55 AA`, at
  a repeated EBR, or after 256 EBRs per extended partition, each noted.
- GPT: signature; `HeaderSize` 92 B to the block size; header CRC-32;
  `MyLBA`; first usable LBA not after the last, the header outside the
  usable range (libblkid), the last usable LBA's byte offset within 64 bits;
  a nonzero entry count; entry size 128 B times a power of two (UEFI; Linux
  and libblkid accept only 128); the primary array after the header and
  before the first usable LBA, the backup array after the last usable LBA
  and before the backup header (UEFI 5.3.1); the array whole in the file and
  its CRC-32. Entries: type GUID zero means unused; first LBA not after the
  last and not before the first usable LBA; no overlaps (sorted, so the
  check is `O(n log n)`). An entry that ends after the last usable LBA is
  listed and noted.
- GPT recovery: when the primary header or array fails, the backup in the
  last block of the file is tried (UEFI 5.3.2) and used with a note naming
  the primary's failure. With a valid primary, the backup at `AlternateLBA`
  is verified when it is in the file and reported as verified, beyond the
  file, invalid, not matching, or with a differing entry array; it is never
  required, since disk dumps are often cut short.
- APM: the driver count at most 61 (the room in block 0); `pmMapBlkCnt`
  nonzero and its entries whole in the file; every entry `PM` with the same
  `pmMapBlkCnt` (Inside Macintosh); no partition at block 0 (the driver
  descriptor); no two partitions overlap. Boot code must lie inside its
  partition and the file, otherwise it is noted and not classified.
- Partitions that start beyond the end of the file are noted and not
  classified; partitions that end beyond it are classified from the bytes
  present and noted (truncated dumps). Children are borrowed slices of the
  input, nothing is copied or decoded, and non-overlapping partitions keep
  the bytes classified within the input size. At most 4096 children
  (`MAX_COMPONENTS`) are listed, the rest counted in a note.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| P1 | MBR sectors are 512 B | An MBR from a 4Kn disk (4096 B sectors) would show partitions at an eighth of their offsets; `hdiutil_mbr_image_has_one_hfs_partition_from_sector_1` pins the 512 B case |
| P2 | Non-zero MBR bootstrap code is x86 real-mode code (UEFI Table 5.1, BBS 6.5.1) | A disk written for a device that is not a PC with other code in the first 440 B: the target still says x86, and the code model's different verdict appears as a warning note (`apply_target`); no such disk was tested |
| P2a | The partitions describe a disk better than its boot code: partitioning tools write x86 boot code onto disks for any device | The bootstrap code is listed after the partitions, so a recognized partition supplies the primary ISA (`partitions_supply_the_primary_isa_before_the_bootstrap_code`); the boot code does only when no partition is recognized |
| P3 | A record of type `0xEE` from LBA 1 marks a GPT disk even when no header is found | `protective_mbr_without_a_header_is_a_gpt_parse_error`; `corrupt_primary_falls_back_to_a_valid_backup` (erased primary, protective MBR, valid backup) |
| P4 | A GPT header next to a legacy MBR without `0xEE` is stale | `stale_gpt_behind_a_legacy_mbr_is_not_read`; a real disk whose tools left a valid MBR and a current GPT would be misreported as MBR |
| P5 | The GPT CRC-32 is the IEEE 802.3 CRC (Linux `efi_crc32`; the UEFI text of `CalculateCrc32` was not consulted) | `hdiutil_gpt_image_verifies_both_headers_and_entry_arrays`: macOS-written headers and arrays verify |
| P6 | APM map entries are `sbBlkSize` apart (Inside Macintosh, Linux, libblkid) | `apm_with_2048_byte_blocks_reads_entries_at_that_stride`; a CD whose map uses 512 B entries under a 2048 B `sbBlkSize` would not be detected |
| P7 | APM logical blocks (`pmLgBootStart`, `pmLgDataStart`) are `sbBlkSize` blocks from the partition start (Inside Macintosh defines logical blocks as software-defined) | A driver partition whose boot code checksum does not match its bytes at that offset |
| P8 | The GRUB BIOS boot partition holds code (GRUB manual) but no named ISA | `gpt_partitions_hold_an_ext_filesystem_and_bios_boot_code`: the child has no target |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| MBR images inside archives | Archives check a member's first 4 KiB before the whole member, and the MBR rule requires partitions to start inside the bytes examined, so an MBR image whose partitions start after 4 KiB (the usual 1 MiB alignment) is not listed (`mbr_member_is_listed_only_when_a_partition_starts_in_the_recognition_prefix`). GPT and APM images are listed. Inside Android sparse images the expanded image is classified whole (up to 64 MiB) |
| MBR dumps cut before a partition's start | Not recognized as MBR (weak detection requires every partition to start inside the input); the bytes go to the other checks and the code model |
| 4Kn MBR disks | Read with 512 B sectors (P1) |
| Old APM maps (`TS` signature) | Recognized, then an `Unsupported` parse error: Inside Macintosh gives only the signature |
| APM boot code checksums (`pmBootCksum`), GPT attributes | Reported, not verified or interpreted beyond the three UEFI attribute bits |
| A/UX data areas (`pmLgDataStart` nonzero) | Noted; the whole partition is classified |
| Hybrid MBR records next to a GPT | Counted in a note, not listed: the GPT describes the disk |
| Nested tables in partitions (BSD disklabels, Solaris VTOC, Minix subpartitions that libblkid and Linux read) | Not parsed; such a partition is listed only if its bytes are a recognized format |
| GPT partition types that hold code other than the BIOS boot partition (PReP boot, ChromeOS kernel, vendor boot loader partitions) | Listed only when recognized; no type GUID sets a target |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly 2026-09-05,
Node 25.8.1 with Playwright Chromium), `cargo test --all-features --locked`
passed (1524 tests, 6 ignored, none of them partition tests), including
`tests/partitions.rs` (34 tests) and the 13 unit tests in
`src/formats/partitions.rs` and its submodules, and
`web/tests/partitions.test.mjs` (4 tests, after `./build-web.sh`) passed
with no skips. The whole browser suite (176 tests) passed with 4 skips, the
tests that need D10 and RX113 firmware that is not in the repository. The tests cover the
three hdiutil images (`tests/fixtures/partitions/README.md`), synthetic
MBR, EBR, GPT (512 and 4096 B blocks) and APM tables built from the
documented layouts, MBR, GPT and APM partitions holding the ext2 and ext4
fixtures, a GPT disk inside a tar archive and an MBR disk inside an Android
sparse image, every prefix of the small synthetic tables, and byte mutations
(0x00, 0xFF, bit flips; GPT mutations also with the CRCs recomputed).
Partition tables written by other tools (fdisk, sfdisk, gdisk, Windows,
Android vendor tools) and real Mac driver partitions were not tested: not
verified.
