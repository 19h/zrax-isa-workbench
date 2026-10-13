//! Partition tables: the PC master boot record (MBR) with its extended boot
//! record (EBR) chains, the GUID Partition Table (GPT) and the Apple
//! Partition Map (APM). Each partition is a child classified from its own
//! bytes, so the filesystems and firmware images inside report themselves.
//!
//! Sources:
//! - UEFI Specification 2.10, chapter 5: Tables 5.1 and 5.2 (legacy MBR and
//!   its partition records), 5.3 and 5.4 (protective MBR), 5.5 (GPT
//!   header), 5.6 to 5.8 (partition entries, type GUIDs, attributes), and
//!   the validity tests of sections 5.2.1 and 5.3.2.
//! - BIOS Boot Specification 1.01, section 6.5.1: a PC BIOS loads the boot
//!   sector at `0000:7C00h` and starts it with the INT 13h drive number in
//!   `DL`, as real-mode x86 code.
//! - Inside Macintosh: Devices (1994), chapter 3: "The Structure of Block
//!   Devices", "Driver Descriptor Record" and "Partition Map Entry Record".
//! - util-linux v2.40.2: `libblkid/src/partitions/dos.c` (`probe_dos_pt`,
//!   which tells an MBR from a FAT, exFAT or NTFS boot sector),
//!   `superblocks/vfat.c` (`fat_valid_superblock`), `partitions/gpt.c`,
//!   `partitions/mac.c`, and `include/pt-mbr-partnames.h` and
//!   `include/pt-gpt-partnames.h` (type names).
//! - Linux v6.11: `block/partitions/msdos.c` (`parse_extended`, the EBR
//!   walk), `block/partitions/efi.c` (`is_gpt_valid`, `pmbr_part_valid`,
//!   `efi_crc32`) and `block/partitions/mac.c`.
//! - GRUB 2.12: `include/grub/gpt_partition.h` and the manual's "BIOS
//!   installation" node: the BIOS boot partition holds GRUB's core image.
//!
//! Units and byte order: MBR and GPT fields are little-endian, APM fields
//! big-endian. MBR sector numbers count 512-byte sectors (the table does not
//! record a sector size), GPT LBAs count the logical block size whose LBA 1
//! holds the header (512 or 4096 bytes), and APM block numbers count
//! `sbBlkSize` bytes. Child offsets and sizes are file bytes.
//!
//! None of these tables names the processor of a partition's contents, and
//! partition type names (some name an architecture, such as `Linux root
//! (ARM-64)`) are never ISA evidence: partitions are listed when their bytes
//! are a recognized format and are classified from those bytes. Three areas
//! hold code by definition: the MBR bootstrap code (x86, by UEFI Table 5.1
//! and the BIOS Boot Specification), the GPT BIOS boot partition (code with
//! no named ISA, so the code model decides) and APM boot code, whose
//! `pmProcessor` field names the 680x0 that runs it.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum;
use crate::formats::container::{Child, Container, Target, MAX_COMPONENTS};
use crate::types::{Endianness, FileFormat, Isa};
use std::fmt::Write;

mod apm;
mod gpt;
mod mbr;

/// Prefix of generated metadata keys.
const KEY_PREFIX: &str = "partitions";

/// Bytes of an MBR or EBR sector, and of the sectors MBR records count.
const SECTOR_SIZE: usize = 512;

/// MBR layout (UEFI 2.10 Table 5.1): bootstrap code, the disk signature,
/// two unused bytes, four partition records and the boot signature.
const BOOTSTRAP_SIZE: usize = 440;
const DISK_SIGNATURE: usize = 440;
const RECORDS_OFFSET: usize = 446;
const RECORD_SIZE: usize = 16;
const RECORD_COUNT: usize = 4;
const BOOT_SIGNATURE_OFFSET: usize = 510;

/// Boot signature `0xAA55`, stored as `55 AA`.
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xaa];

/// `BootIndicator` values: `0x80` marks the bootable legacy partition.
/// libblkid and Linux reject a table with any other value than these two.
const BOOT_ACTIVE: u8 = 0x80;
const BOOT_INACTIVE: u8 = 0x00;

/// OS type of the protective record of a GPT disk (UEFI 2.10, 5.2.2).
const OS_TYPE_GPT_PROTECTIVE: u8 = 0xee;

/// LBA of the primary GPT header, where a protective record starts.
const GPT_HEADER_LBA: u32 = 1;

/// Label of the bootstrap code child.
const BOOTSTRAP_LABEL: &str = "MBR bootstrap code";

/// Bootstrap code runs as 16-bit real-mode x86 code: UEFI Table 5.1 names
/// the field x86 code, and a PC BIOS starts it at `0000:7C00h` with INT 13h
/// services (BIOS Boot Specification 1.01, 6.5.1).
const BOOTSTRAP_TARGET: Target = Target::new(Isa::X86, 16, Endianness::Little);

/// OEM names at offset 3 of NTFS and exFAT boot sectors (the libblkid
/// `ntfs.c` and `exfat.c` magics).
const OEM_NAME_OFFSET: usize = 3;
const NTFS_OEM_NAME: &[u8; 8] = b"NTFS    ";
const EXFAT_OEM_NAME: &[u8; 8] = b"EXFAT   ";

/// FAT BIOS parameter block fields (libblkid `struct msdos_super_block`).
const BPB_BYTES_PER_SECTOR: usize = 0x0b;
const BPB_SECTORS_PER_CLUSTER: usize = 0x0d;
const BPB_RESERVED_SECTORS: usize = 0x0e;
const BPB_FAT_COUNT: usize = 0x10;
const BPB_MEDIA: usize = 0x15;

/// Sector sizes and media descriptors `fat_valid_superblock` accepts.
const BPB_MIN_SECTOR: u16 = 512;
const BPB_MAX_SECTOR: u16 = 4096;
const BPB_MEDIA_REMOVABLE: u8 = 0xf0;
const BPB_MEDIA_MIN_FIXED: u8 = 0xf8;

/// Partition labels shown in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// MBR OS type names (util-linux v2.40.2 `include/pt-mbr-partnames.h`).
/// Names only: they are never ISA evidence.
const MBR_TYPE_NAMES: &[(u8, &str)] = &[
    (0x01, "FAT12"),
    (0x02, "XENIX root"),
    (0x03, "XENIX usr"),
    (0x04, "FAT16 <32M"),
    (0x05, "Extended"),
    (0x06, "FAT16"),
    (0x07, "HPFS/NTFS/exFAT"),
    (0x08, "AIX"),
    (0x09, "AIX bootable"),
    (0x0a, "OS/2 Boot Manager"),
    (0x0b, "W95 FAT32"),
    (0x0c, "W95 FAT32 (LBA)"),
    (0x0e, "W95 FAT16 (LBA)"),
    (0x0f, "W95 Ext'd (LBA)"),
    (0x11, "Hidden FAT12"),
    (0x12, "Compaq diagnostics"),
    (0x14, "Hidden FAT16 <32M"),
    (0x16, "Hidden FAT16"),
    (0x17, "Hidden HPFS/NTFS"),
    (0x1b, "Hidden W95 FAT32"),
    (0x1c, "Hidden W95 FAT32 (LBA)"),
    (0x1e, "Hidden W95 FAT16 (LBA)"),
    (0x27, "Hidden NTFS WinRE"),
    (0x39, "Plan 9"),
    (0x41, "PPC PReP Boot"),
    (0x42, "SFS"),
    (0x4d, "QNX4.x"),
    (0x4e, "QNX4.x 2nd part"),
    (0x4f, "QNX4.x 3rd part"),
    (0x63, "GNU HURD or SysV"),
    (0x80, "Old Minix"),
    (0x81, "Minix / old Linux"),
    (0x82, "Linux swap / Solaris"),
    (0x83, "Linux"),
    (0x84, "OS/2 hidden or Intel hibernation"),
    (0x85, "Linux extended"),
    (0x86, "NTFS volume set"),
    (0x87, "NTFS volume set"),
    (0x88, "Linux plaintext"),
    (0x8e, "Linux LVM"),
    (0x9f, "BSD/OS"),
    (0xa0, "IBM Thinkpad hibernation"),
    (0xa5, "FreeBSD"),
    (0xa6, "OpenBSD"),
    (0xa7, "NeXTSTEP"),
    (0xa8, "Darwin UFS"),
    (0xa9, "NetBSD"),
    (0xab, "Darwin boot"),
    (0xaf, "HFS / HFS+"),
    (0xb7, "BSDI fs"),
    (0xb8, "BSDI swap"),
    (0xbe, "Solaris boot"),
    (0xbf, "Solaris"),
    (0xda, "Non-FS data"),
    (0xde, "Dell Utility"),
    (0xea, "Linux extended boot"),
    (0xeb, "BeOS fs"),
    (0xee, "GPT"),
    (0xef, "EFI (FAT-12/16/32)"),
    (0xf0, "Linux/PA-RISC boot"),
    (0xf8, "EBBR protective"),
    (0xfb, "VMware VMFS"),
    (0xfc, "VMware VMKCORE"),
    (0xfd, "Linux raid autodetect"),
];

/// A partition table layout recognized by [`detect`] or [`detect_weak`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// PC master boot record: four primary partition records and the EBR
    /// chains of extended partitions.
    Mbr,
    /// GUID Partition Table, found by its header at LBA 1 or through a
    /// protective MBR.
    Gpt,
    /// Apple Partition Map: a driver descriptor record in block 0 and one
    /// partition map entry per block from block 1.
    ApplePartitionMap,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Mbr => FileFormat::Mbr,
            Self::Gpt => FileFormat::Gpt,
            Self::ApplePartitionMap => FileFormat::ApplePartitionMap,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Mbr => "MBR",
            Self::Gpt => "GPT",
            Self::ApplePartitionMap => "Apple Partition Map",
        }
    }

    /// The MBR has a two-byte signature that boot sectors share, so it is
    /// recognized from its structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Mbr)
    }
}

/// Strong recognition. GPT: the header signature `EFI PART` at LBA 1 for
/// 512- or 4096-byte blocks, unless LBA 0 holds a legacy MBR with
/// partitions and no protective record: such a GPT is stale (UEFI 2.10,
/// 5.3.2), Linux and libblkid ignore it, and [`detect_weak`] reports the
/// MBR. APM: the driver descriptor signature `ER` with a power-of-two block
/// size and a partition map entry at block 1 whose map size the entries
/// present agree on. A damaged table is then a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if gpt::has_header_signature(data) && !mbr::has_legacy_partitions(data) {
        return Some(Layout::Gpt);
    }
    if apm::is_present(data) {
        return Some(Layout::ApplePartitionMap);
    }
    None
}

/// Weak recognition of an MBR, which has only the two-byte boot signature:
/// every boot indicator `0x00` or `0x80`, at least one record in use, every
/// used record starting after the MBR and inside the input, no two used
/// records overlapping, and a sector that is not a FAT, exFAT or NTFS boot
/// sector (libblkid `probe_dos_pt`). A valid protective MBR whose GPT
/// header [`detect`] did not find is reported as GPT.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    mbr::detect(data)
}

/// Parse `data` as the given partition table layout.
///
/// # Errors
///
/// [`ClassifierError::PartitionParseError`] for a missing or invalid
/// table: a bad signature or checksum, an inconsistent record or entry, or
/// overlapping partitions. Partitions beyond the end of the file are noted
/// instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Mbr => mbr::parse(data),
        Layout::Gpt => gpt::parse(data),
        Layout::ApplePartitionMap => apm::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::PartitionParseError {
        message: message.into(),
    }
}

/// The message of a parse error, for notes about a table that is checked
/// but not required (a GPT backup header).
fn error_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::PartitionParseError { message } => message,
        other => other.to_string(),
    }
}

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "table field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, at)?))
}

fn le_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, at)?))
}

fn be_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `n` and the noun in the number it takes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// The first [`NOTE_NAMES`] labels, then a count of the rest.
fn name_list(labels: &[String]) -> String {
    let shown = labels.len().min(NOTE_NAMES);
    let mut text = labels[..shown].join(", ");
    if labels.len() > shown {
        let _ = write!(text, " and {} more", labels.len() - shown);
    }
    text
}

/// One MBR or EBR partition record (UEFI 2.10 Table 5.2): boot indicator
/// (1), starting CHS (3), OS type (1), ending CHS (3), starting LBA (4) and
/// size in LBAs (4). The CHS fields are not read: UEFI does not use them,
/// and LBA-era tables hold placeholders there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Record {
    /// `BootIndicator`.
    boot_indicator: u8,
    /// `OSType`.
    os_type: u8,
    /// `StartingLBA`, in sectors from the table's base (LBA 0 for the MBR).
    start: u32,
    /// `SizeInLBA`, in sectors.
    size: u32,
}

impl Record {
    /// UEFI 2.10, 5.2.1: "A Partition Record that contains an `OSType`
    /// value of zero or a `SizeInLBA` value of zero may be ignored."
    fn is_used(self) -> bool {
        self.os_type != 0 && self.size != 0
    }

    fn has_valid_boot_indicator(self) -> bool {
        matches!(self.boot_indicator, BOOT_ACTIVE | BOOT_INACTIVE)
    }

    /// The protective record of a GPT disk as Linux `pmbr_part_valid`
    /// accepts it: type `0xEE` starting at LBA 1 (UEFI Table 5.4).
    fn is_protective(self) -> bool {
        self.os_type == OS_TYPE_GPT_PROTECTIVE && self.start == GPT_HEADER_LBA
    }
}

/// The four partition records of `sector`, or `None` when it is shorter
/// than a sector or lacks the boot signature.
fn boot_records(sector: &[u8]) -> Option<[Record; RECORD_COUNT]> {
    if sector.get(BOOT_SIGNATURE_OFFSET..SECTOR_SIZE)? != BOOT_SIGNATURE {
        return None;
    }
    let mut records = [Record::default(); RECORD_COUNT];
    for (i, record) in records.iter_mut().enumerate() {
        let at = RECORDS_OFFSET + i * RECORD_SIZE;
        let bytes = sector.get(at..at + RECORD_SIZE)?;
        *record = Record {
            boot_indicator: bytes[0],
            os_type: bytes[4],
            start: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            size: u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
        };
    }
    Some(records)
}

/// The name of an MBR OS type, if it has one.
fn mbr_type_name(os_type: u8) -> Option<&'static str> {
    MBR_TYPE_NAMES
        .iter()
        .find(|&&(id, _)| id == os_type)
        .map(|&(_, name)| name)
}

/// Whether `sector` is a volume boot record rather than an MBR: an NTFS or
/// exFAT OEM name, or a FAT BIOS parameter block that libblkid's
/// `fat_valid_superblock` accepts (its cluster-count bound aside). libblkid
/// rejects an MBR for the same sectors, so a FAT, exFAT or NTFS volume keeps
/// its boot sector.
fn is_volume_boot_record(sector: &[u8]) -> bool {
    let oem_name = sector.get(OEM_NAME_OFFSET..OEM_NAME_OFFSET + 8);
    if oem_name == Some(NTFS_OEM_NAME) || oem_name == Some(EXFAT_OEM_NAME) {
        return true;
    }
    let Some(bpb) = sector.get(..=BPB_MEDIA) else {
        return false;
    };
    let bytes_per_sector =
        u16::from_le_bytes([bpb[BPB_BYTES_PER_SECTOR], bpb[BPB_BYTES_PER_SECTOR + 1]]);
    let reserved = u16::from_le_bytes([bpb[BPB_RESERVED_SECTORS], bpb[BPB_RESERVED_SECTORS + 1]]);
    let media = bpb[BPB_MEDIA];
    bytes_per_sector.is_power_of_two()
        && (BPB_MIN_SECTOR..=BPB_MAX_SECTOR).contains(&bytes_per_sector)
        && bpb[BPB_SECTORS_PER_CLUSTER].is_power_of_two()
        && reserved != 0
        && bpb[BPB_FAT_COUNT] != 0
        && (media == BPB_MEDIA_REMOVABLE || media >= BPB_MEDIA_MIN_FIXED)
}

/// List the bootstrap code area of an MBR or protective MBR as x86
/// real-mode code, unless it is all zeros.
fn push_bootstrap<'a>(c: &mut Container<'a>, sector: &'a [u8]) {
    let Some(code) = sector.get(..BOOTSTRAP_SIZE) else {
        return;
    };
    if code.iter().all(|&b| b == 0) {
        c.notes.push(
            "Bootstrap code area (440 B) is all zeros: no BIOS boot code, as on UEFI-only disks \
             and devices that are not PCs"
                .to_string(),
        );
        return;
    }
    c.notes.push(
        "Bootstrap code: 440 B at 0x0, classified as 16-bit x86 real-mode code because a PC \
         BIOS runs it; devices that are not PCs may leave other bytes there"
            .to_string(),
    );
    c.children.push(
        Child::stored(BOOTSTRAP_LABEL, 0, code)
            .as_code()
            .with_target(BOOTSTRAP_TARGET),
    );
}

/// How a partition's child is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    /// Filesystems and firmware images: listed when their bytes are a
    /// recognized format.
    Member,
    /// Code by definition with no named ISA (the GPT BIOS boot partition):
    /// always classified, by the code model if needed.
    Code,
}

/// Lists partitions as children, clipped to the file, and records the ones
/// it could not list.
#[derive(Debug, Default)]
struct Placement {
    /// Partitions that start beyond the end of the file.
    beyond: Vec<String>,
    /// Partitions that end beyond the end of the file; their present bytes
    /// are listed.
    truncated: Vec<String>,
    /// Partitions not listed because [`MAX_COMPONENTS`] children were.
    unlisted: usize,
}

impl Placement {
    /// List the partition `label` at file offset `offset` with `size`
    /// bytes. Offsets and sizes that overflow are beyond the file.
    fn place<'a>(
        &mut self,
        c: &mut Container<'a>,
        data: &'a [u8],
        label: String,
        offset: u64,
        size: u64,
        content: Content,
    ) {
        let Some(start) = usize::try_from(offset)
            .ok()
            .filter(|&start| start < data.len())
        else {
            self.beyond.push(label);
            return;
        };
        if c.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
            return;
        }
        let end = offset.saturating_add(size);
        let present_end = usize::try_from(end).map_or(data.len(), |end| end.min(data.len()));
        if (present_end as u64) < end {
            self.truncated.push(label.clone());
        }
        let child = Child::stored(label, start, &data[start..present_end]);
        c.children.push(match content {
            Content::Member => child.if_recognized(),
            Content::Code => child,
        });
    }

    /// Notes for the partitions that were clipped or left out.
    fn push_notes(&self, c: &mut Container<'_>) {
        if !self.truncated.is_empty() {
            c.notes.push(format!(
                "Partitions that end beyond the end of the file are classified from the bytes \
                 present: {}",
                name_list(&self.truncated)
            ));
        }
        if !self.beyond.is_empty() {
            c.notes.push(format!(
                "Partitions that start beyond the end of the file are not classified: {}",
                name_list(&self.beyond)
            ));
        }
        if self.unlisted > 0 {
            c.notes.push(format!(
                "{} not listed (limit {MAX_COMPONENTS})",
                count(
                    self.unlisted,
                    "further partition was",
                    "further partitions were"
                )
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sector with the boot signature and one record.
    fn sector_with_record(record: [u8; RECORD_SIZE]) -> Vec<u8> {
        let mut sector = vec![0u8; SECTOR_SIZE];
        sector[RECORDS_OFFSET..RECORDS_OFFSET + RECORD_SIZE].copy_from_slice(&record);
        sector[BOOT_SIGNATURE_OFFSET..].copy_from_slice(&BOOT_SIGNATURE);
        sector
    }

    #[test]
    fn records_are_read_from_little_endian_fields() {
        let sector = sector_with_record([
            0x80, 0xfe, 0xff, 0xff, 0x83, 0xfe, 0xff, 0xff, 0x00, 0x08, 0, 0, 0x00, 0x10, 0, 0,
        ]);
        let records = boot_records(&sector).expect("signature present");
        assert_eq!(
            records[0],
            Record {
                boot_indicator: BOOT_ACTIVE,
                os_type: 0x83,
                start: 2048,
                size: 4096,
            }
        );
        assert!(records[0].is_used());
        assert!(!records[1].is_used());
        assert_eq!(boot_records(&sector[..SECTOR_SIZE - 1]), None);
    }

    #[test]
    fn a_record_with_a_type_but_no_size_is_unused() {
        let record = Record {
            boot_indicator: 0,
            os_type: 0x83,
            start: 1,
            size: 0,
        };
        assert!(!record.is_used());
    }

    #[test]
    fn fat_ntfs_and_exfat_boot_sectors_are_volume_boot_records() {
        let mut fat = vec![0u8; SECTOR_SIZE];
        fat[BPB_BYTES_PER_SECTOR..BPB_BYTES_PER_SECTOR + 2].copy_from_slice(&512u16.to_le_bytes());
        fat[BPB_SECTORS_PER_CLUSTER] = 4;
        fat[BPB_RESERVED_SECTORS] = 1;
        fat[BPB_FAT_COUNT] = 2;
        fat[BPB_MEDIA] = 0xf8;
        assert!(is_volume_boot_record(&fat));
        fat[BPB_MEDIA] = 0xf1;
        assert!(
            !is_volume_boot_record(&fat),
            "media 0xF1 is not a FAT medium"
        );

        let mut ntfs = vec![0u8; SECTOR_SIZE];
        ntfs[OEM_NAME_OFFSET..OEM_NAME_OFFSET + 8].copy_from_slice(NTFS_OEM_NAME);
        assert!(is_volume_boot_record(&ntfs));
        let mut exfat = vec![0u8; SECTOR_SIZE];
        exfat[OEM_NAME_OFFSET..OEM_NAME_OFFSET + 8].copy_from_slice(EXFAT_OEM_NAME);
        assert!(is_volume_boot_record(&exfat));
        assert!(!is_volume_boot_record(&[0u8; SECTOR_SIZE]));
    }

    #[test]
    fn placement_clips_partitions_to_the_file() {
        let data = [7u8; 1024];
        let mut c = Container::new(FileFormat::Mbr, "test", KEY_PREFIX);
        let mut placement = Placement::default();
        placement.place(&mut c, &data, "inside".into(), 0, 512, Content::Member);
        placement.place(&mut c, &data, "clipped".into(), 512, 4096, Content::Code);
        placement.place(&mut c, &data, "beyond".into(), 1024, 512, Content::Member);
        placement.place(
            &mut c,
            &data,
            "overflow".into(),
            u64::MAX,
            1,
            Content::Member,
        );
        assert_eq!(c.children.len(), 2);
        assert_eq!(c.children[1].stored_size, 512);
        assert_eq!(placement.truncated, ["clipped"]);
        assert_eq!(placement.beyond, ["beyond", "overflow"]);
    }

    #[test]
    fn long_name_lists_are_counted() {
        let labels: Vec<String> = (1..=10).map(|i| format!("P{i}")).collect();
        assert_eq!(
            name_list(&labels),
            "P1, P2, P3, P4, P5, P6, P7, P8 and 2 more"
        );
        assert_eq!(count(1, "entry", "entries"), "1 entry");
        assert_eq!(count(0, "entry", "entries"), "0 entries");
    }
}
