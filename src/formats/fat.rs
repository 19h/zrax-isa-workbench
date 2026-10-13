//! FAT12, FAT16, FAT32 and exFAT volumes: the boot sector and its BIOS
//! parameter block, the file allocation tables, the directory tree with
//! long file names (FAT) and directory entry sets (exFAT), regular files in
//! a recognized format as members, and the volume boot code.
//!
//! Sources:
//! - [FATGEN] Microsoft, "Microsoft Extensible Firmware Initiative FAT32
//!   File System Specification. FAT: General Overview of On-Disk Format",
//!   version 1.03, December 6, 2000 (`fatgen103.doc`, SHA-256
//!   `b17d66c796d9cd3070adf4ccbc00add5a8b6b6f5491fe8ea949df778fce60172`):
//!   sections "Boot Sector and BPB", "FAT Data Structure", "FAT Type
//!   Determination", "FAT32 `FSInfo` Sector Structure and Backup Boot
//!   Sector", "FAT Directory Structure", "FAT Long Directory Entries",
//!   "Validating The Contents of a Directory" and "Other Notes Relating to
//!   FAT Directories".
//! - [EXFAT] Microsoft, "exFAT file system specification", Basic
//!   Specification revision 1.00, seventh release (26-Aug-2019),
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>:
//!   sections 2 (volume structure), 3 (boot regions and checksum), 4 (FAT),
//!   5 (cluster heap), 6 (directory entry templates), 7 (directory entry
//!   definitions) and 8.2 (unrecognized entries).
//!
//! All fields are little-endian. Sector and cluster numbers are converted
//! to file offsets; offsets in notes and metadata are file bytes. FAT names
//! no processor for the files it holds, so members are classified from
//! their own bytes. The boot sector's jump field is an x86 jump into boot
//! code that the PC BIOS runs in real mode; that code is a child with an
//! x86 16-bit target.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod bpb;
mod dir;
mod exfat;
mod table;
mod walk;

/// Boot sector signature at byte 510 of sector 0, whatever the sector size
/// ([FATGEN] "Boot Sector and BPB"; [EXFAT] 3.1.20).
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xaa];
const BOOT_SIGNATURE_OFFSET: usize = 510;

/// The smallest sector, which holds the boot sector fields.
const MIN_SECTOR_SIZE: usize = 512;

/// Size of a directory entry ([FATGEN] "FAT Directory Structure";
/// [EXFAT] 6, Table 13).
const DIRECTORY_ENTRY_SIZE: usize = 32;

/// The two jump forms `BS_jmpBoot` may take: `EB rel8 90` (short jump and
/// `NOP`) and `E9 rel16` (near jump).
const JMP_SHORT: u8 = 0xeb;
const JMP_NEAR: u8 = 0xe9;
const NOP: u8 = 0x90;

/// x86 instructions an idle loop is built from: `CLI`, `HLT` and `NOP`
/// before a jump back to them. The name of the pattern is ours, not from
/// either specification.
const CLI: u8 = 0xfa;
const HLT: u8 = 0xf4;

/// The PC BIOS runs the boot sector's code in x86 real mode
/// ([FATGEN] `BS_jmpBoot`: "a three-byte Intel x86 unconditional branch").
const BOOT_CODE_TARGET: Target = Target::new(Isa::X86, 16, Endianness::Little);

/// A dump may end before the volume its boot sector declares (a missing
/// last track, an image rounded down to whole MiB). [FATGEN] calls such a
/// volume malformed; weak detection of FAT12, FAT16 and FAT32 accepts at
/// most 1 MiB and at most an eighth of the volume missing. The bounds are
/// ours. A volume cut shorter (the first 64 MiB of a larger partition that
/// a container decoded) is still parsed by [`parse_container`] as a
/// truncated volume, and exFAT, which carries its name, is recognized at
/// any length.
const MAX_MISSING_SIZE: u64 = 1 << 20;
const MAX_MISSING_DIVISOR: u64 = 8;

/// A FAT layout. FAT12, FAT16 and FAT32 are told apart by the count of
/// clusters alone ([FATGEN] "FAT Type Determination"), exFAT by its file
/// system name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Fewer than 4,085 clusters: 12-bit FAT entries.
    Fat12,
    /// 4,085 to 65,524 clusters: 16-bit FAT entries.
    Fat16,
    /// 65,525 clusters or more: 28-bit FAT entries in 32-bit fields.
    Fat32,
    /// exFAT (`"EXFAT   "` at offset 3).
    ExFat,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Fat12 | Self::Fat16 | Self::Fat32 => FileFormat::Fat,
            Self::ExFat => FileFormat::ExFat,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
        }
    }

    /// FAT12, FAT16 and FAT32 have no magic (the boot signature `55 AA`
    /// is shared with master boot records) and are recognized from a
    /// consistent BPB; exFAT carries its file system name.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Fat12 | Self::Fat16 | Self::Fat32 => true,
            Self::ExFat => false,
        }
    }
}

/// Strong recognition: the exFAT file system name `"EXFAT   "` at offset
/// 3 ([EXFAT] 3.1.2). The rest of the boot region is checked by
/// [`parse_container`], so a damaged exFAT volume is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    exfat::detect(data).then_some(Layout::ExFat)
}

/// Weak recognition of FAT12, FAT16 and FAT32: an x86 jump and the boot
/// signature, a BPB whose sector size, cluster size, reserved sectors, FAT
/// count, media descriptor, total sectors and FAT size are consistent, a
/// FAT type by cluster count that agrees with the BPB layout, the metadata
/// region in the input, a first FAT entry that holds a media descriptor,
/// and a volume no more than slightly larger than the input.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    bpb::Geometry::parse(data)
        .ok()
        .filter(|g| g.coverage.is_tolerated(g.volume_size()))
        .map(|g| g.layout())
}

/// Parse a FAT or exFAT volume into the shared container model: the
/// volume boot code (when present) and the regular files that start with a
/// recognized format, labeled by their path.
///
/// # Errors
///
/// [`ClassifierError::FatParseError`] for a boot sector or BPB that does
/// not validate, a FAT type other than `layout`, and for exFAT a boot
/// checksum mismatch, an unsupported revision or an unreadable root
/// directory, and for a volume larger than the input whose FATs (or exFAT
/// root directory entries) lie past the end of the input. Damage below the
/// root is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Fat12 | Layout::Fat16 | Layout::Fat32 => dir::parse(data, layout),
        Layout::ExFat => exfat::parse(data),
    }
}

/// A result below the root of a volume: the error is a defect that skips
/// the entry and becomes a note.
type Walk<T> = std::result::Result<T, String>;

/// Why stored bytes below the root could not be read.
#[derive(Debug)]
enum Fault {
    /// A defect that skips the entry and becomes a note.
    Defect(String),
    /// The clusters lie inside the volume but past the end of the input,
    /// which holds only the start of a truncated volume.
    Absent,
}

impl From<String> for Fault {
    fn from(defect: String) -> Self {
        Self::Defect(defect)
    }
}

/// The result of a read of stored bytes below the root of a volume.
type ReadResult<T> = std::result::Result<T, Fault>;

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::FatParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid file range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated volume at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

/// `value` divided by `divisor`, rounded up. `divisor` is not zero.
fn div_round_up(value: u64, divisor: u64) -> u64 {
    value / divisor + u64::from(value % divisor != 0)
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

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A volume serial number in the `XXXX-XXXX` form DOS prints.
fn serial_text(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff)
}

/// How the declared volume relates to the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    /// The input holds the volume exactly.
    Exact,
    /// The input ends this many bytes before the volume does.
    Truncated(u64),
    /// This many bytes follow the volume.
    Trailing(u64),
}

impl Coverage {
    /// Compare the declared volume size with the input.
    fn of(volume_size: u64, input_size: usize) -> Self {
        let input_size = input_size as u64;
        match volume_size.checked_sub(input_size) {
            Some(0) => Self::Exact,
            Some(missing) => Self::Truncated(missing),
            None => Self::Trailing(input_size - volume_size),
        }
    }

    /// Whether weak detection accepts the volume: it may end before the
    /// input does, and may extend beyond it by at most
    /// [`MAX_MISSING_SIZE`] and an eighth of the volume.
    fn is_tolerated(self, volume_size: u64) -> bool {
        match self {
            Self::Exact | Self::Trailing(_) => true,
            Self::Truncated(missing) => {
                missing <= MAX_MISSING_SIZE && missing <= volume_size / MAX_MISSING_DIVISOR
            }
        }
    }
}

/// The error for a volume larger than the input whose structures needed
/// before anything can be listed lie past the end of the input.
fn truncated_volume(volume_size: u64, input_size: usize) -> ClassifierError {
    error(format!(
        "Truncated volume: {volume_size} B declared, {input_size} B present"
    ))
}

/// The note for a volume that is not exactly the input, if any.
fn coverage_note(coverage: Coverage, volume_size: u64, data: &[u8]) -> Option<String> {
    match coverage {
        Coverage::Exact => None,
        Coverage::Truncated(_) => Some(format!(
            "Volume truncated: {} of {} present; files are listed only when all of their data \
             is present",
            size_text(data.len() as u64),
            size_text(volume_size)
        )),
        Coverage::Trailing(size) => {
            let start = usize::try_from(volume_size).expect("smaller than the input");
            let kind = if is_padding(&data[start..]) {
                "padding"
            } else {
                "data that is not part of the volume"
            };
            Some(format!(
                "{size} B after the volume at 0x{start:X} are {kind}"
            ))
        }
    }
}

/// The destination of a boot sector's jump field (`EB rel8 90` or
/// `E9 rel16`), as a byte offset in the sector, or `None` for another
/// first byte. Real-mode offsets wrap at 64 KiB, so a jump backwards from
/// the start of the sector ends beyond it.
fn jump_target(jump: [u8; 3]) -> Option<usize> {
    match jump {
        [JMP_SHORT, rel, NOP] => {
            let destination = 2i32 + i32::from(i8::from_le_bytes([rel]));
            Some(usize::try_from(destination & 0xffff).expect("masked to 16 bits"))
        }
        [JMP_NEAR, low, high] => {
            let destination = 3i32 + i32::from(i16::from_le_bytes([low, high]));
            Some(usize::try_from(destination & 0xffff).expect("masked to 16 bits"))
        }
        _ => None,
    }
}

/// `CLI`, `HLT` and `NOP` instructions followed by a short or near jump
/// back into them or onto itself: code that never leaves the boot sector,
/// written by formatters that provide no boot code.
fn is_idle_loop(code: &[u8]) -> bool {
    let idle = code
        .iter()
        .take_while(|&&b| matches!(b, CLI | HLT | NOP))
        .count();
    // A jump of `len` bytes at `idle` lands at `idle + len + rel`; it stays
    // in the loop when that is at most `idle`, that is when it goes back
    // between `len` and `idle + len` bytes.
    let stays = |back: i64, len: usize| {
        let longest = i64::try_from(idle + len).unwrap_or(i64::MAX);
        let shortest = i64::try_from(len).expect("2 or 3");
        (shortest..=longest).contains(&back)
    };
    match code.get(idle..) {
        Some([JMP_SHORT, rel, ..]) => stays(-i64::from(i8::from_le_bytes([*rel])), 2),
        Some([JMP_NEAR, low, high, ..]) => stays(-i64::from(i16::from_le_bytes([*low, *high])), 3),
        _ => false,
    }
}

/// What the boot sector's boot code area holds.
struct BootCode<'a> {
    /// The code as an x86 real-mode child, when there is code.
    child: Option<Child<'a>>,
    /// What was found, for the notes.
    note: String,
}

impl BootCode<'_> {
    /// No code, for the reason `note` gives.
    fn none(note: String) -> Self {
        Self { child: None, note }
    }
}

/// The volume boot code from the jump destination to the boot signature,
/// as an x86 real-mode child, unless the jump leaves the boot code area
/// (`code_start..510`), the area holds one repeated byte (zero fill, or
/// the `HLT` fill of [EXFAT] 3.1.19), or the code is an idle loop. Returns
/// the child, if any, and a note saying what was found.
fn boot_code(data: &[u8], code_start: usize) -> Result<BootCode<'_>> {
    let jump: [u8; 3] = array(data, 0)?;
    let Some(target) = jump_target(jump) else {
        return Ok(BootCode::none(format!(
            "No boot code: the jump field {:02X} {:02X} {:02X} is not an x86 jump",
            jump[0], jump[1], jump[2]
        )));
    };
    if !(code_start..BOOT_SIGNATURE_OFFSET).contains(&target) {
        let place = if target < code_start {
            "into the boot parameters"
        } else {
            "past the boot code area"
        };
        return Ok(BootCode::none(format!(
            "No boot code: the jump field leads {place} (0x{target:X})"
        )));
    }
    let code = slice(data, target, BOOT_SIGNATURE_OFFSET - target)?;
    if code.iter().all(|&b| b == code[0]) {
        return Ok(BootCode::none(format!(
            "No boot code: the boot code area is filled with 0x{:02X}",
            code[0]
        )));
    }
    if is_idle_loop(code) {
        return Ok(BootCode::none(format!(
            "No boot code: the code at 0x{target:X} is an idle loop"
        )));
    }
    let note = format!(
        "Volume boot code at 0x{target:X}-0x{:X} ({} B): x86 real-mode code entered from the \
         jump at offset 0",
        BOOT_SIGNATURE_OFFSET - 1,
        code.len()
    );
    let child = Child::stored("Volume boot code", target, code)
        .with_target(BOOT_CODE_TARGET)
        .as_code();
    Ok(BootCode {
        child: Some(child),
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_targets_follow_both_jump_forms() {
        assert_eq!(jump_target([0xeb, 0x3c, 0x90]), Some(0x3e));
        assert_eq!(jump_target([0xeb, 0x58, 0x90]), Some(0x5a));
        assert_eq!(jump_target([0xeb, 0x76, 0x90]), Some(0x78));
        assert_eq!(jump_target([0xe9, 0x00, 0x01]), Some(0x103));
        // A jump onto itself, and a jump before the sector start, which
        // wraps to the end of the 64 KiB segment.
        assert_eq!(jump_target([0xeb, 0xfe, 0x90]), Some(0));
        assert_eq!(jump_target([0xeb, 0xf0, 0x90]), Some(0xfff2));
        assert_eq!(jump_target([0xeb, 0x3c, 0x00]), None);
        assert_eq!(jump_target([0x33, 0xc0, 0x8e]), None);
    }

    #[test]
    fn idle_loops_jump_back_into_cli_hlt_and_nop() {
        assert!(is_idle_loop(&[0xeb, 0xfe]));
        assert!(is_idle_loop(&[0xf4, 0xeb, 0xfd]));
        assert!(is_idle_loop(&[0xfa, 0xf4, 0xeb, 0xfc, 0x00]));
        assert!(is_idle_loop(&[0xe9, 0xfd, 0xff]));
        // mkfs.fat's message loop starts with `push cs`.
        assert!(!is_idle_loop(&[0x0e, 0x1f, 0xbe, 0x5b, 0x7c]));
        // A jump backwards past the idle instructions leaves them, and a
        // jump to the next instruction or forwards does not loop.
        assert!(!is_idle_loop(&[0xf4, 0xeb, 0xf0]));
        assert!(!is_idle_loop(&[0xeb, 0x00, 0x90]));
        assert!(!is_idle_loop(&[0xeb, 0x10]));
    }

    #[test]
    fn weak_detection_tolerates_volumes_slightly_shorter_than_declared() {
        assert_eq!(Coverage::of(4096, 4096), Coverage::Exact);
        assert_eq!(Coverage::of(4096, 5000), Coverage::Trailing(904));
        let short = Coverage::of(1 << 23, (1 << 23) - 4096);
        assert_eq!(short, Coverage::Truncated(4096));
        assert!(short.is_tolerated(1 << 23));
        // More than an eighth of the volume, or more than 1 MiB, missing.
        assert!(!Coverage::of(4096, 3000).is_tolerated(4096));
        let cut = Coverage::of(1 << 30, (1 << 30) - (2 << 20));
        assert_eq!(cut, Coverage::Truncated(2 << 20));
        assert!(!cut.is_tolerated(1 << 30));
    }

    #[test]
    fn serial_numbers_print_as_two_hex_halves() {
        assert_eq!(serial_text(0x5a52_4146), "5A52-4146");
    }
}
