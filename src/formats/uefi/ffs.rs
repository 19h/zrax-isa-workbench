//! FFS files inside a firmware volume: `EFI_FFS_FILE_HEADER` and
//! `EFI_FFS_FILE_HEADER2` (PI 1.8 Vol. 3, 3.2.3; EDK2 `PiFirmwareFile.h`),
//! file states (PI 1.8 Vol. 3 design 2.2.8; EDK2 `Core/Pei/FwVol/FwVol.c`
//! `GetFileState` and `FindFileEx`) and checksums (EDK2
//! `Core/Dxe/FwVol/Ffs.c` `VerifyHeaderChecksum`, `IsValidFfsFile`).
//!
//! Header: name GUID (16 B), header checksum (1 B, 0x10), data checksum
//! (1 B, 0x11), type (0x12), attributes (0x13), 24-bit size including the
//! header (0x14), state (0x17). With `FFS_ATTRIB_LARGE_FILE` the header is
//! 32 bytes and a u64 `ExtendedSize` at 0x18 holds the size. Files start
//! on 8-byte boundaries relative to the volume.
//!
//! Revision 1 (Framework) volumes use the same header with different
//! attribute meanings, which come from `UEFITool` A75 (`common/ffs.h`,
//! `ffsparser.cpp`) only: bit 0 marks a 2-byte tail holding the inverted
//! `IntegrityCheck` field, bit 1 is a recovery flag rather than an
//! alignment table selector, there are no large files, and the fixed data
//! checksum is `0x5A`.

use super::fv::{VolumeHeader, FILE_ALIGNMENT, REVISION_FRAMEWORK};
use super::*;

const FILE_HEADER_SIZE: usize = 24;
const FILE_HEADER2_SIZE: usize = 32;

/// Header field offsets (the header checksum at 0x10 is covered by the
/// whole-header sum; with it, the data checksum forms the u16
/// `IntegrityCheck`).
const INTEGRITY_CHECK: usize = 0x10;
const FILE_CHECKSUM: usize = 0x11;
const FILE_TYPE: usize = 0x12;
const FILE_ATTRIBUTES: usize = 0x13;
const FILE_SIZE: usize = 0x14;
const FILE_STATE: usize = 0x17;
const EXTENDED_SIZE: usize = 0x18;

/// `EFI_FV_FILETYPE_*` values the walk distinguishes.
const EFI_FV_FILETYPE_RAW: u8 = 0x01;
const EFI_FV_FILETYPE_FREEFORM: u8 = 0x02;
const EFI_FV_FILETYPE_SECURITY_CORE: u8 = 0x03;
const EFI_FV_FILETYPE_MM_CORE_STANDALONE: u8 = 0x0F;
const EFI_FV_FILETYPE_FFS_PAD: u8 = 0xF0;

/// `EFI_FFS_FILE_ATTRIBUTES` bits.
const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
const FFS_ATTRIB_DATA_ALIGNMENT_2: u8 = 0x02;
const FFS_ATTRIB_DATA_ALIGNMENT: u8 = 0x38;
const FFS_ATTRIB_DATA_ALIGNMENT_SHIFT: u32 = 3;
const FFS_ATTRIB_CHECKSUM: u8 = 0x40;

/// Framework `FFS_ATTRIB_TAIL_PRESENT` (the bit PI uses for large files).
const FFS_ATTRIB_TAIL_PRESENT: u8 = 0x01;

/// The Framework file tail: the inverted `IntegrityCheck` (u16).
const FILE_TAIL_SIZE: usize = 2;

/// `Checksum.File` when `FFS_ATTRIB_CHECKSUM` is clear: `FFS_FIXED_CHECKSUM2`
/// in PI volumes, `FFS_FIXED_CHECKSUM` in Framework volumes (`UEFITool`).
const FFS_FIXED_CHECKSUM: u8 = 0xAA;
const FFS_FIXED_CHECKSUM_FRAMEWORK: u8 = 0x5A;

/// `EFI_FFS_FILE_STATE` bits; only the most significant set bit counts.
const EFI_FILE_HEADER_CONSTRUCTION: u8 = 0x01;
const EFI_FILE_DATA_VALID: u8 = 0x04;
const EFI_FILE_MARKED_FOR_UPDATE: u8 = 0x08;
const EFI_FILE_DELETED: u8 = 0x10;
const EFI_FILE_HEADER_INVALID: u8 = 0x20;

/// Data alignment as a power of two, by the 3-bit attribute index (PI 1.8
/// Vol. 3 Table 3.3), without and with `FFS_ATTRIB_DATA_ALIGNMENT_2`.
const DATA_ALIGNMENT_POWERS: [u32; 8] = [0, 4, 7, 9, 10, 12, 15, 16];
const DATA_ALIGNMENT_2_POWERS: [u32; 8] = [17, 18, 19, 20, 21, 22, 23, 24];

/// The fields of one file header.
#[derive(Debug)]
struct FileHeader {
    name: Guid,
    file_type: u8,
    attributes: u8,
    /// 24 or 32 bytes.
    header_size: usize,
    /// The whole file, header and Framework tail included; not yet checked
    /// against the volume.
    size: u64,
    state: u8,
    integrity_check: u16,
    data_checksum: u8,
    /// 2 for a Framework file with a tail, else 0.
    tail_size: usize,
    /// The volume is a revision 1 (Framework) volume.
    framework: bool,
}

/// What the file walk saw in one volume.
#[derive(Debug, Default)]
pub(super) struct FileStats {
    files: usize,
    data_checksums: usize,
    pads: usize,
    deleted: usize,
    header_only: usize,
    misaligned: usize,
    /// Framework file tails that matched.
    tails: usize,
    /// File offset and raw state of a file whose state ended the walk.
    stopped: Option<(usize, u8)>,
    /// Volume offset of free space that is not fully erased.
    dirty_free_space: Option<usize>,
}

impl FileStats {
    /// One clause per fact, for the volume note.
    pub(super) fn describe(&self, volume: &Stream<'_, '_>) -> String {
        let mut clauses = vec![
            count(self.files, "FFS file"),
            "header checksums valid".to_string(),
            format!("{} valid", count(self.data_checksums, "data checksum")),
        ];
        if self.pads > 0 {
            clauses.push(format!("{} skipped", count(self.pads, "pad file")));
        }
        if self.deleted > 0 {
            clauses.push(format!("{} skipped", count(self.deleted, "deleted file")));
        }
        if self.header_only > 0 {
            clauses.push(format!(
                "{} skipped",
                count(self.header_only, "incomplete or invalid header")
            ));
        }
        if self.tails > 0 {
            clauses.push(format!("{} valid", count(self.tails, "file tail")));
        }
        if self.misaligned > 0 {
            clauses.push(format!(
                "{} misaligned for the data alignment attribute",
                count(self.misaligned, "file")
            ));
        }
        if let Some((at, state)) = self.stopped {
            clauses.push(format!(
                "walk stopped at {}: file state 0x{state:02X}, as the PEI core stops",
                volume.place(at)
            ));
        }
        if let Some(at) = self.dirty_free_space {
            clauses.push(format!(
                "free space at {} holds non-erased bytes",
                volume.place(at)
            ));
        }
        clauses.join("; ")
    }
}

/// Read the header at `pos` of a volume of `revision`. The size is checked
/// only for states that use it, because the PEI core skips half-written
/// headers by their length.
fn file_header(bytes: &[u8], pos: usize, revision: u8, place: &str) -> Result<FileHeader> {
    let header = bytes
        .get(pos..)
        .and_then(|rest| rest.get(..FILE_HEADER_SIZE))
        .ok_or_else(|| error(format!("Truncated FFS file header at {place}")))?;
    let attributes = header[FILE_ATTRIBUTES];
    let framework = revision == REVISION_FRAMEWORK;
    let large = !framework && attributes & FFS_ATTRIB_LARGE_FILE != 0;
    let (header_size, size) = if large {
        let extended = le_u64(bytes, pos + EXTENDED_SIZE)
            .map_err(|_| error(format!("Truncated FFS file header at {place}")))?;
        (FILE_HEADER2_SIZE, extended)
    } else {
        (FILE_HEADER_SIZE, u64::from(le_u24(header, FILE_SIZE)?))
    };
    let has_tail = framework && attributes & FFS_ATTRIB_TAIL_PRESENT != 0;
    Ok(FileHeader {
        name: Guid::read(header, 0)?,
        file_type: header[FILE_TYPE],
        attributes,
        header_size,
        size,
        state: header[FILE_STATE],
        integrity_check: le_u16(header, INTEGRITY_CHECK)?,
        data_checksum: header[FILE_CHECKSUM],
        tail_size: if has_tail { FILE_TAIL_SIZE } else { 0 },
        framework,
    })
}

/// The decoded state: the most significant set bit after undoing the
/// erase polarity (`GetFileState`), or 0.
fn file_state(raw: u8, erase_polarity: bool) -> u8 {
    let state = if erase_polarity { !raw } else { raw };
    match state.checked_ilog2() {
        Some(bit) => 1 << bit,
        None => 0,
    }
}

/// The file size checked against the header size, the volume and the
/// file system.
fn checked_size(
    file: &FileHeader,
    pos: usize,
    volume_length: usize,
    header: &VolumeHeader,
    place: &str,
) -> Result<usize> {
    if file.header_size == FILE_HEADER2_SIZE && header.file_system != fv::FileSystem::Ffs3 {
        return Err(error(format!(
            "Unsupported FFS large file at {place}: the volume is not FFSv3"
        )));
    }
    let size = usize::try_from(file.size)
        .ok()
        .filter(|size| *size >= file.header_size + file.tail_size && u32::try_from(*size).is_ok())
        .ok_or_else(|| {
            error(format!(
                "Invalid FFS file size 0x{:X} at {place}",
                file.size
            ))
        })?;
    if size > volume_length - pos {
        return Err(error(format!(
            "Truncated FFS file at {place}: {size} B declared, {} B left in the volume",
            volume_length - pos
        )));
    }
    Ok(size)
}

/// Header checksum: the 8-bit sum of the whole header, with `State` and
/// `Checksum.File` counted as zero, must be zero.
fn verify_header_checksum(header_bytes: &[u8], file: &FileHeader, place: &str) -> Result<()> {
    let sum = sum8(header_bytes)
        .wrapping_sub(file.state)
        .wrapping_sub(file.data_checksum);
    if sum != 0 {
        return Err(error(format!(
            "Invalid FFS file header checksum at {place}"
        )));
    }
    Ok(())
}

/// Data checksum: with `FFS_ATTRIB_CHECKSUM`, the data (without a
/// Framework tail) and `Checksum.File` sum to zero; without it,
/// `Checksum.File` is the fixed value. Returns whether a real checksum was
/// verified.
fn verify_data_checksum(data: &[u8], file: &FileHeader, place: &str) -> Result<bool> {
    if file.attributes & FFS_ATTRIB_CHECKSUM != 0 {
        if sum8(data).wrapping_add(file.data_checksum) != 0 {
            return Err(error(format!("Invalid FFS file data checksum at {place}")));
        }
        return Ok(true);
    }
    let fixed = if file.framework {
        FFS_FIXED_CHECKSUM_FRAMEWORK
    } else {
        FFS_FIXED_CHECKSUM
    };
    if file.data_checksum != fixed {
        return Err(error(format!(
            "Invalid FFS file data checksum 0x{:02X} at {place}: expected the fixed value 0x{fixed:02X}",
            file.data_checksum
        )));
    }
    Ok(false)
}

/// A Framework file tail must hold the inverted `IntegrityCheck`.
fn verify_tail(tail: &[u8], file: &FileHeader, place: &str) -> Result<()> {
    let stored = le_u16(tail, 0)?;
    if stored != !file.integrity_check {
        return Err(error(format!(
            "Invalid FFS file tail 0x{stored:04X} at {place}: expected 0x{:04X}",
            !file.integrity_check
        )));
    }
    Ok(())
}

/// Required alignment of the file data relative to the volume. Framework
/// volumes have no second alignment table.
fn data_alignment(file: &FileHeader) -> usize {
    let index = usize::from(
        (file.attributes & FFS_ATTRIB_DATA_ALIGNMENT) >> FFS_ATTRIB_DATA_ALIGNMENT_SHIFT,
    );
    let power = if file.framework || file.attributes & FFS_ATTRIB_DATA_ALIGNMENT_2 == 0 {
        DATA_ALIGNMENT_POWERS[index]
    } else {
        DATA_ALIGNMENT_2_POWERS[index]
    };
    1 << power
}

/// Walk the files of `volume` (the whole volume, header included).
pub(super) fn walk_files<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    volume: Stream<'a, '_>,
    header: &VolumeHeader,
    depth: usize,
) -> Result<FileStats> {
    let bytes = volume.bytes();
    let erase = header.erase_byte();
    let mut stats = FileStats::default();
    let mut pos = header.files_start;
    while pos < bytes.len() {
        let rest = &bytes[pos..];
        let next_header = &rest[..rest.len().min(FILE_HEADER_SIZE)];
        if next_header.iter().all(|&b| b == erase) {
            // Free space runs to the end of the volume (EDK2 DXE stops at
            // the first erased header).
            if !rest.iter().all(|&b| b == erase) {
                stats.dirty_free_space = Some(pos);
            }
            break;
        }
        let place = volume.place(pos);
        let file = file_header(bytes, pos, header.revision, &place)?;
        let header_bytes = &bytes[pos..pos + file.header_size.min(rest.len())];
        let end = match file_state(file.state, header.erase_polarity()) {
            EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_INVALID => {
                stats.header_only += 1;
                pos + file.header_size
            }
            EFI_FILE_DATA_VALID | EFI_FILE_MARKED_FOR_UPDATE => {
                let size = checked_size(&file, pos, bytes.len(), header, &place)?;
                verify_header_checksum(header_bytes, &file, &place)?;
                let data_end = pos + size - file.tail_size;
                let data = volume.sub(pos + file.header_size, data_end)?;
                if verify_data_checksum(data.bytes(), &file, &place)? {
                    stats.data_checksums += 1;
                }
                if file.tail_size > 0 {
                    verify_tail(&bytes[data_end..pos + size], &file, &place)?;
                    stats.tails += 1;
                }
                if (pos + file.header_size) % data_alignment(&file) != 0 {
                    stats.misaligned += 1;
                }
                if file.file_type == EFI_FV_FILETYPE_FFS_PAD {
                    stats.pads += 1;
                } else {
                    stats.files += 1;
                    file_contents(c, budget, &file, data, depth)?;
                }
                pos + size
            }
            EFI_FILE_DELETED => {
                let size = checked_size(&file, pos, bytes.len(), header, &place)?;
                verify_header_checksum(header_bytes, &file, &place)?;
                stats.deleted += 1;
                pos + size
            }
            // Header valid without data, or no defined state bit: the PEI
            // core ends its search here.
            _ => {
                stats.stopped = Some((pos, file.state));
                break;
            }
        };
        pos = align_up(end, FILE_ALIGNMENT)?;
    }
    Ok(stats)
}

/// List what one valid file holds.
fn file_contents<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &FileHeader,
    data: Stream<'a, '_>,
    depth: usize,
) -> Result<()> {
    let mut context = section::FileContext::new(file.name);
    let walked = match file.file_type {
        EFI_FV_FILETYPE_RAW => section::raw_data(c, budget, &mut context, data, "raw file", depth),
        // Sectioned file types other than SEC, whose format the PI
        // specification leaves undefined.
        EFI_FV_FILETYPE_FREEFORM..=EFI_FV_FILETYPE_MM_CORE_STANDALONE
            if file.file_type != EFI_FV_FILETYPE_SECURITY_CORE =>
        {
            section::walk_sections(c, budget, &mut context, data, depth)
        }
        // SEC, OEM, debug and undefined types: sections when the data is
        // a valid section stream, raw data otherwise.
        _ if section::is_section_stream(data.bytes()) => {
            section::walk_sections(c, budget, &mut context, data, depth)
        }
        _ => section::raw_data(c, budget, &mut context, data, "file data", depth),
    };
    // Images listed before a failure keep their labels when a Framework
    // volume reports the failure instead of rejecting the volume.
    context.finish(c);
    walked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_uses_the_highest_bit_after_polarity() {
        assert_eq!(file_state(0xF8, true), EFI_FILE_DATA_VALID);
        assert_eq!(file_state(0x07, false), EFI_FILE_DATA_VALID);
        assert_eq!(file_state(0xE8, true), EFI_FILE_DELETED);
        assert_eq!(file_state(0xFF, true), 0);
        assert_eq!(file_state(0xFE, true), EFI_FILE_HEADER_CONSTRUCTION);
    }

    /// A header with `attributes` in a volume of `revision`.
    fn header_with(attributes: u8, revision: u8) -> FileHeader {
        let mut bytes = [0u8; FILE_HEADER_SIZE];
        bytes[FILE_ATTRIBUTES] = attributes;
        bytes[FILE_SIZE] = 0x40;
        file_header(&bytes, 0, revision, "0x0").expect("24 bytes are present")
    }

    #[test]
    fn data_alignment_follows_both_tables() {
        let pi = |attributes| data_alignment(&header_with(attributes, fv::REVISION_PI));
        assert_eq!(pi(0x00), 1);
        assert_eq!(pi(0x08), 16);
        assert_eq!(pi(0x38), 64 << 10);
        assert_eq!(pi(0x02), 128 << 10);
        assert_eq!(pi(0x3A), 16 << 20);
        // Framework bit 1 is the recovery flag.
        assert_eq!(data_alignment(&header_with(0x0A, REVISION_FRAMEWORK)), 16);
    }

    #[test]
    fn framework_bit_0_marks_a_tail_instead_of_a_large_file() {
        let framework = header_with(FFS_ATTRIB_TAIL_PRESENT, REVISION_FRAMEWORK);
        assert_eq!(
            (framework.header_size, framework.tail_size, framework.size),
            (FILE_HEADER_SIZE, FILE_TAIL_SIZE, 0x40)
        );
        let mut large = [0u8; FILE_HEADER2_SIZE];
        large[FILE_ATTRIBUTES] = FFS_ATTRIB_LARGE_FILE;
        large[EXTENDED_SIZE] = 0x80;
        let pi = file_header(&large, 0, fv::REVISION_PI, "0x0").unwrap();
        assert_eq!(
            (pi.header_size, pi.tail_size, pi.size),
            (FILE_HEADER2_SIZE, 0, 0x80)
        );
    }
}
