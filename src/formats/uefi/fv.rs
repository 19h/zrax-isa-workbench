//! PI firmware volumes: `EFI_FIRMWARE_VOLUME_HEADER` (PI 1.8 Vol. 3,
//! 3.2.1.1; EDK2 `PiFirmwareVolume.h`), its 16-bit header checksum (EDK2
//! `Core/Dxe/FwVol/Ffs.c` `VerifyFvHeaderChecksum`), the block map, the
//! extended header and its entries, and where the first file starts (EDK2
//! `Core/Pei/FwVol/FwVol.c` `FindFileEx`).
//!
//! Header: zero vector (16 B), file system GUID (0x10), `FvLength` (u64,
//! 0x20), `_FVH` (0x28), attributes (u32, 0x2C), header length (u16, 0x30),
//! checksum (u16, 0x32), extended header offset (u16, 0x34), reserved (1 B),
//! revision (1 B, 0x37), then the block map of `{NumBlocks, Length}` pairs
//! ending in `{0, 0}`.

use super::*;

/// `EFI_FVH_SIGNATURE` and its offset.
const FVH_SIGNATURE: [u8; 4] = *b"_FVH";
const SIGNATURE_OFFSET: usize = 0x28;

/// The block map starts after the fixed header fields.
const BLOCK_MAP_OFFSET: usize = 0x38;
const BLOCK_MAP_ENTRY_SIZE: usize = 8;

/// One block-map entry plus the terminator.
const MIN_HEADER_LENGTH: usize = BLOCK_MAP_OFFSET + 2 * BLOCK_MAP_ENTRY_SIZE;

/// `UEFITool` rejects volumes of 4 GiB - 1 or more.
const MAX_VOLUME_LENGTH: u64 = 0xFFFF_FFFF;

/// `EFI_FVH_REVISION` (PI) and the Framework revision `UEFITool` also
/// accepts.
pub(super) const REVISION_FRAMEWORK: u8 = 1;
pub(super) const REVISION_PI: u8 = 2;

/// `EFI_FVB2_ERASE_POLARITY`: erased bytes are `0xFF` and FFS state bits
/// are inverted.
const EFI_FVB2_ERASE_POLARITY: u32 = 0x0000_0800;

/// `EFI_FIRMWARE_VOLUME_EXT_HEADER`: `FvName` GUID and `ExtHeaderSize`.
const EXT_HEADER_SIZE: usize = 20;

/// `EFI_FIRMWARE_VOLUME_EXT_ENTRY`: `ExtEntrySize` and `ExtEntryType`.
const EXT_ENTRY_HEADER_SIZE: usize = 4;

/// `EFI_FV_EXT_TYPE_USED_SIZE_TYPE`: a u32 used size follows.
const EFI_FV_EXT_TYPE_USED_SIZE_TYPE: u16 = 0x0003;

/// The extended header is 32-bit aligned; files are 8-byte aligned
/// relative to the volume start.
const EXT_HEADER_ALIGNMENT: usize = 4;
pub(super) const FILE_ALIGNMENT: usize = 8;

/// Most `_FVH` hits examined while scanning a region for volumes. Each
/// failed candidate can cost a checksum over up to 64 KiB of header.
const MAX_VOLUME_CANDIDATES: usize = 1024;

/// Flash device images that begin with other data place their first
/// volume on a 4 KiB boundary: the 32-bit and 64-bit Arm EDK2 images shipped with
/// QEMU 11.1.1 start with a branch to 0x1000, where the volume starts. The
/// alignment and the 1 MiB bound on the leading data are this parser's
/// choice from those images, not specification values.
const DEVICE_VOLUME_ALIGNMENT: usize = 0x1000;
const MAX_LEADING_DATA: usize = 1 << 20;

/// Volumes nested in volumes (through FV image sections) are walked up to
/// this depth, counting encapsulation sections too.
pub(super) const MAX_DEPTH: usize = 16;

/// `EFI_FIRMWARE_FILE_SYSTEM2_GUID` (`FFSv2`).
const EFI_FIRMWARE_FILE_SYSTEM2_GUID: Guid = Guid::new(
    0x8C8C_E578,
    0x8A3D,
    0x4F1C,
    [0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3],
);

/// `EFI_FIRMWARE_FILE_SYSTEM3_GUID` (`FFSv3`, large files).
const EFI_FIRMWARE_FILE_SYSTEM3_GUID: Guid = Guid::new(
    0x5473_C07A,
    0x3DCB,
    0x4DCA,
    [0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A],
);

/// Framework `EFI_FIRMWARE_FILE_SYSTEM_GUID` (`FFSv1`; `UEFITool` only).
const EFI_FIRMWARE_FILE_SYSTEM_GUID: Guid = Guid::new(
    0x7A93_54D9,
    0x0468,
    0x444A,
    [0x81, 0xCE, 0x0B, 0xF6, 0x17, 0xD8, 0x90, 0xDF],
);

/// `gEfiSystemNvDataFvGuid`: a variable store volume, not FFS.
const EFI_SYSTEM_NV_DATA_FV_GUID: Guid = Guid::new(
    0xFFF1_2B8D,
    0x7696,
    0x4C8B,
    [0xA9, 0x85, 0x27, 0x47, 0x07, 0x5B, 0x4F, 0x50],
);

/// Vendor file system GUIDs that `UEFITool` A75 walks as `FFSv2`
/// (`common/ffs.cpp` `FFSv2Volumes`); no specification defines them.
const VENDOR_FFS2_GUIDS: &[(Guid, &str)] = &[
    (
        Guid::new(
            0x04AD_EEAD,
            0x61FF,
            0x4D31,
            [0xB6, 0xBA, 0x64, 0xF8, 0xBF, 0x90, 0x1F, 0x5A],
        ),
        "Apple immutable",
    ),
    (
        Guid::new(
            0xBD00_1B8C,
            0x6A71,
            0x487B,
            [0xA1, 0x4F, 0x0C, 0x2A, 0x2D, 0xCF, 0x7A, 0x5D],
        ),
        "Apple authentication",
    ),
    (
        Guid::new(
            0xAD3F_FFFF,
            0xD28B,
            0x44C4,
            [0x9F, 0x13, 0x9E, 0xA9, 0x8A, 0x97, 0xF9, 0xF0],
        ),
        "Intel",
    ),
    (
        Guid::new(
            0xD6A1_CD70,
            0x4B33,
            0x4994,
            [0xA6, 0xEA, 0x37, 0x5F, 0x2C, 0xCC, 0x54, 0x37],
        ),
        "Intel 2",
    ),
    (
        Guid::new(
            0x4F49_4156,
            0xAED6,
            0x4D64,
            [0xA5, 0x37, 0xB8, 0xA5, 0x55, 0x7B, 0xCE, 0xEC],
        ),
        "Sony",
    ),
    (
        Guid::new(
            0x372B_56DF,
            0xCC9F,
            0x4817,
            [0xAB, 0x97, 0x0A, 0x10, 0xA9, 0x2C, 0xEA, 0xA5],
        ),
        "HP",
    ),
];

/// The file system a volume's GUID names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileSystem {
    /// `FFSv2`: files below 16 MiB, 24-byte headers.
    Ffs2,
    /// `FFSv3`: large files with 32-byte headers allowed.
    Ffs3,
    /// A vendor GUID `UEFITool` treats as `FFSv2`.
    VendorFfs2(&'static str),
    /// Framework `FFSv1`: 24-byte headers, walked with the revision 1
    /// rules.
    Framework,
    /// A variable store, not walked.
    VariableStore,
    /// Any other GUID, not walked.
    Unknown,
}

impl FileSystem {
    fn from_guid(guid: Guid) -> Self {
        if guid == EFI_FIRMWARE_FILE_SYSTEM2_GUID {
            Self::Ffs2
        } else if guid == EFI_FIRMWARE_FILE_SYSTEM3_GUID {
            Self::Ffs3
        } else if guid == EFI_FIRMWARE_FILE_SYSTEM_GUID {
            Self::Framework
        } else if guid == EFI_SYSTEM_NV_DATA_FV_GUID {
            Self::VariableStore
        } else if let Some((_, name)) = VENDOR_FFS2_GUIDS.iter().find(|(g, _)| *g == guid) {
            Self::VendorFfs2(name)
        } else {
            Self::Unknown
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Ffs2 => "FFSv2 file system".into(),
            Self::Ffs3 => "FFSv3 file system".into(),
            Self::VendorFfs2(name) => {
                format!("{name} vendor file system, walked as FFSv2 as UEFITool does")
            }
            Self::Framework => "Framework FFSv1 file system".into(),
            Self::VariableStore => "NVRAM variable store (not interpreted)".into(),
            Self::Unknown => "unknown file system (not walked)".into(),
        }
    }

    /// FFS files are walked in `FFSv1`, `FFSv2`, `FFSv3` and
    /// `FFSv2`-compatible volumes.
    pub(super) fn has_ffs_files(self) -> bool {
        matches!(
            self,
            Self::Ffs2 | Self::Ffs3 | Self::VendorFfs2(_) | Self::Framework
        )
    }
}

/// The header fields the file walk needs.
#[derive(Debug)]
pub(super) struct VolumeHeader {
    pub(super) file_system_guid: Guid,
    pub(super) file_system: FileSystem,
    /// `FvLength`: the whole volume, header included, in bytes.
    pub(super) length: usize,
    pub(super) attributes: u32,
    pub(super) header_length: usize,
    pub(super) revision: u8,
    /// Offset of the first FFS file from the volume start.
    pub(super) files_start: usize,
    /// `FvName` from the extended header.
    pub(super) name: Option<Guid>,
    /// `EFI_FV_EXT_TYPE_USED_SIZE_TYPE` value, in bytes from the volume
    /// start.
    pub(super) used_size: Option<usize>,
    /// Sum of `NumBlocks * Length` over the block map.
    pub(super) mapped_size: u64,
}

impl VolumeHeader {
    /// The value of erased bytes.
    pub(super) fn erase_byte(&self) -> u8 {
        if self.attributes & EFI_FVB2_ERASE_POLARITY == 0 {
            0x00
        } else {
            0xFF
        }
    }

    /// FFS state bits are stored inverted when the erase polarity is 1.
    pub(super) fn erase_polarity(&self) -> bool {
        self.attributes & EFI_FVB2_ERASE_POLARITY != 0
    }
}

/// `_FVH` at offset 0x28: recognized as a firmware volume even when the
/// rest of the header is corrupt, so a damaged volume is a parse error.
pub(super) fn has_signature(data: &[u8]) -> bool {
    data.get(SIGNATURE_OFFSET..SIGNATURE_OFFSET + FVH_SIGNATURE.len()) == Some(&FVH_SIGNATURE)
}

/// 16-bit sum of little-endian words, carries dropped (`CalculateSum16`).
fn sum16(bytes: &[u8]) -> u16 {
    bytes.chunks_exact(2).fold(0u16, |sum, w| {
        sum.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
    })
}

/// Parse and validate the header of the volume that starts `volume`;
/// `place` says where it is for messages. Cheap fixed fields are checked
/// before the checksum, so scanning candidates stays inexpensive.
pub(super) fn header(volume: &[u8], place: &str) -> Result<VolumeHeader> {
    let fixed = volume.get(..BLOCK_MAP_OFFSET).ok_or_else(|| {
        error(format!(
            "Truncated firmware volume header at {place}: {} B present",
            volume.len()
        ))
    })?;
    if fixed[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 4] != FVH_SIGNATURE {
        return Err(error(format!(
            "Missing firmware volume signature at {place}"
        )));
    }
    let revision = fixed[0x37];
    if revision != REVISION_PI && revision != REVISION_FRAMEWORK {
        return Err(error(format!(
            "Unsupported firmware volume revision {revision} at {place}"
        )));
    }
    let declared_length = le_u64(fixed, 0x20)?;
    let header_length = usize::from(le_u16(fixed, 0x30)?);
    if header_length < MIN_HEADER_LENGTH || header_length % 2 != 0 {
        return Err(error(format!(
            "Invalid firmware volume header length 0x{header_length:X} at {place}"
        )));
    }
    if declared_length >= MAX_VOLUME_LENGTH || declared_length < header_length as u64 {
        return Err(error(format!(
            "Invalid firmware volume length 0x{declared_length:X} at {place}"
        )));
    }
    let length = to_usize(declared_length, "firmware volume length")?;
    if length > volume.len() {
        return Err(error(format!(
            "Truncated firmware volume at {place}: FvLength {length} B, {} B present",
            volume.len()
        )));
    }
    let header_bytes = &volume[..header_length];
    if sum16(header_bytes) != 0 {
        return Err(error(format!(
            "Invalid firmware volume header checksum at {place}"
        )));
    }
    let mapped_size = block_map(header_bytes, place)?;
    let file_system_guid = Guid::read(fixed, 0x10)?;
    let attributes = le_u32(fixed, 0x2C)?;
    let ext_header_offset = usize::from(le_u16(fixed, 0x34)?);
    let mut header = VolumeHeader {
        file_system_guid,
        file_system: FileSystem::from_guid(file_system_guid),
        length,
        attributes,
        header_length,
        revision,
        files_start: align_up(header_length, FILE_ALIGNMENT)?,
        name: None,
        used_size: None,
        mapped_size,
    };
    // UEFITool honors the extended header only for revision 2 volumes.
    if revision >= REVISION_PI && ext_header_offset != 0 {
        extended_header(&volume[..length], ext_header_offset, place, &mut header)?;
    }
    Ok(header)
}

/// Walk the block map inside the header; returns the mapped size. The
/// terminator must appear before the end of the header.
fn block_map(header: &[u8], place: &str) -> Result<u64> {
    let mut mapped = 0u64;
    for entry in header[BLOCK_MAP_OFFSET..].chunks_exact(BLOCK_MAP_ENTRY_SIZE) {
        let blocks = u64::from(le_u32(entry, 0)?);
        let block_length = u64::from(le_u32(entry, 4)?);
        if blocks == 0 && block_length == 0 {
            return Ok(mapped);
        }
        // Both factors are below 2^32, so the product fits; the sum
        // saturates, since it is only compared with `FvLength`.
        mapped = mapped.saturating_add(blocks * block_length);
    }
    Err(error(format!(
        "Missing firmware volume block map terminator at {place}"
    )))
}

/// Read `EFI_FIRMWARE_VOLUME_EXT_HEADER` and its entries; the first file
/// follows the extended header.
fn extended_header(
    volume: &[u8],
    offset: usize,
    place: &str,
    header: &mut VolumeHeader,
) -> Result<()> {
    if offset < header.header_length || offset % EXT_HEADER_ALIGNMENT != 0 {
        return Err(error(format!(
            "Invalid firmware volume extended header offset 0x{offset:X} at {place}"
        )));
    }
    let ext = volume.get(offset..).unwrap_or_default();
    let fields = ext.get(..EXT_HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated firmware volume extended header at {place} + 0x{offset:X}"
        ))
    })?;
    let name = Guid::read(fields, 0)?;
    let ext_size = to_usize(le_u32(fields, 16)?, "extended header size")?;
    if ext_size < EXT_HEADER_SIZE || ext_size > ext.len() {
        return Err(error(format!(
            "Invalid firmware volume extended header size 0x{ext_size:X} at {place}"
        )));
    }
    let mut pos = EXT_HEADER_SIZE;
    while pos + EXT_ENTRY_HEADER_SIZE <= ext_size {
        let entry_size = usize::from(le_u16(ext, pos)?);
        let entry_type = le_u16(ext, pos + 2)?;
        // A zero size would loop forever in the PEI core's walk.
        if entry_size < EXT_ENTRY_HEADER_SIZE || pos + entry_size > ext_size {
            return Err(error(format!(
                "Invalid firmware volume extension entry size 0x{entry_size:X} at {place} + 0x{:X}",
                offset + pos
            )));
        }
        if entry_type == EFI_FV_EXT_TYPE_USED_SIZE_TYPE && entry_size >= EXT_ENTRY_HEADER_SIZE + 4 {
            header.used_size = Some(to_usize(le_u32(ext, pos + 4)?, "used size")?);
        }
        pos += entry_size;
    }
    header.name = Some(name);
    header.files_start = align_up(offset + ext_size, FILE_ALIGNMENT)?;
    Ok(())
}

/// Walk the volume at the start of `stream`: header, then its FFS files.
/// Returns the volume length.
pub(super) fn walk_volume<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    stream: Stream<'a, '_>,
    depth: usize,
) -> Result<usize> {
    let place = stream.place(0);
    if depth > MAX_DEPTH {
        budget.note(
            c,
            format!(
                "Firmware volume at {place} is nested deeper than {MAX_DEPTH} levels; not walked"
            ),
        );
        return Ok(0);
    }
    let header = header(stream.bytes(), &place)?;
    let volume = stream.sub(0, header.length)?;
    budget.volumes += 1;
    let index = budget.volumes;
    let mut summary = volume_summary(&header);
    if header.file_system.has_ffs_files() {
        let files = match ffs::walk_files(c, budget, volume, &header, depth) {
            Ok(stats) => stats.describe(&volume),
            // The Framework file rules come from `UEFITool` alone, so a
            // revision 1 volume whose files do not follow them is reported
            // rather than rejected.
            Err(e) if header.revision == REVISION_FRAMEWORK => format!(
                "file walk stopped: {}; files after that point are not listed",
                bare_message(e)
            ),
            Err(e) => return Err(e),
        };
        summary.push_str("; ");
        summary.push_str(&files);
    }
    if index <= MAX_DETAIL_NOTES {
        c.push_metadata(
            format!("{KEY_PREFIX}_volume_{}", index - 1),
            format!("Firmware volume {index}"),
            format!("{place}; {summary}"),
        );
    }
    budget.note(c, format!("Firmware volume at {place}: {summary}"));
    Ok(header.length)
}

/// File system, size, revision and erase polarity of a volume.
fn volume_summary(header: &VolumeHeader) -> String {
    let mut clauses = vec![format!(
        "{} {}; {}; revision {}; erase polarity {}; header checksum valid",
        header.file_system_guid,
        header.file_system.describe(),
        size_text(header.length),
        header.revision,
        u8::from(header.erase_polarity())
    )];
    if let Some(name) = header.name {
        clauses.push(format!("name {name}"));
    }
    if let Some(used) = header.used_size {
        clauses.push(format!("used size {}", size_text(used)));
    }
    if header.mapped_size != header.length as u64 {
        clauses.push(format!(
            "block map covers {} B, not FvLength",
            header.mapped_size
        ));
    }
    clauses.join("; ")
}

/// A valid volume found by scanning.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

/// Progress of one region scan.
#[derive(Debug, Default)]
struct Scan {
    candidates: usize,
    exhausted: bool,
}

/// The next offset in `from..end` where a valid volume header starts (its
/// `_FVH` 0x28 bytes in) and the volume fits before `end`.
fn find_volume(data: &[u8], from: usize, end: usize, scan: &mut Scan) -> Option<Span> {
    let window = data.get(from..end)?;
    for hit in memchr::memmem::find_iter(window, &FVH_SIGNATURE) {
        let Some(start) = hit.checked_sub(SIGNATURE_OFFSET) else {
            continue;
        };
        if scan.candidates >= MAX_VOLUME_CANDIDATES {
            scan.exhausted = true;
            return None;
        }
        scan.candidates += 1;
        if let Ok(header) = header(&window[start..], "") {
            return Some(Span {
                start: from + start,
                end: from + start + header.length,
            });
        }
    }
    None
}

/// How volumes found in a region are reported.
#[derive(Debug, Clone, Copy)]
pub(super) enum Placement {
    /// Walked inside this container (volumes following the first one).
    Inline,
    /// Listed as children named after the region (IFD BIOS regions).
    Children(&'static str),
}

/// The volumes [`sequence`] found in a region.
#[derive(Debug, Clone, Copy)]
pub(super) struct VolumeSequence {
    /// Number of volumes found.
    pub(super) volumes: usize,
    /// Offset in `data` where the last volume ends, or the region start
    /// when there is none.
    pub(super) end: usize,
}

/// Walk `data[start..end]` as a sequence of volumes separated by padding.
/// Non-padding bytes between volumes are listed when they are a
/// recognized format. Returns how many volumes were found and where the
/// last one ends.
pub(super) fn sequence<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    data: &'a [u8],
    start: usize,
    end: usize,
    placement: Placement,
) -> Result<VolumeSequence> {
    let mut scan = Scan::default();
    let mut pos = start;
    let mut found = 0;
    let gap_label = match placement {
        Placement::Inline => "Data".to_string(),
        Placement::Children(region) => format!("{region} region data"),
    };
    while let Some(span) = find_volume(data, pos, end, &mut scan) {
        list_gap(c, budget, data, pos, span.start, &gap_label);
        let volume = &data[span.start..span.end];
        match placement {
            Placement::Inline => {
                let stream = Stream::Stored {
                    bytes: volume,
                    base: span.start,
                };
                walk_volume(c, budget, stream, 0)?;
            }
            Placement::Children(region) => {
                let label = format!("{region} region firmware volume at 0x{:X}", span.start);
                let child = Child::stored(label, span.start, volume);
                budget.push(c, child);
            }
        }
        found += 1;
        pos = span.end;
    }
    let last_end = pos;
    list_gap(c, budget, data, pos, end, &gap_label);
    if scan.exhausted {
        c.notes.push(format!(
            "Firmware volume scan stopped after {MAX_VOLUME_CANDIDATES} candidate signatures"
        ));
    }
    Ok(VolumeSequence {
        volumes: found,
        end: last_end,
    })
}

/// List `data[from..to]` when it holds more than padding; only recognized
/// formats are classified.
fn list_gap<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    data: &'a [u8],
    from: usize,
    to: usize,
    label: &str,
) {
    let Some(bytes) = data.get(from..to) else {
        return;
    };
    if bytes.is_empty() || is_padding(bytes) {
        return;
    }
    let child = Child::stored(format!("{label} at 0x{from:X}"), from, bytes).if_recognized();
    budget.push(c, child);
}

/// The first volume of a flash device image that starts with other data:
/// a valid volume header on a 4 KiB boundary after offset 0 and within the
/// first [`MAX_LEADING_DATA`] bytes.
pub(super) fn leading_volume(data: &[u8]) -> Option<usize> {
    let last = MAX_LEADING_DATA.min(data.len());
    (DEVICE_VOLUME_ALIGNMENT..=last)
        .step_by(DEVICE_VOLUME_ALIGNMENT)
        .find(|&offset| {
            let rest = &data[offset..];
            has_signature(rest) && header(rest, "").is_ok()
        })
}

/// Parse a firmware volume file (the volume at offset 0) or a flash device
/// image (the first volume after leading data), then any further volumes in
/// the bytes that follow, as in a BIOS region image.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let start = match layout {
        Layout::FlashDevice => leading_volume(data).ok_or_else(|| {
            error(format!(
                "Missing firmware volume on a 4 KiB boundary in the first {}",
                size_text(MAX_LEADING_DATA)
            ))
        })?,
        _ => 0,
    };
    let mut c = Container::new(FileFormat::UefiFv, layout.label(), KEY_PREFIX);
    let mut budget = Budget::default();
    if start > 0 {
        c.notes.push(format!(
            "{} of leading data before the first firmware volume at 0x{start:X}; listed only when it is a recognized format",
            size_text(start)
        ));
        list_gap(&mut c, &mut budget, data, 0, start, "Leading data");
    }
    let stream = Stream::Stored {
        bytes: &data[start..],
        base: start,
    };
    let first = walk_volume(&mut c, &mut budget, stream, 0)?;
    let further = sequence(
        &mut c,
        &mut budget,
        data,
        start + first,
        data.len(),
        Placement::Inline,
    )?;
    c.consumed = further.end;
    if further.volumes > 0 {
        c.notes.push(format!(
            "{} after the first one",
            count(further.volumes, "further firmware volume")
        ));
    }
    c.notes.push(
        "Firmware volumes and FFS files name no ISA; PE32 and TE images are classified from their own machine fields"
            .into(),
    );
    budget.finish(&mut c);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `FFSv2` volume header: one block of `length` bytes.
    fn volume_header(length: usize) -> Vec<u8> {
        let mut header = vec![0u8; MIN_HEADER_LENGTH];
        header[0x10..0x20].copy_from_slice(&EFI_FIRMWARE_FILE_SYSTEM2_GUID.0);
        header[0x20..0x28].copy_from_slice(&(length as u64).to_le_bytes());
        header[0x28..0x2C].copy_from_slice(&FVH_SIGNATURE);
        header[0x2C..0x30].copy_from_slice(&EFI_FVB2_ERASE_POLARITY.to_le_bytes());
        header[0x30..0x32]
            .copy_from_slice(&u16::try_from(MIN_HEADER_LENGTH).unwrap().to_le_bytes());
        header[0x37] = REVISION_PI;
        header[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
        header[0x3C..0x40].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        let checksum = 0u16.wrapping_sub(sum16(&header));
        header[0x32..0x34].copy_from_slice(&checksum.to_le_bytes());
        header
    }

    #[test]
    fn header_checksum_block_map_and_length_are_validated() {
        let mut volume = volume_header(0x100);
        volume.resize(0x100, 0xFF);
        let header = header(&volume, "0x0").unwrap();
        assert_eq!(header.length, 0x100);
        assert_eq!(header.files_start, MIN_HEADER_LENGTH);
        assert_eq!(header.file_system, FileSystem::Ffs2);
        assert_eq!(header.erase_byte(), 0xFF);
        assert_eq!(header.mapped_size, 0x100);

        let mut bad_checksum = volume.clone();
        bad_checksum[0x32] ^= 1;
        assert!(super::header(&bad_checksum, "0x0").is_err());
        assert!(super::header(&volume[..0xFF], "0x0").is_err());
        let mut odd = volume_header(0x100);
        odd[0x30] = 0x49;
        assert!(super::header(&odd, "0x0").is_err());
    }

    #[test]
    fn scanning_finds_volumes_after_padding_and_bounds_candidates() {
        let mut region = vec![0xFF; 0x40];
        let mut volume = volume_header(0x80);
        volume.resize(0x80, 0xFF);
        region.extend_from_slice(&volume);
        let mut scan = Scan::default();
        let span = find_volume(&region, 0, region.len(), &mut scan).unwrap();
        assert_eq!((span.start, span.end), (0x40, 0xC0));

        let noise = b"_FVH".repeat(4 * MAX_VOLUME_CANDIDATES);
        let mut scan = Scan::default();
        assert!(find_volume(&noise, 0, noise.len(), &mut scan).is_none());
        assert!(scan.exhausted);
    }
}
