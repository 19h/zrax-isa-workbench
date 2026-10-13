//! Intel ME/CSME flash partition tables (`$FPT`): the header versions 1.0,
//! 2.0 and 2.1 and their 32-byte entries, from coreboot 25.09
//! `util/cbfstool/cse_fpt.c` (`get_fpt_buff`, `read_fpt_entries`,
//! `is_partition_valid`), `fpt_formats/fpt_hdr_20.c` and `fpt_hdr_21.c`,
//! the vendored `util/me_cleaner/me_cleaner.py` (checksum coverage, entry
//! fields, NVRAM type), `UEFITool` A75 `common/me.h` and
//! `common/meparser.cpp` (`parseFptRegion`), and `MEAnalyzer` `MEA.py`
//! (the 2.1 CRC-32).
//!
//! The table names partitions, not processors: the ME's own processor is
//! not encoded here, and firmware versions in the manifests are not ISA
//! evidence. Every partition is an opaque component; code partitions are
//! described from their `$CPD` directories (see `cpd.rs`).

use super::*;
use crate::formats::checksum::crc32_update;

/// The table marker.
const MARKER: &[u8; 4] = b"$FPT";

/// The marker follows a 16-byte ROM bypass vector at 0x10, or starts the
/// image (`cse_fpt.c` `get_fpt_buff` tries 0x10 first).
const MARKER_OFFSETS: [usize; 2] = [ROM_BYPASS_SIZE, 0];
const ROM_BYPASS_SIZE: usize = 0x10;

/// Header from the marker: entry count (0x04), header version (0x08),
/// entry version (0x09), header length (0x0A), the 8-bit checksum (1.0 and
/// 2.0) or flags (2.1) at 0x0B, flash cycle fields (0x0C), UMA size or SPS
/// flags (0x10), flags or the 2.1 CRC-32 (0x14), FITC version (0x18, four
/// u16).
const HEADER_SIZE: usize = 0x20;
const ENTRY_SIZE: usize = 0x20;

/// Header versions.
const VERSION_10: u8 = 0x10;
const VERSION_20: u8 = 0x20;
const VERSION_21: u8 = 0x21;

/// `FPT_ENTRY_VERSION` (`cse_fpt.h`).
const ENTRY_VERSION: u8 = 0x10;

/// Header lengths: the 32-byte header alone, or (before ME 11) with the
/// ROM bypass vector in front of it, which the 8-bit checksum then covers
/// (`me_cleaner`; `MEA.py` `fpt_chk_bgn`).
const HEADER_LENGTH: u8 = 0x20;
const HEADER_LENGTH_WITH_BYPASS: u8 = 0x30;

/// Offset of the 2.1 CRC-32 in the header.
const CRC_OFFSET: usize = 0x14;

/// Version 2.1 header flags (0x0B): bit 0 marks `$FPT` redundancy.
const FLAG_REDUNDANCY: u8 = 0x01;

/// `UEFITool` rejects tables with 0x100 or more entries.
const MAX_ENTRIES: usize = 0xFF;

/// Entry flags: type in bits 6:0 (`cse_fpt.c`), the entry-valid byte in
/// bits 31:24 (0xFF marks an invalid entry).
const ENTRY_TYPE_MASK: u32 = 0x7F;
const ENTRY_VALID_SHIFT: u32 = 24;
const ENTRY_INVALID: u32 = 0xFF;

/// Entry types: code and data (`cse_fpt.c`), NVRAM (`me_cleaner`).
const ENTRY_TYPE_CODE: u32 = 0;
const ENTRY_TYPE_DATA: u32 = 1;
const ENTRY_TYPE_NVRAM: u32 = 2;

/// An entry offset of 0xFFFFFFFF marks an absent partition (`UEFITool`).
const OFFSET_ABSENT: u32 = 0xFFFF_FFFF;

/// The pre-CSE manifest tag at 0x1C of a code partition (`me_cleaner`
/// `check_mn2_tag`).
const MANIFEST_TAG_OFFSET: usize = 0x1C;

/// First note of every partition table.
const ME_NOTE: &str = "Partitions are firmware and data for the management engine, whose processor these structures do not identify; every partition is opaque and excluded from ISA analysis";

/// Where the marker is: 0x10 first, then 0.
pub(super) fn marker_offset(data: &[u8]) -> Option<usize> {
    MARKER_OFFSETS
        .into_iter()
        .find(|&at| data.get(at..at + MARKER.len()) == Some(MARKER.as_slice()))
}

/// The table header fields the walk uses.
#[derive(Debug)]
struct Header {
    /// File offset of the marker.
    offset: usize,
    entry_count: usize,
    version: u8,
    entry_version: u8,
    length: u8,
    /// Version 2.1 flags bit 0: a backup table is kept (`MEA.py`).
    redundant: bool,
    /// How the header checksum was checked.
    checksum: String,
}

/// Parse a flash partition table and list its partitions.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let offset = marker_offset(data).ok_or_else(|| error("Missing $FPT marker at 0x10 or 0x0"))?;
    let header = parse_header(data, offset)?;
    let entries = field(
        data,
        offset + HEADER_SIZE,
        header.entry_count * ENTRY_SIZE,
        "$FPT entry table",
    )?;
    let table_end = offset + HEADER_SIZE + entries.len();
    let mut c = Container::new(FileFormat::IntelMe, Layout::IntelFpt.label(), KEY_PREFIX);
    c.notes.push(ME_NOTE.to_string());
    c.notes.push(format!(
        "$FPT at 0x{offset:X}: header version 0x{:02X}, entry version 0x{:02X}, header length 0x{:02X}, {}; {}",
        header.version,
        header.entry_version,
        header.length,
        plural(header.entry_count, "entry", "entries"),
        header.checksum
    ));
    if header.redundant {
        c.notes.push(
            "Redundancy flag set: a backup table may follow (MEAnalyzer reads it at 0x1000); not read"
                .to_string(),
        );
    }
    if header.entry_version != ENTRY_VERSION {
        c.notes.push(format!(
            "Entry version 0x{:02X} differs from the 0x10 that coreboot cse_fpt expects; entries are read in the 32-byte layout",
            header.entry_version
        ));
    }
    if offset == ROM_BYPASS_SIZE && !is_padding(&data[..ROM_BYPASS_SIZE]) {
        c.notes.push(
            "The 16-byte ROM bypass vector before the table is not padding; not analyzed"
                .to_string(),
        );
    }
    push_header_metadata(&mut c, &header);
    let mut listing = Listing::default();
    let mut absent = Vec::new();
    let mut code_partitions = 0;
    for (i, entry) in entries.chunks_exact(ENTRY_SIZE).enumerate() {
        let partition = Entry::read(entry)?;
        if !partition.is_valid() {
            absent.push(partition.name.clone());
            continue;
        }
        let Some(bytes) = partition.bytes(data, table_end, &mut c) else {
            continue;
        };
        if partition.kind() == ENTRY_TYPE_CODE {
            describe_code_partition(&mut c, &mut listing, code_partitions, &partition, bytes);
            code_partitions += 1;
        }
        let label = format!("{} partition ({})", partition.name, partition.kind_name());
        c.push_metadata(
            format!("{KEY_PREFIX}_fpt_entry_{i}"),
            format!("{} partition", partition.name),
            format!(
                "{}; offset 0x{:X}; {}",
                partition.kind_name(),
                partition.offset,
                size_text(bytes.len())
            ),
        );
        listing.push(&mut c, Child::opaque(label, partition.offset, bytes));
    }
    if !absent.is_empty() {
        c.notes.push(format!(
            "Absent or invalid entries (zero offset or length, or the invalid flag): {}",
            listed(&absent)
        ));
    }
    c.consumed = data.len();
    listing.finish(&mut c);
    Ok(c)
}

/// The header at `offset`: a supported version and length, a sane entry
/// count, and the checksum its version defines.
fn parse_header(data: &[u8], offset: usize) -> Result<Header> {
    let bytes = field(data, offset, HEADER_SIZE, "$FPT header")?;
    let entry_count = to_usize(le_u32(bytes, 0x04)?);
    let version = bytes[0x08];
    let entry_version = bytes[0x09];
    let length = bytes[0x0A];
    if !matches!(version, VERSION_10 | VERSION_20 | VERSION_21) {
        return Err(error(format!(
            "Unsupported $FPT header version 0x{version:02X} at 0x{:X}",
            offset + 0x08
        )));
    }
    if entry_count > MAX_ENTRIES {
        return Err(error(format!(
            "Invalid $FPT entry count {entry_count} at 0x{:X}: at most {MAX_ENTRIES}",
            offset + 0x04
        )));
    }
    let checksum = match version {
        VERSION_21 => crc_status(data, offset, entry_count, false)?,
        _ => sum8_status(data, offset, length, entry_count)?,
    };
    Ok(Header {
        offset,
        entry_count,
        version,
        entry_version,
        length,
        redundant: version == VERSION_21 && bytes[0x0B] & FLAG_REDUNDANCY != 0,
        checksum,
    })
}

/// The 8-bit checksum of header versions 1.0 and 2.0: the header bytes
/// (with the ROM bypass vector when the header length includes it) sum to
/// 0. A 2.0 header whose sum is not 0 but whose CRC-32 matches is the 2.1
/// layout with a 2.0 version byte, which `MEAnalyzer` handles the same way.
fn sum8_status(data: &[u8], offset: usize, length: u8, entry_count: usize) -> Result<String> {
    let start = match length {
        HEADER_LENGTH => offset,
        HEADER_LENGTH_WITH_BYPASS if offset == ROM_BYPASS_SIZE => 0,
        _ => {
            return Err(error(format!(
                "Unsupported $FPT header length 0x{length:02X} at 0x{:X}",
                offset + 0x0A
            )))
        }
    };
    let covered = field(data, start, usize::from(length), "$FPT header")?;
    let sum = sum8(covered);
    if sum == 0 {
        return Ok(format!(
            "8-bit header checksum over 0x{start:X}-0x{:X} verified",
            start + covered.len() - 1
        ));
    }
    if data.get(offset + 0x08) == Some(&VERSION_20) {
        if let Ok(status) = crc_status(data, offset, entry_count, true) {
            return Ok(status);
        }
    }
    Err(error(format!(
        "Invalid $FPT header checksum at 0x{:X}: the header sums to 0x{sum:02X}, not 0",
        offset + 0x0B
    )))
}

/// The 2.1 CRC-32 (`MEA.py`): IEEE CRC-32 over the 32-byte header with the
/// CRC field zeroed, followed by every entry. `coreboot` and `UEFITool` do
/// not check it, and `MEAnalyzer` ignores a mismatch in extracted CSME 12+
/// images, which carry placeholder values. A mismatch is therefore a note
/// for a 2.1 header; `required` makes it an error, for a 2.0 header whose
/// 8-bit sum has already failed.
fn crc_status(data: &[u8], offset: usize, entry_count: usize, required: bool) -> Result<String> {
    let header = field(data, offset, HEADER_SIZE, "$FPT header")?;
    let entries = field(
        data,
        offset + HEADER_SIZE,
        entry_count * ENTRY_SIZE,
        "$FPT entry table",
    )?;
    let stored = le_u32(header, CRC_OFFSET)?;
    let mut crc = crc32_update(!0, &header[..CRC_OFFSET]);
    crc = crc32_update(crc, &[0; 4]);
    crc = crc32_update(crc, &header[CRC_OFFSET + 4..]);
    let computed = !crc32_update(crc, entries);
    match (computed == stored, required) {
        (true, false) => Ok("header and entry CRC-32 verified".to_string()),
        (true, true) => Ok(
            "header version 0x20 with the 2.1 layout: header and entry CRC-32 verified".to_string(),
        ),
        (false, false) => Ok(format!(
            "header CRC-32 0x{stored:08X} does not match the computed 0x{computed:08X}; not verified (extracted images carry placeholders)"
        )),
        (false, true) => Err(error("Invalid $FPT header CRC-32")),
    }
}

fn push_header_metadata(c: &mut Container<'_>, header: &Header) {
    c.push_metadata(
        format!("{KEY_PREFIX}_fpt_offset"),
        "$FPT offset",
        format!("0x{:X}", header.offset),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_fpt_header_version"),
        "$FPT header version",
        format!("0x{:02X}", header.version),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_fpt_entry_count"),
        "$FPT entries",
        header.entry_count as u64,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_fpt_checksum"),
        "$FPT checksum",
        header.checksum.clone(),
    );
}

/// One table entry: name (0x00), owner (0x04), offset from the start of
/// the image (0x08), length (0x0C), reserved (0x10), flags (0x1C).
#[derive(Debug)]
struct Entry {
    name: String,
    offset: usize,
    raw_offset: u32,
    length: usize,
    flags: u32,
}

impl Entry {
    fn read(entry: &[u8]) -> Result<Self> {
        let raw_offset = le_u32(entry, 0x08)?;
        Ok(Self {
            name: ascii_name(&entry[..4]),
            offset: to_usize(raw_offset),
            raw_offset,
            length: to_usize(le_u32(entry, 0x0C)?),
            flags: le_u32(entry, 0x1C)?,
        })
    }

    /// `cse_fpt.c` `is_partition_valid`, and the absent offset `UEFITool`
    /// also skips.
    fn is_valid(&self) -> bool {
        self.raw_offset != 0
            && self.raw_offset != OFFSET_ABSENT
            && self.length != 0
            && self.flags >> ENTRY_VALID_SHIFT != ENTRY_INVALID
    }

    fn kind(&self) -> u32 {
        self.flags & ENTRY_TYPE_MASK
    }

    fn kind_name(&self) -> String {
        match self.kind() {
            ENTRY_TYPE_CODE => "code".to_string(),
            ENTRY_TYPE_DATA => "data".to_string(),
            ENTRY_TYPE_NVRAM => "NVRAM".to_string(),
            other => format!("type 0x{other:02X}"),
        }
    }

    /// The partition's bytes, or `None` with a note when it overlaps the
    /// table or does not fit the image (`UEFITool` skips both).
    fn bytes<'a>(
        &self,
        data: &'a [u8],
        table_end: usize,
        c: &mut Container<'_>,
    ) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(self.length);
        if self.offset < table_end {
            c.notes.push(format!(
                "{} partition at 0x{:X} overlaps the partition table; not listed",
                self.name, self.offset
            ));
            return None;
        }
        if let Some(bytes) = end.and_then(|end| data.get(self.offset..end)) {
            return Some(bytes);
        }
        c.notes.push(format!(
            "{} partition 0x{:X} + {} B lies outside the {} B image; not listed",
            self.name,
            self.offset,
            self.length,
            data.len()
        ));
        None
    }
}

/// Notes and metadata for a code partition: its `$CPD` directory with the
/// module names and manifest, or a pre-CSE manifest at its start.
fn describe_code_partition(
    c: &mut Container<'_>,
    listing: &mut Listing,
    index: usize,
    partition: &Entry,
    bytes: &[u8],
) {
    if cpd::has_marker(bytes) {
        match cpd::describe(bytes) {
            Ok(directory) => {
                listing.note(
                    c,
                    format!("{} partition: {}", partition.name, directory.summary()),
                );
                directory.push_metadata(c, index);
            }
            Err(e) => c.notes.push(format!(
                "{} partition: $CPD not parsed ({})",
                partition.name,
                bare_message(e)
            )),
        }
    } else if bytes.get(MANIFEST_TAG_OFFSET..MANIFEST_TAG_OFFSET + 4) == Some(cpd::MANIFEST_TAG) {
        let version =
            cpd::manifest_version(bytes, 0).map_or_else(String::new, |v| format!(", version {v}"));
        listing.note(
            c,
            format!(
                "{} partition: $MN2 manifest at the partition start{version}; RSA signature present, not verified; module list not parsed",
                partition.name
            ),
        );
    }
}

/// The message of a family error without the family prefix.
fn bare_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::PcFirmwareParseError { message } => message,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_found_at_0x10_before_0() {
        let mut data = vec![0u8; 0x20];
        data[..4].copy_from_slice(MARKER);
        assert_eq!(marker_offset(&data), Some(0));
        data[0x10..0x14].copy_from_slice(MARKER);
        assert_eq!(marker_offset(&data), Some(0x10));
        assert_eq!(marker_offset(b"$FP"), None);
    }

    #[test]
    fn entry_validity_follows_cse_fpt() {
        let mut entry = [0u8; ENTRY_SIZE];
        entry[..4].copy_from_slice(b"FTPR");
        entry[0x08..0x0C].copy_from_slice(&0x1000u32.to_le_bytes());
        entry[0x0C..0x10].copy_from_slice(&0x2000u32.to_le_bytes());
        let valid = Entry::read(&entry).unwrap();
        assert!(valid.is_valid());
        assert_eq!(valid.kind_name(), "code");
        entry[0x1F] = 0xFF;
        assert!(!Entry::read(&entry).unwrap().is_valid());
        entry[0x1F] = 0;
        entry[0x08..0x0C].copy_from_slice(&OFFSET_ABSENT.to_le_bytes());
        assert!(!Entry::read(&entry).unwrap().is_valid());
    }
}
