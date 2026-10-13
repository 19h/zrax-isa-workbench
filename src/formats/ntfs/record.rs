//! MFT records ([LAYOUT] `NTFS_RECORD`, `MFT_RECORD`, `ATTR_RECORD`;
//! [NTFS-3G] `mst.c`, `ntfs_mft_record_check`, `ntfs_attr_inconsistent`;
//! [DOCS] `concepts/file_record.html`, `concepts/fixup.html`,
//! `concepts/attribute_header.html`): the update sequence fixups, the
//! record header, and the attribute records with their resident values or
//! non-resident headers.

use super::*;
use std::ops::Range;

/// Record magics ([LAYOUT] `NTFS_RECORD_TYPES`).
const FILE_MAGIC: &[u8; 4] = b"FILE";
const BAAD_MAGIC: &[u8; 4] = b"BAAD";

/// Each 512-byte stride of a record ends with the update sequence number
/// on disk ([LAYOUT] `NTFS_BLOCK_SIZE`).
const STRIDE: usize = 512;

/// The update sequence array must end before the last two bytes of the
/// first stride ([NTFS-3G] `is_valid_record`).
const USA_LIMIT: usize = STRIDE - 2;

/// Record flags ([LAYOUT] `MFT_RECORD_FLAGS`).
const RECORD_IN_USE: u16 = 0x0001;
const RECORD_IS_DIRECTORY: u16 = 0x0002;

/// An NTFS 3.1 header ends with `mft_record_number` at 44; its update
/// sequence array starts at 48 or later.
const NUMBERED_HEADER_SIZE: usize = 48;

/// MFT references: a 48-bit record number and a 16-bit sequence number
/// ([LAYOUT] `MK_MREF`).
const REFERENCE_RECORD_MASK: u64 = 0x0000_ffff_ffff_ffff;
const REFERENCE_SEQUENCE_SHIFT: u32 = 48;

/// Attribute records are 8-byte aligned ([LAYOUT] `ATTR_RECORD`).
const ATTRIBUTE_ALIGNMENT: usize = 8;

/// Header sizes of resident and non-resident attribute records
/// (`resident_end`, `non_resident_end`).
const RESIDENT_HEADER_SIZE: usize = 24;
const NON_RESIDENT_HEADER_SIZE: usize = 64;

/// The space an attribute type field takes, which is all the end marker
/// has ([NTFS-3G] `ntfs_mft_record_check`: "space < 4").
const TYPE_FIELD_SIZE: usize = 4;

/// A resident value length with any of these bits set is corrupt
/// ([NTFS-3G] `ntfs_attr_inconsistent`).
const VALUE_LENGTH_RESERVED: u32 = 0xff00_0000;

/// Fixed part of a `$FILE_NAME` value; the name follows at 0x42 ([LAYOUT]
/// `FILE_NAME_ATTR`).
const FILE_NAME_HEADER_SIZE: usize = 0x42;

/// `$STANDARD_INFORMATION` is at least the NTFS 1.2 layout of 48 bytes, and
/// `$VOLUME_INFORMATION` 12 bytes.
const STANDARD_INFORMATION_MIN_SIZE: usize = 48;
const VOLUME_INFORMATION_SIZE: usize = 12;

/// `file_name_type` of a DOS 8.3 name ([LAYOUT] `FILE_NAME_TYPE_FLAGS`).
pub(super) const FILE_NAME_DOS: u8 = 0x02;

/// A reference to an MFT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reference {
    /// Record number.
    pub(super) record: u64,
    /// Sequence number; 0 means "not checked".
    pub(super) sequence: u16,
}

impl Reference {
    pub(super) fn from_raw(raw: u64) -> Self {
        Self {
            record: raw & REFERENCE_RECORD_MASK,
            sequence: u16::try_from(raw >> REFERENCE_SEQUENCE_SHIFT).expect("16 bits"),
        }
    }

    /// Whether a record with sequence number `sequence` is the one this
    /// reference names ([LAYOUT] "If the sequence number is zero it is
    /// assumed that no sequence number consistency checking should be
    /// performed").
    pub(super) fn names(self, sequence: u16) -> bool {
        self.sequence == 0 || self.sequence == sequence
    }
}

/// Where record bytes are stored in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Piece {
    /// Offset in the record.
    pub(super) offset: usize,
    /// File offset.
    pub(super) file_offset: usize,
    /// Size in bytes.
    pub(super) len: usize,
}

/// The header fields of a non-resident attribute.
#[derive(Debug, Clone)]
pub(super) struct NonResident {
    /// `lowest_vcn`: the first cluster of the attribute this extent maps.
    pub(super) lowest_vcn: u64,
    /// `highest_vcn`; -1 for an empty attribute.
    pub(super) highest_vcn: i64,
    /// The mapping pairs array, as record offsets.
    pub(super) mapping_pairs: Range<usize>,
    /// `compression_unit`: log2 of the clusters in a compression unit.
    pub(super) compression_unit: u8,
    /// `allocated_size`, valid in the extent with `lowest_vcn` 0.
    pub(super) allocated_size: u64,
    /// `data_size`, valid in the extent with `lowest_vcn` 0.
    pub(super) data_size: u64,
    /// `initialized_size`, valid in the extent with `lowest_vcn` 0.
    pub(super) initialized_size: u64,
}

/// How an attribute's value is stored.
#[derive(Debug, Clone)]
pub(super) enum Form {
    /// In the record, at these record offsets.
    Resident(Range<usize>),
    /// In clusters that the mapping pairs locate.
    NonResident(NonResident),
}

/// An attribute record.
#[derive(Debug, Clone)]
pub(super) struct Attribute {
    /// Attribute type code.
    pub(super) kind: u32,
    /// Attribute name; empty when unnamed.
    pub(super) name: String,
    /// `flags`: compression method, encryption and sparseness.
    pub(super) flags: u16,
    /// `instance`, unique in its record.
    pub(super) instance: u16,
    pub(super) form: Form,
}

/// A parsed MFT record with its update sequence fixups applied.
#[derive(Debug)]
pub(super) struct Record {
    /// Record number.
    pub(super) number: u64,
    /// The record's bytes, fixed up.
    bytes: Vec<u8>,
    /// Where the bytes are stored, in record order.
    pieces: Vec<Piece>,
    /// `sequence_number`.
    pub(super) sequence: u16,
    /// `flags`.
    flags: u16,
    /// `base_mft_record`; record 0 for a base record.
    pub(super) base: Reference,
    /// Attribute records in record order.
    pub(super) attributes: Vec<Attribute>,
}

/// The error for record `number`.
fn record_error(number: u64, problem: impl std::fmt::Display) -> ClassifierError {
    error(format!("Invalid MFT record {number}: {problem}"))
}

/// What is wrong with an attribute record, before the record and type are
/// named.
type Problem<T> = std::result::Result<T, String>;

fn u16_field(record: &[u8], at: usize) -> Problem<u16> {
    le_u16(record, at).map_err(message)
}

fn u32_field(record: &[u8], at: usize) -> Problem<u32> {
    le_u32(record, at).map_err(message)
}

fn i64_field(record: &[u8], at: usize) -> Problem<i64> {
    le_i64(record, at).map_err(message)
}

/// Check and apply the update sequence fixups of a record that starts with
/// `FILE` ([NTFS-3G] `ntfs_mst_post_read_fixup_warn`).
fn apply_fixups(number: u64, bytes: &mut [u8]) -> Result<()> {
    let size = bytes.len();
    let usa_offset = usize::from(le_u16(bytes, 4)?);
    let usa_count = usize::from(le_u16(bytes, 6)?);
    let valid = size % STRIDE == 0
        && usa_offset % 2 == 0
        && usa_count == 1 + size / STRIDE
        && usa_offset + 2 * usa_count <= USA_LIMIT;
    if !valid {
        return Err(record_error(
            number,
            format!(
                "update sequence array at 0x{usa_offset:X} with {usa_count} entries does not fit \
                 a record of {size} B"
            ),
        ));
    }
    let usn = [bytes[usa_offset], bytes[usa_offset + 1]];
    for stride in 0..size / STRIDE {
        let tail = stride * STRIDE + STRIDE - 2;
        if bytes[tail..tail + 2] != usn {
            return Err(record_error(
                number,
                format!(
                    "stride {stride} does not end with the update sequence number (incomplete \
                     multi-sector transfer)"
                ),
            ));
        }
        let entry = usa_offset + 2 * (stride + 1);
        bytes.copy_within(entry..entry + 2, tail);
    }
    Ok(())
}

impl Record {
    /// The bytes of a `FILE` record with its fixups applied, for comparing
    /// copies.
    ///
    /// # Errors
    ///
    /// A record without the `FILE` magic, or invalid fixups.
    pub(super) fn fixed_up(number: u64, mut bytes: Vec<u8>) -> Result<Vec<u8>> {
        if bytes.get(..4) != Some(FILE_MAGIC.as_slice()) {
            return Err(record_error(number, "missing FILE magic"));
        }
        apply_fixups(number, &mut bytes)?;
        Ok(bytes)
    }

    /// Parse record `number` from its stored bytes, which `pieces` locate.
    /// `None` for a slot that holds no record (a zero magic).
    ///
    /// # Errors
    ///
    /// A `BAAD` or unknown magic, invalid fixups, or a header or attribute
    /// that ntfs-3g rejects.
    pub(super) fn parse(
        number: u64,
        mut bytes: Vec<u8>,
        pieces: Vec<Piece>,
    ) -> Result<Option<Self>> {
        match bytes.get(..4) {
            Some(magic) if magic == FILE_MAGIC => {}
            Some([0, 0, 0, 0]) => return Ok(None),
            Some(magic) if magic == BAAD_MAGIC => {
                return Err(record_error(
                    number,
                    "BAAD magic (a failed multi-sector transfer)",
                ))
            }
            _ => {
                return Err(record_error(
                    number,
                    format!("magic 0x{:08X} instead of FILE", le_u32(&bytes, 0)?),
                ))
            }
        }
        apply_fixups(number, &mut bytes)?;
        let flags = le_u16(&bytes, 22)?;
        if flags & RECORD_IN_USE == 0 {
            // A record not in use (never used, or deleted) keeps whatever it
            // held; nothing reads its attributes.
            return Ok(Some(Self {
                number,
                sequence: le_u16(&bytes, 16)?,
                base: Reference::from_raw(le_u64(&bytes, 32)?),
                bytes,
                pieces,
                flags,
                attributes: Vec::new(),
            }));
        }
        let header = header(number, &bytes)?;
        let attributes = attributes(number, &bytes, header.attributes_offset, header.in_use)?;
        Ok(Some(Self {
            number,
            bytes,
            pieces,
            sequence: header.sequence,
            flags: header.flags,
            base: header.base,
            attributes,
        }))
    }

    pub(super) fn is_in_use(&self) -> bool {
        self.flags & RECORD_IN_USE != 0
    }

    pub(super) fn is_directory(&self) -> bool {
        self.flags & RECORD_IS_DIRECTORY != 0
    }

    /// Whether this is a base record rather than an extension record of
    /// another file.
    pub(super) fn is_base(&self) -> bool {
        // An extension record of $MFT names record 0 with its sequence
        // number (1), so only a zero reference marks a base record.
        self.base.record == 0 && self.base.sequence == 0
    }

    /// The value of a resident attribute.
    pub(super) fn resident_value(&self, attribute: &Attribute) -> Option<&[u8]> {
        match &attribute.form {
            Form::Resident(range) => self.bytes.get(range.clone()),
            Form::NonResident(_) => None,
        }
    }

    /// The bytes of a non-resident attribute's mapping pairs array.
    pub(super) fn mapping_pairs(&self, attribute: &NonResident) -> &[u8] {
        &self.bytes[attribute.mapping_pairs.clone()]
    }

    /// The file offset of record byte `at`.
    pub(super) fn file_offset(&self, at: usize) -> Option<usize> {
        self.pieces
            .iter()
            .find(|piece| (piece.offset..piece.offset + piece.len).contains(&at))
            .map(|piece| piece.file_offset + (at - piece.offset))
    }

    /// The file offset of the record bytes `range` when the input stores
    /// them as they are: in one piece, and without a stride end, whose
    /// stored bytes are the update sequence number.
    pub(super) fn stored_offset(&self, range: &Range<usize>) -> Option<usize> {
        if range.is_empty() {
            return None;
        }
        let fixed = (range.start / STRIDE..=(range.end - 1) / STRIDE).any(|stride| {
            let tail = stride * STRIDE + STRIDE - 2;
            tail < range.end && tail + 2 > range.start
        });
        if fixed {
            return None;
        }
        let piece = self
            .pieces
            .iter()
            .find(|piece| piece.offset <= range.start && range.end <= piece.offset + piece.len)?;
        Some(piece.file_offset + (range.start - piece.offset))
    }
}

/// The record header fields the reader uses.
struct Header {
    sequence: u16,
    flags: u16,
    base: Reference,
    attributes_offset: usize,
    /// `bytes_in_use`.
    in_use: usize,
}

/// Check the record header ([NTFS-3G] `ntfs_mft_record_check`).
///
/// Layout: magic (4), `usa_ofs` (2), `usa_count` (2), `lsn` (8),
/// `sequence_number` (2) at 16, `link_count` (2), `attrs_offset` (2) at 20,
/// `flags` (2) at 22, `bytes_in_use` (4) at 24, `bytes_allocated` (4) at 28,
/// `base_mft_record` (8) at 32, `next_attr_instance` (2), reserved (2), and
/// in NTFS 3.1 `mft_record_number` (4) at 44.
fn header(number: u64, bytes: &[u8]) -> Result<Header> {
    let size = bytes.len();
    let allocated = le_u32(bytes, 28)? as usize;
    if allocated != size {
        return Err(record_error(
            number,
            format!("bytes_allocated {allocated} B instead of the record size {size} B"),
        ));
    }
    let in_use = le_u32(bytes, 24)? as usize;
    if in_use > size {
        return Err(record_error(
            number,
            format!("bytes_in_use {in_use} B exceeds the record size {size} B"),
        ));
    }
    let attributes_offset = usize::from(le_u16(bytes, 20)?);
    if attributes_offset % ATTRIBUTE_ALIGNMENT != 0 || attributes_offset >= in_use {
        return Err(record_error(
            number,
            format!("attributes offset 0x{attributes_offset:X}"),
        ));
    }
    // An NTFS 3.1 header records its own number; another number means the
    // MFT runlist led to the wrong record.
    if usize::from(le_u16(bytes, 4)?) >= NUMBERED_HEADER_SIZE {
        let stored = le_u32(bytes, 44)?;
        if u64::from(stored) != number & u64::from(u32::MAX) {
            return Err(record_error(number, format!("it is numbered {stored}")));
        }
    }
    Ok(Header {
        sequence: le_u16(bytes, 16)?,
        flags: le_u16(bytes, 22)?,
        base: Reference::from_raw(le_u64(bytes, 32)?),
        attributes_offset,
        in_use,
    })
}

/// The attribute records from `start` to the end marker, which must lie
/// within the `in_use` bytes; types must not decrease ([NTFS-3G]
/// `ntfs_mft_record_check`).
fn attributes(number: u64, bytes: &[u8], start: usize, in_use: usize) -> Result<Vec<Attribute>> {
    let mut attributes = Vec::new();
    let mut offset = start;
    let mut previous = AT_STANDARD_INFORMATION;
    loop {
        let space = in_use - offset;
        if space < TYPE_FIELD_SIZE {
            return Err(record_error(number, "missing end marker"));
        }
        let kind = le_u32(bytes, offset)?;
        if kind == AT_END {
            return Ok(attributes);
        }
        if space < RESIDENT_HEADER_SIZE || kind < previous {
            return Err(record_error(
                number,
                format!("attribute 0x{kind:X} at 0x{offset:X} is out of order or cut short"),
            ));
        }
        let length = le_u32(bytes, offset + 4)? as usize;
        if length > space || length % ATTRIBUTE_ALIGNMENT != 0 || length < RESIDENT_HEADER_SIZE {
            return Err(record_error(
                number,
                format!("attribute 0x{kind:X} at 0x{offset:X} has length {length} B"),
            ));
        }
        let record = &bytes[offset..offset + length];
        let attribute = attribute(record, offset)
            .map_err(|problem| record_error(number, format!("attribute 0x{kind:X} {problem}")))?;
        attributes.push(attribute);
        previous = kind;
        offset += length;
    }
}

/// Parse one attribute record, which starts at record offset `offset`
/// ([NTFS-3G] `ntfs_attr_inconsistent`).
///
/// Layout: type (4), length (4), `non_resident` (1) at 8, `name_length`
/// (1) at 9, `name_offset` (2) at 10, `flags` (2) at 12, `instance` (2) at
/// 14. Resident: `value_length` (4) at 16, `value_offset` (2) at 20.
/// Non-resident: `lowest_vcn` (8) at 16, `highest_vcn` (8) at 24,
/// `mapping_pairs_offset` (2) at 32, `compression_unit` (1) at 34,
/// `allocated_size` (8) at 40, `data_size` (8) at 48, `initialized_size`
/// (8) at 56.
fn attribute(record: &[u8], offset: usize) -> Problem<Attribute> {
    let kind = u32_field(record, 0)?;
    let length = record.len();
    let non_resident = record[8];
    let name_length = usize::from(record[9]);
    let name_offset = usize::from(u16_field(record, 10)?);
    let name_end = name_offset + 2 * name_length;
    if name_length > 0 && name_end > length {
        return Err(format!(
            "name at 0x{name_offset:X} passes the attribute's end"
        ));
    }
    let name = if name_length == 0 {
        String::new()
    } else {
        utf16_text(&record[name_offset..name_end])
    };
    let flags = u16_field(record, 12)?;
    let instance = u16_field(record, 14)?;
    let form = match non_resident {
        0 => Form::Resident(resident_value(record, offset)?),
        1 => Form::NonResident(non_resident_header(record, offset)?),
        other => return Err(format!("has non_resident {other}")),
    };
    check_known_type(kind, &form, record, offset)?;
    Ok(Attribute {
        kind,
        name,
        flags,
        instance,
        form,
    })
}

/// The record offsets of a resident attribute's value.
fn resident_value(record: &[u8], offset: usize) -> Problem<Range<usize>> {
    let value_length = u32_field(record, 16)?;
    let value_offset = usize::from(u16_field(record, 20)?);
    if value_length & VALUE_LENGTH_RESERVED != 0 {
        return Err(format!("has value length 0x{value_length:X}"));
    }
    let value_length = value_length as usize;
    let end = value_offset + value_length;
    if value_length > 0 && end > record.len() {
        return Err(format!(
            "value at 0x{value_offset:X} + {value_length} B passes the attribute's end"
        ));
    }
    if value_length == 0 {
        return Ok(offset..offset);
    }
    Ok(offset + value_offset..offset + end)
}

/// The header of a non-resident attribute, with its mapping pairs as record
/// offsets.
fn non_resident_header(record: &[u8], offset: usize) -> Problem<NonResident> {
    if record.len() < NON_RESIDENT_HEADER_SIZE {
        return Err(format!(
            "is non-resident in {} B, less than its {NON_RESIDENT_HEADER_SIZE} B header",
            record.len()
        ));
    }
    let lowest_vcn = i64_field(record, 16)?;
    let highest_vcn = i64_field(record, 24)?;
    let mapping_pairs_offset = usize::from(u16_field(record, 32)?);
    if mapping_pairs_offset >= record.len() || mapping_pairs_offset < NON_RESIDENT_HEADER_SIZE {
        return Err(format!(
            "has mapping pairs offset 0x{mapping_pairs_offset:X}"
        ));
    }
    // ntfs-3g compares the VCNs unsigned, so an empty attribute's
    // highest_vcn of -1 passes.
    if lowest_vcn < 0 || (highest_vcn < lowest_vcn && highest_vcn != -1) {
        return Err(format!("maps VCNs 0x{lowest_vcn:X} to 0x{highest_vcn:X}"));
    }
    let sizes = [
        i64_field(record, 40)?,
        i64_field(record, 48)?,
        i64_field(record, 56)?,
    ];
    if sizes.iter().any(|&size| size < 0) {
        return Err("has a negative size".to_string());
    }
    let [allocated_size, data_size, initialized_size] = sizes.map(i64::unsigned_abs);
    Ok(NonResident {
        lowest_vcn: lowest_vcn.unsigned_abs(),
        highest_vcn,
        mapping_pairs: offset + mapping_pairs_offset..offset + record.len(),
        compression_unit: record[34],
        allocated_size,
        data_size,
        initialized_size,
    })
}

/// The checks ntfs-3g applies to well-known attribute types.
fn check_known_type(kind: u32, form: &Form, record: &[u8], offset: usize) -> Problem<()> {
    let resident = match form {
        Form::Resident(range) => Some(range.clone()),
        Form::NonResident(_) => None,
    };
    let value = resident
        .as_ref()
        .map(|range| &record[range.start - offset..range.end - offset]);
    match kind {
        AT_FILE_NAME => {
            let value = value.ok_or("is not resident")?;
            let name_units = value.get(0x40).copied().map_or(0, usize::from);
            if value.len() < FILE_NAME_HEADER_SIZE
                || name_units == 0
                || FILE_NAME_HEADER_SIZE + 2 * name_units > value.len()
            {
                return Err(format!("holds a file name of {} B", value.len()));
            }
        }
        AT_STANDARD_INFORMATION => {
            let value = value.ok_or("is not resident")?;
            if value.len() < STANDARD_INFORMATION_MIN_SIZE {
                return Err(format!("holds {} B", value.len()));
            }
        }
        AT_VOLUME_NAME => {
            value.ok_or("is not resident")?;
        }
        AT_VOLUME_INFORMATION => {
            let value = value.ok_or("is not resident")?;
            if value.len() < VOLUME_INFORMATION_SIZE {
                return Err(format!("holds {} B", value.len()));
            }
        }
        AT_INDEX_ALLOCATION if resident.is_some() => {
            return Err("is resident".to_string());
        }
        _ => {}
    }
    Ok(())
}

/// A `$FILE_NAME` value ([LAYOUT] `FILE_NAME_ATTR`).
#[derive(Debug, Clone)]
pub(super) struct FileName {
    /// `parent_directory`.
    pub(super) parent: Reference,
    /// `file_name_type`: POSIX, Win32, DOS, or Win32 and DOS.
    pub(super) namespace: u8,
    /// The name.
    pub(super) name: String,
}

impl FileName {
    /// Read a `$FILE_NAME` value that [`Record::parse`] checked.
    ///
    /// Layout: `parent_directory` (8), four times (8 each), allocated and
    /// data size (8 each), `file_attributes` (4) at 0x38, EA size or reparse
    /// tag (4), `file_name_length` (1) at 0x40, `file_name_type` (1) at
    /// 0x41, the UTF-16LE name at 0x42.
    pub(super) fn read(value: &[u8]) -> Option<Self> {
        let units = usize::from(*value.get(0x40)?);
        let name = value.get(FILE_NAME_HEADER_SIZE..FILE_NAME_HEADER_SIZE + 2 * units)?;
        Some(Self {
            parent: Reference::from_raw(le_u64(value, 0).ok()?),
            namespace: *value.get(0x41)?,
            name: utf16_text(name),
        })
    }

    /// Whether this is a DOS 8.3 alias of another name.
    pub(super) fn is_dos_alias(&self) -> bool {
        self.namespace == FILE_NAME_DOS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1 KiB `FILE` record with the update sequence array at 0x30 (USN
    /// 0x0102) and the given last bytes of each stride.
    fn protected_record(tails: [[u8; 2]; 2]) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..4].copy_from_slice(FILE_MAGIC);
        bytes[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&3u16.to_le_bytes());
        bytes[0x30..0x36].copy_from_slice(&[0x02, 0x01, 0xaa, 0xbb, 0xcc, 0xdd]);
        bytes[510..512].copy_from_slice(&tails[0]);
        bytes[1022..1024].copy_from_slice(&tails[1]);
        bytes
    }

    #[test]
    fn fixups_restore_the_stride_ends_and_detect_torn_writes() {
        let fixed = Record::fixed_up(0, protected_record([[0x02, 0x01]; 2])).unwrap();
        assert_eq!(&fixed[510..512], &[0xaa, 0xbb]);
        assert_eq!(&fixed[1022..1024], &[0xcc, 0xdd]);
        let torn = Record::fixed_up(7, protected_record([[0x02, 0x01], [0x03, 0x01]]));
        assert_eq!(
            torn.unwrap_err().to_string(),
            "NTFS volume parse error: Invalid MFT record 7: stride 1 does not end with the \
             update sequence number (incomplete multi-sector transfer)"
        );
        let mut short_array = protected_record([[0x02, 0x01]; 2]);
        short_array[6..8].copy_from_slice(&2u16.to_le_bytes());
        assert!(Record::fixed_up(0, short_array).is_err());
    }

    #[test]
    fn references_split_record_and_sequence_numbers() {
        let reference = Reference::from_raw(0x0005_0000_0000_0005);
        assert_eq!(reference.record, 5);
        assert_eq!(reference.sequence, 5);
        assert!(reference.names(5));
        assert!(!reference.names(6));
        assert!(Reference::from_raw(42).names(9));
    }
}
