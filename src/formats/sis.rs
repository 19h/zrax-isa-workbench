//! Symbian OS v9 software installation packages (SIS files, `.sis` and
//! `.sisx`).
//!
//! A SIS 9 file is the 16-byte Symbian file header (UID1 `0x10201A7A`,
//! UID2, the package UID and a UID checksum) followed by one `SISContents`
//! field. Every structure is a `SISField`: a 32-bit type, a 31-bit length
//! (63-bit when bit 31 is set), the value, and zero padding to a 4-byte
//! boundary; inside a `SISArray` the type is left out. `SISContents` holds
//! the optional controller and data CRC-16s, the `SISController` with the
//! package metadata (usually zlib-compressed), and `SISData`, whose data
//! units hold the files, each in its own `SISCompressed`.
//!
//! Sources:
//! - "Symbian OS v9.X SIS File Format Specification" 1.1, June 2006
//!   (Symbian Software Ltd; SGL.GT0188.251): sections 2.5 and 2.11
//!   (embedding depth), 2.8 and 4.1.12 (data indices), 2.12 (`SISField`
//!   encoding and alignment), 3.1 (file header), 4.1-4.5 (structures) and
//!   Appendix A (field types).
//! - Symbian Foundation `appinstall` (EPL 1.0), commit
//!   `760927eba63e3324cceee974b9ed582da90cb9a3`: the device installer's
//!   reader in `installationservices/swi/source/sisfile/` (`sisparser.cpp`
//!   for the header and UID checksum, `sisfield.cpp` for lengths, padding
//!   and arrays, `siscontents.cpp`, `siscontroller.cpp`,
//!   `siscompressed.cpp`), the values in
//!   `installationservices/swi/inc/swi/sisfieldtypes.h` and
//!   `installtypes.h`, and `MakeSIS`'s library
//!   `secureswitools/swisistools/source/sisxlibrary/` (`fieldroot.cpp` for
//!   the CRC-16, `siscontents.cpp` for the UID checksum, `siscompressed.cpp`
//!   for the zlib streams).
//!
//! The package names no processor. Its files are children classified on
//! their own bytes (E32 executables by the EPOC parser) and listed only when
//! they are a recognized format. Offsets are file offsets, except inside
//! the decoded `SISController`, whose errors name controller offsets. The
//! pre-v9 EPOC SIS format is not implemented: no Symbian specification of
//! it was found (see `docs/sis.md`).

use crate::error::{ClassifierError, Result};
use crate::formats::checksum;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::Container;
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt;

mod controller;
mod data;

use controller::Controller;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "sis";

/// UID1 of every SIS 9 file (specification section 3.1.1; `MakeSIS`
/// `KUidSISXApp`).
const SISX_UID1: u32 = 0x1020_1A7A;

/// The Symbian file header: UID1, UID2, UID3 and the UID checksum, 4 bytes
/// each (section 3.1).
const HEADER_SIZE: usize = 16;

/// Bytes of the UIDs the UID checksum covers.
const UIDS_SIZE: usize = 12;

/// Fields are padded with zero bytes to 4-byte boundaries (section 2.12.2).
const ALIGNMENT: usize = 4;

/// Bit 31 of a field's first length word: the length is 63 bits wide and
/// a second word follows (section 2.12.1.2).
const LONG_LENGTH: u32 = 0x8000_0000;

/// `TCompressionAlgorithm`: stored as-is.
const COMPRESS_NONE: u32 = 0;
/// `TCompressionAlgorithm`: deflate. The specification cites RFC 1951, but
/// `MakeSIS` writes zlib streams (`deflateInit`, RFC 1950), which the
/// installer inflates with `CEZDecompressor`; the sample packages' streams
/// carry the zlib header.
const COMPRESS_DEFLATE: u32 = 1;

/// Characters of a `SISString` kept for labels, notes and metadata. Our
/// bound; it covers a full Symbian path.
const MAX_TEXT: usize = 256;

/// Names shown in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// A SIS layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Symbian OS v9 package: UID1 `0x10201A7A` and a `SISContents` field
    /// at offset 0x10.
    Sis9,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Sis9 => FileFormat::SymbianSis,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sis9 => "Symbian OS v9 SIS package",
        }
    }

    /// Recognized from complete structure rather than a magic value.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Sis9 => false,
        }
    }
}

/// Strong recognition: UID1 `0x10201A7A` and the `SISContents` field type
/// (12) right after the 16-byte header. A damaged package is then reported
/// as a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let uid1 = le_u32(data, 0)?;
    let first_field = le_u32(data, HEADER_SIZE)?;
    (uid1 == SISX_UID1 && FieldType(first_field) == FieldType::CONTENTS).then_some(Layout::Sis9)
}

/// Parse a SIS package into the shared container model: package notes and
/// metadata, and one child per stored file in a recognized format.
///
/// # Errors
///
/// [`ClassifierError::SisParseError`] for a wrong UID1 or UID checksum, a
/// truncated or inconsistent `SISField`, a controller that does not decode,
/// a structure member of the wrong type, embedding deeper than the
/// installer allows, or data after `SISContents` that is not padding.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Sis9 => parse_package(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::SisParseError {
        message: message.into(),
    }
}

/// Little-endian 32-bit word at `at`, if present.
fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Round `value` up to the next 4-byte boundary.
fn align4(value: usize) -> Option<usize> {
    value
        .checked_add(ALIGNMENT - 1)
        .map(|value| value & !(ALIGNMENT - 1))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// `n` followed by the singular or plural noun, for notes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Names for a note: the first [`NOTE_NAMES`] are kept and the rest only
/// counted, so a note stays small for any package.
#[derive(Debug, Default)]
struct NameList {
    shown: Vec<String>,
    total: usize,
}

impl NameList {
    fn push(&mut self, name: impl Into<String>) {
        if self.shown.len() < NOTE_NAMES {
            self.shown.push(name.into());
        }
        self.total += 1;
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl fmt::Display for NameList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.shown.join(", "))?;
        let hidden = self.total - self.shown.len();
        if hidden > 0 {
            write!(f, " and {hidden} more")?;
        }
        Ok(())
    }
}

/// A `SISField` type value (specification Appendix A; `TFieldType` in
/// `sisfieldtypes.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldType(u32);

impl FieldType {
    const STRING: Self = Self(1);
    const ARRAY: Self = Self(2);
    const COMPRESSED: Self = Self(3);
    const VERSION: Self = Self(4);
    const DATE: Self = Self(6);
    const TIME: Self = Self(7);
    const DATE_TIME: Self = Self(8);
    const UID: Self = Self(9);
    const LANGUAGE: Self = Self(11);
    const CONTENTS: Self = Self(12);
    const CONTROLLER: Self = Self(13);
    const INFO: Self = Self(14);
    const SUPPORTED_LANGUAGES: Self = Self(15);
    const SUPPORTED_OPTIONS: Self = Self(16);
    const PREREQUISITES: Self = Self(17);
    const PROPERTIES: Self = Self(19);
    const LOGO: Self = Self(23);
    const FILE_DESCRIPTION: Self = Self(24);
    const HASH: Self = Self(25);
    const IF: Self = Self(26);
    const ELSE_IF: Self = Self(27);
    const INSTALL_BLOCK: Self = Self(28);
    const EXPRESSION: Self = Self(29);
    const DATA: Self = Self(30);
    const DATA_UNIT: Self = Self(31);
    const FILE_DATA: Self = Self(32);
    const CONTROLLER_CHECKSUM: Self = Self(34);
    const DATA_CHECKSUM: Self = Self(35);
    const BLOB: Self = Self(37);
    const SIGNATURE_CERTIFICATE_CHAIN: Self = Self(39);
    const DATA_INDEX: Self = Self(40);
    const CAPABILITIES: Self = Self(41);

    /// The specification's name for the types this parser reads.
    fn name(self) -> &'static str {
        match self {
            Self::STRING => "SISString",
            Self::ARRAY => "SISArray",
            Self::COMPRESSED => "SISCompressed",
            Self::VERSION => "SISVersion",
            Self::DATE => "SISDate",
            Self::TIME => "SISTime",
            Self::DATE_TIME => "SISDateTime",
            Self::UID => "SISUid",
            Self::LANGUAGE => "SISLanguage",
            Self::CONTENTS => "SISContents",
            Self::CONTROLLER => "SISController",
            Self::INFO => "SISInfo",
            Self::SUPPORTED_LANGUAGES => "SISSupportedLanguages",
            Self::SUPPORTED_OPTIONS => "SISSupportedOptions",
            Self::PREREQUISITES => "SISPrerequisites",
            Self::PROPERTIES => "SISProperties",
            Self::LOGO => "SISLogo",
            Self::FILE_DESCRIPTION => "SISFileDescription",
            Self::HASH => "SISHash",
            Self::IF => "SISIf",
            Self::ELSE_IF => "SISElseIf",
            Self::INSTALL_BLOCK => "SISInstallBlock",
            Self::EXPRESSION => "SISExpression",
            Self::DATA => "SISData",
            Self::DATA_UNIT => "SISDataUnit",
            Self::FILE_DATA => "SISFileData",
            Self::CONTROLLER_CHECKSUM => "SISControllerChecksum",
            Self::DATA_CHECKSUM => "SISDataChecksum",
            Self::BLOB => "SISBlob",
            Self::SIGNATURE_CERTIFICATE_CHAIN => "SISSignatureCertificateChain",
            Self::DATA_INDEX => "SISDataIndex",
            Self::CAPABILITIES => "SISCapabilities",
            _ => "SISField",
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

/// The coordinate system of a buffer's offsets, for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Space {
    /// Offsets in the input file.
    File,
    /// Offsets in the decoded `SISController`.
    Controller,
}

/// Bytes that hold `SISField`s, with the coordinate system of their
/// offsets.
#[derive(Debug, Clone, Copy)]
struct Buffer<'a> {
    bytes: &'a [u8],
    space: Space,
}

/// How a field's type is stored.
#[derive(Debug, Clone, Copy)]
enum Header {
    /// With its type, which must be the given one.
    Typed(FieldType),
    /// Without its type, as an element of a `SISArray` of that type.
    InArray(FieldType),
}

/// One `SISField`, in the coordinates of the buffer it was read from.
#[derive(Debug, Clone, Copy)]
struct Field<'a> {
    kind: FieldType,
    /// Offset of the first header byte (the type, or the length inside a
    /// `SISArray`).
    start: usize,
    /// The header and value, without the padding.
    raw: &'a [u8],
    /// Offset of the value.
    value_start: usize,
    /// The value.
    value: &'a [u8],
    /// Offset after the padding. It may lie up to 3 bytes past the
    /// enclosing value, which the next read then rejects.
    end: usize,
}

impl Field<'_> {
    /// Offset after the value.
    fn value_end(&self) -> usize {
        self.value_start + self.value.len()
    }
}

impl<'a> Buffer<'a> {
    fn file(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            space: Space::File,
        }
    }

    fn controller(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            space: Space::Controller,
        }
    }

    /// `offset` in this buffer's coordinates, for messages.
    fn at(self, offset: usize) -> String {
        match self.space {
            Space::File => format!("0x{offset:X}"),
            Space::Controller => format!("controller offset 0x{offset:X}"),
        }
    }

    /// The `len` bytes at `offset`, which must end at or before `limit`.
    fn bytes_at(self, offset: usize, len: usize, limit: usize, what: &str) -> Result<&'a [u8]> {
        offset
            .checked_add(len)
            .filter(|end| *end <= limit)
            .and_then(|end| self.bytes.get(offset..end))
            .ok_or_else(|| error(format!("Truncated {what} at {}", self.at(offset))))
    }

    /// Little-endian 32-bit word at `offset`, before `limit`.
    fn word(self, offset: usize, limit: usize, what: &str) -> Result<u32> {
        let bytes = self.bytes_at(offset, 4, limit, what)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("bytes_at returns exactly 4 bytes"),
        ))
    }

    /// The type word of the field at `offset`, without reading the field.
    fn kind_at(self, offset: usize, limit: usize, what: &str) -> Result<FieldType> {
        self.word(offset, limit, what).map(FieldType)
    }

    /// The field at `offset`, whose value must end at or before `limit`.
    /// A typed field of another type is reported as missing.
    fn field(self, offset: usize, limit: usize, header: Header) -> Result<Field<'a>> {
        let (kind, length_at) = match header {
            Header::Typed(expected) => {
                let found = self.kind_at(offset, limit, expected.name())?;
                if found != expected {
                    return Err(error(format!(
                        "Missing {} at {} (field type {})",
                        expected.name(),
                        self.at(offset),
                        found.0
                    )));
                }
                (expected, offset + 4)
            }
            Header::InArray(kind) => (kind, offset),
        };
        let first = self.word(length_at, limit, kind.name())?;
        let (length, value_start) = if first & LONG_LENGTH == 0 {
            (u64::from(first), length_at + 4)
        } else {
            // The 63-bit form: bit 0 of the high word is bit 31 of the
            // length (`CField::ReadLengthL`).
            let high = self.word(length_at + 4, limit, kind.name())?;
            let low = u64::from(first & !LONG_LENGTH) | (u64::from(high & 1) << 31);
            ((u64::from(high >> 1) << 32) | low, length_at + 8)
        };
        let value_end = usize::try_from(length)
            .ok()
            .and_then(|length| value_start.checked_add(length))
            .filter(|end| *end <= limit && *end <= self.bytes.len());
        let Some(value_end) = value_end else {
            return Err(if limit == self.bytes.len() {
                error(format!(
                    "Truncated {} at {}: {length} B value, {} B left",
                    kind.name(),
                    self.at(offset),
                    limit.saturating_sub(value_start)
                ))
            } else {
                error(format!(
                    "Invalid {} length {length} B at {}: exceeds its enclosing field",
                    kind.name(),
                    self.at(offset)
                ))
            });
        };
        let end = align4(value_end).ok_or_else(|| error("Field range overflow"))?;
        Ok(Field {
            kind,
            start: offset,
            raw: &self.bytes[offset..value_end],
            value_start,
            value: &self.bytes[value_start..value_end],
            end,
        })
    }
}

/// Reads the members of one structure's value in order. Members after the
/// ones a reader asks for are unknown extensions and are skipped, as the
/// installer does (specification section 2.3).
#[derive(Debug)]
struct Members<'a> {
    buffer: Buffer<'a>,
    pos: usize,
    end: usize,
}

impl<'a> Members<'a> {
    /// The members of `field`'s value.
    fn of(buffer: Buffer<'a>, field: &Field<'a>) -> Self {
        Self {
            buffer,
            pos: field.value_start,
            end: field.value_end(),
        }
    }

    /// The next member, which must be a field of type `kind`.
    fn field(&mut self, kind: FieldType) -> Result<Field<'a>> {
        let field = self.buffer.field(self.pos, self.end, Header::Typed(kind))?;
        self.pos = field.end;
        Ok(field)
    }

    /// The next member if it is a field of type `kind`. At the end of the
    /// value there is none; the next mandatory member then reports the
    /// truncation.
    fn optional(&mut self, kind: FieldType) -> Result<Option<Field<'a>>> {
        match self.buffer.kind_at(self.pos, self.end, kind.name()) {
            Ok(found) if found == kind => self.field(kind).map(Some),
            _ => Ok(None),
        }
    }

    /// The next member, a `SISArray` of `element` fields: the elements,
    /// each stored without its type.
    fn array(&mut self, element: FieldType) -> Result<Vec<Field<'a>>> {
        let array = self.field(FieldType::ARRAY)?;
        let mut items = Members::of(self.buffer, &array);
        let stored = FieldType(items.u32("SISArray element type")?);
        if stored != element {
            return Err(error(format!(
                "Invalid SISArray element type {} at {}; expected {element}",
                stored.0,
                self.buffer.at(array.start)
            )));
        }
        let mut elements = Vec::new();
        while items.pos < items.end {
            let field = self
                .buffer
                .field(items.pos, items.end, Header::InArray(element))?;
            // The installer requires the elements, padding included, to
            // fill the array exactly (`KErrSISArrayReadError`).
            if field.end > items.end {
                return Err(error(format!(
                    "Invalid SISArray at {}: the {} at {} runs past the array",
                    self.buffer.at(array.start),
                    element.name(),
                    self.buffer.at(field.start)
                )));
            }
            items.pos = field.end;
            elements.push(field);
        }
        Ok(elements)
    }

    /// The next `len` bytes.
    fn bytes(&mut self, len: usize, what: &str) -> Result<&'a [u8]> {
        let bytes = self.buffer.bytes_at(self.pos, len, self.end, what)?;
        self.pos += len;
        Ok(bytes)
    }

    fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.bytes(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> Result<u16> {
        let bytes = self.bytes(2, what)?;
        Ok(u16::from_le_bytes(
            bytes.try_into().expect("bytes returns exactly 2 bytes"),
        ))
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        let bytes = self.bytes(4, what)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("bytes returns exactly 4 bytes"),
        ))
    }

    fn u64(&mut self, what: &str) -> Result<u64> {
        let bytes = self.bytes(8, what)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("bytes returns exactly 8 bytes"),
        ))
    }

    /// The rest of the value after the members read so far.
    fn rest(&self) -> &'a [u8] {
        self.buffer
            .bytes
            .get(self.pos..self.end)
            .unwrap_or_default()
    }
}

/// A `SISString` holds 16-bit characters, so its length is even (the
/// installer's `KErrSISInvalidStringLength`).
fn check_string(buffer: Buffer<'_>, field: &Field<'_>) -> Result<()> {
    if field.value.len() % 2 != 0 {
        return Err(error(format!(
            "Invalid SISString at {}: odd length {} B",
            buffer.at(field.start),
            field.value.len()
        )));
    }
    Ok(())
}

/// The text of a `SISString`: UCS-2 little-endian (section 4.1.1), of which
/// at most [`MAX_TEXT`] characters are kept.
fn text(buffer: Buffer<'_>, field: &Field<'_>) -> Result<String> {
    check_string(buffer, field)?;
    let units = field
        .value
        .chunks_exact(2)
        .take(MAX_TEXT)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let mut text: String = char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if field.value.len() / 2 > MAX_TEXT {
        text.push('\u{2026}');
    }
    Ok(text)
}

/// A `SISCompressed` value: the algorithm (u32), the declared uncompressed
/// size (u64) and the stored bytes (section 4.1.3).
#[derive(Debug, Clone, Copy)]
struct Compressed<'a> {
    /// Offset of the `SISCompressed` field.
    start: usize,
    algorithm: u32,
    /// Declared size of the data after decompression, in bytes.
    uncompressed_size: u64,
    /// Offset of the stored bytes.
    offset: usize,
    /// The stored (possibly compressed) bytes.
    bytes: &'a [u8],
}

impl<'a> Compressed<'a> {
    fn read(buffer: Buffer<'a>, field: &Field<'a>) -> Result<Self> {
        let mut members = Members::of(buffer, field);
        let algorithm = members.u32("SISCompressed algorithm")?;
        let uncompressed_size = members.u64("SISCompressed uncompressed size")?;
        Ok(Self {
            start: field.start,
            algorithm,
            uncompressed_size,
            offset: members.pos,
            bytes: members.rest(),
        })
    }
}

/// A checksum field compared with the CRC-16 of the field it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crc {
    /// The optional checksum field is not present.
    Absent,
    /// The stored value equals the computed CRC.
    Matches(u16),
    /// The stored value differs from the computed CRC.
    Differs { stored: u16, computed: u16 },
    /// Present but not computed: the covered field exceeds [`MAX_PAYLOAD`].
    Unchecked(u16),
}

impl Crc {
    /// Compare `stored` with the CRC-16 of `covered`.
    fn check(stored: Option<u16>, covered: &Field<'_>) -> Self {
        let Some(stored) = stored else {
            return Self::Absent;
        };
        if covered.raw.len() > MAX_PAYLOAD {
            return Self::Unchecked(stored);
        }
        let computed = field_crc(covered);
        if computed == stored {
            Self::Matches(stored)
        } else {
            Self::Differs { stored, computed }
        }
    }

    /// The check's result for `name`, for a note.
    fn describe(self, name: &str) -> String {
        match self {
            Self::Absent => format!("no {name} CRC-16"),
            Self::Matches(value) => format!("{name} CRC-16 0x{value:04X} matches"),
            Self::Differs { stored, computed } => {
                format!("{name} CRC-16 0x{stored:04X} does not match the computed 0x{computed:04X}")
            }
            Self::Unchecked(value) => format!(
                "{name} CRC-16 0x{value:04X} not verified (the field exceeds {} MiB)",
                MAX_PAYLOAD >> 20
            ),
        }
    }

    /// The check's result for metadata.
    fn metadata(self) -> String {
        match self {
            Self::Absent => "absent".to_string(),
            Self::Matches(value) => format!("0x{value:04X} (matches)"),
            Self::Differs { stored, computed } => {
                format!("0x{stored:04X} (computed 0x{computed:04X})")
            }
            Self::Unchecked(value) => format!("0x{value:04X} (not verified)"),
        }
    }
}

/// The CRC-16 that `SISControllerChecksum` and `SISDataChecksum` hold: the
/// whole field, header through zero padding (sections 4.2.2-4.2.3;
/// `MakeSIS` `CStructure::CalculateCrc` and `PaddingCrc`). `MakeSIS` calls it
/// the `ZModem` CRC-16: polynomial 0x1021, initial value 0, no reflection and
/// no final XOR (`DoTheCrc`), which is the CRC-16/IBM-3740 register
/// started at 0.
fn field_crc(field: &Field<'_>) -> u16 {
    let padding = [0u8; ALIGNMENT];
    let padding_len = (ALIGNMENT - field.raw.len() % ALIGNMENT) % ALIGNMENT;
    let crc = checksum::crc16_ibm3740_update(0, field.raw);
    checksum::crc16_ibm3740_update(crc, &padding[..padding_len])
}

/// The UID checksum of the header: the CRC-16 of the UIDs' odd bytes in the
/// high half and of their even bytes in the low half (`Parser::CheckUidCrc`
/// with `Mem::Crc`; `MakeSIS` `CSISContents::UidChecksum`).
fn uid_checksum(uids: &[u8; UIDS_SIZE]) -> u32 {
    let even: [u8; UIDS_SIZE / 2] = std::array::from_fn(|i| uids[2 * i]);
    let odd: [u8; UIDS_SIZE / 2] = std::array::from_fn(|i| uids[2 * i + 1]);
    let low = checksum::crc16_ibm3740_update(0, &even);
    let high = checksum::crc16_ibm3740_update(0, &odd);
    (u32::from(high) << 16) | u32::from(low)
}

/// The Symbian file header (section 3.1).
#[derive(Debug, Clone, Copy)]
struct FileHeader {
    /// Reserved; `MakeSIS` writes 0.
    uid2: u32,
    /// The package UID.
    uid3: u32,
}

impl FileHeader {
    /// Read the header (UID1 at 0, UID2 at 4, UID3 at 8, the UID checksum
    /// at 0xC, all little-endian) and check UID1 and the UID checksum, which
    /// the installer rejects when it does not match (`KErrCorrupt`).
    fn read(data: &[u8]) -> Result<Self> {
        let header = Buffer::file(data).bytes_at(0, HEADER_SIZE, data.len(), "file header")?;
        let word = |at: usize| le_u32(header, at).expect("header holds four words");
        let uid1 = word(0);
        if uid1 != SISX_UID1 {
            return Err(error(format!(
                "Invalid UID1 0x{uid1:08X}; expected 0x{SISX_UID1:08X}"
            )));
        }
        let uids: &[u8; UIDS_SIZE] = header[..UIDS_SIZE]
            .try_into()
            .expect("header holds the three UIDs");
        let stored = word(UIDS_SIZE);
        let computed = uid_checksum(uids);
        if stored != computed {
            return Err(error(format!(
                "Invalid UID checksum 0x{stored:08X} at 0xC; computed 0x{computed:08X}"
            )));
        }
        Ok(Self {
            uid2: word(4),
            uid3: word(8),
        })
    }
}

/// The members of `SISContents` (section 4.2.1).
#[derive(Debug)]
struct Contents<'a> {
    /// The whole `SISContents` field.
    field: Field<'a>,
    controller_crc: Option<u16>,
    data_crc: Option<u16>,
    /// The `SISCompressed<SISController>` field.
    controller: Field<'a>,
    /// The `SISData` field.
    data: Field<'a>,
    /// Bytes of unknown fields after `SISData`.
    unknown: usize,
}

impl<'a> Contents<'a> {
    /// The checksums, controller and data in the order the installer reads
    /// them (`CContents::ConstructL`); both checksums are optional.
    fn read(file: Buffer<'a>) -> Result<Self> {
        let field = file.field(
            HEADER_SIZE,
            file.bytes.len(),
            Header::Typed(FieldType::CONTENTS),
        )?;
        let mut members = Members::of(file, &field);
        let controller_crc = members
            .optional(FieldType::CONTROLLER_CHECKSUM)?
            .map(|checksum| crc_value(file, &checksum))
            .transpose()?;
        let data_crc = members
            .optional(FieldType::DATA_CHECKSUM)?
            .map(|checksum| crc_value(file, &checksum))
            .transpose()?;
        let controller = members.field(FieldType::COMPRESSED)?;
        let data = members.field(FieldType::DATA)?;
        Ok(Self {
            field,
            controller_crc,
            data_crc,
            controller,
            data,
            unknown: members.rest().len(),
        })
    }
}

/// The 16-bit checksum a `SISControllerChecksum` or `SISDataChecksum`
/// holds.
fn crc_value(buffer: Buffer<'_>, field: &Field<'_>) -> Result<u16> {
    Members::of(buffer, field).u16(field.kind.name())
}

/// A codec error's own message, without the compressed-stream prefix.
fn codec_message(e: &ClassifierError) -> String {
    match e {
        ClassifierError::CompressedParseError { message } => message.clone(),
        other => other.to_string(),
    }
}

/// The decoded `SISController` bytes, which start with the controller's
/// own field header.
fn decode_controller<'a>(stored: &Compressed<'a>) -> Result<Cow<'a, [u8]>> {
    let at = format!("0x{:X}", stored.start);
    let size = usize::try_from(stored.uncompressed_size)
        .ok()
        .filter(|size| *size <= MAX_PAYLOAD)
        .ok_or_else(|| {
            error(format!(
                "Unsupported SISController size {} B at {at}: exceeds {} MiB",
                stored.uncompressed_size,
                MAX_PAYLOAD >> 20
            ))
        })?;
    let decoded = match stored.algorithm {
        COMPRESS_NONE => Cow::Borrowed(stored.bytes),
        COMPRESS_DEFLATE => Cow::Owned(
            compressed::decode_limited(Codec::Zlib, stored.bytes, size)
                .map_err(|e| {
                    error(format!(
                        "Invalid SISController zlib stream at {at}: {}",
                        codec_message(&e)
                    ))
                })?
                .data,
        ),
        other => {
            return Err(error(format!(
                "Unsupported SISCompressed algorithm {other} for the SISController at {at}"
            )))
        }
    };
    // The installer reads exactly the declared size and requires an
    // uncompressed field to store exactly that many bytes
    // (`CCompressed::DataProviderL`, `ReadControllerDataL`).
    if decoded.len() != size {
        return Err(error(format!(
            "Invalid SISCompressed at {at}: the SISController is {} B, the header says {size} B",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn parse_package(data: &[u8]) -> Result<Container<'_>> {
    let header = FileHeader::read(data)?;
    let file = Buffer::file(data);
    let contents = Contents::read(file)?;
    let stored_controller = Compressed::read(file, &contents.controller)?;
    let controller_bytes = decode_controller(&stored_controller)?;
    let package = controller::parse(&controller_bytes)?;
    let units = data::units(file, &contents.data)?;
    let consumed = contents.field.end.min(data.len());
    let trailing = &data[consumed..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} B after SISContents at 0x{consumed:X}",
            trailing.len()
        )));
    }

    let mut c = Container::new(FileFormat::SymbianSis, Layout::Sis9.label(), KEY_PREFIX);
    c.consumed = consumed;
    let summary = data::extract(&mut c, &units, &package);
    let checks = Checks {
        header,
        controller_crc: Crc::check(contents.controller_crc, &contents.controller),
        data_crc: Crc::check(contents.data_crc, &contents.data),
        controller_algorithm: stored_controller.algorithm,
    };
    push_notes(&mut c, &package, &units, &summary, &checks);
    if contents.unknown > 0 {
        c.notes.push(format!(
            "{} B of unknown fields after SISData were skipped",
            contents.unknown
        ));
    }
    if !trailing.is_empty() {
        c.notes
            .push(format!("{} B of padding after SISContents", trailing.len()));
    }
    push_metadata(&mut c, &package, &units, &summary, &checks);
    Ok(c)
}

/// What the parser checked outside the controller.
#[derive(Debug, Clone, Copy)]
struct Checks {
    header: FileHeader,
    controller_crc: Crc,
    data_crc: Crc,
    controller_algorithm: u32,
}

/// Package, file, signature and integrity notes, most important first.
fn push_notes(
    c: &mut Container<'_>,
    package: &Controller,
    units: &[data::DataUnit<'_>],
    summary: &data::Summary,
    checks: &Checks,
) {
    let info = &package.info;
    c.notes.push(format!(
        "Package \"{}\"; UID 0x{:08X}; version {}; vendor \"{}\"",
        info.name.as_deref().unwrap_or_default(),
        info.uid,
        info.version,
        info.unique_vendor
    ));
    c.notes.push(format!(
        "Install type {}; flags 0x{:02X}; {}",
        info.install_type_text(),
        info.install_flags,
        count(package.languages, "language", "languages")
    ));
    if checks.header.uid3 != info.uid {
        c.notes.push(format!(
            "Header UID3 0x{:08X} differs from the package UID 0x{:08X}",
            checks.header.uid3, info.uid
        ));
    }
    c.notes.push(
        "SIS packages name no processor; each listed file is classified from its own bytes"
            .to_string(),
    );
    summary.push_notes(c, units.len());
    if !package.embedded.is_empty() {
        c.notes.push(format!(
            "Embedded packages: {}",
            controller::embedded_names(package)
        ));
    }
    let chains = package.signature_chains;
    if chains == 0 {
        c.notes
            .push("Unsigned: the SISController has no SISSignatureCertificateChain".to_string());
    } else {
        c.notes.push(format!(
            "{} present; signatures and certificates are not verified",
            count(
                chains,
                "signature certificate chain",
                "signature certificate chains"
            )
        ));
    }
    let crcs = format!(
        "{}; {}",
        checks.controller_crc.describe("controller"),
        checks.data_crc.describe("data")
    );
    let mut crcs = capitalized(&crcs);
    if matches!(checks.controller_crc, Crc::Differs { .. })
        || matches!(checks.data_crc, Crc::Differs { .. })
    {
        crcs.push_str("; the installer does not check these CRCs");
    }
    c.notes.push(crcs);
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Package identity, structure counts and checks as `sis_` metadata.
fn push_metadata(
    c: &mut Container<'_>,
    package: &Controller,
    units: &[data::DataUnit<'_>],
    summary: &data::Summary,
    checks: &Checks,
) {
    let info = &package.info;
    c.push_metadata(
        "sis_package_uid",
        "Package UID",
        format!("0x{:08X}", info.uid),
    );
    if let Some(name) = &info.name {
        c.push_metadata("sis_package_name", "Package name", name.clone());
    }
    c.push_metadata(
        "sis_vendor",
        "Vendor (unique name)",
        info.unique_vendor.clone(),
    );
    if let Some(vendor) = &info.vendor_name {
        c.push_metadata("sis_vendor_name", "Vendor name", vendor.clone());
    }
    c.push_metadata("sis_version", "Package version", info.version.to_string());
    c.push_metadata("sis_install_type", "Install type", info.install_type_text());
    c.push_metadata(
        "sis_install_flags",
        "Install flags",
        format!("0x{:02X}", info.install_flags),
    );
    c.push_metadata(
        "sis_creation_time",
        "Creation time (not authenticated)",
        info.created.to_string(),
    );
    c.push_metadata(
        "sis_languages",
        "Supported languages",
        package.languages as u64,
    );
    c.push_metadata(
        "sis_header_uid2",
        "Header UID2 (reserved)",
        format!("0x{:08X}", checks.header.uid2),
    );
    c.push_metadata(
        "sis_controller_compression",
        "Controller compression",
        match checks.controller_algorithm {
            COMPRESS_DEFLATE => "zlib",
            _ => "none",
        },
    );
    c.push_metadata(
        "sis_controller_crc",
        "Controller CRC-16",
        checks.controller_crc.metadata(),
    );
    c.push_metadata("sis_data_crc", "Data CRC-16", checks.data_crc.metadata());
    c.push_metadata(
        "sis_signature_chains",
        "Signature certificate chains (not verified)",
        package.signature_chains as u64,
    );
    c.push_metadata(
        "sis_file_descriptions",
        "File descriptions",
        controller::description_count(package) as u64,
    );
    c.push_metadata("sis_data_units", "Data units", units.len() as u64);
    c.push_metadata("sis_stored_files", "Stored files", summary.stored() as u64);
    c.push_metadata(
        "sis_embedded_packages",
        "Embedded packages",
        controller::embedded_count(package) as u64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field header followed by `value` and its padding.
    fn field(kind: u32, value: &[u8]) -> Vec<u8> {
        let mut out = kind.to_le_bytes().to_vec();
        out.extend_from_slice(
            &u32::try_from(value.len())
                .expect("small test field")
                .to_le_bytes(),
        );
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn uid_checksum_matches_a_real_package_header() {
        // UIDs of IDA's `arm_logexportv11_sis9` test input header.
        let uids = [0x7A, 0x1A, 0x20, 0x10, 0, 0, 0, 0, 0x61, 0x1C, 0x00, 0xA0];
        assert_eq!(uid_checksum(&uids), 0x6B28_F331);
    }

    #[test]
    fn crc_is_the_zmodem_crc16_of_the_check_string() {
        // MakeSIS `DoTheCrc`: "123456789" gives 0x31C3.
        assert_eq!(checksum::crc16_ibm3740_update(0, b"123456789"), 0x31C3);
    }

    #[test]
    fn field_crc_covers_the_header_value_and_zero_padding() {
        let bytes = field(37, b"abc");
        let buffer = Buffer::file(&bytes);
        let blob = buffer
            .field(0, bytes.len(), Header::Typed(FieldType::BLOB))
            .expect("the blob fits");
        assert_eq!(blob.raw.len(), 11);
        assert_eq!(blob.end, 12);
        assert_eq!(field_crc(&blob), checksum::crc16_ibm3740_update(0, &bytes));
    }

    #[test]
    fn long_lengths_carry_bit_31_in_the_high_word() {
        // Length 0x8000_0004: low word 0x0000_0004 with bit 31 set, high
        // word 1 (bit 31 of the length).
        let mut bytes = 37u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(LONG_LENGTH | 4).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let message = Buffer::file(&bytes)
            .field(0, bytes.len(), Header::Typed(FieldType::BLOB))
            .unwrap_err()
            .to_string();
        assert!(message.contains("2147483652 B value"), "{message}");

        // A short value in the long form reads normally.
        let mut bytes = 37u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(LONG_LENGTH | 2).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(b"xy\0\0");
        let blob = Buffer::file(&bytes)
            .field(0, bytes.len(), Header::Typed(FieldType::BLOB))
            .expect("the blob fits");
        assert_eq!((blob.value_start, blob.value), (12, &b"xy"[..]));
    }

    #[test]
    fn arrays_must_hold_their_element_type_and_end_exactly() {
        // SISArray<SISString> with one element "A".
        let mut value = 1u32.to_le_bytes().to_vec();
        value.extend_from_slice(&2u32.to_le_bytes());
        value.extend_from_slice(&[b'A', 0, 0, 0]);
        let mut outer = field(2, &value);
        let wrapper = field(14, &outer);
        let buffer = Buffer::file(&wrapper);
        let info = buffer
            .field(0, wrapper.len(), Header::Typed(FieldType::INFO))
            .expect("the wrapper fits");
        let strings = Members::of(buffer, &info)
            .array(FieldType::STRING)
            .expect("a valid array");
        assert_eq!(strings.len(), 1);
        assert_eq!(text(buffer, &strings[0]).expect("even length"), "A");

        let message = Members::of(buffer, &info)
            .array(FieldType::BLOB)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("Invalid SISArray element type 1"),
            "{message}"
        );

        // An element whose padding runs past the array: the array length
        // counts the value but not the padding.
        outer[4] = 10;
        let wrapper = field(14, &outer);
        let buffer = Buffer::file(&wrapper);
        let info = buffer
            .field(0, wrapper.len(), Header::Typed(FieldType::INFO))
            .expect("the wrapper fits");
        let message = Members::of(buffer, &info)
            .array(FieldType::STRING)
            .unwrap_err()
            .to_string();
        assert!(message.contains("runs past the array"), "{message}");
    }

    #[test]
    fn strings_are_ucs2_and_kept_to_the_text_limit() {
        let odd = field(1, b"abc");
        let buffer = Buffer::file(&odd);
        let string = buffer
            .field(0, odd.len(), Header::Typed(FieldType::STRING))
            .expect("the string fits");
        assert!(text(buffer, &string).is_err());

        let long: Vec<u8> = "x"
            .repeat(MAX_TEXT + 5)
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let bytes = field(1, &long);
        let buffer = Buffer::file(&bytes);
        let string = buffer
            .field(0, bytes.len(), Header::Typed(FieldType::STRING))
            .expect("the string fits");
        let shown = text(buffer, &string).expect("even length");
        assert_eq!(shown.chars().count(), MAX_TEXT + 1);
        assert!(shown.ends_with('\u{2026}'));
    }

    #[test]
    fn detection_needs_uid1_and_the_contents_type() {
        let mut header = vec![0u8; 24];
        header[..4].copy_from_slice(&SISX_UID1.to_le_bytes());
        header[16..20].copy_from_slice(&12u32.to_le_bytes());
        assert_eq!(detect(&header), Some(Layout::Sis9));
        header[16..20].copy_from_slice(b"EPOC");
        assert_eq!(detect(&header), None);
        assert_eq!(detect(&header[..19]), None);
    }
}
