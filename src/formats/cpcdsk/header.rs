//! AMSDOS and +3DOS file headers: the first 128-byte record of a file,
//! recognized inside a disk image by its checksum (and the `PLUS3DOS`
//! signature), and standalone headered files.
//!
//! AMSDOS ([AMSHDR]; [IDSK] `StAmsdos`; [AMSROM] `0xCE92`, `0xCF05`): user
//! (0), name (1, 8 B) and extension (9, 3 B) padded with spaces, zero (12,
//! 4 B), tape block number (16) and last-block flag (17), zero on disc,
//! file type (18), data length (19), load address (21), first-block flag
//! (23), logical length (24), entry address (26), unused (28, 36 B), real
//! length (64, 24-bit), checksum (67: the 16-bit sum of bytes 0-66),
//! unused (69). The file type is protection (bit 0), contents (bits 1-3:
//! BASIC, binary, screen image, ASCII; 4-7 unallocated) and version (bits
//! 4-7). Words are little-endian.
//!
//! +3DOS ([P3MAN] "File headers" and "DOS OPEN"; [Z88DK]): `PLUS3DOS` (0),
//! soft EOF 0x1A (8), issue (9), version (10), file length including the
//! header (11, 32-bit little-endian), +3 BASIC header data (15: type,
//! length, two parameters; CODE files have their load address in the
//! first), reserved (23), checksum (127: the sum of bytes 0-126 modulo
//! 256). AMSDOS and +3DOS do not recognize each other's headers ([P3MAN]).

use super::*;
use crate::formats::container::Child;
use std::borrow::Cow;

/// Size of a header: the file's first CP/M record.
pub(super) const HEADER_SIZE: usize = 128;

/// A header record.
pub(super) type Record = [u8; HEADER_SIZE];

// AMSDOS header fields.
const AMSDOS_USER: usize = 0;
const AMSDOS_NAME: usize = 1;
/// Name (8) and extension (3) characters.
const AMSDOS_NAME_SIZE: usize = 11;
/// The zero field (12-15), then the tape block number and last-block flag
/// (16, 17), which are zero on disc.
const AMSDOS_ZERO_START: usize = 12;
const AMSDOS_ZERO_END: usize = 18;
const AMSDOS_FILE_TYPE: usize = 18;
const AMSDOS_LOAD_ADDRESS: usize = 21;
const AMSDOS_FIRST_BLOCK: usize = 23;
const AMSDOS_LOGICAL_LENGTH: usize = 24;
const AMSDOS_ENTRY_ADDRESS: usize = 26;
const AMSDOS_REAL_LENGTH: usize = 64;
/// The checksum follows the 67 bytes it sums ([AMSROM] `0xCE92`:
/// `ld b,$43`).
const AMSDOS_CHECKSUM: usize = 67;

/// Highest AMSDOS user number ([AMSHDR]).
const MAX_USER: u8 = 15;

/// First-block flag: 0xFF per [AMSHDR]; iDSK writes 0.
const FIRST_BLOCK_SET: u8 = 0xff;

// AMSDOS file type bits and contents values ([AMSHDR]).
const TYPE_PROTECTED: u8 = 0x01;
const CONTENTS_SHIFT: u8 = 1;
const CONTENTS_MASK: u8 = 0x07;
const VERSION_SHIFT: u8 = 4;
const CONTENTS_BASIC: u8 = 0;
const CONTENTS_BINARY: u8 = 1;
const CONTENTS_SCREEN: u8 = 2;
const CONTENTS_ASCII: u8 = 3;
/// ASCII files are version 1, all other files version 0 ([AMSHDR]).
const ASCII_VERSION: u8 = 1;

/// +3DOS signature and the soft-EOF byte after it ([P3MAN]).
pub(super) const PLUS3DOS_SIGNATURE: &[u8; 9] = b"PLUS3DOS\x1a";

// +3DOS header fields.
const PLUS3DOS_ISSUE: usize = 9;
const PLUS3DOS_VERSION: usize = 10;
const PLUS3DOS_FILE_LENGTH: usize = 11;
const PLUS3DOS_BASIC_TYPE: usize = 15;
const PLUS3DOS_BASIC_LENGTH: usize = 16;
const PLUS3DOS_PARAMETER_1: usize = 18;
const PLUS3DOS_PARAMETER_2: usize = 20;
const PLUS3DOS_CHECKSUM: usize = 127;

/// The issue number +3DOS writes; "the issue number must equal the
/// software's issue number" ([P3MAN]). z88dk writes 1.
const SUPPORTED_ISSUE: u8 = 1;

// +3 BASIC header types ([P3MAN] "DOS OPEN").
const BASIC_PROGRAM: u8 = 0;
const BASIC_NUMERIC_ARRAY: u8 = 1;
const BASIC_CHARACTER_ARRAY: u8 = 2;
const BASIC_CODE: u8 = 3;

/// A program's first parameter is 8000h or the autostart line ([P3MAN]).
const NO_AUTOSTART: u16 = 0x8000;

/// `SCREEN$` is CODE of the 6912-byte display file at 16384. This is the
/// Spectrum BASIC convention by our reading; the cited sources only name
/// `SCREEN$` as a CODE file. It keeps a picture out of the code model.
const SCREEN_ADDRESS: u16 = 0x4000;
const SCREEN_SIZE: u16 = 6912;

/// Prefixes of the standalone layouts' metadata keys.
const AMSDOS_KEY_PREFIX: &str = "amsdos";
const PLUS3DOS_KEY_PREFIX: &str = "plus3dos";

fn word(record: &Record, at: usize) -> u16 {
    u16::from_le_bytes([record[at], record[at + 1]])
}

/// The first record of `data`, if it has one.
pub(super) fn first_record(data: &[u8]) -> Option<&Record> {
    data.get(..HEADER_SIZE)?.try_into().ok()
}

/// Where a file's body loads and starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Load {
    /// Target address of the first byte after the header.
    pub(super) address: u16,
    /// Execution address, when the header has one.
    pub(super) entry: Option<u16>,
}

/// What a header says its file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Description {
    /// Where the body loads, when it is machine code.
    pub(super) load: Option<Load>,
    /// What the file is, for the notes.
    pub(super) summary: String,
}

impl Description {
    fn code(load: Load, summary: String) -> Self {
        Self {
            load: Some(load),
            summary,
        }
    }

    fn data(summary: impl Into<String>) -> Self {
        Self {
            load: None,
            summary: summary.into(),
        }
    }
}

/// An AMSDOS header ([AMSHDR]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AmsdosHeader {
    pub(super) user: u8,
    /// `NAME.EXT`, attribute bits cleared and padding removed.
    pub(super) name: String,
    pub(super) file_type: u8,
    pub(super) load_address: u16,
    /// File length in bytes, excluding the header.
    pub(super) logical_length: u16,
    pub(super) entry_address: u16,
    /// The 24-bit copy of the length.
    pub(super) real_length: u32,
    pub(super) checksum: u16,
}

/// The AMSDOS checksum of `record`: the sum of bytes 0-66, which cannot
/// exceed 67 × 255 and so fits 16 bits.
fn amsdos_sum(record: &Record) -> u16 {
    record[..AMSDOS_CHECKSUM]
        .iter()
        .map(|&b| u16::from(b))
        .sum()
}

impl AmsdosHeader {
    /// The header in `record` when its checksum matches, as AMSDOS checks
    /// ([AMSROM] `0xCF05`), and is not zero: a record of zeros is not a
    /// header ([IDSK] `CheckAmsdos`).
    pub(super) fn parse(record: &Record) -> Option<Self> {
        let checksum = word(record, AMSDOS_CHECKSUM);
        (checksum != 0 && amsdos_sum(record) == checksum).then(|| Self {
            user: record[AMSDOS_USER],
            name: file_name(&record[AMSDOS_NAME..AMSDOS_NAME + AMSDOS_NAME_SIZE]),
            file_type: record[AMSDOS_FILE_TYPE],
            load_address: word(record, AMSDOS_LOAD_ADDRESS),
            logical_length: word(record, AMSDOS_LOGICAL_LENGTH),
            entry_address: word(record, AMSDOS_ENTRY_ADDRESS),
            real_length: u32::from(word(record, AMSDOS_REAL_LENGTH))
                | u32::from(record[AMSDOS_REAL_LENGTH + 2]) << 16,
            checksum,
        })
    }

    fn contents(&self) -> u8 {
        (self.file_type >> CONTENTS_SHIFT) & CONTENTS_MASK
    }

    fn version(&self) -> u8 {
        self.file_type >> VERSION_SHIFT
    }

    fn describe(&self) -> Description {
        let address = self.load_address;
        let protected = self.file_type & TYPE_PROTECTED != 0;
        match (self.contents(), protected) {
            (CONTENTS_BINARY, false) => Description::code(
                Load {
                    address,
                    entry: Some(self.entry_address),
                },
                format!(
                    "AMSDOS binary; load address 0x{address:04X}; entry 0x{:04X}",
                    self.entry_address
                ),
            ),
            (CONTENTS_BINARY, true) => Description::data(format!(
                "AMSDOS protected binary; load address 0x{address:04X}; the stored form of \
                 protected files is not documented, not analyzed"
            )),
            (CONTENTS_BASIC, false) => {
                Description::data("AMSDOS BASIC program (tokenized BASIC, not machine code)")
            }
            (CONTENTS_BASIC, true) => {
                Description::data("AMSDOS protected BASIC program (not machine code)")
            }
            (CONTENTS_SCREEN, _) => Description::data("AMSDOS screen image (not machine code)"),
            (CONTENTS_ASCII, _) => Description::data("AMSDOS ASCII file (not machine code)"),
            (contents, _) => Description::data(format!(
                "AMSDOS file type 0x{:02X}: contents value {contents} is unallocated; not analyzed",
                self.file_type
            )),
        }
    }
}

/// A +3DOS header ([P3MAN]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Plus3Header {
    pub(super) issue: u8,
    pub(super) version: u8,
    /// File length in bytes, including the header ([Z88DK]).
    pub(super) file_length: u32,
    /// +3 BASIC header data: type, length and two parameters.
    pub(super) basic_type: u8,
    pub(super) basic_length: u16,
    pub(super) parameter_1: u16,
    pub(super) parameter_2: u16,
}

/// The +3DOS checksum of `record`: the sum of bytes 0-126 modulo 256.
fn plus3_sum(record: &Record) -> u8 {
    record[..PLUS3DOS_CHECKSUM]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_add(b))
}

impl Plus3Header {
    /// The header in `record` when "the signature and checksum are as
    /// expected" ([P3MAN]).
    pub(super) fn parse(record: &Record) -> Option<Self> {
        let valid = record.starts_with(PLUS3DOS_SIGNATURE)
            && plus3_sum(record) == record[PLUS3DOS_CHECKSUM];
        valid.then(|| Self::fields(record))
    }

    fn fields(record: &Record) -> Self {
        Self {
            issue: record[PLUS3DOS_ISSUE],
            version: record[PLUS3DOS_VERSION],
            file_length: u32::from_le_bytes([
                record[PLUS3DOS_FILE_LENGTH],
                record[PLUS3DOS_FILE_LENGTH + 1],
                record[PLUS3DOS_FILE_LENGTH + 2],
                record[PLUS3DOS_FILE_LENGTH + 3],
            ]),
            basic_type: record[PLUS3DOS_BASIC_TYPE],
            basic_length: word(record, PLUS3DOS_BASIC_LENGTH),
            parameter_1: word(record, PLUS3DOS_PARAMETER_1),
            parameter_2: word(record, PLUS3DOS_PARAMETER_2),
        }
    }

    /// Bytes after the header that the file length covers.
    fn body_length(&self) -> usize {
        usize::try_from(self.file_length)
            .unwrap_or(usize::MAX)
            .saturating_sub(HEADER_SIZE)
    }

    fn describe(&self) -> Description {
        let address = self.parameter_1;
        match self.basic_type {
            BASIC_CODE if address == SCREEN_ADDRESS && self.basic_length == SCREEN_SIZE => {
                Description::data(
                    "+3DOS CODE of 6912 B at 0x4000: the display file (SCREEN$), not machine code",
                )
            }
            BASIC_CODE => Description::code(
                Load {
                    address,
                    entry: None,
                },
                format!(
                    "+3DOS CODE; load address 0x{address:04X}; the header has no entry address"
                ),
            ),
            BASIC_PROGRAM if address < NO_AUTOSTART => Description::data(format!(
                "+3DOS BASIC program, autostart line {address} (not machine code)"
            )),
            BASIC_PROGRAM => Description::data("+3DOS BASIC program (not machine code)"),
            BASIC_NUMERIC_ARRAY => Description::data("+3DOS numeric array (not machine code)"),
            BASIC_CHARACTER_ARRAY => Description::data("+3DOS character array (not machine code)"),
            other => Description::data(format!(
                "+3DOS file with header data type 0x{other:02X}, not a +3 BASIC type; not analyzed"
            )),
        }
    }
}

/// A file header found in a file's first record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FileHeader {
    Amsdos(AmsdosHeader),
    Plus3(Plus3Header),
}

impl FileHeader {
    /// The header in `record`. +3DOS is tried first: its signature is
    /// explicit, while an AMSDOS checksum can match by chance.
    pub(super) fn parse(record: &Record) -> Option<Self> {
        Plus3Header::parse(record)
            .map(Self::Plus3)
            .or_else(|| AmsdosHeader::parse(record).map(Self::Amsdos))
    }

    /// Bytes after the header that the header declares.
    pub(super) fn body_length(&self) -> usize {
        match self {
            Self::Amsdos(header) => usize::from(header.logical_length),
            Self::Plus3(header) => header.body_length(),
        }
    }

    /// What the header says the file holds.
    pub(super) fn describe(&self) -> Description {
        match self {
            Self::Amsdos(header) => header.describe(),
            Self::Plus3(header) => header.describe(),
        }
    }
}

/// Validate a standalone AMSDOS file: the checksum, every field
/// [AMSHDR] fixes, matching logical and real lengths, and a size of the
/// header plus the logical length, rounded up to at most a whole record.
pub(super) fn standalone_amsdos(data: &[u8]) -> Result<AmsdosHeader> {
    let record = first_record(data).ok_or_else(|| {
        error(format!(
            "Truncated AMSDOS header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    let header = AmsdosHeader::parse(record).ok_or_else(|| {
        error(format!(
            "Invalid AMSDOS header checksum 0x{:04X} (computed 0x{:04X})",
            word(record, AMSDOS_CHECKSUM),
            amsdos_sum(record)
        ))
    })?;
    if header.user > MAX_USER {
        return Err(error(format!("Invalid AMSDOS user number {}", header.user)));
    }
    let name = &record[AMSDOS_NAME..AMSDOS_NAME + AMSDOS_NAME_SIZE];
    if name[0] == b' ' || !name.iter().all(|&b| b == b' ' || b.is_ascii_graphic()) {
        return Err(error("Invalid AMSDOS file name"));
    }
    if record[AMSDOS_ZERO_START..AMSDOS_ZERO_END]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(error("Invalid AMSDOS header: bytes 12-17 are not zero"));
    }
    let contents = header.contents();
    let expected_version = if contents == CONTENTS_ASCII {
        ASCII_VERSION
    } else {
        0
    };
    if contents > CONTENTS_ASCII || header.version() != expected_version {
        return Err(error(format!(
            "Unknown AMSDOS file type 0x{:02X}",
            header.file_type
        )));
    }
    let first_block = record[AMSDOS_FIRST_BLOCK];
    if first_block != 0 && first_block != FIRST_BLOCK_SET {
        return Err(error(format!(
            "Invalid AMSDOS first-block flag 0x{first_block:02X}"
        )));
    }
    let length = usize::from(header.logical_length);
    if length == 0 || header.real_length != u32::from(header.logical_length) {
        return Err(error(format!(
            "Invalid AMSDOS lengths: logical {length} B, real {} B",
            header.real_length
        )));
    }
    let stored = data.len() - HEADER_SIZE;
    if stored < length {
        return Err(error(format!(
            "Truncated AMSDOS file: the header declares {length} B, {stored} B follow"
        )));
    }
    if stored > round_up(length, HEADER_SIZE) {
        return Err(error(format!(
            "Invalid AMSDOS file size: {stored} B follow the header for a logical length of \
             {length} B"
        )));
    }
    Ok(header)
}

/// Report a headered file's body: a Z80 load section at the header's
/// address when it is machine code, an opaque child otherwise.
fn load_body<'a>(c: &mut Container<'a>, description: &Description, label: &str, body: &'a [u8]) {
    c.notes
        .push(format!("{}; {} B", description.summary, body.len()));
    match description.load {
        Some(load) => {
            c.target = Some(Z80);
            c.entry = load.entry.map(u64::from);
            c.code_sections = true;
            c.push_section(u64::from(load.address), HEADER_SIZE, Cow::Borrowed(body));
            if let Some(section) = c.sections.last_mut() {
                section.label = format!("{label} at 0x{:04X}", load.address);
            }
        }
        None if body.is_empty() => {}
        None => c
            .children
            .push(Child::opaque(label.to_string(), HEADER_SIZE, body)),
    }
}

/// What follows the file's declared end: record padding (CP/M stores whole
/// 128-byte records) or other data.
fn padding_note(data: &[u8], end: usize) -> Option<String> {
    let extra = data.len().checked_sub(end).filter(|&n| n > 0)?;
    Some(if end + extra <= round_up(end, HEADER_SIZE) {
        format!("{extra} B of record padding after the file's end at 0x{end:X}")
    } else {
        format!("{extra} B after the file's end at 0x{end:X} are not part of the file")
    })
}

/// A standalone AMSDOS file.
pub(super) fn parse_amsdos(data: &[u8]) -> Result<Container<'_>> {
    let header = standalone_amsdos(data)?;
    let length = usize::from(header.logical_length);
    let body = slice(data, HEADER_SIZE, length)?;
    let mut c = Container::new(
        FileFormat::Amsdos,
        Layout::Amsdos.label(),
        AMSDOS_KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "AMSDOS header: user {}, \"{}\", file type 0x{:02X}; checksum 0x{:04X} verified",
        header.user, header.name, header.file_type, header.checksum
    ));
    load_body(&mut c, &header.describe(), &header.name, body);
    c.notes
        .push("AMSDOS is the Amstrad CPC disc system; the platform's CPU is the Z80".to_string());
    c.notes.extend(padding_note(data, HEADER_SIZE + length));
    let prefix = AMSDOS_KEY_PREFIX;
    c.push_metadata(
        format!("{prefix}_user"),
        "User number",
        u64::from(header.user),
    );
    c.push_metadata(
        format!("{prefix}_file_name"),
        "File name",
        header.name.clone(),
    );
    c.push_metadata(
        format!("{prefix}_file_type"),
        "File type",
        u64::from(header.file_type),
    );
    c.push_metadata(
        format!("{prefix}_load_address"),
        "Load address",
        u64::from(header.load_address),
    );
    c.push_metadata(
        format!("{prefix}_entry_address"),
        "Entry address",
        u64::from(header.entry_address),
    );
    c.push_metadata(
        format!("{prefix}_logical_length"),
        "Logical length (B)",
        u64::from(header.logical_length),
    );
    Ok(c)
}

/// A standalone +3DOS file.
pub(super) fn parse_plus3dos(data: &[u8]) -> Result<Container<'_>> {
    let record = first_record(data).ok_or_else(|| {
        error(format!(
            "Truncated +3DOS header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    if !record.starts_with(PLUS3DOS_SIGNATURE) {
        return Err(error("Missing +3DOS signature"));
    }
    let computed = plus3_sum(record);
    if computed != record[PLUS3DOS_CHECKSUM] {
        return Err(error(format!(
            "Invalid +3DOS header checksum 0x{:02X} (computed 0x{computed:02X})",
            record[PLUS3DOS_CHECKSUM]
        )));
    }
    let header = Plus3Header::fields(record);
    if header.issue != SUPPORTED_ISSUE {
        return Err(error(format!(
            "Unsupported +3DOS header issue {}",
            header.issue
        )));
    }
    let file_length = usize::try_from(header.file_length).unwrap_or(usize::MAX);
    if file_length < HEADER_SIZE {
        return Err(error(format!(
            "Invalid +3DOS file length {file_length} B: shorter than the {HEADER_SIZE} B header"
        )));
    }
    if file_length > data.len() {
        return Err(error(format!(
            "Truncated +3DOS file: the header declares {file_length} B, {} B present",
            data.len()
        )));
    }
    let body = &data[HEADER_SIZE..file_length];
    let mut c = Container::new(
        FileFormat::Plus3Dos,
        Layout::Plus3Dos.label(),
        PLUS3DOS_KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "+3DOS header issue {}, version {}; file length {file_length} B including the header; \
         checksum 0x{computed:02X} verified",
        header.issue, header.version
    ));
    if usize::from(header.basic_length) != body.len() {
        c.notes.push(format!(
            "+3 BASIC header length {} B differs from the {} B after the header",
            header.basic_length,
            body.len()
        ));
    }
    load_body(&mut c, &header.describe(), "CODE", body);
    c.notes
        .push("+3DOS is the Spectrum +3 disc system; the platform's CPU is the Z80".to_string());
    c.notes.extend(padding_note(data, file_length));
    let prefix = PLUS3DOS_KEY_PREFIX;
    c.push_metadata(
        format!("{prefix}_version"),
        "Header version",
        u64::from(header.version),
    );
    c.push_metadata(
        format!("{prefix}_file_length"),
        "File length (B)",
        u64::from(header.file_length),
    );
    c.push_metadata(
        format!("{prefix}_basic_type"),
        "+3 BASIC file type",
        u64::from(header.basic_type),
    );
    c.push_metadata(
        format!("{prefix}_parameter_1"),
        "+3 BASIC parameter 1",
        u64::from(header.parameter_1),
    );
    c.push_metadata(
        format!("{prefix}_parameter_2"),
        "+3 BASIC parameter 2",
        u64::from(header.parameter_2),
    );
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An AMSDOS binary header for `NAME.BIN`, user 0, loading `length`
    /// bytes at 0x4000 with entry 0x4001.
    fn amsdos_record(length: u16) -> Record {
        let mut record = [0u8; HEADER_SIZE];
        record[1..12].copy_from_slice(b"NAME    BIN");
        record[AMSDOS_FILE_TYPE] = CONTENTS_BINARY << CONTENTS_SHIFT;
        record[AMSDOS_LOAD_ADDRESS..AMSDOS_LOAD_ADDRESS + 2]
            .copy_from_slice(&0x4000u16.to_le_bytes());
        record[AMSDOS_LOGICAL_LENGTH..AMSDOS_LOGICAL_LENGTH + 2]
            .copy_from_slice(&length.to_le_bytes());
        record[AMSDOS_ENTRY_ADDRESS..AMSDOS_ENTRY_ADDRESS + 2]
            .copy_from_slice(&0x4001u16.to_le_bytes());
        record[AMSDOS_REAL_LENGTH..AMSDOS_REAL_LENGTH + 2].copy_from_slice(&length.to_le_bytes());
        let sum = amsdos_sum(&record);
        record[AMSDOS_CHECKSUM..AMSDOS_CHECKSUM + 2].copy_from_slice(&sum.to_le_bytes());
        record
    }

    #[test]
    fn amsdos_checksums_sum_67_bytes() {
        let record = amsdos_record(3);
        let header = AmsdosHeader::parse(&record).expect("valid header");
        assert_eq!(header.name, "NAME.BIN");
        assert_eq!(header.logical_length, 3);
        let description = header.describe();
        assert_eq!(
            description.load,
            Some(Load {
                address: 0x4000,
                entry: Some(0x4001)
            })
        );
        // A zero record sums to its zero checksum but is no header.
        assert_eq!(AmsdosHeader::parse(&[0; HEADER_SIZE]), None);
        let mut bad = record;
        bad[66] ^= 1;
        assert_eq!(AmsdosHeader::parse(&bad), None);
        // Bytes after the checksum are not summed.
        let mut tail = record;
        tail[100] = 0x55;
        assert!(AmsdosHeader::parse(&tail).is_some());
    }

    #[test]
    fn standalone_amsdos_files_validate_their_size() {
        let mut file = amsdos_record(3).to_vec();
        file.extend_from_slice(&[0x3e, 0x01, 0xc9]);
        assert!(standalone_amsdos(&file).is_ok());
        // Record padding is allowed, a second record is not.
        file.resize(HEADER_SIZE * 2, 0x1a);
        assert!(standalone_amsdos(&file).is_ok());
        file.push(0);
        assert!(standalone_amsdos(&file).is_err());
        assert!(standalone_amsdos(&file[..HEADER_SIZE + 2]).is_err());
    }

    #[test]
    fn plus3_checksums_are_modulo_256() {
        let mut record = [0u8; HEADER_SIZE];
        record[..9].copy_from_slice(PLUS3DOS_SIGNATURE);
        record[PLUS3DOS_ISSUE] = 1;
        record[PLUS3DOS_FILE_LENGTH] = 0x88;
        record[PLUS3DOS_BASIC_TYPE] = BASIC_CODE;
        record[PLUS3DOS_PARAMETER_1 + 1] = 0x80;
        record[PLUS3DOS_CHECKSUM] = plus3_sum(&record);
        let header = Plus3Header::parse(&record).expect("valid header");
        assert_eq!(header.body_length(), 8);
        assert_eq!(header.describe().load.map(|l| l.address), Some(0x8000));
        assert!(matches!(
            FileHeader::parse(&record),
            Some(FileHeader::Plus3(_))
        ));
        record[PLUS3DOS_CHECKSUM] ^= 1;
        assert_eq!(Plus3Header::parse(&record), None);
    }

    #[test]
    fn screen_dumps_and_basic_are_not_code() {
        let screen = Plus3Header {
            issue: 1,
            version: 0,
            file_length: 7040,
            basic_type: BASIC_CODE,
            basic_length: SCREEN_SIZE,
            parameter_1: SCREEN_ADDRESS,
            parameter_2: 0,
        };
        assert_eq!(screen.describe().load, None);
        let program = Plus3Header {
            basic_type: BASIC_PROGRAM,
            parameter_1: 10,
            ..screen
        };
        assert!(program.describe().summary.contains("autostart line 10"));
    }
}
