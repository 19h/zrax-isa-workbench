//! Data files that carry their own magic and hold no code:
//!
//! - Apple binary property lists: `bplist00` header, objects, offset table
//!   and a 32-byte trailer (Apple CF `CFBinaryPList.c`, CF-1153.18,
//!   `__CFBinaryPlistGetTopLevelInfo`).
//! - Qualcomm Atheros Wi-Fi board data (`board-2.bin`): a magic string,
//!   then 4-byte aligned information elements (Linux
//!   `drivers/net/wireless/ath/ath10k/hw.h` and `ath11k/hw.h`, v6.6:
//!   `ATH10K_BOARD_MAGIC`, `struct ath10k_fw_ie`, `ATH10K_BD_IE_BOARD`).
//!
//! Both are opaque: the ISA is unknown and no byte reaches the code model.
//! The structure is checked so that a damaged file is a parse error rather
//! than raw data.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;

/// `bplist` followed by the two-character format version.
const BPLIST_MAGIC: &[u8] = b"bplist";
/// The only version `CFBinaryPList.c` writes and reads as a binary plist.
const BPLIST_VERSION: &[u8] = b"00";
const BPLIST_HEADER_SIZE: usize = 8;
/// Unused (5), sort version, offset int size, object ref size, object
/// count (8), top object (8), offset table offset (8); big-endian.
const BPLIST_TRAILER_SIZE: usize = 32;

/// Board data magics of the ath10k, ath11k and ath12k drivers.
const QCA_BOARD_MAGICS: [&[u8]; 3] = [
    b"QCA-ATH10K-BOARD",
    b"QCA-ATH11K-BOARD",
    b"QCA-ATH12K-BOARD",
];
/// Information element header: id and length, both `__le32`.
const QCA_IE_HEADER_SIZE: usize = 8;
/// `ATH10K_BD_IE_BOARD` / `ATH11K_BD_IE_BOARD`: one board, made of sub-IEs.
const QCA_IE_BOARD: u32 = 0;
/// `ATH10K_BD_IE_BOARD_NAME`: the board name string inside a board IE.
const QCA_IE_BOARD_NAME: u32 = 0;
/// Board names reported as metadata; the count is always reported.
const QCA_MAX_LISTED_BOARDS: usize = 8;

/// A data file layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Apple binary property list (`bplist00`).
    BinaryPlist,
    /// Qualcomm Atheros Wi-Fi board data.
    QcaBoard,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::BinaryPlist => FileFormat::Bplist,
            Self::QcaBoard => FileFormat::QcaBoard,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::BinaryPlist => "Apple binary property list",
            Self::QcaBoard => "QCA board data",
        }
    }

    /// Both layouts open with a magic string.
    pub fn is_weak(self) -> bool {
        false
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::DataFileParseError {
        message: message.into(),
    }
}

/// A file that opens with a binary plist or board data magic.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(BPLIST_MAGIC) {
        Some(Layout::BinaryPlist)
    } else if QCA_BOARD_MAGICS.iter().any(|m| data.starts_with(m)) {
        Some(Layout::QcaBoard)
    } else {
        None
    }
}

/// Parse a data file of the given layout.
///
/// # Errors
///
/// [`ClassifierError::DataFileParseError`] for an unsupported version, a
/// trailer or offset table outside the file, or an information element
/// that runs past the end.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::BinaryPlist => parse_bplist(data),
        Layout::QcaBoard => parse_qca_board(data),
    }
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes = data
        .get(at..at + 8)
        .ok_or_else(|| error(format!("Truncated binary plist at 0x{at:X}")))?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(word))
}

/// A big-endian unsigned integer of `size` bytes (1, 2, 4 or 8).
fn be_uint(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |value, &b| (value << 8) | u64::from(b))
}

fn is_plist_int_size(size: u8) -> bool {
    matches!(size, 1 | 2 | 4 | 8)
}

/// The trailer locates the offset table; every object offset must point
/// between the header and the table, as `CFBinaryPList.c` checks.
fn parse_bplist(data: &[u8]) -> Result<Container<'_>> {
    let version = data
        .get(BPLIST_MAGIC.len()..BPLIST_HEADER_SIZE)
        .ok_or_else(|| error("Truncated binary plist header at 0x0"))?;
    if version != BPLIST_VERSION {
        return Err(error(format!(
            "Unsupported binary plist version {:?} at 0x6",
            String::from_utf8_lossy(version)
        )));
    }
    let trailer = data
        .len()
        .checked_sub(BPLIST_TRAILER_SIZE)
        .filter(|&t| t > BPLIST_HEADER_SIZE)
        .ok_or_else(|| error("Missing binary plist trailer"))?;
    let offset_size = data[trailer + 6];
    let ref_size = data[trailer + 7];
    if !is_plist_int_size(offset_size) || !is_plist_int_size(ref_size) {
        return Err(error(format!(
            "Invalid binary plist trailer at 0x{trailer:X}: offset size {offset_size}, reference size {ref_size}"
        )));
    }
    let objects = be_u64(data, trailer + 8)?;
    let top = be_u64(data, trailer + 16)?;
    let table_offset = be_u64(data, trailer + 24)?;
    let invalid = || {
        error(format!(
            "Invalid binary plist trailer at 0x{trailer:X}: {objects} objects, top object {top}, offset table at 0x{table_offset:X}"
        ))
    };
    let size = usize::from(offset_size);
    let table = usize::try_from(table_offset).map_err(|_| invalid())?;
    let count = usize::try_from(objects).map_err(|_| invalid())?;
    let table_end = count
        .checked_mul(size)
        .and_then(|bytes| bytes.checked_add(table))
        .ok_or_else(invalid)?;
    if count == 0 || top >= objects || table < BPLIST_HEADER_SIZE || table_end > trailer {
        return Err(invalid());
    }
    for (index, entry) in data[table..table_end].chunks_exact(size).enumerate() {
        let offset = be_uint(entry);
        if offset < BPLIST_HEADER_SIZE as u64 || offset >= table as u64 {
            return Err(error(format!(
                "Invalid binary plist object offset 0x{offset:X} at 0x{:X}",
                table + index * size
            )));
        }
    }
    let mut c = Container::new(FileFormat::Bplist, Layout::BinaryPlist.label(), "bplist");
    c.consumed = data.len();
    c.opaque = true;
    c.notes
        .push("Apple binary property list; data, not code".to_string());
    c.push_metadata("bplist_objects", "Objects", objects);
    c.push_metadata("bplist_top_object", "Top object", top);
    c.push_metadata(
        "bplist_offset_size",
        "Offset size (B)",
        u64::from(offset_size),
    );
    c.push_metadata(
        "bplist_reference_size",
        "Object reference size (B)",
        u64::from(ref_size),
    );
    Ok(c)
}

/// `pos` rounded up to a multiple of four.
fn align4(pos: usize) -> Option<usize> {
    pos.checked_add(3).map(|p| p & !3)
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data
        .get(at..at + 4)
        .ok_or_else(|| error(format!("Truncated QCA board IE header at 0x{at:X}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The information elements of `data[start..end]`: (id, data offset, data
/// length), each element padded to four bytes.
fn ies(data: &[u8], start: usize, end: usize) -> Result<Vec<(u32, usize, usize)>> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        if end - pos < QCA_IE_HEADER_SIZE {
            return Err(error(format!("Truncated QCA board IE header at 0x{pos:X}")));
        }
        let id = le_u32(data, pos)?;
        let len = le_u32(data, pos + 4)? as usize;
        let body = pos + QCA_IE_HEADER_SIZE;
        if len > end - body {
            return Err(error(format!(
                "Truncated QCA board IE {id} at 0x{pos:X}: {len} B declared, {} B left",
                end - body
            )));
        }
        out.push((id, body, len));
        // Padding after the last element may run up to the end only.
        pos = align4(body + len).map_or(end, |next| next.min(end));
    }
    Ok(out)
}

/// Magic, NUL and padding to four bytes, then elements up to the end.
fn parse_qca_board(data: &[u8]) -> Result<Container<'_>> {
    let magic = QCA_BOARD_MAGICS
        .iter()
        .find(|m| data.starts_with(m))
        .ok_or_else(|| error("Invalid QCA board magic at 0x0"))?;
    if data.get(magic.len()) != Some(&0) {
        return Err(error(format!(
            "Missing NUL after the QCA board magic at 0x{:X}",
            magic.len()
        )));
    }
    let first = align4(magic.len() + 1).ok_or_else(|| error("Invalid QCA board magic at 0x0"))?;
    let elements = ies(data, first, data.len())?;
    let mut names = Vec::new();
    let mut boards = 0usize;
    for &(id, body, len) in &elements {
        if id != QCA_IE_BOARD {
            continue;
        }
        boards += 1;
        for (sub_id, sub_body, sub_len) in ies(data, body, body + len)? {
            if sub_id == QCA_IE_BOARD_NAME && names.len() < QCA_MAX_LISTED_BOARDS {
                let name = &data[sub_body..sub_body + sub_len];
                names.push(
                    String::from_utf8_lossy(name)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
        }
    }
    if boards == 0 {
        return Err(error(format!(
            "Missing QCA board element after 0x{first:X}"
        )));
    }
    let driver = String::from_utf8_lossy(&magic[4..10]).to_lowercase();
    let mut c = Container::new(FileFormat::QcaBoard, Layout::QcaBoard.label(), "qca_board");
    c.consumed = data.len();
    c.opaque = true;
    c.notes.push(format!(
        "Qualcomm Atheros {driver} board data: {} elements, {boards} boards; calibration data, not code",
        elements.len()
    ));
    c.push_metadata("qca_board_elements", "Elements", elements.len() as u64);
    c.push_metadata("qca_board_count", "Boards", boards as u64);
    for (index, name) in names.into_iter().enumerate() {
        c.push_metadata(format!("qca_board_{index}"), format!("Board {index}"), name);
    }
    Ok(c)
}
