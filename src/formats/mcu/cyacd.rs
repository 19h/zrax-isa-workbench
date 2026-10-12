//! Cypress/Infineon bootloader text files: `.cyacd` (`PSoC` Creator
//! bootloadable, `PSoC` 3/4/5LP) and `.cyacd2` (DFU SDK, `PSoC` 4/6). One record
//! per line in hex digits; a header line without a prefix, then `:` rows.
//!
//! Sources:
//! - `.cyacd`: Cypress Bootloader Host `cybtldr_parse.c`
//!   (`CyBtldr_ParseHeader`, `CyBtldr_ParseRowData`) and `cybtldr_api2.c`,
//!   as mirrored in rabbitholecomputing/SCSI2SD at
//!   `7ae322c12de9e67a298ab635f16f72b595d6c456`; cyflash `cyflash/cyacd.py`
//!   at `6d742d67d960cd6477cf80af714607a973bbcb05` (row checksum). Header:
//!   big-endian silicon ID, silicon revision, checksum type. Row: array ID,
//!   big-endian row number and data length, data, checksum (the two's
//!   complement of the 8-bit sum of every preceding row byte).
//! - `.cyacd2`: Infineon AN213924 rev *H, ".cyacd2 file format", and
//!   Infineon/mtb-example-psoc4-dfu-host at
//!   `65115d86ed34692e3c44c60819011b56f932482a` `source/cybtldr_parse.c`.
//!   Header: file version 1, little-endian silicon ID, silicon revision,
//!   checksum type, app ID, little-endian product ID. Rows: little-endian
//!   byte address and data, with no checksum in the file; `@APPINFO` and
//!   `@EIV` metadata rows.
//!
//! The header's checksum type selects the checksum of the bootloader's
//! command packets (type 0: 16-bit two's complement of the byte sum; type
//! 1: CRC-16 with reflected polynomial `0x8408`), computed by the host per
//! packet (`CyBtldr_ComputeChecksum`). No packet checksum is stored in the
//! file, so it is reported, not verified; the stored `.cyacd` row checksum
//! is a one-byte sum whatever the type. The silicon ID names a device, not
//! an ISA. There is no magic, so the layout is recognized only when every
//! line parses and every `.cyacd` row checksum matches.

use super::*;

/// Row and metadata line prefixes.
const ROW_PREFIX: u8 = b':';
const METADATA_PREFIX: u8 = b'@';
const APPINFO_PREFIX: &[u8] = b"@APPINFO:0x";
const APPINFO_SEPARATOR: &[u8] = b",0x";
const EIV_PREFIX: &[u8] = b"@EIV:";

/// Decoded header sizes: `.cyacd` 6 bytes (12 hex digits), `.cyacd2` 12
/// bytes (24 hex digits).
const CYACD_HEADER_SIZE: usize = 6;
const CYACD2_HEADER_SIZE: usize = 12;

/// `.cyacd` row bytes besides the data: array ID, row number (2), data
/// length (2), checksum.
const CYACD_ROW_OVERHEAD: usize = 6;

/// Offset of the data in a decoded `.cyacd` row.
const CYACD_ROW_DATA_OFFSET: usize = 5;

/// `.cyacd2` row address.
const CYACD2_ADDRESS_SIZE: usize = 4;

/// The only `.cyacd2` file version.
const CYACD2_FILE_VERSION: u8 = 1;

/// The `.cyacd2` file version as the header's first two hex digits.
const CYACD2_VERSION_DIGITS: &[u8] = b"01";

/// Header checksum types (Infineon `cybtldr_command.h`).
const SUM_CHECKSUM: u8 = 0x00;
const CRC_CHECKSUM: u8 = 0x01;

/// Most hex digits a `@APPINFO` value may have (a 32-bit word).
const MAX_WORD_DIGITS: usize = 8;

/// Transform name for rows decoded from hex text.
const HEX_TRANSFORM: &str = "ASCII hex";

/// One text line without its line ending.
struct Line<'a> {
    /// File offset of the line's first byte.
    offset: usize,
    text: &'a [u8],
}

/// Split into lines ending in LF or CRLF. Every byte must be printable
/// ASCII; only the last line (after the final line ending) may be empty.
fn lines(data: &[u8]) -> Result<Vec<Line<'_>>> {
    let mut lines = Vec::new();
    let mut offset = 0;
    for raw in data.split(|b| *b == b'\n') {
        let text = raw.strip_suffix(b"\r").unwrap_or(raw);
        if let Some(bad) = text.iter().position(|b| !b.is_ascii_graphic()) {
            return Err(error(format!(
                "Invalid cyacd character 0x{:02X} at 0x{:X}",
                text[bad],
                offset + bad
            )));
        }
        lines.push(Line { offset, text });
        offset += raw.len() + 1;
    }
    if lines.last().is_some_and(|line| line.text.is_empty()) {
        lines.pop();
    }
    if let Some(empty) = lines.iter().find(|line| line.text.is_empty()) {
        return Err(error(format!(
            "Invalid empty cyacd line at 0x{:X}",
            empty.offset
        )));
    }
    Ok(lines)
}

/// The value of one hex digit, either case.
fn hex_digit(digit: u8, offset: usize) -> Result<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| error(format!("Invalid hex digit at 0x{offset:X}")))
}

/// Decode hex digits at file offset `offset` into bytes.
fn decode_hex(text: &[u8], offset: usize) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(error(format!(
            "Invalid cyacd record at 0x{offset:X}: odd number of hex digits"
        )));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for (i, pair) in text.chunks_exact(2).enumerate() {
        let at = offset + 2 * i;
        let high = hex_digit(pair[0], at)?;
        let low = hex_digit(pair[1], at + 1)?;
        bytes.push(high << 4 | low);
    }
    Ok(bytes)
}

/// The layout the first line announces: 12 hex digits for `.cyacd`, 24
/// digits starting with file version `01` for `.cyacd2`. Only the first
/// line is read, so other input is rejected cheaply.
fn header_layout(data: &[u8]) -> Option<Layout> {
    let end = memchr::memchr(b'\n', data).unwrap_or(data.len());
    let first = &data[..end];
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    if !first.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    if first.len() == CYACD_HEADER_SIZE * 2 {
        Some(Layout::Cyacd)
    } else if first.len() == CYACD2_HEADER_SIZE * 2 && first.starts_with(CYACD2_VERSION_DIGITS) {
        Some(Layout::Cyacd2)
    } else {
        None
    }
}

/// Weak recognition: the header and every row must parse.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let layout = header_layout(data)?;
    parse(data, layout).is_ok().then_some(layout)
}

/// A decoded data row.
struct Row {
    /// Index of the row's line.
    line: usize,
    /// File offset of the row's text.
    offset: usize,
    /// Length of the row's text.
    text_len: usize,
    /// `.cyacd` flash array ID; `None` for `.cyacd2`.
    array: Option<u8>,
    /// `.cyacd`: row number; `.cyacd2`: byte address.
    address: u64,
    /// Row data bytes.
    data: Vec<u8>,
}

impl Row {
    /// Whether `next` continues this row in flash and in the file: the next
    /// row number of the same array with the same size (`.cyacd`), or the
    /// next byte address (`.cyacd2`), on the next line.
    fn is_continued_by(&self, next: &Row) -> bool {
        let adjacent = next.line == self.line + 1;
        let contiguous = match self.array {
            Some(array) => {
                next.array == Some(array)
                    && next.address == self.address + 1
                    && next.data.len() == self.data.len()
            }
            None => next.address == self.address + self.data.len() as u64,
        };
        adjacent && contiguous
    }

    /// The address one past the row: the next row number (`.cyacd`) or
    /// byte address (`.cyacd2`).
    fn end(&self) -> u64 {
        match self.array {
            Some(_) => self.address + 1,
            None => self.address + self.data.len() as u64,
        }
    }
}

/// `.cyacd` row: array ID, row number (BE), data length N (BE), N data
/// bytes, checksum; the decoded size must be N + 6 and the bytes must sum
/// to zero modulo 256.
fn cyacd_row(line: &Line<'_>, index: usize) -> Result<Row> {
    let bytes = decode_hex(&line.text[1..], line.offset + 1)?;
    if bytes.len() < CYACD_ROW_OVERHEAD {
        return Err(error(format!("Truncated cyacd row at 0x{:X}", line.offset)));
    }
    let size = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if bytes.len() != size + CYACD_ROW_OVERHEAD {
        return Err(error(format!(
            "Invalid cyacd row at 0x{:X}: data length {size} B, {} B present",
            line.offset,
            bytes.len() - CYACD_ROW_OVERHEAD
        )));
    }
    if size == 0 {
        return Err(error(format!(
            "Invalid empty cyacd row at 0x{:X}",
            line.offset
        )));
    }
    let checksum_at = bytes.len() - 1;
    let sum = bytes[..checksum_at]
        .iter()
        .fold(0u8, |sum, b| sum.wrapping_add(*b));
    let expected = sum.wrapping_neg();
    if bytes[checksum_at] != expected {
        return Err(error(format!(
            "Invalid cyacd row checksum 0x{:02X} at 0x{:X}; computed 0x{expected:02X}",
            bytes[checksum_at], line.offset
        )));
    }
    Ok(Row {
        line: index,
        offset: line.offset,
        text_len: line.text.len(),
        array: Some(bytes[0]),
        address: u64::from(u16::from_be_bytes([bytes[1], bytes[2]])),
        data: bytes[CYACD_ROW_DATA_OFFSET..checksum_at].to_vec(),
    })
}

/// `.cyacd2` row: byte address (LE), then at least one data byte.
fn cyacd2_row(line: &Line<'_>, index: usize) -> Result<Row> {
    let bytes = decode_hex(&line.text[1..], line.offset + 1)?;
    if bytes.len() <= CYACD2_ADDRESS_SIZE {
        return Err(error(format!(
            "Truncated cyacd2 row at 0x{:X}",
            line.offset
        )));
    }
    let address = le_u32(&bytes, 0)?;
    Ok(Row {
        line: index,
        offset: line.offset,
        text_len: line.text.len(),
        array: None,
        address: u64::from(address),
        data: bytes[CYACD2_ADDRESS_SIZE..].to_vec(),
    })
}

/// `@APPINFO:0x<start>,0x<length>`: `__cy_app_verify_start` and
/// `__cy_app_verify_length`.
struct AppInfo {
    start: u32,
    length: u32,
}

/// `.cyacd2` metadata from `@APPINFO` and `@EIV` rows.
#[derive(Default)]
struct Metadata {
    app_info: Option<AppInfo>,
    /// Encryption initial vector; empty when the row carries none.
    eiv: Option<Vec<u8>>,
}

/// A hex word of one to eight digits.
fn hex_word(text: &[u8], offset: usize) -> Result<u32> {
    if text.is_empty() || text.len() > MAX_WORD_DIGITS {
        return Err(error(format!(
            "Invalid cyacd2 @APPINFO value at 0x{offset:X}"
        )));
    }
    let mut value = 0u32;
    for (i, digit) in text.iter().enumerate() {
        value = value << 4 | u32::from(hex_digit(*digit, offset + i)?);
    }
    Ok(value)
}

/// `@APPINFO:0x<start>,0x<length>` or `@EIV:<hex bytes>`.
fn metadata_row(line: &Line<'_>, metadata: &mut Metadata) -> Result<()> {
    if let Some(values) = line.text.strip_prefix(APPINFO_PREFIX) {
        if metadata.app_info.is_some() {
            return Err(error(format!(
                "Duplicate cyacd2 @APPINFO row at 0x{:X}",
                line.offset
            )));
        }
        let separator = values
            .windows(APPINFO_SEPARATOR.len())
            .position(|w| w == APPINFO_SEPARATOR)
            .ok_or_else(|| {
                error(format!(
                    "Invalid cyacd2 @APPINFO row at 0x{:X}",
                    line.offset
                ))
            })?;
        let start_offset = line.offset + APPINFO_PREFIX.len();
        let start = hex_word(&values[..separator], start_offset)?;
        let length_at = separator + APPINFO_SEPARATOR.len();
        let length = hex_word(&values[length_at..], start_offset + length_at)?;
        metadata.app_info = Some(AppInfo { start, length });
        return Ok(());
    }
    if let Some(vector) = line.text.strip_prefix(EIV_PREFIX) {
        if metadata.eiv.is_some() {
            return Err(error(format!(
                "Duplicate cyacd2 @EIV row at 0x{:X}",
                line.offset
            )));
        }
        metadata.eiv = Some(decode_hex(vector, line.offset + EIV_PREFIX.len())?);
        return Ok(());
    }
    Err(error(format!(
        "Unknown cyacd2 metadata row at 0x{:X}",
        line.offset
    )))
}

/// Reject `.cyacd` rows that repeat an (array, row) pair and `.cyacd2`
/// rows whose byte ranges overlap. After sorting, any overlap shows between
/// neighbours of the same array.
fn check_unique(rows: &[Row]) -> Result<()> {
    let mut extents: Vec<(Option<u8>, u64, u64, usize)> = rows
        .iter()
        .map(|row| (row.array, row.address, row.end(), row.offset))
        .collect();
    extents.sort_unstable();
    for pair in extents.windows(2) {
        let (array, _, end, offset) = pair[0];
        let (next_array, next_start, _, next_offset) = pair[1];
        if array != next_array || next_start >= end {
            continue;
        }
        return Err(error(match array {
            Some(id) => format!(
                "Duplicate cyacd row {next_start} of array {id} at 0x{offset:X} and \
                 0x{next_offset:X}"
            ),
            None => format!(
                "Overlapping cyacd2 rows at 0x{offset:X} and 0x{next_offset:X} for address \
                 0x{next_start:X}"
            ),
        }));
    }
    Ok(())
}

/// Parse a `.cyacd` or `.cyacd2` file into load sections of merged rows.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    if header_layout(data) != Some(layout) {
        return Err(error(format!(
            "Invalid {} header line at 0x0",
            layout.label()
        )));
    }
    let lines = lines(data)?;
    let header = decode_hex(lines[0].text, 0)?;
    let mut c = Container::new(FileFormat::Cyacd, layout.label(), layout.key_prefix());
    c.consumed = data.len();
    let checksum_type = match layout {
        Layout::Cyacd => cyacd_header(&mut c, &header)?,
        _ => cyacd2_header(&mut c, &header)?,
    };
    let mut rows = Vec::new();
    let mut metadata = Metadata::default();
    for (index, line) in lines.iter().enumerate().skip(1) {
        match (line.text[0], layout) {
            (ROW_PREFIX, Layout::Cyacd) => rows.push(cyacd_row(line, index)?),
            (ROW_PREFIX, _) => rows.push(cyacd2_row(line, index)?),
            (METADATA_PREFIX, Layout::Cyacd2) => metadata_row(line, &mut metadata)?,
            _ => {
                return Err(error(format!(
                    "Invalid {} line at 0x{:X}",
                    layout.label(),
                    line.offset
                )))
            }
        }
    }
    if rows.is_empty() {
        return Err(error(format!("Missing {} data rows", layout.label())));
    }
    check_unique(&rows)?;
    let row_evidence = match layout {
        Layout::Cyacd => "every row checksum verified",
        _ => "rows carry no checksum in the file",
    };
    c.notes.push(format!(
        "{}: {}, {} B; {row_evidence}; the silicon ID names a device, not an ISA",
        layout.label(),
        count(rows.len(), "row", "rows"),
        rows.iter().map(|row| row.data.len()).sum::<usize>()
    ));
    if layout == Layout::Cyacd {
        c.notes.push(
            "Section addresses are flash row numbers within the named array; the row size and \
             array base are not encoded"
                .to_string(),
        );
    }
    push_sections(&mut c, rows);
    let packet_checksum = if checksum_type == SUM_CHECKSUM {
        "16-bit sum"
    } else {
        "CRC-16"
    };
    c.push_metadata(
        "cyacd_packet_checksum",
        "Bootloader packet checksum",
        packet_checksum,
    );
    cyacd2_metadata(&mut c, metadata);
    Ok(c)
}

/// `.cyacd` header: silicon ID (BE), silicon revision, checksum type.
fn cyacd_header(c: &mut Container<'_>, header: &[u8]) -> Result<u8> {
    let silicon_id = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let checksum_type = checksum_type(header[5], 5)?;
    c.push_metadata(
        "cyacd_silicon_id",
        "Silicon ID",
        format!("0x{silicon_id:08X}"),
    );
    c.push_metadata(
        "cyacd_silicon_revision",
        "Silicon revision",
        u64::from(header[4]),
    );
    Ok(checksum_type)
}

/// `.cyacd2` header: file version, silicon ID (LE), silicon revision,
/// checksum type, app ID, product ID (LE).
fn cyacd2_header(c: &mut Container<'_>, header: &[u8]) -> Result<u8> {
    if header[0] != CYACD2_FILE_VERSION {
        return Err(error(format!(
            "Unsupported cyacd2 file version {}",
            header[0]
        )));
    }
    let silicon_id = le_u32(header, 1)?;
    let checksum_type = checksum_type(header[6], 6)?;
    let product_id = le_u32(header, 8)?;
    c.push_metadata("cyacd_file_version", "File version", u64::from(header[0]));
    c.push_metadata(
        "cyacd_silicon_id",
        "Silicon ID",
        format!("0x{silicon_id:08X}"),
    );
    c.push_metadata(
        "cyacd_silicon_revision",
        "Silicon revision",
        u64::from(header[5]),
    );
    c.push_metadata("cyacd_app_id", "Application ID", u64::from(header[7]));
    c.push_metadata(
        "cyacd_product_id",
        "Product ID",
        format!("0x{product_id:08X}"),
    );
    Ok(checksum_type)
}

/// A header checksum type at decoded header byte `at` (file offset
/// `2 * at`).
fn checksum_type(value: u8, at: usize) -> Result<u8> {
    if value == SUM_CHECKSUM || value == CRC_CHECKSUM {
        Ok(value)
    } else {
        Err(error(format!(
            "Unsupported cyacd checksum type {value} at 0x{:X}",
            2 * at
        )))
    }
}

/// Merge rows that continue each other into load sections.
fn push_sections(c: &mut Container<'_>, rows: Vec<Row>) {
    let mut runs: Vec<Vec<Row>> = Vec::new();
    for row in rows {
        match runs.last_mut() {
            Some(run) if run.last().is_some_and(|last| last.is_continued_by(&row)) => run.push(row),
            _ => runs.push(vec![row]),
        }
    }
    let mut sections = Sections::new();
    for run in runs {
        let first = &run[0];
        let last = &run[run.len() - 1];
        let label = match first.array {
            Some(array) if run.len() == 1 => format!("Array {array} row {}", first.address),
            Some(array) => format!("Array {array} rows {}-{}", first.address, last.address),
            None => format!("Load section {}", c.sections.len() + 1),
        };
        let address = first.address;
        let offset = first.offset;
        let stored_size = last.offset + last.text_len - offset;
        let mut bytes = Vec::with_capacity(run.iter().map(|row| row.data.len()).sum());
        for row in &run {
            bytes.extend_from_slice(&row.data);
        }
        sections.push(
            c,
            transformed_section(label, address, offset, stored_size, bytes, HEX_TRANSFORM),
        );
    }
    sections.finish(c);
}

/// `@APPINFO` as metadata; a non-empty `@EIV` makes the rows opaque.
fn cyacd2_metadata(c: &mut Container<'_>, metadata: Metadata) {
    if let Some(app_info) = metadata.app_info {
        c.push_metadata(
            "cyacd_app_verify_start",
            "Application verify start",
            format!("0x{:X}", app_info.start),
        );
        c.push_metadata(
            "cyacd_app_verify_length",
            "Application verify length",
            format!("0x{:X}", app_info.length),
        );
    }
    match metadata.eiv {
        None => {}
        Some(vector) if vector.is_empty() => c
            .notes
            .push("@EIV row carries no vector; rows analyzed as plaintext".to_string()),
        Some(vector) => {
            c.push_metadata(
                "cyacd_eiv",
                "Encryption initial vector",
                hex_string(&vector),
            );
            c.opaque = true;
            c.notes.push(
                "@EIV row present: data rows are treated as encrypted and not analyzed".to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_checksum_is_the_twos_complement_of_the_byte_sum() {
        // Array 0, row 1, two data bytes AA 55: the sum is 0x02, so the
        // checksum is 0xFE.
        let line = Line {
            offset: 0,
            text: b":0000010002AA55FE",
        };
        let row = cyacd_row(&line, 1).unwrap();
        assert_eq!(row.array, Some(0));
        assert_eq!(row.address, 1);
        assert_eq!(row.data, [0xaa, 0x55]);
        let bad = Line {
            offset: 0,
            text: b":0000010002AA55FF",
        };
        assert!(cyacd_row(&bad, 1).is_err());
    }

    #[test]
    fn header_layout_reads_only_the_first_line() {
        assert_eq!(header_layout(b"1E8C11690000\n:"), Some(Layout::Cyacd));
        assert_eq!(
            header_layout(b"01AABBCCDD110001EEFF0011\r\n"),
            Some(Layout::Cyacd2)
        );
        assert_eq!(header_layout(b"02AABBCCDD110001EEFF0011\n"), None);
        assert_eq!(header_layout(b":1E8C11690000\n"), None);
        assert_eq!(header_layout(&[0xff; 12]), None);
    }

    #[test]
    fn hex_values_are_bounded_and_case_insensitive() {
        assert_eq!(hex_word(b"10000000", 0).unwrap(), 0x1000_0000);
        assert!(hex_word(b"100000000", 0).is_err());
        assert!(hex_word(b"", 0).is_err());
        assert!(hex_word(b"12G4", 0).is_err());
        assert_eq!(decode_hex(b"aBfF", 0).unwrap(), [0xab, 0xff]);
        assert!(decode_hex(b"abc", 0).is_err());
    }
}
