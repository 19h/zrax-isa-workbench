//! Volvo/Ford Binary Format (VBF) container parser.
//!
//! VBF files are a flash programming container format used by Volvo and Ford
//! for ECU firmware updates via diagnostic tools (VIDA, IDS, FDRS).
//!
//! # Container Structure
//!
//! ```text
//! +---------------------------------------------+
//! | ASCII Header (plaintext, variable size)      |
//! | Starts: "vbf_version = X.Y;\nheader\n{\n"   |
//! | Contains: metadata key-value pairs           |
//! | Ends: closing "}" at brace depth 0           |
//! +---------------------------------------------+
//! | Block 0: [4B addr BE][4B len BE][data][2B CRC16] |
//! +---------------------------------------------+
//! | Block 1: [4B addr BE][4B len BE][data][2B CRC16] |
//! +---------------------------------------------+
//! | ...                                          |
//! +---------------------------------------------+
//! ```
//!
//! # Header Format
//!
//! The header is ASCII text with a C-like syntax:
//! ```text
//! vbf_version = 2.3;
//! header
//! {
//!     sw_part_number = "FV6P-7J104-JB";
//!     sw_part_type = EXE;
//!     network = CAN_HS;
//!     ecu_address = 0x7E1;
//!     frame_format = CAN_STANDARD;
//!     description = { "line1" "line2" };
//!     erase = { {0x80000000, 0x20000} };
//!     file_checksum = 0xB18398B6;
//! }
//! ```
//!
//! # Binary Blocks
//!
//! After the header, the file contains a sequence of binary data blocks.
//! Each block has:
//! - 4-byte big-endian start address (flash memory target)
//! - 4-byte big-endian length
//! - `length` bytes of raw firmware payload
//! - 2-byte CRC-16/CCITT-FALSE over the payload
//!
//! # ISA Identification
//!
//! The flash addresses reveal the target MCU architecture:
//! - `0x80xxxxxx` / `0xA0xxxxxx` → Infineon TriCore (PFlash / DFlash)
//! - `0x0001xxxx`–`0x001Fxxxx` → Freescale/NXP PowerPC MPC56xx
//! - `0x08xxxxxx` → ARM Cortex-M (STM32 flash)
//! - `0x00xxxxxx` (low addresses) → Various embedded MCUs
//!
//! The CHIPID field in the description may also identify the exact MCU.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, ClassificationSource, Endianness, FileFormat, Isa};

/// Magic prefix: "vbf_version"
const MAGIC_PREFIX: &[u8] = b"vbf_version";

/// Minimum file size for a valid VBF file.
const MIN_VBF_SIZE: usize = 32;

/// A parsed VBF data block.
#[derive(Debug)]
struct VbfBlock {
    /// Flash target address (big-endian u32).
    address: u32,
    /// Block data length.
    length: u32,
    /// Offset into the file where payload data begins.
    data_offset: usize,
}

/// Parsed VBF header fields.
#[derive(Debug, Default)]
struct VbfHeader {
    /// VBF version string (e.g., "2.3").
    version: Option<String>,
    /// Software part number.
    sw_part_number: Option<String>,
    /// Software part type (EXE, CAL, DATA, SBL).
    sw_part_type: Option<String>,
    /// CAN network type.
    network: Option<String>,
    /// ECU UDS diagnostic address.
    ecu_address: Option<u32>,
    /// Frame format.
    frame_format: Option<String>,
    /// File checksum.
    file_checksum: Option<u32>,
    /// Description lines.
    description: Vec<String>,
    /// Erase regions (address, length).
    erase_regions: Vec<(u32, u32)>,
    /// Byte offset where binary data starts (after header closing brace).
    binary_start: usize,
}

/// Detect whether the given data is a VBF file.
///
/// VBF files start with the ASCII string `"vbf_version"`.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < MIN_VBF_SIZE {
        return false;
    }
    // Skip optional BOM or leading whitespace
    let start = skip_whitespace(data, 0);
    if start + MAGIC_PREFIX.len() > data.len() {
        return false;
    }
    &data[start..start + MAGIC_PREFIX.len()] == MAGIC_PREFIX
}

/// Parse the VBF container and classify the contained firmware.
///
/// Extracts metadata from the ASCII header, then parses the binary block
/// structure to determine the target ISA from flash addresses. If the
/// payload is extractable, runs heuristic analysis on the concatenated blocks.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MIN_VBF_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: MIN_VBF_SIZE,
            actual: data.len(),
        });
    }

    // Parse the ASCII header
    let header = parse_header(data)?;

    // Parse binary blocks
    let blocks = parse_blocks(data, header.binary_start);

    // Determine ISA from flash addresses
    let (isa, endianness, bitwidth, addr_note) = classify_from_addresses(&blocks);

    // Also try CHIPID from description
    let (chip_isa, chip_note) = classify_from_chipid(&header.description);

    // Pick best classification
    let (final_isa, final_endian, final_bits, platform_note) = if chip_isa != Isa::Unknown(0) {
        // CHIPID is more specific than address ranges
        let endian = match chip_isa {
            Isa::Ppc | Isa::Ppc64 => Endianness::Big,
            _ => Endianness::Little,
        };
        let bits: u8 = match chip_isa {
            Isa::Ppc64 | Isa::AArch64 => 64,
            _ => 32,
        };
        (chip_isa, endian, bits, chip_note)
    } else if isa != Isa::Unknown(0) {
        (isa, endianness, bitwidth, addr_note)
    } else {
        (Isa::Unknown(0), Endianness::Little, 0, None)
    };

    let mut result =
        ClassificationResult::from_format(final_isa, final_bits, final_endian, FileFormat::Vbf);

    if final_isa != Isa::Unknown(0) {
        result.confidence = 0.92;
        result.source = ClassificationSource::Combined;
    } else {
        result.confidence = 0.0;
    }

    // Add metadata notes
    result
        .metadata
        .notes
        .push("Volvo/Ford VBF firmware container".into());

    if let Some(ref ver) = header.version {
        result.metadata.notes.push(format!("VBF version: {}", ver));
    }
    if let Some(ref pn) = header.sw_part_number {
        result.metadata.notes.push(format!("Part number: {}", pn));
    }
    if let Some(ref pt) = header.sw_part_type {
        result.metadata.notes.push(format!("Part type: {}", pt));
    }
    if let Some(addr) = header.ecu_address {
        result
            .metadata
            .notes
            .push(format!("ECU address: 0x{:03X}", addr));
    }
    if let Some(ref net) = header.network {
        result.metadata.notes.push(format!("Network: {}", net));
    }
    if let Some(note) = platform_note {
        result.metadata.notes.push(format!("Platform: {}", note));
    }

    // Block summary
    if !blocks.is_empty() {
        let total_payload: usize = blocks.iter().map(|b| b.length as usize).sum();
        result.metadata.notes.push(format!(
            "{} data block(s), {} bytes total payload",
            blocks.len(),
            total_payload
        ));

        // Show address ranges
        for (i, block) in blocks.iter().take(4).enumerate() {
            result.metadata.notes.push(format!(
                "Block {}: 0x{:08X}, {} bytes",
                i, block.address, block.length
            ));
        }
        if blocks.len() > 4 {
            result
                .metadata
                .notes
                .push(format!("... and {} more block(s)", blocks.len() - 4));
        }
    }

    // Description lines
    for desc in &header.description {
        let trimmed = desc.trim();
        if !trimmed.is_empty() {
            result
                .metadata
                .notes
                .push(format!("Description: {}", trimmed));
        }
    }

    result
        .metadata
        .notes
        .push("Payload blocks contain unencrypted firmware (heuristic analysis possible)".into());

    Ok(result)
}

/// Parse the VBF container and also return the concatenated payload bytes.
///
/// This is the container-aware entry point used by `detect_payload()` in lib.rs
/// to feed extracted firmware blocks to the heuristic ISA analyzer.
pub fn parse_with_payload(data: &[u8]) -> Result<(ClassificationResult, Vec<u8>)> {
    let result = parse(data)?;

    // Extract concatenated payload from all blocks
    let header = parse_header(data)?;
    let blocks = parse_blocks(data, header.binary_start);
    let mut payload = Vec::new();
    for block in &blocks {
        let end = block.data_offset + block.length as usize;
        if end <= data.len() {
            payload.extend_from_slice(&data[block.data_offset..end]);
        }
    }

    Ok((result, payload))
}

// ============================================================================
// Header parsing
// ============================================================================

/// Find a keyword in text that is not part of a larger word.
/// The keyword must be preceded by whitespace/newline/BOF and followed by
/// whitespace/'{'/EOF.
fn find_standalone_keyword(text: &str, keyword: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(pos) = text[search_start..].find(keyword) {
        let abs_pos = search_start + pos;
        // Check preceding character
        let preceded_ok = abs_pos == 0
            || text.as_bytes()[abs_pos - 1].is_ascii_whitespace()
            || text.as_bytes()[abs_pos - 1] == b';';
        // Check following character
        let end_pos = abs_pos + keyword.len();
        let followed_ok = end_pos >= text.len()
            || text.as_bytes()[end_pos].is_ascii_whitespace()
            || text.as_bytes()[end_pos] == b'{';
        if preceded_ok && followed_ok {
            return Some(abs_pos);
        }
        search_start = abs_pos + 1;
    }
    None
}

/// Skip ASCII whitespace (space, tab, CR, LF).
fn skip_whitespace(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && matches!(data[pos], b' ' | b'\t' | b'\r' | b'\n') {
        pos += 1;
    }
    pos
}

/// Parse the ASCII header, extracting key-value fields.
fn parse_header(data: &[u8]) -> Result<VbfHeader> {
    let mut header = VbfHeader::default();

    // Find vbf_version line.
    // The header is ASCII text but the file also contains binary data after the
    // closing brace, so from_utf8 will fail on the full slice. Use lossy conversion
    // only up to the first non-ASCII byte, or use String::from_utf8_lossy.
    let text_end = data.len().min(64 * 1024);
    let text = String::from_utf8_lossy(&data[..text_end]);

    let text = &*text; // Cow -> &str

    // Extract version
    if let Some(pos) = text.find("vbf_version") {
        if let Some(eq) = text[pos..].find('=') {
            let after_eq = &text[pos + eq + 1..];
            if let Some(semi) = after_eq.find(';') {
                header.version = Some(after_eq[..semi].trim().to_string());
            }
        }
    }

    // Find the standalone "header" keyword (not inside another word like "frame_format")
    // It must be preceded by whitespace/newline/BOF and followed by whitespace or "{"
    let header_start = find_standalone_keyword(text, "header");
    if header_start.is_none() {
        return Err(ClassifierError::InvalidMagic {
            expected: "VBF header block".into(),
            actual: "no 'header' keyword found".into(),
        });
    }

    // Find the opening brace of the header block
    let header_start = header_start.unwrap();
    let after_header = &text[header_start + 6..];
    let open_brace = after_header.find('{');
    if open_brace.is_none() {
        return Err(ClassifierError::InvalidMagic {
            expected: "VBF header opening brace".into(),
            actual: "no '{' after 'header'".into(),
        });
    }

    let content_start = header_start + 6 + open_brace.unwrap() + 1;

    // Track brace depth to find the closing brace. We start at depth=1
    // (we've consumed the opening brace of `header {`).
    let mut depth: i32 = 1;
    let mut pos = content_start;
    let mut in_string = false;
    let bytes = text.as_bytes();

    while pos < bytes.len() && depth > 0 {
        match bytes[pos] {
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        pos += 1;
    }

    if depth != 0 {
        return Err(ClassifierError::InvalidMagic {
            expected: "VBF header closing brace".into(),
            actual: "unbalanced braces in header".into(),
        });
    }

    // pos now points at the closing `}` byte
    header.binary_start = pos + 1;

    // Extract the header content between braces
    let header_content = &text[content_start..pos];

    // Parse key = value pairs
    parse_header_fields(header_content, &mut header);

    Ok(header)
}

/// Parse individual header fields from the header content string.
fn parse_header_fields(content: &str, header: &mut VbfHeader) {
    // Simple key=value parser for semicolon-terminated fields
    // We need to handle nested braces for description, erase, omit

    let bytes = content.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        // Skip whitespace
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        // Skip comments (// to end of line)
        if pos + 1 < bytes.len() && bytes[pos] == b'/' && bytes[pos + 1] == b'/' {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }

        // Read key name
        let key_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'=' {
            pos += 1;
        }
        let key = &content[key_start..pos];

        // Skip to '='
        while pos < bytes.len() && bytes[pos] != b'=' {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        pos += 1; // skip '='

        // Skip whitespace after '='
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // Read value (may be simple, quoted, or brace-enclosed)
        if pos >= bytes.len() {
            break;
        }

        let value = if bytes[pos] == b'{' {
            // Brace-enclosed value — find matching close
            let start = pos;
            let mut depth = 0i32;
            let mut in_str = false;
            while pos < bytes.len() {
                match bytes[pos] {
                    b'"' => in_str = !in_str,
                    b'{' if !in_str => depth += 1,
                    b'}' if !in_str => {
                        depth -= 1;
                        if depth == 0 {
                            pos += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                pos += 1;
            }
            // Skip trailing semicolon
            if pos < bytes.len() && bytes[pos] == b';' {
                pos += 1;
            }
            &content[start..pos.min(content.len())]
        } else if bytes[pos] == b'"' {
            // Quoted string
            pos += 1;
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                pos += 1;
            }
            let val = &content[start..pos];
            if pos < bytes.len() {
                pos += 1;
            } // skip closing quote
              // Skip trailing semicolon
            while pos < bytes.len() && bytes[pos] != b';' {
                pos += 1;
            }
            if pos < bytes.len() {
                pos += 1;
            }
            val
        } else {
            // Simple value terminated by semicolon
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b';' {
                pos += 1;
            }
            let val = content[start..pos].trim();
            if pos < bytes.len() {
                pos += 1;
            }
            val
        };

        // Store parsed fields
        match key {
            "sw_part_number" => {
                header.sw_part_number = Some(value.trim_matches('"').to_string());
            }
            "sw_part_type" => {
                header.sw_part_type = Some(value.trim().to_string());
            }
            "network" => {
                header.network = Some(value.trim().to_string());
            }
            "ecu_address" => {
                header.ecu_address = parse_hex_u32(value.trim());
            }
            "frame_format" => {
                header.frame_format = Some(value.trim().to_string());
            }
            "file_checksum" => {
                header.file_checksum = parse_hex_u32(value.trim());
            }
            "description" => {
                // Extract quoted strings from the braces
                parse_description(value, &mut header.description);
            }
            "erase" => {
                parse_address_pairs(value, &mut header.erase_regions);
            }
            _ => {} // ignore unknown keys
        }
    }
}

/// Parse a hex string like "0x7E1" into u32.
fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim().trim_matches('"');
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

/// Extract quoted strings from a description block like `{ "line1" "line2" }`.
fn parse_description(value: &str, out: &mut Vec<String>) {
    let mut pos = 0;
    let bytes = value.as_bytes();
    while pos < bytes.len() {
        if bytes[pos] == b'"' {
            pos += 1;
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                pos += 1;
            }
            out.push(value[start..pos].to_string());
            if pos < bytes.len() {
                pos += 1;
            }
        } else {
            pos += 1;
        }
    }
}

/// Parse address/length pairs from erase/omit blocks like `{ {0x80000000, 0x20000} }`.
fn parse_address_pairs(value: &str, out: &mut Vec<(u32, u32)>) {
    // Find all inner {addr, len} pairs.
    // The structure is: { {addr1, len1} {addr2, len2} ... }
    // We need to find each inner {} pair and extract the comma-separated values.
    let bytes = value.as_bytes();
    let mut depth = 0i32;
    let mut inner_start = 0usize;
    let mut pos = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b'{' => {
                depth += 1;
                if depth == 2 {
                    // Start of an inner pair
                    inner_start = pos + 1;
                }
            }
            b'}' => {
                if depth == 2 {
                    // End of an inner pair
                    let inner = &value[inner_start..pos];
                    if let Some(comma) = inner.find(',') {
                        let addr = parse_hex_u32(inner[..comma].trim());
                        let len = parse_hex_u32(inner[comma + 1..].trim());
                        if let (Some(a), Some(l)) = (addr, len) {
                            out.push((a, l));
                        }
                    }
                }
                depth -= 1;
            }
            _ => {}
        }
        pos += 1;
    }
}

// ============================================================================
// Binary block parsing
// ============================================================================

/// Parse binary data blocks after the header.
fn parse_blocks(data: &[u8], start: usize) -> Vec<VbfBlock> {
    let mut blocks = Vec::new();
    let mut pos = start;

    while pos + 8 <= data.len() {
        let addr = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let length =
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);

        // Sanity checks
        if length == 0 || length > 16 * 1024 * 1024 {
            break; // Invalid block
        }
        let block_end = pos + 8 + length as usize + 2; // +2 for CRC
        if block_end > data.len() {
            break; // Truncated block
        }

        blocks.push(VbfBlock {
            address: addr,
            length,
            data_offset: pos + 8,
        });

        pos = block_end;
    }

    blocks
}

// ============================================================================
// ISA classification from flash addresses
// ============================================================================

/// Classify ISA from flash memory address ranges.
fn classify_from_addresses(blocks: &[VbfBlock]) -> (Isa, Endianness, u8, Option<String>) {
    if blocks.is_empty() {
        return (Isa::Unknown(0), Endianness::Little, 0, None);
    }

    let mut has_tricore_pflash = false; // 0x80xxxxxx
    let mut has_tricore_dflash = false; // 0xA0xxxxxx
    let mut has_ppc_flash = false; // 0x0001xxxx-0x001Fxxxx
    let mut has_arm_flash = false; // 0x08xxxxxx
    let mut has_arm_low = false; // 0x00000000-0x000FFFFF (Cortex-M)

    for block in blocks {
        let addr = block.address;
        match addr >> 24 {
            0x80 | 0x8F => has_tricore_pflash = true,
            0xA0 | 0xAF => has_tricore_dflash = true,
            0x08 => has_arm_flash = true,
            0x00 => {
                if addr >= 0x00010000 && addr <= 0x001FFFFF {
                    has_ppc_flash = true;
                } else if addr < 0x00100000 {
                    has_arm_low = true;
                }
            }
            _ => {}
        }
    }

    if has_tricore_pflash || has_tricore_dflash {
        (
            Isa::Tricore,
            Endianness::Little,
            32,
            Some("Infineon TriCore (flash at 0x80xxxxxx/0xA0xxxxxx)".into()),
        )
    } else if has_ppc_flash {
        (
            Isa::Ppc,
            Endianness::Big,
            32,
            Some("Freescale/NXP PowerPC MPC56xx (flash at 0x0001xxxx)".into()),
        )
    } else if has_arm_flash {
        (
            Isa::Arm,
            Endianness::Little,
            32,
            Some("ARM Cortex-M (flash at 0x08xxxxxx, STM32-style)".into()),
        )
    } else if has_arm_low {
        (
            Isa::Arm,
            Endianness::Little,
            32,
            Some("ARM (flash at low address range)".into()),
        )
    } else {
        (Isa::Unknown(0), Endianness::Little, 0, None)
    }
}

/// Try to identify the MCU from CHIPID in description strings.
fn classify_from_chipid(description: &[String]) -> (Isa, Option<String>) {
    for line in description {
        if let Some(chipid_pos) = line.find("CHIPID:") {
            let after = line[chipid_pos + 7..].trim();
            // CHIPID is typically a hex string like "0x80080162"
            if let Some(id) = parse_hex_u32(after.split_whitespace().next().unwrap_or("")) {
                return classify_chipid(id);
            }
        }
        // Also look for "CHIPID" as a standalone description key
        let upper = line.to_uppercase();
        if upper.starts_with("CHIPID") {
            if let Some(val) = line.split_whitespace().last() {
                if let Some(id) = parse_hex_u32(val) {
                    return classify_chipid(id);
                }
            }
        }
    }
    (Isa::Unknown(0), None)
}

/// Map a CHIPID value to an ISA.
fn classify_chipid(id: u32) -> (Isa, Option<String>) {
    // Common automotive MCU CHIPIDs
    match id {
        // Infineon TriCore TC17xx
        0x80080162 => (
            Isa::Tricore,
            Some("Infineon SAK-TC1782 (TriCore AUDO-NG)".into()),
        ),
        0x80080142 => (
            Isa::Tricore,
            Some("Infineon SAK-TC1767 (TriCore TC1.6P)".into()),
        ),
        0x80080172 => (
            Isa::Tricore,
            Some("Infineon SAK-TC1797 (TriCore AUDO-NG)".into()),
        ),
        // Freescale/NXP MPC56xx
        0x102A2 => (Isa::Ppc, Some("Freescale MPC5644A (PowerPC e200z4)".into())),
        0x10242 => (Isa::Ppc, Some("Freescale MPC5634M (PowerPC e200z3)".into())),
        0x10282 => (Isa::Ppc, Some("Freescale MPC5643L (PowerPC e200z4)".into())),
        // Renesas SH7058
        0x7058 => (Isa::Sh, Some("Renesas SH7058 (SuperH SH-2A)".into())),
        _ => {
            // Try heuristic ranges
            if id >= 0x80080000 && id <= 0x800801FF {
                (
                    Isa::Tricore,
                    Some(format!("Infineon TriCore (CHIPID 0x{:08X})", id)),
                )
            } else if id >= 0x10000 && id <= 0x1FFFF {
                (
                    Isa::Ppc,
                    Some(format!("Freescale/NXP PowerPC (CHIPID 0x{:05X})", id)),
                )
            } else {
                (Isa::Unknown(0), None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal VBF file with given header and blocks.
    fn make_test_vbf(part_number: &str, blocks: &[(u32, &[u8])]) -> Vec<u8> {
        let header = format!(
            "vbf_version = 2.3;\nheader\n{{\n  sw_part_number = \"{}\";\n  \
             sw_part_type = EXE;\n  network = CAN_HS;\n  ecu_address = 0x7E1;\n  \
             frame_format = CAN_STANDARD;\n  file_checksum = 0x00000000;\n}}",
            part_number
        );
        let mut data = header.into_bytes();

        for (addr, payload) in blocks {
            data.extend_from_slice(&addr.to_be_bytes());
            data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            data.extend_from_slice(payload);
            // Append dummy CRC16
            data.extend_from_slice(&[0x00, 0x00]);
        }

        data
    }

    #[test]
    fn test_detect_valid_vbf() {
        let data = make_test_vbf("FV6P-7J104-JB", &[(0x80000000, &[0u8; 64])]);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_rejects_non_vbf() {
        assert!(!detect(b"not a vbf file at all"));
        assert!(!detect(&[0x7F, b'E', b'L', b'F']));
    }

    #[test]
    fn test_detect_too_small() {
        assert!(!detect(b"vbf"));
    }

    #[test]
    fn test_parse_header() {
        let data = make_test_vbf("FV6P-7J104-JB", &[(0x80000000, &[0u8; 64])]);
        let header = parse_header(&data).unwrap();
        assert_eq!(header.version.as_deref(), Some("2.3"));
        assert_eq!(header.sw_part_number.as_deref(), Some("FV6P-7J104-JB"));
        assert_eq!(header.sw_part_type.as_deref(), Some("EXE"));
        assert_eq!(header.ecu_address, Some(0x7E1));
    }

    #[test]
    fn test_parse_blocks_tricore() {
        let data = make_test_vbf(
            "FV6P-7J104-JB",
            &[(0x80000000, &[0u8; 128]), (0xA0040000, &[0u8; 64])],
        );
        let header = parse_header(&data).unwrap();
        let blocks = parse_blocks(&data, header.binary_start);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].address, 0x80000000);
        assert_eq!(blocks[0].length, 128);
        assert_eq!(blocks[1].address, 0xA0040000);
        assert_eq!(blocks[1].length, 64);
    }

    #[test]
    fn test_classify_tricore_addresses() {
        let blocks = vec![
            VbfBlock {
                address: 0x80000000,
                length: 128,
                data_offset: 0,
            },
            VbfBlock {
                address: 0xA0040000,
                length: 64,
                data_offset: 0,
            },
        ];
        let (isa, endian, bits, _) = classify_from_addresses(&blocks);
        assert_eq!(isa, Isa::Tricore);
        assert_eq!(endian, Endianness::Little);
        assert_eq!(bits, 32);
    }

    #[test]
    fn test_classify_ppc_addresses() {
        let blocks = vec![
            VbfBlock {
                address: 0x00010008,
                length: 1024,
                data_offset: 0,
            },
            VbfBlock {
                address: 0x00180000,
                length: 512,
                data_offset: 0,
            },
        ];
        let (isa, endian, bits, _) = classify_from_addresses(&blocks);
        assert_eq!(isa, Isa::Ppc);
        assert_eq!(endian, Endianness::Big);
        assert_eq!(bits, 32);
    }

    #[test]
    fn test_classify_arm_addresses() {
        let blocks = vec![VbfBlock {
            address: 0x08000000,
            length: 256,
            data_offset: 0,
        }];
        let (isa, _, bits, _) = classify_from_addresses(&blocks);
        assert_eq!(isa, Isa::Arm);
        assert_eq!(bits, 32);
    }

    #[test]
    fn test_parse_full_vbf() {
        let data = make_test_vbf("FV6P-7J104-JB", &[(0x80000000, &[0u8; 128])]);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Tricore);
        assert_eq!(result.format, FileFormat::Vbf);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_parse_ppc_vbf() {
        let data = make_test_vbf("EL3A-14C204-ADA", &[(0x00010008, &[0u8; 256])]);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Ppc);
        assert_eq!(result.endianness, Endianness::Big);
    }

    #[test]
    fn test_parse_with_payload() {
        let payload_data = vec![0xAAu8; 128];
        let data = make_test_vbf("FV6P-7J104-JB", &[(0x80000000, &payload_data)]);
        let (result, extracted) = parse_with_payload(&data).unwrap();
        assert_eq!(result.isa, Isa::Tricore);
        assert_eq!(extracted.len(), 128);
        assert!(extracted.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_nested_braces_header() {
        // Verify parser handles nested braces in description and erase fields
        let header = "vbf_version = 2.3;\nheader\n{\n  \
            sw_part_number = \"TEST-1234\";\n  \
            description = { \"line 1\" \"line {2}\" };\n  \
            erase = { {0x80000000, 0x20000} {0x80020000, 0x20000} };\n  \
            file_checksum = 0x12345678;\n}";
        let mut data = header.as_bytes().to_vec();
        // Add one block
        data.extend_from_slice(&0x80000000u32.to_be_bytes());
        data.extend_from_slice(&16u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0u8; 2]); // CRC

        let parsed = parse_header(&data).unwrap();
        assert_eq!(parsed.sw_part_number.as_deref(), Some("TEST-1234"));
        assert_eq!(parsed.erase_regions.len(), 2);
        assert_eq!(parsed.erase_regions[0], (0x80000000, 0x20000));
    }

    #[test]
    fn test_chipid_classification() {
        let (isa, note) = classify_chipid(0x80080162);
        assert_eq!(isa, Isa::Tricore);
        assert!(note.unwrap().contains("TC1782"));

        let (isa, note) = classify_chipid(0x102A2);
        assert_eq!(isa, Isa::Ppc);
        assert!(note.unwrap().contains("MPC5644A"));
    }
}
