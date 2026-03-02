//! SGML Object File container format parser (SGO).
//!
//! SGO files (`.sgo`) are a proprietary binary container format used by
//! Volkswagen Group's **ODIS** (Offboard Diagnostic Information System)
//! and **VAS** diagnostic tools for distributing ECU firmware updates.
//! Despite the name "SGML Object File", they are NOT SGML/XML documents —
//! the name is a legacy artifact from VW's internal tooling.
//!
//! # Container Structure
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0x0000  16    Magic: "SGML Object File" (ASCII)
//! 0x0010   2    Version (big-endian u16, typically 0x0002)
//! 0x0012   2    Flags (big-endian u16, typically 0x0000)
//! 0x0014   4    Checksum / hash (variable per file)
//! 0x0018   1    Section count
//! 0x0019   1    Marker byte (always 0x31)
//! 0x001A   2    Reserved (0x0000)
//! 0x001C  16    Four section pointers (4 × [offset:u16, type:u16])
//!               Fixed values: (0x003E, 0x0100), (0x0092, 0x0100),
//!                             (0x00B2, 0x0100), (0x00B7, 0x0100)
//! 0x002C   4    Data descriptor (variable per file)
//! 0x0030   1    Separator byte (0x00)
//! 0x0031  var   XOR-0xFF encoded filename (null-terminated, ends with ".sgm")
//! ~0x0092 var   Zero-padded metadata region
//! ~0x0130 var   Revision string (XOR-0xFF encoded) + secondary metadata
//! ~0x0190 var   Section index table (u32 entries)
//! ~0x01B0 var   Compressed/encrypted firmware payload (to end of file)
//! ```
//!
//! # Filename Encoding
//!
//! The original filename is stored starting at offset 0x31, encoded by
//! XOR-ing each byte with 0xFF (bitwise NOT). The encoded filename always
//! ends with `.sgm` (encoded as `0xD1 0x8C 0x98 0x92`).
//!
//! # Payload Compression
//!
//! The firmware payload (starting around offset 0x1B0) is compressed and/or
//! encrypted using a proprietary scheme. Byte entropy analysis shows 7.2–7.9
//! bits/byte, confirming the payload is NOT raw machine code. Therefore, ISA
//! classification relies on metadata (part number → ECU platform mapping)
//! rather than heuristic code analysis.
//!
//! # Part Number → ECU Platform Mapping
//!
//! VW Group ECU part numbers follow a systematic scheme:
//! - First 3 chars: system group (e.g., `03C` = petrol engine Simos)
//! - Chars 3-6: component type (e.g., `906` = engine management)
//! - Chars 6-9: sub-component (e.g., `014` = variant)
//! - Suffix: revision letters (e.g., `A`, `AB`, `BC`)
//!
//! These part number prefixes map deterministically to ECU hardware platforms
//! and therefore to specific processor ISAs.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};

/// Magic bytes: "SGML Object File" (16 bytes ASCII).
pub const MAGIC: &[u8; 16] = b"SGML Object File";

/// Minimum file size for a valid SGO file (magic + header).
const MIN_SGO_SIZE: usize = 0x40;

/// Offset where the XOR-encoded filename starts.
const FILENAME_OFFSET: usize = 0x31;

/// Maximum filename length to decode.
const MAX_FILENAME_LEN: usize = 200;

/// ECU platform mapping from VW Group part number prefixes.
///
/// Each entry maps a 9-character part number prefix (or shorter for
/// broader matches) to an ECU hardware platform and ISA.
struct PartNumberMapping {
    /// Part number prefix to match (first N characters)
    prefix: &'static str,
    /// Resulting ISA
    isa: Isa,
    /// Endianness
    endianness: Endianness,
    /// Bitwidth
    bitwidth: u8,
    /// ECU platform description
    description: &'static str,
}

/// VW Group part number prefix → ECU platform → ISA mapping table.
///
/// Ordered from most specific to least specific. The first match wins.
///
/// Sources: VW Workshop manuals, Bosch ECU identification guides, Ross-Tech
/// VAG-COM documentation, and community ECU identification databases.
const PART_NUMBER_MAPPINGS: &[PartNumberMapping] = &[
    // ========================================================================
    // Diesel engine ECUs
    // ========================================================================
    // 03L906xxx = Bosch EDC17 (2.0 TDI Common Rail) → TriCore
    PartNumberMapping {
        prefix: "03L906",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch EDC17 (2.0 TDI CR, TriCore)",
    },
    // 03G906xxx = Bosch EDC16 (1.9/2.0 TDI Pumpe-Düse) → PowerPC MPC5xx
    PartNumberMapping {
        prefix: "03G906",
        isa: Isa::Ppc,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "Bosch EDC16 (TDI PD, MPC5xx/PowerPC)",
    },
    // 038906016/019 = Bosch EDC15/EDC16 (1.9 TDI VP/PD) → C166 (EDC15) or PPC (EDC16)
    // 038906016 = EDC15 → C166
    PartNumberMapping {
        prefix: "038906016",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch EDC15 (1.9 TDI VP, C166)",
    },
    // 038906019 = EDC16 → PowerPC
    PartNumberMapping {
        prefix: "038906019",
        isa: Isa::Ppc,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "Bosch EDC16 (1.9 TDI PD, MPC5xx/PowerPC)",
    },
    // 038997xxx = EEPROM data for diesel ECU
    PartNumberMapping {
        prefix: "038997",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Diesel ECU EEPROM data (C166-era)",
    },
    // 04L906xxx = Bosch EDC17/MD1 (EA288 2.0 TDI) → TriCore
    PartNumberMapping {
        prefix: "04L906",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch EDC17/MD1 (EA288 TDI, TriCore)",
    },
    // ========================================================================
    // Petrol engine ECUs — Simos family (03C prefix)
    // ========================================================================
    // 03C906014/016 = Simos 7.x (early, ST10F275/C167) → C166
    // 03C906021/022 = Simos 9.x/10.x → TriCore (TC1766/TC1767)
    // 03C906024/027 = Simos 10.x/12.x → TriCore
    // 03C906032 = Simos 6.x → C166
    // 03C906056 = Continental Simos 18.x → TriCore (TC277)
    PartNumberMapping {
        prefix: "03C906056",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Continental Simos 18 (1.0/1.5 TSI, TriCore TC277)",
    },
    PartNumberMapping {
        prefix: "03C906027",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Continental Simos 12 (1.4 TSI, TriCore)",
    },
    PartNumberMapping {
        prefix: "03C906024",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Continental Simos 10 (1.4 TSI, TriCore)",
    },
    PartNumberMapping {
        prefix: "03C906022",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Continental Simos 9/10 (1.4 TSI, TriCore)",
    },
    PartNumberMapping {
        prefix: "03C906021",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Continental Simos 9 (1.4 TSI, TriCore)",
    },
    // 03C906014/016/032 = Simos 7.x / Simos 6.x → C166
    PartNumberMapping {
        prefix: "03C906032",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Continental Simos 6 (1.4/1.6 FSI, C166/ST10)",
    },
    PartNumberMapping {
        prefix: "03C906014",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Continental Simos 7 (1.4/1.6 FSI, C166/ST10F275)",
    },
    PartNumberMapping {
        prefix: "03C906016",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Continental Simos 7 (1.4/1.6 FSI, C166/ST10F275)",
    },
    // 03C906 catch-all for remaining Simos variants
    PartNumberMapping {
        prefix: "03C906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Continental Simos (petrol, likely C166/ST10)",
    },
    // ========================================================================
    // Petrol engine ECUs — Bosch ME/MED family
    // ========================================================================
    // 06J906xxx = Bosch MED17.5 (EA888 2.0 TSI Gen1/2) → TriCore
    PartNumberMapping {
        prefix: "06J906",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MED17.5 (2.0 TSI, TriCore)",
    },
    // 06F906xxx = Bosch MED9.1 (EA113 2.0 TFSI) → TriCore (TC1766)
    PartNumberMapping {
        prefix: "06F906",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MED9.1 (2.0 TFSI, TriCore TC1766)",
    },
    // 06A906xxx = Bosch ME7.5 (EA113 1.8T / 2.0) → C166
    PartNumberMapping {
        prefix: "06A906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.5 (1.8T/2.0, C166/C167)",
    },
    // 07K906xxx = Bosch ME7.1 / Simos 6 (2.5L I5) → C166
    PartNumberMapping {
        prefix: "07K906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.1 (2.5L I5, C166/C167)",
    },
    // 022906xxx = Bosch ME7.1 (2.8 VR6 / 3.2 V6) → C166
    PartNumberMapping {
        prefix: "022906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.1 (2.8/3.2 VR6, C166/C167)",
    },
    // 030906xxx = Bosch ME7.1 / Simos (various petrol) → C166
    PartNumberMapping {
        prefix: "030906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.1 (petrol, C166/C167)",
    },
    // 032906xxx = Bosch Motronic ME7 (2.8 VR6 / V6) → C166
    PartNumberMapping {
        prefix: "032906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7 (VR6/V6, C166/C167)",
    },
    // 036906xxx = Bosch ME7.5 (1.6/2.0 petrol) → C166
    PartNumberMapping {
        prefix: "036906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.5 (1.6/2.0 petrol, C166/C167)",
    },
    // 03H906xxx = Bosch ME7.1 (3.2/3.6 VR6) → C166
    PartNumberMapping {
        prefix: "03H906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7.1 (3.2/3.6 VR6, C166/C167)",
    },
    // 037906xxx = Bosch ME7 (older petrol) → C166
    PartNumberMapping {
        prefix: "037906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7 (petrol, C166/C167)",
    },
    // ========================================================================
    // EEPROM data modules (997 component code)
    // ========================================================================
    PartNumberMapping {
        prefix: "022997",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "ME7 EEPROM data (C166)",
    },
    PartNumberMapping {
        prefix: "030997",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "ME7 EEPROM data (C166)",
    },
    PartNumberMapping {
        prefix: "036997",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "ME7.5 EEPROM data (C166)",
    },
    PartNumberMapping {
        prefix: "036998",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "ME7.5 coding data (C166)",
    },
    PartNumberMapping {
        prefix: "03C997",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Simos EEPROM data (C166)",
    },
    PartNumberMapping {
        prefix: "03G997",
        isa: Isa::Ppc,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "EDC16 EEPROM data (PowerPC)",
    },
    // ========================================================================
    // Transmission ECUs
    // ========================================================================
    // 09G927xxx = Aisin 09G/09M automatic (Renesas V850 or similar)
    PartNumberMapping {
        prefix: "09G927",
        isa: Isa::V850,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Aisin 09G automatic transmission (V850)",
    },
    // ========================================================================
    // Other modules
    // ========================================================================
    // 470909xxx = Electric power steering → typically ARM Cortex
    PartNumberMapping {
        prefix: "470909",
        isa: Isa::Arm,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Electric power steering ECU (ARM)",
    },
    // 5K0937xxx = BCM (Body Control Module)
    PartNumberMapping {
        prefix: "5K0937",
        isa: Isa::Arm,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Body Control Module (ARM)",
    },
    // 1K0907xxx = ABS/ESP module
    PartNumberMapping {
        prefix: "1K0907",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "ABS/ESP control module (C166)",
    },
    // 1K0035xxx = Infotainment/radio modules → SH or ARM
    PartNumberMapping {
        prefix: "1K0035",
        isa: Isa::Arm,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Infotainment/radio module (ARM)",
    },
    // 4H0907xxx = Audi A8 modules → TriCore (newer Audi platforms)
    PartNumberMapping {
        prefix: "4H0907",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Audi A8 ECU module (TriCore)",
    },
    // 8K0907xxx = Audi A4/A5 modules
    PartNumberMapping {
        prefix: "8K0907",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Audi A4/A5 ECU module (TriCore)",
    },
    // 01S907xxx = Audi multitronic CVT
    PartNumberMapping {
        prefix: "01S907",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Audi multitronic CVT (C166)",
    },
    // ========================================================================
    // Broad fallbacks by system group
    // ========================================================================
    // Any remaining xxx906xxx = engine ECU, default to C166 (most common legacy)
    PartNumberMapping {
        prefix: "906",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "VW/Audi engine ECU (likely C166)",
    },
];

/// Detect whether the given data is an SGO container.
///
/// Detection is straightforward: check for the 16-byte ASCII magic
/// `"SGML Object File"` at offset 0.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < MIN_SGO_SIZE {
        return false;
    }
    &data[..16] == MAGIC
}

/// Parse the SGO container and classify the contained firmware.
///
/// Since the payload is compressed/encrypted, classification relies on
/// metadata extraction:
/// 1. Decode the XOR-0xFF encoded filename from the header
/// 2. Extract the VW Group part number from the decoded filename
/// 3. Map the part number prefix to an ECU platform and ISA
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MIN_SGO_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: MIN_SGO_SIZE,
            actual: data.len(),
        });
    }

    // Verify magic
    if &data[..16] != MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: "SGML Object File".into(),
            actual: format!("{:?}", &data[..16]),
        });
    }

    // Extract header fields
    let version = u16::from_be_bytes([data[0x10], data[0x11]]);
    let section_count = data[0x18];

    // Decode the XOR-0xFF encoded filename
    let decoded_name = decode_filename(data);

    // Extract part number from decoded filename
    let part_number = extract_part_number(&decoded_name);

    // Map part number to ECU platform
    let mapping = match &part_number {
        Some(pn) => lookup_part_number(pn),
        None => None,
    };

    // Build result
    let mut result = if let Some(m) = mapping {
        let mut r =
            ClassificationResult::from_format(m.isa, m.bitwidth, m.endianness, FileFormat::Sgo);
        r.confidence = 0.90; // Part number mapping is reliable but not as strong as embedded ECU strings
        r.source = crate::types::ClassificationSource::Combined;
        r.metadata
            .notes
            .push(format!("ECU platform: {}", m.description));
        r
    } else {
        // No part number mapping found — Unknown ISA
        let mut r = ClassificationResult::from_format(
            Isa::Unknown(0),
            0,
            Endianness::Little,
            FileFormat::Sgo,
        );
        r.confidence = 0.0;
        r.metadata.notes.push(
            "SGO container detected but part number could not be mapped to an ECU platform".into(),
        );
        r
    };

    // Add format identification
    result.metadata.notes.insert(
        0,
        "VW/Audi ODIS firmware container (SGML Object File)".into(),
    );

    // Add metadata
    if let Some(ref name) = decoded_name {
        result
            .metadata
            .notes
            .push(format!("Encoded filename: {}", name));
    }
    if let Some(ref pn) = part_number {
        result.metadata.notes.push(format!("Part number: {}", pn));
    }

    result.metadata.notes.push(format!(
        "SGO v{}, {} section(s), {} bytes",
        version,
        section_count,
        data.len()
    ));

    // Note about compressed payload
    result
        .metadata
        .notes
        .push("Payload is compressed/encrypted (heuristic ISA analysis not applicable)".into());

    Ok(result)
}

// ============================================================================
// Filename decoding
// ============================================================================

/// Decode the XOR-0xFF encoded filename from the SGO header.
///
/// The filename starts at offset 0x31 and is encoded by XOR-ing each byte
/// with 0xFF. It ends when we encounter a byte that decodes to 0xFF (i.e.,
/// a raw 0x00 byte in the file), or when we've decoded MAX_FILENAME_LEN bytes.
fn decode_filename(data: &[u8]) -> Option<String> {
    if data.len() <= FILENAME_OFFSET {
        return None;
    }

    let mut decoded = Vec::new();
    let end = data.len().min(FILENAME_OFFSET + MAX_FILENAME_LEN);

    for i in FILENAME_OFFSET..end {
        let raw = data[i];
        if raw == 0x00 {
            // 0x00 XOR 0xFF = 0xFF, which is not a valid ASCII char → end of string
            break;
        }
        let ch = raw ^ 0xFF;
        if ch == 0xFF {
            break;
        }
        decoded.push(ch);
    }

    if decoded.is_empty() {
        return None;
    }

    // The decoded filename typically ends with ".sgm"
    String::from_utf8(decoded).ok()
}

/// Extract the VW Group part number from a decoded filename.
///
/// Filenames follow the pattern: `PARTNUMBER_REVISION.sgm`
/// e.g., `03C906014A__8312.sgm` → part number `03C906014A`
///
/// The part number is everything before the last `_NNNN.sgm` suffix
/// (where NNNN is a 4-digit revision code).
fn extract_part_number(decoded_name: &Option<String>) -> Option<String> {
    let name = decoded_name.as_ref()?;

    // Remove .sgm extension if present
    let base = name.strip_suffix(".sgm").unwrap_or(name);

    // The part number is the portion before the revision suffix
    // Revision suffix patterns: _NNNN, __NNNN, _NNNN_NNNN
    // We want the longest prefix that looks like a VW part number
    //
    // VW part numbers: 3 chars + 3 digits + 3 digits + 0-2 letters
    // e.g., 03C906014A, 038906016AB, 1K0035180AG

    // Find the last '_' followed by digits (the revision code)
    if let Some(pos) = base.rfind('_') {
        let after = &base[pos + 1..];
        if after.len() >= 4
            && after
                .chars()
                .all(|c| c.is_ascii_digit() || c == '_' || c == 'Z')
        {
            let pn = &base[..pos];
            // Trim trailing underscores
            let pn = pn.trim_end_matches('_');
            if !pn.is_empty() {
                return Some(pn.to_string());
            }
        }
    }

    // Fallback: return the full base name
    Some(base.to_string())
}

/// Look up an ECU platform mapping for the given part number.
fn lookup_part_number(part_number: &str) -> Option<&'static PartNumberMapping> {
    // Try exact prefix matches in order (most specific first)
    for mapping in PART_NUMBER_MAPPINGS {
        if part_number.starts_with(mapping.prefix) {
            return Some(mapping);
        }
        // Also try if the part number contains the prefix (for sub-component matching)
        if mapping.prefix.len() == 3 && part_number.len() >= 9 {
            // For 3-char broad prefixes like "906", check at position 3
            if &part_number[3..6] == mapping.prefix {
                return Some(mapping);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SGO file with the given encoded filename.
    fn make_test_sgo(filename: &str) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        // Magic
        data[..16].copy_from_slice(MAGIC);
        // Version
        data[0x10] = 0x00;
        data[0x11] = 0x02;
        // Section count
        data[0x18] = 0x03;
        // Marker
        data[0x19] = 0x31;
        // Fixed section pointers
        data[0x1c] = 0x00;
        data[0x1d] = 0x3e;
        data[0x1e] = 0x01;
        data[0x1f] = 0x00;

        // Encode filename with XOR 0xFF
        for (i, &b) in filename.as_bytes().iter().enumerate() {
            if FILENAME_OFFSET + i >= data.len() {
                break;
            }
            data[FILENAME_OFFSET + i] = b ^ 0xFF;
        }

        data
    }

    #[test]
    fn test_detect_valid_sgo() {
        let data = make_test_sgo("03C906014A__8312.sgm");
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_rejects_non_sgo() {
        let data = vec![0u8; 0x200];
        assert!(!detect(&data));

        let elf_data = [
            0x7F, b'E', b'L', b'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(!detect(&elf_data));
    }

    #[test]
    fn test_detect_too_small() {
        let data = b"SGML Object File";
        assert!(!detect(data));
    }

    #[test]
    fn test_decode_filename() {
        let data = make_test_sgo("03C906014A__8312.sgm");
        let decoded = decode_filename(&data);
        assert_eq!(decoded.as_deref(), Some("03C906014A__8312.sgm"));
    }

    #[test]
    fn test_extract_part_number_standard() {
        let name = Some("03C906014A__8312.sgm".to_string());
        assert_eq!(extract_part_number(&name), Some("03C906014A".to_string()));
    }

    #[test]
    fn test_extract_part_number_double_underscore() {
        let name = Some("038906016AB_7989.sgm".to_string());
        assert_eq!(extract_part_number(&name), Some("038906016AB".to_string()));
    }

    #[test]
    fn test_extract_part_number_underscore_in_suffix() {
        let name = Some("03L906022QF_6211.sgm".to_string());
        assert_eq!(extract_part_number(&name), Some("03L906022QF".to_string()));
    }

    #[test]
    fn test_lookup_tricore_edc17() {
        let m = lookup_part_number("03L906022QF").unwrap();
        assert_eq!(m.isa, Isa::Tricore);
    }

    #[test]
    fn test_lookup_ppc_edc16() {
        let m = lookup_part_number("03G906016GB").unwrap();
        assert_eq!(m.isa, Isa::Ppc);
    }

    #[test]
    fn test_lookup_c166_me7() {
        let m = lookup_part_number("06A906033EL").unwrap();
        assert_eq!(m.isa, Isa::C166);
    }

    #[test]
    fn test_lookup_tricore_med17() {
        let m = lookup_part_number("06J906027FC").unwrap();
        assert_eq!(m.isa, Isa::Tricore);
    }

    #[test]
    fn test_lookup_c166_simos7() {
        let m = lookup_part_number("03C906014A").unwrap();
        assert_eq!(m.isa, Isa::C166);
    }

    #[test]
    fn test_lookup_tricore_simos9() {
        let m = lookup_part_number("03C906021F").unwrap();
        assert_eq!(m.isa, Isa::Tricore);
    }

    #[test]
    fn test_parse_sgo() {
        let data = make_test_sgo("03L906022QF_6211.sgm");
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Tricore);
        assert_eq!(result.format, FileFormat::Sgo);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_parse_sgo_c166() {
        let data = make_test_sgo("03C906014A__8312.sgm");
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::C166);
        assert_eq!(result.format, FileFormat::Sgo);
    }
}
