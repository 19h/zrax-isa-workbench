//! ECU EEPROM/Flash dump container format parser (EPR).
//!
//! EPR files are a proprietary binary container format used by automotive ECU
//! programming and tuning tools (commonly found in Eastern European tuning
//! workshops, associated with tools like ScanMatik, Alientech K-TAG/KESSv2,
//! and similar). The `.EPR` extension stands for "EEPROM Record" or
//! "ECU Programming Record".
//!
//! # Container Structure
//!
//! EPR files are composed of fixed **128-byte (0x80) records**, each beginning
//! with a type byte:
//!
//! | Offset | Size | Field        | Description                        |
//! |--------|------|--------------|------------------------------------|
//! | 0x00   | 1    | Record type  | Purpose of this record (0x00–0xFF) |
//! | 0x01   | 2    | CRC/ID       | Per-record integrity/identifier    |
//! | 0x03   | 4    | Metadata     | Timestamps, flags, addresses       |
//! | 0x07   | 1    | Reserved     | Padding                            |
//! | 0x08   | 120  | Payload      | ECU data or metadata strings       |
//!
//! # Record Types
//!
//! - **Type 0x01**: File header — contains dates, calibration IDs, tool info
//! - **Types 0x08–0x0A**: Triple-redundant data blocks (same payload in 3 copies)
//! - **Types 0x0B–0x3F**: Calibration maps, variant coding, adaptation values
//! - **Type 0x00**: Empty/padding (container allocated larger than actual data)
//! - **Type 0xFF**: End-of-data marker
//!
//! # ECU Types
//!
//! The format is associated with a wide range of automotive ECUs:
//! - Bosch EDC17/EDC16/MED17/ME9/ME7 (VW/Audi/BMW/Mercedes)
//! - Siemens/Continental SID (Ford, PSA)
//! - Magneti Marelli MJ8F (Fiat group)
//! - Denso (Toyota/Honda)
//!
//! # Payload Extraction
//!
//! The parser extracts raw ECU data from payload bytes (offset 0x08–0x7F of
//! each non-header, non-padding record) and concatenates them into a
//! contiguous buffer for ISA heuristic analysis.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, ClassifierOptions, Endianness, FileFormat, Isa};

/// EPR record size in bytes.
const RECORD_SIZE: usize = 0x80;

/// Payload offset within each record (bytes 0x08 through 0x7F).
const PAYLOAD_OFFSET: usize = 0x08;

/// Payload size per record.
const PAYLOAD_SIZE: usize = RECORD_SIZE - PAYLOAD_OFFSET; // 120 bytes

/// Minimum file size for EPR detection (at least 4 records = 512 bytes).
const MIN_EPR_SIZE: usize = RECORD_SIZE * 4;

/// Maximum number of records we'll scan for metadata extraction.
const MAX_METADATA_RECORDS: usize = 64;

/// Known ECU type strings and their corresponding ISA mappings.
struct EcuTypeMapping {
    /// Substring to match in EPR metadata
    pattern: &'static [u8],
    /// Resulting ISA
    isa: Isa,
    /// Endianness of the ECU's processor
    endianness: Endianness,
    /// Bitwidth
    bitwidth: u8,
    /// Human-readable description
    description: &'static str,
}

/// ECU string patterns → architecture mappings.
///
/// These are matched against strings found in EPR record payloads.
/// Order matters: more specific patterns should come first.
const ECU_MAPPINGS: &[EcuTypeMapping] = &[
    // Bosch EDC17 / MED17 / MG1 → Infineon TriCore (TC1766, TC1767, TC1797, TC277)
    EcuTypeMapping {
        pattern: b"EDC17",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch EDC17 (TriCore)",
    },
    EcuTypeMapping {
        pattern: b"MED17",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MED17 (TriCore)",
    },
    EcuTypeMapping {
        pattern: b"MG1C",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MG1 (TriCore)",
    },
    EcuTypeMapping {
        pattern: b"MD1C",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MD1 (TriCore)",
    },
    EcuTypeMapping {
        pattern: b"TriCore",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "TriCore (explicit reference)",
    },
    // Bosch EDC16 → Freescale MPC5xx (PowerPC-based)
    EcuTypeMapping {
        pattern: b"EDC16",
        isa: Isa::Ppc,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "Bosch EDC16 (MPC5xx/PowerPC)",
    },
    EcuTypeMapping {
        pattern: b"MPC5",
        isa: Isa::Ppc,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "Freescale MPC5xx (PowerPC)",
    },
    // Bosch EDC15 / ME7 / MSA15 → Infineon/Siemens C16x
    EcuTypeMapping {
        pattern: b"EDC15",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch EDC15 (C16x)",
    },
    EcuTypeMapping {
        pattern: b"ME7",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch ME7 (C16x)",
    },
    EcuTypeMapping {
        pattern: b"MSA15",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Bosch MSA15 (C16x)",
    },
    EcuTypeMapping {
        pattern: b"C167",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Infineon C167 (C16x family)",
    },
    // Bosch ME9 / MED9 → Infineon TriCore (TC1766)
    EcuTypeMapping {
        pattern: b"MED9",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch MED9 (TriCore TC1766)",
    },
    EcuTypeMapping {
        pattern: b"ME9",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Bosch ME9 (TriCore)",
    },
    // Siemens/Continental SID → various, but often TriCore for SID8xx
    EcuTypeMapping {
        pattern: b"SID80",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Siemens SID80x (TriCore)",
    },
    // Siemens SID2xx → ST10/C16x
    EcuTypeMapping {
        pattern: b"SID20",
        isa: Isa::C166,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "Siemens SID20x (C16x/ST10)",
    },
    // Magneti Marelli → various
    EcuTypeMapping {
        pattern: b"MJ8",
        isa: Isa::Unknown(0),
        endianness: Endianness::Little,
        bitwidth: 0,
        description: "Magneti Marelli MJ8 (mixed platforms)",
    },
    // Denso → Renesas SH/V850
    EcuTypeMapping {
        pattern: b"Denso",
        isa: Isa::Sh,
        endianness: Endianness::Big,
        bitwidth: 32,
        description: "Denso (SuperH/V850)",
    },
    // VW/Audi EV_ECM variant coding strings
    // EV_ECMxxTDI = diesel, EV_ECMxxTFS = TFSI petrol
    // The part numbers following EV_ECM are for EDC17/MED17 (TriCore) ECUs
    // when the engine size is >= 1.6L (numbers 16 and above after ECM)
    // Older ME7/EDC15 ECUs don't typically use EV_ECM format.
    EcuTypeMapping {
        pattern: b"EV_ECM",
        isa: Isa::Tricore,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "VW/Audi ECM variant coding (likely EDC17/MED17 TriCore)",
    },
    // NEC 78K0R EEPROM references
    EcuTypeMapping {
        pattern: b"78K0R",
        isa: Isa::K78k0r,
        endianness: Endianness::Little,
        bitwidth: 16,
        description: "NEC 78K0R",
    },
    // Renesas V850 references
    EcuTypeMapping {
        pattern: b"V850",
        isa: Isa::V850,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Renesas V850",
    },
    // Renesas RH850 references
    EcuTypeMapping {
        pattern: b"RH850",
        isa: Isa::Rh850,
        endianness: Endianness::Little,
        bitwidth: 32,
        description: "Renesas RH850",
    },
];

/// Detect whether the given data is an EPR container.
///
/// EPR files have no magic number, so detection is structural:
/// 1. File size must be an exact multiple of 128 bytes
/// 2. File must contain at least 4 records (512 bytes minimum)
/// 3. The record type bytes must show a plausible distribution:
///    - At least some non-zero type bytes in the first few records
///    - Significant number of 0x00-type (padding) records
///    - Record types generally in range 0x00–0x74 or 0xFF
/// 4. Header records (type 0x01) should contain date-like ASCII strings
/// 5. Data records should contain VIN-like or part-number-like strings
pub fn detect(data: &[u8]) -> bool {
    // Must be at least 512 bytes and an exact multiple of 128
    if data.len() < MIN_EPR_SIZE || data.len() % RECORD_SIZE != 0 {
        return false;
    }

    // Must be a power-of-two size OR a multiple of common EEPROM sizes.
    // ECU EEPROMs come in: 512, 1K, 2K, 4K, 8K, 16K, 32K, 64K, 128K, 256K, etc.
    // Some EPR files are 192KB (3 * 64K) which is not a power-of-two but is valid.
    let len = data.len();
    let is_power_of_two = len.is_power_of_two();
    let is_eeprom_multiple = len % 512 == 0 && len <= 4 * 1024 * 1024; // Up to 4MB
    if !is_power_of_two && !is_eeprom_multiple {
        return false;
    }

    let total_records = data.len() / RECORD_SIZE;

    // Scan the first min(64, total) records for structural validation
    let scan_count = total_records.min(MAX_METADATA_RECORDS);
    let mut type_zero_count = 0u32;
    let mut type_nonzero_count = 0u32;
    let mut has_date_string = false;
    let mut has_automotive_string = false;
    let mut invalid_structure = 0u32;

    for i in 0..scan_count {
        let offset = i * RECORD_SIZE;
        let record = &data[offset..offset + RECORD_SIZE];
        let rtype = record[0];

        if rtype == 0x00 {
            type_zero_count += 1;
        } else {
            type_nonzero_count += 1;
        }

        // Check payload area for automotive strings
        let payload = &record[PAYLOAD_OFFSET..];

        // Look for date strings (DD-MM-YY or YY-MM-DD format)
        if contains_date_pattern(payload) {
            has_date_string = true;
        }

        // Look for automotive identifiers: VINs, part numbers, ECU strings
        if contains_automotive_string(payload) {
            has_automotive_string = true;
        }

        // Check for invalid: records with all 0xFF in payload (blank flash) are OK,
        // but records with the record byte being an ASCII letter AND the next bytes
        // also forming readable text (like an ELF or PE header) are suspicious
        if rtype >= 0x80 && rtype != 0xFF {
            invalid_structure += 1;
        }
    }

    // Structural scoring
    let mut score = 0i32;

    // Must have at least 1 non-zero record type
    if type_nonzero_count == 0 {
        return false;
    }

    // Automotive strings are a very strong signal
    if has_automotive_string {
        score += 40;
    }

    // Date strings are a good signal
    if has_date_string {
        score += 20;
    }

    // Having a mix of zero and non-zero record types is expected
    if type_zero_count > 0 && type_nonzero_count > 0 {
        score += 10;
    }

    // Large fraction of type-0x00 padding records is typical
    // (in a 128KB file with 1024 records, 500+ are typically padding)
    let zero_fraction = type_zero_count as f64 / scan_count as f64;
    if zero_fraction > 0.3 && zero_fraction < 0.98 {
        score += 10;
    }

    // Penalize if many records have high type bytes (unlikely in EPR)
    if invalid_structure > scan_count as u32 / 4 {
        score -= 30;
    }

    // Check for triple-redundancy pattern: same payload appearing in
    // 3 consecutive records with types 0x08, 0x09, 0x0A
    if has_triple_redundancy(data) {
        score += 30;
    }

    // Additional: check if the file has the characteristic VW/Audi-style
    // software version string pattern "EV_ECM" or similar
    if has_ev_ecm_string(data) {
        score += 25;
    }

    // For very small files (< 8KB), require stronger evidence
    let threshold = if data.len() < 8192 { 40 } else { 25 };

    score >= threshold
}

/// Parse the EPR container and classify the contained ECU firmware.
///
/// The parser:
/// 1. Extracts metadata (dates, VINs, part numbers, ECU type strings)
/// 2. Attempts ECU-type-based ISA identification from metadata strings
/// 3. Extracts raw payload data from all non-header/non-padding records
/// 4. Runs heuristic ISA analysis on the extracted payload
/// 5. Returns a classification result combining metadata and heuristic evidence
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MIN_EPR_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: MIN_EPR_SIZE,
            actual: data.len(),
        });
    }

    let total_records = data.len() / RECORD_SIZE;

    // Phase 1: Extract metadata from records
    let metadata = extract_metadata(data, total_records);

    // Phase 2: Try ECU-type-based ISA identification
    let ecu_match = identify_ecu_type(&metadata);

    // Phase 3: Extract raw payload data for heuristic analysis
    let payload = extract_payload(data, total_records);

    // Phase 4: Build the result
    let mut result = if let Some(ecu) = &ecu_match {
        // We have an ECU type match — use it with high confidence
        let mut r = ClassificationResult::from_format(
            ecu.isa,
            ecu.bitwidth,
            ecu.endianness,
            FileFormat::Epr,
        );
        r.confidence = 0.95;
        r.source = crate::types::ClassificationSource::Combined;
        r.metadata
            .notes
            .push(format!("ECU type: {}", ecu.description));
        r
    } else if !payload.is_empty() {
        // No ECU string match — fall back to heuristic analysis on extracted payload
        let options = ClassifierOptions::new();
        match crate::heuristics::analyze(&payload, &options) {
            Ok(mut heuristic_result) => {
                heuristic_result.format = FileFormat::Epr;
                heuristic_result.source = crate::types::ClassificationSource::Combined;
                heuristic_result
                    .metadata
                    .notes
                    .push("ISA identified by heuristic analysis of extracted EPR payload".into());
                heuristic_result
            }
            Err(_) => {
                // Heuristic analysis was inconclusive — return Unknown
                let mut r = ClassificationResult::from_format(
                    Isa::Unknown(0),
                    0,
                    Endianness::Little,
                    FileFormat::Epr,
                );
                r.confidence = 0.0;
                r.metadata
                    .notes
                    .push("EPR container detected but payload ISA could not be determined".into());
                r
            }
        }
    } else {
        // No payload at all (all records are padding)
        let mut r = ClassificationResult::from_format(
            Isa::Unknown(0),
            0,
            Endianness::Little,
            FileFormat::Epr,
        );
        r.confidence = 0.0;
        r.metadata
            .notes
            .push("EPR container detected but contains no data payload".into());
        r
    };

    // Enrich result with metadata
    result
        .metadata
        .notes
        .insert(0, "ECU EEPROM/Flash dump (EPR container)".into());

    // Add extracted metadata strings
    if !metadata.dates.is_empty() {
        result
            .metadata
            .notes
            .push(format!("Dates: {}", metadata.dates.join(", ")));
    }
    if !metadata.vins.is_empty() {
        result
            .metadata
            .notes
            .push(format!("VIN(s): {}", metadata.vins.join(", ")));
    }
    if !metadata.part_numbers.is_empty() {
        result.metadata.notes.push(format!(
            "Part numbers: {}",
            metadata.part_numbers.join(", ")
        ));
    }
    if !metadata.ecu_types.is_empty() {
        result
            .metadata
            .notes
            .push(format!("ECU references: {}", metadata.ecu_types.join(", ")));
    }

    // Record counts metadata
    result.metadata.notes.push(format!(
        "EPR: {} records total, {} data, {} payload bytes extracted",
        total_records,
        total_records.saturating_sub(count_padding_records(data, total_records)),
        payload.len()
    ));

    Ok(result)
}

/// Parse the EPR container and return extracted payload along with metadata.
///
/// This is the richer parse function used by `detect_payload` which needs
/// access to the extracted payload for heuristic candidates.
pub fn parse_with_payload(data: &[u8]) -> Result<(ClassificationResult, Vec<u8>)> {
    if data.len() < MIN_EPR_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: MIN_EPR_SIZE,
            actual: data.len(),
        });
    }

    let total_records = data.len() / RECORD_SIZE;
    let payload = extract_payload(data, total_records);
    let result = parse(data)?;

    Ok((result, payload))
}

// ============================================================================
// Metadata extraction
// ============================================================================

/// Extracted metadata from EPR records.
struct EprMetadata {
    /// Date strings found (DD-MM-YY format)
    dates: Vec<String>,
    /// Vehicle Identification Numbers
    vins: Vec<String>,
    /// ECU part numbers (VW/Audi/BMW/etc. style)
    part_numbers: Vec<String>,
    /// ECU type references (EDC17, MED17, etc.)
    ecu_types: Vec<String>,
    /// Raw strings for further matching
    all_strings: Vec<String>,
}

/// Extract metadata strings from all records.
fn extract_metadata(data: &[u8], total_records: usize) -> EprMetadata {
    let mut meta = EprMetadata {
        dates: Vec::new(),
        vins: Vec::new(),
        part_numbers: Vec::new(),
        ecu_types: Vec::new(),
        all_strings: Vec::new(),
    };

    // Scan all records (not just the first 64) for metadata, but limit to avoid
    // spending too long on very large files
    let scan_count = total_records.min(512);

    for i in 0..scan_count {
        let offset = i * RECORD_SIZE;
        if offset + RECORD_SIZE > data.len() {
            break;
        }
        let record = &data[offset..offset + RECORD_SIZE];

        // Skip all-zero records quickly
        if record.iter().all(|&b| b == 0) {
            continue;
        }

        // Extract printable ASCII strings of length >= 5 from the full record
        let strings = extract_ascii_strings(record, 5);

        for s in &strings {
            // Date patterns: DD-MM-YY or YY-MM-DD
            if is_date_string(s) && !meta.dates.contains(s) {
                meta.dates.push(s.clone());
            }

            // VIN patterns: 17 alphanumeric characters starting with W, S, J, 1-5, etc.
            if is_vin_string(s) && !meta.vins.contains(s) {
                meta.vins.push(s.clone());
            }

            // Part number patterns: xxLnnnnnxxxx or nnnnnnnnn
            if is_part_number(s) && !meta.part_numbers.contains(s) {
                meta.part_numbers.push(s.clone());
            }

            // ECU type references
            if is_ecu_type_string(s) && !meta.ecu_types.contains(s) {
                meta.ecu_types.push(s.clone());
            }
        }

        meta.all_strings.extend(strings);
    }

    // Deduplicate
    meta.dates.sort();
    meta.dates.dedup();
    meta.vins.sort();
    meta.vins.dedup();
    meta.part_numbers.sort();
    meta.part_numbers.dedup();
    meta.ecu_types.sort();
    meta.ecu_types.dedup();

    meta
}

/// Identify the ECU type from metadata strings and return the ISA mapping.
fn identify_ecu_type(metadata: &EprMetadata) -> Option<&'static EcuTypeMapping> {
    // Check all extracted strings against our ECU mapping table
    for mapping in ECU_MAPPINGS {
        for s in &metadata.all_strings {
            if s.as_bytes()
                .windows(mapping.pattern.len())
                .any(|w| w == mapping.pattern)
            {
                // Skip Unknown mappings (like Marelli which is multi-platform)
                if mapping.isa != Isa::Unknown(0) {
                    return Some(mapping);
                }
            }
        }
    }
    // Also check ECU type strings specifically
    for mapping in ECU_MAPPINGS {
        for s in &metadata.ecu_types {
            if s.as_bytes()
                .windows(mapping.pattern.len())
                .any(|w| w == mapping.pattern)
            {
                if mapping.isa != Isa::Unknown(0) {
                    return Some(mapping);
                }
            }
        }
    }
    None
}

// ============================================================================
// Payload extraction
// ============================================================================

/// Extract raw payload data from all non-header, non-padding records.
///
/// This concatenates the 120-byte payload section (bytes 0x08–0x7F) from
/// every record that contains actual data (non-zero content, not all-FF).
fn extract_payload(data: &[u8], total_records: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(total_records * PAYLOAD_SIZE);

    for i in 0..total_records {
        let offset = i * RECORD_SIZE;
        if offset + RECORD_SIZE > data.len() {
            break;
        }
        let record = &data[offset..offset + RECORD_SIZE];
        let record_payload = &record[PAYLOAD_OFFSET..];

        // Skip records that are entirely zero (padding)
        if record_payload.iter().all(|&b| b == 0x00) {
            continue;
        }

        // Skip records that are entirely 0xFF (blank flash/EEPROM)
        if record_payload.iter().all(|&b| b == 0xFF) {
            continue;
        }

        // Skip records that appear to be pure ASCII metadata (dates, strings)
        // We want binary payload data for ISA classification
        let printable_count = record_payload
            .iter()
            .filter(|&&b| b == 0 || (0x20..=0x7E).contains(&b))
            .count();
        if printable_count * 100 / record_payload.len() > 85 {
            // This record is mostly text — likely metadata, skip for ISA analysis
            continue;
        }

        payload.extend_from_slice(record_payload);
    }

    payload
}

/// Count padding (all-zero) records.
fn count_padding_records(data: &[u8], total_records: usize) -> usize {
    let mut count = 0;
    for i in 0..total_records {
        let offset = i * RECORD_SIZE;
        if offset + RECORD_SIZE > data.len() {
            break;
        }
        let record = &data[offset..offset + RECORD_SIZE];
        if record.iter().all(|&b| b == 0) {
            count += 1;
        }
    }
    count
}

// ============================================================================
// String extraction helpers
// ============================================================================

/// Extract printable ASCII strings of at least `min_len` characters.
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    strings.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    // Flush remaining
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            strings.push(s.to_string());
        }
    }

    strings
}

/// Check if a string looks like a date (DD-MM-YY or YY-MM-DD).
fn is_date_string(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 8 {
        return false;
    }
    // Pattern: NN-NN-NN where N is digit
    if bytes.len() >= 8
        && bytes[2] == b'-'
        && bytes[5] == b'-'
        && bytes[0..2].iter().all(|b| b.is_ascii_digit())
        && bytes[3..5].iter().all(|b| b.is_ascii_digit())
        && bytes[6..8].iter().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    false
}

/// Check if a string looks like a VIN (Vehicle Identification Number).
/// VINs are exactly 17 characters, alphanumeric (no I, O, Q).
fn is_vin_string(s: &str) -> bool {
    // VINs can be embedded in longer strings, so look for 17-char subsequence
    if s.len() < 17 {
        return false;
    }
    // Check the first 17 characters
    let vin_candidate = &s[..17];
    if !vin_candidate
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() && b != b'I' && b != b'O' && b != b'Q')
    {
        return false;
    }
    // VINs typically start with a country/manufacturer code
    let first = vin_candidate.as_bytes()[0];
    matches!(
        first,
        b'W' | b'S' | b'J' | b'Z' | b'V' | b'T' | b'Y' | b'K' | b'L' | b'M' | b'1'..=b'5' | b'9'
    )
}

/// Check if a string looks like an ECU part number.
fn is_part_number(s: &str) -> bool {
    if s.len() < 8 || s.len() > 30 {
        return false;
    }
    let bytes = s.as_bytes();
    // VW/Audi style: 03L906022CH, 4H0907409, 1Z0907115F
    // Pattern: starts with digit(s) + letter + digit(s)
    let has_digits = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    let has_letters = bytes.iter().filter(|b| b.is_ascii_alphabetic()).count();
    // Must have both digits and letters, with digits being majority
    has_digits >= 3 && has_letters >= 1 && has_digits > has_letters
}

/// Check if a string references a known ECU type.
fn is_ecu_type_string(s: &str) -> bool {
    let patterns = [
        "EDC17", "EDC16", "EDC15", "MED17", "MED9", "ME9", "ME7", "MG1", "MD1", "SID", "MPC5",
        "TriCore", "C167", "MJ8", "78K0R", "V850", "RH850", "EV_ECM", "Denso",
    ];
    patterns.iter().any(|p| s.contains(p))
}

// ============================================================================
// Detection helpers
// ============================================================================

/// Check if payload bytes contain a date pattern.
fn contains_date_pattern(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    for window in data.windows(8) {
        if window[2] == b'-'
            && window[5] == b'-'
            && window[0..2].iter().all(|b| b.is_ascii_digit())
            && window[3..5].iter().all(|b| b.is_ascii_digit())
            && window[6..8].iter().all(|b| b.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Check if payload contains automotive-related strings.
fn contains_automotive_string(data: &[u8]) -> bool {
    // Quick check for common ECU string fragments
    let patterns: &[&[u8]] = &[
        b"EDC1", b"MED1", b"ME7.", b"ME9.", b"MG1C", b"SID2", b"SID8", b"MPC5", b"EV_E", b"TriC",
        b"C167", b"BPG", b"EEPROM", b"FLASH", b"ECU",
    ];

    for pattern in patterns {
        if data.windows(pattern.len()).any(|window| window == *pattern) {
            return true;
        }
    }

    // Check for VIN-like patterns: 3 uppercase letters followed by many alphanumerics
    // e.g., "WV1ZZZ", "WAUZZZ", "WBA"
    let vin_prefixes: &[&[u8]] = &[
        b"WV1", b"WVW", b"WAU", b"WBA", b"WDB", b"WDD", b"WF0", b"ZAR", b"ZFA", b"SAL", b"SAJ",
        b"VF1", b"VF3", b"VF7",
    ];
    for prefix in vin_prefixes {
        if data.windows(prefix.len()).any(|window| window == *prefix) {
            return true;
        }
    }

    false
}

/// Check for the triple-redundancy pattern (types 0x08, 0x09, 0x0A with same payload).
fn has_triple_redundancy(data: &[u8]) -> bool {
    let total_records = data.len() / RECORD_SIZE;
    if total_records < 3 {
        return false;
    }

    for i in 0..total_records.saturating_sub(2) {
        let r0 = &data[i * RECORD_SIZE..(i + 1) * RECORD_SIZE];
        let r1 = &data[(i + 1) * RECORD_SIZE..(i + 2) * RECORD_SIZE];
        let r2 = &data[(i + 2) * RECORD_SIZE..(i + 3) * RECORD_SIZE];

        // Check for consecutive type bytes 0x08, 0x09, 0x0A
        if r0[0] == 0x08 && r1[0] == 0x09 && r2[0] == 0x0A {
            // Check if payload portions match
            let p0 = &r0[PAYLOAD_OFFSET..];
            let p1 = &r1[PAYLOAD_OFFSET..];
            let p2 = &r2[PAYLOAD_OFFSET..];

            if p0 == p1 && p1 == p2 && !p0.iter().all(|&b| b == 0) {
                return true;
            }
        }
    }

    false
}

/// Check for "EV_ECM" pattern (VW/Audi ECU variant coding string).
fn has_ev_ecm_string(data: &[u8]) -> bool {
    let pattern = b"EV_ECM";
    data.windows(pattern.len()).any(|w| w == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal EPR file with known structure.
    fn make_test_epr(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        for (rtype, payload_data) in records {
            let mut record = vec![0u8; RECORD_SIZE];
            record[0] = *rtype;
            let copy_len = payload_data.len().min(PAYLOAD_SIZE);
            record[PAYLOAD_OFFSET..PAYLOAD_OFFSET + copy_len]
                .copy_from_slice(&payload_data[..copy_len]);
            data.extend_from_slice(&record);
        }
        // Pad to at least 4 records
        while data.len() < MIN_EPR_SIZE {
            data.extend_from_slice(&[0u8; RECORD_SIZE]);
        }
        data
    }

    #[test]
    fn test_detect_with_automotive_strings() {
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[..6].copy_from_slice(b"EDC17C");
        let records = vec![
            (0x01u8, b"04-11-09" as &[u8]),
            (0x17, &payload[..]),
            (0x00, &[]),
            (0x00, &[]),
        ];
        let data = make_test_epr(&records);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_with_vin() {
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[..17].copy_from_slice(b"WV1ZZZ7HZAH219042");
        let records = vec![
            (0x01u8, b"20-06-10" as &[u8]),
            (0x08, &payload[..]),
            (0x00, &[]),
            (0x00, &[]),
        ];
        let data = make_test_epr(&records);
        assert!(detect(&data));
    }

    #[test]
    fn test_reject_non_epr() {
        // ELF header should not be detected as EPR
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        assert!(!detect(&data));
    }

    #[test]
    fn test_reject_random_data() {
        // Random-looking data should not be detected as EPR
        let data: Vec<u8> = (0..512).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        assert!(!detect(&data));
    }

    #[test]
    fn test_date_detection() {
        assert!(is_date_string("04-11-09"));
        assert!(is_date_string("20-06-10"));
        assert!(!is_date_string("not-a-date"));
        assert!(!is_date_string("short"));
    }

    #[test]
    fn test_vin_detection() {
        assert!(is_vin_string("WV1ZZZ7HZAH219042"));
        assert!(is_vin_string("WAUZZZ4H8BN001546"));
        assert!(!is_vin_string("SHORTVIN"));
    }

    #[test]
    fn test_ecu_type_identification() {
        let meta = EprMetadata {
            dates: vec![],
            vins: vec![],
            part_numbers: vec![],
            ecu_types: vec!["EDC17CP10".to_string()],
            all_strings: vec!["EDC17CP10".to_string()],
        };
        let result = identify_ecu_type(&meta);
        assert!(result.is_some());
        assert_eq!(result.unwrap().isa, Isa::Tricore);
    }

    #[test]
    fn test_ecu_type_edc16() {
        let meta = EprMetadata {
            dates: vec![],
            vins: vec![],
            part_numbers: vec![],
            ecu_types: vec!["EDC16C39".to_string()],
            all_strings: vec!["EDC16C39".to_string()],
        };
        let result = identify_ecu_type(&meta);
        assert!(result.is_some());
        assert_eq!(result.unwrap().isa, Isa::Ppc);
    }

    #[test]
    fn test_triple_redundancy_detection() {
        let payload = [0xAAu8; PAYLOAD_SIZE];
        let mut data = Vec::new();
        // Record 0: header
        let mut r0 = vec![0u8; RECORD_SIZE];
        r0[0] = 0x01;
        data.extend_from_slice(&r0);
        // Records 1-3: triple redundancy (types 0x08, 0x09, 0x0A)
        for rtype in [0x08u8, 0x09, 0x0A] {
            let mut rec = vec![0u8; RECORD_SIZE];
            rec[0] = rtype;
            rec[PAYLOAD_OFFSET..].copy_from_slice(&payload);
            data.extend_from_slice(&rec);
        }
        // Pad
        while data.len() < MIN_EPR_SIZE {
            data.extend_from_slice(&[0u8; RECORD_SIZE]);
        }
        assert!(has_triple_redundancy(&data));
    }

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"\x00\x00Hello World\x00\x01\x02Test";
        let strings = extract_ascii_strings(data, 4);
        assert!(strings.contains(&"Hello World".to_string()));
        assert!(strings.contains(&"Test".to_string()));
    }
}
