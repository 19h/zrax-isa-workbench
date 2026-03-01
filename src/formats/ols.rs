//! WinOLS Project File container format parser.
//!
//! WinOLS is a popular tool for modifying ECU firmwares.
//! The `.ols` file format contains the binary firmware as well as metadata,
//! maps, project properties, and sometimes compressed blocks.

use crate::error::{ClassifierError, Result};
use crate::formats::DetectedFormat;
use crate::types::{ClassificationResult, Endianness, Isa};

/// Check if the file is a WinOLS container.
pub fn detect(data: &[u8]) -> bool {
    data.len() >= 16 && &data[0..15] == b"\x0b\x00\x00\x00WinOLS File"
}

/// Parse the WinOLS file and try to extract and analyze the contained firmware.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    let mut result = ClassificationResult::from_format(
        Isa::Unknown(0),
        0,
        Endianness::Little,
        crate::types::FileFormat::Ols,
    );
    result.format = crate::types::FileFormat::Ols;
    result
        .metadata
        .notes
        .push("WinOLS (.ols) file containing ECU tuning data".to_string());

    // Look for common ECU microcontrollers within the OLS file.
    // OLS files often contain strings that identify the ECU type.

    let mut found_tricore = false;
    let mut found_mpc5 = false;
    let mut found_c166 = false;

    let mut i = 0;
    while i < data.len().saturating_sub(10) {
        if data[i] == b'T' || data[i] == b'E' || data[i] == b'M' {
            let s = &data[i..i + 10];
            if s.starts_with(b"EDC17") || s.starts_with(b"MED17") || s.starts_with(b"TriCore") {
                found_tricore = true;
                break; // Fast exit if found
            } else if s.starts_with(b"EDC16") || s.starts_with(b"MPC5") {
                found_mpc5 = true;
            } else if s.starts_with(b"EDC15") || s.starts_with(b"ME7") || s.starts_with(b"C167") {
                found_c166 = true;
            }
        }
        i += 1;
    }

    // If we have a very clear hint from metadata, we can surface it
    if found_tricore {
        result.isa = Isa::Tricore;
        result.bitwidth = 32;
        result.endianness = Endianness::Little;
        result.confidence = 0.95; // Container metadata is highly reliable
        result
            .metadata
            .notes
            .push("Detected TriCore (EDC17/MED17) references in project metadata".to_string());
    } else if found_mpc5 {
        result.isa = Isa::Ppc;
        result.bitwidth = 32;
        result.endianness = Endianness::Big;
        result.confidence = 0.95;
        result
            .metadata
            .notes
            .push("Detected MPC5xx (EDC16) references in project metadata".to_string());
    } else if found_c166 {
        result.isa = Isa::C166;
        result.bitwidth = 16;
        result.endianness = Endianness::Little;
        result.confidence = 0.95;
        result
            .metadata
            .notes
            .push("Detected C167 (EDC15/ME7) references in project metadata".to_string());
    } else {
        // We'll fall back to raw analysis on the whole file if no strings found,
        // although it's usually noisy. Let's just output Unknown or let the caller decide.
        // For containers, sometimes we don't know the exact ISA unless we extract.
        result
            .metadata
            .notes
            .push("No explicit ECU architecture strings found in OLS header".to_string());
    }

    Ok(result)
}
