//! SNES SPC700 sound file (`.spc`).
//!
//! A snapshot of the SNES audio subsystem: SPC700 registers, the 64 KB audio
//! RAM (driver code plus samples) and the DSP registers. The header names the
//! format, so the ISA is always the SPC700.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa};

/// File signature at offset 0.
pub const MAGIC: &[u8] = b"SNES-SPC700 Sound File Data";

/// Header (0x100 bytes) plus 64 KB of audio RAM.
const MIN_LEN: usize = 0x100 + 0x1_0000;

/// Detect an SPC sound file.
pub fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Parse an SPC sound file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if !detect(data) {
        return Err(ClassifierError::UnknownFormat {
            magic: data.iter().take(4).copied().collect(),
        });
    }
    let mut notes = vec!["SNES SPC700 sound file".to_string()];
    if data.len() < MIN_LEN {
        notes.push(format!("Truncated: {} of {MIN_LEN} bytes", data.len()));
    }
    // PC register at 0x25 (little-endian), valid when the header is v0.30.
    let pc = data.get(0x25..0x27).map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])));
    let mut result = ClassificationResult::from_format(Isa::Spc700, 8, Endianness::Little, FileFormat::SnesSpc);
    result.metadata = ClassificationMetadata {
        entry_point: pc,
        notes,
        ..Default::default()
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_parses() {
        let mut data = MAGIC.to_vec();
        data.extend_from_slice(b" v0.30\x1a\x1a\x1a\x1e");
        data.resize(MIN_LEN, 0);
        data[0x25..0x27].copy_from_slice(&0x0400u16.to_le_bytes());
        assert!(detect(&data));
        let r = parse(&data).unwrap();
        assert_eq!((r.isa, r.format), (Isa::Spc700, FileFormat::SnesSpc));
        assert_eq!(r.metadata.entry_point, Some(0x400));
        assert!(!detect(b"SNES-SPC701 Sound File Data"));
    }
}
