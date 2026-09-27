//! Motorola DSP LOD files (the text load format of the DSP56000/56100/
//! 56300/96000 assemblers and linkers).
//!
//! ```text
//! _START DGE 0000 0000 0000 DSP56000 3.1
//! _DATA P 0040
//! 0003F8 08F4BE 003300 ...
//! _END 0000
//! ```
//!
//! `_START` names the processor. Files without it still identify the family
//! by their word width: 4 hex digits per word for the 16-bit DSP56100, 6 for
//! the 24-bit DSP56000/56300, 8 for the 32-bit DSP96000.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Only the start of the file is looked at for detection.
const PROBE: usize = 4096;

fn lines(data: &[u8]) -> impl Iterator<Item = &str> {
    data.split(|&b| b == b'\n')
        .filter_map(|l| std::str::from_utf8(l).ok())
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

fn is_data_record(line: &str) -> bool {
    let mut t = line.split_whitespace();
    t.next() == Some("_DATA")
        && matches!(t.next(), Some("P" | "X" | "Y" | "L" | "E"))
        && t.next().is_some_and(|a| a.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Detect a LOD file: the first line is `_START` or a `_DATA` record.
pub fn detect(data: &[u8]) -> bool {
    let head = &data[..data.len().min(PROBE)];
    match lines(head).next() {
        Some(first) if first.starts_with("_START ") => lines(head).skip(1).take(8).any(is_data_record),
        Some(first) => is_data_record(first),
        None => false,
    }
}

/// Processor from the `_START` line or from the width of the data words.
fn processor(data: &[u8]) -> (Isa, u8, &'static str) {
    let mut words = lines(data).filter(|l| !l.starts_with('_')).flat_map(str::split_whitespace);
    if let Some(start) = lines(data).next().filter(|l| l.starts_with("_START ")) {
        let upper = start.to_ascii_uppercase();
        for (tag, found) in [
            ("DSP96", (Isa::Dsp96k, 32, "DSP96000")),
            ("DSP561", (Isa::Dsp56k, 16, "DSP56100")),
            ("DSP563", (Isa::Dsp56k, 24, "DSP56300")),
            ("DSP566", (Isa::Dsp56k, 16, "DSP56600")),
            ("DSP560", (Isa::Dsp56k, 24, "DSP56000")),
        ] {
            if upper.contains(tag) {
                return found;
            }
        }
    }
    match words.next().map(str::len) {
        Some(4) => (Isa::Dsp56k, 16, "DSP56100"),
        Some(8) => (Isa::Dsp96k, 32, "DSP96000"),
        _ => (Isa::Dsp56k, 24, "DSP56000"),
    }
}

/// Parse a LOD file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if !detect(data) {
        return Err(ClassifierError::UnknownFormat {
            magic: data.iter().take(4).copied().collect(),
        });
    }
    let (isa, bits, name) = processor(data);
    let records = lines(data).filter(|l| is_data_record(l)).count();
    let mut result = ClassificationResult::from_format(isa, bits, Endianness::Big, FileFormat::DspLod);
    result.variant = Variant::new(name);
    result.metadata = ClassificationMetadata {
        section_count: Some(records),
        notes: vec![format!("Motorola DSP LOD file ({name})")],
        ..Default::default()
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_processor() {
        let lod = b"_START DGE 0000 0000 0000 DSP56000 3.1\r\n\r\n_DATA P 0000\r\n0C0040 \r\n_END 0000\r\n";
        assert!(detect(lod));
        let r = parse(lod).unwrap();
        assert_eq!((r.isa, r.format, r.variant.name.as_str()), (Isa::Dsp56k, FileFormat::DspLod, "DSP56000"));
    }

    #[test]
    fn word_width_without_start() {
        let lod = b"\n_DATA P 000000\n12345678 9ABCDEF0\n_END 000000\n";
        assert!(detect(lod));
        assert_eq!(parse(lod).unwrap().isa, Isa::Dsp96k);
        let lod = b"_DATA P 0000\n1234 5678\n_END 0000\n";
        assert_eq!(parse(lod).unwrap().variant.name, "DSP56100");
    }

    #[test]
    fn rejects_other_text() {
        assert!(!detect(b"_START of a readme\nhello\n"));
        assert!(!detect(b"_DATA Q 00\n"));
        assert!(!detect(b"int main() {}\n"));
    }
}
