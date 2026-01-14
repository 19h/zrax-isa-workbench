//! Output formatters for detection payloads.
//!
//! This module provides trait-based formatters for rendering detection results
//! in various output formats (human-readable, JSON, compact).

use crate::types::{
    DetectionPayload, ExtensionDetection, FormatDetection, IsaCandidate,
    IsaClassification, MetadataEntry, Note, NoteLevel,
};
use std::path::Path;

/// Trait for formatting detection payloads.
///
/// Implementors provide methods for rendering each component of a detection
/// payload, plus a method to render the complete payload.
pub trait PayloadFormatter {
    /// Format the file path header.
    fn format_file(&self, path: &Path) -> String;

    /// Format the format detection result.
    fn format_format(&self, format: &FormatDetection) -> Option<String>;

    /// Format the primary ISA classification.
    fn format_isa(&self, isa: &IsaClassification) -> Option<String>;

    /// Format the list of ISA candidates.
    fn format_candidates(&self, candidates: &[IsaCandidate]) -> Option<String>;

    /// Format the detected extensions.
    fn format_extensions(&self, extensions: &[ExtensionDetection]) -> Option<String>;

    /// Format metadata entries.
    fn format_metadata(&self, metadata: &[MetadataEntry]) -> Option<String>;

    /// Format analysis notes.
    fn format_notes(&self, notes: &[Note]) -> Option<String>;

    /// Format the complete payload.
    ///
    /// Default implementation concatenates all component outputs.
    fn format_payload(&self, payload: &DetectionPayload, path: &Path) -> String {
        let mut parts = Vec::new();

        parts.push(self.format_file(path));

        if let Some(s) = self.format_format(&payload.format) {
            parts.push(s);
        }
        if let Some(s) = self.format_isa(&payload.primary) {
            parts.push(s);
        }
        if let Some(s) = self.format_extensions(&payload.extensions) {
            parts.push(s);
        }
        if let Some(s) = self.format_metadata(&payload.metadata) {
            parts.push(s);
        }
        if let Some(s) = self.format_candidates(&payload.candidates) {
            parts.push(s);
        }
        if let Some(s) = self.format_notes(&payload.notes) {
            parts.push(s);
        }

        parts.join("")
    }
}

/// Human-readable output formatter.
#[derive(Debug, Clone)]
pub struct HumanFormatter {
    /// Show verbose output (additional metadata)
    pub verbose: bool,
    /// Quiet mode (minimal output)
    pub quiet: bool,
    /// Show candidates even if not requested
    pub show_candidates: bool,
}

impl Default for HumanFormatter {
    fn default() -> Self {
        Self {
            verbose: false,
            quiet: false,
            show_candidates: false,
        }
    }
}

impl HumanFormatter {
    /// Create a new human formatter with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a verbose formatter.
    pub fn verbose() -> Self {
        Self {
            verbose: true,
            quiet: false,
            show_candidates: false,
        }
    }

    /// Create a quiet formatter.
    pub fn quiet() -> Self {
        Self {
            verbose: false,
            quiet: true,
            show_candidates: false,
        }
    }
}

impl PayloadFormatter for HumanFormatter {
    fn format_file(&self, path: &Path) -> String {
        if self.quiet {
            String::new()
        } else {
            format!("File: {}\n", path.display())
        }
    }

    fn format_format(&self, format: &FormatDetection) -> Option<String> {
        if self.quiet {
            return None;
        }
        let mut s = format!("  Format:     {}", format.format);
        if let Some(ref variant) = format.variant_name {
            s.push_str(&format!(" ({})", variant));
        }
        s.push('\n');
        Some(s)
    }

    fn format_isa(&self, isa: &IsaClassification) -> Option<String> {
        if self.quiet {
            return Some(format!("{}\n", isa.isa));
        }

        let mut s = String::new();
        s.push_str(&format!(
            "  ISA:        {} ({})\n",
            isa.isa,
            isa.isa.name()
        ));
        s.push_str(&format!("  Bitwidth:   {}-bit\n", isa.bitwidth));
        s.push_str(&format!("  Endianness: {}\n", isa.endianness));
        s.push_str(&format!(
            "  Confidence: {:.1}%\n",
            isa.confidence * 100.0
        ));

        if let Some(ref variant) = isa.variant {
            if !variant.name.is_empty() {
                s.push_str(&format!("  Variant:    {}\n", variant));
            }
        }

        if self.verbose {
            s.push_str(&format!("  Source:     {:?}\n", isa.source));
        }

        Some(s)
    }

    fn format_candidates(&self, candidates: &[IsaCandidate]) -> Option<String> {
        if candidates.is_empty() || self.quiet {
            return None;
        }

        // Only show candidates in verbose mode or if explicitly requested
        if !self.verbose && !self.show_candidates {
            return None;
        }

        let mut s = String::from("  Candidates:\n");
        for (i, c) in candidates.iter().take(5).enumerate() {
            s.push_str(&format!(
                "    {}. {} ({}-bit, {}) - score: {}, {:.1}%\n",
                i + 1,
                c.isa,
                c.bitwidth,
                c.endianness,
                c.raw_score,
                c.confidence * 100.0
            ));
        }
        Some(s)
    }

    fn format_extensions(&self, extensions: &[ExtensionDetection]) -> Option<String> {
        if extensions.is_empty() || self.quiet {
            return None;
        }

        let names: Vec<&str> = extensions.iter().map(|e| e.name.as_str()).collect();
        Some(format!("  Extensions: {}\n", names.join(", ")))
    }

    fn format_metadata(&self, metadata: &[MetadataEntry]) -> Option<String> {
        if metadata.is_empty() || !self.verbose {
            return None;
        }

        let mut s = String::new();
        for entry in metadata {
            s.push_str(&format!("  {:10}  {}\n", entry.label, entry.value));
        }
        Some(s)
    }

    fn format_notes(&self, notes: &[Note]) -> Option<String> {
        if notes.is_empty() {
            return None;
        }

        // Only show warnings/errors unless verbose
        let to_show: Vec<_> = if self.verbose {
            notes.iter().collect()
        } else {
            notes
                .iter()
                .filter(|n| n.level != NoteLevel::Info)
                .collect()
        };

        if to_show.is_empty() {
            return None;
        }

        let mut s = String::new();
        for note in to_show {
            let prefix = match note.level {
                NoteLevel::Info => "  [info]",
                NoteLevel::Warning => "  [warn]",
                NoteLevel::Error => "  [error]",
            };
            s.push_str(&format!("{} {}\n", prefix, note.message));
        }
        Some(s)
    }

    fn format_payload(&self, payload: &DetectionPayload, path: &Path) -> String {
        if self.quiet {
            // Quiet mode: just "path: isa"
            return format!("{}: {}\n", path.display(), payload.primary.isa);
        }

        // Normal mode: build full output
        let mut parts = Vec::new();

        parts.push(self.format_file(path));

        if let Some(s) = self.format_isa(&payload.primary) {
            parts.push(s);
        }
        if let Some(s) = self.format_format(&payload.format) {
            parts.push(s);
        }
        if let Some(s) = self.format_extensions(&payload.extensions) {
            parts.push(s);
        }
        if let Some(s) = self.format_metadata(&payload.metadata) {
            parts.push(s);
        }
        if let Some(s) = self.format_candidates(&payload.candidates) {
            parts.push(s);
        }
        if let Some(s) = self.format_notes(&payload.notes) {
            parts.push(s);
        }

        parts.push(String::from("\n")); // Trailing newline
        parts.join("")
    }
}

/// JSON output formatter.
#[derive(Debug, Clone)]
pub struct JsonFormatter {
    /// Pretty-print JSON
    pub pretty: bool,
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self { pretty: true }
    }
}

impl JsonFormatter {
    /// Create a new JSON formatter with pretty printing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a compact JSON formatter.
    pub fn compact() -> Self {
        Self { pretty: false }
    }
}

impl PayloadFormatter for JsonFormatter {
    fn format_file(&self, _path: &Path) -> String {
        String::new() // Handled in format_payload
    }

    fn format_format(&self, _format: &FormatDetection) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_isa(&self, _isa: &IsaClassification) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_candidates(&self, _candidates: &[IsaCandidate]) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_extensions(&self, _extensions: &[ExtensionDetection]) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_metadata(&self, _metadata: &[MetadataEntry]) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_notes(&self, _notes: &[Note]) -> Option<String> {
        None // Handled in format_payload
    }

    fn format_payload(&self, payload: &DetectionPayload, path: &Path) -> String {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            file: String,
            format: &'a str,
            format_variant: Option<&'a str>,
            isa: String,
            isa_name: &'static str,
            bitwidth: u8,
            endianness: String,
            confidence: f64,
            source: String,
            variant: Option<String>,
            extensions: Vec<ExtensionJson<'a>>,
            metadata: Vec<MetadataJson<'a>>,
            candidates: Vec<CandidateJson>,
            notes: Vec<NoteJson<'a>>,
        }

        #[derive(serde::Serialize)]
        struct ExtensionJson<'a> {
            name: &'a str,
            category: String,
            confidence: f64,
            source: String,
        }

        #[derive(serde::Serialize)]
        struct MetadataJson<'a> {
            key: String,
            value: String,
            label: &'a str,
        }

        #[derive(serde::Serialize)]
        struct CandidateJson {
            isa: String,
            bitwidth: u8,
            endianness: String,
            raw_score: i64,
            confidence: f64,
        }

        #[derive(serde::Serialize)]
        struct NoteJson<'a> {
            level: &'a str,
            message: &'a str,
            context: Option<&'a str>,
        }

        let output = JsonOutput {
            file: path.display().to_string(),
            format: format_name(&payload.format.format),
            format_variant: payload.format.variant_name.as_deref(),
            isa: payload.primary.isa.to_string(),
            isa_name: payload.primary.isa.name(),
            bitwidth: payload.primary.bitwidth,
            endianness: payload.primary.endianness.to_string(),
            confidence: payload.primary.confidence,
            source: format!("{:?}", payload.primary.source),
            variant: payload.primary.variant.as_ref().map(|v| v.to_string()),
            extensions: payload
                .extensions
                .iter()
                .map(|e| ExtensionJson {
                    name: &e.name,
                    category: format!("{:?}", e.category),
                    confidence: e.confidence,
                    source: format!("{:?}", e.source),
                })
                .collect(),
            metadata: payload
                .metadata
                .iter()
                .map(|m| MetadataJson {
                    key: format!("{:?}", m.key),
                    value: m.value.to_string(),
                    label: &m.label,
                })
                .collect(),
            candidates: payload
                .candidates
                .iter()
                .map(|c| CandidateJson {
                    isa: c.isa.to_string(),
                    bitwidth: c.bitwidth,
                    endianness: c.endianness.to_string(),
                    raw_score: c.raw_score,
                    confidence: c.confidence,
                })
                .collect(),
            notes: payload
                .notes
                .iter()
                .map(|n| NoteJson {
                    level: match n.level {
                        NoteLevel::Info => "info",
                        NoteLevel::Warning => "warning",
                        NoteLevel::Error => "error",
                    },
                    message: &n.message,
                    context: n.context.as_deref(),
                })
                .collect(),
        };

        if self.pretty {
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        } else {
            serde_json::to_string(&output).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

/// Compact single-line output formatter.
#[derive(Debug, Clone, Default)]
pub struct ShortFormatter;

impl ShortFormatter {
    /// Create a new short formatter.
    pub fn new() -> Self {
        Self
    }
}

impl PayloadFormatter for ShortFormatter {
    fn format_file(&self, _path: &Path) -> String {
        String::new() // Handled in format_payload
    }

    fn format_format(&self, _format: &FormatDetection) -> Option<String> {
        None
    }

    fn format_isa(&self, _isa: &IsaClassification) -> Option<String> {
        None
    }

    fn format_candidates(&self, _candidates: &[IsaCandidate]) -> Option<String> {
        None
    }

    fn format_extensions(&self, _extensions: &[ExtensionDetection]) -> Option<String> {
        None
    }

    fn format_metadata(&self, _metadata: &[MetadataEntry]) -> Option<String> {
        None
    }

    fn format_notes(&self, _notes: &[Note]) -> Option<String> {
        None
    }

    fn format_payload(&self, payload: &DetectionPayload, path: &Path) -> String {
        let exts = if payload.extensions.is_empty() {
            String::new()
        } else {
            let names: Vec<&str> = payload.extensions.iter().map(|e| e.name.as_str()).collect();
            format!(" [{}]", names.join(","))
        };

        format!(
            "{}\t{}\t{}\t{}\t{:.0}%{}\n",
            path.display(),
            payload.primary.isa,
            payload.primary.bitwidth,
            payload.primary.endianness,
            payload.primary.confidence * 100.0,
            exts
        )
    }
}

/// Candidates-only output formatter.
#[derive(Debug, Clone, Default)]
pub struct CandidatesFormatter;

impl CandidatesFormatter {
    /// Create a new candidates formatter.
    pub fn new() -> Self {
        Self
    }
}

impl PayloadFormatter for CandidatesFormatter {
    fn format_file(&self, path: &Path) -> String {
        format!("Candidates for {}:\n", path.display())
    }

    fn format_format(&self, _format: &FormatDetection) -> Option<String> {
        None
    }

    fn format_isa(&self, _isa: &IsaClassification) -> Option<String> {
        None
    }

    fn format_candidates(&self, candidates: &[IsaCandidate]) -> Option<String> {
        if candidates.is_empty() {
            return Some(String::from("  No candidates available\n"));
        }

        let mut s = String::new();
        for (i, c) in candidates.iter().enumerate() {
            s.push_str(&format!(
                "  {}. {} ({}-bit, {}) - score: {}, confidence: {:.1}%\n",
                i + 1,
                c.isa,
                c.bitwidth,
                c.endianness,
                c.raw_score,
                c.confidence * 100.0
            ));
        }
        Some(s)
    }

    fn format_extensions(&self, _extensions: &[ExtensionDetection]) -> Option<String> {
        None
    }

    fn format_metadata(&self, _metadata: &[MetadataEntry]) -> Option<String> {
        None
    }

    fn format_notes(&self, _notes: &[Note]) -> Option<String> {
        None
    }

    fn format_payload(&self, payload: &DetectionPayload, path: &Path) -> String {
        let mut s = self.format_file(path);
        if let Some(candidates) = self.format_candidates(&payload.candidates) {
            s.push_str(&candidates);
        }
        s.push('\n');
        s
    }
}

/// Helper function to get format display name.
fn format_name(format: &crate::types::FileFormat) -> &'static str {
    use crate::types::FileFormat;
    match format {
        FileFormat::Elf => "ELF",
        FileFormat::Pe => "PE/COFF",
        FileFormat::MachO => "Mach-O",
        FileFormat::MachOFat => "Mach-O Fat",
        FileFormat::Coff => "COFF",
        FileFormat::Xcoff => "XCOFF",
        FileFormat::Ecoff => "ECOFF",
        FileFormat::Raw => "Raw",
        FileFormat::Aout => "a.out",
        FileFormat::Plan9Aout => "Plan 9 a.out",
        FileFormat::MinixAout => "Minix a.out",
        FileFormat::Mz => "MZ/DOS",
        FileFormat::Ne => "NE",
        FileFormat::Le => "LE",
        FileFormat::Lx => "LX",
        FileFormat::Com => "COM",
        FileFormat::Omf => "OMF",
        FileFormat::Pef => "PEF",
        FileFormat::IntelHex => "Intel HEX",
        FileFormat::Srec => "S-record",
        FileFormat::TiTxt => "TI-TXT",
        FileFormat::Bflt => "bFLT",
        FileFormat::Dxe => "DXE",
        FileFormat::Goff => "GOFF",
        FileFormat::MvsLoad => "MVS Load",
        FileFormat::Som => "HP-UX SOM",
        FileFormat::Rsx11 => "RSX-11",
        FileFormat::Vms => "VMS",
        FileFormat::Ieee695 => "IEEE-695",
        FileFormat::Wasm => "WebAssembly",
        FileFormat::JavaClass => "Java Class",
        FileFormat::Dex => "DEX",
        FileFormat::Odex => "ODEX",
        FileFormat::Vdex => "VDEX",
        FileFormat::Art => "ART",
        FileFormat::LlvmBc => "LLVM Bitcode",
        FileFormat::FatElf => "FatELF",
        FileFormat::Archive => "ar Archive",
        FileFormat::WindowsLib => "Windows .lib",
        FileFormat::Xbe => "XBE",
        FileFormat::Xex => "XEX",
        FileFormat::SelfPs3 => "PS3 SELF",
        FileFormat::SelfPs4 => "PS4 SELF",
        FileFormat::SelfPs5 => "PS5 SELF",
        FileFormat::Nso => "NSO",
        FileFormat::Nro => "NRO",
        FileFormat::Dol => "DOL",
        FileFormat::Rel => "REL",
        FileFormat::ZImage => "zImage",
        FileFormat::UImage => "uImage",
        FileFormat::Fit => "FIT",
        FileFormat::Dtb => "DTB",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Endianness, ExtensionCategory, ExtensionSource, FileFormat, Isa, ClassificationSource};
    use std::path::PathBuf;

    fn sample_payload() -> DetectionPayload {
        DetectionPayload::new(
            FormatDetection::new(FileFormat::Elf),
            IsaClassification::from_format(Isa::X86_64, 64, Endianness::Little),
        )
        .with_extension(ExtensionDetection::from_code("AVX2", ExtensionCategory::Simd, 0.95))
        .with_metadata(MetadataEntry::entry_point(0x401000))
    }

    #[test]
    fn test_human_formatter() {
        let formatter = HumanFormatter::new();
        let payload = sample_payload();
        let output = formatter.format_payload(&payload, &PathBuf::from("/bin/test"));

        assert!(output.contains("File: /bin/test"));
        assert!(output.contains("x86_64"));
        assert!(output.contains("64-bit"));
        assert!(output.contains("AVX2"));
    }

    #[test]
    fn test_human_formatter_quiet() {
        let formatter = HumanFormatter::quiet();
        let payload = sample_payload();
        let output = formatter.format_payload(&payload, &PathBuf::from("/bin/test"));

        assert!(output.contains("/bin/test: x86_64"));
        assert!(!output.contains("Extensions"));
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new();
        let payload = sample_payload();
        let output = formatter.format_payload(&payload, &PathBuf::from("/bin/test"));

        assert!(output.contains("\"file\": \"/bin/test\""));
        assert!(output.contains("\"isa\": \"x86_64\""));
        assert!(output.contains("\"AVX2\""));
    }

    #[test]
    fn test_short_formatter() {
        let formatter = ShortFormatter::new();
        let payload = sample_payload();
        let output = formatter.format_payload(&payload, &PathBuf::from("/bin/test"));

        assert!(output.contains("/bin/test\tx86_64\t64\tlittle"));
        assert!(output.contains("[AVX2]"));
    }
}
