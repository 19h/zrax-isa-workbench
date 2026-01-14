//! Error types for the ISA classifier.
//!
//! This module defines all error types used throughout the classifier,
//! providing detailed error information for debugging and user feedback.

use thiserror::Error;

/// Primary error type for the ISA classifier.
#[derive(Debug, Error)]
pub enum ClassifierError {
    /// IO error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The file is too small to contain valid binary data.
    #[error("File too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    /// Invalid magic bytes for the detected format.
    #[error("Invalid magic bytes: expected {expected}, got {actual}")]
    InvalidMagic { expected: String, actual: String },

    /// Unsupported or unknown file format.
    #[error("Unknown file format: magic bytes {magic:02X?}")]
    UnknownFormat { magic: Vec<u8> },

    /// Error parsing ELF format.
    #[error("ELF parse error: {message}")]
    ElfParseError { message: String },

    /// Error parsing PE/COFF format.
    #[error("PE/COFF parse error: {message}")]
    PeParseError { message: String },

    /// Error parsing Mach-O format.
    #[error("Mach-O parse error: {message}")]
    MachOParseError { message: String },

    /// Unknown or unsupported e_machine value in ELF.
    #[error("Unknown ELF e_machine value: {value} (0x{value:04X})")]
    UnknownElfMachine { value: u16 },

    /// Unknown or unsupported PE machine type.
    #[error("Unknown PE machine type: {value} (0x{value:04X})")]
    UnknownPeMachine { value: u16 },

    /// Unknown or unsupported Mach-O CPU type.
    #[error("Unknown Mach-O CPU type: {value} (0x{value:08X})")]
    UnknownMachOCpuType { value: u32 },

    /// Truncated data when reading.
    #[error("Truncated data at offset {offset}: expected {expected} bytes, got {actual}")]
    TruncatedData {
        offset: usize,
        expected: usize,
        actual: usize,
    },

    /// Invalid section or segment.
    #[error("Invalid {kind} at index {index}: {message}")]
    InvalidSection {
        kind: String,
        index: usize,
        message: String,
    },

    /// Heuristic analysis failed to determine architecture.
    #[error("Heuristic analysis inconclusive: confidence {confidence:.2}% below threshold {threshold:.2}%")]
    HeuristicInconclusive { confidence: f64, threshold: f64 },

    /// Multiple architectures detected (e.g., fat binary).
    #[error("Multiple architectures detected: {architectures:?}")]
    MultipleArchitectures { architectures: Vec<String> },

    /// Configuration error.
    #[error("Configuration error: {message}")]
    ConfigError { message: String },
}

/// Result type alias for classifier operations.
pub type Result<T> = std::result::Result<T, ClassifierError>;

/// Extension trait for adding context to errors.
pub trait ResultExt<T> {
    /// Add context to an error.
    fn context(self, msg: impl Into<String>) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| ClassifierError::ElfParseError {
            message: format!("{}: {}", msg.into(), e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ClassifierError::FileTooSmall {
            expected: 16,
            actual: 4,
        };
        assert!(err.to_string().contains("16"));
        assert!(err.to_string().contains("4"));
    }

    #[test]
    fn test_unknown_machine() {
        let err = ClassifierError::UnknownElfMachine { value: 0xBEEF };
        let msg = err.to_string();
        assert!(msg.contains("BEEF"));
    }
}
