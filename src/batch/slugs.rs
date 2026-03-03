//! Slug derivation functions for S3 key paths.
//!
//! Converts ISA, FileFormat, Endianness, and filenames into filesystem-safe
//! slug strings as specified in `docs/batch-store/02-s3-key-layout.md` Section 4.

use crate::types::{Endianness, FileFormat, Isa};

/// Derive an S3-key-safe slug from an ISA variant.
///
/// Uses `Isa::Display` which already produces lowercase strings, except
/// for `Unknown(n)` which produces `unknown(0xNNNN)` — we convert that
/// to `unknown_0xNNNN`.
pub fn isa_slug(isa: &Isa) -> String {
    let display = format!("{}", isa);
    // Unknown(n) renders as "unknown(0xNNNN)" — make it key-safe
    display.replace('(', "_").replace(')', "")
}

/// Derive an S3-key-safe slug from a FileFormat variant.
///
/// Uses `Debug` variant name, lowercased, with non-alphanumeric chars removed.
pub fn format_slug(format: &FileFormat) -> String {
    let debug = format!("{:?}", format);
    debug
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// Derive an S3-key-safe slug from an Endianness value.
pub fn endianness_slug(endianness: &Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "le",
        Endianness::Big => "be",
        Endianness::BiEndian => "bi",
    }
}

/// Endianness display string for metadata JSON.
pub fn endianness_display(endianness: &Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
        Endianness::BiEndian => "bi-endian",
    }
}

/// Sanitize a filename for use in `.ref` file keys.
///
/// Rules (from `docs/batch-store/02-s3-key-layout.md` Section 4.3):
/// 1. Take the original filename (basename only)
/// 2. Replace any character not in `[a-zA-Z0-9._-]` with `_`
/// 3. Collapse consecutive underscores to a single underscore
/// 4. Truncate to 128 characters maximum
/// 5. If empty, use `unnamed`
pub fn sanitize_filename(name: &str) -> String {
    // Take basename only
    let basename = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);

    // Replace disallowed characters
    let replaced: String = basename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();

    // Collapse consecutive underscores
    let mut result = String::with_capacity(replaced.len());
    let mut last_was_underscore = false;
    for c in replaced.chars() {
        if c == '_' {
            if !last_was_underscore {
                result.push(c);
            }
            last_was_underscore = true;
        } else {
            result.push(c);
            last_was_underscore = false;
        }
    }

    // Strip leading underscores
    let result = result.trim_start_matches('_').to_string();

    // Truncate to 128 chars
    let result = if result.len() > 128 {
        result[..128].to_string()
    } else {
        result
    };

    // Empty → "unnamed"
    if result.is_empty() {
        "unnamed".to_string()
    } else {
        result
    }
}

/// Extract the 2-level hex fanout prefix from a SHA-256 hex string.
///
/// Given `"a1b2c3d4..."`, returns `("a1", "b2")`.
pub fn hash_fanout(sha256_hex: &str) -> (&str, &str) {
    debug_assert!(sha256_hex.len() >= 4);
    (&sha256_hex[..2], &sha256_hex[2..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isa_slug_normal() {
        assert_eq!(isa_slug(&Isa::X86_64), "x86_64");
        assert_eq!(isa_slug(&Isa::AArch64), "aarch64");
        assert_eq!(isa_slug(&Isa::Arm), "arm");
        assert_eq!(isa_slug(&Isa::Tricore), "tricore");
        assert_eq!(isa_slug(&Isa::Mips), "mips");
        assert_eq!(isa_slug(&Isa::Ppc), "ppc");
    }

    #[test]
    fn test_isa_slug_unknown() {
        assert_eq!(isa_slug(&Isa::Unknown(0x1234)), "unknown_0x1234");
    }

    #[test]
    fn test_format_slug() {
        assert_eq!(format_slug(&FileFormat::Elf), "elf");
        assert_eq!(format_slug(&FileFormat::Pe), "pe");
        assert_eq!(format_slug(&FileFormat::MachO), "macho");
        assert_eq!(format_slug(&FileFormat::MachOFat), "machofat");
        assert_eq!(format_slug(&FileFormat::Raw), "raw");
        assert_eq!(format_slug(&FileFormat::IntelHex), "intelhex");
        assert_eq!(format_slug(&FileFormat::JavaClass), "javaclass");
        assert_eq!(format_slug(&FileFormat::SelfPs3), "selfps3");
        assert_eq!(format_slug(&FileFormat::WindowsLib), "windowslib");
        assert_eq!(format_slug(&FileFormat::LlvmBc), "llvmbc");
    }

    #[test]
    fn test_endianness_slug() {
        assert_eq!(endianness_slug(&Endianness::Little), "le");
        assert_eq!(endianness_slug(&Endianness::Big), "be");
        assert_eq!(endianness_slug(&Endianness::BiEndian), "bi");
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("firmware.bin"), "firmware.bin");
        assert_eq!(sanitize_filename("rkos"), "rkos");
        assert_eq!(
            sanitize_filename("firmware (v2.3).bin"),
            "firmware_v2.3_.bin"
        );
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename(""), "unnamed");
        assert_eq!(sanitize_filename("   "), "unnamed");
    }

    #[test]
    fn test_sanitize_filename_truncation() {
        let long_name = "a".repeat(200);
        let sanitized = sanitize_filename(&long_name);
        assert!(sanitized.len() <= 128);
    }

    #[test]
    fn test_hash_fanout() {
        let (a, b) = hash_fanout("a1b2c3d4e5f6");
        assert_eq!(a, "a1");
        assert_eq!(b, "b2");
    }
}
