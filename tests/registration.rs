//! Registration completeness: every `FileFormat` JSON ID has a display name
//! in the browser's `FORMAT_NAMES`, so the UI never falls back to the
//! uppercased ID.

use std::collections::HashSet;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Variant names of `pub enum FileFormat` in `src/types.rs`.
fn file_format_variants() -> Vec<String> {
    let source = std::fs::read_to_string(format!("{ROOT}/src/types.rs")).expect("types.rs");
    let start = source
        .find("pub enum FileFormat {")
        .expect("FileFormat enum");
    let body = &source[start..];
    let end = body.find("\n}\n").expect("end of FileFormat enum");
    body[..end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//") && !line.starts_with('#'))
        .filter_map(|line| line.strip_suffix(','))
        .filter(|name| name.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
        .filter(|name| name.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_string)
        .collect()
}

/// Keys of `FORMAT_NAMES` in `web/format.js`.
fn format_name_keys() -> HashSet<String> {
    let source = std::fs::read_to_string(format!("{ROOT}/web/format.js")).expect("format.js");
    let start = source.find("const FORMAT_NAMES = {").expect("FORMAT_NAMES");
    let body = &source[start..];
    let end = body.find("};").expect("end of FORMAT_NAMES");
    body[..end]
        .split([',', '{', '\n'])
        .filter_map(|entry| entry.split_once(':'))
        .map(|(key, _)| key.trim().to_string())
        .collect()
}

#[test]
fn every_format_id_has_a_web_display_name() {
    let variants = file_format_variants();
    assert!(
        variants.len() > 50,
        "parsed {} FileFormat variants",
        variants.len()
    );
    let keys = format_name_keys();
    let missing: Vec<String> = variants
        .iter()
        .map(|v| v.to_lowercase())
        .filter(|id| !keys.contains(id))
        .collect();
    assert!(missing.is_empty(), "FORMAT_NAMES lacks {missing:?}");
}

#[test]
fn parsed_ids_match_the_serde_ids() {
    for (variant, format) in [
        ("Elf", zrax::FileFormat::Elf),
        ("MachOFat", zrax::FileFormat::MachOFat),
    ] {
        let id = serde_json::to_string(&format).unwrap();
        assert_eq!(id.trim_matches('"'), variant.to_lowercase());
    }
}
