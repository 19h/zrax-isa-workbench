//! Streaming string and certificate scans for the browser scan worker. The
//! worker reads a file in slices and pushes them here, so it holds no
//! resident copy of the file.

use wasm_bindgen::prelude::*;

use crate::certificates::{self, WINDOW_OVERLAP};
use crate::strings::{Encodings, FoundString, Options, Scanner, ENCODINGS, TAG_NAMES};

/// Compact rows `[offset, size, chars, encoding, tags, clipped, text]`,
/// where `encoding` indexes [`string_encoding_ids`] and `tags` holds the
/// bits of [`string_tag_ids`].
fn rows_json(found: &[FoundString]) -> String {
    let rows: Vec<(u64, u64, u64, usize, u16, bool, &str)> = found
        .iter()
        .map(|s| {
            let encoding = ENCODINGS
                .iter()
                .position(|e| *e == s.encoding)
                .unwrap_or_default();
            (
                s.offset,
                s.size,
                s.chars,
                encoding,
                s.tags.bits(),
                s.clipped,
                s.text.as_str(),
            )
        })
        .collect();
    serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
}

/// Encoding identifiers in row-index order.
#[wasm_bindgen]
pub fn string_encoding_ids() -> String {
    let ids: Vec<&str> = ENCODINGS.iter().map(|e| e.id()).collect();
    serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string())
}

/// Tag identifiers and their bits, in display order: `[[bit, id], ...]`.
#[wasm_bindgen]
pub fn string_tag_ids() -> String {
    let ids: Vec<(u16, &str)> = TAG_NAMES
        .iter()
        .map(|(tag, id)| (tag.bits(), *id))
        .collect();
    serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string())
}

/// Bytes a certificate window must extend past its reported range.
#[wasm_bindgen]
pub fn certificate_window_overlap() -> u32 {
    u32::try_from(WINDOW_OVERLAP).unwrap_or(u32::MAX)
}

/// String extraction over consecutive slices of one file.
#[wasm_bindgen]
pub struct StringScan {
    scanner: Scanner,
    found: Vec<FoundString>,
}

#[wasm_bindgen]
impl StringScan {
    /// A scan for runs of at least `min_chars` characters in the encodings
    /// whose bits (in [`string_encoding_ids`] order) are set in `encodings`.
    ///
    /// # Errors
    ///
    /// A JavaScript error for a minimum outside 3..=255 or no encoding.
    #[wasm_bindgen(constructor)]
    pub fn new(min_chars: u32, encodings: u8) -> Result<StringScan, JsValue> {
        let encodings = Encodings::from_bits_truncate(encodings);
        let options = Options::new(min_chars as usize, encodings)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        Ok(Self {
            scanner: Scanner::new(options),
            found: Vec::new(),
        })
    }

    /// Consume the next slice; return the strings it completed as rows.
    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.found.clear();
        self.scanner.push(chunk, &mut self.found);
        rows_json(&self.found)
    }

    /// End the input; return the remaining strings as rows.
    pub fn finish(&mut self) -> String {
        self.found.clear();
        self.scanner.finish(&mut self.found);
        rows_json(&self.found)
    }
}

/// Certificate scanning over overlapping windows of one file.
#[wasm_bindgen]
pub struct CertificateScan {
    scan: certificates::Scan,
}

impl Default for CertificateScan {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl CertificateScan {
    /// An empty scan.
    #[wasm_bindgen(constructor)]
    pub fn new() -> CertificateScan {
        Self {
            scan: certificates::Scan::new(),
        }
    }

    /// Record certificates starting in `window[..report_len]`; the window's
    /// first byte is at file offset `base`.
    pub fn push_window(&mut self, window: &[u8], base: u64, report_len: u32) {
        self.scan.push_window(window, base, report_len as usize);
    }

    /// Describe and link everything found; the report as JSON. The scan is
    /// empty afterwards.
    pub fn finish(&mut self) -> String {
        let report = std::mem::take(&mut self.scan).finish();
        serde_json::to_string(&report)
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() }).to_string())
    }
}

/// Duplicate and issuer links among certificates gathered from several
/// files, for the workbench's all-files certificate view.
#[wasm_bindgen]
#[derive(Default)]
pub struct CertificateLinks {
    ders: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl CertificateLinks {
    /// An empty set.
    #[wasm_bindgen(constructor)]
    pub fn new() -> CertificateLinks {
        Self::default()
    }

    /// Add one DER certificate to the set.
    pub fn push(&mut self, der: &[u8]) {
        self.ders.push(der.to_vec());
    }

    /// Link the set (see [`certificates::link`]); the links in push order
    /// as JSON, `[{"duplicate_of", "issuer_index", "self_issued"}, ...]`.
    /// The set is empty afterwards.
    pub fn finish(&mut self) -> String {
        let links = certificates::link(std::mem::take(&mut self.ders));
        serde_json::to_string(&links)
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() }).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_carry_encoding_indexes_and_tag_bits() {
        let mut scan = StringScan::new(4, 0b0001).unwrap();
        let mut rows = scan.push(b"\x00https://example.invalid/\x00");
        rows.push_str(&scan.finish());
        assert_eq!(
            rows,
            r#"[[1,24,24,0,1,false,"https://example.invalid/"]][]"#
        );
        assert_eq!(
            string_encoding_ids(),
            r#"["ascii","utf8","utf16le","utf16be"]"#
        );
        assert!(string_tag_ids().starts_with(r#"[[1,"url"],[2,"email"]"#));
    }

    #[test]
    fn certificate_windows_finish_as_one_report() {
        let leaf = include_bytes!("../../tests/fixtures/certificates/leaf.der");
        let mut data = vec![0u8; 100];
        data.extend_from_slice(leaf);
        let mut scan = CertificateScan::new();
        scan.push_window(&data[..64], 0, 64);
        scan.push_window(&data[64..], 64, (data.len() - 64) as u32);
        let report: serde_json::Value = serde_json::from_str(&scan.finish()).unwrap();
        assert_eq!(report["certificates"][0]["offset"], 100);
        assert_eq!(certificate_window_overlap(), 2 << 20);
    }

    #[test]
    fn certificate_links_link_certificates_pushed_separately() {
        let root = include_bytes!("../../tests/fixtures/certificates/root.der");
        let leaf = include_bytes!("../../tests/fixtures/certificates/leaf.der");
        let intermediate = include_bytes!("../../tests/fixtures/certificates/intermediate.der");
        let mut links = CertificateLinks::new();
        for der in [&leaf[..], &intermediate[..], &root[..]] {
            links.push(der);
        }
        assert_eq!(
            links.finish(),
            concat!(
                r#"[{"duplicate_of":null,"issuer_index":1,"self_issued":false},"#,
                r#"{"duplicate_of":null,"issuer_index":2,"self_issued":false},"#,
                r#"{"duplicate_of":null,"issuer_index":null,"self_issued":true}]"#,
            )
        );
        assert_eq!(links.finish(), "[]");
    }
}
