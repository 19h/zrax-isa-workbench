//! WebAssembly bindings for the ISA classifier.
//!
//! Exposes `classify` as a JS-callable function via wasm-bindgen.
//! Accepts a `Uint8Array` and returns a JSON string with the full
//! detection payload (format, ISA, candidates, metadata, extensions, notes).

use wasm_bindgen::prelude::*;

use crate::types::ClassifierOptions;
use crate::{detect_payload, version};

/// Classify a binary blob and return the full detection payload as JSON.
///
/// # Arguments
/// * `data` - raw file bytes (`Uint8Array` from JS)
///
/// # Returns
/// A JSON string containing the `DetectionPayload`, or an error message string
/// prefixed with `"ERROR: "` if classification fails.
#[wasm_bindgen]
pub fn classify(data: &[u8]) -> String {
    let options = ClassifierOptions::new();
    match detect_payload(data, &options) {
        Ok(payload) => serde_json::to_string(&payload)
            .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e)),
        Err(e) => {
            // Return a valid JSON error object so JS can always JSON.parse()
            let msg = format!("{}", e).replace('\"', "\\\"");
            format!("{{\"error\": \"{}\"}}", msg)
        }
    }
}

/// Return the library version string.
#[wasm_bindgen]
pub fn classifier_version() -> String {
    version().to_string()
}
