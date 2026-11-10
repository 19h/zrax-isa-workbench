//! `wasm-bindgen` surface of the workbench engine for the browser's
//! analysis worker. Each method forwards to [`Engine`] and encodes the
//! result the way `web/analysis-worker.js` reads it: JSON text for
//! structures, typed arrays for cells and bytes, and `{"error": message}`
//! for failures of JSON-returning methods.

use std::sync::Arc;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::engine::{self, Curve, Engine, Patch};

/// A serialized value, or the error object the worker checks for.
fn json_or_error<T: Serialize>(result: crate::Result<T>) -> String {
    match result {
        Ok(value) => serde_json::to_string(&value).unwrap_or_else(|error| error_json(&error)),
        Err(error) => error_json(&error),
    }
}

fn error_json(error: &dyn std::fmt::Display) -> String {
    serde_json::json!({ "error": error.to_string() }).to_string()
}

/// One binary's resident analysis state, owned by a browser worker.
#[wasm_bindgen]
pub struct WorkbenchEngine {
    engine: Engine,
}

#[wasm_bindgen]
impl WorkbenchEngine {
    /// Copy the binary into resident WASM memory once.
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> Self {
        Self {
            engine: Engine::new(Arc::from(data)),
        }
    }

    /// Run the existing architecture classifier against the resident binary.
    pub fn classification(&self) -> String {
        if self.engine.is_opaque() {
            return serde_json::json!({ "error": "Opaque component; ISA analysis was not applied" }).to_string();
        }
        crate::wasm::classify(self.engine.data())
    }

    /// Copy opaque component bytes for entropy and hex inspection without
    /// applying the code model to ciphertext, metadata or configuration.
    pub fn opaque(data: &[u8]) -> Self {
        Self {
            engine: Engine::opaque(Arc::from(data)),
        }
    }

    /// List validated children and load sections with their stored coordinates.
    pub fn subfiles(&self) -> String {
        json_or_error(self.engine.subfiles())
    }

    /// Labelled stored ranges: sections, members and signature structures.
    /// They place strings and certificates and are computed for opaque
    /// components too, since they are not classification evidence.
    pub fn regions(&self) -> String {
        json_or_error(self.engine.regions())
    }

    /// Extract the decoded bytes of a listed member; the new file starts at zero.
    ///
    /// # Errors
    ///
    /// A JavaScript error when the member is missing, malformed or too large.
    pub fn subfile(&self, index: u32) -> Result<Vec<u8>, JsValue> {
        // The worker shows this text as is, without the error variant's prefix.
        if self.engine.is_opaque() {
            return Err(JsValue::from_str(
                "Opaque components have no analyzed subfiles",
            ));
        }
        self.engine
            .subfile(index as usize)
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Payload coordinates and encoded keybags for inline Image4 controls.
    /// Key material stays in session memory and is never added to payload JSON.
    pub fn image4_info(&self) -> String {
        json_or_error(self.engine.image4_info())
    }

    /// Decrypt an Image4 payload using hex material. `auto` requires a unique
    /// recognized structure; `cbc` and `ctr` permit inspecting raw candidates.
    ///
    /// # Errors
    ///
    /// A JavaScript error for invalid material, missing Image4 payload fields,
    /// oversized data or an unsuccessful/ambiguous automatic mode trial.
    pub fn decrypt_image4(&self, key: &str, iv: &str, mode: &str) -> Result<Vec<u8>, JsValue> {
        self.engine
            .decrypt_image4(key, iv, mode)
            .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    /// Exact local entropy for each profile bin, sampling at most 4096 B per bin.
    pub fn profile(&self, points: u32) -> Vec<f32> {
        self.engine.profile(points as usize)
    }

    /// Analyze a bounded tile of map cells. Each cell returns entropy and five
    /// byte-class fractions: zero, control, printable ASCII, high, and 0xff.
    /// Small cells use a centered window of up to 256 B for entropy only.
    pub fn cells(
        &self,
        start: u32,
        span: u32,
        bytes_per_cell: u32,
        from: u32,
        count: u32,
    ) -> Vec<f32> {
        self.engine.cells(start, span, bytes_per_cell, from, count)
    }

    /// Analyze a spatial patch in fixed file coordinates. A Hilbert block at
    /// every resolution contains the same contiguous interval; linear blocks
    /// aggregate the corresponding square of byte rows. Output is row-major.
    // The argument list is the worker's message layout (web/protocol.js).
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub fn spatial_cells(
        &self,
        side: u32,
        scale: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        from: u32,
        count: u32,
        linear: bool,
    ) -> Vec<f32> {
        let curve = if linear {
            Curve::Linear
        } else {
            Curve::Hilbert
        };
        let patch = Patch {
            side,
            scale,
            x,
            y,
            width,
            height,
            curve,
        };
        self.engine.spatial_cells(&patch, from, count)
    }

    /// Inspect a bounded byte window with exact entropy, histogram, Apeiron
    /// forensic byte statistics, and an explicitly labeled raw-DEFLATE ratio.
    pub fn inspect(&self, offset: u32, length: u32) -> String {
        let stats = self.engine.inspect(offset as usize, length as usize);
        serde_json::json!({
            "start": stats.start, "length": stats.length, "entropy": stats.entropy,
            "histogram": stats.histogram.to_vec(),
            "compressed_bytes": stats.compressed_bytes,
            "deflate_ratio": stats.deflate_ratio,
            "text_ratio": stats.text_ratio, "high_ratio": stats.high_ratio,
            "null_ratio": stats.null_ratio, "variation": stats.variation,
        })
        .to_string()
    }

    /// Copy a bounded slice for the hex inspector, never the complete binary.
    pub fn bytes(&self, offset: u32, length: u32) -> Vec<u8> {
        self.engine.bytes(offset as usize, length as usize).to_vec()
    }
}

/// Apeiron's distance-to-pixel permutation for a power-of-two canvas side.
#[wasm_bindgen]
pub fn hilbert_indices(side: u32) -> Vec<u32> {
    engine::hilbert_indices(side)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workbench::hilbert_distance;

    #[test]
    fn exact_entropy_and_tail_classes() {
        let bytes: Vec<u8> = (0..=255).collect();
        let engine = WorkbenchEngine::new(&bytes);
        let cells = engine.cells(0, 256, 256, 0, 1);
        assert!((cells[0] - 8.0).abs() < 1e-6);
        assert!((cells[1..6].iter().sum::<f32>() - 1.0).abs() < 1e-6);
        let tail = engine.cells(254, 2, 256, 0, 1);
        assert_eq!(tail[0], 1.0);
        assert_eq!(tail[4], 0.5);
        assert_eq!(tail[5], 0.5);
    }

    #[test]
    fn compression_is_a_measured_unclamped_ratio() {
        let engine = WorkbenchEngine::new(&[0; 4096]);
        let value: serde_json::Value = serde_json::from_str(&engine.inspect(0, 4096)).unwrap();
        assert_eq!(value["entropy"], 0.0);
        assert!(value["deflate_ratio"].as_f64().unwrap() < 0.02);
        let short = WorkbenchEngine::new(&[42]);
        let value: serde_json::Value = serde_json::from_str(&short.inspect(0, 1)).unwrap();
        assert!(value["deflate_ratio"].as_f64().unwrap() > 1.0);
    }

    #[test]
    fn empty_and_out_of_bounds_windows_are_defined() {
        let engine = WorkbenchEngine::new(&[]);
        assert_eq!(engine.profile(0), vec![0.0]);
        assert_eq!(engine.cells(u32::MAX, u32::MAX, 0, 0, 1), vec![0.0; 6]);
        assert!(engine.bytes(u32::MAX, u32::MAX).is_empty());
        let value: serde_json::Value = serde_json::from_str(&engine.inspect(0, 4096)).unwrap();
        assert!(value["deflate_ratio"].is_null());
    }

    #[test]
    fn regions_are_json_for_containers_and_opaque_components() {
        let tar = include_bytes!("../../tests/fixtures/archives/gnu.tar");
        for engine in [WorkbenchEngine::new(tar), WorkbenchEngine::opaque(tar)] {
            let value: serde_json::Value = serde_json::from_str(&engine.regions()).unwrap();
            let regions = value.as_array().unwrap();
            assert!(!regions.is_empty());
            assert_eq!(regions[0]["kind"], "member");
        }
        let empty = WorkbenchEngine::new(b"no structure");
        assert_eq!(empty.regions(), "[]");
    }

    #[test]
    fn map_permutation_is_bijective() {
        let positions = hilbert_indices(256);
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..65536).collect::<Vec<u32>>());
        assert!(hilbert_indices(3).is_empty());
        assert!(hilbert_indices(1024).is_empty());
    }

    #[test]
    fn spatial_hilbert_cells_preserve_coarse_file_intervals() {
        let bytes: Vec<u8> = (0..65536).map(|i| (i / 256) as u8).collect();
        let engine = WorkbenchEngine::new(&bytes);
        let cells = engine.spatial_cells(256, 16, 0, 0, 16, 16, 0, 256, false);
        for y in 0..16 {
            for x in 0..16 {
                let d = hilbert_distance(16, x, y) as usize;
                let index = (y * 16 + x) as usize;
                assert_eq!(cells[index * 6], 0.0);
                let expected = engine.cells(0, 65536, 256, d as u32, 1);
                assert_eq!(&cells[index * 6..index * 6 + 6], expected.as_slice());
            }
        }
    }

    #[test]
    fn linear_spatial_cells_aggregate_squares_and_clip_eof() {
        let bytes: Vec<u8> = (0..1000).map(|i| (i / 32) as u8).collect();
        let engine = WorkbenchEngine::new(&bytes);
        let cells = engine.spatial_cells(32, 16, 0, 0, 2, 2, 0, 4, true);
        assert_eq!(cells[0], 4.0);
        assert!((cells[2] - 15.0 / 16.0).abs() < 1e-6);
        let hole = engine.spatial_cells(32, 1, 31, 31, 1, 1, 0, 1, true);
        assert_eq!(hole, vec![-1.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        assert!(engine
            .spatial_cells(3, 1, 0, 0, 1, 1, 0, 1, false)
            .is_empty());
    }
}
