//! Browser workbench analysis using the vendored Apeiron kernels.

#[allow(dead_code, missing_docs)]
mod apeiron {
    pub mod byte;
    pub mod entropy;
    pub mod hilbert;
}

use apeiron::{byte::ByteAnalysis, entropy, hilbert};
use wasm_bindgen::prelude::*;

/// One binary's resident analysis state, owned by a browser worker.
#[wasm_bindgen]
pub struct WorkbenchEngine {
    data: Vec<u8>,
}

#[wasm_bindgen]
impl WorkbenchEngine {
    /// Copy the binary into resident WASM memory once.
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Run the existing architecture classifier against the resident binary.
    pub fn classification(&self) -> String {
        crate::wasm::classify(&self.data)
    }

    /// Exact local entropy for each profile bin, sampling at most 4096 B per bin.
    pub fn profile(&self, points: u32) -> Vec<f32> {
        let points = (points as usize).clamp(1, 4096).min(self.data.len().max(1));
        (0..points)
            .map(|i| {
                let quotient = self.data.len() / points;
                let remainder = self.data.len() % points;
                let a = i * quotient + i.min(remainder);
                let b = (i + 1) * quotient + (i + 1).min(remainder);
                let length = (b - a).min(4096);
                let start = a + (b - a - length) / 2;
                entropy::calculate_entropy(&self.data[start..start + length]) as f32
            })
            .collect()
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
        let start = (start as usize).min(self.data.len());
        let end = start.saturating_add(span as usize).min(self.data.len());
        let bpc = (bytes_per_cell as usize).max(1);
        let count = (count as usize).min(65536);
        let mut output = Vec::with_capacity(count * 6);
        let mut histogram = [0u32; 256];
        for i in 0..count {
            let a = start
                .saturating_add((from as usize + i).saturating_mul(bpc))
                .min(end);
            let b = a.saturating_add(bpc).min(end);
            let window = bpc.max(256).min(self.data.len());
            let ws = if bpc < 256 {
                a.saturating_add((b - a) / 2)
                    .saturating_sub(window / 2)
                    .min(self.data.len() - window)
            } else {
                a
            };
            let we = if bpc < 256 { ws + window } else { b };
            let h = if a == b {
                0.0
            } else {
                entropy::calculate_entropy_with_buffer(&self.data[ws..we], &mut histogram)
            };
            if bpc < 256 || a == b {
                histogram.fill(0);
                for &byte in &self.data[a..b] {
                    histogram[byte as usize] += 1;
                }
            }
            let length = (b - a).max(1) as f32;
            let zero = histogram[0] as f32 / length;
            let control = (histogram[1..32].iter().sum::<u32>() + histogram[127]) as f32 / length;
            let ascii = histogram[32..127].iter().sum::<u32>() as f32 / length;
            let ff = histogram[255] as f32 / length;
            let high = histogram[128..255].iter().sum::<u32>() as f32 / length;
            output.extend_from_slice(&[h as f32, zero, control, ascii, high, ff]);
        }
        output
    }

    /// Analyze a spatial patch in fixed file coordinates. A Hilbert block at
    /// every resolution contains the same contiguous interval; linear blocks
    /// aggregate the corresponding square of byte rows. Output is row-major.
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
        if !side.is_power_of_two()
            || !scale.is_power_of_two()
            || scale > side
            || side > 32768
            || width == 0
            || height == 0
        {
            return Vec::new();
        }
        let side = side as usize;
        let scale = scale as usize;
        let grid = side / scale;
        let count = (count as usize).min(65536).min(
            (width as usize)
                .saturating_mul(height as usize)
                .saturating_sub(from as usize),
        );
        let mut out = Vec::with_capacity(count * 6);
        let mut histogram = [0u32; 256];
        let mut linear_bytes = Vec::new();
        for i in from as usize..from as usize + count {
            let px = x as usize + i % width as usize;
            let py = y as usize + i / width as usize;
            if px >= grid || py >= grid {
                out.extend_from_slice(&[-1.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
                continue;
            }
            let origin = if linear {
                py * scale * side + px * scale
            } else {
                hilbert::xy2d(grid as u64, px as u64, py as u64) as usize * scale * scale
            };
            histogram.fill(0);
            let mut length = 0;
            linear_bytes.clear();
            if linear {
                for row in 0..scale {
                    let a = origin.saturating_add(row * side).min(self.data.len());
                    let b = a.saturating_add(scale).min(self.data.len());
                    linear_bytes.extend_from_slice(&self.data[a..b]);
                    length += b - a;
                }
            } else {
                let a = origin.min(self.data.len());
                let b = a.saturating_add(scale * scale).min(self.data.len());
                length = b - a;
            }
            if length == 0 {
                out.extend_from_slice(&[-1.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
                continue;
            }
            let actual = if linear {
                linear_bytes.as_slice()
            } else {
                &self.data[origin..origin + length]
            };
            let cell_entropy = entropy::calculate_entropy_with_buffer(actual, &mut histogram);
            let h = if scale * scale < 256 {
                let window = 256.min(self.data.len());
                let a = origin
                    .saturating_sub(window / 2)
                    .min(self.data.len() - window);
                entropy::calculate_entropy(&self.data[a..a + window])
            } else {
                cell_entropy
            };
            let n = length as f32;
            out.extend_from_slice(&[
                h as f32,
                histogram[0] as f32 / n,
                (histogram[1..32].iter().sum::<u32>() + histogram[127]) as f32 / n,
                histogram[32..127].iter().sum::<u32>() as f32 / n,
                histogram[128..255].iter().sum::<u32>() as f32 / n,
                histogram[255] as f32 / n,
            ]);
        }
        out
    }

    /// Inspect a bounded byte window with exact entropy, histogram, Apeiron
    /// forensic byte statistics, and an explicitly labeled raw-DEFLATE ratio.
    pub fn inspect(&self, offset: u32, length: u32) -> String {
        let a = (offset as usize).min(self.data.len());
        let b = a
            .saturating_add((length as usize).min(4 * 1024 * 1024))
            .min(self.data.len());
        let bytes = &self.data[a..b];
        let mut histogram = [0u32; 256];
        let h = entropy::calculate_entropy_with_buffer(bytes, &mut histogram);
        let compressed = if bytes.is_empty() {
            None
        } else {
            Some(miniz_oxide::deflate::compress_to_vec(bytes, 6).len())
        };
        let analysis = ByteAnalysis::analyze(bytes);
        serde_json::json!({
            "start": a, "length": bytes.len(), "entropy": h,
            "histogram": histogram.to_vec(),
            "compressed_bytes": compressed,
            "deflate_ratio": compressed.map(|n| n as f64 / bytes.len() as f64),
            "text_ratio": analysis.text_ratio, "high_ratio": analysis.high_ratio,
            "null_ratio": analysis.null_ratio, "variation": analysis.variation,
        })
        .to_string()
    }

    /// Copy a bounded slice for the hex inspector, never the complete binary.
    pub fn bytes(&self, offset: u32, length: u32) -> Vec<u8> {
        let a = (offset as usize).min(self.data.len());
        let b = a
            .saturating_add((length as usize).min(4 * 1024 * 1024))
            .min(self.data.len());
        self.data[a..b].to_vec()
    }
}

/// Apeiron's distance-to-pixel permutation for a power-of-two canvas side.
#[wasm_bindgen]
pub fn hilbert_indices(side: u32) -> Vec<u32> {
    if !side.is_power_of_two() || side > 512 {
        return Vec::new();
    }
    (0..side as u64 * side as u64)
        .map(|d| {
            let (x, y) = hilbert::d2xy(side as u64, d);
            (y * side as u64 + x) as u32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
                let d = hilbert::xy2d(16, x, y) as usize;
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
