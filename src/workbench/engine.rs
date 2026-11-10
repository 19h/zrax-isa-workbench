//! The workbench's resident analysis of one binary: classification,
//! members, entropy maps and bounded byte windows.
//!
//! Measurement definitions (entropy formula, sampled profile, raw-DEFLATE
//! ratio) and the map's coordinate invariants are recorded in
//! `web/README.md`. All offsets and sizes are bytes of the resident binary.

// Measurements go to the map as `f32`, and every converted count or index
// is bounded by the limits below (a window, a tile, or a map of at most
// `MAX_MAP_SIDE` squared cells), so these conversions lose nothing that is
// reported.
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use std::sync::Arc;

use super::apeiron::{byte::ByteAnalysis, entropy, hilbert};
use crate::formats::apple::Image4Info;
use crate::inspection::{Region, Subfile};
use crate::types::{ClassifierOptions, DetectionPayload};
use crate::{ClassifierError, Result};

/// Values per map cell: entropy, then the zero, control, printable ASCII,
/// high and `0xFF` byte-class fractions.
pub const CELL_VALUES: usize = 6;

/// Entropy value of a map cell that lies beyond the end of the binary.
pub const HOLE_ENTROPY: f32 = -1.0;

/// Most profile bins one call computes.
pub const MAX_PROFILE_POINTS: usize = 4096;

/// Most cells one call computes, so a tile stays a bounded unit of work.
pub const MAX_CELLS_PER_CALL: usize = 65536;

/// Largest map side in cells; a power of two.
pub const MAX_MAP_SIDE: u32 = 32768;

/// Largest canvas side [`hilbert_indices`] permutes.
pub const MAX_PERMUTATION_SIDE: u32 = 512;

/// Largest window [`Engine::inspect`] and [`Engine::bytes`] return, in bytes.
pub const MAX_WINDOW_BYTES: usize = 4 * 1024 * 1024;

/// Bytes sampled per profile bin, centered in the bin.
const PROFILE_SAMPLE_BYTES: usize = 4096;

/// Cells smaller than this take their entropy from a centered window of
/// this many bytes: fewer samples cannot reach 8 bits per byte.
const ENTROPY_WINDOW_BYTES: usize = 256;

/// The raw-DEFLATE level of the complexity measure.
const DEFLATE_LEVEL: u8 = 6;

/// How file offsets are laid out on the square map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// A Hilbert curve: a block at every resolution holds one contiguous
    /// file interval.
    Hilbert,
    /// Rows of `side` bytes, left to right, top to bottom.
    Linear,
}

/// A rectangle of map cells at one resolution. The map is `side` × `side`
/// bytes; each cell covers `scale` × `scale` of them, so the grid at this
/// resolution is `side / scale` cells wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patch {
    /// Map side in bytes; a power of two, at most [`MAX_MAP_SIDE`].
    pub side: u32,
    /// Bytes per cell side; a power of two, at most `side`.
    pub scale: u32,
    /// Left cell column of the patch.
    pub x: u32,
    /// Top cell row of the patch.
    pub y: u32,
    /// Patch width in cells.
    pub width: u32,
    /// Patch height in cells.
    pub height: u32,
    /// The layout of file offsets on the map.
    pub curve: Curve,
}

/// Statistics of one bounded byte window.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// Offset of the window's first byte.
    pub start: usize,
    /// Window size in bytes, after clipping to the binary.
    pub length: usize,
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
    /// Count of each byte value.
    pub histogram: [u32; 256],
    /// Size of the window as raw DEFLATE at level 6; `None` when empty.
    pub compressed_bytes: Option<usize>,
    /// `compressed_bytes / length`, unclamped; `None` when empty.
    pub deflate_ratio: Option<f64>,
    /// Fraction of printable ASCII bytes.
    pub text_ratio: f32,
    /// Fraction of bytes with the high bit set.
    pub high_ratio: f32,
    /// Fraction of zero bytes.
    pub null_ratio: f32,
    /// Apeiron's normalized byte-to-byte variation estimate.
    pub variation: f32,
}

/// One binary's resident analysis state.
#[derive(Debug, Clone)]
pub struct Engine {
    data: Arc<[u8]>,
    opaque: bool,
}

impl Engine {
    /// Analyze `data` as a file: classification and members apply.
    pub fn new(data: Arc<[u8]>) -> Self {
        Self {
            data,
            opaque: false,
        }
    }

    /// Inspect an opaque component (ciphertext, metadata, configuration):
    /// entropy and bytes only, never the code model.
    pub fn opaque(data: Arc<[u8]>) -> Self {
        Self { data, opaque: true }
    }

    /// The resident bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The resident bytes as a shared buffer, for analyses that outlive a
    /// borrow of the engine.
    pub fn shared_data(&self) -> Arc<[u8]> {
        Arc::clone(&self.data)
    }

    /// Whether this is an opaque component.
    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    /// Run the classifier; `None` for an opaque component, to which ISA
    /// analysis is not applied.
    ///
    /// # Errors
    ///
    /// Any [`ClassifierError`] of [`crate::detect_payload`].
    pub fn classification(&self) -> Result<Option<DetectionPayload>> {
        if self.opaque {
            return Ok(None);
        }
        crate::detect_payload(&self.data, &ClassifierOptions::new()).map(Some)
    }

    /// Validated children and load sections with their stored coordinates;
    /// empty for an opaque component.
    ///
    /// # Errors
    ///
    /// The container's parse error.
    pub fn subfiles(&self) -> Result<Vec<Subfile>> {
        if self.opaque {
            return Ok(Vec::new());
        }
        crate::inspection::subfiles(&self.data)
    }

    /// Labelled stored ranges: sections, members and signature structures.
    /// They place strings and certificates and are computed for opaque
    /// components too, since they are not classification evidence.
    ///
    /// # Errors
    ///
    /// The format's parse error.
    pub fn regions(&self) -> Result<Vec<Region>> {
        crate::inspection::regions(&self.data)
    }

    /// The decoded bytes of a listed member; the new file starts at zero.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::InspectionError`] for an opaque component;
    /// otherwise the errors of [`crate::inspection::extract_subfile`].
    pub fn subfile(&self, index: usize) -> Result<Vec<u8>> {
        if self.opaque {
            return Err(ClassifierError::InspectionError {
                message: "Opaque components have no analyzed subfiles".into(),
            });
        }
        crate::inspection::extract_subfile(&self.data, index)
    }

    /// Payload coordinates and encoded keybags of an IMG4 or IM4P; `None`
    /// for other formats. Key material is never added to payload JSON.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::AppleParseError`] for malformed payload fields.
    pub fn image4_info(&self) -> Result<Option<Image4Info>> {
        crate::formats::apple::image4_info(&self.data)
    }

    /// Decrypt an Image4 payload with hexadecimal key material (whitespace
    /// ignored). `mode` is `auto`, `cbc` or `ctr`: `auto` requires a unique
    /// recognized structure, the others permit inspecting raw candidates.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::AppleParseError`] for a missing payload, invalid
    /// material or an unknown mode; the errors of [`crate::image4`] for an
    /// unsuccessful or ambiguous trial.
    pub fn decrypt_image4(&self, key: &str, iv: &str, mode: &str) -> Result<Vec<u8>> {
        use crate::image4::{self, Mode};
        let invalid = |message: &str| ClassifierError::AppleParseError {
            message: message.into(),
        };
        let info = crate::formats::apple::image4_info(&self.data)?
            .ok_or_else(|| invalid("Missing Image4 payload"))?;
        let normalize = |text: &str| {
            text.chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>()
        };
        let key =
            hex::decode(normalize(key)).map_err(|_| invalid("Invalid AES key hexadecimal"))?;
        let iv = hex::decode(normalize(iv)).map_err(|_| invalid("Invalid AES IV hexadecimal"))?;
        let end = info
            .offset
            .checked_add(info.size)
            .ok_or_else(|| invalid("Invalid Image4 payload range"))?;
        let payload = self
            .data
            .get(info.offset..end)
            .ok_or_else(|| invalid("Truncated Image4 payload"))?;
        let trial = match mode {
            "auto" => image4::automatic(payload, &key, &iv)?,
            "cbc" => image4::trial(payload, &key, &iv, Mode::Cbc)?,
            "ctr" => image4::trial(payload, &key, &iv, Mode::Ctr)?,
            _ => return Err(invalid("Unsupported Image4 AES mode")),
        };
        Ok(trial.data)
    }

    /// Exact local entropy for each of `points` equal bins (clamped to
    /// 1..=[`MAX_PROFILE_POINTS`] and to the binary's size), sampling at
    /// most 4096 B centered in each bin.
    pub fn profile(&self, points: usize) -> Vec<f32> {
        let points = points
            .clamp(1, MAX_PROFILE_POINTS)
            .min(self.data.len().max(1));
        (0..points)
            .map(|i| {
                let quotient = self.data.len() / points;
                let remainder = self.data.len() % points;
                let a = i * quotient + i.min(remainder);
                let b = (i + 1) * quotient + (i + 1).min(remainder);
                let length = (b - a).min(PROFILE_SAMPLE_BYTES);
                let start = a + (b - a - length) / 2;
                entropy::calculate_entropy(&self.data[start..start + length]) as f32
            })
            .collect()
    }

    /// Analyze `count` consecutive cells of `bytes_per_cell` bytes, starting
    /// at cell `from` of the interval `start..start + span`. Each cell
    /// yields [`CELL_VALUES`] numbers. Cells under 256 B take their entropy
    /// from a centered 256 B window; the class fractions are always the
    /// cell's own.
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
        let count = (count as usize).min(MAX_CELLS_PER_CALL);
        let mut output = Vec::with_capacity(count * CELL_VALUES);
        let mut histogram = [0u32; 256];
        for i in 0..count {
            let a = start
                .saturating_add((from as usize + i).saturating_mul(bpc))
                .min(end);
            let b = a.saturating_add(bpc).min(end);
            let window = bpc.max(ENTROPY_WINDOW_BYTES).min(self.data.len());
            let ws = if bpc < ENTROPY_WINDOW_BYTES {
                a.saturating_add((b - a) / 2)
                    .saturating_sub(window / 2)
                    .min(self.data.len() - window)
            } else {
                a
            };
            let we = if bpc < ENTROPY_WINDOW_BYTES {
                ws + window
            } else {
                b
            };
            let h = if a == b {
                0.0
            } else {
                entropy::calculate_entropy_with_buffer(&self.data[ws..we], &mut histogram)
            };
            if bpc < ENTROPY_WINDOW_BYTES || a == b {
                histogram.fill(0);
                for &byte in &self.data[a..b] {
                    histogram[byte as usize] += 1;
                }
            }
            let length = (b - a).max(1) as f32;
            output.extend_from_slice(&cell_values(h as f32, &histogram, length));
        }
        output
    }

    /// Analyze cells `from..from + count` of `patch` in row-major order.
    /// Each cell yields [`CELL_VALUES`] numbers; a cell beyond the grid or
    /// the end of the binary has [`HOLE_ENTROPY`] and zero fractions.
    /// Returns nothing for a patch whose `side` or `scale` is not a power
    /// of two, whose side exceeds [`MAX_MAP_SIDE`], or that is empty.
    pub fn spatial_cells(&self, patch: &Patch, from: u32, count: u32) -> Vec<f32> {
        const HOLE: [f32; CELL_VALUES] = [HOLE_ENTROPY, 0.0, 0.0, 0.0, 0.0, 0.0];
        if !patch.side.is_power_of_two()
            || !patch.scale.is_power_of_two()
            || patch.scale > patch.side
            || patch.side > MAX_MAP_SIDE
            || patch.width == 0
            || patch.height == 0
        {
            return Vec::new();
        }
        let linear = patch.curve == Curve::Linear;
        let side = patch.side as usize;
        let scale = patch.scale as usize;
        let width = patch.width as usize;
        let grid = side / scale;
        let from = from as usize;
        let count = (count as usize).min(MAX_CELLS_PER_CALL).min(
            width
                .saturating_mul(patch.height as usize)
                .saturating_sub(from),
        );
        let mut out = Vec::with_capacity(count * CELL_VALUES);
        let mut histogram = [0u32; 256];
        let mut linear_bytes = Vec::new();
        for i in from..from + count {
            let px = patch.x as usize + i % width;
            let py = patch.y as usize + i / width;
            if px >= grid || py >= grid {
                out.extend_from_slice(&HOLE);
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
                out.extend_from_slice(&HOLE);
                continue;
            }
            let actual = if linear {
                linear_bytes.as_slice()
            } else {
                &self.data[origin..origin + length]
            };
            let cell_entropy = entropy::calculate_entropy_with_buffer(actual, &mut histogram);
            let h = if scale * scale < ENTROPY_WINDOW_BYTES {
                let window = ENTROPY_WINDOW_BYTES.min(self.data.len());
                let a = origin
                    .saturating_sub(window / 2)
                    .min(self.data.len() - window);
                entropy::calculate_entropy(&self.data[a..a + window])
            } else {
                cell_entropy
            };
            out.extend_from_slice(&cell_values(h as f32, &histogram, length as f32));
        }
        out
    }

    /// Inspect the window `offset..offset + length`, clipped to the binary
    /// and to [`MAX_WINDOW_BYTES`]: exact entropy, histogram, Apeiron's
    /// byte statistics and a measured raw-DEFLATE ratio.
    pub fn inspect(&self, offset: usize, length: usize) -> Inspection {
        let (start, end) = self.window(offset, length);
        let bytes = &self.data[start..end];
        let mut histogram = [0u32; 256];
        let entropy = entropy::calculate_entropy_with_buffer(bytes, &mut histogram);
        let compressed_bytes = if bytes.is_empty() {
            None
        } else {
            Some(miniz_oxide::deflate::compress_to_vec(bytes, DEFLATE_LEVEL).len())
        };
        let analysis = ByteAnalysis::analyze(bytes);
        Inspection {
            start,
            length: bytes.len(),
            entropy,
            histogram,
            compressed_bytes,
            deflate_ratio: compressed_bytes.map(|n| n as f64 / bytes.len() as f64),
            text_ratio: analysis.text_ratio,
            high_ratio: analysis.high_ratio,
            null_ratio: analysis.null_ratio,
            variation: analysis.variation,
        }
    }

    /// The bytes of `offset..offset + length`, clipped to the binary and to
    /// [`MAX_WINDOW_BYTES`].
    pub fn bytes(&self, offset: usize, length: usize) -> &[u8] {
        let (start, end) = self.window(offset, length);
        &self.data[start..end]
    }

    fn window(&self, offset: usize, length: usize) -> (usize, usize) {
        let start = offset.min(self.data.len());
        let end = start
            .saturating_add(length.min(MAX_WINDOW_BYTES))
            .min(self.data.len());
        (start, end)
    }
}

/// One cell's output: entropy, then each byte class as a fraction of
/// `length` bytes.
fn cell_values(entropy: f32, histogram: &[u32; 256], length: f32) -> [f32; CELL_VALUES] {
    let zero = histogram[0] as f32 / length;
    let control = (histogram[1..32].iter().sum::<u32>() + histogram[127]) as f32 / length;
    let ascii = histogram[32..127].iter().sum::<u32>() as f32 / length;
    let high = histogram[128..255].iter().sum::<u32>() as f32 / length;
    let ff = histogram[255] as f32 / length;
    [entropy, zero, control, ascii, high, ff]
}

/// Apeiron's distance-to-pixel permutation for a power-of-two canvas side:
/// element `d` is `y * side + x` of the `d`-th point on the curve. Empty
/// when `side` is not a power of two or exceeds [`MAX_PERMUTATION_SIDE`].
pub fn hilbert_indices(side: u32) -> Vec<u32> {
    if !side.is_power_of_two() || side > MAX_PERMUTATION_SIDE {
        return Vec::new();
    }
    (0..u64::from(side) * u64::from(side))
        .map(|d| {
            let (x, y) = hilbert::d2xy(u64::from(side), d);
            (y * u64::from(side) + x) as u32
        })
        .collect()
}

/// Distance along the Hilbert curve of cell (`x`, `y`) on a grid `side`
/// cells wide; `side` must be a power of two.
pub fn hilbert_distance(side: u64, x: u64, y: u64) -> u64 {
    hilbert::xy2d(side, x, y)
}

/// The cell (`x`, `y`) at `distance` along the Hilbert curve of a grid
/// `side` cells wide; `side` must be a power of two.
pub fn hilbert_point(side: u64, distance: u64) -> (u64, u64) {
    hilbert::d2xy(side, distance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(bytes: &[u8]) -> Engine {
        Engine::new(Arc::from(bytes))
    }

    #[test]
    fn opaque_components_are_inspected_but_never_classified() {
        let tar = include_bytes!("../../tests/fixtures/archives/gnu.tar");
        let opaque = Engine::opaque(Arc::from(&tar[..]));
        assert!(opaque.classification().unwrap().is_none());
        assert!(opaque.subfiles().unwrap().is_empty());
        assert!(!opaque.regions().unwrap().is_empty());
        let error = opaque.subfile(0).unwrap_err().to_string();
        assert!(error.contains("Opaque components have no analyzed subfiles"));
        assert!(engine(tar).classification().unwrap().is_some());
        assert!(!engine(tar).subfiles().unwrap().is_empty());
    }

    #[test]
    fn inspection_reports_a_measured_unclamped_ratio() {
        let zeros = engine(&[0; 4096]).inspect(0, 4096);
        assert_eq!(zeros.entropy, 0.0);
        assert_eq!(zeros.histogram[0], 4096);
        assert!(zeros.deflate_ratio.unwrap() < 0.02);
        let short = engine(&[42]).inspect(0, 1);
        assert!(short.deflate_ratio.unwrap() > 1.0);
        let empty = engine(&[]).inspect(0, 4096);
        assert_eq!((empty.start, empty.length), (0, 0));
        assert!(empty.compressed_bytes.is_none() && empty.deflate_ratio.is_none());
    }

    #[test]
    fn windows_are_clipped_to_the_binary_and_the_window_limit() {
        let data = vec![7u8; MAX_WINDOW_BYTES + 10];
        let engine = engine(&data);
        assert_eq!(engine.bytes(0, usize::MAX).len(), MAX_WINDOW_BYTES);
        assert_eq!(engine.bytes(MAX_WINDOW_BYTES + 4, 100).len(), 6);
        assert!(engine.bytes(usize::MAX, usize::MAX).is_empty());
    }

    #[test]
    fn hilbert_distance_and_point_are_inverse() {
        for distance in 0..256 {
            let (x, y) = hilbert_point(16, distance);
            assert_eq!(hilbert_distance(16, x, y), distance);
        }
    }

    #[test]
    fn a_shared_buffer_is_not_copied() {
        let data: Arc<[u8]> = Arc::from(&b"shared"[..]);
        let engine = Engine::new(data.clone());
        assert!(std::ptr::eq(engine.data().as_ptr(), data.as_ptr()));
    }
}
