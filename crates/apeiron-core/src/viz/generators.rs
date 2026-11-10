//! Pixel generation functions for binary visualizations.
//!
//! Each generator produces a Vec<Color32> for rendering visualization textures.
//!
//! Optimizations:
//! - Parallel digraph counting with thread-local histograms
//! - Precomputed histogram caching for similarity matrix
//! - SIMD chi-squared distance computation
//! - Reduced texture generation overhead

use crate::compat::{Color32, Vec2};
use rayon::prelude::*;

use crate::analysis::jsd::JsdWindow;
use crate::analysis::{ByteAnalysis, JSDAnalysis, KolmogorovAnalysis, ANALYSIS_WINDOW};
use crate::hilbert::{xy2d, HilbertBuffer};

// =============================================================================
// Color Utilities
// =============================================================================

/// Convert HSV to RGB Color32.
///
/// - hue: 0-360 degrees
/// - saturation: 0-1
/// - value: 0-1
#[inline]
pub fn hsv_to_rgb(hue: f64, saturation: f64, value: f64) -> Color32 {
    let h = (hue % 360.0) / 60.0;
    let c = value * saturation;
    let x = c * (1.0 - (h % 2.0 - 1.0).abs());
    let m = value - c;

    let (r, g, b) = if h < 1.0 {
        (c, x, 0.0)
    } else if h < 2.0 {
        (x, c, 0.0)
    } else if h < 3.0 {
        (0.0, c, x)
    } else if h < 4.0 {
        (0.0, x, c)
    } else if h < 5.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    Color32::from_rgb(
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

/// Map similarity value (0-1) to color for recurrence plots.
/// Uses "inferno" colormap style for better perceptual uniformity.
#[inline]
pub fn similarity_to_color(similarity: f64, is_diagonal: bool) -> Color32 {
    let t = similarity.clamp(0.0, 1.0).powf(0.4);

    if is_diagonal {
        return Color32::from_rgb((180.0 + t * 75.0) as u8, (220.0 + t * 35.0) as u8, 255);
    }

    let (r, g, b) = if t < 0.2 {
        let s = t / 0.2;
        (s * 0.25, 0.0, s * 0.35)
    } else if t < 0.4 {
        let s = (t - 0.2) / 0.2;
        (0.25 + s * 0.45, 0.0, 0.35 + s * 0.1)
    } else if t < 0.6 {
        let s = (t - 0.4) / 0.2;
        (0.7 + s * 0.25, s * 0.25, 0.45 - s * 0.35)
    } else if t < 0.8 {
        let s = (t - 0.6) / 0.2;
        (0.95 + s * 0.05, 0.25 + s * 0.45, 0.1 + s * 0.1)
    } else {
        let s = (t - 0.8) / 0.2;
        (1.0, 0.7 + s * 0.3, 0.2 + s * 0.7)
    };

    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

// =============================================================================
// Sample Interval Constants
// =============================================================================

const COMPLEXITY_SAMPLE_INTERVAL: usize = 64;
const RCMSE_SAMPLE_INTERVAL: usize = 64;

// =============================================================================
// Lookup Functions
// =============================================================================

#[inline]
fn lookup_complexity(complexity_map: &[f32], offset: usize) -> f32 {
    if complexity_map.is_empty() {
        return 0.0;
    }
    let index = offset / COMPLEXITY_SAMPLE_INTERVAL;
    complexity_map.get(index).copied().unwrap_or(0.0)
}

#[inline]
fn lookup_rcmse(rcmse_map: &[f32], offset: usize) -> f32 {
    if rcmse_map.is_empty() {
        return 0.5;
    }
    let index = offset / RCMSE_SAMPLE_INTERVAL;
    rcmse_map.get(index).copied().unwrap_or(0.5)
}

/// Collapse repeated integer world coordinates before running an analysis
/// kernel. At 4x zoom, one byte is analyzed once instead of 16 times.
fn render_byte_layout(
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    use_linear: bool,
    color: impl Fn(usize) -> Color32 + Sync,
) -> Vec<Color32> {
    if tex_size == 0 {
        return Vec::new();
    }
    // Overview pixels usually address distinct bytes. Preserve the direct
    // projection path there; coordinate deduplication pays off only at zoom.
    if scale_x >= 1.0 && scale_y >= 1.0 {
        return (0..tex_size * tex_size)
            .into_par_iter()
            .map(|i| {
                let x = world_min.x + (i % tex_size) as f32 * scale_x;
                let y = world_min.y + (i / tex_size) as f32 * scale_y;
                if !x.is_finite()
                    || !y.is_finite()
                    || x < 0.0
                    || y < 0.0
                    || x >= dimension as f32
                    || y >= dimension as f32
                {
                    return Color32::from_rgb(13, 13, 13);
                }
                let offset = if use_linear {
                    y as u64 * dimension + x as u64
                } else {
                    xy2d(dimension, x as u64, y as u64)
                };
                if offset >= file_size {
                    Color32::from_rgb(13, 13, 13)
                } else {
                    color(offset as usize)
                }
            })
            .collect();
    }
    let axis = |min: f32, scale: f32| {
        let mut values = Vec::new();
        let mut indices = Vec::with_capacity(tex_size);
        for i in 0..tex_size {
            let world = min + i as f32 * scale;
            let coordinate = if world.is_finite() && world >= 0.0 && world < dimension as f32 {
                Some(world as u64)
            } else {
                None
            };
            if values.last() != Some(&coordinate) {
                values.push(coordinate);
            }
            indices.push(values.len() - 1);
        }
        (values, indices)
    };
    let (xs, x_indices) = axis(world_min.x, scale_x);
    let (ys, y_indices) = axis(world_min.y, scale_y);
    let pixels: Vec<Color32> = (0..xs.len() * ys.len())
        .into_par_iter()
        .map(|i| {
            let (Some(x), Some(y)) = (xs[i % xs.len()], ys[i / xs.len()]) else {
                return Color32::from_rgb(13, 13, 13);
            };
            let offset = if use_linear {
                y * dimension + x
            } else {
                xy2d(dimension, x, y)
            };
            if offset >= file_size {
                Color32::from_rgb(13, 13, 13)
            } else {
                color(offset as usize)
            }
        })
        .collect();
    if xs.len() == tex_size && ys.len() == tex_size {
        return pixels;
    }
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|i| pixels[y_indices[i / tex_size] * xs.len() + x_indices[i % tex_size]])
        .collect()
}

// =============================================================================
// Hilbert Curve Visualization
// =============================================================================

pub fn generate_hilbert_pixels(
    data: &[u8],
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
) -> Vec<Color32> {
    render_byte_layout(
        dimension,
        file_size.min(data.len() as u64),
        tex_size,
        world_min,
        scale_x,
        scale_y,
        false,
        |start| {
            let end = start.saturating_add(ANALYSIS_WINDOW).min(data.len());
            let [r, g, b] = ByteAnalysis::analyze(&data[start..end]).to_color();
            Color32::from_rgb(r, g, b)
        },
    )
}

pub fn generate_hilbert_pixels_progressive(
    buffer: &HilbertBuffer,
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    time_seconds: f64,
) -> Vec<Color32> {
    use crate::hilbert::{entropy_to_color, entropy_to_color_preview, placeholder_pulse_color};

    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let tex_y = idx / tex_size;
            let tex_x = idx % tex_size;

            let world_x = (world_min.x + tex_x as f32 * scale_x) as u64;
            let world_y = (world_min.y + tex_y as f32 * scale_y) as u64;

            if world_x >= dimension || world_y >= dimension {
                return Color32::from_rgb(13, 13, 13);
            }

            let d = xy2d(dimension, world_x, world_y);

            if d >= file_size {
                return Color32::from_rgb(13, 13, 13);
            }

            match buffer.lookup(d) {
                Some((entropy, is_fine)) => {
                    let (r, g, b) = if is_fine {
                        entropy_to_color(entropy)
                    } else {
                        entropy_to_color_preview(entropy)
                    };
                    Color32::from_rgb(r, g, b)
                }
                None => {
                    let (r, g, b) = placeholder_pulse_color(time_seconds);
                    Color32::from_rgb(r, g, b)
                }
            }
        })
        .collect()
}

// =============================================================================
// Linear Layout Visualization
// =============================================================================

/// Generate entropy pixels using linear (row-major) byte mapping.
/// Bytes are laid out left-to-right, top-to-bottom like reading text.
/// This makes it easy to visualize file sections as horizontal bands.
pub fn generate_linear_entropy_pixels(
    data: &[u8],
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
) -> Vec<Color32> {
    let file_size = file_size.min(data.len() as u64);
    if scale_x < 1.0 || scale_y < 1.0 {
        return render_byte_layout(
            dimension,
            file_size,
            tex_size,
            world_min,
            scale_x,
            scale_y,
            true,
            |start| {
                let end = start.saturating_add(ANALYSIS_WINDOW).min(data.len());
                let [r, g, b] = ByteAnalysis::analyze(&data[start..end]).to_color();
                Color32::from_rgb(r, g, b)
            },
        );
    }
    // Keep the direct row-major loop for overview rendering.
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let x = world_min.x + (idx % tex_size) as f32 * scale_x;
            let y = world_min.y + (idx / tex_size) as f32 * scale_y;
            if x < 0.0 || y < 0.0 || !x.is_finite() || !y.is_finite() {
                return Color32::from_rgb(13, 13, 13);
            }
            let world_x = x as u64;
            let world_y = y as u64;
            if world_x >= dimension || world_y >= dimension {
                return Color32::from_rgb(13, 13, 13);
            }
            let offset = world_y * dimension + world_x;
            if offset >= file_size {
                return Color32::from_rgb(13, 13, 13);
            }
            let start = offset as usize;
            let end = start.saturating_add(ANALYSIS_WINDOW).min(data.len());
            let [r, g, b] = ByteAnalysis::analyze(&data[start..end]).to_color();
            Color32::from_rgb(r, g, b)
        })
        .collect()
}

pub fn generate_computing_placeholder(tex_size: usize, time_seconds: f64) -> Vec<Color32> {
    let total = tex_size * tex_size;
    let mut pixels = Vec::with_capacity(total);

    let pulse = ((time_seconds * 2.0 * std::f64::consts::PI).sin() * 0.5 + 0.5) as f32;
    let base_color = 25.0 + pulse * 10.0;

    for idx in 0..total {
        let y = idx / tex_size;
        let x = idx % tex_size;
        let gradient = ((x + y) as f32 / (tex_size * 2) as f32) * 15.0;
        let v = (base_color + gradient) as u8;
        pixels.push(Color32::from_rgb(v, v, v.saturating_add(12)));
    }

    pixels
}

// =============================================================================
// Similarity Matrix Visualization (Optimized)
// =============================================================================

const SIMILARITY_WINDOW: usize = 32;

/// A cached axis window: dense counts for O(1) lookup and sparse support
/// for comparisons that visit at most 64 occupied bins, rather than 256.
struct WindowHistogram {
    counts: [u8; 256],
    support: [u8; SIMILARITY_WINDOW],
    distinct: usize,
    total: usize,
    position: usize,
}

impl WindowHistogram {
    fn new(data: &[u8], position: usize) -> Self {
        let mut result = Self {
            counts: [0; 256],
            support: [0; SIMILARITY_WINDOW],
            distinct: 0,
            total: 0,
            position,
        };
        if position >= data.len() {
            return result;
        }
        let end = position.saturating_add(SIMILARITY_WINDOW).min(data.len());
        result.total = end - position;
        for &byte in &data[position..end] {
            let count = &mut result.counts[byte as usize];
            if *count == 0 {
                result.support[result.distinct] = byte;
                result.distinct += 1;
            }
            *count += 1;
        }
        result
    }

    fn distance(&self, other: &Self, terms: &[[f64; 33]; 33]) -> f64 {
        if self.total == 0 || other.total == 0 {
            return 2.0;
        }
        let mut sum = 0.0;
        let full = self.total == SIMILARITY_WINDOW && other.total == SIMILARITY_WINDOW;
        if full {
            // For normalized histograms, chi^2 = 2 - sum(4*p*q/(p+q)).
            // Only shared bins contribute to this sum. No second support pass
            // is needed, and disjoint support gives exactly distance 2.
            let (small, large) = if self.distinct <= other.distinct {
                (self, other)
            } else {
                (other, self)
            };
            for &byte in &small.support[..small.distinct] {
                let y = large.counts[byte as usize] as usize;
                if y != 0 {
                    sum += terms[small.counts[byte as usize] as usize][y];
                }
            }
            return (2.0 - sum).clamp(0.0, 2.0);
        }
        let inv_x = 1.0 / self.total as f64;
        let inv_y = 1.0 / other.total as f64;
        for &byte in &self.support[..self.distinct] {
            let x = self.counts[byte as usize] as usize;
            let y = other.counts[byte as usize] as usize;
            sum += if full {
                terms[x][y]
            } else {
                let p = x as f64 * inv_x;
                let q = y as f64 * inv_y;
                (p - q).powi(2) / (p + q + 1e-30)
            };
        }
        for &byte in &other.support[..other.distinct] {
            if self.counts[byte as usize] == 0 {
                sum += if full {
                    terms[0][other.counts[byte as usize] as usize]
                } else {
                    other.counts[byte as usize] as f64 * inv_y
                };
            }
        }
        sum
    }
}

fn similarity_terms() -> &'static [[f64; 33]; 33] {
    use std::sync::OnceLock;
    static TERMS: OnceLock<[[f64; 33]; 33]> = OnceLock::new();
    TERMS.get_or_init(|| {
        let mut terms = [[0.0; 33]; 33];
        for (x, row) in terms.iter_mut().enumerate() {
            for (y, term) in row.iter_mut().enumerate() {
                let p = x as f64 / SIMILARITY_WINDOW as f64;
                let q = y as f64 / SIMILARITY_WINDOW as f64;
                *term = 4.0 * p * q / (p + q + 1e-30);
            }
        }
        terms
    })
}

pub fn generate_similarity_matrix_pixels(
    data: &[u8],
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    dimension: u64,
) -> Vec<Color32> {
    let dim = dimension as f64;
    let axis = |min: f32, scale: f32| -> Vec<Option<WindowHistogram>> {
        (0..tex_size)
            .map(|i| {
                let world = min + i as f32 * scale;
                if world < 0.0 || world >= dim as f32 {
                    None
                } else {
                    let pos = ((world as f64 / dim) * file_size as f64) as usize;
                    Some(WindowHistogram::new(data, pos))
                }
            })
            .collect()
    };
    // Each histogram is constructed once per axis, rather than twice per pixel.
    let xs = axis(world_min.x, scale_x);
    let ys = axis(world_min.y, scale_y);
    let terms = similarity_terms();
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let (Some(x), Some(y)) = (&xs[idx % tex_size], &ys[idx / tex_size]) else {
                return Color32::from_rgb(10, 10, 15);
            };
            let similarity = 1.0 - (x.distance(y, terms) / 2.0).sqrt();
            let diagonal = x.position.abs_diff(y.position) < SIMILARITY_WINDOW;
            similarity_to_color(similarity, diagonal)
        })
        .collect()
}

// =============================================================================
// Digraph Visualization (Optimized with parallel counting)
// =============================================================================

/// Digraph size constant
const DIGRAPH_SIZE: usize = 256 * 256;

/// Build digraph using parallel thread-local histograms.
/// Optimized with boxed fixed-size arrays and SIMD merge using u64x4.
fn build_digraph_parallel(data: &[u8]) -> (Vec<u64>, u64) {
    use wide::u64x4;

    if data.len() < 2 {
        return (vec![0u64; DIGRAPH_SIZE], 1);
    }

    // Use larger chunks to reduce allocations - minimum 64KB per chunk
    let num_threads = rayon::current_num_threads();
    let chunk_size = (data.len() / num_threads).max(65536);

    // Parallel digraph counting with boxed fixed-size arrays
    let results: Vec<Box<[u64; DIGRAPH_SIZE]>> = data
        .par_chunks(chunk_size)
        .map(|chunk| {
            // Boxed array - single allocation, known size
            let mut local_digraph: Box<[u64; DIGRAPH_SIZE]> =
                unsafe { Box::new_zeroed().assume_init() };

            // Process windows - unroll by 2 for better ILP
            let windows = chunk.windows(2);
            for window in windows {
                let idx = (window[0] as usize) * 256 + (window[1] as usize);
                unsafe {
                    *local_digraph.get_unchecked_mut(idx) += 1;
                }
            }
            local_digraph
        })
        .collect();

    // Allocate output
    let mut digraph = vec![0u64; DIGRAPH_SIZE];

    // Merge with SIMD u64x4 - process 4 elements at a time
    for local in &results {
        for i in (0..DIGRAPH_SIZE).step_by(4) {
            let current = u64x4::new([digraph[i], digraph[i + 1], digraph[i + 2], digraph[i + 3]]);
            let local_vals = u64x4::new([local[i], local[i + 1], local[i + 2], local[i + 3]]);
            let sum = current + local_vals;
            let arr = sum.to_array();
            digraph[i] = arr[0];
            digraph[i + 1] = arr[1];
            digraph[i + 2] = arr[2];
            digraph[i + 3] = arr[3];
        }
    }

    // Find max - scalar loop with unrolling (SIMD max not available for u64x4)
    let mut max_count = 1u64;
    for i in (0..DIGRAPH_SIZE).step_by(4) {
        let m0 = digraph[i];
        let m1 = digraph[i + 1];
        let m2 = digraph[i + 2];
        let m3 = digraph[i + 3];
        // Chain of max operations - compiler optimizes this well
        max_count = max_count.max(m0).max(m1).max(m2).max(m3);
    }

    // Add cross-chunk transitions
    let mut offset = 0;
    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        if i > 0 && offset > 0 {
            let from = data[offset - 1] as usize;
            let to = chunk[0] as usize;
            let idx = from * 256 + to;
            digraph[idx] += 1;
            max_count = max_count.max(digraph[idx]);
        }
        offset += chunk.len();
    }

    (digraph, max_count)
}

/// Color the fixed 256x256 byte-pair space once, then resample its palette.
fn render_pair_palette(
    palette: &[Color32],
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    background: Color32,
) -> Vec<Color32> {
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let x = world_min.x + (idx % tex_size) as f32 * scale_x;
            let y = world_min.y + (idx / tex_size) as f32 * scale_y;
            if !(0.0..256.0).contains(&x) || !(0.0..256.0).contains(&y) {
                background
            } else {
                palette[y as usize * 256 + x as usize]
            }
        })
        .collect()
}

pub fn generate_digraph_pixels(
    data: &[u8],
    _file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
) -> Vec<Color32> {
    let (digraph, max_count) = build_digraph_parallel(data);
    let sqrt_max = (max_count as f64).sqrt();
    let background = Color32::from_rgb(8, 8, 12);
    let palette: Vec<Color32> = digraph
        .par_iter()
        .enumerate()
        .map(|(idx, &count)| {
            if count == 0 {
                return background;
            }
            let intensity = ((count as f64).sqrt() / sqrt_max).powf(0.6);
            let hue = ((idx % 256 + idx / 256) as f64 / 512.0) * 300.0;
            hsv_to_rgb(hue, 0.85 - intensity * 0.2, 0.15 + intensity * 0.85)
        })
        .collect();
    render_pair_palette(&palette, tex_size, world_min, scale_x, scale_y, background)
}

// =============================================================================
// Byte Phase Space Visualization (Optimized)
// =============================================================================

/// Build phase space using parallel counting.
/// Optimized with boxed fixed-size arrays and better merge.
fn build_phase_space_parallel(data: &[u8]) -> (Vec<(u64, u64)>, u64) {
    if data.len() < 2 {
        return (vec![(0u64, 0u64); DIGRAPH_SIZE], 1);
    }

    let num_threads = rayon::current_num_threads();
    let chunk_size = (data.len() / num_threads).max(65536);

    // Each thread computes (last_pos, count) for its chunk using boxed arrays
    let results: Vec<(usize, Box<[(u64, u64); DIGRAPH_SIZE]>)> = data
        .par_chunks(chunk_size)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let base_offset = chunk_idx * chunk_size;
            // Boxed array - single allocation
            let mut local_space: Box<[(u64, u64); DIGRAPH_SIZE]> =
                unsafe { Box::new_zeroed().assume_init() };

            for (i, window) in chunk.windows(2).enumerate() {
                let x = window[0] as usize;
                let y = window[1] as usize;
                let idx = y * 256 + x;
                let pos = (base_offset + i) as u64;
                unsafe {
                    let entry = local_space.get_unchecked_mut(idx);
                    entry.0 = pos;
                    entry.1 += 1;
                }
            }

            let boundary = base_offset + chunk.len() - 1;
            if boundary + 1 < data.len() {
                let idx = data[boundary + 1] as usize * 256 + data[boundary] as usize;
                local_space[idx].0 = boundary as u64;
                local_space[idx].1 += 1;
            }
            (chunk_idx, local_space)
        })
        .collect();

    // Merge results - process in chunk index order for correct position tracking
    let mut phase_space = vec![(0u64, 0u64); DIGRAPH_SIZE];

    // par_chunks is indexed; collect already preserves chunk order.
    for (_chunk_idx, local) in &results {
        // Process 4 elements at a time for better cache usage
        for i in (0..DIGRAPH_SIZE).step_by(4) {
            unsafe {
                for j in 0..4 {
                    let local_entry = local.get_unchecked(i + j);
                    if local_entry.1 > 0 {
                        let entry = phase_space.get_unchecked_mut(i + j);
                        entry.0 = local_entry.0; // Later chunks have higher positions
                        entry.1 += local_entry.1;
                    }
                }
            }
        }
    }

    // Find max count using SIMD-friendly loop
    let mut max_count = 1u64;
    for entry in &phase_space {
        max_count = max_count.max(entry.1);
    }

    (phase_space, max_count)
}

pub fn generate_byte_phase_space_pixels(
    data: &[u8],
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
) -> Vec<Color32> {
    if file_size < 2 {
        return vec![Color32::from_rgb(10, 10, 15); tex_size * tex_size];
    }
    let (phase_space, max_count) = build_phase_space_parallel(data);
    let sqrt_max = (max_count as f64).sqrt();
    let palette: Vec<Color32> = phase_space
        .par_iter()
        .enumerate()
        .map(|(idx, &(last_pos, count))| {
            if count == 0 {
                return Color32::from_rgb(8, 8, 12);
            }
            let intensity = ((count as f64).sqrt() / sqrt_max).powf(0.5);
            let coord_hue = ((idx % 256 + idx / 256) as f64 / 512.0) * 360.0;
            let pos_hue = last_pos as f64 / file_size as f64 * 120.0;
            let hue = (coord_hue * 0.7 + pos_hue * 0.3) % 360.0;
            hsv_to_rgb(hue, 0.75 + intensity * 0.2, 0.1 + intensity * 0.9)
        })
        .collect();
    render_pair_palette(
        &palette,
        tex_size,
        world_min,
        scale_x,
        scale_y,
        Color32::from_rgb(10, 10, 15),
    )
}

// =============================================================================
// Kolmogorov Complexity Visualization
// =============================================================================

pub fn generate_kolmogorov_pixels(
    complexity_map: &[f32],
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    use_linear: bool,
) -> Vec<Color32> {
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let tex_y = idx / tex_size;
            let tex_x = idx % tex_size;

            let world_x = (world_min.x + tex_x as f32 * scale_x) as u64;
            let world_y = (world_min.y + tex_y as f32 * scale_y) as u64;

            if world_x >= dimension || world_y >= dimension {
                return Color32::from_rgb(13, 13, 13);
            }

            let d = if use_linear {
                world_y * dimension + world_x
            } else {
                xy2d(dimension, world_x, world_y)
            };

            if d >= file_size {
                return Color32::from_rgb(13, 13, 13);
            }

            let complexity = lookup_complexity(complexity_map, d as usize);
            let analysis = KolmogorovAnalysis::from_value(complexity as f64);
            let [r, g, b] = analysis.to_color();
            Color32::from_rgb(r, g, b)
        })
        .collect()
}

// =============================================================================
// Jensen-Shannon Divergence Visualization
// =============================================================================

pub fn generate_jsd_pixels(
    data: &[u8],
    reference_distribution: &[f64; 256],
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    use_linear: bool,
) -> Vec<Color32> {
    let prepared = JsdWindow::new(reference_distribution, ANALYSIS_WINDOW);
    render_byte_layout(
        dimension,
        file_size.min(data.len() as u64),
        tex_size,
        world_min,
        scale_x,
        scale_y,
        use_linear,
        |start| {
            let end = start.saturating_add(ANALYSIS_WINDOW).min(data.len());
            let analysis = JSDAnalysis {
                divergence: prepared.divergence(&data[start..end]),
            };
            let [r, g, b] = analysis.to_color();
            Color32::from_rgb(r, g, b)
        },
    )
}

// =============================================================================
// Multi-Scale Entropy (RCMSE) Visualization
// =============================================================================

pub fn generate_rcmse_pixels(
    rcmse_map: &[f32],
    dimension: u64,
    file_size: u64,
    tex_size: usize,
    world_min: Vec2,
    scale_x: f32,
    scale_y: f32,
    use_linear: bool,
) -> Vec<Color32> {
    (0..tex_size * tex_size)
        .into_par_iter()
        .map(|idx| {
            let tex_y = idx / tex_size;
            let tex_x = idx % tex_size;

            let world_x = (world_min.x + tex_x as f32 * scale_x) as u64;
            let world_y = (world_min.y + tex_y as f32 * scale_y) as u64;

            if world_x >= dimension || world_y >= dimension {
                return Color32::from_rgb(13, 13, 13);
            }

            let d = if use_linear {
                world_y * dimension + world_x
            } else {
                xy2d(dimension, world_x, world_y)
            };

            if d >= file_size {
                return Color32::from_rgb(13, 13, 13);
            }

            let rcmse_value = lookup_rcmse(rcmse_map, d as usize);
            let t = rcmse_value.clamp(0.0, 1.0);

            let (r, g, b) = if t < 0.25 {
                let s = t / 0.25;
                (0.4 - s * 0.2, 0.1 + s * 0.2, 0.8 + s * 0.1)
            } else if t < 0.45 {
                let s = (t - 0.25) / 0.2;
                (0.2 - s * 0.1, 0.3 + s * 0.3, 0.9 - s * 0.2)
            } else if t < 0.65 {
                let s = (t - 0.45) / 0.2;
                (0.1, 0.6 + s * 0.2, 0.7 - s * 0.4)
            } else if t < 0.85 {
                let s = (t - 0.65) / 0.2;
                (0.1 + s * 0.8, 0.8, 0.3 - s * 0.2)
            } else {
                let s = (t - 0.85) / 0.15;
                (0.9 + s * 0.1, 0.8 - s * 0.2, 0.1)
            };

            Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{byte_distribution, calculate_jsd};

    #[test]
    fn cached_similarity_distance_matches_scalar_full_and_tail_windows() {
        let data: Vec<u8> = (0..513).map(|i| ((i * 137 + i / 3) % 256) as u8).collect();
        for x in [0, 17, 255, 480, 490, 512, 513] {
            for y in [0, 11, 256, 482, 500, 512, 513] {
                let hx = WindowHistogram::new(&data, x);
                let hy = WindowHistogram::new(&data, y);
                let expected = if hx.total == 0 || hy.total == 0 {
                    2.0
                } else {
                    (0..256)
                        .map(|b| {
                            let p = hx.counts[b] as f64 / hx.total as f64;
                            let q = hy.counts[b] as f64 / hy.total as f64;
                            (p - q).powi(2) / (p + q + 1e-30)
                        })
                        .sum::<f64>()
                };
                assert!((hx.distance(&hy, similarity_terms()) - expected).abs() < 1e-12);
            }
        }
    }

    #[test]
    fn repeated_coordinates_preserve_byte_and_jsd_colors() {
        let data: Vec<u8> = (0..4093).map(|i| ((i * 137 + i / 3) % 256) as u8).collect();
        let reference = byte_distribution(&data);
        for linear in [false, true] {
            for scale in [0.25, 1.0, 2.0] {
                let size = 32;
                let minimum = Vec2::new(-1.0, 59.0);
                let actual = generate_jsd_pixels(
                    &data,
                    &reference,
                    64,
                    data.len() as u64,
                    size,
                    minimum,
                    scale,
                    scale,
                    linear,
                );
                let bytes = if linear {
                    generate_linear_entropy_pixels(
                        &data,
                        64,
                        data.len() as u64,
                        size,
                        minimum,
                        scale,
                        scale,
                    )
                } else {
                    generate_hilbert_pixels(
                        &data,
                        64,
                        data.len() as u64,
                        size,
                        minimum,
                        scale,
                        scale,
                    )
                };
                for i in 0..size * size {
                    let x = minimum.x + (i % size) as f32 * scale;
                    let y = minimum.y + (i / size) as f32 * scale;
                    let background = Color32::from_rgb(13, 13, 13);
                    if !(0.0..64.0).contains(&x) || !(0.0..64.0).contains(&y) {
                        assert_eq!(actual[i], background);
                        assert_eq!(bytes[i], background);
                        continue;
                    }
                    let offset = if linear {
                        y as u64 * 64 + x as u64
                    } else {
                        xy2d(64, x as u64, y as u64)
                    } as usize;
                    if offset >= data.len() {
                        assert_eq!(actual[i], background);
                        assert_eq!(bytes[i], background);
                        continue;
                    }
                    let chunk = &data[offset..(offset + ANALYSIS_WINDOW).min(data.len())];
                    let [r, g, b] = JSDAnalysis {
                        divergence: calculate_jsd(chunk, &reference),
                    }
                    .to_color();
                    let expected = Color32::from_rgb(r, g, b);
                    for (a, e) in actual[i].to_array().iter().zip(expected.to_array()) {
                        assert!(a.abs_diff(e) <= 1);
                    }
                    let [r, g, b] = ByteAnalysis::analyze(chunk).to_color();
                    assert_eq!(bytes[i], Color32::from_rgb(r, g, b));
                }
            }
        }
        assert!(
            generate_jsd_pixels(&data, &reference, 64, 4093, 0, Vec2::ZERO, 1.0, 1.0, false)
                .is_empty()
        );
    }

    #[test]
    fn parallel_pair_counts_include_every_boundary_and_last_position() {
        for len in [0usize, 1, 2, 65537, 2 * 65536 + 17] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + i / 256) as u8).collect();
            let (digraph, _) = build_digraph_parallel(&data);
            let (space, _) = build_phase_space_parallel(&data);
            let mut expected_counts = vec![0u64; DIGRAPH_SIZE];
            let mut expected_space = vec![(0u64, 0u64); DIGRAPH_SIZE];
            for (pos, pair) in data.windows(2).enumerate() {
                expected_counts[pair[0] as usize * 256 + pair[1] as usize] += 1;
                let entry = &mut expected_space[pair[1] as usize * 256 + pair[0] as usize];
                entry.0 = pos as u64;
                entry.1 += 1;
            }
            assert_eq!(digraph, expected_counts);
            assert_eq!(space, expected_space);
            assert_eq!(digraph.iter().sum::<u64>(), len.saturating_sub(1) as u64);
        }
    }
}
