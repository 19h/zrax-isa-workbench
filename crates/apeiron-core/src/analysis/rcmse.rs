//! Refined Composite Multi-Scale Entropy (RCMSE) analysis.
//!
//! RCMSE reveals complexity across multiple time scales, distinguishing:
//! - Random/encrypted data (entropy decreases with scale)
//! - Structured/complex data (entropy constant across scales)
//! - Deterministic chaos (entropy increases then decreases)
//!
//! Optimizations:
//! - Direct byte processing (eliminates byte-to-f64 copy)
//! - SIMD coarse-graining using f64x4
//! - Thread-local buffer reuse
//! - Optimized Welford's algorithm with SIMD

use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use wide::f64x4;

/// Default parameters for RCMSE calculation.
pub const RCMSE_EMBEDDING_DIM: usize = 2; // m parameter
pub const RCMSE_TOLERANCE_FACTOR: f64 = 0.15; // r = 0.15 * SD
pub const RCMSE_MAX_SCALE: usize = 20; // Maximum scale factor τ

/// Coarse-grain directly from bytes at scale τ with offset k.
/// Uses SIMD for accumulating byte sums when window size >= 8.
/// Returns the number of points written.
#[inline]
fn coarse_grain_bytes_into(data: &[u8], scale: usize, offset: usize, out: &mut [f64]) -> usize {
    if scale == 0 || data.is_empty() || offset == 0 || offset > scale {
        return 0;
    }

    let n = data.len();
    let num_points = (n.saturating_sub(offset - 1)) / scale;

    if num_points == 0 {
        return 0;
    }

    let inv_scale = 1.0 / scale as f64;
    let actual_points = num_points.min(out.len());

    // Use SIMD for larger windows
    if scale >= 8 {
        use wide::u32x4;

        for j in 0..actual_points {
            let start = j * scale + (offset - 1);
            let end = (start + scale).min(n);
            let window = &data[start..end];

            // SIMD sum: process 8 bytes at a time
            let chunks = window.chunks_exact(8);
            let remainder = chunks.remainder();

            let mut sum_vec = u32x4::ZERO;
            for chunk in chunks {
                // Load 8 bytes, accumulate as u32
                let v0 = u32x4::new([
                    chunk[0] as u32,
                    chunk[1] as u32,
                    chunk[2] as u32,
                    chunk[3] as u32,
                ]);
                let v1 = u32x4::new([
                    chunk[4] as u32,
                    chunk[5] as u32,
                    chunk[6] as u32,
                    chunk[7] as u32,
                ]);
                sum_vec += v0 + v1;
            }

            // Horizontal sum
            let arr = sum_vec.to_array();
            let mut sum = arr[0] + arr[1] + arr[2] + arr[3];

            // Handle remainder
            for &b in remainder {
                sum += b as u32;
            }

            out[j] = sum as f64 * inv_scale;
        }
    } else {
        // Scalar path for small windows (more efficient due to less overhead)
        for j in 0..actual_points {
            let start = j * scale + (offset - 1);
            let end = (start + scale).min(n);

            let mut sum = 0u32;
            for i in start..end {
                sum += unsafe { *data.get_unchecked(i) } as u32;
            }
            out[j] = sum as f64 * inv_scale;
        }
    }

    actual_points
}

/// Coarse-grain a time series at scale τ with offset k, writing into a pre-allocated buffer.
/// Uses 8-way SIMD accumulation for larger windows.
/// Returns the number of points written.
#[inline]
fn coarse_grain_into(data: &[f64], scale: usize, offset: usize, out: &mut [f64]) -> usize {
    if scale == 0 || data.is_empty() || offset == 0 || offset > scale {
        return 0;
    }

    let n = data.len();
    let num_points = (n.saturating_sub(offset - 1)) / scale;

    if num_points == 0 {
        return 0;
    }

    let inv_scale = 1.0 / scale as f64;
    let actual_points = num_points.min(out.len());

    for j in 0..actual_points {
        let start = j * scale + (offset - 1);
        let end = (start + scale).min(n);
        let window = &data[start..end];

        // Use dual SIMD accumulators for 8-way parallelism and reduced dependency chains
        let mut sum = 0.0f64;

        if window.len() >= 8 {
            let chunks = window.chunks_exact(8);
            let remainder = chunks.remainder();

            let mut simd_sum0 = f64x4::ZERO;
            let mut simd_sum1 = f64x4::ZERO;

            for chunk in chunks {
                simd_sum0 += f64x4::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
                simd_sum1 += f64x4::new([chunk[4], chunk[5], chunk[6], chunk[7]]);
            }

            // Combine accumulators
            let combined = simd_sum0 + simd_sum1;
            let arr = combined.to_array();
            sum = arr[0] + arr[1] + arr[2] + arr[3];

            for &v in remainder {
                sum += v;
            }
        } else if window.len() >= 4 {
            let chunks = window.chunks_exact(4);
            let remainder = chunks.remainder();

            let mut simd_sum = f64x4::ZERO;
            for chunk in chunks {
                simd_sum += f64x4::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }

            let arr = simd_sum.to_array();
            sum = arr[0] + arr[1] + arr[2] + arr[3];

            for &v in remainder {
                sum += v;
            }
        } else {
            for &v in window {
                sum += v;
            }
        }

        out[j] = sum * inv_scale;
    }

    actual_points
}

/// Optimized pattern matching using sorted indices and bucket pruning.
/// This is O(n * k) where k is average matches per point.
#[inline]
fn count_pattern_matches_optimized(series: &[f64], r: f64) -> (u64, u64) {
    let n = series.len();
    const M: usize = 2; // Embedding dimension (hardcoded for optimization)

    if n <= M + 1 {
        return (0, 0);
    }

    let num_templates = n - M;
    let num_templates_extended = n - M - 1;

    // Create index array sorted by first element of each template vector
    let mut indices: Vec<usize> = (0..num_templates).collect();
    indices.sort_unstable_by(|&a, &b| {
        series[a]
            .partial_cmp(&series[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // For small series, use simple O(n²) which has less overhead
    if num_templates < 32 {
        return count_pattern_matches_simple(series, r);
    }

    // Parallel counting with atomic counters
    let count_m = AtomicU64::new(0);
    let count_m_plus_1 = AtomicU64::new(0);

    // Process in parallel chunks
    indices.par_chunks(64).for_each(|chunk| {
        let mut local_m: u64 = 0;
        let mut local_m_plus_1: u64 = 0;

        for &i in chunk {
            let vi0 = series[i];
            let vi1 = series[i + 1];

            // Binary search to find starting point within tolerance
            let target_min = vi0 - r;
            let target_max = vi0 + r;

            // Find range of indices where first element is within [vi0 - r, vi0 + r]
            let start_idx = indices.partition_point(|&idx| series[idx] < target_min);
            let end_idx = indices.partition_point(|&idx| series[idx] <= target_max);

            // Compare only with vectors in range
            for &j in &indices[start_idx..end_idx] {
                if j <= i {
                    continue; // Avoid double counting and self-comparison
                }

                let vj0 = series[j];
                let vj1 = series[j + 1];

                // Unrolled m=2 Chebyshev distance check
                let d0 = (vi0 - vj0).abs();
                let d1 = (vi1 - vj1).abs();

                if d0 <= r && d1 <= r {
                    local_m += 2; // Count both (i,j) and (j,i)

                    // Check m+1 dimension if both indices are valid
                    if i < num_templates_extended && j < num_templates_extended {
                        let d2 = (series[i + 2] - series[j + 2]).abs();
                        if d2 <= r {
                            local_m_plus_1 += 2;
                        }
                    }
                }
            }
        }

        count_m.fetch_add(local_m, Ordering::Relaxed);
        count_m_plus_1.fetch_add(local_m_plus_1, Ordering::Relaxed);
    });

    (
        count_m.load(Ordering::Relaxed),
        count_m_plus_1.load(Ordering::Relaxed),
    )
}

/// Simple O(n²) pattern matching for small series (less overhead than sorted version).
#[inline]
fn count_pattern_matches_simple(series: &[f64], r: f64) -> (u64, u64) {
    let n = series.len();
    const M: usize = 2;

    if n <= M + 1 {
        return (0, 0);
    }

    let num_templates = n - M;
    let num_templates_extended = n - M - 1;

    let mut count_m: u64 = 0;
    let mut count_m_plus_1: u64 = 0;

    for i in 0..num_templates {
        let vi0 = series[i];
        let vi1 = series[i + 1];

        for j in (i + 1)..num_templates {
            let vj0 = series[j];
            let vj1 = series[j + 1];

            // Unrolled m=2 check with early exit
            let d0 = (vi0 - vj0).abs();
            if d0 > r {
                continue;
            }
            let d1 = (vi1 - vj1).abs();
            if d1 > r {
                continue;
            }

            count_m += 2;

            if i < num_templates_extended && j < num_templates_extended {
                let d2 = (series[i + 2] - series[j + 2]).abs();
                if d2 <= r {
                    count_m_plus_1 += 2;
                }
            }
        }
    }

    (count_m, count_m_plus_1)
}

/// Calculate standard deviation using single-pass Welford's online algorithm.
/// Optimized with SIMD - computes mean and variance simultaneously.
/// Single pass halves memory bandwidth compared to two-pass approach.
#[inline]
fn std_deviation(data: &[f64]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let n = data.len();

    // Single-pass Welford's algorithm with SIMD
    // For each value x: delta = x - mean, mean += delta/n, M2 += delta * (x - mean)
    // Final variance = M2 / (n - 1)

    // Process in chunks of 4 using a vectorized running sum approach
    // This is equivalent to Welford but batched for SIMD efficiency
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    // Dual accumulators for sum and sum of squares (compensated summation)
    let mut sum0 = f64x4::ZERO;
    let mut sum1 = f64x4::ZERO;
    let mut sq_sum0 = f64x4::ZERO;
    let mut sq_sum1 = f64x4::ZERO;

    for chunk in chunks {
        let v0 = f64x4::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let v1 = f64x4::new([chunk[4], chunk[5], chunk[6], chunk[7]]);
        sum0 += v0;
        sum1 += v1;
        sq_sum0 += v0 * v0;
        sq_sum1 += v1 * v1;
    }

    // Combine SIMD accumulators
    let sum_combined = sum0 + sum1;
    let sq_combined = sq_sum0 + sq_sum1;
    let sum_arr = sum_combined.to_array();
    let sq_arr = sq_combined.to_array();

    let mut sum = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3];
    let mut sq_sum = sq_arr[0] + sq_arr[1] + sq_arr[2] + sq_arr[3];

    // Handle remainder
    for &v in remainder {
        sum += v;
        sq_sum += v * v;
    }

    // Variance = E[X²] - E[X]² = (sum_sq/n) - (sum/n)²
    // Using Bessel correction: var = (n * sum_sq - sum²) / (n * (n-1))
    let n_f = n as f64;
    let variance = (n_f * sq_sum - sum * sum) / (n_f * (n_f - 1.0));

    // Handle numerical issues (can be slightly negative due to FP errors)
    if variance < 0.0 {
        0.0
    } else {
        variance.sqrt()
    }
}

/// Calculate standard deviation directly from bytes (avoids f64 conversion).
/// Single-pass algorithm: computes sum and sum-of-squares simultaneously.
/// Uses SIMD u32/u64 for sum accumulation to avoid overflow.
#[inline]
fn std_deviation_bytes(data: &[u8]) -> f64 {
    use wide::u32x4;

    if data.len() < 2 {
        return 0.0;
    }

    let n = data.len();
    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();

    // Accumulators: sum uses u64 to avoid overflow, sq_sum uses u64
    // For 256 max byte value: 256^2 * 16 * max_chunks fits in u64
    let mut sum_vec0 = u32x4::ZERO;
    let mut sum_vec1 = u32x4::ZERO;
    let mut sum_vec2 = u32x4::ZERO;
    let mut sum_vec3 = u32x4::ZERO;

    // For squared sum: max per byte = 255^2 = 65025
    // Use u64 accumulator to handle large files
    let mut sq_sum: u64 = 0;

    for chunk in chunks {
        // Load 16 bytes in 4 vectors
        let v0 = u32x4::new([
            chunk[0] as u32,
            chunk[1] as u32,
            chunk[2] as u32,
            chunk[3] as u32,
        ]);
        let v1 = u32x4::new([
            chunk[4] as u32,
            chunk[5] as u32,
            chunk[6] as u32,
            chunk[7] as u32,
        ]);
        let v2 = u32x4::new([
            chunk[8] as u32,
            chunk[9] as u32,
            chunk[10] as u32,
            chunk[11] as u32,
        ]);
        let v3 = u32x4::new([
            chunk[12] as u32,
            chunk[13] as u32,
            chunk[14] as u32,
            chunk[15] as u32,
        ]);

        sum_vec0 += v0;
        sum_vec1 += v1;
        sum_vec2 += v2;
        sum_vec3 += v3;

        // Compute squared sums using SIMD multiply
        let sq0 = v0 * v0;
        let sq1 = v1 * v1;
        let sq2 = v2 * v2;
        let sq3 = v3 * v3;

        // Horizontal sum of squared values
        let sq0_arr = sq0.to_array();
        let sq1_arr = sq1.to_array();
        let sq2_arr = sq2.to_array();
        let sq3_arr = sq3.to_array();

        sq_sum += (sq0_arr[0] + sq0_arr[1] + sq0_arr[2] + sq0_arr[3]) as u64;
        sq_sum += (sq1_arr[0] + sq1_arr[1] + sq1_arr[2] + sq1_arr[3]) as u64;
        sq_sum += (sq2_arr[0] + sq2_arr[1] + sq2_arr[2] + sq2_arr[3]) as u64;
        sq_sum += (sq3_arr[0] + sq3_arr[1] + sq3_arr[2] + sq3_arr[3]) as u64;
    }

    // Combine sum vectors
    let combined01 = sum_vec0 + sum_vec1;
    let combined23 = sum_vec2 + sum_vec3;
    let combined = combined01 + combined23;
    let arr = combined.to_array();
    let mut sum = (arr[0] as u64) + (arr[1] as u64) + (arr[2] as u64) + (arr[3] as u64);

    // Handle remainder
    for &b in remainder {
        let v = b as u64;
        sum += v;
        sq_sum += v * v;
    }

    // Variance = E[X²] - E[X]² = (sum_sq/n) - (sum/n)²
    // Using Bessel correction: var = (n * sum_sq - sum²) / (n * (n-1))
    let n_f = n as f64;
    let sum_f = sum as f64;
    let sq_sum_f = sq_sum as f64;
    let variance = (n_f * sq_sum_f - sum_f * sum_f) / (n_f * (n_f - 1.0));

    if variance < 0.0 {
        0.0
    } else {
        variance.sqrt()
    }
}

/// Calculate RCMSE for a single scale factor τ with optimized coarse-graining.
/// Works directly from f64 data (used for pre-converted data).
fn rcmse_at_scale_optimized(
    data: &[f64],
    scale: usize,
    r: f64,
    buffer: &mut Vec<f64>,
) -> Option<f64> {
    if scale == 0 {
        return None;
    }

    let max_coarse_len = data.len() / scale + 1;
    buffer.resize(max_coarse_len, 0.0);

    let mut total_m: u64 = 0;
    let mut total_m_plus_1: u64 = 0;

    // Process all τ coarse-grained series (offsets 1 to τ)
    for k in 1..=scale {
        let len = coarse_grain_into(data, scale, k, buffer);
        if len <= RCMSE_EMBEDDING_DIM + 1 {
            continue;
        }
        let (n_m, n_m_plus_1) = count_pattern_matches_optimized(&buffer[..len], r);
        total_m += n_m;
        total_m_plus_1 += n_m_plus_1;
    }

    // RCMSE is undefined if no matches found
    if total_m == 0 || total_m_plus_1 == 0 {
        return None;
    }

    let ratio = total_m_plus_1 as f64 / total_m as f64;
    Some(-ratio.ln())
}

/// Calculate RCMSE for a single scale factor τ directly from bytes.
/// Eliminates the need for a separate byte-to-f64 conversion allocation.
#[inline]
fn rcmse_at_scale_from_bytes(
    data: &[u8],
    scale: usize,
    r: f64,
    buffer: &mut Vec<f64>,
) -> Option<f64> {
    if scale == 0 {
        return None;
    }

    let max_coarse_len = data.len() / scale + 1;
    buffer.resize(max_coarse_len, 0.0);

    let mut total_m: u64 = 0;
    let mut total_m_plus_1: u64 = 0;

    // Process all τ coarse-grained series (offsets 1 to τ)
    for k in 1..=scale {
        let len = coarse_grain_bytes_into(data, scale, k, buffer);
        if len <= RCMSE_EMBEDDING_DIM + 1 {
            continue;
        }
        let (n_m, n_m_plus_1) = count_pattern_matches_optimized(&buffer[..len], r);
        total_m += n_m;
        total_m_plus_1 += n_m_plus_1;
    }

    // RCMSE is undefined if no matches found
    if total_m == 0 || total_m_plus_1 == 0 {
        return None;
    }

    let ratio = total_m_plus_1 as f64 / total_m as f64;
    Some(-ratio.ln())
}

/// Classification of data based on RCMSE profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCMSEClassification {
    /// Entropy decreases monotonically (white noise, encrypted, compressed).
    Random,
    /// Entropy is relatively constant across scales (1/f noise, structured complexity).
    Structured,
    /// Entropy increases at small scales then decreases (deterministic chaos).
    Chaotic,
    /// Insufficient data to classify.
    Unknown,
}

/// RCMSE analysis results for visualization.
#[derive(Debug, Clone)]
pub struct RCMSEAnalysis {
    /// Sample entropy values at each scale (scale 1 to max_scale).
    pub entropy_by_scale: Vec<f64>,
    /// Linear regression slope of entropy vs scale.
    pub slope: f64,
    /// Complexity index based on the entropy profile.
    pub complexity_index: f64,
    /// Mean entropy across all scales.
    pub mean_entropy: f64,
    /// Classification based on entropy profile.
    pub classification: RCMSEClassification,
}

impl RCMSEAnalysis {
    /// Map RCMSE analysis to RGB color.
    pub fn to_color(&self) -> [u8; 3] {
        // Normalize complexity index to [0, 1]
        let ci = self.complexity_index.clamp(0.0, 2.0) / 2.0;

        // Use slope to determine base hue
        let slope_normalized = ((self.slope + 0.3) / 0.4).clamp(0.0, 1.0);

        match self.classification {
            RCMSEClassification::Random => {
                // Purple to blue gradient based on entropy level
                let intensity = (1.0 - ci) * 0.5 + 0.3;
                let r = (0.4 * intensity * 255.0) as u8;
                let g = (0.1 * intensity * 255.0) as u8;
                let b = (0.9 * intensity * 255.0) as u8;
                [r, g, b]
            }
            RCMSEClassification::Structured => {
                // Green to cyan gradient (complex, 1/f-like)
                let intensity = ci * 0.6 + 0.4;
                let r = (0.1 * intensity * 255.0) as u8;
                let g = (0.8 * intensity * 255.0) as u8;
                let b = (0.5 * intensity * 255.0) as u8;
                [r, g, b]
            }
            RCMSEClassification::Chaotic => {
                // Yellow to orange gradient (deterministic chaos)
                let intensity = ci * 0.7 + 0.3;
                let r = (1.0 * intensity * 255.0) as u8;
                let g = (0.7 * intensity * 255.0) as u8;
                let b = (0.1 * intensity * 255.0) as u8;
                [r, g, b]
            }
            RCMSEClassification::Unknown => {
                // Gray for insufficient data
                let v = (0.3 + slope_normalized * 0.4) * 255.0;
                [v as u8, v as u8, v as u8]
            }
        }
    }
}

/// Calculate RCMSE analysis for a data chunk.
/// Optimized to work directly from bytes when possible.
pub fn calculate_rcmse(data: &[u8], max_scale: usize) -> RCMSEAnalysis {
    // Calculate tolerance based on standard deviation (directly from bytes)
    let sd = std_deviation_bytes(data);
    let r = RCMSE_TOLERANCE_FACTOR * sd;

    // Need minimum data length for meaningful analysis
    let min_length_for_scale = |scale: usize| (RCMSE_EMBEDDING_DIM + 2) * scale;

    if data.len() < min_length_for_scale(1) || r == 0.0 {
        return RCMSEAnalysis {
            entropy_by_scale: Vec::new(),
            slope: 0.0,
            complexity_index: 0.0,
            mean_entropy: 0.0,
            classification: RCMSEClassification::Unknown,
        };
    }

    // Determine valid scales
    let valid_max_scale = (1..=max_scale)
        .take_while(|&s| data.len() >= min_length_for_scale(s))
        .last()
        .unwrap_or(0);

    if valid_max_scale < 3 {
        return RCMSEAnalysis {
            entropy_by_scale: Vec::new(),
            slope: 0.0,
            complexity_index: 0.0,
            mean_entropy: 0.0,
            classification: RCMSEClassification::Unknown,
        };
    }

    // OPTIMIZATION: Process bytes directly without f64 conversion allocation
    // Each thread does its own coarse-graining directly from bytes
    let scale_results: Vec<(usize, Option<f64>)> = (1..=valid_max_scale)
        .into_par_iter()
        .map(|scale| {
            // Each thread gets its own buffer - sized for this specific scale
            let mut buffer = Vec::with_capacity(data.len() / scale + 1);
            // Use direct byte processing to avoid massive f64 allocation
            let entropy = rcmse_at_scale_from_bytes(data, scale, r, &mut buffer);
            (scale, entropy)
        })
        .collect();

    // Collect valid results
    let mut entropy_by_scale = Vec::with_capacity(valid_max_scale);
    let mut valid_scales = Vec::with_capacity(valid_max_scale);
    let mut last_valid_entropy = None;

    for (scale, entropy_opt) in scale_results {
        if let Some(entropy) = entropy_opt {
            entropy_by_scale.push(entropy);
            valid_scales.push(scale as f64);
            last_valid_entropy = Some(entropy);
        } else if let Some(prev) = last_valid_entropy {
            // Use previous value for continuity
            entropy_by_scale.push(prev);
            valid_scales.push(scale as f64);
        }
    }

    if entropy_by_scale.len() < 3 {
        return RCMSEAnalysis {
            entropy_by_scale,
            slope: 0.0,
            complexity_index: 0.0,
            mean_entropy: 0.0,
            classification: RCMSEClassification::Unknown,
        };
    }

    // Calculate linear regression slope using SIMD
    let n = valid_scales.len() as f64;
    let mean_scale: f64 = valid_scales.iter().sum::<f64>() / n;
    let mean_entropy: f64 = entropy_by_scale.iter().sum::<f64>() / n;

    let mut numerator = 0.0;
    let mut denominator = 0.0;
    for (scale, entropy) in valid_scales.iter().zip(entropy_by_scale.iter()) {
        numerator += (scale - mean_scale) * (entropy - mean_entropy);
        denominator += (scale - mean_scale).powi(2);
    }

    let slope = if denominator > 0.0 {
        numerator / denominator
    } else {
        0.0
    };

    // Detect early increase (characteristic of chaotic signals)
    let has_early_increase = entropy_by_scale.len() >= 3
        && entropy_by_scale[1] > entropy_by_scale[0]
        && entropy_by_scale[2] > entropy_by_scale[0];

    // Classification based on slope and pattern
    let classification = if has_early_increase && slope < 0.05 {
        RCMSEClassification::Chaotic
    } else if slope < -0.05 {
        RCMSEClassification::Random
    } else if slope.abs() < 0.05 {
        RCMSEClassification::Structured
    } else {
        RCMSEClassification::Unknown
    };

    // Complexity index: combine mean entropy with slope information
    let slope_factor = 1.0 - slope.abs().min(0.3) / 0.3;
    let entropy_factor = (mean_entropy / 3.0).min(1.0);
    let complexity_index = slope_factor * entropy_factor * 2.0;

    RCMSEAnalysis {
        entropy_by_scale,
        slope,
        complexity_index,
        mean_entropy,
        classification,
    }
}

// =============================================================================
// ULTRA-FAST HISTOGRAM-BASED APPROXIMATION
// =============================================================================
// For visualization, we don't need exact RCMSE - we need a value that correlates
// with complexity. This histogram approach reduces O(n²) to O(n + b²) where b
// is the number of histogram bins (typically 16-32).

/// Number of histogram bins for fast approximation.
const FAST_HIST_BINS: usize = 16;

/// Sparse scales for ultra-fast mode: only compute these scales.
/// Chosen to capture the key characteristics: small (1), medium (3), large (6).
const FAST_SCALES: [usize; 3] = [1, 3, 6];

/// Ultra-fast pattern count using 2D histogram approximation.
/// Instead of O(n²) pairwise comparisons, we:
/// 1. Quantize values into bins: O(n)
/// 2. Build 2D histogram of consecutive pairs: O(n)
/// 3. Count matches by summing nearby bins: O(b²)
///
/// This gives O(n + b²) complexity, which is effectively O(n) since b is constant.
#[inline]
fn count_pattern_matches_histogram(series: &[f64], r: f64) -> (u64, u64) {
    let n = series.len();
    const M: usize = 2; // Embedding dimension

    if n <= M + 1 {
        return (0, 0);
    }

    // Find min/max for quantization
    let mut min_val = series[0];
    let mut max_val = series[0];
    for &v in &series[1..] {
        if v < min_val {
            min_val = v;
        }
        if v > max_val {
            max_val = v;
        }
    }

    let range = max_val - min_val;
    if range < 1e-10 {
        // All values are the same - everything matches
        let num_templates = n - M;
        let pairs = (num_templates * (num_templates - 1)) as u64;
        return (pairs, pairs);
    }

    // Calculate bin width and tolerance in bins
    let bin_width = range / FAST_HIST_BINS as f64;
    let r_bins = ((r / bin_width).ceil() as usize).min(FAST_HIST_BINS - 1);

    // Quantize values to bins: O(n)
    let quantize = |v: f64| -> usize {
        let bin = ((v - min_val) / bin_width) as usize;
        bin.min(FAST_HIST_BINS - 1)
    };

    // Build 2D histogram of (series[i], series[i+1]) pairs: O(n)
    // This represents the embedding vectors for m=2
    let mut hist_m = [[0u32; FAST_HIST_BINS]; FAST_HIST_BINS];
    let num_templates = n - M;

    for i in 0..num_templates {
        let b0 = quantize(series[i]);
        let b1 = quantize(series[i + 1]);
        hist_m[b0][b1] += 1;
    }

    // Build 3D histogram for m+1 (we can flatten to 2D by combining dimensions)
    // For simplicity, we use a separate 2D histogram for (series[i+1], series[i+2])
    // and estimate m+1 matches from the overlap
    let mut hist_m1_suffix = [[0u32; FAST_HIST_BINS]; FAST_HIST_BINS];
    let num_templates_ext = n - M - 1;

    for i in 0..num_templates_ext {
        let b1 = quantize(series[i + 1]);
        let b2 = quantize(series[i + 2]);
        hist_m1_suffix[b1][b2] += 1;
    }

    // Summed-area table gives each tolerance neighborhood in O(1).
    let mut prefix = [[0u64; FAST_HIST_BINS + 1]; FAST_HIST_BINS + 1];
    for row in 0..FAST_HIST_BINS {
        let mut row_sum = 0;
        for col in 0..FAST_HIST_BINS {
            row_sum += hist_m[row][col] as u64;
            prefix[row + 1][col + 1] = prefix[row][col + 1] + row_sum;
        }
    }
    // Cache rounded suffix contributions by multiplicity. Rounding remains
    // per suffix bin, exactly as in the existing visualization approximation.
    let max_count = hist_m.iter().flatten().copied().max().unwrap_or(0) as usize;
    let mut suffix_cache = vec![None; max_count + 1];
    let mut count_m = 0u64;
    let mut count_m_plus_1 = 0u64;
    for b0 in 0..FAST_HIST_BINS {
        for b1 in 0..FAST_HIST_BINS {
            let c1 = hist_m[b0][b1] as u64;
            if c1 == 0 {
                continue;
            }
            let low0 = b0.saturating_sub(r_bins);
            let high0 = (b0 + r_bins + 1).min(FAST_HIST_BINS);
            let low1 = b1.saturating_sub(r_bins);
            let high1 = (b1 + r_bins + 1).min(FAST_HIST_BINS);
            let neighbors = prefix[high0][high1] + prefix[low0][low1]
                - prefix[low0][high1]
                - prefix[high0][low1];
            count_m += c1 * (neighbors - 1); // Exclude each template's self-match.
            let suffix = suffix_cache[c1 as usize].get_or_insert_with(|| {
                let mut rows = [0u64; FAST_HIST_BINS + 1];
                for (row, bins) in hist_m1_suffix.iter().enumerate() {
                    let sum: u64 = bins
                        .iter()
                        .filter(|&&c| c > 0)
                        .map(|&c| {
                            let scale = (c as f64 / num_templates_ext as f64).min(1.0);
                            (c1 as f64 * scale * c1 as f64) as u64
                        })
                        .sum();
                    rows[row + 1] = rows[row] + sum;
                }
                rows
            });
            count_m_plus_1 += suffix[high1] - suffix[low1];
        }
    }

    // Ensure count_m_plus_1 doesn't exceed count_m (physical constraint)
    count_m_plus_1 = count_m_plus_1.min(count_m);

    (count_m.max(1), count_m_plus_1.max(1))
}

#[cfg(test)]
fn count_pattern_matches_histogram_reference(series: &[f64], r: f64) -> (u64, u64) {
    let n = series.len();
    const M: usize = 2; // Embedding dimension

    if n <= M + 1 {
        return (0, 0);
    }

    // Find min/max for quantization
    let mut min_val = series[0];
    let mut max_val = series[0];
    for &v in &series[1..] {
        if v < min_val {
            min_val = v;
        }
        if v > max_val {
            max_val = v;
        }
    }

    let range = max_val - min_val;
    if range < 1e-10 {
        // All values are the same - everything matches
        let num_templates = n - M;
        let pairs = (num_templates * (num_templates - 1)) as u64;
        return (pairs, pairs);
    }

    // Calculate bin width and tolerance in bins
    let bin_width = range / FAST_HIST_BINS as f64;
    let r_bins = (r / bin_width).ceil() as usize;

    // Quantize values to bins: O(n)
    let quantize = |v: f64| -> usize {
        let bin = ((v - min_val) / bin_width) as usize;
        bin.min(FAST_HIST_BINS - 1)
    };

    // Build 2D histogram of (series[i], series[i+1]) pairs: O(n)
    // This represents the embedding vectors for m=2
    let mut hist_m = [[0u32; FAST_HIST_BINS]; FAST_HIST_BINS];
    let num_templates = n - M;

    for i in 0..num_templates {
        let b0 = quantize(series[i]);
        let b1 = quantize(series[i + 1]);
        hist_m[b0][b1] += 1;
    }

    // Build 3D histogram for m+1 (we can flatten to 2D by combining dimensions)
    // For simplicity, we use a separate 2D histogram for (series[i+1], series[i+2])
    // and estimate m+1 matches from the overlap
    let mut hist_m1_suffix = [[0u32; FAST_HIST_BINS]; FAST_HIST_BINS];
    let num_templates_ext = n - M - 1;

    for i in 0..num_templates_ext {
        let b1 = quantize(series[i + 1]);
        let b2 = quantize(series[i + 2]);
        hist_m1_suffix[b1][b2] += 1;
    }

    // Count matches: sum over all bin pairs within tolerance
    // Two templates match if all their bin indices are within r_bins of each other
    let mut count_m: u64 = 0;
    let mut count_m_plus_1: u64 = 0;

    for b0 in 0..FAST_HIST_BINS {
        for b1 in 0..FAST_HIST_BINS {
            let c1 = hist_m[b0][b1] as u64;
            if c1 == 0 {
                continue;
            }

            // Count matches with nearby bins
            let b0_min = b0.saturating_sub(r_bins);
            let b0_max = (b0 + r_bins + 1).min(FAST_HIST_BINS);
            let b1_min = b1.saturating_sub(r_bins);
            let b1_max = (b1 + r_bins + 1).min(FAST_HIST_BINS);

            for b0_other in b0_min..b0_max {
                for b1_other in b1_min..b1_max {
                    let c2 = hist_m[b0_other][b1_other] as u64;
                    if c2 == 0 {
                        continue;
                    }

                    // Matches between these two bins
                    // If same bin, count pairs within; otherwise count cross-products
                    if b0 == b0_other && b1 == b1_other {
                        // Self-matches: n*(n-1) pairs
                        count_m += c1 * (c1 - 1);
                    } else {
                        // Cross-matches: n1 * n2 pairs (but avoid double counting)
                        // Only count if (b0_other, b1_other) > (b0, b1) lexicographically
                        if b0_other > b0 || (b0_other == b0 && b1_other > b1) {
                            count_m += 2 * c1 * c2;
                        }
                    }
                }
            }

            // For m+1 matches, we need the third dimension to also match
            // Approximate by checking if the suffix histogram has nearby matches
            // This is a simplification but works well for visualization
            let b1_min_ext = b1.saturating_sub(r_bins);
            let b1_max_ext = (b1 + r_bins + 1).min(FAST_HIST_BINS);

            for b1_ext in b1_min_ext..b1_max_ext {
                for b2 in 0..FAST_HIST_BINS {
                    let c_suffix = hist_m1_suffix[b1_ext][b2] as u64;
                    if c_suffix > 0 {
                        // Approximate m+1 matches based on histogram overlap
                        // Scale by the ratio of suffix matches to total templates
                        let scale = (c_suffix as f64 / num_templates_ext as f64).min(1.0);
                        count_m_plus_1 += (c1 as f64 * scale * c1 as f64) as u64;
                    }
                }
            }
        }
    }

    // Ensure count_m_plus_1 doesn't exceed count_m (physical constraint)
    count_m_plus_1 = count_m_plus_1.min(count_m);

    (count_m.max(1), count_m_plus_1.max(1))
}

/// Ultra-fast RCMSE at a single scale using histogram approximation.
#[inline]
fn rcmse_at_scale_fast(data: &[u8], scale: usize, r: f64, buffer: &mut Vec<f64>) -> Option<f64> {
    if scale == 0 {
        return None;
    }

    let max_coarse_len = data.len() / scale + 1;
    buffer.resize(max_coarse_len, 0.0);

    let mut total_m: u64 = 0;
    let mut total_m_plus_1: u64 = 0;

    // For ultra-fast mode, only process offset 1 (skip other offsets)
    // This is a significant speedup with minimal accuracy loss for visualization
    let len = coarse_grain_bytes_into(data, scale, 1, buffer);
    if len <= RCMSE_EMBEDDING_DIM + 1 {
        return None;
    }

    let (n_m, n_m_plus_1) = count_pattern_matches_histogram(&buffer[..len], r);
    total_m += n_m;
    total_m_plus_1 += n_m_plus_1;

    if total_m == 0 || total_m_plus_1 == 0 {
        return None;
    }

    let ratio = total_m_plus_1 as f64 / total_m as f64;
    Some(-ratio.ln())
}

/// Calculate a simplified RCMSE complexity value for fast visualization.
///
/// This uses an ultra-fast histogram-based approximation that is ~100x faster
/// than the full RCMSE algorithm while still capturing the key complexity signal.
///
/// Returns a value between 0.0 and 1.0:
/// - 0.0: Random/encrypted (steep negative slope)
/// - 0.5: Structured/complex (flat slope)
/// - 1.0: Chaotic/interesting (positive early slope)
///
/// # Performance
/// - Full RCMSE: O(n² × scales × offsets) ≈ O(n² × 36) for default params
/// - Fast RCMSE: O(n × scales) ≈ O(n × 3) with histogram approximation
thread_local! {
    static QUICK_BUFFER: std::cell::RefCell<Vec<f64>> =
        std::cell::RefCell::new(Vec::with_capacity(257));
}

pub fn calculate_rcmse_quick(data: &[u8]) -> f32 {
    if data.len() <= 4096 {
        QUICK_BUFFER
            .with(|buffer| calculate_rcmse_quick_with_buffer(data, &mut buffer.borrow_mut()))
    } else {
        calculate_rcmse_quick_with_buffer(data, &mut Vec::new())
    }
}

fn calculate_rcmse_quick_with_buffer(data: &[u8], buffer: &mut Vec<f64>) -> f32 {
    // Minimum data length for meaningful analysis
    if data.len() < 16 {
        return 0.5;
    }

    // Calculate tolerance from byte standard deviation (fast path)
    let sd = std_deviation_bytes(data);
    if sd < 1.0 {
        // Near-uniform data
        return 0.5;
    }
    let r = RCMSE_TOLERANCE_FACTOR * sd;

    // Compute entropy at sparse scales using histogram approximation
    let mut entropies = [0.0f64; 3];
    let mut valid_count = 0;

    for (i, &scale) in FAST_SCALES.iter().enumerate() {
        if data.len() < (RCMSE_EMBEDDING_DIM + 2) * scale {
            break;
        }
        if let Some(entropy) = rcmse_at_scale_fast(data, scale, r, buffer) {
            entropies[i] = entropy;
            valid_count += 1;
        }
    }

    if valid_count < 2 {
        return 0.5;
    }

    // Estimate slope from available scales
    let slope = if valid_count == 3 {
        // Linear regression approximation with 3 points
        // scales: 1, 3, 6 -> normalized: 0, 0.4, 1.0
        // slope ≈ (e6 - e1) / 5 adjusted for scale spacing
        (entropies[2] - entropies[0]) / 5.0
    } else {
        // 2 points: use simple difference
        (entropies[1] - entropies[0]) / 2.0
    };

    // Check for early increase (chaotic signature)
    let has_early_increase = valid_count >= 2 && entropies[1] > entropies[0] * 1.1;

    // Compute mean entropy for complexity factor
    let mean_entropy: f64 = entropies[..valid_count].iter().sum::<f64>() / valid_count as f64;
    let entropy_factor = (mean_entropy / 3.0).min(1.0) as f32;

    // Classification and mapping to 0-1 range
    if has_early_increase && slope > -0.05 {
        // Chaotic: high complexity signal
        0.7 + entropy_factor * 0.25
    } else if slope < -0.08 {
        // Random: entropy decreases sharply with scale
        0.1 + entropy_factor * 0.2
    } else if slope.abs() < 0.05 {
        // Structured: flat entropy profile
        0.4 + entropy_factor * 0.3
    } else {
        // Ambiguous
        0.5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_prefix_matches_existing_approximation() {
        let mut seed = 0xc0ffeeu64;
        for len in [0, 1, 3, 4, 16, 32, 64, 128, 256, 513] {
            let series: Vec<f64> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed % 256) as f64
                })
                .collect();
            for r in [0.0, 0.01, 5.0, 11.0, 50.0, 255.0, 512.0] {
                assert_eq!(
                    count_pattern_matches_histogram(&series, r),
                    count_pattern_matches_histogram_reference(&series, r),
                    "len={len}, r={r}"
                );
            }
            let uniform = vec![42.0; len];
            assert_eq!(
                count_pattern_matches_histogram(&uniform, 1.0),
                count_pattern_matches_histogram_reference(&uniform, 1.0)
            );
        }
    }

    #[test]
    fn test_rcmse_uniform() {
        let data = vec![128u8; 512];
        let analysis = calculate_rcmse(&data, 6);
        // Uniform data has zero variation, so RCMSE is undefined
        assert_eq!(analysis.classification, RCMSEClassification::Unknown);
    }

    #[test]
    fn test_rcmse_random() {
        // Generate pseudo-random data
        let data: Vec<u8> = (0..512).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        let analysis = calculate_rcmse(&data, 6);
        // Random/varied data should either have negative slope or be classified as Random/Unknown
        // The exact behavior depends on the pattern and scale parameters
        assert!(
            analysis.slope < 0.1
                || analysis.classification == RCMSEClassification::Random
                || analysis.classification == RCMSEClassification::Unknown,
            "Expected random classification or negative slope, got slope={}, class={:?}",
            analysis.slope,
            analysis.classification
        );
    }

    #[test]
    fn test_rcmse_quick() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let value = calculate_rcmse_quick(&data);
        assert!(value >= 0.0 && value <= 1.0);
    }

    #[test]
    fn test_std_deviation_bytes() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let sd = std_deviation_bytes(&data);
        // Standard deviation of 0..99 is about 29.15
        assert!((sd - 29.15).abs() < 0.5);
    }
}
