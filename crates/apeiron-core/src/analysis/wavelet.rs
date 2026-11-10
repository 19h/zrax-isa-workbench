//! Haar wavelet transform and entropy analysis.
//!
//! Based on: "Wavelet Decomposition of Software Entropy Reveals Symptoms of Malicious Code"
//! Wojnowicz et al., Journal of Innovation in Digital Ecosystems (2016)
//!
//! Key insight: Malware concentrates entropic energy at COARSE levels (large entropy shifts
//! from encrypted/compressed sections), while clean files concentrate energy at FINE levels.
//!
//! Optimizations:
//! - SIMD Haar transform using wide crate (f64x4)
//! - In-place transform to avoid allocations
//! - Deduplication: uses entropy module's chunk_entropy_fast
//! - Unrolled operations for small fixed-size inputs

use super::entropy::chunk_entropy_fast;
use wide::f64x4;

/// Window size for computing entropy stream (256 bytes as per paper).
pub const WAVELET_CHUNK_SIZE: usize = 256;

/// Orthonormal Haar scaling factor: 1/sqrt(2)
const INV_SQRT2: f64 = std::f64::consts::FRAC_1_SQRT_2;

/// SIMD version of INV_SQRT2
const INV_SQRT2_X4: f64x4 = f64x4::new([INV_SQRT2, INV_SQRT2, INV_SQRT2, INV_SQRT2]);

/// Compute Shannon entropy for a single chunk.
/// Delegates to optimized entropy module.
#[inline]
pub fn chunk_entropy(chunk: &[u8]) -> f64 {
    if chunk.is_empty() {
        return 0.0;
    }
    chunk_entropy_fast(chunk)
}

/// Compute the entropy stream from raw file data.
/// Each element is the Shannon entropy of a 256-byte chunk.
pub fn compute_entropy_stream(data: &[u8]) -> Vec<f64> {
    if data.is_empty() {
        return Vec::new();
    }

    let num_chunks = (data.len() + WAVELET_CHUNK_SIZE - 1) / WAVELET_CHUNK_SIZE;
    let mut stream = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let start = i * WAVELET_CHUNK_SIZE;
        let end = (start + WAVELET_CHUNK_SIZE).min(data.len());
        stream.push(chunk_entropy(&data[start..end]));
    }

    stream
}

/// Compute entropy stream in parallel using rayon (for large files).
pub fn compute_entropy_stream_parallel(data: &[u8]) -> Vec<f64> {
    use rayon::prelude::*;

    if data.is_empty() {
        return Vec::new();
    }

    let num_chunks = (data.len() + WAVELET_CHUNK_SIZE - 1) / WAVELET_CHUNK_SIZE;

    (0..num_chunks)
        .into_par_iter()
        .map(|i| {
            let start = i * WAVELET_CHUNK_SIZE;
            let end = (start + WAVELET_CHUNK_SIZE).min(data.len());
            chunk_entropy(&data[start..end])
        })
        .collect()
}

/// Perform Haar wavelet transform using SIMD acceleration.
/// Returns wavelet coefficients organized by level: Vec<Vec<f64>>
/// Level 0 is coarsest (1 coefficient), level J-1 is finest (2^(J-1) coefficients)
/// where J = floor(log2(signal.len()))
///
/// Uses orthonormal Haar wavelet (multiply by 1/sqrt(2)) to match the paper's
/// energy distribution.
pub fn haar_wavelet_transform(signal: &[f64]) -> Vec<Vec<f64>> {
    if signal.is_empty() {
        return Vec::new();
    }

    // Truncate to power of 2
    let j = (signal.len() as f64).log2().floor() as usize;
    if j == 0 {
        return Vec::new();
    }

    let n = 1 << j; // 2^j

    // Copy input data - we'll transform in place
    let mut data: Vec<f64> = signal[..n].to_vec();

    // Store coefficients by level
    let mut coefficients: Vec<Vec<f64>> = Vec::with_capacity(j);

    // Iteratively compute wavelet coefficients from fine to coarse
    let mut current_len = n;

    while current_len > 1 {
        let half = current_len / 2;

        // Use SIMD for the transform when we have enough elements
        if half >= 4 {
            haar_step_simd(&mut data, current_len, half);
        } else {
            haar_step_scalar(&mut data, current_len, half);
        }

        // Extract detail coefficients (second half after transform)
        let details: Vec<f64> = data[half..current_len].to_vec();
        coefficients.push(details);

        current_len = half;
    }

    // Reverse so level 0 is coarsest (1 coefficient), level J-1 is finest
    coefficients.reverse();
    coefficients
}

/// SIMD-accelerated Haar wavelet step with minimal copying.
/// Uses stack-allocated temp buffer for small sizes, thread-local for large.
/// Processes 4 pairs at a time using f64x4.
#[inline]
fn haar_step_simd(data: &mut [f64], len: usize, half: usize) {
    // For small inputs, use stack-allocated buffer (no heap allocation)
    if len <= 64 {
        haar_step_simd_small(data, len, half);
        return;
    }

    // For larger inputs, process in-place using a two-phase approach:
    // Phase 1: Compute details (can be done in-place in reverse order)
    // Phase 2: Compute averages (overwrites original data)

    // We need to copy the input first because both averages and details read from original
    // Use thread-local buffer sized appropriately
    thread_local! {
        static HAAR_SCRATCH: std::cell::UnsafeCell<Vec<f64>> = const { std::cell::UnsafeCell::new(Vec::new()) };
    }

    HAAR_SCRATCH.with(|scratch| {
        let scratch = unsafe { &mut *scratch.get() };

        // Resize if needed (only allocates once per thread for max size seen)
        if scratch.len() < len {
            scratch.resize(len, 0.0);
        }

        // Copy input data (required because we read pairs that overlap with output)
        scratch[..len].copy_from_slice(&data[..len]);

        // Process 4 pairs at a time with SIMD
        let simd_pairs = half / 4;
        let scalar_start = simd_pairs * 4;

        // SIMD processing - load from scratch, write to data
        for i in 0..simd_pairs {
            let base = i * 4;
            let idx0 = 2 * base;

            // Load 4 consecutive pairs using gather-like pattern
            let left = f64x4::new([
                scratch[idx0],
                scratch[idx0 + 2],
                scratch[idx0 + 4],
                scratch[idx0 + 6],
            ]);
            let right = f64x4::new([
                scratch[idx0 + 1],
                scratch[idx0 + 3],
                scratch[idx0 + 5],
                scratch[idx0 + 7],
            ]);

            // SIMD Haar transform
            let averages = (left + right) * INV_SQRT2_X4;
            let details = (left - right) * INV_SQRT2_X4;

            let avg_arr = averages.to_array();
            let det_arr = details.to_array();

            // Write results - averages go to first half, details to second half
            unsafe {
                *data.get_unchecked_mut(base) = avg_arr[0];
                *data.get_unchecked_mut(base + 1) = avg_arr[1];
                *data.get_unchecked_mut(base + 2) = avg_arr[2];
                *data.get_unchecked_mut(base + 3) = avg_arr[3];

                *data.get_unchecked_mut(half + base) = det_arr[0];
                *data.get_unchecked_mut(half + base + 1) = det_arr[1];
                *data.get_unchecked_mut(half + base + 2) = det_arr[2];
                *data.get_unchecked_mut(half + base + 3) = det_arr[3];
            }
        }

        // Handle remaining pairs with scalar code
        for i in scalar_start..half {
            let left = scratch[2 * i];
            let right = scratch[2 * i + 1];
            data[i] = (left + right) * INV_SQRT2;
            data[half + i] = (left - right) * INV_SQRT2;
        }
    });
}

/// Stack-allocated Haar step for small inputs (no heap allocation).
#[inline]
fn haar_step_simd_small(data: &mut [f64], len: usize, half: usize) {
    // Stack buffer for small inputs (64 f64s = 512 bytes)
    let mut temp = [0.0f64; 64];
    temp[..len].copy_from_slice(&data[..len]);

    let simd_pairs = half / 4;
    let scalar_start = simd_pairs * 4;

    for i in 0..simd_pairs {
        let base = i * 4;
        let idx0 = 2 * base;

        let left = f64x4::new([temp[idx0], temp[idx0 + 2], temp[idx0 + 4], temp[idx0 + 6]]);
        let right = f64x4::new([
            temp[idx0 + 1],
            temp[idx0 + 3],
            temp[idx0 + 5],
            temp[idx0 + 7],
        ]);

        let averages = (left + right) * INV_SQRT2_X4;
        let details = (left - right) * INV_SQRT2_X4;

        let avg_arr = averages.to_array();
        let det_arr = details.to_array();

        data[base] = avg_arr[0];
        data[base + 1] = avg_arr[1];
        data[base + 2] = avg_arr[2];
        data[base + 3] = avg_arr[3];
        data[half + base] = det_arr[0];
        data[half + base + 1] = det_arr[1];
        data[half + base + 2] = det_arr[2];
        data[half + base + 3] = det_arr[3];
    }

    for i in scalar_start..half {
        let left = temp[2 * i];
        let right = temp[2 * i + 1];
        data[i] = (left + right) * INV_SQRT2;
        data[half + i] = (left - right) * INV_SQRT2;
    }
}

/// Small fixed buffer for scalar Haar steps (max 8 averages).
/// For larger inputs, we use the SIMD path anyway.
#[inline]
fn haar_step_scalar(data: &mut [f64], _len: usize, half: usize) {
    // Stack-allocated buffer for small sizes (avoids heap allocation)
    // half < 4 means we have at most 3 averages to store
    debug_assert!(
        half < 4,
        "haar_step_scalar should only be called for half < 4"
    );

    let mut temp_avg = [0.0f64; 4];

    for i in 0..half {
        let left = data[2 * i];
        let right = data[2 * i + 1];
        temp_avg[i] = (left + right) * INV_SQRT2;
        data[half + i] = (left - right) * INV_SQRT2;
    }

    // Copy averages back
    for i in 0..half {
        data[i] = temp_avg[i];
    }
}

/// Perform in-place Haar wavelet transform (avoids all allocations except output).
/// Returns wavelet coefficients flattened with level boundaries.
pub fn haar_wavelet_transform_inplace(signal: &mut [f64]) -> Vec<usize> {
    let n = signal.len();
    if n < 2 || !n.is_power_of_two() {
        return Vec::new();
    }

    let j = n.trailing_zeros() as usize;
    let mut level_boundaries = Vec::with_capacity(j + 1);
    level_boundaries.push(0);

    let mut current_len = n;

    while current_len > 1 {
        let half = current_len / 2;

        if half >= 4 {
            haar_step_simd(signal, current_len, half);
        } else {
            haar_step_scalar(signal, current_len, half);
        }

        level_boundaries.push(half);
        current_len = half;
    }

    level_boundaries
}

/// Compute energy spectrum from wavelet coefficients.
/// Energy at level j = sum of squared coefficients at that level.
/// Returns Vec<f64> where index 0 is coarsest level energy.
/// Optimized with 8-way SIMD and dual accumulators for better ILP.
pub fn wavelet_energy_spectrum(coefficients: &[Vec<f64>]) -> Vec<f64> {
    coefficients
        .iter()
        .map(|level| {
            // 8-way SIMD with dual accumulators for maximum ILP
            let chunks = level.chunks_exact(8);
            let remainder = chunks.remainder();

            let mut acc0 = f64x4::ZERO;
            let mut acc1 = f64x4::ZERO;

            for chunk in chunks {
                let v0 = f64x4::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let v1 = f64x4::new([chunk[4], chunk[5], chunk[6], chunk[7]]);
                acc0 += v0 * v0;
                acc1 += v1 * v1;
            }

            // Combine accumulators
            let combined = acc0 + acc1;
            let arr = combined.to_array();
            let mut energy = arr[0] + arr[1] + arr[2] + arr[3];

            // Handle remainder with 4-way SIMD if possible
            if remainder.len() >= 4 {
                let v = f64x4::new([remainder[0], remainder[1], remainder[2], remainder[3]]);
                let squared = v * v;
                let sq_arr = squared.to_array();
                energy += sq_arr[0] + sq_arr[1] + sq_arr[2] + sq_arr[3];
                for &d in &remainder[4..] {
                    energy += d * d;
                }
            } else {
                for &d in remainder {
                    energy += d * d;
                }
            }

            energy
        })
        .collect()
}

/// Wavelet entropy analysis results for visualization and classification.
#[derive(Debug, Clone)]
pub struct WaveletAnalysis {
    /// Energy at each resolution level (index 0 = coarsest)
    pub energy_spectrum: Vec<f64>,
    /// Total energy in the signal
    pub total_energy: f64,
    /// Ratio of energy at coarse levels (first half) to total energy
    pub coarse_energy_ratio: f64,
    /// Suspiciousness score (0.0 = normal, 1.0 = highly suspicious)
    pub suspiciousness: f64,
    /// Number of resolution levels
    pub num_levels: usize,
}

impl WaveletAnalysis {
    /// Analyze wavelet decomposition of an entropy signal.
    pub fn from_entropy_stream(stream: &[f64]) -> Self {
        let coefficients = haar_wavelet_transform(stream);

        if coefficients.is_empty() {
            return Self {
                energy_spectrum: Vec::new(),
                total_energy: 0.0,
                coarse_energy_ratio: 0.5,
                suspiciousness: 0.5,
                num_levels: 0,
            };
        }

        let energy_spectrum = wavelet_energy_spectrum(&coefficients);
        let num_levels = energy_spectrum.len();
        let total_energy: f64 = energy_spectrum.iter().sum();

        if total_energy == 0.0 || num_levels < 2 {
            return Self {
                energy_spectrum,
                total_energy,
                coarse_energy_ratio: 0.5,
                suspiciousness: 0.5,
                num_levels,
            };
        }

        // Calculate coarse energy ratio (first half of levels)
        let coarse_levels = (num_levels + 1) / 2;
        let coarse_energy: f64 = energy_spectrum[..coarse_levels].iter().sum();
        let coarse_energy_ratio = coarse_energy / total_energy;

        // Calculate suspiciousness score
        let mean_energy = total_energy / num_levels as f64;
        let energy_variance: f64 = energy_spectrum
            .iter()
            .map(|e| (e - mean_energy).powi(2))
            .sum::<f64>()
            / num_levels as f64;
        let energy_std = energy_variance.sqrt();

        // Normalize coarse ratio to suspiciousness
        let ratio_suspiciousness = ((coarse_energy_ratio - 0.3) / 0.4).clamp(0.0, 1.0);

        // High energy variance also indicates suspicious structure
        let cv = if mean_energy > 0.0 {
            energy_std / mean_energy
        } else {
            0.0
        };
        let variance_suspiciousness = (cv / 2.0).clamp(0.0, 1.0);

        // Combined suspiciousness (weighted)
        let suspiciousness = ratio_suspiciousness * 0.7 + variance_suspiciousness * 0.3;

        Self {
            energy_spectrum,
            total_energy,
            coarse_energy_ratio,
            suspiciousness,
            num_levels,
        }
    }

    /// Map wavelet analysis to RGB color.
    pub fn to_color(&self) -> [u8; 3] {
        let t = self.suspiciousness.clamp(0.0, 1.0);

        // Cool-to-hot colormap emphasizing suspicious regions
        let (r, g, b) = if t < 0.2 {
            let s = t / 0.2;
            (0.1 + s * 0.1, 0.2 + s * 0.3, 0.7 + s * 0.2)
        } else if t < 0.4 {
            let s = (t - 0.2) / 0.2;
            (0.2 - s * 0.1, 0.5 + s * 0.3, 0.9 - s * 0.2)
        } else if t < 0.6 {
            let s = (t - 0.4) / 0.2;
            (0.1 + s * 0.6, 0.8 - s * 0.1, 0.7 - s * 0.5)
        } else if t < 0.8 {
            let s = (t - 0.6) / 0.2;
            (0.7 + s * 0.3, 0.7 - s * 0.3, 0.2 - s * 0.1)
        } else {
            let s = (t - 0.8) / 0.2;
            (1.0, 0.4 - s * 0.2, 0.1 + s * 0.3)
        };

        [(r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8]
    }
}

/// Highly optimized wavelet suspiciousness for exactly 8 entropy values.
/// Performs unrolled Haar wavelet transform and computes suspiciousness in one pass.
/// Zero heap allocations.
///
/// Uses orthonormal Haar wavelet (multiply by 1/sqrt(2)) to match the paper's
/// energy distribution.
#[inline(always)]
pub fn wavelet_suspiciousness_8(stream: &[f64; 8]) -> f64 {
    // Use SIMD for the 8-element transform
    let s0 = f64x4::new([stream[0], stream[2], stream[4], stream[6]]);
    let s1 = f64x4::new([stream[1], stream[3], stream[5], stream[7]]);

    // Level 2 (finest): 4 detail coefficients
    let d2 = (s0 - s1) * INV_SQRT2_X4;
    let a2 = (s0 + s1) * INV_SQRT2_X4;

    let d2_arr = d2.to_array();
    let a2_arr = a2.to_array();

    // Level 1: 2 detail coefficients
    let d1_0 = (a2_arr[0] - a2_arr[1]) * INV_SQRT2;
    let d1_1 = (a2_arr[2] - a2_arr[3]) * INV_SQRT2;

    let a1_0 = (a2_arr[0] + a2_arr[1]) * INV_SQRT2;
    let a1_1 = (a2_arr[2] + a2_arr[3]) * INV_SQRT2;

    // Level 0 (coarsest): 1 detail coefficient
    let d0_0 = (a1_0 - a1_1) * INV_SQRT2;

    // Compute energies at each level using SIMD for level 2
    let d2_sq = d2 * d2;
    let d2_sq_arr = d2_sq.to_array();
    let e2 = d2_sq_arr[0] + d2_sq_arr[1] + d2_sq_arr[2] + d2_sq_arr[3];
    let e1 = d1_0 * d1_0 + d1_1 * d1_1;
    let e0 = d0_0 * d0_0;

    let total_energy = e0 + e1 + e2;

    if total_energy < 1e-10 {
        return 0.5;
    }

    let coarse_energy = e0 + e1;
    let coarse_ratio = coarse_energy / total_energy;

    let mean_energy = total_energy * (1.0 / 3.0);
    let var = (e0 - mean_energy) * (e0 - mean_energy)
        + (e1 - mean_energy) * (e1 - mean_energy)
        + (e2 - mean_energy) * (e2 - mean_energy);
    let std = (var * (1.0 / 3.0)).sqrt();
    let cv = std / mean_energy;

    let ratio_susp = ((coarse_ratio - 0.4) * 2.5).clamp(0.0, 1.0);
    let var_susp = (cv * 0.5).clamp(0.0, 1.0);

    ratio_susp * 0.7 + var_susp * 0.3
}

/// Calculate a quick wavelet suspiciousness value for visualization.
pub fn calculate_wavelet_suspiciousness(data: &[u8]) -> f32 {
    let stream = compute_entropy_stream(data);
    if stream.len() < 4 {
        return 0.5;
    }
    let analysis = WaveletAnalysis::from_entropy_stream(&stream);
    analysis.suspiciousness as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_stream() {
        let data = vec![0u8; 1024];
        let stream = compute_entropy_stream(&data);
        assert_eq!(stream.len(), 4);
        for &entropy in &stream {
            assert!(entropy < 0.1, "Uniform data should have near-zero entropy");
        }
    }

    #[test]
    fn test_entropy_stream_random() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let stream = compute_entropy_stream(&data);
        assert_eq!(stream.len(), 4);
        for &entropy in &stream {
            assert!(entropy > 7.5, "Random data should have high entropy");
        }
    }

    #[test]
    fn test_haar_transform() {
        let signal: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let coefficients = haar_wavelet_transform(&signal);

        assert_eq!(coefficients.len(), 3);
        assert_eq!(coefficients[0].len(), 1);
        assert_eq!(coefficients[1].len(), 2);
        assert_eq!(coefficients[2].len(), 4);
    }

    #[test]
    fn test_wavelet_energy_preservation() {
        let signal: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0];
        let coefficients = haar_wavelet_transform(&signal);
        let wavelet_energy: f64 = coefficients
            .iter()
            .flat_map(|level| level.iter())
            .map(|d| d * d)
            .sum();

        assert!(wavelet_energy > 0.0, "Wavelet energy should be positive");
    }

    #[test]
    fn test_simd_haar_correctness() {
        // Verify SIMD produces same results as reference
        let signal: Vec<f64> = (0..64).map(|i| i as f64).collect();
        let coefficients = haar_wavelet_transform(&signal);

        // Compute reference manually for first level
        let half = signal.len() / 2;
        for i in 0..half {
            let expected_detail = (signal[2 * i] - signal[2 * i + 1]) * INV_SQRT2;
            let actual_detail = coefficients.last().unwrap()[i];
            assert!(
                (expected_detail - actual_detail).abs() < 1e-10,
                "Detail mismatch at {i}"
            );
        }
    }

    #[test]
    fn test_wavelet_suspiciousness_8() {
        // Test the optimized 8-element version
        let stream = [5.0, 5.1, 5.0, 5.2, 5.1, 5.0, 5.1, 5.0];
        let susp = wavelet_suspiciousness_8(&stream);
        assert!(susp >= 0.0 && susp <= 1.0);
    }
}
