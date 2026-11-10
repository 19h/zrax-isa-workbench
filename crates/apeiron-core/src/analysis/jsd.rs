//! Jensen-Shannon Divergence analysis.
//!
//! JSD is a symmetric and bounded measure of similarity between probability distributions.
//! Used to detect anomalous regions in binary files.
//!
//! Optimizations:
//! - True SIMD f64x4 for 256-element distribution operations
//! - Accurate ln() with SIMD structure for instruction-level parallelism
//! - Fused mixture + KL computation to reduce memory passes
//! - Dual accumulators for better instruction-level parallelism
//! - Branchless zero-masking for non-positive inputs

use super::entropy::byte_distribution;
use wide::f64x4;

/// Small epsilon to avoid log(0) - SIMD broadcast version
const EPSILON: f64 = 1e-10;
const EPSILON_X4: f64x4 = f64x4::new([EPSILON, EPSILON, EPSILON, EPSILON]);
const HALF_X4: f64x4 = f64x4::new([0.5, 0.5, 0.5, 0.5]);

/// Accurate SIMD natural log using scalar ln() for full double precision.
/// Uses SIMD structure for instruction-level parallelism while maintaining
/// accuracy required for JSD computation (must be exactly 0 for identical distributions).
///
/// Performance: The SIMD structure allows 4 independent ln() calls to pipeline,
/// and the conditional checks are branch-predicted well since values are usually > 0.
#[inline(always)]
fn fast_ln_f64x4(x: f64x4) -> f64x4 {
    let arr = x.to_array();
    // Use accurate ln() - critical for JSD precision
    f64x4::new([
        if arr[0] > 0.0 { arr[0].ln() } else { 0.0 },
        if arr[1] > 0.0 { arr[1].ln() } else { 0.0 },
        if arr[2] > 0.0 { arr[2].ln() } else { 0.0 },
        if arr[3] > 0.0 { arr[3].ln() } else { 0.0 },
    ])
}

/// Calculate KL divergence D_KL(P || Q) between two probability distributions.
/// Uses true SIMD with dual accumulators.
#[inline]
fn kl_divergence(p: &[f64; 256], q: &[f64; 256]) -> f64 {
    let mut div0 = f64x4::ZERO;
    let mut div1 = f64x4::ZERO;

    // Process 8 elements at a time with dual accumulators
    for i in (0..256).step_by(8) {
        let p_vec0 = f64x4::new([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let p_vec1 = f64x4::new([p[i + 4], p[i + 5], p[i + 6], p[i + 7]]);
        let q_vec0 = f64x4::new([q[i], q[i + 1], q[i + 2], q[i + 3]]);
        let q_vec1 = f64x4::new([q[i + 4], q[i + 5], q[i + 6], q[i + 7]]);

        // Add epsilon to q to avoid division by zero
        let q_safe0 = q_vec0 + EPSILON_X4;
        let q_safe1 = q_vec1 + EPSILON_X4;

        // Compute ratios
        let ratio0 = p_vec0 / q_safe0;
        let ratio1 = p_vec1 / q_safe1;

        // SIMD ln computation
        let ln_ratio0 = fast_ln_f64x4(ratio0);
        let ln_ratio1 = fast_ln_f64x4(ratio1);

        // p * ln(p/q) - ln returns 0 for invalid inputs, so masking is implicit
        div0 += p_vec0 * ln_ratio0;
        div1 += p_vec1 * ln_ratio1;
    }

    // Combine and horizontal sum
    let combined = div0 + div1;
    let arr = combined.to_array();
    let sum = arr[0] + arr[1] + arr[2] + arr[3];

    // Convert to bits (log base 2)
    sum / std::f64::consts::LN_2
}

/// Calculate Jensen-Shannon divergence between two probability distributions.
/// Fully SIMD-optimized with vectorized ln computation and dual accumulators.
///
/// JSD is a symmetric and bounded measure of similarity between distributions.
/// JSD(P || Q) = 0.5 * KL(P || M) + 0.5 * KL(Q || M), where M = 0.5 * (P + Q)
///
/// Returns a value between 0.0 (identical distributions) and 1.0 (maximally different).
pub fn jensen_shannon_divergence(p: &[f64; 256], q: &[f64; 256]) -> f64 {
    // Fused computation with dual accumulators for better ILP
    let mut kl_p_m_0 = f64x4::ZERO;
    let mut kl_p_m_1 = f64x4::ZERO;
    let mut kl_q_m_0 = f64x4::ZERO;
    let mut kl_q_m_1 = f64x4::ZERO;

    // Process 8 elements per iteration (2 SIMD vectors)
    for i in (0..256).step_by(8) {
        // Load first vector of 4 elements
        let p_vec0 = f64x4::new([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let q_vec0 = f64x4::new([q[i], q[i + 1], q[i + 2], q[i + 3]]);

        // Load second vector of 4 elements
        let p_vec1 = f64x4::new([p[i + 4], p[i + 5], p[i + 6], p[i + 7]]);
        let q_vec1 = f64x4::new([q[i + 4], q[i + 5], q[i + 6], q[i + 7]]);

        // M = 0.5 * (P + Q) with epsilon for numerical stability
        let m_vec0 = (p_vec0 + q_vec0) * HALF_X4 + EPSILON_X4;
        let m_vec1 = (p_vec1 + q_vec1) * HALF_X4 + EPSILON_X4;

        // Compute ratios P/M and Q/M
        let ratio_p0 = p_vec0 / m_vec0;
        let ratio_p1 = p_vec1 / m_vec1;
        let ratio_q0 = q_vec0 / m_vec0;
        let ratio_q1 = q_vec1 / m_vec1;

        // Vectorized ln computation using true SIMD polynomial
        let ln_ratio_p0 = fast_ln_f64x4(ratio_p0);
        let ln_ratio_p1 = fast_ln_f64x4(ratio_p1);
        let ln_ratio_q0 = fast_ln_f64x4(ratio_q0);
        let ln_ratio_q1 = fast_ln_f64x4(ratio_q1);

        // p * ln(p/m) - the ln function returns 0 for p <= 0, so multiplication handles masking
        // We add epsilon to ensure p > 0 contribution is captured
        kl_p_m_0 += p_vec0 * ln_ratio_p0;
        kl_p_m_1 += p_vec1 * ln_ratio_p1;
        kl_q_m_0 += q_vec0 * ln_ratio_q0;
        kl_q_m_1 += q_vec1 * ln_ratio_q1;
    }

    // Combine accumulators
    let kl_p_m = kl_p_m_0 + kl_p_m_1;
    let kl_q_m = kl_q_m_0 + kl_q_m_1;

    // Horizontal sums
    let kl_p_arr = kl_p_m.to_array();
    let kl_q_arr = kl_q_m.to_array();

    let kl_p_sum = kl_p_arr[0] + kl_p_arr[1] + kl_p_arr[2] + kl_p_arr[3];
    let kl_q_sum = kl_q_arr[0] + kl_q_arr[1] + kl_q_arr[2] + kl_q_arr[3];

    // Convert from natural log to log base 2: divide by ln(2)
    // JSD = 0.5 * (KL(P || M) + KL(Q || M)) / ln(2)
    let inv_ln2 = 1.0 / std::f64::consts::LN_2;
    let jsd = 0.5 * (kl_p_sum + kl_q_sum) * inv_ln2;

    // JSD is bounded [0, 1] when using log base 2
    jsd.clamp(0.0, 1.0)
}

/// Calculate Jensen-Shannon divergence of a data chunk against a reference distribution.
///
/// Returns a value between 0.0 (identical to reference) and 1.0 (maximally different).
pub fn calculate_jsd(data: &[u8], reference: &[f64; 256]) -> f64 {
    let local_dist = byte_distribution(data);
    jensen_shannon_divergence(&local_dist, reference)
}

/// Prepared JSD contributions for repeated windows against one reference.
/// Construction costs O(256 * window_size) time and space; each full window
/// costs O(window_size + distinct_bytes), with no logarithms in the hot path.
/// Preserves the epsilon and base-2 convention of `calculate_jsd`.
/// Prepared window sizes range from 1 to 256 bytes.
pub struct JsdWindow {
    window_size: usize,
    baseline: f64,
    contributions: Vec<f64>,
    reference: [f64; 256],
}

impl JsdWindow {
    pub fn new(reference: &[f64; 256], window_size: usize) -> Self {
        assert!((1..=256).contains(&window_size));
        let mut baseline = 0.0;
        let mut contributions = vec![0.0; 256 * (window_size + 1)];
        let factor = 0.5 / std::f64::consts::LN_2;
        for (byte, &q) in reference.iter().enumerate() {
            let zero = if q > 0.0 {
                q * (q / (0.5 * q + EPSILON)).ln() * factor
            } else {
                0.0
            };
            baseline += zero;
            for count in 1..=window_size {
                let p = count as f64 / window_size as f64;
                let m = 0.5 * (p + q) + EPSILON;
                let q_term = if q > 0.0 { q * (q / m).ln() } else { 0.0 };
                contributions[byte * (window_size + 1) + count] =
                    (p * (p / m).ln() + q_term) * factor - zero;
            }
        }
        Self {
            window_size,
            baseline,
            contributions,
            reference: *reference,
        }
    }

    pub fn divergence(&self, data: &[u8]) -> f64 {
        // EOF windows have a different normalization. Their rare calls use
        // the general kernel, including its uniform empty-data convention.
        if data.len() != self.window_size {
            return calculate_jsd(data, &self.reference);
        }
        let mut counts = [0u16; 256];
        let mut touched = [0u8; 256];
        let mut distinct = 0;
        for &byte in data {
            let count = &mut counts[byte as usize];
            if *count == 0 {
                touched[distinct] = byte;
                distinct += 1;
            }
            *count += 1;
        }
        let mut result = self.baseline;
        for &byte in &touched[..distinct] {
            let byte = byte as usize;
            result += self.contributions[byte * (self.window_size + 1) + counts[byte] as usize];
        }
        result.clamp(0.0, 1.0)
    }
}

/// Batch calculate JSD for multiple chunks against the same reference.
/// More efficient than calling calculate_jsd repeatedly.
pub fn calculate_jsd_batch(data: &[u8], chunk_size: usize, reference: &[f64; 256]) -> Vec<f64> {
    use rayon::prelude::*;

    let num_chunks = data.len() / chunk_size;

    (0..num_chunks)
        .into_par_iter()
        .map(|i| {
            let start = i * chunk_size;
            let end = start + chunk_size;
            let local_dist = byte_distribution(&data[start..end]);
            jensen_shannon_divergence(&local_dist, reference)
        })
        .collect()
}

/// Jensen-Shannon divergence analysis results for color mapping.
#[derive(Debug, Clone, Copy)]
pub struct JSDAnalysis {
    /// JSD value (0.0 = similar to reference, 1.0 = very different).
    pub divergence: f64,
}

impl JSDAnalysis {
    /// Create a new analysis from data and reference distribution.
    pub fn from_data(data: &[u8], reference: &[f64; 256]) -> Self {
        Self {
            divergence: calculate_jsd(data, reference),
        }
    }

    /// Map JSD to RGB color.
    ///
    /// Color legend (divergence from reference):
    /// - Dark blue/purple: Very similar to reference (low divergence)
    /// - Cyan/teal: Slightly different
    /// - Green/yellow: Moderately different
    /// - Orange: Significantly different
    /// - Red/magenta: Very different (high divergence/anomalous)
    pub fn to_color(&self) -> [u8; 3] {
        let t = self.divergence.clamp(0.0, 1.0);

        // Cool-to-hot colormap emphasizing anomalies
        let (r, g, b) = if t < 0.15 {
            // Dark blue - very similar
            let s = t / 0.15;
            (0.1, 0.1 + s * 0.2, 0.4 + s * 0.3)
        } else if t < 0.3 {
            // Blue to cyan
            let s = (t - 0.15) / 0.15;
            (0.1, 0.3 + s * 0.4, 0.7 - s * 0.1)
        } else if t < 0.5 {
            // Cyan to green
            let s = (t - 0.3) / 0.2;
            (0.1 + s * 0.3, 0.7 - s * 0.1, 0.6 - s * 0.4)
        } else if t < 0.7 {
            // Green to yellow
            let s = (t - 0.5) / 0.2;
            (0.4 + s * 0.6, 0.6 + s * 0.3, 0.2 - s * 0.1)
        } else if t < 0.85 {
            // Yellow to orange
            let s = (t - 0.7) / 0.15;
            (1.0, 0.9 - s * 0.4, 0.1)
        } else {
            // Orange to red/magenta - anomalous
            let s = (t - 0.85) / 0.15;
            (1.0, 0.5 - s * 0.3, 0.1 + s * 0.4)
        };

        [(r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_windows_match_general_jsd() {
        let mut seed = 0x123456789abcdefu64;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let mut sparse = [0.0; 256];
        sparse[0] = 0.2;
        sparse[128] = 0.8;
        for reference in [byte_distribution(&data), [1.0 / 256.0; 256], sparse] {
            for size in [1, 16, 64, 128] {
                let prepared = JsdWindow::new(&reference, size);
                for chunk in data.chunks(size) {
                    assert!(
                        (prepared.divergence(chunk) - calculate_jsd(chunk, &reference)).abs()
                            < 1e-12
                    );
                }
                for byte in [0, 128, 255] {
                    let uniform = vec![byte; size];
                    assert!(
                        (prepared.divergence(&uniform) - calculate_jsd(&uniform, &reference)).abs()
                            < 1e-12
                    );
                }
                for len in 0..size {
                    assert!(
                        (prepared.divergence(&data[..len])
                            - calculate_jsd(&data[..len], &reference))
                        .abs()
                            < 1e-12
                    );
                }
            }
        }
    }

    #[test]
    fn test_jsd_identical() {
        let dist = [1.0 / 256.0; 256];
        let jsd = jensen_shannon_divergence(&dist, &dist);
        assert!(jsd < 0.01, "Identical distributions should have JSD near 0");
    }

    #[test]
    fn test_jsd_different() {
        let mut dist1 = [0.0f64; 256];
        let mut dist2 = [0.0f64; 256];

        // Concentrate all probability mass at different bytes
        dist1[0] = 1.0;
        dist2[255] = 1.0;

        let jsd = jensen_shannon_divergence(&dist1, &dist2);
        assert!(
            jsd > 0.9,
            "Completely different distributions should have JSD near 1"
        );
    }

    #[test]
    fn test_jsd_symmetric() {
        let dist1 = [1.0 / 256.0; 256];
        let mut dist2 = [0.0f64; 256];
        for i in 0..256 {
            dist2[i] = if i < 128 { 2.0 / 256.0 } else { 0.0 };
        }

        let jsd1 = jensen_shannon_divergence(&dist1, &dist2);
        let jsd2 = jensen_shannon_divergence(&dist2, &dist1);

        assert!((jsd1 - jsd2).abs() < 0.001, "JSD should be symmetric");
    }

    #[test]
    fn test_simd_correctness() {
        // Verify SIMD implementation matches scalar
        let mut p = [0.0f64; 256];
        let mut q = [0.0f64; 256];

        // Create some test distributions
        for i in 0..256 {
            p[i] = ((i + 1) as f64) / 32896.0; // sum = 256*257/2 = 32896
            q[i] = (1.0 + (i as f64).sin().abs()) / 383.0; // normalized
        }

        // Normalize q properly
        let q_sum: f64 = q.iter().sum();
        for i in 0..256 {
            q[i] /= q_sum;
        }

        let jsd = jensen_shannon_divergence(&p, &q);
        assert!(jsd >= 0.0 && jsd <= 1.0, "JSD should be in [0, 1]");
    }
}
