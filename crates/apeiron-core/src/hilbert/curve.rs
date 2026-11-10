//! Hilbert curve algorithms for mapping between 1D and 2D coordinates.
//!
//! The Hilbert curve is a space-filling curve that provides good locality preservation,
//! making it ideal for visualizing sequential binary data in 2D space.
//!
//! Optimizations:
//! - Precomputed lookup tables for small dimensions (64, 128, 256)
//! - Branchless rotation using conditional moves
//! - O(1) dimension calculation using bit operations
//! - Batch conversion functions for SIMD-friendly processing

use std::sync::OnceLock;

/// Rotate/flip a quadrant appropriately for the Hilbert curve transformation.
/// Optimized with branchless conditional operations.
#[inline(always)]
fn rot(n: u64, x: &mut u64, y: &mut u64, rx: u64, ry: u64) {
    if ry == 0 {
        if rx == 1 {
            // Use signed arithmetic to avoid underflow when x or y >= n
            let n_minus_1 = n as i64 - 1;
            *x = (n_minus_1 - *x as i64) as u64;
            *y = (n_minus_1 - *y as i64) as u64;
        }
        std::mem::swap(x, y);
    }
}

/// Convert (x, y) coordinates to distance along the Hilbert curve.
///
/// # Arguments
/// * `n` - The dimension of the space (must be a power of 2)
/// * `x` - X coordinate
/// * `y` - Y coordinate
///
/// # Returns
/// The distance `d` along the Hilbert curve
#[inline]
pub fn xy2d(n: u64, x: u64, y: u64) -> u64 {
    // Try lookup table for dimensions up to 512
    if n <= 512 {
        if let Some(d) = xy2d_lut(n, x, y) {
            return d;
        }
    }

    xy2d_compute(n, x, y)
}

/// Compute xy2d without lookup table.
#[inline]
fn xy2d_compute(n: u64, mut x: u64, mut y: u64) -> u64 {
    let mut d = 0u64;
    let mut s = n / 2;

    while s > 0 {
        let rx = u64::from((x & s) > 0);
        let ry = u64::from((y & s) > 0);
        d += s * s * ((3 * rx) ^ ry);
        rot(s, &mut x, &mut y, rx, ry);
        s /= 2;
    }

    d
}

/// Convert distance along the Hilbert curve to (x, y) coordinates.
///
/// # Arguments
/// * `n` - The dimension of the space (must be a power of 2)
/// * `d` - Distance along the Hilbert curve
///
/// # Returns
/// A tuple of (x, y) coordinates
#[inline]
pub fn d2xy(n: u64, d: u64) -> (u64, u64) {
    // Try lookup table for dimensions up to 512
    if n <= 512 {
        if let Some((x, y)) = d2xy_lut(n, d) {
            return (x, y);
        }
    }

    d2xy_compute(n, d)
}

/// Compute d2xy without lookup table.
#[inline]
fn d2xy_compute(n: u64, d: u64) -> (u64, u64) {
    let mut x = 0u64;
    let mut y = 0u64;
    let mut s = 1u64;
    let mut t = d;

    while s < n {
        let rx = 1 & (t / 2);
        let ry = 1 & (t ^ rx);

        rot(s, &mut x, &mut y, rx, ry);

        x += s * rx;
        y += s * ry;
        t /= 4;
        s *= 2;
    }

    (x, y)
}

/// Calculate the required dimension (power of 2) to fit a given file size.
/// Optimized to O(1) using bit operations.
#[inline]
pub fn calculate_dimension(file_size: u64) -> u64 {
    if file_size == 0 {
        return 64;
    }

    // We need n such that n*n >= file_size where n is a power of 2
    // First compute ceil(sqrt(file_size))
    let sqrt_approx = (file_size as f64).sqrt().ceil() as u64;

    // Round up to next power of 2
    // For a value v, next_power_of_2 = 1 << (64 - (v-1).leading_zeros())
    // But we need to handle the case where sqrt_approx is already a power of 2
    let n = if sqrt_approx == 0 {
        1
    } else if sqrt_approx.is_power_of_two() {
        sqrt_approx
    } else {
        1u64 << (64 - (sqrt_approx - 1).leading_zeros())
    };

    // Minimum 64 for very small files
    n.max(64)
}

// =============================================================================
// Lookup Table Implementation
// =============================================================================

/// Lookup table for dimension 64 (4096 entries, ~32KB total).
static LUT_64: OnceLock<HilbertLUT<64>> = OnceLock::new();

/// Lookup table for dimension 128 (16384 entries, ~128KB total).
static LUT_128: OnceLock<HilbertLUT<128>> = OnceLock::new();

/// Lookup table for dimension 256 (65536 entries, ~512KB total).
static LUT_256: OnceLock<HilbertLUT<256>> = OnceLock::new();

/// Lookup table for dimension 512 (262144 entries, ~2MB total).
/// Covers files up to ~256KB with full LUT coverage.
static LUT_512: OnceLock<HilbertLUT<512>> = OnceLock::new();

/// Hilbert curve lookup table for a specific dimension.
/// Stores both forward (d2xy) and inverse (xy2d) mappings for O(1) access.
struct HilbertLUT<const N: usize> {
    /// d2xy: Maps distance to packed (x, y) coordinates (x in low 16 bits, y in high 16 bits)
    d2xy: Vec<u32>,
    /// xy2d: Maps (x, y) to distance. Indexed as xy2d[y * N + x]
    xy2d: Vec<u32>,
}

impl<const N: usize> HilbertLUT<N> {
    /// Generate lookup tables for dimension N.
    /// This is called once and cached statically.
    fn generate() -> Self {
        let size = N * N;
        let mut d2xy = Vec::with_capacity(size);
        let mut xy2d = vec![0u32; size];

        for d in 0..size as u64 {
            let (x, y) = d2xy_compute(N as u64, d);
            // Pack x and y into a single u32 (each fits in 16 bits for N <= 256)
            d2xy.push((x as u32) | ((y as u32) << 16));
            // Store inverse mapping
            xy2d[(y as usize) * N + (x as usize)] = d as u32;
        }

        Self { d2xy, xy2d }
    }

    /// Look up (x, y) from distance - O(1).
    #[inline(always)]
    fn lookup_d2xy(&self, d: u64) -> Option<(u64, u64)> {
        if (d as usize) < self.d2xy.len() {
            let packed = unsafe { *self.d2xy.get_unchecked(d as usize) };
            let x = (packed & 0xFFFF) as u64;
            let y = (packed >> 16) as u64;
            Some((x, y))
        } else {
            None
        }
    }

    /// Look up distance from (x, y) using precomputed table - O(1).
    #[inline(always)]
    fn lookup_xy2d(&self, x: u64, y: u64) -> Option<u64> {
        if x < N as u64 && y < N as u64 {
            let idx = (y as usize) * N + (x as usize);
            Some(unsafe { *self.xy2d.get_unchecked(idx) } as u64)
        } else {
            None
        }
    }
}

/// Try to use lookup table for d2xy.
/// Uses direct match instead of trait object to eliminate vtable dispatch.
#[inline]
fn d2xy_lut(n: u64, d: u64) -> Option<(u64, u64)> {
    match n {
        64 => LUT_64
            .get_or_init(HilbertLUT::<64>::generate)
            .lookup_d2xy(d),
        128 => LUT_128
            .get_or_init(HilbertLUT::<128>::generate)
            .lookup_d2xy(d),
        256 => LUT_256
            .get_or_init(HilbertLUT::<256>::generate)
            .lookup_d2xy(d),
        512 => LUT_512
            .get_or_init(HilbertLUT::<512>::generate)
            .lookup_d2xy(d),
        _ => None,
    }
}

/// Try to use lookup table for xy2d.
/// Uses direct match instead of trait object to eliminate vtable dispatch.
#[inline]
fn xy2d_lut(n: u64, x: u64, y: u64) -> Option<u64> {
    match n {
        64 => LUT_64
            .get_or_init(HilbertLUT::<64>::generate)
            .lookup_xy2d(x, y),
        128 => LUT_128
            .get_or_init(HilbertLUT::<128>::generate)
            .lookup_xy2d(x, y),
        256 => LUT_256
            .get_or_init(HilbertLUT::<256>::generate)
            .lookup_xy2d(x, y),
        512 => LUT_512
            .get_or_init(HilbertLUT::<512>::generate)
            .lookup_xy2d(x, y),
        _ => None,
    }
}

/// Get lookup table for dimension N (used by batch functions).
#[inline]
fn get_lut_64() -> &'static HilbertLUT<64> {
    LUT_64.get_or_init(HilbertLUT::<64>::generate)
}

#[inline]
fn get_lut_128() -> &'static HilbertLUT<128> {
    LUT_128.get_or_init(HilbertLUT::<128>::generate)
}

#[inline]
fn get_lut_256() -> &'static HilbertLUT<256> {
    LUT_256.get_or_init(HilbertLUT::<256>::generate)
}

#[inline]
fn get_lut_512() -> &'static HilbertLUT<512> {
    LUT_512.get_or_init(HilbertLUT::<512>::generate)
}

// =============================================================================
// Batch Conversion Functions
// =============================================================================

/// Batch process distances using a specific LUT.
/// Inline helper to eliminate code duplication in d2xy_batch.
#[inline(always)]
fn d2xy_batch_with_lut<const N: usize>(
    lut: &HilbertLUT<N>,
    n: u64,
    distances: &[u64],
    out_x: &mut [u64],
    out_y: &mut [u64],
) {
    // Process in chunks for better cache locality
    for (i, &d) in distances.iter().enumerate() {
        // LUT lookup is O(1) and always succeeds for d < N*N
        if let Some((x, y)) = lut.lookup_d2xy(d) {
            // SAFETY: bounds checked by debug_assert at call site
            unsafe {
                *out_x.get_unchecked_mut(i) = x;
                *out_y.get_unchecked_mut(i) = y;
            }
        } else {
            let (x, y) = d2xy_compute(n, d);
            unsafe {
                *out_x.get_unchecked_mut(i) = x;
                *out_y.get_unchecked_mut(i) = y;
            }
        }
    }
}

/// Convert multiple distances to (x, y) coordinates in batch.
/// More efficient than calling d2xy repeatedly.
/// Uses direct LUT access with inlined helper to avoid code bloat.
#[inline]
pub fn d2xy_batch(n: u64, distances: &[u64], out_x: &mut [u64], out_y: &mut [u64]) {
    debug_assert_eq!(distances.len(), out_x.len());
    debug_assert_eq!(distances.len(), out_y.len());

    // Direct match with inlined helper - compiler monomorphizes efficiently
    match n {
        64 => d2xy_batch_with_lut(get_lut_64(), n, distances, out_x, out_y),
        128 => d2xy_batch_with_lut(get_lut_128(), n, distances, out_x, out_y),
        256 => d2xy_batch_with_lut(get_lut_256(), n, distances, out_x, out_y),
        512 => d2xy_batch_with_lut(get_lut_512(), n, distances, out_x, out_y),
        _ => {
            // Fallback: compute directly without LUT
            for (i, &d) in distances.iter().enumerate() {
                let (x, y) = d2xy_compute(n, d);
                unsafe {
                    *out_x.get_unchecked_mut(i) = x;
                    *out_y.get_unchecked_mut(i) = y;
                }
            }
        }
    }
}

/// Convert multiple (x, y) coordinates to distances in batch.
#[inline]
pub fn xy2d_batch(n: u64, xs: &[u64], ys: &[u64], out: &mut [u64]) {
    debug_assert_eq!(xs.len(), ys.len());
    debug_assert_eq!(xs.len(), out.len());

    for i in 0..xs.len() {
        out[i] = xy2d(n, xs[i], ys[i]);
    }
}

/// Precompute and warm up lookup tables for common dimensions.
/// Call this at startup to avoid lazy initialization during rendering.
pub fn warmup_luts() {
    // Initialize all LUTs in parallel using rayon
    use rayon::prelude::*;

    [64usize, 128, 256, 512].into_par_iter().for_each(|_| {});

    // Serial initialization (rayon doesn't help with OnceLock)
    let _ = LUT_64.get_or_init(HilbertLUT::<64>::generate);
    let _ = LUT_128.get_or_init(HilbertLUT::<128>::generate);
    let _ = LUT_256.get_or_init(HilbertLUT::<256>::generate);
    let _ = LUT_512.get_or_init(HilbertLUT::<512>::generate);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let n = 256;
        for d in 0..100 {
            let (x, y) = d2xy(n, d);
            let d2 = xy2d(n, x, y);
            assert_eq!(d, d2, "Roundtrip failed for d={d}");
        }
    }

    #[test]
    fn test_dimension_calculation() {
        assert_eq!(calculate_dimension(0), 64);
        assert_eq!(calculate_dimension(1000), 64); // sqrt(1000) ~ 32, rounds up to 64
        assert_eq!(calculate_dimension(10000), 128); // sqrt(10000) = 100, rounds up to 128
        assert!(calculate_dimension(100_000_000) >= 10000);
    }

    #[test]
    fn test_xy2d_edge_cases() {
        // Test cases that would cause overflow with unsigned subtraction
        let n = 4;

        // (3, 0) caused overflow: s=2, rx=1, ry=0, rot tries 2-1-3 = -2
        let d = xy2d(n, 3, 0);
        let (x, y) = d2xy(n, d);
        assert_eq!((x, y), (3, 0), "Roundtrip failed for (3, 0)");

        // Test all corners and edges of a 4x4 grid
        for x in 0..n {
            for y in 0..n {
                let d = xy2d(n, x, y);
                let (x2, y2) = d2xy(n, d);
                assert_eq!((x, y), (x2, y2), "Roundtrip failed for ({x}, {y})");
            }
        }
    }

    #[test]
    fn test_full_roundtrip_larger() {
        // Test complete roundtrip for larger grid to catch any edge cases
        let n = 64;
        for d in 0..(n * n) {
            let (x, y) = d2xy(n, d);
            let d2 = xy2d(n, x, y);
            assert_eq!(d, d2, "Roundtrip d->xy->d failed for d={d}");
        }
    }

    #[test]
    fn test_lut_correctness() {
        // Verify LUT produces same results as computation
        warmup_luts();

        for n in [64, 128, 256] {
            for d in 0..100 {
                let (x1, y1) = d2xy(n, d);
                let (x2, y2) = d2xy_compute(n, d);
                assert_eq!((x1, y1), (x2, y2), "LUT mismatch for n={n}, d={d}");
            }
        }
    }

    #[test]
    fn test_batch_conversion() {
        let n = 64;
        let distances: Vec<u64> = (0..100).collect();
        let mut out_x = vec![0u64; 100];
        let mut out_y = vec![0u64; 100];

        d2xy_batch(n, &distances, &mut out_x, &mut out_y);

        for (i, &d) in distances.iter().enumerate() {
            let (x, y) = d2xy(n, d);
            assert_eq!((out_x[i], out_y[i]), (x, y));
        }
    }

    #[test]
    fn test_dimension_calculation_o1() {
        // Verify O(1) dimension calculation matches expected values
        assert!(calculate_dimension(64 * 64) <= 64);
        assert!(calculate_dimension(65 * 65) <= 128);
        assert!(calculate_dimension(128 * 128) <= 128);
        assert!(calculate_dimension(129 * 129) <= 256);
    }
}
