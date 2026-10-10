//! Shannon entropy calculation and byte distribution analysis.
//!
//! Provides entropy calculation, byte frequency distribution, and related utilities.
//! Optimized with:
//! - 4-way parallel histogram counting to avoid cache contention
//! - Cache-aligned buffers for optimal memory access
//! - Precomputed log2 lookup table for common count values
//! - Sparse count updates for short windows, with exact count logarithms
//! - SIMD histogram merging with u32x4

use wide::f64x4;

/// Window size for byte analysis (matches original implementation).
pub const ANALYSIS_WINDOW: usize = 64;

/// Cache-aligned histogram for optimal memory access.
/// 64-byte alignment ensures each histogram starts on a cache line boundary.
#[repr(C, align(64))]
struct AlignedHistogram {
    counts: [u32; 256],
}

impl AlignedHistogram {
    #[inline(always)]
    const fn new() -> Self {
        Self {
            counts: [0u32; 256],
        }
    }
}

/// Exact count-weighted logarithms shared by all entropy kernels.
const LOG2_LUT_SIZE: usize = 4096;

fn get_entropy_lut() -> &'static [f64; LOG2_LUT_SIZE + 1] {
    use std::sync::OnceLock;
    static LUT: OnceLock<[f64; LOG2_LUT_SIZE + 1]> = OnceLock::new();
    LUT.get_or_init(|| {
        let mut lut = [0.0; LOG2_LUT_SIZE + 1];
        for (count, value) in lut.iter_mut().enumerate().skip(1) {
            *value = count as f64 * (count as f64).log2();
        }
        lut
    })
}

fn count_bytes_wide(data: &[u8]) -> [u64; 256] {
    // Each local histogram remains below u32::MAX; only the reduction is wide.
    data.chunks(64 * 1024 * 1024)
        .map(|chunk| {
            let mut counts = [0u32; 256];
            count_bytes_4way(chunk, &mut counts);
            counts.map(u64::from)
        })
        .fold(
            [0u64; 256],
            |mut sum, counts| {
                for (total, count) in sum.iter_mut().zip(counts) {
                    *total += count;
                }
                sum
            },
        )
}

fn entropy_from_wide_counts(counts: &[u64; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let weighted: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| c as f64 * (c as f64).log2())
        .sum();
    ((total as f64).log2() - weighted / total as f64).clamp(0.0, 8.0)
}

/// Count and accumulate c*log2(c) exactly. Small windows update only the
/// affected bin, rather than evaluating a SIMD logarithm for all 256 bins.
#[inline]
fn entropy_with_counts(data: &[u8], counts: &mut [u32; 256]) -> f64 {
    counts.fill(0);
    if data.is_empty() {
        return 0.0;
    }
    if data.len() > u32::MAX as usize {
        let wide = count_bytes_wide(data);
        for (count, &value) in counts.iter_mut().zip(&wide) {
            *count = value.min(u32::MAX as u64) as u32;
        }
        return entropy_from_wide_counts(&wide, data.len());
    }
    let lut = get_entropy_lut();
    let mut weighted_sum = 0.0;
    if data.len() < FOURWAY_THRESHOLD {
        for &byte in data {
            let count = &mut counts[byte as usize];
            weighted_sum += lut[*count as usize + 1] - lut[*count as usize];
            *count += 1;
        }
    } else {
        count_bytes_4way(data, counts);
        for &count in counts.iter() {
            weighted_sum += if count as usize <= LOG2_LUT_SIZE {
                lut[count as usize]
            } else {
                count as f64 * (count as f64).log2()
            };
        }
    }
    let total = data.len() as f64;
    let log_total = if data.len() <= LOG2_LUT_SIZE {
        lut[data.len()] / total
    } else {
        total.log2()
    };
    (log_total - weighted_sum / total).clamp(0.0, 8.0)
}

/// Count bytes using 4-way parallel histograms.
/// This avoids cache line contention when processing sequential bytes
/// that might hash to the same histogram buckets.
#[inline]
fn count_bytes_4way(data: &[u8], out: &mut [u32; 256]) {
    // Four separate histograms to avoid cache contention
    let mut h0 = AlignedHistogram::new();
    let mut h1 = AlignedHistogram::new();
    let mut h2 = AlignedHistogram::new();
    let mut h3 = AlignedHistogram::new();

    // Process 4 bytes at a time
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // Safety: chunks_exact guarantees 4 bytes
        unsafe {
            let b0 = *chunk.get_unchecked(0) as usize;
            let b1 = *chunk.get_unchecked(1) as usize;
            let b2 = *chunk.get_unchecked(2) as usize;
            let b3 = *chunk.get_unchecked(3) as usize;
            *h0.counts.get_unchecked_mut(b0) += 1;
            *h1.counts.get_unchecked_mut(b1) += 1;
            *h2.counts.get_unchecked_mut(b2) += 1;
            *h3.counts.get_unchecked_mut(b3) += 1;
        }
    }

    // Handle remainder
    for (i, &byte) in remainder.iter().enumerate() {
        match i {
            0 => h0.counts[byte as usize] += 1,
            1 => h1.counts[byte as usize] += 1,
            2 => h2.counts[byte as usize] += 1,
            _ => h3.counts[byte as usize] += 1,
        }
    }

    // Merge histograms using SIMD u32x4 operations
    // Process 4 histogram bins at a time with vectorized addition
    use wide::u32x4;

    for i in (0..256).step_by(4) {
        let v0 = u32x4::new([
            h0.counts[i],
            h0.counts[i + 1],
            h0.counts[i + 2],
            h0.counts[i + 3],
        ]);
        let v1 = u32x4::new([
            h1.counts[i],
            h1.counts[i + 1],
            h1.counts[i + 2],
            h1.counts[i + 3],
        ]);
        let v2 = u32x4::new([
            h2.counts[i],
            h2.counts[i + 1],
            h2.counts[i + 2],
            h2.counts[i + 3],
        ]);
        let v3 = u32x4::new([
            h3.counts[i],
            h3.counts[i + 1],
            h3.counts[i + 2],
            h3.counts[i + 3],
        ]);

        let sum = v0 + v1 + v2 + v3;
        let arr = sum.to_array();

        out[i] = arr[0];
        out[i + 1] = arr[1];
        out[i + 2] = arr[2];
        out[i + 3] = arr[3];
    }
}

/// Count bytes using simple sequential method (better for small data).
#[inline]
fn count_bytes_simple(data: &[u8], out: &mut [u32; 256]) {
    for c in out.iter_mut() {
        *c = 0;
    }
    for &byte in data {
        out[byte as usize] += 1;
    }
}

/// Threshold for using 4-way counting vs simple counting.
/// Below this, the setup overhead of 4-way counting isn't worth it.
const FOURWAY_THRESHOLD: usize = 256;

/// Calculate Shannon entropy for a byte slice.
///
/// Shannon entropy measures the average information content per byte.
/// Values range from 0 (completely uniform) to 8 (maximum randomness).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    entropy_with_counts(data, &mut [0u32; 256])
}

/// Exact Shannon entropy for a chunk, including empty chunks.
#[inline]
pub fn chunk_entropy_fast(chunk: &[u8]) -> f64 {
    calculate_entropy(chunk)
}

/// Calculate byte frequency distribution (probability distribution) for a byte slice.
///
/// Returns an array of 256 probabilities, one for each possible byte value.
/// Uses SIMD for vectorized count-to-probability conversion.
pub fn byte_distribution(data: &[u8]) -> [f64; 256] {
    if data.is_empty() {
        // Return uniform distribution for empty data
        return [1.0 / 256.0; 256];
    }
    if data.len() > u32::MAX as usize {
        let counts = count_bytes_wide(data);
        return counts.map(|c| c as f64 / data.len() as f64);
    }

    let mut counts = [0u32; 256];

    if data.len() >= FOURWAY_THRESHOLD {
        count_bytes_4way(data, &mut counts);
    } else {
        count_bytes_simple(data, &mut counts);
    }

    let inv_total = 1.0 / data.len() as f64;
    let inv_total_x4 = f64x4::splat(inv_total);
    let mut dist = [0.0f64; 256];

    // Convert counts to probabilities using SIMD
    for i in (0..256).step_by(4) {
        let c_vec = f64x4::new([
            counts[i] as f64,
            counts[i + 1] as f64,
            counts[i + 2] as f64,
            counts[i + 3] as f64,
        ]);
        let p_vec = c_vec * inv_total_x4;
        let arr = p_vec.to_array();
        dist[i] = arr[0];
        dist[i + 1] = arr[1];
        dist[i + 2] = arr[2];
        dist[i + 3] = arr[3];
    }

    dist
}

/// Estimate the byte distribution using bounded, contiguous block reads.
/// Files up to 10 MiB are counted exactly. Larger files count the first MiB
/// and at most 10 million body bytes in stratified 16 KiB blocks. Header and
/// body estimates are weighted by their actual file sizes.
/// Time is O(min(n, sampling_budget)); sampled I/O is bounded by the same
/// budget rather than touching millions of pages through strided reads.
pub fn byte_distribution_sampled(data: &[u8]) -> [f64; 256] {
    const SMALL_FILE_THRESHOLD: usize = 10 * 1024 * 1024;
    const HEADER_SIZE: usize = 1024 * 1024;
    const TARGET_SAMPLES: usize = 10_000_000;
    const BLOCK_SIZE: usize = 16 * 1024;
    const BLOCK_COUNT: usize = TARGET_SAMPLES / BLOCK_SIZE;
    if data.len() <= SMALL_FILE_THRESHOLD {
        return byte_distribution(data);
    }
    let header = byte_distribution(&data[..HEADER_SIZE]);
    let body = &data[HEADER_SIZE..];
    if body.len() <= TARGET_SAMPLES {
        let body_distribution = byte_distribution(body);
        let weight = HEADER_SIZE as f64 / data.len() as f64;
        return std::array::from_fn(|i| header[i] * weight + body_distribution[i] * (1.0 - weight));
    }
    let mut counts = [0u64; 256];
    let mut samples = 0usize;
    for block in 0..BLOCK_COUNT {
        // Partition with quotient/remainder arithmetic, avoiding usize products
        // that could overflow for multi-terabyte mappings.
        let quotient = body.len() / BLOCK_COUNT;
        let remainder = body.len() % BLOCK_COUNT;
        let low = block * quotient + block.min(remainder);
        let high = low + quotient + usize::from(block < remainder);
        let length = BLOCK_SIZE.min(high - low);
        // Deterministic SplitMix64 jitter within each stratum reduces alignment
        // with periodic file structure while preserving reproducibility.
        let mut random = (block as u64).wrapping_add(0x9e3779b97f4a7c15);
        random = (random ^ (random >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        random = (random ^ (random >> 27)).wrapping_mul(0x94d049bb133111eb);
        random ^= random >> 31;
        let start = low + random as usize % (high - low - length + 1);
        let mut local = [0u32; 256];
        count_bytes_4way(&body[start..start + length], &mut local);
        for (sum, count) in counts.iter_mut().zip(local) {
            *sum += count as u64;
        }
        samples += length;
    }
    let header_weight = HEADER_SIZE as f64 / data.len() as f64;
    let body_weight = (1.0 - header_weight) / samples as f64;
    std::array::from_fn(|i| header[i] * header_weight + counts[i] as f64 * body_weight)
}

/// Precompute entropy values for all chunks at a given interval.
/// Returns entropies for chunks starting at positions 0, interval, 2*interval, ...
pub fn precompute_chunk_entropies(data: &[u8], chunk_size: usize, interval: usize) -> Vec<f64> {
    if data.len() < chunk_size {
        return Vec::new();
    }

    let num_positions = (data.len() - chunk_size) / interval + 1;

    (0..num_positions)
        .into_iter()
        .map(|i| {
            let start = i * interval;
            let end = start + chunk_size;
            if end <= data.len() {
                chunk_entropy_fast(&data[start..end])
            } else {
                chunk_entropy_fast(&data[start..])
            }
        })
        .collect()
}

/// Extract the first printable ASCII string (length > 4) from data.
pub fn extract_ascii(data: &[u8]) -> Option<String> {
    let mut current = String::new();

    for &byte in data {
        if byte >= 32 && byte <= 126 {
            current.push(byte as char);
        } else {
            if current.len() > 4 {
                return Some(current);
            }
            current.clear();
        }
    }

    if current.len() > 4 {
        Some(current)
    } else {
        None
    }
}

/// Compute entropy into a preallocated counts buffer (avoids allocation).
/// Returns entropy value. For inputs above u32::MAX bytes, the scratch counts
/// saturate while a wide histogram supplies the exact entropy calculation.
#[inline]
pub fn calculate_entropy_with_buffer(data: &[u8], counts: &mut [u32; 256]) -> f64 {
    entropy_with_counts(data, counts)
}

/// Calculate entropy for multiple windows in a batch.
/// This is more efficient than calling calculate_entropy repeatedly because:
/// - Allocates a single reusable histogram buffer
/// - Better cache locality when processing sequential windows
/// - Amortizes function call overhead
///
/// # Arguments
/// * `data` - The full data buffer
/// * `offsets` - Starting positions for each window
/// * `window_size` - Size of each window
///
/// # Returns
/// Vector of entropy values, one for each offset
pub fn calculate_entropy_batch(data: &[u8], offsets: &[usize], window_size: usize) -> Vec<f64> {
    // For small batches, just use normal entropy calculation
    if offsets.len() < 64 {
        return offsets
            .iter()
            .map(|&offset| {
                let end = offset.saturating_add(window_size).min(data.len());
                if offset < data.len() && end > offset {
                    calculate_entropy(&data[offset..end])
                } else {
                    0.0
                }
            })
            .collect();
    }

    // For larger batches, use parallel processing with thread-local buffers
    offsets
        .iter()
        .map(|&offset| {
            let end = offset.saturating_add(window_size).min(data.len());
            if offset < data.len() && end > offset {
                // Thread-local would be ideal but for simplicity use inline buffer
                let mut counts = [0u32; 256];
                calculate_entropy_with_buffer(&data[offset..end], &mut counts)
            } else {
                0.0
            }
        })
        .collect()
}

/// Calculate entropy for multiple windows, returning results in a preallocated buffer.
/// Even more efficient than calculate_entropy_batch when called repeatedly.
#[inline]
pub fn calculate_entropy_batch_into(
    data: &[u8],
    offsets: &[usize],
    window_size: usize,
    results: &mut [f64],
) {
    assert!(results.len() >= offsets.len());

    // Sequential processing with reused histogram buffer for small batches
    if offsets.len() < 64 {
        let mut counts = [0u32; 256];
        for (i, &offset) in offsets.iter().enumerate() {
            let end = offset.saturating_add(window_size).min(data.len());
            results[i] = if offset < data.len() && end > offset {
                calculate_entropy_with_buffer(&data[offset..end], &mut counts)
            } else {
                0.0
            };
        }
        return;
    }

    // Parallel processing for large batches
    results[..offsets.len()]
        .iter_mut()
        .zip(offsets.iter())
        .for_each(|(result, &offset)| {
            let end = offset.saturating_add(window_size).min(data.len());
            *result = if offset < end {
                calculate_entropy(&data[offset..end])
            } else {
                0.0
            };
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampled_distribution_weights_header_and_avoids_byte_stride_aliasing() {
        let mut data = vec![255; 32 * 1024 * 1024];
        data[..1024 * 1024].fill(0);
        let distribution = byte_distribution_sampled(&data);
        assert!((distribution[0] - 1.0 / 32.0).abs() < 1e-12);
        assert!((distribution[255] - 31.0 / 32.0).abs() < 1e-12);
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let distribution = byte_distribution_sampled(&data);
        for probability in distribution {
            assert!((probability - 1.0 / 256.0).abs() < 1e-12);
        }
        assert_eq!(byte_distribution_sampled(&[]), byte_distribution(&[]));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn wide_histogram_and_entropy_support_counts_above_u32_max() {
        let data: Vec<u8> = (0..65539).map(|i| i as u8).collect();
        let mut expected = [0u64; 256];
        for &byte in &data {
            expected[byte as usize] += 1;
        }
        assert_eq!(count_bytes_wide(&data), expected);
        let count = u32::MAX as u64 + 1;
        let mut counts = [0u64; 256];
        counts[0] = count;
        counts[255] = count;
        assert_eq!(entropy_from_wide_counts(&counts, (2 * count) as usize), 1.0);
    }

    fn scalar_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / data.len() as f64;
                -p * p.log2()
            })
            .sum()
    }

    #[test]
    fn entropy_matches_scalar_for_skewed_and_short_windows() {
        let mut seed = 0xfeedbeefu64;
        let data: Vec<u8> = (0..10000)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                if i % 3 == 0 {
                    0
                } else {
                    seed as u8
                }
            })
            .collect();
        let mut counts = [99; 256];
        for len in [
            0, 1, 3, 7, 15, 63, 64, 65, 127, 255, 256, 257, 4096, 8193, 10000,
        ] {
            for input in [&data[..len], &vec![42; len][..]] {
                let expected = scalar_entropy(input);
                assert!((calculate_entropy(input) - expected).abs() < 1e-12);
                assert!((chunk_entropy_fast(input) - expected).abs() < 1e-12);
                assert!(
                    (calculate_entropy_with_buffer(input, &mut counts) - expected).abs() < 1e-12
                );
                assert_eq!(counts.iter().map(|&c| c as usize).sum::<usize>(), len);
            }
        }
    }

    #[test]
    fn batch_into_handles_eof_and_overflow_without_touching_extra_slots() {
        let data = vec![1; 100];
        let offsets: Vec<usize> = (0..80).chain([99, 100, usize::MAX]).collect();
        let expected = calculate_entropy_batch(&data, &offsets, 64);
        let mut results = vec![-1.0; offsets.len() + 1];
        calculate_entropy_batch_into(&data, &offsets, 64, &mut results);
        assert_eq!(&results[..offsets.len()], expected);
        assert_eq!(results[offsets.len()], -1.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All zeros should have zero entropy
        let data = vec![0u8; 256];
        assert!(calculate_entropy(&data) < 0.01);
    }

    #[test]
    fn test_entropy_random() {
        // All different bytes should have maximum entropy (8 bits)
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_byte_distribution() {
        let data = vec![0u8, 1, 2, 3];
        let dist = byte_distribution(&data);
        assert!((dist[0] - 0.25).abs() < 0.01);
        assert!((dist[1] - 0.25).abs() < 0.01);
        assert!(dist[255] < 0.01);
    }

    #[test]
    fn test_extract_ascii() {
        let data = b"Hello World\x00\xff\xfe";
        let ascii = extract_ascii(data);
        assert_eq!(ascii, Some("Hello World".to_string()));
    }

    #[test]
    fn test_fourway_counting_correctness() {
        // Verify 4-way counting produces same results as simple
        let data: Vec<u8> = (0..1000).map(|i| (i * 17 + 31) as u8).collect();

        let mut counts_simple = [0u32; 256];
        count_bytes_simple(&data, &mut counts_simple);

        let mut counts_4way = [0u32; 256];
        count_bytes_4way(&data, &mut counts_4way);

        for i in 0..256 {
            assert_eq!(counts_simple[i], counts_4way[i], "Mismatch at index {i}");
        }
    }

    #[test]
    fn test_large_data_entropy() {
        // Test with larger data to exercise 4-way path
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let entropy = calculate_entropy(&data);
        // Should be close to max entropy since we have uniform distribution
        assert!(entropy > 7.9);
    }
}
