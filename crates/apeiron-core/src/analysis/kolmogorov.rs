//! Kolmogorov complexity approximation using tiered compression algorithms.
//!
//! Kolmogorov complexity K(x) is the length of the shortest program that produces x.
//! Since K(x) is uncomputable, we approximate it using the compression ratio.
//!
//! # Tiered Compression System
//!
//! This implementation uses a dynamic, size-based tiered system that balances
//! compression quality (K(x) accuracy) against speed:
//!
//! | Tier | Size Range    | Algorithm | Text K(x) | Binary K(x) | Speed     |
//! |------|---------------|-----------|-----------|-------------|-----------|
//! | 1    | ≤1MB          | xz -9     | ~0.249    | ~0.38       | 0.9 MB/s  |
//! | 2    | 1–64MB        | xz -6     | ~0.264    | ~0.40       | 1.1 MB/s  |
//! | 3    | 64MB–1GB      | zstd -19  | ~0.270    | ~0.43       | 1.2 MB/s  |
//! | 4    | 1–16GB        | zstd -8   | ~0.317    | ~0.47       | 36 MB/s   |
//! | 5    | 16–100GB      | zstd -1   | ~0.407    | ~0.55       | 233 MB/s  |
//!
//! # Rationale
//!
//! - **Tier 1-2 (XZ/LZMA)**: Best compression ratios for accurate K(x) approximation.
//!   XZ uses LZMA2 algorithm which achieves near-optimal compression on most data types.
//!   Speed is acceptable for small data where compression quality matters most.
//!
//! - **Tier 3-5 (Zstd)**: Zstandard provides excellent throughput scaling with adjustable
//!   compression levels. For large data, the slight decrease in compression ratio is
//!   offset by dramatically improved speed, making analysis tractable.
//!
//! # Optimizations
//!
//! - Fast incompressibility detection bypasses compression for random/encrypted data
//! - Thread-local buffers avoid repeated allocations
//! - SIMD-accelerated byte frequency analysis
//! - Parallel batch processing for large datasets

use std::cell::RefCell;
use std::io::Write;
use xz2::write::XzEncoder;

/// Size thresholds for compression tier selection (in bytes).
mod thresholds {
    /// Streaming threshold: chunks below this size use fast Zstd for interactive visualization.
    /// Small chunks (e.g., 128-256 bytes) don't benefit from expensive compression algorithms
    /// since the compression ratio at this scale is dominated by overhead, not data patterns.
    pub const STREAMING_FAST: usize = 4 * 1024; // 4KB
    /// Tier 1 upper bound: 1 MB
    pub const TIER_1_MAX: usize = 1 * 1024 * 1024;
    /// Tier 2 upper bound: 64 MB
    pub const TIER_2_MAX: usize = 64 * 1024 * 1024;
    /// Tier 3 upper bound: 1 GB
    pub const TIER_3_MAX: usize = 1 * 1024 * 1024 * 1024;
    /// Tier 4 upper bound: 16 GB
    pub const TIER_4_MAX: usize = 16 * 1024 * 1024 * 1024;
    // Tier 5: 16GB - 100GB (implicit, everything above TIER_4_MAX)
}

/// Compression tier selection based on data size.
///
/// Each tier represents a different algorithm and compression level optimized
/// for the specific size range, balancing K(x) accuracy against speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionTier {
    /// <4KB (streaming): Zstd level 1 (ultrafast for interactive visualization)
    /// Used for small chunks in streaming/progressive rendering where latency matters.
    TierStreamingFast,
    /// ≤1MB: XZ preset 9 (best compression, ~0.9 MB/s)
    Tier1Xz9,
    /// 1-64MB: XZ preset 6 (good compression, ~1.1 MB/s)
    Tier2Xz6,
    /// 64MB-1GB: Zstd level 19 (high compression, ~1.2 MB/s)
    Tier3Zstd19,
    /// 1-16GB: Zstd level 8 (balanced, ~36 MB/s)
    Tier4Zstd8,
    /// 16-100GB: Zstd level 1 (fast, ~233 MB/s)
    Tier5Zstd1,
}

impl CompressionTier {
    /// Select the appropriate compression tier for the given data size.
    ///
    /// For small chunks (< 4KB), uses fast Zstd to support interactive streaming
    /// visualization. For larger data, uses the full tiered system with XZ/Zstd.
    #[inline]
    pub fn from_size(size: usize) -> Self {
        // Fast path for streaming visualization with small chunks
        if size < thresholds::STREAMING_FAST {
            CompressionTier::TierStreamingFast
        } else if size <= thresholds::TIER_1_MAX {
            CompressionTier::Tier1Xz9
        } else if size <= thresholds::TIER_2_MAX {
            CompressionTier::Tier2Xz6
        } else if size <= thresholds::TIER_3_MAX {
            CompressionTier::Tier3Zstd19
        } else if size <= thresholds::TIER_4_MAX {
            CompressionTier::Tier4Zstd8
        } else {
            CompressionTier::Tier5Zstd1
        }
    }

    /// Select tier for accurate K(x) approximation (ignores streaming fast path).
    ///
    /// Use this when compression ratio accuracy is more important than speed,
    /// such as for final analysis results rather than interactive previews.
    #[inline]
    pub fn from_size_accurate(size: usize) -> Self {
        if size <= thresholds::TIER_1_MAX {
            CompressionTier::Tier1Xz9
        } else if size <= thresholds::TIER_2_MAX {
            CompressionTier::Tier2Xz6
        } else if size <= thresholds::TIER_3_MAX {
            CompressionTier::Tier3Zstd19
        } else if size <= thresholds::TIER_4_MAX {
            CompressionTier::Tier4Zstd8
        } else {
            CompressionTier::Tier5Zstd1
        }
    }

    /// Get the expected K(x) range for text data with this tier.
    #[inline]
    pub const fn text_kx_range(&self) -> (f64, f64) {
        match self {
            CompressionTier::TierStreamingFast => (0.35, 0.50), // Same as Zstd-1, less accurate
            CompressionTier::Tier1Xz9 => (0.20, 0.30),
            CompressionTier::Tier2Xz6 => (0.22, 0.31),
            CompressionTier::Tier3Zstd19 => (0.23, 0.32),
            CompressionTier::Tier4Zstd8 => (0.27, 0.37),
            CompressionTier::Tier5Zstd1 => (0.35, 0.46),
        }
    }

    /// Get the expected K(x) range for binary data with this tier.
    #[inline]
    pub const fn binary_kx_range(&self) -> (f64, f64) {
        match self {
            CompressionTier::TierStreamingFast => (0.50, 0.65), // Same as Zstd-1, less accurate
            CompressionTier::Tier1Xz9 => (0.33, 0.43),
            CompressionTier::Tier2Xz6 => (0.35, 0.45),
            CompressionTier::Tier3Zstd19 => (0.38, 0.48),
            CompressionTier::Tier4Zstd8 => (0.42, 0.52),
            CompressionTier::Tier5Zstd1 => (0.50, 0.60),
        }
    }

    /// Get the approximate throughput in MB/s for this tier.
    #[inline]
    pub const fn throughput_mbps(&self) -> f64 {
        match self {
            CompressionTier::TierStreamingFast => 300.0, // Ultrafast for streaming
            CompressionTier::Tier1Xz9 => 0.9,
            CompressionTier::Tier2Xz6 => 1.1,
            CompressionTier::Tier3Zstd19 => 1.2,
            CompressionTier::Tier4Zstd8 => 36.0,
            CompressionTier::Tier5Zstd1 => 233.0,
        }
    }

    /// Get human-readable description of the tier.
    pub const fn description(&self) -> &'static str {
        match self {
            CompressionTier::TierStreamingFast => "Zstd level 1 (streaming/ultrafast)",
            CompressionTier::Tier1Xz9 => "XZ preset 9 (best compression)",
            CompressionTier::Tier2Xz6 => "XZ preset 6 (good compression)",
            CompressionTier::Tier3Zstd19 => "Zstd level 19 (high compression)",
            CompressionTier::Tier4Zstd8 => "Zstd level 8 (balanced)",
            CompressionTier::Tier5Zstd1 => "Zstd level 1 (fast)",
        }
    }
}

impl std::fmt::Display for CompressionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// Thread-local encoder buffers and small-window contexts avoid repeated allocations.
thread_local! {
    static XZ_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
    static ZSTD_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
    static ZSTD_CONTEXT: RefCell<zstd::zstd_safe::CCtx<'static>> =
        RefCell::new(zstd::zstd_safe::CCtx::create());
}

/// Fast check if data is likely incompressible (high entropy).
/// Uses SIMD byte frequency counting - random data has roughly equal byte frequencies.
/// Returns true if data appears random/encrypted (complexity will be ~1.0).
#[inline]
fn is_likely_incompressible(data: &[u8]) -> bool {
    use wide::u32x4;

    // Only use fast path for larger data where savings matter
    if data.len() < 256 {
        return false;
    }

    // Sample first 256 bytes to check distribution
    let sample = &data[..256];

    // Count unique bytes and high bytes using SIMD-friendly approach
    let mut seen = [0u8; 256]; // 0 = not seen, 1 = seen
    let mut high_byte_count = 0u32;

    // Process 8 bytes at a time
    let chunks = sample.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // Mark bytes as seen and count high bytes
        // Use bit manipulation for high byte detection: byte & 0x80 != 0
        unsafe {
            *seen.get_unchecked_mut(chunk[0] as usize) = 1;
            *seen.get_unchecked_mut(chunk[1] as usize) = 1;
            *seen.get_unchecked_mut(chunk[2] as usize) = 1;
            *seen.get_unchecked_mut(chunk[3] as usize) = 1;
            *seen.get_unchecked_mut(chunk[4] as usize) = 1;
            *seen.get_unchecked_mut(chunk[5] as usize) = 1;
            *seen.get_unchecked_mut(chunk[6] as usize) = 1;
            *seen.get_unchecked_mut(chunk[7] as usize) = 1;
        }

        // Count high bytes using bit manipulation: (byte >> 7) is 1 for high bytes
        high_byte_count += (chunk[0] >> 7) as u32
            + (chunk[1] >> 7) as u32
            + (chunk[2] >> 7) as u32
            + (chunk[3] >> 7) as u32
            + (chunk[4] >> 7) as u32
            + (chunk[5] >> 7) as u32
            + (chunk[6] >> 7) as u32
            + (chunk[7] >> 7) as u32;
    }

    for &b in remainder {
        seen[b as usize] = 1;
        high_byte_count += (b >> 7) as u32;
    }

    // Count unique bytes using SIMD horizontal sum
    let mut unique_count = 0u32;

    // Sum the seen array using SIMD (256 bytes = 16 iterations of 16 bytes each)
    for i in (0..256).step_by(16) {
        let v0 = u32x4::new([
            seen[i] as u32,
            seen[i + 1] as u32,
            seen[i + 2] as u32,
            seen[i + 3] as u32,
        ]);
        let v1 = u32x4::new([
            seen[i + 4] as u32,
            seen[i + 5] as u32,
            seen[i + 6] as u32,
            seen[i + 7] as u32,
        ]);
        let v2 = u32x4::new([
            seen[i + 8] as u32,
            seen[i + 9] as u32,
            seen[i + 10] as u32,
            seen[i + 11] as u32,
        ]);
        let v3 = u32x4::new([
            seen[i + 12] as u32,
            seen[i + 13] as u32,
            seen[i + 14] as u32,
            seen[i + 15] as u32,
        ]);

        let sum = v0 + v1 + v2 + v3;
        let arr = sum.to_array();
        unique_count += arr[0] + arr[1] + arr[2] + arr[3];
    }

    // Random/encrypted data typically has:
    // - High unique byte count (>200 for 256 samples)
    // - Roughly 50% high bytes (100-156 for 256 samples)
    unique_count >= 200 && high_byte_count >= 100 && high_byte_count <= 156
}

/// Compress data using XZ/LZMA2 algorithm.
///
/// # Arguments
/// * `data` - Input data to compress
/// * `preset` - XZ preset level (0-9, higher = better compression, slower)
/// * `buffer` - Pre-allocated output buffer for compressed data
///
/// # Returns
/// Compression ratio (compressed_size / original_size)
#[inline]
fn compress_xz(data: &[u8], preset: u32, buffer: &mut Vec<u8>) -> f64 {
    buffer.clear();
    buffer.reserve(data.len());

    let mut encoder = XzEncoder::new(&mut *buffer, preset);

    if encoder.write_all(data).is_err() {
        return 1.0; // Assume incompressible on error
    }

    if encoder.finish().is_err() {
        return 1.0;
    }

    buffer.len() as f64 / data.len() as f64
}

/// Compress data using Zstandard algorithm.
///
/// # Arguments
/// * `data` - Input data to compress
/// * `level` - Zstd compression level (1-22, higher = better compression, slower)
/// * `buffer` - Pre-allocated output buffer for compressed data
///
/// # Returns
/// Compression ratio (compressed_size / original_size)
#[inline]
fn compress_zstd(data: &[u8], level: i32, buffer: &mut Vec<u8>) -> f64 {
    buffer.clear();
    if data.is_empty() {
        return 0.0;
    }
    if data.len() < 4096 {
        // Continue + end reproduces the existing streaming frame convention,
        // including its unspecified content size. A bulk API changes the ratio.
        buffer.reserve(zstd::zstd_safe::compress_bound(data.len()) + 128);
        let capacity = buffer.capacity();
        return ZSTD_CONTEXT.with(|context| {
            let mut context = context.borrow_mut();
            if context
                .reset(zstd::zstd_safe::ResetDirective::SessionAndParameters)
                .is_err()
                || context
                    .set_parameter(zstd::zstd_safe::CParameter::CompressionLevel(level))
                    .is_err()
            {
                return 1.0;
            }
            let mut input = zstd::zstd_safe::InBuffer::around(data);
            let mut output = zstd::zstd_safe::OutBuffer::around(buffer);
            while input.pos() < data.len() {
                if context.compress_stream(&mut output, &mut input).is_err() {
                    return 1.0;
                }
            }
            loop {
                match context.end_stream(&mut output) {
                    Ok(0) => break,
                    Ok(_) if output.pos() < capacity => {}
                    Ok(_) => return 1.0,
                    Err(_) => return 1.0,
                }
            }
            output.pos() as f64 / data.len() as f64
        });
    }
    // Larger tiers keep their contexts scoped to the call, avoiding retention
    // of a large high-compression workspace on each Rayon worker.
    buffer.reserve(data.len());
    match zstd::stream::Encoder::new(&mut *buffer, level) {
        Ok(mut encoder) => {
            if encoder.write_all(data).is_err() || encoder.finish().is_err() {
                return 1.0;
            }
        }
        Err(_) => return 1.0,
    }
    buffer.len() as f64 / data.len() as f64
}

/// Compress data using the tiered compression system.
///
/// Automatically selects the optimal algorithm based on data size:
/// - Streaming (<4KB): Zstd level 1 (ultrafast for interactive visualization)
/// - Tier 1 (4KB-1MB): XZ preset 9
/// - Tier 2 (1-64MB): XZ preset 6
/// - Tier 3 (64MB-1GB): Zstd level 19
/// - Tier 4 (1-16GB): Zstd level 8
/// - Tier 5 (16-100GB): Zstd level 1
///
/// # Arguments
/// * `data` - Input data to compress
///
/// # Returns
/// Tuple of (compression_ratio, tier_used)
#[inline]
pub fn compress_tiered(data: &[u8]) -> (f64, CompressionTier) {
    let tier = CompressionTier::from_size(data.len());

    let ratio = match tier {
        CompressionTier::TierStreamingFast => {
            // Ultrafast Zstd for small chunks in streaming visualization
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 1, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier1Xz9 => {
            XZ_BUFFER.with(|buf| compress_xz(data, 9, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier2Xz6 => {
            XZ_BUFFER.with(|buf| compress_xz(data, 6, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier3Zstd19 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 19, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier4Zstd8 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 8, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier5Zstd1 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 1, &mut buf.borrow_mut()))
        }
    };

    (ratio, tier)
}

/// Compress data using a specific tier (override automatic selection).
///
/// This is useful when you want consistent results across different data sizes,
/// or when you know the optimal tier for your use case.
#[inline]
pub fn compress_with_tier(data: &[u8], tier: CompressionTier) -> f64 {
    match tier {
        CompressionTier::TierStreamingFast | CompressionTier::Tier5Zstd1 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 1, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier1Xz9 => {
            XZ_BUFFER.with(|buf| compress_xz(data, 9, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier2Xz6 => {
            XZ_BUFFER.with(|buf| compress_xz(data, 6, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier3Zstd19 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 19, &mut buf.borrow_mut()))
        }
        CompressionTier::Tier4Zstd8 => {
            ZSTD_BUFFER.with(|buf| compress_zstd(data, 8, &mut buf.borrow_mut()))
        }
    }
}

/// Approximate Kolmogorov complexity using tiered compression.
///
/// Returns a value between 0.0 (highly compressible/simple) and 1.0 (incompressible/random).
/// Values > 1.0 are clamped (can occur with very small inputs due to compression overhead).
///
/// # Algorithm Selection
///
/// The compression algorithm is automatically selected based on data size to balance
/// K(x) approximation accuracy against computation time:
///
/// - **Small data (≤64MB)**: Uses XZ/LZMA2 for best compression ratio accuracy
/// - **Large data (>64MB)**: Uses Zstd for practical computation times
///
/// # Optimizations
///
/// - Fast path for likely-incompressible data (random/encrypted)
/// - Thread-local encoder buffer reuse
/// - Automatic tier selection based on input size
#[inline]
pub fn calculate_kolmogorov_complexity(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Fast path: skip compression for likely-incompressible data
    if is_likely_incompressible(data) {
        return 0.95; // High complexity, slightly below max to indicate "detected" vs "measured"
    }

    let (ratio, _tier) = compress_tiered(data);
    ratio.clamp(0.0, 1.0)
}

/// Calculate Kolmogorov complexity with tier information.
///
/// Returns both the complexity value and the compression tier that was used,
/// which can be useful for understanding the accuracy/speed tradeoff.
#[inline]
pub fn calculate_kolmogorov_complexity_with_tier(data: &[u8]) -> (f64, CompressionTier) {
    if data.is_empty() {
        return (0.0, CompressionTier::Tier1Xz9);
    }

    // Fast path: skip compression for likely-incompressible data
    if is_likely_incompressible(data) {
        let tier = CompressionTier::from_size(data.len());
        return (0.95, tier);
    }

    let (ratio, tier) = compress_tiered(data);
    (ratio.clamp(0.0, 1.0), tier)
}

/// Calculate Kolmogorov complexity with a preallocated buffer.
/// More efficient for repeated calls with similar-sized data.
///
/// Uses XZ preset 6 by default for the buffer-based API (good balance).
#[inline]
pub fn calculate_kolmogorov_complexity_with_buffer(data: &[u8], buffer: &mut Vec<u8>) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Fast path for incompressible data
    if is_likely_incompressible(data) {
        return 0.95;
    }

    // Select algorithm based on size
    let tier = CompressionTier::from_size(data.len());
    let ratio = match tier {
        CompressionTier::TierStreamingFast | CompressionTier::Tier5Zstd1 => {
            compress_zstd(data, 1, buffer)
        }
        CompressionTier::Tier1Xz9 => compress_xz(data, 9, buffer),
        CompressionTier::Tier2Xz6 => compress_xz(data, 6, buffer),
        CompressionTier::Tier3Zstd19 => compress_zstd(data, 19, buffer),
        CompressionTier::Tier4Zstd8 => compress_zstd(data, 8, buffer),
    };

    ratio.clamp(0.0, 1.0)
}

/// Batch calculate Kolmogorov complexity for multiple chunks.
/// More efficient than calling calculate_kolmogorov_complexity repeatedly.
///
/// Uses parallel processing via Rayon for improved throughput on multi-core systems.
/// Each chunk is compressed using the tier appropriate for its size.
pub fn calculate_kolmogorov_batch(data: &[u8], chunk_size: usize) -> Vec<f64> {
    use rayon::prelude::*;

    if data.is_empty() || chunk_size == 0 {
        return Vec::new();
    }

    let num_chunks = data.len() / chunk_size;

    (0..num_chunks)
        .into_par_iter()
        .map(|i| {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(data.len());
            calculate_kolmogorov_complexity(&data[start..end])
        })
        .collect()
}

/// Batch calculate with tier information.
/// Returns complexity values and the tier used for each chunk.
pub fn calculate_kolmogorov_batch_with_tiers(
    data: &[u8],
    chunk_size: usize,
) -> Vec<(f64, CompressionTier)> {
    use rayon::prelude::*;

    if data.is_empty() || chunk_size == 0 {
        return Vec::new();
    }

    let num_chunks = data.len() / chunk_size;

    (0..num_chunks)
        .into_par_iter()
        .map(|i| {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(data.len());
            calculate_kolmogorov_complexity_with_tier(&data[start..end])
        })
        .collect()
}

/// Calculate complexity for streaming/progressive computation.
/// Returns an iterator that yields (offset, complexity) pairs.
pub fn calculate_kolmogorov_streaming(
    data: &[u8],
    chunk_size: usize,
    interval: usize,
) -> impl Iterator<Item = (usize, f64)> + '_ {
    let num_positions = if data.len() >= chunk_size {
        (data.len() - chunk_size) / interval + 1
    } else {
        0
    };

    (0..num_positions).map(move |i| {
        let offset = i * interval;
        let end = (offset + chunk_size).min(data.len());
        let complexity = calculate_kolmogorov_complexity(&data[offset..end]);
        (offset, complexity)
    })
}

/// Calculate complexity for streaming with tier information.
pub fn calculate_kolmogorov_streaming_with_tier(
    data: &[u8],
    chunk_size: usize,
    interval: usize,
) -> impl Iterator<Item = (usize, f64, CompressionTier)> + '_ {
    let num_positions = if data.len() >= chunk_size {
        (data.len() - chunk_size) / interval + 1
    } else {
        0
    };

    (0..num_positions).map(move |i| {
        let offset = i * interval;
        let end = (offset + chunk_size).min(data.len());
        let (complexity, tier) = calculate_kolmogorov_complexity_with_tier(&data[offset..end]);
        (offset, complexity, tier)
    })
}

/// Estimate compression time for given data size.
///
/// Returns estimated time in seconds based on tier throughput characteristics.
pub fn estimate_compression_time(size: usize) -> f64 {
    let tier = CompressionTier::from_size(size);
    let throughput_bytes_per_sec = tier.throughput_mbps() * 1024.0 * 1024.0;
    size as f64 / throughput_bytes_per_sec
}

/// Get recommended chunk size for a given total data size.
///
/// Returns a chunk size that balances granularity with compression efficiency.
/// Smaller chunks give more detail but may have worse compression ratios.
pub fn recommended_chunk_size(total_size: usize) -> usize {
    // Aim for ~1000 chunks for good visualization granularity
    // but ensure minimum chunk size for reasonable compression
    let ideal = total_size / 1000;
    ideal.clamp(256, 1024 * 1024) // Min 256 bytes, max 1MB per chunk
}

/// Kolmogorov complexity analysis results for color mapping.
#[derive(Debug, Clone, Copy)]
pub struct KolmogorovAnalysis {
    /// Compression ratio (0.0 = highly compressible, 1.0 = incompressible).
    pub complexity: f64,
    /// The compression tier used for this analysis.
    pub tier: CompressionTier,
}

impl KolmogorovAnalysis {
    /// Create a new analysis from raw data.
    #[inline]
    pub fn from_data(data: &[u8]) -> Self {
        let (complexity, tier) = calculate_kolmogorov_complexity_with_tier(data);
        Self { complexity, tier }
    }

    /// Create from precomputed complexity value (assumes Tier1 for compatibility).
    #[inline]
    pub const fn from_value(complexity: f64) -> Self {
        Self {
            complexity,
            tier: CompressionTier::Tier1Xz9,
        }
    }

    /// Create from precomputed complexity value and tier.
    #[inline]
    pub const fn from_value_with_tier(complexity: f64, tier: CompressionTier) -> Self {
        Self { complexity, tier }
    }

    /// Check if this complexity value is within expected range for text data.
    #[inline]
    pub fn is_text_like(&self) -> bool {
        let (min, max) = self.tier.text_kx_range();
        self.complexity >= min && self.complexity <= max
    }

    /// Check if this complexity value is within expected range for binary data.
    #[inline]
    pub fn is_binary_like(&self) -> bool {
        let (min, max) = self.tier.binary_kx_range();
        self.complexity >= min && self.complexity <= max
    }

    /// Map Kolmogorov complexity to RGB color.
    ///
    /// Color legend (viridis-inspired for scientific data):
    /// - Deep purple/blue: Very low complexity (simple/repetitive data)
    /// - Teal/green: Low-medium complexity (structured data)
    /// - Yellow: Medium-high complexity (mixed/code)
    /// - Orange/red: High complexity (compressed/encrypted)
    /// - Bright pink/white: Maximum complexity (random/noise)
    #[inline]
    pub fn to_color(&self) -> [u8; 3] {
        let t = self.complexity.clamp(0.0, 1.0);

        // Viridis-inspired colormap for scientific visualization
        let (r, g, b) = if t < 0.2 {
            // Deep purple to blue
            let s = t / 0.2;
            (0.25 + s * 0.05, 0.0 + s * 0.15, 0.5 + s * 0.2)
        } else if t < 0.4 {
            // Blue to teal
            let s = (t - 0.2) / 0.2;
            (0.3 - s * 0.15, 0.15 + s * 0.4, 0.7 - s * 0.1)
        } else if t < 0.6 {
            // Teal to green-yellow
            let s = (t - 0.4) / 0.2;
            (0.15 + s * 0.6, 0.55 + s * 0.25, 0.6 - s * 0.4)
        } else if t < 0.8 {
            // Yellow to orange
            let s = (t - 0.6) / 0.2;
            (0.75 + s * 0.25, 0.8 - s * 0.3, 0.2 - s * 0.1)
        } else {
            // Orange to hot pink/red
            let s = (t - 0.8) / 0.2;
            (1.0, 0.5 - s * 0.3, 0.1 + s * 0.4)
        };

        [(r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_zstd_preserves_streaming_sizes_and_independent_frames() {
        let mut buffer = Vec::new();
        for level in [1, 8, 19, 1] {
            for len in [0, 1, 63, 64, 128, 256, 1024, 4095, 4096, 8193] {
                for data in [
                    vec![0; len],
                    (0..len).map(|i| (i * 17 + i / 7) as u8).collect(),
                ] {
                    let ratio = compress_zstd(&data, level, &mut buffer);
                    if data.is_empty() {
                        assert_eq!(ratio, 0.0);
                        continue;
                    }
                    let expected = zstd::stream::encode_all(&data[..], level).unwrap();
                    assert_eq!(buffer.len(), expected.len(), "level={level}, len={len}");
                    assert_eq!(zstd::stream::decode_all(&buffer[..]).unwrap(), data);
                    assert_eq!(ratio, expected.len() as f64 / len as f64);
                }
            }
        }
    }

    #[test]
    fn test_tier_selection() {
        // Test streaming fast tier for small chunks
        assert_eq!(
            CompressionTier::from_size(128),
            CompressionTier::TierStreamingFast
        ); // 128 bytes - streaming window
        assert_eq!(
            CompressionTier::from_size(1000),
            CompressionTier::TierStreamingFast
        ); // 1000 bytes - small chunk
        assert_eq!(
            CompressionTier::from_size(4 * 1024 - 1),
            CompressionTier::TierStreamingFast
        ); // Just below 4KB threshold
        assert_eq!(
            CompressionTier::from_size(4 * 1024),
            CompressionTier::Tier1Xz9
        ); // Exactly 4KB - transitions to Tier1
           // Test tier boundaries
        assert_eq!(
            CompressionTier::from_size(512 * 1024),
            CompressionTier::Tier1Xz9
        ); // 512KB
        assert_eq!(
            CompressionTier::from_size(1024 * 1024),
            CompressionTier::Tier1Xz9
        ); // Exactly 1MB
        assert_eq!(
            CompressionTier::from_size(1024 * 1024 + 1),
            CompressionTier::Tier2Xz6
        ); // 1MB + 1
        assert_eq!(
            CompressionTier::from_size(32 * 1024 * 1024),
            CompressionTier::Tier2Xz6
        ); // 32MB
        assert_eq!(
            CompressionTier::from_size(64 * 1024 * 1024),
            CompressionTier::Tier2Xz6
        ); // Exactly 64MB
        assert_eq!(
            CompressionTier::from_size(64 * 1024 * 1024 + 1),
            CompressionTier::Tier3Zstd19
        ); // 64MB + 1
        assert_eq!(
            CompressionTier::from_size(512 * 1024 * 1024),
            CompressionTier::Tier3Zstd19
        ); // 512MB
        assert_eq!(
            CompressionTier::from_size(1024 * 1024 * 1024),
            CompressionTier::Tier3Zstd19
        ); // Exactly 1GB
        assert_eq!(
            CompressionTier::from_size(1024 * 1024 * 1024 + 1),
            CompressionTier::Tier4Zstd8
        ); // 1GB + 1
        assert_eq!(
            CompressionTier::from_size(8usize * 1024 * 1024 * 1024),
            CompressionTier::Tier4Zstd8
        ); // 8GB
        assert_eq!(
            CompressionTier::from_size(16usize * 1024 * 1024 * 1024),
            CompressionTier::Tier4Zstd8
        ); // Exactly 16GB
        assert_eq!(
            CompressionTier::from_size(16usize * 1024 * 1024 * 1024 + 1),
            CompressionTier::Tier5Zstd1
        ); // 16GB + 1
        assert_eq!(
            CompressionTier::from_size(50usize * 1024 * 1024 * 1024),
            CompressionTier::Tier5Zstd1
        ); // 50GB
    }

    #[test]
    fn test_complexity_uniform() {
        // All zeros should be highly compressible
        let data = vec![0u8; 1000];
        let complexity = calculate_kolmogorov_complexity(&data);
        assert!(
            complexity < 0.15,
            "Uniform data should have low complexity: {}",
            complexity
        );
    }

    #[test]
    fn test_complexity_random() {
        // "Random" data should be less compressible
        let data: Vec<u8> = (0..1000).map(|i| (i * 17 + 31) as u8).collect();
        let complexity = calculate_kolmogorov_complexity(&data);
        assert!(
            complexity > 0.2,
            "Varied data should have higher complexity: {}",
            complexity
        );
    }

    #[test]
    fn test_complexity_with_tier_info() {
        // Small data uses streaming fast tier
        let small_data = vec![0u8; 1000];
        let (complexity, tier) = calculate_kolmogorov_complexity_with_tier(&small_data);
        assert!(complexity < 0.2); // Zstd-1 still compresses zeros well
        assert_eq!(tier, CompressionTier::TierStreamingFast); // 1000 bytes < 4KB

        // Larger data uses accurate tiers
        let large_data = vec![0u8; 5000];
        let (complexity2, tier2) = calculate_kolmogorov_complexity_with_tier(&large_data);
        assert!(complexity2 < 0.15); // XZ-9 compresses zeros very well
        assert_eq!(tier2, CompressionTier::Tier1Xz9); // 5000 bytes >= 4KB
    }

    #[test]
    fn test_analysis_color() {
        let low = KolmogorovAnalysis::from_value(0.0);
        let high = KolmogorovAnalysis::from_value(1.0);

        let low_color = low.to_color();
        let high_color = high.to_color();

        // Low complexity should be more blue
        assert!(low_color[2] > low_color[0]);
        // High complexity should be more red
        assert!(high_color[0] > high_color[2]);
    }

    #[test]
    fn test_batch_complexity() {
        let data: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let results = calculate_kolmogorov_batch(&data, 100);
        assert_eq!(results.len(), 10);

        for r in &results {
            assert!(*r >= 0.0 && *r <= 1.0);
        }
    }

    #[test]
    fn test_batch_with_tiers() {
        let data: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let results = calculate_kolmogorov_batch_with_tiers(&data, 100);
        assert_eq!(results.len(), 10);

        for (complexity, tier) in &results {
            assert!(*complexity >= 0.0 && *complexity <= 1.0);
            // 100-byte chunks use streaming fast tier for interactive visualization
            assert_eq!(*tier, CompressionTier::TierStreamingFast);
        }
    }

    #[test]
    fn test_with_buffer() {
        let data = vec![0u8; 1000];
        let mut buffer = Vec::new();

        let c1 = calculate_kolmogorov_complexity(&data);
        let c2 = calculate_kolmogorov_complexity_with_buffer(&data, &mut buffer);

        assert!(
            (c1 - c2).abs() < 0.01,
            "Buffer version should match: {} vs {}",
            c1,
            c2
        );
    }

    #[test]
    fn test_compress_with_specific_tier() {
        let data = vec![0u8; 1000];

        // Test each tier explicitly
        let rs = compress_with_tier(&data, CompressionTier::TierStreamingFast);
        let r1 = compress_with_tier(&data, CompressionTier::Tier1Xz9);
        let r2 = compress_with_tier(&data, CompressionTier::Tier2Xz6);
        let r3 = compress_with_tier(&data, CompressionTier::Tier3Zstd19);
        let r4 = compress_with_tier(&data, CompressionTier::Tier4Zstd8);
        let r5 = compress_with_tier(&data, CompressionTier::Tier5Zstd1);

        // All should compress uniform data well
        assert!(rs < 0.2, "Streaming Fast Zstd-1: {}", rs);
        assert!(r1 < 0.15, "Tier 1 XZ-9: {}", r1);
        assert!(r2 < 0.15, "Tier 2 XZ-6: {}", r2);
        assert!(r3 < 0.15, "Tier 3 Zstd-19: {}", r3);
        assert!(r4 < 0.15, "Tier 4 Zstd-8: {}", r4);
        assert!(r5 < 0.2, "Tier 5 Zstd-1: {}", r5); // Same as streaming
    }

    #[test]
    fn test_tier_descriptions() {
        assert!(CompressionTier::TierStreamingFast
            .description()
            .contains("streaming"));
        assert!(CompressionTier::Tier1Xz9.description().contains("preset 9"));
        assert!(CompressionTier::Tier3Zstd19
            .description()
            .contains("level 19"));
        assert!(CompressionTier::Tier5Zstd1
            .description()
            .contains("level 1"));
    }

    #[test]
    fn test_estimate_compression_time() {
        // 1MB at Tier 1 (0.9 MB/s) should take ~1.1 seconds
        let time_1mb = estimate_compression_time(1024 * 1024);
        assert!(time_1mb > 0.9 && time_1mb < 1.3);

        // 100MB at Tier 2 would be faster per MB
        let time_100mb = estimate_compression_time(64 * 1024 * 1024);
        // At 1.1 MB/s, 64MB should take ~58 seconds
        assert!(time_100mb > 50.0 && time_100mb < 70.0);
    }

    #[test]
    fn test_recommended_chunk_size() {
        // Small file: minimum chunk size
        assert_eq!(recommended_chunk_size(1000), 256);

        // 1MB file: ~1000 bytes per chunk
        let chunk_1mb = recommended_chunk_size(1024 * 1024);
        assert!(chunk_1mb >= 256 && chunk_1mb <= 2048);

        // 1GB file: larger chunks
        let chunk_1gb = recommended_chunk_size(1024 * 1024 * 1024);
        assert!(chunk_1gb >= 1024 && chunk_1gb <= 1024 * 1024);
    }
}
