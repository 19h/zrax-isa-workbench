//! Progressive Hilbert entropy computation with realtime rendering support.
//!
//! This module provides lock-free progressive computation of entropy values
//! for Hilbert curve visualization. It uses a two-phase approach:
//!
//! 1. **Coarse pass**: Quick hierarchical sampling (~10K samples) for instant preview
//! 2. **Fine pass**: Full precision sequential computation for final quality
//!
//! The main thread can read computed values at any time without blocking,
//! while the background thread continuously refines the data.
//!
//! Optimizations:
//! - Batch entropy computation using 4-way parallel histograms
//! - Precomputed log2 lookup table reuse from entropy module
//! - Aligned histogram buffers for cache efficiency

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};


use crate::analysis::entropy::{calculate_entropy, calculate_entropy_batch};

/// Window size for entropy calculation (matches ANALYSIS_WINDOW).
const ENTROPY_WINDOW: usize = 64;

/// Target number of coarse samples for instant preview.
const COARSE_SAMPLE_TARGET: usize = 10_000;

/// Minimum file size for progressive rendering (100MB).
/// Files smaller than this are computed immediately.
pub const PROGRESSIVE_THRESHOLD: u64 = 100 * 1024 * 1024;

/// Sample interval for fine pass (bytes between samples).
/// Matches the granularity used elsewhere in the app.
pub const FINE_SAMPLE_INTERVAL: usize = 64;

/// Shared buffer for progressive Hilbert entropy computation.
///
/// This structure is designed for lock-free access:
/// - Background thread writes entropy values
/// - Main thread reads for rendering
/// - Atomic counters track progress
pub struct HilbertBuffer {
    // === Coarse pass data ===
    /// Coarse entropy values (hierarchical pass).
    /// One value per "block" of the file.
    coarse_entropy: Vec<AtomicU32>,

    /// Block size for coarse pass (bytes per coarse sample).
    coarse_block_size: usize,

    /// Whether coarse pass is complete.
    coarse_complete: AtomicBool,

    // === Fine pass data ===
    /// Fine entropy values (full precision).
    /// Stored as AtomicU32 (f32 bits) for lock-free access.
    fine_entropy: Vec<AtomicU32>,

    /// Number of fine samples computed so far.
    fine_progress: AtomicUsize,

    /// Total fine samples needed for full precision.
    fine_total: usize,

    // === Control flags ===
    /// Whether computation is paused (e.g., user switched modes).
    paused: AtomicBool,

    /// Whether computation should be cancelled (e.g., tab closed).
    cancelled: AtomicBool,

    // === File info ===
    /// File size in bytes.
    file_size: u64,
}

impl HilbertBuffer {
    /// Create a new buffer for the given file size.
    pub fn new(file_size: u64) -> Self {
        // Calculate coarse block size to get ~COARSE_SAMPLE_TARGET samples
        let coarse_block_size = (file_size as usize / COARSE_SAMPLE_TARGET).max(ENTROPY_WINDOW);
        let coarse_count = (file_size as usize / coarse_block_size).max(1);

        // Calculate fine sample count
        let fine_total = (file_size as usize).div_ceil(FINE_SAMPLE_INTERVAL).max(1);

        // Pre-allocate fine entropy with sentinel values
        let fine_entropy: Vec<AtomicU32> = (0..fine_total)
            .map(|_| AtomicU32::new(f32::NAN.to_bits()))
            .collect();

        Self {
            coarse_entropy: (0..coarse_count).map(|_| AtomicU32::new(0)).collect(),
            coarse_block_size,
            coarse_complete: AtomicBool::new(false),
            fine_entropy,
            fine_progress: AtomicUsize::new(0),
            fine_total,
            paused: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            file_size,
        }
    }

    /// Check if coarse pass is complete.
    #[inline]
    pub fn is_coarse_complete(&self) -> bool {
        self.coarse_complete.load(Ordering::Acquire)
    }

    /// Get the number of fine samples computed.
    #[inline]
    pub fn fine_progress(&self) -> usize {
        self.fine_progress.load(Ordering::Acquire)
    }

    /// Get the total number of fine samples.
    #[inline]
    pub fn fine_total(&self) -> usize {
        self.fine_total
    }

    /// Check if fine pass is complete.
    #[inline]
    pub fn is_fine_complete(&self) -> bool {
        self.fine_progress() >= self.fine_total
    }

    /// Get progress as a fraction (0.0 to 1.0).
    pub fn progress_fraction(&self) -> f32 {
        if self.fine_total == 0 {
            return 1.0;
        }
        self.fine_progress() as f32 / self.fine_total as f32
    }

    /// Look up entropy for a file offset.
    ///
    /// Returns:
    /// - `Some((entropy, true))` if fine precision is available
    /// - `Some((entropy, false))` if only coarse precision is available
    /// - `None` if not yet computed
    pub fn lookup(&self, file_offset: u64) -> Option<(f32, bool)> {
        if file_offset >= self.file_size {
            return None;
        }

        // Try fine precision first
        let fine_idx = file_offset as usize / FINE_SAMPLE_INTERVAL;
        if fine_idx < self.fine_progress() {
            let bits = self.fine_entropy[fine_idx].load(Ordering::Acquire);
            let entropy = f32::from_bits(bits);
            if !entropy.is_nan() {
                return Some((entropy, true));
            }
        }

        // Fall back to coarse
        if self.is_coarse_complete() {
            let coarse_idx =
                (file_offset as usize / self.coarse_block_size).min(self.coarse_entropy.len() - 1);
            return Some((
                f32::from_bits(self.coarse_entropy[coarse_idx].load(Ordering::Relaxed)),
                false,
            ));
        }

        None
    }

    /// Pause computation.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    /// Resume computation.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    /// Check if paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Cancel computation (cannot be resumed).
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Get coarse block size.
    pub fn coarse_block_size(&self) -> usize {
        self.coarse_block_size
    }
}

/// Background refiner that progressively computes entropy values.
pub struct HilbertRefiner {
    /// Shared buffer for results.
    #[allow(dead_code)]
    buffer: Arc<HilbertBuffer>,

    /// Background computation thread handle.
    #[allow(dead_code)]
    handle: JoinHandle<()>,
}

impl HilbertRefiner {
    /// Start progressive Hilbert computation for the given file data.
    ///
    /// Returns the shared buffer that can be used for rendering immediately.
    /// The background thread will populate it progressively.
    pub fn start(data: Arc<[u8]>, file_size: u64) -> Arc<HilbertBuffer> {
        let buffer = Arc::new(HilbertBuffer::new(file_size));
        let buffer_clone = Arc::clone(&buffer);

        let handle = thread::spawn(move || {
            Self::compute(buffer_clone, data);
        });

        // Store handle to ensure thread is tracked (though we don't join it)
        let _refiner = HilbertRefiner {
            buffer: Arc::clone(&buffer),
            handle,
        };

        buffer
    }

    /// Main computation function (runs in background thread).
    fn compute(buffer: Arc<HilbertBuffer>, data: Arc<[u8]>) {
        // Phase 1: Coarse pass (instant)
        Self::compute_coarse(&buffer, &data);

        if buffer.is_cancelled() {
            return;
        }

        // Phase 2: Fine pass (progressive)
        Self::compute_fine(&buffer, &data);
    }

    /// Compute coarse entropy values for quick preview.
    fn compute_coarse(buffer: &HilbertBuffer, data: &[u8]) {
        let block_size = buffer.coarse_block_size;
        let num_blocks = buffer.coarse_entropy.len();

        for i in 0..num_blocks {
            if buffer.is_cancelled() {
                return;
            }

            // Sample from center of block for better representation
            let block_start = i * block_size;
            let sample_offset = block_start + block_size / 2;
            let sample_offset = sample_offset.min(data.len().saturating_sub(ENTROPY_WINDOW));

            let end = (sample_offset + ENTROPY_WINDOW).min(data.len());
            if sample_offset < end {
                let entropy = calculate_entropy(&data[sample_offset..end]);
                buffer.coarse_entropy[i].store((entropy as f32).to_bits(), Ordering::Relaxed);
            }
        }

        buffer.coarse_complete.store(true, Ordering::Release);
    }

    /// Compute fine entropy values for full precision.
    /// Optimized with batch entropy computation for better cache utilization.
    fn compute_fine(buffer: &HilbertBuffer, data: &[u8]) {
        let total = buffer.fine_total;
        let interval = FINE_SAMPLE_INTERVAL;

        // Larger batch size for better throughput
        const BATCH_SIZE: usize = 16_384;

        let mut i = 0;
        while i < total {
            // Check for cancellation
            if buffer.is_cancelled() {
                return;
            }

            // Check for pause - spin wait with sleep
            while buffer.is_paused() && !buffer.is_cancelled() {
                thread::sleep(std::time::Duration::from_millis(50));
            }

            if buffer.is_cancelled() {
                return;
            }

            // Process a batch using optimized batch entropy
            let batch_end = (i + BATCH_SIZE).min(total);

            // Collect offsets for batch processing
            let offsets: Vec<usize> = (i..batch_end)
                .map(|j| j * interval)
                .filter(|&offset| offset < data.len())
                .collect();

            if !offsets.is_empty() {
                // Use batch entropy computation
                let entropies = calculate_entropy_batch(data, &offsets, ENTROPY_WINDOW);

                // Store results
                for (idx, entropy) in entropies.into_iter().enumerate() {
                    let j = i + idx;
                    if j < batch_end {
                        buffer.fine_entropy[j].store((entropy as f32).to_bits(), Ordering::Release);
                    }
                }

                // Fill any remaining slots (past end of file) with 0
                for j in (i + offsets.len())..batch_end {
                    buffer.fine_entropy[j].store(0.0_f32.to_bits(), Ordering::Release);
                }
            } else {
                // All offsets past end of file
                for j in i..batch_end {
                    buffer.fine_entropy[j].store(0.0_f32.to_bits(), Ordering::Release);
                }
            }

            // Update progress after batch
            buffer.fine_progress.store(batch_end, Ordering::Release);
            i = batch_end;
        }
    }
}

// =============================================================================
// Color Functions for Progressive Rendering
// =============================================================================

/// Generate an animated pulse color for uncomputed regions.
///
/// Creates a gentle pulsing effect between dark gray shades.
pub fn placeholder_pulse_color(time_seconds: f64) -> (u8, u8, u8) {
    // Gentle pulse: 0.5 Hz oscillation
    let pulse = ((time_seconds * std::f64::consts::PI).sin() * 0.5 + 0.5) as f32;
    let base: f32 = 25.0;
    let range: f32 = 12.0;
    let v = (base + pulse * range) as u8;
    // Slight blue tint to indicate "working"
    (v, v, v.saturating_add(8))
}

/// Convert entropy value to RGB color (full precision).
pub fn entropy_to_color(entropy: f32) -> (u8, u8, u8) {
    // Same color mapping as the main visualization
    let h = entropy * 0.7; // Hue: 0 (red/low entropy) to 0.7 (blue/high entropy)
    let s = 0.85;
    let v = 0.3 + entropy * 0.6; // Brighter for higher entropy

    hsv_to_rgb(h * 360.0, s, v)
}

/// Convert entropy value to RGB color (coarse/preview quality).
/// Slightly desaturated to indicate lower precision.
pub fn entropy_to_color_preview(entropy: f32) -> (u8, u8, u8) {
    let h = entropy * 0.7;
    let s = 0.6; // Less saturated
    let v = 0.25 + entropy * 0.5; // Slightly dimmer

    hsv_to_rgb(h * 360.0, s, v)
}

/// Convert HSV to RGB.
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fine_pass_covers_partial_tail_and_publishes_coarse_values() {
        let data: Vec<u8> = (0..129).map(|i| i as u8).collect();
        let buffer = HilbertBuffer::new(data.len() as u64);
        HilbertRefiner::compute_coarse(&buffer, &data);
        assert!(buffer.lookup(128).is_some());
        assert!(!buffer.lookup(128).unwrap().1);
        HilbertRefiner::compute_fine(&buffer, &data);
        assert!(buffer.is_fine_complete());
        assert_eq!(buffer.fine_total(), 3);
        assert_eq!(buffer.lookup(128), Some((0.0, true)));
        assert_eq!(buffer.lookup(129), None);
    }

    #[test]
    fn test_buffer_creation() {
        let buffer = HilbertBuffer::new(1024 * 1024); // 1MB
        assert!(!buffer.is_coarse_complete());
        assert_eq!(buffer.fine_progress(), 0);
        assert!(buffer.fine_total() > 0);
    }
}
