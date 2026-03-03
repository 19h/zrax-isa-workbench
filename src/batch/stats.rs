//! Atomic pipeline statistics for cross-thread progress tracking.
//!
//! These counters are updated by pipeline stages and read by the TUI thread.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for pipeline progress.
///
/// All fields are atomically updated by pipeline threads and read by the TUI.
#[derive(Debug)]
pub struct PipelineStats {
    // Walker stage
    pub discovered_files: AtomicU64,
    pub discovered_bytes: AtomicU64,
    pub skipped: AtomicU64,

    // Hasher stage
    pub hashed_files: AtomicU64,
    pub hashed_bytes: AtomicU64,

    // Classifier stage
    pub classified_files: AtomicU64,

    // Writer stage
    pub written_files: AtomicU64,

    // Errors (any stage)
    pub errors: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self {
            discovered_files: AtomicU64::new(0),
            discovered_bytes: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            hashed_files: AtomicU64::new(0),
            hashed_bytes: AtomicU64::new(0),
            classified_files: AtomicU64::new(0),
            written_files: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    /// Take a snapshot of all counters for display.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            discovered_files: self.discovered_files.load(Ordering::Relaxed),
            discovered_bytes: self.discovered_bytes.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            hashed_files: self.hashed_files.load(Ordering::Relaxed),
            hashed_bytes: self.hashed_bytes.load(Ordering::Relaxed),
            classified_files: self.classified_files.load(Ordering::Relaxed),
            written_files: self.written_files.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

impl Clone for PipelineStats {
    fn clone(&self) -> Self {
        let snap = self.snapshot();
        let s = Self::new();
        s.discovered_files
            .store(snap.discovered_files, Ordering::Relaxed);
        s.discovered_bytes
            .store(snap.discovered_bytes, Ordering::Relaxed);
        s.skipped.store(snap.skipped, Ordering::Relaxed);
        s.hashed_files.store(snap.hashed_files, Ordering::Relaxed);
        s.hashed_bytes.store(snap.hashed_bytes, Ordering::Relaxed);
        s.classified_files
            .store(snap.classified_files, Ordering::Relaxed);
        s.written_files.store(snap.written_files, Ordering::Relaxed);
        s.errors.store(snap.errors, Ordering::Relaxed);
        s
    }
}

/// A non-atomic snapshot of pipeline statistics.
#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub discovered_files: u64,
    pub discovered_bytes: u64,
    pub skipped: u64,
    pub hashed_files: u64,
    pub hashed_bytes: u64,
    pub classified_files: u64,
    pub written_files: u64,
    pub errors: u64,
}

impl StatsSnapshot {
    /// Total files processed (written + errors).
    pub fn total_processed(&self) -> u64 {
        self.written_files + self.errors
    }

    /// Progress fraction (0.0 - 1.0) based on discovered vs written.
    pub fn progress_fraction(&self) -> f64 {
        if self.discovered_files == 0 {
            0.0
        } else {
            self.total_processed() as f64 / self.discovered_files as f64
        }
    }
}
