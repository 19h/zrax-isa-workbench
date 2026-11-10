//! Modes, layouts and background-task messages shared by the generators.
//!
//! From apeiron `src/app/types.rs`, without the egui application state
//! (`FileData`, `Viewport`, `Selection`, `HexView`, `TextureParams`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;

/// Interval for sampling Kolmogorov complexity (every N bytes).
pub const COMPLEXITY_SAMPLE_INTERVAL: usize = 64;

/// Interval for sampling RCMSE (every N bytes).
pub const RCMSE_SAMPLE_INTERVAL: usize = 64;

/// How bytes are mapped to 2D space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ByteLayout {
    /// Hilbert curve - preserves locality but scrambles linear order.
    #[default]
    Hilbert,
    /// Linear (row-major) - top-left to bottom-right, like reading text.
    /// Better for visualizing sections/segments which are contiguous byte ranges.
    Linear,
}

impl ByteLayout {
    /// Get display name for the layout.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hilbert => "Hilbert",
            Self::Linear => "Linear",
        }
    }

    /// Get short indicator for HUD.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Hilbert => "HIL",
            Self::Linear => "LIN",
        }
    }

    /// Toggle to the other layout.
    pub fn toggle(&self) -> Self {
        match self {
            Self::Hilbert => Self::Linear,
            Self::Linear => Self::Hilbert,
        }
    }
}

// =============================================================================
// Visualization Mode
// =============================================================================

/// Available visualization modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VisualizationMode {
    /// Hilbert curve with entropy-based coloring (default).
    Hilbert,
    /// Structural similarity matrix (recurrence plot) - reveals repeating patterns.
    SimilarityMatrix,
    /// Byte value digraph - shows byte pair transitions.
    Digraph,
    /// Byte phase space - plots byte[i] vs byte[i+1] showing file trajectory.
    BytePhaseSpace,
    /// Kolmogorov complexity approximation - shows algorithmic complexity via compression.
    KolmogorovComplexity,
    /// Jensen-Shannon divergence - shows distribution anomalies vs file baseline.
    #[default]
    JensenShannonDivergence,
    /// Refined Composite Multi-Scale Entropy - reveals complexity across time scales.
    MultiScaleEntropy,
}

impl VisualizationMode {
    /// Get display name for the mode.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hilbert => "Hilbert Curve",
            Self::SimilarityMatrix => "Similarity Matrix",
            Self::Digraph => "Byte Digraph",
            Self::BytePhaseSpace => "Byte Phase Space",
            Self::KolmogorovComplexity => "Kolmogorov Complexity",
            Self::JensenShannonDivergence => "JS Divergence",
            Self::MultiScaleEntropy => "Multi-Scale Entropy (RCMSE)",
        }
    }

    /// Get all available modes.
    pub fn all() -> &'static [Self] {
        &[
            Self::Hilbert,
            Self::SimilarityMatrix,
            Self::Digraph,
            Self::BytePhaseSpace,
            Self::KolmogorovComplexity,
            Self::JensenShannonDivergence,
            Self::MultiScaleEntropy,
        ]
    }

    /// Get the world dimension for this mode.
    /// Digraph and BytePhaseSpace use a fixed 256×256 space (byte values).
    /// Other modes scale with file size.
    pub fn world_dimension(self, file_dimension: u64) -> f32 {
        match self {
            Self::Digraph | Self::BytePhaseSpace => 256.0,
            Self::Hilbert
            | Self::SimilarityMatrix
            | Self::KolmogorovComplexity
            | Self::JensenShannonDivergence
            | Self::MultiScaleEntropy => file_dimension as f32,
        }
    }

    /// Get the minimum texture size for this mode.
    pub fn min_texture_size(self) -> usize {
        match self {
            // These modes contain exactly 256 bins per axis. Nearest sampling
            // preserves all bins when the native texture is enlarged on screen.
            Self::Digraph | Self::BytePhaseSpace => 256,
            Self::SimilarityMatrix => 2048,
            Self::Hilbert
            | Self::KolmogorovComplexity
            | Self::JensenShannonDivergence
            | Self::MultiScaleEntropy => 512,
        }
    }

    /// Whether this mode should render the full world space.
    pub fn renders_full_world(self) -> bool {
        match self {
            Self::SimilarityMatrix | Self::Digraph | Self::BytePhaseSpace => true,
            Self::Hilbert
            | Self::KolmogorovComplexity
            | Self::JensenShannonDivergence
            | Self::MultiScaleEntropy => false,
        }
    }

    /// Whether this mode supports switching between Hilbert and Linear layout.
    /// Modes with their own coordinate systems (Digraph, PhaseSpace, SimilarityMatrix)
    /// don't support layout switching.
    pub fn supports_layout_toggle(self) -> bool {
        match self {
            Self::Hilbert
            | Self::KolmogorovComplexity
            | Self::JensenShannonDivergence
            | Self::MultiScaleEntropy => true,
            Self::SimilarityMatrix | Self::Digraph | Self::BytePhaseSpace => false,
        }
    }
}

/// Background computation tasks for lazy loading.
pub enum BackgroundTask {
    /// Next complexity sample batch; append to the existing map.
    ComplexityPartial { data: Vec<f32>, progress: f32 },
    /// Final complexity map (computation complete).
    ComplexityComplete,
    /// Next RCMSE sample batch; append to the existing map.
    RcmsePartial { data: Vec<f32>, progress: f32 },
    /// Final RCMSE map (computation complete).
    RcmseComplete,
}

/// Pending background computations.
pub struct BackgroundTasks {
    /// All workers share one bounded channel for this file.
    pub sender: SyncSender<BackgroundTask>,
    /// Cancellation flag shared with workers.
    pub cancelled: Arc<AtomicBool>,
    /// Receiver for completed tasks.
    pub receiver: Receiver<BackgroundTask>,
    /// Whether complexity map is being computed.
    pub computing_complexity: bool,
    /// Whether RCMSE map is being computed.
    pub computing_rcmse: bool,
    /// Progress of complexity map computation (0.0-1.0).
    pub complexity_progress: f32,
    /// Progress of RCMSE map computation (0.0-1.0).
    pub rcmse_progress: f32,
}

impl BackgroundTasks {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(8);
        Self {
            sender,
            receiver,
            cancelled: Arc::new(AtomicBool::new(false)),
            computing_complexity: false,
            computing_rcmse: false,
            complexity_progress: 0.0,
            rcmse_progress: 0.0,
        }
    }
}

impl Default for BackgroundTasks {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}
