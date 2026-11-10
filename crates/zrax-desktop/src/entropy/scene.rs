//! What apeiron needs to visualize one file, and the state its slower
//! analyses build up in the background.
//!
//! Source of the model: apeiron `src/main.rs` (`load_file`) and
//! `src/app/types.rs` (`FileData`). A scene belongs to one file. It holds
//! the byte distribution the divergence mode compares against, the sampled
//! Kolmogorov and multi-scale entropy maps (computed on worker threads the
//! first time their mode is shown, and drawn while they fill), and, for
//! large files, the progressive Hilbert entropy buffer.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, OnceLock, RwLock, RwLockReadGuard};

use apeiron::analysis::byte_distribution_sampled;
use apeiron::background::{compute_samples, AnalysisTask};
use apeiron::hilbert::{calculate_dimension, HilbertBuffer, HilbertRefiner, PROGRESSIVE_THRESHOLD};
use apeiron::types::{BackgroundTask, ByteLayout, VisualizationMode};

use crate::entropy::viewport::world_side;

/// Batches a sampling worker may have queued before it blocks; as in
/// apeiron's `BackgroundTasks`.
const SAMPLE_CHANNEL_BATCHES: usize = 8;

/// What the map shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapMode {
    /// Apeiron's forensic byte coloring: nulls, text, code, high entropy.
    Forensic,
    /// Apeiron's recurrence plot of byte-window similarity.
    Similarity,
    /// Apeiron's 256 × 256 byte-pair frequency heatmap.
    Digraph,
    /// Apeiron's byte phase space, colored by file position.
    PhaseSpace,
    /// Apeiron's sampled compression complexity.
    Kolmogorov,
    /// Apeiron's divergence of each region from the file's distribution.
    Divergence,
    /// Apeiron's refined composite multi-scale entropy.
    MultiScale,
    /// The browser workbench's entropy map, in its ink-to-magenta palette.
    Entropy,
}

impl MapMode {
    /// Every mode, in toolbar order.
    pub const ALL: [MapMode; 8] = [
        MapMode::Entropy,
        MapMode::Forensic,
        MapMode::Similarity,
        MapMode::Digraph,
        MapMode::PhaseSpace,
        MapMode::Kolmogorov,
        MapMode::Divergence,
        MapMode::MultiScale,
    ];

    /// The three-letter name on the toolbar; apeiron's for its modes.
    pub fn short_name(self) -> &'static str {
        match self {
            MapMode::Entropy => "ent",
            MapMode::Forensic => "hil",
            MapMode::Similarity => "sim",
            MapMode::Digraph => "dig",
            MapMode::PhaseSpace => "phs",
            MapMode::Kolmogorov => "kol",
            MapMode::Divergence => "jsd",
            MapMode::MultiScale => "mse",
        }
    }

    /// What the mode shows, for the legend and tooltips.
    pub fn description(self) -> &'static str {
        match self {
            MapMode::Entropy => "entropy, 0 to 8 bits/byte; magenta from 7.2",
            MapMode::Forensic => {
                "byte forensics: blue nulls, cyan text, green code, red high entropy"
            }
            MapMode::Similarity => "similarity matrix: window x against window y",
            MapMode::Digraph => "byte digraph: byte value against the next byte value",
            MapMode::PhaseSpace => "byte phase space: byte i against byte i+1, colored by position",
            MapMode::Kolmogorov => "compression complexity: purple low, green medium, red maximal",
            MapMode::Divergence => "Jensen-Shannon divergence from the file's byte distribution",
            MapMode::MultiScale => "multi-scale entropy (RCMSE): blue regular, red complex",
        }
    }

    /// Apeiron's own mode, for everything but the workbench's entropy map.
    pub fn apeiron(self) -> Option<VisualizationMode> {
        match self {
            MapMode::Entropy => None,
            MapMode::Forensic => Some(VisualizationMode::Hilbert),
            MapMode::Similarity => Some(VisualizationMode::SimilarityMatrix),
            MapMode::Digraph => Some(VisualizationMode::Digraph),
            MapMode::PhaseSpace => Some(VisualizationMode::BytePhaseSpace),
            MapMode::Kolmogorov => Some(VisualizationMode::KolmogorovComplexity),
            MapMode::Divergence => Some(VisualizationMode::JensenShannonDivergence),
            MapMode::MultiScale => Some(VisualizationMode::MultiScaleEntropy),
        }
    }

    /// Whether a point of the map stands for a file offset. The similarity
    /// matrix, the digraph and the phase space plot other things.
    pub fn maps_file_offsets(self) -> bool {
        !matches!(
            self,
            MapMode::Similarity | MapMode::Digraph | MapMode::PhaseSpace
        )
    }

    /// Whether the mode is drawn once for the whole world at a fixed
    /// resolution instead of per visible region.
    pub fn renders_full_world(self) -> bool {
        self.apeiron()
            .is_some_and(VisualizationMode::renders_full_world)
    }

    /// The smallest texture the mode is generated at.
    pub fn min_texture_size(self) -> usize {
        self.apeiron()
            .map_or(256, VisualizationMode::min_texture_size)
    }

    /// The sampled map the mode draws from, if it needs one.
    fn sample_task(self) -> Option<AnalysisTask> {
        match self {
            MapMode::Kolmogorov => Some(AnalysisTask::Complexity),
            MapMode::MultiScale => Some(AnalysisTask::Rcmse),
            _ => None,
        }
    }
}

const SAMPLING_IDLE: u8 = 0;
const SAMPLING_RUNNING: u8 = 1;
const SAMPLING_DONE: u8 = 2;

/// A map of one value per sample interval, filled by a worker thread.
#[derive(Default)]
pub struct SampleMap {
    samples: RwLock<Vec<f32>>,
    state: AtomicU8,
    /// Fraction computed, as `f32` bits.
    progress: AtomicU32,
    /// Counts batches received, so views can tell the map changed.
    revision: AtomicU64,
}

impl SampleMap {
    /// The samples so far. Held only while a frame is generated.
    pub fn read(&self) -> RwLockReadGuard<'_, Vec<f32>> {
        // A worker that panicked mid-append leaves usable samples behind.
        self.samples
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fraction of the map computed, 0.0 to 1.0.
    pub fn progress(&self) -> f32 {
        f32::from_bits(self.progress.load(Ordering::Relaxed))
    }

    /// Whether the worker is still filling the map.
    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Acquire) == SAMPLING_RUNNING
    }

    fn append(&self, batch: Vec<f32>, progress: f32) {
        self.samples
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(batch);
        self.progress.store(progress.to_bits(), Ordering::Relaxed);
        self.revision.fetch_add(1, Ordering::Release);
    }
}

/// One file as apeiron sees it.
pub struct Scene {
    data: Arc<[u8]>,
    /// Side of the Hilbert world: apeiron's power-of-two dimension.
    hilbert_dimension: u64,
    /// Side of apeiron's linear world: the ceiling of the square root.
    linear_dimension: u64,
    /// The file's own byte distribution, sampled for large files.
    reference_distribution: [f64; 256],
    complexity: Arc<SampleMap>,
    multi_scale: Arc<SampleMap>,
    /// Started on the first forensic frame of a file large enough for
    /// progressive refinement; `None` inside for smaller files.
    hilbert_buffer: OnceLock<Option<Arc<HilbertBuffer>>>,
    /// Tells the sampling workers to stop.
    cancelled: Arc<AtomicBool>,
}

impl Scene {
    /// A scene over `data`. Samples the byte distribution; starts no
    /// background work.
    pub fn new(data: Arc<[u8]>) -> Self {
        let size = data.len() as u64;
        // A resident file is at most 2^30 bytes: exact in f64, and its
        // root fits u64.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let linear_dimension = ((size as f64).sqrt().ceil() as u64).max(1);
        Self {
            hilbert_dimension: calculate_dimension(size),
            linear_dimension,
            reference_distribution: byte_distribution_sampled(&data),
            data,
            complexity: Arc::default(),
            multi_scale: Arc::default(),
            hilbert_buffer: OnceLock::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The file's bytes.
    pub fn data(&self) -> &Arc<[u8]> {
        &self.data
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// The byte distribution of the whole file.
    pub fn reference_distribution(&self) -> &[f64; 256] {
        &self.reference_distribution
    }

    /// Side of the square world `mode` is drawn in, in world units: bytes
    /// for the file layouts, byte values for the digraph and phase space.
    pub fn dimension(&self, mode: MapMode, layout: ByteLayout) -> u64 {
        match mode {
            MapMode::Digraph | MapMode::PhaseSpace => 256,
            MapMode::Similarity => self.hilbert_dimension,
            // The engine's map is a power-of-two square in both layouts.
            MapMode::Entropy => world_side(self.size()),
            _ => match layout {
                ByteLayout::Hilbert => self.hilbert_dimension,
                ByteLayout::Linear => self.linear_dimension,
            },
        }
    }

    /// The sampled Kolmogorov complexity map.
    pub fn complexity(&self) -> &SampleMap {
        &self.complexity
    }

    /// The sampled multi-scale entropy map.
    pub fn multi_scale(&self) -> &SampleMap {
        &self.multi_scale
    }

    /// The progressive entropy buffer, for a file of at least
    /// [`PROGRESSIVE_THRESHOLD`] bytes. Starts the refiner on first use.
    pub fn hilbert_buffer(&self) -> Option<&Arc<HilbertBuffer>> {
        self.hilbert_buffer
            .get_or_init(|| {
                (self.size() >= PROGRESSIVE_THRESHOLD)
                    .then(|| HilbertRefiner::start(Arc::clone(&self.data), self.size()))
            })
            .as_ref()
    }

    /// Start whatever `mode` draws from, unless it is started already.
    pub fn prepare(&self, mode: MapMode) {
        let Some(task) = mode.sample_task() else {
            return;
        };
        let map = match task {
            AnalysisTask::Complexity => &self.complexity,
            AnalysisTask::Rcmse => &self.multi_scale,
        };
        let was_idle = map
            .state
            .compare_exchange(
                SAMPLING_IDLE,
                SAMPLING_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if was_idle {
            spawn_sampling(
                Arc::clone(&self.data),
                task,
                Arc::clone(map),
                Arc::clone(&self.cancelled),
            );
        }
    }

    /// A number that changes whenever what `mode` draws from has grown, so
    /// a view knows to draw it again.
    pub fn revision(&self, mode: MapMode) -> u64 {
        match mode {
            MapMode::Kolmogorov => self.complexity.revision.load(Ordering::Acquire),
            MapMode::MultiScale => self.multi_scale.revision.load(Ordering::Acquire),
            MapMode::Forensic => self
                .hilbert_buffer
                .get()
                .and_then(Option::as_ref)
                .map_or(0, |buffer| {
                    buffer.fine_progress() as u64 + u64::from(buffer.is_coarse_complete())
                }),
            _ => 0,
        }
    }

    /// Fraction done of the background work `mode` waits for; `None` when
    /// nothing is under way.
    pub fn background_progress(&self, mode: MapMode) -> Option<f32> {
        match mode {
            MapMode::Kolmogorov if self.complexity.is_running() => Some(self.complexity.progress()),
            MapMode::MultiScale if self.multi_scale.is_running() => {
                Some(self.multi_scale.progress())
            }
            MapMode::Forensic => self
                .hilbert_buffer
                .get()
                .and_then(Option::as_ref)
                .filter(|buffer| !buffer.is_fine_complete())
                .map(|buffer| buffer.progress_fraction()),
            _ => None,
        }
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        if let Some(Some(buffer)) = self.hilbert_buffer.get() {
            buffer.cancel();
        }
    }
}

/// Run apeiron's sampler for `task` on a worker thread and collect its
/// batches into `map` on another, as apeiron's update loop does.
fn spawn_sampling(
    data: Arc<[u8]>,
    task: AnalysisTask,
    map: Arc<SampleMap>,
    cancelled: Arc<AtomicBool>,
) {
    let (sender, receiver) = mpsc::sync_channel(SAMPLE_CHANNEL_BATCHES);
    std::thread::spawn(move || compute_samples(&data, task, &sender, &cancelled));
    std::thread::spawn(move || {
        // Ends when the sampler drops its sender: finished or cancelled.
        for update in receiver {
            match update {
                BackgroundTask::ComplexityPartial { data, progress }
                | BackgroundTask::RcmsePartial { data, progress } => map.append(data, progress),
                BackgroundTask::ComplexityComplete | BackgroundTask::RcmseComplete => {}
            }
        }
        map.state.store(SAMPLING_DONE, Ordering::Release);
        map.revision.fetch_add(1, Ordering::Release);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scene(size: usize) -> Scene {
        let data: Vec<u8> = (0..size)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        Scene::new(Arc::from(data))
    }

    #[test]
    fn each_mode_has_its_own_world() {
        let scene = scene(72_080);
        let hilbert = scene.dimension(MapMode::Forensic, ByteLayout::Hilbert);
        assert!(hilbert.is_power_of_two() && hilbert * hilbert >= 72_080);
        assert_eq!(scene.dimension(MapMode::Forensic, ByteLayout::Linear), 269);
        assert_eq!(scene.dimension(MapMode::Digraph, ByteLayout::Linear), 256);
        assert_eq!(
            scene.dimension(MapMode::PhaseSpace, ByteLayout::Hilbert),
            256
        );
        assert_eq!(
            scene.dimension(MapMode::Similarity, ByteLayout::Linear),
            hilbert
        );
        assert_eq!(scene.dimension(MapMode::Entropy, ByteLayout::Linear), 512);
    }

    #[test]
    fn sampled_maps_fill_in_the_background_and_report_completion() {
        let scene = scene(64 * 100);
        assert_eq!(scene.revision(MapMode::Kolmogorov), 0);
        assert_eq!(scene.background_progress(MapMode::Kolmogorov), None);
        scene.prepare(MapMode::Kolmogorov);
        scene.prepare(MapMode::Kolmogorov);
        // 100 samples of a 6.4 KiB file take milliseconds; bound the wait.
        let started = std::time::Instant::now();
        while scene.complexity().is_running() {
            assert!(started.elapsed().as_secs() < 30, "sampling did not finish");
            std::thread::yield_now();
        }
        assert_eq!(scene.complexity().read().len(), 100);
        assert!(scene.revision(MapMode::Kolmogorov) > 0);
        assert_eq!(scene.background_progress(MapMode::Kolmogorov), None);
        assert!(scene.multi_scale().read().is_empty());
    }

    #[test]
    fn small_files_have_no_progressive_buffer() {
        assert!(scene(4096).hilbert_buffer().is_none());
    }

    #[test]
    fn only_file_layout_modes_map_points_to_offsets() {
        let plotted: Vec<MapMode> = MapMode::ALL
            .into_iter()
            .filter(|mode| !mode.maps_file_offsets())
            .collect();
        assert_eq!(
            plotted,
            [MapMode::Similarity, MapMode::Digraph, MapMode::PhaseSpace]
        );
        assert!(MapMode::Digraph.renders_full_world());
        assert!(!MapMode::Forensic.renders_full_world());
        assert!(!MapMode::Entropy.renders_full_world());
    }
}
