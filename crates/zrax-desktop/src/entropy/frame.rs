//! One rendered frame of the map: the pixels for a region of a mode's
//! world at a resolution.
//!
//! Source of the approach: apeiron `src/main.rs` (`generate_texture`,
//! `generate_cpu_image`). A frame covers the part of the world the view
//! shows, at about one texel per device pixel, so zooming in draws finer
//! data instead of magnifying old pixels. Modes whose world is small and
//! fixed (similarity, digraph, phase space) are drawn whole, at a fixed
//! resolution.
//!
//! Apeiron's compute renderer draws its four GPU modes when an adapter is
//! available; everything else, and every mode when there is none, goes
//! through apeiron's CPU generators. The workbench's own entropy mode asks
//! the zrax engine for the visible cells.

use std::sync::{Mutex, PoisonError};

use apeiron::compat::{Color32, Vec2};
use apeiron::gpu::{GpuRenderer, GpuVizMode};
use apeiron::hilbert::{d2xy, xy2d};
use apeiron::types::ByteLayout;
use apeiron::viz;
use zrax::workbench::{Curve, Engine, Patch, CELL_VALUES, MAX_CELLS_PER_CALL};

use crate::entropy::raster;
use crate::entropy::scene::{MapMode, Scene};

/// Largest texture side generated, as in apeiron.
pub const MAX_TEXTURE_SIDE: usize = 4096;

/// Most cells per side the workbench's entropy mode analyzes for a frame.
const MAX_ENTROPY_CELLS: u64 = 512;

/// Bytes per pixel of a frame.
const PIXEL_BYTES: usize = 4;

/// What to draw.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameSpec {
    /// The visualization.
    pub mode: MapMode,
    /// How offsets are laid out, for the modes that map offsets.
    pub layout: ByteLayout,
    /// Top-left corner of the region, in world units.
    pub world_min: (f32, f32),
    /// Bottom-right corner of the region, in world units.
    pub world_max: (f32, f32),
    /// Texels per side to generate.
    pub texture_side: usize,
    /// The scene revision the frame is drawn from (see `Scene::revision`).
    pub revision: u64,
}

impl FrameSpec {
    /// Whether `shown`, the spec of the frame on screen, is close enough to
    /// this one that drawing again would change little: same mode, layout,
    /// resolution and data, and corners within `tolerance` of the region's
    /// size.
    pub fn is_satisfied_by(&self, shown: &FrameSpec, tolerance: f32) -> bool {
        let span = (self.world_max.0 - self.world_min.0).max(self.world_max.1 - self.world_min.1);
        let limit = span * tolerance;
        let is_near =
            |a: (f32, f32), b: (f32, f32)| (a.0 - b.0).abs() <= limit && (a.1 - b.1).abs() <= limit;
        self.mode == shown.mode
            && self.layout == shown.layout
            && self.texture_side == shown.texture_side
            && self.revision == shown.revision
            && is_near(self.world_min, shown.world_min)
            && is_near(self.world_max, shown.world_max)
    }
}

/// Rendered pixels and the world region they cover.
pub struct Frame {
    /// Top-left corner of the pixels, in world units. The workbench's
    /// entropy mode snaps the region outward to whole cells.
    pub world_min: (f32, f32),
    /// Bottom-right corner of the pixels, in world units.
    pub world_max: (f32, f32),
    /// Image width in pixels.
    pub width: usize,
    /// Image height in pixels.
    pub height: usize,
    /// BGRA pixels, row-major.
    pub pixels: Vec<u8>,
    /// Whether apeiron's compute renderer drew it.
    pub used_gpu: bool,
}

/// Apeiron's compute renderer, created on first use and shared by every
/// frame. It owns its own device; the file it holds is replaced when a
/// frame of another file is drawn.
#[derive(Default)]
pub struct Gpu {
    state: Mutex<GpuState>,
}

#[derive(Default)]
enum GpuState {
    /// No frame has asked for the GPU yet.
    #[default]
    Untried,
    /// No adapter, or the device could not be created.
    Unavailable,
    Ready {
        renderer: Box<GpuRenderer>,
        /// Identity of the uploaded file: buffer address, size, dimension.
        uploaded: Option<(usize, usize, u64)>,
    },
}

impl Gpu {
    /// Whether an adapter was found; `None` before the first GPU frame.
    #[cfg(test)]
    fn is_available(&self) -> Option<bool> {
        match *self.state.lock().unwrap_or_else(PoisonError::into_inner) {
            GpuState::Untried => None,
            GpuState::Unavailable => Some(false),
            GpuState::Ready { .. } => Some(true),
        }
    }

    /// Draw `spec` with the compute renderer. `None` when there is no
    /// adapter or the file does not fit a GPU buffer; the caller then uses
    /// the CPU generators.
    fn render(
        &self,
        scene: &Scene,
        mode: GpuVizMode,
        dimension: u64,
        spec: &FrameSpec,
    ) -> Option<Vec<u8>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, GpuState::Untried) {
            *state = match GpuRenderer::new() {
                Some(renderer) => GpuState::Ready {
                    renderer: Box::new(renderer),
                    uploaded: None,
                },
                None => GpuState::Unavailable,
            };
        }
        let GpuState::Ready { renderer, uploaded } = &mut *state else {
            return None;
        };
        let data = scene.data();
        let identity = (data.as_ptr() as usize, data.len(), dimension);
        if *uploaded != Some(identity) {
            *uploaded = renderer
                .upload_mapped_file(data.clone(), dimension)
                .then_some(identity);
        }
        if uploaded.is_none() || !renderer.is_ready() {
            return None;
        }
        let side = u32::try_from(spec.texture_side).ok()?;
        Some(renderer.render(
            mode,
            side,
            side,
            spec.world_min.0,
            spec.world_min.1,
            spec.world_max.0,
            spec.world_max.1,
        ))
    }
}

/// The compute renderer's mode for `spec`, when it can draw it: the
/// Hilbert layout only, and the forensic mode only without a progressive
/// buffer (whose refinement the CPU path shows).
fn gpu_mode(scene: &Scene, spec: &FrameSpec) -> Option<GpuVizMode> {
    if spec.layout != ByteLayout::Hilbert && spec.mode.maps_file_offsets() {
        return None;
    }
    match spec.mode {
        MapMode::Forensic if scene.hilbert_buffer().is_none() => Some(GpuVizMode::Hilbert),
        MapMode::Similarity => Some(GpuVizMode::SimilarityMatrix),
        MapMode::Digraph => Some(GpuVizMode::Digraph),
        MapMode::PhaseSpace => Some(GpuVizMode::BytePhaseSpace),
        _ => None,
    }
}

/// Draw `spec`. `time_seconds` animates apeiron's placeholders for data
/// that is still being computed. CPU-bound; call it off the main thread.
pub fn render(
    scene: &Scene,
    engine: &Engine,
    gpu: &Gpu,
    spec: FrameSpec,
    time_seconds: f64,
) -> Frame {
    if spec.mode == MapMode::Entropy {
        return render_entropy(engine, spec);
    }
    let dimension = scene.dimension(spec.mode, spec.layout);
    let side = spec.texture_side;
    let gpu_pixels =
        gpu_mode(scene, &spec).and_then(|mode| gpu.render(scene, mode, dimension, &spec));
    let used_gpu = gpu_pixels.is_some();
    let mut pixels = gpu_pixels.unwrap_or_else(|| {
        let colors = render_cpu(scene, &spec, dimension, time_seconds);
        let mut bytes = Vec::with_capacity(colors.len() * PIXEL_BYTES);
        for color in colors {
            bytes.extend_from_slice(&color.to_array());
        }
        bytes
    });
    // Both paths produce RGBA; the window wants BGRA.
    for pixel in pixels.as_chunks_mut::<PIXEL_BYTES>().0 {
        pixel.swap(0, 2);
    }
    Frame {
        world_min: spec.world_min,
        world_max: spec.world_max,
        width: side,
        height: side,
        pixels,
        used_gpu,
    }
}

/// Apeiron's CPU generator for `spec` (`generate_cpu_image`).
fn render_cpu(scene: &Scene, spec: &FrameSpec, dimension: u64, time_seconds: f64) -> Vec<Color32> {
    let data: &[u8] = scene.data();
    let file_size = scene.size();
    let side = spec.texture_side;
    let world_min = Vec2::new(spec.world_min.0, spec.world_min.1);
    // A texture side is at most 4096: exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let (scale_x, scale_y) = (
        (spec.world_max.0 - spec.world_min.0) / side as f32,
        (spec.world_max.1 - spec.world_min.1) / side as f32,
    );
    let use_linear = spec.layout == ByteLayout::Linear;
    match spec.mode {
        MapMode::Forensic if use_linear => viz::generate_linear_entropy_pixels(
            data, dimension, file_size, side, world_min, scale_x, scale_y,
        ),
        MapMode::Forensic => match scene.hilbert_buffer() {
            Some(buffer) => viz::generate_hilbert_pixels_progressive(
                buffer,
                dimension,
                file_size,
                side,
                world_min,
                scale_x,
                scale_y,
                time_seconds,
            ),
            None => viz::generate_hilbert_pixels(
                data, dimension, file_size, side, world_min, scale_x, scale_y,
            ),
        },
        MapMode::Similarity => viz::generate_similarity_matrix_pixels(
            data, file_size, side, world_min, scale_x, scale_y, dimension,
        ),
        MapMode::Digraph => {
            viz::generate_digraph_pixels(data, file_size, side, world_min, scale_x, scale_y)
        }
        MapMode::PhaseSpace => viz::generate_byte_phase_space_pixels(
            data, file_size, side, world_min, scale_x, scale_y,
        ),
        MapMode::Kolmogorov => {
            let samples = scene.complexity().read();
            if samples.is_empty() {
                viz::generate_computing_placeholder(side, time_seconds)
            } else {
                viz::generate_kolmogorov_pixels(
                    &samples, dimension, file_size, side, world_min, scale_x, scale_y, use_linear,
                )
            }
        }
        MapMode::Divergence => viz::generate_jsd_pixels(
            data,
            scene.reference_distribution(),
            dimension,
            file_size,
            side,
            world_min,
            scale_x,
            scale_y,
            use_linear,
        ),
        MapMode::MultiScale => {
            let samples = scene.multi_scale().read();
            if samples.is_empty() {
                viz::generate_computing_placeholder(side, time_seconds)
            } else {
                viz::generate_rcmse_pixels(
                    &samples, dimension, file_size, side, world_min, scale_x, scale_y, use_linear,
                )
            }
        }
        // Drawn by `render_entropy`; `render` never sends it here.
        MapMode::Entropy => Vec::new(),
    }
}

/// The workbench's entropy map for the visible region: the engine's cells
/// at the finest power-of-two scale that keeps the region within
/// [`MAX_ENTROPY_CELLS`] per side, each drawn as a block of whole pixels.
fn render_entropy(engine: &Engine, spec: FrameSpec) -> Frame {
    let side = crate::entropy::viewport::world_side(engine.data().len() as u64);
    // World coordinates are within 0..=side (at most 2^15).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let world = |value: f32| (value.max(0.0) as u64).min(side);
    let (left, top) = (world(spec.world_min.0), world(spec.world_min.1));
    let (right, bottom) = (
        world(spec.world_max.0.ceil()).max(left + 1).min(side),
        world(spec.world_max.1.ceil()).max(top + 1).min(side),
    );
    let span = (right - left).max(bottom - top);
    let scale = span
        .div_ceil(MAX_ENTROPY_CELLS)
        .next_power_of_two()
        .min(side);
    let (cell_left, cell_top) = (left / scale, top / scale);
    let cells_wide = (right.div_ceil(scale) - cell_left).max(1);
    let cells_high = (bottom.div_ceil(scale) - cell_top).max(1);

    // The map side is at most `MAX_MAP_SIDE` (2^15), so these fit u32.
    #[allow(clippy::cast_possible_truncation)]
    let patch = Patch {
        side: side as u32,
        scale: scale as u32,
        x: cell_left as u32,
        y: cell_top as u32,
        width: cells_wide as u32,
        height: cells_high as u32,
        curve: match spec.layout {
            ByteLayout::Hilbert => Curve::Hilbert,
            ByteLayout::Linear => Curve::Linear,
        },
    };
    let total = patch.width * patch.height;
    let mut cells = Vec::with_capacity(total as usize * CELL_VALUES);
    let mut from = 0;
    while from < total {
        // A tile is at most 65536 cells.
        #[allow(clippy::cast_possible_truncation)]
        let count = (total - from).min(MAX_CELLS_PER_CALL as u32);
        cells.extend(engine.spatial_cells(&patch, from, count));
        from += count;
    }

    let upscale = (spec.texture_side / patch.width.max(patch.height) as usize).max(1);
    let (pixels, width, height) = raster::rasterize(&cells, patch.width as usize, upscale);
    // Cell coordinates are below 2^15: exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let to_world = |cell: u64| (cell * scale) as f32;
    Frame {
        world_min: (to_world(cell_left), to_world(cell_top)),
        world_max: (
            to_world(cell_left + cells_wide),
            to_world(cell_top + cells_high),
        ),
        width,
        height,
        pixels,
        used_gpu: false,
    }
}

/// Where file offsets sit in the world of a mode that maps offsets, at
/// byte resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSpace {
    /// World side in bytes.
    pub dimension: u64,
    /// How offsets are laid out.
    pub layout: ByteLayout,
}

impl MapSpace {
    /// The byte offset at world cell (`x`, `y`); `None` outside the world.
    /// The offset may lie beyond the end of the file.
    pub fn offset_at(self, x: u64, y: u64) -> Option<u64> {
        if x >= self.dimension || y >= self.dimension {
            return None;
        }
        Some(match self.layout {
            ByteLayout::Hilbert => xy2d(self.dimension, x, y),
            ByteLayout::Linear => y * self.dimension + x,
        })
    }

    /// The world cell holding the byte at `offset`.
    pub fn position_of(self, offset: u64) -> (u64, u64) {
        match self.layout {
            ByteLayout::Hilbert => d2xy(self.dimension, offset),
            ByteLayout::Linear => (offset % self.dimension, offset / self.dimension),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn fixture(size: usize) -> (Scene, Engine) {
        let data: Arc<[u8]> = (0..size)
            .map(|i| u8::try_from(i * 7 % 256).unwrap_or(0))
            .collect();
        (Scene::new(data.clone()), Engine::new(data))
    }

    fn spec(mode: MapMode, layout: ByteLayout, world_side: f32, texture_side: usize) -> FrameSpec {
        FrameSpec {
            mode,
            layout,
            world_min: (0.0, 0.0),
            world_max: (world_side, world_side),
            texture_side,
            revision: 0,
        }
    }

    #[test]
    fn every_cpu_mode_fills_a_frame_of_the_requested_size() {
        let (scene, engine) = fixture(16 * 1024);
        // No adapter is requested: an untried GPU stays untried only if
        // nothing asks for it, so use the linear layout and CPU-only modes
        // plus the modes that have no GPU path.
        let gpu = Gpu::default();
        for mode in [
            MapMode::Forensic,
            MapMode::Kolmogorov,
            MapMode::Divergence,
            MapMode::MultiScale,
        ] {
            let dimension = scene.dimension(mode, ByteLayout::Linear);
            // World sides of a 16 KiB file are small: exact in f32.
            #[allow(clippy::cast_precision_loss)]
            let frame = render(
                &scene,
                &engine,
                &gpu,
                spec(mode, ByteLayout::Linear, dimension as f32, 64),
                0.0,
            );
            assert_eq!((frame.width, frame.height), (64, 64), "{mode:?}");
            assert_eq!(frame.pixels.len(), 64 * 64 * 4, "{mode:?}");
            assert!(!frame.used_gpu);
        }
        assert_eq!(gpu.is_available(), None);
    }

    #[test]
    fn frames_are_bgra() {
        // A file of printable text: apeiron's forensic color for text is
        // cyan, so blue and green dominate red.
        let data: Arc<[u8]> = Arc::from(vec![b'a'; 4096]);
        let (scene, engine) = (Scene::new(data.clone()), Engine::new(data));
        let dimension = scene.dimension(MapMode::Forensic, ByteLayout::Linear);
        #[allow(clippy::cast_precision_loss)]
        let frame = render(
            &scene,
            &engine,
            &Gpu::default(),
            spec(MapMode::Forensic, ByteLayout::Linear, dimension as f32, 8),
            0.0,
        );
        let [blue, _green, red, alpha] = [
            frame.pixels[0],
            frame.pixels[1],
            frame.pixels[2],
            frame.pixels[3],
        ];
        assert!(blue > red, "expected a cyan pixel, got b={blue} r={red}");
        assert_eq!(alpha, 255);
    }

    #[test]
    fn the_entropy_mode_refines_with_the_visible_region() {
        let (_, engine) = fixture(1 << 20);
        let whole = render_entropy(
            &engine,
            spec(MapMode::Entropy, ByteLayout::Hilbert, 1024.0, 1024),
        );
        // 1 MiB is a 1024-byte square: 512 cells of 2 × 2 bytes per side.
        assert_eq!(whole.width, 1024);
        assert_eq!(whole.world_max, (1024.0, 1024.0));

        let mut zoomed = spec(MapMode::Entropy, ByteLayout::Hilbert, 0.0, 1024);
        zoomed.world_min = (100.5, 200.25);
        zoomed.world_max = (164.5, 264.25);
        let detail = render_entropy(&engine, zoomed);
        // 64 bytes across fit within 512 cells at one byte per cell; the
        // region snaps outward to whole cells: 100..165 and 200..265.
        assert_eq!(detail.world_min, (100.0, 200.0));
        assert_eq!(detail.world_max, (165.0, 265.0));
        assert_eq!(detail.width, 65 * (1024 / 65));
    }

    #[test]
    fn a_frame_is_reused_until_the_view_moves_past_the_tolerance() {
        let shown = spec(MapMode::Forensic, ByteLayout::Hilbert, 100.0, 512);
        let mut wanted = shown;
        wanted.world_min.0 = 1.0;
        assert!(wanted.is_satisfied_by(&shown, 0.02));
        wanted.world_min.0 = 3.0;
        assert!(!wanted.is_satisfied_by(&shown, 0.02));
        let mut newer = shown;
        newer.revision = 1;
        assert!(!newer.is_satisfied_by(&shown, 0.02));
        let mut other_mode = shown;
        other_mode.mode = MapMode::Divergence;
        assert!(!other_mode.is_satisfied_by(&shown, 0.02));
    }

    #[test]
    fn offsets_and_positions_round_trip_in_both_layouts() {
        for (layout, dimension) in [(ByteLayout::Hilbert, 64), (ByteLayout::Linear, 37)] {
            let space = MapSpace { dimension, layout };
            for offset in [0, 1, 63, 64, 1000, dimension * dimension - 1] {
                let (x, y) = space.position_of(offset);
                assert_eq!(space.offset_at(x, y), Some(offset), "{layout:?} {offset}");
            }
            assert_eq!(space.offset_at(dimension, 0), None);
        }
    }
}
