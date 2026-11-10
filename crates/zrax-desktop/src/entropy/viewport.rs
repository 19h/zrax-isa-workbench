//! Coordinates of the entropy map and the camera over it.
//!
//! Source: `web/viewport.js` and the coordinate invariants recorded in
//! `web/README.md`. The map is a square of `side` × `side` bytes, `side`
//! being the smallest power of two whose square holds the file. A layer
//! shows it at `scale` × `scale` bytes per cell. World coordinates run from
//! 0.0 to 1.0 across the square at every resolution.

use zrax::workbench::{hilbert_distance, hilbert_point, Curve};

/// Cells per side of the base layer, at most.
pub const BASE_GRID: u64 = 256;

/// Smallest zoom limit, for files whose base layer already shows bytes.
const MIN_MAX_ZOOM: f64 = 8.0;

/// Map side in bytes for a file of `size` bytes: a power of two, at least 2.
pub fn world_side(size: u64) -> u64 {
    let mut side = 2u64;
    while side.saturating_mul(side) < size {
        side *= 2;
    }
    side
}

/// Bytes per cell side of the base layer: the whole map in at most
/// [`BASE_GRID`] cells per side.
pub fn base_scale(side: u64) -> u64 {
    (side / BASE_GRID).max(1)
}

/// Deepest zoom: one byte per cell shown at 16 cells across the frame, or
/// [`MIN_MAX_ZOOM`] for small files.
pub fn max_zoom(side: u64) -> f64 {
    // A power of two up to 2^32: exact in f64.
    #[allow(clippy::cast_precision_loss)]
    let by_side = side as f64 / 16.0;
    by_side.max(MIN_MAX_ZOOM)
}

/// One resolution of the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grid {
    /// Map side in bytes.
    pub side: u64,
    /// Bytes per cell side.
    pub scale: u64,
    /// How offsets are laid out.
    pub curve: Curve,
}

impl Grid {
    /// The base layer of a file of `size` bytes.
    pub fn base(size: u64, curve: Curve) -> Self {
        let side = world_side(size);
        Self {
            side,
            scale: base_scale(side),
            curve,
        }
    }

    /// Cells per side.
    pub fn cells_per_side(self) -> u64 {
        self.side / self.scale
    }

    /// Bytes one cell covers.
    pub fn bytes_per_cell(self) -> u64 {
        self.scale * self.scale
    }

    /// The cell (column, row) holding the byte at `offset`.
    pub fn cell_of(self, offset: u64) -> (u64, u64) {
        match self.curve {
            Curve::Hilbert => hilbert_point(self.cells_per_side(), offset / self.bytes_per_cell()),
            Curve::Linear => (
                offset % self.side / self.scale,
                offset / self.side / self.scale,
            ),
        }
    }

    /// The first byte offset of the cell at (`column`, `row`). On the
    /// linear layout a cell is a square of byte rows; this is its top-left
    /// byte.
    pub fn origin_of(self, column: u64, row: u64) -> u64 {
        match self.curve {
            Curve::Hilbert => {
                hilbert_distance(self.cells_per_side(), column, row) * self.bytes_per_cell()
            }
            Curve::Linear => row * self.scale * self.side + column * self.scale,
        }
    }
}

/// The part of the map a frame shows: its top-left corner in world
/// coordinates and the magnification (1.0 shows the whole map).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Magnification, at least 1.0.
    pub zoom: f64,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            zoom: 1.0,
        }
    }
}

impl Viewport {
    fn clamp(&mut self) {
        let end = 1.0 - 1.0 / self.zoom;
        self.x = self.x.clamp(0.0, end);
        self.y = self.y.clamp(0.0, end);
    }

    /// Multiply the zoom by `factor`, keeping the world point under the
    /// frame position (`anchor_x`, `anchor_y`, each 0.0..=1.0) in place.
    pub fn zoom_at(&mut self, factor: f64, anchor_x: f64, anchor_y: f64, max_zoom: f64) {
        let world_x = self.x + anchor_x / self.zoom;
        let world_y = self.y + anchor_y / self.zoom;
        self.zoom = (self.zoom * factor).clamp(1.0, max_zoom.max(1.0));
        self.x = world_x - anchor_x / self.zoom;
        self.y = world_y - anchor_y / self.zoom;
        self.clamp();
    }

    /// Move the map by a fraction of the frame, as a drag does.
    pub fn pan(&mut self, frame_dx: f64, frame_dy: f64) {
        self.x -= frame_dx / self.zoom;
        self.y -= frame_dy / self.zoom;
        self.clamp();
    }

    /// Center the frame on a world position.
    pub fn center(&mut self, world_x: f64, world_y: f64) {
        self.x = world_x - 0.5 / self.zoom;
        self.y = world_y - 0.5 / self.zoom;
        self.clamp();
    }

    /// The world position under a frame position (each 0.0..=1.0).
    pub fn world_at(&self, frame_x: f64, frame_y: f64) -> (f64, f64) {
        (self.x + frame_x / self.zoom, self.y + frame_y / self.zoom)
    }

    /// Whether a world position is inside the frame.
    pub fn contains(&self, world_x: f64, world_y: f64) -> bool {
        let span = 1.0 / self.zoom;
        (self.x..=self.x + span).contains(&world_x) && (self.y..=self.y + span).contains(&world_y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_map_side_is_the_smallest_power_of_two_square_holding_the_file() {
        assert_eq!(world_side(0), 2);
        assert_eq!(world_side(4), 2);
        assert_eq!(world_side(5), 4);
        assert_eq!(world_side(72_080), 512);
        assert_eq!(world_side(65_536), 256);
        assert_eq!(world_side(65_537), 512);
        assert_eq!(base_scale(512), 2);
        assert_eq!(base_scale(256), 1);
        assert_eq!(base_scale(2), 1);
    }

    #[test]
    fn cells_and_offsets_round_trip_on_both_layouts() {
        for curve in [Curve::Hilbert, Curve::Linear] {
            let grid = Grid {
                side: 64,
                scale: 4,
                curve,
            };
            for row in 0..grid.cells_per_side() {
                for column in 0..grid.cells_per_side() {
                    let origin = grid.origin_of(column, row);
                    assert_eq!(grid.cell_of(origin), (column, row), "{curve:?}");
                }
            }
        }
    }

    #[test]
    fn a_hilbert_cell_holds_one_contiguous_interval() {
        let grid = Grid {
            side: 64,
            scale: 4,
            curve: Curve::Hilbert,
        };
        let origin = grid.origin_of(3, 5);
        assert_eq!(origin % 16, 0);
        assert_eq!(grid.cell_of(origin + 15), (3, 5));
        assert_ne!(grid.cell_of(origin + 16), (3, 5));
    }

    #[test]
    fn zooming_keeps_the_anchor_in_place_and_stays_on_the_map() {
        let mut view = Viewport::default();
        view.zoom_at(2.0, 0.75, 0.25, 64.0);
        assert_eq!(view.zoom, 2.0);
        assert_eq!(view.world_at(0.75, 0.25), (0.75, 0.25));
        view.zoom_at(1000.0, 0.5, 0.5, 64.0);
        assert_eq!(view.zoom, 64.0);
        view.zoom_at(0.0001, 0.5, 0.5, 64.0);
        assert_eq!(view, Viewport::default());
    }

    #[test]
    fn panning_and_centering_are_clamped_to_the_map() {
        let mut view = Viewport {
            x: 0.0,
            y: 0.0,
            zoom: 4.0,
        };
        view.pan(-0.4, -0.4);
        assert_eq!((view.x, view.y), (0.1, 0.1));
        view.pan(10.0, 10.0);
        assert_eq!((view.x, view.y), (0.0, 0.0));
        view.center(1.0, 1.0);
        assert_eq!((view.x, view.y), (0.75, 0.75));
        assert!(view.contains(0.9, 0.9) && !view.contains(0.5, 0.9));
    }
}
