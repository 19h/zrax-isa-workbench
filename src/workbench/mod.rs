//! Workbench analysis using the vendored Apeiron kernels: the resident
//! [`Engine`] behind the browser and desktop workbenches.
//!
//! The engine is plain Rust (`workbench` feature). The `wasm` feature adds
//! the `wasm-bindgen` classes the browser workers call: `wasm` wraps the
//! engine, `scan` streams string and certificate scans.

// Apeiron is vendored as published (see `apeiron/README.md` and its
// LICENSE). Its lookup tables and SIMD loops use unchecked indexing, so the
// crate's `deny(unsafe_code)` is lifted for this module only.
#[allow(dead_code, missing_docs, unsafe_code)]
mod apeiron {
    pub mod byte;
    pub mod entropy;
    pub mod hilbert;
}

mod engine;

#[cfg(feature = "wasm")]
mod scan;
#[cfg(feature = "wasm")]
mod wasm;

pub use engine::{
    hilbert_distance, hilbert_indices, hilbert_point, Curve, Engine, Inspection, Patch,
    CELL_VALUES, HOLE_ENTROPY, MAX_CELLS_PER_CALL, MAX_MAP_SIDE, MAX_PERMUTATION_SIDE,
    MAX_PROFILE_POINTS, MAX_WINDOW_BYTES,
};
