//! Hilbert curve algorithms and progressive rendering.
//!
//! This module provides:
//! - Core Hilbert curve coordinate transformation algorithms
//! - Progressive Hilbert entropy computation for large files

pub mod curve;
pub mod refiner;

pub use curve::{calculate_dimension, d2xy, xy2d};
pub use refiner::{
    entropy_to_color, entropy_to_color_preview, placeholder_pulse_color, HilbertBuffer,
    HilbertRefiner, FINE_SAMPLE_INTERVAL, PROGRESSIVE_THRESHOLD,
};
