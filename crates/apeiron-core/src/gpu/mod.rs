//! GPU-accelerated visualization rendering using wgpu compute shaders.
//!
//! This module provides hardware-accelerated rendering for binary visualizations
//! using compute shaders. It handles:
//! - Device and pipeline management
//! - File data upload to GPU buffers
//! - Compute shader dispatch for different visualization modes
//! - Texture readback for display

mod renderer;

pub use renderer::{GpuRenderer, GpuVizMode};
