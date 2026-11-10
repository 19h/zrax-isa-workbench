//! Visualization pixel generation for binary entropy visualizations.
//!
//! This module contains CPU-based pixel generators for each visualization mode:
//! - Hilbert curve entropy mapping
//! - Similarity matrix (recurrence plot)
//! - Byte digraph (transition frequencies)
//! - Byte phase space (trajectory plot)
//! - Kolmogorov complexity
//! - Jensen-Shannon divergence
//! - Multi-scale entropy (RCMSE)

mod generators;

pub use generators::{
    generate_byte_phase_space_pixels, generate_computing_placeholder, generate_digraph_pixels,
    generate_hilbert_pixels, generate_hilbert_pixels_progressive, generate_jsd_pixels,
    generate_kolmogorov_pixels, generate_linear_entropy_pixels, generate_rcmse_pixels,
    generate_similarity_matrix_pixels,
};

// Re-export color utilities used by generators
pub use generators::{hsv_to_rgb, similarity_to_color};
