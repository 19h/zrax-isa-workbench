//! Analysis algorithms for binary data inspection.
//!
//! This module provides comprehensive analysis utilities:
//! - Shannon entropy calculation
//! - Kolmogorov complexity approximation
//! - Jensen-Shannon divergence
//! - Refined Composite Multi-Scale Entropy (RCMSE)
//! - Haar wavelet transform and entropy analysis
//! - Byte-level forensic analysis

pub mod byte;
pub mod entropy;
pub mod jsd;
pub mod kolmogorov;
pub mod rcmse;
pub mod wavelet;

// Re-export commonly used items
pub use byte::{identify_file_type, ByteAnalysis};
pub use entropy::{
    byte_distribution, byte_distribution_sampled, calculate_entropy, chunk_entropy_fast,
    extract_ascii, precompute_chunk_entropies, ANALYSIS_WINDOW,
};
pub use jsd::{calculate_jsd, jensen_shannon_divergence, JSDAnalysis};
pub use kolmogorov::{calculate_kolmogorov_complexity, KolmogorovAnalysis};
pub use rcmse::{calculate_rcmse, calculate_rcmse_quick, RCMSEAnalysis, RCMSEClassification};
pub use wavelet::{
    calculate_wavelet_suspiciousness, compute_entropy_stream, haar_wavelet_transform,
    wavelet_energy_spectrum, wavelet_suspiciousness_8, WaveletAnalysis, WAVELET_CHUNK_SIZE,
};
