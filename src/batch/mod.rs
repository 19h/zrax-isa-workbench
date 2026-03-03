//! Batch classification and storage system.
//!
//! This module implements the batch ingestion pipeline described in
//! `docs/batch-store/`. It classifies binary files in parallel, writes
//! results to a local staging directory in the S3 key layout, and
//! produces ledgers, indexes, and statistics.
//!
//! # Architecture
//!
//! ```text
//!   Walker (1 thread) → Hasher Pool (j/2) → Classifier Pool (j/2) → Writer (1 thread)
//! ```
//!
//! # Usage
//!
//! ```bash
//! isa-classify batch -i /data/firmware -o /staging/run-001 -j 16
//! ```

pub mod keys;
pub mod pipeline;
pub mod routing;
pub mod slugs;
pub mod stats;
pub mod tui;
pub mod types;
pub mod writer;

pub use keys::KeyConfig;
pub use pipeline::{PipelineConfig, PipelineResult};
pub use routing::{RoutingConfig, RoutingDecision};
pub use stats::PipelineStats;
pub use types::*;
pub use writer::StagingWriter;
