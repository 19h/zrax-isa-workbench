//! Multi-stage concurrent batch ingestion pipeline.
//!
//! Architecture (from `docs/batch-store/04-batch-ingestion.md` Section 2):
//!
//! ```text
//!   Walker (1 thread) → Hasher Pool (j/2) → Classifier Pool (j/2) → Writer (1 thread)
//! ```
//!
//! All stages communicate via bounded crossbeam channels.

use super::keys::KeyConfig;
use super::routing::{route, RoutingConfig, RoutingDecision, RoutingInput};
use super::stats::PipelineStats;
use super::types::*;
use super::writer::{ClassifiedFile, LedgerRotationConfig, StagingWriter};
use crate::detect_payload;
use crate::types::{ClassificationSource, ClassifierOptions, Endianness, FileFormat, Isa};
use chrono::Utc;
use crossbeam_channel::{bounded, Receiver, Sender};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Pipeline messages
// ---------------------------------------------------------------------------

/// Message from walker → hasher.
struct WalkItem {
    path: PathBuf,
    file_size: u64,
}

/// Message from hasher → classifier.
struct HashedItem {
    path: PathBuf,
    sha256_hex: String,
    data: Vec<u8>,
    file_size: u64,
}

// ---------------------------------------------------------------------------
// Pipeline configuration
// ---------------------------------------------------------------------------

/// Complete batch pipeline configuration.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Input directory to scan.
    pub input_dir: PathBuf,
    /// Output staging directory.
    pub staging_dir: PathBuf,
    /// S3 key prefix.
    pub prefix: String,
    /// Number of total worker threads.
    pub jobs: usize,
    /// Minimum file size to process (bytes).
    pub min_file_size: u64,
    /// Maximum file size to process (bytes).
    pub max_file_size: u64,
    /// Follow symbolic links.
    pub follow_symlinks: bool,
    /// Run ID.
    pub run_id: String,
    /// Classifier options.
    pub classifier_options: ClassifierOptions,
    /// Routing configuration.
    pub routing_config: RoutingConfig,
    /// Ledger rotation configuration.
    pub ledger_config: LedgerRotationConfig,
    /// Whether to skip files whose hash exists in local index shards.
    pub skip_existing: bool,
    /// Enable deep scan mode.
    pub deep_scan: bool,
    /// Enable extension detection.
    pub detect_extensions: bool,
}

impl PipelineConfig {
    /// Generate a default run ID based on current time.
    pub fn generate_run_id() -> String {
        let now = Utc::now();
        format!("{}-batch-001", now.format("%Y%m%dT%H%M%SZ"))
    }
}

// ---------------------------------------------------------------------------
// Pipeline execution
// ---------------------------------------------------------------------------

/// Result returned when the pipeline completes.
pub struct PipelineResult {
    pub run_manifest: RunManifest,
    pub stats: PipelineStats,
}

/// Run the batch ingestion pipeline.
///
/// This is the main entry point for `isa-classify batch`.
pub fn run_pipeline(
    config: PipelineConfig,
    stats: Arc<PipelineStats>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<PipelineResult> {
    let started_at = Utc::now();

    let key_config = KeyConfig::new(&config.prefix);
    let classifier_version = crate::version().to_string();

    // Compute thread allocation: hasher gets j/2 (min 1), classifier gets j/2 (min 1)
    let hasher_threads = (config.jobs / 2).max(1);
    let classifier_threads = (config.jobs - hasher_threads).max(1);

    // Channel capacities (from spec: Section 2.3)
    let walker_to_hasher_cap = 2 * config.jobs;
    let hasher_to_classifier_cap = 2 * config.jobs;
    let classifier_to_writer_cap = 4 * config.jobs;

    let (walk_tx, walk_rx): (Sender<WalkItem>, Receiver<WalkItem>) = bounded(walker_to_hasher_cap);
    let (hash_tx, hash_rx): (Sender<HashedItem>, Receiver<HashedItem>) =
        bounded(hasher_to_classifier_cap);
    let (class_tx, class_rx): (Sender<ClassifiedFile>, Receiver<ClassifiedFile>) =
        bounded(classifier_to_writer_cap);

    let _shutdown_clone = shutdown.clone();
    let _stats_clone = stats.clone();

    // ---------------------------------------------------------------
    // Stage 1: Walker (1 thread)
    // ---------------------------------------------------------------
    let walker_config = config.clone();
    let walker_shutdown = shutdown.clone();
    let walker_stats = stats.clone();
    let walker_handle = thread::Builder::new()
        .name("walker".into())
        .spawn(move || {
            let walker = WalkDir::new(&walker_config.input_dir)
                .follow_links(walker_config.follow_symlinks)
                .min_depth(1);

            for entry in walker {
                if walker_shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        walker_stats.errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("Walk error: {}", e);
                        continue;
                    }
                };

                if !entry.file_type().is_file() {
                    continue;
                }

                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        walker_stats.errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("Metadata error: {}: {}", entry.path().display(), e);
                        continue;
                    }
                };

                let file_size = metadata.len();

                // Size filters
                if file_size < walker_config.min_file_size {
                    walker_stats.skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if file_size > walker_config.max_file_size {
                    walker_stats.skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                walker_stats
                    .discovered_files
                    .fetch_add(1, Ordering::Relaxed);
                walker_stats
                    .discovered_bytes
                    .fetch_add(file_size, Ordering::Relaxed);

                if walk_tx
                    .send(WalkItem {
                        path: entry.into_path(),
                        file_size,
                    })
                    .is_err()
                {
                    break; // Receiver dropped
                }
            }
            drop(walk_tx);
        })?;

    // ---------------------------------------------------------------
    // Stage 2: Hasher Pool (j/2 threads)
    // ---------------------------------------------------------------
    let mut hasher_handles = Vec::with_capacity(hasher_threads);
    for i in 0..hasher_threads {
        let rx = walk_rx.clone();
        let tx = hash_tx.clone();
        let sd = shutdown.clone();
        let st = stats.clone();

        let handle = thread::Builder::new()
            .name(format!("hasher-{}", i))
            .spawn(move || {
                while let Ok(item) = rx.recv() {
                    if sd.load(Ordering::Relaxed) {
                        break;
                    }

                    // Read file
                    let data = match std::fs::read(&item.path) {
                        Ok(d) => d,
                        Err(e) => {
                            st.errors.fetch_add(1, Ordering::Relaxed);
                            eprintln!("Read error: {}: {}", item.path.display(), e);
                            continue;
                        }
                    };

                    // Compute SHA-256
                    let mut hasher = Sha256::new();
                    hasher.update(&data);
                    let hash = hasher.finalize();
                    let sha256_hex = hex::encode(hash);

                    st.hashed_files.fetch_add(1, Ordering::Relaxed);
                    st.hashed_bytes.fetch_add(item.file_size, Ordering::Relaxed);

                    if tx
                        .send(HashedItem {
                            path: item.path,
                            sha256_hex,
                            data,
                            file_size: item.file_size,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        hasher_handles.push(handle);
    }
    // Drop the extra sender clone so the channel closes when all hashers finish
    drop(walk_rx);
    drop(hash_tx);

    // ---------------------------------------------------------------
    // Stage 3: Classifier Pool (j/2 threads)
    // ---------------------------------------------------------------
    let mut classifier_handles = Vec::with_capacity(classifier_threads);
    for i in 0..classifier_threads {
        let rx = hash_rx.clone();
        let tx = class_tx.clone();
        let sd = shutdown.clone();
        let st = stats.clone();
        let opts = config.classifier_options.clone();
        let routing_cfg = config.routing_config.clone();
        let key_cfg = key_config.clone();

        let handle = thread::Builder::new()
            .name(format!("classifier-{}", i))
            .spawn(move || {
                while let Ok(item) = rx.recv() {
                    if sd.load(Ordering::Relaxed) {
                        break;
                    }

                    let original_name = item
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unnamed")
                        .to_string();
                    let source_path = item.path.display().to_string();

                    // Run classification
                    let payload = match detect_payload(&item.data, &opts) {
                        Ok(p) => p,
                        Err(e) => {
                            st.errors.fetch_add(1, Ordering::Relaxed);
                            // Build an error result
                            let routing = RoutingDecision {
                                status: RoutingStatus::Ambiguous,
                                ambiguous_reason: Some(AmbiguousReason::Error),
                                confidence_band: ConfidenceBand::VeryLow,
                            };
                            let view_key = key_cfg.ambiguous_view_key(
                                &item.sha256_hex,
                                AmbiguousReason::Error,
                                &FileFormat::Raw,
                                &original_name,
                            );
                            let result = ClassifiedFile {
                                sha256_hex: item.sha256_hex,
                                data: item.data,
                                file_size: item.file_size,
                                original_name,
                                source_path,
                                format: FileFormat::Raw,
                                format_variant: None,
                                isa: Isa::Unknown(0),
                                bitwidth: 0,
                                endianness: Endianness::Little,
                                confidence: 0.0,
                                source: ClassificationSource::Heuristic,
                                variant: None,
                                candidates: vec![],
                                extensions: vec![],
                                metadata_entries: vec![],
                                notes: vec![crate::types::Note {
                                    level: crate::types::NoteLevel::Error,
                                    message: format!("Classification error: {}", e),
                                    context: None,
                                }],
                                routing,
                                view_key,
                            };
                            let _ = tx.send(result);
                            continue;
                        }
                    };

                    // Extract classification details
                    let format = payload.format.format;
                    let format_variant = payload.format.variant_name.clone();
                    let isa = payload.primary.isa;
                    let bitwidth = payload.primary.bitwidth;
                    let endianness = payload.primary.endianness;
                    let confidence = payload.primary.confidence;
                    let source = payload.primary.source;
                    let variant = payload.primary.variant.clone();

                    // Get runner-up score for margin calculation
                    let winner_score = payload.candidates.first().map(|c| c.raw_score).unwrap_or(0);
                    let runner_up_score =
                        payload.candidates.get(1).map(|c| c.raw_score).unwrap_or(0);

                    // Make routing decision
                    let routing_input = RoutingInput {
                        is_error: false,
                        isa: &isa,
                        confidence,
                        winner_score,
                        runner_up_score,
                    };
                    let routing = route(&routing_cfg, &routing_input);

                    // Compute view key based on routing
                    let view_key = match routing.status {
                        RoutingStatus::Classified => key_cfg.classified_view_key(
                            &item.sha256_hex,
                            &format,
                            &isa,
                            bitwidth,
                            &endianness,
                            &original_name,
                        ),
                        RoutingStatus::Ambiguous => {
                            let reason =
                                routing.ambiguous_reason.unwrap_or(AmbiguousReason::LowConf);
                            key_cfg.ambiguous_view_key(
                                &item.sha256_hex,
                                reason,
                                &format,
                                &original_name,
                            )
                        }
                        _ => key_cfg.classified_view_key(
                            &item.sha256_hex,
                            &format,
                            &isa,
                            bitwidth,
                            &endianness,
                            &original_name,
                        ),
                    };

                    st.classified_files.fetch_add(1, Ordering::Relaxed);

                    let result = ClassifiedFile {
                        sha256_hex: item.sha256_hex,
                        data: item.data,
                        file_size: item.file_size,
                        original_name,
                        source_path,
                        format,
                        format_variant,
                        isa,
                        bitwidth,
                        endianness,
                        confidence,
                        source,
                        variant,
                        candidates: payload.candidates,
                        extensions: payload.extensions,
                        metadata_entries: payload.metadata,
                        notes: payload.notes,
                        routing,
                        view_key,
                    };

                    if tx.send(result).is_err() {
                        break;
                    }
                }
            })?;
        classifier_handles.push(handle);
    }
    drop(hash_rx);
    drop(class_tx);

    // ---------------------------------------------------------------
    // Stage 4: Writer (current thread — runs synchronously)
    // ---------------------------------------------------------------
    let mut writer = StagingWriter::new(
        config.staging_dir.clone(),
        key_config.clone(),
        config.run_id.clone(),
        classifier_version.clone(),
        config.ledger_config.clone(),
    );

    while let Ok(result) = class_rx.recv() {
        if shutdown.load(Ordering::Relaxed) {
            // Graceful shutdown: finish what we have, then stop
            if let Err(e) = writer.write_result(&result) {
                eprintln!("Writer error: {}", e);
            }
            break;
        }
        if let Err(e) = writer.write_result(&result) {
            eprintln!("Writer error: {}", e);
            stats.errors.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.written_files.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Drain any remaining items after shutdown signal
    for result in class_rx.try_iter() {
        if let Err(e) = writer.write_result(&result) {
            eprintln!("Writer error (drain): {}", e);
        } else {
            stats.written_files.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Wait for all pipeline threads to finish
    let _ = walker_handle.join();
    for h in hasher_handles {
        let _ = h.join();
    }
    for h in classifier_handles {
        let _ = h.join();
    }

    // Flush remaining buffers
    writer.flush_all()?;

    let completed_at = Utc::now();
    let duration = (completed_at - started_at).num_milliseconds() as f64 / 1000.0;
    let files_per_second = if duration > 0.0 {
        writer.counts.processed as f64 / duration
    } else {
        0.0
    };
    let bytes_per_second = if duration > 0.0 {
        writer.total_bytes_stored as f64 / duration
    } else {
        0.0
    };

    // Build run manifest
    let manifest = RunManifest {
        schema_version: 1,
        run_id: config.run_id.clone(),
        run_type: "batch".to_string(),
        status: if shutdown.load(Ordering::Relaxed) {
            RunStatus::Cancelled
        } else if writer.counts.errors > 0 && writer.counts.classified == 0 {
            RunStatus::Failed
        } else {
            RunStatus::Completed
        },
        parameters: RunParameters {
            input_path: config.input_dir.display().to_string(),
            staging_path: config.staging_dir.display().to_string(),
            prefix: config.prefix.clone(),
            jobs: config.jobs,
            min_confidence: config.routing_config.min_confidence,
            min_margin: config.routing_config.min_margin,
            classifier_version: classifier_version.clone(),
            deep_scan: config.deep_scan,
            detect_extensions: config.detect_extensions,
        },
        timing: RunTiming {
            started_at,
            completed_at: Some(completed_at),
            duration_seconds: duration,
            files_per_second,
            bytes_per_second,
        },
        counts: writer.counts.clone(),
        storage: RunStorage {
            total_bytes_ingested: stats.discovered_bytes.load(Ordering::Relaxed),
            total_bytes_stored: writer.total_bytes_stored,
            bytes_saved_by_dedup: 0, // TODO: track dedup savings
            objects_created: writer.counts.classified + writer.counts.ambiguous,
            metadata_files_created: writer.counts.classified + writer.counts.ambiguous,
            ref_files_created: writer.counts.classified + writer.counts.ambiguous,
            ledger_segments_global: writer.ledger_segments_global,
            ledger_segments_isa: writer.ledger_segments_isa,
            index_shards_updated: 0, // Set below
        },
        breakdown_by_status: writer.status_counts.clone(),
        breakdown_by_format: writer.format_counts.clone(),
        breakdown_by_isa: writer.isa_counts.clone(),
        errors_summary: writer
            .error_summaries
            .iter()
            .map(|(k, (count, example))| ErrorSummary {
                error_type: k.clone(),
                count: *count,
                example: example.clone(),
            })
            .collect(),
    };

    // Write run manifest and stats
    writer.write_run_manifest(&manifest)?;
    writer.write_stats(&manifest)?;

    Ok(PipelineResult {
        run_manifest: manifest,
        stats: Arc::try_unwrap(stats).unwrap_or_else(|arc| (*arc).clone()),
    })
}
