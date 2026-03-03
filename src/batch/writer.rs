//! Single-threaded writer for the batch pipeline.
//!
//! The writer serializes all disk I/O to the staging directory:
//! - Binary objects
//! - Metadata sidecars
//! - View ref files
//! - Ledger buffers (flushed on rotation thresholds)
//! - Index shard buffers (flushed at end of run)
//!
//! See `docs/batch-store/04-batch-ingestion.md` Section 2.2 (Stage 4)
//! and `docs/batch-store/10-local-staging.md` for file creation semantics.

use super::keys::{staging_path, KeyConfig};
use super::slugs::{
    endianness_display, endianness_slug, format_slug, hash_fanout, isa_slug, sanitize_filename,
};
use super::types::*;
use crate::types::{ClassificationSource, Endianness, FileFormat, Isa, IsaCandidate};
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Thresholds for ledger segment rotation.
#[derive(Debug, Clone)]
pub struct LedgerRotationConfig {
    /// Max lines per ledger segment (default: 50,000).
    pub max_lines: usize,
    /// Max uncompressed bytes per ledger segment (default: 10 MB).
    pub max_bytes: usize,
}

impl Default for LedgerRotationConfig {
    fn default() -> Self {
        Self {
            max_lines: 50_000,
            max_bytes: 10 * 1024 * 1024,
        }
    }
}

/// In-memory ledger buffer for a single stream (global or per-ISA).
struct LedgerBuffer {
    /// Lines accumulated in the current segment.
    lines: Vec<String>,
    /// Approximate uncompressed byte count.
    bytes: usize,
    /// Current segment sequence number (1-based).
    sequence: u32,
    /// Key prefix path for segments (e.g., `<P>/ledgers/global/<run_id>/`).
    key_prefix: String,
}

impl LedgerBuffer {
    fn new(key_prefix: String) -> Self {
        Self {
            lines: Vec::with_capacity(1024),
            bytes: 0,
            sequence: 1,
            key_prefix,
        }
    }

    fn append(&mut self, line: String) {
        self.bytes += line.len() + 1; // +1 for newline
        self.lines.push(line);
    }

    fn should_rotate(&self, config: &LedgerRotationConfig) -> bool {
        self.lines.len() >= config.max_lines || self.bytes >= config.max_bytes
    }

    fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Flush the buffer: compress with zstd and write to staging.
    fn flush(&mut self, staging_root: &Path) -> std::io::Result<()> {
        if self.lines.is_empty() {
            return Ok(());
        }

        let key = format!("{}/{:06}.jsonl.zst", self.key_prefix, self.sequence);
        let path = staging_path(staging_root, &key);

        // Ensure parent directory
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Join lines into NDJSON
        let ndjson = self.lines.join("\n") + "\n";

        // Compress with zstd level 3
        let compressed = zstd::encode_all(ndjson.as_bytes(), 3)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Atomic write: .tmp → rename
        let tmp_path = path.with_extension("zst.tmp");
        fs::write(&tmp_path, &compressed)?;
        fs::rename(&tmp_path, &path)?;

        self.sequence += 1;
        self.lines.clear();
        self.bytes = 0;
        Ok(())
    }
}

/// The staging writer.
///
/// Receives classified results and writes all artifacts to the local staging
/// directory in the exact S3 key layout.
pub struct StagingWriter {
    /// Root of the staging directory.
    staging_root: PathBuf,
    /// Key derivation config.
    key_config: KeyConfig,
    /// Run ID for this batch.
    run_id: String,
    /// Classifier version string.
    classifier_version: String,

    /// Ledger rotation config.
    ledger_config: LedgerRotationConfig,
    /// Global ledger buffer.
    global_ledger: LedgerBuffer,
    /// Per-ISA ledger buffers (keyed by ISA slug).
    isa_ledgers: HashMap<String, LedgerBuffer>,

    /// Index shard buffers: `(ab_hex, cd_hex) → BTreeMap<sha256, IndexEntry>`.
    index_shards: HashMap<(String, String), BTreeMap<String, IndexEntry>>,

    /// Running counts for the run manifest.
    pub counts: RunCounts,
    /// Per-format counts.
    pub format_counts: HashMap<String, u64>,
    /// Per-ISA counts.
    pub isa_counts: HashMap<String, u64>,
    /// Per-status counts.
    pub status_counts: HashMap<String, u64>,
    /// Per-confidence-band counts.
    pub band_counts: HashMap<String, u64>,
    /// Total bytes stored.
    pub total_bytes_stored: u64,
    /// Error summaries.
    pub error_summaries: HashMap<String, (u64, String)>,
    /// Number of ledger segments flushed (global).
    pub ledger_segments_global: u64,
    /// Number of ledger segments flushed (ISA).
    pub ledger_segments_isa: u64,
}

impl StagingWriter {
    /// Create a new staging writer.
    pub fn new(
        staging_root: PathBuf,
        key_config: KeyConfig,
        run_id: String,
        classifier_version: String,
        ledger_config: LedgerRotationConfig,
    ) -> Self {
        let global_key_prefix = format!("{}/ledgers/global/{}", key_config.prefix, run_id);
        Self {
            staging_root,
            key_config,
            run_id,
            classifier_version,
            ledger_config,
            global_ledger: LedgerBuffer::new(global_key_prefix),
            isa_ledgers: HashMap::new(),
            index_shards: HashMap::new(),
            counts: RunCounts::default(),
            format_counts: HashMap::new(),
            isa_counts: HashMap::new(),
            status_counts: HashMap::new(),
            band_counts: HashMap::new(),
            total_bytes_stored: 0,
            error_summaries: HashMap::new(),
            ledger_segments_global: 0,
            ledger_segments_isa: 0,
        }
    }

    /// Write a classified file result to staging.
    ///
    /// This is the main entry point called by the pipeline for each processed file.
    pub fn write_result(&mut self, result: &ClassifiedFile) -> std::io::Result<()> {
        self.counts.processed += 1;

        match result.routing.status {
            RoutingStatus::Duplicate => {
                self.counts.duplicates += 1;
                *self.status_counts.entry("duplicate".into()).or_default() += 1;
                // Duplicates: only log to global ledger, no files written
                self.write_ledger_entry(result)?;
                return Ok(());
            }
            RoutingStatus::Error => {
                self.counts.errors += 1;
                *self.status_counts.entry("error".into()).or_default() += 1;
            }
            RoutingStatus::Ambiguous => {
                self.counts.ambiguous += 1;
                let reason_str = result
                    .routing
                    .ambiguous_reason
                    .map(|r| format!("ambiguous_{}", r.slug()))
                    .unwrap_or_else(|| "ambiguous".into());
                *self.status_counts.entry(reason_str).or_default() += 1;
            }
            RoutingStatus::Classified => {
                self.counts.classified += 1;
                *self.status_counts.entry("classified".into()).or_default() += 1;
            }
        }

        // Update format/ISA/band counters
        let fmt_slug = format_slug(&result.format);
        let isa_slug_str = isa_slug(&result.isa);
        let band = ConfidenceBand::from_confidence(result.confidence);
        *self.format_counts.entry(fmt_slug.clone()).or_default() += 1;
        *self.isa_counts.entry(isa_slug_str.clone()).or_default() += 1;
        let band_str = match band {
            ConfidenceBand::High => "high",
            ConfidenceBand::Medium => "medium",
            ConfidenceBand::Low => "low",
            ConfidenceBand::VeryLow => "very_low",
        };
        *self.band_counts.entry(band_str.into()).or_default() += 1;

        // 1. Write binary
        self.write_binary(result)?;

        // 2. Write metadata sidecar
        self.write_metadata(result)?;

        // 3. Write view ref
        self.write_ref(result)?;

        // 4. Append to ledger buffers
        self.write_ledger_entry(result)?;

        // 5. Add to index shard buffer
        self.add_index_entry(result);

        self.total_bytes_stored += result.file_size;

        Ok(())
    }

    /// Write the binary file to staging.
    fn write_binary(&self, result: &ClassifiedFile) -> std::io::Result<()> {
        let key = self.key_config.object_key(&result.sha256_hex);
        let path = staging_path(&self.staging_root, &key);

        // Skip if already exists (dedup: same hash = same content)
        if path.exists() {
            return Ok(());
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Atomic write
        let tmp = path.with_extension("bin.tmp");
        fs::write(&tmp, &result.data)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Write the metadata sidecar.
    fn write_metadata(&self, result: &ClassifiedFile) -> std::io::Result<()> {
        let key = self.key_config.meta_key(&result.sha256_hex);
        let path = staging_path(&self.staging_root, &key);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let sidecar = self.build_metadata_sidecar(result);
        let json = serde_json::to_string_pretty(&sidecar)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let tmp = path.with_extension("meta.json.tmp");
        fs::write(&tmp, json.as_bytes())?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Write the view ref file.
    fn write_ref(&self, result: &ClassifiedFile) -> std::io::Result<()> {
        let view_key = &result.view_key;
        let path = staging_path(&self.staging_root, view_key);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let ref_file = RefFile {
            sha256: result.sha256_hex.clone(),
            object_key: self.key_config.object_key(&result.sha256_hex),
            meta_key: self.key_config.meta_key(&result.sha256_hex),
            original_name: result.original_name.clone(),
            file_size: result.file_size,
            ingested_at: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&ref_file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let tmp = path.with_extension("ref.tmp");
        fs::write(&tmp, json.as_bytes())?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Append a ledger entry to global and ISA-specific buffers.
    fn write_ledger_entry(&mut self, result: &ClassifiedFile) -> std::io::Result<()> {
        let entry = self.build_ledger_entry(result);
        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Global ledger
        self.global_ledger.append(line.clone());
        if self.global_ledger.should_rotate(&self.ledger_config) {
            self.global_ledger.flush(&self.staging_root)?;
            self.ledger_segments_global += 1;
        }

        // ISA-specific ledger (skip for duplicates)
        if result.routing.status != RoutingStatus::Duplicate {
            let isa_slug_str = isa_slug(&result.isa);
            let isa_key_prefix = format!(
                "{}/ledgers/isa={}/{}",
                self.key_config.prefix, isa_slug_str, self.run_id
            );
            let ledger = self
                .isa_ledgers
                .entry(isa_slug_str)
                .or_insert_with(|| LedgerBuffer::new(isa_key_prefix));
            ledger.append(line);
            if ledger.should_rotate(&self.ledger_config) {
                ledger.flush(&self.staging_root)?;
                self.ledger_segments_isa += 1;
            }
        }

        Ok(())
    }

    /// Add an entry to the in-memory index shard buffer.
    fn add_index_entry(&mut self, result: &ClassifiedFile) {
        let (ab, cd) = hash_fanout(&result.sha256_hex);
        let shard_key = (ab.to_string(), cd.to_string());

        let entry = IndexEntry {
            sha256: result.sha256_hex.clone(),
            object_key: self.key_config.object_key(&result.sha256_hex),
            meta_key: self.key_config.meta_key(&result.sha256_hex),
            format: format_slug(&result.format),
            isa: isa_slug(&result.isa),
            bits: result.bitwidth,
            endian: endianness_slug(&result.endianness).to_string(),
            confidence: result.confidence,
            status: result.routing.status,
            file_size: result.file_size,
            ingested_at: Utc::now(),
        };

        self.index_shards
            .entry(shard_key)
            .or_default()
            .insert(result.sha256_hex.clone(), entry);
    }

    /// Flush all remaining buffers to disk.
    ///
    /// Called at the end of a batch run (or on graceful shutdown).
    pub fn flush_all(&mut self) -> std::io::Result<()> {
        // Flush remaining ledger buffers
        if !self.global_ledger.is_empty() {
            self.global_ledger.flush(&self.staging_root)?;
            self.ledger_segments_global += 1;
        }
        for (_, ledger) in &mut self.isa_ledgers {
            if !ledger.is_empty() {
                ledger.flush(&self.staging_root)?;
                self.ledger_segments_isa += 1;
            }
        }

        // Flush index shards (read-modify-write merge)
        self.flush_index_shards()?;

        Ok(())
    }

    /// Flush all in-memory index shard buffers to staging.
    ///
    /// Implements the merge algorithm from `docs/batch-store/10-local-staging.md` Section 5.
    fn flush_index_shards(&mut self) -> std::io::Result<()> {
        let shards = std::mem::take(&mut self.index_shards);
        for ((ab, cd), new_entries) in shards {
            let key = format!("{}/index/sha256/{}/{}.idx", self.key_config.prefix, ab, cd);
            let path = staging_path(&self.staging_root, &key);

            // Load existing shard if present
            let mut merged: BTreeMap<String, IndexEntry> = BTreeMap::new();
            if path.exists() {
                let contents = fs::read_to_string(&path)?;
                for line in contents.lines() {
                    if let Some(entry) = IndexEntry::from_tsv_line(line) {
                        merged.insert(entry.sha256.clone(), entry);
                    }
                }
            }

            // Merge new entries (new wins on collision)
            for (hash, entry) in new_entries {
                merged.insert(hash, entry);
            }

            // Write sorted shard
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("idx.tmp");
            let mut file = fs::File::create(&tmp)?;
            for (_, entry) in &merged {
                writeln!(file, "{}", entry.to_tsv_line())?;
            }
            file.flush()?;
            drop(file);
            fs::rename(&tmp, &path)?;
        }
        Ok(())
    }

    /// Write the run manifest to staging.
    pub fn write_run_manifest(&self, manifest: &RunManifest) -> std::io::Result<()> {
        let key = self.key_config.run_manifest_key(&manifest.run_id);
        let path = staging_path(&self.staging_root, &key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Write or update the stats file.
    pub fn write_stats(&self, manifest: &RunManifest) -> std::io::Result<()> {
        let key = self.key_config.stats_key();
        let path = staging_path(&self.staging_root, &key);

        // Load existing or create new
        let mut stats = if path.exists() {
            let contents = fs::read_to_string(&path)?;
            serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        } else {
            StatsFile::new()
        };

        stats.merge_run(manifest);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&stats)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(&path, json)?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Builders
    // -------------------------------------------------------------------

    fn build_metadata_sidecar(&self, result: &ClassifiedFile) -> MetadataSidecar {
        let obj_key = self.key_config.object_key(&result.sha256_hex);
        let sanitized = sanitize_filename(&result.original_name);

        let classification_source = match result.source {
            ClassificationSource::FileFormat => "file_format",
            ClassificationSource::Heuristic => "heuristic",
            ClassificationSource::Combined => "combined",
            ClassificationSource::UserSpecified => "user_specified",
        };

        let candidates: Vec<MetaCandidate> = result
            .candidates
            .iter()
            .enumerate()
            .take(10)
            .map(|(i, c)| MetaCandidate {
                rank: (i + 1) as u32,
                isa: isa_slug(&c.isa),
                isa_display: c.isa.name().to_string(),
                bitwidth: c.bitwidth,
                endianness: endianness_display(&c.endianness).to_string(),
                raw_score: c.raw_score,
                confidence: c.confidence,
            })
            .collect();

        let extensions: Vec<MetaExtension> = result
            .extensions
            .iter()
            .map(|e| MetaExtension {
                name: e.name.clone(),
                category: format!("{:?}", e.category).to_lowercase(),
                confidence: e.confidence,
                source: format!("{:?}", e.source).to_lowercase(),
            })
            .collect();

        let metadata_entries: Vec<MetaEntry> = result
            .metadata_entries
            .iter()
            .map(|m| MetaEntry {
                key: format!("{:?}", m.key).to_lowercase(),
                value: format!("{}", m.value),
                label: m.label.clone(),
            })
            .collect();

        let notes: Vec<MetaNote> = result
            .notes
            .iter()
            .map(|n| MetaNote {
                level: format!("{:?}", n.level).to_lowercase(),
                message: n.message.clone(),
                context: n.context.clone(),
            })
            .collect();

        let variant = result.variant.as_ref().map(|v| MetaVariant {
            name: v.name.clone(),
            profile: v.profile.clone(),
            abi: v.abi.clone(),
        });

        MetadataSidecar {
            schema_version: 1,
            identity: MetaIdentity {
                sha256: result.sha256_hex.clone(),
                file_size: result.file_size,
                object_key: obj_key,
            },
            names: MetaNames {
                original_names: vec![result.original_name.clone()],
                original_paths: vec![result.source_path.clone()],
                sanitized_name: sanitized,
            },
            classification: MetaClassification {
                format: format_slug(&result.format),
                format_display: format!("{}", result.format),
                format_variant: result.format_variant.clone(),
                isa: isa_slug(&result.isa),
                isa_display: result.isa.name().to_string(),
                bitwidth: result.bitwidth,
                endianness: endianness_display(&result.endianness).to_string(),
                confidence: result.confidence,
                source: classification_source.to_string(),
                variant,
            },
            candidates,
            extensions,
            metadata: metadata_entries,
            notes,
            routing: MetaRouting {
                status: result.routing.status,
                view_key: result.view_key.clone(),
                ambiguous_reason: result.routing.ambiguous_reason,
                confidence_band: result.routing.confidence_band,
            },
            provenance: MetaProvenance {
                run_id: self.run_id.clone(),
                classifier_version: self.classifier_version.clone(),
                ingested_at: Utc::now(),
                source_path: result.source_path.clone(),
                reclassified_count: 0,
                previous_classifications: vec![],
            },
        }
    }

    fn build_ledger_entry(&self, result: &ClassifiedFile) -> LedgerEntry {
        let runner_up = result.candidates.get(1).map(|c| isa_slug(&c.isa));
        let margin = if let Some(second) = result.candidates.get(1) {
            if second.raw_score > 0 {
                let first_score = result.candidates.first().map(|c| c.raw_score).unwrap_or(0);
                (first_score - second.raw_score) as f64 / second.raw_score as f64
            } else {
                1.0
            }
        } else {
            1.0
        };

        let ext_names: Vec<String> = result.extensions.iter().map(|e| e.name.clone()).collect();

        let action = match result.routing.status {
            RoutingStatus::Duplicate => LedgerAction::Duplicate,
            _ => LedgerAction::Ingest,
        };

        LedgerEntry {
            ts: Utc::now(),
            run: self.run_id.clone(),
            sha256: result.sha256_hex.clone(),
            size: result.file_size,
            fmt: format_slug(&result.format),
            isa: isa_slug(&result.isa),
            bits: result.bitwidth,
            endian: endianness_slug(&result.endianness).to_string(),
            conf: result.confidence,
            src: match result.source {
                ClassificationSource::FileFormat => "file_format".into(),
                ClassificationSource::Heuristic => "heuristic".into(),
                ClassificationSource::Combined => "combined".into(),
                ClassificationSource::UserSpecified => "user_specified".into(),
            },
            status: result.routing.status,
            amb_reason: result.routing.ambiguous_reason,
            margin,
            runner_up,
            orig_name: result.original_name.clone(),
            orig_path: result.source_path.clone(),
            obj_key: self.key_config.object_key(&result.sha256_hex),
            meta_key: self.key_config.meta_key(&result.sha256_hex),
            view_key: result.view_key.clone(),
            ext: ext_names,
            cv: self.classifier_version.clone(),
            action,
        }
    }
}

// ---------------------------------------------------------------------------
// ClassifiedFile — the message type passed from classifier → writer
// ---------------------------------------------------------------------------

/// A fully classified file ready to be written to staging.
///
/// This is the message type sent from the classifier pool to the writer thread.
pub struct ClassifiedFile {
    /// SHA-256 hex digest (64 lowercase hex chars).
    pub sha256_hex: String,
    /// Raw file data.
    pub data: Vec<u8>,
    /// File size in bytes.
    pub file_size: u64,
    /// Original filename (basename).
    pub original_name: String,
    /// Full original source path.
    pub source_path: String,

    // Classification results
    pub format: FileFormat,
    pub format_variant: Option<String>,
    pub isa: Isa,
    pub bitwidth: u8,
    pub endianness: Endianness,
    pub confidence: f64,
    pub source: ClassificationSource,
    pub variant: Option<crate::types::Variant>,
    pub candidates: Vec<IsaCandidate>,
    pub extensions: Vec<crate::types::ExtensionDetection>,
    pub metadata_entries: Vec<crate::types::MetadataEntry>,
    pub notes: Vec<crate::types::Note>,

    // Routing
    pub routing: super::routing::RoutingDecision,
    /// Pre-computed view key.
    pub view_key: String,
}
