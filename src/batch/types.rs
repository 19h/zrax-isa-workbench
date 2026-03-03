//! Data structures for the batch store system.
//!
//! These types map directly to the JSON/TSV schemas defined in
//! `docs/batch-store/03-schemas.md`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Routing status for a classified file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStatus {
    Classified,
    Ambiguous,
    Duplicate,
    Error,
}

/// Reason code for ambiguous routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguousReason {
    /// Primary ISA confidence below threshold.
    LowConf,
    /// Winner's margin over runner-up below threshold.
    LowMargin,
    /// Classification engine returned an error.
    Error,
    /// Detected ISA is `Unknown(n)`.
    UnknownIsa,
}

impl AmbiguousReason {
    /// Slug for S3 key paths.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::LowConf => "low_conf",
            Self::LowMargin => "low_margin",
            Self::Error => "error",
            Self::UnknownIsa => "unknown_isa",
        }
    }
}

/// Confidence band for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    /// >= 0.80
    High,
    /// 0.50 - 0.79
    Medium,
    /// 0.30 - 0.49
    Low,
    /// < 0.30
    VeryLow,
}

impl ConfidenceBand {
    /// Determine the confidence band for a given confidence score.
    pub fn from_confidence(confidence: f64) -> Self {
        if confidence >= 0.80 {
            Self::High
        } else if confidence >= 0.50 {
            Self::Medium
        } else if confidence >= 0.30 {
            Self::Low
        } else {
            Self::VeryLow
        }
    }
}

// ---------------------------------------------------------------------------
// Ledger action
// ---------------------------------------------------------------------------

/// Action type for ledger entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerAction {
    Ingest,
    Reclassify,
    Delete,
    Duplicate,
}

// ---------------------------------------------------------------------------
// Metadata Sidecar (.meta.json)
// ---------------------------------------------------------------------------

/// Complete metadata sidecar stored alongside each binary object.
///
/// Schema: `docs/batch-store/03-schemas.md` Section 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSidecar {
    pub schema_version: u32,
    pub identity: MetaIdentity,
    pub names: MetaNames,
    pub classification: MetaClassification,
    pub candidates: Vec<MetaCandidate>,
    pub extensions: Vec<MetaExtension>,
    pub metadata: Vec<MetaEntry>,
    pub notes: Vec<MetaNote>,
    pub routing: MetaRouting,
    pub provenance: MetaProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaIdentity {
    pub sha256: String,
    pub file_size: u64,
    pub object_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaNames {
    pub original_names: Vec<String>,
    pub original_paths: Vec<String>,
    pub sanitized_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaClassification {
    pub format: String,
    pub format_display: String,
    pub format_variant: Option<String>,
    pub isa: String,
    pub isa_display: String,
    pub bitwidth: u8,
    pub endianness: String,
    pub confidence: f64,
    pub source: String,
    pub variant: Option<MetaVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaVariant {
    pub name: String,
    pub profile: Option<String>,
    pub abi: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaCandidate {
    pub rank: u32,
    pub isa: String,
    pub isa_display: String,
    pub bitwidth: u8,
    pub endianness: String,
    pub raw_score: i64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaExtension {
    pub name: String,
    pub category: String,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaEntry {
    pub key: String,
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaNote {
    pub level: String,
    pub message: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRouting {
    pub status: RoutingStatus,
    pub view_key: String,
    pub ambiguous_reason: Option<AmbiguousReason>,
    pub confidence_band: ConfidenceBand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaProvenance {
    pub run_id: String,
    pub classifier_version: String,
    pub ingested_at: DateTime<Utc>,
    pub source_path: String,
    pub reclassified_count: u32,
    pub previous_classifications: Vec<PreviousClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousClassification {
    pub isa: String,
    pub confidence: f64,
    pub classifier_version: String,
    pub reclassified_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Ledger Entry (NDJSON line)
// ---------------------------------------------------------------------------

/// A single ledger entry (one line in an NDJSON ledger segment).
///
/// Schema: `docs/batch-store/03-schemas.md` Section 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub ts: DateTime<Utc>,
    pub run: String,
    pub sha256: String,
    pub size: u64,
    pub fmt: String,
    pub isa: String,
    pub bits: u8,
    pub endian: String,
    pub conf: f64,
    pub src: String,
    pub status: RoutingStatus,
    pub amb_reason: Option<AmbiguousReason>,
    pub margin: f64,
    pub runner_up: Option<String>,
    pub orig_name: String,
    pub orig_path: String,
    pub obj_key: String,
    pub meta_key: String,
    pub view_key: String,
    pub ext: Vec<String>,
    pub cv: String,
    pub action: LedgerAction,
}

// ---------------------------------------------------------------------------
// Ref File (.ref)
// ---------------------------------------------------------------------------

/// Lightweight pointer file stored in the view tree.
///
/// Schema: `docs/batch-store/03-schemas.md` Section 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefFile {
    pub sha256: String,
    pub object_key: String,
    pub meta_key: String,
    pub original_name: String,
    pub file_size: u64,
    pub ingested_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Index Shard Entry (TSV line)
// ---------------------------------------------------------------------------

/// A single entry in a TSV index shard.
///
/// Schema: `docs/batch-store/03-schemas.md` Section 3.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub sha256: String,
    pub object_key: String,
    pub meta_key: String,
    pub format: String,
    pub isa: String,
    pub bits: u8,
    pub endian: String,
    pub confidence: f64,
    pub status: RoutingStatus,
    pub file_size: u64,
    pub ingested_at: DateTime<Utc>,
}

impl IndexEntry {
    /// Serialize to TSV line (no trailing newline).
    pub fn to_tsv_line(&self) -> String {
        let status_str = match self.status {
            RoutingStatus::Classified => "classified",
            RoutingStatus::Ambiguous => "ambiguous",
            RoutingStatus::Error => "error",
            RoutingStatus::Duplicate => "duplicate",
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}",
            self.sha256,
            self.object_key,
            self.meta_key,
            self.format,
            self.isa,
            self.bits,
            self.endian,
            self.confidence,
            status_str,
            self.file_size,
            self.ingested_at.to_rfc3339(),
        )
    }

    /// Parse from a TSV line.
    pub fn from_tsv_line(line: &str) -> Option<Self> {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 11 {
            return None;
        }
        let status = match fields[8] {
            "classified" => RoutingStatus::Classified,
            "ambiguous" => RoutingStatus::Ambiguous,
            "error" => RoutingStatus::Error,
            "duplicate" => RoutingStatus::Duplicate,
            _ => return None,
        };
        Some(IndexEntry {
            sha256: fields[0].to_string(),
            object_key: fields[1].to_string(),
            meta_key: fields[2].to_string(),
            format: fields[3].to_string(),
            isa: fields[4].to_string(),
            bits: fields[5].parse().ok()?,
            endian: fields[6].to_string(),
            confidence: fields[7].parse().ok()?,
            status,
            file_size: fields[9].parse().ok()?,
            ingested_at: fields[10].parse().ok()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Run Manifest
// ---------------------------------------------------------------------------

/// Run manifest stored at `runs/<run_id>.json`.
///
/// Schema: `docs/batch-store/03-schemas.md` Section 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: u32,
    pub run_id: String,
    #[serde(rename = "type")]
    pub run_type: String,
    pub status: RunStatus,
    pub parameters: RunParameters,
    pub timing: RunTiming,
    pub counts: RunCounts,
    pub storage: RunStorage,
    pub breakdown_by_status: HashMap<String, u64>,
    pub breakdown_by_format: HashMap<String, u64>,
    pub breakdown_by_isa: HashMap<String, u64>,
    pub errors_summary: Vec<ErrorSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunParameters {
    pub input_path: String,
    pub staging_path: String,
    pub prefix: String,
    pub jobs: usize,
    pub min_confidence: f64,
    pub min_margin: f64,
    pub classifier_version: String,
    pub deep_scan: bool,
    pub detect_extensions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTiming {
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: f64,
    pub files_per_second: f64,
    pub bytes_per_second: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunCounts {
    pub total_input_files: u64,
    pub processed: u64,
    pub classified: u64,
    pub ambiguous: u64,
    pub duplicates: u64,
    pub errors: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunStorage {
    pub total_bytes_ingested: u64,
    pub total_bytes_stored: u64,
    pub bytes_saved_by_dedup: u64,
    pub objects_created: u64,
    pub metadata_files_created: u64,
    pub ref_files_created: u64,
    pub ledger_segments_global: u64,
    pub ledger_segments_isa: u64,
    pub index_shards_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummary {
    pub error_type: String,
    pub count: u64,
    pub example: String,
}

// ---------------------------------------------------------------------------
// Statistics File
// ---------------------------------------------------------------------------

/// Aggregate statistics stored at `stats/current.json`.
///
/// Schema: `docs/batch-store/03-schemas.md` Section 6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsFile {
    pub schema_version: u32,
    pub last_updated: DateTime<Utc>,
    pub last_run_id: String,
    pub totals: StatsTotals,
    pub by_format: HashMap<String, StatsCount>,
    pub by_isa: HashMap<String, StatsCount>,
    pub by_status: HashMap<String, u64>,
    pub by_confidence_band: HashMap<String, u64>,
    pub runs_completed: u64,
    pub last_10_runs: Vec<StatsRunSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsTotals {
    pub files: u64,
    pub bytes: u64,
    pub classified: u64,
    pub ambiguous: u64,
    pub errors: u64,
    pub unique_isas: u64,
    pub unique_formats: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsCount {
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsRunSummary {
    pub run_id: String,
    #[serde(rename = "type")]
    pub run_type: String,
    pub files: u64,
    pub duration_seconds: f64,
    pub completed_at: DateTime<Utc>,
}

impl StatsFile {
    /// Create a new empty stats file.
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            last_updated: Utc::now(),
            last_run_id: String::new(),
            totals: StatsTotals::default(),
            by_format: HashMap::new(),
            by_isa: HashMap::new(),
            by_status: HashMap::new(),
            by_confidence_band: HashMap::new(),
            runs_completed: 0,
            last_10_runs: Vec::new(),
        }
    }

    /// Merge counts from a completed run manifest into this stats file.
    pub fn merge_run(&mut self, manifest: &RunManifest) {
        self.last_updated = Utc::now();
        self.last_run_id = manifest.run_id.clone();
        self.runs_completed += 1;

        self.totals.files += manifest.counts.classified + manifest.counts.ambiguous;
        self.totals.bytes += manifest.storage.total_bytes_stored;
        self.totals.classified += manifest.counts.classified;
        self.totals.ambiguous += manifest.counts.ambiguous;
        self.totals.errors += manifest.counts.errors;

        for (fmt, count) in &manifest.breakdown_by_format {
            let entry = self.by_format.entry(fmt.clone()).or_default();
            entry.count += count;
        }
        for (isa, count) in &manifest.breakdown_by_isa {
            let entry = self.by_isa.entry(isa.clone()).or_default();
            entry.count += count;
        }
        for (status, count) in &manifest.breakdown_by_status {
            *self.by_status.entry(status.clone()).or_default() += count;
        }

        self.totals.unique_isas = self.by_isa.len() as u64;
        self.totals.unique_formats = self.by_format.len() as u64;

        // Add to last_10_runs
        if let Some(completed_at) = manifest.timing.completed_at {
            self.last_10_runs.push(StatsRunSummary {
                run_id: manifest.run_id.clone(),
                run_type: manifest.run_type.clone(),
                files: manifest.counts.processed,
                duration_seconds: manifest.timing.duration_seconds,
                completed_at,
            });
            // Keep only last 10
            if self.last_10_runs.len() > 10 {
                self.last_10_runs.remove(0);
            }
        }
    }
}
