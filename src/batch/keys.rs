//! S3 key derivation for all storage paths.
//!
//! Every key is deterministically computable from known inputs.
//! See `docs/batch-store/02-s3-key-layout.md` for the complete specification.

use super::slugs::{endianness_slug, format_slug, hash_fanout, isa_slug, sanitize_filename};
use super::types::AmbiguousReason;
use crate::types::{Endianness, FileFormat, Isa};

/// Configuration for key derivation.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// Root prefix for all keys (e.g., `isa-harvester/v1`).
    pub prefix: String,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            prefix: "isa-harvester/v1".to_string(),
        }
    }
}

impl KeyConfig {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    // -------------------------------------------------------------------
    // Objects
    // -------------------------------------------------------------------

    /// Binary object key: `<P>/objects/sha256/<ab>/<cd>/<hash>.bin`
    pub fn object_key(&self, sha256_hex: &str) -> String {
        let (ab, cd) = hash_fanout(sha256_hex);
        format!(
            "{}/objects/sha256/{}/{}/{}.bin",
            self.prefix, ab, cd, sha256_hex
        )
    }

    /// Metadata sidecar key: `<P>/objects/sha256/<ab>/<cd>/<hash>.meta.json`
    pub fn meta_key(&self, sha256_hex: &str) -> String {
        let (ab, cd) = hash_fanout(sha256_hex);
        format!(
            "{}/objects/sha256/{}/{}/{}.meta.json",
            self.prefix, ab, cd, sha256_hex
        )
    }

    // -------------------------------------------------------------------
    // Views — Classified
    // -------------------------------------------------------------------

    /// Classified view ref key.
    ///
    /// `<P>/views/classified/fmt=<f>/isa=<i>/bits=<b>/endian=<e>/<ab>/<cd>/<hash>__<name>.ref`
    pub fn classified_view_key(
        &self,
        sha256_hex: &str,
        format: &FileFormat,
        isa: &Isa,
        bitwidth: u8,
        endianness: &Endianness,
        original_name: &str,
    ) -> String {
        let (ab, cd) = hash_fanout(sha256_hex);
        let name = sanitize_filename(original_name);
        format!(
            "{}/views/classified/fmt={}/isa={}/bits={}/endian={}/{}/{}/{}__{}.ref",
            self.prefix,
            format_slug(format),
            isa_slug(isa),
            bitwidth,
            endianness_slug(endianness),
            ab,
            cd,
            sha256_hex,
            name,
        )
    }

    // -------------------------------------------------------------------
    // Views — Ambiguous
    // -------------------------------------------------------------------

    /// Ambiguous view ref key.
    ///
    /// `<P>/views/ambiguous/reason=<r>/fmt=<f>/<ab>/<cd>/<hash>__<name>.ref`
    pub fn ambiguous_view_key(
        &self,
        sha256_hex: &str,
        reason: AmbiguousReason,
        format: &FileFormat,
        original_name: &str,
    ) -> String {
        let (ab, cd) = hash_fanout(sha256_hex);
        let name = sanitize_filename(original_name);
        format!(
            "{}/views/ambiguous/reason={}/fmt={}/{}/{}/{}__{}.ref",
            self.prefix,
            reason.slug(),
            format_slug(format),
            ab,
            cd,
            sha256_hex,
            name,
        )
    }

    // -------------------------------------------------------------------
    // Index
    // -------------------------------------------------------------------

    /// Index shard key: `<P>/index/sha256/<ab>/<cd>.idx`
    pub fn index_shard_key(&self, sha256_hex: &str) -> String {
        let (ab, cd) = hash_fanout(sha256_hex);
        format!("{}/index/sha256/{}/{}.idx", self.prefix, ab, cd)
    }

    // -------------------------------------------------------------------
    // Ledgers
    // -------------------------------------------------------------------

    /// Global ledger segment key.
    ///
    /// `<P>/ledgers/global/<run_id>/<seq>.jsonl.zst`
    pub fn global_ledger_key(&self, run_id: &str, sequence: u32) -> String {
        format!(
            "{}/ledgers/global/{}/{:06}.jsonl.zst",
            self.prefix, run_id, sequence
        )
    }

    /// ISA-specific ledger segment key.
    ///
    /// `<P>/ledgers/isa=<isa>/<run_id>/<seq>.jsonl.zst`
    pub fn isa_ledger_key(&self, isa: &Isa, run_id: &str, sequence: u32) -> String {
        format!(
            "{}/ledgers/isa={}/{}/{:06}.jsonl.zst",
            self.prefix,
            isa_slug(isa),
            run_id,
            sequence
        )
    }

    // -------------------------------------------------------------------
    // Runs
    // -------------------------------------------------------------------

    /// Run manifest key: `<P>/runs/<run_id>.json`
    pub fn run_manifest_key(&self, run_id: &str) -> String {
        format!("{}/runs/{}.json", self.prefix, run_id)
    }

    // -------------------------------------------------------------------
    // Stats
    // -------------------------------------------------------------------

    /// Stats file key: `<P>/stats/current.json`
    pub fn stats_key(&self) -> String {
        format!("{}/stats/current.json", self.prefix)
    }
}

/// Convert a relative S3 key to a local staging file path.
///
/// Given staging root `/staging/run-001` and key `isa-harvester/v1/objects/sha256/a1/b2/hash.bin`,
/// returns `/staging/run-001/isa-harvester/v1/objects/sha256/a1/b2/hash.bin`.
pub fn staging_path(staging_root: &std::path::Path, key: &str) -> std::path::PathBuf {
    staging_root.join(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HASH: &str = "a1b2c3d4e5f67890abcdef0123456789abcdef0123456789abcdef0123456789";

    fn cfg() -> KeyConfig {
        KeyConfig::default()
    }

    #[test]
    fn test_object_key() {
        let key = cfg().object_key(TEST_HASH);
        assert_eq!(
            key,
            format!("isa-harvester/v1/objects/sha256/a1/b2/{}.bin", TEST_HASH)
        );
    }

    #[test]
    fn test_meta_key() {
        let key = cfg().meta_key(TEST_HASH);
        assert!(key.ends_with(".meta.json"));
        assert!(key.contains("/objects/sha256/a1/b2/"));
    }

    #[test]
    fn test_classified_view_key() {
        let key = cfg().classified_view_key(
            TEST_HASH,
            &FileFormat::Elf,
            &Isa::AArch64,
            64,
            &Endianness::Little,
            "rkos",
        );
        assert!(key.contains("/views/classified/"));
        assert!(key.contains("fmt=elf/"));
        assert!(key.contains("isa=aarch64/"));
        assert!(key.contains("bits=64/"));
        assert!(key.contains("endian=le/"));
        assert!(key.ends_with("__rkos.ref"));
    }

    #[test]
    fn test_ambiguous_view_key() {
        let key = cfg().ambiguous_view_key(
            TEST_HASH,
            AmbiguousReason::LowConf,
            &FileFormat::Raw,
            "mystery.bin",
        );
        assert!(key.contains("/views/ambiguous/"));
        assert!(key.contains("reason=low_conf/"));
        assert!(key.contains("fmt=raw/"));
        assert!(key.ends_with("__mystery.bin.ref"));
    }

    #[test]
    fn test_index_shard_key() {
        let key = cfg().index_shard_key(TEST_HASH);
        assert_eq!(key, "isa-harvester/v1/index/sha256/a1/b2.idx");
    }

    #[test]
    fn test_global_ledger_key() {
        let key = cfg().global_ledger_key("20260302T143022Z-batch-001", 1);
        assert_eq!(
            key,
            "isa-harvester/v1/ledgers/global/20260302T143022Z-batch-001/000001.jsonl.zst"
        );
    }

    #[test]
    fn test_isa_ledger_key() {
        let key = cfg().isa_ledger_key(&Isa::AArch64, "20260302T143022Z-batch-001", 1);
        assert!(key.contains("isa=aarch64/"));
        assert!(key.ends_with("000001.jsonl.zst"));
    }

    #[test]
    fn test_run_manifest_key() {
        let key = cfg().run_manifest_key("20260302T143022Z-batch-001");
        assert_eq!(key, "isa-harvester/v1/runs/20260302T143022Z-batch-001.json");
    }

    #[test]
    fn test_stats_key() {
        assert_eq!(cfg().stats_key(), "isa-harvester/v1/stats/current.json");
    }

    #[test]
    fn test_staging_path() {
        let root = std::path::Path::new("/staging/run-001");
        let key = "isa-harvester/v1/objects/sha256/a1/b2/hash.bin";
        let path = staging_path(root, key);
        assert_eq!(
            path,
            std::path::PathBuf::from(
                "/staging/run-001/isa-harvester/v1/objects/sha256/a1/b2/hash.bin"
            )
        );
    }
}
