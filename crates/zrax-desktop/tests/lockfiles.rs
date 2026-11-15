//! The applications' lockfile (`crates/Cargo.lock`) must resolve the
//! classifier's own dependencies to the versions the classifier's lockfile
//! (`Cargo.lock`) pins.
//!
//! The two workspaces are locked separately so that a GUI toolkit's
//! dependency tree cannot move the classifier's versions. The price is that
//! they could drift apart, and the desktop build would then classify with
//! other decoder versions than the CLI, the WASM build and the donation
//! server were tested with. This test fails on that drift.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The classifier features the desktop enables on top of the defaults-off
/// build (`workbench`, which implies `certificates` and `image4-aes`); their
/// optional dependencies are compiled in.
const ENABLED_OPTIONAL_DEPENDENCIES: &[&str] =
    &["wide", "x509-parser", "base64", "aes", "cbc", "ctr"];

/// Every version of every package in a lockfile.
fn locked_versions(lockfile: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(lockfile)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", lockfile.display()));
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line != "[[package]]" {
            continue;
        }
        let name = lines.next().and_then(|line| quoted_value(line, "name"));
        let version = lines.next().and_then(|line| quoted_value(line, "version"));
        if let (Some(name), Some(version)) = (name, version) {
            versions.entry(name).or_default().insert(version);
        }
    }
    versions
}

/// The value of a `key = "value"` line.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let value = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
    Some(value.trim().trim_matches('"').to_string())
}

/// The classifier's dependencies that are part of the desktop build: every
/// entry of its `[dependencies]` table that is not optional, plus the
/// optional ones the desktop enables.
fn classifier_dependencies(manifest: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(manifest)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", manifest.display()));
    let mut in_dependencies = false;
    let mut names = Vec::new();
    for line in text.lines() {
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        let Some((name, specification)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let is_entry = in_dependencies && !name.is_empty() && !name.starts_with('#');
        let is_optional = specification.contains("optional = true");
        if is_entry && (!is_optional || ENABLED_OPTIONAL_DEPENDENCIES.contains(&name)) {
            names.push(name.to_string());
        }
    }
    names
}

#[test]
fn both_lockfiles_agree_on_the_classifiers_dependencies() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let classifier = locked_versions(&repository.join("Cargo.lock"));
    let applications = locked_versions(&repository.join("crates/Cargo.lock"));
    let dependencies = classifier_dependencies(&repository.join("Cargo.toml"));
    assert!(
        dependencies.len() > 10,
        "the classifier's dependency table was not read: {dependencies:?}"
    );

    let mut drifted = Vec::new();
    for name in &dependencies {
        let pinned = classifier
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the classifier's Cargo.lock"));
        let resolved = applications.get(name).cloned().unwrap_or_default();
        if !pinned.is_subset(&resolved) {
            drifted.push(format!(
                "{name}: classifier {pinned:?}, applications {resolved:?}"
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "crates/Cargo.lock resolves classifier dependencies differently; \
         align it with `cargo update -p <name> --precise <version>` in crates/:\n{}",
        drifted.join("\n")
    );
}
