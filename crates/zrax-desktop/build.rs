//! Build script for the desktop workbench.
//!
//! 1. Generates the display-name tables from `web/format.js`. That file is
//!    the one place JSON IDs are mapped to display names (AGENTS.md 4.1);
//!    generating from it keeps the browser and the desktop in agreement
//!    without a second hand-written table.
//! 2. Records the git commit the binary is built from. The donation server
//!    decides by zrax revision which clients may upload, so the app states
//!    its revision when it asks.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the object literals start in `web/format.js`, and the Rust table
/// each becomes.
const NAME_TABLES: &[(&str, &str)] = &[
    ("const ISA_NAMES = {", "ISA_NAMES"),
    ("const FORMAT_NAMES = {", "FORMAT_NAMES"),
    ("function fmtCat(c) {\n  const m = {", "CATEGORY_NAMES"),
];

fn main() {
    let manifest_dir = PathBuf::from(env("CARGO_MANIFEST_DIR"));
    let repository = manifest_dir.join("../..");
    let format_js = repository.join("web/format.js");
    println!("cargo:rerun-if-changed={}", format_js.display());
    let source = std::fs::read_to_string(&format_js)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", format_js.display()));

    let mut generated = String::new();
    for (opening, table) in NAME_TABLES {
        let mut entries = object_entries(&source, opening);
        entries.sort();
        entries.dedup_by(|a, b| a.0 == b.0);
        writeln!(
            generated,
            "/// `{table}` of `web/format.js`, sorted by ID.\npub static {table}: &[(&str, &str)] = &["
        )
        .expect("write to string");
        for (id, name) in entries {
            writeln!(generated, "    ({id:?}, {name:?}),").expect("write to string");
        }
        generated.push_str("];\n\n");
    }
    let out_dir = PathBuf::from(env("OUT_DIR"));
    std::fs::write(out_dir.join("names.rs"), generated).expect("write names.rs");

    record_revision(&repository);
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// The `id: 'name'` pairs of the JavaScript object literal that follows
/// `opening`, up to its closing brace. The tables hold nothing but such
/// pairs; anything else (an escape, a nested object) fails the build so the
/// tables cannot silently fall out of step with the browser.
fn object_entries(source: &str, opening: &str) -> Vec<(String, String)> {
    let start = source
        .find(opening)
        .unwrap_or_else(|| panic!("web/format.js no longer contains `{opening}`"));
    let body = &source[start + opening.len()..];
    let end = body
        .find('}')
        .unwrap_or_else(|| panic!("unterminated object after `{opening}`"));
    let body = &body[..end];
    assert!(
        !body.contains('\\') && !body.contains('{'),
        "the object after `{opening}` holds an escape or a nested object; \
         teach crates/zrax-desktop/build.rs to read it"
    );

    let mut entries = Vec::new();
    let mut rest = body;
    while let Some(colon) = rest.find(": '") {
        let id_start = rest[..colon]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |at| at + 1);
        let id = &rest[id_start..colon];
        let value = &rest[colon + 3..];
        let close = value
            .find('\'')
            .unwrap_or_else(|| panic!("unterminated name for `{id}` after `{opening}`"));
        assert!(!id.is_empty(), "missing ID before a name after `{opening}`");
        entries.push((id.to_string(), value[..close].to_string()));
        rest = &value[close + 1..];
    }
    assert!(!entries.is_empty(), "no names found after `{opening}`");
    entries
}

/// Export `ZRAX_GIT_REV`: the full commit id, or empty when unknown.
/// `ZRAX_REV` in the environment overrides git, for builds from a source
/// archive of a known commit.
fn record_revision(repository: &Path) {
    println!("cargo:rerun-if-env-changed=ZRAX_REV");
    println!(
        "cargo:rerun-if-changed={}",
        repository.join(".git/HEAD").display()
    );
    let revision = match std::env::var("ZRAX_REV") {
        Ok(revision) if !revision.trim().is_empty() => revision.trim().to_string(),
        _ => git(repository, &["rev-parse", "HEAD"]).unwrap_or_default(),
    };
    println!("cargo:rustc-env=ZRAX_GIT_REV={revision}");
}

fn git(repository: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
