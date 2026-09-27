//! Train the embedded raw-code model from a corpus built by
//! `scripts/build_corpus.py`.
//!
//! ```text
//! cargo run --release --example train_model -- --corpus DIR
//!     [--out src/heuristics/model.bin] [--split all|train] [--alpha 16]
//!     [--min-bytes 49152] [--source-cap 1048576] [--exclude a,b,c (default: pru,trimedia)]
//! ```
//!
//! `--split train` leaves the corpus test split out, for honest evaluation
//! with `examples/eval.rs --model`.
//!
//! `--source-cap` bounds how many bytes of a class may come from one corpus
//! source (Debian binaries, armgen, the LLVM matrix, idaref, ...). Without it
//! a class is dominated by whichever toolchain contributed the most bytes, and
//! code from other compilers fits a sibling class better (LLVM-built MIPS32
//! looking more like the LLVM-heavy MIPS64 model than the GCC-heavy MIPS32 one).

use isa_classifier::heuristics::model::{class_info, Model, ModelBuilder, COST_SCALE};
use std::collections::BTreeMap;
use std::io::BufRead;

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let corpus = arg("--corpus").expect("--corpus DIR is required");
    let out = arg("--out").unwrap_or_else(|| {
        format!("{}/src/heuristics/model.bin", env!("CARGO_MANIFEST_DIR"))
    });
    let split = arg("--split").unwrap_or_else(|| "all".into());
    let alpha: f64 = arg("--alpha").and_then(|v| v.parse().ok()).unwrap_or(16.0);
    let min_bytes: u64 = arg("--min-bytes").and_then(|v| v.parse().ok()).unwrap_or(48 * 1024);
    let source_cap: u64 = arg("--source-cap").and_then(|v| v.parse().ok()).unwrap_or(1 << 20);
    // Classes left out of the shipped model unless --exclude says otherwise:
    // - pru: trained on GCC output only, it absorbed 14 of 19 false-alarm
    //   windows on real .rodata (margins up to 1.5 bits/byte, above the
    //   strong-window threshold); raw PRU firmware outside ELF is rare.
    // - trimedia: one program (the tmlinux kernel); it accepted a real .rodata
    //   file and had the largest false-alarm margin (0.87 bits/byte). TriMedia
    //   objects are identified from their TMObj header instead.
    let exclude: Vec<String> = arg("--exclude")
        .unwrap_or_else(|| "pru,trimedia".into())
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let manifest = std::fs::File::open(format!("{corpus}/manifest.jsonl")).expect("manifest.jsonl");
    let mut rows: Vec<serde_json::Value> = std::io::BufReader::new(manifest)
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    // Deterministic shuffle so the per-source cap samples evenly, not by file order.
    rows.sort_by_key(|r| fnv(r["id"].as_str().unwrap_or("")));
    let mut builders: BTreeMap<String, ModelBuilder> = BTreeMap::new();
    let mut skipped: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_source: BTreeMap<(String, String), u64> = BTreeMap::new();
    for row in &rows {
        let class = row["class"].as_str().unwrap();
        if split != "all" && row["split"] != split.as_str() {
            continue;
        }
        if class_info(class).is_none() || exclude.iter().any(|e| e == class) {
            *skipped.entry(class.to_string()).or_default() += row["size"].as_u64().unwrap_or(0);
            continue;
        }
        let size = row["size"].as_u64().unwrap_or(0);
        let used = per_source
            .entry((class.to_string(), row["source"].as_str().unwrap_or("").to_string()))
            .or_default();
        if *used >= source_cap {
            continue;
        }
        *used += size;
        let path = format!("{corpus}/samples/{class}/{}.bin", row["id"].as_str().unwrap());
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        builders.entry(class.to_string()).or_default().add(&data);
    }

    let mut tables = Vec::new();
    for (class, b) in &builders {
        if b.bytes() < min_bytes {
            eprintln!("skip {class:14} {:>9} bytes (< {min_bytes})", b.bytes());
            continue;
        }
        eprintln!("keep {class:14} {:>9} bytes", b.bytes());
        tables.push((class.clone(), b.build(alpha, COST_SCALE)));
    }
    for (class, bytes) in &skipped {
        eprintln!("skip {class:14} {bytes:>9} bytes (not a model class or excluded)");
    }
    let bytes = Model::serialize(&tables, COST_SCALE);
    Model::parse(&bytes).expect("round trip");
    std::fs::write(&out, &bytes).unwrap_or_else(|e| panic!("{out}: {e}"));
    eprintln!("wrote {} classes, {} bytes to {out}", tables.len(), bytes.len());
}
