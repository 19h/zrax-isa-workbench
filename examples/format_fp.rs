//! Count container-format detections on raw corpus samples (all of which are
//! headerless code or data, so every detection is a false positive).
//!
//! `cargo run --release --example format_fp -- --corpus DIR`

use isa_classifier::formats::{detect_format, DetectedFormat};
use std::collections::BTreeMap;
use std::io::BufRead;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = args.iter().position(|a| a == "--corpus").and_then(|i| args.get(i + 1)).expect("--corpus");
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut n = 0usize;
    let manifest = std::fs::File::open(format!("{corpus}/manifest.jsonl")).unwrap();
    for line in std::io::BufReader::new(manifest).lines() {
        let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let class = row["class"].as_str().unwrap();
        let path = format!("{corpus}/samples/{class}/{}.bin", row["id"].as_str().unwrap());
        let data = std::fs::read(&path).unwrap();
        n += 1;
        let f = detect_format(&data);
        if !matches!(f, DetectedFormat::Raw) {
            let key = format!("{f:?}");
            let key = key.split([' ', '{', '(']).next().unwrap_or("?").to_string();
            hits.entry(key).or_default().push(format!("{class}:{}", row["source"].as_str().unwrap_or("")));
        }
    }
    println!("{n} raw samples");
    for (k, v) in &hits {
        let mut by: BTreeMap<&str, usize> = BTreeMap::new();
        for x in v {
            *by.entry(x.as_str()).or_default() += 1;
        }
        let top: Vec<String> = by.iter().map(|(a, b)| format!("{a}={b}")).take(6).collect();
        println!("{k:<12} {:>6} ({:.3}%)  {}", v.len(), 100.0 * v.len() as f64 / n as f64, top.join(" "));
    }
}
