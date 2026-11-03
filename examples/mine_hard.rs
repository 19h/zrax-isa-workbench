//! Mine hard negatives: windows of known non-code files that a model calls code.
//!
//! Reads `path<TAB>class<TAB>group` lines on stdin (class is a `neg_*` corpus
//! class), scans each whole file the way the classifier does, and writes the
//! windows that come out as code as one sample per file in `build_corpus.py`
//! layout (`<out>/samples/<class>/<id>.bin`, `<out>/manifest.jsonl`, split
//! `train`, source `fw1-hard`).
//!
//! ```text
//! cargo run --release --example mine_hard -- --model M --out DIR < list.tsv
//! ```

use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use zrax::heuristics::{self, Model, WindowKind};

/// Smallest mined sample worth keeping (matches `MIN_SAMPLE_BYTES`).
const MIN_SAMPLE_BYTES: usize = 256;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let model_bytes = std::fs::read(arg("--model").expect("--model M")).expect("read model");
    let model = Model::parse(&model_bytes).expect("parse model");
    let out = arg("--out").expect("--out DIR");
    let mut manifest = std::fs::File::create(format!("{out}/manifest.jsonl")).expect("manifest");
    let (mut files, mut hit_files, mut hit_bytes) = (0usize, 0usize, 0usize);
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let fields: Vec<&str> = line.split('\t').collect();
        let [path, class, group] = fields[..] else {
            continue;
        };
        let data = std::fs::read(path).expect("read input");
        files += 1;
        let scan = heuristics::scan(&data, &model, heuristics::DEFAULT_WINDOW, data.len());
        let mut sample = Vec::new();
        for window in &scan.windows {
            if matches!(window.kind, WindowKind::Code { .. }) {
                sample.extend_from_slice(&data[window.offset..window.offset + window.len]);
            }
        }
        if sample.len() < MIN_SAMPLE_BYTES {
            continue;
        }
        let digest = Sha256::digest(&sample);
        let id: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        let dir = format!("{out}/samples/{class}");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(format!("{dir}/{id}.bin"), &sample).expect("write sample");
        let row = serde_json::json!({
            "id": id, "class": class, "group": group, "split": "train",
            "source": "fw1-hard", "size": sample.len(),
        });
        writeln!(manifest, "{row}").expect("write manifest");
        hit_files += 1;
        hit_bytes += sample.len();
    }
    eprintln!("{files} files scanned, {hit_files} with code windows, {hit_bytes} bytes mined");
}
