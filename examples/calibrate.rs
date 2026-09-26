//! Dump per-window verdicts on the held-out corpus split, for fitting the
//! confidence calibration in `heuristics`.
//!
//! `cargo run --release --example calibrate -- --corpus DIR --model M > windows.csv`
//!
//! Columns: class, sample, is_code, window_len, verdict (code/ambiguous/data/padding),
//! predicted family, correct (1/0), margin (bits/byte).

use isa_classifier::heuristics::{self, class_info, Model, WindowKind};
use std::io::BufRead;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let corpus = arg("--corpus").expect("--corpus");
    let bytes = std::fs::read(arg("--model").expect("--model")).unwrap();
    let model = Model::parse(&bytes).unwrap();
    let cap: usize = arg("--max-per-class").and_then(|v| v.parse().ok()).unwrap_or(150);
    let window: usize = arg("--window").and_then(|v| v.parse().ok()).unwrap_or(heuristics::DEFAULT_WINDOW);
    let mut seen = std::collections::HashMap::<String, usize>::new();
    println!("class,sample,is_code,len,verdict,pred_family,correct,margin");
    let manifest = std::fs::File::open(format!("{corpus}/manifest.jsonl")).unwrap();
    for line in std::io::BufReader::new(manifest).lines() {
        let row: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        if row["split"] != "test" {
            continue;
        }
        let class = row["class"].as_str().unwrap();
        let info = class_info(class);
        let is_code = info.is_some_and(|i| i.is_code());
        if is_code && !model.classes().any(|c| c.name == class) {
            continue;
        }
        if !is_code && !class.starts_with("neg_") {
            continue;
        }
        let n = seen.entry(class.to_string()).or_default();
        if *n >= cap {
            continue;
        }
        *n += 1;
        let id = row["id"].as_str().unwrap();
        let data = std::fs::read(format!("{corpus}/samples/{class}/{id}.bin")).unwrap();
        let scan = heuristics::scan(&data, &model, window, data.len());
        for w in &scan.windows {
            let (verdict, fam, margin) = match w.kind {
                WindowKind::Code { class, margin } => ("code", model.class(class).family, margin),
                WindowKind::Ambiguous { best } => ("ambiguous", model.class(best).family, 0.0),
                WindowKind::Data => ("data", "data", 0.0),
                WindowKind::Padding => ("padding", "data", 0.0),
            };
            let correct = match info {
                Some(i) if i.is_code() => fam == i.family,
                _ => fam == "data",
            };
            println!("{class},{id},{},{},{verdict},{fam},{},{margin:.3}", is_code as u8, w.len, correct as u8);
        }
    }
}
