//! Print the per-window verdicts and the best classes for a file.
//!
//! `cargo run --release --example scan_debug -- FILE [--model M] [--window N] [--top K]`

use isa_classifier::heuristics::{self, Model, WindowKind};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let path = args.get(1).expect("FILE");
    let data = std::fs::read(path).expect("read");
    let window: usize = arg("--window").and_then(|v| v.parse().ok()).unwrap_or(heuristics::DEFAULT_WINDOW);
    let top: usize = arg("--top").and_then(|v| v.parse().ok()).unwrap_or(4);
    let bytes = arg("--model").map(|p| std::fs::read(p).expect("model"));
    let model = match &bytes {
        Some(b) => Model::parse(b).expect("model"),
        None => Model::embedded().clone(),
    };
    let scan = heuristics::scan(&data, &model, window, data.len());
    for w in &scan.windows {
        let slice = &data[w.offset..w.offset + w.len];
        let pairs = (w.len.max(2) - 1) as f64;
        let mut costs: Vec<(f64, &str)> = (0..model.len())
            .map(|i| {
                let t = model.table(i);
                let c: u64 = slice.windows(2).map(|p| u64::from(t[(p[0] as usize) << 8 | p[1] as usize])).sum();
                (c as f64 / f64::from(model.cost_scale()) / pairs, model.class(i).name)
            })
            .collect();
        costs.push((8.0, "uniform"));
        costs.sort_by(|a, b| a.0.total_cmp(&b.0));
        let verdict = match w.kind {
            WindowKind::Padding => "padding".to_string(),
            WindowKind::Data => "data".to_string(),
            WindowKind::Ambiguous { best } => format!("ambiguous({})", model.class(best).name),
            WindowKind::Code { class, margin } => format!("CODE {} +{:.2}b/B", model.class(class).name, margin),
        };
        let best: Vec<String> = costs.iter().take(top).map(|(c, n)| format!("{n}={c:.2}")).collect();
        println!("{:>8x} {:>6} {:<28} {}", w.offset, w.len, verdict, best.join(" "));
    }
    match scan.decide() {
        Some(d) => println!(
            "=> {} conf={:.3} family_share={:.2} code_bytes={} scanned={}",
            d.info.name, d.confidence, d.family_share, d.code_bytes, d.scanned_bytes
        ),
        None => println!("=> no code"),
    }
}
