//! Print how the code windows of raw files split between ISA families, to
//! study mixed images: per file, the two families with the most window
//! weight (windows, bytes, strong windows, summed weight) and the family of
//! the first code window.
//!
//! The weight is the classifier's window weight before the false-alarm
//! allowance (`src/heuristics/mod.rs`, `window_weight`), the measure that
//! ranks the families.
//!
//! ```text
//! cargo run --release --example family_split -- FILE...
//! ```
//!
//! Output: one tab-separated row per file with code windows: path, first
//! family, its offset, then family, windows, bytes, strong windows and
//! weight for the two leading families.

use std::collections::HashMap;

use zrax::heuristics::{self, Model, WindowKind};
use zrax::ClassifierOptions;

/// Window weight parameters, as in `src/heuristics/mod.rs`.
const WEIGHT_MIDPOINT: f64 = 0.6;
const WEIGHT_WIDTH: f64 = 0.15;
const STRONG_MARGIN: f64 = 1.0;

#[derive(Default)]
struct FamilyTotal {
    windows: usize,
    bytes: usize,
    strong: usize,
    weight: f64,
}

#[allow(clippy::cast_precision_loss)]
fn window_weight(margin: f64, len: usize) -> f64 {
    let size = (len as f64 / heuristics::DEFAULT_WINDOW as f64)
        .sqrt()
        .min(1.0);
    size / (1.0 + (-(margin - WEIGHT_MIDPOINT) / WEIGHT_WIDTH).exp())
}

fn split(path: &str, model: &Model, budget: usize) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let scan = heuristics::scan(&data, model, heuristics::DEFAULT_WINDOW, budget);
    let mut totals: HashMap<&'static str, FamilyTotal> = HashMap::new();
    let mut first: Option<(&'static str, usize)> = None;
    for window in &scan.windows {
        let WindowKind::Code { class, margin } = window.kind else {
            continue;
        };
        let family = model.class(class).family;
        first.get_or_insert((family, window.offset));
        let total = totals.entry(family).or_default();
        total.windows += 1;
        total.bytes += window.len;
        total.strong += usize::from(margin >= STRONG_MARGIN);
        total.weight += window_weight(margin, window.len);
    }
    let (first_family, first_offset) = first?;
    let mut ranked: Vec<_> = totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.weight.total_cmp(&a.1.weight).then(a.0.cmp(b.0)));
    let mut row = format!("{path}\t{first_family}\t0x{first_offset:X}");
    for (family, total) in ranked.iter().take(2) {
        row.push_str(&format!(
            "\t{family}\t{}\t{}\t{}\t{:.2}",
            total.windows, total.bytes, total.strong, total.weight
        ));
    }
    Some(row)
}

fn main() {
    let model = Model::embedded();
    let budget = ClassifierOptions::new().max_scan_bytes;
    for path in std::env::args().skip(1) {
        if let Some(row) = split(&path, model, budget) {
            println!("{row}");
        }
    }
}
