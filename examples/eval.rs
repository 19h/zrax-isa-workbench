//! Accuracy harness for the raw-code classifier, on the held-out split of a
//! corpus built by `scripts/build_corpus.py`.
//!
//! Every test sample is classified whole (up to the per-sample cap of the
//! corpus) and as short snippets cut out of it, at the default confidence
//! threshold, so the numbers are what a user actually gets: accepted-correct,
//! accepted-wrong, or rejected. Non-code samples (`neg_*` classes) must be
//! rejected; anything else is a false accept.
//!
//! ```text
//! cargo run --release --example train_model -- --corpus DIR --split train --out /tmp/m.bin
//! cargo run --release --example eval -- --corpus DIR --model /tmp/m.bin [--snippets 128,512,2048]
//!     [--csv out.csv] [--verbose]
//! cargo run --release --example eval -- --firmware ../armgen/firmware [--model M]
//! ```
//!
//! `--firmware` evaluates multi-ISA detection on synthetic firmware images
//! (`<name>.bin` + `<name>.json` with `isa.all`), scoring the detected set of
//! ISA families against the truth.
//!
//! Without `--model` the embedded model is used, which has seen the test
//! split and therefore only measures fit, not generalisation.

use isa_classifier::heuristics::{self, class_info, ClassKind, Model};
use isa_classifier::ClassifierOptions;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

struct Case {
    class: String,
    source: String,
    /// "file" or the snippet size.
    kind: String,
    data: Vec<u8>,
}

#[derive(Default, Clone)]
struct Tally {
    n: usize,
    correct: usize,
    exact: usize,
    wrong: usize,
    rejected: usize,
    confusions: BTreeMap<String, usize>,
}

impl Tally {
    fn merge(&mut self, o: &Tally) {
        self.n += o.n;
        self.correct += o.correct;
        self.exact += o.exact;
        self.wrong += o.wrong;
        self.rejected += o.rejected;
        for (k, v) in &o.confusions {
            *self.confusions.entry(k.clone()).or_default() += v;
        }
    }
    fn pct(&self, x: usize) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            100.0 * x as f64 / self.n as f64
        }
    }
}

/// armgen oracle family name → model family.
fn armgen_family(f: &str) -> &'static str {
    match f {
        "arm32" | "thumb" => "arm",
        "aarch64" => "aarch64",
        "x86" | "x86_64" => "x86",
        "mips32_be" | "mips32_le" | "mips64_be" | "mips64_le" => "mips",
        "ppc32" | "ppc64_be" | "ppc64_le" => "ppc",
        "sparc32" | "sparc64" => "sparc",
        "riscv32" | "riscv64" => "riscv",
        "s390x" => "s390",
        "loongarch64" => "loongarch",
        "hexagon" => "hexagon",
        "avr" => "avr",
        "msp430" => "msp430",
        _ => "?",
    }
}

fn firmware_eval(dir: &str, model: &Model) {
    let mut images = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "bin") && p.with_extension("json").exists() {
                images.push(p);
            }
        }
    }
    images.sort();
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<(Vec<String>, Vec<String>, String)>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= images.len() {
                    break;
                }
                let meta: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(images[i].with_extension("json")).unwrap()).unwrap();
                let mut truth: Vec<String> = meta["isa"]["all"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| armgen_family(v.as_str().unwrap()).to_string())
                    .collect();
                truth.sort();
                truth.dedup();
                let data = std::fs::read(&images[i]).unwrap();
                let found: Vec<String> = heuristics::detect_multi_isa_with_model(&data, model, heuristics::DEFAULT_WINDOW)
                    .into_iter()
                    .filter_map(|d| heuristics::family_of(d.isa).map(str::to_string))
                    .collect();
                out.lock().unwrap().push((truth, found, images[i].display().to_string()));
            });
        }
    });
    let out = out.into_inner().unwrap();
    let (mut exact, mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize, 0usize);
    let mut per_family: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for (truth, found, path) in &out {
        let mut f = found.clone();
        f.sort();
        if &f == truth {
            exact += 1;
        }
        for t in truth {
            let e = per_family.entry(t.clone()).or_default();
            if found.contains(t) {
                tp += 1;
                e.0 += 1;
            } else {
                fn_ += 1;
                e.2 += 1;
            }
        }
        for x in found {
            if !truth.contains(x) {
                fp += 1;
                per_family.entry(x.clone()).or_default().1 += 1;
            }
        }
        if args_verbose() && &f != truth {
            eprintln!("{path}: truth={truth:?} found={found:?}");
        }
    }
    println!("{:<12} {:>6} {:>6} {:>6} {:>8} {:>8}", "family", "tp", "fp", "fn", "prec", "recall");
    for (fam, (t, f, n)) in &per_family {
        println!(
            "{:<12} {:>6} {:>6} {:>6} {:>7.1}% {:>7.1}%",
            fam,
            t,
            f,
            n,
            100.0 * *t as f64 / (t + f).max(1) as f64,
            100.0 * *t as f64 / (t + n).max(1) as f64
        );
    }
    println!(
        "FIRMWARE: images={} exact-set={:.1}% family precision={:.1}% recall={:.1}%",
        out.len(),
        100.0 * exact as f64 / out.len().max(1) as f64,
        100.0 * tp as f64 / (tp + fp).max(1) as f64,
        100.0 * tp as f64 / (tp + fn_).max(1) as f64
    );
}

fn args_verbose() -> bool {
    std::env::args().any(|a| a == "--verbose")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    if let Some(dir) = arg("--firmware") {
        let bytes = arg("--model").map(|p| std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}")));
        let model = match &bytes {
            Some(b) => Model::parse(b).expect("valid model"),
            None => Model::embedded().clone(),
        };
        firmware_eval(&dir, &model);
        return;
    }
    let corpus = arg("--corpus").expect("--corpus DIR is required");
    let snippet_sizes: Vec<usize> = arg("--snippets")
        .unwrap_or_else(|| "128,512,2048".into())
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect();
    let per_class_cap: usize = arg("--max-per-class").and_then(|v| v.parse().ok()).unwrap_or(300);
    let verbose = args.iter().any(|a| a == "--verbose");
    let model_bytes = arg("--model").map(|p| std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}")));
    let model = match &model_bytes {
        Some(b) => Model::parse(b).expect("valid model"),
        None => Model::embedded().clone(),
    };
    let known: Vec<&str> = model.classes().map(|c| c.name).collect();

    // Load the test split.
    let mut cases = Vec::new();
    let mut per_class: BTreeMap<String, usize> = BTreeMap::new();
    let manifest = std::fs::File::open(format!("{corpus}/manifest.jsonl")).expect("manifest.jsonl");
    let mut rows: Vec<serde_json::Value> = std::io::BufReader::new(manifest)
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    // Deterministic shuffle: the per-class cap must sample all sources, not
    // whichever one comes first in the manifest.
    let fnv = |s: &str| s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    rows.sort_by_key(|r| fnv(r["id"].as_str().unwrap_or("")));
    for row in rows {
        if row["split"] != "test" {
            continue;
        }
        let class = row["class"].as_str().unwrap().to_string();
        let is_neg = class.starts_with("neg_");
        if !is_neg && !known.contains(&class.as_str()) {
            continue; // ISA not in this model
        }
        let count = per_class.entry(class.clone()).or_default();
        if *count >= per_class_cap {
            continue;
        }
        *count += 1;
        let id = row["id"].as_str().unwrap();
        let data = std::fs::read(format!("{corpus}/samples/{class}/{id}.bin")).unwrap();
        let source = format!("{}:{}", row["source"].as_str().unwrap_or(""), row["group"].as_str().unwrap_or(""));
        for &sz in &snippet_sizes {
            if data.len() >= 2 * sz {
                let off = (data.len() / 2 - sz / 2) & !0xF;
                cases.push(Case { class: class.clone(), source: source.clone(), kind: format!("{sz:>6}B"), data: data[off..off + sz].to_vec() });
            }
        }
        cases.push(Case { class, source, kind: "  file".into(), data });
    }
    eprintln!("{} cases", cases.len());

    let mut opts = ClassifierOptions::new();
    opts.detect_extensions = false;
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<(Option<(String, String)>, f64)>>> = Mutex::new(vec![None; cases.len()]);
    let t0 = std::time::Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= cases.len() {
                    break;
                }
                let r = heuristics::analyze_with_model(&cases[i].data, &opts, &model);
                let out = match r {
                    Ok(r) => {
                        let fam = heuristics::CLASSES
                            .iter()
                            .find(|c| matches!(c.kind, ClassKind::Code { isa, endianness, bitwidth, .. }
                                if isa == r.isa && endianness == r.endianness && bitwidth == r.bitwidth))
                            .map(|c| c.family)
                            .unwrap_or("?");
                        (Some((format!("{}/{}/{}", r.isa.name(), r.endianness, r.bitwidth), fam.to_string())), r.confidence)
                    }
                    Err(_) => (None, 0.0),
                };
                results.lock().unwrap()[i] = Some(out);
            });
        }
    });
    let elapsed = t0.elapsed();
    let results: Vec<_> = results.into_inner().unwrap().into_iter().map(Option::unwrap).collect();

    let mut by_class: BTreeMap<(String, String), Tally> = BTreeMap::new();
    let mut csv = String::from("class,kind,source,len,predicted,confidence\n");
    for (c, (pred, conf)) in cases.iter().zip(&results) {
        let mut t = Tally { n: 1, ..Default::default() };
        let truth = class_info(&c.class);
        match (pred, truth) {
            (None, _) => t.rejected += 1,
            (Some((label, fam)), Some(info)) if info.is_code() => {
                if *fam == info.family {
                    t.correct += 1;
                    if let ClassKind::Code { isa, endianness, bitwidth, .. } = info.kind {
                        t.exact += (*label == format!("{}/{}/{}", isa.name(), endianness, bitwidth)) as usize;
                    }
                } else {
                    t.wrong += 1;
                    *t.confusions.entry(label.clone()).or_default() += 1;
                }
            }
            (Some((label, _)), _) => {
                t.wrong += 1;
                *t.confusions.entry(label.clone()).or_default() += 1;
            }
        }
        if verbose && t.correct == 0 && !(c.class.starts_with("neg_") && t.rejected == 1) {
            eprintln!("{} {} {} len={} -> {:?} {:.2}", c.class, c.kind.trim(), c.source, c.data.len(), pred.as_ref().map(|p| &p.0), conf);
        }
        csv.push_str(&format!(
            "{},{},{},{},{},{:.3}\n",
            c.class,
            c.kind.trim(),
            c.source.replace(',', ";"),
            c.data.len(),
            pred.as_ref().map(|p| p.0.as_str()).unwrap_or("-"),
            conf
        ));
        by_class.entry((c.class.clone(), c.kind.clone())).or_default().merge(&t);
    }

    println!("{:<14} {:>7} {:>5} {:>8} {:>7} {:>7} {:>8}  confusions", "class", "input", "n", "correct", "exact", "wrong", "rejected");
    let mut kinds: BTreeMap<String, (Tally, Tally, Vec<f64>)> = BTreeMap::new();
    for ((class, kind), t) in &by_class {
        let conf: Vec<String> = {
            let mut v: Vec<_> = t.confusions.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1));
            v.iter().take(3).map(|(k, v)| format!("{k}:{v}")).collect()
        };
        println!(
            "{:<14} {:>7} {:>5} {:>7.1}% {:>6.1}% {:>6.1}% {:>7.1}%  {}",
            class,
            kind,
            t.n,
            t.pct(t.correct),
            t.pct(t.exact),
            t.pct(t.wrong),
            t.pct(t.rejected),
            conf.join(" ")
        );
        let e = kinds.entry(kind.clone()).or_default();
        if class.starts_with("neg_") {
            e.1.merge(t);
        } else {
            e.0.merge(t);
            e.2.push(t.pct(t.correct));
        }
    }
    println!();
    for (kind, (code, neg, per_class)) in &kinds {
        let macro_avg = per_class.iter().sum::<f64>() / per_class.len().max(1) as f64;
        println!(
            "SUMMARY {:>7}: code n={:5} correct={:5.1}% exact={:5.1}% wrong={:4.1}% rejected={:4.1}% macro-correct={:5.1}% | non-code n={:4} false-accept={:4.1}%",
            kind,
            code.n,
            code.pct(code.correct),
            code.pct(code.exact),
            code.pct(code.wrong),
            code.pct(code.rejected),
            macro_avg,
            neg.n,
            neg.pct(neg.wrong)
        );
    }
    eprintln!("{:.1}s", elapsed.as_secs_f64());
    if let Some(path) = arg("--csv") {
        std::fs::write(path, csv).unwrap();
    }
}
