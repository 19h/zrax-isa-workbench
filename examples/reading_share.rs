//! Print every transform reading of raw files: ISA, confidence and the share
//! of the input the decided family explains as code.
//!
//! The readings and the trial count match the classifier's transform search
//! (`src/lib.rs`, `search_transforms`), so the numbers show why a reading
//! is or is not accepted. With `--tsv`, only files whose stored reading is
//! inconclusive are listed, one `path, reading, isa, confidence, share` row
//! per reading, followed by the decided family's code windows and the
//! informative windows scanned. With `--recovered`, each file is taken to be
//! code that a transform put back in order: one row for the stored bytes
//! scored with the transform search's trial penalty. With `--stored`, one row
//! for the stored reading of every file that decides an ISA.
//!
//! ```text
//! cargo run --release --example reading_share -- [--tsv | --recovered | --stored] FILE...
//! ```

use zrax::heuristics;
use zrax::transform::CANDIDATES;
use zrax::ClassifierOptions;

fn main() {
    let options = ClassifierOptions {
        detect_extensions: false,
        ..ClassifierOptions::new()
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tsv = args.iter().any(|a| a == "--tsv");
    let recovered = args.iter().any(|a| a == "--recovered");
    let stored_only = args.iter().any(|a| a == "--stored");
    for path in args.iter().filter(|a| !a.starts_with("--")) {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if recovered {
            let trials = CANDIDATES.iter().filter(|t| t.applies(data.len())).count() + 1;
            print_row(
                path,
                "recovered",
                &heuristics::analyze_reading(&data, &options, trials),
            );
            continue;
        }
        let stored = heuristics::analyze_reading(&data, &options, 1);
        if stored_only {
            print_row(path, "stored", &stored);
            continue;
        }
        if tsv && stored.result.is_ok() {
            continue;
        }
        let applicable: Vec<_> = CANDIDATES
            .iter()
            .copied()
            .filter(|t| t.applies(data.len()))
            .collect();
        let trials = applicable.len() + 1;
        if !tsv {
            println!("{path}");
            print_reading("stored", &stored);
        }
        for t in applicable {
            let Some(transformed) = t.apply(&data) else {
                continue;
            };
            let reading = heuristics::analyze_reading(&transformed, &options, trials);
            if tsv {
                print_row(path, &t.name(), &reading);
            } else {
                print_reading(&t.name(), &reading);
            }
        }
    }
}

fn print_reading(name: &str, reading: &heuristics::Reading) {
    match &reading.result {
        Ok(r) => println!(
            "  {name:36} {:14} confidence {:.2} code share {:.3}",
            r.isa.name(),
            r.confidence,
            reading.code_share
        ),
        Err(_) => println!(
            "  {name:36} inconclusive      code share {:.3}",
            reading.code_share
        ),
    }
}

fn print_row(path: &str, name: &str, reading: &heuristics::Reading) {
    if let Ok(r) = &reading.result {
        println!(
            "{path}\t{name}\t{}\t{:.3}\t{:.3}\t{}\t{}",
            r.isa.name(),
            r.confidence,
            reading.code_share,
            reading.code_windows,
            reading.informative_windows
        );
    }
}
