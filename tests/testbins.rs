//! Integration test suite for the ISA classifier using ground-truth test binaries.
//!
//! Iterates all files in `testbins/` and classifies each one, comparing the result
//! against the expected ISA derived from the filename prefix.
//!
//! Run with: `cargo test --test testbins -- --nocapture` for full output.

use isa_classifier::{classify_file, ClassifierError, Isa};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Known-failure list: files that are inherently ambiguous and allowed to be
// misclassified or fall below threshold without failing the test.
// ---------------------------------------------------------------------------
const KNOWN_FAILURES: &[&str] = &[
    // 1800-byte file that is ~90% zero bytes, inherently ambiguous
    "mips32_le_mipsel-unknown-linux-gnu_O0_min_nop_sled.bin",
    // 16 KB slice of an unidentified firmware that is almost entirely strings
    // and tables ("ROM DATA OUT", "ERASE ERROR!!"); the SH label is unverified.
    "superh_le_unknown-fw.bin",
];

// ---------------------------------------------------------------------------
// Filename prefix → acceptable ISA family mapping
// ---------------------------------------------------------------------------

/// Map a test filename to its expected ISA family (a set of acceptable `Isa` variants).
/// Returns `None` if the filename doesn't match any known pattern.
fn expected_isas(filename: &str) -> Option<Vec<Isa>> {
    // Order matters: longer/more-specific prefixes first
    let mappings: &[(&str, &[Isa])] = &[
        ("aarch64_", &[Isa::AArch64]),
        ("arm32_", &[Isa::Arm]),
        ("thumb_", &[Isa::Arm]),
        ("fw1-armhf32", &[Isa::Arm]),
        ("avr_", &[Isa::Avr]),
        ("hexagon_", &[Isa::Hexagon]),
        ("loongarch64_", &[Isa::LoongArch64, Isa::LoongArch32]),
        ("mips32_", &[Isa::Mips, Isa::Mips64]),
        ("mips64_", &[Isa::Mips, Isa::Mips64]),
        ("linux-mips", &[Isa::Mips, Isa::Mips64]),
        ("msp430_", &[Isa::Msp430]),
        ("ppc32_", &[Isa::Ppc, Isa::Ppc64, Isa::PpcVle]),
        ("ppc64_", &[Isa::Ppc, Isa::Ppc64, Isa::PpcVle]),
        ("riscv32_", &[Isa::RiscV32, Isa::RiscV64]),
        ("riscv64_", &[Isa::RiscV32, Isa::RiscV64]),
        // Despite the name, an ESP-IDF image built with riscv32-esp-elf.
        ("fw1-riscv64", &[Isa::RiscV32]),
        ("s390x_", &[Isa::S390x, Isa::S390]),
        ("sparc32_", &[Isa::Sparc, Isa::Sparc64]),
        ("sparc64_", &[Isa::Sparc, Isa::Sparc64]),
        ("x86_64_", &[Isa::X86, Isa::X86_64]),
        ("x86_i686", &[Isa::X86, Isa::X86_64]),
        // TriCore files: both .bin (raw) and .o (ELF) variants
        ("tricore", &[Isa::Tricore]),
        // SuperH (SH2/SH4) raw firmware
        ("superh_", &[Isa::Sh, Isa::Sh4]),
        // RH850 / V850 raw firmware
        ("rh850_", &[Isa::Rh850, Isa::V850]),
        // ARC / ARCompact / ARCv2 raw firmware
        ("arc_", &[Isa::Arc, Isa::ArcCompact, Isa::ArcCompact2]),
        // IA-64 (Itanium) — PE/EFI binaries
        ("ia64_", &[Isa::Ia64]),
    ];

    for &(prefix, isas) in mappings {
        if filename.starts_with(prefix) {
            return Some(isas.to_vec());
        }
    }

    None
}

/// Result of classifying a single testbin file.
#[derive(Debug, Clone)]
enum TestResult {
    /// Classifier returned an ISA (may or may not match expected)
    Classified(Isa),
    /// Classifier returned below-threshold (HeuristicInconclusive)
    BelowThreshold,
    /// Other error (IO, parse, etc.)
    Error(String),
}

fn classify_testbin(path: &Path) -> TestResult {
    match classify_file(path) {
        Ok(result) => TestResult::Classified(result.isa),
        Err(ClassifierError::HeuristicInconclusive { .. }) => TestResult::BelowThreshold,
        Err(e) => TestResult::Error(format!("{}", e)),
    }
}

/// Get family name for display purposes (groups related ISAs together).
fn isa_family(isa: &Isa) -> &'static str {
    match isa {
        Isa::X86 | Isa::X86_64 => "x86",
        Isa::Arm => "arm",
        Isa::AArch64 => "aarch64",
        Isa::RiscV32 | Isa::RiscV64 => "riscv",
        Isa::Mips | Isa::Mips64 => "mips",
        Isa::Ppc | Isa::Ppc64 | Isa::PpcVle => "ppc",
        Isa::S390 | Isa::S390x => "s390",
        Isa::Sparc | Isa::Sparc64 => "sparc",
        Isa::LoongArch32 | Isa::LoongArch64 => "loongarch",
        Isa::Hexagon => "hexagon",
        Isa::Avr => "avr",
        Isa::Msp430 => "msp430",
        Isa::Tricore => "tricore",
        Isa::M68k | Isa::ColdFire => "m68k",
        Isa::Sh | Isa::Sh4 => "sh",
        Isa::Arc | Isa::ArcCompact | Isa::ArcCompact2 => "arc",
        Isa::V850 | Isa::Rh850 => "rh850",
        Isa::Ia64 => "ia64",
        _ => "other",
    }
}

#[test]
fn testbins_regression_suite() {
    let testbins_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testbins");
    assert!(
        testbins_dir.exists(),
        "testbins directory not found at {:?}",
        testbins_dir
    );

    let mut entries: Vec<_> = std::fs::read_dir(&testbins_dir)
        .expect("failed to read testbins directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".bin") || name.ends_with(".o")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut total = 0usize;
    let mut correct = 0usize;
    let mut wrong = 0usize;
    let mut below_threshold = 0usize;
    let mut errors = 0usize;
    let mut skipped = 0usize;

    // Track misclassifications: "expected_family -> got" => count
    let mut misclass: HashMap<String, Vec<String>> = HashMap::new();
    // Track below-threshold by family
    let mut below_by_family: HashMap<String, usize> = HashMap::new();

    for entry in &entries {
        let filename = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();

        let acceptable = match expected_isas(&filename) {
            Some(isas) => isas,
            None => {
                skipped += 1;
                continue;
            }
        };

        total += 1;
        let is_known_failure = KNOWN_FAILURES.contains(&filename.as_str());

        let result = classify_testbin(&path);

        match &result {
            TestResult::Classified(got_isa) => {
                if acceptable.contains(got_isa) {
                    correct += 1;
                } else {
                    // It classified but to the wrong ISA
                    wrong += 1;
                    if !is_known_failure {
                        let expected_family = expected_isas(&filename)
                            .map(|v| isa_family(&v[0]).to_string())
                            .unwrap_or_else(|| "?".to_string());
                        let key = format!("{} -> {}", expected_family, got_isa);
                        misclass.entry(key).or_default().push(filename.clone());
                    }
                }
            }
            TestResult::BelowThreshold => {
                below_threshold += 1;
                let family = expected_isas(&filename)
                    .map(|v| isa_family(&v[0]).to_string())
                    .unwrap_or_else(|| "?".to_string());
                *below_by_family.entry(family).or_insert(0) += 1;
            }
            TestResult::Error(msg) => {
                if !is_known_failure {
                    errors += 1;
                    eprintln!("  ERROR: {} -> {}", filename, msg);
                }
            }
        }
    }

    // Print summary
    let pct = |n: usize| -> f64 { n as f64 / total as f64 * 100.0 };
    eprintln!();
    eprintln!("=== TESTBINS REGRESSION SUMMARY ===");
    eprintln!("Total:           {}", total);
    eprintln!("Correct:         {} ({:.1}%)", correct, pct(correct));
    eprintln!("Wrong answer:    {} ({:.1}%)", wrong, pct(wrong));
    eprintln!(
        "Below threshold: {} ({:.1}%)",
        below_threshold,
        pct(below_threshold)
    );
    eprintln!("Errors:          {} ({:.1}%)", errors, pct(errors));
    if skipped > 0 {
        eprintln!("Skipped:         {} (unrecognized prefix)", skipped);
    }

    // Print misclassification breakdown
    if !misclass.is_empty() {
        eprintln!();
        eprintln!("=== MISCLASSIFICATION BREAKDOWN ===");
        let mut sorted: Vec<_> = misclass.iter().collect();
        sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (key, files) in &sorted {
            eprintln!("  {}: {} files", key, files.len());
            for f in files.iter().take(3) {
                eprintln!("    e.g. {}", f);
            }
        }
    }

    // Print below-threshold breakdown
    if !below_by_family.is_empty() {
        eprintln!();
        eprintln!("=== BELOW-THRESHOLD BY FAMILY ===");
        let mut sorted: Vec<_> = below_by_family.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (family, count) in &sorted {
            eprintln!("  {}: {}", family, count);
        }
    }

    // Assertions - these encode our quality gates
    let non_known_wrong = misclass.values().map(|v| v.len()).sum::<usize>();

    // GATE 1: A wrong ISA is worse than "don't know": at most 0.5% wrong.
    assert!(
        non_known_wrong * 200 <= total,
        "Too many wrong answers: {} (max 0.5%). See breakdown above.",
        non_known_wrong
    );

    // GATE 2: At least 97% correct
    let correct_pct = pct(correct);
    assert!(
        correct_pct >= 97.0,
        "Correct rate too low: {:.1}% (min required: 97.0%)",
        correct_pct
    );

    // GATE 3: No unexpected errors (non-IO, non-threshold)
    assert!(
        errors == 0,
        "Unexpected errors: {}. Fix these before committing.",
        errors
    );

    eprintln!();
    eprintln!("All quality gates passed.");
}

/// Detailed per-family accuracy test — ensures no single ISA family regresses badly.
#[test]
fn testbins_per_family_accuracy() {
    let testbins_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testbins");
    if !testbins_dir.exists() {
        eprintln!("Skipping per-family test: testbins directory not found");
        return;
    }

    let mut entries: Vec<_> = std::fs::read_dir(&testbins_dir)
        .expect("failed to read testbins directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".bin") || name.ends_with(".o")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    // family -> (correct, total)
    let mut family_stats: HashMap<String, (usize, usize)> = HashMap::new();

    for entry in &entries {
        let filename = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();

        let acceptable = match expected_isas(&filename) {
            Some(isas) => isas,
            None => continue,
        };

        let family = isa_family(&acceptable[0]).to_string();
        let stats = family_stats.entry(family).or_insert((0, 0));
        stats.1 += 1; // total

        match classify_testbin(&path) {
            TestResult::Classified(got_isa) if acceptable.contains(&got_isa) => {
                stats.0 += 1; // correct
            }
            _ => {}
        }
    }

    eprintln!();
    eprintln!("=== PER-FAMILY ACCURACY ===");
    let mut sorted: Vec<_> = family_stats.iter().collect();
    sorted.sort_by_key(|&(name, _)| name.clone());
    for (family, (correct, total)) in &sorted {
        let pct = *correct as f64 / *total as f64 * 100.0;
        let status = if pct == 0.0 {
            " <-- ALL BELOW THRESHOLD"
        } else {
            ""
        };
        eprintln!(
            "  {:12} {:3}/{:3} ({:5.1}%){}",
            family, correct, total, pct, status
        );
    }

    // Families with format-based detection (ELF .o files) should have very high rates
    if let Some(&(correct, total)) = family_stats.get("tricore") {
        let pct = correct as f64 / total as f64 * 100.0;
        // TriCore .o files are ELF-detected, should be near 100%
        assert!(
            pct >= 90.0,
            "TriCore accuracy dropped below 90%: {:.1}% ({}/{})",
            pct,
            correct,
            total
        );
    }

    // Major architectures — check that well-tuned ones don't regress.
    // Thresholds are set ~10% below current values to catch regressions
    // without failing on normal variance.
    let family_min_thresholds: &[(&str, f64)] = &[
        ("arm", 90.0),       // currently 97.7%
        ("aarch64", 60.0),   // currently 72.5%
        ("hexagon", 90.0),   // currently 100%
        ("tricore", 90.0),   // currently 100% (ELF-based)
        ("loongarch", 70.0), // currently 82.1%
        ("avr", 50.0),       // currently 61.5%
        ("msp430", 80.0),    // currently 91.7%
        ("s390", 65.0),      // currently 76.9%
        ("mips", 30.0),      // currently 38.9%
        ("ppc", 25.0),       // currently 33.3%
        ("x86", 28.0),       // currently 36.1%
        ("riscv", 10.0),     // currently 16.8% — many below threshold
                             // sparc: currently 2.6%, no minimum enforced yet
    ];

    for &(family_name, min_pct) in family_min_thresholds {
        if let Some(&(correct, total)) = family_stats.get(family_name) {
            let pct = correct as f64 / total as f64 * 100.0;
            assert!(
                pct >= min_pct,
                "{} accuracy dropped below {:.0}%: {:.1}% ({}/{})",
                family_name,
                min_pct,
                pct,
                correct,
                total
            );
        }
    }

    eprintln!();
    eprintln!("Per-family accuracy checks passed.");
}
