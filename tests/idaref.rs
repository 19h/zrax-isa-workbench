//! Integration test against IDA Pro's reference corpus in `idaref/`.
//!
//! File names start with the IDA processor module that opens them, which
//! gives the ground truth. Most files are containers (ELF, PE, COFF, Mach-O,
//! ...) whose header names the ISA; raw dumps go through the code model.
//!
//! Two kinds of expectation:
//! * `Is(..)` — the ISA we must report (any slice of a fat binary counts).
//! * `Unsupported` — an ISA this crate has no variant for (6809, ST20, TLCS-900,
//!   ...). The only acceptable outcomes are "unknown" and "inconclusive":
//!   claiming some *other* ISA is a false positive, not a near miss.
//!
//! Run with `cargo test --test idaref -- --nocapture` for the full report.

use isa_classifier::{detect_payload, ClassificationSource, ClassifierError, ClassifierOptions, Isa};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use Isa::*;

enum Expect {
    Is(&'static [Isa]),
    Unsupported,
}
use Expect::{Is, Unsupported};

/// IDA processor-module prefix → expectation. Longer prefixes first.
const PREFIXES: &[(&str, Expect)] = &[
    ("metapc_", Is(&[X86, X86_64])),
    ("pc_", Is(&[X86, X86_64])),
    ("x86_", Is(&[X86, X86_64])),
    ("x64_", Is(&[X86, X86_64])),
    ("cygwin1.dll", Is(&[X86, X86_64])),
    ("libdbg.so", Is(&[Arm])), // an ARM EABI4 shared object despite the pc_ neighbours
    ("libfoo.so", Is(&[X86, X86_64])),
    ("msvcp100d.dll", Is(&[X86, X86_64])),
    ("msvcr100d.dll", Is(&[X86, X86_64])),
    ("ntoskrnl.exe", Is(&[X86, X86_64])),
    ("pentnt.pe", Is(&[X86, X86_64])),
    ("interr_30730_64.macho", Is(&[X86_64, AArch64])),
    ("arm64_", Is(&[AArch64])),
    ("armb_", Is(&[Arm, AArch64])),
    ("arm_", Is(&[Arm, AArch64])),
    ("arm.", Is(&[Arm, AArch64])),
    ("mipsl_", Is(&[Mips, Mips64])),
    ("mipsb_", Is(&[Mips, Mips64])),
    ("mips_", Is(&[Mips, Mips64])),
    ("tx19ab_", Is(&[Mips, Mips64])), // Toshiba TX19A is a MIPS32/MIPS16e core
    ("ppc64_", Is(&[Ppc, Ppc64])),
    ("ppcl_", Is(&[Ppc, Ppc64])),
    ("ppc_", Is(&[Ppc, Ppc64, PpcVle])),
    ("sparcb_", Is(&[Sparc, Sparc64])),
    ("sparcl", Is(&[Sparc, Sparc64])),
    ("sparc_", Is(&[Sparc, Sparc64])),
    ("riscv_", Is(&[RiscV32, RiscV64])),
    ("alpha_", Is(&[Alpha])),
    ("ia64_", Is(&[Ia64])),
    ("hppa_", Is(&[Parisc])),
    ("s390x_", Is(&[S390x, S390])),
    ("s390_", Is(&[S390, S390x])),
    ("mc68k_", Is(&[M68k, ColdFire])),
    ("68K_", Is(&[M68k, ColdFire])),
    ("68k_", Is(&[M68k, ColdFire])),
    ("68040_", Is(&[M68k, ColdFire])),
    ("68030_", Is(&[M68k, ColdFire])),
    ("68000_", Is(&[M68k, ColdFire])),
    ("coldfire_", Is(&[ColdFire, M68k])),
    ("6812_", Is(&[Hcs12])),
    ("hcs12x_", Is(&[Hcs12])),
    ("6811_", Is(&[Hc11])),
    ("6809_", Is(&[M6809])),
    ("6808_", Unsupported),
    ("hcs08_", Unsupported),
    ("sh4b_", Is(&[Sh, Sh4])),
    ("sh4_", Is(&[Sh, Sh4])),
    ("sh3b_", Is(&[Sh, Sh4])),
    ("sh3_", Is(&[Sh, Sh4])),
    ("sh2a_", Is(&[Sh, Sh4])),
    ("sh_", Is(&[Sh, Sh4])),
    ("arcv2_", Is(&[Arc, ArcCompact, ArcCompact2])),
    ("arcmpct_", Is(&[Arc, ArcCompact, ArcCompact2])),
    ("arc_", Is(&[Arc, ArcCompact, ArcCompact2])),
    ("arc.", Is(&[Arc, ArcCompact, ArcCompact2])),
    ("v850e2m_", Is(&[V850, Rh850])),
    ("v850e1_", Is(&[V850, Rh850])),
    ("v850_", Is(&[V850, Rh850])),
    ("rh850_", Is(&[Rh850, V850])),
    ("rx_", Is(&[Rx])),
    ("rl78_", Is(&[Rl78])),
    ("78k0_", Is(&[K78k0r])),
    ("h8sxm_", Is(&[H8300])),
    ("h8sx_", Is(&[H8300])),
    ("h8s_", Is(&[H8300])),
    ("h8h_", Is(&[H8300])),
    ("h8368_", Is(&[H8300])),
    ("h8300_", Is(&[H8300])),
    ("h8500", Unsupported),
    ("h8_", Is(&[H8300])),
    ("h8.", Is(&[H8300])),
    ("m32r_", Is(&[M32r])),
    ("m32c80_", Is(&[M16c])),
    ("m16c60_", Is(&[M16c])),
    ("r8c_", Is(&[M16c])), // R8C is an M16C/60-series core
    ("r32c_", Unsupported),
    ("avr_", Is(&[Avr])),
    ("msp430_", Is(&[Msp430])),
    ("tricore_", Is(&[Tricore])),
    ("tricore-", Is(&[Tricore])),
    ("tricore.", Is(&[Tricore])),
    ("i860_", Is(&[I860])),
    ("i960_", Is(&[I960])),
    ("xtensab_", Is(&[Xtensa])),
    ("xtensa_", Is(&[Xtensa])),
    ("tms320c6_", Is(&[TiC6000])),
    ("tms320c67_", Is(&[TiC6000])),
    ("tms320c64_", Is(&[TiC6000])),
    ("tms320c54_", Is(&[TiC5500])),
    ("tms32054_", Is(&[TiC5500])),
    ("tms32055_", Is(&[TiC5500])),
    ("tms32055-", Is(&[TiC5500])),
    ("tms320c5_", Is(&[TiC5500])),
    ("tms32028_", Is(&[TiC28x, TiC2000])),
    ("tms320c2_", Is(&[TiC2000, TiC28x])),
    ("tms320c3", Unsupported),
    ("cskyv1b_", Is(&[Csky])),
    ("cskyv1_", Is(&[Csky])),
    ("mcore_", Is(&[Csky])), // EM_MCORE; C-SKY V1 is the M·CORE derivative that uses it
    ("c166_", Is(&[C166])),
    ("pic33_", Is(&[Pic])),
    ("pic16cxx_", Is(&[Pic])),
    ("java_", Is(&[Jvm])),
    ("java.", Is(&[Jvm])),
    ("dalvik_", Is(&[Dalvik, Arm, AArch64])), // OAT/ODEX files are ELF containers
    ("cli_", Is(&[Clr, X86, X86_64])),        // mixed-mode assemblies carry native code
    ("wasm_", Is(&[Wasm])),
    ("ebc_", Is(&[Ebc])),
    ("spu_", Is(&[CellSpu])),
    ("m65816_", Is(&[W65816])),
    ("m65c02_", Is(&[Mcs6502, W65816])),
    ("m6502_", Is(&[Mcs6502])),
    ("z80_", Is(&[Z80])),
    ("gb_", Is(&[Z80])),
    ("z8_", Unsupported),
    ("fr_", Is(&[Fr30, Fr80])),
    ("ad2106x_", Is(&[Sharc])),
    ("ad218x_", Unsupported),
    ("nds32_", Is(&[Nds32])),
    ("st9_", Is(&[St9])),
    ("st20_", Unsupported),
    ("dsp56k_", Unsupported),
    ("dsp561xx", Unsupported),
    ("dsp563xx_", Unsupported),
    ("oakdsp_", Unsupported),
    ("tlcs900", Unsupported),
    ("mn102l00", Unsupported),
    ("unsp_", Unsupported),
    ("80196", Unsupported),
    ("kr1878", Unsupported),
    ("cr16_", Unsupported),
    ("f2mc16lx_", Unsupported),
    ("c39_", Unsupported),
    ("51xa-", Unsupported),
    ("m740_", Unsupported),
    ("m750_", Unsupported),
    ("spc700_", Unsupported),
    ("trimedia", Unsupported),
    ("clemency_", Unsupported), // 9-bit bytes
];

/// Not binaries: IDA databases, listings, debug side files.
const SKIP_SUFFIXES: &[&str] = &[
    ".id0", ".id1", ".id2", ".nam", ".til", ".hints", ".dwz", ".mas", ".pdb", ".dbg", ".i64", ".idb",
];

/// Files whose IDA prefix does not describe the bytes (documented exceptions).
const KNOWN_EXCEPTIONS: &[&str] = &[
    // Named for the ARM processor module, but the file is an x86 PE.
    "arm_bad_pubdefs.aof",
    // A MIPS little-endian ECOFF (per its header and `file`), loaded into IDA as NDS32.
    "nds32_dsp.bin",
    // .NET native image (NGen) compiled for ARM: ARM is the right answer.
    "cli_system.windows.ni.pe",
];

const MAX_READ: usize = 4 << 20;

fn expectation(name: &str) -> Option<&'static Expect> {
    PREFIXES.iter().find(|(p, _)| name.starts_with(p)).map(|(_, e)| e)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Outcome {
    Correct,
    Wrong,
    Inconclusive,
    Error,
    UnsupportedOk,
    FalseClaim,
}

fn read_limited(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?.take(MAX_READ as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

#[test]
fn idaref_classification_suite() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("idaref");
    if !dir.exists() {
        eprintln!("idaref/ not present, skipping");
        return;
    }
    let options = ClassifierOptions {
        detect_extensions: false,
        max_scan_bytes: 256 * 1024,
        ..ClassifierOptions::new()
    };

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !SKIP_SUFFIXES.iter().any(|s| n.ends_with(s)) && !KNOWN_EXCEPTIONS.contains(&n.as_str()))
        .collect();
    names.sort();

    let mut per_prefix: BTreeMap<String, BTreeMap<Outcome, usize>> = BTreeMap::new();
    let mut failures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unmapped = 0usize;

    for name in &names {
        let Some(expect) = expectation(name) else {
            unmapped += 1;
            continue;
        };
        let data = read_limited(&dir.join(name)).expect("read");
        let r = detect_payload(&data, &options);
        let (outcome, got) = match (expect, r) {
            (Is(isas), Ok(p)) => {
                let hit = isas.contains(&p.primary.isa) || p.slices.iter().any(|s| isas.contains(&s.isa));
                if hit {
                    (Outcome::Correct, p.primary.isa.to_string())
                } else if matches!(p.primary.isa, Unknown(_)) {
                    (Outcome::Inconclusive, p.primary.isa.to_string())
                } else {
                    (Outcome::Wrong, p.primary.isa.to_string())
                }
            }
            (Is(_), Err(ClassifierError::HeuristicInconclusive { .. } | ClassifierError::FileTooSmall { .. })) => {
                (Outcome::Inconclusive, "-".into())
            }
            (Is(_), Err(e)) => (Outcome::Error, e.to_string()),
            (Unsupported, Ok(p)) if !matches!(p.primary.isa, Unknown(_)) => {
                // A header that names some ISA we map is not a heuristic false
                // claim; count it separately so the report shows it.
                let _ = p.primary.source == ClassificationSource::FileFormat;
                (Outcome::FalseClaim, p.primary.isa.to_string())
            }
            (Unsupported, _) => (Outcome::UnsupportedOk, "-".into()),
        };
        let prefix = PREFIXES.iter().find(|(p, _)| name.starts_with(p)).map_or("?", |(p, _)| p);
        *per_prefix.entry(prefix.to_string()).or_default().entry(outcome).or_default() += 1;
        if matches!(outcome, Outcome::Wrong | Outcome::FalseClaim | Outcome::Error) {
            failures
                .entry(format!("{outcome:?} {prefix} -> {got}"))
                .or_default()
                .push(name.clone());
        }
    }

    let mut totals: BTreeMap<Outcome, usize> = BTreeMap::new();
    eprintln!("\n{:<22} {:>7} {:>6} {:>6} {:>6} {:>6} {:>6}", "prefix", "correct", "wrong", "incon", "error", "unsOK", "false");
    for (prefix, o) in &per_prefix {
        let g = |k| o.get(&k).copied().unwrap_or(0);
        eprintln!(
            "{:<22} {:>7} {:>6} {:>6} {:>6} {:>6} {:>6}",
            prefix,
            g(Outcome::Correct),
            g(Outcome::Wrong),
            g(Outcome::Inconclusive),
            g(Outcome::Error),
            g(Outcome::UnsupportedOk),
            g(Outcome::FalseClaim)
        );
        for (k, v) in o {
            *totals.entry(*k).or_default() += v;
        }
    }
    eprintln!("\nFAILURES:");
    for (k, files) in &failures {
        eprintln!("  {k}: {} e.g. {}", files.len(), files.iter().take(3).cloned().collect::<Vec<_>>().join(", "));
    }
    let g = |k| totals.get(&k).copied().unwrap_or(0);
    let supported = g(Outcome::Correct) + g(Outcome::Wrong) + g(Outcome::Inconclusive) + g(Outcome::Error);
    let unsupported = g(Outcome::UnsupportedOk) + g(Outcome::FalseClaim);
    let pct = |a: usize, n: usize| 100.0 * a as f64 / n.max(1) as f64;
    eprintln!(
        "\nsupported: {} files, correct {:.1}%, wrong {:.1}%, inconclusive {:.1}%, errors {:.1}%",
        supported,
        pct(g(Outcome::Correct), supported),
        pct(g(Outcome::Wrong), supported),
        pct(g(Outcome::Inconclusive), supported),
        pct(g(Outcome::Error), supported)
    );
    eprintln!(
        "unsupported ISAs: {} files, correctly not claimed {:.1}%; unmapped files: {}",
        unsupported,
        pct(g(Outcome::UnsupportedOk), unsupported),
        unmapped
    );

    // Precision matters most: a wrong ISA is worse than "don't know".
    let decided = g(Outcome::Correct) + g(Outcome::Wrong);
    assert!(pct(g(Outcome::Correct), decided) >= 99.0, "too many wrong answers");
    assert!(pct(decided, supported) >= 88.0, "too many files left undecided");
    assert!(pct(g(Outcome::FalseClaim), unsupported) <= 10.0, "too many false claims on unsupported ISAs");
}
