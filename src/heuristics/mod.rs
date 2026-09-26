//! Heuristic ISA identification for headerless data (raw firmware, dumps,
//! extracted sections).
//!
//! # How it works
//!
//! The input is cut into windows. Every window is scored against every class
//! of the byte-bigram [`Model`]: the score of a class is the number of bits
//! the window costs to encode under that class's model. Code classes compete
//! with *data* classes (read-only data, text, media, numeric tables) and with
//! the uniform distribution, so a window is only called code when some ISA
//! explains it better than every non-code hypothesis, and by a clear margin
//! over every other ISA family.
//!
//! The primary ISA is the family that wins the most code bytes; the variant
//! within the family (endianness, 32/64-bit, Thumb vs A32, ...) is the class
//! with the lowest total cost over that family's windows. Confidence is the
//! family's share of code windows scaled by the strength of its evidence.
//!
//! There are no per-ISA hand-written rules in here: everything ISA-specific
//! lives in the trained model, which is rebuilt from ground-truth code with
//! `scripts/build_corpus.py` + `examples/train_model.rs`.

pub mod model;

use std::collections::HashMap;

pub use model::{class_info, ClassInfo, ClassKind, Model, ModelBuilder, ModelError, CLASSES};

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, ClassificationSource, ClassifierOptions, Endianness, FileFormat, Isa,
    Variant,
};

/// Default analysis window.
pub const DEFAULT_WINDOW: usize = 1024;
/// Inputs up to this size are scored as a single window.
const SINGLE_WINDOW_MAX: usize = 2 * DEFAULT_WINDOW;
/// Smallest window (tail or whole input) worth scoring.
const MIN_WINDOW: usize = 24;
/// Minimum per-byte margin (bits) of the winning family over every other
/// hypothesis, code or data, for a window to count as code.
///
/// Measured on held-out code: at this margin, windows of 128 bytes and more
/// are wrong well under 0.2% of the time, while ~95% of 1KB code windows pass.
pub const MIN_MARGIN_BITS_PER_BYTE: f64 = 0.4;
/// Minimum total margin (bits) for a window, which only matters for tiny inputs.
const MIN_MARGIN_BITS: f64 = 16.0;
/// Confidence calibration (fitted on the held-out corpus split with
/// `examples/calibrate.rs`).
///
/// Bigram bit counts are wildly overconfident as probabilities, so a window
/// contributes a *weight* instead: a logistic in its per-byte margin, scaled
/// down for windows shorter than 1 KB.
///
/// Data windows occasionally slip past the margin gate (~0.2% of windows),
/// but never with a margin of `STRONG_MARGIN` or more. Strong windows
/// therefore count in full, while the summed weight of weak windows is
/// reduced by `FALSE_ALARM_PER_WINDOW` for every non-padding window scanned:
/// a handful of weak hits in a large data blob cancels out, a small function
/// on its own still gets through. Evidence `E` maps to `1 - exp(-E / EVIDENCE_SCALE)`.
const WEIGHT_MIDPOINT: f64 = 0.6;
const WEIGHT_WIDTH: f64 = 0.15;
const STRONG_MARGIN: f64 = 1.0;
const FALSE_ALARM_PER_WINDOW: f64 = 0.05;
const EVIDENCE_SCALE: f64 = 0.5;

/// Weight of one code window in the confidence estimate.
fn window_weight(margin: f64, len: usize) -> f64 {
    let size = (len as f64 / DEFAULT_WINDOW as f64).sqrt().min(1.0);
    size / (1.0 + (-(margin - WEIGHT_MIDPOINT) / WEIGHT_WIDTH).exp())
}

/// A window whose most common byte covers this fraction is padding.
const PADDING_FRACTION: f64 = 0.90;
/// A window this printable is text. The 99th percentile of real code
/// windows is below 0.8 for every ISA in the corpus.
const TEXT_FRACTION: f64 = 0.90;

/// Aggregate score of one ISA variant over the analysed input.
#[derive(Debug, Clone)]
pub struct ArchitectureScore {
    /// The ISA.
    pub isa: Isa,
    /// Evidence in bits: how much better this class explains the code
    /// windows than the best non-code hypothesis (negative = worse).
    pub raw_score: i64,
    /// This candidate's share of the positive evidence of all candidates
    /// (not a probability; the calibrated decision confidence is on the
    /// classification result).
    pub confidence: f64,
    /// Byte order.
    pub endianness: Endianness,
    /// Register width.
    pub bitwidth: u8,
}

/// What a window turned out to be.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WindowKind {
    /// Dominated by a single byte value (erased flash, zero fill).
    Padding,
    /// Best explained by a non-code model.
    Data,
    /// Some ISA is best, but not by enough to call it.
    Ambiguous {
        /// Model index of the best code class.
        best: usize,
    },
    /// Code of the given model class.
    Code {
        /// Model index of the winning class.
        class: usize,
        /// Margin over the best other family / data hypothesis, bits per byte.
        margin: f64,
    },
}

/// Verdict for one window.
#[derive(Debug, Clone, Copy)]
pub struct WindowVerdict {
    /// Offset of the window in the input.
    pub offset: usize,
    /// Length of the window.
    pub len: usize,
    /// Classification of the window.
    pub kind: WindowKind,
}

/// Result of scanning an input with a model.
#[derive(Debug, Clone)]
pub struct Scan<'m> {
    model: &'m Model<'m>,
    /// Per-window verdicts in input order.
    pub windows: Vec<WindowVerdict>,
    /// For every code window (same order as they appear in `windows`), the
    /// cost of each class in bits minus the cost of the best data hypothesis
    /// (negative = the class explains the window better than data does).
    code_costs: Vec<Vec<f64>>,
}

impl<'m> Scan<'m> {
    /// The model used for the scan.
    pub fn model(&self) -> &'m Model<'m> {
        self.model
    }

    /// Total bytes in code windows.
    pub fn code_bytes(&self) -> usize {
        self.windows
            .iter()
            .filter(|w| matches!(w.kind, WindowKind::Code { .. }))
            .map(|w| w.len)
            .sum()
    }

    /// Total bytes scanned.
    pub fn scanned_bytes(&self) -> usize {
        self.windows.iter().map(|w| w.len).sum()
    }

    fn code_windows(&self) -> impl Iterator<Item = (&WindowVerdict, usize, f64, &Vec<f64>)> {
        self.windows
            .iter()
            .filter_map(|w| match w.kind {
                WindowKind::Code { class, margin } => Some((w, class, margin)),
                _ => None,
            })
            .zip(self.code_costs.iter())
            .map(|((w, c, m), costs)| (w, c, m, costs))
    }

    /// Per family: code bytes won and net evidence (see [`window_weight`]), strongest first.
    pub fn family_votes(&self) -> Vec<(&'static str, usize, f64)> {
        // (bytes, strong weight, weak weight)
        let mut votes: HashMap<&'static str, (usize, f64, f64)> = HashMap::new();
        for (w, class, margin, _) in self.code_windows() {
            let e = votes.entry(self.model.class(class).family).or_default();
            e.0 += w.len;
            if margin >= STRONG_MARGIN {
                e.1 += window_weight(margin, w.len);
            } else {
                e.2 += window_weight(margin, w.len);
            }
        }
        let allowance = FALSE_ALARM_PER_WINDOW * self.informative_windows() as f64;
        let mut v: Vec<_> = votes
            .into_iter()
            .map(|(f, (b, strong, weak))| (f, b, strong + (weak - allowance).max(0.0)))
            .collect();
        v.sort_by(|a, b| b.2.total_cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(b.0)));
        v
    }

    /// Number of windows that were not padding.
    fn informative_windows(&self) -> usize {
        self.windows.iter().filter(|w| w.kind != WindowKind::Padding).count()
    }

    /// Evidence (bits better than data) of every class, summed over the code
    /// windows won by `family` (or all code windows when `family` is `None`).
    pub fn class_evidence(&self, family: Option<&str>) -> Vec<f64> {
        let mut ev = vec![0.0; self.model.len()];
        for (_, class, _, costs) in self.code_windows() {
            if family.is_some_and(|f| self.model.class(class).family != f) {
                continue;
            }
            for (e, c) in ev.iter_mut().zip(costs) {
                *e -= c;
            }
        }
        ev
    }

    /// The decision: best class, confidence, and supporting numbers.
    pub fn decide(&self) -> Option<Decision> {
        let votes = self.family_votes();
        let &(family, _, family_weight) = votes.first()?;
        let code_bytes: usize = votes.iter().map(|v| v.1).sum();
        let total_weight: f64 = votes.iter().map(|v| v.2).sum();
        let evidence = self.class_evidence(Some(family));
        let class = (0..self.model.len())
            .filter(|&i| self.model.class(i).family == family)
            .max_by(|&a, &b| evidence[a].total_cmp(&evidence[b]))?;
        let share = if total_weight > 0.0 { family_weight / total_weight } else { 0.0 };
        let strength = 1.0 - (-family_weight / EVIDENCE_SCALE).exp();
        Some(Decision {
            class,
            info: self.model.class(class),
            confidence: (share * strength).clamp(0.0, 0.99),
            family_share: share,
            code_bytes,
            scanned_bytes: self.scanned_bytes(),
        })
    }
}

/// Outcome of [`Scan::decide`].
#[derive(Debug, Clone, Copy)]
pub struct Decision {
    /// Model index of the chosen class.
    pub class: usize,
    /// Description of the chosen class.
    pub info: &'static ClassInfo,
    /// Calibrated confidence (0-1).
    pub confidence: f64,
    /// Chosen family's share of the (weighted) code evidence.
    pub family_share: f64,
    /// Bytes in code windows.
    pub code_bytes: usize,
    /// Bytes scanned.
    pub scanned_bytes: usize,
}

/// Tile the input into windows (a single window for small inputs).
fn tiles(len: usize, window: usize) -> Vec<(usize, usize)> {
    if len <= SINGLE_WINDOW_MAX.max(window) {
        return if len >= MIN_WINDOW { vec![(0, len)] } else { Vec::new() };
    }
    let full = len / window;
    let mut out: Vec<(usize, usize)> = (0..full).map(|i| (i * window, window)).collect();
    let tail = len - full * window;
    if tail >= MIN_WINDOW * 4 {
        out.push((full * window, tail));
    }
    out
}

/// Pick at most `wanted` of `candidates`, evenly spread (code in a firmware
/// image can be anywhere, and a prefix would miss it).
fn spread(candidates: &[usize], wanted: usize) -> Vec<usize> {
    if candidates.len() <= wanted {
        return candidates.to_vec();
    }
    let wanted = wanted.max(1);
    (0..wanted)
        .map(|i| candidates[i * (candidates.len() - 1) / (wanted - 1).max(1)])
        .collect()
}

fn is_padding(w: &[u8]) -> bool {
    let mut hist = [0u32; 256];
    for &b in w {
        hist[b as usize] += 1;
    }
    let max = hist.iter().copied().max().unwrap_or(0);
    max as f64 >= PADDING_FRACTION * w.len() as f64
}

fn is_text(w: &[u8]) -> bool {
    let printable = w
        .iter()
        .filter(|&&b| (0x20..0x7F).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    printable as f64 >= TEXT_FRACTION * w.len() as f64
}

/// Score one window against every class; returns costs in model units.
fn window_costs(model: &Model, w: &[u8], costs: &mut Vec<u64>) {
    costs.clear();
    let pairs: Vec<u16> = w.windows(2).map(|p| u16::from(p[0]) << 8 | u16::from(p[1])).collect();
    for i in 0..model.len() {
        let t = model.table(i);
        costs.push(pairs.iter().map(|&p| u64::from(t[p as usize])).sum());
    }
}

/// Scan `data` with `model` using windows of `window` bytes, looking at no
/// more than `budget` bytes in total.
pub fn scan<'m>(data: &[u8], model: &'m Model<'m>, window: usize, budget: usize) -> Scan<'m> {
    let window = window.max(MIN_WINDOW * 4);
    let scale = f64::from(model.cost_scale());
    let mut windows = Vec::new();
    let mut code_costs = Vec::new();
    let mut costs = Vec::with_capacity(model.len());

    // Padding is cheap to recognise, so find it everywhere first and spend the
    // scan budget only on the rest: an 8 MB image with 6 KB of code in it
    // must not be sampled into nothing but erased flash.
    let all = tiles(data.len(), window);
    let padding: Vec<bool> = all.iter().map(|&(o, l)| is_padding(&data[o..o + l])).collect();
    let informative: Vec<usize> = (0..all.len()).filter(|&i| !padding[i]).collect();
    let mut chosen = vec![false; all.len()];
    for i in spread(&informative, (budget / window).max(1)) {
        chosen[i] = true;
    }

    for (i, &(off, len)) in all.iter().enumerate() {
        let w = &data[off..off + len];
        if padding[i] {
            windows.push(WindowVerdict { offset: off, len, kind: WindowKind::Padding });
            continue;
        }
        if !chosen[i] {
            continue;
        }
        if is_text(w) {
            windows.push(WindowVerdict { offset: off, len, kind: WindowKind::Data });
            continue;
        }
        window_costs(model, w, &mut costs);
        let pairs = (len - 1) as f64;
        let uniform = 8.0 * pairs * scale;

        let data_best = (0..model.len())
            .filter(|&i| !model.class(i).is_code())
            .map(|i| costs[i] as f64)
            .fold(uniform, f64::min);
        let best_code = (0..model.len())
            .filter(|&i| model.class(i).is_code())
            .min_by_key(|&i| costs[i]);

        let kind = match best_code {
            Some(best) if (costs[best] as f64) < data_best => {
                let family = model.class(best).family;
                let rival = (0..model.len())
                    .filter(|&i| model.class(i).family != family)
                    .map(|i| costs[i] as f64)
                    .fold(uniform, f64::min);
                let margin_bits = (rival - costs[best] as f64) / scale;
                let margin = margin_bits / pairs;
                if margin >= MIN_MARGIN_BITS_PER_BYTE && margin_bits >= MIN_MARGIN_BITS {
                    code_costs.push(costs.iter().map(|&c| (c as f64 - data_best) / scale).collect());
                    WindowKind::Code { class: best, margin }
                } else {
                    WindowKind::Ambiguous { best }
                }
            }
            _ => WindowKind::Data,
        };
        windows.push(WindowVerdict { offset: off, len, kind });
    }

    Scan { model, windows, code_costs }
}

fn scan_budget(data_len: usize, options: &ClassifierOptions) -> usize {
    let budget = if options.fast_mode {
        options.max_scan_bytes.min(64 * 1024)
    } else {
        options.max_scan_bytes
    };
    if options.deep_scan {
        data_len.max(budget)
    } else {
        budget
    }
}

fn result_for(info: &ClassInfo, confidence: f64) -> Option<ClassificationResult> {
    let ClassKind::Code { isa, endianness, bitwidth, variant } = info.kind else {
        return None;
    };
    let mut result = ClassificationResult::from_heuristics(isa, bitwidth, endianness, confidence);
    result.source = ClassificationSource::Heuristic;
    result.format = FileFormat::Raw;
    if let Some(v) = variant {
        result.variant = Variant::new(v);
    }
    Some(result)
}

/// Classify headerless data with the embedded model.
pub fn analyze(data: &[u8], options: &ClassifierOptions) -> Result<ClassificationResult> {
    analyze_with_model(data, options, Model::embedded())
}

/// Classify headerless data with a specific model.
pub fn analyze_with_model(
    data: &[u8],
    options: &ClassifierOptions,
    model: &Model,
) -> Result<ClassificationResult> {
    analyze_detailed_with_model(data, options, model).0
}

/// Classify headerless data and also return the ranked candidates, from a
/// single scan.
pub fn analyze_detailed(
    data: &[u8],
    options: &ClassifierOptions,
) -> (Result<ClassificationResult>, Vec<ArchitectureScore>) {
    analyze_detailed_with_model(data, options, Model::embedded())
}

fn analyze_detailed_with_model(
    data: &[u8],
    options: &ClassifierOptions,
    model: &Model,
) -> (Result<ClassificationResult>, Vec<ArchitectureScore>) {
    if data.len() < MIN_WINDOW {
        return (
            Err(ClassifierError::FileTooSmall { expected: MIN_WINDOW, actual: data.len() }),
            Vec::new(),
        );
    }
    let scan = scan(data, model, DEFAULT_WINDOW, scan_budget(data.len(), options));
    let candidates = candidates_from_scan(&scan);
    let inconclusive = |confidence: f64| ClassifierError::HeuristicInconclusive {
        confidence: confidence * 100.0,
        threshold: options.min_confidence * 100.0,
    };
    let result = match scan.decide() {
        None => Err(inconclusive(0.0)),
        Some(d) if d.confidence < options.min_confidence => Err(inconclusive(d.confidence)),
        Some(d) => result_for(d.info, d.confidence).ok_or_else(|| inconclusive(0.0)).map(|mut r| {
            if options.detect_extensions {
                r.extensions = crate::extensions::detect_from_code(data, r.isa, r.endianness);
            }
            r
        }),
    };
    (result, candidates)
}

/// Per-class scores for the input, best first.
///
/// `raw_score` is the evidence in bits over the code windows found in the
/// input; classes of the same ISA/endianness/bitwidth are merged.
pub fn score_all_architectures(data: &[u8], options: &ClassifierOptions) -> Vec<ArchitectureScore> {
    let model = Model::embedded();
    let scan = scan(data, model, DEFAULT_WINDOW, scan_budget(data.len(), options));
    candidates_from_scan(&scan)
}

fn candidates_from_scan(scan: &Scan) -> Vec<ArchitectureScore> {
    let model = scan.model();
    let evidence = scan.class_evidence(None);
    let mut merged: HashMap<(Isa, u8, Endianness), f64> = HashMap::new();
    for i in 0..model.len() {
        if let ClassKind::Code { isa, endianness, bitwidth, .. } = model.class(i).kind {
            let e = merged.entry((isa, bitwidth, endianness)).or_insert(f64::NEG_INFINITY);
            *e = e.max(evidence[i]);
        }
    }
    let positive: f64 = merged.values().filter(|v| **v > 0.0).sum();
    let mut out: Vec<ArchitectureScore> = merged
        .into_iter()
        .map(|((isa, bitwidth, endianness), ev)| ArchitectureScore {
            isa,
            raw_score: ev.round() as i64,
            confidence: if positive > 0.0 { ev.max(0.0) / positive } else { 0.0 },
            endianness,
            bitwidth,
        })
        .collect();
    out.sort_by(|a, b| b.raw_score.cmp(&a.raw_score).then(a.isa.name().cmp(b.isa.name())));
    out
}

/// The `n` best candidates.
pub fn top_candidates(data: &[u8], n: usize, options: &ClassifierOptions) -> Vec<ArchitectureScore> {
    let mut v = score_all_architectures(data, options);
    v.truncate(n);
    v
}

/// ISA found in some region of a multi-ISA image.
#[derive(Debug, Clone)]
pub struct DetectedIsa {
    /// The ISA detected.
    pub isa: Isa,
    /// Number of windows classified as this ISA family.
    pub window_count: usize,
    /// Total bytes in those windows.
    pub total_bytes: usize,
    /// Average per-window margin over the runner-up hypothesis, bits per byte.
    pub avg_score: f64,
    /// Byte order.
    pub endianness: Endianness,
    /// Register width.
    pub bitwidth: u8,
}

/// Find every ISA that owns a meaningful share of the code in `data`.
///
/// Windows of `window_size` bytes tile the whole input. A family is reported
/// when its calibrated evidence (the same measure that drives single-ISA
/// confidence, false-alarm allowance included) is at least
/// `MULTI_MIN_EVIDENCE` and it owns at least 2% of the code bytes.
pub fn detect_multi_isa(data: &[u8], _options: &ClassifierOptions, window_size: usize) -> Vec<DetectedIsa> {
    detect_multi_isa_with_model(data, Model::embedded(), window_size)
}

/// Minimum net evidence for a family in [`detect_multi_isa`]: one clear 1 KB
/// code window is enough (its weight is ~1), a few weak hits are not.
const MULTI_MIN_EVIDENCE: f64 = 0.35;

/// [`detect_multi_isa`] with a specific model.
pub fn detect_multi_isa_with_model(data: &[u8], model: &Model, window_size: usize) -> Vec<DetectedIsa> {
    let window = window_size.max(MIN_WINDOW * 4);
    let scan = scan(data, model, window, data.len());
    let votes = scan.family_votes();
    let code_bytes: usize = votes.iter().map(|v| v.1).sum();
    let mut out = Vec::new();
    for (family, bytes, evidence) in votes {
        if evidence < MULTI_MIN_EVIDENCE || (bytes as f64) < 0.02 * code_bytes as f64 {
            continue;
        }
        let (windows, margin_sum) = scan
            .code_windows()
            .filter(|(_, c, _, _)| model.class(*c).family == family)
            .fold((0usize, 0.0f64), |(n, m), (_, _, margin, _)| (n + 1, m + margin));
        let class_ev = scan.class_evidence(Some(family));
        let Some(best) = (0..model.len())
            .filter(|&i| model.class(i).family == family)
            .max_by(|&a, &b| class_ev[a].total_cmp(&class_ev[b]))
        else {
            continue;
        };
        if let ClassKind::Code { isa, endianness, bitwidth, .. } = model.class(best).kind {
            out.push(DetectedIsa {
                isa,
                window_count: windows,
                total_bytes: bytes,
                avg_score: margin_sum / windows.max(1) as f64,
                endianness,
                bitwidth,
            });
        }
    }
    out
}

/// Coarse ISA family of `isa` as used by the model (e.g. `Mips` and `Mips64`
/// are both "mips"), or `None` for ISAs the model does not know.
pub fn family_of(isa: Isa) -> Option<&'static str> {
    CLASSES.iter().find_map(|c| match c.kind {
        ClassKind::Code { isa: ci, .. } if ci == isa => Some(c.family),
        _ => None,
    })
}

/// Byte ranges of `data` that the embedded model classifies as code of the
/// same family as `isa` (all windows are scanned, at most `budget` bytes).
///
/// Code-pattern analyses (e.g. extension detection) should look only here:
/// headers, literal pools, string tables and padding are not instructions.
/// Returns an empty list if `isa` is not a model ISA or no window matches.
pub fn code_regions(data: &[u8], isa: Isa, budget: usize) -> Vec<(usize, usize)> {
    let model = Model::embedded();
    let Some(family) = family_of(isa) else {
        return Vec::new();
    };
    let scan = scan(data, model, DEFAULT_WINDOW, budget);
    let mut out: Vec<(usize, usize)> = Vec::new();
    for w in &scan.windows {
        if let WindowKind::Code { class, .. } = w.kind {
            if model.class(class).family == family {
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == w.offset => last.1 += w.len,
                    _ => out.push((w.offset, w.len)),
                }
            }
        }
    }
    out
}

/// ISAs the embedded model can recognise in headerless data.
pub fn supported_isas() -> Vec<Isa> {
    let mut v: Vec<Isa> = Model::embedded()
        .classes()
        .filter_map(|c| match c.kind {
            ClassKind::Code { isa, .. } => Some(isa),
            ClassKind::Data => None,
        })
        .collect();
    v.sort_by_key(|i| i.name());
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A toy model: "x86" loves 0x90 0x90, "arm" loves 0xE1 0xA0, data loves zeros.
    fn toy_model() -> Vec<u8> {
        let mut x86 = ModelBuilder::new();
        let mut arm = ModelBuilder::new();
        let mut rodata = ModelBuilder::new();
        for i in 0..20_000u32 {
            x86.add(&[0x90, 0x90, 0xC3, (i % 7) as u8]);
            arm.add(&[0xE1, 0xA0, 0x00, 0x01 + (i % 5) as u8]);
            rodata.add(&[0x00, 0x00, (i % 3) as u8, 0x00]);
        }
        Model::serialize(
            &[
                ("x86".into(), x86.build(16.0, model::COST_SCALE)),
                ("arm".into(), arm.build(16.0, model::COST_SCALE)),
                ("neg_rodata".into(), rodata.build(16.0, model::COST_SCALE)),
            ],
            model::COST_SCALE,
        )
    }

    fn repeat(pattern: &[u8], n: usize) -> Vec<u8> {
        pattern.iter().copied().cycle().take(n).collect()
    }

    #[test]
    fn classifies_by_likelihood() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let opts = ClassifierOptions::new();
        let r = analyze_with_model(&repeat(&[0x90, 0x90, 0xC3, 0x03], 4096), &opts, &model).unwrap();
        assert_eq!(r.isa, Isa::X86);
        let r = analyze_with_model(&repeat(&[0xE1, 0xA0, 0x00, 0x02], 4096), &opts, &model).unwrap();
        assert_eq!(r.isa, Isa::Arm);
        assert_eq!(r.variant.name, "a32");
    }

    #[test]
    fn data_and_noise_are_rejected() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let opts = ClassifierOptions::new();
        let zeros_ish = repeat(&[0, 0, 1, 0, 0, 0, 2, 0], 4096);
        assert!(matches!(
            analyze_with_model(&zeros_ish, &opts, &model),
            Err(ClassifierError::HeuristicInconclusive { .. })
        ));
        let mut x: u64 = 0x1234_5678;
        let noise: Vec<u8> = (0..8192)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        assert!(analyze_with_model(&noise, &opts, &model).is_err());
        assert!(analyze_with_model(&vec![0xFF; 64 * 1024], &opts, &model).is_err());
    }

    #[test]
    fn padding_does_not_dilute_code() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let mut data = vec![0xFF; 256 * 1024];
        let code = repeat(&[0xE1, 0xA0, 0x00, 0x04], 8192);
        data[100_000..100_000 + code.len()].copy_from_slice(&code);
        let r = analyze_with_model(&data, &ClassifierOptions::new(), &model).unwrap();
        assert_eq!(r.isa, Isa::Arm);
        assert!(r.confidence > 0.9);
    }

    #[test]
    fn tiling_and_sampling() {
        assert_eq!(tiles(10, 1024), vec![]);
        assert_eq!(tiles(100, 1024), vec![(0, 100)]);
        let t = tiles(10 * 1024, 1024);
        assert_eq!(t.len(), 10);
        assert_eq!(t[9], (9 * 1024, 1024));
        let idx: Vec<usize> = (0..1000).collect();
        let s = spread(&idx, 64);
        assert_eq!(s.len(), 64);
        assert_eq!((s[0], s[63]), (0, 999));
        assert_eq!(spread(&idx[..10], 64).len(), 10);
    }

    #[test]
    fn budget_is_spent_on_non_padding() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        // 8 MB of erased flash with 8 KB of code near the start.
        let mut data = vec![0xFF; 8 << 20];
        let code = repeat(&[0xE1, 0xA0, 0x00, 0x04], 8192);
        data[4096..4096 + code.len()].copy_from_slice(&code);
        let opts = ClassifierOptions { max_scan_bytes: 64 * 1024, ..ClassifierOptions::new() };
        let r = analyze_with_model(&data, &opts, &model).unwrap();
        assert_eq!(r.isa, Isa::Arm);
    }

    #[test]
    fn multi_isa_reports_both_regions() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let mut data = repeat(&[0x90, 0x90, 0xC3, 0x01], 16 * 1024);
        data.extend(repeat(&[0xE1, 0xA0, 0x00, 0x03], 16 * 1024));
        let s = scan(&data, &model, 1024, data.len());
        let fams: Vec<_> = s.family_votes().into_iter().map(|v| v.0).collect();
        assert_eq!(fams.len(), 2);
        assert!(fams.contains(&"x86") && fams.contains(&"arm"));
    }
}
