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
mod sh4;
mod w65816;
mod z80;

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

/// Least code windows of the decided family in an input of at least
/// [`LARGE_INPUT_WINDOWS`] informative windows. One strong 1 KiB window
/// reaches 0.86 confidence on its own. In the fw1 corpus (2026-11-04), 66
/// raw files were decided by a single window in an input this large; 34 of
/// them are ECU calibration maps, and most of the rest GPU microcode,
/// vendor update blobs and ECU dumps whose answers the ISA does not fit.
/// One window is therefore not evidence for a whole image; smaller inputs,
/// where one window is most of the input, are unaffected. The bound is 8
/// informative windows: fw1 golden code files decided by one window have at
/// most 6, while Qualcomm data segments accepted on one pointer-table
/// window have 8 to 11 (2026-11-04).
const MIN_CODE_WINDOWS: usize = 2;
const LARGE_INPUT_WINDOWS: usize = 8;

/// Sparse code: fewer than one code window per [`SPARSE_CODE_RATIO`]
/// informative windows. Chance strong windows grow with the input, and one
/// window just over the strong margin gives 0.86, so sparse evidence must be
/// clearly stronger than that ([`SPARSE_MIN_CONFIDENCE`]). In the fw1 set
/// (2026-11-04), 40 answered raw files were this sparse: the wrong ones
/// (camera, toy and Qualcomm images read as MN10300, PIC, C-SKY or FR30)
/// were at 0.84-0.86, while firmware updates with a small uncompressed code
/// part (SH, Alpha, x86-64, MIPS) were at 0.98-0.99. The ratio was 128
/// until a byte lane of Namco System 21 DSP data (`sv1-data-l.bin`) read as
/// µ'nSP at 0.86 from 2 of 240 windows; at 64 the other stored readings it
/// affects are five byte-swapped 68000 ECU dumps (68000 at 0.85 from 2 or 3
/// windows, recovered by the byte-swap reading) and two `faceauth`
/// segments whose answer comes from their boot marker (fw1, 2026-11-04).
const SPARSE_CODE_RATIO: usize = 64;
const SPARSE_MIN_CONFIDENCE: f64 = 0.9;

/// A window whose most common byte covers this fraction is padding.
const PADDING_FRACTION: f64 = 0.90;
/// A window whose most common aligned 16- or 32-bit word covers this
/// fraction of its words is padding too: erased 14-bit PIC program words
/// (`0x3FFF`), tables of one repeated pointer, and 16-bit bitmaps that are
/// mostly background colour are fill with sparse content, not evidence. Such
/// sprite windows of an `SPG2xx` game ROM (`29dl640e.u3`) measure 0.77-0.83 and
/// were read as x86 at 0.99; 4 of 44,472 code windows of the shipped corpus
/// (30 samples per class) reach 0.7 (fw1 audit, 2026-11-04).
const WORD_FILL_FRACTION: f64 = 0.70;
/// Word widths, in bytes, of the word-fill test.
const FILL_WORD_WIDTHS: [usize; 2] = [2, 4];
/// A window with fewer distinct adjacent byte pairs than this is fill too: a
/// few short values repeated (flat image areas, unrolled stores) match some
/// class's handful of cheap pairs by chance. 0.08% of the corpus's code
/// windows have fewer (827,023 non-fill windows, 2026-11-04); the median
/// uncompressed-image window has 6.
const MIN_DISTINCT_PAIRS: usize = 16;
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
    /// Multiplier of the weak-window false-alarm allowance: the number of
    /// alternative readings of the input that were tried (1 normally).
    trials: f64,
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
        let allowance = self.false_alarm_allowance();
        let mut v: Vec<_> = self
            .family_weights()
            .into_iter()
            .map(|f| (f.family, f.bytes, f.strong + (f.weak - allowance).max(0.0)))
            .collect();
        v.sort_by(|a, b| b.2.total_cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(b.0)));
        v
    }

    /// Code bytes and window weights won by each family, in no order.
    fn family_weights(&self) -> Vec<FamilyWeight> {
        let mut weights: HashMap<&'static str, FamilyWeight> = HashMap::new();
        for (w, class, margin, _) in self.code_windows() {
            let family = self.model.class(class).family;
            let e = weights.entry(family).or_insert(FamilyWeight {
                family,
                bytes: 0,
                strong: 0.0,
                weak: 0.0,
            });
            e.bytes += w.len;
            if margin >= STRONG_MARGIN {
                e.strong += window_weight(margin, w.len);
            } else {
                e.weak += window_weight(margin, w.len);
            }
        }
        weights.into_values().collect()
    }

    /// Summed weight of weak windows that chance hits in data can reach.
    fn false_alarm_allowance(&self) -> f64 {
        FALSE_ALARM_PER_WINDOW * self.trials * self.informative_windows() as f64
    }

    /// The family with the most evidence before the false-alarm allowance.
    /// The allowance is the same for every family, so it decides whether a
    /// family's evidence is above chance (the confidence), not which family's
    /// evidence is largest: ranking after it, where it clamps weak evidence
    /// to zero, let one strong window of another family outrank many weak
    /// windows of one family (fw1, 2026-11-04: Sega SH-4 boot ROMs read as
    /// ARM, Thumb firmware as PowerPC, an interleaved 68000 program as MIPS).
    fn most_supported_family(&self) -> Option<&'static str> {
        most_supported(self.family_weights())
    }

    /// Number of windows that were not padding.
    fn informative_windows(&self) -> usize {
        self.windows.iter().filter(|w| w.kind != WindowKind::Padding).count()
    }

    /// Code windows won by `family`.
    fn family_windows(&self, family: &str) -> usize {
        self.code_windows()
            .filter(|&(_, class, _, _)| self.model.class(class).family == family)
            .count()
    }

    /// Bytes in code windows won by `family`, as a share of the scanned
    /// bytes that were not padding.
    // Both counts are bounded by the input size; a share needs no more than
    // f64's 52-bit mantissa.
    #[allow(clippy::cast_precision_loss)]
    fn informative_share(&self, family: &str) -> f64 {
        let informative: usize = self
            .windows
            .iter()
            .filter(|w| w.kind != WindowKind::Padding)
            .map(|w| w.len)
            .sum();
        let won: usize = self
            .code_windows()
            .filter(|&(_, class, _, _)| self.model.class(class).family == family)
            .map(|(w, ..)| w.len)
            .sum();
        if informative == 0 {
            0.0
        } else {
            won as f64 / informative as f64
        }
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
        let family = self.most_supported_family()?;
        let &(_, _, family_weight) = votes.iter().find(|v| v.0 == family)?;
        let code_bytes: usize = votes.iter().map(|v| v.1).sum();
        let total_weight: f64 = votes.iter().map(|v| v.2).sum();
        let evidence = self.class_evidence(Some(family));
        let best = (0..self.model.len())
            .filter(|&i| self.model.class(i).family == family)
            .max_by(|&a, &b| evidence[a].total_cmp(&evidence[b]))?;
        let class = supported_variant(self.model, best, &evidence);
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

    /// `decision`, or the Z80 variant when the decision is 8080/8085 but a
    /// linear Z80 decode of the family's code windows finds more Z80
    /// prefix-group instructions than 8080/8085 code holds
    /// ([`MIN_PREFIX_GROUP_SHARE_FOR_Z80`]).
    fn checked_z80_variant(&self, data: &[u8], decision: Decision) -> Decision {
        if decision.info.name != "i8085" {
            return decision;
        }
        let code = self.family_code(data, decision.info.family);
        let z80 = (0..self.model.len()).find(|&i| self.model.class(i).name == "z80");
        match z80 {
            Some(class) if z80::prefix_group_share(&code) > MIN_PREFIX_GROUP_SHARE_FOR_Z80 => {
                Decision {
                    class,
                    info: self.model.class(class),
                    ..decision
                }
            }
            _ => decision,
        }
    }

    /// The class to report for `decision`: the 65816 when the decision is
    /// the 6502 but its code windows switch to the 65816's native mode
    /// ([`MIN_NATIVE_MODE_INSTRUCTIONS`], [`MIN_NATIVE_MODE_PER_MILLE`]).
    /// The 65816 has no model data: 65816 code reads as 6502 code, which its
    /// emulation mode runs.
    fn checked_6502_variant(&self, data: &[u8], decision: &Decision) -> &'static ClassInfo {
        if decision.info.name != "mos6502" {
            return decision.info;
        }
        let count = w65816::native_mode_count(&self.family_code(data, decision.info.family));
        let per_mille = 1000.0 * f64::from(count.native) / f64::from(count.instructions.max(1));
        let is_native =
            count.native >= MIN_NATIVE_MODE_INSTRUCTIONS && per_mille >= MIN_NATIVE_MODE_PER_MILLE;
        match class_info("w65816") {
            Some(info) if is_native => info,
            _ => decision.info,
        }
    }

    /// The class to report for `decision`: the SH-4 when the decision is
    /// SH and its code windows hold SH-4-only instructions, at least
    /// [`MIN_SH4_ONLY_INSTRUCTIONS`] and [`MIN_SH4_ONLY_PER_MILLE`], in the
    /// decision's byte order. SH-4
    /// code reads as SH code, which the SH-4 runs; without those
    /// instructions the bytes do not tell it from SH-2 or SH-3 code.
    fn checked_sh_variant(&self, data: &[u8], decision: &Decision) -> &'static ClassInfo {
        let (le, sh4) = match decision.info.name {
            "sh" => (true, "sh4"),
            "sheb" => (false, "sh4eb"),
            _ => return decision.info,
        };
        let count = sh4::sh4_only_count(&self.family_code(data, decision.info.family), le);
        let is_sh4 = count.sh4_only >= MIN_SH4_ONLY_INSTRUCTIONS
            && count.per_mille() >= MIN_SH4_ONLY_PER_MILLE;
        match class_info(sh4) {
            Some(info) if is_sh4 => info,
            _ => decision.info,
        }
    }

    /// The class to report for `decision`, after the variant checks the
    /// byte model cannot make: 65816 over 6502, SH-4 over other SH code.
    fn reported_class(&self, data: &[u8], decision: &Decision) -> &'static ClassInfo {
        match decision.info.family {
            "6502" => self.checked_6502_variant(data, decision),
            "sh" => self.checked_sh_variant(data, decision),
            _ => decision.info,
        }
    }

    /// The bytes of the code windows won by classes of `family`, in order.
    fn family_code(&self, data: &[u8], family: &str) -> Vec<u8> {
        self.code_windows()
            .filter(|&(_, class, _, _)| self.model.class(class).family == family)
            .flat_map(|(w, ..)| data[w.offset..w.offset + w.len].iter().copied())
            .collect()
    }
}

/// Variants whose instruction set extends another's, as (superset, base)
/// model classes, forming the chain eZ80 > Z80 > 8080/8085. Z80 code is also
/// valid eZ80 code, and 8080 code valid Z80 code, so an image of the base
/// fits both classes; the base is the claim the bytes support unless the
/// superset's encodings make its class clearly better. A Z80 answer reduced
/// to 8080/8085 returns to Z80 on prefix-group evidence
/// ([`Scan::checked_z80_variant`]).
const SUPERSET_VARIANTS: &[(&str, &str)] = &[("ez80", "z80"), ("z80", "i8085")];
/// Least ratio of superset to base evidence for the superset variant.
/// TI-84 CE eZ80 code measures 2.0-2.6, Z80 ROMs that chose eZ80 1.0-1.5
/// (fw1 corpus, 2026-11-04). Z80 to 8080/8085 evidence on the fw1 program
/// ROMs whose MAME driver names the CPU: 0.41-1.0 for the 21 8080/8085 ROMs,
/// 0.75-8.8 for the Z80 ROMs, most of which below the ratio hold prefix-group
/// instructions.
const SUPERSET_EVIDENCE_RATIO: f64 = 1.75;

/// Most Z80 prefix-group instructions, as a share of a linear decode of the
/// Z80 family's code windows, that an 8080/8085 answer may contain; above it
/// the answer is Z80 (8080 code is Z80 code; the Z80 adds instructions).
/// Relative jumps are not counted: the 8085 executes instructions at those
/// opcodes (see `z80.rs`). On the fw1 program ROMs whose MAME driver names
/// the CPU (whole files, 2026-11-04), the 21 8080/8085 ROMs measure
/// 0-0.06%, and the Z80 ROMs the model read as 8080/8085 0.4-30%.
const MIN_PREFIX_GROUP_SHARE_FOR_Z80: f64 = 0.002;

/// Least 65816 native-mode instructions (`REP`/`SEP` of the register-width
/// flags, `XCE` after `CLC`/`SEC`; see `w65816.rs`) in the 6502 family's code
/// windows, and least of them per thousand instructions, for a 65816 answer.
/// On the fw1 set (whole files, 2026-11-04), the 6502 ROMs whose MAME driver
/// names the CPU and the 6502 training samples hold 0-3 (at most 0.36 per
/// thousand); `W65C816` ROMs (MAME `we816`), the CMD `SuperCPU` ROM, SNES copier
/// BIOS ROMs and an Apple II SCSI card ROM that enters native mode hold
/// 42-168 (2.7-35.7 per thousand).
const MIN_NATIVE_MODE_INSTRUCTIONS: u32 = 8;
const MIN_NATIVE_MODE_PER_MILLE: f64 = 1.0;

/// Least SH-4-only instructions (see `sh4.rs`) in the SH family's code
/// windows, and least of them per thousand instructions, for an SH-4
/// answer. In MAME-identified fw1 ROMs (2026-11-04), SH-2 code windows
/// (SH7604, SH7032, SH7043A) hold 0 to 2 (at most 0.10 per thousand) and
/// Sega NAOMI BIOS ROMs 121 to 1,260 (3.6 to 5.6 per thousand); each GCC
/// SH training sample holds at most 2, which in a small program's code
/// windows can pass 1 per thousand.
const MIN_SH4_ONLY_INSTRUCTIONS: u32 = 8;
const MIN_SH4_ONLY_PER_MILLE: f64 = 1.0;

/// `class`, or the base variant it extends when the evidence does not
/// clearly favor the superset.
fn supported_variant(model: &Model, class: usize, evidence: &[f64]) -> usize {
    let mut supported = class;
    // One step per pair at most: the pairs form chains without cycles.
    for _ in 0..SUPERSET_VARIANTS.len() {
        match base_variant(model, supported) {
            Some(base) if evidence[supported] < SUPERSET_EVIDENCE_RATIO * evidence[base] => {
                supported = base;
            }
            _ => break,
        }
    }
    supported
}

/// The model class of the base variant that `class` extends, if any.
fn base_variant(model: &Model, class: usize) -> Option<usize> {
    let name = model.class(class).name;
    let &(_, base_name) = SUPERSET_VARIANTS
        .iter()
        .find(|(superset, _)| *superset == name)?;
    (0..model.len()).find(|&i| model.class(i).name == base_name)
}

/// Code bytes and window weights one family won in a scan.
struct FamilyWeight {
    family: &'static str,
    bytes: usize,
    /// Summed weight of windows at or above [`STRONG_MARGIN`].
    strong: f64,
    /// Summed weight of the other code windows.
    weak: f64,
}

/// Window weights within this share of the largest tie: the summed weight
/// does not resolve smaller differences. Shifting the 1 KiB window grid of
/// the four Sega Hikaru BIOS ROMs (SH-4 boot code and an ARM sound program
/// of about equal size) by 128 to 896 B moved a family's summed weight by up
/// to 3.6% and swapped the two families in two of the ROMs (fw1,
/// 2026-11-04).
const WEIGHT_TIE_SHARE: f64 = 0.05;

/// The family of `weights` with the most window weight, see
/// [`Scan::most_supported_family`]. Families within [`WEIGHT_TIE_SHARE`] of
/// the most weight tie; a tie goes to the most code bytes, then the most
/// weight, then the first name.
fn most_supported(weights: Vec<FamilyWeight>) -> Option<&'static str> {
    let total = |f: &FamilyWeight| f.strong + f.weak;
    let largest = weights.iter().map(total).fold(0.0, f64::max);
    weights
        .into_iter()
        .filter(|f| total(f) >= largest * (1.0 - WEIGHT_TIE_SHARE))
        .max_by(|a, b| {
            a.bytes
                .cmp(&b.bytes)
                .then(total(a).total_cmp(&total(b)))
                .then(b.family.cmp(a.family))
        })
        .map(|f| f.family)
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
        || FILL_WORD_WIDTHS.iter().any(|&width| is_word_fill(w, width))
        || has_few_distinct_pairs(w)
}

/// Whether the window has fewer than [`MIN_DISTINCT_PAIRS`] distinct
/// adjacent byte pairs. Windows of one or two bytes have none and are left
/// to the other tests.
fn has_few_distinct_pairs(w: &[u8]) -> bool {
    if w.len() < 2 {
        return false;
    }
    let mut seen = [0u64; 1024];
    let mut distinct = 0usize;
    for pair in w.windows(2) {
        let index = usize::from(pair[0]) << 8 | usize::from(pair[1]);
        let bit = 1u64 << (index % 64);
        if seen[index / 64] & bit == 0 {
            seen[index / 64] |= bit;
            distinct += 1;
            if distinct >= MIN_DISTINCT_PAIRS {
                return false;
            }
        }
    }
    true
}

/// Whether one aligned `width`-byte value covers [`WORD_FILL_FRACTION`] of
/// the window's words. A value above half the words is the majority, so a
/// majority vote finds the only candidate.
fn is_word_fill(w: &[u8], width: usize) -> bool {
    let mut candidate: &[u8] = &[];
    let mut lead = 0usize;
    for word in w.chunks_exact(width) {
        if lead == 0 {
            candidate = word;
            lead = 1;
        } else if word == candidate {
            lead += 1;
        } else {
            lead -= 1;
        }
    }
    let words = w.chunks_exact(width).count();
    let matching = w
        .chunks_exact(width)
        .filter(|&word| word == candidate)
        .count();
    // Window lengths are bounded by the window size, far below u32::MAX.
    let words = f64::from(u32::try_from(words).unwrap_or(u32::MAX));
    let matching = f64::from(u32::try_from(matching).unwrap_or(u32::MAX));
    words > 0.0 && matching >= WORD_FILL_FRACTION * words
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
    scan_with_trials(data, model, window, budget, 1)
}

/// Extra total margin, in bits, a window needs when `trials` readings of
/// the input are tried: a union bound over `trials` chances of a false
/// accept costs `log2(trials)` bits.
fn trial_penalty_bits(trials: usize) -> f64 {
    trial_count(trials).log2().ceil()
}

/// `trials` as a float, at least one.
fn trial_count(trials: usize) -> f64 {
    f64::from(u32::try_from(trials.max(1)).unwrap_or(u32::MAX))
}

/// [`scan`] for one of `trials` alternative readings of an input (byte
/// swaps, de-interleaving, spare-area removal). Each window needs
/// `log2(trials)` more bits of total margin, and the weak-window
/// false-alarm allowance is multiplied by `trials`.
fn scan_with_trials<'m>(
    data: &[u8],
    model: &'m Model<'m>,
    window: usize,
    budget: usize,
    trials: usize,
) -> Scan<'m> {
    let min_margin_bits = MIN_MARGIN_BITS + trial_penalty_bits(trials);
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
                if margin >= MIN_MARGIN_BITS_PER_BYTE && margin_bits >= min_margin_bits {
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

    Scan {
        model,
        trials: trial_count(trials),
        windows,
        code_costs,
    }
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

/// [`analyze_detailed`] for one of `trials` alternative readings of the
/// same input, with the union-bound penalty of [`scan_with_trials`].
pub fn analyze_detailed_with_trials(
    data: &[u8],
    options: &ClassifierOptions,
    trials: usize,
) -> (Result<ClassificationResult>, Vec<ArchitectureScore>) {
    analyze_detailed_with_model_trials(data, options, Model::embedded(), trials)
}

fn analyze_detailed_with_model(
    data: &[u8],
    options: &ClassifierOptions,
    model: &Model,
) -> (Result<ClassificationResult>, Vec<ArchitectureScore>) {
    analyze_detailed_with_model_trials(data, options, model, 1)
}

fn analyze_detailed_with_model_trials(
    data: &[u8],
    options: &ClassifierOptions,
    model: &Model,
    trials: usize,
) -> (Result<ClassificationResult>, Vec<ArchitectureScore>) {
    let reading = analyze_reading_with_model(data, options, model, trials);
    (reading.result, reading.scores)
}

/// One reading of an input: its classification, the candidate scores, and
/// how much of the input the decided ISA family explains.
#[derive(Debug)]
pub struct Reading {
    /// The classification, or why there is none.
    pub result: Result<ClassificationResult>,
    /// Candidate scores, as [`analyze_detailed_with_trials`] returns them.
    pub scores: Vec<ArchitectureScore>,
    /// Bytes in code windows won by the decided family, as a share (0-1) of
    /// the informative (non-padding) bytes scanned; 0 without a decision.
    pub code_share: f64,
    /// Code windows won by the decided family, and informative windows
    /// scanned.
    pub code_windows: usize,
    /// Windows scanned that were not padding.
    pub informative_windows: usize,
}

/// Classify `data` like [`analyze_detailed_with_trials`] and also report how
/// much of it the decided family explains. A reading that only a handful of
/// strong windows support has a small `code_share` even at high confidence.
pub fn analyze_reading(data: &[u8], options: &ClassifierOptions, trials: usize) -> Reading {
    analyze_reading_with_model(data, options, Model::embedded(), trials)
}

fn analyze_reading_with_model(
    data: &[u8],
    options: &ClassifierOptions,
    model: &Model,
    trials: usize,
) -> Reading {
    if data.len() < MIN_WINDOW {
        return Reading {
            result: Err(ClassifierError::FileTooSmall {
                expected: MIN_WINDOW,
                actual: data.len(),
            }),
            scores: Vec::new(),
            code_share: 0.0,
            code_windows: 0,
            informative_windows: 0,
        };
    }
    let budget = scan_budget(data.len(), options);
    let scan = scan_with_trials(data, model, DEFAULT_WINDOW, budget, trials);
    let candidates = candidates_from_scan(&scan);
    let inconclusive = |confidence: f64| ClassifierError::HeuristicInconclusive {
        confidence: confidence * 100.0,
        threshold: options.min_confidence * 100.0,
    };
    let decision = scan.decide().map(|d| scan.checked_z80_variant(data, d));
    let code_share = decision.map_or(0.0, |d| scan.informative_share(d.info.family));
    let code_windows = decision.map_or(0, |d| scan.family_windows(d.info.family));
    let informative_windows = scan.informative_windows();
    let sparse = ClassifierError::HeuristicSparseCode {
        code_windows,
        informative_windows,
    };
    let result = match decision {
        None => Err(inconclusive(0.0)),
        Some(d) if d.confidence < options.min_confidence => Err(inconclusive(d.confidence)),
        Some(_) if code_windows < MIN_CODE_WINDOWS && informative_windows >= LARGE_INPUT_WINDOWS => {
            Err(sparse)
        }
        Some(d)
            if code_windows * SPARSE_CODE_RATIO < informative_windows
                && d.confidence < SPARSE_MIN_CONFIDENCE =>
        {
            Err(sparse)
        }
        Some(d) => result_for(scan.reported_class(data, &d), d.confidence)
            .ok_or_else(|| inconclusive(0.0))
            .map(|mut r| {
                if options.detect_extensions {
                    r.extensions = crate::extensions::detect_from_code(data, r.isa, r.endianness);
                }
                r
            }),
    };
    Reading {
        result,
        scores: candidates,
        code_share,
        code_windows,
        informative_windows,
    }
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
    // Classes of one ISA, bit width and byte order merge into one candidate.
    // The candidates stay in model order, so the confidence sum and the order
    // of candidates that tie on score are the same on every run (a hash map
    // made both depend on its random seed).
    let mut merged: Vec<((Isa, u8, Endianness), f64)> = Vec::new();
    for i in 0..model.len() {
        if let ClassKind::Code { isa, endianness, bitwidth, .. } = model.class(i).kind {
            let key = (isa, bitwidth, endianness);
            match merged.iter_mut().find(|(candidate, _)| *candidate == key) {
                Some((_, best)) => *best = best.max(evidence[i]),
                None => merged.push((key, evidence[i])),
            }
        }
    }
    let positive: f64 = merged
        .iter()
        .map(|(_, ev)| *ev)
        .filter(|ev| *ev > 0.0)
        .sum();
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
    /// Toy code (`toy_x86`, `toy_arm`) cycles the last byte through the values
    /// the model saw: one repeated word, or fewer than 16 distinct byte pairs,
    /// is fill (`is_padding`).
    fn toy_model() -> Vec<u8> {
        let mut x86 = ModelBuilder::new();
        let mut arm = ModelBuilder::new();
        let mut rodata = ModelBuilder::new();
        for i in 0..20_000u32 {
            x86.add(&[0x90, 0x90, 0xC3, (i % 7) as u8]);
            arm.add(&[0xE1, 0xA0, 0x00, 0x01 + (i % 9) as u8]);
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

    #[test]
    fn windows_filled_by_one_word_are_padding() {
        // Erased 14-bit PIC program memory: 0x3FFF stored little-endian.
        let erased: Vec<u8> = [0xff, 0x3f].repeat(512);
        assert!(is_padding(&erased));
        // A table of one handler pointer, with a few other entries.
        let mut table: Vec<u8> = 0xF010_6ECC_u32.to_le_bytes().repeat(256);
        table[0..4].copy_from_slice(&0xF010_6DFC_u32.to_le_bytes());
        assert!(is_padding(&table));
        // Words that differ are not fill, even when two bytes alternate
        // with other values.
        let varied: Vec<u8> = (0..1024u32)
            .flat_map(|i| [0x90, u8::try_from(i % 13).expect("below 13")])
            .collect();
        assert!(!is_padding(&varied));
        assert!(!is_word_fill(&[], 4));
    }

    #[test]
    fn mostly_background_bitmaps_are_padding() {
        // A 16-bit sprite window: background colour 0x8914 in three of four
        // pixels, varied pixels in the rest.
        let sprite: Vec<u8> = (0..512u16)
            .flat_map(|i| {
                let pixel = if i % 4 == 3 {
                    0x5500 | (i * 37 % 251)
                } else {
                    0x8914
                };
                pixel.to_le_bytes()
            })
            .collect();
        assert!(is_word_fill(&sprite, 2));
        // Two pixels in three on background is not enough.
        let busy: Vec<u8> = (0..512u16)
            .flat_map(|i| {
                let pixel = if i % 3 == 2 {
                    0x5500 | (i * 37 % 251)
                } else {
                    0x8914
                };
                pixel.to_le_bytes()
            })
            .collect();
        assert!(!is_word_fill(&busy, 2));
    }

    #[test]
    fn windows_of_a_few_repeated_values_are_padding() {
        // Two RGB565 colors in alternating runs: three distinct byte pairs.
        let flat: Vec<u8> = [[0x59, 0xce].repeat(40), [0xba, 0xd6].repeat(24)]
            .concat()
            .repeat(8);
        assert!(has_few_distinct_pairs(&flat));
        assert!(is_padding(&flat));
        let varied: Vec<u8> = (0..=255u8).collect();
        assert!(!has_few_distinct_pairs(&varied));
        assert!(!has_few_distinct_pairs(&[0x00]));
    }

    /// A model with the Z80 family's plain, eZ80 and 8080/8085 classes.
    fn z80_model() -> Vec<u8> {
        let mut z80 = ModelBuilder::new();
        let mut ez80 = ModelBuilder::new();
        let mut i8085 = ModelBuilder::new();
        z80.add(&[0x3e, 0x01, 0xc9]);
        ez80.add(&[0x5b, 0x21, 0x00]);
        i8085.add(&[0x20, 0x30, 0xc9]);
        Model::serialize(
            &[
                ("z80".into(), z80.build(16.0, model::COST_SCALE)),
                ("ez80".into(), ez80.build(16.0, model::COST_SCALE)),
                ("i8085".into(), i8085.build(16.0, model::COST_SCALE)),
            ],
            model::COST_SCALE,
        )
    }

    #[test]
    fn superset_variant_needs_clearly_more_evidence_than_its_base() {
        let bytes = z80_model();
        let model = Model::parse(&bytes).unwrap();
        let (z80, ez80, i8085) = (0, 1, 2);
        assert_eq!(model.class(z80).name, "z80");
        assert_eq!(model.class(i8085).name, "i8085");
        // eZ80 ahead, but not by the ratio: the Z80 claim is the one supported.
        assert_eq!(
            supported_variant(&model, ez80, &[1000.0, 1500.0, 100.0]),
            z80
        );
        // eZ80 encodings dominate.
        assert_eq!(
            supported_variant(&model, ez80, &[1000.0, 2000.0, 100.0]),
            ez80
        );
        // Plain Z80 is never promoted.
        assert_eq!(supported_variant(&model, z80, &[1000.0, 100.0, 100.0]), z80);
        // Z80 not clearly ahead of 8080/8085: the 8080 claim is supported,
        // also at the end of the chain from eZ80.
        assert_eq!(
            supported_variant(&model, z80, &[1000.0, 100.0, 800.0]),
            i8085
        );
        assert_eq!(
            supported_variant(&model, ez80, &[1000.0, 1500.0, 900.0]),
            i8085
        );
        assert_eq!(
            supported_variant(&model, i8085, &[1000.0, 1500.0, 900.0]),
            i8085
        );
    }

    fn repeat(pattern: &[u8], n: usize) -> Vec<u8> {
        pattern.iter().copied().cycle().take(n).collect()
    }

    /// `n` bytes of toy code: `head` followed by each of `last` in turn.
    fn toy_code(head: [u8; 3], last: std::ops::Range<u8>, n: usize) -> Vec<u8> {
        let pattern: Vec<u8> = last.flat_map(|b| [head[0], head[1], head[2], b]).collect();
        repeat(&pattern, n)
    }

    fn toy_x86(n: usize) -> Vec<u8> {
        toy_code([0x90, 0x90, 0xC3], 0..7, n)
    }

    fn toy_arm(n: usize) -> Vec<u8> {
        toy_code([0xE1, 0xA0, 0x00], 1..10, n)
    }

    #[test]
    fn classifies_by_likelihood() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let opts = ClassifierOptions::new();
        let r = analyze_with_model(&toy_x86(4096), &opts, &model).unwrap();
        assert_eq!(r.isa, Isa::X86);
        let r = analyze_with_model(&toy_arm(4096), &opts, &model).unwrap();
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
        let code = toy_arm(8192);
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
        let code = toy_arm(8192);
        data[4096..4096 + code.len()].copy_from_slice(&code);
        let opts = ClassifierOptions { max_scan_bytes: 64 * 1024, ..ClassifierOptions::new() };
        let r = analyze_with_model(&data, &opts, &model).unwrap();
        assert_eq!(r.isa, Isa::Arm);
    }

    #[test]
    fn many_weak_windows_outrank_one_strong_window_of_another_family() {
        let weight = |family, bytes, strong, weak| FamilyWeight {
            family,
            bytes,
            strong,
            weak,
        };
        // 61 weak 68000 windows against one strong MIPS window: the
        // allowance would zero the 68000 evidence, but it is the larger.
        let weights = vec![
            weight("mips", 10 * 1024, 0.96, 3.6),
            weight("m68k", 61 * 1024, 0.0, 25.06),
        ];
        assert_eq!(most_supported(weights), Some("m68k"));
        // Equal weight: more bytes, then the first name.
        let tie = vec![weight("b", 2048, 1.0, 0.0), weight("a", 1024, 1.0, 0.0)];
        assert_eq!(most_supported(tie), Some("b"));
        let tie = vec![weight("b", 1024, 1.0, 0.0), weight("a", 1024, 1.0, 0.0)];
        assert_eq!(most_supported(tie), Some("a"));
        // Weight within 5% of the most ties and goes to more bytes (the
        // Hikaru BIOS `epr-23400.ic94`: 31 SH windows, 28 stronger ARM
        // windows); beyond it, weight decides.
        let near = vec![
            weight("arm", 28 * 1024, 19.0, 6.70),
            weight("sh", 31 * 1024, 16.0, 9.41),
        ];
        assert_eq!(most_supported(near), Some("sh"));
        let apart = vec![
            weight("arm", 28 * 1024, 19.0, 6.70),
            weight("sh", 31 * 1024, 16.0, 8.00),
        ];
        assert_eq!(most_supported(apart), Some("arm"));
        assert_eq!(most_supported(Vec::new()), None);
    }

    #[test]
    fn multi_isa_reports_both_regions() {
        let bytes = toy_model();
        let model = Model::parse(&bytes).unwrap();
        let mut data = toy_x86(16 * 1024);
        data.extend(toy_arm(16 * 1024));
        let s = scan(&data, &model, 1024, data.len());
        let fams: Vec<_> = s.family_votes().into_iter().map(|v| v.0).collect();
        assert_eq!(fams.len(), 2);
        assert!(fams.contains(&"x86") && fams.contains(&"arm"));
    }
}
