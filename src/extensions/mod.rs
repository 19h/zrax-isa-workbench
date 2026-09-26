//! ISA extension detection from decoded instructions.
//!
//! Extensions are reported only on evidence from *decoded instructions in code*:
//!
//! 1. The input is reduced to the byte ranges that the embedded statistical
//!    model classifies as code of the ISA family being analysed
//!    ([`crate::heuristics::code_regions`]). Headers, string tables, literal
//!    data and padding never reach the decoders. No code, no extensions.
//! 2. Each region is swept linearly by a per-ISA decoder that knows the
//!    instruction boundaries (x86 length decoding, RISC-V 16/32-bit parcels,
//!    fixed-width words elsewhere) and classifies every decoded instruction by
//!    its exact encoding (opcode, mandatory prefix, VEX/EVEX fields, funct
//!    fields, ...).
//! 3. Instructions are tallied in blocks. A block containing an encoding the
//!    decoder knows to be invalid is thrown away as a whole: random data and a
//!    desynchronised sweep produce invalid encodings quickly, real code does
//!    not.
//! 4. An extension is reported only if its instruction count clears both an
//!    absolute minimum and a minimum share of all decoded instructions (see
//!    [`ExtDef`]), and, for vector ISAs whose encoding space is large, only if
//!    an instruction that any real use of the extension needs (vector length
//!    setup, predicate setup, ...) is present as well.
//!
//! Silence is preferred over a wrong claim: ISAs for which the encodings can
//! not be pinned down precisely have no detector.

mod aarch64;
mod alpha;
mod arm;
mod loongarch;
mod mips;
mod ppc;
mod riscv;
mod s390x;
mod x86;

use crate::types::{Endianness, Extension, ExtensionCategory, Isa};

/// Scan budget handed to [`crate::heuristics::code_regions`].
const SCAN_BUDGET: usize = 4 << 20;

/// Default minimum number of instruction hits for an extension.
///
/// One or two matching encodings can come from a stray data word that made it
/// into a code window, or from the first instructions of a region whose start
/// is not an instruction boundary; three independent hits in clean blocks
/// practically never do (see the corpus checks in the module tests).
const DEFAULT_MIN_HITS: u32 = 3;

/// Default share: at least one hit per `DEFAULT_PER` decoded instructions.
///
/// 1/2000 = 0.05%, for extensions that occupy a *large* encoding space
/// (x86 SSE/AVX/AVX-512, AArch64 Advanced SIMD/SVE/SME, ARM VFP/NEON, RISC-V
/// V, PowerPC VMX/VSX, z/Architecture vectors, LoongArch LSX/LASX, MIPS MSA),
/// where a data word that survives block gating can look like an
/// instruction. Code that really uses such an extension through a compiler
/// (auto-vectorisation, intrinsics) produces far more than that.
const DEFAULT_PER: u32 = 2000;

/// Share for *narrow* extensions, recognised by exact or near-exact encodings
/// (at least ~16 fixed bits: LSE atomics, CRC32, AES/SHA/PMULL, PAC/BTI,
/// BMI/POPCNT/LZCNT, RDRAND, bit-manipulation and M/A on RISC-V, ...).
///
/// Such code is often small (a CRC routine, a handful of atomics, one AES
/// key schedule) in a large program. Stray hits are rare: over 19.7M decoded
/// AArch64 instructions of Debian arm64 binaries all narrow classes together
/// had 5 stray hits (1 per 4M), over 22.8M x86-64 instructions of Debian
/// amd64 binaries there were none. 1/50000 keeps a margin of about 80x.
const NARROW_PER: u32 = 50_000;

/// How an extension is decided from the tallies.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExtDef {
    /// Reported name.
    pub name: &'static str,
    /// Reported category.
    pub category: ExtensionCategory,
    /// Minimum number of hits.
    pub min_hits: u32,
    /// Minimum share of hits: `hits * per >= decoded instructions`.
    pub per: u32,
    /// Another entry (by index) that must have at least one hit.
    pub anchor: Option<usize>,
    /// Internal evidence class (an anchor), never reported.
    pub hidden: bool,
}

impl ExtDef {
    /// A reported extension with the default evidence rule.
    pub const fn new(name: &'static str, category: ExtensionCategory) -> Self {
        Self {
            name,
            category,
            min_hits: DEFAULT_MIN_HITS,
            per: DEFAULT_PER,
            anchor: None,
            hidden: false,
        }
    }

    /// A reported extension recognised by exact encodings (see [`NARROW_PER`]).
    pub const fn narrow(name: &'static str, category: ExtensionCategory) -> Self {
        Self::new(name, category).rule(DEFAULT_MIN_HITS, NARROW_PER)
    }

    /// An internal evidence class used as an anchor; never reported.
    pub const fn hidden(name: &'static str) -> Self {
        Self {
            hidden: true,
            ..Self::new(name, ExtensionCategory::Other)
        }
    }

    /// Override the evidence rule.
    pub const fn rule(mut self, min_hits: u32, per: u32) -> Self {
        self.min_hits = min_hits;
        self.per = per;
        self
    }

    /// Require at least one hit of the named entry of `defs` as well.
    pub const fn anchored(mut self, defs_anchor_index: usize) -> Self {
        self.anchor = Some(defs_anchor_index);
        self
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Index of `name` in `defs`; fails compilation (in const context) if absent.
pub(crate) const fn index_of(defs: &[ExtDef], name: &str) -> usize {
    assert!(defs.len() <= 64, "at most 64 evidence classes per ISA");
    let mut i = 0;
    while i < defs.len() {
        if str_eq(defs[i].name, name) {
            return i;
        }
        i += 1;
    }
    panic!("unknown extension name")
}

/// Evidence bit of `name` in `defs`; fails compilation (in const context) if absent.
pub(crate) const fn bit_of(defs: &[ExtDef], name: &str) -> u64 {
    1u64 << index_of(defs, name)
}

/// Accumulates per-extension instruction hits over clean blocks.
///
/// Decoders report every decoded instruction with [`Tally::insn`] (with the
/// evidence bits it carries, possibly none) and every undecodable position
/// with [`Tally::invalid`]. Instructions are grouped into blocks of
/// `block_len` decode steps; a block that contains an invalid step
/// contributes nothing, neither hits nor instruction count.
#[derive(Debug)]
pub(crate) struct Tally {
    block_len: u32,
    hits: [u64; 64],
    decoded: u64,
    blk_masks: Vec<u64>,
    blk_steps: u32,
    blk_valid: u32,
    blk_bad: bool,
}

impl Tally {
    pub fn new(block_len: u32) -> Self {
        Self {
            block_len: block_len.max(1),
            hits: [0; 64],
            decoded: 0,
            blk_masks: Vec::new(),
            blk_steps: 0,
            blk_valid: 0,
            blk_bad: false,
        }
    }

    /// A decoded instruction carrying the evidence bits `mask`.
    #[inline]
    pub fn insn(&mut self, mask: u64) {
        self.blk_steps += 1;
        self.blk_valid += 1;
        if mask != 0 {
            self.blk_masks.push(mask);
        }
        if self.blk_steps >= self.block_len {
            self.flush();
        }
    }

    /// An undecodable position: the current block is discarded.
    #[inline]
    pub fn invalid(&mut self) {
        self.blk_steps += 1;
        self.blk_bad = true;
        if self.blk_steps >= self.block_len {
            self.flush();
        }
    }

    /// Close the current block (at region ends, or at caller-defined chunk ends).
    pub fn flush(&mut self) {
        if !self.blk_bad {
            self.decoded += u64::from(self.blk_valid);
            for &m in &self.blk_masks {
                let mut m = m;
                while m != 0 {
                    let b = m.trailing_zeros() as usize;
                    self.hits[b] += 1;
                    m &= m - 1;
                }
            }
        }
        self.blk_masks.clear();
        self.blk_steps = 0;
        self.blk_valid = 0;
        self.blk_bad = false;
    }

    /// Instructions counted (in clean blocks).
    #[cfg(test)]
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// Hits of evidence class `i` (in clean blocks).
    #[cfg(test)]
    pub fn hits(&self, i: usize) -> u64 {
        self.hits[i]
    }

    /// The extensions of `defs` whose evidence clears their rule.
    pub fn report(&self, defs: &[ExtDef]) -> Vec<Extension> {
        let mut out = Vec::new();
        for (i, d) in defs.iter().enumerate() {
            if d.hidden {
                continue;
            }
            let h = self.hits[i];
            if h < u64::from(d.min_hits) || h * u64::from(d.per) < self.decoded {
                continue;
            }
            if let Some(a) = d.anchor {
                if self.hits[a] == 0 {
                    continue;
                }
            }
            out.push(Extension::with_confidence(d.name, d.category, confidence(h, d.min_hits)));
        }
        out
    }
}

/// Confidence from the hit count: 0.6 at the minimum, approaching 0.99 as
/// the evidence grows (0.85 about 16 hits above the minimum).
fn confidence(hits: u64, min_hits: u32) -> f64 {
    let extra = hits.saturating_sub(u64::from(min_hits)) as f64;
    (0.6 + 0.39 * (1.0 - (-extra / 16.0).exp())).min(0.99)
}

/// A per-ISA detector.
struct Detector {
    defs: &'static [ExtDef],
    block_len: u32,
    scan: fn(&[u8], Isa, Endianness, &mut Tally),
}

fn detector(isa: Isa) -> Option<Detector> {
    Some(match isa {
        Isa::X86 | Isa::X86_64 => Detector { defs: x86::EXTS, block_len: 64, scan: x86::scan },
        Isa::AArch64 => Detector { defs: aarch64::EXTS, block_len: 64, scan: aarch64::scan },
        Isa::RiscV32 | Isa::RiscV64 => {
            Detector { defs: riscv::EXTS, block_len: 64, scan: riscv::scan }
        }
        Isa::Arm => Detector { defs: arm::EXTS, block_len: arm::CHUNK as u32, scan: arm::scan },
        Isa::LoongArch32 | Isa::LoongArch64 => {
            Detector { defs: loongarch::EXTS, block_len: 64, scan: loongarch::scan }
        }
        Isa::S390 | Isa::S390x => Detector { defs: s390x::EXTS, block_len: 64, scan: s390x::scan },
        Isa::Ppc | Isa::Ppc64 => Detector { defs: ppc::EXTS, block_len: 64, scan: ppc::scan },
        Isa::Mips | Isa::Mips64 => Detector { defs: mips::EXTS, block_len: 64, scan: mips::scan },
        Isa::Alpha => Detector { defs: alpha::EXTS, block_len: 64, scan: alpha::scan },
        _ => return None,
    })
}

/// Run the detector for `isa` over explicit code ranges of `data`.
fn detect_in_regions(
    data: &[u8],
    regions: &[(usize, usize)],
    isa: Isa,
    endianness: Endianness,
) -> Vec<Extension> {
    let Some(d) = detector(isa) else {
        return Vec::new();
    };
    let mut tally = Tally::new(d.block_len);
    for &(off, len) in regions {
        let Some(code) = data.get(off..off.saturating_add(len)) else {
            continue;
        };
        (d.scan)(code, isa, endianness, &mut tally);
        tally.flush();
    }
    tally.report(d.defs)
}

/// Detect extensions from code analysis.
///
/// Only the parts of `data` that the embedded model classifies as code of
/// `isa`'s family are decoded; if there are none, nothing is reported.
pub fn detect_from_code(data: &[u8], isa: Isa, endianness: Endianness) -> Vec<Extension> {
    if detector(isa).is_none() {
        return Vec::new();
    }
    let regions = crate::heuristics::code_regions(data, isa, SCAN_BUDGET);
    if regions.is_empty() {
        return Vec::new();
    }
    detect_in_regions(data, &regions, isa, endianness)
}

/// The extensions [`detect_from_code`] can report for an ISA.
pub fn known_extensions(isa: Isa) -> Vec<(&'static str, ExtensionCategory)> {
    detector(isa)
        .map(|d| d.defs.iter().filter(|e| !e.hidden).map(|e| (e.name, e.category)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// Run a detector over `code` as one region, with thresholds as in production.
    pub fn detect(code: &[u8], isa: Isa, endianness: Endianness) -> Vec<String> {
        detect_in_regions(code, &[(0, code.len())], isa, endianness)
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    /// Per-class raw hit counts of a detector over `code` (one region, no thresholds).
    pub fn hits(code: &[u8], isa: Isa, endianness: Endianness) -> Vec<(&'static str, u64)> {
        let d = detector(isa).expect("detector");
        let mut tally = Tally::new(d.block_len);
        (d.scan)(code, isa, endianness, &mut tally);
        tally.flush();
        d.defs
            .iter()
            .enumerate()
            .filter(|(i, _)| tally.hits(*i) > 0)
            .map(|(i, e)| (e.name, tally.hits(i)))
            .collect()
    }

    /// Repeat `unit` until `n` bytes.
    pub fn repeat(unit: &[u8], n: usize) -> Vec<u8> {
        unit.iter().copied().cycle().take(n).collect()
    }

    /// Little-endian bytes of 32-bit words.
    pub fn le_words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Big-endian bytes of 32-bit words.
    pub fn be_words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions_lists_reportable_names() {
        let x86 = known_extensions(Isa::X86_64);
        for n in ["SSE2", "AVX", "AVX2", "AVX-512", "AES-NI", "FMA", "BMI2", "APX"] {
            assert!(x86.iter().any(|(name, _)| *name == n), "{n}");
        }
        let a64 = known_extensions(Isa::AArch64);
        for n in ["SVE", "PAC", "BTI", "LSE", "CRC32", "AES"] {
            assert!(a64.iter().any(|(name, _)| *name == n), "{n}");
        }
        let rv = known_extensions(Isa::RiscV64);
        for n in ["M", "A", "F", "D", "C", "V", "Zba", "Zbb"] {
            assert!(rv.iter().any(|(name, _)| *name == n), "{n}");
        }
        let arm = known_extensions(Isa::Arm);
        assert!(arm.iter().any(|(name, _)| *name == "NEON"));
        assert!(!arm.iter().any(|(name, _)| name.starts_with("Thumb")));
        assert!(known_extensions(Isa::Hexagon).is_empty());
    }

    #[test]
    fn tables_fit_and_names_are_unique() {
        for isa in [
            Isa::X86_64,
            Isa::AArch64,
            Isa::RiscV64,
            Isa::Arm,
            Isa::LoongArch64,
            Isa::S390x,
            Isa::Ppc64,
            Isa::Mips,
            Isa::Alpha,
        ] {
            let d = detector(isa).unwrap();
            assert!(d.defs.len() <= 64);
            for (i, a) in d.defs.iter().enumerate() {
                assert!(d.defs[i + 1..].iter().all(|b| b.name != a.name), "{isa:?} {}", a.name);
                if let Some(x) = a.anchor {
                    assert!(x < d.defs.len());
                }
            }
        }
    }

    #[test]
    fn block_gating_discards_blocks_with_invalid_steps() {
        let mut t = Tally::new(4);
        t.insn(1);
        t.insn(1);
        t.invalid();
        t.insn(1); // block of 4 closes: discarded
        t.insn(1);
        t.insn(0);
        t.flush(); // partial clean block counts
        assert_eq!(t.decoded(), 2);
        assert_eq!(t.hits(0), 1);
    }

    #[test]
    fn thresholds_need_count_and_share() {
        const DEFS: &[ExtDef] = &[ExtDef::new("X", ExtensionCategory::Simd)];
        let mut t = Tally::new(1_000_000);
        for _ in 0..2 {
            t.insn(1);
        }
        t.flush();
        assert!(t.report(DEFS).is_empty(), "two hits are not enough");
        let mut t = Tally::new(1_000_000);
        for _ in 0..3 {
            t.insn(1);
        }
        for _ in 0..10_000 {
            t.insn(0);
        }
        t.flush();
        assert!(t.report(DEFS).is_empty(), "3 in 10003 is below 1/2000");
        let mut t = Tally::new(1_000_000);
        for _ in 0..10 {
            t.insn(1);
        }
        for _ in 0..10_000 {
            t.insn(0);
        }
        t.flush();
        let r = t.report(DEFS);
        assert_eq!(r.len(), 1);
        assert!(r[0].confidence > 0.6 && r[0].confidence < 0.99);
    }

    #[test]
    fn confidence_grows_with_hits() {
        assert!(confidence(3, 3) < confidence(10, 3));
        assert!(confidence(10, 3) < confidence(100, 3));
        assert!(confidence(100_000, 3) <= 0.99);
    }

    /// Diagnostics over real files: `EXTDET_LIST` names a file with one
    /// `<isa> <path>` per line (isa: x86, x86_64, aarch64, arm, armeb,
    /// riscv64, ...). Prints regions, instruction count, raw evidence and the
    /// verdict per file, plus a summary of how often each extension was reported.
    #[test]
    #[ignore]
    fn extdet_diag() {
        let Ok(list) = std::env::var("EXTDET_LIST") else {
            return;
        };
        let verbose = std::env::var("EXTDET_VERBOSE").is_ok();
        let mut summary: std::collections::BTreeMap<String, usize> = Default::default();
        let mut files = 0usize;
        let start = std::time::Instant::now();
        let mut scan_time = std::time::Duration::ZERO;
        let mut code_bytes = 0usize;
        for line in std::fs::read_to_string(list).unwrap().lines() {
            let mut it = line.split_whitespace();
            let (Some(isa), Some(path)) = (it.next(), it.next()) else {
                continue;
            };
            let (isa, e) = match isa {
                "x86" => (Isa::X86, Endianness::Little),
                "x86_64" => (Isa::X86_64, Endianness::Little),
                "aarch64" => (Isa::AArch64, Endianness::Little),
                "arm" => (Isa::Arm, Endianness::Little),
                "armeb" => (Isa::Arm, Endianness::Big),
                "riscv64" => (Isa::RiscV64, Endianness::Little),
                "riscv32" => (Isa::RiscV32, Endianness::Little),
                "loongarch64" => (Isa::LoongArch64, Endianness::Little),
                "s390x" => (Isa::S390x, Endianness::Big),
                "ppc64" => (Isa::Ppc64, Endianness::Big),
                "ppc64le" => (Isa::Ppc64, Endianness::Little),
                "ppc" => (Isa::Ppc, Endianness::Big),
                "mips" => (Isa::Mips, Endianness::Big),
                "mipsel" => (Isa::Mips, Endianness::Little),
                "mips64el" => (Isa::Mips64, Endianness::Little),
                "alpha" => (Isa::Alpha, Endianness::Little),
                other => panic!("isa {other}"),
            };
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            files += 1;
            let regions = crate::heuristics::code_regions(&data, isa, SCAN_BUDGET);
            let d = detector(isa).unwrap();
            let mut t = Tally::new(d.block_len);
            let mut n = 0usize;
            let t0 = std::time::Instant::now();
            for &(off, len) in &regions {
                (d.scan)(&data[off..off + len], isa, e, &mut t);
                t.flush();
                n += len;
            }
            scan_time += t0.elapsed();
            code_bytes += n;
            let found = t.report(d.defs);
            for f in &found {
                *summary.entry(f.name.clone()).or_default() += 1;
            }
            if verbose {
                let raw: Vec<String> = d
                    .defs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| t.hits(*i) > 0)
                    .map(|(i, x)| format!("{}={}", x.name, t.hits(i)))
                    .collect();
                let names: Vec<String> =
                    found.iter().map(|f| format!("{}({:.2})", f.name, f.confidence)).collect();
                println!(
                    "{path}: regions={} code={}B decoded={} raw[{}] => {}",
                    regions.len(),
                    n,
                    t.decoded(),
                    raw.join(" "),
                    names.join(",")
                );
            }
        }
        let el = start.elapsed();
        println!(
            "files={files} code={code_bytes}B total={el:?} decode={scan_time:?} ({:.1} ms/MB)",
            scan_time.as_secs_f64() * 1e3 / (code_bytes.max(1) as f64 / 1048576.0)
        );
        for (k, v) in summary {
            println!("  {k}: {v}");
        }
    }

    /// Print the context of every x86 instruction carrying `EXTDET_BIT` evidence
    /// (by name) in `EXTDET_FILE`.
    #[test]
    #[ignore]
    fn extdet_where_x86() {
        let (Ok(file), Ok(name)) = (std::env::var("EXTDET_FILE"), std::env::var("EXTDET_BIT")) else {
            return;
        };
        let data = std::fs::read(file).unwrap();
        let bit = 1u64 << x86::EXTS.iter().position(|e| e.name == name).unwrap();
        for (off, len) in crate::heuristics::code_regions(&data, Isa::X86_64, SCAN_BUDGET) {
            let code = &data[off..off + len];
            let mut pos = 0;
            let mut n = 0;
            while pos < code.len() {
                match x86::decode(&code[pos..], true) {
                    x86::Decoded::Insn { len, ext } => {
                        if ext & bit != 0 {
                            let a = pos.saturating_sub(24);
                            println!(
                                "region {off:#x}+{pos:#x} (insn #{n}, len {len}): {:02x?} | {:02x?}",
                                &code[a..pos],
                                &code[pos..(pos + 16).min(code.len())]
                            );
                        }
                        pos += len;
                    }
                    x86::Decoded::Invalid => pos += 1,
                    x86::Decoded::Truncated => break,
                }
                n += 1;
            }
        }
    }

    /// Classify every little-endian 32-bit word of `EXTDET_WORDS` with the
    /// word classifier named by `EXTDET_DUMP` (aarch64, riscv64, a32, t32,
    /// loongarch, ppc, mips, alpha) and write one line per word to
    /// `EXTDET_OUT`: `-` if invalid, else the evidence names joined by `+`.
    #[test]
    #[ignore]
    fn dump_words() {
        let (Ok(kind), Ok(inp), Ok(out)) =
            (std::env::var("EXTDET_DUMP"), std::env::var("EXTDET_WORDS"), std::env::var("EXTDET_OUT"))
        else {
            return;
        };
        let (defs, f): (&[ExtDef], Box<dyn Fn(u32) -> Option<u64>>) = match kind.as_str() {
            "aarch64" => (aarch64::EXTS, Box::new(aarch64::classify)),
            "riscv64" => (riscv::EXTS, Box::new(|w| riscv::classify32(w, true))),
            "riscv16" => (riscv::EXTS, Box::new(|w| riscv::classify16(w as u16, true))),
            "a32" => (arm::EXTS, Box::new(|w| Some(arm::classify_a32(w)))),
            "t32" => (arm::EXTS, Box::new(|w| Some(arm::classify_t32(w)))),
            "loongarch" => (loongarch::EXTS, Box::new(loongarch::classify)),
            "ppc" => (ppc::EXTS, Box::new(ppc::classify)),
            "mips" => (mips::EXTS, Box::new(mips::classify)),
            "alpha" => (alpha::EXTS, Box::new(alpha::classify)),
            other => panic!("{other}"),
        };
        let data = std::fs::read(inp).unwrap();
        let mut res = String::with_capacity(data.len() * 2);
        for c in data.chunks_exact(4) {
            match f(u32::from_le_bytes([c[0], c[1], c[2], c[3]])) {
                None => res.push('-'),
                Some(m) => {
                    let names: Vec<&str> =
                        (0..defs.len()).filter(|i| m >> i & 1 != 0).map(|i| defs[i].name).collect();
                    res.push_str(&names.join("+"));
                }
            }
            res.push('\n');
        }
        std::fs::write(out, res).unwrap();
    }

    #[test]
    fn no_code_no_extensions() {
        // Text and padding are not code.
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(200);
        assert!(detect_from_code(&text, Isa::X86_64, Endianness::Little).is_empty());
        assert!(detect_from_code(&vec![0u8; 65536], Isa::AArch64, Endianness::Little).is_empty());
        assert!(detect_from_code(&[], Isa::X86_64, Endianness::Little).is_empty());
    }
}
