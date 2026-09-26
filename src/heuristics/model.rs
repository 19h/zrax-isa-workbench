//! Byte-bigram models of machine code, one per ISA variant.
//!
//! Each class is a first-order Markov model over bytes, `P(b[t] | b[t-1])`,
//! trained on ground-truth code (see `scripts/build_corpus.py` and
//! `examples/train_model.rs`). A window of input is scored by its total
//! code length under every model; the model that compresses the window best
//! explains it best. Because every model is scored the same way, costs are
//! directly comparable across ISAs and across window sizes, which is exactly
//! what the old hand-tuned point systems could not provide.
//!
//! Besides the ISA classes, the model contains a few *data* classes
//! (read-only data, text, media, numeric tables) and the implicit uniform
//! distribution (8 bits/byte). Those are what "not code" means: a window that
//! one of them explains best is data, whatever the ISA models think.
//!
//! # File format (all integers little-endian)
//!
//! ```text
//! 0   4   magic "ISAM"
//! 4   2   version (1)
//! 6   2   class count N
//! 8   4   cost scale S (costs are in units of 1/S bits)
//! 12  4   reserved (0)
//! 16  16*N  class names, NUL-padded ASCII
//! ..  65536*N  cost tables, one u8 per (previous byte, byte) pair,
//!              index = prev << 8 | byte, value = round(-log2 P * S)
//! ```

use crate::types::{Endianness, Isa};
use std::sync::OnceLock;

/// File magic.
pub const MAGIC: &[u8; 4] = b"ISAM";
/// Current format version.
pub const VERSION: u16 = 1;
/// Cost units per bit used by the trainer.
///
/// Half-bit resolution: measured on the held-out split it is indistinguishable
/// from 1/16 bit, while 1-bit resolution doubles false accepts on data. Coarse
/// costs also make the table compress well when the model is shipped over
/// HTTP (the WASM build).
pub const COST_SCALE: u32 = 2;
/// Largest per-byte cost the trainer emits, in bits.
pub const MAX_COST_BITS: f64 = 10.0;
/// Size of one cost table.
pub const TABLE_LEN: usize = 256 * 256;
const HEADER_LEN: usize = 16;
const NAME_LEN: usize = 16;

/// What a model class stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKind {
    /// Machine code (or bytecode) of one ISA variant.
    Code {
        /// ISA reported for this class.
        isa: Isa,
        /// Byte order of the instruction stream.
        endianness: Endianness,
        /// Register width reported for this class.
        bitwidth: u8,
        /// Encoding/mode refinement, e.g. `thumb` or `micromips`.
        variant: Option<&'static str>,
    },
    /// Some kind of non-code content.
    Data,
}

/// Static description of a model class, keyed by the class name in the model file.
#[derive(Debug, Clone, Copy)]
pub struct ClassInfo {
    /// Class name as stored in the model file and used by the corpus.
    pub name: &'static str,
    /// Coarse ISA family; margins are measured between families so that
    /// e.g. MIPS32 vs MIPS64 never erodes confidence in "MIPS".
    pub family: &'static str,
    /// What the class represents.
    pub kind: ClassKind,
}

impl ClassInfo {
    /// Whether this is a code class.
    pub fn is_code(&self) -> bool {
        matches!(self.kind, ClassKind::Code { .. })
    }
}

macro_rules! code {
    ($name:literal, $family:literal, $isa:ident, $e:ident, $bits:literal) => {
        ClassInfo {
            name: $name,
            family: $family,
            kind: ClassKind::Code {
                isa: Isa::$isa,
                endianness: Endianness::$e,
                bitwidth: $bits,
                variant: None,
            },
        }
    };
    ($name:literal, $family:literal, $isa:ident, $e:ident, $bits:literal, $variant:literal) => {
        ClassInfo {
            name: $name,
            family: $family,
            kind: ClassKind::Code {
                isa: Isa::$isa,
                endianness: Endianness::$e,
                bitwidth: $bits,
                variant: Some($variant),
            },
        }
    };
}

macro_rules! data {
    ($name:literal) => {
        ClassInfo {
            name: $name,
            family: "data",
            kind: ClassKind::Data,
        }
    };
}

/// Every class name a model file may contain. Unknown names in a model file
/// are ignored, so the table can grow ahead of the shipped model.
pub const CLASSES: &[ClassInfo] = &[
    code!("x86", "x86", X86, Little, 32),
    code!("x86_64", "x86", X86_64, Little, 64),
    code!("arm", "arm", Arm, Little, 32, "a32"),
    code!("thumb", "arm", Arm, Little, 32, "thumb"),
    code!("armeb", "arm", Arm, Big, 32, "a32"),
    code!("thumbeb", "arm", Arm, Big, 32, "thumb"),
    code!("aarch64", "aarch64", AArch64, Little, 64),
    code!("mips", "mips", Mips, Big, 32),
    code!("mipsel", "mips", Mips, Little, 32),
    code!("mips64", "mips", Mips64, Big, 64),
    code!("mips64el", "mips", Mips64, Little, 64),
    code!("micromips", "mips", Mips, Big, 32, "micromips"),
    code!("micromipsel", "mips", Mips, Little, 32, "micromips"),
    code!("ppc", "ppc", Ppc, Big, 32),
    code!("ppc64", "ppc", Ppc64, Big, 64),
    code!("ppc64le", "ppc", Ppc64, Little, 64),
    code!("ppcvle", "ppc", PpcVle, Big, 32, "vle"),
    code!("sparc", "sparc", Sparc, Big, 32),
    code!("sparc64", "sparc", Sparc64, Big, 64),
    code!("s390", "s390", S390, Big, 32),
    code!("s390x", "s390", S390x, Big, 64),
    code!("riscv32", "riscv", RiscV32, Little, 32),
    code!("riscv64", "riscv", RiscV64, Little, 64),
    code!("loongarch32", "loongarch", LoongArch32, Little, 32),
    code!("loongarch64", "loongarch", LoongArch64, Little, 64),
    code!("hexagon", "hexagon", Hexagon, Little, 32),
    code!("avr", "avr", Avr, Little, 8),
    code!("msp430", "msp430", Msp430, Little, 16),
    code!("tricore", "tricore", Tricore, Little, 32),
    code!("lanai", "lanai", Lanai, Big, 32),
    code!("bpf", "bpf", Bpf, Little, 64),
    code!("wasm", "wasm", Wasm, Little, 32),
    code!("jvm", "jvm", Jvm, Big, 32),
    code!("dalvik", "dalvik", Dalvik, Little, 32),
    code!("m68k", "m68k", M68k, Big, 32),
    code!("sh", "sh", Sh, Little, 32),
    code!("sheb", "sh", Sh, Big, 32),
    code!("alpha", "alpha", Alpha, Little, 64),
    code!("hppa", "hppa", Parisc, Big, 32),
    code!("ia64", "ia64", Ia64, Little, 64),
    code!("xtensa", "xtensa", Xtensa, Little, 32),
    code!("xtensaeb", "xtensa", Xtensa, Big, 32),
    code!("arc", "arc", ArcCompact, Little, 32),
    code!("v850", "v850", V850, Little, 32),
    code!("csky", "csky", Csky, Little, 32, "v2"),
    code!("cskyv1", "csky", Csky, Little, 32, "v1"),
    code!("cskyv1eb", "csky", Csky, Big, 32, "v1"),
    code!("c166", "c166", C166, Little, 16),
    code!("rl78", "rl78", Rl78, Little, 16),
    code!("rx", "rx", Rx, Little, 32),
    code!("tic6000", "tic6000", TiC6000, Little, 32),
    code!("tic28x", "tic28x", TiC28x, Little, 32),
    code!("hcs12", "hcs12", Hcs12, Big, 16),
    code!("hc11", "hc11", Hc11, Big, 8),
    code!("s12z", "s12z", S12z, Big, 16),
    code!("fr30", "fr30", Fr30, Big, 32),
    code!("vax", "vax", Vax, Little, 32),
    code!("i960", "i960", I960, Little, 32),
    code!("cellspu", "cellspu", CellSpu, Big, 32),
    code!("microblaze", "microblaze", MicroBlaze, Big, 32),
    code!("microblazeel", "microblaze", MicroBlaze, Little, 32),
    code!("nios2", "nios2", Nios2, Little, 32),
    code!("openrisc", "openrisc", OpenRisc, Big, 32),
    code!("blackfin", "blackfin", Blackfin, Little, 32),
    code!("kvx", "kvx", Kvx, Little, 64),
    code!("h8300", "h8300", H8300, Big, 16),
    code!("m32r", "m32r", M32r, Big, 32),
    code!("m16c", "m16c", M16c, Little, 16),
    code!("nds32", "nds32", Nds32, Little, 32),
    code!("pru", "pru", TiPru, Little, 32),
    code!("frv", "frv", Frv, Big, 32),
    data!("neg_rodata"),
    data!("neg_text"),
    data!("neg_media"),
    data!("neg_table"),
];

/// Look up the static description of a class name.
pub fn class_info(name: &str) -> Option<&'static ClassInfo> {
    CLASSES.iter().find(|c| c.name == name)
}

/// A loaded model: a set of classes and their cost tables.
///
/// Tables borrow from the model bytes; the embedded model is `'static`.
#[derive(Debug, Clone)]
pub struct Model<'a> {
    classes: Vec<(&'static ClassInfo, &'a [u8])>,
    cost_scale: u32,
}

/// Error returned when model bytes are malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError(pub &'static str);

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid ISA model: {}", self.0)
    }
}

impl std::error::Error for ModelError {}

impl<'a> Model<'a> {
    /// Parse a model file. Classes whose names are not in [`CLASSES`] are skipped.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ModelError> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err(ModelError("bad magic"));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(ModelError("unsupported version"));
        }
        let n = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let cost_scale = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if cost_scale == 0 {
            return Err(ModelError("zero cost scale"));
        }
        let names_end = HEADER_LEN + n * NAME_LEN;
        if bytes.len() != names_end + n * TABLE_LEN {
            return Err(ModelError("size does not match class count"));
        }
        let mut classes = Vec::with_capacity(n);
        for i in 0..n {
            let raw = &bytes[HEADER_LEN + i * NAME_LEN..HEADER_LEN + (i + 1) * NAME_LEN];
            let len = raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
            let name = std::str::from_utf8(&raw[..len]).map_err(|_| ModelError("non-UTF-8 class name"))?;
            if let Some(info) = class_info(name) {
                let off = names_end + i * TABLE_LEN;
                classes.push((info, &bytes[off..off + TABLE_LEN]));
            }
        }
        Ok(Self { classes, cost_scale })
    }

    /// Serialize class tables (as produced by [`ModelBuilder`]) into a model file.
    pub fn serialize(classes: &[(String, Vec<u8>)], cost_scale: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + classes.len() * (NAME_LEN + TABLE_LEN));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(classes.len() as u16).to_le_bytes());
        out.extend_from_slice(&cost_scale.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for (name, _) in classes {
            let mut rec = [0u8; NAME_LEN];
            let n = name.len().min(NAME_LEN);
            rec[..n].copy_from_slice(&name.as_bytes()[..n]);
            out.extend_from_slice(&rec);
        }
        for (_, table) in classes {
            assert_eq!(table.len(), TABLE_LEN);
            out.extend_from_slice(table);
        }
        out
    }

    /// The model compiled into the library.
    pub fn embedded() -> &'static Model<'static> {
        static MODEL: OnceLock<Model<'static>> = OnceLock::new();
        MODEL.get_or_init(|| {
            Model::parse(include_bytes!("model.bin")).expect("embedded ISA model is valid")
        })
    }

    /// Number of classes.
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Whether the model has no classes.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Class description by index.
    pub fn class(&self, i: usize) -> &'static ClassInfo {
        self.classes[i].0
    }

    /// Cost table by index (`TABLE_LEN` entries).
    pub fn table(&self, i: usize) -> &'a [u8] {
        self.classes[i].1
    }

    /// Iterate over class descriptions.
    pub fn classes(&self) -> impl Iterator<Item = &'static ClassInfo> + '_ {
        self.classes.iter().map(|(c, _)| *c)
    }

    /// Cost units per bit.
    pub fn cost_scale(&self) -> u32 {
        self.cost_scale
    }
}

/// Accumulates bigram statistics for one class and turns them into a cost table.
#[derive(Clone)]
pub struct ModelBuilder {
    unigram: Vec<u64>,
    bigram: Vec<u64>,
}

impl Default for ModelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelBuilder {
    /// Empty statistics.
    pub fn new() -> Self {
        Self {
            unigram: vec![0; 256],
            bigram: vec![0; TABLE_LEN],
        }
    }

    /// Add one contiguous run of training bytes.
    pub fn add(&mut self, data: &[u8]) {
        for &b in data {
            self.unigram[b as usize] += 1;
        }
        for w in data.windows(2) {
            self.bigram[(w[0] as usize) << 8 | w[1] as usize] += 1;
        }
    }

    /// Number of training bytes seen.
    pub fn bytes(&self) -> u64 {
        self.unigram.iter().sum()
    }

    /// Build the quantized cost table.
    ///
    /// `P(b | a) = (n(a,b) + alpha * P(b)) / (n(a) + alpha)`: rare contexts
    /// back off to the class's own byte distribution.
    pub fn build(&self, alpha: f64, cost_scale: u32) -> Vec<u8> {
        let n = self.bytes() as f64;
        let unigram: Vec<f64> = self
            .unigram
            .iter()
            .map(|&c| (c as f64 + 0.5) / (n + 128.0))
            .collect();
        let mut table = vec![0u8; TABLE_LEN];
        for a in 0..256 {
            let row = &self.bigram[a << 8..(a + 1) << 8];
            let na: u64 = row.iter().sum();
            for b in 0..256 {
                let p = (row[b] as f64 + alpha * unigram[b]) / (na as f64 + alpha);
                // Cap at MAX_COST_BITS: a transition never seen in training is
                // unlikely, not impossible, and one odd byte pair must not
                // outweigh a whole window of evidence.
                let cost = (-p.log2()).min(MAX_COST_BITS) * f64::from(cost_scale);
                table[a << 8 | b] = cost.round().clamp(0.0, 255.0) as u8;
            }
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_are_unique_and_fit() {
        for (i, a) in CLASSES.iter().enumerate() {
            assert!(a.name.len() <= NAME_LEN, "{}", a.name);
            for b in &CLASSES[i + 1..] {
                assert_ne!(a.name, b.name);
            }
        }
    }

    #[test]
    fn serialize_round_trip() {
        let mut b = ModelBuilder::new();
        b.add(&[1, 2, 3, 1, 2, 3, 1, 2, 3]);
        let table = b.build(16.0, COST_SCALE);
        let bytes = Model::serialize(
            &[("x86".into(), table.clone()), ("not-a-class".into(), table.clone())],
            COST_SCALE,
        );
        let m = Model::parse(&bytes).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.class(0).name, "x86");
        assert_eq!(m.table(0), &table[..]);
        // Seen transitions must be cheaper than unseen ones.
        assert!(m.table(0)[1 << 8 | 2] < m.table(0)[1 << 8 | 3]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(Model::parse(b"nope").is_err());
        let mut bytes = Model::serialize(&[], COST_SCALE);
        bytes[4] = 9;
        assert!(Model::parse(&bytes).is_err());
    }

    #[test]
    fn embedded_model_loads() {
        let m = Model::embedded();
        assert_eq!(m.cost_scale(), COST_SCALE);
    }
}
