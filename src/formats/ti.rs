//! Texas Instruments firmware containers. Wire specifications and coverage
//! boundaries are recorded in docs/ti-containers.md. No device is inferred
//! from an address or from an unqualified multicore core ID.
use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, Endianness, FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue,
    Variant as CpuVariant,
};
use std::borrow::Cow;

mod fip;
mod mcelf;
mod text;
mod x509;

/// Maximum extracted bytes, independent of destination address gaps.
pub const MAX_PAYLOAD: usize = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    AmbiguousBoot,
    C28xBoot,
    C54xBoot,
    C55xLegacy,
    C6000Boot,
    C31Boot,
    C32Boot,
    C4xBoot,
    Ais,
    Rprc,
    Multicore,
    GpImage,
    OmapImage,
    Oad,
    OadMetadata,
    X509,
    AsciiHex,
    Tagged,
    Tektronix,
    Mcuboot,
    Mcelf,
    Fip,
    CcsData,
}
impl Variant {
    pub const ALL: &'static [Self] = &[
        Self::AmbiguousBoot,
        Self::C28xBoot,
        Self::C54xBoot,
        Self::C55xLegacy,
        Self::C6000Boot,
        Self::C31Boot,
        Self::C32Boot,
        Self::C4xBoot,
        Self::Ais,
        Self::Rprc,
        Self::Multicore,
        Self::GpImage,
        Self::OmapImage,
        Self::Oad,
        Self::OadMetadata,
        Self::X509,
        Self::AsciiHex,
        Self::Tagged,
        Self::Tektronix,
        Self::Mcuboot,
        Self::Mcelf,
        Self::Fip,
        Self::CcsData,
    ];
    pub fn format(self) -> FileFormat {
        match self {
            Self::AmbiguousBoot
            | Self::C28xBoot
            | Self::C54xBoot
            | Self::C55xLegacy
            | Self::C6000Boot
            | Self::C31Boot
            | Self::C32Boot
            | Self::C4xBoot => FileFormat::TiBoot,
            Self::Ais => FileFormat::TiAis,
            Self::Rprc => FileFormat::TiRprc,
            Self::Multicore => FileFormat::TiMulticore,
            Self::GpImage | Self::OmapImage => FileFormat::TiImage,
            Self::Oad | Self::OadMetadata => FileFormat::TiOad,
            Self::X509 => FileFormat::TiX509,
            Self::AsciiHex => FileFormat::TiAsciiHex,
            Self::Tagged => FileFormat::TiTagged,
            Self::Tektronix => FileFormat::TiTekHex,
            Self::Mcuboot => FileFormat::Mcuboot,
            Self::Mcelf => FileFormat::TiMcelf,
            Self::Fip => FileFormat::Fip,
            Self::CcsData => FileFormat::TiData,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::AmbiguousBoot => "Ambiguous C28x/C54x ROM boot table",
            Self::C28xBoot => "C28x ROM boot table",
            Self::C54xBoot => "C54x ROM boot table",
            Self::C55xLegacy => "C5510 boot table",
            Self::C6000Boot => "Unkeyed 32-bit boot table",
            Self::C31Boot => "C31/VC33 ROM boot table",
            Self::C32Boot => "C32 ROM boot table",
            Self::C4xBoot => "C4x ROM boot table",
            Self::Ais => "Application Image Script",
            Self::Rprc => "RPRC",
            Self::Multicore => "Multicore appimage",
            Self::GpImage => "GP ROM image",
            Self::Oad => "OAD image",
            Self::OadMetadata => "OAD external-flash metadata",
            Self::OmapImage => "OMAP CH/GP ROM image",
            Self::X509 => "TI X.509 boot image",
            Self::AsciiHex => "TI ASCII Hex",
            Self::Tagged => "TI SDSMAC tagged",
            Self::Tektronix => "Extended Tektronix",
            Self::Mcuboot => "MCUboot",
            Self::Mcelf => "TI multicore ELF",
            Self::Fip => "TF-A Firmware Image Package",
            Self::CcsData => "CCS GO DSP data",
        }
    }
}

pub(super) fn err(message: impl Into<String>) -> ClassifierError {
    ClassifierError::TiContainerParseError {
        message: message.into(),
    }
}
pub(super) fn bytes(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| err("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| err(format!("Truncated file range 0x{start:X} + {len} B")))
}
pub(super) fn r16(data: &[u8], at: usize, le: bool) -> Result<u16> {
    let b = bytes(data, at, 2)?;
    Ok(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}
pub(super) fn r32(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let b = bytes(data, at, 4)?;
    Ok(if le {
        u32::from_le_bytes(b.try_into().unwrap())
    } else {
        u32::from_be_bytes(b.try_into().unwrap())
    })
}
fn tail(data: &[u8], pos: usize) -> Result<()> {
    if bytes(data, pos, data.len().saturating_sub(pos))?
        .iter()
        .any(|b| *b != 0 && *b != 255)
    {
        return Err(err("Unexpected bytes after image terminator"));
    }
    Ok(())
}
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3).ok_or_else(|| err("Alignment overflow"))? & !3)
}

#[derive(Debug)]
pub struct Section<'a> {
    pub label: String,
    /// Address units are stated in the container notes (bytes unless stated).
    pub address: u64,
    pub offset: usize,
    pub data: Cow<'a, [u8]>,
}
#[derive(Debug)]
pub struct Child<'a> {
    pub label: String,
    pub offset: usize,
    pub data: &'a [u8],
    /// Data-only or encrypted components are never submitted to the ISA model.
    pub opaque: bool,
    /// Processor-specific role markers, when the format defines them uniquely.
    pub isa_hint: Option<(Isa, u8, Endianness)>,
}
#[derive(Debug)]
pub struct Container<'a> {
    pub variant: Variant,
    pub entry: Option<u64>,
    pub sections: Vec<Section<'a>>,
    pub children: Vec<Child<'a>>,
    pub notes: Vec<String>,
    pub consumed: usize,
    pub opaque: bool,
    isa: Isa,
    bits: u8,
    endian: Endianness,
}
impl<'a> Container<'a> {
    pub(super) fn new(variant: Variant) -> Self {
        Self {
            variant,
            entry: None,
            sections: Vec::new(),
            children: Vec::new(),
            notes: Vec::new(),
            consumed: 0,
            opaque: false,
            isa: Isa::Unknown(0),
            bits: 0,
            endian: Endianness::Little,
        }
    }
    pub(super) fn section(
        &mut self,
        address: u64,
        offset: usize,
        data: Cow<'a, [u8]>,
    ) -> Result<()> {
        address
            .checked_add(data.len() as u64)
            .ok_or_else(|| err("Load address overflow"))?;
        self.sections.push(Section {
            label: format!("Load section {}", self.sections.len() + 1),
            address,
            offset,
            data,
        });
        Ok(())
    }
    pub fn classification(&self) -> ClassificationResult {
        let mut r = ClassificationResult::from_format(
            self.isa,
            self.bits,
            self.endian,
            self.variant.format(),
        );
        if matches!(self.isa, Isa::Unknown(_)) {
            r.confidence = 0.0;
        }
        r.variant = CpuVariant::new(self.variant.label());
        r.metadata.entry_point = self.entry;
        r.metadata.section_count = Some(if self.sections.is_empty() {
            self.children.len()
        } else {
            self.sections.len()
        });
        r.metadata.code_size = if self.sections.is_empty() && !self.children.is_empty() {
            None
        } else {
            Some(self.sections.iter().map(|s| s.data.len() as u64).sum())
        };
        r.metadata.notes = self.notes.clone();
        r.metadata.notes.insert(
            0,
            format!(
                "{}; exact device model is not encoded or not uniquely determined",
                self.variant.label()
            ),
        );
        if self.opaque {
            r.metadata
                .notes
                .push("Payload is encrypted or metadata-only; ISA analysis was not applied".into());
        }
        r
    }
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let item = |key: String, label: String, value: MetadataValue| {
            MetadataEntry::new(MetadataKey::Custom(key), value, label)
        };
        let mut v = vec![item(
            "ti_image_size".into(),
            "Container size (B)".into(),
            MetadataValue::Integer(self.consumed as u64),
        )];
        for (i, s) in self.sections.iter().enumerate() {
            v.push(item(
                format!("ti_section_{i}"),
                s.label.clone(),
                MetadataValue::String(format!(
                    "file 0x{:X}; destination 0x{:X}; {} B",
                    s.offset,
                    s.address,
                    s.data.len()
                )),
            ));
        }
        for (i, child) in self.children.iter().enumerate() {
            v.push(item(
                format!("ti_component_{i}"),
                child.label.clone(),
                MetadataValue::String(format!(
                    "file 0x{:X}; {} B{}",
                    child.offset,
                    child.data.len(),
                    if child.opaque || self.opaque {
                        "; opaque"
                    } else {
                        ""
                    }
                )),
            ));
        }
        v
    }
    /// Sparse load ranges are concatenated in stream order; destination gaps
    /// and fill commands never allocate a destination-sized memory image.
    pub fn payload(&self) -> Result<Vec<u8>> {
        if self.opaque {
            return Ok(Vec::new());
        }
        let n = self.sections.iter().try_fold(0usize, |n, s| {
            n.checked_add(s.data.len())
                .filter(|n| *n <= MAX_PAYLOAD)
                .ok_or_else(|| err("Decoded payload exceeds 64 MiB"))
        })?;
        let mut v = Vec::with_capacity(n);
        for s in &self.sections {
            v.extend_from_slice(&s.data);
        }
        Ok(v)
    }
    /// A concatenation across unrelated load ranges is suitable for the code
    /// model, but must not manufacture a nested file header across a gap.
    pub fn nested_payload_is_contiguous(&self) -> bool {
        !matches!(
            self.variant,
            Variant::AsciiHex | Variant::Tagged | Variant::Tektronix
        ) || self.sections.len() == 1
    }
}

/// Magic-bearing families are detected independently of parse success so a
/// corrupted container yields a format error instead of a confident raw ISA.
pub fn detect_strong(data: &[u8]) -> Option<Variant> {
    if data.starts_with(b"RPRC") || data.starts_with(b"CRPR") {
        return Some(Variant::Rprc);
    }
    if data.starts_with(b"MSTR") || data.starts_with(b"RTSM") {
        return Some(Variant::Multicore);
    }
    if data.starts_with(b"TIPA") {
        return Some(Variant::Ais);
    }
    if matches!(
        data.get(..8),
        Some(
            b"CC26x2R1"
                | b"CC13x2R1"
                | b"CC13x4  "
                | b"CC26x3  "
                | b"CC26x4  "
                | b"OAD IMG "
                | b"CC23x0R2"
        )
    ) {
        return Some(Variant::Oad);
    }
    if data.starts_with(b"OAD NVM1") {
        return Some(Variant::OadMetadata);
    }
    if data.starts_with(&0x96f3b83du32.to_le_bytes()) {
        return Some(Variant::Mcuboot);
    }
    if data.starts_with(&0xaa640001u32.to_le_bytes()) {
        return Some(Variant::Fip);
    }
    if mcelf::detect(data) {
        return Some(Variant::Mcelf);
    }
    if data
        .get(20..32)
        .is_some_and(|name| name.starts_with(b"CHSETTINGS"))
    {
        return Some(Variant::OmapImage);
    }
    if x509::detect(data) {
        return Some(Variant::X509);
    }
    if let Some(kind) = text::detect(data) {
        return Some(kind);
    }
    None
}
/// Weak signatures require a complete structure and a loaded entry point.
pub fn detect_weak(data: &[u8]) -> Option<Variant> {
    if data.len() < 4 {
        return None;
    }
    if parse_container(data, Variant::C28xBoot).is_ok()
        && parse_container(data, Variant::C54xBoot).is_ok()
    {
        return Some(Variant::AmbiguousBoot);
    }
    for kind in [
        Variant::C28xBoot,
        Variant::C54xBoot,
        Variant::C31Boot,
        Variant::C32Boot,
        Variant::C4xBoot,
        Variant::C55xLegacy,
        Variant::C6000Boot,
        Variant::GpImage,
    ] {
        if parse_container(data, kind).is_ok() {
            return Some(kind);
        }
    }
    None
}
pub fn parse_container(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    match kind {
        Variant::AmbiguousBoot => {
            parse_container(data, Variant::C28xBoot)?;
            parse_container(data, Variant::C54xBoot)?;
            let mut c = Container::new(kind);
            c.opaque = true;
            c.consumed = data.len();
            c.notes.push(
                "Both C28x and C54x layouts validate; target and payload boundaries are ambiguous"
                    .into(),
            );
            Ok(c)
        }
        Variant::Ais => ais(data),
        Variant::Rprc => rprc(data),
        Variant::Multicore => multicore(data),
        Variant::C28xBoot => word_boot(data, kind, 8),
        Variant::C54xBoot => {
            let mut found = None;
            for registers in [2, 4] {
                if let Ok(c) = word_boot(data, kind, registers) {
                    if found.is_some() {
                        return Err(err("Ambiguous C54x boot-mode header"));
                    }
                    found = Some(c);
                }
            }
            found.ok_or_else(|| err("Invalid C54x parallel/serial boot table"))
        }
        Variant::C55xLegacy => unkeyed(data, true),
        Variant::C6000Boot => unkeyed(data, false),
        Variant::C31Boot | Variant::C32Boot | Variant::C4xBoot => c3_boot(data, kind),
        Variant::GpImage => gp(data),
        Variant::OmapImage => omap(data),
        Variant::Oad => oad(data),
        Variant::OadMetadata => oad_metadata(data),
        Variant::X509 => x509::parse(data),
        Variant::Mcuboot => mcuboot(data),
        Variant::Mcelf => mcelf::parse(data),
        Variant::Fip => fip::parse(data),
        Variant::CcsData => text::ccs(data),
        Variant::AsciiHex | Variant::Tagged | Variant::Tektronix => text::parse(data, kind),
    }
}
pub fn parse(data: &[u8], kind: Variant) -> Result<ClassificationResult> {
    Ok(parse_container(data, kind)?.classification())
}

fn word_boot(data: &[u8], kind: Variant, registers: usize) -> Result<Container<'_>> {
    let key = r16(data, 0, true)?;
    let le = matches!(key, 0x08aa | 0x10aa);
    if !le && !matches!(r16(data, 0, false)?, 0x08aa | 0x10aa) {
        return Err(err("Invalid 8/16-bit ROM boot key"));
    }
    let addr = |at| -> Result<u64> {
        Ok(((r16(data, at, le)? as u64) << 16) | r16(data, at + 2, le)? as u64)
    };
    let limit = if kind == Variant::C54xBoot {
        1u64 << 23
    } else {
        1u64 << 32
    };
    let entry = addr(2 + registers * 2)?;
    if entry >= limit {
        return Err(err("Entry exceeds destination address width"));
    }
    let mut c = Container::new(kind);
    c.entry = Some(entry);
    let mut pos = 6 + registers * 2;
    loop {
        let n = r16(data, pos, le)? as usize;
        pos += 2;
        if n == 0 {
            break;
        }
        let address = addr(pos)?;
        pos += 4;
        if address + n as u64 > limit {
            return Err(err("Section exceeds word address space"));
        }
        c.section(address, pos, Cow::Borrowed(bytes(data, pos, n * 2)?))?;
        pos += n * 2;
    }
    if c.sections.is_empty() {
        return Err(err("Boot table has no load sections"));
    }
    tail(data, pos)?;
    c.consumed = pos;
    c.isa = if kind == Variant::C28xBoot {
        Isa::TiC28x
    } else {
        Isa::TiC5400
    };
    c.bits = if kind == Variant::C28xBoot { 32 } else { 16 };
    c.endian = if kind == Variant::C28xBoot {
        Endianness::Little
    } else {
        Endianness::Big
    };
    c.notes.push(format!(
        "Header and stream words are {}; 32-bit addresses use most significant word first",
        if le { "little-endian" } else { "big-endian" }
    ));
    c.notes.push(format!(
        "Entry and destinations use 16-bit word addresses; {} register/reserved words",
        registers
    ));
    Ok(c)
}
fn unkeyed(data: &[u8], registers: bool) -> Result<Container<'_>> {
    let mut found = None;
    for le in [false, true] {
        let attempt = (|| {
            let mut c = Container::new(if registers {
                Variant::C55xLegacy
            } else {
                Variant::C6000Boot
            });
            let entry = r32(data, 0, le)? as u64;
            if entry == 0 || (registers && entry >= 1 << 24) {
                return Err(err("Invalid unkeyed entry"));
            }
            c.entry = Some(entry);
            let mut pos = 4;
            if registers {
                let n = r32(data, 4, le)? as usize;
                bytes(
                    data,
                    8,
                    n.checked_mul(4)
                        .ok_or_else(|| err("Register count overflow"))?,
                )?;
                pos = 8 + n * 4;
                c.notes.push(format!("Register configurations: {n}"));
            }
            loop {
                let n = r32(data, pos, le)? as usize;
                pos += 4;
                if n == 0 {
                    break;
                }
                let a = r32(data, pos, le)? as u64;
                pos += 4;
                if a + n as u64 > if registers { 1 << 24 } else { 1u64 << 32 } {
                    return Err(err("Section address overflow"));
                }
                let prefix = if registers { (a & 1) as usize } else { 0 };
                if registers && n < 2 {
                    return Err(err("C5510 sections require at least two bytes"));
                }
                c.section(
                    a,
                    pos + prefix,
                    Cow::Borrowed(bytes(data, pos + prefix, n)?),
                )?;
                pos += prefix + n;
                if registers && pos & 1 != 0 {
                    bytes(data, pos, 1)?;
                    pos += 1;
                }
                // C6000 boot tables pad each section to a 32-bit word.
                if !registers {
                    pos = align4(pos)?;
                    bytes(data, 0, pos)?;
                }
            }
            if c.sections.is_empty()
                || !c
                    .sections
                    .iter()
                    .any(|s| entry >= s.address && entry < s.address + s.data.len() as u64)
            {
                return Err(err("Unkeyed entry is outside loaded bytes"));
            }
            tail(data, pos)?;
            c.consumed = pos;
            c.notes.push(format!("Structural recognition, no magic or target ID; stream fields are {}-endian; addresses and sizes are bytes",if le {"little"}else{"big"}));
            Ok(c)
        })();
        if let Ok(c) = attempt {
            if found.is_some() {
                return Err(err("Ambiguous unkeyed byte order"));
            }
            found = Some(c);
        }
    }
    found.ok_or_else(|| err("Invalid unkeyed boot table"))
}

fn c3_boot(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    let first = r32(data, 0, true)?;
    let memory = matches!(first, 8 | 16 | 32);
    let mut pos = match kind {
        Variant::C31Boot => {
            if memory {
                8
            } else {
                0
            }
        }
        Variant::C32Boot => {
            if memory {
                16
            } else {
                12
            }
        }
        Variant::C4xBoot => {
            if memory {
                12
            } else {
                8
            }
        }
        _ => return Err(err("Invalid C3x/C4x boot kind")),
    };
    bytes(data, 0, pos)?;
    let mut c = Container::new(kind);
    loop {
        let count = r32(data, pos, true)? as usize;
        pos += 4;
        if count == 0 {
            break;
        }
        let address = r32(data, pos, true)? as u64;
        pos += 4;
        if address + count as u64
            > if kind == Variant::C4xBoot {
                1u64 << 32
            } else {
                1 << 24
            }
        {
            return Err(err("C3x/C4x section exceeds word address space"));
        }
        let octets = if kind == Variant::C32Boot {
            let control = r32(data, pos, true)?;
            pos += 4;
            // Low-byte bits xx identify the strobe; data-type size belongs
            // to bits 16-17 of the strobe value, shifted left eight bits in
            // this record. See SPRU031H appendix C's read_mb routine.
            if control & 0xf0 != 0x60 || control & 3 != 0 || control & 0x0c == 0x0c {
                return Err(err("Invalid C32 block control word"));
            }
            if !memory || control & 0x0c == 0 {
                4
            } else {
                match (control >> 24) & 3 {
                    0 => 1,
                    1 => 2,
                    3 => 4,
                    _ => return Err(err("Reserved C32 data width")),
                }
            }
        } else {
            4
        };
        let n = count
            .checked_mul(octets)
            .ok_or_else(|| err("C3x section count overflow"))?;
        c.section(address, pos, Cow::Borrowed(bytes(data, pos, n)?))?;
        pos += n;
    }
    if c.sections.is_empty() {
        return Err(err("C3x/C4x boot table has no blocks"));
    }
    if kind == Variant::C4xBoot {
        bytes(data, pos, 12)?;
        c.notes.push(format!(
            "IVTP 0x{:X}; TVTP 0x{:X}; IACK 0x{:X}",
            r32(data, pos, true)?,
            r32(data, pos + 4, true)?,
            r32(data, pos + 8, true)?
        ));
        pos += 12;
    }
    tail(data, pos)?;
    c.entry = Some(c.sections[0].address);
    c.consumed = pos;
    // Headerless peripheral tables are structurally recognizable but do not
    // carry a unique processor marker. Do not turn arbitrary records into C3x.
    if memory {
        c.isa = Isa::TiC3x;
        c.bits = 32;
    }
    c.notes.push(format!("{} boot; 32-bit control words and code words are least-significant byte first; entry is the first block destination; destinations use target words",if memory{"External memory"}else{"Peripheral stream (structural recognition)"}));
    Ok(c)
}
fn rprc(data: &[u8]) -> Result<Container<'_>> {
    match (rprc_layout(data, false), rprc_layout(data, true)) {
        (Ok(normal), Ok(radar))
            if !normal.sections.is_empty()
                && normal.sections.iter().zip(&radar.sections).any(|(a, b)| {
                    a.address != b.address || a.offset != b.offset || a.data != b.data
                }) =>
        {
            let mut c = Container::new(Variant::Rprc);
            c.entry = normal.entry;
            c.consumed = data.len();
            c.opaque = true;
            c.notes.push("Both MCU+ and radar RPRC layouts validate; section boundaries are ambiguous and were not analyzed".into());
            Ok(c)
        }
        (Ok(normal), _) => Ok(normal),
        (_, Ok(radar)) => Ok(radar),
        (Err(error), _) => Err(error),
    }
}
fn rprc_layout(data: &[u8], radar: bool) -> Result<Container<'_>> {
    let le = if data.starts_with(b"RPRC") {
        true
    } else if data.starts_with(b"CRPR") {
        false
    } else {
        return Err(err("Invalid RPRC magic"));
    };
    let n = r32(data, 12, le)? as usize;
    if n > data.len().saturating_sub(20) / 20 {
        return Err(err("Invalid RPRC section count"));
    }
    let mut c = Container::new(Variant::Rprc);
    c.entry = Some(r32(data, 4, le)? as u64);
    c.notes.push(format!(
        "RPRC version {}; {}-endian header; processor ISA is not encoded",
        r32(data, 16, le)?,
        if le { "little" } else { "big" }
    ));
    let mut pos = if radar { 24 } else { 20 };
    bytes(data, 0, pos)?;
    if radar {
        if r32(data, 20, le)? != 0 {
            return Err(err("Invalid radar RPRC reserved header word"));
        }
        c.notes
            .push("Radar RPRC layout: 24 B file header, size in second section-header word".into());
    }
    for _ in 0..n {
        let a = r32(data, pos, le)? as u64;
        let reserved = if radar { 0 } else { r32(data, pos + 4, le)? };
        let size = r32(data, pos + if radar { 4 } else { 8 }, le)? as usize;
        bytes(data, pos, 20)?;
        if radar
            && [8, 12, 16]
                .iter()
                .any(|offset| r32(data, pos + offset, le).ok() != Some(0))
        {
            return Err(err("Invalid radar RPRC reserved section words"));
        }
        pos += 20;
        if reserved != 0 {
            c.notes.push(format!("Reserved address field 0x{reserved:X} is retained; not interpreted as a 64-bit address"));
        }
        if a + size as u64 > 1u64 << 32 {
            return Err(err("RPRC destination overflow"));
        }
        c.section(a, pos, Cow::Borrowed(bytes(data, pos, size)?))?;
        pos += size;
    }
    tail(data, pos)?;
    c.consumed = pos;
    Ok(c)
}
fn multicore(data: &[u8]) -> Result<Container<'_>> {
    let le = if data.starts_with(b"MSTR") {
        true
    } else if data.starts_with(b"RTSM") {
        false
    } else {
        return Err(err("Invalid multicore start token"));
    };
    let n = r32(data, 4, le)? as usize;
    let header = 24usize
        .checked_add(n.checked_mul(8).ok_or_else(|| err("Core count overflow"))?)
        .ok_or_else(|| err("Header overflow"))?;
    if n == 0 {
        return Err(err("Multicore image has no cores"));
    }
    bytes(data, 0, header)?;
    if r32(data, header - 4, le)? != 0x444e454d {
        return radar_multicore(data, le, n);
    }
    let mut c = Container::new(Variant::Multicore);
    c.notes.push(format!(
        "Device ID {}; core IDs are platform-dependent and do not uniquely identify an ISA",
        r32(data, 8, le)?
    ));
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let at = 16 + i * 8;
        let id = r32(data, at, le)?;
        let offset = r32(data, at + 4, le)? as usize;
        if offset < header || offset >= data.len() {
            return Err(err("Core image offset is outside payload area"));
        }
        entries.push((id, offset));
    }
    let mut ordered: Vec<usize> = entries.iter().map(|e| e.1).collect();
    ordered.sort_unstable();
    if ordered.windows(2).any(|w| w[0] == w[1]) {
        return Err(err("Duplicate core image offsets"));
    }
    let first = ordered[0];
    tail(&data[..first], header)?;
    for (id, offset) in entries {
        let idx = ordered.binary_search(&offset).unwrap();
        let end = ordered.get(idx + 1).copied().unwrap_or(data.len());
        let part = bytes(data, offset, end - offset)?;
        // appimage tools accept only RPRC inputs. A malformed child invalidates
        // the image; padding between children is allowed by the RPRC parser.
        let parsed = rprc(part)?;
        c.children.push(Child {
            label: format!("Core {id}"),
            offset,
            data: part,
            opaque: parsed.opaque,
            isa_hint: None,
        });
    }
    c.consumed = data.len();
    Ok(c)
}

fn radar_multicore(data: &[u8], le: bool, n: usize) -> Result<Container<'_>> {
    let header = 32usize
        .checked_add(
            n.checked_mul(32)
                .ok_or_else(|| err("Radar core count overflow"))?,
        )
        .ok_or_else(|| err("Radar header size overflow"))?;
    bytes(data, 0, header)?;
    if r32(data, header - 4, le)? != 0x444e454d {
        return Err(err("Missing radar MEND token"));
    }
    let size = r32(data, 20, le)? as usize;
    if size < header {
        return Err(err("Invalid radar metaimage size"));
    }
    bytes(data, 0, size)?;
    let mut c = Container::new(Variant::Multicore);
    c.consumed = size;
    c.notes.push(format!("mmWave metaimage; device ID {}; shared memory allocation 0x{:08X}; 64-bit header/image CRC fields are not verified",r32(data,8,le)?,r32(data,header-8,le)?));
    let mut ranges = Vec::new();
    for i in 0..n {
        let at = 24 + i * 32;
        let present = r32(data, at, le)?;
        if present == 0 {
            continue;
        }
        let id = r32(data, at + 4, le)?;
        let offset = r32(data, at + 8, le)? as usize;
        let len = r32(data, at + 20, le)? as usize;
        if offset < header || len == 0 {
            return Err(err("Invalid radar component offset/size"));
        }
        let part = bytes(&data[..size], offset, len)?;
        ranges.push((offset, offset + len));
        let opaque = id == 0xcf910000;
        let hint = match id {
            0x35510000 => Some((Isa::Arm, 32, Endianness::Little)),
            0xd5510000 => Some((Isa::TiC6000, 32, Endianness::Little)),
            _ => None,
        };
        let parsed = if !part.starts_with(&[0x30]) {
            rprc(part)?
        } else {
            x509::parse(part)?
        };
        c.children.push(Child {
            label: format!("Radar core 0x{id:08X}"),
            offset,
            data: part,
            opaque: opaque || parsed.opaque,
            isa_hint: hint,
        });
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(err("Overlapping radar component file ranges"));
    }
    if c.children.is_empty() {
        return Err(err("Radar metaimage has no present images"));
    }
    let rest = &data[size..];
    if rest.len() >= 4 && !rest[..4].iter().all(|b| *b == 0 || *b == 255) {
        let expected = r32(rest, 0, true)?;
        c.notes.push(if crc32(&data[..size]) == expected {
            "Appended radar CRC32 verified".into()
        } else {
            "Appended radar CRC32 mismatch".into()
        });
        tail(data, size + 4)?;
        c.consumed += 4;
    } else {
        tail(data, size)?;
    }
    Ok(c)
}
fn ais(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(b"TIPA") {
        return Err(err("Invalid AIS magic"));
    }
    let mut c = Container::new(Variant::Ais);
    let mut pos = 4;
    let mut commands = 0;
    let mut secure = false;
    loop {
        let op = r32(data, pos, true)?;
        pos += 4;
        commands += 1;
        match op {
            0x58535901 => {
                let a = r32(data, pos, true)? as u64;
                let n = r32(data, pos + 4, true)? as usize;
                pos += 8;
                if a + n as u64 > 1u64 << 32 {
                    return Err(err("AIS destination overflow"));
                }
                c.section(a, pos, Cow::Borrowed(bytes(data, pos, n)?))?;
                pos += align4(n)?;
                bytes(data, 0, pos)?;
            }
            0x5853590a => {
                let a = r32(data, pos, true)?;
                let n = r32(data, pos + 4, true)?;
                let kind = r32(data, pos + 8, true)?;
                let pattern = r32(data, pos + 12, true)?;
                if kind > 2 || u64::from(a) + u64::from(n) > 1u64 << 32 {
                    return Err(err("Invalid AIS fill range/type"));
                }
                c.notes.push(format!("Fill: byte address 0x{a:X}; {n} B; {}-bit pattern 0x{pattern:X} (not expanded)",8<<kind));
                pos += 16;
            }
            0x58535903 | 0x58535904 | 0x58535963 => {}
            0x58535902 => {
                bytes(data, pos, 8)?;
                pos += 8;
                c.notes.push(
                    "AIS target CRC validation command present; target CRC is not verified".into(),
                );
            }
            0x58535905 => {
                let a = r32(data, pos, true)?;
                pos += 4;
                c.notes.push(format!("Intermediate jump to 0x{a:X}"));
            }
            0x58535906 => {
                c.entry = Some(r32(data, pos, true)? as u64);
                pos += 4;
            }
            0x5853590d => {
                let function = r32(data, pos, true)?;
                pos += 4;
                let n = (function >> 16) as usize;
                bytes(data, pos, n * 4)?;
                pos += n * 4;
            }
            0x58535907 => {
                bytes(data, pos, 16)?;
                pos += 16;
            }
            0x58535920 => {
                if commands != 1 {
                    return Err(err("Secure AIS key-load command must be first"));
                }
                bytes(data, pos, 32)?;
                pos += 32;
                secure = true;
                c.opaque = true;
                c.notes.push("Basic secure AIS (SPRUGQ9); key records and signatures are not authenticated; encrypted sections are excluded from ISA analysis".into());
            }
            0x58535921 | 0x58535922 if secure => {
                let address = r32(data, pos, true)?;
                let size = r32(data, pos + 4, true)? as usize;
                pos += 8;
                if u64::from(address) + size as u64 > 1u64 << 32 {
                    return Err(err("Encrypted AIS load address overflow"));
                }
                let stored = align4(size.max(16))?;
                bytes(data, pos, stored)?;
                c.notes.push(format!("Encrypted load section: destination byte 0x{address:X}; {size} B decoded; {stored} B stored"));
                pos += stored;
            }
            0x58535923 if secure => {
                let mode = r32(data, pos, true)?;
                if mode > 2 {
                    return Err(err("Unknown secure AIS exit mode"));
                }
                pos += 4;
            }
            _ => {
                return Err(err(format!(
                    "Unsupported AIS opcode 0x{op:08X} at 0x{:X}",
                    pos - 4
                )))
            }
        }
        if secure
            && matches!(
                op,
                0x58535905 | 0x58535906 | 0x58535907 | 0x5853590d | 0x58535923
            )
        {
            bytes(data, pos, 32)?;
            pos += 32;
        }
        if op == 0x58535906 {
            break;
        }
    }
    tail(data, pos)?;
    c.consumed = pos;
    c.notes.push(format!(
        "{commands} AIS commands; headers and fills are excluded from code analysis"
    ));
    Ok(c)
}
fn gp(data: &[u8]) -> Result<Container<'_>> {
    let le = r32(data, 0, true)? as usize == data.len().saturating_sub(8);
    let n = r32(data, 0, le)? as usize;
    let address = r32(data, 4, le)? as u64;
    if n < 16
        || n != data.len().saturating_sub(8)
        || address == 0
        || address + n as u64 > 1u64 << 32
    {
        return Err(err("Invalid size/address-only GP image"));
    }
    let mut c = Container::new(Variant::GpImage);
    c.section(address, 8, Cow::Borrowed(bytes(data, 8, n)?))?;
    c.entry = Some(address);
    c.consumed = data.len();
    c.notes.push(
        "Structural recognition of a size/address-only GP header; header does not identify an ISA"
            .into(),
    );
    Ok(c)
}
fn omap(data: &[u8]) -> Result<Container<'_>> {
    bytes(data, 0, 520)?;
    let le = r32(data, 0, true)? < 512;
    let mut pos = 0;
    let mut sections = Vec::new();
    let mut settings = false;
    loop {
        let offset = r32(data, pos, le)? as usize;
        let size = r32(data, pos + 4, le)? as usize;
        bytes(&data[..512], pos, 32)?;
        if offset == u32::MAX as usize && size == u32::MAX as usize {
            break;
        }
        if offset == 0 || size == 0 || offset < pos + 32 {
            return Err(err("Invalid OMAP configuration TOC entry"));
        }
        let record = bytes(&data[..512], offset, size)?;
        let name = bytes(data, pos + 20, 12)?;
        let name = String::from_utf8_lossy(name)
            .trim_end_matches('\0')
            .to_string();
        if name == "CHSETTINGS" {
            if r32(record, 0, le)? != 0xc0c0c0c1 {
                return Err(err("Invalid OMAP CHSETTINGS key"));
            }
            settings = true;
        }
        sections.push((offset, offset + size, name));
        pos += 32;
    }
    if !settings {
        return Err(err("OMAP configuration header has no CHSETTINGS"));
    }
    if sections.iter().any(|(start, _, _)| *start < pos + 32) {
        return Err(err("OMAP configuration data overlaps TOC"));
    }
    let mut ranges: Vec<_> = sections.iter().map(|(a, b, _)| (*a, *b)).collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(err("Overlapping OMAP configuration ranges"));
    }
    let image = gp(&data[512..])?;
    let mut c = Container::new(Variant::OmapImage);
    c.entry = image.entry;
    c.consumed = data.len();
    c.isa = Isa::Arm;
    c.bits = 32;
    c.endian = if le {
        Endianness::Little
    } else {
        Endianness::Big
    };
    for section in image.sections {
        c.section(section.address, section.offset + 512, section.data)?;
    }
    for (offset, end, name) in sections {
        c.notes.push(format!(
            "{name}: configuration header offset 0x{offset:X}; {} B",
            end - offset
        ));
    }
    c.notes.push(
        "OMAP configuration header (512 B) followed by GP size/load-address header (8 B)".into(),
    );
    Ok(c)
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn oad(data: &[u8]) -> Result<Container<'_>> {
    if detect_strong_id(data) != Some(Variant::Oad) {
        return Err(err("Unknown OAD image identifier"));
    }
    bytes(data, 0, 44)?;
    let len = r32(data, 24, true)? as usize;
    let header = r16(data, 40, true)? as usize;
    if header < 44 || len < header {
        return Err(err("Invalid OAD length/header"));
    }
    bytes(data, 0, len)?;
    tail(data, len)?;
    let mut c = Container::new(Variant::Oad);
    let image_type = data[18];
    if image_type < 0x10 && &data[..8] != b"OAD IMG " {
        c.isa = Isa::Arm;
        c.bits = 32;
    } else if (0x10..0x20).contains(&image_type) || image_type >= 0x40 {
        c.opaque = true;
        c.notes
            .push("OAD user-data or reserved image type; payload ISA analysis was skipped".into());
    } else {
        c.notes.push("Generic or host-processor OAD image; header does not uniquely identify the payload ISA".into());
    }
    c.entry = Some(r32(data, 28, true)? as u64);
    let stored_crc = r32(data, 8, true)?;
    c.notes.push(format!(
        "Image identifier {}; BIM version {}; metadata version {}; image type {}",
        String::from_utf8_lossy(&data[..8]),
        data[12],
        data[13],
        data[18]
    ));
    c.notes.push(if stored_crc == u32::MAX {
        "OAD CRC is unset".into()
    } else if crc32(&data[12..len]) == stored_crc {
        "OAD CRC32 verified over image bytes from offset 12".into()
    } else {
        "OAD CRC32 mismatch (image may be damaged or header status bytes modified)".into()
    });
    let mut pos = header;
    while pos < len {
        bytes(&data[..len], pos, 8)?;
        let kind = data[pos];
        let size = r32(data, pos + 4, true)? as usize;
        if size < 8 {
            return Err(err("OAD segment length is smaller than its header"));
        }
        bytes(&data[..len], pos, size)?;
        match kind {
            0 => {
                if size < 24 {
                    return Err(err("Truncated OAD image-boundary segment"));
                }
            }
            1 => {
                if size < 12 {
                    return Err(err("Truncated OAD contiguous-image segment"));
                }
                let address = r32(data, pos + 8, true)? as u64;
                if address + (size - 12) as u64 > 1u64 << 32 {
                    return Err(err("OAD destination overflow"));
                }
                c.section(
                    address,
                    pos + 12,
                    Cow::Borrowed(bytes(data, pos + 12, size - 12)?),
                )?;
            }
            3 => {
                if size < 85 {
                    return Err(err("Truncated OAD security segment"));
                }
                c.notes.push(
                    "OAD security segment present; signature authenticity is not verified".into(),
                );
            }
            _ => c.notes.push(format!(
                "OAD segment type {kind} retained as metadata ({size} B)"
            )),
        }
        pos += size;
    }
    if c.sections.is_empty() {
        return Err(err("OAD image has no contiguous payload"));
    }
    c.consumed = len;
    Ok(c)
}
fn detect_strong_id(data: &[u8]) -> Option<Variant> {
    if matches!(
        data.get(..8),
        Some(
            b"CC26x2R1"
                | b"CC13x2R1"
                | b"CC13x4  "
                | b"CC26x3  "
                | b"CC26x4  "
                | b"OAD IMG "
                | b"CC23x0R2"
        )
    ) {
        Some(Variant::Oad)
    } else {
        None
    }
}
fn oad_metadata(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(b"OAD NVM1") {
        return Err(err("Invalid OAD metadata identifier"));
    }
    bytes(data, 0, 52)?;
    let mut c = Container::new(Variant::OadMetadata);
    c.opaque = true;
    c.consumed = 52;
    c.notes.push(format!(
        "External-flash metadata entry; advertised image length {} B; image is stored separately",
        r32(data, 24, true)?
    ));
    Ok(c)
}
fn mcuboot(data: &[u8]) -> Result<Container<'_>> {
    if r32(data, 0, true)? != 0x96f3b83d {
        return Err(err("Invalid MCUboot magic"));
    }
    bytes(data, 0, 32)?;
    let h = r16(data, 8, true)? as usize;
    let protected = r16(data, 10, true)? as usize;
    let size = r32(data, 12, true)? as usize;
    if h < 32 || size == 0 {
        return Err(err("Invalid MCUboot header/image length"));
    }
    let mut pos = h
        .checked_add(size)
        .ok_or_else(|| err("MCUboot payload overflow"))?;
    bytes(data, h, size)?;
    if protected != 0 {
        let end = tlvs(data, pos, 0x6908)?;
        if end - pos != protected {
            return Err(err("MCUboot protected TLV length mismatch"));
        }
        pos = end;
    }
    if data.get(pos..pos.saturating_add(2)) == Some(&[7, 0x69]) {
        pos = tlvs(data, pos, 0x6907)?;
    }
    // Flash padding and a boot trailer are outside the signed image. Their
    // contents are not code and do not change the payload boundaries.
    let mut c = Container::new(Variant::Mcuboot);
    let flags = r32(data, 16, true)?;
    // Unrecognized future flags can change the payload encoding (compression
    // is an example). Restrict ISA analysis to the documented plain flags.
    c.opaque = flags & 0x0c != 0 || flags & !0x3d != 0;
    c.consumed = pos;
    if flags & !0x3d != 0 {
        c.notes.push(
            "Unknown MCUboot flags; payload encoding is unknown and ISA analysis was skipped"
                .into(),
        );
    }
    c.notes.push(format!("MCUboot flags 0x{flags:X}; version {}.{}.{}+{}; signature/hash authenticity is not verified",data[20],data[21],r16(data,22,true)?,r32(data,24,true)?));
    c.section(
        r32(data, 4, true)? as u64,
        h,
        Cow::Borrowed(bytes(data, h, size)?),
    )?;
    Ok(c)
}
fn tlvs(data: &[u8], start: usize, magic: u16) -> Result<usize> {
    if r16(data, start, true)? != magic {
        return Err(err("Missing MCUboot TLV magic"));
    }
    let n = r16(data, start + 2, true)? as usize;
    if n < 4 {
        return Err(err("Invalid MCUboot TLV total size"));
    }
    let block = bytes(data, start, n)?;
    let mut pos = 4;
    while pos < n {
        bytes(block, pos, 4)?;
        let size = r16(block, pos + 2, true)? as usize;
        pos += 4;
        bytes(block, pos, size)?;
        pos += size;
    }
    Ok(start + n)
}
