//! Texas Instruments firmware containers. Wire specifications and coverage
//! boundaries are recorded in docs/ti-containers.md. No device is inferred
//! from an address or from an unqualified multicore core ID.
//!
//! This module holds the shared container model, bounds-checked readers,
//! detection and dispatch; each format family lives in its own submodule.
use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, Endianness, FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue,
    Variant as CpuVariant,
};
use std::borrow::Cow;

mod ais;
mod boot;
mod fip;
mod mcelf;
mod mcuboot;
mod multicore;
mod oad;
mod rom_image;
mod rprc;
mod text;
mod x509;

/// Maximum extracted bytes, independent of destination address gaps.
pub const MAX_PAYLOAD: usize = 64 << 20;

/// A recognized container layout; [`Variant::label`] describes each one.
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
    /// Every layout, for exhaustive parsing in tests.
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

    /// The reported file format; related layouts share one.
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

    /// Human-readable layout name, used as the classification variant.
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

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::TiContainerParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

/// Fail unless `len` bytes are present at `start`.
fn ensure(data: &[u8], start: usize, len: usize) -> Result<()> {
    slice(data, start, len).map(|_| ())
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn u16_at(data: &[u8], at: usize, le: bool) -> Result<u16> {
    let bytes = array(data, at)?;
    Ok(if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let bytes = array(data, at)?;
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn u64_at(data: &[u8], at: usize, le: bool) -> Result<u64> {
    let bytes = array(data, at)?;
    Ok(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    u16_at(data, at, true)
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    u32_at(data, at, true)
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    u64_at(data, at, true)
}

/// Erased flash: the only bytes allowed to pad an image.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Only padding may follow an image that ends at `end`.
fn expect_padding(data: &[u8], end: usize) -> Result<()> {
    if !is_padding(slice(data, end, data.len().saturating_sub(end))?) {
        return Err(error("Unexpected bytes after image terminator"));
    }
    Ok(())
}

/// Round up to a multiple of four bytes.
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3)
        .ok_or_else(|| error("Alignment overflow"))?
        & !3)
}

/// IEEE 802.3 CRC-32, as used by OAD headers and radar metaimage trailers.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Bytes that the container loads into target memory.
#[derive(Debug)]
pub struct Section<'a> {
    pub label: String,
    /// Address units are stated in the container notes (bytes unless stated).
    pub address: u64,
    /// File offset of the stored bytes (for text formats, of their encoding).
    pub offset: usize,
    pub data: Cow<'a, [u8]>,
}

/// An embedded image (core image, signed payload, FIP component) that is
/// classified on its own.
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

/// A parsed container. Formats either load sections into target memory or
/// wrap independent images (`children`) that are classified separately.
#[derive(Debug)]
pub struct Container<'a> {
    pub variant: Variant,
    pub entry: Option<u64>,
    pub sections: Vec<Section<'a>>,
    pub children: Vec<Child<'a>>,
    pub notes: Vec<String>,
    /// Bytes of the input that belong to the container.
    pub consumed: usize,
    /// Encrypted or metadata-only content that must not be analyzed as code.
    pub opaque: bool,
    /// Architecture, when the format itself identifies one.
    isa: Isa,
    bits: u8,
    endian: Endianness,
}

impl<'a> Container<'a> {
    fn new(variant: Variant) -> Self {
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

    fn push_section(&mut self, address: u64, offset: usize, data: Cow<'a, [u8]>) -> Result<()> {
        address
            .checked_add(data.len() as u64)
            .ok_or_else(|| error("Load address overflow"))?;
        self.sections.push(Section {
            label: format!("Load section {}", self.sections.len() + 1),
            address,
            offset,
            data,
        });
        Ok(())
    }

    /// The container-level result; the ISA is unknown unless the layout
    /// itself identifies one.
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
        // Wrappers without load sections describe their components instead.
        let wraps_children = self.sections.is_empty() && !self.children.is_empty();
        if wraps_children {
            r.metadata.section_count = Some(self.children.len());
            r.metadata.code_size = None;
        } else {
            r.metadata.section_count = Some(self.sections.len());
            r.metadata.code_size = Some(self.sections.iter().map(|s| s.data.len() as u64).sum());
        }
        let mut notes = vec![format!(
            "{}; exact device model is not encoded or not uniquely determined",
            self.variant.label()
        )];
        notes.extend(self.notes.iter().cloned());
        if self.opaque {
            notes
                .push("Payload is encrypted or metadata-only; ISA analysis was not applied".into());
        }
        r.metadata.notes = notes;
        r
    }

    /// Container size plus one entry per section and child.
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let custom = |key: String, label: String, value: MetadataValue| {
            MetadataEntry::new(MetadataKey::Custom(key), value, label)
        };
        let mut entries = vec![custom(
            "ti_image_size".into(),
            "Container size (B)".into(),
            MetadataValue::Integer(self.consumed as u64),
        )];
        for (i, s) in self.sections.iter().enumerate() {
            entries.push(custom(
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
            let opaque = if child.opaque || self.opaque {
                "; opaque"
            } else {
                ""
            };
            entries.push(custom(
                format!("ti_component_{i}"),
                child.label.clone(),
                MetadataValue::String(format!(
                    "file 0x{:X}; {} B{opaque}",
                    child.offset,
                    child.data.len()
                )),
            ));
        }
        entries
    }

    /// Sparse load ranges are concatenated in stream order; destination gaps
    /// and fill commands never allocate a destination-sized memory image.
    pub fn payload(&self) -> Result<Vec<u8>> {
        if self.opaque {
            return Ok(Vec::new());
        }
        let size = self.sections.iter().try_fold(0usize, |size, s| {
            size.checked_add(s.data.len())
                .filter(|size| *size <= MAX_PAYLOAD)
                .ok_or_else(|| error("Decoded payload exceeds 64 MiB"))
        })?;
        let mut payload = Vec::with_capacity(size);
        for s in &self.sections {
            payload.extend_from_slice(&s.data);
        }
        Ok(payload)
    }

    /// A concatenation across unrelated load ranges is suitable for the code
    /// model, but must not manufacture a nested file header across a gap.
    pub fn nested_payload_is_contiguous(&self) -> bool {
        let text = matches!(
            self.variant,
            Variant::AsciiHex | Variant::Tagged | Variant::Tektronix
        );
        !text || self.sections.len() == 1
    }
}

/// Magic-bearing families are detected independently of parse success so a
/// corrupted container yields a format error instead of a confident raw ISA.
pub fn detect_strong(data: &[u8]) -> Option<Variant> {
    let variant = if data.starts_with(b"RPRC") || data.starts_with(b"CRPR") {
        Variant::Rprc
    } else if data.starts_with(b"MSTR") || data.starts_with(b"RTSM") {
        Variant::Multicore
    } else if data.starts_with(b"TIPA") {
        Variant::Ais
    } else if oad::is_image(data) {
        Variant::Oad
    } else if data.starts_with(oad::METADATA_ID) {
        Variant::OadMetadata
    } else if data.starts_with(&mcuboot::MAGIC.to_le_bytes()) {
        Variant::Mcuboot
    } else if data.starts_with(&fip::MAGIC.to_le_bytes()) {
        Variant::Fip
    } else if mcelf::detect(data) {
        Variant::Mcelf
    } else if rom_image::is_omap(data) {
        Variant::OmapImage
    } else if x509::detect(data) {
        Variant::X509
    } else {
        return text::detect(data);
    };
    Some(variant)
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
    [
        Variant::C28xBoot,
        Variant::C54xBoot,
        Variant::C31Boot,
        Variant::C32Boot,
        Variant::C4xBoot,
        Variant::C55xLegacy,
        Variant::C6000Boot,
        Variant::GpImage,
    ]
    .into_iter()
    .find(|kind| parse_container(data, *kind).is_ok())
}

/// Parse `data` as the given layout.
pub fn parse_container(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    match kind {
        Variant::AmbiguousBoot => boot::ambiguous(data),
        Variant::C28xBoot => boot::c28x(data),
        Variant::C54xBoot => boot::c54x(data),
        Variant::C55xLegacy | Variant::C6000Boot => boot::unkeyed(data, kind),
        Variant::C31Boot | Variant::C32Boot | Variant::C4xBoot => boot::c3x(data, kind),
        Variant::Ais => ais::parse(data),
        Variant::Rprc => rprc::parse(data),
        Variant::Multicore => multicore::parse(data),
        Variant::GpImage => rom_image::gp(data),
        Variant::OmapImage => rom_image::omap(data),
        Variant::Oad => oad::parse(data),
        Variant::OadMetadata => oad::parse_metadata(data),
        Variant::X509 => x509::parse(data),
        Variant::Mcuboot => mcuboot::parse(data),
        Variant::Mcelf => mcelf::parse(data),
        Variant::Fip => fip::parse(data),
        Variant::CcsData => text::ccs(data),
        Variant::AsciiHex | Variant::Tagged | Variant::Tektronix => text::parse(data, kind),
    }
}

/// Parse `data` as the given layout and classify the container alone.
pub fn parse(data: &[u8], kind: Variant) -> Result<ClassificationResult> {
    Ok(parse_container(data, kind)?.classification())
}
