//! Labelled stored ranges of one input: container members and load
//! sections, executable segments and sections, and signature and
//! certificate structures. A region says where a string or a certificate
//! lies. It is not classification evidence, and nothing in it is verified.
//!
//! | Input | Regions |
//! | --- | --- |
//! | Shared container model, ar | Children (`member`) and load sections (`section`) at their stored ranges |
//! | ELF | Section headers with file bytes (`formats::elf::sections`) |
//! | PE | Section table (`formats::pe::sections`); attribute certificate table and its `WIN_CERTIFICATE` entries (`formats::pe::attribute_certificates`) |
//! | Mach-O, fat Mach-O | Each slice (`member`), its segments and sections with file bytes, and `LC_CODE_SIGNATURE` |
//! | IMG4, IM4M | The `IM4M` manifest and its signature (`signature`) and certificate chain (`certificates`) |
//! | CAB | The Authenticode signature after the cabinet |

use serde::Serialize;

use super::container;
use crate::error::Result;
use crate::formats::apple::Layout as AppleLayout;
use crate::formats::container::{Kind, MAX_COMPONENTS};
use crate::formats::{self, cab, elf, macho, pe, DetectedFormat, NamedRange};

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegionKind {
    /// A container child or a fat Mach-O slice.
    Member,
    /// A Mach-O segment.
    Segment,
    /// An executable section or a container load section.
    Section,
    /// A signature structure.
    Signature,
    /// A certificate chain.
    Certificates,
}

/// One labelled stored range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Region {
    /// Name in the format's own terms; untrusted text.
    pub label: String,
    /// What the range holds.
    pub kind: RegionKind,
    /// Byte offset in the input.
    pub offset: u64,
    /// Size in bytes; the range lies within the input.
    pub size: u64,
}

impl Region {
    fn contains(&self, offset: u64, size: u64) -> bool {
        offset >= self.offset && offset.saturating_add(size) <= self.offset + self.size
    }
}

fn push_ranges(
    regions: &mut Vec<Region>,
    kind: RegionKind,
    base: u64,
    ranges: impl IntoIterator<Item = NamedRange>,
) {
    regions.extend(ranges.into_iter().map(|range| Region {
        label: range.name,
        kind,
        offset: base + range.offset,
        size: range.size,
    }));
}

/// Segments, sections and the code signature of the Mach-O image that
/// starts at the beginning of `image`, which is at offset `base` of the
/// input. A dyld cache member's offsets refer to another file and are
/// skipped.
fn push_macho(image: &[u8], base: u64, regions: &mut Vec<Region>) -> Result<()> {
    let parsed = macho::parse_image(image)?;
    if !parsed.offsets_in_input {
        return Ok(());
    }
    for segment in &parsed.segments {
        let range = NamedRange::clipped(
            segment.name.clone(),
            segment.file_offset,
            segment.file_size,
            image.len(),
        );
        push_ranges(regions, RegionKind::Segment, base, range);
        let sections = segment
            .sections
            .iter()
            .filter(|section| !section.is_zero_fill() && section.offset != 0)
            .filter_map(|section| {
                NamedRange::clipped(
                    format!("{},{}", section.segment_name, section.name),
                    u64::from(section.offset),
                    section.size,
                    image.len(),
                )
            });
        push_ranges(regions, RegionKind::Section, base, sections);
    }
    let signature = parsed.code_signature.and_then(|range| {
        NamedRange::clipped(
            "Mach-O code signature".to_string(),
            u64::from(range.offset),
            u64::from(range.size),
            image.len(),
        )
    });
    push_ranges(regions, RegionKind::Signature, base, signature);
    Ok(())
}

fn push_fat(data: &[u8], fat64: bool, regions: &mut Vec<Region>) -> Result<()> {
    for entry in macho::parse_fat_all(data, fat64)? {
        let label = format!("{} slice", macho::cpu_type_description(entry.cpu_type));
        let Some(slice) = NamedRange::clipped(label, entry.offset, entry.size, data.len()) else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::try_from(slice.offset),
            usize::try_from(slice.offset + slice.size),
        ) else {
            continue;
        };
        let image = &data[start..end];
        let base = slice.offset;
        push_ranges(regions, RegionKind::Member, 0, [slice]);
        push_macho(image, base, regions)?;
    }
    Ok(())
}

fn push_image4(data: &[u8], regions: &mut Vec<Region>) -> Result<()> {
    for range in formats::apple::image4_manifest_ranges(data)? {
        let kind = if range.name == "IM4M certificate chain" {
            RegionKind::Certificates
        } else {
            RegionKind::Signature
        };
        push_ranges(regions, kind, 0, [range]);
    }
    Ok(())
}

fn push_container(data: &[u8], regions: &mut Vec<Region>) -> Result<()> {
    let Some(c) = container(data)? else {
        return Ok(());
    };
    let clipped = |label: &str, offset: usize, size: usize| {
        NamedRange::clipped(label.to_string(), offset as u64, size as u64, data.len())
    };
    let members = c
        .children
        .iter()
        .filter_map(|child| clipped(&child.label, child.offset, child.stored_size));
    push_ranges(regions, RegionKind::Member, 0, members);
    let sections = c
        .sections
        .iter()
        .filter_map(|section| clipped(&section.label, section.offset, section.stored_size));
    push_ranges(regions, RegionKind::Section, 0, sections);
    Ok(())
}

/// Every region of `data`, ordered by offset with enclosing regions first,
/// at most 4096.
///
/// # Errors
///
/// The detected format's parse error when the structure that supplies the
/// regions is invalid.
pub fn regions(data: &[u8]) -> Result<Vec<Region>> {
    let mut regions = Vec::new();
    match formats::detect_format(data) {
        DetectedFormat::Elf { .. } => {
            push_ranges(&mut regions, RegionKind::Section, 0, elf::sections(data));
        }
        DetectedFormat::Pe { pe_offset } => {
            push_ranges(
                &mut regions,
                RegionKind::Section,
                0,
                pe::sections(data, pe_offset),
            );
            push_ranges(
                &mut regions,
                RegionKind::Signature,
                0,
                pe::attribute_certificates(data, pe_offset),
            );
        }
        DetectedFormat::MachO { .. } => push_macho(data, 0, &mut regions)?,
        DetectedFormat::MachOFat { fat64, .. } => push_fat(data, fat64, &mut regions)?,
        DetectedFormat::Container {
            kind: Kind::Apple(AppleLayout::Img4 | AppleLayout::Im4m),
        } => push_image4(data, &mut regions)?,
        DetectedFormat::Container { kind: Kind::Cab(_) } => {
            let signature = cab::signature_range(data);
            push_ranges(&mut regions, RegionKind::Signature, 0, signature);
        }
        _ => {}
    }
    push_container(data, &mut regions)?;
    regions.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(b.size.cmp(&a.size))
            .then_with(|| a.label.cmp(&b.label))
    });
    regions.dedup();
    regions.truncate(MAX_COMPONENTS);
    Ok(regions)
}

/// The regions that contain `size` bytes at `offset`, outermost first.
pub fn enclosing(regions: &[Region], offset: u64, size: u64) -> Vec<&Region> {
    let mut found: Vec<&Region> = regions
        .iter()
        .filter(|region| region.contains(offset, size))
        .collect();
    found.sort_by(|a, b| b.size.cmp(&a.size).then(a.offset.cmp(&b.offset)));
    found
}
