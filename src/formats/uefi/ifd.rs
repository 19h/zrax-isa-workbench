//! Intel flash descriptor images: the descriptor map and region section
//! (coreboot 25.09 `util/ifdtool/ifdtool.h` and `ifdtool.c`, flashrom
//! v1.8.0 `include/ich_descriptors.h`, `UEFITool` A75 `common/descriptor.h`
//! and `ffsparser.cpp` `parseIntelImage`). No Intel document was read.
//!
//! `FLVALSIG` (`0x0FF0A55A`) sits at 0x10, or at 0x0 before the Ibex Peak
//! B-step. `FLMAP0` follows it: component base `FCBA` (bits 7:0), region
//! base `FRBA` (bits 23:16) and region count `NR` (bits 26:24, reserved
//! from the 100-series PCHs on); `FLMAP1`: master base `FMBA` (bits 7:0)
//! and PCH strap base `FPSBA` (bits 23:16). Bases are in 16-byte units
//! from the start of the image. Each `FLREG` register holds a region base
//! (bits 14:0) and inclusive limit (bits 30:16) in 4 KiB units; a base
//! above the limit marks an unused region. flashrom documents 13-bit fields
//! before Lynx Point and coreboot masks them to 12 bits; the 15-bit mask
//! is used for every generation.

use super::*;

/// `FLVALSIG` and where it may sit.
const FLVALSIG: u32 = 0x0FF0_A55A;
const SIGNATURE_OFFSET: usize = 0x10;
const LEGACY_SIGNATURE_OFFSET: usize = 0x00;

/// The descriptor region is 4 KiB (`UEFITool` `FLASH_DESCRIPTOR_SIZE`).
const DESCRIPTOR_SIZE: usize = 0x1000;

/// Map base fields are 8 bits wide, in 16-byte units; `UEFITool` rejects
/// fields above `FLASH_DESCRIPTOR_MAX_BASE`.
const BASE_FIELD_MASK: u32 = 0xFF;
const BASE_UNIT_SHIFT: u32 = 4;
const MAX_BASE_FIELD: u32 = 0xE0;

/// The second base in `FLMAP0` (`FRBA`) and `FLMAP1` (`FPSBA`).
const SECOND_BASE_SHIFT: u32 = 16;

/// `FLMAP0` `NR`: number of regions minus one, before the 100 series.
const FLMAP0_NR_SHIFT: u32 = 24;
const FLMAP0_NR_MASK: u32 = 0x7;

/// `FLUMAP1` sits at a fixed offset and bounds the region table (coreboot
/// `max_regions_from_fdbar`).
const FLUMAP1_OFFSET: usize = 0xEFC;

/// At most 16 `FLREG` registers (Cannon Point and later).
const MAX_REGIONS: usize = 16;
const FLREG_SIZE: usize = 4;

/// `FLREG` fields: 15-bit base and limit in 4 KiB units (flashrom
/// `ICH_FREG_BASE`/`ICH_FREG_LIMIT`).
const REGION_FIELD_MASK: u32 = 0x7FFF;
const REGION_LIMIT_SHIFT: u32 = 16;
const REGION_UNIT_SHIFT: u32 = 12;
const REGION_LIMIT_LOW_BITS: usize = 0xFFF;

/// An erased register, which `UEFITool` also skips.
const FLREG_ERASED: u32 = 0xFFFF_FFFF;

/// Region indices with their own handling.
const REGION_DESCRIPTOR: usize = 0;
const REGION_BIOS: usize = 1;
const REGION_ME: usize = 2;
const REGION_GBE: usize = 3;
const REGION_BIOS2: usize = 6;
const REGION_IE: usize = 10;
const REGION_10GBE0: usize = 11;
const REGION_10GBE1: usize = 12;

/// Region names by index (coreboot `region_names`).
const REGION_NAMES: [&str; MAX_REGIONS] = [
    "Descriptor",
    "BIOS",
    "ME",
    "GbE",
    "Platform data",
    "Device expansion 1",
    "Secondary BIOS",
    "Reserved 7",
    "EC",
    "Device expansion 2",
    "IE",
    "10GbE 0",
    "10GbE 1",
    "Reserved 13",
    "Reserved 14",
    "PTT",
];

/// The flash descriptor signature at 0x10, or at 0x0 (legacy).
pub(super) fn has_signature(data: &[u8]) -> bool {
    signature_offset(data).is_some()
}

fn signature_offset(data: &[u8]) -> Option<usize> {
    [SIGNATURE_OFFSET, LEGACY_SIGNATURE_OFFSET]
        .into_iter()
        .find(|&at| le_u32(data, at).ok() == Some(FLVALSIG))
}

/// One used region, in bytes from the start of the image.
#[derive(Debug, Clone, Copy)]
struct Region {
    index: usize,
    base: usize,
    /// Exclusive end.
    end: usize,
}

impl Region {
    fn name(&self) -> &'static str {
        REGION_NAMES[self.index]
    }
}

/// Decode `FLREG`; `None` for an unused register: an erased one, a base
/// above the limit (flashrom), or a zero limit field for any region but the
/// descriptor, which would end inside the descriptor (`UEFITool` skips
/// those too).
fn decode_region(index: usize, flreg: u32) -> Option<Region> {
    if flreg == FLREG_ERASED {
        return None;
    }
    let base_field = flreg & REGION_FIELD_MASK;
    let limit_field = (flreg >> REGION_LIMIT_SHIFT) & REGION_FIELD_MASK;
    if limit_field == 0 && index != REGION_DESCRIPTOR {
        return None;
    }
    let base = (base_field as usize) << REGION_UNIT_SHIFT;
    let limit = ((limit_field as usize) << REGION_UNIT_SHIFT) | REGION_LIMIT_LOW_BITS;
    (base <= limit).then_some(Region {
        index,
        base,
        end: limit + 1,
    })
}

/// A map base field converted to bytes, checked against the descriptor.
fn map_base(field: u32, name: &str) -> Result<usize> {
    if field > MAX_BASE_FIELD {
        return Err(error(format!(
            "Invalid flash descriptor map: {name} 0x{field:02X} is beyond the descriptor"
        )));
    }
    Ok((field as usize) << BASE_UNIT_SHIFT)
}

/// How many `FLREG` registers fit between `FRBA` and the next map
/// structure (coreboot `max_regions_from_fdbar`), at most 16.
fn region_count(frba: usize, others: &[usize]) -> usize {
    let next = others
        .iter()
        .copied()
        .chain([FLUMAP1_OFFSET])
        .filter(|&base| base > frba)
        .min()
        .unwrap_or(FLUMAP1_OFFSET);
    ((next - frba) / FLREG_SIZE).min(MAX_REGIONS)
}

/// The descriptor map fields the region walk uses, in bytes from the start
/// of the image.
#[derive(Debug)]
struct DescriptorMap {
    /// `FRBA`: the `FLREG` table.
    frba: usize,
    /// `FLMAP0` `NR`, reported only: it is reserved on current platforms.
    nr: u32,
    /// `FLREG` registers between `FRBA` and the next map structure.
    region_count: usize,
}

/// Descriptor map: `FLMAP0` and `FLMAP1` follow `FLVALSIG` at `fdbar`.
fn descriptor_map(data: &[u8], fdbar: usize) -> Result<DescriptorMap> {
    let flmap0 = le_u32(data, fdbar + 4)?;
    let flmap1 = le_u32(data, fdbar + 8)?;
    let fcba = map_base(flmap0 & BASE_FIELD_MASK, "FCBA")?;
    let frba = map_base((flmap0 >> SECOND_BASE_SHIFT) & BASE_FIELD_MASK, "FRBA")?;
    let fmba = map_base(flmap1 & BASE_FIELD_MASK, "FMBA")?;
    let fpsba = map_base((flmap1 >> SECOND_BASE_SHIFT) & BASE_FIELD_MASK, "FPSBA")?;
    if fcba == frba || fcba == fmba || frba == fmba {
        return Err(error(format!(
            "Invalid flash descriptor map: FCBA 0x{fcba:X}, FRBA 0x{frba:X} and FMBA 0x{fmba:X} are not distinct"
        )));
    }
    if frba <= fdbar {
        return Err(error(format!(
            "Invalid flash descriptor map: FRBA 0x{frba:X} precedes the signature"
        )));
    }
    Ok(DescriptorMap {
        frba,
        nr: (flmap0 >> FLMAP0_NR_SHIFT) & FLMAP0_NR_MASK,
        region_count: region_count(frba, &[fcba, fmba, fpsba]),
    })
}

/// The used regions of the descriptor, sorted by base and checked for
/// overlaps and against the image.
fn regions(data: &[u8], map: &DescriptorMap) -> Result<Vec<Region>> {
    let mut used = Vec::new();
    for index in 0..map.region_count {
        let flreg = le_u32(data, map.frba + index * FLREG_SIZE)?;
        if let Some(region) = decode_region(index, flreg) {
            used.push(region);
        }
    }
    used.sort_by_key(|r| r.base);
    for pair in used.windows(2) {
        if pair[1].base < pair[0].end {
            return Err(error(format!(
                "Invalid flash region map: {} 0x{:X}-0x{:X} overlaps {} 0x{:X}-0x{:X}",
                pair[0].name(),
                pair[0].base,
                pair[0].end - 1,
                pair[1].name(),
                pair[1].base,
                pair[1].end - 1
            )));
        }
    }
    if let Some(r) = used
        .iter()
        .find(|r| r.index != REGION_DESCRIPTOR && r.base < DESCRIPTOR_SIZE)
    {
        return Err(error(format!(
            "Invalid flash region {} at 0x{:X}: inside the descriptor",
            r.name(),
            r.base
        )));
    }
    if !used.iter().any(|r| r.index == REGION_BIOS) {
        return Err(error("Missing BIOS region in the flash descriptor"));
    }
    Ok(used)
}

/// How a region's contents are reported.
#[derive(Debug, Clone, Copy)]
enum Content {
    /// Firmware volumes, each a child.
    Volumes,
    /// Never analyzed, for the stated reason.
    Opaque(&'static str),
    /// Listed only when it is a recognized format.
    Member,
}

fn content(index: usize) -> Content {
    match index {
        REGION_BIOS | REGION_BIOS2 => Content::Volumes,
        REGION_ME | REGION_IE => {
            Content::Opaque("firmware of a separate engine whose layout is not established here")
        }
        REGION_GBE | REGION_10GBE0 | REGION_10GBE1 => {
            Content::Opaque("network controller configuration data")
        }
        _ => Content::Member,
    }
}

/// Parse a flash image with an Intel flash descriptor: the region map,
/// then each region's contents.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let fdbar =
        signature_offset(data).ok_or_else(|| error("Missing flash descriptor signature"))?;
    if data.len() < DESCRIPTOR_SIZE {
        return Err(error(format!(
            "Truncated flash descriptor: {DESCRIPTOR_SIZE} B required, {} B present",
            data.len()
        )));
    }
    let map = descriptor_map(data, fdbar)?;
    let used = regions(data, &map)?;
    let mut c = Container::new(
        FileFormat::IntelIfd,
        Layout::FlashDescriptor.label(),
        KEY_PREFIX,
    );
    let mut budget = Budget::default();
    let listed: Vec<String> = used
        .iter()
        .map(|r| format!("{} 0x{:X}-0x{:X}", r.name(), r.base, r.end - 1))
        .collect();
    c.notes.push(format!(
        "Intel flash descriptor at 0x{fdbar:X}; regions {}; the descriptor names no host ISA",
        listed.join(", ")
    ));
    c.notes.push(format!(
        "{} FLREG registers at 0x{:X} read up to the next map structure; FLMAP0 NR field {} (reserved from the 100-series PCHs on)",
        map.region_count, map.frba, map.nr
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_ifd_signature_offset"),
        "Descriptor signature offset",
        format!("0x{fdbar:X}"),
    );
    let mut pos = DESCRIPTOR_SIZE;
    for region in &used {
        c.push_metadata(
            format!("{KEY_PREFIX}_ifd_region_{}", region.index),
            format!("{} region", region.name()),
            format!("0x{:X}-0x{:X}", region.base, region.end - 1),
        );
        if region.index == REGION_DESCRIPTOR {
            continue;
        }
        if region.base >= data.len() {
            if region.index == REGION_BIOS {
                return Err(error(format!(
                    "Truncated flash image: the BIOS region at 0x{:X} is outside the {} B image",
                    region.base,
                    data.len()
                )));
            }
            c.notes.push(format!(
                "{} region at 0x{:X} is outside the image (a second flash chip or a truncated dump)",
                region.name(),
                region.base
            ));
            continue;
        }
        if region.end > data.len() {
            return Err(error(format!(
                "Truncated flash image: the {} region ends at 0x{:X}, {} B present",
                region.name(),
                region.end,
                data.len()
            )));
        }
        list_unassigned(&mut c, &mut budget, data, pos, region.base);
        list_region(&mut c, &mut budget, data, region)?;
        pos = pos.max(region.end);
    }
    list_unassigned(&mut c, &mut budget, data, pos, data.len());
    c.consumed = data.len();
    budget.finish(&mut c);
    Ok(c)
}

/// List one region's contents.
fn list_region<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    data: &'a [u8],
    region: &Region,
) -> Result<()> {
    let bytes = &data[region.base..region.end];
    let name = region.name();
    if bytes.iter().all(|&b| b == 0xFF) {
        c.notes.push(format!("{name} region is erased"));
        return Ok(());
    }
    match content(region.index) {
        Content::Volumes => {
            let (found, _) = fv::sequence(
                c,
                budget,
                data,
                region.base,
                region.end,
                fv::Placement::Children(name),
            )?;
            if found == 0 {
                c.notes
                    .push(format!("{name} region holds no firmware volume"));
            }
        }
        Content::Opaque(reason) => {
            c.notes.push(format!("{name} region: {reason}; opaque"));
            budget.push(
                c,
                Child::opaque(format!("{name} region"), region.base, bytes),
            );
        }
        Content::Member => {
            let child = Child::stored(format!("{name} region"), region.base, bytes).if_recognized();
            budget.push(c, child);
        }
    }
    Ok(())
}

/// Bytes no region covers are listed when they hold a recognized format.
fn list_unassigned<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    data: &'a [u8],
    from: usize,
    to: usize,
) {
    let Some(bytes) = data.get(from..to) else {
        return;
    };
    if bytes.is_empty() || is_padding(bytes) {
        return;
    }
    let label = format!("Unassigned data at 0x{from:X}");
    budget.push(c, Child::stored(label, from, bytes).if_recognized());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_registers_decode_with_15_bit_fields() {
        let bios = decode_region(1, 0x0004_0003).unwrap();
        assert_eq!((bios.base, bios.end), (0x3000, 0x5000));
        let high = decode_region(1, 0x7FFF_4000).unwrap();
        assert_eq!((high.base, high.end), (0x0400_0000, 0x0800_0000));
        assert!(decode_region(4, 0x0000_7FFF).is_none());
        assert!(decode_region(4, FLREG_ERASED).is_none());
        // A zero limit field ends inside the descriptor: unused.
        assert!(decode_region(5, 0).is_none());
        let descriptor = decode_region(0, 0).unwrap();
        assert_eq!((descriptor.base, descriptor.end), (0, 0x1000));
    }

    #[test]
    fn region_count_stops_at_the_next_map_structure() {
        assert_eq!(region_count(0x40, &[0x30, 0x80, 0x100]), 16);
        assert_eq!(region_count(0x40, &[0x30, 0x54, 0x100]), 5);
        assert_eq!(region_count(0xE00, &[0x30]), 16);
    }
}
