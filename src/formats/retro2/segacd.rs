//! Sega CD / Mega-CD system areas: the boot sector of a system disc.
//!
//! Sega "Mega-CD Disc Format Specifications" Ver 2.00 (1992-02-24): the
//! system ID (0x000-0x0FF), the disc ID (0x100-0x1FF), the initial program
//! code from 0x200 in sector 0 and the system program in sectors 1-15
//! (Fig. 3-2). System ID (Appendix 2, Fig. A-2; rom-properties
//! `MCD_SystemID`), big-endian: disc identifier `SEGADISCSYSTEM` (a data disc,
//! `SEGADATADISC`, has no boot program), volume name (11) at 0x10, system
//! name (11) at 0x20, then the initial program (IP) offset, load size, entry
//! offset and work RAM size at 0x30-0x3F and the same four values for the
//! system program (SP) at 0x40-0x4F. The SP starts on a sector boundary
//! (lower 11 bits 0). The disc ID has the Mega Drive header layout:
//! hardware designation at 0x100, titles at 0x120 and 0x150, product code
//! at 0x180, region at 0x1F0 (Appendix 3).
//!
//! The main CPU runs the IP after the sub-CPU's boot program loads it, and
//! the sub-CPU executes the SP ("Mega-CD BIOS Manual" Ver 2.00 §4). The main
//! CPU is the Mega Drive's MC68000; the sub-CPU is an MC68000 at 12.5 MHz
//! ("Mega-CD Outline" §2). Where each program is loaded is not established
//! by the documents fetched, so no load address is reported.

use super::*;
use crate::formats::container::Child;
use crate::formats::MAX_PAYLOAD;

/// Disc identifier of a system disc.
const DISC_SYSTEM: &[u8] = b"SEGADISCSYSTEM";

/// System ID and disc ID.
const SYSTEM_AREA_SIZE: usize = 0x200;

/// System ID fields: offset and size.
const VOLUME_NAME: (usize, usize) = (0x10, 11);
const SYSTEM_NAME: (usize, usize) = (0x20, 11);

/// Disc ID fields: offset and size.
const HARDWARE: (usize, usize) = (0x100, 16);
const DOMESTIC_TITLE: (usize, usize) = (0x120, 48);
const OVERSEAS_TITLE: (usize, usize) = (0x150, 48);
const PRODUCT: (usize, usize) = (0x180, 14);
const REGION: (usize, usize) = (0x1f0, 16);

/// A boot program's System ID entry, relative to its base: disc offset,
/// load size, entry offset and work RAM size (Fig. A-2).
const PROGRAM_OFFSET: usize = 0;
const PROGRAM_SIZE: usize = 4;
const PROGRAM_ENTRY: usize = 8;
const PROGRAM_WORK_RAM: usize = 12;

/// Sectors are 2048 bytes; the SP starts at a sector boundary.
const SECTOR_SIZE: u32 = 0x800;

/// One boot program's System ID entry: offset, load size, entry offset and
/// work RAM size, at `base`.
struct Program {
    label: &'static str,
    variant: &'static str,
    base: usize,
    key: &'static str,
    /// The program starts on a sector boundary (the SP, Appendix 2).
    sector_aligned: bool,
}

const PROGRAMS: [Program; 2] = [
    Program {
        label: "Initial program (main CPU)",
        variant: "MC68000 (main CPU)",
        base: 0x30,
        key: "segacd_ip",
        sector_aligned: false,
    },
    Program {
        label: "System program (sub-CPU)",
        variant: "MC68000 (sub-CPU)",
        base: 0x40,
        key: "segacd_sp",
        sector_aligned: true,
    },
];

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(DISC_SYSTEM)
}

fn field_text(data: &[u8], (offset, size): (usize, usize)) -> String {
    header_text(&data[offset..offset + size])
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    range(data, "Sega CD system area", 0, SYSTEM_AREA_SIZE)?;
    if !detect(data) {
        return Err(error("Missing Sega CD disc identifier SEGADISCSYSTEM"));
    }
    let mut c = Container::new(FileFormat::SegaCdIp, "68000", "segacd");
    c.target = Some(M68000);
    c.consumed = data.len();
    c.notes.push(format!(
        "Sega CD system disc; volume {}; system {}; hardware {}",
        field_text(data, VOLUME_NAME),
        field_text(data, SYSTEM_NAME),
        field_text(data, HARDWARE)
    ));
    c.notes.push(format!(
        "Domestic title: {}; overseas title: {}",
        field_text(data, DOMESTIC_TITLE),
        field_text(data, OVERSEAS_TITLE)
    ));
    c.notes.push(format!(
        "Product: {}; region: {}",
        field_text(data, PRODUCT),
        field_text(data, REGION)
    ));
    c.push_metadata(
        "segacd_volume_name",
        "Volume name",
        field_text(data, VOLUME_NAME),
    );
    c.push_metadata("segacd_product", "Product code", field_text(data, PRODUCT));
    c.push_metadata("segacd_region", "Region", field_text(data, REGION));
    let mut end = SYSTEM_AREA_SIZE;
    for program in &PROGRAMS {
        if let Some(program_end) = push_program(&mut c, data, program)? {
            end = end.max(program_end);
        }
    }
    c.notes.push(
        "Both CPUs are MC68000s (Mega-CD Outline); load addresses are not encoded in the system \
            ID"
        .into(),
    );
    if data.len() > end {
        c.notes.push(format!(
            "{} after 0x{end:X} are not analyzed (the disc continues with its file system)",
            size_text((data.len() - end) as u64)
        ));
    }
    Ok(c)
}

/// List one boot program as a child; returns its end offset.
fn push_program<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    program: &Program,
) -> Result<Option<usize>> {
    let offset = be_u32(data, program.base + PROGRAM_OFFSET)?;
    let size = be_u32(data, program.base + PROGRAM_SIZE)?;
    let entry = be_u32(data, program.base + PROGRAM_ENTRY)?;
    let work_ram = be_u32(data, program.base + PROGRAM_WORK_RAM)?;
    c.push_metadata(
        format!("{}_offset", program.key),
        format!("{} offset", program.label),
        format!("0x{offset:X}"),
    );
    if size == 0 {
        c.notes.push(format!(
            "{}: load size 0; nothing to analyze",
            program.label
        ));
        return Ok(None);
    }
    if size as usize > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported {} of {size} B: the limit is {}",
            program.label,
            size_text(MAX_PAYLOAD as u64)
        )));
    }
    let start = offset as usize;
    let bytes = range(data, program.label, start, size as usize)?;
    c.notes.push(format!(
        "{}: disc offset 0x{offset:X} + {size} B; entry offset 0x{entry:X}; work RAM {work_ram} B",
        program.label
    ));
    if entry >= size {
        c.notes.push(format!(
            "{}: entry offset 0x{entry:X} lies outside the {size} B program",
            program.label
        ));
    }
    if program.sector_aligned && offset % SECTOR_SIZE != 0 {
        c.notes.push(format!(
            "{}: offset 0x{offset:X} is not on a 2048-byte sector boundary",
            program.label
        ));
    }
    c.children.push(
        Child::stored(program.label, start, bytes)
            .with_target(M68000)
            .with_variant(program.variant)
            .as_code(),
    );
    Ok(Some(start + bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_discs_are_not_system_discs() {
        assert!(detect(b"SEGADISCSYSTEM  "));
        assert!(!detect(b"SEGADATADISC    "));
    }
}
