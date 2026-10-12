//! `PlayStation` `PS-X EXE` executables (psx-spx "CDROM File Playstation EXE
//! and SYSTEM.CNF"; `PSn00bSDK` `struct EXEC` in `libpsn00b/include/psxapi.h`
//! and the header writer in `tools/util/elf2x.c` at `5d9aa2d3`).
//!
//! Header (0x800 bytes, little-endian): ID `PS-X EXE` (8), zero fill (8),
//! initial PC `pc0` (4) at 0x10, initial GP `gp0` (4), destination `t_addr`
//! (4), text size `t_size` (4, a multiple of 0x800), `d_addr` and `d_size`
//! (unused), memfill `b_addr` and `b_size`, stack base and offset `s_addr`
//! and `s_size`, BIOS scratch (20) at 0x38, then an ASCII region marker from
//! 0x4C. The text follows at 0x800 and is loaded to `t_addr`; there is no
//! relocation information.

use super::*;

/// ASCII ID at offset 0.
const MAGIC: &[u8; 8] = b"PS-X EXE";

/// Header size; the text starts here.
const HEADER_SIZE: usize = 0x800;

/// CD-ROM sector size; `t_size` is a whole number of sectors.
const SECTOR_SIZE: u32 = 0x800;

/// Header fields.
const PC0: usize = 0x10;
const GP0: usize = 0x14;
const T_ADDR: usize = 0x18;
const T_SIZE: usize = 0x1c;
const B_ADDR: usize = 0x28;
const B_SIZE: usize = 0x2c;
const S_ADDR: usize = 0x30;
const S_SIZE: usize = 0x34;

/// Region marker field (elf2x `license[64]`).
const REGION_MARKER: usize = 0x4c;
const REGION_MARKER_SIZE: usize = 64;

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated PS-X EXE header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing PS-X EXE ID"));
    }
    let pc0 = le_u32(data, PC0)?;
    let gp0 = le_u32(data, GP0)?;
    let t_addr = le_u32(data, T_ADDR)?;
    let t_size = le_u32(data, T_SIZE)?;
    let b_addr = le_u32(data, B_ADDR)?;
    let b_size = le_u32(data, B_SIZE)?;
    let s_addr = le_u32(data, S_ADDR)?;
    let s_size = le_u32(data, S_SIZE)?;
    if t_size == 0 {
        return Err(error("Missing PS-X EXE text: t_size is 0"));
    }
    let text_size = t_size as usize;
    let text_bytes = data.get(HEADER_SIZE..).unwrap_or_default();
    let text_bytes = text_bytes.get(..text_size).ok_or_else(|| {
        error(format!(
            "Truncated PS-X EXE text: t_size {text_size} B, {} B present",
            text_bytes.len()
        ))
    })?;
    let end = HEADER_SIZE + text_size;
    let trailing = &data[end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the PS-X EXE text at 0x{end:X}",
            size_text(trailing.len())
        )));
    }

    let mut c = Container::new(FileFormat::PsxExe, "R3000A (MIPS I)", "psx");
    c.target = Some(Target::new(Isa::Mips, 32, Endianness::Little));
    c.entry = Some(u64::from(pc0));
    c.consumed = end;
    c.code_sections = true;
    c.notes.push(format!(
        "PlayStation PS-X EXE; text {} loaded at 0x{t_addr:08X}; no relocation information",
        size_text(text_size)
    ));
    c.notes.push(format!(
        "Initial PC 0x{pc0:08X}; initial GP 0x{gp0:08X}; stack 0x{s_addr:08X} + 0x{s_size:X}"
    ));
    if b_size != 0 {
        c.notes.push(format!(
            "Memfill 0x{b_addr:08X} + {b_size} B is zeroed before the program starts"
        ));
    }
    if t_size % SECTOR_SIZE != 0 {
        c.notes
            .push(format!("t_size {text_size} B is not a multiple of 2048 B"));
    }
    let text_end = u64::from(t_addr) + u64::from(t_size);
    if !(u64::from(t_addr)..text_end).contains(&u64::from(pc0)) {
        c.notes.push(format!(
            "Initial PC 0x{pc0:08X} lies outside the text at 0x{t_addr:08X}-0x{:08X}",
            text_end - 1
        ));
    }
    let region = text(&data[REGION_MARKER..REGION_MARKER + REGION_MARKER_SIZE]);
    if region.is_empty() {
        c.notes.push("No region marker".into());
    } else {
        c.notes.push(format!("Region marker: {region}"));
    }
    if !trailing.is_empty() {
        c.notes.push(format!(
            "{} of padding after the text",
            size_text(trailing.len())
        ));
    }
    c.notes.push(
        "The header names no CPU; the PlayStation CPU is a little-endian MIPS R3000A (MIPS I)"
            .into(),
    );
    c.push_metadata("psx_t_addr", "Text address", format!("0x{t_addr:08X}"));
    c.push_metadata("psx_t_size", "Text size (B)", u64::from(t_size));
    c.push_metadata("psx_region", "Region marker", region);
    c.sections.push(section(
        "Text",
        u64::from(t_addr),
        HEADER_SIZE,
        text_size,
        Cow::Borrowed(text_bytes),
        None,
    ));
    Ok(c)
}
