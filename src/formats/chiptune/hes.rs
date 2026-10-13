//! PC Engine HES tunes (Mamiya, "HES Music Format Spec V1.00", Aug. 17,
//! 2000).
//!
//! Header (little-endian): `HESM` (4), version 0 (1), start song (1),
//! request (init) address (2, a logical address), initial MPR0-MPR7 bank
//! registers (8); then a `DATA` block: `DATA` (4), data size (4), load
//! address (4, a physical address), reserved 0 (4), data. Physical
//! addresses span 0x000000-0x1FFFFF (ROM 0x000000-0x0FFFFF). The
//! specification's I/O map names the `HuC6280`, whose MPR registers map
//! logical 8 KiB pages to physical banks.
//!
//! The specification shows one `DATA` block. Game Music Emu 0.6.5
//! (`Hes_Emu.cpp`) notes that "many files have bad sizes in the only block"
//! and loads what is present, so a size beyond the file is noted, not
//! rejected; further `DATA` blocks that follow directly are read as well.

use super::*;

/// Header: magic, version, start song, init address, MPR0-MPR7.
const MAGIC: &[u8; 4] = b"HESM";
const HEADER_SIZE: usize = 0x10;
const VERSION: usize = 0x04;
const START_SONG: usize = 0x05;
const INIT: usize = 0x06;
const MPR: usize = 0x08;
const MPR_COUNT: usize = 8;

/// The only specified version.
const SUPPORTED_VERSION: u8 = 0;

/// `DATA` block header: magic, size, load address, reserved.
const DATA_MAGIC: &[u8; 4] = b"DATA";
const DATA_HEADER_SIZE: usize = 0x10;
const DATA_SIZE: usize = 0x04;
const DATA_LOAD: usize = 0x08;
const DATA_RESERVED: usize = 0x0c;

/// Physical address space of the memory map (21 bits).
const PHYSICAL_SPACE: u64 = 0x20_0000;

/// The `HuC6280` runs 6502-family code, little-endian.
const HUC6280: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// `HESM` at offset 0.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Header, then the `DATA` blocks as load sections at their physical
/// addresses.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = data.get(..HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated HES header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    if !header.starts_with(MAGIC) {
        return Err(error("Missing HES magic"));
    }
    let version = header[VERSION];
    if version != SUPPORTED_VERSION {
        return Err(error(format!("Unsupported HES version {version}")));
    }
    let init = le_u16(header, INIT)?;
    let banks = &header[MPR..MPR + MPR_COUNT];
    let mut c = Container::new(FileFormat::Hes, Layout::Hes.label(), "hes");
    c.target = Some(HUC6280);
    c.entry = Some(u64::from(init));
    c.code_sections = true;
    let mut pos = HEADER_SIZE;
    loop {
        pos = data_block(&mut c, data, pos)?;
        if !data[pos..].starts_with(DATA_MAGIC) || c.sections.len() == container::MAX_COMPONENTS {
            break;
        }
    }
    c.consumed = pos;
    if c.sections.iter().all(|section| section.data.is_empty()) {
        return Err(error("Missing HES program data"));
    }
    c.notes.insert(
        0,
        format!(
            "HES version {version}: start song {}; init 0x{init:04X} (logical address); MPR0-MPR7 {}",
            header[START_SONG],
            banks
                .iter()
                .map(|bank| format!("0x{bank:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );
    c.notes.insert(
        1,
        "HuC6280 (6502-family) driver; load addresses are physical addresses, which the MPR banks map into the 64 KiB logical space"
            .into(),
    );
    if pos < data.len() {
        c.notes.push(format!(
            "{} after the last DATA block; ignored",
            compressed::size_text(data.len() - pos)
        ));
    }
    Ok(c)
}

/// The `DATA` block at `pos`; returns the offset after its data. A size
/// beyond the file is clipped to the bytes present.
fn data_block<'a>(c: &mut Container<'a>, data: &'a [u8], pos: usize) -> Result<usize> {
    let header = data
        .get(pos..pos + DATA_HEADER_SIZE)
        .ok_or_else(|| error(format!("Truncated HES DATA block header at 0x{pos:X}")))?;
    if !header.starts_with(DATA_MAGIC) {
        return Err(error(format!("Missing HES DATA block at 0x{pos:X}")));
    }
    let size = le_u32(header, DATA_SIZE)? as usize;
    let load = le_u32(header, DATA_LOAD)?;
    let reserved = le_u32(header, DATA_RESERVED)?;
    let body_at = pos + DATA_HEADER_SIZE;
    let available = data.len() - body_at;
    let stored = size.min(available);
    if size > available {
        c.notes.push(format!(
            "DATA block at 0x{pos:X} declares {size} B; {available} B present"
        ));
    }
    if reserved != 0 {
        c.notes.push(format!(
            "DATA block at 0x{pos:X}: reserved field is 0x{reserved:X}, not 0"
        ));
    }
    if u64::from(load) + stored as u64 > PHYSICAL_SPACE {
        c.notes.push(format!(
            "DATA block at 0x{pos:X}: load address 0x{load:06X} + {stored} B exceeds the 2 MiB physical address space"
        ));
    }
    c.sections.push(borrowed_section(
        format!("DATA 0x{load:06X}"),
        u64::from(load),
        body_at,
        &data[body_at..body_at + stored],
    ));
    Ok(body_at + stored)
}
