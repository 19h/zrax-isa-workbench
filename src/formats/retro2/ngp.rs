//! Neo Geo Pocket and Neo Geo Pocket Color ROMs.
//!
//! `NeeGee`, "Everything You Always Wanted To Know About `NeoGeo` Pocket
//! Color" (2000-04-16), Cart ROM Header Info, and `NeoPop` `ngp/rom.h`
//! `RomHeader`: the cartridge appears at 0x200000 and starts with a 64-byte
//! header: recognition code (28) `COPYRIGHT BY SNK CORPORATION` (SNK) or
//! ` LICENSED BY SNK CORPORATION` (third party; the strings as
//! rom-properties `ngpc_structs.h` sizes them to the field), startup
//! address (4, little-endian) at 0x1C, ID code (2, little-endian BCD) at
//! 0x20, version (1) at 0x22, compatible system (1: 0x00 monochrome, 0x10
//! color) at 0x23, title (12, ASCII) at 0x24 and 16 reserved zero bytes at
//! 0x30. The last 16 KiB block is reserved for the system program.
//!
//! The main CPU is a Toshiba TLCS-900/H; a Z80-compatible sound CPU runs a
//! program the main CPU loads at run time (`NeeGee`). `NeoPop` `mem.h` maps
//! the cartridge at 0x200000-0x3FFFFF and, beyond 2 MiB, at
//! 0x800000-0x9FFFFF, and `reset_memory` hands the startup address to the
//! BIOS.

use super::*;

/// Recognition codes (28 bytes each).
const SNK_CODE: &[u8; 28] = b"COPYRIGHT BY SNK CORPORATION";
const LICENSEE_CODE: &[u8; 28] = b" LICENSED BY SNK CORPORATION";

/// Header fields.
const HEADER_SIZE: usize = 0x40;
const STARTUP: usize = 0x1c;
const ID_CODE: usize = 0x20;
const VERSION: usize = 0x22;
const SYSTEM: usize = 0x23;
const TITLE: (usize, usize) = (0x24, 12);
const RESERVED: usize = 0x30;

/// Compatible system codes.
const SYSTEM_MONOCHROME: u8 = 0x00;
const SYSTEM_COLOR: u8 = 0x10;

/// Cartridge windows (`NeoPop` `ROM_START`, `HIROM_START`), 2 MiB each.
const ROM_START: u64 = 0x20_0000;
const HIROM_START: u64 = 0x80_0000;
const WINDOW_SIZE: usize = 2 << 20;

/// TLCS-900/H code, little-endian (the header's own words are
/// little-endian).
const TLCS900: Target = Target::new(Isa::Tlcs900, 16, Endianness::Little);
const CPU_VARIANT: &str = "TLCS-900/H";

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(SNK_CODE) || data.starts_with(LICENSEE_CODE)
}

/// Whether `address` lies in the mapped cartridge.
fn is_mapped(address: u64, rom_size: usize) -> bool {
    let low = rom_size.min(WINDOW_SIZE) as u64;
    let high = rom_size.saturating_sub(WINDOW_SIZE) as u64;
    (ROM_START..ROM_START + low).contains(&address)
        || (HIROM_START..HIROM_START + high).contains(&address)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "Neo Geo Pocket header", 0, HEADER_SIZE)?;
    if !detect(data) {
        return Err(error(
            "Missing Neo Geo Pocket recognition code COPYRIGHT or LICENSED BY SNK CORPORATION",
        ));
    }
    if data.len() > 2 * WINDOW_SIZE {
        return Err(error(format!(
            "Unsupported Neo Geo Pocket ROM of {} B: the cartridge windows hold 4 MiB",
            data.len()
        )));
    }
    let startup = le_u32(data, STARTUP)?;
    if !is_mapped(u64::from(startup), data.len()) {
        return Err(error(format!(
            "Invalid startup address 0x{startup:06X}: outside the {} cartridge mapped at 0x200000",
            size_text(data.len() as u64)
        )));
    }
    let system = match header[SYSTEM] {
        SYSTEM_MONOCHROME => "monochrome".to_string(),
        SYSTEM_COLOR => "color".to_string(),
        other => format!("unknown system code 0x{other:02X}"),
    };
    let title = header_text(&header[TITLE.0..TITLE.0 + TITLE.1]);
    let id_code = u16::from_le_bytes([header[ID_CODE], header[ID_CODE + 1]]);
    let licensee = if data.starts_with(SNK_CODE) {
        "SNK"
    } else {
        "third party"
    };

    let mut c = Container::new(FileFormat::NgpRom, CPU_VARIANT, "ngp");
    c.target = Some(TLCS900);
    c.entry = Some(u64::from(startup));
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "Neo Geo Pocket ROM {title} ({licensee}); {system}; ID code {id_code:04X}; version {}",
        header[VERSION]
    ));
    c.notes.push(format!(
        "Startup address 0x{startup:06X}; Toshiba TLCS-900/H main CPU (NeeGee); the Z80 sound \
            program is loaded at run time and is not located by the header"
    ));
    if header[RESERVED..].iter().any(|&b| b != 0) {
        c.notes
            .push("Reserved header bytes 0x30-0x3F are not all zero".into());
    }
    c.push_metadata("ngp_title", "Title", title);
    c.push_metadata("ngp_id_code", "ID code", format!("{id_code:04X}"));
    c.push_metadata("ngp_system", "Compatible system", system);
    let (low, high) = data.split_at(data.len().min(WINDOW_SIZE));
    c.sections.push(stored_section("ROM", ROM_START, 0, low));
    if !high.is_empty() {
        c.sections.push(stored_section(
            "ROM above 2 MiB",
            HIROM_START,
            WINDOW_SIZE,
            high,
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_addresses_must_be_in_a_cartridge_window() {
        assert!(is_mapped(0x20_0040, 0x8_0000));
        assert!(!is_mapped(0x28_0000, 0x8_0000));
        assert!(is_mapped(0x80_0010, 0x30_0000));
        assert!(!is_mapped(0x80_0010, 0x20_0000));
    }

    #[test]
    fn recognition_codes_fill_the_28_byte_field() {
        assert!(detect(SNK_CODE));
        assert!(detect(LICENSEE_CODE));
        assert!(!detect(b"COPYRIGHT BY SNK CORP"));
    }
}
