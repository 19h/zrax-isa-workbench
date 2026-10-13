//! Bandai `WonderSwan` and `WonderSwan` Color ROMs.
//!
//! trap15 "`WSMan` rev.7", Cartridge Metadata: the last 10 bytes of the ROM,
//! preceded by a byte that must be zero: publisher ID (1), system (1: 0
//! `WonderSwan`, 1 `WonderSwan` Color; "BIOS seems to ignore this"), game ID
//! (1), revision (1), ROM size code (1), save type (1), flags (1: bit 0
//! vertical, bit 1 8-bit ROM bus, bit 2 1-cycle ROM access), RTC present (1)
//! and the checksum (2, little-endian). "`WStech` doc v2.4" §6: the checksum
//! is the sum of all ROM bytes except the last two. `WSMan` marks size codes
//! 0 and 1 as uncertain, so only codes 2-9 (512 KiB to 16 MiB) are used.
//!
//! The footer has no magic, so the layout is weak: the size code must match
//! the file size, the byte before the footer must be zero, and the checksum
//! must match. The CPU is a NEC V30MZ, "binary compatible with the Intel
//! 80186" (`WSMan` CPU Overview); it starts at FFFF:0000 (Mednafen
//! `v30mz_reset`; `WSMan`: execution "begins at 0FFFF:0000h"). Which ROM
//! bank the reset address reaches is not stated in the sources.

use super::*;

/// Footer fields, relative to the start of the 10-byte footer.
const FOOTER_SIZE: usize = 10;
const PUBLISHER: usize = 0;
const SYSTEM: usize = 1;
const GAME_ID: usize = 2;
const REVISION: usize = 3;
const ROM_SIZE: usize = 4;
const SAVE_TYPE: usize = 5;
const FLAGS: usize = 6;
const RTC: usize = 7;
const CHECKSUM: usize = 8;

/// The byte before the footer must be zero (`WSMan`).
const ZERO_BYTE_SIZE: usize = 1;

/// ROM size codes that `WSMan` lists without a question mark.
#[rustfmt::skip]
const ROM_SIZES: [(u8, usize); 8] = [
    (0x2, 512 << 10),
    (0x3, 1 << 20),
    (0x4, 2 << 20),
    (0x5, 3 << 20),
    (0x6, 4 << 20),
    (0x7, 6 << 20),
    (0x8, 8 << 20),
    (0x9, 16 << 20),
];

/// Save types (`WSMan`).
const SAVE_TYPES: [(u8, &str); 9] = [
    (0x00, "none"),
    (0x01, "8 KiB SRAM"),
    (0x02, "32 KiB SRAM"),
    (0x03, "128 KiB SRAM"),
    (0x04, "256 KiB SRAM"),
    (0x05, "512 KiB SRAM"),
    (0x10, "1 Kbit EEPROM"),
    (0x20, "16 Kbit EEPROM"),
    (0x50, "8 Kbit EEPROM"),
];

/// Flag bits.
const FLAG_VERTICAL: u8 = 1 << 0;
const FLAG_8_BIT_BUS: u8 = 1 << 1;
const FLAG_1_CYCLE: u8 = 1 << 2;

/// System byte values.
const SYSTEM_COLOR: u8 = 1;

/// The reset address FFFF:0000 as a 20-bit physical address.
const RESET_ADDRESS: u64 = 0xffff0;

/// V30MZ code: 16-bit x86, little-endian.
const V30MZ: Target = Target::new(Isa::X86, 16, Endianness::Little);
const CPU_VARIANT: &str = "NEC V30MZ";

/// The 16-bit sum of every byte except the stored checksum.
fn checksum(data: &[u8]) -> u16 {
    data[..data.len() - 2]
        .iter()
        .fold(0u16, |sum, &b| sum.wrapping_add(u16::from(b)))
}

fn declared_size(code: u8) -> Option<usize> {
    ROM_SIZES
        .iter()
        .find(|(known, _)| *known == code)
        .map(|(_, size)| *size)
}

/// Why the footer does not describe `data`, if it does not.
fn mismatch(data: &[u8]) -> Option<String> {
    let Some(start) = data.len().checked_sub(FOOTER_SIZE + ZERO_BYTE_SIZE) else {
        return Some(format!("{} B cannot hold the footer", data.len()));
    };
    let footer = &data[start + ZERO_BYTE_SIZE..];
    let code = footer[ROM_SIZE];
    let Some(size) = declared_size(code) else {
        return Some(format!(
            "ROM size code 0x{code:02X} is not one of 0x02-0x09"
        ));
    };
    if size != data.len() {
        return Some(format!(
            "the footer declares {}, the file holds {} B",
            size_text(size as u64),
            data.len()
        ));
    }
    if data[start] != 0 {
        return Some(format!(
            "the byte before the footer at 0x{start:X} is 0x{:02X}, not 0",
            data[start]
        ));
    }
    let stored = u16::from_le_bytes([footer[CHECKSUM], footer[CHECKSUM + 1]]);
    let computed = checksum(data);
    (stored != computed)
        .then(|| format!("checksum 0x{stored:04X} does not match the computed 0x{computed:04X}"))
}

/// Weak recognition: a footer whose size, zero byte and checksum all match.
pub(super) fn detect(data: &[u8]) -> bool {
    mismatch(data).is_none()
}

fn save_type_name(code: u8) -> String {
    SAVE_TYPES
        .iter()
        .find(|(known, _)| *known == code)
        .map_or_else(
            || format!("unknown (0x{code:02X})"),
            |(_, name)| (*name).to_string(),
        )
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if let Some(reason) = mismatch(data) {
        return Err(error(format!("Invalid WonderSwan footer: {reason}")));
    }
    let footer = &data[data.len() - FOOTER_SIZE..];
    let system = if footer[SYSTEM] == SYSTEM_COLOR {
        "WonderSwan Color"
    } else {
        "WonderSwan"
    };
    let flags = footer[FLAGS];
    let stored = u16::from_le_bytes([footer[CHECKSUM], footer[CHECKSUM + 1]]);

    let mut c = Container::new(FileFormat::WonderSwanRom, CPU_VARIANT, "wswan");
    c.target = Some(V30MZ);
    c.entry = Some(RESET_ADDRESS);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "{system} ROM of {}; publisher 0x{:02X}; game ID 0x{:02X}; revision {}",
        size_text(data.len() as u64),
        footer[PUBLISHER],
        footer[GAME_ID],
        footer[REVISION]
    ));
    c.notes.push(format!(
        "Save type {}; {} orientation; {}-bit ROM bus; {}-cycle ROM access; RTC {}",
        save_type_name(footer[SAVE_TYPE]),
        if flags & FLAG_VERTICAL == 0 {
            "horizontal"
        } else {
            "vertical"
        },
        if flags & FLAG_8_BIT_BUS == 0 { 16 } else { 8 },
        if flags & FLAG_1_CYCLE == 0 { 3 } else { 1 },
        if footer[RTC] == 0 {
            "absent"
        } else {
            "present"
        }
    ));
    c.notes.push(format!(
        "Checksum 0x{stored:04X} verified (sum of all bytes except the last two)"
    ));
    c.notes.push(
        "NEC V30MZ, binary compatible with the Intel 80186 (WSMan); reported as 16-bit x86".into(),
    );
    c.notes.push(
        "Entry is the reset address FFFF:0000 (physical 0xFFFF0); the section address is the ROM \
            offset, and the cartridge maps banks into the 20-bit address space"
            .into(),
    );
    c.push_metadata("wswan_system", "System", system.to_string());
    c.push_metadata(
        "wswan_publisher",
        "Publisher ID",
        u64::from(footer[PUBLISHER]),
    );
    c.push_metadata("wswan_game_id", "Game ID", u64::from(footer[GAME_ID]));
    c.push_metadata("wswan_checksum", "Checksum", format!("0x{stored:04X}"));
    c.sections.push(stored_section("ROM", 0, 0, data));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksum_skips_its_own_two_bytes() {
        let data = [1u8, 2, 3, 0xff, 0xff];
        assert_eq!(checksum(&data), 6);
    }

    #[test]
    fn uncertain_size_codes_are_not_used() {
        assert_eq!(declared_size(0x2), Some(512 << 10));
        assert_eq!(declared_size(0x0), None);
        assert_eq!(declared_size(0x1), None);
    }
}
