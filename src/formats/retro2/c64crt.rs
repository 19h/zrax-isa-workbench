//! Commodore 64 `.crt` cartridge images.
//!
//! VICE manual §17.14 "The CRT cartridge image format" (and MAME
//! `src/lib/formats/cbm_crt.cpp`), all fields big-endian: signature `C64
//! CARTRIDGE   ` (16), file header length (4; the default and minimum is
//! 0x40, "some cartridge images exist which use a value of $00000020, which
//! is wrong"), version (2) at 0x14, hardware type (2) at 0x16, EXROM (1) at
//! 0x18, GAME (1) at 0x19, hardware subtype (1) at 0x1A, name (32) at 0x20.
//! CHIP packets follow the header: `CHIP` (4), total packet length (4, which
//! "should always be equal to ROM image size + $10"), chip type (2: 0 ROM,
//! 1 RAM, 2 Flash ROM, 3 EEPROM), bank number (2), load address (2) and ROM
//! image size (2), then the data.
//!
//! The C64 CPU is a 6510 (MAME `c64.cpp`, `m6510_device`). Each ROM, Flash
//! or EEPROM chip is classified as 6510 code on its own; RAM chips are data.
//! The cartridge type defines the banking, which is not modeled.

use super::*;
use crate::formats::container::{Child, MAX_COMPONENTS};

/// The C64 signature (VICE lists C128, CBM2, VIC20 and PLUS4 signatures,
/// which are other machines).
const SIGNATURE: &[u8; 16] = b"C64 CARTRIDGE   ";

/// File header fields.
const HEADER_LENGTH: usize = 0x10;
const VERSION: usize = 0x14;
const HARDWARE_TYPE: usize = 0x16;
const EXROM: usize = 0x18;
const GAME: usize = 0x19;
const SUBTYPE: usize = 0x1a;
const NAME: (usize, usize) = (0x20, 32);
const MIN_HEADER_LENGTH: usize = 0x40;

/// CHIP packet fields, relative to the packet.
const CHIP_MAGIC: &[u8; 4] = b"CHIP";
const CHIP_HEADER_SIZE: usize = 0x10;
const PACKET_LENGTH: usize = 0x4;
const CHIP_TYPE: usize = 0x8;
const BANK: usize = 0xa;
const LOAD_ADDRESS: usize = 0xc;
const IMAGE_SIZE: usize = 0xe;

/// Chip types (VICE §17.14.2).
const CHIP_ROM: u16 = 0;
const CHIP_RAM: u16 = 1;
const CHIP_FLASH: u16 = 2;
const CHIP_EEPROM: u16 = 3;

/// The 6510 addresses 64 KiB.
const ADDRESS_SPACE_END: u32 = 0x1_0000;

/// The CPU core (MAME `c64.cpp`).
const CPU_VARIANT: &str = "6510";

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(SIGNATURE)
}

fn chip_type_name(chip_type: u16) -> String {
    match chip_type {
        CHIP_ROM => "ROM".to_string(),
        CHIP_RAM => "RAM".to_string(),
        CHIP_FLASH => "Flash ROM".to_string(),
        CHIP_EEPROM => "EEPROM".to_string(),
        other => format!("unknown chip type {other}"),
    }
}

/// One CHIP packet.
struct Chip {
    offset: usize,
    length: usize,
    kind: u16,
    bank: u16,
    load_address: u16,
    size: u16,
}

/// The CHIP packet at `offset`, validated against the file and the 6510
/// address space.
fn chip(data: &[u8], offset: usize) -> Result<Chip> {
    let header = range(data, "CHIP packet header", offset, CHIP_HEADER_SIZE)?;
    if !header.starts_with(CHIP_MAGIC) {
        return Err(error(format!(
            "Invalid CHIP packet signature at 0x{offset:X}"
        )));
    }
    let length = be_u32(header, PACKET_LENGTH)?;
    let chip = Chip {
        offset,
        length: usize::try_from(length)
            .map_err(|_| error(format!("Invalid CHIP packet length 0x{length:X}")))?,
        kind: be_u16(header, CHIP_TYPE)?,
        bank: be_u16(header, BANK)?,
        load_address: be_u16(header, LOAD_ADDRESS)?,
        size: be_u16(header, IMAGE_SIZE)?,
    };
    if chip.length < CHIP_HEADER_SIZE + usize::from(chip.size) {
        return Err(error(format!(
            "Invalid CHIP packet length {} B at 0x{offset:X}: shorter than the 16 B header and {} \
                B of data",
            chip.length, chip.size
        )));
    }
    if u32::from(chip.load_address) + u32::from(chip.size) > ADDRESS_SPACE_END {
        return Err(error(format!(
            "Invalid CHIP packet at 0x{offset:X}: load address 0x{:04X} + {} B exceeds the 64 KiB \
                address space",
            chip.load_address, chip.size
        )));
    }
    range(data, "CHIP packet", offset, chip.length)?;
    Ok(chip)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "CRT header", 0, MIN_HEADER_LENGTH)?;
    if !detect(data) {
        return Err(error("Missing CRT signature C64 CARTRIDGE"));
    }
    let declared = be_u32(data, HEADER_LENGTH)?;
    let start = usize::try_from(declared)
        .unwrap_or(usize::MAX)
        .max(MIN_HEADER_LENGTH);
    if start > data.len() {
        return Err(error(format!(
            "Truncated CRT header: header length 0x{declared:X} exceeds the {} B file",
            data.len()
        )));
    }
    let name = header_text(&header[NAME.0..NAME.0 + NAME.1]);
    let hardware = be_u16(data, HARDWARE_TYPE)?;

    let mut c = Container::new(FileFormat::C64Crt, CPU_VARIANT, "c64crt");
    c.target = Some(MOS_6502);
    c.consumed = data.len();
    c.notes.push(format!(
        "C64 cartridge {name}; CRT version {}.{:02}; hardware type {hardware}; subtype {}; EXROM \
            {}; GAME {}",
        header[VERSION],
        header[VERSION + 1],
        header[SUBTYPE],
        header[EXROM],
        header[GAME]
    ));
    if u64::from(declared) < MIN_HEADER_LENGTH as u64 {
        c.notes.push(format!(
            "Header length 0x{declared:X} is below the minimum 0x40; CHIP packets are read from \
                0x40"
        ));
    }
    c.push_metadata("c64crt_name", "Cartridge name", name);
    c.push_metadata("c64crt_hardware_type", "Hardware type", u64::from(hardware));
    push_chips(&mut c, data, start)?;
    c.notes.push(
        "6510 CPU (MAME); each ROM chip is a separate slice at its load address; banking by the \
            cartridge hardware is not modeled"
            .into(),
    );
    Ok(c)
}

/// List every CHIP packet up to the end of the file.
fn push_chips<'a>(c: &mut Container<'a>, data: &'a [u8], start: usize) -> Result<()> {
    let mut offset = start;
    let mut listed = 0usize;
    let mut unlisted = 0usize;
    while offset < data.len() {
        let chip = chip(data, offset)?;
        let bytes_start = chip.offset + CHIP_HEADER_SIZE;
        let bytes = &data[bytes_start..bytes_start + usize::from(chip.size)];
        if chip.length != CHIP_HEADER_SIZE + usize::from(chip.size) {
            c.notes.push(format!(
                "CHIP packet at 0x{:X}: packet length {} B is not the image size + 16 B",
                chip.offset, chip.length
            ));
        }
        offset += chip.length;
        if listed >= MAX_COMPONENTS {
            unlisted += 1;
            continue;
        }
        listed += 1;
        let label = format!(
            "CHIP bank {} at 0x{:04X} ({})",
            chip.bank,
            chip.load_address,
            chip_type_name(chip.kind)
        );
        let child = if chip.kind == CHIP_RAM {
            Child::opaque(label, bytes_start, bytes)
        } else {
            Child::stored(label, bytes_start, bytes)
                .with_target(MOS_6502)
                .with_variant(CPU_VARIANT)
                .as_code()
        };
        c.children.push(child);
    }
    if listed == 0 {
        return Err(error(
            "Missing CHIP packets: the CRT file holds no chip data",
        ));
    }
    if unlisted > 0 {
        c.notes.push(format!(
            "{unlisted} further CHIP packets were not listed (limit {MAX_COMPONENTS})"
        ));
    }
    c.push_metadata(
        "c64crt_chip_count",
        "CHIP packets",
        (listed + unlisted) as u64,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_packets_must_fit_the_address_space() {
        let mut data = vec![0u8; CHIP_HEADER_SIZE + 0x10];
        data[..4].copy_from_slice(CHIP_MAGIC);
        data[PACKET_LENGTH..PACKET_LENGTH + 4].copy_from_slice(&0x20u32.to_be_bytes());
        data[LOAD_ADDRESS..LOAD_ADDRESS + 2].copy_from_slice(&0xfff8u16.to_be_bytes());
        data[IMAGE_SIZE..IMAGE_SIZE + 2].copy_from_slice(&0x10u16.to_be_bytes());
        assert!(chip(&data, 0).is_err());
        data[LOAD_ADDRESS..LOAD_ADDRESS + 2].copy_from_slice(&0x8000u16.to_be_bytes());
        assert_eq!(chip(&data, 0).unwrap().size, 0x10);
    }
}
