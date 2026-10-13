//! Atari Lynx `.lnx` cartridge images.
//!
//! Mednafen `lynx/cart.h` `LYNX_HEADER` and `CCart::DecodeHeader` (64 bytes,
//! little-endian after the magic): `LYNX` (4), bank 0 page size (2), bank 1
//! page size (2), version (2) at 8, cartridge name (32) at 0x0A,
//! manufacturer (16) at 0x2A, rotation (1) at 0x3A (0 none, 1 left, 2 right)
//! and 5 spare bytes. Mednafen accepts the header only with version 1. A
//! bank holds 256 pages, so its size is the page size times 256; Mednafen
//! supports page sizes 0x100, 0x200, 0x400 and 0x800 (64-512 KiB), and 0 for
//! an unused bank 1. Bank 0 follows the header, then bank 1.
//!
//! The CPU is a 65C02 (Mednafen `c65c02.h`, from Handy). The cartridge is
//! read through the cartridge port rather than mapped into the CPU's
//! address space, and its first block holds a boot loader that the boot ROM
//! decrypts and runs at 0x0200 (cc65 `libsrc/lynx/bootldr.s`), so the banks
//! are cartridge data that holds code, not a memory image.

use super::*;

/// Header magic and the version Mednafen requires.
const MAGIC: &[u8; 4] = b"LYNX";
const SUPPORTED_VERSION: u16 = 1;

/// Header fields.
const HEADER_SIZE: usize = 64;
const BANK0_PAGE_SIZE: usize = 4;
const BANK1_PAGE_SIZE: usize = 6;
const VERSION: usize = 8;
const CART_NAME: (usize, usize) = (0x0a, 32);
const MANUFACTURER: (usize, usize) = (0x2a, 16);
const ROTATION: usize = 0x3a;

/// Pages per bank, and the page sizes Mednafen maps.
const PAGES_PER_BANK: usize = 256;
const PAGE_SIZES: [u16; 4] = [0x100, 0x200, 0x400, 0x800];

/// The CPU core (Mednafen `c65c02.h`).
const CPU_VARIANT: &str = "65C02";

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC) && le_u16(data, VERSION).is_ok_and(|v| v == SUPPORTED_VERSION)
}

/// Bank 1 may be unused (page size 0); bank 0 holds the boot loader.
const OPTIONAL_BANK: u8 = 1;

/// The size of `bank` with `page_size`-byte pages.
fn bank_size(page_size: u16, bank: u8) -> Result<usize> {
    if page_size == 0 && bank == OPTIONAL_BANK {
        return Ok(0);
    }
    if !PAGE_SIZES.contains(&page_size) {
        return Err(error(format!(
            "Unsupported bank {bank} page size 0x{page_size:X}: Mednafen maps 0x100, 0x200, 0x400 \
                or 0x800"
        )));
    }
    Ok(usize::from(page_size) * PAGES_PER_BANK)
}

fn rotation_name(rotation: u8) -> String {
    match rotation {
        0 => "none".to_string(),
        1 => "left".to_string(),
        2 => "right".to_string(),
        other => format!("unknown (0x{other:02X})"),
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "LNX header", 0, HEADER_SIZE)?;
    if !detect(data) {
        return Err(error("Missing LNX magic LYNX with version 1"));
    }
    let bank0 = bank_size(le_u16(data, BANK0_PAGE_SIZE)?, 0)?;
    let bank1 = bank_size(le_u16(data, BANK1_PAGE_SIZE)?, 1)?;
    let contents = &data[HEADER_SIZE..];
    if contents.is_empty() {
        return Err(error(
            "Truncated LNX image: no cartridge data after the header",
        ));
    }
    if contents.len() > bank0 + bank1 {
        return Err(error(format!(
            "Invalid trailing data: {} B of cartridge data exceed the {} of banks 0 and 1",
            contents.len(),
            size_text((bank0 + bank1) as u64)
        )));
    }
    let name = header_text(&header[CART_NAME.0..CART_NAME.0 + CART_NAME.1]);
    let manufacturer = header_text(&header[MANUFACTURER.0..MANUFACTURER.0 + MANUFACTURER.1]);

    let mut c = Container::new(FileFormat::LynxRom, CPU_VARIANT, "lynx");
    c.target = Some(MOS_6502);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "Atari Lynx cartridge {name}; manufacturer {manufacturer}; rotation {}",
        rotation_name(header[ROTATION])
    ));
    c.notes.push(format!(
        "Bank 0: {}; bank 1: {}",
        size_text(bank0 as u64),
        if bank1 == 0 {
            "unused".to_string()
        } else {
            size_text(bank1 as u64)
        }
    ));
    if contents.len() < bank0 + bank1 {
        c.notes.push(format!(
            "{} of cartridge data are shorter than the declared banks; the rest reads as fill",
            size_text(contents.len() as u64)
        ));
    }
    c.notes.push(
        "65C02 CPU (Mednafen); the cartridge is read through the cartridge port, and its first \
            block holds a boot loader that the boot ROM decrypts (cc65 bootldr.s); decryption is \
            not attempted"
            .into(),
    );
    c.notes
        .push("Section addresses are byte offsets within each cartridge bank".into());
    c.push_metadata("lynx_cart_name", "Cartridge name", name);
    c.push_metadata("lynx_manufacturer", "Manufacturer", manufacturer);
    c.push_metadata("lynx_bank0_size", "Bank 0 size", size_text(bank0 as u64));
    c.push_metadata("lynx_bank1_size", "Bank 1 size", size_text(bank1 as u64));
    let (first, second) = contents.split_at(contents.len().min(bank0));
    c.sections
        .push(stored_section("Cartridge bank 0", 0, HEADER_SIZE, first));
    if !second.is_empty() {
        c.sections.push(stored_section(
            "Cartridge bank 1",
            0,
            HEADER_SIZE + first.len(),
            second,
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banks_hold_256_pages_and_only_bank_1_may_be_unused() {
        assert_eq!(bank_size(0x200, 0).unwrap(), 128 << 10);
        assert_eq!(bank_size(0, 1).unwrap(), 0);
        assert!(bank_size(0, 0).is_err());
        assert!(bank_size(0x300, 0).is_err());
    }
}
