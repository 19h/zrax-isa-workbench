//! Atari 7800 `.a78` cartridge images.
//!
//! 7800 8-bit dev wiki "A78 Header Specification" (oldid 1120) and cc65
//! `libsrc/atari7800/exehdr.s`: a 128-byte header, then the ROM. Header
//! version (1) at 0, `ATARI7800` padded to 16 bytes at 1, title (32) at
//! 0x11, ROM size without the header (4, big-endian) at 0x31, cart type (2,
//! big-endian bit field) at 0x35, controller 1 and 2 types at 0x37 and 0x38,
//! TV type at 0x39, save device at 0x3A, slot passthrough device at 0x3F, the
//! v4 mapper at 0x40, and `ACTUAL CART DATA STARTS HERE` at 0x64. MAME
//! `a78_slot.cpp` checks the 9 bytes `ATARI7800` at 1 and reads the size and
//! type big-endian.
//!
//! The CPU is a 6502 (MAME `a7800.cpp`, `M6502` at 1.79 MHz). A cartridge
//! without banking ends at 0xFFFF (cc65 `cfg/atari7800.cfg`: the ROM starts
//! at 0x10000 minus its size; vectors at 0xFFFA-0xFFFF; a 128-byte
//! encryption signature at 0xFF7A-0xFFF9), and the 6502 reset vector is at
//! 0xFFFC (`NESdev` Wiki "CPU memory map"). The signature is not verified.

use super::*;
use crate::formats::MAX_PAYLOAD;

/// The magic text at offset 1 (MAME compares 9 bytes).
const MAGIC: &[u8; 9] = b"ATARI7800";
const MAGIC_OFFSET: usize = 1;

/// Header fields.
const HEADER_SIZE: usize = 128;
const VERSION: usize = 0x00;
const TITLE: (usize, usize) = (0x11, 32);
const ROM_SIZE: usize = 0x31;
const CART_TYPE: usize = 0x35;
const CONTROLLER_1: usize = 0x37;
const CONTROLLER_2: usize = 0x38;
const TV_TYPE: usize = 0x39;
const SAVE_DEVICE: usize = 0x3a;
const PASSTHROUGH: usize = 0x3f;
const MAPPER: usize = 0x40;
const END_MAGIC: &[u8] = b"ACTUAL CART DATA STARTS HERE";
const END_MAGIC_OFFSET: usize = 0x64;

/// Header version 4 adds the mapper field, which takes precedence.
const VERSION_WITH_MAPPER: u8 = 4;
const MAPPER_LINEAR: u8 = 0;

/// Cart type bits (A78 specification, "cart type details").
#[rustfmt::skip]
const CART_TYPE_BITS: [(u16, &str); 16] = [
    (1 << 0,  "POKEY at 0x4000"),
    (1 << 1,  "SuperGame bank switching"),
    (1 << 2,  "SuperGame RAM at 0x4000"),
    (1 << 3,  "ROM at 0x4000"),
    (1 << 4,  "bank 6 at 0x4000"),
    (1 << 5,  "banked RAM"),
    (1 << 6,  "POKEY at 0x450"),
    (1 << 7,  "mirror RAM at 0x4000"),
    (1 << 8,  "Activision banking"),
    (1 << 9,  "absolute banking"),
    (1 << 10, "POKEY at 0x440"),
    (1 << 11, "YM2151 at 0x460"),
    (1 << 12, "Souper"),
    (1 << 13, "banksets"),
    (1 << 14, "halt banked RAM"),
    (1 << 15, "POKEY at 0x800"),
];

/// Cart type bits that select a bank-switching scheme.
const BANKING_BITS: u16 = (1 << 1) | (1 << 8) | (1 << 9) | (1 << 12) | (1 << 13);

/// The cartridge window of an unbanked cartridge ends at 0xFFFF; the 6502
/// reset vector is at 0xFFFC.
const ADDRESS_SPACE_END: u64 = 0x1_0000;
const RESET_VECTOR: u64 = 0xfffc;

/// The CPU core (MAME `M6502`).
const CPU_VARIANT: &str = "6502";

pub(super) fn detect(data: &[u8]) -> bool {
    has_magic(data, MAGIC_OFFSET, MAGIC)
}

/// The cart type's set bits, by name.
fn cart_type_names(cart_type: u16) -> String {
    let names: Vec<&str> = CART_TYPE_BITS
        .iter()
        .filter(|(bit, _)| cart_type & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "plain ROM".to_string()
    } else {
        names.join(", ")
    }
}

/// Whether the ROM is mapped without banking, from the v4 mapper when the
/// header has one and from the cart type bits otherwise.
fn is_linear(header: &[u8], cart_type: u16) -> bool {
    if header[VERSION] >= VERSION_WITH_MAPPER {
        header[MAPPER] == MAPPER_LINEAR
    } else {
        cart_type & BANKING_BITS == 0
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "A78 header", 0, HEADER_SIZE)?;
    if !detect(data) {
        return Err(error("Missing A78 magic ATARI7800 at 0x1"));
    }
    let size = be_u32(data, ROM_SIZE)?;
    let cart_type = be_u16(data, CART_TYPE)?;
    let size = usize::try_from(size)
        .ok()
        .filter(|&size| size > 0 && size <= MAX_PAYLOAD)
        .ok_or_else(|| error(format!("Invalid A78 ROM size {size} B at 0x{ROM_SIZE:X}")))?;
    let rom = range(data, "A78 ROM data", HEADER_SIZE, size)?;
    let trailer = expect_padding(data, HEADER_SIZE + size, "declared ROM data")?;
    let title = header_text(&header[TITLE.0..TITLE.0 + TITLE.1]);

    let mut c = Container::new(FileFormat::Atari7800Rom, CPU_VARIANT, "a7800");
    c.target = Some(MOS_6502);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "Atari 7800 cartridge {title}; A78 header version {}; ROM {}",
        header[VERSION],
        size_text(size as u64)
    ));
    c.notes.push(format!(
        "Cart type 0x{cart_type:04X}: {}; controllers {} and {}; TV type 0x{:02X}; save device \
            0x{:02X}; slot passthrough 0x{:02X}",
        cart_type_names(cart_type),
        header[CONTROLLER_1],
        header[CONTROLLER_2],
        header[TV_TYPE],
        header[SAVE_DEVICE],
        header[PASSTHROUGH]
    ));
    if !header[END_MAGIC_OFFSET..].starts_with(END_MAGIC) {
        c.notes
            .push("The header end text ACTUAL CART DATA STARTS HERE is missing".into());
    }
    if let Some(note) = trailer {
        c.notes.push(note);
    }
    c.push_metadata("a7800_title", "Title", title);
    c.push_metadata("a7800_cart_type", "Cart type", format!("0x{cart_type:04X}"));
    c.push_metadata("a7800_rom_size", "ROM size", size_text(size as u64));
    let address = if is_linear(header, cart_type) {
        push_linear_entry(&mut c, rom)?
    } else {
        c.notes.push(
            "Bank-switched cartridge: the section address is the ROM offset; banking is not \
                modeled and no entry is derived"
                .into(),
        );
        0
    };
    c.notes.push(
        "6502 CPU (MAME); the console checks a cartridge signature, which is not verified here"
            .into(),
    );
    c.sections
        .push(stored_section("ROM", address, HEADER_SIZE, rom));
    Ok(c)
}

/// An unbanked ROM ends at 0xFFFF: its start address and the reset vector
/// stored at 0xFFFC.
fn push_linear_entry(c: &mut Container<'_>, rom: &[u8]) -> Result<u64> {
    let size = rom.len() as u64;
    if size > ADDRESS_SPACE_END {
        return Err(error(format!(
            "Invalid A78 ROM size {size} B: an unbanked cartridge holds at most 64 KiB"
        )));
    }
    let start = ADDRESS_SPACE_END - size;
    if start > RESET_VECTOR {
        c.notes.push(format!(
            "Unbanked ROM at 0x{start:04X}-0xFFFF does not reach the reset vector at 0xFFFC"
        ));
        return Ok(start);
    }
    let vector = usize::try_from(RESET_VECTOR - start).expect("the vector lies in a 64 KiB ROM");
    let entry = le_u16(rom, vector)?;
    c.entry = Some(u64::from(entry));
    c.notes.push(format!(
        "Unbanked ROM at 0x{start:04X}-0xFFFF; reset vector 0x{entry:04X} at 0xFFFC"
    ));
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cart_type_bits_are_named() {
        assert_eq!(cart_type_names(0), "plain ROM");
        assert_eq!(
            cart_type_names(0x0003),
            "POKEY at 0x4000, SuperGame bank switching"
        );
    }

    #[test]
    fn the_v4_mapper_takes_precedence_over_the_cart_type() {
        let mut header = [0u8; HEADER_SIZE];
        assert!(is_linear(&header, 0));
        assert!(!is_linear(&header, 1 << 1));
        header[VERSION] = VERSION_WITH_MAPPER;
        assert!(is_linear(&header, 1 << 1));
        header[MAPPER] = 1;
        assert!(!is_linear(&header, 0));
    }
}
