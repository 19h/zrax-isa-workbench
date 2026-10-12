//! Game Boy Advance cartridge and multiboot images (`.gba`, `.mb`).
//!
//! Layout from GBATEK "GBA Cartridge Header" and devkitPro gba-tools
//! `src/gbafix.c` at `054d507f90d32784274b6cf7e03f1c43d02d7a57` (logo
//! bytes and `HeaderComplement`). The 192-byte header is little-endian:
//! entry branch (4 B) at 0x000, Nintendo logo (156 B) at 0x004, title
//! (12 B) at 0x0A0, game code (4 B) at 0x0AC, maker code (2 B) at 0x0B0,
//! fixed 0x96 at 0x0B2, main unit code 0x0B3, device type 0x0B4, software
//! version 0x0BC, complement 0x0BD. The CPU is the ARM7TDMI (`ARMv4T`);
//! the whole image is its code and data.

use super::*;

/// Cartridge header size; the program follows (multiboot: from 0x0C0).
const HEADER_SIZE: usize = 0xC0;

/// The logo occupies 0x004-0x09F.
const LOGO: Range<usize> = 0x004..0x0A0;

/// Logo bits the BIOS lets vary (GBATEK): 0x09C bits 2 and 7 (debug
/// handler), 0x09E bits 0 and 1 (cartridge key number).
const LOGO_VARIABLE_BITS: [(usize, u8); 2] = [(0x09C, 0x84), (0x09E, 0x03)];

/// Fixed value at 0x0B2.
const FIXED_OFFSET: usize = 0x0B2;
const FIXED_VALUE: u8 = 0x96;

/// The complement at 0x0BD covers 0x0A0-0x0BC (GBATEK, gbafix.c).
const COMPLEMENT_OFFSET: usize = 0x0BD;
const COMPLEMENT_RANGE: Range<usize> = 0x0A0..0x0BD;
const COMPLEMENT_BIAS: u8 = 0x19;

/// Reserved bytes, zero in a gbafix header.
const RESERVED: [Range<usize>; 2] = [0x0B5..0x0BC, 0x0BE..0x0C0];

/// Header fields read once.
const TITLE: Range<usize> = 0x0A0..0x0AC;
const GAME_CODE: Range<usize> = 0x0AC..0x0B0;
const MAKER_CODE: Range<usize> = 0x0B0..0x0B2;
const MAIN_UNIT_CODE: usize = 0x0B3;
const SOFTWARE_VERSION: usize = 0x0BC;

/// An ARM `B` with condition AL: top byte 0xEA. The target is the
/// instruction address + 8 + the sign-extended 24-bit word offset.
const ARM_BRANCH_MASK: u32 = 0xFF00_0000;
const ARM_BRANCH_AL: u32 = 0xEA00_0000;
const BRANCH_OFFSET_MASK: u32 = 0x00FF_FFFF;
const BRANCH_OFFSET_SIGN: i64 = 0x0080_0000;
const BRANCH_OFFSET_RANGE: i64 = 0x0100_0000;
const BRANCH_PIPELINE: i64 = 8;

/// Cartridge ROM is mapped at 0x08000000, at most 32 MiB (GBATEK "GBA
/// Memory Map"); multiboot images load at 0x02000000 instead.
const ROM_ADDRESS: u64 = 0x0800_0000;
const MAX_ROM_SIZE: usize = 32 << 20;

/// Game code of NDS `PassMe` boot images (GBATEK).
const PASSME_GAME_CODE: &[u8] = b"PASS";

/// The complement check value of a header.
fn complement(header: &[u8]) -> u8 {
    let sum = header[COMPLEMENT_RANGE]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_add(b));
    0u8.wrapping_sub(sum.wrapping_add(COMPLEMENT_BIAS))
}

/// The 156 logo bytes, ignoring the bits the BIOS lets vary.
fn is_logo(header: &[u8]) -> bool {
    header[LOGO]
        .iter()
        .zip(NINTENDO_LOGO)
        .enumerate()
        .all(|(i, (&stored, expected))| {
            let ignored = LOGO_VARIABLE_BITS
                .iter()
                .find(|(offset, _)| *offset == LOGO.start + i)
                .map_or(0, |(_, bits)| *bits);
            stored & !ignored == expected & !ignored
        })
}

/// File offset an ARM `B` at offset 0 jumps to, if the word is one.
fn branch_target(word: u32) -> Option<i64> {
    if word & ARM_BRANCH_MASK != ARM_BRANCH_AL {
        return None;
    }
    let unsigned = i64::from(word & BRANCH_OFFSET_MASK);
    let words = if unsigned & BRANCH_OFFSET_SIGN == 0 {
        unsigned
    } else {
        unsigned - BRANCH_OFFSET_RANGE
    };
    Some(BRANCH_PIPELINE + words * 4)
}

/// The entry branch target, when it lands in the file after the header.
fn entry_offset(data: &[u8]) -> Option<usize> {
    let target = branch_target(le_u32(data, 0).ok()?)?;
    let target = usize::try_from(target).ok()?;
    (HEADER_SIZE..data.len())
        .contains(&target)
        .then_some(target)
}

/// Fixed byte and complement, plus the logo, or an entry branch into the
/// file and zero reserved bytes.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(header) = data.get(..HEADER_SIZE) else {
        return false;
    };
    if header[FIXED_OFFSET] != FIXED_VALUE || header[COMPLEMENT_OFFSET] != complement(header) {
        return false;
    }
    is_logo(header)
        || entry_offset(data).is_some()
            && RESERVED
                .iter()
                .all(|reserved| header[reserved.clone()].iter().all(|&b| b == 0))
}

/// Parse a GBA image: the whole file is one code section at the cartridge
/// address.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "GBA header", 0, HEADER_SIZE)?;
    let fixed = header[FIXED_OFFSET];
    if fixed != FIXED_VALUE {
        return Err(error(format!(
            "Invalid fixed byte 0x{fixed:02X} at 0x{FIXED_OFFSET:X}: expected 0x{FIXED_VALUE:02X}"
        )));
    }
    let stored = header[COMPLEMENT_OFFSET];
    let computed = complement(header);
    if stored != computed {
        return Err(error(format!(
            "Invalid header complement 0x{stored:02X} at 0x{COMPLEMENT_OFFSET:X}: computed \
                0x{computed:02X}"
        )));
    }
    if data.len() > MAX_ROM_SIZE {
        return Err(error(format!(
            "Invalid ROM size {} B: exceeds the 32 MiB cartridge window",
            data.len()
        )));
    }
    let passme = &header[GAME_CODE] == PASSME_GAME_CODE;
    // A PassMe image boots a DS; which core runs it is not stated.
    let variant = if passme { "" } else { ARM7TDMI };
    let mut c = Container::new(FileFormat::GbaRom, variant, "gba");
    c.target = Some(ARM_LITTLE);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "Header complement 0x{stored:02X} verified; fixed byte 0x{FIXED_VALUE:02X}"
    ));
    c.notes.push(if is_logo(header) {
        "Nintendo logo at 0x004 matches".to_string()
    } else {
        "Nintendo logo at 0x004 does not match; recognized from the entry branch".to_string()
    });
    match entry_offset(data) {
        Some(offset) => {
            let entry = ROM_ADDRESS + offset as u64;
            c.entry = Some(entry);
            c.notes.push(format!(
                "Entry branch at 0x000 to 0x{entry:08X} (file 0x{offset:X}); ARM state"
            ));
        }
        None => c
            .notes
            .push("Word at 0x000 is not an ARM branch into the image; entry not determined".into()),
    }
    if passme {
        c.notes.push(
            "Game code PASS: an NDS PassMe boot image, not a GBA game; CPU core not determined"
                .into(),
        );
    }
    c.notes.push(
        "Load address 0x08000000 assumes a cartridge image; multiboot images load at 0x02000000 \
            and share the header layout"
            .into(),
    );
    c.push_metadata("gba_title", "Title", header_text(&header[TITLE]));
    c.push_metadata(
        "gba_game_code",
        "Game code",
        header_text(&header[GAME_CODE]),
    );
    c.push_metadata(
        "gba_maker_code",
        "Maker code",
        header_text(&header[MAKER_CODE]),
    );
    c.push_metadata(
        "gba_main_unit_code",
        "Main unit code",
        format!("0x{:02X}", header[MAIN_UNIT_CODE]),
    );
    c.push_metadata(
        "gba_software_version",
        "Software version",
        u64::from(header[SOFTWARE_VERSION]),
    );
    c.sections.push(section(
        "Cartridge ROM",
        ROM_ADDRESS,
        0,
        Cow::Borrowed(data),
        None,
    ));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_targets_are_sign_extended_word_offsets() {
        // gbafix writes 0xEA00002E, a branch to 0xC0.
        assert_eq!(branch_target(0xEA00_002E), Some(0xC0));
        assert_eq!(branch_target(0xEAFF_FFFE), Some(0));
        assert_eq!(branch_target(0xE1A0_0000), None);
    }
}
