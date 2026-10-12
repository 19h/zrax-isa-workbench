//! Game Boy and Game Boy Color cartridge images (`.gb`, `.gbc`).
//!
//! Layout from Pan Docs "The Cartridge Header" (gbdev/pandocs
//! `src/The_Cartridge_Header.md` at
//! `4b31c4ba0bccc94080b80216287d14519d18e160`). The header occupies file
//! 0x100-0x14F: entry (4 B), Nintendo logo (48 B) at 0x104, title at
//! 0x134, CGB flag 0x143, new licensee code (2 B) 0x144, SGB flag 0x146,
//! cartridge type 0x147, ROM size 0x148, RAM size 0x149, destination
//! 0x14A, old licensee code 0x14B, mask ROM version 0x14C, header checksum
//! 0x14D and the big-endian global checksum 0x14E. Pan Docs names the CPU
//! "an 8-bit 8080-like Sharp CPU (speculated to be a SM83 core)"; the code
//! model's `sm83` class belongs to the Z80 family, so the target is
//! [`Isa::Z80`] with variant SM83.

use super::*;

/// End of the cartridge header.
const HEADER_END: usize = 0x150;

/// The CPU starts at 0x0100 after the boot ROM.
const ENTRY: u64 = 0x100;

/// The 48-byte logo at 0x104 (Pan Docs). The DMG boot ROM checks all of
/// it; CGB and later check only the first 0x18 bytes.
const LOGO_OFFSET: usize = 0x104;
const LOGO_CGB_CHECKED: usize = 0x18;
#[rustfmt::skip]
const LOGO: [u8; 48] = [
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
];

/// The header checksum at 0x14D covers 0x134-0x14C.
const CHECKSUM_RANGE: Range<usize> = 0x134..0x14D;
const HEADER_CHECKSUM: usize = 0x14D;

/// Big-endian sum of every ROM byte except its own two.
const GLOBAL_CHECKSUM: usize = 0x14E;

/// Title: 16 bytes, or 15 when 0x143 is the CGB flag.
const TITLE_START: usize = 0x134;
const CGB_FLAG: usize = 0x143;
const TITLE_END: usize = 0x144;

/// CGB flag values with a defined meaning.
const CGB_ENHANCED: u8 = 0x80;
const CGB_ONLY: u8 = 0xC0;

/// 0x146 = 0x03: Super Game Boy functions supported.
const SGB_FLAG: usize = 0x146;
const SGB_SUPPORTED: u8 = 0x03;

const CARTRIDGE_TYPE: usize = 0x147;
const ROM_SIZE: usize = 0x148;
const RAM_SIZE: usize = 0x149;
const DESTINATION: usize = 0x14A;
const MASK_ROM_VERSION: usize = 0x14C;

/// Old licensee code 0x33 defers to the two-character code at 0x144.
const OLD_LICENSEE: usize = 0x14B;
const USE_NEW_LICENSEE: u8 = 0x33;
const NEW_LICENSEE: Range<usize> = 0x144..0x146;

/// ROM size codes 0x00-0x08 are 32 KiB shifted left by the code.
const ROM_SIZE_UNIT: u64 = 32 << 10;
const MAX_ROM_SIZE_CODE: u8 = 0x08;

/// ROM banks are 16 KiB.
const BANK_SIZE: u64 = 16 << 10;

/// Unofficial ROM size codes (1.1, 1.2 and 1.5 MiB); Pan Docs knows no
/// cartridges or ROM files using them. Bank counts are derived from those
/// sizes.
const UNOFFICIAL_ROM_SIZES: [(u8, u64); 3] = [(0x52, 72), (0x53, 80), (0x54, 96)];

/// Emulator GBX files end with a 64-byte footer whose last 4 bytes are
/// `GBX!` (rom-properties `dmg_structs.h`, as quoted in the spec notes).
const GBX_FOOTER_SIZE: usize = 64;
const GBX_MAGIC: &[u8] = b"GBX!";

/// Cartridge type codes at 0x147 (Pan Docs table).
const CARTRIDGE_TYPES: &[(u8, &str)] = &[
    (0x00, "ROM ONLY"),
    (0x01, "MBC1"),
    (0x02, "MBC1+RAM"),
    (0x03, "MBC1+RAM+BATTERY"),
    (0x05, "MBC2"),
    (0x06, "MBC2+BATTERY"),
    (0x08, "ROM+RAM"),
    (0x09, "ROM+RAM+BATTERY"),
    (0x0B, "MMM01"),
    (0x0C, "MMM01+RAM"),
    (0x0D, "MMM01+RAM+BATTERY"),
    (0x0F, "MBC3+TIMER+BATTERY"),
    (0x10, "MBC3+TIMER+RAM+BATTERY"),
    (0x11, "MBC3"),
    (0x12, "MBC3+RAM"),
    (0x13, "MBC3+RAM+BATTERY"),
    (0x19, "MBC5"),
    (0x1A, "MBC5+RAM"),
    (0x1B, "MBC5+RAM+BATTERY"),
    (0x1C, "MBC5+RUMBLE"),
    (0x1D, "MBC5+RUMBLE+RAM"),
    (0x1E, "MBC5+RUMBLE+RAM+BATTERY"),
    (0x20, "MBC6"),
    (0x22, "MBC7+SENSOR+RUMBLE+RAM+BATTERY"),
    (0xFC, "POCKET CAMERA"),
    (0xFD, "BANDAI TAMA5"),
    (0xFE, "HuC3"),
    (0xFF, "HuC1+RAM+BATTERY"),
];

/// RAM size codes at 0x149 (Pan Docs).
const RAM_SIZES: &[(u8, &str)] = &[
    (0x00, "none"),
    (0x01, "unused code 0x01"),
    (0x02, "8 KiB"),
    (0x03, "32 KiB"),
    (0x04, "128 KiB"),
    (0x05, "64 KiB"),
];

/// The value the boot ROM compares with 0x14D.
fn header_checksum(data: &[u8]) -> u8 {
    data[CHECKSUM_RANGE]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_sub(b).wrapping_sub(1))
}

/// The ROM size the header declares.
fn declared_rom_size(code: u8) -> Result<u64> {
    if code <= MAX_ROM_SIZE_CODE {
        return Ok(ROM_SIZE_UNIT << code);
    }
    UNOFFICIAL_ROM_SIZES
        .iter()
        .find(|(unofficial, _)| *unofficial == code)
        .map(|(_, banks)| banks * BANK_SIZE)
        .ok_or_else(|| {
            error(format!(
                "Unknown ROM size code 0x{code:02X} at 0x{ROM_SIZE:X}"
            ))
        })
}

fn table_name(table: &[(u8, &'static str)], code: u8) -> String {
    table.iter().find(|(known, _)| *known == code).map_or_else(
        || format!("unknown (0x{code:02X})"),
        |(_, name)| (*name).to_string(),
    )
}

/// The full logo, or the part CGB boot ROMs check plus a valid header
/// checksum. Reports the layout from the CGB flag.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let header = data.get(..HEADER_END)?;
    let logo = &header[LOGO_OFFSET..LOGO_OFFSET + LOGO.len()];
    let cgb_logo = logo[..LOGO_CGB_CHECKED] == LOGO[..LOGO_CGB_CHECKED];
    let recognized = logo == LOGO || cgb_logo && header[HEADER_CHECKSUM] == header_checksum(header);
    recognized.then(|| layout(header))
}

fn layout(header: &[u8]) -> Layout {
    if matches!(header[CGB_FLAG], CGB_ENHANCED | CGB_ONLY) {
        Layout::Gbc
    } else {
        Layout::Gb
    }
}

/// Parse a Game Boy image: the declared ROM is one code section.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "Game Boy header", 0, HEADER_END)?;
    let stored = header[HEADER_CHECKSUM];
    let computed = header_checksum(header);
    if stored != computed {
        return Err(error(format!(
            "Invalid header checksum 0x{stored:02X} at 0x{HEADER_CHECKSUM:X}: computed \
                0x{computed:02X}"
        )));
    }
    let rom_size_code = header[ROM_SIZE];
    let declared = declared_rom_size(rom_size_code)?;
    let rom_size = usize::try_from(declared)
        .ok()
        .filter(|size| *size <= data.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated ROM: the header declares {}, the file has {} B",
                size_text(declared),
                data.len()
            ))
        })?;
    let rom = &data[..rom_size];
    let trailer = trailer_note(data, rom_size)?;

    let mut c = Container::new(FileFormat::GbRom, "SM83", "gb");
    c.target = Some(Target::new(Isa::Z80, 8, Endianness::Little));
    c.entry = Some(ENTRY);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(
        "Sharp SM83 CPU (Pan Docs: an 8080-like Sharp CPU, speculated to be an SM83 core); \
            reported as the Z80 family, which holds the code model's sm83 class"
            .into(),
    );
    c.notes.push(format!(
        "Header checksum 0x{stored:02X} verified; entry at 0x0100"
    ));
    let logo = &header[LOGO_OFFSET..LOGO_OFFSET + LOGO.len()];
    if logo != LOGO {
        c.notes.push(
            "Nintendo logo matches only in the first 0x18 bytes, which CGB boot ROMs check".into(),
        );
    }
    c.notes.push(global_checksum_note(rom, header)?);
    c.notes.push(match header[CGB_FLAG] {
        CGB_ENHANCED => "CGB flag 0x80: Game Boy Color enhancements, backwards compatible".into(),
        CGB_ONLY => "CGB flag 0xC0: Game Boy Color only".into(),
        _ => "No CGB flag: monochrome Game Boy cartridge".to_string(),
    });
    if header[SGB_FLAG] == SGB_SUPPORTED {
        c.notes.push("Super Game Boy functions supported".into());
    }
    if UNOFFICIAL_ROM_SIZES
        .iter()
        .any(|(code, _)| *code == rom_size_code)
    {
        c.notes.push(format!(
            "ROM size code 0x{rom_size_code:02X} is unofficial; no cartridges using it are known"
        ));
    }
    if let Some(note) = trailer {
        c.notes.push(note);
    }
    c.notes
        .push("Section address is the ROM offset; banks are mapped by the cartridge".into());
    push_metadata(&mut c, header, declared);
    c.sections
        .push(section("ROM", 0, 0, Cow::Borrowed(rom), None));
    Ok(c)
}

/// Bytes after the declared ROM: erased flash or zero fill, or a GBX
/// footer (rom-properties `dmg_structs.h`: 64 bytes ending in `GBX!`).
/// Anything else is not part of a cartridge image.
fn trailer_note(data: &[u8], rom_size: usize) -> Result<Option<String>> {
    let trailer = &data[rom_size..];
    if trailer.is_empty() {
        return Ok(None);
    }
    if trailer.len() == GBX_FOOTER_SIZE && trailer.ends_with(GBX_MAGIC) {
        return Ok(Some(format!(
            "{GBX_FOOTER_SIZE} B GBX footer at 0x{rom_size:X}; not parsed"
        )));
    }
    if is_padding(trailer) {
        return Ok(Some(format!(
            "{} of padding after the declared ROM",
            size_text(trailer.len() as u64)
        )));
    }
    Err(error(format!(
        "Invalid trailing data: {} B at 0x{rom_size:X} after the declared ROM",
        trailer.len()
    )))
}

/// The global checksum is not checked by the hardware, so a mismatch is a
/// note, not an error.
fn global_checksum_note(rom: &[u8], header: &[u8]) -> Result<String> {
    let stored = be_u16(header, GLOBAL_CHECKSUM)?;
    let sum = rom
        .iter()
        .enumerate()
        .filter(|(i, _)| !(GLOBAL_CHECKSUM..GLOBAL_CHECKSUM + 2).contains(i))
        .fold(0u16, |sum, (_, &b)| sum.wrapping_add(u16::from(b)));
    Ok(if sum == stored {
        format!("Global checksum 0x{stored:04X} verified")
    } else {
        format!(
            "Global checksum 0x{stored:04X} does not match the computed 0x{sum:04X}; the hardware \
                does not check it"
        )
    })
}

fn push_metadata(c: &mut Container<'_>, header: &[u8], declared: u64) {
    let title_end = if layout(header) == Layout::Gbc {
        CGB_FLAG
    } else {
        TITLE_END
    };
    c.push_metadata(
        "gb_title",
        "Title",
        header_text(&header[TITLE_START..title_end]),
    );
    c.push_metadata(
        "gb_cartridge_type",
        "Cartridge type",
        table_name(CARTRIDGE_TYPES, header[CARTRIDGE_TYPE]),
    );
    c.push_metadata("gb_rom_size", "ROM size", size_text(declared));
    c.push_metadata(
        "gb_ram_size",
        "RAM size",
        table_name(RAM_SIZES, header[RAM_SIZE]),
    );
    c.push_metadata(
        "gb_cgb_flag",
        "CGB flag",
        format!("0x{:02X}", header[CGB_FLAG]),
    );
    let licensee = if header[OLD_LICENSEE] == USE_NEW_LICENSEE {
        header_text(&header[NEW_LICENSEE])
    } else {
        format!("0x{:02X}", header[OLD_LICENSEE])
    };
    c.push_metadata("gb_licensee", "Licensee code", licensee);
    c.push_metadata(
        "gb_destination",
        "Destination",
        match header[DESTINATION] {
            0x00 => "Japan (and possibly overseas)".to_string(),
            0x01 => "Overseas only".to_string(),
            other => format!("unknown (0x{other:02X})"),
        },
    );
    c.push_metadata(
        "gb_mask_rom_version",
        "Mask ROM version",
        u64::from(header[MASK_ROM_VERSION]),
    );
}
