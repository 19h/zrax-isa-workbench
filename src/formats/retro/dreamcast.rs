//! Dreamcast `IP.BIN`: the 0x8000-byte boot area in the first 16 sectors of
//! the last data track (Marcus Comstedt, "IP.BIN and `1ST_READ.BIN`" and
//! "IP0000.BIN"; `KallistiOS` `utils/makeip/src/field.c` and `crc.c` at
//! `568c3404`).
//!
//! The boot ROM loads it to 0x8C008000: meta information (0x100), table of
//! contents (0x200) at 0x100, SEGA license screen code at 0x300-0x36FF (the
//! entry point), area protection symbols at 0x3700 (8 slots of 32 bytes: two
//! SH-4 branch instructions, then 28 bytes of text), bootstrap 1 at
//! 0x3800-0x5FFF and bootstrap 2 at 0x6000-0x7FFF.
//!
//! Meta information, ASCII and space-padded: hardware ID (16), maker ID
//! (16), device info (16: CRC as four hex digits, space, device, disc x/y)
//! at 0x20, area symbols (8) at 0x30, peripherals (8: seven hex digits) at
//! 0x38, product number (10) at 0x40, version (6) at 0x4A, release date (16)
//! at 0x50, boot file name (16) at 0x60, software maker (16) at 0x70 and
//! title (128) at 0x80.

use super::*;

/// Hardware ID at offset 0.
const HARDWARE_ID: &[u8; 16] = b"SEGA SEGAKATANA ";

/// Maker ID at 0x10; Comstedt: always this value.
const MAKER_ID: &[u8; 16] = b"SEGA ENTERPRISES";

/// Size of IP.BIN and its load address.
const IP_BIN_SIZE: usize = 0x8000;
const LOAD_ADDRESS: u64 = 0x8c00_8000;

/// The license screen code is the entry point the boot ROM calls.
const ENTRY_OFFSET: u64 = 0x300;

/// Where the boot ROM loads `1ST_READ.BIN` (Comstedt).
const BOOT_FILE_ADDRESS: u32 = 0x8c01_0000;

/// An SH-4 code area of IP.BIN.
struct CodeArea {
    label: &'static str,
    region: Region,
}

/// The SH-4 code areas, in file order.
const CODE_AREAS: [CodeArea; 3] = [
    CodeArea {
        label: "License screen code",
        region: Region {
            offset: 0x300,
            size: 0x3400,
        },
    },
    CodeArea {
        label: "Bootstrap 1",
        region: Region {
            offset: 0x3800,
            size: 0x2800,
        },
    },
    CodeArea {
        label: "Bootstrap 2",
        region: Region {
            offset: 0x6000,
            size: 0x2000,
        },
    },
];

/// Meta information fields.
const MAKER_ID_FIELD: Region = field(0x10, 16);
const DEVICE_INFO: Region = field(0x20, 16);
const AREA_SYMBOLS: Region = field(0x30, 8);
const PERIPHERALS: Region = field(0x38, 8);
const PRODUCT_NUMBER: Region = field(0x40, 10);
const VERSION: Region = field(0x4a, 6);
const RELEASE_DATE: Region = field(0x50, 16);
const BOOT_FILENAME: Region = field(0x60, 16);
const SOFTWARE_MAKER: Region = field(0x70, 16);
const TITLE: Region = field(0x80, 128);

/// The device info CRC covers the product number and version (makeip
/// `update_crc`), written as four uppercase hex digits.
const CRC_RANGE: Region = field(0x40, 16);
const CRC_DIGITS: usize = 4;

/// CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF, no
/// reflection, no final XOR (makeip `calcCRC`; the parameter name is
/// derived).
const CRC_POLYNOMIAL: u16 = 0x1021;
const CRC_INITIAL: u16 = 0xffff;

/// Area symbols are positional: J, U, E (Comstedt's slot texts name the
/// regions).
const AREAS: [(u8, &str); 3] = [(b'J', "Japan"), (b'U', "USA"), (b'E', "Europe")];

/// Area protection slots at 0x3700: 32 bytes each, text after two SH-4
/// branch instructions.
const AREA_SLOTS: usize = 0x3700;
const AREA_SLOT_SIZE: usize = 32;
const AREA_SLOT_COUNT: usize = 8;
const AREA_SLOT_TEXT: usize = 4;

/// Peripherals: seven hex digits; bit 0 marks a Windows CE title.
const PERIPHERAL_DIGITS: usize = 7;
const PERIPHERAL_WINDOWS_CE: u32 = 0x1;

const fn field(offset: usize, size: usize) -> Region {
    Region { offset, size }
}

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(HARDWARE_ID)
}

/// The bytes of a meta information field; IP.BIN is at least 0x8000 bytes
/// when this is called.
fn bytes(data: &[u8], region: Region) -> &[u8] {
    &data[region.offset..region.end()]
}

fn field_text(data: &[u8], region: Region) -> String {
    text(bytes(data, region))
}

/// makeip `calcCRC`.
fn device_info_crc(bytes: &[u8]) -> u16 {
    let mut crc = CRC_INITIAL;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ CRC_POLYNOMIAL
            };
        }
    }
    crc
}

/// A field of `digits` hex digits, if it is one.
fn hex_digits(field: &[u8], digits: usize) -> Option<u32> {
    let digits = field.get(..digits)?;
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() < IP_BIN_SIZE {
        return Err(error(format!(
            "Truncated IP.BIN: {} B of {IP_BIN_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing IP.BIN hardware ID SEGA SEGAKATANA"));
    }
    let mut c = Container::new(FileFormat::DreamcastIp, "SH-4", "dreamcast");
    c.target = Some(Target::new(Isa::Sh4, 32, Endianness::Little));
    c.entry = Some(LOAD_ADDRESS + ENTRY_OFFSET);
    c.consumed = IP_BIN_SIZE;
    c.code_sections = true;
    push_meta_notes(&mut c, data);
    push_device_crc(&mut c, data);
    push_areas(&mut c, data);
    push_peripherals(&mut c, data);
    let boot_file = field_text(data, BOOT_FILENAME);
    c.notes.push(format!(
        "Boot file {boot_file} is loaded to 0x{BOOT_FILE_ADDRESS:08X} from the disc file system and is not part of IP.BIN; its MIL-CD scrambling is not handled"
    ));
    c.notes.push(
        "The header names no CPU; the Dreamcast CPU is a little-endian Hitachi SH-4".to_string(),
    );
    let rest = data.len() - IP_BIN_SIZE;
    if rest > 0 {
        c.notes.push(format!(
            "{} follow IP.BIN at 0x{IP_BIN_SIZE:X} and are not analyzed (a track image continues with the disc file system)",
            size_text(rest)
        ));
    }
    c.push_metadata("dreamcast_boot_filename", "Boot file", boot_file);
    for area in CODE_AREAS {
        c.sections.push(section(
            area.label,
            LOAD_ADDRESS + area.region.offset as u64,
            area.region.offset,
            area.region.size,
            Cow::Borrowed(bytes(data, area.region)),
            None,
        ));
    }
    Ok(c)
}

fn push_meta_notes(c: &mut Container<'_>, data: &[u8]) {
    let product = field_text(data, PRODUCT_NUMBER);
    let version = field_text(data, VERSION);
    let release = field_text(data, RELEASE_DATE);
    c.notes.push(format!(
        "Dreamcast IP.BIN; product {product}; version {version}; release date {release}"
    ));
    c.notes.push(format!(
        "Title: {}; software maker: {}",
        field_text(data, TITLE),
        field_text(data, SOFTWARE_MAKER)
    ));
    if bytes(data, MAKER_ID_FIELD) != MAKER_ID {
        c.notes.push(format!(
            "Maker ID is {}, not SEGA ENTERPRISES",
            field_text(data, MAKER_ID_FIELD)
        ));
    }
    c.push_metadata("dreamcast_product_number", "Product number", product);
    c.push_metadata("dreamcast_version", "Version", version);
    c.push_metadata("dreamcast_release_date", "Release date", release);
}

/// The device info field starts with the CRC of the product number and
/// version; the boot ROM accepts `0000`, so a mismatch is only reported.
fn push_device_crc(c: &mut Container<'_>, data: &[u8]) {
    let computed = device_info_crc(bytes(data, CRC_RANGE));
    let stored = hex_digits(bytes(data, DEVICE_INFO), CRC_DIGITS);
    let crc_note = match stored {
        Some(stored) if stored == u32::from(computed) => {
            format!("CRC 0x{computed:04X} verified")
        }
        Some(stored) => format!(
            "CRC 0x{stored:04X} does not match the computed 0x{computed:04X}; the boot ROM does not check it"
        ),
        None => format!("CRC field is not four hex digits; computed 0x{computed:04X}"),
    };
    c.notes.push(format!(
        "Device info: {}; {crc_note}",
        field_text(data, DEVICE_INFO)
    ));
    c.push_metadata(
        "dreamcast_device_info_crc",
        "Computed device info CRC",
        format!("0x{computed:04X}"),
    );
}

fn push_areas(c: &mut Container<'_>, data: &[u8]) {
    let symbols = bytes(data, AREA_SYMBOLS);
    let areas: Vec<&str> = AREAS
        .iter()
        .zip(symbols)
        .filter(|((symbol, _), stored)| *stored == symbol)
        .map(|((_, name), _)| *name)
        .collect();
    let listed = if areas.is_empty() {
        "none".to_string()
    } else {
        areas.join(", ")
    };
    c.notes.push(format!("Area symbols: {listed}"));
    c.push_metadata(
        "dreamcast_area_symbols",
        "Area symbols",
        field_text(data, AREA_SYMBOLS),
    );
    let texts: Vec<String> = (0..AREA_SLOT_COUNT)
        .map(|slot| {
            let start = AREA_SLOTS + slot * AREA_SLOT_SIZE;
            text(&data[start + AREA_SLOT_TEXT..start + AREA_SLOT_SIZE])
        })
        .filter(|text| !text.is_empty())
        .collect();
    if !texts.is_empty() {
        c.notes
            .push(format!("Area protection texts: {}", texts.join(" / ")));
    }
}

fn push_peripherals(c: &mut Container<'_>, data: &[u8]) {
    let Some(peripherals) = hex_digits(bytes(data, PERIPHERALS), PERIPHERAL_DIGITS) else {
        c.notes.push(format!(
            "Peripherals field {} is not seven hex digits",
            field_text(data, PERIPHERALS)
        ));
        return;
    };
    let windows_ce = if peripherals & PERIPHERAL_WINDOWS_CE == 0 {
        ""
    } else {
        "; uses Windows CE (how its executables are packaged is not established)"
    };
    c.notes
        .push(format!("Peripherals: 0x{peripherals:07X}{windows_ce}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_info_crc_is_crc16_ccitt_false() {
        assert_eq!(device_info_crc(b"123456789"), 0x29b1);
        // Super Magnetic Neo (Sega Retro): product and version give 61A7.
        assert_eq!(device_info_crc(b"T40206N   V1.001"), 0x61a7);
    }

    #[test]
    fn hex_fields_must_be_all_digits() {
        assert_eq!(hex_digits(b"61A7 GD-ROM1/1", 4), Some(0x61a7));
        assert_eq!(hex_digits(b"61G7", 4), None);
        assert_eq!(hex_digits(b"61", 4), None);
    }

    #[test]
    fn code_areas_lie_inside_ip_bin_and_skip_the_area_symbols() {
        assert_eq!(CODE_AREAS[0].region.end(), AREA_SLOTS);
        assert_eq!(CODE_AREAS[2].region.end(), IP_BIN_SIZE);
    }
}
