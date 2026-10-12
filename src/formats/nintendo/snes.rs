//! SNES ROM images with an internal header (`.sfc`, `.smc`).
//!
//! Layout from the `SNESdev` Wiki "ROM header" (oldid 1456), "ROM file
//! formats" (oldid 858) and "CPU vectors" (oldid 535); candidate locations
//! and consistency rules as in bsnes `bsnes/heuristics/super-famicom.cpp` at
//! `78474e5d39f58872dc21aca18cf9eb583b147fe7` (`scoreHeader`). The header
//! has no magic. It lies at ROM offset 0x7FC0 (`LoROM`), 0xFFC0 (`HiROM`) or
//! 0x40FFC0 (`ExHiROM`), optionally after a 512-byte copier header, and holds
//! (CPU addresses, little-endian): title (21 B) at 0xFFC0, map mode 0xFFD5,
//! chipset 0xFFD6, ROM size 0xFFD7, RAM size 0xFFD8, region 0xFFD9,
//! developer ID 0xFFDA, version 0xFFDB, checksum complement 0xFFDC and
//! checksum 0xFFDE, then the interrupt vectors 0xFFE0-0xFFFF. The main CPU
//! is the 65C816 (Ricoh 5A22); the raw code model has no 65816 class.

use super::*;

/// Optional SMC/SWC/FIG copier header before the ROM.
const COPIER_HEADER_SIZE: usize = 0x200;

/// Header fields (0xFFC0-0xFFDF) and vectors (0xFFE0-0xFFFF), relative to
/// the header start.
const HEADER_SPAN: usize = 0x40;
const TITLE: Range<usize> = 0x00..0x15;
const MAP_MODE: usize = 0x15;
const CHIPSET: usize = 0x16;
const ROM_SIZE: usize = 0x17;
const RAM_SIZE: usize = 0x18;
const REGION: usize = 0x19;
const DEVELOPER_ID: usize = 0x1A;
const VERSION: usize = 0x1B;
const COMPLEMENT: usize = 0x1C;
const CHECKSUM: usize = 0x1E;
/// Emulation-mode RESET vector (CPU 0xFFFC); the CPU always resets into
/// 6502 emulation mode.
const RESET_VECTOR: usize = 0x3C;

/// Expanded header (CPU 0xFFB0-0xFFBF) when the developer ID is 0x33:
/// maker code (2 ASCII) and game code (4 ASCII), relative to the header.
const EXPANDED_HEADER_SIZE: usize = 0x10;
const EXPANDED_MAKER_CODE: Range<usize> = 0x00..0x02;
const EXPANDED_GAME_CODE: Range<usize> = 0x02..0x06;
const DEVELOPER_EXPANDED: u8 = 0x33;

/// Map mode `001smmmm`: the top three bits are fixed; `s` selects fast
/// ROM access; `mmmm` is the mapping.
const MAP_MODE_FIXED_MASK: u8 = 0xE0;
const MAP_MODE_FIXED: u8 = 0x20;
const MAP_MODE_FAST: u8 = 0x10;
const MAP_MODE_MAPPING: u8 = 0x0F;

/// Map mode nibbles by header location (`SNESdev`; rom-properties for the
/// full byte values): 0x0 `LoROM`, 0x2 S-DD1 (rom-properties: `ExLoROM`), 0x3
/// SA-1 at the `LoROM` location; 0x1 `HiROM`, 0xA SPC7110 at the `HiROM`
/// location; 0x5 `ExHiROM`.
const LOROM_MAPPINGS: [u8; 3] = [0x0, 0x2, 0x3];
const HIROM_MAPPINGS: [u8; 2] = [0x1, 0xA];
const EXHIROM_MAPPINGS: [u8; 1] = [0x5];

/// The reset vector must point into the ROM half of bank 0x00.
const ROM_BANK_START: u16 = 0x8000;

/// Bank 0x00 address 0x8000 in ROM offsets: `LoROM` maps the first 32 KiB
/// there, `HiROM` the second, `ExHiROM` the second of the upper 4 MiB.
const LOROM_BANK0: usize = 0x0000;
const HIROM_BANK0: usize = 0x8000;
const EXHIROM_BANK0: usize = 0x40_8000;

/// Coprocessor chipsets have a low nibble of 3 or more.
const CHIPSET_COPROCESSOR: u8 = 0x3;

/// Chipset low nibble (`SNESdev`; 0x9 and 0xA from rom-properties).
const CHIPSET_MEMORY: [(u8, &str); 9] = [
    (0x0, "ROM"),
    (0x1, "ROM+RAM"),
    (0x2, "ROM+RAM+battery"),
    (0x3, "ROM+coprocessor"),
    (0x4, "ROM+coprocessor+RAM"),
    (0x5, "ROM+coprocessor+RAM+battery"),
    (0x6, "ROM+coprocessor+battery"),
    (0x9, "ROM+battery+RTC-4513+enhancement chip"),
    (0xA, "ROM+battery+RTC+GSU-1+enhancement chip"),
];

/// Chipset high nibble when a coprocessor is present.
const COPROCESSORS: [(u8, &str); 8] = [
    (0x0, "DSP"),
    (0x1, "GSU (SuperFX)"),
    (0x2, "OBC1"),
    (0x3, "SA-1"),
    (0x4, "S-DD1"),
    (0x5, "S-RTC"),
    (0xE, "other (Super Game Boy or Satellaview)"),
    (0xF, "custom (subtype at 0xFFBF)"),
];

/// Region codes at 0xFFD9.
const REGIONS: [&str; 0x15] = [
    "Japan",
    "North America",
    "Europe",
    "Scandinavia",
    "Finland",
    "Denmark",
    "France",
    "Netherlands",
    "Spain",
    "Germany",
    "Italy",
    "China",
    "Indonesia",
    "South Korea",
    "common",
    "Canada",
    "Brazil or Nintendo Gateway System",
    "Australia",
    "other (X)",
    "other (Y)",
    "other (Z)",
];

/// The 65C816 in the Ricoh 5A22, 16-bit, little-endian.
const W65816: Target = Target::new(Isa::W65816, 16, Endianness::Little);
const RICOH_5A22: &str = "65C816 (Ricoh 5A22)";

/// Where an internal header may be: the mapping's header offset in a ROM
/// that may follow a copier header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Location {
    /// How the cartridge maps the ROM.
    pub(super) mapping: SnesMapping,
    /// A 512-byte copier header precedes the ROM.
    pub(super) copier_header: bool,
}

impl Location {
    const fn new(mapping: SnesMapping, copier_header: bool) -> Self {
        Self {
            mapping,
            copier_header,
        }
    }

    /// File offset of the ROM: after the copier header when there is one.
    fn rom_offset(self) -> usize {
        if self.copier_header {
            COPIER_HEADER_SIZE
        } else {
            0
        }
    }

    /// File offset of the internal header.
    fn header_offset(self) -> usize {
        self.rom_offset() + self.mapping.header_offset()
    }

    fn layout(self) -> Layout {
        Layout::Snes {
            mapping: self.mapping,
            copier_header: self.copier_header,
        }
    }
}

/// Every header location, without and with a copier header.
const LOCATIONS: [Location; 6] = [
    Location::new(SnesMapping::LoRom, false),
    Location::new(SnesMapping::HiRom, false),
    Location::new(SnesMapping::ExHiRom, false),
    Location::new(SnesMapping::LoRom, true),
    Location::new(SnesMapping::HiRom, true),
    Location::new(SnesMapping::ExHiRom, true),
];

impl SnesMapping {
    /// ROM offset of the header (CPU 0x00FFC0).
    fn header_offset(self) -> usize {
        match self {
            Self::LoRom => 0x7FC0,
            Self::HiRom => 0xFFC0,
            Self::ExHiRom => 0x40_FFC0,
        }
    }

    /// ROM offset of CPU 0x008000, where the reset vector points.
    fn bank0_offset(self) -> usize {
        match self {
            Self::LoRom => LOROM_BANK0,
            Self::HiRom => HIROM_BANK0,
            Self::ExHiRom => EXHIROM_BANK0,
        }
    }

    /// Map mode nibbles valid at this location.
    fn mappings(self) -> &'static [u8] {
        match self {
            Self::LoRom => &LOROM_MAPPINGS,
            Self::HiRom => &HIROM_MAPPINGS,
            Self::ExHiRom => &EXHIROM_MAPPINGS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::LoRom => "LoROM",
            Self::HiRom => "HiROM",
            Self::ExHiRom => "ExHiROM",
        }
    }
}

/// A validated internal header.
struct Header<'a> {
    /// The ROM after any copier header.
    rom: &'a [u8],
    /// File offset of the ROM.
    rom_offset: usize,
    /// File offset of the header.
    offset: usize,
    /// The 64 header and vector bytes.
    bytes: &'a [u8],
    checksum: u16,
    reset: u16,
}

fn byte_sum(bytes: &[u8]) -> u64 {
    bytes.iter().map(|&b| u64::from(b)).sum()
}

/// 16-bit sum of all ROM bytes, as if the ROM were a power of two: the
/// part after the largest power of two is zero-padded to a power of two
/// and repeated to fill another such block (`SNESdev` "ROM header").
fn rom_checksum(rom: &[u8]) -> u16 {
    let Some(highest_bit) = usize::BITS.checked_sub(rom.len().leading_zeros() + 1) else {
        return 0;
    };
    let base = 1usize << highest_bit;
    let rest = &rom[base..];
    let mut total = byte_sum(&rom[..base]);
    if !rest.is_empty() {
        // `rest` is shorter than `base`, so its padded size divides `base`.
        let repeats = base / rest.len().next_power_of_two();
        total += byte_sum(rest) * repeats as u64;
    }
    u16::try_from(total & 0xFFFF).expect("masked to 16 bits")
}

/// Title bytes: printable ASCII, or JIS X 0201 katakana as Japanese
/// titles use them.
fn is_title(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| (0x20..=0x7E).contains(b) || KATAKANA.contains(b))
}

/// Check the header at `location`. Cheap checks come first; the checksum
/// sums the whole ROM.
fn validate(data: &[u8], location: Location) -> Result<Header<'_>> {
    let mapping = location.mapping;
    let rom_offset = location.rom_offset();
    let rom = data
        .get(rom_offset..)
        .ok_or_else(|| error("Truncated copier header"))?;
    let offset = location.header_offset();
    let bytes = range(data, "SNES internal header", offset, HEADER_SPAN)?;
    let map_mode = bytes[MAP_MODE];
    let valid_mode = map_mode & MAP_MODE_FIXED_MASK == MAP_MODE_FIXED
        && mapping.mappings().contains(&(map_mode & MAP_MODE_MAPPING));
    if !valid_mode {
        return Err(error(format!(
            "Invalid map mode 0x{map_mode:02X} at 0x{:X}: not a {} mode",
            offset + MAP_MODE,
            mapping.name()
        )));
    }
    let complement = le_u16(bytes, COMPLEMENT)?;
    let checksum = le_u16(bytes, CHECKSUM)?;
    if checksum ^ complement != 0xFFFF {
        return Err(error(format!(
            "Invalid checksum complement 0x{complement:04X} at 0x{:X}: checksum is \
                0x{checksum:04X}",
            offset + COMPLEMENT
        )));
    }
    if !is_title(&bytes[TITLE]) {
        return Err(error(format!(
            "Invalid title at 0x{offset:X}: not printable text"
        )));
    }
    let reset = le_u16(bytes, RESET_VECTOR)?;
    let reset_offset = usize::from(reset.wrapping_sub(ROM_BANK_START)) + mapping.bank0_offset();
    if reset < ROM_BANK_START || reset_offset >= rom.len() {
        return Err(error(format!(
            "Invalid reset vector 0x{reset:04X} at 0x{:X}: not in the ROM of bank 0x00",
            offset + RESET_VECTOR
        )));
    }
    let computed = rom_checksum(rom);
    if computed != checksum {
        return Err(error(format!(
            "Invalid checksum 0x{checksum:04X} at 0x{:X}: computed 0x{computed:04X}",
            offset + CHECKSUM
        )));
    }
    Ok(Header {
        rom,
        rom_offset,
        offset,
        bytes,
        checksum,
        reset,
    })
}

/// The locations whose header validates completely.
fn valid_locations(data: &[u8]) -> Vec<Location> {
    LOCATIONS
        .into_iter()
        .filter(|&location| validate(data, location).is_ok())
        .collect()
}

/// Exactly one complete header, or ambiguity when several validate.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    match valid_locations(data).as_slice() {
        [] => None,
        [location] => Some(location.layout()),
        _ => Some(Layout::SnesAmbiguous),
    }
}

/// Parse a SNES ROM whose header validates at `location`.
pub(super) fn parse(data: &[u8], location: Location) -> Result<Container<'_>> {
    let header = validate(data, location)?;
    let mapping = location.mapping;
    let bytes = header.bytes;
    let mut c = Container::new(FileFormat::SnesRom, RICOH_5A22, "snes");
    c.target = Some(W65816);
    c.entry = Some(u64::from(header.reset));
    c.consumed = data.len();
    c.code_sections = true;
    if header.rom_offset > 0 {
        c.notes
            .push("512-byte copier header at 0x0 skipped; not parsed".into());
    }
    c.notes.push(format!(
        "Internal header at file 0x{:X} ({}); checksum 0x{:04X} and complement verified",
        header.offset,
        mapping.name(),
        header.checksum
    ));
    let map_mode = bytes[MAP_MODE];
    let speed = if map_mode & MAP_MODE_FAST != 0 {
        "FastROM"
    } else {
        "SlowROM"
    };
    c.notes.push(format!("Map mode 0x{map_mode:02X}: {speed}"));
    c.notes.push(format!(
        "Entry is the emulation-mode reset vector 0x{:04X} in bank 0x00; the CPU resets into 6502 \
            emulation mode",
        header.reset
    ));
    let chipset = bytes[CHIPSET];
    if chipset & 0x0F >= CHIPSET_COPROCESSOR {
        c.notes.push(format!(
            "Chipset 0x{chipset:02X}: {}; coprocessor code is not classified separately",
            chipset_name(chipset)
        ));
    }
    c.notes
        .push("The raw code model has no 65816 class; the ISA is the platform's".into());
    c.notes.push(format!(
        "Section address is the ROM offset; the cartridge maps it into CPU banks ({})",
        mapping.name()
    ));
    let declared = 1u64.checked_shl(u32::from(bytes[ROM_SIZE]) + 10);
    if declared.is_some_and(|size| (header.rom.len() as u64) > size) {
        c.notes.push(format!(
            "ROM is larger than the declared size byte 0x{:02X}",
            bytes[ROM_SIZE]
        ));
    }
    push_metadata(&mut c, data, &header, declared);
    c.sections.push(section(
        "ROM",
        0,
        header.rom_offset,
        Cow::Borrowed(header.rom),
        None,
    ));
    Ok(c)
}

/// Several header locations validate: the mapping is not determined, so
/// nothing is extracted and the ISA stays unknown.
pub(super) fn parse_ambiguous(data: &[u8]) -> Result<Container<'_>> {
    let valid = valid_locations(data);
    if valid.len() < 2 {
        return Err(error(
            "Invalid ambiguous SNES layout: fewer than two header locations validate",
        ));
    }
    let locations: Vec<String> = valid
        .iter()
        .map(|location| {
            format!(
                "{} at file 0x{:X}",
                location.mapping.name(),
                location.header_offset()
            )
        })
        .collect();
    let mut c = Container::new(FileFormat::SnesRom, "", "snes");
    c.consumed = data.len();
    c.notes.push(format!(
        "Ambiguous internal header: complete headers at {}; the mapping is not determined and the \
            ROM is not analyzed",
        locations.join(", ")
    ));
    Ok(c)
}

fn chipset_name(chipset: u8) -> String {
    let memory = CHIPSET_MEMORY
        .iter()
        .find(|(code, _)| *code == chipset & 0x0F)
        .map_or_else(
            || format!("unknown (0x{chipset:02X})"),
            |(_, name)| (*name).to_string(),
        );
    if chipset & 0x0F < CHIPSET_COPROCESSOR {
        return memory;
    }
    let coprocessor = COPROCESSORS
        .iter()
        .find(|(code, _)| *code == chipset >> 4)
        .map_or("unknown coprocessor", |(_, name)| *name);
    format!("{memory} ({coprocessor})")
}

fn push_metadata(c: &mut Container<'_>, data: &[u8], header: &Header<'_>, declared: Option<u64>) {
    let bytes = header.bytes;
    c.push_metadata("snes_title", "Title", header_text(&bytes[TITLE]));
    c.push_metadata(
        "snes_map_mode",
        "Map mode",
        format!("0x{:02X}", bytes[MAP_MODE]),
    );
    c.push_metadata("snes_chipset", "Chipset", chipset_name(bytes[CHIPSET]));
    c.push_metadata(
        "snes_rom_size",
        "Declared ROM size",
        declared.map_or_else(|| format!("unknown (0x{:02X})", bytes[ROM_SIZE]), size_text),
    );
    let ram_size = match bytes[RAM_SIZE] {
        0 => "none".to_string(),
        shift => 1u64
            .checked_shl(u32::from(shift) + 10)
            .map_or_else(|| format!("unknown (0x{shift:02X})"), size_text),
    };
    c.push_metadata("snes_ram_size", "Declared RAM size", ram_size);
    let region = bytes[REGION];
    c.push_metadata(
        "snes_region",
        "Region",
        REGIONS.get(usize::from(region)).map_or_else(
            || format!("unknown (0x{region:02X})"),
            |name| (*name).to_string(),
        ),
    );
    c.push_metadata(
        "snes_developer_id",
        "Developer ID",
        format!("0x{:02X}", bytes[DEVELOPER_ID]),
    );
    c.push_metadata("snes_version", "ROM version", u64::from(bytes[VERSION]));
    c.push_metadata(
        "snes_checksum",
        "Checksum (verified)",
        format!("0x{:04X}", header.checksum),
    );
    if bytes[DEVELOPER_ID] == DEVELOPER_EXPANDED {
        // The expanded header precedes the header in the same bank.
        let expanded = header.offset - EXPANDED_HEADER_SIZE;
        if let Ok(fields) = range(data, "expanded header", expanded, EXPANDED_HEADER_SIZE) {
            c.push_metadata(
                "snes_maker_code",
                "Maker code",
                header_text(&fields[EXPANDED_MAKER_CODE]),
            );
            c.push_metadata(
                "snes_game_code",
                "Game code",
                header_text(&fields[EXPANDED_GAME_CODE]),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mirrors_the_part_after_the_largest_power_of_two() {
        assert_eq!(rom_checksum(&[]), 0);
        assert_eq!(rom_checksum(&[1, 2, 3, 4]), 10);
        // 4 + 2 bytes: the 2-byte rest is repeated twice.
        assert_eq!(rom_checksum(&[1, 1, 1, 1, 5, 6]), 4 + 2 * 11);
        // 4 + 1 bytes: the 1-byte rest is repeated four times.
        assert_eq!(rom_checksum(&[0, 0, 0, 0, 3]), 12);
    }

    #[test]
    fn mappings_accept_their_own_map_modes() {
        assert!(SnesMapping::LoRom.mappings().contains(&0x3));
        assert!(!SnesMapping::HiRom.mappings().contains(&0x0));
        assert_eq!(SnesMapping::ExHiRom.header_offset(), 0x40_FFC0);
    }

    #[test]
    fn copier_headers_shift_the_rom_and_its_header_by_512_bytes() {
        let headered = Location::new(SnesMapping::HiRom, true);
        assert_eq!(headered.rom_offset(), 0x200);
        assert_eq!(headered.header_offset(), 0x1_01C0);
        assert_eq!(
            headered.layout(),
            Layout::Snes {
                mapping: SnesMapping::HiRom,
                copier_header: true
            }
        );
    }
}
