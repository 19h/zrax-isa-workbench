//! iNES and NES 2.0 images (`.nes`).
//!
//! Layout from the `NESdev` Wiki "iNES" (oldid 23194) and "NES 2.0" (oldid
//! 24342) pages: a 16-byte header (`NES` 0x1A, PRG-ROM and CHR-ROM sizes,
//! flags 6 and 7, then the iNES or NES 2.0 fields), an optional 512-byte
//! trainer, PRG-ROM, CHR-ROM, then the PlayChoice-10 INST-ROM and PROM
//! (iNES) or the miscellaneous ROM area (NES 2.0). Header fields are single
//! bytes and nibbles. The `NESdev` "CPU" page (oldid 24046) names the console
//! CPU: a Ricoh 6502 core without decimal mode (RP2A03 NTSC, RP2A07 PAL).
//! CHR-ROM is PPU pattern data and never reaches the code model.

use super::*;

/// `NES` followed by the MS-DOS end-of-file character.
const MAGIC: &[u8] = b"NES\x1A";

const HEADER_SIZE: usize = 16;

/// The trainer is loaded at CPU 0x7000-0x71FF.
const TRAINER_SIZE: usize = 512;
const TRAINER_ADDRESS: u64 = 0x7000;

/// iNES size units: PRG-ROM in 16 KiB, CHR-ROM in 8 KiB.
const PRG_UNIT: u64 = 16 << 10;
const CHR_UNIT: u64 = 8 << 10;

/// Header bytes.
const PRG_SIZE_LSB: usize = 4;
const CHR_SIZE_LSB: usize = 5;
const FLAGS6: usize = 6;
const FLAGS7: usize = 7;
const MAPPER_MSB: usize = 8;
const SIZE_MSB: usize = 9;
const PRG_RAM_SHIFTS: usize = 10;
const CHR_RAM_SHIFTS: usize = 11;
const TIMING: usize = 12;
const CONSOLE_DETAIL: usize = 13;
const MISC_ROMS: usize = 14;
const EXPANSION_DEVICE: usize = 15;

/// iNES byte 9 bit 0: TV system (0 NTSC, 1 PAL).
const INES_TV_SYSTEM: usize = 9;

/// Bytes 12-15 are zero in a clean iNES header.
const INES_UNUSED: Range<usize> = 12..16;

/// Flags 6: battery or other non-volatile memory, 512-byte trainer.
const FLAGS6_BATTERY: u8 = 0x02;
const FLAGS6_TRAINER: u8 = 0x04;

/// Flags 7: iNES Vs. Unisystem and PlayChoice-10 bits; bits 2-3 select the
/// header revision; NES 2.0 bits 0-1 are the console type.
const FLAGS7_VS_UNISYSTEM: u8 = 0x01;
const FLAGS7_PLAYCHOICE: u8 = 0x02;
const REVISION_MASK: u8 = 0x0C;
const REVISION_INES: u8 = 0x00;
const REVISION_NES20: u8 = 0x08;
const CONSOLE_TYPE_MASK: u8 = 0x03;

/// NES 2.0 console types (flags 7 bits 0-1).
const CONSOLE_NES: u8 = 0;
const CONSOLE_VS_SYSTEM: u8 = 1;
const CONSOLE_PLAYCHOICE: u8 = 2;

/// An NES 2.0 size MSB nibble of 0xF selects the exponent-multiplier form.
const EXPONENT_FORM: u8 = 0x0F;

/// NES 2.0 RAM sizes: shift count 0 means none, otherwise `64 << shift` B.
const RAM_SIZE_BASE: u64 = 64;

/// NES 2.0 CPU/PPU timing (byte 12 bits 0-1).
const TIMING_MASK: u8 = 0x03;
const TIMING_PAL: u8 = 1;
const TIMING_DENDY: u8 = 3;
const TIMINGS: [&str; 4] = [
    "RP2C02 (NTSC)",
    "RP2C07 (PAL)",
    "multiple regions",
    "UA6538 (Dendy)",
];

/// NES 2.0 extended console types (byte 13 bits 0-3 when the console type
/// is 3). Types 0x0-0x2 are reserved and mean console types 0-2.
const EXTENDED_DECIMAL_MODE: u8 = 0x3;
const EXTENDED_EPSM: u8 = 0x4;
const EXTENDED_CONSOLE_TYPES: [&str; 16] = [
    "NES/Famicom (reserved code)",
    "Vs. System (reserved code)",
    "PlayChoice-10 (reserved code)",
    "Famiclone with a CPU that supports decimal mode",
    "NES/Famicom with EPSM module or plug-through cartridge",
    "V.R. Technology VT01 with red/cyan STN palette",
    "V.R. Technology VT02",
    "V.R. Technology VT03",
    "V.R. Technology VT09",
    "V.R. Technology VT32",
    "V.R. Technology VT369",
    "UMC UM6578",
    "Famicom Network System",
    "reserved",
    "reserved",
    "reserved",
];

/// Vs. System hardware types (byte 13 bits 4-7): 0x0-0x4 are Vs.
/// Unisystem variants.
const VS_UNISYSTEM_LAST: u8 = 0x4;
const VS_DUAL_SYSTEM: u8 = 0x5;
const VS_DUAL_SYSTEM_PROTECTED: u8 = 0x6;

/// PlayChoice-10 INST-ROM, then the PROM (16 B data and 16 B
/// counter-out), after CHR-ROM in iNES images. The PROM is often missing.
const INST_ROM_SIZE: usize = 8 << 10;
const PROM_SIZE: usize = 32;

/// Some images end with a 128-byte or 127-byte title.
const TITLE_TRAILER_SIZES: [usize; 2] = [127, 128];

/// The CPU vectors NMI, RESET and IRQ/BRK occupy CPU 0xFFFA-0xFFFF
/// (`NESdev` "CPU memory map", oldid 21671).
const VECTORS_SIZE: usize = 6;
const RESET_VECTOR: usize = 2;

/// Mapper 0 (NROM) has no bank switching: PRG-ROM ends at CPU 0xFFFF, so
/// its last six bytes are the vectors. From the NROM board, not the cited
/// header pages.
const MAPPER_NROM: u16 = 0;

/// The console CPU named by the `NESdev` "CPU" page.
const RICOH_2A03: &str = "Ricoh 2A03 (6502 without decimal mode)";
const RICOH_2A07: &str = "Ricoh 2A07 (6502 without decimal mode)";
const DECIMAL_MODE_6502: &str = "6502 with decimal mode (famiclone)";

/// 6502-family code, 8-bit, little-endian operands.
const MCS6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The console family a header names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Console {
    /// NES or Famicom, or an iNES header without the Vs. and `PlayChoice`
    /// flags.
    Standard,
    /// Vs. System: PPU type and hardware type (NES 2.0 byte 13), when known.
    VsSystem(Option<u8>),
    /// PlayChoice-10.
    PlayChoice,
    /// An NES 2.0 extended console type 0x3-0xF.
    Extended(u8),
}

/// The header fields the parser uses. Sizes are bytes.
struct Header {
    nes20: bool,
    /// iNES bytes 7-15 are trustworthy (bits 2-3 of byte 7 and bytes 12-15
    /// zero), or the header is NES 2.0.
    clean: bool,
    prg_size: u64,
    chr_size: u64,
    trainer: bool,
    mapper: u16,
    submapper: Option<u8>,
    console: Console,
    /// NES 2.0 CPU/PPU timing.
    timing: Option<u8>,
    /// NES 2.0 miscellaneous ROM count.
    misc_roms: u8,
}

/// NES 2.0 ROM size from the LSB byte and the MSB nibble in `unit` bytes,
/// or in exponent-multiplier form (`2^E * (MM * 2 + 1)` B) when the nibble
/// is 0xF. `None` when the size overflows 64 bits.
fn nes20_size(lsb: u8, msb: u8, unit: u64) -> Option<u64> {
    if msb == EXPONENT_FORM {
        let exponent = u32::from(lsb >> 2);
        let multiplier = u64::from(lsb & 0x03) * 2 + 1;
        return 1u64.checked_shl(exponent)?.checked_mul(multiplier);
    }
    Some((u64::from(msb) << 8 | u64::from(lsb)) * unit)
}

/// The NES 2.0 ROM sizes a header declares.
struct RomSizes {
    /// PRG-ROM size in bytes, `None` when it overflows 64 bits.
    prg_size: Option<u64>,
    /// CHR-ROM size in bytes, `None` when it overflows 64 bits.
    chr_size: Option<u64>,
}

/// NES 2.0 PRG-ROM and CHR-ROM sizes.
fn nes20_sizes(header: &[u8]) -> RomSizes {
    let msb = header[SIZE_MSB];
    RomSizes {
        prg_size: nes20_size(header[PRG_SIZE_LSB], msb & 0x0F, PRG_UNIT),
        chr_size: nes20_size(header[CHR_SIZE_LSB], msb >> 4, CHR_UNIT),
    }
}

/// Header, trainer, PRG-ROM and CHR-ROM size, when it does not overflow.
fn image_size(header: &[u8], prg: Option<u64>, chr: Option<u64>) -> Option<u64> {
    let trainer = if header[FLAGS6] & FLAGS6_TRAINER != 0 {
        TRAINER_SIZE as u64
    } else {
        0
    };
    (HEADER_SIZE as u64 + trainer)
        .checked_add(prg?)?
        .checked_add(chr?)
}

/// The `NESdev` identification: bits 2-3 of byte 7 equal to 2, and the NES
/// 2.0 sizes fit the file. Anything else is read as iNES.
fn is_nes20(data: &[u8], header: &[u8]) -> bool {
    if header[FLAGS7] & REVISION_MASK != REVISION_NES20 {
        return false;
    }
    let RomSizes { prg_size, chr_size } = nes20_sizes(header);
    image_size(header, prg_size, chr_size).is_some_and(|size| size <= data.len() as u64)
}

/// `NES` 0x1A at offset 0. A file too short for the header is still
/// recognized, so it is reported as truncated.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if !data.starts_with(MAGIC) {
        return None;
    }
    let nes20 = data
        .get(..HEADER_SIZE)
        .is_some_and(|header| is_nes20(data, header));
    Some(if nes20 { Layout::Nes20 } else { Layout::Ines })
}

fn read_header(header: &[u8], layout: Layout) -> Result<Header> {
    let flags6 = header[FLAGS6];
    let flags7 = header[FLAGS7];
    let low_mapper = u16::from(flags6 >> 4);
    let middle_mapper = u16::from(flags7 & 0xF0);
    if layout == Layout::Nes20 {
        let RomSizes { prg_size, chr_size } = nes20_sizes(header);
        let prg_size = prg_size.ok_or_else(|| error("Invalid PRG-ROM size: exceeds 64 bits"))?;
        let chr_size = chr_size.ok_or_else(|| error("Invalid CHR-ROM size: exceeds 64 bits"))?;
        let console = match flags7 & CONSOLE_TYPE_MASK {
            CONSOLE_NES => Console::Standard,
            CONSOLE_VS_SYSTEM => Console::VsSystem(Some(header[CONSOLE_DETAIL])),
            CONSOLE_PLAYCHOICE => Console::PlayChoice,
            // Extended types 0x0-0x2 are reserved and mean console types 0-2.
            _ => match header[CONSOLE_DETAIL] & 0x0F {
                CONSOLE_NES => Console::Standard,
                CONSOLE_VS_SYSTEM => Console::VsSystem(None),
                CONSOLE_PLAYCHOICE => Console::PlayChoice,
                extended => Console::Extended(extended),
            },
        };
        return Ok(Header {
            nes20: true,
            clean: true,
            prg_size,
            chr_size,
            trainer: flags6 & FLAGS6_TRAINER != 0,
            mapper: u16::from(header[MAPPER_MSB] & 0x0F) << 8 | middle_mapper | low_mapper,
            submapper: Some(header[MAPPER_MSB] >> 4),
            console,
            timing: Some(header[TIMING] & TIMING_MASK),
            misc_roms: header[MISC_ROMS] & 0x03,
        });
    }
    let clean =
        flags7 & REVISION_MASK == REVISION_INES && header[INES_UNUSED].iter().all(|&b| b == 0);
    let console = match (
        clean && flags7 & FLAGS7_VS_UNISYSTEM != 0,
        clean && flags7 & FLAGS7_PLAYCHOICE != 0,
    ) {
        (false, false) => Console::Standard,
        (true, false) => Console::VsSystem(None),
        (_, true) => Console::PlayChoice,
    };
    Ok(Header {
        nes20: false,
        clean,
        prg_size: u64::from(header[PRG_SIZE_LSB]) * PRG_UNIT,
        chr_size: u64::from(header[CHR_SIZE_LSB]) * CHR_UNIT,
        trainer: flags6 & FLAGS6_TRAINER != 0,
        // NESdev: when the header is not clean, mask off the upper mapper
        // nibble, which old tools overwrote with text such as `DiskDude!`.
        mapper: if clean {
            middle_mapper | low_mapper
        } else {
            low_mapper
        },
        submapper: None,
        console,
        timing: None,
        misc_roms: 0,
    })
}

/// The CPU variant the cited sources state for a console, if any.
fn cpu_variant(header: &Header) -> Option<&'static str> {
    match header.console {
        Console::Standard | Console::Extended(EXTENDED_EPSM) => match header.timing {
            Some(TIMING_PAL) => Some(RICOH_2A07),
            // The Dendy is a famiclone; its CPU is not described.
            Some(TIMING_DENDY) => None,
            _ => Some(RICOH_2A03),
        },
        Console::Extended(EXTENDED_DECIMAL_MODE) => Some(DECIMAL_MODE_6502),
        Console::VsSystem(_) | Console::PlayChoice | Console::Extended(_) => None,
    }
}

/// The Vs. System hardware type (byte 13 bits 4-7).
fn vs_hardware(hardware: u8) -> String {
    match hardware {
        0x0..=VS_UNISYSTEM_LAST => format!("Vs. Unisystem (hardware type 0x{hardware:X})"),
        VS_DUAL_SYSTEM => "Vs. Dual System".to_string(),
        VS_DUAL_SYSTEM_PROTECTED => {
            "Vs. Dual System (Raid on Bungeling Bay protection)".to_string()
        }
        _ => format!("reserved hardware type 0x{hardware:X}"),
    }
}

/// What the header says about the console, and whether a CPU variant
/// could be named for it.
fn console_note(header: &Header) -> Option<String> {
    let console = match header.console {
        Console::Standard => return None,
        Console::VsSystem(None) => "Console type Vs. System".to_string(),
        Console::VsSystem(Some(detail)) => format!(
            "Console type Vs. System; {}; Vs. PPU type 0x{:X}",
            vs_hardware(detail >> 4),
            detail & 0x0F
        ),
        Console::PlayChoice => "Console type PlayChoice-10".to_string(),
        Console::Extended(extended) => format!(
            "Extended console type 0x{extended:X}: {}",
            EXTENDED_CONSOLE_TYPES[usize::from(extended & 0x0F)]
        ),
    };
    Some(if cpu_variant(header).is_some() {
        console
    } else {
        format!(
            "{console}; the cited sources do not describe its CPU, so no CPU variant is reported"
        )
    })
}

/// The `size` bytes of `what` at `offset`, for a size the header declares.
fn declared<'a>(data: &'a [u8], what: &str, offset: usize, size: u64) -> Result<&'a [u8]> {
    let size = usize::try_from(size)
        .map_err(|_| error(format!("Truncated {what}: {size} B exceeds the file")))?;
    range(data, what, offset, size)
}

/// Parse an iNES or NES 2.0 image into its trainer, PRG-ROM, CHR-ROM and
/// trailing ROMs.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = range(data, "iNES header", 0, HEADER_SIZE)?;
    let fields = read_header(header, layout)?;
    if fields.prg_size == 0 {
        return Err(error("Missing PRG-ROM: size 0"));
    }
    let variant = cpu_variant(&fields);
    let mut c = Container::new(FileFormat::NesRom, variant.unwrap_or(""), "nes");
    c.target = Some(MCS6502);
    c.notes.push(revision_note(&fields));
    if let Some(note) = console_note(&fields) {
        c.notes.push(note);
    }

    let mut pos = HEADER_SIZE;
    if fields.trainer {
        let trainer = range(data, "trainer", pos, TRAINER_SIZE)?;
        c.notes.push(format!(
            "Trainer: file 0x{pos:X}, {TRAINER_SIZE} B, loaded at CPU 0x{TRAINER_ADDRESS:04X}"
        ));
        c.children
            .push(code_child("Trainer", pos, trainer, variant));
        pos += TRAINER_SIZE;
    }
    let prg = declared(data, "PRG-ROM", pos, fields.prg_size)?;
    c.notes.push(format!(
        "PRG-ROM: file 0x{pos:X}, {}; mapper {}{}; bank switching is not modeled",
        size_text(fields.prg_size),
        fields.mapper,
        fields
            .submapper
            .map_or_else(String::new, |s| format!(" (submapper {s})"))
    ));
    vector_notes(&mut c, prg, fields.mapper);
    c.children.push(code_child("PRG-ROM", pos, prg, variant));
    pos += prg.len();

    let chr = declared(data, "CHR-ROM", pos, fields.chr_size)?;
    if chr.is_empty() {
        c.notes
            .push("No CHR-ROM: the cartridge uses CHR-RAM".into());
    } else {
        c.notes.push(format!(
            "CHR-ROM: file 0x{pos:X}, {} of PPU pattern data; not analyzed as code",
            size_text(fields.chr_size)
        ));
        c.children.push(Child::opaque("CHR-ROM", pos, chr));
        pos += chr.len();
    }
    pos = push_trailing_roms(&mut c, data, pos, &fields)?;
    c.consumed = pos;
    push_metadata(&mut c, header, &fields);
    Ok(c)
}

/// 6502 code the console runs, with the CPU variant when one is stated.
/// Trainer and PRG-ROM have no header of their own, so they go straight to
/// the code model.
fn code_child<'a>(
    label: &str,
    offset: usize,
    bytes: &'a [u8],
    variant: Option<&'static str>,
) -> Child<'a> {
    let child = Child::stored(label, offset, bytes)
        .as_code()
        .with_target(MCS6502);
    match variant {
        Some(variant) => child.with_variant(variant),
        None => child,
    }
}

fn revision_note(fields: &Header) -> String {
    match (fields.nes20, fields.clean) {
        (true, _) => "NES 2.0 header".to_string(),
        (false, true) => "iNES header".to_string(),
        (false, false) => "Archaic iNES or iNES 0.7 header: bytes 7-15 hold other data, so flags \
            7 and the upper mapper nibble are ignored"
            .to_string(),
    }
}

/// The vectors in the last six PRG-ROM bytes. They are the CPU's vectors
/// only when the mapper fixes the last bank at 0xC000-0xFFFF; mapper 0 has
/// no banking, so its reset vector is reported as the entry.
fn vector_notes(c: &mut Container<'_>, prg: &[u8], mapper: u16) {
    let Some(vectors) = prg.len().checked_sub(VECTORS_SIZE).map(|at| &prg[at..]) else {
        return;
    };
    let word = |at: usize| u16::from_le_bytes([vectors[at], vectors[at + 1]]);
    let reset = word(RESET_VECTOR);
    if mapper == MAPPER_NROM {
        c.entry = Some(u64::from(reset));
        c.notes.push(format!(
            "Entry is the reset vector 0x{reset:04X}; mapper 0 maps the end of PRG-ROM at CPU \
                0xFFFF"
        ));
    } else {
        c.notes.push(format!(
            "Last PRG-ROM bytes hold NMI 0x{:04X}, reset 0x{reset:04X}, IRQ 0x{:04X}; they are \
                the CPU vectors only if mapper {mapper} fixes the last bank at 0xC000-0xFFFF",
            word(0),
            word(4)
        ));
    }
}

/// PlayChoice-10 INST-ROM and PROM (iNES), the miscellaneous ROM area
/// (NES 2.0), a title trailer or padding. Returns the end of the image.
fn push_trailing_roms<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    mut pos: usize,
    fields: &Header,
) -> Result<usize> {
    let rest = &data[pos..];
    if fields.misc_roms > 0 {
        if rest.is_empty() {
            return Err(error(format!(
                "Missing miscellaneous ROM area: the header declares {} ROMs, the file ends at \
                    0x{pos:X}",
                fields.misc_roms
            )));
        }
        c.notes.push(format!(
            "Miscellaneous ROM area: file 0x{pos:X}, {} ({} ROMs); not analyzed",
            size_text(rest.len() as u64),
            fields.misc_roms
        ));
        c.children
            .push(Child::opaque("Miscellaneous ROMs", pos, rest));
        return Ok(data.len());
    }
    let playchoice = !fields.nes20 && fields.console == Console::PlayChoice;
    if playchoice && rest.len() >= INST_ROM_SIZE {
        c.notes.push(format!(
            "PlayChoice-10 INST-ROM: file 0x{pos:X}, {}; not analyzed",
            size_text(INST_ROM_SIZE as u64)
        ));
        c.children.push(Child::opaque(
            "PlayChoice-10 INST-ROM",
            pos,
            &rest[..INST_ROM_SIZE],
        ));
        pos += INST_ROM_SIZE;
        match data.get(pos..pos + PROM_SIZE) {
            Some(prom) => {
                c.children
                    .push(Child::opaque("PlayChoice-10 PROM", pos, prom));
                pos += PROM_SIZE;
            }
            None => c.notes.push("PlayChoice-10 PROM is missing".into()),
        }
    } else if playchoice {
        c.notes.push("PlayChoice-10 INST-ROM is missing".into());
    }
    let trailer = &data[pos..];
    if trailer.is_empty() {
        return Ok(pos);
    }
    if TITLE_TRAILER_SIZES.contains(&trailer.len()) && !is_padding(trailer) {
        c.push_metadata("nes_trailer_title", "Trailer title", header_text(trailer));
        c.notes
            .push(format!("{} B title trailer at 0x{pos:X}", trailer.len()));
        return Ok(data.len());
    }
    if is_padding(trailer) {
        c.notes.push(format!(
            "{} of padding after the image",
            size_text(trailer.len() as u64)
        ));
        return Ok(data.len());
    }
    Err(error(format!(
        "Invalid trailing data: {} B at 0x{pos:X} after the last ROM",
        trailer.len()
    )))
}

/// NES 2.0 RAM size from a shift count: none, or `64 << shift` B.
fn ram_size(shift: u8) -> String {
    if shift == 0 {
        "none".to_string()
    } else {
        size_text(RAM_SIZE_BASE << shift)
    }
}

fn push_metadata(c: &mut Container<'_>, header: &[u8], fields: &Header) {
    c.push_metadata("nes_mapper", "Mapper", u64::from(fields.mapper));
    if let Some(submapper) = fields.submapper {
        c.push_metadata("nes_submapper", "Submapper", u64::from(submapper));
    }
    c.push_metadata("nes_prg_rom_size", "PRG-ROM size (B)", fields.prg_size);
    c.push_metadata("nes_chr_rom_size", "CHR-ROM size (B)", fields.chr_size);
    let battery = header[FLAGS6] & FLAGS6_BATTERY != 0;
    c.push_metadata(
        "nes_battery",
        "Battery-backed memory",
        if battery { "yes" } else { "no" },
    );
    let console = match fields.console {
        Console::Standard => "NES/Famicom".to_string(),
        Console::VsSystem(_) => "Vs. System".to_string(),
        Console::PlayChoice => "PlayChoice-10".to_string(),
        Console::Extended(extended) => {
            EXTENDED_CONSOLE_TYPES[usize::from(extended & 0x0F)].to_string()
        }
    };
    c.push_metadata("nes_console_type", "Console type", console);
    if let Some(timing) = fields.timing {
        c.push_metadata(
            "nes_timing",
            "CPU/PPU timing",
            TIMINGS[usize::from(timing & TIMING_MASK)],
        );
    }
    if fields.nes20 {
        let shifts = [
            (
                "nes_prg_ram_size",
                "PRG-RAM size",
                header[PRG_RAM_SHIFTS] & 0x0F,
            ),
            (
                "nes_prg_nvram_size",
                "PRG-NVRAM size",
                header[PRG_RAM_SHIFTS] >> 4,
            ),
            (
                "nes_chr_ram_size",
                "CHR-RAM size",
                header[CHR_RAM_SHIFTS] & 0x0F,
            ),
            (
                "nes_chr_nvram_size",
                "CHR-NVRAM size",
                header[CHR_RAM_SHIFTS] >> 4,
            ),
        ];
        for (key, label, shift) in shifts {
            c.push_metadata(key, label, ram_size(shift));
        }
        c.push_metadata(
            "nes_expansion_device",
            "Default expansion device",
            format!("0x{:02X}", header[EXPANSION_DEVICE] & 0x7F),
        );
    } else if fields.clean {
        let pal = header[INES_TV_SYSTEM] & 0x01 != 0;
        c.push_metadata(
            "nes_tv_system",
            "TV system (rarely set)",
            if pal { "PAL" } else { "NTSC" },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nes20_sizes_use_units_or_the_exponent_form() {
        assert_eq!(nes20_size(2, 0, PRG_UNIT), Some(32 << 10));
        assert_eq!(nes20_size(1, 1, CHR_UNIT), Some(257 * 8192));
        // E = 8, MM = 1: 2^8 * 3 B.
        assert_eq!(nes20_size(0x21, EXPONENT_FORM, PRG_UNIT), Some(768));
        // E = 63, MM = 3 overflows.
        assert_eq!(nes20_size(0xFF, EXPONENT_FORM, PRG_UNIT), None);
    }

    #[test]
    fn ram_sizes_are_64_byte_shifts() {
        assert_eq!(ram_size(0), "none");
        assert_eq!(ram_size(7), "8 KiB");
    }
}
