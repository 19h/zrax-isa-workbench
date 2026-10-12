//! Nintendo DS and `DSi` cartridge images (`.nds`).
//!
//! Layout from GBATEK "DS Cartridge Header", "`DSi` Cartridge Header", "DS
//! Cartridge Secure Area" and "DS Technical Data"; CRCs and the secure-area
//! states from devkitPro ndstool `source/header.cpp` at
//! `76e8b681bb225d945a48852821e03114e6c7ce1c`. All header fields are
//! little-endian. The header names two code areas whose cores are fixed by
//! position: ARM9 (ARM946E-S, `ARMv5TE`) and ARM7 (ARM7TDMI, `ARMv4T`).
//! Each becomes a child classified from its own bytes.

use super::*;

/// The NDS header fields (`0x000-0x17F`). `DSi`-capable images continue
/// with the extended header up to [`DSI_HEADER_SIZE`].
const HEADER_SIZE: usize = 0x180;

/// End of the `DSi` extended header.
const DSI_HEADER_SIZE: usize = 0x1000;

/// Nintendo logo at 0x0C0, its CRC-16 at 0x15C, the header CRC-16 at 0x15E.
const LOGO_OFFSET: usize = 0x0C0;
const LOGO_CRC_OFFSET: usize = 0x15C;
const HEADER_CRC_OFFSET: usize = 0x15E;

/// CRC-16/MODBUS of the logo; the BIOS checks only that the field holds it.
const LOGO_CRC: u16 = 0xCF56;

/// ARM9 and ARM7 code areas: ROM offset, entry, RAM address and size.
const ARM9_FIELDS: usize = 0x020;
const ARM7_FIELDS: usize = 0x030;

/// Header fields read once: title (12 B), game code (4 B), maker code
/// (2 B), unit code, device capacity, ROM version.
const TITLE: Range<usize> = 0x000..0x00C;
const GAME_CODE: Range<usize> = 0x00C..0x010;
const MAKER_CODE: Range<usize> = 0x010..0x012;
const UNIT_CODE: usize = 0x012;
const DEVICE_CAPACITY: usize = 0x014;
const ROM_VERSION: usize = 0x01E;
const SECURE_AREA_CRC: usize = 0x06C;
const TOTAL_USED_ROM_SIZE: usize = 0x080;

/// Chip size is 128 KiB shifted left by the capacity byte.
const CAPACITY_UNIT_SHIFT: u32 = 17;

/// Unit code bit 1: `DSi`-capable (0x02 NDS and `DSi`, 0x03 `DSi` only).
const UNIT_DSI: u8 = 0x02;
const UNIT_DSI_ONLY: u8 = 0x03;

/// `DSi` flags at 0x01C; bit 1 marks modcrypted (AES-CTR) areas.
const DSI_FLAGS: usize = 0x01C;
const DSI_FLAG_MODCRYPT: u8 = 0x02;

/// `DSi` `ARM9i` and `ARM7i` areas: ROM offset at +0, RAM address at +8, size at
/// +12.
const ARM9I_FIELDS: usize = 0x1C0;
const ARM7I_FIELDS: usize = 0x1D0;

/// Modcrypt area 1 and 2: offset and size each.
const MODCRYPT_AREAS: [usize; 2] = [0x220, 0x228];

/// 0x1BF bit 6: an NDS cartridge whose header carries an RSA signature at
/// 0xF80 (made after the `DSi` launched).
const SECURITY_FLAGS: usize = 0x1BF;
const SECURITY_HEADER_RSA: u8 = 0x40;
const RSA_SIGNATURE: usize = 0xF80;

/// `DSi` SHA1-HMACs (ARM9, ARM7, digest master, icon, `ARM9i`, `ARM7i`, ARM9
/// without secure area) at 0x300-0x3B3.
const DSI_HMACS: Range<usize> = 0x300..0x3B4;

/// Secure area: file 0x4000-0x7FFF, present when the ARM9 binary starts
/// there. Its first 2 KiB are KEY1-encrypted on cartridges.
const SECURE_AREA: Range<usize> = 0x4000..0x8000;
const SECURE_AREA_ENCRYPTED_END: usize = 0x4800;

/// Decrypted secure-area ID, and the pattern the BIOS writes over it
/// (`E7FFDEFF E7FFDEFF` as little-endian words).
const SECURE_AREA_ID: [u8; 8] = *b"encryObj";
const SECURE_AREA_ID_ERASED: [u8; 8] = [0xFF, 0xDE, 0xFF, 0xE7, 0xFF, 0xDE, 0xFF, 0xE7];
const SECURE_AREA_ID_SIZE: usize = 8;

/// A memory region a code area must load into (GBATEK header table).
struct Region {
    name: &'static str,
    addresses: Range<u64>,
}

const MAIN_RAM: Region = Region {
    name: "main RAM",
    addresses: 0x0200_0000..0x023B_FE00,
};

const ARM7_WRAM: Region = Region {
    name: "ARM7 WRAM",
    addresses: 0x037F_8000..0x0380_7E00,
};

/// One code area named by the header. `offset` and `size` are file bytes;
/// `entry` and `load` are ARM addresses.
struct Binary {
    name: &'static str,
    offset: usize,
    entry: u64,
    load: u64,
    size: usize,
}

impl Binary {
    /// ROM offset, entry address, RAM address and size (4 B each) at `at`.
    fn read(header: &[u8], name: &'static str, at: usize) -> Result<Self> {
        Ok(Self {
            name,
            offset: le_usize(header, at)?,
            entry: u64::from(le_u32(header, at + 4)?),
            load: u64::from(le_u32(header, at + 8)?),
            size: le_usize(header, at + 12)?,
        })
    }

    /// First address after the loaded bytes; `u64` cannot overflow here.
    fn end(&self) -> u64 {
        self.load + self.size as u64
    }

    /// The stored bytes, once the area is known to lie in the file after
    /// the header and to load, with its entry, into one of `regions`
    /// (GBATEK gives the same ranges for the RAM and the entry addresses).
    fn validate<'a>(&self, data: &'a [u8], regions: &[Region]) -> Result<&'a [u8]> {
        if self.size == 0 {
            return Err(error(format!("Missing {}: size 0", self.name)));
        }
        if self.offset < HEADER_SIZE {
            return Err(error(format!(
                "Invalid {} ROM offset 0x{:X}: inside the header",
                self.name, self.offset
            )));
        }
        let image = range(data, self.name, self.offset, self.size)?;
        let fits = |region: &Region| {
            region.addresses.start <= self.load && self.end() <= region.addresses.end
        };
        if !regions.iter().any(fits) {
            return Err(error(format!(
                "Invalid {} RAM address 0x{:08X}: {} do not fit {}",
                self.name,
                self.load,
                size_text(self.size as u64),
                region_list(regions)
            )));
        }
        let holds_entry = |region: &Region| region.addresses.contains(&self.entry);
        if !regions.iter().any(holds_entry) {
            return Err(error(format!(
                "Invalid {} entry 0x{:08X}: not in {}",
                self.name,
                self.entry,
                region_list(regions)
            )));
        }
        Ok(image)
    }

    /// Whether the entry lies in the bytes this area loads. The header
    /// ranges do not require it, so an entry elsewhere is only noted.
    fn is_entry_loaded(&self) -> bool {
        (self.load..self.end()).contains(&self.entry)
    }

    fn note(&self, core: &str) -> String {
        let outside = if self.is_entry_loaded() {
            ""
        } else {
            " (outside the loaded bytes)"
        };
        format!(
            "{}: file 0x{:X}, {}, loaded at 0x{:08X}, entry 0x{:08X}{outside}; {core}",
            self.name,
            self.offset,
            size_text(self.size as u64),
            self.load,
            self.entry
        )
    }
}

/// The regions for an error message: `main RAM 0x02000000-0x023BFE00 or
/// ...`.
fn region_list(regions: &[Region]) -> String {
    let names: Vec<String> = regions
        .iter()
        .map(|r| {
            format!(
                "{} 0x{:08X}-0x{:08X}",
                r.name, r.addresses.start, r.addresses.end
            )
        })
        .collect();
    names.join(" or ")
}

/// What the stored secure area holds (GBATEK "DS Cartridge Secure Area";
/// ndstool `DetectRomType`).
enum SecureArea {
    /// The ARM9 binary starts outside 0x4000-0x7FFF.
    Absent,
    /// The decrypted ID, or the pattern the BIOS writes over it.
    Decrypted(&'static str),
    /// KEY1-encrypted on cartridges, or not identifiable without the key.
    Unknown,
}

fn secure_area(data: &[u8], arm9: &Binary) -> SecureArea {
    if !SECURE_AREA.contains(&arm9.offset) {
        return SecureArea::Absent;
    }
    match range(
        data,
        "secure area ID",
        SECURE_AREA.start,
        SECURE_AREA_ID_SIZE,
    ) {
        Ok(id) if id == SECURE_AREA_ID => SecureArea::Decrypted("ID encryObj"),
        Ok(id) if id == SECURE_AREA_ID_ERASED => {
            SecureArea::Decrypted("ID overwritten with E7FFDEFF E7FFDEFF, as after the BIOS boot")
        }
        _ => SecureArea::Unknown,
    }
}

/// Logo CRC-16 field 0xCF56, plus the logo itself or a matching header
/// CRC-16.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(header) = data.get(..HEADER_CRC_OFFSET + 2) else {
        return false;
    };
    if le_u16(header, LOGO_CRC_OFFSET).ok() != Some(LOGO_CRC) {
        return false;
    }
    header[LOGO_OFFSET..LOGO_CRC_OFFSET] == NINTENDO_LOGO
        || le_u16(header, HEADER_CRC_OFFSET).ok()
            == Some(checksum::crc16_modbus(&header[..HEADER_CRC_OFFSET]))
}

/// Parse a DS or `DSi` cartridge image into its ARM9 and ARM7 binaries.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, "DS header", 0, HEADER_SIZE)?;
    let logo_crc = le_u16(header, LOGO_CRC_OFFSET)?;
    if logo_crc != LOGO_CRC {
        return Err(error(format!(
            "Invalid logo CRC-16 0x{logo_crc:04X} at 0x{LOGO_CRC_OFFSET:X}: expected \
                0x{LOGO_CRC:04X}"
        )));
    }
    let header_crc = le_u16(header, HEADER_CRC_OFFSET)?;
    let computed = checksum::crc16_modbus(&header[..HEADER_CRC_OFFSET]);
    if header_crc != computed {
        return Err(error(format!(
            "Invalid header CRC-16 0x{header_crc:04X} at 0x{HEADER_CRC_OFFSET:X}: computed \
                0x{computed:04X}"
        )));
    }
    let arm9 = Binary::read(header, "ARM9 binary", ARM9_FIELDS)?;
    let arm7 = Binary::read(header, "ARM7 binary", ARM7_FIELDS)?;
    let arm9_image = arm9.validate(data, &[MAIN_RAM])?;
    let arm7_image = arm7.validate(data, &[MAIN_RAM, ARM7_WRAM])?;
    let unit_code = header[UNIT_CODE];
    let dsi = unit_code & UNIT_DSI != 0;
    let modcrypt = if dsi {
        modcrypt_areas(data)?
    } else {
        Vec::new()
    };

    let mut c = Container::new(FileFormat::NdsRom, ARM946E_S, "nds");
    c.target = Some(ARM_LITTLE);
    c.entry = Some(arm9.entry);
    c.consumed = data.len();
    c.notes.push(format!(
        "Header CRC-16 0x{header_crc:04X} verified; logo CRC-16 field is 0x{LOGO_CRC:04X}"
    ));
    if header[LOGO_OFFSET..LOGO_CRC_OFFSET] != NINTENDO_LOGO {
        c.notes.push(
            "Nintendo logo at 0x0C0 differs from the standard logo; the BIOS checks only the logo \
                CRC-16 field"
                .into(),
        );
    }
    c.notes.push(arm9.note("ARM946E-S"));
    c.notes.push(arm7.note("ARM7TDMI"));
    c.notes.push("Entry point is the ARM9 entry".into());
    push_header_metadata(&mut c, header, &arm9, &arm7)?;

    let area = secure_area(data, &arm9);
    c.notes.push(match &area {
        SecureArea::Absent => "No secure area: the ARM9 binary starts outside 0x4000-0x7FFF".into(),
        SecureArea::Decrypted(id) => format!("Secure area is decrypted ({id})"),
        SecureArea::Unknown => {
            "Secure area 0x4000-0x47FF is KEY1-encrypted or unidentified; not analyzed".into()
        }
    });
    if let Some(note) = secure_area_crc_note(data, &area)? {
        c.notes.push(note);
    }
    push_arm9(&mut c, arm9_image, &arm9, &area, &modcrypt);
    c.children.push(core_child(
        "ARM7 binary",
        arm7.offset,
        arm7_image,
        ARM7TDMI,
        &modcrypt,
    ));

    if dsi {
        push_dsi(&mut c, data, unit_code, &modcrypt)?;
    } else {
        if unit_code != 0 {
            c.notes.push(format!("Unknown unit code 0x{unit_code:02X}"));
        }
        // The flags byte lies in the extended header, past `header`.
        let signed =
            data.len() >= DSI_HEADER_SIZE && byte(data, SECURITY_FLAGS)? & SECURITY_HEADER_RSA != 0;
        if signed {
            c.notes.push(format!(
                "Flags at 0x{SECURITY_FLAGS:X} mark a header RSA-SHA1 signature at \
                    0x{RSA_SIGNATURE:X}; not verified"
            ));
        }
    }
    let used = le_usize(header, TOTAL_USED_ROM_SIZE)?;
    if data.len() < used {
        c.notes.push(format!(
            "File ends before the total used ROM size ({}); later data may be missing",
            size_text(used as u64)
        ));
    }
    c.notes
        .push("NitroROM file system, overlays and icon/title are not parsed".into());
    c.children.sort_by_key(|child| child.offset);
    Ok(c)
}

fn push_header_metadata(
    c: &mut Container<'_>,
    header: &[u8],
    arm9: &Binary,
    arm7: &Binary,
) -> Result<()> {
    c.push_metadata("nds_title", "Title", header_text(&header[TITLE]));
    c.push_metadata(
        "nds_game_code",
        "Game code",
        header_text(&header[GAME_CODE]),
    );
    c.push_metadata(
        "nds_maker_code",
        "Maker code",
        header_text(&header[MAKER_CODE]),
    );
    c.push_metadata(
        "nds_unit_code",
        "Unit code",
        format!("0x{:02X}", header[UNIT_CODE]),
    );
    let capacity = byte(header, DEVICE_CAPACITY)?;
    let chip_size = 1u64
        .checked_shl(CAPACITY_UNIT_SHIFT + u32::from(capacity))
        .map_or_else(|| format!("unknown (0x{capacity:02X})"), size_text);
    c.push_metadata("nds_chip_size", "Device capacity", chip_size);
    c.push_metadata(
        "nds_rom_version",
        "ROM version",
        u64::from(byte(header, ROM_VERSION)?),
    );
    c.push_metadata(
        "nds_arm9_entry",
        "ARM9 entry",
        format!("0x{:08X}", arm9.entry),
    );
    c.push_metadata(
        "nds_arm7_entry",
        "ARM7 entry",
        format!("0x{:08X}", arm7.entry),
    );
    c.push_metadata(
        "nds_total_used_rom_size",
        "Total used ROM size (B)",
        u64::from(le_u32(header, TOTAL_USED_ROM_SIZE)?),
    );
    Ok(())
}

/// A code area of one core, or an opaque child when a modcrypt area
/// overlaps it. The binaries are raw code without a header, so they go
/// straight to the code model.
fn core_child<'a>(
    name: &str,
    offset: usize,
    image: &'a [u8],
    variant: &'static str,
    modcrypt: &[Range<usize>],
) -> Child<'a> {
    // `range` proved that `offset + image.len()` lies in the file.
    let end = offset + image.len();
    if modcrypt
        .iter()
        .any(|area| area.start < end && offset < area.end)
    {
        Child::opaque(format!("{name} (modcrypted)"), offset, image)
    } else {
        Child::stored(name, offset, image)
            .as_code()
            .with_target(ARM_LITTLE)
            .with_variant(variant)
    }
}

/// The ARM9 binary, with an encrypted or unidentified secure-area prefix
/// split off as opaque so it never reaches the code model.
fn push_arm9<'a>(
    c: &mut Container<'a>,
    image: &'a [u8],
    arm9: &Binary,
    area: &SecureArea,
    modcrypt: &[Range<usize>],
) {
    let encrypted = match area {
        SecureArea::Unknown => SECURE_AREA_ENCRYPTED_END
            .saturating_sub(arm9.offset)
            .min(image.len()),
        SecureArea::Absent | SecureArea::Decrypted(_) => 0,
    };
    let (secure, code) = image.split_at(encrypted);
    if !secure.is_empty() {
        c.children.push(Child::opaque(
            "ARM9 secure area (encrypted or unidentified)",
            arm9.offset,
            secure,
        ));
    }
    if !code.is_empty() {
        c.children.push(core_child(
            "ARM9 binary",
            arm9.offset + encrypted,
            code,
            ARM946E_S,
            modcrypt,
        ));
    }
}

/// The secure-area CRC-16 covers 0x4000-0x7FFF in its encrypted form, so a
/// match only says the stored bytes are the ones the CRC was made over.
fn secure_area_crc_note(data: &[u8], area: &SecureArea) -> Result<Option<String>> {
    if matches!(area, SecureArea::Absent) {
        return Ok(None);
    }
    let stored = le_u16(data, SECURE_AREA_CRC)?;
    let note = match data.get(SECURE_AREA) {
        None => format!(
            "Secure area CRC-16 0x{stored:04X} not verified: the file ends before 0x{:X}",
            SECURE_AREA.end
        ),
        Some(bytes) if checksum::crc16_modbus(bytes) == stored => {
            format!("Secure area CRC-16 0x{stored:04X} matches the stored bytes 0x4000-0x7FFF")
        }
        Some(_) => format!(
            "Secure area CRC-16 0x{stored:04X} does not match the stored bytes 0x4000-0x7FFF; the \
                CRC covers the KEY1-encrypted form"
        ),
    };
    Ok(Some(note))
}

/// The modcrypt (AES-CTR) areas the `DSi` extended header lists when its
/// flags mark the image as modcrypted, as file ranges.
fn modcrypt_areas(data: &[u8]) -> Result<Vec<Range<usize>>> {
    range(data, "DSi extended header", 0, DSI_HEADER_SIZE)?;
    let mut areas = Vec::new();
    if byte(data, DSI_FLAGS)? & DSI_FLAG_MODCRYPT == 0 {
        return Ok(areas);
    }
    for at in MODCRYPT_AREAS {
        let offset = le_usize(data, at)?;
        let size = le_usize(data, at + 4)?;
        if size > 0 {
            areas.push(offset..offset.saturating_add(size));
        }
    }
    Ok(areas)
}

/// `DSi` extended header: `ARM9i`/`ARM7i` areas as children (opaque where a
/// modcrypt area covers them), signature and modcrypt notes.
fn push_dsi<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    unit_code: u8,
    modcrypt: &[Range<usize>],
) -> Result<()> {
    let unit = if unit_code == UNIT_DSI_ONLY {
        "DSi only"
    } else {
        "NDS and DSi"
    };
    c.notes.push(format!(
        "DSi extended header: unit code 0x{unit_code:02X} ({unit}); RSA-SHA1 header signature at \
            0x{RSA_SIGNATURE:X} and SHA1-HMACs at 0x{:X}-0x{:X} not verified",
        DSI_HMACS.start,
        DSI_HMACS.end - 1
    ));
    if byte(data, DSI_FLAGS)? & DSI_FLAG_MODCRYPT != 0 {
        let areas: Vec<String> = modcrypt
            .iter()
            .map(|area| format!("0x{:X}-0x{:X}", area.start, area.end))
            .collect();
        c.notes.push(if areas.is_empty() {
            "DSi flags mark the image as modcrypted, but no modcrypt area is listed".to_string()
        } else {
            format!(
                "Modcrypt (AES-CTR) areas {}; not decrypted",
                areas.join(", ")
            )
        });
    }
    let areas = [
        ("ARM9i binary", ARM9I_FIELDS, ARM946E_S),
        ("ARM7i binary", ARM7I_FIELDS, ARM7TDMI),
    ];
    for (name, at, variant) in areas {
        let offset = le_usize(data, at)?;
        let load = le_u32(data, at + 8)?;
        let size = le_usize(data, at + 12)?;
        if size == 0 {
            continue;
        }
        let Ok(image) = range(data, name, offset, size) else {
            c.notes.push(format!(
                "{name}: 0x{offset:X} + {} lies outside the file; not extracted",
                size_text(size as u64)
            ));
            continue;
        };
        c.notes.push(format!(
            "{name}: file 0x{offset:X}, {}, loaded at 0x{load:08X}",
            size_text(size as u64)
        ));
        c.children
            .push(core_child(name, offset, image, variant, modcrypt));
    }
    Ok(())
}
