//! Sega Master System and Game Gear cartridge ROMs.
//!
//! SMS Power! "ROM Header": a 16-byte header at 0x7FF0, 0x3FF0 or 0x1FF0
//! (only 0x7FF0 is seen in known software): `TMR SEGA` (8), reserved (2),
//! checksum (2, little-endian) at +0xA, product code (2.5: two BCD bytes and
//! the high nibble of +0xE), version (low nibble of +0xE), region code (high
//! nibble of +0xF) and ROM size code (low nibble of +0xF). `PicoDrive`
//! `detect_media` probes the three offsets in this order.
//!
//! The checksum is the 16-bit sum of the bytes from 0 to the size the code
//! declares, skipping the 16 header bytes (WLA-DX `compute_sms_checksum`).
//! Only the export Master System BIOS checks it; Game Gear and Japanese
//! releases often carry a wrong one (SMS Power!), so a mismatch is reported,
//! not rejected. The CPU is a Z80 that sees the cartridge slot from 0x0000
//! (`MacDonald`, "SMS/GG hardware notes", Z80 memory map).

use super::*;
use crate::formats::MAX_PAYLOAD;

/// The header magic and the offsets probed for it, in order.
const TMR_SEGA: &[u8; 8] = b"TMR SEGA";
const HEADER_OFFSETS: [usize; 3] = [0x7ff0, 0x3ff0, 0x1ff0];
const HEADER_SIZE: usize = 16;

/// Header fields, relative to the header.
const CHECKSUM: usize = 0xa;
const PRODUCT_CODE: usize = 0xc;
const VERSION: usize = 0xe;
const REGION_AND_SIZE: usize = 0xf;

/// Region codes (high nibble of +0xF).
const REGION_SMS_JAPAN: u8 = 0x3;
const REGION_SMS_EXPORT: u8 = 0x4;
const REGION_GG_JAPAN: u8 = 0x5;
const REGION_GG_EXPORT: u8 = 0x6;
const REGION_GG_INTERNATIONAL: u8 = 0x7;

/// A ROM size code and whether the BIOS checksum routines handle it: SMS
/// Power! marks 48 KiB and 1 MiB as buggy in some or all BIOSes.
struct RomSize {
    code: u8,
    size: usize,
    reliable: bool,
}

/// ROM size codes (low nibble of +0xF).
#[rustfmt::skip]
const ROM_SIZES: [RomSize; 9] = [
    RomSize { code: 0xa, size: 8 << 10,   reliable: true },
    RomSize { code: 0xb, size: 16 << 10,  reliable: true },
    RomSize { code: 0xc, size: 32 << 10,  reliable: true },
    RomSize { code: 0xd, size: 48 << 10,  reliable: false },
    RomSize { code: 0xe, size: 64 << 10,  reliable: true },
    RomSize { code: 0xf, size: 128 << 10, reliable: true },
    RomSize { code: 0x0, size: 256 << 10, reliable: true },
    RomSize { code: 0x1, size: 512 << 10, reliable: true },
    RomSize { code: 0x2, size: 1 << 20,   reliable: false },
];

/// The Z80 starts at address 0, where the slot area begins.
const ENTRY: u64 = 0;

/// The high and low halves of a header byte: region and ROM size share
/// +0xF, the product code's top digits and the version share +0xE.
fn high_nibble(byte: u8) -> u8 {
    byte >> 4
}

fn low_nibble(byte: u8) -> u8 {
    byte & 0x0f
}

/// The first header offset that holds `TMR SEGA`.
fn header_offset(data: &[u8]) -> Option<usize> {
    HEADER_OFFSETS
        .into_iter()
        .find(|&offset| has_magic(data, offset, TMR_SEGA) && data.len() >= offset + HEADER_SIZE)
}

/// Strong recognition from `TMR SEGA`; the region code names the system.
pub(super) fn detect(data: &[u8]) -> Option<SegaSystem> {
    let offset = header_offset(data)?;
    Some(system(high_nibble(data[offset + REGION_AND_SIZE])))
}

fn system(region: u8) -> SegaSystem {
    match region {
        REGION_SMS_JAPAN | REGION_SMS_EXPORT => SegaSystem::MasterSystem,
        REGION_GG_JAPAN | REGION_GG_EXPORT | REGION_GG_INTERNATIONAL => SegaSystem::GameGear,
        _ => SegaSystem::Unspecified,
    }
}

fn region_name(region: u8) -> String {
    match region {
        REGION_SMS_JAPAN => "SMS Japan".to_string(),
        REGION_SMS_EXPORT => "SMS Export".to_string(),
        REGION_GG_JAPAN => "GG Japan".to_string(),
        REGION_GG_EXPORT => "GG Export".to_string(),
        REGION_GG_INTERNATIONAL => "GG International".to_string(),
        other => format!("unknown (0x{other:X})"),
    }
}

/// The product code: the high nibble of +0xE in decimal, then the two BCD
/// bytes, high pair first (`26 70` is 7026; with nibble 0xA, 107026).
fn product_code(header: &[u8]) -> String {
    let low = header[PRODUCT_CODE];
    let high = header[PRODUCT_CODE + 1];
    let extra = high_nibble(header[VERSION]);
    if extra == 0 {
        format!("{high:02X}{low:02X}")
    } else {
        format!("{extra}{high:02X}{low:02X}")
    }
}

/// The 16-bit sum of the first `size` bytes, skipping the header.
fn checksum(data: &[u8], size: usize, header: usize) -> u16 {
    data[..size]
        .iter()
        .enumerate()
        .filter(|(i, _)| !(header..header + HEADER_SIZE).contains(i))
        .fold(0u16, |sum, (_, &b)| sum.wrapping_add(u16::from(b)))
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let offset = header_offset(data)
        .ok_or_else(|| error("Missing TMR SEGA header at 0x7FF0, 0x3FF0 or 0x1FF0"))?;
    if data.len() > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported Master System ROM of {} B: the limit is {}",
            data.len(),
            size_text(MAX_PAYLOAD as u64)
        )));
    }
    let header = range(data, "TMR SEGA header", offset, HEADER_SIZE)?;
    let region = high_nibble(header[REGION_AND_SIZE]);
    let size_code = low_nibble(header[REGION_AND_SIZE]);
    let version = low_nibble(header[VERSION]);
    let stored = u16::from_le_bytes([header[CHECKSUM], header[CHECKSUM + 1]]);
    let layout = Layout::Sega8Bit(system(region));

    let mut c = Container::new(FileFormat::SmsRom, "Z80", "sms");
    c.target = Some(Z80);
    c.entry = Some(ENTRY);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "{}; TMR SEGA header at 0x{offset:04X}; region code 0x{region:X} ({})",
        layout.label(),
        region_name(region)
    ));
    c.notes.push(format!(
        "Product code {}; version {version}",
        product_code(header)
    ));
    push_checksum(&mut c, data, offset, size_code, stored, region);
    c.notes.push(
        "Z80 CPU (SMS/GG hardware notes); entry at 0x0000, where the cartridge slot starts".into(),
    );
    c.notes.push(
        "Section address is the ROM offset; the cartridge mapper pages banks into the Z80 address \
            space"
            .into(),
    );
    c.push_metadata("sms_product_code", "Product code", product_code(header));
    c.push_metadata("sms_version", "Version", u64::from(version));
    c.push_metadata("sms_region", "Region", region_name(region));
    c.push_metadata("sms_checksum", "ROM checksum", format!("0x{stored:04X}"));
    c.sections.push(stored_section("ROM", 0, 0, data));
    Ok(c)
}

/// Verify the checksum over the declared size where the size code allows
/// it; only the export Master System BIOS checks it.
fn push_checksum(
    c: &mut Container<'_>,
    data: &[u8],
    header: usize,
    size_code: u8,
    stored: u16,
    region: u8,
) {
    let Some(size) = ROM_SIZES.iter().find(|s| s.code == size_code) else {
        c.notes.push(format!(
            "Unknown ROM size code 0x{size_code:X}; checksum 0x{stored:04X} not verified"
        ));
        return;
    };
    c.push_metadata(
        "sms_rom_size",
        "Declared ROM size",
        size_text(size.size as u64),
    );
    if !size.reliable {
        c.notes.push(format!(
            "ROM size code 0x{size_code:X} ({}) is buggy in some BIOS checksum routines; checksum \
                0x{stored:04X} not verified",
            size_text(size.size as u64)
        ));
        return;
    }
    if size.size > data.len() || header + HEADER_SIZE > size.size {
        c.notes.push(format!(
            "Declared ROM size {} does not cover the {} B file and its header; checksum \
                0x{stored:04X} not verified",
            size_text(size.size as u64),
            data.len()
        ));
        return;
    }
    let computed = checksum(data, size.size, header);
    c.push_metadata(
        "sms_checksum_computed",
        "Computed ROM checksum",
        format!("0x{computed:04X}"),
    );
    let checked_by = if region == REGION_SMS_EXPORT {
        "the export Master System BIOS checks it"
    } else {
        "only the export Master System BIOS checks it"
    };
    if computed == stored {
        c.notes.push(format!(
            "ROM checksum 0x{stored:04X} verified over the first {}",
            size_text(size.size as u64)
        ));
    } else {
        c.notes.push(format!(
            "ROM checksum 0x{stored:04X} does not match the computed 0x{computed:04X}; {checked_by}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_codes_are_bcd_with_a_hex_prefix_nibble() {
        let mut header = [0u8; HEADER_SIZE];
        header[PRODUCT_CODE] = 0x26;
        header[PRODUCT_CODE + 1] = 0x70;
        assert_eq!(product_code(&header), "7026");
        header[VERSION] = 0x21;
        assert_eq!(product_code(&header), "27026");
        header[VERSION] = 0xa0;
        assert_eq!(product_code(&header), "107026");
    }

    #[test]
    fn checksum_skips_the_header() {
        let mut data = vec![1u8; 0x2000];
        data[0x1ff0..].fill(0xff);
        assert_eq!(checksum(&data, 0x2000, 0x1ff0), 0x1ff0);
    }

    #[test]
    fn region_codes_name_the_system() {
        assert_eq!(system(4), SegaSystem::MasterSystem);
        assert_eq!(system(7), SegaSystem::GameGear);
        assert_eq!(system(0), SegaSystem::Unspecified);
    }
}
