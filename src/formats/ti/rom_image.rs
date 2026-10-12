//! GP ROM images (size and load-address header) and OMAP images, which
//! prefix a GP image with a 512-byte configuration header (TI U-Boot
//! tools/omapimage.c).
use super::*;

const GP_HEADER_SIZE: usize = 8;
const CONFIG_HEADER_SIZE: usize = 512;
const TOC_ENTRY_SIZE: usize = 32;
const CHSETTINGS_KEY: u32 = 0xc0c0_c0c1;

/// The first configuration TOC entry of an OMAP image is CHSETTINGS.
pub(super) fn is_omap(data: &[u8]) -> bool {
    data.get(20..32)
        .is_some_and(|name| name.starts_with(b"CHSETTINGS"))
}

/// A size word and load address, then the image. The size must match the
/// file in exactly one byte order; nothing in the header identifies an ISA.
pub(super) fn gp(data: &[u8]) -> Result<Container<'_>> {
    let image_size = data.len().saturating_sub(GP_HEADER_SIZE);
    let le = le_u32(data, 0)? as usize == image_size;
    let size = u32_at(data, 0, le)? as usize;
    let address = u64::from(u32_at(data, 4, le)?);
    if size < 16 || size != image_size || address == 0 || address + size as u64 > 1u64 << 32 {
        return Err(error("Invalid size/address-only GP image"));
    }
    let mut c = Container::new(Variant::GpImage);
    c.push_section(
        address,
        GP_HEADER_SIZE,
        Cow::Borrowed(slice(data, GP_HEADER_SIZE, size)?),
    )?;
    c.entry = Some(address);
    c.consumed = data.len();
    c.notes.push(
        "Structural recognition of a size/address-only GP header; header does not identify an ISA"
            .into(),
    );
    Ok(c)
}

/// The configuration header is a TOC of 32-byte (offset, size, ..., name)
/// entries ending in an all-ones entry, followed by the records it locates.
/// The GP image starts after the header.
pub(super) fn omap(data: &[u8]) -> Result<Container<'_>> {
    ensure(data, 0, CONFIG_HEADER_SIZE + GP_HEADER_SIZE)?;
    let config = &data[..CONFIG_HEADER_SIZE];
    // The first record offset lies inside the header in the right byte order.
    let le = le_u32(data, 0)? < CONFIG_HEADER_SIZE as u32;
    let mut pos = 0;
    let mut records = Vec::new();
    let mut has_settings = false;
    loop {
        let offset = u32_at(data, pos, le)?;
        let size = u32_at(data, pos + 4, le)?;
        ensure(config, pos, TOC_ENTRY_SIZE)?;
        if offset == u32::MAX && size == u32::MAX {
            break;
        }
        let (offset, size) = (offset as usize, size as usize);
        if offset == 0 || size == 0 || offset < pos + TOC_ENTRY_SIZE {
            return Err(error("Invalid OMAP configuration TOC entry"));
        }
        let record = slice(config, offset, size)?;
        let name = String::from_utf8_lossy(slice(data, pos + 20, 12)?)
            .trim_end_matches('\0')
            .to_string();
        if name == "CHSETTINGS" {
            if u32_at(record, 0, le)? != CHSETTINGS_KEY {
                return Err(error("Invalid OMAP CHSETTINGS key"));
            }
            has_settings = true;
        }
        records.push((offset, offset + size, name));
        pos += TOC_ENTRY_SIZE;
    }
    if !has_settings {
        return Err(error("OMAP configuration header has no CHSETTINGS"));
    }
    if records
        .iter()
        .any(|(start, _, _)| *start < pos + TOC_ENTRY_SIZE)
    {
        return Err(error("OMAP configuration data overlaps TOC"));
    }
    let mut ranges: Vec<_> = records
        .iter()
        .map(|(start, end, _)| (*start, *end))
        .collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(error("Overlapping OMAP configuration ranges"));
    }
    let image = gp(&data[CONFIG_HEADER_SIZE..])?;
    let mut c = Container::new(Variant::OmapImage);
    c.entry = image.entry;
    c.consumed = data.len();
    c.isa = Isa::Arm;
    c.bits = 32;
    c.endian = if le {
        Endianness::Little
    } else {
        Endianness::Big
    };
    for section in image.sections {
        c.push_section(
            section.address,
            section.offset + CONFIG_HEADER_SIZE,
            section.data,
        )?;
    }
    for (offset, end, name) in records {
        c.notes.push(format!(
            "{name}: configuration header offset 0x{offset:X}; {} B",
            end - offset
        ));
    }
    c.notes.push(
        "OMAP configuration header (512 B) followed by GP size/load-address header (8 B)".into(),
    );
    Ok(c)
}
