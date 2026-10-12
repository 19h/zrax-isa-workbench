//! `MCUboot` images (`docs/design.md` in mcu-tools/mcuboot), used by TI and
//! other MCU vendors. All fields are little-endian.
use super::*;

pub(super) const MAGIC: u32 = 0x96f3_b83d;
const HEADER_SIZE: usize = 32;
const TLV_INFO_MAGIC: u16 = 0x6907;
const TLV_PROT_INFO_MAGIC: u16 = 0x6908;

const IMAGE_F_PIC: u32 = 0x01;
const IMAGE_F_ENCRYPTED_AES128: u32 = 0x04;
const IMAGE_F_ENCRYPTED_AES256: u32 = 0x08;
const IMAGE_F_NON_BOOTABLE: u32 = 0x10;
const IMAGE_F_RAM_LOAD: u32 = 0x20;
const ENCRYPTED: u32 = IMAGE_F_ENCRYPTED_AES128 | IMAGE_F_ENCRYPTED_AES256;
const KNOWN_FLAGS: u32 = IMAGE_F_PIC | ENCRYPTED | IMAGE_F_NON_BOOTABLE | IMAGE_F_RAM_LOAD;

/// Header: magic, load address (4), header size (8), protected TLV size
/// (10), image size (12), flags (16), version (20..28). The image follows
/// the header, then the optional protected TLV area and the TLV area.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if le_u32(data, 0)? != MAGIC {
        return Err(error("Invalid MCUboot magic"));
    }
    ensure(data, 0, HEADER_SIZE)?;
    let header = usize::from(le_u16(data, 8)?);
    let protected = usize::from(le_u16(data, 10)?);
    let size = le_u32(data, 12)? as usize;
    if header < HEADER_SIZE || size == 0 {
        return Err(error("Invalid MCUboot header/image length"));
    }
    let mut pos = header
        .checked_add(size)
        .ok_or_else(|| error("MCUboot payload overflow"))?;
    let image = slice(data, header, size)?;
    if protected != 0 {
        let end = tlv_area_end(data, pos, TLV_PROT_INFO_MAGIC)?;
        if end - pos != protected {
            return Err(error("MCUboot protected TLV length mismatch"));
        }
        pos = end;
    }
    if le_u16(data, pos).ok() == Some(TLV_INFO_MAGIC) {
        pos = tlv_area_end(data, pos, TLV_INFO_MAGIC)?;
    }
    // Flash padding and a boot trailer are outside the signed image. Their
    // contents are not code and do not change the payload boundaries.
    let mut c = Container::new(Variant::Mcuboot);
    let flags = le_u32(data, 16)?;
    // Unrecognized future flags can change the payload encoding (compression
    // is an example). Restrict ISA analysis to the documented plain flags.
    let unknown_flags = flags & !KNOWN_FLAGS != 0;
    c.opaque = flags & ENCRYPTED != 0 || unknown_flags;
    c.consumed = pos;
    if unknown_flags {
        c.notes.push(
            "Unknown MCUboot flags; payload encoding is unknown and ISA analysis was skipped"
                .into(),
        );
    }
    c.notes.push(format!(
        "MCUboot flags 0x{flags:X}; version {}.{}.{}+{}; signature/hash authenticity is not verified",
        data[20],
        data[21],
        le_u16(data, 22)?,
        le_u32(data, 24)?
    ));
    c.push_section(u64::from(le_u32(data, 4)?), header, Cow::Borrowed(image))?;
    Ok(c)
}

/// Validate the TLV area at `start` and return its end. The area starts with
/// its magic and total length (including this header), followed by
/// (type, length, value) entries.
fn tlv_area_end(data: &[u8], start: usize, magic: u16) -> Result<usize> {
    if le_u16(data, start)? != magic {
        return Err(error("Missing MCUboot TLV magic"));
    }
    let total = usize::from(le_u16(data, start + 2)?);
    if total < 4 {
        return Err(error("Invalid MCUboot TLV total size"));
    }
    let area = slice(data, start, total)?;
    let mut pos = 4;
    while pos < total {
        ensure(area, pos, 4)?;
        let len = usize::from(le_u16(area, pos + 2)?);
        pos += 4;
        ensure(area, pos, len)?;
        pos += len;
    }
    Ok(start + total)
}
