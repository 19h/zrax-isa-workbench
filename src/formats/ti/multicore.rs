//! Multicore images: MCU+ appimages of per-core RPRC images, and mmWave
//! radar metaimages of RPRC or certificate-wrapped components.
use super::*;

/// Header terminator: "MEND" read in the header's byte order.
const END_TOKEN: u32 = 0x444e_454d;

/// Radar component IDs with a documented processor role.
const RADAR_MSS: u32 = 0x3551_0000;
const RADAR_DSS: u32 = 0xd551_0000;
/// Radar subsystem (RF) firmware, which is never analyzed.
const RADAR_BSS: u32 = 0xcf91_0000;

/// MCU+ appimage: "MSTR", core count, device ID, reserved, (core ID, image
/// offset) records and "MEND". Each core image runs to the next one. Any
/// other header with the same start token is a radar metaimage.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let le = if data.starts_with(b"MSTR") {
        true
    } else if data.starts_with(b"RTSM") {
        false
    } else {
        return Err(error("Invalid multicore start token"));
    };
    let cores = u32_at(data, 4, le)? as usize;
    let records = cores
        .checked_mul(8)
        .ok_or_else(|| error("Core count overflow"))?;
    let header = records
        .checked_add(24)
        .ok_or_else(|| error("Header overflow"))?;
    if cores == 0 {
        return Err(error("Multicore image has no cores"));
    }
    ensure(data, 0, header)?;
    if u32_at(data, header - 4, le)? != END_TOKEN {
        return radar(data, le, cores);
    }
    let mut c = Container::new(Variant::Multicore);
    c.notes.push(format!(
        "Device ID {}; core IDs are platform-dependent and do not uniquely identify an ISA",
        u32_at(data, 8, le)?
    ));
    let mut images = Vec::with_capacity(cores);
    for i in 0..cores {
        let at = 16 + i * 8;
        let id = u32_at(data, at, le)?;
        let offset = u32_at(data, at + 4, le)? as usize;
        if offset < header || offset >= data.len() {
            return Err(error("Core image offset is outside payload area"));
        }
        images.push((id, offset));
    }
    let mut starts: Vec<usize> = images.iter().map(|&(_, offset)| offset).collect();
    starts.sort_unstable();
    if starts.windows(2).any(|w| w[0] == w[1]) {
        return Err(error("Duplicate core image offsets"));
    }
    expect_padding(&data[..starts[0]], header)?;
    for (id, offset) in images {
        let next = starts.partition_point(|&start| start <= offset);
        let end = starts.get(next).copied().unwrap_or(data.len());
        let image = slice(data, offset, end - offset)?;
        // appimage tools accept only RPRC inputs. A malformed child invalidates
        // the image; padding between children is allowed by the RPRC parser.
        let parsed = rprc::parse(image)?;
        c.children.push(Child {
            label: format!("Core {id}"),
            offset,
            data: image,
            opaque: parsed.opaque,
            isa_hint: None,
        });
    }
    c.consumed = data.len();
    Ok(c)
}

/// Radar metaimage: 24-byte header, 32-byte component records (present
/// flag, ID, offset, ..., size), shared-memory word and "MEND". The image
/// size is in the header and may be followed by a CRC32 of the image.
fn radar(data: &[u8], le: bool, count: usize) -> Result<Container<'_>> {
    let records = count
        .checked_mul(32)
        .ok_or_else(|| error("Radar core count overflow"))?;
    let header = records
        .checked_add(32)
        .ok_or_else(|| error("Radar header size overflow"))?;
    ensure(data, 0, header)?;
    if u32_at(data, header - 4, le)? != END_TOKEN {
        return Err(error("Missing radar MEND token"));
    }
    let size = u32_at(data, 20, le)? as usize;
    if size < header {
        return Err(error("Invalid radar metaimage size"));
    }
    ensure(data, 0, size)?;
    let image = &data[..size];
    let mut c = Container::new(Variant::Multicore);
    c.consumed = size;
    c.notes.push(format!(
        "mmWave metaimage; device ID {}; shared memory allocation 0x{:08X}; 64-bit header/image CRC fields are not verified",
        u32_at(data, 8, le)?,
        u32_at(data, header - 8, le)?
    ));
    let mut ranges = Vec::new();
    for i in 0..count {
        let at = 24 + i * 32;
        let present = u32_at(data, at, le)? != 0;
        if !present {
            continue;
        }
        let id = u32_at(data, at + 4, le)?;
        let offset = u32_at(data, at + 8, le)? as usize;
        let len = u32_at(data, at + 20, le)? as usize;
        if offset < header || len == 0 {
            return Err(error("Invalid radar component offset/size"));
        }
        let part = slice(image, offset, len)?;
        ranges.push((offset, offset + len));
        let isa_hint = match id {
            RADAR_MSS => Some((Isa::Arm, 32, Endianness::Little)),
            RADAR_DSS => Some((Isa::TiC6000, 32, Endianness::Little)),
            _ => None,
        };
        // Signed components start with a DER certificate SEQUENCE.
        let parsed = if part.starts_with(&[0x30]) {
            x509::parse(part)?
        } else {
            rprc::parse(part)?
        };
        c.children.push(Child {
            label: format!("Radar core 0x{id:08X}"),
            offset,
            data: part,
            opaque: id == RADAR_BSS || parsed.opaque,
            isa_hint,
        });
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(error("Overlapping radar component file ranges"));
    }
    if c.children.is_empty() {
        return Err(error("Radar metaimage has no present images"));
    }
    let trailer = &data[size..];
    if trailer.len() >= 4 && !is_padding(&trailer[..4]) {
        let verdict = if crc32(image) == le_u32(trailer, 0)? {
            "verified"
        } else {
            "mismatch"
        };
        c.notes.push(format!("Appended radar CRC32 {verdict}"));
        expect_padding(data, size + 4)?;
        c.consumed += 4;
    } else {
        expect_padding(data, size)?;
    }
    Ok(c)
}
