//! RPRC images in the MCU+/K3 and mmWave radar layouts.
use super::*;

const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 20;

/// When both layouts validate but disagree about the sections, the section
/// boundaries are ambiguous and nothing is extracted.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    match (layout(data, false), layout(data, true)) {
        (Ok(mcu_plus), Ok(radar))
            if !mcu_plus.sections.is_empty()
                && mcu_plus.sections.iter().zip(&radar.sections).any(|(a, b)| {
                    a.address != b.address || a.offset != b.offset || a.data != b.data
                }) =>
        {
            let mut c = Container::new(Variant::Rprc);
            c.entry = mcu_plus.entry;
            c.consumed = data.len();
            c.opaque = true;
            c.notes.push("Both MCU+ and radar RPRC layouts validate; section boundaries are ambiguous and were not analyzed".into());
            Ok(c)
        }
        (Ok(mcu_plus), _) => Ok(mcu_plus),
        (_, Ok(radar)) => Ok(radar),
        (Err(error), _) => Err(error),
    }
}

/// File header: magic, entry, reserved, section count, version; radar
/// appends a zero word. Section headers are 20 bytes: MCU+ stores (address,
/// reserved, size, 8 reserved bytes) and radar (address, size, 12 zero bytes).
fn layout(data: &[u8], radar: bool) -> Result<Container<'_>> {
    let le = if data.starts_with(b"RPRC") {
        true
    } else if data.starts_with(b"CRPR") {
        false
    } else {
        return Err(error("Invalid RPRC magic"));
    };
    let count = u32_at(data, 12, le)? as usize;
    if count > data.len().saturating_sub(FILE_HEADER_SIZE) / SECTION_HEADER_SIZE {
        return Err(error("Invalid RPRC section count"));
    }
    let mut c = Container::new(Variant::Rprc);
    c.entry = Some(u64::from(u32_at(data, 4, le)?));
    c.notes.push(format!(
        "RPRC version {}; {}-endian header; processor ISA is not encoded",
        u32_at(data, 16, le)?,
        if le { "little" } else { "big" }
    ));
    let mut pos = if radar { 24 } else { FILE_HEADER_SIZE };
    ensure(data, 0, pos)?;
    if radar {
        if u32_at(data, 20, le)? != 0 {
            return Err(error("Invalid radar RPRC reserved header word"));
        }
        c.notes
            .push("Radar RPRC layout: 24 B file header, size in second section-header word".into());
    }
    for _ in 0..count {
        let address = u64::from(u32_at(data, pos, le)?);
        let (reserved, size) = if radar {
            (0, u32_at(data, pos + 4, le)?)
        } else {
            (u32_at(data, pos + 4, le)?, u32_at(data, pos + 8, le)?)
        };
        let size = size as usize;
        ensure(data, pos, SECTION_HEADER_SIZE)?;
        if radar
            && [8, 12, 16]
                .iter()
                .any(|offset| u32_at(data, pos + offset, le).ok() != Some(0))
        {
            return Err(error("Invalid radar RPRC reserved section words"));
        }
        pos += SECTION_HEADER_SIZE;
        if reserved != 0 {
            c.notes.push(format!(
                "Reserved address field 0x{reserved:X} is retained; not interpreted as a 64-bit address"
            ));
        }
        if address + size as u64 > 1u64 << 32 {
            return Err(error("RPRC destination overflow"));
        }
        c.push_section(address, pos, Cow::Borrowed(slice(data, pos, size)?))?;
        pos += size;
    }
    expect_padding(data, pos)?;
    c.consumed = pos;
    Ok(c)
}
