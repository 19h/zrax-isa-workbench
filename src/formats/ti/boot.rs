//! Magic-less or weakly keyed DSP ROM boot tables: C28x/C54x word tables,
//! C5510 and generic 32-bit tables, and C3x/C4x tables.
use super::*;

/// A table that validates as both C28x and C54x is reported, but nothing is
/// extracted from it.
pub(super) fn ambiguous(data: &[u8]) -> Result<Container<'_>> {
    c28x(data)?;
    c54x(data)?;
    let mut c = Container::new(Variant::AmbiguousBoot);
    c.opaque = true;
    c.consumed = data.len();
    c.notes.push(
        "Both C28x and C54x layouts validate; target and payload boundaries are ambiguous".into(),
    );
    Ok(c)
}

/// C28x tables reserve eight register words after the key.
pub(super) fn c28x(data: &[u8]) -> Result<Container<'_>> {
    word_table(data, Variant::C28xBoot, 8)
}

/// C54x parallel tables carry two register words and serial tables four.
pub(super) fn c54x(data: &[u8]) -> Result<Container<'_>> {
    let parallel = word_table(data, Variant::C54xBoot, 2);
    let serial = word_table(data, Variant::C54xBoot, 4);
    match (parallel, serial) {
        (Ok(_), Ok(_)) => Err(error("Ambiguous C54x boot-mode header")),
        (Ok(c), Err(_)) | (Err(_), Ok(c)) => Ok(c),
        (Err(_), Err(_)) => Err(error("Invalid C54x parallel/serial boot table")),
    }
}

/// Key word (0x08AA or 0x10AA), `registers` register/reserved words, a
/// 32-bit entry, then (word count, 32-bit destination, words) records up to
/// a zero count. Entry, destinations and counts are in 16-bit words.
fn word_table(data: &[u8], kind: Variant, registers: usize) -> Result<Container<'_>> {
    let is_key = |word| matches!(word, 0x08aa | 0x10aa);
    let le = is_key(le_u16(data, 0)?);
    if !le && !is_key(u16_at(data, 0, false)?) {
        return Err(error("Invalid 8/16-bit ROM boot key"));
    }
    // 32-bit values are stored most significant word first in both byte orders.
    let address = |at: usize| -> Result<u64> {
        let high = u64::from(u16_at(data, at, le)?);
        let low = u64::from(u16_at(data, at + 2, le)?);
        Ok((high << 16) | low)
    };
    let c28x = kind == Variant::C28xBoot;
    let limit = if c28x { 1u64 << 32 } else { 1u64 << 23 };

    let entry = address(2 + registers * 2)?;
    if entry >= limit {
        return Err(error("Entry exceeds destination address width"));
    }
    let mut c = Container::new(kind);
    c.entry = Some(entry);
    let mut pos = 6 + registers * 2;
    loop {
        let words = usize::from(u16_at(data, pos, le)?);
        pos += 2;
        if words == 0 {
            break;
        }
        let destination = address(pos)?;
        pos += 4;
        if destination + words as u64 > limit {
            return Err(error("Section exceeds word address space"));
        }
        let payload = slice(data, pos, words * 2)?;
        c.push_section(destination, pos, Cow::Borrowed(payload))?;
        pos += payload.len();
    }
    if c.sections.is_empty() {
        return Err(error("Boot table has no load sections"));
    }
    expect_padding(data, pos)?;
    c.consumed = pos;
    (c.isa, c.bits, c.endian) = if c28x {
        (Isa::TiC28x, 32, Endianness::Little)
    } else {
        (Isa::TiC5400, 16, Endianness::Big)
    };
    c.notes.push(format!(
        "Header and stream words are {}; 32-bit addresses use most significant word first",
        if le { "little-endian" } else { "big-endian" }
    ));
    c.notes.push(format!(
        "Entry and destinations use 16-bit word addresses; {registers} register/reserved words"
    ));
    Ok(c)
}

/// Production C5510 tables (`C55xLegacy`) and generic 32-bit tables
/// (`C6000Boot`) carry no key, so exactly one byte order must validate.
pub(super) fn unkeyed(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    let big = unkeyed_layout(data, kind, false);
    let little = unkeyed_layout(data, kind, true);
    match (big, little) {
        (Ok(_), Ok(_)) => Err(error("Ambiguous unkeyed byte order")),
        (Ok(c), Err(_)) | (Err(_), Ok(c)) => Ok(c),
        (Err(_), Err(_)) => Err(error("Invalid unkeyed boot table")),
    }
}

/// 32-bit entry, then (byte count, byte destination, data) records up to a
/// zero count. C5510 tables add register records after the entry and keep
/// records 16-bit aligned; generic tables pad each section to 32 bits.
fn unkeyed_layout(data: &[u8], kind: Variant, le: bool) -> Result<Container<'_>> {
    let c5510 = kind == Variant::C55xLegacy;
    let limit = if c5510 { 1u64 << 24 } else { 1u64 << 32 };
    let mut c = Container::new(kind);
    let entry = u64::from(u32_at(data, 0, le)?);
    if entry == 0 || (c5510 && entry >= limit) {
        return Err(error("Invalid unkeyed entry"));
    }
    c.entry = Some(entry);
    let mut pos = 4;
    if c5510 {
        let registers = u32_at(data, 4, le)? as usize;
        let size = registers
            .checked_mul(4)
            .ok_or_else(|| error("Register count overflow"))?;
        ensure(data, 8, size)?;
        pos = 8 + size;
        c.notes
            .push(format!("Register configurations: {registers}"));
    }
    loop {
        let size = u32_at(data, pos, le)? as usize;
        pos += 4;
        if size == 0 {
            break;
        }
        let address = u64::from(u32_at(data, pos, le)?);
        pos += 4;
        if address + size as u64 > limit {
            return Err(error("Section address overflow"));
        }
        // A C5510 section at an odd address is preceded by one pad byte.
        let pad = if c5510 { (address & 1) as usize } else { 0 };
        if c5510 && size < 2 {
            return Err(error("C5510 sections require at least two bytes"));
        }
        let start = pos + pad;
        c.push_section(address, start, Cow::Borrowed(slice(data, start, size)?))?;
        pos = start + size;
        if c5510 {
            if pos % 2 != 0 {
                ensure(data, pos, 1)?;
                pos += 1;
            }
        } else {
            pos = align4(pos)?;
            ensure(data, 0, pos)?;
        }
    }
    let loads_entry = |s: &Section| entry >= s.address && entry < s.address + s.data.len() as u64;
    if !c.sections.iter().any(loads_entry) {
        return Err(error("Unkeyed entry is outside loaded bytes"));
    }
    expect_padding(data, pos)?;
    c.consumed = pos;
    c.notes.push(format!(
        "Structural recognition, no magic or target ID; stream fields are {}-endian; addresses and sizes are bytes",
        if le { "little" } else { "big" }
    ));
    Ok(c)
}

/// C3x/C4x tables (SPRU031H appendix C, SPRU063 chapter 10), all fields
/// little-endian. External-memory tables start with the memory width (8, 16
/// or 32); peripheral streams have no width word. Records are (word count,
/// destination, [C32 control word,] data) up to a zero count. C4x tables end
/// with IVTP, TVTP and IACK values.
pub(super) fn c3x(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    let memory = matches!(le_u32(data, 0)?, 8 | 16 | 32);
    let mut pos = match (kind, memory) {
        (Variant::C31Boot, true) => 8,
        (Variant::C31Boot, false) => 0,
        (Variant::C32Boot, true) => 16,
        (Variant::C32Boot, false) => 12,
        (Variant::C4xBoot, true) => 12,
        (Variant::C4xBoot, false) => 8,
        _ => return Err(error("Invalid C3x/C4x boot kind")),
    };
    ensure(data, 0, pos)?;
    let limit = if kind == Variant::C4xBoot {
        1u64 << 32
    } else {
        1u64 << 24
    };
    let mut c = Container::new(kind);
    loop {
        let count = le_u32(data, pos)? as usize;
        pos += 4;
        if count == 0 {
            break;
        }
        let address = u64::from(le_u32(data, pos)?);
        pos += 4;
        if address + count as u64 > limit {
            return Err(error("C3x/C4x section exceeds word address space"));
        }
        let word_size = if kind == Variant::C32Boot {
            let control = le_u32(data, pos)?;
            pos += 4;
            c32_word_size(control, memory)?
        } else {
            4
        };
        let size = count
            .checked_mul(word_size)
            .ok_or_else(|| error("C3x section count overflow"))?;
        c.push_section(address, pos, Cow::Borrowed(slice(data, pos, size)?))?;
        pos += size;
    }
    if c.sections.is_empty() {
        return Err(error("C3x/C4x boot table has no blocks"));
    }
    if kind == Variant::C4xBoot {
        ensure(data, pos, 12)?;
        c.notes.push(format!(
            "IVTP 0x{:X}; TVTP 0x{:X}; IACK 0x{:X}",
            le_u32(data, pos)?,
            le_u32(data, pos + 4)?,
            le_u32(data, pos + 8)?
        ));
        pos += 12;
    }
    expect_padding(data, pos)?;
    c.entry = Some(c.sections[0].address);
    c.consumed = pos;
    // Headerless peripheral tables are structurally recognizable but do not
    // carry a unique processor marker. Do not turn arbitrary records into C3x.
    if memory {
        c.isa = Isa::TiC3x;
        c.bits = 32;
    }
    c.notes.push(format!(
        "{} boot; 32-bit control words and code words are least-significant byte first; entry is the first block destination; destinations use target words",
        if memory {
            "External memory"
        } else {
            "Peripheral stream (structural recognition)"
        }
    ));
    Ok(c)
}

/// Bytes per stored word of a C32 block. Low-byte bits identify the strobe;
/// the data-type size belongs to bits 16-17 of the strobe value, shifted left
/// eight bits in this record. See SPRU031H appendix C's `read_mb` routine.
fn c32_word_size(control: u32, memory: bool) -> Result<usize> {
    if control & 0xf0 != 0x60 || control & 3 != 0 || control & 0x0c == 0x0c {
        return Err(error("Invalid C32 block control word"));
    }
    if !memory || control & 0x0c == 0 {
        return Ok(4);
    }
    match (control >> 24) & 3 {
        0 => Ok(1),
        1 => Ok(2),
        3 => Ok(4),
        _ => Err(error("Reserved C32 data width")),
    }
}
