//! MCU+ multicore ELF (TI multicore-elf): an ordinary ELF whose TI notes map
//! each segment to a core and list per-core entry points.
use super::*;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PF_X: u32 = 1;

const NOTE_VENDOR: u32 = 0xaaaa_5555;
const NOTE_SEGMENT_MAP: u32 = 0xbbbb_7777;
const NOTE_ENTRY_POINTS: u32 = 0xcccc_9999;
const NOTE_OTFA: u32 = 0xdddd_bbbb;
const VENDOR_NAME: &[u8] = b"Texas Instruments ";

/// ELF class and data encoding.
#[derive(Clone, Copy)]
struct Ident {
    is64: bool,
    le: bool,
}

#[derive(Debug)]
struct Segment {
    kind: u32,
    offset: usize,
    size: usize,
    /// Physical (load) address.
    address: u64,
    flags: u32,
}

fn ident(d: &[u8]) -> Option<Ident> {
    if !d.starts_with(b"\x7fELF")
        || !matches!(d.get(4), Some(1 | 2))
        || !matches!(d.get(5), Some(1 | 2))
    {
        return None;
    }
    Some(Ident {
        is64: d[4] == 2,
        le: d[5] == 1,
    })
}

/// Program header table location: (file offset, entry size, entry count).
fn program_table(d: &[u8], elf: Ident) -> Result<(usize, usize, usize)> {
    let le = elf.le;
    if elf.is64 {
        Ok((
            usize::try_from(u64_at(d, 32, le)?).map_err(|_| error("Program offset overflow"))?,
            usize::from(u16_at(d, 54, le)?),
            usize::from(u16_at(d, 56, le)?),
        ))
    } else {
        Ok((
            u32_at(d, 28, le)? as usize,
            usize::from(u16_at(d, 42, le)?),
            usize::from(u16_at(d, 44, le)?),
        ))
    }
}

fn min_entry_size(elf: Ident) -> usize {
    if elf.is64 {
        56
    } else {
        32
    }
}

fn segments(d: &[u8], elf: Ident) -> Result<Vec<Segment>> {
    let (table, entry_size, count) = program_table(d, elf)?;
    if count == 0 || entry_size < min_entry_size(elf) {
        return Err(error("Invalid MCELF program header table"));
    }
    let table_size = count
        .checked_mul(entry_size)
        .ok_or_else(|| error("Program header count overflow"))?;
    ensure(d, table, table_size)?;
    let le = elf.le;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = table + i * entry_size;
        let kind = u32_at(d, at, le)?;
        // ELF64 moves p_flags up next to p_type and widens the other fields.
        let (offset, address, size, mem_size, flags) = if elf.is64 {
            (
                u64_at(d, at + 8, le)?,
                u64_at(d, at + 24, le)?,
                u64_at(d, at + 32, le)?,
                u64_at(d, at + 40, le)?,
                u32_at(d, at + 4, le)?,
            )
        } else {
            (
                u64::from(u32_at(d, at + 4, le)?),
                u64::from(u32_at(d, at + 12, le)?),
                u64::from(u32_at(d, at + 16, le)?),
                u64::from(u32_at(d, at + 20, le)?),
                u32_at(d, at + 24, le)?,
            )
        };
        let offset = usize::try_from(offset).map_err(|_| error("Segment offset overflow"))?;
        let size = usize::try_from(size).map_err(|_| error("Segment length overflow"))?;
        ensure(d, offset, size)?;
        if kind == PT_LOAD && (size as u64 > mem_size || address.checked_add(mem_size).is_none()) {
            return Err(error("Invalid MCELF load memory range"));
        }
        out.push(Segment {
            kind,
            offset,
            size,
            address,
            flags,
        });
    }
    Ok(out)
}

/// TI's `__add_rs_note_segment` emits a final `PT_NOTE` containing 1..16 zero
/// padding bytes and a 32-byte random string, without ELF note records. It
/// is deliberately excluded from code and note decoding.
fn is_random_string(d: &[u8], segment: &Segment, data: &[u8]) -> bool {
    (33..=48).contains(&data.len())
        && segment.offset + segment.size == d.len()
        && segment.address == 0
        && segment.flags == 0
        && data[..data.len() - 32].iter().all(|b| *b == 0)
}

/// The TI notes, as (type, descriptor), from every `PT_NOTE` segment.
fn ti_notes<'a>(d: &'a [u8], elf: Ident, segments: &[Segment]) -> Result<Vec<(u32, &'a [u8])>> {
    let le = elf.le;
    let mut found: Vec<(u32, &[u8])> = Vec::new();
    for segment in segments.iter().filter(|s| s.kind == PT_NOTE) {
        let data = slice(d, segment.offset, segment.size)?;
        if is_random_string(d, segment, data) {
            continue;
        }
        let mut pos = 0;
        while pos < data.len() {
            // Name size, descriptor size and type, then the 4-byte aligned
            // name and descriptor.
            let name_size = u32_at(data, pos, le)? as usize;
            let desc_size = u32_at(data, pos + 4, le)? as usize;
            let kind = u32_at(data, pos + 8, le)?;
            pos += 12;
            let name = slice(data, pos, name_size)?;
            pos += align4(name.len())?;
            let desc = slice(data, pos, desc_size)?;
            pos += align4(desc_size)?;
            ensure(data, 0, pos)?;
            let expected_name: Option<&[u8]> = match kind {
                NOTE_VENDOR => Some(VENDOR_NAME),
                NOTE_SEGMENT_MAP => Some(b"Segment Map "),
                NOTE_ENTRY_POINTS => Some(b"Entry Points "),
                _ => None,
            };
            if let Some(expected_name) = expected_name {
                if name != expected_name {
                    return Err(error("TI multicore ELF note name/type mismatch"));
                }
                if found.iter().any(|&(seen, _)| seen == kind) {
                    return Err(error("Duplicate TI multicore ELF note"));
                }
                found.push((kind, desc));
            } else if kind == NOTE_OTFA && name == b"otfaConfig" {
                if desc.len() < 8 {
                    return Err(error("Truncated OTFA configuration note"));
                }
                found.push((kind, desc));
            }
        }
    }
    Ok(found)
}

/// Identify the namespaced vendor note without requiring all load ranges
/// to validate first. A damaged MCELF must not become a plain ARM ELF.
pub(super) fn detect(d: &[u8]) -> bool {
    ident(d).is_some_and(|elf| has_vendor_note(d, elf).unwrap_or(false))
}

/// Whether a `PT_NOTE` segment starts with the TI vendor note (an 18-byte
/// name and an empty descriptor).
fn has_vendor_note(d: &[u8], elf: Ident) -> Result<bool> {
    let le = elf.le;
    let (table, entry_size, count) = program_table(d, elf)?;
    if entry_size < min_entry_size(elf) {
        return Ok(false);
    }
    let table_size = count
        .checked_mul(entry_size)
        .ok_or_else(|| error("Program header count overflow"))?;
    ensure(d, table, table_size)?;
    for i in 0..count {
        let at = table + i * entry_size;
        if u32_at(d, at, le)? != PT_NOTE {
            continue;
        }
        let offset = if elf.is64 {
            usize::try_from(u64_at(d, at + 8, le)?).map_err(|_| error("Note offset overflow"))?
        } else {
            u32_at(d, at + 4, le)? as usize
        };
        if let Ok(note) = slice(d, offset, 12 + VENDOR_NAME.len()) {
            if u32_at(note, 0, le)? == VENDOR_NAME.len() as u32
                && u32_at(note, 4, le)? == 0
                && u32_at(note, 8, le)? == NOTE_VENDOR
                && &note[12..] == VENDOR_NAME
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Loadable segments become sections; executable ones also become children,
/// classified separately because each may belong to a different core.
pub(super) fn parse(d: &[u8]) -> Result<Container<'_>> {
    let elf = ident(d).ok_or_else(|| error("Invalid MCELF ELF identification"))?;
    let le = elf.le;
    let segments = segments(d, elf)?;
    let notes = ti_notes(d, elf, &segments)?;
    let note = |kind| {
        notes
            .iter()
            .find(|&&(found, _)| found == kind)
            .map(|&(_, desc)| desc)
    };
    if note(NOTE_VENDOR).is_none() {
        return Err(error("Missing TI multicore ELF vendor note"));
    }
    // One core ID byte per non-note segment.
    let core_map =
        note(NOTE_SEGMENT_MAP).ok_or_else(|| error("Missing TI segment-to-core note"))?;
    // (core ID, entry address) records with a class-sized address.
    let entry_points =
        note(NOTE_ENTRY_POINTS).ok_or_else(|| error("Missing TI core entry-point note"))?;
    let record_size = if elf.is64 { 12 } else { 8 };
    if entry_points.len() % record_size != 0 {
        return Err(error("Invalid MCELF core entry-point record size"));
    }
    let mapped: Vec<&Segment> = segments.iter().filter(|s| s.kind != PT_NOTE).collect();
    if core_map.len() != mapped.len() {
        return Err(error("MCELF segment/core map length mismatch"));
    }
    let mut c = Container::new(Variant::Mcelf);
    c.consumed = d.len();
    if notes
        .iter()
        .any(|&(kind, desc)| kind == NOTE_OTFA && desc[0] != 0)
    {
        // OTFA can add encryption, authentication and ECC to load segments.
        // These stored bytes cannot be analyzed as untransformed code.
        c.opaque = true;
        c.notes.push(
            "Enabled OTFA encoding; stored segments require OTFA decoding before ISA analysis"
                .into(),
        );
    }
    // e_machine describes the combined ELF, not each independently mapped
    // core. Keep its declared value in notes and classify each segment's code.
    let combined = crate::formats::elf::parse(d, d[4], d[5])?;
    c.notes.push(format!(
        "Combined ELF declares {}; per-core IDs are platform-dependent",
        combined.isa
    ));
    for record in entry_points.chunks_exact(record_size) {
        let core = u32_at(record, 0, le)?;
        let address = if elf.is64 {
            u64_at(record, 4, le)?
        } else {
            u64::from(u32_at(record, 4, le)?)
        };
        c.notes
            .push(format!("Core {core}: entry byte address 0x{address:X}"));
    }
    for (segment, core) in mapped.iter().zip(core_map) {
        if segment.kind != PT_LOAD || segment.size == 0 {
            continue;
        }
        let payload = slice(d, segment.offset, segment.size)?;
        c.push_section(segment.address, segment.offset, Cow::Borrowed(payload))?;
        let section = c.sections.last_mut().expect("section was just pushed");
        section.label = format!("Core {core} load segment (flags 0x{:X})", segment.flags);
        if segment.flags & PF_X != 0 {
            c.children.push(Child {
                label: format!("Core {core} code segment"),
                offset: segment.offset,
                data: payload,
                opaque: false,
                isa_hint: None,
            });
        }
    }
    if c.children.is_empty() {
        c.opaque = true;
        c.notes
            .push("No executable load segments; data is retained as metadata".into());
    }
    Ok(c)
}
