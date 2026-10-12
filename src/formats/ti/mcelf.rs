//! MCU+ multicore ELF: ordinary ELF program headers and TI note types.
use super::*;

#[derive(Debug)]
struct Segment {
    kind: u32,
    offset: usize,
    size: usize,
    address: u64,
    flags: u32,
}
fn r64(d: &[u8], p: usize, le: bool) -> Result<u64> {
    let b = bytes(d, p, 8)?;
    Ok(if le {
        u64::from_le_bytes(b.try_into().unwrap())
    } else {
        u64::from_be_bytes(b.try_into().unwrap())
    })
}
fn segments(d: &[u8]) -> Result<Vec<Segment>> {
    if !d.starts_with(b"\x7fELF")
        || !matches!(d.get(4), Some(1 | 2))
        || !matches!(d.get(5), Some(1 | 2))
    {
        return Err(err("Invalid MCELF ELF identification"));
    }
    let le = d[5] == 1;
    let is64 = d[4] == 2;
    let (offset, stride, n) = if is64 {
        (
            usize::try_from(r64(d, 32, le)?).map_err(|_| err("Program offset overflow"))?,
            r16(d, 54, le)? as usize,
            r16(d, 56, le)? as usize,
        )
    } else {
        (
            r32(d, 28, le)? as usize,
            r16(d, 42, le)? as usize,
            r16(d, 44, le)? as usize,
        )
    };
    if n == 0 || stride < if is64 { 56 } else { 32 } {
        return Err(err("Invalid MCELF program header table"));
    }
    bytes(
        d,
        offset,
        n.checked_mul(stride)
            .ok_or_else(|| err("Program header count overflow"))?,
    )?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let at = offset + i * stride;
        let kind = r32(d, at, le)?;
        let (offset, address, size, mem, flags) = if is64 {
            (
                r64(d, at + 8, le)?,
                r64(d, at + 24, le)?,
                r64(d, at + 32, le)?,
                r64(d, at + 40, le)?,
                r32(d, at + 4, le)?,
            )
        } else {
            (
                r32(d, at + 4, le)? as u64,
                r32(d, at + 12, le)? as u64,
                r32(d, at + 16, le)? as u64,
                r32(d, at + 20, le)? as u64,
                r32(d, at + 24, le)?,
            )
        };
        let offset = usize::try_from(offset).map_err(|_| err("Segment offset overflow"))?;
        let size = usize::try_from(size).map_err(|_| err("Segment length overflow"))?;
        bytes(d, offset, size)?;
        if kind == 1 && (size as u64 > mem || address.checked_add(mem).is_none()) {
            return Err(err("Invalid MCELF load memory range"));
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
fn notes<'a>(d: &'a [u8], segments: &[Segment]) -> Result<Vec<(u32, &'a [u8])>> {
    let mut out = Vec::new();
    let le = d[5] == 1;
    for s in segments.iter().filter(|s| s.kind == 4) {
        let data = bytes(d, s.offset, s.size)?;
        // TI's __add_rs_note_segment emits a final PT_NOTE containing 1..16
        // zero padding bytes and a 32-byte random string, without ELF note
        // records. It is deliberately excluded from code and note decoding.
        if (33..=48).contains(&data.len())
            && s.offset + s.size == d.len()
            && s.address == 0
            && s.flags == 0
            && data[..data.len() - 32].iter().all(|b| *b == 0)
        {
            continue;
        }
        let mut pos = 0;
        while pos < data.len() {
            let name = r32(data, pos, le)? as usize;
            let size = r32(data, pos + 4, le)? as usize;
            let kind = r32(data, pos + 8, le)?;
            pos += 12;
            let name = bytes(data, pos, name)?;
            pos += align4(name.len())?;
            let desc = bytes(data, pos, size)?;
            pos += align4(size)?;
            bytes(data, 0, pos)?;
            let expected = match kind {
                0xaaaa5555 => Some(b"Texas Instruments ".as_slice()),
                0xbbbb7777 => Some(b"Segment Map ".as_slice()),
                0xcccc9999 => Some(b"Entry Points ".as_slice()),
                _ => None,
            };
            if let Some(expected) = expected {
                if name != expected {
                    return Err(err("TI multicore ELF note name/type mismatch"));
                }
                if out.iter().any(|(old, _)| *old == kind) {
                    return Err(err("Duplicate TI multicore ELF note"));
                }
                out.push((kind, desc));
            } else if kind == 0xddddbbbb && name == b"otfaConfig" {
                if desc.len() < 8 {
                    return Err(err("Truncated OTFA configuration note"));
                }
                out.push((kind, desc));
            }
        }
    }
    Ok(out)
}
pub(super) fn detect(d: &[u8]) -> bool {
    if !d.starts_with(b"\x7fELF")
        || !matches!(d.get(4), Some(1 | 2))
        || !matches!(d.get(5), Some(1 | 2))
    {
        return false;
    }
    // Identify the namespaced vendor note without requiring all load ranges
    // to validate first. A damaged MCELF must not become a plain ARM ELF.
    (|| -> Result<bool> {
        let le = d[5] == 1;
        let is64 = d[4] == 2;
        let (offset, stride, n) = if is64 {
            (
                usize::try_from(r64(d, 32, le)?).map_err(|_| err("Program offset overflow"))?,
                r16(d, 54, le)? as usize,
                r16(d, 56, le)? as usize,
            )
        } else {
            (
                r32(d, 28, le)? as usize,
                r16(d, 42, le)? as usize,
                r16(d, 44, le)? as usize,
            )
        };
        if stride < if is64 { 56 } else { 32 } {
            return Ok(false);
        }
        bytes(
            d,
            offset,
            n.checked_mul(stride)
                .ok_or_else(|| err("Program header count overflow"))?,
        )?;
        for i in 0..n {
            let at = offset + i * stride;
            if r32(d, at, le)? != 4 {
                continue;
            }
            let note = if is64 {
                usize::try_from(r64(d, at + 8, le)?).map_err(|_| err("Note offset overflow"))?
            } else {
                r32(d, at + 4, le)? as usize
            };
            if let Ok(prefix) = bytes(d, note, 30) {
                if r32(prefix, 0, le)? == 18
                    && r32(prefix, 4, le)? == 0
                    && r32(prefix, 8, le)? == 0xaaaa5555
                    && &prefix[12..30] == b"Texas Instruments "
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })()
    .unwrap_or(false)
}
pub(super) fn parse(d: &[u8]) -> Result<Container<'_>> {
    let segments = segments(d)?;
    let notes = notes(d, &segments)?;
    let le = d[5] == 1;
    if !notes.iter().any(|(kind, _)| *kind == 0xaaaa5555) {
        return Err(err("Missing TI multicore ELF vendor note"));
    }
    let map = notes
        .iter()
        .find(|(k, _)| *k == 0xbbbb7777)
        .map(|(_, b)| *b)
        .ok_or_else(|| err("Missing TI segment-to-core note"))?;
    let entries = notes
        .iter()
        .find(|(k, _)| *k == 0xcccc9999)
        .map(|(_, b)| *b)
        .ok_or_else(|| err("Missing TI core entry-point note"))?;
    let stride = if d[4] == 2 { 12 } else { 8 };
    if entries.len() % stride != 0 {
        return Err(err("Invalid MCELF core entry-point record size"));
    }
    let mapped: Vec<&Segment> = segments.iter().filter(|s| s.kind != 4).collect();
    if map.len() != mapped.len() {
        return Err(err("MCELF segment/core map length mismatch"));
    }
    let mut c = Container::new(Variant::Mcelf);
    c.consumed = d.len();
    if notes
        .iter()
        .any(|(kind, desc)| *kind == 0xddddbbbb && desc[0] != 0)
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
    let elf = crate::formats::elf::parse(d, d[4], d[5])?;
    c.notes.push(format!(
        "Combined ELF declares {}; per-core IDs are platform-dependent",
        elf.isa
    ));
    for entry in entries.chunks_exact(stride) {
        let core = r32(entry, 0, le)?;
        let address = if stride == 12 {
            r64(entry, 4, le)?
        } else {
            r32(entry, 4, le)? as u64
        };
        c.notes
            .push(format!("Core {core}: entry byte address 0x{address:X}"));
    }
    for (s, core) in mapped.iter().zip(map) {
        if s.kind == 1 && s.size != 0 {
            let payload = bytes(d, s.offset, s.size)?;
            c.section(s.address, s.offset, Cow::Borrowed(payload))?;
            let last = c.sections.last_mut().unwrap();
            last.label = format!("Core {core} load segment (flags 0x{:X})", s.flags);
            if s.flags & 1 != 0 {
                c.children.push(Child {
                    label: format!("Core {core} code segment"),
                    offset: s.offset,
                    data: payload,
                    opaque: false,
                    isa_hint: None,
                });
            }
        }
    }
    if c.children.is_empty() {
        c.opaque = true;
        c.notes
            .push("No executable load segments; data is retained as metadata".into());
    }
    Ok(c)
}
