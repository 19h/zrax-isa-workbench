//! Toyota CUW (Calibration Update Wizard) calibration containers.
//!
//! Toyota publishes no specification. The outer framing follows the
//! community reconstruction in `kaikozlov/ghidra_rh850` at commit `7b31684d`
//! (`tools/techstream/parse_cuw_container.py`), recovered from Techstream
//! V18 `Cuw.exe`. All multi-byte fields are big-endian: the magic
//! `\0CALIBRATION\0` (13 B), a format type (1 B), a CRC-32 (4 B) over the
//! bytes from the size field to the declared end, the declared total size
//! (4 B), then members of a name length (2 B), name, payload length (4 B),
//! payload CRC-32 (4 B) and payload. The first member is `attach.att`
//! (INI text); formats `0x04` and `0x67` follow it with a member count
//! (1 B) and that many members. Other format types have an undocumented
//! tail.

use super::*;

/// `\0CALIBRATION\0`.
pub(super) const MAGIC: &[u8; 13] = b"\0CALIBRATION\0";

/// Format types `Cuw.exe` accepts.
const FORMAT_TYPES: &[u8] = &[
    0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x65, 0x66, 0x67,
];

/// Format types whose tail is a member list.
const MEMBER_LIST_FORMATS: &[u8] = &[0x04, 0x67];

/// Header: magic, format type, CRC-32, declared size.
const FORMAT_TYPE: usize = 13;
const CRC: usize = 14;
const TOTAL_SIZE: usize = 18;
const FIRST_MEMBER: usize = 22;

/// The first member's name.
const ATTACHMENT: &str = "attach.att";

/// A parsed member record.
struct Member<'a> {
    /// The member's payload as a component.
    child: Child<'a>,
    /// File offset just past the payload: the next member or the tail.
    end: usize,
}

/// One member record and the offset after it.
fn member<'a>(data: &'a [u8], pos: usize, notes: &mut Vec<String>) -> Result<Member<'a>> {
    let name_len = usize::from(be_u16(data, pos)?);
    let name_bytes = slice(data, pos + 2, name_len)?;
    let name = String::from_utf8_lossy(name_bytes).to_string();
    let payload_len = be_u32(data, pos + 2 + name_len)? as usize;
    let stored_crc = be_u32(data, pos + 6 + name_len)?;
    let payload_at = pos + 10 + name_len;
    let payload = slice(data, payload_at, payload_len)
        .map_err(|_| error(format!("Truncated CUW member {name} at 0x{pos:X}")))?;
    let computed = crate::formats::checksum::crc32(payload);
    if computed != stored_crc {
        return Err(error(format!(
            "Invalid CUW member CRC-32 for {name}: stored 0x{stored_crc:08X}, computed 0x{computed:08X}"
        )));
    }
    notes.push(format!("Member {name}: {payload_len} B; CRC-32 verified"));
    let child = if name.eq_ignore_ascii_case(ATTACHMENT) {
        // INI text describing the vehicle, nodes and logical blocks.
        Child::opaque(name, payload_at, payload)
    } else {
        // CPU images in newer packages are obfuscated; only recognized
        // formats (plain S-record text) are listed.
        Child::stored(name, payload_at, payload).if_recognized()
    };
    Ok(Member {
        child,
        end: payload_at + payload_len,
    })
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(MAGIC) {
        return Err(error("Missing CUW magic"));
    }
    let format_type = *slice(data, FORMAT_TYPE, 1)?.first().expect("one byte");
    if !FORMAT_TYPES.contains(&format_type) {
        return Err(error(format!(
            "Unsupported CUW format type 0x{format_type:02X}"
        )));
    }
    let stored_crc = be_u32(data, CRC)?;
    let total = be_u32(data, TOTAL_SIZE)? as usize;
    let image = data.get(..total).ok_or_else(|| {
        error(format!(
            "Truncated CUW container: header declares {total} B, {} B present",
            data.len()
        ))
    })?;
    if total < FIRST_MEMBER {
        return Err(error(format!("Invalid CUW size {total} B")));
    }
    let computed = crate::formats::checksum::crc32(&image[TOTAL_SIZE..]);
    if computed != stored_crc {
        return Err(error(format!(
            "Invalid CUW CRC-32: stored 0x{stored_crc:08X}, computed 0x{computed:08X}"
        )));
    }
    let mut c = Container::new(
        FileFormat::ToyotaCuw,
        format!("CUW format 0x{format_type:02X}"),
        "cuw",
    );
    c.consumed = total;
    c.notes.push(format!(
        "Toyota CUW calibration container, format 0x{format_type:02X}; container CRC-32 verified"
    ));
    c.notes.push(
        "Layout from community reverse engineering of Techstream; no field names a CPU".into(),
    );
    let first = member(image, FIRST_MEMBER, &mut c.notes)?;
    c.children.push(first.child);
    let mut pos = first.end;
    if MEMBER_LIST_FORMATS.contains(&format_type) {
        let count = usize::from(*slice(image, pos, 1)?.first().expect("one byte"));
        pos += 1;
        for _ in 0..count {
            let record = member(image, pos, &mut c.notes)?;
            c.children.push(record.child);
            pos = record.end;
        }
        if pos != total {
            return Err(error(format!(
                "Invalid CUW size: members end at 0x{pos:X}, header declares 0x{total:X}"
            )));
        }
    } else if pos < total {
        c.notes.push(format!(
            "{} B of format-specific data after {ATTACHMENT} are not interpreted",
            total - pos
        ));
        c.children
            .push(Child::opaque("Format-specific data", pos, &image[pos..]));
    }
    if data.len() > total {
        c.notes.push(format!(
            "{} B after the declared size are not covered by the CRC",
            data.len() - total
        ));
    }
    Ok(c)
}
