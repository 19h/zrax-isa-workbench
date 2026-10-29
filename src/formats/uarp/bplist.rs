//! Structural validation of opaque UARP binary property lists. Layout:
//! apple-oss-distributions/CF `CF-1153.18/CFBinaryPList.c`,
//! `__CFBinaryPlistGetTopLevelInfo` and `__CFBinaryPlistGetOffsetForValueFromArray2`.
//! Objects are checked once by offset, without recursive graph traversal.

use super::{error, slice, Result};

pub(super) const MAGIC: &[u8; 8] = b"bplist00";
const TRAILER_SIZE: usize = 32;
const MAX_OBJECTS: usize = 65_536;
const MAX_REFERENCES: usize = 1_048_576;
const SUPPORTED_WIDTHS: &[usize] = &[1, 2, 4, 8];
const MAX_INTEGER_WIDTH: usize = 8;
const TYPE_SHIFT: u32 = 4;
const INFO_MASK: u8 = 0x0f;
const TYPE_SIMPLE: u8 = 0;
const TYPE_INTEGER: u8 = 1;
const TYPE_REAL: u8 = 2;
const TYPE_DATE: u8 = 3;
const TYPE_DATA: u8 = 4;
const TYPE_ASCII: u8 = 5;
const TYPE_UTF16: u8 = 6;
const TYPE_UID: u8 = 8;
const TYPE_ARRAY: u8 = 10;
const TYPE_ORDERED_SET: u8 = 11;
const TYPE_SET: u8 = 12;
const TYPE_DICTIONARY: u8 = 13;
const SIMPLE_NULL: u8 = 0;
const SIMPLE_FALSE: u8 = 8;
const SIMPLE_TRUE: u8 = 9;
const SIMPLE_FILL: u8 = 15;
const EXTENDED_LENGTH: u8 = 15;
const REAL32_EXPONENT: u8 = 2;
const REAL64_EXPONENT: u8 = 3;
const DATE_INFO: u8 = 3;
const DATE_SIZE: usize = 8;
const MAX_INTEGER_EXPONENT: u8 = 4;
const MAX_LENGTH_EXPONENT: u8 = 3;

fn unsigned(data: &[u8]) -> Result<usize> {
    if data.is_empty() || data.len() > MAX_INTEGER_WIDTH {
        return Err(error("Invalid UARP property-list integer width"));
    }
    let value = data
        .iter()
        .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
    usize::try_from(value).map_err(|_| error("Unsupported UARP property-list integer"))
}

/// Check the header, trailer, offset table, object extents and every object
/// reference. The graph is not followed, so cyclic input cannot recurse.
/// Trailer: reserved (0..6), offset width (6), reference width (7), object
/// count (8), root index (16), offset-table position (24); 64-bit fields
/// are big-endian. Objects and offsets are file byte coordinates.
pub(super) fn validate(data: &[u8]) -> Result<()> {
    if !data.starts_with(MAGIC) || data.len() < MAGIC.len() + TRAILER_SIZE {
        return Err(error("Invalid UARP binary property list"));
    }
    let trailer_start = data.len() - TRAILER_SIZE;
    let trailer = &data[trailer_start..];
    let offset_width = usize::from(trailer[6]);
    let reference_width = usize::from(trailer[7]);
    if !SUPPORTED_WIDTHS.contains(&offset_width) || !SUPPORTED_WIDTHS.contains(&reference_width) {
        return Err(error(
            "Invalid UARP property-list offset or reference width",
        ));
    }
    let count = unsigned(&trailer[8..16])?;
    let root = unsigned(&trailer[16..24])?;
    let table = unsigned(&trailer[24..32])?;
    if count == 0 || count > MAX_OBJECTS || root >= count || table < MAGIC.len() {
        return Err(error(
            "Invalid UARP property-list object count, root or table",
        ));
    }
    // Count was bounded before multiplication; offset width is at most 8.
    if table.checked_add(count * offset_width) != Some(trailer_start) {
        return Err(error("Invalid UARP property-list offset-table extent"));
    }
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let offset = unsigned(slice(
            data,
            table + index * offset_width,
            offset_width,
            "property-list offset",
        )?)?;
        if offset < MAGIC.len() || offset >= table {
            return Err(error("Invalid UARP property-list object offset"));
        }
        offsets.push(offset);
    }
    offsets.sort_unstable();
    if offsets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(error("Duplicate UARP property-list object offset"));
    }
    let mut references = 0;
    for (index, &offset) in offsets.iter().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(table);
        let object = &data[offset..end];
        object_size(object, reference_width, count, &mut references)?;
    }
    Ok(())
}

fn object_size(
    data: &[u8],
    reference_width: usize,
    count: usize,
    references: &mut usize,
) -> Result<()> {
    let marker = data[0]; // every object interval is nonempty and in bounds.
    let kind = marker >> TYPE_SHIFT;
    let info = marker & INFO_MASK;
    let mut pos = 1;
    let size = match kind {
        TYPE_SIMPLE if matches!(info, SIMPLE_NULL | SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_FILL) => 0,
        TYPE_INTEGER if info <= MAX_INTEGER_EXPONENT => 1 << info,
        TYPE_REAL if matches!(info, REAL32_EXPONENT | REAL64_EXPONENT) => 1 << info,
        TYPE_DATE if info == DATE_INFO => DATE_SIZE,
        TYPE_UID => usize::from(info) + 1,
        TYPE_DATA | TYPE_ASCII | TYPE_UTF16 | TYPE_ARRAY | TYPE_ORDERED_SET | TYPE_SET
        | TYPE_DICTIONARY => {
            let length = length(data, info, &mut pos)?;
            let width = match kind {
                TYPE_UTF16 => 2,
                TYPE_ARRAY | TYPE_ORDERED_SET | TYPE_SET => reference_width,
                TYPE_DICTIONARY => reference_width * 2,
                _ => 1,
            };
            let bytes = length
                .checked_mul(width)
                .ok_or_else(|| error("Invalid UARP property-list object size"))?;
            let contents = slice(data, pos, bytes, "property-list object")?;
            if matches!(
                kind,
                TYPE_ARRAY | TYPE_ORDERED_SET | TYPE_SET | TYPE_DICTIONARY
            ) {
                let reference_count = bytes / reference_width;
                *references = references
                    .checked_add(reference_count)
                    .filter(|&total| total <= MAX_REFERENCES)
                    .ok_or_else(|| error("Unsupported UARP property-list reference count"))?;
                for reference in contents.chunks_exact(reference_width) {
                    if unsigned(reference)? >= count {
                        return Err(error("Invalid UARP property-list object reference"));
                    }
                }
            }
            bytes
        }
        _ => {
            return Err(error(format!(
                "Unsupported UARP property-list marker 0x{marker:02X}"
            )))
        }
    };
    slice(data, pos, size, "property-list object")?;
    Ok(())
}

fn length(data: &[u8], info: u8, pos: &mut usize) -> Result<usize> {
    if info != EXTENDED_LENGTH {
        return Ok(usize::from(info));
    }
    let marker = slice(data, *pos, 1, "property-list length")?[0];
    if marker >> TYPE_SHIFT != TYPE_INTEGER || marker & INFO_MASK > MAX_LENGTH_EXPONENT {
        return Err(error("Invalid UARP property-list length integer"));
    }
    let width = 1 << (marker & INFO_MASK);
    let value = unsigned(slice(data, *pos + 1, width, "property-list length")?)?;
    *pos += 1 + width;
    Ok(value)
}
