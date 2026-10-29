//! Apple `RTKit` firmware tables (`rkosftab` and `RKOSFTAB`).
//!
//! Layout and diagnostics adapted from `ftab-dump/src/rkos_parser.rs` at
//! `7f10b041d4e9dc6e903c29bd572c5a989fddea68`, whose layout is derived from
//! Apple's updater libraries and cross-checked against idevicerestore's
//! `ftab.h`. All numeric fields are little-endian; offsets and lengths are
//! absolute file byte coordinates. The manifest is opaque and unauthenticated.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::types::FileFormat;
use std::collections::BTreeMap;

const HEADER_SIZE: usize = 0x30;
const ENTRY_SIZE: usize = 0x10;
const MAGIC_OFFSET: usize = 0x20;
const MAGIC_LOWER: &[u8; 8] = b"rkosftab";
const MAGIC_UPPER: &[u8; 8] = b"RKOSFTAB";
const VALID_FLAG: u32 = u32::MAX;
const ALIGNMENT: usize = 4;

/// Recognize either complete magic at byte offset `0x20`, including when
/// the remaining header or table is truncated.
pub fn detect(data: &[u8]) -> bool {
    matches!(data.get(MAGIC_OFFSET..MAGIC_OFFSET + MAGIC_LOWER.len()),
        Some(magic) if magic == MAGIC_LOWER || magic == MAGIC_UPPER)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::FtabParseError {
        message: message.into(),
    }
}

fn slice<'a>(data: &'a [u8], offset: usize, size: usize, field: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| error(format!("Invalid {field} range at 0x{offset:X} + {size} B")))?;
    data.get(offset..end)
        .ok_or_else(|| error(format!("Truncated {field} at 0x{offset:X} + {size} B")))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice(data, offset, 4, "FTAB field")?
            .try_into()
            .expect("slice has exactly four bytes"),
    ))
}

fn field_size(data: &[u8], offset: usize) -> Result<usize> {
    usize::try_from(le_u32(data, offset)?)
        .map_err(|_| error(format!("Unsupported FTAB field at 0x{offset:X}")))
}

/// A validated nonempty occupied byte range, used for overlap diagnostics.
struct Region {
    index: usize,
    offset: usize,
    end: usize,
}

/// Parse a complete FTAB header and file table. Each nonempty payload is an
/// independent child; zero-length placeholders are metadata only. The
/// manifest remains opaque, irrespective of its magic. Duplicate tags,
/// overlaps, alignment and reserved words are diagnostics, as in the source
/// reader; truncated ranges and payloads inside the table are errors.
///
/// Header: generation (0), valid flag (4), nonce (8), manifest offset
/// (16), manifest size (20), reserved words (24, 28), magic (32), count
/// (40), reserved word (44). Entry: tag (0), offset (4), size (8), reserved
/// (12). All coordinates and sizes are in bytes.
///
/// # Errors
///
/// [`ClassifierError::FtabParseError`] for invalid magic, truncated data,
/// payloads overlapping the metadata table, or resource limits. At most
/// 4096 entries and 256 MiB of aggregate referenced payload are accepted.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, HEADER_SIZE, "FTAB header")?;
    if !detect(data) {
        return Err(error("Invalid FTAB magic at 0x20"));
    }
    let count = field_size(data, 0x28)?;
    // Bound the count by actual bytes before allocating or iterating.
    if count > (data.len() - HEADER_SIZE) / ENTRY_SIZE {
        return Err(error(format!(
            "Truncated FTAB file table at 0x{HEADER_SIZE:X}; {count} entries"
        )));
    }
    if count > MAX_COMPONENTS {
        return Err(error(format!(
            "Unsupported FTAB file count {count}; limit {MAX_COMPONENTS}"
        )));
    }
    let table_end = HEADER_SIZE + count * ENTRY_SIZE;
    let mut c = Container::new(FileFormat::Ftab, "Apple FTAB", "ftab");
    c.push_metadata("ftab_generation", "Generation", u64::from(le_u32(data, 0)?));
    let valid = le_u32(data, 4)?;
    c.push_metadata("ftab_valid", "Valid flag", format!("0x{valid:08X}"));
    if valid != VALID_FLAG {
        c.notes
            .push(format!("Unexpected FTAB valid flag 0x{valid:08X}"));
    }
    let nonce = u64::from_le_bytes(
        slice(data, 8, 8, "FTAB boot nonce")?
            .try_into()
            .map_err(|_| error("Truncated FTAB boot nonce at 0x8"))?,
    );
    c.push_metadata("ftab_boot_nonce", "Boot nonce", format!("0x{nonce:016X}"));
    for offset in [0x18, 0x1c, 0x2c] {
        let value = le_u32(data, offset)?;
        if value != 0 {
            c.notes.push(format!(
                "Nonzero FTAB reserved word at 0x{offset:X}: 0x{value:X}"
            ));
        }
    }
    let manifest_offset = field_size(data, 0x10)?;
    let manifest_size = field_size(data, 0x14)?;
    let mut consumed = table_end;
    let mut extracted = manifest_size;
    if manifest_size != 0 {
        let manifest = slice(data, manifest_offset, manifest_size, "FTAB manifest")?;
        consumed = consumed.max(manifest_offset + manifest_size);
        c.children
            .push(Child::opaque("Manifest", manifest_offset, manifest));
        c.notes
            .push("FTAB manifest is opaque; signature not verified".into());
        if manifest_offset < table_end {
            c.notes
                .push("FTAB manifest overlaps the metadata table".into());
        }
        note_alignment(&mut c, manifest_offset, "manifest");
    } else if manifest_offset != 0 {
        c.notes.push(format!(
            "FTAB manifest offset 0x{manifest_offset:X} has zero length"
        ));
    }
    if extracted > MAX_EXTRACTED {
        return Err(error(format!(
            "Unsupported FTAB payload total; limit {MAX_EXTRACTED} B"
        )));
    }

    let mut regions = Vec::with_capacity(count);
    let mut tags = BTreeMap::new();
    let mut previous_offset = None;
    for index in 0..count {
        let record = HEADER_SIZE + index * ENTRY_SIZE;
        let tag = slice(data, record, 4, "FTAB tag")?;
        let label = tag_text(tag);
        let offset = field_size(data, record + 4)?;
        let size = field_size(data, record + 8)?;
        let reserved = le_u32(data, record + 12)?;
        if reserved != 0 {
            c.notes.push(format!(
                "Nonzero FTAB entry {index} reserved word: 0x{reserved:X}"
            ));
        }
        if size == 0 {
            c.push_metadata(
                format!("ftab_placeholder_{index}"),
                format!("Placeholder {label}"),
                format!("file 0x{offset:X}; 0 B; no payload"),
            );
            continue;
        }
        if offset < table_end {
            return Err(error(format!(
                "Invalid FTAB entry {index} offset 0x{offset:X}; before table end 0x{table_end:X}"
            )));
        }
        let payload = slice(data, offset, size, "FTAB payload")?;
        extracted = extracted
            .checked_add(size)
            .filter(|&total| total <= MAX_EXTRACTED)
            .ok_or_else(|| {
                error(format!(
                    "Unsupported FTAB payload total; limit {MAX_EXTRACTED} B"
                ))
            })?;
        let end = offset + size; // slice proved the addition fits usize and the file.
        consumed = consumed.max(end);
        note_alignment(&mut c, offset, &format!("entry {index}"));
        if previous_offset.is_some_and(|previous| offset < previous) {
            c.notes
                .push(format!("FTAB entry {index} is out of file order"));
        }
        previous_offset = Some(offset);
        if let Some(first) = tags.insert(tag, index) {
            c.notes.push(format!(
                "Duplicate FTAB tag {label} in entries {first} and {index}"
            ));
        }
        if manifest_size != 0 && offset < manifest_offset + manifest_size && manifest_offset < end {
            c.notes
                .push(format!("FTAB manifest overlaps entry {index}"));
        }
        regions.push(Region { index, offset, end });
        // The tag names a role, never an ISA. Classification uses the bytes.
        c.children.push(Child::stored(label, offset, payload));
    }
    note_overlaps(&mut c, &mut regions);
    if !data[consumed..].iter().all(|byte| matches!(byte, 0 | 0xff)) {
        return Err(error(format!(
            "Invalid FTAB trailing bytes at 0x{consumed:X}"
        )));
    }
    c.consumed = consumed;
    Ok(c)
}

fn tag_text(tag: &[u8]) -> String {
    if tag.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        String::from_utf8_lossy(tag).into_owned()
    } else {
        hex::encode_upper(tag)
    }
}

fn note_alignment(c: &mut Container<'_>, offset: usize, field: &str) {
    if offset % ALIGNMENT != 0 {
        c.notes.push(format!(
            "FTAB {field} offset 0x{offset:X} is not {ALIGNMENT}-byte aligned"
        ));
    }
}

/// Sort occupied regions and track the furthest end so a nested short range
/// cannot hide an overlap. O(n log n) time, O(1) space beyond the sort.
fn note_overlaps(c: &mut Container<'_>, regions: &mut [Region]) {
    regions.sort_unstable_by_key(|region| (region.offset, region.index));
    let mut furthest: Option<&Region> = None;
    for region in regions.iter() {
        if let Some(first) = furthest {
            if region.offset < first.end {
                c.notes.push(format!(
                    "FTAB entries {} and {} overlap",
                    first.index, region.index
                ));
            }
            if region.end > first.end {
                furthest = Some(region);
            }
        } else {
            furthest = Some(region);
        }
    }
}
