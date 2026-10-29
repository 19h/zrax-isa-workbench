//! UARP super binaries, adapted from `uarp-dump/src/uarp_parser.rs` at
//! `1b41607c6805d59b61cb4a8f536153d58b52c866`. That source derives the
//! 44-byte header, 40-byte payload records and packed TLVs from Apple's
//! `uarpSuperBinaryHeaderEndianSwap`, `uarpPayloadHeaderEndianSwap` and
//! `uarpProcessTLV`. Numeric fields are big-endian; role tags are raw bytes.
//! Offsets are absolute file byte coordinates. See `docs/uarp.md`.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::types::FileFormat;

mod bplist;

const HEADER_SIZE: usize = 44;
const HEADER_SIZE_WORD: u32 = 44;
const PAYLOAD_HEADER_SIZE: usize = 40;
const TLV_HEADER_SIZE: usize = 8;
const MAX_TLVS: usize = 4096;
const TLV_PREVIEW_SIZE: usize = 64;
// Observed compressed-table role in the local UARP sample corpus.
const CTAB_TAG: &[u8; 4] = b"CTAB";

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::UarpParseError {
        message: message.into(),
    }
}

fn slice<'a>(data: &'a [u8], offset: usize, size: usize, field: &str) -> Result<&'a [u8]> {
    let end = offset.checked_add(size).ok_or_else(|| {
        error(format!(
            "Invalid UARP {field} range at 0x{offset:X} + {size} B"
        ))
    })?;
    data.get(offset..end)
        .ok_or_else(|| error(format!("Truncated UARP {field} at 0x{offset:X} + {size} B")))
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        slice(data, offset, 4, "field")?
            .try_into()
            .expect("slice has exactly four bytes"),
    ))
}

fn field_size(data: &[u8], offset: usize) -> Result<usize> {
    usize::try_from(be_u32(data, offset)?)
        .map_err(|_| error(format!("Unsupported UARP field at 0x{offset:X}")))
}

fn version(data: &[u8], offset: usize) -> Result<String> {
    Ok(format!(
        "{}.{}.{}.{}",
        be_u32(data, offset)?,
        be_u32(data, offset + 4)?,
        be_u32(data, offset + 8)?,
        be_u32(data, offset + 12)?
    ))
}

/// Weak recognition: fixed header sizes, a nonempty payload table, every
/// metadata TLV and every referenced range must validate. No UARP magic
/// exists; a version word alone never identifies a super binary.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < HEADER_SIZE || be_u32(data, 4).ok() != Some(HEADER_SIZE_WORD) {
        return false;
    }
    parse_container(data).is_ok()
}

/// Parse a UARP super binary with independent payload children and metadata
/// TLV previews. The declared super-binary size bounds all referenced bytes.
/// Data after that extent may only be zero or erased-flash padding.
///
/// Header: format (0), header size (4), image size (8), four-word version
/// (12), metadata offset/size (28/32), payload-table offset/size (36/40).
/// Payload: header size (0), raw role tag (4), four-word version (8),
/// metadata offset/size (24/28), payload offset/size (32/36). All sizes and
/// offsets are in bytes; all words are big-endian except the raw tag.
///
/// # Errors
///
/// [`ClassifierError::UarpParseError`] for invalid sizes, truncated ranges
/// or TLVs, payloads overlapping structural headers, or resource limits:
/// 4096 payloads, 4096 total TLVs, 256 MiB aggregate referenced bytes.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, HEADER_SIZE, "header")?;
    let header_size = field_size(data, 4)?;
    if header_size != HEADER_SIZE {
        return Err(error(format!(
            "Invalid UARP header size {header_size} B; expected {HEADER_SIZE} B"
        )));
    }
    let image_size = field_size(data, 8)?;
    if image_size < HEADER_SIZE {
        return Err(error(format!("Invalid UARP image size {image_size} B")));
    }
    let image = slice(data, 0, image_size, "image")?;
    let table_offset = field_size(image, 36)?;
    let table_size = field_size(image, 40)?;
    if table_size == 0 || table_size % PAYLOAD_HEADER_SIZE != 0 {
        return Err(error(format!(
            "Invalid UARP payload-table size {table_size} B"
        )));
    }
    slice(image, table_offset, table_size, "payload table")?;
    if table_offset < HEADER_SIZE {
        return Err(error(format!(
            "Invalid UARP payload-table offset 0x{table_offset:X}"
        )));
    }
    let count = table_size / PAYLOAD_HEADER_SIZE;
    if count > MAX_COMPONENTS {
        return Err(error(format!(
            "Unsupported UARP payload count {count}; limit {MAX_COMPONENTS}"
        )));
    }
    let table_end = table_offset + table_size;
    let mut c = Container::new(FileFormat::Uarp, "UARP super binary", "uarp");
    c.push_metadata(
        "uarp_format_version",
        "Format version",
        u64::from(be_u32(image, 0)?),
    );
    c.push_metadata("uarp_version", "Super-binary version", version(image, 12)?);
    c.notes.push(
        "UARP role tags and version fields name no ISA; payloads are classified independently"
            .into(),
    );
    c.notes.push(
        "UARP metadata is parsed structurally; signatures and digests are not verified".into(),
    );
    let mut budget = Budget {
        referenced: 0,
        tlvs: 0,
    };
    metadata(
        &mut c,
        image,
        &MetadataRegion {
            offset: field_size(image, 28)?,
            size: field_size(image, 32)?,
            table_offset,
            table_end,
            key: "uarp_global".into(),
        },
        &mut budget,
    )?;
    for index in 0..count {
        let record = table_offset + index * PAYLOAD_HEADER_SIZE;
        let size = field_size(image, record)?;
        if size != PAYLOAD_HEADER_SIZE {
            return Err(error(format!(
                "Invalid UARP payload {index} header size {size} B"
            )));
        }
        let tag = slice(image, record + 4, 4, "role tag")?;
        let label = if tag.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            String::from_utf8_lossy(tag).into_owned()
        } else {
            hex::encode_upper(tag)
        };
        c.push_metadata(
            format!("uarp_payload_{index}_version"),
            format!("{label} version"),
            version(image, record + 8)?,
        );
        metadata(
            &mut c,
            image,
            &MetadataRegion {
                offset: field_size(image, record + 24)?,
                size: field_size(image, record + 28)?,
                table_offset,
                table_end,
                key: format!("uarp_payload_{index}"),
            },
            &mut budget,
        )?;
        let offset = field_size(image, record + 32)?;
        let size = field_size(image, record + 36)?;
        if size == 0 {
            c.push_metadata(
                format!("uarp_placeholder_{index}"),
                format!("{label} placeholder"),
                "0 B; no payload",
            );
            continue;
        }
        let payload = content_region(image, offset, size, table_offset, table_end)?;
        budget.add(size)?;
        if payload.starts_with(bplist::MAGIC) {
            bplist::validate(payload)?;
            c.children.push(Child::opaque(label, offset, payload));
        } else if tag == CTAB_TAG {
            // Observed CTAB members carry chunked compressed data alongside
            // an FTAB with the same compose-payload digest. Until that codec
            // is implemented, the role is conservatively treated as opaque.
            c.notes.push(
                "CTAB payload is potentially compressed; not decoded or analyzed as code".into(),
            );
            c.children.push(Child::opaque(label, offset, payload));
        } else {
            c.children.push(Child::stored(label, offset, payload));
        }
    }
    let trailer = &data[image_size..];
    if trailer.starts_with(bplist::MAGIC) {
        bplist::validate(trailer)?;
        budget.add(trailer.len())?;
        c.children
            .push(Child::opaque("Property list trailer", image_size, trailer));
        c.notes
            .push("UARP binary property list trailer is opaque; not authenticated".into());
    } else if !trailer.iter().all(|byte| matches!(byte, 0 | 0xff)) {
        return Err(error(format!(
            "Invalid UARP trailing bytes at 0x{image_size:X}"
        )));
    }
    c.consumed = image_size;
    Ok(c)
}

/// Budget includes repeated and overlapping references, preventing cheap
/// table entries from causing unbounded repeated metadata or code analysis.
struct Budget {
    referenced: usize,
    tlvs: usize,
}

impl Budget {
    fn add(&mut self, size: usize) -> Result<()> {
        self.referenced = self
            .referenced
            .checked_add(size)
            .filter(|&total| total <= MAX_EXTRACTED)
            .ok_or_else(|| {
                error(format!(
                    "Unsupported UARP referenced-byte total; limit {MAX_EXTRACTED} B"
                ))
            })?;
        Ok(())
    }
}

struct MetadataRegion {
    offset: usize,
    size: usize,
    table_offset: usize,
    table_end: usize,
    key: String,
}

/// Validate before arithmetic and reject aliases of the structural headers.
fn content_region(
    data: &[u8],
    offset: usize,
    size: usize,
    table_offset: usize,
    table_end: usize,
) -> Result<&[u8]> {
    let contents = slice(data, offset, size, "content")?;
    if offset < HEADER_SIZE || (offset < table_end && table_offset < offset + size) {
        return Err(error(format!(
            "Invalid UARP content at 0x{offset:X}; overlaps a structural header"
        )));
    }
    Ok(contents)
}

/// Packed TLVs: big-endian type and byte size, then exactly size bytes,
/// with no alignment padding. At most 64 bytes of each value are displayed.
fn metadata(
    c: &mut Container<'_>,
    image: &[u8],
    region: &MetadataRegion,
    budget: &mut Budget,
) -> Result<()> {
    if region.size == 0 {
        return Ok(());
    }
    let contents = content_region(
        image,
        region.offset,
        region.size,
        region.table_offset,
        region.table_end,
    )?;
    budget.add(region.size)?;
    let mut pos = 0;
    let mut index = 0;
    while pos < contents.len() {
        if budget.tlvs >= MAX_TLVS {
            return Err(error(format!(
                "Unsupported UARP TLV count; limit {MAX_TLVS}"
            )));
        }
        slice(contents, pos, TLV_HEADER_SIZE, "TLV header").map_err(|_| {
            error(format!(
                "Truncated UARP TLV header at 0x{:X}",
                region.offset + pos
            ))
        })?;
        let kind = be_u32(contents, pos)?;
        let size = field_size(contents, pos + 4)?;
        let value = slice(contents, pos + TLV_HEADER_SIZE, size, "TLV value").map_err(|_| {
            error(format!(
                "Truncated UARP TLV value at 0x{:X} + {size} B",
                region.offset + pos + TLV_HEADER_SIZE
            ))
        })?;
        let preview = hex::encode_upper(&value[..value.len().min(TLV_PREVIEW_SIZE)]);
        let suffix = if value.len() > TLV_PREVIEW_SIZE {
            "..."
        } else {
            ""
        };
        c.push_metadata(
            format!("{}_tlv_{index}", region.key),
            format!("TLV 0x{kind:08X}"),
            format!(
                "file 0x{:X}; {size} B; {preview}{suffix}",
                region.offset + pos
            ),
        );
        pos += TLV_HEADER_SIZE + size; // slice validated the entire range.
        index += 1;
        budget.tlvs += 1;
    }
    Ok(())
}
