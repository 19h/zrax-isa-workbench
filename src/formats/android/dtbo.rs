//! DTB/DTBO table images (`dtbo.img`, and `dtb.img` on some devices):
//! `struct dt_table_header` and `struct dt_table_entry` of AOSP
//! `platform/system/libufdt` at `9b70f594` (`utils/src/dt_table.h`), with
//! the checks of `utils/src/mkdtboimg.py` and the writer layout of
//! `utils/src/mkdtimg_core.c`.
//!
//! A 32-byte header is followed, at `dt_entries_offset`, by 32-byte
//! entries that each locate one device tree blob by an offset from the
//! start of the header. Version 1 entries carry a compression format in
//! the low four bits of `flags` (none, zlib, gzip). Every field is
//! big-endian (`cpu_to_fdt32`). `mkdtimg` stores a blob once when several
//! entries name the same file, so entries may share a blob.
//!
//! Each blob is a device tree, classified by the device tree parser. The
//! table names no CPU: `id`, `rev` and `custom` are board identifiers.

use super::*;
use std::collections::HashSet;

/// `dt_table_header` and `dt_table_entry` sizes; `mkdtboimg.py` refuses
/// any other `header_size` or `dt_entry_size`.
const DT_TABLE_HEADER_SIZE: usize = 32;
const DT_TABLE_ENTRY_SIZE: usize = 32;

/// Highest `version` (`DT_TABLE_DEFAULT_VERSION` is 0; version 1 adds the
/// compression format to the entry flags).
const DT_TABLE_VERSION_FLAGS: u32 = 1;

/// Low four bits of a version 1 entry's `flags`
/// (`DtEntry.COMPRESSION_FORMAT_MASK`) and their values
/// (`enum dt_compression_info`).
const COMPRESSION_FORMAT_MASK: u32 = 0x0f;
const NO_COMPRESSION: u32 = 0;
const ZLIB_COMPRESSION: u32 = 1;
const GZIP_COMPRESSION: u32 = 2;

/// The header fields after the magic: `total_size` (4), `header_size`
/// (8), `dt_entry_size` (12), `dt_entry_count` (16), `dt_entries_offset`
/// (20), `page_size` (24), `version` (28).
struct Header {
    total_size: usize,
    entry_count: usize,
    entries_offset: usize,
    page_size: u32,
    version: u32,
}

/// One `dt_table_entry`: `dt_size` (0), `dt_offset` (4), `id` (8), `rev`
/// (12), then `custom[4]`, or `flags` and `custom[3]` in version 1.
struct Entry {
    size: usize,
    offset: usize,
    id: u32,
    rev: u32,
    /// `custom[0]` in version 0, `flags` in version 1.
    word4: u32,
    custom: [u32; 3],
}

fn be_usize(data: &[u8], at: usize) -> Result<usize> {
    Ok(be_u32(data, at)? as usize)
}

/// The header, checked against the file: the fixed sizes, the version,
/// and an entry table that lies inside `total_size`.
fn header(data: &[u8]) -> Result<Header> {
    let bytes = slice(data, 0, DT_TABLE_HEADER_SIZE, "DTBO table header")?;
    if be_u32(bytes, 0)? != DT_TABLE_MAGIC {
        return Err(error("Missing DTBO table magic"));
    }
    let header_size = be_usize(bytes, 8)?;
    if header_size != DT_TABLE_HEADER_SIZE {
        return Err(error(format!(
            "Unsupported DTBO table header_size {header_size} B"
        )));
    }
    let entry_size = be_usize(bytes, 12)?;
    if entry_size != DT_TABLE_ENTRY_SIZE {
        return Err(error(format!(
            "Unsupported DTBO table dt_entry_size {entry_size} B"
        )));
    }
    let header = Header {
        total_size: be_usize(bytes, 4)?,
        entry_count: be_usize(bytes, 16)?,
        entries_offset: be_usize(bytes, 20)?,
        page_size: be_u32(bytes, 24)?,
        version: be_u32(bytes, 28)?,
    };
    if header.version > DT_TABLE_VERSION_FLAGS {
        return Err(error(format!(
            "Unsupported DTBO table version {}",
            header.version
        )));
    }
    if header.total_size > data.len() {
        return Err(error(format!(
            "Truncated DTBO table: total_size {} B, {} B in the file",
            header.total_size,
            data.len()
        )));
    }
    if header.entries_offset < DT_TABLE_HEADER_SIZE {
        return Err(error(format!(
            "Invalid DTBO table dt_entries_offset 0x{:X} inside the header",
            header.entries_offset
        )));
    }
    let room = header.total_size.saturating_sub(header.entries_offset) / DT_TABLE_ENTRY_SIZE;
    if header.entries_offset > header.total_size || header.entry_count > room {
        return Err(error(format!(
            "Invalid DTBO table: {} entries at 0x{:X} do not fit in total_size {} B",
            header.entry_count, header.entries_offset, header.total_size
        )));
    }
    Ok(header)
}

/// Entry `index`, whose blob must lie after the entry table and inside
/// `total_size`.
fn entry(data: &[u8], header: &Header, index: usize) -> Result<Entry> {
    let at = header.entries_offset + index * DT_TABLE_ENTRY_SIZE;
    let bytes = slice(data, at, DT_TABLE_ENTRY_SIZE, "DTBO table entry")?;
    let entry = Entry {
        size: be_usize(bytes, 0)?,
        offset: be_usize(bytes, 4)?,
        id: be_u32(bytes, 8)?,
        rev: be_u32(bytes, 12)?,
        word4: be_u32(bytes, 16)?,
        custom: [be_u32(bytes, 20)?, be_u32(bytes, 24)?, be_u32(bytes, 28)?],
    };
    let table_end = header.entries_offset + header.entry_count * DT_TABLE_ENTRY_SIZE;
    let end = entry.offset.checked_add(entry.size);
    if entry.offset < table_end || end.map_or(true, |end| end > header.total_size) {
        return Err(error(format!(
            "Invalid DTBO table entry {index} at 0x{at:X}: blob 0x{:X} + {} B outside 0x{table_end:X}..0x{:X}",
            entry.offset, entry.size, header.total_size
        )));
    }
    Ok(entry)
}

impl Entry {
    /// The compression format: always none before version 1.
    fn compression(&self, version: u32) -> u32 {
        if version >= DT_TABLE_VERSION_FLAGS {
            self.word4 & COMPRESSION_FORMAT_MASK
        } else {
            NO_COMPRESSION
        }
    }

    /// `id 0x..; rev 0x..; custom ...`, in the version's field names.
    fn fields(&self, version: u32) -> String {
        let custom = if version >= DT_TABLE_VERSION_FLAGS {
            format!(
                "flags 0x{:X}; custom 0x{:X} 0x{:X} 0x{:X}",
                self.word4, self.custom[0], self.custom[1], self.custom[2]
            )
        } else {
            format!(
                "custom 0x{:X} 0x{:X} 0x{:X} 0x{:X}",
                self.word4, self.custom[0], self.custom[1], self.custom[2]
            )
        };
        format!("id 0x{:X}; rev 0x{:X}; {custom}", self.id, self.rev)
    }
}

/// The codec of a compression format, if it is one `mkdtboimg.py` writes.
fn compression_codec(format: u32) -> Option<Codec> {
    match format {
        ZLIB_COMPRESSION => Some(Codec::Zlib),
        GZIP_COMPRESSION => Some(Codec::Gzip),
        _ => None,
    }
}

/// Parse a DTB/DTBO table image into one component per distinct blob.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = header(data)?;
    let mut c = Container::new(
        FileFormat::AndroidDtbo,
        format!("DTBO table v{}", header.version),
        KEY_PREFIX,
    );
    c.consumed = header.total_size;
    c.notes.push(format!(
        "DTBO table version {}: {}; page size {} B; total size {} B",
        header.version,
        counted(header.entry_count, "entry", "entries"),
        header.page_size,
        header.total_size
    ));
    c.push_metadata(
        "android_dtbo_version",
        "DTBO table version",
        u64::from(header.version),
    );
    c.push_metadata(
        "android_dtbo_entry_count",
        "Entries",
        header.entry_count as u64,
    );
    c.push_metadata(
        "android_dtbo_page_size",
        "Page size (B)",
        u64::from(header.page_size),
    );
    let mut budget = Budget::new();
    // The blobs listed so far, by offset and size.
    let mut listed: HashSet<(usize, usize)> = HashSet::new();
    let mut shared = 0usize;
    for index in 0..header.entry_count {
        let entry = entry(data, &header, index)?;
        let compression = entry.compression(header.version);
        c.push_metadata(
            format!("android_dtbo_entry_{index}"),
            format!("Entry {index}"),
            format!(
                "file 0x{:X}; {} B; {}",
                entry.offset,
                entry.size,
                entry.fields(header.version)
            ),
        );
        if !listed.insert((entry.offset, entry.size)) {
            shared += 1;
            continue;
        }
        if is_component_limit(c.children.len(), header.entry_count, &mut c.notes) {
            break;
        }
        let label = format!(
            "DT entry {index} (id 0x{:X}, rev 0x{:X})",
            entry.id, entry.rev
        );
        let stored = &data[entry.offset..entry.offset + entry.size];
        c.children.push(blob_child(
            label,
            &entry,
            stored,
            compression,
            &mut budget,
            &mut c.notes,
        ));
    }
    if shared > 0 {
        c.notes.push(format!(
            "{} the blob of an earlier entry; shared blobs are listed once",
            counted(shared, "entry shares", "entries share")
        ));
    }
    c.notes.push(
        "The table names no CPU (id, rev and custom fields identify boards); each blob is classified on its own"
            .into(),
    );
    push_unexplained_tail(&mut c, data, header.total_size);
    Ok(c)
}

/// The component for one blob: a stored or decoded device tree, or an
/// opaque blob when it is not one.
fn blob_child<'a>(
    label: String,
    entry: &Entry,
    stored: &'a [u8],
    compression: u32,
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> Child<'a> {
    if compression == NO_COMPRESSION {
        if !stored.starts_with(&FDT_MAGIC) {
            notes.push(format!(
                "{label}: does not start with a device tree header; kept opaque"
            ));
            return Child::opaque(label, entry.offset, stored);
        }
        return Child::stored(label, entry.offset, stored);
    }
    let Some(codec) = compression_codec(compression) else {
        notes.push(format!(
            "{label}: unknown compression format {compression}; kept opaque"
        ));
        return Child::opaque(label, entry.offset, stored);
    };
    match compressed::decode_limited(codec, stored, budget.limit()) {
        Ok(decoded) => {
            budget.spend(decoded.data.len());
            notes.push(decoded_note(&label, codec, stored, &decoded));
            Child::decoded(
                label,
                entry.offset,
                stored.len(),
                Cow::Owned(decoded.data),
                codec.name(),
            )
        }
        Err(e) => {
            notes.push(format!(
                "{label}: blob does not decode as {} ({e}); kept opaque",
                codec.name()
            ));
            Child::opaque(label, entry.offset, stored)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_1_entries_carry_the_compression_format_in_their_flags() {
        let entry = Entry {
            size: 0,
            offset: 0,
            id: 0,
            rev: 0,
            word4: 0x12,
            custom: [0; 3],
        };
        assert_eq!(entry.compression(0), NO_COMPRESSION);
        assert_eq!(entry.compression(1), GZIP_COMPRESSION);
        assert_eq!(compression_codec(ZLIB_COMPRESSION), Some(Codec::Zlib));
        assert_eq!(compression_codec(3), None);
        assert!(entry.fields(1).contains("flags 0x12"));
        assert!(entry.fields(0).contains("custom 0x12"));
    }
}
