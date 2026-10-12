//! Nintendo 3DS homebrew `3DSX` executables (3dbrew "3DSX Format" oldid
//! 14592; devkitPro 3dstools `src/3dsx.h` and `src/3dsxtool.cpp` at
//! `718d6f23`; `Luma3DS` `sysmodules/loader/source/3dsx.c` at `aef31308`).
//!
//! All fields are little-endian: magic, header size (2), relocation header
//! size (2), format version (4), flags (4), then the code, read-only data,
//! data (including BSS) and BSS sizes (4 each); the extended header adds the
//! SMDH offset and size and the `RomFS` offset. Three relocation headers
//! (absolute and relative entry counts) follow the header, then the code,
//! read-only data and data segments (data without BSS), the relocation
//! tables (4 bytes per entry), and the SMDH and `RomFS`. Segments are loaded
//! page-aligned and back to back; the entry point is the start of the code
//! segment.

use super::*;

/// `3DSX` magic.
const MAGIC: &[u8; 4] = b"3DSX";

/// `3DSX` header sizes without and with the extended header.
const BASIC_HEADER_SIZE: usize = 32;
const EXTENDED_HEADER_SIZE: usize = 44;

/// `3DSX` header fields.
const HEADER_SIZE_FIELD: usize = 4;
const RELOC_HEADER_SIZE_FIELD: usize = 6;
const FORMAT_VERSION: usize = 8;
const CODE_SIZE: usize = 0x10;
const RODATA_SIZE: usize = 0x14;
const DATA_SIZE: usize = 0x18;
const BSS_SIZE: usize = 0x1c;
const SMDH_OFFSET: usize = 0x20;
const SMDH_SIZE: usize = 0x24;
const ROMFS_OFFSET: usize = 0x28;

/// A relocation header holds two counts (absolute, relative); `Luma3DS`
/// requires the three headers to fit in one page
/// (`3 * 4 * (relocHdrSize / 4) <= 0x1000`).
const RELOC_COUNTS_SIZE: usize = 8;
const RELOC_HEADER_COUNT: usize = 3;
const RELOC_HEADERS_LIMIT: usize = 0x1000;

/// A relocation entry: skip and patch counts (2 bytes each).
const RELOC_ENTRY_SIZE: usize = 4;

/// Strong recognition: `3DSX` at offset 0.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// The `3DSX` header fields this parser uses; sizes in bytes.
struct FileHeader {
    header_size: usize,
    reloc_header_size: usize,
    format_version: u32,
    code_size: usize,
    rodata_size: usize,
    data_size: usize,
    bss_size: usize,
    extended: Option<Extended>,
}

/// The extended header: SMDH range and `RomFS` offset (file offsets).
struct Extended {
    smdh_offset: usize,
    smdh_size: usize,
    romfs_offset: usize,
}

fn read_header(data: &[u8]) -> Result<FileHeader> {
    if data.len() < BASIC_HEADER_SIZE {
        return Err(error(format!(
            "Truncated 3DSX header: {} B of {BASIC_HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing 3DSX magic"));
    }
    let header_size = usize::from(le_u16(data, HEADER_SIZE_FIELD)?);
    if header_size != BASIC_HEADER_SIZE && header_size != EXTENDED_HEADER_SIZE {
        return Err(error(format!(
            "Unsupported 3DSX header size {header_size} B"
        )));
    }
    let reloc_header_size = usize::from(le_u16(data, RELOC_HEADER_SIZE_FIELD)?);
    let reloc_headers_size = RELOC_HEADER_COUNT * 4 * (reloc_header_size / 4);
    if reloc_header_size < RELOC_COUNTS_SIZE || reloc_headers_size > RELOC_HEADERS_LIMIT {
        return Err(error(format!(
            "Invalid 3DSX relocation header size {reloc_header_size} B"
        )));
    }
    let data_size = le_usize(data, DATA_SIZE, "3DSX data size")?;
    let bss_size = le_usize(data, BSS_SIZE, "3DSX BSS size")?;
    if bss_size > data_size {
        return Err(error(format!(
            "Invalid 3DSX BSS size {bss_size} B: the data segment is {data_size} B"
        )));
    }
    let extended = if header_size == EXTENDED_HEADER_SIZE {
        Some(Extended {
            smdh_offset: le_usize(data, SMDH_OFFSET, "SMDH offset")?,
            smdh_size: le_usize(data, SMDH_SIZE, "SMDH size")?,
            romfs_offset: le_usize(data, ROMFS_OFFSET, "RomFS offset")?,
        })
    } else {
        None
    };
    Ok(FileHeader {
        header_size,
        reloc_header_size,
        format_version: le_u32(data, FORMAT_VERSION)?,
        code_size: le_usize(data, CODE_SIZE, "3DSX code size")?,
        rodata_size: le_usize(data, RODATA_SIZE, "3DSX read-only data size")?,
        data_size,
        bss_size,
        extended,
    })
}

/// A stored range in the file, or a truncation error naming it.
fn file_range(data: &[u8], offset: usize, size: usize, what: &str) -> Result<Region> {
    match offset.checked_add(size) {
        Some(end) if end <= data.len() => Ok(Region { offset, size }),
        _ => Err(error(format!(
            "Truncated 3DSX {what} at 0x{offset:X} + {size} B"
        ))),
    }
}

/// Relocation counts summed over the three relocation headers.
struct Relocations {
    absolute: usize,
    relative: usize,
}

/// The three relocation headers after the `3DSX` header.
fn relocations(data: &[u8], header: &FileHeader) -> Result<Relocations> {
    let mut counts = Relocations {
        absolute: 0,
        relative: 0,
    };
    for segment in 0..RELOC_HEADER_COUNT {
        let at = header.header_size + segment * header.reloc_header_size;
        let reloc_header = slice(data, at, RELOC_COUNTS_SIZE)
            .map_err(|_| error(format!("Truncated 3DSX relocation header at 0x{at:X}")))?;
        let absolute = le_usize(reloc_header, 0, "3DSX relocation count")?;
        let relative = le_usize(reloc_header, 4, "3DSX relocation count")?;
        counts.absolute = counts
            .absolute
            .checked_add(absolute)
            .ok_or_else(|| error("Invalid 3DSX relocation count"))?;
        counts.relative = counts
            .relative
            .checked_add(relative)
            .ok_or_else(|| error("Invalid 3DSX relocation count"))?;
    }
    Ok(counts)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = read_header(data)?;
    let counts = relocations(data, &header)?;
    let code_at = header.header_size + RELOC_HEADER_COUNT * header.reloc_header_size;
    let code = file_range(data, code_at, header.code_size, "code segment")?;
    let rodata = file_range(
        data,
        code.end(),
        header.rodata_size,
        "read-only data segment",
    )?;
    let stored_data_size = header.data_size - header.bss_size;
    let data_segment = file_range(data, rodata.end(), stored_data_size, "data segment")?;
    let reloc_size = counts
        .absolute
        .checked_add(counts.relative)
        .and_then(|entries| entries.checked_mul(RELOC_ENTRY_SIZE))
        .ok_or_else(|| error("Invalid 3DSX relocation count"))?;
    let reloc_tables = file_range(data, data_segment.end(), reloc_size, "relocation tables")?;

    let mut c = Container::new(FileFormat::N3ds3dsx, ARM11_VARIANT, "n3ds");
    c.target = Some(ARM11);
    c.notes.push(format!(
        "3DSX homebrew executable (format version {}); code {}, read-only data {}, data {} including {} BSS; {} absolute and {} relative relocations",
        header.format_version,
        size_text(header.code_size),
        size_text(header.rodata_size),
        size_text(header.data_size),
        size_text(header.bss_size),
        counts.absolute,
        counts.relative
    ));
    c.notes.push(
        "Segments are page-aligned and loaded back to back from a base the header does not record; the entry point is the start of the code segment"
            .to_string(),
    );
    c.consumed = match &header.extended {
        Some(extended) => push_extended(&mut c, data, extended, reloc_tables.end())?,
        None => reloc_tables.end(),
    };
    let trailing = &data[c.consumed..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the 3DSX image at 0x{:X}",
            size_text(trailing.len()),
            c.consumed
        )));
    }
    c.notes.push(ARM11_NOTE.to_string());
    c.push_metadata(
        "n3ds_code_size",
        "Code segment size (B)",
        header.code_size as u64,
    );
    if code.size > 0 {
        c.children.push(
            Child::stored("Code segment", code.offset, &data[code.offset..code.end()])
                .with_target(ARM11),
        );
    }
    let data_regions = [
        ("Read-only data segment", rodata),
        ("Data segment", data_segment),
    ];
    for (label, region) in data_regions {
        if region.size > 0 {
            c.children.push(Child::opaque(
                label,
                region.offset,
                &data[region.offset..region.end()],
            ));
        }
    }
    c.children.sort_by_key(|child| child.offset);
    Ok(c)
}

/// The SMDH and `RomFS` of an extended header, as data. Returns where the
/// image ends: the end of the file when a `RomFS` is present, otherwise the
/// end of the last structure. A `RomFS` offset before that end, or at the
/// end of the file, means there is no `RomFS` (an offset of 0 for a missing
/// `RomFS` is this parser's reading of 3dsxtool, not a documented value).
fn push_extended<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    extended: &Extended,
    tables_end: usize,
) -> Result<usize> {
    let smdh = file_range(data, extended.smdh_offset, extended.smdh_size, "SMDH")?;
    let mut end = tables_end;
    if smdh.size > 0 {
        c.children.push(Child::opaque(
            "SMDH",
            smdh.offset,
            &data[smdh.offset..smdh.end()],
        ));
        end = end.max(smdh.end());
    }
    let romfs_offset = extended.romfs_offset;
    if romfs_offset > data.len() {
        return Err(error(format!(
            "Truncated 3DSX RomFS at 0x{romfs_offset:X}: file {} B",
            data.len()
        )));
    }
    if romfs_offset < end || romfs_offset == data.len() {
        return Ok(end);
    }
    c.children
        .push(Child::opaque("RomFS", romfs_offset, &data[romfs_offset..]));
    c.notes
        .push("RomFS is listed but its file system is not parsed".to_string());
    Ok(data.len())
}
