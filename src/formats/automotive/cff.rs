//! Mercedes-Benz CFF (Caesar flash file) containers.
//!
//! Daimler publishes no specification. The layout follows the community
//! reconstruction `CaesarSuite` at commit `f8e8463f`
//! (`Caesar/Caesar/Flash/CaesarFlashContainer.cs`, `FlashHeader.cs`,
//! `FlashDataBlock.cs`, `FlashSegment.cs`, `CaesarReader.cs`): a 0x410-byte
//! stub, the header size (i32 at 0x410), the flash header at 0x414, and a
//! CRC-32 over everything before the last four bytes (reflected polynomial,
//! initial value all ones, no final XOR), all little-endian. Structures are
//! bit-flag records: a flag word whose bits, least significant first, say
//! whether each field is present; strings are offsets from the structure's
//! base to NUL-terminated text, tables are offsets to arrays of offsets.
//! Segment data sits at `0x414 + header size + language block length +
//! FlashData`, segments of one data block back to back. `CaesarSuite` notes
//! that this assumes embedded, unprotected segments; the file has no magic,
//! so recognition needs the checksum and a consistent header.

use super::*;

/// Size of the stub before the header-size field.
const STUB_SIZE: usize = 0x410;

/// Base of the flash header and of its relative offsets.
const HEADER_BASE: usize = 0x414;

/// Longest string read from a bit-flag record.
const MAX_STRING: usize = 4096;

/// A bit-flag record reader.
struct Fields<'a> {
    data: &'a [u8],
    pos: usize,
    flags: u64,
    base: usize,
}

impl<'a> Fields<'a> {
    /// A record at `base` whose flag word is `flag_bytes` (2 or 4) long,
    /// followed by `skip` unused bytes.
    fn new(data: &'a [u8], base: usize, flag_bytes: usize, skip: usize) -> Result<Self> {
        let flags = match flag_bytes {
            2 => u64::from(le_u16(data, base)?),
            _ => u64::from(le_u32(data, base)?),
        };
        Ok(Self {
            data,
            pos: base + flag_bytes + skip,
            flags,
            base,
        })
    }

    fn present(&mut self) -> bool {
        let set = self.flags & 1 != 0;
        self.flags >>= 1;
        set
    }

    fn i32(&mut self) -> Result<i32> {
        if !self.present() {
            return Ok(0);
        }
        let value = le_u32(self.data, self.pos)?;
        self.pos += 4;
        Ok(i32::from_le_bytes(value.to_le_bytes()))
    }

    fn i16(&mut self) -> Result<i16> {
        if !self.present() {
            return Ok(0);
        }
        let value = le_u16(self.data, self.pos)?;
        self.pos += 2;
        Ok(i16::from_le_bytes(value.to_le_bytes()))
    }

    fn u8(&mut self) -> Result<u8> {
        if !self.present() {
            return Ok(0);
        }
        let value = *slice(self.data, self.pos, 1)?.first().expect("one byte");
        self.pos += 1;
        Ok(value)
    }

    fn string(&mut self) -> Result<Option<String>> {
        if !self.present() {
            return Ok(None);
        }
        let offset = le_u32(self.data, self.pos)?;
        self.pos += 4;
        let at = relative(self.base, offset)?;
        let rest = self
            .data
            .get(at..)
            .ok_or_else(|| error(format!("Invalid CFF string offset 0x{at:X}")))?;
        let window = &rest[..rest.len().min(MAX_STRING)];
        let len = memchr::memchr(0, window)
            .ok_or_else(|| error(format!("Unterminated CFF string at 0x{at:X}")))?;
        Ok(Some(String::from_utf8_lossy(&window[..len]).into_owned()))
    }
}

/// `base + offset` for a signed 32-bit file offset.
fn relative(base: usize, offset: u32) -> Result<usize> {
    let offset = i64::from(i32::from_le_bytes(offset.to_le_bytes()));
    i64::try_from(base)
        .ok()
        .and_then(|base| base.checked_add(offset))
        .and_then(|at| usize::try_from(at).ok())
        .ok_or_else(|| error("Invalid CFF offset"))
}

/// A non-negative count or length.
fn count(value: i32, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid CFF {what} {value}")))
}

/// Entry `index` of the offset table at `base + table`.
fn table_entry(data: &[u8], base: usize, table: i32, index: usize) -> Result<usize> {
    let table_at = relative(base, u32::from_le_bytes(table.to_le_bytes()))?;
    let entry = le_u32(data, table_at + index * 4)?;
    relative(table_at, entry)
}

/// The fields of the flash header that locate data.
struct FlashHeader {
    header_size: usize,
    language_block_length: usize,
    data_block_count: usize,
    data_block_table: i32,
    names: Vec<(&'static str, String)>,
}

fn flash_header(data: &[u8]) -> Result<FlashHeader> {
    let header_size = count(
        i32::from_le_bytes(le_u32(data, STUB_SIZE)?.to_le_bytes()),
        "header size",
    )?;
    if HEADER_BASE
        .checked_add(header_size)
        .map_or(true, |end| end > data.len())
    {
        return Err(error(format!("Invalid CFF header size {header_size} B")));
    }
    let mut f = Fields::new(data, HEADER_BASE, 4, 2)?;
    let mut names = Vec::new();
    let mut named = |label: &'static str, value: Option<String>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            names.push((label, value));
        }
    };
    named("Flash name", f.string()?);
    named("Generation parameters", f.string()?);
    f.i32()?;
    f.i32()?;
    named("Author", f.string()?);
    named("Created", f.string()?);
    named("Authoring tool", f.string()?);
    named("FTRAFO version", f.string()?);
    f.i32()?;
    named("CFF version", f.string()?);
    let _flash_areas = f.i32()?;
    let _description_table = f.i32()?;
    let data_block_count = count(f.i32()?, "data block count")?;
    let data_block_table = f.i32()?;
    let _ctf_table = f.i32()?;
    let language_block_length = count(f.i32()?, "language block length")?;
    f.i32()?;
    f.i32()?;
    f.i32()?;
    f.i32()?;
    f.u8()?;
    if data_block_count > data.len() / 4 {
        return Err(error(format!(
            "Invalid CFF data block count {data_block_count}"
        )));
    }
    Ok(FlashHeader {
        header_size,
        language_block_length,
        data_block_count,
        data_block_table,
        names,
    })
}

/// A flash data block's fields that locate and describe its segments.
struct DataBlock {
    qualifier: String,
    flash_data: usize,
    segments: Vec<(u32, usize, String)>,
    encrypted: bool,
    secured: bool,
}

fn data_block(data: &[u8], base: usize) -> Result<DataBlock> {
    let mut f = Fields::new(data, base, 4, 2)?;
    let qualifier = f.string()?.unwrap_or_else(|| "unnamed".into());
    f.i32()?; // long name
    f.i32()?; // description
    let flash_data = count(f.i32()?, "flash data offset")?;
    f.i32()?; // block length
    f.i32()?; // data format
    f.i32()?; // file name
    f.i32()?; // filter count
    f.i32()?; // filter table
    let segment_count = count(f.i32()?, "segment count")?;
    let segment_table = f.i32()?;
    let encryption_mode = f.i16()?;
    f.i32()?; // key length
    f.i32()?; // key buffer
    f.i32()?; // own ident count
    f.i32()?; // own ident table
    let security_count = count(f.i32()?, "security count")?;
    if segment_count > MAX_COMPONENTS {
        return Err(error(format!("Invalid CFF segment count {segment_count}")));
    }
    let mut segments = Vec::with_capacity(segment_count);
    for index in 0..segment_count {
        let at = table_entry(data, base, segment_table, index)?;
        let mut s = Fields::new(data, at, 2, 0)?;
        let address = u32::from_le_bytes(s.i32()?.to_le_bytes());
        let length = count(s.i32()?, "segment length")?;
        s.i32()?;
        let name = s.string()?.unwrap_or_default();
        segments.push((address, length, name));
    }
    Ok(DataBlock {
        qualifier,
        flash_data,
        segments,
        encrypted: encryption_mode != 0,
        secured: security_count > 0,
    })
}

/// The stored CRC-32 (no final XOR) of everything before the last four bytes.
fn checksum_matches(data: &[u8]) -> bool {
    let Some(body_end) = data.len().checked_sub(4) else {
        return false;
    };
    let computed = crate::formats::checksum::crc32_update(!0, &data[..body_end]);
    data[body_end..] == computed.to_le_bytes()
}

/// Weak recognition: the checksum and a parseable header.
pub(super) fn is_cff(data: &[u8]) -> bool {
    data.len() > HEADER_BASE + 8 && checksum_matches(data) && flash_header(data).is_ok()
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() <= HEADER_BASE + 8 {
        return Err(error(format!("Truncated CFF file: {} B", data.len())));
    }
    if !checksum_matches(data) {
        return Err(error("Invalid CFF file CRC-32"));
    }
    let header = flash_header(data)?;
    let mut c = Container::new(FileFormat::MercedesCff, "Caesar flash file", "cff");
    c.consumed = data.len();
    c.notes.push(
        "Mercedes-Benz CFF flash container; file CRC-32 verified; layout from community reverse engineering"
            .into(),
    );
    for (label, value) in &header.names {
        c.notes.push(format!("{label}: {value}"));
    }
    let data_base = HEADER_BASE + header.header_size + header.language_block_length;
    for index in 0..header.data_block_count {
        let at = table_entry(data, HEADER_BASE, header.data_block_table, index)?;
        let block = data_block(data, at)?;
        let mut cursor = data_base
            .checked_add(block.flash_data)
            .ok_or_else(|| error("Invalid CFF flash data offset"))?;
        for (address, length, name) in &block.segments {
            let stored = slice(data, cursor, *length).map_err(|_| {
                error(format!(
                    "Truncated CFF segment {name} of {}: 0x{cursor:X} + {length} B",
                    block.qualifier
                ))
            })?;
            let label = format!("{} {name} at 0x{address:08X}", block.qualifier);
            c.children.push(if block.encrypted {
                Child::opaque(label, cursor, stored)
            } else {
                Child::stored(label, cursor, stored)
            });
            cursor += length;
            if c.children.len() >= MAX_COMPONENTS {
                break;
            }
        }
        if block.encrypted {
            c.notes.push(format!(
                "{}: encrypted data block; segments not analyzed",
                block.qualifier
            ));
        }
        if block.secured {
            c.notes.push(format!(
                "{}: signatures or checksums present but not verified",
                block.qualifier
            ));
        }
    }
    c.notes
        .push("No CFF field names a CPU; ISA from the segment data".into());
    Ok(c)
}
