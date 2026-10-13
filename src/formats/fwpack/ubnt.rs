//! Ubiquiti firmware images.
//!
//! Layout (`OpenWrt` firmware-utils `src/fw.h`, written by `mkfwimage.c` and
//! `mkfwimage2.c`), all integers big-endian:
//! - header (268 B): magic (4), version string (256, NUL-padded), CRC-32
//!   of the magic and version (4), zero pad (4);
//! - records: `PART` (56-byte header: magic, name (16), pad (12), memory
//!   address, index, flash base address, entry address, data size and
//!   partition size, 4 B each), the data, then the CRC-32 of the header and
//!   data (4) and a zero pad (4);
//! - an end record: `END.`, the CRC-32 of every byte before it (4) and a
//!   zero pad (4); or `ENDS`, a 256-byte RSA signature and a zero pad.
//!
//! `mkfwimage` writes `OPEN` unless `-m` names another magic; binwalk
//! v2.3.4 `src/binwalk/magic/firmware` lists `UBNT` and `GEOS` as Ubiquiti
//! header magics, `EXEC` records ("additional data") laid out as `PART`
//! records, and `ENDS` ("RSA 2048 bit"). Every CRC is zlib `crc32` (CRC-32
//! ISO-HDLC).

use super::*;
use crate::formats::checksum;

/// Header magics: the `mkfwimage` default and the two binwalk lists for
/// Ubiquiti's own images.
const HEADER_MAGICS: [&[u8; 4]; 3] = [b"OPEN", b"UBNT", b"GEOS"];

/// `header_t`: magic, version, CRC, pad.
const HEADER_SIZE: usize = 268;
const VERSION_OFFSET: usize = 4;
const VERSION_SIZE: usize = 256;
const HEADER_CRC: usize = 260;
const HEADER_PAD: usize = 264;

/// Record magics (`fw.h` `MAGIC_PART`, `MAGIC_END`, `MAGIC_ENDS`; binwalk
/// `EXEC`).
const PART_MAGIC: &[u8; 4] = b"PART";
const EXEC_MAGIC: &[u8; 4] = b"EXEC";
const END_MAGIC: &[u8; 4] = b"END.";
const ENDS_MAGIC: &[u8; 4] = b"ENDS";
const MAGIC_SIZE: usize = 4;

/// `part_t` fields.
const PART_HEADER_SIZE: usize = 56;
const PART_NAME: usize = 4;
const PART_NAME_SIZE: usize = 16;
const PART_MEMORY_ADDRESS: usize = 32;
const PART_INDEX: usize = 36;
const PART_BASE_ADDRESS: usize = 40;
const PART_ENTRY_ADDRESS: usize = 44;
const PART_DATA_SIZE: usize = 48;
const PART_SIZE: usize = 52;

/// `part_crc_t`: CRC and pad after the data.
const PART_CRC_SIZE: usize = 8;

/// `signature_t`: magic, CRC, pad.
const END_SIZE: usize = 12;
const END_CRC: usize = 4;
const END_PAD: usize = 8;

/// `signature_rsa_t`: magic, RSA signature, pad.
const ENDS_SIZE: usize = 264;
const RSA_SIGNATURE_SIZE: usize = 256;
const ENDS_PAD: usize = 260;

/// Most records one image may hold; `mkfwimage` writes at most eight
/// partitions (`MAX_SECTIONS`).
const MAX_RECORDS: usize = MAX_COMPONENTS;

/// A header magic at 0 and the `PART` magic of the first record right
/// after the header: two 32-bit keys, so ASCII text that starts with
/// `OPEN` is not taken for an image.
pub(super) fn detect(data: &[u8]) -> bool {
    let (Some(magic), Some(first)) = (
        data.get(..MAGIC_SIZE),
        data.get(HEADER_SIZE..HEADER_SIZE + MAGIC_SIZE),
    ) else {
        return false;
    };
    HEADER_MAGICS.iter().any(|m| magic == m.as_slice()) && first == PART_MAGIC
}

/// Parse a Ubiquiti image: verify the header CRC, every record CRC and
/// the end CRC, and list the partitions as components.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, HEADER_SIZE, "Ubiquiti header")?;
    let magic = &header[..MAGIC_SIZE];
    if !HEADER_MAGICS.iter().any(|m| magic == m.as_slice()) {
        return Err(error(format!(
            "Invalid Ubiquiti header magic {}",
            display_text(magic)
        )));
    }
    let stored = be_u32(header, HEADER_CRC)?;
    let computed = checksum::crc32(&header[..HEADER_CRC]);
    if stored != computed {
        return Err(error(format!(
            "Invalid Ubiquiti header CRC-32: stored 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    let pad = be_u32(header, HEADER_PAD)?;
    if pad != 0 {
        return Err(error(format!(
            "Invalid Ubiquiti header pad 0x{pad:08X}: must be zero"
        )));
    }
    let version = display_text(until_nul(
        &header[VERSION_OFFSET..VERSION_OFFSET + VERSION_SIZE],
    ));
    let mut c = Container::new(
        FileFormat::UbiquitiFw,
        Layout::UbiquitiFirmware.label(),
        "ubnt",
    );
    c.notes.push(format!(
        "Ubiquiti firmware image: header magic {}; version {version}; header CRC-32 verified",
        display_text(magic)
    ));
    c.push_metadata("ubnt_magic", "Header magic", display_text(magic));
    c.push_metadata("ubnt_version", "Version", version);

    let end = records(data, &mut c)?;
    expect_padding(data, end, "Ubiquiti image")?;
    c.consumed = end;
    Ok(c)
}

/// Walk the records after the header up to and including the end record.
/// Returns the file offset just past the end record.
fn records<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<usize> {
    let mut pos = HEADER_SIZE;
    let mut record_count = 0usize;
    for _ in 0..MAX_RECORDS {
        let magic = slice(data, pos, MAGIC_SIZE, "Ubiquiti record magic")?;
        match <&[u8; 4]>::try_from(magic).expect("slice has exactly 4 bytes") {
            PART_MAGIC | EXEC_MAGIC => {
                let record = record(data, pos)?;
                pos = record.end;
                record_count += 1;
                push_record(c, &record);
            }
            END_MAGIC => return end_record(data, pos, record_count, c),
            ENDS_MAGIC => return signed_end_record(data, pos, record_count, c),
            _ => {
                return Err(error(format!(
                    "Unknown Ubiquiti record magic {} at 0x{pos:X}",
                    display_text(magic)
                )))
            }
        }
    }
    Err(error(format!(
        "Unsupported Ubiquiti image: more than {MAX_RECORDS} records"
    )))
}

/// A `PART` or `EXEC` record whose CRC-32 matched.
#[derive(Debug)]
struct Record<'a> {
    /// `PART` or `EXEC`.
    exec: bool,
    name: String,
    index: u32,
    memory_address: u32,
    base_address: u32,
    entry_address: u32,
    /// Flash space the partition reserves, in bytes.
    partition_size: u32,
    /// File offset of the data.
    offset: usize,
    contents: &'a [u8],
    /// File offset just past the record's CRC and pad.
    end: usize,
}

/// The record at `pos`: its header, data and CRC-32, checked.
fn record(data: &[u8], pos: usize) -> Result<Record<'_>> {
    let header = slice(data, pos, PART_HEADER_SIZE, "Ubiquiti partition header")?;
    let exec = header[..MAGIC_SIZE] == *EXEC_MAGIC;
    let data_size = to_usize(be_u32(header, PART_DATA_SIZE)?);
    let name = display_text(until_nul(&header[PART_NAME..PART_NAME + PART_NAME_SIZE]));
    let offset = pos + PART_HEADER_SIZE;
    let contents = slice(data, offset, data_size, "Ubiquiti partition data")?;
    let crc_at = offset + data_size;
    let trailer = slice(data, crc_at, PART_CRC_SIZE, "Ubiquiti partition CRC")?;
    let stored = be_u32(trailer, 0)?;
    let computed = checksum::crc32(&data[pos..crc_at]);
    if stored != computed {
        return Err(error(format!(
            "Invalid CRC-32 of Ubiquiti partition {name} at 0x{pos:X}: stored 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(Record {
        exec,
        name,
        index: be_u32(header, PART_INDEX)?,
        memory_address: be_u32(header, PART_MEMORY_ADDRESS)?,
        base_address: be_u32(header, PART_BASE_ADDRESS)?,
        entry_address: be_u32(header, PART_ENTRY_ADDRESS)?,
        partition_size: be_u32(header, PART_SIZE)?,
        offset,
        contents,
        end: crc_at + PART_CRC_SIZE,
    })
}

/// List a record as a component with a note. `PART` data is a firmware
/// component classified from its own bytes; `EXEC` data has no documented
/// meaning and is opaque. Empty records are only noted.
fn push_record<'a>(c: &mut Container<'a>, record: &Record<'a>) {
    let kind = if record.exec {
        "additional data"
    } else {
        "partition"
    };
    let label = if record.name.is_empty() {
        format!("Partition {}", record.index)
    } else {
        record.name.clone()
    };
    let mut note = format!(
        "{label}: {kind} {}, {} of a {} partition at flash base 0x{:08X}; load address 0x{:08X}; entry 0x{:08X}; CRC-32 verified",
        record.index,
        size_text(record.contents.len()),
        size_text(to_usize(record.partition_size)),
        record.base_address,
        record.memory_address,
        record.entry_address
    );
    if record.contents.len() > to_usize(record.partition_size) {
        note.push_str("; the data is larger than the partition");
    }
    c.notes.push(note);
    if record.contents.is_empty() {
        return;
    }
    let child = if record.exec {
        Child::opaque(label, record.offset, record.contents)
    } else {
        Child::stored(label, record.offset, record.contents)
    };
    c.children.push(child);
}

/// The `END.` record at `pos`: the CRC-32 of the image before it and a zero
/// pad. Returns the offset just past it.
fn end_record(
    data: &[u8],
    pos: usize,
    record_count: usize,
    c: &mut Container<'_>,
) -> Result<usize> {
    let record = slice(data, pos, END_SIZE, "Ubiquiti end record")?;
    let stored = be_u32(record, END_CRC)?;
    let computed = checksum::crc32(&data[..pos]);
    if stored != computed {
        return Err(error(format!(
            "Invalid Ubiquiti image CRC-32 in the end record at 0x{pos:X}: stored 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    expect_zero_pad(record, END_PAD, pos)?;
    c.notes.push(format!(
        "{}; end record at 0x{pos:X}: image CRC-32 verified",
        counted(record_count, "record", "records")
    ));
    Ok(pos + END_SIZE)
}

/// The `ENDS` record at `pos`: an RSA signature and a zero pad. The
/// signature needs Ubiquiti's key and is not verified. Returns the offset
/// just past it.
fn signed_end_record(
    data: &[u8],
    pos: usize,
    record_count: usize,
    c: &mut Container<'_>,
) -> Result<usize> {
    let record = slice(data, pos, ENDS_SIZE, "Ubiquiti signed end record")?;
    expect_zero_pad(record, ENDS_PAD, pos)?;
    c.notes.push(format!(
        "{}; signed end record at 0x{pos:X}: RSA signature ({RSA_SIGNATURE_SIZE} B) present, not verified; the image has no overall CRC-32",
        counted(record_count, "record", "records")
    ));
    Ok(pos + ENDS_SIZE)
}

/// The end record's pad word must be zero (binwalk treats any other value
/// as no record).
fn expect_zero_pad(record: &[u8], at: usize, pos: usize) -> Result<()> {
    let pad = be_u32(record, at)?;
    if pad == 0 {
        return Ok(());
    }
    Err(error(format!(
        "Invalid Ubiquiti end record pad 0x{pad:08X} at 0x{:X}: must be zero",
        pos + at
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_the_header_magic_and_the_first_record_magic() {
        let mut image = vec![0u8; HEADER_SIZE + MAGIC_SIZE];
        image[..4].copy_from_slice(b"UBNT");
        image[HEADER_SIZE..].copy_from_slice(PART_MAGIC);
        assert!(detect(&image));
        image[..4].copy_from_slice(b"OPEN");
        assert!(detect(&image));
        image[HEADER_SIZE..].copy_from_slice(END_MAGIC);
        assert!(!detect(&image));
        image[HEADER_SIZE..].copy_from_slice(PART_MAGIC);
        image[..4].copy_from_slice(b"OPEX");
        assert!(!detect(&image));
        assert!(!detect(&image[..HEADER_SIZE]));
    }
}
