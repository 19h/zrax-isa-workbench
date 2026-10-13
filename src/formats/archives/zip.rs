//! ZIP archives (PKWARE APPNOTE.TXT 6.3.10, 2022-11-01; every field is
//! little-endian, section 4.3.3).
//!
//! The central directory is authoritative (4.3.12, 4.3.16). The end of
//! central directory record is searched backwards over the last 64 KiB +
//! 22 B; a ZIP64 locator right before it (4.3.15) leads to the ZIP64 end of
//! central directory record (4.3.14), and ZIP64 extended information extra
//! fields (4.5.3) replace saturated entry fields. Every entry's local file
//! header (4.3.7) and data descriptor (4.3.9) are cross-checked against its
//! central directory entry, and local records may not overlap.
//!
//! Methods 0 (stored), 8 (deflate), 12 (bzip2), 14 (LZMA, 5.8.8), 93
//! (Zstandard) and 95 (xz) are decoded and every member's CRC-32 (4.4.7) is
//! verified. Deflate64 (9), other methods and encrypted members (flag bit 0
//! or method 99, 4.4.4 and Appendix E) are opaque. Package types are
//! labelled from member names; none of them names an ISA, and "version made
//! by" names a host system, not an ISA (4.4.2). In a PDX package, the data
//! files the ODX documents name are listed whatever their format (see
//! [`pdx`]).

use super::*;

mod pdx;

/// Local file header signature `0x04034B50` (4.3.7).
const LOCAL_HEADER_SIGNATURE: [u8; 4] = *b"PK\x03\x04";

/// Central directory file header signature `0x02014B50` (4.3.12).
const CENTRAL_HEADER_SIGNATURE: [u8; 4] = *b"PK\x01\x02";

/// End of central directory signature `0x06054B50` (4.3.16).
const END_SIGNATURE: [u8; 4] = *b"PK\x05\x06";

/// ZIP64 end of central directory record signature `0x06064B50` (4.3.14).
const ZIP64_END_SIGNATURE: [u8; 4] = *b"PK\x06\x06";

/// ZIP64 end of central directory locator signature `0x07064B50` (4.3.15).
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = *b"PK\x06\x07";

/// Optional data descriptor signature `0x08074B50` (4.3.9.3).
const DATA_DESCRIPTOR_SIGNATURE: [u8; 4] = *b"PK\x07\x08";

/// Digital signature record signature `0x05054B50` (4.3.13), the last
/// record of the central directory when present: signature, size (2), data.
const DIGITAL_SIGNATURE: [u8; 4] = *b"PK\x05\x05";
const DIGITAL_SIGNATURE_HEADER_SIZE: usize = 6;

/// Fixed parts of the records.
const LOCAL_HEADER_SIZE: usize = 30;
const CENTRAL_HEADER_SIZE: usize = 46;
const END_RECORD_SIZE: usize = 22;
const ZIP64_LOCATOR_SIZE: usize = 20;
const ZIP64_END_RECORD_SIZE: usize = 56;

/// The ZIP64 end record's size field counts the record without the
/// signature and the size field itself (4.3.14.1).
const ZIP64_END_LEAD_SIZE: usize = 12;

/// Offset of the comment length in the end record.
const END_COMMENT_LENGTH: usize = 20;

/// Longest archive comment (a 16-bit length).
const MAX_COMMENT: usize = 0xffff;

/// ZIP64 extended information extra field header ID (4.5.3).
const ZIP64_EXTRA_ID: u16 = 0x0001;

/// Extra field block header: ID (2), data size (2) (4.5.1).
const EXTRA_BLOCK_HEADER_SIZE: usize = 4;

/// General purpose bit flags (4.4.4).
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const FLAG_MASKED_HEADERS: u16 = 1 << 13;

/// Compression methods (4.4.5).
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_DEFLATE64: u16 = 9;
const METHOD_BZIP2: u16 = 12;
const METHOD_LZMA: u16 = 14;
const METHOD_ZSTD: u16 = 93;
const METHOD_XZ: u16 = 95;
/// AE-x encryption marker (Appendix E).
const METHOD_AES: u16 = 99;

/// A 16- or 32-bit field whose value is in a ZIP64 record (4.4.1.4).
const SATURATED_16: u16 = 0xffff;
const SATURATED_32: u32 = 0xffff_ffff;

/// LZMA member data (5.8.8): LZMA SDK major and minor version, a 16-bit
/// properties size, the properties (the `lc`/`lp`/`pb` byte and the 32-bit
/// dictionary size), then the raw LZMA stream.
const LZMA_MEMBER_HEADER_SIZE: usize = 4;
const LZMA_PROPERTIES_SIZE: usize = 5;

/// APK Signing Block magic, the last 16 bytes before the central directory.
/// From Android's "APK Signature Scheme v2" documentation, not APPNOTE.
const APK_SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Largest `manifest.json` read to label a Nordic DFU package (my limit).
const MAX_MANIFEST_SIZE: u64 = 64 << 10;

/// Nordic DFU `manifest.json` entries that name an image (nrfutil package
/// layout; my reading of nrfutil output, not a published specification).
const NORDIC_IMAGE_KEYS: &[&str] = &[
    "application",
    "bootloader",
    "softdevice",
    "softdevice_bootloader",
];

/// A ZIP starts with a local file header, or with the end of central
/// directory record when it has no entries.
pub(super) fn is_zip(data: &[u8]) -> bool {
    data.starts_with(&LOCAL_HEADER_SIGNATURE)
        || (data.starts_with(&END_SIGNATURE) && data.len() >= END_RECORD_SIZE)
}

/// Where the central directory is, from the end records.
struct Directory {
    /// File offset of the end of central directory record.
    end_offset: usize,
    /// End of that record and its comment.
    end: usize,
    /// File offset of the central directory.
    offset: usize,
    /// Central directory size in bytes.
    size: usize,
    /// Declared number of entries.
    entries: usize,
    /// File offset of the record that follows the central directory (the
    /// ZIP64 end record or the end record).
    next_record: usize,
    /// The ZIP64 end record supplied the values.
    zip64: bool,
}

/// One central directory entry, with ZIP64 values applied.
struct Entry<'a> {
    /// File name as stored.
    name_bytes: &'a [u8],
    /// File name for labels and notes.
    name: String,
    /// General purpose bit flags.
    flags: u16,
    /// Compression method.
    method: u16,
    /// CRC-32 of the uncompressed data.
    crc: u32,
    /// Stored size in bytes, including any encryption header.
    compressed_size: u64,
    /// Decoded size in bytes.
    uncompressed_size: u64,
    /// File offset of the local file header.
    local_offset: usize,
    /// File offset after this central directory header and its name,
    /// extra field and comment.
    header_end: usize,
}

impl Entry<'_> {
    fn is_directory(&self) -> bool {
        self.name_bytes.ends_with(b"/")
    }

    fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == METHOD_AES
    }
}

/// A local record checked against its entry, in file offsets.
struct Local {
    /// Start of the stored (compressed) data.
    data_offset: usize,
    /// End of the stored data.
    data_end: usize,
    /// End of the local record, after the data descriptor if any.
    end: usize,
    /// The member has a data descriptor (flag bit 3).
    has_descriptor: bool,
}

/// How a member's stored bytes become its contents.
enum Method {
    Stored,
    /// Decoded by the codec layer; LZMA members carry the ZIP LZMA header
    /// (5.8.8) instead of the LZMA-alone one.
    Codec(Codec),
    /// No Deflate64 decoder exists in this crate.
    Deflate64,
    Unsupported,
}

fn method(id: u16) -> Method {
    match id {
        METHOD_STORED => Method::Stored,
        METHOD_DEFLATE => Method::Codec(Codec::Deflate),
        METHOD_BZIP2 => Method::Codec(Codec::Bzip2),
        METHOD_LZMA => Method::Codec(Codec::Lzma),
        METHOD_ZSTD => Method::Codec(Codec::Zstd),
        METHOD_XZ => Method::Codec(Codec::Xz),
        METHOD_DEFLATE64 => Method::Deflate64,
        _ => Method::Unsupported,
    }
}

/// Package layouts recognized from member names. None of them names an ISA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Package {
    Apk,
    Ipa,
    NordicDfu,
    Pdx,
    Jar,
}

impl Package {
    fn label(self) -> &'static str {
        match self {
            Self::Apk => "Android APK",
            Self::Ipa => "iOS IPA",
            Self::NordicDfu => "Nordic DFU package",
            Self::Pdx => "ASAM ODX PDX package",
            Self::Jar => "Java JAR",
        }
    }

    /// Value of the `zip_package` metadata entry.
    fn id(self) -> &'static str {
        match self {
            Self::Apk => "apk",
            Self::Ipa => "ipa",
            Self::NordicDfu => "nordic_dfu",
            Self::Pdx => "pdx",
            Self::Jar => "jar",
        }
    }
}

/// A package layout and the member names that matched it.
struct PackageMatch {
    package: Package,
    evidence: String,
}

/// What the member walk found, for notes and metadata.
#[derive(Default)]
struct Tally {
    files: usize,
    directories: usize,
    crc_verified: usize,
    descriptors: usize,
    encrypted: NameList,
    deflate64: NameList,
    unsupported: NameList,
    /// Members whose data failed to decode or verify, with the reason.
    failed: NameList,
    /// Contents of a root `manifest.json`, for the Nordic DFU label.
    manifest: Option<Vec<u8>>,
}

/// Parse a ZIP archive: central directory, local records, then members.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let directory = directory(data)?;
    let entries = central_entries(data, &directory)?;
    let records = entries
        .iter()
        .map(|entry| local_record(data, entry, directory.offset))
        .collect::<Result<Vec<_>>>()?;
    check_overlaps(&entries, &records)?;

    let mut c = Container::new(FileFormat::Zip, Layout::Zip.label(), "zip");
    c.consumed = directory.end;
    let data_files = pdx::data_files(data, &entries, &records);
    let mut members = Members::default();
    let mut tally = Tally::default();
    for (entry, record) in entries.iter().zip(&records) {
        let walk = Walk {
            data_files: &data_files,
            members: &mut members,
            tally: &mut tally,
        };
        extract(data, entry, record, &mut c, walk);
    }
    let package = package(&entries, tally.manifest.as_deref());
    push_notes(
        data,
        &directory,
        entries.len(),
        package.as_ref(),
        &tally,
        &mut c,
    );
    members.push_notes(&mut c);
    pdx::push_notes(&mut c, &data_files, &entries);
    if let Some(found) = package {
        c.variant = found.package.label().to_string();
        c.push_metadata("zip_package", "Package type", found.package.id());
    }
    c.push_metadata("zip_entries", "Entries", entries.len() as u64);
    c.push_metadata(
        "zip_central_directory_offset",
        "Central directory offset",
        directory.offset as u64,
    );
    c.push_metadata(
        "zip_crc_verified",
        "Members with verified CRC-32",
        tally.crc_verified as u64,
    );
    c.push_metadata(
        "zip_data_descriptors",
        "Data descriptors",
        tally.descriptors as u64,
    );
    Ok(c)
}

/// The end of central directory record: the last signature in the final
/// 64 KiB + 22 B whose comment reaches the end of the file, allowing only
/// padding after it.
fn find_end_record(data: &[u8]) -> Result<usize> {
    let last = data
        .len()
        .checked_sub(END_RECORD_SIZE)
        .ok_or_else(|| error(format!("Truncated ZIP archive: {} B", data.len())))?;
    let first = last.saturating_sub(MAX_COMMENT);
    let mut rejected = None;
    for offset in (first..=last).rev() {
        if !data[offset..].starts_with(&END_SIGNATURE) {
            continue;
        }
        let comment = usize::from(le_u16(data, offset + END_COMMENT_LENGTH)?);
        let end = offset + END_RECORD_SIZE + comment;
        if data.get(end..).is_some_and(is_padding) {
            return Ok(offset);
        }
        rejected.get_or_insert(offset);
    }
    Err(match rejected {
        Some(offset) => error(format!(
            "Invalid ZIP archive comment length at 0x{:X}",
            offset + END_COMMENT_LENGTH
        )),
        None => error("Missing ZIP end of central directory record"),
    })
}

/// End of central directory record (4.3.16): disk numbers (4, 6), entries
/// on this disk (8), total entries (10), directory size (12) and offset
/// (16), comment length (20).
fn directory(data: &[u8]) -> Result<Directory> {
    let end_offset = find_end_record(data)?;
    let record = slice(data, end_offset, END_RECORD_SIZE, "ZIP end record")?;
    let comment = usize::from(le_u16(record, END_COMMENT_LENGTH)?);
    let end = end_offset + END_RECORD_SIZE + comment;
    let has_locator = end_offset
        .checked_sub(ZIP64_LOCATOR_SIZE)
        .is_some_and(|locator| data[locator..].starts_with(&ZIP64_LOCATOR_SIGNATURE));
    let directory = if has_locator {
        zip64_directory(data, end_offset - ZIP64_LOCATOR_SIZE, end_offset, end)?
    } else {
        let disk = le_u16(record, 4)?;
        let directory_disk = le_u16(record, 6)?;
        let disk_entries = le_u16(record, 8)?;
        let entries = le_u16(record, 10)?;
        if disk != 0 || directory_disk != 0 || disk_entries != entries {
            return Err(error(format!(
                "Unsupported multi-disk ZIP archive (end record at 0x{end_offset:X})"
            )));
        }
        Directory {
            end_offset,
            end,
            offset: file_offset(le_u32(record, 16)?.into(), "central directory offset")?,
            size: file_offset(le_u32(record, 12)?.into(), "central directory size")?,
            entries: usize::from(entries),
            next_record: end_offset,
            zip64: false,
        }
    };
    let directory_end = directory.offset.checked_add(directory.size);
    if directory_end != Some(directory.next_record) {
        return Err(error(format!(
            "Invalid ZIP central directory at 0x{:X} + {} B: the next record is at 0x{:X}",
            directory.offset, directory.size, directory.next_record
        )));
    }
    let capacity = directory.size / CENTRAL_HEADER_SIZE;
    if directory.entries > capacity {
        return Err(error(format!(
            "Invalid ZIP entry count {}: a {} B central directory holds at most {capacity}",
            directory.entries, directory.size
        )));
    }
    Ok(directory)
}

/// A 64-bit offset or size from a record, as a file coordinate.
fn file_offset(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid ZIP {what} 0x{value:X}")))
}

/// ZIP64 locator (4.3.15): disk with the ZIP64 end record (4), its offset
/// (8), total disks (16). ZIP64 end record (4.3.14): size of the rest (4),
/// versions (12, 14), disk numbers (16, 20), entries on this disk (24),
/// total entries (32), directory size (40) and offset (48), then
/// extensible data up to the locator.
fn zip64_directory(
    data: &[u8],
    locator_offset: usize,
    end_offset: usize,
    end: usize,
) -> Result<Directory> {
    let locator = slice(data, locator_offset, ZIP64_LOCATOR_SIZE, "ZIP64 locator")?;
    let record_disk = le_u32(locator, 4)?;
    let disks = le_u32(locator, 16)?;
    if record_disk != 0 || disks > 1 {
        return Err(error(format!(
            "Unsupported multi-disk ZIP64 archive (locator at 0x{locator_offset:X})"
        )));
    }
    let record_offset = file_offset(le_u64(locator, 8)?, "ZIP64 end record offset")?;
    let before_locator = &data[..locator_offset];
    let record = slice(
        before_locator,
        record_offset,
        ZIP64_END_RECORD_SIZE,
        "ZIP64 end record",
    )?;
    if !record.starts_with(&ZIP64_END_SIGNATURE) {
        return Err(error(format!(
            "Missing ZIP64 end record at 0x{record_offset:X}"
        )));
    }
    let rest = le_u64(record, 4)?;
    let record_end = u64::try_from(record_offset + ZIP64_END_LEAD_SIZE)
        .ok()
        .and_then(|lead_end| lead_end.checked_add(rest));
    if record_end != u64::try_from(locator_offset).ok() {
        return Err(error(format!(
            "Invalid ZIP64 end record size at 0x{:X}: the locator is at 0x{locator_offset:X}",
            record_offset + 4
        )));
    }
    let disk = le_u32(record, 16)?;
    let directory_disk = le_u32(record, 20)?;
    let disk_entries = le_u64(record, 24)?;
    let entries = le_u64(record, 32)?;
    if disk != 0 || directory_disk != 0 || disk_entries != entries {
        return Err(error(format!(
            "Unsupported multi-disk ZIP64 archive (end record at 0x{record_offset:X})"
        )));
    }
    Ok(Directory {
        end_offset,
        end,
        offset: file_offset(le_u64(record, 48)?, "ZIP64 central directory offset")?,
        size: file_offset(le_u64(record, 40)?, "ZIP64 central directory size")?,
        // Bounded by the directory size in `directory`.
        entries: usize::try_from(entries).unwrap_or(usize::MAX),
        next_record: record_offset,
        zip64: true,
    })
}

/// Walk the central directory: exactly the declared entries, then an
/// optional digital signature record, ending at the directory's end.
fn central_entries<'a>(data: &'a [u8], directory: &Directory) -> Result<Vec<Entry<'a>>> {
    let records = &data[..directory.next_record];
    let mut entries = Vec::with_capacity(directory.entries);
    let mut pos = directory.offset;
    for _ in 0..directory.entries {
        let entry = central_entry(records, pos)?;
        pos = entry.header_end;
        entries.push(entry);
    }
    if records[pos..].starts_with(&DIGITAL_SIGNATURE) {
        let size = usize::from(le_u16(records, pos + 4)?);
        let signature_offset = pos + DIGITAL_SIGNATURE_HEADER_SIZE;
        slice(records, signature_offset, size, "ZIP digital signature")?;
        pos = signature_offset + size;
    }
    if pos != directory.next_record {
        return Err(error(format!(
            "Invalid ZIP central directory: {} entries end at 0x{pos:X}, the directory at 0x{:X}",
            entries.len(),
            directory.next_record
        )));
    }
    Ok(entries)
}

/// Central directory header (4.3.12): flags (8), method (10), CRC-32 (16),
/// compressed (20) and uncompressed (24) size, name (28), extra (30) and
/// comment (32) lengths, start disk (34), local header offset (42); then
/// name, extra field and comment.
fn central_entry(records: &[u8], pos: usize) -> Result<Entry<'_>> {
    let header = slice(
        records,
        pos,
        CENTRAL_HEADER_SIZE,
        "ZIP central directory header",
    )?;
    if !header.starts_with(&CENTRAL_HEADER_SIGNATURE) {
        return Err(error(format!(
            "Missing ZIP central directory header at 0x{pos:X}"
        )));
    }
    let flags = le_u16(header, 8)?;
    let name_len = usize::from(le_u16(header, 28)?);
    let extra_len = usize::from(le_u16(header, 30)?);
    let comment_len = usize::from(le_u16(header, 32)?);
    let name_offset = pos + CENTRAL_HEADER_SIZE;
    let name_bytes = slice(
        records,
        name_offset,
        name_len,
        "ZIP central directory file name",
    )?;
    let extra = slice(
        records,
        name_offset + name_len,
        extra_len,
        "ZIP central directory extra field",
    )?;
    let comment_offset = name_offset + name_len + extra_len;
    slice(records, comment_offset, comment_len, "ZIP file comment")?;
    let name = display_name(name_bytes);
    if flags & FLAG_MASKED_HEADERS != 0 {
        return Err(error(format!(
            "Unsupported ZIP central directory encryption (flag bit 13) for `{name}` at 0x{pos:X}"
        )));
    }

    // ZIP64 values appear only for saturated fields, in this order (4.5.3).
    let mut zip64 = Zip64Values::new(extra, &name, pos);
    let uncompressed_size = match le_u32(header, 24)? {
        SATURATED_32 => zip64.take_u64("uncompressed size")?,
        size => u64::from(size),
    };
    let compressed_size = match le_u32(header, 20)? {
        SATURATED_32 => zip64.take_u64("compressed size")?,
        size => u64::from(size),
    };
    let local_offset = match le_u32(header, 42)? {
        SATURATED_32 => zip64.take_u64("local header offset")?,
        offset => u64::from(offset),
    };
    let disk = match le_u16(header, 34)? {
        SATURATED_16 => zip64.take_u32("start disk")?,
        disk => u32::from(disk),
    };
    if disk != 0 {
        return Err(error(format!(
            "Unsupported multi-disk ZIP member `{name}` (disk {disk}) at 0x{pos:X}"
        )));
    }
    let entry = Entry {
        name_bytes,
        flags,
        method: le_u16(header, 10)?,
        crc: le_u32(header, 16)?,
        compressed_size,
        uncompressed_size,
        local_offset: file_offset(local_offset, "local header offset")?,
        header_end: comment_offset + comment_len,
        name,
    };
    Ok(entry)
}

/// The data of the first extra field block with header ID `id` (4.5.1:
/// header ID, data size, data). The walk stops at a block that does not
/// fit: Android `zipalign` pads local extra fields with zero bytes that are
/// not always whole blocks.
fn extra_block(extra: &[u8], id: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while let Some(block_header) = extra.get(pos..pos + EXTRA_BLOCK_HEADER_SIZE) {
        let block_id = u16::from_le_bytes([block_header[0], block_header[1]]);
        let size = usize::from(u16::from_le_bytes([block_header[2], block_header[3]]));
        let block_start = pos + EXTRA_BLOCK_HEADER_SIZE;
        let block = extra.get(block_start..block_start + size)?;
        if block_id == id {
            return Some(block);
        }
        pos = block_start + size;
    }
    None
}

/// The values of a ZIP64 extended information extra field, consumed in
/// the fixed order of 4.5.3.
struct Zip64Values<'a> {
    field: Option<&'a [u8]>,
    pos: usize,
    name: &'a str,
    header_offset: usize,
}

impl<'a> Zip64Values<'a> {
    fn new(extra: &'a [u8], name: &'a str, header_offset: usize) -> Self {
        Self {
            field: extra_block(extra, ZIP64_EXTRA_ID),
            pos: 0,
            name,
            header_offset,
        }
    }

    fn take(&mut self, what: &str, len: usize) -> Result<&'a [u8]> {
        let value = self
            .field
            .and_then(|field| field.get(self.pos..self.pos + len))
            .ok_or_else(|| {
                error(format!(
                    "Missing ZIP64 {what} for `{}` in the header at 0x{:X}",
                    self.name, self.header_offset
                ))
            })?;
        self.pos += len;
        Ok(value)
    }

    fn take_u64(&mut self, what: &str) -> Result<u64> {
        le_u64(self.take(what, 8)?, 0)
    }

    fn take_u32(&mut self, what: &str) -> Result<u32> {
        le_u32(self.take(what, 4)?, 0)
    }
}

/// Local file header (4.3.7): flags (6), method (8), CRC-32 (14),
/// compressed (18) and uncompressed (22) size, name (26) and extra (28)
/// lengths; then name, extra field, data and the optional data descriptor.
/// Members must lie before the central directory at `directory_offset`.
fn local_record(data: &[u8], entry: &Entry<'_>, directory_offset: usize) -> Result<Local> {
    let area = &data[..directory_offset];
    let offset = entry.local_offset;
    let header = slice(area, offset, LOCAL_HEADER_SIZE, "ZIP local file header")?;
    if !header.starts_with(&LOCAL_HEADER_SIGNATURE) {
        return Err(error(format!(
            "Missing ZIP local file header for `{}` at 0x{offset:X}",
            entry.name
        )));
    }
    let differs = |field: &str| {
        error(format!(
            "Invalid ZIP local file header for `{}` at 0x{offset:X}: {field} differs from the \
             central directory",
            entry.name
        ))
    };
    let flags = le_u16(header, 6)?;
    if le_u16(header, 8)? != entry.method {
        return Err(differs("method"));
    }
    if (flags ^ entry.flags) & (FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR) != 0 {
        return Err(differs("general purpose flags"));
    }
    let name_len = usize::from(le_u16(header, 26)?);
    let extra_len = usize::from(le_u16(header, 28)?);
    let name_offset = offset + LOCAL_HEADER_SIZE;
    if slice(area, name_offset, name_len, "ZIP local file name")? != entry.name_bytes {
        return Err(differs("file name"));
    }
    let extra = slice(
        area,
        name_offset + name_len,
        extra_len,
        "ZIP local extra field",
    )?;
    let data_offset = name_offset + name_len + extra_len;
    let data_end = usize::try_from(entry.compressed_size)
        .ok()
        .and_then(|size| data_offset.checked_add(size))
        .filter(|end| *end <= area.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated ZIP member `{}` at 0x{data_offset:X} + {} B: the central directory \
                 starts at 0x{directory_offset:X}",
                entry.name, entry.compressed_size
            ))
        })?;
    let zip64 = extra_block(extra, ZIP64_EXTRA_ID);
    if flags & FLAG_DATA_DESCRIPTOR == 0 {
        let sizes = local_sizes(header, zip64);
        let expected = Sizes {
            compressed: entry.compressed_size,
            uncompressed: entry.uncompressed_size,
        };
        if le_u32(header, 14)? != entry.crc || sizes != Some(expected) {
            return Err(differs("CRC-32 or size"));
        }
        return Ok(Local {
            data_offset,
            data_end,
            end: data_end,
            has_descriptor: false,
        });
    }
    let descriptor_len = data_descriptor(area, data_end, entry, zip64.is_some())?;
    Ok(Local {
        data_offset,
        data_end,
        end: data_end + descriptor_len,
        has_descriptor: true,
    })
}

/// The sizes a local header records for its member.
#[derive(PartialEq, Eq)]
struct Sizes {
    /// Stored size in bytes, including any encryption header.
    compressed: u64,
    /// Decoded size in bytes.
    uncompressed: u64,
}

/// Compressed and uncompressed size of a local header. When either 32-bit
/// field is saturated, the local ZIP64 field holds both, uncompressed size
/// first (4.5.3).
fn local_sizes(header: &[u8], zip64: Option<&[u8]>) -> Option<Sizes> {
    let compressed = le_u32(header, 18).ok()?;
    let uncompressed = le_u32(header, 22).ok()?;
    if compressed != SATURATED_32 && uncompressed != SATURATED_32 {
        return Some(Sizes {
            compressed: u64::from(compressed),
            uncompressed: u64::from(uncompressed),
        });
    }
    let field = zip64?;
    Some(Sizes {
        compressed: le_u64(field, 8).ok()?,
        uncompressed: le_u64(field, 0).ok()?,
    })
}

/// Length of the data descriptor at `at` (4.3.9): CRC-32 and the two
/// sizes, with or without the optional signature, and with 4- or 8-byte
/// sizes. The first form whose values match the central directory entry
/// is taken; the 8-byte form is tried first when the local header has a
/// ZIP64 field (4.3.9.2).
fn data_descriptor(area: &[u8], at: usize, entry: &Entry<'_>, zip64: bool) -> Result<usize> {
    let size_widths = if zip64 { [8, 4] } else { [4, 8] };
    for has_signature in [true, false] {
        for size_width in size_widths {
            let lead = if has_signature {
                DATA_DESCRIPTOR_SIGNATURE.len()
            } else {
                0
            };
            let len = lead + 4 + 2 * size_width;
            let Some(descriptor) = area.get(at..at + len) else {
                continue;
            };
            if has_signature && !descriptor.starts_with(&DATA_DESCRIPTOR_SIGNATURE) {
                continue;
            }
            if descriptor_matches(&descriptor[lead..], size_width, entry) {
                return Ok(len);
            }
        }
    }
    if area.len() < at + 12 {
        return Err(error(format!(
            "Truncated ZIP data descriptor for `{}` at 0x{at:X}",
            entry.name
        )));
    }
    Err(error(format!(
        "Invalid ZIP data descriptor for `{}` at 0x{at:X}: CRC-32 and sizes do not match the \
         central directory",
        entry.name
    )))
}

/// Descriptor body: CRC-32, compressed size, uncompressed size, each size
/// `size_width` bytes.
fn descriptor_matches(body: &[u8], size_width: usize, entry: &Entry<'_>) -> bool {
    let sizes = if size_width == 8 {
        le_u64(body, 4).ok().zip(le_u64(body, 12).ok())
    } else {
        le_u32(body, 4)
            .ok()
            .zip(le_u32(body, 8).ok())
            .map(|(compressed, uncompressed)| (u64::from(compressed), u64::from(uncompressed)))
    };
    le_u32(body, 0).ok() == Some(entry.crc)
        && sizes == Some((entry.compressed_size, entry.uncompressed_size))
}

/// Local records may not overlap: overlapping entries would let one stored
/// payload be classified many times (the "overlapping files" ZIP bomb).
fn check_overlaps(entries: &[Entry<'_>], records: &[Local]) -> Result<()> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].local_offset);
    for pair in order.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if entries[second].local_offset < records[first].end {
            return Err(error(format!(
                "Invalid ZIP central directory: `{}` at 0x{:X} overlaps `{}` at 0x{:X}",
                entries[second].name,
                entries[second].local_offset,
                entries[first].name,
                entries[first].local_offset
            )));
        }
    }
    Ok(())
}

/// The state a member walk updates.
struct Walk<'w> {
    /// Data files the archive's own index names (PDX).
    data_files: &'w [pdx::DataFile],
    members: &'w mut Members,
    tally: &'w mut Tally,
}

/// Read one member: directories and encrypted members are counted, file
/// members are decoded and CRC-checked, then listed when they are a
/// recognized format or a data file the archive's index names.
fn extract<'a>(
    data: &'a [u8],
    entry: &Entry<'a>,
    record: &Local,
    c: &mut Container<'a>,
    walk: Walk<'_>,
) {
    let Walk {
        data_files,
        members,
        tally,
    } = walk;
    if record.has_descriptor {
        tally.descriptors += 1;
    }
    if entry.is_directory() {
        tally.directories += 1;
        return;
    }
    tally.files += 1;
    if entry.is_encrypted() {
        tally.encrypted.push(entry.name.as_str());
        return;
    }
    if !members.has_room(c) {
        return;
    }
    let Some(contents) = verified_contents(data, entry, record, members, tally) else {
        return;
    };
    if entry.name_bytes == b"manifest.json" && entry.uncompressed_size <= MAX_MANIFEST_SIZE {
        tally.manifest = Some(contents.data.to_vec());
    }
    let stored = &data[record.data_offset..record.data_end];
    let child = match contents.transform {
        Some(transform) => Child::decoded(
            entry.name.clone(),
            record.data_offset,
            stored.len(),
            contents.data,
            transform,
        ),
        None => Child::stored(entry.name.clone(), record.data_offset, stored),
    };
    match data_files.iter().find(|file| file.is_named(&entry.name)) {
        Some(file) => pdx::list_data_file(c, members, child, file),
        None => members.offer(c, child),
    }
}

/// A file member's contents, decoded within the extraction limits and
/// checked against the central directory's size and CRC-32. Failures are
/// tallied and give `None`.
fn verified_contents<'a>(
    data: &'a [u8],
    entry: &Entry<'_>,
    record: &Local,
    members: &mut Members,
    tally: &mut Tally,
) -> Option<Contents<'a>> {
    let stored = &data[record.data_offset..record.data_end];
    let contents = contents(entry, stored, record.data_offset, members, tally)?;
    if contents.data.len() as u64 != entry.uncompressed_size {
        tally.failed.push(format!(
            "{}: {} B of data, the central directory declares {} B",
            entry.name,
            contents.data.len(),
            entry.uncompressed_size
        ));
        return None;
    }
    let crc = checksum::crc32(&contents.data);
    if crc != entry.crc {
        tally.failed.push(format!(
            "{}: CRC-32 0x{crc:08X}, the central directory declares 0x{:08X}",
            entry.name, entry.crc
        ));
        return None;
    }
    tally.crc_verified += 1;
    Some(contents)
}

/// A member's contents and the codec that produced them from the stored
/// bytes.
struct Contents<'a> {
    data: Cow<'a, [u8]>,
    transform: Option<&'static str>,
}

/// A member's contents: the stored bytes, or their decode within the
/// extraction limits. Opaque methods and failed decodes are tallied.
fn contents<'a>(
    entry: &Entry<'_>,
    stored: &'a [u8],
    data_offset: usize,
    members: &mut Members,
    tally: &mut Tally,
) -> Option<Contents<'a>> {
    let codec = match method(entry.method) {
        Method::Stored => {
            return Some(Contents {
                data: Cow::Borrowed(stored),
                transform: None,
            })
        }
        Method::Codec(codec) => codec,
        Method::Deflate64 => {
            tally.deflate64.push(entry.name.as_str());
            return None;
        }
        Method::Unsupported => {
            tally
                .unsupported
                .push(format!("{} (method {})", entry.name, entry.method));
            return None;
        }
    };
    if !members.reserve(&entry.name, entry.uncompressed_size) {
        return None;
    }
    let limit = usize::try_from(entry.uncompressed_size).expect("reserved within MAX_PAYLOAD");
    let decoded = match codec {
        Codec::Lzma => decode_lzma(stored, data_offset, entry.uncompressed_size, limit),
        _ => compressed::decode_limited(codec, stored, limit).map(|decoded| decoded.data),
    };
    match decoded {
        Ok(decoded) => Some(Contents {
            data: Cow::Owned(decoded),
            transform: Some(codec.name()),
        }),
        Err(e) => {
            tally.failed.push(format!(
                "{}: {} data does not decode ({e})",
                entry.name,
                codec.name()
            ));
            None
        }
    }
}

/// Decode LZMA member data (5.8.8) as an LZMA-alone stream whose header is
/// the member's properties and the central directory's uncompressed size.
/// With the size known, the optional end-of-stream marker (flag bit 1) is
/// not needed. `data_offset` is the stored data's file offset, for errors.
fn decode_lzma(
    stored: &[u8],
    data_offset: usize,
    uncompressed_size: u64,
    limit: usize,
) -> Result<Vec<u8>> {
    let header_size = LZMA_MEMBER_HEADER_SIZE + LZMA_PROPERTIES_SIZE;
    if stored.len() < header_size {
        return Err(error(format!(
            "Truncated ZIP LZMA header at 0x{data_offset:X}"
        )));
    }
    let properties_size = usize::from(u16::from_le_bytes([stored[2], stored[3]]));
    if properties_size != LZMA_PROPERTIES_SIZE {
        return Err(error(format!(
            "Unsupported ZIP LZMA properties size {properties_size} at 0x{:X}",
            data_offset + 2
        )));
    }
    let properties = &stored[LZMA_MEMBER_HEADER_SIZE..header_size];
    let stream = &stored[header_size..];
    let mut alone = Vec::with_capacity(LZMA_PROPERTIES_SIZE + 8 + stream.len());
    alone.extend_from_slice(properties);
    alone.extend_from_slice(&uncompressed_size.to_le_bytes());
    alone.extend_from_slice(stream);
    Ok(compressed::decode_limited(Codec::Lzma, &alone, limit)?.data)
}

/// Summary, package, integrity and opaque-member notes, most important
/// first.
fn push_notes(
    data: &[u8],
    directory: &Directory,
    entries: usize,
    package: Option<&PackageMatch>,
    tally: &Tally,
    c: &mut Container<'_>,
) {
    let zip64 = if directory.zip64 {
        "; ZIP64 end records"
    } else {
        ""
    };
    c.notes.push(format!(
        "{} ({}, {}); central directory at 0x{:X}, {} B{zip64}",
        count(entries, "entry", "entries"),
        count(tally.files, "file", "files"),
        count(tally.directories, "directory", "directories"),
        directory.offset,
        directory.size
    ));
    if let Some(found) = package {
        c.notes.push(format!(
            "Package layout: {} ({}); the package type does not determine an ISA",
            found.package.label(),
            found.evidence
        ));
    }
    if tally.files > 0 {
        c.notes.push(format!(
            "CRC-32 verified for {} of {} file members",
            tally.crc_verified, tally.files
        ));
    }
    if tally.descriptors > 0 {
        c.notes.push(format!(
            "{} (flag bit 3); each matches its central directory entry",
            count(
                tally.descriptors,
                "member uses a data descriptor",
                "members use data descriptors"
            )
        ));
    }
    if !tally.encrypted.is_empty() {
        c.notes.push(format!(
            "Encrypted members (flag bit 0) are opaque and were not analyzed: {}",
            tally.encrypted
        ));
    }
    if !tally.deflate64.is_empty() {
        c.notes.push(format!(
            "Deflate64 members (method 9) are not decoded and are opaque: {}",
            tally.deflate64
        ));
    }
    if !tally.unsupported.is_empty() {
        c.notes.push(format!(
            "Members with unsupported compression methods are opaque: {}",
            tally.unsupported
        ));
    }
    if !tally.failed.is_empty() {
        c.notes.push(format!(
            "Members that failed to decode or verify were not classified: {}",
            tally.failed
        ));
    }
    let signing_block = directory
        .offset
        .checked_sub(APK_SIGNING_BLOCK_MAGIC.len())
        .map(|start| &data[start..directory.offset]);
    if signing_block == Some(APK_SIGNING_BLOCK_MAGIC.as_slice()) {
        c.notes.push(
            "APK Signing Block before the central directory; signatures not verified".to_string(),
        );
    }
    let trailing = data.len() - directory.end;
    if trailing > 0 {
        c.notes.push(format!(
            "{trailing} B of padding after the end record at 0x{:X}",
            directory.end_offset
        ));
    }
}

/// The package type the member names match, and the names that matched.
fn package(entries: &[Entry<'_>], manifest: Option<&[u8]>) -> Option<PackageMatch> {
    let has = |name: &[u8]| entries.iter().any(|e| e.name_bytes == name);
    if has(b"AndroidManifest.xml") && has(b"classes.dex") {
        return Some(PackageMatch {
            package: Package::Apk,
            evidence: "AndroidManifest.xml and classes.dex at the root".to_string(),
        });
    }
    if let Some(bundle) = entries.iter().find_map(|e| ipa_bundle(&e.name)) {
        return Some(PackageMatch {
            package: Package::Ipa,
            evidence: format!("Payload/{bundle}/"),
        });
    }
    if let Some(images) = manifest.and_then(nordic_images) {
        return Some(PackageMatch {
            package: Package::NordicDfu,
            evidence: format!("manifest.json names {}", images.join(", ")),
        });
    }
    if is_pdx(entries) {
        return Some(PackageMatch {
            package: Package::Pdx,
            evidence: "index.xml at the root and .odx* members".to_string(),
        });
    }
    if has(b"META-INF/MANIFEST.MF") {
        return Some(PackageMatch {
            package: Package::Jar,
            evidence: "META-INF/MANIFEST.MF".to_string(),
        });
    }
    None
}

/// Is the archive shaped like an ASAM PDX package: `index.xml` at the root
/// and at least one `.odx*` member?
fn is_pdx(entries: &[Entry<'_>]) -> bool {
    let has_index = entries
        .iter()
        .any(|e| e.name_bytes.eq_ignore_ascii_case(b"index.xml"));
    has_index && entries.iter().any(|e| is_odx_name(&e.name))
}

/// The application bundle of an IPA member path `Payload/<name>.app/...`.
fn ipa_bundle(name: &str) -> Option<&str> {
    let (bundle, _) = name.strip_prefix("Payload/")?.split_once('/')?;
    let (stem, extension) = bundle.rsplit_once('.')?;
    (!stem.is_empty() && extension == "app").then_some(bundle)
}

/// ODX documents use the extensions `.odx` and `.odx-<category>`
/// (odxtools 11.7.0 `loadfile.py`), in any case.
fn is_odx_name(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, extension)| {
        extension
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("odx"))
    })
}

/// The image entries a Nordic DFU `manifest.json` names under `manifest`.
fn nordic_images(manifest: &[u8]) -> Option<Vec<&'static str>> {
    let value: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    let entries = value.get("manifest")?.as_object()?;
    let images: Vec<&'static str> = NORDIC_IMAGE_KEYS
        .iter()
        .copied()
        .filter(|key| entries.contains_key(*key))
        .collect();
    (!images.is_empty()).then_some(images)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_blocks_are_found_and_bad_framing_stops_the_walk() {
        let extra = [0x55, 0x54, 1, 0, 9, 0x01, 0x00, 2, 0, 0xaa, 0xbb];
        assert_eq!(extra_block(&extra, ZIP64_EXTRA_ID), Some(&[0xaa, 0xbb][..]));
        assert_eq!(extra_block(&extra, 0x7875), None);
        let padded = [0, 0, 0];
        assert_eq!(extra_block(&padded, ZIP64_EXTRA_ID), None);
        let overrun = [0x01, 0x00, 9, 0, 1];
        assert_eq!(extra_block(&overrun, ZIP64_EXTRA_ID), None);
    }

    #[test]
    fn package_names_are_matched_exactly() {
        assert_eq!(ipa_bundle("Payload/App.app/App"), Some("App.app"));
        assert_eq!(ipa_bundle("Payload/.app/App"), None);
        assert_eq!(ipa_bundle("Payload/App.application/App"), None);
        assert_eq!(ipa_bundle("payload/App.app/App"), None);
        assert!(is_odx_name("flash/ecu.odx-f"));
        assert!(is_odx_name("DIAG.ODX"));
        assert!(!is_odx_name("index.xml"));
        assert_eq!(
            nordic_images(br#"{"manifest": {"application": {"bin_file": "a.bin"}}}"#),
            Some(vec!["application"])
        );
        assert_eq!(nordic_images(br#"{"manifest": {}}"#), None);
        assert_eq!(nordic_images(b"not json"), None);
    }

    #[test]
    fn end_record_search_takes_the_last_record_whose_comment_fits() {
        // An empty archive, then a second end record whose comment length
        // overruns the file.
        let mut data = END_SIGNATURE.to_vec();
        data.resize(END_RECORD_SIZE, 0);
        assert_eq!(find_end_record(&data).unwrap(), 0);
        data.extend_from_slice(&[0xff; 8]);
        assert_eq!(find_end_record(&data).unwrap(), 0);
        let mut overrun = data.clone();
        overrun[END_COMMENT_LENGTH] = 1;
        overrun.truncate(END_RECORD_SIZE);
        assert!(find_end_record(&overrun)
            .unwrap_err()
            .to_string()
            .contains("Invalid ZIP archive comment length at 0x14"));
        assert!(find_end_record(&data[..END_RECORD_SIZE - 1]).is_err());
    }

    #[test]
    fn lzma_members_need_the_five_byte_properties_header() {
        let short = [9, 20, 5, 0, 0x5d];
        assert!(decode_lzma(&short, 0x40, 0, 0)
            .unwrap_err()
            .to_string()
            .contains("Truncated ZIP LZMA header at 0x40"));
        let wrong_size = [9, 20, 4, 0, 0x5d, 0, 0, 1, 0];
        assert!(decode_lzma(&wrong_size, 0x40, 0, 0)
            .unwrap_err()
            .to_string()
            .contains("properties size 4 at 0x42"));
    }
}
