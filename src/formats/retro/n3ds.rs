//! Nintendo 3DS NCCH partitions: CXI executables and CFA archives.
//!
//! NCCH (3dbrew "NCCH" oldid 23516, "`ExeFS`" oldid 16109 and "NCCH/Extended
//! Header" oldid 23704), all little-endian: an RSA-2048 signature (0x100),
//! `NCCH` at 0x100, content size in media units at 0x104, partition ID (8)
//! at 0x108, maker code (2) at 0x110, version (2) at 0x112, program ID (8)
//! at 0x118, product code (16) at 0x150, `ExHeader` size in bytes at 0x180,
//! flags (8) at 0x188, then offset and size pairs in media units for the
//! plain region (0x190), logo region (0x198), `ExeFS` (0x1A0, hash region size
//! at 0x1A8) and `RomFS` (0x1B0), and the `ExeFS` superblock SHA-256 at 0x1C0.
//! A media unit is `0x200 << flags[6]` bytes. Unless flags[7] sets
//! `NoCrypto`, the `ExHeader`, `ExeFS` and `RomFS` are AES-128-CTR encrypted.
//!
//! The `ExHeader` starts at 0x200. Its system control info holds the
//! application title (8), the `CompressExefsCode` flag at 0x0D, and the
//! text, read-only and data code sets (address, pages, size) at 0x10, 0x20
//! and 0x30. The `ExeFS` starts with a 0x200-byte header: ten file entries of
//! name (8), offset after the header (4) and size (4), then their SHA-256
//! hashes in reverse order from 0x1E0. A compressed `.code` uses the backward
//! LZ codec ([`compressed::Codec::Blz`]).

use super::*;
use crate::formats::compressed::{self, Codec};
use sha2::{Digest, Sha256};

/// NCCH magic and its offset, after the header signature.
const NCCH_MAGIC: &[u8; 4] = b"NCCH";
const NCCH_MAGIC_OFFSET: usize = 0x100;

/// The NCCH header ends where the `ExHeader` begins.
const NCCH_HEADER_SIZE: usize = 0x200;

/// NCCH header fields.
const CONTENT_SIZE: usize = 0x104;
const PARTITION_ID: usize = 0x108;
const MAKER_CODE: usize = 0x110;
const MAKER_CODE_SIZE: usize = 2;
const NCCH_VERSION: usize = 0x112;
const PROGRAM_ID: usize = 0x118;
const PRODUCT_CODE: usize = 0x150;
const PRODUCT_CODE_SIZE: usize = 0x10;
const EXHEADER_SIZE: usize = 0x180;
const FLAGS: usize = 0x188;
const FLAGS_SIZE: usize = 8;
const PLAIN_REGION: usize = 0x190;
const LOGO_REGION: usize = 0x198;
const EXEFS_REGION: usize = 0x1a0;
const EXEFS_HASH_REGION_SIZE: usize = 0x1a8;
const ROMFS_REGION: usize = 0x1b0;
const EXEFS_SUPERBLOCK_HASH: usize = 0x1c0;

/// Flag bytes at 0x188.
const FLAG_CRYPTO_METHOD: usize = 3;
const FLAG_PLATFORM: usize = 4;
const FLAG_CONTENT_TYPE: usize = 5;
const FLAG_UNIT_SIZE: usize = 6;
const FLAG_BITMASK: usize = 7;

/// flags[7] bits.
const FIXED_CRYPTO_KEY: u8 = 0x01;
const NO_MOUNT_ROMFS: u8 = 0x02;
const NO_CRYPTO: u8 = 0x04;
const NEW_KEY_Y_GENERATOR: u8 = 0x20;

/// flags[5] bits 0-1: form type. Types 2 and 3 are executables (CXI).
const FORM_TYPE_MASK: u8 = 0x03;
const FORM_EXECUTABLE_WITHOUT_ROMFS: u8 = 2;
const FORM_EXECUTABLE: u8 = 3;

/// flags[5] bits 2-7: content type.
const CONTENT_TYPE_SHIFT: u32 = 2;

/// flags[4]: content platform.
const PLATFORM_CTR: u8 = 1;
const PLATFORM_SNAKE: u8 = 2;

/// One media unit at exponent 0 (0x200 bytes), as a power of two.
const MEDIA_UNIT_SHIFT: u32 = 9;

/// `ExHeader` system control info fields.
const SCI_APP_TITLE: usize = 0;
const SCI_APP_TITLE_SIZE: usize = 8;
const SCI_FLAGS: usize = 0x0d;
const SCI_TEXT_CODE_SET: usize = 0x10;
const SCI_STACK_SIZE: usize = 0x1c;
const SCI_RO_CODE_SET: usize = 0x20;
const SCI_DATA_CODE_SET: usize = 0x30;
const SCI_BSS_SIZE: usize = 0x3c;
const SCI_MIN_SIZE: usize = 0x40;

/// SCI flag bit 0: `.code` is compressed.
const COMPRESS_EXEFS_CODE: u8 = 0x01;

/// A code set: address (4), physical region size in pages (4), size in
/// bytes (4).
const CODE_SET_SIZE: usize = 8;

/// `ExeFS` header: ten 16-byte file entries, then SHA-256 hashes stored in
/// reverse order, the hash of entry `i` at `0x1E0 - 0x20 * i`.
const EXEFS_HEADER_SIZE: usize = 0x200;
const EXEFS_FILE_COUNT: usize = 10;
const EXEFS_ENTRY_SIZE: usize = 16;
const EXEFS_NAME_SIZE: usize = 8;
const EXEFS_LAST_HASH: usize = 0x1e0;
const SHA256_SIZE: usize = 32;

/// The `ExeFS` file that holds the code segments.
const CODE_FILE: &str = ".code";

/// Strong recognition: `NCCH` after the header signature.
pub(super) fn detect(data: &[u8]) -> bool {
    data.get(NCCH_MAGIC_OFFSET..)
        .is_some_and(|rest| rest.starts_with(NCCH_MAGIC))
}

/// The NCCH header fields this parser uses. Regions are in bytes.
struct NcchHeader {
    partition_id: u64,
    maker_code: String,
    version: u16,
    program_id: u64,
    product_code: String,
    exheader_size: usize,
    flags: [u8; FLAGS_SIZE],
    /// Bytes per media unit; at most the content size.
    media_unit: usize,
    content_size: usize,
    plain: Region,
    logo: Region,
    exefs: Region,
    exefs_hash_size: usize,
    romfs: Region,
}

impl NcchHeader {
    fn is_encrypted(&self) -> bool {
        self.flags[FLAG_BITMASK] & NO_CRYPTO == 0
    }

    fn is_executable(&self) -> bool {
        matches!(
            self.flags[FLAG_CONTENT_TYPE] & FORM_TYPE_MASK,
            FORM_EXECUTABLE_WITHOUT_ROMFS | FORM_EXECUTABLE
        )
    }
}

/// A size in media units as bytes, if it fits the content.
fn media_bytes(units: u32, media_unit: usize, content_size: usize, what: &str) -> Result<usize> {
    usize::try_from(units)
        .ok()
        .and_then(|units| units.checked_mul(media_unit))
        .filter(|bytes| *bytes <= content_size)
        .ok_or_else(|| {
            error(format!(
                "Invalid NCCH {what}: 0x{units:X} media units exceed the {} content",
                size_text(content_size)
            ))
        })
}

/// An offset and size pair in media units at `at`, checked against the
/// content.
fn media_region(
    data: &[u8],
    at: usize,
    media_unit: usize,
    content_size: usize,
    what: &str,
) -> Result<Region> {
    let offset = media_bytes(le_u32(data, at)?, media_unit, content_size, what)?;
    let size = media_bytes(le_u32(data, at + 4)?, media_unit, content_size, what)?;
    match offset.checked_add(size) {
        Some(end) if end <= content_size => Ok(Region { offset, size }),
        _ => Err(error(format!(
            "Invalid NCCH {what} 0x{offset:X} + {size} B: beyond the {} content",
            size_text(content_size)
        ))),
    }
}

/// The media unit and the content size it scales, in bytes.
struct MediaLayout {
    media_unit: usize,
    content_size: usize,
}

/// The media unit, `0x200 << flags[6]` bytes, and the content size in
/// media units at 0x104; both must fit in the file.
fn media_layout(data: &[u8], flags: [u8; FLAGS_SIZE]) -> Result<MediaLayout> {
    let exponent = flags[FLAG_UNIT_SIZE];
    let media_unit = 1usize
        .checked_shl(MEDIA_UNIT_SHIFT + u32::from(exponent))
        .filter(|unit| *unit <= data.len())
        .ok_or_else(|| error(format!("Invalid NCCH media unit size exponent {exponent}")))?;
    let content_units = le_u32(data, CONTENT_SIZE)?;
    let content_size = usize::try_from(content_units)
        .ok()
        .and_then(|units| units.checked_mul(media_unit))
        .filter(|size| *size >= NCCH_HEADER_SIZE)
        .ok_or_else(|| {
            error(format!(
                "Invalid NCCH content size 0x{content_units:X} media units"
            ))
        })?;
    if content_size > data.len() {
        return Err(error(format!(
            "Truncated NCCH: content size {content_size} B, file {} B",
            data.len()
        )));
    }
    Ok(MediaLayout {
        media_unit,
        content_size,
    })
}

fn ncch_header(data: &[u8]) -> Result<NcchHeader> {
    if data.len() < NCCH_HEADER_SIZE {
        return Err(error(format!(
            "Truncated NCCH header: {} B of {NCCH_HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing NCCH magic at 0x100"));
    }
    let flags: [u8; FLAGS_SIZE] = array(data, FLAGS)?;
    let MediaLayout {
        media_unit,
        content_size,
    } = media_layout(data, flags)?;
    let region = |at: usize, what: &str| media_region(data, at, media_unit, content_size, what);
    let exefs_hash_units = le_u32(data, EXEFS_HASH_REGION_SIZE)?;
    Ok(NcchHeader {
        partition_id: le_u64(data, PARTITION_ID)?,
        maker_code: text(slice(data, MAKER_CODE, MAKER_CODE_SIZE)?),
        version: le_u16(data, NCCH_VERSION)?,
        program_id: le_u64(data, PROGRAM_ID)?,
        product_code: text(slice(data, PRODUCT_CODE, PRODUCT_CODE_SIZE)?),
        exheader_size: le_usize(data, EXHEADER_SIZE, "ExHeader size")?,
        flags,
        media_unit,
        content_size,
        plain: region(PLAIN_REGION, "plain region")?,
        logo: region(LOGO_REGION, "logo region")?,
        exefs: region(EXEFS_REGION, "ExeFS")?,
        exefs_hash_size: media_bytes(
            exefs_hash_units,
            media_unit,
            content_size,
            "ExeFS hash region",
        )?,
        romfs: region(ROMFS_REGION, "RomFS")?,
    })
}

/// The `ExHeader` system control info fields this parser uses.
struct SystemControlInfo {
    app_title: String,
    compressed_code: bool,
    text: CodeSet,
    read_only: CodeSet,
    data: CodeSet,
    stack_size: u32,
    bss_size: u32,
}

/// A code set: load address and size in bytes.
struct CodeSet {
    address: u32,
    size: u32,
}

fn code_set(sci: &[u8], at: usize) -> Result<CodeSet> {
    Ok(CodeSet {
        address: le_u32(sci, at)?,
        size: le_u32(sci, at + CODE_SET_SIZE)?,
    })
}

fn system_control_info(exheader: &[u8]) -> Result<SystemControlInfo> {
    if exheader.len() < SCI_MIN_SIZE {
        return Err(error(format!(
            "Invalid NCCH ExHeader size {} B: system control info needs {SCI_MIN_SIZE} B",
            exheader.len()
        )));
    }
    Ok(SystemControlInfo {
        app_title: text(&exheader[SCI_APP_TITLE..SCI_APP_TITLE + SCI_APP_TITLE_SIZE]),
        compressed_code: exheader[SCI_FLAGS] & COMPRESS_EXEFS_CODE != 0,
        text: code_set(exheader, SCI_TEXT_CODE_SET)?,
        read_only: code_set(exheader, SCI_RO_CODE_SET)?,
        data: code_set(exheader, SCI_DATA_CODE_SET)?,
        stack_size: le_u32(exheader, SCI_STACK_SIZE)?,
        bss_size: le_u32(exheader, SCI_BSS_SIZE)?,
    })
}

/// One used `ExeFS` file entry, with its range relative to the NCCH.
struct ExefsFile {
    index: usize,
    name: String,
    region: Region,
}

/// The used entries of the `ExeFS` header. Entries with an empty name are
/// unused; every used entry must lie inside the `ExeFS`.
fn exefs_files(header: &[u8], exefs: Region) -> Result<Vec<ExefsFile>> {
    let mut files = Vec::new();
    for index in 0..EXEFS_FILE_COUNT {
        let entry = slice(header, index * EXEFS_ENTRY_SIZE, EXEFS_ENTRY_SIZE)?;
        let name = text(&entry[..EXEFS_NAME_SIZE]);
        if name.is_empty() {
            continue;
        }
        let offset = le_usize(entry, EXEFS_NAME_SIZE, "ExeFS file offset")?;
        let size = le_usize(entry, EXEFS_NAME_SIZE + 4, "ExeFS file size")?;
        let start = EXEFS_HEADER_SIZE + offset;
        let inside = start.checked_add(size).is_some_and(|end| end <= exefs.size);
        if !inside {
            return Err(error(format!(
                "Invalid ExeFS file {name} at 0x{offset:X} + {size} B: beyond the {} ExeFS",
                size_text(exefs.size)
            )));
        }
        files.push(ExefsFile {
            index,
            name,
            region: Region {
                offset: exefs.offset + start,
                size,
            },
        });
    }
    Ok(files)
}

/// The stored SHA-256 of `ExeFS` entry `index`.
fn exefs_hash(header: &[u8], index: usize) -> Result<&[u8]> {
    slice(header, EXEFS_LAST_HASH - SHA256_SIZE * index, SHA256_SIZE)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = ncch_header(data)?;
    let content = &data[..header.content_size];
    let trailing = &data[header.content_size..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the NCCH content at 0x{:X}",
            size_text(trailing.len()),
            header.content_size
        )));
    }
    let exheader = exheader_region(&header)?;
    let kind = if header.is_executable() { "CXI" } else { "CFA" };
    let variant = if header.is_executable() {
        ARM11_VARIANT
    } else {
        "3DS NCCH CFA"
    };
    let mut c = Container::new(FileFormat::N3dsNcch, variant, "n3ds");
    c.consumed = header.content_size;
    if header.is_executable() {
        c.target = Some(ARM11);
    }
    push_ncch_notes(&mut c, &header, kind);

    if header.is_encrypted() {
        push_encrypted_regions(&mut c, content, &header, exheader);
        return Ok(c);
    }
    c.notes
        .push("Content is not encrypted (NoCrypto set)".to_string());
    let sci = match exheader {
        Some(region) => {
            let sci = system_control_info(&content[region.offset..region.end()])?;
            push_sci_notes(&mut c, &sci);
            c.children.push(Child::opaque(
                "ExHeader",
                region.offset,
                &content[region.offset..region.end()],
            ));
            Some(sci)
        }
        None => None,
    };
    push_plain_regions(&mut c, content, &header);
    if header.exefs.size > 0 {
        push_exefs(&mut c, content, &header, sci.as_ref())?;
    }
    if header.romfs.size > 0 {
        c.children.push(Child::opaque(
            "RomFS",
            header.romfs.offset,
            &content[header.romfs.offset..header.romfs.end()],
        ));
        c.notes
            .push("RomFS is listed but its file system is not parsed".to_string());
    }
    c.children.sort_by_key(|child| child.offset);
    if header.is_executable() {
        c.notes.push(ARM11_NOTE.to_string());
    }
    Ok(c)
}

/// The `ExHeader` at 0x200, when the header declares one.
fn exheader_region(header: &NcchHeader) -> Result<Option<Region>> {
    if header.exheader_size == 0 {
        return Ok(None);
    }
    let region = Region {
        offset: NCCH_HEADER_SIZE,
        size: header.exheader_size,
    };
    if header.exheader_size > header.content_size - NCCH_HEADER_SIZE {
        return Err(error(format!(
            "Truncated NCCH ExHeader: {} B at 0x{NCCH_HEADER_SIZE:X} in the {} content",
            header.exheader_size,
            size_text(header.content_size)
        )));
    }
    Ok(Some(region))
}

fn push_ncch_notes(c: &mut Container<'_>, header: &NcchHeader, kind: &str) {
    c.notes.push(format!(
        "3DS NCCH {kind}; product code {}; program ID 0x{:016X}; maker code {}; NCCH version {}",
        header.product_code, header.program_id, header.maker_code, header.version
    ));
    let platform = match header.flags[FLAG_PLATFORM] {
        PLATFORM_CTR => "CTR (Old 3DS)".to_string(),
        PLATFORM_SNAKE => "snake (New 3DS)".to_string(),
        other => format!("unknown 0x{other:02X}"),
    };
    let content_type = header.flags[FLAG_CONTENT_TYPE] >> CONTENT_TYPE_SHIFT;
    c.notes.push(format!(
        "Content platform: {platform}; form type {}; content type {}",
        form_type_name(header.flags[FLAG_CONTENT_TYPE] & FORM_TYPE_MASK),
        content_type_name(content_type)
    ));
    if header.media_unit != 1 << MEDIA_UNIT_SHIFT {
        c.notes
            .push(format!("Media unit size {}", size_text(header.media_unit)));
    }
    if header.flags[FLAG_BITMASK] & NO_MOUNT_ROMFS != 0 {
        c.notes.push("NoMountRomFs is set".to_string());
    }
    c.notes.push(
        "The NCCH header RSA-2048 signature and the ExHeader, logo and RomFS hashes are not verified"
            .to_string(),
    );
    c.push_metadata(
        "n3ds_product_code",
        "Product code",
        header.product_code.clone(),
    );
    c.push_metadata(
        "n3ds_program_id",
        "Program ID",
        format!("0x{:016X}", header.program_id),
    );
    c.push_metadata(
        "n3ds_partition_id",
        "Partition ID",
        format!("0x{:016X}", header.partition_id),
    );
    c.push_metadata("n3ds_platform", "Content platform", platform);
    c.push_metadata(
        "n3ds_encryption",
        "Encryption",
        if header.is_encrypted() {
            "AES-128-CTR"
        } else {
            "none (NoCrypto)"
        },
    );
}

fn form_type_name(form_type: u8) -> &'static str {
    match form_type {
        0 => "not assigned",
        1 => "simple content",
        FORM_EXECUTABLE_WITHOUT_ROMFS => "executable without RomFS",
        _ => "executable",
    }
}

fn content_type_name(content_type: u8) -> String {
    match content_type {
        0 => "unspecified".to_string(),
        1 => "system update".to_string(),
        2 => "manual".to_string(),
        3 => "download play child".to_string(),
        4 => "trial".to_string(),
        5 => "extended system update".to_string(),
        other => format!("unknown {other}"),
    }
}

/// The secondary key slot of a crypto method (flags[3]), per 3dbrew.
fn key_slot(crypto_method: u8) -> Option<u8> {
    match crypto_method {
        0x00 => Some(0x2c),
        0x01 => Some(0x25),
        0x0a => Some(0x18),
        0x0b => Some(0x1b),
        _ => None,
    }
}

/// Encrypted `ExHeader`, `ExeFS` and `RomFS`: listed, never analyzed.
fn push_encrypted_regions<'a>(
    c: &mut Container<'a>,
    content: &'a [u8],
    header: &NcchHeader,
    exheader: Option<Region>,
) {
    let method = header.flags[FLAG_CRYPTO_METHOD];
    let slot = match key_slot(method) {
        Some(slot) => format!("secondary key slot 0x{slot:02X}"),
        None => "unknown key slot".to_string(),
    };
    let mut note = format!(
        "Content is AES-128-CTR encrypted (NoCrypto clear; crypto method 0x{method:02X}, {slot}); ExHeader, ExeFS and RomFS are opaque"
    );
    if header.flags[FLAG_BITMASK] & FIXED_CRYPTO_KEY != 0 {
        note.push_str("; FixedCryptoKey set");
    }
    if header.flags[FLAG_BITMASK] & NEW_KEY_Y_GENERATOR != 0 {
        note.push_str("; new keyY generator");
    }
    c.notes.push(note);
    c.opaque = true;
    let encrypted = [
        ("ExHeader (encrypted)", exheader),
        ("ExeFS (encrypted)", Some(header.exefs)),
        ("RomFS (encrypted)", Some(header.romfs)),
    ];
    for (label, region) in encrypted {
        let Some(region) = region.filter(|region| region.size > 0) else {
            continue;
        };
        c.children.push(Child::opaque(
            label,
            region.offset,
            &content[region.offset..region.end()],
        ));
    }
    push_plain_regions(c, content, header);
    c.children.sort_by_key(|child| child.offset);
}

/// The plain region (SDK library names) and the logo are data.
fn push_plain_regions<'a>(c: &mut Container<'a>, content: &'a [u8], header: &NcchHeader) {
    for (label, region) in [("Plain region", header.plain), ("Logo", header.logo)] {
        if region.size > 0 {
            c.children.push(Child::opaque(
                label,
                region.offset,
                &content[region.offset..region.end()],
            ));
        }
    }
}

fn push_sci_notes(c: &mut Container<'_>, sci: &SystemControlInfo) {
    let compression = if sci.compressed_code {
        "compressed (CompressExefsCode)"
    } else {
        "not compressed"
    };
    c.notes.push(format!(
        "ExHeader: application title {}; .code {compression}; text 0x{:08X} + {} B; read-only data 0x{:08X} + {} B; data 0x{:08X} + {} B; BSS {} B; stack {} B",
        sci.app_title,
        sci.text.address,
        sci.text.size,
        sci.read_only.address,
        sci.read_only.size,
        sci.data.address,
        sci.data.size,
        sci.bss_size,
        sci.stack_size
    ));
    c.push_metadata("n3ds_app_title", "Application title", sci.app_title.clone());
    c.push_metadata(
        "n3ds_text_address",
        "Text address",
        format!("0x{:08X}", sci.text.address),
    );
}

/// `ExeFS` files as children: `.code` decoded and classified as ARM11 code,
/// the banner, icon and logo as data. The superblock hash and every file
/// hash are checked; a mismatch is reported, not rejected.
fn push_exefs<'a>(
    c: &mut Container<'a>,
    content: &'a [u8],
    header: &NcchHeader,
    sci: Option<&SystemControlInfo>,
) -> Result<()> {
    let exefs = header.exefs;
    if exefs.size < EXEFS_HEADER_SIZE {
        return Err(error(format!(
            "Truncated ExeFS header: {} B of {EXEFS_HEADER_SIZE} B",
            exefs.size
        )));
    }
    let exefs_header = &content[exefs.offset..exefs.offset + EXEFS_HEADER_SIZE];
    let files = exefs_files(exefs_header, exefs)?;
    let superblock = if header.exefs_hash_size == 0 || header.exefs_hash_size > exefs.size {
        "superblock hash region is empty or beyond the ExeFS; not verified".to_string()
    } else {
        let hashed = &content[exefs.offset..exefs.offset + header.exefs_hash_size];
        let stored = slice(content, EXEFS_SUPERBLOCK_HASH, SHA256_SIZE)?;
        if Sha256::digest(hashed).as_slice() == stored {
            "superblock SHA-256 verified".to_string()
        } else {
            "superblock SHA-256 does not match".to_string()
        }
    };
    let mut verified = 0usize;
    let mut mismatched = Vec::new();
    for file in &files {
        let bytes = &content[file.region.offset..file.region.end()];
        if Sha256::digest(bytes).as_slice() == exefs_hash(exefs_header, file.index)? {
            verified += 1;
        } else {
            mismatched.push(file.name.clone());
        }
        let child = exefs_child(c, file, bytes, sci);
        c.children.push(child);
    }
    let mismatch = if mismatched.is_empty() {
        String::new()
    } else {
        format!("; mismatch for {}", mismatched.join(", "))
    };
    c.notes.push(format!(
        "ExeFS: {} files; {superblock}; file SHA-256 verified for {verified} of {}{mismatch}",
        files.len(),
        files.len()
    ));
    Ok(())
}

/// One `ExeFS` file as a child. Only `.code` is code, and only when the
/// `ExHeader` says whether it is compressed.
fn exefs_child<'a>(
    c: &mut Container<'a>,
    file: &ExefsFile,
    bytes: &'a [u8],
    sci: Option<&SystemControlInfo>,
) -> Child<'a> {
    let offset = file.region.offset;
    if file.name != CODE_FILE {
        return Child::opaque(file.name.clone(), offset, bytes);
    }
    let Some(sci) = sci else {
        c.notes.push(
            ".code is opaque: without an ExHeader its compression is not recorded".to_string(),
        );
        return Child::opaque(CODE_FILE, offset, bytes);
    };
    if !sci.compressed_code {
        return Child::stored(CODE_FILE, offset, bytes).with_target(ARM11);
    }
    match compressed::decode(Codec::Blz, bytes) {
        Ok(decoded) => {
            c.notes.push(format!(
                ".code: {} stored, {} decoded (BLZ)",
                size_text(bytes.len()),
                size_text(decoded.data.len())
            ));
            Child::decoded(
                CODE_FILE,
                offset,
                bytes.len(),
                Cow::Owned(decoded.data),
                Codec::Blz.name(),
            )
            .with_target(ARM11)
        }
        Err(e) => {
            c.notes
                .push(format!(".code is opaque: it does not decode as BLZ ({e})"));
            Child::opaque(CODE_FILE, offset, bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_regions_scale_by_the_unit_and_stay_inside_the_content() {
        let mut header = vec![0u8; 8];
        header[..4].copy_from_slice(&2u32.to_le_bytes());
        header[4..].copy_from_slice(&3u32.to_le_bytes());
        let region = media_region(&header, 0, 0x200, 0x1000, "ExeFS").unwrap();
        assert_eq!((region.offset, region.size), (0x400, 0x600));
        assert!(media_region(&header, 0, 0x200, 0x800, "ExeFS").is_err());
        assert!(media_region(&header, 0, 1 << 62, usize::MAX, "ExeFS").is_err());
    }

    #[test]
    fn key_slots_follow_the_crypto_method() {
        assert_eq!(key_slot(0), Some(0x2c));
        assert_eq!(key_slot(0x0b), Some(0x1b));
        assert_eq!(key_slot(2), None);
    }
}
