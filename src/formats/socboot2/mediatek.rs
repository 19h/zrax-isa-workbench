//! `MediaTek` preloader images: the generic device header (`EMMC_BOOT`,
//! `SF_BOOT`, `SDMMC_BOOT`, `UFS_BOOT`), the boot ROM layout (BRLYT) and
//! the GFH record chain that starts with `GFH_FILE_INFO`.
//!
//! Sources: U-Boot `tools/mtk_image.[ch]` (`union gen_boot_header`,
//! `struct brom_layout_header`, `struct gfh_common_header`,
//! `struct gfh_file_info`, `struct gfh_brom_cfg`, `put_hash`); the
//! vendor's `fbtool.c` (`EMMC_HEADER_v1`, `BR_Layout_v1`, `GFH_FILE_INFO_v1`,
//! `strip_pl_hdr`); mtkclient (`UFS_BOOT` name, `MMM\x01` check). Only the
//! `UFS_BOOT` name is confirmed for UFS; its header is read as the generic
//! device header and must lead to valid BRLYT and GFH records.
//!
//! Units: on eMMC, NOR and SD the BRLYT addresses are bytes from the start
//! of the device header; NAND layouts use pages and are not supported.

use super::*;
use sha2::{Digest, Sha256};

/// Generic device header (`gen_boot_header`, 0x200 bytes): name (0, 12 B,
/// NUL-padded), version (0x0C), size (0x10: the offset of the BRLYT).
const DEVICE_NAME_SIZE: usize = 12;
const DEVICE_VERSION: usize = 0x0c;
const DEVICE_SIZE: usize = 0x10;
const DEVICE_FIELDS_SIZE: usize = 0x14;
const DEVICE_HEADER_VERSION: u32 = 1;

/// Device header names. The first three are confirmed with their NUL
/// padding; mtkclient matches `UFS_BOOT` on its eight characters only.
const DEVICE_NAMES: [(&[u8], Layout, bool); 4] = [
    (b"EMMC_BOOT", Layout::MediatekEmmc, true),
    (b"SF_BOOT", Layout::MediatekSf, true),
    (b"SDMMC_BOOT", Layout::MediatekSdmmc, true),
    (b"UFS_BOOT", Layout::MediatekUfs, false),
];

/// BRLYT (`brom_layout_header`, 0x28 bytes): name (0, 8 B), version (8),
/// GFH address (0x0C), image end (0x10), magic (0x14), device type (0x18),
/// GFH address as `fbtool.c` reads it (0x1C), boundary (0x20), attribute
/// (0x24).
const BRLYT_NAME: &[u8; 8] = b"BRLYT\0\0\0";
const BRLYT_VERSION: usize = 0x08;
const BRLYT_GFH_ADDRESS: usize = 0x0c;
const BRLYT_TOTAL_SIZE: usize = 0x10;
const BRLYT_MAGIC_OFFSET: usize = 0x14;
const BRLYT_TYPE: usize = 0x18;
const BRLYT_BL_BEGIN: usize = 0x1c;
const BRLYT_SIZE: usize = 0x28;
const BRLYT_HEADER_VERSION: u32 = 1;
/// `m_bl_exist_magic`, `"BBBB"`.
const BRLYT_MAGIC: u32 = 0x4242_4242;

/// BRLYT device types (`mtk_image.h` `BRLYT_TYPE_*`).
const BRLYT_TYPE_NAND: u32 = 0x1_0002;
const BRLYT_TYPE_EMMC: u32 = 0x1_0005;
const BRLYT_TYPE_NOR: u32 = 0x1_0007;
const BRLYT_TYPE_SDMMC: u32 = 0x1_0008;
const BRLYT_TYPE_SNAND: u32 = 0x1_0009;

/// GFH common header (`gfh_common_header`, 8 bytes): magic and version
/// (0: `"MMM"` in the low 24 bits, record version in the high byte), size
/// (4, u16), type (6, u16).
const GFH_MAGIC: u32 = 0x004d_4d4d;
const GFH_MAGIC_MASK: u32 = 0x00ff_ffff;
const GFH_VERSION_SHIFT: u32 = 24;
const GFH_RECORD_SIZE: usize = 4;
const GFH_RECORD_TYPE: usize = 6;
const GFH_COMMON_SIZE: usize = 8;

/// GFH record types (`GFH_TYPE_*`).
const GFH_FILE_INFO: u16 = 0;
const GFH_BL_INFO: u16 = 1;
const GFH_ANTI_CLONE: u16 = 2;
const GFH_BL_SEC_KEY: u16 = 3;
const GFH_BROM_CFG: u16 = 7;
const GFH_BROM_SEC_CFG: u16 = 8;

/// `GFH_FILE_INFO` (0x38 bytes): common header, name (8, 12 B), file
/// version (0x14), file type (0x18, u16), flash type (0x1A), signature
/// type (0x1B), load address of the GFH start (0x1C), file length from the
/// GFH start (0x20), maximum size (0x24), GFH chain size (0x28), signature
/// size (0x2C), jump offset from the GFH start (0x30), attributes (0x34).
const FILE_INFO_NAME: &[u8; 10] = b"FILE_INFO\0";
const FILE_INFO_NAME_OFFSET: usize = 0x08;
const FILE_INFO_FILE_TYPE: usize = 0x18;
const FILE_INFO_FLASH_TYPE: usize = 0x1a;
const FILE_INFO_SIG_TYPE: usize = 0x1b;
const FILE_INFO_LOAD_ADDRESS: usize = 0x1c;
const FILE_INFO_FILE_LENGTH: usize = 0x20;
const FILE_INFO_MAX_SIZE: usize = 0x24;
const FILE_INFO_CONTENT_OFFSET: usize = 0x28;
const FILE_INFO_SIG_SIZE: usize = 0x2c;
const FILE_INFO_JUMP_OFFSET: usize = 0x30;
const FILE_INFO_SIZE: usize = 0x38;

/// Signature types (`GFH_SIG_TYPE_*`): none, or a SHA-256 hash over the
/// image before it (`put_hash`). Other values are signed preloaders whose
/// schemes are not documented in the sources read.
const SIG_TYPE_NONE: u8 = 0;
const SIG_TYPE_SHA256: u8 = 1;
const SHA256_SIZE: usize = 32;

/// `gfh_brom_cfg`: `cfg_bits` (0x08) and `jump_bl_arm64` (0x55). Both mark
/// a hand-off to the bootloader in `AArch64`.
const BROM_CFG_BITS: usize = 0x08;
const BROM_CFG_JUMP_BL_ARM64: usize = 0x55;
const BROM_CFG_JUMP_BL_ARM64_EN: u32 = 0x1000;
const JUMP_BL_ARM64: u8 = 0x64;

/// Most GFH record types named in the notes.
const MAX_NAMED_RECORDS: usize = 8;

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    for (name, layout, padded) in DEVICE_NAMES {
        let is_padded = !padded || data.get(name.len()) == Some(&0);
        if data.starts_with(name) && is_padded {
            return Some(layout);
        }
    }
    is_file_info(data, 0).then_some(Layout::MediatekGfh)
}

/// Whether a `GFH_FILE_INFO` record starts at `at`: magic, size 0x38,
/// type 0 and the name `FILE_INFO`.
fn is_file_info(data: &[u8], at: usize) -> bool {
    let Ok(record) = range(data, at, FILE_INFO_SIZE, "GFH_FILE_INFO") else {
        return false;
    };
    let magic_ok = le_u32(record, 0).is_ok_and(|word| word & GFH_MAGIC_MASK == GFH_MAGIC);
    let size_ok = le_u16(record, GFH_RECORD_SIZE).ok().map(usize::from) == Some(FILE_INFO_SIZE);
    let type_ok = le_u16(record, GFH_RECORD_TYPE).ok() == Some(GFH_FILE_INFO);
    let name_end = FILE_INFO_NAME_OFFSET + FILE_INFO_NAME.len();
    magic_ok && size_ok && type_ok && &record[FILE_INFO_NAME_OFFSET..name_end] == FILE_INFO_NAME
}

fn device_type_name(device_type: u32) -> &'static str {
    match device_type {
        BRLYT_TYPE_NAND => "NAND",
        BRLYT_TYPE_EMMC => "eMMC",
        BRLYT_TYPE_NOR => "NOR",
        BRLYT_TYPE_SDMMC => "SD/MMC",
        BRLYT_TYPE_SNAND => "SPI-NAND",
        _ => "unknown",
    }
}

fn record_type_name(record_type: u16) -> String {
    match record_type {
        GFH_FILE_INFO => "FILE_INFO".into(),
        GFH_BL_INFO => "BL_INFO".into(),
        GFH_ANTI_CLONE => "ANTI_CLONE".into(),
        GFH_BL_SEC_KEY => "BL_SEC_KEY".into(),
        GFH_BROM_CFG => "BROM_CFG".into(),
        GFH_BROM_SEC_CFG => "BROM_SEC_CFG".into(),
        other => format!("type 0x{other:X}"),
    }
}

/// The BRLYT at `at`, validated, and the GFH offset it names.
fn brlyt_gfh_offset(data: &[u8], at: usize, notes: &mut Vec<String>) -> Result<usize> {
    let brlyt = range(data, at, BRLYT_SIZE, "BRLYT")?;
    if &brlyt[..BRLYT_NAME.len()] != BRLYT_NAME {
        return Err(error(format!("Missing BRLYT name at 0x{at:X}")));
    }
    let version = le_u32(brlyt, BRLYT_VERSION)?;
    if version != BRLYT_HEADER_VERSION {
        return Err(error(format!("Unsupported BRLYT version {version}")));
    }
    if le_u32(brlyt, BRLYT_MAGIC_OFFSET)? != BRLYT_MAGIC {
        return Err(error(format!(
            "Missing BRLYT magic BBBB at 0x{:X}",
            at + BRLYT_MAGIC_OFFSET
        )));
    }
    let device_type = le_u32(brlyt, BRLYT_TYPE)?;
    if matches!(device_type, BRLYT_TYPE_NAND | BRLYT_TYPE_SNAND) {
        return Err(error(format!(
            "Unsupported BRLYT device type 0x{device_type:X} ({}): addresses are in pages",
            device_type_name(device_type)
        )));
    }
    notes.push(format!(
        "BRLYT at 0x{at:X}; device type 0x{device_type:X} ({})",
        device_type_name(device_type)
    ));
    // `fbtool.c` reads the GFH at 0x1C, mtkclient at 0x0C; U-Boot writes
    // the same value to both.
    let bl_begin = le_size(brlyt, BRLYT_BL_BEGIN)?;
    let boot_region = le_size(brlyt, BRLYT_GFH_ADDRESS)?;
    if bl_begin == boot_region {
        return Ok(bl_begin);
    }
    let gfh = [bl_begin, boot_region]
        .into_iter()
        .find(|&offset| is_file_info(data, offset))
        .ok_or_else(|| {
            error(format!(
                "Missing GFH_FILE_INFO at the BRLYT addresses 0x{bl_begin:X} and 0x{boot_region:X}"
            ))
        })?;
    notes.push(format!(
        "BRLYT names two GFH addresses, 0x{bl_begin:X} and 0x{boot_region:X}; GFH_FILE_INFO found at 0x{gfh:X}"
    ));
    Ok(gfh)
}

/// The fields of a `GFH_FILE_INFO` record that locate the code.
struct FileInfo {
    file_type: u16,
    flash_type: u8,
    sig_type: u8,
    /// Target address of the GFH start.
    load_address: u32,
    /// Bytes from the GFH start to the end of the signature.
    file_length: usize,
    max_size: u32,
    /// Size of the GFH chain in bytes.
    content_offset: usize,
    sig_size: usize,
    /// Code start, in bytes from the GFH start.
    jump_offset: usize,
}

/// The `GFH_FILE_INFO` record at `gfh`, with the checks of `strip_pl_hdr`.
fn file_info(data: &[u8], gfh: usize) -> Result<FileInfo> {
    let record = range(data, gfh, FILE_INFO_SIZE, "GFH_FILE_INFO")?;
    if !is_file_info(data, gfh) {
        return Err(error(format!("Missing GFH_FILE_INFO record at 0x{gfh:X}")));
    }
    let info = FileInfo {
        file_type: le_u16(record, FILE_INFO_FILE_TYPE)?,
        flash_type: record[FILE_INFO_FLASH_TYPE],
        sig_type: record[FILE_INFO_SIG_TYPE],
        load_address: le_u32(record, FILE_INFO_LOAD_ADDRESS)?,
        file_length: le_size(record, FILE_INFO_FILE_LENGTH)?,
        max_size: le_u32(record, FILE_INFO_MAX_SIZE)?,
        content_offset: le_size(record, FILE_INFO_CONTENT_OFFSET)?,
        sig_size: le_size(record, FILE_INFO_SIG_SIZE)?,
        jump_offset: le_size(record, FILE_INFO_JUMP_OFFSET)?,
    };
    let code_start = info.jump_offset.checked_add(info.sig_size);
    if code_start.map_or(true, |needed| info.file_length < needed) {
        return Err(error(format!(
            "Invalid GFH_FILE_INFO: file length {} B is shorter than the jump offset 0x{:X} plus the {} B signature",
            info.file_length, info.jump_offset, info.sig_size
        )));
    }
    if info.jump_offset < FILE_INFO_SIZE {
        return Err(error(format!(
            "Invalid GFH_FILE_INFO jump offset 0x{:X}: inside the record",
            info.jump_offset
        )));
    }
    if info.content_offset < FILE_INFO_SIZE || info.content_offset > info.file_length {
        return Err(error(format!(
            "Invalid GFH_FILE_INFO content offset 0x{:X}",
            info.content_offset
        )));
    }
    Ok(info)
}

/// The GFH records in `chain` (the bytes before the content offset), as
/// type and record bytes. The chain may end before the content offset.
fn gfh_records<'a>(
    chain: &'a [u8],
    gfh: usize,
    notes: &mut Vec<String>,
) -> Result<Vec<(u16, &'a [u8])>> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + GFH_COMMON_SIZE <= chain.len() {
        if le_u32(chain, pos)? & GFH_MAGIC_MASK != GFH_MAGIC {
            notes.push(format!(
                "The GFH chain ends at 0x{:X}, before the content offset",
                gfh + pos
            ));
            break;
        }
        let size = usize::from(le_u16(chain, pos + GFH_RECORD_SIZE)?);
        let record_type = le_u16(chain, pos + GFH_RECORD_TYPE)?;
        if size < GFH_COMMON_SIZE || size > chain.len() - pos {
            return Err(error(format!(
                "Invalid GFH record at 0x{:X}: size {size} B",
                gfh + pos
            )));
        }
        records.push((record_type, &chain[pos..pos + size]));
        pos += size;
    }
    Ok(records)
}

/// The `AArch64` hand-off a `GFH_BROM_CFG` record requests, and the note
/// that states the evidence.
fn brom_cfg_target(records: &[(u16, &[u8])]) -> (Option<Target>, String) {
    let Some((_, record)) = records.iter().find(|(t, _)| *t == GFH_BROM_CFG) else {
        return (
            None,
            "No GFH_BROM_CFG record; the header names no instruction set".into(),
        );
    };
    let cfg_bits = le_u32(record, BROM_CFG_BITS).ok();
    let jump_byte = record.get(BROM_CFG_JUMP_BL_ARM64).copied();
    let (Some(cfg_bits), Some(jump_byte)) = (cfg_bits, jump_byte) else {
        return (
            None,
            format!(
                "GFH_BROM_CFG record of {} B is too short for the AArch64 hand-off fields",
                record.len()
            ),
        );
    };
    let enabled = cfg_bits & BROM_CFG_JUMP_BL_ARM64_EN != 0;
    let requested = jump_byte == JUMP_BL_ARM64;
    match (enabled, requested) {
        (true, true) => (
            Some(Target::new(Isa::AArch64, 64, Endianness::Little)),
            "GFH_BROM_CFG requests an AArch64 hand-off (cfg_bits 0x1000 and jump_bl_arm64 0x64)"
                .into(),
        ),
        (false, false) => (
            None,
            "GFH_BROM_CFG does not request an AArch64 hand-off; that does not establish AArch32, so the ISA comes from the code model"
                .into(),
        ),
        _ => (
            None,
            format!(
                "GFH_BROM_CFG AArch64 fields disagree (cfg_bits 0x{cfg_bits:X}, jump_bl_arm64 0x{jump_byte:02X}); no instruction set claimed"
            ),
        ),
    }
}

/// The GFH record types, in chain order, as one note.
fn records_note(records: &[(u16, &[u8])]) -> String {
    let mut names: Vec<String> = records
        .iter()
        .take(MAX_NAMED_RECORDS)
        .map(|(record_type, _)| record_type_name(*record_type))
        .collect();
    if records.len() > MAX_NAMED_RECORDS {
        names.push(format!("{} more", records.len() - MAX_NAMED_RECORDS));
    }
    format!("GFH records: {}", names.join(", "))
}

/// The signature or hash after the code, as an opaque child, with a note.
/// A SHA-256 hash is checked the way U-Boot's `put_hash` writes it.
fn signature_child<'a>(
    image: &'a [u8],
    gfh: usize,
    info: &FileInfo,
    notes: &mut Vec<String>,
) -> Option<Child<'a>> {
    let sig_start = info.file_length - info.sig_size;
    let signature = &image[sig_start..];
    match info.sig_type {
        SIG_TYPE_NONE if info.sig_size == 0 => {
            notes.push("No signature or hash (sig_type 0)".into());
            return None;
        }
        SIG_TYPE_SHA256 if info.sig_size == SHA256_SIZE => {
            let verified = Sha256::digest(&image[..sig_start]).as_slice() == signature;
            notes.push(if verified {
                "SHA-256 hash over the image verified (integrity only; not a signature)".into()
            } else {
                "SHA-256 hash field does not match the image; not verified".into()
            });
        }
        sig_type => notes.push(format!(
            "Signature type {sig_type}, {} B; not verified",
            info.sig_size
        )),
    }
    (info.sig_size > 0).then(|| Child::opaque("Signature", gfh + sig_start, signature))
}

/// Parse the GFH image at `gfh` into `c`: notes, metadata, the code child,
/// the signature and any recognized data after the image.
fn parse_gfh<'a>(data: &'a [u8], gfh: usize, c: &mut Container<'a>) -> Result<()> {
    let info = file_info(data, gfh)?;
    let image = range(data, gfh, info.file_length, "preloader image")?;
    let records = gfh_records(&image[..info.content_offset], gfh, &mut c.notes)?;
    let (target, isa_note) = brom_cfg_target(&records);
    let version = le_u32(image, 0)? >> GFH_VERSION_SHIFT;
    c.notes.push(format!(
        "MediaTek preloader; GFH_FILE_INFO version {version} at 0x{gfh:X}; file type {}, flash type {}",
        info.file_type, info.flash_type
    ));
    c.notes.push(records_note(&records));
    c.notes.push(isa_note);
    if info.jump_offset != info.content_offset {
        c.notes.push(format!(
            "Code starts at the jump offset 0x{:X}, not at the end of the GFH chain (0x{:X})",
            info.jump_offset, info.content_offset
        ));
    }
    let entry = u64::from(info.load_address) + info.jump_offset as u64;
    c.target = target;
    c.entry = Some(entry);
    c.consumed = gfh + info.file_length;
    c.push_metadata(
        "mediatek_load_address",
        "GFH load address",
        format!("0x{:08X}", info.load_address),
    );
    c.push_metadata(
        "mediatek_file_length",
        "File length (B)",
        info.file_length as u64,
    );
    c.push_metadata(
        "mediatek_max_size",
        "Maximum size (B)",
        u64::from(info.max_size),
    );
    c.push_metadata(
        "mediatek_sig_type",
        "Signature type",
        u64::from(info.sig_type),
    );
    let code_end = info.file_length - info.sig_size;
    let code = &image[info.jump_offset..code_end];
    let mut code_child = Child::stored("Preloader code", gfh + info.jump_offset, code);
    if let Some(target) = target {
        code_child = code_child.with_target(target);
    }
    c.children.push(code_child);
    if let Some(signature) = signature_child(image, gfh, &info, &mut c.notes) {
        c.children.push(signature);
    }
    let end = c.consumed;
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
        c.children.push(member);
    }
    Ok(())
}

pub(super) fn parse_device(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = range(data, 0, DEVICE_FIELDS_SIZE, "MediaTek device header")?;
    let name = text_field(&header[..DEVICE_NAME_SIZE]);
    let expected = DEVICE_NAMES
        .iter()
        .find(|(_, candidate, _)| *candidate == layout)
        .map(|(name, _, _)| *name)
        .ok_or_else(|| error("Unsupported MediaTek layout"))?;
    if !header.starts_with(expected) {
        return Err(error("Missing MediaTek device header name"));
    }
    let version = le_u32(header, DEVICE_VERSION)?;
    if version != DEVICE_HEADER_VERSION {
        return Err(error(format!(
            "Unsupported MediaTek device header version {version}"
        )));
    }
    let brlyt_offset = le_size(header, DEVICE_SIZE)?;
    if brlyt_offset < DEVICE_FIELDS_SIZE {
        return Err(error(format!(
            "Invalid MediaTek device header size 0x{brlyt_offset:X}"
        )));
    }

    let mut c = Container::new(FileFormat::MediatekPreloader, layout.label(), "mediatek");
    c.notes.push(format!(
        "{name} device header, version {version}; BRLYT at 0x{brlyt_offset:X}"
    ));
    if layout == Layout::MediatekUfs {
        c.notes.push(
            "The UFS_BOOT header layout is not documented in the sources read; it was read as the generic device header and validated by the BRLYT and GFH records"
                .into(),
        );
    }
    let gfh = brlyt_gfh_offset(data, brlyt_offset, &mut c.notes)?;
    let total_size = le_u32(data, brlyt_offset + BRLYT_TOTAL_SIZE)?;
    c.push_metadata(
        "mediatek_brlyt_total_size",
        "BRLYT image end",
        format!("0x{total_size:X}"),
    );
    parse_gfh(data, gfh, &mut c)?;
    Ok(c)
}

pub(super) fn parse_gfh_image(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(
        FileFormat::MediatekPreloader,
        Layout::MediatekGfh.label(),
        "mediatek",
    );
    parse_gfh(data, 0, &mut c)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GFH record header: magic with version 1, size, type.
    fn record(size: u16, record_type: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; usize::from(size)];
        bytes[..4].copy_from_slice(&(GFH_MAGIC | 1 << GFH_VERSION_SHIFT).to_le_bytes());
        bytes[4..6].copy_from_slice(&size.to_le_bytes());
        bytes[6..8].copy_from_slice(&record_type.to_le_bytes());
        bytes
    }

    #[test]
    fn brom_cfg_needs_both_aarch64_fields() {
        let mut cfg = record(0x64, GFH_BROM_CFG);
        let none = brom_cfg_target(&[(GFH_BROM_CFG, &cfg)]);
        assert!(none.0.is_none());
        cfg[BROM_CFG_BITS..BROM_CFG_BITS + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(brom_cfg_target(&[(GFH_BROM_CFG, &cfg)]).0.is_none());
        cfg[BROM_CFG_JUMP_BL_ARM64] = JUMP_BL_ARM64;
        assert_eq!(
            brom_cfg_target(&[(GFH_BROM_CFG, &cfg)]).0,
            Some(Target::new(Isa::AArch64, 64, Endianness::Little))
        );
        let short = record(0x20, GFH_BROM_CFG);
        assert!(brom_cfg_target(&[(GFH_BROM_CFG, &short)]).0.is_none());
    }

    #[test]
    fn gfh_records_stop_at_a_missing_magic_and_reject_bad_sizes() {
        let mut chain = record(0x38, GFH_FILE_INFO);
        chain.extend(record(0x0c, GFH_BL_INFO));
        chain.extend([0u8; 16]);
        let mut notes = Vec::new();
        let records = gfh_records(&chain, 0, &mut notes).expect("valid chain");
        assert_eq!(records.len(), 2);
        assert_eq!(notes.len(), 1);
        let mut bad = record(0x38, GFH_FILE_INFO);
        bad[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert!(gfh_records(&bad, 0, &mut notes).is_err());
    }
}
