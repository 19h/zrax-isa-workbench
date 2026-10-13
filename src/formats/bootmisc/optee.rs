//! OP-TEE OS images with the `OPTE` header.
//!
//! Layouts, from `optee_os` 4.3.0 `scripts/gen_tee_bin.py`
//! (`output_header_v1`, `output_header_v2`, `get_arch_id`), TF-A v2.11.0
//! `include/lib/optee_utils.h` (`optee_header_t`, `optee_image_t`) and
//! `lib/optee/optee_utils.c` (`tee_validate_header`, `parse_optee_header`,
//! `parse_optee_image`), and U-Boot `include/tee/optee.h` (`struct
//! optee_header`) and `lib/optee/optee.c` (`optee_verify_image`). All
//! fields are little-endian.
//!
//! Common header: magic (0), version (4, one byte), architecture (5, one
//! byte: 0 `AArch32`, 1 `AArch64`), flags (6, 16 bits, unused).
//!
//! Version 1 (`tee.bin`, 28 bytes): init size (8), init load address high
//! (0x0C) and low (0x10) words, init memory usage (0x14), paged size
//! (0x18); the init part and then the paged part follow the header, and
//! U-Boot requires the file to be exactly header, init and paged parts.
//!
//! Version 2 (`tee-header_v2.bin`): image count (8), then 16-byte records
//! of load address high, load address low, image ID (0 pager, 1 paged) and
//! size. The header is a file of its own; `gen_tee_bin.py` writes the pager
//! and pageable images to separate files, so this file holds no code.

use super::*;

/// `TEE_MAGIC_NUM_OPTEE`, the bytes `OPTE` read little-endian.
const OPTEE_MAGIC: u32 = 0x4554_504f;

/// Header versions (`output_header_v1`, `output_header_v2`).
const VERSION_1: u8 = 1;
const VERSION_2: u8 = 2;

/// Common header fields.
const VERSION_OFFSET: usize = 4;
const ARCH_OFFSET: usize = 5;
const FLAGS_OFFSET: usize = 6;

/// `OPTEE_ARCH_ARM32` and `OPTEE_ARCH_ARM64`.
const ARCH_ARM32: u8 = 0;
const ARCH_ARM64: u8 = 1;

/// Version 1 fields and size (`struct optee_header` in U-Boot).
const V1_INIT_SIZE: usize = 0x08;
const V1_LOAD_HI: usize = 0x0c;
const V1_LOAD_LO: usize = 0x10;
const V1_INIT_MEM_USAGE: usize = 0x14;
const V1_PAGED_SIZE: usize = 0x18;
const V1_HEADER_SIZE: usize = 0x1c;

/// Version 2 fields and record size (`optee_header_t`, `optee_image_t`).
const V2_IMAGE_COUNT: usize = 0x08;
const V2_HEADER_SIZE: usize = 0x0c;
const V2_IMAGE_SIZE: usize = 0x10;

/// `OPTEE_MAX_NUM_IMAGES`: TF-A accepts one or two images.
const MAX_IMAGES: u32 = 2;

/// `OPTEE_PAGER_IMAGE_ID` and `OPTEE_PAGED_IMAGE_ID`.
const PAGER_IMAGE_ID: u32 = 0;
const PAGED_IMAGE_ID: u32 = 1;

/// Both load address words set to this value: the loader decides the
/// address (`parse_optee_image`).
const LOADER_DECIDES: u32 = 0xffff_ffff;

/// The magic and a documented header version. Requiring the version byte
/// keeps text that starts with "OPTE" from becoming a parse error.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if le_u32(data, 0).ok()? != OPTEE_MAGIC {
        return None;
    }
    match *data.get(VERSION_OFFSET)? {
        VERSION_1 => Some(Layout::OpteeV1),
        VERSION_2 => Some(Layout::OpteeV2),
        _ => None,
    }
}

/// What the architecture field names.
struct Arch {
    target: Target,
    /// The execution state, for notes.
    name: &'static str,
}

/// The architecture field: an explicit target. It does not state the
/// A32 code byte order, so that order comes from the code.
fn arch_target(arch: u8) -> Result<Arch> {
    let (target, name) = match arch {
        ARCH_ARM32 => (Target::without_byte_order(Isa::Arm, 32), "AArch32"),
        ARCH_ARM64 => (Target::new(Isa::AArch64, 64, Endianness::Little), "AArch64"),
        other => return Err(error(format!("Unknown OP-TEE architecture {other}"))),
    };
    Ok(Arch { target, name })
}

/// Architecture and flags notes and metadata shared by both versions.
fn describe_common(c: &mut Container<'_>, header: &[u8], arch_name: &str) -> Result<()> {
    let flags = le_u16(header, FLAGS_OFFSET)?;
    c.notes.push(format!(
        "Architecture field {} names {arch_name} (optee_os gen_tee_bin.py get_arch_id)",
        header[ARCH_OFFSET]
    ));
    if flags != 0 {
        c.notes.push(format!(
            "Header flags 0x{flags:04X}; OP-TEE and TF-A define none"
        ));
    }
    c.push_metadata("optee_arch", "Architecture", arch_name);
    c.push_metadata("optee_flags", "Flags", format!("0x{flags:04X}"));
    Ok(())
}

/// The A32 code byte order is not a header field.
fn byte_order_note(c: &mut Container<'_>, arch: u8) {
    if arch == ARCH_ARM32 {
        c.notes.push(
            "The header does not state the A32 code byte order; it comes from the code".into(),
        );
    }
}

/// A 64-bit load address from its high and low words.
fn load_address(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

pub(super) fn parse_v1(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, V1_HEADER_SIZE, "OP-TEE v1 header")?;
    if le_u32(header, 0)? != OPTEE_MAGIC || header[VERSION_OFFSET] != VERSION_1 {
        return Err(error("Missing OP-TEE magic and header version 1"));
    }
    let arch = header[ARCH_OFFSET];
    let Arch {
        target,
        name: arch_name,
    } = arch_target(arch)?;
    let init_size = to_usize(le_u32(header, V1_INIT_SIZE)?.into(), "OP-TEE init size")?;
    let load = load_address(le_u32(header, V1_LOAD_HI)?, le_u32(header, V1_LOAD_LO)?);
    let init_mem_usage = le_u32(header, V1_INIT_MEM_USAGE)?;
    let paged_size = to_usize(le_u32(header, V1_PAGED_SIZE)?.into(), "OP-TEE paged size")?;
    if init_size == 0 {
        return Err(error("Invalid OP-TEE init size 0 B: the pager is missing"));
    }
    let init = range(data, V1_HEADER_SIZE, init_size, "OP-TEE init part")?;
    let paged_offset = V1_HEADER_SIZE + init_size;
    let paged = range(data, paged_offset, paged_size, "OP-TEE paged part")?;
    let end = paged_offset + paged_size;
    expect_padding(data, end, "OP-TEE image")?;

    let mut c = Container::new(FileFormat::OpteeImage, Layout::OpteeV1.label(), "optee");
    c.target = Some(target);
    c.entry = Some(load);
    c.consumed = end;
    c.notes.push(format!(
        "OP-TEE header version 1: init part {} at 0x{V1_HEADER_SIZE:X}, paged part {} at 0x{paged_offset:X}",
        size_text(init_size),
        size_text(paged_size)
    ));
    describe_common(&mut c, header, arch_name)?;
    byte_order_note(&mut c, arch);
    c.notes.push(format!(
        "Init load address and entry point 0x{load:X}; init memory usage {}",
        size_text(init_mem_usage as usize)
    ));
    c.push_metadata("optee_version", "Header version", u64::from(VERSION_1));
    c.push_metadata(
        "optee_load_address",
        "Init load address",
        format!("0x{load:X}"),
    );
    c.push_metadata(
        "optee_init_mem_usage",
        "Init memory usage (B)",
        u64::from(init_mem_usage),
    );
    c.children.push(
        Child::stored("Init part (pager)", V1_HEADER_SIZE, init)
            .with_target(target)
            .as_code(),
    );
    if paged_size > 0 {
        c.children.push(
            Child::stored("Paged part", paged_offset, paged)
                .with_target(target)
                .as_code(),
        );
    }
    Ok(c)
}

/// One version 2 image record.
struct ImageRecord {
    id: u32,
    /// Load address, or `None` when the loader decides it.
    address: Option<u64>,
    /// Image size in bytes.
    size: u32,
}

fn image_record(record: &[u8], index: usize) -> Result<ImageRecord> {
    let high = le_u32(record, 0)?;
    let low = le_u32(record, 4)?;
    let id = le_u32(record, 8)?;
    let size = le_u32(record, 12)?;
    if !matches!(id, PAGER_IMAGE_ID | PAGED_IMAGE_ID) {
        return Err(error(format!(
            "Unknown OP-TEE image ID {id} in record {index}"
        )));
    }
    let address =
        (high != LOADER_DECIDES || low != LOADER_DECIDES).then(|| load_address(high, low));
    Ok(ImageRecord { id, address, size })
}

fn image_name(id: u32) -> &'static str {
    if id == PAGER_IMAGE_ID {
        "pager"
    } else {
        "paged"
    }
}

pub(super) fn parse_v2(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, V2_HEADER_SIZE, "OP-TEE v2 header")?;
    if le_u32(header, 0)? != OPTEE_MAGIC || header[VERSION_OFFSET] != VERSION_2 {
        return Err(error("Missing OP-TEE magic and header version 2"));
    }
    let arch = header[ARCH_OFFSET];
    let Arch {
        target,
        name: arch_name,
    } = arch_target(arch)?;
    let count = le_u32(header, V2_IMAGE_COUNT)?;
    if count == 0 || count > MAX_IMAGES {
        return Err(error(format!(
            "Invalid OP-TEE image count {count}: TF-A accepts 1 or 2"
        )));
    }
    let count = count as usize;
    let table = range(
        data,
        V2_HEADER_SIZE,
        count * V2_IMAGE_SIZE,
        "OP-TEE image table",
    )?;
    let mut records: Vec<ImageRecord> = Vec::with_capacity(count);
    for (index, record) in table.chunks_exact(V2_IMAGE_SIZE).enumerate() {
        let record = image_record(record, index)?;
        if records.iter().any(|r| r.id == record.id) {
            return Err(error(format!(
                "Duplicate OP-TEE image ID {} in record {index}",
                record.id
            )));
        }
        records.push(record);
    }
    let end = V2_HEADER_SIZE + table.len();

    let mut c = Container::new(FileFormat::OpteeImage, Layout::OpteeV2.label(), "optee");
    c.target = Some(target);
    c.consumed = end;
    c.entry = records
        .iter()
        .find(|r| r.id == PAGER_IMAGE_ID)
        .and_then(|r| r.address);
    c.notes.push(format!(
        "OP-TEE header version 2: {}; the images are separate files (tee-pager_v2.bin, tee-pageable_v2.bin) and are not in this file",
        counted(count, "image record", "image records")
    ));
    describe_common(&mut c, header, arch_name)?;
    byte_order_note(&mut c, arch);
    c.push_metadata("optee_version", "Header version", u64::from(VERSION_2));
    for (i, record) in records.iter().enumerate() {
        let address = match record.address {
            Some(address) => format!("load 0x{address:X}"),
            None => "load address chosen by the loader".to_string(),
        };
        c.push_metadata(
            format!("optee_image_{i}"),
            format!("Image {i}"),
            format!(
                "{} image; {address}; {}",
                image_name(record.id),
                size_text(record.size as usize)
            ),
        );
    }
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_a_documented_version() {
        assert_eq!(detect(b"OPTE\x01"), Some(Layout::OpteeV1));
        assert_eq!(detect(b"OPTE\x02"), Some(Layout::OpteeV2));
        assert_eq!(detect(b"OPTE\x03"), None);
        assert_eq!(detect(b"OPTE"), None);
    }

    #[test]
    fn loader_decided_addresses_have_no_value() {
        let mut record = [0xffu8; 16];
        record[8..12].copy_from_slice(&PAGED_IMAGE_ID.to_le_bytes());
        let parsed = image_record(&record, 0).unwrap();
        assert_eq!((parsed.id, parsed.address), (PAGED_IMAGE_ID, None));
        record[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(image_record(&record, 0).unwrap().address, Some(0xffff_ffff));
        record[8] = 7;
        assert!(image_record(&record, 0).is_err());
    }
}
