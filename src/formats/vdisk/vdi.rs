//! `VirtualBox` VDI images with a version 1 header (`VirtualBox` `v7.2.20`
//! `src/VBox/Storage/VDICore.h`: `VDIPREHEADER`, `VDIHEADER1`,
//! `VDIHEADER1PLUS` and the block pointer values; `VDI.cpp`:
//! `vdiValidatePreHeader`, `vdiValidateHeader` and the block offset
//! arithmetic; `include/VBox/vd.h`: the version macros; QEMU `v11.1.1`
//! `block/vdi.c`).
//!
//! Every field is little-endian. A 64-byte text line "for eyes only" is
//! followed by the signature and version, the header, a block map of one
//! 32-bit pointer per block and the blocks, each `cbBlockExtra` service
//! bytes and `cbBlock` data bytes. The old version 0 header (`VirtualBox`
//! before 1.4) is recognized and reported as unsupported.

use super::*;

/// `VDI_IMAGE_SIGNATURE` at offset 64, after the text line.
const SIGNATURE: u32 = 0xbeda_107f;
const SIGNATURE_OFFSET: usize = 64;
const VERSION_OFFSET: usize = 68;

/// Header versions: major 1 (`VDI_IMAGE_VERSION_MAJOR`), or the old
/// `0x00000002` whose major version is 0.
const VERSION_MAJOR: u32 = 1;
const OLD_VERSION: u32 = 0x0000_0002;

/// The pre-header (text line, signature, version) and the version 1
/// header after it; `VDIHEADER1PLUS` adds the LCHS geometry.
const PREHEADER_SIZE: usize = 72;
const HEADER1_SIZE: usize = 384;

/// `VDIIMAGETYPE` values.
const TYPE_NORMAL: u32 = 1;
const TYPE_FIXED: u32 = 2;
const TYPE_UNDO: u32 = 3;
const TYPE_DIFF: u32 = 4;

/// Block pointers that do not locate a block: `VDI_IMAGE_BLOCK_FREE`
/// (not allocated, reads may return anything) and `VDI_IMAGE_BLOCK_ZERO`.
const BLOCK_FREE: u32 = 0xffff_ffff;
const BLOCK_ZERO: u32 = 0xffff_fffe;

/// Block pointers are 32-bit.
const POINTER_SIZE: u64 = 4;

const TRANSFORM: &str = "VDI blocks";

/// Is this a VDI image: the signature at 0x40 and header version 1 (or
/// the old 0.2)?
pub(super) fn is_present(data: &[u8]) -> bool {
    le_u32(data, SIGNATURE_OFFSET).is_ok_and(|signature| signature == SIGNATURE)
        && le_u32(data, VERSION_OFFSET)
            .is_ok_and(|version| version >> 16 == VERSION_MAJOR || version == OLD_VERSION)
}

/// The version 1 header fields this parser uses.
struct Header {
    version: u32,
    size: u32,
    image_type: u32,
    blocks_offset: u32,
    data_offset: u32,
    /// Virtual disk size in bytes.
    disk_size: u64,
    block_size: u32,
    block_extra: u32,
    blocks: u32,
    blocks_allocated: u32,
    create_uuid: [u8; 16],
    modify_uuid: [u8; 16],
    linkage_uuid: [u8; 16],
}

/// `VDIHEADER1` after the pre-header: header size, image type, flags,
/// comment (256), block map and data offsets, legacy geometry (16), an
/// unused word, disk size (8), block size, extra block size, block count,
/// allocated block count, and the creation, modification, linkage and
/// parent modification UUIDs (16 each).
fn header(data: &[u8]) -> Result<Header> {
    let pre = slice(data, 0, PREHEADER_SIZE, "VDI pre-header")?;
    if le_u32(pre, SIGNATURE_OFFSET)? != SIGNATURE {
        return Err(error("Missing VDI signature"));
    }
    let version = le_u32(pre, VERSION_OFFSET)?;
    if version >> 16 != VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported VDI header version {}.{}",
            version >> 16,
            version & 0xffff
        )));
    }
    let bytes = slice(data, PREHEADER_SIZE, HEADER1_SIZE, "VDI header")?;
    Ok(Header {
        version,
        size: le_u32(bytes, 0)?,
        image_type: le_u32(bytes, 4)?,
        blocks_offset: le_u32(bytes, 268)?,
        data_offset: le_u32(bytes, 272)?,
        disk_size: le_u64(bytes, 296)?,
        block_size: le_u32(bytes, 304)?,
        block_extra: le_u32(bytes, 308)?,
        blocks: le_u32(bytes, 312)?,
        blocks_allocated: le_u32(bytes, 316)?,
        create_uuid: array(bytes, 320)?,
        modify_uuid: array(bytes, 336)?,
        linkage_uuid: array(bytes, 352)?,
    })
}

/// The checks of `vdiValidateHeader`: header size, block map and data
/// offsets, image type, sizes and counts, and non-null creation and
/// modification UUIDs.
fn check(h: &Header) -> Result<()> {
    if (h.size as usize) < HEADER1_SIZE {
        return Err(error(format!("Invalid VDI header size {} B", h.size)));
    }
    let header_end = (PREHEADER_SIZE + HEADER1_SIZE) as u64;
    if u64::from(h.blocks_offset) < header_end {
        return Err(error(format!(
            "Invalid VDI block map offset 0x{:X}: inside the header",
            h.blocks_offset
        )));
    }
    let map_end = u64::from(h.blocks_offset) + u64::from(h.blocks) * POINTER_SIZE;
    if u64::from(h.data_offset) < map_end {
        return Err(error(format!(
            "Invalid VDI data offset 0x{:X}: inside the block map",
            h.data_offset
        )));
    }
    if !(TYPE_NORMAL..=TYPE_DIFF).contains(&h.image_type) {
        return Err(error(format!("Invalid VDI image type {}", h.image_type)));
    }
    if h.disk_size == 0 || h.blocks == 0 || !h.block_size.is_power_of_two() {
        return Err(error(format!(
            "Invalid VDI geometry: {} B disk, {} blocks of {} B",
            h.disk_size, h.blocks, h.block_size
        )));
    }
    // VirtualBox accepts any power of two; blocks smaller than a sector
    // would only multiply the block map walk.
    if u64::from(h.block_size) < SECTOR_SIZE {
        return Err(error(format!(
            "Unsupported VDI block size {} B",
            h.block_size
        )));
    }
    if h.blocks_allocated > h.blocks {
        return Err(error(format!(
            "Invalid VDI header: {} of {} blocks allocated",
            h.blocks_allocated, h.blocks
        )));
    }
    if h.block_extra != 0 && !h.block_extra.is_power_of_two() {
        return Err(error(format!(
            "Invalid VDI extra block size {} B",
            h.block_extra
        )));
    }
    if u64::from(h.block_size) * u64::from(h.blocks) < h.disk_size {
        return Err(error(format!(
            "Invalid VDI header: {} blocks of {} cover less than the {} disk",
            h.blocks,
            size_text(u64::from(h.block_size)),
            size_text(h.disk_size)
        )));
    }
    if h.create_uuid == [0; 16] || h.modify_uuid == [0; 16] {
        return Err(error(
            "Invalid VDI header: null creation or modification UUID",
        ));
    }
    Ok(())
}

/// Parse a VDI image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let h = header(data)?;
    check(&h)?;
    let kind = match h.image_type {
        TYPE_NORMAL => "dynamic",
        TYPE_FIXED => "fixed",
        TYPE_UNDO => "undo",
        _ => "differencing",
    };
    let mut c = container_for(data, Layout::Vdi, format!("VDI {kind}"));
    c.notes.push(format!(
        "VDI {kind} image, header version {}.{}; {} disk; {} of {} ({} allocated); {} B of \
         service data per block",
        h.version >> 16,
        h.version & 0xffff,
        size_text(h.disk_size),
        counted(u64::from(h.blocks), "block", "blocks"),
        size_text(u64::from(h.block_size)),
        h.blocks_allocated,
        h.block_extra
    ));
    let text = byte_text(&data[..SIGNATURE_OFFSET]);
    if !text.is_empty() {
        c.notes
            .push(format!("Image info text: {}", text.trim_end_matches('?')));
    }
    c.push_metadata(
        "vdisk_vdi_block_size",
        "Block size (B)",
        u64::from(h.block_size),
    );
    let parent = (h.image_type == TYPE_DIFF).then(|| {
        let reference = format!("with UUID {}", guid_text(h.linkage_uuid));
        c.notes
            .push(format!("Differencing image of the parent {reference}"));
        Parent {
            role: "parent image",
            reference,
        }
    });
    range(
        data,
        u64::from(h.blocks_offset),
        u64::from(h.blocks) * POINTER_SIZE,
        "VDI block map",
    )?;
    let mut guest = Guest::new(data, h.disk_size);
    map_blocks(data, &h, parent.is_some(), &mut guest)?;
    guest.finish(&mut c, TRANSFORM, parent.as_ref())?;
    Ok(c)
}

/// Map every block in the analyzed range. An allocated pointer `p` below
/// `cBlocksAllocated` locates the block's data at `offData + p x
/// (cbBlockExtra + cbBlock) + cbBlockExtra`; free blocks of a
/// differencing image (`has_parent`) are the parent's.
fn map_blocks<'a>(
    data: &'a [u8],
    h: &Header,
    has_parent: bool,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let block_size = u64::from(h.block_size);
    let stride = u64::from(h.block_extra) + block_size;
    for block in 0..guest.block_count(block_size) {
        let at = u64::from(h.blocks_offset) + block * POINTER_SIZE;
        let pointer = le_u32(range(data, at, POINTER_SIZE, "VDI block map")?, 0)?;
        match pointer {
            BLOCK_FREE if has_parent => guest.parent(block_size),
            BLOCK_FREE | BLOCK_ZERO => guest.zero(block_size),
            pointer if pointer >= h.blocks_allocated => {
                return Err(error(format!(
                    "Invalid VDI block pointer {pointer} for block {block}: only {} blocks are \
                     allocated",
                    h.blocks_allocated
                )));
            }
            pointer => {
                let offset = u64::from(h.data_offset)
                    + u64::from(pointer) * stride
                    + u64::from(h.block_extra);
                guest.stored(offset, block_size, "VDI data block")?;
            }
        }
    }
    Ok(())
}
