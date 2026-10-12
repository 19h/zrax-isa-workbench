//! NXP i.MX boot images: HAB image vector table (IVT) images with their
//! boot data, device configuration data (DCD) and command sequence file
//! (CSF), and i.MX 8/9 AHAB containers.
//!
//! Layout (U-Boot `5e3b01c8` `include/imximage.h` `flash_header_v2_t`,
//! `boot_data_t` and `FLASH_OFFSET_*`, `tools/imximage.c`,
//! `arch/arm/include/asm/mach-imx/hab.h`, `arch/arm/mach-imx/hab.c`,
//! `include/imx8image.h` `flash_header_v3_t`, `boot_img_t`,
//! `sig_blk_hdr_t`; SPSDK `fb0f666d` `spsdk/image/hab/hab_header.py`,
//! `segments/seg_ivt.py`, `spsdk/image/ahab/ahab_container.py`,
//! `ahab_iae.py`):
//!
//! - Every HAB structure starts with a header word: tag, big-endian length,
//!   version (`0x4X` for HAB 4). The IVT (tag `0xD1`, 32 bytes) then holds
//!   little-endian absolute addresses: entry, reserved, DCD, boot data,
//!   self, CSF, reserved. A pointer maps to a file offset as
//!   `pointer - self + IVT offset`.
//! - Boot data (12 bytes) gives the start address and byte size of the
//!   loaded image and a plugin flag. U-Boot's `u-boot.imx` starts at the
//!   IVT, so its image start lies before the file; a disk dump has the IVT
//!   at 0x400 and a `FlexSPI` NOR image at 0x1000. Only file offsets 0, 0x400
//!   and 0x1000 are probed.
//! - No IVT field names a CPU or instruction set. The application bytes
//!   after the headers are a raw-code child for the code model.
//! - An AHAB container header starts with version, little-endian length
//!   and tag `0x87` (in that order), then flags, software and fuse
//!   versions, the image count and the signature block offset. Each
//!   128-byte image entry gives an offset relative to the container, size,
//!   load and entry addresses, flags (type, core ID, hash type, encryption)
//!   and a hash. The signature block (tag `0x90`) follows the image array;
//!   U-Boot's container length ends after its header and SPSDK's after the
//!   whole block. The core ID numbering is `SoC`-specific (SPSDK device
//!   databases and U-Boot disagree) and the container does not name its
//!   `SoC`, so core IDs are reported but never mapped to an ISA.

use super::*;

/// HAB tags (SPSDK `SegmentTag`, U-Boot `imximage.h`, `hab.h`).
const IVT_TAG: u8 = 0xd1;
const DCD_TAG: u8 = 0xd2;
const CSF_TAG: u8 = 0xd4;

/// HAB 4 structures carry version `0x4X`. U-Boot `hab.c` accepts any minor
/// version; SPSDK accepts `0x40..=0x4E`.
const HAB_VERSION_MAJOR_MASK: u8 = 0xf0;
const HAB_VERSION_4: u8 = 0x40;

/// The HAB header word: tag, big-endian length, version.
const HAB_HEADER_SIZE: usize = 4;
const HAB_LENGTH: usize = 1;
const HAB_VERSION: usize = 3;

/// IVT: 32 bytes, its header length field is 0x0020.
const IVT_SIZE: usize = 0x20;
const IVT_LENGTH: u16 = 0x0020;
const IVT_ENTRY: usize = 0x04;
const IVT_RESERVED1: usize = 0x08;
const IVT_DCD: usize = 0x0c;
const IVT_BOOT_DATA: usize = 0x10;
const IVT_SELF: usize = 0x14;
const IVT_CSF: usize = 0x18;
const IVT_RESERVED2: usize = 0x1c;

/// IVT file offsets: 0 (an image file such as `u-boot.imx`, or a serial
/// download image), 0x400 (SD/eMMC, SPI NOR, NAND and SATA media) and
/// 0x1000 (QSPI/`FlexSPI` and parallel NOR media) (U-Boot `FLASH_OFFSET_*`;
/// SPSDK i.MX `RT10xx` `bootable_image` segments).
const IVT_OFFSETS: [usize; 3] = [0, 0x400, 0x1000];

/// Boot data: start address, size in bytes, plugin flag.
const BOOT_DATA_SIZE: usize = 12;
const BOOT_DATA_START: usize = 0;
const BOOT_DATA_LENGTH: usize = 4;
const BOOT_DATA_PLUGIN: usize = 8;

/// `FlexSPI` configuration block tag at offset 0 of `FlexSPI` NOR images, in
/// front of an IVT at 0x1000 (U-Boot `imx8mimage.c` `generate_fspi_header`).
const FCB_TAG: [u8; 4] = *b"FCFB";
const FLEXSPI_IVT_OFFSET: usize = 0x1000;

/// AHAB container header (U-Boot `flash_header_v3_t`): version 0x00,
/// length 0x01 (LE16), tag 0x03, flags 0x04, software version 0x08 (LE16),
/// fuse version 0x0A, image count 0x0B, signature block offset 0x0C (LE16).
const AHAB_TAG: u8 = 0x87;
const AHAB_VERSION_LEGACY: u8 = 0x00;
const AHAB_VERSION_2: u8 = 0x02;
const AHAB_LENGTH: usize = 0x01;
const AHAB_TAG_OFFSET: usize = 0x03;
const AHAB_FLAGS: usize = 0x04;
const AHAB_SW_VERSION: usize = 0x08;
const AHAB_FUSE_VERSION: usize = 0x0a;
const AHAB_IMAGE_COUNT: usize = 0x0b;
const AHAB_SIGNATURE_BLOCK: usize = 0x0c;
const AHAB_HEADER_SIZE: usize = 0x10;

/// AHAB image array entry (U-Boot `boot_img_t`; SPSDK `ImageArrayEntry`):
/// offset from the container start 0x00, size 0x04, load address 0x08
/// (LE64), entry point 0x10 (LE64), flags 0x18, then metadata, hash and IV.
const IMAGE_ENTRY_SIZE: usize = 0x80;
const IMAGE_OFFSET: usize = 0x00;
const IMAGE_SIZE: usize = 0x04;
const IMAGE_LOAD: usize = 0x08;
const IMAGE_ENTRY: usize = 0x10;
const IMAGE_FLAGS: usize = 0x18;

/// Image flags: type 3:0, core ID 7:4; the hash type is 10:8 and the
/// encryption bit 11 in legacy containers, 11:8 and 12 in version 2
/// (SPSDK `ImageArrayEntry`, `ImageArrayEntryV2`; U-Boot's
/// `IMG_FLAG_ENCRYPTED_MASK` 0x400 overlaps the hash field, so SPSDK is
/// followed).
const IMAGE_TYPE_MASK: u32 = 0xf;
const CORE_ID_SHIFT: u32 = 4;
const CORE_ID_MASK: u32 = 0xf;
const HASH_SHIFT: u32 = 8;
const LEGACY_HASH_MASK: u32 = 0x7;
const V2_HASH_MASK: u32 = 0xf;
const LEGACY_ENCRYPTED: u32 = 1 << 11;
const V2_ENCRYPTED: u32 = 1 << 12;

/// Legacy hash types: 0 SHA-256, 1 SHA-384, 2 SHA-512.
const LEGACY_HASHES: [&str; 3] = ["SHA-256", "SHA-384", "SHA-512"];

/// Image type 3 is executable code; every other type is data, firmware for
/// a security subsystem or configuration and is opaque.
const IMAGE_TYPE_EXECUTABLE: u32 = 3;

/// Image types U-Boot `IMG_TYPE_*` and SPSDK agree on.
const IMAGE_TYPES: [(u32, &str); 8] = [
    (1, "CSF"),
    (2, "SCD"),
    (IMAGE_TYPE_EXECUTABLE, "executable"),
    (4, "data"),
    (5, "DCD/DDR initialization"),
    (6, "SECO/ELE firmware"),
    (7, "provisioning"),
    (8, "DEK validation"),
];

/// Signature block header: version, length (LE16), tag `0x90`.
const SIGNATURE_BLOCK_TAG: u8 = 0x90;
const SIGNATURE_BLOCK_HEADER_SIZE: usize = 0x10;

/// U-Boot `imx8image.c` pads the first container to 0x400 bytes
/// (`FIRST_CONTAINER_HEADER_LENGTH`), or 0x4000 for version 2 containers
/// (`CONTAINER_PQC_ALIGNMENT`); the next container header follows there.
const FIRST_CONTAINER_LENGTH: usize = 0x400;
const FIRST_CONTAINER_LENGTH_V2: usize = 0x4000;

/// A HAB header word.
struct HabHeader {
    tag: u8,
    length: u16,
    version: u8,
}

/// An image vector table; pointers are absolute target addresses.
struct Ivt {
    /// File offset of the IVT.
    offset: usize,
    version: u8,
    entry: u32,
    dcd: u32,
    boot_data: u32,
    self_address: u32,
    csf: u32,
}

impl Ivt {
    /// File offset of target address `address`, in the image that holds
    /// this IVT; `None` before the start of the file.
    fn file_offset(&self, address: u64) -> Option<usize> {
        let self_address = u64::from(self.self_address);
        let offset = u64::try_from(self.offset).ok()?;
        let position = if address >= self_address {
            offset.checked_add(address - self_address)?
        } else {
            offset.checked_sub(self_address - address)?
        };
        usize::try_from(position).ok()
    }
}

/// Boot data: the loaded image's start address and byte size.
struct BootData {
    start: u32,
    size: u32,
    plugin: u32,
}

/// A device configuration data block.
struct Dcd {
    /// File offset.
    offset: usize,
    /// Length from the DCD header, in bytes.
    length: usize,
}

/// Where the IVT's CSF pointer leads.
enum Csf {
    /// No CSF pointer: the image is unsigned.
    Absent,
    /// A CSF header at this file offset.
    Present { offset: usize, version: u8 },
    /// The CSF area lies in the file but holds no CSF header (not yet
    /// signed).
    Unwritten { offset: usize },
    /// The CSF area lies after the end of the file.
    BeyondFile { address: u32 },
}

/// A validated HAB image.
struct HabImage {
    ivt: Ivt,
    boot_data: BootData,
    dcd: Option<Dcd>,
    csf: Csf,
    /// File offset of the entry point.
    entry_offset: usize,
    /// File range of the application bytes after the headers.
    code_start: usize,
    code_end: usize,
    /// End of the declared image in the file, clipped to the file.
    image_end: usize,
    /// Bytes of the declared image after the end of the file.
    missing: u64,
}

/// One AHAB image array entry.
struct AhabImage {
    /// File offset of the image.
    offset: usize,
    size: usize,
    load_address: u64,
    entry: u64,
    flags: u32,
}

/// A validated AHAB container.
struct AhabContainer {
    /// File offset of the container header.
    offset: usize,
    version: u8,
    flags: u32,
    sw_version: u16,
    fuse_version: u8,
    images: Vec<AhabImage>,
    signature_block: SignatureBlock,
    /// End of the header, signature block and non-empty images.
    end: usize,
}

/// An AHAB signature block (SRK table, certificate, signature, blob).
struct SignatureBlock {
    /// File offset.
    offset: usize,
    /// Length from its header, in bytes.
    length: usize,
}

fn hab_header(data: &[u8], at: usize) -> Result<HabHeader> {
    Ok(HabHeader {
        tag: byte(data, at)?,
        length: be_u16(data, at + HAB_LENGTH)?,
        version: byte(data, at + HAB_VERSION)?,
    })
}

fn is_hab4(version: u8) -> bool {
    version & HAB_VERSION_MAJOR_MASK == HAB_VERSION_4
}

/// The IVT at `offset`: header word, reserved words zero.
fn ivt(data: &[u8], offset: usize) -> Result<Ivt> {
    let header = hab_header(data, offset)?;
    if header.tag != IVT_TAG || header.length != IVT_LENGTH || !is_hab4(header.version) {
        return Err(error(format!("Missing IVT header at 0x{offset:X}")));
    }
    let table = slice(data, offset, IVT_SIZE)?;
    if le_u32(table, IVT_RESERVED1)? != 0 || le_u32(table, IVT_RESERVED2)? != 0 {
        return Err(error(format!(
            "Invalid IVT at 0x{offset:X}: reserved words are not zero"
        )));
    }
    Ok(Ivt {
        offset,
        version: header.version,
        entry: le_u32(table, IVT_ENTRY)?,
        dcd: le_u32(table, IVT_DCD)?,
        boot_data: le_u32(table, IVT_BOOT_DATA)?,
        self_address: le_u32(table, IVT_SELF)?,
        csf: le_u32(table, IVT_CSF)?,
    })
}

/// File offset of `len` bytes at IVT pointer `address`, which must lie in
/// the file.
fn pointed(data: &[u8], ivt: &Ivt, address: u32, what: &str, len: usize) -> Result<usize> {
    ivt.file_offset(u64::from(address))
        .filter(|offset| offset.checked_add(len).is_some_and(|end| end <= data.len()))
        .ok_or_else(|| {
            error(format!(
                "Invalid IVT {what} pointer 0x{address:08X}: outside the file"
            ))
        })
}

/// The DCD at `address`: header word with tag `0xD2`; its commands are not
/// interpreted.
fn dcd(data: &[u8], ivt: &Ivt, address: u32) -> Result<Dcd> {
    let offset = pointed(data, ivt, address, "DCD", HAB_HEADER_SIZE)?;
    let header = hab_header(data, offset)?;
    if header.tag != DCD_TAG || !is_hab4(header.version) {
        return Err(error(format!(
            "Invalid DCD header at 0x{offset:X}: tag 0x{:02X}, version 0x{:02X}",
            header.tag, header.version
        )));
    }
    let length = usize::from(header.length);
    if length < HAB_HEADER_SIZE {
        return Err(error(format!(
            "Invalid DCD length {length} B at 0x{offset:X}"
        )));
    }
    slice(data, offset, length)
        .map_err(|_| error(format!("Truncated DCD at 0x{offset:X}: {length} B")))?;
    Ok(Dcd { offset, length })
}

/// The CSF pointer, which must lie in the declared image after the
/// headers. A CSF area past the end of the file or without a CSF header is
/// an image prepared for signing.
fn csf(data: &[u8], ivt: &Ivt, image: &BootData, headers_end: usize) -> Result<Csf> {
    let address = ivt.csf;
    if address == 0 {
        return Ok(Csf::Absent);
    }
    let image_end = u64::from(image.start) + u64::from(image.size);
    let offset = ivt
        .file_offset(u64::from(address))
        .filter(|&offset| offset >= headers_end && u64::from(address) < image_end)
        .ok_or_else(|| {
            error(format!(
                "Invalid IVT CSF pointer 0x{address:08X}: not in the image after its headers"
            ))
        })?;
    if offset >= data.len() {
        return Ok(Csf::BeyondFile { address });
    }
    match hab_header(data, offset) {
        Ok(header) if header.tag == CSF_TAG && is_hab4(header.version) => Ok(Csf::Present {
            offset,
            version: header.version,
        }),
        _ => Ok(Csf::Unwritten { offset }),
    }
}

/// The HAB image whose IVT is at file offset `offset`, with every pointer
/// checked: boot data in the file after the IVT, the IVT and boot data in
/// the declared image, the entry point in the application bytes.
fn hab_image(data: &[u8], offset: usize) -> Result<HabImage> {
    let ivt = ivt(data, offset)?;
    let ivt_end = offset + IVT_SIZE;
    let boot_data_offset = pointed(data, &ivt, ivt.boot_data, "boot data", BOOT_DATA_SIZE)?;
    if boot_data_offset < ivt_end {
        return Err(error(format!(
            "Invalid IVT boot data pointer 0x{:08X}: overlaps or precedes the IVT",
            ivt.boot_data
        )));
    }
    let boot_data = BootData {
        start: le_u32(data, boot_data_offset + BOOT_DATA_START)?,
        size: le_u32(data, boot_data_offset + BOOT_DATA_LENGTH)?,
        plugin: le_u32(data, boot_data_offset + BOOT_DATA_PLUGIN)?,
    };
    let image_start = u64::from(boot_data.start);
    let image_end = image_start + u64::from(boot_data.size);
    let ivt_address = u64::from(ivt.self_address);
    let boot_data_end = u64::from(ivt.boot_data) + BOOT_DATA_SIZE as u64;
    if ivt_address < image_start || boot_data_end > image_end {
        return Err(error(format!(
            "Invalid boot data: image 0x{:08X} + {} B does not hold the IVT and boot data",
            boot_data.start, boot_data.size
        )));
    }
    let entry = u64::from(ivt.entry);
    if entry < image_start || entry >= image_end {
        return Err(error(format!(
            "Invalid IVT entry 0x{:08X}: outside the image 0x{:08X} + {} B",
            ivt.entry, boot_data.start, boot_data.size
        )));
    }
    let dcd = match ivt.dcd {
        0 => None,
        address => Some(dcd(data, &ivt, address)?),
    };
    let mut headers_end = boot_data_offset + BOOT_DATA_SIZE;
    if let Some(dcd) = dcd.as_ref().filter(|dcd| dcd.offset >= offset) {
        headers_end = headers_end.max(dcd.offset + dcd.length);
    }
    // The boot data lies after the IVT, so the image end does too.
    let declared_end = offset as u64 + (image_end - ivt_address);
    let file_end = usize::try_from(declared_end).map_or(data.len(), |end| end.min(data.len()));
    let csf = csf(data, &ivt, &boot_data, headers_end)?;
    let code_end = match csf {
        Csf::Present { offset, .. } | Csf::Unwritten { offset } => offset,
        Csf::Absent | Csf::BeyondFile { .. } => file_end,
    };
    let entry_offset = ivt
        .file_offset(entry)
        .filter(|entry_offset| (headers_end..code_end).contains(entry_offset))
        .ok_or_else(|| {
            error(format!(
                "Invalid IVT entry 0x{:08X}: not in the application bytes at 0x{headers_end:X}..0x{code_end:X}",
                ivt.entry
            ))
        })?;
    Ok(HabImage {
        ivt,
        boot_data,
        dcd,
        csf,
        entry_offset,
        code_start: headers_end,
        code_end,
        image_end: file_end,
        missing: declared_end - file_end as u64,
    })
}

/// The first consistent IVT at a documented offset.
fn find_hab_image(data: &[u8]) -> Result<HabImage> {
    let mut first_error = None;
    for offset in IVT_OFFSETS {
        match hab_image(data, offset) {
            Ok(image) => return Ok(image),
            Err(e) => {
                let has_tag = hab_header(data, offset).is_ok_and(|h| h.tag == IVT_TAG);
                if has_tag && first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    Err(first_error.unwrap_or_else(|| error("Missing IVT at file offset 0x0, 0x400 or 0x1000")))
}

/// A consistent IVT at file offset 0, 0x400 or 0x1000.
pub(super) fn has_ivt(data: &[u8]) -> bool {
    IVT_OFFSETS
        .iter()
        .any(|&offset| hab_image(data, offset).is_ok())
}

/// Parse a HAB image: the application bytes are one child for the code
/// model; DCD and CSF are opaque.
pub(super) fn parse_ivt_image(data: &[u8]) -> Result<Container<'_>> {
    let image = find_hab_image(data)?;
    let ivt = &image.ivt;
    let mut c = Container::new(FileFormat::ImxImage, "i.MX HAB image", "imx");
    c.entry = Some(u64::from(ivt.entry));
    c.notes.push(format!(
        "i.MX image vector table at 0x{:X}, HAB version 0x{:02X}; the IVT names no CPU or instruction set",
        ivt.offset, ivt.version
    ));
    c.notes.push(format!(
        "Boot data: image 0x{:08X} + {} B; IVT self 0x{:08X}; entry 0x{:08X} (file offset 0x{:X})",
        image.boot_data.start,
        image.boot_data.size,
        ivt.self_address,
        ivt.entry,
        image.entry_offset
    ));
    if image.boot_data.plugin != 0 {
        c.notes.push(
            "Plugin image: the boot ROM runs the entry and returns to load the next image".into(),
        );
    }
    if ivt.offset == FLEXSPI_IVT_OFFSET && data.starts_with(&FCB_TAG) {
        c.notes
            .push("FlexSPI configuration block (FCFB) at 0x0; not interpreted".into());
    }
    if image.missing > 0 {
        c.notes.push(format!(
            "Boot data declares {} B beyond the end of the file",
            image.missing
        ));
    }
    c.push_metadata("imx_ivt_offset", "IVT file offset", ivt.offset as u64);
    c.push_metadata(
        "imx_image_start",
        "Image start address",
        format!("0x{:08X}", image.boot_data.start),
    );
    c.push_metadata(
        "imx_image_length",
        "Image length (B)",
        u64::from(image.boot_data.size),
    );
    if let Some(dcd) = &image.dcd {
        c.notes.push(format!(
            "DCD at 0x{:X}: {} B; device configuration commands are not interpreted",
            dcd.offset, dcd.length
        ));
        c.children
            .push(opaque_child(data, "DCD", dcd.offset, dcd.length)?);
    }
    // The application bytes start after the headers, inside the loaded
    // image, so they are raw code rather than the start of a nested file.
    let application = stored_child(
        data,
        "Application image",
        image.code_start,
        image.code_end - image.code_start,
    )?;
    c.children.push(application.as_code());
    match image.csf {
        Csf::Absent => c.notes.push("No CSF: the image is not signed".into()),
        Csf::Present { offset, version } => {
            c.notes.push(format!(
                "CSF at 0x{offset:X}, HAB version 0x{version:02X}; signatures and certificates not verified"
            ));
            c.children.push(opaque_child(
                data,
                "CSF",
                offset,
                image.image_end.saturating_sub(offset),
            )?);
        }
        Csf::Unwritten { offset } => c.notes.push(format!(
            "CSF area at 0x{offset:X} holds no CSF header: the image is prepared for signing but not signed"
        )),
        Csf::BeyondFile { address } => c.notes.push(format!(
            "CSF pointer 0x{address:08X} lies after the end of the file: the image is prepared for signing but not signed"
        )),
    }
    c.consumed = image.image_end;
    push_trailing(data, &mut c);
    Ok(c)
}

/// The AHAB container header at `offset`, its image entries and signature
/// block header, each range inside the file.
fn ahab_container(data: &[u8], offset: usize) -> Result<AhabContainer> {
    let version = byte(data, offset)?;
    if byte(data, offset + AHAB_TAG_OFFSET)? != AHAB_TAG {
        return Err(error(format!(
            "Missing AHAB container tag 0x87 at 0x{offset:X}"
        )));
    }
    if version != AHAB_VERSION_LEGACY && version != AHAB_VERSION_2 {
        return Err(error(format!(
            "Unsupported AHAB container version 0x{version:02X} at 0x{offset:X}"
        )));
    }
    let length = usize::from(le_u16(data, offset + AHAB_LENGTH)?);
    let count = usize::from(byte(data, offset + AHAB_IMAGE_COUNT)?);
    if count == 0 {
        return Err(error(format!(
            "Invalid AHAB container at 0x{offset:X}: no images"
        )));
    }
    let array_end = AHAB_HEADER_SIZE + count * IMAGE_ENTRY_SIZE;
    let minimum = array_end + SIGNATURE_BLOCK_HEADER_SIZE;
    if length < minimum {
        return Err(error(format!(
            "Invalid AHAB container length {length} B at 0x{offset:X}: {count} image entries and the signature block header need {minimum} B"
        )));
    }
    let header = slice(data, offset, length).map_err(|_| {
        error(format!(
            "Truncated AHAB container header at 0x{offset:X}: {length} B"
        ))
    })?;
    let signature_block = signature_block(data, offset, header, array_end)?;
    // U-Boot counts the signature block header, SPSDK the whole block.
    if length != minimum && length != array_end + signature_block.length {
        return Err(error(format!(
            "Invalid AHAB container length {length} B at 0x{offset:X}: neither {minimum} B nor the {} B up to the end of the signature block",
            array_end + signature_block.length
        )));
    }
    let mut end = (offset + length).max(signature_block.offset + signature_block.length);
    let mut images = Vec::with_capacity(count);
    for index in 0..count {
        let image = ahab_image(data, offset, header, version, index)?;
        if image.size > 0 {
            end = end.max(image.offset + image.size);
        }
        images.push(image);
    }
    Ok(AhabContainer {
        offset,
        version,
        flags: le_u32(header, AHAB_FLAGS)?,
        sw_version: le_u16(header, AHAB_SW_VERSION)?,
        fuse_version: byte(header, AHAB_FUSE_VERSION)?,
        images,
        signature_block,
        end,
    })
}

/// The signature block, which directly follows the image array (U-Boot
/// `imx8image.c`; SPSDK aligns its offset after the image array, which is
/// already 16-byte aligned).
fn signature_block(
    data: &[u8],
    container: usize,
    header: &[u8],
    array_end: usize,
) -> Result<SignatureBlock> {
    let relative = usize::from(le_u16(header, AHAB_SIGNATURE_BLOCK)?);
    if relative != array_end {
        return Err(error(format!(
            "Invalid AHAB signature block offset 0x{relative:X} in the container at 0x{container:X}: expected 0x{array_end:X}"
        )));
    }
    // The signature block header orders its bytes like the container
    // header: version, length, tag.
    let offset = container + relative;
    if byte(data, offset + AHAB_TAG_OFFSET)? != SIGNATURE_BLOCK_TAG {
        return Err(error(format!(
            "Missing AHAB signature block tag 0x90 at 0x{offset:X}"
        )));
    }
    let length = usize::from(le_u16(data, offset + AHAB_LENGTH)?);
    if length < SIGNATURE_BLOCK_HEADER_SIZE {
        return Err(error(format!(
            "Invalid AHAB signature block length {length} B at 0x{offset:X}"
        )));
    }
    slice(data, offset, length).map_err(|_| {
        error(format!(
            "Truncated AHAB signature block at 0x{offset:X}: {length} B"
        ))
    })?;
    Ok(SignatureBlock { offset, length })
}

/// Image array entry `index` of the container at `container`.
fn ahab_image(
    data: &[u8],
    container: usize,
    header: &[u8],
    version: u8,
    index: usize,
) -> Result<AhabImage> {
    let entry = slice(
        header,
        AHAB_HEADER_SIZE + index * IMAGE_ENTRY_SIZE,
        IMAGE_ENTRY_SIZE,
    )?;
    let relative = le_u32(entry, IMAGE_OFFSET)? as usize;
    let size = le_u32(entry, IMAGE_SIZE)? as usize;
    let flags = le_u32(entry, IMAGE_FLAGS)?;
    if version == AHAB_VERSION_LEGACY {
        let hash = (flags >> HASH_SHIFT) & LEGACY_HASH_MASK;
        if hash as usize >= LEGACY_HASHES.len() {
            return Err(error(format!(
                "Unsupported AHAB image {index} hash type {hash} in the container at 0x{container:X}"
            )));
        }
    }
    let offset = end_of(container, relative)?;
    if size > 0 {
        if relative < header.len() {
            return Err(error(format!(
                "Invalid AHAB image {index} offset 0x{relative:X}: inside the container header at 0x{container:X}"
            )));
        }
        slice(data, offset, size).map_err(|_| {
            error(format!(
                "Truncated AHAB image {index}: 0x{offset:X} + {size} B exceeds the {} B file",
                data.len()
            ))
        })?;
    }
    Ok(AhabImage {
        offset,
        size,
        load_address: le_u64(entry, IMAGE_LOAD)?,
        entry: le_u64(entry, IMAGE_ENTRY)?,
        flags,
    })
}

/// A complete AHAB container header at file offset 0 that places at least
/// one image in the file. The header key is only a version and a tag byte,
/// so a header whose images are all empty is not enough evidence.
pub(super) fn is_ahab(data: &[u8]) -> bool {
    ahab_container(data, 0).is_ok_and(|c| c.images.iter().any(|image| image.size > 0))
}

fn image_type_name(image_type: u32) -> String {
    IMAGE_TYPES
        .iter()
        .find(|(value, _)| *value == image_type)
        .map_or_else(
            || format!("type {image_type}"),
            |(_, name)| (*name).to_string(),
        )
}

/// Note image `index` of `container` and append it as a child: executable
/// images for the code model, everything else opaque.
fn push_ahab_image<'a>(
    data: &'a [u8],
    c: &mut Container<'a>,
    container: &AhabContainer,
    index: usize,
    image: &AhabImage,
) -> Result<()> {
    let label = format!("Container 0x{:X} image {index}", container.offset);
    let image_type = image.flags & IMAGE_TYPE_MASK;
    let core_id = (image.flags >> CORE_ID_SHIFT) & CORE_ID_MASK;
    let (hash, encrypted) = if container.version == AHAB_VERSION_LEGACY {
        let hash = (image.flags >> HASH_SHIFT) & LEGACY_HASH_MASK;
        let name = LEGACY_HASHES
            .get(hash as usize)
            .map_or_else(|| format!("hash type {hash}"), |name| (*name).to_string());
        (name, image.flags & LEGACY_ENCRYPTED != 0)
    } else {
        let hash = (image.flags >> HASH_SHIFT) & V2_HASH_MASK;
        (format!("hash type {hash}"), image.flags & V2_ENCRYPTED != 0)
    };
    let mut details = vec![
        format!("{label}: {}", image_type_name(image_type)),
        format!("{} B at 0x{:X}", image.size, image.offset),
        format!("load 0x{:X}", image.load_address),
        format!("entry 0x{:X}", image.entry),
        format!("core ID {core_id}"),
        format!("{hash} digest not verified"),
    ];
    if encrypted {
        details.push("encrypted".into());
    }
    c.notes.push(details.join("; "));
    if image.size == 0 {
        return Ok(());
    }
    let child = if image_type == IMAGE_TYPE_EXECUTABLE && !encrypted {
        stored_child(data, label, image.offset, image.size)?
    } else {
        opaque_child(data, label, image.offset, image.size)?
    };
    c.children.push(child);
    Ok(())
}

/// Notes for one container and its images.
fn push_ahab_container<'a>(
    data: &'a [u8],
    c: &mut Container<'a>,
    container: &AhabContainer,
) -> Result<()> {
    c.notes.push(format!(
        "AHAB container at 0x{:X}: version {}; image count {}; flags 0x{:08X}; software version {}; fuse version {}; signature block at 0x{:X}: {} B, not verified",
        container.offset,
        container.version,
        container.images.len(),
        container.flags,
        container.sw_version,
        container.fuse_version,
        container.signature_block.offset,
        container.signature_block.length
    ));
    for (index, image) in container.images.iter().enumerate() {
        push_ahab_image(data, c, container, index, image)?;
    }
    Ok(())
}

/// Parse the AHAB container at file offset 0 and the one U-Boot places
/// after the padded first container, when a valid header is there.
pub(super) fn parse_ahab(data: &[u8]) -> Result<Container<'_>> {
    let first = ahab_container(data, 0)?;
    let next_offset = match first.version {
        AHAB_VERSION_LEGACY => FIRST_CONTAINER_LENGTH,
        _ => FIRST_CONTAINER_LENGTH_V2,
    };
    let header_end = first.signature_block.offset + first.signature_block.length;
    let second = (header_end <= next_offset)
        .then(|| ahab_container(data, next_offset).ok())
        .flatten();
    let mut c = Container::new(FileFormat::ImxImage, "i.MX AHAB container", "imx");
    c.notes.push(
        "AHAB core IDs (image flags bits 7:4) are SoC-specific and the container does not name its SoC; no ISA is inferred from them"
            .into(),
    );
    let mut consumed = first.end;
    push_ahab_container(data, &mut c, &first)?;
    if let Some(second) = &second {
        push_ahab_container(data, &mut c, second)?;
        consumed = consumed.max(second.end);
    }
    let containers = 1 + usize::from(second.is_some());
    c.push_metadata("imx_container_count", "AHAB containers", containers as u64);
    c.consumed = consumed;
    push_trailing(data, &mut c);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ivt_at(offset: usize, self_address: u32) -> Ivt {
        Ivt {
            offset,
            version: HAB_VERSION_4,
            entry: 0,
            dcd: 0,
            boot_data: 0,
            self_address,
            csf: 0,
        }
    }

    #[test]
    fn ivt_pointers_map_relative_to_the_ivt_file_offset() {
        let ivt = ivt_at(0x400, 0x8780_0400);
        assert_eq!(ivt.file_offset(0x8780_0400), Some(0x400));
        assert_eq!(ivt.file_offset(0x8780_0000), Some(0));
        assert_eq!(ivt.file_offset(0x8780_0000 - 1), None);
        assert_eq!(ivt.file_offset(0x8780_1000), Some(0x1000));
    }

    #[test]
    fn hab_versions_are_major_version_four() {
        assert!(is_hab4(0x40) && is_hab4(0x41) && is_hab4(0x4f));
        assert!(!is_hab4(0x50) && !is_hab4(0x00));
    }

    #[test]
    fn image_types_outside_the_agreed_table_are_numbered() {
        assert_eq!(image_type_name(IMAGE_TYPE_EXECUTABLE), "executable");
        assert_eq!(image_type_name(0xd), "type 13");
    }
}
