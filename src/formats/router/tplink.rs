//! TP-Link firmware headers (`OpenWrt` firmware-utils `mktplinkfw.c`,
//! `mktplinkfw2.c` and `mktplinkfw-lib.c`).
//!
//! Both layouts are 512-byte big-endian headers without a magic; the kernel
//! follows the header and the root filesystem offset is relative to the
//! header that precedes the kernel (the start of the file unless a
//! `mktplinkfw2` bootloader is prepended).
//!
//! - v1 layout (`mktplinkfw`, version word `01 00 00 00`, or `02 00 00 00`
//!   with `-m 2`): vendor name (0x04, 24 B), firmware version string (0x1C,
//!   36 B), hardware ID (0x40), hardware revision (0x44), region code
//!   (0x48), salted MD5 (0x4C), kernel load address (0x74), kernel entry
//!   point (0x78), firmware length (0x7C), kernel offset (0x80, always
//!   0x200), kernel length (0x84), root filesystem offset (0x88) and length
//!   (0x8C), bootloader offset (0x90) and length (0x94), version numbers
//!   (0x98, three 16-bit fields). The header is zero-filled, and combined
//!   images (`-c`) leave the MD5 and root filesystem fields zero.
//! - v2 layout (`mktplinkfw2`, version word `02 00 00 00` or `03 00 00 00`):
//!   firmware version string (0x04, 48 B), hardware ID (0x34), hardware
//!   revision (0x38), additional hardware version (0x3C), salted MD5
//!   (0x40), kernel load address (0x68), entry point (0x6C), firmware length
//!   (0x70), kernel offset (0x74) and length (0x78), root filesystem offset
//!   (0x7C) and length (0x80), bootloader offset (0x84, from the end of the
//!   header) and length (0x88), the constant `0x55AA` (0x8C), a secondary
//!   version (0x8E), the constant `0xA5` (0x90) and version numbers (0x91,
//!   three bytes). The header is `0xFF`-filled, so combined images leave
//!   the root filesystem fields `0xFFFFFFFF`. With a bootloader
//!   (`prepend_bootloader`), the bootloader follows the header, padded, and
//!   a complete second image (header, kernel, root filesystem) follows it;
//!   the outer kernel offset points into that image and the root filesystem
//!   offset is the second image's own.

use super::*;

/// Which header layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Generation {
    /// `mktplinkfw`.
    V1,
    /// `mktplinkfw2`.
    V2,
}

/// `sizeof(struct fw_header)` in both tools.
const HEADER_SIZE: usize = 0x200;

/// Version words: `HEADER_VERSION_V1`/`_V2` in `mktplinkfw.c`, and
/// `htonl(bswap_32(n))` for n = 2 or 3 in `mktplinkfw2.c`.
const VERSION_1: u32 = 0x0100_0000;
const VERSION_2: u32 = 0x0200_0000;
const VERSION_3: u32 = 0x0300_0000;

/// v1 string and version fields.
const V1_VENDOR: usize = 0x04;
const V1_VENDOR_SIZE: usize = 24;
const V1_FW_VERSION: usize = 0x1c;
const V1_FW_VERSION_SIZE: usize = 36;
const V1_REGION_CODE: usize = 0x48;
const V1_VERSION_NUMBERS: usize = 0x98;

/// v2 string, version and constant fields.
const V2_FW_VERSION: usize = 0x04;
const V2_FW_VERSION_SIZE: usize = 48;
const V2_HW_VER_ADD: usize = 0x3c;
const V2_UNK4: usize = 0x8c;
const V2_SECONDARY_VERSION: usize = 0x8e;
const V2_UNK5: usize = 0x90;
const V2_VERSION_NUMBERS: usize = 0x91;

/// The constants `mktplinkfw2` writes as `unk4` and `unk5` ("magic").
const V2_UNK4_VALUE: u16 = 0x55aa;
const V2_UNK5_VALUE: u8 = 0xa5;

/// A field `mktplinkfw2` leaves at its `0xFF` fill.
const V2_UNSET: u32 = 0xffff_ffff;

const MD5_SIZE: usize = 16;

/// JFFS2 end-of-filesystem mark that `-j` writes at 4 KiB and 64 KiB
/// boundaries after the root filesystem (`pad_jffs2` in
/// `mktplinkfw-lib.c`).
const JFFS2_EOF_MARK: [u8; 4] = [0xde, 0xad, 0xc0, 0xde];
const JFFS2_MARK_ALIGN: usize = 4096;

/// Where a layout keeps the fields both layouts share.
struct Fields {
    hw_id: usize,
    hw_rev: usize,
    md5: usize,
    kernel_load: usize,
    kernel_entry: usize,
    fw_length: usize,
    kernel_offset: usize,
    kernel_len: usize,
    rootfs_offset: usize,
    rootfs_len: usize,
    boot_offset: usize,
    boot_len: usize,
}

const V1_FIELDS: Fields = Fields {
    hw_id: 0x40,
    hw_rev: 0x44,
    md5: 0x4c,
    kernel_load: 0x74,
    kernel_entry: 0x78,
    fw_length: 0x7c,
    kernel_offset: 0x80,
    kernel_len: 0x84,
    rootfs_offset: 0x88,
    rootfs_len: 0x8c,
    boot_offset: 0x90,
    boot_len: 0x94,
};

const V2_FIELDS: Fields = Fields {
    hw_id: 0x34,
    hw_rev: 0x38,
    md5: 0x40,
    kernel_load: 0x68,
    kernel_entry: 0x6c,
    fw_length: 0x70,
    kernel_offset: 0x74,
    kernel_len: 0x78,
    rootfs_offset: 0x7c,
    rootfs_len: 0x80,
    boot_offset: 0x84,
    boot_len: 0x88,
};

/// A file range: offset and length in bytes.
#[derive(Debug, Clone, Copy)]
struct Range {
    offset: usize,
    len: usize,
}

impl Range {
    /// Exclusive end; in range because [`range`] checked it.
    fn end(self) -> usize {
        self.offset + self.len
    }
}

/// The `len` bytes at `offset`, which must lie inside the file.
fn range(data: &[u8], offset: usize, len: usize, what: &str) -> Result<Range> {
    slice(data, offset, len, what)?;
    Ok(Range { offset, len })
}

/// What only one of the layouts carries.
struct LayoutFields<'a> {
    /// v1 only.
    vendor: Option<&'a str>,
    fw_version: &'a str,
    /// The identity note: strings, version numbers and layout extras.
    identity: String,
}

/// A validated header.
struct Header<'a> {
    generation: Generation,
    /// Version number from the version word (1, 2 or 3).
    version: u8,
    fields: LayoutFields<'a>,
    hw_id: u32,
    hw_rev: u32,
    md5: &'a [u8],
    kernel_load: u32,
    kernel_entry: u32,
    kernel: Range,
    rootfs: Option<Range>,
    /// v2 only: the bootloader after the header.
    bootloader: Option<Range>,
    /// File offset of the header that precedes the kernel.
    image_base: usize,
    /// v1 bootloader fields as stored; the layout does not establish where
    /// the bootloader is.
    v1_boot: Option<BootFields>,
}

/// Bootloader offset and length fields as stored.
#[derive(Debug, Clone, Copy)]
struct BootFields {
    offset: u32,
    len: u32,
}

impl Header<'_> {
    /// The end of the last component.
    fn end(&self) -> usize {
        [Some(self.kernel), self.rootfs, self.bootloader]
            .iter()
            .flatten()
            .map(|r| r.end())
            .max()
            .unwrap_or(HEADER_SIZE)
    }
}

/// The version number a layout accepts in its version word.
fn version_number(generation: Generation, word: u32) -> Option<u8> {
    match (generation, word) {
        (Generation::V1, VERSION_1) => Some(1),
        (Generation::V1 | Generation::V2, VERSION_2) => Some(2),
        (Generation::V2, VERSION_3) => Some(3),
        _ => None,
    }
}

/// A non-empty printable string field.
fn text_field<'a>(header: &'a [u8], at: usize, size: usize, what: &str) -> Result<&'a str> {
    ascii_field(slice(header, at, size, what)?)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| error(format!("Invalid TP-Link {what}: not a printable string")))
}

/// Fill after the image: erased flash, plus JFFS2 end marks at 4 KiB
/// boundaries.
fn is_flash_fill(data: &[u8], start: usize) -> bool {
    let mut pos = start;
    while pos < data.len() {
        if pos % JFFS2_MARK_ALIGN == 0 && data[pos..].starts_with(&JFFS2_EOF_MARK) {
            pos += JFFS2_EOF_MARK.len();
        } else if matches!(data[pos], 0x00 | 0xff) {
            pos += 1;
        } else {
            return false;
        }
    }
    true
}

/// The v1 strings and version numbers.
fn v1_fields(header: &[u8]) -> Result<LayoutFields<'_>> {
    let vendor = text_field(header, V1_VENDOR, V1_VENDOR_SIZE, "vendor name")?;
    let fw_version = text_field(
        header,
        V1_FW_VERSION,
        V1_FW_VERSION_SIZE,
        "firmware version string",
    )?;
    let numbers = format!(
        "{}.{}.{}",
        be_u16(header, V1_VERSION_NUMBERS)?,
        be_u16(header, V1_VERSION_NUMBERS + 2)?,
        be_u16(header, V1_VERSION_NUMBERS + 4)?
    );
    let region = be_u32(header, V1_REGION_CODE)?;
    Ok(LayoutFields {
        vendor: Some(vendor),
        fw_version,
        identity: format!(
            "Vendor {vendor}; firmware version string {fw_version}; version {numbers}; region code {region}"
        ),
    })
}

/// The v2 string, constants and version numbers.
fn v2_fields(header: &[u8]) -> Result<LayoutFields<'_>> {
    let fw_version = text_field(
        header,
        V2_FW_VERSION,
        V2_FW_VERSION_SIZE,
        "firmware version string",
    )?;
    let unk4 = be_u16(header, V2_UNK4)?;
    let [unk5] = array(header, V2_UNK5)?;
    if unk4 != V2_UNK4_VALUE || unk5 != V2_UNK5_VALUE {
        return Err(error(format!(
            "Invalid TP-Link v2 header constants 0x{unk4:04X} and 0x{unk5:02X}, expected 0x55AA and 0xA5"
        )));
    }
    let [major, middle, minor] = array(header, V2_VERSION_NUMBERS)?;
    let [secondary_major, secondary_minor] = array(header, V2_SECONDARY_VERSION)?;
    let hw_ver_add = be_u32(header, V2_HW_VER_ADD)?;
    Ok(LayoutFields {
        vendor: None,
        fw_version,
        identity: format!(
            "Firmware version string {fw_version}; version {major}.{middle}.{minor}; secondary version {secondary_major}.{secondary_minor}; additional hardware version 0x{hw_ver_add:X}"
        ),
    })
}

/// Where the kernel's image starts, and the v2 bootloader before it.
struct Placement {
    bootloader: Option<Range>,
    /// File offset of the header that precedes the kernel.
    image_base: usize,
}

/// The kernel offset rule and the v2 bootloader.
fn kernel_placement(
    data: &[u8],
    header: &[u8],
    generation: Generation,
    fields: &Fields,
    kernel_offset: usize,
) -> Result<Placement> {
    let boot_len = to_usize(be_u32(header, fields.boot_len)?);
    if generation == Generation::V1 || boot_len == 0 {
        if kernel_offset != HEADER_SIZE {
            return Err(error(format!(
                "Invalid TP-Link kernel offset 0x{kernel_offset:X}: expected 0x200"
            )));
        }
        return Ok(Placement {
            bootloader: None,
            image_base: 0,
        });
    }
    // `prepend_bootloader` in `mktplinkfw2.c`: the bootloader follows the
    // header and the second image's header precedes the kernel.
    let boot_start = HEADER_SIZE
        .checked_add(to_usize(be_u32(header, fields.boot_offset)?))
        .ok_or_else(|| error("Invalid TP-Link bootloader offset"))?;
    let bootloader = range(data, boot_start, boot_len, "TP-Link bootloader")?;
    let image_base = kernel_offset.saturating_sub(HEADER_SIZE);
    if image_base < bootloader.end() {
        return Err(error(format!(
            "Invalid TP-Link kernel offset 0x{kernel_offset:X}: the bootloader at 0x{boot_start:X} leaves no room for the second image header"
        )));
    }
    let inner_word = be_u32(
        slice(data, image_base, 4, "TP-Link second image header")?,
        0,
    )?;
    if inner_word != be_u32(header, 0)? {
        return Err(error(format!(
            "Invalid TP-Link second image header at 0x{image_base:X}: version word 0x{inner_word:08X}"
        )));
    }
    Ok(Placement {
        bootloader: Some(bootloader),
        image_base,
    })
}

/// The root filesystem, if the header declares one: its offset is relative
/// to `image_base`, and it must lie after that header and outside the
/// kernel.
fn rootfs_range(
    data: &[u8],
    header: &[u8],
    generation: Generation,
    fields: &Fields,
    image_base: usize,
    kernel: Range,
) -> Result<Option<Range>> {
    let stored_offset = be_u32(header, fields.rootfs_offset)?;
    let stored_len = be_u32(header, fields.rootfs_len)?;
    let invalid_offset = || {
        error(format!(
            "Invalid TP-Link root filesystem offset 0x{stored_offset:X}"
        ))
    };
    let v2_unset =
        generation == Generation::V2 && (stored_offset, stored_len) == (V2_UNSET, V2_UNSET);
    if v2_unset || (stored_len == 0 && stored_offset == 0) {
        // Combined images (`-c`) leave the fields at their fill.
        return Ok(None);
    }
    let offset = image_base
        .checked_add(to_usize(stored_offset))
        .ok_or_else(invalid_offset)?;
    if stored_len == 0 {
        // `-O` points the offset of a combined image at the end of the
        // kernel.
        if !(kernel.end()..=data.len()).contains(&offset) {
            return Err(invalid_offset());
        }
        return Ok(None);
    }
    let rootfs = range(
        data,
        offset,
        to_usize(stored_len),
        "TP-Link root filesystem",
    )?;
    if rootfs.offset < image_base + HEADER_SIZE {
        return Err(error(format!(
            "Invalid TP-Link root filesystem at 0x{offset:X}: inside the header"
        )));
    }
    if rootfs.offset < kernel.end() && kernel.offset < rootfs.end() {
        return Err(error(format!(
            "Invalid TP-Link root filesystem at 0x{offset:X}: overlaps the kernel"
        )));
    }
    Ok(Some(rootfs))
}

/// Validate the header and every range it declares.
fn read_header(data: &[u8], generation: Generation) -> Result<Header<'_>> {
    let header = slice(data, 0, HEADER_SIZE, "TP-Link header")?;
    let word = be_u32(header, 0)?;
    let version = version_number(generation, word).ok_or_else(|| {
        error(format!(
            "Unsupported TP-Link header version word 0x{word:08X}"
        ))
    })?;
    let (layout_fields, fields) = match generation {
        Generation::V1 => (v1_fields(header)?, &V1_FIELDS),
        Generation::V2 => (v2_fields(header)?, &V2_FIELDS),
    };

    let kernel_offset = to_usize(be_u32(header, fields.kernel_offset)?);
    let placement = kernel_placement(data, header, generation, fields, kernel_offset)?;
    let kernel_len = to_usize(be_u32(header, fields.kernel_len)?);
    if kernel_len == 0 {
        return Err(error("Invalid TP-Link kernel length 0 B"));
    }
    let kernel = range(data, kernel_offset, kernel_len, "TP-Link kernel")?;
    let rootfs = rootfs_range(
        data,
        header,
        generation,
        fields,
        placement.image_base,
        kernel,
    )?;

    let fw_length = to_usize(be_u32(header, fields.fw_length)?);
    if fw_length != 0 && data.len() > fw_length {
        return Err(error(format!(
            "Invalid TP-Link firmware length {fw_length} B: the file is {} B",
            data.len()
        )));
    }
    let v1_boot = match generation {
        Generation::V1 => Some(BootFields {
            offset: be_u32(header, fields.boot_offset)?,
            len: be_u32(header, fields.boot_len)?,
        })
        .filter(|boot| boot.len > 0),
        Generation::V2 => None,
    };
    let parsed = Header {
        generation,
        version,
        fields: layout_fields,
        hw_id: be_u32(header, fields.hw_id)?,
        hw_rev: be_u32(header, fields.hw_rev)?,
        md5: slice(header, fields.md5, MD5_SIZE, "TP-Link MD5")?,
        kernel_load: be_u32(header, fields.kernel_load)?,
        kernel_entry: be_u32(header, fields.kernel_entry)?,
        kernel,
        rootfs,
        bootloader: placement.bootloader,
        image_base: placement.image_base,
        v1_boot,
    };
    let end = parsed.end();
    if !is_flash_fill(data, end) {
        return Err(error(format!(
            "Unexpected data after the TP-Link image at 0x{end:X}"
        )));
    }
    Ok(parsed)
}

/// Whether `data` holds a complete, consistent header of `generation`.
pub(super) fn is_valid(data: &[u8], generation: Generation) -> bool {
    read_header(data, generation).is_ok()
}

/// The MD5 note: unset in combined v1 images, otherwise present and not
/// checked.
fn md5_text(md5: &[u8]) -> String {
    if md5.iter().all(|&b| b == 0) {
        "MD5 field is zero (combined images leave it unset)".to_string()
    } else {
        format!(
            "salted MD5 {} not verified (no MD5 implementation)",
            hex_digest(md5)
        )
    }
}

pub(super) fn parse(data: &[u8], generation: Generation) -> Result<Container<'_>> {
    let header = read_header(data, generation)?;
    let (layout, tool) = match header.generation {
        Generation::V1 => (Layout::TpLinkV1, "mktplinkfw"),
        Generation::V2 => (Layout::TpLinkV2, "mktplinkfw2"),
    };
    let mut c = Container::new(FileFormat::TpLink, layout.label(), "tplink");
    c.consumed = header.end();
    c.notes.push(format!(
        "TP-Link firmware header, {tool} layout, version {}; {}",
        header.version,
        md5_text(header.md5)
    ));
    c.notes.push(header.fields.identity.clone());
    c.notes.push(format!(
        "Hardware ID 0x{:08X}, revision 0x{:X}; the hardware ID is a board identifier and names no architecture",
        header.hw_id, header.hw_rev
    ));
    c.notes.push(format!(
        "Kernel load address 0x{:08X}, entry point 0x{:08X}, read as big-endian; some boards store both little-endian (mktplinkfw -e, mktplinkfw2 FLAG_LE_KERNEL_LA_EP); addresses are not ISA evidence",
        header.kernel_load, header.kernel_entry
    ));
    if let Some(boot) = header.bootloader {
        c.notes.push(format!(
            "Bootloader of {} after the header; the second image header at 0x{:X} precedes the kernel and the root filesystem offset is relative to it",
            size_text(boot.len),
            header.image_base
        ));
    }
    if header.rootfs.is_none() {
        c.notes
            .push("No root filesystem declared (combined kernel image)".into());
    }
    if let Some(boot) = header.v1_boot {
        c.notes.push(format!(
            "Bootloader fields: offset 0x{:X}, {} B; the v1 layout does not establish where it is stored, so it is not extracted",
            boot.offset, boot.len
        ));
    }
    if let Some(vendor) = header.fields.vendor {
        c.push_metadata("tplink_vendor", "Vendor name", vendor);
    }
    c.push_metadata(
        "tplink_firmware_version",
        "Firmware version string",
        header.fields.fw_version,
    );
    c.push_metadata(
        "tplink_hardware_id",
        "Hardware ID",
        format!("0x{:08X}", header.hw_id),
    );
    c.push_metadata(
        "tplink_hardware_revision",
        "Hardware revision",
        format!("0x{:X}", header.hw_rev),
    );
    c.push_metadata(
        "tplink_kernel_load_address",
        "Kernel load address",
        format!("0x{:08X}", header.kernel_load),
    );
    c.push_metadata(
        "tplink_kernel_entry",
        "Kernel entry point",
        format!("0x{:08X}", header.kernel_entry),
    );
    c.push_metadata(
        "tplink_md5",
        "Salted MD5 (not verified)",
        hex_digest(header.md5),
    );

    let mut extractor = Extractor::default();
    if let Some(boot) = header.bootloader {
        c.children.push(Child::stored(
            "Bootloader",
            boot.offset,
            &data[boot.offset..boot.end()],
        ));
    }
    let kernel = header.kernel;
    c.children.push(extractor.component(
        "Kernel".into(),
        kernel.offset,
        &data[kernel.offset..kernel.end()],
        &mut c.notes,
    ));
    if let Some(rootfs) = header.rootfs {
        c.children.push(extractor.component(
            "Root filesystem".into(),
            rootfs.offset,
            &data[rootfs.offset..rootfs.end()],
            &mut c.notes,
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_words_select_the_layout() {
        assert_eq!(version_number(Generation::V1, VERSION_1), Some(1));
        assert_eq!(version_number(Generation::V1, VERSION_2), Some(2));
        assert_eq!(version_number(Generation::V1, VERSION_3), None);
        assert_eq!(version_number(Generation::V2, VERSION_1), None);
        assert_eq!(version_number(Generation::V2, VERSION_3), Some(3));
    }

    #[test]
    fn flash_fill_accepts_jffs2_marks_only_at_4_kib_boundaries() {
        let mut data = vec![0xffu8; 0x3000];
        data[0x1000..0x1004].copy_from_slice(&JFFS2_EOF_MARK);
        data[0x2000..0x2004].copy_from_slice(&JFFS2_EOF_MARK);
        assert!(is_flash_fill(&data, 0x800));
        data[0x2800..0x2804].copy_from_slice(&JFFS2_EOF_MARK);
        assert!(!is_flash_fill(&data, 0x800));
    }

    #[test]
    fn md5_text_distinguishes_unset_digests() {
        assert!(md5_text(&[0; MD5_SIZE]).contains("zero"));
        assert!(md5_text(&[1; MD5_SIZE]).contains("not verified"));
    }
}
