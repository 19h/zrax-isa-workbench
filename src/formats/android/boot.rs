//! Android boot images (`ANDROID!`, header versions 0 to 4) and `vendor_boot`
//! images (`VNDRBOOT`, versions 3 and 4), from `bootimg.h` and
//! `mkbootimg.py` at mkbootimg `d2bb0af5`.
//!
//! Versions 0 to 2 place every section on a `page_size` boundary after a
//! one-page header: kernel, ramdisk, second stage, then the recovery DTBO
//! (v1 and v2, at its absolute `recovery_dtbo_offset`) and the DTB (v2).
//! Versions 3 and 4 use fixed 4096-byte pages and hold only the kernel, the
//! generic ramdisk and (v4) a boot signature. `vendor_boot` images place the
//! vendor ramdisk section, the DTB, the vendor ramdisk table (v4) and the
//! bootconfig (v4) on the vendor `page_size`. Header fields are
//! little-endian: `bootimg.h` uses host order and every AOSP host and
//! target is little-endian.

use super::*;
use crate::formats::checksum::Sha1;

/// Header sizes in bytes (`boot_img_hdr_v0` and `BOOT_IMAGE_HEADER_V*_SIZE`).
const BOOT_V0_HEADER_SIZE: usize = 0x660;
const BOOT_V1_HEADER_SIZE: usize = 0x670;
const BOOT_V2_HEADER_SIZE: usize = 0x67c;
const BOOT_V3_HEADER_SIZE: usize = 0x62c;
const BOOT_V4_HEADER_SIZE: usize = 0x630;

/// `vendor_boot` header sizes (`VENDOR_BOOT_IMAGE_HEADER_V*_SIZE`).
const VENDOR_V3_HEADER_SIZE: usize = 0x840;
const VENDOR_V4_HEADER_SIZE: usize = 0x850;

/// `header_version` is the u32 at 0x28 in every boot image version.
const HEADER_VERSION: usize = 0x28;

/// Highest header version mkbootimg writes. In a v0 Qualcomm image built
/// with `LineageOS` `mkbootimg --dt`, the field holds `max(0, dt_size)`.
const MAX_HEADER_VERSION: u32 = 4;

/// Versions 3 and 4 always use 4096-byte pages
/// (`BOOT_IMAGE_HEADER_V3_PAGESIZE`).
const GKI_PAGE_SIZE: u32 = 4096;

/// Page sizes AOSP `mkbootimg.py` accepts (`--pagesize` choices 2^11-2^14).
const PAGE_SIZES: [u32; 4] = [2048, 4096, 8192, 16384];

/// Smallest and largest power-of-two page size accepted. Sizes above the
/// `mkbootimg.py` choices come from non-AOSP tools (our bound, UNCONFIRMED:
/// the spec notes do not establish them); Magisk reads a v0 `page_size` of
/// `0x02000000` or more as a Samsung PXA header, which is not supported.
const MIN_PAGE_SIZE: u32 = 2048;
const MAX_PAGE_SIZE: u32 = 128 << 10;

/// `certify_bootimg.py` appends a 16 KiB boot certificate block that the
/// v4 header does not describe.
const GKI_CERTIFICATE_SIZE: usize = 16 << 10;

/// `os_version` packs the version A.B.C above bit 11 (7 bits each) and the
/// patch level below it: year - 2000 in bits 10-4, month in bits 3-0.
const OS_VERSION_SHIFT: u32 = 11;
const OS_PATCH_LEVEL_MASK: u32 = 0x7ff;
const OS_VERSION_FIELD_MASK: u32 = 0x7f;
const OS_VERSION_MAJOR_SHIFT: u32 = 14;
const OS_VERSION_MINOR_SHIFT: u32 = 7;
const OS_PATCH_YEAR_SHIFT: u32 = 4;
const OS_PATCH_MONTH_MASK: u32 = 0xf;
const OS_PATCH_YEAR_BASE: u32 = 2000;

/// The image ID holds a 20-byte SHA-1 in its first 20 bytes.
const IMAGE_ID_SIZE: usize = 32;
const SHA1_SIZE: usize = 20;

/// `MediaTek` payload header (Magisk `mtk_hdr`): magic `0x58881688`
/// (little-endian), payload size, 32-byte name, padding to 512 bytes.
const MTK_MAGIC: u32 = 0x5888_1688;
const MTK_HEADER_SIZE: usize = 512;

/// `vendor_ramdisk_table_entry_v4` size; larger strides are allowed.
const VENDOR_RAMDISK_ENTRY_SIZE: u32 = 108;

/// Vendor ramdisk types (`VENDOR_RAMDISK_TYPE_*`).
const VENDOR_RAMDISK_TYPES: [&str; 4] = ["none", "platform", "recovery", "DLKM"];

/// Header fields of versions 0 to 2 (`boot_img_hdr_v0` to `_v2`). Addresses
/// are target physical addresses; sizes are bytes.
struct PagedHeader {
    kernel_size: u32,
    kernel_address: u32,
    ramdisk_size: u32,
    ramdisk_address: u32,
    second_size: u32,
    second_address: u32,
    tags_address: u32,
    page_size: u32,
    os_version: u32,
    name: String,
    cmdline: String,
    id: [u8; IMAGE_ID_SIZE],
    recovery_dtbo_size: u32,
    /// Absolute file offset of the recovery DTBO.
    recovery_dtbo_offset: u64,
    header_size: u32,
    dtb_size: u32,
    dtb_address: u64,
}

/// Header fields of versions 0 to 2. v0 layout: magic (8), then u32 kernel
/// size, kernel address, ramdisk size, ramdisk address, second size, second
/// address, tags address, page size, header version and OS version from
/// 0x08; name (16) at 0x30; cmdline (512) at 0x40; id (32) at 0x240; extra
/// cmdline (1024) at 0x260. v1 adds the recovery DTBO size (u32) at 0x660,
/// its file offset (u64) at 0x664 and the header size (u32) at 0x66C; v2
/// adds the DTB size (u32) at 0x670 and its address (u64) at 0x674.
fn paged_header(data: &[u8], version: u32) -> Result<PagedHeader> {
    let size = match version {
        0 => BOOT_V0_HEADER_SIZE,
        1 => BOOT_V1_HEADER_SIZE,
        _ => BOOT_V2_HEADER_SIZE,
    };
    let header = slice(data, 0, size, "boot image header")?;
    let mut cmdline = asciiz(&header[0x40..0x240]);
    cmdline.push_str(&asciiz(&header[0x260..0x660]));
    let (recovery_dtbo_size, recovery_dtbo_offset, header_size) = if version >= 1 {
        (
            le_u32(header, 0x660)?,
            le_u64(header, 0x664)?,
            le_u32(header, 0x66c)?,
        )
    } else {
        (0, 0, 0)
    };
    let (dtb_size, dtb_address) = if version >= 2 {
        (le_u32(header, 0x670)?, le_u64(header, 0x674)?)
    } else {
        (0, 0)
    };
    Ok(PagedHeader {
        kernel_size: le_u32(header, 0x08)?,
        kernel_address: le_u32(header, 0x0c)?,
        ramdisk_size: le_u32(header, 0x10)?,
        ramdisk_address: le_u32(header, 0x14)?,
        second_size: le_u32(header, 0x18)?,
        second_address: le_u32(header, 0x1c)?,
        tags_address: le_u32(header, 0x20)?,
        page_size: le_u32(header, 0x24)?,
        os_version: le_u32(header, 0x2c)?,
        name: asciiz(&header[0x30..0x40]),
        cmdline,
        id: field(header, 0x240)?,
        recovery_dtbo_size,
        recovery_dtbo_offset,
        header_size,
        dtb_size,
        dtb_address,
    })
}

/// Whole pages that `size` bytes occupy, `ceil(size / page_size)`. Sizes
/// are at most `u32::MAX`, so the sum cannot overflow.
fn pages(size: u64, page_size: u64) -> u64 {
    (size + page_size - 1) / page_size
}

/// Successive sections, each starting on a page boundary.
struct Pages {
    page_size: u64,
    next: u64,
}

impl Pages {
    /// Sections that start after a `header_size`-byte header rounded up
    /// to whole pages.
    fn after_header(page_size: u32, header_size: usize) -> Self {
        let page_size = u64::from(page_size);
        Self {
            page_size,
            next: pages(header_size as u64, page_size) * page_size,
        }
    }

    /// The file offset of the next `size`-byte section; the section after
    /// it starts on the following page boundary.
    fn place(&mut self, size: u32) -> Result<u64> {
        let offset = self.next;
        self.next = pages(u64::from(size), self.page_size)
            .checked_mul(self.page_size)
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| error("Invalid boot image section layout"))?;
        Ok(offset)
    }

    /// The end of the last placed section's padding, as a file offset.
    fn end(&self) -> usize {
        usize::try_from(self.next).unwrap_or(usize::MAX)
    }
}

/// The `size` bytes of `what` at file offset `offset`. An absent (empty)
/// section is not checked against the file, whose last padding may be
/// missing.
fn section<'a>(data: &'a [u8], offset: u64, size: u32, what: &str) -> Result<(usize, &'a [u8])> {
    if size == 0 {
        return Ok((usize::try_from(offset).unwrap_or(usize::MAX), &[]));
    }
    let bytes = slice64(data, offset, u64::from(size), what)?;
    let offset = usize::try_from(offset).expect("section lies in the file");
    Ok((offset, bytes))
}

/// A page size from the header: a power of two from 2 KiB to 128 KiB. A
/// size outside the `mkbootimg.py` choices is noted.
fn page_size(value: u32, what: &str, notes: &mut Vec<String>) -> Result<u32> {
    if !value.is_power_of_two() || !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&value) {
        return Err(error(format!("Unsupported {what} page size {value} B")));
    }
    if !PAGE_SIZES.contains(&value) {
        notes.push(format!(
            "Page size {} is outside the sizes AOSP mkbootimg.py writes",
            size_text(value as usize)
        ));
    }
    Ok(value)
}

/// The OS version and security patch level an `os_version` field encodes,
/// or `None` for a half that is zero (not set).
fn os_version(value: u32) -> (Option<String>, Option<String>) {
    let version = value >> OS_VERSION_SHIFT;
    let patch = value & OS_PATCH_LEVEL_MASK;
    let release = (version != 0).then(|| {
        format!(
            "{}.{}.{}",
            version >> OS_VERSION_MAJOR_SHIFT,
            (version >> OS_VERSION_MINOR_SHIFT) & OS_VERSION_FIELD_MASK,
            version & OS_VERSION_FIELD_MASK
        )
    });
    let patch_level = (patch != 0).then(|| {
        format!(
            "{}-{:02}",
            OS_PATCH_YEAR_BASE + (patch >> OS_PATCH_YEAR_SHIFT),
            patch & OS_PATCH_MONTH_MASK
        )
    });
    (release, patch_level)
}

/// Notes and metadata for the `os_version` field.
fn push_os_version(c: &mut Container<'_>, value: u32) {
    let (release, patch_level) = os_version(value);
    c.notes.push(format!(
        "OS version {}; security patch level {}",
        release.as_deref().unwrap_or("not set"),
        patch_level.as_deref().unwrap_or("not set")
    ));
    if let Some(release) = release {
        c.push_metadata("android_os_version", "OS version", release);
    }
    if let Some(patch_level) = patch_level {
        c.push_metadata(
            "android_os_patch_level",
            "Security patch level",
            patch_level,
        );
    }
}

/// Board name and command line, when set.
fn push_strings(c: &mut Container<'_>, name: &str, cmdline: &str) {
    if !name.is_empty() {
        c.notes.push(format!("Board name: {name}"));
        c.push_metadata("android_board_name", "Board name", name);
    }
    if !cmdline.is_empty() {
        c.push_metadata("android_cmdline", "Kernel command line", cmdline);
    }
}

/// A kernel or ramdisk section: a `MediaTek` payload header is stripped
/// (and noted), then the payload is decoded when compressed.
fn payload_section<'a>(
    label: &str,
    offset: usize,
    stored: &'a [u8],
    budget: &mut Budget,
    notes: &mut Vec<String>,
) -> Child<'a> {
    let (offset, stored) = strip_mediatek(label, offset, stored, notes);
    payload_child(label.to_string(), offset, stored, budget, notes)
}

/// The payload after a 512-byte `MediaTek` header, if `stored` starts with
/// one whose size fits: magic (4), payload size (4), name (32), padding.
fn strip_mediatek<'a>(
    label: &str,
    offset: usize,
    stored: &'a [u8],
    notes: &mut Vec<String>,
) -> (usize, &'a [u8]) {
    if le_u32(stored, 0).ok() != Some(MTK_MAGIC) || stored.len() < MTK_HEADER_SIZE {
        return (offset, stored);
    }
    let size = le_u32(stored, 4).unwrap_or_default() as usize;
    let name = asciiz(&stored[8..40]);
    if let Some(payload) = stored.get(MTK_HEADER_SIZE..MTK_HEADER_SIZE.saturating_add(size)) {
        notes.push(format!(
            "{label}: 512-byte MediaTek header \"{name}\" before the payload"
        ));
        (offset + MTK_HEADER_SIZE, payload)
    } else {
        notes.push(format!(
            "{label}: MediaTek header declares {size} B, more than the section holds; header kept"
        ));
        (offset, stored)
    }
}

/// Whether the first 20 bytes of `id` are mkbootimg's SHA-1 over each part
/// followed by its size as a little-endian u32, and the rest is zero.
fn is_mkbootimg_id(parts: &[&[u8]], id: &[u8; IMAGE_ID_SIZE]) -> bool {
    let mut sha = Sha1::new();
    for part in parts {
        sha.update(part);
        let size = u32::try_from(part.len()).expect("section sizes are u32");
        sha.update(&size.to_le_bytes());
    }
    let digest = sha.finish();
    id[..SHA1_SIZE] == digest && id[SHA1_SIZE..].iter().all(|&b| b == 0)
}

/// Parse a boot image; the header version selects the layout.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, HEADER_VERSION + 4, "boot image header")?;
    if !data.starts_with(BOOT_MAGIC) {
        return Err(error("Missing boot image magic"));
    }
    match le_u32(data, HEADER_VERSION)? {
        version @ 3..=MAX_HEADER_VERSION => parse_gki(data, version),
        version @ 0..=2 => parse_paged(data, version, None),
        // Do not read a large version as a future layout: Qualcomm v0
        // images store the appended device-tree size here.
        dt_size => parse_paged(data, 0, Some(dt_size)),
    }
}

/// Versions 0 to 2, and Qualcomm v0 images with a `dt_size` at 0x28.
fn parse_paged(data: &[u8], version: u32, dt_size: Option<u32>) -> Result<Container<'_>> {
    let header = paged_header(data, version)?;
    let variant = match dt_size {
        Some(_) => "Boot image header v0 (appended device tree)".to_string(),
        None => format!("Boot image header v{version}"),
    };
    let mut c = Container::new(FileFormat::AndroidBoot, variant, KEY_PREFIX);
    c.consumed = data.len();
    let mut page_notes = Vec::new();
    let page = page_size(header.page_size, "boot image", &mut page_notes)?;
    c.notes.push(match dt_size {
        Some(size) => format!(
            "Android boot image, header v0; page size {page} B; the header_version field holds the size of an appended device-tree image ({size} B), as Qualcomm (LineageOS mkbootimg --dt) and Samsung images use it"
        ),
        None => format!("Android boot image, header v{version}; page size {page} B"),
    });
    c.notes.append(&mut page_notes);
    push_os_version(&mut c, header.os_version);
    push_strings(&mut c, &header.name, &header.cmdline);
    c.push_metadata(
        "android_boot_header_version",
        "Header version",
        u64::from(version),
    );
    c.push_metadata("android_boot_page_size", "Page size (B)", u64::from(page));
    push_address(
        &mut c,
        "android_kernel_address",
        "Kernel load address",
        u64::from(header.kernel_address),
    );
    push_address(
        &mut c,
        "android_ramdisk_address",
        "Ramdisk load address",
        u64::from(header.ramdisk_address),
    );
    if header.second_size > 0 {
        push_address(
            &mut c,
            "android_second_address",
            "Second-stage load address",
            u64::from(header.second_address),
        );
    }
    push_address(
        &mut c,
        "android_tags_address",
        "Kernel tags address",
        u64::from(header.tags_address),
    );
    if version == 2 {
        push_address(
            &mut c,
            "android_dtb_address",
            "DTB load address",
            header.dtb_address,
        );
    }
    let expected_header_size = match version {
        1 => Some(BOOT_V1_HEADER_SIZE),
        2 => Some(BOOT_V2_HEADER_SIZE),
        _ => None,
    };
    if let Some(expected) = expected_header_size {
        if header.header_size as usize != expected {
            c.notes.push(format!(
                "Header size field is {} B, not {expected} B; the layout follows the version",
                header.header_size
            ));
        }
    }

    let mut pages = Pages::after_header(page, BOOT_V0_HEADER_SIZE);
    let mut budget = Budget::new();
    let (kernel_offset, kernel) = section(
        data,
        pages.place(header.kernel_size)?,
        header.kernel_size,
        "boot image kernel",
    )?;
    let (ramdisk_offset, ramdisk) = section(
        data,
        pages.place(header.ramdisk_size)?,
        header.ramdisk_size,
        "boot image ramdisk",
    )?;
    let (second_offset, second) = section(
        data,
        pages.place(header.second_size)?,
        header.second_size,
        "boot image second stage",
    )?;
    let appended_dt = match dt_size {
        Some(size) => Some(section(
            data,
            pages.place(size)?,
            size,
            "boot image appended device tree",
        )?),
        None => None,
    };
    // unpack_bootimg.py takes the DTB position from page counts that
    // include the recovery DTBO, and the DTBO itself from its offset field.
    let dtbo_page = pages.place(header.recovery_dtbo_size)?;
    let recovery_dtbo = if header.recovery_dtbo_size > 0 {
        let dtbo = section(
            data,
            header.recovery_dtbo_offset,
            header.recovery_dtbo_size,
            "boot image recovery DTBO",
        )?;
        if header.recovery_dtbo_offset != dtbo_page {
            c.notes.push(format!(
                "Recovery DTBO offset 0x{:X} differs from its page-aligned position 0x{dtbo_page:X}",
                header.recovery_dtbo_offset
            ));
        }
        Some(dtbo)
    } else {
        None
    };
    let dtb = section(
        data,
        pages.place(header.dtb_size)?,
        header.dtb_size,
        "boot image DTB",
    )?;

    let mut id_parts = vec![kernel, ramdisk, second];
    if let Some((_, dt)) = appended_dt {
        id_parts.push(dt);
    }
    if version >= 1 {
        id_parts.push(recovery_dtbo.map_or(&[][..], |(_, bytes)| bytes));
    }
    if version >= 2 {
        id_parts.push(dtb.1);
    }
    c.notes.push(if header.id.iter().all(|&b| b == 0) {
        "Image ID is empty".into()
    } else if is_mkbootimg_id(&id_parts, &header.id) {
        "Image ID matches the mkbootimg SHA-1 of the sections (an identifier, not a signature)"
            .into()
    } else {
        "Image ID is not the mkbootimg SHA-1 of the sections; vendor tools may store other values"
            .into()
    });
    c.notes.push(
        "The header names no CPU; the kernel and other sections are classified from their own bytes"
            .into(),
    );

    if !kernel.is_empty() {
        c.children.push(payload_section(
            "Kernel",
            kernel_offset,
            kernel,
            &mut budget,
            &mut c.notes,
        ));
    }
    if !ramdisk.is_empty() {
        c.children.push(payload_section(
            "Ramdisk",
            ramdisk_offset,
            ramdisk,
            &mut budget,
            &mut c.notes,
        ));
    }
    if !second.is_empty() {
        c.children
            .push(Child::stored("Second-stage loader", second_offset, second));
    }
    if let Some((offset, dt)) = appended_dt.filter(|(_, dt)| !dt.is_empty()) {
        c.children
            .push(Child::opaque("Appended device tree", offset, dt));
    }
    if let Some((offset, dtbo)) = recovery_dtbo {
        c.children
            .push(Child::opaque("Recovery DTBO", offset, dtbo));
    }
    if !dtb.1.is_empty() {
        c.children.push(Child::opaque("DTB", dtb.0, dtb.1));
    }
    push_unexplained_tail(&mut c, data, pages.end());
    Ok(c)
}

/// Versions 3 and 4. Layout: magic (8), u32 kernel size at 0x08, ramdisk
/// size at 0x0C, OS version at 0x10, header size at 0x14, reserved (16) at
/// 0x18, header version at 0x28, cmdline (1536) at 0x2C; v4 adds the boot
/// signature size (u32) at 0x62C.
fn parse_gki(data: &[u8], version: u32) -> Result<Container<'_>> {
    let size = if version == 3 {
        BOOT_V3_HEADER_SIZE
    } else {
        BOOT_V4_HEADER_SIZE
    };
    let header = slice(data, 0, size, "boot image header")?;
    let kernel_size = le_u32(header, 0x08)?;
    let ramdisk_size = le_u32(header, 0x0c)?;
    let header_size = le_u32(header, 0x14)?;
    let signature_size = if version == 4 {
        le_u32(header, 0x62c)?
    } else {
        0
    };
    let mut c = Container::new(
        FileFormat::AndroidBoot,
        format!("Boot image header v{version}"),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Android boot image, header v{version}; fixed {GKI_PAGE_SIZE} B pages; load addresses and the DTB are in vendor_boot"
    ));
    push_os_version(&mut c, le_u32(header, 0x10)?);
    push_strings(&mut c, "", &asciiz(&header[0x2c..0x62c]));
    c.push_metadata(
        "android_boot_header_version",
        "Header version",
        u64::from(version),
    );
    if header_size as usize != size {
        c.notes.push(format!(
            "Header size field is {header_size} B, not {size} B; the layout follows the version"
        ));
    }
    c.notes.push(
        "The header names no CPU; the kernel and ramdisk are classified from their own bytes"
            .into(),
    );

    let mut pages = Pages::after_header(GKI_PAGE_SIZE, size);
    let mut budget = Budget::new();
    let (kernel_offset, kernel) = section(
        data,
        pages.place(kernel_size)?,
        kernel_size,
        "boot image kernel",
    )?;
    let (ramdisk_offset, ramdisk) = section(
        data,
        pages.place(ramdisk_size)?,
        ramdisk_size,
        "boot image ramdisk",
    )?;
    let (signature_offset, signature) = section(
        data,
        pages.place(signature_size)?,
        signature_size,
        "boot image signature",
    )?;
    if !kernel.is_empty() {
        c.children.push(payload_section(
            "Kernel",
            kernel_offset,
            kernel,
            &mut budget,
            &mut c.notes,
        ));
    }
    if !ramdisk.is_empty() {
        c.children.push(payload_section(
            "Ramdisk",
            ramdisk_offset,
            ramdisk,
            &mut budget,
            &mut c.notes,
        ));
    }
    if !signature.is_empty() {
        c.notes.push(format!(
            "Boot signature: {signature_size} B (AVB vbmeta used by VTS); not verified"
        ));
        c.children
            .push(Child::opaque("Boot signature", signature_offset, signature));
    }
    let end = pages.end();
    let tail = push_partition_tail(&mut c, data, end);
    let rest = data.get(end..).unwrap_or_default();
    // certify_bootimg.py appends certificates (AVB vbmeta images) that the
    // header does not describe; an AVB footer's own vbmeta can sit there too.
    let is_footer_vbmeta = tail.vbmeta_offset == Some(end);
    if signature.is_empty() && rest.starts_with(AVB_VBMETA_MAGIC) && !is_footer_vbmeta {
        let certificate = &rest[..rest.len().min(GKI_CERTIFICATE_SIZE)];
        c.notes.push(format!(
            "Boot certificate block ({} B) after the ramdisk, not described by the header; not verified",
            certificate.len()
        ));
        c.children
            .push(Child::opaque("Boot certificate", end, certificate));
    } else if !tail.has_footer && !tail.has_marker && !is_padding(rest) {
        c.notes.push(format!(
            "{} after the last section are not described by the header",
            size_text(rest.len())
        ));
    }
    Ok(c)
}

/// `vendor_boot` header fields (`vendor_boot_img_hdr_v3` and `_v4`).
struct VendorHeader {
    version: u32,
    page_size: u32,
    kernel_address: u32,
    ramdisk_address: u32,
    vendor_ramdisk_size: u32,
    cmdline: String,
    tags_address: u32,
    name: String,
    header_size: u32,
    dtb_size: u32,
    dtb_address: u64,
    table_size: u32,
    table_entries: u32,
    table_entry_size: u32,
    bootconfig_size: u32,
}

/// `vendor_boot` header. Layout: magic (8), u32 header version at 0x08, page
/// size at 0x0C, kernel address at 0x10, ramdisk address at 0x14, vendor
/// ramdisk size at 0x18, cmdline (2048) at 0x1C, tags address at 0x81C,
/// name (16) at 0x820, header size at 0x830, DTB size at 0x834, DTB address
/// (u64) at 0x838; v4 adds the vendor ramdisk table size at 0x840, entry
/// count at 0x844, entry size at 0x848 and bootconfig size at 0x84C.
fn vendor_header(data: &[u8]) -> Result<VendorHeader> {
    slice(data, 0, 12, "vendor_boot header")?;
    if !data.starts_with(VENDOR_BOOT_MAGIC) {
        return Err(error("Missing vendor_boot magic"));
    }
    let version = le_u32(data, 0x08)?;
    let size = match version {
        3 => VENDOR_V3_HEADER_SIZE,
        4 => VENDOR_V4_HEADER_SIZE,
        _ => {
            return Err(error(format!(
                "Unsupported vendor_boot header version {version}"
            )))
        }
    };
    let header = slice(data, 0, size, "vendor_boot header")?;
    let v4 = |at: usize| {
        if version == 4 {
            le_u32(header, at)
        } else {
            Ok(0)
        }
    };
    Ok(VendorHeader {
        version,
        page_size: le_u32(header, 0x0c)?,
        kernel_address: le_u32(header, 0x10)?,
        ramdisk_address: le_u32(header, 0x14)?,
        vendor_ramdisk_size: le_u32(header, 0x18)?,
        cmdline: asciiz(&header[0x1c..0x81c]),
        tags_address: le_u32(header, 0x81c)?,
        name: asciiz(&header[0x820..0x830]),
        header_size: le_u32(header, 0x830)?,
        dtb_size: le_u32(header, 0x834)?,
        dtb_address: le_u64(header, 0x838)?,
        table_size: v4(0x840)?,
        table_entries: v4(0x844)?,
        table_entry_size: v4(0x848)?,
        bootconfig_size: v4(0x84c)?,
    })
}

/// One vendor ramdisk table entry: size, offset relative to the vendor
/// ramdisk section, type, name (32) at 0x0C, 16 board IDs at 0x2C.
struct VendorRamdisk {
    size: u32,
    offset: u32,
    kind: u32,
    name: String,
}

/// The vendor ramdisk table: `entries` records of `entry_size` bytes,
/// which must fit in the table's `table_size` bytes.
fn vendor_ramdisk_table(table: &[u8], entries: u32, entry_size: u32) -> Result<Vec<VendorRamdisk>> {
    if entry_size < VENDOR_RAMDISK_ENTRY_SIZE {
        return Err(error(format!(
            "Invalid vendor ramdisk table entry size {entry_size} B"
        )));
    }
    let fits = u64::from(entries) * u64::from(entry_size) <= table.len() as u64;
    if !fits {
        return Err(error(format!(
            "Invalid vendor ramdisk table: {entries} entries of {entry_size} B exceed the {} B table",
            table.len()
        )));
    }
    let stride = entry_size as usize;
    table
        .chunks_exact(stride)
        .take(entries as usize)
        .map(|entry| {
            Ok(VendorRamdisk {
                size: le_u32(entry, 0)?,
                offset: le_u32(entry, 4)?,
                kind: le_u32(entry, 8)?,
                name: asciiz(&entry[0x0c..0x2c]),
            })
        })
        .collect()
}

/// Display label of a vendor ramdisk table entry.
fn vendor_ramdisk_label(index: usize, entry: &VendorRamdisk) -> String {
    let kind = VENDOR_RAMDISK_TYPES.get(entry.kind as usize).map_or_else(
        || format!("type {}", entry.kind),
        |name| (*name).to_string(),
    );
    if entry.name.is_empty() {
        format!("Vendor ramdisk {index} ({kind})")
    } else {
        format!("Vendor ramdisk {} ({kind})", entry.name)
    }
}

/// Parse a `vendor_boot` image.
pub(super) fn parse_vendor(data: &[u8]) -> Result<Container<'_>> {
    let header = vendor_header(data)?;
    let version = header.version;
    let mut page_notes = Vec::new();
    let page = page_size(header.page_size, "vendor_boot", &mut page_notes)?;
    let header_size = if version == 3 {
        VENDOR_V3_HEADER_SIZE
    } else {
        VENDOR_V4_HEADER_SIZE
    };
    let mut c = Container::new(
        FileFormat::AndroidVendorBoot,
        format!("vendor_boot header v{version}"),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Android vendor_boot image, header v{version}; page size {page} B"
    ));
    c.notes.append(&mut page_notes);
    push_strings(&mut c, &header.name, &header.cmdline);
    c.push_metadata(
        "android_boot_header_version",
        "Header version",
        u64::from(version),
    );
    c.push_metadata("android_boot_page_size", "Page size (B)", u64::from(page));
    push_address(
        &mut c,
        "android_kernel_address",
        "Kernel load address",
        u64::from(header.kernel_address),
    );
    push_address(
        &mut c,
        "android_ramdisk_address",
        "Ramdisk load address",
        u64::from(header.ramdisk_address),
    );
    push_address(
        &mut c,
        "android_tags_address",
        "Kernel tags address",
        u64::from(header.tags_address),
    );
    push_address(
        &mut c,
        "android_dtb_address",
        "DTB load address",
        header.dtb_address,
    );
    if header.header_size as usize != header_size {
        c.notes.push(format!(
            "Header size field is {} B, not {header_size} B; the layout follows the version",
            header.header_size
        ));
    }
    c.notes.push(
        "The header names no CPU; load addresses are not ISA evidence; ramdisks are classified from their own bytes"
            .into(),
    );

    let mut pages = Pages::after_header(page, header_size);
    let (ramdisks_offset, ramdisks) = section(
        data,
        pages.place(header.vendor_ramdisk_size)?,
        header.vendor_ramdisk_size,
        "vendor ramdisk section",
    )?;
    let (dtb_offset, dtb) = section(
        data,
        pages.place(header.dtb_size)?,
        header.dtb_size,
        "vendor_boot DTB",
    )?;
    let (_, table) = section(
        data,
        pages.place(header.table_size)?,
        header.table_size,
        "vendor ramdisk table",
    )?;
    let (bootconfig_offset, bootconfig) = section(
        data,
        pages.place(header.bootconfig_size)?,
        header.bootconfig_size,
        "vendor_boot bootconfig",
    )?;

    let mut budget = Budget::new();
    if version == 4 && header.table_entries > 0 {
        let entries = vendor_ramdisk_table(table, header.table_entries, header.table_entry_size)?;
        let total: u64 = entries.iter().map(|e| u64::from(e.size)).sum();
        c.notes.push(format!(
            "Vendor ramdisk table: {} entries in a {} B section",
            entries.len(),
            ramdisks.len()
        ));
        if total != u64::from(header.vendor_ramdisk_size) {
            c.notes.push(format!(
                "Vendor ramdisk sizes add up to {total} B, not the {} B the header declares",
                header.vendor_ramdisk_size
            ));
        }
        for (i, entry) in entries.iter().enumerate() {
            if is_component_limit(c.children.len(), entries.len(), &mut c.notes) {
                break;
            }
            let stored = slice(
                ramdisks,
                entry.offset as usize,
                entry.size as usize,
                "vendor ramdisk",
            )
            .map_err(|_| {
                error(format!(
                    "Invalid vendor ramdisk table entry {i}: 0x{:X} + {} B is outside the {} B vendor ramdisk section",
                    entry.offset,
                    entry.size,
                    ramdisks.len()
                ))
            })?;
            if stored.is_empty() {
                continue;
            }
            let label = vendor_ramdisk_label(i, entry);
            let offset = ramdisks_offset + entry.offset as usize;
            let child = payload_child(label, offset, stored, &mut budget, &mut c.notes);
            c.children.push(child);
        }
    } else if !ramdisks.is_empty() {
        c.children.push(payload_child(
            "Vendor ramdisk".into(),
            ramdisks_offset,
            ramdisks,
            &mut budget,
            &mut c.notes,
        ));
    }
    if !dtb.is_empty() {
        c.children.push(Child::opaque("DTB", dtb_offset, dtb));
    }
    if !bootconfig.is_empty() {
        c.children
            .push(Child::opaque("Bootconfig", bootconfig_offset, bootconfig));
    }
    push_unexplained_tail(&mut c, data, pages.end());
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_decodes_release_and_patch_level() {
        // mkbootimg: (14 << 14 | 0 << 7 | 0) << 11 | (24 << 4 | 5)
        let value = ((14 << 14) << 11) | (24 << 4) | 5;
        assert_eq!(
            os_version(value),
            (Some("14.0.0".into()), Some("2024-05".into()))
        );
        assert_eq!(os_version(0), (None, None));
        let (year, month) = (20, 12);
        let value = (((11 << 14) | (2 << 7) | 3) << 11) | (year << 4) | month;
        assert_eq!(
            os_version(value),
            (Some("11.2.3".into()), Some("2020-12".into()))
        );
    }

    #[test]
    fn pages_round_each_section_up_to_the_page_size() {
        let mut pages = Pages::after_header(2048, BOOT_V0_HEADER_SIZE);
        assert_eq!(pages.place(1).unwrap(), 2048);
        assert_eq!(pages.place(2048).unwrap(), 4096);
        assert_eq!(pages.place(0).unwrap(), 6144);
        assert_eq!(pages.place(2049).unwrap(), 6144);
        assert_eq!(pages.end(), 10240);
        let vendor = Pages::after_header(2048, VENDOR_V4_HEADER_SIZE);
        assert_eq!(vendor.next, 4096, "a 2128 B header takes two 2048 B pages");
    }

    #[test]
    fn mediatek_header_is_stripped_only_when_its_size_fits() {
        let mut section = vec![0u8; MTK_HEADER_SIZE + 8];
        section[..4].copy_from_slice(&MTK_MAGIC.to_le_bytes());
        section[4..8].copy_from_slice(&8u32.to_le_bytes());
        section[8..14].copy_from_slice(b"KERNEL");
        let mut notes = Vec::new();
        let (offset, payload) = strip_mediatek("Kernel", 0x800, &section, &mut notes);
        assert_eq!((offset, payload.len()), (0x800 + MTK_HEADER_SIZE, 8));
        assert!(notes[0].contains("\"KERNEL\""));
        section[4..8].copy_from_slice(&9u32.to_le_bytes());
        let (offset, payload) = strip_mediatek("Kernel", 0x800, &section, &mut notes);
        assert_eq!((offset, payload.len()), (0x800, section.len()));
    }
}
