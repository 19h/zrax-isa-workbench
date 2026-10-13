//! Windows UX capsules (EDK2 `MdePkg/Include/IndustryStandard/WindowsUxCapsule.h`,
//! after Microsoft's "Windows UEFI Firmware Update Platform" specification,
//! which was not read): an `EFI_CAPSULE_HEADER`, then a
//! `DISPLAY_DISPLAY_PAYLOAD` (0x00 `Version`, 0x01 `Checksum`, 0x02
//! `ImageType`, 0x03 reserved, 0x04 `Mode`, 0x08 `OffsetX`, 0x0C `OffsetY`)
//! and the image shown while firmware updates. The checks follow EDK2
//! `DisplayCapsuleImage`. The image is data and listed as opaque.

use super::*;

/// `DISPLAY_DISPLAY_PAYLOAD.Version` that EDK2 accepts.
const DISPLAY_PAYLOAD_VERSION: u8 = 1;

/// Size of `DISPLAY_DISPLAY_PAYLOAD` before the image.
const DISPLAY_PAYLOAD_SIZE: usize = 16;

/// `ImageType` 0, the only type EDK2 displays: a BMP image.
const IMAGE_TYPE_BMP: u8 = 0;

/// Parse a Windows UX capsule. The 8-bit sum of the whole capsule must be
/// zero (EDK2 `CalculateCheckSum8`); it is verified.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, Layout::WindowsUx, &mut extra)?;
    let guid = bounds.capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(Layout::WindowsUx, guid, bounds.capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, bounds.capsule, Layout::WindowsUx)?;
    let body = bounds.body;
    if body.base != EFI_CAPSULE_HEADER_SIZE {
        c.notes.push(format!(
            "HeaderSize is {} B; EDK2 displays only UX capsules with the 28 B header",
            body.base
        ));
    }
    let payload = body.sub(0, DISPLAY_PAYLOAD_SIZE, "DISPLAY_DISPLAY_PAYLOAD")?;
    let version = payload.u8(0, "Version")?;
    if version != DISPLAY_PAYLOAD_VERSION {
        return Err(error(format!(
            "Unsupported DISPLAY_DISPLAY_PAYLOAD version {version} at 0x{:X} (1 expected)",
            payload.base
        )));
    }
    let sum = bounds
        .capsule
        .bytes
        .iter()
        .fold(0u8, |sum, b| sum.wrapping_add(*b));
    if sum != 0 {
        return Err(error(format!(
            "Invalid Windows UX capsule checksum: 8-bit sum 0x{sum:02X} (0 expected)"
        )));
    }
    let image_type = payload.u8(2, "ImageType")?;
    let mode = payload.u32(4, "Mode")?;
    let offset_x = payload.u32(8, "OffsetX")?;
    let offset_y = payload.u32(12, "OffsetY")?;
    let image = body.rest(DISPLAY_PAYLOAD_SIZE, "display image")?;
    // EDK2 rejects a payload that is no larger than its header.
    if image.len() == 0 {
        return Err(error(format!(
            "Missing display image at 0x{:X}",
            image.base
        )));
    }
    c.notes.push(format!(
        "DISPLAY_DISPLAY_PAYLOAD version 1: checksum verified; ImageType {image_type}, Mode {mode}, OffsetX {offset_x}, OffsetY {offset_y}; image {} at 0x{:X}",
        size_text(image.len()),
        image.base
    ));
    let label = if image_type == IMAGE_TYPE_BMP {
        "Display image (BMP)".to_string()
    } else {
        c.notes.push(format!(
            "ImageType {image_type} is not BMP (0), the only type EDK2 displays"
        ));
        format!("Display image (type {image_type})")
    };
    c.children.push(image.opaque_child(label));
    Ok(c)
}
