//! Vendor capsule headers that `UEFITool` A75 recognizes (`common/ffs.h`,
//! `FfsParser::parseCapsule`). No vendor document was read; the layouts and
//! checks are `UEFITool`'s.
//!
//! - Toshiba: 0x00 `CapsuleGuid`, 0x10 `HeaderSize`, 0x14 `FullSize`, 0x18
//!   `Flags`; the body starts at `HeaderSize`.
//! - AMI Aptio: an `EFI_CAPSULE_HEADER`, then 0x1C `RomImageOffset` and
//!   0x1E `RomLayoutOffset` (u16 each); the ROM image starts at
//!   `RomImageOffset`. `UEFITool` leaves the certificate and ROM area map
//!   between the header and the ROM image unparsed, and so does this
//!   module.

use super::*;

/// Parse a Toshiba capsule: the body is one child classified on its own.
/// The meaning of `Flags` is not documented, so it is reported raw.
pub(super) fn parse_toshiba(data: &[u8]) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, Layout::Toshiba, &mut extra)?;
    let capsule = bounds.capsule;
    let guid = capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(Layout::Toshiba, guid, capsule.len());
    c.notes.extend(extra);
    let flags = capsule.u32(0x18, "Flags")?;
    c.push_metadata(
        "capsule_header_size",
        "Header size (B)",
        bounds.body.base as u64,
    );
    c.push_metadata("capsule_flags", "Capsule flags", MetadataValue::Hex(flags));
    c.notes.push(format!(
        "Toshiba capsule header as UEFITool A75 reads it: HeaderSize {} B, FullSize {} B, Flags 0x{flags:08X} (meaning not documented)",
        bounds.body.base,
        capsule.len()
    ));
    push_body(&mut c, bounds.body, "Capsule body");
    Ok(c)
}

/// Parse an AMI Aptio capsule: the ROM image from `RomImageOffset` to
/// `CapsuleImageSize` is one child classified on its own. The signed
/// layout's signature is not verified.
pub(super) fn parse_aptio(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, layout, &mut extra)?;
    let capsule = bounds.capsule;
    let guid = capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(layout, guid, capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, capsule, layout)?;
    let header_size = to_usize(capsule.u32(0x10, "HeaderSize")?, "HeaderSize")?;
    let rom_image_offset = bounds.body.base;
    let rom_layout_offset = capsule.u16(0x1E, "RomLayoutOffset")?;
    c.push_metadata(
        "capsule_rom_image_offset",
        "ROM image offset",
        MetadataValue::Address(rom_image_offset as u64),
    );
    c.push_metadata(
        "capsule_rom_layout_offset",
        "ROM layout table offset",
        MetadataValue::Address(u64::from(rom_layout_offset)),
    );
    let signature = if layout == Layout::AptioSigned {
        "; signature not verified"
    } else {
        ""
    };
    c.notes.push(format!(
        "AMI Aptio header as UEFITool A75 reads it: RomImageOffset 0x{rom_image_offset:X}, RomLayoutOffset 0x{rom_layout_offset:X}{signature}"
    ));
    if header_size != rom_image_offset {
        c.notes.push(format!(
            "HeaderSize {header_size} B differs from RomImageOffset; the ROM image is taken at RomImageOffset, as UEFITool does"
        ));
    }
    push_body(&mut c, bounds.body, "ROM image");
    Ok(c)
}
