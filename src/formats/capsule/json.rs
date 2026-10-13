//! JSON capsules (UEFI 2.10, 23.5): the body is an
//! `EFI_JSON_CAPSULE_HEADER` (0x00 `Version`, 0x04 `CapsuleId`, 0x08
//! `PayloadLength`, u32 each) followed by `PayloadLength` bytes of JSON
//! for firmware configuration or update. The JSON schema is out of the
//! spec's scope, so the payload is listed as opaque data.

use super::*;

/// `EFI_JSON_CAPSULE_HEADER.Version`, "initially 0x00000001".
const JSON_CAPSULE_HEADER_VERSION: u32 = 1;

/// `Version`, `CapsuleId` and `PayloadLength`.
const JSON_CAPSULE_HEADER_SIZE: usize = 12;

/// Parse a JSON capsule. The payload must fit the body; bytes after it may
/// only be padding, because the capsule "must be constructed to consist of
/// a single `EFI_JSON_CAPSULE_HEADER` structure with JSON payload follows"
/// (23.5.3).
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, Layout::Json, &mut extra)?;
    let guid = bounds.capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(Layout::Json, guid, bounds.capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, bounds.capsule, Layout::Json)?;
    let body = bounds.body;
    let header = body.sub(0, JSON_CAPSULE_HEADER_SIZE, "EFI_JSON_CAPSULE_HEADER")?;
    let version = header.u32(0, "Version")?;
    if version != JSON_CAPSULE_HEADER_VERSION {
        return Err(error(format!(
            "Unsupported EFI_JSON_CAPSULE_HEADER version {version} at 0x{:X} (1 expected)",
            header.base
        )));
    }
    let capsule_id = header.u32(4, "CapsuleId")?;
    let length = to_usize(header.u32(8, "PayloadLength")?, "PayloadLength")?;
    let payload = body.sub(JSON_CAPSULE_HEADER_SIZE, length, "JSON payload")?;
    let rest = body.rest(JSON_CAPSULE_HEADER_SIZE + length, "capsule body")?;
    if !is_padding(rest.bytes) {
        return Err(error(format!(
            "Unexpected {} after the JSON payload at 0x{:X}",
            size_text(rest.len()),
            rest.base
        )));
    }
    c.push_metadata(
        "capsule_json_capsule_id",
        "JSON CapsuleId",
        MetadataValue::Hex(capsule_id),
    );
    c.notes.push(format!(
        "EFI_JSON_CAPSULE_HEADER version 1, CapsuleId 0x{capsule_id:08X}: JSON payload {} at 0x{:X}",
        size_text(length),
        payload.base
    ));
    if length == 0 {
        c.notes.push(
            "PayloadLength is 0; UEFI 2.10 section 23.5.3: firmware does not process the capsule"
                .into(),
        );
    } else {
        c.children.push(payload.opaque_child("JSON payload"));
    }
    Ok(c)
}
