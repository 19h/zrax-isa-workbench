//! FMP capsules (UEFI 2.10, 23.3.2-23.3.3): the
//! `EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER` at `HeaderSize`, its
//! `ItemOffsetList`, the embedded drivers and the payload items, validated
//! as EDK2 `ValidateFmpCapsule` validates them; and nested FMP capsules,
//! whose outer GUID is a platform's ESRT firmware class (EDK2
//! `IsNestedFmpCapsule`).
//!
//! Layout of the capsule body, offsets relative to its start:
//!
//! - 0x00 `Version` (u32, 1), 0x04 `EmbeddedDriverCount` (u16), 0x06
//!   `PayloadItemCount` (u16), 0x08 `ItemOffsetList` (u64 each, drivers
//!   first, ascending);
//! - each item runs to the next item's offset, the last one to the end of
//!   the capsule (UEFI 2.10 23.3.3; EDK2 `ProcessFmpCapsuleImage`).

use super::payload::Payload;
use super::*;

/// `EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER_INIT_VERSION`.
const FMP_CAPSULE_HEADER_INIT_VERSION: u32 = 1;

/// `Version`, `EmbeddedDriverCount` and `PayloadItemCount`.
const FMP_CAPSULE_HEADER_SIZE: usize = 8;

/// One `ItemOffsetList` entry (u64).
const ITEM_OFFSET_SIZE: usize = 8;

/// The items of an FMP capsule, each with the bytes up to the next item.
struct Items<'a> {
    /// Embedded drivers (UEFI images for `LoadImage()`).
    drivers: Vec<Region<'a>>,
    /// Payload items, each starting with its image header.
    payloads: Vec<Region<'a>>,
}

/// Parse an FMP capsule: drivers and payload items as children, payload
/// firmware images first and embedded drivers last, so that a driver only
/// supplies the primary ISA when no payload has one.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, Layout::Fmp, &mut extra)?;
    let guid = bounds.capsule.guid(0, "CapsuleGuid")?;
    let mut c = new_container(Layout::Fmp, guid, bounds.capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, bounds.capsule, Layout::Fmp)?;
    // EDK2 `ValidateFmpCapsule`: "HeaderSize >= CapsuleImageSize" is invalid.
    if bounds.body.len() == 0 {
        return Err(error(format!(
            "Missing EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER at 0x{:X}: the capsule ends at its header",
            bounds.body.base
        )));
    }
    let items = items(bounds.body)?;
    c.push_metadata(
        "capsule_embedded_driver_count",
        "Embedded drivers",
        items.drivers.len() as u64,
    );
    c.push_metadata(
        "capsule_payload_count",
        "Payload items",
        items.payloads.len() as u64,
    );
    c.notes.push(format!(
        "EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER version 1 at 0x{:X}: {}, {}",
        bounds.body.base,
        counted(items.drivers.len(), "embedded driver", "embedded drivers"),
        counted(items.payloads.len(), "payload item", "payload items")
    ));
    if items.drivers.is_empty() && items.payloads.is_empty() {
        c.notes.push(
            "The capsule lists no drivers or payload items; UEFI 2.10 section 23.3.3: firmware does not process it"
                .into(),
        );
    }
    let mut listing = Listing::default();
    let mut unrecorded = 0usize;
    for (i, item) in items.payloads.iter().enumerate() {
        let number = i + 1;
        let payload = Payload::read(*item, number)?;
        if i < MAX_DETAIL_NOTES {
            payload.describe(&mut c, number);
        } else {
            unrecorded += 1;
        }
        payload.push_children(&mut c, number, &mut listing);
    }
    if unrecorded > 0 {
        c.notes.push(format!(
            "Notes and metadata for {} left out",
            counted(unrecorded, "further payload item", "further payload items")
        ));
    }
    for (i, driver) in items.drivers.iter().enumerate() {
        listing.push(&mut c, driver.child(format!("Embedded driver {}", i + 1)));
    }
    listing.finish(&mut c);
    Ok(c)
}

/// The `ItemOffsetList` of the FMP capsule body `body`, checked in the
/// order of EDK2 `ValidateFmpCapsule`: the header version, the item count
/// against the body size, then each offset (inside the body, after the
/// offset list, above the previous one). A capsule without items must end
/// at its 8-byte header.
fn items(body: Region<'_>) -> Result<Items<'_>> {
    let header = body.sub(
        0,
        FMP_CAPSULE_HEADER_SIZE,
        "EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER",
    )?;
    let version = header.u32(0, "Version")?;
    if version != FMP_CAPSULE_HEADER_INIT_VERSION {
        return Err(error(format!(
            "Unsupported EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER version {version} at 0x{:X} (1 expected)",
            header.base
        )));
    }
    let driver_count = usize::from(header.u16(4, "EmbeddedDriverCount")?);
    let payload_count = usize::from(header.u16(6, "PayloadItemCount")?);
    let count = driver_count + payload_count;
    if count > (body.len() - FMP_CAPSULE_HEADER_SIZE) / ITEM_OFFSET_SIZE {
        return Err(error(format!(
            "Invalid ItemOffsetList at 0x{:X}: {count} entries do not fit the {} B capsule body",
            body.offset(FMP_CAPSULE_HEADER_SIZE),
            body.len()
        )));
    }
    let list_end = FMP_CAPSULE_HEADER_SIZE + count * ITEM_OFFSET_SIZE;
    if count == 0 && body.len() != FMP_CAPSULE_HEADER_SIZE {
        return Err(error(format!(
            "Unexpected {} after an EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER without items at 0x{:X}",
            size_text(body.len() - FMP_CAPSULE_HEADER_SIZE),
            body.offset(FMP_CAPSULE_HEADER_SIZE)
        )));
    }
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        let offset = body.u64(
            FMP_CAPSULE_HEADER_SIZE + i * ITEM_OFFSET_SIZE,
            "ItemOffsetList",
        )?;
        if offset >= body.len() as u64 {
            return Err(error(format!(
                "Invalid ItemOffsetList[{i}] 0x{offset:X}: beyond the {} B capsule body",
                body.len()
            )));
        }
        if offset < list_end as u64 {
            return Err(error(format!(
                "Invalid ItemOffsetList[{i}] 0x{offset:X}: inside the {list_end} B FMP capsule header"
            )));
        }
        let offset = to_usize(offset, "ItemOffsetList entry")?;
        if let Some(&previous) = offsets.last() {
            if offset <= previous {
                return Err(error(format!(
                    "Invalid ItemOffsetList[{i}] 0x{offset:X}: not above the previous entry 0x{previous:X}"
                )));
            }
        }
        offsets.push(offset);
    }
    let mut regions = Vec::with_capacity(count);
    for (i, &offset) in offsets.iter().enumerate() {
        let end = offsets.get(i + 1).copied().unwrap_or(body.len());
        regions.push(body.sub(offset, end - offset, "FMP capsule item")?);
    }
    let payloads = regions.split_off(driver_count);
    Ok(Items {
        drivers: regions,
        payloads,
    })
}

/// Whether `data` is a nested FMP capsule that a weak recognition can
/// accept: the outer header fills the file exactly (UEFI 2.10 8.5.5) and
/// the inner FMP capsule parses completely.
pub(super) fn is_nested(data: &[u8]) -> bool {
    let fills_file = Extent::read(Region::new(data), Layout::NestedFmp)
        .is_ok_and(|extent| extent.end == data.len());
    fills_file && parse_nested(data).is_ok()
}

/// Parse a nested FMP capsule: an outer `EFI_CAPSULE_HEADER` whose GUID is
/// not documented, and at `HeaderSize` an FMP capsule whose
/// `CapsuleImageSize` is the rest of the outer capsule (EDK2
/// `IsNestedFmpCapsule` and `IsValidCapsuleHeader`). The inner capsule is
/// one child classified on its own; it must parse completely.
pub(super) fn parse_nested(data: &[u8]) -> Result<Container<'_>> {
    let mut extra = Vec::new();
    let bounds = bounds(data, Layout::NestedFmp, &mut extra)?;
    let guid = bounds.capsule.guid(0, "CapsuleGuid")?;
    let inner = bounds.body;
    let inner_guid = inner.guid(0, "nested capsule CapsuleGuid")?;
    if inner_guid != EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID {
        return Err(error(format!(
            "Missing nested FMP capsule at 0x{:X}: CapsuleGuid {inner_guid}",
            inner.base
        )));
    }
    let inner_size = to_usize(inner.u32(0x18, "nested capsule CapsuleImageSize")?, "size")?;
    if inner_size != inner.len() {
        return Err(error(format!(
            "Invalid nested FMP capsule at 0x{:X}: CapsuleImageSize {inner_size} B, {} B remain in the outer capsule",
            inner.base,
            inner.len()
        )));
    }
    if let Err(e) = parse(inner.bytes) {
        return Err(error(format!(
            "Invalid nested FMP capsule at 0x{:X}, offsets relative to it: {}",
            inner.base,
            bare_message(e)
        )));
    }
    let mut c = new_container(Layout::NestedFmp, guid, bounds.capsule.len());
    c.notes.extend(extra);
    push_efi_header(&mut c, bounds.capsule, Layout::NestedFmp)?;
    c.notes.push(
        "EDK2 processes such a capsule as nested FMP when its GUID is an ESRT firmware class of the platform; the file alone does not show that"
            .into(),
    );
    c.notes.push(format!(
        "FMP capsule: {} at 0x{:X}",
        size_text(inner.len()),
        inner.base
    ));
    c.children.push(inner.child("FMP capsule"));
    Ok(c)
}

/// The message of a capsule error without the family prefix.
fn bare_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::CapsuleParseError { message } => message,
        other => other.to_string(),
    }
}
