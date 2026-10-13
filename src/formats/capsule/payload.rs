//! FMP payload items (UEFI 2.10, 23.3.2 and 23.1.2): the
//! `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER`, the update image passed
//! to `SetImage()` and the vendor code bytes after it.
//!
//! Inside the update image, in the order EDK2 `GenerateCapsule.py` writes
//! them and `FmpDxe` reads them: an optional
//! `EFI_FIRMWARE_IMAGE_AUTHENTICATION` (`MonotonicCount`, then a
//! `WIN_CERTIFICATE_UEFI_GUID`), an optional `EFI_FIRMWARE_IMAGE_DEP`
//! dependency expression, an optional EDK2 `FMP_PAYLOAD_HEADER` (`MSS1`),
//! then the firmware image itself.
//!
//! Image header, offsets from its start: 0x00 `Version` (1-3), 0x04
//! `UpdateImageTypeId`, 0x14 `UpdateImageIndex`, 0x15 reserved (3), 0x18
//! `UpdateImageSize`, 0x1C `UpdateVendorCodeSize`, 0x20
//! `UpdateHardwareInstance` (version 2 and later), 0x28
//! `ImageCapsuleSupport` (version 3).

use super::*;

/// `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER_INIT_VERSION`.
const IMAGE_HEADER_INIT_VERSION: u32 = 3;

/// Image header size of version 1, up to `UpdateHardwareInstance` (EDK2
/// `ValidateFmpCapsule`).
const IMAGE_HEADER_V1_SIZE: usize = 32;

/// Image header size of version 2, up to `ImageCapsuleSupport`.
const IMAGE_HEADER_V2_SIZE: usize = 40;

/// Image header size of version 3.
const IMAGE_HEADER_V3_SIZE: usize = 48;

/// `ImageCapsuleSupport`: the update image starts with
/// `EFI_FIRMWARE_IMAGE_AUTHENTICATION`.
const CAPSULE_SUPPORT_AUTHENTICATION: u64 = 0x1;

/// `ImageCapsuleSupport`: an `EFI_FIRMWARE_IMAGE_DEP` follows the
/// authentication data.
const CAPSULE_SUPPORT_DEPENDENCY: u64 = 0x2;

/// `MonotonicCount` before the certificate.
const MONOTONIC_COUNT_SIZE: usize = 8;

/// `WIN_CERTIFICATE_UEFI_GUID` without `CertData`: `dwLength`,
/// `wRevision`, `wCertificateType`, `CertType`.
const WIN_CERTIFICATE_UEFI_GUID_SIZE: usize = 24;

/// `WIN_CERTIFICATE.wRevision`.
const WIN_CERT_REVISION: u16 = 0x0200;

/// `WIN_CERTIFICATE.wCertificateType` for a GUID-typed certificate.
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

/// `EFI_CERT_TYPE_PKCS7_GUID` (EDK2 `ImageAuthentication.h`): DER PKCS#7
/// `SignedData`, the type UEFI 2.10 23.1.2 requires.
const EFI_CERT_TYPE_PKCS7_GUID: Guid = Guid::new(
    0x4AAF_D29D,
    0x68DF,
    0x49EE,
    [0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7],
);

/// `EFI_CERT_TYPE_RSA2048_SHA256_GUID` (EDK2 `WinCertificate.h`), which
/// EDK2 `GenFds` also writes for FMP payloads.
const EFI_CERT_TYPE_RSA2048_SHA256_GUID: Guid = Guid::new(
    0xA771_7414,
    0xC616,
    0x4977,
    [0x94, 0x20, 0x84, 0x47, 0x12, 0xA7, 0x35, 0xBF],
);

// Dependency expression opcodes (UEFI 2.10, Table 23.1).
const EFI_FMP_DEP_PUSH_GUID: u8 = 0x00;
const EFI_FMP_DEP_PUSH_VERSION: u8 = 0x01;
const EFI_FMP_DEP_VERSION_STR: u8 = 0x02;
const EFI_FMP_DEP_AND: u8 = 0x03;
const EFI_FMP_DEP_LTE: u8 = 0x0C;
const EFI_FMP_DEP_END: u8 = 0x0D;
const EFI_FMP_DEP_DECLARE_LENGTH: u8 = 0x0E;

/// `FMP_PAYLOAD_HEADER_SIGNATURE`, `SIGNATURE_32('M', 'S', 'S', '1')`.
const FMP_PAYLOAD_HEADER_SIGNATURE: [u8; 4] = *b"MSS1";

/// `FMP_PAYLOAD_HEADER`: signature, `HeaderSize`, `FwVersion`,
/// `LowestSupportedVersion`.
const FMP_PAYLOAD_HEADER_SIZE: usize = 16;

/// An `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER`.
#[derive(Debug, Clone, Copy)]
struct ImageHeader {
    version: u32,
    type_id: Guid,
    index: u8,
    /// `UpdateHardwareInstance`, from version 2.
    hardware_instance: Option<u64>,
    /// `ImageCapsuleSupport`, from version 3.
    capsule_support: Option<u64>,
}

/// The signature type named by `WIN_CERTIFICATE_UEFI_GUID.CertType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertType {
    Pkcs7,
    Rsa2048Sha256,
}

impl CertType {
    fn from_guid(guid: Guid) -> Option<Self> {
        if guid == EFI_CERT_TYPE_PKCS7_GUID {
            Some(Self::Pkcs7)
        } else if guid == EFI_CERT_TYPE_RSA2048_SHA256_GUID {
            Some(Self::Rsa2048Sha256)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pkcs7 => "PKCS7",
            Self::Rsa2048Sha256 => "RSA2048/SHA-256",
        }
    }
}

/// An `EFI_FIRMWARE_IMAGE_AUTHENTICATION`.
#[derive(Debug, Clone, Copy)]
struct Authentication<'a> {
    /// `MonotonicCount` and the whole certificate (`8 + dwLength` bytes).
    region: Region<'a>,
    monotonic_count: u64,
    cert_type: CertType,
}

/// An EDK2 `FMP_PAYLOAD_HEADER`.
#[derive(Debug, Clone, Copy)]
struct PayloadHeader {
    /// `HeaderSize`, in bytes.
    size: usize,
    fw_version: u32,
    lowest_supported_version: u32,
}

/// One payload item of an FMP capsule.
#[derive(Debug, Clone, Copy)]
pub(super) struct Payload<'a> {
    /// File offset of the image header.
    offset: usize,
    header: ImageHeader,
    /// The `UpdateImageSize` bytes after the image header.
    update_image: Region<'a>,
    /// The `UpdateVendorCodeSize` bytes after the update image.
    vendor_code: Region<'a>,
    auth: Option<Authentication<'a>>,
    /// The dependency expression, END opcode included.
    dependency: Option<Region<'a>>,
    fmp_header: Option<PayloadHeader>,
    /// The firmware image after every header.
    image: Region<'a>,
}

impl<'a> Payload<'a> {
    /// Read payload item `number` (from 1) from `item`, which runs to the
    /// next item or the end of the capsule. Its size must equal the image
    /// header, `UpdateImageSize` and `UpdateVendorCodeSize` together (EDK2
    /// `ValidateFmpCapsule`).
    pub(super) fn read(item: Region<'a>, number: usize) -> Result<Self> {
        let what = "EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER";
        let version = item.u32(0, what)?;
        let header_size = match version {
            1 => IMAGE_HEADER_V1_SIZE,
            2 => IMAGE_HEADER_V2_SIZE,
            IMAGE_HEADER_INIT_VERSION => IMAGE_HEADER_V3_SIZE,
            _ => {
                return Err(error(format!(
                    "Unsupported {what} version {version} at 0x{:X} (1 to 3 expected)",
                    item.base
                )))
            }
        };
        let fields = item.sub(0, header_size, what)?;
        let header = ImageHeader {
            version,
            type_id: fields.guid(0x04, "UpdateImageTypeId")?,
            index: fields.u8(0x14, "UpdateImageIndex")?,
            hardware_instance: (version >= 2)
                .then(|| fields.u64(0x20, "UpdateHardwareInstance"))
                .transpose()?,
            capsule_support: (version >= 3)
                .then(|| fields.u64(0x28, "ImageCapsuleSupport"))
                .transpose()?,
        };
        let image_size = fields.u32(0x18, "UpdateImageSize")?;
        let vendor_code_size = fields.u32(0x1C, "UpdateVendorCodeSize")?;
        let declared = header_size as u64 + u64::from(image_size) + u64::from(vendor_code_size);
        if declared != item.len() as u64 {
            return Err(error(format!(
                "Invalid payload item {number} at 0x{:X}: {} B, but the image header, UpdateImageSize and UpdateVendorCodeSize give {declared} B",
                item.base,
                item.len()
            )));
        }
        let image_size = to_usize(image_size, "UpdateImageSize")?;
        let update_image = item.sub(header_size, image_size, "update image")?;
        let vendor_code = item.rest(header_size + image_size, "vendor code")?;
        let support = header.capsule_support.unwrap_or(0);
        let auth = authentication(update_image, support & CAPSULE_SUPPORT_AUTHENTICATION != 0)?;
        let after_auth = update_image.rest(auth.map_or(0, |a| a.region.len()), "update image")?;
        let dependency = if support & CAPSULE_SUPPORT_DEPENDENCY != 0 {
            Some(dependency(after_auth)?)
        } else {
            None
        };
        let after_dependency =
            after_auth.rest(dependency.map_or(0, Region::len), "update image")?;
        let fmp_header = payload_header(after_dependency)?;
        let image = after_dependency.rest(fmp_header.map_or(0, |h| h.size), "firmware image")?;
        Ok(Self {
            offset: item.base,
            header,
            update_image,
            vendor_code,
            auth,
            dependency,
            fmp_header,
            image,
        })
    }

    /// Notes and metadata for payload item `number`.
    pub(super) fn describe(&self, c: &mut Container<'_>, number: usize) {
        let h = &self.header;
        let mut fields = vec![
            format!("image header version {}", h.version),
            format!("UpdateImageTypeId {}", h.type_id),
            format!("UpdateImageIndex {}", h.index),
        ];
        if let Some(instance) = h.hardware_instance {
            fields.push(format!("UpdateHardwareInstance 0x{instance:X}"));
        }
        if let Some(support) = h.capsule_support {
            fields.push(format!(
                "ImageCapsuleSupport 0x{support:X}{}",
                support_names(support)
            ));
        }
        c.notes.push(format!(
            "Payload item {number} at 0x{:X}: {}",
            self.offset,
            fields.join(", ")
        ));
        c.notes.push(self.contents_note(number));
        let key = format!("capsule_payload_{number}");
        c.push_metadata(
            format!("{key}_type_id"),
            format!("Payload {number} UpdateImageTypeId"),
            h.type_id.to_string(),
        );
        c.push_metadata(
            format!("{key}_image_index"),
            format!("Payload {number} UpdateImageIndex"),
            u64::from(h.index),
        );
        if let Some(p) = self.fmp_header {
            c.push_metadata(
                format!("{key}_fw_version"),
                format!("Payload {number} FwVersion"),
                MetadataValue::Hex(p.fw_version),
            );
            c.push_metadata(
                format!("{key}_lowest_supported_version"),
                format!("Payload {number} LowestSupportedVersion"),
                MetadataValue::Hex(p.lowest_supported_version),
            );
        }
    }

    /// `Payload item 1 update image (...): ...`: what the update image
    /// holds.
    fn contents_note(&self, number: usize) -> String {
        let mut parts = Vec::new();
        if let Some(a) = self.auth {
            parts.push(format!(
                "EFI_FIRMWARE_IMAGE_AUTHENTICATION {} ({} signature, MonotonicCount 0x{:X}; not verified)",
                size_text(a.region.len()),
                a.cert_type.name(),
                a.monotonic_count
            ));
        }
        if let Some(d) = self.dependency {
            parts.push(format!(
                "EFI_FIRMWARE_IMAGE_DEP {} (not evaluated)",
                size_text(d.len())
            ));
        }
        if let Some(p) = self.fmp_header {
            parts.push(format!(
                "FMP_PAYLOAD_HEADER (FwVersion 0x{:08X}, LowestSupportedVersion 0x{:08X})",
                p.fw_version, p.lowest_supported_version
            ));
        }
        if self.image.len() == 0 {
            parts.push("no firmware image after the headers".into());
        } else {
            parts.push(format!(
                "firmware image {} at 0x{:X}",
                size_text(self.image.len()),
                self.image.base
            ));
        }
        parts.push(format!("vendor code {}", size_text(self.vendor_code.len())));
        format!(
            "Payload item {number} update image ({} at 0x{:X}): {}",
            size_text(self.update_image.len()),
            self.update_image.base,
            parts.join("; ")
        )
    }

    /// The firmware image (classified on its own), then the authentication
    /// data and the vendor code (opaque).
    pub(super) fn push_children(
        &self,
        c: &mut Container<'a>,
        number: usize,
        listing: &mut Listing,
    ) {
        if self.image.len() > 0 {
            let label = format!("Payload {number} ({})", self.header.type_id);
            listing.push(c, self.image.child(label));
        }
        if let Some(a) = self.auth {
            let label = format!(
                "Payload {number} authentication ({} signature, not verified)",
                a.cert_type.name()
            );
            listing.push(c, a.region.opaque_child(label));
        }
        if self.vendor_code.len() > 0 {
            let label = format!("Payload {number} vendor code");
            listing.push(c, self.vendor_code.opaque_child(label));
        }
    }
}

/// ` (authentication, dependency)` for the `ImageCapsuleSupport` bits.
fn support_names(support: u64) -> String {
    let mut names = Vec::new();
    if support & CAPSULE_SUPPORT_AUTHENTICATION != 0 {
        names.push("authentication".to_string());
    }
    if support & CAPSULE_SUPPORT_DEPENDENCY != 0 {
        names.push("dependency".to_string());
    }
    let undefined = support & !(CAPSULE_SUPPORT_AUTHENTICATION | CAPSULE_SUPPORT_DEPENDENCY);
    if undefined != 0 {
        names.push(format!("undefined bits 0x{undefined:X}"));
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join(", "))
    }
}

/// The `EFI_FIRMWARE_IMAGE_AUTHENTICATION` at the start of `image`.
///
/// It is present when `required` (`CAPSULE_SUPPORT_AUTHENTICATION`), or,
/// for image headers before version 3 and capsules that do not set the
/// bit, when its `CertType` is a signature type EDK2 writes: the evidence
/// EDK2 `GenerateCapsule.py` (`IsSigned`) uses. Once present, its revision,
/// certificate type and `dwLength` must be valid.
fn authentication(image: Region<'_>, required: bool) -> Result<Option<Authentication<'_>>> {
    let cert_type_at = MONOTONIC_COUNT_SIZE + 8;
    if !required {
        let named = image
            .guid(cert_type_at, "CertType")
            .ok()
            .and_then(CertType::from_guid);
        if named.is_none() {
            return Ok(None);
        }
    }
    let what = "EFI_FIRMWARE_IMAGE_AUTHENTICATION";
    let header = image.sub(
        0,
        MONOTONIC_COUNT_SIZE + WIN_CERTIFICATE_UEFI_GUID_SIZE,
        what,
    )?;
    let monotonic_count = header.u64(0, "MonotonicCount")?;
    let length = header.u32(8, "dwLength")?;
    let revision = header.u16(12, "wRevision")?;
    let certificate_type = header.u16(14, "wCertificateType")?;
    let cert_guid = header.guid(cert_type_at, "CertType")?;
    if revision != WIN_CERT_REVISION {
        return Err(error(format!(
            "Invalid WIN_CERTIFICATE wRevision 0x{revision:04X} at 0x{:X} (0x0200 expected)",
            header.offset(12)
        )));
    }
    if certificate_type != WIN_CERT_TYPE_EFI_GUID {
        return Err(error(format!(
            "Unsupported WIN_CERTIFICATE wCertificateType 0x{certificate_type:04X} at 0x{:X} (WIN_CERT_TYPE_EFI_GUID 0x0EF1 expected)",
            header.offset(14)
        )));
    }
    let cert_type = CertType::from_guid(cert_guid).ok_or_else(|| {
        error(format!(
            "Unsupported CertType {cert_guid} at 0x{:X} (PKCS7 or RSA2048/SHA-256 expected)",
            header.offset(cert_type_at)
        ))
    })?;
    let length = to_usize(length, "dwLength")?;
    if length < WIN_CERTIFICATE_UEFI_GUID_SIZE {
        return Err(error(format!(
            "Invalid WIN_CERTIFICATE dwLength {length} B at 0x{:X}: smaller than the {WIN_CERTIFICATE_UEFI_GUID_SIZE} B header",
            header.offset(8)
        )));
    }
    let size = length
        .checked_add(MONOTONIC_COUNT_SIZE)
        .ok_or_else(|| error("Invalid WIN_CERTIFICATE dwLength"))?;
    let region = image.sub(0, size, what)?;
    Ok(Some(Authentication {
        region,
        monotonic_count,
        cert_type,
    }))
}

/// The `EFI_FIRMWARE_IMAGE_DEP` at the start of `bytes`, up to and
/// including its END opcode, walked with the operand lengths of EDK2
/// `ValidateDependency`. Every opcode advances at least one byte, so the
/// walk is bounded by the image size.
fn dependency(bytes: Region<'_>) -> Result<Region<'_>> {
    let mut at = 0;
    while let Some(&opcode) = bytes.bytes.get(at) {
        let length = match opcode {
            EFI_FMP_DEP_PUSH_GUID => 1 + 16,
            EFI_FMP_DEP_PUSH_VERSION | EFI_FMP_DEP_DECLARE_LENGTH => 1 + 4,
            EFI_FMP_DEP_VERSION_STR => {
                let text = &bytes.bytes[at + 1..];
                let nul = text.iter().position(|&b| b == 0).ok_or_else(|| {
                    error(format!(
                        "Truncated DECLARE_VERSION_NAME string at 0x{:X}: no NUL terminator",
                        bytes.offset(at + 1)
                    ))
                })?;
                1 + nul + 1
            }
            EFI_FMP_DEP_AND..=EFI_FMP_DEP_LTE => 1,
            EFI_FMP_DEP_END => return bytes.sub(0, at + 1, "EFI_FIRMWARE_IMAGE_DEP"),
            other => {
                return Err(error(format!(
                    "Invalid dependency opcode 0x{other:02X} at 0x{:X}",
                    bytes.offset(at)
                )))
            }
        };
        at += length;
    }
    Err(error(format!(
        "Missing END opcode in the EFI_FIRMWARE_IMAGE_DEP at 0x{:X}",
        bytes.base
    )))
}

/// The EDK2 `FMP_PAYLOAD_HEADER` at the start of `bytes`, when it starts
/// with `MSS1`. `HeaderSize` must cover the 16-byte header and fit the
/// update image (EDK2 `GetFmpPayloadHeaderSize`).
fn payload_header(bytes: Region<'_>) -> Result<Option<PayloadHeader>> {
    if bytes.bytes.get(..4) != Some(&FMP_PAYLOAD_HEADER_SIGNATURE[..]) {
        return Ok(None);
    }
    let header = bytes.sub(0, FMP_PAYLOAD_HEADER_SIZE, "FMP_PAYLOAD_HEADER")?;
    let size = to_usize(
        header.u32(4, "HeaderSize")?,
        "FMP_PAYLOAD_HEADER HeaderSize",
    )?;
    if size < FMP_PAYLOAD_HEADER_SIZE {
        return Err(error(format!(
            "Invalid FMP_PAYLOAD_HEADER HeaderSize {size} B at 0x{:X}: smaller than {FMP_PAYLOAD_HEADER_SIZE} B",
            header.offset(4)
        )));
    }
    bytes.sub(0, size, "FMP_PAYLOAD_HEADER")?;
    Ok(Some(PayloadHeader {
        size,
        fw_version: header.u32(8, "FwVersion")?,
        lowest_supported_version: header.u32(12, "LowestSupportedVersion")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_walk_stops_after_end_and_rejects_unknown_opcodes() {
        // PUSH_GUID <16 B>, PUSH_VERSION 1, GTE, DECLARE_VERSION_NAME "v1", END
        let mut expression = vec![EFI_FMP_DEP_PUSH_GUID];
        expression.extend_from_slice(&[0xAA; 16]);
        expression.extend_from_slice(&[EFI_FMP_DEP_PUSH_VERSION, 1, 0, 0, 0, 0x0A]);
        expression.extend_from_slice(&[EFI_FMP_DEP_VERSION_STR, b'v', b'1', 0, EFI_FMP_DEP_END]);
        let length = expression.len();
        expression.extend_from_slice(b"MSS1");
        let region = Region::new(&expression);
        assert_eq!(dependency(region).unwrap().len(), length);
        assert!(dependency(Region::new(&expression[..length - 1])).is_err());
        assert!(dependency(Region::new(&[0x0F, EFI_FMP_DEP_END])).is_err());
        assert!(dependency(Region::new(&[EFI_FMP_DEP_VERSION_STR, b'x'])).is_err());
        assert!(dependency(Region::new(&[])).is_err());
    }

    #[test]
    fn payload_header_needs_its_signature_and_a_fitting_size() {
        let mut header = b"MSS1".to_vec();
        header.extend_from_slice(&16u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());
        let parsed = payload_header(Region::new(&header)).unwrap().unwrap();
        assert_eq!((parsed.size, parsed.fw_version), (16, 2));
        assert!(payload_header(Region::new(b"MSS2")).unwrap().is_none());
        header[4] = 15;
        assert!(payload_header(Region::new(&header)).is_err());
        header[4] = 17;
        assert!(payload_header(Region::new(&header)).is_err());
    }
}
