//! UEFI capsules: `EFI_CAPSULE_GUID`, FMP (image header versions 1-3,
//! authentication, dependency expressions, `FMP_PAYLOAD_HEADER`, vendor
//! code, embedded drivers), nested FMP, JSON, Windows UX, Intel, Lenovo,
//! Toshiba and AMI Aptio capsules built around the UEFI firmware volume
//! fixture: children classified on their own bytes in stored coordinates,
//! payloads before drivers, corrupted fields, truncation and mutation
//! sweeps. Real firmware volumes and EFI images from `IDA_INPUT_DIR` and
//! capsules from `UEFI_CAPSULE_DIR` are checked when those are set.

use std::path::{Path, PathBuf};
use zrax::formats::capsule::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa, MetadataKey};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/uefi");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn assert_note(p: &DetectionPayload, text: &str) {
    assert!(has_note(p, text), "missing note {text:?}: {:#?}", p.notes);
}

fn metadata(p: &DetectionPayload, key: &str) -> String {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}: {:?}", p.metadata))
        .value
        .to_string()
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label}: {:#?}", p.slices))
}

fn labels(p: &DetectionPayload) -> Vec<&str> {
    p.slices.iter().filter_map(|s| s.label.as_deref()).collect()
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// On-disk bytes of an `EFI_GUID`: `data1`, `data2`, `data3`
/// little-endian, then `data4` in order.
fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&data1.to_le_bytes());
    out[4..6].copy_from_slice(&data2.to_le_bytes());
    out[6..8].copy_from_slice(&data3.to_le_bytes());
    out[8..].copy_from_slice(&data4);
    out
}

// Capsule GUIDs (UEFI 2.10 23.3.1 and 23.5.1, EDK2 headers, UEFITool A75
// `ffs.h`).
const EFI_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x3B66_86BD,
    0x0D76,
    0x4030,
    [0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0],
);
const FMP_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x6DCB_D5ED,
    0xE82D,
    0x4C44,
    [0xBD, 0xA1, 0x71, 0x94, 0x19, 0x9A, 0xD9, 0x2A],
);
const JSON_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x67D6_F4CD,
    0xD6B8,
    0x4573,
    [0xBF, 0x4A, 0xDE, 0x5E, 0x25, 0x2D, 0x61, 0xAE],
);
const WINDOWS_UX_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x3B8C_8162,
    0x188C,
    0x46A4,
    [0xAE, 0xC9, 0xBE, 0x43, 0xF1, 0xD6, 0x56, 0x97],
);
const INTEL_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x5391_82B9,
    0xABB5,
    0x4391,
    [0xB6, 0x9A, 0xE3, 0xA9, 0x43, 0xF7, 0x2F, 0xCC],
);
const LENOVO2_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x25B5_FE76,
    0x8243,
    0x4A5C,
    [0xA9, 0xBD, 0x7E, 0xE3, 0x24, 0x61, 0x98, 0xB5],
);
const TOSHIBA_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x3BE0_7062,
    0x1D51,
    0x45D2,
    [0x83, 0x2B, 0xF0, 0x93, 0x25, 0x7E, 0xD4, 0x61],
);
const APTIO_SIGNED_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x4A3C_A68B,
    0x7723,
    0x48FB,
    [0x80, 0x3D, 0x57, 0x8C, 0xC1, 0xFE, 0xC4, 0x4D],
);
const APTIO_UNSIGNED_CAPSULE_GUID: (u32, u16, u16, [u8; 8]) = (
    0x14EE_BB90,
    0x890A,
    0x43DB,
    [0xAE, 0xD1, 0x5D, 0x3C, 0x45, 0x88, 0xA4, 0x18],
);

// Signature types (EDK2 `ImageAuthentication.h`, `WinCertificate.h`).
const EFI_CERT_TYPE_PKCS7_GUID: (u32, u16, u16, [u8; 8]) = (
    0x4AAF_D29D,
    0x68DF,
    0x49EE,
    [0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7],
);
const EFI_CERT_TYPE_RSA2048_SHA256_GUID: (u32, u16, u16, [u8; 8]) = (
    0xA771_7414,
    0xC616,
    0x4977,
    [0x94, 0x20, 0x84, 0x47, 0x12, 0xA7, 0x35, 0xBF],
);

fn guid_bytes(parts: (u32, u16, u16, [u8; 8])) -> [u8; 16] {
    guid(parts.0, parts.1, parts.2, parts.3)
}

/// A synthetic `UpdateImageTypeId` or ESRT firmware class.
fn type_id(n: u8) -> [u8; 16] {
    guid(0x5A1E_7E57, 0, 0x4000, [0x80, 0, 0, 0, 0, 0, 0, 0xC0 + n])
}

const UEFI_HEADER_SIZE: usize = 0x20;
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
const CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE: u32 = 0x0002_0000;
const CAPSULE_FLAGS_INITIATE_RESET: u32 = 0x0004_0000;
const CAPSULE_SUPPORT_AUTHENTICATION: u64 = 0x1;
const CAPSULE_SUPPORT_DEPENDENCY: u64 = 0x2;
const WIN_CERT_REVISION: u16 = 0x0200;
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// Dependency opcodes (UEFI 2.10 Table 23.1).
const EFI_FMP_DEP_PUSH_GUID: u8 = 0x00;
const EFI_FMP_DEP_PUSH_VERSION: u8 = 0x01;
const EFI_FMP_DEP_GTE: u8 = 0x0A;
const EFI_FMP_DEP_END: u8 = 0x0D;

/// The 4 KiB `FFSv2` firmware volume of the UEFI fixtures; its first image
/// is an x86-64 PE32 driver.
fn firmware_volume() -> Vec<u8> {
    fixture("sample.fd")
}

/// The minimal x86-64 PE32+ image inside `pe32-sections.bin` (after the
/// 4-byte section header, 0x1AC bytes), with `Machine` (PE offset 0x44)
/// set to `machine`.
fn pe_image(machine: u16) -> Vec<u8> {
    let sections = fixture("pe32-sections.bin");
    let mut image = sections[4..0x1B0].to_vec();
    image[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
    image
}

/// An `EFI_CAPSULE_HEADER` capsule (UEFI 2.10 8.5.3.1): `CapsuleGuid`,
/// `HeaderSize`, `Flags`, `CapsuleImageSize` (header plus body), zero fill
/// up to `header_size` (EDK2 writes 0x20), then the body.
fn efi_capsule(guid: [u8; 16], header_size: usize, flags: u32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; header_size];
    out[..16].copy_from_slice(&guid);
    put_u32(&mut out, 0x10, header_size as u32);
    put_u32(&mut out, 0x14, flags);
    put_u32(&mut out, 0x18, (header_size + body.len()) as u32);
    out.extend_from_slice(body);
    out
}

/// An FMP capsule body (UEFI 2.10 23.3.2): `Version` 1,
/// `EmbeddedDriverCount`, `PayloadItemCount`, `ItemOffsetList` (u64,
/// relative to the body), then the drivers and the payload items.
fn fmp_body(drivers: &[Vec<u8>], payloads: &[Vec<u8>]) -> Vec<u8> {
    let count = drivers.len() + payloads.len();
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(drivers.len() as u16).to_le_bytes());
    out.extend_from_slice(&(payloads.len() as u16).to_le_bytes());
    let mut offset = 8 + 8 * count;
    for item in drivers.iter().chain(payloads) {
        out.extend_from_slice(&(offset as u64).to_le_bytes());
        offset += item.len();
    }
    for item in drivers.iter().chain(payloads) {
        out.extend_from_slice(item);
    }
    out
}

/// Fields of one `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER` and the
/// bytes after it.
struct Item<'a> {
    /// 1 (32-byte header), 2 (40 B, `UpdateHardwareInstance`) or 3 (48 B,
    /// `ImageCapsuleSupport`).
    version: u32,
    type_id: [u8; 16],
    index: u8,
    hardware_instance: u64,
    capsule_support: u64,
    /// `UpdateImageSize` bytes.
    update_image: &'a [u8],
    /// `UpdateVendorCodeSize` bytes.
    vendor_code: &'a [u8],
}

impl<'a> Item<'a> {
    /// A version 3 item without vendor code.
    fn v3(type_id: [u8; 16], capsule_support: u64, update_image: &'a [u8]) -> Self {
        Self {
            version: 3,
            type_id,
            index: 1,
            hardware_instance: 0,
            capsule_support,
            update_image,
            vendor_code: &[],
        }
    }

    /// `Version`, `UpdateImageTypeId`, `UpdateImageIndex`, three reserved
    /// bytes, `UpdateImageSize`, `UpdateVendorCodeSize`,
    /// `UpdateHardwareInstance` (v2+), `ImageCapsuleSupport` (v3), the
    /// update image and the vendor code.
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.type_id);
        out.extend_from_slice(&[self.index, 0, 0, 0]);
        out.extend_from_slice(&(self.update_image.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.vendor_code.len() as u32).to_le_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&self.hardware_instance.to_le_bytes());
        }
        if self.version >= 3 {
            out.extend_from_slice(&self.capsule_support.to_le_bytes());
        }
        out.extend_from_slice(self.update_image);
        out.extend_from_slice(self.vendor_code);
        out
    }
}

/// An `EFI_FIRMWARE_IMAGE_AUTHENTICATION` (UEFI 2.10 23.1.2):
/// `MonotonicCount`, a `WIN_CERTIFICATE_UEFI_GUID` (`dwLength` = 24 +
/// certificate, revision 0x0200, `WIN_CERT_TYPE_EFI_GUID`, `CertType`) and
/// synthetic certificate bytes, followed by `rest`.
fn authenticated(cert_type: [u8; 16], certificate: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&7u64.to_le_bytes());
    out.extend_from_slice(&((24 + certificate.len()) as u32).to_le_bytes());
    out.extend_from_slice(&WIN_CERT_REVISION.to_le_bytes());
    out.extend_from_slice(&WIN_CERT_TYPE_EFI_GUID.to_le_bytes());
    out.extend_from_slice(&cert_type);
    out.extend_from_slice(certificate);
    out.extend_from_slice(rest);
    out
}

/// An EDK2 `FMP_PAYLOAD_HEADER`: `MSS1`, `HeaderSize` 16, `FwVersion`,
/// `LowestSupportedVersion`, followed by `image`.
fn with_payload_header(fw_version: u32, lowest_supported_version: u32, image: &[u8]) -> Vec<u8> {
    let mut out = b"MSS1".to_vec();
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&fw_version.to_le_bytes());
    out.extend_from_slice(&lowest_supported_version.to_le_bytes());
    out.extend_from_slice(image);
    out
}

/// `PUSH_GUID <type_id(9)>`, `PUSH_VERSION 2`, `GTE`, `END` (24 B), then
/// `rest`.
fn with_dependency(rest: &[u8]) -> Vec<u8> {
    let mut out = vec![EFI_FMP_DEP_PUSH_GUID];
    out.extend_from_slice(&type_id(9));
    out.push(EFI_FMP_DEP_PUSH_VERSION);
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&[EFI_FMP_DEP_GTE, EFI_FMP_DEP_END]);
    out.extend_from_slice(rest);
    out
}

/// The FMP capsule of most tests: flags `PERSIST_ACROSS_RESET` and
/// `INITIATE_RESET`; one AArch64 embedded driver; one version 3 payload
/// with a PKCS7 authentication (64 synthetic certificate bytes), an
/// `FMP_PAYLOAD_HEADER` and the firmware volume, plus 8 B of vendor code.
fn fmp_capsule() -> Vec<u8> {
    let image = authenticated(
        guid_bytes(EFI_CERT_TYPE_PKCS7_GUID),
        &[0x30; 64],
        &with_payload_header(2, 1, &firmware_volume()),
    );
    let item = Item {
        vendor_code: b"VENDOR01",
        hardware_instance: 0x2,
        ..Item::v3(type_id(1), CAPSULE_SUPPORT_AUTHENTICATION, &image)
    };
    let flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET;
    let body = fmp_body(&[pe_image(IMAGE_FILE_MACHINE_ARM64)], &[item.bytes()]);
    efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, flags, &body)
}

/// Offsets of `fmp_capsule`: the body at 0x20; the item offset list (two
/// entries) ends at 0x38; the driver (0x1AC B) ends at 0x1E4; the image
/// header (48 B) ends at 0x214; the authentication (8 + 24 + 64 B) ends at
/// 0x274; the payload header ends at 0x284, where the volume starts.
const FMP_DRIVER_OFFSET: usize = 0x38;
const FMP_ITEM_OFFSET: usize = 0x1E4;
const FMP_AUTH_OFFSET: usize = 0x214;
const FMP_VOLUME_OFFSET: usize = 0x284;

/// A Toshiba capsule (UEFITool A75 `TOSHIBA_CAPSULE_HEADER`):
/// `CapsuleGuid`, `HeaderSize`, `FullSize`, `Flags`, then the body.
fn toshiba_capsule(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; UEFI_HEADER_SIZE];
    out[..16].copy_from_slice(&guid_bytes(TOSHIBA_CAPSULE_GUID));
    put_u32(&mut out, 0x10, UEFI_HEADER_SIZE as u32);
    put_u32(&mut out, 0x14, (UEFI_HEADER_SIZE + body.len()) as u32);
    put_u32(&mut out, 0x18, 0x0000_0001);
    out.extend_from_slice(body);
    out
}

/// An AMI Aptio capsule (UEFITool A75 `APTIO_CAPSULE_HEADER`): an
/// `EFI_CAPSULE_HEADER` whose `HeaderSize` equals `RomImageOffset`, then
/// `RomImageOffset` (0x400) and `RomLayoutOffset` (0x228, u16 each),
/// synthetic header data (0x5A) up to the ROM image, then the ROM.
fn aptio_capsule(guid: [u8; 16], rom: &[u8]) -> Vec<u8> {
    const ROM_IMAGE_OFFSET: usize = 0x400;
    let mut out = efi_capsule(
        guid,
        ROM_IMAGE_OFFSET,
        CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
        rom,
    );
    out[0x1C..0x1E].copy_from_slice(&(ROM_IMAGE_OFFSET as u16).to_le_bytes());
    out[0x1E..0x20].copy_from_slice(&0x228u16.to_le_bytes());
    out[0x20..ROM_IMAGE_OFFSET].fill(0x5A);
    out
}

/// A JSON capsule body (UEFI 2.10 23.5.2): `Version` 1, `CapsuleId`,
/// `PayloadLength`, then the JSON text.
fn json_body(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0x1234u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// A Windows UX capsule (EDK2 `WindowsUxCapsule.h`): the 28-byte header,
/// then `DISPLAY_DISPLAY_PAYLOAD` (`Version` 1, `Checksum`, `ImageType` 0,
/// reserved, `Mode` 1, `OffsetX` 100, `OffsetY` 200) and a synthetic `BM`
/// image. `Checksum` makes the 8-bit sum of the capsule zero.
fn ux_capsule() -> Vec<u8> {
    let mut payload = vec![1, 0, 0, 0];
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&100u32.to_le_bytes());
    payload.extend_from_slice(&200u32.to_le_bytes());
    payload.extend_from_slice(b"BM synthetic bitmap");
    let mut capsule = efi_capsule(guid_bytes(WINDOWS_UX_CAPSULE_GUID), 28, 0, &payload);
    let sum = capsule.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
    capsule[28 + 1] = 0u8.wrapping_sub(sum);
    capsule
}

/// A nested FMP capsule (EDK2 `IsNestedFmpCapsule`): a capsule with the
/// platform's ESRT GUID `type_id(7)` and `PERSIST_ACROSS_RESET`, whose body
/// is `fmp_capsule`.
fn nested_capsule() -> Vec<u8> {
    efi_capsule(
        type_id(7),
        UEFI_HEADER_SIZE,
        CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
        &fmp_capsule(),
    )
}

/// Every positive fixture with its layout.
fn fixtures() -> Vec<(&'static str, Vec<u8>, Layout)> {
    let volume = firmware_volume();
    vec![
        (
            "efi",
            efi_capsule(guid_bytes(EFI_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &volume),
            Layout::Efi,
        ),
        ("fmp", fmp_capsule(), Layout::Fmp),
        ("nested", nested_capsule(), Layout::NestedFmp),
        (
            "json",
            efi_capsule(
                guid_bytes(JSON_CAPSULE_GUID),
                UEFI_HEADER_SIZE,
                0,
                &json_body(br#"{"setting": 1}"#),
            ),
            Layout::Json,
        ),
        ("ux", ux_capsule(), Layout::WindowsUx),
        (
            "intel",
            efi_capsule(guid_bytes(INTEL_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &volume),
            Layout::Intel,
        ),
        (
            "lenovo",
            efi_capsule(
                guid_bytes(LENOVO2_CAPSULE_GUID),
                UEFI_HEADER_SIZE,
                0,
                &volume,
            ),
            Layout::Lenovo,
        ),
        ("toshiba", toshiba_capsule(&volume), Layout::Toshiba),
        (
            "aptio-signed",
            aptio_capsule(guid_bytes(APTIO_SIGNED_CAPSULE_GUID), &volume),
            Layout::AptioSigned,
        ),
        (
            "aptio-unsigned",
            aptio_capsule(guid_bytes(APTIO_UNSIGNED_CAPSULE_GUID), &volume),
            Layout::AptioUnsigned,
        ),
    ]
}

#[test]
fn every_fixture_is_detected_as_its_layout() {
    for (name, data, layout) in fixtures() {
        let detected = capsule::detect(&data).or_else(|| capsule::detect_weak(&data));
        assert_eq!(detected, Some(layout), "{name}");
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::UefiCapsule, "{name}");
        assert_eq!(
            p.format.variant_name.as_deref(),
            Some(layout.label()),
            "{name}"
        );
        assert!(capsule::parse_container(&data, layout).is_ok(), "{name}");
    }
    assert!(Layout::NestedFmp.is_weak());
    assert!(!Layout::Fmp.is_weak());
}

#[test]
fn efi_capsule_body_is_a_firmware_volume_classified_on_its_own() {
    let volume = firmware_volume();
    let flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET;
    let data = efi_capsule(
        guid_bytes(EFI_CAPSULE_GUID),
        UEFI_HEADER_SIZE,
        flags,
        &volume,
    );
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let body = slice(&p, "Capsule body");
    assert_eq!((body.offset, body.size), (0x20, volume.len() as u64));
    assert_eq!(body.isa, Isa::X86_64);
    assert_note(
        &p,
        "Capsule GUID 3B6686BD-0D76-4030-B70E-B5519E2FC5A0 (EFI_CAPSULE_GUID)",
    );
    assert_note(&p, "Flags 0x00050000: PERSIST_ACROSS_RESET, INITIATE_RESET");
    assert_note(&p, "Capsule body: 4 KiB at 0x20");
    assert_note(&p, "Capsule body: x86_64 (contained UEFI firmware volume)");
    assert_eq!(metadata(&p, "capsule_flags"), "0x00050000");
    assert_eq!(metadata(&p, "capsule_header_size"), "32");
    assert_eq!(metadata(&p, "capsule_image_size"), data.len().to_string());
}

#[test]
fn fmp_payloads_precede_embedded_drivers_and_keep_stored_offsets() {
    let data = fmp_capsule();
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::UefiCapsule);
    // The payload's firmware volume, not the AArch64 driver, names the ISA.
    assert_eq!(p.primary.isa, Isa::X86_64);
    let payload_label = "Payload 1 (5A1E7E57-0000-4000-8000-0000000000C1)";
    let auth_label = "Payload 1 authentication (PKCS7 signature, not verified)";
    assert_eq!(
        labels(&p),
        [
            payload_label,
            auth_label,
            "Payload 1 vendor code",
            "Embedded driver 1"
        ]
    );
    let payload = slice(&p, payload_label);
    assert_eq!(
        (payload.offset, payload.size),
        (FMP_VOLUME_OFFSET as u64, 4096)
    );
    assert_eq!(payload.isa, Isa::X86_64);
    let auth = slice(&p, auth_label);
    assert_eq!((auth.offset, auth.size), (FMP_AUTH_OFFSET as u64, 96));
    assert_eq!(auth.isa, Isa::Unknown(0));
    let vendor = slice(&p, "Payload 1 vendor code");
    assert_eq!(
        (vendor.offset, vendor.size),
        ((FMP_VOLUME_OFFSET + 4096) as u64, 8)
    );
    assert_eq!(vendor.isa, Isa::Unknown(0));
    let driver = slice(&p, "Embedded driver 1");
    assert_eq!(
        (driver.offset, driver.size),
        (FMP_DRIVER_OFFSET as u64, 0x1AC)
    );
    assert_eq!(driver.isa, Isa::AArch64);
    assert_note(
        &p,
        "EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER version 1 at 0x20: 1 embedded driver, 1 payload item",
    );
    assert_note(
        &p,
        &format!(
            "Payload item 1 at 0x{FMP_ITEM_OFFSET:X}: image header version 3, UpdateImageTypeId 5A1E7E57-0000-4000-8000-0000000000C1, UpdateImageIndex 1, UpdateHardwareInstance 0x2, ImageCapsuleSupport 0x1 (authentication)"
        ),
    );
    assert_note(
        &p,
        "EFI_FIRMWARE_IMAGE_AUTHENTICATION 96 B (PKCS7 signature, MonotonicCount 0x7; not verified)",
    );
    assert_note(
        &p,
        "FMP_PAYLOAD_HEADER (FwVersion 0x00000002, LowestSupportedVersion 0x00000001); firmware image 4 KiB at 0x284; vendor code 8 B",
    );
    assert_note(&p, "Primary ISA selected from Payload 1");
    assert_eq!(
        metadata(&p, "capsule_payload_1_type_id"),
        "5A1E7E57-0000-4000-8000-0000000000C1"
    );
    assert_eq!(metadata(&p, "capsule_payload_1_fw_version"), "0x00000002");
    assert_eq!(metadata(&p, "capsule_embedded_driver_count"), "1");
    assert_eq!(metadata(&p, "capsule_payload_count"), "1");
}

#[test]
fn an_fmp_capsule_with_only_a_driver_takes_the_driver_isa() {
    let body = fmp_body(&[pe_image(IMAGE_FILE_MACHINE_ARM64)], &[]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_note(&p, "Primary ISA selected from Embedded driver 1");
    // A driver that is the last item runs to the end of the capsule.
    assert_eq!(slice(&p, "Embedded driver 1").size, 0x1AC);
}

#[test]
fn image_header_versions_one_and_two_are_shorter_and_have_no_capsule_support() {
    let volume = firmware_volume();
    for (version, header_size) in [(1u32, 32usize), (2, 40)] {
        let item = Item {
            version,
            ..Item::v3(type_id(2), 0, &volume)
        };
        let body = fmp_body(&[], &[item.bytes()]);
        let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
        let p = classify(&data);
        let label = "Payload 1 (5A1E7E57-0000-4000-8000-0000000000C2)";
        assert_eq!(slice(&p, label).offset, (0x20 + 16 + header_size) as u64);
        assert_eq!(slice(&p, label).isa, Isa::X86_64);
        assert!(!has_note(&p, "ImageCapsuleSupport"), "version {version}");
        assert_eq!(
            has_note(&p, "UpdateHardwareInstance"),
            version == 2,
            "version {version}"
        );
    }
}

#[test]
fn dependency_expressions_and_rsa_signatures_are_skipped_before_the_image() {
    let volume = firmware_volume();
    // Version 3 with both bits: authentication, dependency, payload header.
    let image = authenticated(
        guid_bytes(EFI_CERT_TYPE_PKCS7_GUID),
        &[0x30; 16],
        &with_dependency(&with_payload_header(5, 4, &volume)),
    );
    let support = CAPSULE_SUPPORT_AUTHENTICATION | CAPSULE_SUPPORT_DEPENDENCY;
    let body = fmp_body(&[], &[Item::v3(type_id(3), support, &image).bytes()]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
    let p = classify(&data);
    assert_note(&p, "ImageCapsuleSupport 0x3 (authentication, dependency)");
    assert_note(&p, "EFI_FIRMWARE_IMAGE_DEP 24 B (not evaluated)");
    // 0x20 body + 16 header and list + 48 image header + 48 auth + 24 + 16.
    let label = "Payload 1 (5A1E7E57-0000-4000-8000-0000000000C3)";
    assert_eq!(slice(&p, label).offset, 0x20 + 16 + 48 + 48 + 24 + 16);
    assert_eq!(slice(&p, label).isa, Isa::X86_64);

    // A version 2 header has no ImageCapsuleSupport: the RSA2048/SHA-256
    // certificate is recognized by its CertType, as GenerateCapsule does.
    let image = authenticated(
        guid_bytes(EFI_CERT_TYPE_RSA2048_SHA256_GUID),
        &[0x11; 16 + 256 + 256],
        &volume,
    );
    let item = Item {
        version: 2,
        ..Item::v3(type_id(4), 0, &image)
    };
    let body = fmp_body(&[], &[item.bytes()]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
    let p = classify(&data);
    let auth = slice(
        &p,
        "Payload 1 authentication (RSA2048/SHA-256 signature, not verified)",
    );
    assert_eq!(auth.size, 8 + 24 + 528);
    assert_eq!(
        slice(&p, "Payload 1 (5A1E7E57-0000-4000-8000-0000000000C4)").isa,
        Isa::X86_64
    );
}

#[test]
fn nested_fmp_capsules_are_weak_and_classify_the_inner_capsule() {
    let data = nested_capsule();
    assert_eq!(capsule::detect(&data), None);
    assert_eq!(capsule::detect_weak(&data), Some(Layout::NestedFmp));
    let p = classify(&data);
    assert_eq!(p.format.variant_name.as_deref(), Some("Nested FMP capsule"));
    assert!(p.format.confidence < 1.0);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let inner = slice(&p, "FMP capsule");
    assert_eq!(
        (inner.offset, inner.size),
        (0x20, fmp_capsule().len() as u64)
    );
    assert_note(&p, "platform-defined GUID");
    assert_note(&p, "ESRT firmware class");
    // A trailing byte breaks the exact size the weak layout requires.
    let mut longer = data.clone();
    longer.push(0);
    assert_eq!(capsule::detect_weak(&longer), None);
    // So does an inner capsule that does not parse.
    let mut broken = data.clone();
    put_u32(&mut broken, 0x20 + 0x20, 2);
    assert_eq!(capsule::detect_weak(&broken), None);
    let message = capsule::parse_container(&broken, Layout::NestedFmp)
        .unwrap_err()
        .to_string();
    assert!(
        message.contains("Invalid nested FMP capsule at 0x20, offsets relative to it: Unsupported EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER version 2 at 0x20"),
        "{message}"
    );
}

#[test]
fn json_and_windows_ux_payloads_are_opaque() {
    let payload = br#"{"setting": 1}"#;
    let data = efi_capsule(
        guid_bytes(JSON_CAPSULE_GUID),
        UEFI_HEADER_SIZE,
        0,
        &json_body(payload),
    );
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    let json = slice(&p, "JSON payload");
    assert_eq!((json.offset, json.size), (0x20 + 12, payload.len() as u64));
    assert_eq!(json.isa, Isa::Unknown(0));
    assert_note(
        &p,
        "EFI_JSON_CAPSULE_HEADER version 1, CapsuleId 0x00001234",
    );
    assert_eq!(metadata(&p, "capsule_json_capsule_id"), "0x00001234");
    let empty = efi_capsule(
        guid_bytes(JSON_CAPSULE_GUID),
        UEFI_HEADER_SIZE,
        0,
        &json_body(b""),
    );
    assert_note(&classify(&empty), "PayloadLength is 0");

    let data = ux_capsule();
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    let image = slice(&p, "Display image (BMP)");
    assert_eq!((image.offset, image.size), (28 + 16, 19));
    assert_note(
        &p,
        "checksum verified; ImageType 0, Mode 1, OffsetX 100, OffsetY 200",
    );
    let mut corrupt = data.clone();
    corrupt[28 + 16] ^= 0x01;
    assert!(error_text(&corrupt).contains("Invalid Windows UX capsule checksum"));
}

#[test]
fn vendor_headers_locate_their_bodies_as_uefitool_does() {
    let volume = firmware_volume();
    let data = toshiba_capsule(&volume);
    let p = classify(&data);
    assert_eq!(slice(&p, "Capsule body").offset, 0x20);
    assert_eq!(slice(&p, "Capsule body").isa, Isa::X86_64);
    assert_note(
        &p,
        "FullSize 4128 B, Flags 0x00000001 (meaning not documented)",
    );

    for (parts, signed) in [
        (APTIO_SIGNED_CAPSULE_GUID, true),
        (APTIO_UNSIGNED_CAPSULE_GUID, false),
    ] {
        let data = aptio_capsule(guid_bytes(parts), &volume);
        let p = classify(&data);
        let rom = slice(&p, "ROM image");
        assert_eq!((rom.offset, rom.size), (0x400, volume.len() as u64));
        assert_eq!(rom.isa, Isa::X86_64);
        assert_eq!(has_note(&p, "signature not verified"), signed);
        assert_note(&p, "RomImageOffset 0x400, RomLayoutOffset 0x228");
        assert_eq!(metadata(&p, "capsule_rom_layout_offset"), "0x228");
    }

    for parts in [INTEL_CAPSULE_GUID, LENOVO2_CAPSULE_GUID] {
        let data = efi_capsule(guid_bytes(parts), UEFI_HEADER_SIZE, 0, &volume);
        let p = classify(&data);
        assert_eq!(slice(&p, "Capsule body").isa, Isa::X86_64);
        assert_note(&p, "header as UEFITool A75 reads it");
    }
}

#[test]
fn flag_rules_and_trailing_bytes() {
    let volume = firmware_volume();
    let flags = CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE | 0x0000_0003;
    let body = fmp_body(&[], &[Item::v3(type_id(5), 0, &volume).bytes()]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, flags, &body);
    let p = classify(&data);
    assert_note(
        &p,
        "Flags 0x00020003: POPULATE_SYSTEM_TABLE, GUID-defined bits 0x0003",
    );
    assert_note(
        &p,
        "POPULATE_SYSTEM_TABLE is set without PERSIST_ACROSS_RESET",
    );
    assert_note(&p, "does not allow for FMP capsule contents");

    let mut padded = efi_capsule(guid_bytes(EFI_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &volume);
    padded.extend_from_slice(&[0xFF; 0x200]);
    assert_note(
        &classify(&padded),
        "512 B of padding after the capsule at 0x1020",
    );
    let mut trailing = padded.clone();
    trailing.push(0x42);
    assert_eq!(
        error_text(&trailing),
        "UEFI capsule parse error: Unexpected 513 B after the capsule at 0x1020"
    );
}

/// A change to `fmp_capsule` and the error it must produce.
struct Corruption {
    apply: fn(&mut [u8]),
    expected: &'static str,
}

/// File offset of the FMP capsule body in `fmp_capsule`.
const FMP_BODY_OFFSET: usize = 0x20;

#[test]
fn corrupted_fmp_fields_are_format_errors_in_check_order() {
    let base = fmp_capsule();
    let cases = [
        Corruption {
            apply: |d| {
                let longer = d.len() as u32 + 1;
                put_u32(d, 0x18, longer);
            },
            expected: "Truncated capsule: CapsuleImageSize 4749 B, file 4748 B",
        },
        Corruption {
            apply: |d| put_u32(d, FMP_BODY_OFFSET, 2),
            expected: "Unsupported EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER version 2 at 0x20 (1 expected)",
        },
        Corruption {
            apply: |d| d[FMP_BODY_OFFSET + 6..FMP_BODY_OFFSET + 8].fill(0xFF),
            expected: "Invalid ItemOffsetList at 0x28: 65536 entries do not fit the 4716 B capsule body",
        },
        Corruption {
            apply: |d| put_u64(d, FMP_BODY_OFFSET + 8, 0x10_0000),
            expected: "Invalid ItemOffsetList[0] 0x100000: beyond the 4716 B capsule body",
        },
        Corruption {
            apply: |d| put_u64(d, FMP_BODY_OFFSET + 8, 0x10),
            expected: "Invalid ItemOffsetList[0] 0x10: inside the 24 B FMP capsule header",
        },
        Corruption {
            apply: |d| put_u64(d, FMP_BODY_OFFSET + 16, 0x18),
            expected: "Invalid ItemOffsetList[1] 0x18: not above the previous entry 0x18",
        },
        Corruption {
            apply: |d| put_u32(d, FMP_ITEM_OFFSET, 4),
            expected: "Unsupported EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER version 4 at 0x1E4 (1 to 3 expected)",
        },
        Corruption {
            apply: |d| put_u32(d, FMP_ITEM_OFFSET + 0x1C, 9),
            expected: "Invalid payload item 1 at 0x1E4: 4264 B, but the image header, UpdateImageSize and UpdateVendorCodeSize give 4265 B",
        },
        Corruption {
            apply: |d| d[FMP_AUTH_OFFSET + 12] = 0x01,
            expected: "Invalid WIN_CERTIFICATE wRevision 0x0201 at 0x220 (0x0200 expected)",
        },
        Corruption {
            apply: |d| d[FMP_AUTH_OFFSET + 16] ^= 0xFF,
            expected: "Unsupported CertType",
        },
        Corruption {
            apply: |d| put_u32(d, FMP_AUTH_OFFSET + 8, 0x10_0000),
            expected: "Truncated EFI_FIRMWARE_IMAGE_AUTHENTICATION at 0x214",
        },
        Corruption {
            apply: |d| put_u32(d, FMP_VOLUME_OFFSET - 12, 8),
            expected: "Invalid FMP_PAYLOAD_HEADER HeaderSize 8 B at 0x278: smaller than 16 B",
        },
    ];
    for case in cases {
        let mut data = base.clone();
        (case.apply)(&mut data);
        let message = error_text(&data);
        let expected = case.expected;
        assert!(message.contains(expected), "{expected:?} in {message:?}");
        assert!(
            message.starts_with("UEFI capsule parse error: "),
            "{message}"
        );
    }
    // A dependency bit without a valid expression.
    let volume = firmware_volume();
    let item = Item::v3(type_id(6), CAPSULE_SUPPORT_DEPENDENCY, &volume);
    let body = fmp_body(&[], &[item.bytes()]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
    assert!(error_text(&data).contains("Invalid dependency opcode 0x"));
    // An FMP capsule that ends at its capsule header.
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &[]);
    assert!(error_text(&data).contains("Missing EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER at 0x20"));
    // No items: the body must end after the 8-byte header.
    let data = efi_capsule(
        guid_bytes(FMP_CAPSULE_GUID),
        UEFI_HEADER_SIZE,
        0,
        &fmp_body(&[], &[]),
    );
    assert_note(&classify(&data), "lists no drivers or payload items");
    let mut extra = fmp_body(&[], &[]);
    extra.push(0);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &extra);
    assert!(error_text(&data)
        .contains("Unexpected 1 B after an EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER"));
}

#[test]
fn inconsistent_header_sizes_are_not_capsules() {
    let volume = firmware_volume();
    let good = efi_capsule(guid_bytes(EFI_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &volume);
    // HeaderSize smaller than EFI_CAPSULE_HEADER, beyond CapsuleImageSize,
    // or beyond the file: the GUID alone does not make a capsule.
    for header_size in [0u32, 27, 0x2000, 0x0FF0_A55A] {
        let mut data = good.clone();
        put_u32(&mut data, 0x10, header_size);
        assert_eq!(capsule::detect(&data), None, "HeaderSize {header_size}");
        assert!(capsule::parse_container(&data, Layout::Efi).is_err());
    }
    let mut data = aptio_capsule(guid_bytes(APTIO_SIGNED_CAPSULE_GUID), &volume);
    data[0x1C..0x1E].copy_from_slice(&0x10u16.to_le_bytes());
    assert_eq!(capsule::detect(&data), None);
    assert!(capsule::detect(&good[..27]).is_none());
}

#[test]
fn every_truncation_is_an_error_or_not_a_capsule() {
    for (name, data, layout) in fixtures() {
        for end in 0..data.len() {
            let prefix = &data[..end];
            assert!(
                capsule::parse_container(prefix, layout).is_err(),
                "{name}: prefix {end} parses"
            );
            if end % 3 == 0 || end < 0x400 {
                if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                    assert_ne!(
                        p.format.format,
                        FileFormat::UefiCapsule,
                        "{name}: prefix {end}"
                    );
                }
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xFF, |b| b ^ 0x01];
    for (_, data, layout) in fixtures() {
        for i in 0..data.len() {
            for mutate in mutations {
                let mut mutated = data.clone();
                mutated[i] = mutate(mutated[i]);
                let _ = capsule::parse_container(&mutated, layout);
                let _ = capsule::detect(&mutated);
                let _ = capsule::detect_weak(&mutated);
            }
            // Full classification (children included) on every header byte,
            // then every 7th byte.
            if i < 0x300 || i % 7 == 0 {
                let mut mutated = data.clone();
                mutated[i] ^= 0xFF;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

#[test]
fn item_counts_are_bounded_by_the_body() {
    // 65535 drivers and 65535 payloads declared in an 8-byte header.
    let mut body = fmp_body(&[], &[]);
    body[4..8].copy_from_slice(&[0xFF; 4]);
    let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
    assert!(error_text(&data).contains("131070 entries do not fit the 8 B capsule body"));
    // Many tiny drivers: every one is listed and classified on its own.
    let drivers: Vec<Vec<u8>> = (0..300).map(|i| vec![i as u8; 3]).collect();
    let data = efi_capsule(
        guid_bytes(FMP_CAPSULE_GUID),
        UEFI_HEADER_SIZE,
        0,
        &fmp_body(&drivers, &[]),
    );
    let p = classify(&data);
    assert_eq!(p.slices.len(), 300);
}

#[test]
fn json_id_is_stable() {
    assert_eq!(
        serde_json::to_string(&FileFormat::UefiCapsule).expect("serializes"),
        "\"ueficapsule\""
    );
    assert_eq!(FileFormat::UefiCapsule.to_string(), "UEFI capsule");
}

/// Files of `dir` (recursively) of at most 64 MiB.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            files(&path, out);
        } else if meta.len() <= 64 << 20 {
            out.push(path);
        }
    }
}

/// IDA's test inputs (`IDA_INPUT_DIR`, read in place, never copied): no
/// input is a capsule, and real firmware volumes and EFI images wrapped in
/// synthetic capsules keep the ISA they have on their own, with the
/// payload, not the embedded driver, naming the capsule's ISA.
#[test]
fn ida_inputs_are_not_capsules_and_keep_their_isa_when_wrapped() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let mut all = Vec::new();
    files(&dir, &mut all);
    for path in &all {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        assert_eq!(capsule::detect(&data), None, "{}", path.display());
        assert_eq!(capsule::detect_weak(&data), None, "{}", path.display());
    }
    eprintln!("{} IDA inputs checked: none is a capsule", all.len());

    let volumes = [
        "pc_uefi_fv_diskio_64.fv",
        "pc_uefi_fv_mixed_64.fv",
        "arm64_uefi_fv_diskio.fv",
    ];
    let drivers = [
        "pc_test_efi_pe.pe",
        "pc_test_efi_pe_64.pe",
        "arm_efi_dxecore.pe",
        "pc_test_efi_te.te",
        "arm_efi_memoryinit_64.te",
    ];
    let mut wrapped = 0;
    for volume_name in volumes {
        let Ok(volume) = std::fs::read(dir.join(volume_name)) else {
            continue;
        };
        let own = classify(&volume).primary.isa;
        let data = efi_capsule(guid_bytes(EFI_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &volume);
        let p = classify(&data);
        assert_eq!(slice(&p, "Capsule body").isa, own, "{volume_name}");
        for driver_name in drivers {
            let Ok(driver) = std::fs::read(dir.join(driver_name)) else {
                continue;
            };
            let driver_isa = classify(&driver).primary.isa;
            let image = with_payload_header(1, 1, &volume);
            let body = fmp_body(&[driver], &[Item::v3(type_id(8), 0, &image).bytes()]);
            let data = efi_capsule(guid_bytes(FMP_CAPSULE_GUID), UEFI_HEADER_SIZE, 0, &body);
            let p = classify(&data);
            let payload = slice(&p, "Payload 1 (5A1E7E57-0000-4000-8000-0000000000C8)");
            assert_eq!(payload.isa, own, "{volume_name} with {driver_name}");
            assert_eq!(
                slice(&p, "Embedded driver 1").isa,
                driver_isa,
                "{driver_name}"
            );
            assert_eq!(p.primary.isa, own, "{volume_name} with {driver_name}");
            wrapped += 1;
        }
    }
    eprintln!("{wrapped} IDA volume and driver pairs wrapped in FMP capsules");
}

/// Real capsules in `UEFI_CAPSULE_DIR` (read in place): every file that
/// starts with a documented capsule GUID classifies as a capsule with at
/// least one component, unless it is a header without a body (AMI firmware
/// stores such a copy of its capsule header in a freeform file); a file cut
/// short of its `CapsuleImageSize` must be a truncation error.
#[test]
fn capsules_in_uefi_capsule_dir_classify() {
    let Some(dir) = std::env::var_os("UEFI_CAPSULE_DIR").map(PathBuf::from) else {
        eprintln!("skipped: UEFI_CAPSULE_DIR is not set");
        return;
    };
    let mut all = Vec::new();
    files(&dir, &mut all);
    let mut checked = 0;
    for path in &all {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if capsule::detect(&data).is_none() && capsule::detect_weak(&data).is_none() {
            continue;
        }
        let p = match detect_payload(&data, &ClassifierOptions::new()) {
            Ok(p) => p,
            Err(e) if e.to_string().contains("Truncated capsule") => {
                eprintln!("{}: {e}", path.display());
                continue;
            }
            Err(e) => panic!("{}: {e}", path.display()),
        };
        assert_eq!(
            p.format.format,
            FileFormat::UefiCapsule,
            "{}",
            path.display()
        );
        let header_only = p.notes.iter().any(|n| n.message == "Capsule has no body");
        assert!(!p.slices.is_empty() || header_only, "{}", path.display());
        eprintln!(
            "{}: {:?}, components: {}, primary {:?}",
            path.display(),
            p.format.variant_name,
            p.slices.len(),
            p.primary.isa
        );
        checked += 1;
    }
    eprintln!("{checked} capsules checked");
}
