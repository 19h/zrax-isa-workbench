//! Standalone X.509 certificate files: DER and PEM detection strength,
//! opaque classification, certificate members and rejected trailing data.

use zrax::formats::{container::Kind, detect_format, x509, DetectedFormat};
use zrax::inspection::{extract_subfile, subfiles};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const ROOT: &[u8] = include_bytes!("fixtures/certificates/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/certificates/intermediate.der");
const LEAF: &[u8] = include_bytes!("fixtures/certificates/leaf.der");
const CHAIN_PEM: &[u8] = include_bytes!("fixtures/certificates/chain.pem");
const CHAIN_CRLF_PEM: &[u8] = include_bytes!("fixtures/certificates/chain-crlf.pem");
const NOT_A_CERTIFICATE_PEM: &[u8] = include_bytes!("fixtures/certificates/not-a-certificate.pem");
const TI_SIGNED: &[u8] = include_bytes!("fixtures/ti/vendor.signed");

fn payload(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn layout(data: &[u8]) -> Option<x509::Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::X509(layout),
        } => Some(layout),
        _ => None,
    }
}

fn custom(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| match &m.value {
            zrax::MetadataValue::String(s) => s.clone(),
            other => format!("{other:?}"),
        })
}

fn notes(p: &DetectionPayload) -> Vec<&str> {
    p.notes.iter().map(|n| n.message.as_str()).collect()
}

#[test]
fn a_der_certificate_file_is_an_opaque_x509_container() {
    assert_eq!(layout(LEAF), Some(x509::Layout::Der));
    let p = payload(LEAF);
    assert_eq!(p.format.format, FileFormat::X509);
    assert_eq!(p.format.variant_name.as_deref(), Some("X.509 certificate (DER)"));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(notes(&p).contains(&"X.509 certificate; signature not verified"));
    assert_eq!(
        custom(&p, "x509_not_after").as_deref(),
        Some("2050-01-01T00:00:00Z")
    );
    assert!(custom(&p, "x509_subject")
        .unwrap()
        .contains("CN=Zrax Fixture Code Signing"));
    assert_eq!(custom(&p, "x509_public_key").as_deref(), Some("Ed25519 255-bit"));
    let json = serde_json::to_value(&p).unwrap();
    assert_eq!(json["format"]["format"], "x509");
}

#[test]
fn erased_flash_padding_is_accepted_and_other_trailing_bytes_are_not() {
    let mut padded = ROOT.to_vec();
    padded.extend_from_slice(&[0xff; 64]);
    assert_eq!(layout(&padded), Some(x509::Layout::Der));
    let mut trailing = ROOT.to_vec();
    trailing.extend_from_slice(b"trailer");
    assert_eq!(layout(&trailing), None);
}

#[test]
fn truncated_der_files_are_not_certificate_files() {
    for end in 0..LEAF.len() {
        assert_eq!(layout(&LEAF[..end]), None, "end {end}");
    }
}

#[test]
fn a_pem_bundle_lists_each_certificate_as_an_opaque_member() {
    for bundle in [CHAIN_PEM, CHAIN_CRLF_PEM] {
        assert_eq!(layout(bundle), Some(x509::Layout::Pem));
        let p = payload(bundle);
        assert_eq!(p.format.variant_name.as_deref(), Some("X.509 certificates (PEM)"));
        assert!(notes(&p).contains(&"3 PEM certificates; signatures and chains not verified"));
        assert!(custom(&p, "x509_certificate_0")
            .unwrap()
            .starts_with("Zrax Fixture Code Signing; issued by Zrax Fixture Intermediate CA"));
        let members = subfiles(bundle).unwrap();
        assert_eq!(members.len(), 3);
        assert!(members.iter().all(|m| m.opaque && m.transform == Some("base64")));
        assert_eq!(members[0].label, "certificate 0 (Zrax Fixture Code Signing)");
        for (member, der) in members.iter().zip([LEAF, INTERMEDIATE, ROOT]) {
            assert_eq!(extract_subfile(bundle, member.index).unwrap(), der);
        }
    }
}

#[test]
fn byte_order_mark_and_leading_whitespace_are_allowed() {
    let mut text = b"\xef\xbb\xbf\n  ".to_vec();
    text.extend_from_slice(CHAIN_PEM);
    assert_eq!(layout(&text), Some(x509::Layout::Pem));
    assert!(detect_payload(&text, &ClassifierOptions::new()).is_ok());
}

#[test]
fn a_damaged_pem_file_is_a_format_error() {
    let error = detect_payload(NOT_A_CERTIFICATE_PEM, &ClassifierOptions::new())
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("X.509 parse error: Invalid certificate in PEM block at 0x0"),
        "{error}"
    );
    let mut trailing = CHAIN_PEM.to_vec();
    trailing.extend_from_slice(b"comment\n");
    let error = detect_payload(&trailing, &ClassifierOptions::new())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        format!(
            "X.509 parse error: Unexpected text at 0x{:X} outside certificate blocks",
            CHAIN_PEM.len()
        )
    );
    let error = detect_payload(b"-----BEGIN CERTIFICATE-----\n", &ClassifierOptions::new())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "X.509 parse error: Missing complete PEM certificate block at 0x0"
    );
}

#[test]
fn truncated_pem_files_fail_or_end_on_a_block_boundary() {
    for end in 0..CHAIN_PEM.len() {
        let text = &CHAIN_PEM[..end];
        if end < 27 {
            assert_eq!(layout(text), None, "end {end}");
            continue;
        }
        assert_eq!(layout(text), Some(x509::Layout::Pem), "end {end}");
        if let Ok(p) = detect_payload(text, &ClassifierOptions::new()) {
            assert_eq!(p.format.format, FileFormat::X509);
            assert!(text.trim_ascii_end().ends_with(b"-----END CERTIFICATE-----"));
        }
    }
}

#[test]
fn mutations_do_not_panic() {
    for original in [LEAF, CHAIN_PEM] {
        for at in 0..original.len() {
            for value in [0x00, 0xff, original[at] ^ 0x01] {
                let mut data = original.to_vec();
                data[at] = value;
                let _ = detect_payload(&data, &ClassifierOptions::new());
            }
        }
    }
}

#[test]
fn ti_x509_boot_images_remain_ti() {
    assert!(matches!(detect_format(TI_SIGNED), DetectedFormat::Ti { .. }));
}
