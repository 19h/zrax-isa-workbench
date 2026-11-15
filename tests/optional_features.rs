//! The `certificates` and `image4-aes` features: with them a certificate
//! file is the X.509 format and AES decrypts; without them a certificate
//! file is raw input that the code model refuses, and nothing is decrypted.

use zrax::image4::{self, Mode};
use zrax::report::Outcome;
use zrax::{detect_report, ClassifierOptions};

/// Every certificate fixture (`tests/fixtures/certificates/README.md`).
const CERTIFICATE_FILES: [(&str, &[u8]); 6] = [
    ("root.der", include_bytes!("fixtures/certificates/root.der")),
    (
        "intermediate.der",
        include_bytes!("fixtures/certificates/intermediate.der"),
    ),
    ("leaf.der", include_bytes!("fixtures/certificates/leaf.der")),
    (
        "expired.der",
        include_bytes!("fixtures/certificates/expired.der"),
    ),
    (
        "chain.pem",
        include_bytes!("fixtures/certificates/chain.pem"),
    ),
    (
        "chain-crlf.pem",
        include_bytes!("fixtures/certificates/chain-crlf.pem"),
    ),
];

/// AES-128 key and IV of FIPS 197 Appendix B and SP 800-38A F.2.1.
const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
/// SP 800-38A F.2.2 (CBC-AES128.Decrypt), block 1: ciphertext and plaintext.
const CBC_CIPHERTEXT: [u8; 16] = [
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
];
#[cfg(feature = "image4-aes")]
const CBC_PLAINTEXT: [u8; 16] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
];

#[cfg(feature = "certificates")]
#[test]
fn with_certificates_a_certificate_file_is_the_x509_format() {
    for (name, data) in CERTIFICATE_FILES {
        let report = detect_report(data, &ClassifierOptions::new());
        let Outcome::Decided(payload) = &report.outcome else {
            panic!("{name}: not classified");
        };
        assert_eq!(payload.format.format, zrax::FileFormat::X509, "{name}");
        assert!(
            matches!(payload.primary.isa, zrax::Isa::Unknown(_)),
            "{name}"
        );
    }
}

#[cfg(not(feature = "certificates"))]
#[test]
fn without_certificates_a_certificate_file_is_refused_not_read_as_code() {
    for (name, data) in CERTIFICATE_FILES {
        let report = detect_report(data, &ClassifierOptions::new());
        assert!(
            matches!(report.outcome, Outcome::Abstained(_)),
            "{name}: read as code"
        );
        assert_eq!(report.layout, None, "{name}");
    }
}

#[cfg(feature = "image4-aes")]
#[test]
fn with_image4_aes_cbc_decrypts_the_sp_800_38a_vector() {
    let plaintext = image4::decrypt(&CBC_CIPHERTEXT, &KEY, &IV, Mode::Cbc).expect("decrypts");
    assert_eq!(plaintext, CBC_PLAINTEXT);
}

#[cfg(not(feature = "image4-aes"))]
#[test]
fn without_image4_aes_nothing_is_decrypted() {
    for mode in [Mode::Cbc, Mode::Ctr] {
        assert!(image4::decrypt(&CBC_CIPHERTEXT, &KEY, &IV, mode).is_err());
        assert!(image4::trial(&CBC_CIPHERTEXT, &KEY, &IV, mode).is_err());
    }
    assert!(image4::automatic(&CBC_CIPHERTEXT, &KEY, &IV).is_err());
}

/// Argument errors do not depend on the feature.
#[test]
fn key_and_iv_sizes_are_checked_in_every_build() {
    assert!(image4::decrypt(&CBC_CIPHERTEXT, &KEY[..15], &IV, Mode::Cbc).is_err());
    assert!(image4::decrypt(&CBC_CIPHERTEXT, &KEY, &IV[..8], Mode::Cbc).is_err());
    assert!(image4::decrypt(&[], &KEY, &IV, Mode::Cbc).is_err());
}
