//! Digests and signatures in the signature and main headers (rpm
//! `docs/manual/signatures_digests.md`, `lib/rpmvs.cc`, `build/pack.cc`;
//! LSB 5.0 section 25.2.3).
//!
//! The header digests cover the main header as stored
//! (`hdrblobDigestUpdate`: magic, counts, index and store of the region,
//! which in a package spans the whole header). The MD5 digest covers the
//! main header and the payload. The payload digests in the main header
//! cover the stored payload, and their `ALT` forms the uncompressed one.
//! SHA-1, SHA-256, SHA-512 and MD5 digests are verified and a mismatch is
//! an error. SHA3-256 digests are reported as present and not verified (the
//! crate has no SHA-3 implementation). `OpenPGP`, IMA and fs-verity
//! signatures are reported as present and never verified.

use super::*;
use sha2::{Digest, Sha256, Sha512};

/// Signature header digest and signature tags (`rpmSigTag`, `rpmtag.h`).
const RPMSIGTAG_DSA: u32 = 267;
const RPMSIGTAG_RSA: u32 = 268;
const RPMSIGTAG_SHA1: u32 = 269;
const RPMSIGTAG_SHA256: u32 = 272;
const RPMSIGTAG_FILESIGNATURES: u32 = 274;
const RPMSIGTAG_VERITYSIGNATURES: u32 = 276;
const RPMSIGTAG_OPENPGP: u32 = 278;
const RPMSIGTAG_SHA3_256: u32 = 279;
const RPMSIGTAG_PGP: u32 = 1002;
const RPMSIGTAG_MD5: u32 = 1004;
const RPMSIGTAG_GPG: u32 = 1005;

/// Main header payload digest tags (`rpmtag.h`).
const RPMTAG_PAYLOADSHA256: u32 = 5092;
const RPMTAG_PAYLOADSHA256ALGO: u32 = 5093;
const RPMTAG_PAYLOADSHA256ALT: u32 = 5097;
const RPMTAG_PAYLOADSHA512: u32 = 5121;
const RPMTAG_PAYLOADSHA512ALT: u32 = 5122;
const RPMTAG_PAYLOADSHA3_256: u32 = 5123;
const RPMTAG_PAYLOADSHA3_256ALT: u32 = 5124;

/// `RPM_HASH_SHA256` (`rpmcrypto.h`): the algorithm rpm writes in
/// `RPMTAG_PAYLOADSHA256ALGO`.
const RPM_HASH_SHA256: u64 = 8;

/// MD5 digest size.
const MD5_SIZE: usize = 16;

/// A digest algorithm the crate implements.
#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut hasher = checksum::Sha1::new();
                hasher.update(bytes);
                hasher.finish().to_vec()
            }
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

/// The bytes a digest covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    /// The main header as stored.
    MainHeader,
    /// The payload as stored.
    StoredPayload,
    /// The uncompressed payload.
    DecodedPayload,
}

/// A digest stored as hexadecimal text.
struct HexDigest {
    header: HeaderKind,
    tag: u32,
    algorithm: Algorithm,
    coverage: Coverage,
    /// Name in notes and errors.
    name: &'static str,
}

const fn hex_digest(
    header: HeaderKind,
    tag: u32,
    algorithm: Algorithm,
    coverage: Coverage,
    name: &'static str,
) -> HexDigest {
    HexDigest {
        header,
        tag,
        algorithm,
        coverage,
        name,
    }
}

/// The hexadecimal digests that are verified, signature header first.
const HEX_DIGESTS: &[HexDigest] = &[
    hex_digest(
        HeaderKind::Signature,
        RPMSIGTAG_SHA256,
        Algorithm::Sha256,
        Coverage::MainHeader,
        "header SHA-256",
    ),
    hex_digest(
        HeaderKind::Signature,
        RPMSIGTAG_SHA1,
        Algorithm::Sha1,
        Coverage::MainHeader,
        "header SHA-1",
    ),
    hex_digest(
        HeaderKind::Main,
        RPMTAG_PAYLOADSHA256,
        Algorithm::Sha256,
        Coverage::StoredPayload,
        "payload SHA-256",
    ),
    hex_digest(
        HeaderKind::Main,
        RPMTAG_PAYLOADSHA512,
        Algorithm::Sha512,
        Coverage::StoredPayload,
        "payload SHA-512",
    ),
    hex_digest(
        HeaderKind::Main,
        RPMTAG_PAYLOADSHA256ALT,
        Algorithm::Sha256,
        Coverage::DecodedPayload,
        "uncompressed payload SHA-256",
    ),
    hex_digest(
        HeaderKind::Main,
        RPMTAG_PAYLOADSHA512ALT,
        Algorithm::Sha512,
        Coverage::DecodedPayload,
        "uncompressed payload SHA-512",
    ),
];

/// A tag whose presence is reported but whose value is not checked.
struct Present {
    header: HeaderKind,
    tag: u32,
    name: &'static str,
}

const fn present(header: HeaderKind, tag: u32, name: &'static str) -> Present {
    Present { header, tag, name }
}

/// SHA3-256 digests, which the crate cannot compute.
const SHA3_DIGESTS: &[Present] = &[
    present(HeaderKind::Signature, RPMSIGTAG_SHA3_256, "header SHA3-256"),
    present(HeaderKind::Main, RPMTAG_PAYLOADSHA3_256, "payload SHA3-256"),
    present(
        HeaderKind::Main,
        RPMTAG_PAYLOADSHA3_256ALT,
        "uncompressed payload SHA3-256",
    ),
];

/// Signatures, which need the signer's key.
const SIGNATURES: &[Present] = &[
    present(
        HeaderKind::Signature,
        RPMSIGTAG_OPENPGP,
        "OpenPGP header signatures",
    ),
    present(HeaderKind::Signature, RPMSIGTAG_RSA, "RSA header signature"),
    present(HeaderKind::Signature, RPMSIGTAG_DSA, "DSA header signature"),
    present(
        HeaderKind::Signature,
        RPMSIGTAG_PGP,
        "RSA header and payload signature",
    ),
    present(
        HeaderKind::Signature,
        RPMSIGTAG_GPG,
        "DSA header and payload signature",
    ),
    present(
        HeaderKind::Signature,
        RPMSIGTAG_FILESIGNATURES,
        "IMA file signatures",
    ),
    present(
        HeaderKind::Signature,
        RPMSIGTAG_VERITYSIGNATURES,
        "fs-verity file signatures",
    ),
];

/// What was verified and what is only present.
#[derive(Debug, Default)]
pub(super) struct Report {
    /// Digests that matched.
    verified: Vec<String>,
    /// Digests present that were not checked, with the reason.
    unverified: Vec<String>,
    /// Signatures present.
    signatures: Vec<&'static str>,
}

/// The header of `kind`.
fn header_of<'h, 'a>(
    kind: HeaderKind,
    signature: &'h Header<'a>,
    main: &'h Header<'a>,
) -> &'h Header<'a> {
    match kind {
        HeaderKind::Signature => signature,
        HeaderKind::Main => main,
    }
}

/// Verify the digests over the main header and the stored payload, and
/// list the digests and signatures that are only present.
///
/// # Errors
///
/// A digest that is not hexadecimal of its algorithm's size, or one that
/// does not match.
pub(super) fn verify(
    data: &[u8],
    signature: &Header<'_>,
    main: &Header<'_>,
    extent: Extent,
) -> Result<Report> {
    let mut report = Report::default();
    let payload_algorithm = main.number(RPMTAG_PAYLOADSHA256ALGO)?;
    for digest in HEX_DIGESTS {
        let covered = match digest.coverage {
            Coverage::MainHeader => main.bytes,
            Coverage::StoredPayload => &data[extent.payload..extent.end],
            Coverage::DecodedPayload => continue,
        };
        let header = header_of(digest.header, signature, main);
        let is_sha256_payload = digest.tag == RPMTAG_PAYLOADSHA256;
        match payload_algorithm {
            Some(algorithm) if is_sha256_payload && algorithm != RPM_HASH_SHA256 => {
                if header.contains(digest.tag) {
                    report.unverified.push(format!(
                        "{} (algorithm {algorithm}, not SHA-256)",
                        digest.name
                    ));
                }
                continue;
            }
            _ => {}
        }
        if check_hex(header, digest, covered)? {
            report.verified.push(digest.name.to_string());
        }
    }
    if let Some(stored) = signature.bin(RPMSIGTAG_MD5)? {
        let covered = &data[extent.header..extent.end];
        check_md5(stored, covered)?;
        report.verified.push("header and payload MD5".to_string());
    }
    for digest in SHA3_DIGESTS {
        if header_of(digest.header, signature, main).contains(digest.tag) {
            report
                .unverified
                .push(format!("{} (no SHA-3 implementation)", digest.name));
        }
    }
    for item in SIGNATURES {
        if header_of(item.header, signature, main).contains(item.tag) {
            report.signatures.push(item.name);
        }
    }
    Ok(report)
}

/// Verify the uncompressed payload digests against the decoded archive;
/// returns the names of those that matched.
///
/// # Errors
///
/// As [`verify`].
pub(super) fn verify_decoded(main: &Header<'_>, decoded: &[u8]) -> Result<Vec<String>> {
    let payload_algorithm = main.number(RPMTAG_PAYLOADSHA256ALGO)?;
    let mut verified = Vec::new();
    for digest in HEX_DIGESTS {
        if digest.coverage != Coverage::DecodedPayload {
            continue;
        }
        let other_algorithm = payload_algorithm.is_some_and(|a| a != RPM_HASH_SHA256);
        if digest.tag == RPMTAG_PAYLOADSHA256ALT && other_algorithm {
            continue;
        }
        if check_hex(main, digest, decoded)? {
            verified.push(digest.name.to_string());
        }
    }
    Ok(verified)
}

/// Check the hexadecimal digest `digest` in `header` against `covered`.
/// Returns false when the header has no such tag.
fn check_hex(header: &Header<'_>, digest: &HexDigest, covered: &[u8]) -> Result<bool> {
    let Some(stored) = header.string(digest.tag)? else {
        return Ok(false);
    };
    let computed = hex::encode(digest.algorithm.digest(covered));
    let is_hex = stored.len() == computed.len() && stored.iter().all(u8::is_ascii_hexdigit);
    if !is_hex {
        return Err(error(format!(
            "Invalid {} digest: {} B of text, expected {} hex digits",
            digest.name,
            stored.len(),
            computed.len()
        )));
    }
    if !stored.eq_ignore_ascii_case(computed.as_bytes()) {
        return Err(error(format!(
            "Invalid {} digest: stored {}, computed {computed}",
            digest.name,
            display_text(stored)
        )));
    }
    Ok(true)
}

/// Check the binary MD5 digest of the main header and payload.
fn check_md5(stored: &[u8], covered: &[u8]) -> Result<()> {
    if stored.len() != MD5_SIZE {
        return Err(error(format!(
            "Invalid header and payload MD5 digest: {} B, expected {MD5_SIZE} B",
            stored.len()
        )));
    }
    let computed = checksum::md5(covered);
    if stored != computed {
        return Err(error(format!(
            "Invalid header and payload MD5 digest: stored {}, computed {}",
            hex::encode(stored),
            hex::encode(computed)
        )));
    }
    Ok(())
}

impl Report {
    /// Record digests verified later, against the uncompressed payload.
    pub(super) fn add_verified(&mut self, names: Vec<String>) {
        self.verified.extend(names);
    }

    /// Notes and metadata for what was verified and what is only present.
    pub(super) fn push_notes(&self, c: &mut Container<'_>) {
        if self.verified.is_empty() {
            c.notes
                .push("No header or payload digest was verified".to_string());
        } else {
            c.notes
                .push(format!("Digests verified: {}", self.verified.join(", ")));
            c.push_metadata(
                "rpm_digests_verified",
                "Digests verified",
                self.verified.join(", "),
            );
        }
        if !self.unverified.is_empty() {
            c.notes.push(format!(
                "Digests present, not verified: {}",
                self.unverified.join(", ")
            ));
        }
        if self.signatures.is_empty() {
            c.notes.push("The package is not signed".to_string());
        } else {
            c.notes.push(format!(
                "Signatures present, not verified: {}",
                self.signatures.join(", ")
            ));
            c.push_metadata(
                "rpm_signatures",
                "Signatures (not verified)",
                self.signatures.join(", "),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithms_hash_known_vectors() {
        assert_eq!(
            hex::encode(Algorithm::Sha1.digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(Algorithm::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hex::encode(Algorithm::Sha512.digest(b"abc")).starts_with("ddaf35a193617aba"));
    }

    #[test]
    fn md5_mismatches_and_sizes_are_errors() {
        let covered = b"header and payload";
        let digest = checksum::md5(covered);
        assert!(check_md5(&digest, covered).is_ok());
        assert!(check_md5(&digest[..15], covered).is_err());
        let mut wrong = digest;
        wrong[0] ^= 1;
        let message = check_md5(&wrong, covered).unwrap_err().to_string();
        assert!(
            message.contains("Invalid header and payload MD5 digest"),
            "{message}"
        );
    }

    #[test]
    fn digest_names_are_unique() {
        let names: Vec<&str> = HEX_DIGESTS
            .iter()
            .map(|d| d.name)
            .chain(SHA3_DIGESTS.iter().map(|d| d.name))
            .chain(SIGNATURES.iter().map(|d| d.name))
            .collect();
        for (i, name) in names.iter().enumerate() {
            assert!(!names[i + 1..].contains(name), "{name}");
        }
    }
}
