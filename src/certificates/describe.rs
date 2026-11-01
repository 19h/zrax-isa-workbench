//! Certificate fields decoded with `x509-parser`. The algorithm, curve and
//! key-size tables are ported from cert-dump 3.0.1 `src/parser.rs`; an OID
//! missing from them is reported in dotted form.

use serde::Serialize;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::objects::{oid2sn, oid_registry};
use x509_parser::prelude::{X509Certificate, X509Name};
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::error::{ClassifierError, Result};

/// Signature algorithm OIDs and names.
const SIGNATURE_ALGORITHMS: &[(&str, &str)] = &[
    // RSA PKCS #1 v1.5 (RFC 8017, appendix A.2.4) and RSASSA-PSS.
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.14", "sha224WithRSAEncryption"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
    // DSA (RFC 3279, RFC 5758).
    ("1.2.840.10040.4.3", "dsa-with-sha1"),
    ("2.16.840.1.101.3.4.3.1", "dsa-with-sha224"),
    ("2.16.840.1.101.3.4.3.2", "dsa-with-sha256"),
    // ECDSA (RFC 5758).
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.1", "ecdsa-with-SHA224"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    // EdDSA (RFC 8410).
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
    // SM2 with SM3 (GM/T 0006).
    ("1.2.156.10197.1.501", "sm2sign-with-sm3"),
    // GOST R 34.10-2012 (RFC 9215).
    (
        "1.2.643.7.1.1.3.2",
        "id-tc26-signwithdigest-gost3410-12-256",
    ),
    (
        "1.2.643.7.1.1.3.3",
        "id-tc26-signwithdigest-gost3410-12-512",
    ),
    // ML-DSA (FIPS 204) and the provisional Dilithium round 3 OID.
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
    ("1.3.6.1.4.1.2.267.7.6.5", "CRYSTALS-Dilithium(6,5)-R3"),
];

/// Subject public key algorithm OIDs and names.
const PUBLIC_KEY_ALGORITHMS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.1", "RSA"),
    ("1.2.840.113549.1.1.10", "RSA-PSS"),
    ("1.2.840.113549.1.1.7", "RSA-OAEP"),
    ("1.2.840.10040.4.1", "DSA"),
    ("1.2.840.10045.2.1", "EC"),
    ("1.3.101.110", "X25519"),
    ("1.3.101.111", "X448"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
    ("1.2.156.10197.1.301", "SM2"),
    ("1.2.643.7.1.1.1.1", "id-tc26-gost3410-12-256"),
    ("1.2.643.7.1.1.1.2", "id-tc26-gost3410-12-512"),
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
    ("1.3.6.1.4.1.2.267.7.6.5", "CRYSTALS-Dilithium(6,5)-R3"),
    // Provisional Kyber OIDs, as in cert-dump; not the FIPS 203 ML-KEM OIDs.
    ("1.3.6.1.4.1.22554.5.6.1", "ML-KEM-512"),
    ("1.3.6.1.4.1.22554.5.6.2", "ML-KEM-768"),
    ("1.3.6.1.4.1.22554.5.6.3", "ML-KEM-1024"),
    ("1.3.6.1.4.1.2.267.8.4.4", "CRYSTALS-Kyber(1024)-R3"),
];

/// Algorithms whose key size follows from the OID alone, in bits. cert-dump
/// also lists ML-DSA and ML-KEM here with public-key byte counts or
/// parameter-set numbers; the port reports no bit size for them.
const FIXED_KEY_BITS: &[(&str, u32)] = &[
    ("1.3.101.110", 255),
    ("1.3.101.111", 448),
    ("1.3.101.112", 255),
    ("1.3.101.113", 448),
    ("1.2.156.10197.1.301", 256),
    ("1.2.643.7.1.1.1.1", 256),
    ("1.2.643.7.1.1.1.2", 512),
];

/// Named elliptic curves: OID, name and field size in bits.
const CURVES: &[(&str, &str, u32)] = &[
    ("1.2.840.10045.3.1.1", "P-192", 192),
    ("1.3.132.0.33", "P-224", 224),
    ("1.2.840.10045.3.1.7", "P-256", 256),
    ("1.3.132.0.34", "P-384", 384),
    ("1.3.132.0.35", "P-521", 521),
    ("1.3.132.0.10", "secp256k1", 256),
    ("1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", 256),
    ("1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", 384),
    ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", 512),
    ("1.2.156.10197.1.301", "sm2p256v1", 256),
    ("1.2.643.7.1.2.1.1.1", "GOST R 34.10-2012 256-bit", 256),
    ("1.2.643.7.1.2.1.2.1", "GOST R 34.10-2012 512-bit", 512),
];

const RSA_OIDS: &[&str] = &[
    "1.2.840.113549.1.1.1",
    "1.2.840.113549.1.1.10",
    "1.2.840.113549.1.1.7",
];
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// One extension of the certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extension {
    /// Dotted OID.
    pub oid: String,
    /// Short name from the `x509-parser` registry, or the dotted OID.
    pub name: String,
    /// The extension's `critical` flag.
    pub critical: bool,
}

/// Decoded certificate fields. Dates are UTC; nothing here is verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// X.509 version: 1, 2 or 3.
    pub version: u32,
    /// Serial number as uppercase hexadecimal of its unsigned value.
    pub serial: String,
    /// Subject distinguished name, most significant RDN first.
    pub subject: String,
    /// First subject common name.
    pub subject_cn: Option<String>,
    /// Issuer distinguished name, most significant RDN first.
    pub issuer: String,
    /// First issuer common name.
    pub issuer_cn: Option<String>,
    /// Start of validity, RFC 3339 UTC.
    pub not_before: String,
    /// End of validity, RFC 3339 UTC.
    pub not_after: String,
    /// Start of validity in seconds since 1970-01-01 UTC.
    pub not_before_unix: i64,
    /// End of validity in seconds since 1970-01-01 UTC.
    pub not_after_unix: i64,
    /// Public key algorithm name, or its dotted OID.
    pub public_key_algorithm: String,
    /// Public key algorithm OID.
    pub public_key_oid: String,
    /// RSA modulus, curve field or fixed algorithm size in bits.
    pub public_key_bits: Option<u32>,
    /// Named curve of an EC key.
    pub curve: Option<String>,
    /// Signature algorithm name, or its dotted OID.
    pub signature_algorithm: String,
    /// Signature algorithm OID.
    pub signature_oid: String,
    /// The `cA` flag of basic constraints, when the extension is present.
    pub is_ca: Option<bool>,
    /// The basic constraints path length limit.
    pub path_len: Option<u32>,
    /// Key usage bits that are set (RFC 5280, section 4.2.1.3).
    pub key_usage: Vec<&'static str>,
    /// Extended key usage purposes (RFC 5280, section 4.2.1.12).
    pub extended_key_usage: Vec<String>,
    /// Subject alternative names as `type:value`.
    pub subject_alt_names: Vec<String>,
    /// Subject key identifier, uppercase hexadecimal.
    pub subject_key_id: Option<String>,
    /// Authority key identifier, uppercase hexadecimal.
    pub authority_key_id: Option<String>,
    /// Every extension in encoded order.
    pub extensions: Vec<Extension>,
}

/// Encoded names and key identifiers used to link issuers.
#[derive(Debug, Clone)]
pub(super) struct Names {
    pub(super) subject: Vec<u8>,
    pub(super) issuer: Vec<u8>,
    pub(super) subject_key_id: Option<Vec<u8>>,
    pub(super) authority_key_id: Option<Vec<u8>>,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::X509ParseError {
        message: message.into(),
    }
}

fn lookup<'a>(table: &[(&str, &'a str)], oid: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(entry, _)| *entry == oid)
        .map(|(_, name)| *name)
}

fn upper_hex(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

const SECONDS_PER_DAY: i64 = 86_400;

/// Proleptic Gregorian date of a day count since 1970-01-01
/// (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms",
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// RFC 3339 in UTC, e.g. `2025-01-01T00:00:00Z`.
fn rfc3339(time: ASN1Time) -> String {
    let seconds = time.timestamp();
    let (year, month, day) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    let second_of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60
    )
}

fn common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .find_map(|attribute| attribute.as_str().ok())
        .map(|cn| cn.trim().to_string())
}

/// Bit length of an unsigned big-endian integer.
fn bit_length(bytes: &[u8]) -> u32 {
    let significant: &[u8] = match bytes.iter().position(|&b| b != 0) {
        Some(first) => &bytes[first..],
        None => return 0,
    };
    let bits = significant.len().saturating_mul(8) - significant[0].leading_zeros() as usize;
    u32::try_from(bits).unwrap_or(u32::MAX)
}

/// Algorithm name, key size in bits and curve name of a public key.
fn public_key(spki: &SubjectPublicKeyInfo<'_>) -> (String, String, Option<u32>, Option<String>) {
    let oid = spki.algorithm.algorithm.to_id_string();
    let name = lookup(PUBLIC_KEY_ALGORITHMS, &oid).map_or_else(|| oid.clone(), str::to_string);
    let curve = (oid == EC_PUBLIC_KEY)
        .then(|| spki.algorithm.parameters.as_ref()?.as_oid().ok())
        .flatten()
        .and_then(|curve| {
            let id = curve.to_id_string();
            CURVES.iter().find(|(entry, _, _)| *entry == id)
        });
    let bits = if RSA_OIDS.contains(&oid.as_str()) {
        match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => Some(bit_length(rsa.modulus)),
            _ => None,
        }
    } else if let Some((_, _, curve_bits)) = curve {
        Some(*curve_bits)
    } else {
        FIXED_KEY_BITS
            .iter()
            .find(|(entry, _)| *entry == oid)
            .map(|(_, bits)| *bits)
    };
    (
        name,
        oid,
        bits,
        curve.map(|(_, curve_name, _)| (*curve_name).to_string()),
    )
}

fn key_usage(certificate: &X509Certificate<'_>) -> Vec<&'static str> {
    let Ok(Some(usage)) = certificate.key_usage() else {
        return Vec::new();
    };
    let usage = usage.value;
    [
        (usage.digital_signature(), "digitalSignature"),
        (usage.non_repudiation(), "nonRepudiation"),
        (usage.key_encipherment(), "keyEncipherment"),
        (usage.data_encipherment(), "dataEncipherment"),
        (usage.key_agreement(), "keyAgreement"),
        (usage.key_cert_sign(), "keyCertSign"),
        (usage.crl_sign(), "cRLSign"),
        (usage.encipher_only(), "encipherOnly"),
        (usage.decipher_only(), "decipherOnly"),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .map(|(_, name)| name)
    .collect()
}

fn extended_key_usage(certificate: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(usage)) = certificate.extended_key_usage() else {
        return Vec::new();
    };
    let usage = usage.value;
    let mut purposes: Vec<String> = [
        (usage.any, "anyExtendedKeyUsage"),
        (usage.server_auth, "serverAuth"),
        (usage.client_auth, "clientAuth"),
        (usage.code_signing, "codeSigning"),
        (usage.email_protection, "emailProtection"),
        (usage.time_stamping, "timeStamping"),
        (usage.ocsp_signing, "OCSPSigning"),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .map(|(_, name)| name.to_string())
    .collect();
    purposes.extend(usage.other.iter().map(Oid::to_id_string));
    purposes
}

fn ip_address(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => format!("{a}.{b}.{c}.{d}"),
        _ if bytes.len() == 16 => bytes
            .chunks(2)
            .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
            .collect::<Vec<_>>()
            .join(":"),
        _ => upper_hex(bytes),
    }
}

fn general_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(dns) => format!("DNS:{dns}"),
        GeneralName::RFC822Name(email) => format!("email:{email}"),
        GeneralName::URI(uri) => format!("URI:{uri}"),
        GeneralName::IPAddress(bytes) => format!("IP:{}", ip_address(bytes)),
        GeneralName::DirectoryName(directory) => format!("DirName:{directory}"),
        GeneralName::RegisteredID(oid) => format!("RID:{}", oid.to_id_string()),
        GeneralName::OtherName(oid, _) => format!("othername:{}", oid.to_id_string()),
        GeneralName::X400Address(_) => "X400Address".to_string(),
        GeneralName::EDIPartyName(_) => "EDIPartyName".to_string(),
    }
}

fn subject_alt_names(certificate: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    names.value.general_names.iter().map(general_name).collect()
}

/// Subject and authority key identifiers as encoded.
fn key_identifiers(certificate: &X509Certificate<'_>) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut subject = None;
    let mut authority = None;
    for extension in certificate.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => subject = Some(id.0.to_vec()),
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                authority = aki.key_identifier.as_ref().map(|id| id.0.to_vec());
            }
            _ => {}
        }
    }
    (subject, authority)
}

fn extensions(certificate: &X509Certificate<'_>) -> Vec<Extension> {
    let registry = oid_registry();
    certificate
        .extensions()
        .iter()
        .map(|extension| {
            let oid = extension.oid.to_id_string();
            let name =
                oid2sn(&extension.oid, registry).map_or_else(|_| oid.clone(), str::to_string);
            Extension {
                oid,
                name,
                critical: extension.critical,
            }
        })
        .collect()
}

/// Decode one DER certificate, which must be exactly one `Certificate`.
pub(super) fn describe(der: &[u8]) -> Result<(Summary, Names)> {
    let (rest, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| error(format!("Invalid certificate structure: {e}")))?;
    if !rest.is_empty() {
        return Err(error(format!(
            "Trailing {} B after certificate",
            rest.len()
        )));
    }
    let tbs = &certificate.tbs_certificate;
    let signature_oid = certificate.signature_algorithm.algorithm.to_id_string();
    let signature_algorithm = lookup(SIGNATURE_ALGORITHMS, &signature_oid)
        .map_or_else(|| signature_oid.clone(), str::to_string);
    let (public_key_algorithm, public_key_oid, public_key_bits, curve) =
        public_key(certificate.public_key());
    let constraints = certificate.basic_constraints().ok().flatten();
    let (subject_key_id, authority_key_id) = key_identifiers(&certificate);
    let validity = certificate.validity();
    let summary = Summary {
        version: certificate.version().0 + 1,
        serial: upper_hex(&tbs.serial.to_bytes_be()),
        subject: certificate.subject().to_string(),
        subject_cn: common_name(certificate.subject()),
        issuer: certificate.issuer().to_string(),
        issuer_cn: common_name(certificate.issuer()),
        not_before: rfc3339(validity.not_before),
        not_after: rfc3339(validity.not_after),
        not_before_unix: validity.not_before.timestamp(),
        not_after_unix: validity.not_after.timestamp(),
        public_key_algorithm,
        public_key_oid,
        public_key_bits,
        curve,
        signature_algorithm,
        signature_oid,
        is_ca: constraints.as_ref().map(|c| c.value.ca),
        path_len: constraints.and_then(|c| c.value.path_len_constraint),
        key_usage: key_usage(&certificate),
        extended_key_usage: extended_key_usage(&certificate),
        subject_alt_names: subject_alt_names(&certificate),
        subject_key_id: subject_key_id.as_deref().map(upper_hex),
        authority_key_id: authority_key_id.as_deref().map(upper_hex),
        extensions: extensions(&certificate),
    };
    let names = Names {
        subject: tbs.subject.as_raw().to_vec(),
        issuer: tbs.issuer.as_raw().to_vec(),
        subject_key_id,
        authority_key_id,
    };
    Ok((summary, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_ignores_leading_zero_octets_and_bits() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x7f, 0xff]), 15);
        assert_eq!(bit_length(&[0x01]), 1);
    }

    #[test]
    fn dates_are_utc_rfc3339_across_epochs() {
        let date = |seconds| rfc3339(ASN1Time::from_timestamp(seconds).unwrap());
        assert_eq!(date(0), "1970-01-01T00:00:00Z");
        assert_eq!(date(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(date(-1), "1969-12-31T23:59:59Z");
        assert_eq!(date(253_402_300_799), "9999-12-31T23:59:59Z");
    }

    #[test]
    fn unknown_algorithm_oids_are_reported_in_dotted_form() {
        assert_eq!(lookup(SIGNATURE_ALGORITHMS, "1.2.3.4"), None);
        assert_eq!(
            lookup(SIGNATURE_ALGORITHMS, "1.2.840.113549.1.1.11"),
            Some("sha256WithRSAEncryption")
        );
    }
}
