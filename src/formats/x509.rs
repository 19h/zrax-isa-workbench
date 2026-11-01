//! Standalone X.509 certificate files: one DER `Certificate` (RFC 5280,
//! section 4.1), or text of RFC 7468 `CERTIFICATE` blocks (RFC 7468,
//! sections 2 and 5) separated by whitespace.
//!
//! Certificates are found and decoded by [`crate::certificates`], with the
//! same rules as scanning other inputs. A certificate file holds no code:
//! the container is opaque and its ISA unknown. Signatures and chains are
//! not verified.

use std::borrow::Cow;

use crate::certificates::{self, Certificate, Encoding};
use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container};
use crate::types::FileFormat;

/// The PEM encapsulation boundary that opens a certificate file.
const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
/// UTF-8 byte order mark, which some editors write before PEM text.
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";
const KEY_PREFIX: &str = "x509";

/// A certificate file layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// One DER certificate, optionally followed by `0x00`/`0xFF` padding.
    Der,
    /// One or more PEM `CERTIFICATE` blocks.
    Pem,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::X509
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Der => "X.509 certificate (DER)",
            Self::Pem => "X.509 certificates (PEM)",
        }
    }

    /// DER has no magic and needs a complete certificate; PEM opens with
    /// its encapsulation boundary.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Der)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::X509ParseError {
        message: message.into(),
    }
}

/// Text after an optional byte order mark and leading whitespace.
fn pem_text_start(data: &[u8]) -> usize {
    let start = if data.starts_with(UTF8_BOM) {
        UTF8_BOM.len()
    } else {
        0
    };
    start
        + data[start..]
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count()
}

/// A text file that opens with `-----BEGIN CERTIFICATE-----`.
pub fn detect_strong(data: &[u8]) -> Option<Layout> {
    data[pem_text_start(data)..]
        .starts_with(PEM_BEGIN)
        .then_some(Layout::Pem)
}

fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0x00 || b == 0xff)
}

/// A file that is exactly one DER certificate plus erased-flash padding.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    let size = certificates::der_certificate_at_start(data)?;
    is_padding(&data[size..]).then_some(Layout::Der)
}

/// "leaf; issued by root; SHA-256 …" for bundle metadata, using common
/// names where present.
fn certificate_line(certificate: &Certificate) -> Option<String> {
    let summary = certificate.summary.as_ref()?;
    let subject = summary.subject_cn.as_deref().unwrap_or(&summary.subject);
    let issuer = summary.issuer_cn.as_deref().unwrap_or(&summary.issuer);
    Some(format!(
        "{subject}; issued by {issuer}; SHA-256 {}",
        certificate.sha256
    ))
}

/// A scanned offset or size as a position in the input it came from.
fn position(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid certificate offset 0x{value:X}")))
}

fn push_single(c: &mut Container<'_>, certificate: &Certificate) {
    let Some(summary) = &certificate.summary else {
        return;
    };
    c.push_metadata("x509_subject", "Subject", summary.subject.clone());
    c.push_metadata("x509_issuer", "Issuer", summary.issuer.clone());
    c.push_metadata(
        "x509_not_before",
        "Not before (UTC)",
        summary.not_before.clone(),
    );
    c.push_metadata(
        "x509_not_after",
        "Not after (UTC)",
        summary.not_after.clone(),
    );
    let key = match summary.public_key_bits {
        Some(bits) => format!("{} {bits}-bit", summary.public_key_algorithm),
        None => summary.public_key_algorithm.clone(),
    };
    c.push_metadata("x509_public_key", "Public key", key);
    c.push_metadata(
        "x509_signature_algorithm",
        "Signature algorithm",
        summary.signature_algorithm.clone(),
    );
    c.push_metadata("x509_sha256", "SHA-256", certificate.sha256.clone());
}

fn parse_der(data: &[u8]) -> Result<Container<'_>> {
    let size = certificates::der_certificate_at_start(data)
        .ok_or_else(|| error("Invalid DER certificate at 0x0"))?;
    if !is_padding(&data[size..]) {
        return Err(error(format!(
            "Unexpected {} B after the certificate at 0x{size:X}",
            data.len() - size
        )));
    }
    let report = certificates::scan(&data[..size]);
    let certificate = report
        .certificates
        .first()
        .ok_or_else(|| error("Invalid DER certificate at 0x0"))?;
    let mut c = Container::new(FileFormat::X509, Layout::Der.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.opaque = true;
    c.notes
        .push("X.509 certificate; signature not verified".to_string());
    c.push_metadata("x509_certificate_count", "Certificates", 1u64);
    push_single(&mut c, certificate);
    Ok(c)
}

/// Every non-whitespace byte must belong to a parseable `CERTIFICATE`
/// block. Each block becomes an opaque child holding its DER bytes.
fn parse_pem(data: &[u8]) -> Result<Container<'_>> {
    let report = certificates::scan(data);
    if report.truncated {
        return Err(error(format!(
            "Unsupported PEM file with more than {} certificates",
            certificates::MAX_CERTIFICATES
        )));
    }
    let blocks: Vec<&Certificate> = report
        .certificates
        .iter()
        .filter(|c| c.encoding == Encoding::Pem)
        .collect();
    let mut pos = pem_text_start(data);
    for block in &blocks {
        let start = position(block.offset)?;
        if let Some(at) = data[pos..start]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
        {
            return Err(error(format!(
                "Unexpected text at 0x{:X} outside certificate blocks",
                pos + at
            )));
        }
        if let Some(message) = &block.error {
            return Err(error(format!(
                "Invalid certificate in PEM block at 0x{start:X}: {message}"
            )));
        }
        pos = start + position(block.stored_size)?;
    }
    if blocks.is_empty() {
        return Err(error("Missing complete PEM certificate block at 0x0"));
    }
    if let Some(at) = data[pos..].iter().position(|b| !b.is_ascii_whitespace()) {
        return Err(error(format!(
            "Unexpected text at 0x{:X} outside certificate blocks",
            pos + at
        )));
    }
    let mut c = Container::new(FileFormat::X509, Layout::Pem.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.opaque = true;
    let count = blocks.len();
    c.notes.push(if count == 1 {
        "1 PEM certificate; signature not verified".to_string()
    } else {
        format!("{count} PEM certificates; signatures and chains not verified")
    });
    c.push_metadata("x509_certificate_count", "Certificates", count as u64);
    if let [single] = blocks.as_slice() {
        push_single(&mut c, single);
    } else {
        for (index, block) in blocks.iter().enumerate() {
            if let Some(line) = certificate_line(block) {
                c.push_metadata(
                    format!("x509_certificate_{index}"),
                    format!("Certificate {index}"),
                    line,
                );
            }
        }
    }
    for (index, block) in blocks.iter().enumerate() {
        let label = match block.summary.as_ref().and_then(|s| s.subject_cn.as_deref()) {
            Some(cn) => format!("certificate {index} ({cn})"),
            None => format!("certificate {index}"),
        };
        let mut child = Child::decoded(
            label,
            position(block.offset)?,
            position(block.stored_size)?,
            Cow::Owned(block.der.clone()),
            "base64",
        );
        child.opaque = true;
        c.children.push(child);
    }
    Ok(c)
}

/// Parse a certificate file of the given layout.
///
/// # Errors
///
/// [`ClassifierError::X509ParseError`] for an invalid certificate, trailing
/// data, or text outside PEM certificate blocks.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Der => parse_der(data),
        Layout::Pem => parse_pem(data),
    }
}
