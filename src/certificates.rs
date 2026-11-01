//! X.509 certificates found anywhere in a byte buffer: DER `Certificate`
//! structures (RFC 5280, section 4.1) and textual `CERTIFICATE` blocks
//! (RFC 7468, sections 2 and 5).
//!
//! The scanner and the algorithm-name tables are ported from cert-dump 3.0.1
//! (commit `0c4baea`, `src/scanner.rs` and `src/parser.rs`; MIT, same author).
//! `docs/certificates.md` lists the intentional differences.
//!
//! DER candidates need definite, minimal lengths (X.690, sections 8.1.3 and
//! 10.1). Structure is parsed with `x509-parser`. Signatures and chains are
//! not verified: an issuer link only means that the issuer's encoded subject
//! name equals this certificate's encoded issuer name. No clock is read, so
//! results depend only on the input bytes.

mod describe;
mod scan;

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub use describe::{Extension, Summary};

/// Most certificates one scan reports; later ones set [`Report::truncated`].
pub const MAX_CERTIFICATES: usize = 4096;

/// Largest DER certificate considered, in bytes (the TI boot-certificate
/// limit).
pub const MAX_CERTIFICATE_SIZE: usize = 1 << 20;

/// Largest PEM block considered, from the `BEGIN` marker through the `END`
/// marker, in bytes. Base64 of [`MAX_CERTIFICATE_SIZE`] plus line breaks fits.
pub const MAX_PEM_BLOCK: usize = 2 << 20;

/// Bytes a window must extend past its reported range so that every
/// certificate starting in that range is complete.
pub const WINDOW_OVERLAP: usize = MAX_PEM_BLOCK;

/// Width of base64 lines in re-encoded PEM (RFC 7468, section 2).
const PEM_LINE_CHARS: usize = 64;

const NOT_VERIFIED_NOTE: &str =
    "Signatures and chains not verified; issuer links compare encoded names only";

/// How a certificate is stored in the scanned bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// A binary DER `Certificate` structure.
    Der,
    /// A base64 `-----BEGIN CERTIFICATE-----` block.
    Pem,
}

/// One certificate occurrence.
#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    /// Position in offset order, starting at 0.
    pub index: usize,
    /// Byte offset of the DER structure or of the PEM `BEGIN` marker.
    pub offset: u64,
    /// Stored bytes: the DER structure, or the PEM block through its `END`
    /// marker.
    pub stored_size: u64,
    /// How the certificate is stored.
    pub encoding: Encoding,
    /// Size of the DER encoding in bytes.
    pub der_size: usize,
    /// Lowercase hexadecimal SHA-256 of the DER encoding.
    pub sha256: String,
    /// The DER encoding as an RFC 7468 PEM block with 64-character lines.
    pub pem: String,
    /// Decoded fields; absent when [`Certificate::error`] is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    /// Why a PEM block's contents are not a parseable certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Index of another certificate whose encoded subject equals this
    /// certificate's encoded issuer. A name match, not a verified signature.
    pub issuer_index: Option<usize>,
    /// The encoded subject and issuer names are equal (RFC 5280,
    /// section 3.2, "self-issued"). The signature is not checked.
    pub self_issued: bool,
    /// Index of the first certificate with the same DER encoding.
    pub duplicate_of: Option<usize>,
    /// The DER encoding.
    #[serde(skip)]
    pub der: Vec<u8>,
    #[serde(skip)]
    names: Option<describe::Names>,
}

/// The certificates of one input, in offset order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// Certificates in offset order.
    pub certificates: Vec<Certificate>,
    /// Scanning stopped after [`MAX_CERTIFICATES`] certificates.
    pub truncated: bool,
    /// Sentence-case remarks on what the report does not establish.
    pub notes: Vec<String>,
}

/// A certificate located by the scanners, before description and linking.
#[derive(Debug)]
struct Found {
    offset: u64,
    stored_size: u64,
    encoding: Encoding,
    der: Vec<u8>,
}

/// Accumulates certificates over consecutive windows of one input.
///
/// Each window reports the certificates that start in its first
/// `report_len` bytes. Windows must be pushed in increasing order without
/// gaps between their reported ranges, and must extend [`WINDOW_OVERLAP`]
/// bytes past the reported range unless they end the input. The report is
/// then identical to [`scan`] over the whole input.
#[derive(Debug, Default)]
pub struct Scan {
    found: Vec<Found>,
    truncated: bool,
}

impl Scan {
    /// An empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `window`, whose first byte is at input offset `base`, for
    /// certificates starting in `window[..report_len]`.
    pub fn push_window(&mut self, window: &[u8], base: u64, report_len: usize) {
        if self.truncated {
            return;
        }
        let report_len = report_len.min(window.len());
        let remaining = MAX_CERTIFICATES - self.found.len();
        // One more than fits shows whether this window overflows the limit.
        let limit = remaining + 1;
        let mut found = scan::der_certificates(window, report_len, limit);
        found.extend(scan::pem_certificates(window, report_len, limit));
        found.sort_by_key(|f| (f.offset, f.encoding));
        if found.len() > remaining {
            found.truncate(remaining);
            self.truncated = true;
        }
        for mut f in found {
            f.offset += base;
            self.found.push(f);
        }
    }

    /// Describe, deduplicate and link the accumulated certificates.
    pub fn finish(self) -> Report {
        let mut certificates: Vec<Certificate> = self
            .found
            .into_iter()
            .enumerate()
            .map(|(index, found)| certificate(index, found))
            .collect();
        link_duplicates(&mut certificates);
        link_issuers(&mut certificates);
        let mut notes = Vec::new();
        if !certificates.is_empty() {
            notes.push(NOT_VERIFIED_NOTE.to_string());
        }
        if self.truncated {
            notes.push(format!(
                "Scanning stopped after {MAX_CERTIFICATES} certificates"
            ));
        }
        Report {
            certificates,
            truncated: self.truncated,
            notes,
        }
    }
}

/// Every DER and PEM certificate in `data`, in offset order.
pub fn scan(data: &[u8]) -> Report {
    let mut accumulator = Scan::new();
    accumulator.push_window(data, 0, data.len());
    accumulator.finish()
}

/// The DER encoding as a PEM block: RFC 7468 labels, 64-character base64
/// lines and a final line break.
pub fn to_pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / PEM_LINE_CHARS + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    // Base64 output is ASCII, so every byte index is a character boundary.
    let mut start = 0;
    while start < body.len() {
        let end = (start + PEM_LINE_CHARS).min(body.len());
        pem.push_str(&body[start..end]);
        pem.push('\n');
        start = end;
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn certificate(index: usize, found: Found) -> Certificate {
    let (summary, names, error) = match describe::describe(&found.der) {
        Ok((summary, names)) => (Some(summary), Some(names), None),
        Err(error) => (None, None, Some(error.to_string())),
    };
    Certificate {
        index,
        offset: found.offset,
        stored_size: found.stored_size,
        encoding: found.encoding,
        der_size: found.der.len(),
        sha256: hex::encode(Sha256::digest(&found.der)),
        pem: to_pem(&found.der),
        summary,
        error,
        issuer_index: None,
        self_issued: false,
        duplicate_of: None,
        der: found.der,
        names,
    }
}

fn link_duplicates(certificates: &mut [Certificate]) {
    let mut first: HashMap<String, usize> = HashMap::new();
    for c in certificates.iter_mut() {
        match first.get(&c.sha256) {
            Some(&original) => c.duplicate_of = Some(original),
            None => {
                first.insert(c.sha256.clone(), c.index);
            }
        }
    }
}

/// Link each certificate to an issuer by encoded name. Among several
/// candidates, one whose subject key identifier equals this certificate's
/// authority key identifier wins; otherwise the lowest index. Duplicates are
/// never chosen as issuers, so a chain points at first occurrences.
fn link_issuers(certificates: &mut [Certificate]) {
    let mut by_subject: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for c in certificates.iter() {
        if let (Some(names), None) = (&c.names, c.duplicate_of) {
            by_subject.entry(&names.subject).or_default().push(c.index);
        }
    }
    let mut links = Vec::with_capacity(certificates.len());
    for c in certificates.iter() {
        let Some(names) = &c.names else {
            links.push((false, None));
            continue;
        };
        if names.subject == names.issuer {
            links.push((true, None));
            continue;
        }
        let candidates: Vec<usize> = by_subject
            .get(names.issuer.as_slice())
            .map(|list| list.iter().copied().filter(|&i| i != c.index).collect())
            .unwrap_or_default();
        let by_key = names.authority_key_id.as_ref().and_then(|aki| {
            candidates.iter().copied().find(|&i| {
                certificates[i]
                    .names
                    .as_ref()
                    .and_then(|issuer| issuer.subject_key_id.as_ref())
                    == Some(aki)
            })
        });
        links.push((false, by_key.or_else(|| candidates.first().copied())));
    }
    for (c, (self_issued, issuer_index)) in certificates.iter_mut().zip(links) {
        c.self_issued = self_issued;
        c.issuer_index = issuer_index;
    }
}
