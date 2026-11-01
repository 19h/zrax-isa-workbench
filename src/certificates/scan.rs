//! Certificate candidates in a window: DER structures that `x509-parser`
//! accepts exactly, and RFC 7468 `CERTIFICATE` blocks with strict base64.
//! Ported from cert-dump 3.0.1 `src/scanner.rs`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use memchr::{memchr_iter, memmem};

use super::{Encoding, Found, MAX_CERTIFICATE_SIZE, MAX_PEM_BLOCK};

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
/// `[0] EXPLICIT Version`: context tag 0, length 3, `INTEGER`, length 1.
const VERSION_PREFIX: [u8; 4] = [0xa0, 0x03, 0x02, 0x01];
/// Version values 0, 1 and 2 encode v1, v2 and v3 (RFC 5280, section 4.1.2.1).
const MAX_VERSION: u8 = 2;
/// Long-form DER lengths of up to four octets (4 GiB) are read.
const MAX_LENGTH_OCTETS: usize = 4;

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

/// Header size and content size of the definite-length element at `at`.
/// Long forms must be minimal (X.690, section 10.1).
fn der_lengths(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *data.get(at.checked_add(1)?)?;
    if first & 0x80 == 0 {
        return Some((2, usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > MAX_LENGTH_OCTETS {
        return None;
    }
    let start = at.checked_add(2)?;
    let octets = data.get(start..start.checked_add(count)?)?;
    if octets[0] == 0 {
        return None;
    }
    let len = octets.iter().try_fold(0usize, |value, b| {
        value.checked_mul(256)?.checked_add(usize::from(*b))
    })?;
    if len < 0x80 {
        return None;
    }
    Some((2 + count, len))
}

/// The DER `Certificate` starting at `at`, if one is there: an outer
/// `SEQUENCE` whose first element is the `TBSCertificate` `SEQUENCE`,
/// starting with a version or a serial number. Only then does the full
/// parser run, and it must consume the structure exactly.
fn der_candidate(window: &[u8], at: usize) -> Option<&[u8]> {
    let (header, content) = der_lengths(window, at)?;
    let size = header.checked_add(content)?;
    if size > MAX_CERTIFICATE_SIZE {
        return None;
    }
    let candidate = window.get(at..at.checked_add(size)?)?;
    if candidate.get(header) != Some(&SEQUENCE) {
        return None;
    }
    let (tbs_header, _) = der_lengths(candidate, header)?;
    let tbs = candidate.get(header + tbs_header..)?;
    let has_version = tbs.starts_with(&VERSION_PREFIX)
        && tbs
            .get(VERSION_PREFIX.len())
            .is_some_and(|v| *v <= MAX_VERSION);
    if !has_version && tbs.first() != Some(&INTEGER) {
        return None;
    }
    match x509_parser::parse_x509_certificate(candidate) {
        Ok(([], _)) => Some(candidate),
        _ => None,
    }
}

/// DER certificates starting in `window[..report_len]`, at most `limit`.
/// Every `SEQUENCE` tag is a candidate, including tags inside certificates
/// already found, so the result does not depend on window boundaries.
pub(super) fn der_certificates(window: &[u8], report_len: usize, limit: usize) -> Vec<Found> {
    let mut found = Vec::new();
    for at in memchr_iter(SEQUENCE, &window[..report_len]) {
        if found.len() == limit {
            break;
        }
        if let Some(der) = der_candidate(window, at) {
            found.push(Found {
                offset: at as u64,
                stored_size: der.len() as u64,
                encoding: Encoding::Der,
                der: der.to_vec(),
            });
        }
    }
    found
}

/// Base64 body of a PEM block with ASCII whitespace removed, decoded with
/// strict padding. Anything else in the body rejects the block.
fn decode_pem_body(body: &[u8]) -> Option<Vec<u8>> {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let der = STANDARD.decode(compact).ok()?;
    (!der.is_empty() && der.len() <= MAX_CERTIFICATE_SIZE).then_some(der)
}

/// PEM blocks whose `BEGIN` marker starts in `window[..report_len]`, at most
/// `limit`. An `END` marker closes the nearest `BEGIN` before it; earlier
/// unterminated `BEGIN` markers are ignored. Each byte is searched a bounded
/// number of times, so marker floods take linear time.
pub(super) fn pem_certificates(window: &[u8], report_len: usize, limit: usize) -> Vec<Found> {
    let begin_finder = memmem::Finder::new(PEM_BEGIN);
    let end_finder = memmem::Finder::new(PEM_END);
    let mut found = Vec::new();
    let mut pos = 0;
    while found.len() < limit && pos < report_len {
        let Some(begin) = begin_finder.find(&window[pos..]).map(|rel| pos + rel) else {
            break;
        };
        if begin >= report_len {
            break;
        }
        let body_start = begin + PEM_BEGIN.len();
        // No END after this BEGIN means none after any later BEGIN either.
        let Some(end) = end_finder
            .find(&window[body_start..])
            .map(|rel| body_start + rel)
        else {
            break;
        };
        let footer_end = end + PEM_END.len();
        pos = footer_end;
        // The innermost BEGIN before this END owns the block.
        let begin = memmem::rfind(&window[body_start..end], PEM_BEGIN)
            .map_or(begin, |rel| body_start + rel);
        if begin >= report_len || footer_end - begin > MAX_PEM_BLOCK {
            continue;
        }
        let Some(der) = decode_pem_body(&window[begin + PEM_BEGIN.len()..end]) else {
            continue;
        };
        found.push(Found {
            offset: begin as u64,
            stored_size: (footer_end - begin) as u64,
            encoding: Encoding::Pem,
            der,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_lengths_require_minimal_definite_forms() {
        assert_eq!(der_lengths(&[0x30, 0x05], 0), Some((2, 5)));
        assert_eq!(der_lengths(&[0x30, 0x81, 0x80], 0), Some((3, 0x80)));
        assert_eq!(der_lengths(&[0x30, 0x82, 0x01, 0x00], 0), Some((4, 0x100)));
        // Long form for a short length, a leading zero octet, indefinite
        // length, too many octets and truncation.
        assert_eq!(der_lengths(&[0x30, 0x81, 0x7f], 0), None);
        assert_eq!(der_lengths(&[0x30, 0x82, 0x00, 0x80], 0), None);
        assert_eq!(der_lengths(&[0x30, 0x80], 0), None);
        assert_eq!(der_lengths(&[0x30, 0x85, 1, 0, 0, 0, 0], 0), None);
        assert_eq!(der_lengths(&[0x30, 0x82, 0x01], 0), None);
        assert_eq!(der_lengths(&[0x30], 0), None);
    }

    #[test]
    fn pem_flood_without_end_markers_stops_at_the_first_unterminated_begin() {
        let flood = PEM_BEGIN.repeat(100_000);
        assert!(pem_certificates(&flood, flood.len(), usize::MAX).is_empty());
    }
}
