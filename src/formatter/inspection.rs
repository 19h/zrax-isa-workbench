//! Text renderings of certificate and string reports for the `certs` and
//! `strings` CLI subcommands.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;

use crate::certificates::{Certificate, Report};
use crate::inspection::{enclosing, Region};
use crate::strings::FoundString;

/// Separator between the outer and inner regions of a path.
const REGION_SEPARATOR: &str = " > ";

/// How the `strings` text output prints offsets, as in GNU `strings -t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetRadix {
    /// Octal offsets.
    Octal,
    /// Decimal offsets.
    Decimal,
    /// Hexadecimal offsets.
    Hex,
}

/// The regions that contain a certificate, outermost first, joined with
/// `" > "`.
pub fn certificate_location(regions: &[Region], certificate: &Certificate) -> Option<String> {
    let path = enclosing(regions, certificate.offset, certificate.stored_size);
    if path.is_empty() {
        return None;
    }
    let labels: Vec<&str> = path.iter().map(|region| region.label.as_str()).collect();
    Some(labels.join(REGION_SEPARATOR))
}

fn push_field(out: &mut String, label: &str, value: &str) {
    // `write!` to a `String` cannot fail.
    let _ = writeln!(out, "      {:<11} {value}", format!("{label}:"));
}

fn push_certificate(out: &mut String, certificate: &Certificate, regions: &[Region]) {
    let encoding = match certificate.encoding {
        crate::certificates::Encoding::Der => "DER",
        crate::certificates::Encoding::Pem => "PEM",
    };
    let _ = writeln!(
        out,
        "  [{}] {encoding} at 0x{:X}, {} B",
        certificate.index, certificate.offset, certificate.stored_size
    );
    if let Some(location) = certificate_location(regions, certificate) {
        push_field(out, "Within", &location);
    }
    if let Some(error) = &certificate.error {
        push_field(out, "Error", error);
        return;
    }
    let Some(summary) = &certificate.summary else {
        return;
    };
    push_field(out, "Subject", &summary.subject);
    let issuer = if certificate.self_issued {
        format!("{} (self-issued)", summary.issuer)
    } else {
        summary.issuer.clone()
    };
    push_field(out, "Issuer", &issuer);
    push_field(out, "Serial", &summary.serial);
    let validity = format!("{} to {}", summary.not_before, summary.not_after);
    push_field(out, "Valid", &validity);
    let key = match (summary.public_key_bits, &summary.curve) {
        (Some(bits), Some(curve)) => {
            format!("{} {bits}-bit ({curve})", summary.public_key_algorithm)
        }
        (Some(bits), None) => format!("{} {bits}-bit", summary.public_key_algorithm),
        (None, _) => summary.public_key_algorithm.clone(),
    };
    push_field(out, "Key", &key);
    push_field(out, "Signature", &summary.signature_algorithm);
    push_field(out, "SHA-256", &certificate.sha256);
    if let Some(issuer) = certificate.issuer_index {
        push_field(out, "Issued by", &format!("[{issuer}] (name match)"));
    }
    if let Some(original) = certificate.duplicate_of {
        push_field(out, "Duplicate", &format!("of [{original}]"));
    }
}

/// The human-readable certificate listing of one file.
pub fn certificates_human(path: &Path, report: &Report, regions: &[Region]) -> String {
    let mut out = format!("File: {}\n", path.display());
    let _ = writeln!(out, "  Certificates: {}", report.certificates.len());
    for note in &report.notes {
        let _ = writeln!(out, "  Note: {note}");
    }
    for certificate in &report.certificates {
        out.push('\n');
        push_certificate(&mut out, certificate, regions);
    }
    out
}

fn tree_name(certificate: &Certificate) -> String {
    let name = certificate.summary.as_ref().map_or("(unparsed)", |s| {
        s.subject_cn.as_deref().unwrap_or(s.subject.as_str())
    });
    let suffix = if certificate.self_issued {
        " (self-issued)"
    } else {
        ""
    };
    format!("{name} [{}]{suffix}", certificate.index)
}

fn push_subtree(
    out: &mut String,
    certificates: &[Certificate],
    index: usize,
    prefix: &str,
    visited: &mut HashSet<usize>,
) {
    let children: Vec<&Certificate> = certificates
        .iter()
        .filter(|c| c.issuer_index == Some(index) && c.duplicate_of.is_none())
        .filter(|c| !visited.contains(&c.index))
        .collect();
    for (position, child) in children.iter().enumerate() {
        if !visited.insert(child.index) {
            continue;
        }
        let last = position + 1 == children.len();
        let (branch, indent) = if last {
            ("└─ ", "   ")
        } else {
            ("├─ ", "│  ")
        };
        let _ = writeln!(out, "  {prefix}{branch}{}", tree_name(child));
        push_subtree(
            out,
            certificates,
            child.index,
            &format!("{prefix}{indent}"),
            visited,
        );
    }
}

/// The issuer links of one file as a tree. Roots are certificates without
/// an issuer link; certificates only reachable through a cycle are listed
/// as unlinked, and duplicates by their first occurrence.
pub fn certificates_tree(path: &Path, report: &Report) -> String {
    let certificates = &report.certificates;
    let mut out = format!("File: {}\n", path.display());
    let _ = writeln!(
        out,
        "  Issuer links compare encoded names; signatures not verified"
    );
    let mut visited = HashSet::new();
    for root in certificates
        .iter()
        .filter(|c| c.issuer_index.is_none() && c.duplicate_of.is_none())
    {
        visited.insert(root.index);
        let _ = writeln!(out, "  {}", tree_name(root));
        push_subtree(&mut out, certificates, root.index, "", &mut visited);
    }
    let unlinked: Vec<&Certificate> = certificates
        .iter()
        .filter(|c| c.duplicate_of.is_none() && !visited.contains(&c.index))
        .collect();
    if !unlinked.is_empty() {
        let _ = writeln!(out, "  Unlinked (issuer cycle):");
        for certificate in unlinked {
            let _ = writeln!(out, "    {}", tree_name(certificate));
        }
    }
    for (index, original) in certificates
        .iter()
        .filter_map(|c| c.duplicate_of.map(|original| (c.index, original)))
    {
        let _ = writeln!(out, "  Duplicate: [{index}] of [{original}]");
    }
    out
}

/// GNU-style text: one string per line, optionally after its offset.
pub fn strings_text(strings: &[FoundString], radix: Option<OffsetRadix>) -> String {
    let mut out = String::new();
    for found in strings {
        let _ = match radix {
            None => writeln!(out, "{}", found.text),
            Some(OffsetRadix::Octal) => writeln!(out, "{:7o} {}", found.offset, found.text),
            Some(OffsetRadix::Decimal) => writeln!(out, "{:7} {}", found.offset, found.text),
            Some(OffsetRadix::Hex) => writeln!(out, "{:7x} {}", found.offset, found.text),
        };
    }
    out
}

/// A CSV field, quoted when it contains a quote, comma or line break.
fn csv_field(value: &str) -> String {
    if value.contains(['"', ',', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// CSV with the header `offset,size,chars,encoding,tags,clipped,text`.
/// Offsets are decimal bytes and tags are separated by `;`.
pub fn strings_csv(strings: &[FoundString]) -> String {
    let mut out = String::from("offset,size,chars,encoding,tags,clipped,text\r\n");
    for found in strings {
        let tags: Vec<&str> = found.tags.ids().collect();
        let _ = write!(
            out,
            "{},{},{},{},{},{},{}\r\n",
            found.offset,
            found.size,
            found.chars,
            found.encoding.id(),
            tags.join(";"),
            found.clipped,
            csv_field(&found.text)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strings::{extract, Encodings, Options};

    #[test]
    fn csv_quotes_fields_that_need_it() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn strings_text_prints_offsets_in_the_requested_radix() {
        let options = Options::new(4, Encodings::ASCII).unwrap();
        let found = extract(b"\x00\x00abcd\x00", &options, usize::MAX).strings;
        assert_eq!(strings_text(&found, None), "abcd\n");
        assert_eq!(
            strings_text(&found, Some(OffsetRadix::Hex)),
            "      2 abcd\n"
        );
        let csv = strings_csv(&found);
        assert_eq!(
            csv,
            "offset,size,chars,encoding,tags,clipped,text\r\n2,4,4,ascii,,false,abcd\r\n"
        );
    }
}
