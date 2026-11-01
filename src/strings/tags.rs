//! Lexical tags on string text. Each tag is a pattern match on the
//! characters only; it does not establish that the text is used as a URL,
//! a path or a format string. The rules are listed in `docs/strings.md`.

use bitflags::bitflags;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

bitflags! {
    /// Pattern matches on a string's text.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Tags: u16 {
        /// `scheme://` with a scheme of at least two characters.
        const URL = 1;
        /// `local@domain.tld`.
        const EMAIL = 1 << 1;
        /// Four dotted decimal octets, each at most 255.
        const IPV4 = 1 << 2;
        /// A Unix absolute path of two or more segments, `X:\` or UNC.
        const PATH = 1 << 3;
        /// `8-4-4-4-12` hexadecimal groups.
        const UUID = 1 << 4;
        /// A printf-style conversion.
        const FORMAT = 1 << 5;
        /// A delimited run of 32, 40, 64 or 128 hexadecimal digits.
        const DIGEST = 1 << 6;
        /// An Itanium (`_Z`) or MSVC (`?...@@`) mangled C++ name.
        const MANGLED = 1 << 7;
        /// An RFC 7468 `-----BEGIN ` encapsulation boundary.
        const PEM = 1 << 8;
    }
}

/// Tag identifiers in display order.
pub const TAG_NAMES: &[(Tags, &str)] = &[
    (Tags::URL, "url"),
    (Tags::EMAIL, "email"),
    (Tags::IPV4, "ipv4"),
    (Tags::PATH, "path"),
    (Tags::UUID, "uuid"),
    (Tags::FORMAT, "format"),
    (Tags::DIGEST, "digest"),
    (Tags::MANGLED, "mangled"),
    (Tags::PEM, "pem"),
];

impl Tags {
    /// The tag with identifier `id`.
    pub fn from_id(id: &str) -> Option<Self> {
        TAG_NAMES
            .iter()
            .find(|(_, entry)| *entry == id)
            .map(|(tag, _)| *tag)
    }

    /// Identifiers of the tags in this set, in display order.
    pub fn ids(self) -> impl Iterator<Item = &'static str> {
        TAG_NAMES
            .iter()
            .filter(move |(tag, _)| self.contains(*tag))
            .map(|(_, name)| *name)
    }
}

impl Serialize for Tags {
    /// A list of tag identifiers.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for name in self.ids() {
            seq.serialize_element(name)?;
        }
        seq.end()
    }
}

/// A pattern test on string text.
type Matcher = fn(&[u8]) -> bool;

/// Each tag and its pattern test.
const MATCHERS: [(Tags, Matcher); 9] = [
    (Tags::URL, has_url),
    (Tags::EMAIL, has_email),
    (Tags::IPV4, has_ipv4),
    (Tags::PATH, has_path),
    (Tags::UUID, has_uuid),
    (Tags::FORMAT, has_format),
    (Tags::DIGEST, has_digest),
    (Tags::MANGLED, is_mangled),
    (Tags::PEM, has_pem_boundary),
];

/// Every tag whose pattern occurs in `text`.
pub fn tag_text(text: &str) -> Tags {
    let bytes = text.as_bytes();
    MATCHERS
        .into_iter()
        .filter(|(_, matches)| matches(bytes))
        .fold(Tags::empty(), |tags, (tag, _)| tags | tag)
}

fn is_scheme_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')
}

/// `scheme://x`, where the scheme starts with a letter and has at least two
/// characters (so `C://` is not a URL), and something other than whitespace
/// follows.
fn has_url(text: &[u8]) -> bool {
    let separator = b"://";
    text.windows(separator.len())
        .enumerate()
        .filter(|(_, window)| *window == separator)
        .any(|(at, _)| {
            let scheme_start = text[..at]
                .iter()
                .rposition(|&b| !is_scheme_char(b))
                .map_or(0, |p| p + 1);
            let scheme = &text[scheme_start..at];
            let after = text.get(at + separator.len());
            scheme.len() >= 2
                && scheme[0].is_ascii_alphabetic()
                && after.is_some_and(|b| !b.is_ascii_whitespace())
        })
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// A non-empty local part, `@`, and a domain of dot-separated labels whose
/// last label has at least two letters.
fn has_email(text: &[u8]) -> bool {
    text.iter()
        .enumerate()
        .filter(|(_, &b)| b == b'@')
        .any(|(at, _)| {
            let local_start = text[..at]
                .iter()
                .rposition(|&b| !is_email_local_char(b))
                .map_or(0, |p| p + 1);
            let domain_end = text[at + 1..]
                .iter()
                .position(|&b| !is_domain_char(b))
                .map_or(text.len(), |p| at + 1 + p);
            let domain = &text[at + 1..domain_end];
            let domain = domain.strip_suffix(b".").unwrap_or(domain);
            let labels: Vec<&[u8]> = domain.split(|&b| b == b'.').collect();
            let tld = labels.last().copied().unwrap_or_default();
            local_start < at
                && labels.len() >= 2
                && labels.iter().all(|label| !label.is_empty())
                && tld.len() >= 2
                && tld.iter().all(u8::is_ascii_alphabetic)
        })
}

/// A token of digits and dots that is exactly four components of one to
/// three digits, each at most 255; one trailing dot is allowed.
fn has_ipv4(text: &[u8]) -> bool {
    text.split(|&b| !(b.is_ascii_digit() || b == b'.'))
        .map(|token| token.strip_suffix(b".").unwrap_or(token))
        .any(|token| {
            let parts: Vec<&[u8]> = token.split(|&b| b == b'.').collect();
            parts.len() == 4
                && parts.iter().all(|part| {
                    (1..=3).contains(&part.len())
                        && part.iter().fold(0u32, |n, d| n * 10 + u32::from(d - b'0')) <= 255
                })
        })
}

fn is_path_segment_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'+' | b'@')
}

/// Length of the path segment at the start of `text`.
fn segment_len(text: &[u8]) -> usize {
    text.iter()
        .take_while(|&&b| is_path_segment_char(b))
        .count()
}

/// `/a/b` at the start of a token (start of text, after whitespace or one of
/// `" ' = ( : ,`), `X:\a`, or `\\host\`.
fn has_path(text: &[u8]) -> bool {
    let unix = text.iter().enumerate().any(|(at, &b)| {
        let delimited = at == 0
            || matches!(
                text[at - 1],
                b' ' | b'\t' | b'"' | b'\'' | b'=' | b'(' | b':' | b','
            );
        if b != b'/' || !delimited {
            return false;
        }
        let first = segment_len(&text[at + 1..]);
        let second_at = at + 1 + first;
        first > 0 && text.get(second_at) == Some(&b'/') && segment_len(&text[second_at + 1..]) > 0
    });
    let windows = text.windows(4).any(|w| {
        w[0].is_ascii_alphabetic() && w[1] == b':' && w[2] == b'\\' && is_path_segment_char(w[3])
    });
    let unc = text.windows(3).enumerate().any(|(at, w)| {
        w[0] == b'\\' && w[1] == b'\\' && is_path_segment_char(w[2]) && {
            let host = segment_len(&text[at + 2..]);
            text.get(at + 2 + host) == Some(&b'\\')
        }
    });
    unix || windows || unc
}

/// `8-4-4-4-12` hexadecimal groups not adjacent to further hex digits.
fn has_uuid(text: &[u8]) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    const LEN: usize = 36;
    if text.len() < LEN {
        return false;
    }
    (0..=text.len() - LEN).any(|start| {
        let candidate = &text[start..start + LEN];
        let delimited = (start == 0 || !text[start - 1].is_ascii_hexdigit())
            && !text.get(start + LEN).is_some_and(u8::is_ascii_hexdigit);
        let mut pos = 0;
        let groups = GROUPS.iter().enumerate().all(|(i, &len)| {
            let group = &candidate[pos..pos + len];
            pos += len;
            let dash = i == GROUPS.len() - 1 || candidate[pos] == b'-';
            pos += 1;
            dash && group.iter().all(u8::is_ascii_hexdigit)
        });
        delimited && groups
    })
}

/// `%` followed by optional flags, width, precision and length modifier,
/// then a conversion character. `%%` is not a conversion.
fn has_format(text: &[u8]) -> bool {
    const FLAGS: &[u8] = b"-+ #0'";
    const LENGTHS: &[&[u8]] = &[
        b"hh", b"ll", b"I64", b"I32", b"h", b"l", b"j", b"z", b"t", b"L", b"q",
    ];
    const CONVERSIONS: &[u8] = b"diouxXeEfFgGaAcspn@";
    let mut at = 0;
    while at < text.len() {
        if text[at] != b'%' {
            at += 1;
            continue;
        }
        if text.get(at + 1) == Some(&b'%') {
            at += 2;
            continue;
        }
        let mut pos = at + 1;
        while text.get(pos).is_some_and(|b| FLAGS.contains(b)) {
            pos += 1;
        }
        if text.get(pos) == Some(&b'*') {
            pos += 1;
        } else {
            while text.get(pos).is_some_and(u8::is_ascii_digit) {
                pos += 1;
            }
        }
        if text.get(pos) == Some(&b'.') {
            pos += 1;
            if text.get(pos) == Some(&b'*') {
                pos += 1;
            } else {
                while text.get(pos).is_some_and(u8::is_ascii_digit) {
                    pos += 1;
                }
            }
        }
        if let Some(length) = LENGTHS.iter().find(|l| text[pos..].starts_with(l)) {
            pos += length.len();
        }
        if text.get(pos).is_some_and(|b| CONVERSIONS.contains(b)) {
            return true;
        }
        at += 1;
    }
    false
}

/// A maximal hexadecimal run of 32, 40, 64 or 128 digits in one letter
/// case, containing at least one decimal digit and one letter.
fn has_digest(text: &[u8]) -> bool {
    const LENGTHS: [usize; 4] = [32, 40, 64, 128];
    text.split(|b| !b.is_ascii_hexdigit()).any(|run| {
        let lower = run.iter().all(|b| !b.is_ascii_uppercase());
        let upper = run.iter().all(|b| !b.is_ascii_lowercase());
        LENGTHS.contains(&run.len())
            && (lower || upper)
            && run.iter().any(u8::is_ascii_digit)
            && run.iter().any(u8::is_ascii_alphabetic)
    })
}

/// The whole text is an Itanium name (`_Z` or `__Z` followed by a digit or
/// an uppercase letter) or an MSVC name (`?` with `@@` later).
fn is_mangled(text: &[u8]) -> bool {
    let itanium = text
        .strip_prefix(b"__Z")
        .or_else(|| text.strip_prefix(b"_Z"))
        .and_then(|rest| rest.first())
        .is_some_and(|b| b.is_ascii_digit() || b.is_ascii_uppercase());
    let msvc = text.first() == Some(&b'?') && text.windows(2).any(|w| w == b"@@");
    itanium || msvc
}

/// `-----BEGIN ` followed by an uppercase label and `-----`.
fn has_pem_boundary(text: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN ";
    text.windows(BEGIN.len())
        .enumerate()
        .filter(|(_, w)| *w == BEGIN)
        .any(|(at, _)| {
            let label = &text[at + BEGIN.len()..];
            let label_len = label
                .iter()
                .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b' ')
                .count();
            label_len > 0 && label[label_len..].starts_with(b"-----")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(text: &str) -> Vec<&'static str> {
        tag_text(text).ids().collect()
    }

    #[test]
    fn each_tag_has_positive_and_negative_examples() {
        let cases: &[(&str, &[&str])] = &[
            ("see https://example.invalid/x", &["url"]),
            ("C://not-a-url", &[]),
            ("http:// ", &[]),
            ("mail root@example.invalid now", &["email"]),
            ("user@localhost", &[]),
            ("@example.com", &[]),
            ("connect 192.0.2.1.", &["ipv4"]),
            ("192.0.2.256", &[]),
            ("1.2.3.4.5", &[]),
            ("/usr/lib/libc.so", &["path"]),
            ("PATH=/usr/bin", &["path"]),
            ("/single", &[]),
            ("a/b/c", &[]),
            ("C:\\Windows\\System32", &["path"]),
            ("\\\\server\\share", &["path"]),
            ("{6ba7b810-9dad-11d1-80b4-00c04fd430c8}", &["uuid"]),
            ("6ba7b810-9dad-11d1-80b4-00c04fd430c8a", &[]),
            ("value %d of %s", &["format"]),
            ("%-08.3lf", &["format"]),
            ("%llu", &["format"]),
            ("100%% sure", &[]),
            ("%y", &[]),
            ("d41d8cd98f00b204e9800998ecf8427e", &["digest"]),
            ("00000000000000000000000000000000", &[]),
            ("d41d8cd98f00b204e9800998ecf8427e0", &[]),
            ("_ZN4core3fmt5write17h", &["mangled"]),
            ("__Z3foov", &["mangled"]),
            ("?Foo@Bar@@QAEXXZ", &["mangled"]),
            ("_Zebra", &[]),
            ("-----BEGIN CERTIFICATE-----", &["pem"]),
            ("-----BEGIN certificate-----", &[]),
        ];
        for (text, expected) in cases {
            assert_eq!(tags(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn tags_serialize_as_identifier_lists() {
        let tags = Tags::URL | Tags::PATH;
        assert_eq!(serde_json::to_string(&tags).unwrap(), r#"["url","path"]"#);
        assert_eq!(Tags::from_id("digest"), Some(Tags::DIGEST));
        assert_eq!(Tags::from_id("nope"), None);
    }
}
