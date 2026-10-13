//! The XML data (MSWIM "XML Data"; wimlib `src/xml.c`): a UTF-16LE
//! document, after a byte order mark 0xFEFF, whose `<WIM>` root holds one
//! `<IMAGE INDEX="n">` element per image. This reader takes from it what
//! the listing reports: each image's `<NAME>` and `<WINDOWS><ARCH>`, and
//! whether `<ESD><ENCRYPTED>` marks the resources as encrypted (wimlib
//! `read_wim_xml_data`, which refuses such files). It scans for those
//! elements and does not validate the document.

use super::resource::{self, Reader};
use super::*;
use crate::types::MetadataValue;

/// Largest XML data read. The document holds a few elements per image;
/// the bound is ours.
const MAX_XML: usize = 16 << 20;

/// Longest image name reported, in characters; the bound is ours.
const MAX_NAME: usize = 256;

/// The byte order mark that starts the document (MSWIM).
const BYTE_ORDER_MARK: char = '\u{feff}';

/// Processor architectures of `<WINDOWS><ARCH>` (wimlib `describe_arch`,
/// from the Windows `PROCESSOR_ARCHITECTURE_*` values).
const ARCHITECTURES: [(u32, &str); 6] = [
    (0, "x86"),
    (1, "MIPS"),
    (5, "ARM"),
    (6, "IA-64"),
    (9, "x64"),
    (12, "ARM64"),
];

/// What the XML data says about one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImageInfo {
    /// The `INDEX` attribute, 1-based.
    pub(super) index: u32,
    pub(super) name: Option<String>,
    /// The `<WINDOWS><ARCH>` value.
    pub(super) arch: Option<u32>,
}

/// What the listing uses from the XML data.
#[derive(Debug, Default)]
pub(super) struct XmlInfo {
    pub(super) images: Vec<ImageInfo>,
    pub(super) encrypted: bool,
}

impl XmlInfo {
    /// The information for 1-based image `index`.
    pub(super) fn image(&self, index: u32) -> Option<&ImageInfo> {
        self.images.iter().find(|image| image.index == index)
    }
}

/// Read the XML data; problems become notes and give `None`.
pub(super) fn read(data: &[u8], header: &Header, c: &mut Container<'_>) -> Option<XmlInfo> {
    let resource = header.xml;
    if resource.is_absent() {
        c.notes.push("The WIM has no XML data".to_string());
        return None;
    }
    let Some(size) = usize::try_from(resource.size)
        .ok()
        .filter(|&size| size <= MAX_XML)
    else {
        c.notes.push(format!(
            "XML data of {} B exceeds the {} read limit; not read",
            resource.size,
            size_text(MAX_XML)
        ));
        return None;
    };
    let mut reader = Reader::new(data, header, &[]);
    let bytes = match reader.read_resource(&resource, size) {
        Ok(bytes) => bytes,
        Err(e) => {
            c.notes.push(format!(
                "XML data at 0x{:X} not read: {}",
                resource.offset,
                resource::message(&e)
            ));
            return None;
        }
    };
    let text = utf16_text(&bytes.data);
    let info = parse(&text);
    if info.images.len() != header.image_count as usize {
        c.notes.push(format!(
            "The XML data describes {} and the header counts {}",
            count(info.images.len(), "image", "images"),
            header.image_count
        ));
    }
    for image in &info.images {
        let key = format!("wim_image_{}", image.index);
        if let Some(name) = &image.name {
            c.push_metadata(
                format!("{key}_name"),
                format!("Image {} name", image.index),
                name.as_str(),
            );
        }
        if let Some(arch) = image.arch {
            c.push_metadata(
                format!("{key}_arch"),
                format!("Image {} XML architecture", image.index),
                MetadataValue::String(arch_text(arch)),
            );
        }
    }
    Some(info)
}

/// UTF-16LE text without the byte order mark; unpaired surrogates become
/// replacement characters and an odd last byte is dropped.
fn utf16_text(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let text: String = char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    match text.strip_prefix(BYTE_ORDER_MARK) {
        Some(rest) => rest.to_string(),
        None => text,
    }
}

/// An architecture value with its name.
fn arch_text(arch: u32) -> String {
    match ARCHITECTURES.iter().find(|(value, _)| *value == arch) {
        Some((_, name)) => format!("{arch} ({name})"),
        None => arch.to_string(),
    }
}

/// The images, names and architectures, and the encryption marker.
fn parse(text: &str) -> XmlInfo {
    let mut info = XmlInfo {
        encrypted: element(text, "ESD").is_some_and(|esd| esd.contains("<ENCRYPTED")),
        images: Vec::new(),
    };
    let mut rest = text;
    while let Some(start) = find_start_tag(rest, "IMAGE") {
        let after = &rest[start..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let tag = &after[..tag_end];
        let body_start = tag_end + 1;
        let body_end = after[body_start..]
            .find("</IMAGE>")
            .map_or(after.len(), |end| body_start + end);
        let body = &after[body_start..body_end];
        if let Some(index) = attribute(tag, "INDEX").and_then(|v| v.trim().parse().ok()) {
            info.images.push(ImageInfo {
                index,
                name: element(body, "NAME").map(|name| truncated_name(&unescape(name))),
                arch: element(body, "WINDOWS")
                    .and_then(|windows| element(windows, "ARCH"))
                    .and_then(|arch| arch.trim().parse().ok()),
            });
        }
        // `body_end` is past the start tag, so every pass moves on.
        rest = &after[body_end..];
    }
    info
}

/// The offset of the next `<name` start tag (followed by `>`, `/` or
/// white space, so `<NAME` does not match `<NAMES`).
fn find_start_tag(text: &str, name: &str) -> Option<usize> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(found) = text[from..].find(&open) {
        let at = from + found;
        let next = text[at + open.len()..].chars().next();
        if matches!(next, Some('>' | '/' | ' ' | '\t' | '\r' | '\n')) {
            return Some(at);
        }
        from = at + open.len();
    }
    None
}

/// The content of the first `<name>...</name>` element.
fn element<'t>(text: &'t str, name: &str) -> Option<&'t str> {
    let start = find_start_tag(text, name)?;
    let after = &text[start..];
    let content = after.find('>')? + 1;
    let close = format!("</{name}>");
    let end = after[content..].find(&close)?;
    Some(&after[content..content + end])
}

/// The value of attribute `name` in a start tag, in double or single
/// quotes.
fn attribute<'t>(tag: &'t str, name: &str) -> Option<&'t str> {
    let mut from = 0;
    while let Some(found) = tag[from..].find(name) {
        let at = from + found;
        from = at + name.len();
        let before = tag[..at].chars().next_back();
        if !matches!(before, Some(' ' | '\t' | '\r' | '\n')) {
            continue;
        }
        let rest = tag[from..].trim_start();
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let inner = &value[1..];
        return inner.find(quote).map(|end| &inner[..end]);
    }
    None
}

/// Text with the five predefined entities and numeric character references
/// replaced.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        let Some(semicolon) = after.find(';').filter(|&end| end <= 12) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let entity = &after[1..semicolon];
        let replacement = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = replacement {
            out.push(c);
            rest = &after[semicolon + 1..];
        } else {
            out.push('&');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    out
}

/// A name of at most [`MAX_NAME`] characters, with control characters
/// replaced.
fn truncated_name(name: &str) -> String {
    let mut out: String = name
        .trim()
        .chars()
        .take(MAX_NAME)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if name.trim().chars().count() > MAX_NAME {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn images_names_and_architectures_are_read() {
        let text = utf16(
            "<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX=\"2\"><DIRCOUNT>1</DIRCOUNT>\
             <WINDOWS><ARCH>9</ARCH></WINDOWS><NAME>Pro &amp; Home</NAME></IMAGE>\
             <IMAGE INDEX='1'><NAMES>x</NAMES><NAME>  Setup\u{1}Media </NAME></IMAGE></WIM>",
        );
        let info = parse(&utf16_text(&text));
        assert!(!info.encrypted);
        assert_eq!(
            info.images,
            vec![
                ImageInfo {
                    index: 2,
                    name: Some("Pro & Home".to_string()),
                    arch: Some(9),
                },
                ImageInfo {
                    index: 1,
                    name: Some("Setup Media".to_string()),
                    arch: None,
                },
            ]
        );
        assert_eq!(info.image(1).unwrap().index, 1);
        assert_eq!(arch_text(9), "9 (x64)");
        assert_eq!(arch_text(42), "42");
    }

    #[test]
    fn the_esd_encryption_marker_is_found() {
        let info = parse("<WIM><ESD><ENCRYPTED>1</ENCRYPTED></ESD></WIM>");
        assert!(info.encrypted);
        assert!(!parse("<WIM><ENCRYPTED/></WIM>").encrypted);
    }

    #[test]
    fn entities_and_long_names_are_handled() {
        assert_eq!(unescape("a&lt;b&#x41;&#66;&bogus;&"), "a<bAB&bogus;&");
        let long = "x".repeat(MAX_NAME + 5);
        let name = truncated_name(&long);
        assert_eq!(name.chars().count(), MAX_NAME + 1);
        assert!(name.ends_with('…'));
    }

    #[test]
    fn broken_documents_do_not_panic() {
        for text in [
            "<IMAGE",
            "<IMAGE INDEX=\"1\"",
            "<IMAGE INDEX=\"1\">",
            "<IMAGE INDEX=1><NAME>a",
            "<IMAGE INDEX=\"\u{e9}\"><NAME>\u{e9}</NAME></IMAGE>",
            "&&&;<<<>>>",
        ] {
            let _ = parse(text);
        }
    }
}
