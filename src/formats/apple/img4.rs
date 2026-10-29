//! Image4 (ASN.1 DER): `IMG4`, `IM4P`, `IM4M` and `IM4R`.
//!
//! Layouts, from img4lib `libvfs/vfs_img4.c` (`DERImg4ItemSpecs`,
//! `DERImg4PayloadItemSpecs`, `DERImg4ManifestItemSpecs`,
//! `DERImg4RestoreInfoItemSpecs`, `kbagSpecs`), `PyIMG4` `pyimg4/parser.py`
//! (`IMG4._parse`, `IM4P._parse`, `IM4M._parse`) and img4tool
//! `img4tool/img4tool.cpp` (`printIM4P`):
//!
//! ```text
//! IMG4 ::= SEQUENCE { IA5String "IMG4", IM4P,
//!                     [0] EXPLICIT IM4M OPTIONAL, [1] EXPLICIT IM4R OPTIONAL }
//! IM4P ::= SEQUENCE { IA5String "IM4P", IA5String type, IA5String description,
//!                     OCTET STRING payload, OCTET STRING keybag OPTIONAL,
//!                     SEQUENCE { INTEGER algorithm, INTEGER size } OPTIONAL,
//!                     [0] EXPLICIT SEQUENCE { IA5String "PAYP", SET } OPTIONAL }
//! IM4M ::= SEQUENCE { IA5String "IM4M", INTEGER version,
//!                     SET { [PRIVATE MANB] }, OCTET STRING signature OPTIONAL,
//!                     SEQUENCE certificates OPTIONAL }
//! IM4R ::= SEQUENCE { IA5String "IM4R", SET { properties } }
//! ```
//!
//! A property is a PRIVATE-class constructed element whose high tag number
//! is its four-character code read big-endian; it wraps
//! `SEQUENCE { IA5String code, value }`. `MANB` holds a `MANP` group of
//! manifest-wide properties and one group per image type.
//!
//! The DER reader accepts definite lengths of up to four octets and tag
//! numbers of up to five octets, and every element must lie inside its
//! parent. The schema has a fixed depth, so elements are read level by
//! level without recursion.

use super::*;
use crate::formats::compressed::{self, Codec};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::cmp::Ordering;

/// Universal tags, as first identifier octets.
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const IA5_STRING: u8 = 0x16;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;

/// Context-specific constructed `[0]` and `[1]`.
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_1: u8 = 0xa1;

/// First identifier octet of an Image4 property: PRIVATE class (`11`),
/// constructed (`0x20`) and the high-tag-number marker (`0x1F`).
const PROPERTY: u8 = 0xff;

/// Low five identifier bits that announce a high tag number.
const HIGH_TAG_NUMBER: u8 = 0x1f;

/// A four-character code needs 32 bits: five base-128 octets.
const MAX_TAG_NUMBER_OCTETS: usize = 5;

/// A tag-number octet that only carries the continuation bit is a leading
/// zero, which DER forbids.
const NONMINIMAL_TAG_OCTET: u8 = 0x80;

/// Definite long-form lengths of up to four octets; img4tool
/// (`ASN1DERElement::makeASN1Size`) writes at most `0x84`.
const MAX_LENGTH_OCTETS: usize = 4;

/// The long-form marker without length octets: indefinite length.
const INDEFINITE_LENGTH: u8 = 0x80;

/// INTEGER contents are read as unsigned: at most eight value octets, after
/// an optional leading zero (sign) octet.
const MAX_INTEGER_VALUE_OCTETS: usize = 8;

/// Structure magics: the `IA5String` that opens each structure.
const IMG4_MAGIC: [u8; 4] = *b"IMG4";
const IM4P_MAGIC: [u8; 4] = *b"IM4P";
const IM4M_MAGIC: [u8; 4] = *b"IM4M";
const IM4R_MAGIC: [u8; 4] = *b"IM4R";
const PAYP_MAGIC: [u8; 4] = *b"PAYP";

/// The layout each structure magic opens.
const MAGICS: [([u8; 4], Layout); 4] = [
    (IMG4_MAGIC, Layout::Img4),
    (IM4P_MAGIC, Layout::Im4p),
    (IM4M_MAGIC, Layout::Im4m),
    (IM4R_MAGIC, Layout::Im4r),
];

/// Manifest body, manifest-wide properties, and the identifiers and nonce
/// reported in metadata.
const MANB: [u8; 4] = *b"MANB";
const MANP: [u8; 4] = *b"MANP";
const CHIP: [u8; 4] = *b"CHIP";
const BORD: [u8; 4] = *b"BORD";
const BNCN: [u8; 4] = *b"BNCN";

/// The type xnu `img4/firmware.h` names `KernelCache`.
const KERNELCACHE_TYPE: [u8; 4] = *b"krnl";

/// The only compression algorithm the sources define: img4lib reopens the
/// payload with LZFSE when `deco == 1`, img4tool rejects anything else.
const COMPRESSION_LZFSE: u64 = 1;

/// Keybag types (`PyIMG4` `KeybagType`) and field sizes (img4lib
/// `IOCTL_IMG4_GET_KEYBAG2`, `PyIMG4` `Keybag._parse`).
const KEYBAG_PRODUCTION: u64 = 1;
const KEYBAG_DEVELOPMENT: u64 = 2;
const KEYBAG_IV_SIZE: usize = 16;
const KEYBAG_KEY_SIZE: usize = 32;

/// Longest description or value text shown in notes and metadata (our
/// bound).
const MAX_TEXT_SIZE: usize = 128;

/// Most property or image names listed per group (our bound).
const MAX_LISTED_NAMES: usize = 64;

/// Identifier and length octets of an element.
#[derive(Clone, Copy)]
struct Header {
    /// First identifier octet: class, constructed bit, low tag number.
    identifier: u8,
    /// High tag number (a property's four-character code), or the low five
    /// identifier bits.
    number: u32,
    /// File offset of the contents.
    contents_offset: usize,
    /// Declared contents length in bytes.
    len: usize,
}

/// A DER element in file coordinates.
#[derive(Clone, Copy)]
struct Element<'a> {
    /// First identifier octet.
    identifier: u8,
    /// High tag number, or the low five identifier bits.
    number: u32,
    /// File offset of the identifier octet.
    offset: usize,
    /// File offset of the contents.
    contents_offset: usize,
    /// The contents octets.
    contents: &'a [u8],
}

impl Element<'_> {
    /// File offset just past the element.
    fn end(&self) -> usize {
        self.contents_offset + self.contents.len()
    }
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    data.get(at)
        .copied()
        .ok_or_else(|| error(format!("Truncated DER element header at 0x{at:X}")))
}

/// A high tag number and the octets that encode it.
struct TagNumber {
    /// The tag number.
    number: u32,
    /// Octets the number occupies, in bytes.
    len: usize,
}

/// Base-128 tag-number octets at `at`, most significant first, with the
/// continuation bit set on all but the last. Returns the number and the
/// octets used.
fn tag_number(data: &[u8], at: usize) -> Result<TagNumber> {
    let mut number: u64 = 0;
    for i in 0..MAX_TAG_NUMBER_OCTETS {
        let octet = byte(data, at + i)?;
        if i == 0 && octet == NONMINIMAL_TAG_OCTET {
            return Err(error(format!(
                "Invalid DER tag number at 0x{at:X}: leading zero octet"
            )));
        }
        number = (number << 7) | u64::from(octet & 0x7f);
        if octet & 0x80 == 0 {
            let number = u32::try_from(number).map_err(|_| {
                error(format!(
                    "Unsupported DER tag number at 0x{at:X}: more than 32 bits"
                ))
            })?;
            return Ok(TagNumber { number, len: i + 1 });
        }
    }
    Err(error(format!(
        "Unsupported DER tag number at 0x{at:X}: more than {MAX_TAG_NUMBER_OCTETS} octets"
    )))
}

/// The identifier and length octets at `at`. The contents are not required
/// to be present, so detection can use this on a prefix.
fn read_header(data: &[u8], at: usize) -> Result<Header> {
    let identifier = byte(data, at)?;
    let mut pos = at + 1;
    let number = if identifier & HIGH_TAG_NUMBER == HIGH_TAG_NUMBER {
        let tag = tag_number(data, pos)?;
        pos += tag.len;
        tag.number
    } else {
        u32::from(identifier & HIGH_TAG_NUMBER)
    };
    let first = byte(data, pos)?;
    pos += 1;
    let len = match first.cmp(&INDEFINITE_LENGTH) {
        Ordering::Less => usize::from(first),
        Ordering::Equal => {
            return Err(error(format!("Invalid indefinite DER length at 0x{at:X}")));
        }
        Ordering::Greater => {
            let count = usize::from(first & 0x7f);
            if count > MAX_LENGTH_OCTETS {
                return Err(error(format!(
                    "Unsupported {count}-octet DER length at 0x{at:X}"
                )));
            }
            let octets = slice(data, pos, count)?;
            pos += count;
            // At most four octets, so the value fits a 32-bit `usize`.
            octets
                .iter()
                .fold(0usize, |len, b| (len << 8) | usize::from(*b))
        }
    };
    Ok(Header {
        identifier,
        number,
        contents_offset: pos,
        len,
    })
}

/// The element at `at`, which must end by `limit`, the end of its parent.
fn read_element(data: &[u8], at: usize, limit: usize) -> Result<Element<'_>> {
    let header = read_header(data, at)?;
    let available = limit.saturating_sub(header.contents_offset);
    let contents = header
        .contents_offset
        .checked_add(header.len)
        .filter(|end| *end <= limit)
        .and_then(|end| data.get(header.contents_offset..end))
        .ok_or_else(|| {
            error(format!(
                "Truncated DER element at 0x{at:X}: {} B declared, {available} B available",
                header.len
            ))
        })?;
    Ok(Element {
        identifier: header.identifier,
        number: header.number,
        offset: at,
        contents_offset: header.contents_offset,
        contents,
    })
}

/// The elements that make up a constructed element's contents. Each
/// element takes at least two bytes, so the loop is bounded by the parent.
fn children<'a>(data: &'a [u8], parent: &Element<'a>) -> Result<Vec<Element<'a>>> {
    let mut items = Vec::new();
    let mut pos = parent.contents_offset;
    let end = parent.end();
    while pos < end {
        let item = read_element(data, pos, end)?;
        pos = item.end();
        items.push(item);
    }
    Ok(items)
}

/// `element`, which must carry `identifier`.
fn expect<'a>(element: Element<'a>, identifier: u8, what: &str) -> Result<Element<'a>> {
    if element.identifier == identifier {
        return Ok(element);
    }
    Err(error(format!(
        "Invalid {what} at 0x{:X}: tag 0x{:02X}, expected 0x{identifier:02X}",
        element.offset, element.identifier
    )))
}

fn ia5_string<'a>(element: Element<'a>, what: &str) -> Result<&'a [u8]> {
    Ok(expect(element, IA5_STRING, what)?.contents)
}

/// INTEGER contents as an unsigned big-endian value. img4tool writes no
/// sign octet, and no content octets at all for zero, so an empty INTEGER
/// is zero and a ninth octet is accepted only as a leading zero.
fn integer(element: Element<'_>, what: &str) -> Result<u64> {
    let contents = expect(element, INTEGER, what)?.contents;
    let value = match contents {
        [0, rest @ ..] if rest.len() <= MAX_INTEGER_VALUE_OCTETS => rest,
        _ if contents.len() <= MAX_INTEGER_VALUE_OCTETS => contents,
        _ => {
            return Err(error(format!(
                "Unsupported {what} at 0x{:X}: {} B INTEGER",
                element.offset,
                contents.len()
            )))
        }
    };
    Ok(value
        .iter()
        .fold(0u64, |value, b| (value << 8) | u64::from(*b)))
}

/// The `IA5String` magic that opens a structure.
fn expect_magic(element: Element<'_>, magic: [u8; 4]) -> Result<()> {
    let name = fourcc_text(magic);
    if ia5_string(element, &format!("{name} magic"))? == magic {
        return Ok(());
    }
    Err(error(format!(
        "Missing {name} magic at 0x{:X}",
        element.offset
    )))
}

/// The single element inside an EXPLICIT context tag.
fn explicit<'a>(data: &'a [u8], element: Element<'a>, what: &str) -> Result<Element<'a>> {
    let items = children(data, &element)?;
    let [inner] = items.as_slice() else {
        return Err(error(format!(
            "Invalid {what} at 0x{:X}: expected one element, found {}",
            element.offset,
            items.len()
        )));
    };
    Ok(*inner)
}

/// The outer `SEQUENCE`, followed by nothing but padding.
fn root<'a>(data: &'a [u8], name: &str) -> Result<Element<'a>> {
    let root = expect(read_element(data, 0, data.len())?, SEQUENCE, name)?;
    let trailing = &data[root.end()..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} B after the {name} SEQUENCE at 0x{:X}",
            trailing.len(),
            root.end()
        )));
    }
    Ok(root)
}

/// The Image4 layout named by the `IA5String` that opens the outer
/// `SEQUENCE`, from the identifier and length octets alone.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let outer = read_header(data, 0).ok()?;
    if outer.identifier != SEQUENCE {
        return None;
    }
    let magic = read_header(data, outer.contents_offset).ok()?;
    if magic.identifier != IA5_STRING || magic.len != IM4P_MAGIC.len() {
        return None;
    }
    let name = slice(data, magic.contents_offset, magic.len).ok()?;
    MAGICS
        .iter()
        .find(|(magic, _)| magic.as_slice() == name)
        .map(|(_, layout)| *layout)
}

/// An Image4 property: `[PRIVATE code] SEQUENCE { IA5String code, value }`.
#[derive(Clone, Copy)]
struct Property<'a> {
    fourcc: [u8; 4],
    value: Element<'a>,
}

fn property<'a>(data: &'a [u8], element: Element<'a>) -> Result<Property<'a>> {
    if element.identifier != PROPERTY {
        return Err(error(format!(
            "Invalid Image4 property at 0x{:X}: tag 0x{:02X}, expected a PRIVATE constructed tag",
            element.offset, element.identifier
        )));
    }
    let fourcc = element.number.to_be_bytes();
    let label = fourcc_text(fourcc);
    let body = expect(
        explicit(data, element, &format!("Image4 property {label}"))?,
        SEQUENCE,
        &format!("Image4 property {label}"),
    )?;
    let fields = children(data, &body)?;
    let [name, value] = fields.as_slice() else {
        return Err(error(format!(
            "Invalid Image4 property {label} at 0x{:X}: expected a name and a value",
            element.offset
        )));
    };
    if ia5_string(*name, &format!("Image4 property {label} name"))? != fourcc {
        return Err(error(format!(
            "Invalid Image4 property {label} at 0x{:X}: the name does not repeat the tag",
            element.offset
        )));
    }
    Ok(Property {
        fourcc,
        value: *value,
    })
}

/// The properties that make up a `SET`.
fn properties<'a>(data: &'a [u8], set: Element<'a>, what: &str) -> Result<Vec<Property<'a>>> {
    let set = expect(set, SET, what)?;
    children(data, &set)?
        .into_iter()
        .map(|item| property(data, item))
        .collect()
}

/// Up to [`MAX_LISTED_NAMES`] four-character codes, comma-separated, with a
/// count of the rest.
fn names(fourccs: impl ExactSizeIterator<Item = [u8; 4]>) -> String {
    let total = fourccs.len();
    let listed = fourccs
        .take(MAX_LISTED_NAMES)
        .map(fourcc_text)
        .collect::<Vec<_>>()
        .join(", ");
    if total > MAX_LISTED_NAMES {
        format!("{listed} and {} more", total - MAX_LISTED_NAMES)
    } else {
        listed
    }
}

/// The compression info `SEQUENCE`.
#[derive(Clone, Copy)]
struct Compression {
    /// Algorithm value; 1 is LZFSE.
    algorithm: u64,
    /// Declared decoded size in bytes.
    size: u64,
}

/// Encoded keybag fields; no device-key unwrapping is implied.
struct Keybag<'a> {
    kind: u64,
    iv: &'a [u8],
    key: &'a [u8],
}

const MAX_KEYBAG_TRIALS: usize = 8;
const MAX_KEYBAGS: usize = crate::formats::container::MAX_COMPONENTS;

/// An `IM4P` structure.
struct Im4p<'a> {
    fourcc: [u8; 4],
    description: &'a [u8],
    /// The payload `OCTET STRING`.
    data: Element<'a>,
    /// Keybag types, when the payload is encrypted.
    keybags: Option<Vec<Keybag<'a>>>,
    compression: Option<Compression>,
    /// `PAYP` payload properties.
    properties: Option<Vec<Property<'a>>>,
}

/// Type, description and payload, then the optional keybag, compression
/// info and `PAYP`, which are told apart by tag.
fn im4p<'a>(data: &'a [u8], element: Element<'a>) -> Result<Im4p<'a>> {
    let element = expect(element, SEQUENCE, "IM4P")?;
    let items = children(data, &element)?;
    let [magic, fourcc, description, payload, optional @ ..] = items.as_slice() else {
        return Err(error(format!(
            "Missing IM4P elements at 0x{:X}: expected magic, type, description and payload",
            element.offset
        )));
    };
    expect_magic(*magic, IM4P_MAGIC)?;
    let fourcc: [u8; 4] = ia5_string(*fourcc, "IM4P type")?.try_into().map_err(|_| {
        error(format!(
            "Invalid IM4P type at 0x{:X}: {} B, expected a four-character code",
            fourcc.offset,
            fourcc.contents.len()
        ))
    })?;
    let mut im4p = Im4p {
        fourcc,
        description: ia5_string(*description, "IM4P description")?,
        data: expect(*payload, OCTET_STRING, "IM4P payload")?,
        keybags: None,
        compression: None,
        properties: None,
    };
    for item in optional {
        match item.identifier {
            OCTET_STRING if im4p.keybags.is_none() => im4p.keybags = Some(keybags(data, *item)?),
            SEQUENCE if im4p.compression.is_none() => {
                im4p.compression = Some(compression(data, *item)?);
            }
            CONTEXT_0 if im4p.properties.is_none() => {
                im4p.properties = Some(payload_properties(data, *item)?);
            }
            OCTET_STRING | SEQUENCE | CONTEXT_0 => {
                return Err(error(format!(
                    "Duplicate IM4P element 0x{:02X} at 0x{:X}",
                    item.identifier, item.offset
                )))
            }
            _ => {
                return Err(error(format!(
                    "Unknown IM4P element 0x{:02X} at 0x{:X}",
                    item.identifier, item.offset
                )))
            }
        }
    }
    Ok(im4p)
}

/// Keybag types from the keybag `OCTET STRING`, which holds a complete DER
/// `SEQUENCE OF SEQUENCE { INTEGER type, OCTET STRING iv, OCTET STRING key }`.
fn keybags<'a>(data: &'a [u8], element: Element<'a>) -> Result<Vec<Keybag<'a>>> {
    let list = expect(
        read_element(data, element.contents_offset, element.end())?,
        SEQUENCE,
        "IM4P keybag",
    )?;
    if list.end() != element.end() {
        return Err(error(format!(
            "Invalid IM4P keybag at 0x{:X}: bytes after the keybag SEQUENCE",
            element.offset
        )));
    }
    // Read element boundaries before validating entries, preserving the DER
    // error order while bounding the temporary element list.
    let mut entries = Vec::new();
    let mut pos = list.contents_offset;
    while pos < list.end() {
        if entries.len() >= MAX_KEYBAGS {
            return Err(error(format!(
                "Unsupported IM4P keybag count; limit {MAX_KEYBAGS}"
            )));
        }
        let entry = read_element(data, pos, list.end())?;
        pos = entry.end();
        entries.push(entry);
    }
    let mut bags = Vec::new();
    for entry in entries {
        let entry = expect(entry, SEQUENCE, "IM4P keybag entry")?;
        let fields = children(data, &entry)?;
        let [kind, iv, key] = fields.as_slice() else {
            return Err(error(format!(
                "Invalid IM4P keybag entry at 0x{:X}: expected type, IV and key",
                entry.offset
            )));
        };
        let kind = integer(*kind, "IM4P keybag type")?;
        let iv = expect(*iv, OCTET_STRING, "IM4P keybag IV")?;
        let key = expect(*key, OCTET_STRING, "IM4P keybag key")?;
        if iv.contents.len() != KEYBAG_IV_SIZE || key.contents.len() != KEYBAG_KEY_SIZE {
            return Err(error(format!(
                "Invalid IM4P keybag entry at 0x{:X}: IV {} B and key {} B, expected {KEYBAG_IV_SIZE} B and {KEYBAG_KEY_SIZE} B",
                entry.offset,
                iv.contents.len(),
                key.contents.len()
            )));
        }
        bags.push(Keybag {
            kind,
            iv: iv.contents,
            key: key.contents,
        });
    }
    if bags.is_empty() {
        return Err(error(format!(
            "Invalid IM4P keybag at 0x{:X}: no entries",
            element.offset
        )));
    }
    Ok(bags)
}

fn compression(data: &[u8], element: Element<'_>) -> Result<Compression> {
    let fields = children(data, &element)?;
    let [algorithm, size] = fields.as_slice() else {
        return Err(error(format!(
            "Invalid IM4P compression info at 0x{:X}: expected algorithm and size",
            element.offset
        )));
    };
    Ok(Compression {
        algorithm: integer(*algorithm, "IM4P compression algorithm")?,
        size: integer(*size, "IM4P decoded size")?,
    })
}

/// `[0] EXPLICIT SEQUENCE { IA5String "PAYP", SET { properties } }`.
fn payload_properties<'a>(data: &'a [u8], element: Element<'a>) -> Result<Vec<Property<'a>>> {
    let body = expect(explicit(data, element, "IM4P PAYP")?, SEQUENCE, "IM4P PAYP")?;
    let fields = children(data, &body)?;
    let [magic, set] = fields.as_slice() else {
        return Err(error(format!(
            "Invalid IM4P PAYP at 0x{:X}: expected magic and properties",
            body.offset
        )));
    };
    expect_magic(*magic, PAYP_MAGIC)?;
    properties(data, *set, "IM4P PAYP properties")
}

/// An `IM4M` structure.
struct Manifest<'a> {
    element: Element<'a>,
    version: u64,
    /// `MANP` manifest-wide properties, when present.
    manp: Option<Vec<Property<'a>>>,
    /// Types of the per-image property groups.
    images: Vec<[u8; 4]>,
    signature: Option<Element<'a>>,
    certificates: Option<Element<'a>>,
}

/// Magic, version and the `MANB` body, then the signature and the
/// certificate chain, which an unsigned manifest leaves out.
fn im4m<'a>(data: &'a [u8], element: Element<'a>) -> Result<Manifest<'a>> {
    let element = expect(element, SEQUENCE, "IM4M")?;
    let items = children(data, &element)?;
    let [magic, version, body, signed @ ..] = items.as_slice() else {
        return Err(error(format!(
            "Missing IM4M elements at 0x{:X}: expected magic, version and body",
            element.offset
        )));
    };
    expect_magic(*magic, IM4M_MAGIC)?;
    let version = integer(*version, "IM4M version")?;
    let body_properties = properties(data, *body, "IM4M body")?;
    let [manb] = body_properties.as_slice() else {
        return Err(error(format!(
            "Invalid IM4M body at 0x{:X}: expected one MANB property, found {}",
            body.offset,
            body_properties.len()
        )));
    };
    if manb.fourcc != MANB {
        return Err(error(format!(
            "Missing IM4M MANB property at 0x{:X}",
            body.offset
        )));
    }
    let mut manifest = Manifest {
        element,
        version,
        manp: None,
        images: Vec::new(),
        signature: None,
        certificates: None,
    };
    for group in properties(data, manb.value, "IM4M MANB")? {
        let label = fourcc_text(group.fourcc);
        let members = properties(data, group.value, &format!("IM4M {label} properties"))?;
        if group.fourcc != MANP {
            manifest.images.push(group.fourcc);
        } else if manifest.manp.replace(members).is_some() {
            return Err(error(format!(
                "Duplicate IM4M MANP properties at 0x{:X}",
                group.value.offset
            )));
        }
    }
    match signed {
        [] => {}
        [signature] => {
            manifest.signature = Some(expect(*signature, OCTET_STRING, "IM4M signature")?);
        }
        [signature, certificates] => {
            manifest.signature = Some(expect(*signature, OCTET_STRING, "IM4M signature")?);
            manifest.certificates =
                Some(expect(*certificates, SEQUENCE, "IM4M certificate chain")?);
        }
        [_, _, extra, ..] => {
            return Err(error(format!(
                "Unknown IM4M element 0x{:02X} at 0x{:X}",
                extra.identifier, extra.offset
            )))
        }
    }
    Ok(manifest)
}

/// An `IM4R` structure: magic and a `SET` of properties.
struct RestoreInfo<'a> {
    element: Element<'a>,
    properties: Vec<Property<'a>>,
}

fn im4r<'a>(data: &'a [u8], element: Element<'a>) -> Result<RestoreInfo<'a>> {
    let element = expect(element, SEQUENCE, "IM4R")?;
    let fields = children(data, &element)?;
    let [magic, set] = fields.as_slice() else {
        return Err(error(format!(
            "Invalid IM4R at 0x{:X}: expected magic and properties",
            element.offset
        )));
    };
    expect_magic(*magic, IM4R_MAGIC)?;
    Ok(RestoreInfo {
        element,
        properties: properties(data, *set, "IM4R properties")?,
    })
}

/// What the stored payload turned out to be.
enum Contents {
    /// Not compressed with a codec the payload declares or starts with.
    Stored,
    /// Decoded through `codec`; `note` says what was checked.
    Decoded {
        codec: Codec,
        decoded: compressed::Decoded,
        note: String,
    },
    /// Declared or recognized compression that could not be applied; the
    /// reason.
    Undecodable(String),
}

/// Stored and decoded sizes and the integrity check the decoder verified.
fn decoded_note(codec: Codec, stored: &[u8], decoded: &compressed::Decoded) -> String {
    let check = match decoded.check {
        Some(check) => format!("{check} verified"),
        None => "no integrity check verified".to_string(),
    };
    format!(
        "{}, {} B stored, {} B decoded; {check}",
        codec.name(),
        stored.len(),
        decoded.data.len()
    )
}

/// Decode a payload with compression info. The decoded size must match
/// the declared size, which also bounds the decoder's output.
fn decode_declared(stored: &[u8], info: Compression) -> Contents {
    if info.algorithm != COMPRESSION_LZFSE {
        return Contents::Undecodable(format!(
            "unsupported compression algorithm {}; not decoded",
            info.algorithm
        ));
    }
    let Some(size) = usize::try_from(info.size)
        .ok()
        .filter(|size| *size <= MAX_PAYLOAD)
    else {
        return Contents::Undecodable(format!(
            "compression info declares {} B decoded, beyond the {} MiB extraction limit; not decoded",
            info.size,
            MAX_PAYLOAD >> 20
        ));
    };
    match compressed::decode_limited(Codec::Lzfse, stored, size) {
        Ok(decoded) if decoded.data.len() == size => {
            let note = format!(
                "{}; decoded size matches the compression info",
                decoded_note(Codec::Lzfse, stored, &decoded)
            );
            Contents::Decoded {
                codec: Codec::Lzfse,
                decoded,
                note,
            }
        }
        Ok(decoded) => Contents::Undecodable(format!(
            "LZFSE stream decodes to {} B, compression info declares {size} B; not used",
            decoded.data.len()
        )),
        Err(e) => Contents::Undecodable(format!("does not decode as LZFSE ({e})")),
    }
}

/// Decode a payload without compression info when it starts with a
/// `complzss`/`complzvn` header or an LZFSE block magic, as img4tool
/// (`uncompressIfNeeded`) and img4lib do.
fn decode_recognized(stored: &[u8]) -> Contents {
    let Some(codec) = compressed::sniff(stored) else {
        return match crate::image4::decompress(stored) {
            Some(candidate) => {
                let codec = candidate.codec;
                let decoded = candidate.decoded;
                let note = format!(
                    "Codec trial {}; decoded structure recognized; {}",
                    codec.name(),
                    decoded_note(codec, stored, &decoded)
                );
                Contents::Decoded {
                    codec,
                    decoded,
                    note,
                }
            }
            None => Contents::Stored,
        };
    };
    match compressed::decode(codec, stored) {
        Ok(decoded) => {
            // `sniff` matched the eight-byte `complzss`/`complzvn` signature.
            let note = match codec {
                Codec::Lzss => format!(
                    "{} header; {}",
                    printable(&stored[..8], 8),
                    decoded_note(codec, stored, &decoded)
                ),
                _ => format!(
                    "{}; no compression info, so the decoded size is not declared",
                    decoded_note(codec, stored, &decoded)
                ),
            };
            Contents::Decoded {
                codec,
                decoded,
                note,
            }
        }
        Err(e) => Contents::Undecodable(format!("does not decode as {} ({e})", codec.name())),
    }
}

/// Try the encoded material without claiming it is unwrapped. Ambiguous
/// recognized outputs stay opaque, and declared decoded sizes must match.
fn keybag_trial(
    stored: &[u8],
    keybags: &[Keybag<'_>],
    compression: Option<Compression>,
) -> Result<Option<crate::image4::Trial>> {
    let mut selected = None;
    for bag in keybags.iter().take(MAX_KEYBAG_TRIALS) {
        for mode in [crate::image4::Mode::Cbc, crate::image4::Mode::Ctr] {
            let Ok(candidate) = crate::image4::trial(stored, bag.key, bag.iv, mode) else {
                continue;
            };
            if compression.is_some_and(|info| info.size != candidate.data.len() as u64) {
                continue;
            }
            selected = crate::image4::select_candidate(selected, candidate)?;
        }
    }
    Ok(selected)
}

/// Read payload coordinates and encoded key material without invoking
/// decryption recursively or interpreting manifest authentication.
pub(super) fn info(data: &[u8]) -> Result<Option<Image4Info>> {
    let element = match detect(data) {
        Some(Layout::Im4p) => root(data, "IM4P")?,
        Some(Layout::Img4) => {
            let root = root(data, "IMG4")?;
            let items = children(data, &root)?;
            let [magic, payload, ..] = items.as_slice() else {
                return Err(error("Missing IMG4 payload"));
            };
            expect_magic(*magic, IMG4_MAGIC)?;
            *payload
        }
        _ => return Ok(None),
    };
    let payload = im4p(data, element)?;
    let keybags = payload
        .keybags
        .unwrap_or_default()
        .iter()
        .map(|bag| Image4Keybag {
            class: bag.kind,
            iv: hex::encode_upper(bag.iv),
            key: hex::encode_upper(bag.key),
        })
        .collect();
    Ok(Some(Image4Info {
        label: fourcc_text(payload.fourcc),
        offset: payload.data.contents_offset,
        size: payload.data.contents.len(),
        keybags,
    }))
}

/// Keybag types as text: "2 keybags: production, development".
fn keybag_text(types: &[Keybag<'_>]) -> String {
    let kinds: Vec<String> = types
        .iter()
        .map(|bag| match bag.kind {
            KEYBAG_PRODUCTION => "production".to_string(),
            KEYBAG_DEVELOPMENT => "development".to_string(),
            other => format!("type {other}"),
        })
        .collect();
    let plural = if types.len() == 1 { "" } else { "s" };
    format!("{} keybag{plural}: {}", types.len(), kinds.join(", "))
}

/// The payload child, labelled with the type: opaque when encrypted or
/// not decodable, decoded when compressed, stored otherwise. Bytes after a
/// compressed stream (an appended image) follow as their own child.
fn push_payload_children<'a>(c: &mut Container<'a>, label: &str, im4p: &Im4p<'a>) {
    let offset = im4p.data.contents_offset;
    let stored = im4p.data.contents;
    if let Some(keybags) = &im4p.keybags {
        let trial = keybag_trial(stored, keybags, im4p.compression);
        if let Err(error) = &trial {
            c.notes
                .push(format!("{label} payload: {error}; left opaque"));
        }
        if let Ok(Some(candidate)) = trial {
            let codec_note = candidate
                .codec
                .map_or(String::new(), |codec| format!("; {codec} decoded"));
            c.notes.push(format!("{label} payload: encoded keybag material was usable as supplied; {}{codec_note}; structure recognized; not authenticated", candidate.mode.name()));
            let transform = match (candidate.mode, candidate.codec) {
                (crate::image4::Mode::Cbc, Some(_)) => "AES-CBC + decompression",
                (crate::image4::Mode::Ctr, Some(_)) => "AES-CTR + decompression",
                (mode, None) => mode.name(),
            };
            c.children.push(Child::decoded(
                label,
                offset,
                stored.len(),
                Cow::Owned(candidate.data),
                transform,
            ));
            return;
        }
        c.notes.push(format!(
            "{label} payload: encrypted; keybag present ({}); not decrypted",
            keybag_text(keybags)
        ));
        if let Some(info) = im4p.compression {
            c.notes.push(format!(
                "{label} payload: compression info (algorithm {}, {} B decoded) describes the plaintext",
                info.algorithm, info.size
            ));
        }
        c.notes.push(format!("At most {MAX_KEYBAG_TRIALS} encoded keybags were tried with AES-CBC and AES-CTR; no unique recognized plaintext; device-wrapped keys are not unwrapped"));
        c.children.push(Child::opaque(label, offset, stored));
        return;
    }
    let contents = match im4p.compression {
        Some(info) => decode_declared(stored, info),
        None => decode_recognized(stored),
    };
    match contents {
        Contents::Stored => c.children.push(Child::stored(label, offset, stored)),
        Contents::Undecodable(reason) => {
            c.notes.push(format!("{label} payload: {reason}"));
            c.children.push(Child::opaque(label, offset, stored));
        }
        Contents::Decoded {
            codec,
            decoded,
            note,
        } => {
            c.notes.push(format!("{label} payload: {note}"));
            let stream_size = decoded.consumed.unwrap_or(stored.len()).min(stored.len());
            c.children.push(Child::decoded(
                label,
                offset,
                stream_size,
                Cow::Owned(decoded.data),
                codec.name(),
            ));
            let trailer = &stored[stream_size..];
            if !is_padding(trailer) {
                c.notes.push(format!(
                    "{label} payload: {} B follow the compressed stream at 0x{:X}; listed when they are a recognized format",
                    trailer.len(),
                    offset + stream_size
                ));
                c.children.push(
                    Child::stored(format!("{label} trailer"), offset + stream_size, trailer)
                        .if_recognized(),
                );
            }
        }
    }
}

/// Notes, metadata and the payload child of an `IM4P`.
fn push_payload<'a>(c: &mut Container<'a>, im4p: &Im4p<'a>) {
    let label = fourcc_text(im4p.fourcc);
    let description = printable(im4p.description, MAX_TEXT_SIZE);
    c.notes.push(if description.is_empty() {
        format!("IM4P type {label}; empty description")
    } else {
        format!("IM4P type {label}; description \"{description}\"")
    });
    if im4p.fourcc == KERNELCACHE_TYPE {
        c.notes
            .push("Type krnl is the KernelCache (xnu img4/firmware.h)".to_string());
    }
    c.notes
        .push("Image4 fields name no ISA; the ISA comes from the payload".to_string());
    c.push_metadata("apple_im4p_type", "IM4P type", label.clone());
    c.push_metadata("apple_im4p_description", "IM4P description", description);
    c.push_metadata(
        "apple_im4p_payload_offset",
        "IM4P payload file offset",
        format!("0x{:X}", im4p.data.contents_offset),
    );
    c.push_metadata(
        "apple_im4p_payload_size",
        "IM4P payload stored size (B)",
        im4p.data.contents.len() as u64,
    );
    if let Some(info) = im4p.compression {
        c.push_metadata(
            "apple_im4p_compression_algorithm",
            "IM4P compression algorithm",
            info.algorithm,
        );
        c.push_metadata(
            "apple_im4p_decoded_size",
            "IM4P declared decoded size (B)",
            info.size,
        );
    }
    if let Some(keybags) = &im4p.keybags {
        c.push_metadata("apple_im4p_keybags", "IM4P keybags", keybag_text(keybags));
    }
    if let Some(properties) = &im4p.properties {
        c.notes.push(format!(
            "IM4P payload properties (PAYP): {}; meaning not interpreted",
            names(properties.iter().map(|p| p.fourcc))
        ));
    }
    push_payload_children(c, &label, im4p);
}

/// The `INTEGER` value of a manifest-wide property, as hex.
fn integer_property(properties: &[Property<'_>], fourcc: [u8; 4]) -> Option<String> {
    let property = properties.iter().find(|p| p.fourcc == fourcc)?;
    integer(property.value, "")
        .ok()
        .map(|value| format!("0x{value:X}"))
}

/// Notes and metadata of an `IM4M`. Property values other than the chip and
/// board identifiers (for example the device ECID) are not reported.
fn push_manifest(c: &mut Container<'_>, manifest: &Manifest<'_>) {
    let images = names(manifest.images.iter().copied());
    let signature = match (manifest.signature, manifest.certificates) {
        (Some(signature), Some(certificates)) => format!(
            "signature ({} B) and certificate chain ({} B) present; not verified",
            signature.contents.len(),
            certificates.contents.len()
        ),
        (Some(signature), None) => format!(
            "signature ({} B) present, no certificate chain; not verified",
            signature.contents.len()
        ),
        (None, _) => "no signature".to_string(),
    };
    c.notes.push(format!(
        "IM4M manifest version {}: {}; {signature}",
        manifest.version,
        counted(manifest.images.len(), "image entry", "image entries")
    ));
    c.push_metadata(
        "apple_im4m_offset",
        "IM4M file offset",
        format!("0x{:X}", manifest.element.offset),
    );
    c.push_metadata(
        "apple_im4m_size",
        "IM4M size (B)",
        (manifest.element.end() - manifest.element.offset) as u64,
    );
    c.push_metadata("apple_im4m_version", "IM4M version", manifest.version);
    c.push_metadata("apple_im4m_images", "IM4M image entries", images);
    if let Some(properties) = &manifest.manp {
        c.push_metadata(
            "apple_im4m_properties",
            "IM4M manifest properties (MANP)",
            names(properties.iter().map(|p| p.fourcc)),
        );
        if let Some(chip) = integer_property(properties, CHIP) {
            c.push_metadata("apple_im4m_chip", "Chip ID (CHIP)", chip);
        }
        if let Some(board) = integer_property(properties, BORD) {
            c.push_metadata("apple_im4m_board", "Board ID (BORD)", board);
        }
    } else {
        c.notes
            .push("IM4M manifest has no MANP manifest properties".to_string());
    }
    if let Some(signature) = manifest.signature {
        c.push_metadata(
            "apple_im4m_signature_size",
            "IM4M signature size (B); not verified",
            signature.contents.len() as u64,
        );
    }
    if let Some(certificates) = manifest.certificates {
        c.push_metadata(
            "apple_im4m_certificates_size",
            "IM4M certificate chain size (B); not verified",
            certificates.contents.len() as u64,
        );
    }
}

/// Notes and metadata of an `IM4R`; the boot nonce is shown as stored.
fn push_restore_info(c: &mut Container<'_>, info: &RestoreInfo<'_>) {
    c.notes.push(format!(
        "IM4R restore info: {}",
        names(info.properties.iter().map(|p| p.fourcc))
    ));
    c.push_metadata(
        "apple_im4r_offset",
        "IM4R file offset",
        format!("0x{:X}", info.element.offset),
    );
    let nonce = info
        .properties
        .iter()
        .find(|p| p.fourcc == BNCN && p.value.identifier == OCTET_STRING);
    if let Some(nonce) = nonce {
        let bytes = nonce.value.contents;
        c.push_metadata(
            "apple_im4r_nonce",
            "Boot nonce (BNCN, bytes as stored)",
            hex(&bytes[..bytes.len().min(MAX_TEXT_SIZE)]),
        );
    }
}

/// A standalone `IM4P`.
pub(super) fn parse_im4p(data: &[u8]) -> Result<Container<'_>> {
    let root = root(data, "IM4P")?;
    let im4p = im4p(data, root)?;
    let mut c = Container::new(FileFormat::Im4p, Layout::Im4p.label(), KEY_PREFIX);
    c.consumed = root.end();
    push_payload(&mut c, &im4p);
    Ok(c)
}

/// An `IMG4`: magic and `IM4P`, then the optional `[0]` manifest and `[1]`
/// restore info.
pub(super) fn parse_img4(data: &[u8]) -> Result<Container<'_>> {
    let root = root(data, "IMG4")?;
    let items = children(data, &root)?;
    let [magic, payload, parts @ ..] = items.as_slice() else {
        return Err(error(
            "Missing IMG4 elements at 0x0: expected magic and an IM4P payload",
        ));
    };
    expect_magic(*magic, IMG4_MAGIC)?;
    let im4p = im4p(data, *payload)?;
    let mut manifest = None;
    let mut restore_info = None;
    for part in parts {
        match part.identifier {
            CONTEXT_0 if manifest.is_none() => {
                manifest = Some(im4m(data, explicit(data, *part, "IMG4 manifest")?)?);
            }
            CONTEXT_1 if restore_info.is_none() => {
                restore_info = Some(im4r(data, explicit(data, *part, "IMG4 restore info")?)?);
            }
            CONTEXT_0 | CONTEXT_1 => {
                return Err(error(format!(
                    "Duplicate IMG4 element 0x{:02X} at 0x{:X}",
                    part.identifier, part.offset
                )))
            }
            _ => {
                return Err(error(format!(
                    "Unknown IMG4 element 0x{:02X} at 0x{:X}",
                    part.identifier, part.offset
                )))
            }
        }
    }
    let mut c = Container::new(FileFormat::Img4, Layout::Img4.label(), KEY_PREFIX);
    c.consumed = root.end();
    c.notes.push(format!(
        "Image4 file: IM4P payload; {}; {}",
        if manifest.is_some() {
            "IM4M manifest"
        } else {
            "no IM4M manifest"
        },
        if restore_info.is_some() {
            "IM4R restore info"
        } else {
            "no IM4R restore info"
        }
    ));
    push_payload(&mut c, &im4p);
    if let Some(manifest) = &manifest {
        push_manifest(&mut c, manifest);
    }
    if let Some(info) = &restore_info {
        push_restore_info(&mut c, info);
    }
    Ok(c)
}

/// A standalone `IM4M`; it holds no code.
pub(super) fn parse_im4m(data: &[u8]) -> Result<Container<'_>> {
    let root = root(data, "IM4M")?;
    let manifest = im4m(data, root)?;
    let mut c = Container::new(FileFormat::Img4, Layout::Im4m.label(), KEY_PREFIX);
    c.consumed = root.end();
    c.opaque = true;
    c.notes
        .push("Standalone Image4 manifest (IM4M); metadata only".to_string());
    push_manifest(&mut c, &manifest);
    Ok(c)
}

/// A standalone `IM4R`; it holds no code.
pub(super) fn parse_im4r(data: &[u8]) -> Result<Container<'_>> {
    let root = root(data, "IM4R")?;
    let info = im4r(data, root)?;
    let mut c = Container::new(FileFormat::Img4, Layout::Im4r.label(), KEY_PREFIX);
    c.consumed = root.end();
    c.opaque = true;
    c.notes
        .push("Standalone Image4 restore info (IM4R); metadata only".to_string());
    push_restore_info(&mut c, &info);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths_are_read_and_bounded() {
        let short = [0x04, 0x02, 0xaa, 0xbb];
        let element = read_element(&short, 0, short.len()).unwrap();
        assert_eq!(element.contents, [0xaa, 0xbb]);
        assert_eq!(element.end(), 4);

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[0; 0x80]);
        assert_eq!(
            read_element(&long, 0, long.len()).unwrap().contents.len(),
            0x80
        );
        // The element must end inside its parent.
        assert!(read_element(&long, 0, long.len() - 1).is_err());
    }

    #[test]
    fn indefinite_and_oversized_lengths_are_rejected() {
        assert!(read_header(&[0x30, 0x80], 0).is_err());
        assert!(read_header(&[0x04, 0x85, 1, 0, 0, 0, 0], 0).is_err());
        assert!(read_header(&[0x04, 0x84, 0xff, 0xff, 0xff], 0).is_err());
    }

    #[test]
    fn property_tags_carry_the_fourcc_as_a_high_tag_number() {
        // [PRIVATE 'MANB'] with an empty body, as in the PyIMG4 fixtures.
        let tag = [0xff, 0x84, 0xea, 0x85, 0x9c, 0x42, 0x00];
        let header = read_header(&tag, 0).unwrap();
        assert_eq!(header.identifier, PROPERTY);
        assert_eq!(header.number.to_be_bytes(), MANB);
        assert_eq!(header.contents_offset, 7);
        // A leading 0x80 octet is not minimal; six octets exceed 32 bits.
        assert!(read_header(&[0xff, 0x80, 0x01, 0x00], 0).is_err());
        assert!(read_header(&[0xff, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00], 0).is_err());
        assert!(read_header(&[0xff, 0x9f, 0xff, 0xff, 0xff, 0x7f, 0x00], 0).is_err());
    }

    #[test]
    fn integers_are_unsigned_and_bounded() {
        let element = |contents: &[u8]| {
            let mut der = vec![
                INTEGER,
                u8::try_from(contents.len()).expect("short test integer"),
            ];
            der.extend_from_slice(contents);
            der
        };
        let read = |der: &[u8]| integer(read_element(der, 0, der.len()).unwrap(), "test");
        assert_eq!(read(&element(&[])).unwrap(), 0);
        assert_eq!(
            read(&element(&[0x07, 0x85, 0x80, 0x00])).unwrap(),
            0x0785_8000
        );
        assert_eq!(
            read(&element(&[0, 0xff, 0, 0, 0, 0, 0, 0, 0])).unwrap(),
            0xff << 56
        );
        assert!(read(&element(&[1, 0, 0, 0, 0, 0, 0, 0, 0])).is_err());
    }

    #[test]
    fn detection_reads_only_the_header() {
        // A declared length far beyond the input still identifies the layout.
        let im4p = [
            0x30, 0x84, 0x02, 0x01, 0x40, 0x62, 0x16, 0x04, b'I', b'M', b'4', b'P',
        ];
        assert_eq!(detect(&im4p), Some(Layout::Im4p));
        let im4r = [0x30, 0x21, 0x16, 0x04, b'I', b'M', b'4', b'R'];
        assert_eq!(detect(&im4r), Some(Layout::Im4r));
        assert_eq!(
            detect(&[0x31, 0x06, 0x16, 0x04, b'I', b'M', b'4', b'P']),
            None
        );
        assert_eq!(
            detect(&[0x30, 0x06, 0x16, 0x05, b'I', b'M', b'4', b'P']),
            None
        );
        assert_eq!(detect(&[0x30, 0x06, 0x16, 0x04, b'I', b'M']), None);
    }
}
