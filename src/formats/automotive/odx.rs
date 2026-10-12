//! ASAM ODX documents (MCD-2D / ISO 22901-1), FLASH category (ODX-F).
//!
//! The ASAM schemas are not public; the element model follows odxtools
//! 11.7.0 (`flash.py`, `ecumem.py`, `mem.py`, `datablock.py`,
//! `flashdata.py`, `internflashdata.py`, `externflashdata.py`,
//! `dataformatselection.py`, `segment.py`): `ODX/FLASH/ECU-MEMS/ECU-MEM/MEM`
//! holds `DATABLOCKS` (with `FLASHDATA-REF` and `SEGMENTS`) and
//! `FLASHDATAS/FLASHDATA` elements typed `INTERN-FLASHDATA` (inline `DATA`)
//! or `EXTERN-FLASHDATA` (a `DATAFILE` in the PDX). `DATAFORMAT/@SELECTION`
//! is `INTEL-HEX`, `MOTOROLA-S`, `BINARY` (hex text) or `USER-DEFINED`.
//! Nothing in the FLASH model names a CPU.

use super::*;
use xml::Document;

/// `DATAFORMAT/@SELECTION` values.
const INTEL_HEX: &str = "INTEL-HEX";
const MOTOROLA_S: &str = "MOTOROLA-S";
const BINARY: &str = "BINARY";

/// Is `data` an ODX document: an optional XML declaration and comments,
/// then an `ODX` root element?
pub(super) fn is_odx(data: &[u8]) -> bool {
    let text = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let mut rest = skip_whitespace(text);
    loop {
        if rest.starts_with(b"<?") || rest.starts_with(b"<!--") {
            let end: &[u8] = if rest.starts_with(b"<?") {
                b"?>"
            } else {
                b"-->"
            };
            let Some(at) = memchr::memmem::find(rest, end) else {
                return false;
            };
            rest = skip_whitespace(&rest[at + end.len()..]);
            continue;
        }
        return rest.starts_with(b"<ODX")
            && matches!(rest.get(4), Some(b' ' | b'>' | b'\t' | b'\r' | b'\n'));
    }
}

/// `bytes` without leading XML whitespace.
fn skip_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Remove whitespace inside hex record lines, as odxtools does before
/// parsing `INTEL-HEX` and `MOTOROLA-S` data, keeping one record per line.
fn hex_records(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for line in text.lines() {
        let record: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if !record.is_empty() {
            out.extend_from_slice(record.as_bytes());
            out.push(b'\n');
        }
    }
    out
}

/// Decode `BINARY` data: hexadecimal text, whitespace ignored.
fn hex_bytes(text: &str) -> Result<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return Err(error(
            "Invalid ODX BINARY flash data: odd number of hex digits",
        ));
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| error("Invalid ODX BINARY flash data: not hexadecimal"))
        })
        .collect()
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let doc = Document::parse(data)?;
    if doc.root().name != "ODX" {
        return Err(error(format!(
            "Missing ODX root element (found {})",
            doc.root().name
        )));
    }
    let mut c = Container::new(FileFormat::Odx, "ODX", "odx");
    c.consumed = data.len();
    let version = doc
        .root()
        .attribute("MODEL-VERSION")
        .unwrap_or("not stated");
    let Some(flash) = doc.child(0, "FLASH") else {
        let category = doc.nodes[0]
            .children
            .first()
            .map_or("none", |&i| doc.nodes[i].name.as_str());
        c.variant = format!("ODX ({category})");
        c.notes.push(format!(
            "ODX document, model version {version}; category {category} carries no flash data"
        ));
        return Ok(c);
    };
    c.variant = "ODX-F".into();
    let name = doc.child_text(flash, "SHORT-NAME").unwrap_or("unnamed");
    c.notes.push(format!(
        "ODX-F flash document {name}, model version {version}"
    ));
    c.notes
        .push("Nothing in the ODX FLASH model names a CPU; ISA from the flash data".into());

    // FLASHDATA ID -> referencing data blocks and their segment addresses.
    let mut placements: Vec<(String, String)> = Vec::new();
    for block in doc.descendants(flash, "DATABLOCK") {
        let Some(reference) = doc
            .child(block, "FLASHDATA-REF")
            .and_then(|r| doc.nodes[r].attribute("ID-REF"))
        else {
            continue;
        };
        let block_name = doc.child_text(block, "SHORT-NAME").unwrap_or("unnamed");
        let starts: Vec<String> = doc
            .descendants(block, "SEGMENT")
            .into_iter()
            .filter_map(|s| doc.child_text(s, "SOURCE-START-ADDRESS"))
            .map(|a| format!("0x{}", a.to_ascii_uppercase()))
            .collect();
        let detail = if starts.is_empty() {
            format!("data block {block_name}")
        } else {
            format!("data block {block_name}, segments at {}", starts.join(", "))
        };
        placements.push((reference.to_string(), detail));
    }

    let flashdatas = doc.descendants(flash, "FLASHDATA");
    for (i, &node) in flashdatas.iter().enumerate().take(MAX_COMPONENTS) {
        let element = &doc.nodes[node];
        let id = element.attribute("ID").unwrap_or("");
        let kind = element
            .attribute("xsi:type")
            .or_else(|| element.attribute("type"))
            .unwrap_or("FLASHDATA");
        let short_name = doc
            .child_text(node, "SHORT-NAME")
            .map_or_else(|| format!("flash data {}", i + 1), str::to_string);
        let selection = doc
            .child(node, "DATAFORMAT")
            .and_then(|f| doc.nodes[f].attribute("SELECTION"))
            .unwrap_or("USER-DEFINED")
            .to_string();
        let label = format!("{short_name} ({selection})");
        let transformed = doc.child(node, "ENCRYPT-COMPRESS-METHOD").is_some();
        let placement = placements
            .iter()
            .find(|(r, _)| r == id)
            .map_or(String::new(), |(_, d)| format!("; {d}"));
        c.notes.push(format!("{label}: {kind}{placement}"));
        if let Some(file) = doc.child_text(node, "DATAFILE") {
            c.notes.push(format!(
                "{label}: external data file {file} is not part of a standalone ODX document"
            ));
            continue;
        }
        let Some(data_node) = doc.child(node, "DATA") else {
            c.notes.push(format!("{label}: no DATA element"));
            continue;
        };
        let text = &doc.nodes[data_node].text;
        let (offset, stored_size) = doc.nodes[data_node]
            .text_span
            .map_or((0, 0), |(start, end)| (start, end - start));
        let child = if transformed || !matches!(selection.as_str(), INTEL_HEX | MOTOROLA_S | BINARY)
        {
            c.notes.push(format!(
                "{label}: encrypted, compressed or user-defined data; not analyzed"
            ));
            Child::opaque(label, offset, slice(data, offset, stored_size)?)
        } else if selection == BINARY {
            Child::decoded(
                label,
                offset,
                stored_size,
                Cow::Owned(hex_bytes(text)?),
                "ODX hex text",
            )
        } else {
            Child::decoded(
                label,
                offset,
                stored_size,
                Cow::Owned(hex_records(text)),
                "ODX text",
            )
        };
        c.children.push(child);
    }
    if flashdatas.len() > MAX_COMPONENTS {
        c.notes.push(format!(
            "{} further flash data elements were not listed",
            flashdatas.len() - MAX_COMPONENTS
        ));
    }
    let signed = !doc.descendants(flash, "FW-SIGNATURE").is_empty()
        || !doc.descendants(flash, "FW-CHECKSUM").is_empty();
    if signed {
        c.notes
            .push("Firmware signatures and checksums are present but not verified".into());
    }
    Ok(c)
}
