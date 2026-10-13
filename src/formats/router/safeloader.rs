//! TP-Link `SafeLoader` factory images (`OpenWrt` firmware-utils
//! `tplink-safeloader.c`: `generate_factory_image`, `put_partitions`,
//! `safeloader_parse_image` and `read_partition_table`).
//!
//! Layout, integers big-endian: the image size including this preamble
//! (0), the MD5 of a fixed salt followed by the bytes from 0x14 (4, 16 B),
//! a 0x1000-byte header (0x14), then the payload at 0x1014: a 0x800-byte
//! `fwup-ptn` partition table of text lines
//! `fwup-ptn <name> base 0x<hex> size 0x<hex>\t\r\n`, ended by a NUL and
//! `0xFF` fill, followed by the partitions. Bases are relative to the
//! payload, so the first partition (base 0x800) starts at 0x1814. The
//! header holds vendor information (a length of at most 0x1000, then text),
//! the string `fw-type:Cloud` and unknown data, or unspecified bytes. Meta
//! partitions (`soft-version`, `support-list`, `extra-para`) start with a
//! data length and a zero word.

use super::*;

/// What `tplink-safeloader` hashes before the image data from 0x14
/// (firmware-utils `0179ab1e`, `tplink-safeloader.c` `md5_salt`, `put_md5`).
const MD5_SALT: [u8; 16] = [
    0x7a, 0x2b, 0x15, 0xed, 0x9b, 0x98, 0x59, 0x6d, 0xe5, 0x04, 0xab, 0x44, 0xac, 0x2a, 0x9f, 0x4e,
];

/// Image size and MD5.
const PREAMBLE_SIZE: usize = 0x14;
const MD5_OFFSET: usize = 4;
const MD5_SIZE: usize = 16;

/// `SAFELOADER_HEADER_SIZE`, and the payload offset of every header type
/// but `?NEW`.
const HEADER_SIZE: usize = 0x1000;
const PAYLOAD_OFFSET: usize = PREAMBLE_SIZE + HEADER_SIZE;

/// `SAFELOADER_PAYLOAD_TABLE_SIZE`.
const TABLE_SIZE: usize = 0x800;

/// Vendor information: its length at 0x14, then the text, within the
/// header.
const VENDOR_TEXT: usize = PREAMBLE_SIZE + 4;
const MAX_VENDOR_LEN: usize = HEADER_SIZE - 4;

/// Header identifiers `safeloader_parse_image` tests at 0x14.
const CLOUD_ID: &[u8] = b"fw-type:Cloud";
const QNEW_ID: &[u8] = b"?NEW";

/// The first token of each partition table line.
const ENTRY_TAG: &str = "fwup-ptn";

/// `MAX_PARTITIONS`, and the name buffer of `read_partition_table` (32 B
/// with the NUL).
const MAX_PARTITIONS: usize = 32;
const MAX_NAME_LEN: usize = 31;

/// Partitions that hold code by the tool's default names
/// (`set_partition_names`), optionally with an `@N` suffix.
const CODE_PARTITIONS: [&str; 2] = ["os-image", "file-system"];

/// Partitions the tool fills with layout and version data.
const META_PARTITIONS: [&str; 4] = [
    "partition-table",
    "soft-version",
    "support-list",
    "extra-para",
];

/// `struct meta_header`: data length and a zero word.
const META_HEADER_SIZE: usize = 8;

/// First byte (`pad1`) of a numeric `soft-version`.
const SOFT_VERSION_NUMERIC_TAG: u8 = 0xff;

/// Notes list at most this many support-list entries, each cut after
/// `MAX_TEXT_CHARS`.
const MAX_LISTED_SUPPORT: usize = 8;
const MAX_TEXT_CHARS: usize = 128;

/// What the 0x1000-byte header holds (`enum safeloader_image_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderType {
    /// Vendor information text.
    Vendor { len: usize },
    /// `fw-type:Cloud` and unknown data.
    Cloud,
    /// Unspecified contents.
    Default,
}

impl HeaderType {
    fn name(self) -> &'static str {
        match self {
            Self::Vendor { .. } => "vendor information",
            Self::Cloud => "cloud",
            Self::Default => "default",
        }
    }
}

/// One `fwup-ptn` line, with the base converted to a file offset.
#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    name: &'a str,
    offset: usize,
    size: usize,
}

/// A structurally valid factory image.
struct Image<'a> {
    size: usize,
    header_type: HeaderType,
    entries: Vec<Entry<'a>>,
}

/// `0x` and one to eight hex digits.
fn hex_value(token: &str) -> Option<u32> {
    let digits = token.strip_prefix("0x")?;
    if !(1..=8).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// One `fwup-ptn` line as written: the base is relative to the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TableLine<'a> {
    name: &'a str,
    base: u32,
    size: u32,
}

/// `fwup-ptn <name> base 0x<hex> size 0x<hex>`, with `\t\r` before the
/// line feed as the tool writes it.
fn parse_entry(line: &[u8], at: usize) -> Result<TableLine<'_>> {
    let invalid = || {
        error(format!(
            "Invalid SafeLoader partition table entry at 0x{at:X}"
        ))
    };
    let text = std::str::from_utf8(line).map_err(|_| invalid())?;
    let tokens: Vec<&str> = text.trim_end_matches(['\t', '\r']).split(' ').collect();
    let [tag, name, "base", base, "size", size] = tokens[..] else {
        return Err(invalid());
    };
    let name_valid =
        (1..=MAX_NAME_LEN).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_graphic());
    if tag != ENTRY_TAG || !name_valid {
        return Err(invalid());
    }
    Ok(TableLine {
        name,
        base: hex_value(base).ok_or_else(invalid)?,
        size: hex_value(size).ok_or_else(invalid)?,
    })
}

/// The `fwup-ptn` lines at the start of `table`, followed only by the NUL
/// and `0xFF` fill the tool writes; each partition after the table and the
/// previous one, and inside the image.
fn parse_table(table: &[u8], image_size: usize) -> Result<Vec<Entry<'_>>> {
    let mut entries: Vec<Entry<'_>> = Vec::new();
    let mut pos = 0;
    let mut next_free = PAYLOAD_OFFSET + TABLE_SIZE;
    while table[pos..].starts_with(ENTRY_TAG.as_bytes()) {
        let at = PAYLOAD_OFFSET + pos;
        if entries.len() == MAX_PARTITIONS {
            return Err(error(format!(
                "Invalid SafeLoader partition table: more than {MAX_PARTITIONS} entries"
            )));
        }
        let line_len = table[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| {
                error(format!(
                    "Truncated SafeLoader partition table entry at 0x{at:X}"
                ))
            })?;
        let TableLine { name, base, size } = parse_entry(&table[pos..pos + line_len], at)?;
        let size = to_usize(size);
        let end = PAYLOAD_OFFSET
            .checked_add(to_usize(base))
            .and_then(|offset| offset.checked_add(size))
            .filter(|&end| end <= image_size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid SafeLoader partition {name}: base 0x{base:X} + {size} B lies outside the {image_size} B image"
                ))
            })?;
        let offset = end - size;
        if offset < next_free {
            return Err(error(format!(
                "Invalid SafeLoader partition {name}: base 0x{base:X} overlaps the table or the previous partition"
            )));
        }
        entries.push(Entry { name, offset, size });
        next_free = end;
        pos += line_len + 1;
    }
    if entries.is_empty() {
        return Err(error(
            "Missing SafeLoader fwup-ptn partition table at 0x1014",
        ));
    }
    if !is_padding(&table[pos..]) {
        return Err(error(format!(
            "Invalid SafeLoader partition table: unexpected bytes at 0x{:X}",
            PAYLOAD_OFFSET + pos
        )));
    }
    Ok(entries)
}

/// The header type, as `safeloader_parse_image` decides it.
fn header_type(data: &[u8]) -> Result<HeaderType> {
    let header = slice(data, PREAMBLE_SIZE, HEADER_SIZE, "SafeLoader header")?;
    if header.starts_with(QNEW_ID) {
        return Err(error(
            "Unsupported SafeLoader ?NEW header: its size field and MD5 are not documented",
        ));
    }
    if header.starts_with(CLOUD_ID) {
        return Ok(HeaderType::Cloud);
    }
    let vendor_len = to_usize(be_u32(header, 0)?);
    if vendor_len > HEADER_SIZE {
        return Ok(HeaderType::Default);
    }
    if vendor_len > MAX_VENDOR_LEN {
        return Err(error(format!(
            "Invalid SafeLoader vendor information length {vendor_len} B: at most {MAX_VENDOR_LEN} B fit"
        )));
    }
    Ok(HeaderType::Vendor { len: vendor_len })
}

/// Validate the preamble, header type, partition table and partitions.
fn read_image(data: &[u8]) -> Result<Image<'_>> {
    let size = to_usize(be_u32(data, 0)?);
    let minimum = PAYLOAD_OFFSET + TABLE_SIZE;
    if size < minimum {
        return Err(error(format!(
            "Invalid SafeLoader image size {size} B: the header and partition table take {minimum} B"
        )));
    }
    if size > data.len() {
        return Err(error(format!(
            "Truncated SafeLoader image: the preamble declares {size} B, {} B present",
            data.len()
        )));
    }
    let header_type = header_type(data)?;
    let table = slice(
        data,
        PAYLOAD_OFFSET,
        TABLE_SIZE,
        "SafeLoader partition table",
    )?;
    let entries = parse_table(table, size)?;
    let last_end = entries
        .last()
        .map_or(minimum, |entry| entry.offset + entry.size);
    if !is_padding(&data[last_end..]) {
        return Err(error(format!(
            "Unexpected data after the last SafeLoader partition at 0x{last_end:X}"
        )));
    }
    Ok(Image {
        size,
        header_type,
        entries,
    })
}

/// Whether `data` is a structurally complete factory image.
pub(super) fn is_valid(data: &[u8]) -> bool {
    read_image(data).is_ok()
}

/// The name without an `@N` suffix.
fn base_name(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// The data of a meta partition, when its header is consistent.
fn meta_data(partition: &[u8]) -> Option<&[u8]> {
    let len = to_usize(be_u32(partition, 0).ok()?);
    let zero = be_u32(partition, 4).ok()?;
    if zero != 0 {
        return None;
    }
    slice(partition, META_HEADER_SIZE, len, "meta partition").ok()
}

/// `soft-version`: numeric (`struct soft_version`: `0xFF`, major, minor,
/// patch, BCD year (2 B), month and day, revision, optional compatibility
/// level) or text.
fn soft_version_text(data: &[u8]) -> String {
    let [SOFT_VERSION_NUMERIC_TAG, major, minor, patch, year_hi, year_lo, month, day, r0, r1, r2, r3, ..] =
        *data
    else {
        let text = data.split(|&b| b == 0).next().unwrap_or(data);
        return display_text(text, MAX_TEXT_CHARS);
    };
    let revision = u32::from_be_bytes([r0, r1, r2, r3]);
    format!(
        "{major}.{minor}.{patch}, built {year_hi:02X}{year_lo:02X}-{month:02X}-{day:02X}, revision {revision}"
    )
}

/// `support-list`: `SupportList:` and one board line each, CR LF separated.
fn support_list_note(data: &[u8]) -> Option<String> {
    let lines: Vec<&[u8]> = data
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty() && *line != b"SupportList:")
        .collect();
    if lines.is_empty() {
        return None;
    }
    let mut listed: Vec<String> = lines
        .iter()
        .take(MAX_LISTED_SUPPORT)
        .map(|line| display_text(line, MAX_TEXT_CHARS))
        .collect();
    if lines.len() > MAX_LISTED_SUPPORT {
        listed.push(format!("{} more", lines.len() - MAX_LISTED_SUPPORT));
    }
    Some(format!(
        "Support list: {}; board names are not ISA evidence",
        listed.join(", ")
    ))
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let image = read_image(data)?;
    let md5 = &data[MD5_OFFSET..MD5_OFFSET + MD5_SIZE];
    let mut hasher = checksum::Md5::new();
    hasher.update(&MD5_SALT);
    hasher.update(&data[PREAMBLE_SIZE..image.size]);
    // A mismatch is noted, not an error: the layout is recognized from its
    // structure, and other vendor tools may salt differently.
    let md5_note = if hasher.finish()[..] == *md5 {
        format!(
            "MD5 {} of the salt and the bytes from 0x14 verified (an integrity check, not authentication)",
            hex_digest(md5)
        )
    } else {
        format!(
            "MD5 {} does not match the tplink-safeloader salted digest of the bytes from 0x14",
            hex_digest(md5)
        )
    };
    let mut c = Container::new(
        FileFormat::TpLink,
        Layout::TpLinkSafeLoader.label(),
        "tplink",
    );
    c.consumed = image.size;
    c.notes.push(format!(
        "TP-Link SafeLoader factory image, {} header; {} partitions in the fwup-ptn table (bases relative to 0x1014); {md5_note}",
        image.header_type.name(),
        image.entries.len()
    ));
    if let HeaderType::Vendor { len } = image.header_type {
        let vendor = &data[VENDOR_TEXT..VENDOR_TEXT + len];
        if !vendor.is_empty() {
            c.notes.push(format!(
                "Vendor information: {}",
                display_text(vendor, MAX_TEXT_CHARS)
            ));
        }
    }
    c.push_metadata(
        "tplink_safeloader_header",
        "Header type",
        image.header_type.name(),
    );
    c.push_metadata("tplink_md5", "Salted MD5", hex_digest(md5));

    let mut extractor = Extractor::default();
    let mut unnamed_roles = Vec::new();
    for entry in &image.entries {
        // `parse_table` placed every partition inside the image.
        let stored = &data[entry.offset..entry.offset + entry.size];
        let label = format!("Partition {}", entry.name);
        let role = base_name(entry.name);
        if CODE_PARTITIONS.contains(&role) {
            c.children
                .push(extractor.component(label, entry.offset, stored, &mut c.notes));
        } else if META_PARTITIONS.contains(&role) {
            meta_notes(&mut c, role, stored);
            c.children.push(Child::opaque(label, entry.offset, stored));
        } else {
            unnamed_roles.push(entry.name);
            c.children
                .push(Child::stored(label, entry.offset, stored).if_recognized());
        }
    }
    if !unnamed_roles.is_empty() {
        c.notes.push(format!(
            "Partitions {} have no role in tplink-safeloader.c; listed only when they are a recognized format",
            unnamed_roles.join(", ")
        ));
    }
    Ok(c)
}

/// Notes and metadata from the `soft-version` and `support-list` meta
/// partitions.
fn meta_notes(c: &mut Container<'_>, role: &str, partition: &[u8]) {
    let Some(contents) = meta_data(partition) else {
        return;
    };
    match role {
        "soft-version" => {
            let version = soft_version_text(contents);
            c.notes.push(format!("Soft version {version}"));
            c.push_metadata("tplink_soft_version", "Soft version", version);
        }
        "support-list" => {
            if let Some(note) = support_list_note(contents) {
                c.notes.push(note);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_follow_the_put_partitions_format() {
        let line = b"fwup-ptn os-image base 0x01000 size 0x113b45\t\r";
        let expected = TableLine {
            name: "os-image",
            base: 0x1000,
            size: 0x0011_3b45,
        };
        assert_eq!(parse_entry(line, 0x1014).unwrap(), expected);
        assert!(parse_entry(b"fwup-ptn os-image base 0x+1 size 0x1", 0).is_err());
        assert!(parse_entry(b"fwup-ptn os-image base 1000 size 0x1", 0).is_err());
        assert!(parse_entry(b"fwup-ptn  base 0x1 size 0x1", 0).is_err());
        assert!(parse_entry(b"fwup-ptn a base 0x1 size 0x1 extra", 0).is_err());
    }

    #[test]
    fn hex_values_need_a_prefix_and_at_most_eight_digits() {
        assert_eq!(hex_value("0x800"), Some(0x800));
        assert_eq!(hex_value("0xFFFFFFFF"), Some(u32::MAX));
        assert_eq!(hex_value("0x100000000"), None);
        assert_eq!(hex_value("0x"), None);
        assert_eq!(hex_value("800"), None);
    }

    #[test]
    fn soft_versions_are_numeric_or_text() {
        let numeric = [0xff, 1, 2, 3, 0x20, 0x26, 0x10, 0x12, 0, 0, 0, 7];
        assert_eq!(
            soft_version_text(&numeric),
            "1.2.3, built 2026-10-12, revision 7"
        );
        assert_eq!(
            soft_version_text(b"soft_ver:1.0.0\n\0"),
            "soft_ver:1.0.0\\x0A"
        );
    }

    #[test]
    fn support_lists_skip_the_title_and_are_bounded() {
        let note = support_list_note(b"SupportList:\r\nCPE210(TP-LINK|UN|N300-2):1.0\r\n").unwrap();
        assert!(
            note.starts_with("Support list: CPE210(TP-LINK|UN|N300-2):1.0;"),
            "{note}"
        );
        let many: Vec<u8> = (0..10).flat_map(|_| b"board\r\n".iter().copied()).collect();
        assert!(support_list_note(&many).unwrap().contains("2 more"));
    }

    #[test]
    fn partition_names_drop_the_index_suffix() {
        assert_eq!(base_name("os-image@1"), "os-image");
        assert_eq!(base_name("file-system"), "file-system");
    }
}
