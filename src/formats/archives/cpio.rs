//! CPIO archives: SVR4 `newc` (`070701`) and `crc` (`070702`), POSIX
//! portable ASCII `odc` (`070707`) and the old binary format (`0x71C7`, in
//! either byte order).
//!
//! Sources: libarchive v3.7.4 `cpio.5` and
//! `archive_read_support_format_cpio.c` (header layouts, padding, the
//! binary format's 32-bit word order), POSIX.1-2024 `pax` ("cpio
//! Interchange Format": `c_magic` `070707`, `TRAILER!!!`) and Linux v6.11
//! `init/initramfs.c` (newc and crc as initramfs reads them, NUL padding
//! between concatenated archives).
//!
//! Each entry is a header, the NUL-terminated name and the data. newc and
//! crc headers are 110 B of 8-digit hex fields, with the name and the data
//! each padded to 4 bytes; odc headers are 76 B of octal fields without
//! padding; binary headers are 26 B of 16-bit words in the archive byte
//! order, 32-bit values as two words with the most significant first, with
//! the name and the data padded to 2 bytes. An archive ends at the
//! `TRAILER!!!` entry. Archives may follow each other after NUL padding, as
//! in Linux initramfs images. The crc format's checksum is the 32-bit sum
//! of the data bytes and is verified for every regular file. Regular files
//! (mode type `0100000`) are the members.

use super::*;

/// ASCII magics at offset 0.
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";
const ODC_MAGIC: &[u8; 6] = b"070707";

/// Old binary `h_magic`: octal 070707 as a 16-bit word.
const BINARY_MAGIC: u16 = 0o070_707;

/// Fixed header sizes.
const SVR4_HEADER_SIZE: usize = 110;
const ODC_HEADER_SIZE: usize = 76;
const BINARY_HEADER_SIZE: usize = 26;

/// newc and crc fields after the magic, 8 hex digits each: `c_ino`,
/// `c_mode`, `c_uid`, `c_gid`, `c_nlink`, `c_mtime`, `c_filesize`,
/// `c_devmajor`, `c_devminor`, `c_rdevmajor`, `c_rdevminor`, `c_namesize`,
/// `c_check`.
const SVR4_FIRST_FIELD: usize = 6;
const SVR4_FIELD_LEN: usize = 8;
const SVR4_MODE: Field = Field::new(14, SVR4_FIELD_LEN);
const SVR4_FILESIZE: Field = Field::new(54, SVR4_FIELD_LEN);
const SVR4_NAMESIZE: Field = Field::new(94, SVR4_FIELD_LEN);
const SVR4_CHECK: Field = Field::new(102, SVR4_FIELD_LEN);

/// odc fields after the magic, octal: `c_dev`, `c_ino`, `c_mode`, `c_uid`,
/// `c_gid`, `c_nlink`, `c_rdev` (6 digits each), `c_mtime` (11),
/// `c_namesize` (6), `c_filesize` (11).
const ODC_FIELDS: [Field; 10] = [
    Field::new(6, 6),
    Field::new(12, 6),
    ODC_MODE,
    Field::new(24, 6),
    Field::new(30, 6),
    Field::new(36, 6),
    Field::new(42, 6),
    Field::new(48, 11),
    ODC_NAMESIZE,
    ODC_FILESIZE,
];
const ODC_MODE: Field = Field::new(18, 6);
const ODC_NAMESIZE: Field = Field::new(59, 6);
const ODC_FILESIZE: Field = Field::new(65, 11);

/// Old binary 16-bit word offsets: `h_mode`, `h_namesize`, and the two
/// words of `h_filesize`.
const BINARY_MODE: usize = 6;
const BINARY_NAMESIZE: usize = 20;
const BINARY_FILESIZE: usize = 22;

/// Name and data alignment.
const SVR4_ALIGNMENT: usize = 4;
const BINARY_ALIGNMENT: usize = 2;

/// The name of the entry that ends an archive.
const TRAILER: &[u8] = b"TRAILER!!!";

/// File type bits of `c_mode` (POSIX `<sys/stat.h>` values).
const MODE_TYPE_MASK: u32 = 0o170_000;
const MODE_REGULAR: u32 = 0o100_000;
const MODE_DIRECTORY: u32 = 0o040_000;
const MODE_SYMLINK: u32 = 0o120_000;

/// One CPIO header layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Newc,
    Crc,
    Odc,
    BinaryLe,
    BinaryBe,
}

impl Variant {
    fn layout(self) -> Layout {
        match self {
            Self::Newc => Layout::CpioNewc,
            Self::Crc => Layout::CpioCrc,
            Self::Odc => Layout::CpioOdc,
            Self::BinaryLe => Layout::CpioBinaryLe,
            Self::BinaryBe => Layout::CpioBinaryBe,
        }
    }

    /// Short name for notes.
    fn name(self) -> &'static str {
        match self {
            Self::Newc => "newc",
            Self::Crc => "crc",
            Self::Odc => "odc",
            Self::BinaryLe => "little-endian binary",
            Self::BinaryBe => "big-endian binary",
        }
    }
}

/// The variant whose magic starts `data`.
fn variant_at(data: &[u8]) -> Option<Variant> {
    if data.starts_with(NEWC_MAGIC) {
        Some(Variant::Newc)
    } else if data.starts_with(CRC_MAGIC) {
        Some(Variant::Crc)
    } else if data.starts_with(ODC_MAGIC) {
        Some(Variant::Odc)
    } else if data.starts_with(&BINARY_MAGIC.to_le_bytes()) {
        Some(Variant::BinaryLe)
    } else if data.starts_with(&BINARY_MAGIC.to_be_bytes()) {
        Some(Variant::BinaryBe)
    } else {
        None
    }
}

/// Strong recognition: an ASCII magic and a valid first header and name.
/// The first entry's data is not required, so a truncated archive is
/// recognized and reported as a parse error.
pub(super) fn detect_ascii(data: &[u8]) -> Option<Layout> {
    let variant = variant_at(data)?;
    if matches!(variant, Variant::BinaryLe | Variant::BinaryBe) {
        return None;
    }
    let fields = header(data, 0, variant).ok()?;
    entry_name(data, 0, &fields).ok()?;
    Some(variant.layout())
}

/// Weak recognition of the two-byte binary magic: every entry up to the
/// last trailer is valid, and only padding, further archives or a
/// recognized format follow.
pub(super) fn detect_binary(data: &[u8]) -> Option<Layout> {
    let variant = variant_at(data)?;
    if !matches!(variant, Variant::BinaryLe | Variant::BinaryBe) {
        return None;
    }
    let walk = walk(data, |_, _| {}).ok()?;
    let rest = &data[walk.rest..];
    let complete = is_padding(rest) || container::is_recognized(rest);
    complete.then_some(variant.layout())
}

/// One entry, in file offsets.
struct Entry<'a> {
    /// `c_mode`: file type and permission bits.
    mode: u32,
    /// Name without its terminating NUL.
    name: &'a [u8],
    /// File offset of the data.
    data_offset: usize,
    /// The data: file contents, or a symbolic link's target.
    contents: &'a [u8],
    /// `c_check` of the crc format: the 32-bit sum of the data bytes.
    check: u32,
    /// File offset after the entry and its padding, at most the file size.
    next: usize,
}

/// The fixed header at `pos`.
fn header(data: &[u8], pos: usize, variant: Variant) -> Result<HeaderFields> {
    match variant {
        Variant::Newc | Variant::Crc => svr4_header(data, pos, variant),
        Variant::Odc => odc_header(data, pos),
        Variant::BinaryLe => binary_header(data, pos, true),
        Variant::BinaryBe => binary_header(data, pos, false),
    }
}

/// The header field `field` of the header at `pos`, as digits in `radix`.
fn header_number(header: &[u8], field: Field, radix: u32, pos: usize) -> Result<u64> {
    ascii_number(field.bytes(header), radix).ok_or_else(|| {
        error(format!(
            "Invalid CPIO header field at 0x{:X}",
            pos + field.offset
        ))
    })
}

/// A 64-bit size from a header, as a byte count in memory.
fn byte_count(value: u64, what: &str, pos: usize) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| error(format!("Invalid CPIO {what} 0x{value:X} at 0x{pos:X}")))
}

/// The header values every variant supplies, in bytes.
struct HeaderFields {
    /// Fixed header size.
    header_size: usize,
    /// `c_mode`.
    mode: u32,
    /// Name size, including the terminating NUL.
    namesize: usize,
    /// Data size.
    size: usize,
    /// `c_check` (crc format), else 0.
    check: u32,
    /// Name and data alignment.
    alignment: usize,
}

/// newc and crc header (110 B): magic, then 13 fields of 8 hex digits
/// (`c_mode` at 14, `c_filesize` at 54, `c_namesize` at 94, `c_check` at
/// 102); the name follows, then the data, each padded to 4 bytes.
fn svr4_header(data: &[u8], pos: usize, variant: Variant) -> Result<HeaderFields> {
    let (magic, what) = if variant == Variant::Crc {
        (CRC_MAGIC, "CPIO crc header")
    } else {
        (NEWC_MAGIC, "CPIO newc header")
    };
    let header = slice(data, pos, SVR4_HEADER_SIZE, what)?;
    if !header.starts_with(magic) {
        return Err(error(format!("Missing CPIO magic at 0x{pos:X}")));
    }
    for offset in (SVR4_FIRST_FIELD..SVR4_HEADER_SIZE).step_by(SVR4_FIELD_LEN) {
        header_number(header, Field::new(offset, SVR4_FIELD_LEN), 16, pos)?;
    }
    // Every field is 8 hex digits, so each value fits in 32 bits.
    let hex_field = |field: Field| -> Result<u32> {
        let value = header_number(header, field, 16, pos)?;
        Ok(u32::try_from(value).expect("8 hex digits fit in 32 bits"))
    };
    let fields = HeaderFields {
        header_size: SVR4_HEADER_SIZE,
        mode: hex_field(SVR4_MODE)?,
        namesize: byte_count(hex_field(SVR4_NAMESIZE)?.into(), "name size", pos)?,
        size: byte_count(hex_field(SVR4_FILESIZE)?.into(), "file size", pos)?,
        check: hex_field(SVR4_CHECK)?,
        alignment: SVR4_ALIGNMENT,
    };
    Ok(fields)
}

/// odc header (76 B): magic, then octal fields (`c_mode` at 18,
/// `c_namesize` at 59, `c_filesize` at 65); the name and the data follow
/// without padding.
fn odc_header(data: &[u8], pos: usize) -> Result<HeaderFields> {
    let header = slice(data, pos, ODC_HEADER_SIZE, "CPIO odc header")?;
    if !header.starts_with(ODC_MAGIC) {
        return Err(error(format!("Missing CPIO magic at 0x{pos:X}")));
    }
    for field in ODC_FIELDS {
        header_number(header, field, 8, pos)?;
    }
    let octal_field = |field: Field| header_number(header, field, 8, pos);
    let mode = octal_field(ODC_MODE)?;
    let fields = HeaderFields {
        header_size: ODC_HEADER_SIZE,
        mode: u32::try_from(mode).expect("6 octal digits fit in 32 bits"),
        namesize: byte_count(octal_field(ODC_NAMESIZE)?, "name size", pos)?,
        size: byte_count(octal_field(ODC_FILESIZE)?, "file size", pos)?,
        check: 0,
        alignment: 1,
    };
    Ok(fields)
}

/// Old binary header (26 B) of 16-bit words in the archive byte order:
/// `h_magic`, `h_dev`, `h_ino`, `h_mode` (6), `h_uid`, `h_gid`, `h_nlink`,
/// `h_rdev`, `h_mtime` (two words), `h_namesize` (20), `h_filesize` (22,
/// two words, most significant first); the name and the data follow, each
/// padded to 2 bytes.
fn binary_header(data: &[u8], pos: usize, le: bool) -> Result<HeaderFields> {
    let header = slice(data, pos, BINARY_HEADER_SIZE, "CPIO binary header")?;
    let word = |at: usize| {
        let bytes = [header[at], header[at + 1]];
        if le {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    if word(0) != BINARY_MAGIC {
        return Err(error(format!("Missing CPIO magic at 0x{pos:X}")));
    }
    let size = (u32::from(word(BINARY_FILESIZE)) << 16) | u32::from(word(BINARY_FILESIZE + 2));
    let fields = HeaderFields {
        header_size: BINARY_HEADER_SIZE,
        mode: u32::from(word(BINARY_MODE)),
        namesize: usize::from(word(BINARY_NAMESIZE)),
        size: byte_count(size.into(), "file size", pos)?,
        check: 0,
        alignment: BINARY_ALIGNMENT,
    };
    Ok(fields)
}

/// An entry's name and where its data starts.
struct EntryName<'a> {
    /// Name without its terminating NUL.
    name: &'a [u8],
    /// File offset of the data, after the name's padding.
    data_offset: usize,
}

/// The name of the entry whose header is at `pos`: `namesize` bytes (with
/// the NUL) after the header, padded to `alignment` counted from the start
/// of the file, as Linux initramfs counts it.
fn entry_name<'a>(data: &'a [u8], pos: usize, fields: &HeaderFields) -> Result<EntryName<'a>> {
    let namesize = fields.namesize;
    let name_offset = pos + fields.header_size;
    let stored_name = slice(data, name_offset, namesize, "CPIO entry name")?;
    let Some((&0, name)) = stored_name.split_last() else {
        return Err(error(format!(
            "Invalid CPIO name size {namesize} at 0x{pos:X}: the name must end with NUL"
        )));
    };
    let data_offset = align_up(name_offset + namesize, fields.alignment)
        .ok_or_else(|| error(format!("Invalid CPIO name size {namesize} at 0x{pos:X}")))?;
    Ok(EntryName { name, data_offset })
}

/// The entry whose header is at `pos`: header, name, then `size` bytes of
/// data padded like the name. Padding after the final data may be cut off
/// by the end of the file.
fn entry(data: &[u8], pos: usize, variant: Variant) -> Result<Entry<'_>> {
    let fields = header(data, pos, variant)?;
    let EntryName { name, data_offset } = entry_name(data, pos, &fields)?;
    let contents = slice(data, data_offset, fields.size, "CPIO member data")?;
    let data_end = data_offset + fields.size;
    let next = align_up(data_end, fields.alignment)
        .unwrap_or(data_end)
        .min(data.len());
    Ok(Entry {
        mode: fields.mode,
        name,
        data_offset,
        contents,
        check: fields.check,
        next,
    })
}

/// Where the concatenated archives at the start of `data` end.
struct Walk {
    /// Archive count.
    archives: usize,
    /// Variants in order of first use.
    variants: Vec<Variant>,
    /// File offset after the last archive's trailer entry.
    end: usize,
    /// File offset of the first non-NUL byte after it, or the file size.
    rest: usize,
}

/// Walk every entry of the archives at the start of `data`, calling `visit`
/// for each entry before a trailer. After a trailer, NUL bytes are skipped
/// and another archive continues the walk when a CPIO magic follows.
fn walk<'a>(data: &'a [u8], mut visit: impl FnMut(Variant, &Entry<'a>)) -> Result<Walk> {
    let mut pos = 0;
    let mut walk = Walk {
        archives: 0,
        variants: Vec::new(),
        end: 0,
        rest: 0,
    };
    loop {
        let variant = variant_at(&data[pos..])
            .ok_or_else(|| error(format!("Missing CPIO magic at 0x{pos:X}")))?;
        if !walk.variants.contains(&variant) {
            walk.variants.push(variant);
        }
        loop {
            let entry = entry(data, pos, variant)?;
            pos = entry.next;
            if entry.name == TRAILER {
                break;
            }
            visit(variant, &entry);
        }
        walk.archives += 1;
        walk.end = pos;
        walk.rest = data[pos..]
            .iter()
            .position(|b| *b != 0)
            .map_or(data.len(), |skipped| pos + skipped);
        if variant_at(&data[walk.rest..]).is_none() {
            return Ok(walk);
        }
        pos = walk.rest;
    }
}

/// What the walk found, for notes and metadata.
#[derive(Default)]
struct Tally {
    entries: usize,
    files: usize,
    directories: usize,
    symlinks: usize,
    other: usize,
    /// Regular files with data in crc archives.
    checked: usize,
    checksums_verified: usize,
    checksum_failed: NameList,
}

/// Parse concatenated CPIO archives that start with `layout`.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    if variant_at(data).map(Variant::layout) != Some(layout) {
        return Err(error("Missing CPIO magic at 0x0"));
    }
    let mut c = Container::new(FileFormat::Cpio, layout.label(), "cpio");
    let mut members = Members::default();
    let mut tally = Tally::default();
    let walk = walk(data, |variant, entry| {
        record(variant, entry, &mut tally, &mut c, &mut members);
    })?;
    c.consumed = walk.end;
    push_notes(&walk, &tally, &mut c);
    push_trailing(data, walk.rest, "CPIO", &mut c)?;
    members.push_notes(&mut c);
    c.push_metadata("cpio_entries", "Entries", tally.entries as u64);
    c.push_metadata("cpio_archives", "Archives", walk.archives as u64);
    if walk.variants.contains(&Variant::Crc) {
        c.push_metadata(
            "cpio_checksums_verified",
            "Data checksums verified",
            tally.checksums_verified as u64,
        );
    }
    Ok(c)
}

/// Count one entry; verify and offer a regular file.
fn record<'a>(
    variant: Variant,
    entry: &Entry<'a>,
    tally: &mut Tally,
    c: &mut Container<'a>,
    members: &mut Members,
) {
    tally.entries += 1;
    match entry.mode & MODE_TYPE_MASK {
        MODE_REGULAR => {}
        MODE_DIRECTORY => {
            tally.directories += 1;
            return;
        }
        MODE_SYMLINK => {
            tally.symlinks += 1;
            return;
        }
        _ => {
            tally.other += 1;
            return;
        }
    }
    tally.files += 1;
    let name = display_name(entry.name);
    // Hard links other than the one that carries the data have no data.
    if entry.contents.is_empty() {
        return;
    }
    if variant == Variant::Crc {
        tally.checked += 1;
        let sum = entry
            .contents
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        if sum != entry.check {
            tally.checksum_failed.push(format!(
                "{name} (sum 0x{sum:08X}, header 0x{:08X})",
                entry.check
            ));
            return;
        }
        tally.checksums_verified += 1;
    }
    if members.has_room(c) {
        members.offer(c, Child::stored(name, entry.data_offset, entry.contents));
    }
}

fn push_notes(walk: &Walk, tally: &Tally, c: &mut Container<'_>) {
    c.notes.push(format!(
        "{} ({}, {}, {}, {} other) before `TRAILER!!!`",
        count(tally.entries, "entry", "entries"),
        count(tally.files, "regular file", "regular files"),
        count(tally.directories, "directory", "directories"),
        count(tally.symlinks, "symbolic link", "symbolic links"),
        tally.other
    ));
    if walk.archives > 1 {
        let variants: Vec<&str> = walk.variants.iter().map(|v| v.name()).collect();
        c.notes.push(format!(
            "{} concatenated archives ({})",
            walk.archives,
            variants.join(", ")
        ));
    }
    if walk.variants.contains(&Variant::Crc) {
        c.notes.push(format!(
            "crc format data checksums verified for {} of {} regular files with data",
            tally.checksums_verified, tally.checked
        ));
    }
    let unchecked: Vec<&str> = walk
        .variants
        .iter()
        .filter(|v| **v != Variant::Crc)
        .map(|v| v.name())
        .collect();
    if !unchecked.is_empty() {
        c.notes.push(format!(
            "{} archives carry no data checksum",
            unchecked.join(", ")
        ));
    }
    if !tally.checksum_failed.is_empty() {
        c.notes.push(format!(
            "Members that failed the crc format checksum were not classified: {}",
            tally.checksum_failed
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A newc entry: header fields in hex, the name with its NUL padded to
    /// 4 bytes, then the data padded to 4 bytes.
    fn newc(name: &str, mode: u32, contents: &[u8]) -> Vec<u8> {
        let namesize = name.len() + 1;
        let mut entry = format!(
            "070701{:08X}{mode:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}\
             {namesize:08X}{:08X}",
            1,
            0,
            0,
            1,
            0,
            contents.len(),
            0,
            0,
            0,
            0,
            0
        )
        .into_bytes();
        entry.extend_from_slice(name.as_bytes());
        entry.push(0);
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry.extend_from_slice(contents);
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry
    }

    #[test]
    fn entries_and_trailers_are_walked_in_order() {
        let mut archive = newc("a", MODE_REGULAR | 0o644, b"abcde");
        archive.extend(newc("TRAILER!!!", 0, b""));
        let mut names = Vec::new();
        let walk = walk(&archive, |_, entry| names.push(entry.name.to_vec())).unwrap();
        assert_eq!(names, [b"a".to_vec()]);
        assert_eq!(walk.archives, 1);
        assert_eq!(walk.end, archive.len());
        assert_eq!(walk.rest, archive.len());
        assert_eq!(detect_ascii(&archive), Some(Layout::CpioNewc));
    }

    #[test]
    fn names_must_end_with_nul_and_fields_must_be_hex() {
        let mut archive = newc("a", MODE_REGULAR, b"");
        let name_at = SVR4_HEADER_SIZE;
        archive[name_at + 1] = b'x';
        let unterminated = entry(&archive, 0, Variant::Newc).err();
        assert!(unterminated
            .expect("a name without NUL is rejected")
            .to_string()
            .contains("the name must end with NUL"));
        let mut archive = newc("a", MODE_REGULAR, b"");
        archive[SVR4_MODE.offset] = b'g';
        let not_hex = entry(&archive, 0, Variant::Newc).err();
        assert!(not_hex
            .expect("a non-hex field is rejected")
            .to_string()
            .contains("Invalid CPIO header field at 0xE"));
        assert_eq!(detect_ascii(&archive), None);
    }

    #[test]
    fn ascii_detection_needs_the_first_header_and_name_but_not_the_data() {
        let archive = newc("a", MODE_REGULAR, b"abcdefgh");
        let name_end = SVR4_HEADER_SIZE + 2;
        assert_eq!(detect_ascii(&archive[..name_end]), Some(Layout::CpioNewc));
        assert_eq!(detect_ascii(&archive[..name_end - 1]), None);
        assert!(entry(&archive[..name_end], 0, Variant::Newc)
            .err()
            .expect("the data is missing")
            .to_string()
            .contains("Truncated CPIO member data at 0x70 + 8 B"));
    }
}
