//! tar archives: the POSIX ustar and pax interchange formats and the GNU
//! format.
//!
//! Sources: POSIX.1-2024 `pax` ("ustar Interchange Format" and "pax
//! Interchange Format"); GNU tar 1.35 `src/tar.h` (`struct posix_header`,
//! `OLDGNU_MAGIC`, `struct sparse_header`), `src/create.c`
//! (`write_gnu_long_link`, `to_chars`) and `src/list.c` (base-256
//! numbers); libarchive v3.7.4 `tar.5` and
//! `archive_read_support_format_tar.c` (checksum rules).
//!
//! An archive is a sequence of 512-byte header blocks, each followed by its
//! data padded to whole blocks, and ends with zero blocks. Every header's
//! checksum is verified. Numeric fields are octal ASCII or GNU base-256.
//! GNU long names (`L`) and pax `path` and `size` records apply to the next
//! entry. Regular files (type `0`, NUL or `7`) are the members; sparse files
//! and multivolume continuations hold fragments and are not classified.
//! Archives without a magic (Unix v7) are not recognized.

use super::*;

/// Header and data block size.
const BLOCK_SIZE: usize = 512;

/// One header block.
type Block = [u8; BLOCK_SIZE];

/// Fields of `struct posix_header` (`tar.h`).
const NAME: Field = Field::new(0, 100);
const SIZE: Field = Field::new(124, 12);
const CHECKSUM: Field = Field::new(148, 8);
const TYPEFLAG: usize = 156;
const PREFIX: Field = Field::new(345, 155);

/// POSIX `magic` at 257 (`TMAGIC`, followed by the `version` field), and
/// GNU `OLDGNU_MAGIC`, which spans `magic` and `version`.
const MAGIC_OFFSET: usize = 257;
const USTAR_MAGIC: &[u8; 6] = b"ustar\0";
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";

/// GNU sparse headers: `isextended` in the header (`struct oldgnu_header`)
/// and in each extension block (`struct sparse_header`).
const GNU_IS_EXTENDED: usize = 482;
const SPARSE_BLOCK_IS_EXTENDED: usize = 504;

/// Base-256 numbers (GNU `to_chars`): bit 7 of the first byte marks the
/// encoding, bit 6 is the sign of a two's-complement value.
const BASE256_FLAG: u8 = 0x80;
const BASE256_NEGATIVE: u8 = 0x40;
const BASE256_VALUE_MASK: u8 = 0x3f;

/// Type flags (`tar.h` and POSIX `pax`).
const REGTYPE: u8 = b'0';
const AREGTYPE: u8 = 0;
const LNKTYPE: u8 = b'1';
const SYMTYPE: u8 = b'2';
const CHRTYPE: u8 = b'3';
const BLKTYPE: u8 = b'4';
const DIRTYPE: u8 = b'5';
const FIFOTYPE: u8 = b'6';
const CONTTYPE: u8 = b'7';
const XHDTYPE: u8 = b'x';
const XGLTYPE: u8 = b'g';
const GNUTYPE_LONGNAME: u8 = b'L';
const GNUTYPE_LONGLINK: u8 = b'K';
const GNUTYPE_SPARSE: u8 = b'S';
const GNUTYPE_MULTIVOL: u8 = b'M';

/// pax keywords this parser applies, and the prefix of GNU sparse keys.
const PAX_PATH: &[u8] = b"path";
const PAX_SIZE: &[u8] = b"size";
const PAX_GNU_SPARSE: &[u8] = b"GNU.sparse.";

/// Which magic a header carries; it decides whether `prefix` is a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// POSIX ustar or pax: `ustar\0`.
    Ustar,
    /// GNU: `ustar  \0`; bytes 345 onwards are not `prefix`.
    Gnu,
    /// No magic (v7, or a header written by an unknown tool).
    Unmarked,
}

fn dialect(header: &Block) -> Dialect {
    let magic = &header[MAGIC_OFFSET..MAGIC_OFFSET + GNU_MAGIC.len()];
    if magic == GNU_MAGIC {
        Dialect::Gnu
    } else if magic.starts_with(USTAR_MAGIC) {
        Dialect::Ustar
    } else {
        Dialect::Unmarked
    }
}

/// A tar archive starts with a header that carries a magic and a valid
/// checksum.
pub(super) fn is_tar(data: &[u8]) -> bool {
    let Some(header) = data.get(..BLOCK_SIZE) else {
        return false;
    };
    let header: &Block = header.try_into().expect("slice has exactly one block");
    dialect(header) != Dialect::Unmarked && has_valid_checksum(header)
}

/// Whether `chksum` matches the sum of the 512 header bytes with the field
/// itself counted as spaces, as unsigned bytes (POSIX) or as signed bytes
/// (an old BSD and Solaris bug that libarchive accepts).
fn has_valid_checksum(header: &Block) -> bool {
    let Some(stored) = octal(CHECKSUM.bytes(header)) else {
        return false;
    };
    let field = CHECKSUM.offset..CHECKSUM.offset + CHECKSUM.len;
    let mut unsigned_sum: u64 = 0;
    let mut signed_sum: i64 = 0;
    for (i, &byte) in header.iter().enumerate() {
        let byte = if field.contains(&i) { b' ' } else { byte };
        unsigned_sum += u64::from(byte);
        signed_sum += i64::from(i8::from_ne_bytes([byte]));
    }
    stored == unsigned_sum || i64::try_from(stored) == Ok(signed_sum)
}

/// An octal field: optional leading spaces, octal digits, then only NUL
/// or space. A field without digits is 0 (GNU tar `from_header`).
fn octal(field: &[u8]) -> Option<u64> {
    let start = field.iter().position(|b| *b != b' ').unwrap_or(field.len());
    let rest = &field[start..];
    let digits_len = rest
        .iter()
        .position(|b| !(b'0'..=b'7').contains(b))
        .unwrap_or(rest.len());
    let (digits, terminator) = rest.split_at(digits_len);
    if !terminator.iter().all(|b| matches!(b, 0 | b' ')) {
        return None;
    }
    if digits.is_empty() {
        return Some(0);
    }
    ascii_number(digits, 8)
}

/// A numeric field: octal, or base-256 when bit 7 of the first byte is set
/// (a big-endian number over the rest of the field). Negative base-256
/// values are invalid for every field read here.
fn number(field: &[u8]) -> Option<u64> {
    let (&first, rest) = field.split_first()?;
    if first & BASE256_FLAG == 0 {
        return octal(field);
    }
    if first & BASE256_NEGATIVE != 0 {
        return None;
    }
    rest.iter()
        .try_fold(u64::from(first & BASE256_VALUE_MASK), |value, &byte| {
            value.checked_mul(256)?.checked_add(u64::from(byte))
        })
}

/// The bytes of a NUL-terminated field before the first NUL.
fn until_nul(field: &[u8]) -> &[u8] {
    let len = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..len]
}

/// One header block with its fields decoded.
struct Header {
    /// File offset of the header block.
    offset: usize,
    typeflag: u8,
    dialect: Dialect,
    /// `prefix/name` for ustar headers with a prefix, else `name`.
    name: Vec<u8>,
    /// The `size` field in bytes.
    size: u64,
    /// The `size` field used base-256.
    base256_size: bool,
    /// GNU sparse headers: extension blocks follow (`isextended`).
    is_extended: bool,
}

/// Header block (`struct posix_header`): name (0, 100), mode, uid, gid,
/// size (124, 12), mtime, chksum (148, 8), typeflag (156), linkname, magic
/// (257), version, uname, gname, devmajor, devminor, prefix (345, 155).
fn header(data: &[u8], pos: usize) -> Result<Header> {
    let block: &Block = slice(data, pos, BLOCK_SIZE, "tar header")?
        .try_into()
        .expect("slice has exactly one block");
    if !has_valid_checksum(block) {
        return Err(error(format!(
            "Invalid tar header checksum at 0x{:X}",
            pos + CHECKSUM.offset
        )));
    }
    let size_field = SIZE.bytes(block);
    let size = number(size_field).ok_or_else(|| {
        error(format!(
            "Invalid tar size field at 0x{:X}",
            pos + SIZE.offset
        ))
    })?;
    let dialect = dialect(block);
    let typeflag = block[TYPEFLAG];
    let mut name = Vec::new();
    let prefix = until_nul(PREFIX.bytes(block));
    if dialect == Dialect::Ustar && !prefix.is_empty() {
        name.extend_from_slice(prefix);
        name.push(b'/');
    }
    name.extend_from_slice(until_nul(NAME.bytes(block)));
    Ok(Header {
        offset: pos,
        typeflag,
        dialect,
        name,
        size,
        base256_size: size_field[0] & BASE256_FLAG != 0,
        is_extended: dialect == Dialect::Gnu
            && typeflag == GNUTYPE_SPARSE
            && block[GNU_IS_EXTENDED] != 0,
    })
}

/// Long names and pax records that apply to the next entry.
#[derive(Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    path: Option<Vec<u8>>,
    size: Option<u64>,
    sparse: bool,
}

/// What the walk found, for notes and metadata.
#[derive(Default)]
struct Tally {
    entries: usize,
    files: usize,
    directories: usize,
    links: usize,
    other: usize,
    pax_headers: usize,
    global_headers: usize,
    long_names: usize,
    base256_sizes: usize,
    sparse: NameList,
    continuations: NameList,
}

impl Tally {
    /// Whether a pax extended or global header has been seen, which makes
    /// the archive pax interchange format.
    fn has_pax_headers(&self) -> bool {
        self.pax_headers + self.global_headers > 0
    }
}

/// Parse a tar archive: headers and members up to the end-of-archive zero
/// blocks, then the data after them.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let first = header(data, 0)?;
    let mut c = Container::new(FileFormat::Tar, Layout::Tar.label(), "tar");
    let mut members = Members::default();
    let mut tally = Tally::default();
    let mut pending = Pending::default();
    let mut pos = 0;
    let end = loop {
        let rest = &data[pos..];
        if is_padding(rest) || rest.get(..BLOCK_SIZE).is_some_and(is_zero) {
            break pos;
        }
        let header = header(data, pos)?;
        pos = entry(
            data,
            &header,
            &mut pending,
            &mut tally,
            &mut c,
            &mut members,
        )?;
    };
    let zero_blocks = data[end..]
        .chunks_exact(BLOCK_SIZE)
        .take_while(|block| is_zero(block))
        .count();
    c.consumed = end + zero_blocks * BLOCK_SIZE;
    let format_name = format_name(first.dialect, &tally);
    c.variant = format!("{format_name} archive");
    push_notes(format_name, &tally, zero_blocks, &mut c);
    push_trailing(data, c.consumed, "tar", &mut c)?;
    members.push_notes(&mut c);
    c.push_metadata("tar_entries", "Entries", tally.entries as u64);
    c.push_metadata("tar_regular_files", "Regular files", tally.files as u64);
    Ok(c)
}

fn is_zero(block: &[u8]) -> bool {
    block.iter().all(|b| *b == 0)
}

/// The data of one entry and the file offset after its padding. Meta
/// headers update `pending`; other entries consume it.
fn entry<'a>(
    data: &'a [u8],
    header: &Header,
    pending: &mut Pending,
    tally: &mut Tally,
    c: &mut Container<'a>,
    members: &mut Members,
) -> Result<usize> {
    let mut data_offset = header.offset + BLOCK_SIZE;
    match header.typeflag {
        XHDTYPE | XGLTYPE | GNUTYPE_LONGNAME | GNUTYPE_LONGLINK => {
            let stored = entry_data(data, data_offset, header.size, &header.name)?;
            meta_header(header, stored.contents, data_offset, pending, tally)?;
            return Ok(stored.next);
        }
        GNUTYPE_SPARSE if header.is_extended => {
            data_offset = skip_sparse_extensions(data, data_offset)?;
        }
        _ => {}
    }

    let pending = std::mem::take(pending);
    let name = pending
        .path
        .or(pending.long_name)
        .unwrap_or_else(|| header.name.clone());
    let name = display_name(&name);
    let size = pending.size.unwrap_or(header.size);
    if pending.size.is_none() && header.base256_size {
        tally.base256_sizes += 1;
    }
    tally.entries += 1;
    let is_regular = matches!(header.typeflag, REGTYPE | AREGTYPE | CONTTYPE);
    let stored_size = match header.typeflag {
        // POSIX stores no data for these types, whatever `size` says.
        SYMTYPE | CHRTYPE | BLKTYPE | DIRTYPE | FIFOTYPE => 0,
        // Hard links carry data only in the pax interchange format; ustar
        // and GNU readers ignore their `size`, which some writers fill in
        // (libarchive `archive_read_support_format_tar.c` does the same).
        LNKTYPE if !tally.has_pax_headers() => 0,
        _ => size,
    };
    let stored = entry_data(data, data_offset, stored_size, name.as_bytes())?;
    match header.typeflag {
        // Old archives mark directories as regular files with a trailing
        // slash.
        _ if is_regular && name.ends_with('/') => tally.directories += 1,
        // Sparse files and multivolume continuations hold fragments of a
        // file, so their data is not the file's contents.
        _ if is_regular && pending.sparse => {
            tally.other += 1;
            tally.sparse.push(name);
        }
        _ if is_regular => {
            tally.files += 1;
            if members.has_room(c) {
                members.offer(c, Child::stored(name, data_offset, stored.contents));
            }
        }
        DIRTYPE => tally.directories += 1,
        LNKTYPE | SYMTYPE => tally.links += 1,
        GNUTYPE_SPARSE => {
            tally.other += 1;
            tally.sparse.push(name);
        }
        GNUTYPE_MULTIVOL => {
            tally.other += 1;
            tally.continuations.push(name);
        }
        _ => tally.other += 1,
    }
    Ok(stored.next)
}

/// An entry's data and where the next header starts.
struct EntryData<'a> {
    contents: &'a [u8],
    /// File offset after the data and its padding to whole blocks.
    next: usize,
}

/// The `size` bytes of data at `data_offset` and the offset after their
/// padding to whole blocks.
fn entry_data<'a>(
    data: &'a [u8],
    data_offset: usize,
    size: u64,
    name: &[u8],
) -> Result<EntryData<'a>> {
    let truncated = || {
        error(format!(
            "Truncated tar member `{}` at 0x{data_offset:X} + {size} B",
            display_name(name)
        ))
    };
    let len = usize::try_from(size).map_err(|_| truncated())?;
    let next = data_offset
        .checked_add(len)
        .and_then(|end| align_up(end, BLOCK_SIZE))
        .filter(|next| *next <= data.len())
        .ok_or_else(truncated)?;
    Ok(EntryData {
        contents: &data[data_offset..data_offset + len],
        next,
    })
}

/// Skip the GNU sparse extension blocks after a sparse header; each block
/// says in `isextended` whether another follows.
fn skip_sparse_extensions(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let block = slice(data, pos, BLOCK_SIZE, "tar sparse extension block")?;
        pos += BLOCK_SIZE;
        if block[SPARSE_BLOCK_IS_EXTENDED] == 0 {
            return Ok(pos);
        }
    }
}

/// Apply a pax extended header, a pax global header or a GNU long name.
fn meta_header(
    header: &Header,
    contents: &[u8],
    data_offset: usize,
    pending: &mut Pending,
    tally: &mut Tally,
) -> Result<()> {
    match header.typeflag {
        XHDTYPE => {
            tally.pax_headers += 1;
            let mut size_record = None;
            pax_records(contents, data_offset, |key, value| {
                if key == PAX_PATH {
                    pending.path = Some(value.to_vec());
                } else if key == PAX_SIZE {
                    size_record = Some(value);
                } else if key.starts_with(PAX_GNU_SPARSE) {
                    pending.sparse = true;
                }
            })?;
            if let Some(value) = size_record {
                let size = ascii_number(value, 10).ok_or_else(|| {
                    error(format!(
                        "Invalid pax size record in the extended header at 0x{:X}",
                        header.offset
                    ))
                })?;
                pending.size = Some(size);
            }
        }
        // Global records are checked for framing but not applied: a
        // global `path` or `size` would apply to every later entry.
        XGLTYPE => {
            tally.global_headers += 1;
            pax_records(contents, data_offset, |_, _| {})?;
        }
        GNUTYPE_LONGNAME => {
            tally.long_names += 1;
            pending.long_name = Some(until_nul(contents).to_vec());
        }
        _ => tally.long_names += 1,
    }
    Ok(())
}

/// pax extended header records (POSIX `pax`, "pax Extended Header"):
/// `"%d %s=%s\n"`, where the decimal length counts the whole record.
/// `visit` receives each keyword and value; NUL bytes after the last
/// record are padding. `offset` is the records' file offset, for errors.
fn pax_records<'a>(
    records: &'a [u8],
    offset: usize,
    mut visit: impl FnMut(&'a [u8], &'a [u8]),
) -> Result<()> {
    let mut pos = 0;
    while pos < records.len() && !is_zero(&records[pos..]) {
        let rest = &records[pos..];
        let invalid = || {
            error(format!(
                "Invalid pax extended header record at 0x{:X}",
                offset + pos
            ))
        };
        let digits = rest.iter().position(|b| *b == b' ').ok_or_else(invalid)?;
        let len = ascii_number(&rest[..digits], 10)
            .and_then(|len| usize::try_from(len).ok())
            .filter(|len| *len > digits + 1)
            .ok_or_else(invalid)?;
        let record = rest
            .get(..len)
            .filter(|record| record.ends_with(b"\n"))
            .ok_or_else(invalid)?;
        let body = &record[digits + 1..len - 1];
        let separator = body.iter().position(|b| *b == b'=').ok_or_else(invalid)?;
        visit(&body[..separator], &body[separator + 1..]);
        pos += len;
    }
    Ok(())
}

/// The archive's format name: the first header's dialect, and pax when
/// any pax header was seen.
fn format_name(first: Dialect, tally: &Tally) -> &'static str {
    match first {
        Dialect::Gnu => "GNU tar",
        _ if tally.has_pax_headers() => "pax",
        _ => "POSIX ustar",
    }
}

fn push_notes(format_name: &str, tally: &Tally, zero_blocks: usize, c: &mut Container<'_>) {
    c.notes.push(format!(
        "{format_name} format; {} ({}, {}, {}, {} other); every header checksum verified",
        count(tally.entries, "entry", "entries"),
        count(tally.files, "regular file", "regular files"),
        count(tally.directories, "directory", "directories"),
        count(tally.links, "link", "links"),
        tally.other
    ));
    if tally.pax_headers > 0 {
        c.notes.push(format!(
            "{}; `path` and `size` records applied",
            count(
                tally.pax_headers,
                "pax extended header",
                "pax extended headers"
            )
        ));
    }
    if tally.global_headers > 0 {
        c.notes.push(format!(
            "{}; global records are not applied",
            count(
                tally.global_headers,
                "pax global header",
                "pax global headers"
            )
        ));
    }
    if tally.long_names > 0 {
        c.notes.push(count(
            tally.long_names,
            "GNU long name or link name header",
            "GNU long name or link name headers",
        ));
    }
    if tally.base256_sizes > 0 {
        c.notes.push(format!(
            "{} in GNU base-256 encoding",
            count(tally.base256_sizes, "size", "sizes")
        ));
    }
    if !tally.sparse.is_empty() {
        c.notes.push(format!(
            "Sparse members hold only their data fragments and were not classified: {}",
            tally.sparse
        ));
    }
    if !tally.continuations.is_empty() {
        c.notes.push(format!(
            "Multivolume continuation members were not classified: {}",
            tally.continuations
        ));
    }
    if zero_blocks < 2 {
        c.notes.push(format!(
            "The archive ends with {} instead of 2",
            count(zero_blocks, "zero block", "zero blocks")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_fields_allow_leading_spaces_and_nul_or_space_terminators() {
        assert_eq!(octal(b"0000644\0"), Some(0o644));
        assert_eq!(octal(b"   644 \0"), Some(0o644));
        assert_eq!(octal(b"\0\0\0\0"), Some(0));
        assert_eq!(octal(b"64 4\0"), None);
        assert_eq!(octal(b"0009\0"), None);
        assert_eq!(octal(b"07777777777777777777777"), None);
    }

    #[test]
    fn base256_numbers_are_big_endian_and_never_negative() {
        let mut field = [0u8; 12];
        field[0] = BASE256_FLAG;
        field[8..].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert_eq!(number(&field), Some(0x1234_5678));
        field[0] = BASE256_FLAG | BASE256_NEGATIVE;
        assert_eq!(number(&field), None);
        // More than 64 significant bits overflow.
        field[0] = BASE256_FLAG | 1;
        assert_eq!(number(&field), None);
    }

    #[test]
    fn pax_records_are_length_framed() {
        let records = b"30 mtime=1700000000.123456789\n14 path=a/b.c\n\0\0";
        let mut seen = Vec::new();
        pax_records(records, 0x200, |key, value| seen.push((key, value))).unwrap();
        assert_eq!(
            seen,
            [
                (&b"mtime"[..], &b"1700000000.123456789"[..]),
                (&b"path"[..], &b"a/b.c"[..])
            ]
        );
        let bad_length = b"15 path=a/b.c\n";
        assert!(pax_records(bad_length, 0x200, |_, _| {})
            .unwrap_err()
            .to_string()
            .contains("Invalid pax extended header record at 0x200"));
        assert!(pax_records(b"5 a\n", 0, |_, _| {}).is_err());
        assert!(pax_records(b"x path=a\n", 0, |_, _| {}).is_err());
    }
}
