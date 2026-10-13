//! The payload: a cpio archive of `newc` entries (`070701`; `070702` is
//! read too) or of rpm's stripped entries (`07070X`), usually compressed
//! with the codec `RPMTAG_PAYLOADCOMPRESSOR` names (rpm `lib/cpio.cc`,
//! `lib/rpmfi.cc`, `build/pack.cc`, `lib/rpmte.cc`; LSB 5.0 section
//! 25.2.5).
//!
//! The walk follows rpm's own payload reader (`rpmcpioHeaderRead`) rather
//! than the archive family's CPIO parser, for two reasons: that parser
//! needs a complete archive, while a payload that decodes to more than the
//! extraction limit is decoded as a prefix; and a stripped entry carries
//! only an index into the main header's file table, which supplies the
//! file's name, type and size.
//!
//! Entry layout, with offsets counted from the start of the archive:
//! - `newc`: magic (6), 13 fields of 8 hex digits (`c_mode` at 8,
//!   `c_filesize` at 48, `c_namesize` at 88 after the magic), the name
//!   with its NUL, padding to 4 bytes, the data, padding to 4 bytes.
//! - stripped: magic (6), the file index (8 hex digits), padding to 4
//!   bytes, the data, padding to 4 bytes. A regular file's data is its
//!   header size, except that every member of a hard-link set but the last
//!   has none; a symbolic link's data is its target.
//!
//! Either archive ends with a `newc` entry named `TRAILER!!!` (a stripped
//! index of `ffffffff` also ends it, as rpm reads it).

use super::*;
use std::collections::HashMap;

/// Main header file and payload tags (`rpmtag.h`).
const RPMTAG_FILESIZES: u32 = 1028;
const RPMTAG_FILEMODES: u32 = 1030;
const RPMTAG_FILEDIGESTS: u32 = 1035;
const RPMTAG_FILEFLAGS: u32 = 1037;
const RPMTAG_FILEDEVICES: u32 = 1095;
const RPMTAG_FILEINODES: u32 = 1096;
const RPMTAG_DIRINDEXES: u32 = 1116;
const RPMTAG_BASENAMES: u32 = 1117;
const RPMTAG_DIRNAMES: u32 = 1118;
const RPMTAG_PAYLOADFORMAT: u32 = 1124;
const RPMTAG_PAYLOADCOMPRESSOR: u32 = 1125;
const RPMTAG_PAYLOADFLAGS: u32 = 1126;
const RPMTAG_LONGFILESIZES: u32 = 5008;
const RPMTAG_FILEDIGESTALGO: u32 = 5011;

/// Entry magics (`CPIO_NEWC_MAGIC`, `CPIO_CRC_MAGIC`,
/// `CPIO_STRIPPED_MAGIC`).
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";
const STRIPPED_MAGIC: &[u8; 6] = b"07070X";
const MAGIC_SIZE: usize = 6;

/// `newc` header fields after the magic (`PHYS_HDR_SIZE`): 13 fields of 8
/// hex digits, of which the reader uses these three.
const NEWC_FIELDS_SIZE: usize = 104;
const FIELD_LEN: usize = 8;
const MODE_FIELD: usize = 8;
const FILESIZE_FIELD: usize = 48;
const NAMESIZE_FIELD: usize = 88;

/// The largest `c_namesize` rpm reads (`rpmcpioHeaderRead`).
const MAX_NAME_SIZE: usize = 4096;

/// Names, data and headers are padded to 4 bytes.
const ALIGNMENT: usize = 4;

/// The name of the entry that ends an archive.
const TRAILER: &[u8] = b"TRAILER!!!";

/// A stripped file index that ends the archive: -1 (`rpmcpioHeaderRead`).
const STRIPPED_END: u32 = 0xffff_ffff;

/// File type bits of a mode (POSIX `<sys/stat.h>` values).
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// `RPMFILE_GHOST`: the file is in the header but not in the payload (LSB
/// 5.0 Table 25-11).
const RPMFILE_GHOST: u32 = 1 << 6;

/// Bytes at the start of a file that are checked for a recognized format
/// before the whole file is checked.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// The only payload format rpm writes (`build/pack.cc` `getIOFlags`).
const PAYLOAD_FORMAT_CPIO: &[u8] = b"cpio";

/// Payload compressor names and their codecs (`build/pack.cc`
/// `getIOFlags`; the `rpmio.cc` I/O types `gzdio`, `bzdio`, `xzdio`,
/// `lzdio` and `zstdio`).
const COMPRESSORS: &[(&[u8], Codec)] = &[
    (b"gzip", Codec::Gzip),
    (b"bzip2", Codec::Bzip2),
    (b"xz", Codec::Xz),
    (b"lzma", Codec::Lzma),
    (b"zstd", Codec::Zstd),
];

/// The compressor rpm reads with when the header names none
/// (`rpmtePayload` in `lib/rpmte.cc`).
const DEFAULT_COMPRESSOR: Codec = Codec::Gzip;

/// File digest algorithms (`rpmHashAlgo` in `rpmcrypto.h`).
const FILE_DIGEST_ALGORITHMS: &[(u64, &str)] = &[
    (1, "MD5"),
    (2, "SHA-1"),
    (3, "RIPEMD-160"),
    (5, "MD2"),
    (6, "TIGER-192"),
    (7, "HAVAL-5-160"),
    (8, "SHA-256"),
    (9, "SHA-384"),
    (10, "SHA-512"),
    (11, "SHA-224"),
    (12, "SHA3-256"),
    (14, "SHA3-512"),
];

/// The file digest algorithm when `RPMTAG_FILEDIGESTALGO` is absent
/// (`RPM_HASH_MD5`, `rpmfilesPopulate` in `lib/rpmfi.cc`).
const RPM_HASH_MD5: u64 = 1;

/// How the stored payload is encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Encoding {
    /// Compressed with a supported codec.
    Compressed(Codec),
    /// A cpio archive as stored, read through rpm's gzip path.
    Uncompressed,
    /// A compressor name the crate has no codec for.
    Unsupported(String),
}

/// The decoded (or uncompressed) cpio archive.
#[derive(Debug)]
struct Archive<'a> {
    /// The archive: borrowed when stored uncompressed, owned when decoded.
    bytes: Cow<'a, [u8]>,
    /// The codec that produced `bytes`.
    codec: Option<Codec>,
    /// The whole stream was decoded; false when decoding stopped at
    /// [`MAX_PAYLOAD`].
    complete: bool,
    /// Stored bytes the compressed stream occupied, when known.
    consumed: Option<usize>,
    /// Integrity check the decoder verified.
    check: Option<&'static str>,
}

/// What the payload holds.
#[derive(Debug)]
enum Content<'a> {
    /// The package has no payload bytes.
    Empty,
    /// The payload cannot be read; the reason is noted.
    Opaque(String),
    /// A cpio archive.
    Archive(Archive<'a>),
}

/// The payload as stored and what it holds.
#[derive(Debug)]
pub(super) struct Payload<'a> {
    /// File offset of the stored payload.
    offset: usize,
    /// The stored payload.
    stored: &'a [u8],
    format: Option<&'a [u8]>,
    compressor: Option<&'a [u8]>,
    flags: Option<&'a [u8]>,
    content: Content<'a>,
}

/// Read the payload format and compressor tags and decode the payload.
///
/// # Errors
///
/// A payload tag of the wrong type. A payload that does not decode is not
/// an error: it is listed as opaque.
pub(super) fn read<'a>(data: &'a [u8], main: &Header<'a>, extent: Extent) -> Result<Payload<'a>> {
    let stored = &data[extent.payload..extent.end];
    let format = main.string(RPMTAG_PAYLOADFORMAT)?;
    let compressor = main.string(RPMTAG_PAYLOADCOMPRESSOR)?;
    let flags = main.string(RPMTAG_PAYLOADFLAGS)?;
    let content = match format {
        _ if stored.is_empty() => Content::Empty,
        Some(format) if format != PAYLOAD_FORMAT_CPIO => Content::Opaque(format!(
            "payload format `{}` is not cpio",
            display_text(format)
        )),
        _ => match encoding(compressor, stored) {
            Encoding::Unsupported(name) => {
                Content::Opaque(format!("payload compressor `{name}` is not supported"))
            }
            Encoding::Uncompressed => Content::Archive(Archive {
                bytes: Cow::Borrowed(stored),
                codec: None,
                complete: true,
                consumed: None,
                check: None,
            }),
            Encoding::Compressed(codec) => decode(codec, stored),
        },
    };
    Ok(Payload {
        offset: extent.payload,
        stored,
        format,
        compressor,
        flags,
        content,
    })
}

/// The codec the compressor tag names, or rpm's default gzip. A gzip
/// payload that starts with a cpio entry instead is uncompressed: rpm
/// reads it with zlib's `gzread`, which passes non-gzip data through
/// (zlib 1.3.1 `zlib.h`); `ufdio` packages store their payload that way.
fn encoding(compressor: Option<&[u8]>, stored: &[u8]) -> Encoding {
    let codec = match compressor {
        None => DEFAULT_COMPRESSOR,
        Some(name) => match COMPRESSORS.iter().find(|(known, _)| *known == name) {
            Some(&(_, codec)) => codec,
            None => return Encoding::Unsupported(display_text(name)),
        },
    };
    let is_gzip = compressed::sniff(stored) == Some(Codec::Gzip);
    if codec == Codec::Gzip && !is_gzip && starts_with_entry(stored) {
        return Encoding::Uncompressed;
    }
    Encoding::Compressed(codec)
}

/// Whether `bytes` starts with a cpio entry magic rpm reads.
fn starts_with_entry(bytes: &[u8]) -> bool {
    [NEWC_MAGIC, CRC_MAGIC, STRIPPED_MAGIC]
        .iter()
        .any(|magic| bytes.starts_with(*magic))
}

/// Decode the stored payload whole, or its first [`MAX_PAYLOAD`] bytes
/// when it decodes to more.
fn decode(codec: Codec, stored: &[u8]) -> Content<'static> {
    match compressed::decode(codec, stored) {
        Ok(decoded) => Content::Archive(Archive {
            bytes: Cow::Owned(decoded.data),
            codec: Some(codec),
            complete: true,
            consumed: decoded.consumed,
            check: decoded.check,
        }),
        Err(e) => match compressed::decode_prefix(codec, stored, MAX_PAYLOAD) {
            Ok(prefix) if prefix.len() == MAX_PAYLOAD => Content::Archive(Archive {
                bytes: Cow::Owned(prefix),
                codec: Some(codec),
                complete: false,
                consumed: None,
                check: None,
            }),
            _ => Content::Opaque(format!("it does not decode as {} ({e})", codec.name())),
        },
    }
}

impl<'a> Payload<'a> {
    /// The uncompressed archive, when it was decoded whole.
    pub(super) fn complete_archive(&self) -> Option<&[u8]> {
        match &self.content {
            Content::Archive(archive) if archive.complete => Some(&archive.bytes),
            _ => None,
        }
    }

    /// List the payload's recognized files as children, with notes and
    /// metadata. `declared_size` is the uncompressed size the headers
    /// state.
    ///
    /// # Errors
    ///
    /// A file digest tag of the wrong type.
    pub(super) fn push(
        self,
        main: &Header<'_>,
        declared_size: Option<u64>,
        c: &mut Container<'a>,
    ) -> Result<()> {
        self.push_metadata(c);
        match self.content {
            Content::Empty => c.notes.push("The package has no payload".to_string()),
            Content::Opaque(reason) => {
                c.notes.push(format!(
                    "Payload at 0x{:X} ({}) is listed as opaque: {reason}",
                    self.offset,
                    size_text(self.stored.len())
                ));
                c.children
                    .push(Child::opaque("Payload", self.offset, self.stored));
            }
            Content::Archive(archive) => {
                let placement = Placement {
                    offset: self.offset,
                    stored_size: self.stored.len(),
                };
                push_archive_notes(&archive, placement, self.compressor, declared_size, c);
                c.push_metadata(
                    "rpm_payload_decoded_size",
                    "Payload archive size (B)",
                    archive.bytes.len() as u64,
                );
                list_archive(archive, placement, main, c);
            }
        }
        push_file_digest_note(main, c)
    }

    fn push_metadata(&self, c: &mut Container<'_>) {
        c.push_metadata("rpm_payload_offset", "Payload offset", self.offset as u64);
        c.push_metadata(
            "rpm_payload_size",
            "Payload size (B)",
            self.stored.len() as u64,
        );
        let tags = [
            ("rpm_payload_format", "Payload format", self.format),
            (
                "rpm_payload_compressor",
                "Payload compressor",
                self.compressor,
            ),
            ("rpm_payload_flags", "Payload compression flags", self.flags),
        ];
        for (key, label, value) in tags {
            if let Some(value) = value {
                c.push_metadata(key, label, display_text(value));
            }
        }
    }
}

/// Where the stored payload lies in the file.
#[derive(Debug, Clone, Copy)]
struct Placement {
    /// File offset of the stored payload.
    offset: usize,
    /// Stored payload size.
    stored_size: usize,
}

/// How the archive was stored and decoded.
fn push_archive_notes(
    archive: &Archive<'_>,
    placement: Placement,
    compressor: Option<&[u8]>,
    declared_size: Option<u64>,
    c: &mut Container<'_>,
) {
    let offset = placement.offset;
    let stored = size_text(placement.stored_size);
    let Some(codec) = archive.codec else {
        c.notes.push(format!(
            "Payload at 0x{offset:X}: uncompressed cpio, {stored}; rpm reads it through its gzip \
             path, which passes data that is not gzip through"
        ));
        return;
    };
    let decoded = size_text(archive.bytes.len());
    let default = if compressor.is_none() {
        "; the header names no compressor, so rpm's default gzip applies"
    } else {
        ""
    };
    if !archive.complete {
        c.notes.push(format!(
            "Payload at 0x{offset:X}: {}-compressed cpio, {stored} stored; decoding stopped at \
             the {} extraction limit, so later entries are not listed and no integrity check \
             was verified{default}",
            codec.name(),
            size_text(MAX_PAYLOAD)
        ));
        return;
    }
    let check = match archive.check {
        Some(check) => format!("{check} verified"),
        None => "no integrity check verified".to_string(),
    };
    c.notes.push(format!(
        "Payload at 0x{offset:X}: {}-compressed cpio, {stored} stored, {decoded} decoded; \
         {check}{default}",
        codec.name()
    ));
    let decoded_size = archive.bytes.len() as u64;
    if let Some(declared) = declared_size.filter(|size| *size != decoded_size) {
        c.notes.push(format!(
            "The payload archive is {decoded_size} B; the headers declare {declared} B"
        ));
    }
    if let Some(consumed) = archive.consumed.filter(|n| *n < placement.stored_size) {
        let rest = placement.stored_size - consumed;
        c.notes.push(format!(
            "{} after the compressed payload stream at 0x{:X} are not part of it",
            size_text(rest),
            offset + consumed
        ));
    }
}

/// Walk the archive and list its recognized regular files: stored slices
/// of the input for an uncompressed payload, decoded copies with the
/// stored payload's range otherwise. A file table that cannot resolve
/// stripped entries is noted.
fn list_archive<'a>(
    archive: Archive<'a>,
    placement: Placement,
    main: &Header<'_>,
    c: &mut Container<'a>,
) {
    let table = if archive.bytes.starts_with(STRIPPED_MAGIC) {
        match file_table(main) {
            Ok(table) => Some(table),
            Err(e) => {
                c.notes.push(format!(
                    "The payload uses stripped entries, but the main header's file table cannot \
                     resolve them ({e}); no files are listed"
                ));
                return;
            }
        }
    } else {
        None
    };
    match archive.bytes {
        Cow::Borrowed(bytes) => {
            let listing = walk(bytes, table.as_ref());
            for file in &listing.files {
                c.children.push(
                    Child::stored(
                        file.label.clone(),
                        placement.offset + file.offset,
                        file.contents,
                    )
                    .if_recognized(),
                );
            }
            listing.push_notes(bytes, archive.complete, c);
        }
        Cow::Owned(bytes) => {
            let codec = archive
                .codec
                .expect("an owned archive was decoded by a codec");
            let listing = walk(&bytes, table.as_ref());
            for file in &listing.files {
                c.children.push(
                    Child::decoded(
                        file.label.clone(),
                        placement.offset,
                        placement.stored_size,
                        Cow::Owned(file.contents.to_vec()),
                        codec.name(),
                    )
                    .if_recognized(),
                );
            }
            listing.push_notes(&bytes, archive.complete, c);
        }
    }
}

/// The main header's file arrays, which stripped entries index.
#[derive(Debug)]
struct FileTable<'h> {
    basenames: Vec<&'h [u8]>,
    dirnames: Vec<&'h [u8]>,
    dirindexes: Vec<u32>,
    modes: Vec<u16>,
    /// File sizes in bytes (`RPMTAG_LONGFILESIZES` or `RPMTAG_FILESIZES`).
    sizes: Vec<u64>,
    /// Whether each file's entry carries its contents: false for all but
    /// the last member of a hard-link set.
    carries_contents: Vec<bool>,
}

/// `values` for `tag`, which must hold one value per file.
fn per_file<T>(values: Option<Vec<T>>, tag: &str, files: usize) -> Result<Vec<T>> {
    let values = values.ok_or_else(|| error(format!("Missing {tag}")))?;
    if values.len() != files {
        return Err(error(format!(
            "Invalid {tag}: {} values for {files} files",
            values.len()
        )));
    }
    Ok(values)
}

/// Read the file table: names (`RPMTAG_DIRNAMES`, `RPMTAG_DIRINDEXES`,
/// `RPMTAG_BASENAMES`), modes, sizes, and the flags, inodes and devices
/// that define hard-link sets.
fn file_table<'h>(main: &Header<'h>) -> Result<FileTable<'h>> {
    let basenames = main
        .strings(RPMTAG_BASENAMES)?
        .ok_or_else(|| error("Missing RPMTAG_BASENAMES"))?;
    let files = basenames.len();
    let dirnames = main
        .strings(RPMTAG_DIRNAMES)?
        .ok_or_else(|| error("Missing RPMTAG_DIRNAMES"))?;
    let dirindexes = per_file(main.u32s(RPMTAG_DIRINDEXES)?, "RPMTAG_DIRINDEXES", files)?;
    if let Some(index) = dirindexes
        .iter()
        .find(|&&index| to_usize(index) >= dirnames.len())
    {
        return Err(error(format!(
            "Invalid RPMTAG_DIRINDEXES: directory {index} of {}",
            dirnames.len()
        )));
    }
    let modes = per_file(main.u16s(RPMTAG_FILEMODES)?, "RPMTAG_FILEMODES", files)?;
    let sizes = match main.u64s(RPMTAG_LONGFILESIZES)? {
        Some(sizes) => per_file(Some(sizes), "RPMTAG_LONGFILESIZES", files)?,
        None => per_file(main.u32s(RPMTAG_FILESIZES)?, "RPMTAG_FILESIZES", files)?
            .into_iter()
            .map(u64::from)
            .collect(),
    };
    let optional = |values: Option<Vec<u32>>, tag: &str| -> Result<Option<Vec<u32>>> {
        values.map(|v| per_file(Some(v), tag, files)).transpose()
    };
    let flags = optional(main.u32s(RPMTAG_FILEFLAGS)?, "RPMTAG_FILEFLAGS")?;
    let inodes = optional(main.u32s(RPMTAG_FILEINODES)?, "RPMTAG_FILEINODES")?;
    let devices = optional(main.u32s(RPMTAG_FILEDEVICES)?, "RPMTAG_FILEDEVICES")?;
    let links = LinkFields {
        modes: &modes,
        flags: flags.as_deref(),
        inodes: inodes.as_deref(),
        devices: devices.as_deref(),
    };
    let carries_contents = links.content_carriers();
    Ok(FileTable {
        basenames,
        dirnames,
        dirindexes,
        modes,
        sizes,
        carries_contents,
    })
}

/// The per-file fields that define hard-link sets (`rpmfilesBuildNLink`):
/// regular, non-ghost files with an inode above 0 that share device and
/// inode.
struct LinkFields<'t> {
    modes: &'t [u16],
    flags: Option<&'t [u32]>,
    inodes: Option<&'t [u32]>,
    devices: Option<&'t [u32]>,
}

impl LinkFields<'_> {
    /// Whether each file's entry carries its contents: in a hard-link set
    /// only the last member (the highest index) does (`rpmfiStat`).
    fn content_carriers(&self) -> Vec<bool> {
        let mut carries = vec![true; self.modes.len()];
        let (Some(inodes), Some(devices)) = (self.inodes, self.devices) else {
            return carries;
        };
        let is_linkable = |i: usize| {
            let is_ghost = self
                .flags
                .is_some_and(|flags| flags[i] & RPMFILE_GHOST != 0);
            u32::from(self.modes[i]) & S_IFMT == S_IFREG && !is_ghost && inodes[i] > 0
        };
        let mut last = HashMap::new();
        for i in (0..self.modes.len()).filter(|&i| is_linkable(i)) {
            last.insert((devices[i], inodes[i]), i);
        }
        for i in (0..self.modes.len()).filter(|&i| is_linkable(i)) {
            carries[i] = last.get(&(devices[i], inodes[i])) == Some(&i);
        }
        carries
    }
}

impl FileTable<'_> {
    fn len(&self) -> usize {
        self.basenames.len()
    }

    fn mode(&self, fx: usize) -> u32 {
        u32::from(self.modes[fx])
    }

    /// Bytes of data the file's stripped entry carries.
    fn content_size(&self, fx: usize) -> u64 {
        match self.mode(fx) & S_IFMT {
            S_IFREG if self.carries_contents[fx] => self.sizes[fx],
            S_IFLNK => self.sizes[fx],
            _ => 0,
        }
    }

    /// The file's path: its directory name, then its base name.
    fn path(&self, fx: usize) -> String {
        let directory = self.dirnames[to_usize(self.dirindexes[fx])];
        let mut path = String::from_utf8_lossy(directory).into_owned();
        path.push_str(&String::from_utf8_lossy(self.basenames[fx]));
        path
    }
}

/// How an entry names its file.
#[derive(Debug, Clone, Copy)]
enum EntryName<'d> {
    /// A `newc` entry's stored name, without its NUL.
    Stored(&'d [u8]),
    /// A stripped entry's index into the file table.
    Indexed(usize),
}

/// One archive entry, in archive offsets.
#[derive(Debug)]
struct Entry<'d> {
    mode: u32,
    name: EntryName<'d>,
    /// Offset of the data.
    data_offset: usize,
    contents: &'d [u8],
}

/// What one read at an entry boundary found.
#[derive(Debug)]
enum Step<'d> {
    Entry(Entry<'d>),
    /// The `TRAILER!!!` entry (or a stripped end index); `next` is the
    /// offset after it.
    Trailer {
        next: usize,
    },
}

/// Why the walk stopped before a trailer.
#[derive(Debug)]
enum Stop {
    /// The archive ends inside the entry.
    Truncated,
    /// The entry is not one rpm reads.
    Invalid(String),
}

/// An 8-digit hex field.
fn hex_field(field: &[u8]) -> Option<u32> {
    if field.len() != FIELD_LEN {
        return None;
    }
    let text = std::str::from_utf8(field).ok()?;
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

/// The `len` bytes at `start`, or [`Stop::Truncated`].
fn take(archive: &[u8], start: usize, len: usize) -> std::result::Result<&[u8], Stop> {
    start
        .checked_add(len)
        .and_then(|end| archive.get(start..end))
        .ok_or(Stop::Truncated)
}

/// The data offset after a header or name that ends at `end`.
fn data_offset(end: usize) -> std::result::Result<usize, Stop> {
    align_up(end, ALIGNMENT).ok_or(Stop::Truncated)
}

/// Read the entry at `pos` (`rpmcpioHeaderRead`).
fn read_entry<'d>(
    archive: &'d [u8],
    pos: usize,
    table: Option<&FileTable<'_>>,
) -> std::result::Result<Step<'d>, Stop> {
    let magic = take(archive, pos, MAGIC_SIZE)?;
    if magic == STRIPPED_MAGIC {
        return read_stripped(archive, pos, table);
    }
    if magic != NEWC_MAGIC && magic != CRC_MAGIC {
        return Err(Stop::Invalid("no cpio entry magic".to_string()));
    }
    let fields = take(archive, pos + MAGIC_SIZE, NEWC_FIELDS_SIZE)?;
    let field = |at: usize, what: &str| {
        hex_field(&fields[at..at + FIELD_LEN])
            .ok_or_else(|| Stop::Invalid(format!("{what} is not hex")))
    };
    let mode = field(MODE_FIELD, "c_mode")?;
    let size = to_usize(field(FILESIZE_FIELD, "c_filesize")?);
    let name_size = to_usize(field(NAMESIZE_FIELD, "c_namesize")?);
    if name_size == 0 || name_size > MAX_NAME_SIZE {
        return Err(Stop::Invalid(format!(
            "c_namesize {name_size} is outside 1 to {MAX_NAME_SIZE}"
        )));
    }
    let name_at = pos + MAGIC_SIZE + NEWC_FIELDS_SIZE;
    let Some((&0, name)) = take(archive, name_at, name_size)?.split_last() else {
        return Err(Stop::Invalid("the name does not end with NUL".to_string()));
    };
    let data_at = data_offset(name_at + name_size)?;
    if name == TRAILER {
        return Ok(Step::Trailer { next: data_at });
    }
    Ok(Step::Entry(Entry {
        mode,
        name: EntryName::Stored(name),
        data_offset: data_at,
        contents: take(archive, data_at, size)?,
    }))
}

/// Read a stripped entry at `pos`: magic, file index, then the contents
/// the file table gives it.
fn read_stripped<'d>(
    archive: &'d [u8],
    pos: usize,
    table: Option<&FileTable<'_>>,
) -> std::result::Result<Step<'d>, Stop> {
    let index_field = take(archive, pos + MAGIC_SIZE, FIELD_LEN)?;
    let index = hex_field(index_field)
        .ok_or_else(|| Stop::Invalid("the file index is not hex".to_string()))?;
    let data_at = data_offset(pos + MAGIC_SIZE + FIELD_LEN)?;
    if index == STRIPPED_END {
        return Ok(Step::Trailer { next: data_at });
    }
    let Some(table) = table else {
        return Err(Stop::Invalid(
            "a stripped entry in an archive that started with newc entries".to_string(),
        ));
    };
    let fx = to_usize(index);
    if fx >= table.len() {
        return Err(Stop::Invalid(format!(
            "file index {fx} is outside the {}-file table",
            table.len()
        )));
    }
    let size = usize::try_from(table.content_size(fx)).unwrap_or(usize::MAX);
    Ok(Step::Entry(Entry {
        mode: table.mode(fx),
        name: EntryName::Indexed(fx),
        data_offset: data_at,
        contents: take(archive, data_at, size)?,
    }))
}

/// A regular file in a recognized format.
#[derive(Debug)]
struct ListedFile<'d> {
    label: String,
    /// Offset of the contents in the archive.
    offset: usize,
    contents: &'d [u8],
}

/// Entry counts of a walk.
#[derive(Debug, Default)]
struct Tally {
    entries: usize,
    files: usize,
    directories: usize,
    symlinks: usize,
    other: usize,
    /// Regular files with contents checked for a recognized format.
    examined: usize,
    /// Regular files with contents not checked because
    /// [`MAX_COMPONENTS`] files were listed.
    unexamined: usize,
    /// Entries in rpm's stripped layout.
    stripped: usize,
}

/// Where the walk ended.
#[derive(Debug)]
enum End {
    /// At the trailer; `next` is the offset after it.
    Trailer { next: usize },
    /// The archive ends inside the entry at `at`.
    Truncated { at: usize },
    /// The entry at `at` is invalid.
    Invalid { at: usize, message: String },
}

/// The recognized files of an archive and what the walk found.
#[derive(Debug)]
struct Listing<'d> {
    files: Vec<ListedFile<'d>>,
    tally: Tally,
    end: End,
}

/// Walk the archive's entries from offset 0 to the trailer, or to the
/// first entry that is truncated or invalid. Every entry advances the
/// offset by at least its 14-byte header, so the walk is bounded by the
/// archive size.
fn walk<'d>(archive: &'d [u8], table: Option<&FileTable<'_>>) -> Listing<'d> {
    let mut files = Vec::new();
    let mut tally = Tally::default();
    let mut pos = 0;
    let end = loop {
        match read_entry(archive, pos, table) {
            Ok(Step::Trailer { next }) => break End::Trailer { next },
            Ok(Step::Entry(entry)) => {
                record(&entry, table, &mut tally, &mut files);
                let entry_end = entry.data_offset + entry.contents.len();
                match align_up(entry_end, ALIGNMENT) {
                    Some(next) => pos = next,
                    None => break End::Truncated { at: entry_end },
                }
            }
            Err(Stop::Truncated) => break End::Truncated { at: pos },
            Err(Stop::Invalid(message)) => break End::Invalid { at: pos, message },
        }
    };
    Listing { files, tally, end }
}

/// Count one entry, and keep a regular file with contents when its first
/// bytes, and then its whole contents, are a recognized format.
fn record<'d>(
    entry: &Entry<'d>,
    table: Option<&FileTable<'_>>,
    tally: &mut Tally,
    files: &mut Vec<ListedFile<'d>>,
) {
    tally.entries += 1;
    if matches!(entry.name, EntryName::Indexed(_)) {
        tally.stripped += 1;
    }
    match entry.mode & S_IFMT {
        S_IFREG => tally.files += 1,
        S_IFDIR => tally.directories += 1,
        S_IFLNK => tally.symlinks += 1,
        _ => tally.other += 1,
    }
    // Hard links other than the one that carries the data have none.
    if entry.mode & S_IFMT != S_IFREG || entry.contents.is_empty() {
        return;
    }
    if files.len() >= MAX_COMPONENTS {
        tally.unexamined += 1;
        return;
    }
    tally.examined += 1;
    let contents = entry.contents;
    let prefix = &contents[..contents.len().min(RECOGNITION_PREFIX)];
    if !container::is_recognized(prefix) || !container::is_recognized(contents) {
        return;
    }
    let label = match (entry.name, table) {
        (EntryName::Stored(name), _) => String::from_utf8_lossy(name).into_owned(),
        (EntryName::Indexed(fx), Some(table)) => table.path(fx),
        (EntryName::Indexed(fx), None) => format!("File {fx}"),
    };
    files.push(ListedFile {
        label,
        offset: entry.data_offset,
        contents,
    });
}

impl Listing<'_> {
    /// Notes for the entries, the listed files and where the walk ended.
    fn push_notes(&self, archive: &[u8], complete: bool, c: &mut Container<'_>) {
        let tally = &self.tally;
        let layout = if tally.stripped > 0 {
            "stripped (`07070X`) entries, indexed into the main header's file table"
        } else {
            "newc entries"
        };
        c.notes.push(format!(
            "Payload archive of {layout}: {} ({}, {}, {}, {} other)",
            counted(tally.entries, "entry", "entries"),
            counted(tally.files, "regular file", "regular files"),
            counted(tally.directories, "directory", "directories"),
            counted(tally.symlinks, "symbolic link", "symbolic links"),
            tally.other
        ));
        c.push_metadata(
            "rpm_payload_entries",
            "Payload archive entries",
            tally.entries as u64,
        );
        if tally.examined > 0 {
            c.notes.push(format!(
                "{} of {} regular files with contents are in a recognized format and listed",
                self.files.len(),
                tally.examined
            ));
        }
        if tally.unexamined > 0 {
            c.notes.push(format!(
                "File listing stopped at {MAX_COMPONENTS} components; {} not examined",
                counted(
                    tally.unexamined,
                    "further regular file was",
                    "further regular files were"
                )
            ));
        }
        match &self.end {
            End::Trailer { next } => {
                let rest = archive.get(*next..).unwrap_or_default();
                if rest.iter().any(|&b| b != 0) {
                    c.notes.push(format!(
                        "{} after the `TRAILER!!!` entry at archive offset 0x{next:X} are not \
                         part of the archive",
                        size_text(rest.len())
                    ));
                }
            }
            End::Truncated { at } if complete => c.notes.push(format!(
                "The payload archive ends inside the entry at archive offset 0x{at:X}, before a \
                 `TRAILER!!!` entry; later entries are not listed"
            )),
            End::Truncated { at } => c.notes.push(format!(
                "The decoded prefix ends inside the entry at archive offset 0x{at:X}; it and \
                 later entries are not listed"
            )),
            End::Invalid { at, message } => c.notes.push(format!(
                "The payload archive entry at archive offset 0x{at:X} is invalid ({message}); it \
                 and later entries are not listed"
            )),
        }
    }
}

/// Note the per-file digests the main header carries, which are not
/// verified.
fn push_file_digest_note(main: &Header<'_>, c: &mut Container<'_>) -> Result<()> {
    let Some(digests) = main.strings(RPMTAG_FILEDIGESTS)? else {
        return Ok(());
    };
    let present = digests.iter().filter(|d| !d.is_empty()).count();
    if present == 0 {
        return Ok(());
    }
    let algorithm = main.number(RPMTAG_FILEDIGESTALGO)?.unwrap_or(RPM_HASH_MD5);
    let name = FILE_DIGEST_ALGORITHMS
        .iter()
        .find(|(id, _)| *id == algorithm)
        .map_or_else(
            || format!("algorithm {algorithm}"),
            |(_, name)| (*name).to_string(),
        );
    c.notes.push(format!(
        "File digests ({name}) present for {}, not verified",
        counted(present, "file", "files")
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_HEADER: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";

    /// A newc entry: magic, 13 hex fields (mode, size and name size set),
    /// the name with its NUL padded to 4 bytes, the data padded to 4 bytes.
    fn newc(name: &str, mode: u32, contents: &[u8]) -> Vec<u8> {
        let mut entry = NEWC_MAGIC.to_vec();
        let size = u32::try_from(contents.len()).expect("small test file");
        let name_size = u32::try_from(name.len() + 1).expect("short test name");
        let fields = [0, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, name_size, 0];
        for field in fields {
            entry.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        entry.extend_from_slice(name.as_bytes());
        entry.push(0);
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry.extend_from_slice(contents);
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry
    }

    /// A stripped entry: magic, file index, padding, the data padded to 4.
    fn stripped(index: u32, contents: &[u8]) -> Vec<u8> {
        let mut entry = STRIPPED_MAGIC.to_vec();
        entry.extend_from_slice(format!("{index:08x}").as_bytes());
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry.extend_from_slice(contents);
        entry.resize(align_up(entry.len(), 4).unwrap(), 0);
        entry
    }

    fn table(modes: Vec<u16>, sizes: Vec<u64>) -> FileTable<'static> {
        let files = modes.len();
        FileTable {
            basenames: vec![b"f".as_slice(); files],
            dirnames: vec![b"/d/".as_slice()],
            dirindexes: vec![0; files],
            carries_contents: vec![true; files],
            modes,
            sizes,
        }
    }

    #[test]
    fn newc_walks_list_recognized_files_to_the_trailer() {
        let mut archive = newc("./usr", S_IFDIR | 0o755, b"");
        archive.extend(newc("./usr/hello", S_IFREG | 0o755, ELF_HEADER));
        archive.extend(newc("./usr/README", S_IFREG | 0o644, b"text"));
        archive.extend(newc("TRAILER!!!", 0, b""));
        let listing = walk(&archive, None);
        assert!(matches!(listing.end, End::Trailer { next } if next == archive.len()));
        assert_eq!(listing.tally.entries, 3);
        assert_eq!(listing.tally.files, 2);
        assert_eq!(listing.tally.directories, 1);
        assert_eq!(listing.tally.examined, 2);
        assert_eq!(listing.files.len(), 1);
        assert_eq!(listing.files[0].label, "./usr/hello");
        assert_eq!(listing.files[0].contents, ELF_HEADER);
        let offset = listing.files[0].offset;
        assert_eq!(&archive[offset..offset + ELF_HEADER.len()], ELF_HEADER);
    }

    #[test]
    fn truncated_and_invalid_entries_end_the_walk() {
        let mut archive = newc("./a", S_IFREG, ELF_HEADER);
        archive.extend(newc("TRAILER!!!", 0, b""));
        for end in 0..archive.len() - 4 {
            let listing = walk(&archive[..end], None);
            assert!(!matches!(listing.end, End::Trailer { .. }), "{end}");
        }
        let mut bad = archive.clone();
        bad[MAGIC_SIZE + NAMESIZE_FIELD] = b'g';
        assert!(matches!(walk(&bad, None).end, End::Invalid { at: 0, .. }));
        let mut bad = archive;
        bad[0] = b'1';
        assert!(matches!(walk(&bad, None).end, End::Invalid { .. }));
    }

    #[test]
    fn stripped_entries_take_names_and_sizes_from_the_table() {
        let table = table(
            vec![0o040_755, 0o100_755],
            vec![4096, ELF_HEADER.len() as u64],
        );
        let mut archive = stripped(0, b"");
        archive.extend(stripped(1, ELF_HEADER));
        archive.extend(newc("TRAILER!!!", 0, b""));
        let listing = walk(&archive, Some(&table));
        assert!(
            matches!(listing.end, End::Trailer { .. }),
            "{:?}",
            listing.end
        );
        assert_eq!(listing.tally.stripped, 2);
        assert_eq!(listing.files.len(), 1);
        assert_eq!(listing.files[0].label, "/d/f");
        assert_eq!(listing.files[0].offset, 32);

        let mut end_index = stripped(1, ELF_HEADER);
        end_index.extend(stripped(STRIPPED_END, b""));
        assert!(matches!(
            walk(&end_index, Some(&table)).end,
            End::Trailer { .. }
        ));
        let outside = stripped(2, b"");
        assert!(matches!(
            walk(&outside, Some(&table)).end,
            End::Invalid { .. }
        ));
        assert!(matches!(
            walk(&stripped(1, ELF_HEADER), None).end,
            End::Invalid { .. }
        ));
    }

    #[test]
    fn only_the_last_hard_link_carries_contents() {
        let modes = [0o100_644u16, 0o100_644, 0o100_644, 0o040_755];
        let flags = [0, 0, RPMFILE_GHOST, 0];
        let inodes = [7u32, 7, 7, 7];
        let devices = [1u32, 1, 1, 1];
        let links = LinkFields {
            modes: &modes,
            flags: Some(&flags),
            inodes: Some(&inodes),
            devices: Some(&devices),
        };
        assert_eq!(links.content_carriers(), [false, true, true, true]);
        let unlinked = LinkFields {
            inodes: None,
            ..links
        };
        assert_eq!(unlinked.content_carriers(), [true; 4]);
    }

    #[test]
    fn compressor_names_select_codecs_and_gzip_passes_cpio_through() {
        let archive = newc("TRAILER!!!", 0, b"");
        assert_eq!(encoding(None, &archive), Encoding::Uncompressed);
        assert_eq!(encoding(Some(b"gzip"), &archive), Encoding::Uncompressed);
        assert_eq!(
            encoding(Some(b"xz"), &archive),
            Encoding::Compressed(Codec::Xz)
        );
        assert_eq!(
            encoding(Some(b"zstd"), b"\x28\xb5\x2f\xfd"),
            Encoding::Compressed(Codec::Zstd)
        );
        assert_eq!(
            encoding(Some(b"lzip"), b"LZIP"),
            Encoding::Unsupported("lzip".to_string())
        );
        assert_eq!(encoding(None, b"junk"), Encoding::Compressed(Codec::Gzip));
    }

    #[test]
    fn hex_fields_need_eight_hex_digits() {
        assert_eq!(hex_field(b"0000001f"), Some(0x1f));
        assert_eq!(hex_field(b"FFFFFFFF"), Some(STRIPPED_END));
        assert_eq!(hex_field(b"0000001g"), None);
        assert_eq!(hex_field(b"+000001f"), None);
        assert_eq!(hex_field(b"1f"), None);
    }
}
