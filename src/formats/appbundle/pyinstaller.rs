//! `PyInstaller` archives (`CArchive`, PKG).
//!
//! Layout (`PyInstaller` v6.22.3 `bootloader/src/pyi_archive.h`,
//! `PyInstaller/archive/writers.py` `CArchiveWriter`), all integers
//! big-endian: the entries' data from archive offset 0, the table of
//! contents (TOC) at `toc_offset`, then the 88-byte cookie, so that
//! `pkg_length = toc_offset + toc_length + 88`.
//!
//! - Cookie (`ARCHIVE_COOKIE`, `'!8sIIII64s'`): magic
//!   `MEI\x0C\x0B\x0A\x0B\x0E` (8), `pkg_length` (4), `toc_offset` (4),
//!   `toc_length` (4), `python_version` (4: major * 100 + minor since
//!   `PyInstaller` 4, major * 10 + minor in 3.x), `python_libname` (64,
//!   NUL-padded; `readers.py` rejects an empty name).
//! - TOC entry (`TOC_ENTRY`, `'!IIIIBc'`): `entry_length` (4, including the
//!   name), `offset` (4, from the archive start), `length` (4, stored),
//!   `uncompressed_length` (4), `compression_flag` (1: 1 is zlib, 0 is
//!   stored), `typecode` (1), then the NUL-terminated UTF-8 name padded to
//!   a multiple of 16 (`_serialize_toc`).
//!
//! The bootloader (`pyi_archive.c` `pyi_archive_open`) and the reader
//! (`readers.py` `_find_magic_pattern`) find the cookie by scanning the
//! whole file from the end, and compute the archive start as the cookie's
//! end minus `pkg_length`: Linux builds store the archive in an ELF section
//! (`objcopy --add-section pydata=...`), macOS builds sign the executable
//! after appending it, and Windows signatures may follow it
//! (`api.py` `EXE.assemble`).

use super::*;
use crate::formats::compressed::Codec;

/// `MEI\014\013\012\013\016` (`writers.py` `_COOKIE_MAGIC_PATTERN`).
const COOKIE_MAGIC: [u8; 8] = *b"MEI\x0c\x0b\x0a\x0b\x0e";

/// Cookie size: magic, four 32-bit fields and the 64-byte library name.
const COOKIE_SIZE: usize = 88;

/// Cookie fields after the magic.
const COOKIE_PKG_LENGTH: usize = 8;
const COOKIE_TOC_OFFSET: usize = 12;
const COOKIE_TOC_LENGTH: usize = 16;
const COOKIE_PYTHON_VERSION: usize = 20;
const COOKIE_PYTHON_LIBNAME: usize = 24;

/// Fixed part of a TOC entry, before the name.
const TOC_ENTRY_HEADER_SIZE: usize = 18;

/// `compression_flag` values (`pyi_archive.h`: 1 = compressed, 0 =
/// uncompressed; the bootloader inflates only entries flagged 1).
const FLAG_STORED: u8 = 0;
const FLAG_ZLIB: u8 = 1;

/// Type codes (`pyi_archive.h` `ARCHIVE_ITEM_*`; `api.py` `PKG.xformdict`
/// for `a`).
const ITEM_BINARY: u8 = b'b';
const ITEM_DEPENDENCY: u8 = b'd';
const ITEM_PYZ: u8 = b'z';
const ITEM_ZIPFILE: u8 = b'Z';
const ITEM_PYPACKAGE: u8 = b'M';
const ITEM_PYMODULE: u8 = b'm';
const ITEM_PYSOURCE: u8 = b's';
const ITEM_DATA: u8 = b'x';
const ITEM_RUNTIME_OPTION: u8 = b'o';
const ITEM_SPLASH: u8 = b'l';
const ITEM_SYMLINK: u8 = b'n';
/// A nested PKG (`'PKG': 'a'` in `PKG.xformdict`), not in the bootloader's
/// list.
const ITEM_PKG: u8 = b'a';

/// The PYZ archive magic (`writers.py` `ZlibArchiveWriter`).
const PYZ_MAGIC: &[u8; 4] = b"PYZ\0";

/// Python version codes: 3.x and older wrote `major * 10 + minor`
/// (v3.6 `writers.py`), 4.x and later `major * 100 + minor` (v4.10, v6.22.3).
const OLD_VERSION_CODES: std::ops::RangeInclusive<u32> = 20..=39;
const VERSION_CODES: std::ops::RangeInclusive<u32> = 300..=399;

/// The cookie, with sizes already in `usize`.
#[derive(Debug)]
struct Cookie<'a> {
    /// File offset of the cookie.
    offset: usize,
    /// Length of the whole archive, cookie included.
    pkg_length: usize,
    /// TOC position from the archive start.
    toc_offset: usize,
    /// TOC length.
    toc_length: usize,
    /// Encoded Python version.
    python_version: u32,
    /// Python shared library name, without padding.
    python_libname: &'a [u8],
}

impl Cookie<'_> {
    /// File offset just after the cookie, where the archive ends.
    fn end(&self) -> usize {
        self.offset + COOKIE_SIZE
    }

    /// File offset of the archive start, if `pkg_length` fits before the
    /// cookie's end.
    fn start(&self) -> Option<usize> {
        self.end().checked_sub(self.pkg_length)
    }

    /// Whether the TOC ends where the cookie starts, as every writer
    /// places it.
    fn toc_ends_at_cookie(&self) -> bool {
        self.toc_offset
            .checked_add(self.toc_length)
            .and_then(|end| end.checked_add(COOKIE_SIZE))
            == Some(self.pkg_length)
    }
}

/// The cookie at `at`.
fn read_cookie(data: &[u8], at: usize) -> Result<Cookie<'_>> {
    let cookie = slice(data, at, COOKIE_SIZE, "PyInstaller cookie")?;
    let field = |offset| be_u32(cookie, offset, "PyInstaller cookie").map(to_usize);
    Ok(Cookie {
        offset: at,
        pkg_length: field(COOKIE_PKG_LENGTH)?,
        toc_offset: field(COOKIE_TOC_OFFSET)?,
        toc_length: field(COOKIE_TOC_LENGTH)?,
        python_version: be_u32(cookie, COOKIE_PYTHON_VERSION, "PyInstaller cookie")?,
        python_libname: until_nul(&cookie[COOKIE_PYTHON_LIBNAME..]),
    })
}

/// The last occurrence of the cookie magic, as the bootloader's
/// back-to-front scan finds it.
fn find_cookie(data: &[u8]) -> Option<usize> {
    memchr::memmem::rfind(data, &COOKIE_MAGIC)
}

/// The input is an archive of its own: the cookie magic in the last 88
/// bytes, and a package length equal to the input length.
pub(super) fn is_standalone(data: &[u8]) -> bool {
    let Some(at) = data.len().checked_sub(COOKIE_SIZE) else {
        return false;
    };
    data[at..].starts_with(&COOKIE_MAGIC)
        && read_cookie(data, at).is_ok_and(|cookie| cookie.pkg_length == data.len())
}

/// An archive inside a host: the last cookie in the file, an archive start
/// after offset 0, a TOC that ends at the cookie and a library name.
pub(super) fn is_embedded(data: &[u8]) -> bool {
    let Some(cookie) = find_cookie(data).and_then(|at| read_cookie(data, at).ok()) else {
        return false;
    };
    cookie.start().is_some_and(|start| start > 0)
        && cookie.toc_ends_at_cookie()
        && !cookie.python_libname.is_empty()
}

/// One TOC entry.
#[derive(Debug)]
struct Entry<'a> {
    /// Name bytes, without padding.
    name: &'a [u8],
    /// File offset of the stored data.
    offset: usize,
    /// Stored bytes.
    stored: &'a [u8],
    /// Declared decoded length.
    uncompressed_length: usize,
    /// `compression_flag`.
    flag: u8,
    /// `typecode`.
    typecode: u8,
}

impl Entry<'_> {
    fn label(&self) -> String {
        display_name(self.name)
    }

    /// The last path component of the name (`/` or `\` separated, as
    /// Windows builds store them).
    fn basename(&self) -> &[u8] {
        self.name
            .rsplit(|&b| b == b'/' || b == b'\\')
            .next()
            .unwrap_or(self.name)
    }
}

/// The archive's location in the file and its TOC.
#[derive(Debug)]
struct Archive<'a> {
    cookie: Cookie<'a>,
    /// File offset of the archive start.
    start: usize,
    entries: Vec<Entry<'a>>,
}

/// Locate the cookie, check the archive's extent and read the TOC.
fn read_archive(data: &[u8]) -> Result<Archive<'_>> {
    let at = find_cookie(data)
        .ok_or_else(|| error("Missing PyInstaller cookie (magic MEI\\x0C\\x0B\\x0A\\x0B\\x0E)"))?;
    let cookie = read_cookie(data, at)?;
    let start = cookie.start().ok_or_else(|| {
        error(format!(
            "Invalid package length {} B: the cookie at 0x{at:X} ends at 0x{:X}",
            cookie.pkg_length,
            cookie.end()
        ))
    })?;
    if !cookie.toc_ends_at_cookie() {
        return Err(error(format!(
            "Invalid TOC range 0x{:X} + {} B in a {} B archive: the TOC must end at the \
             {COOKIE_SIZE}-byte cookie",
            cookie.toc_offset, cookie.toc_length, cookie.pkg_length
        )));
    }
    if cookie.python_libname.is_empty() {
        return Err(error(format!(
            "Missing Python library name in the cookie at 0x{at:X}"
        )));
    }
    let entries = read_toc(data, start, &cookie)?;
    Ok(Archive {
        cookie,
        start,
        entries,
    })
}

/// Walk the TOC. Every entry's data must lie in the archive's data area,
/// before the TOC; a stored entry's two lengths must agree.
fn read_toc<'a>(data: &'a [u8], start: usize, cookie: &Cookie<'_>) -> Result<Vec<Entry<'a>>> {
    // `start + pkg_length` is the cookie's end, inside `data`, and the TOC
    // ends where the cookie starts (`toc_ends_at_cookie`).
    let toc_start = start + cookie.toc_offset;
    let toc = &data[toc_start..toc_start + cookie.toc_length];
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < toc.len() {
        let file_offset = toc_start + pos;
        let header = slice(toc, pos, TOC_ENTRY_HEADER_SIZE, "TOC entry")
            .map_err(|_| error(format!("Truncated TOC entry at 0x{file_offset:X}")))?;
        let entry_length = to_usize(be_u32(header, 0, "TOC entry")?);
        if entry_length < TOC_ENTRY_HEADER_SIZE || entry_length > toc.len() - pos {
            return Err(error(format!(
                "Invalid TOC entry length {entry_length} B at 0x{file_offset:X}"
            )));
        }
        let name = until_nul(&toc[pos + TOC_ENTRY_HEADER_SIZE..pos + entry_length]);
        let offset = to_usize(be_u32(header, 4, "TOC entry")?);
        let length = to_usize(be_u32(header, 8, "TOC entry")?);
        let uncompressed_length = to_usize(be_u32(header, 12, "TOC entry")?);
        let flag = header[16];
        let typecode = header[17];
        let in_data_area = offset
            .checked_add(length)
            .is_some_and(|end| end <= cookie.toc_offset);
        if !in_data_area {
            return Err(error(format!(
                "Invalid data range 0x{offset:X} + {length} B for TOC entry {} at \
                 0x{file_offset:X}: the data area ends at 0x{:X}",
                display_name(name),
                cookie.toc_offset
            )));
        }
        if flag == FLAG_STORED && length != uncompressed_length {
            return Err(error(format!(
                "Invalid TOC entry {} at 0x{file_offset:X}: stored length {length} B differs \
                 from uncompressed length {uncompressed_length} B",
                display_name(name)
            )));
        }
        // The data ends before the TOC, which is inside `data`.
        entries.push(Entry {
            name,
            offset: start + offset,
            stored: &data[start + offset..start + offset + length],
            uncompressed_length,
            flag,
            typecode,
        });
        pos += entry_length;
    }
    Ok(entries)
}

/// Python version from its cookie code, or `None` for a code neither
/// encoding produces.
fn python_version(code: u32) -> Option<String> {
    if OLD_VERSION_CODES.contains(&code) {
        Some(format!("{}.{}", code / 10, code % 10))
    } else if VERSION_CODES.contains(&code) {
        Some(format!("{}.{}", code / 100, code % 100))
    } else {
        None
    }
}

/// What the TOC holds, by role.
#[derive(Debug, Default)]
struct Census {
    binaries: usize,
    data_files: usize,
    modules: usize,
    scripts: usize,
    options: Vec<String>,
    dependencies: usize,
    symlinks: usize,
    unknown: Vec<String>,
    unsupported_flags: Vec<String>,
}

/// Parse a `PyInstaller` archive, standalone or inside a host executable.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let archive = read_archive(data)?;
    let cookie = &archive.cookie;
    let mut c = Container::new(
        FileFormat::PyInstaller,
        Layout::PyInstaller.label(),
        "pyinstaller",
    );
    c.consumed = cookie.pkg_length;
    push_location_notes(&mut c, &archive, data.len());
    let library = display_name(cookie.python_libname);
    let version = python_version(cookie.python_version);
    c.notes.push(match &version {
        Some(version) => format!("Python {version}; Python library {library}"),
        None => format!(
            "Unknown Python version code {}; Python library {library}",
            cookie.python_version
        ),
    });
    c.push_metadata(
        "pyinstaller_archive_offset",
        "Archive offset (B)",
        archive.start as u64,
    );
    c.push_metadata(
        "pyinstaller_python_version",
        "Python version",
        version.unwrap_or_else(|| format!("code {}", cookie.python_version)),
    );
    c.push_metadata("pyinstaller_python_library", "Python library", library);
    c.push_metadata(
        "pyinstaller_toc_entries",
        "TOC entries",
        archive.entries.len() as u64,
    );

    let mut census = Census::default();
    push_python_code(&mut c, &archive.entries, &mut census);
    let mut members = Members::default();
    push_members(&mut c, &archive, &mut members, &mut census);
    push_census_notes(&mut c, &census);
    members.push_notes(&mut c, "file", "files");
    Ok(c)
}

/// Where the archive lies in the input.
fn push_location_notes(c: &mut Container<'_>, archive: &Archive<'_>, input_len: usize) {
    let end = archive.cookie.end();
    if archive.start > 0 {
        c.notes.push(format!(
            "Archive at file offset 0x{:X} ({}); the {} before it (the host executable) are \
             not part of it",
            archive.start,
            size_text(archive.cookie.pkg_length),
            size_text(archive.start)
        ));
    }
    if end < input_len {
        c.notes.push(format!(
            "{} after the archive (section headers, a code signature or other data) are not \
             part of it",
            size_text(input_len - end)
        ));
    }
}

/// Python scripts (the entry points and run-time hooks) and the PYZ
/// archive of the application's modules, as opaque children: marshalled
/// Python bytecode has no ISA here. Bootstrap modules are counted.
fn push_python_code<'a>(c: &mut Container<'a>, entries: &[Entry<'a>], census: &mut Census) {
    for entry in entries {
        let role = match entry.typecode {
            ITEM_PYSOURCE => {
                census.scripts += 1;
                "Python script"
            }
            ITEM_PYZ => "PYZ archive",
            ITEM_PYMODULE | ITEM_PYPACKAGE => {
                census.modules += 1;
                continue;
            }
            _ => continue,
        };
        if c.children.len() >= MAX_COMPONENTS {
            continue;
        }
        let stored_pyz = entry.typecode == ITEM_PYZ && entry.flag == FLAG_STORED;
        if stored_pyz && !entry.stored.starts_with(PYZ_MAGIC) {
            c.notes.push(format!(
                "PYZ archive {} does not start with the PYZ\\0 magic",
                entry.label()
            ));
        }
        c.children.push(Child::opaque(
            format!("{role} {} (Python bytecode)", entry.label()),
            entry.offset,
            entry.stored,
        ));
    }
}

/// Binaries, data files, zip files and nested archives that are in a
/// recognized format. The Python library the cookie names comes first: it
/// is the interpreter every other binary is loaded into.
fn push_members<'a>(
    c: &mut Container<'a>,
    archive: &Archive<'a>,
    members: &mut Members,
    census: &mut Census,
) {
    let library = archive.cookie.python_libname;
    let is_library = |entry: &Entry<'_>| {
        entry.typecode == ITEM_BINARY && (entry.name == library || entry.basename() == library)
    };
    let first = archive.entries.iter().position(is_library);
    let rest = archive
        .entries
        .iter()
        .enumerate()
        .filter(|&(i, _)| Some(i) != first)
        .map(|(_, entry)| entry);
    for entry in first.map(|i| &archive.entries[i]).into_iter().chain(rest) {
        let recognition = match entry.typecode {
            ITEM_BINARY => {
                census.binaries += 1;
                Recognition::Prefix
            }
            ITEM_DATA | ITEM_ZIPFILE => {
                census.data_files += 1;
                Recognition::Prefix
            }
            ITEM_PKG => {
                census.data_files += 1;
                Recognition::Whole
            }
            ITEM_SPLASH => {
                push_splash(c, entry);
                continue;
            }
            ITEM_RUNTIME_OPTION => {
                census.options.push(entry.label());
                continue;
            }
            ITEM_DEPENDENCY => {
                census.dependencies += 1;
                continue;
            }
            ITEM_SYMLINK => {
                census.symlinks += 1;
                continue;
            }
            ITEM_PYSOURCE | ITEM_PYZ | ITEM_PYMODULE | ITEM_PYPACKAGE => continue,
            other => {
                census
                    .unknown
                    .push(format!("{} (0x{other:02X})", entry.label()));
                continue;
            }
        };
        if entry.uncompressed_length == 0 {
            continue;
        }
        let contents = match entry.flag {
            FLAG_STORED => Contents::Stored(entry.stored),
            FLAG_ZLIB => Contents::Compressed {
                stored: entry.stored,
                codec: Codec::Zlib,
                size: entry.uncompressed_length,
            },
            other => {
                census
                    .unsupported_flags
                    .push(format!("{} (flag {other})", entry.label()));
                continue;
            }
        };
        members.offer(
            c,
            Member {
                label: entry.label(),
                offset: entry.offset,
                contents,
                recognition,
            },
        );
    }
}

/// Splash screen resources (Tcl/Tk script and image), listed as opaque.
fn push_splash<'a>(c: &mut Container<'a>, entry: &Entry<'a>) {
    if c.children.len() < MAX_COMPONENTS {
        c.children.push(Child::opaque(
            format!("Splash screen resources {}", entry.label()),
            entry.offset,
            entry.stored,
        ));
    }
}

/// Counts of what the TOC holds, and what is not analyzed.
fn push_census_notes(c: &mut Container<'_>, census: &Census) {
    c.notes.push(format!(
        "TOC: {}, {}, {} and {}",
        counted(census.binaries, "binary", "binaries"),
        counted(census.data_files, "data file", "data files"),
        counted(census.scripts, "Python script", "Python scripts"),
        counted(census.modules, "bootstrap module", "bootstrap modules"),
    ));
    if !census.options.is_empty() {
        c.notes.push(format!(
            "Run-time options: {}",
            bounded_list(&census.options)
        ));
    }
    if census.dependencies > 0 {
        c.notes.push(format!(
            "{} on files in other archives or directories (not followed)",
            counted(census.dependencies, "dependency", "dependencies")
        ));
    }
    if census.symlinks > 0 {
        c.notes.push(format!(
            "{} (not followed)",
            counted(census.symlinks, "symbolic link", "symbolic links")
        ));
    }
    if !census.unknown.is_empty() {
        c.notes.push(format!(
            "Unknown type codes, not analyzed: {}",
            bounded_list(&census.unknown)
        ));
    }
    if !census.unsupported_flags.is_empty() {
        c.notes.push(format!(
            "Unsupported compression flags, not decoded: {}",
            bounded_list(&census.unsupported_flags)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_versions_decode_both_encodings() {
        assert_eq!(python_version(27).as_deref(), Some("2.7"));
        assert_eq!(python_version(39).as_deref(), Some("3.9"));
        assert_eq!(python_version(310).as_deref(), Some("3.10"));
        assert_eq!(python_version(313).as_deref(), Some("3.13"));
        assert_eq!(python_version(0), None);
        assert_eq!(python_version(100), None);
    }

    #[test]
    fn the_last_cookie_is_found_and_its_extent_checked() {
        let mut data = vec![0u8; 200];
        data[10..18].copy_from_slice(&COOKIE_MAGIC);
        data[100..108].copy_from_slice(&COOKIE_MAGIC);
        assert_eq!(find_cookie(&data), Some(100));
        data[100 + COOKIE_PKG_LENGTH..100 + COOKIE_PKG_LENGTH + 4]
            .copy_from_slice(&188u32.to_be_bytes());
        let cookie = read_cookie(&data, 100).unwrap();
        assert_eq!(cookie.end(), 188);
        assert_eq!(cookie.start(), Some(0));
        assert!(!cookie.toc_ends_at_cookie());
        assert!(read_cookie(&data, 150).is_err());
    }
}
