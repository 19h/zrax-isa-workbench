//! Read-only filesystem images: Squashfs, Cramfs and romfs.
//!
//! Each image is a container whose children are its regular files. A walk
//! of the directory tree finds every regular file; a file is listed only
//! when its first block is a format the classifier recognizes
//! ([`container::is_recognized`]), and only then is the whole file read.
//!
//! Sources:
//! - Squashfs 4.0: Linux v6.11 (`98f7e32f20d2`) `fs/squashfs/squashfs_fs.h`
//!   (on-disk structures), `super.c` (superblock and table checks),
//!   `block.c`, `cache.c`, `inode.c`, `dir.c`, `file.c`, `fragment.c`,
//!   `id.c`, `export.c`, `xattr_id.c` and the `*_wrapper.c` compressors;
//!   squashfs-tools 4.6.1 (`d8cb82d98403`) `squashfs_fs.h`,
//!   `squashfs_compat.h` (the 1.x-3.x superblock), `unsquash-4.c` and the
//!   compressor option layouts in `gzip_wrapper.h`, `xz_wrapper.h`,
//!   `lzo_wrapper.h`, `lz4_wrapper.h` and `zstd_wrapper.h`;
//!   squashfs-tools 4.7.5 (`708c59ae8085`) `squashfs_fs.h` (streamed magic).
//! - Cramfs: Linux v6.11 `include/uapi/linux/cramfs_fs.h`,
//!   `fs/cramfs/inode.c` and `fs/cramfs/README`; util-linux v2.40.2
//!   (`1cebcc34373e`) `disk-utils/cramfs.h`, `cramfs_common.c`,
//!   `mkfs.cramfs.c` and `fsck.cramfs.c`.
//! - romfs: Linux v6.11 `Documentation/filesystems/romfs.rst`,
//!   `include/uapi/linux/romfs_fs.h` and `fs/romfs/super.c`; genromfs
//!   commit `e4225b49` `genromfs.c`.
//!
//! None of these formats names an ISA. Their byte order (Cramfs host order,
//! Squashfs 1.x-3.x big-endian images) describes the machine that built the
//! image, not the code in it, so the container target is always unknown and
//! the ISA comes from the members.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::{checksum, MAX_PAYLOAD};
use crate::types::FileFormat;
use std::borrow::Cow;

mod cramfs;
mod romfs;
mod squashfs;

/// Deepest directory nesting that is walked.
const MAX_DEPTH: usize = 64;

/// Longest directory path that is walked (Linux `PATH_MAX`).
const MAX_PATH: usize = 4096;

/// A read-only filesystem layout recognized by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Squashfs 4.0, little-endian (`hsqs`); members are enumerated.
    Squashfs,
    /// Squashfs 1.x-3.x in either byte order, or a big-endian (`sqsh`)
    /// superblock of any version; recognized from the superblock, members
    /// not enumerated.
    SquashfsLegacy,
    /// Streamed Squashfs (`HSQS`/`SQSH`, squashfs-tools 4.7 and later),
    /// whose superblock is at the end of the file; members not enumerated.
    SquashfsStreamed,
    /// Cramfs in either byte order, superblock at offset 0 or 512.
    Cramfs,
    /// romfs (`-rom1fs-`).
    Romfs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Squashfs | Self::SquashfsLegacy | Self::SquashfsStreamed => FileFormat::Squashfs,
            Self::Cramfs => FileFormat::Cramfs,
            Self::Romfs => FileFormat::Romfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Squashfs => "SquashFS 4.0",
            Self::SquashfsLegacy => "SquashFS 1.x-3.x or big-endian",
            Self::SquashfsStreamed => "Streamed SquashFS",
            Self::Cramfs => "CramFS",
            Self::Romfs => "romfs",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Squashfs
            | Self::SquashfsLegacy
            | Self::SquashfsStreamed
            | Self::Cramfs
            | Self::Romfs => false,
        }
    }
}

/// Strong recognition: the Squashfs, Cramfs or romfs magic.
pub fn detect(data: &[u8]) -> Option<Layout> {
    squashfs::detect(data)
        .or_else(|| cramfs::detect(data))
        .or_else(|| romfs::detect(data))
}

/// Parse a read-only filesystem image into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::RofsParseError`] for a truncated or inconsistent
/// superblock, checksum, metadata table, inode or directory. A regular file
/// whose data does not decode is not an error; it is left out and counted
/// in a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Squashfs => squashfs::parse(data),
        Layout::SquashfsLegacy => squashfs::parse_legacy(data),
        Layout::SquashfsStreamed => squashfs::parse_streamed(data),
        Layout::Cramfs => cramfs::parse(data),
        Layout::Romfs => romfs::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::RofsParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

/// A u16 in the byte order `le` selects (true means little-endian).
fn u16_at(data: &[u8], at: usize, le: bool) -> Result<u16> {
    let bytes = array(data, at)?;
    Ok(if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

/// A u32 in the byte order `le` selects (true means little-endian).
fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let bytes = array(data, at)?;
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// A u64 in the byte order `le` selects (true means little-endian).
fn u64_at(data: &[u8], at: usize, le: bool) -> Result<u64> {
    let bytes = array(data, at)?;
    Ok(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
}

/// A file offset or size read from the image, as `usize`.
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Only padding may follow an image that ends at `end`.
fn expect_padding(data: &[u8], end: usize, format: &str) -> Result<()> {
    let trailing = data.get(end..).unwrap_or_default();
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} B after the {format} image at 0x{end:X}",
            trailing.len()
        )));
    }
    Ok(())
}

/// Note for the padding after an image that ends at `end`, if any.
fn padding_note(data: &[u8], end: usize) -> Option<String> {
    let padding = data.len().saturating_sub(end);
    (padding > 0).then(|| format!("Image ends at 0x{end:X}; {padding} B of padding follow"))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// A directory entry name as a path component, or `None` for `.` and
/// `..`, which a walker must skip. A name is never empty and never holds
/// `/` or NUL, so a label cannot escape its directory.
fn entry_name<'n>(raw: &'n [u8], at: usize, format: &str) -> Result<Option<Cow<'n, str>>> {
    if raw.is_empty() || raw.contains(&b'/') || raw.contains(&0) {
        return Err(error(format!("Invalid {format} file name at 0x{at:X}")));
    }
    if raw == b"." || raw == b".." {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(raw)))
}

/// Whether a directory at `depth` with path `path` is walked.
fn is_walkable(depth: usize, path: &str) -> bool {
    depth <= MAX_DEPTH && path.len() <= MAX_PATH
}

/// The path of the directory being walked, extended and restored as the
/// walk descends and returns.
#[derive(Default)]
struct WalkPath {
    path: String,
}

impl WalkPath {
    /// Append `/name`; returns the length to [`WalkPath::restore`] to.
    fn push(&mut self, name: &str) -> usize {
        let parent_len = self.path.len();
        self.path.push('/');
        self.path.push_str(name);
        parent_len
    }

    fn restore(&mut self, parent_len: usize) {
        self.path.truncate(parent_len);
    }

    fn as_str(&self) -> &str {
        &self.path
    }
}

/// Why a regular file was not listed.
enum Unread {
    /// [`MAX_EXTRACTED`] was reached.
    Limit,
    /// The file is larger than [`MAX_PAYLOAD`].
    TooLarge,
    /// The file's data does not decode or lies outside the image.
    Invalid(ClassifierError),
}

impl From<ClassifierError> for Unread {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// Bytes probed, decoded or listed for regular files (first blocks,
/// members, and the shared blocks decoded to reach their data), bounded by
/// [`MAX_EXTRACTED`]. Every read is charged before it happens, so the
/// decoding work of one image is bounded too.
#[derive(Default)]
struct Budget {
    used: usize,
}

impl Budget {
    /// Account for `size` more bytes, or fail once the limit would pass.
    fn charge(&mut self, size: usize) -> std::result::Result<(), Unread> {
        match self.used.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.used = total;
                Ok(())
            }
            _ => Err(Unread::Limit),
        }
    }
}

/// How a layout reads its regular files.
trait FileReader<'a> {
    /// A regular file as the layout's inode describes it.
    type File;

    /// Size of `file` in bytes.
    fn size(&self, file: &Self::File) -> u64;

    /// Size of the first block of `file` in bytes, the part that is probed
    /// for a recognized format.
    fn first_block_size(&self, file: &Self::File) -> usize;

    /// The first block of `file`, stored or decoded. Shared blocks decoded
    /// on the way (fragment blocks, table blocks) are charged to `budget`.
    fn first_block(
        &mut self,
        file: &Self::File,
        budget: &mut Budget,
    ) -> std::result::Result<Cow<'a, [u8]>, Unread>;

    /// The whole of `file` as a member labeled `path`; `first` is the block
    /// [`FileReader::first_block`] returned. The member's bytes were
    /// charged by the caller; shared blocks are charged to `budget`.
    fn member(
        &mut self,
        file: &Self::File,
        path: String,
        first: Cow<'a, [u8]>,
        budget: &mut Budget,
    ) -> std::result::Result<Child<'a>, Unread>;
}

/// The regular files a directory walk found and the members listed from
/// them, bounded by [`MAX_COMPONENTS`] members and the [`Budget`].
#[derive(Default)]
struct Members<'a> {
    listed: Vec<Child<'a>>,
    budget: Budget,
    /// Regular files the walk found.
    files: usize,
    /// Regular files not examined once [`MAX_COMPONENTS`] were listed.
    over_component_limit: usize,
    /// Regular files not examined or extracted once the budget ran out.
    over_extraction_limit: usize,
    /// Recognized files larger than [`MAX_PAYLOAD`].
    too_large: usize,
    /// Regular files whose data did not decode.
    unreadable: usize,
    /// The first file that did not decode, with the reason.
    first_failure: Option<String>,
    /// Directories not walked because of [`MAX_DEPTH`] or [`MAX_PATH`].
    unwalked_directories: usize,
}

impl<'a> Members<'a> {
    /// Examine one regular file: probe its first block and, when that is a
    /// recognized format, list the whole file.
    fn examine<R: FileReader<'a>>(&mut self, reader: &mut R, file: &R::File, path: &str) {
        self.files += 1;
        if self.listed.len() >= MAX_COMPONENTS {
            self.over_component_limit += 1;
            return;
        }
        match read_member(reader, file, path, &mut self.budget) {
            Ok(Some(child)) => self.listed.push(child.if_recognized()),
            Ok(None) => {}
            Err(Unread::Limit) => self.over_extraction_limit += 1,
            Err(Unread::TooLarge) => self.too_large += 1,
            Err(Unread::Invalid(e)) => {
                self.unreadable += 1;
                if self.first_failure.is_none() {
                    self.first_failure = Some(format!("{path} ({e})"));
                }
            }
        }
    }

    /// Move the listed members into `c` and record what was found and
    /// what was left out. `probe` names what recognition looked at.
    fn finish(self, c: &mut Container<'a>, probe: &str) {
        c.notes.push(format!(
            "{} regular files; {} recognized members listed; members are recognized from their {probe}",
            self.files,
            self.listed.len()
        ));
        if self.over_component_limit > 0 {
            c.notes.push(format!(
                "Member limit reached ({MAX_COMPONENTS} members); {} further regular files were not examined",
                self.over_component_limit
            ));
        }
        if self.over_extraction_limit > 0 {
            c.notes.push(format!(
                "Extraction limit reached ({}); {} regular files were not examined or extracted",
                size_text(MAX_EXTRACTED),
                self.over_extraction_limit
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} recognized regular files exceed the {} member limit and are not listed",
                self.too_large,
                size_text(MAX_PAYLOAD)
            ));
        }
        if let Some(first) = &self.first_failure {
            c.notes.push(format!(
                "{} regular files could not be read and are not listed; first: {first}",
                self.unreadable
            ));
        }
        if self.unwalked_directories > 0 {
            c.notes.push(format!(
                "{} directories nested deeper than {MAX_DEPTH} levels or {MAX_PATH} B were not walked",
                self.unwalked_directories
            ));
        }
        c.push_metadata(
            format!("{}_regular_files", c.key_prefix),
            "Regular files",
            self.files as u64,
        );
        c.children = self.listed;
    }
}

/// The member for `file` when its first block is a recognized format. The
/// first block is charged before it is read, and the rest of the file
/// before it is extracted.
fn read_member<'a, R: FileReader<'a>>(
    reader: &mut R,
    file: &R::File,
    path: &str,
    budget: &mut Budget,
) -> std::result::Result<Option<Child<'a>>, Unread> {
    let probe_size = reader.first_block_size(file);
    budget.charge(probe_size)?;
    let first = reader.first_block(file, budget)?;
    if !container::is_recognized(&first) {
        return Ok(None);
    }
    let size = usize::try_from(reader.size(file))
        .ok()
        .filter(|size| *size <= MAX_PAYLOAD)
        .ok_or(Unread::TooLarge)?;
    budget.charge(size.saturating_sub(probe_size))?;
    reader
        .member(file, path.to_string(), first, budget)
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_skip_dot_entries_and_reject_separators() {
        assert_eq!(
            entry_name(b"busybox", 0, "test").unwrap().as_deref(),
            Some("busybox")
        );
        assert!(entry_name(b".", 0, "test").unwrap().is_none());
        assert!(entry_name(b"..", 0, "test").unwrap().is_none());
        assert!(entry_name(b"", 0, "test").is_err());
        assert!(entry_name(b"../etc", 0, "test").is_err());
        assert!(entry_name(b"a\0b", 0, "test").is_err());
    }

    #[test]
    fn budget_stops_at_the_extraction_limit() {
        let mut budget = Budget::default();
        assert!(budget.charge(MAX_EXTRACTED).is_ok());
        assert!(matches!(budget.charge(1), Err(Unread::Limit)));
        assert!(matches!(budget.charge(usize::MAX), Err(Unread::Limit)));
    }

    #[test]
    fn walk_limits_cover_depth_and_path_length() {
        assert!(is_walkable(MAX_DEPTH, "/a"));
        assert!(!is_walkable(MAX_DEPTH + 1, "/a"));
        assert!(!is_walkable(1, &"a".repeat(MAX_PATH + 1)));
    }

    #[test]
    fn walk_paths_extend_and_restore() {
        let mut path = WalkPath::default();
        let root = path.push("bin");
        let bin = path.push("busybox");
        assert_eq!(path.as_str(), "/bin/busybox");
        path.restore(bin);
        assert_eq!(path.as_str(), "/bin");
        path.restore(root);
        assert_eq!(path.as_str(), "");
    }

    #[test]
    fn readers_honour_the_requested_byte_order() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16_at(&bytes, 0, true).unwrap(), 0x0201);
        assert_eq!(u16_at(&bytes, 0, false).unwrap(), 0x0102);
        assert_eq!(u32_at(&bytes, 4, false).unwrap(), 0x0506_0708);
        assert_eq!(u64_at(&bytes, 0, true).unwrap(), 0x0807_0605_0403_0201);
        assert!(u32_at(&bytes, 5, true).is_err());
        assert!(slice(&bytes, usize::MAX, 2).is_err());
    }
}
