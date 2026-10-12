//! Flash filesystems on raw MTD: UBI images, UBIFS volume images and JFFS2
//! images.
//!
//! Sources, Linux v6.11 (tag `v6.11`, commit `98f7e32f20d2`) unless stated:
//! - UBI: `drivers/mtd/ubi/ubi-media.h` (erase-counter and
//!   volume-identifier headers, volume table records), `drivers/mtd/ubi/io.c`
//!   (`validate_ec_hdr`, `validate_vid_hdr`), `drivers/mtd/ubi/attach.c`
//!   (`ubi_compare_lebs`, `validate_vid_hdr`) and `drivers/mtd/ubi/vtbl.c`
//!   (`vtbl_check`, `process_lvol`, `check_av`).
//! - UBIFS: `fs/ubifs/ubifs-media.h`, `fs/ubifs/key.h`, `fs/ubifs/scan.c`
//!   (`ubifs_scan`, `ubifs_scan_a_node`), `fs/ubifs/io.c`
//!   (`ubifs_check_node`), `fs/ubifs/sb.c` (`validate_sb`) and
//!   `fs/ubifs/file.c` (`read_block`).
//! - JFFS2: `include/uapi/linux/jffs2.h`, `fs/jffs2/scan.c`
//!   (`jffs2_scan_eraseblock`, `jffs2_scan_inode_node`,
//!   `jffs2_scan_dirent_node`), `fs/jffs2/readinode.c` (`read_dnode`),
//!   `fs/jffs2/nodelist.c` (`jffs2_add_fd_to_list`) and `fs/jffs2/compr*.c`.
//!   LZMA (type `0x08`) comes from the `OpenWrt` v24.10.0 patch
//!   `530-jffs2_make_lzma_available.patch`, not from mainline.
//!
//! UBI headers are big-endian and UBIFS nodes little-endian; JFFS2 nodes use
//! the image's byte order. None of these is the code byte order, and none of
//! these formats names a processor: UBI volumes are classified from their
//! own contents, and UBIFS and JFFS2 regular files are listed when they are
//! a recognized format. Filesystem trees are rebuilt by scanning every node
//! and keeping the newest copy (highest UBIFS sequence number or JFFS2
//! version); the UBIFS index is not walked.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum;
use crate::formats::compressed::{self, size_text, Codec};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{FileFormat, MetadataValue};
use std::borrow::Cow;
use std::collections::BTreeMap;

mod jffs2;
mod ubi;
mod ubifs;

/// A recognized flash filesystem layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// UBI image: PEBs with erase-counter and volume-identifier headers.
    Ubi,
    /// UBIFS volume image: LEB 0 holds the superblock node.
    Ubifs,
    /// JFFS2 image.
    Jffs2 {
        /// Node integers are big-endian.
        big_endian: bool,
    },
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Ubi => FileFormat::Ubi,
            Self::Ubifs => FileFormat::Ubifs,
            Self::Jffs2 { .. } => FileFormat::Jffs2,
        }
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ubi => "UBI image",
            Self::Ubifs => "UBIFS image",
            Self::Jffs2 { big_endian: false } => "JFFS2 image (little-endian)",
            Self::Jffs2 { big_endian: true } => "JFFS2 image (big-endian)",
        }
    }

    /// JFFS2 has a 16-bit node magic and is recognized only when every node
    /// validates.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Jffs2 { .. })
    }
}

/// Magic-bearing layouts: the UBI erase-counter header magic `UBI#` at
/// offset 0, or a UBIFS node header at offset 0 whose type is the
/// superblock.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(&ubi::EC_HDR_MAGIC) {
        Some(Layout::Ubi)
    } else if ubifs::starts_with_superblock(data) {
        Some(Layout::Ubifs)
    } else {
        None
    }
}

/// JFFS2, recognized only when every node header, node, name and data CRC
/// in the image matches and only erased or zeroed (dirty) flash lies
/// between nodes.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    jffs2::detect(data)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::MtdParseError`] for malformed structure, a failed
/// CRC that the format treats as fatal, or a range outside the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Ubi => ubi::parse(data),
        Layout::Ubifs => ubifs::parse(data),
        Layout::Jffs2 { big_endian } => jffs2::parse(data, !big_endian),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::MtdParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated image at 0x{start:X} + {len} B")))
}

/// `N` bytes at `at`.
fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    array(data, at).map(u32::from_be_bytes)
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    array(data, at).map(u64::from_be_bytes)
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    array(data, at).map(u16::from_le_bytes)
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    array(data, at).map(u32::from_le_bytes)
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    array(data, at).map(u64::from_le_bytes)
}

/// The byte at `at`.
fn byte(data: &[u8], at: usize) -> Result<u8> {
    array::<1>(data, at).map(|[b]| b)
}

/// CRC-32 with the register preset to all ones and no final inversion:
/// `crc32(UBI_CRC32_INIT, ...)` in UBI and UBIFS.
fn crc32_ones(bytes: &[u8]) -> u32 {
    checksum::crc32_update(!0, bytes)
}

/// CRC-32 with a zero preset and no final inversion: `crc32(0, ...)` in
/// JFFS2.
fn crc32_zero(bytes: &[u8]) -> u32 {
    checksum::crc32_update(0, bytes)
}

/// Erased flash.
fn is_erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0xff)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Round up to a multiple of `align` (a power of two).
fn align_up(n: usize, align: usize) -> Result<usize> {
    n.checked_add(align - 1)
        .map(|n| n & !(align - 1))
        .ok_or_else(|| error("Alignment overflow"))
}

/// A file range: offset and length of stored bytes, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    offset: usize,
    size: usize,
}

/// What a directory entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    RegularFile,
    Directory,
    Other,
}

/// A live directory entry: the newest entry for its parent and name, and
/// not a deletion.
#[derive(Debug)]
struct Dirent {
    /// Inode number of the directory holding the entry.
    parent: u32,
    name: Vec<u8>,
    /// Inode number the entry names.
    inum: u32,
    kind: EntryKind,
}

/// Longest parent chain followed when building a path; deeper entries,
/// and directory cycles, are unreachable (own bound).
const MAX_PATH_DEPTH: usize = 128;

/// Longest path built, in bytes (own bound, the Linux `PATH_MAX`).
const MAX_PATH_LEN: usize = 4096;

/// Most regular files whose paths are built for one image (own bound).
const MAX_FILES: usize = 65536;

/// A regular file reachable from the root directory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Member {
    /// Full path from `/`.
    path: String,
    /// Inode number; hard links share it.
    inum: u32,
}

/// Regular files reachable from the root directory, sorted by path.
#[derive(Debug, Default)]
struct Tree {
    members: Vec<Member>,
    /// Regular-file entries whose parent chain does not reach the root.
    unreachable: usize,
    /// Regular-file entries beyond [`MAX_FILES`].
    unlisted: usize,
    /// Directory entries.
    directories: usize,
    /// Entries that are neither regular files nor directories.
    others: usize,
}

/// The regular files that `dirents` reach from `root`. A directory has one
/// parent; when several live entries name the same directory inode, the
/// first in `dirents` order is used.
fn regular_files(dirents: &[Dirent], root: u32) -> Tree {
    let mut directories: BTreeMap<u32, &Dirent> = BTreeMap::new();
    let mut tree = Tree::default();
    for dirent in dirents {
        match dirent.kind {
            EntryKind::Directory => {
                tree.directories += 1;
                directories.entry(dirent.inum).or_insert(dirent);
            }
            EntryKind::Other => tree.others += 1,
            EntryKind::RegularFile => {}
        }
    }
    for dirent in dirents.iter().filter(|d| d.kind == EntryKind::RegularFile) {
        if tree.members.len() >= MAX_FILES {
            tree.unlisted += 1;
            continue;
        }
        match path_of(dirent, &directories, root) {
            Some(path) => tree.members.push(Member {
                path,
                inum: dirent.inum,
            }),
            None => tree.unreachable += 1,
        }
    }
    tree.members.sort();
    tree
}

/// `/a/b/name` for an entry, following directory entries up to `root`.
fn path_of(dirent: &Dirent, directories: &BTreeMap<u32, &Dirent>, root: u32) -> Option<String> {
    let mut components = vec![dirent.name.as_slice()];
    let mut parent = dirent.parent;
    let mut len = dirent.name.len() + 1;
    for _ in 0..MAX_PATH_DEPTH {
        if parent == root {
            let mut path = String::with_capacity(len);
            for name in components.iter().rev() {
                path.push('/');
                path.push_str(&String::from_utf8_lossy(name));
            }
            return Some(path);
        }
        let entry = directories.get(&parent)?;
        len += entry.name.len() + 1;
        if len > MAX_PATH_LEN {
            return None;
        }
        components.push(&entry.name);
        parent = entry.parent;
    }
    None
}

/// How an extent's stored bytes become file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// Stored as-is.
    Stored,
    /// No stored bytes: the extent is zeros (JFFS2 `JFFS2_COMPR_ZERO`).
    Zeros,
    /// A stream of one codec.
    Codec(Codec),
    /// JFFS2 zlib: see [`jffs2::zlib`].
    Jffs2Zlib,
    /// JFFS2 (`OpenWrt`) LZMA: see [`jffs2::lzma`].
    Jffs2Lzma,
}

impl Encoding {
    /// Name used in the data-node summary note.
    fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Zeros => "zero-fill",
            Self::Codec(codec) => codec.name(),
            Self::Jffs2Zlib => "zlib",
            Self::Jffs2Lzma => "LZMA",
        }
    }
}

/// One run of file bytes.
#[derive(Debug)]
struct Extent<'a> {
    /// Offset in the file, in bytes.
    file_offset: u64,
    /// Decoded size in bytes.
    size: usize,
    /// The stored bytes.
    stored: &'a [u8],
    /// Offset of the stored bytes in the parsed image.
    offset: usize,
    encoding: Encoding,
}

/// The contents of one regular file (one inode).
#[derive(Debug, Default)]
struct FileData<'a> {
    /// File size in bytes.
    size: u64,
    /// Extents in the order they apply; later extents overwrite earlier
    /// ones where they overlap.
    extents: Vec<Extent<'a>>,
    /// Why the file cannot be extracted, when the metadata says so.
    unsupported: Option<String>,
}

/// Bytes decoded or zero-filled while assembling one image's files,
/// counting recognition prefixes and extents that later ones overwrite
/// (own bound: twice [`MAX_EXTRACTED`]). It bounds the work a hostile
/// image can cause with many overlapping extents or hard links.
const MAX_DECODE_WORK: usize = 2 * MAX_EXTRACTED;

/// Why a file's bytes were not assembled.
#[derive(Debug)]
enum Unassembled {
    /// The image's [`MAX_DECODE_WORK`] budget is spent.
    OverBudget,
    /// An extent does not decode to its declared size.
    Invalid(ClassifierError),
}

impl From<ClassifierError> for Unassembled {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// The decoded bytes of one extent, exactly `extent.size` of them.
fn decode_extent<'a>(extent: &Extent<'a>) -> Result<Cow<'a, [u8]>> {
    let size = extent.size;
    let decoded = match extent.encoding {
        Encoding::Stored => Cow::Borrowed(extent.stored),
        Encoding::Zeros => Cow::Owned(vec![0; size]),
        Encoding::Codec(codec) => {
            let decoded = compressed::decode_limited(codec, extent.stored, size)?;
            // UBIFS and JFFS2 both require LZO1X to consume its whole input
            // (`lzo1x_decompress_safe` returns `LZO_E_INPUT_NOT_CONSUMED`).
            if codec == Codec::Lzo1x && decoded.consumed != Some(extent.stored.len()) {
                return Err(error(format!(
                    "Invalid LZO1X data at 0x{:X}: input not consumed",
                    extent.offset
                )));
            }
            Cow::Owned(decoded.data)
        }
        Encoding::Jffs2Zlib => Cow::Owned(jffs2::zlib(extent.stored, size)?),
        Encoding::Jffs2Lzma => Cow::Owned(jffs2::lzma(extent.stored, size)?),
    };
    if decoded.len() != size {
        return Err(error(format!(
            "Invalid data at 0x{:X}: {} B decoded, {size} B declared",
            extent.offset,
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// The first `len` bytes of a file: extents applied in order, bytes that no
/// extent covers (holes) zero. Only extents that overlap the range are
/// decoded, and each charges its decoded size (or its zero fill) to
/// `work_left`.
fn assemble(
    extents: &[Extent<'_>],
    len: usize,
    work_left: &mut usize,
) -> std::result::Result<Vec<u8>, Unassembled> {
    let mut out = vec![0u8; len];
    for extent in extents {
        let Ok(start) = usize::try_from(extent.file_offset) else {
            continue;
        };
        if start >= len || extent.size == 0 {
            continue;
        }
        let end = start.saturating_add(extent.size).min(len);
        let work = if extent.encoding == Encoding::Zeros {
            end - start
        } else {
            extent.size
        };
        *work_left = work_left.checked_sub(work).ok_or(Unassembled::OverBudget)?;
        let target = &mut out[start..end];
        if extent.encoding == Encoding::Zeros {
            target.fill(0);
        } else {
            let decoded = decode_extent(extent)?;
            target.copy_from_slice(&decoded[..end - start]);
        }
    }
    Ok(out)
}

/// The stored range of a file's extents: from the first stored byte to the
/// end of the last.
fn stored_span(extents: &[Extent<'_>]) -> Option<Span> {
    let start = extents.iter().map(|e| e.offset).min()?;
    let end = extents.iter().map(|e| e.offset + e.stored.len()).max()?;
    Some(Span {
        offset: start,
        size: end - start,
    })
}

/// Bytes of a member decoded to decide whether it is a recognized format
/// (own bound: one UBIFS block, the usual JFFS2 page size).
const RECOGNITION_PREFIX: usize = 4096;

/// Members named in individual notes when they cannot be extracted; the
/// rest are counted (own bound).
const MAX_MEMBER_NOTES: usize = 8;

/// What happened to the regular files of an image that were not listed.
#[derive(Debug, Default)]
struct MemberReport {
    /// Not examined because [`MAX_COMPONENTS`] members were listed.
    unexamined: usize,
    /// Recognized but left out at [`MAX_EXTRACTED`].
    over_budget: usize,
    /// Not extracted because [`MAX_DECODE_WORK`] was spent.
    over_work: usize,
    /// Recognized but larger than [`MAX_PAYLOAD`].
    too_large: usize,
    /// Encrypted or in an unsupported encoding.
    unsupported: usize,
    /// Data that does not decode.
    failed: usize,
    /// Notes for the first failures.
    notes: Vec<String>,
}

impl MemberReport {
    fn fail(&mut self, path: &str, reason: &Unassembled) {
        match reason {
            Unassembled::OverBudget => self.over_work += 1,
            Unassembled::Invalid(e) => {
                self.failed += 1;
                if self.notes.len() < MAX_MEMBER_NOTES {
                    self.notes
                        .push(format!("{path}: data does not decode ({e})"));
                }
            }
        }
    }

    fn unsupported(&mut self, path: &str, reason: &str) {
        self.unsupported += 1;
        if self.notes.len() < MAX_MEMBER_NOTES {
            self.notes.push(format!("{path}: {reason}; not extracted"));
        }
    }

    /// Notes for the container, after the listed members.
    fn into_notes(self) -> Vec<String> {
        let mut notes = self.notes;
        let unnamed = (self.failed + self.unsupported).saturating_sub(notes.len());
        if unnamed > 0 {
            notes.push(format!("{unnamed} further files were not extracted"));
        }
        if self.too_large > 0 {
            notes.push(format!(
                "{} recognized files exceed the {} extraction limit; not extracted",
                self.too_large,
                size_text(MAX_PAYLOAD)
            ));
        }
        if self.over_budget > 0 {
            notes.push(format!(
                "Extraction stopped at {}; {} recognized files not extracted",
                size_text(MAX_EXTRACTED),
                self.over_budget
            ));
        }
        if self.over_work > 0 {
            notes.push(format!(
                "Decoding stopped after {}; {} files not extracted",
                size_text(MAX_DECODE_WORK),
                self.over_work
            ));
        }
        if self.unexamined > 0 {
            notes.push(format!(
                "Member listing stopped at {MAX_COMPONENTS} members; {} files not examined",
                self.unexamined
            ));
        }
        notes
    }
}

/// What examining an inode's contents decided; hard links reuse it.
#[derive(Debug, Clone, Copy)]
enum Examined {
    /// Not listed: not a recognized format, no stored bytes, or reported
    /// in a note.
    Unlisted,
    /// Listed as this child of the container.
    Child(usize),
}

/// A listed member's contents and their stored range.
struct Extracted {
    span: Span,
    contents: Vec<u8>,
}

/// The listing of one image's members, bounded by [`MAX_COMPONENTS`],
/// [`MAX_EXTRACTED`] and [`MAX_DECODE_WORK`].
struct Listing {
    report: MemberReport,
    extracted: usize,
    work_left: usize,
    examined: BTreeMap<u32, Examined>,
}

impl Listing {
    /// Decide whether `file` is listed: its first [`RECOGNITION_PREFIX`]
    /// bytes are assembled first, so files that would not be listed are
    /// never extracted.
    fn extract(&mut self, path: &str, file: &FileData<'_>) -> Option<Extracted> {
        if let Some(reason) = &file.unsupported {
            self.report.unsupported(path, reason);
            return None;
        }
        // No stored bytes: empty, or holes only.
        let span = stored_span(&file.extents)?;
        let Ok(size) = usize::try_from(file.size) else {
            self.report.too_large += 1;
            return None;
        };
        let prefix = match assemble(
            &file.extents,
            size.min(RECOGNITION_PREFIX),
            &mut self.work_left,
        ) {
            Ok(prefix) => prefix,
            Err(reason) => {
                self.report.fail(path, &reason);
                return None;
            }
        };
        if !container::is_recognized(&prefix) {
            return None;
        }
        if size > MAX_PAYLOAD {
            self.report.too_large += 1;
            return None;
        }
        if self.extracted + size > MAX_EXTRACTED {
            self.report.over_budget += 1;
            return None;
        }
        let contents = if size == prefix.len() {
            prefix
        } else {
            match assemble(&file.extents, size, &mut self.work_left) {
                Ok(contents) => contents,
                Err(reason) => {
                    self.report.fail(path, &reason);
                    return None;
                }
            }
        };
        self.extracted += size;
        Some(Extracted { span, contents })
    }

    /// List a hard link to the inode already listed as child `index`, with
    /// a copy of its contents.
    fn push_link(
        &mut self,
        c: &mut Container<'_>,
        index: usize,
        path: &str,
        transform: &'static str,
    ) {
        let first = &c.children[index];
        let size = first.data.len();
        if self.extracted + size > MAX_EXTRACTED {
            self.report.over_budget += 1;
            return;
        }
        self.extracted += size;
        let span = Span {
            offset: first.offset,
            size: first.stored_size,
        };
        let contents = first.data.to_vec();
        c.children
            .push(member_child(path, span, contents, transform));
    }
}

/// A listed member: only classified when it is a recognized format.
fn member_child<'a>(
    path: &str,
    span: Span,
    contents: Vec<u8>,
    transform: &'static str,
) -> Child<'a> {
    Child::decoded(
        path,
        span.offset,
        span.size,
        Cow::Owned(contents),
        transform,
    )
    .if_recognized()
}

/// List the regular files that are a recognized format as children of
/// `c`. `file_of` builds an inode's contents, or returns `None` for a
/// deleted inode; each inode is examined once, and its hard links list the
/// same contents.
fn push_members<'a>(
    c: &mut Container<'a>,
    members: &[Member],
    transform: &'static str,
    file_of: impl Fn(u32) -> Option<FileData<'a>>,
) {
    let mut listing = Listing {
        report: MemberReport::default(),
        extracted: 0,
        work_left: MAX_DECODE_WORK,
        examined: BTreeMap::new(),
    };
    for member in members {
        if c.children.len() >= MAX_COMPONENTS {
            listing.report.unexamined += 1;
            continue;
        }
        match listing.examined.get(&member.inum).copied() {
            None => {
                let extracted =
                    file_of(member.inum).and_then(|file| listing.extract(&member.path, &file));
                let examined = match extracted {
                    Some(Extracted { span, contents }) => {
                        let child = member_child(&member.path, span, contents, transform);
                        c.children.push(child);
                        Examined::Child(c.children.len() - 1)
                    }
                    None => Examined::Unlisted,
                };
                listing.examined.insert(member.inum, examined);
            }
            Some(Examined::Child(index)) => listing.push_link(c, index, &member.path, transform),
            Some(Examined::Unlisted) => {}
        }
    }
    c.notes.extend(listing.report.into_notes());
}

/// `"3 LZO1X, 1 stored"`: how many data nodes use each encoding, most
/// common first.
fn encoding_summary(names: impl Iterator<Item = &'static str>) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for name in names {
        *counts.entry(name).or_default() += 1;
    }
    let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    ranked
        .iter()
        .map(|(name, count)| format!("{count} {name}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The note on a tree's entries.
fn tree_note(tree: &Tree) -> String {
    let mut parts = vec![format!(
        "{} regular files, {} directories, {} other entries",
        tree.members.len() + tree.unreachable + tree.unlisted,
        tree.directories,
        tree.others
    )];
    if tree.unreachable > 0 {
        parts.push(format!(
            "{} files are not reachable from the root directory",
            tree.unreachable
        ));
    }
    if tree.unlisted > 0 {
        parts.push(format!(
            "paths were built for the first {MAX_FILES} files only"
        ));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirent(parent: u32, name: &str, inum: u32, kind: EntryKind) -> Dirent {
        Dirent {
            parent,
            name: name.as_bytes().to_vec(),
            inum,
            kind,
        }
    }

    fn member(path: &str, inum: u32) -> Member {
        Member {
            path: path.to_string(),
            inum,
        }
    }

    fn stored(file_offset: u64, data: &[u8], offset: usize) -> Extent<'_> {
        Extent {
            file_offset,
            size: data.len(),
            stored: data,
            offset,
            encoding: Encoding::Stored,
        }
    }

    #[test]
    fn crc_variants_match_the_kernel_seeds() {
        // A ones seed without final inversion is CRC-32/JAMCRC, the IEEE
        // check value inverted. The zero-seed value is
        // `~zlib.crc32(data, 0xFFFFFFFF)` (Python 3).
        assert_eq!(crc32_ones(b"123456789"), !0xcbf4_3926);
        assert_eq!(crc32_zero(b""), 0);
        assert_eq!(crc32_zero(b"123456789"), 0x2dfd_2d88);
    }

    #[test]
    fn paths_follow_directory_entries_to_the_root() {
        let dirents = vec![
            dirent(1, "bin", 10, EntryKind::Directory),
            dirent(10, "tool", 11, EntryKind::RegularFile),
            dirent(1, "top", 12, EntryKind::RegularFile),
            dirent(99, "orphan", 13, EntryKind::RegularFile),
            dirent(20, "loop", 20, EntryKind::Directory),
            dirent(20, "in-loop", 21, EntryKind::RegularFile),
            dirent(1, "link", 14, EntryKind::Other),
        ];
        let tree = regular_files(&dirents, 1);
        assert_eq!(
            tree.members,
            vec![member("/bin/tool", 11), member("/top", 12)]
        );
        assert_eq!(tree.unreachable, 2);
        assert_eq!(tree.directories, 2);
        assert_eq!(tree.others, 1);
        assert_eq!(
            tree_note(&tree),
            "4 regular files, 2 directories, 1 other entries; \
             2 files are not reachable from the root directory"
        );
    }

    #[test]
    fn assembly_applies_extents_in_order_and_zero_fills_holes() {
        let extents = vec![
            stored(0, b"aaaaaaaa", 0x100),
            stored(2, b"bb", 0x40),
            Extent {
                file_offset: 6,
                size: 1 << 30,
                stored: &[],
                offset: 0x80,
                encoding: Encoding::Zeros,
            },
        ];
        let mut work = MAX_DECODE_WORK;
        assert_eq!(
            assemble(&extents, 12, &mut work).unwrap(),
            b"aabbaa\0\0\0\0\0\0"
        );
        // Eight and two decoded bytes, six zero-filled.
        assert_eq!(MAX_DECODE_WORK - work, 16);
        assert_eq!(assemble(&extents, 3, &mut work).unwrap(), b"aab");
        assert_eq!(
            stored_span(&extents),
            Some(Span {
                offset: 0x40,
                size: 0xC8
            })
        );
    }

    #[test]
    fn assembly_stops_when_the_work_budget_is_spent() {
        let extents = vec![stored(0, b"abcd", 0), stored(0, b"efgh", 4)];
        let mut work = 6;
        assert!(matches!(
            assemble(&extents, 4, &mut work),
            Err(Unassembled::OverBudget)
        ));
    }

    #[test]
    fn extents_must_decode_to_their_declared_size() {
        let extent = Extent {
            size: 4,
            ..stored(0, b"abc", 0)
        };
        let mut work = MAX_DECODE_WORK;
        assert!(matches!(
            assemble(&[extent], 4, &mut work),
            Err(Unassembled::Invalid(_))
        ));
    }

    #[test]
    fn hard_links_share_one_examination() {
        let elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
        let mut c = Container::new(FileFormat::Jffs2, "test", "test");
        let members = [member("/a", 5), member("/b", 5), member("/text", 6)];
        let examined = std::cell::Cell::new(0);
        push_members(&mut c, &members, "test file", |inum| {
            examined.set(examined.get() + 1);
            let data: &[u8] = if inum == 5 { elf } else { b"text" };
            Some(FileData {
                size: data.len() as u64,
                extents: vec![stored(0, data, 0x10)],
                unsupported: None,
            })
        });
        assert_eq!(examined.get(), 2);
        let labels: Vec<&str> = c.children.iter().map(|ch| ch.label.as_str()).collect();
        assert_eq!(labels, ["/a", "/b"]);
        assert_eq!(c.children[1].data.as_ref(), elf);
        assert_eq!(c.children[1].offset, 0x10);
    }
}
