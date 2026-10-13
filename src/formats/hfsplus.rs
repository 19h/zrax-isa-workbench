//! HFS Plus and HFSX volumes: the volume header and the HFS wrapper, the
//! extents overflow, catalog and attributes B-trees, hard and symbolic
//! links, decmpfs (`AppleFSCompression`) files, and a catalog walk from the
//! root folder that lists regular files in a recognized format as members.
//!
//! Sources:
//! - [TN1150] Apple Technical Note TN1150, "HFS Plus Volume Format"
//!   (revision of 2004-03-05,
//!   <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>,
//!   SHA-256 `fd1ca22de7ec38c044bcc726b5bc14b5b0ee63f1b242039f8bc4f3728e247cb5`):
//!   "Volume Header", "B-Trees", "Catalog File", "Extents Overflow File",
//!   "Attributes File", "Hard Links", "Symbolic Links", "Journal", "HFSX"
//!   and "HFS Wrapper".
//! - [HFS] apple-oss-distributions/hfs, tag `hfs-715.120.4`:
//!   `core/hfs_format.h` (on-disk structures and constants, identical to the
//!   macOS 27.0 SDK copy), `core/BTreesPrivate.h` (`kMaxTreeDepth`),
//!   `core/BTreeTreeOps.c` (`SearchTree`), `core/hfs_catalog.c`
//!   (`cat_lookupbykey`, `cat_resolvelink`, the `':'` slash substitute) and
//!   `core/hfs_catalog.h` (`kHFSAliasType`, `kHFSAliasCreator`).
//! - [XNU] apple-oss-distributions/xnu, tag `xnu-11215.1.10`:
//!   `bsd/vfs/vfs_utfconv.c` (`UCS_ALT_NULL`); the macOS SDK `sys/stat.h`
//!   (`UF_COMPRESSED`).
//! - decmpfs data (the attribute's header, the compression types and the
//!   resource fork's chunk tables) is decoded by `formats::decmpfs`, shared
//!   with APFS, which cites its sources (xnu `bsd/sys/decmpfs.h` and
//!   `bsd/kern/decmpfs.c`, The Sleuth Kit, libfshfs and apfs-fuse).
//!
//! Volume structures are big-endian; decmpfs headers and chunk tables are
//! little-endian. Block numbers count allocation blocks of the volume's
//! `blockSize`; offsets in notes, metadata and members are file bytes. The
//! volume names no processor, so members are classified from their own
//! bytes.
//!
//! A volume larger than the input (`totalBlocks` times `blockSize`, [TN1150]
//! "Volume Header"; containers hand on the first 64 MiB of a larger
//! partition) is read as a truncated volume when its header, its B-tree
//! header nodes and its root folder are present: B-tree nodes past the end
//! of the input are skipped and counted, and files are listed only when
//! all of their data is present.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::Container;
use crate::formats::decmpfs;
use crate::types::FileFormat;
use std::cell::Cell;

mod attributes;
mod btree;
mod catalog;
mod fork;
mod header;
mod walk;

use btree::{BTree, TreeKind};
use header::{ForkData, VolumeHeader};

/// File offset of the volume header, and of the HFS master directory block
/// in a wrapper ([TN1150] "Volume Header", "HFS Wrapper").
const VOLUME_HEADER_OFFSET: usize = 1024;

/// Size of the volume header ([TN1150] "Volume Header").
const VOLUME_HEADER_SIZE: usize = 512;

/// `kHFSPlusSigWord` (`H+`) and `kHFSXSigWord` (`HX`).
const HFS_PLUS_SIG_WORD: u16 = 0x482b;
const HFSX_SIG_WORD: u16 = 0x4858;

/// `kHFSSigWord` (`BD`), the signature of an HFS master directory block.
const HFS_SIG_WORD: u16 = 0x4244;

/// `kHFSPlusVersion` and `kHFSXVersion`.
const HFS_PLUS_VERSION: u16 = 4;
const HFSX_VERSION: u16 = 5;

/// Volume attribute bits ([TN1150] "Volume Attributes"; [HFS]
/// `kHFSVolumeInconsistentMask`).
const VOLUME_UNMOUNTED: u32 = 0x0000_0100;
const BOOT_VOLUME_INCONSISTENT: u32 = 0x0000_0800;
const VOLUME_JOURNALED: u32 = 0x0000_2000;
const VOLUME_INCONSISTENT: u32 = 0x0000_4000;
/// `kHFSContentProtectionMask`: files may be encrypted with per-file keys
/// ([HFS] `hfs_format.h`).
const CONTENT_PROTECTION: u32 = 0x4000_0000;

/// Reserved catalog node IDs ([TN1150] "Catalog File").
const ROOT_PARENT_ID: u32 = 1;
const ROOT_FOLDER_ID: u32 = 2;
const EXTENTS_FILE_ID: u32 = 3;
const CATALOG_FILE_ID: u32 = 4;
const STARTUP_FILE_ID: u32 = 7;
const ATTRIBUTES_FILE_ID: u32 = 8;
const FIRST_USER_CATALOG_NODE_ID: u32 = 16;

/// Fork types in extent keys ([TN1150] "Extents Overflow File Key").
const DATA_FORK: u8 = 0x00;
const RESOURCE_FORK: u8 = 0xff;

/// `kJIJournalInFSMask`, `kJIJournalOnOtherDeviceMask` and
/// `kJIJournalNeedInitMask` ([TN1150] "Journal Info Block").
const JOURNAL_IN_FS: u32 = 0x1;
const JOURNAL_ON_OTHER_DEVICE: u32 = 0x2;
const JOURNAL_NEED_INIT: u32 = 0x4;

/// `JOURNAL_HEADER_MAGIC` and `ENDIAN_MAGIC` ([TN1150] "Journal Header").
const JOURNAL_HEADER_MAGIC: u32 = 0x4a4e_4c78;
const JOURNAL_ENDIAN_MAGIC: u32 = 0x1234_5678;

/// Journal info block: flags (4), `device_signature` (32), then the
/// journal offset and size (8 each).
const JOURNAL_INFO_OFFSET_FIELD: usize = 36;
const JOURNAL_INFO_SIZE_FIELD: usize = 44;

/// Journal header: magic, endian (4 each), start, end, size (8 each).
const JOURNAL_HEADER_SIZE: usize = 32;

/// B-tree node reads are limited to this many times the volume size. A
/// search reads one node per tree level, and the walk searches the catalog
/// once per folder and the attributes B-tree once per compressed file, so
/// the index nodes are read many times. The factor is ours.
const METADATA_READ_FACTOR: u64 = 64;

/// An HFS Plus volume, an HFSX volume, or an HFS Plus volume embedded in an
/// HFS wrapper ([TN1150] "HFSX", "HFS Wrapper"; an HFSX volume never has a
/// wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `H+` volume header at 1024, version 4.
    HfsPlus,
    /// `HX` volume header at 1024, version 5 or later.
    Hfsx,
    /// HFS master directory block (`BD`) at 1024 whose embedded volume
    /// (`drEmbedSigWord` `H+`) holds an HFS Plus volume header.
    HfsWrapper,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::HfsPlus | Self::HfsWrapper => FileFormat::HfsPlus,
            Self::Hfsx => FileFormat::Hfsx,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::HfsPlus => "HFS+",
            Self::Hfsx => "HFSX",
            Self::HfsWrapper => "HFS+ in an HFS wrapper",
        }
    }

    /// No layout is weak: each needs a signature and version and a
    /// consistent volume header.
    pub fn is_weak(self) -> bool {
        match self {
            Self::HfsPlus | Self::Hfsx | Self::HfsWrapper => false,
        }
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::HfsPlusParseError {
        message: message.into(),
    }
}

/// Why a read of the volume failed.
#[derive(Debug)]
enum Fault {
    /// The volume is invalid; the error says how.
    Invalid(ClassifierError),
    /// The bytes lie inside the volume but past the end of the input, which
    /// holds only the start of a truncated volume.
    Absent,
}

impl From<ClassifierError> for Fault {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// The result of a read of the volume's bytes.
type ReadResult<T> = std::result::Result<T, Fault>;

/// A read that failed because the volume is invalid.
fn invalid<T>(message: impl Into<String>) -> ReadResult<T> {
    Err(Fault::Invalid(error(message)))
}

/// A size in bytes as text; a size past the address space in bytes.
fn volume_size_text(size: u64) -> String {
    usize::try_from(size).map_or_else(|_| format!("{size} B"), size_text)
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated volume at 0x{start:X} + {len} B")))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_be_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// HFS+ as the family of the shared decmpfs decoder: its error variant and
/// reads, xnu's attribute limit (`MAX_DECMPFS_XATTR_SIZE`; the attribute is
/// stored inline in the attributes B-tree), and the chunk table's and type 1
/// size errors as this reader reported them before the decoder was shared.
struct HfsPlusFamily;

impl decmpfs::Family for HfsPlusFamily {
    const MAX_ATTRIBUTE_SIZE: usize = decmpfs::MAX_DECMPFS_XATTR_SIZE;
    const REFUSES_SHORT_FORKS: bool = false;
    const EMPTY_TYPE1_IS_TRUNCATED: bool = false;

    fn error(message: impl Into<String>) -> ClassifierError {
        error(message)
    }

    fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
        slice(data, start, len)
    }
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A four-character code as text, with non-printable bytes as `.`.
fn four_cc(value: u32) -> String {
    value
        .to_be_bytes()
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect()
}

/// Detect an HFS Plus or HFSX volume header at 1024, or an HFS wrapper at
/// 1024 whose embedded volume holds one. Detection checks the signature,
/// the version, a power-of-two block size of at least 512 B, the free block
/// count and catalog and extents forks that lie inside the volume. The
/// volume size, the B-trees and the files are checked by
/// [`parse_container`], so a truncated or damaged volume is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if let Ok(volume) = VolumeHeader::read(data, 0) {
        return Some(volume.layout());
    }
    let wrapper = header::Wrapper::parse(data).ok()?;
    let embedded = VolumeHeader::read(data, wrapper.offset).ok()?;
    (embedded.signature == HFS_PLUS_SIG_WORD).then_some(Layout::HfsWrapper)
}

/// Bytes of the input that hold the volume, and where they start.
struct Placement {
    /// File offset of volume byte 0.
    offset: usize,
    /// Size of the wrapper's embedded extent, which the volume must fit in;
    /// `None` for a volume that starts the input.
    extent: Option<usize>,
    /// Bytes of the volume's region present from `offset`: to the end of
    /// the input, or of the wrapper's embedded extent.
    present: usize,
    /// The HFS wrapper, if the volume is embedded in one.
    wrapper: Option<header::Wrapper>,
}

/// Where the volume lies in `data` for `layout`. A wrapper whose embedded
/// extent passes the end of the input is placed when the embedded volume
/// header is present; the volume is then read as a truncated volume.
fn place(data: &[u8], layout: Layout) -> Result<Placement> {
    match layout {
        Layout::HfsPlus | Layout::Hfsx => Ok(Placement {
            offset: 0,
            extent: None,
            present: data.len(),
            wrapper: None,
        }),
        Layout::HfsWrapper => {
            let wrapper = header::Wrapper::parse(data)?;
            let header_end = wrapper
                .offset
                .checked_add(VOLUME_HEADER_OFFSET + VOLUME_HEADER_SIZE);
            let present = match wrapper.offset.checked_add(wrapper.size) {
                Some(end) if end <= data.len() => wrapper.size,
                Some(_) if header_end.is_some_and(|end| end <= data.len()) => {
                    data.len() - wrapper.offset
                }
                _ => return Err(truncated_wrapper(&wrapper, data.len())),
            };
            Ok(Placement {
                offset: wrapper.offset,
                extent: Some(wrapper.size),
                present,
                wrapper: Some(wrapper),
            })
        }
    }
}

/// The error for a wrapper whose embedded extent passes the end of the
/// input.
fn truncated_wrapper(wrapper: &header::Wrapper, input_size: usize) -> ClassifierError {
    error(format!(
        "Truncated HFS wrapper: the embedded volume at 0x{:X} needs {} B, {} B present",
        wrapper.offset,
        wrapper.size,
        input_size.saturating_sub(wrapper.offset)
    ))
}

/// The error for a volume larger than the bytes of its region: `present`
/// bytes of the input, or of the wrapper's embedded extent.
fn truncated_volume(header: &VolumeHeader, present: usize) -> ClassifierError {
    error(format!(
        "Truncated volume: {} blocks of {} need {} B, {present} B present",
        header.total_blocks,
        size_text(header.block_size as usize),
        header.size()
    ))
}

impl Placement {
    /// Whether the wrapper's embedded extent passes the end of the input.
    fn is_wrapper_cut(&self) -> bool {
        self.extent.is_some_and(|extent| self.present < extent)
    }

    /// The error for a volume that does not fit in its region, or whose
    /// header nodes or root folder lie past the end of the input: the
    /// truncated wrapper, or the truncated volume.
    fn truncation_error(&self, header: &VolumeHeader, input_size: usize) -> ClassifierError {
        match &self.wrapper {
            Some(wrapper) if self.is_wrapper_cut() => truncated_wrapper(wrapper, input_size),
            _ => truncated_volume(header, self.present),
        }
    }
}

/// The volume's bytes and header, with the metadata read budget.
struct Volume<'a> {
    /// The volume's `totalBlocks` allocation blocks, or the bytes of them
    /// present when the input ends inside the volume.
    data: &'a [u8],
    /// File offset of volume byte 0.
    base: usize,
    header: VolumeHeader,
    /// Bytes of B-tree nodes the reader may still read; see
    /// [`Volume::charge`].
    metadata_budget: Cell<u64>,
}

impl<'a> Volume<'a> {
    fn block_size(&self) -> u64 {
        u64::from(self.header.block_size)
    }

    /// File offset of volume byte `at`.
    fn file_offset(&self, at: usize) -> usize {
        self.base + at
    }

    /// Whether the input ends before the volume does.
    fn is_truncated(&self) -> bool {
        (self.data.len() as u64) < self.header.size()
    }

    /// The bytes of the volume present, as text for notes.
    fn present_text(&self) -> String {
        size_text(self.data.len())
    }

    /// Check that `count` allocation blocks from block `start` lie inside
    /// the volume.
    fn check_extent(&self, start: u32, count: u32) -> Result<()> {
        let end = u64::from(start) + u64::from(count);
        if end > u64::from(self.header.total_blocks) {
            return Err(error(format!(
                "Invalid extent: blocks 0x{start:X} + {count} beyond the {} blocks of the volume",
                self.header.total_blocks
            )));
        }
        Ok(())
    }

    /// The bytes of `count` allocation blocks from block `start`.
    fn blocks(&self, start: u32, count: u32) -> ReadResult<&'a [u8]> {
        self.check_extent(start, count)?;
        let first = u64::from(start) * self.block_size();
        self.present(first, u64::from(count) * self.block_size())
    }

    /// The `len` bytes at volume offset `at`, a range inside the volume;
    /// absent when they pass the end of the input.
    fn present(&self, at: u64, len: u64) -> ReadResult<&'a [u8]> {
        let range = at
            .checked_add(len)
            .filter(|&end| end <= self.data.len() as u64)
            .and_then(|end| Some(usize::try_from(at).ok()?..usize::try_from(end).ok()?));
        match range {
            Some(range) => Ok(&self.data[range]),
            None => Err(Fault::Absent),
        }
    }

    /// What the metadata read limit is a multiple of, for messages.
    fn budget_basis(&self) -> String {
        if self.is_truncated() {
            format!("the {} present", self.present_text())
        } else {
            "the volume size".to_string()
        }
    }

    /// Account for `size` bytes of metadata about to be read.
    fn charge(&self, size: usize) -> Result<()> {
        let remaining = self.metadata_budget.get();
        let Some(left) = remaining.checked_sub(size as u64) else {
            self.metadata_budget.set(0);
            return Err(error(format!(
                "Invalid metadata: more than {} B of B-tree nodes read ({METADATA_READ_FACTOR} times \
                 {})",
                (self.data.len() as u64).saturating_mul(METADATA_READ_FACTOR),
                self.budget_basis()
            )));
        };
        self.metadata_budget.set(left);
        Ok(())
    }

    /// The metadata read limit was reached; the walk stops.
    fn is_exhausted(&self) -> bool {
        self.metadata_budget.get() == 0
    }
}

/// A volume with its B-trees opened.
struct Filesystem<'a> {
    vol: Volume<'a>,
    /// The extents overflow B-tree, unless its fork is empty.
    extents: Option<BTree>,
    catalog: BTree,
    /// The attributes B-tree, if the volume has one.
    attributes: Option<BTree>,
}

impl<'a> Filesystem<'a> {
    /// Open the extents overflow, catalog and attributes B-trees. The
    /// extents overflow file's own extents are all in the volume header
    /// ([TN1150] "Core Concepts").
    fn open(vol: Volume<'a>) -> ReadResult<Self> {
        let header = &vol.header;
        let extents = if header.extents_file.logical_size == 0 {
            None
        } else {
            let fork = special_fork(&vol, None, &header.extents_file, EXTENTS_FILE_ID)?;
            Some(BTree::open(&vol, TreeKind::Extents, fork)?)
        };
        let catalog_fork = special_fork(
            &vol,
            extents.as_ref(),
            &header.catalog_file,
            CATALOG_FILE_ID,
        )?;
        let catalog = BTree::open(&vol, TreeKind::Catalog, catalog_fork)?;
        // No attributes file when its first extent has no blocks
        // ([TN1150] "Attributes File").
        let attributes = if header.attributes_file.extents[0].block_count == 0 {
            None
        } else {
            let fork = special_fork(
                &vol,
                extents.as_ref(),
                &header.attributes_file,
                ATTRIBUTES_FILE_ID,
            )?;
            Some(BTree::open(&vol, TreeKind::Attributes, fork)?)
        };
        Ok(Self {
            vol,
            extents,
            catalog,
            attributes,
        })
    }
}

/// The whole data fork of a special file, with its overflow extents.
fn special_fork(
    vol: &Volume<'_>,
    extents: Option<&BTree>,
    data: &ForkData,
    file_id: u32,
) -> ReadResult<fork::Fork> {
    fork::resolve(vol, extents, data, file_id, DATA_FORK, data.logical_size)
}

/// A read of a structure the volume cannot be listed without: bytes past
/// the end of the input are the error `truncation`.
fn needed<T>(read: ReadResult<T>, truncation: impl FnOnce() -> ClassifierError) -> Result<T> {
    match read {
        Ok(value) => Ok(value),
        Err(Fault::Invalid(e)) => Err(e),
        Err(Fault::Absent) => Err(truncation()),
    }
}

/// Parse an HFS Plus or HFSX volume into the shared container model.
/// Regular files whose first bytes are a recognized format are its
/// children, labeled by their path; decmpfs files are decoded first.
///
/// # Errors
///
/// [`ClassifierError::HfsPlusParseError`] for an invalid volume header or
/// wrapper, an unsupported HFSX version, a volume larger than its wrapper's
/// embedded extent or followed by data other than padding, an invalid
/// extents, catalog or attributes B-tree header, or a missing root folder,
/// and for a volume larger than the input whose B-tree header nodes or
/// root folder lie past the end of the input. Damage below the root folder
/// is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let placement = place(data, layout)?;
    let header = VolumeHeader::read(data, placement.offset)?;
    if header.signature == HFSX_SIG_WORD && header.version != HFSX_VERSION {
        // [TN1150] "HFSX": an implementation must not access an HFSX
        // volume whose version it does not recognize.
        return Err(error(format!(
            "Unsupported HFSX version {}",
            header.version
        )));
    }
    let volume_size = header.size();
    if placement
        .extent
        .is_some_and(|extent| volume_size > extent as u64)
    {
        return Err(placement.truncation_error(&header, data.len()));
    }
    let available = &data[placement.offset..placement.offset + placement.present];
    let consumed = match usize::try_from(volume_size)
        .ok()
        .filter(|&size| size <= available.len())
    {
        Some(size) => consumed_size(data, available, size, &placement, &header)?,
        // The input ends inside the volume: all of it belongs to the volume.
        None => data.len(),
    };
    let present = volume_bytes(available, volume_size);
    let declared = header.clone();
    let truncation = || placement.truncation_error(&declared, data.len());
    let vol = Volume {
        data: present,
        base: placement.offset,
        header,
        metadata_budget: Cell::new((present.len() as u64).saturating_mul(METADATA_READ_FACTOR)),
    };
    // The B-tree header nodes and the root folder must be present; without
    // them nothing can be listed.
    let fs = needed(Filesystem::open(vol), truncation)?;
    let root = needed(walk::root(&fs), truncation)?;
    let mut c = Container::new(layout.format(), layout.label(), "hfsplus");
    c.consumed = consumed;
    describe(&fs, layout, placement.wrapper.as_ref(), &mut c);
    journal_notes(&fs, &mut c);
    walk::walk(&fs, root, &mut c);
    walk::startup_file(&fs, &mut c);
    Ok(c)
}

/// The bytes of a volume of `size` bytes present in `available`: all of
/// them, or those before the end of the input.
fn volume_bytes(available: &[u8], size: u64) -> &[u8] {
    let present = usize::try_from(size).map_or(available.len(), |size| size.min(available.len()));
    &available[..present]
}

/// The bytes of the input a complete volume of `size` bytes consumes, after
/// checking what follows it in `available`.
fn consumed_size(
    data: &[u8],
    available: &[u8],
    size: usize,
    placement: &Placement,
    header: &VolumeHeader,
) -> Result<usize> {
    // A disk that is not a multiple of the block size ends in less than one
    // block that no allocation block counts; it holds the alternate volume
    // header ([TN1150] "Volume Header"). Within a wrapper, the rest of the
    // embedded extent belongs to the wrapper's allocation.
    let trailing = &available[size..];
    if placement.wrapper.is_none()
        && trailing.len() >= header.block_size as usize
        && !is_padding(trailing)
    {
        return Err(error(format!(
            "Invalid trailing data: {} B after the volume at 0x{size:X} are not padding",
            trailing.len()
        )));
    }
    // A wrapper's own structures surround the embedded volume, and a
    // remainder shorter than a block belongs to the disk; longer padding
    // does not.
    let consumed = if placement.wrapper.is_some() || trailing.len() < header.block_size as usize {
        data.len()
    } else {
        size
    };
    Ok(consumed)
}

/// Summary notes and metadata from the volume header and the catalog
/// B-tree header.
fn describe(
    fs: &Filesystem<'_>,
    layout: Layout,
    wrapper: Option<&header::Wrapper>,
    c: &mut Container<'_>,
) {
    let header = &fs.vol.header;
    c.notes.push(format!(
        "{} volume: {} allocation blocks of {}; catalog B-tree of {} nodes of {}, depth {}",
        layout.label(),
        header.total_blocks,
        size_text(header.block_size as usize),
        fs.catalog.total_nodes,
        size_text(fs.catalog.node_size),
        fs.catalog.depth
    ));
    if fs.vol.is_truncated() {
        c.notes.push(format!(
            "Volume truncated: {} of {} present; files are listed only when all of their data is \
             present",
            fs.vol.present_text(),
            volume_size_text(header.size())
        ));
    }
    if let Some(wrapper) = wrapper {
        c.notes.push(format!(
            "HFS wrapper \"{}\": embedded volume at 0x{:X}, {}; the wrapper's own files are not \
             read",
            wrapper.volume_name,
            wrapper.offset,
            size_text(wrapper.size)
        ));
        c.push_metadata(
            "hfsplus_wrapper_offset",
            "Embedded volume offset",
            wrapper.offset as u64,
        );
    }
    if header.signature == HFSX_SIG_WORD {
        let names = match fs.catalog.key_compare_type {
            btree::BINARY_COMPARE => "case-sensitive names (keyCompareType 0xBC)".to_string(),
            btree::CASE_FOLDING => "case-insensitive names (keyCompareType 0xCF)".to_string(),
            other => format!("unknown keyCompareType 0x{other:02X}"),
        };
        c.notes.push(format!("HFSX catalog: {names}"));
    }
    if header.attributes & VOLUME_UNMOUNTED == 0 {
        c.notes
            .push("The volume was not unmounted cleanly (kHFSVolumeUnmountedBit clear)".into());
    }
    if header.attributes & (BOOT_VOLUME_INCONSISTENT | VOLUME_INCONSISTENT) != 0 {
        c.notes
            .push("The volume header marks the volume inconsistent".into());
    }
    if header.attributes & CONTENT_PROTECTION != 0 {
        c.notes.push(
            "Content protection (kHFSContentProtectionBit): file contents may be encrypted with \
             per-file keys, which the reader does not have"
                .into(),
        );
    }
    c.notes.push(
        "No processor field: the volume header and catalog name no CPU; members are classified \
         from their own bytes"
            .into(),
    );

    let signature = if header.signature == HFSX_SIG_WORD {
        "HX"
    } else {
        "H+"
    };
    c.push_metadata("hfsplus_signature", "Signature", signature);
    c.push_metadata("hfsplus_version", "Version", u64::from(header.version));
    c.push_metadata(
        "hfsplus_last_mounted_version",
        "Last mounted version",
        four_cc(header.last_mounted_version),
    );
    c.push_metadata(
        "hfsplus_block_size",
        "Allocation block size (B)",
        u64::from(header.block_size),
    );
    c.push_metadata(
        "hfsplus_total_blocks",
        "Allocation blocks",
        u64::from(header.total_blocks),
    );
    c.push_metadata(
        "hfsplus_free_blocks",
        "Free allocation blocks",
        u64::from(header.free_blocks),
    );
    c.push_metadata(
        "hfsplus_file_count",
        "Files (volume header)",
        u64::from(header.file_count),
    );
    c.push_metadata(
        "hfsplus_folder_count",
        "Folders (volume header)",
        u64::from(header.folder_count),
    );
    c.push_metadata(
        "hfsplus_catalog_node_size",
        "Catalog node size (B)",
        fs.catalog.node_size as u64,
    );
}

/// Notes on the journal, which is located but never replayed.
fn journal_notes(fs: &Filesystem<'_>, c: &mut Container<'_>) {
    let header = &fs.vol.header;
    if header.attributes & VOLUME_JOURNALED == 0 {
        return;
    }
    match journal(&fs.vol) {
        Ok(text) => c.notes.push(text),
        Err(Fault::Invalid(e)) => c.notes.push(format!(
            "Journaled volume; the journal could not be read: {}",
            walk::message(e)
        )),
        Err(Fault::Absent) => c.notes.push(format!(
            "Journaled volume; the journal lies past the {} present and was not read",
            fs.vol.present_text()
        )),
    }
}

/// What the journal info block and the journal header say.
fn journal(vol: &Volume<'_>) -> ReadResult<String> {
    let info = vol.blocks(vol.header.journal_info_block, 1)?;
    let flags = be_u32(info, 0)?;
    if flags & JOURNAL_ON_OTHER_DEVICE != 0 || flags & JOURNAL_IN_FS == 0 {
        return Ok("Journaled volume; the journal is on another device and was not read".into());
    }
    let offset = be_u64(info, JOURNAL_INFO_OFFSET_FIELD)?;
    let size = be_u64(info, JOURNAL_INFO_SIZE_FIELD)?;
    let header_end = offset.checked_add(JOURNAL_HEADER_SIZE as u64);
    if header_end.map_or(true, |end| end > vol.header.size()) {
        return invalid(format!("Invalid journal offset 0x{offset:X}"));
    }
    let location = format!(
        "journal of {} at 0x{:X}",
        size_text(usize::try_from(size).unwrap_or(usize::MAX)),
        vol.base as u64 + offset
    );
    if flags & JOURNAL_NEED_INIT != 0 {
        return Ok(format!(
            "Journaled volume: {location} needs initialization and holds no transactions"
        ));
    }
    // The journal header is written in the byte order of the host that
    // wrote it; ENDIAN_MAGIC tells which ([TN1150] "Journal Header").
    let journal_header = vol.present(offset, JOURNAL_HEADER_SIZE as u64)?;
    let le = if be_u32(journal_header, 0)? == JOURNAL_HEADER_MAGIC {
        false
    } else if le_u32(journal_header, 0)? == JOURNAL_HEADER_MAGIC {
        true
    } else {
        return invalid(format!(
            "Invalid journal header magic 0x{:08X}",
            be_u32(journal_header, 0)?
        ));
    };
    let read_u64 = |at| {
        if le {
            le_u64(journal_header, at)
        } else {
            be_u64(journal_header, at)
        }
    };
    let endian = if le {
        le_u32(journal_header, 4)?
    } else {
        be_u32(journal_header, 4)?
    };
    if endian != JOURNAL_ENDIAN_MAGIC {
        return invalid(format!("Invalid journal endian field 0x{endian:08X}"));
    }
    let start = read_u64(8)?;
    let end = read_u64(16)?;
    if start == end {
        Ok(format!(
            "Journaled volume: {location}, empty (no transactions); not replayed"
        ))
    } else {
        Ok(format!(
            "Journaled volume: {location} holds transactions that were not replayed; metadata \
             may be stale"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_character_codes_show_unprintable_bytes_as_dots() {
        assert_eq!(four_cc(0x4846_534a), "HFSJ");
        assert_eq!(four_cc(0x3130_2e30), "10.0");
        assert_eq!(four_cc(0x0000_0001), "....");
    }

    #[test]
    fn layouts_name_their_formats() {
        assert_eq!(Layout::HfsPlus.format(), FileFormat::HfsPlus);
        assert_eq!(Layout::HfsWrapper.format(), FileFormat::HfsPlus);
        assert_eq!(Layout::Hfsx.format(), FileFormat::Hfsx);
        assert!(!Layout::Hfsx.is_weak());
    }
}
