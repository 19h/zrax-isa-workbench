//! APFS containers: the container superblock and its checkpoints, the
//! container and volume object maps, volume superblocks, the file-system
//! tree of each volume, and a directory walk from each volume's root that
//! lists regular files in a recognized format as members, decoding decmpfs
//! (`AppleFSCompression`) files first. The embedded EFI driver, when the
//! container has one, is listed last.
//!
//! Sources:
//! - [REF] Apple, "Apple File System Reference", revision of 2020-06-22
//!   (<https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>,
//!   SHA-256 `74c3db584971aea2b11549ca25799ead824e1bd8994e94cd3f8665ce5aea79cc`):
//!   "Objects", "EFI Jumpstart", "Container" (including "Mounting an Apple
//!   File System Partition"), "Object Maps", "Volumes", "File-System
//!   Objects", "File-System Constants", "Data Streams", "Extended Fields",
//!   "B-Trees", "Encryption" and "Sealed Volumes".
//! - [FUSE] sgan81/apfs-fuse commit
//!   `66b86bd525e8cb90f9012543be89b1f092b75cf3`: `ApfsLib/Util.cpp`
//!   (`Fletcher64`, `VerifyBlock`), `ApfsLib/ApfsContainer.cpp` (the
//!   checkpoint scan), `ApfsLib/ApfsVolume.cpp`, `ApfsLib/BTree.cpp`,
//!   `ApfsLib/ApfsDir.cpp` (directory record keys, file extents) and
//!   `ApfsLib/Decmpfs.cpp` (decmpfs types and chunk tables), for what [REF]
//!   leaves open.
//! - [LIBFS] libyal/libfsapfs commit
//!   `cc122619a0fa5cecf7c077742ac62251fb85fb6c`: `libfsapfs_checksum.c`
//!   (Fletcher-64) and the `fsapfs_*.h` structure layouts, as a cross-check.
//! - [XNU] apple-oss-distributions/xnu tag `xnu-11215.1.10`:
//!   `bsd/sys/decmpfs.h` (`decmpfs_disk_header`, `DECMPFS_XATTR_NAME`,
//!   `CMP_Type1`), `bsd/sys/xattr.h` (`XATTR_RESOURCEFORK_NAME`) and
//!   `bsd/sys/stat.h` (`UF_COMPRESSED`).
//!
//! Every integer is little-endian ([REF] "About Apple File System").
//! Addresses count blocks of the container's `nx_block_size`; offsets in
//! notes, metadata and members are file bytes. The container names no
//! processor, so members are classified from their own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{Child, Container};
use crate::types::FileFormat;

mod btree;
mod decmpfs;
mod object;
mod omap;
mod records;
mod superblock;
mod volume;
mod walk;

use object::Disk;
use superblock::{Checkpoint, NxSuperblock};

/// Offset of `nx_magic` in the container superblock, after the 32-byte
/// object header ([REF] `nx_superblock_t`).
const NX_MAGIC_OFFSET: usize = 32;

/// `NX_MAGIC` (`'BSXN'`), which reads `NXSB` on disk.
const NX_MAGIC: &[u8; 4] = b"NXSB";

/// `OID_NX_SUPERBLOCK`: the container superblock's ephemeral identifier.
const OID_NX_SUPERBLOCK: u64 = 1;

/// Object types and storage flags ([REF] "Object Types", "Object Type
/// Flags").
const OBJECT_TYPE_MASK: u32 = 0x0000_ffff;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJ_STORAGETYPE_MASK: u32 = 0xc000_0000;
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x0000_0001;
const OBJECT_TYPE_BTREE: u32 = 0x0000_0002;
const OBJECT_TYPE_BTREE_NODE: u32 = 0x0000_0003;
const OBJECT_TYPE_OMAP: u32 = 0x0000_000b;
const OBJECT_TYPE_FS: u32 = 0x0000_000d;
const OBJECT_TYPE_FSTREE: u32 = 0x0000_000e;
const OBJECT_TYPE_EFI_JUMPSTART: u32 = 0x0000_0014;

/// `NX_MINIMUM_BLOCK_SIZE`, `NX_MAXIMUM_BLOCK_SIZE` and
/// `NX_MINIMUM_CONTAINER_SIZE` ([REF] "Block and Container Sizes").
const NX_MINIMUM_BLOCK_SIZE: u32 = 4096;
const NX_MAXIMUM_BLOCK_SIZE: u32 = 65_536;
const NX_MINIMUM_CONTAINER_SIZE: u64 = 1 << 20;

/// The object header (`obj_phys_t`): checksum, oid, xid, type, subtype.
const OBJECT_HEADER_SIZE: usize = 32;

/// The container superblock fields detection reads: `nx_block_size` (36)
/// and `nx_block_count` (40).
const NX_BLOCK_SIZE_FIELD: usize = 36;
const NX_BLOCK_COUNT_FIELD: usize = 40;

/// Object fields: `o_oid` (8), `o_xid` (16), `o_type` (24), `o_subtype`
/// (28).
const O_OID_FIELD: usize = 8;
const O_TYPE_FIELD: usize = 24;

/// Object reads are limited to this many times the number of blocks
/// present. A search reads one node per tree level and resolves each
/// virtual node through the object map, and the walk searches the
/// file-system tree for every directory and file, so index nodes are read
/// many times. The factor is ours.
const METADATA_READ_FACTOR: u64 = 64;

/// The one container layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A container whose block 0 holds an `nx_superblock_t` (`NXSB`).
    Container,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Container => FileFormat::Apfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Container => "APFS container",
        }
    }

    /// The container is recognized by its superblock magic, object
    /// identifier, type and geometry.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Container => false,
        }
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ApfsParseError {
        message: message.into(),
    }
}

/// The text of a `ClassifierError` without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::ApfsParseError { message } => message,
        other => other.to_string(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated structure at 0x{start:X} + {len} B")))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
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

/// Stored bytes in the input: a file offset and a size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    /// File offset.
    offset: usize,
    /// Size in bytes.
    size: usize,
}

/// Blocks of `block_size` bytes needed to hold `bytes` bytes.
fn blocks_for(bytes: usize, block_size: usize) -> u64 {
    (bytes / block_size + usize::from(bytes % block_size != 0)) as u64
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Whether `block_size` and `block_count` describe a container [REF]
/// allows: a power-of-two block size from 4 KiB to 64 KiB and at least
/// `NX_MINIMUM_CONTAINER_SIZE` bytes, whose size fits in 64 bits.
fn is_valid_geometry(block_size: u32, block_count: u64) -> bool {
    let size_ok = block_size.is_power_of_two()
        && (NX_MINIMUM_BLOCK_SIZE..=NX_MAXIMUM_BLOCK_SIZE).contains(&block_size);
    size_ok
        && block_count
            .checked_mul(u64::from(block_size))
            .is_some_and(|bytes| bytes >= NX_MINIMUM_CONTAINER_SIZE)
}

/// Detect a container superblock in block 0: `NXSB` at 32, the
/// superblock's object identifier and type (`OID_NX_SUPERBLOCK`,
/// `OBJ_EPHEMERAL | OBJECT_TYPE_NX_SUPERBLOCK`) and a valid block size and
/// count. The checksum, the checkpoints and the volumes are checked by
/// [`parse_container`], so a damaged container is a parse error or noted.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.get(NX_MAGIC_OFFSET..NX_MAGIC_OFFSET + NX_MAGIC.len())? != NX_MAGIC {
        return None;
    }
    let oid = le_u64(data, O_OID_FIELD).ok()?;
    let object_type = le_u32(data, O_TYPE_FIELD).ok()?;
    let block_size = le_u32(data, NX_BLOCK_SIZE_FIELD).ok()?;
    let block_count = le_u64(data, NX_BLOCK_COUNT_FIELD).ok()?;
    let is_superblock =
        oid == OID_NX_SUPERBLOCK && object_type == OBJ_EPHEMERAL | OBJECT_TYPE_NX_SUPERBLOCK;
    (is_superblock && is_valid_geometry(block_size, block_count)).then_some(Layout::Container)
}

/// Parse an APFS container into the shared container model. Regular files
/// of each readable volume whose first bytes are a recognized format are
/// its children, labeled `/<volume name>/<path>`; encrypted volumes are
/// listed as opaque children, and the EFI driver last.
///
/// A container cut short is parsed as far as its bytes go: objects beyond
/// the end are noted as not present.
///
/// # Errors
///
/// [`ClassifierError::ApfsParseError`] for a block 0 shorter than a block
/// or with an invalid superblock, a container without a superblock whose
/// checksum verifies, an unsupported (version 1) container, or data other
/// than padding after the container. Damage below the container superblock
/// is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let block0 = NxSuperblock::read_block0(data)?;
    let size = block0.size();
    let consumed = match usize::try_from(size) {
        Ok(size) if size <= data.len() => {
            let trailing = &data[size..];
            if trailing.len() >= block0.block_size() && !is_padding(trailing) {
                return Err(error(format!(
                    "Invalid trailing data: {} after the container at 0x{size:X} are not \
                     padding",
                    size_text(trailing.len())
                )));
            }
            if trailing.len() < block0.block_size() {
                data.len()
            } else {
                size
            }
        }
        _ => data.len(),
    };
    let disk = Disk::new(data, &block0);
    let checkpoint = Checkpoint::latest(&disk, &block0)?;
    let mut c = Container::new(layout.format(), layout.label(), "apfs");
    c.consumed = consumed;
    describe(&disk, &checkpoint, &mut c);
    walk::walk(&disk, &checkpoint.superblock, &mut c);
    superblock::efi_driver(&disk, &checkpoint.superblock, &mut c);
    if !c.children.is_empty() && c.children.iter().all(|child| child.opaque) {
        c.opaque = true;
    }
    if disk.absent_reads() > 0 {
        c.notes.push(format!(
            "{} beyond the {} present",
            counted(
                disk.absent_reads(),
                "object read was skipped because its block lies",
                "object reads were skipped because their blocks lie"
            ),
            counted(
                usize::try_from(disk.present_blocks()).unwrap_or(usize::MAX),
                "block",
                "blocks"
            )
        ));
    }
    Ok(c)
}

/// Summary notes and metadata from the chosen container superblock.
fn describe(disk: &Disk<'_>, checkpoint: &Checkpoint, c: &mut Container<'_>) {
    let sb = &checkpoint.superblock;
    let volumes = sb.fs_oids.iter().filter(|&&oid| oid != 0).count();
    c.notes.push(format!(
        "APFS container: {} of {}; checkpoint xid {} ({}); {} of {} volume slots used",
        counted(
            usize::try_from(sb.block_count).unwrap_or(usize::MAX),
            "block",
            "blocks"
        ),
        size_text(sb.block_size()),
        sb.xid,
        checkpoint.source_text(),
        volumes,
        sb.max_file_systems
    ));
    c.notes.extend(checkpoint.notes());
    if disk.present_blocks() < sb.block_count {
        c.notes.push(format!(
            "Truncated container: {} of its {} blocks are present; objects beyond them are not \
             read",
            disk.present_blocks(),
            sb.block_count
        ));
    }
    c.notes.extend(sb.feature_notes());
    c.notes.push(
        "No processor field: the container and volume superblocks name no CPU; members are \
         classified from their own bytes"
            .into(),
    );
    c.push_metadata("apfs_block_size", "Block size (B)", sb.block_size() as u64);
    c.push_metadata("apfs_block_count", "Blocks", sb.block_count);
    c.push_metadata(
        "apfs_blocks_present",
        "Blocks present",
        disk.present_blocks(),
    );
    c.push_metadata("apfs_checkpoint_xid", "Checkpoint transaction", sb.xid);
    c.push_metadata("apfs_container_uuid", "Container UUID", sb.uuid_text());
    c.push_metadata("apfs_volume_count", "Volumes", volumes as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_needs_a_power_of_two_block_size_and_a_megabyte() {
        assert!(is_valid_geometry(4096, 256));
        assert!(is_valid_geometry(65_536, 16));
        assert!(!is_valid_geometry(4096, 255));
        assert!(!is_valid_geometry(2048, 1024));
        assert!(!is_valid_geometry(12_288, 1024));
        assert!(!is_valid_geometry(131_072, 1024));
        assert!(!is_valid_geometry(4096, u64::MAX));
    }

    #[test]
    fn counts_use_singular_and_plural_forms() {
        assert_eq!(counted(1, "block", "blocks"), "1 block");
        assert_eq!(counted(2, "block", "blocks"), "2 blocks");
    }

    #[test]
    fn the_layout_names_its_format() {
        assert_eq!(Layout::Container.format(), FileFormat::Apfs);
        assert_eq!(Layout::Container.label(), "APFS container");
        assert!(!Layout::Container.is_weak());
    }
}
