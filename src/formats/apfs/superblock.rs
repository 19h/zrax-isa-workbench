//! The container superblock `nx_superblock_t`, the choice of the latest
//! valid checkpoint ([REF] "Mounting an Apple File System Partition";
//! [FUSE] `ApfsContainer::Init` scans the whole descriptor area), and the
//! EFI jumpstart driver ([REF] "Booting from an Apple File System
//! Partition", `nx_efi_jumpstart_t`).

use super::object::{has_valid_checksum, Header};
use super::*;
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::fmt::Write;

/// `nx_superblock_t` field offsets ([REF]; every field 64-bit aligned):
/// features (48), read-only compatible (56), incompatible (64), UUID (72),
/// checkpoint descriptor blocks (104) and base (112), object map (160),
/// maximum volumes (180), volume identifiers (184), flags (1264), EFI
/// jumpstart (1272), Fusion UUID (1280), keybag range (1296).
const NX_FEATURES: usize = 48;
const NX_READONLY_COMPATIBLE_FEATURES: usize = 56;
const NX_INCOMPATIBLE_FEATURES: usize = 64;
const NX_UUID: usize = 72;
const NX_XP_DESC_BLOCKS: usize = 104;
const NX_XP_DESC_BASE: usize = 112;
const NX_OMAP_OID: usize = 160;
const NX_MAX_FILE_SYSTEMS_FIELD: usize = 180;
const NX_FS_OID: usize = 184;
const NX_FLAGS: usize = 1264;
const NX_EFI_JUMPSTART: usize = 1272;
const NX_FUSION_UUID: usize = 1280;
const NX_KEYLOCKER: usize = 1296;

/// `NX_MAX_FILE_SYSTEMS`.
const NX_MAX_FILE_SYSTEMS: usize = 100;

/// The superblock fields read, up to the end of `nx_keylocker`.
const NX_SUPERBLOCK_SIZE: usize = 1312;

/// The high bit of `nx_xp_desc_blocks` marks a descriptor area that is not
/// contiguous, whose base is then a B-tree of fragments.
const XP_NOT_CONTIGUOUS: u32 = 0x8000_0000;

/// Incompatible container features ([REF] "Incompatible Container Feature
/// Flags").
const NX_INCOMPAT_VERSION1: u64 = 0x0000_0001;
const NX_INCOMPAT_VERSION2: u64 = 0x0000_0002;
const NX_INCOMPAT_FUSION: u64 = 0x0000_0100;

/// `NX_CRYPTO_SW` in `nx_flags`.
const NX_CRYPTO_SW: u64 = 0x0000_0004;

/// `NX_EFI_JUMPSTART_MAGIC` (`'RDSJ'`, which reads `JSDR` on disk) and
/// `NX_EFI_JUMPSTART_VERSION`.
const NX_EFI_JUMPSTART_MAGIC: &[u8; 4] = b"JSDR";
const NX_EFI_JUMPSTART_VERSION: u32 = 1;

/// `nx_efi_jumpstart_t`: magic (32), version (36), driver length (40),
/// extent count (44), 16 reserved words, then `prange_t` extents (176) of a
/// start block and a block count.
const NEJ_VERSION: usize = 36;
const NEJ_EFI_FILE_LEN: usize = 40;
const NEJ_NUM_EXTENTS: usize = 44;
const NEJ_REC_EXTENTS: usize = 176;
const PRANGE_SIZE: usize = 16;

/// The member label and transform of the EFI driver.
const EFI_DRIVER_LABEL: &str = "EFI jumpstart driver";
const EFI_DRIVER_TRANSFORM: &str = "APFS EFI jumpstart extents";

/// A container superblock.
#[derive(Debug, Clone)]
pub(super) struct NxSuperblock {
    /// Block it was read from.
    pub(super) paddr: u64,
    /// `o_xid`.
    pub(super) xid: u64,
    /// `nx_block_size` in bytes.
    block_size: u32,
    /// `nx_block_count`.
    pub(super) block_count: u64,
    features: u64,
    readonly_compatible: u64,
    incompatible: u64,
    uuid: [u8; 16],
    /// `nx_xp_desc_blocks`, with the contiguity flag.
    desc_blocks: u32,
    /// `nx_xp_desc_base`.
    desc_base: u64,
    /// `nx_omap_oid`: physical address of the container's object map.
    pub(super) omap_oid: u64,
    /// `nx_max_file_systems`.
    pub(super) max_file_systems: u32,
    /// `nx_fs_oid`: virtual object identifiers of the volumes; 0 is unused.
    pub(super) fs_oids: Vec<u64>,
    flags: u64,
    /// `nx_efi_jumpstart`: physical address of the EFI jumpstart, or 0.
    pub(super) efi_jumpstart: u64,
    /// Whether `nx_fusion_uuid` is set.
    has_fusion_uuid: bool,
    /// `nx_keylocker` block count.
    keylocker_blocks: u64,
}

impl NxSuperblock {
    /// Parse the superblock fields of `block`, read from block `paddr`. The
    /// checksum is checked by the caller.
    fn parse(block: &[u8], paddr: u64) -> Result<Self> {
        let fields = slice(block, 0, NX_SUPERBLOCK_SIZE).map_err(|_| {
            error(format!(
                "Truncated container superblock in block 0x{paddr:X}: {} B of {NX_SUPERBLOCK_SIZE} \
                 B",
                block.len()
            ))
        })?;
        if &fields[NX_MAGIC_OFFSET..NX_MAGIC_OFFSET + 4] != NX_MAGIC {
            return Err(error(format!(
                "Invalid container superblock magic in block 0x{paddr:X}"
            )));
        }
        let block_size = le_u32(fields, NX_BLOCK_SIZE_FIELD)?;
        let block_count = le_u64(fields, NX_BLOCK_COUNT_FIELD)?;
        if !is_valid_geometry(block_size, block_count) {
            return Err(error(format!(
                "Invalid container geometry: {block_count} blocks of {block_size} B"
            )));
        }
        let max_file_systems = le_u32(fields, NX_MAX_FILE_SYSTEMS_FIELD)?;
        let slots = (max_file_systems as usize).min(NX_MAX_FILE_SYSTEMS);
        let fs_oids = (0..slots)
            .map(|i| le_u64(fields, NX_FS_OID + 8 * i))
            .collect::<Result<Vec<_>>>()?;
        let uuid: [u8; 16] = fields[NX_UUID..NX_UUID + 16].try_into().expect("16 bytes");
        Ok(Self {
            paddr,
            xid: Header::parse(fields)?.xid,
            block_size,
            block_count,
            features: le_u64(fields, NX_FEATURES)?,
            readonly_compatible: le_u64(fields, NX_READONLY_COMPATIBLE_FEATURES)?,
            incompatible: le_u64(fields, NX_INCOMPATIBLE_FEATURES)?,
            uuid,
            desc_blocks: le_u32(fields, NX_XP_DESC_BLOCKS)?,
            desc_base: le_u64(fields, NX_XP_DESC_BASE)?,
            omap_oid: le_u64(fields, NX_OMAP_OID)?,
            max_file_systems,
            fs_oids,
            flags: le_u64(fields, NX_FLAGS)?,
            efi_jumpstart: le_u64(fields, NX_EFI_JUMPSTART)?,
            has_fusion_uuid: fields[NX_FUSION_UUID..NX_FUSION_UUID + 16]
                .iter()
                .any(|&b| b != 0),
            keylocker_blocks: le_u64(fields, NX_KEYLOCKER + 8)?,
        })
    }

    /// The superblock copy in block 0, which must be complete.
    pub(super) fn read_block0(data: &[u8]) -> Result<Self> {
        let block_size = le_u32(data, NX_BLOCK_SIZE_FIELD).map_err(|_| {
            error(format!(
                "Truncated container superblock: {} B present",
                data.len()
            ))
        })?;
        let block = data.get(..block_size as usize).ok_or_else(|| {
            error(format!(
                "Truncated container superblock: block 0 needs {block_size} B, {} B present",
                data.len()
            ))
        })?;
        Self::parse(block, 0)
    }

    /// `nx_block_size` in bytes.
    pub(super) fn block_size(&self) -> usize {
        self.block_size as usize
    }

    /// The container size in bytes (`nx_block_count` blocks).
    pub(super) fn size(&self) -> u64 {
        // Parsing checked that the product does not overflow.
        self.block_count * u64::from(self.block_size)
    }

    /// The container UUID in the usual 8-4-4-4-12 form.
    pub(super) fn uuid_text(&self) -> String {
        uuid_text(&self.uuid)
    }

    /// Notes on the container's features, flags and keybag.
    pub(super) fn feature_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.incompatible & NX_INCOMPAT_FUSION != 0 || self.has_fusion_uuid {
            notes.push(
                "Fusion container (NX_INCOMPAT_FUSION): blocks on the second device are not \
                 available"
                    .into(),
            );
        }
        let known = NX_INCOMPAT_VERSION2 | NX_INCOMPAT_FUSION;
        if self.incompatible & !known != 0 {
            notes.push(format!(
                "Unknown incompatible container features 0x{:X}",
                self.incompatible & !known
            ));
        }
        if self.features != 0 || self.readonly_compatible != 0 {
            notes.push(format!(
                "Container features 0x{:X}, read-only compatible features 0x{:X}",
                self.features, self.readonly_compatible
            ));
        }
        if self.flags & NX_CRYPTO_SW != 0 {
            notes.push("The container uses software encryption (NX_CRYPTO_SW)".into());
        }
        if self.keylocker_blocks != 0 {
            notes.push(format!(
                "Container keybag of {} (nx_keylocker); not unwrapped",
                counted(
                    usize::try_from(self.keylocker_blocks).unwrap_or(usize::MAX),
                    "block",
                    "blocks"
                )
            ));
        }
        notes
    }
}

/// `uuid` in the 8-4-4-4-12 form, its bytes in stored order.
pub(super) fn uuid_text(uuid: &[u8; 16]) -> String {
    let mut hex = String::with_capacity(2 * uuid.len());
    for byte in uuid {
        write!(hex, "{byte:02X}").expect("writing to a String cannot fail");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Where the chosen superblock came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The copy in block 0.
    Block0,
    /// Block `index` of the checkpoint descriptor area.
    Descriptor { index: u64 },
}

/// The container superblock of the latest valid checkpoint.
#[derive(Debug)]
pub(super) struct Checkpoint {
    pub(super) superblock: NxSuperblock,
    source: Source,
    /// Transaction of the block 0 copy.
    block0_xid: u64,
    /// Whether the block 0 copy's checksum verifies.
    block0_valid: bool,
    /// Descriptor area blocks whose checksum failed (zero blocks excluded).
    invalid_blocks: usize,
    /// Why the descriptor area was not (fully) read.
    descriptor_note: Option<String>,
}

impl Checkpoint {
    /// The superblock with the largest transaction identifier among the
    /// container superblocks in the checkpoint descriptor area whose
    /// checksum verifies and whose geometry matches block 0, or the block 0
    /// copy when none does.
    ///
    /// # Errors
    ///
    /// A version 1 container, or no superblock whose checksum verifies.
    pub(super) fn latest(disk: &Disk<'_>, block0: &NxSuperblock) -> Result<Self> {
        if block0.incompatible & NX_INCOMPAT_VERSION1 != 0
            && block0.incompatible & NX_INCOMPAT_VERSION2 == 0
        {
            return Err(error(
                "Unsupported container: APFS version 1 (the macOS 10.12 prerelease format)",
            ));
        }
        let block0_valid = disk.blocks(0, 1).is_ok_and(has_valid_checksum);
        let mut checkpoint = Self {
            source: Source::Block0,
            block0_xid: block0.xid,
            block0_valid,
            invalid_blocks: 0,
            descriptor_note: None,
            superblock: block0.clone(),
        };
        let best = checkpoint.scan_descriptors(disk, block0);
        match best {
            Some(found) => {
                checkpoint.source = Source::Descriptor {
                    index: found.paddr - block0.desc_base,
                };
                checkpoint.superblock = found;
            }
            None if block0_valid => {}
            None => {
                return Err(error(
                    "Invalid container superblock: the block 0 checksum does not verify and no \
                     checkpoint superblock does",
                ))
            }
        }
        Ok(checkpoint)
    }

    /// The valid superblock with the largest xid in the descriptor area.
    fn scan_descriptors(&mut self, disk: &Disk<'_>, block0: &NxSuperblock) -> Option<NxSuperblock> {
        if block0.desc_blocks & XP_NOT_CONTIGUOUS != 0 {
            self.descriptor_note = Some(
                "The checkpoint descriptor area is not contiguous (a B-tree of fragments), \
                 which is not read; the block 0 superblock is used"
                    .into(),
            );
            return None;
        }
        let count = u64::from(block0.desc_blocks);
        let end = block0.desc_base.saturating_add(count);
        // Only blocks inside the container and the input are read, so a
        // hostile count cannot make the scan run long.
        let readable_end = end.min(disk.present_blocks());
        if readable_end < end {
            self.descriptor_note = Some(format!(
                "The checkpoint descriptor area (blocks 0x{:X}-0x{:X}) is not wholly present; \
                 {} read",
                block0.desc_base,
                end - 1,
                counted(
                    usize::try_from(readable_end.saturating_sub(block0.desc_base))
                        .unwrap_or(usize::MAX),
                    "block was",
                    "blocks were"
                )
            ));
        }
        let mut best: Option<NxSuperblock> = None;
        for paddr in block0.desc_base..readable_end {
            let Ok(block) = disk.blocks(paddr, 1) else {
                continue;
            };
            if block.iter().all(|&b| b == 0) {
                continue;
            }
            if !has_valid_checksum(block) {
                self.invalid_blocks += 1;
                continue;
            }
            let Ok(header) = Header::parse(block) else {
                continue;
            };
            if header.kind() != OBJECT_TYPE_NX_SUPERBLOCK || header.oid != OID_NX_SUPERBLOCK {
                continue;
            }
            let Ok(candidate) = NxSuperblock::parse(block, paddr) else {
                self.invalid_blocks += 1;
                continue;
            };
            let same_geometry = candidate.block_size == block0.block_size
                && candidate.block_count == block0.block_count;
            if !same_geometry {
                self.invalid_blocks += 1;
                continue;
            }
            if best.as_ref().map_or(true, |b| candidate.xid > b.xid) {
                best = Some(candidate);
            }
        }
        best
    }

    /// Where the chosen superblock came from, for the summary note.
    pub(super) fn source_text(&self) -> String {
        match self.source {
            Source::Block0 => "block 0".into(),
            Source::Descriptor { index } => format!(
                "checkpoint descriptor block {index}, block 0x{:X}",
                self.superblock.paddr
            ),
        }
    }

    /// Notes on the block 0 copy and the descriptor area.
    pub(super) fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if !self.block0_valid {
            notes.push(
                "The block 0 superblock's checksum does not verify; it was used only to find \
                 the checkpoints"
                    .into(),
            );
        } else if self.block0_xid != self.superblock.xid {
            notes.push(format!(
                "Block 0 holds checkpoint xid {}; the latest valid checkpoint, xid {}, is used",
                self.block0_xid, self.superblock.xid
            ));
        }
        if let Some(note) = &self.descriptor_note {
            notes.push(note.clone());
        }
        if self.invalid_blocks > 0 {
            notes.push(format!(
                "{} of the checkpoint descriptor area skipped: checksum or superblock invalid",
                counted(self.invalid_blocks, "block", "blocks")
            ));
        }
        notes
    }
}

/// List the embedded EFI driver last, when the container has one.
pub(super) fn efi_driver<'a>(disk: &Disk<'a>, sb: &NxSuperblock, c: &mut Container<'a>) {
    if sb.efi_jumpstart == 0 {
        return;
    }
    match jumpstart_driver(disk, sb.efi_jumpstart) {
        Ok(child) => {
            c.notes.push(format!(
                "EFI jumpstart at block 0x{:X}: an embedded EFI driver of {}, listed last",
                sb.efi_jumpstart,
                size_text(child.data.len())
            ));
            c.children.push(child);
        }
        Err(e) => c.notes.push(format!(
            "EFI jumpstart at block 0x{:X} not read: {}",
            sb.efi_jumpstart,
            message(e)
        )),
    }
}

/// The EFI driver of the jumpstart in block `paddr`: its extents read in
/// order and cut at `nej_efi_file_len`.
fn jumpstart_driver<'a>(disk: &Disk<'a>, paddr: u64) -> Result<Child<'a>> {
    let object = disk.object(paddr, paddr)?;
    if object.header.kind() != OBJECT_TYPE_EFI_JUMPSTART {
        return Err(error(format!(
            "Invalid EFI jumpstart: object type 0x{:X}",
            object.header.object_type
        )));
    }
    let bytes = object.bytes;
    if slice(bytes, OBJECT_HEADER_SIZE, 4)? != NX_EFI_JUMPSTART_MAGIC {
        return Err(error("Invalid EFI jumpstart magic"));
    }
    let version = le_u32(bytes, NEJ_VERSION)?;
    if version != NX_EFI_JUMPSTART_VERSION {
        return Err(error(format!(
            "Unsupported EFI jumpstart version {version}"
        )));
    }
    let length = le_u32(bytes, NEJ_EFI_FILE_LEN)? as usize;
    if length == 0 || length > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported EFI driver length of {}",
            size_text(length)
        )));
    }
    let count = le_u32(bytes, NEJ_NUM_EXTENTS)? as usize;
    let available = (bytes.len() - NEJ_REC_EXTENTS) / PRANGE_SIZE;
    if count > available {
        return Err(error(format!(
            "Invalid EFI jumpstart: {count} extents, at most {available} fit in the block"
        )));
    }
    let mut pieces: Vec<&'a [u8]> = Vec::new();
    let mut first_run: Option<Run> = None;
    let mut collected = 0usize;
    for i in 0..count {
        if collected >= length {
            break;
        }
        let at = NEJ_REC_EXTENTS + PRANGE_SIZE * i;
        let start = le_u64(bytes, at)?;
        let blocks = le_u64(bytes, at + 8)?;
        if blocks == 0 {
            continue;
        }
        let wanted = length - collected;
        let stored = disk.blocks(start, blocks.min(blocks_for(wanted, disk.block_size())))?;
        let piece = &stored[..stored.len().min(wanted)];
        if first_run.is_none() {
            first_run = Some(Run {
                offset: disk.file_offset(start),
                size: piece.len(),
            });
        }
        collected += piece.len();
        pieces.push(piece);
    }
    if collected < length {
        return Err(error(format!(
            "Invalid EFI jumpstart: its extents hold {} of the {} driver",
            size_text(collected),
            size_text(length)
        )));
    }
    let run = first_run.expect("at least one extent was read");
    if let [whole] = pieces.as_slice() {
        return Ok(Child::stored(EFI_DRIVER_LABEL, run.offset, whole));
    }
    Ok(Child::decoded(
        EFI_DRIVER_LABEL,
        run.offset,
        run.size,
        Cow::Owned(pieces.concat()),
        EFI_DRIVER_TRANSFORM,
    ))
}
