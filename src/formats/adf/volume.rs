//! `AmigaDOS` volumes: the DOS type, floppy and hardfile geometry, the root
//! block, and the notes and metadata that describe a volume ([FAQ] 3,
//! 4.1-4.3, 7). The walk below the root block is in `walk.rs`.

use super::boot::{BootBlock, DOS_TYPE_OFFSET, FLOPPY_BOOT_BLOCKS};
use super::walk::{self, Census};
use super::*;

/// DOS type flags, the fourth byte of the boot block ([FAQ] 4.1; [ADFLIB]
/// `adf_blk.h`; [AMITOOLS] `DosType.py`).
const DOS_FFS: u8 = 0x01;
const DOS_INTL: u8 = 0x02;
const DOS_DIRCACHE: u8 = 0x04;

/// The last DOS type: 0-5 are the OFS and FFS variants of [FAQ] 4.1, 6 and
/// 7 the long-name file systems that [AMITOOLS] `DosType.py` lists.
const MAX_DOS_TYPE: u8 = 7;

/// Bytes of file data in an OFS data block, after its 24-byte header
/// ([FAQ] 4.1: "OFS Datablock stores BSIZE-24 bytes"); FFS data blocks
/// hold `BSIZE` bytes.
const OFS_DATA_SIZE: usize = BLOCK_SIZE - 24;

/// Root block fields ([FAQ] 4.2).
const HT_SIZE: usize = 0x00c;
const BM_FLAG: usize = 0x138;
const BM_PAGES: usize = 0x13c;
const BM_PAGE_COUNT: usize = 25;
const BM_EXT: usize = 0x1a0;
/// `v_days`, `v_mins`, `v_ticks`: the last change of the volume.
const VOLUME_DATE: usize = 0x1d8;
/// `c_days`, `c_mins`, `c_ticks`: when the volume was formatted.
const CREATION_DATE: usize = 0x1e4;

/// `bm_flag` of a valid bitmap: -1 ([FAQ] 4.2).
const BM_VALID: u32 = 0xffff_ffff;

/// Blocks one bitmap block maps: `(BSIZE / 4 - 1) * 32` ([FAQ] 4.3).
const BLOCKS_PER_BITMAP_BLOCK: usize = (BLOCK_LONGS - 1) * 32;

/// Names hold at most 30 characters ([ADFLIB] `ADF_MAX_NAME_LEN`).
pub(super) const MAX_NAME_LEN: usize = 30;

/// Floppy geometry: [ADFLIB] `adf_dev_type.c` lists 80 to 83 cylinders of
/// 2 heads and 11 (DD) or 22 (HD) sectors of 512 B; [FAQ] 3 describes the
/// 80-cylinder disks.
const FLOPPY_CYLINDERS: [u32; 4] = [80, 81, 82, 83];
const FLOPPY_HEADS: u32 = 2;
const DD_SECTORS: u32 = 11;
const HD_SECTORS: u32 = 22;

/// Reserved blocks at the start of a floppy volume: its boot block.
const FLOPPY_RESERVED: u32 = 2;

/// Fewest blocks of a hardfile: the boot blocks, a root block and a bitmap
/// block ([FAQ] 5.1 lists them as a minimal disk). The bound is ours.
const MIN_HARDFILE_BLOCKS: usize = 4;

/// Days from 1970-01-01 to 1978-01-01, the `AmigaDOS` epoch ([FAQ] 4.2).
const EPOCH_DAYS: i64 = 2922;
const MINUTES_PER_DAY: u32 = 24 * 60;
/// Ticks are 1/50 s ([FAQ] 4.2).
const TICKS_PER_SECOND: u32 = 50;
const TICKS_PER_MINUTE: u32 = 60 * TICKS_PER_SECOND;

/// Prefix of the metadata keys.
pub(super) const KEY_PREFIX: &str = "adf";

/// A DOS type from the boot block: `DOS\0` to `DOS\7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DosType(u8);

impl DosType {
    /// The DOS type with `flags` as its fourth byte, if `AmigaDOS` defines
    /// it.
    pub(super) fn from_flags(flags: u8) -> Option<Self> {
        (flags <= MAX_DOS_TYPE).then_some(Self(flags))
    }

    /// The Fast File System: raw data blocks ([FAQ] 4.1).
    pub(super) fn is_ffs(self) -> bool {
        self.0 & DOS_FFS != 0
    }

    /// International mode: its own flag, and implied by the directory
    /// cache ([FAQ] 4.1: "the international mode is also enabled, but the
    /// related flag (bit #1) will stay cleared") and long-name types
    /// ([AMITOOLS] `is_intl`).
    pub(super) fn is_international(self) -> bool {
        self.0 & (DOS_INTL | DOS_DIRCACHE) != 0
    }

    /// `DOS\4` and `DOS\5` ([AMITOOLS] `is_dircache`).
    pub(super) fn has_dircache(self) -> bool {
        self.0 & (DOS_INTL | DOS_DIRCACHE) == DOS_DIRCACHE
    }

    /// `DOS\6` and `DOS\7` ([AMITOOLS] `is_longname`).
    pub(super) fn has_long_names(self) -> bool {
        self.0 & (DOS_INTL | DOS_DIRCACHE) == DOS_INTL | DOS_DIRCACHE
    }

    /// Bytes of file data in a data block.
    pub(super) fn data_size(self) -> usize {
        if self.is_ffs() {
            BLOCK_SIZE
        } else {
            OFS_DATA_SIZE
        }
    }

    /// The DOS type as `AmigaOS` prints it: `DOS\3`.
    pub(super) fn name(self) -> String {
        format!("DOS\\{}", self.0)
    }

    /// The file system and its modes: `FFS, international mode`.
    pub(super) fn description(self) -> String {
        let mut text = String::from(if self.is_ffs() { "FFS" } else { "OFS" });
        if self.is_international() {
            text.push_str(", international mode");
        }
        if self.has_dircache() {
            text.push_str(", directory cache");
        }
        if self.has_long_names() {
            text.push_str(", long file names");
        }
        text
    }
}

/// The geometry of a floppy image, from its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FloppyGeometry {
    pub(super) density: Density,
    pub(super) cylinders: u32,
}

impl FloppyGeometry {
    /// The floppy whose image is `size` bytes, if one is.
    fn of_size(size: usize) -> Option<Self> {
        [Density::Double, Density::High]
            .into_iter()
            .flat_map(|density| FLOPPY_CYLINDERS.map(|cylinders| Self { density, cylinders }))
            .find(|geometry| geometry.size() == size)
    }

    fn sectors(self) -> u32 {
        match self.density {
            Density::Double => DD_SECTORS,
            Density::High => HD_SECTORS,
        }
    }

    /// Blocks on the disk: sectors, then sides, then cylinders ([FAQ] 3).
    fn blocks(self) -> u32 {
        self.cylinders * FLOPPY_HEADS * self.sectors()
    }

    fn size(self) -> usize {
        usize::try_from(self.blocks()).expect("a floppy has fewer than 4,000 blocks") * BLOCK_SIZE
    }

    fn describe(self) -> String {
        format!(
            "{} floppy image: {} cylinders, {FLOPPY_HEADS} heads, {} sectors per track ({} \
             blocks of 512 B, {})",
            density_name(self.density),
            self.cylinders,
            self.sectors(),
            self.blocks(),
            size_text(self.size() as u64)
        )
    }
}

/// An `AmigaDOS` volume: a floppy image, a hardfile or a partition.
#[derive(Debug)]
pub(super) struct Volume<'a> {
    /// The input file.
    pub(super) data: &'a [u8],
    /// File offset of block 0 of the volume.
    pub(super) base: usize,
    /// Blocks in the volume, as its geometry gives them.
    pub(super) blocks: u32,
    /// Blocks at the start that hold the boot block, not file system
    /// blocks.
    pub(super) reserved: u32,
    pub(super) dos: DosType,
}

impl<'a> Volume<'a> {
    /// The file system block `number`.
    pub(super) fn block(&self, number: u32) -> Walk<Block<'a>> {
        if number < self.reserved || number >= self.blocks {
            return Err(format!(
                "block {number} is not a file system block (blocks {}-{})",
                self.reserved,
                self.blocks.saturating_sub(1)
            ));
        }
        let offset = block_offset(self.base, number)
            .ok_or_else(|| format!("block {number} lies beyond the end of the input"))?;
        Block::at(self.data, number, offset).ok_or_else(|| {
            format!("block {number} at 0x{offset:X} lies beyond the end of the input")
        })
    }

    /// Blocks of the volume that the input holds.
    pub(super) fn blocks_present(&self) -> usize {
        let present = self.data.len().saturating_sub(self.base) / BLOCK_SIZE;
        present.min(usize::try_from(self.blocks).unwrap_or(usize::MAX))
    }
}

/// File offset of block `number` of a volume at `base`.
fn block_offset(base: usize, number: u32) -> Option<usize> {
    usize::try_from(number)
        .ok()?
        .checked_mul(BLOCK_SIZE)?
        .checked_add(base)
}

/// A volume and its root block.
#[derive(Debug)]
pub(super) struct Mounted<'a> {
    pub(super) volume: Volume<'a>,
    pub(super) root: Block<'a>,
}

/// Where the root block of a volume of `blocks` blocks may be: the
/// reserved blocks plus `highKey`, halved ([FAQ] 4.2; [LINUX] `(reserved +
/// size - 1) / 2`), then `blocks / 2` ([ADFLIB] `adfVolCalcRootBlk`;
/// [AMITOOLS] `num_blocks // 2`). They differ only for odd block counts.
pub(super) fn root_candidates(blocks: u32, reserved: u32) -> Vec<u32> {
    let high_key = u64::from(blocks.saturating_sub(1));
    let formula = u32::try_from((u64::from(reserved) + high_key) / 2).expect("below 2^32");
    let half = blocks / 2;
    if formula == half {
        vec![formula]
    } else {
        vec![formula, half]
    }
}

/// Why `block` is not a valid root block, if it is not one.
fn root_defect(block: &Block<'_>) -> Option<String> {
    let kind = block.long(TYPE);
    let secondary = block.long(SECONDARY_TYPE);
    if kind != T_HEADER || secondary != ST_ROOT {
        return Some(format!(
            "its types are {} and {}, not T_HEADER (2) and ST_ROOT (1)",
            signed(kind),
            signed(secondary)
        ));
    }
    if !block.is_checksum_valid() {
        return Some(format!(
            "its checksum is 0x{:08X}, not 0x{:08X}",
            block.long(CHECKSUM),
            block.expected_checksum(CHECKSUM)
        ));
    }
    None
}

/// A long read as the signed value it holds.
pub(super) fn signed(value: u32) -> i32 {
    i32::from_be_bytes(value.to_be_bytes())
}

/// Mount the volume of `blocks` blocks at file offset `base` at the first
/// of its root block candidates that holds a valid root block. The error
/// says why the first candidate is not one.
pub(super) fn mount(
    data: &[u8],
    base: usize,
    blocks: u32,
    reserved: u32,
    dos: DosType,
) -> Walk<Mounted<'_>> {
    let candidates = root_candidates(blocks, reserved);
    let mut first_defect = None;
    for number in candidates {
        let defect = match block_offset(base, number).and_then(|at| Block::at(data, number, at)) {
            Some(root) => match root_defect(&root) {
                None => {
                    let volume = Volume {
                        data,
                        base,
                        blocks,
                        reserved,
                        dos,
                    };
                    return Ok(Mounted { volume, root });
                }
                Some(defect) => format!("block {number} at 0x{:X}: {defect}", root.offset),
            },
            None => format!("block {number} lies beyond the end of the input"),
        };
        first_defect.get_or_insert(defect);
    }
    Err(first_defect.expect("there is at least one candidate"))
}

/// Recognize an ADF floppy image: see [`super::detect`].
pub(super) fn detect_floppy(data: &[u8]) -> Option<Layout> {
    let geometry = FloppyGeometry::of_size(data.len())?;
    let boot = BootBlock::read(data, 0, FLOPPY_BOOT_BLOCKS)?;
    if !boot.has_dos_signature() {
        return None;
    }
    if let Some(dos) = DosType::from_flags(boot.flags()) {
        if mount(data, 0, geometry.blocks(), FLOPPY_RESERVED, dos).is_ok() {
            return Some(Layout::Floppy(geometry.density));
        }
    }
    boot.is_bootable()
        .then_some(Layout::BootFloppy(geometry.density))
}

/// Recognize an unpartitioned hardfile: see [`super::detect`]. Every input
/// passes through here, so the signature is checked before anything else.
pub(super) fn detect_hardfile(data: &[u8]) -> bool {
    data.starts_with(&boot::DOS_SIGNATURE) && mount_hardfile(data).is_ok()
}

/// The volume of a hardfile: a whole number of blocks with `DOS` and a DOS
/// type at offset 0 and a root block in the middle. A hardfile does not
/// record its reserved blocks (the UAE mountlist in [FAQ] 7 uses 1, floppies
/// and most partitions 2), so both root positions are tried.
fn mount_hardfile(data: &[u8]) -> Result<Mounted<'_>> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(error(format!(
            "Invalid hardfile size {} B: not a whole number of 512-byte blocks",
            data.len()
        )));
    }
    let blocks = data.len() / BLOCK_SIZE;
    if blocks < MIN_HARDFILE_BLOCKS {
        return Err(error(format!(
            "Truncated hardfile: {} B hold fewer than {MIN_HARDFILE_BLOCKS} blocks",
            data.len()
        )));
    }
    let blocks = u32::try_from(blocks).map_err(|_| {
        error(format!(
            "Unsupported hardfile size {} B: AmigaDOS addresses at most 2^32 blocks",
            data.len()
        ))
    })?;
    let dos = dos_type(data)?;
    mount(data, 0, blocks, FLOPPY_RESERVED, dos)
        .map_err(|defect| error(format!("Invalid root block: {defect}")))
}

/// The DOS type at offset 0: `DOS` and a DOS type of 0-7.
fn dos_type(data: &[u8]) -> Result<DosType> {
    let id = data
        .get(..4)
        .ok_or_else(|| error(format!("Truncated boot block: {} B", data.len())))?;
    if id[..3] != boot::DOS_SIGNATURE {
        return Err(error(format!(
            "Missing DOS signature at 0x0: {:02X} {:02X} {:02X}",
            id[0], id[1], id[2]
        )));
    }
    DosType::from_flags(id[DOS_TYPE_OFFSET]).ok_or_else(|| {
        error(format!(
            "Unsupported DOS type 0x{:02X} at 0x3: AmigaDOS defines 0-7",
            id[DOS_TYPE_OFFSET]
        ))
    })
}

/// The floppy geometry of `data`, which must be a `density` image.
fn floppy_geometry(data: &[u8], density: Density) -> Result<FloppyGeometry> {
    let geometry = FloppyGeometry::of_size(data.len()).ok_or_else(|| {
        error(format!(
            "Invalid image size {} B: not a floppy of 80-83 cylinders, 2 heads and 11 or 22 \
             sectors",
            data.len()
        ))
    })?;
    if geometry.density != density {
        return Err(error(format!(
            "Invalid image size {} B: the size of a {} floppy, not {}",
            data.len(),
            density_name(geometry.density),
            density_name(density)
        )));
    }
    Ok(geometry)
}

fn density_name(density: Density) -> &'static str {
    match density {
        Density::Double => "DD",
        Density::High => "HD",
    }
}

/// The two boot blocks at offset 0.
fn floppy_boot_block(data: &[u8]) -> Result<BootBlock<'_>> {
    BootBlock::read(data, 0, FLOPPY_BOOT_BLOCKS)
        .ok_or_else(|| error(format!("Truncated boot block: {} B", data.len())))
}

/// Parse an ADF floppy image holding an `AmigaDOS` volume.
///
/// # Errors
///
/// [`ClassifierError::AdfParseError`] when the image is not a `density`
/// floppy, the boot block does not start with `DOS` and a DOS type of 0-7,
/// or the middle block is not a valid root block.
pub(super) fn parse_floppy(data: &[u8], density: Density) -> Result<Container<'_>> {
    let geometry = floppy_geometry(data, density)?;
    let dos = dos_type(data)?;
    let boot = floppy_boot_block(data)?;
    let mounted = mount(data, 0, geometry.blocks(), FLOPPY_RESERVED, dos)
        .map_err(|defect| error(format!("Invalid root block: {defect}")))?;
    let mut c = Container::new(FileFormat::Adf, Layout::Floppy(density).label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(geometry.describe());
    single_volume(&mounted, &boot, &mut c);
    Ok(c)
}

/// Parse an unpartitioned hardfile.
///
/// # Errors
///
/// [`ClassifierError::AdfParseError`] when the input is not a whole number
/// of blocks, does not start with `DOS` and a DOS type of 0-7, or holds no
/// valid root block in the middle.
pub(super) fn parse_hardfile(data: &[u8]) -> Result<Container<'_>> {
    let mounted = mount_hardfile(data)?;
    let boot = floppy_boot_block(data)?;
    let mut c = Container::new(FileFormat::AmigaHdf, Layout::Hardfile.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(format!(
        "Hardfile without a Rigid Disk Block: one AmigaDOS volume of {} blocks of 512 B ({})",
        mounted.volume.blocks,
        size_text(data.len() as u64)
    ));
    single_volume(&mounted, &boot, &mut c);
    Ok(c)
}

/// The volume, its members and its boot code, for an image that holds one
/// volume. The volume's files describe it better than its boot code, so
/// the boot code follows them and supplies the primary ISA only when no
/// file does.
fn single_volume<'a>(mounted: &Mounted<'a>, boot: &BootBlock<'a>, c: &mut Container<'a>) {
    describe(mounted, "", KEY_PREFIX, c);
    let boot_code = boot.boot_code("Boot block code");
    c.notes.push(boot_code.note.clone());
    push_boot_metadata(boot, KEY_PREFIX, c);
    let mut census = Census::default();
    walk::walk_volume(mounted, "", &mut census, c);
    census.report(c);
    c.children.extend(boot_code.child);
}

/// Parse an ADF floppy image whose boot block is bootable but which holds
/// no `AmigaDOS` volume.
///
/// # Errors
///
/// [`ClassifierError::AdfParseError`] when the image is not a `density`
/// floppy or its boot block is not bootable (the `DOS` signature, a valid
/// checksum and code).
pub(super) fn parse_boot_floppy(data: &[u8], density: Density) -> Result<Container<'_>> {
    let geometry = floppy_geometry(data, density)?;
    let boot = floppy_boot_block(data)?;
    if !boot.has_dos_signature() {
        return Err(error(format!(
            "Missing DOS signature at 0x0: {:02X} {:02X} {:02X}",
            boot.id[0], boot.id[1], boot.id[2]
        )));
    }
    if !boot.is_checksum_valid() {
        return Err(error(format!(
            "Invalid boot block checksum 0x{:08X} at 0x4: 0x{:08X} expected",
            boot.stored_checksum, boot.computed_checksum
        )));
    }
    if !boot.has_code() {
        return Err(error(
            "Missing boot code: the boot code area 0xC-0x3FF is zero",
        ));
    }
    let mut c = Container::new(
        FileFormat::Adf,
        Layout::BootFloppy(density).label(),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(geometry.describe());
    let reason = match DosType::from_flags(boot.flags()) {
        Some(dos) => match mount(data, 0, geometry.blocks(), FLOPPY_RESERVED, dos) {
            Ok(mounted) => {
                return Err(error(format!(
                    "Invalid boot floppy: block {} holds a valid root block, so the disk holds \
                     an AmigaDOS volume",
                    mounted.root.number
                )))
            }
            Err(defect) => format!("no AmigaDOS root block ({defect})"),
        },
        None => format!(
            "no AmigaDOS volume (DOS type 0x{:02X} is not one of 0-7)",
            boot.flags()
        ),
    };
    c.notes.push(format!(
        "Bootable disk with {reason}: the tracks hold data in a layout of the disk's own, read \
         by its boot code, and are not interpreted"
    ));
    let boot_code = boot.boot_code("Boot block code");
    c.notes.push(boot_code.note.clone());
    push_boot_metadata(&boot, KEY_PREFIX, &mut c);
    c.children.extend(boot_code.child);
    Ok(c)
}

/// Boot block metadata: the checksum and `bb_dosblock`.
pub(super) fn push_boot_metadata(boot: &BootBlock<'_>, key: &str, c: &mut Container<'_>) {
    let checksum = if boot.is_checksum_valid() {
        format!("0x{:08X} (valid)", boot.stored_checksum)
    } else {
        format!(
            "0x{:08X} (invalid; 0x{:08X} expected)",
            boot.stored_checksum, boot.computed_checksum
        )
    };
    c.push_metadata(
        format!("{key}_boot_checksum"),
        "Boot block checksum",
        checksum,
    );
    c.push_metadata(
        format!("{key}_boot_dos_block"),
        "Boot block bb_dosblock",
        u64::from(boot.dos_block),
    );
}

/// Notes and metadata for a mounted volume. `drive` starts the notes
/// (`""`, or `"DH0: "` on a partitioned disk) and `key` the metadata keys
/// (`adf`, or `adf_partition_0`).
pub(super) fn describe(mounted: &Mounted<'_>, drive: &str, key: &str, c: &mut Container<'_>) {
    let volume = &mounted.volume;
    let root = &mounted.root;
    let name = root.bstr(NAME, MAX_NAME_LEN).map(latin1);
    let name_text = name.as_ref().map_or_else(
        || "with an invalid name length".to_string(),
        |n| format!("\"{n}\""),
    );
    c.notes.push(format!(
        "{drive}AmigaDOS volume {name_text}: {} ({}); {} blocks, root block {} at 0x{:X}",
        volume.dos.description(),
        volume.dos.name(),
        volume.blocks,
        root.number,
        root.offset
    ));
    let table_size = root.long(HT_SIZE);
    if usize::try_from(table_size).ok() != Some(TABLE_ENTRIES) {
        c.notes.push(format!(
            "{drive}The root block gives a hash table size of {table_size}; {TABLE_ENTRIES} \
             entries are read"
        ));
    }
    c.notes.push(format!("{drive}{}", bitmap_note(mounted)));
    if volume.dos.has_dircache() {
        c.notes.push(format!(
            "{drive}Directory cache blocks are not read; directories are listed from their hash \
             tables"
        ));
    }
    c.push_metadata(format!("{key}_dos_type"), "DOS type", volume.dos.name());
    c.push_metadata(
        format!("{key}_filesystem"),
        "File system",
        volume.dos.description(),
    );
    if let Some(name) = name {
        c.push_metadata(format!("{key}_volume_name"), "Volume name", name);
    }
    c.push_metadata(
        format!("{key}_block_count"),
        "Blocks",
        u64::from(volume.blocks),
    );
    c.push_metadata(
        format!("{key}_root_block"),
        "Root block",
        u64::from(root.number),
    );
    for (field, suffix, label) in [
        (CREATION_DATE, "created", "Formatted"),
        (VOLUME_DATE, "modified", "Last changed"),
    ] {
        if let Some(date) = date_text(root.long(field), root.long(field + 4), root.long(field + 8))
        {
            c.push_metadata(format!("{key}_{suffix}"), label, date);
        }
    }
}

/// What the root block says about the bitmap, and whether the bitmap
/// blocks it lists pass their checksum (long 0, the normal algorithm:
/// [FAQ] 4.3). Bitmap extension blocks are not read, and the map itself is
/// not compared with the blocks the files use.
fn bitmap_note(mounted: &Mounted<'_>) -> String {
    let root = &mounted.root;
    let flag = root.long(BM_FLAG);
    let pages: Vec<u32> = (0..BM_PAGE_COUNT)
        .map(|i| root.long(BM_PAGES + 4 * i))
        .filter(|&page| page != 0)
        .collect();
    let failed = pages
        .iter()
        .filter(|&&page| {
            mounted
                .volume
                .block(page)
                .map_or(true, |block| !block.is_checksum_valid())
        })
        .count();
    let mapped = usize::try_from(
        mounted
            .volume
            .blocks
            .saturating_sub(mounted.volume.reserved),
    )
    .unwrap_or(usize::MAX);
    let needed = div_round_up(mapped, BLOCKS_PER_BITMAP_BLOCK);
    let mut parts = Vec::new();
    if flag != BM_VALID {
        parts.push(format!(
            "the root block marks it as not valid (bm_flag 0x{flag:08X})"
        ));
    }
    parts.push(if failed == 0 {
        format!(
            "{} listed in the root block, checksums valid",
            counted(pages.len(), "block", "blocks")
        )
    } else {
        format!(
            "{failed} of {} listed in the root block unreadable or failing their checksum",
            counted(pages.len(), "block", "blocks")
        )
    });
    if pages.len() < needed.min(BM_PAGE_COUNT) {
        parts.push(format!("{needed} needed to map {mapped} blocks"));
    }
    if root.long(BM_EXT) != 0 {
        parts.push(format!(
            "bitmap extension blocks from block {} are not read",
            root.long(BM_EXT)
        ));
    }
    format!("Bitmap: {}", parts.join("; "))
}

/// An `AmigaDOS` date stamp ([FAQ] 4.2: days since 1 January 1978, minutes
/// past midnight, ticks of 1/50 s) as `YYYY-MM-DD HH:MM:SS`, unless a field
/// is out of range. "A day value of zero is considered illegal by most
/// programs", so day 0 gives none.
fn date_text(days: u32, minutes: u32, ticks: u32) -> Option<String> {
    if days == 0 || minutes >= MINUTES_PER_DAY || ticks >= TICKS_PER_MINUTE {
        return None;
    }
    let date = civil_from_days(i64::from(days) + EPOCH_DAYS);
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        date.year,
        date.month,
        date.day,
        minutes / 60,
        minutes % 60,
        ticks / TICKS_PER_SECOND
    ))
}

/// A proleptic Gregorian calendar date.
struct CivilDate {
    year: i64,
    month: i64,
    day: i64,
}

/// The date `days` after 1970-01-01, by Howard Hinnant's `civil_from_days`
/// ("chrono-Compatible Low-Level Date Algorithms").
fn civil_from_days(days: i64) -> CivilDate {
    const DAYS_PER_ERA: i64 = 146_097;
    let z = days + 719_468;
    let era = z.div_euclid(DAYS_PER_ERA);
    let day_of_era = z - era * DAYS_PER_ERA;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    CivilDate { year, month, day }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_types_name_their_file_system_and_modes() {
        let names: Vec<String> = (0..=7)
            .map(|flags| DosType::from_flags(flags).unwrap().description())
            .collect();
        assert_eq!(
            names,
            [
                "OFS",
                "FFS",
                "OFS, international mode",
                "FFS, international mode",
                "OFS, international mode, directory cache",
                "FFS, international mode, directory cache",
                "OFS, international mode, long file names",
                "FFS, international mode, long file names",
            ]
        );
        assert_eq!(DosType::from_flags(8), None);
        assert_eq!(DosType::from_flags(3).unwrap().name(), "DOS\\3");
        assert_eq!(DosType::from_flags(0).unwrap().data_size(), 488);
        assert_eq!(DosType::from_flags(1).unwrap().data_size(), 512);
    }

    #[test]
    fn floppy_sizes_give_their_geometry() {
        let dd = FloppyGeometry::of_size(901_120).unwrap();
        assert_eq!(
            (dd.density, dd.cylinders, dd.blocks()),
            (Density::Double, 80, 1760)
        );
        let hd = FloppyGeometry::of_size(1_802_240).unwrap();
        assert_eq!((hd.density, hd.blocks()), (Density::High, 3520));
        assert_eq!(
            FloppyGeometry::of_size(83 * 2 * 11 * 512)
                .unwrap()
                .cylinders,
            83
        );
        assert_eq!(FloppyGeometry::of_size(901_120 - 512), None);
        assert_eq!(FloppyGeometry::of_size(84 * 2 * 11 * 512), None);
    }

    #[test]
    fn root_blocks_lie_in_the_middle() {
        assert_eq!(root_candidates(1760, 2), [880]);
        assert_eq!(root_candidates(3520, 2), [1760]);
        // An odd block count: the FAQ formula first, then blocks / 2.
        assert_eq!(root_candidates(1001, 2), [501, 500]);
        assert_eq!(root_candidates(1001, 1), [500]);
    }

    #[test]
    fn date_stamps_count_from_1978() {
        assert_eq!(date_text(1, 0, 0).as_deref(), Some("1978-01-02 00:00:00"));
        // 1993-05-17 is day 5615 after 1978-01-01.
        assert_eq!(
            date_text(5615, 12 * 60 + 34, 56 * 50 + 7).as_deref(),
            Some("1993-05-17 12:34:56")
        );
        assert_eq!(
            date_text(8095, 0, 0).as_deref(),
            Some("2000-03-01 00:00:00")
        );
        assert_eq!(date_text(0, 0, 0), None);
        assert_eq!(date_text(1, 1440, 0), None);
        assert_eq!(date_text(1, 0, 3000), None);
    }
}
