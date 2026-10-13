//! Hard disk images with a Rigid Disk Block: the `RDSK` block, its
//! partition list and its file system header list with their load segment
//! blocks ([RKRM] `devices/hardblocks.h` and `dos/filehandler.h`; [FAQ] 6;
//! [LINUX] `block/partitions/amiga.c`). Each `AmigaDOS` partition is
//! walked as a volume; other partitions are listed when their bytes are a
//! recognized format, and file system handlers are listed when their load
//! segments hold a Hunk executable.

use super::boot::{BootBlock, FLOPPY_BOOT_BLOCKS};
use super::volume::{self, DosType, KEY_PREFIX};
use super::walk::{self, Census};
use super::*;
use crate::formats::amiga_hunk::HUNK_HEADER;
use crate::formats::container::{Child, MAX_COMPONENTS};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// Block identifiers ([RKRM] `devices/hardblocks.h`: `IDNAME_RIGIDDISK`,
/// `IDNAME_PARTITION`, `IDNAME_FILESYSHEADER`, `IDNAME_LOADSEG`).
const IDNAME_RIGIDDISK: [u8; 4] = *b"RDSK";
const IDNAME_PARTITION: [u8; 4] = *b"PART";
const IDNAME_FILESYSHEADER: [u8; 4] = *b"FSHD";
const IDNAME_LOADSEG: [u8; 4] = *b"LSEG";

/// "The `RigidDiskBlock` must exist on the disk within the first
/// `RDB_LOCATION_LIMIT` blocks" ([RKRM] `devices/hardblocks.h`).
const RDB_LOCATION_LIMIT: u32 = 16;

/// "optional block addresses below contain $ffffffff to indicate a NULL
/// address, as zero is a valid address" ([RKRM] `devices/hardblocks.h`).
const NO_BLOCK: u32 = 0xffff_ffff;

/// `*_SummedLongs`, the size of the checksummed structure in longs; the
/// checksum makes those longs sum to zero ([RKRM] `devices/hardblocks.h`).
const SUMMED_LONGS: usize = 0x04;

/// Longs of the `RigidDiskBlock`, `PartitionBlock` and
/// `FileSysHeaderBlock` structures (256 B each: "using only the first 256
/// bytes for all blocks but the `LoadSeg` data").
const STRUCTURE_LONGS: usize = 64;

/// Longs of the `LoadSegBlock` header before `lsb_LoadData`, plus one long
/// of data: the shortest load segment block.
const MIN_LOADSEG_LONGS: usize = 6;

/// `RigidDiskBlock` fields.
const RDB_BLOCK_BYTES: usize = 0x10;
const RDB_FLAGS: usize = 0x14;
const RDB_BAD_BLOCK_LIST: usize = 0x18;
const RDB_PARTITION_LIST: usize = 0x1c;
const RDB_FILE_SYS_HEADER_LIST: usize = 0x20;
const RDB_DRIVE_INIT: usize = 0x24;
const RDB_CYLINDERS: usize = 0x40;
const RDB_SECTORS: usize = 0x44;
const RDB_HEADS: usize = 0x48;
/// `rdb_DiskVendor[8]`, `rdb_DiskProduct[16]`, `rdb_DiskRevision[4]`.
const RDB_DISK_VENDOR: usize = 0xa0;
const RDB_DISK_PRODUCT: usize = 0xa8;
const RDB_DISK_REVISION: usize = 0xb8;
const RDB_DISK_IDENTIFICATION_END: usize = 0xbc;
/// `RDBFF_DISKID`: "`rdb_Disk`... identification valid".
const RDBFF_DISKID: u32 = 0x10;

/// `PartitionBlock` fields.
const PB_NEXT: usize = 0x10;
const PB_FLAGS: usize = 0x14;
/// `pb_DriveName[32]`, "preferred DOS device name: BSTR form".
const PB_DRIVE_NAME: usize = 0x24;
const MAX_DRIVE_NAME_LEN: usize = 31;
/// `pb_Environment[17]`, continued by `pb_EReserved[15]` ("reserved for
/// future environment vector"): at most 32 longs.
const PB_ENVIRONMENT: usize = 0x80;
const MAX_ENVIRONMENT_LONGS: usize = 32;
/// `PBFF_BOOTABLE`, `PBFF_NOMOUNT`.
const PBFF_BOOTABLE: u32 = 0x01;
const PBFF_NOMOUNT: u32 = 0x02;

/// `DosEnvec` indexes ([RKRM] `dos/filehandler.h`). Entry `i` is present
/// when `de_TableSize` is at least `i`.
const DE_SIZEBLOCK: usize = 1;
const DE_NUMHEADS: usize = 3;
const DE_SECSPERBLK: usize = 4;
const DE_BLKSPERTRACK: usize = 5;
const DE_RESERVEDBLKS: usize = 6;
const DE_LOWCYL: usize = 9;
const DE_UPPERCYL: usize = 10;
const DE_BOOTPRI: usize = 15;
const DE_DOSTYPE: usize = 16;
const DE_BOOTBLOCKS: usize = 19;
/// `de_SizeBlock` of 512-byte blocks, in longs ("standard value is 128").
const SIZE_BLOCK_LONGS: u32 = 128;

/// Most boot blocks read from a partition. `de_BootBlocks` has no bound in
/// the sources; this one is ours.
const MAX_BOOT_BLOCKS: u32 = 64;

/// `FileSysHeaderBlock` fields.
const FHB_NEXT: usize = 0x10;
const FHB_DOS_TYPE: usize = 0x20;
const FHB_VERSION: usize = 0x24;
const FHB_SEG_LIST_BLOCKS: usize = 0x48;

/// `LoadSegBlock` fields: `lsb_Next` and `lsb_LoadData`, "code stored like
/// an executable, with relocation hunks" ([FAQ] 6.5).
const LSB_NEXT: usize = 0x10;
const LSB_LOAD_DATA: usize = 0x14;

/// Most partitions and file system headers read. [LINUX] reads 16
/// partitions; the sources set no bound, and this one is ours.
const MAX_LIST_LENGTH: usize = 128;

/// Transform of a file system handler assembled from its load segment
/// blocks.
const LOADSEG_TRANSFORM: &str = "RDB LoadSeg blocks";

/// Recognize a Rigid Disk Block: see [`super::detect`].
pub(super) fn detect(data: &[u8]) -> bool {
    find_rdb(data).is_some()
}

/// The first valid `RigidDiskBlock` in the first 16 blocks. Every input
/// passes through here, so blocks without the identifier are passed over
/// before anything else is computed.
fn find_rdb(data: &[u8]) -> Option<Block<'_>> {
    (0..RDB_LOCATION_LIMIT)
        .filter(|&number| starts_with_rdsk(data, number))
        .find_map(|number| rigid_disk_block(data, number).ok())
}

/// The `RigidDiskBlock` in disk block `number`. After block 0 its
/// partition list must start at a valid `PART` block: a disk image stored
/// inside another file (the first member of a tar archive) has its `RDSK`
/// block at block 1, and its block pointers, which count from the start of
/// the disk, then miss. The rule is ours.
fn rigid_disk_block(data: &[u8], number: u32) -> Walk<Block<'_>> {
    let rdb = structure(data, number, IDNAME_RIGIDDISK, STRUCTURE_LONGS)?;
    if number == 0 {
        return Ok(rdb);
    }
    let first = rdb.long(RDB_PARTITION_LIST);
    structure(data, first, IDNAME_PARTITION, STRUCTURE_LONGS).map_err(|defect| {
        format!(
            "the RDSK block {number} follows other data and its partition list does not start \
             at a partition block ({defect})"
        )
    })?;
    Ok(rdb)
}

/// Disk block `number` starts with `RDSK`.
fn starts_with_rdsk(data: &[u8], number: u32) -> bool {
    disk_block(data, number).is_some_and(|block| block.bytes[..4] == IDNAME_RIGIDDISK)
}

/// Disk block `number`, if the input holds all of it.
fn disk_block(data: &[u8], number: u32) -> Option<Block<'_>> {
    let offset = usize::try_from(number).ok()?.checked_mul(BLOCK_SIZE)?;
    Block::at(data, number, offset)
}

/// The Rigid Disk Block structure `id` in disk block `number`: the input
/// holds the block, `id` starts it, its summed longs lie between
/// `min_longs` and the block size, and they sum to zero.
fn structure(data: &[u8], number: u32, id: [u8; 4], min_longs: usize) -> Walk<Block<'_>> {
    let block = disk_block(data, number)
        .ok_or_else(|| format!("block {number} lies beyond the end of the input"))?;
    let name = String::from_utf8_lossy(&id).into_owned();
    if block.bytes[..4] != id {
        return Err(format!("block {number} does not start with {name}"));
    }
    let longs = usize::try_from(block.long(SUMMED_LONGS)).unwrap_or(usize::MAX);
    if !(min_longs..=BLOCK_LONGS).contains(&longs) {
        return Err(format!(
            "the {name} block {number} sums {longs} longs, not {min_longs} to {BLOCK_LONGS}"
        ));
    }
    if block.sum(longs) != 0 {
        return Err(format!("the {name} block {number} fails its checksum"));
    }
    Ok(block)
}

/// Parse a hard disk image with a Rigid Disk Block.
///
/// # Errors
///
/// [`ClassifierError::AdfParseError`] when the first 16 blocks hold no
/// valid `RigidDiskBlock` or it gives a block size other than 512 B.
/// Problems in the partition and file system lists are notes.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let rdb = find_rdb(data).ok_or_else(|| error(missing_rdb(data)))?;
    let block_bytes = rdb.long(RDB_BLOCK_BYTES);
    if usize::try_from(block_bytes).ok() != Some(BLOCK_SIZE) {
        return Err(error(format!(
            "Unsupported rdb_BlockBytes {block_bytes} at 0x{:X}: only 512-byte blocks are read",
            rdb.offset + RDB_BLOCK_BYTES
        )));
    }
    let mut c = Container::new(FileFormat::AmigaHdf, Layout::RigidDisk.label(), KEY_PREFIX);
    c.consumed = data.len();
    describe_rdb(data, &rdb, &mut c);
    let mut disk = Disk {
        data,
        read: BlockSet::new(data.len() / BLOCK_SIZE),
        census: Census::default(),
        walked: 0,
        handlers: Vec::new(),
        boot_codes: Vec::new(),
    };
    disk.read.insert(rdb.number);
    disk.partitions(&rdb, &mut c);
    disk.file_systems(&rdb, &mut c);
    if disk.walked > 0 {
        disk.census.report(&mut c);
    }
    // Partitions and their files first, then the code that loads them.
    c.children.extend(disk.handlers);
    c.children.extend(disk.boot_codes);
    Ok(c)
}

/// The error for an input whose first 16 blocks hold no valid
/// `RigidDiskBlock`.
fn missing_rdb(data: &[u8]) -> String {
    let damaged = (0..RDB_LOCATION_LIMIT)
        .filter(|&number| starts_with_rdsk(data, number))
        .find_map(|number| rigid_disk_block(data, number).err());
    match damaged {
        Some(defect) => format!("Invalid Rigid Disk Block: {defect}"),
        None => {
            format!("Missing Rigid Disk Block: no RDSK in the first {RDB_LOCATION_LIMIT} blocks")
        }
    }
}

/// Notes and metadata for the `RigidDiskBlock` itself.
fn describe_rdb(data: &[u8], rdb: &Block<'_>, c: &mut Container<'_>) {
    let cylinders = rdb.long(RDB_CYLINDERS);
    let heads = rdb.long(RDB_HEADS);
    let sectors = rdb.long(RDB_SECTORS);
    let blocks = u64::from(cylinders) * u64::from(heads) * u64::from(sectors);
    c.notes.push(format!(
        "Rigid Disk Block at block {} (0x{:X}): {cylinders} cylinders, {heads} heads, {sectors} \
         sectors per track ({blocks} blocks of 512 B)",
        rdb.number, rdb.offset
    ));
    let image_blocks = data.len() as u64 / BLOCK_SIZE as u64;
    if blocks > image_blocks {
        c.notes.push(format!(
            "The drive geometry gives {blocks} blocks; the image holds {image_blocks}"
        ));
    }
    if rdb.long(RDB_FLAGS) & RDBFF_DISKID != 0 {
        let field = |start: usize, end: usize| {
            latin1(&rdb.bytes[start..end])
                .trim_end_matches(['\0', ' '])
                .to_string()
        };
        let identification = [
            field(RDB_DISK_VENDOR, RDB_DISK_PRODUCT),
            field(RDB_DISK_PRODUCT, RDB_DISK_REVISION),
            field(RDB_DISK_REVISION, RDB_DISK_IDENTIFICATION_END),
        ];
        c.notes.push(format!(
            "Drive identification: vendor \"{}\", product \"{}\", revision \"{}\"",
            identification[0], identification[1], identification[2]
        ));
        for (key, label, value) in [
            ("disk_vendor", "Disk vendor", &identification[0]),
            ("disk_product", "Disk product", &identification[1]),
            ("disk_revision", "Disk revision", &identification[2]),
        ] {
            c.push_metadata(format!("{KEY_PREFIX}_{key}"), label, value.clone());
        }
    }
    let bad_blocks = rdb.long(RDB_BAD_BLOCK_LIST);
    if bad_blocks != NO_BLOCK {
        c.notes.push(format!(
            "A bad block list starts at block {bad_blocks}; its replacement blocks are not applied \
             when the partitions are read"
        ));
    }
    let drive_init = rdb.long(RDB_DRIVE_INIT);
    if drive_init != NO_BLOCK {
        c.notes.push(format!(
            "Drive initialization code at block {drive_init} is not extracted"
        ));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_rdb_block"),
        "Rigid Disk Block",
        u64::from(rdb.number),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_geometry"),
        "Drive geometry",
        format!("{cylinders} cylinders, {heads} heads, {sectors} sectors"),
    );
}

/// A partition's environment vector ([RKRM] `dos/filehandler.h`
/// `DosEnvec`): the entries that `de_TableSize` says are present.
struct Environment {
    longs: Vec<u32>,
}

impl Environment {
    fn read(block: &Block<'_>) -> Self {
        let table_size = usize::try_from(block.long(PB_ENVIRONMENT)).unwrap_or(usize::MAX);
        let count = table_size.saturating_add(1).min(MAX_ENVIRONMENT_LONGS);
        Self {
            longs: (0..count)
                .map(|i| block.long(PB_ENVIRONMENT + 4 * i))
                .collect(),
        }
    }

    /// Entry `index`, when the table holds it.
    fn get(&self, index: usize) -> Option<u32> {
        self.longs.get(index).copied()
    }
}

/// Where a partition lies on the disk.
#[derive(Debug)]
struct Extent {
    /// First disk block.
    start: u64,
    /// Blocks in the partition.
    blocks: u32,
}

/// A partition whose start lies in the input.
struct Partition<'a> {
    /// Zero-based position in the partition list.
    index: usize,
    /// `pb_DriveName`, or `Partition <n>` when it is empty or invalid.
    drive: String,
    /// Prefix of the partition's metadata keys.
    key: String,
    environment: Environment,
    extent: Extent,
    /// File offset of the first block.
    offset: usize,
    /// Bytes of the partition that the input holds.
    present: usize,
    boot: BootBlock<'a>,
}

/// The state of a Rigid Disk Block parse.
struct Disk<'a> {
    data: &'a [u8],
    /// The Rigid Disk Block structures read, so that no list loops.
    read: BlockSet,
    census: Census,
    /// `AmigaDOS` volumes walked.
    walked: usize,
    /// File system handlers, listed after the partitions.
    handlers: Vec<Child<'a>>,
    /// Partition boot code, listed last.
    boot_codes: Vec<Child<'a>>,
}

impl<'a> Disk<'a> {
    /// Walk the partition list.
    fn partitions(&mut self, rdb: &Block<'a>, c: &mut Container<'a>) {
        let mut next = rdb.long(RDB_PARTITION_LIST);
        let mut index = 0usize;
        while next != NO_BLOCK {
            if index == MAX_LIST_LENGTH {
                c.notes.push(format!(
                    "The partition list continues past {MAX_LIST_LENGTH} partitions; the rest is \
                     not read"
                ));
                return;
            }
            let block = match structure(self.data, next, IDNAME_PARTITION, STRUCTURE_LONGS) {
                Ok(block) => block,
                Err(defect) => {
                    c.notes
                        .push(format!("The partition list ends early: {defect}"));
                    return;
                }
            };
            if !self.read.insert(next) {
                c.notes.push(format!(
                    "The partition list loops back to block {next}; it ends there"
                ));
                return;
            }
            self.partition(index, &block, c);
            next = block.long(PB_NEXT);
            index += 1;
        }
        if index == 0 {
            c.notes
                .push("The Rigid Disk Block lists no partitions".to_string());
        }
    }

    /// One partition: its extent from the environment, then its volume.
    fn partition(&mut self, index: usize, block: &Block<'a>, c: &mut Container<'a>) {
        let drive = block
            .bstr(PB_DRIVE_NAME, MAX_DRIVE_NAME_LEN)
            .map(latin1)
            .filter(|name| !name.is_empty() && !name.contains(['/', ':']))
            .unwrap_or_else(|| format!("Partition {}", index + 1));
        let environment = Environment::read(block);
        let extent = match partition_extent(&environment) {
            Ok(extent) => extent,
            Err(defect) => {
                c.notes.push(format!(
                    "{drive} (partition block {}): {defect}; not read",
                    block.number
                ));
                return;
            }
        };
        let Some(offset) = extent
            .start
            .checked_mul(BLOCK_SIZE as u64)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|&offset| offset < self.data.len())
        else {
            c.notes.push(format!(
                "{drive}: the partition starts at block {}, beyond the end of the input",
                extent.start
            ));
            return;
        };
        c.notes
            .push(partition_note(&drive, block, &environment, &extent, offset));
        let full_size = u64::from(extent.blocks) * BLOCK_SIZE as u64;
        let present = usize::try_from(full_size).map_or(self.data.len() - offset, |size| {
            size.min(self.data.len() - offset)
        });
        if (present as u64) < full_size {
            c.notes.push(format!(
                "{drive}: the partition ends beyond the end of the input; {} of it is present",
                size_text(present as u64)
            ));
        }
        let boot_blocks = environment
            .get(DE_BOOTBLOCKS)
            .filter(|&n| n > 0)
            .map_or(FLOPPY_BOOT_BLOCKS, |n| {
                usize::try_from(n.min(MAX_BOOT_BLOCKS).min(extent.blocks)).unwrap_or(1)
            });
        let Some(boot) = BootBlock::read(self.data, offset, boot_blocks) else {
            c.notes.push(format!(
                "{drive}: the boot block at 0x{offset:X} lies beyond the end of the input"
            ));
            return;
        };
        let partition = Partition {
            index,
            key: format!("{KEY_PREFIX}_partition_{index}"),
            drive,
            environment,
            extent,
            offset,
            present,
            boot,
        };
        c.push_metadata(
            partition.key.clone(),
            format!("Partition {}", index + 1),
            format!(
                "{}; first block {}; {} blocks; file 0x{offset:X}",
                partition.drive, partition.extent.start, partition.extent.blocks
            ),
        );
        let boot = &partition.boot;
        match DosType::from_flags(boot.flags()).filter(|_| boot.has_dos_signature()) {
            Some(dos) => self.dos_volume(&partition, dos, c),
            None => self.foreign_volume(&partition, c),
        }
    }

    /// An `AmigaDOS` partition: the file system is the one its boot block
    /// names ([FAQ] 6.3: "Don't rely only on the PART and FSHD `DosType`
    /// field").
    fn dos_volume(&mut self, partition: &Partition<'a>, dos: DosType, c: &mut Container<'a>) {
        let drive = &partition.drive;
        let boot = &partition.boot;
        if let Some(listed) = partition.environment.get(DE_DOSTYPE) {
            if listed != u32::from_be_bytes(boot.id) {
                c.notes.push(format!(
                    "{drive}: the environment names DOS type {}, the boot block {}; the boot \
                     block is used",
                    dos_type_text(listed),
                    dos.name()
                ));
            }
        }
        // [FAQ] 6.3: reserved blocks are "usually = 2 (minimum 1)".
        let reserved = partition
            .environment
            .get(DE_RESERVEDBLKS)
            .filter(|&n| n >= 1)
            .unwrap_or(2);
        let blocks = partition.extent.blocks;
        match volume::mount(self.data, partition.offset, blocks, reserved, dos) {
            Ok(mounted) => {
                volume::describe(&mounted, &format!("{drive}: "), &partition.key, c);
                walk::walk_volume(&mounted, &format!("{drive}:"), &mut self.census, c);
                self.walked += 1;
            }
            Err(defect) => c.notes.push(format!(
                "{drive}: {} partition without a valid root block ({defect}); not walked",
                dos.name()
            )),
        }
        let boot_code = boot.boot_code(&format!("{drive}: boot block code"));
        c.notes.push(boot_code.note);
        volume::push_boot_metadata(boot, &partition.key, c);
        self.boot_codes.extend(boot_code.child);
    }

    /// A partition with another file system (Professional File System,
    /// Smart File System, a foreign format): listed when its bytes are a
    /// recognized format.
    fn foreign_volume(&mut self, partition: &Partition<'a>, c: &mut Container<'a>) {
        let drive = &partition.drive;
        c.notes.push(format!(
            "{drive}: the boot block starts with {}, not an AmigaDOS DOS type; the partition is \
             listed only if it is a recognized format",
            dos_type_text(u32::from_be_bytes(partition.boot.id))
        ));
        if c.children.len() >= MAX_COMPONENTS {
            return;
        }
        let start = partition.offset;
        let child = Child::stored(
            format!("Partition {} ({drive})", partition.index + 1),
            start,
            &self.data[start..start + partition.present],
        );
        c.children.push(child.if_recognized());
    }

    /// Walk the file system header list and list each handler whose load
    /// segments hold a Hunk executable.
    fn file_systems(&mut self, rdb: &Block<'a>, c: &mut Container<'a>) {
        let mut next = rdb.long(RDB_FILE_SYS_HEADER_LIST);
        let mut count = 0usize;
        while next != NO_BLOCK {
            if count == MAX_LIST_LENGTH {
                c.notes.push(format!(
                    "The file system header list continues past {MAX_LIST_LENGTH} entries; the \
                     rest is not read"
                ));
                return;
            }
            let block = match structure(self.data, next, IDNAME_FILESYSHEADER, STRUCTURE_LONGS) {
                Ok(block) => block,
                Err(defect) => {
                    c.notes
                        .push(format!("The file system header list ends early: {defect}"));
                    return;
                }
            };
            if !self.read.insert(next) {
                c.notes.push(format!(
                    "The file system header list loops back to block {next}; it ends there"
                ));
                return;
            }
            self.file_system(&block, c);
            next = block.long(FHB_NEXT);
            count += 1;
        }
    }

    /// One file system header and its load segment chain.
    fn file_system(&mut self, header: &Block<'a>, c: &mut Container<'a>) {
        let dos_type = dos_type_text(header.long(FHB_DOS_TYPE));
        let version = header.long(FHB_VERSION);
        let name = format!(
            "File system {dos_type} version {}.{}",
            version >> 16,
            version & 0xffff
        );
        let first = header.long(FHB_SEG_LIST_BLOCKS);
        if first == NO_BLOCK {
            c.notes.push(format!(
                "{name} (block {}): no load segment blocks",
                header.number
            ));
            return;
        }
        let segments = match self.load_segments(first) {
            Ok(segments) => segments,
            Err(defect) => {
                c.notes.push(format!(
                    "{name} (block {}): {defect}; not extracted",
                    header.number
                ));
                return;
            }
        };
        let starts_with_hunk_header = segments
            .bytes
            .get(..4)
            .is_some_and(|word| word == HUNK_HEADER.to_be_bytes());
        c.notes.push(format!(
            "{name} (block {}): {} load segment blocks from block {first}, {} B{}",
            header.number,
            segments.blocks,
            segments.bytes.len(),
            if starts_with_hunk_header {
                ""
            } else {
                " that do not start with HUNK_HEADER; not classified"
            }
        ));
        if starts_with_hunk_header {
            self.handlers.push(Child::decoded(
                name,
                segments.offset,
                segments.stored_size,
                Cow::Owned(segments.bytes),
                LOADSEG_TRANSFORM,
            ));
        }
    }

    /// The concatenated `lsb_LoadData` of the load segment chain from
    /// block `first`.
    fn load_segments(&mut self, first: u32) -> Walk<LoadSegments> {
        let mut bytes = Vec::new();
        let mut first_run: Option<(usize, usize)> = None;
        let mut blocks = 0usize;
        let mut next = first;
        while next != NO_BLOCK {
            let block = structure(self.data, next, IDNAME_LOADSEG, MIN_LOADSEG_LONGS)?;
            if !self.read.insert(next) {
                return Err(format!(
                    "the load segment chain reaches block {next} a second time"
                ));
            }
            let longs = usize::try_from(block.long(SUMMED_LONGS)).expect("checked by structure");
            let load_data = &block.bytes[LSB_LOAD_DATA..longs * 4];
            if bytes.len() + load_data.len() > MAX_PAYLOAD {
                return Err(format!(
                    "the load segments exceed the {} extraction limit",
                    size_text(MAX_PAYLOAD as u64)
                ));
            }
            first_run.get_or_insert((block.offset + LSB_LOAD_DATA, load_data.len()));
            bytes.extend_from_slice(load_data);
            blocks += 1;
            next = block.long(LSB_NEXT);
        }
        let (offset, stored_size) = first_run.expect("the chain starts with a block");
        Ok(LoadSegments {
            bytes,
            offset,
            stored_size,
            blocks,
        })
    }
}

/// A file system handler's load segments.
struct LoadSegments {
    bytes: Vec<u8>,
    /// File offset and size of the first block's load data.
    offset: usize,
    stored_size: usize,
    blocks: usize,
}

/// The extent of a partition from its environment ([LINUX]: start
/// `LowCyl × Surfaces × BlocksPerTrack`, size `(HighCyl - LowCyl + 1) ×
/// Surfaces × BlocksPerTrack`). Only 512-byte blocks of one sector are
/// read.
fn partition_extent(environment: &Environment) -> Walk<Extent> {
    let field = |index: usize| {
        environment
            .get(index)
            .ok_or_else(|| format!("the environment vector ends before entry {index}"))
    };
    let size_block = field(DE_SIZEBLOCK)?;
    if size_block != SIZE_BLOCK_LONGS {
        return Err(format!(
            "unsupported block size of {size_block} longs (only 128, 512 B, is read)"
        ));
    }
    let sectors_per_block = field(DE_SECSPERBLK)?;
    if sectors_per_block != 1 {
        return Err(format!(
            "unsupported {sectors_per_block} sectors per block (only 1 is read)"
        ));
    }
    let surfaces = u64::from(field(DE_NUMHEADS)?);
    let blocks_per_track = u64::from(field(DE_BLKSPERTRACK)?);
    let low = u64::from(field(DE_LOWCYL)?);
    let high = u64::from(field(DE_UPPERCYL)?);
    if surfaces == 0 || blocks_per_track == 0 || high < low {
        return Err(format!(
            "invalid geometry: {surfaces} surfaces, {blocks_per_track} blocks per track, \
             cylinders {low}-{high}"
        ));
    }
    let cylinder_blocks = surfaces * blocks_per_track;
    let start = low * cylinder_blocks;
    let blocks = u32::try_from((high - low + 1) * cylinder_blocks).map_err(|_| {
        format!(
            "{} blocks exceed what AmigaDOS addresses",
            (high - low + 1) * cylinder_blocks
        )
    })?;
    Ok(Extent { start, blocks })
}

/// The note describing a partition.
fn partition_note(
    drive: &str,
    block: &Block<'_>,
    environment: &Environment,
    extent: &Extent,
    offset: usize,
) -> String {
    let flags = block.long(PB_FLAGS);
    let mut parts = vec![format!(
        "{drive} (partition block {}): cylinders {}-{}, {} blocks from block {} (0x{offset:X})",
        block.number,
        environment.get(DE_LOWCYL).unwrap_or(0),
        environment.get(DE_UPPERCYL).unwrap_or(0),
        extent.blocks,
        extent.start
    )];
    if flags & PBFF_BOOTABLE != 0 {
        let priority = environment.get(DE_BOOTPRI).map_or(0, volume::signed);
        parts.push(format!("bootable, boot priority {priority}"));
    }
    if flags & PBFF_NOMOUNT != 0 {
        parts.push("not mounted automatically".to_string());
    }
    parts.join("; ")
}

/// A DOS type long as `AmigaOS` prints it: three characters and the number
/// of the fourth byte (`DOS\3`), four characters, or hex.
fn dos_type_text(dos_type: u32) -> String {
    let bytes = dos_type.to_be_bytes();
    let printable = |b: &u8| b.is_ascii_graphic();
    if bytes[..3].iter().all(printable) {
        let prefix = String::from_utf8_lossy(&bytes[..3]).into_owned();
        if printable(&bytes[3]) {
            format!("{prefix}{}", char::from(bytes[3]))
        } else {
            format!("{prefix}\\{}", bytes[3])
        }
    } else {
        format!("0x{dos_type:08X}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_types_print_as_amigaos_does() {
        assert_eq!(dos_type_text(0x444f_5303), "DOS\\3");
        assert_eq!(dos_type_text(0x5046_5303), "PFS\\3");
        assert_eq!(dos_type_text(0x7265_7376), "resv");
        assert_eq!(dos_type_text(0x0000_0001), "0x00000001");
    }

    #[test]
    fn partition_extents_come_from_the_environment() {
        // TableSize 16, SizeBlock 128, SecOrg 0, Surfaces 2, SectorPerBlock
        // 1, BlocksPerTrack 32, Reserved 2, PreAlloc 0, Interleave 0,
        // LowCyl 2, HighCyl 9, ...
        let mut longs = vec![16, 128, 0, 2, 1, 32, 2, 0, 0, 2, 9];
        longs.resize(17, 0);
        let environment = Environment { longs };
        let extent = partition_extent(&environment).unwrap();
        assert_eq!((extent.start, extent.blocks), (128, 512));
        let mut short = Environment {
            longs: vec![5, 128, 0, 2, 1, 32],
        };
        assert!(partition_extent(&short)
            .unwrap_err()
            .contains("ends before entry 9"));
        short.longs = vec![16, 256, 0, 2, 1, 32, 2, 0, 0, 2, 9];
        assert!(partition_extent(&short).unwrap_err().contains("block size"));
        short.longs = vec![16, 128, 0, 0, 1, 32, 2, 0, 0, 2, 9];
        assert!(partition_extent(&short).unwrap_err().contains("geometry"));
    }
}
