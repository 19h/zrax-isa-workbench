//! Apple II disk images: DOS 3.3 and `ProDOS` volumes in raw 16-sector or
//! block images (`.dsk`, `.do`, `.po`) and in 2IMG images (`.2mg`), with
//! every file a child labeled by its path and the boot code a child after
//! the files.
//!
//! Primary sources (pins and hashes in `docs/apple2.md`):
//! - [CP2] `CiderPress` II (`fadden/CiderPress2` at `7a055a20`):
//!   `DiskArc/FS/DOS-notes.md`, `DOS.cs`, `DOS_VTOC.cs`, `DOS_FileEntry.cs`,
//!   `ProDOS-notes.md`, `ProDOS.cs`, `ProDOS_FileEntry.cs`,
//!   `ProDOS_FileDesc.cs`, `DiskArc/Disk/TwoIMG-notes.md`, `TwoIMG.cs`,
//!   `Unadorned-notes.md` and the skew tables of `GeneralChunkAccess.cs`.
//! - [BAD] Worth and Lechner, "Beneath Apple DOS", the reference [CP2]
//!   cites for DOS: chapter 4 (VTOC, catalog, track/sector lists, file
//!   types, binary files, pp. 4-2 to 4-12) and chapter 5 (boot, p. 5-6).
//! - [TRM] Apple, "`ProDOS` 8 Technical Reference Manual": Preface, "Memory
//!   Use", "Writing a `ProDOS` System Program" and Appendix B (directory
//!   headers and entries, storage types, Figure B-15 for the sector to
//!   block mapping).
//! - [2IMG] magnet.ch "Disk Images" (web.archive.org snapshot
//!   19981206023530), the 2IMG description [CP2] cites.
//! - [A2REF] Apple, "Apple II Reference Manual" (1979), chapter 1: "a
//!   Synertek/MOS Technology 6502 microprocessor". [A2C] Apple, "Apple `IIc`
//!   Technical Reference Manual" (1985), section 2.1: the 65C02.
//!
//! DOS 3.3 and `ProDOS` 8 are operating systems of the Apple II, whose CPU is
//! a 6502 ([A2REF]) or, in the `IIc` and enhanced `IIe`, a 65C02 ([A2C]); `ProDOS`
//! 8 calls are made "in programs written in the 6502 machine language"
//! ([TRM] Preface). The disk names no CPU of its own, so the container has
//! no target. Binary (DOS `B`, `ProDOS` `BIN`) and system (`ProDOS` `SYS`)
//! files are memory images that `BLOAD`, `BRUN` and the `ProDOS` system
//! loader place in memory; they are children with a 6502 target (a binary
//! file may also hold data such as a picture, which is not told apart).
//! Every other file type is an opaque child. The boot sector or blocks,
//! which the disk controller ROM loads at 0x0800, follow the files as a
//! 6502 child. The variant (6502 or 65C02) is not fixed by the disk.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod dos33;
mod prodos;
mod twoimg;

/// A DOS sector and half a `ProDOS` block ([BAD] p. 4-3, [TRM] B.5).
const SECTOR_SIZE: usize = 256;

/// Sectors per track of a 16-sector 5.25" disk ([BAD] p. 4-3).
const SECTORS_PER_TRACK: usize = 16;

const TRACK_SIZE: usize = SECTOR_SIZE * SECTORS_PER_TRACK;

/// A `ProDOS` block ([TRM] B.1).
const BLOCK_SIZE: usize = 512;

/// Blocks per 16-sector track ([TRM] Figure B-15: block = 8 * track +
/// offset).
const BLOCKS_PER_TRACK: usize = TRACK_SIZE / BLOCK_SIZE;

/// The position within a track, in 256-byte units of a `ProDOS`-order image,
/// of each DOS 3.3 logical sector: `2 * offset + half - 1` from [TRM]
/// Figure B-15 (sector offsets `0 7 6 6 5 5 4 4 3 3 2 2 1 1 0 7`, halves
/// `1 1 2 1 2 1 2 1 2 1 2 1 2 1 2 2`). [CP2] `sDos2Phys` followed by
/// `sPhys2Prodos` gives the same table. It is its own inverse, so position
/// `p` of a `ProDOS`-order track holds DOS sector `DOS_SECTOR_POSITION[p]`.
const DOS_SECTOR_POSITION: [usize; SECTORS_PER_TRACK] =
    [0, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 15];

/// The Apple II CPU family ([A2REF], [A2C]).
const MOS_6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// Where the disk controller ROM loads the boot sector ([BAD] p. 5-6) or
/// the `ProDOS` loader blocks ([TRM] "Memory Use").
const BOOT_LOAD_ADDRESS: u16 = 0x0800;

/// Prefix of the metadata keys of every layout.
const KEY_PREFIX: &str = "apple2";

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// The order of the 256-byte sectors in an image file ([CP2]
/// `Unadorned-notes.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// DOS order (`.do`, most `.dsk`): DOS logical sector `s` of track `t`
    /// at `(16 * t + s) * 256`.
    Dos,
    /// `ProDOS` order (`.po`): 512-byte block `b` at `512 * b`.
    ProDos,
}

impl Order {
    fn name(self) -> &'static str {
        match self {
            Self::Dos => "DOS order",
            Self::ProDos => "ProDOS order",
        }
    }
}

/// An Apple II disk image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A raw DOS 3.3 image of 35 or 40 tracks of 16 sectors whose VTOC and
    /// catalog validate in this order.
    Dos33(Order),
    /// A raw DOS 3.3 image whose catalog validates equally well in both
    /// orders; nothing is extracted.
    Dos33Ambiguous,
    /// A raw `ProDOS` volume image: 140 or 160 KiB in either order, any other
    /// size in `ProDOS` order.
    ProDos(Order),
    /// A raw 140 or 160 KiB `ProDOS` image whose volume directory validates
    /// in both orders; nothing is extracted.
    ProDosAmbiguous,
    /// A 2IMG image: the `2IMG` header, then the disk data in DOS order,
    /// `ProDOS` order or as nibbles.
    TwoImg,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Dos33(_) | Self::Dos33Ambiguous => FileFormat::Apple2Dos,
            Self::ProDos(_) | Self::ProDosAmbiguous => FileFormat::ProDos,
            Self::TwoImg => FileFormat::TwoImg,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dos33(Order::Dos) => "DOS 3.3, DOS order",
            Self::Dos33(Order::ProDos) => "DOS 3.3, ProDOS order",
            Self::Dos33Ambiguous => "DOS 3.3, ambiguous sector order",
            Self::ProDos(Order::ProDos) => "ProDOS, ProDOS order",
            Self::ProDos(Order::Dos) => "ProDOS, DOS order",
            Self::ProDosAmbiguous => "ProDOS, ambiguous sector order",
            Self::TwoImg => "2IMG",
        }
    }

    /// Raw images have no magic and are recognized from their size and a
    /// complete VTOC and catalog or volume directory; 2IMG carries a magic
    /// and a header of fixed values.
    pub fn is_weak(self) -> bool {
        !matches!(self, Self::TwoImg)
    }
}

/// Strong recognition: the `2IMG` magic with a header length of 52 or 64,
/// version 1 and a known image format. The offsets and lengths are checked
/// by [`parse_container`], so a damaged 2IMG file is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    twoimg::detect(data).then_some(Layout::TwoImg)
}

/// Weak recognition of raw images: a DOS 3.3 image of exactly 35 or 40
/// tracks whose VTOC and whole catalog chain validate, or a `ProDOS` image
/// exactly as large as its volume whose volume directory header, chain and
/// entries validate. A 16-sector image is tried in both sector orders;
/// DOS 3.3 is tried first.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    dos33_layout(data).or_else(|| prodos_layout(data))
}

/// Parse an Apple II disk image into the shared container model: the files
/// in catalog or directory order (binary and system files as 6502 code,
/// the others opaque), then the boot code.
///
/// # Errors
///
/// [`ClassifierError::Apple2ParseError`] for an image whose size, VTOC,
/// catalog chain or volume directory does not validate in the layout's
/// order, an ambiguous layout that is not ambiguous, and for 2IMG a header,
/// data range or data size that does not validate. Damage below the
/// catalog or volume directory (track/sector lists, index blocks,
/// subdirectories) is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Dos33(order) => parse_raw_dos33(data, order),
        Layout::ProDos(order) => parse_raw_prodos(data, order),
        Layout::Dos33Ambiguous => parse_ambiguous_dos33(data),
        Layout::ProDosAmbiguous => parse_ambiguous_prodos(data),
        Layout::TwoImg => twoimg::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::Apple2ParseError {
        message: message.into(),
    }
}

/// A result below the catalog or volume directory: the error is a defect
/// that skips the file and becomes a note.
type Walk<T> = std::result::Result<T, String>;

/// The layout of a raw DOS 3.3 image, from the order its catalog supports
/// ([`Dos33Evidence::order`]) with no order to prefer on a tie.
fn dos33_layout(data: &[u8]) -> Option<Layout> {
    match Dos33Evidence::gather(data, 0, data.len())?.order(None) {
        OrderChoice::Found(order) => Some(Layout::Dos33(order)),
        OrderChoice::Ambiguous => Some(Layout::Dos33Ambiguous),
        OrderChoice::Invalid => None,
    }
}

/// The sector order a DOS 3.3 catalog supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrderChoice {
    Found(Order),
    /// The catalog validates equally in both orders.
    Ambiguous,
    /// The catalog does not validate in the order its chain supports.
    Invalid,
}

/// How far a raw DOS 3.3 image's catalog reaches in one order.
#[derive(Debug, Clone, Copy)]
struct Reach {
    /// Catalog sectors the chain links reach before it ends, leaves the
    /// disk or repeats.
    chain: usize,
    /// The VTOC and catalog validate.
    valid: bool,
}

/// The catalog reach of the disk data of a DOS 3.3 image in each order.
struct Dos33Evidence {
    dos: Reach,
    prodos: Reach,
}

impl Dos33Evidence {
    /// The reach of the `size` bytes at `start` of `input`; `None` when
    /// that is not a DOS 3.3 image size or not in the input.
    fn gather(input: &[u8], start: usize, size: usize) -> Option<Self> {
        if !dos33::is_image_size(size) {
            return None;
        }
        let reach = |order| {
            Disk::new(input, start, size, order).map(|disk| Reach {
                chain: dos33::chain_length(disk),
                valid: dos33::open(disk).is_ok(),
            })
        };
        Some(Self {
            dos: reach(Order::Dos)?,
            prodos: reach(Order::ProDos)?,
        })
    }

    /// The order the catalog supports: the one in which its chain is
    /// longer, when the catalog validates in it. In the wrong order the
    /// chain of a standard catalog (track 17, sectors 15 down to 1) ends
    /// after two sectors ([CP2] `DOS.TestImage` scores 29 against 3),
    /// because sector 14 is read from where sector 1, the end of the chain,
    /// is stored; so a catalog damaged in its own order is not taken in the
    /// other. With chains of equal length, the order in which the catalog
    /// validates; when it validates in both, `tie` (a 2IMG header's order,
    /// which [CP2] `AnalyzeFileSystem` tries first) or ambiguity.
    fn order(&self, tie: Option<Order>) -> OrderChoice {
        let (dos, prodos) = (self.dos, self.prodos);
        let found = |order| OrderChoice::Found(order);
        match dos.chain.cmp(&prodos.chain) {
            std::cmp::Ordering::Greater if dos.valid => found(Order::Dos),
            std::cmp::Ordering::Less if prodos.valid => found(Order::ProDos),
            std::cmp::Ordering::Equal => match (dos.valid, prodos.valid, tie) {
                (true, true, Some(order)) => found(order),
                (true, true, None) => OrderChoice::Ambiguous,
                (true, false, _) => found(Order::Dos),
                (false, true, _) => found(Order::ProDos),
                (false, false, _) => OrderChoice::Invalid,
            },
            _ => OrderChoice::Invalid,
        }
    }

    /// How the order was found, for the notes.
    fn note(&self) -> String {
        format!("Sector order from the catalog chain: {}", self.counts())
    }

    /// The chain lengths and validity in both orders.
    fn counts(&self) -> String {
        let validity = match (self.dos.valid, self.prodos.valid) {
            (true, true) => "it validates in both",
            (true, false) => "it validates only in DOS order",
            (false, true) => "it validates only in ProDOS order",
            (false, false) => "it validates in neither",
        };
        format!(
            "{} in DOS order, {} in ProDOS order; {validity}",
            counted(self.dos.chain, "sector", "sectors"),
            counted(self.prodos.chain, "sector", "sectors")
        )
    }
}

/// The orders in which a raw `ProDOS` image's volume directory validates:
/// `ProDOS` order for every size, and DOS order for 16-sector floppy sizes.
fn prodos_layout(data: &[u8]) -> Option<Layout> {
    let validates = |order| {
        Disk::new(data, 0, data.len(), order)
            .is_some_and(|disk| prodos::open(disk, prodos::Fit::Exact).is_ok())
    };
    let in_dos_order = dos33::is_image_size(data.len()) && validates(Order::Dos);
    match (validates(Order::ProDos), in_dos_order) {
        (true, true) => Some(Layout::ProDosAmbiguous),
        (true, false) => Some(Layout::ProDos(Order::ProDos)),
        (false, true) => Some(Layout::ProDos(Order::Dos)),
        (false, false) => None,
    }
}

/// A raw image's disk data in `order`.
fn raw_disk(data: &[u8], order: Order) -> Result<Disk<'_>> {
    Disk::new(data, 0, data.len(), order).ok_or_else(|| {
        error(format!(
            "Unsupported image size {} B for {}",
            data.len(),
            order.name()
        ))
    })
}

fn parse_raw_dos33(data: &[u8], order: Order) -> Result<Container<'_>> {
    let disk = raw_disk(data, order)?;
    let catalog = dos33::open(disk)?;
    let layout = Layout::Dos33(order);
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    let order_note = Dos33Evidence::gather(data, 0, data.len()).map(|evidence| evidence.note());
    dos33::push_volume(disk, &catalog, order_note, &mut c);
    Ok(c)
}

fn parse_raw_prodos(data: &[u8], order: Order) -> Result<Container<'_>> {
    let disk = raw_disk(data, order)?;
    let volume = prodos::open(disk, prodos::Fit::Exact)?;
    let layout = Layout::ProDos(order);
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    prodos::push_volume(disk, &volume, &mut c);
    Ok(c)
}

/// An image whose filesystem validates in both orders: reported with notes
/// and no children, so the ISA stays unknown.
fn ambiguous_container(data: &[u8], layout: Layout, note: String) -> Container<'_> {
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(note);
    c.notes
        .push("The sector order is ambiguous, so no files or boot code are extracted".to_string());
    c
}

fn parse_ambiguous_dos33(data: &[u8]) -> Result<Container<'_>> {
    let evidence = Dos33Evidence::gather(data, 0, data.len())
        .filter(|evidence| evidence.order(None) == OrderChoice::Ambiguous)
        .ok_or_else(|| {
            error(
                "Invalid ambiguous DOS 3.3 image: the catalog does not validate equally in both \
                 sector orders",
            )
        })?;
    Ok(ambiguous_container(
        data,
        Layout::Dos33Ambiguous,
        evidence.note(),
    ))
}

fn parse_ambiguous_prodos(data: &[u8]) -> Result<Container<'_>> {
    if prodos_layout(data) != Some(Layout::ProDosAmbiguous) {
        return Err(error(
            "Invalid ambiguous ProDOS image: the volume directory does not validate in both \
             sector orders",
        ));
    }
    Ok(ambiguous_container(
        data,
        Layout::ProDosAmbiguous,
        "The volume directory validates in DOS order and in ProDOS order".to_string(),
    ))
}

/// The disk data of an image: `size` bytes at `start` in the input, in
/// `order`. DOS-order data holds whole tracks; `ProDOS`-order data whole
/// blocks.
#[derive(Debug, Clone, Copy)]
struct Disk<'a> {
    input: &'a [u8],
    start: usize,
    size: usize,
    order: Order,
}

impl<'a> Disk<'a> {
    /// `None` when the range is not in the input or not whole tracks (DOS
    /// order) or blocks (`ProDOS` order).
    fn new(input: &'a [u8], start: usize, size: usize, order: Order) -> Option<Self> {
        let unit = match order {
            Order::Dos => TRACK_SIZE,
            Order::ProDos => BLOCK_SIZE,
        };
        let end = start.checked_add(size)?;
        (end <= input.len() && size % unit == 0).then_some(Self {
            input,
            start,
            size,
            order,
        })
    }

    fn blocks(&self) -> usize {
        self.size / BLOCK_SIZE
    }

    /// The input offset of DOS logical sector `sector` of `track`. Sectors
    /// map to positions within a track only on 16-sector disks, so the data
    /// must hold whole tracks.
    fn sector_offset(&self, track: usize, sector: usize) -> Option<usize> {
        if sector >= SECTORS_PER_TRACK || self.size % TRACK_SIZE != 0 {
            return None;
        }
        let position = match self.order {
            Order::Dos => sector,
            Order::ProDos => DOS_SECTOR_POSITION[sector],
        };
        let within = track
            .checked_mul(TRACK_SIZE)?
            .checked_add(position * SECTOR_SIZE)?;
        (within < self.size).then_some(self.start + within)
    }

    /// DOS logical sector `sector` of `track`.
    fn sector(&self, track: usize, sector: usize) -> Option<&'a [u8; SECTOR_SIZE]> {
        let offset = self.sector_offset(track, sector)?;
        self.input
            .get(offset..offset + SECTOR_SIZE)?
            .try_into()
            .ok()
    }

    /// The input offsets of the two 256-byte halves of `block`. In DOS
    /// order, block `8 * t + k` is DOS sectors `DOS_SECTOR_POSITION[2k]` and
    /// `DOS_SECTOR_POSITION[2k + 1]` of track `t` ([TRM] Figure B-15).
    fn block_offsets(&self, block: usize) -> Option<[usize; 2]> {
        match self.order {
            Order::ProDos => {
                let first = block.checked_mul(BLOCK_SIZE)?;
                (first < self.size)
                    .then_some([self.start + first, self.start + first + SECTOR_SIZE])
            }
            Order::Dos => {
                let track = block / BLOCKS_PER_TRACK;
                let half = (block % BLOCKS_PER_TRACK) * 2;
                Some([
                    self.sector_offset(track, DOS_SECTOR_POSITION[half])?,
                    self.sector_offset(track, DOS_SECTOR_POSITION[half + 1])?,
                ])
            }
        }
    }

    /// The 512 bytes of `block`, copied when its halves are not adjacent.
    fn block(&self, block: usize) -> Option<Cow<'a, [u8; BLOCK_SIZE]>> {
        let [first, second] = self.block_offsets(block)?;
        if second == first + SECTOR_SIZE {
            let bytes: &[u8; BLOCK_SIZE] =
                self.input.get(first..first + BLOCK_SIZE)?.try_into().ok()?;
            return Some(Cow::Borrowed(bytes));
        }
        let mut bytes = [0u8; BLOCK_SIZE];
        bytes[..SECTOR_SIZE].copy_from_slice(self.input.get(first..first + SECTOR_SIZE)?);
        bytes[SECTOR_SIZE..].copy_from_slice(self.input.get(second..second + SECTOR_SIZE)?);
        Some(Cow::Owned(bytes))
    }
}

/// The little-endian 16-bit field at `at` of a fixed-size record.
fn le_u16<const N: usize>(record: &[u8; N], at: usize) -> u16 {
    u16::from_le_bytes([record[at], record[at + 1]])
}

/// Stored bytes of a file in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    offset: usize,
    len: usize,
}

/// A piece of a file: stored bytes, or a hole that reads as zeros (a
/// sparse sector or block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    Stored(Run),
    Hole(usize),
}

impl Piece {
    fn len(self) -> usize {
        match self {
            Self::Stored(run) => run.len,
            Self::Hole(len) => len,
        }
    }
}

/// A file's bytes as stored runs and holes in file order. Adjacent runs
/// merge, so a contiguous file is one run.
#[derive(Debug, Default)]
struct Assembly {
    pieces: Vec<Piece>,
    len: usize,
}

impl Assembly {
    fn push_stored(&mut self, offset: usize, len: usize) {
        self.len += len;
        if let Some(Piece::Stored(last)) = self.pieces.last_mut() {
            if last.offset + last.len == offset {
                last.len += len;
                return;
            }
        }
        self.pieces.push(Piece::Stored(Run { offset, len }));
    }

    fn push_hole(&mut self, len: usize) {
        self.len += len;
        if let Some(Piece::Hole(last)) = self.pieces.last_mut() {
            *last += len;
            return;
        }
        self.pieces.push(Piece::Hole(len));
    }

    /// The two halves of a block at `offsets`.
    fn push_block(&mut self, offsets: [usize; 2]) {
        for offset in offsets {
            self.push_stored(offset, SECTOR_SIZE);
        }
    }

    /// The `len` bytes from `start`, as far as the file reaches.
    fn range(&self, start: usize, len: usize) -> Self {
        let end = start.saturating_add(len).min(self.len);
        let mut range = Self::default();
        let mut position = 0usize;
        for &piece in &self.pieces {
            let piece_end = position + piece.len();
            let from = start.max(position);
            let to = end.min(piece_end);
            if from < to {
                match piece {
                    Piece::Stored(run) => {
                        range.push_stored(run.offset + (from - position), to - from);
                    }
                    Piece::Hole(_) => range.push_hole(to - from),
                }
            }
            position = piece_end;
        }
        range
    }

    /// The first stored run, if any.
    fn first_run(&self) -> Option<Run> {
        self.pieces.iter().find_map(|piece| match piece {
            Piece::Stored(run) => Some(*run),
            Piece::Hole(_) => None,
        })
    }

    /// The bytes as a child labeled `label`: empty at `fallback_offset`
    /// when there are none, borrowed when they are one stored run,
    /// otherwise reassembled through `transform` with the first stored run
    /// as the stored range (at `fallback_offset` when only holes remain).
    fn to_child<'a>(
        &self,
        input: &'a [u8],
        label: String,
        transform: &'static str,
        fallback_offset: usize,
    ) -> Child<'a> {
        match self.pieces.as_slice() {
            [] => return Child::stored(label, fallback_offset, &[]),
            [Piece::Stored(run)] => {
                return Child::stored(label, run.offset, &input[run.offset..run.offset + run.len]);
            }
            _ => {}
        }
        let mut bytes = Vec::with_capacity(self.len);
        for &piece in &self.pieces {
            match piece {
                Piece::Stored(run) => {
                    bytes.extend_from_slice(&input[run.offset..run.offset + run.len]);
                }
                Piece::Hole(len) => bytes.resize(bytes.len() + len, 0),
            }
        }
        let first = self.first_run().unwrap_or(Run {
            offset: fallback_offset,
            len: 0,
        });
        Child::decoded(label, first.offset, first.len, Cow::Owned(bytes), transform)
    }
}

/// What a file holds, from its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    /// A memory image of 6502 code loaded at `load_address`; `file_type`
    /// names the type for the metadata.
    Code {
        load_address: u16,
        file_type: &'static str,
    },
    /// Data, BASIC, text or another type that is never analyzed.
    Opaque,
}

/// A file ready to be listed.
#[derive(Debug)]
struct File {
    label: String,
    contents: Assembly,
    kind: FileKind,
    /// How a fragmented file is reassembled.
    transform: &'static str,
    /// Input offset reported for a file with no stored bytes.
    fallback_offset: usize,
}

/// What the file walk listed and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    files: usize,
    code_files: usize,
    opaque_files: usize,
    extracted: usize,
    unlisted: usize,
    over_budget: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

impl Census {
    /// Record a problem below the catalog or volume directory.
    fn problem(&mut self, text: String) {
        if self.problems.len() < MAX_PROBLEM_NOTES {
            self.problems.push(text);
        } else {
            self.unlisted_problems += 1;
        }
    }

    /// Whether another file of `size` bytes may be listed: there is room
    /// for another component and the extraction limits allow it. The size
    /// is charged before the file is read, so a volume of cross-linked or
    /// sparse files is bounded by the total limit.
    fn admit(&mut self, c: &Container<'_>, size: usize) -> bool {
        self.files += 1;
        if c.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
            return false;
        }
        if size > MAX_PAYLOAD || self.extracted + size > MAX_EXTRACTED {
            self.over_budget += 1;
            return false;
        }
        self.extracted += size;
        true
    }

    /// List an admitted `file` as a child: code files with the 6502 target
    /// and their load address in the metadata, other files opaque.
    fn push_file<'a>(&mut self, c: &mut Container<'a>, input: &'a [u8], file: File) {
        let index = c.children.len();
        let size = file.contents.len;
        let mut child =
            file.contents
                .to_child(input, file.label, file.transform, file.fallback_offset);
        match file.kind {
            FileKind::Code {
                load_address,
                file_type,
            } => {
                c.push_metadata(
                    format!("{KEY_PREFIX}_load_address_{index}"),
                    format!("{}: load address", child.label),
                    format!("0x{load_address:04X} ({file_type} file, {size} B)"),
                );
                child = child.with_target(MOS_6502).as_code();
                self.code_files += 1;
            }
            FileKind::Opaque => {
                child.opaque = true;
                self.opaque_files += 1;
            }
        }
        c.children.push(child);
    }

    /// Notes: what was listed, then what was left out and why.
    fn report(self, c: &mut Container<'_>, code_types: &str) {
        c.notes.push(format!(
            "{} listed: {} as 6502 code ({code_types}), {} opaque",
            counted(self.code_files + self.opaque_files, "file", "files"),
            self.code_files,
            self.opaque_files
        ));
        if self.unlisted > 0 {
            c.notes.push(format!(
                "{} not listed: at most {MAX_COMPONENTS} components are listed",
                counted(self.unlisted, "file was", "files were")
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "{} not extracted: the {} MiB total extraction limit was reached",
                counted(self.over_budget, "file was", "files were"),
                MAX_EXTRACTED >> 20
            ));
        }
        c.notes.extend(self.problems);
        if self.unlisted_problems > 0 {
            c.notes.push(format!(
                "{} not listed",
                counted(
                    self.unlisted_problems,
                    "further problem was",
                    "further problems were"
                )
            ));
        }
        c.push_metadata(
            format!("{KEY_PREFIX}_file_count"),
            "Files",
            self.files as u64,
        );
    }
}

/// Push the boot code in `contents`, at `place` on the disk, as a 6502
/// child after the files, unless it is one repeated byte (an unformatted
/// or zeroed area); a note says which.
fn push_boot<'a>(
    c: &mut Container<'a>,
    input: &'a [u8],
    contents: &Assembly,
    place: &str,
    transform: &'static str,
) {
    let Some(first) = contents.first_run() else {
        return;
    };
    let child = contents.to_child(
        input,
        format!("Boot code ({place})"),
        transform,
        first.offset,
    );
    if let Some(&fill) = child.data.first() {
        if child.data.iter().all(|&b| b == fill) {
            c.notes
                .push(format!("No boot code: {place} is filled with 0x{fill:02X}"));
            return;
        }
    }
    if c.children.len() >= MAX_COMPONENTS {
        return;
    }
    c.notes.push(format!(
        "Boot code: {place} at 0x{:X} ({} B), which the disk controller ROM loads at \
         0x{BOOT_LOAD_ADDRESS:04X}; classified as 6502 code",
        first.offset,
        child.data.len()
    ));
    c.children.push(child.with_target(MOS_6502).as_code());
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// `value` divided by `divisor`, rounded up. `divisor` is not zero.
fn div_round_up(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sector_position_table_is_its_own_inverse_and_matches_figure_b15() {
        for (sector, &position) in DOS_SECTOR_POSITION.iter().enumerate() {
            assert_eq!(DOS_SECTOR_POSITION[position], sector);
        }
        // Figure B-15: sector offset and half of block for sectors 0-F.
        let offsets = [0, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 7];
        let halves = [1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 2];
        for sector in 0..SECTORS_PER_TRACK {
            assert_eq!(
                DOS_SECTOR_POSITION[sector],
                2 * offsets[sector] + halves[sector] - 1
            );
        }
    }

    #[test]
    fn blocks_and_sectors_map_between_the_two_orders() {
        let input = vec![0u8; 35 * TRACK_SIZE];
        let dos = Disk::new(&input, 0, input.len(), Order::Dos).unwrap();
        let prodos = Disk::new(&input, 0, input.len(), Order::ProDos).unwrap();
        // Block 0 is DOS sectors 0 and 14 of track 0; block 9 is sectors
        // 13 and 12 of track 1.
        assert_eq!(dos.block_offsets(0), Some([0, 14 * SECTOR_SIZE]));
        assert_eq!(
            dos.block_offsets(9),
            Some([TRACK_SIZE + 13 * SECTOR_SIZE, TRACK_SIZE + 12 * SECTOR_SIZE])
        );
        assert_eq!(prodos.block_offsets(9), Some([9 * 512, 9 * 512 + 256]));
        // DOS sector 1 of track 17 is the second half of block 17 * 8 + 7.
        assert_eq!(
            prodos.sector_offset(17, 1),
            Some(17 * TRACK_SIZE + 14 * SECTOR_SIZE)
        );
        assert_eq!(prodos.sector_offset(35, 0), None);
        assert_eq!(dos.block_offsets(280), None);
        assert_eq!(
            Disk::new(&input, 0, 1000, Order::ProDos).map(|d| d.size),
            None
        );
    }

    #[test]
    fn assemblies_merge_adjacent_runs_and_cut_ranges() {
        let mut assembly = Assembly::default();
        assembly.push_stored(0x100, 0x100);
        assembly.push_stored(0x200, 0x100);
        assembly.push_hole(0x100);
        assembly.push_stored(0x800, 0x100);
        assert_eq!(assembly.len, 0x400);
        assert_eq!(
            assembly.pieces,
            [
                Piece::Stored(Run {
                    offset: 0x100,
                    len: 0x200
                }),
                Piece::Hole(0x100),
                Piece::Stored(Run {
                    offset: 0x800,
                    len: 0x100
                }),
            ]
        );
        let range = assembly.range(4, 0x1fe);
        assert_eq!(
            range.pieces,
            [
                Piece::Stored(Run {
                    offset: 0x104,
                    len: 0x1fc
                }),
                Piece::Hole(2)
            ]
        );
        assert_eq!(assembly.range(0x380, 0x1000).len, 0x80);
        assert_eq!(assembly.range(0x1000, 4).len, 0);
    }

    #[test]
    fn reassembled_children_fill_holes_with_zeros() {
        let input: Vec<u8> = (0..=255u8).cycle().take(0x1000).collect();
        let mut assembly = Assembly::default();
        assembly.push_stored(0x10, 2);
        assembly.push_hole(2);
        assembly.push_stored(0x20, 2);
        let child = assembly.to_child(&input, "f".into(), "test", 0);
        assert_eq!(child.data.as_ref(), [0x10, 0x11, 0, 0, 0x20, 0x21]);
        assert_eq!((child.offset, child.stored_size), (0x10, 2));
        assert_eq!(child.transform, Some("test"));
        let mut contiguous = Assembly::default();
        contiguous.push_stored(0x30, 4);
        let child = contiguous.to_child(&input, "g".into(), "test", 0);
        assert!(matches!(child.data, Cow::Borrowed(_)));
        assert_eq!(child.transform, None);
    }

    #[test]
    fn the_census_stops_at_the_extraction_and_component_limits() {
        let mut c = Container::new(FileFormat::ProDos, "test", KEY_PREFIX);
        let mut census = Census::default();
        for _ in 0..MAX_EXTRACTED / MAX_PAYLOAD {
            assert!(census.admit(&c, MAX_PAYLOAD));
        }
        assert!(!census.admit(&c, 1));
        assert!(!census.admit(&c, MAX_PAYLOAD + 1));
        let mut fresh = Census::default();
        assert!(!fresh.admit(&c, MAX_PAYLOAD + 1));
        for _ in 0..MAX_COMPONENTS {
            c.children.push(Child::stored("member", 0, &[]));
        }
        assert!(!fresh.admit(&c, 0));
        census.report(&mut c, "test");
        assert!(c.notes.contains(
            &"2 files were not extracted: the 256 MiB total extraction limit was reached"
                .to_string()
        ));
        fresh.report(&mut c, "test");
        assert!(c
            .notes
            .contains(&"1 file was not listed: at most 4096 components are listed".to_string()));
    }
}
