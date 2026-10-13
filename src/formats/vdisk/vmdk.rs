//! `VMware` VMDK hosted sparse extents: monolithic sparse and
//! stream-optimized (`VMware` Technical Note "Virtual Disk Format 5.0",
//! EN-000777-00, "Hosted Sparse Extent Header", "Hosted Sparse Extent
//! Metadata" and "Stream-Optimized Compressed"; QEMU `v11.1.1`
//! `block/vmdk.c` for version 3, zlib-wrapped grains and the footer
//! position).
//!
//! The 512-byte header is little-endian and counts in 512-byte sectors.
//! A grain directory of 32-bit entries points to grain tables of
//! `numGTEsPerGT` 32-bit entries, each the sector of one grain (0 not
//! allocated, 1 a zeroed grain when the header enables them). In a
//! stream-optimized extent each grain is a compressed stream behind a
//! marker that names its guest LBA; the header's grain directory offset
//! may be `GD_AT_END`, in which case the footer near the end of the file
//! holds the real one. The embedded text descriptor names the disk type
//! and, for a delta link, the parent.
//!
//! `VMware`'s `ESXi` `COWD` sparse extents and `SESparse` extents are other
//! layouts and are not recognized; descriptor files of flat disks are
//! text and are not recognized either.

use super::*;

/// `SPARSE_MAGICNUMBER` 0x564D444B ('V' 'M' 'D' 'K'), stored
/// little-endian.
const SPARSE_MAGIC: [u8; 4] = *b"KDMV";

/// Versions 1 and 2 are documented; QEMU reads version 3 (changed block
/// tracking, `VMware` KB 2064959) and writes it for stream-optimized disks.
const MAX_VERSION: u32 = 3;

const HEADER_SIZE: usize = 512;

/// Header flags.
const FLAG_NEWLINE_CHECK: u32 = 1 << 0;
const FLAG_ZEROED_GRAINS: u32 = 1 << 2;
const FLAG_COMPRESSED: u32 = 1 << 16;
const FLAG_MARKERS: u32 = 1 << 17;

/// The four bytes at 73 that detect FTP text-mode corruption:
/// `singleEndLineChar`, `nonEndLineChar`, `doubleEndLineChar1` and
/// `doubleEndLineChar2`.
const NEWLINE_CHECK_OFFSET: usize = 73;
const NEWLINE_CHECK: [u8; 4] = *b"\n \r\n";

/// `compressAlgorithm` values.
const COMPRESSION_NONE: u16 = 0;
const COMPRESSION_DEFLATE: u16 = 1;

/// `gdOffset` of a stream-optimized header whose footer holds the real
/// value.
const GD_AT_END: u64 = u64::MAX;

/// Grain table entries with a meaning other than a grain sector.
const GTE_UNALLOCATED: u32 = 0;
const GTE_ZEROED: u32 = 1;

/// Grain directory and grain table entries are 32-bit.
const ENTRY_SIZE: u64 = 4;

/// `numGTEsPerGT` is 512 for virtual disks; QEMU accepts fewer.
const MAX_GTES_PER_GT: u32 = 512;

/// Grain sizes: a power of two of at least 8 sectors (4 KiB), and at most
/// 128 Ki sectors (64 MiB, the extraction limit) as a resource bound of
/// this parser.
const MIN_GRAIN_SECTORS: u64 = 8;
const MAX_GRAIN_SECTORS: u64 = 1 << 17;

/// Markers: a value (8), a size (4) and, when the size is 0, a type (4).
/// A grain marker's value is the grain's LBA and its size the compressed
/// length; its data follows the size.
const GRAIN_MARKER_HEADER: u64 = 12;
const MARKER_EOS: u32 = 0;
const MARKER_FOOTER: u32 = 3;

/// The footer marker, footer and end-of-stream marker fill the last three
/// sectors of a stream-optimized extent (QEMU reads them at the file size
/// minus 1536).
const FOOTER_AREA: usize = 3 * HEADER_SIZE;

/// Most descriptor bytes that are read for the disk type and parent.
const MAX_DESCRIPTOR: u64 = 1 << 20;

/// The `parentCID` of a base disk.
const NO_PARENT_CID: &str = "ffffffff";

/// QEMU writes grains with zlib's `compress2`; the technote names RFC 1951.
const GRAIN_CODECS: &[Codec] = &[Codec::Zlib, Codec::Deflate];

const TRANSFORM: &str = "VMDK grains";

/// Is this a hosted sparse extent header: the magic and version 1 to 3?
pub(super) fn is_present(data: &[u8]) -> bool {
    data.starts_with(&SPARSE_MAGIC) && matches!(le_u32(data, 4), Ok(1..=MAX_VERSION))
}

/// The sparse extent header fields this parser uses.
struct Header {
    version: u32,
    flags: u32,
    /// Extent size in sectors.
    capacity: u64,
    /// Grain size in sectors.
    grain_size: u64,
    /// Embedded descriptor offset and size, in sectors.
    descriptor_offset: u64,
    descriptor_size: u64,
    gtes_per_gt: u32,
    /// Grain directory offset, in sectors.
    gd_offset: u64,
    compress_algorithm: u16,
    newline_check: [u8; 4],
}

impl Header {
    fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    fn grain_bytes(&self) -> u64 {
        self.grain_size * SECTOR_SIZE
    }
}

/// `SparseExtentHeader`: magic, version, flags, capacity (8), grain size
/// (8), descriptor offset (8) and size (8), GTEs per GT (4), redundant GD
/// offset (8), GD offset (8), overhead (8), unclean shutdown (1), the
/// newline check (4) and the compression algorithm (2).
fn header(bytes: &[u8]) -> Result<Header> {
    if bytes[..4] != SPARSE_MAGIC {
        return Err(error("Missing VMDK sparse extent magic"));
    }
    Ok(Header {
        version: le_u32(bytes, 4)?,
        flags: le_u32(bytes, 8)?,
        capacity: le_u64(bytes, 12)?,
        grain_size: le_u64(bytes, 20)?,
        descriptor_offset: le_u64(bytes, 28)?,
        descriptor_size: le_u64(bytes, 36)?,
        gtes_per_gt: le_u32(bytes, 44)?,
        gd_offset: le_u64(bytes, 56)?,
        compress_algorithm: le_u16(bytes, 77)?,
        newline_check: array(bytes, NEWLINE_CHECK_OFFSET)?,
    })
}

/// The footer of a stream-optimized extent: a footer marker (size 0, type
/// 3), the header copy with the real grain directory offset, and the
/// end-of-stream marker (value, size and type 0).
fn footer(data: &[u8]) -> Result<Header> {
    let start = data
        .len()
        .checked_sub(FOOTER_AREA)
        .ok_or_else(|| error("Truncated VMDK stream-optimized extent: no room for the footer"))?;
    let area = &data[start..];
    let marker = &area[..HEADER_SIZE];
    let eos = &area[2 * HEADER_SIZE..];
    let marker_ok = le_u32(marker, 8)? == 0 && le_u32(marker, 12)? == MARKER_FOOTER;
    let eos_ok = le_u64(eos, 0)? == 0 && le_u32(eos, 8)? == 0 && le_u32(eos, 12)? == MARKER_EOS;
    if !marker_ok || !eos_ok {
        return Err(error(format!(
            "Invalid VMDK stream-optimized footer at 0x{start:X}: missing footer or \
             end-of-stream marker"
        )));
    }
    let h = header(&area[HEADER_SIZE..2 * HEADER_SIZE])?;
    if h.gd_offset == GD_AT_END {
        return Err(error(
            "Invalid VMDK stream-optimized footer: its grain directory offset is GD_AT_END",
        ));
    }
    Ok(h)
}

/// Checks on the header fields that the grain walk depends on.
fn check(h: &Header) -> Result<()> {
    if !(1..=MAX_VERSION).contains(&h.version) {
        return Err(error(format!("Unsupported VMDK version {}", h.version)));
    }
    if h.flags & FLAG_NEWLINE_CHECK != 0 && h.newline_check != NEWLINE_CHECK {
        return Err(error(
            "Invalid VMDK newline check bytes: the extent was altered by a text-mode transfer",
        ));
    }
    if !h.grain_size.is_power_of_two()
        || !(MIN_GRAIN_SECTORS..=MAX_GRAIN_SECTORS).contains(&h.grain_size)
    {
        return Err(error(format!(
            "Unsupported VMDK grain size {} sectors",
            h.grain_size
        )));
    }
    if !(1..=MAX_GTES_PER_GT).contains(&h.gtes_per_gt) {
        return Err(error(format!(
            "Invalid VMDK numGTEsPerGT {}",
            h.gtes_per_gt
        )));
    }
    if h.capacity.checked_mul(SECTOR_SIZE).is_none() {
        return Err(error(format!(
            "Invalid VMDK capacity {} sectors",
            h.capacity
        )));
    }
    if h.is_compressed() && h.compress_algorithm != COMPRESSION_DEFLATE {
        return Err(error(format!(
            "Unsupported VMDK compression algorithm {}",
            h.compress_algorithm
        )));
    }
    Ok(())
}

/// What the embedded descriptor says.
#[derive(Debug, Default)]
struct Descriptor {
    create_type: Option<String>,
    parent_cid: Option<String>,
    parent_hint: Option<String>,
    extents: usize,
}

/// Read `key=value` lines of the embedded descriptor (keys are not
/// case-sensitive, values may be quoted) and count the extent lines.
fn descriptor(data: &[u8], h: &Header) -> Result<Descriptor> {
    let mut found = Descriptor::default();
    if h.descriptor_offset == 0 {
        return Ok(found);
    }
    let size = h
        .descriptor_size
        .saturating_mul(SECTOR_SIZE)
        .min(MAX_DESCRIPTOR);
    let text = range(
        data,
        h.descriptor_offset.saturating_mul(SECTOR_SIZE),
        size,
        "VMDK embedded descriptor",
    )?;
    let end = memchr::memchr(0, text).unwrap_or(text.len());
    for line in String::from_utf8_lossy(&text[..end]).lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let is_extent = ["RW ", "RDONLY ", "NOACCESS "]
            .iter()
            .any(|access| line.starts_with(access));
        if is_extent {
            found.extents += 1;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = byte_text(value.trim().trim_matches('"').as_bytes());
        match key.trim().to_ascii_lowercase().as_str() {
            "createtype" => found.create_type = Some(value),
            "parentcid" => found.parent_cid = Some(value),
            "parentfilenamehint" => found.parent_hint = Some(value),
            _ => {}
        }
    }
    Ok(found)
}

/// The parent of a delta link: its `parentCID` is not `ffffffff`.
fn parent(found: &Descriptor) -> Option<Parent> {
    let cid = found.parent_cid.as_deref()?;
    if cid.eq_ignore_ascii_case(NO_PARENT_CID) {
        return None;
    }
    let reference = match &found.parent_hint {
        Some(hint) => format!("{hint} (parent CID {cid})"),
        None => format!("with CID {cid}"),
    };
    Some(Parent {
        role: "parent link",
        reference,
    })
}

/// Parse a hosted sparse extent.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut h = header(slice(data, 0, HEADER_SIZE, "VMDK sparse extent header")?)?;
    check(&h)?;
    let found = descriptor(data, &h)?;
    let mut footer_note = None;
    if h.gd_offset == GD_AT_END {
        h = footer(data)?;
        check(&h)?;
        footer_note = Some(format!(
            "Stream-optimized footer at 0x{:X} holds the grain directory offset",
            data.len() - 2 * HEADER_SIZE
        ));
    }
    let variant = match &found.create_type {
        Some(kind) => format!("VMDK {kind}"),
        None if h.is_compressed() => "VMDK stream-optimized extent".to_string(),
        None => "VMDK sparse extent".to_string(),
    };
    let mut c = container_for(data, Layout::Vmdk, variant);
    let compression = if h.is_compressed() {
        "deflate-compressed grains"
    } else if h.compress_algorithm == COMPRESSION_NONE {
        "uncompressed grains"
    } else {
        "uncompressed grains (compressAlgorithm set without flag bit 16)"
    };
    c.notes.push(format!(
        "VMDK sparse extent version {}; {} capacity; {} grains; {} GTEs per grain table; {}{}",
        h.version,
        size_text(h.capacity * SECTOR_SIZE),
        size_text(h.grain_bytes()),
        h.gtes_per_gt,
        compression,
        if h.flags & FLAG_MARKERS != 0 {
            "; markers"
        } else {
            ""
        }
    ));
    if let Some(note) = footer_note {
        c.notes.push(note);
    }
    if let Some(kind) = &found.create_type {
        c.push_metadata("vdisk_vmdk_create_type", "Disk type", kind.as_str());
    }
    if found.extents > 1 {
        c.notes.push(format!(
            "The descriptor lists {} extents; only this extent's grains are read",
            found.extents
        ));
    }
    c.push_metadata("vdisk_vmdk_grain_size", "Grain size (B)", h.grain_bytes());
    let parent = parent(&found);
    if let Some(parent) = &parent {
        c.notes
            .push(format!("Delta link of the parent {}", parent.reference));
    }
    let mut guest = Guest::new(data, h.capacity * SECTOR_SIZE);
    map_grains(data, &h, parent.is_some(), &mut guest)?;
    guest.finish(&mut c, TRANSFORM, parent.as_ref())?;
    Ok(c)
}

/// The grain table that grain directory entry `gd_index` points to, or
/// `None` when it is not allocated.
fn grain_table<'a>(data: &'a [u8], h: &Header, gd_index: u64) -> Result<Option<&'a [u8]>> {
    let at = h
        .gd_offset
        .saturating_mul(SECTOR_SIZE)
        .saturating_add(gd_index * ENTRY_SIZE);
    let entry = range(data, at, ENTRY_SIZE, "VMDK grain directory")?;
    let sector = u64::from(u32::from_le_bytes(entry.try_into().expect("4 bytes")));
    if sector == 0 {
        return Ok(None);
    }
    range(
        data,
        sector * SECTOR_SIZE,
        u64::from(h.gtes_per_gt) * ENTRY_SIZE,
        "VMDK grain table",
    )
    .map(Some)
}

/// Map every grain in the analyzed range. Unallocated grains are the
/// parent link's when `has_parent` is true, zeros otherwise.
fn map_grains<'a>(
    data: &'a [u8],
    h: &Header,
    has_parent: bool,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let grain_bytes = h.grain_bytes();
    let gtes = u64::from(h.gtes_per_gt);
    let directory_entries = div_ceil(h.capacity, gtes * h.grain_size);
    range(
        data,
        h.gd_offset.saturating_mul(SECTOR_SIZE),
        directory_entries * ENTRY_SIZE,
        "VMDK grain directory",
    )?;
    let mut table: Option<&'a [u8]> = None;
    for grain in 0..guest.block_count(grain_bytes) {
        let gt_index = grain % gtes;
        if gt_index == 0 {
            table = grain_table(data, h, grain / gtes)?;
        }
        let entry = match table {
            Some(gt) => le_u32(
                gt,
                usize::try_from(gt_index * ENTRY_SIZE).expect("in the table"),
            )?,
            None => GTE_UNALLOCATED,
        };
        match entry {
            GTE_UNALLOCATED if has_parent => guest.parent(grain_bytes),
            GTE_UNALLOCATED => guest.zero(grain_bytes),
            GTE_ZEROED if h.flags & FLAG_ZEROED_GRAINS != 0 => guest.zero(grain_bytes),
            sector if h.is_compressed() => {
                let block = compressed_grain(data, h, grain, u64::from(sector))?;
                guest.compressed(block, grain_bytes);
            }
            sector => guest.stored(u64::from(sector) * SECTOR_SIZE, grain_bytes, "VMDK grain")?,
        }
    }
    Ok(())
}

/// The compressed grain at `sector`: behind a grain marker that must name
/// the grain's own LBA when the extent has markers, otherwise a bare
/// stream. Compressed data is at most two grains long (QEMU's read
/// buffer).
fn compressed_grain<'a>(
    data: &'a [u8],
    h: &Header,
    grain: u64,
    sector: u64,
) -> Result<CompressedBlock<'a>> {
    let offset = sector * SECTOR_SIZE;
    let max_stored = 2 * h.grain_bytes();
    let (start, length) = if h.flags & FLAG_MARKERS != 0 {
        let marker = range(data, offset, GRAIN_MARKER_HEADER, "VMDK grain marker")?;
        let lba = le_u64(marker, 0)?;
        let size = u64::from(le_u32(marker, 8)?);
        let expected = grain * h.grain_size;
        if size == 0 {
            return Err(error(format!(
                "Invalid VMDK grain marker at 0x{offset:X}: a metadata marker where grain \
                 {grain} should be"
            )));
        }
        if lba != expected {
            return Err(error(format!(
                "Invalid VMDK grain marker at 0x{offset:X}: LBA {lba}, expected {expected}"
            )));
        }
        if size > max_stored {
            return Err(error(format!(
                "Invalid VMDK grain marker at 0x{offset:X}: {size} B of compressed data"
            )));
        }
        (offset + GRAIN_MARKER_HEADER, size)
    } else {
        // A bare stream ends where its decoder stops; at most two grains
        // of the file are handed to it.
        range(data, offset, 1, "VMDK compressed grain")?;
        let available = data.len() as u64 - offset;
        (offset, max_stored.min(available))
    };
    let stored = range(data, start, length, "VMDK compressed grain")?;
    Ok(CompressedBlock {
        what: "VMDK compressed grain",
        offset: usize::try_from(start).expect("range checked the offset"),
        stored,
        codecs: GRAIN_CODECS,
        block_size: usize::try_from(h.grain_bytes()).expect("grains are at most 64 MiB"),
        skip: 0,
    })
}
