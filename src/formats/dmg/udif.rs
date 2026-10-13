//! A UDIF image as a container: the trailer, the block tables from the XML
//! property list or the binary resource fork, the checksums, and one child
//! per partition that holds a recognized format.
//!
//! Checksums (libdmg-hfsplus `dmg/dmglib.c` `buildDmg` and
//! `calculateMasterChecksum`; 7-Zip `DmgHandler.cpp` `CHandler::Open2` and
//! `CHandler::Extract`): the data fork CRC-32 covers the stored data fork;
//! a block table's CRC-32 covers its partition's decoded bytes, ignore
//! chunks left out; the master CRC-32 covers the block tables' checksum
//! values, concatenated in table order. All three use the IEEE CRC-32.

use super::*;
use crate::formats::checksum;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{self, Child, Container, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use blkx::{Kind, Table};
use koly::Trailer;
use std::borrow::Cow;
use std::fmt::Write;

/// Partition types that are maps, boot records, drivers or free space
/// rather than volumes (7-Zip `k_Names` entries with `IsFs = false`). They
/// are decoded after the volumes and only for their checksums: they never
/// become children, so a boot record never decides the image's ISA.
const MAP_TYPES: &[&str] = &[
    "Apple_Free",
    "DDM",
    "Apple_partition_map",
    "GPT",
    "MBR",
    "Driver",
    "Patches",
    // The EFI system partition type GUID: a FAT volume, but boot support
    // rather than the image's content.
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
];

/// Most names listed in one note.
const MAX_LISTED: usize = 8;

/// Data fork CRC-32s over larger forks are not computed, to keep
/// classification fast.
const MAX_CHECKED_DATA_FORK: u64 = MAX_PAYLOAD as u64;

/// Where the block tables were read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Xml,
    ResourceFork,
}

impl Source {
    fn text(self) -> &'static str {
        match self {
            Self::Xml => "the XML property list",
            Self::ResourceFork => "the resource fork",
        }
    }
}

/// A block table and the partition it describes.
#[derive(Debug)]
struct Partition {
    /// Display name: `CFName` or `Name`, trimmed.
    name: String,
    /// The partition type from a `name (type : n)` name.
    type_name: Option<String>,
    table: Table,
}

impl Partition {
    fn new(name: Option<&str>, fallback: String, table_bytes: &[u8], t: &Trailer) -> Result<Self> {
        let name = name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or(fallback, display_text);
        let table = blkx::table(table_bytes, &name, t.data_fork.offset)?;
        Ok(Self {
            type_name: partition_type(&name),
            name,
            table,
        })
    }

    /// Whether this is a map, boot record, driver or free space.
    fn is_map(&self) -> bool {
        let text = self.type_name.as_deref().unwrap_or(&self.name);
        MAP_TYPES.iter().any(|map| text.contains(map))
    }
}

/// The type in a `name (type : n)` partition name, as darling-dmg
/// `DMGDisk::parseNameAndType` reads it.
fn partition_type(name: &str) -> Option<String> {
    let inner = name.strip_suffix(')')?;
    let open = inner.rfind('(')?;
    let (kind, _number) = inner[open + 1..].rsplit_once(':')?;
    let kind = kind.trim();
    (!kind.is_empty()).then(|| kind.to_string())
}

/// The block tables of an image and where they were read from.
#[derive(Debug)]
struct Tables {
    source: Source,
    /// In the order they are stored.
    partitions: Vec<Partition>,
}

/// Read the block tables from the XML property list, or from the binary
/// resource fork when the trailer names no property list.
fn read_partitions(data: &[u8], t: &Trailer) -> Result<Tables> {
    let mut partitions = Vec::new();
    if !t.xml.is_empty() {
        let xml = t.xml.bytes(data, "XML property list")?;
        for (i, entry) in plist::blkx_entries(xml)?.into_iter().enumerate() {
            let fallback = match &entry.id {
                Some(id) => format!("Partition {}", display_text(id.trim())),
                None => format!("Block table {i}"),
            };
            let bytes = entry
                .data
                .ok_or_else(|| error(format!("Missing Data in block table entry {i}")))?;
            let name = entry.cf_name.as_deref().or(entry.name.as_deref());
            partitions.push(Partition::new(name, fallback, &bytes, t)?);
        }
        return Ok(Tables {
            source: Source::Xml,
            partitions,
        });
    }
    let fork = t.resource_fork.bytes(data, "resource fork")?;
    for resource in rsrc::blkx_resources(fork)? {
        let fallback = format!("Partition {}", resource.id);
        partitions.push(Partition::new(
            resource.name.as_deref(),
            fallback,
            resource.data,
            t,
        )?);
    }
    Ok(Tables {
        source: Source::ResourceFork,
        partitions,
    })
}

/// Verify the data fork CRC-32 when the trailer stores one and the fork is
/// small enough; the returned text says what was checked.
fn data_fork_checksum(data: &[u8], t: &Trailer) -> Result<String> {
    let checksum = &t.data_fork_checksum;
    if checksum.is_absent() {
        return Ok("No data fork checksum is stored".into());
    }
    let Some(stored) = checksum.crc32() else {
        return Ok(format!(
            "Data fork checksum ({}) not verified",
            checksum.describe()
        ));
    };
    if t.data_fork.length > MAX_CHECKED_DATA_FORK {
        return Ok(format!(
            "Data fork CRC-32 0x{stored:08X} not verified: the data fork is larger than {}",
            size_text(MAX_CHECKED_DATA_FORK)
        ));
    }
    let computed = checksum::crc32(t.data_fork.bytes(data, "data fork")?);
    if computed != stored {
        return Err(error(format!(
            "Invalid data fork CRC-32 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(format!("Data fork CRC-32 0x{stored:08X} verified"))
}

/// Verify the master CRC-32 over the tables' checksum values.
fn master_checksum(t: &Trailer, partitions: &[Partition]) -> Result<String> {
    let master = &t.master_checksum;
    if master.is_absent() {
        return Ok("No master checksum is stored".into());
    }
    let Some(stored) = master.crc32() else {
        return Ok(format!(
            "Master checksum ({}) not verified",
            master.describe()
        ));
    };
    // A segment after the first holds no tables (`hdiutil segment` writes
    // an empty `resource-fork`) but repeats the image's master checksum.
    if partitions.is_empty() {
        return Ok(format!(
            "Master CRC-32 0x{stored:08X} not verified: there are no block tables"
        ));
    }
    let mut crc = !0u32;
    for p in partitions {
        let Some(value) = p.table.checksum.value_bytes() else {
            return Ok(format!(
                "Master CRC-32 0x{stored:08X} not verified: the checksum of {} is not a whole \
                 number of bytes",
                p.name
            ));
        };
        crc = checksum::crc32_update(crc, value);
    }
    let computed = !crc;
    if computed != stored {
        return Err(error(format!(
            "Invalid master CRC-32 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(format!("Master CRC-32 0x{stored:08X} verified"))
}

/// Why a partition was not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Skipped {
    /// Zero fill and free space only: nothing is stored.
    NoData,
    /// A chunk type no reader documents.
    UnsupportedChunk(u32),
    /// A chunk lies in another segment file.
    OtherSegment,
    /// The extraction budget is spent.
    Budget,
}

/// The decoded bytes of a partition.
#[derive(Debug)]
struct Assembled<'a> {
    bytes: Cow<'a, [u8]>,
    /// The whole partition was decoded, not just its first bytes.
    complete: bool,
    /// File range that holds the stored chunks.
    span: Span,
}

/// A range of file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
}

impl Span {
    /// The smallest range that covers both.
    fn union(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// A partition's stored chunk bytes, or `None` when the chunk lies past
/// this segment's data fork in a multi-segment image.
fn stored<'a>(
    data: &'a [u8],
    t: &Trailer,
    p: &Partition,
    chunk: &blkx::Chunk,
) -> Result<Option<&'a [u8]>> {
    let fork_end = t.data_fork.offset + t.data_fork.length;
    let inside = chunk.offset >= t.data_fork.offset
        && chunk
            .offset
            .checked_add(chunk.length)
            .is_some_and(|end| end <= fork_end);
    if !inside {
        if t.segment_count > 1 {
            return Ok(None);
        }
        return Err(error(format!(
            "Truncated chunk of {} at 0x{:X} + {} B: the data fork ends at 0x{fork_end:X}",
            p.name, chunk.offset, chunk.length
        )));
    }
    range(data, chunk.offset, chunk.length, "chunk").map(Some)
}

/// Decode one compressed chunk, of which the first `take` bytes are
/// needed. A chunk within the extraction limit must decode to exactly its
/// size; a larger one is decoded only as far as `take`.
fn decode_chunk(
    p: &Partition,
    chunk: &blkx::Chunk,
    codec: Codec,
    stored: &[u8],
    take: usize,
) -> Result<Vec<u8>> {
    let what = || {
        format!(
            "{} chunk of {} at 0x{:X}",
            chunk.kind.name(),
            p.name,
            chunk.offset
        )
    };
    let invalid = |e: ClassifierError| error(format!("Invalid {}: {e}", what()));
    let size = chunk.size();
    let (decoded, expected) = match usize::try_from(size) {
        Ok(size) if size <= MAX_PAYLOAD => (
            compressed::decode_limited(codec, stored, size)
                .map_err(invalid)?
                .data,
            size,
        ),
        _ => (
            compressed::decode_prefix(codec, stored, take).map_err(invalid)?,
            take,
        ),
    };
    if decoded.len() != expected {
        return Err(error(format!(
            "Invalid {}: it decodes to {} B of {size} B",
            what(),
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Assemble the first `limit` bytes of a partition from its chunks: zero
/// fill and free space as zeros, raw chunks copied, compressed chunks
/// decoded. A partition that is one raw chunk is a slice of the file.
fn assemble<'a>(
    data: &'a [u8],
    t: &Trailer,
    p: &Partition,
    limit: usize,
) -> Result<std::result::Result<Assembled<'a>, Skipped>> {
    let size = p.table.size();
    let want = usize::try_from(size).map_or(limit, |size| size.min(limit));
    let complete = want as u64 == size;
    if let [chunk] = p.table.chunks[..] {
        if chunk.kind == Kind::Raw && complete && chunk.length == size {
            let Some(bytes) = stored(data, t, p, &chunk)? else {
                return Ok(Err(Skipped::OtherSegment));
            };
            return Ok(Ok(Assembled {
                bytes: Cow::Borrowed(bytes),
                complete,
                span: Span {
                    start: chunk.offset,
                    end: chunk.offset + chunk.length,
                },
            }));
        }
    }
    let mut out: Vec<u8> = Vec::new();
    let mut span: Option<Span> = None;
    for chunk in &p.table.chunks {
        if out.len() >= want {
            break;
        }
        let left = want - out.len();
        let take = usize::try_from(chunk.size()).map_or(left, |size| size.min(left));
        if let Kind::Unknown(chunk_type) = chunk.kind {
            return Ok(Err(Skipped::UnsupportedChunk(chunk_type)));
        }
        if !chunk.kind.is_stored() {
            out.resize(out.len() + take, 0);
            continue;
        }
        let Some(bytes) = stored(data, t, p, chunk)? else {
            return Ok(Err(Skipped::OtherSegment));
        };
        let chunk_span = Span {
            start: chunk.offset,
            end: chunk.offset + chunk.length,
        };
        span = Some(span.map_or(chunk_span, |s| s.union(chunk_span)));
        match chunk.kind {
            Kind::Compressed(codec) => {
                let decoded = decode_chunk(p, chunk, codec, bytes, take)?;
                out.extend_from_slice(&decoded[..take]);
            }
            _ if chunk.length == chunk.size() => out.extend_from_slice(&bytes[..take]),
            _ => {
                return Err(error(format!(
                    "Invalid raw chunk of {} at 0x{:X}: {} B stored for {} B",
                    p.name,
                    chunk.offset,
                    chunk.length,
                    chunk.size()
                )));
            }
        }
    }
    // The extraction limit may stop before the first stored chunk; the
    // decoded bytes are then zeros only.
    let Some(span) = span else {
        return Ok(Err(Skipped::NoData));
    };
    Ok(Ok(Assembled {
        bytes: Cow::Owned(out),
        complete,
        span,
    }))
}

/// The CRC-32 of a decoded partition's bytes, ignore chunks left out.
fn partition_crc32(p: &Partition, bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    let mut at = 0usize;
    for chunk in &p.table.chunks {
        // The chunks tile the table's sectors (`blkx::table`), and the
        // whole partition was decoded, so every chunk lies in `bytes`.
        let size = usize::try_from(chunk.size()).expect("a decoded chunk fits in memory");
        let part = &bytes[at..at + size];
        if chunk.kind != Kind::Ignore {
            crc = checksum::crc32_update(crc, part);
        }
        at += size;
    }
    !crc
}

/// What was established about a partition's checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Crc {
    Verified(u32),
    NotVerified(String),
    Absent,
}

/// Check a partition's table checksum: against the decoded bytes when the
/// whole partition was decoded, or against nothing when every chunk is
/// free space (the CRC-32 of no bytes is 0).
fn table_crc(p: &Partition, assembled: Option<&Assembled<'_>>) -> Result<Crc> {
    let checksum = &p.table.checksum;
    if checksum.is_absent() {
        return Ok(Crc::Absent);
    }
    let Some(stored) = checksum.crc32() else {
        return Ok(Crc::NotVerified(format!(
            "checksum {}",
            checksum.describe()
        )));
    };
    let computed = match assembled {
        Some(a) if a.complete => partition_crc32(p, &a.bytes),
        Some(_) => return Ok(Crc::NotVerified("cut at the extraction limit".into())),
        None if p.table.chunks.iter().all(|c| c.kind == Kind::Ignore) => 0,
        None => return Ok(Crc::NotVerified("not decoded".into())),
    };
    if computed != stored {
        return Err(error(format!(
            "Invalid CRC-32 of {}: stored 0x{stored:08X}, computed 0x{computed:08X}",
            p.name
        )));
    }
    Ok(Crc::Verified(stored))
}

/// The transform of a decoded partition, named after its stored chunks.
fn transform(table: &Table) -> &'static str {
    let mut kinds = table
        .chunks
        .iter()
        .map(|c| c.kind)
        .filter(|kind| kind.is_stored());
    let Some(first) = kinds.next() else {
        return "UDIF chunks";
    };
    if kinds.any(|kind| kind != first) {
        return "UDIF chunks";
    }
    match first {
        Kind::Raw => "UDIF raw chunks",
        Kind::Compressed(Codec::Adc) => "UDIF ADC chunks",
        Kind::Compressed(Codec::Zlib) => "UDIF zlib chunks",
        Kind::Compressed(Codec::Bzip2) => "UDIF bzip2 chunks",
        Kind::Compressed(Codec::Lzfse) => "UDIF LZFSE chunks",
        Kind::Compressed(Codec::Xz) => "UDIF LZMA chunks",
        _ => "UDIF chunks",
    }
}

/// `a, b and 3 more`: up to [`MAX_LISTED`] names.
fn listed(names: &[String]) -> String {
    let mut text = names
        .iter()
        .take(MAX_LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX_LISTED {
        let _ = write!(text, " and {} more", names.len() - MAX_LISTED);
    }
    text
}

/// What happened to the partitions, for notes.
#[derive(Debug, Default)]
struct Outcome {
    verified: usize,
    unverified: Vec<String>,
    unrecognized: Vec<String>,
    skipped: Vec<String>,
    cut: Vec<String>,
}

/// Parse a UDIF image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let t = koly::trailer(data)?;
    if t.xml.is_empty() && t.resource_fork.is_empty() {
        return Err(error(
            "Unsupported UDIF image: the trailer names no XML property list or resource fork",
        ));
    }
    let data_fork_note = data_fork_checksum(data, &t)?;
    let Tables { source, partitions } = read_partitions(data, &t)?;
    let master_note = master_checksum(&t, &partitions)?;
    let mut c = Container::new(FileFormat::AppleDmg, Layout::Udif.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(format!(
        "UDIF version 4 image: {} in {}; disk of {} sectors of 512 B",
        counted(partitions.len(), "block table", "block tables"),
        source.text(),
        t.sector_count
    ));
    c.notes.push(data_fork_note.clone());
    c.notes.push(master_note.clone());
    push_trailer_metadata(&mut c, &t, data_fork_note, master_note);

    // Volumes first, then maps, boot records and free space.
    let mut order: Vec<usize> = (0..partitions.len())
        .filter(|&i| !partitions[i].is_map())
        .collect();
    order.extend((0..partitions.len()).filter(|&i| partitions[i].is_map()));
    let mut outcome = Outcome::default();
    let mut budget = MAX_EXTRACTED;
    let mut statuses: Vec<String> = vec![String::new(); partitions.len()];
    for &i in &order {
        let p = &partitions[i];
        let assembled = if !p.table.has_stored_data() {
            Err(Skipped::NoData)
        } else if budget == 0 {
            Err(Skipped::Budget)
        } else {
            assemble(data, &t, p, MAX_PAYLOAD.min(budget))?
        };
        let crc = table_crc(p, assembled.as_ref().ok())?;
        match &crc {
            Crc::Verified(_) => outcome.verified += 1,
            Crc::NotVerified(why) => outcome.unverified.push(format!("{} ({why})", p.name)),
            Crc::Absent => outcome.unverified.push(format!("{} (no checksum)", p.name)),
        }
        statuses[i] = partition_status(p, &assembled, &crc);
        match assembled {
            Ok(a) => {
                // A slice of the file is not extracted, so it costs nothing.
                if let Cow::Owned(bytes) = &a.bytes {
                    budget -= bytes.len().min(budget);
                }
                if !a.complete {
                    outcome.cut.push(p.name.clone());
                }
                // Maps, boot records and free space are decoded for their
                // checksums only: on their own they describe nothing (a
                // protective MBR without the disk it maps is not a GPT).
                if p.is_map() {
                    continue;
                }
                if container::is_recognized(&a.bytes) {
                    c.children.push(child(p, a));
                } else {
                    outcome.unrecognized.push(p.name.clone());
                }
            }
            Err(Skipped::NoData) => {}
            Err(skipped) => {
                let reason = skipped_text(&skipped);
                outcome.skipped.push(format!("{} ({reason})", p.name));
            }
        }
    }
    push_outcome_notes(&mut c, &partitions, &outcome);
    push_layout_notes(&mut c, &t, &partitions);
    for (i, p) in partitions.iter().enumerate() {
        c.push_metadata(
            format!("dmg_partition_{i}"),
            p.name.clone(),
            statuses[i].clone(),
        );
    }
    Ok(c)
}

/// The child for a decoded partition that holds a recognized format.
fn child<'a>(p: &Partition, a: Assembled<'a>) -> Child<'a> {
    // `stored` checked that every chunk lies in the input.
    let offset = usize::try_from(a.span.start).expect("chunks lie in the input");
    match a.bytes {
        Cow::Borrowed(bytes) => Child::stored(p.name.clone(), offset, bytes),
        Cow::Owned(bytes) => {
            let stored_size =
                usize::try_from(a.span.end - a.span.start).expect("chunks lie in the input");
            Child::decoded(
                p.name.clone(),
                offset,
                stored_size,
                Cow::Owned(bytes),
                transform(&p.table),
            )
        }
    }
}

fn skipped_text(skipped: &Skipped) -> String {
    match skipped {
        Skipped::NoData => "no stored data".into(),
        Skipped::UnsupportedChunk(chunk_type) => {
            format!("unsupported chunk type 0x{chunk_type:08X}")
        }
        Skipped::OtherSegment => "a chunk is in another segment file".into(),
        Skipped::Budget => format!(
            "the {} extraction limit was reached",
            size_text(MAX_EXTRACTED as u64)
        ),
    }
}

/// `sectors 40-2007 (984 KiB); chunks: zlib 2, ignore 2; CRC-32
/// 0xEB0E2F8C verified`, for a partition's metadata entry.
fn partition_status(
    p: &Partition,
    assembled: &std::result::Result<Assembled<'_>, Skipped>,
    crc: &Crc,
) -> String {
    let table = &p.table;
    let sectors = if table.sector_count == 0 {
        format!("sector {}; empty", table.first_sector)
    } else {
        format!(
            "sectors {}-{} ({})",
            table.first_sector,
            table.first_sector + table.sector_count - 1,
            size_text(table.size())
        )
    };
    let crc = match crc {
        Crc::Verified(value) => format!("CRC-32 0x{value:08X} verified"),
        Crc::NotVerified(why) => format!("checksum not verified ({why})"),
        Crc::Absent => "no checksum".into(),
    };
    let decoded = match assembled {
        Ok(a) if a.complete => String::new(),
        Ok(a) => format!("; first {} decoded", size_text(a.bytes.len() as u64)),
        Err(Skipped::NoData) => String::new(),
        Err(skipped) => format!("; not decoded: {}", skipped_text(skipped)),
    };
    format!(
        "{sectors}; chunks: {}; {crc}{decoded}",
        if table.chunks.is_empty() {
            "none".to_string()
        } else {
            table.chunk_summary()
        }
    )
}

fn push_trailer_metadata(c: &mut Container<'_>, t: &Trailer, data_fork: String, master: String) {
    c.push_metadata("dmg_flags", "UDIF flags", t.flags_text());
    c.push_metadata("dmg_image_variant", "Image variant", t.variant_text());
    c.push_metadata("dmg_sector_count", "Disk sectors (512 B)", t.sector_count);
    c.push_metadata("dmg_data_fork", "Data fork", t.data_fork.describe());
    if !t.xml.is_empty() {
        c.push_metadata("dmg_xml_plist", "XML property list", t.xml.describe());
    }
    if !t.resource_fork.is_empty() {
        c.push_metadata(
            "dmg_resource_fork",
            "Resource fork",
            t.resource_fork.describe(),
        );
    }
    if t.segment_number != 0 || t.segment_count != 0 {
        c.push_metadata(
            "dmg_segment",
            "Segment",
            format!("{} of {}", t.segment_number, t.segment_count),
        );
    }
    if t.running_data_fork_offset != 0 {
        c.push_metadata(
            "dmg_running_data_fork_offset",
            "Segment data offset (B)",
            t.running_data_fork_offset,
        );
    }
    c.push_metadata("dmg_data_fork_checksum", "Data fork checksum", data_fork);
    c.push_metadata("dmg_master_checksum", "Master checksum", master);
    if t.has_code_signature() {
        c.push_metadata(
            "dmg_code_signature",
            "Code signature",
            format!("{}; not verified", t.code_signature.describe()),
        );
    }
}

fn push_outcome_notes(c: &mut Container<'_>, partitions: &[Partition], outcome: &Outcome) {
    if partitions.is_empty() {
        c.notes.push(
            "There are no block tables: the image describes no partitions (in a segmented \
             image the first segment holds them)"
                .into(),
        );
    } else if outcome.unverified.is_empty() {
        c.notes.push(format!(
            "Block table CRC-32 verified for every partition ({})",
            partitions.len()
        ));
    } else {
        c.notes.push(format!(
            "Block table CRC-32 verified for {} of {} partitions; not verified: {}",
            outcome.verified,
            partitions.len(),
            listed(&outcome.unverified)
        ));
    }
    c.notes
        .push("Disk images name no ISA; each partition is classified on its own".into());
    if !outcome.unrecognized.is_empty() {
        c.notes.push(format!(
            "Not in a recognized format, so not classified: {}",
            listed(&outcome.unrecognized)
        ));
    }
    if !outcome.skipped.is_empty() {
        c.notes
            .push(format!("Not decoded: {}", listed(&outcome.skipped)));
    }
    if !outcome.cut.is_empty() {
        c.notes.push(format!(
            "Only the first bytes were decoded and analyzed ({} per partition, {} per image): {}",
            size_text(MAX_PAYLOAD as u64),
            size_text(MAX_EXTRACTED as u64),
            listed(&outcome.cut)
        ));
    }
}

/// Notes on the disk layout: whether the tables tile the disk, segments
/// and the code signature.
fn push_layout_notes(c: &mut Container<'_>, t: &Trailer, partitions: &[Partition]) {
    if !partitions.is_empty() {
        push_tiling_note(c, t, partitions);
    }
    if t.segment_count > 1 {
        c.notes.push(format!(
            "Segment {} of {}: chunks stored in the other segment files are not available",
            t.segment_number, t.segment_count
        ));
    }
    if t.has_code_signature() {
        c.notes.push(format!(
            "A code signature of {} B is stored at 0x{:X}; not verified",
            t.code_signature.length, t.code_signature.offset
        ));
    }
}

/// A note when the tables, sorted by first sector, leave gaps, overlap or
/// end before or after the disk's sector count.
fn push_tiling_note(c: &mut Container<'_>, t: &Trailer, partitions: &[Partition]) {
    let mut extents: Vec<(u64, u64)> = partitions
        .iter()
        .map(|p| (p.table.first_sector, p.table.sector_count))
        .collect();
    extents.sort_unstable();
    let mut next = 0u64;
    let mut tiles = true;
    for (first, count) in extents {
        tiles &= first == next;
        next = first.saturating_add(count);
    }
    if !tiles || next != t.sector_count {
        c.notes.push(format!(
            "The block tables do not tile the disk: they end at sector {next} of {}, with gaps or \
             overlaps",
            t.sector_count
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_types_come_from_the_parenthesized_suffix() {
        assert_eq!(
            partition_type("disk image (Apple_HFS : 4)").as_deref(),
            Some("Apple_HFS")
        );
        assert_eq!(
            partition_type("GPT Header (Primary GPT Header : 1)").as_deref(),
            Some("Primary GPT Header")
        );
        assert_eq!(
            partition_type("(Apple_Free : 3)").as_deref(),
            Some("Apple_Free")
        );
        assert_eq!(partition_type("Whole_Disk"), None);
        assert_eq!(partition_type("odd (: 1)"), None);
    }

    #[test]
    fn listed_names_are_bounded() {
        let names: Vec<String> = (0..10).map(|i| format!("p{i}")).collect();
        assert_eq!(listed(&names[..2]), "p0, p1");
        assert!(listed(&names).ends_with("p7 and 2 more"));
    }
}
