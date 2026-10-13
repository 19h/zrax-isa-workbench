//! coreboot CBFS: a chain of big-endian `struct cbfs_file` entries, each
//! starting with `LARCHIVE` on a 64-byte boundary from the region start and
//! followed by its NUL-terminated name, its attributes and its data
//! (coreboot 25.09 `cbfs_serialized.h`, `cbfs_walk`).
//!
//! Attributes are a tag, a length covering the whole attribute, and a body
//! (`cbfs_find_attr`). The master header (`ORBC`) is the data of a file of
//! type `CBFSHEADER`; legacy ROMs also locate it through a little-endian
//! signed offset from the end of the ROM in their last four bytes. The
//! legacy stage header is little-endian, unlike every other structure.
//!
//! File headers and attributes are the container's own structure, so a
//! broken one is a parse error. File contents are checked per file: a stage
//! header, payload segment table or compressed stream that does not hold up
//! leaves that file opaque, with a note.
//!
//! Stage programs and SELF payload `CODE` segments are flat images built
//! from ELF load segments without the ELF header (`cbfs-mkstage.c`,
//! `cbfs-mkpayload.c`), so they go straight to the code model. `RAW` files
//! and types without a fixed content are listed only when their bytes are a
//! recognized format; configuration, images and microcode are opaque.

use super::*;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Child, Target};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, Isa};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::borrow::Cow;

/// File header magic.
pub(super) const FILE_MAGIC: &[u8; 8] = b"LARCHIVE";

/// `struct cbfs_file` before the name.
const FILE_HEADER_SIZE: usize = 24;

/// `CBFS_METADATA_MAX_SIZE`: header, name and attributes.
const METADATA_MAX_SIZE: usize = 256;

/// `CBFS_ALIGNMENT`: file headers start on these boundaries.
const ALIGNMENT: usize = 64;

/// `CBFS_HEADER_MAGIC` (`"ORBC"`) and the two header versions (`"1111"`,
/// `"1112"`).
const HEADER_MAGIC: u32 = 0x4f52_4243;
const HEADER_VERSION1: u32 = 0x3131_3131;
const HEADER_VERSION2: u32 = 0x3131_3132;

/// `struct cbfs_header`.
const MASTER_HEADER_SIZE: usize = 32;

/// The master-header pointer at the end of a legacy ROM.
const POINTER_SIZE: usize = 4;

/// `CBFS_ARCHITECTURE_UNKNOWN`, written for version-1 headers (x86 only
/// at the time) and by current cbfstool `add-master-header`.
const ARCHITECTURE_UNKNOWN: u32 = 0xffff_ffff;

/// Attribute tags (`CBFS_FILE_ATTR_TAG_*`); the comments give the bytes as
/// stored.
const ATTRIBUTE_UNUSED: u32 = 0x0000_0000;
const ATTRIBUTE_UNUSED2: u32 = 0xffff_ffff;
const ATTRIBUTE_COMPRESSION: u32 = 0x4243_5a4c; // "BCZL"
const ATTRIBUTE_HASH: u32 = 0x6873_6148; // "hsaH"
const ATTRIBUTE_POSITION: u32 = 0x4243_5350; // "BCSP"
const ATTRIBUTE_ALIGNMENT: u32 = 0x4243_4c41; // "BCLA"
const ATTRIBUTE_IBB: u32 = 0x3249_4242; // "2IBB"
const ATTRIBUTE_PADDING: u32 = 0x4744_4150; // "GNDP"
const ATTRIBUTE_STAGEHEADER: u32 = 0x5374_6748; // "StgH"

/// Tags that are known but carry nothing the classifier uses.
const IGNORED_ATTRIBUTES: &[u32] = &[
    ATTRIBUTE_POSITION,
    ATTRIBUTE_ALIGNMENT,
    ATTRIBUTE_IBB,
    ATTRIBUTE_PADDING,
];

/// `struct cbfs_file_attribute` before the body.
const ATTRIBUTE_HEADER_SIZE: usize = 8;

/// Whole-attribute sizes `cbfs_find_attr` callers require.
const COMPRESSION_ATTRIBUTE_SIZE: usize = 16;
const STAGEHEADER_ATTRIBUTE_SIZE: usize = 24;

/// Hash attribute bytes before the digest: tag, length, 3 reserved bytes
/// and the algorithm.
const HASH_ATTRIBUTE_PREFIX: usize = 12;

/// `CBFS_COMPRESS_*`.
const COMPRESS_NONE: u32 = 0;
const COMPRESS_LZMA: u32 = 1;
const COMPRESS_LZ4: u32 = 2;

/// Legacy `struct cbfs_stage`.
const LEGACY_STAGE_HEADER_SIZE: usize = 28;

/// `struct cbfs_payload_segment` and its types.
const SEGMENT_SIZE: usize = 28;
const SEGMENT_CODE: u32 = 0x434f_4445; // "CODE"
const SEGMENT_DATA: u32 = 0x4441_5441; // "DATA"
const SEGMENT_BSS: u32 = 0x4253_5320; // "BSS "
const SEGMENT_ENTRY: u32 = 0x454e_5452; // "ENTR"
const SEGMENT_PARAMS: u32 = 0x5041_5241; // "PARA"

/// What a file's data holds, which decides how it is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    /// `DELETED` and `NULL` entries: free space.
    Empty,
    /// The master header.
    MasterHeader,
    /// Legacy stage: a little-endian stage header, then the program.
    LegacyStage,
    /// Stage: the program, described by a stage-header attribute.
    Stage,
    /// SELF payload: a segment table, then the segments.
    Payload,
    /// Code, possibly in a format of its own: always classified.
    Code,
    /// Listed only when the bytes are a recognized format.
    Recognized,
    /// Configuration, images or tables: listed, never analyzed.
    Data,
}

/// How the bytes of one component are classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// A flat program image (stage, payload `CODE` segment): straight to
    /// the code model, never parsed as a nested container.
    Program,
    /// Classified on their own: as a nested format when recognized,
    /// otherwise by the code model.
    Always,
    /// Listed only when the bytes are a recognized format.
    IfRecognized,
    /// Listed, never analyzed.
    Opaque,
}

impl Content {
    /// How a file of this content is classified when it is one component.
    /// A SELF payload is one component only when its segment table does
    /// not hold up; empty entries and the master header are no component.
    fn policy(self) -> Policy {
        match self {
            Self::LegacyStage | Self::Stage => Policy::Program,
            Self::Code => Policy::Always,
            Self::Recognized => Policy::IfRecognized,
            Self::Empty | Self::MasterHeader | Self::Payload | Self::Data => Policy::Opaque,
        }
    }
}

/// `enum cbfs_type`: value, name and content. Types not listed are
/// classified only when recognized.
const FILE_TYPES: &[(u32, &str, Content)] = &[
    (0x0000_0000, "DELETED", Content::Empty),
    (0xffff_ffff, "NULL", Content::Empty),
    (0x01, "BOOTBLOCK", Content::Code),
    (0x02, "CBFSHEADER", Content::MasterHeader),
    (0x10, "LEGACY_STAGE", Content::LegacyStage),
    (0x11, "STAGE", Content::Stage),
    (0x20, "SELF", Content::Payload),
    (0x21, "FIT_PAYLOAD", Content::Recognized),
    (0x30, "OPTIONROM", Content::Code),
    (0x40, "BOOTSPLASH", Content::Data),
    (0x50, "RAW", Content::Recognized),
    (0x51, "VSA", Content::Code),
    (0x52, "MBI", Content::Recognized),
    (0x53, "MICROCODE", Content::Data),
    (0x54, "INTEL_FIT", Content::Data),
    (0x60, "FSP", Content::Recognized),
    (0x61, "MRC", Content::Code),
    (0x62, "MMA", Content::Recognized),
    (0x63, "EFI", Content::Recognized),
    (0x70, "STRUCT", Content::Data),
    (0x80, "AMDFW", Content::Recognized),
    (0xaa, "CMOS_DEFAULT", Content::Data),
    (0xab, "SPD", Content::Data),
    (0xac, "MRC_CACHE", Content::Data),
    (0x01aa, "CMOS_LAYOUT", Content::Data),
];

/// Master-header `architecture` values: name, and the target where the
/// value also fixes the register width. x86, MIPS and RISC-V name a family
/// without its width (coreboot builds 32- and 64-bit x86 and RISC-V), so
/// they set no target. Only 64-bit Arm fixes the instruction byte order.
const ARCHITECTURES: &[(u32, &str, Option<Target>)] = &[
    (ARCHITECTURE_UNKNOWN, "unknown", None),
    (0x0000_0001, "x86", None),
    (
        0x0000_0010,
        "ARM",
        Some(Target::without_byte_order(Isa::Arm, 32)),
    ),
    (
        0x0000_aa64,
        "AArch64",
        Some(Target::new(Isa::AArch64, 64, Endianness::Little)),
    ),
    (0x0000_0100, "MIPS", None),
    (0xc001_d0de, "RISC-V", None),
    (
        0x4075_70ff,
        "PPC64",
        Some(Target::without_byte_order(Isa::Ppc64, 64)),
    ),
];

/// vboot `enum vb2_hash_algorithm` values.
const VB2_HASH_SHA1: u8 = 1;
const VB2_HASH_SHA256: u8 = 2;
const VB2_HASH_SHA512: u8 = 3;
const VB2_HASH_SHA224: u8 = 4;
const VB2_HASH_SHA384: u8 = 5;

/// Hash algorithms: value, name and digest size.
const HASH_ALGORITHMS: &[(u8, &str, usize)] = &[
    (VB2_HASH_SHA1, "SHA-1", 20),
    (VB2_HASH_SHA256, "SHA-256", 32),
    (VB2_HASH_SHA512, "SHA-512", 64),
    (VB2_HASH_SHA224, "SHA-224", 28),
    (VB2_HASH_SHA384, "SHA-384", 48),
];

/// `struct cbfs_header`, big-endian: magic, version, `romsize` (end of the
/// CBFS in the boot media), `bootblocksize`, `align`, `offset` (first
/// entry), `architecture`, padding.
struct MasterHeader {
    version: u32,
    rom_size: u32,
    bootblock_size: u32,
    align: u32,
    first_entry: u32,
    architecture: u32,
}

/// Compression attribute body: algorithm and decoded size in bytes.
struct CompressionAttribute {
    algorithm: u32,
    decoded_size: u32,
}

/// Stage-header attribute body: load address, entry offset from it, and
/// memory size in bytes (including BSS).
struct StageAttribute {
    load_address: u64,
    entry_offset: u32,
    memory_size: u32,
}

/// Hash attribute body: vboot algorithm and digest.
struct HashAttribute<'a> {
    algorithm: u8,
    digest: &'a [u8],
}

/// The attributes the classifier uses; the first of each tag wins, as in
/// `cbfs_find_attr`.
#[derive(Default)]
struct Attributes<'a> {
    compression: Option<CompressionAttribute>,
    stage: Option<StageAttribute>,
    hash: Option<HashAttribute<'a>>,
    /// Attributes with a tag this parser does not know.
    unknown: usize,
}

/// A file whose header and attributes passed the checks.
struct Entry<'a> {
    /// File offset of the header.
    offset: usize,
    name: String,
    file_type: u32,
    attributes: Attributes<'a>,
    /// File offset of the data.
    data_offset: usize,
    data: &'a [u8],
}

impl Entry<'_> {
    fn content(&self) -> Content {
        file_type(self.file_type).map_or(Content::Recognized, |known| known.content)
    }

    fn type_name(&self) -> String {
        file_type(self.file_type).map_or_else(
            || format!("type 0x{:X}", self.file_type),
            |known| known.name.to_string(),
        )
    }

    fn label(&self) -> String {
        if self.name.is_empty() {
            format!("Unnamed file at 0x{:X}", self.offset)
        } else {
            self.name.clone()
        }
    }
}

/// The files of one region.
#[derive(Default)]
struct Walk<'a> {
    /// Files other than `DELETED` and `NULL`, at most [`MAX_COMPONENTS`].
    files: Vec<Entry<'a>>,
    /// `DELETED` and `NULL` entries.
    empty: usize,
    /// Files past [`MAX_COMPONENTS`].
    unlisted: usize,
    /// Bytes at 64-byte positions without a file header that are not
    /// erased flash.
    stray: usize,
}

/// A file's bytes and how to decode them.
struct Stored<'a> {
    label: String,
    /// File offset of the stored bytes.
    offset: usize,
    bytes: &'a [u8],
    /// `CBFS_COMPRESS_*`.
    compression: u32,
    /// Most bytes decoding may produce, as the format declares.
    limit: usize,
    /// The declared size is the exact decoded size rather than a bound.
    exact: bool,
}

/// What the hash attributes established.
#[derive(Default)]
struct HashTally {
    verified: usize,
    unchecked: usize,
}

/// A file type listed in [`FILE_TYPES`].
struct FileType {
    /// `enum cbfs_type` name without its `CBFS_TYPE_` prefix.
    name: &'static str,
    /// What files of this type hold.
    content: Content,
}

/// The listed file type with `value`, if any.
fn file_type(value: u32) -> Option<FileType> {
    FILE_TYPES
        .iter()
        .find(|(id, _, _)| *id == value)
        .map(|&(_, name, content)| FileType { name, content })
}

/// The message of a content error, for a note.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::CorebootParseError { message } => message,
        other => other.to_string(),
    }
}

fn expect_attribute_size(tag_name: &str, at: usize, len: usize, expected: usize) -> Result<()> {
    if len == expected {
        Ok(())
    } else {
        Err(error(format!(
            "Invalid CBFS {tag_name} attribute at 0x{at:X}: {len} B, expected {expected} B"
        )))
    }
}

/// Attributes between `start` and the end of `metadata` (the data offset),
/// walked as `cbfs_find_attr` does: tag (u32), length (u32, at least 8 B,
/// covering the whole attribute), body. An unused tag ends the list.
/// `at` is the file offset of `metadata`.
fn attributes(metadata: &[u8], at: usize, start: usize) -> Result<Attributes<'_>> {
    let end = metadata.len();
    let mut attributes = Attributes::default();
    let mut pos = start;
    while pos + ATTRIBUTE_HEADER_SIZE <= end {
        let tag = be_u32(metadata, pos)?;
        if tag == ATTRIBUTE_UNUSED || tag == ATTRIBUTE_UNUSED2 {
            break;
        }
        let len = be_u32(metadata, pos + 4)? as usize;
        let attribute_at = at + pos;
        if len < ATTRIBUTE_HEADER_SIZE || len > end - pos {
            return Err(error(format!(
                "Invalid CBFS attribute 0x{tag:08X} at 0x{attribute_at:X}: length {len} B"
            )));
        }
        let attribute = &metadata[pos..pos + len];
        match tag {
            ATTRIBUTE_COMPRESSION => {
                expect_attribute_size(
                    "compression",
                    attribute_at,
                    len,
                    COMPRESSION_ATTRIBUTE_SIZE,
                )?;
                if attributes.compression.is_none() {
                    attributes.compression = Some(CompressionAttribute {
                        algorithm: be_u32(attribute, 8)?,
                        decoded_size: be_u32(attribute, 12)?,
                    });
                }
            }
            ATTRIBUTE_STAGEHEADER => {
                expect_attribute_size(
                    "stage header",
                    attribute_at,
                    len,
                    STAGEHEADER_ATTRIBUTE_SIZE,
                )?;
                if attributes.stage.is_none() {
                    attributes.stage = Some(StageAttribute {
                        load_address: be_u64(attribute, 8)?,
                        entry_offset: be_u32(attribute, 16)?,
                        memory_size: be_u32(attribute, 20)?,
                    });
                }
            }
            ATTRIBUTE_HASH => {
                let hash = hash_attribute(attribute, attribute_at)?;
                if attributes.hash.is_none() {
                    attributes.hash = Some(hash);
                }
            }
            tag if IGNORED_ATTRIBUTES.contains(&tag) => {}
            _ => attributes.unknown += 1,
        }
        pos += len;
    }
    Ok(attributes)
}

/// Hash attribute: tag, length, 3 reserved bytes, algorithm (u8), digest.
/// For a known algorithm the length must be exactly the prefix plus its
/// digest size (`cbfs_file_hash`).
fn hash_attribute(attribute: &[u8], at: usize) -> Result<HashAttribute<'_>> {
    let prefix = field(attribute, 0, HASH_ATTRIBUTE_PREFIX, "CBFS hash attribute")
        .map_err(|_| error(format!("Truncated CBFS hash attribute at 0x{at:X}")))?;
    let algorithm = prefix[HASH_ATTRIBUTE_PREFIX - 1];
    let digest = &attribute[HASH_ATTRIBUTE_PREFIX..];
    if let Some((_, name, size)) = HASH_ALGORITHMS.iter().find(|(id, _, _)| *id == algorithm) {
        if digest.len() != *size {
            return Err(error(format!(
                "Invalid CBFS hash attribute at 0x{at:X}: {} B digest for {name}, expected {size} B",
                digest.len()
            )));
        }
    }
    Ok(HashAttribute { algorithm, digest })
}

/// The file whose header is at file offset `at`, checked as `cbfs_walk`
/// does. `data` ends at the region end. Header: magic (8), `len` (u32, data
/// bytes), `type` (u32), `attributes_offset` (u32, from the header; 0 for
/// none), `offset` (u32, from the header to the data), then the name; all
/// big-endian. As in coreboot, the name and attributes of empty entries
/// are not interpreted.
fn file(data: &[u8], at: usize) -> Result<Entry<'_>> {
    let header = field(data, at, FILE_HEADER_SIZE, "CBFS file header")?;
    let data_len = be_u32(header, 8)? as usize;
    let file_type = be_u32(header, 12)?;
    let attributes_offset = be_u32(header, 16)? as usize;
    let metadata_size = be_u32(header, 20)? as usize;
    if metadata_size > METADATA_MAX_SIZE {
        return Err(error(format!(
            "Invalid CBFS file header at 0x{at:X}: data offset {metadata_size} B exceeds the {METADATA_MAX_SIZE} B metadata limit"
        )));
    }
    let data_offset = at + metadata_size;
    let contents = data
        .get(data_offset..)
        .and_then(|rest| rest.get(..data_len))
        .ok_or_else(|| {
            error(format!(
                "Truncated CBFS file at 0x{at:X}: {data_len} B of data declared at 0x{data_offset:X}, {} B present",
                data.len().saturating_sub(data_offset)
            ))
        })?;
    let mut entry = Entry {
        offset: at,
        name: String::new(),
        file_type,
        attributes: Attributes::default(),
        data_offset,
        data: contents,
    };
    if entry.content() == Content::Empty {
        return Ok(entry);
    }
    let names_end = if attributes_offset == 0 {
        metadata_size
    } else {
        attributes_offset
    };
    if names_end <= FILE_HEADER_SIZE || metadata_size < attributes_offset {
        return Err(error(format!(
            "Invalid CBFS file header at 0x{at:X}: attributes at +{attributes_offset}, data at +{metadata_size}"
        )));
    }
    let metadata = &data[at..data_offset];
    let name = c_string(&metadata[FILE_HEADER_SIZE..names_end]).ok_or_else(|| {
        error(format!(
            "Invalid CBFS file name at 0x{:X}: missing terminator",
            at + FILE_HEADER_SIZE
        ))
    })?;
    entry.name = String::from_utf8_lossy(name).into_owned();
    if attributes_offset != 0 {
        entry.attributes = attributes(metadata, at, attributes_offset)?;
    }
    Ok(entry)
}

/// Walk the region `data[start..end]`: from each 64-byte position (relative
/// to `start`) that holds `LARCHIVE`, take the file and continue at the
/// next boundary after its data; other positions are skipped, as in
/// `cbfs_walk`. Every step advances at least 64 bytes.
fn walk(data: &[u8], start: usize, end: usize) -> Result<Walk<'_>> {
    let region = &data[..end];
    let mut walk = Walk::default();
    let mut pos = start;
    while pos + FILE_HEADER_SIZE < end {
        if !region[pos..].starts_with(FILE_MAGIC) {
            let block = &region[pos..end.min(pos + ALIGNMENT)];
            if !is_padding(block) {
                walk.stray += block.len();
            }
            pos += ALIGNMENT;
            continue;
        }
        let entry = file(region, pos)?;
        let data_end = entry.data_offset + entry.data.len();
        // An empty entry with no metadata and no data would not move the
        // walk; coreboot never writes one.
        pos = (start + align_up(data_end - start, ALIGNMENT)?).max(pos + ALIGNMENT);
        if entry.content() == Content::Empty {
            walk.empty += 1;
        } else if walk.files.len() < MAX_COMPONENTS {
            walk.files.push(entry);
        } else {
            walk.unlisted += 1;
        }
    }
    Ok(walk)
}

/// Master header at file offset `at`: magic and version, and the first
/// entry below the ROM size, as `cbfs_header_valid` requires.
fn master_header(data: &[u8], at: usize) -> Result<MasterHeader> {
    let bytes = field(data, at, MASTER_HEADER_SIZE, "CBFS master header")?;
    if be_u32(bytes, 0)? != HEADER_MAGIC {
        return Err(error(format!(
            "Missing CBFS master header magic at 0x{at:X}"
        )));
    }
    let version = be_u32(bytes, 4)?;
    if version != HEADER_VERSION1 && version != HEADER_VERSION2 {
        return Err(error(format!(
            "Unsupported CBFS master header version 0x{version:08X} at 0x{at:X}"
        )));
    }
    let header = MasterHeader {
        version,
        rom_size: be_u32(bytes, 8)?,
        bootblock_size: be_u32(bytes, 12)?,
        align: be_u32(bytes, 16)?,
        first_entry: be_u32(bytes, 20)?,
        architecture: be_u32(bytes, 24)?,
    };
    if header.first_entry >= header.rom_size {
        return Err(error(format!(
            "Invalid CBFS master header at 0x{at:X}: first entry 0x{:X} is not below the ROM size 0x{:X}",
            header.first_entry, header.rom_size
        )));
    }
    Ok(header)
}

/// File offset of the master header named by the last four bytes: a
/// little-endian signed offset from the end of the ROM.
fn pointer_target(data: &[u8]) -> Result<usize> {
    let pointer_at = data
        .len()
        .checked_sub(POINTER_SIZE)
        .ok_or_else(|| error("Truncated CBFS ROM: no master header pointer"))?;
    let relative = i32::from_le_bytes(array(data, pointer_at)?);
    let target = i64::try_from(data.len())
        .ok()
        .and_then(|len| len.checked_add(i64::from(relative)))
        .and_then(|target| usize::try_from(target).ok())
        .filter(|target| *target < data.len())
        .ok_or_else(|| {
            error(format!(
                "Invalid CBFS master header pointer at 0x{pointer_at:X}: offset {relative} leaves the ROM"
            ))
        })?;
    Ok(target)
}

/// A legacy ROM's master header and the bounds of its CBFS region.
struct Rom {
    header_offset: usize,
    header: MasterHeader,
    start: usize,
    end: usize,
}

/// Locate a legacy ROM's CBFS through the end pointer and check that the
/// region starts with a file header.
fn rom(data: &[u8]) -> Result<Rom> {
    let header_offset = pointer_target(data)?;
    let header = master_header(data, header_offset)?;
    let end = header.rom_size as usize;
    if end > data.len() {
        return Err(error(format!(
            "Truncated CBFS ROM: the master header at 0x{header_offset:X} declares {}, {} B present",
            size_text(header.rom_size as usize),
            data.len()
        )));
    }
    if header.align as usize != ALIGNMENT {
        return Err(error(format!(
            "Unsupported CBFS alignment {} B in the master header at 0x{header_offset:X}",
            header.align
        )));
    }
    let start = header.first_entry as usize;
    if !data[start..end].starts_with(FILE_MAGIC) {
        return Err(error(format!(
            "Missing CBFS file header at 0x{start:X}, the first entry the master header names"
        )));
    }
    file(&data[..end], start)?;
    Ok(Rom {
        header_offset,
        header,
        start,
        end,
    })
}

/// Weak recognition: the end pointer reaches a valid master header and the
/// file headers of the region it names walk cleanly.
pub(super) fn is_master_header_rom(data: &[u8]) -> bool {
    rom(data).is_ok_and(|rom| walk(data, rom.start, rom.end).is_ok())
}

/// `"1112"` for `CBFS_HEADER_VERSION2`.
fn version_text(version: u32) -> String {
    String::from_utf8_lossy(&version.to_be_bytes()).into_owned()
}

/// Report the master header and set the container target from its
/// architecture when the value fixes the register width.
fn adopt_master_header(c: &mut Container<'_>, header: &MasterHeader, at: usize) {
    let architecture = ARCHITECTURES
        .iter()
        .find(|(value, _, _)| *value == header.architecture);
    c.notes.push(format!(
        "Master header version {} at 0x{at:X}: ROM size {}, first entry at 0x{:X}, bootblock size {} B",
        version_text(header.version),
        size_text(header.rom_size as usize),
        header.first_entry,
        header.bootblock_size
    ));
    match architecture {
        Some((_, name, Some(target))) => {
            c.target = Some(*target);
            c.notes.push(format!(
                "Architecture {name} (0x{:08X}) from the master header",
                header.architecture
            ));
        }
        Some((ARCHITECTURE_UNKNOWN, _, None)) => c.notes.push(
            "Master header architecture is unknown (0xFFFFFFFF); ISA taken from the contained code"
                .into(),
        ),
        Some((value, name, None)) => c.notes.push(format!(
            "Master header architecture {name} (0x{value:08X}) does not encode the register width; ISA taken from the contained code"
        )),
        None => c.notes.push(format!(
            "Master header architecture 0x{:08X} is not defined by coreboot; ISA taken from the contained code",
            header.architecture
        )),
    }
    c.push_metadata(
        "cbfs_architecture",
        "Master header architecture",
        architecture.map_or_else(
            || format!("0x{:08X}", header.architecture),
            |(_, name, _)| (*name).to_string(),
        ),
    );
}

/// Whether the digest matches `bytes`; `None` for an algorithm this crate
/// cannot compute (SHA-1) or does not know.
fn digest_matches(hash: &HashAttribute<'_>, bytes: &[u8]) -> Option<bool> {
    let computed: Vec<u8> = match hash.algorithm {
        VB2_HASH_SHA256 => Sha256::digest(bytes).to_vec(),
        VB2_HASH_SHA512 => Sha512::digest(bytes).to_vec(),
        VB2_HASH_SHA224 => Sha224::digest(bytes).to_vec(),
        VB2_HASH_SHA384 => Sha384::digest(bytes).to_vec(),
        _ => return None,
    };
    Some(computed == hash.digest)
}

/// Check a file's hash attribute against its stored data, which is what
/// coreboot's `cbfs_file_hash_mismatch` hashes before decompressing.
fn check_hash(entry: &Entry<'_>, tally: &mut HashTally, notes: &mut Vec<String>) {
    let Some(hash) = &entry.attributes.hash else {
        return;
    };
    let name = HASH_ALGORITHMS
        .iter()
        .find(|(id, _, _)| *id == hash.algorithm)
        .map_or("unknown algorithm", |(_, name, _)| *name);
    match digest_matches(hash, entry.data) {
        Some(true) => tally.verified += 1,
        Some(false) => notes.push(format!(
            "{}: {name} hash attribute does not match the stored file data",
            entry.label()
        )),
        None => tally.unchecked += 1,
    }
}

/// Decode a component within the budget, which is charged the declared
/// size. `Ok(None)` when the budget is exhausted; `Err` for a stream that
/// does not decode to the declared size.
fn decode(codec: Codec, stored: &Stored<'_>, budget: &mut Budget) -> Result<Option<Vec<u8>>> {
    let limit = stored.limit;
    if limit > MAX_PAYLOAD {
        return Err(error(format!(
            "Invalid {} stream: declares {}, beyond the {} extraction limit",
            codec.name(),
            size_text(limit),
            size_text(MAX_PAYLOAD)
        )));
    }
    if !budget.spend(limit) {
        return Ok(None);
    }
    let decoded = compressed::decode_limited(codec, stored.bytes, limit)?.data;
    if stored.exact && decoded.len() != limit {
        return Err(error(format!(
            "Invalid {} stream: {} B decoded, {limit} B declared",
            codec.name(),
            decoded.len()
        )));
    }
    Ok(Some(decoded))
}

/// Add one component: opaque bytes as stored, everything else stored or
/// decoded and classified as `policy` says. A stream that does not decode
/// stays opaque, with a note.
fn push_component<'a>(
    c: &mut Container<'a>,
    stored: Stored<'a>,
    policy: Policy,
    budget: &mut Budget,
) {
    let child = match (policy, stored.compression) {
        (Policy::Opaque, _) => Child::opaque(stored.label, stored.offset, stored.bytes),
        (_, COMPRESS_NONE) => Child::stored(stored.label, stored.offset, stored.bytes),
        (_, algorithm) => {
            let codec = match algorithm {
                COMPRESS_LZMA => Codec::Lzma,
                COMPRESS_LZ4 => Codec::Lz4,
                _ => {
                    c.notes.push(format!(
                        "{}: unsupported compression {algorithm}; not analyzed",
                        stored.label
                    ));
                    let child = Child::opaque(stored.label, stored.offset, stored.bytes);
                    push_child(c, child, policy, budget);
                    return;
                }
            };
            match decode(codec, &stored, budget) {
                Ok(Some(decoded)) => Child::decoded(
                    stored.label,
                    stored.offset,
                    stored.bytes.len(),
                    Cow::Owned(decoded),
                    codec.name(),
                ),
                Ok(None) => return,
                Err(e) => {
                    c.notes
                        .push(format!("{}: {}; not analyzed", stored.label, message(e)));
                    Child::opaque(stored.label, stored.offset, stored.bytes)
                }
            }
        }
    };
    push_child(c, child, policy, budget);
}

/// Add `child` with the classification `policy` names, unless the
/// component limit is reached.
fn push_child<'a>(c: &mut Container<'a>, child: Child<'a>, policy: Policy, budget: &mut Budget) {
    if !budget.admit() {
        return;
    }
    let child = match policy {
        Policy::Program => child.as_code(),
        Policy::IfRecognized => child.if_recognized(),
        Policy::Always | Policy::Opaque => child,
    };
    c.children.push(child);
}

/// How a file's data is compressed.
struct FileCompression {
    /// `CBFS_COMPRESS_*`; `COMPRESS_NONE` without a compression attribute.
    algorithm: u32,
    /// Declared decoded size in bytes; 0 without a compression attribute.
    decoded_size: usize,
}

/// The compression attribute's algorithm and decoded size, or no
/// compression.
fn attribute_compression(entry: &Entry<'_>) -> FileCompression {
    entry.attributes.compression.as_ref().map_or(
        FileCompression {
            algorithm: COMPRESS_NONE,
            decoded_size: 0,
        },
        |a| FileCompression {
            algorithm: a.algorithm,
            decoded_size: a.decoded_size as usize,
        },
    )
}

/// Legacy stage (`struct cbfs_stage`, little-endian): compression (u32),
/// entry (u64), load address (u64), data size (u32), memory size (u32),
/// then the data. coreboot requires the data to fill the file.
fn legacy_stage<'a>(entry: &Entry<'a>, notes: &mut Vec<String>) -> Result<Stored<'a>> {
    let header = field(
        entry.data,
        0,
        LEGACY_STAGE_HEADER_SIZE,
        "legacy stage header",
    )
    .map_err(|_| {
        error(format!(
            "Truncated legacy stage header at 0x{:X}",
            entry.data_offset
        ))
    })?;
    let compression = le_u32(header, 0)?;
    let entry_point = le_u64(header, 4)?;
    let load_address = le_u64(header, 12)?;
    let size = le_u32(header, 20)? as usize;
    let memory_size = le_u32(header, 24)?;
    let present = entry.data.len() - LEGACY_STAGE_HEADER_SIZE;
    if size != present {
        return Err(error(format!(
            "Invalid legacy stage header at 0x{:X}: {size} B of data declared, {present} B present",
            entry.data_offset
        )));
    }
    notes.push(format!(
        "{}: legacy stage; load address 0x{load_address:X}; entry 0x{entry_point:X}; memory size {memory_size} B",
        entry.label()
    ));
    Ok(Stored {
        label: entry.label(),
        offset: entry.data_offset + LEGACY_STAGE_HEADER_SIZE,
        bytes: &entry.data[LEGACY_STAGE_HEADER_SIZE..],
        compression,
        limit: memory_size as usize,
        exact: false,
    })
}

/// Stage: the program image, described by the stage-header attribute and
/// compressed as the compression attribute says.
fn stage<'a>(entry: &Entry<'a>, notes: &mut Vec<String>) -> Result<Stored<'a>> {
    let header = entry
        .attributes
        .stage
        .as_ref()
        .ok_or_else(|| error("Missing stage header attribute"))?;
    let entry_point = header
        .load_address
        .checked_add(u64::from(header.entry_offset))
        .ok_or_else(|| error("Invalid stage header attribute: the entry address overflows"))?;
    let mut note = format!(
        "{}: stage; load address 0x{:X}; entry 0x{entry_point:X}; memory size {} B",
        entry.label(),
        header.load_address,
        header.memory_size
    );
    if header.entry_offset >= header.memory_size {
        note.push_str("; the entry lies outside the stage's memory");
    }
    notes.push(note);
    let FileCompression {
        algorithm: compression,
        decoded_size,
    } = attribute_compression(entry);
    Ok(Stored {
        label: entry.label(),
        offset: entry.data_offset,
        bytes: entry.data,
        compression,
        limit: decoded_size,
        exact: true,
    })
}

/// One `struct cbfs_payload_segment` that has stored bytes.
struct Segment<'a> {
    /// `Program` for `CODE`, `Opaque` for `DATA`.
    policy: Policy,
    stored: Stored<'a>,
}

/// SELF payload: 28-byte big-endian segment records — type, compression,
/// offset (from the payload start), load address (u64), stored size,
/// memory size — up to the ENTRY record. The record count is bounded by
/// the file size.
fn payload<'a>(entry: &Entry<'a>, notes: &mut Vec<String>) -> Result<Vec<Segment<'a>>> {
    let mut segments = Vec::new();
    let mut entry_point = None;
    let mut bss = 0usize;
    for i in 0..entry.data.len() / SEGMENT_SIZE {
        let record = &entry.data[i * SEGMENT_SIZE..(i + 1) * SEGMENT_SIZE];
        let segment_type = be_u32(record, 0)?;
        let load_address = be_u64(record, 12)?;
        let (kind, policy) = match segment_type {
            SEGMENT_CODE => ("CODE", Policy::Program),
            SEGMENT_DATA => ("DATA", Policy::Opaque),
            SEGMENT_BSS => {
                bss += 1;
                continue;
            }
            SEGMENT_PARAMS => continue,
            SEGMENT_ENTRY => {
                entry_point = Some(load_address);
                break;
            }
            _ => {
                return Err(error(format!(
                    "Unknown payload segment type 0x{segment_type:08X} at 0x{:X}",
                    entry.data_offset + i * SEGMENT_SIZE
                )))
            }
        };
        let offset = be_u32(record, 8)? as usize;
        let size = be_u32(record, 20)? as usize;
        let bytes = entry
            .data
            .get(offset..)
            .and_then(|rest| rest.get(..size))
            .ok_or_else(|| {
                error(format!(
                    "Truncated payload {kind} segment at 0x{:X}: {size} B at +0x{offset:X}",
                    entry.data_offset + i * SEGMENT_SIZE
                ))
            })?;
        if bytes.is_empty() {
            continue;
        }
        segments.push(Segment {
            policy,
            stored: Stored {
                label: format!("{} {kind} at 0x{load_address:X}", entry.label()),
                offset: entry.data_offset + offset,
                bytes,
                compression: be_u32(record, 4)?,
                limit: be_u32(record, 24)? as usize,
                exact: false,
            },
        });
    }
    let entry_point = entry_point.ok_or_else(|| error("Missing payload ENTRY segment"))?;
    // cbfstool stores segments one after another. Overlapping segments
    // would hand the same bytes to the classifier more than once.
    let mut ranges: Vec<(usize, usize)> = segments
        .iter()
        .map(|s| (s.stored.offset, s.stored.offset + s.stored.bytes.len()))
        .collect();
    ranges.sort_unstable();
    if let Some(pair) = ranges.windows(2).find(|w| w[1].0 < w[0].1) {
        return Err(error(format!(
            "Invalid payload segments: stored ranges overlap at 0x{:X}",
            pair[1].0
        )));
    }
    notes.push(format!(
        "{}: SELF payload; {} stored segments, {bss} BSS; entry 0x{entry_point:X}",
        entry.label(),
        segments.len()
    ));
    Ok(segments)
}

/// Add the components of one file, after reporting it in the metadata.
fn add_file<'a>(
    c: &mut Container<'a>,
    index: usize,
    entry: &Entry<'a>,
    budget: &mut Budget,
    tally: &mut HashTally,
) {
    let FileCompression {
        algorithm: compression,
        decoded_size,
    } = attribute_compression(entry);
    let codec = match compression {
        COMPRESS_NONE => String::new(),
        COMPRESS_LZMA => format!("; LZMA, {decoded_size} B decoded size declared"),
        COMPRESS_LZ4 => format!("; LZ4, {decoded_size} B decoded size declared"),
        other => format!("; unknown compression {other}"),
    };
    c.push_metadata(
        format!("cbfs_file_{index}"),
        entry.label(),
        format!(
            "{}; file 0x{:X}; {} B{codec}",
            entry.type_name(),
            entry.data_offset,
            entry.data.len()
        ),
    );
    check_hash(entry, tally, &mut c.notes);
    let content = entry.content();
    let stored = match content {
        Content::Empty | Content::MasterHeader => return,
        Content::LegacyStage => legacy_stage(entry, &mut c.notes),
        Content::Stage => stage(entry, &mut c.notes),
        Content::Payload => match payload(entry, &mut c.notes) {
            Ok(segments) => {
                for segment in segments {
                    push_component(c, segment.stored, segment.policy, budget);
                }
                return;
            }
            Err(e) => Err(e),
        },
        Content::Code | Content::Recognized | Content::Data => Ok(Stored {
            label: entry.label(),
            offset: entry.data_offset,
            bytes: entry.data,
            compression,
            limit: decoded_size,
            exact: true,
        }),
    };
    let policy = content.policy();
    match stored {
        Ok(stored) => push_component(c, stored, policy, budget),
        Err(e) => {
            c.notes
                .push(format!("{}: {}; not analyzed", entry.label(), message(e)));
            let child = Child::opaque(entry.label(), entry.data_offset, entry.data);
            push_child(c, child, policy, budget);
        }
    }
}

/// Build the container for the region `data[start..end]`; `master` is a
/// master header already located through the ROM pointer.
fn region_container<'a>(
    data: &'a [u8],
    start: usize,
    end: usize,
    layout: Layout,
    master: Option<(usize, &MasterHeader)>,
) -> Result<Container<'a>> {
    let walk = walk(data, start, end)?;
    let mut c = Container::new(layout.format(), layout.label(), "cbfs");
    c.consumed = data.len();
    c.notes.push(format!(
        "CBFS region at 0x{start:X}, {}: {} files, {} empty entries; 64-byte alignment",
        size_text(end - start),
        walk.files.len() + walk.unlisted,
        walk.empty
    ));
    let mut have_master = master.is_some();
    if let Some((at, header)) = master {
        adopt_master_header(&mut c, header, at);
    }
    let mut budget = Budget::new();
    let mut tally = HashTally::default();
    for (index, entry) in walk.files.iter().enumerate() {
        if entry.content() == Content::MasterHeader && !have_master {
            // Read the header from the file's own data, in file offsets.
            let file_end = entry.data_offset + entry.data.len();
            match master_header(&data[..file_end], entry.data_offset) {
                Ok(header) => {
                    adopt_master_header(&mut c, &header, entry.data_offset);
                    have_master = true;
                }
                Err(e) => c
                    .notes
                    .push(format!("{}: {}; ignored", entry.label(), message(e))),
            }
        }
        add_file(&mut c, index, entry, &mut budget, &mut tally);
    }
    if tally.verified > 0 {
        c.notes.push(format!(
            "{} file hash attributes verified over the stored file data",
            tally.verified
        ));
    }
    if tally.unchecked > 0 {
        c.notes.push(format!(
            "{} file hash attributes not verified (SHA-1 or unknown algorithm)",
            tally.unchecked
        ));
    }
    let unknown_attributes: usize = walk.files.iter().map(|e| e.attributes.unknown).sum();
    if unknown_attributes > 0 {
        c.notes.push(format!(
            "{unknown_attributes} file attributes with unknown tags were not interpreted"
        ));
    }
    if walk.stray > 0 {
        c.notes.push(format!(
            "{} B at 64-byte positions without a file header are not erased flash",
            walk.stray
        ));
    }
    if walk.unlisted > 0 {
        c.notes.push(format!(
            "{} files after the first {MAX_COMPONENTS} were validated but not listed",
            walk.unlisted
        ));
    }
    c.notes.extend(budget.note());
    Ok(c)
}

/// Parse a CBFS region whose first file header is at offset 0.
pub(super) fn parse_region(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    // The walk stops short of a header that does not fit; the header that
    // made the region recognizable must be complete.
    file(data, 0)?;
    region_container(data, 0, data.len(), layout, None)
}

/// Parse a legacy ROM located through its master-header pointer.
pub(super) fn parse_rom(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let Rom {
        header_offset,
        header,
        start,
        end,
    } = rom(data)?;
    let mut c = region_container(data, start, end, layout, Some((header_offset, &header)))?;
    let before = &data[..start];
    if !is_padding(before) {
        c.notes.push(format!(
            "{} B before the CBFS region at 0x{start:X} are not interpreted",
            before.len()
        ));
    }
    // The pointer itself occupies the last four bytes.
    let pointer_at = data.len() - POINTER_SIZE;
    let after = data.get(end..pointer_at).unwrap_or_default();
    if !is_padding(after) {
        c.notes.push(format!(
            "{} B after the CBFS region at 0x{end:X} are not interpreted",
            after.len()
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file header with `name`, optional attribute bytes and data, padded
    /// as cbfstool pads it.
    fn file_bytes(file_type: u32, name: &str, attributes: &[u8], contents: &[u8]) -> Vec<u8> {
        let name_size = align_up(name.len() + 1, 4).expect("short name");
        let attributes_offset = if attributes.is_empty() {
            0
        } else {
            FILE_HEADER_SIZE + name_size
        };
        let data_offset = FILE_HEADER_SIZE + name_size + attributes.len();
        let be32 = |n: usize| u32::try_from(n).expect("test sizes fit").to_be_bytes();
        let mut out = FILE_MAGIC.to_vec();
        out.extend_from_slice(&be32(contents.len()));
        out.extend_from_slice(&file_type.to_be_bytes());
        out.extend_from_slice(&be32(attributes_offset));
        out.extend_from_slice(&be32(data_offset));
        out.extend_from_slice(name.as_bytes());
        out.resize(FILE_HEADER_SIZE + name_size, 0);
        out.extend_from_slice(attributes);
        out.extend_from_slice(contents);
        out
    }

    #[test]
    fn the_walk_skips_empty_entries_and_unaligned_gaps() {
        let mut region = file_bytes(0x50, "a", &[], b"abc");
        region.resize(64, 0xff);
        region.extend(file_bytes(0xffff_ffff, "", &[], &[0xff; 8]));
        region.resize(256, 0xff);
        region.extend(file_bytes(0x50, "b", &[], b"d"));
        region.resize(320, 0xff);
        let walk = walk(&region, 0, region.len()).unwrap();
        let names: Vec<&str> = walk.files.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(walk.empty, 1);
        assert_eq!(walk.stray, 0);
        assert_eq!(walk.files[1].data_offset, 256 + 28);
    }

    #[test]
    fn file_headers_follow_cbfs_walk_limits() {
        let mut bytes = file_bytes(0x50, "a", &[], b"abc");
        bytes[20..24].copy_from_slice(&257u32.to_be_bytes());
        let message = file(&bytes, 0).err().expect("rejected").to_string();
        assert!(
            message.contains("exceeds the 256 B metadata limit"),
            "{message}"
        );

        let mut bytes = file_bytes(0x50, "a", &[], b"abc");
        bytes[16..20].copy_from_slice(&24u32.to_be_bytes());
        assert!(file(&bytes, 0).is_err());

        let bytes = file_bytes(0x50, "a", &[], b"abc");
        assert!(file(&bytes[..bytes.len() - 1], 0).is_err());
    }

    #[test]
    fn attributes_are_read_until_an_unused_tag() {
        let mut attributes = Vec::new();
        attributes.extend_from_slice(&ATTRIBUTE_COMPRESSION.to_be_bytes());
        attributes.extend_from_slice(&16u32.to_be_bytes());
        attributes.extend_from_slice(&COMPRESS_LZ4.to_be_bytes());
        attributes.extend_from_slice(&100u32.to_be_bytes());
        attributes.extend_from_slice(&[0; 8]);
        let bytes = file_bytes(0x50, "a", &attributes, b"x");
        let entry = file(&bytes, 0).expect("valid file");
        let compression = entry.attributes.compression.expect("compression attribute");
        assert_eq!((compression.algorithm, compression.decoded_size), (2, 100));

        let mut short = attributes.clone();
        short[4..8].copy_from_slice(&12u32.to_be_bytes());
        let bytes = file_bytes(0x50, "a", &short, b"x");
        assert!(file(&bytes, 0).is_err());
    }

    #[test]
    fn hash_digests_are_checked_for_the_sha2_family() {
        let digest = Sha256::digest(b"abc").to_vec();
        let hash = HashAttribute {
            algorithm: VB2_HASH_SHA256,
            digest: &digest,
        };
        assert_eq!(digest_matches(&hash, b"abc"), Some(true));
        assert_eq!(digest_matches(&hash, b"abd"), Some(false));
        let sha1 = HashAttribute {
            algorithm: VB2_HASH_SHA1,
            digest: &[0; 20],
        };
        assert_eq!(digest_matches(&sha1, b"abc"), None);
    }

    #[test]
    fn the_rom_pointer_is_a_signed_offset_from_the_end() {
        let mut rom = vec![0xffu8; 128];
        rom[124..].copy_from_slice(&(-64i32).to_le_bytes());
        assert_eq!(pointer_target(&rom).unwrap(), 64);
        rom[124..].copy_from_slice(&(-200i32).to_le_bytes());
        assert!(pointer_target(&rom).is_err());
        rom[124..].copy_from_slice(&0i32.to_le_bytes());
        assert!(pointer_target(&rom).is_err());
    }
}
