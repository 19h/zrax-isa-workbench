//! `update_engine` payloads (`payload.bin`, magic `CrAU`), from
//! `update_metadata.proto` and `payload_consumer/payload_metadata.cc` at
//! `update_engine` `dc84c255`, with major version 1 from `android-10.0.0_r1`.
//!
//! The header is big-endian: magic, u64 major version, u64 manifest size,
//! and for major version 2 a u32 metadata signature size. The manifest is a
//! protobuf `DeltaArchiveManifest`. Operation data offsets are relative to
//! the end of the metadata signature (`blob_start`), and so is the payload
//! signature. Full-payload operations (REPLACE, `REPLACE_BZ`, `REPLACE_XZ`,
//! ZERO, DISCARD) are reassembled into partition images at
//! `dst_extents * block_size`; delta operations need the source partition,
//! so such partitions stay opaque.

use super::*;
use sha2::{Digest, Sha256};

/// Major versions (`kChromeOSMajorPayloadVersion`,
/// `kBrilloMajorPayloadVersion`) and their header sizes.
const MAJOR_CHROMEOS: u64 = 1;
const MAJOR_BRILLO: u64 = 2;
const HEADER_SIZE_CHROMEOS: usize = 20;
const HEADER_SIZE_BRILLO: usize = 24;

/// `DeltaArchiveManifest.block_size` default.
const DEFAULT_BLOCK_SIZE: u64 = 4096;

/// `kSparseHole`: an extent that names no blocks.
const SPARSE_HOLE: u64 = u64::MAX;

/// Protobuf wire types (protobuf.dev encoding guide).
const WIRE_VARINT: u64 = 0;
const WIRE_I64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_SGROUP: u64 = 3;
const WIRE_EGROUP: u64 = 4;
const WIRE_I32: u64 = 5;

/// A varint holds at most ten 7-bit groups.
const MAX_VARINT_BYTES: usize = 10;

/// `DeltaArchiveManifest` fields. 1, 2 and 6-9 are the major version 1
/// operation lists and partition infos (reserved in major version 2).
const MANIFEST_INSTALL_OPERATIONS: u32 = 1;
const MANIFEST_KERNEL_INSTALL_OPERATIONS: u32 = 2;
const MANIFEST_BLOCK_SIZE: u32 = 3;
const MANIFEST_SIGNATURES_OFFSET: u32 = 4;
const MANIFEST_SIGNATURES_SIZE: u32 = 5;
const MANIFEST_OLD_KERNEL_INFO: u32 = 6;
const MANIFEST_NEW_KERNEL_INFO: u32 = 7;
const MANIFEST_OLD_ROOTFS_INFO: u32 = 8;
const MANIFEST_NEW_ROOTFS_INFO: u32 = 9;
const MANIFEST_MINOR_VERSION: u32 = 12;
const MANIFEST_PARTITIONS: u32 = 13;
const MANIFEST_PARTIAL_UPDATE: u32 = 16;
const MANIFEST_SECURITY_PATCH_LEVEL: u32 = 18;

/// `PartitionUpdate` fields.
const PARTITION_NAME: u32 = 1;
const PARTITION_OLD_INFO: u32 = 6;
const PARTITION_NEW_INFO: u32 = 7;
const PARTITION_OPERATIONS: u32 = 8;

/// `PartitionInfo` fields.
const INFO_SIZE: u32 = 1;
const INFO_HASH: u32 = 2;

/// `InstallOperation` fields.
const OPERATION_TYPE: u32 = 1;
const OPERATION_DATA_OFFSET: u32 = 2;
const OPERATION_DATA_LENGTH: u32 = 3;
const OPERATION_DST_EXTENTS: u32 = 6;
const OPERATION_DATA_SHA256: u32 = 8;

/// `Extent` fields.
const EXTENT_START_BLOCK: u32 = 1;
const EXTENT_NUM_BLOCKS: u32 = 2;

/// `InstallOperation.Type` values that produce output without a source
/// partition.
const OP_REPLACE: u64 = 0;
const OP_REPLACE_BZ: u64 = 1;
const OP_ZERO: u64 = 6;
const OP_DISCARD: u64 = 7;
const OP_REPLACE_XZ: u64 = 8;

/// `InstallOperation.Type` names, indexed by value (0-13).
const OPERATION_NAMES: [&str; 14] = [
    "REPLACE",
    "REPLACE_BZ",
    "MOVE",
    "BSDIFF",
    "SOURCE_COPY",
    "SOURCE_BSDIFF",
    "ZERO",
    "DISCARD",
    "REPLACE_XZ",
    "PUFFDIFF",
    "BROTLI_BSDIFF",
    "ZUCCHINI",
    "LZ4DIFF_BSDIFF",
    "LZ4DIFF_PUFFDIFF",
];

/// Major version 1 partition names (`kPartitionNameRoot`,
/// `kPartitionNameKernel`).
const PARTITION_ROOT: &str = "root";
const PARTITION_KERNEL: &str = "kernel";

/// Reassembly transform name for components.
const TRANSFORM: &str = "Android OTA";

/// A protobuf field value.
#[derive(Clone, Copy)]
enum Value<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32,
}

/// One field of a message: its number, value and the file offset of the
/// value (for nested messages and error messages).
struct Field<'a> {
    number: u32,
    value: Value<'a>,
    offset: usize,
}

impl<'a> Field<'a> {
    fn wire_error(&self, what: &str) -> ClassifierError {
        error(format!(
            "Invalid OTA manifest {what} (field {}) at 0x{:X}: unexpected wire type",
            self.number, self.offset
        ))
    }

    fn varint(&self, what: &str) -> Result<u64> {
        match self.value {
            Value::Varint(value) => Ok(value),
            _ => Err(self.wire_error(what)),
        }
    }

    fn bytes(&self, what: &str) -> Result<&'a [u8]> {
        match self.value {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(self.wire_error(what)),
        }
    }

    fn string(&self, what: &str) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes(what)?).into_owned())
    }

    fn message(&self, what: &str) -> Result<Fields<'a>> {
        Ok(Fields::new(self.bytes(what)?, self.offset))
    }
}

/// The fields of one serialized message, in wire order. `base` is the
/// file offset of the message.
struct Fields<'a> {
    message: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Fields<'a> {
    fn new(message: &'a [u8], base: usize) -> Self {
        Self {
            message,
            pos: 0,
            base,
        }
    }

    /// A base-128 varint, least-significant group first.
    fn varint(&mut self) -> Result<u64> {
        let start = self.pos;
        let mut value = 0u64;
        for i in 0..MAX_VARINT_BYTES {
            let Some(&byte) = self.message.get(self.pos) else {
                return Err(error(format!(
                    "Truncated OTA manifest varint at 0x{:X}",
                    self.base + start
                )));
            };
            self.pos += 1;
            let group = u64::from(byte & 0x7f);
            // The tenth byte may only hold the top bit of a 64-bit value.
            if i == MAX_VARINT_BYTES - 1 && group > 1 {
                break;
            }
            value |= group << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(error(format!(
            "Invalid OTA manifest varint at 0x{:X}",
            self.base + start
        )))
    }

    /// The `len` bytes at the current position.
    fn take(&mut self, len: usize, number: u32) -> Result<&'a [u8]> {
        let start = self.pos;
        let bytes = start
            .checked_add(len)
            .and_then(|end| self.message.get(start..end))
            .ok_or_else(|| {
                error(format!(
                    "Truncated OTA manifest field {number} at 0x{:X} + {len} B",
                    self.base + start
                ))
            })?;
        self.pos += len;
        Ok(bytes)
    }

    /// The next field, or `None` at the end of the message.
    fn next_field(&mut self) -> Result<Option<Field<'a>>> {
        if self.pos >= self.message.len() {
            return Ok(None);
        }
        let tag_offset = self.base + self.pos;
        let tag = self.varint()?;
        let number = u32::try_from(tag >> 3)
            .ok()
            .filter(|&n| n != 0)
            .ok_or_else(|| {
                error(format!(
                    "Invalid OTA manifest field number at 0x{tag_offset:X}"
                ))
            })?;
        let offset = self.base + self.pos;
        let value = match tag & 7 {
            WIRE_VARINT => Value::Varint(self.varint()?),
            WIRE_I64 => {
                self.take(8, number)?;
                Value::Fixed64
            }
            WIRE_LEN => {
                let len = usize::try_from(self.varint()?).unwrap_or(usize::MAX);
                let start = self.base + self.pos;
                let bytes = self.take(len, number)?;
                return Ok(Some(Field {
                    number,
                    value: Value::Bytes(bytes),
                    offset: start,
                }));
            }
            WIRE_I32 => {
                self.take(4, number)?;
                Value::Fixed32
            }
            WIRE_SGROUP | WIRE_EGROUP => {
                return Err(error(format!(
                    "Unsupported protobuf group in the OTA manifest at 0x{tag_offset:X}"
                )))
            }
            wire_type => {
                return Err(error(format!(
                    "Invalid protobuf wire type {wire_type} in the OTA manifest at 0x{tag_offset:X}"
                )))
            }
        };
        Ok(Some(Field {
            number,
            value,
            offset,
        }))
    }
}

/// A run of `num_blocks` destination blocks from `start_block`.
struct Extent {
    start_block: u64,
    num_blocks: u64,
}

/// One `InstallOperation`.
struct Operation<'a> {
    kind: u64,
    /// Relative to `blob_start`.
    data_offset: Option<u64>,
    data_length: u64,
    dst_extents: Vec<Extent>,
    data_sha256: Option<&'a [u8]>,
}

/// `PartitionInfo`: size in bytes and SHA-256 of the partition image.
#[derive(Default)]
struct PartitionInfo<'a> {
    size: Option<u64>,
    hash: Option<&'a [u8]>,
}

/// One `PartitionUpdate`.
struct Partition<'a> {
    name: String,
    operations: Vec<Operation<'a>>,
    new_info: PartitionInfo<'a>,
    /// `old_partition_info` is present only in delta payloads.
    has_old_info: bool,
}

impl Partition<'_> {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            operations: Vec::new(),
            new_info: PartitionInfo::default(),
            has_old_info: false,
        }
    }
}

/// The parts of `DeltaArchiveManifest` the classifier uses.
struct Manifest<'a> {
    block_size: u64,
    signatures_offset: u64,
    signatures_size: u64,
    minor_version: u64,
    partitions: Vec<Partition<'a>>,
    partial_update: bool,
    security_patch_level: Option<String>,
}

/// `Extent`: start block (1) and block count (2).
fn extent(mut fields: Fields<'_>) -> Result<Extent> {
    let mut e = Extent {
        start_block: 0,
        num_blocks: 0,
    };
    while let Some(f) = fields.next_field()? {
        match f.number {
            EXTENT_START_BLOCK => e.start_block = f.varint("start_block")?,
            EXTENT_NUM_BLOCKS => e.num_blocks = f.varint("num_blocks")?,
            _ => {}
        }
    }
    Ok(e)
}

/// `InstallOperation`: type (1, required), data offset (2) and length (3),
/// destination extents (6), data SHA-256 (8). Source extents and hashes
/// are not needed: delta operations are not applied.
fn operation(mut fields: Fields<'_>) -> Result<Operation<'_>> {
    let offset = fields.base;
    let mut kind = None;
    let mut op = Operation {
        kind: 0,
        data_offset: None,
        data_length: 0,
        dst_extents: Vec::new(),
        data_sha256: None,
    };
    while let Some(f) = fields.next_field()? {
        match f.number {
            OPERATION_TYPE => kind = Some(f.varint("operation type")?),
            OPERATION_DATA_OFFSET => op.data_offset = Some(f.varint("data_offset")?),
            OPERATION_DATA_LENGTH => op.data_length = f.varint("data_length")?,
            OPERATION_DST_EXTENTS => op.dst_extents.push(extent(f.message("dst_extents")?)?),
            OPERATION_DATA_SHA256 => op.data_sha256 = Some(f.bytes("data_sha256_hash")?),
            _ => {}
        }
    }
    op.kind = kind.ok_or_else(|| {
        error(format!(
            "Missing InstallOperation type in the OTA manifest at 0x{offset:X}"
        ))
    })?;
    Ok(op)
}

/// Merge a `PartitionInfo` message (size 1, hash 2) into `info`; a later
/// occurrence of an embedded message merges into the earlier one.
fn merge_partition_info<'a>(mut fields: Fields<'a>, info: &mut PartitionInfo<'a>) -> Result<()> {
    while let Some(f) = fields.next_field()? {
        match f.number {
            INFO_SIZE => info.size = Some(f.varint("partition size")?),
            INFO_HASH => info.hash = Some(f.bytes("partition hash")?),
            _ => {}
        }
    }
    Ok(())
}

/// `PartitionUpdate`: name (1, required), old (6) and new (7) partition
/// info, operations (8).
fn partition(mut fields: Fields<'_>) -> Result<Partition<'_>> {
    let offset = fields.base;
    let mut name = None;
    let mut p = Partition::new("");
    while let Some(f) = fields.next_field()? {
        match f.number {
            PARTITION_NAME => name = Some(f.string("partition_name")?),
            PARTITION_OLD_INFO => p.has_old_info = true,
            PARTITION_NEW_INFO => {
                merge_partition_info(f.message("new_partition_info")?, &mut p.new_info)?;
            }
            PARTITION_OPERATIONS => p.operations.push(operation(f.message("operations")?)?),
            _ => {}
        }
    }
    p.name = name.ok_or_else(|| {
        error(format!(
            "Missing partition_name in the OTA manifest at 0x{offset:X}"
        ))
    })?;
    Ok(p)
}

/// `DeltaArchiveManifest` at file offset `base`. Major version 1 keeps the
/// root and kernel operations in fields 1 and 2 and their infos in 6-9.
fn manifest(message: &[u8], base: usize, major: u64) -> Result<Manifest<'_>> {
    let mut fields = Fields::new(message, base);
    let mut m = Manifest {
        block_size: DEFAULT_BLOCK_SIZE,
        signatures_offset: 0,
        signatures_size: 0,
        minor_version: 0,
        partitions: Vec::new(),
        partial_update: false,
        security_patch_level: None,
    };
    let mut root = Partition::new(PARTITION_ROOT);
    let mut kernel = Partition::new(PARTITION_KERNEL);
    let chromeos = major == MAJOR_CHROMEOS;
    while let Some(f) = fields.next_field()? {
        match f.number {
            MANIFEST_BLOCK_SIZE => m.block_size = f.varint("block_size")?,
            MANIFEST_SIGNATURES_OFFSET => m.signatures_offset = f.varint("signatures_offset")?,
            MANIFEST_SIGNATURES_SIZE => m.signatures_size = f.varint("signatures_size")?,
            MANIFEST_MINOR_VERSION => m.minor_version = f.varint("minor_version")?,
            MANIFEST_PARTITIONS => m.partitions.push(partition(f.message("partitions")?)?),
            MANIFEST_PARTIAL_UPDATE => m.partial_update = f.varint("partial_update")? != 0,
            MANIFEST_SECURITY_PATCH_LEVEL => {
                m.security_patch_level = Some(f.string("security_patch_level")?);
            }
            MANIFEST_INSTALL_OPERATIONS if chromeos => {
                root.operations
                    .push(operation(f.message("install_operations")?)?);
            }
            MANIFEST_KERNEL_INSTALL_OPERATIONS if chromeos => kernel
                .operations
                .push(operation(f.message("kernel_install_operations")?)?),
            MANIFEST_OLD_KERNEL_INFO if chromeos => kernel.has_old_info = true,
            MANIFEST_OLD_ROOTFS_INFO if chromeos => root.has_old_info = true,
            MANIFEST_NEW_KERNEL_INFO if chromeos => {
                merge_partition_info(f.message("new_kernel_info")?, &mut kernel.new_info)?;
            }
            MANIFEST_NEW_ROOTFS_INFO if chromeos => {
                merge_partition_info(f.message("new_rootfs_info")?, &mut root.new_info)?;
            }
            _ => {}
        }
    }
    if m.block_size == 0 {
        return Err(error("Invalid OTA manifest block_size 0"));
    }
    for p in [root, kernel] {
        if !p.operations.is_empty() || p.new_info.size.is_some() {
            m.partitions.push(p);
        }
    }
    Ok(m)
}

/// The name of an operation type.
fn operation_name(kind: u64) -> String {
    usize::try_from(kind)
        .ok()
        .and_then(|i| OPERATION_NAMES.get(i))
        .map_or_else(|| format!("type {kind}"), |name| (*name).to_string())
}

/// Operations that need no source partition.
fn is_full_operation(kind: u64) -> bool {
    matches!(
        kind,
        OP_REPLACE | OP_REPLACE_BZ | OP_REPLACE_XZ | OP_ZERO | OP_DISCARD
    )
}

/// Operation types the schema defines (0 to 13).
fn is_known_operation(kind: u64) -> bool {
    usize::try_from(kind).is_ok_and(|i| i < OPERATION_NAMES.len())
}

/// Operations that carry a data blob.
fn has_blob(kind: u64) -> bool {
    matches!(kind, OP_REPLACE | OP_REPLACE_BZ | OP_REPLACE_XZ)
}

/// The codec of a compressed REPLACE operation's blob.
fn operation_codec(kind: u64) -> Option<Codec> {
    match kind {
        OP_REPLACE_BZ => Some(Codec::Bzip2),
        OP_REPLACE_XZ => Some(Codec::Xz),
        _ => None,
    }
}

/// Bytes of target memory an extent list covers, or `None` on overflow.
fn extents_size(extents: &[Extent], block_size: u64) -> Option<u64> {
    extents.iter().try_fold(0u64, |total, e| {
        e.num_blocks
            .checked_mul(block_size)
            .and_then(|size| total.checked_add(size))
    })
}

/// The end of the last destination extent in bytes, or `None` on overflow.
fn extents_end(extents: &[Extent], block_size: u64) -> Option<u64> {
    extents
        .iter()
        .filter(|e| e.start_block != SPARSE_HOLE)
        .try_fold(0u64, |end, e| {
            let extent_end = e
                .start_block
                .checked_add(e.num_blocks)?
                .checked_mul(block_size)?;
            Some(end.max(extent_end))
        })
}

/// The start of the first destination extent in bytes, or `None` when the
/// operation writes nothing (only sparse holes) or the start overflows.
fn extents_start(extents: &[Extent], block_size: u64) -> Option<u64> {
    extents
        .iter()
        .filter(|e| e.start_block != SPARSE_HOLE && e.num_blocks > 0)
        .map(|e| e.start_block.checked_mul(block_size))
        .try_fold(u64::MAX, |start, extent_start| {
            Some(start.min(extent_start?))
        })
        .filter(|&start| start != u64::MAX)
}

/// Limits shared by the partitions of one payload: bytes of partition
/// images allocated, and bytes written into them (operations may write the
/// same blocks repeatedly).
struct Limits {
    budget: Budget,
    writes: usize,
}

/// A reassembled partition image, or why it was not reassembled.
enum Reassembly {
    Image {
        data: Vec<u8>,
        /// The partition's full size; `data` is shorter when capped.
        full_size: u64,
        /// Operations whose data SHA-256 matched.
        hashes_verified: usize,
        /// Operations that write only beyond the extracted prefix.
        beyond_limit: usize,
    },
    Opaque(String),
}

/// Write `bytes` and then zeros up to `len` bytes at byte `start`, keeping
/// only what falls inside `image`. Returns the bytes written.
fn write_clipped(image: &mut [u8], start: u64, len: u64, bytes: &[u8]) -> usize {
    let Ok(start) = usize::try_from(start) else {
        return 0;
    };
    if start >= image.len() {
        return 0;
    }
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let room = (image.len() - start).min(len);
    let out = &mut image[start..start + room];
    let copied = bytes.len().min(room);
    out[..copied].copy_from_slice(&bytes[..copied]);
    out[copied..].fill(0);
    room
}

/// Apply one full-payload operation to `image`. The data blob is decoded
/// for `REPLACE_BZ` and `REPLACE_XZ`, then spread over the destination
/// extents in order and zero-padded; ZERO and DISCARD write zeros.
/// `writes` is the number of bytes the payload may still write.
fn apply(
    index: usize,
    op: &Operation<'_>,
    blob: &[u8],
    image: &mut [u8],
    block_size: u64,
    writes: &mut usize,
) -> std::result::Result<(), String> {
    let size = extents_size(&op.dst_extents, block_size)
        .ok_or_else(|| format!("operation {index} has overflowing extents"))?;
    let content: Cow<'_, [u8]> = match operation_codec(op.kind) {
        Some(codec) => {
            let limit = usize::try_from(size).unwrap_or(usize::MAX).min(MAX_PAYLOAD);
            let decoded = compressed::decode_limited(codec, blob, limit).map_err(|e| {
                format!(
                    "operation {index} ({}) does not decode: {e}",
                    operation_name(op.kind)
                )
            })?;
            Cow::Owned(decoded.data)
        }
        None if op.kind == OP_REPLACE => Cow::Borrowed(blob),
        None => Cow::Borrowed(&[]),
    };
    if content.len() as u64 > size {
        return Err(format!(
            "operation {index} has {} B of data for {size} B of extents",
            content.len()
        ));
    }
    let mut rest: &[u8] = &content;
    for e in &op.dst_extents {
        // Each product fits: `extents_size` summed them without overflow.
        let len = e.num_blocks.saturating_mul(block_size);
        let take = rest.len().min(usize::try_from(len).unwrap_or(usize::MAX));
        let (bytes, after) = rest.split_at(take);
        rest = after;
        let Some(start) = e.start_block.checked_mul(block_size) else {
            continue;
        };
        if e.start_block == SPARSE_HOLE {
            continue;
        }
        let written = write_clipped(image, start, len, bytes);
        *writes = writes
            .checked_sub(written)
            .ok_or_else(|| format!("operation {index} exceeds the write limit"))?;
    }
    Ok(())
}

/// Why a partition holds operations that cannot be applied without more
/// than the payload: delta operations need the source partition, and
/// unknown types have no defined effect.
fn unsupported_operations(partition: &Partition<'_>) -> Option<String> {
    let mut delta: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for op in &partition.operations {
        if is_full_operation(op.kind) {
            continue;
        }
        let list = if is_known_operation(op.kind) {
            &mut delta
        } else {
            &mut unknown
        };
        let name = operation_name(op.kind);
        if !list.contains(&name) {
            list.push(name);
        }
    }
    let mut reasons = Vec::new();
    if !delta.is_empty() {
        reasons.push(format!(
            "delta operations ({}) need the source partition",
            delta.join(", ")
        ));
    }
    if !unknown.is_empty() {
        reasons.push(format!("unknown operations ({})", unknown.join(", ")));
    }
    (!reasons.is_empty()).then(|| {
        format!(
            "{}: {}; not reassembled",
            partition.name,
            reasons.join("; ")
        )
    })
}

/// Reassemble a full-payload partition image from its operations, cut at
/// [`MAX_PAYLOAD`] and the remaining extraction budget. Operations that
/// write only beyond the cut are not decoded.
fn reassemble(
    partition: &Partition<'_>,
    blobs: &[&[u8]],
    block_size: u64,
    limits: &mut Limits,
) -> Reassembly {
    if let Some(reason) = unsupported_operations(partition) {
        return Reassembly::Opaque(reason);
    }
    let extent_end = partition.operations.iter().try_fold(0u64, |end, op| {
        Some(end.max(extents_end(&op.dst_extents, block_size)?))
    });
    let Some(extent_end) = extent_end else {
        return Reassembly::Opaque(format!(
            "{}: destination extents overflow; not reassembled",
            partition.name
        ));
    };
    let full_size = partition.new_info.size.unwrap_or(0).max(extent_end);
    let limit = limits.budget.limit();
    if limit == 0 && full_size > 0 {
        return Reassembly::Opaque(format!(
            "{}: not reassembled; the extraction limit of {} was reached",
            partition.name,
            size_text(MAX_EXTRACTED)
        ));
    }
    let size = usize::try_from(full_size).map_or(limit, |size| size.min(limit));
    let mut image = vec![0u8; size];
    limits.budget.spend(size);
    let mut hashes_verified = 0;
    let mut beyond_limit = 0;
    for (i, (op, blob)) in partition.operations.iter().zip(blobs).enumerate() {
        if let Some(expected) = op.data_sha256 {
            if Sha256::digest(blob).as_slice() != expected {
                return Reassembly::Opaque(format!(
                    "{}: operation {i} data SHA-256 does not match; not reassembled",
                    partition.name
                ));
            }
            hashes_verified += 1;
        }
        let writes_inside = extents_start(&op.dst_extents, block_size)
            .is_some_and(|start| start < image.len() as u64);
        if !writes_inside {
            beyond_limit += usize::from(!op.dst_extents.is_empty());
            continue;
        }
        if let Err(reason) = apply(i, op, blob, &mut image, block_size, &mut limits.writes) {
            return Reassembly::Opaque(format!("{}: {reason}; not reassembled", partition.name));
        }
    }
    Reassembly::Image {
        data: image,
        full_size,
        hashes_verified,
        beyond_limit,
    }
}

/// The stored data of one operation.
struct Blob<'a> {
    /// File offset of the data; `blob_start` for an operation without data.
    offset: usize,
    /// The stored bytes, possibly compressed.
    bytes: &'a [u8],
}

/// The file offset and stored bytes an operation's data occupies, checked
/// against the file and the payload signature.
fn operation_blob<'a>(
    data: &'a [u8],
    blob_start: usize,
    manifest: &Manifest<'_>,
    partition: &str,
    index: usize,
    op: &Operation<'_>,
) -> Result<Blob<'a>> {
    if op.data_length == 0 {
        return Ok(Blob {
            offset: blob_start,
            bytes: &[],
        });
    }
    let offset = op.data_offset.ok_or_else(|| {
        error(format!(
            "Missing data_offset for OTA partition {partition} operation {index}"
        ))
    })?;
    if manifest.signatures_size > 0
        && offset.saturating_add(op.data_length) > manifest.signatures_offset
    {
        return Err(error(format!(
            "Invalid OTA operation data for partition {partition} operation {index}: overlaps the payload signature"
        )));
    }
    let start = (blob_start as u64).checked_add(offset).ok_or_else(|| {
        error(format!(
            "Invalid OTA data_offset for partition {partition} operation {index}"
        ))
    })?;
    let what = format!("OTA data for partition {partition} operation {index}");
    let bytes = slice64(data, start, op.data_length, &what)?;
    Ok(Blob {
        offset: usize::try_from(start).expect("blob lies in the file"),
        bytes,
    })
}

/// Parse an update payload: header, manifest, signatures, then one
/// component per partition.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, HEADER_SIZE_CHROMEOS, "OTA payload header")?;
    if !data.starts_with(OTA_MAGIC) {
        return Err(error("Missing OTA payload magic"));
    }
    let major = be_u64(data, 4)?;
    let header_size = match major {
        MAJOR_CHROMEOS => HEADER_SIZE_CHROMEOS,
        MAJOR_BRILLO => HEADER_SIZE_BRILLO,
        _ => {
            return Err(error(format!(
                "Unsupported OTA payload major version {major}"
            )))
        }
    };
    slice(data, 0, header_size, "OTA payload header")?;
    let manifest_size = be_u64(data, 12)?;
    let metadata_signature_size = if major == MAJOR_BRILLO {
        be_u32(data, 20)? as usize
    } else {
        0
    };
    let manifest_bytes = slice64(data, header_size as u64, manifest_size, "OTA manifest")?;
    let metadata_size = header_size + manifest_bytes.len();
    slice(
        data,
        metadata_size,
        metadata_signature_size,
        "OTA metadata signature",
    )?;
    let blob_start = metadata_size + metadata_signature_size;
    let manifest = manifest(manifest_bytes, header_size, major)?;

    let mut payload_end = blob_start;
    let signature = if manifest.signatures_size > 0 {
        let start = (blob_start as u64)
            .checked_add(manifest.signatures_offset)
            .ok_or_else(|| error("Invalid OTA signatures_offset"))?;
        let bytes = slice64(
            data,
            start,
            manifest.signatures_size,
            "OTA payload signature",
        )?;
        let start = usize::try_from(start).expect("signature lies in the file");
        payload_end = payload_end.max(start + bytes.len());
        Some(start)
    } else {
        None
    };
    // Every operation's data range is checked before anything is decoded.
    let mut blobs = Vec::with_capacity(manifest.partitions.len());
    for p in &manifest.partitions {
        let mut ranges = Vec::with_capacity(p.operations.len());
        for (i, op) in p.operations.iter().enumerate() {
            let blob = operation_blob(data, blob_start, &manifest, &p.name, i, op)?;
            if has_blob(op.kind) || !blob.bytes.is_empty() {
                payload_end = payload_end.max(blob.offset + blob.bytes.len());
            }
            ranges.push(blob);
        }
        blobs.push(ranges);
    }
    let trailing = &data[payload_end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the OTA payload at 0x{payload_end:X}",
            size_text(trailing.len())
        )));
    }

    let mut c = Container::new(
        FileFormat::AndroidOta,
        format!(
            "OTA payload v{major} ({})",
            if manifest.minor_version == 0 {
                "full"
            } else {
                "delta"
            }
        ),
        KEY_PREFIX,
    );
    c.consumed = payload_end;
    c.notes.push(format!(
        "Android OTA payload, major version {major}; manifest {} B",
        manifest_bytes.len()
    ));
    c.notes.push(if metadata_signature_size > 0 {
        format!("Metadata signature: {metadata_signature_size} B; not verified")
    } else {
        "No metadata signature".into()
    });
    c.notes.push(format!(
        "{} payload (minor version {}){}; block size {} B; {} partitions",
        if manifest.minor_version == 0 {
            "Full"
        } else {
            "Delta"
        },
        manifest.minor_version,
        if manifest.partial_update {
            "; partial update"
        } else {
            ""
        },
        manifest.block_size,
        manifest.partitions.len()
    ));
    c.notes.push(match signature {
        Some(offset) => format!(
            "Payload signature: {} B at 0x{offset:X}; not verified",
            manifest.signatures_size
        ),
        None => "Payload is unsigned (no signature blob)".into(),
    });
    if let Some(level) = &manifest.security_patch_level {
        c.notes.push(format!("Security patch level: {level}"));
    }
    c.notes.push(
        "The manifest names partitions, not a CPU; reassembled partition images are classified on their own"
            .into(),
    );
    c.push_metadata("android_ota_major_version", "Major version", major);
    c.push_metadata(
        "android_ota_minor_version",
        "Minor version",
        manifest.minor_version,
    );
    c.push_metadata(
        "android_ota_block_size",
        "Block size (B)",
        manifest.block_size,
    );
    c.push_metadata(
        "android_ota_manifest_size",
        "Manifest size (B)",
        manifest_bytes.len() as u64,
    );

    let mut limits = Limits {
        budget: Budget::new(),
        writes: MAX_EXTRACTED,
    };
    for (p, ranges) in manifest.partitions.iter().zip(&blobs) {
        if is_component_limit(c.children.len(), manifest.partitions.len(), &mut c.notes) {
            break;
        }
        let stored_start = ranges
            .iter()
            .filter(|blob| !blob.bytes.is_empty())
            .map(|blob| blob.offset)
            .min()
            .unwrap_or(blob_start);
        let stored_end = ranges
            .iter()
            .map(|blob| blob.offset + blob.bytes.len())
            .max()
            .unwrap_or(blob_start)
            .max(stored_start);
        let stored = &data[stored_start..stored_end];
        let blob_bytes: Vec<&[u8]> = ranges.iter().map(|blob| blob.bytes).collect();
        match reassemble(p, &blob_bytes, manifest.block_size, &mut limits) {
            Reassembly::Image {
                data: image,
                full_size,
                hashes_verified,
                beyond_limit,
            } => {
                c.notes.push(partition_note(
                    p,
                    &image,
                    full_size,
                    hashes_verified,
                    beyond_limit,
                ));
                c.children.push(Child::decoded(
                    p.name.clone(),
                    stored_start,
                    stored.len(),
                    Cow::Owned(image),
                    TRANSFORM,
                ));
            }
            Reassembly::Opaque(reason) => {
                c.notes.push(reason);
                c.children
                    .push(Child::opaque(p.name.clone(), stored_start, stored));
            }
        }
    }
    Ok(c)
}

/// What was reassembled and checked for one partition.
fn partition_note(
    p: &Partition<'_>,
    image: &[u8],
    full_size: u64,
    hashes_verified: usize,
    beyond_limit: usize,
) -> String {
    let mut parts = vec![format!(
        "{}: reassembled {} B from {} operations",
        p.name,
        image.len(),
        p.operations.len()
    )];
    if hashes_verified > 0 {
        parts.push(format!(
            "operation data SHA-256 verified for {hashes_verified}"
        ));
    }
    let complete = image.len() as u64 == full_size;
    if !complete {
        parts.push(format!(
            "{full_size} B partition cut at the extraction limit; {beyond_limit} operations beyond it not applied"
        ));
    }
    match (p.new_info.hash, p.new_info.size) {
        (Some(hash), Some(size)) if complete && size == full_size => {
            if Sha256::digest(image).as_slice() == hash {
                parts.push("partition SHA-256 verified".into());
            } else {
                parts.push("partition SHA-256 does not match the reassembled image".into());
            }
        }
        (Some(_), _) => parts.push("partition SHA-256 not verified".into()),
        (None, _) => {}
    }
    if p.has_old_info {
        parts.push("old partition info present".into());
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_decode_and_reject_overlong_encodings() {
        let mut fields = Fields::new(&[0x96, 0x01, 0x7f], 0);
        assert_eq!(fields.varint().unwrap(), 150);
        assert_eq!(fields.varint().unwrap(), 127);
        assert!(fields.varint().is_err(), "end of message");
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(Fields::new(&max, 0).varint().unwrap(), u64::MAX);
        let overlong = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert!(Fields::new(&overlong, 0).varint().is_err());
        let eleven = [0x80; 11];
        assert!(Fields::new(&eleven, 0).varint().is_err());
    }

    #[test]
    fn fields_bound_lengths_and_reject_groups() {
        // Field 1 LEN of 2 bytes, then field 2 varint 5.
        let mut fields = Fields::new(&[0x0a, 0x02, b'h', b'i', 0x10, 0x05], 0x18);
        let first = fields.next_field().unwrap().unwrap();
        assert_eq!(
            (first.number, first.bytes("name").unwrap(), first.offset),
            (1, &b"hi"[..], 0x1a)
        );
        let second = fields.next_field().unwrap().unwrap();
        assert_eq!((second.number, second.varint("n").unwrap()), (2, 5));
        assert!(second.bytes("n").is_err(), "wire type mismatch");
        assert!(fields.next_field().unwrap().is_none());
        assert!(Fields::new(&[0x0a, 0x05, 0], 0).next_field().is_err());
        assert!(Fields::new(&[0x0b], 0).next_field().is_err(), "group");
        assert!(Fields::new(&[0x0e], 0).next_field().is_err(), "wire type 6");
        assert!(Fields::new(&[0x00], 0).next_field().is_err(), "field 0");
    }

    #[test]
    fn writes_are_clipped_to_the_image_and_zero_padded() {
        let mut image = [0xaau8; 8];
        assert_eq!(write_clipped(&mut image, 2, 4, b"xy"), 4);
        assert_eq!(&image, b"\xaa\xaaxy\0\0\xaa\xaa");
        assert_eq!(write_clipped(&mut image, 6, 100, b"abc"), 2);
        assert_eq!(&image[6..], b"ab");
        assert_eq!(write_clipped(&mut image, 8, 4, b"z"), 0);
        assert_eq!(write_clipped(&mut image, u64::MAX, 4, b"z"), 0);
    }
}
