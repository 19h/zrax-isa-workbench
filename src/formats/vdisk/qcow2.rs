//! QEMU QCOW2 images, versions 2 and 3 (QEMU `v11.1.1`
//! `docs/interop/qcow2.rst`: "Header", "Header extensions", "Cluster
//! mapping", "Extended L2 Entries"; reserved-bit masks and the cluster size
//! limit from `block/qcow2.h`).
//!
//! Every field is big-endian. The guest disk is mapped through a two-level
//! table: L1 entries point to L2 tables of one cluster each, and L2 entries
//! describe guest clusters (stored, compressed, zero or unallocated).
//! Unallocated clusters belong to the backing file when there is one.
//! Refcounts, snapshots and bitmaps describe host clusters and are not
//! needed to read the active guest disk; only their table bounds are
//! checked.

use super::*;

/// `QFI\xfb`.
const QCOW_MAGIC: [u8; 4] = *b"QFI\xfb";

/// The version 2 header ends at 72; a version 3 header is at least 104
/// bytes and a multiple of 8.
const V2_HEADER_SIZE: usize = 72;
const V3_MIN_HEADER_SIZE: usize = 104;
const HEADER_ALIGN: usize = 8;

/// `compression_type`, present when `header_length` exceeds 104.
const COMPRESSION_TYPE_OFFSET: usize = 104;
const COMPRESSION_DEFLATE: u8 = 0;
const COMPRESSION_ZSTD: u8 = 1;

/// Cluster sizes: at least 512 B by the specification, at most 2 MiB as
/// QEMU implements (`MIN_CLUSTER_BITS`, `MAX_CLUSTER_BITS`). Extended L2
/// entries need at least 16 KiB clusters.
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;
const MIN_EXTENDED_L2_CLUSTER_BITS: u32 = 14;

/// `crypt_method` values.
const CRYPT_NONE: u32 = 0;
const CRYPT_AES: u32 = 1;
const CRYPT_LUKS: u32 = 2;

/// Incompatible feature bits; an implementation must refuse unknown ones.
const INCOMPAT_DIRTY: u64 = 1 << 0;
const INCOMPAT_CORRUPT: u64 = 1 << 1;
const INCOMPAT_DATA_FILE: u64 = 1 << 2;
const INCOMPAT_COMPRESSION: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
const INCOMPAT_KNOWN: u64 = INCOMPAT_DIRTY
    | INCOMPAT_CORRUPT
    | INCOMPAT_DATA_FILE
    | INCOMPAT_COMPRESSION
    | INCOMPAT_EXTENDED_L2;

/// Compatible feature bit 0: lazy refcounts.
const COMPAT_LAZY_REFCOUNTS: u64 = 1 << 0;

/// Auto-clear feature bit 1: the external data file is a raw image.
const AUTOCLEAR_RAW_DATA_FILE: u64 = 1 << 1;

/// `refcount_order` may not exceed 6 (64-bit refcounts).
const MAX_REFCOUNT_ORDER: u32 = 6;

/// Longest backing file name.
const MAX_BACKING_NAME: u32 = 1023;

/// Header extension types.
const EXT_END: u32 = 0;
const EXT_BACKING_FORMAT: u32 = 0xe279_2aca;
const EXT_FULL_DISK_ENCRYPTION: u32 = 0x0537_be77;
const EXT_DATA_FILE: u32 = 0x4441_5441;

/// Header extension type and length fields.
const EXT_HEADER_SIZE: usize = 8;

/// L1 entry: L2 table offset and reserved bits (`L1E_OFFSET_MASK`,
/// `L1E_RESERVED_MASK`).
const L1E_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L1E_RESERVED_MASK: u64 = 0x7f00_0000_0000_01ff;

/// L2 entry flags and the standard descriptor's offset and reserved bits
/// (`L2E_OFFSET_MASK`, `L2E_STD_RESERVED_MASK`).
const L2E_COMPRESSED: u64 = 1 << 62;
const L2E_ZERO: u64 = 1 << 0;
const L2E_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2E_STD_RESERVED_MASK: u64 = 0x3f00_0000_0000_01fe;

/// Compressed descriptors count additional 512-byte sectors.
const COMPRESSED_SECTOR_SIZE: u64 = 512;

/// Table entries are 8 bytes; extended L2 entries are 16.
const ENTRY_SIZE: u64 = 8;
const EXTENDED_ENTRY_SIZE: u64 = 16;

/// Subclusters of an extended L2 entry, and the halves of its bitmap.
const SUBCLUSTERS: u32 = 32;
const SUBCLUSTER_MASK: u64 = 0xffff_ffff;

/// Codecs of the two compression types. Deflate clusters have no zlib
/// header.
const DEFLATE_CODECS: &[Codec] = &[Codec::Deflate];
const ZSTD_CODECS: &[Codec] = &[Codec::Zstd];

const TRANSFORM: &str = "QCOW2 clusters";

/// Is this a QCOW2 header: the magic and version 2 or 3?
pub(super) fn is_present(data: &[u8]) -> bool {
    data.starts_with(&QCOW_MAGIC) && matches!(be_u32(data, 4), Ok(2 | 3))
}

/// The header fields this parser uses.
struct Header {
    version: u32,
    backing_file_offset: u64,
    backing_file_size: u32,
    cluster_bits: u32,
    /// Virtual disk size in bytes.
    size: u64,
    crypt_method: u32,
    l1_size: u32,
    l1_table_offset: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    nb_snapshots: u32,
    incompatible: u64,
    compatible: u64,
    autoclear: u64,
    /// Bytes of the header structure, where the extensions start.
    length: usize,
    compression_type: u8,
}

impl Header {
    fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    fn has_extended_l2(&self) -> bool {
        self.incompatible & INCOMPAT_EXTENDED_L2 != 0
    }

    /// L2 entries per table.
    fn l2_entries(&self) -> u64 {
        let entry_size = if self.has_extended_l2() {
            EXTENDED_ENTRY_SIZE
        } else {
            ENTRY_SIZE
        };
        self.cluster_size() / entry_size
    }
}

/// Header: magic, version, backing file offset (8) and size (4), cluster
/// bits, virtual size (8), crypt method, L1 size, L1 offset (8), refcount
/// table offset (8) and clusters, snapshot count and offset (8); version 3
/// adds incompatible, compatible and auto-clear features (8 each),
/// refcount order, header length and the compression type at 104.
fn header(data: &[u8]) -> Result<Header> {
    let fixed = slice(data, 0, V2_HEADER_SIZE, "QCOW2 header")?;
    if fixed[..4] != QCOW_MAGIC {
        return Err(error("Missing QCOW2 magic"));
    }
    let version = be_u32(fixed, 4)?;
    if !matches!(version, 2 | 3) {
        return Err(error(format!("Unsupported QCOW2 version {version}")));
    }
    let cluster_bits = be_u32(fixed, 20)?;
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(error(format!(
            "Unsupported QCOW2 cluster_bits {cluster_bits}"
        )));
    }
    let crypt_method = be_u32(fixed, 32)?;
    if crypt_method > CRYPT_LUKS {
        return Err(error(format!("Unknown QCOW2 crypt_method {crypt_method}")));
    }
    let mut h = Header {
        version,
        backing_file_offset: be_u64(fixed, 8)?,
        backing_file_size: be_u32(fixed, 16)?,
        cluster_bits,
        size: be_u64(fixed, 24)?,
        crypt_method,
        l1_size: be_u32(fixed, 36)?,
        l1_table_offset: be_u64(fixed, 40)?,
        refcount_table_offset: be_u64(fixed, 48)?,
        refcount_table_clusters: be_u32(fixed, 56)?,
        nb_snapshots: be_u32(fixed, 60)?,
        incompatible: 0,
        compatible: 0,
        autoclear: 0,
        length: V2_HEADER_SIZE,
        compression_type: COMPRESSION_DEFLATE,
    };
    if version == 2 {
        return Ok(h);
    }
    let v3 = slice(data, 0, V3_MIN_HEADER_SIZE, "QCOW2 version 3 header")?;
    h.incompatible = be_u64(v3, 72)?;
    h.compatible = be_u64(v3, 80)?;
    h.autoclear = be_u64(v3, 88)?;
    let refcount_order = be_u32(v3, 96)?;
    if refcount_order > MAX_REFCOUNT_ORDER {
        return Err(error(format!(
            "Invalid QCOW2 refcount_order {refcount_order}"
        )));
    }
    let header_length = be_u32(v3, 100)? as usize;
    if header_length < V3_MIN_HEADER_SIZE
        || header_length % HEADER_ALIGN != 0
        || header_length as u64 > h.cluster_size()
    {
        return Err(error(format!(
            "Invalid QCOW2 header_length {header_length}"
        )));
    }
    h.length = header_length;
    let unknown = h.incompatible & !INCOMPAT_KNOWN;
    if unknown != 0 {
        return Err(error(format!(
            "Unsupported QCOW2 incompatible features 0x{unknown:X}"
        )));
    }
    if header_length > COMPRESSION_TYPE_OFFSET {
        h.compression_type = slice(data, COMPRESSION_TYPE_OFFSET, 1, "QCOW2 header")?[0];
    }
    let named = h.incompatible & INCOMPAT_COMPRESSION != 0;
    match (named, h.compression_type) {
        (false, COMPRESSION_DEFLATE) | (true, COMPRESSION_ZSTD) => {}
        (true, COMPRESSION_DEFLATE) => {
            return Err(error(
                "Invalid QCOW2 header: the compression type bit is set with compression type 0",
            ));
        }
        (false, kind) => {
            return Err(error(format!(
                "Invalid QCOW2 compression type {kind} without the compression type bit"
            )));
        }
        (true, kind) => {
            return Err(error(format!("Unsupported QCOW2 compression type {kind}")));
        }
    }
    if h.has_extended_l2() && cluster_bits < MIN_EXTENDED_L2_CLUSTER_BITS {
        return Err(error(format!(
            "Invalid QCOW2 header: extended L2 entries need 16 KiB clusters, not {}",
            size_text(h.cluster_size())
        )));
    }
    Ok(h)
}

/// What the header extensions name.
#[derive(Debug, Default)]
struct Extensions {
    backing_format: Option<String>,
    data_file: Option<String>,
    /// The LUKS header's offset, when a full disk encryption pointer is
    /// present.
    encryption_header: Option<u64>,
}

/// Walk the header extensions from the end of the header to the end of
/// the first cluster: type (4), length (4), data padded to 8 bytes, until
/// the end type.
fn extensions(data: &[u8], h: &Header) -> Result<Extensions> {
    let mut found = Extensions::default();
    let end = usize::try_from(h.cluster_size()).expect("clusters are at most 2 MiB");
    let mut pos = h.length;
    while pos + EXT_HEADER_SIZE <= end {
        let kind = be_u32(
            slice(data, pos, EXT_HEADER_SIZE, "QCOW2 header extension")?,
            0,
        )?;
        if kind == EXT_END {
            break;
        }
        let length = be_u32(data, pos + 4)? as usize;
        let body = slice(
            data,
            pos + EXT_HEADER_SIZE,
            length,
            "QCOW2 header extension",
        )?;
        if pos + EXT_HEADER_SIZE + length > end {
            return Err(error(format!(
                "Invalid QCOW2 header extension 0x{kind:08X} at 0x{pos:X}: it runs past the \
                 first cluster"
            )));
        }
        match kind {
            EXT_BACKING_FORMAT => found.backing_format = Some(byte_text(body)),
            EXT_DATA_FILE => found.data_file = Some(byte_text(body)),
            EXT_FULL_DISK_ENCRYPTION => found.encryption_header = Some(be_u64(body, 0)?),
            _ => {}
        }
        pos += EXT_HEADER_SIZE + padded_extension(length);
    }
    Ok(found)
}

/// An extension's data length rounded up to the 8-byte alignment.
fn padded_extension(length: usize) -> usize {
    (length / HEADER_ALIGN + usize::from(length % HEADER_ALIGN != 0)) * HEADER_ALIGN
}

/// The backing file name: `backing_file_size` bytes at
/// `backing_file_offset`, not NUL-terminated.
fn backing_name(data: &[u8], h: &Header) -> Result<Option<String>> {
    if h.backing_file_offset == 0 {
        return Ok(None);
    }
    if h.backing_file_size > MAX_BACKING_NAME {
        return Err(error(format!(
            "Invalid QCOW2 backing file name size {} B",
            h.backing_file_size
        )));
    }
    let name = range(
        data,
        h.backing_file_offset,
        u64::from(h.backing_file_size),
        "QCOW2 backing file name",
    )?;
    Ok(Some(byte_text(name)))
}

/// The L1 and refcount tables must lie in the file at cluster-aligned
/// offsets, and the L1 table must cover the virtual disk (QEMU refuses an
/// image whose L1 table is too small).
fn check_tables(data: &[u8], h: &Header) -> Result<()> {
    let cluster_size = h.cluster_size();
    for (offset, name) in [
        (h.l1_table_offset, "L1 table"),
        (h.refcount_table_offset, "refcount table"),
    ] {
        if offset % cluster_size != 0 {
            return Err(error(format!(
                "Invalid QCOW2 {name} offset 0x{offset:X}: not cluster-aligned"
            )));
        }
    }
    range(
        data,
        h.l1_table_offset,
        u64::from(h.l1_size) * ENTRY_SIZE,
        "QCOW2 L1 table",
    )?;
    range(
        data,
        h.refcount_table_offset,
        u64::from(h.refcount_table_clusters) * cluster_size,
        "QCOW2 refcount table",
    )?;
    let l1_coverage = cluster_size * h.l2_entries();
    let needed = div_ceil(h.size, l1_coverage);
    if u64::from(h.l1_size) < needed {
        return Err(error(format!(
            "Invalid QCOW2 L1 table: {} entries cover less than the {} virtual disk",
            h.l1_size,
            size_text(h.size)
        )));
    }
    Ok(())
}

/// Parse a QCOW2 image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let h = header(data)?;
    let found = extensions(data, &h)?;
    let backing = backing_name(data, &h)?;
    check_tables(data, &h)?;

    let mut c = container_for(data, Layout::Qcow2, format!("QCOW2 v{}", h.version));
    push_header_notes(&mut c, &h, &found, backing.as_deref());
    if h.crypt_method != CRYPT_NONE {
        let method = if h.crypt_method == CRYPT_AES {
            "AES-CBC"
        } else {
            "LUKS"
        };
        c.notes.push(format!(
            "Guest data is encrypted ({method}); the guest disk is not assembled or analyzed"
        ));
        c.opaque = true;
        push_unreadable(&mut c, h.size);
        return Ok(c);
    }
    if h.incompatible & INCOMPAT_DATA_FILE != 0 {
        c.notes.push(format!(
            "Guest clusters are stored in the external data file {}, which is not part of this \
             file; the guest disk is not assembled",
            found.data_file.as_deref().unwrap_or("(not named)")
        ));
        push_unreadable(&mut c, h.size);
        return Ok(c);
    }
    let parent = backing.map(|name| Parent {
        role: "backing file",
        reference: name,
    });
    let mut guest = Guest::new(data, h.size);
    map_clusters(data, &h, parent.is_some(), &mut guest)?;
    guest.finish(&mut c, TRANSFORM, parent.as_ref())?;
    Ok(c)
}

/// Notes and metadata from the header and its extensions.
fn push_header_notes(c: &mut Container<'_>, h: &Header, found: &Extensions, backing: Option<&str>) {
    let mut summary = format!(
        "QCOW2 version {}; {} clusters; {} virtual disk; {}",
        h.version,
        size_text(h.cluster_size()),
        size_text(h.size),
        counted(u64::from(h.l1_size), "L1 entry", "L1 entries")
    );
    if h.compression_type == COMPRESSION_ZSTD {
        summary.push_str("; zstd compression");
    }
    if h.has_extended_l2() {
        summary.push_str("; extended L2 entries (32 subclusters)");
    }
    if h.compatible & COMPAT_LAZY_REFCOUNTS != 0 {
        summary.push_str("; lazy refcounts");
    }
    c.notes.push(summary);
    if h.incompatible & INCOMPAT_DIRTY != 0 {
        c.notes.push(
            "Dirty bit set: refcounts may be inconsistent; the cluster mapping is read as stored"
                .into(),
        );
    }
    if h.incompatible & INCOMPAT_CORRUPT != 0 {
        c.notes.push(
            "Corrupt bit set: QEMU found an inconsistency and refuses to write this image".into(),
        );
    }
    if h.nb_snapshots > 0 {
        c.notes.push(format!(
            "{} internal snapshots; only the active L1 table is read",
            h.nb_snapshots
        ));
    }
    if let Some(name) = backing {
        c.notes.push(format!(
            "Backing file: {name}{}",
            found
                .backing_format
                .as_deref()
                .map(|format| format!(" (format {format})"))
                .unwrap_or_default()
        ));
        c.push_metadata("vdisk_qcow2_backing_file", "Backing file", name);
    }
    if let Some(offset) = found.encryption_header {
        c.notes
            .push(format!("LUKS encryption header at 0x{offset:X} (not read)"));
    }
    if h.autoclear & AUTOCLEAR_RAW_DATA_FILE != 0 {
        c.notes
            .push("The external data file is marked as a consistent raw image".into());
    }
    if let Some(name) = &found.data_file {
        c.push_metadata("vdisk_qcow2_data_file", "External data file", name.as_str());
    }
    c.push_metadata("vdisk_qcow2_version", "QCOW2 version", u64::from(h.version));
    c.push_metadata(
        "vdisk_qcow2_cluster_size",
        "Cluster size (B)",
        h.cluster_size(),
    );
    c.push_metadata(
        "vdisk_qcow2_snapshots",
        "Internal snapshots",
        u64::from(h.nb_snapshots),
    );
}

/// The L2 table an L1 entry points to, or `None` when it is unallocated.
fn l2_table<'a>(data: &'a [u8], h: &Header, l1_index: u64) -> Result<Option<&'a [u8]>> {
    let at = h.l1_table_offset + l1_index * ENTRY_SIZE;
    let entry = u64::from_be_bytes(
        range(data, at, ENTRY_SIZE, "QCOW2 L1 table")?
            .try_into()
            .expect("8 bytes"),
    );
    if entry & L1E_RESERVED_MASK != 0 {
        return Err(error(format!(
            "Invalid QCOW2 L1 entry {l1_index} at 0x{at:X}: reserved bits set"
        )));
    }
    let offset = entry & L1E_OFFSET_MASK;
    if offset == 0 {
        return Ok(None);
    }
    if offset % h.cluster_size() != 0 {
        return Err(error(format!(
            "Invalid QCOW2 L1 entry {l1_index}: L2 table offset 0x{offset:X} is not \
             cluster-aligned"
        )));
    }
    range(data, offset, h.cluster_size(), "QCOW2 L2 table").map(Some)
}

/// Map every guest cluster in the analyzed range. Unallocated clusters are
/// the backing file's when `has_backing` is true, zeros otherwise.
fn map_clusters<'a>(
    data: &'a [u8],
    h: &Header,
    has_backing: bool,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let cluster_size = h.cluster_size();
    let l2_entries = h.l2_entries();
    let entry_size = cluster_size / l2_entries;
    let mut table: Option<&'a [u8]> = None;
    for cluster in 0..guest.block_count(cluster_size) {
        let l1_index = cluster / l2_entries;
        let l2_index = cluster % l2_entries;
        if l2_index == 0 {
            table = l2_table(data, h, l1_index)?;
        }
        let Some(l2) = table else {
            unallocated(guest, cluster_size, has_backing);
            continue;
        };
        let at = usize::try_from(l2_index * entry_size).expect("inside one cluster");
        let entry = be_u64(l2, at)?;
        let bitmap = if h.has_extended_l2() {
            be_u64(l2, at + 8)?
        } else {
            0
        };
        let mapping = ClusterEntry {
            index: cluster,
            entry,
            bitmap,
        };
        map_cluster(data, h, &mapping, has_backing, guest)?;
    }
    Ok(())
}

/// One guest cluster's L2 entry.
struct ClusterEntry {
    /// Guest cluster number.
    index: u64,
    /// The descriptor and flags.
    entry: u64,
    /// The subcluster bitmap of an extended entry (0 otherwise).
    bitmap: u64,
}

fn unallocated(guest: &mut Guest<'_>, length: u64, has_backing: bool) {
    if has_backing {
        guest.parent(length);
    } else {
        guest.zero(length);
    }
}

/// Map one guest cluster from its L2 entry: compressed, zero, unallocated
/// or stored (per subcluster with extended L2 entries).
fn map_cluster<'a>(
    data: &'a [u8],
    h: &Header,
    mapping: &ClusterEntry,
    has_backing: bool,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let cluster_size = h.cluster_size();
    let entry = mapping.entry;
    if entry & L2E_COMPRESSED != 0 {
        if mapping.bitmap != 0 {
            return Err(error(format!(
                "Invalid QCOW2 L2 entry for cluster {}: a compressed cluster with a subcluster \
                 bitmap",
                mapping.index
            )));
        }
        let block = compressed_cluster(data, h, entry)?;
        guest.compressed(block, cluster_size);
        return Ok(());
    }
    if entry & L2E_STD_RESERVED_MASK != 0 {
        return Err(error(format!(
            "Invalid QCOW2 L2 entry for cluster {}: reserved bits set",
            mapping.index
        )));
    }
    let offset = entry & L2E_OFFSET_MASK;
    if offset % cluster_size != 0 {
        return Err(error(format!(
            "Invalid QCOW2 L2 entry for cluster {}: host offset 0x{offset:X} is not \
             cluster-aligned",
            mapping.index
        )));
    }
    if !h.has_extended_l2() {
        if entry & L2E_ZERO != 0 {
            guest.zero(cluster_size);
        } else if offset == 0 {
            unallocated(guest, cluster_size, has_backing);
        } else {
            guest.stored(offset, cluster_size, "QCOW2 data cluster")?;
        }
        return Ok(());
    }
    let allocated = mapping.bitmap & SUBCLUSTER_MASK;
    let zero = mapping.bitmap >> SUBCLUSTERS;
    if allocated & zero != 0 {
        return Err(error(format!(
            "Invalid QCOW2 L2 entry for cluster {}: subclusters both allocated and zero",
            mapping.index
        )));
    }
    if allocated != 0 && offset == 0 {
        return Err(error(format!(
            "Invalid QCOW2 L2 entry for cluster {}: allocated subclusters without a host cluster",
            mapping.index
        )));
    }
    let subcluster_size = cluster_size / u64::from(SUBCLUSTERS);
    for sub in 0..SUBCLUSTERS {
        let bit = 1u64 << sub;
        if allocated & bit != 0 {
            let at = offset + u64::from(sub) * subcluster_size;
            guest.stored(at, subcluster_size, "QCOW2 data subcluster")?;
        } else if zero & bit != 0 {
            guest.zero(subcluster_size);
        } else {
            unallocated(guest, subcluster_size, has_backing);
        }
    }
    Ok(())
}

/// A compressed cluster descriptor with `x = 62 - (cluster_bits - 8)`:
/// host offset in bits 0 to x-1, additional 512-byte sectors in bits x to
/// 61. The stored bytes run to the end of the last sector (clipped to the
/// file, which may end inside it).
fn compressed_cluster<'a>(data: &'a [u8], h: &Header, entry: u64) -> Result<CompressedBlock<'a>> {
    let offset_bits = 62 - (h.cluster_bits - 8);
    let offset = entry & ((1u64 << offset_bits) - 1);
    let sector_mask = (1u64 << (h.cluster_bits - 8)) - 1;
    let sectors = ((entry >> offset_bits) & sector_mask) + 1;
    let stored_size = sectors * COMPRESSED_SECTOR_SIZE - offset % COMPRESSED_SECTOR_SIZE;
    let start = usize::try_from(offset)
        .ok()
        .filter(|&start| start < data.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated QCOW2 compressed cluster at 0x{offset:X}: beyond the end of the file"
            ))
        })?;
    let end = usize::try_from(stored_size)
        .ok()
        .and_then(|size| start.checked_add(size))
        .map_or(data.len(), |end| end.min(data.len()));
    let codecs = if h.compression_type == COMPRESSION_ZSTD {
        ZSTD_CODECS
    } else {
        DEFLATE_CODECS
    };
    Ok(CompressedBlock {
        what: "QCOW2 compressed cluster",
        offset: start,
        stored: &data[start..end],
        codecs,
        block_size: usize::try_from(h.cluster_size()).expect("clusters are at most 2 MiB"),
        skip: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_descriptors_split_offset_and_sector_count() {
        // 4 KiB clusters: x = 62 - (12 - 8) = 58; offset 0x1234, two
        // additional sectors.
        let entry = L2E_COMPRESSED | (2u64 << 58) | 0x1234;
        let mut data = vec![0u8; 0x2000];
        data[0x1234] = 0xAA;
        let h = Header {
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 12,
            size: 4096,
            crypt_method: CRYPT_NONE,
            l1_size: 1,
            l1_table_offset: 0,
            refcount_table_offset: 0,
            refcount_table_clusters: 0,
            nb_snapshots: 0,
            incompatible: 0,
            compatible: 0,
            autoclear: 0,
            length: V3_MIN_HEADER_SIZE,
            compression_type: COMPRESSION_DEFLATE,
        };
        let block = compressed_cluster(&data, &h, entry & !L2E_COMPRESSED).unwrap();
        assert_eq!(block.offset, 0x1234);
        // Three sectors from the one holding 0x1234: 0x1200..0x1800.
        assert_eq!(block.stored.len(), 0x1800 - 0x1234);
        assert_eq!(block.block_size, 4096);
        assert!(compressed_cluster(&data[..0x1000], &h, entry & !L2E_COMPRESSED).is_err());
    }

    #[test]
    fn extensions_are_padded_to_eight_bytes() {
        assert_eq!(padded_extension(5), 8);
        assert_eq!(padded_extension(8), 8);
        assert_eq!(padded_extension(0), 0);
    }
}
