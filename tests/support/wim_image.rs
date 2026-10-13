//! A WIM builder for tests, from the documented layout: the header, the
//! lookup table, the XML data and the integrity table (Microsoft "Windows
//! Imaging File Format (WIM)"; wimlib v1.14.5 `include/wimlib/header.h`,
//! `src/blob_table.c`, `src/xml.c`, `src/integrity.c`), resources stored,
//! chunked or solid (`src/resource.c`, `include/wimlib/resource.h`), and
//! metadata resources of security data, directory entries and stream
//! entries (`src/security.c`, `src/dentry.c`). It writes resources, then
//! the metadata resources, the lookup table, the XML data and the
//! integrity table, as wimlib and 7-Zip lay them out. Chunks are coded by
//! the test encoders `xpress.rs`, `wim_lzx.rs` and `lzms.rs`, which callers
//! include next to this module.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

use super::lzms;
use super::wim_lzx;
use super::xpress;
use zrax::formats::checksum::Sha1;

pub const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
pub const HEADER_SIZE: usize = 208;
pub const VERSION_DEFAULT: u32 = 0x0001_0D00;
pub const VERSION_SOLID: u32 = 0x0000_0E00;

/// Header flags.
pub const FLAG_COMPRESSION: u32 = 0x0000_0002;
pub const FLAG_RP_FIX: u32 = 0x0000_0080;
pub const FLAG_XPRESS: u32 = 0x0002_0000;
pub const FLAG_LZX: u32 = 0x0004_0000;
pub const FLAG_LZMS: u32 = 0x0008_0000;

/// Resource header flags.
pub const RESOURCE_METADATA: u8 = 0x02;
pub const RESOURCE_COMPRESSED: u8 = 0x04;
pub const RESOURCE_SOLID: u8 = 0x10;

/// The uncompressed size of a solid resource entry.
pub const SOLID_MARKER: u64 = 0x1_0000_0000;

/// File attributes.
pub const ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

/// Header field offsets.
pub const VERSION_FIELD: usize = 0x0C;
pub const FLAGS_FIELD: usize = 0x10;
pub const CHUNK_SIZE_FIELD: usize = 0x14;
pub const PART_NUMBER_FIELD: usize = 0x28;
pub const TOTAL_PARTS_FIELD: usize = 0x2A;
pub const IMAGE_COUNT_FIELD: usize = 0x2C;
pub const LOOKUP_FIELD: usize = 0x30;
pub const XML_FIELD: usize = 0x48;
pub const BOOT_INDEX_FIELD: usize = 0x78;
pub const INTEGRITY_FIELD: usize = 0x7C;

/// Size of a directory entry's fixed fields and of a stream entry's.
const DENTRY_SIZE: usize = 102;
const STREAM_ENTRY_SIZE: usize = 38;

/// A compression format of the header or of a solid resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Xpress,
    Lzx,
    Lzms,
}

impl Codec {
    fn flag(self) -> u32 {
        match self {
            Self::Xpress => FLAG_XPRESS,
            Self::Lzx => FLAG_LZX,
            Self::Lzms => FLAG_LZMS,
        }
    }

    /// The solid resource format number: 1 XPRESS, 2 LZX, 3 LZMS.
    fn number(self) -> u32 {
        match self {
            Self::Xpress => 1,
            Self::Lzx => 2,
            Self::Lzms => 3,
        }
    }

    /// One chunk's stored bytes; the chunk is stored as is when coding does
    /// not make it smaller.
    fn chunk(self, chunk: &[u8], chunk_size: usize) -> Vec<u8> {
        let coded = match self {
            Self::Xpress => xpress::compress(chunk),
            Self::Lzx => {
                let bits = chunk_size.trailing_zeros().max(15) as u8;
                wim_lzx::compress(chunk, bits, 32_768, false)
            }
            Self::Lzms => lzms::compress(chunk),
        };
        if coded.len() < chunk.len() {
            coded
        } else {
            chunk.to_vec()
        }
    }
}

/// A named data stream.
#[derive(Debug, Clone)]
pub struct Stream {
    pub name: String,
    pub data: Vec<u8>,
}

/// A directory tree node.
#[derive(Debug, Clone)]
pub enum Node {
    File {
        name: String,
        data: Vec<u8>,
        streams: Vec<Stream>,
        /// Store the unnamed stream in an unnamed stream entry with a zero
        /// main hash, as wimlib reads some files.
        unnamed_entry: bool,
    },
    Dir {
        name: String,
        children: Vec<Node>,
    },
    /// A symbolic link: a reparse point whose reparse data is a stream.
    Symlink {
        name: String,
        reparse: Vec<u8>,
    },
    /// An encrypted file whose raw data is a stream.
    Encrypted {
        name: String,
        data: Vec<u8>,
    },
}

pub fn file(name: &str, data: &[u8]) -> Node {
    Node::File {
        name: name.to_string(),
        data: data.to_vec(),
        streams: Vec::new(),
        unnamed_entry: false,
    }
}

pub fn dir(name: &str, children: Vec<Node>) -> Node {
    Node::Dir {
        name: name.to_string(),
        children,
    }
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Self::File { name, .. }
            | Self::Dir { name, .. }
            | Self::Symlink { name, .. }
            | Self::Encrypted { name, .. } => name,
        }
    }

    /// The blobs of this node: unnamed stream first, then named streams.
    fn blobs(&self) -> Vec<&[u8]> {
        match self {
            Self::File { data, streams, .. } => std::iter::once(data.as_slice())
                .chain(streams.iter().map(|s| s.data.as_slice()))
                .collect(),
            Self::Dir { .. } => Vec::new(),
            Self::Symlink { reparse, .. } => vec![reparse.as_slice()],
            Self::Encrypted { data, .. } => vec![data.as_slice()],
        }
    }

    /// Bytes of the entry and its stream entries.
    fn size(&self) -> usize {
        let streams: usize = match self {
            Self::File {
                streams,
                unnamed_entry,
                ..
            } => {
                streams
                    .iter()
                    .map(|s| stream_entry_size(utf16(&s.name).len()))
                    .sum::<usize>()
                    + if *unnamed_entry {
                        stream_entry_size(0)
                    } else {
                        0
                    }
            }
            _ => 0,
        };
        dentry_size(utf16(self.name()).len()) + streams
    }
}

/// An image: its XML name and its root directory's entries.
#[derive(Debug, Clone)]
pub struct Image {
    pub name: String,
    pub root: Vec<Node>,
}

/// Solid resource settings: every file blob goes into one solid resource.
#[derive(Debug, Clone, Copy)]
pub struct Solid {
    pub codec: Option<Codec>,
    pub chunk_size: u32,
}

/// What to build.
#[derive(Debug, Clone)]
pub struct Spec {
    pub version: u32,
    pub compression: Option<Codec>,
    pub chunk_size: u32,
    pub images: Vec<Image>,
    pub solid: Option<Solid>,
    /// Chunk size of an integrity table, if one is written.
    pub integrity_chunk: Option<u32>,
    /// Extra XML after the images, inside `<WIM>`.
    pub xml_extra: String,
    pub boot_index: u32,
    /// A security descriptor in each metadata resource.
    pub security_descriptor: bool,
}

impl Spec {
    pub fn new(images: Vec<Image>) -> Self {
        Self {
            version: VERSION_DEFAULT,
            compression: None,
            chunk_size: 0,
            images,
            solid: None,
            integrity_chunk: None,
            xml_extra: String::new(),
            boot_index: 0,
            security_descriptor: false,
        }
    }
}

/// Where a resource landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub hash: [u8; 20],
    pub offset: usize,
    pub stored_size: usize,
    pub size: usize,
    pub compressed: bool,
}

/// A built WIM and where its parts are.
#[derive(Debug, Clone)]
pub struct Built {
    pub bytes: Vec<u8>,
    /// File resources in the order written (for solid WIMs, the solid
    /// resource with the hash of its uncompressed data).
    pub resources: Vec<Placed>,
    pub metadata: Vec<Placed>,
    pub lookup: Placed,
    pub xml: Placed,
}

impl Built {
    /// The resource of `data`.
    pub fn resource(&self, data: &[u8]) -> Placed {
        let hash = sha1(data);
        *self
            .resources
            .iter()
            .find(|r| r.hash == hash)
            .expect("the data is a resource")
    }
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finish()
}

pub fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn dentry_size(name_bytes: usize) -> usize {
    align8(DENTRY_SIZE + if name_bytes > 0 { name_bytes + 2 } else { 0 })
}

fn stream_entry_size(name_bytes: usize) -> usize {
    align8(STREAM_ENTRY_SIZE + if name_bytes > 0 { name_bytes + 2 } else { 0 })
}

/// A resource header: stored size (7 bytes), flags, offset, size.
pub fn reshdr(stored_size: u64, flags: u8, offset: u64, size: u64) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..7].copy_from_slice(&stored_size.to_le_bytes()[..7]);
    out[7] = flags;
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..].copy_from_slice(&size.to_le_bytes());
    out
}

/// A lookup table entry: resource header, part number, reference count and
/// hash.
pub fn lookup_entry(header: [u8; 24], part: u16, references: u32, hash: [u8; 20]) -> Vec<u8> {
    let mut out = header.to_vec();
    out.extend_from_slice(&part.to_le_bytes());
    out.extend_from_slice(&references.to_le_bytes());
    out.extend_from_slice(&hash);
    out
}

/// A non-solid resource's stored bytes: a chunk table of `chunks - 1`
/// 4-byte offsets from the end of the table, then the chunks.
pub fn chunked(data: &[u8], codec: Codec, chunk_size: usize) -> Vec<u8> {
    let chunks: Vec<Vec<u8>> = data
        .chunks(chunk_size)
        .map(|chunk| codec.chunk(chunk, chunk_size))
        .collect();
    let mut table = Vec::new();
    let mut offset = 0u32;
    for chunk in &chunks[..chunks.len().saturating_sub(1)] {
        offset += chunk.len() as u32;
        table.extend_from_slice(&offset.to_le_bytes());
    }
    let mut out = table;
    for chunk in chunks {
        out.extend_from_slice(&chunk);
    }
    out
}

/// A solid resource's stored bytes: its header, the chunk sizes and the
/// chunks.
pub fn solid_resource(data: &[u8], codec: Option<Codec>, chunk_size: usize) -> Vec<u8> {
    let chunks: Vec<Vec<u8>> = data
        .chunks(chunk_size)
        .map(|chunk| match codec {
            Some(codec) => codec.chunk(chunk, chunk_size),
            None => chunk.to_vec(),
        })
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    out.extend_from_slice(&codec.map_or(0, Codec::number).to_le_bytes());
    for chunk in &chunks {
        out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    }
    for chunk in chunks {
        out.extend_from_slice(&chunk);
    }
    out
}

/// A stream entry to write: its UTF-16LE name (empty when unnamed) and
/// hash.
struct ExtraStream {
    name: Vec<u8>,
    hash: [u8; 20],
}

/// The fields of a directory entry that depend on its node.
struct EntryFields {
    attributes: u32,
    main_hash: [u8; 20],
    /// The reparse tag of a reparse point; 0 otherwise.
    tag: u32,
    extra: Vec<ExtraStream>,
}

impl EntryFields {
    fn of(node: Option<&Node>) -> Self {
        let zero = [0u8; 20];
        let plain = |attributes, main_hash, tag| Self {
            attributes,
            main_hash,
            tag,
            extra: Vec::new(),
        };
        match node {
            None | Some(Node::Dir { .. }) => plain(ATTRIBUTE_DIRECTORY, zero, 0),
            Some(Node::File {
                data,
                streams,
                unnamed_entry,
                ..
            }) => {
                let data_hash = if data.is_empty() { zero } else { sha1(data) };
                let mut extra = Vec::new();
                let main_hash = if *unnamed_entry {
                    extra.push(ExtraStream {
                        name: Vec::new(),
                        hash: data_hash,
                    });
                    zero
                } else {
                    data_hash
                };
                for s in streams {
                    extra.push(ExtraStream {
                        name: utf16(&s.name),
                        hash: sha1(&s.data),
                    });
                }
                Self {
                    attributes: ATTRIBUTE_ARCHIVE,
                    main_hash,
                    tag: 0,
                    extra,
                }
            }
            Some(Node::Symlink { reparse, .. }) => plain(
                ATTRIBUTE_REPARSE_POINT | ATTRIBUTE_ARCHIVE,
                sha1(reparse),
                0xA000_000C,
            ),
            Some(Node::Encrypted { data, .. }) => {
                plain(ATTRIBUTE_ENCRYPTED | ATTRIBUTE_ARCHIVE, sha1(data), 0)
            }
        }
    }
}

/// One directory entry and its stream entries.
fn write_dentry(out: &mut Vec<u8>, node: Option<&Node>, subdir: u64) {
    let start = out.len();
    let name = node.map_or_else(Vec::new, |n| utf16(n.name()));
    let size = dentry_size(name.len());
    let EntryFields {
        attributes,
        main_hash,
        tag,
        extra,
    } = EntryFields::of(node);
    out.extend_from_slice(&(size as u64).to_le_bytes());
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes()); // security ID: none
    out.extend_from_slice(&subdir.to_le_bytes());
    out.extend_from_slice(&[0; 16]); // reserved
    for time in [0x01D9_0000_0000_0000u64; 3] {
        out.extend_from_slice(&time.to_le_bytes());
    }
    out.extend_from_slice(&main_hash);
    out.extend_from_slice(&[0; 4]); // unknown
    out.extend_from_slice(&tag.to_le_bytes()); // reparse tag or link group
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // no short name
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    if !name.is_empty() {
        out.extend_from_slice(&name);
        out.extend_from_slice(&[0, 0]);
    }
    out.resize(start + size, 0);
    for stream in extra {
        let entry_start = out.len();
        let entry_size = stream_entry_size(stream.name.len());
        out.extend_from_slice(&(entry_size as u64).to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&stream.hash);
        out.extend_from_slice(&(stream.name.len() as u16).to_le_bytes());
        if !stream.name.is_empty() {
            out.extend_from_slice(&stream.name);
            out.extend_from_slice(&[0, 0]);
        }
        out.resize(entry_start + entry_size, 0);
    }
}

/// An image's metadata resource: security data, the root entry and an
/// 8-byte zero that ends the root's own list (wimlib
/// `write_dentry_tree`), then each directory's entries and an 8-byte zero,
/// directories in breadth-first order.
pub fn metadata_resource(image: &Image, security_descriptor: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if security_descriptor {
        // One descriptor of 20 bytes: length 8 + 8 + 20 = 36, aligned to 40.
        out.extend_from_slice(&36u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&20u64.to_le_bytes());
        out.extend_from_slice(&[1, 0, 4, 0x80]);
        out.extend_from_slice(&[0; 16]);
        out.resize(40, 0);
    } else {
        out.extend_from_slice(&8u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    // Directory lists in breadth-first order; list 0 is the root's.
    let mut lists: Vec<&[Node]> = vec![&image.root];
    let mut i = 0;
    while i < lists.len() {
        for node in lists[i] {
            if let Node::Dir { children, .. } = node {
                lists.push(children);
            }
        }
        i += 1;
    }
    let root_offset = out.len();
    let mut offset = root_offset + dentry_size(0) + 8;
    let mut list_offsets = Vec::new();
    for list in &lists {
        list_offsets.push(offset);
        offset += list.iter().map(Node::size).sum::<usize>() + 8;
    }
    write_dentry(&mut out, None, list_offsets[0] as u64);
    out.extend_from_slice(&[0; 8]);
    let mut next_list = 1;
    for list in &lists {
        for node in *list {
            let subdir = if matches!(node, Node::Dir { .. }) {
                next_list += 1;
                list_offsets[next_list - 1] as u64
            } else {
                0
            };
            write_dentry(&mut out, Some(node), subdir);
        }
        out.extend_from_slice(&[0; 8]);
    }
    assert_eq!(out.len(), offset);
    out
}

/// Every blob of an image's tree, depth first, with repeats.
fn tree_blobs<'n>(nodes: &'n [Node], out: &mut Vec<&'n [u8]>) {
    for node in nodes {
        out.extend(node.blobs());
        if let Node::Dir { children, .. } = node {
            tree_blobs(children, out);
        }
    }
}

/// The XML data: a UTF-16LE document with a byte order mark.
pub fn xml_data(spec: &Spec) -> Vec<u8> {
    let mut text = String::from("<WIM><TOTALBYTES>0</TOTALBYTES>");
    for (i, image) in spec.images.iter().enumerate() {
        text.push_str(&format!(
            "<IMAGE INDEX=\"{}\"><DIRCOUNT>1</DIRCOUNT><NAME>{}</NAME></IMAGE>",
            i + 1,
            image.name
        ));
    }
    text.push_str(&spec.xml_extra);
    text.push_str("</WIM>");
    let mut out = vec![0xff, 0xfe];
    out.extend_from_slice(&utf16(&text));
    out
}

/// Store `data` as a resource of `spec`'s compression, returning where it
/// landed and its stored size.
fn store(out: &mut Vec<u8>, data: &[u8], spec: &Spec) -> Placed {
    let offset = out.len();
    let (stored, compressed) = match spec.compression {
        Some(codec) if !data.is_empty() => (chunked(data, codec, spec.chunk_size as usize), true),
        _ => (data.to_vec(), false),
    };
    out.extend_from_slice(&stored);
    Placed {
        hash: sha1(data),
        offset,
        stored_size: stored.len(),
        size: data.len(),
        compressed,
    }
}

/// Build the WIM of `spec`.
pub fn build(spec: &Spec) -> Built {
    let mut out = vec![0u8; HEADER_SIZE];
    // Distinct non-empty blobs in first-use order, with reference counts.
    let mut blobs: Vec<(&[u8], u32)> = Vec::new();
    for image in &spec.images {
        let mut all = Vec::new();
        tree_blobs(&image.root, &mut all);
        for blob in all.into_iter().filter(|b| !b.is_empty()) {
            match blobs.iter_mut().find(|(b, _)| *b == blob) {
                Some((_, count)) => *count += 1,
                None => blobs.push((blob, 1)),
            }
        }
    }
    let mut lookup = Vec::new();
    let mut resources = Vec::new();
    match spec.solid {
        None => {
            for &(blob, references) in &blobs {
                let placed = store(&mut out, blob, spec);
                let flags = if placed.compressed {
                    RESOURCE_COMPRESSED
                } else {
                    0
                };
                lookup.extend(lookup_entry(
                    reshdr(
                        placed.stored_size as u64,
                        flags,
                        placed.offset as u64,
                        blob.len() as u64,
                    ),
                    1,
                    references,
                    placed.hash,
                ));
                resources.push(placed);
            }
        }
        Some(solid) => {
            let joined: Vec<u8> = blobs.iter().flat_map(|(b, _)| b.iter().copied()).collect();
            let offset = out.len();
            let stored = solid_resource(&joined, solid.codec, solid.chunk_size as usize);
            out.extend_from_slice(&stored);
            lookup.extend(lookup_entry(
                reshdr(
                    stored.len() as u64,
                    RESOURCE_SOLID,
                    offset as u64,
                    SOLID_MARKER,
                ),
                1,
                1,
                [0; 20],
            ));
            // Blob entries: the size in the stored size field, the offset in
            // the run's uncompressed data, an uncompressed size of 0
            // (wimlib `write.c`; 7-Zip `IsSolidSmall`).
            let mut position = 0u64;
            for &(blob, references) in &blobs {
                lookup.extend(lookup_entry(
                    reshdr(blob.len() as u64, RESOURCE_SOLID, position, 0),
                    1,
                    references,
                    sha1(blob),
                ));
                position += blob.len() as u64;
            }
            resources.push(Placed {
                hash: sha1(&joined),
                offset,
                stored_size: stored.len(),
                size: joined.len(),
                compressed: solid.codec.is_some(),
            });
        }
    }
    let mut metadata = Vec::new();
    for image in &spec.images {
        let resource = metadata_resource(image, spec.security_descriptor);
        let placed = store(&mut out, &resource, spec);
        let flags = RESOURCE_METADATA
            | if placed.compressed {
                RESOURCE_COMPRESSED
            } else {
                0
            };
        lookup.extend(lookup_entry(
            reshdr(
                placed.stored_size as u64,
                flags,
                placed.offset as u64,
                resource.len() as u64,
            ),
            1,
            1,
            placed.hash,
        ));
        metadata.push(placed);
    }
    let lookup_offset = out.len();
    out.extend_from_slice(&lookup);
    let xml = xml_data(spec);
    let xml_offset = out.len();
    out.extend_from_slice(&xml);
    let mut flags = FLAG_RP_FIX;
    if let Some(codec) = spec.compression.or(spec.solid.and_then(|s| s.codec)) {
        flags |= FLAG_COMPRESSION | codec.flag();
    }
    out[..8].copy_from_slice(MAGIC);
    out[8..12].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    out[VERSION_FIELD..VERSION_FIELD + 4].copy_from_slice(&spec.version.to_le_bytes());
    out[FLAGS_FIELD..FLAGS_FIELD + 4].copy_from_slice(&flags.to_le_bytes());
    let chunk_size = if spec.compression.is_some() {
        spec.chunk_size
    } else {
        0
    };
    out[CHUNK_SIZE_FIELD..CHUNK_SIZE_FIELD + 4].copy_from_slice(&chunk_size.to_le_bytes());
    out[0x18..0x28].copy_from_slice(&[0x5a; 16]); // GUID
    out[PART_NUMBER_FIELD..PART_NUMBER_FIELD + 2].copy_from_slice(&1u16.to_le_bytes());
    out[TOTAL_PARTS_FIELD..TOTAL_PARTS_FIELD + 2].copy_from_slice(&1u16.to_le_bytes());
    out[IMAGE_COUNT_FIELD..IMAGE_COUNT_FIELD + 4]
        .copy_from_slice(&(spec.images.len() as u32).to_le_bytes());
    out[LOOKUP_FIELD..LOOKUP_FIELD + 24].copy_from_slice(&reshdr(
        lookup.len() as u64,
        RESOURCE_METADATA,
        lookup_offset as u64,
        lookup.len() as u64,
    ));
    out[XML_FIELD..XML_FIELD + 24].copy_from_slice(&reshdr(
        xml.len() as u64,
        0,
        xml_offset as u64,
        xml.len() as u64,
    ));
    out[BOOT_INDEX_FIELD..BOOT_INDEX_FIELD + 4].copy_from_slice(&spec.boot_index.to_le_bytes());
    if let Some(chunk) = spec.integrity_chunk {
        let checked = &out[HEADER_SIZE..lookup_offset + lookup.len()];
        let hashes: Vec<[u8; 20]> = checked.chunks(chunk as usize).map(sha1).collect();
        let mut table = Vec::new();
        let size = 12 + 20 * hashes.len();
        table.extend_from_slice(&(size as u32).to_le_bytes());
        table.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        table.extend_from_slice(&chunk.to_le_bytes());
        for hash in hashes {
            table.extend_from_slice(&hash);
        }
        let integrity_offset = out.len();
        out.extend_from_slice(&table);
        out[INTEGRITY_FIELD..INTEGRITY_FIELD + 24].copy_from_slice(&reshdr(
            size as u64,
            0,
            integrity_offset as u64,
            size as u64,
        ));
    }
    Built {
        bytes: out,
        resources,
        metadata,
        lookup: Placed {
            hash: sha1(&lookup),
            offset: lookup_offset,
            stored_size: lookup.len(),
            size: lookup.len(),
            compressed: false,
        },
        xml: Placed {
            hash: sha1(&xml),
            offset: xml_offset,
            stored_size: xml.len(),
            size: xml.len(),
            compressed: false,
        },
    }
}
