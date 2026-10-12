//! Read-only filesystem images: SquashFS 4.0 with every compressor, basic
//! and extended inodes, fragments, sparse and stored blocks, multi-block
//! metadata and the optional tables; SquashFS 1.x-3.x, big-endian and
//! streamed superblocks; CramFS in both byte orders, after a boot-code pad
//! and with extended block pointers; and romfs. Members are listed only when
//! recognized, with stored offsets and decoded ranges; corrupt fields,
//! truncations and byte mutations are errors or stay bounded.

use std::collections::HashMap;
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::Kind;
use zrax::formats::rofs::Layout;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::types::ContainedArch;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/compressed");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

/// The committed synthetic ELF: a 64-byte x86-64 header, then 192 B of the
/// repeated text `zrax compressed fixture `.
fn payload_elf() -> Vec<u8> {
    fixture("payload.elf")
}

/// ELF `e_machine` values.
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// An ELF64 little-endian header (`e_ident`, `e_type` = `ET_EXEC`,
/// `e_machine`) followed by nonzero filler up to `size` bytes.
fn elf64(machine: u16, size: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..size.max(64)).map(|i| (i % 251) as u8 | 1).collect();
    data[..64].fill(0);
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&machine.to_le_bytes());
    data
}

/// `size` bytes of plain text that no format recognizes.
fn text(size: usize) -> Vec<u8> {
    b"plain words for a read only filesystem fixture\n"
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn labels(payload: &DetectionPayload) -> Vec<String> {
    payload
        .slices
        .iter()
        .map(|s| s.label.clone().unwrap_or_default())
        .collect()
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no slice {label}; slices {:?}", labels(payload)))
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn detected_layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::Rofs(layout),
        } => Some(layout),
        _ => None,
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[at..at + 2].copy_from_slice(&bytes);
}

fn put_u32(out: &mut [u8], at: usize, value: u32, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[at..at + 4].copy_from_slice(&bytes);
}

fn put_u64(out: &mut [u8], at: usize, value: u64, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[at..at + 8].copy_from_slice(&bytes);
}

/// `value` rounded up to a multiple of `to`.
fn round_up(value: usize, to: usize) -> usize {
    match value % to {
        0 => value,
        remainder => value + to - remainder,
    }
}

fn align(out: &mut Vec<u8>, to: usize) {
    let padded = round_up(out.len(), to);
    out.resize(padded, 0);
}

/// Every truncation of `image` shorter than `end` is an error or is not
/// reported as `format`; every byte mutation of `image[..end]` classifies
/// or fails without panicking.
fn sweep(image: &[u8], end: usize, format: FileFormat) {
    for cut in 0..end {
        if let Ok(p) = detect_payload(&image[..cut], &ClassifierOptions::new()) {
            assert_ne!(p.format.format, format, "prefix {cut} still parses");
        }
    }
    for i in 0..end {
        for value in [0x00, 0xff, image[i] ^ 0x01] {
            let mut mutated = image.to_vec();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

/// gzip options: level 9 (i32), window 15 (i16), default strategy (i16).
fn gzip_options() -> Vec<u8> {
    let mut options = 9i32.to_le_bytes().to_vec();
    options.extend_from_slice(&15i16.to_le_bytes());
    options.extend_from_slice(&1i16.to_le_bytes());
    options
}

// SquashFS 4.0 fixtures, built from `squashfs_fs.h` (Linux v6.11): every
// field little-endian.

const SQUASHFS_BLOCK_SIZE: usize = 4096;
const SQUASHFS_BLOCK_LOG: u16 = 12;

/// `SQUASHFS_METADATA_SIZE`: decoded bytes per metadata block.
const METADATA_SIZE: usize = 8192;

/// Metadata block header bit 15 (`SQUASHFS_COMPRESSED_BIT`): stored as-is.
const METADATA_STORED: u16 = 0x8000;

/// Block list and fragment size bit 24 (`SQUASHFS_COMPRESSED_BIT_BLOCK`):
/// stored as-is.
const BLOCK_STORED: u32 = 1 << 24;

/// `SQUASHFS_INVALID_FRAG`, `SQUASHFS_INVALID_BLK`, `SQUASHFS_INVALID_XATTR`.
const NO_FRAGMENT: u32 = 0xffff_ffff;
const NO_TABLE: u64 = u64::MAX;
const NO_XATTR: u32 = 0xffff_ffff;

/// Superblock flag bit 10 (`SQUASHFS_COMP_OPT`).
const COMP_OPT: u16 = 1 << 10;

/// Inode types (`SQUASHFS_DIR_TYPE`, `SQUASHFS_REG_TYPE`,
/// `SQUASHFS_SYMLINK_TYPE`, and the extended `SQUASHFS_LDIR_TYPE`,
/// `SQUASHFS_LREG_TYPE`).
const DIR_TYPE: u16 = 1;
const REG_TYPE: u16 = 2;
const SYMLINK_TYPE: u16 = 3;
const LDIR_TYPE: u16 = 8;
const LREG_TYPE: u16 = 9;

/// Compressor IDs (`ZLIB_COMPRESSION` ... `ZSTD_COMPRESSION`).
const GZIP: u16 = 1;
const LZMA: u16 = 2;
const LZO: u16 = 3;
const XZ: u16 = 4;
const LZ4: u16 = 5;
const ZSTD: u16 = 6;

/// A fixture block compressor.
type Compress = fn(&[u8]) -> Vec<u8>;

/// gzip compressor blocks are zlib streams (`gzip_wrapper.c`).
fn zlib(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bytes, 9)
}

/// LZ4 compressor blocks are raw LZ4 blocks (`lz4_wrapper.c`).
fn lz4_block(bytes: &[u8]) -> Vec<u8> {
    lz4_flex::block::compress(bytes)
}

/// The committed xz stream of `payload.elf` (`xz -9`); fixtures that use
/// it store only that file.
fn xz_payload(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes, payload_elf(), "xz fixture holds payload.elf only");
    fixture("payload.elf.xz")
}

/// The committed LZMA-alone stream of `payload.elf` (`lzma -9`).
fn lzma_payload(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes, payload_elf(), "LZMA fixture holds payload.elf only");
    fixture("payload.elf.lzma")
}

/// The committed Zstandard frame of `payload.elf` (`zstd -19 --check`).
fn zstd_payload(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes, payload_elf(), "zstd fixture holds payload.elf only");
    fixture("payload.elf.zst")
}

/// A raw LZO1X block (Linux `Documentation/staging/lzo.rst`) for
/// `payload.elf`: its 64-byte header and first 24 B of text as one literal
/// run (first byte 17 + 88), then the periodic rest as one M3 match (`001`
/// with L = 0, so length 2 + 31 + 135 = 168, and the LE16 `D << 2`, distance
/// D + 1 = 24), then the end marker `11 00 00`.
fn lzo_payload(bytes: &[u8]) -> Vec<u8> {
    const LITERALS: usize = 88;
    const DISTANCE: usize = 24;
    assert_eq!(bytes.len(), LITERALS + 168);
    assert!((LITERALS..bytes.len()).all(|i| bytes[i] == bytes[i - DISTANCE]));
    let mut out = vec![17 + LITERALS as u8];
    out.extend_from_slice(&bytes[..LITERALS]);
    out.extend_from_slice(&[0x20, 135]);
    out.extend_from_slice(&(((DISTANCE - 1) as u16) << 2).to_le_bytes());
    out.extend_from_slice(&[0x11, 0x00, 0x00]);
    out
}

/// One metadata block: a 2-byte header (bit 15 set when stored, the low 15
/// bits the stored size), then the compressed bytes when smaller, else the
/// bytes themselves.
fn metadata_block(bytes: &[u8], compress: Option<Compress>) -> Vec<u8> {
    let compressed = compress.map(|c| c(bytes)).filter(|c| c.len() < bytes.len());
    let mut out = Vec::new();
    match compressed {
        Some(c) => {
            out.extend_from_slice(&(c.len() as u16).to_le_bytes());
            out.extend_from_slice(&c);
        }
        None => {
            out.extend_from_slice(&(bytes.len() as u16 | METADATA_STORED).to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
    out
}

/// A metadata table being written: finished blocks (header and stored
/// bytes) and the decoded bytes of the current block. A block is finished
/// when it holds 8 KiB, so structures span blocks freely.
struct Metadata {
    compress: Option<Compress>,
    stored: Vec<u8>,
    pending: Vec<u8>,
}

impl Metadata {
    fn new(compress: Option<Compress>) -> Self {
        Self {
            compress,
            stored: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Reference of the next byte: the table-relative offset of its block
    /// in bits 16 and up, its offset in the decoded block in bits 0-15.
    fn reference(&self) -> u64 {
        ((self.stored.len() as u64) << 16) | self.pending.len() as u64
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.pending.push(b);
            if self.pending.len() == METADATA_SIZE {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        if !self.pending.is_empty() {
            let block = metadata_block(&self.pending, self.compress);
            self.stored.extend_from_slice(&block);
            self.pending.clear();
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        self.flush();
        std::mem::take(&mut self.stored)
    }
}

/// A regular file of a SquashFS fixture.
struct SqFile {
    name: String,
    contents: Vec<u8>,
    /// Extended inode (type 9) instead of basic (type 2).
    extended: bool,
    /// The tail (the whole file when smaller than a block) goes into the
    /// shared fragment block.
    fragment: bool,
    /// Data blocks carry the stored bit instead of being compressed.
    stored: bool,
}

/// A directory of a SquashFS fixture; children sorted by name.
struct SqDir {
    name: String,
    /// Extended inode (type 8, with one index entry) instead of basic.
    extended: bool,
    children: Vec<SqNode>,
}

enum SqNode {
    File(SqFile),
    Dir(SqDir),
    /// A symbolic link: name and target path.
    Symlink(&'static str, &'static [u8]),
}

fn sq_file(name: &str, contents: Vec<u8>) -> SqFile {
    SqFile {
        name: name.to_string(),
        contents,
        extended: false,
        fragment: false,
        stored: false,
    }
}

fn sq_dir(name: &str, children: Vec<SqNode>) -> SqDir {
    SqDir {
        name: name.to_string(),
        extended: false,
        children,
    }
}

/// How a SquashFS fixture is stored.
struct SqImage {
    compressor: u16,
    /// Data and fragment block compressor; `None` stores every block.
    data: Option<Compress>,
    /// Metadata block compressor; `None` stores every metadata block.
    metadata: Option<Compress>,
    /// Compressor options payload, written after the superblock.
    options: Option<Vec<u8>>,
    /// Export table (inode references by inode number).
    export_table: bool,
    /// Xattr id table with one id.
    xattr_table: bool,
}

fn sq_image(compressor: u16, data: Option<Compress>) -> SqImage {
    SqImage {
        compressor,
        data,
        metadata: None,
        options: None,
        export_table: false,
        xattr_table: false,
    }
}

/// An inode written to the inode table.
#[derive(Clone, Copy)]
struct Written {
    reference: u64,
    number: u32,
}

/// Where a file's data blocks are stored: the first block's file offset
/// and the stored bytes of all blocks.
#[derive(Clone, Copy, Debug)]
struct Stored {
    start: u64,
    size: u64,
}

/// A built SquashFS fixture and where its parts are.
struct SqFixture {
    image: Vec<u8>,
    bytes_used: usize,
    /// Data blocks by path.
    files: HashMap<String, Stored>,
    /// Fragment blocks: file offset and stored size.
    fragments: Vec<Stored>,
}

struct SqBuilder {
    data: Option<Compress>,
    image: Vec<u8>,
    inodes: Metadata,
    directories: Metadata,
    /// Decoded bytes of the fragment block being filled.
    fragment: Vec<u8>,
    /// Fragment entries: block file offset and size field.
    fragment_entries: Vec<(u64, u32)>,
    /// Inode references by inode number minus 1.
    references: Vec<u64>,
    files: HashMap<String, Stored>,
}

/// Inode header: type, mode, uid index, gid index, mtime, inode number.
fn base_inode(kind: u16, number: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&0o755u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&number.to_le_bytes());
    out
}

/// A directory listing entry before it is written.
struct Entry {
    name: String,
    kind: u16,
    written: Written,
}

/// Directory listing: headers (entry count minus one, inode table block,
/// base inode number), each followed by up to 256 entries whose inodes
/// start in that block (inode offset, inode number delta, basic type, name
/// size minus one, name).
fn listing(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let block = entries[i].written.reference >> 16;
        let group: Vec<&Entry> = entries[i..]
            .iter()
            .take(256)
            .take_while(|e| e.written.reference >> 16 == block)
            .collect();
        let base = group[0].written.number;
        out.extend_from_slice(&(group.len() as u32 - 1).to_le_bytes());
        out.extend_from_slice(&(block as u32).to_le_bytes());
        out.extend_from_slice(&base.to_le_bytes());
        for e in &group {
            out.extend_from_slice(&((e.written.reference & 0xffff) as u16).to_le_bytes());
            let delta = (i64::from(e.written.number) - i64::from(base)) as i16;
            out.extend_from_slice(&delta.to_le_bytes());
            out.extend_from_slice(&e.kind.to_le_bytes());
            out.extend_from_slice(&(e.name.len() as u16 - 1).to_le_bytes());
            out.extend_from_slice(e.name.as_bytes());
        }
        i += group.len();
    }
    out
}

impl SqBuilder {
    fn next_inode(&mut self) -> Written {
        let reference = self.inodes.reference();
        self.references.push(reference);
        Written {
            reference,
            number: self.references.len() as u32,
        }
    }

    /// One data block: nothing for a zero block (sparse, size 0), the
    /// compressed bytes when smaller, else the bytes with the stored bit.
    fn data_block(&mut self, chunk: &[u8], stored: bool) -> u32 {
        if chunk.iter().all(|b| *b == 0) {
            return 0;
        }
        let compressed = self
            .data
            .filter(|_| !stored)
            .map(|c| c(chunk))
            .filter(|c| c.len() < chunk.len());
        match compressed {
            Some(c) => {
                self.image.extend_from_slice(&c);
                c.len() as u32
            }
            None => {
                self.image.extend_from_slice(chunk);
                chunk.len() as u32 | BLOCK_STORED
            }
        }
    }

    /// Put a tail into the fragment block; returns its fragment index and
    /// offset.
    fn add_tail(&mut self, tail: &[u8]) -> (u32, u32) {
        if self.fragment.len() + tail.len() > SQUASHFS_BLOCK_SIZE {
            self.flush_fragment();
        }
        let offset = self.fragment.len() as u32;
        self.fragment.extend_from_slice(tail);
        (self.fragment_entries.len() as u32, offset)
    }

    fn flush_fragment(&mut self) {
        if self.fragment.is_empty() {
            return;
        }
        let start = self.image.len() as u64;
        let block = std::mem::take(&mut self.fragment);
        let compressed = self
            .data
            .map(|c| c(&block))
            .filter(|c| c.len() < block.len());
        let size = match compressed {
            Some(c) => {
                self.image.extend_from_slice(&c);
                c.len() as u32
            }
            None => {
                self.image.extend_from_slice(&block);
                block.len() as u32 | BLOCK_STORED
            }
        };
        self.fragment_entries.push((start, size));
    }

    /// Regular file: data blocks, the tail, then the inode. Basic (type 2):
    /// start block (u32), fragment, fragment offset, file size (u32), block
    /// list. Extended (type 9): start block (u64), file size (u64), sparse
    /// bytes (u64), link count, fragment, fragment offset, xattr, block list.
    fn file(&mut self, f: &SqFile, path: &str) -> Written {
        let tail_len = if f.fragment {
            f.contents.len() % SQUASHFS_BLOCK_SIZE
        } else {
            0
        };
        let blocks_len = f.contents.len() - tail_len;
        let start = self.image.len() as u64;
        let block_list: Vec<u32> = f.contents[..blocks_len]
            .chunks(SQUASHFS_BLOCK_SIZE)
            .map(|chunk| self.data_block(chunk, f.stored))
            .collect();
        self.files.insert(
            path.to_string(),
            Stored {
                start,
                size: self.image.len() as u64 - start,
            },
        );
        let (fragment, offset) = if tail_len > 0 {
            self.add_tail(&f.contents[blocks_len..])
        } else {
            (NO_FRAGMENT, 0)
        };
        let written = self.next_inode();
        let size = f.contents.len() as u64;
        let mut inode;
        if f.extended {
            inode = base_inode(LREG_TYPE, written.number);
            inode.extend_from_slice(&start.to_le_bytes());
            inode.extend_from_slice(&size.to_le_bytes());
            inode.extend_from_slice(&0u64.to_le_bytes());
            inode.extend_from_slice(&1u32.to_le_bytes());
            inode.extend_from_slice(&fragment.to_le_bytes());
            inode.extend_from_slice(&offset.to_le_bytes());
            inode.extend_from_slice(&NO_XATTR.to_le_bytes());
        } else {
            inode = base_inode(REG_TYPE, written.number);
            inode.extend_from_slice(&(start as u32).to_le_bytes());
            inode.extend_from_slice(&fragment.to_le_bytes());
            inode.extend_from_slice(&offset.to_le_bytes());
            inode.extend_from_slice(&(size as u32).to_le_bytes());
        }
        for entry in block_list {
            inode.extend_from_slice(&entry.to_le_bytes());
        }
        self.inodes.write(&inode);
        written
    }

    /// Symbolic link (type 3): link count, target size, then the target
    /// without a NUL.
    fn symlink(&mut self, target: &[u8]) -> Written {
        let written = self.next_inode();
        let mut inode = base_inode(SYMLINK_TYPE, written.number);
        inode.extend_from_slice(&1u32.to_le_bytes());
        inode.extend_from_slice(&(target.len() as u32).to_le_bytes());
        inode.extend_from_slice(target);
        self.inodes.write(&inode);
        written
    }

    /// Directory: children first, then the listing, then the inode. Basic
    /// (type 1): start block, link count, file size (u16), offset (u16),
    /// parent inode number (not read; 0 here). Extended (type 8): link
    /// count, file size (u32), start block, parent, index count (u16),
    /// offset (u16), xattr, then one index entry (listing position, start
    /// block, name size minus one, name).
    fn directory(&mut self, d: &SqDir, path: &str) -> Written {
        let mut entries = Vec::new();
        for child in &d.children {
            let (name, kind, written) = match child {
                SqNode::File(f) => (
                    f.name.clone(),
                    REG_TYPE,
                    self.file(f, &format!("{path}/{}", f.name)),
                ),
                SqNode::Dir(sub) => (
                    sub.name.clone(),
                    DIR_TYPE,
                    self.directory(sub, &format!("{path}/{}", sub.name)),
                ),
                SqNode::Symlink(name, target) => {
                    (name.to_string(), SYMLINK_TYPE, self.symlink(target))
                }
            };
            entries.push(Entry {
                name,
                kind,
                written,
            });
        }
        let position = self.directories.reference();
        let start_block = (position >> 16) as u32;
        let offset = (position & 0xffff) as u16;
        let bytes = listing(&entries);
        self.directories.write(&bytes);
        let file_size = bytes.len() as u32 + 3;
        let written = self.next_inode();
        let mut inode;
        if d.extended {
            inode = base_inode(LDIR_TYPE, written.number);
            inode.extend_from_slice(&2u32.to_le_bytes());
            inode.extend_from_slice(&file_size.to_le_bytes());
            inode.extend_from_slice(&start_block.to_le_bytes());
            inode.extend_from_slice(&0u32.to_le_bytes());
            inode.extend_from_slice(&1u16.to_le_bytes());
            inode.extend_from_slice(&offset.to_le_bytes());
            inode.extend_from_slice(&NO_XATTR.to_le_bytes());
            let first = entries[0].name.as_bytes();
            inode.extend_from_slice(&0u32.to_le_bytes());
            inode.extend_from_slice(&start_block.to_le_bytes());
            inode.extend_from_slice(&(first.len() as u32 - 1).to_le_bytes());
            inode.extend_from_slice(first);
        } else {
            inode = base_inode(DIR_TYPE, written.number);
            inode.extend_from_slice(&start_block.to_le_bytes());
            inode.extend_from_slice(&2u32.to_le_bytes());
            inode.extend_from_slice(&(file_size as u16).to_le_bytes());
            inode.extend_from_slice(&offset.to_le_bytes());
            inode.extend_from_slice(&0u32.to_le_bytes());
        }
        self.inodes.write(&inode);
        written
    }
}

/// Write `bytes` as metadata blocks at the end of `image`; returns the file
/// offset of each block, which is the table's index.
fn write_table(image: &mut Vec<u8>, bytes: &[u8], compress: Option<Compress>) -> Vec<u64> {
    let mut index = Vec::new();
    for chunk in bytes.chunks(METADATA_SIZE) {
        index.push(image.len() as u64);
        image.extend_from_slice(&metadata_block(chunk, compress));
    }
    index
}

fn write_index(image: &mut Vec<u8>, index: &[u64]) -> u64 {
    let start = image.len() as u64;
    for entry in index {
        image.extend_from_slice(&entry.to_le_bytes());
    }
    start
}

/// A SquashFS 4.0 image in mksquashfs order: superblock, compressor
/// options, data and fragment blocks, inode table, directory table,
/// fragment table, export table, id table, xattr tables; then zero padding
/// to 4 KiB. Superblock: magic, inode count, mkfs time, block size,
/// fragment count, compressor, block log, flags, id count, version 4.0,
/// root inode reference, bytes used, then the id, xattr id, inode,
/// directory, fragment and export table starts.
fn squashfs(spec: &SqImage, root: &SqDir) -> SqFixture {
    let mut b = SqBuilder {
        data: spec.data,
        image: vec![0; 96],
        inodes: Metadata::new(spec.metadata),
        directories: Metadata::new(spec.metadata),
        fragment: Vec::new(),
        fragment_entries: Vec::new(),
        references: Vec::new(),
        files: HashMap::new(),
    };
    let mut flags = 0u16;
    if let Some(options) = &spec.options {
        flags |= COMP_OPT;
        b.image.extend_from_slice(&metadata_block(options, None));
    }
    let root_inode = b.directory(root, "");
    b.flush_fragment();
    let inode_table_start = b.image.len() as u64;
    let inodes = b.inodes.finish();
    b.image.extend_from_slice(&inodes);
    let directory_table_start = b.image.len() as u64;
    let directories = b.directories.finish();
    b.image.extend_from_slice(&directories);
    let mut image = b.image;

    let mut entries = Vec::new();
    for (start, size) in &b.fragment_entries {
        entries.extend_from_slice(&start.to_le_bytes());
        entries.extend_from_slice(&size.to_le_bytes());
        entries.extend_from_slice(&0u32.to_le_bytes());
    }
    let fragment_blocks = write_table(&mut image, &entries, spec.metadata);
    let fragment_table_start = write_index(&mut image, &fragment_blocks);

    let lookup_table_start = if spec.export_table {
        let references: Vec<u8> = b.references.iter().flat_map(|r| r.to_le_bytes()).collect();
        let blocks = write_table(&mut image, &references, spec.metadata);
        write_index(&mut image, &blocks)
    } else {
        NO_TABLE
    };

    let id_blocks = write_table(&mut image, &0u32.to_le_bytes(), spec.metadata);
    let id_table_start = write_index(&mut image, &id_blocks);

    let xattr_id_table_start = if spec.xattr_table {
        // One `user.zrax` value: type 0, name size, name, value size, value.
        let xattr_table_start = image.len() as u64;
        let mut xattrs = Vec::new();
        xattrs.extend_from_slice(&0u16.to_le_bytes());
        xattrs.extend_from_slice(&4u16.to_le_bytes());
        xattrs.extend_from_slice(b"zrax");
        xattrs.extend_from_slice(&1u32.to_le_bytes());
        xattrs.push(b'1');
        write_table(&mut image, &xattrs, spec.metadata);
        // One id: xattr reference, count, total size.
        let mut ids = Vec::new();
        ids.extend_from_slice(&0u64.to_le_bytes());
        ids.extend_from_slice(&1u32.to_le_bytes());
        ids.extend_from_slice(&(xattrs.len() as u32).to_le_bytes());
        let blocks = write_table(&mut image, &ids, spec.metadata);
        let header = image.len() as u64;
        image.extend_from_slice(&xattr_table_start.to_le_bytes());
        image.extend_from_slice(&1u32.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        write_index(&mut image, &blocks);
        header
    } else {
        NO_TABLE
    };
    let bytes_used = image.len();

    image[0..4].copy_from_slice(b"hsqs");
    put_u32(&mut image, 4, b.references.len() as u32, true);
    put_u32(&mut image, 12, SQUASHFS_BLOCK_SIZE as u32, true);
    put_u32(&mut image, 16, b.fragment_entries.len() as u32, true);
    put_u16(&mut image, 20, spec.compressor, true);
    put_u16(&mut image, 22, SQUASHFS_BLOCK_LOG, true);
    put_u16(&mut image, 24, flags, true);
    put_u16(&mut image, 26, 1, true);
    put_u16(&mut image, 28, 4, true);
    put_u16(&mut image, 30, 0, true);
    put_u64(&mut image, 32, root_inode.reference, true);
    put_u64(&mut image, 40, bytes_used as u64, true);
    put_u64(&mut image, 48, id_table_start, true);
    put_u64(&mut image, 56, xattr_id_table_start, true);
    put_u64(&mut image, 64, inode_table_start, true);
    put_u64(&mut image, 72, directory_table_start, true);
    put_u64(&mut image, 80, fragment_table_start, true);
    put_u64(&mut image, 88, lookup_table_start, true);
    align(&mut image, 4096);

    let fragments = b
        .fragment_entries
        .iter()
        .map(|(start, size)| Stored {
            start: *start,
            size: u64::from(size & !BLOCK_STORED),
        })
        .collect();
    SqFixture {
        image,
        bytes_used,
        files: b.files,
        fragments,
    }
}

/// An AArch64 ELF spanning two blocks and a tail: the header block, a zero
/// block (sparse in SquashFS, a hole in CramFS), then 100 B.
fn arm64_with_hole() -> Vec<u8> {
    let mut contents = elf64(EM_AARCH64, SQUASHFS_BLOCK_SIZE);
    contents.extend(std::iter::repeat(0).take(SQUASHFS_BLOCK_SIZE));
    contents.extend(text(100));
    contents
}

/// `/bin/app.elf` (x86-64, one block), `/bin/notes.txt` (fragment),
/// `/empty`, `/lib` (extended directory) with `arm64.elf` (extended inode,
/// stored block, sparse block, fragment tail) and `tiny.elf` (x86-64 header
/// only, in the fragment), `/readme` (two blocks of text) and the symlink
/// `/sh`, which is not a regular file.
fn rich_tree() -> SqDir {
    let arm64 = SqFile {
        extended: true,
        fragment: true,
        stored: true,
        ..sq_file("arm64.elf", arm64_with_hole())
    };
    let tiny = SqFile {
        fragment: true,
        ..sq_file("tiny.elf", elf64(EM_X86_64, 64))
    };
    let notes = SqFile {
        fragment: true,
        ..sq_file("notes.txt", text(100))
    };
    sq_dir(
        "",
        vec![
            SqNode::Dir(sq_dir(
                "bin",
                vec![
                    SqNode::File(sq_file("app.elf", payload_elf())),
                    SqNode::File(notes),
                ],
            )),
            SqNode::File(sq_file("empty", Vec::new())),
            SqNode::Dir(SqDir {
                extended: true,
                ..sq_dir("lib", vec![SqNode::File(arm64), SqNode::File(tiny)])
            }),
            SqNode::File(sq_file("readme", text(5000))),
            SqNode::Symlink("sh", b"bin/app.elf"),
        ],
    )
}

fn rich_zlib() -> SqFixture {
    let spec = SqImage {
        metadata: Some(zlib),
        export_table: true,
        xattr_table: true,
        ..sq_image(GZIP, Some(zlib))
    };
    squashfs(&spec, &rich_tree())
}

#[test]
fn squashfs_lists_recognized_members_with_stored_offsets_and_decoded_ranges() {
    let fixture = rich_zlib();
    assert_eq!(detected_layout(&fixture.image), Some(Layout::Squashfs));
    let p = classify(&fixture.image);
    assert_eq!(p.format.format, FileFormat::Squashfs);
    assert_eq!(p.primary.isa, Isa::X86_64, "{:?}", p.notes);
    assert_eq!(
        labels(&p),
        ["/bin/app.elf", "/lib/arm64.elf", "/lib/tiny.elf"]
    );
    assert!(has_note(&p, "6 regular files; 3 recognized members listed"));
    assert!(has_note(&p, "gzip compression (ID 1); block size 4 KiB"));
    assert!(has_note(&p, "Primary ISA selected from /bin/app.elf"));

    let app = slice(&p, "/bin/app.elf");
    let stored = fixture.files["/bin/app.elf"];
    assert_eq!((app.offset, app.size), (stored.start, stored.size));
    let decoded = app.decoded.as_ref().expect("zlib block");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("zlib", 256));
    assert_eq!(app.isa, Isa::X86_64);

    let arm64 = slice(&p, "/lib/arm64.elf");
    assert_eq!(arm64.isa, Isa::AArch64);
    let stored = fixture.files["/lib/arm64.elf"];
    // The stored first block and the empty sparse block; the tail is in
    // the compressed fragment block.
    assert_eq!(stored.size, SQUASHFS_BLOCK_SIZE as u64);
    assert_eq!((arm64.offset, arm64.size), (stored.start, stored.size));
    let decoded = arm64.decoded.as_ref().expect("assembled member");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("zlib", 8292));

    let tiny = slice(&p, "/lib/tiny.elf");
    let fragment = fixture.fragments[0];
    assert_eq!((tiny.offset, tiny.size), (fragment.start, fragment.size));
    assert_eq!(tiny.decoded.as_ref().map(|d| d.size), Some(64));
    assert_eq!(tiny.isa, Isa::X86_64);
}

#[test]
fn squashfs_stored_blocks_and_fragments_keep_file_coordinates() {
    let spec = sq_image(GZIP, None);
    let fixture = squashfs(&spec, &rich_tree());
    let p = classify(&fixture.image);
    assert_eq!(
        labels(&p),
        ["/bin/app.elf", "/lib/arm64.elf", "/lib/tiny.elf"]
    );
    // One stored block: the member is the stored bytes, nothing decoded.
    let app = slice(&p, "/bin/app.elf");
    assert_eq!(
        (app.offset, app.size),
        (fixture.files["/bin/app.elf"].start, 256)
    );
    assert!(app.decoded.is_none());
    // A stored block, a sparse block and a stored tail: assembled.
    let arm64 = slice(&p, "/lib/arm64.elf");
    let decoded = arm64.decoded.as_ref().expect("assembled member");
    assert_eq!(
        (decoded.transform.as_str(), decoded.size),
        ("SquashFS block list", 8292)
    );
    // A tail in a stored fragment block is listed where it is stored:
    // after notes.txt (100 B) and the arm64.elf tail (100 B).
    let tiny = slice(&p, "/lib/tiny.elf");
    assert_eq!(
        (tiny.offset, tiny.size),
        (fixture.fragments[0].start + 200, 64)
    );
    assert!(tiny.decoded.is_none());
}

/// A compressor case: compressor ID, block compressor, options block,
/// codec name in notes and expected options note.
type CompressorCase = (u16, Compress, Option<Vec<u8>>, &'static str, &'static str);

#[test]
fn squashfs_decodes_the_blocks_of_every_compressor_and_reports_options() {
    let cases: [CompressorCase; 6] = [
        (
            GZIP,
            zlib,
            Some(gzip_options()),
            "zlib",
            "gzip options: level 9; window 15",
        ),
        (LZMA, lzma_payload, None, "LZMA", "lzma compression (ID 2)"),
        (
            LZO,
            lzo_payload,
            // lzo1x_999, level 8.
            Some([4u32.to_le_bytes(), 8u32.to_le_bytes()].concat()),
            "LZO1X",
            "lzo options: algorithm lzo1x_999; level 8",
        ),
        (
            XZ,
            xz_payload,
            // 8 KiB dictionary; BCJ filters x86 (bit 0) and arm (bit 3).
            Some([8192u32.to_le_bytes(), 0b1001u32.to_le_bytes()].concat()),
            "xz",
            "BCJ filters requested at build time: x86, arm (not ISA evidence)",
        ),
        (
            LZ4,
            lz4_block,
            // Version 1 (`LZ4_LEGACY`), high compression.
            Some([1u32.to_le_bytes(), 1u32.to_le_bytes()].concat()),
            "LZ4 block",
            "lz4 options: version 1; high compression",
        ),
        (
            ZSTD,
            zstd_payload,
            Some(15u32.to_le_bytes().to_vec()),
            "Zstandard",
            "zstd options: level 15",
        ),
    ];
    for (id, compress, options, transform, note) in cases {
        let spec = SqImage {
            options,
            ..sq_image(id, Some(compress))
        };
        let root = sq_dir("", vec![SqNode::File(sq_file("app.elf", payload_elf()))]);
        let fixture = squashfs(&spec, &root);
        let p = classify(&fixture.image);
        assert_eq!(p.format.format, FileFormat::Squashfs, "ID {id}");
        assert_eq!(p.primary.isa, Isa::X86_64, "ID {id}: {:?}", p.notes);
        assert!(has_note(&p, note), "ID {id}: {:?}", p.notes);
        let app = slice(&p, "/app.elf");
        let decoded = app.decoded.as_ref().expect("compressed block");
        assert_eq!((decoded.transform.as_str(), decoded.size), (transform, 256));
        assert_eq!(app.size, fixture.files["/app.elf"].size, "ID {id}");
        assert!(app.size < 256, "ID {id}: the block is compressed");
    }
}

#[test]
fn squashfs_lz4_without_options_is_noted_and_unknown_compressors_are_errors() {
    let root = sq_dir("", vec![SqNode::File(sq_file("app.elf", payload_elf()))]);
    let fixture = squashfs(&sq_image(LZ4, Some(lz4_block)), &root);
    let p = classify(&fixture.image);
    assert!(has_note(&p, "LZ4 image without compressor options"));
    assert_eq!(p.primary.isa, Isa::X86_64);

    let mut unknown = fixture.image.clone();
    put_u16(&mut unknown, 20, 7, true);
    assert!(error_text(&unknown).contains("Unknown SquashFS compressor ID 7"));
}

#[test]
fn squashfs_metadata_spans_blocks_and_long_listings_split_into_headers() {
    // `a.elf` has an extended inode (60 B), which shifts the 32-byte basic
    // inodes so that `f254`'s inode starts 4 B before the end of the first
    // 8 KiB metadata block and continues in the second.
    let mut children = vec![SqNode::File(SqFile {
        extended: true,
        ..sq_file("a.elf", elf64(EM_AARCH64, 64))
    })];
    for i in 0..300 {
        let contents = if i == 254 { payload_elf() } else { Vec::new() };
        children.push(SqNode::File(sq_file(&format!("f{i:03}"), contents)));
    }
    let root = sq_dir("", vec![SqNode::Dir(sq_dir("etc", children))]);
    for metadata in [None, Some(zlib as Compress)] {
        let spec = SqImage {
            metadata,
            ..sq_image(GZIP, Some(zlib))
        };
        let fixture = squashfs(&spec, &root);
        let p = classify(&fixture.image);
        assert_eq!(labels(&p), ["/etc/a.elf", "/etc/f254"], "{:?}", p.notes);
        assert!(has_note(
            &p,
            "301 regular files; 2 recognized members listed"
        ));
        assert_eq!(slice(&p, "/etc/a.elf").isa, Isa::AArch64);
        assert_eq!(slice(&p, "/etc/f254").isa, Isa::X86_64);
    }
}

#[test]
fn squashfs_without_recognized_members_has_an_unknown_isa() {
    let root = sq_dir("", vec![SqNode::File(sq_file("readme", text(3000)))]);
    let fixture = squashfs(&sq_image(GZIP, Some(zlib)), &root);
    let p = classify(&fixture.image);
    assert_eq!(p.format.format, FileFormat::Squashfs);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "1 regular files; 0 recognized members listed"));
}

#[test]
fn squashfs_undecodable_members_are_noted_not_listed() {
    let fixture = rich_zlib();
    let mut corrupt = fixture.image.clone();
    // Damage the middle of /bin/app.elf's zlib block.
    let app = fixture.files["/bin/app.elf"];
    corrupt[(app.start + app.size / 2) as usize] ^= 0x55;
    let p = classify(&corrupt);
    assert_eq!(labels(&p), ["/lib/arm64.elf", "/lib/tiny.elf"]);
    assert!(has_note(
        &p,
        "1 regular files could not be read and are not listed; first: /bin/app.elf"
    ));
    assert_eq!(p.primary.isa, Isa::AArch64);
}

#[test]
fn squashfs_structure_errors_name_the_field() {
    let fixture = rich_zlib();
    let image = &fixture.image;

    let mut garbage = image.clone();
    assert!(image.len() > fixture.bytes_used + 10, "the image is padded");
    garbage[fixture.bytes_used + 10] = 0x41;
    assert!(error_text(&garbage).contains("after the SquashFS image"));

    let mut block_size = image.clone();
    put_u32(&mut block_size, 12, 3000, true);
    assert!(error_text(&block_size).contains("Invalid SquashFS block size 3000 B"));

    let mut version = image.clone();
    put_u16(&mut version, 28, 5, true);
    assert!(error_text(&version).contains("Unsupported SquashFS version 5.0"));

    let mut id_table = image.clone();
    let id_start = u64::from_le_bytes(image[48..56].try_into().unwrap());
    put_u64(&mut id_table, 48, id_start - 8, true);
    assert!(error_text(&id_table).contains("Invalid SquashFS id table index"));

    let mut inode_start = image.clone();
    let directory_start = u64::from_le_bytes(image[72..80].try_into().unwrap());
    put_u64(&mut inode_start, 64, directory_start, true);
    assert!(error_text(&inode_start).contains("Invalid SquashFS inode table start"));

    let mut truncated = image.clone();
    truncated.truncate(fixture.bytes_used - 1);
    assert!(error_text(&truncated).contains("Truncated SquashFS image"));
}

#[test]
fn squashfs_directory_loops_are_errors() {
    // With stored metadata the root listing is plain bytes: point the
    // `bin` entry at the root directory's own inode.
    let fixture = squashfs(&sq_image(GZIP, Some(zlib)), &rich_tree());
    let mut image = fixture.image.clone();
    let root_offset = u64::from_le_bytes(image[32..40].try_into().unwrap()) & 0xffff;
    let directory_start = u64::from_le_bytes(image[72..80].try_into().unwrap()) as usize;
    let name = image[directory_start..]
        .windows(3)
        .position(|w| w == b"bin")
        .expect("root listing names bin")
        + directory_start;
    // Entry: inode offset, inode number delta, type, name size, name.
    put_u16(&mut image, name - 8, root_offset as u16, true);
    assert!(error_text(&image).contains("listings overlap or repeat"));
}

#[test]
fn squashfs_truncations_and_mutations_are_bounded() {
    let fixture = rich_zlib();
    sweep(&fixture.image, fixture.bytes_used, FileFormat::Squashfs);
    let stored = squashfs(&sq_image(GZIP, None), &rich_tree());
    sweep(&stored.image, stored.bytes_used, FileFormat::Squashfs);
}

/// SquashFS 1.x-3.x superblock (`squashfs_super_block_3`, packed, in the
/// image's byte order): magic, inodes (4), 1.x/2.x bytes used (8, u32),
/// version (28, 30), 1.x block size (32, u16), block log (34), 2.x/3.x
/// block size (51), fragments (55), 3.x bytes used (63, u64); then zeros up
/// to `bytes_used`.
fn legacy_squashfs(le: bool, major: u16, minor: u16) -> Vec<u8> {
    const BYTES_USED: u64 = 4096;
    let mut image = vec![0u8; BYTES_USED as usize];
    let magic = if le { b"hsqs" } else { b"sqsh" };
    image[..4].copy_from_slice(magic);
    put_u32(&mut image, 4, 5, le);
    put_u32(&mut image, 8, BYTES_USED as u32, le);
    put_u16(&mut image, 28, major, le);
    put_u16(&mut image, 30, minor, le);
    put_u16(&mut image, 32, 32768, le);
    put_u16(&mut image, 34, if major == 1 { 15 } else { 17 }, le);
    put_u32(&mut image, 51, 131_072, le);
    put_u32(&mut image, 55, 2, le);
    put_u64(&mut image, 63, BYTES_USED, le);
    image
}

#[test]
fn legacy_and_big_endian_squashfs_are_recognized_but_not_enumerated() {
    let cases = [
        (
            legacy_squashfs(true, 3, 1),
            "SquashFS 3.1, little-endian; block size 128 KiB; 5 inodes; 2 fragments",
        ),
        (
            legacy_squashfs(false, 3, 0),
            "SquashFS 3.0, big-endian; block size 128 KiB; 5 inodes; 2 fragments",
        ),
        (
            legacy_squashfs(false, 2, 1),
            "SquashFS 2.1, big-endian; block size 128 KiB; 5 inodes; 2 fragments",
        ),
        (
            legacy_squashfs(true, 1, 0),
            "SquashFS 1.0, little-endian; block size 32 KiB; 5 inodes",
        ),
        (
            legacy_squashfs(false, 4, 0),
            "Big-endian SquashFS 4.0 superblock",
        ),
    ];
    for (image, note) in cases {
        assert_eq!(detected_layout(&image), Some(Layout::SquashfsLegacy));
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Squashfs);
        assert!(has_note(&p, note), "{note}: {:?}", p.notes);
        assert!(p.slices.is_empty());
        assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    }
    let p = classify(&legacy_squashfs(true, 3, 1));
    assert!(has_note(&p, "Compressor not recorded in the superblock"));
    assert!(has_note(&p, "member enumeration is not implemented"));

    let mut truncated = legacy_squashfs(false, 3, 1);
    truncated.truncate(4000);
    assert!(error_text(&truncated).contains("Truncated SquashFS image"));
    assert!(error_text(&legacy_squashfs(false, 7, 0)).contains("Unsupported SquashFS version"));
}

#[test]
fn legacy_squashfs_truncations_and_mutations_are_bounded() {
    for (le, major, minor) in [(false, 3, 1), (true, 2, 0), (false, 1, 0)] {
        let image = legacy_squashfs(le, major, minor);
        sweep(&image, image.len(), FileFormat::Squashfs);
    }
}

#[test]
fn streamed_squashfs_needs_its_zeroed_placeholder() {
    let mut image = vec![0u8; 4096];
    image[..4].copy_from_slice(b"HSQS");
    image[200] = 0x5a;
    assert_eq!(detected_layout(&image), Some(Layout::SquashfsStreamed));
    let p = classify(&image);
    assert!(has_note(&p, "Streamed SquashFS (little-endian magic"));
    image[50] = 1;
    assert_eq!(detected_layout(&image), None);
}

// CramFS fixtures, built from `cramfs_fs.h` (Linux v6.11) and the
// util-linux v2.40.2 `mkfs.cramfs` layout: superblock, directory entries
// (width-first), file data (block pointers, then zlib blocks), padding to
// the 4 KiB page; every field in the image's byte order.

const CRAMFS_MAGIC: u32 = 0x28cd_3d45;
const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const CRAMFS_SUPERBLOCK_SIZE: usize = 76;
const CRAMFS_PAGE: usize = 4096;
const FLAG_FSID_VERSION_2: u32 = 0x1;
const FLAG_SORTED_DIRS: u32 = 0x2;
const FLAG_HOLES: u32 = 0x100;
const FLAG_EXT_BLOCK_POINTERS: u32 = 0x800;
const BLK_FLAG_UNCOMPRESSED: u32 = 1 << 31;
const BLK_FLAG_DIRECT_PTR: u32 = 1 << 30;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;
const S_IFLNK: u16 = 0o120_000;

enum CramNode {
    File(&'static str, Vec<u8>),
    Dir(&'static str, Vec<CramNode>),
    Symlink(&'static str, &'static [u8]),
    /// A file whose block pointers use the extended flags.
    ExtFile(&'static str, Vec<u8>),
}

impl CramNode {
    fn name(&self) -> &'static str {
        match self {
            Self::File(name, _)
            | Self::Dir(name, _)
            | Self::Symlink(name, _)
            | Self::ExtFile(name, _) => name,
        }
    }
}

struct CramSpec {
    le: bool,
    /// Superblock offset: 0, or 512 after a boot-code pad.
    pad: usize,
    /// Zero blocks become holes (`CRAMFS_FLAG_HOLES`).
    holes: bool,
    /// Extended block pointers (`CRAMFS_FLAG_EXT_BLOCK_POINTERS`).
    extended: bool,
}

/// A built CramFS fixture: the image and each file's stored range (block
/// pointers through the last block) by name.
struct CramFixture {
    image: Vec<u8>,
    files: HashMap<&'static str, Stored>,
}

/// Inode words: `mode:16, uid:16; size:24, gid:8; namelen:6, offset:26`,
/// the first field of each word in its low bits for a little-endian image
/// and in its high bits for a big-endian one. `namelen` and `offset` are
/// in 4-byte units.
fn cram_inode(le: bool, mode: u16, size: usize, name_len: usize, offset: usize) -> Vec<u8> {
    let (size, namelen, offset) = (size as u32, (name_len / 4) as u32, (offset / 4) as u32);
    let words = if le {
        [u32::from(mode), size, namelen | offset << 6]
    } else {
        [u32::from(mode) << 16, size << 8, namelen << 26 | offset]
    };
    let mut out = vec![0u8; 12];
    for (i, word) in words.iter().enumerate() {
        put_u32(&mut out, i * 4, *word, le);
    }
    out
}

/// File data: one u32 pointer per page (the file offset where the block
/// ends), then each block as a zlib stream (or nothing for a hole), then
/// padding to 4 bytes. Returns the pointer table's offset and the end of
/// the last block.
fn cram_data(out: &mut Vec<u8>, contents: &[u8], spec: &CramSpec) -> Stored {
    align(out, 4);
    let table = out.len();
    let blocks = contents.chunks(CRAMFS_PAGE).count();
    out.resize(table + 4 * blocks, 0);
    for (i, chunk) in contents.chunks(CRAMFS_PAGE).enumerate() {
        if !(spec.holes && chunk.iter().all(|b| *b == 0)) {
            out.extend_from_slice(&zlib(chunk));
        }
        let end = out.len() as u32;
        put_u32(out, table + 4 * i, end, spec.le);
    }
    let end = out.len();
    align(out, 4);
    Stored {
        start: table as u64,
        size: (end - table) as u64,
    }
}

/// File data with extended pointers for three blocks: block 0 direct and
/// uncompressed (start / 4 with both flags), block 1 direct and compressed
/// (start / 4 with the direct flag; a u16 length, then the zlib stream),
/// block 2 a plain end pointer, starting where block 1 ends.
fn cram_ext_data(out: &mut Vec<u8>, contents: &[u8], le: bool) -> Stored {
    let chunks: Vec<&[u8]> = contents.chunks(CRAMFS_PAGE).collect();
    assert_eq!(chunks.len(), 3);
    align(out, 4);
    let table = out.len();
    out.resize(table + 12, 0);
    let block0 = out.len();
    out.extend_from_slice(chunks[0]);
    put_u32(
        out,
        table,
        BLK_FLAG_DIRECT_PTR | BLK_FLAG_UNCOMPRESSED | (block0 / 4) as u32,
        le,
    );
    align(out, 4);
    let block1 = out.len();
    let compressed = zlib(chunks[1]);
    out.resize(block1 + 2, 0);
    put_u16(out, block1, compressed.len() as u16, le);
    out.extend_from_slice(&compressed);
    put_u32(
        out,
        table + 4,
        BLK_FLAG_DIRECT_PTR | (block1 / 4) as u32,
        le,
    );
    out.extend_from_slice(&zlib(chunks[2]));
    let end = out.len();
    put_u32(out, table + 8, end as u32, le);
    align(out, 4);
    Stored {
        start: table as u64,
        size: (end - table) as u64,
    }
}

/// A CramFS image: [pad] superblock (magic, size, flags, future,
/// signature, CRC, edition, blocks, files, name, root inode), directory
/// entries width-first (inode, then the name NUL-padded to 4 bytes), file
/// data, zero padding to 4 KiB. The CRC-32 covers the superblock offset to
/// the end with the CRC field zero.
fn cramfs(spec: &CramSpec, root: &[CramNode]) -> CramFixture {
    let le = spec.le;
    let start = spec.pad;
    let mut out = vec![0u8; start + CRAMFS_SUPERBLOCK_SIZE];
    let entry_size = |c: &CramNode| 12 + round_up(c.name().len(), 4);

    let mut dirs: Vec<&[CramNode]> = vec![root];
    let mut k = 0;
    while k < dirs.len() {
        for child in dirs[k] {
            if let CramNode::Dir(_, children) = child {
                dirs.push(children);
            }
        }
        k += 1;
    }
    let mut regions = Vec::new();
    for dir in &dirs {
        let size: usize = dir.iter().map(entry_size).sum();
        regions.push((out.len(), size));
        out.resize(out.len() + size, 0);
    }

    let mut files = HashMap::new();
    let mut data = Vec::new();
    for dir in &dirs {
        for child in dir.iter() {
            let stored = match child {
                CramNode::File(_, contents) if contents.is_empty() => Stored { start: 0, size: 0 },
                CramNode::File(_, contents) => cram_data(&mut out, contents, spec),
                CramNode::Symlink(_, target) => cram_data(&mut out, target, spec),
                CramNode::ExtFile(_, contents) => cram_ext_data(&mut out, contents, le),
                CramNode::Dir(..) => continue,
            };
            files.insert(child.name(), stored);
            data.push(stored.start as usize);
        }
    }

    let mut data = data.into_iter();
    let mut subdirectory = 1;
    let mut inodes = 1;
    for (i, dir) in dirs.iter().enumerate() {
        let mut pos = regions[i].0;
        for child in dir.iter() {
            let (mode, size, offset) = match child {
                CramNode::File(_, contents) | CramNode::ExtFile(_, contents) => (
                    S_IFREG | 0o755,
                    contents.len(),
                    data.next().expect("one offset per file"),
                ),
                CramNode::Symlink(_, target) => (
                    S_IFLNK | 0o777,
                    target.len(),
                    data.next().expect("one offset per file"),
                ),
                CramNode::Dir(..) => {
                    let (offset, size) = regions[subdirectory];
                    subdirectory += 1;
                    (S_IFDIR | 0o755, size, offset)
                }
            };
            let name = child.name().as_bytes();
            let padded = round_up(name.len(), 4);
            let inode = cram_inode(le, mode, size, padded, offset);
            out[pos..pos + 12].copy_from_slice(&inode);
            out[pos + 12..pos + 12 + name.len()].copy_from_slice(name);
            pos += 12 + padded;
            inodes += 1;
        }
    }

    align(&mut out, CRAMFS_PAGE);
    let size = out.len();
    let mut flags = FLAG_FSID_VERSION_2 | FLAG_SORTED_DIRS;
    if spec.holes {
        flags |= FLAG_HOLES;
    }
    if spec.extended {
        flags |= FLAG_EXT_BLOCK_POINTERS;
    }
    put_u32(&mut out, start, CRAMFS_MAGIC, le);
    put_u32(&mut out, start + 4, size as u32, le);
    put_u32(&mut out, start + 8, flags, le);
    out[start + 16..start + 32].copy_from_slice(CRAMFS_SIGNATURE);
    put_u32(&mut out, start + 40, (size / CRAMFS_PAGE) as u32, le);
    put_u32(&mut out, start + 44, inodes, le);
    out[start + 48..start + 58].copy_from_slice(b"Compressed");
    let root_inode = cram_inode(le, S_IFDIR | 0o755, regions[0].1, 0, regions[0].0);
    out[start + 64..start + 76].copy_from_slice(&root_inode);
    let crc = zrax::formats::checksum::crc32(&out[start..size]);
    put_u32(&mut out, start + 32, crc, le);
    CramFixture { image: out, files }
}

/// `/bin/app.elf` (x86-64, one block) and `/bin/busybox` (AArch64: header
/// block, zero block, 100 B), `/empty`, `/readme.txt` and the symlink
/// `/sh`, sorted as `mkfs.cramfs` sorts them.
fn cram_tree() -> Vec<CramNode> {
    vec![
        CramNode::Dir(
            "bin",
            vec![
                CramNode::File("app.elf", payload_elf()),
                CramNode::File("busybox", arm64_with_hole()),
            ],
        ),
        CramNode::File("empty", Vec::new()),
        CramNode::File("readme.txt", text(300)),
        CramNode::Symlink("sh", b"bin/busybox"),
    ]
}

fn cram_spec(le: bool, pad: usize, holes: bool) -> CramSpec {
    CramSpec {
        le,
        pad,
        holes,
        extended: false,
    }
}

#[test]
fn cramfs_lists_members_in_both_byte_orders_and_after_a_pad() {
    for (le, pad, holes) in [(true, 0, true), (false, 0, false), (false, 512, true)] {
        let fixture = cramfs(&cram_spec(le, pad, holes), &cram_tree());
        assert_eq!(detected_layout(&fixture.image), Some(Layout::Cramfs));
        let p = classify(&fixture.image);
        let case = format!("le {le}, pad {pad}");
        assert_eq!(p.format.format, FileFormat::Cramfs, "{case}");
        assert_eq!(
            labels(&p),
            ["/bin/app.elf", "/bin/busybox"],
            "{case}: {:?}",
            p.notes
        );
        assert_eq!(p.primary.isa, Isa::X86_64, "{case}");
        let order = if le { "little-endian" } else { "big-endian" };
        assert!(has_note(&p, &format!("CramFS, {order} (the builder's host order, not ISA evidence); superblock at 0x{pad:X}")), "{case}: {:?}", p.notes);
        assert!(has_note(&p, "CRC-32 0x"), "{case}");
        assert!(
            has_note(&p, "4 regular files; 2 recognized members listed"),
            "{case}"
        );
        assert!(has_note(&p, "block size 4 KiB assumed"), "{case}");

        let app = slice(&p, "/bin/app.elf");
        let stored = fixture.files["app.elf"];
        assert_eq!(
            (app.offset, app.size),
            (stored.start, stored.size),
            "{case}"
        );
        let decoded = app.decoded.as_ref().expect("zlib block");
        assert_eq!((decoded.transform.as_str(), decoded.size), ("zlib", 256));
        let busybox = slice(&p, "/bin/busybox");
        assert_eq!(busybox.isa, Isa::AArch64, "{case}");
        assert_eq!(busybox.decoded.as_ref().map(|d| d.size), Some(8292));
    }
}

#[test]
fn cramfs_extended_block_pointers_are_followed() {
    let mut contents = elf64(EM_AARCH64, CRAMFS_PAGE);
    contents.extend(text(CRAMFS_PAGE + 500));
    let spec = CramSpec {
        extended: true,
        ..cram_spec(true, 0, false)
    };
    let fixture = cramfs(&spec, &[CramNode::ExtFile("ext.elf", contents)]);
    let p = classify(&fixture.image);
    assert!(has_note(
        &p,
        "Flags: sorted directories, extended block pointers"
    ));
    let ext = slice(&p, "/ext.elf");
    assert_eq!(ext.isa, Isa::AArch64);
    let stored = fixture.files["ext.elf"];
    assert_eq!((ext.offset, ext.size), (stored.start, stored.size));
    assert_eq!(ext.decoded.as_ref().map(|d| d.size), Some(2 * 4096 + 500));
}

#[test]
fn cramfs_checks_crc_flags_root_and_size() {
    let fixture = cramfs(&cram_spec(true, 0, true), &cram_tree());
    let image = &fixture.image;

    let mut crc = image.clone();
    crc[image.len() - 1] ^= 1;
    assert!(error_text(&crc).contains("Invalid CramFS CRC-32"));

    let mut flags = image.clone();
    put_u32(&mut flags, 8, FLAG_FSID_VERSION_2 | 0x1000, true);
    assert!(error_text(&flags).contains("Unsupported CramFS flags 0x1000"));

    let mut root = image.clone();
    root[64] = 0;
    root[65] = 0x80;
    assert!(error_text(&root).contains("Invalid CramFS root inode"));

    let mut truncated = image.clone();
    truncated.truncate(image.len() - 4);
    assert!(error_text(&truncated).contains("Truncated CramFS image"));

    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("after the CramFS image"));

    // Without the signature, data at offset 512 is not CramFS.
    let mut unsigned = cramfs(&cram_spec(false, 512, false), &cram_tree()).image;
    unsigned[512 + 16] = b'c';
    assert_eq!(detected_layout(&unsigned), None);
}

#[test]
fn cramfs_old_superblocks_have_no_crc_and_end_with_the_input() {
    for le in [true, false] {
        let mut image = cramfs(&cram_spec(le, 0, false), &cram_tree()).image;
        // Clear `CRAMFS_FLAG_FSID_VERSION_2`: `size`, `fsid` and the CRC are
        // no longer valid, so a corrupt CRC field is not checked.
        put_u32(&mut image, 8, FLAG_SORTED_DIRS, le);
        put_u32(&mut image, 32, 0, le);
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Cramfs);
        assert!(has_note(
            &p,
            "Old superblock without size, file count or CRC-32"
        ));
        assert!(!has_note(&p, "verified"), "{:?}", p.notes);
        assert_eq!(labels(&p), ["/bin/app.elf", "/bin/busybox"]);
    }
}

#[test]
fn cramfs_truncations_and_mutations_are_bounded() {
    for spec in [cram_spec(true, 0, true), cram_spec(false, 512, false)] {
        let fixture = cramfs(&spec, &cram_tree());
        // The directory entries and the first file's data hold every
        // structure; the rest is zlib data and padding.
        let structure = fixture.files["app.elf"].start as usize + 64;
        sweep(&fixture.image, structure, FileFormat::Cramfs);
        for cut in structure..fixture.image.len() {
            assert!(detect_payload(&fixture.image[..cut], &ClassifierOptions::new()).is_err());
        }
    }
}

// romfs fixtures, built from `romfs_fs.h` (Linux v6.11) and the genromfs
// layout: every field big-endian, headers on 16-byte boundaries.

const ROMFH_HRD: u32 = 0;
const ROMFH_DIR: u32 = 1;
const ROMFH_REG: u32 = 2;
const ROMFH_SYM: u32 = 3;
const ROMFH_EXEC: u32 = 8;

enum RomNode {
    File(String, Vec<u8>),
    Dir(&'static str, Vec<RomNode>),
    Symlink(&'static str, &'static [u8]),
}

fn rom_file(name: &str, contents: Vec<u8>) -> RomNode {
    RomNode::File(name.to_string(), contents)
}

/// A romfs image being written: the bytes, every header's offset and
/// metadata size (header plus padded name), and each file's data offset.
struct RomBuilder {
    out: Vec<u8>,
    headers: Vec<(usize, usize)>,
    data: HashMap<String, usize>,
}

impl RomBuilder {
    /// File header: next and type bits (0), spec (4), size (8), checksum
    /// (12), then the name NUL-terminated and padded to 16 bytes.
    fn header(&mut self, name: &str, kind: u32, spec: u32, size: u32) -> usize {
        align(&mut self.out, 16);
        let at = self.out.len();
        self.out.extend_from_slice(&kind.to_be_bytes());
        self.out.extend_from_slice(&spec.to_be_bytes());
        self.out.extend_from_slice(&size.to_be_bytes());
        self.out.extend_from_slice(&0u32.to_be_bytes());
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        align(&mut self.out, 16);
        self.headers.push((at, self.out.len() - at));
        at
    }

    fn set_next(&mut self, at: usize, next: usize) {
        let mode = u32::from_be_bytes(self.out[at..at + 4].try_into().unwrap()) & 15;
        put_u32(&mut self.out, at, next as u32 | mode, false);
    }

    fn set_spec(&mut self, at: usize, spec: usize) {
        put_u32(&mut self.out, at + 4, spec as u32, false);
    }

    /// A directory's entries: `.` (for the root, a directory pointing at
    /// itself; else a hard link to the directory), `..` (a hard link to the
    /// parent), then the children; a subdirectory's entries follow its
    /// header. Returns the offset of the first entry.
    fn listing(&mut self, children: &[RomNode], directory: Option<usize>, parent: usize) -> usize {
        let dot = match directory {
            None => {
                let dot = self.header(".", ROMFH_DIR, 0, 0);
                self.set_spec(dot, dot);
                dot
            }
            Some(directory) => self.header(".", ROMFH_HRD, directory as u32, 0),
        };
        let parent = if directory.is_none() { dot } else { parent };
        let dotdot = self.header("..", ROMFH_HRD, parent as u32, 0);
        self.set_next(dot, dotdot);
        let own = directory.unwrap_or(dot);
        let mut previous = dotdot;
        for child in children {
            let at = match child {
                RomNode::File(name, contents) => {
                    let at = self.header(name, ROMFH_REG | ROMFH_EXEC, 0, contents.len() as u32);
                    self.data.insert(name.clone(), self.out.len());
                    self.out.extend_from_slice(contents);
                    at
                }
                RomNode::Symlink(name, target) => {
                    let at = self.header(name, ROMFH_SYM, 0, target.len() as u32);
                    self.out.extend_from_slice(target);
                    at
                }
                RomNode::Dir(name, entries) => {
                    let at = self.header(name, ROMFH_DIR, 0, 0);
                    let first = self.listing(entries, Some(at), own);
                    self.set_spec(at, first);
                    at
                }
            };
            self.set_next(previous, at);
            previous = at;
        }
        dot
    }
}

/// Sum of the big-endian words of `bytes`.
fn word_sum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |sum, w| {
        sum.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    })
}

/// A romfs image: superblock (`-rom1fs-`, size, checksum, volume name
/// padded to 16), the root listing, padding to 16 for the recorded size,
/// then zeros to 1 KiB as genromfs pads. Each header's checksum makes the
/// header and padded name sum to 0; the superblock checksum makes the first
/// 512 bytes sum to 0. Returns the image, the recorded size and each
/// file's data offset.
fn romfs(volume: &str, root: &[RomNode]) -> (Vec<u8>, usize, HashMap<String, usize>) {
    let mut b = RomBuilder {
        out: b"-rom1fs-".to_vec(),
        headers: Vec::new(),
        data: HashMap::new(),
    };
    b.out.extend_from_slice(&[0; 8]);
    b.out.extend_from_slice(volume.as_bytes());
    b.out.push(0);
    b.listing(root, None, 0);
    align(&mut b.out, 16);
    let size = b.out.len();
    put_u32(&mut b.out, 8, size as u32, false);
    for &(at, meta) in &b.headers {
        let sum = word_sum(&b.out[at..at + meta]);
        put_u32(&mut b.out, at + 12, 0u32.wrapping_sub(sum), false);
    }
    let sum = word_sum(&b.out[..size.min(512)]);
    put_u32(&mut b.out, 12, 0u32.wrapping_sub(sum), false);
    align(&mut b.out, 1024);
    (b.out, size, b.data)
}

/// `/bin/app.elf` (x86-64), `/bin/readme.txt`, `/arm64.elf` (AArch64) and
/// the symlink `/sh`.
fn rom_tree() -> Vec<RomNode> {
    vec![
        RomNode::Dir(
            "bin",
            vec![
                rom_file("app.elf", payload_elf()),
                rom_file("readme.txt", text(300)),
            ],
        ),
        rom_file("arm64.elf", elf64(EM_AARCH64, 600)),
        RomNode::Symlink("sh", b"bin/app.elf"),
    ]
}

#[test]
fn romfs_lists_members_where_they_are_stored() {
    let (image, size, data) = romfs("zrax", &rom_tree());
    assert_eq!(detected_layout(&image), Some(Layout::Romfs));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Romfs);
    assert_eq!(labels(&p), ["/bin/app.elf", "/arm64.elf"], "{:?}", p.notes);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(
        &p,
        &format!("romfs, big-endian; volume \"zrax\"; {size} B; superblock checksum verified")
    ));
    assert!(has_note(&p, "File header checksums verified"));
    assert!(has_note(&p, "3 regular files; 2 recognized members listed"));
    let app = slice(&p, "/bin/app.elf");
    assert_eq!((app.offset, app.size), (data["app.elf"] as u64, 256));
    assert!(app.decoded.is_none());
    assert_eq!(slice(&p, "/arm64.elf").isa, Isa::AArch64);
}

#[test]
fn romfs_checksums_and_loops() {
    let (image, _, data) = romfs("zrax", &rom_tree());

    let mut superblock = image.clone();
    superblock[20] ^= 1;
    assert!(error_text(&superblock).contains("Invalid romfs superblock checksum"));

    // A file header checksum outside the first 512 bytes is advisory, as
    // in Linux: noted, and the file is still listed.
    let arm64_header = data["arm64.elf"] - 32;
    assert!(arm64_header >= 512);
    let mut header = image.clone();
    header[arm64_header + 12] ^= 1;
    let p = classify(&header);
    assert!(has_note(&p, &format!("1 file headers fail their checksum (Linux does not check them); first at 0x{arm64_header:X}")), "{:?}", p.notes);
    assert_eq!(labels(&p), ["/bin/app.elf", "/arm64.elf"]);

    // Point /bin's first entry at the root listing: the walk repeats. The
    // root `.` header follows the volume name; `..` and `bin` follow it.
    let be_word = |at: usize| u32::from_be_bytes(image[at..at + 4].try_into().unwrap()) as usize;
    let root = 32;
    assert_eq!(&image[root + 16..root + 18], b".\0");
    let dotdot = be_word(root) & !15;
    let bin = be_word(dotdot) & !15;
    assert_eq!(&image[bin + 16..bin + 19], b"bin");
    // Rebalance the header checksum by the same amount, so the header and
    // the superblock region still sum to zero.
    let mut looped = image.clone();
    let delta = (root as u32).wrapping_sub(be_word(bin + 4) as u32);
    put_u32(&mut looped, bin + 4, root as u32, false);
    let checksum = (be_word(bin + 12) as u32).wrapping_sub(delta);
    put_u32(&mut looped, bin + 12, checksum, false);
    let looped_error = error_text(&looped);
    assert!(
        looped_error.contains("file headers repeat"),
        "{looped_error}"
    );

    let mut trailing = image.clone();
    let last = trailing.len() - 1;
    trailing[last] = 0x41;
    assert!(error_text(&trailing).contains("after the romfs image"));
}

#[test]
fn romfs_truncations_and_mutations_are_bounded() {
    let (image, size, _) = romfs("zrax", &rom_tree());
    sweep(&image, size, FileFormat::Romfs);
}

/// A chain of `levels` directories named `d`, the innermost holding
/// `files`.
fn nested_rom_dirs(levels: usize, files: Vec<RomNode>) -> RomNode {
    let mut node = RomNode::Dir("d", files);
    for _ in 1..levels {
        node = RomNode::Dir("d", vec![node]);
    }
    node
}

#[test]
fn romfs_directories_past_the_walk_depth_are_noted_not_walked() {
    // `a.elf` is 64 directories deep, the deepest level that is walked;
    // `b.elf` is one level further.
    let deepest = nested_rom_dirs(1, vec![rom_file("b.elf", elf64(EM_AARCH64, 64))]);
    let level_64 = nested_rom_dirs(64, vec![rom_file("a.elf", elf64(EM_X86_64, 64)), deepest]);
    let (image, _, _) = romfs("deep", &[level_64]);
    let p = classify(&image);
    let path = format!("{}/a.elf", "/d".repeat(64));
    assert_eq!(labels(&p), [path.as_str()], "{:?}", p.notes);
    assert!(has_note(&p, "1 regular files; 1 recognized members listed"));
    assert!(has_note(
        &p,
        "1 directories nested deeper than 64 levels or 4096 B were not walked"
    ));
}

#[test]
fn romfs_member_limit_is_noted() {
    let files: Vec<RomNode> = (0..4097)
        .map(|i| rom_file(&format!("f{i:04}"), elf64(EM_X86_64, 64)))
        .collect();
    let (image, _, _) = romfs("many", &files);
    let p = classify(&image);
    assert_eq!(p.slices.len(), 4096);
    assert!(has_note(
        &p,
        "4097 regular files; 4096 recognized members listed"
    ));
    assert!(has_note(
        &p,
        "Member limit reached (4096 members); 1 further regular files were not examined"
    ));
}

#[test]
fn raw_lzo1x_and_lz4_blocks_decode_through_the_codec_layer() {
    let payload = payload_elf();
    let lzo = compressed::decode_limited(Codec::Lzo1x, &lzo_payload(&payload), 4096).unwrap();
    assert_eq!(lzo.data, payload);
    let lz4 = compressed::decode_limited(Codec::Lz4Block, &lz4_block(&payload), 4096).unwrap();
    assert_eq!(lz4.data, payload);
    assert!(compressed::decode_limited(Codec::Lz4Block, &lz4_block(&payload), 255).is_err());
}
