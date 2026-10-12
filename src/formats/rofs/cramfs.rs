//! Cramfs in either byte order: superblock, CRC-32, inode bitfields,
//! directory walk and zlib-compressed blocks (sources in the family
//! module).
//!
//! Every field is in the builder's host byte order, which the magic
//! reveals. All offsets are file offsets from the start of the input, also
//! when the superblock follows a 512-byte boot-code pad. A regular file is
//! a table of block pointers followed by its blocks; each block holds one
//! page of the file, compressed as a zlib stream.

use super::*;

/// `CRAMFS_MAGIC`, read in the image's byte order.
const CRAMFS_MAGIC: u32 = 0x28cd_3d45;

/// `CRAMFS_MAGIC_WEND`: the magic of an image in the other byte order.
const CRAMFS_MAGIC_WEND: u32 = 0x453d_cd28;

/// `CRAMFS_SIGNATURE`, at superblock offset 16.
const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const SIGNATURE_OFFSET: usize = 16;

/// Superblock: magic, size, flags, future, signature, fsid (CRC,
/// edition, blocks, files), volume name, root inode.
const SUPERBLOCK_SIZE: usize = 76;

/// Offset of `fsid.crc` in the superblock.
const CRC_OFFSET: usize = 32;

/// Offset of the root inode in the superblock.
const ROOT_OFFSET: usize = 64;

/// Volume name field: 16 bytes, NUL-padded.
const NAME_OFFSET: usize = 48;
const NAME_SIZE: usize = 16;

/// Boot-code pad that `mkfs.cramfs -p` leaves before the superblock
/// (`PAD_SIZE`).
const PAD_SIZE: usize = 512;

/// Superblock flags (`cramfs_fs.h`).
const FLAG_FSID_VERSION_2: u32 = 0x0000_0001;
const FLAG_SORTED_DIRS: u32 = 0x0000_0002;
const FLAG_HOLES: u32 = 0x0000_0100;
const FLAG_WRONG_SIGNATURE: u32 = 0x0000_0200;
const FLAG_SHIFTED_ROOT_OFFSET: u32 = 0x0000_0400;
const FLAG_EXT_BLOCK_POINTERS: u32 = 0x0000_0800;

/// Flags Linux accepts (`CRAMFS_SUPPORTED_FLAGS`): the low byte and the
/// four feature flags.
const SUPPORTED_FLAGS: u32 = 0x0000_00ff
    | FLAG_HOLES
    | FLAG_WRONG_SIGNATURE
    | FLAG_SHIFTED_ROOT_OFFSET
    | FLAG_EXT_BLOCK_POINTERS;

/// Names of the feature flags, for notes.
const FLAG_NAMES: [(u32, &str); 5] = [
    (FLAG_SORTED_DIRS, "sorted directories"),
    (FLAG_HOLES, "holes"),
    (FLAG_WRONG_SIGNATURE, "wrong signature"),
    (FLAG_SHIFTED_ROOT_OFFSET, "shifted root offset"),
    (FLAG_EXT_BLOCK_POINTERS, "extended block pointers"),
];

/// Inode size: mode and uid; size and gid; name length and offset.
const INODE_SIZE: usize = 12;

/// Inode bitfield widths (`struct cramfs_inode`).
const SIZE_WIDTH: u32 = 24;
const NAMELEN_WIDTH: u32 = 6;
const OFFSET_WIDTH: u32 = 26;

/// Name lengths and offsets are stored in 4-byte units.
const UNIT_SHIFT: u32 = 2;

/// File type bits of `mode` (POSIX `S_IFMT`, `S_IFDIR`, `S_IFREG`).
const S_IFMT: u16 = 0o170_000;
const S_IFDIR: u16 = 0o040_000;
const S_IFREG: u16 = 0o100_000;

/// Block pointer flags (`CRAMFS_BLK_FLAG_*`), used with
/// `CRAMFS_FLAG_EXT_BLOCK_POINTERS`.
const BLK_FLAG_UNCOMPRESSED: u32 = 1 << 31;
const BLK_FLAG_DIRECT_PTR: u32 = 1 << 30;
const BLK_FLAGS: u32 = BLK_FLAG_UNCOMPRESSED | BLK_FLAG_DIRECT_PTR;

/// A direct block pointer holds the block start in 4-byte units
/// (`CRAMFS_BLK_DIRECT_PTR_SHIFT`).
const BLK_DIRECT_PTR_SHIFT: u32 = 2;

/// Size of the length prefix of a direct, compressed block.
const DIRECT_LENGTH_SIZE: usize = 2;

/// Block size: the builder's page size, which the image does not record.
/// 4 KiB is the `mkfs.cramfs` default on common hosts and is assumed.
const BLOCK_SIZE: usize = 4096;

/// Largest stored block Linux accepts: two pages compressed, one page
/// uncompressed (`cramfs_read_folio`).
const MAX_COMPRESSED_BLOCK: usize = 2 * BLOCK_SIZE;

/// The transform of a member assembled from holes and stored blocks
/// without decoding.
const ASSEMBLED: &str = "CramFS block list";

/// Strong recognition: the magic in either byte order at offset 0, or
/// at offset 512 followed by the signature (a boot-code pad comes first,
/// so the signature is required there).
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if magic_order(data, 0).is_some() {
        return Some(Layout::Cramfs);
    }
    magic_order(data, PAD_SIZE)?;
    let signature = PAD_SIZE + SIGNATURE_OFFSET;
    let signed = data.get(signature..signature + CRAMFS_SIGNATURE.len()) == Some(CRAMFS_SIGNATURE);
    signed.then_some(Layout::Cramfs)
}

/// The byte order of a Cramfs magic at `at`: true for little-endian.
fn magic_order(data: &[u8], at: usize) -> Option<bool> {
    match le_u32(data, at).ok()? {
        CRAMFS_MAGIC => Some(true),
        CRAMFS_MAGIC_WEND => Some(false),
        _ => None,
    }
}

/// An inode: `mode:16, uid:16; size:24, gid:8; namelen:6, offset:26`, in
/// the image's byte order. In a little-endian image the first field of
/// each word is its low bits; in a big-endian image, its high bits.
struct Inode {
    mode: u16,
    /// File size, or total entry bytes of a directory.
    size: u32,
    /// Name bytes after the inode (the field times 4).
    name_len: usize,
    /// File offset of the block pointers or first entry (the field times
    /// 4); 0 when there are none.
    offset: usize,
}

impl Inode {
    fn is_directory(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

fn low_bits(value: u32, width: u32) -> u32 {
    value & ((1 << width) - 1)
}

/// The inode at file offset `at`.
fn inode(image: &[u8], at: usize, le: bool) -> Result<Inode> {
    let raw = slice(image, at, INODE_SIZE)?;
    let mode = u16_at(raw, 0, le)?;
    let size_gid = u32_at(raw, 4, le)?;
    let name_offset = u32_at(raw, 8, le)?;
    let (size, namelen, offset) = if le {
        (
            low_bits(size_gid, SIZE_WIDTH),
            low_bits(name_offset, NAMELEN_WIDTH),
            name_offset >> NAMELEN_WIDTH,
        )
    } else {
        (
            size_gid >> (32 - SIZE_WIDTH),
            name_offset >> OFFSET_WIDTH,
            low_bits(name_offset, OFFSET_WIDTH),
        )
    };
    Ok(Inode {
        mode,
        size,
        // Both fields are at most 26 bits, so the products fit in usize.
        name_len: (namelen as usize) << UNIT_SHIFT,
        offset: (offset as usize) << UNIT_SHIFT,
    })
}

/// The superblock fields the reader uses.
struct Superblock {
    le: bool,
    /// File offset of the superblock (0 or 512).
    start: usize,
    /// File offset where the image ends: `size` with `FSID_VERSION_2`,
    /// otherwise the end of the input.
    end: usize,
    flags: u32,
    /// `fsid` (CRC, edition, blocks, files), with `FSID_VERSION_2`.
    fsid: Option<Fsid>,
    root: Inode,
}

/// The filesystem identification of a version 2 superblock.
struct Fsid {
    crc: u32,
    edition: u32,
    blocks: u32,
    files: u32,
}

/// Superblock (76 bytes, image byte order): magic, size (4), flags (8),
/// future (12), signature (16), `fsid` CRC (32), edition (36), blocks (40)
/// and files (44), volume name (48), root inode (64). Checked in Linux
/// order (`cramfs_read_super`), then `fsck.cramfs` (`test_super`,
/// `test_crc`).
fn superblock(data: &[u8]) -> Result<Superblock> {
    let (start, le) = match (magic_order(data, 0), magic_order(data, PAD_SIZE)) {
        (Some(le), _) => (0, le),
        (None, Some(le)) => (PAD_SIZE, le),
        (None, None) => return Err(error("Missing CramFS magic")),
    };
    let header = slice(data, start, SUPERBLOCK_SIZE)?;
    let flags = u32_at(header, 8, le)?;
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(error(format!(
            "Unsupported CramFS flags 0x{:X}",
            flags & !SUPPORTED_FLAGS
        )));
    }
    let root = inode(header, ROOT_OFFSET, le)?;
    if !root.is_directory() {
        return Err(error(format!(
            "Invalid CramFS root inode: mode 0o{:o} is not a directory",
            root.mode
        )));
    }
    let shifted = flags & FLAG_SHIFTED_ROOT_OFFSET != 0;
    let expected_root = [SUPERBLOCK_SIZE, PAD_SIZE + SUPERBLOCK_SIZE];
    if root.offset != 0 && !shifted && !expected_root.contains(&root.offset) {
        return Err(error(format!(
            "Invalid CramFS root offset 0x{:X}",
            root.offset
        )));
    }
    let (end, fsid) = if flags & FLAG_FSID_VERSION_2 == 0 {
        (data.len(), None)
    } else {
        let fsid = Fsid {
            crc: u32_at(header, CRC_OFFSET, le)?,
            edition: u32_at(header, 36, le)?,
            blocks: u32_at(header, 40, le)?,
            files: u32_at(header, 44, le)?,
        };
        (image_end(data, header, start, le, &fsid)?, Some(fsid))
    };
    Ok(Superblock {
        le,
        start,
        end,
        flags,
        fsid,
        root,
    })
}

/// The image end a version 2 superblock records, after checking it and
/// the CRC-32 over `start..size` with the CRC field taken as zero.
fn image_end(data: &[u8], header: &[u8], start: usize, le: bool, fsid: &Fsid) -> Result<usize> {
    let size = to_usize(u32_at(header, 4, le)?.into(), "CramFS size")?;
    if size < start + SUPERBLOCK_SIZE {
        return Err(error(format!("Invalid CramFS size {size} B")));
    }
    if size > data.len() {
        return Err(error(format!(
            "Truncated CramFS image: size is {size} B, {} B present",
            data.len()
        )));
    }
    if fsid.files == 0 {
        return Err(error("Invalid CramFS file count 0"));
    }
    let crc_at = start + CRC_OFFSET;
    let mut crc = checksum::crc32_update(!0, &data[start..crc_at]);
    crc = checksum::crc32_update(crc, &[0; 4]);
    crc = !checksum::crc32_update(crc, &data[crc_at + 4..size]);
    if crc != fsid.crc {
        return Err(error(format!(
            "Invalid CramFS CRC-32: stored 0x{:08X}, computed 0x{crc:08X}",
            fsid.crc
        )));
    }
    Ok(size)
}

/// Where block `i` of a file is stored.
#[derive(Clone, Copy)]
struct StoredBlock {
    start: usize,
    len: usize,
    compressed: bool,
}

/// One block of a file as read: its bytes and where they are stored.
struct Block<'a> {
    bytes: Cow<'a, [u8]>,
    stored: StoredBlock,
}

/// A block pointer split into its flags and value. Without extended
/// pointers there are no flags.
struct BlockPointer {
    uncompressed: bool,
    direct: bool,
    value: u32,
}

impl BlockPointer {
    /// File offset of a direct block's start.
    fn direct_start(&self) -> usize {
        // The value has at most 30 bits, so the start fits in 32 bits.
        (self.value as usize) << BLK_DIRECT_PTR_SHIFT
    }
}

/// A regular file: its block pointer table and size.
struct RegularFile {
    /// File offset of the block pointer table.
    offset: usize,
    /// Size in bytes (at most 16 MiB - 1).
    size: usize,
}

impl RegularFile {
    /// One block pointer per started block.
    fn blocks(&self) -> usize {
        (self.size + BLOCK_SIZE - 1) / BLOCK_SIZE
    }

    /// Decoded size of block `i`: a whole block, or the remainder.
    fn block_len(&self, i: usize) -> usize {
        self.size.saturating_sub(i * BLOCK_SIZE).min(BLOCK_SIZE)
    }
}

/// Reads regular file data from block pointers.
struct Reader<'a> {
    image: &'a [u8],
    le: bool,
    /// `CRAMFS_FLAG_EXT_BLOCK_POINTERS`: pointers carry the uncompressed
    /// and direct flags.
    extended: bool,
}

impl<'a> Reader<'a> {
    /// Block pointer `i` of `file`.
    fn pointer(&self, file: &RegularFile, i: usize) -> Result<BlockPointer> {
        let pointer = u32_at(self.image, file.offset + i * 4, self.le)?;
        if !self.extended {
            return Ok(BlockPointer {
                uncompressed: false,
                direct: false,
                value: pointer,
            });
        }
        Ok(BlockPointer {
            uncompressed: pointer & BLK_FLAG_UNCOMPRESSED != 0,
            direct: pointer & BLK_FLAG_DIRECT_PTR != 0,
            value: pointer & !BLK_FLAGS,
        })
    }

    /// File offset after the block pointer table.
    fn table_end(&self, file: &RegularFile) -> Result<usize> {
        let table_size = file.blocks() * 4;
        slice(self.image, file.offset, table_size)?;
        Ok(file.offset + table_size)
    }

    /// The length prefix of a direct, compressed block at `start`.
    fn direct_length(&self, start: usize) -> Result<usize> {
        Ok(usize::from(u16_at(self.image, start, self.le)?))
    }

    /// Where block `i` is stored. A plain pointer is the file offset of
    /// the block's end, and a block starts where the previous one ends
    /// (block 0 after the pointer table). With extended pointers, a direct
    /// pointer holds the block start in 4-byte units: an uncompressed
    /// direct block is one page (or the file's remainder), a compressed one
    /// starts with its length as a u16 (`cramfs_read_folio`).
    fn stored_block(&self, file: &RegularFile, i: usize) -> Result<StoredBlock> {
        let pointer = self.pointer(file, i)?;
        if pointer.direct {
            let start = pointer.direct_start();
            if pointer.uncompressed {
                return Ok(StoredBlock {
                    start,
                    len: file.block_len(i),
                    compressed: false,
                });
            }
            let len = self.direct_length(start)?;
            return Ok(StoredBlock {
                // `direct_length` read two bytes at `start`.
                start: start + DIRECT_LENGTH_SIZE,
                len,
                compressed: true,
            });
        }
        let start = if i == 0 {
            self.table_end(file)?
        } else {
            self.block_end(file, i - 1)?
        };
        let len = (pointer.value as usize).checked_sub(start).ok_or_else(|| {
            error(format!(
                "Invalid CramFS block pointer 0x{:08X} of block {i}: before the block start 0x{start:X}",
                pointer.value
            ))
        })?;
        Ok(StoredBlock {
            start,
            len,
            compressed: !pointer.uncompressed,
        })
    }

    /// File offset where block `i` ends, which is where block `i + 1`
    /// starts when its pointer is not direct.
    fn block_end(&self, file: &RegularFile, i: usize) -> Result<usize> {
        let pointer = self.pointer(file, i)?;
        if !pointer.direct {
            return Ok(pointer.value as usize);
        }
        let start = pointer.direct_start();
        let len = if pointer.uncompressed {
            BLOCK_SIZE
        } else {
            DIRECT_LENGTH_SIZE + self.direct_length(start)?
        };
        start
            .checked_add(len)
            .ok_or_else(|| error("Invalid CramFS block pointer: offset overflow"))
    }

    /// Block `i` as `file.block_len(i)` bytes: a hole when its stored
    /// length is 0, its stored bytes when uncompressed, else the decoded
    /// zlib stream.
    fn block(&self, file: &RegularFile, i: usize) -> Result<Block<'a>> {
        let stored = self.stored_block(file, i)?;
        let expected = file.block_len(i);
        if stored.len == 0 {
            return Ok(Block {
                bytes: Cow::Owned(vec![0; expected]),
                stored,
            });
        }
        let limit = if stored.compressed {
            MAX_COMPRESSED_BLOCK
        } else {
            BLOCK_SIZE
        };
        let start = stored.start;
        if stored.len > limit {
            return Err(error(format!(
                "Invalid CramFS block at 0x{start:X}: {} B stored",
                stored.len
            )));
        }
        let raw = slice(self.image, start, stored.len)?;
        let bytes = if stored.compressed {
            let decoded = compressed::decode_limited(Codec::Zlib, raw, expected)
                .map_err(|e| error(format!("Invalid CramFS block at 0x{start:X}: {e}")))?;
            Cow::Owned(decoded.data)
        } else {
            Cow::Borrowed(raw)
        };
        if bytes.len() != expected {
            return Err(error(format!(
                "Invalid CramFS block at 0x{start:X}: {} B, expected {expected} B",
                bytes.len()
            )));
        }
        Ok(Block { bytes, stored })
    }
}

impl<'a> FileReader<'a> for Reader<'a> {
    type File = RegularFile;

    fn size(&self, file: &RegularFile) -> u64 {
        file.size as u64
    }

    fn first_block_size(&self, file: &RegularFile) -> usize {
        file.block_len(0)
    }

    fn first_block(
        &mut self,
        file: &RegularFile,
        _budget: &mut Budget,
    ) -> std::result::Result<Cow<'a, [u8]>, Unread> {
        if file.size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        Ok(self.block(file, 0)?.bytes)
    }

    fn member(
        &mut self,
        file: &RegularFile,
        path: String,
        first: Cow<'a, [u8]>,
        _budget: &mut Budget,
    ) -> std::result::Result<Child<'a>, Unread> {
        let mut contents = Vec::with_capacity(file.size);
        contents.extend_from_slice(&first);
        let mut stored_start = file.offset;
        let mut stored_end = self.table_end(file)?;
        let mut decoded = false;
        for i in 0..file.blocks() {
            let stored = if i == 0 {
                self.stored_block(file, 0)?
            } else {
                let block = self.block(file, i)?;
                contents.extend_from_slice(&block.bytes);
                block.stored
            };
            if stored.len > 0 {
                decoded |= stored.compressed;
                // `block` found the stored bytes inside the image.
                stored_start = stored_start.min(stored.start);
                stored_end = stored_end.max(stored.start + stored.len);
            }
        }
        let transform = if decoded {
            Codec::Zlib.name()
        } else {
            ASSEMBLED
        };
        Ok(Child::decoded(
            path,
            stored_start,
            stored_end - stored_start,
            Cow::Owned(contents),
            transform,
        ))
    }
}

/// Walks the directory tree from the root, examining every regular file.
struct Walker<'a> {
    image: &'a [u8],
    le: bool,
    reader: Reader<'a>,
    members: Members<'a>,
    /// Entry bytes walked; more than the image holds means directories
    /// repeat (a loop).
    walked: usize,
    path: WalkPath,
}

impl Walker<'_> {
    /// Walk the entries of `dir`: each an inode followed by its NUL-padded
    /// name, contiguous from the directory's offset for `size` bytes.
    fn walk(&mut self, dir: &Inode, depth: usize) -> Result<()> {
        let size = dir.size as usize;
        if size == 0 {
            return Ok(());
        }
        self.walked = self
            .walked
            .checked_add(size)
            .filter(|walked| *walked <= self.image.len())
            .ok_or_else(|| error("Invalid CramFS directory structure: directories repeat"))?;
        let start = dir.offset;
        slice(self.image, start, size)?;
        // The entries lie in the image, so their end is a file offset.
        let end = start + size;
        let mut pos = start;
        while pos < end {
            let entry = inode(self.image, pos, self.le)?;
            let name_start = pos + INODE_SIZE;
            let name_end = name_start + entry.name_len;
            if name_end > end {
                return Err(error(format!(
                    "Invalid CramFS directory entry at 0x{pos:X}: crosses the directory end 0x{end:X}"
                )));
            }
            let padded = &self.image[name_start..name_end];
            let used = padded
                .iter()
                .rposition(|b| *b != 0)
                .map_or(0, |last| last + 1);
            if let Some(name) = entry_name(&padded[..used], pos, "CramFS")? {
                let parent_len = self.path.push(&name);
                let visited = self.visit(&entry, depth);
                self.path.restore(parent_len);
                visited?;
            }
            pos = name_end;
        }
        Ok(())
    }

    /// Descend into a directory or examine a regular file; symlinks,
    /// devices, FIFOs and sockets hold no code.
    fn visit(&mut self, entry: &Inode, depth: usize) -> Result<()> {
        if entry.is_directory() {
            if is_walkable(depth + 1, self.path.as_str()) {
                self.walk(entry, depth + 1)?;
            } else {
                self.members.unwalked_directories += 1;
            }
        } else if entry.is_regular() {
            let file = RegularFile {
                offset: entry.offset,
                size: entry.size as usize,
            };
            self.members
                .examine(&mut self.reader, &file, self.path.as_str());
        }
        Ok(())
    }
}

/// Feature flags set in `flags`, by name.
fn flag_names(flags: u32) -> Vec<&'static str> {
    FLAG_NAMES
        .iter()
        .filter(|(flag, _)| flags & flag != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Parse a Cramfs image and list its recognized regular files.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let sb = superblock(data)?;
    expect_padding(data, sb.end, "CramFS")?;
    let image = &data[..sb.end];
    let order = if sb.le { "little-endian" } else { "big-endian" };

    let mut c = Container::new(FileFormat::Cramfs, Layout::Cramfs.label(), "cramfs");
    c.consumed = sb.end;
    c.notes.push(format!(
        "CramFS, {order} (the builder's host order, not ISA evidence); superblock at 0x{:X}",
        sb.start
    ));
    match &sb.fsid {
        Some(fsid) => c.notes.push(format!(
            "Version 2 superblock: {} B; {} files; {} blocks; edition {}; CRC-32 0x{:08X} verified",
            sb.end, fsid.files, fsid.blocks, fsid.edition, fsid.crc
        )),
        None => c.notes.push(
            "Old superblock without size, file count or CRC-32; the image is taken to end with the input"
                .to_string(),
        ),
    }
    let flags = flag_names(sb.flags);
    if !flags.is_empty() {
        c.notes.push(format!("Flags: {}", flags.join(", ")));
    }
    let header = slice(image, sb.start, SUPERBLOCK_SIZE)?;
    if slice(header, SIGNATURE_OFFSET, CRAMFS_SIGNATURE.len())? != CRAMFS_SIGNATURE {
        c.notes
            .push("Signature field is not \"Compressed ROMFS\"".to_string());
    }
    let name = slice(header, NAME_OFFSET, NAME_SIZE)?;
    let name_len = name.iter().position(|b| *b == 0).unwrap_or(NAME_SIZE);
    let name = String::from_utf8_lossy(&name[..name_len]).into_owned();
    c.notes.push(format!(
        "Volume name \"{}\"; block size 4 KiB assumed (the builder's page size is not recorded)",
        name.escape_debug()
    ));
    if sb.root.offset == 0 {
        c.notes.push("Empty filesystem (root offset 0)".to_string());
    }
    if let Some(note) = padding_note(data, sb.end) {
        c.notes.push(note);
    }
    c.push_metadata("cramfs_byte_order", "Byte order", order);
    c.push_metadata(
        "cramfs_superblock_offset",
        "Superblock offset (B)",
        sb.start as u64,
    );
    c.push_metadata("cramfs_volume_name", "Volume name", name);
    if let Some(fsid) = &sb.fsid {
        c.push_metadata("cramfs_files", "Files", u64::from(fsid.files));
        c.push_metadata(
            "cramfs_crc32",
            "CRC-32 (verified)",
            format!("0x{:08X}", fsid.crc),
        );
    }

    let mut walker = Walker {
        image,
        le: sb.le,
        reader: Reader {
            image,
            le: sb.le,
            extended: sb.flags & FLAG_EXT_BLOCK_POINTERS != 0,
        },
        members: Members::default(),
        walked: 0,
        path: WalkPath::default(),
    };
    walker.walk(&sb.root, 0)?;
    walker.members.finish(&mut c, "first 4 KiB block");
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_bitfields_follow_the_image_byte_order() {
        // Directory, size 0x123456, gid 7, name length 2 (8 B), offset
        // 0x13 (0x4C B).
        let le = [
            0xed, 0x41, 0, 0, 0x56, 0x34, 0x12, 7, 0xc2, 0x04, 0x00, 0x00,
        ];
        let be = [
            0x41, 0xed, 0, 0, 0x12, 0x34, 0x56, 7, 0x08, 0x00, 0x00, 0x13,
        ];
        for (bytes, little) in [(le, true), (be, false)] {
            let entry = inode(&bytes, 0, little).unwrap();
            assert!(entry.is_directory());
            assert_eq!(entry.size, 0x12_3456);
            assert_eq!(entry.name_len, 8);
            assert_eq!(entry.offset, 0x4c);
        }
    }

    #[test]
    fn detection_needs_the_signature_after_a_pad() {
        let mut data = vec![0u8; PAD_SIZE + SUPERBLOCK_SIZE];
        data[PAD_SIZE..PAD_SIZE + 4].copy_from_slice(&CRAMFS_MAGIC.to_be_bytes());
        assert_eq!(detect(&data), None);
        let signature = PAD_SIZE + SIGNATURE_OFFSET;
        data[signature..signature + 16].copy_from_slice(CRAMFS_SIGNATURE);
        assert_eq!(detect(&data), Some(Layout::Cramfs));
        assert_eq!(detect(&CRAMFS_MAGIC.to_le_bytes()), Some(Layout::Cramfs));
    }

    #[test]
    fn files_have_one_block_per_started_page() {
        let file = RegularFile {
            offset: 0,
            size: BLOCK_SIZE + 1,
        };
        assert_eq!(file.blocks(), 2);
        assert_eq!(file.block_len(0), BLOCK_SIZE);
        assert_eq!(file.block_len(1), 1);
        assert_eq!(
            flag_names(FLAG_SORTED_DIRS | FLAG_HOLES),
            ["sorted directories", "holes"]
        );
    }
}
