//! romfs: a big-endian superblock with a word-sum checksum, then file
//! headers on 16-byte boundaries, each followed by its NUL-terminated name
//! and its data (sources in the family module).
//!
//! A directory's header points to its first entry; entries are chained
//! by their `next` offsets. genromfs writes `.` and `..` as real entries:
//! the root's `.` is the first file header, a directory pointing at itself,
//! and other `.` and `..` entries are hard links. A walk skips both names
//! and never follows hard links, so it cannot loop on them.

use super::*;

/// Superblock magic: `ROMSB_WORD0` and `ROMSB_WORD1`.
const ROMFS_MAGIC: &[u8; 8] = b"-rom1fs-";

/// Size of a file header, and of the superblock before the volume name
/// (`ROMFH_SIZE`).
const ROMFH_SIZE: usize = 16;

/// Headers and names are padded to 16 bytes (`ROMFH_PAD`, `ROMFH_MASK`).
const ROMFH_PAD: usize = 15;
const ROMFH_MASK: u32 = !15;

/// File type bits of `next` (`ROMFH_TYPE`) and the executable bit
/// (`ROMFH_EXEC`; `romfs.rst` calls it bit 4, the header defines 8).
const ROMFH_TYPE: u32 = 7;
const ROMFH_EXEC: u32 = 8;

/// File types (`ROMFH_DIR`, `ROMFH_REG`); hard links (`ROMFH_HRD`, 0),
/// symlinks, devices, sockets and FIFOs are not read.
const ROMFH_DIR: u32 = 1;
const ROMFH_REG: u32 = 2;

/// Longest name, including its NUL (`ROMFS_MAXFN`).
const ROMFS_MAXFN: usize = 128;

/// The superblock checksum covers the first 512 bytes, or the whole image
/// when it is smaller (`romfs_fill_super`).
const CHECKSUM_SPAN: usize = 512;

/// Smallest header with its name and padding: 16 bytes and an empty name
/// padded to 16. Bounds how many headers an image can hold.
const MIN_HEADER_SPAN: usize = 2 * ROMFH_SIZE;

/// Bytes of a regular file that are probed for a recognized format before
/// the file is listed.
const PROBE_SIZE: usize = 4096;

/// Strong recognition: the eight-byte magic.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    data.starts_with(ROMFS_MAGIC).then_some(Layout::Romfs)
}

/// Sum of the big-endian u32 words of `bytes`, ignoring a partial last
/// word (`romfs_checksum`). A valid region sums to 0.
fn word_sum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(
            word.try_into().expect("chunk has 4 bytes"),
        ))
    })
}

/// Round up to the 16-byte header alignment.
fn align16(n: usize) -> usize {
    (n + ROMFH_PAD) & !ROMFH_PAD
}

/// The length of the NUL-terminated name at `at`, at most `max` bytes
/// when no NUL comes first (`romfs_dev_strnlen`).
fn name_len(image: &[u8], at: usize, max: usize) -> Result<usize> {
    let available = image.len().saturating_sub(at).min(max);
    let area = slice(image, at, available)?;
    Ok(area.iter().position(|b| *b == 0).unwrap_or(available))
}

/// A file header: next header and mode bits (0), type-specific value (4),
/// data size (8), checksum (12), then the name.
struct FileHeader {
    /// File offset of the next header in the same directory; 0 ends it.
    next: usize,
    kind: u32,
    executable: bool,
    /// Directories: offset of the first entry; hard links: the target.
    spec: u32,
    size: u32,
    /// The name's file offset and length, without the NUL.
    name_start: usize,
    name_len: usize,
    /// File offset of the data: the header and padded name come first
    /// (`i_metasize`).
    data_start: usize,
    /// The header and padded name sum to 0 (genromfs `dumpri`; Linux does
    /// not check it).
    checksum_ok: bool,
}

/// The file header at `at`.
fn file_header(image: &[u8], at: usize) -> Result<FileHeader> {
    let raw = slice(image, at, ROMFH_SIZE)?;
    let next = be_u32(raw, 0)?;
    let name_start = at + ROMFH_SIZE;
    let name_len = name_len(image, name_start, ROMFS_MAXFN)?;
    // The name lies in the image, so these sums are below its length
    // plus 16.
    let meta_size = align16(ROMFH_SIZE + name_len + 1);
    let metadata = slice(image, at, meta_size)?;
    Ok(FileHeader {
        next: (next & ROMFH_MASK) as usize,
        kind: next & ROMFH_TYPE,
        executable: next & ROMFH_EXEC != 0,
        spec: be_u32(raw, 4)?,
        size: be_u32(raw, 8)?,
        name_start,
        name_len,
        data_start: at + meta_size,
        checksum_ok: word_sum(metadata) == 0,
    })
}

/// A regular file's data.
struct RegularFile {
    /// File offset of the data.
    offset: usize,
    /// Size in bytes.
    size: usize,
}

/// The first `len` bytes of `file`'s data.
fn contents<'a>(image: &'a [u8], file: &RegularFile, len: usize) -> Result<&'a [u8]> {
    slice(image, file.offset, len).map_err(|_| {
        error(format!(
            "Invalid romfs file data at 0x{:X}: {} B pass the image end 0x{:X}",
            file.offset,
            file.size,
            image.len()
        ))
    })
}

/// Reads regular files, which romfs stores as-is after their headers.
struct Reader<'a> {
    image: &'a [u8],
}

impl<'a> FileReader<'a> for Reader<'a> {
    type File = RegularFile;

    fn size(&self, file: &RegularFile) -> u64 {
        file.size as u64
    }

    fn first_block_size(&self, file: &RegularFile) -> usize {
        file.size.min(PROBE_SIZE)
    }

    fn first_block(
        &mut self,
        file: &RegularFile,
        _budget: &mut Budget,
    ) -> std::result::Result<Cow<'a, [u8]>, Unread> {
        let probe = contents(self.image, file, self.first_block_size(file))?;
        Ok(Cow::Borrowed(probe))
    }

    fn member(
        &mut self,
        file: &RegularFile,
        path: String,
        _first: Cow<'a, [u8]>,
        _budget: &mut Budget,
    ) -> std::result::Result<Child<'a>, Unread> {
        let data = contents(self.image, file, file.size)?;
        Ok(Child::stored(path, file.offset, data))
    }
}

/// Walks directory chains from the root, examining every regular file.
struct Walker<'a> {
    image: &'a [u8],
    reader: Reader<'a>,
    members: Members<'a>,
    /// Headers visited; more than the image can hold means a chain or a
    /// directory repeats (a loop).
    visited: usize,
    max_headers: usize,
    executables: usize,
    bad_checksums: usize,
    first_bad_checksum: Option<usize>,
    path: WalkPath,
}

impl Walker<'_> {
    /// Walk the chain of entries that starts at `first`.
    fn walk(&mut self, first: usize, depth: usize) -> Result<()> {
        let mut at = first;
        while at != 0 {
            self.visited += 1;
            if self.visited > self.max_headers {
                return Err(error(
                    "Invalid romfs directory structure: file headers repeat",
                ));
            }
            let header = file_header(self.image, at)?;
            if !header.checksum_ok {
                self.bad_checksums += 1;
                self.first_bad_checksum.get_or_insert(at);
            }
            let raw_name = slice(self.image, header.name_start, header.name_len)?;
            if let Some(name) = entry_name(raw_name, at, "romfs")? {
                let parent_len = self.path.push(&name);
                let visited = self.visit(&header, depth);
                self.path.restore(parent_len);
                visited?;
            }
            at = header.next;
        }
        Ok(())
    }

    /// Descend into a directory or examine a regular file. Hard links,
    /// symlinks, devices, sockets and FIFOs are not followed.
    fn visit(&mut self, header: &FileHeader, depth: usize) -> Result<()> {
        match header.kind {
            ROMFH_DIR => {
                if is_walkable(depth + 1, self.path.as_str()) {
                    self.walk((header.spec & ROMFH_MASK) as usize, depth + 1)?;
                } else {
                    self.members.unwalked_directories += 1;
                }
            }
            ROMFH_REG => {
                self.executables += usize::from(header.executable);
                let file = RegularFile {
                    offset: header.data_start,
                    size: header.size as usize,
                };
                self.members
                    .examine(&mut self.reader, &file, self.path.as_str());
            }
            _ => {}
        }
        Ok(())
    }
}

/// Superblock (big-endian): magic, image size (8), checksum (12), volume
/// name (16), NUL-terminated and padded to 16 bytes. Checked in Linux
/// order (`romfs_fill_super`): magic and size, then the checksum of the
/// first 512 bytes; the root directory is the first file header.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(ROMFS_MAGIC) {
        return Err(error("Missing romfs magic"));
    }
    let size = to_usize(be_u32(data, 8)?.into(), "romfs size")?;
    if size < ROMFH_SIZE {
        return Err(error(format!("Invalid romfs size {size} B")));
    }
    if size > data.len() {
        return Err(error(format!(
            "Truncated romfs image: size is {size} B, {} B present",
            data.len()
        )));
    }
    let image = &data[..size];
    let sum = word_sum(&image[..size.min(CHECKSUM_SPAN)]);
    if sum != 0 {
        return Err(error(format!(
            "Invalid romfs superblock checksum: the first {} B sum to 0x{sum:08X}",
            size.min(CHECKSUM_SPAN)
        )));
    }
    expect_padding(data, size, "romfs")?;
    let volume_len = name_len(image, ROMFH_SIZE, ROMFS_MAXFN)?;
    let volume = String::from_utf8_lossy(slice(image, ROMFH_SIZE, volume_len)?).into_owned();
    let root_at = align16(ROMFH_SIZE + volume_len + 1);
    let root = file_header(image, root_at)?;
    if root.kind != ROMFH_DIR {
        return Err(error(format!(
            "Invalid romfs root header at 0x{root_at:X}: type {}, expected a directory",
            root.kind
        )));
    }

    let mut c = Container::new(FileFormat::Romfs, Layout::Romfs.label(), "romfs");
    c.consumed = size;
    c.notes.push(format!(
        "romfs, big-endian; volume \"{}\"; {size} B; superblock checksum verified",
        volume.escape_debug()
    ));
    if let Some(note) = padding_note(data, size) {
        c.notes.push(note);
    }
    c.push_metadata("romfs_volume_name", "Volume name", volume);
    c.push_metadata("romfs_size", "Image size (B)", size as u64);

    let mut walker = Walker {
        image,
        reader: Reader { image },
        members: Members::default(),
        visited: 0,
        max_headers: size / MIN_HEADER_SPAN,
        executables: 0,
        bad_checksums: 0,
        first_bad_checksum: None,
        path: WalkPath::default(),
    };
    walker.walk((root.spec & ROMFH_MASK) as usize, 0)?;
    if let Some(first) = walker.first_bad_checksum {
        c.notes.push(format!(
            "{} file headers fail their checksum (Linux does not check them); first at 0x{first:X}",
            walker.bad_checksums
        ));
    } else {
        c.notes.push("File header checksums verified".to_string());
    }
    c.push_metadata(
        "romfs_executable_files",
        "Executable regular files",
        walker.executables as u64,
    );
    walker.members.finish(&mut c, "first 4 KiB");
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_sums_wrap_and_ignore_a_partial_word() {
        assert_eq!(word_sum(&[0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]), 0);
        assert_eq!(word_sum(&[0, 0, 0, 2, 9]), 2);
    }

    #[test]
    fn names_end_at_a_nul_or_the_limit() {
        assert_eq!(name_len(b"ab\0cd", 0, 128).unwrap(), 2);
        assert_eq!(name_len(b"abcd", 0, 3).unwrap(), 3);
        assert_eq!(name_len(b"abcd", 1, 128).unwrap(), 3);
        assert_eq!(align16(17), 32);
        assert_eq!(align16(32), 32);
    }
}
