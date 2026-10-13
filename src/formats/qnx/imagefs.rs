//! The image filesystem (`sys/image.h`): `struct image_header`, the
//! directory of `union image_dirent` entries, the files and the image
//! trailer.
//!
//! Header (target byte order): signature `imagefs` (0), flags (7),
//! `image_size` (8, header to the end of the trailer), `hdr_dir_size` (0xC,
//! header to the end of the directory), `dir_offset` (0x10), `boot_ino[4]`
//! (0x14), `script_ino` (0x24), `chain_paddr` (0x28), `spare[10]` (0x2C),
//! `mountflags` (0x54) and the NUL-terminated `mountpoint` (0x58), padded to
//! four bytes. Every directory entry starts with `struct image_attr`: size
//! (0), `extattr_offset` (2), `ino` (4), `mode` (8), `gid` (0xC), `uid`
//! (0x10), `mtime` (0x14). A regular file adds `offset` (0x18, from the
//! image header), `size` (0x1C) and its path (0x20); an entry of size 0 ends
//! the directory (mkifs `ifs_make_fsys`).

use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::MetadataValue;
use std::borrow::Cow;

/// Image header flags (`IMAGE_FLAGS_*`).
const IMAGE_FLAGS_BIGENDIAN: u8 = 0x01;
const IMAGE_FLAGS_READONLY: u8 = 0x02;
const IMAGE_FLAGS_INO_BITS: u8 = 0x04;

/// Every flag `sys/image.h` defines (the name is this parser's).
const IMAGE_FLAGS_DEFINED: u8 = 0x07;

/// Offset of `mountpoint`: the fixed part of `struct image_header`.
const IMAGE_HEADER_SIZE: usize = 0x58;

/// Size of `struct image_attr`, the common start of every directory entry.
const IMAGE_ATTR_SIZE: usize = 24;

/// Offset of `path` in `struct image_file`, after `offset` and `size`.
const FILE_PATH_OFFSET: usize = 0x20;

/// File type bits of `mode` (QNX `sys/stat.h`).
const S_IFMT: u32 = 0xf000;
const S_IFIFO: u32 = 0x1000;
const S_IFCHR: u32 = 0x2000;
const S_IFDIR: u32 = 0x4000;
const S_IFNAM: u32 = 0x5000;
const S_IFBLK: u32 = 0x6000;
const S_IFREG: u32 = 0x8000;
const S_IFLNK: u32 = 0xa000;

/// Bytes at the start of a file checked for a recognized format before the
/// whole file is checked and listed.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Paths quoted in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// A verified image filesystem: its header and directory, with offsets
/// relative to the image header.
pub(super) struct ImageFs {
    /// Header, directory and trailer byte order (true means little-endian).
    pub(super) le: bool,
    flags: u8,
    /// Image header to the end of the trailer, bytes.
    pub(super) image_size: usize,
    /// The trailer checksum, verified.
    checksum: u32,
    boot_ino: [u32; 4],
    script_ino: u32,
    chain_paddr: u32,
    mountpoint: String,
    files: Vec<FileEntry>,
    directories: usize,
    symlinks: usize,
    devices: usize,
    /// Entries of a file type that no source names.
    other_entries: usize,
    /// Entries with inode 0, which readers skip.
    skipped_entries: usize,
}

/// A regular file of the image filesystem.
struct FileEntry {
    ino: u32,
    /// Path as stored, without a leading slash.
    path: String,
    /// Offset of the data from the image header, bytes.
    offset: usize,
    /// Size of the data, bytes.
    size: usize,
}

impl FileEntry {
    /// The member label: the path below the root.
    fn label(&self) -> String {
        if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        }
    }
}

/// Parse a bare image filesystem (`imagefs` at offset 0).
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let fs = read(data, 0)?;
    let mut c = Container::new(FileFormat::QnxIfs, Layout::ImageFs.label(), KEY_PREFIX);
    c.consumed = fs.image_size;
    c.notes.push(
        "Image filesystem without a startup header; no architecture is named, members are classified on their own"
            .to_string(),
    );
    describe(
        &mut c,
        &fs,
        &Source::Stored {
            image: data,
            offset: 0,
        },
    );
    if let Some(note) = trailing_note(data, fs.image_size) {
        c.notes.push(note);
    }
    Ok(c)
}

/// Read and verify the image filesystem at the start of `image`; `base` is
/// its file offset for messages. The trailer checksum must match and every
/// directory entry and file must lie inside `image_size`.
pub(super) fn read(image: &[u8], base: usize) -> Result<ImageFs> {
    let header = image
        .get(..IMAGE_HEADER_SIZE)
        .ok_or_else(|| error(format!("Truncated image header at 0x{base:X}")))?;
    if !header.starts_with(IMAGE_SIGNATURE) {
        return Err(error(format!("Missing imagefs signature at 0x{base:X}")));
    }
    let flags = header[IMAGE_SIGNATURE.len()];
    let le = flags & IMAGE_FLAGS_BIGENDIAN == 0;
    let image_size = to_usize(u32_at(header, 0x08, le)?);
    let hdr_dir_size = to_usize(u32_at(header, 0x0c, le)?);
    let dir_offset = to_usize(u32_at(header, 0x10, le)?);
    let mut boot_ino = [0u32; 4];
    for (i, ino) in boot_ino.iter_mut().enumerate() {
        *ino = u32_at(header, 0x14 + 4 * i, le)?;
    }
    let script_ino = u32_at(header, 0x24, le)?;
    let chain_paddr = u32_at(header, 0x28, le)?;
    let directory_fits = hdr_dir_size
        .checked_add(TRAILER_SIZE)
        .is_some_and(|end| end <= image_size);
    if image_size % 4 != 0 || !directory_fits {
        return Err(error(format!(
            "Invalid image_size 0x{image_size:X} at 0x{:X} (hdr_dir_size 0x{hdr_dir_size:X})",
            base + 0x08
        )));
    }
    if dir_offset <= IMAGE_HEADER_SIZE || dir_offset > hdr_dir_size {
        return Err(error(format!(
            "Invalid dir_offset 0x{dir_offset:X} at 0x{:X}",
            base + 0x10
        )));
    }
    let region = image.get(..image_size).ok_or_else(|| {
        error(format!(
            "Truncated image filesystem at 0x{base:X}: image_size {} B, {} B present",
            image_size,
            image.len()
        ))
    })?;
    let trailer = image_size - TRAILER_SIZE;
    if !has_zero_word_sum(region, le) {
        return Err(error(format!(
            "Invalid image trailer checksum at 0x{:X}",
            base + trailer
        )));
    }
    let mountpoint = nul_terminated(&region[IMAGE_HEADER_SIZE..dir_offset]).ok_or_else(|| {
        error(format!(
            "Missing mountpoint terminator at 0x{:X}",
            base + IMAGE_HEADER_SIZE
        ))
    })?;
    let mut fs = ImageFs {
        le,
        flags,
        image_size,
        checksum: u32_at(region, trailer, le)?,
        boot_ino,
        script_ino,
        chain_paddr,
        mountpoint: String::from_utf8_lossy(mountpoint).into_owned(),
        files: Vec::new(),
        directories: 0,
        symlinks: 0,
        devices: 0,
        other_entries: 0,
        skipped_entries: 0,
    };
    read_directory(&mut fs, &region[..hdr_dir_size], dir_offset, base)?;
    Ok(fs)
}

/// The bytes of `field` before its first NUL, if it has one.
fn nul_terminated(field: &[u8]) -> Option<&[u8]> {
    field.iter().position(|b| *b == 0).map(|end| &field[..end])
}

/// Walk the directory entries from `dir_offset` to the end of `directory`
/// (`hdr_dir_size`). Every entry is at least [`IMAGE_ATTR_SIZE`] bytes, so
/// the walk is bounded by the directory size.
fn read_directory(
    fs: &mut ImageFs,
    directory: &[u8],
    dir_offset: usize,
    base: usize,
) -> Result<()> {
    let mut pos = dir_offset;
    loop {
        let size = u16_at(directory, pos, fs.le).map_err(|_| {
            error(format!(
                "Missing image directory terminator before 0x{:X}",
                base + directory.len()
            ))
        })?;
        let size = usize::from(size);
        if size == 0 {
            return Ok(());
        }
        if size < IMAGE_ATTR_SIZE {
            return Err(error(format!(
                "Invalid directory entry size {size} B at 0x{:X}",
                base + pos
            )));
        }
        let entry = slice(directory, pos, size).map_err(|_| {
            error(format!(
                "Truncated directory entry at 0x{:X}: {size} B run past hdr_dir_size",
                base + pos
            ))
        })?;
        read_entry(fs, entry, base + pos)?;
        pos += size;
    }
}

/// Record one directory entry; `at` is its file offset for messages.
fn read_entry(fs: &mut ImageFs, entry: &[u8], at: usize) -> Result<()> {
    let ino = u32_at(entry, 0x04, fs.le)?;
    let mode = u32_at(entry, 0x08, fs.le)?;
    if ino == 0 {
        fs.skipped_entries += 1;
        return Ok(());
    }
    match mode & S_IFMT {
        S_IFREG => {
            let offset = to_usize(u32_at(entry, 0x18, fs.le)?);
            let size = to_usize(u32_at(entry, 0x1c, fs.le)?);
            let path = entry
                .get(FILE_PATH_OFFSET..)
                .and_then(nul_terminated)
                .ok_or_else(|| {
                    error(format!(
                        "Missing path terminator in directory entry at 0x{at:X}"
                    ))
                })?;
            let path = String::from_utf8_lossy(path).into_owned();
            let inside = offset
                .checked_add(size)
                .is_some_and(|end| end <= fs.image_size - TRAILER_SIZE);
            if !inside {
                return Err(error(format!(
                    "Invalid file entry at 0x{at:X}: data 0x{offset:X} + {size} B lies outside the image filesystem"
                )));
            }
            fs.files.push(FileEntry {
                ino,
                path,
                offset,
                size,
            });
        }
        S_IFDIR => fs.directories += 1,
        S_IFLNK => fs.symlinks += 1,
        S_IFCHR | S_IFBLK | S_IFIFO | S_IFNAM => fs.devices += 1,
        _ => fs.other_entries += 1,
    }
    Ok(())
}

/// Where the bytes of an image filesystem come from.
pub(super) enum Source<'a, 'd> {
    /// Stored in the input with the image header at file offset `offset`:
    /// members are slices of the input.
    Stored {
        /// The image filesystem, from its header.
        image: &'a [u8],
        /// File offset of the image header.
        offset: usize,
    },
    /// Decoded from the stored bytes at `offset..offset + stored_size` by
    /// `transform`: members are copies, and their stored coordinates are
    /// those of the compressed stream.
    Decoded {
        /// The decoded image filesystem.
        image: &'d [u8],
        /// File offset of the compressed stream.
        offset: usize,
        /// Stored size of the compressed stream, bytes.
        stored_size: usize,
        /// Codec that produced `image`.
        transform: &'static str,
    },
}

impl<'a: 'd, 'd> Source<'a, 'd> {
    /// The image filesystem bytes, from its header. A stored image outlives
    /// a decoded one, so both are returned for the shorter lifetime.
    fn image(&self) -> &'d [u8] {
        match *self {
            Self::Decoded { image, .. } | Self::Stored { image, .. } => image,
        }
    }

    fn is_decoded(&self) -> bool {
        matches!(self, Self::Decoded { .. })
    }

    /// The component for the file `file`. Its range was validated against
    /// `image_size` when the directory was read.
    fn child(&self, file: &FileEntry) -> Child<'a> {
        let end = file.offset + file.size;
        match *self {
            Self::Stored { image, offset } => {
                Child::stored(file.label(), offset + file.offset, &image[file.offset..end])
            }
            Self::Decoded {
                image,
                offset,
                stored_size,
                transform,
            } => Child::decoded(
                file.label(),
                offset,
                stored_size,
                Cow::Owned(image[file.offset..end].to_vec()),
                transform,
            ),
        }
    }
}

/// What the member listing found and left out.
#[derive(Default)]
struct Listing {
    /// Members listed as recognized formats.
    listed: usize,
    /// Decoded bytes copied for members, counted against [`MAX_EXTRACTED`].
    extracted: usize,
    /// Regular files not examined once [`MAX_COMPONENTS`] were listed.
    unexamined: usize,
    /// Recognized decoded files not copied because [`MAX_EXTRACTED`] would
    /// be exceeded.
    over_extraction_limit: usize,
    /// Recognized decoded files larger than [`MAX_PAYLOAD`].
    too_large: usize,
    /// Whether the boot script was listed.
    script_listed: bool,
}

impl Listing {
    /// Reserve `size` decoded bytes for a member; false when the member is
    /// too large or the image would exceed [`MAX_EXTRACTED`].
    fn reserve(&mut self, size: usize) -> bool {
        if size > MAX_PAYLOAD {
            self.too_large += 1;
            return false;
        }
        match self.extracted.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.extracted = total;
                true
            }
            _ => {
                self.over_extraction_limit += 1;
                false
            }
        }
    }
}

/// Add the notes, metadata and components of the verified image filesystem
/// `fs`: the boot script as an opaque component, and every regular file
/// whose bytes are a recognized format as a member.
pub(super) fn describe<'a>(c: &mut Container<'a>, fs: &ImageFs, source: &Source<'a, '_>) {
    c.notes.push(header_note(fs, source));
    c.notes.push(directory_note(fs));
    if fs.chain_paddr != 0 {
        c.notes.push(format!(
            "chain_paddr 0x{:X} names a further image filesystem; it is not followed",
            fs.chain_paddr
        ));
    }
    if let Some(note) = bootstrap_note(fs) {
        c.notes.push(note);
    }
    c.push_metadata("qnx_mountpoint", "Mountpoint", fs.mountpoint.as_str());
    c.push_metadata(
        "qnx_image_flags",
        "Image header flags",
        MetadataValue::Hex(u32::from(fs.flags)),
    );
    c.push_metadata(
        "qnx_image_checksum",
        "Image trailer checksum (verified)",
        MetadataValue::Hex(fs.checksum),
    );
    c.push_metadata("qnx_regular_files", "Regular files", fs.files.len() as u64);
    let listing = list_members(c, fs, source);
    c.notes.push(format!(
        "{} recognized members listed; members are recognized from their first {}",
        listing.listed,
        size_text(RECOGNITION_PREFIX)
    ));
    if listing.unexamined > 0 {
        c.notes.push(format!(
            "Member limit reached ({MAX_COMPONENTS} members); {} further regular files were not examined",
            listing.unexamined
        ));
    }
    if listing.over_extraction_limit > 0 {
        c.notes.push(format!(
            "Extraction limit reached ({}); {} recognized regular files were not extracted",
            size_text(MAX_EXTRACTED),
            listing.over_extraction_limit
        ));
    }
    if listing.too_large > 0 {
        c.notes.push(format!(
            "{} recognized regular files exceed the {} member limit and are not listed",
            listing.too_large,
            size_text(MAX_PAYLOAD)
        ));
    }
}

/// "Image filesystem at 0x...: size, byte order; mountpoint; checksum".
fn header_note(fs: &ImageFs, source: &Source<'_, '_>) -> String {
    let location = match *source {
        Source::Stored { offset, .. } => format!("at 0x{offset:X}"),
        Source::Decoded { transform, .. } => format!("({transform}-decoded)"),
    };
    let mountpoint = if fs.mountpoint.is_empty() {
        "no mountpoint".to_string()
    } else {
        format!("mountpoint {}", fs.mountpoint)
    };
    let mut flags = Vec::new();
    if fs.flags & IMAGE_FLAGS_READONLY != 0 {
        flags.push("read-only".to_string());
    }
    if fs.flags & IMAGE_FLAGS_INO_BITS != 0 {
        flags.push("inode flag bits valid".to_string());
    }
    if fs.flags & !IMAGE_FLAGS_DEFINED != 0 {
        flags.push(format!(
            "undefined flags 0x{:02X}",
            fs.flags & !IMAGE_FLAGS_DEFINED
        ));
    }
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!("; {}", flags.join(", "))
    };
    format!(
        "Image filesystem {location}: {}, {}; {mountpoint}{flags}; image trailer checksum verified",
        size_text(fs.image_size),
        byte_order_name(fs.le)
    )
}

/// "Image directory: counts", with the unknown and skipped entries when
/// there are any.
fn directory_note(fs: &ImageFs) -> String {
    let unknown = match fs.other_entries {
        0 => String::new(),
        n => format!(", {n} of unknown type"),
    };
    let mut parts = vec![format!(
        "Image directory: {} regular files, {} directories, {} symbolic links, {} devices{unknown}",
        fs.files.len(),
        fs.directories,
        fs.symlinks,
        fs.devices
    )];
    if fs.skipped_entries > 0 {
        parts.push(format!(
            "{} entries with inode 0 skipped",
            fs.skipped_entries
        ));
    }
    parts.join("; ")
}

/// The files that `boot_ino` names as bootstrap programs, if any.
fn bootstrap_note(fs: &ImageFs) -> Option<String> {
    let names: Vec<String> = fs
        .files
        .iter()
        .filter(|f| fs.boot_ino.iter().any(|ino| *ino != 0 && *ino == f.ino))
        .take(NOTE_NAMES)
        .map(FileEntry::label)
        .collect();
    (!names.is_empty()).then(|| format!("Bootstrap programs (boot_ino): {}", names.join(", ")))
}

/// List the boot script and the recognized regular files of `fs`.
fn list_members<'a>(c: &mut Container<'a>, fs: &ImageFs, source: &Source<'a, '_>) -> Listing {
    let mut listing = Listing::default();
    let image = source.image();
    for file in &fs.files {
        let bytes = &image[file.offset..file.offset + file.size];
        if fs.script_ino != 0 && file.ino == fs.script_ino && !listing.script_listed {
            listing.script_listed = true;
            c.notes.push(script::summary(&file.label(), bytes));
            if !source.is_decoded() || listing.reserve(file.size) {
                c.children.push(Child {
                    opaque: true,
                    ..source.child(file)
                });
            }
            continue;
        }
        if c.children.len() >= MAX_COMPONENTS {
            listing.unexamined += 1;
            continue;
        }
        let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
        if !container::is_recognized(prefix) || !container::is_recognized(bytes) {
            continue;
        }
        if source.is_decoded() && !listing.reserve(file.size) {
            continue;
        }
        c.children.push(source.child(file).if_recognized());
        listing.listed += 1;
    }
    listing
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `value` as a little-endian u32 field.
    fn le32(value: usize) -> [u8; 4] {
        u32::try_from(value).unwrap().to_le_bytes()
    }

    /// A little-endian image filesystem: the header with mountpoint `/`,
    /// a root directory entry (28 B), one regular file entry `bin/x` of
    /// `contents` (40 B), the terminator, the file data and the trailer.
    fn image(contents: &[u8]) -> Vec<u8> {
        let dir_offset = 0x5c;
        let root: u8 = 0x1c;
        let file_entry: u8 = 0x28;
        let hdr_dir_size = dir_offset + usize::from(root) + usize::from(file_entry) + 4;
        let data_offset = hdr_dir_size;
        let image_size = round_up4(data_offset + contents.len()).unwrap() + TRAILER_SIZE;
        let mut out = vec![0u8; image_size];
        out[..7].copy_from_slice(IMAGE_SIGNATURE);
        out[0x08..0x0c].copy_from_slice(&le32(image_size));
        out[0x0c..0x10].copy_from_slice(&le32(hdr_dir_size));
        out[0x10..0x14].copy_from_slice(&le32(dir_offset));
        out[0x58] = b'/';
        let mut pos = dir_offset;
        out[pos] = root;
        out[pos + 4..pos + 8].copy_from_slice(&1u32.to_le_bytes());
        out[pos + 8..pos + 12].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
        pos += usize::from(root);
        out[pos] = file_entry;
        out[pos + 4..pos + 8].copy_from_slice(&2u32.to_le_bytes());
        out[pos + 8..pos + 12].copy_from_slice(&(S_IFREG | 0o755).to_le_bytes());
        out[pos + 0x18..pos + 0x1c].copy_from_slice(&le32(data_offset));
        out[pos + 0x1c..pos + 0x20].copy_from_slice(&le32(contents.len()));
        out[pos + 0x20..pos + 0x25].copy_from_slice(b"bin/x");
        out[data_offset..data_offset + contents.len()].copy_from_slice(contents);
        let sum = out.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_le_bytes(w.try_into().unwrap()))
        });
        out[image_size - 4..].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
        out
    }

    #[test]
    fn a_minimal_image_filesystem_reads_its_directory() {
        let data = image(b"payload");
        let fs = read(&data, 0).unwrap();
        assert!(fs.le);
        assert_eq!(fs.mountpoint, "/");
        assert_eq!(fs.directories, 1);
        assert_eq!(fs.files.len(), 1);
        assert_eq!(fs.files[0].label(), "/bin/x");
        assert_eq!(fs.files[0].size, 7);
    }

    #[test]
    fn checksum_and_ranges_are_enforced() {
        let data = image(b"payload");
        let mut corrupt = data.clone();
        corrupt[0x90] ^= 1;
        let message = read(&corrupt, 0).err().unwrap().to_string();
        assert!(
            message.contains("Invalid image trailer checksum"),
            "{message}"
        );
        for end in 0..data.len() {
            assert!(read(&data[..end], 0).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn listing_reserves_decoded_bytes_up_to_the_limit() {
        let mut listing = Listing::default();
        assert!(listing.reserve(MAX_PAYLOAD));
        assert!(!listing.reserve(MAX_PAYLOAD + 1));
        assert_eq!(listing.too_large, 1);
        for _ in 0..3 {
            assert!(listing.reserve(MAX_PAYLOAD));
        }
        assert!(!listing.reserve(1));
        assert_eq!(listing.over_extraction_limit, 1);
    }
}
