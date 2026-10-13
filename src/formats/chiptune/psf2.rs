//! The PSF2 virtual filesystem in the reserved area (PSF v1.6, "PSF2:
//! Virtual filesystem format").
//!
//! All quantities are little-endian and all offsets relative to the start
//! of the reserved area; the root directory is at offset 0. A directory is
//! an entry count (4) and 48-byte entries: name (36, NUL-padded), offset
//! (4), uncompressed size (4) and block size (4). Size, block size and
//! offset all zero is an empty file; size and block size zero with a
//! nonzero offset is a subdirectory; anything else is a file stored as a
//! table of compressed block sizes followed by zlib blocks that decode to
//! the block size (the last may be shorter). "The offset of any
//! subdirectory or file must be greater than the offset of its directory
//! entry", so the walk cannot loop.
//!
//! Playback starts with the IOP module `psf2.irx`. IOP modules are ELF
//! files, so the ELF parser names their ISA from `e_machine`; this module
//! does not. Files are decoded only when their first block starts a
//! recognized format.

use super::*;

/// Directory entry count, entry size and entry fields.
const COUNT_SIZE: usize = 4;
const ENTRY_SIZE: usize = 48;
const NAME_SIZE: usize = 36;
const ENTRY_OFFSET: usize = 36;
const ENTRY_LENGTH: usize = 40;
const ENTRY_BLOCK_SIZE: usize = 44;

/// One size-table entry per compressed block.
const BLOCK_SIZE_ENTRY: usize = 4;

/// "The total length of a path must be no longer than 255 bytes."
const MAX_PATH: usize = 255;

/// Name characters are ASCII 32-126 except these separators.
const SEPARATORS: [u8; 3] = *b"/\\:";

/// The module that starts playback.
const DRIVER: &str = "psf2.irx";

/// Counts collected while walking the filesystem.
#[derive(Default)]
struct Walk {
    /// Entries visited, bounded by [`container::MAX_COMPONENTS`].
    entries: usize,
    files: usize,
    directories: usize,
    /// Uncompressed size of all files, in bytes.
    total_size: u64,
    /// Decoded bytes kept for listed members.
    extracted: usize,
    /// Files left undecoded by the member or byte limits.
    undecoded: usize,
    /// The walk stopped at the entry limit.
    truncated: bool,
    /// `psf2.irx` is in the root directory.
    has_driver: bool,
}

/// Walk the filesystem in `area` (file offset `base`), listing every file in
/// the metadata and recognized files as children.
pub(super) fn list<'a>(c: &mut Container<'a>, area: &'a [u8], base: usize) -> Result<()> {
    let mut walk = Walk::default();
    directory(c, &mut walk, area, base, 0, "")?;
    c.notes.push(format!(
        "PSF2 filesystem: {} files ({}) in {} subdirectories; files are decoded only when their first block starts a recognized format",
        walk.files,
        compressed::size_text(usize::try_from(walk.total_size).unwrap_or(usize::MAX)),
        walk.directories
    ));
    if !walk.has_driver {
        c.notes.push(format!(
            "No {DRIVER} in the root directory; a MiniPSF2 takes it from a library"
        ));
    }
    if walk.truncated {
        c.notes.push(format!(
            "Listing stopped after {} entries",
            container::MAX_COMPONENTS
        ));
    }
    if walk.undecoded > 0 {
        c.notes.push(format!(
            "{} files were not decoded (limits {} members, {} decoded in total, {} per member)",
            walk.undecoded,
            container::MAX_COMPONENTS,
            compressed::size_text(container::MAX_EXTRACTED),
            compressed::size_text(MAX_PAYLOAD)
        ));
    }
    Ok(())
}

/// A 36-byte name field: nonzero length, NUL-padded, ASCII 32-126 without
/// path separators.
fn entry_name(field: &[u8]) -> Option<&str> {
    let len = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    let name = &field[..len];
    let valid = !name.is_empty()
        && name
            .iter()
            .all(|b| (b' '..=b'~').contains(b) && !SEPARATORS.contains(b));
    if valid {
        std::str::from_utf8(name).ok()
    } else {
        None
    }
}

/// The directory at `at`. Recursion depth is bounded by the path length
/// limit: every level adds at least two bytes to the path.
fn directory<'a>(
    c: &mut Container<'a>,
    walk: &mut Walk,
    area: &'a [u8],
    base: usize,
    at: usize,
    prefix: &str,
) -> Result<()> {
    let count = le_u32(area, at)
        .map_err(|_| error(format!("Truncated PSF2 directory at 0x{:X}", base + at)))?
        as usize;
    let entries_at = at + COUNT_SIZE;
    if count > (area.len() - entries_at) / ENTRY_SIZE {
        return Err(error(format!(
            "Invalid PSF2 directory at 0x{:X}: {count} entries exceed the reserved area",
            base + at
        )));
    }
    for i in 0..count {
        if walk.entries == container::MAX_COMPONENTS {
            walk.truncated = true;
            return Ok(());
        }
        walk.entries += 1;
        let entry_at = entries_at + i * ENTRY_SIZE;
        let entry = &area[entry_at..entry_at + ENTRY_SIZE];
        let name = entry_name(&entry[..NAME_SIZE])
            .ok_or_else(|| error(format!("Invalid PSF2 file name at 0x{:X}", base + entry_at)))?;
        let path = format!("{prefix}{name}");
        if path.len() > MAX_PATH {
            return Err(error(format!(
                "Invalid PSF2 path at 0x{:X}: longer than {MAX_PATH} B",
                base + entry_at
            )));
        }
        if prefix.is_empty() && name.eq_ignore_ascii_case(DRIVER) {
            walk.has_driver = true;
        }
        let offset = le_u32(entry, ENTRY_OFFSET)? as usize;
        let size = le_u32(entry, ENTRY_LENGTH)?;
        let block = le_u32(entry, ENTRY_BLOCK_SIZE)?;
        if (offset, size, block) == (0, 0, 0) {
            walk.files += 1;
            c.push_metadata(format!("psf_file_{}", walk.files - 1), path, "empty file");
            continue;
        }
        if offset <= entry_at || offset > area.len() {
            return Err(error(format!(
                "Invalid PSF2 entry {path} at 0x{:X}: offset 0x{offset:X} does not lie after the entry in the reserved area",
                base + entry_at
            )));
        }
        if (size, block) == (0, 0) {
            walk.directories += 1;
            directory(c, walk, area, base, offset, &format!("{path}/"))?;
        } else {
            let entry = FileEntry {
                path: &path,
                offset,
                size,
                block,
            };
            file(c, walk, area, base, &entry)?;
        }
    }
    Ok(())
}

/// Decode block `index` of `path`, which must produce exactly `expected`
/// bytes.
fn decode_block(stored: &[u8], expected: usize, path: &str, index: usize) -> Result<Vec<u8>> {
    let decoded = compressed::decode_limited(Codec::Zlib, stored, expected)
        .map_err(|e| error(format!("Invalid PSF2 block {index} of {path}: {e}")))?;
    if decoded.data.len() != expected {
        return Err(error(format!(
            "Invalid PSF2 block {index} of {path}: {} B decoded, {expected} B expected",
            decoded.data.len()
        )));
    }
    Ok(decoded.data)
}

/// A file's directory entry.
struct FileEntry<'p> {
    /// Path from the root, `/`-separated.
    path: &'p str,
    /// Offset of the size table in the reserved area.
    offset: usize,
    /// Uncompressed size, in bytes.
    size: u32,
    /// Uncompressed size of every block but the last, in bytes.
    block: u32,
}

/// A file entry: validate its size table and blocks, record it, and decode
/// it when its first block starts a recognized format.
fn file<'a>(
    c: &mut Container<'a>,
    walk: &mut Walk,
    area: &'a [u8],
    base: usize,
    entry: &FileEntry<'_>,
) -> Result<()> {
    let FileEntry { path, offset, .. } = *entry;
    walk.files += 1;
    walk.total_size += u64::from(entry.size);
    if entry.block == 0 {
        return Err(error(format!("Invalid PSF2 file {path}: block size 0")));
    }
    let size = entry.size as usize;
    let block = entry.block as usize;
    let blocks = size / block + usize::from(size % block != 0);
    if blocks > (area.len() - offset) / BLOCK_SIZE_ENTRY {
        return Err(error(format!(
            "Invalid PSF2 file {path}: a size table of {blocks} entries exceeds the reserved area"
        )));
    }
    let mut ranges = Vec::with_capacity(blocks);
    let mut at = offset + blocks * BLOCK_SIZE_ENTRY;
    for i in 0..blocks {
        let stored = le_u32(area, offset + i * BLOCK_SIZE_ENTRY)? as usize;
        let end = at
            .checked_add(stored)
            .filter(|end| *end <= area.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated PSF2 file {path}: block {i} at 0x{:X} exceeds the reserved area",
                    base + at
                ))
            })?;
        ranges.push(at..end);
        at = end;
    }
    let stored_size = at - offset;
    c.push_metadata(
        format!("psf_file_{}", walk.files - 1),
        path.to_string(),
        format!(
            "file 0x{:X}; {size} B in {blocks} zlib blocks of {block} B",
            base + offset
        ),
    );
    let Some(first) = ranges.first() else {
        return Ok(());
    };
    let fits = c.children.len() < container::MAX_COMPONENTS
        && size <= MAX_PAYLOAD
        && walk.extracted + size <= container::MAX_EXTRACTED;
    if !fits {
        walk.undecoded += 1;
        return Ok(());
    }
    let mut content = decode_block(&area[first.clone()], block.min(size), path, 0)?;
    if !container::is_recognized(&content) {
        return Ok(());
    }
    for (i, range) in ranges.iter().enumerate().skip(1) {
        let expected = block.min(size - i * block);
        content.extend(decode_block(&area[range.clone()], expected, path, i)?);
    }
    walk.extracted += size;
    c.children.push(
        Child::decoded(
            path.to_string(),
            base + offset,
            stored_size,
            Cow::Owned(content),
            Codec::Zlib.name(),
        )
        .if_recognized(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_nul_padded_printable_ascii_without_separators() {
        let mut field = [0u8; NAME_SIZE];
        field[..8].copy_from_slice(b"psf2.irx");
        assert_eq!(entry_name(&field), Some("psf2.irx"));
        assert_eq!(
            entry_name(&[b'x'; NAME_SIZE]).map(str::len),
            Some(NAME_SIZE)
        );
        assert_eq!(entry_name(&[0; NAME_SIZE]), None);
        field[0] = b'/';
        assert_eq!(entry_name(&field), None);
    }
}
