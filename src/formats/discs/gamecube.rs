//! `GameCube` disc images: the disc header (`boot.bin`), `bi2.bin`, the
//! apploader, the boot DOL and the FST (sources in the family module).
//!
//! Every field is big-endian and every offset a byte offset in the image
//! (Dolphin's `GameCube` volumes use an offset shift of 0). The disc carries
//! no signature or checksum, so nothing here is authenticated.

use super::*;
use crate::formats::container::Target;
use crate::types::{Endianness, Isa};

/// Disc magic at 0x1C (`GAMECUBE_DISC_MAGIC`; YAGCD "DVD Magic Word").
const GAMECUBE_DISC_MAGIC: u32 = 0xC233_9F3D;
const MAGIC_OFFSET: usize = 0x1C;

/// Main executable offset, FST offset, FST size and maximum FST size in
/// the disc header (YAGCD 13.1; Dolphin `GetBootDOLOffset`,
/// `GetFSTOffset`, `GetFSTSize`).
const DOL_OFFSET_FIELD: usize = 0x420;
const FST_OFFSET_FIELD: usize = 0x424;
const FST_SIZE_FIELD: usize = 0x428;
const FST_MAX_SIZE_FIELD: usize = 0x42C;

/// Country code of `bi2.bin` (0x440 + 0x18), which Dolphin reads as the
/// region (`VolumeGC::GetRegion`).
const REGION_OFFSET: usize = 0x458;

/// The apploader header (`APPLOADER_ADDRESS`; YAGCD 13.3): the date
/// (10 ASCII bytes and padding; Dolphin reads 16), entry point, code size
/// and trailer size, then the code.
const APPLOADER_ADDRESS: usize = 0x2440;
const APPLOADER_HEADER_SIZE: usize = 0x20;
const APPLOADER_DATE_SIZE: usize = 16;
const APPLOADER_ENTRY: usize = 0x10;
const APPLOADER_CODE_SIZE: usize = 0x14;
const APPLOADER_TRAILER_SIZE: usize = 0x18;

/// Where the apploader code and trailer are loaded (YAGCD 13.3; Dolphin
/// `RunApploader` reads them to physical 0x01200000).
const APPLOADER_LOAD_ADDRESS: u32 = 0x8120_0000;

/// The disc header, `bi2.bin` and the apploader header: the bytes every
/// `GameCube` image holds before its apploader code.
const SYSTEM_AREA_SIZE: usize = APPLOADER_ADDRESS + APPLOADER_HEADER_SIZE;

/// The DOL header (Dolphin `DolReader.h`, `SDolHeader`): 7 text and 11
/// data section offsets from 0x00, their sizes from 0x90 in the same
/// order, and the entry point at 0xE0.
const DOL_HEADER_SIZE: usize = 0x100;
const DOL_SECTIONS: usize = 7 + 11;
const DOL_SECTION_OFFSETS: usize = 0x00;
const DOL_SECTION_SIZES: usize = 0x90;
const DOL_ENTRY: usize = 0xE0;

/// An FST entry: three 32-bit words (`FST_ENTRY_SIZE`).
const FST_ENTRY_SIZE: usize = 12;

/// Largest FST Dolphin loads (`ARBITRARY_FILE_SYSTEM_SIZE_LIMIT`).
const MAX_FST_SIZE: u32 = 128 << 20;

/// Deepest directory nesting the FST walk validates. Each open directory
/// is kept on a stack, so this bounds its memory; Dolphin sets no limit,
/// and real discs nest a few levels.
const MAX_FST_NESTING: usize = 1024;

/// The low three bytes of an entry's first word are its name offset in
/// the string table; a nonzero top byte marks a directory.
const FST_NAME_OFFSET_MASK: u32 = 0x00FF_FFFF;
const FST_DIRECTORY_MASK: u32 = 0xFF00_0000;

/// The CPU the apploader runs on: Dolphin's `RunFunction` single-steps the
/// emulated PowerPC from its entry point, with `MSR[LE]` clear.
const APPLOADER_TARGET: Target = Target::new(Isa::Ppc, 32, Endianness::Big);

/// Strong recognition: the magic at 0x1C.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(MAGIC_OFFSET..MAGIC_OFFSET + 4)?;
    (magic == GAMECUBE_DISC_MAGIC.to_be_bytes()).then_some(Layout::GameCube)
}

/// Parse a `GameCube` disc image: header notes, the boot DOL and apploader
/// as children, and the FST files that are a recognized format.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = disc_header(data)?;
    let magic = be_u32(data, MAGIC_OFFSET)?;
    if magic != GAMECUBE_DISC_MAGIC {
        return Err(error(format!(
            "Invalid GameCube disc magic 0x{magic:08X} at 0x{MAGIC_OFFSET:X}"
        )));
    }
    if data.len() < SYSTEM_AREA_SIZE {
        return Err(error(format!(
            "Truncated GameCube system area: {} B of 0x{SYSTEM_AREA_SIZE:X} B (disc header, bi2.bin and apploader header)",
            data.len()
        )));
    }
    let mut c = Container::new(
        FileFormat::GameCubeDisc,
        Layout::GameCube.label(),
        "gamecube",
    );
    c.consumed = data.len();
    push_disc_header(&mut c, &header);
    push_region(&mut c, be_u32(data, REGION_OFFSET)?);
    // The boot DOL comes first: it is the program the disc boots, so it
    // supplies the primary ISA. The apploader, which runs on the same CPU,
    // stands in when there is no DOL, and both precede the FST files, which
    // can hold anything.
    push_boot_dol(data, &mut c)?;
    push_apploader(data, &mut c)?;
    push_fst_members(data, &mut c)?;
    Ok(c)
}

/// The apploader as a child: its code and trailer, which Dolphin's
/// `RunApploader` loads together to 0x81200000 and runs on the PowerPC.
fn push_apploader<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<()> {
    let header = slice(data, APPLOADER_ADDRESS, APPLOADER_HEADER_SIZE)?;
    let date = ascii_text(&header[..APPLOADER_DATE_SIZE]);
    let entry = be_u32(header, APPLOADER_ENTRY)?;
    let code_size = be_u32(header, APPLOADER_CODE_SIZE)?;
    let trailer_size = be_u32(header, APPLOADER_TRAILER_SIZE)?;
    let loaded_size = u64::from(code_size) + u64::from(trailer_size);
    // `RunApploader` rejects both values as a corrupted apploader.
    if entry == u32::MAX || loaded_size == u64::from(u32::MAX) {
        return Err(error(format!(
            "Invalid apploader header at 0x{APPLOADER_ADDRESS:X}: entry 0x{entry:08X}, {code_size} B of code, {trailer_size} B of trailer"
        )));
    }
    let prefix = c.key_prefix;
    c.push_metadata(
        format!("{prefix}_apploader_date"),
        "Apploader date",
        date.clone(),
    );
    c.push_metadata(
        format!("{prefix}_apploader_entry"),
        "Apploader entry point",
        u64::from(entry),
    );
    if loaded_size == 0 {
        c.notes.push(format!(
            "Apploader {date} is empty (code and trailer sizes are 0)"
        ));
        return Ok(());
    }
    let start = APPLOADER_ADDRESS + APPLOADER_HEADER_SIZE;
    if loaded_size > MAX_PAYLOAD as u64 {
        return Err(error(format!(
            "Invalid apploader size {loaded_size} B at 0x{start:X}"
        )));
    }
    let code = range(data, start as u64, loaded_size).ok_or_else(|| {
        error(format!(
            "Truncated apploader at 0x{start:X} + {loaded_size} B"
        ))
    })?;
    c.notes.push(format!(
        "Apploader {date}: entry 0x{entry:08X}; {code_size} B of code and {trailer_size} B of trailer loaded at 0x{APPLOADER_LOAD_ADDRESS:08X} and run on the PowerPC"
    ));
    c.children.push(
        Child::stored("Apploader", start, code)
            .as_code()
            .with_target(APPLOADER_TARGET),
    );
    Ok(())
}

/// The boot DOL (main executable) as a child, which the DOL parser
/// classifies. Datel discs leave its offset 0 (Dolphin
/// `GetBootDOLOffset`).
fn push_boot_dol<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<()> {
    let offset = to_usize(u64::from(be_u32(data, DOL_OFFSET_FIELD)?), "DOL offset")?;
    if offset == 0 {
        c.notes
            .push("No main executable: the DOL offset is 0, as on Datel discs".into());
        return Ok(());
    }
    let header = slice(data, offset, DOL_HEADER_SIZE)
        .map_err(|_| error(format!("Truncated main executable header at 0x{offset:X}")))?;
    let end = dol_end(header)?.ok_or_else(|| {
        error(format!(
            "Invalid main executable at 0x{offset:X}: every DOL section is empty"
        ))
    })?;
    let size = end.max(DOL_HEADER_SIZE as u64);
    if size > MAX_PAYLOAD as u64 {
        return Err(error(format!(
            "Invalid main executable size {size} B at 0x{offset:X}"
        )));
    }
    let bytes = range(data, offset as u64, size).ok_or_else(|| {
        error(format!(
            "Truncated main executable at 0x{offset:X} + {size} B"
        ))
    })?;
    let entry = be_u32(header, DOL_ENTRY)?;
    c.notes.push(format!(
        "Main executable: {size} B DOL at 0x{offset:X}; entry 0x{entry:08X}"
    ));
    let prefix = c.key_prefix;
    c.push_metadata(
        format!("{prefix}_dol_offset"),
        "Main executable offset",
        offset as u64,
    );
    c.push_metadata(
        format!("{prefix}_dol_size"),
        "Main executable size (B)",
        size,
    );
    c.children
        .push(Child::stored("Main executable (DOL)", offset, bytes));
    Ok(())
}

/// The end of the last non-empty section of the DOL whose header is
/// `header`, or `None` when every section is empty. Dolphin's
/// `GetBootDOLSize` takes the largest `offset + size` over all 18 sections;
/// `DolReader` loads only the non-empty ones, and only those count here.
fn dol_end(header: &[u8]) -> Result<Option<u64>> {
    let mut end = None;
    for i in 0..DOL_SECTIONS {
        let offset = be_u32(header, DOL_SECTION_OFFSETS + 4 * i)?;
        let size = be_u32(header, DOL_SECTION_SIZES + 4 * i)?;
        if size != 0 {
            end = end.max(Some(u64::from(offset) + u64::from(size)));
        }
    }
    Ok(end)
}

/// Probe for FST files: a recognized prefix, or a DOL header whose
/// sections end inside the file. DOL detection checks the whole section
/// table against the file size, so a prefix alone never recognizes a DOL.
fn is_member_candidate(bytes: &[u8]) -> bool {
    if is_prefix_recognized(bytes) {
        return true;
    }
    let Some(header) = bytes.get(..DOL_HEADER_SIZE) else {
        return false;
    };
    matches!(
        dol_end(header),
        Ok(Some(end)) if end >= DOL_HEADER_SIZE as u64 && end <= bytes.len() as u64
    )
}

/// One FST entry (YAGCD 13.4.1; Dolphin `FileInfoGCWii`).
struct FstEntry {
    /// Nonzero top byte of the first word.
    is_directory: bool,
    /// Offset of the NUL-terminated name in the string table.
    name_offset: usize,
    /// Files: byte offset of the data in the image. Directories: index of
    /// the parent directory (0 for the root).
    offset_or_parent: u32,
    /// Files: size in bytes. Directories: index of the first entry after
    /// the directory (the root: the entry count).
    size_or_next: u32,
}

/// The FST entry with index `index`; the caller has checked that the entry
/// table holds it.
fn fst_entry(fst: &[u8], index: usize) -> Result<FstEntry> {
    let at = index * FST_ENTRY_SIZE;
    let flags_and_name = be_u32(fst, at)?;
    Ok(FstEntry {
        is_directory: flags_and_name & FST_DIRECTORY_MASK != 0,
        name_offset: (flags_and_name & FST_NAME_OFFSET_MASK) as usize,
        offset_or_parent: be_u32(fst, at + 4)?,
        size_or_next: be_u32(fst, at + 8)?,
    })
}

/// The name of FST entry `index`. The name must start inside the string
/// table (Dolphin: "Impossibly large name offset"), which ends with a NUL
/// byte, so every name in it is terminated.
fn fst_name(names: &[u8], entry: &FstEntry, index: usize) -> Result<String> {
    let raw = names.get(entry.name_offset..).filter(|raw| !raw.is_empty());
    let raw = raw.ok_or_else(|| {
        error(format!(
            "Invalid FST entry {index}: name offset 0x{:X} outside the {} B string table",
            entry.name_offset,
            names.len()
        ))
    })?;
    Ok(ascii_text(raw))
}

/// A directory the FST walk is inside.
#[derive(Clone, Copy)]
struct OpenDirectory {
    /// Index of the directory's entry.
    index: usize,
    /// Index of the first entry after the directory.
    next: usize,
    /// Length of the walk path before the directory's name was appended.
    parent_path_len: usize,
    /// Whether the directory is within the depth and path limits.
    is_walked: bool,
}

/// Validate the FST the way Dolphin's `FileSystemGCWii` does and list its
/// files that are a recognized format.
fn push_fst_members<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<()> {
    let offset = be_u32(data, FST_OFFSET_FIELD)?;
    let size = be_u32(data, FST_SIZE_FIELD)?;
    let max_size = be_u32(data, FST_MAX_SIZE_FIELD)?;
    if size == 0 {
        c.notes
            .push("No FST: its size is 0, so no files are listed".into());
        return Ok(());
    }
    if (size as usize) < FST_ENTRY_SIZE || size > MAX_FST_SIZE {
        return Err(error(format!("Invalid FST size {size} B at 0x{offset:X}")));
    }
    let fst = range(data, u64::from(offset), u64::from(size))
        .ok_or_else(|| error(format!("Truncated FST at 0x{offset:X} + {size} B")))?;
    let root = fst_entry(fst, 0)?;
    if !root.is_directory {
        return Err(error("Invalid FST: the root entry is not a directory"));
    }
    // The root is its own parent (Dolphin validates it against itself).
    if root.offset_or_parent != 0 {
        return Err(error(format!(
            "Invalid FST root: parent index {} instead of 0",
            root.offset_or_parent
        )));
    }
    let count = root.size_or_next as usize;
    let table_size = count
        .checked_mul(FST_ENTRY_SIZE)
        .filter(|table_size| count > 0 && *table_size <= fst.len())
        .ok_or_else(|| error(format!("Invalid FST entry count {count} for {size} B")))?;
    if fst.last() != Some(&0) {
        return Err(error(
            "Invalid FST: the string table does not end with a NUL byte",
        ));
    }
    let names = &fst[table_size..];
    fst_name(names, &root, 0)?;
    let mut members = Members::new(is_member_candidate);
    let directories = walk_fst(data, fst, names, count, &mut members)?;
    c.notes.push(format!(
        "FST at 0x{offset:X}: {size} B, {}, {}",
        counted(count, "entry", "entries"),
        counted(directories, "directory", "directories")
    ));
    let prefix = c.key_prefix;
    c.push_metadata(
        format!("{prefix}_fst_offset"),
        "FST offset",
        u64::from(offset),
    );
    c.push_metadata(
        format!("{prefix}_fst_size"),
        "FST size (B)",
        u64::from(size),
    );
    c.push_metadata(
        format!("{prefix}_fst_max_size"),
        "Maximum FST size (B)",
        u64::from(max_size),
    );
    members.finish(c);
    Ok(())
}

/// Walk FST entries 1 to `count - 1` in order, keeping the directories
/// that contain the current entry on a stack. Every directory's parent
/// must be the directory that contains it, and its range must lie inside
/// its parent's (Dolphin `FileInfoGCWii::IsValid`). Returns the number of
/// directories below the root.
fn walk_fst<'a>(
    data: &'a [u8],
    fst: &[u8],
    names: &[u8],
    count: usize,
    members: &mut Members<'a>,
) -> Result<usize> {
    let mut open = vec![OpenDirectory {
        index: 0,
        next: count,
        parent_path_len: 0,
        is_walked: true,
    }];
    let mut path = String::new();
    let mut directories = 0;
    for index in 1..count {
        while open.last().is_some_and(|d| d.next <= index) {
            let done = open.pop().expect("the stack is not empty");
            path.truncate(done.parent_path_len);
        }
        // The root ends after the last entry, so it is never closed.
        let parent = *open.last().expect("the root contains every entry");
        let entry = fst_entry(fst, index)?;
        let name = fst_name(names, &entry, index)?;
        if !entry.is_directory {
            if parent.is_walked {
                let file_path = format!("{path}/{name}");
                members.offer(
                    data,
                    &file_path,
                    u64::from(entry.offset_or_parent),
                    u64::from(entry.size_or_next),
                );
            } else {
                members.files += 1;
            }
            continue;
        }
        let next = entry.size_or_next as usize;
        if entry.offset_or_parent as usize != parent.index {
            return Err(error(format!(
                "Invalid FST entry {index}: parent index {} instead of {}",
                entry.offset_or_parent, parent.index
            )));
        }
        if next <= index || next > parent.next {
            return Err(error(format!(
                "Invalid FST entry {index}: next index {next} outside {}..={}",
                index + 1,
                parent.next
            )));
        }
        if open.len() > MAX_FST_NESTING {
            return Err(error(format!(
                "Unsupported FST: directories nested deeper than {MAX_FST_NESTING} levels at entry {index}"
            )));
        }
        directories += 1;
        let parent_path_len = path.len();
        let mut is_walked = false;
        if parent.is_walked {
            path.push('/');
            path.push_str(&name);
            is_walked = is_walkable(open.len(), &path);
            if !is_walked {
                members.unwalked_directories += 1;
                path.truncate(parent_path_len);
            }
        }
        open.push(OpenDirectory {
            index,
            next,
            parent_path_len,
            is_walked,
        });
    }
    Ok(directories)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DOL header with one text section at `offset` of `size` bytes.
    fn dol_header(offset: u32, size: u32) -> Vec<u8> {
        let mut header = vec![0u8; DOL_HEADER_SIZE];
        header[0..4].copy_from_slice(&offset.to_be_bytes());
        header[DOL_SECTION_SIZES..DOL_SECTION_SIZES + 4].copy_from_slice(&size.to_be_bytes());
        header
    }

    #[test]
    fn dol_end_counts_only_non_empty_sections() {
        let mut header = dol_header(0x100, 0x40);
        assert_eq!(dol_end(&header).unwrap(), Some(0x140));
        // An empty data section with a stray offset does not extend the DOL.
        header[0x1C..0x20].copy_from_slice(&0x9000u32.to_be_bytes());
        assert_eq!(dol_end(&header).unwrap(), Some(0x140));
        assert_eq!(dol_end(&[0u8; DOL_HEADER_SIZE]).unwrap(), None);
        assert!(dol_end(&header[..0x80]).is_err());
    }

    #[test]
    fn dol_candidates_must_fit_their_file() {
        let mut file = dol_header(0x100, 0x40);
        file.resize(0x140, 0);
        assert!(is_member_candidate(&file));
        assert!(!is_member_candidate(&file[..0x13F]));
        assert!(!is_member_candidate(&[0u8; 0x200]));
    }

    #[test]
    fn fst_entries_split_flags_and_name_offsets() {
        let mut fst = vec![0u8; FST_ENTRY_SIZE];
        fst[0..4].copy_from_slice(&0x0100_0010u32.to_be_bytes());
        fst[8..12].copy_from_slice(&3u32.to_be_bytes());
        let entry = fst_entry(&fst, 0).unwrap();
        assert!(entry.is_directory);
        assert_eq!(entry.name_offset, 0x10);
        assert_eq!(entry.size_or_next, 3);
        assert!(fst_entry(&fst, 1).is_err());
    }
}
