//! The Atari DOS 2.0S, 2.0D and 2.5 file system on 128- and 256-byte
//! sectors ("Inside Atari DOS" chapter 2; Altirra 4.31 `diskfsdos2.cpp`;
//! `AtariSIO` `Dos2xUtils.cpp`).
//!
//! - VTOC, sector 360: the DOS code (2 for DOS 2.x) at 0, the total and free
//!   sector counts (2 + 2, little-endian) at 1 and 3, and from byte 10 a
//!   bitmap of sectors 0-719 in which a set bit (0x80 first) marks a free
//!   sector. The boot sectors 1-3 and sectors 360-368 (VTOC and directory)
//!   are always in use (Altirra `Validate`).
//! - Directory, sectors 361-368: eight 16-byte entries in the first 128
//!   bytes of each sector, 64 in all; entry n describes file number n. An
//!   entry holds the flags, the sector count (2), the first sector (2), the
//!   name (8) and the extension (3), space-padded. The first entry with
//!   flags 0 ends the directory.
//! - Data sectors: size - 3 data bytes (125 or 253), then the file number
//!   (bits 7-2) with bits 9-8 of the next sector (bits 1-0), the low byte of
//!   the next sector (0 ends the file) and the number of data bytes used
//!   (bit 7 masked on 128-byte sectors, Altirra `GetSectorDataBytes`).
//!
//! Flags (Altirra `DirEnt`): 0x80 deleted, 0x40 in use, 0x20 locked, 0x10
//! `MyDOS` subdirectory, 0x04 `MyDOS` 16-bit sector links, 0x02 written by
//! DOS 2, 0x01 open for output. Deleted and open entries are hidden; DOS 2.5
//! (1040 sectors of 128 bytes) marks a file that uses sectors above 719 with
//! 0x03 and the in-use bit clear (Altirra `IsVisible`; `AtariSIO`
//! `SetAtariDirectory`). DOS 1.x files (0x02 clear) use another sector
//! format and `MyDOS` entries other links; both are noted, not extracted.
//!
//! Each file is reassembled from its sector chain, which must stay on the
//! disk, carry the file's number in every sector and visit no sector twice
//! (Altirra `ReadFile`). Binary load files are 6502 code; other files are
//! listed as opaque.

use super::atr::{Disk, Sector};
use super::*;
use crate::formats::container::{Child, MAX_EXTRACTED};
use std::borrow::Cow;
use std::ops::{Range, RangeInclusive};

/// VTOC sector and fields.
const VTOC_SECTOR: usize = 360;
const VTOC_CODE: usize = 0;
const VTOC_TOTAL: usize = 1;
const VTOC_FREE: usize = 3;
const VTOC_BITMAP: usize = 10;

/// DOS codes in the VTOC (Altirra `Init`).
const DOS1_CODE: u8 = 1;
const DOS2_CODE: u8 = 2;

/// The VTOC bitmap maps sectors 0-719, so a DOS 2.x disk has at least 720.
const MIN_SECTORS: usize = 720;

/// DOS 2.5 enhanced density: 1040 sectors of 128 bytes.
const DOS25_SECTORS: usize = 1040;

/// Sectors DOS 2.x keeps in use: the boot sectors, the VTOC and the
/// directory.
const BOOT_SECTORS: RangeInclusive<usize> = 1..=3;
const SYSTEM_SECTORS: RangeInclusive<usize> = 360..=368;

/// Directory geometry.
const DIRECTORY_SECTOR: usize = 361;
const ENTRIES_PER_SECTOR: usize = 8;
const ENTRY_SIZE: usize = 16;
const MAX_FILES: usize = 64;

/// Directory entry fields.
const ENTRY_FLAGS: usize = 0;
const ENTRY_SECTOR_COUNT: usize = 1;
const ENTRY_FIRST_SECTOR: usize = 3;
const ENTRY_NAME: Range<usize> = 5..13;
const ENTRY_EXTENSION: Range<usize> = 13..16;

/// Directory flags (Altirra `DirEnt`).
const FLAG_DELETED: u8 = 0x80;
const FLAG_IN_USE: u8 = 0x40;
const FLAG_SUBDIRECTORY: u8 = 0x10;
const FLAG_EXTENDED_LINKS: u8 = 0x04;
const FLAG_DOS2: u8 = 0x02;
const FLAG_OPEN_FOR_OUTPUT: u8 = 0x01;

/// The DOS 2.5 flag combination of a file that uses sectors above 719.
const DOS25_EXTENDED_MASK: u8 = FLAG_IN_USE | FLAG_DOS2 | FLAG_OPEN_FOR_OUTPUT;
const DOS25_EXTENDED: u8 = FLAG_DOS2 | FLAG_OPEN_FOR_OUTPUT;

/// Data sector trailer: link and file number, link low byte, byte count.
const TRAILER_SIZE: usize = 3;
const LINK_HIGH_MASK: u8 = 0x03;
const FILE_NUMBER_SHIFT: u8 = 2;
const SINGLE_DENSITY_COUNT_MASK: u8 = 0x7f;

/// Transform of a file gathered from more than one sector.
const CHAIN_TRANSFORM: &str = "DOS 2 sector chain";

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// A recognized DOS 2.x VTOC.
struct Vtoc<'a> {
    bytes: &'a [u8],
    /// DOS 2.5 enhanced density.
    dos25: bool,
}

impl Vtoc<'_> {
    fn is_free(&self, sector: usize) -> bool {
        let mask = 0x80u8 >> (sector % 8);
        self.bytes
            .get(VTOC_BITMAP + sector / 8)
            .is_some_and(|byte| byte & mask != 0)
    }

    fn total(&self) -> u16 {
        le_u16(self.bytes, VTOC_TOTAL).unwrap_or_default()
    }

    fn free(&self) -> u16 {
        le_u16(self.bytes, VTOC_FREE).unwrap_or_default()
    }
}

/// The DOS 2.x VTOC of `disk`, or the note that says why there is none.
fn mount<'a>(disk: &Disk<'a>) -> std::result::Result<Vtoc<'a>, String> {
    let size = disk.sector_size();
    if size != SINGLE_DENSITY && size != DOUBLE_DENSITY {
        return Err(format!(
            "No Atari DOS 2.x file system: DOS 2.x uses 128- or 256-byte sectors, not {size} B"
        ));
    }
    if disk.sector_count() < MIN_SECTORS {
        return Err(format!(
            "No Atari DOS 2.x file system: {}, fewer than the {MIN_SECTORS} its VTOC maps",
            count_text(disk.sector_count(), "sector")
        ));
    }
    let bytes = disk.sector(VTOC_SECTOR).map_or(&[][..], |s| s.bytes);
    match bytes.get(VTOC_CODE).copied() {
        Some(DOS2_CODE) => {}
        Some(DOS1_CODE) => {
            return Err(
                "No Atari DOS 2.x file system: VTOC code 0x01 at sector 360 is the DOS 1.x code"
                    .into(),
            )
        }
        code => {
            return Err(format!(
                "No Atari DOS 2.x file system: VTOC code 0x{:02X} at sector 360 (DOS 2.x writes \
                    0x02)",
                code.unwrap_or_default()
            ))
        }
    }
    let vtoc = Vtoc {
        bytes,
        dos25: size == SINGLE_DENSITY && disk.sector_count() == DOS25_SECTORS,
    };
    if let Some(sector) = BOOT_SECTORS
        .chain(SYSTEM_SECTORS)
        .find(|&s| vtoc.is_free(s))
    {
        return Err(format!(
            "No Atari DOS 2.x file system: the VTOC at sector 360 marks sector {sector} free, \
                which DOS 2.x keeps in use"
        ));
    }
    Ok(vtoc)
}

/// How a directory entry is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// A DOS 2 file, extracted.
    File,
    /// Deleted, or not in use.
    Hidden,
    /// Open for output: DOS 2.x does not list it.
    OpenForOutput,
    /// Written by DOS 1.x, whose sector format differs.
    Dos1,
    /// A `MyDOS` subdirectory.
    Subdirectory,
    /// A `MyDOS` file with 16-bit sector links.
    ExtendedLinks,
}

fn entry_kind(flags: u8, dos25: bool) -> EntryKind {
    if flags & FLAG_DELETED != 0 {
        EntryKind::Hidden
    } else if flags & FLAG_SUBDIRECTORY != 0 {
        EntryKind::Subdirectory
    } else if dos25 && flags & DOS25_EXTENDED_MASK == DOS25_EXTENDED {
        EntryKind::File
    } else if flags & FLAG_OPEN_FOR_OUTPUT != 0 {
        EntryKind::OpenForOutput
    } else if flags & FLAG_IN_USE == 0 {
        EntryKind::Hidden
    } else if flags & FLAG_DOS2 == 0 {
        EntryKind::Dos1
    } else if flags & FLAG_EXTENDED_LINKS != 0 {
        EntryKind::ExtendedLinks
    } else {
        EntryKind::File
    }
}

/// The 16 bytes of directory entry `number` (0-63).
fn directory_entry<'a>(disk: &Disk<'a>, number: usize) -> Option<&'a [u8]> {
    let sector = disk.sector(DIRECTORY_SECTOR + number / ENTRIES_PER_SECTOR)?;
    let at = (number % ENTRIES_PER_SECTOR) * ENTRY_SIZE;
    sector.bytes.get(at..at + ENTRY_SIZE)
}

/// `NAME.EXT` from the space-padded fields; bytes outside printable ASCII
/// are replaced.
fn file_name(entry: &[u8], number: usize) -> String {
    let text = |field: &[u8]| -> String {
        let end = field
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |last| last + 1);
        field[..end]
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() {
                    char::from(b)
                } else {
                    char::REPLACEMENT_CHARACTER
                }
            })
            .collect()
    };
    let name = text(&entry[ENTRY_NAME]);
    let extension = text(&entry[ENTRY_EXTENSION]);
    match (name.is_empty(), extension.is_empty()) {
        (true, true) => format!("File {number}"),
        (_, true) => name,
        _ => format!("{name}.{extension}"),
    }
}

/// A file's bytes and where its first sector is stored.
struct FileData<'a> {
    /// File offset of the first sector.
    offset: usize,
    /// Data bytes in the first sector.
    first_size: usize,
    /// Sectors in the chain.
    sectors: usize,
    data: Cow<'a, [u8]>,
}

/// Follow the chain of file `number` from `first`. `marks` records, per
/// sector, the last file that visited it, so a loop is found without
/// clearing it between files.
fn read_file<'a>(
    disk: &Disk<'a>,
    number: usize,
    first: usize,
    marks: &mut [u8],
) -> std::result::Result<FileData<'a>, String> {
    if first == 0 {
        return Err("the directory names sector 0 as its first sector".into());
    }
    let size = disk.sector_size();
    let capacity = size - TRAILER_SIZE;
    let mark = u8::try_from(number + 1).expect("at most 64 files");
    let mut runs: Vec<Sector<'a>> = Vec::new();
    let mut sector = first;
    while sector != 0 {
        let Some(stored) = disk.sector(sector) else {
            return Err(format!(
                "sector {sector} is beyond the {}-sector disk",
                disk.sector_count()
            ));
        };
        if stored.bytes.len() != size {
            return Err(format!("sector {sector} is a 128-byte boot sector"));
        }
        if marks[sector] == mark {
            return Err(format!("sector {sector} appears twice in the chain"));
        }
        marks[sector] = mark;
        let trailer = &stored.bytes[capacity..];
        let owner = usize::from(trailer[0] >> FILE_NUMBER_SHIFT);
        if owner != number {
            return Err(format!("sector {sector} carries file number {owner}"));
        }
        let used = if size == SINGLE_DENSITY {
            trailer[2] & SINGLE_DENSITY_COUNT_MASK
        } else {
            trailer[2]
        };
        let used = usize::from(used);
        if used > capacity {
            return Err(format!(
                "sector {sector} declares {used} B of data, more than {capacity}"
            ));
        }
        runs.push(Sector {
            offset: stored.offset,
            bytes: &stored.bytes[..used],
        });
        sector = (usize::from(trailer[0] & LINK_HIGH_MASK) << 8) | usize::from(trailer[1]);
    }
    let head = runs[0];
    let data = if let [only] = runs.as_slice() {
        Cow::Borrowed(only.bytes)
    } else {
        Cow::Owned(
            runs.iter()
                .flat_map(|run| run.bytes.iter().copied())
                .collect(),
        )
    };
    Ok(FileData {
        offset: head.offset,
        first_size: head.bytes.len(),
        sectors: runs.len(),
        data,
    })
}

/// Notes about entries and chains, reported up to [`MAX_PROBLEM_NOTES`].
#[derive(Default)]
struct Problems {
    listed: Vec<String>,
    more: usize,
}

impl Problems {
    fn push(&mut self, note: String) {
        if self.listed.len() < MAX_PROBLEM_NOTES {
            self.listed.push(note);
        } else {
            self.more += 1;
        }
    }
}

/// The file as a child: 6502 code when it is a binary load file, opaque
/// otherwise.
fn file_child(name: String, file: FileData<'_>) -> Child<'_> {
    let child = match file.data {
        Cow::Borrowed(bytes) => Child::stored(name, file.offset, bytes),
        Cow::Owned(bytes) => Child::decoded(
            name,
            file.offset,
            file.first_size,
            Cow::Owned(bytes),
            CHAIN_TRANSFORM,
        ),
    };
    if xex::detect(&child.data) {
        child.with_target(MOS_6502).with_variant(CPU_VARIANT)
    } else {
        Child {
            opaque: true,
            ..child
        }
    }
}

/// List the files of a DOS 2.x file system in directory order, or note why
/// the disk has none.
pub(super) fn push_files<'a>(disk: &Disk<'a>, c: &mut Container<'a>) {
    let vtoc = match mount(disk) {
        Ok(vtoc) => vtoc,
        Err(note) => {
            c.notes.push(note);
            return;
        }
    };
    let mut marks = vec![0u8; disk.sector_count() + 1];
    let mut problems = Problems::default();
    let mut hidden = 0usize;
    let mut files = 0usize;
    let mut extracted = 0usize;
    for number in 0..MAX_FILES {
        let Some(entry) = directory_entry(disk, number) else {
            break;
        };
        let flags = entry[ENTRY_FLAGS];
        if flags == 0 {
            break;
        }
        let name = file_name(entry, number);
        match entry_kind(flags, vtoc.dos25) {
            EntryKind::File => {}
            EntryKind::Hidden => {
                hidden += 1;
                continue;
            }
            EntryKind::OpenForOutput => {
                problems.push(format!("{name}: open for output; not listed"));
                continue;
            }
            EntryKind::Dos1 => {
                problems.push(format!(
                    "{name}: DOS 1.x file; its sectors are not interpreted"
                ));
                continue;
            }
            EntryKind::Subdirectory => {
                problems.push(format!("{name}: MyDOS subdirectory; not interpreted"));
                continue;
            }
            EntryKind::ExtendedLinks => {
                problems.push(format!("{name}: MyDOS 16-bit sector links; not extracted"));
                continue;
            }
        }
        let first = usize::from(le_u16(entry, ENTRY_FIRST_SECTOR).unwrap_or_default());
        let file = match read_file(disk, number, first, &mut marks) {
            Ok(file) => file,
            Err(problem) => {
                problems.push(format!("{name}: {problem}; not extracted"));
                continue;
            }
        };
        let listed = usize::from(le_u16(entry, ENTRY_SECTOR_COUNT).unwrap_or_default());
        if listed != file.sectors {
            problems.push(format!(
                "{name}: the directory lists {}, the chain has {}",
                count_text(listed, "sector"),
                file.sectors
            ));
        }
        if extracted + file.data.len() > MAX_EXTRACTED {
            problems.push(format!(
                "{name}: extraction limit of {} reached; not extracted",
                size_text(MAX_EXTRACTED as u64)
            ));
            break;
        }
        extracted += file.data.len();
        files += 1;
        c.children.push(file_child(name, file));
    }
    let edition = if vtoc.dos25 {
        " (DOS 2.5 enhanced density)"
    } else {
        ""
    };
    c.notes.push(format!(
        "Atari DOS 2.x file system{edition}: {}; the VTOC records {} of {} sectors free",
        count_text(files, "file"),
        vtoc.free(),
        vtoc.total()
    ));
    if hidden > 0 {
        c.notes.push(format!(
            "Deleted or unused directory entries, not listed: {hidden}"
        ));
    }
    c.notes.extend(problems.listed);
    if problems.more > 0 {
        c.notes.push(format!(
            "Further file system problems, not listed: {}",
            problems.more
        ));
    }
    c.push_metadata("atr_dos_files", "DOS 2.x files", files as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_follow_altirra_visibility() {
        assert_eq!(entry_kind(0x42, false), EntryKind::File);
        assert_eq!(entry_kind(0x62, false), EntryKind::File);
        assert_eq!(entry_kind(0x80, false), EntryKind::Hidden);
        assert_eq!(entry_kind(0xc2, false), EntryKind::Hidden);
        assert_eq!(entry_kind(0x43, false), EntryKind::OpenForOutput);
        assert_eq!(entry_kind(0x03, false), EntryKind::OpenForOutput);
        assert_eq!(entry_kind(0x03, true), EntryKind::File);
        assert_eq!(entry_kind(0x40, false), EntryKind::Dos1);
        assert_eq!(entry_kind(0x46, false), EntryKind::ExtendedLinks);
        assert_eq!(entry_kind(0x10, false), EntryKind::Subdirectory);
    }

    #[test]
    fn names_are_trimmed_and_joined() {
        let mut entry = [b' '; ENTRY_SIZE];
        entry[ENTRY_NAME][..3].copy_from_slice(b"DUP");
        entry[ENTRY_EXTENSION].copy_from_slice(b"SYS");
        assert_eq!(file_name(&entry, 0), "DUP.SYS");
        entry[ENTRY_EXTENSION].copy_from_slice(b"   ");
        assert_eq!(file_name(&entry, 0), "DUP");
        entry[ENTRY_NAME].copy_from_slice(b"        ");
        assert_eq!(file_name(&entry, 5), "File 5");
        entry[ENTRY_NAME][0] = 0x9b;
        assert_eq!(file_name(&entry, 5), "\u{FFFD}");
    }

    #[test]
    fn problems_are_counted_beyond_the_limit() {
        let mut problems = Problems::default();
        for i in 0..MAX_PROBLEM_NOTES + 2 {
            problems.push(format!("problem {i}"));
        }
        assert_eq!(
            (problems.listed.len(), problems.more),
            (MAX_PROBLEM_NOTES, 2)
        );
    }
}
