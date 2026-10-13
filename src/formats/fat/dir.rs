//! FAT12, FAT16 and FAT32 volumes: the parse into the container model and
//! the directory walk. Directories are linear arrays of 32-byte entries
//! ([FATGEN] "FAT Directory Structure"); long names are sets of long
//! entries before their short entry, each carrying the checksum of the
//! short name ([FATGEN] "FAT Long Directory Entries"); entries are told
//! apart as [FATGEN] "Validating The Contents of a Directory" prescribes.

use super::bpb::{self, Geometry};
use super::table::Heap;
use super::walk::{self, DirectoryData, Extent, FileRef, Span, Walker, MAX_DEPTH};
use super::*;

/// `DIR_Attr` bits.
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
const ATTR_LONG_NAME_MASK: u8 = ATTR_LONG_NAME | ATTR_DIRECTORY | ATTR_ARCHIVE;

/// `DIR_Name[0]`: a free (deleted) entry; a free entry after which every
/// entry is free; the stand-in for a name that starts with 0xE5.
const DELETED: u8 = 0xe5;
const END_OF_DIRECTORY: u8 = 0x00;
const ESCAPED_E5: u8 = 0x05;

/// `LDIR_Ord` flag of the last long entry of a set, which is stored first.
const LAST_LONG_ENTRY: u8 = 0x40;

/// A long name has at most 255 characters: 20 entries of 13.
const MAX_LONG_ENTRIES: u8 = 20;
const LONG_ENTRY_CHARS: usize = 13;

/// UTF-16 name characters of a long entry: `LDIR_Name1` (offset 1, five
/// characters), `LDIR_Name2` (14, six) and `LDIR_Name3` (28, two).
const LONG_NAME_FIELDS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];

/// A directory holds at most 65,536 entries ([FATGEN] "Other Notes
/// Relating to FAT Directories").
const MAX_DIRECTORY_SIZE: u64 = 65_536 * DIRECTORY_ENTRY_SIZE as u64;

/// Bytes that are illegal in a short name, besides values below 0x20.
const ILLEGAL_SHORT_NAME_BYTES: [u8; 16] = [
    0x22, 0x2a, 0x2b, 0x2c, 0x2e, 0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x5b, 0x5c, 0x5d, 0x7c,
];

/// Characters that are illegal in a long name, besides control codes: the
/// short-name set without `+ , ; = [ ]` and `.` ([FATGEN] "Name Limits and
/// Character Sets").
const ILLEGAL_LONG_NAME_CHARS: [char; 9] = ['"', '*', '/', ':', '<', '>', '?', '\\', '|'];

/// The dot and dotdot entries of a subdirectory.
const DOT: &[u8; 11] = b".          ";
const DOT_DOT: &[u8; 11] = b"..         ";

/// Transform of a file whose clusters are not contiguous.
const CHAIN_TRANSFORM: &str = "FAT cluster chain";

/// Parse a FAT12, FAT16 or FAT32 volume.
///
/// # Errors
///
/// [`ClassifierError::FatParseError`] when the boot sector does not
/// validate (see [`Geometry::parse`]) or the cluster count makes the volume
/// another FAT type than `layout`.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let g = Geometry::parse(data)?;
    if g.layout() != layout {
        return Err(error(format!(
            "Invalid FAT type: the cluster count makes the volume {}, not {}",
            g.layout().label(),
            layout.label()
        )));
    }
    let mut c = Container::new(FileFormat::Fat, layout.label(), "fat");
    c.consumed = usize::try_from(g.volume_size()).map_or(data.len(), |size| size.min(data.len()));
    bpb::describe(&g, data, &mut c);
    let boot_code = boot_code(data, g.boot_code_start())?;
    c.notes.push(boot_code.note);
    walk_volume(&g, data, &mut c);
    // The volume's files describe it better than its boot stub (formatters
    // write x86 boot code onto volumes for any device), so the boot code
    // follows them and supplies the primary ISA only when no file does.
    c.children.extend(boot_code.child);
    Ok(c)
}

/// A subdirectory waiting to be read.
struct Pending {
    cluster: u32,
    node: usize,
    depth: usize,
}

/// The directory an entry is in: its path node and depth below the root.
#[derive(Debug, Clone, Copy)]
struct Location {
    node: usize,
    depth: usize,
}

/// A long-name set being read.
struct LongName {
    /// `LDIR_Chksum` of the set.
    checksum: u8,
    /// The ordinal of the entry expected next; 0 once entry 1 was read.
    next: u8,
    /// Name characters of the entries read so far, in stored order (the
    /// last part of the name first).
    parts: Vec<[u16; LONG_ENTRY_CHARS]>,
}

/// Long entries seen before the next short entry.
enum LongState {
    None,
    Collecting(LongName),
    /// A set broke; its remaining entries are skipped.
    Orphaned,
}

/// One directory's walk: the walker and the root's volume label.
struct DirectoryWalk<'w, 'v, 'a> {
    walker: &'w mut Walker<'v, 'a>,
    fat32: bool,
    label: Option<String>,
}

/// Walk the tree from the root directory and append the members to `c`.
/// Problems, including an unreadable FAT32 root directory, are notes.
fn walk_volume<'a>(g: &Geometry, data: &'a [u8], c: &mut Container<'a>) {
    let table = g.table(data);
    let heap = Heap {
        data,
        offset: g.heap_offset(),
        cluster_size: g.cluster_size(),
    };
    let mut walker = Walker::new(&table, &heap, CHAIN_TRANSFORM);
    let span = Span::Chain {
        max_size: MAX_DIRECTORY_SIZE,
    };
    // The FAT32 root directory is a cluster chain; the FAT12/FAT16 root is
    // the fixed region after the FATs.
    let root = if let Some(fields) = g.fat32 {
        walker.directory(fields.root_cluster, span)
    } else {
        let (offset, bytes) = g.root_region(data);
        Ok(DirectoryData {
            extents: vec![Extent { offset, bytes }],
            cut: false,
        })
    };
    let mut walk = DirectoryWalk {
        walker: &mut walker,
        fat32: g.fat32.is_some(),
        label: None,
    };
    let mut pending = Vec::new();
    match root {
        Ok(root) => {
            let subdirectories = walk.directory(&root, 0, 0, c);
            pending.extend(subdirectories.into_iter().rev());
        }
        Err(defect) => walk
            .walker
            .problem(format!("Skipped the root directory: {defect}")),
    }
    while let Some(directory) = pending.pop() {
        match walk.walker.directory(directory.cluster, span) {
            Ok(contents) => {
                let subdirectories = walk.directory(&contents, directory.node, directory.depth, c);
                // Reversed, so that subdirectories are walked in entry order.
                pending.extend(subdirectories.into_iter().rev());
            }
            Err(defect) => {
                let path = walk.walker.path(directory.node, "");
                walk.walker.problem(format!("Skipped {path}: {defect}"));
            }
        }
    }
    if let Some(label) = walk.label.take() {
        c.push_metadata(
            "fat_directory_label",
            "Volume label (root directory)",
            label,
        );
    }
    walker.census.report(c);
}

impl<'a> DirectoryWalk<'_, '_, 'a> {
    /// Read the entries of one directory, list its members and return its
    /// subdirectories in entry order.
    fn directory(
        &mut self,
        contents: &DirectoryData<'a>,
        node: usize,
        depth: usize,
        c: &mut Container<'a>,
    ) -> Vec<Pending> {
        self.walker.census.directories += 1;
        if contents.cut {
            let path = self.walker.path(node, "");
            self.walker.problem(format!(
                "{path}: the directory chain is longer than {}; the rest was not read",
                size_text(MAX_DIRECTORY_SIZE)
            ));
        }
        let mut subdirectories = Vec::new();
        let mut long = LongState::None;
        for (_, entry) in walk::entries(&contents.extents) {
            let attr = entry[11];
            let is_long = attr & ATTR_LONG_NAME_MASK == ATTR_LONG_NAME;
            match entry[0] {
                END_OF_DIRECTORY => break,
                DELETED => {
                    if !is_long {
                        self.walker.census.deleted += 1;
                    }
                    self.drop_long_name(&mut long);
                }
                _ if is_long => self.long_entry(&mut long, entry),
                _ => {
                    let name = short_name(entry);
                    let long_name = self.take_long_name(&mut long, &name);
                    let at = Location { node, depth };
                    self.short_entry(entry, long_name, at, &mut subdirectories, c);
                }
            }
        }
        self.drop_long_name(&mut long);
        subdirectories
    }

    /// One short entry: a file to examine, a subdirectory to walk, the
    /// root's volume label, or an invalid entry.
    fn short_entry(
        &mut self,
        entry: &[u8],
        long_name: Option<String>,
        at: Location,
        subdirectories: &mut Vec<Pending>,
        c: &mut Container<'a>,
    ) {
        let Location { node, depth } = at;
        let name = &short_name(entry);
        if name == DOT || name == DOT_DOT {
            return;
        }
        let kind = entry[11] & (ATTR_DIRECTORY | ATTR_VOLUME_ID);
        if kind == ATTR_VOLUME_ID {
            if node == 0 && self.label.is_none() {
                self.label = Some(bpb::field_text(name));
            } else if node != 0 {
                self.walker.census.invalid_entries += 1;
            }
            return;
        }
        if kind == ATTR_DIRECTORY | ATTR_VOLUME_ID || !is_valid_short_name(name) {
            self.walker.census.invalid_entries += 1;
            return;
        }
        let name = long_name.unwrap_or_else(|| short_name_text(name));
        let first_cluster = first_cluster(entry, self.fat32);
        if kind == ATTR_DIRECTORY {
            if depth >= MAX_DEPTH {
                self.walker.census.too_deep += 1;
                return;
            }
            let child = self.walker.add_node(node, &name);
            subdirectories.push(Pending {
                cluster: first_cluster,
                node: child,
                depth: depth + 1,
            });
            return;
        }
        let size = u64::from(u32::from_le_bytes(
            entry[28..32].try_into().expect("4-byte slice"),
        ));
        let file = FileRef {
            first_cluster,
            size,
            valid_size: size,
            contiguous: false,
        };
        let path = self.walker.path(node, &name);
        self.walker.file(path, &file, c);
    }

    /// One long entry: it starts a set (`LAST_LONG_ENTRY`), continues the
    /// set with the next lower ordinal and the same checksum, or is an
    /// orphan.
    fn long_entry(&mut self, long: &mut LongState, entry: &[u8]) {
        let ordinal = entry[0];
        let checksum = entry[13];
        // `LDIR_Type` 0 marks a name component; `LDIR_FstClusLO` must be 0.
        let is_name_part = entry[12] == 0 && entry[26..28] == [0, 0];
        if ordinal & LAST_LONG_ENTRY != 0 {
            self.drop_long_name(long);
            let count = ordinal & !LAST_LONG_ENTRY;
            *long = if is_name_part && (1..=MAX_LONG_ENTRIES).contains(&count) {
                LongState::Collecting(LongName {
                    checksum,
                    next: count - 1,
                    parts: vec![long_name_chars(entry)],
                })
            } else {
                self.walker.census.unused_long_names += 1;
                LongState::Orphaned
            };
            return;
        }
        match long {
            LongState::Collecting(set)
                if is_name_part
                    && set.next != 0
                    && ordinal == set.next
                    && checksum == set.checksum =>
            {
                set.parts.push(long_name_chars(entry));
                set.next -= 1;
            }
            LongState::Orphaned => {}
            LongState::None | LongState::Collecting(_) => {
                self.walker.census.unused_long_names += 1;
                *long = LongState::Orphaned;
            }
        }
    }

    /// End a set without a short entry: it is counted as unused.
    fn drop_long_name(&mut self, long: &mut LongState) {
        if let LongState::Collecting(_) = std::mem::replace(long, LongState::None) {
            self.walker.census.unused_long_names += 1;
        }
    }

    /// The long name for the short entry `name`, when a complete set
    /// precedes it, its checksum matches and the name is valid.
    fn take_long_name(&mut self, long: &mut LongState, name: &[u8; 11]) -> Option<String> {
        let LongState::Collecting(set) = std::mem::replace(long, LongState::None) else {
            return None;
        };
        let text = (set.next == 0 && set.checksum == short_name_checksum(name))
            .then(|| long_name_text(&set.parts))
            .flatten();
        if text.is_none() {
            self.walker.census.unused_long_names += 1;
        }
        text
    }
}

/// `DIR_Name` of an entry.
fn short_name(entry: &[u8]) -> [u8; 11] {
    entry[..11].try_into().expect("an entry has 32 bytes")
}

/// `ChkSum` of [FATGEN]: an 8-bit rotate right and add over the 11 bytes.
fn short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// The 13 UTF-16 characters of a long entry.
fn long_name_chars(entry: &[u8]) -> [u16; LONG_ENTRY_CHARS] {
    let mut chars = [0u16; LONG_ENTRY_CHARS];
    let positions = LONG_NAME_FIELDS
        .iter()
        .flat_map(|&(offset, count)| (0..count).map(move |i| offset + 2 * i));
    for (slot, at) in chars.iter_mut().zip(positions) {
        *slot = u16::from_le_bytes([entry[at], entry[at + 1]]);
    }
    chars
}

/// The long name of a set whose parts are in stored order: up to the
/// first NUL (later characters are 0xFFFF padding), or `None` when it is
/// empty or holds a character that a long name may not.
fn long_name_text(parts: &[[u16; LONG_ENTRY_CHARS]]) -> Option<String> {
    let units: Vec<u16> = parts
        .iter()
        .rev()
        .flatten()
        .copied()
        .take_while(|&unit| unit != 0)
        .collect();
    let name = String::from_utf16_lossy(&units);
    let is_valid = !name.is_empty()
        && !name
            .chars()
            .any(|ch| ch.is_control() || ILLEGAL_LONG_NAME_CHARS.contains(&ch));
    is_valid.then_some(name)
}

/// A short name that [FATGEN] allows: no leading space, no byte below
/// 0x20 except 0x05 first, and none of the illegal punctuation.
fn is_valid_short_name(name: &[u8; 11]) -> bool {
    name[0] != b' '
        && name.iter().enumerate().all(|(i, &b)| {
            (b >= 0x20 || (i == 0 && b == ESCAPED_E5)) && !ILLEGAL_SHORT_NAME_BYTES.contains(&b)
        })
}

/// A short name as `BASE.EXT` without padding. Bytes outside printable
/// ASCII are in an unknown OEM code page and print as `_`, as [FATGEN]
/// "Name Matching In Short & Long Names" returns untranslatable
/// characters.
fn short_name_text(name: &[u8; 11]) -> String {
    let text = |bytes: &[u8]| -> String {
        bytes
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    char::from(b)
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_end()
            .to_string()
    };
    let base = text(&name[..8]);
    let extension = text(&name[8..]);
    if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    }
}

/// `DIR_FstClusLO`, with `DIR_FstClusHI` above it on FAT32 (it is always 0
/// on FAT12 and FAT16).
fn first_cluster(entry: &[u8], fat32: bool) -> u32 {
    let low = u32::from(u16::from_le_bytes([entry[26], entry[27]]));
    let high = if fat32 {
        u32::from(u16::from_le_bytes([entry[20], entry[21]]))
    } else {
        0
    };
    low | (high << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_checksums_rotate_and_add() {
        // mtools' alias for "Long File Name Payload.elf" in the fixtures.
        assert_eq!(short_name_checksum(b"LONGFI~1ELF"), 0x7d);
        assert_eq!(short_name_checksum(&[0; 11]), 0);
    }

    #[test]
    fn short_names_print_without_padding() {
        assert_eq!(short_name_text(b"PAYLOAD ELF"), "PAYLOAD.ELF");
        assert_eq!(short_name_text(b"BOOT       "), "BOOT");
        assert_eq!(short_name_text(b"\x05BC     TXT"), "_BC.TXT");
        assert!(is_valid_short_name(b"\x05BC     TXT"));
        assert!(!is_valid_short_name(b" BC     TXT"));
        assert!(!is_valid_short_name(b"A.B     TXT"));
        assert!(!is_valid_short_name(b"A\x01B     TXT"));
    }

    #[test]
    fn long_names_end_at_the_first_nul() {
        let mut first = [0xffffu16; LONG_ENTRY_CHARS];
        for (slot, ch) in first.iter_mut().zip("Long File Nam".encode_utf16()) {
            *slot = ch;
        }
        let mut last = [0xffffu16; LONG_ENTRY_CHARS];
        for (slot, ch) in last.iter_mut().zip("e.elf\0".encode_utf16()) {
            *slot = ch;
        }
        assert_eq!(
            long_name_text(&[last, first]).as_deref(),
            Some("Long File Name.elf")
        );
        let mut slash = [0u16; LONG_ENTRY_CHARS];
        for (slot, ch) in slash.iter_mut().zip("a/b".encode_utf16()) {
            *slot = ch;
        }
        assert_eq!(long_name_text(&[slash]), None);
        assert_eq!(long_name_text(&[[0; LONG_ENTRY_CHARS]]), None);
    }

    #[test]
    fn long_entry_characters_come_from_three_fields() {
        let mut entry = [0u8; 32];
        for (i, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            entry[at] = b'a' + u8::try_from(i).unwrap();
        }
        let chars = long_name_chars(&entry);
        assert_eq!(String::from_utf16_lossy(&chars), "abcdefghijklm");
    }
}
