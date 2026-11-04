//! OLE compound files ([MS-CFB] v20210407, "Compound File Binary File
//! Format"): Windows Installer packages (`.msi`), legacy Office documents
//! and other structured storage.
//!
//! The header (section 2.2), the DIFAT, FAT and mini FAT (sections 2.4 to
//! 2.6) and the directory (section 2.6) locate every stream. Streams are
//! members classified when their bytes are a recognized format (a cabinet
//! in an installer package); the rest is data and is not listed. Windows
//! Installer stream names are stored packed into CJK code points; they are
//! unpacked as Wine `dlls/msi/table.c` (`decode_streamname`) does.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;

/// `D0 CF 11 E0 A1 B1 1A E1` (section 2.2, Header Signature).
pub const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const HEADER_SIZE: usize = 512;
/// Header fields (section 2.2): major version (0x1A), byte order (0x1C),
/// sector shift (0x1E), mini sector shift (0x20), directory sector count
/// (0x28), FAT sector count (0x2C), first directory sector (0x30), mini
/// stream cutoff (0x38), first mini FAT sector (0x3C), mini FAT sector
/// count (0x40), first DIFAT sector (0x44), DIFAT sector count (0x48), the
/// first 109 DIFAT entries (0x4C).
const MAJOR_VERSION: usize = 0x1a;
const BYTE_ORDER: usize = 0x1c;
const SECTOR_SHIFT: usize = 0x1e;
const MINI_SECTOR_SHIFT: usize = 0x20;
const DIRECTORY_SECTORS: usize = 0x28;
const FAT_SECTORS: usize = 0x2c;
const FIRST_DIRECTORY_SECTOR: usize = 0x30;
const MINI_STREAM_CUTOFF: usize = 0x38;
const FIRST_MINI_FAT_SECTOR: usize = 0x3c;
const MINI_FAT_SECTORS: usize = 0x40;
const FIRST_DIFAT_SECTOR: usize = 0x44;
const DIFAT_SECTORS: usize = 0x48;
const HEADER_DIFAT: usize = 0x4c;
const HEADER_DIFAT_ENTRIES: usize = 109;

const BYTE_ORDER_MARK: u16 = 0xfffe;
const VERSION_3_SECTOR_SHIFT: u16 = 9;
const VERSION_4_SECTOR_SHIFT: u16 = 12;
const MINI_SECTOR_SIZE_SHIFT: u16 = 6;
const STANDARD_MINI_CUTOFF: u32 = 4096;

/// Special sector numbers (section 2.1).
const MAX_REGULAR_SECTOR: u32 = 0xffff_fffa;
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE_SECTOR: u32 = 0xffff_ffff;

/// Directory entry (section 2.6.1, 128 bytes): name (64 B UTF-16LE), name
/// length in bytes (0x40), object type (0x42), left sibling (0x44), right
/// sibling (0x48), child (0x4C), CLSID (0x50), starting sector (0x74),
/// stream size (0x78, 8 B; the high half is zero in version 3).
const ENTRY_SIZE: usize = 128;
const ENTRY_NAME_LEN: usize = 0x40;
const ENTRY_TYPE: usize = 0x42;
const ENTRY_LEFT: usize = 0x44;
const ENTRY_RIGHT: usize = 0x48;
const ENTRY_CHILD: usize = 0x4c;
const ENTRY_CLSID: usize = 0x50;
const ENTRY_START: usize = 0x74;
const ENTRY_SIZE_FIELD: usize = 0x78;
const NO_STREAM: u32 = 0xffff_ffff;
const TYPE_STORAGE: u8 = 1;
const TYPE_STREAM: u8 = 2;
const TYPE_ROOT: u8 = 5;

/// Root CLSID of a Windows Installer package, {000C1084-0000-0000-C000-000000000046},
/// in its stored byte order.
const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Most directory entries read, and the total bytes extracted from streams
/// (one stream is also capped at [`MAX_PAYLOAD`]).
const MAX_ENTRIES: usize = 1 << 16;
const MAX_EXTRACTED: usize = 256 << 20;

/// A compound file layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Any compound file.
    CompoundFile,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::Cfb
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        "Compound file"
    }

    /// The header signature is eight bytes.
    pub fn is_weak(self) -> bool {
        false
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CfbParseError {
        message: message.into(),
    }
}

/// A file that opens with the compound file signature.
pub fn detect(data: &[u8]) -> Option<Layout> {
    data.starts_with(&SIGNATURE).then_some(Layout::CompoundFile)
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| error(format!("Truncated compound file at 0x{at:X}")))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| error(format!("Truncated compound file at 0x{at:X}")))
}

/// The sector geometry and allocation tables of one file.
struct Sectors<'a> {
    data: &'a [u8],
    size: usize,
    /// Sectors that start inside the file.
    count: usize,
    fat: Vec<u32>,
}

impl<'a> Sectors<'a> {
    /// Sector `n` starts one sector after the header area.
    fn sector(&self, n: u32) -> Result<&'a [u8]> {
        let index = n as usize;
        if n > MAX_REGULAR_SECTOR || index >= self.count {
            return Err(error(format!("Invalid sector number 0x{n:X}")));
        }
        let start = (index + 1) * self.size;
        // The last sector of a file may be cut short; it reads as present.
        Ok(&self.data[start..(start + self.size).min(self.data.len())])
    }

    fn offset(&self, n: u32) -> usize {
        (n as usize + 1) * self.size
    }

    /// The sectors of the chain that starts at `start`, at most `limit`
    /// bytes' worth. A sector met twice means the chain loops.
    fn chain(&self, start: u32, limit: usize, what: &str) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut n = start;
        while n != END_OF_CHAIN && out.len() * self.size < limit {
            if !seen.insert(n) {
                return Err(error(format!(
                    "Invalid {what} sector chain at 0x{start:X}: it loops"
                )));
            }
            self.sector(n)?;
            out.push(n);
            n = *self
                .fat
                .get(n as usize)
                .ok_or_else(|| error(format!("Invalid {what} sector 0x{n:X}: outside the FAT")))?;
        }
        Ok(out)
    }

    /// The bytes of a regular-sector chain, cut to `size`.
    fn read(&self, start: u32, size: usize, what: &str) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size.min(self.count * self.size));
        for n in self.chain(start, size, what)? {
            out.extend_from_slice(self.sector(n)?);
        }
        if out.len() < size {
            return Err(error(format!(
                "Truncated {what} at sector 0x{start:X}: {size} B declared, {} B in its chain",
                out.len()
            )));
        }
        out.truncate(size);
        Ok(out)
    }
}

/// FAT sector numbers: the header's 109 DIFAT entries, then the DIFAT
/// sector chain (each sector ends with the number of the next).
fn fat_sector_numbers(data: &[u8], sector_size: usize, count: usize) -> Result<Vec<u32>> {
    let fat_sectors = le_u32(data, FAT_SECTORS)? as usize;
    if fat_sectors > count {
        return Err(error(format!(
            "Invalid FAT sector count {fat_sectors} at 0x{FAT_SECTORS:X}: the file has {count} sectors"
        )));
    }
    let mut numbers = Vec::with_capacity(fat_sectors);
    for i in 0..HEADER_DIFAT_ENTRIES.min(fat_sectors) {
        numbers.push(le_u32(data, HEADER_DIFAT + 4 * i)?);
    }
    let mut next = le_u32(data, FIRST_DIFAT_SECTOR)?;
    let mut difat_sectors = le_u32(data, DIFAT_SECTORS)? as usize;
    let per_sector = sector_size / 4 - 1;
    while numbers.len() < fat_sectors && difat_sectors > 0 {
        let index = next as usize;
        if next > MAX_REGULAR_SECTOR || index >= count {
            return Err(error(format!("Invalid DIFAT sector 0x{next:X}")));
        }
        let start = (index + 1) * sector_size;
        for i in 0..per_sector {
            if numbers.len() == fat_sectors {
                break;
            }
            numbers.push(le_u32(data, start + 4 * i)?);
        }
        next = le_u32(data, start + 4 * per_sector)?;
        difat_sectors -= 1;
    }
    if numbers.len() < fat_sectors {
        return Err(error(format!(
            "Truncated DIFAT: {} of {fat_sectors} FAT sectors located",
            numbers.len()
        )));
    }
    Ok(numbers)
}

/// One directory entry.
struct Entry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

fn entry(directory: &[u8], index: usize) -> Result<Entry> {
    let at = index * ENTRY_SIZE;
    let raw = directory
        .get(at..at + ENTRY_SIZE)
        .ok_or_else(|| error(format!("Truncated directory entry {index}")))?;
    let name_len = usize::from(le_u16(raw, ENTRY_NAME_LEN)?).min(ENTRY_NAME_LEN);
    let units: Vec<u16> = raw[..name_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let mut size = u64::from(le_u32(raw, ENTRY_SIZE_FIELD)?);
    size |= u64::from(le_u32(raw, ENTRY_SIZE_FIELD + 4)?) << 32;
    Ok(Entry {
        name: stream_name(&units),
        kind: raw[ENTRY_TYPE],
        left: le_u32(raw, ENTRY_LEFT)?,
        right: le_u32(raw, ENTRY_RIGHT)?,
        child: le_u32(raw, ENTRY_CHILD)?,
        start: le_u32(raw, ENTRY_START)?,
        size,
    })
}

/// The 64 characters a Windows Installer packed code (6 bits) stands for.
const INSTALLER_CHARS: &[u8; 64] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

/// The character of the low six bits of `code`.
fn installer_char(code: u32) -> char {
    char::from(INSTALLER_CHARS[(code & 0x3f) as usize])
}

/// UTF-16 name, with Windows Installer packing undone: `0x3800..0x4800`
/// hold two characters, `0x4800..0x4840` one, and `0x4840` marks a table.
fn stream_name(units: &[u16]) -> String {
    let mut name = String::new();
    for c in char::decode_utf16(units.iter().copied()) {
        let Ok(c) = c else {
            name.push(char::REPLACEMENT_CHARACTER);
            continue;
        };
        let code = u32::from(c);
        match code {
            0x3800..=0x47ff => {
                let packed = code - 0x3800;
                name.push(installer_char(packed));
                name.push(installer_char(packed >> 6));
            }
            0x4800..=0x483f => name.push(installer_char(code - 0x4800)),
            0x4840 => name.push('!'),
            _ if c.is_control() => name.extend(c.escape_unicode()),
            _ => name.push(c),
        }
    }
    name
}

/// Streams in directory-tree order with their paths. Each sibling tree is
/// walked once; entries reached twice or out of range are errors.
fn walk(entries: &[Entry]) -> Result<Vec<(String, usize)>> {
    let mut streams = Vec::new();
    let mut visited = HashSet::new();
    // (entry, path of its storage)
    let mut stack: Vec<(u32, String)> = vec![(entries[0].child, String::new())];
    while let Some((id, parent)) = stack.pop() {
        if id == NO_STREAM {
            continue;
        }
        let index = id as usize;
        let e = entries
            .get(index)
            .ok_or_else(|| error(format!("Invalid directory entry reference {id}")))?;
        if !visited.insert(index) {
            return Err(error(format!(
                "Invalid directory tree: entry {id} is reached twice"
            )));
        }
        let path = if parent.is_empty() {
            e.name.clone()
        } else {
            format!("{parent}/{}", e.name)
        };
        stack.push((e.right, parent.clone()));
        stack.push((e.left, parent));
        match e.kind {
            TYPE_STREAM => streams.push((path, index)),
            TYPE_STORAGE => stack.push((e.child, path)),
            _ => {}
        }
    }
    streams.sort_by_key(|&(_, index)| index);
    Ok(streams)
}

/// Parse a compound file: header, allocation tables, directory and the
/// streams that are a recognized format.
///
/// # Errors
///
/// [`ClassifierError::CfbParseError`] for an unsupported version or sector
/// size, a FAT, mini FAT or directory chain outside the file or looping, or
/// a directory tree that reaches an entry twice.
pub fn parse_container(data: &[u8], _layout: Layout) -> Result<Container<'_>> {
    if data.len() < HEADER_SIZE || !data.starts_with(&SIGNATURE) {
        return Err(error("Truncated compound file header at 0x0"));
    }
    let version = le_u16(data, MAJOR_VERSION)?;
    let shift = le_u16(data, SECTOR_SHIFT)?;
    let mini_shift = le_u16(data, MINI_SECTOR_SHIFT)?;
    let expected = match version {
        3 => VERSION_3_SECTOR_SHIFT,
        4 => VERSION_4_SECTOR_SHIFT,
        _ => {
            return Err(error(format!(
                "Unsupported compound file version {version} at 0x1A"
            )))
        }
    };
    if le_u16(data, BYTE_ORDER)? != BYTE_ORDER_MARK
        || shift != expected
        || mini_shift != MINI_SECTOR_SIZE_SHIFT
    {
        return Err(error(format!(
            "Invalid compound file header: version {version}, sector shift {shift}, mini sector shift {mini_shift}"
        )));
    }
    if version == 3 && le_u32(data, DIRECTORY_SECTORS)? != 0 {
        return Err(error(
            "Invalid directory sector count at 0x28 for version 3",
        ));
    }
    if le_u32(data, MINI_STREAM_CUTOFF)? != STANDARD_MINI_CUTOFF {
        return Err(error("Invalid mini stream cutoff at 0x38"));
    }
    let size = 1usize << shift;
    // Sectors after the header area, the last one possibly cut short.
    let count = (data.len() - size.min(data.len()) + size - 1) / size;
    let mut sectors = Sectors {
        data,
        size,
        count,
        fat: Vec::new(),
    };
    for n in fat_sector_numbers(data, size, count)? {
        let sector = sectors.sector(n)?;
        sectors.fat.extend(
            sector
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])),
        );
    }

    let directory_start = le_u32(data, FIRST_DIRECTORY_SECTOR)?;
    let directory_sectors =
        sectors.chain(directory_start, MAX_ENTRIES * ENTRY_SIZE, "directory")?;
    let mut directory = Vec::with_capacity(directory_sectors.len() * size);
    for n in directory_sectors {
        directory.extend_from_slice(sectors.sector(n)?);
    }
    let entries = (0..directory.len() / ENTRY_SIZE)
        .map(|i| entry(&directory, i))
        .collect::<Result<Vec<_>>>()?;
    let root = entries
        .first()
        .filter(|e| e.kind == TYPE_ROOT)
        .ok_or_else(|| error("Missing root storage entry in the directory"))?;
    let installer = directory.get(ENTRY_CLSID..ENTRY_CLSID + 16) == Some(&MSI_CLSID[..]);

    let mini_fat_sectors = le_u32(data, MINI_FAT_SECTORS)? as usize;
    let mini_fat: Vec<u32> = if mini_fat_sectors == 0 {
        Vec::new()
    } else {
        let start = le_u32(data, FIRST_MINI_FAT_SECTOR)?;
        let bytes = sectors.read(start, mini_fat_sectors.min(count) * size, "mini FAT")?;
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    };
    let mini_stream = if root.start == END_OF_CHAIN || root.size == 0 {
        Vec::new()
    } else {
        let size = usize::try_from(root.size)
            .ok()
            .filter(|&s| s <= sectors.count * sectors.size)
            .ok_or_else(|| error(format!("Invalid mini stream size {} B", root.size)))?;
        sectors.read(root.start, size, "mini stream")?
    };

    let mut c = Container::new(FileFormat::Cfb, Layout::CompoundFile.label(), "cfb");
    c.consumed = data.len();
    let streams = walk(&entries)?;
    let mut budget = MAX_EXTRACTED;
    let mut skipped = 0usize;
    for (path, index) in &streams {
        let e = &entries[*index];
        let Some(len) = usize::try_from(e.size)
            .ok()
            .filter(|&n| n > 0 && n <= budget.min(MAX_PAYLOAD))
        else {
            skipped += usize::from(e.size > 0);
            continue;
        };
        let bytes = if e.size < u64::from(STANDARD_MINI_CUTOFF) {
            mini_read(&mini_stream, &mini_fat, e.start, len)?
        } else {
            sectors.read(e.start, len, "stream")?
        };
        budget -= len;
        let offset = if e.size < u64::from(STANDARD_MINI_CUTOFF) {
            0
        } else {
            sectors.offset(e.start)
        };
        c.children.push(
            Child::decoded(
                path.clone(),
                offset,
                len,
                Cow::Owned(bytes),
                "CFB sector chain",
            )
            .if_recognized(),
        );
    }
    c.notes.push(format!(
        "{} version {version}: {} B sectors, {}, {}{}",
        if installer { "Windows Installer package (compound file)" } else { "Compound file" },
        size,
        count_text(entries.len(), "directory entry", "directory entries"),
        count_text(streams.len(), "stream", "streams"),
        if skipped > 0 {
            format!(
                "; {skipped} not extracted (over the {} MiB stream or {} MiB total extraction limit)",
                MAX_PAYLOAD >> 20,
                MAX_EXTRACTED >> 20
            )
        } else {
            String::new()
        }
    ));
    c.push_metadata("cfb_version", "Version", u64::from(version));
    c.push_metadata("cfb_streams", "Streams", streams.len() as u64);
    if installer {
        c.push_metadata("cfb_root_class", "Root class", "Windows Installer package");
    }
    Ok(c)
}

/// "1 stream", "3 streams".
fn count_text(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The bytes of a mini-stream chain: 64-byte mini sectors located in the
/// mini stream by the mini FAT.
fn mini_read(mini_stream: &[u8], mini_fat: &[u32], start: u32, size: usize) -> Result<Vec<u8>> {
    let mini_size = 1usize << MINI_SECTOR_SIZE_SHIFT;
    let mut out = Vec::with_capacity(size);
    let mut seen = HashSet::new();
    let mut n = start;
    while out.len() < size {
        if n == END_OF_CHAIN || n == FREE_SECTOR {
            return Err(error(format!(
                "Truncated mini stream chain at 0x{start:X}: {size} B declared, {} B read",
                out.len()
            )));
        }
        if !seen.insert(n) {
            return Err(error(format!(
                "Invalid mini stream chain at 0x{start:X}: it loops"
            )));
        }
        let at = n as usize * mini_size;
        let sector = mini_stream
            .get(at..at + mini_size)
            .ok_or_else(|| error(format!("Invalid mini sector 0x{n:X}")))?;
        out.extend_from_slice(sector);
        n = *mini_fat
            .get(n as usize)
            .ok_or_else(|| error(format!("Invalid mini sector 0x{n:X}: outside the mini FAT")))?;
    }
    out.truncate(size);
    Ok(out)
}
