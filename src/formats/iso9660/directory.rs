//! Directory records (ECMA-119 9.1, Table 8) and the identifiers they
//! carry: ISO 9660 file identifiers (7.5) and Joliet UCS-2 names (Annex C).
//! A directory is a sequence of records; no record crosses a 2048-byte
//! logical sector, and zero bytes fill each sector after its last record
//! (6.8.1.1).

use super::*;

/// File flags (9.1.6, Table 10).
const FLAG_DIRECTORY: u8 = 0x02;
const FLAG_ASSOCIATED: u8 = 0x04;
const FLAG_MULTI_EXTENT: u8 = 0x80;

/// Bytes of a directory record before the file identifier.
const RECORD_HEADER_SIZE: usize = 33;

/// The root directory record in a volume descriptor: the header and a
/// one-byte identifier, with no system use field (8.4.18).
const ROOT_RECORD_SIZE: usize = 34;

/// Reserved directory identifiers: the directory itself and its parent
/// (6.8.2.2, 7.6.2).
const CURRENT_DIRECTORY: &[u8] = &[0x00];
const PARENT_DIRECTORY: &[u8] = &[0x01];

/// SEPARATOR 2, before the file version number (7.4.3.1).
const SEPARATOR_2: char = ';';

/// SEPARATOR 1, before the file name extension (7.4.3.1).
const SEPARATOR_1: char = '.';

/// A directory record, after the checks of [`Record::parse`].
#[derive(Debug, Clone)]
pub(super) struct Record<'a> {
    /// File offset of the record.
    pub(super) offset: usize,
    /// Extended attribute record length, in logical blocks.
    ear_blocks: u8,
    /// First logical block of the extent (little-endian half).
    pub(super) extent: u32,
    /// Data length in bytes (little-endian half).
    pub(super) data_len: u32,
    flags: u8,
    /// File unit size or interleave gap size is nonzero (9.1.7, 9.1.8).
    pub(super) interleaved: bool,
    /// The file or directory identifier.
    pub(super) identifier: &'a [u8],
    /// The system use field (9.1.13).
    pub(super) system_use: &'a [u8],
    /// File offset of the system use field.
    pub(super) system_use_offset: usize,
    /// The little-endian and big-endian halves of the extent or the data
    /// length disagree; the little-endian values are used, as Linux
    /// (`isonum_733`) and libarchive read them.
    pub(super) byte_orders_differ: bool,
}

impl<'a> Record<'a> {
    /// The record at `at`, which may use at most `available` bytes. Layout:
    /// length (0), EAR length (1), extent (2, 7.3.3), data length (10,
    /// 7.3.3), recording time (18, 7 B), flags (25), file unit size (26),
    /// interleave gap (27), volume sequence number (28, 7.2.3), identifier
    /// length (32), identifier (33), a padding byte when the identifier
    /// length is even, then the system use field.
    pub(super) fn parse(data: &'a [u8], at: usize, available: usize) -> Result<Self> {
        let len = usize::from(byte(data, at)?);
        if len < RECORD_HEADER_SIZE + 1 || len > available {
            return Err(error(format!(
                "Invalid directory record at 0x{at:X}: length {len} B (room for {available} B)"
            )));
        }
        let record = slice(data, at, len)?;
        let identifier_len = usize::from(record[32]);
        let identifier_end = RECORD_HEADER_SIZE + identifier_len;
        if identifier_len == 0 || identifier_end > len {
            return Err(error(format!(
                "Invalid directory record at 0x{at:X}: identifier length {identifier_len} in a \
                 {len} B record"
            )));
        }
        let (extent, extent_be) = both_u32_halves(record, 2)?;
        let (data_len, data_len_be) = both_u32_halves(record, 10)?;
        // The padding byte after an even-length identifier (9.1.12); a
        // record that ends right after the identifier has no system use.
        let system_use_start = (identifier_end + usize::from(identifier_len % 2 == 0)).min(len);
        Ok(Self {
            offset: at,
            ear_blocks: record[1],
            extent,
            data_len,
            flags: record[25],
            interleaved: record[26] != 0 || record[27] != 0,
            identifier: &record[RECORD_HEADER_SIZE..identifier_end],
            system_use: &record[system_use_start..],
            system_use_offset: at + system_use_start,
            byte_orders_differ: extent != extent_be || data_len != data_len_be,
        })
    }

    /// The root directory record of a volume descriptor at `at`: 34 bytes,
    /// a directory, identifier 00, both byte orders in agreement.
    pub(super) fn parse_root(data: &'a [u8], at: usize) -> Result<Self> {
        let length = byte(data, at)?;
        if usize::from(length) != ROOT_RECORD_SIZE {
            return Err(error(format!(
                "Invalid root directory record at 0x{at:X}: length {length} B, expected \
                 {ROOT_RECORD_SIZE}"
            )));
        }
        let root = Self::parse(data, at, ROOT_RECORD_SIZE)?;
        both_u32(data, at + 2, "root directory extent")?;
        both_u32(data, at + 10, "root directory data length")?;
        if !root.is_directory() || root.identifier != CURRENT_DIRECTORY {
            return Err(error(format!(
                "Invalid root directory record at 0x{at:X}: flags 0x{:02X}, identifier {:02X?}",
                root.flags, root.identifier
            )));
        }
        Ok(root)
    }

    pub(super) fn is_directory(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    pub(super) fn is_associated(&self) -> bool {
        self.flags & FLAG_ASSOCIATED != 0
    }

    /// Not the final record of a file (9.1.6, bit 7).
    pub(super) fn is_multi_extent(&self) -> bool {
        self.flags & FLAG_MULTI_EXTENT != 0
    }

    /// The `.` record (identifier 00), the directory itself.
    pub(super) fn is_self(&self) -> bool {
        self.identifier == CURRENT_DIRECTORY
    }

    /// The `.` or `..` record (identifier 00 or 01).
    pub(super) fn is_self_or_parent(&self) -> bool {
        self.identifier == CURRENT_DIRECTORY || self.identifier == PARENT_DIRECTORY
    }

    /// File offset of the data: the extent, after the extended attribute
    /// record (6.4.4.2).
    pub(super) fn data_offset(&self, block_size: usize) -> Option<usize> {
        let block = self.extent.checked_add(u32::from(self.ear_blocks))?;
        block_offset(block, block_size)
    }
}

/// The records of a directory extent, in order. The first defect ends the
/// iteration: the records after it cannot be located.
pub(super) struct Records<'a> {
    image: &'a [u8],
    start: usize,
    end: usize,
    pos: usize,
}

/// The records of the directory stored at `start..start + len`.
pub(super) fn records(image: &[u8], start: usize, len: usize) -> Records<'_> {
    Records {
        image,
        start,
        end: start.saturating_add(len).min(image.len()),
        pos: start,
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = std::result::Result<Record<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.end {
            let in_sector = (self.pos - self.start) % SECTOR_SIZE;
            let length = self.image[self.pos];
            if length == 0 {
                // Zero fill up to the next logical sector (6.8.1.1).
                self.pos += SECTOR_SIZE - in_sector;
                continue;
            }
            let available = (SECTOR_SIZE - in_sector).min(self.end - self.pos);
            let record = Record::parse(self.image, self.pos, available);
            self.pos = match record {
                Ok(_) => self.pos + usize::from(length),
                Err(_) => self.end,
            };
            return Some(record.map_err(descriptors::message));
        }
        None
    }
}

/// A file identifier without its version number (`;1`) and, when the
/// extension is empty, without the trailing SEPARATOR 1 (7.5.1). Directory
/// identifiers carry neither.
fn without_version(mut name: String, is_directory: bool) -> String {
    if is_directory {
        return name;
    }
    if let Some(separator) = name.rfind(SEPARATOR_2) {
        let version = &name[separator + 1..];
        if version.bytes().all(|b| b.is_ascii_digit()) {
            name.truncate(separator);
        }
    }
    if name.len() > 1 && name.ends_with(SEPARATOR_1) {
        name.pop();
    }
    name
}

/// The name an ISO 9660 identifier gives, as ASCII text.
pub(super) fn iso_name(identifier: &[u8], is_directory: bool) -> String {
    without_version(
        String::from_utf8_lossy(identifier).into_owned(),
        is_directory,
    )
}

/// The name a Joliet identifier gives: UCS-2, big-endian (Annex C.3.4),
/// with SEPARATOR 2 as `00 3B` (C.3.7).
pub(super) fn joliet_name(identifier: &[u8], is_directory: bool) -> String {
    without_version(ucs2_text(identifier), is_directory)
}

/// A name usable as a path component: not empty, not `.` or `..`, and
/// without `/` or NUL, so a label cannot escape its directory.
pub(super) fn checked_name(name: String) -> std::result::Result<String, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(format!("name {name:?} is not a path component"));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory record with the two-byte system use field `SU`.
    fn record_bytes(identifier: &[u8], flags: u8) -> Vec<u8> {
        record_with_system_use(identifier, flags, 2)
    }

    /// A directory record with `system_use` bytes of system use, ending
    /// in `SU`.
    fn record_with_system_use(identifier: &[u8], flags: u8, system_use: usize) -> Vec<u8> {
        let padding = usize::from(identifier.len() % 2 == 0);
        let len = RECORD_HEADER_SIZE + identifier.len() + padding + system_use;
        let mut record = vec![0u8; len];
        record[0] = u8::try_from(len).unwrap();
        record[2..6].copy_from_slice(&20u32.to_le_bytes());
        record[6..10].copy_from_slice(&20u32.to_be_bytes());
        record[10..14].copy_from_slice(&2048u32.to_le_bytes());
        record[14..18].copy_from_slice(&2048u32.to_be_bytes());
        record[25] = flags;
        record[32] = u8::try_from(identifier.len()).unwrap();
        record[33..33 + identifier.len()].copy_from_slice(identifier);
        record[len - 2] = b'S';
        record[len - 1] = b'U';
        record
    }

    #[test]
    fn records_split_identifier_padding_and_system_use() {
        let bytes = record_bytes(b"AB", 0);
        let record = Record::parse(&bytes, 0, bytes.len()).unwrap();
        assert_eq!(record.identifier, b"AB");
        assert_eq!(record.system_use, b"SU");
        assert_eq!(record.system_use_offset, 36);
        assert_eq!(record.extent, 20);
        assert!(!record.byte_orders_differ);
        let bytes = record_bytes(b"ABC", FLAG_DIRECTORY);
        let record = Record::parse(&bytes, 0, bytes.len()).unwrap();
        assert!(record.is_directory());
        assert_eq!(record.system_use, b"SU");
        assert!(Record::parse(&bytes, 0, bytes.len() - 1).is_err());
    }

    #[test]
    fn differing_halves_keep_the_little_endian_value() {
        let mut bytes = record_bytes(b"A", 0);
        bytes[9] = 0x21;
        let record = Record::parse(&bytes, 0, bytes.len()).unwrap();
        assert_eq!(record.extent, 20);
        assert!(record.byte_orders_differ);
    }

    #[test]
    fn zero_fill_skips_to_the_next_sector() {
        let mut image = vec![0u8; 2 * SECTOR_SIZE];
        let first = record_bytes(&[0], FLAG_DIRECTORY);
        image[..first.len()].copy_from_slice(&first);
        let second = record_bytes(b"FILE.BIN;1", 0);
        image[SECTOR_SIZE..SECTOR_SIZE + second.len()].copy_from_slice(&second);
        let found: Vec<Record<'_>> = records(&image, 0, image.len())
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].offset, SECTOR_SIZE);
        assert!(found[0].is_self());
        assert!(!found[1].is_self_or_parent());
    }

    #[test]
    fn a_record_may_not_cross_a_sector() {
        // Eight 255-byte records fill 2040 bytes; a ninth one would end in
        // the next sector.
        let mut image = vec![0u8; 2 * SECTOR_SIZE];
        let filler = record_with_system_use(b"A", 0, 255 - RECORD_HEADER_SIZE - 1);
        assert_eq!(filler.len(), 255);
        for i in 0..9 {
            image[i * 255..(i + 1) * 255].copy_from_slice(&filler);
        }
        let found: Vec<_> = records(&image, 0, image.len()).collect();
        assert_eq!(found.len(), 9);
        assert!(found[..8].iter().all(std::result::Result::is_ok));
        assert!(found[8].as_ref().unwrap_err().contains("0x7F8"));
    }

    #[test]
    fn names_lose_their_version_and_empty_extension() {
        assert_eq!(iso_name(b"README.TXT;1", false), "README.TXT");
        assert_eq!(iso_name(b"KERNEL.;1", false), "KERNEL");
        assert_eq!(iso_name(b"A;B", false), "A;B");
        assert_eq!(iso_name(b"DIR.X", true), "DIR.X");
        let joliet: Vec<u8> = "boot.img;1"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert_eq!(joliet_name(&joliet, false), "boot.img");
        assert!(checked_name("a/b".to_string()).is_err());
        assert!(checked_name("..".to_string()).is_err());
        assert_eq!(checked_name("x".to_string()).unwrap(), "x");
    }
}
