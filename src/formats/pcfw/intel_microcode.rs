//! Intel microcode updates: Intel SDM Vol. 3A (order 253668-093US), section
//! 12.11.1 (Tables 12-7 and 12-8) and 12.11.2 (Tables 12-9 and 12-10),
//! validated as Linux v6.12 `arch/x86/kernel/cpu/microcode/intel.c`
//! (`intel_microcode_sanity_check`) does. A file may hold several updates
//! back to back, as the kernel's `GenuineIntel.bin` does
//! (`scan_microcode`).
//!
//! The update has no magic. Header version 1, loader revision 1, a BCD
//! date, consistent sizes and zero checksums are the only evidence, so the
//! layout is recognized only when every update in the file validates.

use super::*;
use std::fmt::Write as _;

/// Header: header version (0x00), update revision (0x04), BCD date
/// `mmddyyyy` (0x08), processor signature (0x0C), checksum (0x10), loader
/// revision (0x14), processor flags (0x18), data size (0x1C), total size
/// (0x20), 12 reserved bytes (0x24).
const HEADER_SIZE: usize = 48;

/// Table 12-7: the only header version; Linux `MC_HEADER_TYPE_MICROCODE`
/// (version 2 is an In-Field Scan image, not a microcode update).
const HEADER_VERSION: u32 = 1;

/// Table 12-7: "The initial version is 00000001H"; Linux rejects others.
const LOADER_REVISION: u32 = 1;

/// A data size field of 0 means 2000 B of encrypted data in a 2048 B
/// update (section 12.11.1).
const DEFAULT_DATA_SIZE: usize = 2000;
const DEFAULT_TOTAL_SIZE: usize = 2048;

/// Table 12-7: the total size "is always a multiple of 1024".
const TOTAL_SIZE_UNIT: usize = 1024;

const DWORD_SIZE: usize = 4;

/// Table 12-9: extended signature count, table checksum, 12 reserved bytes.
const EXTENDED_HEADER_SIZE: usize = 20;

/// Table 12-10: processor signature, processor flags, checksum.
const EXTENDED_SIGNATURE_SIZE: usize = 12;

/// First note of every microcode container.
const MICROCODE_NOTE: &str = "Microcode update data: encrypted, with no executable code (Intel SDM Vol. 3A 12.11.1); excluded from ISA analysis";

/// A creation date from the BCD `mmddyyyy` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// Month in bits 31:24, day in bits 23:16 and year in bits 15:0, each
    /// in BCD (Table 12-8); `None` unless every digit is decimal and the
    /// month and day are in range.
    fn from_bcd(raw: u32) -> Option<Self> {
        let [month, day, year_high, year_low] = raw.to_be_bytes();
        let month = bcd_byte(month).filter(|m| (1..=12).contains(m))?;
        let day = bcd_byte(day).filter(|d| (1..=31).contains(d))?;
        let year = u16::from(bcd_byte(year_high)?) * 100 + u16::from(bcd_byte(year_low)?);
        Some(Self { year, month, day })
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Two BCD digits as a number, or `None` when a digit is above 9.
fn bcd_byte(byte: u8) -> Option<u8> {
    let (high, low) = (byte >> 4, byte & 0x0F);
    (high <= 9 && low <= 9).then_some(high * 10 + low)
}

/// One validated update.
#[derive(Debug)]
struct Update<'a> {
    /// File offset of the header.
    offset: usize,
    /// The whole update: header, data and extended signature table.
    bytes: &'a [u8],
    revision: u32,
    date: Date,
    signature: u32,
    platform_flags: u32,
    /// Encrypted data size in bytes.
    data_size: usize,
    /// Processor signatures of the extended signature table.
    extended: Vec<u32>,
}

/// The updates of a file, back to back from offset 0.
struct UpdateList<'a> {
    /// The updates in file order.
    updates: Vec<Update<'a>>,
    /// File offset after the last update; only padding may follow.
    end: usize,
}

/// An update's sizes, from the data size and total size fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpdateSizes {
    /// Encrypted data size in bytes.
    data_size: usize,
    /// Header, data and extended signature table, in bytes.
    total_size: usize,
}

/// Whether `data` is a sequence of valid updates, optionally followed by
/// erased-flash padding.
pub(super) fn is_valid(data: &[u8]) -> bool {
    // Cheap rejection before the full walk: the first header version.
    le_u32(data, 0).ok() == Some(HEADER_VERSION) && updates(data).is_ok()
}

/// Every update in `data` and where the last one ends.
fn updates(data: &[u8]) -> Result<UpdateList<'_>> {
    let mut list: Vec<Update<'_>> = Vec::new();
    let mut pos = 0;
    while let Some(rest) = data.get(pos..).filter(|rest| !rest.is_empty()) {
        if !list.is_empty() && is_padding(rest) {
            break;
        }
        let update = parse_update(data, pos)?;
        // Every update is at least 1024 B, so the walk advances.
        pos += update.bytes.len();
        list.push(update);
    }
    if list.is_empty() {
        return Err(error("Missing microcode update header"));
    }
    Ok(UpdateList {
        updates: list,
        end: pos,
    })
}

/// The update whose header is at `offset`. The cheap header fields come
/// first (versions, date, sizes), then the stored bytes and the checksums.
fn parse_update(data: &[u8], offset: usize) -> Result<Update<'_>> {
    let header = field(data, offset, HEADER_SIZE, "microcode update header")?;
    let version = le_u32(header, 0)?;
    if version != HEADER_VERSION {
        return Err(error(format!(
            "Unsupported microcode header version {version} at 0x{offset:X}"
        )));
    }
    let loader = le_u32(header, 0x14)?;
    if loader != LOADER_REVISION {
        return Err(error(format!(
            "Unsupported microcode loader revision {loader} at 0x{offset:X}"
        )));
    }
    let raw_date = le_u32(header, 0x08)?;
    let date = Date::from_bcd(raw_date).ok_or_else(|| {
        error(format!(
            "Invalid microcode date 0x{raw_date:08X} at 0x{offset:X}: not a BCD mmddyyyy date"
        ))
    })?;
    let UpdateSizes {
        data_size,
        total_size,
    } = sizes(header, offset)?;
    let bytes = field(data, offset, total_size, "microcode update")?;
    let body = field(bytes, 0, HEADER_SIZE + data_size, "microcode update data")?;
    let sum = dword_sum(body);
    if sum != 0 {
        return Err(error(format!(
            "Invalid microcode checksum at 0x{offset:X}: header and data sum to 0x{sum:08X}, not 0"
        )));
    }
    let extended = extended_signatures(bytes, header, body.len(), offset)?;
    Ok(Update {
        offset,
        bytes,
        revision: le_u32(header, 0x04)?,
        date,
        signature: le_u32(header, 0x0C)?,
        platform_flags: le_u32(header, 0x18)?,
        data_size,
        extended,
    })
}

/// Data size and total size in bytes. A data size field of 0 means the
/// 2048 B default; otherwise the data size is a multiple of 4 B, the total
/// a multiple of 1024 B, and the header and data fit in the total.
fn sizes(header: &[u8], offset: usize) -> Result<UpdateSizes> {
    let data_size = to_usize(le_u32(header, 0x1C)?);
    if data_size == 0 {
        return Ok(UpdateSizes {
            data_size: DEFAULT_DATA_SIZE,
            total_size: DEFAULT_TOTAL_SIZE,
        });
    }
    let total_size = to_usize(le_u32(header, 0x20)?);
    if data_size % DWORD_SIZE != 0 {
        return Err(error(format!(
            "Invalid microcode data size {data_size} B at 0x{offset:X}: not a multiple of 4 B"
        )));
    }
    if total_size % TOTAL_SIZE_UNIT != 0 {
        return Err(error(format!(
            "Invalid microcode total size {total_size} B at 0x{offset:X}: not a multiple of 1024 B"
        )));
    }
    let fits = data_size
        .checked_add(HEADER_SIZE)
        .is_some_and(|body| body <= total_size);
    if !fits {
        return Err(error(format!(
            "Invalid microcode sizes at 0x{offset:X}: the 48 B header and {data_size} B of data exceed the {total_size} B total size"
        )));
    }
    Ok(UpdateSizes {
        data_size,
        total_size,
    })
}

/// Wrapping sum of the little-endian DWORDs of `bytes`.
fn dword_sum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(DWORD_SIZE).fold(0u32, |sum, dword| {
        let word = u32::from_le_bytes(dword.try_into().expect("chunk has 4 bytes"));
        sum.wrapping_add(word)
    })
}

/// The extended signature table in the bytes after the data, when the
/// total size leaves room for one: its size must match its count, its
/// DWORDs must sum to 0, and each entry's checksum must make the update
/// with that signature and flags sum to 0 (Table 12-7, `Checksum[n]`).
fn extended_signatures(
    bytes: &[u8],
    header: &[u8],
    body_size: usize,
    offset: usize,
) -> Result<Vec<u32>> {
    let table = bytes.get(body_size..).unwrap_or_default();
    if table.is_empty() {
        return Ok(Vec::new());
    }
    let at = offset + body_size;
    let entries_size = table.len().checked_sub(EXTENDED_HEADER_SIZE);
    let Some(entries_size) = entries_size.filter(|n| n % EXTENDED_SIGNATURE_SIZE == 0) else {
        return Err(error(format!(
            "Truncated microcode extended signature table at 0x{at:X}: {} B",
            table.len()
        )));
    };
    let count = to_usize(le_u32(table, 0)?);
    if count != entries_size / EXTENDED_SIGNATURE_SIZE {
        return Err(error(format!(
            "Invalid microcode extended signature count {count} at 0x{at:X}: the table holds {}",
            entries_size / EXTENDED_SIGNATURE_SIZE
        )));
    }
    let sum = dword_sum(table);
    if sum != 0 {
        return Err(error(format!(
            "Invalid microcode extended signature table checksum at 0x{at:X}: the table sums to 0x{sum:08X}, not 0"
        )));
    }
    let primary = le_u32(header, 0x0C)?
        .wrapping_add(le_u32(header, 0x18)?)
        .wrapping_add(le_u32(header, 0x10)?);
    let entries = table.get(EXTENDED_HEADER_SIZE..).unwrap_or_default();
    let mut signatures = Vec::with_capacity(count);
    for (i, entry) in entries.chunks_exact(EXTENDED_SIGNATURE_SIZE).enumerate() {
        let signature = le_u32(entry, 0)?;
        let replaced = signature
            .wrapping_add(le_u32(entry, 4)?)
            .wrapping_add(le_u32(entry, 8)?);
        if replaced != primary {
            return Err(error(format!(
                "Invalid microcode extended signature {i} checksum at 0x{:X}",
                at + EXTENDED_HEADER_SIZE + i * EXTENDED_SIGNATURE_SIZE
            )));
        }
        signatures.push(signature);
    }
    Ok(signatures)
}

/// Parse a file of microcode updates into a container whose components are
/// the opaque updates.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let UpdateList { updates, end } = updates(data)?;
    let mut c = Container::new(
        FileFormat::IntelMicrocode,
        Layout::IntelMicrocode.label(),
        KEY_PREFIX,
    );
    c.notes.push(MICROCODE_NOTE.to_string());
    c.notes.push(format!(
        "{}; header version 1, loader revision 1; every header-and-data checksum and extended signature table checksum verified",
        plural(updates.len(), "update", "updates")
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_microcode_count"),
        "Microcode updates",
        updates.len() as u64,
    );
    let mut listing = Listing::default();
    for (i, update) in updates.iter().enumerate() {
        if listing.admits_detail() {
            c.notes.push(describe(i, update));
            push_update_metadata(&mut c, i, update);
        }
        let label = format!(
            "Microcode update {} (processor signature 0x{:08X}, revision 0x{:X})",
            i + 1,
            update.signature,
            update.revision
        );
        listing.push(&mut c, Child::opaque(label, update.offset, update.bytes));
    }
    c.notes.extend(padding_note(data, end));
    c.consumed = data.len();
    c.opaque = true;
    listing.finish(&mut c);
    Ok(c)
}

/// One update's note: where it is, what it names and what was checked.
fn describe(index: usize, update: &Update<'_>) -> String {
    let mut note = format!(
        "Update {} at 0x{:X}: revision 0x{:X}, date {}, processor signature 0x{:08X}, platform flags 0x{:02X}; {} of encrypted data in {}",
        index + 1,
        update.offset,
        update.revision,
        update.date,
        update.signature,
        update.platform_flags,
        size_text(update.data_size),
        size_text(update.bytes.len())
    );
    if !update.extended.is_empty() {
        let signatures: Vec<String> = update
            .extended
            .iter()
            .map(|s| format!("0x{s:08X}"))
            .collect();
        let _ = write!(
            note,
            "; {} ({}), each checksum verified",
            plural(
                update.extended.len(),
                "extended signature",
                "extended signatures"
            ),
            listed(&signatures)
        );
    }
    note
}

fn push_update_metadata(c: &mut Container<'_>, index: usize, update: &Update<'_>) {
    let key = |name: &str| format!("{KEY_PREFIX}_microcode_{index}_{name}");
    let ordinal = index + 1;
    c.push_metadata(
        key("revision"),
        format!("Update {ordinal} revision"),
        format!("0x{:X}", update.revision),
    );
    c.push_metadata(
        key("date"),
        format!("Update {ordinal} date"),
        update.date.to_string(),
    );
    c.push_metadata(
        key("signature"),
        format!("Update {ordinal} processor signature"),
        format!("0x{:08X}", update.signature),
    );
    c.push_metadata(
        key("platform_flags"),
        format!("Update {ordinal} platform flags"),
        format!("0x{:02X}", update.platform_flags),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_bcd_month_day_year() {
        let date = Date::from_bcd(0x0718_1998).unwrap();
        assert_eq!((date.year, date.month, date.day), (1998, 7, 18));
        assert_eq!(date.to_string(), "1998-07-18");
        assert!(Date::from_bcd(0x1318_1998).is_none());
        assert!(Date::from_bcd(0x0700_1998).is_none());
        assert!(Date::from_bcd(0x071A_1998).is_none());
        assert!(Date::from_bcd(0x0718_19A8).is_none());
    }

    #[test]
    fn dword_sums_wrap() {
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0, 0, 0];
        assert_eq!(dword_sum(&bytes), 0);
    }

    #[test]
    fn a_zero_data_size_means_the_2048_byte_default() {
        let mut header = [0u8; HEADER_SIZE];
        header[0x20..0x24].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            sizes(&header, 0).unwrap(),
            UpdateSizes {
                data_size: 2000,
                total_size: 2048,
            }
        );
        header[0x1C..0x20].copy_from_slice(&0x400u32.to_le_bytes());
        header[0x20..0x24].copy_from_slice(&0x400u32.to_le_bytes());
        assert!(sizes(&header, 0).is_err());
        header[0x20..0x24].copy_from_slice(&0x800u32.to_le_bytes());
        assert_eq!(
            sizes(&header, 0).unwrap(),
            UpdateSizes {
                data_size: 0x400,
                total_size: 0x800,
            }
        );
    }
}
