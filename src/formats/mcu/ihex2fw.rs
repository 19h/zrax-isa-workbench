//! Linux `ihex2fw` firmware: Intel HEX records in a compact binary form,
//! as linux-firmware ships them for USB devices that load code by address
//! (`.fw` files of the Keyspan, Edgeport and Whiteheat drivers).
//!
//! Source: Linux v6.11 `include/linux/ihex.h` (`struct ihex_binrec`,
//! `__ihex_next_binrec`, `ihex_validate_fw`). Each record is a big-endian
//! load address (4) and data length (2) followed by the data; the next
//! record starts at the record size rounded up to 4 bytes. A zero-length
//! record ends the list, and the kernel accepts a file only when that
//! record is its last 6 bytes.
//!
//! There is no magic, so the layout is recognized only from a complete
//! structure: at least [`MIN_RECORDS`] records, none of them empty, only
//! zero bytes in the alignment padding, an end record of six zero bytes
//! that ends the file, and no two records loading the same address. The
//! padding and end-record address are not specified by the header; the
//! zero values are those of all 19 such files in the fw1 corpus
//! (2026-11-04). The records name no ISA: their addresses are the Intel HEX
//! load addresses, and the code model classifies their data.

use super::*;

/// Size of a record header: address (4) and length (2).
const RECORD_HEADER: usize = 6;

/// Records start on 4-byte boundaries.
const RECORD_ALIGN: usize = 4;

/// Least records of a recognized file (our choice: a lone record and an end
/// record are too little structure to tell the layout from other data).
const MIN_RECORDS: usize = 2;

/// Name of the reassembly of several records into one load section.
const RECORDS_TRANSFORM: &str = "ihex2fw records";

/// One data record.
struct Record<'a> {
    address: u64,
    /// File offset of the record's data.
    offset: usize,
    data: &'a [u8],
}

impl Record<'_> {
    /// Whether `next` continues this record in the target address space.
    fn is_continued_by(&self, next: &Record<'_>) -> bool {
        self.address + self.data.len() as u64 == next.address
    }
}

/// The records of a complete `ihex2fw` file, or an error naming the first
/// defect.
fn records(data: &[u8]) -> Result<Vec<Record<'_>>> {
    let last = data
        .len()
        .checked_sub(RECORD_HEADER)
        .ok_or_else(|| error("Truncated ihex2fw file: no end record"))?;
    let mut records = Vec::new();
    let mut pos = 0;
    loop {
        if pos > last {
            return Err(error(format!(
                "Truncated ihex2fw records: no end record at 0x{last:X}"
            )));
        }
        let header = slice(data, pos, RECORD_HEADER)?;
        let address = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
        if len == 0 {
            if pos != last || address != 0 {
                return Err(error(format!(
                    "Invalid ihex2fw end record at 0x{pos:X}: the file ends at 0x{:X}",
                    data.len()
                )));
            }
            return Ok(records);
        }
        let data_offset = pos + RECORD_HEADER;
        let record = slice(data, data_offset, len)?;
        let end = data_offset + len;
        let next = end + (RECORD_ALIGN - end % RECORD_ALIGN) % RECORD_ALIGN;
        let padding = data.get(end..next).unwrap_or_default();
        if padding.iter().any(|b| *b != 0) {
            return Err(error(format!(
                "Invalid ihex2fw record padding at 0x{end:X}"
            )));
        }
        records.push(Record {
            address: u64::from(address),
            offset: data_offset,
            data: record,
        });
        pos = next;
    }
}

/// The first two records that load the same address, if any.
fn overlap(records: &[Record<'_>]) -> Option<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = records
        .iter()
        .map(|r| (r.address, r.address + r.data.len() as u64))
        .collect();
    ranges.sort_unstable();
    ranges
        .windows(2)
        .find(|pair| pair[1].0 < pair[0].1)
        .map(|pair| (pair[0].0, pair[1].0))
}

/// Whether `data` is a complete `ihex2fw` record file.
pub(super) fn detect(data: &[u8]) -> bool {
    records(data).is_ok_and(|records| records.len() >= MIN_RECORDS && overlap(&records).is_none())
}

/// Parse an `ihex2fw` file into load sections: records that follow each
/// other in the file and in the address space form one section.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let records = records(data)?;
    if records.len() < MIN_RECORDS {
        return Err(error(format!(
            "Missing ihex2fw data records: {} of at least {MIN_RECORDS}",
            records.len()
        )));
    }
    if let Some((first, second)) = overlap(&records) {
        return Err(error(format!(
            "Duplicate ihex2fw load address: records at 0x{first:X} and 0x{second:X} overlap"
        )));
    }
    let layout = Layout::Ihex2fw;
    let mut c = Container::new(layout.format(), layout.label(), layout.key_prefix());
    c.consumed = data.len();
    c.notes.push(format!(
        "{}, {} B; addresses are the Intel HEX load addresses and name no ISA",
        count(records.len(), "record", "records"),
        records.iter().map(|r| r.data.len()).sum::<usize>()
    ));
    let mut runs: Vec<Vec<&Record<'_>>> = Vec::new();
    for record in &records {
        match runs.last_mut() {
            Some(run) if run.last().is_some_and(|last| last.is_continued_by(record)) => {
                run.push(record);
            }
            _ => runs.push(vec![record]),
        }
    }
    let mut sections = Sections::new();
    for run in runs {
        let label = format!("Load section {}", c.sections.len() + 1);
        let first = run[0];
        let section = if let [only] = run.as_slice() {
            stored_section(label, only.address, only.offset, only.data)
        } else {
            let last = run[run.len() - 1];
            let stored_size = last.offset + last.data.len() - first.offset;
            let mut bytes = Vec::with_capacity(run.iter().map(|r| r.data.len()).sum());
            for record in &run {
                bytes.extend_from_slice(record.data);
            }
            transformed_section(
                label,
                first.address,
                first.offset,
                stored_size,
                bytes,
                RECORDS_TRANSFORM,
            )
        };
        sections.push(&mut c, section);
    }
    sections.finish(&mut c);
    c.push_metadata("ihex2fw_records", "Records", records.len() as u64);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record: big-endian address and length, the data, zero padding to
    /// 4 bytes.
    fn record(address: u32, data: &[u8]) -> Vec<u8> {
        let mut out = address.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).expect("short").to_be_bytes());
        out.extend_from_slice(data);
        out.resize(
            out.len() + (RECORD_ALIGN - out.len() % RECORD_ALIGN) % RECORD_ALIGN,
            0,
        );
        out
    }

    fn file(records: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = records.iter().flat_map(|(a, d)| record(*a, d)).collect();
        out.extend_from_slice(&[0; RECORD_HEADER]);
        out
    }

    #[test]
    fn contiguous_records_form_one_section_and_gaps_start_another() {
        let data = file(&[(0x0, b"\x02\x00\x10"), (0x3, b"abcde"), (0x100, b"xy")]);
        assert!(detect(&data));
        let c = parse(&data).expect("valid records");
        assert_eq!(c.sections.len(), 2);
        assert_eq!(c.sections[0].address, 0);
        assert_eq!(&c.sections[0].data[..], b"\x02\x00\x10abcde");
        assert_eq!(c.sections[0].transform, Some(RECORDS_TRANSFORM));
        // Records at 0 (3 B, padded to 12) and 12 (5 B, padded to 24); the
        // third record's data follows its header at 24.
        assert_eq!((c.sections[1].address, c.sections[1].offset), (0x100, 30));
        assert_eq!(c.consumed, data.len());
    }

    #[test]
    fn incomplete_or_inconsistent_record_lists_are_rejected() {
        let valid = file(&[(0x0, b"abc"), (0x10, b"def")]);
        for end in 0..valid.len() {
            assert!(!detect(&valid[..end]), "prefix {end}");
        }
        let mut padding = valid.clone();
        padding[9] = 1;
        assert!(!detect(&padding));
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0; 4]);
        assert!(!detect(&trailing), "the end record must end the file");
        assert!(!detect(&file(&[(0x0, b"abc")])), "one record is too little");
        assert!(!detect(&file(&[(0x0, b"abcd"), (0x2, b"ef")])), "overlap");
        assert!(!detect(&file(&[(0x0, b"abc"), (0x10, b""), (0x20, b"d")])));
        assert!(!detect(&[0; RECORD_HEADER]));
    }
}
