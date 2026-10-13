//! T64 tape images (VICE manual "The T64 tape image format"; VICE
//! `src/tape/t64.c` and `t64.h`).
//!
//! A 64-byte header (signature, version, directory size, used entries,
//! description), a directory of 32-byte file records, then the files'
//! bytes; every number is little-endian. A normal record (entry type 1)
//! holds a start address, an exclusive end address and the file offset of
//! its `end - start` data bytes, which VICE loads at the start address
//! (`tape.c`, `tape_receive_trap`): unlike a disk file, the data carry no
//! load address. Other entry types are C64S extensions that VICE does not
//! read.

use super::*;
use crate::formats::container::MAX_COMPONENTS;

/// Signatures VICE accepts at the start of the 32-byte signature field
/// (`t64.c`, `magic_headers`).
const SIGNATURES: [&[u8]; 3] = [
    b"C64 tape image file",
    b"C64S tape file",
    b"C64S tape image file",
];

const HEADER_SIZE: usize = 64;
const RECORD_SIZE: usize = 32;

/// Header fields (`t64.h`): version (2) at 0x20, directory entries (2) at
/// 0x22, used entries (2) at 0x24, description (24) at 0x28.
const VERSION: usize = 0x20;
const DIRECTORY_ENTRIES: usize = 0x22;
const USED_ENTRIES: usize = 0x24;
const DESCRIPTION: usize = 0x28;
const DESCRIPTION_SIZE: usize = 24;

/// Record fields (`t64.h`): entry type (1), CBM file type (1), start
/// address (2), end address (2), unused (2), data offset (4) at 8, unused
/// (4), name (16) at 0x10.
const ENTRY_TYPE: usize = 0x00;
const CBM_TYPE: usize = 0x01;
const START_ADDRESS: usize = 0x02;
const END_ADDRESS: usize = 0x04;
const DATA_OFFSET: usize = 0x08;
const NAME: usize = 0x10;
const NAME_SIZE: usize = 16;

/// Entry types (`t64.h`, `t64_file_record_type_s`): VICE reads only normal
/// tape files.
const ENTRY_FREE: u8 = 0;
const ENTRY_NORMAL: u8 = 1;

/// The CBM file type of a C64S frozen session snapshot (VICE manual).
const CBM_TYPE_SNAPSHOT: u8 = 0;

/// The 6502 address space.
const ADDRESS_SPACE: usize = 0x1_0000;

pub(super) fn detect(data: &[u8]) -> bool {
    SIGNATURES
        .iter()
        .any(|signature| data.starts_with(signature))
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// A directory record.
struct Record<'a> {
    /// Position in the directory, from 1.
    number: usize,
    entry_type: u8,
    cbm_type: u8,
    start: u16,
    end: u16,
    /// File offset of the data.
    data_offset: usize,
    name: &'a [u8],
}

impl<'a> Record<'a> {
    fn read(number: usize, record: &'a [u8; RECORD_SIZE]) -> Self {
        let offset = u32::from_le_bytes([
            record[DATA_OFFSET],
            record[DATA_OFFSET + 1],
            record[DATA_OFFSET + 2],
            record[DATA_OFFSET + 3],
        ]);
        Self {
            number,
            entry_type: record[ENTRY_TYPE],
            cbm_type: record[CBM_TYPE],
            start: le_u16(record, START_ADDRESS),
            end: le_u16(record, END_ADDRESS),
            data_offset: usize::try_from(offset).unwrap_or(usize::MAX),
            name: &record[NAME..NAME + NAME_SIZE],
        }
    }

    /// The size `end - start` names, in the 16-bit arithmetic of VICE's
    /// loader, so that an end address of 0 stands for 0x10000.
    fn reported_size(&self) -> usize {
        usize::from(self.end.wrapping_sub(self.start))
    }

    /// The file type a label shows.
    fn kind(&self) -> String {
        if self.cbm_type == CBM_TYPE_SNAPSHOT {
            "FRZ".to_string()
        } else {
            FileType::of(self.cbm_type).name()
        }
    }
}

/// The data offsets of the normal records inside the file data, sorted, for
/// VICE's end-address repair (`t64_open`): a record's data end where the
/// next record's data start.
struct DataOffsets(Vec<usize>);

impl DataOffsets {
    fn new(records: &[Record<'_>], data_start: usize, file_size: usize) -> Self {
        let mut offsets: Vec<usize> = records
            .iter()
            .filter(|r| r.entry_type == ENTRY_NORMAL)
            .map(|r| r.data_offset)
            .filter(|offset| (data_start..=file_size).contains(offset))
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        Self(offsets)
    }

    /// The first data offset after `offset`, if any.
    fn next_after(&self, offset: usize) -> Option<usize> {
        let i = self.0.partition_point(|&o| o <= offset);
        self.0.get(i).copied()
    }
}

/// Lists the normal records within the limits.
struct Listing<'o> {
    offsets: &'o DataOffsets,
    data_start: usize,
    unlisted: usize,
    problems: Problems,
}

impl Listing<'_> {
    fn record<'a>(&mut self, data: &'a [u8], record: &Record<'a>, c: &mut Container<'a>) {
        let name = tape_text(record.name);
        let number = record.number;
        if record.entry_type != ENTRY_NORMAL {
            self.problems.push(format!(
                "Skipped entry {number} \"{name}\": entry type {} is not read (VICE reads only \
                    normal tape files)",
                record.entry_type
            ));
            return;
        }
        let offset = record.data_offset;
        if !(self.data_start..=data.len()).contains(&offset) {
            self.problems.push(format!(
                "Skipped entry {number} \"{name}\": data offset 0x{offset:X} is outside the file \
                    data (0x{:X}-0x{:X})",
                self.data_start,
                data.len()
            ));
            return;
        }
        let reported = record.reported_size();
        let size = match self.offsets.next_after(offset) {
            Some(next) => next - offset,
            None => reported.min(data.len() - offset),
        };
        if size != reported {
            self.problems.push(format!(
                "Entry {number} \"{name}\": end address 0x{:04X} names {reported} B; read as \
                    {size} B up to the next file or the end of the tape, as VICE does",
                record.end
            ));
        }
        if size == 0 {
            self.problems
                .push(format!("Skipped entry {number} \"{name}\": no data"));
            return;
        }
        if usize::from(record.start) + size > ADDRESS_SPACE {
            self.problems.push(format!(
                "Skipped entry {number} \"{name}\": {size} B from 0x{:04X} exceed the 64 KiB \
                    address space",
                record.start
            ));
            return;
        }
        if c.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
            return;
        }
        let bytes = &data[offset..offset + size];
        let kind = record.kind();
        let child = if FileType::of(record.cbm_type) == FileType::Prg {
            let label = file_label(&kind, &name, Some(record.start));
            program(Child::stored(label, offset, bytes))
        } else {
            Child::opaque(file_label(&kind, &name, None), offset, bytes)
        };
        c.children.push(child);
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header: &[u8; HEADER_SIZE] = range(data, "T64 header", 0, HEADER_SIZE)?
        .try_into()
        .expect("range returns HEADER_SIZE bytes");
    if !detect(data) {
        return Err(error(
            "Missing T64 signature at 0x0: expected C64 tape image file or C64S tape file",
        ));
    }
    let version = le_u16(header, VERSION);
    let declared_entries = le_u16(header, DIRECTORY_ENTRIES);
    let declared_used = le_u16(header, USED_ENTRIES);
    // VICE reads a zero count as 1: "there are so many broken T64 images
    // out there" (`t64_header_read`).
    let entries = declared_entries.max(1);
    let used = declared_used.max(1);
    if used > entries {
        return Err(error(format!(
            "Invalid T64 header: {used} used entries exceed {entries} directory entries"
        )));
    }
    let directory_size = usize::from(entries) * RECORD_SIZE;
    let directory = range(data, "T64 directory", HEADER_SIZE, directory_size)?;
    let records: Vec<Record<'_>> = directory
        .chunks_exact(RECORD_SIZE)
        .enumerate()
        .map(|(i, record)| {
            let record = record
                .try_into()
                .expect("chunks_exact yields RECORD_SIZE bytes");
            Record::read(i + 1, record)
        })
        .collect();
    let data_start = HEADER_SIZE + directory_size;
    let offsets = DataOffsets::new(&records, data_start, data.len());
    let mut c = Container::new(FileFormat::T64, Layout::T64.label(), KEY_PREFIX);
    c.consumed = data.len();
    let mut listing = Listing {
        offsets: &offsets,
        data_start,
        unlisted: 0,
        problems: Problems::default(),
    };
    for record in records.iter().filter(|r| r.entry_type != ENTRY_FREE) {
        listing.record(data, record, &mut c);
    }
    let description = tape_text(&header[DESCRIPTION..DESCRIPTION + DESCRIPTION_SIZE]);
    let version_text = format!("{}.{}", version >> 8, version & 0xff);
    c.notes.push(format!(
        "T64 version {version_text} tape \"{description}\"; {declared_used} of \
            {declared_entries} directory entries used; {}",
        counted(c.children.len(), "file listed", "files listed")
    ));
    c.notes.push(
        "PRG files are 6502-family code loaded at their start address (the CPU of the Commodore \
            8-bit computers); other files are data"
            .into(),
    );
    if declared_entries == 0 || declared_used == 0 {
        c.notes
            .push("A zero directory size or used-entry count is read as 1, as VICE does".into());
    }
    if listing.unlisted > 0 {
        c.notes.push(format!(
            "{} further files were not listed (limit {MAX_COMPONENTS})",
            listing.unlisted
        ));
    }
    listing.problems.append_to(&mut c.notes);
    c.push_metadata("cbm_tape_description", "Tape description", description);
    c.push_metadata("cbm_t64_version", "T64 version", version_text);
    c.push_metadata(
        "cbm_directory_entries",
        "Directory entries",
        u64::from(entries),
    );
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_offsets_end_each_file_at_the_next() {
        let mut directory = [0u8; 3 * RECORD_SIZE];
        for (i, offset) in [0xa0u32, 0x200, 0x100].into_iter().enumerate() {
            let record = &mut directory[i * RECORD_SIZE..(i + 1) * RECORD_SIZE];
            record[ENTRY_TYPE] = ENTRY_NORMAL;
            record[DATA_OFFSET..DATA_OFFSET + 4].copy_from_slice(&offset.to_le_bytes());
        }
        let records: Vec<Record<'_>> = directory
            .chunks_exact(RECORD_SIZE)
            .enumerate()
            .map(|(i, r)| Record::read(i + 1, r.try_into().expect("32-byte record")))
            .collect();
        let offsets = DataOffsets::new(&records, HEADER_SIZE + 3 * RECORD_SIZE, 0x300);
        assert_eq!(offsets.next_after(0xa0), Some(0x100));
        assert_eq!(offsets.next_after(0x100), Some(0x200));
        assert_eq!(offsets.next_after(0x200), None);
    }

    #[test]
    fn an_end_address_of_zero_reaches_the_top_of_memory() {
        let mut record = [0u8; RECORD_SIZE];
        record[START_ADDRESS..START_ADDRESS + 2].copy_from_slice(&0x0801u16.to_le_bytes());
        assert_eq!(Record::read(1, &record).reported_size(), 0xf7ff);
    }
}
