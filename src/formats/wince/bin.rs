//! `B000FF` BIN files: a 15-byte header (sync bytes, image address, image
//! length) and records of address, length, checksum and data, ended by a
//! record with address 0 and checksum 0 whose length field is the entry
//! point (Microsoft Learn `ee478913`; BLCOMMON `DownloadImage`; Device
//! Emulator `ForEachSectionHeader`).
//!
//! Records are loaded at their addresses. `romimage` does not write them
//! in address order (BLCOMMON: the record with the ROM signature and
//! pointer comes before the record with the ROMHDR), so the ROMHDR is
//! looked up in the assembled image, never by file position.

use super::memory::{Memory, Region};
use super::rom::{self, RomHeader, Translation};
use super::*;
use crate::formats::container::{Container, Section, MAX_COMPONENTS};
use crate::formats::MAX_PAYLOAD;
use crate::types::MetadataValue;
use std::borrow::Cow;
use std::ops::Range;

/// The sync bytes: `B`, then the reserved `0 0 0 F F \n`.
const SYNC: &[u8; 7] = b"B000FF\n";
/// Sync bytes, image address and image length.
const HEADER_SIZE: usize = 15;
/// Record address, length and checksum.
const RECORD_HEADER_SIZE: usize = 12;
/// Most records read. Our own bound, so that record bookkeeping stays
/// small for any input; a BIN file with more records is reported as
/// unsupported.
const MAX_RECORDS: usize = 1 << 18;
/// Transform named for a load section reassembled from consecutive
/// records.
const RECORDS_TRANSFORM: &str = "BIN records";

/// Whether `data` starts with the BIN sync bytes.
pub(super) fn has_sync(data: &[u8]) -> bool {
    data.starts_with(SYNC)
}

/// The run-time image header.
#[derive(Debug)]
struct Header {
    /// Physical start address of the image.
    start: u32,
    /// Length of the image in bytes.
    length: u32,
}

impl Header {
    /// Header: sync bytes (7 B), image address (7), image length (11).
    fn parse(data: &[u8]) -> Result<Self> {
        let fields = slice(data, 0, HEADER_SIZE, "BIN header")?;
        let header = Self {
            start: le_u32(fields, 7)?,
            length: le_u32(fields, 11)?,
        };
        if header.length == 0 {
            return Err(error("Invalid BIN header: the image length is 0"));
        }
        if header.end() > 1 << 32 {
            return Err(error(format!(
                "Invalid BIN header: image 0x{:08X} + {} B exceeds the 32-bit address space",
                header.start, header.length
            )));
        }
        Ok(header)
    }

    /// First address after the image.
    fn end(&self) -> u64 {
        u64::from(self.start) + u64::from(self.length)
    }
}

/// A data record.
#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    /// File offset of the record header.
    offset: usize,
    /// Load address of the data.
    address: u32,
    data: &'a [u8],
}

impl<'a> Record<'a> {
    fn data_offset(&self) -> usize {
        self.offset + RECORD_HEADER_SIZE
    }

    fn end_address(&self) -> u64 {
        u64::from(self.address) + to_u64(self.data.len())
    }

    fn region(&self) -> Region<'a> {
        Region {
            address: u64::from(self.address),
            offset: self.data_offset(),
            bytes: self.data,
        }
    }
}

/// The records of a BIN file and its terminator.
struct Stream<'a> {
    records: Vec<Record<'a>>,
    /// Entry point from the terminator's length field.
    entry: u32,
    /// File offset after the terminator.
    end: usize,
}

/// The BLCOMMON `VerifyChecksum` sum: every data byte, unsigned, added
/// into a 32-bit register that wraps (the algorithm's own arithmetic).
fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
}

/// Read every record up to the terminator, verifying checksums and that
/// each record lies inside the image range.
fn read_records<'a>(data: &'a [u8], header: &Header) -> Result<Stream<'a>> {
    let mut records = Vec::new();
    let mut pos = HEADER_SIZE;
    loop {
        if pos == data.len() {
            return Err(error(format!("Missing BIN terminator record at 0x{pos:X}")));
        }
        let fields = slice(data, pos, RECORD_HEADER_SIZE, "BIN record header")?;
        let address = le_u32(fields, 0)?;
        let length = le_u32(fields, 4)?;
        let stored_checksum = le_u32(fields, 8)?;
        let data_offset = pos + RECORD_HEADER_SIZE;
        // Microsoft Learn ends the file at address 0; BLCOMMON also needs
        // checksum 0 and would load anything else as data at address 0.
        if address == 0 {
            if stored_checksum != 0 {
                return Err(error(format!(
                    "Invalid BIN terminator record at 0x{pos:X}: checksum 0x{stored_checksum:08X} is not 0"
                )));
            }
            return Ok(Stream {
                records,
                entry: length,
                end: data_offset,
            });
        }
        if records.len() == MAX_RECORDS {
            return Err(error(format!(
                "Unsupported BIN image: more than {MAX_RECORDS} records"
            )));
        }
        let bytes = slice(data, data_offset, to_usize(length), "BIN record data")?;
        let computed = checksum(bytes);
        if computed != stored_checksum {
            return Err(error(format!(
                "Invalid BIN record checksum at 0x{pos:X}: stored 0x{stored_checksum:08X}, computed 0x{computed:08X}"
            )));
        }
        let record = Record {
            offset: pos,
            address,
            data: bytes,
        };
        if u64::from(address) < u64::from(header.start) || record.end_address() > header.end() {
            return Err(error(format!(
                "Invalid BIN record at 0x{pos:X}: 0x{address:08X} + {length} B is outside the image 0x{:08X} + {} B",
                header.start, header.length
            )));
        }
        records.push(record);
        pos = data_offset + bytes.len();
    }
}

/// Reject records that load the same address twice. After sorting by
/// address, any overlap shows between neighbours.
fn check_overlaps(records: &[Record<'_>]) -> Result<()> {
    let mut loaded: Vec<&Record<'_>> = records.iter().filter(|r| !r.data.is_empty()).collect();
    loaded.sort_unstable_by_key(|r| r.address);
    for pair in loaded.windows(2) {
        let (low, high) = (pair[0], pair[1]);
        if u64::from(high.address) < low.end_address() {
            return Err(error(format!(
                "Overlapping BIN records at 0x{:X} and 0x{:X} for address 0x{:08X}",
                low.offset, high.offset, high.address
            )));
        }
    }
    Ok(())
}

/// Index ranges of records that follow each other in the file and
/// continue each other's addresses. Empty records end a run; address gaps
/// are never filled.
fn runs(records: &[Record<'_>]) -> Vec<Range<usize>> {
    let mut runs: Vec<Range<usize>> = Vec::new();
    for (i, record) in records.iter().enumerate() {
        if record.data.is_empty() {
            continue;
        }
        let continues = runs.last().is_some_and(|run| {
            run.end == i && records[i - 1].end_address() == u64::from(record.address)
        });
        match runs.last_mut() {
            Some(run) if continues => run.end = i + 1,
            _ => runs.push(i..i + 1),
        }
    }
    runs
}

/// A run as a load section: a single record's data as stored, or the data
/// of several records reassembled from the file range they span.
fn section<'a>(records: &[Record<'a>], index: usize) -> Section<'a> {
    let label = format!("Load section {}", index + 1);
    let first = records[0];
    if let [only] = records {
        return Section {
            label,
            address: u64::from(only.address),
            offset: only.data_offset(),
            stored_size: only.data.len(),
            data: Cow::Borrowed(only.data),
            transform: None,
        };
    }
    let last = records[records.len() - 1];
    let size = records.iter().map(|r| r.data.len()).sum();
    let mut data = Vec::with_capacity(size);
    for record in records {
        data.extend_from_slice(record.data);
    }
    Section {
        label,
        address: u64::from(first.address),
        offset: first.data_offset(),
        stored_size: last.data_offset() + last.data.len() - first.data_offset(),
        data: Cow::Owned(data),
        transform: Some(RECORDS_TRANSFORM),
    }
}

/// One load section per run, up to [`MAX_COMPONENTS`] sections and
/// [`MAX_PAYLOAD`] bytes; the rest is counted in a note.
fn push_sections<'a>(c: &mut Container<'a>, records: &[Record<'a>], runs: &[Range<usize>]) {
    let mut loaded = 0usize;
    let mut left_out = 0usize;
    let mut left_out_size = 0u64;
    for run in runs {
        let size: usize = records[run.clone()].iter().map(|r| r.data.len()).sum();
        let fits = c.sections.len() < MAX_COMPONENTS
            && loaded
                .checked_add(size)
                .is_some_and(|total| total <= MAX_PAYLOAD);
        if !fits {
            left_out += 1;
            left_out_size += to_u64(size);
            continue;
        }
        loaded += size;
        let index = c.sections.len();
        c.sections.push(section(&records[run.clone()], index));
    }
    if left_out > 0 {
        c.notes.push(format!(
            "{} ({}) not listed or analyzed (limits: {MAX_COMPONENTS} sections, {})",
            count(left_out, "further load section", "further load sections"),
            size_text(left_out_size),
            size_text(to_u64(MAX_PAYLOAD))
        ));
    }
}

/// Where the ROMHDR of a BIN image is.
enum Lookup {
    /// No `ECEC` at image offset 0x40.
    NoSignature,
    /// `ECEC` is present but no ROMHDR is consistent; the reason.
    Unresolved(String),
    /// The ROMHDR and how its pointers map to record addresses.
    Found(RomHeader, Translation),
}

/// Find the ROMHDR as BLCOMMON does: `ECEC` at image offset 0x40, the
/// ROMHDR pointer after it, and a ROMHDR whose `physfirst` and `physlast`
/// are the image start and end once the ROM offset is applied. The offset
/// is 0, or the address of an 84-byte record minus the pointer (BLCOMMON
/// and the Device Emulator both look for the ROMHDR as a record of exactly
/// `sizeof(ROMHDR)`). Exactly one candidate may match.
fn find_rom_header(memory: &Memory<'_>, header: &Header, records: &[Record<'_>]) -> Lookup {
    let start = u64::from(header.start);
    let signature = memory.read(start + to_u64(rom::ROM_SIGNATURE_OFFSET), 4);
    if signature.as_deref() != Some(&rom::ROM_SIGNATURE.to_le_bytes()[..]) {
        return Lookup::NoSignature;
    }
    let Some(pointer) = memory
        .read(start + to_u64(rom::ROM_TOC_POINTER_OFFSET), 4)
        .and_then(|bytes| le_u32(&bytes, 0).ok())
    else {
        return Lookup::Unresolved("the ROMHDR pointer at image offset 0x44 is not loaded".into());
    };
    let mut offsets = vec![0i64];
    offsets.extend(
        records
            .iter()
            .filter(|r| r.data.len() == rom::ROMHDR_SIZE)
            .map(|r| i64::from(r.address) - i64::from(pointer)),
    );
    offsets.sort_unstable();
    offsets.dedup();
    let matches: Vec<(RomHeader, Translation)> = offsets
        .into_iter()
        .filter_map(|offset| {
            let translation = Translation::new(offset);
            let address = translation.storage(pointer)?;
            let bytes = memory.read(address, rom::ROMHDR_SIZE)?;
            let candidate = RomHeader::parse(&bytes, address).ok()?;
            let spans_image = translation.storage(candidate.phys_first) == Some(start)
                && translation.storage(candidate.phys_last) == Some(header.end());
            spans_image.then_some((candidate, translation))
        })
        .collect();
    match matches.as_slice() {
        [] => Lookup::Unresolved(format!(
            "no ROMHDR for the pointer 0x{pointer:08X} has physfirst and physlast at the image start and end"
        )),
        [(candidate, translation)] => Lookup::Found(*candidate, *translation),
        _ => Lookup::Unresolved(format!(
            "{} ROMHDR records for the pointer 0x{pointer:08X} span the image",
            matches.len()
        )),
    }
}

/// The message of a family error, without the error's prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::WinCeParseError { message } => message,
        other => other.to_string(),
    }
}

/// Parse a BIN file into load sections and, when its ROMHDR is found,
/// the ROM's target, modules and files.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !has_sync(data) {
        return Err(error("Missing BIN sync bytes B000FF at 0x0"));
    }
    let header = Header::parse(data)?;
    let Stream {
        records,
        entry,
        end,
    } = read_records(data, &header)?;
    check_overlaps(&records)?;
    let trailing = &data[end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected data after the BIN terminator record at 0x{end:X}"
        )));
    }
    let mut c = Container::new(FileFormat::WinCeImage, Layout::Bin.label(), KEY_PREFIX);
    c.consumed = end;
    c.entry = Some(u64::from(entry));
    // The assembled image is the ROM itself (a raw ROM image when
    // contiguous); it goes to the code model, never back to detection.
    c.code_sections = true;
    let runs = runs(&records);
    c.notes.push(format!(
        "{} in {}; image 0x{:08X} + {}; record checksums verified",
        count(records.len(), "record", "records"),
        count(runs.len(), "load section", "load sections"),
        header.start,
        size_text(u64::from(header.length))
    ));
    c.notes.push(format!(
        "Entry point 0x{entry:08X} from the terminating record"
    ));
    push_sections(&mut c, &records, &runs);
    if !trailing.is_empty() {
        c.notes.push(format!(
            "{} of padding after the terminator",
            size_text(to_u64(trailing.len()))
        ));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_bin_start"),
        "BIN image address",
        MetadataValue::Address(u64::from(header.start)),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_bin_length"),
        "BIN image length (B)",
        u64::from(header.length),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_records"),
        "BIN records",
        to_u64(records.len()),
    );
    let memory = Memory::new(records.iter().map(Record::region).collect());
    match find_rom_header(&memory, &header, &records) {
        Lookup::NoSignature => c.notes.push(
            "No ROM signature (ECEC) at image offset 0x40, so there is no ROM table of contents; the ISA comes from the code"
                .into(),
        ),
        Lookup::Unresolved(reason) => c.notes.push(format!(
            "ROM signature at 0x{:08X}, but {reason}; the ROM table of contents was not read",
            u64::from(header.start) + to_u64(rom::ROM_SIGNATURE_OFFSET)
        )),
        Lookup::Found(rom_header, translation) => {
            match rom::read(&memory, rom_header, translation) {
                Ok(rom) => rom::report(&mut c, &rom, &memory),
                Err(e) => {
                    rom::report_header(&mut c, &rom_header, translation);
                    c.notes.push(format!(
                        "The ROM table of contents is invalid ({}); modules and files are not listed",
                        message(e)
                    ));
                }
            }
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(offset: usize, address: u32, data: &[u8]) -> Record<'_> {
        Record {
            offset,
            address,
            data,
        }
    }

    #[test]
    fn checksum_is_an_unsigned_wrapping_byte_sum() {
        assert_eq!(checksum(&[]), 0);
        assert_eq!(checksum(&[0x80, 0xff, 1]), 0x180);
        // 0xFF * 0x0101_0102 is 0x1_0000_00FE: the register wraps.
        assert_eq!(checksum(&vec![0xff; 0x0101_0102]), 0xfe);
    }

    #[test]
    fn runs_merge_file_neighbours_with_contiguous_addresses() {
        let bytes = [0u8; 8];
        let records = [
            record(15, 0x1000, &bytes[..4]),
            record(31, 0x1004, &bytes[..4]),
            record(47, 0x2000, &bytes[..2]),
            record(61, 0x2002, &[]),
            record(73, 0x2002, &bytes[..2]),
            record(87, 0x0ffc, &bytes[..4]),
        ];
        assert_eq!(runs(&records), [0..2, 2..3, 4..5, 5..6]);
        let merged = section(&records[0..2], 0);
        assert_eq!(
            (
                merged.address,
                merged.offset,
                merged.stored_size,
                merged.data.len()
            ),
            (0x1000, 27, 20, 8)
        );
        assert_eq!(merged.transform, Some(RECORDS_TRANSFORM));
        let single = section(&records[2..3], 1);
        assert_eq!(
            (single.offset, single.stored_size, single.transform),
            (59, 2, None)
        );
        assert!(check_overlaps(&records).is_ok());
    }

    #[test]
    fn overlapping_records_are_rejected() {
        let bytes = [0u8; 8];
        let records = [record(15, 0x1000, &bytes), record(35, 0x1004, &bytes)];
        assert_eq!(
            message(check_overlaps(&records).unwrap_err()),
            "Overlapping BIN records at 0xF and 0x23 for address 0x00001004"
        );
    }

    #[test]
    fn header_rejects_empty_and_unaddressable_images() {
        let mut header = b"B000FF\n".to_vec();
        header.extend_from_slice(&0x8000_0000u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        assert!(message(Header::parse(&header).unwrap_err()).contains("length is 0"));
        header[11..15].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        assert!(message(Header::parse(&header).unwrap_err()).contains("32-bit address space"));
        header[11..15].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert_eq!(Header::parse(&header).unwrap().end(), 1 << 32);
        assert!(
            message(Header::parse(&header[..14]).unwrap_err()).starts_with("Truncated BIN header")
        );
    }
}
