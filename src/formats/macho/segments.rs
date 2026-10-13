//! Segments, sections and the code they hold.
//!
//! `segment_command` (56 B) and `segment_command_64` (72 B) share one
//! layout with 4-byte or 8-byte address fields: `cmd` (4), `cmdsize` (4),
//! `segname[16]` at 8, then `vmaddr`, `vmsize`, `fileoff` and `filesize`
//! (one word each) at 24, then `maxprot`, `initprot`, `nsects` and `flags`
//! (4 each). `nsects` sections follow: `section` (68 B) or `section_64`
//! (80 B), each `sectname[16]` at 0, `segname[16]` at 16, `addr` and `size`
//! (one word each) at 32, then `offset`, `align`, `reloff`, `nreloc` and
//! `flags` (4 each) and the reserved words.

use super::commands::{Command, LC_SEGMENT_64};
use super::*;

/// Section types without file content (`loader.h`).
const SECTION_TYPE: u32 = 0xFF;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xC;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

/// Section attributes: only, or some, machine instructions.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// Bytes of the fixed name fields.
const NAME_SIZE: usize = 16;

/// Where the address-sized fields start in a segment command and a section.
const SEGMENT_WORDS: usize = 24;
const SECTION_WORDS: usize = 32;

/// The sizes in bytes that differ between the 32-bit and the 64-bit
/// layout.
struct SegmentLayout {
    /// `segment_command` or `segment_command_64`.
    command: usize,
    /// `section` or `section_64`.
    section: usize,
    /// Address and size fields: 4 or 8.
    word: usize,
}

const SEGMENT_32: SegmentLayout = SegmentLayout {
    command: 56,
    section: 68,
    word: 4,
};

const SEGMENT_64: SegmentLayout = SegmentLayout {
    command: 72,
    section: 80,
    word: 8,
};

/// The address-sized field at `at`.
fn word_at(bytes: &[u8], at: usize, layout: &SegmentLayout, le: bool) -> Result<u64> {
    if layout.word == 8 {
        read_u64(bytes, at, le)
    } else {
        read_u32(bytes, at, le).map(u64::from)
    }
}

/// Read an `LC_SEGMENT` or `LC_SEGMENT_64` command and its sections. As in
/// dyld's `validSegments`, `cmdsize` must be the structure plus exactly
/// `nsects` sections.
pub(super) fn read_segment(command: &Command<'_>) -> Result<Segment> {
    let layout = if command.cmd == LC_SEGMENT_64 {
        &SEGMENT_64
    } else {
        &SEGMENT_32
    };
    command.expect_size(layout.command)?;
    let le = command.little_endian;
    let bytes = command.bytes;
    let word = layout.word;
    let fields = SEGMENT_WORDS + 4 * word;
    let section_count = command.u32_at(fields + 8)?;
    let sections_size = (section_count as usize)
        .checked_mul(layout.section)
        .filter(|&size| size == bytes.len() - layout.command)
        .ok_or_else(|| {
            error(format!(
                "Invalid {} at 0x{:X}: cmdsize {} B does not match nsects {section_count}",
                command.name(),
                command.offset,
                bytes.len()
            ))
        })?;
    let mut segment = Segment {
        name: commands::printable(&bytes[8..8 + NAME_SIZE]),
        vm_address: word_at(bytes, SEGMENT_WORDS, layout, le)?,
        vm_size: word_at(bytes, SEGMENT_WORDS + word, layout, le)?,
        file_offset: word_at(bytes, SEGMENT_WORDS + 2 * word, layout, le)?,
        file_size: word_at(bytes, SEGMENT_WORDS + 3 * word, layout, le)?,
        max_protection: command.u32_at(fields)?,
        initial_protection: command.u32_at(fields + 4)?,
        sections: Vec::with_capacity(section_count as usize),
    };
    let table = &bytes[layout.command..layout.command + sections_size];
    for record in table.chunks_exact(layout.section) {
        segment.sections.push(read_section(record, layout, le)?);
    }
    Ok(segment)
}

/// One `section` or `section_64` record.
fn read_section(record: &[u8], layout: &SegmentLayout, le: bool) -> Result<Section> {
    let word = layout.word;
    let fields = SECTION_WORDS + 2 * word;
    Ok(Section {
        name: commands::printable(&record[..NAME_SIZE]),
        segment_name: commands::printable(&record[NAME_SIZE..2 * NAME_SIZE]),
        address: word_at(record, SECTION_WORDS, layout, le)?,
        size: word_at(record, SECTION_WORDS + word, layout, le)?,
        offset: read_u32(record, fields, le)?,
        flags: read_u32(record, fields + 16, le)?,
    })
}

impl Section {
    /// The section holds machine instructions (`S_ATTR_PURE_INSTRUCTIONS`
    /// or `S_ATTR_SOME_INSTRUCTIONS`).
    pub fn has_instructions(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// The section type allocates zeros instead of storing bytes.
    pub fn is_zero_fill(&self) -> bool {
        matches!(
            self.flags & SECTION_TYPE,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }

    /// The file range of the section's bytes: its `offset` and `size`,
    /// within the file range its segment maps. Zero-fill sections and
    /// sections outside the segment's file bytes (a dSYM's `__TEXT`) store
    /// nothing.
    fn stored_range(&self, segment: &Segment) -> Option<FileRange> {
        if self.is_zero_fill() {
            return None;
        }
        let start = u64::from(self.offset);
        let end = start.saturating_add(self.size);
        let segment_end = segment.file_offset.saturating_add(segment.file_size);
        FileRange {
            start: start.max(segment.file_offset),
            end: end.min(segment_end),
        }
        .non_empty()
    }
}

/// A half-open range of file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileRange {
    start: u64,
    end: u64,
}

impl FileRange {
    fn len(self) -> u64 {
        self.end - self.start
    }

    fn non_empty(self) -> Option<Self> {
        (self.start < self.end).then_some(self)
    }

    /// The part of `self` before `other` and the part after it.
    fn without(self, other: Self) -> [Option<Self>; 2] {
        let before = Self {
            start: self.start,
            end: self.end.min(other.start),
        };
        let after = Self {
            start: self.start.max(other.end),
            end: self.end,
        };
        [before.non_empty(), after.non_empty()]
    }
}

/// The stored bytes of an image's instruction sections, scanned for
/// extensions of the image's ISA.
#[derive(Debug)]
pub struct Code<'a> {
    /// The bytes, in file order without gaps; borrowed when they are one
    /// contiguous range of the input.
    pub bytes: Cow<'a, [u8]>,
    /// Instruction sections with stored bytes.
    pub sections: usize,
    /// Bytes of those sections in the encrypted range, left out.
    pub encrypted: u64,
    /// Bytes of those sections past the end of the input, left out.
    pub missing: u64,
    /// Bytes left out beyond [`MAX_PAYLOAD`].
    pub capped: u64,
}

impl Code<'_> {
    /// What extension detection scans, as a note.
    pub fn note(&self) -> String {
        if self.sections == 0 {
            return "No instruction section has stored bytes; no code is scanned for extensions"
                .to_string();
        }
        let mut parts = vec![format!(
            "Extensions scanned in {} instruction {} ({} B)",
            self.sections,
            if self.sections == 1 {
                "section"
            } else {
                "sections"
            },
            self.bytes.len()
        )];
        if self.encrypted > 0 {
            parts.push(format!("{} B encrypted and left out", self.encrypted));
        }
        if self.missing > 0 {
            parts.push(format!(
                "{} B past the end of the input left out",
                self.missing
            ));
        }
        if self.capped > 0 {
            parts.push(format!(
                "{} B beyond the {} MiB limit left out",
                self.capped,
                MAX_PAYLOAD >> 20
            ));
        }
        parts.join("; ")
    }
}

impl Image {
    /// Sections across all segments.
    pub fn section_count(&self) -> usize {
        self.segments.iter().map(|s| s.sections.len()).sum()
    }

    /// The stored bytes of the instruction sections, without encrypted
    /// bytes, or `None` when the image's file offsets do not locate its
    /// bytes in `data`.
    pub fn code<'a>(&self, data: &'a [u8]) -> Option<Code<'a>> {
        if !self.offsets_in_input {
            return None;
        }
        let encrypted = self
            .encryption
            .filter(Encryption::is_encrypted)
            .and_then(|e| {
                FileRange {
                    start: u64::from(e.offset),
                    end: u64::from(e.offset) + u64::from(e.size),
                }
                .non_empty()
            });
        let input_end = data.len() as u64;
        let mut code = Code {
            bytes: Cow::Borrowed(&[]),
            sections: 0,
            encrypted: 0,
            missing: 0,
            capped: 0,
        };
        let mut ranges = Vec::new();
        for segment in &self.segments {
            for section in segment.sections.iter().filter(|s| s.has_instructions()) {
                let Some(stored) = section.stored_range(segment) else {
                    continue;
                };
                code.sections += 1;
                let pieces = match encrypted {
                    Some(hidden) => stored.without(hidden),
                    None => [Some(stored), None],
                };
                let kept: u64 = pieces.iter().flatten().map(|p| p.len()).sum();
                code.encrypted += stored.len() - kept;
                for piece in pieces.into_iter().flatten() {
                    let present = FileRange {
                        start: piece.start.min(input_end),
                        end: piece.end.min(input_end),
                    };
                    code.missing += piece.len() - present.len();
                    if let Some(present) = present.non_empty() {
                        ranges.push(present);
                    }
                }
            }
        }
        let ranges = merge(ranges);
        code.bytes = gather(data, &ranges, &mut code.capped);
        Some(code)
    }
}

/// Sort ranges and join the ones that overlap or touch.
fn merge(mut ranges: Vec<FileRange>) -> Vec<FileRange> {
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<FileRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// The bytes of `ranges` (sorted, inside `data`): borrowed for one range,
/// otherwise concatenated up to [`MAX_PAYLOAD`], counting the rest in
/// `capped`.
fn gather<'a>(data: &'a [u8], ranges: &[FileRange], capped: &mut u64) -> Cow<'a, [u8]> {
    let slice = |r: &FileRange| {
        let start = usize::try_from(r.start).expect("ranges are clipped to the input");
        let end = usize::try_from(r.end).expect("ranges are clipped to the input");
        &data[start..end]
    };
    if let [only] = ranges {
        return Cow::Borrowed(slice(only));
    }
    let mut bytes = Vec::new();
    for range in ranges {
        let room = MAX_PAYLOAD - bytes.len();
        let piece = slice(range);
        let taken = piece.len().min(room);
        bytes.extend_from_slice(&piece[..taken]);
        *capped += (piece.len() - taken) as u64;
    }
    Cow::Owned(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, end: u64) -> FileRange {
        FileRange { start, end }
    }

    #[test]
    fn ranges_lose_the_overlap_with_a_hidden_range() {
        let hidden = range(10, 20);
        assert_eq!(
            range(0, 30).without(hidden),
            [Some(range(0, 10)), Some(range(20, 30))]
        );
        assert_eq!(range(12, 18).without(hidden), [None, None]);
        assert_eq!(range(0, 10).without(hidden), [Some(range(0, 10)), None]);
        assert_eq!(range(15, 25).without(hidden), [None, Some(range(20, 25))]);
    }

    #[test]
    fn touching_and_overlapping_ranges_merge_in_file_order() {
        let merged = merge(vec![
            range(20, 30),
            range(0, 10),
            range(10, 15),
            range(25, 40),
        ]);
        assert_eq!(merged, [range(0, 15), range(20, 40)]);
    }

    #[test]
    fn one_range_is_borrowed_and_several_are_concatenated() {
        let data: Vec<u8> = (0..16).collect();
        let mut capped = 0;
        let one = gather(&data, &[range(2, 6)], &mut capped);
        assert!(matches!(one, Cow::Borrowed(_)));
        assert_eq!(&one[..], &[2, 3, 4, 5]);
        let two = gather(&data, &[range(0, 2), range(14, 16)], &mut capped);
        assert_eq!(&two[..], &[0, 1, 14, 15]);
        assert_eq!(capped, 0);
    }
}
