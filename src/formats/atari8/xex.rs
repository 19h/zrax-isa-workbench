//! Atari DOS binary load files (`.xex`, `.com`).
//!
//! A sequence of segments: a start address and an inclusive end address (2 +
//! 2, little-endian), then end - start + 1 bytes loaded at the start
//! address. The first segment is preceded by the marker `FF FF`; later ones
//! may be ("Mapping the Atari" entry 736; bw-atari8-tools `xex.5`; cc65
//! `src/ld65/xex.c`). atari800 `binload.c`, Altirra `hleprogramloader.cpp`
//! and `AtariSIO` `ComBlock.cpp` skip any number of markers before a start
//! address, so no segment starts at 0xFFFF, and all three reject an end
//! address below the start.
//!
//! DOS jumps through RUNAD (0x02E0) once the whole file is loaded and calls
//! INITAD (0x02E2) as soon as a segment has loaded it ("Mapping the Atari"
//! entries 736 and 738; `xex.5`). Without a run address DOS returns to its
//! menu; the emulators' default of the first segment's start is their own
//! convention and is not reported.
//!
//! Beyond the marker there is no magic, so a file is recognized only when
//! its segments tile it exactly. Init code may read the rest of a file
//! itself ("raw data blocks", `xex.5`); such files do not tile and are not
//! recognized.

use super::*;
use crate::formats::container::{Section, MAX_COMPONENTS};
use std::borrow::Cow;

/// The marker before the first segment, optional before the others.
const MARKER: [u8; 2] = [0xff, 0xff];

/// Start and end address of a segment.
const ADDRESSES_SIZE: usize = 4;

/// DOS vectors ("Mapping the Atari" entries 736-739).
const RUNAD: u16 = 0x02e0;
const INITAD: u16 = 0x02e2;

/// Init addresses listed one by one in the notes; further ones are counted.
const MAX_INITS_LISTED: usize = 16;

/// One segment, in file coordinates.
#[derive(Debug, Clone, Copy)]
struct Segment {
    /// File offset of the start address, after any markers.
    offset: usize,
    /// First address loaded.
    start: u16,
    /// Last address loaded (inclusive).
    end: u16,
}

impl Segment {
    /// File offset of the loaded bytes.
    fn data_offset(&self) -> usize {
        self.offset + ADDRESSES_SIZE
    }

    /// Bytes loaded, 1 to 65536.
    fn size(&self) -> usize {
        usize::from(self.end - self.start) + 1
    }

    fn covers(&self, address: u16) -> bool {
        (self.start..=self.end).contains(&address)
    }

    /// The DOS vectors the segment consists of, if it loads nothing else.
    fn vector_role(&self) -> Option<&'static str> {
        let vectors = RUNAD..=INITAD + 1;
        if !vectors.contains(&self.start) || !vectors.contains(&self.end) {
            return None;
        }
        let run = self.covers(RUNAD) || self.covers(RUNAD + 1);
        let init = self.covers(INITAD) || self.covers(INITAD + 1);
        match (run, init) {
            (true, true) => Some("RUNAD and INITAD"),
            (true, false) => Some("RUNAD"),
            (false, _) => Some("INITAD"),
        }
    }

    fn label(&self, number: usize) -> String {
        let range = format!("Segment {number}: 0x{:04X}-0x{:04X}", self.start, self.end);
        match self.vector_role() {
            Some(role) => format!("{range} ({role})"),
            None => range,
        }
    }
}

/// The segments of a binary load file in file order. Yields one error at
/// the first defect and stops.
struct Segments<'a> {
    data: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> Segments<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            failed: false,
        }
    }

    /// The segment whose markers or start address are at `self.pos`.
    fn next_segment(&mut self) -> Result<Segment> {
        let data = self.data;
        let first = self.pos;
        if first == 0 && !data.starts_with(&MARKER) {
            return Err(error("Missing binary load marker FF FF at 0x0"));
        }
        let mut offset = first;
        while data
            .get(offset..)
            .is_some_and(|rest| rest.starts_with(&MARKER))
        {
            offset += MARKER.len();
        }
        let remaining = data.len() - offset;
        if remaining == 0 {
            return Err(error(format!(
                "Truncated binary load file: the marker at 0x{first:X} is not followed by a segment"
            )));
        }
        let (Some(start), Some(end)) = (le_u16(data, offset), le_u16(data, offset + 2)) else {
            return Err(error(format!(
                "Truncated segment header at 0x{offset:X}: {remaining} B of {ADDRESSES_SIZE}"
            )));
        };
        if end < start {
            return Err(error(format!(
                "Invalid segment at 0x{offset:X}: end address 0x{end:04X} is below start address 0x{start:04X}"
            )));
        }
        let segment = Segment { offset, start, end };
        let available = remaining - ADDRESSES_SIZE;
        if segment.size() > available {
            return Err(error(format!(
                "Truncated segment at 0x{offset:X}: 0x{start:04X}-0x{end:04X} needs {} B, {available} B remain",
                segment.size()
            )));
        }
        self.pos = segment.data_offset() + segment.size();
        Ok(segment)
    }
}

impl Iterator for Segments<'_> {
    type Item = Result<Segment>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || (self.pos > 0 && self.pos == self.data.len()) {
            return None;
        }
        let segment = self.next_segment();
        self.failed = segment.is_err();
        Some(segment)
    }
}

/// The marker, then segments that are all valid and tile the file. Walks
/// the file without allocating.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(&MARKER) && Segments::new(data).all(|segment| segment.is_ok())
}

/// Standalone recognition, with no disk structure behind it: the segments
/// tile the file and load a run address or an init address, through which
/// DOS starts a program. A file whose segments load neither is not claimed:
/// erased flash with a few programmed bytes tiles into short segments at
/// 0xFFxx surprisingly often, but practically never loads the vectors.
pub(super) fn detect_program(data: &[u8]) -> bool {
    if !detect(data) {
        return false;
    }
    let mut vectors = Vectors::default();
    for segment in Segments::new(data).flatten() {
        let offset = segment.data_offset();
        vectors.load(&segment, &data[offset..offset + segment.size()]);
    }
    vectors.run_address().is_some() || vectors.init_count > 0
}

/// The DOS vectors a file loads.
#[derive(Default)]
struct Vectors {
    /// RUNAD and RUNAD + 1 as last loaded.
    run: [Option<u8>; 2],
    /// Init addresses, in load order, up to [`MAX_INITS_LISTED`].
    inits: Vec<u16>,
    /// Segments that load INITAD completely.
    init_count: usize,
    /// Segments that load only one byte of INITAD.
    partial_inits: usize,
}

impl Vectors {
    /// Record what `segment`, holding `bytes`, writes to the vectors. DOS
    /// calls INITAD after each segment that loads it, so an init address
    /// counts only when one segment loads both of its bytes.
    fn load(&mut self, segment: &Segment, bytes: &[u8]) {
        let byte_at = |address: u16| {
            segment
                .covers(address)
                .then(|| bytes[usize::from(address - segment.start)])
        };
        for (slot, address) in self.run.iter_mut().zip([RUNAD, RUNAD + 1]) {
            if let Some(value) = byte_at(address) {
                *slot = Some(value);
            }
        }
        match (byte_at(INITAD), byte_at(INITAD + 1)) {
            (Some(low), Some(high)) => {
                self.init_count += 1;
                if self.inits.len() < MAX_INITS_LISTED {
                    self.inits.push(u16::from_le_bytes([low, high]));
                }
            }
            (None, None) => {}
            _ => self.partial_inits += 1,
        }
    }

    fn run_address(&self) -> Option<u16> {
        match self.run {
            [Some(low), Some(high)] => Some(u16::from_le_bytes([low, high])),
            _ => None,
        }
    }

    /// The init addresses as `0x0600, 0x0700`, with a count of the rest.
    fn init_text(&self) -> String {
        let listed: Vec<String> = self.inits.iter().map(|a| format!("0x{a:04X}")).collect();
        let more = self.init_count - self.inits.len();
        if more > 0 {
            format!("{} and {more} more", listed.join(", "))
        } else {
            listed.join(", ")
        }
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(FileFormat::AtariXex, CPU_VARIANT, "atarixex");
    c.target = Some(MOS_6502);
    c.code_sections = true;
    c.consumed = data.len();
    let mut vectors = Vectors::default();
    let mut count = 0usize;
    let mut loaded = 0u64;
    for segment in Segments::new(data) {
        let segment = segment?;
        let offset = segment.data_offset();
        let bytes = &data[offset..offset + segment.size()];
        vectors.load(&segment, bytes);
        count += 1;
        loaded += bytes.len() as u64;
        if c.sections.len() < MAX_COMPONENTS {
            c.sections.push(Section {
                label: segment.label(count),
                address: u64::from(segment.start),
                offset,
                stored_size: bytes.len(),
                data: Cow::Borrowed(bytes),
                transform: None,
            });
        }
    }
    let run = vectors.run_address();
    c.entry = run
        .or_else(|| vectors.inits.first().copied())
        .map(u64::from);
    c.notes.push(format!(
        "Atari DOS binary load file: {}, {} loaded",
        count_text(count, "segment"),
        size_text(loaded)
    ));
    c.notes.push(
        "Atari 8-bit computers run NMOS 6502 code (6502 or 6502C); 8-bit, little-endian".into(),
    );
    push_vector_notes(&mut c, &vectors, run);
    if count > c.sections.len() {
        c.notes.push(format!(
            "{} further segments are not listed (limit {MAX_COMPONENTS})",
            count - c.sections.len()
        ));
    }
    c.push_metadata("atarixex_segments", "Segments", count as u64);
    c.push_metadata("atarixex_loaded_size", "Bytes loaded (B)", loaded);
    if let Some(run) = run {
        c.push_metadata(
            "atarixex_runad",
            "Run address (RUNAD)",
            format!("0x{run:04X}"),
        );
    }
    if vectors.init_count > 0 {
        c.push_metadata(
            "atarixex_initad",
            "Init addresses (INITAD)",
            vectors.init_text(),
        );
    }
    Ok(c)
}

fn push_vector_notes(c: &mut Container<'_>, vectors: &Vectors, run: Option<u16>) {
    match (run, vectors.run) {
        (Some(run), _) => c.notes.push(format!("Run address (RUNAD) 0x{run:04X}")),
        (None, [None, None]) => c
            .notes
            .push("No run address (RUNAD): DOS returns to its menu after loading".into()),
        (None, _) => c
            .notes
            .push("Only one byte of RUNAD is loaded; no run address is reported".into()),
    }
    if vectors.init_count > 0 {
        let entry = if run.is_some() {
            ""
        } else {
            "; the first is reported as the entry point"
        };
        c.notes.push(format!(
            "Init calls (INITAD): {}{entry}",
            vectors.init_text()
        ));
    }
    if vectors.partial_inits > 0 {
        c.notes.push(format!(
            "Segments that load only one byte of INITAD: {}; no init call is reported for them",
            vectors.partial_inits
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FF FF`, a segment 0x0600-0x0602 (`LDA #0`, `RTS`), then RUNAD
    /// without a marker.
    const PROGRAM: [u8; 15] = [
        0xff, 0xff, 0x00, 0x06, 0x02, 0x06, 0xa9, 0x00, 0x60, 0xe0, 0x02, 0xe1, 0x02, 0x00, 0x06,
    ];

    #[test]
    fn segments_tile_the_file() {
        let segments: Vec<Segment> = Segments::new(&PROGRAM).map(Result::unwrap).collect();
        assert_eq!(segments.len(), 2);
        assert_eq!((segments[0].start, segments[0].end), (0x0600, 0x0602));
        assert_eq!(segments[0].data_offset(), 6);
        assert_eq!(segments[1].vector_role(), Some("RUNAD"));
        assert!(detect(&PROGRAM));
    }

    #[test]
    fn repeated_markers_are_skipped() {
        let mut data = vec![0xff, 0xff, 0xff, 0xff];
        data.extend_from_slice(&PROGRAM[2..]);
        assert!(detect(&data));
        assert_eq!(Segments::new(&data).next().unwrap().unwrap().offset, 4);
    }

    #[test]
    fn padding_and_trailing_markers_do_not_tile() {
        assert!(!detect(&[0xff; 7]));
        assert!(!detect(&[0xff; 64]));
        let mut data = PROGRAM.to_vec();
        data.extend_from_slice(&MARKER);
        assert!(!detect(&data));
        data.truncate(PROGRAM.len() - 1);
        assert!(!detect(&data));
    }

    #[test]
    fn init_addresses_need_both_bytes_from_one_segment() {
        let segment = Segment {
            offset: 0,
            start: INITAD,
            end: INITAD,
        };
        let mut vectors = Vectors::default();
        vectors.load(&segment, &[0x00]);
        assert_eq!((vectors.init_count, vectors.partial_inits), (0, 1));
        let both = Segment {
            end: INITAD + 1,
            ..segment
        };
        vectors.load(&both, &[0x00, 0x06]);
        assert_eq!(vectors.inits, [0x0600]);
        assert_eq!(both.vector_role(), Some("INITAD"));
    }
}
