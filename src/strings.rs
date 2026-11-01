//! Printable strings in arbitrary bytes, in the manner of GNU `strings`,
//! extended to UTF-8 and UTF-16.
//!
//! | Encoding | A run consists of |
//! | --- | --- |
//! | `ascii` | Bytes `0x20`-`0x7E` and tab (`0x09`) |
//! | `utf8` | ASCII as above and well-formed UTF-8 sequences (Unicode 15.0, section 3.9, Table 3-7) of non-control scalars, with at least one multibyte scalar |
//! | `utf16le`, `utf16be` | 16-bit code units `0x0009`, `0x0020`-`0x007E` and `0x00A0`-`0x00FF`, at either byte parity |
//!
//! A run is reported when it has at least the minimum number of characters.
//! An ASCII run without multibyte scalars is `ascii` even while UTF-8 is
//! enabled. UTF-16 parity is absolute: a unit starts at an even or an odd
//! file offset. A UTF-16LE run preceded by `0x00` therefore also reads as a
//! UTF-16BE run one byte earlier; both are reported when both encodings are
//! enabled. UTF-16 text outside U+0000-U+00FF is not reported.
//!
//! [`Scanner`] consumes the input in chunks of any size and emits strings in
//! `(offset, encoding)` order; the result does not depend on chunk
//! boundaries. Tags ([`Tags`]) are lexical pattern matches on the text.

mod tags;

use bitflags::bitflags;
use serde::Serialize;

use crate::error::{ClassifierError, Result};

pub use tags::{tag_text, Tags, TAG_NAMES};

/// Default minimum run length in characters, as in GNU `strings`.
pub const DEFAULT_MIN_CHARS: usize = 4;
/// Smallest accepted minimum run length in characters.
pub const MIN_MIN_CHARS: usize = 3;
/// Largest accepted minimum run length in characters.
pub const MAX_MIN_CHARS: usize = 255;
/// Characters of text kept per string; longer runs are clipped.
pub const MAX_TEXT_CHARS: usize = 4096;

const TAB: u8 = 0x09;

/// How a string is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// Printable ASCII and tab.
    Ascii,
    /// UTF-8 with at least one multibyte scalar.
    Utf8,
    /// Little-endian 16-bit code units up to U+00FF.
    Utf16le,
    /// Big-endian 16-bit code units up to U+00FF.
    Utf16be,
}

/// Every encoding in output order.
pub const ENCODINGS: [Encoding; 4] = [
    Encoding::Ascii,
    Encoding::Utf8,
    Encoding::Utf16le,
    Encoding::Utf16be,
];

bitflags! {
    /// A set of encodings to report.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Encodings: u8 {
        /// [`Encoding::Ascii`].
        const ASCII = 1;
        /// [`Encoding::Utf8`].
        const UTF8 = 2;
        /// [`Encoding::Utf16le`].
        const UTF16LE = 4;
        /// [`Encoding::Utf16be`].
        const UTF16BE = 8;
    }
}

impl Encoding {
    /// The JSON and command-line identifier.
    pub fn id(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16le => "utf16le",
            Self::Utf16be => "utf16be",
        }
    }

    /// The encoding with identifier `id`.
    pub fn from_id(id: &str) -> Option<Self> {
        ENCODINGS.into_iter().find(|e| e.id() == id)
    }

    /// This encoding as a one-member set.
    pub fn flag(self) -> Encodings {
        match self {
            Self::Ascii => Encodings::ASCII,
            Self::Utf8 => Encodings::UTF8,
            Self::Utf16le => Encodings::UTF16LE,
            Self::Utf16be => Encodings::UTF16BE,
        }
    }
}

/// What to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    min_chars: usize,
    encodings: Encodings,
}

impl Default for Options {
    /// Four characters; ASCII, UTF-8 and UTF-16LE.
    fn default() -> Self {
        Self {
            min_chars: DEFAULT_MIN_CHARS,
            encodings: Encodings::ASCII | Encodings::UTF8 | Encodings::UTF16LE,
        }
    }
}

impl Options {
    /// Report runs of at least `min_chars` characters in `encodings`.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::InspectionError`] when `min_chars` is outside
    /// 3..=255 or no encoding is selected.
    pub fn new(min_chars: usize, encodings: Encodings) -> Result<Self> {
        if !(MIN_MIN_CHARS..=MAX_MIN_CHARS).contains(&min_chars) {
            return Err(ClassifierError::InspectionError {
                message: format!(
                    "Invalid minimum string length {min_chars}; expected {MIN_MIN_CHARS} to {MAX_MIN_CHARS}"
                ),
            });
        }
        if encodings.is_empty() {
            return Err(ClassifierError::InspectionError {
                message: "Missing string encoding".to_string(),
            });
        }
        Ok(Self {
            min_chars,
            encodings,
        })
    }

    /// Minimum run length in characters.
    pub fn min_chars(&self) -> usize {
        self.min_chars
    }

    /// Encodings to report.
    pub fn encodings(&self) -> Encodings {
        self.encodings
    }
}

/// One printable run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundString {
    /// Byte offset of the first character.
    pub offset: u64,
    /// Size of the run in bytes.
    pub size: u64,
    /// Length of the run in characters.
    pub chars: u64,
    /// How the run is encoded.
    pub encoding: Encoding,
    /// The first [`MAX_TEXT_CHARS`] characters.
    pub text: String,
    /// The run is longer than `text`.
    pub clipped: bool,
    /// Lexical pattern matches on `text`.
    pub tags: Tags,
}

/// The text of an open run, clipped at [`MAX_TEXT_CHARS`] characters.
#[derive(Debug, Default)]
struct Text {
    text: String,
    chars: u64,
}

impl Text {
    fn push(&mut self, c: char) {
        if self.chars < MAX_TEXT_CHARS as u64 {
            self.text.push(c);
        }
        self.chars += 1;
    }
}

/// An open run.
#[derive(Debug)]
struct Run {
    start: u64,
    text: Text,
}

fn emit(run: Run, end: u64, encoding: Encoding, options: &Options, out: &mut Vec<FoundString>) {
    if run.text.chars < options.min_chars as u64 || !options.encodings.contains(encoding.flag()) {
        return;
    }
    let tags = tag_text(&run.text.text);
    out.push(FoundString {
        offset: run.start,
        size: end - run.start,
        chars: run.text.chars,
        encoding,
        clipped: run.text.chars > MAX_TEXT_CHARS as u64,
        text: run.text.text,
        tags,
    });
}

/// A UTF-8 sequence after its lead byte.
#[derive(Debug, Clone, Copy)]
struct Pending {
    start: u64,
    scalar: u32,
    remaining: u8,
    /// Allowed range of the first continuation byte (Table 3-7).
    second: (u8, u8),
    seen: u8,
}

/// The first continuation range and the number of continuation bytes for a
/// UTF-8 lead byte, or `None` when it cannot start a well-formed sequence.
fn utf8_lead(lead: u8) -> Option<((u8, u8), u8, u32)> {
    match lead {
        0xc2..=0xdf => Some(((0x80, 0xbf), 1, u32::from(lead & 0x1f))),
        0xe0 => Some(((0xa0, 0xbf), 2, 0)),
        0xe1..=0xec | 0xee..=0xef => Some(((0x80, 0xbf), 2, u32::from(lead & 0x0f))),
        0xed => Some(((0x80, 0x9f), 2, 0x0d)),
        0xf0 => Some(((0x90, 0xbf), 3, 0)),
        0xf1..=0xf3 => Some(((0x80, 0xbf), 3, u32::from(lead & 0x07))),
        0xf4 => Some(((0x80, 0x8f), 3, 4)),
        _ => None,
    }
}

fn is_ascii_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == TAB
}

/// ASCII and UTF-8 runs over single bytes.
#[derive(Debug, Default)]
struct ByteRuns {
    run: Option<Run>,
    multibyte: bool,
    pending: Option<Pending>,
}

impl ByteRuns {
    fn close(&mut self, end: u64, options: &Options, out: &mut Vec<FoundString>) {
        if let Some(run) = self.run.take() {
            let encoding = if self.multibyte {
                Encoding::Utf8
            } else {
                Encoding::Ascii
            };
            emit(run, end, encoding, options, out);
        }
        self.multibyte = false;
    }

    fn push_char(&mut self, start: u64, c: char) {
        self.run
            .get_or_insert_with(|| Run {
                start,
                text: Text::default(),
            })
            .text
            .push(c);
    }

    fn byte(&mut self, at: u64, b: u8, options: &Options, out: &mut Vec<FoundString>) {
        if let Some(mut pending) = self.pending {
            let (low, high) = if pending.seen == 0 {
                pending.second
            } else {
                (0x80, 0xbf)
            };
            if (low..=high).contains(&b) {
                pending.scalar = (pending.scalar << 6) | u32::from(b & 0x3f);
                pending.seen += 1;
                if pending.seen < pending.remaining {
                    self.pending = Some(pending);
                    return;
                }
                self.pending = None;
                match char::from_u32(pending.scalar).filter(|c| !c.is_control()) {
                    Some(c) => {
                        self.push_char(pending.start, c);
                        self.multibyte = true;
                    }
                    None => self.close(pending.start, options, out),
                }
                return;
            }
            // An incomplete sequence ends the run before its lead byte; this
            // byte starts afresh.
            self.pending = None;
            self.close(pending.start, options, out);
        }
        let utf8 = options.encodings.contains(Encodings::UTF8);
        if is_ascii_printable(b) {
            self.push_char(at, char::from(b));
        } else if let (true, Some((second, remaining, scalar))) = (utf8, utf8_lead(b)) {
            self.pending = Some(Pending {
                start: at,
                scalar,
                remaining,
                second,
                seen: 0,
            });
        } else {
            self.close(at, options, out);
        }
    }

    fn finish(&mut self, end: u64, options: &Options, out: &mut Vec<FoundString>) {
        let end = self.pending.take().map_or(end, |pending| pending.start);
        self.close(end, options, out);
    }

    fn open_start(&self) -> Option<u64> {
        match (&self.run, &self.pending) {
            (Some(run), _) => Some(run.start),
            (None, Some(pending)) => Some(pending.start),
            (None, None) => None,
        }
    }
}

fn utf16_char(unit: u16) -> Option<char> {
    match unit {
        0x0009 | 0x0020..=0x007e | 0x00a0..=0x00ff => char::from_u32(u32::from(unit)),
        _ => None,
    }
}

/// UTF-16 runs of one byte order at one byte parity.
#[derive(Debug)]
struct UnitRuns {
    encoding: Encoding,
    run: Option<Run>,
}

impl UnitRuns {
    fn unit(&mut self, at: u64, unit: u16, options: &Options, out: &mut Vec<FoundString>) {
        match utf16_char(unit) {
            Some(c) => self
                .run
                .get_or_insert_with(|| Run {
                    start: at,
                    text: Text::default(),
                })
                .text
                .push(c),
            None => self.close(at, options, out),
        }
    }

    fn close(&mut self, end: u64, options: &Options, out: &mut Vec<FoundString>) {
        if let Some(run) = self.run.take() {
            emit(run, end, self.encoding, options, out);
        }
    }

    /// Close at the end of the last whole unit of this parity before `end`.
    fn finish(&mut self, end: u64, options: &Options, out: &mut Vec<FoundString>) {
        if let Some(run) = &self.run {
            let whole_units = (end - run.start) / 2;
            let run_end = run.start + whole_units * 2;
            self.close(run_end, options, out);
        }
    }
}

/// Streaming string extraction over consecutive chunks of one input.
#[derive(Debug)]
pub struct Scanner {
    options: Options,
    position: u64,
    previous: Option<u8>,
    bytes: ByteRuns,
    /// UTF-16 runners indexed by `parity * 2 + (0 for LE, 1 for BE)`.
    units: [UnitRuns; 4],
    closed: Vec<FoundString>,
}

impl Scanner {
    /// A scanner at offset 0.
    pub fn new(options: Options) -> Self {
        let unit_runs = |encoding| UnitRuns {
            encoding,
            run: None,
        };
        Self {
            options,
            position: 0,
            previous: None,
            bytes: ByteRuns::default(),
            units: [
                unit_runs(Encoding::Utf16le),
                unit_runs(Encoding::Utf16be),
                unit_runs(Encoding::Utf16le),
                unit_runs(Encoding::Utf16be),
            ],
            closed: Vec::new(),
        }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Consume the next chunk and append every string that can no longer
    /// be preceded by another one to `out`, in `(offset, encoding)` order.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<FoundString>) {
        let byte_runs = self
            .options
            .encodings
            .intersects(Encodings::ASCII | Encodings::UTF8);
        let utf16le = self.options.encodings.contains(Encodings::UTF16LE);
        let utf16be = self.options.encodings.contains(Encodings::UTF16BE);
        for &b in chunk {
            let at = self.position;
            if byte_runs {
                self.bytes.byte(at, b, &self.options, &mut self.closed);
            }
            if let Some(previous) = self.previous {
                // The unit made of the previous byte and this one starts at
                // `at - 1`, whose parity selects the runner pair.
                let start = at - 1;
                let parity = usize::from(start % 2 == 1);
                if utf16le {
                    let unit = u16::from_le_bytes([previous, b]);
                    self.units[parity * 2].unit(start, unit, &self.options, &mut self.closed);
                }
                if utf16be {
                    let unit = u16::from_be_bytes([previous, b]);
                    self.units[parity * 2 + 1].unit(start, unit, &self.options, &mut self.closed);
                }
            }
            self.previous = Some(b);
            self.position += 1;
        }
        self.drain(out, false);
    }

    /// Close every open run and append the remaining strings to `out`.
    pub fn finish(&mut self, out: &mut Vec<FoundString>) {
        let end = self.position;
        self.bytes.finish(end, &self.options, &mut self.closed);
        for runner in &mut self.units {
            runner.finish(end, &self.options, &mut self.closed);
        }
        self.drain(out, true);
    }

    /// Move closed strings that start before every open run to `out`.
    fn drain(&mut self, out: &mut Vec<FoundString>, all: bool) {
        let watermark = if all {
            u64::MAX
        } else {
            self.units
                .iter()
                .filter_map(|runner| runner.run.as_ref().map(|run| run.start))
                .chain(self.bytes.open_start())
                .min()
                .unwrap_or(self.position)
        };
        self.closed.sort_by_key(|s| (s.offset, s.encoding));
        let ready = self.closed.partition_point(|s| s.offset < watermark);
        out.extend(self.closed.drain(..ready));
    }
}

/// Strings of a complete input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Extraction {
    /// Strings in `(offset, encoding)` order.
    pub strings: Vec<FoundString>,
    /// More than the requested limit were found.
    pub truncated: bool,
}

/// Every string of `data`, at most `limit`.
pub fn extract(data: &[u8], options: &Options, limit: usize) -> Extraction {
    let mut scanner = Scanner::new(*options);
    let mut strings = Vec::new();
    scanner.push(data, &mut strings);
    scanner.finish(&mut strings);
    let truncated = strings.len() > limit;
    strings.truncate(limit);
    Extraction { strings, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_leads_follow_table_3_7() {
        assert!(utf8_lead(0x80).is_none());
        assert!(utf8_lead(0xc0).is_none());
        assert!(utf8_lead(0xc1).is_none());
        assert!(utf8_lead(0xf5).is_none());
        assert_eq!(utf8_lead(0xe0).map(|l| l.0), Some((0xa0, 0xbf)));
        assert_eq!(utf8_lead(0xed).map(|l| l.0), Some((0x80, 0x9f)));
        assert_eq!(utf8_lead(0xf4).map(|l| l.0), Some((0x80, 0x8f)));
    }

    #[test]
    fn options_reject_out_of_range_lengths_and_empty_sets() {
        assert!(Options::new(2, Encodings::ASCII).is_err());
        assert!(Options::new(256, Encodings::ASCII).is_err());
        assert!(Options::new(4, Encodings::empty()).is_err());
        assert_eq!(Options::new(3, Encodings::ASCII).unwrap().min_chars(), 3);
    }
}
