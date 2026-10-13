//! Psy-Q (SN Systems) LNK object files: the relocatable `.OBJ` files that
//! the SN Systems assemblers and compilers write for `psylink`, best known
//! from the Sony `PlayStation` Psy-Q SDK and also used for the Saturn and
//! the Mega Drive.
//!
//! No SN Systems document of the format is public; the sources are two
//! independent readers (pinned revisions and checksums in `docs/psyq.md`):
//! - PCSX-Redux `tools/psyq-obj-parser/psyq-obj-parser.cc` at commit
//!   `919c5976`: the `LNK` signature and version 2, the record opcodes
//!   (`PsyqOpcode`), the relocation expression operators
//!   (`PsyqExprOpcode`), the bodies of the section, symbol and debug
//!   records, and `.text` as the code section.
//! - psy-k 0.4.0 (`ttkb-oss/psy-k` at `e25c309c`) `src/lib.rs`: the same
//!   records under the names SN's `DUMPOBJ` prints, records 4, 20 and 44,
//!   expression operators 20 and 32-74, and the processor type identifiers
//!   (`cputype`).
//!
//! The file is `LNK`, a version byte and a stream of records, each a
//! one-byte opcode and a body without a length, so every record must be
//! decoded to reach the next one. Record fields are little-endian for every
//! target. The PROGRAMTYPE record (opcode 46, "Processor type" in
//! `DUMPOBJ`) is the format's own target field; only the processor types
//! the sources establish are mapped to an ISA. BYTES records hold section
//! contents as stored: relocations are not applied and zero fill is not
//! materialized.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Signature at offset 0.
const SIGNATURE: &[u8; 3] = b"LNK";
/// File offset of the version byte.
const VERSION_OFFSET: usize = 3;
/// The only version either reader accepts (PCSX-Redux rejects others).
const VERSION: u8 = 2;
/// Signature and version; the first record follows.
const HEADER_SIZE: usize = 4;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "psyq";
/// Transform named for a section reassembled from several BYTES records.
const RECORDS_TRANSFORM: &str = "LNK BYTES records";
/// The code section (PCSX-Redux `Section::isText`). Every other section
/// is treated as data.
const TEXT_SECTION: &[u8] = b".text";
/// Names listed in one note; the rest are only counted.
const NOTE_NAMES: usize = 8;
/// Characters kept of one name in notes and labels.
const NAME_CHARS: usize = 64;

// Record opcodes: PCSX-Redux `PsyqOpcode`, except `RUN_AT_OFFSET`,
// `GROUP_SYMBOL` and `SET_MX_INFO`, which only psy-k decodes (its names).
const END: u8 = 0;
const BYTES: u8 = 2;
const RUN_AT_OFFSET: u8 = 4;
const SWITCH: u8 = 6;
const ZEROES: u8 = 8;
const RELOCATION: u8 = 10;
const EXPORTED_SYMBOL: u8 = 12;
const IMPORTED_SYMBOL: u8 = 14;
const SECTION: u8 = 16;
const LOCAL_SYMBOL: u8 = 18;
const GROUP_SYMBOL: u8 = 20;
const FILENAME: u8 = 28;
const SET_MX_INFO: u8 = 44;
const PROGRAMTYPE: u8 = 46;
const UNINITIALIZED: u8 = 48;
const INC_SLD_LINENUM: u8 = 50;
const INC_SLD_LINENUM_BY_BYTE: u8 = 52;
const INC_SLD_LINENUM_BY_WORD: u8 = 54;
const SET_SLD_LINENUM: u8 = 56;
const SET_SLD_LINENUM_FILE: u8 = 58;
const END_SLD: u8 = 60;
const FUNCTION: u8 = 74;
const FUNCTION_END: u8 = 76;
const BLOCK_START: u8 = 78;
const BLOCK_END: u8 = 80;
const SECTION_DEF: u8 = 82;
const SECTION_DEF2: u8 = 84;
const FUNCTION_START2: u8 = 86;

/// Records that psy-k decodes but marks untested. With no record lengths
/// they cannot be skipped, so they are errors.
const UNTESTED_RECORDS: &[u8] = &[
    22, 24, 26, 30, 32, 34, 36, 38, 40, 42, 62, 64, 66, 68, 70, 72,
];

/// A record whose fixed-size body carries nothing that is reported: debug
/// line, block and function-end records.
struct FixedRecord {
    opcode: u8,
    name: &'static str,
    /// Body size after the opcode, in bytes.
    size: usize,
}

const fn fixed(opcode: u8, name: &'static str, size: usize) -> FixedRecord {
    FixedRecord { opcode, name, size }
}

/// Bodies: `RUN_AT_OFFSET` two u16 (psy-k); `SET_MX_INFO` u16 offset, u8
/// value (psy-k); `INC_SLD_LINENUM` u16 offset; `INC_SLD_LINENUM_BY_BYTE` u16
/// offset, u8 increment; `SET_SLD_LINENUM` u16 offset, u32 line;
/// `SET_SLD_LINENUM_FILE` u16 offset, u32 line, u16 file; `END_SLD` u16;
/// `FUNCTION_END`, `BLOCK_START` and `BLOCK_END` u16 section, u32 offset, u32
/// line.
const FIXED_RECORDS: &[FixedRecord] = &[
    fixed(RUN_AT_OFFSET, "RUN_AT_OFFSET", 4),
    fixed(SET_MX_INFO, "SET_MX_INFO", 3),
    fixed(INC_SLD_LINENUM, "INC_SLD_LINENUM", 2),
    fixed(INC_SLD_LINENUM_BY_BYTE, "INC_SLD_LINENUM_BY_BYTE", 3),
    fixed(SET_SLD_LINENUM, "SET_SLD_LINENUM", 6),
    fixed(SET_SLD_LINENUM_FILE, "SET_SLD_LINENUM_FILE", 8),
    fixed(END_SLD, "END_SLD", 2),
    fixed(FUNCTION_END, "FUNCTION_END", 10),
    fixed(BLOCK_START, "BLOCK_START", 10),
    fixed(BLOCK_END, "BLOCK_END", 10),
];

/// FUNCTION fields before the name: u16 section, u32 offset, u16 file,
/// u32 line, u16 frame register, u32 frame size, u16 return register, u32
/// register mask, u32 mask offset.
const FUNCTION_FIELDS: usize = 28;
/// `FUNCTION_START2` adds two u32 fields that PCSX-Redux does not name.
const FUNCTION_START2_FIELDS: usize = FUNCTION_FIELDS + 8;
/// `SECTION_DEF` and `SECTION_DEF2` fields before the dimensions or name: u16
/// section, u32 value, u16 class, u16 type, u32 size.
const DEF_FIELDS: usize = 14;

// Relocation expression operators: PCSX-Redux `PsyqExprOpcode` and psy-k
// `Expression`.
/// A u32 constant.
const EXPR_CONSTANT: u8 = 0;
/// The address of a symbol, by index.
const EXPR_SYMBOL: u8 = 2;
/// `sectbase(n)`.
const EXPR_SECTION_BASE: u8 = 4;
/// `sectstart(n)`.
const EXPR_SECTION_START: u8 = 12;
/// `grouporg(n)` (psy-k only).
const EXPR_GROUP_ORG: u8 = 20;
/// `sectend(n)`.
const EXPR_SECTION_END: u8 = 22;
/// Operands with a u16 symbol, section or group index.
const EXPR_INDEX_OPERANDS: &[u8] = &[
    EXPR_SYMBOL,
    EXPR_SECTION_BASE,
    EXPR_SECTION_START,
    EXPR_GROUP_ORG,
    EXPR_SECTION_END,
];
/// Operands that psy-k decodes but marks untested: `bank`, `sectof`,
/// `offs`, `groupstart`, `groupof` and `seg`.
const EXPR_UNCONFIRMED_OPERANDS: &[u8] = &[6, 8, 10, 14, 16, 18];
/// Binary operators are the even opcodes from `=` (32) to `arshift_chk`
/// (74): comparisons, `+` (44), `-` (46), `*`, `/` (50), bitwise and shift
/// operators, `---` and the Saturn operators. PCSX-Redux decodes only
/// `+`, `-` and `/`; psy-k all of them.
const EXPR_FIRST_BINARY: u8 = 32;
const EXPR_LAST_BINARY: u8 = 74;

// Processor types (psy-k `cputype`, which lists these three as found in
// the wild; its other values are marked speculative).
const PROCESSOR_68000: u8 = 0;
const PROCESSOR_R3000: u8 = 7;
const PROCESSOR_SH2: u8 = 8;

/// A processor type whose meaning the sources establish.
struct Processor {
    id: u8,
    /// Display name, as psy-k describes the value.
    name: &'static str,
    /// The CPU the value names, reported as the code section's variant.
    variant: &'static str,
    target: Target,
}

/// The `PlayStation` R3000 runs little-endian (PCSX-Redux converts type 7
/// objects to little-endian ELF); the 68000 and the SH-2 are big-endian.
const PROCESSORS: &[Processor] = &[
    Processor {
        id: PROCESSOR_68000,
        name: "Motorola 68000",
        variant: "68000",
        target: Target::new(Isa::M68k, 32, Endianness::Big),
    },
    Processor {
        id: PROCESSOR_R3000,
        name: "MIPS R3000 (PlayStation)",
        variant: "R3000",
        target: Target::new(Isa::Mips, 32, Endianness::Little),
    },
    Processor {
        id: PROCESSOR_SH2,
        name: "Hitachi SH-2 (Saturn)",
        variant: "SH-2",
        target: Target::new(Isa::Sh, 32, Endianness::Big),
    },
];

/// A Psy-Q object layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A version 2 LNK object file.
    Object,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Object => FileFormat::PsyqObject,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Object => "PsyQ LNK object",
        }
    }

    /// The signature and version form a four-byte magic, so no layout is
    /// weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Object => false,
        }
    }
}

/// Strong recognition: `LNK`, version 2 and a documented opcode as the
/// first record. The record stream is checked by the parser, so a damaged
/// object is a parse error rather than raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let first = *data.get(HEADER_SIZE)?;
    // The first record's opcode exists, so the version byte before it does.
    let is_object = data.starts_with(SIGNATURE)
        && data[VERSION_OFFSET] == VERSION
        && is_documented_opcode(first);
    is_object.then_some(Layout::Object)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::PsyqParseError`] for a missing signature, an
/// unsupported version, a truncated, unknown or unsupported record, an
/// inconsistent section or PROGRAMTYPE record, or data after the END
/// record.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Object => parse_object(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::PsyqParseError {
        message: message.into(),
    }
}

/// Every opcode either reader names: the even values up to
/// `FUNCTION_START2`.
fn is_documented_opcode(opcode: u8) -> bool {
    opcode % 2 == 0 && opcode <= FUNCTION_START2
}

/// Records whose layout the readers do not confirm: psy-k's untested
/// records, and `INC_SLD_LINENUM_BY_WORD`, whose increment PCSX-Redux
/// reads as 16 bits and psy-k as 32.
fn is_unconfirmed_record(opcode: u8) -> bool {
    opcode == INC_SLD_LINENUM_BY_WORD || UNTESTED_RECORDS.contains(&opcode)
}

fn is_binary_operator(operator: u8) -> bool {
    operator % 2 == 0 && (EXPR_FIRST_BINARY..=EXPR_LAST_BINARY).contains(&operator)
}

fn processor_by_id(id: u8) -> Option<&'static Processor> {
    PROCESSORS.iter().find(|p| p.id == id)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `n` followed by the singular or plural noun, for notes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// A name for notes and labels: printable ASCII kept, other bytes shown as
/// `.`, at most [`NAME_CHARS`] characters with an ellipsis when cut.
fn display_name(name: &[u8]) -> String {
    if name.is_empty() {
        return "(unnamed)".into();
    }
    let mut text: String = name
        .iter()
        .take(NAME_CHARS)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    if name.len() > NAME_CHARS {
        text.push_str("...");
    }
    text
}

/// Header: signature `LNK` (3), version (1).
fn check_header(data: &[u8]) -> Result<()> {
    let Some(&version) = data.get(VERSION_OFFSET) else {
        return Err(error(format!(
            "Truncated LNK header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    };
    if !data.starts_with(SIGNATURE) {
        return Err(error("Missing LNK signature"));
    }
    if version != VERSION {
        return Err(error(format!("Unsupported LNK version {version}")));
    }
    Ok(())
}

/// Reads the body of one record. Errors name the record and its offset.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Record name and file offset of its opcode, for errors.
    name: &'static str,
    start: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let bytes = self
            .pos
            .checked_add(len)
            .and_then(|end| self.data.get(self.pos..end))
            .ok_or_else(|| {
                error(format!(
                    "Truncated {} record at 0x{:X}",
                    self.name, self.start
                ))
            })?;
        self.pos += len;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let field: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .expect("slice has exactly 2 bytes");
        Ok(u16::from_le_bytes(field))
    }

    fn u32(&mut self) -> Result<u32> {
        let field: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .expect("slice has exactly 4 bytes");
        Ok(u32::from_le_bytes(field))
    }

    /// A string: a length byte and that many bytes, not NUL-terminated.
    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u8()?;
        self.bytes(usize::from(len))
    }

    /// One relocation expression. It is written in prefix order, a binary
    /// operator followed by its two operands, so counting the operands
    /// still owed walks it without recursion and within the record's bytes.
    fn skip_expression(&mut self) -> Result<()> {
        let mut owed: usize = 1;
        while owed > 0 {
            let at = self.pos;
            let operator = self.u8()?;
            if operator == EXPR_CONSTANT {
                self.bytes(4)?;
                owed -= 1;
            } else if EXPR_INDEX_OPERANDS.contains(&operator) {
                self.bytes(2)?;
                owed -= 1;
            } else if is_binary_operator(operator) {
                // The operator itself is settled; its two operands are owed.
                owed += 1;
            } else if EXPR_UNCONFIRMED_OPERANDS.contains(&operator) {
                return Err(error(format!(
                    "Unsupported relocation expression operator {operator} at 0x{at:X}: its \
                     layout is not confirmed"
                )));
            } else {
                return Err(error(format!(
                    "Unknown relocation expression operator {operator} at 0x{at:X}"
                )));
            }
        }
        Ok(())
    }
}

/// Which symbol list a record adds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    Exported,
    Imported,
    Local,
    Uninitialized,
    /// A function named by a FUNCTION or `FUNCTION_START2` debug record.
    Function,
}

/// A decoded record, reduced to what the parser reports or checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record<'a> {
    End,
    /// Section contents; `offset` is the file offset of `payload`.
    Bytes {
        offset: usize,
        payload: &'a [u8],
    },
    Switch {
        section: u16,
    },
    /// Zero fill of `size` bytes in the current section.
    Zeroes {
        size: u32,
    },
    Relocation,
    Section {
        id: u16,
        alignment: u8,
        name: &'a [u8],
    },
    Symbol {
        kind: SymbolKind,
        /// Section of an uninitialized symbol, which must be declared.
        section: Option<u16>,
        name: &'a [u8],
    },
    Filename {
        name: &'a [u8],
    },
    ProgramType {
        processor: u8,
    },
    /// Group, debug and definition records, decoded only to reach the next
    /// record.
    Other,
}

fn record_name(opcode: u8) -> &'static str {
    match opcode {
        BYTES => "BYTES",
        SWITCH => "SWITCH",
        ZEROES => "ZEROES",
        RELOCATION => "RELOCATION",
        EXPORTED_SYMBOL => "EXPORTED_SYMBOL",
        IMPORTED_SYMBOL => "IMPORTED_SYMBOL",
        SECTION => "SECTION",
        LOCAL_SYMBOL => "LOCAL_SYMBOL",
        GROUP_SYMBOL => "GROUP_SYMBOL",
        FILENAME => "FILENAME",
        PROGRAMTYPE => "PROGRAMTYPE",
        UNINITIALIZED => "UNINITIALIZED",
        FUNCTION => "FUNCTION",
        SECTION_DEF => "SECTION_DEF",
        SECTION_DEF2 => "SECTION_DEF2",
        FUNCTION_START2 => "FUNCTION_START2",
        opcode => FIXED_RECORDS
            .iter()
            .find(|r| r.opcode == opcode)
            .map_or("record", |r| r.name),
    }
}

/// A record and the file offset of the record after it.
struct Decoded<'a> {
    record: Record<'a>,
    next: usize,
}

/// The record at `at` and the offset of the next one.
///
/// Bodies (after the opcode; u16 and u32 little-endian, strings a length
/// byte and the bytes): BYTES u16 size and the bytes; SWITCH u16 section;
/// ZEROES u32 size; RELOCATION u8 type, u16 offset, expression;
/// `EXPORTED_SYMBOL` u16 symbol, u16 section, u32 offset, name;
/// `IMPORTED_SYMBOL` u16 symbol, name; SECTION u16 section, u16 group, u8
/// alignment, name; `LOCAL_SYMBOL` u16 section, u32 offset, name;
/// `GROUP_SYMBOL` u16 number, u8 type, name (psy-k); FILENAME u16 number,
/// name; PROGRAMTYPE u8 processor; UNINITIALIZED u16 symbol, u16 section,
/// u32 size, name; FUNCTION and `FUNCTION_START2` fields, name; `SECTION_DEF`
/// fields, name; `SECTION_DEF2` fields, u16 dimension count, tag, name.
fn decode(data: &[u8], at: usize) -> Result<Decoded<'_>> {
    let Some(&opcode) = data.get(at) else {
        return Err(error(format!(
            "Truncated record stream: no END record before the end of the file at 0x{at:X}"
        )));
    };
    let mut r = Reader {
        data,
        pos: at + 1,
        name: record_name(opcode),
        start: at,
    };
    let record = match opcode {
        END => Record::End,
        BYTES => {
            let size = r.u16()?;
            let offset = r.pos;
            Record::Bytes {
                offset,
                payload: r.bytes(usize::from(size))?,
            }
        }
        SWITCH => Record::Switch { section: r.u16()? },
        ZEROES => Record::Zeroes { size: r.u32()? },
        RELOCATION => {
            r.bytes(3)?;
            r.skip_expression()?;
            Record::Relocation
        }
        EXPORTED_SYMBOL => {
            r.bytes(8)?;
            symbol(SymbolKind::Exported, None, r.string()?)
        }
        IMPORTED_SYMBOL => {
            r.bytes(2)?;
            symbol(SymbolKind::Imported, None, r.string()?)
        }
        SECTION => {
            let id = r.u16()?;
            r.bytes(2)?;
            let alignment = r.u8()?;
            Record::Section {
                id,
                alignment,
                name: r.string()?,
            }
        }
        LOCAL_SYMBOL => {
            r.bytes(6)?;
            symbol(SymbolKind::Local, None, r.string()?)
        }
        GROUP_SYMBOL => {
            r.bytes(3)?;
            r.string()?;
            Record::Other
        }
        FILENAME => {
            r.bytes(2)?;
            Record::Filename { name: r.string()? }
        }
        PROGRAMTYPE => Record::ProgramType { processor: r.u8()? },
        UNINITIALIZED => {
            r.bytes(2)?;
            let section = r.u16()?;
            r.bytes(4)?;
            symbol(SymbolKind::Uninitialized, Some(section), r.string()?)
        }
        FUNCTION => {
            r.bytes(FUNCTION_FIELDS)?;
            symbol(SymbolKind::Function, None, r.string()?)
        }
        FUNCTION_START2 => {
            r.bytes(FUNCTION_START2_FIELDS)?;
            symbol(SymbolKind::Function, None, r.string()?)
        }
        SECTION_DEF => {
            r.bytes(DEF_FIELDS)?;
            r.string()?;
            Record::Other
        }
        SECTION_DEF2 => {
            r.bytes(DEF_FIELDS)?;
            let dimensions = r.u16()?;
            // PCSX-Redux reads a count and a u16 per dimension, psy-k a tag
            // and a u32; they agree only when there are none.
            if dimensions != 0 {
                return Err(error(format!(
                    "Unsupported SECTION_DEF2 record at 0x{at:X}: {dimensions} dimensions; their \
                     encoding is not confirmed"
                )));
            }
            r.string()?;
            r.string()?;
            Record::Other
        }
        opcode if is_unconfirmed_record(opcode) => {
            return Err(error(format!(
                "Unsupported record {opcode} at 0x{at:X}: its layout is not confirmed"
            )));
        }
        opcode => {
            let Some(body) = FIXED_RECORDS.iter().find(|r| r.opcode == opcode) else {
                return Err(error(format!("Unknown record opcode {opcode} at 0x{at:X}")));
            };
            r.bytes(body.size)?;
            Record::Other
        }
    };
    Ok(Decoded {
        record,
        next: r.pos,
    })
}

fn symbol(kind: SymbolKind, section: Option<u16>, name: &[u8]) -> Record<'_> {
    Record::Symbol {
        kind,
        section,
        name,
    }
}

/// Decode every record from the header to END, passing each to `visit`
/// with its file offset. Returns the offset just after END. Every record
/// consumes at least its opcode byte, so the walk ends within the input.
fn walk<'a>(
    data: &'a [u8],
    mut visit: impl FnMut(usize, Record<'a>) -> Result<()>,
) -> Result<usize> {
    let mut pos = HEADER_SIZE;
    loop {
        let decoded = decode(data, pos)?;
        if decoded.record == Record::End {
            return Ok(decoded.next);
        }
        visit(pos, decoded.record)?;
        pos = decoded.next;
    }
}

/// A count of names, of which the first [`NOTE_NAMES`] are kept.
#[derive(Default)]
struct Names<'a> {
    count: usize,
    listed: Vec<&'a [u8]>,
}

impl<'a> Names<'a> {
    fn push(&mut self, name: &'a [u8]) {
        self.count += 1;
        if self.listed.len() < NOTE_NAMES {
            self.listed.push(name);
        }
    }

    /// `"3 exported symbols: a, b, c"`, or `None` when there are none.
    fn note(&self, singular: &str, plural: &str) -> Option<String> {
        if self.count == 0 {
            return None;
        }
        let names: Vec<String> = self.listed.iter().map(|n| display_name(n)).collect();
        let more = self.count - self.listed.len();
        let rest = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        Some(format!(
            "{}: {}{rest}",
            count(self.count, singular, plural),
            names.join(", ")
        ))
    }
}

/// A declared section and what the records put in it.
struct SectionInfo<'a> {
    id: u16,
    name: &'a [u8],
    /// Non-empty BYTES records.
    runs: usize,
    /// File offset of the first BYTES payload and end of the last one.
    first: usize,
    end: usize,
    /// Bytes in BYTES records.
    size: usize,
    /// Bytes of ZEROES fill, not materialized.
    zero_fill: u64,
}

impl SectionInfo<'_> {
    /// A ZEROES record at `at` adding `size` bytes of zero fill.
    fn add_zero_fill(&mut self, at: usize, size: u32) -> Result<()> {
        let Some(zero_fill) = self.zero_fill.checked_add(u64::from(size)) else {
            return Err(error(format!(
                "Invalid ZEROES record at 0x{at:X}: the zero fill overflows"
            )));
        };
        self.zero_fill = zero_fill;
        Ok(())
    }

    /// A BYTES payload of `len` bytes at file offset `offset`. Empty
    /// payloads add nothing.
    fn add_bytes(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        if self.runs == 0 {
            self.first = offset;
        }
        self.runs += 1;
        self.end = offset + len;
        self.size += len;
    }

    fn is_code(&self) -> bool {
        self.name == TEXT_SECTION
    }

    fn label(&self) -> String {
        format!("{} (section 0x{:04X})", display_name(self.name), self.id)
    }

    /// `".text (36 B; 8 B zero fill)"`, or the bare name when empty.
    fn summary(&self) -> String {
        let name = display_name(self.name);
        match (self.size, self.zero_fill) {
            (0, 0) => name,
            (size, 0) => format!("{name} ({})", size_text(size as u64)),
            (0, fill) => format!("{name} ({} zero fill)", size_text(fill)),
            (size, fill) => format!(
                "{name} ({}; {} zero fill)",
                size_text(size as u64),
                size_text(fill)
            ),
        }
    }
}

/// What the record stream declares, collected in one walk.
#[derive(Default)]
struct Object<'a> {
    processor: Option<u8>,
    /// Sections in declaration order, and their positions by ID.
    sections: Vec<SectionInfo<'a>>,
    index: BTreeMap<u16, usize>,
    /// Section selected by the last SWITCH record; resolved when used, as
    /// PCSX-Redux does.
    current: Option<u16>,
    relocations: usize,
    exported: Names<'a>,
    imported: Names<'a>,
    local: Names<'a>,
    uninitialized: Names<'a>,
    functions: Names<'a>,
    files: Names<'a>,
}

impl<'a> Object<'a> {
    fn add(&mut self, at: usize, record: Record<'a>) -> Result<()> {
        match record {
            Record::Bytes { offset, payload } => {
                let index = self.current_section(at, "BYTES")?;
                self.sections[index].add_bytes(offset, payload.len());
            }
            Record::Switch { section } => self.current = Some(section),
            Record::Zeroes { size } => {
                let index = self.current_section(at, "ZEROES")?;
                self.sections[index].add_zero_fill(at, size)?;
            }
            Record::Relocation => {
                self.current_section(at, "RELOCATION")?;
                self.relocations += 1;
            }
            Record::Section {
                id,
                alignment,
                name,
            } => self.declare(at, id, alignment, name)?,
            Record::Symbol {
                kind,
                section,
                name,
            } => {
                if let Some(section) = section.filter(|s| !self.index.contains_key(s)) {
                    return Err(error(format!(
                        "Unknown section 0x{section:04X} in the UNINITIALIZED record at 0x{at:X}"
                    )));
                }
                self.names(kind).push(name);
            }
            Record::Filename { name } => self.files.push(name),
            Record::ProgramType { processor } => {
                if self.processor.is_some() {
                    return Err(error(format!("Duplicate PROGRAMTYPE record at 0x{at:X}")));
                }
                self.processor = Some(processor);
            }
            Record::End | Record::Other => {}
        }
        Ok(())
    }

    /// The section the last SWITCH record selected, for the `record` at
    /// `at`.
    fn current_section(&self, at: usize, record: &str) -> Result<usize> {
        let Some(id) = self.current else {
            return Err(error(format!(
                "Missing SWITCH record before the {record} record at 0x{at:X}"
            )));
        };
        self.index.get(&id).copied().ok_or_else(|| {
            error(format!(
                "Unknown section 0x{id:04X} selected for the {record} record at 0x{at:X}"
            ))
        })
    }

    /// A SECTION record. PCSX-Redux rejects an alignment that is not a
    /// power of two; zero passes its test.
    fn declare(&mut self, at: usize, id: u16, alignment: u8, name: &'a [u8]) -> Result<()> {
        if alignment & alignment.wrapping_sub(1) != 0 {
            return Err(error(format!(
                "Invalid SECTION record at 0x{at:X}: alignment {alignment} is not a power of two"
            )));
        }
        if self.index.contains_key(&id) {
            return Err(error(format!(
                "Duplicate section 0x{id:04X} in the SECTION record at 0x{at:X}"
            )));
        }
        self.index.insert(id, self.sections.len());
        self.sections.push(SectionInfo {
            id,
            name,
            runs: 0,
            first: 0,
            end: 0,
            size: 0,
            zero_fill: 0,
        });
        Ok(())
    }

    fn names(&mut self, kind: SymbolKind) -> &mut Names<'a> {
        match kind {
            SymbolKind::Exported => &mut self.exported,
            SymbolKind::Imported => &mut self.imported,
            SymbolKind::Local => &mut self.local,
            SymbolKind::Uninitialized => &mut self.uninitialized,
            SymbolKind::Function => &mut self.functions,
        }
    }
}

fn parse_object(data: &[u8]) -> Result<Container<'_>> {
    check_header(data)?;
    let mut object = Object::default();
    let end = walk(data, |at, record| object.add(at, record))?;
    // `end` follows the END opcode, so it is at most the file size.
    let trailing = &data[end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the END record at 0x{:X}",
            size_text(trailing.len() as u64),
            end - 1
        )));
    }
    let processor = object.processor.and_then(processor_by_id);
    let mut c = Container::new(FileFormat::PsyqObject, Layout::Object.label(), KEY_PREFIX);
    c.consumed = end;
    c.target = processor.map(|p| p.target);
    c.notes.push(processor_note(object.processor, processor));
    push_section_notes(&mut c, &object);
    push_symbol_notes(&mut c, &object);
    push_metadata(&mut c, &object);
    push_children(&mut c, data, &object, processor)?;
    if !trailing.is_empty() {
        c.notes.push(format!(
            "{} of padding after the END record",
            size_text(trailing.len() as u64)
        ));
    }
    Ok(c)
}

fn processor_note(id: Option<u8>, processor: Option<&Processor>) -> String {
    match (id, processor) {
        (Some(id), Some(p)) => {
            format!(
                "LNK version {VERSION} object; processor type {id}: {}",
                p.name
            )
        }
        (Some(id), None) => format!(
            "LNK version {VERSION} object; processor type {id} is not documented, so the ISA is \
             not encoded"
        ),
        (None, _) => format!(
            "LNK version {VERSION} object; no PROGRAMTYPE record, so the processor is not encoded"
        ),
    }
}

fn push_section_notes(c: &mut Container<'_>, object: &Object<'_>) {
    if object.sections.is_empty() {
        c.notes.push("No sections are declared".into());
        return;
    }
    let listed: Vec<String> = object
        .sections
        .iter()
        .take(NOTE_NAMES)
        .map(SectionInfo::summary)
        .collect();
    let more = object.sections.len() - listed.len();
    let rest = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    c.notes.push(format!(
        "{}: {}{rest}",
        count(object.sections.len(), "section", "sections"),
        listed.join(", ")
    ));
    c.notes.push(format!(
        "Section contents are the BYTES records as stored; {} not applied and zero fill is not \
         materialized",
        count(object.relocations, "relocation is", "relocations are")
    ));
    if !object.sections.iter().any(|s| s.is_code() && s.runs > 0) {
        c.notes
            .push("No code: no .text section holds BYTES records".into());
    }
}

fn push_symbol_notes(c: &mut Container<'_>, object: &Object<'_>) {
    let notes = [
        object.exported.note("exported symbol", "exported symbols"),
        object.imported.note("imported symbol", "imported symbols"),
        object.local.note("local symbol", "local symbols"),
        object
            .uninitialized
            .note("uninitialized symbol", "uninitialized symbols"),
        object
            .functions
            .note("function in debug records", "functions in debug records"),
        object.files.note("source file", "source files"),
    ];
    c.notes.extend(notes.into_iter().flatten());
}

fn push_metadata(c: &mut Container<'_>, object: &Object<'_>) {
    c.push_metadata("psyq_version", "LNK version", u64::from(VERSION));
    if let Some(id) = object.processor {
        c.push_metadata("psyq_processor_type", "Processor type", u64::from(id));
    }
    let counts = [
        ("psyq_sections", "Declared sections", object.sections.len()),
        ("psyq_relocations", "Relocations", object.relocations),
        (
            "psyq_exported_symbols",
            "Exported symbols",
            object.exported.count,
        ),
        (
            "psyq_imported_symbols",
            "Imported symbols",
            object.imported.count,
        ),
    ];
    for (key, label, value) in counts {
        c.push_metadata(key, label, value as u64);
    }
}

/// How a listed section's bytes are produced.
enum Contents<'a> {
    /// One BYTES record: its payload as stored.
    Stored(&'a [u8]),
    /// Several BYTES records, concatenated in a second walk.
    Assembled,
    /// Over the extraction limits; listed in a note only.
    Skipped,
}

/// One child per section with BYTES records, in declaration order: `.text`
/// as code under the processor's target, every other section opaque.
fn push_children<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    object: &Object<'a>,
    processor: Option<&Processor>,
) -> Result<()> {
    let with_bytes: Vec<&SectionInfo<'a>> = object.sections.iter().filter(|s| s.runs > 0).collect();
    if with_bytes.len() > MAX_COMPONENTS {
        c.notes.push(format!(
            "{} with BYTES records not listed (limit {MAX_COMPONENTS})",
            count(
                with_bytes.len() - MAX_COMPONENTS,
                "further section",
                "further sections"
            )
        ));
    }
    let listed = &with_bytes[..with_bytes.len().min(MAX_COMPONENTS)];
    let mut extracted = 0usize;
    let contents: Vec<Contents<'a>> = listed
        .iter()
        .map(|s| {
            if s.runs == 1 {
                // `first..end` is the payload of one decoded BYTES record.
                return Contents::Stored(&data[s.first..s.end]);
            }
            // Both terms are at most MAX_EXTRACTED once the first test
            // passes, so the sum cannot overflow.
            if s.size > MAX_PAYLOAD || extracted + s.size > MAX_EXTRACTED {
                return Contents::Skipped;
            }
            extracted += s.size;
            Contents::Assembled
        })
        .collect();
    let assembled = assemble(data, listed, &contents)?;
    for ((section, contents), bytes) in listed.iter().zip(contents).zip(assembled) {
        let label = section.label();
        let child = match (contents, bytes) {
            (Contents::Stored(payload), _) => Child::stored(label, section.first, payload),
            (Contents::Assembled, Some(bytes)) => Child::decoded(
                label,
                section.first,
                section.end - section.first,
                Cow::Owned(bytes),
                RECORDS_TRANSFORM,
            ),
            (Contents::Assembled | Contents::Skipped, _) => {
                c.notes.push(format!(
                    "{label}: {} in {} BYTES records not extracted (limits {} per section, {} \
                     per object)",
                    size_text(section.size as u64),
                    section.runs,
                    size_text(MAX_PAYLOAD as u64),
                    size_text(MAX_EXTRACTED as u64)
                ));
                continue;
            }
        };
        c.children.push(classified(child, section, processor));
    }
    Ok(())
}

/// The concatenated BYTES payloads of each listed section marked
/// [`Contents::Assembled`], from a second walk of the validated records.
fn assemble(
    data: &[u8],
    listed: &[&SectionInfo<'_>],
    contents: &[Contents<'_>],
) -> Result<Vec<Option<Vec<u8>>>> {
    let mut buffers: Vec<Option<Vec<u8>>> = listed
        .iter()
        .zip(contents)
        .map(|(s, contents)| {
            matches!(contents, Contents::Assembled).then(|| Vec::with_capacity(s.size))
        })
        .collect();
    if buffers.iter().all(Option::is_none) {
        return Ok(buffers);
    }
    let slots: BTreeMap<u16, usize> = listed
        .iter()
        .enumerate()
        .map(|(slot, s)| (s.id, slot))
        .collect();
    let mut current = None;
    walk(data, |_, record| {
        match record {
            Record::Switch { section } => current = Some(section),
            Record::Bytes { payload, .. } => {
                let slot = current.and_then(|id| slots.get(&id).copied());
                if let Some(buffer) = slot.and_then(|slot| buffers[slot].as_mut()) {
                    buffer.extend_from_slice(payload);
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(buffers)
}

/// `.text` is code for the processor's target; every other section is
/// data and opaque.
fn classified<'a>(
    child: Child<'a>,
    section: &SectionInfo<'_>,
    processor: Option<&Processor>,
) -> Child<'a> {
    if !section.is_code() {
        return Child {
            opaque: true,
            ..child
        };
    }
    let code = child.as_code();
    match processor {
        Some(p) => code.with_target(p.target).with_variant(p.variant),
        None => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader over `body`, as if it followed an opcode at offset 0.
    fn reader(body: &[u8]) -> Reader<'_> {
        Reader {
            data: body,
            pos: 0,
            name: "RELOCATION",
            start: 0,
        }
    }

    #[test]
    fn expressions_are_skipped_in_prefix_order() {
        // (sectbase(0x68AE) + 0x28): `+`, sectbase, constant.
        let body = [44, 4, 0xae, 0x68, 0, 0x28, 0, 0, 0, 0xff];
        let mut r = reader(&body);
        r.skip_expression().expect("valid expression");
        assert_eq!(r.pos, 9);
        // ((a - b) / 4) with psy-k's Saturn operator around it.
        let body = [74, 50, 46, 2, 1, 0, 22, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut r = reader(&body);
        r.skip_expression().expect("valid expression");
        assert_eq!(r.pos, body.len());
    }

    #[test]
    fn expressions_reject_truncation_and_unconfirmed_operators() {
        let body = [44, 4, 0xae, 0x68];
        assert_eq!(
            reader(&body).skip_expression().unwrap_err().to_string(),
            "PsyQ object parse error: Truncated RELOCATION record at 0x0"
        );
        let unconfirmed = reader(&[44, 6, 0, 0, 0, 0, 0, 0, 0])
            .skip_expression()
            .unwrap_err();
        assert!(unconfirmed.to_string().contains("operator 6 at 0x1"));
        let unknown = reader(&[45]).skip_expression().unwrap_err();
        assert!(unknown
            .to_string()
            .contains("Unknown relocation expression operator 45"));
    }

    #[test]
    fn deep_expressions_are_bounded_by_their_bytes() {
        let mut body = vec![44u8; 100_000];
        body.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert!(reader(&body).skip_expression().is_err());
    }

    #[test]
    fn only_established_processor_types_name_an_isa() {
        assert_eq!(
            processor_by_id(PROCESSOR_R3000).map(|p| p.target.isa),
            Some(Isa::Mips)
        );
        assert_eq!(
            processor_by_id(PROCESSOR_R3000).and_then(|p| p.target.endianness),
            Some(Endianness::Little)
        );
        assert_eq!(
            processor_by_id(PROCESSOR_SH2).map(|p| p.target.isa),
            Some(Isa::Sh)
        );
        assert_eq!(
            processor_by_id(PROCESSOR_68000).map(|p| p.target.isa),
            Some(Isa::M68k)
        );
        for id in [1, 2, 3, 4, 5, 6, 9, 0x43, 0xff] {
            assert!(processor_by_id(id).is_none(), "processor type {id}");
        }
    }

    #[test]
    fn documented_opcodes_are_even_and_bounded() {
        assert!(is_documented_opcode(END));
        assert!(is_documented_opcode(PROGRAMTYPE));
        assert!(is_documented_opcode(FUNCTION_START2));
        assert!(!is_documented_opcode(3));
        assert!(!is_documented_opcode(88));
        for record in FIXED_RECORDS {
            assert_eq!(record_name(record.opcode), record.name);
            assert!(!is_unconfirmed_record(record.opcode));
        }
    }

    #[test]
    fn names_are_printable_and_bounded() {
        assert_eq!(display_name(b".text"), ".text");
        assert_eq!(display_name(b"a\x00b\xff"), "a.b.");
        assert_eq!(display_name(b""), "(unnamed)");
        let long = display_name(&[b'x'; 200]);
        assert_eq!(long.len(), NAME_CHARS + 3);
        let mut names = Names::default();
        for _ in 0..20 {
            names.push(b"sym");
        }
        assert_eq!(names.listed.len(), NOTE_NAMES);
        let note = names.note("symbol", "symbols").expect("note");
        assert!(note.starts_with("20 symbols: sym, sym"), "{note}");
        assert!(note.ends_with(" and 12 more"), "{note}");
    }

    #[test]
    fn sizes_use_exact_binary_units() {
        assert_eq!(size_text(36), "36 B");
        assert_eq!(size_text(2048), "2 KiB");
        assert_eq!(size_text(64 << 20), "64 MiB");
        assert_eq!(size_text(402_907_136), "393464 KiB");
    }
}
