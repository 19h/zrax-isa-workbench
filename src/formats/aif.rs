//! ARM Image Format (AIF): the executable image format of the ARM Software
//! Development Toolkit (`armlink -aif`, `.axf`/`.aif` files) and of RISC OS
//! applications (`!RunImage`), in its executable, non-executable and
//! extended variants, uncompressed, compressed or self-relocating.
//!
//! Sources (retrieval details and checksums in `docs/aif.md`):
//! - ARM DUI 0041C, *ARM Software Development Toolkit Version 2.50
//!   Reference Guide* (November 1998), chapter 13 "ARM Image Format":
//!   section 13.1 (overview), 13.2 (executable, non-executable and extended
//!   AIF), 13.3.1 (image layout) and Table 13-1 (the 128-byte header and the
//!   44-byte extended AIF region header); section 12.8 (`SWI_Exit` is SWI
//!   0x11).
//! - ARM Ltd, "ARM Image Format" (the SDT-era text that DUI 0041C chapter 13
//!   condenses): the compressed layout, `BL DecompressCode` at 0x0, the
//!   debug initialization instruction at 0x40, the self-relocation code.
//! - Acorn Computers, technical memorandum PLG-AIF issue 1.00, "RISC OS
//!   Application Image Format" (January 1989), and the RISC OS
//!   Programmer's Reference Manual volume 4, appendix D: `BLNV 0` as the
//!   header NOP and the linker symbol relationships.
//!
//! "ARM Image Format (AIF) is a simple format for ARM executable images"
//! (DUI 0041C section 13.1), and the header itself is ARM code that an
//! executable image is entered at. The format is therefore the image's
//! target field: ARM, 32-bit. Every header word is in the target byte order
//! (section 13.2: "The most significant byte of this word (in the target
//! byte order) is 0xeb"), so the header's byte order is the code's. Offsets
//! are file offsets and sizes are bytes; addresses are target byte
//! addresses.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Section, Target, MAX_COMPONENTS};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa, MetadataValue};
use std::borrow::Cow;
use std::collections::BTreeSet;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "aif";

/// "a 128-byte header" (section 13.1); "Header is 32 words long".
const HEADER_SIZE: usize = 0x80;
/// Every header field is a 32-bit word.
const WORD: usize = 4;
const HEADER_WORDS: usize = HEADER_SIZE / WORD;

// Header fields (Table 13-1).
/// `BL DecompressCode`, NOP if the image is not compressed.
const DECOMPRESS_CODE: usize = 0x00;
/// `BL SelfRelocCode`, NOP if the image is not self-relocating.
const SELF_RELOC_CODE: usize = 0x04;
/// `BL ZeroInit` (or `BL DBGInit`), NOP if the image has none.
const ZERO_INIT_CODE: usize = 0x08;
/// `BL ImageEntryPoint` (executable) or the entry point offset.
const IMAGE_ENTRY_POINT: usize = 0x0C;
/// The program exit instruction.
const PROGRAM_EXIT: usize = 0x10;
const READ_ONLY_SIZE: usize = 0x14;
const READ_WRITE_SIZE: usize = 0x18;
const DEBUG_SIZE: usize = 0x1C;
const ZERO_INIT_SIZE: usize = 0x20;
const DEBUG_TYPE: usize = 0x24;
const IMAGE_BASE: usize = 0x28;
const WORK_SPACE: usize = 0x2C;
const ADDRESS_MODE: usize = 0x30;
const DATA_BASE: usize = 0x34;
/// The first reserved word; in extended AIF the file offset of the first
/// non-root load region header.
const FIRST_REGION: usize = 0x38;
/// The second reserved word.
const RESERVED: usize = 0x3C;

/// `MOV r0, r0`, the NOP of the SDT documents (Table 13-1 note a).
const NOP: u32 = 0xE1A0_0000;
/// `BLNV 0`, the NOP of the 1989 memo and the RISC OS PRM, which the
/// decompression and self-relocation code also write back into the header.
const BLNV_0: u32 = 0xFB00_0000;
/// The most significant byte of `BL` with the AL condition (section 13.2).
const BL_OPCODE: u32 = 0xEB00_0000;
const OPCODE_MASK: u32 = 0xFF00_0000;
/// The signed 24-bit word offset of a branch.
const BRANCH_OFFSET_MASK: u32 = 0x00FF_FFFF;
const BRANCH_OFFSET_SIGN: i64 = 0x0080_0000;
const BRANCH_OFFSET_RANGE: i64 = 0x0100_0000;
/// A branch offset counts words.
const BRANCH_OFFSET_SCALE: i64 = 4;
/// A branch is relative to its own address plus 8 (the PC reads two
/// instructions ahead).
const BRANCH_PC_AHEAD: i64 = 8;
/// "The most significant nibble of this word (in the target byte order) is
/// 0x0" for a non-executable image's entry offset.
const ENTRY_OFFSET_LIMIT: u32 = 0x1000_0000;

/// `SWI 0x11`, the exit instruction armlink writes by default (Table 13-1;
/// `SWI_Exit` in section 12.8, `OS_Exit` on RISC OS).
const SWI_EXIT: u32 = 0xEF00_0011;
/// `B .`, the branch-to-self Table 13-1 recommends on systems without an
/// exit SWI.
const BRANCH_TO_SELF: u32 = 0xEAFF_FFFE;

/// Bits 0-3 of the debug type word hold the type (Table 13-1).
const DEBUG_TYPE_MASK: u32 = 0xF;
const DEBUG_LOW_LEVEL: u32 = 1;
const DEBUG_SOURCE_LEVEL: u32 = 2;
/// "All other values of image debug type are reserved."
const DEBUG_TYPE_MAX: u32 = DEBUG_LOW_LEVEL | DEBUG_SOURCE_LEVEL;

/// The address mode word: 0, or 26 or 32 in its least significant byte.
const ADDRESS_MODE_WIDTH_MASK: u32 = 0xFF;
const ADDRESS_MODE_26: u32 = 26;
const ADDRESS_MODE_32: u32 = 32;
/// "If the Address mode word has bit 8 set, the image was linked with
/// separate code and data bases."
const SEPARATE_DATA_BASE: u32 = 0x100;
/// Flag bits other than bit 8 (not defined by the sources).
const ADDRESS_MODE_FLAGS_MASK: u32 = 0xFFFF_FF00;

/// The extended AIF region header: next region offset (0 is none), load
/// address, size and a 32-byte name, followed by the region's data.
const REGION_HEADER_SIZE: usize = 44;
const REGION_NEXT: usize = 0;
const REGION_LOAD_ADDRESS: usize = 4;
const REGION_SIZE: usize = 8;
const REGION_NAME: usize = 12;

/// An AIF variant (DUI 0041C section 13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Executable AIF: the header is part of the image, the fourth word is
    /// `BL ImageEntryPoint`, and the image is loaded and entered at the
    /// header.
    Executable,
    /// Non-executable AIF: a loader interprets the header, which is not part
    /// of the image; the fourth word is the entry point offset and the code
    /// at file offset 0x80 is loaded at the image base.
    NonExecutable,
    /// Extended AIF: a non-executable, scatter-loaded image whose word at
    /// 0x38 chains further load regions.
    Extended,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::ArmAif
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Executable => "Executable AIF",
            Self::NonExecutable => "Non-executable AIF",
            Self::Extended => "Extended AIF",
        }
    }

    /// Every variant carries the fixed header instructions, so none is weak.
    pub fn is_weak(self) -> bool {
        false
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AifParseError {
        message: message.into(),
    }
}

/// Strong recognition: a complete 128-byte header whose program exit
/// instruction is `SWI 0x11` or a branch to itself in either byte order,
/// whose first three words are NOP or BL, whose fourth word is a BL or an
/// entry offset, whose debug type and address mode are documented values,
/// and, for executable AIF, whose read-only size includes the header. The
/// area sizes against the file are checked by the parser, so a damaged
/// image is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    Header::read(data)?.layout().ok()
}

/// The header words, in the byte order of the program exit instruction.
struct Header {
    big_endian: bool,
    words: [u32; HEADER_WORDS],
}

impl Header {
    /// The header when `data` holds 128 bytes and an exit instruction.
    fn read(data: &[u8]) -> Option<Self> {
        let bytes = data.get(..HEADER_SIZE)?;
        let le = if is_exit_instruction(word_at(bytes, PROGRAM_EXIT, true)) {
            true
        } else if is_exit_instruction(word_at(bytes, PROGRAM_EXIT, false)) {
            false
        } else {
            return None;
        };
        let mut words = [0u32; HEADER_WORDS];
        for (i, word) in words.iter_mut().enumerate() {
            *word = word_at(bytes, i * WORD, le);
        }
        Some(Self {
            big_endian: !le,
            words,
        })
    }

    /// The word at header offset `at`, a field constant below 0x80.
    fn word(&self, at: usize) -> u32 {
        self.words[at / WORD]
    }

    fn endianness(&self) -> Endianness {
        if self.big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        }
    }

    fn read_only_size(&self) -> u32 {
        self.word(READ_ONLY_SIZE)
    }

    fn read_write_size(&self) -> u32 {
        self.word(READ_WRITE_SIZE)
    }

    fn debug_size(&self) -> u32 {
        self.word(DEBUG_SIZE)
    }

    fn zero_init_size(&self) -> u32 {
        self.word(ZERO_INIT_SIZE)
    }

    /// Bits 0-3 of the debug type word.
    fn debug_type(&self) -> u32 {
        self.word(DEBUG_TYPE) & DEBUG_TYPE_MASK
    }

    fn image_base(&self) -> u32 {
        self.word(IMAGE_BASE)
    }

    fn address_mode(&self) -> u32 {
        self.word(ADDRESS_MODE)
    }

    fn has_separate_data_base(&self) -> bool {
        self.address_mode() & SEPARATE_DATA_BASE != 0
    }

    /// Word 0 is `BL DecompressCode`.
    fn is_compressed(&self) -> bool {
        is_bl(self.word(DECOMPRESS_CODE))
    }

    /// Word 1 is `BL SelfRelocCode`.
    fn is_self_relocating(&self) -> bool {
        is_bl(self.word(SELF_RELOC_CODE))
    }

    /// The variant the header describes, or why it is not an AIF header.
    fn layout(&self) -> Result<Layout> {
        for at in [DECOMPRESS_CODE, SELF_RELOC_CODE, ZERO_INIT_CODE] {
            let word = self.word(at);
            if !(word == NOP || word == BLNV_0 || is_bl(word)) {
                return Err(error(format!(
                    "Invalid AIF header word at 0x{at:X}: 0x{word:08X} is neither NOP nor BL"
                )));
            }
        }
        let entry = self.word(IMAGE_ENTRY_POINT);
        let layout = if is_bl(entry) {
            Layout::Executable
        } else if entry < ENTRY_OFFSET_LIMIT {
            if self.word(FIRST_REGION) == 0 {
                Layout::NonExecutable
            } else {
                Layout::Extended
            }
        } else {
            return Err(error(format!(
                "Invalid AIF entry word at 0x{IMAGE_ENTRY_POINT:X}: 0x{entry:08X} is neither BL \
                 nor an entry offset"
            )));
        };
        if self.debug_type() > DEBUG_TYPE_MAX {
            return Err(error(format!(
                "Invalid AIF debug type 0x{:X}",
                self.word(DEBUG_TYPE)
            )));
        }
        if !is_address_mode(self.address_mode()) {
            return Err(error(format!(
                "Invalid AIF address mode 0x{:08X}",
                self.address_mode()
            )));
        }
        if layout == Layout::Executable && to_usize(self.read_only_size()) < HEADER_SIZE {
            return Err(error(format!(
                "Invalid AIF read-only size {} B: an executable image includes the {HEADER_SIZE} \
                 B header",
                self.read_only_size()
            )));
        }
        Ok(layout)
    }

    /// Read-write, debug and zero-init sizes are "Exact size (a multiple of
    /// 4 bytes)".
    fn check_sizes(&self) -> Result<()> {
        let sizes = [
            ("read-write", READ_WRITE_SIZE),
            ("debug", DEBUG_SIZE),
            ("zero-init", ZERO_INIT_SIZE),
        ];
        for (what, at) in sizes {
            let size = self.word(at);
            if to_usize(size) % WORD != 0 {
                return Err(error(format!(
                    "Invalid AIF {what} size 0x{size:X} at 0x{at:X}: not a multiple of 4"
                )));
            }
        }
        Ok(())
    }

    /// The entry point as an offset from the image base: the target of the
    /// BL at 0xC for executable AIF, the word itself otherwise.
    fn entry_offset(&self, layout: Layout) -> Result<u64> {
        let entry = self.word(IMAGE_ENTRY_POINT);
        if layout != Layout::Executable {
            return Ok(u64::from(entry));
        }
        branch_target(IMAGE_ENTRY_POINT, entry)
            .map(|target| target as u64)
            .ok_or_else(|| {
                error(format!(
                    "Invalid AIF entry point: BL 0x{entry:08X} at 0x{IMAGE_ENTRY_POINT:X} \
                     branches before the image"
                ))
            })
    }
}

/// The word at `at` of a slice whose length was checked by the caller.
fn word_at(bytes: &[u8], at: usize, le: bool) -> u32 {
    let field = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    if le {
        u32::from_le_bytes(field)
    } else {
        u32::from_be_bytes(field)
    }
}

fn is_exit_instruction(word: u32) -> bool {
    word == SWI_EXIT || word == BRANCH_TO_SELF
}

fn is_bl(word: u32) -> bool {
    word & OPCODE_MASK == BL_OPCODE
}

/// 0, or 26 or 32 in the least significant byte with any flag bits.
fn is_address_mode(word: u32) -> bool {
    match word & ADDRESS_MODE_WIDTH_MASK {
        0 => word == 0,
        ADDRESS_MODE_26 | ADDRESS_MODE_32 => true,
        _ => false,
    }
}

/// The offset a branch at offset `at` goes to, or `None` when it would lie
/// before offset 0.
fn branch_target(at: usize, instruction: u32) -> Option<usize> {
    let raw = i64::from(instruction & BRANCH_OFFSET_MASK);
    let words = if raw & BRANCH_OFFSET_SIGN != 0 {
        raw - BRANCH_OFFSET_RANGE
    } else {
        raw
    };
    let target = i64::try_from(at).ok()? + BRANCH_PC_AHEAD + words * BRANCH_OFFSET_SCALE;
    usize::try_from(target).ok()
}

/// A header size as a byte count; saturates on targets whose `usize` is
/// narrower than 32 bits, which then fails every bounds check.
fn to_usize(size: u32) -> usize {
    usize::try_from(size).unwrap_or(usize::MAX)
}

/// The `len` bytes of `what` at `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} ({len} B)")))
}

/// Why `data` has no AIF header.
fn missing_header(data: &[u8]) -> ClassifierError {
    if data.len() < HEADER_SIZE {
        error(format!("Truncated AIF header at 0x0 ({HEADER_SIZE} B)"))
    } else {
        error(format!(
            "Missing AIF program exit instruction at 0x{PROGRAM_EXIT:X} (SWI 0x11 or a branch \
             to itself)"
        ))
    }
}

/// Stored bytes at a file offset.
struct Area<'a> {
    offset: usize,
    bytes: &'a [u8],
}

impl Area<'_> {
    fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }
}

/// The areas of an uncompressed image, in file order.
struct Image<'a> {
    read_only: Area<'a>,
    read_write: Area<'a>,
    /// The debugging data, which follows the read-write area; not located
    /// in extended AIF, where the sources do not place it.
    debug: Option<Area<'a>>,
}

impl<'a> Image<'a> {
    /// The read-only area starts at the header for executable AIF (its size
    /// includes the header) and after it otherwise; the read-write area and
    /// the debugging data follow.
    fn locate(data: &'a [u8], header: &Header, layout: Layout) -> Result<Self> {
        let start = if layout == Layout::Executable {
            0
        } else {
            HEADER_SIZE
        };
        let read_only = area(data, start, header.read_only_size(), "AIF read-only area")?;
        let read_write = area(
            data,
            read_only.end(),
            header.read_write_size(),
            "AIF read-write area",
        )?;
        let debug = if layout == Layout::Extended {
            None
        } else {
            Some(area(
                data,
                read_write.end(),
                header.debug_size(),
                "AIF debugging data",
            )?)
        };
        Ok(Self {
            read_only,
            read_write,
            debug,
        })
    }
}

fn area<'a>(data: &'a [u8], offset: usize, size: u32, what: &str) -> Result<Area<'a>> {
    let bytes = slice(data, offset, to_usize(size), what)?;
    Ok(Area { offset, bytes })
}

/// Parse `data` as the given AIF variant.
///
/// # Errors
///
/// [`ClassifierError::AifParseError`] when the header is missing, is not
/// the given variant or holds undocumented values, when a size is not a
/// multiple of 4, when an area, a branch target or an extended AIF region
/// lies outside the file, or when bytes other than padding follow the image.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = Header::read(data).ok_or_else(|| missing_header(data))?;
    let found = header.layout()?;
    if found != layout {
        return Err(error(format!(
            "Invalid AIF variant: the header describes {}, not {}",
            found.label(),
            layout.label()
        )));
    }
    header.check_sizes()?;
    let entry_offset = header.entry_offset(layout)?;

    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.target = Some(Target::new(Isa::Arm, 32, header.endianness()));
    c.code_sections = true;
    c.entry = Some(u64::from(header.image_base()) + entry_offset);
    push_header_notes(&mut c, &header, layout, entry_offset);
    if header.is_compressed() {
        load_compressed(&mut c, data, &header, layout)?;
    } else {
        load_image(&mut c, data, &header, layout, entry_offset)?;
    }
    push_metadata(&mut c, &header, entry_offset);
    Ok(c)
}

/// The areas of an uncompressed image, the extended AIF regions and what
/// follows them.
fn load_image<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    layout: Layout,
    entry_offset: u64,
) -> Result<()> {
    let image = Image::locate(data, header, layout)?;
    let read_write_address = if header.has_separate_data_base() {
        u64::from(header.word(DATA_BASE))
    } else {
        u64::from(header.image_base()) + u64::from(header.read_only_size())
    };
    push_area(
        c,
        "Read-only area",
        u64::from(header.image_base()),
        &image.read_only,
    );
    push_area(c, "Read-write area", read_write_address, &image.read_write);
    push_image_notes(c, header, layout, &image, entry_offset);
    let Some(debug) = image.debug else {
        return load_extended(c, data, header, image.read_write.end());
    };
    if !debug.bytes.is_empty() {
        c.children
            .push(Child::opaque("Debugging data", debug.offset, debug.bytes));
    }
    c.consumed = debug.end();
    load_trailer(c, data, header, layout)
}

/// The load regions of an extended image after its root image, then the
/// trailing bytes. With debugging data, whose place the sources do not
/// give, the bytes after the regions are not checked.
fn load_extended<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    root_end: usize,
) -> Result<()> {
    let Some(regions_end) = load_regions(c, data, header, root_end)? else {
        // The chain was cut at the component limit, so the end of the image
        // is not known.
        c.consumed = data.len();
        return Ok(());
    };
    c.consumed = regions_end;
    if header.debug_size() != 0 {
        c.notes.push(format!(
            "The {} B of debugging data are not located: the sources do not place them in \
             extended AIF; the {} B after the load regions are not checked",
            header.debug_size(),
            data.len() - regions_end
        ));
        c.consumed = data.len();
        return Ok(());
    }
    load_trailer(c, data, header, Layout::Extended)
}

/// Append a load section, unless the loaded areas would exceed
/// [`MAX_PAYLOAD`]; empty areas are skipped.
fn push_area<'a>(c: &mut Container<'a>, label: &str, address: u64, area: &Area<'a>) {
    if area.bytes.is_empty() {
        return;
    }
    let loaded: usize = c.sections.iter().map(|s| s.stored_size).sum();
    if loaded.saturating_add(area.bytes.len()) > MAX_PAYLOAD {
        c.notes.push(format!(
            "{label} ({} B at 0x{:X}) is not analyzed: the loaded areas would exceed the {} MiB \
             payload limit",
            area.bytes.len(),
            area.offset,
            MAX_PAYLOAD >> 20
        ));
        return;
    }
    c.sections.push(Section {
        label: label.to_string(),
        address,
        offset: area.offset,
        stored_size: area.bytes.len(),
        data: Cow::Borrowed(area.bytes),
        transform: None,
    });
}

/// The chain of extended AIF load regions that the word at 0x38 starts:
/// each a 44-byte header (next region offset, load address, size, name)
/// followed by its data. Returns the end of the last region, or `None` when
/// the chain was cut at [`MAX_COMPONENTS`] regions.
fn load_regions<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    root_end: usize,
) -> Result<Option<usize>> {
    let le = !header.big_endian;
    let mut next = to_usize(header.word(FIRST_REGION));
    let mut visited = BTreeSet::new();
    let mut end = root_end;
    while next != 0 {
        if visited.len() >= MAX_COMPONENTS {
            c.notes.push(format!(
                "Further extended AIF load regions after region {} were not listed (limit \
                 {MAX_COMPONENTS})",
                visited.len()
            ));
            return Ok(None);
        }
        if !visited.insert(next) {
            return Err(error(format!(
                "Invalid extended AIF region chain: the region header at 0x{next:X} is linked \
                 twice"
            )));
        }
        if next < root_end {
            return Err(error(format!(
                "Invalid extended AIF region header offset 0x{next:X}: inside the root image, \
                 which ends at 0x{root_end:X}"
            )));
        }
        let region = slice(data, next, REGION_HEADER_SIZE, "extended AIF region header")?;
        let size = word_at(region, REGION_SIZE, le);
        if to_usize(size) % WORD != 0 {
            return Err(error(format!(
                "Invalid extended AIF region size 0x{size:X} at 0x{:X}: not a multiple of 4",
                next + REGION_SIZE
            )));
        }
        let contents = area(data, next + REGION_HEADER_SIZE, size, "extended AIF region")?;
        let name = region_name(&region[REGION_NAME..REGION_HEADER_SIZE]);
        let label = if name.is_empty() {
            format!("Load region {}", visited.len())
        } else {
            format!("Load region {} ({name})", visited.len())
        };
        let address = u64::from(word_at(region, REGION_LOAD_ADDRESS, le));
        push_area(c, &label, address, &contents);
        end = end.max(contents.end());
        next = to_usize(word_at(region, REGION_NEXT, le));
    }
    c.notes.push(format!(
        "Extended AIF: {} non-root load regions chained from 0x{:X}",
        visited.len(),
        header.word(FIRST_REGION)
    ));
    Ok(Some(end))
}

/// A region name "padded out with zeros": printable ASCII up to the first
/// NUL, other bytes as `\xNN`.
fn region_name(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    field[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b).to_string()
            } else {
                format!("\\x{b:02X}")
            }
        })
        .collect()
}

/// What follows the image at `c.consumed`. A self-relocating executable
/// image ends with the relocation code that word 1 branches to, followed by
/// the relocation list; a non-executable image leaves relocation to its
/// loader, so the bytes after it are listed as opaque relocation data.
/// Otherwise only padding may follow.
fn load_trailer<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    layout: Layout,
) -> Result<()> {
    let image_end = c.consumed;
    if !header.is_self_relocating() {
        return expect_padding(c, data, image_end);
    }
    if layout != Layout::Executable {
        let relocation_data = &data[image_end..];
        let after = if relocation_data.is_empty() {
            String::new()
        } else {
            c.children
                .push(Child::opaque("Relocation data", image_end, relocation_data));
            format!(
                "; the {} B after the image are opaque",
                relocation_data.len()
            )
        };
        c.notes.push(format!(
            "Self-relocating image (BL SelfRelocCode at 0x{SELF_RELOC_CODE:X}), relocated by \
             the loader{after}"
        ));
        c.consumed = data.len();
        return Ok(());
    }
    let instruction = header.word(SELF_RELOC_CODE);
    let target = branch_target(SELF_RELOC_CODE, instruction)
        .filter(|&target| target >= image_end && target < data.len())
        .ok_or_else(|| {
            error(format!(
                "Invalid AIF self-relocation branch 0x{instruction:08X} at \
                 0x{SELF_RELOC_CODE:X}: the code must follow the image, which ends at \
                 0x{image_end:X}, inside the {} B file",
                data.len()
            ))
        })?;
    let gap = &data[image_end..target];
    if !is_padding(gap) {
        return Err(error(format!(
            "Invalid data at 0x{image_end:X}: {} B between the image and the self-relocation \
             code",
            gap.len()
        )));
    }
    let code = Area {
        offset: target,
        bytes: &data[target..],
    };
    let address = u64::from(header.image_base()) + target as u64;
    push_area(c, "Self-relocation code", address, &code);
    c.notes.push(format!(
        "Self-relocating image: relocation code and list, {} B at 0x{target:X} (BL \
         SelfRelocCode at 0x{SELF_RELOC_CODE:X}); relocations are not applied",
        code.bytes.len()
    ));
    let work_space = header.word(WORK_SPACE);
    if work_space != 0 {
        c.notes.push(format!(
            "Self-moving image: {work_space} B of work space reserved above it"
        ));
    }
    c.consumed = data.len();
    Ok(())
}

fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0x00 || b == 0xFF)
}

/// Bytes after the image may only be zero or erased fill; their size is
/// noted. `image_end` is the end of a bounds-checked area.
fn expect_padding(c: &mut Container<'_>, data: &[u8], image_end: usize) -> Result<()> {
    let trailing = &data[image_end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Invalid trailing data at 0x{image_end:X}: {} B after the image",
            trailing.len()
        )));
    }
    if !trailing.is_empty() {
        c.notes
            .push(format!("{} B of padding after the image", trailing.len()));
        c.consumed = data.len();
    }
    Ok(())
}

/// A compressed image: "Header, Compressed image, Decompression data,
/// Decompression code". For executable AIF word 0 branches to the
/// decompression code, which is listed as code; the compressed image and
/// its decompression data are opaque. A non-executable image is
/// decompressed by its loader, so everything after the header is opaque.
fn load_compressed<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    layout: Layout,
) -> Result<()> {
    let sizes = format!(
        "the header's read-only ({} B), read-write ({} B) and debug ({} B) sizes describe the \
         decompressed image",
        header.read_only_size(),
        header.read_write_size(),
        header.debug_size()
    );
    c.consumed = data.len();
    if layout != Layout::Executable {
        if data.len() > HEADER_SIZE {
            c.children.push(Child::opaque(
                "Compressed image",
                HEADER_SIZE,
                &data[HEADER_SIZE..],
            ));
        }
        c.notes.push(format!(
            "Compressed image (BL DecompressCode at 0x0), decompressed by the loader; {sizes}; \
             the {} B after the header are opaque",
            data.len() - HEADER_SIZE
        ));
        return Ok(());
    }
    let instruction = header.word(DECOMPRESS_CODE);
    let target = branch_target(DECOMPRESS_CODE, instruction)
        .filter(|&target| target >= HEADER_SIZE && target < data.len())
        .ok_or_else(|| {
            error(format!(
                "Invalid AIF decompression branch 0x{instruction:08X} at 0x0: the code must lie \
                 after the header inside the {} B file",
                data.len()
            ))
        })?;
    if target > HEADER_SIZE {
        c.children.push(Child::opaque(
            "Compressed image",
            HEADER_SIZE,
            &data[HEADER_SIZE..target],
        ));
    }
    let code = Area {
        offset: target,
        bytes: &data[target..],
    };
    let address = u64::from(header.image_base()) + target as u64;
    push_area(c, "Decompression code", address, &code);
    c.notes.push(format!(
        "Compressed image (BL DecompressCode at 0x0): {sizes}; the compressed image and its \
         decompression data ({} B at 0x{HEADER_SIZE:X}) are opaque, the decompression code ({} B \
         at 0x{target:X}) is analyzed",
        target - HEADER_SIZE,
        code.bytes.len()
    ));
    if header.is_self_relocating() {
        c.notes
            .push("Self-relocating image (BL SelfRelocCode at 0x4) once decompressed".into());
    }
    Ok(())
}

/// Notes that every image gets: the variant and byte order, the ISA rule,
/// the base and entry point, the address mode, the debugging data and the
/// exit instruction.
fn push_header_notes(c: &mut Container<'_>, header: &Header, layout: Layout, entry_offset: u64) {
    let byte_order = if header.big_endian {
        "big-endian"
    } else {
        "little-endian"
    };
    let variant = match layout {
        Layout::Executable => {
            "Executable AIF: the 128 B header is part of the image, which is entered at its \
             first word"
        }
        Layout::NonExecutable => {
            "Non-executable AIF: a loader interprets the 128 B header, which is not part of the \
             image"
        }
        Layout::Extended => {
            "Extended AIF: a non-executable, scatter-loaded image whose word at 0x38 chains \
             further load regions"
        }
    };
    c.notes.push(format!("{variant}; {byte_order} header"));
    c.notes.push(format!(
        "AIF holds ARM executable images (ARM DUI 0041C, section 13.1); the code byte order is \
         the header's ({byte_order})"
    ));
    let entry_source = if layout == Layout::Executable {
        format!("BL ImageEntryPoint at 0x{IMAGE_ENTRY_POINT:X}")
    } else {
        "entry offset at 0xC".to_string()
    };
    c.notes.push(format!(
        "Image base 0x{:08X}; entry point 0x{:08X} ({entry_source}, offset 0x{entry_offset:X})",
        header.image_base(),
        u64::from(header.image_base()) + entry_offset
    ));
    c.notes.push(address_mode_text(header));
    c.notes.push(debug_text(header));
    let exit = header.word(PROGRAM_EXIT);
    c.notes.push(if exit == SWI_EXIT {
        "Program exit instruction SWI 0x11".to_string()
    } else {
        "Program exit instruction B . (a branch to itself)".to_string()
    });
    if layout != Layout::Extended && header.word(FIRST_REGION) != 0 {
        c.notes.push(format!(
            "Reserved word at 0x{FIRST_REGION:X} is 0x{:08X} (expected 0)",
            header.word(FIRST_REGION)
        ));
    }
    if header.word(RESERVED) != 0 {
        c.notes.push(format!(
            "Reserved word at 0x{RESERVED:X} is 0x{:08X} (expected 0)",
            header.word(RESERVED)
        ));
    }
}

/// `"Linked for 32-bit ARM mode; separate data base 0x..."`.
fn address_mode_text(header: &Header) -> String {
    let mode = header.address_mode();
    let width = match mode & ADDRESS_MODE_WIDTH_MASK {
        ADDRESS_MODE_32 => "Linked for 32-bit ARM mode",
        ADDRESS_MODE_26 => "Linked for 26-bit ARM mode (obsolete)",
        _ => "Old-style header (address mode word 0): 26-bit ARM mode",
    };
    let mut parts = vec![width.to_string()];
    if header.has_separate_data_base() {
        parts.push(format!(
            "separate data base 0x{:08X}",
            header.word(DATA_BASE)
        ));
    }
    let undocumented = mode & ADDRESS_MODE_FLAGS_MASK & !SEPARATE_DATA_BASE;
    if undocumented != 0 {
        parts.push(format!(
            "undocumented address mode flags 0x{undocumented:08X}"
        ));
    }
    parts.join("; ")
}

/// The debug type and size, and whether they agree.
fn debug_text(header: &Header) -> String {
    let kind = match header.debug_type() {
        0 => "none",
        DEBUG_LOW_LEVEL => "low-level",
        DEBUG_SOURCE_LEVEL => "source-level (ASD)",
        _ => "low-level and source-level (ASD)",
    };
    let size = header.debug_size();
    match (header.debug_type(), size) {
        (0, 0) => "No debugging data (debug type 0)".to_string(),
        (0, _) => format!("Debug type 0 (none), but the debug size is {size} B"),
        (_, 0) => format!(
            "Debug type {} ({kind}), but the debug size is 0",
            header.debug_type()
        ),
        _ => format!(
            "Debugging data: {size} B, {kind} (debug type {}); opaque, not analyzed",
            header.debug_type()
        ),
    }
}

/// Where the areas lie, the zero-initialized area, and an entry point
/// outside the read-only area.
fn push_image_notes(
    c: &mut Container<'_>,
    header: &Header,
    layout: Layout,
    image: &Image<'_>,
    entry_offset: u64,
) {
    let header_part = if layout == Layout::Executable {
        " (header included)"
    } else {
        ""
    };
    c.notes.push(format!(
        "Read-only area {} B at file 0x{:X}{header_part}; read-write area {} B at file 0x{:X}; \
         zero-initialized area {} B (not stored)",
        image.read_only.bytes.len(),
        image.read_only.offset,
        image.read_write.bytes.len(),
        image.read_write.offset,
        header.zero_init_size()
    ));
    if entry_offset >= u64::from(header.read_only_size()) {
        c.notes.push(format!(
            "Entry point offset 0x{entry_offset:X} lies outside the {} B read-only area",
            header.read_only_size()
        ));
    }
}

fn push_metadata(c: &mut Container<'_>, header: &Header, entry_offset: u64) {
    c.push_metadata(
        "aif_image_base",
        "Image base",
        MetadataValue::Address(u64::from(header.image_base())),
    );
    c.push_metadata(
        "aif_entry_offset",
        "Entry point offset from the image base",
        MetadataValue::Address(entry_offset),
    );
    c.push_metadata(
        "aif_read_only_size",
        "Read-only size (B)",
        u64::from(header.read_only_size()),
    );
    c.push_metadata(
        "aif_read_write_size",
        "Read-write size (B)",
        u64::from(header.read_write_size()),
    );
    c.push_metadata(
        "aif_debug_size",
        "Debug size (B)",
        u64::from(header.debug_size()),
    );
    c.push_metadata(
        "aif_zero_init_size",
        "Zero-init size (B)",
        u64::from(header.zero_init_size()),
    );
    c.push_metadata(
        "aif_debug_type",
        "Debug type word",
        MetadataValue::Hex(header.word(DEBUG_TYPE)),
    );
    c.push_metadata(
        "aif_address_mode",
        "Address mode word",
        MetadataValue::Hex(header.address_mode()),
    );
    if header.has_separate_data_base() {
        c.push_metadata(
            "aif_data_base",
            "Data base",
            MetadataValue::Address(u64::from(header.word(DATA_BASE))),
        );
    }
    if header.word(WORK_SPACE) != 0 {
        c.push_metadata(
            "aif_work_space",
            "Work space (B)",
            u64::from(header.word(WORK_SPACE)),
        );
    }
    c.push_metadata(
        "aif_exit_instruction",
        "Program exit instruction",
        MetadataValue::Hex(header.word(PROGRAM_EXIT)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_targets_are_relative_to_the_instruction_plus_8() {
        assert_eq!(branch_target(0x0C, 0xEB00_001B), Some(0x80));
        assert_eq!(branch_target(0x08, 0xEB00_000C), Some(0x40));
        assert_eq!(branch_target(0x10, 0xEAFF_FFFE), Some(0x10));
        assert_eq!(branch_target(0x04, 0xEBFF_FFFD), Some(0x00));
        assert_eq!(branch_target(0x04, 0xEBFF_FFFC), None);
    }

    #[test]
    fn address_modes_are_zero_or_26_or_32_with_flags() {
        assert!(is_address_mode(0));
        assert!(is_address_mode(26));
        assert!(is_address_mode(32 | SEPARATE_DATA_BASE));
        assert!(is_address_mode(0xFFFF_FF20));
        assert!(!is_address_mode(SEPARATE_DATA_BASE));
        assert!(!is_address_mode(16));
    }

    #[test]
    fn region_names_stop_at_nul_and_escape_other_bytes() {
        assert_eq!(region_name(b"FLASH\0\0\0"), "FLASH");
        assert_eq!(region_name(b"A B\x01"), "A B\\x01");
        assert_eq!(region_name(&[0; 32]), "");
    }

    #[test]
    fn exit_instructions_and_branches_are_recognized() {
        assert!(is_exit_instruction(SWI_EXIT));
        assert!(is_exit_instruction(BRANCH_TO_SELF));
        assert!(!is_exit_instruction(NOP));
        assert!(is_bl(0xEB00_0000));
        assert!(!is_bl(BLNV_0));
        assert!(!is_bl(0xEA00_0000));
    }
}
