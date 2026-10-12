//! Wii U RPX executables and RPL libraries: 32-bit big-endian ELF files for
//! Cafe OS (wut-tools `src/common/elf.h`, `src/elf2rpl/main.cpp`,
//! `src/readrpl/main.cpp` and `verify.cpp` at `b22de1a3`; decaf-emu
//! `src/libdecaf/src/cafe/loader/cafe_loader_rpl.h` at `e6c528a2`).
//!
//! `e_ident` carries `EI_OSABI` 0xCA and `EI_ABIVERSION` 0xFE, and `e_type`
//! is 0xFE01. Section headers (0x28 bytes: name, type, flags, address,
//! offset, size, link, info, alignment, entry size) follow at `e_shoff`. A
//! section with `SHF_DEFLATED` (0x08000000) stores a big-endian inflated
//! size, then a zlib stream. The RPL section types are exports (0x80000001:
//! count, signature, entries), imports (0x80000002: count, signature,
//! library name), CRCs (0x80000003: one zlib CRC-32 of the inflated data per
//! section header, 0 for empty sections) and the file information block
//! (0x80000004: `RPLFileInfo`, whose flags at 0x34 mark an RPX with bit 1).

use super::*;
use crate::formats::checksum::crc32;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::MAX_EXTRACTED;
use crate::formats::elf;

/// `e_ident` bytes that identify a Cafe OS ELF.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_OSABI: usize = 7;
const EI_ABIVERSION: usize = 8;
const ELFDATA2MSB: u8 = 2;
const EABI_CAFE: u8 = 0xca;
const EABI_VERSION_CAFE: u8 = 0xfe;

/// The `e_type` that elf2rpl and decaf-emu write. wut's `elf.h` names
/// `ET_CAFE_RPL` 0xFF01, which neither tool writes.
const ET_CAFE_RPL: u16 = 0xfe01;

/// ELF32 header fields.
const ELF_HEADER_SIZE: usize = 0x34;
const E_TYPE: usize = 0x10;
const E_MACHINE: usize = 0x12;
const E_ENTRY: usize = 0x18;
const E_SHOFF: usize = 0x20;
const E_SHENTSIZE: usize = 0x2e;
const E_SHNUM: usize = 0x30;
const E_SHSTRNDX: usize = 0x32;

/// ELF32 section header size and fields.
const SECTION_HEADER_SIZE: usize = 0x28;
const SH_NAME: usize = 0;
const SH_TYPE: usize = 4;
const SH_FLAGS: usize = 8;
const SH_ADDR: usize = 0xc;
const SH_OFFSET: usize = 0x10;
const SH_SIZE: usize = 0x14;

/// Section types.
const SHT_PROGBITS: u32 = 1;
const SHT_NOBITS: u32 = 8;
const SHT_RPL_EXPORTS: u32 = 0x8000_0001;
const SHT_RPL_IMPORTS: u32 = 0x8000_0002;
const SHT_RPL_CRCS: u32 = 0x8000_0003;
const SHT_RPL_FILEINFO: u32 = 0x8000_0004;

/// Section flags.
const SHF_EXECINSTR: u32 = 0x4;
const SHF_DEFLATED: u32 = 0x0800_0000;

/// A deflated section starts with its inflated size.
const INFLATED_SIZE_FIELD: usize = 4;

/// The CRC section holds one 4-byte CRC per section header.
const CRC_SIZE: usize = 4;

/// Import sections: count, signature, then the library name.
const IMPORT_NAME: usize = 8;

/// `RPLFileInfo`: version at 0 and flags at 0x34 (every version is at
/// least 0x40 bytes); `RPL_IS_RPX` in the flags.
const FILEINFO_VERSION: usize = 0;
const FILEINFO_FLAGS: usize = 0x34;
const FILEINFO_MIN_SIZE: usize = 0x40;
const RPL_IS_RPX: u32 = 0x2;

/// Most import library names listed in one note.
const MAX_LISTED_IMPORTS: usize = 16;

pub(super) fn detect(data: &[u8]) -> bool {
    data.len() > EI_ABIVERSION
        && data.starts_with(ELF_MAGIC)
        && data[EI_CLASS] == elf::class::ELFCLASS32
        && data[EI_DATA] == ELFDATA2MSB
        && data[EI_OSABI] == EABI_CAFE
        && data[EI_ABIVERSION] == EABI_VERSION_CAFE
}

/// One section header; offsets and sizes in bytes.
struct RplSection {
    index: usize,
    name: usize,
    kind: u32,
    flags: u32,
    address: u32,
    offset: usize,
    size: usize,
}

impl RplSection {
    fn is_deflated(&self) -> bool {
        self.flags & SHF_DEFLATED != 0
    }

    fn has_data(&self) -> bool {
        self.kind != SHT_NOBITS && self.size != 0
    }

    /// Program code: executable `SHT_PROGBITS` sections. Import sections
    /// can also be executable (stub tables) and are not code to analyze.
    fn is_text(&self) -> bool {
        self.kind == SHT_PROGBITS && self.flags & SHF_EXECINSTR != 0 && self.size != 0
    }
}

/// The ELF header fields this parser uses.
struct RplHeader {
    machine: u16,
    entry: u32,
    section_offset: usize,
    section_count: usize,
    names_index: usize,
}

fn header(data: &[u8]) -> Result<RplHeader> {
    if data.len() < ELF_HEADER_SIZE {
        return Err(error(format!(
            "Truncated RPL ELF header: {} B of {ELF_HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error(
            "Missing Cafe OS ELF identification (32-bit, big-endian, OSABI 0xCA, ABI version 0xFE)",
        ));
    }
    let e_type = be_u16(data, E_TYPE)?;
    if e_type != ET_CAFE_RPL {
        return Err(error(format!("Unsupported RPL e_type 0x{e_type:04X}")));
    }
    let entry_size = usize::from(be_u16(data, E_SHENTSIZE)?);
    if entry_size != SECTION_HEADER_SIZE {
        return Err(error(format!(
            "Invalid RPL e_shentsize {entry_size} B, expected {SECTION_HEADER_SIZE} B"
        )));
    }
    let section_count = usize::from(be_u16(data, E_SHNUM)?);
    if section_count == 0 {
        return Err(error("Missing RPL section headers: e_shnum is 0"));
    }
    Ok(RplHeader {
        machine: be_u16(data, E_MACHINE)?,
        entry: be_u32(data, E_ENTRY)?,
        section_offset: be_usize(data, E_SHOFF, "RPL e_shoff")?,
        section_count,
        names_index: usize::from(be_u16(data, E_SHSTRNDX)?),
    })
}

/// The section header table; its size is checked against the file before
/// any header is read.
fn section_headers(data: &[u8], header: &RplHeader) -> Result<Vec<RplSection>> {
    let table_size = header.section_count * SECTION_HEADER_SIZE;
    let table = slice(data, header.section_offset, table_size).map_err(|_| {
        error(format!(
            "Truncated RPL section header table at 0x{:X}: {} headers",
            header.section_offset, header.section_count
        ))
    })?;
    table
        .chunks_exact(SECTION_HEADER_SIZE)
        .enumerate()
        .map(|(index, entry)| {
            Ok(RplSection {
                index,
                name: be_usize(entry, SH_NAME, "RPL sh_name")?,
                kind: be_u32(entry, SH_TYPE)?,
                flags: be_u32(entry, SH_FLAGS)?,
                address: be_u32(entry, SH_ADDR)?,
                offset: be_usize(entry, SH_OFFSET, "RPL sh_offset")?,
                size: be_usize(entry, SH_SIZE, "RPL sh_size")?,
            })
        })
        .collect()
}

/// A section's stored bytes; `SHT_NOBITS` sections have none.
fn stored<'a>(data: &'a [u8], section: &RplSection) -> Result<&'a [u8]> {
    if !section.has_data() {
        return Ok(&[]);
    }
    slice(data, section.offset, section.size).map_err(|_| {
        error(format!(
            "Truncated RPL section {} at 0x{:X} + {} B",
            section.index, section.offset, section.size
        ))
    })
}

/// Decoded bytes left for the whole file. Inflated sections stop at
/// [`MAX_EXTRACTED`]; the text sections, which are analyzed together, stop
/// at [`MAX_PAYLOAD`].
struct Budget {
    inflated: usize,
    text: usize,
    skipped: usize,
}

/// A section's bytes as loaded: inflated when `SHF_DEFLATED` is set, with
/// the inflated size checked against the size field. `None` when decoding
/// it would pass the extraction budget.
fn contents<'a>(
    data: &'a [u8],
    section: &RplSection,
    budget: &mut Budget,
) -> Result<Option<Cow<'a, [u8]>>> {
    let stored = stored(data, section)?;
    if !section.is_deflated() || stored.is_empty() {
        return Ok(Some(Cow::Borrowed(stored)));
    }
    let index = section.index;
    if stored.len() < INFLATED_SIZE_FIELD {
        return Err(error(format!(
            "Truncated RPL deflated section {index}: {} B",
            stored.len()
        )));
    }
    let inflated_size = be_usize(stored, 0, "RPL inflated size")?;
    if inflated_size > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported RPL section {index}: inflated size {inflated_size} B exceeds {}",
            size_text(MAX_PAYLOAD)
        )));
    }
    if inflated_size > budget.inflated {
        budget.skipped += 1;
        return Ok(None);
    }
    let stream = &stored[INFLATED_SIZE_FIELD..];
    let decoded = compressed::decode_limited(Codec::Zlib, stream, inflated_size)
        .map_err(|e| error(format!("Invalid zlib stream in RPL section {index}: {e}")))?;
    if decoded.data.len() != inflated_size {
        return Err(error(format!(
            "Invalid RPL section {index}: inflated {} B, size field declares {inflated_size} B",
            decoded.data.len()
        )));
    }
    budget.inflated -= inflated_size;
    Ok(Some(Cow::Owned(decoded.data)))
}

/// Section names from the section name string table, which may itself be
/// deflated. Missing names become `Section <index>`.
struct Names<'a> {
    table: Option<Cow<'a, [u8]>>,
}

impl Names<'_> {
    fn get(&self, section: &RplSection) -> String {
        let name = self.table.as_deref().and_then(|table| {
            let rest = table.get(section.name..)?;
            let end = memchr::memchr(0, rest)?;
            Some(text(&rest[..end]))
        });
        match name {
            Some(name) if !name.is_empty() => name,
            _ => format!("Section {}", section.index),
        }
    }
}

/// What the RPL-specific sections say, for notes.
#[derive(Default)]
struct RplInfo {
    is_rpx: Option<bool>,
    fileinfo_version: Option<u32>,
    imports: Vec<String>,
    exports: u64,
}

fn rpl_info(data: &[u8], sections: &[RplSection], budget: &mut Budget) -> Result<RplInfo> {
    let mut info = RplInfo::default();
    for section in sections {
        if !matches!(
            section.kind,
            SHT_RPL_FILEINFO | SHT_RPL_IMPORTS | SHT_RPL_EXPORTS
        ) {
            continue;
        }
        let Some(bytes) = contents(data, section, budget)? else {
            continue;
        };
        match section.kind {
            SHT_RPL_FILEINFO => {
                if bytes.len() < FILEINFO_MIN_SIZE {
                    return Err(error(format!(
                        "Truncated RPL file information: {} B of {FILEINFO_MIN_SIZE} B",
                        bytes.len()
                    )));
                }
                info.fileinfo_version = Some(be_u32(&bytes, FILEINFO_VERSION)?);
                info.is_rpx = Some(be_u32(&bytes, FILEINFO_FLAGS)? & RPL_IS_RPX != 0);
            }
            SHT_RPL_IMPORTS => {
                if let Some(name) = bytes.get(IMPORT_NAME..) {
                    info.imports.push(text(name));
                }
            }
            _ => {
                if let Ok(count) = be_u32(&bytes, 0) {
                    info.exports += u64::from(count);
                }
            }
        }
    }
    Ok(info)
}

/// An executable section as loaded.
struct TextSection<'a, 's> {
    section: &'s RplSection,
    name: String,
    bytes: Cow<'a, [u8]>,
}

/// The text sections within the budgets, in section header order.
fn text_sections<'a, 's>(
    data: &'a [u8],
    sections: &'s [RplSection],
    names: &Names<'_>,
    budget: &mut Budget,
) -> Result<Vec<TextSection<'a, 's>>> {
    let mut texts = Vec::new();
    for section in sections.iter().filter(|s| s.is_text()) {
        let Some(bytes) = contents(data, section, budget)? else {
            continue;
        };
        if bytes.len() > budget.text {
            budget.skipped += 1;
            continue;
        }
        budget.text -= bytes.len();
        texts.push(TextSection {
            section,
            name: names.get(section),
            bytes,
        });
    }
    Ok(texts)
}

/// CRC results of the text sections against the CRC section.
struct CrcCheck {
    verified: usize,
    mismatched: Vec<String>,
}

/// Compare each text section with its entry in the CRC section. A CRC of 0
/// marks an empty or unrecorded section and is skipped.
fn check_crcs(crcs: &[u8], texts: &[TextSection<'_, '_>]) -> CrcCheck {
    let mut check = CrcCheck {
        verified: 0,
        mismatched: Vec::new(),
    };
    for text in texts {
        let Ok(stored) = be_u32(crcs, text.section.index * CRC_SIZE) else {
            continue;
        };
        if stored == 0 {
            continue;
        }
        if crc32(&text.bytes) == stored {
            check.verified += 1;
        } else {
            check.mismatched.push(text.name.clone());
        }
    }
    check
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = header(data)?;
    let sections = section_headers(data, &header)?;
    let mut budget = Budget {
        inflated: MAX_EXTRACTED,
        text: MAX_PAYLOAD,
        skipped: 0,
    };
    let names = Names {
        table: match sections.get(header.names_index) {
            Some(table) if header.names_index != 0 => contents(data, table, &mut budget)?,
            _ => None,
        },
    };
    let info = rpl_info(data, &sections, &mut budget)?;
    let texts = text_sections(data, &sections, &names, &mut budget)?;
    let crc_note = match sections.iter().find(|s| s.kind == SHT_RPL_CRCS) {
        Some(crc_section) => match contents(data, crc_section, &mut budget)? {
            Some(crcs) => crc_note(&check_crcs(&crcs, &texts), texts.len()),
            None => "CRC section not decoded; section contents not verified".to_string(),
        },
        None => "no CRC section; section contents not verified".to_string(),
    };

    let (isa, bits) = elf::e_machine_to_isa(header.machine, elf::class::ELFCLASS32);
    // The sources name no Wii U CPU model, so the variant is the ISA only.
    let variant = match isa {
        Isa::Ppc => "PowerPC",
        Isa::Unknown(_) => Layout::WiiURpx.label(),
        other => other.name(),
    };
    let mut c = Container::new(FileFormat::WiiURpx, variant, "wiiu");
    c.entry = Some(u64::from(header.entry));
    c.consumed = data.len();
    c.code_sections = true;
    if matches!(isa, Isa::Unknown(_)) {
        c.notes.push(format!(
            "ELF e_machine {} is not mapped to an ISA",
            header.machine
        ));
    } else {
        c.target = Some(Target::new(isa, bits, Endianness::Big));
    }
    let kind = match info.is_rpx {
        Some(true) => "RPX (executable)",
        Some(false) => "RPL (library)",
        None => "RPX/RPL without file information",
    };
    c.notes.push(format!(
        "Wii U {kind}; ELF e_machine {}; entry point 0x{:08X}",
        header.machine, header.entry
    ));
    let deflated = sections.iter().filter(|s| s.is_deflated()).count();
    c.notes.push(format!(
        "{} sections, {deflated} zlib-compressed (SHF_DEFLATED); {crc_note}",
        sections.len()
    ));
    push_info_notes(&mut c, &info, &sections);
    if budget.skipped > 0 {
        c.notes.push(format!(
            "{} sections were not decoded (limits {} inflated, {} of text)",
            budget.skipped,
            size_text(MAX_EXTRACTED),
            size_text(MAX_PAYLOAD)
        ));
    }
    for text in texts {
        let section = text.section;
        let transform = section.is_deflated().then(|| Codec::Zlib.name());
        c.sections.push(super::section(
            text.name,
            u64::from(section.address),
            section.offset,
            section.size,
            text.bytes,
            transform,
        ));
    }
    Ok(c)
}

fn crc_note(check: &CrcCheck, text_count: usize) -> String {
    let mismatch = if check.mismatched.is_empty() {
        String::new()
    } else {
        format!("; CRC-32 mismatch for {}", check.mismatched.join(", "))
    };
    format!(
        "section CRC-32 verified for {} of {text_count} text sections{mismatch}",
        check.verified
    )
}

fn push_info_notes(c: &mut Container<'_>, info: &RplInfo, sections: &[RplSection]) {
    if let Some(version) = info.fileinfo_version {
        c.push_metadata(
            "wiiu_fileinfo_version",
            "File information version",
            format!("0x{version:08X}"),
        );
    }
    let kind = match info.is_rpx {
        Some(true) => "rpx",
        Some(false) => "rpl",
        None => "unknown",
    };
    c.push_metadata("wiiu_kind", "RPX or RPL", kind);
    if !info.imports.is_empty() {
        let listed: Vec<&str> = info
            .imports
            .iter()
            .take(MAX_LISTED_IMPORTS)
            .map(String::as_str)
            .collect();
        let more = info.imports.len().saturating_sub(MAX_LISTED_IMPORTS);
        let suffix = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        c.notes
            .push(format!("Imports: {}{suffix}", listed.join(", ")));
    }
    if info.exports > 0 {
        c.notes.push(format!("Exports: {} entries", info.exports));
    }
    // readrpl `verifySectionOrder`: the CRC section, then the file
    // information block, end the section header table.
    let last_kinds: Vec<u32> = sections.iter().rev().take(2).map(|s| s.kind).collect();
    if last_kinds != [SHT_RPL_FILEINFO, SHT_RPL_CRCS] {
        c.notes.push(
            "Section order differs from elf2rpl: the CRC and file information sections are not last"
                .to_string(),
        );
    }
}
