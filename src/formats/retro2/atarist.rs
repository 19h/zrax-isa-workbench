//! Atari ST GEMDOS executables (`.prg`, `.tos`, `.ttp`, `.app`).
//!
//! TOS.HYP §5.5 "The program format" and `EmuTOS` `bdos/pghdr.h`, big-endian
//! (68000): `ph_branch` 0x601A (2), `ph_tlen` (4), `ph_dlen` (4), `ph_blen`
//! (4), `ph_slen` (4), `ph_res1` (4, "should be 0"), `ph_prgflags` (4) and
//! `ph_absflag` (2, 0 when relocation information is present): 0x1C bytes.
//! TEXT, DATA and the optional symbol table (Digital Research format,
//! 14-byte entries) follow, then the relocation table. It starts with a
//! long offset of the first fixup from the TEXT start (0 for an empty
//! table), then bytes: 0 ends the table, 1 advances by 254, any other value
//! advances by itself and marks a fixup. `EmuTOS` `pgmld01` and `pgfix01`
//! reject a fixup outside TEXT and DATA and an odd later fixup; this parser
//! also requires the first one to be even and the terminating 0 to be in
//! the file. Execution starts at the TEXT start (`EmuTOS` `bdos/proc.c`).
//!
//! The magic is only two bytes (a 68000 `BRA.S` over the header), so the
//! layout is recognized only with sizes that fit the file and a valid
//! relocation table.

use super::*;
use crate::formats::MAX_PAYLOAD;

/// `ph_branch`: a 68000 `BRA.S` over the 0x1C-byte header.
const MAGIC: u16 = 0x601a;

/// Header fields.
const HEADER_SIZE: usize = 0x1c;
const TEXT_SIZE: usize = 0x2;
const DATA_SIZE: usize = 0x6;
const BSS_SIZE: usize = 0xa;
const SYMBOL_SIZE: usize = 0xe;
const RESERVED: usize = 0x12;
const FLAGS: usize = 0x16;
const ABSFLAG: usize = 0x1a;

/// Digital Research symbol table entries are 14 bytes.
const SYMBOL_ENTRY_SIZE: usize = 14;

/// Relocation table bytes after the first long.
const RELOC_END: u8 = 0;
const RELOC_SKIP: u8 = 1;
const RELOC_SKIP_DISTANCE: u64 = 254;
const RELOC_FIRST_SIZE: usize = 4;

/// Program flags (TOS.HYP §5.5.1).
const PF_FASTLOAD: u32 = 1 << 0;
const PF_TTRAMLOAD: u32 = 1 << 1;
const PF_TTRAMMEM: u32 = 1 << 2;
const PF_SHARED_TEXT: u32 = 1 << 12;
const PROTECTION_SHIFT: u32 = 4;
const PROTECTION_MASK: u32 = 0xf;
const TPA_SIZE_SHIFT: u32 = 28;

/// Memory protection modes (bits 4-7).
const PROTECTION_MODES: [&str; 4] = ["private", "global", "super", "read-only"];

/// The program header. TEXT, DATA and the symbol table lie in the file,
/// so their sizes and the relocation table offset fit `usize`.
#[derive(Debug, Clone, Copy)]
struct Header {
    text: usize,
    data: usize,
    bss: u32,
    symbols: usize,
    reserved: u32,
    flags: u32,
    absolute: bool,
    /// File offset of the relocation table, after the symbols.
    relocation_offset: usize,
}

impl Header {
    /// TEXT plus DATA: the bytes that relocation may patch.
    fn image_size(self) -> u64 {
        (self.text + self.data) as u64
    }
}

fn header(data: &[u8]) -> Result<Header> {
    range(data, "GEMDOS program header", 0, HEADER_SIZE)?;
    let magic = be_u16(data, 0)?;
    if magic != MAGIC {
        return Err(error(format!(
            "Missing GEMDOS program magic 0x601A at 0x0 (found 0x{magic:04X})"
        )));
    }
    let text = be_u32(data, TEXT_SIZE)?;
    let data_size = be_u32(data, DATA_SIZE)?;
    let symbols = be_u32(data, SYMBOL_SIZE)?;
    if text == 0 {
        return Err(error("Invalid GEMDOS program: the TEXT segment is empty"));
    }
    let end = HEADER_SIZE as u64 + u64::from(text) + u64::from(data_size) + u64::from(symbols);
    let relocation_offset = usize::try_from(end)
        .ok()
        .filter(|&end| end <= data.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated GEMDOS program: header, TEXT ({text} B), DATA ({data_size} B) and \
                    symbols ({symbols} B) exceed the {} B file",
                data.len()
            ))
        })?;
    Ok(Header {
        text: text as usize,
        data: data_size as usize,
        bss: be_u32(data, BSS_SIZE)?,
        symbols: symbols as usize,
        reserved: be_u32(data, RESERVED)?,
        flags: be_u32(data, FLAGS)?,
        absolute: be_u16(data, ABSFLAG)? != 0,
        relocation_offset,
    })
}

/// A validated relocation table.
struct Relocation {
    /// File offset of the table.
    offset: usize,
    /// Bytes from the first long through the terminating 0.
    size: usize,
    /// Number of fixups.
    fixups: u64,
}

/// One fixup must patch an even address inside TEXT and DATA.
fn expect_fixup(position: u64, header: Header) -> Result<()> {
    if position >= header.image_size() || position % 2 != 0 {
        return Err(error(format!(
            "Invalid relocation fixup at TEXT offset 0x{position:X}: not an even offset inside \
                the {} B of TEXT and DATA",
            header.image_size()
        )));
    }
    Ok(())
}

/// Walk the relocation table; each step consumes one input byte.
fn relocation(data: &[u8], header: Header) -> Result<Relocation> {
    let offset = header.relocation_offset;
    let first = be_u32(data, offset).map_err(|_| {
        error(format!(
            "Truncated GEMDOS relocation table: no first fixup offset at 0x{offset:X}"
        ))
    })?;
    let mut relocation = Relocation {
        offset,
        size: RELOC_FIRST_SIZE,
        fixups: 0,
    };
    if first == 0 {
        return Ok(relocation);
    }
    let mut position = u64::from(first);
    expect_fixup(position, header)?;
    relocation.fixups = 1;
    let table = &data[offset + RELOC_FIRST_SIZE..];
    let end = table.iter().position(|&b| b == RELOC_END).ok_or_else(|| {
        error(format!(
            "Truncated GEMDOS relocation table at 0x{offset:X}: no terminating 0 byte"
        ))
    })?;
    for &step in &table[..end] {
        if step == RELOC_SKIP {
            position += RELOC_SKIP_DISTANCE;
            continue;
        }
        position += u64::from(step);
        expect_fixup(position, header)?;
        relocation.fixups += 1;
    }
    relocation.size += end + 1;
    Ok(relocation)
}

/// Strong recognition: the magic, sizes that fit the file, and a valid
/// relocation table unless the program is absolute.
pub(super) fn detect(data: &[u8]) -> bool {
    if data.len() > MAX_PAYLOAD {
        return false;
    }
    let Ok(header) = header(data) else {
        return false;
    };
    header.absolute || relocation(data, header).is_ok()
}

fn flag_names(flags: u32) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (PF_FASTLOAD, "fastload"),
        (PF_TTRAMLOAD, "load into alternate RAM"),
        (PF_TTRAMMEM, "Malloc from alternate RAM"),
        (PF_SHARED_TEXT, "shared text"),
    ] {
        if flags & bit != 0 {
            names.push(name.to_string());
        }
    }
    let protection = (flags >> PROTECTION_SHIFT) & PROTECTION_MASK;
    names.push(match PROTECTION_MODES.get(protection as usize) {
        Some(mode) => format!("{mode} memory"),
        None => format!("unknown protection mode {protection}"),
    });
    let tpa = (flags >> TPA_SIZE_SHIFT) + 1;
    names.push(format!("alternate RAM TPA {} KiB", tpa * 128));
    names.join(", ")
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported GEMDOS program of {} B: the limit is {}",
            data.len(),
            size_text(MAX_PAYLOAD as u64)
        )));
    }
    let header = header(data)?;
    let text_end = HEADER_SIZE + header.text;
    let mut c = Container::new(FileFormat::AtariStPrg, "68000", "atarist");
    c.target = Some(M68000);
    c.entry = Some(0);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "GEMDOS executable; TEXT {} B, DATA {} B, BSS {} B, symbols {} B",
        header.text, header.data, header.bss, header.symbols
    ));
    c.notes.push(format!(
        "Program flags 0x{:08X}: {}",
        header.flags,
        flag_names(header.flags)
    ));
    if header.reserved != 0 {
        c.notes.push(format!(
            "Reserved header field ph_res1 is 0x{:08X}, not 0",
            header.reserved
        ));
    }
    if header.symbols > 0 {
        let entries = if header.symbols % SYMBOL_ENTRY_SIZE == 0 {
            format!(
                "{} Digital Research entries",
                header.symbols / SYMBOL_ENTRY_SIZE
            )
        } else {
            "not a whole number of 14-byte Digital Research entries".to_string()
        };
        c.notes.push(format!(
            "Symbol table of {} B: {entries}; not parsed",
            header.symbols
        ));
    }
    let image_end = if header.absolute {
        c.notes
            .push("Absolute program (ph_absflag set): no relocation information".into());
        header.relocation_offset
    } else {
        let relocation = relocation(data, header)?;
        c.notes.push(format!(
            "Relocation table at 0x{:X}: {} fixups of 32-bit addresses",
            relocation.offset, relocation.fixups
        ));
        c.push_metadata(
            "atarist_fixup_count",
            "Relocation fixups",
            relocation.fixups,
        );
        relocation.offset + relocation.size
    };
    if let Some(note) = expect_padding(data, image_end, "relocation table")? {
        c.notes.push(note);
    }
    c.notes.push(
        "68000-family code, big-endian (TOS.HYP); addresses are offsets from the TEXT start, which \
            GEMDOS relocates on load; execution starts at the TEXT start"
            .into(),
    );
    c.push_metadata("atarist_text_size", "TEXT size (B)", header.text as u64);
    c.push_metadata("atarist_data_size", "DATA size (B)", header.data as u64);
    c.push_metadata("atarist_bss_size", "BSS size (B)", u64::from(header.bss));
    c.push_metadata(
        "atarist_flags",
        "Program flags",
        format!("0x{:08X}", header.flags),
    );
    c.sections.push(stored_section(
        "TEXT",
        0,
        HEADER_SIZE,
        &data[HEADER_SIZE..text_end],
    ));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header with `text` bytes of TEXT, then the TEXT and `table`.
    fn program(text: u32, table: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; HEADER_SIZE];
        data[..2].copy_from_slice(&MAGIC.to_be_bytes());
        data[TEXT_SIZE..TEXT_SIZE + 4].copy_from_slice(&text.to_be_bytes());
        data.resize(HEADER_SIZE + text as usize, 0x4e);
        data.extend_from_slice(table);
        data
    }

    #[test]
    fn relocation_bytes_advance_and_skip() {
        // First fixup at 2, then +254 (skip), +4: fixups at 2 and 260.
        let data = program(0x200, &[0, 0, 0, 2, RELOC_SKIP, 4, RELOC_END]);
        let header = header(&data).unwrap();
        let table = relocation(&data, header).unwrap();
        assert_eq!(table.fixups, 2);
        assert_eq!(table.size, 7);
    }

    #[test]
    fn odd_or_outside_fixups_and_missing_terminators_are_rejected() {
        let odd = program(0x100, &[0, 0, 0, 2, 3, 0]);
        assert!(relocation(&odd, header(&odd).unwrap()).is_err());
        let outside = program(0x100, &[0, 0, 1, 0, 0]);
        assert!(relocation(&outside, header(&outside).unwrap()).is_err());
        let unterminated = program(0x100, &[0, 0, 0, 2, 4]);
        assert!(relocation(&unterminated, header(&unterminated).unwrap()).is_err());
        let empty = program(0x100, &[0, 0, 0, 0]);
        assert_eq!(
            relocation(&empty, header(&empty).unwrap()).unwrap().fixups,
            0
        );
    }

    #[test]
    fn flags_name_their_bits() {
        assert_eq!(
            flag_names(0x1000_0007),
            "fastload, load into alternate RAM, Malloc from alternate RAM, private memory, \
                alternate RAM TPA 256 KiB"
        );
    }
}
