//! KSS tunes for Z80 machines: MSX, Sega Master System and Game Gear.
//!
//! Original header: Mamiya, "KSS Music Format Spec V1.03" (Nov. 26, 2000).
//! Extended header: digital-sound-antiques/libkss `kssxspec.md` at
//! `2ed95882`. Both are little-endian: magic `KSCC` or `KSSX` (4), load
//! address (2), initial data length (2), init address (2), play address
//! (2), first bank number (1), bank count in bits 0-6 with the 8 KiB mapper
//! in bit 7 (1), a reserved byte (`KSCC`, must be 0) or the extra header
//! size (`KSSX`, 0x00 or 0x10) (1), and device flags (1). A `KSSX` extra
//! header holds the end-of-file offset (4), a reserved word (4, 0), the
//! first and last song numbers (2 each) and four volumes. The initial data
//! follows, loaded at the load address, then the extra 16 KiB or 8 KiB
//! banks, mapped at run time into the window at 0x8000.
//!
//! Game Music Emu 0.6.5 (`Kss_Emu.cpp`) tolerates nonzero reserved bits,
//! initial data beyond the file or the address space and fewer banks than
//! declared; these are noted here, not rejected.

use super::*;

/// Magics and header fields.
const KSCC_MAGIC: &[u8; 4] = b"KSCC";
const KSSX_MAGIC: &[u8; 4] = b"KSSX";
const HEADER_SIZE: usize = 0x10;
const LOAD: usize = 0x04;
const LENGTH: usize = 0x06;
const INIT: usize = 0x08;
const PLAY: usize = 0x0a;
const FIRST_BANK: usize = 0x0c;
const BANKS: usize = 0x0d;
const EXTRA_HEADER: usize = 0x0e;
const DEVICES: usize = 0x0f;

/// Bank byte: count in bits 0-6, 8 KiB mapper in bit 7.
const BANK_COUNT_MASK: u8 = 0x7f;
const MAPPER_8K: u8 = 0x80;
const BANK_16K: usize = 0x4000;
const BANK_8K: usize = 0x2000;

/// Banks are mapped into the window at 0x8000 (both mappers).
const BANK_WINDOW: u64 = 0x8000;

/// Device flag bits that "must be 0".
const KSCC_RESERVED_DEVICES: u8 = 0xf0;
const KSSX_RESERVED_DEVICES: u8 = 0xe0;

/// Device flag bit 1: SN76489, which selects the Sega mode.
const DEVICE_SN76489: u8 = 0x02;

/// `KSSX` extra header sizes and fields.
const KSSX_EXTRA_SIZES: [usize; 2] = [0x00, 0x10];
const KSSX_EXTRA_FULL: usize = 0x10;
const KSSX_RESERVED: usize = 0x04;
const KSSX_FIRST_SONG: usize = 0x08;
const KSSX_LAST_SONG: usize = 0x0a;

/// The Z80 address space.
const Z80_SPACE: usize = 0x1_0000;

/// The Z80, little-endian.
const Z80: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// `KSCC` or `KSSX` at offset 0.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(KSCC_MAGIC) {
        Some(Layout::Kss)
    } else if data.starts_with(KSSX_MAGIC) {
        Some(Layout::Kssx)
    } else {
        None
    }
}

/// Header, then the initial data at the load address and the extra banks
/// at the bank window.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = data.get(..HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated KSS header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    let extended = layout == Layout::Kssx;
    let magic = if extended { KSSX_MAGIC } else { KSCC_MAGIC };
    if !header.starts_with(magic) {
        return Err(error("Missing KSS magic"));
    }
    let load = le_u16(header, LOAD)?;
    let length = usize::from(le_u16(header, LENGTH)?);
    let init = le_u16(header, INIT)?;
    let play = le_u16(header, PLAY)?;
    let first_bank = header[FIRST_BANK];
    let bank_byte = header[BANKS];
    let devices = header[DEVICES];
    let mut c = Container::new(FileFormat::Kss, layout.label(), "kss");
    c.target = Some(Z80);
    c.entry = Some(u64::from(init));
    c.code_sections = true;
    let reserved_devices = if extended {
        KSSX_RESERVED_DEVICES
    } else {
        KSCC_RESERVED_DEVICES
    };
    if devices & reserved_devices != 0 {
        c.notes.push(format!(
            "Device flags 0x{devices:02X} set reserved bits (mask 0x{reserved_devices:02X})"
        ));
    }
    let data_at = if extended {
        HEADER_SIZE + kssx_extra_header(&mut c, data, usize::from(header[EXTRA_HEADER]))?
    } else {
        if header[EXTRA_HEADER] != 0 {
            c.notes.push(format!(
                "Reserved byte 0x0E is 0x{:02X}, not 0",
                header[EXTRA_HEADER]
            ));
        }
        HEADER_SIZE
    };
    initial_data(&mut c, data, data_at, load, length);
    let banks_at = data_at + length;
    let bank_size = if bank_byte & MAPPER_8K == 0 {
        BANK_16K
    } else {
        BANK_8K
    };
    let declared = usize::from(bank_byte & BANK_COUNT_MASK);
    let consumed = bank_sections(&mut c, data, banks_at, bank_size, declared, first_bank);
    if c.sections.is_empty() {
        return Err(error("Missing KSS program data"));
    }
    c.consumed = consumed;
    let mode = if devices & DEVICE_SN76489 == 0 {
        "MSX"
    } else {
        "Sega (SN76489)"
    };
    c.notes.insert(
        0,
        format!(
            "KSS {mode} mode: Z80 driver loaded at 0x{load:04X}; init 0x{init:04X}, play 0x{play:04X}; {declared} banks of {} from bank {first_bank}, mapped at 0x8000",
            compressed::size_text(bank_size)
        ),
    );
    if consumed < data.len() {
        c.notes.push(format!(
            "{} after the last bank; not analyzed",
            compressed::size_text(data.len() - consumed)
        ));
    }
    Ok(c)
}

/// The `KSSX` extra header of `size` bytes after the fixed header; returns
/// its size.
fn kssx_extra_header(c: &mut Container<'_>, data: &[u8], size: usize) -> Result<usize> {
    if !KSSX_EXTRA_SIZES.contains(&size) {
        c.notes.push(format!(
            "KSSX extra header size 0x{size:02X} is neither 0x00 nor 0x10"
        ));
    }
    let extra = data.get(HEADER_SIZE..HEADER_SIZE + size).ok_or_else(|| {
        error(format!(
            "Truncated KSSX extra header: {size} B declared at 0x{HEADER_SIZE:X}"
        ))
    })?;
    if size >= KSSX_EXTRA_FULL {
        let first = le_u16(extra, KSSX_FIRST_SONG)?;
        let last = le_u16(extra, KSSX_LAST_SONG)?;
        c.notes.push(format!("KSSX songs {first} to {last}"));
        if le_u32(extra, KSSX_RESERVED)? != 0 {
            c.notes
                .push("KSSX extra header reserved word is not 0".into());
        }
    }
    Ok(size)
}

/// The initial data at `at`, clipped to the file and the Z80 address space.
fn initial_data<'a>(c: &mut Container<'a>, data: &'a [u8], at: usize, load: u16, length: usize) {
    let available = data.len().saturating_sub(at);
    let space = Z80_SPACE - usize::from(load);
    let stored = length.min(available).min(space);
    if length > available {
        c.notes.push(format!(
            "Initial data declares {length} B at 0x{at:X}; {available} B present"
        ));
    }
    if length > space {
        c.notes.push(format!(
            "Initial data of {length} B at 0x{load:04X} exceeds the Z80 address space; clipped"
        ));
    }
    if stored > 0 {
        c.sections.push(borrowed_section(
            "Initial data".into(),
            u64::from(load),
            at,
            &data[at..at + stored],
        ));
    }
}

/// The extra banks after the initial data; a last bank cut short by the end
/// of the file is kept. Returns the offset after the last bank read.
fn bank_sections<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    at: usize,
    bank_size: usize,
    declared: usize,
    first_bank: u8,
) -> usize {
    let mut pos = at;
    for i in 0..declared {
        let Some(rest) = data.get(pos..).filter(|rest| !rest.is_empty()) else {
            c.notes
                .push(format!("{declared} banks declared; {i} present"));
            break;
        };
        let bank = &rest[..bank_size.min(rest.len())];
        if bank.len() < bank_size {
            c.notes.push(format!(
                "Bank {} at 0x{pos:X} holds {} B of {bank_size} B",
                usize::from(first_bank) + i,
                bank.len()
            ));
        }
        c.sections.push(borrowed_section(
            format!("Bank {}", usize::from(first_bank) + i),
            BANK_WINDOW,
            pos,
            bank,
        ));
        pos += bank.len();
    }
    pos.min(data.len())
}
