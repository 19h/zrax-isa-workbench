//! MSX cartridge ROMs.
//!
//! ASCII "MSX2 Technical Handbook" chapter 5 §7.3.1, Figure 5.48: a 16-byte
//! header at 4000H or 8000H. ID `AB` (41H 42H) at +0, then four Z80 words
//! (little-endian): INIT (initialization routine) at +2, STATEMENT (CALL
//! statement expansion) at +4, DEVICE (device expansion) at +6 and TEXT
//! (BASIC program text) at +8; 0000H when unused. The reserved bytes +0AH to
//! +0FH "should be filled with 00H". STATEMENT and DEVICE routines reside at
//! 4000H-7FFFH; a BASIC program lies in 8000H-BFFFH and starts with 00H. The
//! MSX CPU is a Z80 (chapter 5, "The CPU (Z80) used in the MSX").
//!
//! The header has a two-byte ID, so the layout is weak: it is recognized
//! only when the reserved bytes are zero, at least one address is set, and
//! every address fits exactly one of the two header positions. A cartridge
//! at 8000H has page 2 alone (page 3 is RAM in the handbook's slot sample),
//! so it holds at most 16 KiB; at 4000H the first 32 KiB are visible.

use super::*;
use crate::formats::MAX_PAYLOAD;

/// Cartridge ID of a ROM cartridge (`CD` marks a SUB-ROM).
const ROM_ID: &[u8; 2] = b"AB";

/// Header fields.
const HEADER_SIZE: usize = 16;
const INIT: usize = 2;
const STATEMENT: usize = 4;
const DEVICE: usize = 6;
const TEXT: usize = 8;
const RESERVED: usize = 0xa;

/// Z80 pages of 16 KiB: page 1 at 4000H, page 2 at 8000H, page 3 at C000H.
const PAGE_SIZE: u32 = 0x4000;
const PAGE1: u32 = 0x4000;
const PAGE2: u32 = 0x8000;
const PAGE3: u32 = 0xc000;

/// The first byte of BASIC text is 00H.
const BASIC_TEXT_START: u8 = 0x00;

/// The four header addresses.
#[derive(Debug, Clone, Copy)]
struct Header {
    init: u16,
    statement: u16,
    device: u16,
    text: u16,
}

impl Header {
    fn read(data: &[u8]) -> Option<Self> {
        let header = data.get(..HEADER_SIZE)?;
        let word = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
        Some(Self {
            init: word(INIT),
            statement: word(STATEMENT),
            device: word(DEVICE),
            text: word(TEXT),
        })
    }

    fn is_empty(self) -> bool {
        self.init == 0 && self.statement == 0 && self.device == 0 && self.text == 0
    }
}

fn base_address(base: MsxBase) -> u32 {
    match base {
        MsxBase::Page1 => PAGE1,
        MsxBase::Page2 => PAGE2,
    }
}

/// The Z80 addresses at which the cartridge is visible from `base`.
fn window(base: MsxBase, rom_size: usize) -> std::ops::Range<u32> {
    let start = base_address(base);
    let visible = u32::try_from(rom_size)
        .unwrap_or(u32::MAX)
        .min(PAGE3 - start);
    start..start + visible
}

/// Why the header does not fit `base`, if it does not.
fn mismatch(data: &[u8], header: Header, base: MsxBase) -> Option<String> {
    if base == MsxBase::Page2 && data.len() > PAGE_SIZE as usize {
        return Some(format!("a {} B ROM does not fit page 2 alone", data.len()));
    }
    let window = window(base, data.len());
    let start = window.start;
    let checks = [
        ("INIT", header.init, PAGE1..PAGE3),
        ("STATEMENT", header.statement, PAGE1..PAGE2),
        ("DEVICE", header.device, PAGE1..PAGE2),
        ("TEXT", header.text, PAGE2..PAGE3),
    ];
    for (name, address, allowed) in checks {
        let address = u32::from(address);
        if address == 0 {
            continue;
        }
        if allowed.contains(&address) && window.contains(&address) {
            continue;
        }
        let low = window.start.max(allowed.start);
        let high = window.end.min(allowed.end);
        return Some(if low < high {
            format!(
                "{name} 0x{address:04X} is outside 0x{low:04X}-0x{:04X}",
                high - 1
            )
        } else {
            format!("{name} 0x{address:04X} is not visible from a header at 0x{start:04X}")
        });
    }
    if header.text != 0 {
        let offset = (u32::from(header.text) - start) as usize;
        if data[offset] != BASIC_TEXT_START {
            return Some(format!(
                "BASIC text at 0x{:04X} does not start with 00H",
                header.text
            ));
        }
    }
    None
}

/// Weak recognition: `AB`, zero reserved bytes, at least one address, and
/// exactly one header position that every address fits.
pub(super) fn detect(data: &[u8]) -> Option<MsxBase> {
    if !data.starts_with(ROM_ID) || data.len() > MAX_PAYLOAD {
        return None;
    }
    let header = Header::read(data)?;
    if data[RESERVED..HEADER_SIZE].iter().any(|&b| b != 0) || header.is_empty() {
        return None;
    }
    let fits = |base: MsxBase| mismatch(data, header, base).is_none();
    match (fits(MsxBase::Page1), fits(MsxBase::Page2)) {
        (true, false) => Some(MsxBase::Page1),
        (false, true) => Some(MsxBase::Page2),
        (true, true) | (false, false) => None,
    }
}

pub(super) fn parse(data: &[u8], base: MsxBase) -> Result<Container<'_>> {
    range(data, "MSX cartridge header", 0, HEADER_SIZE)?;
    if !data.starts_with(ROM_ID) {
        return Err(error("Missing MSX cartridge ID AB at 0x0"));
    }
    if data.len() > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported MSX ROM of {} B: the limit is {}",
            data.len(),
            size_text(MAX_PAYLOAD as u64)
        )));
    }
    let header = Header::read(data).expect("the header range was checked");
    if header.is_empty() {
        return Err(error(
            "Invalid MSX cartridge header: INIT, STATEMENT, DEVICE and TEXT are all 0",
        ));
    }
    if let Some(reason) = mismatch(data, header, base) {
        return Err(error(format!(
            "Invalid MSX cartridge header at 0x{:04X}: {reason}",
            base_address(base)
        )));
    }
    let address = base_address(base);
    let mut c = Container::new(FileFormat::MsxRom, "Z80", "msx");
    c.target = Some(Z80);
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(format!(
        "MSX cartridge ROM; header at 0x{address:04X}; INIT 0x{:04X}; STATEMENT 0x{:04X}; DEVICE \
            0x{:04X}; TEXT 0x{:04X}",
        header.init, header.statement, header.device, header.text
    ));
    if header.init != 0 {
        c.entry = Some(u64::from(header.init));
        c.notes.push(format!(
            "Entry: the INIT routine at 0x{:04X}, which the system calls at reset",
            header.init
        ));
    } else {
        c.notes
            .push("No INIT routine; the cartridge only extends BASIC".into());
    }
    if header.text != 0 {
        c.notes.push(format!(
            "BASIC program text at 0x{:04X} is tokenized BASIC, not Z80 code",
            header.text
        ));
    }
    if header.statement != 0 || header.device != 0 {
        c.notes.push(
            "Expansion routines for CALL statements or devices reside in 0x4000-0x7FFF".into(),
        );
    }
    let visible = window(base, data.len());
    if data.len() > (visible.end - visible.start) as usize {
        c.notes.push(format!(
            "The {} ROM exceeds the 0x{:04X}-0x{:04X} window; mapper banking is not modeled",
            size_text(data.len() as u64),
            visible.start,
            visible.end - 1
        ));
    }
    c.notes.push(
        "Z80 CPU (MSX2 Technical Handbook); the section address is the header address".into(),
    );
    c.push_metadata(
        "msx_header_address",
        "Header address",
        format!("0x{address:04X}"),
    );
    c.push_metadata("msx_init", "INIT address", format!("0x{:04X}", header.init));
    c.sections
        .push(stored_section("Cartridge ROM", u64::from(address), 0, data));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rom(size: usize, init: u16) -> Vec<u8> {
        let mut data = vec![0xc9u8; size];
        data[..HEADER_SIZE].fill(0);
        data[..2].copy_from_slice(ROM_ID);
        data[INIT..INIT + 2].copy_from_slice(&init.to_le_bytes());
        data
    }

    #[test]
    fn the_init_address_selects_the_page() {
        assert_eq!(detect(&rom(0x4000, 0x4010)), Some(MsxBase::Page1));
        assert_eq!(detect(&rom(0x4000, 0x8010)), Some(MsxBase::Page2));
        assert_eq!(detect(&rom(0x8000, 0x8010)), Some(MsxBase::Page1));
        assert_eq!(detect(&rom(0x2000, 0x6010)), None);
    }

    #[test]
    fn reserved_bytes_must_be_zero() {
        let mut data = rom(0x4000, 0x4010);
        data[RESERVED] = 1;
        assert_eq!(detect(&data), None);
    }
}
