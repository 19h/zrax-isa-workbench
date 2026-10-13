//! ZX Spectrum memory snapshots: `.z80` (versions 1-3) and `.sna` (48K and
//! 128K).
//!
//! `.z80` (World of Spectrum "Z80 File Format", rev. 1.12): a 30-byte
//! header with the Z80 registers (little-endian words: PC at 6, SP at 8,
//! flags at 12 with bit 5 "compressed" and 255 meaning 1, interrupt mode in
//! bits 0-1 of byte 29). Version 1 (PC not 0) stores 48 KiB of RAM,
//! compressed or not; compressed data ends with `00 ED ED 00`. Versions 2
//! and 3 set PC to 0 and add a header whose length word at 30 is 23 (v2) or
//! 54 or 55 (v3), with the PC at 32, the hardware mode at 34, the last write
//! to port 0x7FFD at 35 and the modify-hardware bit 7 at 37; 16 KiB memory
//! blocks follow, each with a length word (0xFFFF: 16384 bytes stored
//! uncompressed) and a page number. The compression replaces runs with
//! `ED ED nn bb`, "byte bb repeated nn times"; [`decode_rle`] undoes it.
//!
//! `.sna` (World of Spectrum "formats.htm", rev. 1.13): a 27-byte header (SP
//! at 23, interrupt mode at 25, border at 26) and RAM 0x4000-0xFFFF, 49179
//! bytes; the PC is on the stack. The 128K form adds the PC, port 0x7FFD
//! and the TR-DOS flag after the first 49179 bytes (banks 5, 2 and the paged
//! bank), then the remaining banks in ascending order: 131103 bytes, or
//! 147487 when the paged bank is 2 or 5 and is stored twice. Port 0x7FFD
//! bits 0-2 select the RAM bank at 0xC000; bank 5 is always at 0x4000 and
//! bank 2 at 0x8000 (World of Spectrum "128kreference.htm").
//!
//! Neither format has a magic value, so both are weak: a `.z80` file is
//! recognized only when every block decodes to its exact size and the pages
//! are exactly the ones its machine saves; a `.sna` file only at an exact
//! size with consistent registers. The ZX Spectrum CPU is a Z80.

use super::*;

/// Compression escape: `ED ED nn bb`.
const ESCAPE: u8 = 0xed;
const RUN_SIZE: usize = 4;

/// Version 1 end marker.
const V1_END_MARKER: [u8; 4] = [0x00, 0xed, 0xed, 0x00];

/// The transform name for decoded blocks.
const Z80_RLE: &str = "Z80 RLE";

/// Memory sizes.
const PAGE_SIZE: usize = 16 << 10;
const RAM_48K: usize = 48 << 10;
const RAM_BASE: u16 = 0x4000;
const RAM_START: u64 = RAM_BASE as u64;

/// `.z80` header fields.
const Z80_HEADER_SIZE: usize = 30;
const Z80_PC: usize = 6;
const Z80_SP: usize = 8;
const Z80_FLAGS: usize = 12;
const Z80_FLAGS_COMPAT: u8 = 255;
const Z80_COMPRESSED: u8 = 1 << 5;
const Z80_IM_FLAGS: usize = 29;
const IM_MASK: u8 = 0x3;
const MAX_IM: u8 = 2;
const EXTRA_LENGTH: usize = 30;
const EXTRA_PC: usize = 32;
const HARDWARE_MODE: usize = 34;
const PORT_7FFD: usize = 35;
const HARDWARE_FLAGS: usize = 37;
const MODIFY_HARDWARE: u8 = 1 << 7;
const EXTRA_START: usize = 32;

/// Additional header lengths of versions 2 and 3.
const V2_EXTRA_LENGTH: u16 = 23;
const V3_EXTRA_LENGTHS: [u16; 2] = [54, 55];

/// Memory block header: length (2), page (1); length 0xFFFF stores 16 KiB.
const BLOCK_HEADER_SIZE: usize = 3;
const UNCOMPRESSED_BLOCK: u16 = 0xffff;

/// Port 0x7FFD bits 0-2: the RAM bank at 0xC000.
const PAGED_BANK_MASK: u8 = 0x7;

/// RAM banks fixed at 0x4000 and 0x8000 on 128K machines, and where the
/// paged bank appears.
const SCREEN_BANK: u8 = 5;
const SECOND_BANK: u8 = 2;
const BANKS_128K: u8 = 8;
const SECOND_BANK_ADDRESS: u64 = 0x8000;
const PAGED_BANK_ADDRESS: u64 = 0xc000;

/// 48K and `SamRam` pages: page, Z80 address and role (World of Spectrum
/// page table; pages 6 and 7 are the `SamRam` shadow RAM).
const PAGES_48K: [(u8, u64, &str); 5] = [
    (8, 0x4000, ""),
    (4, 0x8000, ""),
    (5, 0xc000, ""),
    (6, 0x8000, " (shadow)"),
    (7, 0xc000, " (shadow)"),
];

/// `.z80` 128K page numbers 3-10 hold RAM banks 0-7.
const FIRST_RAM_PAGE: u8 = 3;

/// `.sna` fields and sizes.
const SNA_HEADER_SIZE: usize = 27;
const SNA_SP: usize = 23;
const SNA_IM: usize = 25;
const SNA_BORDER: usize = 26;
const MAX_BORDER: u8 = 7;
const SNA_48K_SIZE: usize = SNA_HEADER_SIZE + RAM_48K;
const SNA_128K_EXTRA: usize = 4;
const SNA_128K_SIZES: [usize; 2] = [
    SNA_48K_SIZE + SNA_128K_EXTRA + 5 * PAGE_SIZE,
    SNA_48K_SIZE + SNA_128K_EXTRA + 6 * PAGE_SIZE,
];
const SNA_PC: usize = SNA_48K_SIZE;
const SNA_PORT_7FFD: usize = SNA_48K_SIZE + 2;
const SNA_TRDOS: usize = SNA_48K_SIZE + 3;

/// What a `.z80` hardware mode says about memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Machine {
    /// 16K Spectrum (a 48K mode with the modify-hardware bit).
    K16,
    /// 48K Spectrum, with or without Interface 1 or M.G.T.
    K48,
    /// 48K Spectrum with the `SamRam`.
    SamRam,
    /// 128K-class machine (128K, +2, +2A, +3, Pentagon).
    K128,
}

impl Machine {
    /// The pages a snapshot of this machine saves.
    fn pages(self) -> &'static [u8] {
        match self {
            Self::K16 => &[8],
            Self::K48 => &[4, 5, 8],
            Self::SamRam => &[4, 5, 6, 7, 8],
            Self::K128 => &[3, 4, 5, 6, 7, 8, 9, 10],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::K16 => "16K",
            Self::K48 => "48K",
            Self::SamRam => "48K with SamRam",
            Self::K128 => "128K-class",
        }
    }
}

/// The machine a version 2 or 3 hardware mode names. Didaktik-Kompakt,
/// Scorpion and the Timex machines are not supported: the sources fetched
/// do not describe their paging.
fn machine(version: Z80Version, mode: u8, modify: bool) -> Option<Machine> {
    // Modes 0-1 are 48K (with Interface 1), 2 SamRam; 3 is 128K in version
    // 2 and 48K + M.G.T. in version 3, which moves 128K to 4-6; 7-9, 12 and
    // 13 are the +3, Pentagon, +2 and +2A extensions.
    let machine = match (version, mode) {
        (_, 0 | 1) | (Z80Version::V3, 3) => Machine::K48,
        (_, 2) => Machine::SamRam,
        (Z80Version::V2, 3 | 4) | (Z80Version::V3, 4..=6) | (_, 7 | 8 | 9 | 12 | 13) => {
            Machine::K128
        }
        _ => return None,
    };
    Some(if modify && machine == Machine::K48 {
        Machine::K16
    } else {
        machine
    })
}

/// Decode the `.z80` run-length scheme until `expected` bytes are out:
/// `ED ED nn bb` is `nn` copies of `bb`, any other byte is itself. Returns
/// the bytes and how much input they took.
///
/// # Errors
///
/// A run that overshoots `expected`, or input that ends first.
fn decode_rle(input: &[u8], expected: usize) -> Result<(Vec<u8>, usize)> {
    let mut output = Vec::with_capacity(expected);
    let mut pos = 0;
    while output.len() < expected {
        let rest = &input[pos..];
        match rest {
            [ESCAPE, ESCAPE, count, value, ..] => {
                let count = usize::from(*count);
                if output.len() + count > expected {
                    return Err(error(format!(
                        "Invalid .z80 run at 0x{pos:X}: {count} B overshoot the {expected} B block"
                    )));
                }
                output.resize(output.len() + count, *value);
                pos += RUN_SIZE;
            }
            [ESCAPE, ESCAPE, ..] => {
                return Err(error(format!(
                    "Truncated .z80 run at 0x{pos:X}: ED ED without count and value"
                )));
            }
            [literal, ..] => {
                output.push(*literal);
                pos += 1;
            }
            [] => {
                return Err(error(format!(
                    "Truncated .z80 block: {} B of {expected} B decoded",
                    output.len()
                )));
            }
        }
    }
    Ok((output, pos))
}

/// The version a `.z80` header declares, if the header is plausible.
fn z80_version(data: &[u8]) -> Option<Z80Version> {
    let header = data.get(..Z80_HEADER_SIZE)?;
    if header[Z80_IM_FLAGS] & IM_MASK > MAX_IM {
        return None;
    }
    if u16::from_le_bytes([header[Z80_PC], header[Z80_PC + 1]]) != 0 {
        return Some(Z80Version::V1);
    }
    let extra = u16::from_le_bytes([*data.get(EXTRA_LENGTH)?, *data.get(EXTRA_LENGTH + 1)?]);
    if extra == V2_EXTRA_LENGTH {
        Some(Z80Version::V2)
    } else if V3_EXTRA_LENGTHS.contains(&extra) {
        Some(Z80Version::V3)
    } else {
        None
    }
}

/// Whether version 1 flags mark the 48 KiB block as compressed.
fn is_compressed(flags: u8) -> bool {
    let flags = if flags == Z80_FLAGS_COMPAT { 1 } else { flags };
    flags & Z80_COMPRESSED != 0
}

/// Weak recognition: a `.z80` file whose blocks decode exactly, or a
/// `.sna` file of an exact size with consistent registers. An uncompressed
/// version 1 file is identified by its size alone, which is too little.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if let Some(version) = z80_version(data) {
        let uncompressed_v1 = version == Z80Version::V1 && !is_compressed(data[Z80_FLAGS]);
        if !uncompressed_v1 && z80_sections(data, version).is_ok() {
            return Some(Layout::Z80Snapshot(version));
        }
    }
    sna_model(data)
        .filter(|&model| sna_mismatch(data, model).is_none())
        .map(Layout::SnaSnapshot)
}

/// Decoded `.z80` memory and the machine it belongs to.
struct Snapshot<'a> {
    machine: Machine,
    pc: u16,
    paged_bank: Option<u8>,
    sections: Vec<Section<'a>>,
}

fn z80_sections(data: &[u8], version: Z80Version) -> Result<Snapshot<'_>> {
    let header = range(data, ".z80 header", 0, Z80_HEADER_SIZE)?;
    if header[Z80_IM_FLAGS] & IM_MASK > MAX_IM {
        return Err(error(format!(
            "Invalid .z80 interrupt mode {} at 0x{Z80_IM_FLAGS:X}",
            header[Z80_IM_FLAGS] & IM_MASK
        )));
    }
    match version {
        Z80Version::V1 => z80_v1(data, header),
        Z80Version::V2 | Z80Version::V3 => z80_paged(data, version),
    }
}

/// Version 1: one 48 KiB block at 0x4000, compressed with an end marker or
/// stored as-is.
fn z80_v1<'a>(data: &'a [u8], header: &[u8]) -> Result<Snapshot<'a>> {
    let pc = u16::from_le_bytes([header[Z80_PC], header[Z80_PC + 1]]);
    let stored = &data[Z80_HEADER_SIZE..];
    let section = if is_compressed(header[Z80_FLAGS]) {
        let (ram, consumed) = decode_rle(stored, RAM_48K)?;
        if stored[consumed..] != V1_END_MARKER {
            return Err(error(format!(
                "Invalid .z80 version 1 data: the 48 KiB block does not end with 00 ED ED 00 at \
                    the end of the file (0x{:X})",
                Z80_HEADER_SIZE + consumed
            )));
        }
        Section {
            label: "48K RAM".to_string(),
            address: RAM_START,
            offset: Z80_HEADER_SIZE,
            stored_size: consumed,
            data: Cow::Owned(ram),
            transform: Some(Z80_RLE),
        }
    } else {
        if stored.len() != RAM_48K {
            return Err(error(format!(
                "Invalid .z80 version 1 size: {} B of uncompressed RAM, not {RAM_48K} B",
                stored.len()
            )));
        }
        stored_section("48K RAM", RAM_START, Z80_HEADER_SIZE, stored)
    };
    Ok(Snapshot {
        machine: Machine::K48,
        pc,
        paged_bank: None,
        sections: vec![section],
    })
}

/// Versions 2 and 3: 16 KiB pages up to the end of the file, exactly the
/// pages the machine saves.
fn z80_paged(data: &[u8], version: Z80Version) -> Result<Snapshot<'_>> {
    let declared = le_u16(data, EXTRA_LENGTH)?;
    let valid = match version {
        Z80Version::V2 => declared == V2_EXTRA_LENGTH,
        Z80Version::V3 => V3_EXTRA_LENGTHS.contains(&declared),
        // Version 1 has no additional header.
        Z80Version::V1 => false,
    };
    if !valid {
        return Err(error(format!(
            "Invalid .z80 additional header length {declared} at 0x{EXTRA_LENGTH:X}"
        )));
    }
    let extra = usize::from(declared);
    let blocks_start = EXTRA_START + extra;
    range(data, ".z80 additional header", EXTRA_START, extra)?;
    let mode = data[HARDWARE_MODE];
    let modify = data[HARDWARE_FLAGS] & MODIFY_HARDWARE != 0;
    let machine = machine(version, mode, modify)
        .ok_or_else(|| error(format!("Unsupported .z80 hardware mode {mode}")))?;
    let paged_bank = (machine == Machine::K128).then(|| data[PORT_7FFD] & PAGED_BANK_MASK);
    let mut sections = Vec::new();
    let mut seen = Vec::new();
    let mut offset = blocks_start;
    while offset < data.len() {
        let length = le_u16(data, offset)?;
        let page = byte(data, offset + 2)?;
        let contents = offset + BLOCK_HEADER_SIZE;
        if !machine.pages().contains(&page) || seen.contains(&page) {
            return Err(error(format!(
                "Invalid .z80 page {page} at 0x{offset:X} for a {} snapshot",
                machine.name()
            )));
        }
        seen.push(page);
        let (label, address) = page_location(machine, page, paged_bank);
        let section = if length == UNCOMPRESSED_BLOCK {
            stored_section(
                label,
                address,
                contents,
                range(data, ".z80 page", contents, PAGE_SIZE)?,
            )
        } else {
            let stored = range(data, ".z80 page", contents, usize::from(length))?;
            let (page_bytes, consumed) = decode_rle(stored, PAGE_SIZE)?;
            if consumed != stored.len() {
                return Err(error(format!(
                    "Invalid .z80 page {page} at 0x{offset:X}: 16 KiB decoded from {consumed} of \
                        {length} B"
                )));
            }
            Section {
                label,
                address,
                offset: contents,
                stored_size: stored.len(),
                data: Cow::Owned(page_bytes),
                transform: Some(Z80_RLE),
            }
        };
        offset = contents + section.stored_size;
        sections.push(section);
    }
    if seen.len() != machine.pages().len() {
        return Err(error(format!(
            "Missing .z80 pages: {} of the {} pages a {} snapshot saves",
            seen.len(),
            machine.pages().len(),
            machine.name()
        )));
    }
    Ok(Snapshot {
        machine,
        pc: le_u16(data, EXTRA_PC)?,
        paged_bank,
        sections,
    })
}

/// A `.z80` page's label and Z80 address. 128K pages 3-10 are RAM banks
/// 0-7; the 48K and `SamRam` pages map as [`PAGES_48K`] lists.
fn page_location(machine: Machine, page: u8, paged_bank: Option<u8>) -> (String, u64) {
    if machine == Machine::K128 {
        return bank_location(page - FIRST_RAM_PAGE, paged_bank);
    }
    let (address, role) = PAGES_48K
        .iter()
        .find(|(known, _, _)| *known == page)
        .map_or((RAM_START, ""), |(_, address, role)| (*address, *role));
    (
        format!(
            "RAM 0x{address:04X}-0x{:04X}{role} (page {page})",
            address + PAGE_SIZE as u64 - 1
        ),
        address,
    )
}

/// A 128K RAM bank's label and address: bank 5 at 0x4000, bank 2 at
/// 0x8000, the paged bank at 0xC000, and the others at 0xC000, where they
/// can be paged in.
fn bank_location(bank: u8, paged_bank: Option<u8>) -> (String, u64) {
    match bank {
        SCREEN_BANK => (format!("RAM bank {bank} (0x4000)"), RAM_START),
        SECOND_BANK => (format!("RAM bank {bank} (0x8000)"), SECOND_BANK_ADDRESS),
        _ if Some(bank) == paged_bank => (
            format!("RAM bank {bank} (paged at 0xC000)"),
            PAGED_BANK_ADDRESS,
        ),
        _ => (format!("RAM bank {bank} (paged out)"), PAGED_BANK_ADDRESS),
    }
}

pub(super) fn parse_z80(data: &[u8], version: Z80Version) -> Result<Container<'_>> {
    let snapshot = z80_sections(data, version)?;
    let header = &data[..Z80_HEADER_SIZE];
    let mut c = snapshot_container(Layout::Z80Snapshot(version), data.len());
    c.entry = Some(u64::from(snapshot.pc));
    c.notes.push(format!(
        "{}; {} machine; PC 0x{:04X}; SP 0x{:04X}; interrupt mode {}",
        Layout::Z80Snapshot(version).label(),
        snapshot.machine.name(),
        snapshot.pc,
        u16::from_le_bytes([header[Z80_SP], header[Z80_SP + 1]]),
        header[Z80_IM_FLAGS] & IM_MASK
    ));
    if version != Z80Version::V1 {
        c.notes
            .push(format!("Hardware mode {}", data[HARDWARE_MODE]));
    }
    if let Some(bank) = snapshot.paged_bank {
        c.notes.push(format!(
            "Port 0x7FFD 0x{:02X}: RAM bank {bank} at 0xC000",
            data[PORT_7FFD]
        ));
    }
    c.push_metadata(
        "zxsnap_machine",
        "Machine",
        snapshot.machine.name().to_string(),
    );
    c.sections = snapshot.sections;
    Ok(c)
}

/// The `.sna` model an exact file size implies.
fn sna_model(data: &[u8]) -> Option<SnaModel> {
    if data.len() == SNA_48K_SIZE {
        Some(SnaModel::K48)
    } else if SNA_128K_SIZES.contains(&data.len()) {
        Some(SnaModel::K128)
    } else {
        None
    }
}

/// Why a `.sna` file is inconsistent, if it is.
fn sna_mismatch(data: &[u8], model: SnaModel) -> Option<String> {
    let expected_size = match model {
        SnaModel::K48 => data.len() == SNA_48K_SIZE,
        SnaModel::K128 => SNA_128K_SIZES.contains(&data.len()),
    };
    if !expected_size {
        return Some(format!("{} B is not a .sna size", data.len()));
    }
    if data[SNA_IM] > MAX_IM {
        return Some(format!("interrupt mode {} is not 0-2", data[SNA_IM]));
    }
    if data[SNA_BORDER] > MAX_BORDER {
        return Some(format!("border colour {} is not 0-7", data[SNA_BORDER]));
    }
    match model {
        SnaModel::K48 => {
            let sp = u16::from_le_bytes([data[SNA_SP], data[SNA_SP + 1]]);
            (u64::from(sp) < RAM_START || sp == u16::MAX)
                .then(|| format!("SP 0x{sp:04X} does not hold the PC in RAM"))
        }
        SnaModel::K128 => {
            let bank = data[SNA_PORT_7FFD] & PAGED_BANK_MASK;
            let stored_twice = matches!(bank, SCREEN_BANK | SECOND_BANK);
            if data[SNA_TRDOS] > 1 {
                Some(format!("TR-DOS flag {} is not 0 or 1", data[SNA_TRDOS]))
            } else if stored_twice != (data.len() == SNA_128K_SIZES[1]) {
                Some(format!(
                    "paged bank {bank} does not match the {} B size",
                    data.len()
                ))
            } else {
                None
            }
        }
    }
}

pub(super) fn parse_sna(data: &[u8], model: SnaModel) -> Result<Container<'_>> {
    if let Some(reason) = sna_mismatch(data, model) {
        return Err(error(format!("Invalid .sna snapshot: {reason}")));
    }
    let layout = Layout::SnaSnapshot(model);
    let mut c = snapshot_container(layout, data.len());
    let sp = u16::from_le_bytes([data[SNA_SP], data[SNA_SP + 1]]);
    match model {
        SnaModel::K48 => {
            // The PC was pushed onto the stack so that RETN restarts it.
            let at = SNA_HEADER_SIZE + usize::from(sp - RAM_BASE);
            let pc = u16::from_le_bytes([data[at], data[at + 1]]);
            c.entry = Some(u64::from(pc));
            c.notes.push(format!(
                "{}; PC 0x{pc:04X} read from the stack at SP 0x{sp:04X}; interrupt mode {}",
                layout.label(),
                data[SNA_IM]
            ));
            c.sections.push(stored_section(
                "48K RAM",
                RAM_START,
                SNA_HEADER_SIZE,
                &data[SNA_HEADER_SIZE..],
            ));
        }
        SnaModel::K128 => {
            let pc = le_u16(data, SNA_PC)?;
            let bank = data[SNA_PORT_7FFD] & PAGED_BANK_MASK;
            c.entry = Some(u64::from(pc));
            c.notes.push(format!(
                "{}; PC 0x{pc:04X}; SP 0x{sp:04X}; interrupt mode {}; port 0x7FFD 0x{:02X}: RAM \
                    bank {bank} at 0xC000; TR-DOS ROM paged: {}",
                layout.label(),
                data[SNA_IM],
                data[SNA_PORT_7FFD],
                data[SNA_TRDOS]
            ));
            push_sna_128k_banks(&mut c, data, bank);
        }
    }
    c.push_metadata("zxsnap_machine", "Machine", model_name(model).to_string());
    Ok(c)
}

fn model_name(model: SnaModel) -> &'static str {
    match model {
        SnaModel::K48 => "48K",
        SnaModel::K128 => "128K",
    }
}

/// Banks 5, 2 and the paged bank, then the remaining banks in ascending
/// order; the paged bank is stored twice when it is 5 or 2.
fn push_sna_128k_banks<'a>(c: &mut Container<'a>, data: &'a [u8], paged: u8) {
    let paged_bank = Some(paged);
    let first = [SCREEN_BANK, SECOND_BANK];
    let mut offset = SNA_HEADER_SIZE;
    for bank in first {
        let (label, address) = bank_location(bank, paged_bank);
        c.sections.push(stored_section(
            label,
            address,
            offset,
            &data[offset..offset + PAGE_SIZE],
        ));
        offset += PAGE_SIZE;
    }
    let duplicate = if first.contains(&paged) {
        " (paged at 0xC000, stored twice)"
    } else {
        " (paged at 0xC000)"
    };
    c.sections.push(stored_section(
        format!("RAM bank {paged}{duplicate}"),
        PAGED_BANK_ADDRESS,
        offset,
        &data[offset..offset + PAGE_SIZE],
    ));
    offset = SNA_48K_SIZE + SNA_128K_EXTRA;
    for bank in (0..BANKS_128K).filter(|b| !first.contains(b) && *b != paged) {
        let (label, address) = bank_location(bank, paged_bank);
        c.sections.push(stored_section(
            label,
            address,
            offset,
            &data[offset..offset + PAGE_SIZE],
        ));
        offset += PAGE_SIZE;
    }
}

/// The container both snapshot formats share.
fn snapshot_container<'a>(layout: Layout, size: usize) -> Container<'a> {
    let mut c = Container::new(FileFormat::ZxSnapshot, "Z80", "zxsnap");
    c.target = Some(Z80);
    c.consumed = size;
    c.code_sections = true;
    c.notes.push(format!(
        "{}: a memory image, so RAM holds data, the screen and code alike; the ZX Spectrum CPU is \
            a Z80",
        layout.label()
    ));
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_expand_and_literals_pass_through() {
        let (out, used) = decode_rle(&[1, ESCAPE, ESCAPE, 3, 7, ESCAPE, 2], 6).unwrap();
        assert_eq!(out, vec![1, 7, 7, 7, ESCAPE, 2]);
        assert_eq!(used, 7);
    }

    #[test]
    fn overshooting_or_truncated_runs_are_errors() {
        assert!(decode_rle(&[ESCAPE, ESCAPE, 9, 0], 4).is_err());
        assert!(decode_rle(&[ESCAPE, ESCAPE, 2], 4).is_err());
        assert!(decode_rle(&[1, 2], 4).is_err());
    }

    #[test]
    fn hardware_modes_differ_between_versions() {
        assert_eq!(machine(Z80Version::V2, 3, false), Some(Machine::K128));
        assert_eq!(machine(Z80Version::V3, 3, false), Some(Machine::K48));
        assert_eq!(machine(Z80Version::V3, 0, true), Some(Machine::K16));
        assert_eq!(machine(Z80Version::V3, 10, false), None);
    }

    #[test]
    fn sna_128k_sizes_follow_the_paged_bank() {
        assert_eq!(SNA_128K_SIZES, [131_103, 147_487]);
        assert_eq!(SNA_48K_SIZE, 49_179);
    }
}
