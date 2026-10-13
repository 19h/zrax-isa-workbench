//! Sega Mega Drive / Genesis cartridge ROMs.
//!
//! The 68000 vector table fills 0x000-0x0FF (initial SSP at 0, initial PC at
//! 4; rom-properties `M68K_VectorTable`). The ROM header follows at 0x100,
//! big-endian with space-padded strings (rom-properties `MD_RomHeader`,
//! Plutiedev): system type (16), copyright (16), domestic title (48),
//! overseas title (48), serial (14), checksum (2) at 0x18E, device support
//! (16), ROM start and end (4 + 4) at 0x1A0, RAM start and end (4 + 4) at
//! 0x1A8, extra memory (12), modem (12), reserved (40), region (3) at 0x1F0.
//! The TMSS boot ROM accepts `SEGA` at 0x100 or ` SEGA` at 0x101.
//!
//! The checksum is the 16-bit sum of the big-endian words from 0x200 to the
//! end of the file (Genesis Plus GX `getchecksum`); the console does not
//! check it, so a mismatch is reported, not rejected.
//!
//! A `SEGA 32X` ROM adds the 68000 security program user header at 0x3C0:
//! module name (16), version (4), SH-2 program source (4, a ROM offset),
//! SDRAM destination (4), size (4), master and slave SH-2 start addresses
//! and VBRs (4 each), big-endian (rom-properties
//! `_32X_SecurityProgram_UserHeader`; `PicoDrive` `p32x_reset_sh2s`).

use super::*;

/// System type field and the TMSS magic at its start.
const SYSTEM_TYPE: usize = 0x100;
const SYSTEM_TYPE_SIZE: usize = 16;
const TMSS_MAGIC: &[u8; 4] = b"SEGA";

/// The alternative TMSS match: ` SEGA` at 0x101.
const TMSS_ALTERNATIVE: &[u8; 5] = b" SEGA";
const TMSS_ALTERNATIVE_OFFSET: usize = 0x101;

/// `SEGA` with each byte pair swapped, as a byte-swapped dump stores it.
/// Genesis Plus GX matches the full swapped system types; matching the
/// swapped TMSS magic is this parser's generalization.
const SWAPPED_TMSS_MAGIC: &[u8; 4] = b"ESAG";

/// Header fields (rom-properties `MD_RomHeader`).
const COPYRIGHT: usize = 0x110;
const COPYRIGHT_SIZE: usize = 16;
const DOMESTIC_TITLE: usize = 0x120;
const OVERSEAS_TITLE: usize = 0x150;
const TITLE_SIZE: usize = 48;
const SERIAL: usize = 0x180;
const SERIAL_SIZE: usize = 14;
const CHECKSUM: usize = 0x18e;
const DEVICES: usize = 0x190;
const DEVICES_SIZE: usize = 16;
const ROM_START: usize = 0x1a0;
const ROM_END: usize = 0x1a4;
const RAM_START: usize = 0x1a8;
const RAM_END: usize = 0x1ac;
const REGION: usize = 0x1f0;
const REGION_SIZE: usize = 3;

/// End of the ROM header; the checksum covers everything after it.
const HEADER_END: usize = 0x200;

/// Initial stack pointer and program counter in the 68000 vector table.
const INITIAL_SSP: usize = 0;
const INITIAL_PC: usize = 4;

/// Mega-CD disc identifiers at offset 0 (rom-properties `MCD_SystemID`, Sega
/// Retro). A disc also carries a Mega Drive header at 0x100, but its first
/// bytes are not a vector table, so it is not a cartridge ROM.
pub(crate) const MEGA_CD_IDS: [&[u8]; 2] = [b"SEGADISCSYSTEM", b"SEGADATADISC"];

/// System types with a CPU other than the 68000 alone (Plutiedev).
const SYSTEM_32X: &str = "SEGA 32X";
const SYSTEM_TERA286: &str = "SEGA TERA286";

/// SMD copier dumps: a 512-byte header, then 16 KiB blocks whose second
/// half holds the even bytes and first half the odd bytes.
const SMD_HEADER_SIZE: usize = 0x200;
const SMD_BLOCK_SIZE: usize = 0x4000;
const SMD_HALF_BLOCK: usize = 0x2000;

/// 32X security program user header fields (32X Hardware Manual §5.1).
const MARS_HEADER: usize = 0x3c0;
const MARS_MODULE_NAME_SIZE: usize = 16;
const MARS_VERSION: usize = 0x3d0;
const MARS_SOURCE: usize = 0x3d4;
const MARS_DESTINATION: usize = 0x3d8;
const MARS_SIZE: usize = 0x3dc;
const MARS_MASTER_START: usize = 0x3e0;
const MARS_SLAVE_START: usize = 0x3e4;
const MARS_MASTER_VBR: usize = 0x3e8;
const MARS_SLAVE_VBR: usize = 0x3ec;
const MARS_HEADER_END: usize = 0x3f0;

/// `PicoDrive` masks the source and destination with `~0xF0000000`.
const MARS_ADDRESS_MASK: u32 = 0x0fff_ffff;

/// SH-2 address of SDRAM, where the 32X program is copied (`PicoDrive`).
const MARS_SDRAM: u64 = 0x0600_0000;

/// Transform names for slices and sections.
const BYTE_SWAP: &str = "16-bit byte swap";
const SMD_DEINTERLEAVE: &str = "SMD deinterleave";

/// Strong recognition: the TMSS magic in address order, byte-swapped, or in
/// an SMD block. Mega-CD discs are excluded.
pub(super) fn detect(data: &[u8]) -> Option<GenesisDump> {
    if MEGA_CD_IDS.iter().any(|id| data.starts_with(id)) {
        return None;
    }
    if has_tmss_magic(data) {
        return Some(GenesisDump::Linear);
    }
    if has_magic(data, SYSTEM_TYPE, SWAPPED_TMSS_MAGIC) {
        return Some(GenesisDump::ByteSwapped);
    }
    let first_block = data.get(SMD_HEADER_SIZE..SMD_HEADER_SIZE + SMD_BLOCK_SIZE)?;
    let interleaved = data.len() % SMD_BLOCK_SIZE == SMD_HEADER_SIZE
        && has_tmss_magic(&deinterleave_block(first_block));
    interleaved.then_some(GenesisDump::Interleaved)
}

fn has_magic(data: &[u8], offset: usize, magic: &[u8]) -> bool {
    data.get(offset..)
        .is_some_and(|rest| rest.starts_with(magic))
}

/// The check the TMSS boot ROM makes on cartridge bytes in address order.
pub(crate) fn has_tmss_magic(image: &[u8]) -> bool {
    has_magic(image, SYSTEM_TYPE, TMSS_MAGIC)
        || has_magic(image, TMSS_ALTERNATIVE_OFFSET, TMSS_ALTERNATIVE)
}

/// One SMD block in address order: output byte `2i` is block byte
/// `0x2000 + i`, output byte `2i + 1` is block byte `i`.
fn deinterleave_block(block: &[u8]) -> Vec<u8> {
    let (odd, even) = block.split_at(SMD_HALF_BLOCK);
    even.iter()
        .zip(odd)
        .flat_map(|(&even, &odd)| [even, odd])
        .collect()
}

/// Every byte pair swapped; an odd final byte stays in place.
fn swap_pairs(stored: &[u8]) -> Vec<u8> {
    let mut image = stored.to_vec();
    for pair in image.chunks_exact_mut(2) {
        pair.swap(0, 1);
    }
    image
}

/// The cartridge bytes in address order, the file offset they start at, and
/// the transform that produced them.
struct Image<'a> {
    bytes: Cow<'a, [u8]>,
    dump: GenesisDump,
    offset: usize,
    transform: Option<&'static str>,
}

/// The ROM is analyzed as one load section, so it is limited to
/// [`MAX_PAYLOAD`] like every extracted payload.
fn image(data: &[u8], dump: GenesisDump) -> Result<Image<'_>> {
    if data.len() > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported Mega Drive ROM of {} B: the limit is {}",
            data.len(),
            size_text(MAX_PAYLOAD)
        )));
    }
    match dump {
        GenesisDump::Linear => Ok(Image {
            bytes: Cow::Borrowed(data),
            dump,
            offset: 0,
            transform: None,
        }),
        GenesisDump::ByteSwapped => Ok(Image {
            bytes: Cow::Owned(swap_pairs(data)),
            dump,
            offset: 0,
            transform: Some(BYTE_SWAP),
        }),
        GenesisDump::Interleaved => {
            let blocks = data.get(SMD_HEADER_SIZE..).unwrap_or_default();
            if blocks.is_empty() || blocks.len() % SMD_BLOCK_SIZE != 0 {
                return Err(error(format!(
                    "Invalid SMD dump size {} B: not a 512-byte header plus 16 KiB blocks",
                    data.len()
                )));
            }
            let bytes = blocks
                .chunks_exact(SMD_BLOCK_SIZE)
                .flat_map(deinterleave_block)
                .collect();
            Ok(Image {
                bytes: Cow::Owned(bytes),
                dump,
                offset: SMD_HEADER_SIZE,
                transform: Some(SMD_DEINTERLEAVE),
            })
        }
    }
}

/// The 16-bit sum of the big-endian words from 0x200 to the end; a missing
/// final low byte counts as zero (derived from Genesis Plus GX, which reads
/// one byte past the end).
pub(crate) fn checksum(image: &[u8]) -> u16 {
    image
        .get(HEADER_END..)
        .unwrap_or_default()
        .chunks(2)
        .map(|word| u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]))
        .fold(0u16, u16::wrapping_add)
}

/// The ROM header fields that reach notes and metadata.
pub(crate) struct Header {
    pub(crate) system_type: String,
    copyright: String,
    pub(crate) domestic_title: String,
    pub(crate) overseas_title: String,
    pub(crate) serial: String,
    devices: String,
    pub(crate) region: String,
    pub(crate) stored_checksum: u16,
    rom_start: u32,
    rom_end: u32,
    ram_start: u32,
    ram_end: u32,
}

/// The Mega Drive header of a ROM image in address order.
pub(crate) fn header(image: &[u8]) -> Result<Header> {
    if image.len() < HEADER_END {
        return Err(error(format!(
            "Truncated Mega Drive ROM header: {} B of {HEADER_END} B",
            image.len()
        )));
    }
    Ok(Header {
        system_type: text(&image[SYSTEM_TYPE..SYSTEM_TYPE + SYSTEM_TYPE_SIZE]),
        copyright: text(&image[COPYRIGHT..COPYRIGHT + COPYRIGHT_SIZE]),
        domestic_title: text(&image[DOMESTIC_TITLE..DOMESTIC_TITLE + TITLE_SIZE]),
        overseas_title: text(&image[OVERSEAS_TITLE..OVERSEAS_TITLE + TITLE_SIZE]),
        serial: text(&image[SERIAL..SERIAL + SERIAL_SIZE]),
        devices: text(&image[DEVICES..DEVICES + DEVICES_SIZE]),
        region: text(&image[REGION..REGION + REGION_SIZE]),
        stored_checksum: be_u16(image, CHECKSUM)?,
        rom_start: be_u32(image, ROM_START)?,
        rom_end: be_u32(image, ROM_END)?,
        ram_start: be_u32(image, RAM_START)?,
        ram_end: be_u32(image, RAM_END)?,
    })
}

pub(super) fn parse(data: &[u8], dump: GenesisDump) -> Result<Container<'_>> {
    let image = image(data, dump)?;
    let header = header(&image.bytes)?;
    if !has_tmss_magic(&image.bytes) {
        return Err(error("Missing Mega Drive TMSS magic SEGA at 0x100"));
    }
    let initial_ssp = be_u32(&image.bytes, INITIAL_SSP)?;
    let initial_pc = be_u32(&image.bytes, INITIAL_PC)?;
    // A Teradrive ROM boots from the x86 side, so its 68000 vectors are not
    // the entry point (Plutiedev).
    let boots_68000 = header.system_type != SYSTEM_TERA286;
    if boots_68000 {
        expect_initial_pc(initial_pc, image.bytes.len())?;
    }

    let label = Layout::GenesisRom(dump).label();
    let variant = if boots_68000 { "68000" } else { label };
    let mut c = Container::new(FileFormat::GenesisRom, variant, "genesis");
    c.consumed = data.len();
    c.code_sections = true;
    c.notes
        .push(format!("{label}; system type: {}", header.system_type));
    match dump {
        GenesisDump::Linear => {}
        GenesisDump::ByteSwapped => c
            .notes
            .push("Byte-swapped dump: every byte pair was swapped back".into()),
        GenesisDump::Interleaved => c.notes.push(
            "SMD dump: 512-byte copier header skipped and 16 KiB blocks deinterleaved".into(),
        ),
    }
    push_header_notes(&mut c, &header, image.bytes.len());
    if boots_68000 {
        c.target = Some(Target::new(Isa::M68k, 32, Endianness::Big));
        c.entry = Some(u64::from(initial_pc));
        c.notes.push(format!(
            "Initial SSP 0x{initial_ssp:08X}; initial PC 0x{initial_pc:08X}"
        ));
    } else {
        c.notes.push(
            "SEGA TERA286: Teradrive ROM that boots from the x86 side; ISA taken from the code"
                .into(),
        );
    }
    push_checksum(&mut c, &header, &image.bytes);
    c.notes.push(
        "The Z80 sound program is copied by the 68000 at run time; the header does not locate it"
            .into(),
    );
    if header.system_type == SYSTEM_32X {
        push_mars_program(&mut c, data, &image);
    }
    c.sections.push(section(
        "ROM",
        0,
        image.offset,
        data.len() - image.offset,
        image.bytes,
        image.transform,
    ));
    Ok(c)
}

/// The reset vector must address an instruction inside the ROM, which the
/// console maps at address 0; 68000 instructions are word-aligned.
fn expect_initial_pc(initial_pc: u32, rom_size: usize) -> Result<()> {
    let inside = usize::try_from(initial_pc).is_ok_and(|pc| pc < rom_size);
    if !inside {
        return Err(error(format!(
            "Invalid initial PC 0x{initial_pc:08X}: outside the {} ROM",
            size_text(rom_size)
        )));
    }
    if initial_pc % 2 != 0 {
        return Err(error(format!(
            "Invalid initial PC 0x{initial_pc:08X}: not word-aligned"
        )));
    }
    Ok(())
}

fn push_header_notes(c: &mut Container<'_>, header: &Header, rom_size: usize) {
    if !header.domestic_title.is_empty() || !header.overseas_title.is_empty() {
        c.notes.push(format!(
            "Domestic title: {}; overseas title: {}",
            header.domestic_title, header.overseas_title
        ));
    }
    c.notes.push(format!(
        "Serial: {}; copyright: {}; devices: {}; region: {}",
        header.serial, header.copyright, header.devices, header.region
    ));
    c.notes.push(format!(
        "ROM 0x{:06X}-0x{:06X}; RAM 0x{:06X}-0x{:06X}",
        header.rom_start, header.rom_end, header.ram_start, header.ram_end
    ));
    if header.rom_start != 0 {
        c.notes.push(format!(
            "ROM start address 0x{:06X} is not 0x000000",
            header.rom_start
        ));
    }
    let rom_end_inside = usize::try_from(header.rom_end).is_ok_and(|end| end < rom_size);
    if !rom_end_inside {
        c.notes.push(format!(
            "ROM end address 0x{:06X} is beyond the {} image",
            header.rom_end,
            size_text(rom_size)
        ));
    }
    c.push_metadata(
        "genesis_system_type",
        "System type",
        header.system_type.clone(),
    );
    c.push_metadata("genesis_serial", "Serial", header.serial.clone());
    c.push_metadata("genesis_region", "Region", header.region.clone());
    c.push_metadata(
        "genesis_rom_end",
        "ROM end address",
        format!("0x{:06X}", header.rom_end),
    );
}

fn push_checksum(c: &mut Container<'_>, header: &Header, image: &[u8]) {
    let computed = checksum(image);
    let stored = header.stored_checksum;
    if computed == stored {
        c.notes.push(format!(
            "ROM checksum 0x{stored:04X} verified (16-bit sum of the words from 0x200)"
        ));
    } else {
        c.notes.push(format!(
            "ROM checksum 0x{stored:04X} does not match the computed 0x{computed:04X}; the console does not check it"
        ));
    }
    c.push_metadata(
        "genesis_checksum",
        "ROM checksum",
        format!("0x{stored:04X}"),
    );
    c.push_metadata(
        "genesis_checksum_computed",
        "Computed ROM checksum",
        format!("0x{computed:04X}"),
    );
}

/// The 32X security program user header (rom-properties
/// `_32X_SecurityProgram_UserHeader`), big-endian at 0x3C0-0x3EF. Source
/// and destination keep their low 28 bits, as `PicoDrive` reads them.
pub(crate) struct MarsHeader<'a> {
    pub(crate) module_name: &'a [u8],
    pub(crate) version: u32,
    /// Byte offset of the SH-2 program in the ROM.
    pub(crate) source: u32,
    /// Byte offset in SDRAM the program is copied to.
    pub(crate) destination: u32,
    /// Program size in bytes.
    pub(crate) size: u32,
    pub(crate) master_start: u32,
    pub(crate) slave_start: u32,
    pub(crate) master_vbr: u32,
    pub(crate) slave_vbr: u32,
    /// Source or destination had top bits that were masked off.
    pub(crate) masked: bool,
}

/// The 32X user header of a ROM image in address order, when the image is
/// long enough to hold it.
pub(crate) fn mars_header(image: &[u8]) -> Option<MarsHeader<'_>> {
    let word = |at: usize| be_u32(image, at).ok();
    let raw_source = word(MARS_SOURCE)?;
    let raw_destination = word(MARS_DESTINATION)?;
    Some(MarsHeader {
        module_name: image.get(MARS_HEADER..MARS_HEADER + MARS_MODULE_NAME_SIZE)?,
        version: word(MARS_VERSION)?,
        source: raw_source & MARS_ADDRESS_MASK,
        destination: raw_destination & MARS_ADDRESS_MASK,
        size: word(MARS_SIZE)?,
        master_start: word(MARS_MASTER_START)?,
        slave_start: word(MARS_SLAVE_START)?,
        master_vbr: word(MARS_MASTER_VBR)?,
        slave_vbr: word(MARS_SLAVE_VBR)?,
        masked: (raw_source | raw_destination) & !MARS_ADDRESS_MASK != 0,
    })
}

/// The 32X SH-2 program named by the security program user header, as a
/// child for the SH-2 (big-endian `SuperH`; the header names no SH-2 model).
fn push_mars_program<'a>(c: &mut Container<'a>, data: &'a [u8], image: &Image<'_>) {
    let bytes = &image.bytes;
    let Some(mars) = mars_header(bytes).filter(|_| bytes.len() >= MARS_HEADER_END) else {
        c.notes
            .push("SEGA 32X: the security program user header at 0x3C0 is missing".into());
        return;
    };
    let MarsHeader {
        source,
        destination,
        size,
        master_start: master,
        slave_start: slave,
        ..
    } = mars;
    c.notes.push(format!(
        "SEGA 32X: SH-2 program at ROM 0x{source:X} + {size} B, copied to SDRAM 0x{:08X}; master SH-2 start 0x{master:08X}; slave SH-2 start 0x{slave:08X}",
        MARS_SDRAM + u64::from(destination)
    ));
    if size == 0 {
        c.notes
            .push("SEGA 32X: the SH-2 program size is 0; nothing extracted".into());
        return;
    }
    let start = source as usize;
    let Some(program) = start
        .checked_add(size as usize)
        .and_then(|end| bytes.get(start..end))
    else {
        c.notes
            .push("SEGA 32X: the SH-2 program range lies outside the ROM; not extracted".into());
        return;
    };
    let label = "32X SH-2 program";
    let child = match image.dump {
        GenesisDump::Linear => Child::stored(label, start, &data[start..start + program.len()]),
        GenesisDump::ByteSwapped => Child::decoded(
            label,
            start,
            program.len(),
            Cow::Owned(program.to_vec()),
            BYTE_SWAP,
        ),
        GenesisDump::Interleaved => {
            // The range is stored scattered over whole blocks.
            let first_block = start / SMD_BLOCK_SIZE * SMD_BLOCK_SIZE;
            let last_block = (start + program.len() - 1) / SMD_BLOCK_SIZE;
            let end_block = (last_block + 1) * SMD_BLOCK_SIZE;
            Child::decoded(
                label,
                SMD_HEADER_SIZE + first_block,
                end_block - first_block,
                Cow::Owned(program.to_vec()),
                SMD_DEINTERLEAVE,
            )
        }
    };
    c.children
        .push(child.with_target(Target::new(Isa::Sh, 32, Endianness::Big)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smd_blocks_store_odd_bytes_first() {
        let mut block = vec![0u8; SMD_BLOCK_SIZE];
        block[SMD_HALF_BLOCK] = 0xaa;
        block[0] = 0xbb;
        let image = deinterleave_block(&block);
        assert_eq!(&image[..2], &[0xaa, 0xbb]);
        assert_eq!(image.len(), SMD_BLOCK_SIZE);
    }

    #[test]
    fn checksum_sums_words_after_the_header_and_pads_an_odd_byte() {
        let mut image = vec![0u8; HEADER_END];
        image.extend_from_slice(&[0x12, 0x34, 0xff, 0xff, 0x01]);
        assert_eq!(
            checksum(&image),
            0x1234u16.wrapping_add(0xffff).wrapping_add(0x0100)
        );
    }

    #[test]
    fn mega_cd_discs_are_not_cartridge_roms() {
        let mut disc = vec![0x20u8; 0x200];
        disc[..14].copy_from_slice(b"SEGADISCSYSTEM");
        disc[0x100..0x104].copy_from_slice(TMSS_MAGIC);
        assert_eq!(detect(&disc), None);
    }
}
