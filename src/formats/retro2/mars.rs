//! Sega 32X cartridge ROMs.
//!
//! A 32X ROM is a Mega Drive ROM: 68000 vectors (initial PC at 4) and the
//! Mega Drive header at 0x100 (rom-properties `MD_RomHeader`: system type
//! (16), domestic title (48) at 0x120, overseas title (48) at 0x150, serial
//! (14) at 0x180, checksum (2) at 0x18E, region at 0x1F0), with `SEGA` at
//! 0x100 or ` SEGA` at 0x101 for the TMSS boot ROM.
//!
//! The 32X adds the user header at 0x3C0-0x3EF (32X Hardware Manual §5.1;
//! rom-properties `_32X_SecurityProgram_UserHeader`), big-endian: module
//! name (16), version (4), source address (4) at 0x3D4, destination address
//! (4) at 0x3D8, size (4) at 0x3DC, master and slave SH-2 start addresses (4
//! each) at 0x3E0 and 0x3E4, master and slave SH-2 VBRs (4 each) at 0x3E8 and
//! 0x3EC. The source is a byte offset in the ROM, the destination a byte
//! offset in SDRAM, the size in bytes; the boot ROM copies long words, so
//! all seven values must be multiples of 4 or an address error occurs. The
//! initial program `ICD_MARS.PRG` must start at 0x3F0 unchanged (§5.2);
//! rom-properties `MegaDrive.cpp` finds its text `MARS Initial & Security
//! Program` at 0x512, which is the recognition anchor here.
//!
//! `PicoDrive` `p32x_reset_sh2s` masks source and destination with
//! `~0xF0000000` and copies from SH-2 address 0x02000000 + source (the
//! cartridge) to 0x06000000 + destination (SDRAM, 2 Mbit = 256 KiB per the
//! manual). The manual names the CPUs "SH2 (SH7095)"; they run big-endian
//! code (derived: the SH-2 boot ROM reads the big-endian header long words
//! directly).

use super::*;
use crate::formats::container::Child;
use crate::formats::retro::genesis::{self, MarsHeader, MEGA_CD_IDS};
use crate::formats::MAX_PAYLOAD;
use std::ops::Range;

/// The security program text that rom-properties checks.
const SECURITY_TEXT: &[u8] = b"MARS Initial & Security Program";
const SECURITY_TEXT_OFFSET: usize = 0x512;

/// The 68000 initial program counter in the vector table.
const INITIAL_PC: usize = 4;

/// The boot ROM copies long words.
const LONG_WORD: u32 = 4;

/// SH-2 addresses of the cartridge and of SDRAM (`PicoDrive`), and the
/// SDRAM size (2 Mbit, 32X Hardware Manual "SDRAM Component").
const SH2_CARTRIDGE: u64 = 0x0200_0000;
const SH2_SDRAM: u64 = 0x0600_0000;
const SDRAM_SIZE: u64 = 256 << 10;

/// The SH-2 model the 32X Hardware Manual names.
const SH2_VARIANT: &str = "SH-2 (SH7095)";

/// A linear Mega Drive ROM that carries the 32X security program.
pub(super) fn detect(data: &[u8]) -> bool {
    !MEGA_CD_IDS.iter().any(|id| data.starts_with(id))
        && genesis::has_tmss_magic(data)
        && has_magic(data, SECURITY_TEXT_OFFSET, SECURITY_TEXT)
}

/// The 32X user header, whose seven address and size values must be
/// multiples of 4: the boot ROM copies long words.
fn user_header(data: &[u8]) -> Result<MarsHeader<'_>> {
    let user = genesis::mars_header(data).ok_or_else(|| {
        error(format!(
            "Truncated 32X user header: {} B of the ROM present",
            data.len()
        ))
    })?;
    let aligned = [
        ("source address", user.source),
        ("destination address", user.destination),
        ("size", user.size),
        ("master SH-2 start address", user.master_start),
        ("slave SH-2 start address", user.slave_start),
        ("master SH-2 VBR", user.master_vbr),
        ("slave SH-2 VBR", user.slave_vbr),
    ];
    for (name, value) in aligned {
        if value % LONG_WORD != 0 {
            return Err(error(format!(
                "Invalid 32X user header: {name} 0x{value:08X} is not a multiple of 4"
            )));
        }
    }
    Ok(user)
}

/// The SH-2 program's file range: it must lie in the ROM and fit in SDRAM.
fn program_range(data: &[u8], user: &MarsHeader<'_>) -> Result<Option<Range<usize>>> {
    if user.size == 0 {
        return Ok(None);
    }
    let start = usize::try_from(user.source)
        .map_err(|_| error(format!("Invalid 32X source address 0x{:08X}", user.source)))?;
    let size = usize::try_from(user.size)
        .map_err(|_| error(format!("Invalid 32X program size 0x{:08X}", user.size)))?;
    range(data, "32X SH-2 program", start, size)?;
    if u64::from(user.destination) + u64::from(user.size) > SDRAM_SIZE {
        return Err(error(format!(
            "Invalid 32X SH-2 program: SDRAM 0x{:X} + {size} B exceeds the {} SDRAM",
            user.destination,
            size_text(SDRAM_SIZE)
        )));
    }
    Ok(Some(start..start + size))
}

/// The 68000 reset vector must address an even byte inside the ROM.
fn expect_initial_pc(initial_pc: u32, rom_size: usize) -> Result<()> {
    let inside = usize::try_from(initial_pc).is_ok_and(|pc| pc < rom_size);
    if !inside || initial_pc % 2 != 0 {
        return Err(error(format!(
            "Invalid initial PC 0x{initial_pc:08X}: not an even address inside the {} ROM",
            size_text(rom_size as u64)
        )));
    }
    Ok(())
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !detect(data) {
        return Err(error(
            "Missing 32X security program text MARS Initial & Security Program at 0x512",
        ));
    }
    if data.len() > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported 32X ROM of {} B: the limit is {}",
            data.len(),
            size_text(MAX_PAYLOAD as u64)
        )));
    }
    let user = user_header(data)?;
    let program = program_range(data, &user)?;
    let initial_pc = be_u32(data, INITIAL_PC)?;
    expect_initial_pc(initial_pc, data.len())?;

    let mut c = Container::new(FileFormat::Sega32xRom, "68000", "sega32x");
    c.target = Some(M68000);
    c.entry = Some(u64::from(initial_pc));
    c.consumed = data.len();
    c.code_sections = true;
    push_header_notes(&mut c, data, initial_pc)?;
    push_user_header_notes(&mut c, &user, program.is_some());
    match program {
        Some(Range { start, end }) => {
            if start > 0 {
                c.sections
                    .push(stored_section("68000 ROM", 0, 0, &data[..start]));
            }
            if end < data.len() {
                c.sections.push(stored_section(
                    "68000 ROM after the SH-2 program",
                    end as u64,
                    end,
                    &data[end..],
                ));
            }
            c.children.push(
                Child::stored("32X SH-2 program", start, &data[start..end])
                    .with_target(SH2)
                    .with_variant(SH2_VARIANT)
                    .as_code(),
            );
        }
        None => c.sections.push(stored_section("68000 ROM", 0, 0, data)),
    }
    c.notes.push(
        "Section addresses are ROM offsets; the SH-2 program is a separate slice and is not part \
            of the 68000 sections"
            .into(),
    );
    Ok(c)
}

fn push_header_notes(c: &mut Container<'_>, data: &[u8], initial_pc: u32) -> Result<()> {
    let header = genesis::header(data)?;
    c.notes.push(format!(
        "Sega 32X ROM; system type: {}; 68000 initial PC 0x{initial_pc:08X}",
        header.system_type
    ));
    c.notes.push(format!(
        "Domestic title: {}; overseas title: {}",
        header.domestic_title, header.overseas_title
    ));
    c.notes.push(format!(
        "Serial: {}; region: {}",
        header.serial, header.region
    ));
    let stored = header.stored_checksum;
    let computed = genesis::checksum(data);
    if stored == computed {
        c.notes.push(format!(
            "Mega Drive checksum 0x{stored:04X} verified (16-bit sum of the words from 0x200)"
        ));
    } else {
        c.notes.push(format!(
            "Mega Drive checksum 0x{stored:04X} does not match the computed 0x{computed:04X}"
        ));
    }
    c.push_metadata("sega32x_system_type", "System type", header.system_type);
    c.push_metadata("sega32x_serial", "Serial", header.serial);
    c.push_metadata("sega32x_region", "Region", header.region);
    c.push_metadata(
        "sega32x_checksum",
        "ROM checksum",
        format!("0x{stored:04X}"),
    );
    c.push_metadata(
        "sega32x_checksum_computed",
        "Computed ROM checksum",
        format!("0x{computed:04X}"),
    );
    Ok(())
}

fn push_user_header_notes(c: &mut Container<'_>, user: &MarsHeader<'_>, has_program: bool) {
    let module_name = header_text(user.module_name);
    let sdram = SH2_SDRAM + u64::from(user.destination);
    if has_program {
        c.notes.push(format!(
            "32X user header {}: SH-2 program at ROM 0x{:X} (SH-2 0x{:08X}) + {} B, copied to \
                SDRAM 0x{sdram:08X}",
            module_name,
            user.source,
            SH2_CARTRIDGE + u64::from(user.source),
            user.size
        ));
    } else {
        c.notes.push(format!(
            "32X user header {module_name}: the SH-2 program size is 0; nothing is copied to SDRAM"
        ));
    }
    c.notes.push(format!(
        "Master SH-2 start 0x{:08X}, VBR 0x{:08X}; slave SH-2 start 0x{:08X}, VBR 0x{:08X}",
        user.master_start, user.master_vbr, user.slave_start, user.slave_vbr
    ));
    let loaded = sdram..sdram + u64::from(user.size);
    for (name, start) in [("Master", user.master_start), ("Slave", user.slave_start)] {
        if !loaded.contains(&u64::from(start)) {
            c.notes.push(format!(
                "{name} SH-2 start 0x{start:08X} lies outside the copied program"
            ));
        }
    }
    if user.masked {
        c.notes.push(
            "The top four bits of the source or destination address are ignored, as PicoDrive \
                does"
                .into(),
        );
    }
    c.push_metadata("sega32x_module_name", "Module name", module_name);
    c.push_metadata(
        "sega32x_version",
        "User header version",
        format!("0x{:08X}", user.version),
    );
    c.push_metadata(
        "sega32x_sdram_destination",
        "SDRAM destination",
        format!("0x{sdram:08X}"),
    );
    c.push_metadata(
        "sega32x_master_start",
        "Master SH-2 start address",
        format!("0x{:08X}", user.master_start),
    );
    c.push_metadata(
        "sega32x_slave_start",
        "Slave SH-2 start address",
        format!("0x{:08X}", user.slave_start),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mega_cd_discs_with_the_text_are_not_32x_roms() {
        let mut disc = vec![0x20u8; 0x600];
        disc[..14].copy_from_slice(b"SEGADISCSYSTEM");
        disc[0x100..0x104].copy_from_slice(b"SEGA");
        disc[SECURITY_TEXT_OFFSET..SECURITY_TEXT_OFFSET + SECURITY_TEXT.len()]
            .copy_from_slice(SECURITY_TEXT);
        assert!(!detect(&disc));
        disc[..14].fill(0);
        assert!(detect(&disc));
    }
}
