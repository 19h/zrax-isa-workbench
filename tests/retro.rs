//! Console executables and ROM images: Mega Drive ROMs (linear, byte-swapped,
//! SMD, 32X), PS-X EXE, Dreamcast IP.BIN, Wii U RPX with zlib sections and
//! CRCs, 3DS NCCH with ExeFS and BLZ `.code`, 3DSX and PSP PBP, with
//! corrupted fields, truncation and mutation sweeps.

use sha2::{Digest, Sha256};
use zrax::formats::checksum::crc32;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey, MetadataValue,
};

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, needle: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(needle))
}

fn custom<'a>(p: &'a DetectionPayload, key: &str) -> Option<&'a MetadataValue> {
    p.metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.to_string()))
        .map(|m| &m.value)
}

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

/// Write `text` at `at`, space-padded to `len` bytes.
fn put_text(data: &mut [u8], at: usize, len: usize, text: &str) {
    assert!(text.len() <= len);
    data[at..at + len].fill(b' ');
    data[at..at + text.len()].copy_from_slice(text.as_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Truncations must not panic, and those shorter than `min_valid` must fail
/// to parse as `format`.
fn truncation_sweep(data: &[u8], format: FileFormat, min_valid: usize, step: usize) {
    for end in (0..data.len()).step_by(step) {
        let result = detect_payload(&data[..end], &ClassifierOptions::new());
        if end < min_valid {
            let claimed = result.is_ok_and(|p| p.format.format == format);
            assert!(!claimed, "prefix of {end} B still parses as {format}");
        }
    }
}

/// Single-byte mutations (0x00, 0xFF, bit flip) of every `step`-th byte and
/// of every byte in `header`, classified without panicking.
fn mutation_sweep(data: &[u8], header: std::ops::Range<usize>, step: usize) {
    let positions = header.chain((0..data.len()).step_by(step));
    for i in positions.filter(|i| *i < data.len()) {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.to_vec();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

// --- Mega Drive / Genesis ---------------------------------------------------

/// 68000 `NOP`, big-endian.
const M68K_NOP: [u8; 2] = [0x4e, 0x71];

/// SH-2 `RTS` then `NOP`, big-endian.
const SH2_RTS_NOP: [u8; 4] = [0x00, 0x0b, 0x00, 0x09];

/// A Mega Drive ROM of `size` bytes: 68000 vector table (initial SSP
/// 0x00FFFE00 at 0, initial PC 0x00000200 at 4), the header at 0x100
/// (system type, copyright, domestic and overseas titles, serial, checksum
/// at 0x18E, devices, ROM 0..size-1 at 0x1A0, RAM 0xFF0000-0xFFFFFF at
/// 0x1A8, region `JUE` at 0x1F0, all space-padded), then 68000 NOPs from
/// 0x200. The checksum is set by [`set_genesis_checksum`].
fn genesis_rom(system_type: &str, size: usize) -> Vec<u8> {
    let mut rom = vec![0u8; size];
    put_be32(&mut rom, 0, 0x00ff_fe00);
    put_be32(&mut rom, 4, 0x0000_0200);
    put_text(&mut rom, 0x100, 16, system_type);
    put_text(&mut rom, 0x110, 16, "(C)ZRAX 2026.OCT");
    put_text(&mut rom, 0x120, 48, "SYNTHETIC DOMESTIC");
    put_text(&mut rom, 0x150, 48, "SYNTHETIC OVERSEAS");
    put_text(&mut rom, 0x180, 14, "GM 00000000-00");
    put_text(&mut rom, 0x190, 16, "J");
    put_be32(&mut rom, 0x1a0, 0);
    put_be32(&mut rom, 0x1a4, (size - 1) as u32);
    put_be32(&mut rom, 0x1a8, 0x00ff_0000);
    put_be32(&mut rom, 0x1ac, 0x00ff_ffff);
    put_text(&mut rom, 0x1b0, 12, "");
    put_text(&mut rom, 0x1bc, 12, "");
    put_text(&mut rom, 0x1c8, 40, "");
    put_text(&mut rom, 0x1f0, 16, "JUE");
    for word in rom[0x200..].chunks_exact_mut(2) {
        word.copy_from_slice(&M68K_NOP);
    }
    set_genesis_checksum(&mut rom);
    rom
}

/// The checksum at 0x18E: the 16-bit sum of the big-endian words from
/// 0x200 to the end (Genesis Plus GX `getchecksum`).
fn set_genesis_checksum(rom: &mut [u8]) {
    let sum = rom[0x200..]
        .chunks(2)
        .map(|w| u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]))
        .fold(0u16, u16::wrapping_add);
    rom[0x18e..0x190].copy_from_slice(&sum.to_be_bytes());
}

/// A 32X ROM: the security program user header at 0x3C0 (module name,
/// version, SH-2 program source 0x800, SDRAM destination 0, size 0x100,
/// master start 0x06000000, slave start 0x06000100, VBRs), and SH-2 code
/// at 0x800.
fn genesis_32x() -> Vec<u8> {
    let mut rom = genesis_rom("SEGA 32X", 0x1000);
    put_text(&mut rom, 0x3c0, 16, "MARS CHECK MODE");
    put_be32(&mut rom, 0x3d0, 0);
    put_be32(&mut rom, 0x3d4, 0x800);
    put_be32(&mut rom, 0x3d8, 0);
    put_be32(&mut rom, 0x3dc, 0x100);
    put_be32(&mut rom, 0x3e0, 0x0600_0000);
    put_be32(&mut rom, 0x3e4, 0x0600_0100);
    put_be32(&mut rom, 0x3e8, 0x0600_0000);
    put_be32(&mut rom, 0x3ec, 0x0600_0100);
    for word in rom[0x800..0x900].chunks_exact_mut(4) {
        word.copy_from_slice(&SH2_RTS_NOP);
    }
    set_genesis_checksum(&mut rom);
    rom
}

/// Every byte pair swapped, as a byte-swapped dump stores the ROM.
fn byte_swapped(rom: &[u8]) -> Vec<u8> {
    rom.chunks(2)
        .flat_map(|pair| pair.iter().rev().copied())
        .collect()
}

/// An SMD copier dump: a 512-byte header (block count, 0x03, then 0xAA 0xBB
/// at 8), then each 16 KiB block with the odd bytes in its first half and
/// the even bytes in its second half.
fn smd(rom: &[u8]) -> Vec<u8> {
    assert_eq!(rom.len() % 0x4000, 0);
    let mut dump = vec![0u8; 0x200];
    dump[0] = (rom.len() / 0x4000) as u8;
    dump[1] = 3;
    dump[8] = 0xaa;
    dump[9] = 0xbb;
    for block in rom.chunks_exact(0x4000) {
        dump.extend(block.iter().skip(1).step_by(2));
        dump.extend(block.iter().step_by(2));
    }
    dump
}

#[test]
fn genesis_rom_names_the_68000_and_verifies_its_checksum() {
    let rom = genesis_rom("SEGA MEGA DRIVE", 0x800);
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::GenesisRom);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Mega Drive / Genesis ROM")
    );
    assert_eq!(p.primary.isa, Isa::M68k);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(entry_point(&p), Some(0x200));
    assert!(has_note(&p, "ROM checksum 0x"));
    assert!(has_note(
        &p,
        "verified (16-bit sum of the words from 0x200)"
    ));
    assert!(has_note(&p, "Z80 sound program"));
    assert!(has_note(
        &p,
        "Initial SSP 0x00FFFE00; initial PC 0x00000200"
    ));
    assert!(matches!(
        custom(&p, "genesis_system_type"),
        Some(MetadataValue::String(s)) if s == "SEGA MEGA DRIVE"
    ));
}

#[test]
fn genesis_checksum_mismatch_is_reported_not_rejected() {
    let mut rom = genesis_rom("SEGA GENESIS", 0x800);
    rom[0x18e] ^= 0x55;
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::GenesisRom);
    assert_eq!(p.primary.isa, Isa::M68k);
    assert!(has_note(&p, "does not match the computed"));
}

#[test]
fn genesis_initial_pc_must_be_an_even_rom_address() {
    let mut outside = genesis_rom("SEGA MEGA DRIVE", 0x800);
    put_be32(&mut outside, 4, 0x0000_0800);
    let error = detect_payload(&outside, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Invalid initial PC 0x00000800"));

    let mut odd = genesis_rom("SEGA MEGA DRIVE", 0x800);
    put_be32(&mut odd, 4, 0x0000_0201);
    assert!(detect_payload(&odd, &ClassifierOptions::new()).is_err());
}

#[test]
fn genesis_alternative_tmss_magic_at_0x101_is_recognized() {
    let mut rom = genesis_rom("SEGA MEGA DRIVE", 0x800);
    // Byte 0x100 is free; TMSS reads ` SEGA` from 0x101.
    put_text(&mut rom, 0x100, 16, "  SEGA MEGADRIVE");
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::GenesisRom);
}

#[test]
fn genesis_byte_swapped_and_smd_dumps_are_reordered() {
    let rom = genesis_rom("SEGA MEGA DRIVE", 0x8000);
    let swapped = classify(&byte_swapped(&rom));
    assert_eq!(swapped.format.format, FileFormat::GenesisRom);
    assert_eq!(
        swapped.format.variant_name.as_deref(),
        Some("Mega Drive / Genesis ROM (byte-swapped dump)")
    );
    assert_eq!(swapped.primary.isa, Isa::M68k);
    assert!(has_note(&swapped, "ROM checksum 0x"));
    assert!(has_note(&swapped, "verified"));

    let dump = smd(&rom);
    let interleaved = classify(&dump);
    assert_eq!(interleaved.format.format, FileFormat::GenesisRom);
    assert_eq!(
        interleaved.format.variant_name.as_deref(),
        Some("Mega Drive / Genesis ROM (SMD interleaved dump)")
    );
    assert_eq!(interleaved.primary.isa, Isa::M68k);
    assert!(has_note(&interleaved, "verified"));
    assert!(matches!(
        custom(&interleaved, "genesis_section_0"),
        Some(MetadataValue::String(s)) if s.starts_with("file 0x200;")
            && s.contains("32768 B stored; 32768 B decoded (SMD deinterleave)")
    ));
}

#[test]
fn genesis_32x_lists_the_sh2_program_as_its_own_slice() {
    let p = classify(&genesis_32x());
    assert_eq!(p.primary.isa, Isa::M68k);
    let sh2 = slice(&p, "32X SH-2 program");
    assert_eq!(sh2.isa, Isa::Sh);
    assert_eq!(sh2.endianness, Endianness::Big);
    assert_eq!((sh2.offset, sh2.size), (0x800, 0x100));
    assert!(has_note(&p, "SH-2 program at ROM 0x800 + 256 B"));
}

#[test]
fn genesis_teradrive_x86_rom_does_not_claim_the_68000() {
    let p = classify(&genesis_rom("SEGA TERA286", 0x800));
    assert_eq!(p.format.format, FileFormat::GenesisRom);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, "Teradrive ROM that boots from the x86 side"));
}

#[test]
fn mega_cd_discs_are_not_cartridge_roms() {
    let mut disc = genesis_rom("SEGA MEGA DRIVE", 0x800);
    disc[..16].copy_from_slice(b"SEGADISCSYSTEM  ");
    assert_ne!(classify(&disc).format.format, FileFormat::GenesisRom);
}

// --- PS-X EXE ---------------------------------------------------------------

/// MIPS I little-endian code: `addiu sp, sp, -8`, `sw ra, 4(sp)`,
/// `lw ra, 4(sp)`, `jr ra`, `addiu sp, sp, 8`, `nop`, repeated.
fn mips_code(size: usize) -> Vec<u8> {
    let words: [u32; 6] = [
        0x27bd_fff8,
        0xafbf_0004,
        0x8fbf_0004,
        0x03e0_0008,
        0x27bd_0008,
        0x0000_0000,
    ];
    words
        .iter()
        .cycle()
        .flat_map(|w| w.to_le_bytes())
        .take(size)
        .collect()
}

/// A PS-X EXE: `PS-X EXE`, pc0 0x80010000 at 0x10, gp0 0, t_addr
/// 0x80010000 at 0x18, t_size at 0x1C, s_addr 0x801FFFF0 at 0x30, the
/// North America region marker at 0x4C, then the text at 0x800.
fn psx_exe(text: &[u8]) -> Vec<u8> {
    let mut exe = vec![0u8; 0x800];
    exe[..8].copy_from_slice(b"PS-X EXE");
    put_le32(&mut exe, 0x10, 0x8001_0000);
    put_le32(&mut exe, 0x18, 0x8001_0000);
    put_le32(&mut exe, 0x1c, text.len() as u32);
    put_le32(&mut exe, 0x30, 0x801f_fff0);
    let marker = b"Sony Computer Entertainment Inc. for North America area";
    exe[0x4c..0x4c + marker.len()].copy_from_slice(marker);
    exe.extend_from_slice(text);
    exe
}

#[test]
fn psx_exe_loads_its_text_at_t_addr_as_little_endian_mips() {
    let exe = psx_exe(&mips_code(0x800));
    let p = classify(&exe);
    assert_eq!(p.format.format, FileFormat::PsxExe);
    assert_eq!(p.primary.isa, Isa::Mips);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("R3000A (MIPS I)")
    );
    assert_eq!(entry_point(&p), Some(0x8001_0000));
    assert!(has_note(
        &p,
        "Region marker: Sony Computer Entertainment Inc. for North America area"
    ));
    assert!(matches!(
        custom(&p, "psx_section_0"),
        Some(MetadataValue::String(s)) if s == "file 0x800; destination 0x80010000; 2048 B"
    ));
}

#[test]
fn psx_exe_rejects_truncated_text_and_trailing_data() {
    let exe = psx_exe(&mips_code(0x800));
    let mut long = exe.clone();
    put_le32(&mut long, 0x1c, 0x1000);
    let error = detect_payload(&long, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Truncated PS-X EXE text"));

    let mut trailing = exe.clone();
    trailing.extend_from_slice(b"junk");
    assert!(detect_payload(&trailing, &ClassifierOptions::new()).is_err());

    let mut padded = exe.clone();
    padded.extend_from_slice(&[0; 16]);
    assert_eq!(classify(&padded).format.format, FileFormat::PsxExe);

    let mut unaligned = psx_exe(&mips_code(0x7fc));
    unaligned.truncate(0x800 + 0x7fc);
    assert!(has_note(
        &classify(&unaligned),
        "is not a multiple of 2048 B"
    ));
}

// --- Dreamcast IP.BIN ------------------------------------------------------

/// SH-4 `RTS` then `NOP`, little-endian.
const SH4_RTS_NOP: [u8; 4] = [0x0b, 0x00, 0x09, 0x00];

/// CRC-16/CCITT-FALSE as makeip `calcCRC` computes it: polynomial 0x1021,
/// initial value 0xFFFF, most significant bit first.
fn makeip_crc(bytes: &[u8]) -> u16 {
    let mut crc: u32 = 0xffff;
    for &byte in bytes {
        crc ^= u32::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    (crc & 0xffff) as u16
}

/// A Dreamcast IP.BIN: meta information (hardware ID, maker ID, device info
/// with the CRC of product number and version, area symbols `JUE`,
/// peripherals `E000F10`, product, version, release date, boot file name,
/// software maker, title), the three area protection texts at 0x3700 and
/// SH-4 code in the license screen code and bootstrap areas.
fn ip_bin() -> Vec<u8> {
    let mut ip = vec![0u8; 0x8000];
    put_text(&mut ip, 0x00, 16, "SEGA SEGAKATANA");
    put_text(&mut ip, 0x10, 16, "SEGA ENTERPRISES");
    put_text(&mut ip, 0x30, 8, "JUE");
    put_text(&mut ip, 0x38, 8, "E000F10");
    put_text(&mut ip, 0x40, 10, "T-00000");
    put_text(&mut ip, 0x4a, 6, "V1.000");
    put_text(&mut ip, 0x50, 16, "20261012");
    put_text(&mut ip, 0x60, 16, "1ST_READ.BIN");
    put_text(&mut ip, 0x70, 16, "ZRAX TEST");
    put_text(&mut ip, 0x80, 128, "SYNTHETIC IP.BIN");
    let crc = makeip_crc(&ip[0x40..0x50]);
    put_text(&mut ip, 0x20, 16, &format!("{crc:04X} GD-ROM1/1"));
    for (slot, text) in [
        "For JAPAN,TAIWAN,PHILIPINES.",
        "For USA and CANADA.",
        "For EUROPE.",
    ]
    .iter()
    .enumerate()
    {
        put_text(&mut ip, 0x3700 + slot * 32 + 4, 28, text);
    }
    for (start, end) in [(0x300, 0x3700), (0x3800, 0x8000)] {
        for word in ip[start..end].chunks_exact_mut(4) {
            word.copy_from_slice(&SH4_RTS_NOP);
        }
    }
    ip
}

#[test]
fn dreamcast_ip_bin_names_the_sh4_and_verifies_the_device_crc() {
    let ip = ip_bin();
    let p = classify(&ip);
    assert_eq!(p.format.format, FileFormat::DreamcastIp);
    assert_eq!(p.primary.isa, Isa::Sh4);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(entry_point(&p), Some(0x8c00_8300));
    assert!(has_note(&p, "Device info: "));
    assert!(has_note(&p, "verified"));
    assert!(has_note(&p, "Area symbols: Japan, USA, Europe"));
    assert!(has_note(
        &p,
        "Boot file 1ST_READ.BIN is loaded to 0x8C010000"
    ));
    assert!(has_note(&p, "MIL-CD scrambling is not handled"));
    assert!(matches!(
        custom(&p, "dreamcast_section_1"),
        Some(MetadataValue::String(s)) if s == "file 0x3800; destination 0x8C00B800; 10240 B"
    ));

    let mut wrong_crc = ip.clone();
    wrong_crc[0x20] = if wrong_crc[0x20] == b'0' { b'1' } else { b'0' };
    let p = classify(&wrong_crc);
    assert_eq!(p.format.format, FileFormat::DreamcastIp);
    assert!(has_note(&p, "does not match the computed"));

    let mut track = ip;
    track.extend_from_slice(&[0x5a; 0x800]);
    assert!(has_note(&classify(&track), "follow IP.BIN at 0x8000"));
}

// --- Wii U RPX --------------------------------------------------------------

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RPL_IMPORTS: u32 = 0x8000_0002;
const SHT_RPL_CRCS: u32 = 0x8000_0003;
const SHT_RPL_FILEINFO: u32 = 0x8000_0004;
const SHF_ALLOC_EXEC: u32 = 0x2 | 0x4;
const SHF_DEFLATED: u32 = 0x0800_0000;
const EM_PPC: u16 = 20;

/// PowerPC big-endian code: `stwu r1,-16(r1)`, `mflr r0`, `lwz r0,20(r1)`,
/// `mtlr r0`, `addi r1,r1,16`, `blr`, repeated.
fn ppc_code(size: usize) -> Vec<u8> {
    let words: [u32; 6] = [
        0x9421_fff0,
        0x7c08_02a6,
        0x8001_0014,
        0x7c08_03a6,
        0x3821_0010,
        0x4e80_0020,
    ];
    words
        .iter()
        .cycle()
        .flat_map(|w| w.to_be_bytes())
        .take(size)
        .collect()
}

/// One section for [`rpx`]: name, type, flags, address and uncompressed
/// contents (deflated by the builder when `SHF_DEFLATED` is set).
struct RplSection {
    name: &'static str,
    kind: u32,
    flags: u32,
    address: u32,
    contents: Vec<u8>,
}

/// A Cafe OS ELF: `e_ident` with OSABI 0xCA and ABI version 0xFE, `e_type`
/// 0xFE01, `e_machine`, entry 0x02000000, section headers at 0x40 (null,
/// the given sections, `.shstrtab`, `.rplcrcs`, `.rplfileinfo`), then the
/// section data in that order. Deflated sections store a big-endian
/// inflated size and a zlib stream; the CRC section holds the CRC-32 of
/// every section's uncompressed data (0 for the null and CRC sections).
fn rpx(machine: u16, sections: Vec<RplSection>) -> Vec<u8> {
    let mut all = vec![RplSection {
        name: "",
        kind: 0,
        flags: 0,
        address: 0,
        contents: Vec::new(),
    }];
    all.extend(sections);
    let mut names = vec![0u8];
    let mut name_offsets = Vec::new();
    for section in &all {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(section.name.as_bytes());
        names.push(0);
    }
    for name in [".shstrtab", ".rplcrcs", ".rplfileinfo"] {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let names_index = all.len();
    all.push(RplSection {
        name: ".shstrtab",
        kind: SHT_STRTAB,
        flags: 0,
        address: 0,
        contents: names,
    });
    let mut fileinfo = vec![0u8; 0x60];
    put_be32(&mut fileinfo, 0, 0xcafe_0402);
    put_be32(&mut fileinfo, 0x34, 0x2);
    let crc_index = all.len();
    let count = all.len() + 2;
    let mut crcs = vec![0u8; 4 * count];
    for (index, section) in all.iter().enumerate().skip(1) {
        put_be32(&mut crcs, 4 * index, crc32(&section.contents));
    }
    put_be32(&mut crcs, 4 * (crc_index + 1), crc32(&fileinfo));
    all.push(RplSection {
        name: ".rplcrcs",
        kind: SHT_RPL_CRCS,
        flags: 0,
        address: 0,
        contents: crcs,
    });
    all.push(RplSection {
        name: ".rplfileinfo",
        kind: SHT_RPL_FILEINFO,
        flags: 0,
        address: 0,
        contents: fileinfo,
    });

    let table_size = 0x28 * all.len();
    let mut file = vec![0u8; 0x40 + table_size];
    file[..9].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 2, 1, 0xca, 0xfe]);
    file[0x10..0x12].copy_from_slice(&0xfe01u16.to_be_bytes());
    file[0x12..0x14].copy_from_slice(&machine.to_be_bytes());
    put_be32(&mut file, 0x14, 1);
    put_be32(&mut file, 0x18, 0x0200_0000);
    put_be32(&mut file, 0x20, 0x40);
    file[0x28..0x2a].copy_from_slice(&0x34u16.to_be_bytes());
    file[0x2e..0x30].copy_from_slice(&0x28u16.to_be_bytes());
    file[0x30..0x32].copy_from_slice(&(all.len() as u16).to_be_bytes());
    file[0x32..0x34].copy_from_slice(&(names_index as u16).to_be_bytes());
    for (index, section) in all.iter().enumerate() {
        let stored = if section.flags & SHF_DEFLATED != 0 {
            let mut stored = (section.contents.len() as u32).to_be_bytes().to_vec();
            stored.extend(miniz_oxide::deflate::compress_to_vec_zlib(
                &section.contents,
                6,
            ));
            stored
        } else {
            section.contents.clone()
        };
        let header = 0x40 + 0x28 * index;
        let offset = if stored.is_empty() { 0 } else { file.len() };
        put_be32(&mut file, header, name_offsets[index]);
        put_be32(&mut file, header + 4, section.kind);
        put_be32(&mut file, header + 8, section.flags);
        put_be32(&mut file, header + 0xc, section.address);
        put_be32(&mut file, header + 0x10, offset as u32);
        put_be32(&mut file, header + 0x14, stored.len() as u32);
        file.extend_from_slice(&stored);
    }
    file
}

/// A deflated `.text`, an executable import stub section and nothing else.
fn rpx_sections() -> Vec<RplSection> {
    let mut imports = vec![0u8; 8];
    put_be32(&mut imports, 0, 1);
    imports.extend_from_slice(b"coreinit\0\0\0\0");
    vec![
        RplSection {
            name: ".text",
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC_EXEC | SHF_DEFLATED,
            address: 0x0200_0000,
            contents: ppc_code(0x400),
        },
        RplSection {
            name: ".fimport_coreinit",
            kind: SHT_RPL_IMPORTS,
            flags: SHF_ALLOC_EXEC,
            address: 0xc000_0000,
            contents: imports,
        },
    ]
}

#[test]
fn wii_u_rpx_inflates_text_and_verifies_its_crc() {
    let file = rpx(EM_PPC, rpx_sections());
    assert!(matches!(
        detect_format(&file),
        DetectedFormat::Container { .. }
    ));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::WiiURpx);
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(entry_point(&p), Some(0x0200_0000));
    assert!(has_note(&p, "Wii U RPX (executable); ELF e_machine 20"));
    assert!(has_note(
        &p,
        "section CRC-32 verified for 1 of 1 text sections"
    ));
    assert!(has_note(&p, "Imports: coreinit"));
    let text = custom(&p, "wiiu_section_0");
    assert!(matches!(
        text,
        Some(MetadataValue::String(s)) if s.contains("destination 0x2000000")
            && s.contains("B decoded (zlib)")
            && s.contains("1024 B decoded")
    ));
}

#[test]
fn wii_u_rpx_crc_mismatch_is_reported_and_corrupt_zlib_is_an_error() {
    let mut file = rpx(EM_PPC, rpx_sections());
    // Corrupt the stored CRC of section 1 (.text) in the CRC section.
    let crc_entry = find(&file, &crc32(&ppc_code(0x400)).to_be_bytes());
    file[crc_entry] ^= 0xff;
    let p = classify(&file);
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert!(has_note(&p, "CRC-32 mismatch for .text"));

    let mut corrupt = rpx(EM_PPC, rpx_sections());
    // The .text inflated size field: 0x400 becomes 0x410.
    let size_field = section_offset(&corrupt, 1);
    corrupt[size_field + 3] = 0x10;
    let error = detect_payload(&corrupt, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Console image parse error"));

    let mut wrong_type = rpx(EM_PPC, rpx_sections());
    wrong_type[0x10] = 0x00;
    let error = detect_payload(&wrong_type, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Unsupported RPL e_type"));
}

#[test]
fn plain_big_endian_elf_is_not_taken_for_an_rpx() {
    let mut file = rpx(EM_PPC, rpx_sections());
    file[7] = 0;
    file[8] = 0;
    assert!(matches!(detect_format(&file), DetectedFormat::Elf { .. }));
}

#[test]
fn wii_u_rpx_without_a_known_machine_leaves_the_isa_to_the_code() {
    let p = classify(&rpx(0, rpx_sections()));
    assert_eq!(p.format.format, FileFormat::WiiURpx);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, "ELF e_machine 0 is not mapped to an ISA"));
}

/// `sh_offset` of section `index`, from the section headers at 0x40.
fn section_offset(file: &[u8], index: usize) -> usize {
    let at = 0x40 + 0x28 * index + 0x10;
    u32::from_be_bytes(file[at..at + 4].try_into().unwrap()) as usize
}

/// Position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present")
}

// --- Nintendo 3DS NCCH ------------------------------------------------------

/// ARM little-endian code: `push {r4, lr}`, `mov r0, #0`, `pop {r4, pc}`,
/// `bx lr`, repeated.
fn arm_code(size: usize) -> Vec<u8> {
    let words: [u32; 4] = [0xe92d_4010, 0xe3a0_0000, 0xe8bd_8010, 0xe12f_ff1e];
    words
        .iter()
        .cycle()
        .flat_map(|w| w.to_le_bytes())
        .take(size)
        .collect()
}

/// BLZ-compress `decoded`, a repetition of one 4-byte word, as ctrtool's
/// decoder reads it (from the end backwards): the top word as four
/// literals, then back-references of 18 bytes at distance 4 (token
/// `0xF001`: length 15 + 3, displacement 1 + 2), grouped under control
/// bytes (most significant bit first; set for a back-reference). The footer
/// is the header length (8) in bits 31-24 with the compressed region length
/// below it, then the decoded size minus the stored size.
fn blz_repeated_word(decoded: &[u8]) -> Vec<u8> {
    assert_eq!((decoded.len() - 4) % 18, 0);
    let mut tokens: Vec<Option<u8>> = decoded[decoded.len() - 4..]
        .iter()
        .rev()
        .map(|&b| Some(b))
        .collect();
    tokens.extend(std::iter::repeat(None).take((decoded.len() - 4) / 18));
    // Bytes in the order the decoder consumes them, highest address first.
    let mut consumed = Vec::new();
    for group in tokens.chunks(8) {
        let control = group
            .iter()
            .enumerate()
            .filter(|(_, token)| token.is_none())
            .fold(0u8, |control, (i, _)| control | (0x80 >> i));
        consumed.push(control);
        for token in group {
            match token {
                Some(literal) => consumed.push(*literal),
                None => consumed.extend_from_slice(&[0xf0, 0x01]),
            }
        }
    }
    let mut stream: Vec<u8> = consumed.into_iter().rev().collect();
    let region = stream.len() as u32 + 8;
    stream.extend_from_slice(&((8u32 << 24) | region).to_le_bytes());
    let extra = decoded.len() as u32 - stream.len() as u32 - 4;
    stream.extend_from_slice(&extra.to_le_bytes());
    stream
}

/// NCCH fixture options.
struct NcchOptions {
    /// flags[7] `NoCrypto`; clear means the content is encrypted.
    no_crypto: bool,
    /// flags[5] bits 0-1: 3 executable, 1 simple content.
    form_type: u8,
    /// ExHeader `CompressExefsCode`; `.code` is BLZ-compressed when set.
    compressed_code: bool,
}

/// An NCCH partition of 0x1000 bytes (8 media units of 0x200): signature
/// pattern, `NCCH` at 0x100, content size, partition and program ID,
/// maker code `01`, version 2, product code `CTR-P-ZRAX`, ExHeader size
/// 0x400, flags (platform CTR, form type, NoCrypto), ExeFS at unit 5
/// (0xA00) of 3 units with a 1-unit hash region and its superblock hash;
/// the ExHeader at 0x200 (title `CtrApp`, compression flag, text code set
/// 0x00100000 + 0x100); the ExeFS header with `.code` at 0 and `icon` at
/// 0x200 after the header, and their SHA-256 in reverse order from 0x1E0.
fn ncch(options: &NcchOptions) -> Vec<u8> {
    let code = arm_code(0x100 + 18 * 2);
    let stored_code = if options.compressed_code {
        blz_repeated_word(&code)
    } else {
        code.clone()
    };
    let mut icon = b"SMDH".to_vec();
    icon.resize(0x40, 0);

    let mut exefs = vec![0u8; 0x200];
    exefs[..5].copy_from_slice(b".code");
    put_le32(&mut exefs, 8, 0);
    put_le32(&mut exefs, 12, stored_code.len() as u32);
    exefs[16..20].copy_from_slice(b"icon");
    put_le32(&mut exefs, 16 + 8, 0x200);
    put_le32(&mut exefs, 16 + 12, icon.len() as u32);
    exefs[0x1e0..0x200].copy_from_slice(&Sha256::digest(&stored_code));
    exefs[0x1c0..0x1e0].copy_from_slice(&Sha256::digest(&icon));
    exefs.extend_from_slice(&stored_code);
    exefs.resize(0x400, 0);
    exefs.extend_from_slice(&icon);
    exefs.resize(0x600, 0);

    let mut data = vec![0xa5u8; 0x100];
    data.resize(0xa00, 0);
    data[0x100..0x104].copy_from_slice(b"NCCH");
    put_le32(&mut data, 0x104, 8);
    data[0x108..0x110].copy_from_slice(&0x0004_0000_00ab_cd00u64.to_le_bytes());
    data[0x110..0x112].copy_from_slice(b"01");
    put_le16(&mut data, 0x112, 2);
    data[0x118..0x120].copy_from_slice(&0x0004_0000_00ab_cd00u64.to_le_bytes());
    put_text(&mut data, 0x150, 16, "CTR-P-ZRAX");
    data[0x150 + 10..0x160].fill(0);
    put_le32(&mut data, 0x180, 0x400);
    data[0x188 + 4] = 1;
    data[0x188 + 5] = options.form_type;
    data[0x188 + 7] = if options.no_crypto { 0x04 } else { 0 };
    put_le32(&mut data, 0x1a0, 5);
    put_le32(&mut data, 0x1a4, 3);
    put_le32(&mut data, 0x1a8, 1);
    data[0x1c0..0x1e0].copy_from_slice(&Sha256::digest(&exefs[..0x200]));
    data[0x200..0x206].copy_from_slice(b"CtrApp");
    data[0x200 + 0x0d] = u8::from(options.compressed_code);
    put_le32(&mut data, 0x200 + 0x10, 0x0010_0000);
    put_le32(&mut data, 0x200 + 0x14, 1);
    put_le32(&mut data, 0x200 + 0x18, code.len() as u32);
    put_le32(&mut data, 0x200 + 0x1c, 0x4000);
    data.extend_from_slice(&exefs);
    data
}

const CXI: NcchOptions = NcchOptions {
    no_crypto: true,
    form_type: 3,
    compressed_code: true,
};

#[test]
fn ncch_cxi_decodes_blz_code_as_arm11_and_lists_exefs_files() {
    let file = ncch(&CXI);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::N3dsNcch);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARM11 MPCore (ARMv6K)")
    );
    assert!(has_note(&p, "3DS NCCH CXI; product code CTR-P-ZRAX"));
    assert!(has_note(&p, "Content is not encrypted (NoCrypto set)"));
    assert!(has_note(&p, "superblock SHA-256 verified"));
    assert!(has_note(&p, "file SHA-256 verified for 2 of 2"));
    assert!(has_note(&p, ".code compressed (CompressExefsCode)"));
    let code = slice(&p, ".code");
    assert_eq!(code.isa, Isa::Arm);
    assert_eq!(code.offset, 0xc00);
    let decoded = code.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "BLZ");
    assert_eq!(decoded.size, 0x124);
    assert!(matches!(slice(&p, "icon").isa, Isa::Unknown(_)));
    assert!(matches!(slice(&p, "ExHeader").isa, Isa::Unknown(_)));
}

#[test]
fn ncch_uncompressed_code_is_classified_as_stored() {
    let p = classify(&ncch(&NcchOptions {
        compressed_code: false,
        ..CXI
    }));
    let code = slice(&p, ".code");
    assert_eq!(code.isa, Isa::Arm);
    assert!(code.decoded.is_none());
    assert_eq!(code.size, 0x124);
}

#[test]
fn ncch_encrypted_content_is_opaque() {
    let p = classify(&ncch(&NcchOptions {
        no_crypto: false,
        ..CXI
    }));
    assert_eq!(p.format.format, FileFormat::N3dsNcch);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "AES-128-CTR encrypted (NoCrypto clear; crypto method 0x00, secondary key slot 0x2C)"
    ));
    assert!(has_note(&p, "ISA analysis was not applied"));
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
    assert!(p.candidates.is_empty());
    slice(&p, "ExeFS (encrypted)");
}

#[test]
fn ncch_cfa_names_no_cpu() {
    let p = classify(&ncch(&NcchOptions {
        form_type: 1,
        ..CXI
    }));
    assert_eq!(p.format.format, FileFormat::N3dsNcch);
    assert!(has_note(&p, "3DS NCCH CFA"));
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
}

#[test]
fn ncch_hash_mismatch_is_reported_and_bad_regions_are_errors() {
    let mut file = ncch(&CXI);
    file[0xc00] ^= 0x01;
    let p = classify(&file);
    assert!(has_note(&p, "mismatch for .code"));

    let mut beyond = ncch(&CXI);
    put_le32(&mut beyond, 0x1a4, 9);
    let error = detect_payload(&beyond, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Invalid NCCH ExeFS"));

    let mut code_beyond = ncch(&CXI);
    put_le32(&mut code_beyond, 0xa00 + 12, 0x1000);
    assert!(detect_payload(&code_beyond, &ClassifierOptions::new()).is_err());

    let mut trailing = ncch(&CXI);
    trailing.extend_from_slice(b"junk");
    assert!(detect_payload(&trailing, &ClassifierOptions::new()).is_err());
}

#[test]
fn ncch_code_that_does_not_decode_as_blz_is_opaque() {
    let mut file = ncch(&CXI);
    // The BLZ footer's extra size makes the decoded size inconsistent;
    // refresh the ExeFS file hash so only the codec fails.
    let code_end = 0xc00 + blz_repeated_word(&arm_code(0x124)).len();
    file[code_end - 4] ^= 0x10;
    let hash = Sha256::digest(&file[0xc00..code_end]);
    file[0xa00 + 0x1e0..0xa00 + 0x200].copy_from_slice(&hash);
    let p = classify(&file);
    assert!(has_note(&p, ".code is opaque: it does not decode as BLZ"));
    assert!(matches!(slice(&p, ".code").isa, Isa::Unknown(_)));
}

// --- 3DSX -------------------------------------------------------------------

/// SMDH and RomFS for the extended header.
struct Extras {
    smdh: Vec<u8>,
    romfs: Vec<u8>,
}

/// A 3DSX: magic, header size (32, or 44 with the extended header),
/// relocation header size 8, version 0, flags 0, code 0x40, read-only data
/// 0x10, data 0x18 including 8 B BSS; three relocation headers (code: one
/// absolute, one relative); the segments; the two relocation entries; then
/// SMDH and RomFS with their offsets in the extended header.
fn homebrew_3dsx(extras: Option<&Extras>) -> Vec<u8> {
    let header_size = if extras.is_some() { 44 } else { 32 };
    let mut file = vec![0u8; header_size];
    file[..4].copy_from_slice(b"3DSX");
    put_le16(&mut file, 4, header_size as u16);
    put_le16(&mut file, 6, 8);
    put_le32(&mut file, 0x10, 0x40);
    put_le32(&mut file, 0x14, 0x10);
    put_le32(&mut file, 0x18, 0x18);
    put_le32(&mut file, 0x1c, 0x08);
    let mut reloc_headers = vec![0u8; 24];
    put_le32(&mut reloc_headers, 0, 1);
    put_le32(&mut reloc_headers, 4, 1);
    file.extend_from_slice(&reloc_headers);
    file.extend_from_slice(&arm_code(0x40));
    file.extend_from_slice(&[0x11; 0x10]);
    file.extend_from_slice(&[0x22; 0x10]);
    file.extend_from_slice(&[0, 0, 1, 0, 2, 0, 1, 0]);
    if let Some(extras) = extras {
        let smdh_offset = file.len();
        file.extend_from_slice(&extras.smdh);
        let romfs_offset = file.len();
        file.extend_from_slice(&extras.romfs);
        put_le32(&mut file, 0x20, smdh_offset as u32);
        put_le32(&mut file, 0x24, extras.smdh.len() as u32);
        put_le32(&mut file, 0x28, romfs_offset as u32);
    }
    file
}

fn extras() -> Extras {
    let mut smdh = b"SMDH".to_vec();
    smdh.resize(0x40, 0);
    let mut romfs = b"IVFC".to_vec();
    romfs.resize(0x20, 0x33);
    Extras { smdh, romfs }
}

#[test]
fn homebrew_3dsx_lists_its_code_segment_as_arm11_code() {
    let p = classify(&homebrew_3dsx(None));
    assert_eq!(p.format.format, FileFormat::N3ds3dsx);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::Little);
    let code = slice(&p, "Code segment");
    assert_eq!((code.offset, code.size), (56, 0x40));
    assert_eq!(code.isa, Isa::Arm);
    assert!(matches!(slice(&p, "Data segment").isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "data 24 B including 8 B BSS; 1 absolute and 1 relative relocations"
    ));

    let extended = classify(&homebrew_3dsx(Some(&extras())));
    assert_eq!(extended.format.format, FileFormat::N3ds3dsx);
    assert_eq!(slice(&extended, "SMDH").size, 0x40);
    assert_eq!(slice(&extended, "RomFS").size, 0x20);
}

#[test]
fn homebrew_3dsx_rejects_bad_sizes_and_trailing_data() {
    let mut bss = homebrew_3dsx(None);
    put_le32(&mut bss, 0x1c, 0x20);
    let error = detect_payload(&bss, &ClassifierOptions::new()).unwrap_err();
    assert!(error.to_string().contains("Invalid 3DSX BSS size"));

    let mut header = homebrew_3dsx(None);
    put_le16(&mut header, 4, 40);
    assert!(detect_payload(&header, &ClassifierOptions::new()).is_err());

    let mut relocations = homebrew_3dsx(None);
    put_le32(&mut relocations, 32, u32::MAX);
    assert!(detect_payload(&relocations, &ClassifierOptions::new()).is_err());

    let mut trailing = homebrew_3dsx(None);
    trailing.extend_from_slice(b"junk");
    assert!(detect_payload(&trailing, &ClassifierOptions::new()).is_err());
}

// --- PSP PBP ----------------------------------------------------------------

const EM_MIPS: u16 = 8;

/// A 52-byte ELF32 header with the given machine and byte order, type
/// `ET_EXEC`, version 1.
fn elf32(machine: u16, big_endian: bool) -> Vec<u8> {
    let mut elf = vec![0u8; 52];
    elf[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, if big_endian { 2 } else { 1 }, 1]);
    let put16 = |elf: &mut Vec<u8>, at: usize, value: u16| {
        let bytes = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        elf[at..at + 2].copy_from_slice(&bytes);
    };
    put16(&mut elf, 16, 2);
    put16(&mut elf, 18, machine);
    elf
}

/// A PSF table: magic `\0PSF`, version 0x0101, key and data table offsets,
/// entry count, 16-byte index entries (key offset, format 0x0204 UTF-8,
/// length, maximum length, data offset), NUL-terminated keys, then the
/// NUL-terminated values.
fn param_sfo(entries: &[(&str, &str)]) -> Vec<u8> {
    let key_table = 20 + 16 * entries.len();
    let mut keys = Vec::new();
    let mut values = Vec::new();
    let mut index = Vec::new();
    for (key, value) in entries {
        let mut entry = vec![0u8; 16];
        put_le16(&mut entry, 0, keys.len() as u16);
        put_le16(&mut entry, 2, 0x0204);
        put_le32(&mut entry, 4, value.len() as u32 + 1);
        put_le32(&mut entry, 8, value.len() as u32 + 1);
        put_le32(&mut entry, 12, values.len() as u32);
        index.extend_from_slice(&entry);
        keys.extend_from_slice(key.as_bytes());
        keys.push(0);
        values.extend_from_slice(value.as_bytes());
        values.push(0);
    }
    keys.resize((keys.len() + 3) & !3, 0);
    let mut sfo = b"\0PSF".to_vec();
    sfo.extend_from_slice(&0x0101u32.to_le_bytes());
    sfo.extend_from_slice(&(key_table as u32).to_le_bytes());
    sfo.extend_from_slice(&((key_table + keys.len()) as u32).to_le_bytes());
    sfo.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    sfo.extend_from_slice(&index);
    sfo.extend_from_slice(&keys);
    sfo.extend_from_slice(&values);
    sfo
}

/// An encrypted `~PSP` module: the 0x150-byte header (module name at 0x0A,
/// ELF size at 0x28, module size at 0x2C), then either a plain ELF or
/// stand-in ciphertext.
fn psp_module(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut module = vec![0u8; 0x150];
    module[..4].copy_from_slice(b"~PSP");
    module[0x0a..0x0a + name.len()].copy_from_slice(name.as_bytes());
    put_le32(&mut module, 0x28, payload.len() as u32);
    put_le32(&mut module, 0x2c, (0x150 + payload.len()) as u32);
    module.extend_from_slice(payload);
    module
}

/// An EBOOT.PBP: `\0PBP`, version 0x00010000, eight subfile offsets laid
/// out as pack-pbp does (the first at 0x28, each after the previous).
fn pbp(subfiles: [&[u8]; 8]) -> Vec<u8> {
    let mut file = b"\0PBP".to_vec();
    file.extend_from_slice(&0x0001_0000u32.to_le_bytes());
    let mut offset = 0x28u32;
    for subfile in subfiles {
        file.extend_from_slice(&offset.to_le_bytes());
        offset += subfile.len() as u32;
    }
    for subfile in subfiles {
        file.extend_from_slice(subfile);
    }
    file
}

fn homebrew_eboot(data_psp: &[u8]) -> Vec<u8> {
    let sfo = param_sfo(&[
        ("CATEGORY", "MG"),
        ("DISC_ID", "UCJS10001"),
        ("TITLE", "Retro Test"),
    ]);
    let icon = b"\x89PNG\r\n\x1a\nicon".to_vec();
    let empty: &[u8] = &[];
    pbp([&sfo, &icon, empty, empty, empty, empty, data_psp, empty])
}

#[test]
fn psp_pbp_classifies_a_plain_elf_data_psp_on_its_own() {
    let mut elf = elf32(EM_MIPS, false);
    elf.extend_from_slice(&mips_code(0x100));
    let file = homebrew_eboot(&elf);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::PspPbp);
    assert_eq!(p.primary.isa, Isa::Mips);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert!(has_note(
        &p,
        "PARAM.SFO: title Retro Test; category MG; disc ID UCJS10001"
    ));
    assert!(has_note(&p, "DATA.PSP is a plain ELF"));
    let data_psp = slice(&p, "DATA.PSP");
    assert_eq!(data_psp.isa, Isa::Mips);
    assert_eq!(data_psp.size, elf.len() as u64);
    assert!(matches!(slice(&p, "PARAM.SFO").isa, Isa::Unknown(_)));
    assert!(matches!(slice(&p, "ICON0.PNG").isa, Isa::Unknown(_)));
    assert!(matches!(
        custom(&p, "psp_title"),
        Some(MetadataValue::String(s)) if s == "Retro Test"
    ));
}

#[test]
fn psp_encrypted_module_is_opaque_unless_it_stores_a_plain_elf() {
    let encrypted = classify(&homebrew_eboot(&psp_module("Retro", &[0x5a; 0x80])));
    assert_eq!(encrypted.primary.isa, Isa::Mips);
    assert!(has_note(
        &encrypted,
        "DATA.PSP is an encrypted ~PSP module; name Retro"
    ));
    assert!(matches!(slice(&encrypted, "DATA.PSP").isa, Isa::Unknown(_)));

    let mut elf = elf32(EM_MIPS, false);
    elf.extend_from_slice(&mips_code(0x40));
    let fallback = classify(&homebrew_eboot(&psp_module("Retro", &elf)));
    assert!(has_note(&fallback, "stores a plain ELF at 0x150"));
    assert_eq!(slice(&fallback, "DATA.PSP ELF").isa, Isa::Mips);
}

#[test]
fn psp_pbp_offsets_must_increase_and_stay_in_the_file() {
    let mut file = homebrew_eboot(&elf32(EM_MIPS, false));
    put_le32(&mut file, 8 + 4, 0x20);
    let error = detect_payload(&file, &ClassifierOptions::new()).unwrap_err();
    assert!(error
        .to_string()
        .contains("Invalid PBP ICON0.PNG offset 0x20"));

    let mut beyond = homebrew_eboot(&elf32(EM_MIPS, false));
    let len = beyond.len() as u32;
    put_le32(&mut beyond, 8 + 4 * 7, len + 1);
    assert!(detect_payload(&beyond, &ClassifierOptions::new()).is_err());
}

// --- Sweeps -----------------------------------------------------------------

#[test]
fn console_images_survive_truncation() {
    let rom = genesis_rom("SEGA MEGA DRIVE", 0x800);
    truncation_sweep(&rom, FileFormat::GenesisRom, 0x201, 1);
    truncation_sweep(
        &smd(&genesis_rom("SEGA MEGA DRIVE", 0x4000)),
        FileFormat::GenesisRom,
        0x4200,
        97,
    );
    let exe = psx_exe(&mips_code(0x800));
    truncation_sweep(&exe, FileFormat::PsxExe, exe.len(), 1);
    truncation_sweep(&ip_bin(), FileFormat::DreamcastIp, 0x8000, 61);
    let file = rpx(EM_PPC, rpx_sections());
    truncation_sweep(&file, FileFormat::WiiURpx, file.len(), 1);
    let ncch_file = ncch(&CXI);
    truncation_sweep(&ncch_file, FileFormat::N3dsNcch, ncch_file.len(), 1);
    let basic = homebrew_3dsx(None);
    truncation_sweep(&basic, FileFormat::N3ds3dsx, basic.len(), 1);
    let extended = homebrew_3dsx(Some(&extras()));
    truncation_sweep(&extended, FileFormat::N3ds3dsx, extended.len() - 0x20, 1);
    let eboot = homebrew_eboot(&elf32(EM_MIPS, false));
    let last_offset = u32::from_le_bytes(eboot[8 + 4 * 7..8 + 4 * 8].try_into().unwrap());
    truncation_sweep(&eboot, FileFormat::PspPbp, last_offset as usize, 1);
}

#[test]
fn console_images_survive_byte_mutations() {
    mutation_sweep(&genesis_rom("SEGA MEGA DRIVE", 0x400), 0..0x200, 7);
    mutation_sweep(&genesis_32x(), 0x3c0..0x3f0, 13);
    mutation_sweep(&psx_exe(&mips_code(0x800)), 0..0x100, 11);
    mutation_sweep(&ip_bin(), 0..0x100, 509);
    mutation_sweep(&rpx(EM_PPC, rpx_sections()), 0..0x130, 3);
    mutation_sweep(&ncch(&CXI), 0x100..0x260, 5);
    mutation_sweep(&homebrew_3dsx(Some(&extras())), 0..0x40, 1);
    let mut elf = elf32(EM_MIPS, false);
    elf.extend_from_slice(&mips_code(0x40));
    mutation_sweep(&homebrew_eboot(&psp_module("Retro", &elf)), 0..0x28, 1);
}
