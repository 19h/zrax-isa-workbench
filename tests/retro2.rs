//! Console and home-computer images: Master System / Game Gear, 32X,
//! Saturn IP.BIN, Sega CD, MSX, Lynx, Atari 7800, C64 CRT, Atari ST
//! GEMDOS programs, ZX Spectrum .z80 and .sna snapshots, WonderSwan and Neo
//! Geo Pocket, with corrupted fields, truncation and mutation sweeps. All
//! fixtures are synthetic and built here from the documented layouts.

use zrax::formats::container;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey, MetadataValue,
};

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, needle: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(needle))
}

fn custom(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.to_string()))
        .map(|m| m.value.to_string())
}

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

fn variant(p: &DetectionPayload) -> Option<&str> {
    p.primary.variant.as_ref().map(|v| v.name.as_str())
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

/// The family's layout, if `data` is detected as one.
fn layout(data: &[u8]) -> Option<zrax::formats::retro2::Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: container::Kind::Retro2(layout),
        } => Some(layout),
        _ => None,
    }
}

/// Write `text` at `at`, padded with `pad` to `len` bytes.
fn put_text(data: &mut [u8], at: usize, len: usize, text: &str, pad: u8) {
    assert!(text.len() <= len);
    data[at..at + len].fill(pad);
    data[at..at + text.len()].copy_from_slice(text.as_bytes());
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_be16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// Fill `data` with repetitions of `pattern`.
fn fill_with(data: &mut [u8], pattern: &[u8]) {
    for (byte, value) in data.iter_mut().zip(pattern.iter().cycle()) {
        *byte = *value;
    }
}

/// Prefixes shorter than `min_valid` must not parse as `format`; no prefix
/// may panic.
fn truncation_sweep(data: &[u8], format: FileFormat, min_valid: usize, step: usize) {
    for end in (0..data.len()).step_by(step) {
        let result = detect_payload(&data[..end], &ClassifierOptions::new());
        if end < min_valid {
            let claimed = result.is_ok_and(|p| p.format.format == format);
            assert!(!claimed, "prefix of {end} B still parses as {format}");
        }
    }
}

/// Single-byte mutations (0x00, 0xFF, bit flip) of every byte in `header`
/// and every `step`-th byte, classified without panicking.
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

/// Z80: `LD A,1`, `LD (0xC000),A`, `LD HL,0xC000`, `LD A,(HL)`, `INC HL`,
/// `RET`.
const Z80_CODE: [u8; 12] = [
    0x3e, 0x01, 0x32, 0x00, 0xc0, 0x21, 0x00, 0xc0, 0x7e, 0x23, 0xc9, 0x00,
];

/// 68000, big-endian: `LINK A6,#0`, `MOVEQ #1,D0`, `UNLK A6`, `RTS`.
const M68K_CODE: [u8; 10] = [0x4e, 0x56, 0x00, 0x00, 0x70, 0x01, 0x4e, 0x5e, 0x4e, 0x75];

/// SH-2, big-endian: `MOV #1,R0`, `RTS`, `NOP`.
const SH2_CODE: [u8; 6] = [0xe0, 0x01, 0x00, 0x0b, 0x00, 0x09];

/// 6502: `LDA #1`, `STA $0200`, `NOP`, `RTS`.
const MOS6502_CODE: [u8; 7] = [0xa9, 0x01, 0x8d, 0x00, 0x02, 0xea, 0x60];

/// 16-bit x86: `MOV AX,0x1234`, `NOP`, `RET`.
const X86_CODE: [u8; 5] = [0xb8, 0x34, 0x12, 0x90, 0xc3];

/// TLCS-900: `NOP`, `RET`.
const TLCS900_CODE: [u8; 2] = [0x00, 0x0e];

// --- Master System / Game Gear ---------------------------------------------

/// A Master System ROM of `size` bytes: Z80 code from 0, and at `header` the
/// 16-byte `TMR SEGA` header: `TMR SEGA` (8), reserved `00 00`, checksum
/// (little-endian, set by [`set_sms_checksum`]), product code `26 70` (BCD
/// 7026), version 1 in the low nibble of +0xE, region code `region` in the
/// high nibble and ROM size code `size_code` in the low nibble of +0xF.
fn sms_rom(size: usize, header: usize, region: u8, size_code: u8) -> Vec<u8> {
    let mut rom = vec![0u8; size];
    fill_with(&mut rom, &Z80_CODE);
    rom[header..header + 8].copy_from_slice(b"TMR SEGA");
    rom[header + 8..header + 10].fill(0);
    rom[header + 0xc] = 0x26;
    rom[header + 0xd] = 0x70;
    rom[header + 0xe] = 0x01;
    rom[header + 0xf] = (region << 4) | size_code;
    rom
}

/// The checksum over the first `covered` bytes: their 16-bit sum, skipping
/// the 16 header bytes (WLA-DX).
fn set_sms_checksum(rom: &mut [u8], header: usize, covered: usize) {
    let mut sum = 0u16;
    for (i, &b) in rom[..covered].iter().enumerate() {
        if !(header..header + 16).contains(&i) {
            sum = sum.wrapping_add(u16::from(b));
        }
    }
    put_le16(rom, header + 0xa, sum);
}

#[test]
fn sms_export_rom_names_the_z80_and_verifies_its_checksum() {
    let mut rom = sms_rom(0x8000, 0x7ff0, 4, 0xc);
    set_sms_checksum(&mut rom, 0x7ff0, 0x8000);
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::SmsRom);
    assert_eq!(p.format.variant_name.as_deref(), Some("Master System ROM"));
    assert_eq!(p.primary.isa, Isa::Z80);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(entry_point(&p), Some(0));
    assert!(has_note(&p, "ROM checksum 0x"));
    assert!(has_note(&p, "verified over the first 32 KiB"));
    assert!(has_note(&p, "Product code 7026; version 1"));
    assert_eq!(custom(&p, "sms_region").as_deref(), Some("SMS Export"));
}

#[test]
fn game_gear_header_at_0x1ff0_and_checksum_mismatch_are_reported() {
    let rom = sms_rom(0x2000, 0x1ff0, 6, 0xa);
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::SmsRom);
    assert_eq!(p.format.variant_name.as_deref(), Some("Game Gear ROM"));
    assert!(has_note(&p, "TMR SEGA header at 0x1FF0"));
    assert!(has_note(&p, "does not match the computed 0x"));
    assert!(has_note(&p, "only the export Master System BIOS checks it"));
}

#[test]
fn sms_buggy_and_oversized_size_codes_leave_the_checksum_unverified() {
    let buggy = classify(&sms_rom(0x8000, 0x7ff0, 4, 0xd));
    assert!(has_note(&buggy, "is buggy in some BIOS checksum routines"));
    let oversized = classify(&sms_rom(0x8000, 0x7ff0, 4, 0xf));
    assert!(has_note(&oversized, "does not cover the 32768 B file"));
}

#[test]
fn sms_truncations_and_mutations_are_bounded() {
    let mut rom = sms_rom(0x8000, 0x7ff0, 4, 0xc);
    set_sms_checksum(&mut rom, 0x7ff0, 0x8000);
    truncation_sweep(&rom, FileFormat::SmsRom, rom.len(), 509);
    mutation_sweep(&rom, 0x7ff0..0x8000, 4093);
}

// --- Sega 32X ----------------------------------------------------------------

/// A 32X ROM of 0x1000 bytes: 68000 vectors (SSP 0x00FFFE00 at 0, PC
/// 0x000003F0 at 4); the Mega Drive header at 0x100 (system type `SEGA 32X`,
/// titles at 0x120 and 0x150, serial at 0x180, region `JUE` at 0x1F0); 68000
/// code from 0x200; the user header at 0x3C0 (module name `MARS CHECK MODE`,
/// version 0, source 0x800, destination 0, size 0x100, master start
/// 0x06000000, slave start 0x06000004, both VBRs 0x06000000); the security
/// text `MARS Initial & Security Program` at 0x512; SH-2 code at 0x800-0x8FF;
/// the checksum at 0x18E over the words from 0x200.
fn rom_32x() -> Vec<u8> {
    let mut rom = vec![0u8; 0x1000];
    fill_with(&mut rom[0x200..], &M68K_CODE);
    put_be32(&mut rom, 0, 0x00ff_fe00);
    put_be32(&mut rom, 4, 0x0000_03f0);
    put_text(&mut rom, 0x100, 16, "SEGA 32X", b' ');
    put_text(&mut rom, 0x110, 16, "(C)ZRAX 2026.OCT", b' ');
    put_text(&mut rom, 0x120, 48, "SYNTHETIC 32X", b' ');
    put_text(&mut rom, 0x150, 48, "SYNTHETIC 32X", b' ');
    put_text(&mut rom, 0x180, 14, "GM 00000000-00", b' ');
    put_text(&mut rom, 0x1f0, 16, "JUE", b' ');
    put_text(&mut rom, 0x3c0, 16, "MARS CHECK MODE", b' ');
    put_be32(&mut rom, 0x3d0, 0);
    put_be32(&mut rom, 0x3d4, 0x800);
    put_be32(&mut rom, 0x3d8, 0);
    put_be32(&mut rom, 0x3dc, 0x100);
    put_be32(&mut rom, 0x3e0, 0x0600_0000);
    put_be32(&mut rom, 0x3e4, 0x0600_0004);
    put_be32(&mut rom, 0x3e8, 0x0600_0000);
    put_be32(&mut rom, 0x3ec, 0x0600_0000);
    let text = b"MARS Initial & Security Program";
    rom[0x512..0x512 + text.len()].copy_from_slice(text);
    fill_with(&mut rom[0x800..0x900], &SH2_CODE);
    set_genesis_checksum(&mut rom);
    rom
}

/// The Mega Drive checksum: the 16-bit sum of the big-endian words from
/// 0x200.
fn set_genesis_checksum(rom: &mut [u8]) {
    let sum = rom[0x200..]
        .chunks(2)
        .map(|w| u16::from_be_bytes([w[0], w[1]]))
        .fold(0u16, u16::wrapping_add);
    put_be16(rom, 0x18e, sum);
}

#[test]
fn rom_32x_takes_precedence_over_the_mega_drive_and_lists_the_sh2_program() {
    let rom = rom_32x();
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::Sega32xRom);
    assert_eq!(p.primary.isa, Isa::M68k);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(entry_point(&p), Some(0x3f0));
    let sh2 = slice(&p, "32X SH-2 program");
    assert_eq!(sh2.isa, Isa::Sh);
    assert_eq!(sh2.endianness, Endianness::Big);
    assert_eq!((sh2.offset, sh2.size), (0x800, 0x100));
    assert_eq!(
        sh2.variant.as_ref().map(|v| v.name.as_str()),
        Some("SH-2 (SH7095)")
    );
    assert!(has_note(&p, "copied to SDRAM 0x06000000"));
    assert!(has_note(&p, "Mega Drive checksum 0x"));
    assert!(has_note(&p, "verified"));
    assert_eq!(
        custom(&p, "sega32x_section_0").as_deref(),
        Some("file 0x0; destination 0x0; 2048 B")
    );
    assert_eq!(
        custom(&p, "sega32x_section_1").as_deref(),
        Some("file 0x900; destination 0x900; 1792 B")
    );
    assert_eq!(
        custom(&p, "sega32x_module_name").as_deref(),
        Some("MARS CHECK MODE")
    );
}

#[test]
fn rom_32x_without_the_security_text_stays_a_mega_drive_rom() {
    let mut rom = rom_32x();
    rom[0x512] = b'X';
    set_genesis_checksum(&mut rom);
    assert_eq!(classify(&rom).format.format, FileFormat::GenesisRom);
}

#[test]
fn rom_32x_user_header_must_be_aligned_and_fit_rom_and_sdram() {
    let mut unaligned = rom_32x();
    put_be32(&mut unaligned, 0x3d4, 0x802);
    assert!(error_text(&unaligned).contains("source address 0x00000802 is not a multiple of 4"));

    let mut outside = rom_32x();
    put_be32(&mut outside, 0x3dc, 0x1000);
    assert!(error_text(&outside).contains("Truncated 32X SH-2 program"));

    let mut sdram = rom_32x();
    put_be32(&mut sdram, 0x3d8, 0x3_ff04);
    assert!(error_text(&sdram).contains("exceeds the 256 KiB SDRAM"));

    let mut pc = rom_32x();
    put_be32(&mut pc, 4, 0x3f1);
    assert!(error_text(&pc).contains("Invalid initial PC 0x000003F1"));
}

#[test]
fn rom_32x_truncations_and_mutations_are_bounded() {
    let rom = rom_32x();
    truncation_sweep(&rom, FileFormat::Sega32xRom, 0x900, 7);
    mutation_sweep(&rom, 0x3c0..0x3f0, 251);
}

// --- Saturn IP.BIN -----------------------------------------------------------

/// A Saturn IP.BIN of `ip_size` bytes: hardware identifier `SEGA SEGASATURN `,
/// maker ID `SEGA TP T-999   `, product `T-99901G`, version `V1.000`, release
/// date `20261013`, device info `CD-1/1`, areas `JUE`, peripherals `J`,
/// title, IP size (big-endian) at 0xE0, Stack-M and Stack-S 0, 1st read
/// address 0x06004000 and size 0; SH-2 code from 0x100.
fn saturn_ip(ip_size: u32) -> Vec<u8> {
    let mut ip = vec![0u8; ip_size as usize];
    fill_with(&mut ip[0x100..], &SH2_CODE);
    ip[..0x100].fill(b' ');
    ip[0x00..0x10].copy_from_slice(b"SEGA SEGASATURN ");
    put_text(&mut ip, 0x10, 16, "SEGA TP T-999", b' ');
    put_text(&mut ip, 0x20, 10, "T-99901G", b' ');
    put_text(&mut ip, 0x2a, 6, "V1.000", b' ');
    put_text(&mut ip, 0x30, 8, "20261013", b' ');
    put_text(&mut ip, 0x38, 8, "CD-1/1", b' ');
    put_text(&mut ip, 0x40, 10, "JUE", b' ');
    put_text(&mut ip, 0x50, 16, "J", b' ');
    put_text(&mut ip, 0x60, 112, "SYNTHETIC SATURN", b' ');
    ip[0xd0..0x100].fill(0);
    put_be32(&mut ip, 0xe0, ip_size);
    put_be32(&mut ip, 0xf0, 0x0600_4000);
    ip
}

#[test]
fn saturn_ip_bin_names_the_sh2_and_loads_at_0x06002000() {
    let mut disc = saturn_ip(0x1800);
    disc.extend_from_slice(&[0u8; 0x800]);
    let p = classify(&disc);
    assert_eq!(p.format.format, FileFormat::SaturnIp);
    assert_eq!(p.primary.isa, Isa::Sh);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(variant(&p), Some("SH-2"));
    assert_eq!(entry_point(&p), Some(0x0600_2e00));
    assert!(has_note(
        &p,
        "Compatible areas: Japan, North America, Europe PAL"
    ));
    assert!(has_note(&p, "transferred to 0x06004000"));
    assert!(has_note(&p, "follow the IP at 0x1800 and are not analyzed"));
    assert_eq!(
        custom(&p, "saturn_section_0").as_deref(),
        Some("file 0x100; destination 0x6002100; 3328 B")
    );
    assert_eq!(
        custom(&p, "saturn_section_1").as_deref(),
        Some("file 0xE00; destination 0x6002E00; 2560 B")
    );
    assert_eq!(
        custom(&p, "saturn_product_number").as_deref(),
        Some("T-99901G")
    );
}

#[test]
fn saturn_ip_size_must_be_aligned_in_range_and_present() {
    let mut odd = saturn_ip(0x1800);
    put_be32(&mut odd, 0xe0, 0x1802);
    assert!(error_text(&odd).contains("Invalid IP size 0x1802"));
    let mut large = saturn_ip(0x1800);
    put_be32(&mut large, 0xe0, 0x9000);
    assert!(error_text(&large).contains("Invalid IP size 0x9000"));
    let short = saturn_ip(0x1800);
    assert!(error_text(&short[..0x1000]).contains("Truncated Saturn IP"));
}

#[test]
fn saturn_truncations_and_mutations_are_bounded() {
    let ip = saturn_ip(0x1000);
    truncation_sweep(&ip, FileFormat::SaturnIp, ip.len(), 61);
    mutation_sweep(&ip, 0xe0..0x100, 509);
}

// --- Sega CD -----------------------------------------------------------------

/// A Sega CD system area of 0x1000 bytes: `SEGADISCSYSTEM  ` at 0, volume
/// name `ZRAXTEST` at 0x10, system name `ZRAXBOOT` at 0x20; IP at 0x200 of
/// 0x600 B (entry 0, work RAM 0) at 0x30-0x3F; SP at 0x800 of 0x800 B (entry
/// 0x20, work RAM 0x1000) at 0x40-0x4F; the disc ID with `SEGA MEGA DRIVE` at
/// 0x100, titles at 0x120 and 0x150, product `GM 00000000-00` at 0x180 and
/// region `JUE` at 0x1F0; 68000 code in the IP and SP.
fn sega_cd() -> Vec<u8> {
    let mut disc = vec![0u8; 0x1000];
    fill_with(&mut disc[0x200..], &M68K_CODE);
    put_text(&mut disc, 0x00, 16, "SEGADISCSYSTEM", b' ');
    put_text(&mut disc, 0x10, 11, "ZRAXTEST", b' ');
    put_text(&mut disc, 0x20, 11, "ZRAXBOOT", b' ');
    put_be32(&mut disc, 0x30, 0x200);
    put_be32(&mut disc, 0x34, 0x600);
    put_be32(&mut disc, 0x38, 0);
    put_be32(&mut disc, 0x3c, 0);
    put_be32(&mut disc, 0x40, 0x800);
    put_be32(&mut disc, 0x44, 0x800);
    put_be32(&mut disc, 0x48, 0x20);
    put_be32(&mut disc, 0x4c, 0x1000);
    put_text(&mut disc, 0x100, 16, "SEGA MEGA DRIVE", b' ');
    put_text(&mut disc, 0x110, 16, "(C)ZRAX 2026.OCT", b' ');
    put_text(&mut disc, 0x120, 48, "SYNTHETIC CD", b' ');
    put_text(&mut disc, 0x150, 48, "SYNTHETIC CD", b' ');
    put_text(&mut disc, 0x180, 14, "GM 00000000-00", b' ');
    put_text(&mut disc, 0x1f0, 16, "JUE", b' ');
    disc
}

#[test]
fn sega_cd_lists_the_main_and_sub_cpu_programs_as_68000_children() {
    let p = classify(&sega_cd());
    assert_eq!(p.format.format, FileFormat::SegaCdIp);
    assert_eq!(p.primary.isa, Isa::M68k);
    let ip = slice(&p, "Initial program (main CPU)");
    assert_eq!((ip.isa, ip.offset, ip.size), (Isa::M68k, 0x200, 0x600));
    assert_eq!(
        ip.variant.as_ref().map(|v| v.name.as_str()),
        Some("MC68000 (main CPU)")
    );
    let sp = slice(&p, "System program (sub-CPU)");
    assert_eq!((sp.isa, sp.offset, sp.size), (Isa::M68k, 0x800, 0x800));
    assert_eq!(
        sp.variant.as_ref().map(|v| v.name.as_str()),
        Some("MC68000 (sub-CPU)")
    );
    assert!(has_note(&p, "entry offset 0x20"));
    assert_eq!(custom(&p, "segacd_region").as_deref(), Some("JUE"));
}

#[test]
fn sega_cd_programs_must_lie_in_the_file_and_data_discs_are_not_boot_discs() {
    let mut outside = sega_cd();
    put_be32(&mut outside, 0x44, 0x1000);
    assert!(error_text(&outside).contains("Truncated System program (sub-CPU)"));

    let mut unaligned = sega_cd();
    put_be32(&mut unaligned, 0x40, 0x810);
    put_be32(&mut unaligned, 0x44, 0x7f0);
    let p = classify(&unaligned);
    assert!(has_note(&p, "is not on a 2048-byte sector boundary"));

    let mut data_disc = sega_cd();
    put_text(&mut data_disc, 0x00, 16, "SEGADATADISC", b' ');
    assert_ne!(classify(&data_disc).format.format, FileFormat::SegaCdIp);
}

#[test]
fn sega_cd_truncations_and_mutations_are_bounded() {
    let disc = sega_cd();
    truncation_sweep(&disc, FileFormat::SegaCdIp, disc.len(), 13);
    mutation_sweep(&disc, 0x30..0x50, 509);
}

// --- MSX -----------------------------------------------------------------------

/// An MSX cartridge of `size` bytes: `AB`, INIT `init` (little-endian) at 2,
/// STATEMENT, DEVICE and TEXT 0, six zero reserved bytes, then Z80 code.
fn msx_rom(size: usize, init: u16) -> Vec<u8> {
    let mut rom = vec![0u8; size];
    fill_with(&mut rom[0x10..], &Z80_CODE);
    rom[..2].copy_from_slice(b"AB");
    put_le16(&mut rom, 2, init);
    rom
}

#[test]
fn msx_header_address_follows_from_init_and_is_weak() {
    let page1 = classify(&msx_rom(0x8000, 0x4010));
    assert_eq!(page1.format.format, FileFormat::MsxRom);
    assert_eq!(
        page1.format.variant_name.as_deref(),
        Some("MSX cartridge ROM at 0x4000")
    );
    assert!(page1.format.confidence < 1.0);
    assert_eq!(page1.primary.isa, Isa::Z80);
    assert_eq!(entry_point(&page1), Some(0x4010));
    assert_eq!(
        custom(&page1, "msx_section_0").as_deref(),
        Some("file 0x0; destination 0x4000; 32768 B")
    );

    let page2 = classify(&msx_rom(0x4000, 0x8010));
    assert_eq!(
        page2.format.variant_name.as_deref(),
        Some("MSX cartridge ROM at 0x8000")
    );
    assert_eq!(entry_point(&page2), Some(0x8010));
}

#[test]
fn msx_basic_cartridge_points_text_at_a_zero_byte() {
    let mut rom = msx_rom(0x4000, 0);
    put_le16(&mut rom, 8, 0x8010);
    rom[0x10] = 0;
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::MsxRom);
    assert!(has_note(&p, "No INIT routine"));
    assert!(has_note(&p, "BASIC program text at 0x8010"));
    rom[0x10] = 0x3e;
    assert_ne!(classify(&rom).format.format, FileFormat::MsxRom);
}

#[test]
fn msx_headers_that_fit_no_page_are_not_recognized() {
    let mut reserved = msx_rom(0x4000, 0x4010);
    reserved[0xa] = 1;
    assert_eq!(layout(&reserved), None);
    assert_eq!(layout(&msx_rom(0x2000, 0x6010)), None);
    assert_eq!(layout(&msx_rom(0x4000, 0)), None);
    let mut statement = msx_rom(0x4000, 0x8010);
    put_le16(&mut statement, 4, 0x4100);
    assert_eq!(layout(&statement), None);
}

#[test]
fn msx_truncations_and_mutations_are_bounded() {
    let rom = msx_rom(0x4000, 0x4010);
    truncation_sweep(&rom, FileFormat::MsxRom, 0x11, 97);
    mutation_sweep(&rom, 0..0x10, 2039);
}

// --- Atari Lynx ------------------------------------------------------------------

/// An LNX image: `LYNX`, bank 0 page size `page0` and bank 1 page size 0
/// (little-endian), version 1, cart name `ZRAXLYNX` (32), manufacturer
/// `ZRAX` (16), rotation 0, 5 spare bytes; then `data_len` bytes of 6502
/// code.
fn lynx(page0: u16, data_len: usize) -> Vec<u8> {
    let mut image = vec![0u8; 64 + data_len];
    image[..4].copy_from_slice(b"LYNX");
    put_le16(&mut image, 4, page0);
    put_le16(&mut image, 6, 0);
    put_le16(&mut image, 8, 1);
    put_text(&mut image, 0x0a, 32, "ZRAXLYNX", 0);
    put_text(&mut image, 0x2a, 16, "ZRAX", 0);
    fill_with(&mut image[64..], &MOS6502_CODE);
    image
}

#[test]
fn lynx_cartridge_names_the_65c02_and_lists_bank_0() {
    let p = classify(&lynx(0x100, 0x1_0000));
    assert_eq!(p.format.format, FileFormat::LynxRom);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(variant(&p), Some("65C02"));
    assert!(has_note(&p, "Bank 0: 64 KiB; bank 1: unused"));
    assert!(has_note(&p, "decryption is not attempted"));
    assert_eq!(
        custom(&p, "lynx_section_0").as_deref(),
        Some("file 0x40; destination 0x0; 65536 B")
    );
    let short = classify(&lynx(0x200, 0x1000));
    assert!(has_note(&short, "shorter than the declared banks"));
}

#[test]
fn lynx_page_sizes_versions_and_overlong_data_are_checked() {
    assert!(error_text(&lynx(0x300, 0x100)).contains("Unsupported bank 0 page size 0x300"));
    assert!(error_text(&lynx(0x100, 0x1_0001)).contains("Invalid trailing data"));
    let mut version = lynx(0x100, 0x100);
    put_le16(&mut version, 8, 2);
    assert_eq!(layout(&version), None);
}

#[test]
fn lynx_truncations_and_mutations_are_bounded() {
    let image = lynx(0x100, 0x1000);
    truncation_sweep(&image, FileFormat::LynxRom, 65, 37);
    mutation_sweep(&image, 0..64, 1021);
}

// --- Atari 7800 ------------------------------------------------------------------

/// An A78 image with a `size`-byte ROM: header version 3, `ATARI7800`
/// padded with NULs to 16 bytes at 1, title (32) at 0x11, ROM size
/// (big-endian) at 0x31, cart type `cart_type` (big-endian) at 0x35, two
/// 7800 joysticks, NTSC, no save device, `ACTUAL CART DATA STARTS HERE` at
/// 0x64; then 6502 code with the reset vector 0x8000 (little-endian) at
/// 0xFFFC, the ROM's last four bytes but two.
fn a78(size: usize, cart_type: u16) -> Vec<u8> {
    let mut image = vec![0u8; 128 + size];
    image[0] = 3;
    put_text(&mut image, 1, 16, "ATARI7800", 0);
    put_text(&mut image, 0x11, 32, "SYNTHETIC 7800", 0);
    put_be32(&mut image, 0x31, size as u32);
    put_be16(&mut image, 0x35, cart_type);
    image[0x37] = 1;
    image[0x38] = 1;
    image[0x64..0x80].copy_from_slice(b"ACTUAL CART DATA STARTS HERE");
    fill_with(&mut image[128..], &MOS6502_CODE);
    let end = image.len();
    put_le16(&mut image, end - 4, 0x8000);
    image
}

#[test]
fn atari_7800_unbanked_rom_ends_at_0xffff_and_starts_at_its_reset_vector() {
    let p = classify(&a78(0x8000, 0));
    assert_eq!(p.format.format, FileFormat::Atari7800Rom);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(variant(&p), Some("6502"));
    assert_eq!(entry_point(&p), Some(0x8000));
    assert!(has_note(&p, "reset vector 0x8000 at 0xFFFC"));
    assert_eq!(
        custom(&p, "a7800_section_0").as_deref(),
        Some("file 0x80; destination 0x8000; 32768 B")
    );
}

#[test]
fn atari_7800_banked_rom_has_no_entry_and_bad_sizes_are_errors() {
    let banked = classify(&a78(0x2_0000, 0x0002));
    assert_eq!(entry_point(&banked), None);
    assert!(has_note(&banked, "SuperGame bank switching"));
    let mut truncated = a78(0x8000, 0);
    truncated.truncate(0x4000);
    assert!(error_text(&truncated).contains("Truncated A78 ROM data"));
    let mut trailing = a78(0x8000, 0);
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("Invalid trailing data"));
}

#[test]
fn atari_7800_truncations_and_mutations_are_bounded() {
    let image = a78(0x4000, 0);
    truncation_sweep(&image, FileFormat::Atari7800Rom, image.len(), 113);
    mutation_sweep(&image, 0..128, 1021);
}

// --- C64 CRT -------------------------------------------------------------------

/// A CRT image: `C64 CARTRIDGE   `, header length `header_length`, version
/// 1.00, hardware type 0, EXROM 0, GAME 1, subtype 0, name `ZRAX CART`
/// (NUL-padded); then one CHIP packet per entry of `chips` (type, bank, load
/// address, data): `CHIP`, packet length (data + 0x10), type, bank, load
/// address, image size, data; all big-endian.
fn crt(header_length: u32, chips: &[(u16, u16, u16, Vec<u8>)]) -> Vec<u8> {
    let mut image = vec![0u8; 0x40];
    image[..16].copy_from_slice(b"C64 CARTRIDGE   ");
    put_be32(&mut image, 0x10, header_length);
    put_be16(&mut image, 0x14, 0x0100);
    image[0x18] = 0;
    image[0x19] = 1;
    put_text(&mut image, 0x20, 32, "ZRAX CART", 0);
    for (kind, bank, address, bytes) in chips {
        let mut packet = vec![0u8; 0x10];
        packet[..4].copy_from_slice(b"CHIP");
        put_be32(&mut packet, 4, bytes.len() as u32 + 0x10);
        put_be16(&mut packet, 8, *kind);
        put_be16(&mut packet, 0xa, *bank);
        put_be16(&mut packet, 0xc, *address);
        put_be16(&mut packet, 0xe, bytes.len() as u16);
        image.extend_from_slice(&packet);
        image.extend_from_slice(bytes);
    }
    image
}

fn code_6502(size: usize) -> Vec<u8> {
    let mut code = vec![0u8; size];
    fill_with(&mut code, &MOS6502_CODE);
    code
}

#[test]
fn c64_crt_lists_each_chip_as_6510_code_and_ram_as_opaque() {
    let image = crt(
        0x40,
        &[
            (0, 0, 0x8000, code_6502(0x2000)),
            (0, 0, 0xa000, code_6502(0x2000)),
            (1, 0, 0xde00, vec![0; 0x100]),
        ],
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::C64Crt);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(variant(&p), Some("6510"));
    let roml = slice(&p, "CHIP bank 0 at 0x8000 (ROM)");
    assert_eq!(
        (roml.isa, roml.offset, roml.size),
        (Isa::Mcs6502, 0x50, 0x2000)
    );
    assert_eq!(roml.variant.as_ref().map(|v| v.name.as_str()), Some("6510"));
    let romh = slice(&p, "CHIP bank 0 at 0xA000 (ROM)");
    assert_eq!(romh.offset, 0x2060);
    let ram = slice(&p, "CHIP bank 0 at 0xDE00 (RAM)");
    assert!(matches!(ram.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "CHIP bank 0 at 0xDE00 (RAM): opaque"));
    assert_eq!(custom(&p, "c64crt_chip_count").as_deref(), Some("3"));
}

#[test]
fn c64_crt_chip_packets_are_validated() {
    let mut signature = crt(0x40, &[(0, 0, 0x8000, code_6502(0x100))]);
    signature[0x40] = b'X';
    assert!(error_text(&signature).contains("Invalid CHIP packet signature at 0x40"));
    let wrapped = crt(0x40, &[(0, 0, 0xff00, code_6502(0x200))]);
    assert!(error_text(&wrapped).contains("exceeds the 64 KiB address space"));
    assert!(error_text(&crt(0x40, &[])).contains("Missing CHIP packets"));
    let low = classify(&crt(0x20, &[(0, 0, 0x8000, code_6502(0x100))]));
    assert!(has_note(&low, "is below the minimum 0x40"));
}

#[test]
fn c64_crt_truncations_and_mutations_are_bounded() {
    let image = crt(0x40, &[(0, 0, 0x8000, code_6502(0x400))]);
    truncation_sweep(&image, FileFormat::C64Crt, image.len(), 11);
    mutation_sweep(&image, 0..0x50, 127);
}

// --- Atari ST GEMDOS ---------------------------------------------------------------

/// A GEMDOS program: magic 0x601A, TEXT size, DATA size, BSS 0x100, symbol
/// size, reserved 0, flags `flags`, absflag `absolute`, all big-endian; then
/// TEXT (68000 code), DATA (zeros), symbols (`symbols` bytes of 0x20) and,
/// unless absolute, the relocation table `relocation`.
fn gemdos(
    text: usize,
    data: usize,
    symbols: usize,
    flags: u32,
    absolute: bool,
    relocation: &[u8],
) -> Vec<u8> {
    let mut program = vec![0u8; 0x1c];
    put_be16(&mut program, 0, 0x601a);
    put_be32(&mut program, 2, text as u32);
    put_be32(&mut program, 6, data as u32);
    put_be32(&mut program, 0xa, 0x100);
    put_be32(&mut program, 0xe, symbols as u32);
    put_be32(&mut program, 0x16, flags);
    put_be16(&mut program, 0x1a, u16::from(absolute));
    let mut segment = vec![0u8; text];
    fill_with(&mut segment, &M68K_CODE);
    program.extend_from_slice(&segment);
    program.extend(std::iter::repeat(0u8).take(data));
    program.extend(std::iter::repeat(0x20u8).take(symbols));
    if !absolute {
        program.extend_from_slice(relocation);
    }
    program
}

/// A relocation table: first fixup at TEXT offset 4, then +254 (byte 1),
/// +6 (fixup at 264), end.
const RELOCATION: [u8; 7] = [0, 0, 0, 4, 1, 6, 0];

#[test]
fn gemdos_program_text_is_68000_code_with_validated_fixups() {
    let p = classify(&gemdos(0x200, 0x40, 28, 0x0000_0001, false, &RELOCATION));
    assert_eq!(p.format.format, FileFormat::AtariStPrg);
    assert_eq!(p.primary.isa, Isa::M68k);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(entry_point(&p), Some(0));
    assert!(has_note(&p, "2 fixups of 32-bit addresses"));
    assert!(has_note(
        &p,
        "Symbol table of 28 B: 2 Digital Research entries"
    ));
    assert!(has_note(&p, "Program flags 0x00000001: fastload"));
    assert_eq!(
        custom(&p, "atarist_section_0").as_deref(),
        Some("file 0x1C; destination 0x0; 512 B")
    );
    assert_eq!(custom(&p, "atarist_fixup_count").as_deref(), Some("2"));
}

#[test]
fn gemdos_absolute_programs_need_no_relocation_table() {
    let p = classify(&gemdos(0x100, 0, 0, 0, true, &[]));
    assert_eq!(p.format.format, FileFormat::AtariStPrg);
    assert!(has_note(&p, "Absolute program"));
}

#[test]
fn gemdos_magic_without_a_valid_table_is_not_a_program() {
    let outside = gemdos(0x100, 0, 0, 0, false, &[0, 0, 0x01, 0x00, 0]);
    assert_eq!(layout(&outside), None);
    let odd = gemdos(0x100, 0, 0, 0, false, &[0, 0, 0, 4, 3, 0]);
    assert_eq!(layout(&odd), None);
    let unterminated = gemdos(0x100, 0, 0, 0, false, &[0, 0, 0, 4, 2]);
    assert_eq!(layout(&unterminated), None);
    let mut oversized = gemdos(0x200, 0, 0, 0, false, &RELOCATION);
    put_be32(&mut oversized, 2, 0x1000);
    assert_eq!(layout(&oversized), None);
    let mut trailing = gemdos(0x200, 0, 0, 0, false, &RELOCATION);
    trailing.extend_from_slice(b"appended");
    assert!(error_text(&trailing).contains("Invalid trailing data"));
}

#[test]
fn gemdos_truncations_and_mutations_are_bounded() {
    let program = gemdos(0x200, 0x40, 28, 0, false, &RELOCATION);
    truncation_sweep(&program, FileFormat::AtariStPrg, program.len(), 3);
    mutation_sweep(&program, 0..0x1c, 17);
}

// --- ZX Spectrum snapshots ---------------------------------------------------------

/// Compress `bytes` with the `.z80` scheme: runs of at least five equal
/// bytes, or of at least two `ED` bytes, become `ED ED count byte` (count
/// at most 255); a byte directly after a single literal `ED` is never the
/// start of a run.
fn z80_compress(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut after_single_ed = false;
    while i < bytes.len() {
        let value = bytes[i];
        let mut run = 1;
        while i + run < bytes.len() && bytes[i + run] == value && run < 255 {
            run += 1;
        }
        let worth = run >= 5 || (value == 0xed && run >= 2);
        if worth && !after_single_ed {
            out.extend_from_slice(&[0xed, 0xed, run as u8, value]);
            i += run;
            after_single_ed = false;
        } else {
            out.push(value);
            after_single_ed = value == 0xed && !after_single_ed;
            i += 1;
        }
    }
    out
}

/// 16 KiB of RAM: Z80 code at the start, a run of `ED` bytes, `ED` followed
/// by zeros, then zeros with a page marker byte every 4 KiB.
fn ram_page(marker: u8) -> Vec<u8> {
    let mut page = vec![0u8; 0x4000];
    fill_with(&mut page[..0x100], &Z80_CODE);
    page[0x100..0x104].fill(0xed);
    page[0x110] = 0xed;
    for at in (0..0x4000).step_by(0x1000) {
        page[at + 0x800] = marker;
    }
    page
}

/// A `.z80` version 1 header (30 bytes): A 0x12, F 0x34, BC, HL, PC
/// 0x8000, SP 0xFF00, I 0x3F, R 0x01, flags (border 2, compressed), DE,
/// BC', DE', HL', A', F', IY 0x5C3A, IX, IFF1 and IFF2 set, interrupt mode 1;
/// then the compressed 48 KiB RAM and the end marker `00 ED ED 00`.
fn z80_v1() -> Vec<u8> {
    let mut header = vec![0u8; 30];
    header[0] = 0x12;
    header[1] = 0x34;
    put_le16(&mut header, 6, 0x8000);
    put_le16(&mut header, 8, 0xff00);
    header[10] = 0x3f;
    header[11] = 0x01;
    header[12] = (2 << 1) | 0x20;
    put_le16(&mut header, 23, 0x5c3a);
    header[27] = 1;
    header[28] = 1;
    header[29] = 1;
    let ram: Vec<u8> = [ram_page(8), ram_page(4), ram_page(5)].concat();
    header.extend_from_slice(&z80_compress(&ram));
    header.extend_from_slice(&[0x00, 0xed, 0xed, 0x00]);
    header
}

/// A `.z80` version 2 or 3 file: the 30-byte header with PC 0, interrupt
/// mode 1; the additional header of `extra` bytes (23 for v2, 54 for v3)
/// with its length at 30, PC 0x8000 at 32, hardware mode `mode` at 34 and
/// `port_7ffd` at 35; then one block per page: length (little-endian; 0xFFFF
/// for an uncompressed page), page number, data.
fn z80_paged(extra: u16, mode: u8, port_7ffd: u8, pages: &[u8], raw_page: Option<u8>) -> Vec<u8> {
    let mut file = vec![0u8; 32 + usize::from(extra)];
    put_le16(&mut file, 8, 0xff00);
    file[29] = 1;
    put_le16(&mut file, 30, extra);
    put_le16(&mut file, 32, 0x8000);
    file[34] = mode;
    file[35] = port_7ffd;
    for &page in pages {
        let contents = ram_page(page);
        if raw_page == Some(page) {
            file.extend_from_slice(&0xffffu16.to_le_bytes());
            file.push(page);
            file.extend_from_slice(&contents);
        } else {
            let packed = z80_compress(&contents);
            file.extend_from_slice(&(packed.len() as u16).to_le_bytes());
            file.push(page);
            file.extend_from_slice(&packed);
        }
    }
    file
}

#[test]
fn z80_version_1_decodes_48k_of_ram_at_0x4000() {
    let file = z80_v1();
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::ZxSnapshot);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some(".z80 snapshot version 1")
    );
    assert!(p.format.confidence < 1.0);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert_eq!(entry_point(&p), Some(0x8000));
    let section = custom(&p, "zxsnap_section_0").expect("RAM section");
    assert!(
        section.starts_with("file 0x1E; destination 0x4000;"),
        "{section}"
    );
    assert!(
        section.ends_with("B stored; 49152 B decoded (Z80 RLE)"),
        "{section}"
    );
}

#[test]
fn z80_versions_2_and_3_decode_their_pages_per_machine() {
    let v3 = classify(&z80_paged(54, 0, 0, &[4, 5, 8], Some(5)));
    assert_eq!(v3.format.format, FileFormat::ZxSnapshot);
    assert_eq!(
        v3.format.variant_name.as_deref(),
        Some(".z80 snapshot version 3")
    );
    assert_eq!(entry_point(&v3), Some(0x8000));
    assert_eq!(custom(&v3, "zxsnap_machine").as_deref(), Some("48K"));
    let raw = custom(&v3, "zxsnap_section_1").expect("page 5");
    assert!(raw.contains("destination 0xC000; 16384 B"), "{raw}");
    assert!(!raw.contains("decoded"), "{raw}");

    // Version 2 mode 3 is a 128K machine; port 0x7FFD 0x13 pages bank 3.
    let v2 = classify(&z80_paged(23, 3, 0x13, &[3, 4, 5, 6, 7, 8, 9, 10], None));
    assert_eq!(
        v2.format.variant_name.as_deref(),
        Some(".z80 snapshot version 2")
    );
    assert_eq!(custom(&v2, "zxsnap_machine").as_deref(), Some("128K-class"));
    assert!(has_note(&v2, "RAM bank 3 at 0xC000"));
    let bank5 = custom(&v2, "zxsnap_section_5").expect("page 8 is bank 5");
    assert!(bank5.contains("destination 0x4000"), "{bank5}");
    assert!(bank5.ends_with("16384 B decoded (Z80 RLE)"), "{bank5}");
}

#[test]
fn z80_snapshots_with_bad_blocks_or_pages_are_not_recognized() {
    let mut overshoot = z80_v1();
    let end = overshoot.len();
    overshoot[end - 8..end - 4].copy_from_slice(&[0xed, 0xed, 0xff, 0x00]);
    assert_eq!(layout(&overshoot), None);
    let mut no_marker = z80_v1();
    no_marker.truncate(no_marker.len() - 4);
    assert_eq!(layout(&no_marker), None);
    assert_eq!(layout(&z80_paged(54, 0, 0, &[4, 5], None)), None);
    assert_eq!(layout(&z80_paged(54, 0, 0, &[4, 5, 8, 8], None)), None);
    assert_eq!(layout(&z80_paged(54, 10, 0, &[4, 5, 8], None)), None);
    assert_eq!(layout(&z80_paged(40, 0, 0, &[4, 5, 8], None)), None);
    let mut im3 = z80_v1();
    im3[29] = 3;
    assert_eq!(layout(&im3), None);
}

/// A 48K `.sna` file: I 0x3F, the alternate and main register pairs, IY
/// 0x5C3A, interrupt byte 0x04 (IFF2), R, AF, SP 0xFF00 at 23, interrupt
/// mode 1, border 7; then the 48 KiB RAM with the PC 0x8000 pushed at SP.
fn sna_48k() -> Vec<u8> {
    let mut file = vec![0u8; 27];
    file[0] = 0x3f;
    put_le16(&mut file, 15, 0x5c3a);
    file[19] = 0x04;
    put_le16(&mut file, 23, 0xff00);
    file[25] = 1;
    file[26] = 7;
    file.extend_from_slice(&[ram_page(5), ram_page(2), ram_page(0)].concat());
    put_le16(&mut file, 27 + 0xbf00, 0x8000);
    file
}

/// A 128K `.sna` file with bank `paged` at 0xC000: the 27-byte header, banks
/// 5, 2 and `paged`, PC 0x9000, port 0x7FFD `0x10 | paged`, TR-DOS 0, then
/// the remaining banks in ascending order (bank `paged` is not repeated
/// unless it is 5 or 2).
fn sna_128k(paged: u8) -> Vec<u8> {
    let mut file = vec![0u8; 27];
    put_le16(&mut file, 23, 0xff00);
    file[25] = 1;
    file[26] = 1;
    for bank in [5, 2, paged] {
        file.extend_from_slice(&ram_page(bank));
    }
    file.extend_from_slice(&0x9000u16.to_le_bytes());
    file.push(0x10 | paged);
    file.push(0);
    for bank in (0u8..8).filter(|b| *b != 5 && *b != 2 && *b != paged) {
        file.extend_from_slice(&ram_page(bank));
    }
    file
}

#[test]
fn sna_snapshots_take_the_pc_from_the_stack_or_the_128k_header() {
    let p48 = classify(&sna_48k());
    assert_eq!(p48.format.format, FileFormat::ZxSnapshot);
    assert_eq!(
        p48.format.variant_name.as_deref(),
        Some(".sna 48K snapshot")
    );
    assert_eq!(p48.primary.isa, Isa::Z80);
    assert_eq!(entry_point(&p48), Some(0x8000));
    assert!(has_note(&p48, "read from the stack at SP 0xFF00"));

    let p128 = classify(&sna_128k(0));
    assert_eq!(sna_128k(0).len(), 131_103);
    assert_eq!(
        p128.format.variant_name.as_deref(),
        Some(".sna 128K snapshot")
    );
    assert_eq!(entry_point(&p128), Some(0x9000));
    assert_eq!(
        custom(&p128, "zxsnap_section_2").as_deref(),
        Some("file 0x801B; destination 0xC000; 16384 B")
    );
    let twice = classify(&sna_128k(5));
    assert_eq!(sna_128k(5).len(), 147_487);
    assert_eq!(twice.format.format, FileFormat::ZxSnapshot);
    assert!(p128.metadata.len() < twice.metadata.len());
}

#[test]
fn sna_registers_must_be_consistent_with_the_size() {
    let mut im = sna_48k();
    im[25] = 3;
    assert_eq!(layout(&im), None);
    let mut border = sna_48k();
    border[26] = 8;
    assert_eq!(layout(&border), None);
    let mut sp = sna_48k();
    put_le16(&mut sp, 23, 0x3000);
    assert_eq!(layout(&sp), None);
    let mut bank = sna_128k(0);
    bank[49_181] = 0x15;
    assert_eq!(layout(&bank), None);
}

#[test]
fn zx_snapshot_truncations_and_mutations_are_bounded() {
    let v1 = z80_v1();
    truncation_sweep(&v1, FileFormat::ZxSnapshot, v1.len(), 97);
    mutation_sweep(&v1, 0..30, 509);
    let v3 = z80_paged(54, 0, 0, &[4, 5, 8], None);
    truncation_sweep(&v3, FileFormat::ZxSnapshot, v3.len(), 89);
    mutation_sweep(&v3, 0..90, 509);
    let sna = sna_48k();
    truncation_sweep(&sna, FileFormat::ZxSnapshot, sna.len(), 4099);
    mutation_sweep(&sna, 0..27, 8191);
}

// --- WonderSwan ------------------------------------------------------------------

/// A 512 KiB WonderSwan Color ROM: 16-bit x86 code; at the end, a far jump
/// `EA 00 00 00 40` 16 bytes from the end, the zero byte 11 bytes from the
/// end, and the 10-byte footer: publisher 0x01, system 1 (Color), game ID
/// 0x23, revision 0, ROM size code 2 (4 Mbit), save type 1 (8 KiB SRAM),
/// flags 0x04 (1-cycle ROM access), RTC 0, and the checksum (little-endian):
/// the sum of every byte but the last two.
fn wonderswan() -> Vec<u8> {
    let mut rom = vec![0u8; 512 << 10];
    fill_with(&mut rom, &X86_CODE);
    let end = rom.len();
    rom[end - 16..end - 11].copy_from_slice(&[0xea, 0x00, 0x00, 0x00, 0x40]);
    rom[end - 11] = 0;
    rom[end - 10..end - 2].copy_from_slice(&[0x01, 0x01, 0x23, 0x00, 0x02, 0x01, 0x04, 0x00]);
    let sum = rom[..end - 2]
        .iter()
        .fold(0u16, |sum, &b| sum.wrapping_add(u16::from(b)));
    put_le16(&mut rom, end - 2, sum);
    rom
}

#[test]
fn wonderswan_rom_names_the_v30mz_and_verifies_its_checksum() {
    let p = classify(&wonderswan());
    assert_eq!(p.format.format, FileFormat::WonderSwanRom);
    assert!(p.format.confidence < 1.0);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.bitwidth, 16);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(variant(&p), Some("NEC V30MZ"));
    assert_eq!(entry_point(&p), Some(0xffff0));
    assert!(has_note(&p, "WonderSwan Color ROM of 512 KiB"));
    assert!(has_note(
        &p,
        "verified (sum of all bytes except the last two)"
    ));
}

#[test]
fn wonderswan_footer_must_match_size_zero_byte_and_checksum() {
    let mut checksum = wonderswan();
    let end = checksum.len();
    checksum[end - 1] ^= 1;
    assert_eq!(layout(&checksum), None);
    let mut zero = wonderswan();
    zero[end - 11] = 1;
    assert_eq!(layout(&zero), None);
    let mut code = wonderswan();
    code[end - 6] = 0x03;
    assert_eq!(layout(&code), None);
}

#[test]
fn wonderswan_truncations_and_mutations_are_bounded() {
    let rom = wonderswan();
    truncation_sweep(&rom, FileFormat::WonderSwanRom, rom.len(), 65_521);
    let end = rom.len();
    mutation_sweep(&rom, end - 11..end, usize::MAX);
}

// --- Neo Geo Pocket ----------------------------------------------------------------

/// A 32 KiB Neo Geo Pocket Color ROM: `recognition` (28 bytes), startup
/// address 0x200040 (little-endian) at 0x1C, ID code 0x0042 (little-endian
/// BCD) at 0x20, version 1, system 0x10 (color), title `ZRAXNGP` (12) at
/// 0x24, 16 reserved zero bytes, then TLCS-900 code.
fn ngp(recognition: &[u8; 28]) -> Vec<u8> {
    let mut rom = vec![0u8; 0x8000];
    fill_with(&mut rom[0x40..], &TLCS900_CODE);
    rom[..28].copy_from_slice(recognition);
    put_le32(&mut rom, 0x1c, 0x0020_0040);
    put_le16(&mut rom, 0x20, 0x0042);
    rom[0x22] = 1;
    rom[0x23] = 0x10;
    put_text(&mut rom, 0x24, 12, "ZRAXNGP", b' ');
    rom
}

#[test]
fn ngp_rom_names_the_tlcs900h_and_starts_at_its_startup_address() {
    let p = classify(&ngp(b"COPYRIGHT BY SNK CORPORATION"));
    assert_eq!(p.format.format, FileFormat::NgpRom);
    assert_eq!(p.primary.isa, Isa::Tlcs900);
    assert_eq!(variant(&p), Some("TLCS-900/H"));
    assert_eq!(entry_point(&p), Some(0x20_0040));
    assert!(has_note(&p, "ZRAXNGP (SNK); color; ID code 0042"));
    assert_eq!(
        custom(&p, "ngp_section_0").as_deref(),
        Some("file 0x0; destination 0x200000; 32768 B")
    );
    let third_party = classify(&ngp(b" LICENSED BY SNK CORPORATION"));
    assert!(has_note(&third_party, "(third party)"));
}

#[test]
fn ngp_startup_address_must_lie_in_the_cartridge() {
    let mut rom = ngp(b"COPYRIGHT BY SNK CORPORATION");
    put_le32(&mut rom, 0x1c, 0x0020_8000);
    assert!(error_text(&rom).contains("Invalid startup address 0x208000"));
}

#[test]
fn ngp_truncations_and_mutations_are_bounded() {
    let rom = ngp(b"COPYRIGHT BY SNK CORPORATION");
    truncation_sweep(&rom, FileFormat::NgpRom, 0x41, 251);
    mutation_sweep(&rom, 0..0x40, 4093);
}

// --- Contract -------------------------------------------------------------------

#[test]
fn json_ids_are_the_lowercase_variant_names() {
    for (format, id) in [
        (FileFormat::SmsRom, "smsrom"),
        (FileFormat::Sega32xRom, "sega32xrom"),
        (FileFormat::SaturnIp, "saturnip"),
        (FileFormat::SegaCdIp, "segacdip"),
        (FileFormat::MsxRom, "msxrom"),
        (FileFormat::LynxRom, "lynxrom"),
        (FileFormat::Atari7800Rom, "atari7800rom"),
        (FileFormat::C64Crt, "c64crt"),
        (FileFormat::AtariStPrg, "ataristprg"),
        (FileFormat::ZxSnapshot, "zxsnapshot"),
        (FileFormat::WonderSwanRom, "wonderswanrom"),
        (FileFormat::NgpRom, "ngprom"),
    ] {
        assert_eq!(serde_json::to_string(&format).unwrap(), format!("\"{id}\""));
    }
}
