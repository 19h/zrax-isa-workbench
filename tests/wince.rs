//! Windows CE ROM images: `B000FF` BIN records (checksums, ranges,
//! overlaps, terminator), the ROMHDR found through `ECEC` (with and without
//! a ROM offset), `usCPUType` as the target, module code sections and
//! FILES entries as components, raw `.nb0` images recognized from their
//! ROM structure, and truncation and mutation sweeps.

use std::ops::Range;
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa, MetadataKey,
    MetadataValue,
};

/// clang-generated A32 code, committed for the SoC boot image tests.
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/socboot2/arm.text.bin"
);

/// Compiled little-endian MIPS32 code from the repository's testbins.
const MIPS_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips32_le_mipsel-unknown-linux-gnu_O0_call_nested.bin"
);

/// `IMAGE_FILE_MACHINE_ARM`.
const MACHINE_ARM: u16 = 0x01C0;
/// `IMAGE_FILE_MACHINE_R4000`, little-endian MIPS.
const MACHINE_R4000: u16 = 0x0166;
/// `ROM_SIGNATURE`.
const ROM_SIGNATURE: u32 = 0x4345_4345;
/// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`.
const CODE_FLAGS: u32 = 0x6000_0020;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE`.
const DATA_FLAGS: u32 = 0xC000_0040;
/// `IMAGE_SCN_COMPRESSED`.
const COMPRESSED: u32 = 0x0000_2000;
/// `IMAGE_FILE_DLL`.
const IMAGE_FILE_DLL: u16 = 0x2000;

// Layout of the synthetic ROM, as offsets from `physfirst`.

/// `ECEC` and the ROMHDR pointer (`ROM_SIGNATURE_OFFSET`).
const SIGNATURE_AT: usize = 0x40;
const ROMHDR_AT: usize = 0x100;
const ROMHDR_SIZE: usize = 84;
const TOC_AT: usize = ROMHDR_AT + ROMHDR_SIZE;
const TOC_ENTRY_SIZE: usize = 32;
const FILES_AT: usize = TOC_AT + 2 * TOC_ENTRY_SIZE;
const FILES_ENTRY_SIZE: usize = 28;
const NAMES_AT: usize = 0x200;
const NK_E32_AT: usize = 0x280;
const NK_O32_AT: usize = 0x300;
const COREDLL_E32_AT: usize = 0x340;
const COREDLL_O32_AT: usize = 0x3C0;
const NK_CODE_AT: usize = 0x400;
const NK_CODE_SIZE: usize = 0x300;
const NK_DATA_AT: usize = 0x700;
const NK_DATA_SIZE: usize = 0x40;
const COREDLL_CODE_AT: usize = 0x780;
const COREDLL_CODE_SIZE: usize = 0x40;
const ELF_AT: usize = 0x800;
const README_AT: usize = 0x880;
const PACKED_AT: usize = 0x8C0;
const PACKED_SIZE: usize = 0x20;
const IMAGE_SIZE: usize = 0x900;

/// Default runtime start of the image.
const PHYS_FIRST: u32 = 0x8000_0000;
/// Label of nk.exe's code section component.
const NK_CODE_LABEL: &str = "nk.exe o32 0 (RVA 0x1000)";
const COREDLL_CODE_LABEL: &str = "coredll.dll o32 0 (RVA 0x1000)";

fn arm_code() -> Vec<u8> {
    std::fs::read(ARM_CODE).expect("fixture is committed")
}

fn mips_code() -> Vec<u8> {
    std::fs::read(MIPS_CODE).expect("testbin is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

/// How many load sections the metadata lists.
fn section_count(p: &DetectionPayload) -> usize {
    p.metadata
        .iter()
        .filter(|m| matches!(&m.key, MetadataKey::Custom(k) if k.starts_with("wince_section_")))
        .count()
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

fn put_u16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

/// ROMHDR (84 B, `romldr.h`): `dllfirst`, `dlllast`, `physfirst`,
/// `physlast`, `nummods`, `ulRAMStart`, `ulRAMFree`, `ulRAMEnd`,
/// `ulCopyEntries`, `ulCopyOffset`, `ulProfileLen`, `ulProfileOffset`,
/// `numfiles`, `ulKernelFlags`, `ulFSRamPercent`, `ulDrivglobStart`,
/// `ulDrivglobLen`, `usCPUType`, `usMiscFlags`, `pExtensions`,
/// `ulTrackingStart`, `ulTrackingLen`.
fn romhdr(phys_first: u32, phys_last: u32, modules: u32, files: u32, cpu_type: u16) -> Vec<u8> {
    let mut h = vec![0u8; ROMHDR_SIZE];
    put_u32(&mut h, 0x00, 0x0200_0000);
    put_u32(&mut h, 0x04, 0x0400_0000);
    put_u32(&mut h, 0x08, phys_first);
    put_u32(&mut h, 0x0C, phys_last);
    put_u32(&mut h, 0x10, modules);
    put_u32(&mut h, 0x14, 0x8C00_0000);
    put_u32(&mut h, 0x18, 0x8C10_0000);
    put_u32(&mut h, 0x1C, 0x8E00_0000);
    put_u32(&mut h, 0x30, files);
    put_u32(&mut h, 0x34, 0x0000_0002);
    put_u16(&mut h, 0x44, cpu_type);
    h
}

/// `TOCentry` (32 B): `dwFileAttributes`, `ftTime` (8 B), `nFileSize`,
/// `lpszFileName`, `ulE32Offset`, `ulO32Offset`, `ulLoadOffset`.
fn toc_entry(name: u32, e32: u32, o32: u32, file_size: u32) -> Vec<u8> {
    let mut e = vec![0u8; TOC_ENTRY_SIZE];
    put_u32(&mut e, 0, 0x07);
    put_u32(&mut e, 12, file_size);
    put_u32(&mut e, 16, name);
    put_u32(&mut e, 20, e32);
    put_u32(&mut e, 24, o32);
    e
}

/// `FILESentry` (28 B): `dwFileAttributes`, `ftTime` (8 B),
/// `nRealFileSize`, `nCompFileSize`, `lpszFileName`, `ulLoadOffset`.
fn files_entry(name: u32, real_size: u32, stored_size: u32, load: u32) -> Vec<u8> {
    let mut e = vec![0u8; FILES_ENTRY_SIZE];
    put_u32(&mut e, 0, 0x01);
    put_u32(&mut e, 12, real_size);
    put_u32(&mut e, 16, stored_size);
    put_u32(&mut e, 20, name);
    put_u32(&mut e, 24, load);
    e
}

/// `e32_rom` as Windows Embedded Compact 7 lays it out (0x70 B):
/// `e32_objcnt`, `e32_imageflags`, `e32_entryrva`, `e32_vbase`,
/// `e32_subsysmajor`, `e32_subsysminor`, `e32_stackmax`, `e32_vsize`,
/// `e32_sect14rva`, `e32_sect14size`, `e32_timestamp`, `e32_unit[9]`,
/// `e32_subsys`.
fn e32_rom(objects: u16, image_flags: u16, entry_rva: u32, base: u32, size: u32) -> Vec<u8> {
    let mut e = vec![0u8; 0x70];
    put_u16(&mut e, 0, objects);
    put_u16(&mut e, 2, image_flags);
    put_u32(&mut e, 4, entry_rva);
    put_u32(&mut e, 8, base);
    put_u16(&mut e, 12, 6);
    put_u32(&mut e, 16, 0x1_0000);
    put_u32(&mut e, 20, size);
    put_u16(&mut e, 0x6C, 9);
    e
}

/// `o32_rom` (24 B): `o32_vsize`, `o32_rva`, `o32_psize`, `o32_dataptr`,
/// `o32_realaddr`, `o32_flags`.
fn o32_rom(size: u32, rva: u32, stored: u32, data: u32, flags: u32) -> Vec<u8> {
    let mut e = vec![0u8; 24];
    put_u32(&mut e, 0, size);
    put_u32(&mut e, 4, rva);
    put_u32(&mut e, 8, stored);
    put_u32(&mut e, 12, data);
    put_u32(&mut e, 16, data);
    put_u32(&mut e, 20, flags);
    e
}

/// A synthetic XIP region: the image from `physfirst`, and the ranges a
/// BIN file stores as records, in file order.
struct Rom {
    phys_first: u32,
    image: Vec<u8>,
    records: Vec<Range<usize>>,
}

/// An XIP region with two modules and three files:
/// - `nk.exe`: an EXE with a code section (`NK_CODE_SIZE` bytes of `code`)
///   and a data section;
/// - `coredll.dll`: a DLL whose one code section is compressed;
/// - `boot.elf` (an ELF header), `readme.txt` (text) and `packed.dat`
///   (stored compressed).
///
/// Pointers are runtime addresses, `phys_first` plus the layout offset.
fn rom(phys_first: u32, cpu_type: u16, code: &[u8]) -> Rom {
    let at = |offset: usize| phys_first + offset as u32;
    let mut image = vec![0u8; IMAGE_SIZE];
    let mut place = |offset: usize, bytes: &[u8]| {
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    // A32 `B` to the nk.exe code, then the signature and the pointer.
    place(
        0,
        &(0xEA00_0000u32 | ((NK_CODE_AT as u32 - 8) >> 2)).to_le_bytes(),
    );
    place(SIGNATURE_AT, &ROM_SIGNATURE.to_le_bytes());
    place(SIGNATURE_AT + 4, &at(ROMHDR_AT).to_le_bytes());
    place(
        ROMHDR_AT,
        &romhdr(phys_first, at(IMAGE_SIZE), 2, 3, cpu_type),
    );
    let names = [
        "nk.exe",
        "coredll.dll",
        "boot.elf",
        "readme.txt",
        "packed.dat",
    ];
    let mut name_at = Vec::new();
    let mut offset = NAMES_AT;
    for name in names {
        name_at.push(at(offset));
        place(offset, name.as_bytes());
        offset += name.len() + 1;
    }
    place(
        TOC_AT,
        &toc_entry(name_at[0], at(NK_E32_AT), at(NK_O32_AT), 0x2000),
    );
    place(
        TOC_AT + TOC_ENTRY_SIZE,
        &toc_entry(name_at[1], at(COREDLL_E32_AT), at(COREDLL_O32_AT), 0x1800),
    );
    let readme = b"Synthetic ROM image for tests.\n\0";
    let files = [
        files_entry(name_at[2], 64, 64, at(ELF_AT)),
        files_entry(
            name_at[3],
            readme.len() as u32,
            readme.len() as u32,
            at(README_AT),
        ),
        files_entry(name_at[4], 0x100, PACKED_SIZE as u32, at(PACKED_AT)),
    ];
    for (i, entry) in files.iter().enumerate() {
        place(FILES_AT + i * FILES_ENTRY_SIZE, entry);
    }
    place(NK_E32_AT, &e32_rom(2, 0x0102, 0x1000, 0x0001_0000, 0x3000));
    place(
        NK_O32_AT,
        &o32_rom(0x300, 0x1000, 0x400, at(NK_CODE_AT), CODE_FLAGS),
    );
    place(
        NK_O32_AT + 24,
        &o32_rom(
            0x80,
            0x2000,
            NK_DATA_SIZE as u32,
            at(NK_DATA_AT),
            DATA_FLAGS,
        ),
    );
    place(
        COREDLL_E32_AT,
        &e32_rom(1, IMAGE_FILE_DLL | 0x0102, 0x1100, 0x0100_0000, 0x2000),
    );
    place(
        COREDLL_O32_AT,
        &o32_rom(
            0x200,
            0x1000,
            COREDLL_CODE_SIZE as u32,
            at(COREDLL_CODE_AT),
            CODE_FLAGS | COMPRESSED,
        ),
    );
    place(NK_CODE_AT, &code[..NK_CODE_SIZE]);
    place(NK_DATA_AT, &[0x5a; NK_DATA_SIZE]);
    place(COREDLL_CODE_AT, &[0xc3; COREDLL_CODE_SIZE]);
    place(ELF_AT, &elf_x86_64());
    place(README_AT, readme);
    place(PACKED_AT, &[0x99; PACKED_SIZE]);
    // romimage writes the signature record before the ROMHDR record
    // (BLCOMMON), so both come last; the rest leaves address gaps.
    let records = vec![
        0..SIGNATURE_AT,
        TOC_AT..FILES_AT + 3 * FILES_ENTRY_SIZE,
        NAMES_AT..offset,
        NK_E32_AT..COREDLL_O32_AT + 24,
        NK_CODE_AT..NK_DATA_AT + NK_DATA_SIZE,
        COREDLL_CODE_AT..COREDLL_CODE_AT + COREDLL_CODE_SIZE,
        ELF_AT..IMAGE_SIZE,
        SIGNATURE_AT..SIGNATURE_AT + 8,
        ROMHDR_AT..ROMHDR_AT + ROMHDR_SIZE,
    ];
    Rom {
        phys_first,
        image,
        records,
    }
}

/// The default ARM ROM.
fn arm_rom() -> Rom {
    rom(PHYS_FIRST, MACHINE_ARM, &arm_code())
}

/// Record checksum: the unsigned byte sum in a wrapping 32-bit register
/// (BLCOMMON `VerifyChecksum`).
fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
}

/// A BIN record: address, length, checksum, data.
fn record(address: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&address.to_le_bytes());
    r.extend_from_slice(&(data.len() as u32).to_le_bytes());
    r.extend_from_slice(&checksum(data).to_le_bytes());
    r.extend_from_slice(data);
    r
}

/// The terminating record: address 0, the entry point, checksum 0.
fn terminator(entry: u32) -> Vec<u8> {
    let mut r = vec![0u8; 12];
    put_u32(&mut r, 4, entry);
    r
}

/// BIN header (Microsoft Learn `ee478913`): `B000FF\n`, image address,
/// image length.
fn bin_header(start: u32, length: u32) -> Vec<u8> {
    let mut h = b"B000FF\n".to_vec();
    h.extend_from_slice(&start.to_le_bytes());
    h.extend_from_slice(&length.to_le_bytes());
    h
}

/// `rom` as a BIN file whose records are stored at `storage_start` plus
/// the layout offset, with the entry point at the nk.exe code.
fn bin(rom: &Rom, storage_start: u32) -> Vec<u8> {
    let mut file = bin_header(storage_start, IMAGE_SIZE as u32);
    for range in &rom.records {
        file.extend(record(
            storage_start + range.start as u32,
            &rom.image[range.clone()],
        ));
    }
    file.extend(terminator(rom.phys_first + NK_CODE_AT as u32));
    file
}

/// File offset of the record data that holds image offset `at`.
fn bin_offset(rom: &Rom, at: usize) -> u64 {
    let mut pos = 15;
    for range in &rom.records {
        if range.contains(&at) {
            return (pos + 12 + at - range.start) as u64;
        }
        pos += 12 + range.len();
    }
    panic!("image offset 0x{at:X} is not stored");
}

fn assert_arm_rom(p: &DetectionPayload, rom: &Rom, code_offset: u64) {
    assert_eq!(p.format.format, FileFormat::WinCeImage);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::Little);
    let code = slice(p, NK_CODE_LABEL);
    assert_eq!(
        (code.isa, code.offset, code.size),
        (Isa::Arm, code_offset, 0x300)
    );
    let coredll = slice(p, COREDLL_CODE_LABEL);
    assert!(matches!(coredll.isa, Isa::Unknown(_)), "{coredll:?}");
    assert_eq!(slice(p, "boot.elf").isa, Isa::X86_64);
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("readme.txt")));
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("packed.dat")));
    assert!(
        has_note(p, "usCPUType 0x01C0 (ARM little endian)"),
        "{:?}",
        p.notes
    );
    assert!(has_note(p, "Modules: nk.exe, coredll.dll"));
    assert!(has_note(
        p,
        "1 code section is stored compressed (IMAGE_SCN_COMPRESSED)"
    ));
    assert!(has_note(
        p,
        "1 of 3 files are in a recognized format and listed"
    ));
    assert!(has_note(p, "1 file is stored compressed"));
    assert_eq!(
        metadata(p, "wince_module_0").as_deref(),
        Some(
            "EXE; entry RVA 0x1000; base 0x00010000; virtual size 12288 B; 2 sections (1 code, 0 compressed); image flags 0x0102; file size 8192 B"
        )
    );
    assert!(metadata(p, "wince_module_1").is_some_and(|m| m.starts_with("DLL;")));
    assert_eq!(
        metadata(p, "wince_file_2"),
        Some(format!(
            "256 B; stored compressed in 32 B at 0x{:08X}",
            rom.phys_first + PACKED_AT as u32
        ))
    );
    assert_eq!(metadata(p, "wince_cpu_type").as_deref(), Some("0x000001C0"));
}

#[test]
fn bin_rom_names_its_cpu_and_lists_module_code_and_files() {
    let rom = arm_rom();
    let file = bin(&rom, PHYS_FIRST);
    let p = classify(&file);
    assert_arm_rom(&p, &rom, bin_offset(&rom, NK_CODE_AT));
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Windows CE BIN image")
    );
    assert!(has_note(
        &p,
        "9 records in 9 load sections; image 0x80000000 + 2304 B; record checksums verified"
    ));
    assert!(has_note(
        &p,
        "Entry point 0x80000400 from the terminating record"
    ));
    assert!(has_note(&p, "ROMHDR at 0x80000100"));
    assert_eq!(metadata(&p, "wince_records").as_deref(), Some("9"));
    assert_eq!(entry_point(&p), Some(0x8000_0400));
    assert_eq!(section_count(&p), 9);
}

#[test]
fn bin_records_are_loaded_at_their_addresses_without_filling_gaps() {
    let rom = arm_rom();
    let mut file = bin_header(PHYS_FIRST, IMAGE_SIZE as u32);
    // nk.exe's code split into two records that follow each other: one
    // load section reassembled from both.
    let split = NK_CODE_AT + 0x100;
    let mut records = rom.records.clone();
    let code = records
        .iter()
        .position(|r| r.start == NK_CODE_AT)
        .expect("code record");
    records.splice(
        code..=code,
        [NK_CODE_AT..split, split..NK_DATA_AT + NK_DATA_SIZE],
    );
    for range in &records {
        file.extend(record(
            PHYS_FIRST + range.start as u32,
            &rom.image[range.clone()],
        ));
    }
    file.extend(terminator(PHYS_FIRST));
    let p = classify(&file);
    assert!(
        has_note(&p, "10 records in 9 load sections"),
        "{:?}",
        p.notes
    );
    let section = metadata(&p, "wince_section_4").expect("section 5");
    assert!(
        section.ends_with("destination 0x80000400; 844 B stored; 832 B decoded (BIN records)"),
        "{section}"
    );
    // Address gaps are not filled: the sections hold only the record data.
    assert_eq!(section_count(&p), 9);
    let stored: usize = records.iter().map(Range::len).sum();
    assert!(stored < IMAGE_SIZE, "the layout leaves gaps");
    // The module code is not in one record now and is not listed.
    assert!(has_note(
        &p,
        "1 code section is not stored in one record and not listed"
    ));
}

#[test]
fn raw_rom_image_is_recognized_from_its_rom_structure() {
    let rom = arm_rom();
    let mut file = rom.image.clone();
    file.resize(IMAGE_SIZE + 0x700, 0xff);
    let p = classify(&file);
    assert_arm_rom(&p, &rom, NK_CODE_AT as u64);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Windows CE raw ROM image")
    );
    assert!(has_note(
        &p,
        "Raw ROM image of 2304 B loaded at 0x80000000 (physfirst)"
    ));
    assert!(has_note(&p, "1792 B of padding after the image"));
    assert_eq!(entry_point(&p), None);
    assert_eq!(
        metadata(&p, "wince_section_0").as_deref(),
        Some("file 0x0; destination 0x80000000; 2304 B")
    );
}

#[test]
fn rom_offset_maps_runtime_pointers_to_record_addresses() {
    // Records are stored at 0x00200000 while the ROM runs at 0x80200000:
    // BLCOMMON derives the offset from the 84-byte ROMHDR record.
    let rom = rom(0x8020_0000, MACHINE_ARM, &arm_code());
    let file = bin(&rom, 0x0020_0000);
    let p = classify(&file);
    assert_arm_rom(&p, &rom, bin_offset(&rom, NK_CODE_AT));
    assert!(
        has_note(&p, "ROM offset of -0x80000000 (BLCOMMON g_dwROMOffset)"),
        "{:?}",
        p.notes
    );
    assert_eq!(
        metadata(&p, "wince_rom_offset").as_deref(),
        Some("-0x80000000")
    );
    assert!(has_note(&p, "ROMHDR at 0x200100"));
}

/// `IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE`.
const BSS_FLAGS: u32 = 0xC000_0080;

#[test]
fn empty_sections_and_files_need_no_stored_data() {
    // An uninitialized section and an empty file with null pointers: under
    // a negative ROM offset a null pointer has no storage address at all.
    let mut rom = rom(0x8020_0000, MACHINE_ARM, &arm_code());
    let bss = o32_rom(0x80, 0x2000, 0, 0, BSS_FLAGS);
    rom.image[NK_O32_AT + 24..NK_O32_AT + 48].copy_from_slice(&bss);
    let readme = FILES_AT + FILES_ENTRY_SIZE;
    put_u32(&mut rom.image, readme + 12, 0);
    put_u32(&mut rom.image, readme + 16, 0);
    put_u32(&mut rom.image, readme + 24, 0);
    let p = classify(&bin(&rom, 0x0020_0000));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(!has_note(&p, "invalid"), "{:?}", p.notes);
    assert_eq!(
        metadata(&p, "wince_file_1").as_deref(),
        Some("0 B stored at 0x00000000")
    );
    assert_eq!(slice(&p, NK_CODE_LABEL).isa, Isa::Arm);
}

#[test]
fn mips_rom_maps_r4000_to_little_endian_mips() {
    let code = mips_code();
    let rom = rom(PHYS_FIRST, MACHINE_R4000, &code);
    let p = classify(&bin(&rom, PHYS_FIRST));
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Little)
    );
    assert_eq!(slice(&p, NK_CODE_LABEL).isa, Isa::Mips);
    assert!(has_note(&p, "usCPUType 0x0166 (MIPS R4000)"));
}

#[test]
fn unknown_cpu_type_leaves_the_isa_to_the_code() {
    for cpu in [0x0000, 0x1234] {
        let rom = rom(PHYS_FIRST, cpu, &arm_code());
        let p = classify(&bin(&rom, PHYS_FIRST));
        assert!(
            has_note(&p, &format!("usCPUType 0x{cpu:04X} names no architecture")),
            "{:?}",
            p.notes
        );
        assert_eq!(p.primary.isa, Isa::Arm, "code model on the module code");
        assert!(has_note(
            &p,
            &format!("Primary ISA selected from {NK_CODE_LABEL}")
        ));
    }
}

#[test]
fn bin_without_rom_signature_goes_to_the_code_model() {
    let code = arm_code();
    let mut file = bin_header(0x0010_0000, 0x2000);
    file.extend(record(0x0010_0000, &code[..0x800]));
    file.extend(record(0x0010_1000, &code[0x800..0x1000]));
    file.extend(terminator(0x0010_0000));
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::WinCeImage);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(&p, "No ROM signature (ECEC) at image offset 0x40"));
    assert!(has_note(&p, "2 records in 2 load sections"));
    assert!(p.slices.is_empty());
}

#[test]
fn rom_header_must_span_the_bin_image() {
    let mut rom = arm_rom();
    put_u32(&mut rom.image, ROMHDR_AT + 0x0C, PHYS_FIRST + 0x1000);
    let p = classify(&bin(&rom, PHYS_FIRST));
    assert!(
        has_note(&p, "no ROMHDR for the pointer 0x80000100 has physfirst and physlast at the image start and end"),
        "{:?}",
        p.notes
    );
    assert!(p.slices.is_empty());
    assert_eq!(metadata(&p, "wince_cpu_type"), None);
}

#[test]
fn invalid_toc_keeps_the_bin_and_its_target() {
    let mut rom = arm_rom();
    put_u32(&mut rom.image, TOC_AT + 16, 0x9000_0000);
    let p = classify(&bin(&rom, PHYS_FIRST));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(
        has_note(&p, "The ROM table of contents is invalid (Invalid TOC entry 0: the module name at 0x90000000 is not a stored, NUL-terminated ASCII name)"),
        "{:?}",
        p.notes
    );
    assert!(p.slices.is_empty());
}

#[test]
fn bin_record_errors_name_the_record() {
    let rom = arm_rom();
    let file = bin(&rom, PHYS_FIRST);
    let first_data = 15 + 12;

    let mut bad_checksum = file.clone();
    bad_checksum[first_data] ^= 1;
    assert!(
        error_text(&bad_checksum).contains("Invalid BIN record checksum at 0xF: stored 0x"),
        "{}",
        error_text(&bad_checksum)
    );

    let mut outside = file.clone();
    put_u32(&mut outside, 15, PHYS_FIRST - 4);
    assert!(error_text(&outside).contains(
        "Invalid BIN record at 0xF: 0x7FFFFFFC + 64 B is outside the image 0x80000000 + 2304 B"
    ));

    let mut overlap = bin_header(PHYS_FIRST, 0x100);
    overlap.extend(record(PHYS_FIRST, &[1; 0x20]));
    overlap.extend(record(PHYS_FIRST + 0x10, &[2; 0x20]));
    overlap.extend(terminator(PHYS_FIRST));
    assert!(error_text(&overlap)
        .contains("Overlapping BIN records at 0xF and 0x3B for address 0x80000010"));

    let unterminated = &file[..file.len() - 12];
    assert!(error_text(unterminated).contains("Missing BIN terminator record"));

    let mut terminator_checksum = file.clone();
    let end = terminator_checksum.len();
    put_u32(&mut terminator_checksum, end - 4, 1);
    assert!(error_text(&terminator_checksum).contains("Invalid BIN terminator record"));

    let mut trailing = file.clone();
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("Unexpected data after the BIN terminator record"));

    let mut padded = file.clone();
    padded.extend_from_slice(&[0xff; 64]);
    assert!(has_note(
        &classify(&padded),
        "64 B of padding after the terminator"
    ));

    let empty = bin_header(PHYS_FIRST, 0);
    assert!(error_text(&empty).contains("Invalid BIN header: the image length is 0"));
}

/// A named way to damage a fixture.
type Corruption = (&'static str, fn(&mut Vec<u8>));

#[test]
fn raw_rom_weak_detection_requires_the_whole_structure() {
    let rom = arm_rom();
    let is_wince = |data: &[u8]| {
        detect_payload(data, &ClassifierOptions::new())
            .is_ok_and(|p| p.format.format == FileFormat::WinCeImage)
    };
    assert!(is_wince(&rom.image));
    let corruptions: [Corruption; 6] = [
        ("signature", |d| d[SIGNATURE_AT] = b'X'),
        ("pointer", |d| {
            put_u32(d, SIGNATURE_AT + 4, PHYS_FIRST + ROMHDR_AT as u32 + 4)
        }),
        ("physlast past the file", |d| {
            put_u32(d, ROMHDR_AT + 0x0C, PHYS_FIRST + 0x10_0000)
        }),
        ("module name", |d| d[NAMES_AT] = 0x01),
        ("o32 data pointer", |d| {
            put_u32(d, NK_O32_AT + 12, PHYS_FIRST + 0x10_0000)
        }),
        ("data after the image", |d| d.extend_from_slice(b"tail")),
    ];
    for (what, corrupt) in corruptions {
        let mut image = rom.image.clone();
        corrupt(&mut image);
        assert!(!is_wince(&image), "{what}");
    }
    // A ROM without modules proves too little to be recognized.
    let mut empty = rom.image.clone();
    put_u32(&mut empty, ROMHDR_AT + 0x10, 0);
    put_u32(&mut empty, ROMHDR_AT + 0x30, 0);
    assert!(!is_wince(&empty));
}

#[test]
fn truncated_images_never_claim_their_rom() {
    let rom = arm_rom();
    let file = bin(&rom, PHYS_FIRST);
    for end in 0..file.len() {
        let result = detect_payload(&file[..end], &ClassifierOptions::new());
        if end >= 7 {
            assert!(result.is_err(), "BIN prefix {end}");
        } else if let Ok(p) = result {
            assert_ne!(p.format.format, FileFormat::WinCeImage, "BIN prefix {end}");
        }
    }
    for end in 0..rom.image.len() {
        let Ok(p) = detect_payload(&rom.image[..end], &ClassifierOptions::new()) else {
            continue;
        };
        assert_ne!(p.format.format, FileFormat::WinCeImage, "raw prefix {end}");
    }
}

#[test]
fn rom_images_survive_byte_mutations_without_panicking() {
    let rom = arm_rom();
    let images = [bin(&rom, PHYS_FIRST), rom.image.clone()];
    // The ROM structures (the first 0x400 image bytes, the first 0x500 BIN
    // bytes) get all three mutations; code and file bytes get one each.
    for (structure, image) in [(0x500, &images[0]), (0x400, &images[1])] {
        for i in 0..image.len() {
            let values = [0x00, 0xff, image[i] ^ 0x01];
            let mutations = if i < structure {
                &values[..]
            } else {
                &values[i % 3..=i % 3]
            };
            for &value in mutations {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
