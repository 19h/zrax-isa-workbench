//! ELF header fields that bound the classification: `EI_CLASS` sets the
//! PA-RISC bit width; `EI_DATA` must agree with a code-model answer for a
//! machine number the classifier cannot map; `EM_MN10300` names the
//! MN10300 and machine 0x1040 the UniPhier IPP; a header whose loaded code
//! reads decisively as another ISA
//! family names no ISA; ELF images stored after an image's file extent are
//! listed as components.

use zrax::{detect_payload, ClassifierOptions, Endianness, FileFormat, Isa};

/// Compiled AArch64 code (little-endian), from the repository's testbins.
const AARCH64_CODE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/aarch64_aarch64-unknown-linux-gnu_O0_int_crc32.bin"
));

/// `e_machine` value no ELF table assigns.
const EM_UNASSIGNED: u16 = 0x7777;
/// Panasonic UniPhier IPP: unregistered, the value its toolchain writes
/// (big-endian FreeBSD executables in the fw1 audit and the IPP samples).
const EM_IPP: u16 = 0x1040;
/// HP PA-RISC.
const EM_PARISC: u16 = 15;
/// Matsushita MN10300 (binutils `include/elf/common.h`).
const EM_MN10300: u16 = 89;
const EM_386: u16 = 3;
/// `PT_LOAD` and its permission bits (System V ABI, Program Header).
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const ET_EXEC: u16 = 2;

/// An ELF header with no program or section headers, followed by `body`.
///
/// `e_ident`: magic, class, data, version 1; then `e_type`, `e_machine` and
/// `e_version` in the declared byte order. The remaining fields are zero:
/// a 52-byte (ELF32) or 64-byte (ELF64) header.
fn elf(class: u8, data: u8, machine: u16, body: &[u8]) -> Vec<u8> {
    let header_size = if class == ELFCLASS64 { 64 } else { 52 };
    let mut v = vec![0u8; header_size];
    v[..4].copy_from_slice(b"\x7fELF");
    v[4] = class;
    v[5] = data;
    v[6] = 1;
    let put16 = |v: &mut Vec<u8>, at: usize, x: u16| {
        let b = if data == ELFDATA2LSB {
            x.to_le_bytes()
        } else {
            x.to_be_bytes()
        };
        v[at..at + 2].copy_from_slice(&b);
    };
    put16(&mut v, 0x10, ET_EXEC);
    put16(&mut v, 0x12, machine);
    v[0x14..0x18].copy_from_slice(&if data == ELFDATA2LSB {
        1u32.to_le_bytes()
    } else {
        1u32.to_be_bytes()
    });
    v.extend_from_slice(body);
    v
}

#[test]
fn unknown_machine_takes_code_model_answer_in_declared_byte_order() {
    let v = elf(ELFCLASS64, ELFDATA2LSB, EM_UNASSIGNED, AARCH64_CODE);
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::AArch64);
}

#[test]
fn unknown_machine_rejects_code_model_answer_against_ei_data() {
    // Little-endian AArch64 code behind a header that declares big-endian
    // contents: the answer contradicts the file.
    let v = elf(ELFCLASS64, ELFDATA2MSB, EM_UNASSIGNED, AARCH64_CODE);
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert!(p.notes.iter().any(|n| n
        .message
        .contains("contradicts the header's big byte order")));
}

/// A little-endian ELF image with one `PT_LOAD` program header holding
/// `body`. ELF32: `e_phoff` 0x1C = 52, `e_phentsize` 32, `e_phnum` 1;
/// ELF64: `e_phoff` 0x20 = 64, `e_phentsize` 56, `e_phnum` 1. The segment
/// starts right after the program header table; `p_flags` is `flags`.
fn elf_with_segment(class: u8, machine: u16, flags: u32, body: &[u8]) -> Vec<u8> {
    let is_64 = class == ELFCLASS64;
    let (phoff, phentsize) = if is_64 { (64usize, 56usize) } else { (52, 32) };
    let offset = phoff + phentsize;
    let mut v = elf(class, ELFDATA2LSB, machine, &[]);
    v.resize(offset, 0);
    let size = body.len() as u64;
    if is_64 {
        v[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        v[0x36..0x38].copy_from_slice(&(phentsize as u16).to_le_bytes());
        v[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let h = phoff;
        v[h..h + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        v[h + 4..h + 8].copy_from_slice(&flags.to_le_bytes());
        v[h + 8..h + 16].copy_from_slice(&(offset as u64).to_le_bytes());
        v[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
        v[h + 40..h + 48].copy_from_slice(&size.to_le_bytes());
    } else {
        v[0x1c..0x20].copy_from_slice(&(phoff as u32).to_le_bytes());
        v[0x2a..0x2c].copy_from_slice(&(phentsize as u16).to_le_bytes());
        v[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes());
        let h = phoff;
        v[h..h + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        v[h + 4..h + 8].copy_from_slice(&(offset as u32).to_le_bytes());
        v[h + 16..h + 20].copy_from_slice(&(size as u32).to_le_bytes());
        v[h + 20..h + 24].copy_from_slice(&(size as u32).to_le_bytes());
        v[h + 24..h + 28].copy_from_slice(&flags.to_le_bytes());
    }
    v.extend_from_slice(body);
    v
}

/// AArch64 code (`tests/fixtures/transforms`), repeated to several windows.
fn aarch64_code() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transforms/aarch64.text.bin"
    ))
    .expect("fixture is in the repository")
    .repeat(3)
}

#[test]
fn header_contradicted_by_its_loaded_code_names_no_isa() {
    // EM_386 around AArch64 code in a segment marked read-write only, as
    // Qualcomm Cortex-M firmware ships inside `EM_386` images.
    let v = elf_with_segment(ELFCLASS32, EM_386, PF_R | PF_W, &aarch64_code());
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::Unknown(u32::from(EM_386)));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("e_machine names x86")));
}

#[test]
fn header_matched_by_its_code_keeps_its_isa() {
    let v = elf_with_segment(ELFCLASS64, EM_AARCH64, PF_R | PF_X, &aarch64_code());
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(!p
        .notes
        .iter()
        .any(|n| n.message.contains("e_machine names")));
}

#[test]
fn mn10300_machine_names_the_mn10300() {
    let v = elf(ELFCLASS32, ELFDATA2LSB, EM_MN10300, &[]);
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::Mn10300);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(serde_json::to_value(Isa::Mn10300).unwrap(), "mn10300");
}

#[test]
fn ipp_machine_names_the_uniphier_ipp() {
    let v = elf(ELFCLASS32, ELFDATA2MSB, EM_IPP, &[]);
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::Ipp);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(serde_json::to_value(Isa::Ipp).unwrap(), "ipp");
}

#[test]
fn parisc_bit_width_follows_elf_class() {
    for (class, bits) in [(ELFCLASS32, 32), (ELFCLASS64, 64)] {
        let v = elf(class, ELFDATA2MSB, EM_PARISC, &[]);
        let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
        assert_eq!(p.primary.isa, Isa::Parisc);
        assert_eq!(p.primary.bitwidth, bits);
    }
}

/// AArch64 and RISC-V.
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;

#[test]
fn elf_images_appended_after_the_file_extent_are_components() {
    // A header-only ELF (extent 64 B), then an AArch64 image, 16 B of erased
    // flash, then a RISC-V image: a Qualcomm firehose bundle in miniature.
    let mut v = elf(ELFCLASS64, ELFDATA2LSB, EM_UNASSIGNED, &[]);
    let aarch64_at = v.len();
    v.extend(elf(ELFCLASS64, ELFDATA2LSB, EM_AARCH64, &[]));
    v.extend([0xff; 16]);
    let riscv_at = v.len();
    v.extend(elf(ELFCLASS64, ELFDATA2LSB, EM_RISCV, &[]));
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert_eq!(p.format.format, FileFormat::Elf);
    let images: Vec<(u64, Isa)> = p.slices.iter().map(|s| (s.offset, s.isa)).collect();
    assert_eq!(
        images,
        [
            (aarch64_at as u64, Isa::AArch64),
            (riscv_at as u64, Isa::RiscV64)
        ]
    );
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("2 more ELF images follow")));
}

#[test]
fn trailing_bytes_that_are_not_an_elf_header_add_no_components() {
    let mut v = elf(ELFCLASS64, ELFDATA2LSB, EM_AARCH64, &[]);
    v.extend(b"\x7fELX not an image");
    let p = detect_payload(&v, &ClassifierOptions::default()).unwrap();
    assert!(p.slices.is_empty());
}
