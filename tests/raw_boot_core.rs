//! A raw image that carries its boot core's architectural marker (a
//! Cortex-M vector table at the start, an x86 reset vector at the end of a
//! BIOS-sized image) and holds that core's code reports the boot core, also
//! when another core's code dominates the image; a malformed marker or a
//! marker without that core's code changes nothing.

use std::path::Path;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Isa};

/// Thumb (ARMv7-M) code compiled from the repository's test programs.
const THUMB_FIXTURES: [&str; 6] = [
    "thumb_thumbv7m-none-eabi_O0_asm_atomic_ops.bin",
    "thumb_thumbv7m-none-eabi_O0_asm_barriers.bin",
    "thumb_thumbv7m-none-eabi_O0_min_float_add.bin",
    "thumb_thumbv7m-none-eabi_O0_min_float_mul.bin",
    "thumb_thumbv7m-none-eabi_O0_min_div_chain.bin",
    "thumb_thumbv7m-none-eabi_O0_min_store_chain.bin",
];

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .expect("fixture is in the repository")
}

fn thumb_code() -> Vec<u8> {
    THUMB_FIXTURES
        .iter()
        .flat_map(|name| read(&format!("testbins/{name}")))
        .collect()
}

/// RISC-V code (`tests/fixtures/transforms`), repeated `copies` times.
fn riscv_code(copies: usize) -> Vec<u8> {
    read("tests/fixtures/transforms/riscv64.text.bin").repeat(copies)
}

/// A Cortex-M vector table: initial stack pointer in SRAM, reset handler,
/// NMI, HardFault, MemManage, BusFault and UsageFault handlers (Thumb bit
/// set), four reserved words, SVCall, DebugMonitor, one reserved word,
/// PendSV and SysTick.
fn vector_table(reset: u32) -> Vec<u8> {
    let words: [u32; 16] = [
        0x2004_0000,
        reset,
        0x2000_0201,
        0x2000_0203,
        0x2000_0205,
        0x2000_0207,
        0x2000_0209,
        0,
        0,
        0,
        0,
        0x2000_020B,
        0x2000_020D,
        0,
        0x2000_020F,
        0x2000_0211,
    ];
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn classify(image: &[u8]) -> Option<DetectionPayload> {
    detect_payload(image, &ClassifierOptions::new()).ok()
}

#[test]
fn vector_table_names_the_boot_core_of_a_mixed_image() {
    let mixed = [riscv_code(6), thumb_code()].concat();
    let without_table = classify(&mixed).expect("the RISC-V code decides");
    assert_ne!(without_table.primary.isa, Isa::Arm);

    let image = [vector_table(0x2000_0101), mixed].concat();
    let p = classify(&image).expect("the boot core is identified");
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("Cortex-M vector table at offset 0")));
}

#[test]
fn vector_table_without_thumb_code_names_no_core() {
    let image = [vector_table(0x2000_0101), riscv_code(6)].concat();
    let p = classify(&image).expect("the RISC-V code decides");
    assert_ne!(p.primary.isa, Isa::Arm);
}

#[test]
fn a_reset_vector_without_the_thumb_bit_is_no_vector_table() {
    let mixed = [riscv_code(6), thumb_code()].concat();
    let image = [vector_table(0x2000_0100), mixed].concat();
    let p = classify(&image).expect("the RISC-V code decides");
    assert_ne!(p.primary.isa, Isa::Arm);
}

/// 32-bit x86 code compiled from the repository's test programs.
fn x86_code() -> Vec<u8> {
    let mut paths: Vec<_> =
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("testbins"))
            .expect("testbins is in the repository")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("x86_i686") && n.ends_with(".bin"))
            })
            .collect();
    // Directory order is not defined; the fixture must not depend on it.
    paths.sort();
    paths
        .iter()
        .take(8)
        .flat_map(|path| std::fs::read(path).expect("readable fixture"))
        .collect()
}

/// A 64 KiB flash image: `code`, erased flash, and at the end either an x86
/// reset vector (`jmp far F000:E05B`) or erased bytes.
fn bios_image(code: &[u8], reset_vector: bool) -> Vec<u8> {
    let mut image = code.to_vec();
    image.resize(64 * 1024, 0xff);
    if reset_vector {
        let at = image.len() - 16;
        image[at..at + 5].copy_from_slice(&[0xea, 0x5b, 0xe0, 0x00, 0xf0]);
    }
    image
}

#[test]
fn x86_reset_vector_names_the_boot_core_of_a_mixed_flash_image() {
    let mixed = [riscv_code(8), x86_code()].concat();
    assert!(mixed.len() < 60 * 1024);
    let without_vector = classify(&bios_image(&mixed, false)).expect("the RISC-V code decides");
    assert_ne!(without_vector.primary.isa, Isa::X86);
    let p = classify(&bios_image(&mixed, true)).expect("the boot core is identified");
    assert_eq!(p.primary.isa, Isa::X86);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("x86 reset vector")));
}
