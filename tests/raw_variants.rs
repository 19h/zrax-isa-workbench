//! Variant checks the byte model cannot make on its own: 65816 native-mode
//! code over the 6502 class, which has no 65816 sibling, and SH-4 code over
//! the SuperH classes, which have no SH-4 sibling.

use zrax::heuristics::{self, model, Model, ModelBuilder};
use zrax::{ClassifierOptions, Isa};

/// `REP #$30` and `SEP #$30`: 16-bit, then 8-bit accumulator and index.
const REP_MX: [u8; 2] = [0xC2, 0x30];
const SEP_MX: [u8; 2] = [0xE2, 0x30];
const RTS: u8 = 0x60;

/// One 6502 routine: `LDA #i; STA $20i0; LDX #i; STX $21i0; RTS`, with the
/// immediate and address bytes varied so a window holds many distinct
/// byte pairs.
fn routine(i: u8) -> Vec<u8> {
    vec![
        0xA9,
        i,
        0x8D,
        i,
        0x20,
        0xA2,
        i.wrapping_add(3),
        0x8E,
        i,
        0x21,
        RTS,
    ]
}

/// The same routine run in native mode: `REP #$30` before it, `SEP #$30`
/// before its `RTS`.
fn native_routine(i: u8) -> Vec<u8> {
    let body = routine(i);
    [&REP_MX[..], &body[..body.len() - 1], &SEP_MX[..], &[RTS]].concat()
}

fn code(n: usize, routine: fn(u8) -> Vec<u8>) -> Vec<u8> {
    (0..=255u8).cycle().flat_map(routine).take(n).collect()
}

/// A model whose only code class is the 6502, trained on both forms, and
/// one data class.
fn model_bytes() -> Vec<u8> {
    let mut mos6502 = ModelBuilder::new();
    let mut rodata = ModelBuilder::new();
    mos6502.add(&code(64 * 1024, routine));
    mos6502.add(&code(16 * 1024, native_routine));
    for i in 0..20_000u32 {
        rodata.add(&[0x00, 0x00, u8::try_from(i % 3).expect("below 3"), 0x00]);
    }
    Model::serialize(
        &[
            ("mos6502".into(), mos6502.build(16.0, model::COST_SCALE)),
            ("neg_rodata".into(), rodata.build(16.0, model::COST_SCALE)),
        ],
        model::COST_SCALE,
    )
}

#[test]
fn native_mode_code_of_the_6502_family_is_65816() {
    let bytes = model_bytes();
    let model = Model::parse(&bytes).expect("toy model");
    let options = ClassifierOptions::new();
    let plain = heuristics::analyze_with_model(&code(8 * 1024, routine), &options, &model)
        .expect("6502 code classifies");
    assert_eq!(plain.isa, Isa::Mcs6502);
    let native = heuristics::analyze_with_model(&code(8 * 1024, native_routine), &options, &model)
        .expect("65816 code classifies");
    assert_eq!(native.isa, Isa::W65816);
    assert_eq!(native.bitwidth, 16);
}

/// One little-endian SuperH routine: `MOV #i,R1; MOV.L R1,@(4,R14);
/// ADD #4,R14; STS.L PR,@-R15; LDS.L @R15+,PR; RTS; NOP`, with the
/// immediates varied so a window holds many distinct byte pairs.
fn sh_routine(i: u8) -> Vec<u8> {
    let words = [
        0xE100 | u16::from(i),
        0x1E11,
        0x7E04,
        0x4F22,
        0x4F26,
        0x000B,
        0x0009,
    ];
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// The same routine as SH-4 code that switches FPU modes and flushes a cache
/// line: `FSCHG`, `FRCHG` and `OCBWB @R14` before the return.
fn sh4_routine(i: u8) -> Vec<u8> {
    let body = sh_routine(i);
    let sh4_only: Vec<u8> = [0xF3FD_u16, 0xFBFD, 0x0EB3]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    [&body[..body.len() - 4], &sh4_only[..], &body[body.len() - 4..]].concat()
}

/// A model whose only SuperH class is `sh`, trained on both forms, and one
/// data class.
fn sh_model_bytes() -> Vec<u8> {
    let mut sh = ModelBuilder::new();
    let mut rodata = ModelBuilder::new();
    sh.add(&code(64 * 1024, sh_routine));
    sh.add(&code(16 * 1024, sh4_routine));
    for i in 0..20_000u32 {
        rodata.add(&[0x00, 0x00, u8::try_from(i % 3).expect("below 3"), 0x00]);
    }
    Model::serialize(
        &[
            ("sh".into(), sh.build(16.0, model::COST_SCALE)),
            ("neg_rodata".into(), rodata.build(16.0, model::COST_SCALE)),
        ],
        model::COST_SCALE,
    )
}

#[test]
fn superh_code_with_sh4_only_instructions_is_sh4() {
    let bytes = sh_model_bytes();
    let model = Model::parse(&bytes).expect("toy model");
    let options = ClassifierOptions::new();
    let plain = heuristics::analyze_with_model(&code(8 * 1024, sh_routine), &options, &model)
        .expect("SuperH code classifies");
    assert_eq!(plain.isa, Isa::Sh);
    let sh4 = heuristics::analyze_with_model(&code(8 * 1024, sh4_routine), &options, &model)
        .expect("SH-4 code classifies");
    assert_eq!(sh4.isa, Isa::Sh4);
    assert_eq!(sh4.bitwidth, 32);
}
