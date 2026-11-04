//! Variant checks the byte model cannot make on its own: 65816 native-mode
//! code over the 6502 class, which has no 65816 sibling.

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
