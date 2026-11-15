//! The model card describes the embedded model: it names that model's
//! SHA-256, has a record for every class of the model, its tallies add up,
//! and the family and answer sums are the sums of their classes.

use std::path::Path;

use sha2::{Digest, Sha256};
use zrax::heuristics::{ClassKind, Model, ModelCard, Tally, CLASSES, WHOLE_SAMPLE};
use zrax::{Endianness, Isa};

fn card() -> &'static ModelCard {
    ModelCard::embedded()
}

#[test]
fn the_card_names_the_embedded_model() {
    let model =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/heuristics/model.bin"))
            .expect("the model is in the repository");
    assert_eq!(card().model_sha256, hex::encode(Sha256::digest(&model)));
    assert_ne!(card().model_sha256, card().measured_model_sha256);
}

#[test]
fn every_class_of_the_embedded_model_has_a_record_with_training_data() {
    for info in Model::embedded().classes() {
        let record = card()
            .class(info.name)
            .unwrap_or_else(|| panic!("no record for {}", info.name));
        assert!(record.training.samples > 0, "{}", info.name);
        assert!(record.training.groups >= 1, "{}", info.name);
        assert!(record.training.sources >= 1, "{}", info.name);
        assert!(
            record.training.groups <= record.training.samples,
            "{}",
            info.name
        );
    }
}

#[test]
fn every_tally_adds_up() {
    for (name, record) in &card().classes {
        for (input, tally) in &record.held_out {
            assert_eq!(
                tally.correct + tally.wrong + tally.rejected,
                tally.n,
                "{name} {input}"
            );
            assert!(tally.exact <= tally.correct, "{name} {input}");
        }
    }
}

#[test]
fn a_non_code_class_is_never_counted_correct() {
    for info in CLASSES.iter().filter(|info| !info.is_code()) {
        let Some(record) = card().class(info.name) else {
            continue;
        };
        for tally in record.held_out.values() {
            assert_eq!((tally.correct, tally.exact), (0, 0), "{}", info.name);
        }
    }
}

fn class_tally(name: &str) -> Tally {
    card()
        .class(name)
        .and_then(|record| record.held_out.get(WHOLE_SAMPLE))
        .copied()
        .unwrap_or_default()
}

#[test]
fn a_family_sum_is_the_sum_of_its_code_classes() {
    let arm = card()
        .family_held_out("arm", WHOLE_SAMPLE)
        .expect("the Arm classes are measured");
    let mut expected = Tally::default();
    for info in CLASSES
        .iter()
        .filter(|info| info.is_code() && info.family == "arm")
    {
        let tally = class_tally(info.name);
        expected.n += tally.n;
        expected.correct += tally.correct;
        expected.exact += tally.exact;
        expected.wrong += tally.wrong;
        expected.rejected += tally.rejected;
    }
    assert_eq!(arm, expected);
    assert!(arm.n > class_tally("arm").n);
}

#[test]
fn an_answer_sum_covers_only_the_classes_with_that_answer() {
    let aarch64 = card()
        .answer_held_out(Isa::AArch64, Endianness::Little, 64, WHOLE_SAMPLE)
        .expect("AArch64 is measured");
    assert_eq!(aarch64, class_tally("aarch64"));

    let big_arm = card()
        .answer_held_out(Isa::Arm, Endianness::Big, 32, WHOLE_SAMPLE)
        .expect("big-endian Arm is measured");
    let classes: Vec<&str> = CLASSES
        .iter()
        .filter(|info| {
            matches!(
                info.kind,
                ClassKind::Code {
                    isa: Isa::Arm,
                    endianness: Endianness::Big,
                    bitwidth: 32,
                    ..
                }
            )
        })
        .map(|info| info.name)
        .collect();
    assert!(classes.len() >= 2);
    assert_eq!(
        big_arm.n,
        classes
            .iter()
            .map(|name| class_tally(name).n)
            .sum::<usize>()
    );
}

#[test]
fn an_unmeasured_family_input_or_answer_has_no_sum() {
    assert_eq!(card().family_held_out("no such family", WHOLE_SAMPLE), None);
    assert_eq!(card().family_held_out("arm", "no such input"), None);
    assert_eq!(
        card().answer_held_out(Isa::AArch64, Endianness::Big, 64, WHOLE_SAMPLE),
        None
    );
}
