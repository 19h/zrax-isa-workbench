//! The model card: what was measured about the embedded model, per class.
//!
//! The embedded model is trained on every split of its corpus, so it cannot
//! be measured on held-out data itself. The card records the results of its
//! sibling: the same recipe trained on the train split only, evaluated by
//! `examples/eval.rs` on the test split of each corpus. `model_card.json` is
//! written by `scripts/fw1/model_card.py` from those evaluations and names
//! the SHA-256 of the `model.bin` it describes; a test fails when the two
//! drift apart.
//!
//! "Correct" is the right model family. "Exact" also has the right ISA, byte
//! order and bit width. The variant (A32 against Thumb, microMIPS) is not
//! scored.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::model::{ClassKind, CLASSES};
use crate::types::{Endianness, Isa};

/// Input kind of whole held-out samples.
pub const WHOLE_SAMPLE: &str = "file";

/// Outcomes of one class on one kind of held-out input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    /// Samples.
    pub n: usize,
    /// Answered with the right family (for a non-code class: always 0).
    pub correct: usize,
    /// Answered with the right ISA, byte order and bit width.
    pub exact: usize,
    /// Answered with another family (for a non-code class: read as code).
    pub wrong: usize,
    /// Not answered.
    pub rejected: usize,
}

impl Tally {
    fn add(&mut self, other: &Tally) {
        self.n += other.n;
        self.correct += other.correct;
        self.exact += other.exact;
        self.wrong += other.wrong;
        self.rejected += other.rejected;
    }
}

/// What the embedded model's class was trained on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Training {
    /// Samples of the class.
    pub samples: usize,
    /// Distinct sample groups (one program, firmware image or ROM set each).
    pub groups: usize,
    /// Distinct corpus sources (a compiler matrix, a firmware collection).
    pub sources: usize,
}

/// The record of one model class.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassCard {
    /// Training data of the embedded model.
    pub training: Training,
    /// Held-out results of the measured model by input kind: [`WHOLE_SAMPLE`]
    /// or a snippet size in bytes (`"128"`). Empty when the measured model
    /// has no such class or the test split has no sample of it.
    pub held_out: BTreeMap<String, Tally>,
}

/// The record of the embedded model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCard {
    /// Name of the embedded model.
    pub model: String,
    /// SHA-256 of the embedded `model.bin`, lowercase hex.
    pub model_sha256: String,
    /// Name of the model the held-out results were measured with.
    pub measured_model: String,
    /// SHA-256 of that model, lowercase hex.
    pub measured_model_sha256: String,
    /// Date of the measurement, `YYYY-MM-DD`.
    pub measured_on: String,
    /// Corpora whose test splits were evaluated.
    pub corpora: Vec<String>,
    /// Records by class name, as in [`CLASSES`].
    pub classes: BTreeMap<String, ClassCard>,
}

impl ModelCard {
    /// The card of the embedded model.
    ///
    /// # Panics
    ///
    /// If the embedded card is not valid JSON, which the card's tests rule
    /// out for a built crate.
    pub fn embedded() -> &'static ModelCard {
        static CARD: OnceLock<ModelCard> = OnceLock::new();
        CARD.get_or_init(|| {
            serde_json::from_str(include_str!("model_card.json"))
                .expect("the embedded model card is valid")
        })
    }

    /// The record of the class named `name`.
    pub fn class(&self, name: &str) -> Option<&ClassCard> {
        self.classes.get(name)
    }

    /// Held-out results on `input` summed over the code classes of `family`.
    /// `None` when no class of the family was measured on that input.
    pub fn family_held_out(&self, family: &str, input: &str) -> Option<Tally> {
        self.sum(input, |info| info.is_code() && info.family == family)
    }

    /// Held-out results on `input` summed over the classes that answer with
    /// exactly `isa`, `endianness` and `bitwidth`. `None` when no such class
    /// was measured on that input.
    pub fn answer_held_out(
        &self,
        isa: Isa,
        endianness: Endianness,
        bitwidth: u8,
        input: &str,
    ) -> Option<Tally> {
        self.sum(input, |info| {
            matches!(
                info.kind,
                ClassKind::Code { isa: i, endianness: e, bitwidth: b, .. }
                    if i == isa && e == endianness && b == bitwidth
            )
        })
    }

    fn sum(
        &self,
        input: &str,
        selects: impl Fn(&super::model::ClassInfo) -> bool,
    ) -> Option<Tally> {
        let mut total = Tally::default();
        let mut measured = false;
        for info in CLASSES.iter().filter(|info| selects(info)) {
            let Some(tally) = self
                .classes
                .get(info.name)
                .and_then(|card| card.held_out.get(input))
            else {
                continue;
            };
            total.add(tally);
            measured = true;
        }
        measured.then_some(total)
    }
}
