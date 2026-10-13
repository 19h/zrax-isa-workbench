//! The same bytes and options give the same output (AGENTS.md 3.4), down to
//! the order of candidates that tie on score.

use zrax::{detect_payload, ClassifierOptions};

/// Inputs whose candidates include equal-score variants of one ISA (MIPS64
/// in both byte orders), which came out in hash-map order before.
const TIED_INPUTS: &[(&str, usize)] = &[
    (
        "testbins/arm32_arm-unknown-linux-gnueabi_O0_min_mul_chain.bin",
        usize::MAX,
    ),
    ("tests/fixtures/socboot2/arm.text.bin", 294),
];

/// Classifications compared per input; each run builds fresh hash maps
/// with new random seeds.
const RUNS: usize = 64;

/// The payload JSON, or the error text, for `data`.
fn classification(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(payload) => serde_json::to_string(&payload).expect("payloads serialize"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn tied_candidates_come_out_in_the_same_order_on_every_run() {
    for &(path, prefix) in TIED_INPUTS {
        let file = std::fs::read(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
            .expect("input is committed");
        let data = &file[..prefix.min(file.len())];
        let first = classification(data);
        for run in 1..RUNS {
            assert_eq!(classification(data), first, "{path} run {run}");
        }
    }
}
