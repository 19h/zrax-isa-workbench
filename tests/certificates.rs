//! Certificate scanning in arbitrary bytes: DER and PEM discovery, decoded
//! fields, duplicate and issuer links, window equivalence and hostile-input
//! bounds, and links among certificates gathered from several inputs.
//! Fixtures are described in `tests/fixtures/certificates/README.md`.

use zrax::certificates::{
    link, scan, to_pem, Encoding, Link, Report, Scan, MAX_CERTIFICATES, WINDOW_OVERLAP,
};

const ROOT: &[u8] = include_bytes!("fixtures/certificates/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/certificates/intermediate.der");
const LEAF: &[u8] = include_bytes!("fixtures/certificates/leaf.der");
const EXPIRED: &[u8] = include_bytes!("fixtures/certificates/expired.der");
const CHAIN_PEM: &[u8] = include_bytes!("fixtures/certificates/chain.pem");
const CHAIN_CRLF_PEM: &[u8] = include_bytes!("fixtures/certificates/chain-crlf.pem");
const NOT_A_CERTIFICATE_PEM: &[u8] = include_bytes!("fixtures/certificates/not-a-certificate.pem");

const LEAF_SHA256: &str = "6ff05cfb09f06881ca984faa9cb34dde93904204c6e83a47da93dd3fb76d7540";

/// Deterministic noise from a 32-bit linear congruential generator.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

/// `noise` with `parts` copied in at the given offsets.
fn embed(len: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
    let mut data = noise(len, 0x5eed);
    for (offset, bytes) in parts {
        data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    data
}

fn json(report: &Report) -> String {
    serde_json::to_string(report).unwrap()
}

#[test]
fn der_certificates_are_found_at_odd_offsets_in_noise() {
    let data = embed(8192, &[(17, ROOT), (1001, INTERMEDIATE), (3333, LEAF)]);
    let report = scan(&data);
    let found: Vec<(u64, u64, Encoding)> = report
        .certificates
        .iter()
        .map(|c| (c.offset, c.stored_size, c.encoding))
        .collect();
    assert_eq!(
        found,
        vec![
            (17, ROOT.len() as u64, Encoding::Der),
            (1001, INTERMEDIATE.len() as u64, Encoding::Der),
            (3333, LEAF.len() as u64, Encoding::Der),
        ]
    );
    assert_eq!(report.certificates[2].der, LEAF);
    assert_eq!(report.certificates[2].sha256, LEAF_SHA256);
    assert!(!report.truncated);
}

#[test]
fn pem_bundle_links_leaf_intermediate_and_self_issued_root() {
    for bundle in [CHAIN_PEM, CHAIN_CRLF_PEM] {
        let report = scan(bundle);
        let certificates = &report.certificates;
        assert_eq!(certificates.len(), 3);
        assert!(certificates.iter().all(|c| c.encoding == Encoding::Pem));
        assert_eq!(certificates[0].der, LEAF);
        assert_eq!(certificates[1].der, INTERMEDIATE);
        assert_eq!(certificates[2].der, ROOT);
        assert_eq!(certificates[0].issuer_index, Some(1));
        assert_eq!(certificates[1].issuer_index, Some(2));
        assert_eq!(certificates[2].issuer_index, None);
        assert!(certificates[2].self_issued);
        assert!(!certificates[0].self_issued);
        // The first block starts at the BEGIN marker and ends after END.
        assert_eq!(certificates[0].offset, 0);
        let end = b"-----END CERTIFICATE-----";
        let first_end = bundle.windows(end.len()).position(|w| w == end).unwrap() + end.len();
        assert_eq!(certificates[0].stored_size, first_end as u64);
    }
}

#[test]
fn leaf_summary_reports_fixture_fields() {
    let report = scan(LEAF);
    let summary = report.certificates[0].summary.as_ref().unwrap();
    assert_eq!(summary.version, 3);
    assert_eq!(summary.serial, "03");
    assert_eq!(summary.subject_cn.as_deref(), Some("Zrax Fixture Code Signing"));
    assert_eq!(summary.issuer_cn.as_deref(), Some("Zrax Fixture Intermediate CA"));
    assert!(summary.subject.contains("CN=Zrax Fixture Code Signing"));
    assert!(summary.subject.contains("O=Zrax Fixtures"));
    assert_eq!(summary.not_before, "2025-01-01T00:00:00Z");
    assert_eq!(summary.not_after, "2050-01-01T00:00:00Z");
    assert_eq!(summary.not_before_unix, 1_735_689_600);
    assert_eq!(summary.public_key_algorithm, "Ed25519");
    assert_eq!(summary.public_key_bits, Some(255));
    assert_eq!(summary.curve, None);
    assert_eq!(summary.signature_algorithm, "ecdsa-with-SHA256");
    assert_eq!(summary.signature_oid, "1.2.840.10045.4.3.2");
    assert_eq!(summary.is_ca, Some(false));
    assert_eq!(summary.key_usage, vec!["digitalSignature"]);
    assert_eq!(summary.extended_key_usage, vec!["codeSigning"]);
    assert_eq!(
        summary.subject_alt_names,
        vec![
            "DNS:fixture.zrax.invalid",
            "email:fixture@zrax.invalid",
            "IP:192.0.2.1"
        ]
    );
    assert!(summary.subject_key_id.is_some());
    assert!(summary.authority_key_id.is_some());
    let critical: Vec<&str> = summary
        .extensions
        .iter()
        .filter(|e| e.critical)
        .map(|e| e.oid.as_str())
        .collect();
    assert_eq!(critical, vec!["2.5.29.19", "2.5.29.15"]);
}

#[test]
fn key_sizes_and_curves_come_from_the_public_key() {
    let root = scan(ROOT);
    let root = root.certificates[0].summary.as_ref().unwrap();
    assert_eq!(root.public_key_algorithm, "RSA");
    assert_eq!(root.public_key_bits, Some(2048));
    assert_eq!(root.is_ca, Some(true));
    assert_eq!(root.signature_algorithm, "sha256WithRSAEncryption");
    let intermediate = scan(INTERMEDIATE);
    let intermediate = intermediate.certificates[0].summary.as_ref().unwrap();
    assert_eq!(intermediate.public_key_algorithm, "EC");
    assert_eq!(intermediate.curve.as_deref(), Some("P-256"));
    assert_eq!(intermediate.public_key_bits, Some(256));
    assert_eq!(intermediate.path_len, Some(0));
}

#[test]
fn issuer_links_prefer_the_authority_key_identifier_and_skip_duplicates() {
    // The root appears twice; the intermediate must link to the first copy.
    let data = embed(
        6000,
        &[(10, ROOT), (1000, ROOT), (2000, INTERMEDIATE), (3000, LEAF)],
    );
    let report = scan(&data);
    let certificates = &report.certificates;
    assert_eq!(certificates.len(), 4);
    assert_eq!(certificates[1].duplicate_of, Some(0));
    assert_eq!(certificates[0].duplicate_of, None);
    assert_eq!(certificates[2].issuer_index, Some(0));
    assert_eq!(certificates[3].issuer_index, Some(2));
}

/// The links of a scan's certificates, in the shape [`link`] returns.
fn scan_links(report: &Report) -> Vec<Link> {
    report
        .certificates
        .iter()
        .map(|c| Link {
            duplicate_of: c.duplicate_of,
            issuer_index: c.issuer_index,
            self_issued: c.self_issued,
        })
        .collect()
}

#[test]
fn link_joins_certificates_from_separate_inputs() {
    let links = link(vec![LEAF.to_vec(), INTERMEDIATE.to_vec(), ROOT.to_vec()]);
    assert_eq!(
        links,
        vec![
            Link {
                duplicate_of: None,
                issuer_index: Some(1),
                self_issued: false,
            },
            Link {
                duplicate_of: None,
                issuer_index: Some(2),
                self_issued: false,
            },
            Link {
                duplicate_of: None,
                issuer_index: None,
                self_issued: true,
            },
        ]
    );
    assert_eq!(links, scan_links(&scan(CHAIN_PEM)));
}

#[test]
fn link_matches_the_links_of_a_scan_over_the_same_certificates() {
    let data = embed(
        8000,
        &[
            (10, LEAF),
            (1000, ROOT),
            (2000, EXPIRED),
            (3000, INTERMEDIATE),
            (5000, ROOT),
        ],
    );
    let report = scan(&data);
    let ders = report.certificates.iter().map(|c| c.der.clone()).collect();
    assert_eq!(link(ders), scan_links(&report));
}

#[test]
fn link_marks_duplicates_and_never_chooses_them_as_issuers() {
    let links = link(vec![ROOT.to_vec(), ROOT.to_vec(), INTERMEDIATE.to_vec()]);
    assert_eq!(links[0].duplicate_of, None);
    assert_eq!(links[1].duplicate_of, Some(0));
    assert!(links[1].self_issued);
    assert_eq!(links[2].issuer_index, Some(0));
}

#[test]
fn link_gives_entries_that_are_not_certificates_no_links() {
    let mut trailing = LEAF.to_vec();
    trailing.push(0);
    let inputs = vec![
        Vec::new(),
        noise(600, 3),
        trailing,
        LEAF[..LEAF.len() - 1].to_vec(),
        INTERMEDIATE.to_vec(),
    ];
    let links = link(inputs);
    assert_eq!(links.len(), 5);
    assert!(links
        .iter()
        .all(|l| l.issuer_index.is_none() && !l.self_issued));
    assert!(links.iter().all(|l| l.duplicate_of.is_none()));
    assert!(link(Vec::new()).is_empty());
}

#[test]
fn link_survives_byte_mutations_of_a_member() {
    for at in 0..LEAF.len() {
        for mutation in [0x00, 0xff, LEAF[at] ^ (1 << (at % 8))] {
            let mut leaf = LEAF.to_vec();
            leaf[at] = mutation;
            let links = link(vec![leaf, INTERMEDIATE.to_vec(), ROOT.to_vec()]);
            assert_eq!(links[1].issuer_index, Some(2), "at {at}");
            assert!(links[0].issuer_index.map_or(true, |i| i == 1), "at {at}");
        }
    }
}

#[test]
fn der_and_pem_copies_of_one_certificate_are_duplicates() {
    let mut data = LEAF.to_vec();
    data.extend_from_slice(b"\n");
    data.extend_from_slice(to_pem(LEAF).as_bytes());
    let report = scan(&data);
    assert_eq!(report.certificates.len(), 2);
    assert_eq!(report.certificates[0].encoding, Encoding::Der);
    assert_eq!(report.certificates[1].encoding, Encoding::Pem);
    assert_eq!(report.certificates[1].duplicate_of, Some(0));
}

#[test]
fn to_pem_matches_openssl_line_layout() {
    let report = scan(CHAIN_PEM);
    let root = &report.certificates[2];
    let start = usize::try_from(root.offset).unwrap();
    let end = start + usize::try_from(root.stored_size).unwrap();
    // OpenSSL ends the block with a line feed, which `stored_size` excludes.
    assert_eq!(to_pem(ROOT).as_bytes(), &CHAIN_PEM[start..=end]);
    assert_eq!(root.pem, to_pem(ROOT));
}

#[test]
fn pem_block_with_other_contents_is_reported_with_an_error() {
    let report = scan(NOT_A_CERTIFICATE_PEM);
    assert_eq!(report.certificates.len(), 1);
    let c = &report.certificates[0];
    assert!(c.summary.is_none());
    let error = c.error.as_deref().unwrap();
    assert!(error.starts_with("X.509 parse error: Invalid certificate structure"), "{error}");
    assert_eq!(c.issuer_index, None);
    assert!(!c.self_issued);
}

#[test]
fn pem_blocks_with_invalid_base64_are_ignored() {
    let data = b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n";
    assert!(scan(data).certificates.is_empty());
}

#[test]
fn end_marker_closes_the_innermost_begin_marker() {
    let mut data = b"-----BEGIN CERTIFICATE-----\ngarbage\n".to_vec();
    let inner = data.len();
    data.extend_from_slice(to_pem(EXPIRED).as_bytes());
    let report = scan(&data);
    assert_eq!(report.certificates.len(), 1);
    assert_eq!(report.certificates[0].offset, inner as u64);
    assert_eq!(report.certificates[0].der, EXPIRED);
}

#[test]
fn marker_floods_finish_and_find_the_closed_block() {
    let mut data = b"-----BEGIN CERTIFICATE-----".repeat(100_000);
    data.extend_from_slice(to_pem(EXPIRED).as_bytes());
    data.extend_from_slice(&b"-----END CERTIFICATE-----".repeat(100_000));
    let report = scan(&data);
    assert_eq!(report.certificates.len(), 1);
    assert_eq!(report.certificates[0].der, EXPIRED);
}

#[test]
fn windowed_scans_equal_the_whole_input_scan() {
    let mut data = embed(
        20_000,
        &[(3, ROOT), (4095, INTERMEDIATE), (9000, LEAF), (15_000, EXPIRED)],
    );
    data.extend_from_slice(CHAIN_CRLF_PEM);
    data.extend_from_slice(&noise(777, 3));
    let whole = json(&scan(&data));
    for window in [1, 2, 3, 64, 527, 1000, 4096, 16_384, data.len()] {
        let mut accumulator = Scan::new();
        let mut base = 0;
        while base < data.len() {
            let report_len = window.min(data.len() - base);
            let end = (base + report_len + WINDOW_OVERLAP).min(data.len());
            accumulator.push_window(&data[base..end], base as u64, report_len);
            base += report_len;
        }
        assert_eq!(json(&accumulator.finish()), whole, "window {window}");
    }
}

#[test]
fn truncated_inputs_find_only_complete_certificates() {
    let data = embed(LEAF.len() + 40, &[(5, LEAF)]);
    for end in 0..data.len() {
        let report = scan(&data[..end]);
        let complete = end >= 5 + LEAF.len();
        assert_eq!(report.certificates.len(), usize::from(complete), "end {end}");
    }
}

#[test]
fn byte_mutations_do_not_panic() {
    for (index, original) in [ROOT, LEAF, CHAIN_PEM].into_iter().enumerate() {
        for at in 0..original.len() {
            for mutation in [0x00, 0xff, original[at] ^ (1 << (at % 8))] {
                let mut data = original.to_vec();
                data[at] = mutation;
                let report = scan(&data);
                assert!(report.certificates.len() <= 3, "fixture {index} at {at}");
            }
        }
    }
}

#[test]
fn the_certificate_limit_sets_truncated() {
    let data = EXPIRED.repeat(MAX_CERTIFICATES + 1);
    let report = scan(&data);
    assert!(report.truncated);
    assert_eq!(report.certificates.len(), MAX_CERTIFICATES);
    assert!(report
        .notes
        .contains(&format!("Scanning stopped after {MAX_CERTIFICATES} certificates")));
    assert!(report.certificates[1..]
        .iter()
        .all(|c| c.duplicate_of == Some(0)));
}

#[test]
fn json_omits_der_bytes_and_states_what_is_not_verified() {
    let report = scan(CHAIN_PEM);
    let value: serde_json::Value = serde_json::from_str(&json(&report)).unwrap();
    let first = &value["certificates"][0];
    assert_eq!(first["encoding"], "pem");
    assert!(first.get("der").is_none());
    assert!(first.get("error").is_none());
    assert_eq!(first["summary"]["subject_cn"], "Zrax Fixture Code Signing");
    assert_eq!(
        value["notes"][0],
        "Signatures and chains not verified; issuer links compare encoded names only"
    );
    assert!(scan(b"no certificates here").notes.is_empty());
}

#[test]
fn results_are_deterministic() {
    let data = embed(4000, &[(1, LEAF), (900, ROOT)]);
    assert_eq!(json(&scan(&data)), json(&scan(&data)));
}
