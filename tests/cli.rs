//! The `certs` and `strings` subcommands of the `zrax` executable: JSON and
//! CSV output, certificate export and argument errors.

use std::path::Path;
use std::process::{Command, Output};

const CHAIN_PEM: &str = "tests/fixtures/certificates/chain.pem";
const LEAF: &[u8] = include_bytes!("fixtures/certificates/leaf.der");

fn zrax(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zrax"))
        .args(args)
        .output()
        .expect("zrax runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn certs_json_lists_certificates_with_their_regions() {
    let output = zrax(&["certs", "--format", "json", CHAIN_PEM]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["file"], CHAIN_PEM);
    let certificates = value["certificates"].as_array().unwrap();
    assert_eq!(certificates.len(), 3);
    assert_eq!(certificates[0]["summary"]["subject_cn"], "Zrax Fixture Code Signing");
    assert_eq!(certificates[0]["issuer_index"], 1);
    assert_eq!(
        certificates[0]["within"],
        serde_json::json!(["certificate 0 (Zrax Fixture Code Signing)"])
    );
    assert!(certificates[0].get("der").is_none());
}

#[test]
fn certs_dump_writes_der_and_pem_and_refuses_a_nonempty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let out_arg = out.to_str().unwrap();
    let output = zrax(&["certs", "--dump", out_arg, CHAIN_PEM]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(out.join("cert_0.der")).unwrap(), LEAF);
    let pem = std::fs::read_to_string(out.join("cert_0.pem")).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(stdout(&output).contains("Wrote: "));

    let again = zrax(&["certs", "--dump", out_arg, CHAIN_PEM]);
    assert!(!again.status.success());
    let message = String::from_utf8_lossy(&again.stderr);
    assert!(message.contains("is not empty; use --force"), "{message}");
    assert!(zrax(&["certs", "--dump", out_arg, "--force", "--pem", CHAIN_PEM])
        .status
        .success());
}

#[test]
fn certs_dump_with_several_inputs_uses_one_directory_per_input() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let leaf = dir.path().join("leaf.der");
    std::fs::write(&leaf, LEAF).unwrap();
    let output = zrax(&[
        "certs",
        "--dump",
        out.to_str().unwrap(),
        "--der",
        CHAIN_PEM,
        leaf.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    assert!(out.join("input_1").join("cert_2.der").exists());
    assert_eq!(std::fs::read(out.join("input_2").join("cert_0.der")).unwrap(), LEAF);
}

#[test]
fn certs_tree_needs_human_output_and_missing_files_fail() {
    assert!(!zrax(&["certs", "--tree", "--format", "json", CHAIN_PEM])
        .status
        .success());
    let tree = zrax(&["certs", "--tree", CHAIN_PEM]);
    assert!(stdout(&tree).contains("└─ Zrax Fixture Intermediate CA [1]"));
    let missing = zrax(&["certs", "does-not-exist.bin"]);
    assert!(!missing.status.success());
}

#[test]
fn strings_csv_and_offsets_follow_the_options() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.bin");
    // The 0x01 keeps the path's last character and NUL from forming a
    // UTF-16LE unit in front of the wide string.
    let mut data = b"\x00\x00/usr/lib/libc.so\x00\x01".to_vec();
    data.extend("wide".encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, &data).unwrap();
    let file = path.to_str().unwrap();

    let csv = zrax(&["strings", "--format", "csv", file]);
    assert!(csv.status.success());
    assert_eq!(
        stdout(&csv),
        "offset,size,chars,encoding,tags,clipped,text\r\n\
         2,16,16,ascii,path,false,/usr/lib/libc.so\r\n\
         20,8,4,utf16le,,false,wide\r\n"
    );
    let tagged = zrax(&["strings", "--tag", "path", "-t", "d", file]);
    assert_eq!(stdout(&tagged), "      2 /usr/lib/libc.so\n");
    let invalid = zrax(&["strings", "-n", "2", file]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("Invalid minimum string length 2"));
    assert!(Path::new(file).exists());
}
