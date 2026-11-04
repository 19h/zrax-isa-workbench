//! Data files with their own magic: Apple binary property lists and
//! Qualcomm Atheros board data are opaque formats with an unknown ISA, and
//! damaged ones are parse errors.

use zrax::formats::container::Kind;
use zrax::formats::datafile::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierError, ClassifierOptions, FileFormat, Isa};

/// A binary plist with `objects` one-byte objects (`0x09`, true) after the
/// header, a one-byte offset table, and the 32-byte trailer: 5 unused
/// bytes, sort version, offset size 1, reference size 1, object count, top
/// object 0, offset table offset (all big-endian).
fn bplist(objects: u8) -> Vec<u8> {
    let mut v = b"bplist00".to_vec();
    let first = v.len() as u8;
    v.extend(std::iter::repeat(0x09).take(usize::from(objects)));
    let table = v.len() as u64;
    v.extend((0..objects).map(|i| first + i));
    v.extend([0, 0, 0, 0, 0, 0, 1, 1]);
    v.extend(u64::from(objects).to_be_bytes());
    v.extend(0u64.to_be_bytes());
    v.extend(table.to_be_bytes());
    v
}

/// Append an information element: id and length (`__le32`), data, padding
/// to four bytes.
fn push_ie(v: &mut Vec<u8>, id: u32, data: &[u8]) {
    v.extend(id.to_le_bytes());
    v.extend((data.len() as u32).to_le_bytes());
    v.extend(data);
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

/// ath10k board data: magic, NUL, padding to four bytes, then one board
/// element holding a `NAME` (0) and a `DATA` (1) sub-element.
fn qca_board(name: &str) -> Vec<u8> {
    let mut board = Vec::new();
    push_ie(&mut board, 0, name.as_bytes());
    push_ie(&mut board, 1, &[0x5a; 40]);
    let mut v = b"QCA-ATH10K-BOARD\0".to_vec();
    while v.len() % 4 != 0 {
        v.push(0);
    }
    push_ie(&mut v, 0, &board);
    v
}

fn opaque_unknown(v: &[u8], format: FileFormat) {
    let p = detect_payload(v, &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, format);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
}

#[test]
fn binary_plist_is_an_opaque_data_file() {
    let v = bplist(3);
    assert!(matches!(
        detect_format(&v),
        DetectedFormat::Container {
            kind: Kind::DataFile(Layout::BinaryPlist)
        }
    ));
    opaque_unknown(&v, FileFormat::Bplist);
    let c = datafile::parse_container(&v, Layout::BinaryPlist).unwrap();
    assert!(c.opaque);
    assert!(c
        .metadata
        .iter()
        .any(|m| m.label == "Objects" && m.value.to_string() == "3"));
}

#[test]
fn binary_plist_trailer_and_offsets_are_checked() {
    let v = bplist(2);
    for end in 6..v.len() {
        assert!(
            datafile::parse_container(&v[..end], Layout::BinaryPlist).is_err(),
            "{end}"
        );
    }
    let mut version = v.clone();
    version[6..8].copy_from_slice(b"01");
    assert!(matches!(
        datafile::parse_container(&version, Layout::BinaryPlist),
        Err(ClassifierError::DataFileParseError { message }) if message.contains("Unsupported binary plist version")
    ));
    // An object offset that points into the offset table itself
    let mut offset = v.clone();
    offset[10] = 10;
    assert!(datafile::parse_container(&offset, Layout::BinaryPlist).is_err());
    // Top object outside the object count
    let mut top = v.clone();
    let at = top.len() - 9;
    top[at] = 2;
    assert!(datafile::parse_container(&top, Layout::BinaryPlist).is_err());
    // A damaged plist is a format error, not raw data
    assert!(detect_payload(&v[..v.len() - 1], &ClassifierOptions::new()).is_err());
}

#[test]
fn qca_board_data_is_an_opaque_data_file() {
    let v = qca_board("bus=pci,vendor=168c,device=003e");
    assert!(matches!(
        detect_format(&v),
        DetectedFormat::Container {
            kind: Kind::DataFile(Layout::QcaBoard)
        }
    ));
    opaque_unknown(&v, FileFormat::QcaBoard);
    let c = datafile::parse_container(&v, Layout::QcaBoard).unwrap();
    assert!(c
        .metadata
        .iter()
        .any(|m| m.label == "Board 0" && m.value.to_string() == "bus=pci,vendor=168c,device=003e"));
}

#[test]
fn qca_board_elements_must_end_at_the_file_end() {
    let v = qca_board("bus=pci");
    for end in 0..v.len() {
        assert!(
            datafile::parse_container(&v[..end], Layout::QcaBoard).is_err(),
            "{end}"
        );
    }
    let mut long = v.clone();
    long[24..28].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(datafile::parse_container(&long, Layout::QcaBoard).is_err());
    let mut no_nul = v.clone();
    no_nul[16] = b'X';
    assert!(datafile::parse_container(&no_nul, Layout::QcaBoard).is_err());
}

#[test]
fn byte_mutations_do_not_panic() {
    for v in [bplist(4), qca_board("bus=sdio")] {
        for i in 0..v.len() {
            for x in [0x00, 0xff, v[i] ^ 0x80] {
                let mut m = v.clone();
                m[i] = x;
                let _ = detect_payload(&m, &ClassifierOptions::new());
            }
        }
    }
}
