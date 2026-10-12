//! Automotive flash containers: ODX-F flash data (Intel HEX, hex-text
//! binary, opaque transformed data), Honda RWD formats 0x5A and 0x31,
//! Toyota CUW member lists and Mercedes CFF segments, with checksums,
//! truncation and mutation sweeps.

use zrax::formats::checksum::{crc32, crc32_update};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transforms/aarch64.text.bin"
);

fn code() -> Vec<u8> {
    std::fs::read(CODE).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

/// Intel HEX records (type 00 data, 16 B each, then type 01 EOF), each with
/// its two's-complement checksum.
fn intel_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let address = (i * 16) as u16;
        let mut record = vec![chunk.len() as u8, (address >> 8) as u8, address as u8, 0];
        record.extend_from_slice(chunk);
        let sum = record.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        record.push(sum.wrapping_neg());
        out.push(':');
        out.extend(record.iter().map(|b| format!("{b:02X}")));
        out.push('\n');
    }
    out.push_str(":00000001FF\n");
    out
}

/// Motorola S-record S1 data records (16-bit address) and an S9 end record.
fn srec(bytes: &[u8]) -> String {
    let mut out = String::from("S0030000FC\n");
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let address = (i * 16) as u16;
        let mut record = vec![(chunk.len() + 3) as u8, (address >> 8) as u8, address as u8];
        record.extend_from_slice(chunk);
        let sum = record.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        out.push_str("S1");
        out.extend(record.iter().map(|b| format!("{b:02X}")));
        out.push_str(&format!("{:02X}\n", !sum));
    }
    out.push_str("S9030000FC\n");
    out
}

/// An ODX-F document: one data block referencing one flash data element,
/// plus `extra` raw XML inside FLASHDATAS.
fn odx(flashdata: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ODX MODEL-VERSION="2.2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <FLASH ID="FL.example">
    <SHORT-NAME>example</SHORT-NAME>
    <ECU-MEMS>
      <ECU-MEM ID="EM.1">
        <SHORT-NAME>mem</SHORT-NAME>
        <MEM>
          <DATABLOCKS>
            <DATABLOCK ID="DB.1" TYPE="CODE">
              <SHORT-NAME>application</SHORT-NAME>
              <FLASHDATA-REF ID-REF="FD.1"/>
              <SEGMENTS>
                <SEGMENT ID="SEG.1">
                  <SHORT-NAME>seg</SHORT-NAME>
                  <SOURCE-START-ADDRESS>08000000</SOURCE-START-ADDRESS>
                  <UNCOMPRESSED-SIZE>6384</UNCOMPRESSED-SIZE>
                </SEGMENT>
              </SEGMENTS>
            </DATABLOCK>
          </DATABLOCKS>
          <FLASHDATAS>
{flashdata}
          </FLASHDATAS>
        </MEM>
      </ECU-MEM>
    </ECU-MEMS>
  </FLASH>
</ODX>
"#
    )
    .into_bytes()
}

fn intern_flashdata(id: &str, selection: &str, data: &str, transformed: bool) -> String {
    let method = if transformed {
        r#"<ENCRYPT-COMPRESS-METHOD TYPE="A_UINT32">17</ENCRYPT-COMPRESS-METHOD>"#
    } else {
        ""
    };
    format!(
        r#"<FLASHDATA ID="{id}" xsi:type="INTERN-FLASHDATA"><SHORT-NAME>{id}</SHORT-NAME><DATAFORMAT SELECTION="{selection}"/>{method}<DATA>
{data}</DATA></FLASHDATA>"#
    )
}

#[test]
fn odx_intel_hex_flash_data_is_decoded_and_classified() {
    let document = odx(&intern_flashdata(
        "FD.1",
        "INTEL-HEX",
        &intel_hex(&code()),
        false,
    ));
    let p = classify(&document);
    assert_eq!(p.format.format, FileFormat::Odx);
    assert_eq!(p.format.variant_name.as_deref(), Some("ASAM ODX document"));
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].label.as_deref(), Some("FD.1 (INTEL-HEX)"));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("segments at 0x08000000")));
}

#[test]
fn odx_binary_flash_data_is_hex_text() {
    let hex: String = elf_x86_64().iter().map(|b| format!("{b:02X} ")).collect();
    let p = classify(&odx(&intern_flashdata("FD.1", "BINARY", &hex, false)));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(
        p.slices[0].decoded.as_ref().unwrap().transform,
        "ODX hex text"
    );
}

#[test]
fn odx_transformed_and_user_defined_data_stay_opaque() {
    let hex: String = elf_x86_64().iter().map(|b| format!("{b:02X}")).collect();
    for flashdata in [
        intern_flashdata("FD.1", "BINARY", &hex, true),
        intern_flashdata("FD.1", "USER-DEFINED", &hex, false),
    ] {
        let p = classify(&odx(&flashdata));
        assert!(matches!(p.primary.isa, Isa::Unknown(_)));
        assert!(p.candidates.is_empty());
        assert!(p.notes.iter().any(|n| n.message.contains("not analyzed")));
    }
    let extern_data = r#"<FLASHDATA ID="FD.1" xsi:type="EXTERN-FLASHDATA"><SHORT-NAME>x</SHORT-NAME><DATAFORMAT SELECTION="BINARY"/><DATAFILE LATEBOUND-DATAFILE="false">app.bin</DATAFILE></FLASHDATA>"#;
    let p = classify(&odx(extern_data));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("external data file app.bin")));
}

#[test]
fn malformed_odx_is_a_format_error() {
    let document = odx(&intern_flashdata("FD.1", "BINARY", "00", false));
    let text = String::from_utf8(document).unwrap();
    let broken = text.replace("</MEM>", "</MEMORY>");
    assert!(detect_payload(broken.as_bytes(), &ClassifierOptions::new()).is_err());
}

/// RWD format 0x5A: "Z\r\n", six headers (count, then length-prefixed
/// values), start address and length (big-endian), firmware, and the
/// little-endian sum of all preceding bytes.
fn rwd_5a(firmware: &[u8]) -> Vec<u8> {
    let mut data = b"Z\r\n".to_vec();
    let headers: [&[&[u8]]; 6] = [
        &[&[0]],
        &[],
        &[&[0x30]],
        &[b"39990-TV9-A910\0\0"],
        &[&[0, 1, 2, 3, 4, 5]],
        &[&[0x11, 0x22, 0x33]],
    ];
    for values in headers {
        data.push(values.len() as u8);
        for value in values {
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
    }
    data.extend_from_slice(&0x0000_4000u32.to_be_bytes());
    data.extend_from_slice(&(firmware.len() as u32).to_be_bytes());
    data.extend_from_slice(firmware);
    let sum = data.iter().fold(0u32, |s, b| s.wrapping_add(u32::from(*b)));
    data.extend_from_slice(&sum.to_le_bytes());
    data
}

/// RWD format 0x31: "1\r\n", six `T\r\n`-delimited headers (the `&` header
/// holds the key as hex text), 130-byte records (address in 16-byte units,
/// 128 data bytes), and the trailing sum.
fn rwd_31(records: &[(u16, [u8; 128])]) -> Vec<u8> {
    let mut data = b"1\r\n".to_vec();
    for (kind, value) in [
        (b'A', &b"x"[..]),
        (b'B', b""),
        (b'&', b"112233"),
        (b'C', b""),
        (b'D', b""),
        (b'E', b""),
    ] {
        data.extend_from_slice(&[kind, b'\r', b'\n']);
        if !value.is_empty() {
            data.extend_from_slice(value);
            data.extend_from_slice(b"\r\n");
        }
        data.extend_from_slice(&[kind, b'\r', b'\n']);
    }
    for (address, bytes) in records {
        data.extend_from_slice(&address.to_be_bytes());
        data.extend_from_slice(bytes);
    }
    let sum = data.iter().fold(0u32, |s, b| s.wrapping_add(u32::from(*b)));
    data.extend_from_slice(&sum.to_le_bytes());
    data
}

#[test]
fn rwd_firmware_is_listed_but_opaque() {
    let file = rwd_5a(&[0xa5; 256]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::HondaRwd);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].offset, (file.len() - 4 - 256) as u64);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("CAN address 0x18DA30F1")));
    assert!(p.candidates.is_empty());

    // Records at 0x100 and 0x180 form one block; 0x400 starts another.
    let file = rwd_31(&[(0x0010, [1; 128]), (0x0018, [2; 128]), (0x0040, [3; 128])]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::HondaRwd);
    let labels: Vec<_> = p.slices.iter().map(|s| s.label.clone().unwrap()).collect();
    assert_eq!(
        labels,
        [
            "Firmware at 0x00000100 (2 records)",
            "Firmware at 0x00000400 (1 records)"
        ]
    );
}

#[test]
fn rwd_needs_its_checksum_to_be_recognized() {
    let mut file = rwd_5a(&[0xa5; 64]);
    let last = file.len() - 1;
    file[last] ^= 1;
    assert!(!matches!(
        zrax::formats::detect_format(&file),
        zrax::formats::DetectedFormat::Container { .. }
    ));
}

/// CUW: magic, format type, CRC-32 of [18, total), total size, then members
/// of name length, name, payload length, payload CRC-32 and payload (all
/// big-endian); format 0x04 adds a member count before further members.
fn cuw(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = b"\0CALIBRATION\0".to_vec();
    data.push(0x04);
    data.extend_from_slice(&[0; 8]);
    let member = |data: &mut Vec<u8>, name: &str, payload: &[u8]| {
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&crc32(payload).to_be_bytes());
        data.extend_from_slice(payload);
    };
    let (first, rest) = members.split_first().unwrap();
    member(&mut data, first.0, first.1);
    data.push(rest.len() as u8);
    for (name, payload) in rest {
        member(&mut data, name, payload);
    }
    let total = data.len() as u32;
    data[18..22].copy_from_slice(&total.to_be_bytes());
    let crc = crc32(&data[18..]);
    data[14..18].copy_from_slice(&crc.to_be_bytes());
    data
}

#[test]
fn cuw_members_are_verified_and_recognized_payloads_classified() {
    let attach = b"[Vehicle]\r\nVehicleName=TEST\r\n";
    let image = srec(&elf_x86_64());
    let file = cuw(&[
        ("attach.att", attach),
        ("CPUImage1", image.as_bytes()),
        ("blob", &[0x5a; 64]),
    ]);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::ToyotaCuw);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let labels: Vec<_> = p.slices.iter().map(|s| s.label.clone().unwrap()).collect();
    assert_eq!(labels, ["attach.att", "CPUImage1"]);
    let mut corrupt = file.clone();
    let at = corrupt.len() - 10;
    corrupt[at] ^= 1;
    assert!(detect_payload(&corrupt, &ClassifierOptions::new()).is_err());
}

/// One bit-flag record: the flag word (`flag_bytes` wide), two unused bytes
/// for 4-byte flag words, then the present fields as little-endian values.
fn record(flag_bytes: usize, fields: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let flags = fields.iter().fold(0u32, |f, (bit, _)| f | (1 << bit));
    let mut out = if flag_bytes == 2 {
        (flags as u16).to_le_bytes().to_vec()
    } else {
        let mut word = flags.to_le_bytes().to_vec();
        word.extend_from_slice(&[0, 0]);
        word
    };
    for (_, value) in fields {
        out.extend_from_slice(value);
    }
    out
}

fn i32le(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// CFF: 0x410-byte stub, header size, flash header (name, data block count
/// and table), one data block (qualifier, flash data offset 0, one segment)
/// and its segment (address, length, name), the segment data, and the
/// un-inverted CRC-32 of everything before it.
fn cff(segment: &[u8]) -> Vec<u8> {
    // Flash header at 0x414: bit 0 name (string), bit 12 data block count,
    // bit 13 data block table; strings and tables follow the record.
    let header_len = 4 + 2 + 3 * 4;
    let name_at = header_len;
    let table_at = name_at + 8;
    let block_at = table_at + 4;
    let mut header = record(
        4,
        &[(0, i32le(name_at)), (12, i32le(1)), (13, i32le(table_at))],
    );
    header.extend_from_slice(b"FLASH01\0");
    header.extend_from_slice(&i32le(block_at - table_at));
    // Data block: bit 0 qualifier, bit 3 flash data, bit 9 segment count,
    // bit 10 segment table (relative to the block).
    let block_len = 4 + 2 + 4 * 4;
    let block = record(
        4,
        &[
            (0, i32le(block_len)),
            (3, i32le(0)),
            (9, i32le(1)),
            (10, i32le(block_len + 4)),
        ],
    );
    header.extend_from_slice(&block);
    header.extend_from_slice(b"APP\0");
    header.extend_from_slice(&i32le(4));
    // Segment: bit 0 address, bit 1 length, bit 3 name (relative to the segment).
    let segment_len = 2 + 3 * 4;
    header.extend_from_slice(&record(
        2,
        &[
            (0, i32le(0x0800_0000)),
            (1, i32le(segment.len() as i32)),
            (3, i32le(segment_len)),
        ],
    ));
    header.extend_from_slice(b"code\0");
    let mut data = vec![0u8; 0x410];
    data.extend_from_slice(&i32le(header.len() as i32));
    data.extend_from_slice(&header);
    data.extend_from_slice(segment);
    let crc = crc32_update(!0, &data);
    data.extend_from_slice(&crc.to_le_bytes());
    data
}

#[test]
fn cff_segments_are_located_and_classified() {
    let file = cff(&elf_x86_64());
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::MercedesCff);
    assert!(p.format.confidence < 1.0);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices[0].label.as_deref(), Some("APP code at 0x08000000"));
    assert_eq!(p.slices[0].offset, (file.len() - 4 - 64) as u64);
    assert!(p.notes.iter().any(|n| n.message == "Flash name: FLASH01"));
    let mut corrupt = file.clone();
    let at = corrupt.len() - 10;
    corrupt[at] ^= 1;
    assert!(!matches!(
        zrax::formats::detect_format(&corrupt),
        zrax::formats::DetectedFormat::Container { .. }
    ));
}

#[test]
fn automotive_containers_survive_truncation_and_mutation() {
    let fixtures = [
        odx(&intern_flashdata("FD.1", "BINARY", "7F454C46", false)),
        rwd_5a(&[0xa5; 32]),
        rwd_31(&[(0x0010, [1; 128])]),
        cuw(&[
            ("attach.att", b"[V]\r\n"),
            ("img", srec(&elf_x86_64()).as_bytes()),
        ]),
        cff(&elf_x86_64()),
    ];
    for file in &fixtures {
        for end in 0..file.len() {
            let _ = detect_payload(&file[..end], &ClassifierOptions::new());
        }
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
