//! FPGA bitstreams: Xilinx `.bit` files and headerless configuration data
//! in both word orders, Lattice iCE40 (with and without a comment block)
//! and ECP5 bitstreams, Intel Cyclone V `.rbf` and `.pof` files. Every
//! layout is recognized, reports an unknown ISA with no candidates, and
//! survives truncation and byte mutation; corrupt strong layouts are format
//! errors and Zynq boot images are not claimed.

use zrax::formats::checksum::{crc16_ibm3740, crc16_modbus};
use zrax::formats::{container, detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// UG470 Table 5-19: the sync word.
const SYNC_WORD: u32 = 0xaa99_5566;
/// UG470 "Bus Width Auto Detection" pattern.
const BUS_WIDTH_PATTERN: [u32; 2] = [0x0000_00bb, 0x1122_0044];
/// UG470: dummy (pad) word.
const DUMMY_WORD: u32 = 0xffff_ffff;
/// UG470 Table 5-20: Type 1 NOOP.
const NOOP: u32 = 0x2000_0000;
/// UG470 Table 5-23 register addresses.
const REGISTER_CRC: u32 = 0b00000;
const REGISTER_FAR: u32 = 0b00001;
const REGISTER_FDRI: u32 = 0b00010;
const REGISTER_CMD: u32 = 0b00100;
const REGISTER_IDCODE: u32 = 0b01100;
/// UG470 Table 1-1: XC7A35T with revision nibble 0.
const IDCODE_XC7A35T: u32 = 0x0362_d093;

/// Lattice comment block start and iCE40 preamble (IceStorm format.rst).
const COMMENT_START: [u8; 2] = [0xff, 0x00];
const ICE40_PREAMBLE: [u8; 4] = [0x7e, 0xaa, 0x99, 0x7e];

/// prjtrellis `devices.json`: LFE5U-25F.
const IDCODE_LFE5U_25F: u32 = 0x4111_1043;

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn is_bitstream_format(format: FileFormat) -> bool {
    matches!(
        format,
        FileFormat::XilinxBit | FileFormat::LatticeBitstream | FileFormat::IntelFpga
    )
}

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

/// UG470 Table 5-20 Type 1 write header: type `001`, opcode `10`, the
/// register address in bits 26-13, the word count in bits 10-0.
fn type_1_write(register: u32, words: u32) -> u32 {
    (0b001 << 29) | (0b10 << 27) | (register << 13) | words
}

/// UG470 Table 5-22 Type 2 write header: type `010`, opcode `10`, the word
/// count in bits 26-0.
fn type_2_write(words: u32) -> u32 {
    (0b010 << 29) | (0b10 << 27) | words
}

/// 7 series configuration words modelled on UG470 Table 5-19: eight dummy
/// words, the bus-width pattern, two dummy words, the sync word, a NOOP,
/// the IDCODE write, a CMD write, a FAR write, an FDRI write of eight
/// synthetic frame words through a Type 2 packet, a CRC write (synthetic
/// value), a DESYNC command and four NOOPs.
fn series_7_words(idcode: u32) -> Vec<u32> {
    let mut words = vec![DUMMY_WORD; 8];
    words.extend_from_slice(&BUS_WIDTH_PATTERN);
    words.extend_from_slice(&[DUMMY_WORD, DUMMY_WORD, SYNC_WORD, NOOP]);
    words.extend_from_slice(&[type_1_write(REGISTER_IDCODE, 1), idcode]);
    // CMD RCRC (reset CRC).
    words.extend_from_slice(&[type_1_write(REGISTER_CMD, 1), 0x0000_0007]);
    words.extend_from_slice(&[type_1_write(REGISTER_FAR, 1), 0]);
    words.extend_from_slice(&[type_1_write(REGISTER_FDRI, 0), type_2_write(8)]);
    words.extend((1..=8u32).map(|i| 0x0102_0304 * i));
    words.extend_from_slice(&[type_1_write(REGISTER_CRC, 1), 0x1234_5678]);
    // CMD DESYNC.
    words.extend_from_slice(&[type_1_write(REGISTER_CMD, 1), 0x0000_000d]);
    words.extend_from_slice(&[NOOP; 4]);
    words
}

fn big_endian_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn swapped_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// One `.bit` header field: key byte, 16-bit big-endian length (including
/// the NUL), the NUL-terminated string.
fn bit_field(key: u8, value: &str) -> Vec<u8> {
    let mut field = vec![key];
    field.extend_from_slice(&(value.len() as u16 + 1).to_be_bytes());
    field.extend_from_slice(value.as_bytes());
    field.push(0);
    field
}

/// A `.bit` file: the fixed 13-byte prefix (length 9, the nine skipped
/// bytes, length 1), keys `a` to `d`, then `e` with the 32-bit big-endian
/// length of the configuration data.
fn bit_file(configuration: &[u8]) -> Vec<u8> {
    let mut data = vec![
        0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01,
    ];
    data.extend(bit_field(b'a', "top;UserID=0XFFFFFFFF;Version=2023.2"));
    data.extend(bit_field(b'b', "7a35tcpg236"));
    data.extend(bit_field(b'c', "2026/10/12"));
    data.extend(bit_field(b'd', "12:00:00"));
    data.push(b'e');
    data.extend_from_slice(&(configuration.len() as u32).to_be_bytes());
    data.extend_from_slice(configuration);
    data
}

/// A Lattice comment block: `FF 00`, each string with its NUL, then the
/// iCE40 terminator `00 FF`.
fn ice40_comment(strings: &[&str]) -> Vec<u8> {
    let mut data = COMMENT_START.to_vec();
    for s in strings {
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    data.extend_from_slice(&[0x00, 0xff]);
    data
}

/// An iCE40 command stream as icepack writes it (IceStorm format.rst):
/// the preamble, oscillator range (`51 00`), CRC reset (`01 05`), warm
/// boot (`92 00 20`), then for each bank the width-1 (`62`), height
/// (`72`), offset (`82`), bank number (`11`) and CRAM write (`01 01`) with
/// `width * height / 8` synthetic bytes and `00 00`; then the CRC check
/// (`22`) with the CRC-16 that zeroes the running value, wakeup (`01 06`)
/// and one padding byte.
fn ice40_stream(width: u16, height: u16, banks: u8) -> Vec<u8> {
    let mut data = ICE40_PREAMBLE.to_vec();
    data.extend_from_slice(&[0x51, 0x00, 0x01, 0x05]);
    let covered = data.len();
    data.extend_from_slice(&[0x92, 0x00, 0x20]);
    let size = usize::from(width) * usize::from(height) / 8;
    for bank in 0..banks {
        data.push(0x62);
        data.extend_from_slice(&(width - 1).to_be_bytes());
        data.push(0x72);
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[0x82, 0x00, 0x00, 0x11, bank, 0x01, 0x01]);
        data.extend((0..size).map(|i| (i as u8) ^ bank));
        data.extend_from_slice(&[0x00, 0x00]);
    }
    data.push(0x22);
    let crc = crc16_ibm3740(&data[covered..]);
    data.extend_from_slice(&crc.to_be_bytes());
    data.extend_from_slice(&[0x01, 0x06, 0x00]);
    data
}

/// An iCE40 bitstream with a comment block.
fn ice40_with_comment(width: u16, height: u16, banks: u8) -> Vec<u8> {
    let mut data = ice40_comment(&["Generated by nextpnr", "Part: up5k"]);
    data.extend(ice40_stream(width, height, banks));
    data
}

/// An ECP5 `.bit` as prjtrellis writes it: optional `LSCC`, `FF 00`, the
/// strings with their NULs, `FF` (plus four `FF` after `LSCC`), the
/// preamble `FF FF <key> B3`, four dummy bytes, `LSC_RESET_CRC` (`3B` and
/// three zero bytes), `VERIFY_ID` (`E2`, three zero bytes, the IDCODE),
/// `LSC_PROG_CNTRL0` (`22`, three zero bytes, the control word),
/// `LSC_INIT_ADDRESS` (`46`, three zero bytes), then synthetic frame bytes.
fn ecp5_bit(lscc: bool, key: u8, idcode: u32) -> Vec<u8> {
    let mut data = if lscc { b"LSCC".to_vec() } else { Vec::new() };
    data.extend_from_slice(&COMMENT_START);
    for s in ["Part: LFE5U-25F-6CABGA256", "Generated by ecppack"] {
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    data.push(0xff);
    if lscc {
        data.extend_from_slice(&[0xff; 4]);
    }
    data.extend_from_slice(&[0xff, 0xff, key, 0xb3]);
    data.extend_from_slice(&[0xff; 4]);
    data.extend_from_slice(&[0x3b, 0, 0, 0]);
    data.extend_from_slice(&[0xe2, 0, 0, 0]);
    data.extend_from_slice(&idcode.to_be_bytes());
    data.extend_from_slice(&[0x22, 0, 0, 0, 0x40, 0, 0, 0]);
    data.extend_from_slice(&[0x46, 0, 0, 0]);
    data.extend((0..64u8).map(|i| i.wrapping_mul(37)));
    data
}

/// A Cyclone V `.rbf` option frame as mistral writes it: `FF` x 0x80,
/// `jjjj`, 0xA0 bytes of option RAM (synthetic bits), two zero bytes, the
/// little-endian CRC-16/MODBUS over 0x84..0x126, `FF` fill, then synthetic
/// frame bytes.
fn cyclone_v_rbf() -> Vec<u8> {
    let mut data = vec![0xff; 0x80];
    data.extend_from_slice(b"jjjj");
    let mut option_ram = vec![0u8; 0xa0 + 2];
    option_ram[0] = 0x80;
    option_ram[0x10] = 0x40;
    data.extend_from_slice(&option_ram);
    let crc = crc16_modbus(&option_ram);
    data.extend_from_slice(&crc.to_le_bytes());
    data.extend_from_slice(&[0xff; 0x40]);
    data.extend((0..128u8).map(|i| i.wrapping_mul(13)));
    data
}

/// One POF packet: 16-bit tag, 32-bit length (little-endian), payload.
fn pof_packet(tag: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = tag.to_le_bytes().to_vec();
    packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// A POF (openFPGALoader `pofParser.cpp`): `POF\0`, an unknown word, the
/// packet count, then tool (0x01), part (0x02), design (0x03),
/// configuration data (0x11: 12 unknown bytes, then synthetic data),
/// usercode (0x13, last four bytes) and the last packet (0x08, 16 bits).
fn pof() -> Vec<u8> {
    let mut configuration = vec![0u8; 12];
    configuration.extend((0..96u8).map(|i| i.wrapping_mul(29)));
    let packets = [
        pof_packet(0x01, b"Quartus Prime Version 23.1\0"),
        pof_packet(0x02, b"10M08SAE144C8G\0"),
        pof_packet(0x03, b"blinky\0"),
        pof_packet(0x11, &configuration),
        pof_packet(0x13, &[0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]),
        pof_packet(0x08, &[0xcd, 0xab]),
    ];
    let mut data = b"POF\0".to_vec();
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(packets.len() as u32).to_le_bytes());
    for packet in &packets {
        data.extend_from_slice(packet);
    }
    data
}

/// Every layout's fixture with its expected format and variant.
fn fixtures() -> Vec<(&'static str, Vec<u8>, FileFormat, &'static str)> {
    let words = series_7_words(IDCODE_XC7A35T);
    vec![
        (
            "bit",
            bit_file(&big_endian_words(&words)),
            FileFormat::XilinxBit,
            "Xilinx BIT file",
        ),
        (
            "raw",
            big_endian_words(&words),
            FileFormat::XilinxBit,
            "Xilinx raw bitstream",
        ),
        (
            "swapped",
            swapped_words(&words),
            FileFormat::XilinxBit,
            "Xilinx raw bitstream, byte-swapped words",
        ),
        (
            "ice40",
            ice40_with_comment(16, 4, 2),
            FileFormat::LatticeBitstream,
            "Lattice iCE40 bitstream",
        ),
        (
            "ice40-bare",
            ice40_stream(16, 4, 2),
            FileFormat::LatticeBitstream,
            "Lattice iCE40 bitstream without comment block",
        ),
        (
            "ecp5",
            ecp5_bit(true, 0xbd, IDCODE_LFE5U_25F),
            FileFormat::LatticeBitstream,
            "Lattice ECP5/MachXO/Nexus bitstream",
        ),
        (
            "rbf",
            cyclone_v_rbf(),
            FileFormat::IntelFpga,
            "Intel Cyclone V raw binary file",
        ),
        (
            "pof",
            pof(),
            FileFormat::IntelFpga,
            "Intel programmer object file",
        ),
    ]
}

#[test]
fn every_layout_is_recognized_as_a_bitstream_container() {
    for (name, data, format, variant) in fixtures() {
        assert!(
            matches!(
                detect_format(&data),
                DetectedFormat::Container {
                    kind: container::Kind::Bitstream(_)
                }
            ),
            "{name}: {:?}",
            detect_format(&data)
        );
        let p = classify(&data);
        assert_eq!(p.format.format, format, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some(variant), "{name}");
    }
}

#[test]
fn bitstreams_never_reach_the_code_model() {
    for (name, data, _, _) in fixtures() {
        let p = classify(&data);
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
        assert_eq!(p.primary.confidence, 0.0, "{name}");
        assert!(p.candidates.is_empty(), "{name}: {:?}", p.candidates);
        assert!(p.extensions.is_empty(), "{name}");
        assert!(
            has_note(
                &p,
                "FPGA configuration data, not CPU code; excluded from ISA analysis"
            ),
            "{name}"
        );
        assert!(!p.slices.is_empty(), "{name}");
        for slice in &p.slices {
            assert!(matches!(slice.isa, Isa::Unknown(_)), "{name}");
        }
    }
}

#[test]
fn weak_layouts_are_reported_with_reduced_format_confidence() {
    for (name, data, _, _) in fixtures() {
        let p = classify(&data);
        let weak = matches!(name, "raw" | "swapped" | "ice40-bare" | "rbf");
        assert_eq!(p.format.confidence < 1.0, weak, "{name}");
    }
}

#[test]
fn xilinx_bit_reports_header_fields_sync_word_and_device() {
    let configuration = big_endian_words(&series_7_words(IDCODE_XC7A35T | 0x1000_0000));
    let data = bit_file(&configuration);
    let data_offset = data.len() - configuration.len();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "Design name: top;UserID=0XFFFFFFFF;Version=2023.2"
    ));
    assert!(has_note(&p, "Part: 7a35tcpg236"));
    assert!(has_note(&p, "Date: 2026/10/12"));
    assert!(has_note(&p, "Time: 12:00:00"));
    assert!(has_note(
        &p,
        &format!(
            "Configuration data: {} B at 0x{data_offset:X}",
            configuration.len()
        )
    ));
    // Eight dummy words precede the pattern; two more precede the sync word.
    let pattern = data_offset + 32;
    let sync = pattern + 16;
    assert!(has_note(
        &p,
        &format!(
            "Bus-width auto-detection pattern 0x000000BB 0x11220044 at 0x{pattern:X}; sync word 0xAA995566 at 0x{sync:X}"
        )
    ));
    assert!(has_note(&p, "Device IDCODE 0x1362D093"));
    assert!(has_note(&p, "XC7A35T (UG470 Table 1-1)"));
    assert!(has_note(
        &p,
        "CRC register writes: 1; configuration CRC not verified"
    ));
    assert_eq!(
        metadata(&p, "bitstream_part").as_deref(),
        Some("7a35tcpg236")
    );
    assert_eq!(
        metadata(&p, "bitstream_sync_offset"),
        Some(sync.to_string())
    );
    assert_eq!(metadata(&p, "bitstream_device").as_deref(), Some("XC7A35T"));
    assert_eq!(
        metadata(&p, "bitstream_data_size"),
        Some(configuration.len().to_string())
    );
    let slice = &p.slices[0];
    assert_eq!(slice.label.as_deref(), Some("Configuration data"));
    assert_eq!(
        (slice.offset, slice.size),
        (data_offset as u64, configuration.len() as u64)
    );
}

#[test]
fn xilinx_raw_bitstreams_report_padding_and_word_order() {
    let words = series_7_words(IDCODE_XC7A35T);
    let raw = classify(&big_endian_words(&words));
    assert!(has_note(
        &raw,
        "Headerless configuration data; 32 B of 0xFF padding"
    ));
    assert!(has_note(&raw, "sync word 0xAA995566 at 0x30"));
    assert!(has_note(
        &raw,
        "Packet stream: 12 packets; 1 synchronized sequence"
    ));
    let swapped = classify(&swapped_words(&words));
    assert!(has_note(&swapped, "Every 32-bit word is byte-swapped"));
    assert!(has_note(&swapped, "XC7A35T"));
}

#[test]
fn raw_detection_needs_the_exact_synchronization_sequence() {
    // Without the bus-width pattern the words are not recognized.
    let mut words = series_7_words(IDCODE_XC7A35T);
    words.drain(8..10);
    let data = big_endian_words(&words);
    assert!(!matches!(
        detect_format(&data),
        DetectedFormat::Container {
            kind: container::Kind::Bitstream(_)
        }
    ));
    // An invalid packet header after the sync word is not recognized either.
    let mut words = series_7_words(IDCODE_XC7A35T);
    words[13] = 0x7000_0000;
    let data = big_endian_words(&words);
    assert!(!matches!(
        detect_format(&data),
        DetectedFormat::Container {
            kind: container::Kind::Bitstream(_)
        }
    ));
}

#[test]
fn zynq_boot_images_are_not_claimed() {
    // BOOT.BIN header: eight Arm `b .` vectors, the width detection word
    // 0xAA995566 at 0x20 and `XNLX` at 0x24 (UG585 boot header).
    let mut image = Vec::new();
    for _ in 0..8 {
        image.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
    }
    image.extend_from_slice(&SYNC_WORD.to_le_bytes());
    image.extend_from_slice(b"XNLX");
    image.resize(0x8a0, 0);
    let p = detect_payload(&image, &ClassifierOptions::new());
    if let Ok(p) = p {
        assert!(!is_bitstream_format(p.format.format), "{:?}", p.format);
    }
    // A raw bitstream prefix cannot carry the boot image identification:
    // with `XNLX` at 0x24 the words are not a headerless bitstream.
    let mut words = series_7_words(IDCODE_XC7A35T);
    words[9] = u32::from_be_bytes(*b"XNLX");
    let data = big_endian_words(&words);
    assert!(!matches!(
        detect_format(&data),
        DetectedFormat::Container {
            kind: container::Kind::Bitstream(_)
        }
    ));
}

#[test]
fn damaged_bit_files_are_format_errors() {
    let configuration = big_endian_words(&series_7_words(IDCODE_XC7A35T));
    let data = bit_file(&configuration);
    for end in 14..data.len() {
        let e = detect_payload(&data[..end], &ClassifierOptions::new()).unwrap_err();
        assert!(
            e.to_string().starts_with("FPGA bitstream parse error"),
            "{end}: {e}"
        );
    }
    // Configuration data without a sync word.
    let no_sync = bit_file(&big_endian_words(&[DUMMY_WORD; 16]));
    let e = detect_payload(&no_sync, &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string().contains("Missing sync word 0xAA995566"),
        "{e}"
    );
    // A duplicate key.
    let mut duplicate = vec![
        0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01,
    ];
    duplicate.extend(bit_field(b'a', "top"));
    duplicate.extend(bit_field(b'a', "again"));
    duplicate.extend_from_slice(&[b'e', 0, 0, 0, 0]);
    let e = detect_payload(&duplicate, &ClassifierOptions::new()).unwrap_err();
    assert!(
        e.to_string().contains("Duplicate BIT header key 'a'"),
        "{e}"
    );
}

#[test]
fn padding_after_a_bitstream_belongs_to_it() {
    let mut data = bit_file(&big_endian_words(&series_7_words(IDCODE_XC7A35T)));
    let end = data.len();
    data.extend_from_slice(&[0xff; 100]);
    let p = classify(&data);
    assert!(has_note(
        &p,
        &format!("100 B of erased-flash padding after the bitstream at 0x{end:X}")
    ));
    assert_eq!(p.slices.len(), 1);
    assert!(p.candidates.is_empty());
}

#[test]
fn data_after_a_bitstream_is_classified_on_its_own() {
    // The `.bit` header's length field ends the bitstream right before the
    // appended image.
    let bitstream = bit_file(&big_endian_words(&series_7_words(IDCODE_XC7A35T)));
    let mut data = bitstream.clone();
    data.extend(elf_x86_64());
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::XilinxBit);
    assert_eq!(p.slices.len(), 2);
    assert!(matches!(p.slices[0].isa, Isa::Unknown(_)));
    let trailing = &p.slices[1];
    assert_eq!(trailing.label.as_deref(), Some("Data after the bitstream"));
    assert_eq!(trailing.offset, bitstream.len() as u64);
    assert_eq!(trailing.isa, Isa::X86_64);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(
        &p,
        "Primary ISA selected from Data after the bitstream"
    ));
}

#[test]
fn ice40_trailing_data_starts_after_the_wakeup_command() {
    // icepack's padding byte after wakeup belongs to the trailing
    // component once other bytes follow it.
    let bitstream = ice40_with_comment(16, 4, 2);
    let mut data = bitstream.clone();
    data.extend_from_slice(&[0x13, 0x05, 0x10, 0x00]);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::LatticeBitstream);
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[1].offset, (bitstream.len() - 1) as u64);
    assert!(has_note(&p, "5 B after the bitstream at 0x"));
}

#[test]
fn ice40_reports_comments_crc_and_chip_type() {
    // icepack's 384 chip type: CRAM banks of 182 x 80 bits.
    let data = ice40_with_comment(182, 80, 4);
    let p = classify(&data);
    assert!(has_note(&p, "Comment block: 2 strings"));
    assert!(has_note(&p, "Comment: Generated by nextpnr"));
    assert!(has_note(&p, "CRC-16 verified at 1 check command"));
    assert!(has_note(
        &p,
        "CRAM geometry 182 x 80 bits; icepack chip type 384"
    ));
    assert!(has_note(&p, "Internal oscillator range: low"));
    assert!(has_note(&p, "warm boot on"));
    assert_eq!(
        metadata(&p, "bitstream_ice40_chip_type").as_deref(),
        Some("384")
    );
    assert_eq!(
        metadata(&p, "bitstream_comment_1").as_deref(),
        Some("Part: up5k")
    );
    let preamble = ice40_comment(&["Generated by nextpnr", "Part: up5k"]).len();
    assert_eq!(p.slices[0].offset, preamble as u64);
    assert_eq!(p.slices[0].size, (data.len() - 1 - preamble) as u64);
    assert!(has_note(
        &p,
        "1 B of erased-flash padding after the bitstream"
    ));
}

#[test]
fn ice40_crc_errors_are_format_errors_or_unrecognized() {
    let mut commented = ice40_with_comment(16, 4, 2);
    let data_byte = commented.len() - 12;
    commented[data_byte] ^= 0x01;
    let e = detect_payload(&commented, &ClassifierOptions::new()).unwrap_err();
    assert!(e.to_string().contains("Invalid iCE40 CRC-16"), "{e}");

    let mut bare = ice40_stream(16, 4, 2);
    let data_byte = bare.len() - 12;
    bare[data_byte] ^= 0x01;
    assert!(!matches!(
        detect_format(&bare),
        DetectedFormat::Container {
            kind: container::Kind::Bitstream(_)
        }
    ));
}

#[test]
fn ecp5_reports_lscc_comments_and_verify_id() {
    let data = ecp5_bit(true, 0xbd, IDCODE_LFE5U_25F);
    let p = classify(&data);
    assert!(has_note(&p, "LSCC prefix (Radiant .bit)"));
    assert!(has_note(&p, "Comment: Part: LFE5U-25F-6CABGA256"));
    assert!(has_note(&p, "Preamble 0xFFFFBDB3 at 0x"));
    assert!(has_note(&p, "Device IDCODE 0x41111043"));
    assert!(has_note(&p, "LFE5U-25F (prjtrellis devices.json)"));
    assert!(has_note(&p, "frame CRC-16 not verified"));
    assert_eq!(
        metadata(&p, "bitstream_device").as_deref(),
        Some("LFE5U-25F")
    );

    let plain = classify(&ecp5_bit(false, 0xbd, 0x0123_4567));
    assert!(has_note(&plain, "Device IDCODE 0x01234567"));
    assert!(has_note(&plain, "not listed in prjtrellis devices.json"));

    let encrypted = classify(&ecp5_bit(false, 0xbf, IDCODE_LFE5U_25F));
    assert!(has_note(
        &encrypted,
        "Encrypted bitstream: preamble key 0xBF"
    ));
    assert!(!has_note(&encrypted, "Device IDCODE"));
}

#[test]
fn cyclone_v_rbf_needs_its_option_frame_crc() {
    let data = cyclone_v_rbf();
    let p = classify(&data);
    assert!(has_note(&p, "CRC-16"));
    assert!(has_note(&p, "verified"));
    assert_eq!(p.slices[0].size, data.len() as u64);
    let mut corrupt = data.clone();
    corrupt[0x90] ^= 0x01;
    assert!(!matches!(
        detect_format(&corrupt),
        DetectedFormat::Container {
            kind: container::Kind::Bitstream(_)
        }
    ));
}

#[test]
fn pof_reports_strings_usercode_and_configuration_packet() {
    let data = pof();
    let p = classify(&data);
    assert!(has_note(&p, "Tool: Quartus Prime Version 23.1"));
    assert!(has_note(&p, "Part: 10M08SAE144C8G"));
    assert!(has_note(&p, "Design name: blinky"));
    assert!(has_note(&p, "Usercode: 0x12345678"));
    assert!(has_note(
        &p,
        "Last packet value 0xABCD; possibly a CRC, not verified"
    ));
    assert!(!has_note(&p, "Header packet count"));
    // The configuration packet follows the 12-byte header and three
    // packets with 6-byte headers.
    let offset = 12 + (6 + 27) + (6 + 15) + (6 + 7) + 6;
    assert_eq!((p.slices[0].offset, p.slices[0].size), (offset as u64, 108));
    let mut miscounted = data.clone();
    miscounted[8] = 9;
    assert!(has_note(
        &classify(&miscounted),
        "Header packet count 9 differs"
    ));
    let e = detect_payload(&data[..data.len() - 1], &ClassifierOptions::new()).unwrap_err();
    assert!(e.to_string().contains("Truncated POF packet 0x0008"), "{e}");
}

#[test]
fn truncated_bitstreams_never_claim_an_isa() {
    for (name, data, _, _) in fixtures() {
        for end in 0..data.len() {
            let Ok(p) = detect_payload(&data[..end], &ClassifierOptions::new()) else {
                continue;
            };
            if is_bitstream_format(p.format.format) {
                assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name} {end}");
                assert!(p.candidates.is_empty(), "{name} {end}");
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for (name, data, _, _) in fixtures() {
        for i in 0..data.len() {
            let mutations: [fn(u8) -> u8; 4] = [|b| b ^ 0xff, |_| 0x00, |_| 0xff, |b| b ^ 0x01];
            for mutate in mutations {
                let mut mutated = data.clone();
                mutated[i] = mutate(mutated[i]);
                let Ok(p) = detect_payload(&mutated, &ClassifierOptions::new()) else {
                    continue;
                };
                let split = p
                    .slices
                    .iter()
                    .any(|s| s.label.as_deref() == Some("Data after the bitstream"));
                if is_bitstream_format(p.format.format) && !split {
                    assert!(p.candidates.is_empty(), "{name} {i}");
                }
            }
        }
    }
}
