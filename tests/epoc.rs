//! Symbian E32 images: the V, J and original header formats; the CPU
//! identifier as the target for every `TCpu` value; the code and data parts
//! as load sections; compressed contents as an opaque component; the UID
//! checksum and the V header CRC; files without the `EPOC` signature (the
//! former UID-only fallback) not claimed; corrupted fields as errors;
//! truncation and mutation sweeps; and, when `IDA_INPUT_DIR` is set, the
//! `arm_*.epoc` samples among IDA Pro's test inputs.

#[path = "support/e32_image.rs"]
mod e32;

use e32::{Format, Image};
use zrax::formats::{self, epoc};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey,
};

/// Compiled little-endian 32-bit Arm code from the repository's testbins.
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/arm32_arm-unknown-linux-gnueabi_O0_call_nested.bin"
);

/// UID3 of the synthetic images.
const APP_UID3: u32 = 0xA000_1234;

fn arm_code() -> Vec<u8> {
    std::fs::read(ARM_CODE).expect("testbin is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn variant(p: &DetectionPayload) -> Option<&str> {
    p.primary.variant.as_ref().map(|v| v.name.as_str())
}

/// Whether the classifier reports `data` as an E32 image or fails as one.
fn is_claimed(data: &[u8]) -> bool {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => p.format.format == FileFormat::Epoc,
        Err(e) => e.to_string().starts_with("Symbian E32 image parse error"),
    }
}

/// An ARMv5 V image with ARM code, 16 B of data and 8 B of BSS.
fn arm_image_with_data() -> Image {
    let mut image = Image::arm_v5(APP_UID3, &arm_code());
    image.data = (0..16).collect();
    image.bss_size = 8;
    image
}

/// A V image whose contents are `stored` compressed bytes for a 512 B code
/// part.
fn compressed_image(compression: u32, stored: &[u8]) -> Image {
    let mut image = Image::arm_v5(APP_UID3, &[0; 512]);
    image.compression = compression;
    image.stored = Some(stored.to_vec());
    image
}

/// Deterministic bytes that no format recognizes.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn v_images_name_their_cpu_and_load_code_and_data_parts() {
    let image = arm_image_with_data();
    let bytes = image.build();
    let p = classify(&bytes);
    assert_eq!(p.format.format, FileFormat::Epoc);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(variant(&p), Some("ARMv5"));
    assert_eq!(p.slices.len(), 0);

    let code_size = image.code.len();
    let checksum = e32::uid_checksum(&bytes[..12]);
    let crc = e32::header_crc(&bytes[..e32::V_HEADER_SIZE]);
    let expected = [
        "Symbian E32 image, V header format (Symbian OS 8.1b and later); UID1 0x1000007A \
         (executable)"
            .to_string(),
        "CPU 0x2001 (ECpuArmV5): 32-bit little-endian ARM".to_string(),
        format!("UIDs 0x1000007A, 0x100039CE, 0xA0001234; UID checksum 0x{checksum:08X} matches"),
        format!("Header CRC-32 0x{crc:08X} matches (over 156 B)"),
        "Flags 0x12000028: EXE; EABI; EKA2 entry point; ELF-derived imports".to_string(),
        "Tools version 2.1 (build 549); module version 10.0".to_string(),
        format!(
            "Code part {code_size} B at 0x9C (text {code_size} B), linked at 0x00008000; entry \
             point offset 0x0; data part 16 B at 0x{:X}, linked at 0x00400000; 8 B of \
             uninitialised data",
            0x9C + code_size
        ),
        "Import, export and relocation sections are not parsed".to_string(),
    ];
    for note in &expected {
        assert!(has_note(&p, note), "{note} in {:?}", p.notes);
    }

    assert_eq!(metadata(&p, "epoc_header_format").as_deref(), Some("V"));
    assert_eq!(
        metadata(&p, "epoc_cpu").as_deref(),
        Some("0x2001 (ECpuArmV5)")
    );
    assert_eq!(metadata(&p, "epoc_uid3").as_deref(), Some("0xA0001234"));
    assert_eq!(metadata(&p, "epoc_compression").as_deref(), Some("none"));
    assert_eq!(
        metadata(&p, "epoc_secure_id").as_deref(),
        Some("0xA0001234")
    );
    assert_eq!(
        metadata(&p, "epoc_capabilities").as_deref(),
        Some("0x00000000000FFFFF")
    );
    assert_eq!(
        metadata(&p, "epoc_section_0"),
        Some(format!("file 0x9C; destination 0x8000; {code_size} B"))
    );
    assert_eq!(
        metadata(&p, "epoc_section_1"),
        Some(format!(
            "file 0x{:X}; destination 0x400000; 16 B",
            0x9C + code_size
        ))
    );
    assert_eq!(
        metadata(&p, "epoc_image_size"),
        Some(bytes.len().to_string())
    );
}

#[test]
fn sections_hold_the_stored_code_and_data_bytes() {
    let image = arm_image_with_data();
    let bytes = image.build();
    let c = epoc::parse_container(&bytes).expect("parses");
    assert_eq!(c.sections.len(), 2);
    let code = &c.sections[0];
    assert_eq!(
        (code.label.as_str(), code.address, code.offset),
        ("Code part", 0x8000, 0x9C)
    );
    assert_eq!(&*code.data, image.code.as_slice());
    let data = &c.sections[1];
    assert_eq!(
        (data.label.as_str(), data.address, data.offset),
        ("Data part", 0x40_0000, 0x9C + image.code.len())
    );
    assert_eq!(&*data.data, image.data.as_slice());
    assert_eq!(c.entry, Some(0x8000));
    assert!(c.code_sections);
}

#[test]
fn every_cpu_identifier_selects_its_target() {
    let named = [
        (
            e32::CPU_X86,
            Isa::X86,
            "x86",
            "CPU 0x1000 (ECpuX86): 32-bit x86",
        ),
        (
            e32::CPU_ARM_V4,
            Isa::Arm,
            "ARMv4",
            "CPU 0x2000 (ECpuArmV4): 32-bit little-endian ARM",
        ),
        (
            e32::CPU_ARM_V5,
            Isa::Arm,
            "ARMv5",
            "CPU 0x2001 (ECpuArmV5): 32-bit little-endian ARM",
        ),
        (
            e32::CPU_ARM_V6,
            Isa::Arm,
            "ARMv6",
            "CPU 0x2002 (ECpuArmV6): 32-bit little-endian ARM",
        ),
        (
            e32::CPU_MCORE,
            Isa::Csky,
            "M*CORE",
            "CPU 0x4000 (ECpuMCore): Motorola M*CORE, reported as C-SKY",
        ),
    ];
    for format in [Format::V, Format::J, Format::Original] {
        for (cpu, isa, name, note) in named {
            let mut image = Image::arm_v5(APP_UID3, &[0; 64]);
            image.format = format;
            image.cpu = cpu;
            // Non-ARM images carry no ABI or entry point type bits, and
            // without header format bits 0x08 is the old J flag.
            image.flags = if isa == Isa::Arm && format != Format::Original {
                e32::ARM_EKA2_FLAGS
            } else {
                0
            };
            let p = classify(&image.build());
            assert_eq!(p.format.format, FileFormat::Epoc);
            assert_eq!(
                (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
                (isa, 32, Endianness::Little),
                "{format:?} 0x{cpu:X}"
            );
            assert_eq!(p.primary.source, ClassificationSource::FileFormat);
            assert_eq!(variant(&p), Some(name));
            assert!(has_note(&p, note), "{note} in {:?}", p.notes);
        }
    }
}

#[test]
fn unknown_cpu_identifiers_leave_the_isa_to_the_code() {
    for (cpu, note) in [
        (
            e32::CPU_UNKNOWN,
            "CPU 0x0 (ECpuUnknown): the header names no ISA",
        ),
        (
            0x2003,
            "CPU 0x2003 is not a TCpu value: the header names no ISA",
        ),
        (
            0x3000,
            "CPU 0x3000 is not a TCpu value: the header names no ISA",
        ),
    ] {
        // Without code the ISA stays unknown.
        let mut image = Image::arm_v5(APP_UID3, &[0; 64]);
        image.cpu = cpu;
        let p = classify(&image.build());
        assert_eq!(p.format.format, FileFormat::Epoc);
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "0x{cpu:X}");
        assert_eq!(p.primary.confidence, 0.0);
        assert_eq!(variant(&p), Some("Symbian E32 image"));
        assert!(has_note(&p, note), "{note} in {:?}", p.notes);
        assert_eq!(
            metadata(&p, "epoc_cpu"),
            Some(if cpu == 0 {
                "0x0 (ECpuUnknown)".to_string()
            } else {
                format!("0x{cpu:X} (not a TCpu value)")
            })
        );

        // With ARM code the code model answers from the code part.
        let mut image = Image::arm_v5(APP_UID3, &arm_code());
        image.cpu = cpu;
        let p = classify(&image.build());
        assert_eq!(p.format.format, FileFormat::Epoc);
        assert_eq!(p.primary.isa, Isa::Arm, "0x{cpu:X}");
        assert_ne!(p.primary.source, ClassificationSource::FileFormat);
        assert!(has_note(
            &p,
            "ISA identified from the code, not the container"
        ));
    }
}

#[test]
fn original_and_j_headers_read_the_cpu_word_at_0x14() {
    let mut image = Image::original(e32::CPU_ARM_V4, &arm_code());
    image.data = vec![1, 0, 0, 0, 2, 0, 0, 0];
    let bytes = image.build();
    let p = classify(&bytes);
    assert_eq!(
        (p.format.format, p.primary.isa, variant(&p)),
        (FileFormat::Epoc, Isa::Arm, Some("ARMv4"))
    );
    let code_size = image.code.len();
    for note in [
        "Symbian E32 image, original header format (EKA1; no compression); UID1 0x1000007A \
         (executable)"
            .to_string(),
        format!(
            "The original header has no header CRC; code checksum 0x{:08X} and data checksum \
             0x00000003 not verified",
            e32::word(&bytes, 0x18)
        ),
        "Flags 0x00000000: EXE; GCC98r2 ABI; EKA1 entry point; PE-derived imports".to_string(),
        "Tools version 2.1 (build 549)".to_string(),
        format!(
            "Code part {code_size} B at 0x7C (text {code_size} B), linked at 0x10000000; entry \
             point offset 0x0; data part 8 B at 0x{:X}, linked at 0x00000000",
            0x7C + code_size
        ),
    ] {
        assert!(has_note(&p, &note), "{note} in {:?}", p.notes);
    }
    assert_eq!(
        metadata(&p, "epoc_header_format").as_deref(),
        Some("original")
    );
    assert_eq!(metadata(&p, "epoc_secure_id"), None);

    // Tools before 2.00 mark J images with the old J flag and the EABI with
    // the old ELF flag, without header format bits.
    let mut image = Image::original(e32::CPU_ARM_V5, &arm_code());
    image.flags = e32::FLAG_OLD_J | 0x10 | e32::FLAG_DLL;
    image.uid1 = e32::DLL_UID;
    let p = classify(&image.build());
    assert_eq!(metadata(&p, "epoc_header_format").as_deref(), Some("J"));
    assert!(has_note(
        &p,
        "Flags 0x00000019: DLL; EABI; EKA2 entry point; ELF-derived imports"
    ));
    assert!(has_note(&p, "The J header has no header CRC"));
    assert!(has_note(&p, "UID1 0x10000079 (dynamic library)"));
}

#[test]
fn compressed_contents_are_opaque_and_keep_the_header_cpu() {
    let stored = noise(100);
    for (compression, name, method) in [
        (
            e32::COMPRESSION_DEFLATE,
            "Symbian deflate (0x101F7AFC)",
            "a Symbian coding that no codec of this classifier decodes",
        ),
        (
            e32::COMPRESSION_BYTE_PAIR,
            "byte-pair (0x102822AA)",
            "a Symbian coding that no codec of this classifier decodes",
        ),
        (
            0x1234_5678,
            "unknown compression 0x12345678",
            "an unknown method the loader does not support",
        ),
    ] {
        let p = classify(&compressed_image(compression, &stored).build());
        assert_eq!(
            (p.format.format, p.primary.isa, p.primary.endianness),
            (FileFormat::Epoc, Isa::Arm, Endianness::Little)
        );
        assert_eq!(p.slices.len(), 1);
        let slice = &p.slices[0];
        assert_eq!(slice.label.as_deref(), Some("Compressed contents"));
        assert_eq!((slice.offset, slice.size), (0x9C, 100));
        assert!(matches!(slice.isa, Isa::Unknown(_)));
        let note = format!(
            "Contents compressed with {name}: 100 B at 0x9C, 512 B uncompressed after the \
             header; code part 512 B at 0x9C in the uncompressed image; {method}, so the \
             contents are opaque and the code is not analyzed"
        );
        assert!(has_note(&p, &note), "{note} in {:?}", p.notes);
        assert!(has_note(
            &p,
            "Compressed contents: opaque; payload ISA analysis skipped"
        ));
        assert_eq!(metadata(&p, "epoc_compression").as_deref(), Some(name));
        assert_eq!(
            metadata(&p, "epoc_uncompressed_size").as_deref(),
            Some("512")
        );
    }

    // A compressed J image stores 0x80 header bytes: the 0x7C shared ones
    // and the uncompressed size.
    let mut image = compressed_image(e32::COMPRESSION_DEFLATE, &stored);
    image.format = Format::J;
    image.cpu = e32::CPU_X86;
    image.flags = 0;
    let p = classify(&image.build());
    assert_eq!(
        (p.format.format, p.primary.isa, variant(&p)),
        (FileFormat::Epoc, Isa::X86, Some("x86"))
    );
    let slice = &p.slices[0];
    assert_eq!((slice.offset, slice.size), (0x80, 100));
    assert!(has_note(
        &p,
        "Contents compressed with Symbian deflate (0x101F7AFC): 100 B at 0x80, code part 512 B, \
         data part 0 B in the uncompressed image"
    ));
}

#[test]
fn uid_checksum_matches_an_independent_value_and_mismatches_are_noted() {
    // UIDs 0x1000007A, 0x100039CE, 0xA0000180 and their checksum, from
    // IDA's `arm_abook_app.epoc` header.
    let uids = [
        0x7A, 0x00, 0x00, 0x10, 0xCE, 0x39, 0x00, 0x10, 0x80, 0x01, 0x00, 0xA0,
    ];
    assert_eq!(e32::uid_checksum(&uids), 0x1E7C_C9F8);
    let mut image = Image::arm_v5(0xA000_0180, &arm_code());
    image.uid2 = 0x1000_39CE;
    let mut bytes = image.build();
    assert_eq!(e32::word(&bytes, 0x0C), 0x1E7C_C9F8);
    assert!(has_note(
        &classify(&bytes),
        "UID checksum 0x1E7CC9F8 matches"
    ));

    // A damaged checksum is reported; the header is still read.
    e32::set_word(&mut bytes, 0x0C, 0x1E7C_C9F9);
    let crc = e32::header_crc(&bytes[..e32::V_HEADER_SIZE]);
    e32::set_word(&mut bytes, e32::HEADER_CRC, crc);
    let p = classify(&bytes);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "UID checksum 0x1E7CC9F9 does not match the computed 0x1E7CC9F8; the loader rejects the \
         image"
    ));
}

#[test]
fn header_crc_mismatches_are_noted() {
    let mut bytes = Image::arm_v5(APP_UID3, &arm_code()).build();
    let crc = e32::word(&bytes, e32::HEADER_CRC);
    // The minimum heap size at 0x38 is covered by the CRC.
    bytes[0x38] ^= 0x01;
    let computed = e32::header_crc(&bytes[..e32::V_HEADER_SIZE]);
    let p = classify(&bytes);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        &format!(
            "Header CRC-32 0x{crc:08X} does not match the computed 0x{computed:08X} (over 156 \
             B); the loader rejects the image"
        )
    ));
}

#[test]
fn v_flags_name_the_floating_point_and_uid1_consistency() {
    let mut image = Image::arm_v5(APP_UID3, &arm_code());
    image.flags |= e32::FLAG_HW_FLOAT_VFPV2;
    image.uid1 = e32::DLL_UID;
    let p = classify(&image.build());
    assert!(has_note(
        &p,
        "Flags 0x12100028: EXE; EABI; EKA2 entry point; ELF-derived imports; VFPv2 floating point"
    ));
    assert!(has_note(
        &p,
        "UID1 0x10000079 does not match the KImageDll flag (EXE); the loader rejects the image"
    ));
}

#[test]
fn files_without_the_signature_are_not_e32_images() {
    // The former fallback claimed UID2 0x10003A12 with a 0x100xxxxx UID3
    // (the header of pre-v9 SIS packages) ...
    let mut sis = Vec::new();
    for word in [0x1000_0D2Eu32, 0x1000_3A12, 0x1000_0419] {
        sis.extend_from_slice(&word.to_le_bytes());
    }
    let checksum = e32::uid_checksum(&sis);
    sis.extend_from_slice(&checksum.to_le_bytes());
    sis.extend_from_slice(&noise(0x100));
    // ... and a known UID1 with 0x100xxxxx UIDs (a ROM image header).
    let mut rom = Vec::new();
    for word in [e32::DLL_UID, 0x1000_006C, 0x1000_0FF9] {
        rom.extend_from_slice(&word.to_le_bytes());
    }
    let checksum = e32::uid_checksum(&rom);
    rom.extend_from_slice(&checksum.to_le_bytes());
    rom.extend_from_slice(&noise(0x100));
    // An E32 image whose signature is overwritten.
    let mut unsigned = Image::arm_v5(APP_UID3, &arm_code()).build();
    unsigned[e32::SIGNATURE..e32::SIGNATURE + 4].copy_from_slice(b"EPOD");
    for data in [sis, rom, unsigned] {
        assert!(!epoc::detect(&data));
        assert!(!matches!(
            formats::detect_format(&data),
            formats::DetectedFormat::Epoc
        ));
        assert!(!is_claimed(&data));
        assert_eq!(
            epoc::parse_container(&data)
                .map(|_| ())
                .unwrap_err()
                .to_string(),
            "Symbian E32 image parse error: Missing E32 signature EPOC at 0x10"
        );
    }
}

#[test]
fn the_signature_is_strong_so_damaged_images_are_errors() {
    let mut damaged = noise(0x40);
    damaged[0x10..0x14].copy_from_slice(b"EPOC");
    assert!(epoc::detect(&damaged));
    assert_eq!(
        error_text(&damaged),
        "Symbian E32 image parse error: Truncated E32 image header: 64 B of 124 B"
    );
    assert!(!epoc::detect(&damaged[..0x13]));
}

/// Build `image`, apply `patch` to its bytes, reseal its checksums and
/// return the classification error.
fn error_after(image: &Image, patch: impl Fn(&mut Vec<u8>)) -> String {
    let mut bytes = image.build();
    patch(&mut bytes);
    e32::seal(&mut bytes);
    error_text(&bytes)
}

/// A change to an image's bytes.
type Patch = Box<dyn Fn(&mut Vec<u8>)>;

/// A change to an image's bytes and the error it causes.
struct Corruption {
    patch: Patch,
    message: String,
}

fn corruption(patch: impl Fn(&mut Vec<u8>) + 'static, message: impl Into<String>) -> Corruption {
    Corruption {
        patch: Box::new(patch),
        message: message.into(),
    }
}

#[test]
fn corrupted_fields_are_errors() {
    let image = arm_image_with_data();
    let code_size = image.code.len();
    let data_offset = 0x9C + code_size;
    let file_size = data_offset + 16;
    let cases = [
        corruption(
            |b| e32::set_word(b, e32::FLAGS, 0x1300_002A),
            "Unsupported E32 header format 0x03000000 in iFlags 0x1300002A at 0x2C",
        ),
        corruption(
            |b| b.truncate(0x90),
            "Truncated E32 V header: 144 B of 156 B",
        ),
        corruption(
            |b| e32::set_word(b, e32::CODE_OFFSET, 0x98),
            "Invalid E32 header size 0x98 (iCodeOffset at 0x64): less than the 156 B V header",
        ),
        corruption(
            |b| b[e32::EXPORT_DESC_SIZE] = 4,
            "Invalid E32 export description: 4 B end the header at 0xA0, but iCodeOffset is 0x9C",
        ),
        corruption(
            move |b| e32::set_word(b, e32::TEXT_SIZE, size(code_size + 4)),
            format!(
                "Invalid E32 text size {} B: exceeds the {code_size} B code part",
                code_size + 4
            ),
        ),
        corruption(
            move |b| e32::set_word(b, e32::ENTRY_POINT, size(code_size)),
            format!(
                "Invalid E32 entry point offset 0x{code_size:X}: outside the {code_size} B code \
                 part"
            ),
        ),
        corruption(
            move |b| e32::set_word(b, e32::CODE_SIZE, size(file_size)),
            format!("Truncated E32 code part at 0x9C ({file_size} B) in the {file_size} B file"),
        ),
        corruption(
            |b| e32::set_word(b, e32::DATA_OFFSET, 0),
            "Invalid E32 data part: 16 B without a data offset",
        ),
        corruption(
            move |b| e32::set_word(b, e32::DATA_OFFSET, size(data_offset - 4)),
            format!(
                "Invalid E32 data offset 0x{:X}: inside the code part, which ends at \
                 0x{data_offset:X}",
                data_offset - 4
            ),
        ),
        corruption(
            |b| e32::set_word(b, e32::DATA_SIZE, 17),
            format!(
                "Truncated E32 data part at 0x{data_offset:X} (17 B) in the {file_size} B file"
            ),
        ),
    ];
    for case in cases {
        assert_eq!(
            error_after(&image, case.patch),
            format!("Symbian E32 image parse error: {}", case.message)
        );
    }

    let original = Image::original(e32::CPU_ARM_V4, &arm_code());
    assert_eq!(
        error_after(&original, |b| e32::set_word(b, e32::CODE_OFFSET, 0x70)),
        "Symbian E32 image parse error: Invalid E32 header size 0x70 (iCodeOffset at 0x64): less \
         than the 124 B original header"
    );

    // A compressed V image's parts must fit the uncompressed image.
    let compressed = compressed_image(e32::COMPRESSION_DEFLATE, &noise(64));
    assert_eq!(
        error_after(&compressed, |b| e32::set_word(
            b,
            e32::UNCOMPRESSED_SIZE,
            256
        )),
        "Symbian E32 image parse error: Truncated E32 code part at 0x9C (512 B) in the 412 B \
         uncompressed image"
    );
    // A header that ends past the file: the export description extends it
    // to 0x400 B.
    assert_eq!(
        error_after(&compressed, |b| {
            e32::set_word(b, e32::CODE_OFFSET, 0x400);
            b[e32::EXPORT_DESC_SIZE..e32::EXPORT_DESC_SIZE + 2]
                .copy_from_slice(&869u16.to_le_bytes());
        }),
        format!(
            "Symbian E32 image parse error: Truncated E32 image header: 1024 B in the {} B file",
            0x9C + 64
        )
    );
}

fn size(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}

#[test]
fn every_truncation_of_an_uncompressed_image_is_an_error() {
    let mut original = Image::original(e32::CPU_ARM_V4, &arm_code()[..256]);
    original.data = vec![7; 12];
    let fixtures = [arm_image_with_data().build(), original.build()];
    for bytes in fixtures {
        assert!(epoc::parse_container(&bytes).is_ok());
        for end in 0..bytes.len() {
            let prefix = &bytes[..end];
            assert!(epoc::parse_container(prefix).is_err(), "prefix of {end} B");
            if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                assert_ne!(p.format.format, FileFormat::Epoc, "prefix of {end} B");
            }
        }
    }
}

#[test]
fn compressed_images_need_their_whole_stored_header() {
    // The stored compressed bytes carry no length the parser can check, so
    // only prefixes that cut the header are errors.
    let mut j = compressed_image(e32::COMPRESSION_DEFLATE, &noise(32));
    j.format = Format::J;
    for (bytes, header) in [
        (
            compressed_image(e32::COMPRESSION_BYTE_PAIR, &noise(32)).build(),
            e32::V_HEADER_SIZE,
        ),
        (j.build(), e32::COMP_HEADER_SIZE),
    ] {
        for end in 0..header {
            assert!(epoc::parse_container(&bytes[..end]).is_err(), "{end}");
        }
        assert!(epoc::parse_container(&bytes[..header]).is_ok());
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mut original = Image::original(e32::CPU_ARM_V4, &arm_code()[..64]);
    original.data = vec![7; 8];
    let mut j = compressed_image(e32::COMPRESSION_DEFLATE, &noise(16));
    j.format = Format::J;
    let mut v = Image::arm_v5(APP_UID3, &arm_code()[..64]);
    v.data = vec![1; 8];
    let fixtures = [
        v.build(),
        original.build(),
        j.build(),
        compressed_image(e32::COMPRESSION_BYTE_PAIR, &noise(16)).build(),
    ];
    for bytes in fixtures {
        for at in 0..bytes.len() {
            let mut values = vec![0x00, 0xFF];
            values.extend((0..8).map(|bit| bytes[at] ^ (1 << bit)));
            for value in values {
                let mut mutated = bytes.clone();
                mutated[at] = value;
                if let Ok(c) = epoc::parse_container(&mutated) {
                    for section in &c.sections {
                        assert!(section.offset + section.stored_size <= mutated.len());
                    }
                }
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

/// IDA Pro's `arm_*.epoc` test inputs (`IDA_INPUT_DIR`), read in place and
/// never copied: the E32 images classify from their headers, the damaged
/// ones fail with bounded errors, and the ROM images and pre-v9 SIS packages
/// without the signature are not E32 images. Skipped without the variable.
#[test]
fn ida_input_e32_images() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(std::path::PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let read = |name: &str| std::fs::read(dir.join(name)).expect("IDA input is present");

    // Name, header format, CPU variant, compression.
    let images = [
        (
            "arm_abook_app.epoc",
            "V",
            "ARMv5",
            "Symbian deflate (0x101F7AFC)",
        ),
        ("arm_app.epoc", "original", "ARMv4", "none"),
        ("arm_app_caribe.epoc", "original", "ARMv4", "none"),
        ("arm_app_qfileman1.epoc", "original", "ARMv4", "none"),
        ("arm_bytepair.epoc", "V", "ARMv4", "byte-pair (0x102822AA)"),
        (
            "arm_calcsoft_app.epoc",
            "J",
            "ARMv4",
            "Symbian deflate (0x101F7AFC)",
        ),
        ("arm_commwarrior_infected.epoc", "original", "ARMv4", "none"),
        (
            "arm_filelist_app.epoc",
            "V",
            "ARMv5",
            "Symbian deflate (0x101F7AFC)",
        ),
        ("arm_installserver.epoc", "V", "ARMv4", "none"),
        (
            "arm_puttyengine.epoc",
            "V",
            "ARMv5",
            "Symbian deflate (0x101F7AFC)",
        ),
        (
            "arm_trkdriver_ldd.epoc",
            "V",
            "ARMv4",
            "Symbian deflate (0x101F7AFC)",
        ),
        (
            "arm_voicerecorder.epoc",
            "V",
            "ARMv5",
            "byte-pair (0x102822AA)",
        ),
    ];
    for (name, format, cpu, compression) in images {
        let p = classify(&read(name));
        assert_eq!(p.format.format, FileFormat::Epoc, "{name}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (Isa::Arm, 32, Endianness::Little),
            "{name}"
        );
        assert_eq!(variant(&p), Some(cpu), "{name}");
        assert_eq!(
            metadata(&p, "epoc_header_format").as_deref(),
            Some(format),
            "{name}"
        );
        assert_eq!(
            metadata(&p, "epoc_compression").as_deref(),
            Some(compression),
            "{name}"
        );
        assert!(
            p.notes
                .iter()
                .any(|n| n.message.contains("UID checksum") && n.message.ends_with(" matches")),
            "{name}"
        );
        if format == "V" {
            assert!(has_note(&p, "Header CRC-32 0x"), "{name}");
            assert!(!has_note(&p, "does not match"), "{name}: {:?}", p.notes);
        }
    }

    // Damaged images with the signature are errors: header sizes beyond
    // the file or not ending with the export description (the last two
    // also have wrong header CRCs, `arm_bad_huffman` a wrong UID checksum),
    // and a sample cut short inside its code part.
    let damaged = [
        (
            "arm_bad_export_cnt.epoc",
            "Truncated E32 image header: 2004318071 B in the 190 B file",
        ),
        (
            "arm_bad_huffman.epoc",
            "Invalid E32 export description: 738 B end the header at 0x380, but iCodeOffset is \
             0xA3D4AC56",
        ),
        (
            "arm_compressed_bad.epoc",
            "Invalid E32 export description: 0 B end the header at 0x9C, but iCodeOffset is 0x118",
        ),
        (
            "arm_worm_comwar_b.epoc",
            "Truncated E32 code part at 0x7C (25548 B) in the 23320 B file",
        ),
    ];
    for (name, message) in damaged {
        assert_eq!(
            error_text(&read(name)),
            format!("Symbian E32 image parse error: {message}"),
            "{name}"
        );
    }

    // ROM image headers and pre-v9 SIS packages carry UIDs but no
    // signature.
    let unsigned = [
        "arm_bad_filename_ptr.epoc",
        "arm_corrupted_bad.epoc",
        "arm_ekern_eka2.epoc",
        "arm_euser_eka2.epoc",
        "arm_faxmodem.epoc",
        "arm_huge_codeseg.epoc",
        "arm_rom.epoc",
        "arm_rom2.epoc",
        "arm_rom3.epoc",
        "arm_rom_sysagt.epoc",
        "arm_sis.epoc",
        "arm_sis_ptr0_bad.epoc",
        "arm_uncomperr_sis6.epoc",
    ];
    for name in unsigned {
        let bytes = read(name);
        assert!(!epoc::detect(&bytes), "{name}");
        assert!(!is_claimed(&bytes), "{name}");
    }
}
