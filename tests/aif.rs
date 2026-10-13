//! ARM Image Format: executable, non-executable and extended AIF in both
//! byte orders; the read-only and read-write areas as ARM load sections and
//! the debugging data as an opaque component; compressed images (opaque
//! compressed data, analyzed decompression code) and self-relocating images;
//! undocumented header words, sizes that are not word multiples, areas and
//! branch targets outside the file, region chains and trailing data as
//! errors; detection; truncation and mutation sweeps; and, when
//! `IDA_INPUT_DIR` is set, the AIF samples among IDA Pro's test inputs.

use zrax::formats::aif::{self, Layout};
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa, MetadataKey,
    NoteLevel,
};

/// ARMv4T code in ARM state, little- and big-endian
/// (`tests/fixtures/aif/README.md`).
const ARM_LE: &[u8] = include_bytes!("fixtures/aif/arm-le.text.bin");
const ARM_BE: &[u8] = include_bytes!("fixtures/aif/arm-be.text.bin");

/// "a 128-byte header" (ARM DUI 0041C, section 13.1).
const HEADER_SIZE: usize = 0x80;
/// `MOV r0, r0`, the NOP of Table 13-1.
const NOP: u32 = 0xE1A0_0000;
/// `BLNV 0`, the NOP of the 1989 Acorn memo.
const BLNV_0: u32 = 0xFB00_0000;
/// `SWI 0x11`, armlink's default program exit instruction.
const SWI_EXIT: u32 = 0xEF00_0011;
/// `B .`, the branch-to-self alternative.
const BRANCH_TO_SELF: u32 = 0xEAFF_FFFE;
/// The zero-init BL at 0x8 lands on the debug initialization NOP at 0x40,
/// which precedes the zero-init code.
const ZERO_INIT_CODE: u32 = 0x40;
/// Image debug type 3: low-level and source-level data.
const DEBUG_BOTH: u32 = 3;
/// Address mode: linked for 32-bit ARM mode; bit 8 for a separate data base.
const ADDRESS_MODE_32: u32 = 32;
const SEPARATE_DATA_BASE: u32 = 0x100;
/// The extended AIF region header: next, load address, size, 32-byte name.
const REGION_HEADER_SIZE: usize = 44;
const REGION_NAME_SIZE: usize = 32;

/// One extended AIF load region.
struct Region {
    load_address: u32,
    name: &'static str,
    data: Vec<u8>,
}

/// A compressed image's stored parts.
struct Compressed {
    /// The compressed image and its decompression data.
    data: Vec<u8>,
    /// The decompression code that word 0 branches to.
    code: Vec<u8>,
}

/// A synthetic AIF image, written by [`build`] in the layout of ARM DUI
/// 0041C section 13.3.1 and Table 13-1.
struct Image {
    big_endian: bool,
    executable: bool,
    /// The read-only area after the header (executable AIF counts the header
    /// in its read-only size; non-executable AIF does not).
    code: Vec<u8>,
    read_write: Vec<u8>,
    debug: Vec<u8>,
    debug_type: u32,
    zero_init_size: u32,
    image_base: u32,
    work_space: u32,
    address_mode: u32,
    data_base: u32,
    /// Entry point as an offset into `code`.
    entry: u32,
    exit: u32,
    /// Extended AIF regions, after the debugging data.
    regions: Vec<Region>,
    /// Self-relocation code and relocation list, after the image.
    relocation: Option<Vec<u8>>,
    /// Stored instead of the areas when set.
    compressed: Option<Compressed>,
    /// Bytes after everything else.
    trailer: Vec<u8>,
}

/// An executable image of `code` with a 64-byte read-write area, 32 bytes
/// of debugging data and a 256-byte zero-initialized area, linked at
/// 0x8000 for 32-bit mode.
fn executable(code: &[u8], big_endian: bool) -> Image {
    Image {
        big_endian,
        executable: true,
        code: code.to_vec(),
        read_write: (0u8..64).collect(),
        debug: vec![0xD0; 32],
        debug_type: DEBUG_BOTH,
        zero_init_size: 0x100,
        image_base: 0x8000,
        work_space: 0,
        address_mode: ADDRESS_MODE_32,
        data_base: 0,
        entry: 0,
        exit: SWI_EXIT,
        regions: Vec::new(),
        relocation: None,
        compressed: None,
        trailer: Vec::new(),
    }
}

/// The same areas as a non-executable image loaded at 0x0001_0000 and
/// entered 0x10 bytes into its code.
fn non_executable(code: &[u8], big_endian: bool) -> Image {
    Image {
        executable: false,
        image_base: 0x0001_0000,
        entry: 0x10,
        ..executable(code, big_endian)
    }
}

/// A non-executable image without debugging data whose root image is
/// followed by two further load regions.
fn extended(code: &[u8], big_endian: bool) -> Image {
    Image {
        debug: Vec::new(),
        debug_type: 0,
        regions: vec![
            Region {
                load_address: 0x0010_0000,
                name: "FLASH",
                data: vec![0x11; 16],
            },
            Region {
                load_address: 0x0020_0000,
                name: "",
                data: vec![0x22; 8],
            },
        ],
        ..non_executable(code, big_endian)
    }
}

/// `BL` at `from` to `to`: condition AL, signed word offset from `from + 8`.
fn bl(from: usize, to: usize) -> u32 {
    let words = (to as i64 - from as i64 - 8) / 4;
    0xEB00_0000 | (words as u32 & 0x00FF_FFFF)
}

fn put_word(bytes: &mut Vec<u8>, value: u32, big_endian: bool) {
    if big_endian {
        bytes.extend_from_slice(&value.to_be_bytes());
    } else {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

fn u32_of(n: usize) -> u32 {
    u32::try_from(n).expect("test sizes fit in a word")
}

/// Offsets of the parts [`build`] writes.
struct Built {
    bytes: Vec<u8>,
    read_write: usize,
    debug: usize,
    /// First region header, or the self-relocation code, or the end.
    after_debug: usize,
}

/// Write `image`: the header words (0x00 decompress, 0x04 self-relocation,
/// 0x08 zero-init, 0x0C entry, 0x10 exit, 0x14 read-only size, 0x18
/// read-write size, 0x1C debug size, 0x20 zero-init size, 0x24 debug type,
/// 0x28 image base, 0x2C work space, 0x30 address mode, 0x34 data base,
/// 0x38 first region, 0x3C reserved, 0x40 debug init NOP, then NOPs where
/// the zero-init code would be), then the areas, regions, relocation code
/// and trailer.
fn build(image: &Image) -> Built {
    let code_at = HEADER_SIZE;
    let read_write = code_at + image.code.len();
    let debug = read_write + image.read_write.len();
    let after_debug = debug + image.debug.len();
    let region_sizes: usize = image
        .regions
        .iter()
        .map(|r| REGION_HEADER_SIZE + r.data.len())
        .sum();
    let relocation_at = after_debug + region_sizes;
    let read_only_size = if image.executable {
        HEADER_SIZE + image.code.len()
    } else {
        image.code.len()
    };
    let decompress = match &image.compressed {
        Some(compressed) => bl(0x00, HEADER_SIZE + compressed.data.len()),
        None => NOP,
    };
    let self_reloc = if image.relocation.is_some() {
        bl(0x04, relocation_at)
    } else {
        NOP
    };
    let entry = if image.executable {
        bl(0x0C, code_at + image.entry as usize)
    } else {
        image.entry
    };
    let first_region = if image.regions.is_empty() {
        0
    } else {
        u32_of(after_debug)
    };
    let words = [
        decompress,
        self_reloc,
        bl(0x08, ZERO_INIT_CODE as usize),
        entry,
        image.exit,
        u32_of(read_only_size),
        u32_of(image.read_write.len()),
        u32_of(image.debug.len()),
        image.zero_init_size,
        image.debug_type,
        image.image_base,
        image.work_space,
        image.address_mode,
        image.data_base,
        first_region,
        0,
    ];
    let mut bytes = Vec::new();
    for word in words {
        put_word(&mut bytes, word, image.big_endian);
    }
    while bytes.len() < HEADER_SIZE {
        put_word(&mut bytes, NOP, image.big_endian);
    }
    if let Some(compressed) = &image.compressed {
        bytes.extend_from_slice(&compressed.data);
        bytes.extend_from_slice(&compressed.code);
        bytes.extend_from_slice(&image.trailer);
        return Built {
            bytes,
            read_write,
            debug,
            after_debug,
        };
    }
    bytes.extend_from_slice(&image.code);
    bytes.extend_from_slice(&image.read_write);
    bytes.extend_from_slice(&image.debug);
    for (i, region) in image.regions.iter().enumerate() {
        let next = if i + 1 == image.regions.len() {
            0
        } else {
            u32_of(bytes.len() + REGION_HEADER_SIZE + region.data.len())
        };
        put_word(&mut bytes, next, image.big_endian);
        put_word(&mut bytes, region.load_address, image.big_endian);
        put_word(&mut bytes, u32_of(region.data.len()), image.big_endian);
        let mut name = region.name.as_bytes().to_vec();
        name.resize(REGION_NAME_SIZE, 0);
        bytes.extend_from_slice(&name);
        bytes.extend_from_slice(&region.data);
    }
    if let Some(relocation) = &image.relocation {
        bytes.extend_from_slice(relocation);
    }
    bytes.extend_from_slice(&image.trailer);
    Built {
        bytes,
        read_write,
        debug,
        after_debug,
    }
}

/// Overwrite the header word at `at` in the image's byte order.
fn patch(bytes: &mut [u8], at: usize, value: u32, big_endian: bool) {
    let field = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    bytes[at..at + 4].copy_from_slice(&field);
}

fn classify(data: &[u8]) -> Result<DetectionPayload, String> {
    detect_payload(data, &ClassifierOptions::new()).map_err(|e| e.to_string())
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &MetadataKey) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| &m.key == key)
        .map(|m| m.value.to_string())
}

fn custom(p: &DetectionPayload, key: &str) -> Option<String> {
    metadata(p, &MetadataKey::Custom(key.to_string()))
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    aif::parse_container(data, layout)
        .expect_err("not a valid image")
        .to_string()
}

/// Deterministic noise for compressed data.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
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
fn executable_images_load_both_areas_as_arm_code_and_list_debug_data_as_opaque() {
    let image = executable(ARM_LE, false);
    let built = build(&image);
    let data = &built.bytes;
    assert_eq!(aif::detect(data), Some(Layout::Executable));
    let p = classify(data).expect("classifies");
    assert_eq!(p.format.format, FileFormat::ArmAif);
    assert_eq!(p.format.variant_name.as_deref(), Some("Executable AIF"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(
        metadata(&p, &MetadataKey::EntryPoint).as_deref(),
        Some("0x8080")
    );
    assert!(
        !p.notes.iter().any(|n| n.level == NoteLevel::Warning),
        "{:?}",
        p.notes
    );
    assert_eq!(p.slices.len(), 1);
    let debug = &p.slices[0];
    assert_eq!(debug.label.as_deref(), Some("Debugging data"));
    assert_eq!(debug.isa, Isa::Unknown(0));
    assert_eq!((debug.offset, debug.size), (built.debug as u64, 32));

    let c = aif::parse_container(data, Layout::Executable).expect("parses");
    assert_eq!(c.sections.len(), 2);
    let read_only = &c.sections[0];
    assert_eq!(read_only.label, "Read-only area");
    assert_eq!(
        (read_only.offset, read_only.stored_size, read_only.address),
        (0, HEADER_SIZE + ARM_LE.len(), 0x8000)
    );
    let read_write = &c.sections[1];
    assert_eq!(read_write.label, "Read-write area");
    assert_eq!(
        (
            read_write.offset,
            read_write.stored_size,
            read_write.address
        ),
        (
            built.read_write,
            64,
            0x8000 + (HEADER_SIZE + ARM_LE.len()) as u64
        )
    );
    assert_eq!(c.consumed, data.len());
    assert!(c.code_sections);
    assert!(has_note(&p, "Linked for 32-bit ARM mode"));
    assert!(has_note(
        &p,
        "Debugging data: 32 B, low-level and source-level (ASD) (debug type 3)"
    ));
    assert!(has_note(&p, "zero-initialized area 256 B (not stored)"));
    assert!(has_note(&p, "Program exit instruction SWI 0x11"));
    assert_eq!(custom(&p, "aif_image_base").as_deref(), Some("0x8000"));
    assert_eq!(custom(&p, "aif_entry_offset").as_deref(), Some("0x80"));
    assert_eq!(custom(&p, "aif_zero_init_size").as_deref(), Some("256"));
    assert_eq!(
        custom(&p, "aif_exit_instruction").as_deref(),
        Some("0xEF000011")
    );
}

#[test]
fn big_endian_headers_name_big_endian_arm() {
    let built = build(&executable(ARM_BE, true));
    let p = classify(&built.bytes).expect("classifies");
    assert_eq!(p.format.format, FileFormat::ArmAif);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Big)
    );
    assert!(has_note(&p, "big-endian header"));
    assert!(
        !p.notes.iter().any(|n| n.level == NoteLevel::Warning),
        "{:?}",
        p.notes
    );
}

#[test]
fn the_header_byte_order_wins_over_the_code_model_with_a_warning() {
    let built = build(&executable(ARM_LE, true));
    let p = classify(&built.bytes).expect("classifies");
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert!(
        p.notes.iter().any(
            |n| n.level == NoteLevel::Warning && n.message.contains("Header byte order is big")
        ),
        "{:?}",
        p.notes
    );
}

#[test]
fn non_executable_images_load_the_code_after_the_header_at_the_image_base() {
    for (code, big_endian) in [(ARM_LE, false), (ARM_BE, true)] {
        let built = build(&non_executable(code, big_endian));
        let data = &built.bytes;
        assert_eq!(aif::detect(data), Some(Layout::NonExecutable));
        let p = classify(data).expect("classifies");
        assert_eq!(p.format.variant_name.as_deref(), Some("Non-executable AIF"));
        assert_eq!(p.primary.isa, Isa::Arm);
        assert_eq!(
            metadata(&p, &MetadataKey::EntryPoint).as_deref(),
            Some("0x10010")
        );
        assert!(has_note(&p, "entry offset at 0xC"));
        let c = aif::parse_container(data, Layout::NonExecutable).expect("parses");
        assert_eq!(
            (
                c.sections[0].offset,
                c.sections[0].stored_size,
                c.sections[0].address
            ),
            (HEADER_SIZE, code.len(), 0x0001_0000)
        );
        assert_eq!(c.sections[1].address, 0x0001_0000 + code.len() as u64);
    }
}

#[test]
fn a_separate_data_base_places_the_read_write_area() {
    let mut image = executable(ARM_LE, false);
    image.address_mode = ADDRESS_MODE_32 | SEPARATE_DATA_BASE;
    image.data_base = 0x4000_0000;
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::Executable).expect("parses");
    assert_eq!(c.sections[1].address, 0x4000_0000);
    let p = classify(&built.bytes).expect("classifies");
    assert!(has_note(
        &p,
        "Linked for 32-bit ARM mode; separate data base 0x40000000"
    ));
    assert_eq!(custom(&p, "aif_data_base").as_deref(), Some("0x40000000"));
}

#[test]
fn old_style_and_26_bit_address_modes_and_undocumented_flags_are_noted() {
    let mut image = executable(ARM_LE, false);
    image.address_mode = 0;
    let p = classify(&build(&image).bytes).expect("classifies");
    assert!(has_note(&p, "Old-style header (address mode word 0)"));
    image.address_mode = 26 | 0x0001_0000;
    let p = classify(&build(&image).bytes).expect("classifies");
    assert!(has_note(
        &p,
        "Linked for 26-bit ARM mode (obsolete); undocumented address mode flags 0x00010000"
    ));
}

#[test]
fn extended_images_chain_load_regions_after_the_root_image() {
    for (code, big_endian) in [(ARM_LE, false), (ARM_BE, true)] {
        let built = build(&extended(code, big_endian));
        let data = &built.bytes;
        assert_eq!(aif::detect(data), Some(Layout::Extended));
        let c = aif::parse_container(data, Layout::Extended).expect("parses");
        let labels: Vec<&str> = c.sections.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Read-only area",
                "Read-write area",
                "Load region 1 (FLASH)",
                "Load region 2"
            ]
        );
        let flash = &c.sections[2];
        assert_eq!(
            (flash.offset, flash.stored_size, flash.address),
            (built.after_debug + REGION_HEADER_SIZE, 16, 0x0010_0000)
        );
        let second = &c.sections[3];
        assert_eq!(
            (second.offset, second.address),
            (built.after_debug + 2 * REGION_HEADER_SIZE + 16, 0x0020_0000)
        );
        assert_eq!(c.consumed, data.len());
        let p = classify(data).expect("classifies");
        assert_eq!(p.format.variant_name.as_deref(), Some("Extended AIF"));
        assert_eq!(p.primary.isa, Isa::Arm);
        assert!(has_note(
            &p,
            &format!(
                "Extended AIF: 2 non-root load regions chained from 0x{:X}",
                built.after_debug
            )
        ));
    }
}

#[test]
fn extended_images_with_debugging_data_leave_it_unlocated() {
    let mut image = extended(&ARM_LE[..256], false);
    image.debug = vec![0xD0; 32];
    image.debug_type = DEBUG_BOTH;
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::Extended).expect("parses");
    assert_eq!(c.children.len(), 0);
    assert_eq!(c.consumed, built.bytes.len());
    assert!(
        c.notes.iter().any(|n| n.starts_with(
            "The 32 B of debugging data are not located: the sources do not place them in \
             extended AIF"
        )),
        "{:?}",
        c.notes
    );
    // Without debugging data, only padding may follow the last region.
    let mut trailing = extended(&ARM_LE[..256], false);
    trailing.trailer = b"junk".to_vec();
    let built = build(&trailing);
    assert!(parse_error(&built.bytes, Layout::Extended).contains("Invalid trailing data"));
}

#[test]
fn region_chains_that_loop_leave_the_file_or_start_inside_the_root_are_errors() {
    let built = build(&extended(&ARM_LE[..256], false));
    let second = built.after_debug + REGION_HEADER_SIZE + 16;

    let mut looped = built.bytes.clone();
    patch(&mut looped, second, u32_of(built.after_debug), false);
    assert!(parse_error(&looped, Layout::Extended).contains("is linked twice"));

    let mut outside = built.bytes.clone();
    let end = u32_of(outside.len());
    patch(&mut outside, second, end, false);
    assert!(
        parse_error(&outside, Layout::Extended).contains("Truncated extended AIF region header")
    );

    let mut inside = built.bytes.clone();
    patch(&mut inside, 0x38, 0x90, false);
    assert!(parse_error(&inside, Layout::Extended).contains("inside the root image"));

    let mut odd_size = built.bytes.clone();
    patch(&mut odd_size, built.after_debug + 8, 15, false);
    assert!(
        parse_error(&odd_size, Layout::Extended).contains("Invalid extended AIF region size 0xF")
    );
}

#[test]
fn compressed_executables_analyze_only_the_decompression_code() {
    let mut image = executable(ARM_LE, false);
    image.compressed = Some(Compressed {
        data: noise(256),
        code: ARM_LE[..1024].to_vec(),
    });
    let built = build(&image);
    let data = &built.bytes;
    let c = aif::parse_container(data, Layout::Executable).expect("parses");
    assert_eq!(c.sections.len(), 1);
    let code = &c.sections[0];
    assert_eq!(code.label, "Decompression code");
    assert_eq!(
        (code.offset, code.stored_size, code.address),
        (HEADER_SIZE + 256, 1024, 0x8000 + (HEADER_SIZE + 256) as u64)
    );
    let p = classify(data).expect("classifies");
    assert_eq!(p.primary.isa, Isa::Arm);
    let compressed = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Compressed image"))
        .expect("compressed slice");
    assert_eq!(
        (compressed.offset, compressed.size, compressed.isa),
        (HEADER_SIZE as u64, 256, Isa::Unknown(0))
    );
    assert!(has_note(
        &p,
        "Compressed image (BL DecompressCode at 0x0): the header's read-only"
    ));
}

#[test]
fn compressed_non_executable_images_are_opaque_after_the_header() {
    let mut image = non_executable(ARM_LE, true);
    image.compressed = Some(Compressed {
        data: noise(300),
        code: Vec::new(),
    });
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::NonExecutable).expect("parses");
    assert_eq!(c.sections.len(), 0);
    assert_eq!(c.children.len(), 1);
    assert!(c.children[0].opaque);
    assert_eq!(c.children[0].offset, HEADER_SIZE);
    let p = classify(&built.bytes).expect("classifies");
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Arm, Endianness::Big)
    );
    assert!(has_note(&p, "decompressed by the loader"));
}

#[test]
fn decompression_branches_outside_the_file_are_errors() {
    let mut image = executable(ARM_LE, false);
    image.compressed = Some(Compressed {
        data: noise(64),
        code: ARM_LE[..64].to_vec(),
    });
    let mut data = build(&image).bytes;
    patch(&mut data, 0x00, bl(0x00, 0x40), false);
    assert!(parse_error(&data, Layout::Executable).contains("Invalid AIF decompression branch"));
    let end = data.len();
    patch(&mut data, 0x00, bl(0x00, end), false);
    assert!(parse_error(&data, Layout::Executable).contains("Invalid AIF decompression branch"));
}

#[test]
fn self_relocating_executables_load_the_relocation_code_after_the_image() {
    let mut image = executable(ARM_LE, false);
    image.work_space = 0x1000;
    let mut relocation = ARM_LE[..64].to_vec();
    for offset in [0x100u32, 0x104, u32::MAX] {
        relocation.extend_from_slice(&offset.to_le_bytes());
    }
    image.relocation = Some(relocation);
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::Executable).expect("parses");
    let code = c.sections.last().expect("relocation section");
    assert_eq!(code.label, "Self-relocation code");
    assert_eq!(
        (code.offset, code.stored_size, code.address),
        (built.after_debug, 76, 0x8000 + built.after_debug as u64)
    );
    assert_eq!(c.consumed, built.bytes.len());
    let p = classify(&built.bytes).expect("classifies");
    assert!(has_note(
        &p,
        &format!(
            "Self-relocating image: relocation code and list, 76 B at 0x{:X}",
            built.after_debug
        )
    ));
    assert!(has_note(&p, "Self-moving image: 4096 B of work space"));
    assert_eq!(custom(&p, "aif_work_space").as_deref(), Some("4096"));

    let mut backwards = built.bytes.clone();
    patch(&mut backwards, 0x04, bl(0x04, 0x80), false);
    assert!(
        parse_error(&backwards, Layout::Executable).contains("Invalid AIF self-relocation branch")
    );
}

#[test]
fn self_relocating_non_executable_images_list_relocation_data_as_opaque() {
    let mut image = non_executable(ARM_LE, false);
    image.relocation = Some(vec![0x10, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::NonExecutable).expect("parses");
    let relocation = c.children.last().expect("relocation data");
    assert_eq!(relocation.label, "Relocation data");
    assert!(relocation.opaque);
    assert_eq!(
        (relocation.offset, relocation.stored_size),
        (built.after_debug, 8)
    );
}

#[test]
fn header_values_outside_the_documented_set_are_not_detected_and_are_errors() {
    let built = build(&executable(&ARM_LE[..256], false));
    let cases: [(usize, u32, &str); 6] = [
        (0x00, 0x1234_5678, "Invalid AIF header word at 0x0"),
        (0x08, 0xEA00_0000, "Invalid AIF header word at 0x8"),
        (0x0C, 0xE000_0000, "Invalid AIF entry word at 0xC"),
        (0x24, 4, "Invalid AIF debug type 0x4"),
        (0x30, 16, "Invalid AIF address mode 0x00000010"),
        (0x14, 0x40, "Invalid AIF read-only size 64 B"),
    ];
    for (at, value, message) in cases {
        let mut data = built.bytes.clone();
        patch(&mut data, at, value, false);
        assert_eq!(aif::detect(&data), None, "{message}");
        let error = parse_error(&data, Layout::Executable);
        assert!(error.contains(message), "{error}");
        assert!(error.starts_with("ARM AIF parse error: "), "{error}");
    }
    let mut blnv = built.bytes.clone();
    for at in [0x00, 0x04, 0x08] {
        patch(&mut blnv, at, BLNV_0, false);
    }
    assert_eq!(aif::detect(&blnv), Some(Layout::Executable));
}

#[test]
fn sizes_that_are_not_word_multiples_or_exceed_the_file_are_errors() {
    let built = build(&executable(&ARM_LE[..256], false));
    let mut odd = built.bytes.clone();
    patch(&mut odd, 0x18, 0x41, false);
    assert_eq!(aif::detect(&odd), Some(Layout::Executable));
    assert!(parse_error(&odd, Layout::Executable)
        .contains("Invalid AIF read-write size 0x41 at 0x18: not a multiple of 4"));
    let mut long = built.bytes.clone();
    patch(&mut long, 0x1C, 0x1000, false);
    assert!(parse_error(&long, Layout::Executable).contains(&format!(
        "Truncated AIF debugging data at 0x{:X} (4096 B)",
        built.debug
    )));
    let mut huge = built.bytes.clone();
    patch(&mut huge, 0x14, 0xFFFF_FFFC, false);
    assert!(parse_error(&huge, Layout::Executable).contains("Truncated AIF read-only area at 0x0"));
}

#[test]
fn padding_after_the_image_is_noted_and_other_trailing_data_is_an_error() {
    let mut image = executable(&ARM_LE[..256], false);
    image.trailer = vec![0xFF; 12];
    let built = build(&image);
    let p = classify(&built.bytes).expect("padding is accepted");
    assert!(has_note(&p, "12 B of padding after the image"));
    image.trailer = b"appended".to_vec();
    let built = build(&image);
    assert!(
        parse_error(&built.bytes, Layout::Executable).contains(&format!(
            "Invalid trailing data at 0x{:X}: 8 B after the image",
            built.after_debug
        ))
    );
}

#[test]
fn entry_points_and_debug_fields_that_disagree_are_noted() {
    let mut image = executable(&ARM_LE[..256], false);
    image.entry = 256 + 16;
    image.debug_type = 0;
    let p = classify(&build(&image).bytes).expect("classifies");
    assert!(has_note(
        &p,
        "Entry point offset 0x190 lies outside the 384 B read-only area"
    ));
    assert!(has_note(
        &p,
        "Debug type 0 (none), but the debug size is 32 B"
    ));
}

#[test]
fn detection_needs_a_complete_header_and_the_exit_instruction() {
    let mut image = executable(&ARM_LE[..256], false);
    let built = build(&image);
    assert_eq!(aif::detect(&built.bytes[..HEADER_SIZE - 1]), None);
    assert_eq!(
        aif::detect(&built.bytes[..HEADER_SIZE]),
        Some(Layout::Executable)
    );
    image.exit = BRANCH_TO_SELF;
    assert_eq!(aif::detect(&build(&image).bytes), Some(Layout::Executable));
    image.exit = NOP;
    let no_exit = build(&image).bytes;
    assert_eq!(aif::detect(&no_exit), None);
    assert!(parse_error(&no_exit, Layout::Executable)
        .contains("Missing AIF program exit instruction at 0x10"));
    assert!(parse_error(&built.bytes[..64], Layout::Executable)
        .contains("Truncated AIF header at 0x0 (128 B)"));
    assert!(parse_error(&built.bytes, Layout::NonExecutable).contains(
        "Invalid AIF variant: the header describes Executable AIF, not Non-executable AIF"
    ));
    // An Arm zImage starts with eight NOPs and a branch: no exit instruction.
    let mut zimage = Vec::new();
    for _ in 0..8 {
        put_word(&mut zimage, NOP, false);
    }
    put_word(&mut zimage, 0xEA00_0002, false);
    zimage.resize(0x200, 0);
    assert_eq!(aif::detect(&zimage), None);
}

#[test]
fn every_truncation_is_an_error() {
    let fixtures = [
        (
            build(&executable(&ARM_LE[..256], false)).bytes,
            Layout::Executable,
        ),
        (
            build(&non_executable(&ARM_BE[..256], true)).bytes,
            Layout::NonExecutable,
        ),
        (
            build(&extended(&ARM_LE[..256], false)).bytes,
            Layout::Extended,
        ),
    ];
    for (data, layout) in fixtures {
        for end in 0..data.len() {
            let prefix = &data[..end];
            assert!(aif::parse_container(prefix, layout).is_err(), "{end}");
            if let Ok(p) = classify(prefix) {
                assert_ne!(p.format.format, FileFormat::ArmAif, "{end}");
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic_and_keep_areas_in_bounds() {
    let mut compressed = executable(&ARM_LE[..128], false);
    compressed.compressed = Some(Compressed {
        data: noise(32),
        code: ARM_LE[..64].to_vec(),
    });
    let mut relocating = executable(&ARM_LE[..128], true);
    relocating.code = ARM_BE[..128].to_vec();
    relocating.relocation = Some(ARM_BE[..32].to_vec());
    let fixtures = [
        build(&executable(&ARM_LE[..128], false)).bytes,
        build(&extended(&ARM_BE[..128], true)).bytes,
        build(&compressed).bytes,
        build(&relocating).bytes,
    ];
    for data in fixtures {
        for at in 0..data.len() {
            for value in [0x00, 0xFF, data[at] ^ 0x01, data[at] ^ 0x80] {
                let mut mutated = data.clone();
                mutated[at] = value;
                if let Some(layout) = aif::detect(&mutated) {
                    if let Ok(c) = aif::parse_container(&mutated, layout) {
                        assert!(c.consumed <= mutated.len());
                        for s in &c.sections {
                            assert!(s.offset + s.stored_size <= mutated.len());
                        }
                        for child in &c.children {
                            assert!(child.offset + child.stored_size <= mutated.len());
                        }
                    }
                }
                let _ = classify(&mutated);
            }
        }
    }
}

#[test]
fn regions_beyond_the_component_limit_are_noted() {
    let limit = zrax::formats::container::MAX_COMPONENTS;
    let mut image = extended(&ARM_LE[..64], false);
    image.regions = (0..=limit)
        .map(|i| Region {
            load_address: u32_of(0x0100_0000 + i * 4),
            name: "R",
            data: vec![0; 4],
        })
        .collect();
    let built = build(&image);
    let c = aif::parse_container(&built.bytes, Layout::Extended).expect("parses");
    assert_eq!(c.sections.len(), 2 + limit);
    assert!(
        c.notes.iter().any(|n| n
            == &format!(
                "Further extended AIF load regions after region {limit} were not listed (limit \
                 {limit})"
            )),
        "{:?}",
        c.notes
    );
}

/// The AIF samples among IDA Pro's test inputs (`arm_*.axf`), read-only
/// and never committed. Four are armlink output; three are deliberately
/// damaged copies whose sizes do not fit, which are parse errors.
#[test]
fn ida_test_inputs_classify_when_provided() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR not set; skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    // Name, read-only size, read-write size, debug size.
    let valid = [
        ("arm_jump.axf", 0xC8, 0, 0x274),
        ("arm_bad_nsyms.axf", 0xC8, 0, 0x274),
        ("arm_wrong_debugsize.axf", 0xC8, 0, 0x274),
        ("arm_rantest.axf", 0x3EA4, 0x220, 0x2870),
    ];
    for (name, read_only, read_write, debug) in valid {
        let path = dir.join(name);
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} not found; skipped", path.display());
            continue;
        };
        let p = classify(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::ArmAif, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some("Executable AIF"));
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (Isa::Arm, 32, Endianness::Little),
            "{name}"
        );
        assert_eq!(
            metadata(&p, &MetadataKey::EntryPoint).as_deref(),
            Some("0x8080"),
            "{name}"
        );
        let c = aif::parse_container(&data, Layout::Executable).expect("parses");
        let sizes: Vec<usize> = c.sections.iter().map(|s| s.stored_size).collect();
        let expected: Vec<usize> = [read_only, read_write]
            .into_iter()
            .filter(|&size| size > 0)
            .collect();
        assert_eq!(sizes, expected, "{name}");
        assert_eq!(c.children.len(), 1, "{name}");
        assert_eq!(c.children[0].stored_size, debug, "{name}");
        assert_eq!(c.consumed, data.len(), "{name}");
    }
    let damaged = [
        (
            "arm_bad_data_segm.axf",
            "Invalid AIF debug size 0x273 at 0x1C: not a multiple of 4",
        ),
        (
            "arm_bad_file.axf",
            "Truncated AIF read-only area at 0x0 (15532104 B)",
        ),
        (
            "arm_huge_dataseg.axf",
            "Invalid AIF read-write size 0xFFFFFFFF at 0x18: not a multiple of 4",
        ),
    ];
    for (name, message) in damaged {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            continue;
        };
        assert_eq!(aif::detect(&data), Some(Layout::Executable), "{name}");
        let error = classify(&data).expect_err(name);
        assert!(error.contains(message), "{name}: {error}");
    }
    // Header words 0x8 to 0x13 are zero: no exit instruction, so not AIF.
    if let Ok(data) = std::fs::read(dir.join("arm_wrong_debuginfo.axf")) {
        assert_eq!(aif::detect(&data), None);
        if let Ok(p) = classify(&data) {
            assert_ne!(p.format.format, FileFormat::ArmAif);
        }
    }
    if let Ok(data) = std::fs::read(dir.join("arm_jump.axf")) {
        for end in 0..data.len() {
            assert!(aif::parse_container(&data[..end], Layout::Executable).is_err());
        }
        for at in 0..data.len() {
            let mut mutated = data.clone();
            mutated[at] ^= 0xFF;
            let _ = classify(&mutated);
        }
    }
}
