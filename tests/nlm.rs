//! NetWare Loadable Modules: the four binutils NLM targets (signature,
//! header byte order, module name padding, Alpha prefix header) as the
//! target field, the fixed, variable and auxiliary headers in notes and
//! metadata, the code image as the analyzed section, table walking,
//! undocumented header versions, corrupted fields, and truncation and
//! mutation sweeps. `IDA_INPUT_DIR=/path/to/ida/tests/input` also runs the
//! parser over IDA's NLM samples.

use std::path::Path;
use zrax::formats::nlm::{self, Layout};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey, MetadataValue,
};

/// Compiled i686 code from the repository's testbins.
const X86_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/x86_i686-unknown-linux-gnu_O0_call_nested.bin"
);
/// Compiled big-endian 32-bit SPARC code.
const SPARC_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/sparc32_sparc-unknown-linux-gnu_O0_call_nested.bin"
);
/// Compiled big-endian 32-bit PowerPC code.
const PPC_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/ppc32_powerpc-unknown-linux-gnu_O0_call_nested.bin"
);

/// `NLM32_ALPHA_MAGIC` (`include/nlm/common.h`).
const NLM32_ALPHA_MAGIC: u32 = 0x8356_1840;
/// Size of the Alpha prefix header: magic, format, size and padding.
const ALPHA_PREFIX_SIZE: u32 = 16;

// i386 fixed header field offsets (`include/nlm/i386-ext.h`).

/// `version`.
const VERSION_AT: usize = 0x18;
/// `moduleName` (length byte).
const MODULE_NAME_AT: usize = 0x1C;
/// `codeImageSize`.
const CODE_SIZE_AT: usize = 0x2E;
/// `dataImageOffset`.
const DATA_OFFSET_AT: usize = 0x32;
/// `numberOfExternalReferences`.
const EXTERNAL_COUNT_AT: usize = 0x5A;
/// `numberOfPublics`.
const PUBLIC_COUNT_AT: usize = 0x62;
/// `codeStartOffset`.
const CODE_START_AT: usize = 0x6E;
/// `descriptionLength`, the first byte after the 130-byte fixed header.
const DESCRIPTION_LENGTH_AT: usize = 0x82;

/// What a binutils NLM backend fixes for the builder (`bfd/nlm32-*.c`,
/// `include/nlm/*-ext.h`, `bfd/nlm-target.h`).
#[derive(Clone, Copy)]
struct Backend {
    layout: Layout,
    signature: &'static [u8; 24],
    /// Header and data byte order.
    big_endian: bool,
    /// `pad1` after the 14-byte module name.
    name_padding: usize,
    /// One relocation record (`nlm_*_read_reloc`).
    reloc_size: usize,
    /// SPARC import records store the relocation count before the name.
    count_before_name: bool,
    /// Alpha modules start with a prefix header.
    alpha_prefix: bool,
}

const I386: Backend = Backend {
    layout: Layout::I386,
    signature: b"NetWare Loadable Module\x1a",
    big_endian: false,
    name_padding: 0,
    reloc_size: 4,
    count_before_name: false,
    alpha_prefix: false,
};

const SPARC: Backend = Backend {
    layout: Layout::Sparc,
    signature: b"NetWare SPARC Module   \x1a",
    big_endian: true,
    name_padding: 2,
    reloc_size: 12,
    count_before_name: true,
    alpha_prefix: false,
};

const POWERPC: Backend = Backend {
    layout: Layout::PowerPc,
    signature: b"NetWare PowerPC Module \x1a",
    big_endian: true,
    name_padding: 2,
    reloc_size: 4,
    count_before_name: false,
    alpha_prefix: false,
};

const ALPHA: Backend = Backend {
    layout: Layout::Alpha,
    signature: b"NetWare Alpha Module   \x1a",
    big_endian: false,
    name_padding: 2,
    reloc_size: 16,
    count_before_name: false,
    alpha_prefix: true,
};

/// The contents of a synthetic module.
#[derive(Clone)]
struct Module {
    /// Fixed header `version`.
    version: u32,
    code: Vec<u8>,
    data: Vec<u8>,
    /// `uninitializedDataSize`.
    uninitialized: u32,
    /// `codeStartOffset` and `exitProcedureOffset`, code image offsets.
    code_start: u32,
    exit_procedure: u32,
    flags: u32,
    dependencies: Vec<&'static [u8]>,
    /// Number of relocation fixups.
    fixups: u32,
    /// Import names and their relocation counts.
    externals: Vec<(&'static [u8], u32)>,
    /// Export names and offsets.
    publics: Vec<(&'static [u8], u32)>,
    /// Debug record type, value and name.
    debug_records: Vec<(u8, u32, &'static [u8])>,
    /// Number of `CoPyRiGhT=` headers written.
    copyrights: usize,
    message_file: Vec<u8>,
    /// Write a `CuStHeAd`/`CyGnUsEx` header and its section table, which
    /// ends the file.
    cygnus: bool,
}

/// A module with every table populated around `code`.
fn module(code: Vec<u8>) -> Module {
    Module {
        version: 4,
        code,
        data: vec![0x11; 32],
        uninitialized: 0x100,
        code_start: 0,
        exit_procedure: 4,
        flags: 0x10,
        dependencies: vec![b"CLIB", b"TCPIP"],
        fixups: 2,
        externals: vec![(b"printf", 2)],
        publics: vec![(b"main", 0x8000_0000)],
        debug_records: vec![(1, 0, b"main")],
        copyrights: 1,
        message_file: b"synthetic messages".to_vec(),
        cygnus: true,
    }
}

/// File offsets of the stored parts.
#[derive(Default, Clone, Copy)]
struct Offsets {
    code: u32,
    data: u32,
    dependencies: u32,
    fixups: u32,
    externals: u32,
    publics: u32,
    debug_records: u32,
    message_file: u32,
    cygnus_table: u32,
    cygnus_table_size: u32,
}

/// Append a word in the backend's byte order.
fn word(out: &mut Vec<u8>, b: Backend, value: u32) {
    if b.big_endian {
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Write `value` over the word at `at`, in the backend's byte order.
fn put_word(data: &mut [u8], b: Backend, at: usize, value: u32) {
    let bytes = if b.big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    data[at..at + 4].copy_from_slice(&bytes);
}

fn len32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("fixture parts are small")
}

/// A length byte, the text and a NUL (variable header strings,
/// `copyrightMessage`).
fn terminated(out: &mut Vec<u8>, text: &[u8]) {
    out.push(u8::try_from(text.len()).expect("short text"));
    out.extend_from_slice(text);
    out.push(0);
}

/// A length byte and the name (dependencies, imports, exports, debug
/// records).
fn counted(out: &mut Vec<u8>, name: &[u8]) {
    out.push(u8::try_from(name.len()).expect("short name"));
    out.extend_from_slice(name);
}

/// The Alpha prefix header (`nlm32_alpha_external_prefix_header`): magic,
/// format 2, its own size, padding.
fn alpha_prefix(out: &mut Vec<u8>, b: Backend) {
    word(out, b, NLM32_ALPHA_MAGIC);
    word(out, b, 2);
    word(out, b, ALPHA_PREFIX_SIZE);
    word(out, b, 0);
}

/// The fixed header (`*-ext.h`).
fn fixed_header(out: &mut Vec<u8>, b: Backend, m: &Module, o: &Offsets) {
    out.extend_from_slice(b.signature);
    word(out, b, m.version);
    // moduleName: length byte, "TEST.NLM", NUL fill to 14 bytes.
    let mut name = [0u8; 14];
    name[0] = 8;
    name[1..9].copy_from_slice(b"TEST.NLM");
    out.extend_from_slice(&name);
    out.extend(std::iter::repeat(0).take(b.name_padding));
    word(out, b, o.code); // codeImageOffset
    word(out, b, len32(&m.code)); // codeImageSize
    word(out, b, o.data); // dataImageOffset
    word(out, b, len32(&m.data)); // dataImageSize
    word(out, b, m.uninitialized); // uninitializedDataSize
    word(out, b, 0); // customDataOffset: no custom data
    word(out, b, 0); // customDataSize
    word(out, b, o.dependencies); // moduleDependencyOffset
    word(out, b, len32_count(m.dependencies.len()));
    word(out, b, o.fixups); // relocationFixupOffset
    word(out, b, m.fixups);
    word(out, b, o.externals); // externalReferencesOffset
    word(out, b, len32_count(m.externals.len()));
    word(out, b, o.publics); // publicsOffset
    word(out, b, len32_count(m.publics.len()));
    word(out, b, o.debug_records); // debugInfoOffset
    word(out, b, len32_count(m.debug_records.len()));
    word(out, b, m.code_start); // codeStartOffset
    word(out, b, m.exit_procedure); // exitProcedureOffset
    word(out, b, 0); // checkUnloadProcedureOffset: none
    word(out, b, 0); // moduleType
    word(out, b, m.flags); // flags
}

fn len32_count(n: usize) -> u32 {
    u32::try_from(n).expect("few records")
}

/// The variable header: description, stack size, reserved word, " LONG",
/// screen name, thread name.
fn variable_header(out: &mut Vec<u8>, b: Backend) {
    terminated(out, b"Synthetic test module");
    word(out, b, 8192);
    word(out, b, 0);
    out.extend_from_slice(b" LONG");
    terminated(out, b"Test Screen");
    terminated(out, b"test");
}

/// `VeRsIoN#`, `CoPyRiGhT=`, `MeSsAgEs` and, when asked, the Cygnus
/// `CuStHeAd`, in `nlmconv` order.
fn auxiliary_headers(out: &mut Vec<u8>, b: Backend, m: &Module, o: &Offsets) {
    out.extend_from_slice(b"VeRsIoN#");
    for value in [1, 2, 3, 2024, 5, 6] {
        word(out, b, value); // major, minor, revision, year, month, day
    }
    for _ in 0..m.copyrights {
        out.extend_from_slice(b"CoPyRiGhT=");
        terminated(out, b"(c) synthetic");
    }
    out.extend_from_slice(b"MeSsAgEs");
    word(out, b, 4); // languageID
    word(out, b, o.message_file); // messageFileOffset
    word(out, b, len32(&m.message_file)); // messageFileLength
    word(out, b, 2); // messageCount
                     // Help file, RPC data, shared code, shared data, the shared tables and
                     // procedures, productID and reserved0-5: 25 words of zero.
    for _ in 0..25 {
        word(out, b, 0);
    }
    if m.cygnus {
        out.extend_from_slice(b"CuStHeAd");
        word(out, b, 16); // length: dataOffset, dataLength, dataStamp
        word(out, b, o.cygnus_table);
        word(out, b, o.cygnus_table_size);
        out.extend_from_slice(b"CyGnUsEx");
    }
}

/// Everything before the code image.
fn headers(b: Backend, m: &Module, o: &Offsets) -> Vec<u8> {
    let mut out = Vec::new();
    if b.alpha_prefix {
        alpha_prefix(&mut out, b);
    }
    fixed_header(&mut out, b, m, o);
    variable_header(&mut out, b);
    auxiliary_headers(&mut out, b, m, o);
    out
}

/// The stored parts after headers of `header_size` bytes, and their
/// offsets.
fn body(b: Backend, m: &Module, header_size: usize) -> (Vec<u8>, Offsets) {
    let mut out = Vec::new();
    let at = |out: &[u8]| u32::try_from(header_size + out.len()).expect("small file");
    let mut o = Offsets {
        code: at(&out),
        ..Offsets::default()
    };
    out.extend_from_slice(&m.code);
    o.data = at(&out);
    out.extend_from_slice(&m.data);
    o.dependencies = at(&out);
    for name in &m.dependencies {
        counted(&mut out, name);
    }
    o.fixups = at(&out);
    // Fixup records of the target's size; their contents are not
    // interpreted.
    let fixups_size = usize::try_from(m.fixups).expect("few fixups") * b.reloc_size;
    out.extend(std::iter::repeat(0x5A).take(fixups_size));
    o.externals = at(&out);
    for (name, relocations) in &m.externals {
        if b.count_before_name {
            word(&mut out, b, *relocations);
            counted(&mut out, name);
        } else {
            counted(&mut out, name);
            word(&mut out, b, *relocations);
        }
        let size = usize::try_from(*relocations).expect("few relocations") * b.reloc_size;
        out.extend(std::iter::repeat(0).take(size));
    }
    o.publics = at(&out);
    for (name, offset) in &m.publics {
        counted(&mut out, name);
        word(&mut out, b, *offset);
    }
    o.debug_records = at(&out);
    for (kind, value, name) in &m.debug_records {
        out.push(*kind);
        word(&mut out, b, *value);
        counted(&mut out, name);
    }
    o.message_file = at(&out);
    out.extend_from_slice(&m.message_file);
    if m.cygnus {
        o.cygnus_table = at(&out);
        let start = out.len();
        // Section name, NUL padding to 4 bytes, file position, size.
        out.extend_from_slice(b".text\0\0\0");
        word(&mut out, b, o.code);
        word(&mut out, b, len32(&m.code));
        out.extend_from_slice(b".data\0\0\0");
        word(&mut out, b, o.data);
        word(&mut out, b, len32(&m.data));
        o.cygnus_table_size = len32(&out[start..]);
    }
    (out, o)
}

/// The complete module file.
fn build(b: Backend, m: &Module) -> Vec<u8> {
    let header_size = headers(b, m, &Offsets::default()).len();
    let (body, offsets) = body(b, m, header_size);
    let mut file = headers(b, m, &offsets);
    file.extend_from_slice(&body);
    file
}

fn code(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("testbin is committed")
}

/// A small code image for the sweeps.
fn small_code() -> Vec<u8> {
    code(X86_CODE)[..64].to_vec()
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

fn entry_point(p: &DetectionPayload) -> Option<u64> {
    p.metadata.iter().find_map(|m| match (&m.key, &m.value) {
        (MetadataKey::EntryPoint, MetadataValue::Address(address)) => Some(*address),
        _ => None,
    })
}

/// Position of `needle` in `data`.
fn find(data: &[u8], needle: &[u8]) -> usize {
    data.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle is present")
}

#[test]
fn i386_signature_names_x86_and_the_code_image_is_analyzed() {
    let m = module(code(X86_CODE));
    let data = build(I386, &m);
    assert_eq!(nlm::detect(&data), Some(Layout::I386));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::NetWareNlm);
    assert_eq!(p.format.variant_name.as_deref(), Some("NetWare NLM (i386)"));
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(
        &p,
        "The signature names the i386 target (binutils nlm32-i386); header version 4; \
         little-endian header fields"
    ));
    // The code model agrees with the signature, so nothing is contradicted.
    assert!(!p.notes.iter().any(|n| n.message.contains("classifies as")));

    let code_offset = find(&data, &m.code[..16]);
    assert_eq!(
        metadata(&p, "nlm_section_0").as_deref(),
        Some(
            format!(
                "file 0x{code_offset:X}; destination 0x0; {} B",
                m.code.len()
            )
            .as_str()
        )
    );
    assert_eq!(entry_point(&p), Some(0));
    assert_eq!(metadata(&p, "nlm_image_size"), Some(data.len().to_string()));
    assert!(p.slices.is_empty());
}

#[test]
fn big_endian_targets_pad_the_module_name_and_swap_every_word() {
    for (b, path, isa) in [
        (SPARC, SPARC_CODE, Isa::Sparc),
        (POWERPC, PPC_CODE, Isa::Ppc),
    ] {
        let data = build(b, &module(code(path)));
        assert_eq!(nlm::detect(&data), Some(b.layout));
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::NetWareNlm);
        assert_eq!(p.primary.isa, isa);
        assert_eq!(p.primary.endianness, Endianness::Big);
        assert!(has_note(&p, "big-endian header fields"));
        assert!(has_note(&p, "Module TEST.NLM: Synthetic test module"));
        assert!(has_note(
            &p,
            "2 relocation fixups, 1 external reference, 1 public, 1 debug record"
        ));
        // A little-endian reading of the same words does not validate.
        let mut swapped = data.clone();
        swapped[..24].copy_from_slice(I386.signature);
        assert!(detect_payload(&swapped, &ClassifierOptions::new()).is_err());
    }
}

#[test]
fn alpha_modules_start_with_the_prefix_header() {
    let data = build(ALPHA, &module(small_code()));
    assert_eq!(&data[16..40], ALPHA.signature);
    assert_eq!(nlm::detect(&data), Some(Layout::Alpha));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::NetWareNlm);
    assert_eq!(p.primary.isa, Isa::Alpha);
    assert_eq!(p.primary.bitwidth, 64);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert!(has_note(&p, "binutils nlm32-alpha"));

    // Without the prefix magic the Alpha signature is not an NLM.
    let mut no_magic = data.clone();
    no_magic[0] ^= 0xFF;
    assert_eq!(nlm::detect(&no_magic), None);
    // A prefix size that misses the signature is not either.
    let mut moved = data.clone();
    put_word(&mut moved, ALPHA, 8, 20);
    assert_eq!(nlm::detect(&moved), None);
    assert!(nlm::parse_container(&moved, Layout::Alpha).is_err());
}

#[test]
fn code_that_contradicts_the_signature_is_reported_not_adopted() {
    let data = build(I386, &module(code(PPC_CODE)));
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert!(
        p.notes
            .iter()
            .any(|n| n.message.starts_with("Container names x86")),
        "{:?}",
        p.notes
    );
}

#[test]
fn headers_and_tables_reach_notes_and_metadata() {
    let data = build(I386, &module(small_code()));
    let p = classify(&data);
    for note in [
        "Module TEST.NLM: Synthetic test module",
        "Module version 1.2, revision 3, dated 2024-05-06",
        "Code image: 64 B at 0x",
        "start procedure at 0x0, exit procedure at 0x4 (code image offsets)",
        "Data image: 32 B at 0x",
        "not analyzed as code; 256 B of uninitialized data follow it at load time",
        "Flags 0x10: OS_DOMAIN",
        "2 module dependencies: CLIB, TCPIP",
        "2 relocation fixups, 1 external reference, 1 public, 1 debug record",
    ] {
        assert!(has_note(&p, note), "{note}: {:?}", p.notes);
    }
    let expect = [
        ("nlm_header_version", "4"),
        ("nlm_module_name", "TEST.NLM"),
        ("nlm_description", "Synthetic test module"),
        ("nlm_stack_size", "8192"),
        ("nlm_screen_name", "Test Screen"),
        ("nlm_thread_name", "test"),
        ("nlm_flags", "0x00000010"),
        ("nlm_copyright", "(c) synthetic"),
        ("nlm_language_id", "4"),
        ("nlm_message_count", "2"),
        ("nlm_uninitialized_data_size", "256"),
        ("nlm_exit_procedure", "0x4"),
        ("nlm_module_dependencies", "CLIB, TCPIP"),
        ("nlm_relocation_fixups", "2"),
        ("nlm_external_references", "1"),
        ("nlm_publics", "1"),
        ("nlm_debug_records", "1"),
    ];
    for (key, value) in expect {
        assert_eq!(metadata(&p, key).as_deref(), Some(value), "{key}");
    }
    let table = find(&data, b".text\0");
    assert_eq!(
        metadata(&p, "nlm_cygnus_sections"),
        Some(format!("file 0x{table:X}; 32 B; 2 sections"))
    );
    let messages = find(&data, b"synthetic messages");
    assert_eq!(
        metadata(&p, "nlm_message_file"),
        Some(format!("file 0x{messages:X}; 18 B"))
    );
    assert_eq!(metadata(&p, "nlm_check_unload_procedure"), None);
}

#[test]
fn empty_tables_may_point_past_the_end_of_the_file() {
    let mut m = module(small_code());
    m.dependencies.clear();
    m.fixups = 0;
    m.externals.clear();
    m.publics.clear();
    m.debug_records.clear();
    let mut data = build(I386, &m);
    // nlmconv points empty tables at the end of the written data.
    put_word(&mut data, I386, PUBLIC_COUNT_AT - 4, u32::MAX);
    let p = classify(&data);
    assert!(has_note(&p, "No module dependencies"));
    assert!(has_note(
        &p,
        "0 relocation fixups, 0 external references, 0 publics, 0 debug records"
    ));
}

#[test]
fn a_header_version_with_bit_7_keeps_the_headers_and_skips_the_image() {
    let mut data = build(I386, &module(small_code()));
    put_word(&mut data, I386, VERSION_AT, 0x84);
    // The image ranges are not file coordinates in such a module.
    put_word(&mut data, I386, CODE_SIZE_AT, 0x00FF_0000);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::NetWareNlm);
    assert_eq!(p.primary.isa, Isa::X86);
    assert!(has_note(
        &p,
        "Header version 0x84 is not documented (binutils documents versions up to 4); the \
         image and table ranges are not checked and the code image is not analyzed"
    ));
    assert!(has_note(&p, "Module version 1.2, revision 3"));
    assert!(p.candidates.is_empty());
    assert_eq!(metadata(&p, "nlm_section_0"), None);
    assert_eq!(metadata(&p, "nlm_module_name").as_deref(), Some("TEST.NLM"));
}

#[test]
fn corrupted_fields_are_errors_that_name_the_field() {
    let m = module(small_code());
    let data = build(I386, &m);
    let code_size = u32::try_from(m.code.len()).unwrap();
    let message_length_at = find(&data, b"MeSsAgEs") + 8 + 8;
    let with_byte = |at: usize, value: u8| {
        let mut corrupted = data.clone();
        corrupted[at] = value;
        corrupted
    };
    let with_word = |at: usize, value: u32| {
        let mut corrupted = data.clone();
        put_word(&mut corrupted, I386, at, value);
        corrupted
    };
    let cases = [
        (
            with_word(VERSION_AT, 5),
            "Unsupported header version 0x5".to_string(),
        ),
        (
            with_byte(MODULE_NAME_AT, 0),
            "Invalid module name length 0 (1 to 12 B)".into(),
        ),
        (
            with_byte(MODULE_NAME_AT, 13),
            "Invalid module name length 13 (1 to 12 B)".into(),
        ),
        (
            with_byte(DESCRIPTION_LENGTH_AT, 200),
            "Invalid description length 200 at 0x82 (at most 127)".into(),
        ),
        (
            with_word(CODE_SIZE_AT, 0x8000_0000),
            "Truncated code image at 0x".into(),
        ),
        (
            with_word(DATA_OFFSET_AT, 0xFFFF_FFF0),
            "Truncated data image at 0xFFFFFFF0 + 32 B".into(),
        ),
        (
            with_word(EXTERNAL_COUNT_AT, 0x0080_0001),
            "Invalid external references count 8388609 at 0x".into(),
        ),
        (
            with_word(EXTERNAL_COUNT_AT, 2),
            "Truncated external reference".into(),
        ),
        (
            with_word(CODE_START_AT, code_size),
            format!("Invalid code start offset 0x40 (the code image is {code_size} B)"),
        ),
        (
            with_word(message_length_at, 0x1000),
            "Truncated message file at 0x".into(),
        ),
    ];
    for (corrupted, expected) in cases {
        let text = error_text(&corrupted);
        assert!(
            text.starts_with("NetWare module parse error: ") && text.contains(&expected),
            "{expected}: {text}"
        );
    }

    let mut twice = m.clone();
    twice.copyrights = 2;
    assert!(error_text(&build(I386, &twice)).contains("Duplicate CoPyRiGhT= header at 0x"));
}

#[test]
fn bytes_after_the_described_structures_are_noted_not_analyzed() {
    let mut data = build(I386, &module(small_code()));
    let size = data.len();
    data.extend_from_slice(&[0; 64]);
    assert!(!has_note(&classify(&data), "not described by the headers"));
    data.extend_from_slice(b"WATCOM debug information");
    let p = classify(&data);
    assert!(has_note(
        &p,
        &format!("88 B after 0x{size:X} are not described by the headers and are not analyzed")
    ));
    assert_eq!(metadata(&p, "nlm_image_size"), Some(size.to_string()));
}

#[test]
fn every_prefix_is_an_error_or_another_format() {
    for b in [I386, SPARC, POWERPC, ALPHA] {
        let data = build(b, &module(small_code()));
        for end in 0..data.len() {
            let prefix = &data[..end];
            assert!(
                nlm::parse_container(prefix, b.layout).is_err(),
                "{:?} prefix {end}",
                b.layout
            );
            if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                assert_ne!(p.format.format, FileFormat::NetWareNlm, "prefix {end}");
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for b in [I386, SPARC, POWERPC, ALPHA] {
        let data = build(b, &module(small_code()));
        for at in 0..data.len() {
            for mutation in [0x00, 0xFF, data[at] ^ 0x01, data[at] ^ 0x80] {
                let mut mutated = data.clone();
                mutated[at] = mutation;
                let _ = nlm::parse_container(&mutated, b.layout);
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

/// IDA's NLM samples and what each must produce: the module name, or the
/// start of the parse error. The `bad`, `huge` and `truncated` samples are
/// deliberately malformed copies of `pc_netw6.nlm` cut to 16,896 B.
const IDA_SAMPLES: [(&str, Result<&str, &str>); 7] = [
    ("pc_netw6.nlm", Ok("IPTRACE.NLM")),
    ("pc_old.nlm", Ok("VREPAIR.NLM")),
    (
        "pc_bad_codeoff.nlm",
        Err("Truncated code image at 0xFF0001C6 + 16767811 B"),
    ),
    ("pc_bad_impoff.nlm", Err("Unsupported header version 0x49")),
    (
        "pc_bad_import_count.nlm",
        Err("Invalid external references count 8388662 at 0x3B8E (1650 B remain)"),
    ),
    (
        "pc_huge_bss.nlm",
        Err("Truncated message file at 0x41E2 + 1945 B"),
    ),
    (
        "pc_truncated_nlm.nlm",
        Err("Truncated code image at 0x1C6 + 2147493052 B"),
    ),
];

#[test]
fn ida_nlm_samples_parse_or_fail_with_bounded_errors() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR is not set; skipping the IDA NLM samples");
        return;
    };
    let dir = Path::new(&dir);
    for (name, expected) in IDA_SAMPLES {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            eprintln!("{name} is not in IDA_INPUT_DIR; skipped");
            continue;
        };
        match (detect_payload(&data, &ClassifierOptions::new()), expected) {
            (Ok(p), Ok(module_name)) => {
                assert_eq!(p.format.format, FileFormat::NetWareNlm, "{name}");
                assert_eq!(p.primary.isa, Isa::X86, "{name}");
                assert_eq!(
                    metadata(&p, "nlm_module_name").as_deref(),
                    Some(module_name),
                    "{name}"
                );
            }
            (Err(e), Err(message)) => {
                assert_eq!(
                    e.to_string(),
                    format!("NetWare module parse error: {message}"),
                    "{name}"
                );
            }
            (got, _) => panic!("{name}: unexpected {:?}", got.map(|p| p.format.format)),
        }
    }
    if let Ok(data) = std::fs::read(dir.join("pc_netw6.nlm")) {
        let p = classify(&data);
        assert!(has_note(
            &p,
            "339 relocation fixups, 54 external references, 0 publics, 0 debug records"
        ));
        assert!(has_note(
            &p,
            "Module version 6.0, revision 5, dated 2002-04-22"
        ));
        assert_eq!(entry_point(&p), Some(0x2460));
    }
    if let Ok(data) = std::fs::read(dir.join("pc_old.nlm")) {
        assert!(has_note(
            &classify(&data),
            "Header version 0x84 is not documented"
        ));
    }
}
