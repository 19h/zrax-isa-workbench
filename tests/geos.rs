//! PC/GEOS geodes: the 2.0 and 1.x file headers, the executable header and
//! core block, imported libraries, exported entry points and the resource
//! table; code resources (`HAF_CODE`) as 16-bit x86 components and every
//! other resource as an opaque one; non-geode PC/GEOS files, inconsistent
//! counts and out-of-file ranges as errors; truncation and mutation sweeps;
//! and, when `IDA_INPUT_DIR` is set, the PC/GEOS samples among IDA Pro's
//! test inputs.

use zrax::formats::geos::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa, MetadataKey};

/// nasm-assembled 16-bit real-mode code (`tests/fixtures/geos/code.asm`).
const X86_CODE: &[u8] = include_bytes!("fixtures/geos/code.bin");

/// `GeosFileType` and `GeosFileTypeOld` values (`Include/file.def`,
/// `Include/Internal/fileStr.def`).
const GFT_EXECUTABLE: u16 = 1;
const GFT_VM: u16 = 2;
const GFTO_EXECUTABLE: u16 = 0;

/// `GFHF_DBCS` (`Tools/include/os90File.h`).
const GFHF_DBCS: u16 = 0x0400;

/// `GeodeAttrs` bits (`Tools/include/geode.h`).
const GA_PROCESS: u16 = 0x8000;
const GA_LIBRARY: u16 = 0x4000;
const GA_DRIVER: u16 = 0x2000;
const GA_KEEP_FILE_OPEN: u16 = 0x1000;
const GA_APPLICATION: u16 = 0x0200;

/// `GeodeType` values.
const GEODE_TYPE_APPLICATION: u16 = 1;
const GEODE_TYPE_LIBRARY: u16 = 2;

/// Resource allocation flags as `glue` assigns them (`Tools/glue/geo.c`):
/// the core block (`RESF_FIXED | RESF_READ_ONLY`), dgroup (`RESF_FIXED`),
/// ordinary code (`RESF_STANDARD | RESF_SHARED | RESF_CODE |
/// RESF_READ_ONLY`) and an LMem block (`RESF_SWAPABLE | RESF_DISCARDED |
/// RESF_LMEM`).
const FLAGS_CORE_BLOCK: u16 = 0x0880;
const FLAGS_DGROUP: u16 = 0x0080;
const FLAGS_CODE: u16 = 0x0A72;
const FLAGS_LMEM: u16 = 0x001A;

/// `GeodeRelocationEntry` info bytes: source in the high nibble, type in
/// the low one (`Include/Internal/geodeStr.def`).
const GRS_LIBRARY_GRT_CALL: u8 = 0x14;
const GRS_RESOURCE_GRT_SEGMENT: u8 = 0x22;

/// Sizes from `Tools/include/geode.h` and `os90File.h`.
const FILE_HEADER_2_SIZE: usize = 256;
const FILE_HEADER_1_SIZE: usize = 200;
const EXECUTABLE_HEADER_SIZE: usize = 24;
const CORE_BLOCK_SIZE: usize = 64;
const IMPORTED_LIBRARY_SIZE: usize = 14;
const EXPORT_ENTRY_SIZE: usize = 4;
const RESOURCE_ENTRY_SIZE: usize = 10;
const PARAGRAPH: usize = 16;

/// Which file header a synthetic geode carries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    Geos2,
    Geos1,
}

/// One `ImportedLibraryEntry`.
struct Import {
    name: &'static str,
    attributes: u16,
    protocol_major: u16,
    protocol_minor: u16,
}

/// One resource: its bytes, its relocation entries and its allocation
/// flags.
struct Resource {
    data: Vec<u8>,
    relocations: Vec<[u8; 4]>,
    flags: u16,
}

/// A synthetic geode, written by [`build`] in `glue`'s layout.
struct Geode {
    version: Version,
    long_name: &'static str,
    /// `GeosFileType` in the file header.
    file_type: u16,
    /// `GeosFileHeaderFlags`.
    file_flags: u16,
    geode_type: u16,
    attributes: u16,
    heap_space: u16,
    udata_size: u16,
    imports: Vec<Import>,
    /// Exported entry points: offset and resource.
    exports: Vec<[u16; 2]>,
    resources: Vec<Resource>,
    /// The core block's exported entry count, when it should differ from the
    /// executable header's.
    core_export_count: Option<u16>,
}

/// A `GeodeRelocationEntry`: info, extra (the library number for library
/// relocations), offset in the resource.
fn relocation(info: u8, extra: u8, offset: u16) -> [u8; 4] {
    let [low, high] = offset.to_le_bytes();
    [info, extra, low, high]
}

/// A library geode with the core block, dgroup, one code resource (with a
/// library call and a segment relocation) and an LMem block, importing the
/// kernel and one driver.
fn library(version: Version) -> Geode {
    Geode {
        version,
        long_name: "Test Library",
        file_type: match version {
            Version::Geos2 => GFT_EXECUTABLE,
            Version::Geos1 => GFTO_EXECUTABLE,
        },
        file_flags: 0,
        geode_type: GEODE_TYPE_LIBRARY,
        attributes: GA_LIBRARY | GA_KEEP_FILE_OPEN,
        heap_space: 0,
        udata_size: 32,
        imports: vec![
            Import {
                name: "geos",
                attributes: GA_LIBRARY,
                protocol_major: 654,
                protocol_minor: 0,
            },
            Import {
                name: "serial",
                attributes: GA_DRIVER,
                protocol_major: 2,
                protocol_minor: 1,
            },
        ],
        exports: vec![[0x0026, 2], [0, 0]],
        resources: vec![
            Resource {
                data: Vec::new(),
                relocations: Vec::new(),
                flags: FLAGS_CORE_BLOCK,
            },
            Resource {
                data: vec![0x11; 16],
                relocations: Vec::new(),
                flags: FLAGS_DGROUP,
            },
            Resource {
                data: X86_CODE.to_vec(),
                relocations: vec![
                    relocation(GRS_LIBRARY_GRT_CALL, 0, 0x000C),
                    relocation(GRS_RESOURCE_GRT_SEGMENT, 0, 0x0010),
                ],
                flags: FLAGS_CODE,
            },
            Resource {
                data: vec![0x22; 40],
                relocations: vec![relocation(GRS_RESOURCE_GRT_SEGMENT, 0, 0)],
                flags: FLAGS_LMEM,
            },
        ],
        core_export_count: None,
    }
}

/// An application geode: process, application and multi-thread attributes,
/// a heap space requirement and a process class in the code resource.
fn application() -> Geode {
    Geode {
        long_name: "Test App",
        geode_type: GEODE_TYPE_APPLICATION,
        attributes: GA_PROCESS | GA_APPLICATION,
        heap_space: 400,
        exports: Vec::new(),
        ..library(Version::Geos2)
    }
}

/// `text` as a fixed field of `size` bytes, NUL padded.
fn field(text: &str, size: usize) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(size, 0);
    bytes
}

/// `text` blank padded to `size` bytes, as permanent names are.
fn blank_padded(text: &str, size: usize) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(size, b' ');
    bytes
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    put(bytes, at, &value.to_le_bytes());
}

/// The long name field: 8-bit characters, or 16-bit ones under DBCS.
fn long_name_field(geode: &Geode) -> Vec<u8> {
    if geode.file_flags & GFHF_DBCS != 0 {
        let mut bytes: Vec<u8> = geode
            .long_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.resize(36, 0);
        bytes
    } else {
        field(geode.long_name, 36)
    }
}

/// `GeosFileHeader2` (256 B): signature `C7 45 C1 53`, long name (0x04,
/// 36), file type (0x28), flags (0x2A), release 1.2.3.4 (0x2C), protocol
/// 5.6 (0x34), token `TEST`/8 (0x38), creator `GEOS`/0 (0x3E), user notes
/// (0x44, 100), copyright notice (0xA8, 32), creation date 2026-10-13 and
/// time 12:34:56 (0xC8, 0xCA), password, desktop info and reserved bytes.
fn file_header_2(geode: &Geode) -> Vec<u8> {
    let mut header = vec![0u8; FILE_HEADER_2_SIZE];
    put(&mut header, 0x00, &[0xC7, 0x45, 0xC1, 0x53]);
    put(&mut header, 0x04, &long_name_field(geode));
    put_u16(&mut header, 0x28, geode.file_type);
    put_u16(&mut header, 0x2A, geode.file_flags);
    for (i, part) in [1u16, 2, 3, 4].iter().enumerate() {
        put_u16(&mut header, 0x2C + 2 * i, *part);
    }
    put_u16(&mut header, 0x34, 5);
    put_u16(&mut header, 0x36, 6);
    put(&mut header, 0x38, b"TEST");
    put_u16(&mut header, 0x3C, 8);
    put(&mut header, 0x3E, b"GEOS");
    put(&mut header, 0x44, &field("Synthetic test geode", 100));
    put(&mut header, 0xA8, &field("Copyright nobody", 32));
    let date = ((2026 - 1980) << 9) | (10 << 5) | 13;
    let time = (12 << 11) | (34 << 5) | (56 / 2);
    put_u16(&mut header, 0xC8, date);
    put_u16(&mut header, 0xCA, time);
    header
}

/// 1.x `GeosFileHeader` (200 B): signature `C7 45 CF 53`, file type (0x04),
/// flags (0x06), release 1.2.3.4 (0x08), protocol 5.6 (0x10), token
/// `TEST`/8 (0x14), creator `GEOS`/0 (0x1A), long name (0x20, 36), user
/// notes (0x44, 100) and the reserved bytes with the copyright (0xA8, 32).
fn file_header_1(geode: &Geode) -> Vec<u8> {
    let mut header = vec![0u8; FILE_HEADER_1_SIZE];
    put(&mut header, 0x00, &[0xC7, 0x45, 0xCF, 0x53]);
    put_u16(&mut header, 0x04, geode.file_type);
    put_u16(&mut header, 0x06, geode.file_flags);
    for (i, part) in [1u16, 2, 3, 4].iter().enumerate() {
        put_u16(&mut header, 0x08 + 2 * i, *part);
    }
    put_u16(&mut header, 0x10, 5);
    put_u16(&mut header, 0x12, 6);
    put(&mut header, 0x14, b"TEST");
    put_u16(&mut header, 0x18, 8);
    put(&mut header, 0x1A, b"GEOS");
    put(&mut header, 0x20, &long_name_field(geode));
    put(&mut header, 0xA8, &field("Copyright nobody", 32));
    header
}

/// `ExecutableFileHeader` (24 B): attributes, geode type, heap space (2.x;
/// the 1.x kernel protocol 1.0 here), unused, resource, imported library
/// and exported entry counts, udata size, process class (offset 0x0010 in
/// resource 2) and application object (chunk 0x001C in resource 3).
fn executable_header(geode: &Geode) -> Vec<u8> {
    let mut header = vec![0u8; EXECUTABLE_HEADER_SIZE];
    put_u16(&mut header, 0, geode.attributes);
    put_u16(&mut header, 2, geode.geode_type);
    match geode.version {
        Version::Geos2 => put_u16(&mut header, 4, geode.heap_space),
        Version::Geos1 => put_u16(&mut header, 4, 1),
    }
    put_u16(&mut header, 8, count(geode.resources.len()));
    put_u16(&mut header, 10, count(geode.imports.len()));
    put_u16(&mut header, 12, count(geode.exports.len()));
    put_u16(&mut header, 14, geode.udata_size);
    if geode.attributes & GA_PROCESS != 0 {
        put_u16(&mut header, 16, 0x0010);
        put_u16(&mut header, 18, 2);
        put_u16(&mut header, 20, 0x001C);
        put_u16(&mut header, 22, 3);
    }
    header
}

/// The stored core block (64 B): geode handle 0, copies of the attributes,
/// type, release 1.2.3.4 and protocol 5.6, serial 0x1234, permanent name
/// `testlib` and extension `lib` (blank padded), token, reference count,
/// driver table (offset, resource), library entry (offset 0x0026 in
/// resource 2), exported entry count, imported library count, resource
/// count and the in-memory table offsets (0 in the file).
fn core_block(geode: &Geode) -> Vec<u8> {
    let mut core = vec![0u8; CORE_BLOCK_SIZE];
    put_u16(&mut core, 2, geode.attributes);
    put_u16(&mut core, 4, geode.geode_type);
    for (i, part) in [1u16, 2, 3, 4].iter().enumerate() {
        put_u16(&mut core, 6 + 2 * i, *part);
    }
    put_u16(&mut core, 14, 5);
    put_u16(&mut core, 16, 6);
    put_u16(&mut core, 18, 0x1234);
    put(&mut core, 20, &blank_padded("testlib", 8));
    put(&mut core, 28, &blank_padded("lib", 4));
    put(&mut core, 32, b"TEST");
    put_u16(&mut core, 36, 8);
    if geode.attributes & GA_LIBRARY != 0 {
        put_u16(&mut core, 44, 0x0026);
        put_u16(&mut core, 46, 2);
    }
    let exports = geode
        .core_export_count
        .unwrap_or(count(geode.exports.len()));
    put_u16(&mut core, 50, exports);
    put_u16(&mut core, 52, count(geode.imports.len()));
    put_u16(&mut core, 56, count(geode.resources.len()));
    core
}

fn count(n: usize) -> u16 {
    u16::try_from(n).expect("test counts fit in a word")
}

/// `n` rounded up to a paragraph: resource data is padded to one before
/// its relocations.
fn paragraph_align(n: usize) -> usize {
    (n + PARAGRAPH - 1) & !(PARAGRAPH - 1)
}

/// Where [`build`] put each resource's data, in file offsets.
struct Built {
    bytes: Vec<u8>,
    resource_offsets: Vec<usize>,
}

/// The geode in `glue`'s layout: file header, executable header, core
/// block, imported libraries, exported entry points, the four resource
/// arrays (sizes, positions, relocation sizes, flags), then each resource
/// padded to a paragraph and followed by its relocations. 2.x positions
/// exclude the 256-byte file header; 1.x positions are file offsets.
fn build(geode: &Geode) -> Built {
    let (mut bytes, position_base) = match geode.version {
        Version::Geos2 => (file_header_2(geode), FILE_HEADER_2_SIZE),
        Version::Geos1 => (file_header_1(geode), 0),
    };
    bytes.extend(executable_header(geode));
    bytes.extend(core_block(geode));
    for import in &geode.imports {
        bytes.extend(blank_padded(import.name, 8));
        bytes.extend(import.attributes.to_le_bytes());
        bytes.extend(import.protocol_major.to_le_bytes());
        bytes.extend(import.protocol_minor.to_le_bytes());
    }
    for [offset, resource] in &geode.exports {
        bytes.extend(offset.to_le_bytes());
        bytes.extend(resource.to_le_bytes());
    }
    let mut cursor = bytes.len() + geode.resources.len() * RESOURCE_ENTRY_SIZE;
    let mut offsets = Vec::new();
    for resource in &geode.resources {
        offsets.push(cursor);
        cursor += paragraph_align(resource.data.len()) + resource.relocations.len() * 4;
    }
    for resource in &geode.resources {
        bytes.extend(count(resource.data.len()).to_le_bytes());
    }
    for offset in &offsets {
        let position = u32::try_from(offset - position_base).expect("position fits");
        bytes.extend(position.to_le_bytes());
    }
    for resource in &geode.resources {
        bytes.extend(count(resource.relocations.len() * 4).to_le_bytes());
    }
    for resource in &geode.resources {
        bytes.extend(resource.flags.to_le_bytes());
    }
    for (resource, offset) in geode.resources.iter().zip(&offsets) {
        assert_eq!(bytes.len(), *offset);
        bytes.extend(&resource.data);
        bytes.resize(offset + paragraph_align(resource.data.len()), 0);
        for entry in &resource.relocations {
            bytes.extend(entry);
        }
    }
    Built {
        bytes,
        resource_offsets: offsets,
    }
}

fn classify(data: &[u8]) -> Result<DetectionPayload, String> {
    detect_payload(data, &ClassifierOptions::new()).map_err(|e| e.to_string())
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn notes(p: &DetectionPayload) -> Vec<&str> {
    p.notes.iter().map(|n| n.message.as_str()).collect()
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn layout_of(version: Version) -> Layout {
    match version {
        Version::Geos2 => Layout::Geos2,
        Version::Geos1 => Layout::Geos1,
    }
}

#[test]
fn library_geodes_list_code_resources_as_16_bit_x86_and_other_resources_as_opaque() {
    let built = build(&library(Version::Geos2));
    let p = classify(&built.bytes).expect("classifies");
    assert_eq!(p.format.format, FileFormat::GeosGeode);
    assert_eq!(p.format.variant_name.as_deref(), Some("PC/GEOS 2.0+ geode"));
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86, 16));
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(
        labels,
        [
            "Resource 1 (dgroup)",
            "Resource 2 (code)",
            "Resource 3 (LMem block)"
        ]
    );
    let code = &p.slices[1];
    assert_eq!((code.isa, code.bitwidth), (Isa::X86, 16));
    assert_eq!(code.offset, built.resource_offsets[2] as u64);
    assert_eq!(code.size, X86_CODE.len() as u64);
    let stored = &built.bytes[built.resource_offsets[2]..][..X86_CODE.len()];
    assert_eq!(stored, X86_CODE);
    assert_eq!(p.slices[0].isa, Isa::Unknown(0));
    assert_eq!(p.slices[2].isa, Isa::Unknown(0));
    let resources = format!(
        "4 resources (1 code, {} B); 3 relocations, not applied; 32 B of uninitialized data \
         after dgroup",
        X86_CODE.len()
    );
    for expected in [
        "Library geode \"Test Library\"; permanent name \"testlib\", extension \"lib\"",
        "Attributes 0x5000 (library, keep file open)",
        "Release 1.2.3.4; protocol 5.6; token TEST/8; creator GEOS/0",
        "Imports 2 geodes (expected protocol): geos 654.0, serial 2.1 (driver)",
        "2 exported entry points; library entry routine at resource 2, offset 0x0026",
        resources.as_str(),
        "Code resources (HAF_CODE) are 16-bit x86 real-mode code",
        "Resource 1 (dgroup): opaque; payload ISA analysis skipped",
    ] {
        assert!(has_note(&p, expected), "{expected}: {:?}", notes(&p));
    }
    assert_eq!(
        metadata(&p, "geos_permanent_name").as_deref(),
        Some("testlib.lib")
    );
    assert_eq!(
        metadata(&p, "geos_created").as_deref(),
        Some("2026-10-13 12:34:56")
    );
    assert_eq!(
        metadata(&p, "geos_image_size"),
        Some(built.bytes.len().to_string())
    );
}

#[test]
fn version_1_geodes_place_resources_at_absolute_file_offsets() {
    let built = build(&library(Version::Geos1));
    let p = classify(&built.bytes).expect("classifies");
    assert_eq!(p.format.format, FileFormat::GeosGeode);
    assert_eq!(p.format.variant_name.as_deref(), Some("PC/GEOS 1.x geode"));
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86, 16));
    assert_eq!(p.slices[1].offset, built.resource_offsets[2] as u64);
    assert!(
        has_note(&p, "Expected kernel protocol 1.0"),
        "{:?}",
        notes(&p)
    );
    assert_eq!(metadata(&p, "geos_created"), None);
}

#[test]
fn applications_report_the_process_class_application_object_and_heap_space() {
    let p = classify(&build(&application()).bytes).expect("classifies");
    for expected in [
        "Application geode \"Test App\"",
        "0 exported entry points; process class at resource 2, offset 0x0010; application \
         object at resource 3, chunk 0x001C",
        "Heap space requirement 400 paragraphs (6400 B)",
    ] {
        assert!(has_note(&p, expected), "{expected}: {:?}", notes(&p));
    }
}

#[test]
fn geodes_without_code_resources_name_no_isa() {
    let mut geode = library(Version::Geos2);
    geode.resources[2].flags = FLAGS_LMEM;
    let p = classify(&build(&geode).bytes).expect("classifies");
    assert_eq!(p.format.format, FileFormat::GeosGeode);
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert!(p.slices.iter().all(|s| s.isa == Isa::Unknown(0)));
    assert!(
        has_note(&p, "No resource is marked as code"),
        "{:?}",
        notes(&p)
    );
}

#[test]
fn other_pc_geos_file_types_are_not_parsed_as_geodes() {
    let mut geode = library(Version::Geos2);
    geode.file_type = GFT_VM;
    let error = classify(&build(&geode).bytes).expect_err("a VM file is not a geode");
    assert!(
        error.contains("Unsupported PC/GEOS file type 2 (VM file); only geodes are parsed"),
        "{error}"
    );
    let mut old = library(Version::Geos1);
    old.file_type = 1;
    let error = classify(&build(&old).bytes).expect_err("a 1.x VM file is not a geode");
    assert!(error.contains("file type 1 (VM file)"), "{error}");
}

#[test]
fn differing_counts_in_the_executable_header_and_core_block_are_an_error() {
    let mut geode = library(Version::Geos2);
    geode.core_export_count = Some(0x81);
    let error = classify(&build(&geode).bytes).expect_err("counts disagree");
    assert!(
        error.contains(
            "GEOS geode parse error: Invalid geode header: exported entry point count 2 in the \
             executable header, 129 in the core block"
        ),
        "{error}"
    );
}

#[test]
fn inconsistent_resource_tables_are_errors() {
    let geode = library(Version::Geos2);
    let built = build(&geode);
    let tables_end = FILE_HEADER_2_SIZE
        + EXECUTABLE_HEADER_SIZE
        + CORE_BLOCK_SIZE
        + 2 * IMPORTED_LIBRARY_SIZE
        + 2 * EXPORT_ENTRY_SIZE;
    let sizes_at = tables_end;
    let positions_at = sizes_at + 2 * 4;
    let relocation_sizes_at = positions_at + 4 * 4;

    let mut oversized = built.bytes.clone();
    put_u16(&mut oversized, sizes_at + 2 * 3, 0x4000);
    let error = classify(&oversized).expect_err("resource past the end");
    assert!(error.contains("Truncated resource 3 at 0x"), "{error}");

    let mut odd_relocations = built.bytes.clone();
    put_u16(&mut odd_relocations, relocation_sizes_at + 2 * 2, 6);
    let error = classify(&odd_relocations).expect_err("relocation size");
    assert!(
        error.contains("Invalid relocation table size 6 B for resource 2"),
        "{error}"
    );

    let mut inside_tables = built.bytes.clone();
    put(
        &mut inside_tables,
        positions_at + 4 * 2,
        &0u32.to_le_bytes(),
    );
    let error = classify(&inside_tables).expect_err("resource over the header");
    assert!(
        error.contains("Invalid resource 2 position 0x0: file offset 0x100 lies inside"),
        "{error}"
    );

    let mut bad_export = geode;
    bad_export.exports[0] = [0x0026, 9];
    let error = classify(&build(&bad_export).bytes).expect_err("export resource");
    assert!(
        error.contains("Invalid exported entry point 0: resource 9 is not one of the 4 resources"),
        "{error}"
    );

    let mut one_resource = library(Version::Geos2);
    one_resource.resources.truncate(1);
    one_resource.exports.clear();
    let error = classify(&build(&one_resource).bytes).expect_err("no dgroup");
    assert!(error.contains("Invalid resource count 1"), "{error}");
}

#[test]
fn padding_after_the_last_resource_is_noted_and_other_trailing_data_is_an_error() {
    let mut padded = build(&library(Version::Geos2)).bytes;
    padded.extend([0u8; 12]);
    let p = classify(&padded).expect("classifies");
    assert!(has_note(&p, "12 B of padding after the last resource"));
    padded.push(0x41);
    let error = classify(&padded).expect_err("trailing data");
    assert!(error.contains("Invalid trailing data at 0x"), "{error}");
}

#[test]
fn a_last_resource_without_relocations_may_end_the_file_unpadded() {
    let mut geode = library(Version::Geos2);
    geode.resources[3].relocations.clear();
    let built = build(&geode);
    // 40 B of LMem data are padded to 48 B; drop the padding.
    let unpadded = &built.bytes[..built.resource_offsets[3] + 40];
    let p = classify(unpadded).expect("classifies");
    assert_eq!(p.slices[2].size, 40);
    assert_eq!(
        metadata(&p, "geos_image_size"),
        Some(unpadded.len().to_string())
    );
    let short = &unpadded[..unpadded.len() - 1];
    let error = classify(short).expect_err("resource data is missing");
    assert!(error.contains("Truncated resource 3 at 0x"), "{error}");
}

#[test]
fn dbcs_long_names_are_read_as_16_bit_characters() {
    let mut geode = library(Version::Geos2);
    geode.file_flags = GFHF_DBCS;
    geode.long_name = "Bibliothèque";
    let p = classify(&build(&geode).bytes).expect("classifies");
    assert_eq!(
        metadata(&p, "geos_long_name").as_deref(),
        Some("Bibliothèque")
    );
}

#[test]
fn signatures_are_recognized_only_at_offset_0() {
    let built = build(&library(Version::Geos2));
    assert_eq!(geos::detect(&built.bytes), Some(Layout::Geos2));
    assert_eq!(
        geos::detect(&build(&library(Version::Geos1)).bytes),
        Some(Layout::Geos1)
    );
    let mut shifted = vec![0u8];
    shifted.extend(&built.bytes);
    assert_eq!(geos::detect(&shifted), None);
    assert_eq!(geos::detect(b"\xC7\x45\xC2\x53"), None);
}

#[test]
fn every_truncation_is_an_error() {
    for version in [Version::Geos2, Version::Geos1] {
        let data = build(&library(version)).bytes;
        let layout = layout_of(version);
        for end in 0..data.len() {
            let prefix = &data[..end];
            assert!(
                geos::parse_container(prefix, layout).is_err(),
                "prefix {end}"
            );
            assert!(
                !matches!(classify(prefix), Ok(p) if p.format.format == FileFormat::GeosGeode),
                "prefix {end}"
            );
        }
    }
}

#[test]
fn byte_mutations_never_panic_and_keep_components_in_bounds() {
    for version in [Version::Geos2, Version::Geos1] {
        let data = build(&library(version)).bytes;
        let layout = layout_of(version);
        for at in 0..data.len() {
            for value in [0x00, 0xFF, data[at] ^ 0x01, data[at] ^ 0x80] {
                let mut mutated = data.clone();
                mutated[at] = value;
                if let Ok(c) = geos::parse_container(&mutated, layout) {
                    assert!(c.consumed <= mutated.len());
                    for child in &c.children {
                        assert!(child.offset + child.stored_size <= mutated.len());
                    }
                }
                let _ = classify(&mutated);
            }
        }
    }
}

#[test]
fn resources_beyond_the_component_limit_are_counted_in_a_note() {
    let limit = zrax::formats::container::MAX_COMPONENTS;
    let mut geode = library(Version::Geos2);
    geode.exports.clear();
    geode.resources.truncate(2);
    for _ in 0..limit {
        geode.resources.push(Resource {
            data: vec![0x33; 16],
            relocations: Vec::new(),
            flags: FLAGS_LMEM,
        });
    }
    let data = build(&geode).bytes;
    let c = geos::parse_container(&data, Layout::Geos2).expect("parses");
    assert_eq!(c.children.len(), limit);
    assert!(
        c.notes
            .iter()
            .any(|n| n == &format!("1 further resources were not listed (limit {limit})")),
        "{:?}",
        c.notes
    );
}

/// The PC/GEOS geodes among IDA Pro's test inputs (`pc_*.geo`), read-only
/// and never committed. `pc_bad_class.geo` is `pc_dhcp.geo` with the core
/// block's exported entry count changed.
#[test]
fn ida_test_inputs_classify_when_provided() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR not set; skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    // Name, total slices, code slices.
    let expected = [
        ("pc_dhcp.geo", 3, 1),
        ("pc_nontsec.geo", 5, 1),
        ("pc_uiec.geo", 90, 58),
        ("pc_vga.geo", 10, 8),
        ("pc_wdb.geo", 8, 3),
        ("pc_www.geo", 50, 34),
    ];
    for (name, slices, code) in expected {
        let path = dir.join(name);
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} not found; skipped", path.display());
            continue;
        };
        let p = classify(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::GeosGeode, "{name}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth),
            (Isa::X86, 16),
            "{name}"
        );
        assert_eq!(p.slices.len(), slices, "{name}");
        let code_slices = p
            .slices
            .iter()
            .filter(|s| s.label.as_deref().is_some_and(|l| l.ends_with("(code)")))
            .count();
        assert_eq!(code_slices, code, "{name}");
        assert!(
            p.slices
                .iter()
                .all(|s| s.offset + s.size <= data.len() as u64),
            "{name}"
        );
    }
    if let Ok(data) = std::fs::read(dir.join("pc_bad_class.geo")) {
        let error = classify(&data).expect_err("inconsistent counts");
        assert!(
            error.contains("exported entry point count 1 in the executable header, 129"),
            "{error}"
        );
    }
    if let Ok(data) = std::fs::read(dir.join("pc_dhcp.geo")) {
        for end in 0..data.len() {
            assert!(
                geos::parse_container(&data[..end], Layout::Geos2).is_err(),
                "pc_dhcp.geo prefix {end}"
            );
        }
        for at in 0..data.len() {
            for value in [0x00, 0xFF, data[at] ^ 0x01] {
                let mut mutated = data.clone();
                mutated[at] = value;
                let _ = geos::parse_container(&mutated, Layout::Geos2);
            }
        }
    }
}
