//! DOS-family headers the classifier recognizes beyond `MZ` plus an
//! extended header: LE and LX headers at offset 0 without an MZ stub
//! (validated completely, weak detection, CPU type as the ISA evidence, the
//! same classification as behind a stub), and PE images whose DOS header
//! starts with the byte-swapped `ZM` signature; corrupted fields,
//! truncation and mutation sweeps. `IDA_INPUT_DIR=/path/to/ida/tests/input`
//! also runs the parser over IDA's bare LE/LX and `ZM` samples.

use zrax::formats::mz::{self, ExtendedType};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa,
};

/// A 32-bit x86 function: `push ebp; mov ebp, esp; sub esp, 8;
/// mov eax, [ebp+8]; add eax, [ebp+12]; mov [ebp-4], eax;
/// mov eax, [ebp-4]; leave; ret`.
const X86_CODE: &[u8] = &[
    0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x89, 0x45, 0xFC, 0x8B,
    0x45, 0xFC, 0xC9, 0xC3,
];

/// The linear EXE page size (IBM LX specification, `PAGE SIZE`).
const PAGE_SIZE: usize = 4096;

/// Size of the header the builders write: the VxD header of `winnt.h`
/// (`IMAGE_VXD_HEADER`, 196 B); the LX fields end at `ACh`.
const HEADER_SIZE: usize = 0xC4;

/// Object table entry size.
const OBJECT_ENTRY_SIZE: usize = 24;

/// Module flags: library module (`00008000h`).
const MODULE_LIBRARY: u32 = 0x8000;

/// Object flags: readable, executable, big/default (`2005h`), and readable,
/// writable, big/default (`2003h`).
const OBJECT_CODE: u32 = 0x2005;
const OBJECT_DATA: u32 = 0x2003;

/// CPU types (`01h` 80286, `02h` 80386, `03h` 80486).
const CPU_80386: u16 = 2;
const CPU_80486: u16 = 3;

/// OS types (`01h` OS/2, `04h` Windows 386).
const OS_OS2: u16 = 1;
const OS_WINDOWS_386: u16 = 4;

/// Size of the MZ stub the stubbed builders put in front of the header.
const STUB_SIZE: usize = 0x80;

/// The note of a PE image with a `ZM` DOS header.
const ZM_NOTE: &str = "DOS header signature is ZM, the byte-swapped MZ that the MS-DOS loader \
                       also accepts; whether PE loaders accept it is not verified";

/// LE or LX.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Signature {
    Le,
    Lx,
}

impl Signature {
    fn bytes(self) -> &'static [u8; 2] {
        match self {
            Signature::Le => b"LE",
            Signature::Lx => b"LX",
        }
    }

    fn page_entry_size(self) -> usize {
        match self {
            Signature::Le => 4,
            Signature::Lx => 8,
        }
    }

    fn format(self) -> FileFormat {
        match self {
            Signature::Le => FileFormat::Le,
            Signature::Lx => FileFormat::Lx,
        }
    }
}

/// One object: its virtual size, relocation base, flags and the number of
/// pages it takes from the page data, in order.
#[derive(Clone, Copy)]
struct Object {
    virtual_size: u32,
    base: u32,
    flags: u32,
    pages: u32,
}

/// What a linear executable fixture declares.
#[derive(Clone)]
struct Image {
    signature: Signature,
    /// `B-ORD` and `W-ORD` both 1.
    big_endian: bool,
    cpu: u16,
    os: u16,
    module_flags: u32,
    eip_object: u32,
    eip: u32,
    esp_object: u32,
    esp: u32,
    objects: Vec<Object>,
    /// Page data; split into 4 KiB pages.
    code: Vec<u8>,
}

/// An OS/2 80386 program: a code object holding `X86_CODE` and an empty
/// stack object.
fn program(signature: Signature) -> Image {
    Image {
        signature,
        big_endian: false,
        cpu: CPU_80386,
        os: OS_OS2,
        module_flags: 0,
        eip_object: 1,
        eip: 0,
        esp_object: 2,
        esp: 0x1000,
        objects: vec![
            Object {
                virtual_size: X86_CODE.len() as u32,
                base: 0x1_0000,
                flags: OBJECT_CODE,
                pages: 1,
            },
            Object {
                virtual_size: 0x1000,
                base: 0x2_0000,
                flags: OBJECT_DATA,
                pages: 0,
            },
        ],
        code: X86_CODE.to_vec(),
    }
}

/// Little- or big-endian field writer over the file.
struct Writer {
    data: Vec<u8>,
    big_endian: bool,
}

impl Writer {
    fn u16(&mut self, at: usize, value: u16) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.data[at..at + 2].copy_from_slice(&bytes);
    }

    fn u32(&mut self, at: usize, value: u32) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.data[at..at + 4].copy_from_slice(&bytes);
    }
}

/// Field offsets in the header (IBM LX specification, Figure 2).
mod field {
    pub const BYTE_ORDER: usize = 0x02;
    pub const WORD_ORDER: usize = 0x03;
    pub const LEVEL: usize = 0x04;
    pub const CPU: usize = 0x08;
    pub const OS: usize = 0x0A;
    pub const FLAGS: usize = 0x10;
    pub const PAGES: usize = 0x14;
    pub const EIP_OBJECT: usize = 0x18;
    pub const EIP: usize = 0x1C;
    pub const ESP_OBJECT: usize = 0x20;
    pub const ESP: usize = 0x24;
    pub const PAGE_SIZE: usize = 0x28;
    /// LX page offset shift, LE last page size.
    pub const SHIFT_OR_LAST_PAGE: usize = 0x2C;
    pub const OBJECT_TABLE: usize = 0x40;
    pub const OBJECT_COUNT: usize = 0x44;
    pub const PAGE_TABLE: usize = 0x48;
    pub const ITERATED_PAGES: usize = 0x4C;
    pub const RESIDENT_NAMES: usize = 0x58;
    pub const ENTRY_TABLE: usize = 0x5C;
    pub const DATA_PAGES: usize = 0x80;
    pub const NON_RESIDENT_NAMES: usize = 0x88;
}

/// The file layout of a built fixture (file offsets).
struct Built {
    data: Vec<u8>,
    /// Object table.
    objects: usize,
    /// Object page table.
    page_table: usize,
}

/// Build `image` with its header at `header_at` (an MZ stub of that size
/// in front when nonzero): header, object table, object page table, an
/// empty resident name table and entry table, then the 16-byte aligned data
/// pages, which end the file.
fn build(image: &Image, header_at: usize) -> Built {
    let page_count = (image.code.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    let objects_at = HEADER_SIZE;
    let page_table_at = objects_at + OBJECT_ENTRY_SIZE * image.objects.len();
    let names_at = page_table_at + image.signature.page_entry_size() * page_count;
    let tables_end = names_at + 2;
    let data_pages = (header_at + tables_end + 15) & !15;
    let mut w = Writer {
        data: vec![0; data_pages + image.code.len()],
        big_endian: image.big_endian,
    };
    if header_at != 0 {
        w.data[..2].copy_from_slice(b"MZ");
        w.data[0x3C..0x40].copy_from_slice(&(header_at as u32).to_le_bytes());
    }
    let h = header_at;
    w.data[h..h + 2].copy_from_slice(image.signature.bytes());
    let order = u8::from(image.big_endian);
    w.data[h + field::BYTE_ORDER] = order;
    w.data[h + field::WORD_ORDER] = order;
    w.u32(h + field::LEVEL, 0);
    w.u16(h + field::CPU, image.cpu);
    w.u16(h + field::OS, image.os);
    w.u32(h + field::FLAGS, image.module_flags);
    w.u32(h + field::PAGES, page_count as u32);
    w.u32(h + field::EIP_OBJECT, image.eip_object);
    w.u32(h + field::EIP, image.eip);
    w.u32(h + field::ESP_OBJECT, image.esp_object);
    w.u32(h + field::ESP, image.esp);
    w.u32(h + field::PAGE_SIZE, PAGE_SIZE as u32);
    let last_page = image.code.len() - (page_count - 1) * PAGE_SIZE;
    let shift_or_last_page = match image.signature {
        // Page offset shift 0: page offsets are byte offsets.
        Signature::Lx => 0,
        Signature::Le => last_page as u32,
    };
    w.u32(h + field::SHIFT_OR_LAST_PAGE, shift_or_last_page);
    w.u32(h + field::OBJECT_TABLE, objects_at as u32);
    w.u32(h + field::OBJECT_COUNT, image.objects.len() as u32);
    w.u32(h + field::PAGE_TABLE, page_table_at as u32);
    w.u32(h + field::RESIDENT_NAMES, names_at as u32);
    w.u32(h + field::ENTRY_TABLE, names_at as u32 + 1);
    // File-relative.
    w.u32(h + field::DATA_PAGES, data_pages as u32);

    // Objects take consecutive pages, numbered from 1.
    let mut next_page = 1;
    for (i, object) in image.objects.iter().enumerate() {
        let at = h + objects_at + OBJECT_ENTRY_SIZE * i;
        w.u32(at, object.virtual_size);
        w.u32(at + 4, object.base);
        w.u32(at + 8, object.flags);
        w.u32(at + 12, if object.pages == 0 { 0 } else { next_page });
        w.u32(at + 16, object.pages);
        next_page += object.pages;
    }
    for page in 0..page_count {
        let at = h + page_table_at + image.signature.page_entry_size() * page;
        match image.signature {
            // Offset from the data pages, data size, flags 0 (legal page).
            Signature::Lx => {
                let size = if page + 1 == page_count {
                    last_page
                } else {
                    PAGE_SIZE
                };
                w.u32(at, (page * PAGE_SIZE) as u32);
                w.u16(at + 4, size as u16);
            }
            // 24-bit page number, most significant byte first, flags 0.
            Signature::Le => {
                let number = (page + 1) as u32;
                w.data[at..at + 3].copy_from_slice(&number.to_be_bytes()[1..]);
            }
        }
    }
    w.data[data_pages..].copy_from_slice(&image.code);
    Built {
        data: w.data,
        objects: objects_at,
        page_table: page_table_at,
    }
}

/// `image` without a stub.
fn bare(image: &Image) -> Vec<u8> {
    build(image, 0).data
}

/// `image` behind a minimal MZ stub.
fn stubbed(image: &Image) -> Vec<u8> {
    build(image, STUB_SIZE).data
}

/// A PE image: a DOS header with `signature` and `e_lfanew` 0x80, the PE
/// signature, an i386 COFF header (one section, no optional header).
fn pe_image(signature: &[u8; 2]) -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    data[..2].copy_from_slice(signature);
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    // Machine: IMAGE_FILE_MACHINE_I386.
    data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    // NumberOfSections.
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn notes(p: &DetectionPayload) -> Vec<&str> {
    p.notes.iter().map(|n| n.message.as_str()).collect()
}

fn has_note(p: &DetectionPayload, message: &str) -> bool {
    p.notes.iter().any(|n| n.message == message)
}

/// The error `mz::parse` gives for a header without a stub.
fn bare_error(data: &[u8], variant: ExtendedType) -> String {
    mz::parse(data, variant)
        .expect_err("must not parse")
        .to_string()
}

fn is_linear(format: FileFormat) -> bool {
    matches!(format, FileFormat::Le | FileFormat::Lx | FileFormat::Mz)
}

#[test]
fn bare_lx_is_recognized_from_its_structure_with_the_cpu_type_as_isa() {
    let data = bare(&program(Signature::Lx));
    assert_eq!(
        mz::detect_bare(&data),
        Some(ExtendedType::BareLx { cpu: 2, os: 1 })
    );
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Lx);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("BareLx { cpu: 2, os: 1 }")
    );
    assert_eq!(p.format.confidence, 0.85);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("OS/2 80386")
    );
    assert_eq!(
        notes(&p),
        [
            "LX (Linear Executable)",
            "Target OS: OS/2",
            "CPU: 80386",
            "Type: Executable",
            "Pages: 1",
            "Entry: object 1:0x00000000",
            "No MZ stub; the LX header starts at offset 0x0",
        ]
    );
}

#[test]
fn bare_le_uses_its_last_page_size_and_names_its_os_and_cpu() {
    let mut image = program(Signature::Le);
    image.cpu = CPU_80486;
    image.os = OS_WINDOWS_386;
    let data = bare(&image);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Le);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("BareLe { cpu: 3, os: 4 }")
    );
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("Windows 386 80486")
    );
    assert!(has_note(
        &p,
        "No MZ stub; the LE header starts at offset 0x0"
    ));
}

#[test]
fn bare_and_stubbed_headers_classify_alike_apart_from_the_reported_format() {
    for signature in [Signature::Le, Signature::Lx] {
        let image = program(signature);
        let bare = classify(&bare(&image));
        let stubbed = classify(&stubbed(&image));
        // Behind a stub, the DOS header names the file (existing behaviour).
        assert_eq!(stubbed.format.format, FileFormat::Mz);
        assert_eq!(stubbed.format.confidence, 1.0);
        let name = format!("{signature:?}");
        assert_eq!(
            stubbed.format.variant_name,
            Some(format!("{name} {{ cpu: 2, os: 1 }}"))
        );
        assert_eq!(bare.format.format, signature.format());
        assert_eq!(
            bare.format.variant_name,
            Some(format!("Bare{name} {{ cpu: 2, os: 1 }}"))
        );
        assert_eq!(bare.primary.isa, stubbed.primary.isa);
        assert_eq!(bare.primary.bitwidth, stubbed.primary.bitwidth);
        assert_eq!(bare.primary.variant, stubbed.primary.variant);
        let mut expected = notes(&stubbed);
        let no_stub = format!(
            "No MZ stub; the {} header starts at offset 0x0",
            name.to_uppercase()
        );
        expected.push(&no_stub);
        assert_eq!(notes(&bare), expected, "{name}");
    }
}

#[test]
fn multi_page_images_and_libraries_without_an_entry_object_are_recognized() {
    for signature in [Signature::Le, Signature::Lx] {
        let mut image = program(signature);
        image.code = X86_CODE.repeat(400);
        image.objects[0].virtual_size = image.code.len() as u32;
        image.objects[0].pages = 2;
        let p = classify(&bare(&image));
        assert_eq!(p.format.format, signature.format());
        assert!(has_note(&p, "Pages: 2"));

        // A library without an entry routine has EIP object 0.
        let mut library = program(signature);
        library.module_flags = MODULE_LIBRARY;
        library.eip_object = 0;
        let p = classify(&bare(&library));
        assert_eq!(p.format.format, signature.format());
        assert!(has_note(&p, "Type: DLL"));
    }
}

#[test]
fn big_endian_headers_are_read_in_their_declared_order() {
    for signature in [Signature::Le, Signature::Lx] {
        let mut image = program(signature);
        image.big_endian = true;
        let data = bare(&image);
        assert_eq!(
            mz::detect_bare(&data).map(|t| t.detected_format()),
            Some(signature.format())
        );
        let p = classify(&data);
        // The CPU type names x86, whose code is little-endian.
        assert_eq!(p.primary.isa, Isa::X86);
        assert_eq!(p.primary.endianness, Endianness::Little);
        assert!(has_note(&p, "Byte order: BE, Word order: BE"));
        assert!(has_note(&p, "Entry: object 1:0x00000000"));
    }
}

#[test]
fn mixed_or_undefined_byte_orders_are_not_recognized() {
    for (byte_order, word_order) in [(0, 1), (1, 0), (2, 2), (0, 0xFF)] {
        let mut data = bare(&program(Signature::Lx));
        data[field::BYTE_ORDER] = byte_order;
        data[field::WORD_ORDER] = word_order;
        assert_eq!(mz::detect_bare(&data), None);
        assert_eq!(
            bare_error(&data, ExtendedType::BareLx { cpu: 2, os: 1 }),
            format!(
                "MZ/NE/LE/LX parse error: Invalid LX byte and word order \
                 0x{byte_order:X}/0x{word_order:X}"
            )
        );
    }
}

/// A corruption of a valid fixture and the error it must produce.
struct Corruption {
    signature: Signature,
    edit: fn(&mut Built),
    message: &'static str,
}

fn put_u32(built: &mut Built, at: usize, value: u32) {
    built.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn corruptions() -> Vec<Corruption> {
    use Signature::{Le, Lx};
    let lx = |edit: fn(&mut Built), message| Corruption {
        signature: Lx,
        edit,
        message,
    };
    let le = |edit: fn(&mut Built), message| Corruption {
        signature: Le,
        edit,
        message,
    };
    vec![
        lx(
            |b| put_u32(b, field::LEVEL, 1),
            "Unsupported LX format level 1",
        ),
        lx(|b| b.data[field::CPU] = 0, "Unknown LX CPU type 0x0"),
        // Pentium, i860 and MIPS values are not in the LX specification.
        lx(|b| b.data[field::CPU] = 4, "Unknown LX CPU type 0x4"),
        lx(|b| b.data[field::CPU] = 0x40, "Unknown LX CPU type 0x40"),
        lx(|b| b.data[field::OS] = 5, "Unknown LX OS type 0x5"),
        lx(
            |b| put_u32(b, field::PAGE_SIZE, 0),
            "Invalid LX page size 0 B",
        ),
        lx(
            |b| put_u32(b, field::PAGE_SIZE, 0x800),
            "Invalid LX page size 2048 B",
        ),
        lx(
            |b| put_u32(b, field::PAGE_SIZE, 0x8000_1000),
            "Invalid LX page size 2147487744 B",
        ),
        lx(|b| put_u32(b, field::OBJECT_COUNT, 0), "Missing LX objects"),
        lx(
            |b| put_u32(b, field::OBJECT_COUNT, u32::MAX),
            "Invalid LX object table: 4294967295 entries at 0xC4",
        ),
        lx(
            |b| put_u32(b, field::OBJECT_TABLE, 0x10),
            "Invalid LX object table: 2 entries at 0x10",
        ),
        lx(
            |b| put_u32(b, field::OBJECT_TABLE, 0x1_0000),
            "Invalid LX object table: 2 entries at 0x10000",
        ),
        lx(
            |b| put_u32(b, b.objects + 12, 0),
            "Invalid LX object 1 pages: index 0, 1 pages, module has 1",
        ),
        lx(
            |b| put_u32(b, b.objects + 16, 2),
            "Invalid LX object 1 pages: index 1, 2 pages, module has 1",
        ),
        lx(
            |b| put_u32(b, field::EIP_OBJECT, 3),
            "Invalid LX entry objects: EIP object 3, ESP object 2, 2 objects",
        ),
        lx(
            |b| put_u32(b, field::ESP_OBJECT, 3),
            "Invalid LX entry objects: EIP object 1, ESP object 3, 2 objects",
        ),
        lx(
            |b| put_u32(b, field::EIP_OBJECT, 0),
            "Missing LX entry object for a program module",
        ),
        lx(
            |b| put_u32(b, field::PAGES, 0x0080_0002),
            "Invalid LX object page table: 8388610 pages at 0xF4",
        ),
        lx(
            |b| put_u32(b, field::DATA_PAGES, 0),
            "Invalid LX data pages offset 0x0",
        ),
        lx(
            |b| put_u32(b, field::SHIFT_OR_LAST_PAGE, 32),
            "Invalid LX page offset shift 32",
        ),
        lx(
            |b| put_u32(b, field::ITERATED_PAGES, 0x200),
            "Invalid LX iterated pages offset 0x200: data pages are at 0x100",
        ),
        lx(
            |b| put_u32(b, b.page_table, 1),
            "Invalid LX page 1: 20 B at data page offset 0x1",
        ),
        lx(
            |b| b.data[b.page_table + 5] = 0x10,
            "Invalid LX page 1: 4116 B at data page offset 0x0",
        ),
        le(
            |b| put_u32(b, field::SHIFT_OR_LAST_PAGE, 0x1001),
            "Invalid LE last page size 4097 B",
        ),
        le(
            |b| put_u32(b, field::SHIFT_OR_LAST_PAGE, 0x21),
            "Truncated LE data pages: 1 pages at 0x100",
        ),
        le(
            |b| b.data[b.page_table + 2] = 2,
            "Invalid LE page 1: page number 2, module has 1",
        ),
        le(
            |b| put_u32(b, field::CPU, 0x0102),
            "Unknown LE CPU type 0x102",
        ),
    ]
}

#[test]
fn header_and_table_corruptions_are_not_recognized_and_name_the_field() {
    for corruption in corruptions() {
        let image = program(corruption.signature);
        let mut built = build(&image, 0);
        (corruption.edit)(&mut built);
        let data = &built.data;
        assert_eq!(mz::detect_bare(data), None, "{}", corruption.message);
        assert!(
            !matches!(detect_format(data), DetectedFormat::Mz { .. }),
            "{}",
            corruption.message
        );
        let variant = match corruption.signature {
            Signature::Le => ExtendedType::BareLe { cpu: 2, os: 1 },
            Signature::Lx => ExtendedType::BareLx { cpu: 2, os: 1 },
        };
        assert_eq!(
            bare_error(data, variant),
            format!("MZ/NE/LE/LX parse error: {}", corruption.message)
        );
    }
}

#[test]
fn bare_parse_rejects_other_signatures_and_short_headers() {
    let lx = bare(&program(Signature::Lx));
    assert_eq!(
        bare_error(&lx, ExtendedType::BareLe { cpu: 2, os: 1 }),
        "MZ/NE/LE/LX parse error: Invalid LE header: the signature is LX"
    );
    assert_eq!(
        bare_error(
            &stubbed(&program(Signature::Lx)),
            ExtendedType::BareLx { cpu: 2, os: 1 }
        ),
        "MZ/NE/LE/LX parse error: Missing LE or LX signature at offset 0x0"
    );
    assert_eq!(
        bare_error(&lx[..0x40], ExtendedType::BareLx { cpu: 2, os: 1 }),
        "MZ/NE/LE/LX parse error: Truncated LX header: 64 B of 172 B"
    );
}

#[test]
fn ascii_text_starting_with_le_or_lx_is_not_an_executable() {
    for text in [&b"LEGAL NOTICE"[..], b"LXC container configuration"] {
        let mut data = text.repeat(64);
        data.truncate(1024);
        assert_eq!(mz::detect_bare(&data), None);
        assert!(!matches!(detect_format(&data), DetectedFormat::Mz { .. }));
    }
}

#[test]
fn every_truncation_of_a_bare_header_is_unrecognized() {
    for signature in [Signature::Le, Signature::Lx] {
        let data = bare(&program(signature));
        for end in 0..data.len() {
            let prefix = &data[..end];
            assert_eq!(mz::detect_bare(prefix), None, "{signature:?} {end}");
            if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                assert!(!is_linear(p.format.format), "{signature:?} {end}");
            }
        }
    }
}

#[test]
fn byte_mutations_of_bare_headers_never_panic_and_stay_bounded() {
    for signature in [Signature::Le, Signature::Lx] {
        let data = bare(&program(signature));
        for at in 0..data.len() {
            for value in [0x00, 0xFF, data[at] ^ (1 << (at % 8))] {
                let mut mutated = data.clone();
                mutated[at] = value;
                let recognized = mz::detect_bare(&mutated).is_some();
                if let Ok(p) = detect_payload(&mutated, &ClassifierOptions::new()) {
                    if matches!(p.format.format, FileFormat::Le | FileFormat::Lx) {
                        assert!(recognized, "{signature:?} {at} {value:#x}");
                        assert_eq!(p.primary.isa, Isa::X86, "{signature:?} {at}");
                    }
                }
            }
        }
    }
}

#[test]
fn zm_dos_header_with_a_pe_signature_is_a_pe_image_with_a_note() {
    let p = classify(&pe_image(b"ZM"));
    assert_eq!(p.format.format, FileFormat::Pe);
    assert_eq!(p.format.confidence, 1.0);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, ZM_NOTE));

    let p = classify(&pe_image(b"MZ"));
    assert_eq!(p.format.format, FileFormat::Pe);
    assert!(!has_note(&p, ZM_NOTE));
}

#[test]
fn zm_without_a_pe_signature_is_not_a_dos_executable() {
    let pe = pe_image(b"ZM");
    let mut ne = pe.clone();
    ne[0x80..0x84].copy_from_slice(b"NE\x05\x00");
    let mut no_extended_header = pe.clone();
    no_extended_header[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
    let mut le = stubbed(&program(Signature::Le));
    le[..2].copy_from_slice(b"ZM");
    for data in [ne, no_extended_header, le] {
        assert!(!matches!(
            detect_format(&data),
            DetectedFormat::Pe { .. } | DetectedFormat::Mz { .. }
        ));
    }
}

#[test]
fn zm_pe_truncations_are_pe_only_with_the_whole_signature() {
    let data = pe_image(b"ZM");
    for end in 0..data.len() {
        let is_pe = matches!(
            detect_format(&data[..end]),
            DetectedFormat::Pe { pe_offset: 0x80 }
        );
        assert_eq!(is_pe, end >= 0x84, "{end}");
    }
}

/// IDA's LE/LX samples without an MZ stub (`IDA_INPUT_DIR`, read-only): the
/// recognized ones, and the bounded error of each rejected one.
const IDA_BARE_SAMPLES: &[(&str, Result<FileFormat, &str>)] = &[
    ("pc_nomz.le", Ok(FileFormat::Lx)),
    ("pc_huge_imports.lx", Ok(FileFormat::Lx)),
    ("pc_huge_obj.lx", Ok(FileFormat::Lx)),
    ("pc_bad_fixups.lx", Ok(FileFormat::Lx)),
    ("pc_bad_iterate2.lx", Ok(FileFormat::Lx)),
    (
        "pc_bad_nfixups.lx",
        Err("Invalid LX object page table: 8388610 pages at 0xF4"),
    ),
    ("pc_bad_nimports.lx", Err("Missing LX objects")),
    ("pc_bad_nojbs.lx", Err("Invalid LX page size 352699915 B")),
    (
        "pc_bad_npages.lx",
        Err("Invalid LX object 2 pages: index 134219010, 1128879681 pages, module has 2"),
    ),
    (
        "pc_bad_pagesize.lx",
        Err("Invalid LX page size 2147487744 B"),
    ),
    ("pc_bad_vxd.le", Err("Unknown LE CPU type 0x102")),
];

/// IDA's LE/LX samples behind an MZ stub, for the unbinding probe.
const IDA_STUBBED_SAMPLES: &[&str] = &[
    "pc_drv.le",
    "pc_popple_unchecked.le",
    "pc_tomb.le",
    "pc_vxd.le",
    "pc_os2_exe.lx",
];

fn ida_dir() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("IDA_INPUT_DIR");
    if dir.is_none() {
        eprintln!("IDA_INPUT_DIR is not set; skipping the IDA LE/LX/PE samples");
    }
    dir.map(Into::into)
}

#[test]
fn ida_bare_samples_are_recognized_or_rejected_with_a_bounded_error() {
    let Some(dir) = ida_dir() else {
        return;
    };
    for (name, expected) in IDA_BARE_SAMPLES {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            eprintln!("{name} is not in IDA_INPUT_DIR; skipped");
            continue;
        };
        let variant = if data.starts_with(b"LE") {
            ExtendedType::BareLe { cpu: 2, os: 1 }
        } else {
            ExtendedType::BareLx { cpu: 2, os: 1 }
        };
        match expected {
            Ok(format) => {
                let p = classify(&data);
                assert_eq!(p.format.format, *format, "{name}");
                assert_eq!(
                    (p.primary.isa, p.primary.bitwidth),
                    (Isa::X86, 32),
                    "{name}"
                );
                assert_eq!(
                    p.primary.variant.as_ref().map(|v| v.name.as_str()),
                    Some("OS/2 80386"),
                    "{name}"
                );
                assert!(has_note(
                    &p,
                    "No MZ stub; the LX header starts at offset 0x0"
                ));
            }
            Err(message) => {
                assert_eq!(mz::detect_bare(&data), None, "{name}");
                assert_eq!(
                    bare_error(&data, variant),
                    format!("MZ/NE/LE/LX parse error: {message}"),
                    "{name}"
                );
                if let Ok(p) = detect_payload(&data, &ClassifierOptions::new()) {
                    assert!(!is_linear(p.format.format), "{name}");
                }
            }
        }
    }
}

#[test]
fn ida_bare_sample_truncations_and_mutations_are_bounded() {
    let Some(dir) = ida_dir() else {
        return;
    };
    for (name, _) in IDA_BARE_SAMPLES {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            continue;
        };
        for end in 0..data.len() {
            let _ = detect_format(&data[..end]);
            let _ = mz::detect_bare(&data[..end]);
        }
        for at in 0..data.len() {
            for value in [0x00, 0xFF, data[at] ^ (1 << (at % 8))] {
                let mut mutated = data.clone();
                mutated[at] = value;
                if let Some(variant) = mz::detect_bare(&mutated) {
                    let result = mz::parse(&mutated, variant).expect("validated header parses");
                    assert_eq!(result.isa, Isa::X86, "{name} {at}");
                }
            }
        }
    }
}

/// Remove the MZ stub of a stubbed sample the way an unbinding tool does:
/// keep the bytes from the linear header on and rebase the file-relative
/// offsets (iterated pages, data pages, non-resident names) by the stub
/// size.
fn unbind(data: &[u8]) -> Vec<u8> {
    let header = u32::from_le_bytes(data[0x3C..0x40].try_into().expect("4 bytes")) as usize;
    let mut out = data[header..].to_vec();
    for at in [
        field::ITERATED_PAGES,
        field::DATA_PAGES,
        field::NON_RESIDENT_NAMES,
    ] {
        let value = u32::from_le_bytes(out[at..at + 4].try_into().expect("4 bytes"));
        // A zero (absent) offset stays zero.
        let rebased = value.saturating_sub(header as u32);
        out[at..at + 4].copy_from_slice(&rebased.to_le_bytes());
    }
    out
}

#[test]
fn ida_stubbed_samples_validate_once_unbound_and_keep_their_classification() {
    let Some(dir) = ida_dir() else {
        return;
    };
    for name in IDA_STUBBED_SAMPLES {
        let Ok(data) = std::fs::read(dir.join(name)) else {
            eprintln!("{name} is not in IDA_INPUT_DIR; skipped");
            continue;
        };
        let stubbed = classify(&data);
        let bare_data = unbind(&data);
        let expected = match mz::detect(&data) {
            Some(ExtendedType::Le { cpu, os }) => ExtendedType::BareLe { cpu, os },
            Some(ExtendedType::Lx { cpu, os }) => ExtendedType::BareLx { cpu, os },
            other => panic!("{name}: {other:?}"),
        };
        assert_eq!(mz::detect_bare(&bare_data), Some(expected), "{name}");
        let bare = classify(&bare_data);
        assert_eq!(bare.format.format, expected.detected_format(), "{name}");
        assert_eq!(bare.primary.isa, stubbed.primary.isa, "{name}");
        assert_eq!(bare.primary.variant, stubbed.primary.variant, "{name}");
    }
}

#[test]
fn ida_zm_sample_is_a_pe_image() {
    let Some(dir) = ida_dir() else {
        return;
    };
    let Ok(data) = std::fs::read(dir.join("pc_import_samedll.pe")) else {
        eprintln!("pc_import_samedll.pe is not in IDA_INPUT_DIR; skipped");
        return;
    };
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Pe);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86, 32));
    assert!(has_note(&p, ZM_NOTE));
}
