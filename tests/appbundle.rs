//! Application bundles: synthetic PyInstaller archives (standalone and
//! inside host executables), the committed Electron ASAR fixture written by
//! `asar` 4.1.0 and synthetic ASAR headers, and synthetic .NET single-file
//! bundles of versions 1, 2 and 6, all built from the documented layouts
//! (PyInstaller `pyi_archive.h` and `writers.py`, asar `disk.ts` and
//! `pickle.ts`, .NET `bundle_marker.cpp`, `Manifest.cs` and `FileEntry.cs`).
//! Covers members with stored and decoded ranges, verified hashes,
//! corrupted fields, host executables that keep their own classification,
//! and truncation and mutation sweeps. With `APPBUNDLE_SAMPLE_DIR` set, the
//! real bundles in that directory are parsed; with `IDA_INPUT_DIR` set,
//! IDA Pro's test inputs are checked not to be bundles and to keep their
//! classification with an archive appended.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zrax::formats::appbundle::{self, Layout};
use zrax::formats::container::{self, Container, Kind};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// A 256-byte x86-64 ELF header and filler (see
/// `tests/fixtures/compressed/README.md`).
const X86_64_ELF: &[u8] = include_bytes!("fixtures/compressed/payload.elf");

/// A 256-byte AArch64 ELF header and filler (see
/// `tests/fixtures/archives/README.md`).
const AARCH64_ELF: &[u8] = include_bytes!("fixtures/archives/payload.elf");

/// An FFS section stream whose PE32 section (a 4-byte section header, then
/// a 428-byte x86-64 PE32+ image) comes first (see
/// `tests/fixtures/uefi/README.md`).
const PE32_SECTIONS: &[u8] = include_bytes!("fixtures/uefi/pe32-sections.bin");

/// The ASAR fixture (see `tests/fixtures/appbundle/README.md`).
const SAMPLE_ASAR: &[u8] = include_bytes!("fixtures/appbundle/sample.asar");

/// The x86-64 PE32+ image inside [`PE32_SECTIONS`].
fn x86_64_pe() -> &'static [u8] {
    &PE32_SECTIONS[4..0x1b0]
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::AppBundle(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::AppBundle(layout))
        .expect_err("is a parse error")
        .to_string()
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c container::Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("child {label} in {:?}", labels(c)))
}

fn slice<'p>(p: &'p DetectionPayload, label: &str) -> &'p zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn size32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("fixture fits in 32 bits")
}

/// `value` rounded up to a multiple of `alignment`.
fn align(value: usize, alignment: usize) -> usize {
    match value % alignment {
        0 => value,
        rest => value + alignment - rest,
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 9)
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 6)
}

/// A 1 KiB PE32+ image for AMD64 whose data directory 14 (COM descriptor)
/// points at a COR20 header with `COMIMAGE_FLAGS_ILONLY`: an IL-only
/// managed assembly. `e_lfanew` 0x80; one section (`VirtualSize` 0x100,
/// `VirtualAddress` 0x1000, `SizeOfRawData` 0x100, `PointerToRawData`
/// 0x200) after the 0xF0-byte optional header; 16 data directories; the
/// COR20 header at RVA 0x1010 (file 0x210), 72 B, `Flags` at +16.
fn il_only_assembly() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    put(&mut data, 0, b"MZ");
    put(&mut data, 0x3c, &0x80u32.to_le_bytes());
    put(&mut data, 0x80, b"PE\0\0");
    let coff = 0x84;
    put(&mut data, coff, &0x8664u16.to_le_bytes());
    put(&mut data, coff + 2, &1u16.to_le_bytes());
    put(&mut data, coff + 16, &0xf0u16.to_le_bytes());
    put(&mut data, coff + 18, &0x2022u16.to_le_bytes());
    let optional = coff + 20;
    put(&mut data, optional, &0x20bu16.to_le_bytes());
    put(&mut data, optional + 108, &16u32.to_le_bytes());
    let com = optional + 112 + 14 * 8;
    put(&mut data, com, &0x1010u32.to_le_bytes());
    put(&mut data, com + 4, &72u32.to_le_bytes());
    let section = optional + 0xf0;
    put(&mut data, section, b".text\0\0\0");
    for (i, value) in [0x100u32, 0x1000, 0x100, 0x200].iter().enumerate() {
        put(&mut data, section + 8 + i * 4, &value.to_le_bytes());
    }
    put(&mut data, 0x210, &72u32.to_le_bytes());
    put(&mut data, 0x220, &1u32.to_le_bytes());
    data
}

// --- PyInstaller ---

/// `MEI\014\013\012\013\016` (`pyi_archive.h`).
const COOKIE_MAGIC: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const COOKIE_SIZE: usize = 88;
const TOC_ENTRY_HEADER_SIZE: usize = 18;

/// One CArchive entry: its name, type code and contents, zlib-compressed
/// (level 9, as `CArchiveWriter` writes them) when `compress` is set.
struct PkgEntry {
    name: &'static str,
    typecode: u8,
    contents: Vec<u8>,
    compress: bool,
}

fn pkg_entry(name: &'static str, typecode: u8, contents: &[u8], compress: bool) -> PkgEntry {
    PkgEntry {
        name,
        typecode,
        contents: contents.to_vec(),
        compress,
    }
}

/// A CArchive as `CArchiveWriter` lays it out: each entry's data from
/// offset 0, then the TOC, then the cookie. A TOC entry is `entry_length`,
/// `offset`, stored length, uncompressed length (big-endian 32-bit), the
/// compression flag, the type code and the NUL-terminated name padded so
/// the entry is a multiple of 16 bytes. The cookie is the magic, the
/// package length, the TOC offset and length, the Python version code and
/// the library name NUL-padded to 64 bytes.
fn carchive(entries: &[PkgEntry], python_version: u32, libname: &str) -> Vec<u8> {
    let mut data = Vec::new();
    let mut toc = Vec::new();
    for entry in entries {
        let offset = size32(&data);
        let stored = if entry.compress {
            zlib(&entry.contents)
        } else {
            entry.contents.clone()
        };
        data.extend_from_slice(&stored);
        let entry_length = align(TOC_ENTRY_HEADER_SIZE + entry.name.len() + 1, 16);
        let mut record = Vec::new();
        record.extend_from_slice(&u32::try_from(entry_length).unwrap().to_be_bytes());
        record.extend_from_slice(&offset.to_be_bytes());
        record.extend_from_slice(&size32(&stored).to_be_bytes());
        record.extend_from_slice(&size32(&entry.contents).to_be_bytes());
        record.push(u8::from(entry.compress));
        record.push(entry.typecode);
        record.extend_from_slice(entry.name.as_bytes());
        record.resize(entry_length, 0);
        toc.extend_from_slice(&record);
    }
    let toc_offset = size32(&data);
    data.extend_from_slice(&toc);
    let pkg_length = size32(&data) + u32::try_from(COOKIE_SIZE).unwrap();
    data.extend_from_slice(COOKIE_MAGIC);
    data.extend_from_slice(&pkg_length.to_be_bytes());
    data.extend_from_slice(&toc_offset.to_be_bytes());
    data.extend_from_slice(&size32(&toc).to_be_bytes());
    data.extend_from_slice(&python_version.to_be_bytes());
    let mut name = libname.as_bytes().to_vec();
    name.resize(64, 0);
    data.extend_from_slice(&name);
    data
}

/// Marshalled-code stand-in: Python bytecode is opaque to the parser, so
/// any bytes do.
const CODE_OBJECT: &[u8] = b"\xe3\0\0\0\0zrax python code object";

/// A one-file build's archive: two bootstrap modules and the entry script
/// (compressed, as `PKG.cdict` compresses them), the Python library (an
/// x86-64 ELF, compressed), an AArch64 extension module stored as-is, a
/// text data file, a run-time option and a stored PYZ archive.
fn onefile_entries() -> Vec<PkgEntry> {
    vec![
        pkg_entry("struct", b'm', CODE_OBJECT, true),
        pkg_entry("pyimod01_archive", b'm', CODE_OBJECT, true),
        pkg_entry("main", b's', CODE_OBJECT, true),
        pkg_entry(
            "_ssl.cpython-312-aarch64-linux-gnu.so",
            b'b',
            AARCH64_ELF,
            false,
        ),
        pkg_entry("libpython3.12.so.1.0", b'b', X86_64_ELF, true),
        pkg_entry("o pyi-contents-directory _internal", b'o', b"", false),
        pkg_entry(
            "certifi/cacert.pem",
            b'x',
            b"-----BEGIN CERTIFICATE-----\n",
            true,
        ),
        pkg_entry(
            "PYZ.pyz",
            b'z',
            b"PYZ\0\xcb\x0d\x0d\x0a\0\0\0\x11zrax",
            false,
        ),
    ]
}

fn onefile_archive() -> Vec<u8> {
    carchive(&onefile_entries(), 312, "libpython3.12.so.1.0")
}

/// The file offset of `name`'s data in a [`carchive`] of `entries`.
fn entry_offset(entries: &[PkgEntry], name: &str) -> usize {
    let mut offset = 0;
    for entry in entries {
        if entry.name == name {
            return offset;
        }
        offset += if entry.compress {
            zlib(&entry.contents).len()
        } else {
            entry.contents.len()
        };
    }
    panic!("entry {name}")
}

/// The offset of entry `index`'s TOC record from the TOC start.
fn toc_record(entries: &[PkgEntry], index: usize) -> usize {
    entries[..index]
        .iter()
        .map(|entry| align(TOC_ENTRY_HEADER_SIZE + entry.name.len() + 1, 16))
        .sum()
}

/// The file offset of the cookie in an archive.
fn cookie_offset(archive: &[u8]) -> usize {
    archive.len() - COOKIE_SIZE
}

#[test]
fn pyinstaller_archive_is_recognized_standalone_and_lists_its_binaries() {
    let data = onefile_archive();
    assert_eq!(appbundle::detect(&data), Some(Layout::PyInstaller));
    assert_eq!(appbundle::detect_embedded(&data), None);
    let c = parse(&data, Layout::PyInstaller);
    assert_eq!(c.format, FileFormat::PyInstaller);
    assert_eq!(c.target, None);
    assert_eq!(c.consumed, data.len());
    assert!(has_note(
        &c,
        "Python 3.12; Python library libpython3.12.so.1.0"
    ));
    assert!(has_note(
        &c,
        "TOC: 2 binaries, 1 data file, 1 Python script and 2 bootstrap modules"
    ));
    assert!(has_note(
        &c,
        "Run-time options: o pyi-contents-directory _internal"
    ));
    assert!(has_note(
        &c,
        "2 of 3 files are in a recognized format and listed"
    ));
    // The Python library the cookie names leads the members.
    assert_eq!(
        labels(&c),
        [
            "Python script main (Python bytecode)",
            "PYZ archive PYZ.pyz (Python bytecode)",
            "libpython3.12.so.1.0",
            "_ssl.cpython-312-aarch64-linux-gnu.so",
        ]
    );
    let entries = onefile_entries();
    let library = child(&c, "libpython3.12.so.1.0");
    assert_eq!(
        library.offset,
        entry_offset(&entries, "libpython3.12.so.1.0")
    );
    assert_eq!(library.stored_size, zlib(X86_64_ELF).len());
    assert_eq!(library.transform, Some("zlib"));
    assert_eq!(&library.data[..], X86_64_ELF);
    let script = child(&c, "Python script main (Python bytecode)");
    assert!(script.opaque);

    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::PyInstaller);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let library = slice(&p, "libpython3.12.so.1.0");
    assert_eq!(library.isa, Isa::X86_64);
    let decoded = library.decoded.as_ref().expect("decoded range");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("zlib", 256));
    let extension = slice(&p, "_ssl.cpython-312-aarch64-linux-gnu.so");
    assert_eq!(extension.isa, Isa::AArch64);
    assert_eq!(extension.decoded, None);
    assert_eq!(
        extension.offset as usize,
        entry_offset(&entries, "_ssl.cpython-312-aarch64-linux-gnu.so")
    );
    assert!(matches!(
        slice(&p, "Python script main (Python bytecode)").isa,
        Isa::Unknown(_)
    ));
    assert!(payload_has_note(
        &p,
        "Python script main (Python bytecode): opaque; payload ISA analysis skipped"
    ));
}

#[test]
fn pyinstaller_python_versions_use_both_encodings() {
    let entries = [pkg_entry("main", b's', CODE_OBJECT, true)];
    let old = carchive(&entries, 36, "python36.dll");
    assert!(has_note(
        &parse(&old, Layout::PyInstaller),
        "Python 3.6; Python library python36.dll"
    ));
    let odd = carchive(&entries, 7, "python.dll");
    assert!(has_note(
        &parse(&odd, Layout::PyInstaller),
        "Unknown Python version code 7; Python library python.dll"
    ));
}

#[test]
fn pyinstaller_archive_after_a_pe_host_keeps_the_host_format() {
    let mut data = x86_64_pe().to_vec();
    let host = data.len();
    data.extend_from_slice(&onefile_archive());
    // A signature or other data after the archive (macOS re-signs the
    // executable after appending it).
    data.extend_from_slice(&[0xaa; 0x200]);

    assert_eq!(appbundle::detect(&data), None);
    assert_eq!(appbundle::detect_embedded(&data), Some(Layout::PyInstaller));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Pe);
    assert_eq!(p.primary.isa, Isa::X86_64);

    let c = parse(&data, Layout::PyInstaller);
    assert!(has_note(&c, &format!("Archive at file offset 0x{host:X}")));
    assert!(has_note(&c, "512 B after the archive"));
    let entries = onefile_entries();
    let extension = child(&c, "_ssl.cpython-312-aarch64-linux-gnu.so");
    assert_eq!(
        extension.offset,
        host + entry_offset(&entries, "_ssl.cpython-312-aarch64-linux-gnu.so")
    );
    assert_eq!(&extension.data[..], AARCH64_ELF);
}

#[test]
fn pyinstaller_archive_in_an_elf_section_keeps_the_host_format() {
    // objcopy places the `pydata` section before the section headers, so
    // the cookie is not at the end of the file.
    let mut data = AARCH64_ELF.to_vec();
    data.extend_from_slice(&onefile_archive());
    data.extend_from_slice(&[0; 0x140]);
    assert_eq!(appbundle::detect_embedded(&data), Some(Layout::PyInstaller));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::AArch64);
    let c = parse(&data, Layout::PyInstaller);
    assert_eq!(child(&c, "libpython3.12.so.1.0").data.len(), 256);
}

#[test]
fn pyinstaller_side_load_signature_is_not_an_archive() {
    let mut data = x86_64_pe().to_vec();
    data.extend_from_slice(b"MEI\x0d\x0b\x0a\x0b\x0e");
    assert_eq!(appbundle::detect_embedded(&data), None);
    assert!(parse_error(&data, Layout::PyInstaller).contains("Missing PyInstaller cookie"));
}

#[test]
fn pyinstaller_nested_archives_and_unknown_entries_are_reported() {
    let inner = carchive(&[pkg_entry("main", b's', CODE_OBJECT, true)], 312, "Python");
    let entries = [
        pkg_entry("main", b's', CODE_OBJECT, true),
        pkg_entry("inner.pkg", b'a', &inner, true),
        pkg_entry("lib/libfoo.so", b'n', b"libfoo.so.1\0", false),
        pkg_entry("dep", b'd', b"", false),
        pkg_entry("mystery", b'q', b"?", false),
        pkg_entry("splash", b'l', b"tcl tk", true),
    ];
    let data = carchive(&entries, 312, "Python");
    let c = parse(&data, Layout::PyInstaller);
    // A nested archive is recognized from its whole bytes: its cookie is at
    // the end.
    assert_eq!(child(&c, "inner.pkg").data.len(), inner.len());
    assert!(child(&c, "Splash screen resources splash").opaque);
    assert!(has_note(&c, "1 symbolic link (not followed)"));
    assert!(has_note(&c, "1 dependency on files in other archives"));
    assert!(has_note(
        &c,
        "Unknown type codes, not analyzed: mystery (0x71)"
    ));
    let p = classify(&data);
    assert!(matches!(slice(&p, "inner.pkg").isa, Isa::Unknown(_)));
}

#[test]
fn pyinstaller_corrupt_fields_are_errors() {
    let data = onefile_archive();
    let cookie = cookie_offset(&data);
    let toc_offset = u32::from_be_bytes(data[cookie + 12..cookie + 16].try_into().unwrap());
    let toc = usize::try_from(toc_offset).unwrap();

    let mut longer = data.clone();
    put(&mut longer, cookie + 8, &(size32(&data) + 1).to_be_bytes());
    assert!(parse_error(&longer, Layout::PyInstaller).contains("Invalid package length"));
    // The cookie no longer declares the input's size.
    assert_eq!(appbundle::detect(&longer), None);

    let mut toc_short = data.clone();
    put(&mut toc_short, cookie + 16, &16u32.to_be_bytes());
    assert!(parse_error(&toc_short, Layout::PyInstaller)
        .contains("the TOC must end at the 88-byte cookie"));
    // A package length shorter than the cookie itself.
    let mut tiny = data.clone();
    put(&mut tiny, cookie + 8, &10u32.to_be_bytes());
    assert!(parse_error(&tiny, Layout::PyInstaller).contains("in a 10 B archive"));
    assert_eq!(appbundle::detect(&toc_short), Some(Layout::PyInstaller));

    let mut no_library = data.clone();
    put(&mut no_library, cookie + 24, &[0; 64]);
    assert!(parse_error(&no_library, Layout::PyInstaller).contains("Missing Python library name"));

    let mut short_entry = data.clone();
    put(&mut short_entry, toc, &17u32.to_be_bytes());
    assert_eq!(
        parse_error(&short_entry, Layout::PyInstaller),
        format!("Application bundle parse error: Invalid TOC entry length 17 B at 0x{toc:X}")
    );

    let mut outside = data.clone();
    put(&mut outside, toc + 4, &toc_offset.to_be_bytes());
    assert!(parse_error(&outside, Layout::PyInstaller).contains("Invalid data range"));

    // The stored extension module (entry 3) declares another size.
    let mut sizes = data.clone();
    let record = toc + toc_record(&onefile_entries(), 3);
    put(&mut sizes, record + 12, &255u32.to_be_bytes());
    assert!(parse_error(&sizes, Layout::PyInstaller).contains("differs from uncompressed"));
}

#[test]
fn pyinstaller_damaged_members_are_noted() {
    let entries = onefile_entries();
    let mut data = onefile_archive();
    let library = entry_offset(&entries, "libpython3.12.so.1.0");
    // Corrupt the zlib stream's Adler-32, then its first block.
    let end = library + zlib(X86_64_ELF).len();
    data[end - 1] ^= 0xff;
    let c = parse(&data, Layout::PyInstaller);
    assert!(has_note(
        &c,
        "1 file did not decode to the declared size: libpython3.12.so.1.0"
    ));
    assert!(!labels(&c).iter().any(|l| l == "libpython3.12.so.1.0"));
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::AArch64);
}

#[test]
fn pyinstaller_truncations_are_not_archives() {
    let data = onefile_archive();
    for end in 0..data.len() {
        let prefix = &data[..end];
        assert!(
            container::parse(prefix, Kind::AppBundle(Layout::PyInstaller)).is_err(),
            "prefix of {end} B parses"
        );
        assert_eq!(appbundle::detect(prefix), None, "prefix of {end} B");
    }
    for end in (0..data.len()).step_by(7) {
        let claimed = detect_payload(&data[..end], &ClassifierOptions::new())
            .is_ok_and(|p| p.format.format == FileFormat::PyInstaller);
        assert!(!claimed, "prefix of {end} B classifies as PyInstaller");
    }
}

/// Single-byte mutations (0x00, 0xFF, bit flip) of every `step`-th byte
/// and of every byte in `dense`, parsed and classified without panicking.
fn mutation_sweep(data: &[u8], layout: Layout, dense: std::ops::Range<usize>, step: usize) {
    let positions = dense.chain((0..data.len()).step_by(step));
    for i in positions.filter(|i| *i < data.len()) {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.to_vec();
            mutated[i] = value;
            let _ = container::parse(&mutated, Kind::AppBundle(layout));
            let _ = appbundle::detect_embedded(&mutated);
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

#[test]
fn pyinstaller_mutations_do_not_panic() {
    let data = onefile_archive();
    let toc = usize::try_from(u32::from_be_bytes(
        data[cookie_offset(&data) + 12..cookie_offset(&data) + 16]
            .try_into()
            .unwrap(),
    ))
    .unwrap();
    mutation_sweep(&data, Layout::PyInstaller, toc..data.len(), 5);
}

// --- Electron ASAR ---

/// Sizes in [`SAMPLE_ASAR`]: `header_size` (1376) and the start of the
/// file data, 8 bytes later.
const SAMPLE_HEADER_SIZE: usize = 1376;
const SAMPLE_DATA_START: usize = 8 + SAMPLE_HEADER_SIZE;

#[test]
fn asar_fixture_lists_native_modules_with_verified_hashes() {
    assert_eq!(appbundle::detect(SAMPLE_ASAR), Some(Layout::Asar));
    let c = parse(SAMPLE_ASAR, Layout::Asar);
    assert_eq!(c.format, FileFormat::Asar);
    assert_eq!(c.consumed, SAMPLE_ASAR.len());
    assert!(has_note(
        &c,
        "ASAR header: 1376 B (1368 B of JSON); 4 files in the archive, 1 file in the .unpacked \
         directory, 4 directories, 1 link"
    ));
    assert!(has_note(
        &c,
        "Integrity: 4 of 4 declared SHA-256 file hashes verified; block hashes not verified"
    ));
    assert!(has_note(&c, "1 file marked executable"));
    assert!(has_note(
        &c,
        "2 of 4 files are in a recognized format and listed"
    ));
    assert_eq!(labels(&c), ["native/aarch64.node", "native/x86_64.node"]);

    let p = classify(SAMPLE_ASAR);
    assert_eq!(p.format.format, FileFormat::Asar);
    assert_eq!(p.primary.isa, Isa::AArch64);
    let arm = slice(&p, "native/aarch64.node");
    assert_eq!(
        (arm.isa, arm.offset, arm.size),
        (Isa::AArch64, (SAMPLE_DATA_START + 67) as u64, 256)
    );
    let x86 = slice(&p, "native/x86_64.node");
    assert_eq!(
        (x86.isa, x86.offset, x86.size),
        (Isa::X86_64, (SAMPLE_DATA_START + 323) as u64, 256)
    );
}

/// An ASAR archive as `createFilesystemWriteStream` writes it: the size
/// pickle (payload size 4, `header_size`), the header pickle (payload size
/// `header_size - 4`, the string length, the JSON zero-padded to four
/// bytes), then `files`.
fn asar(json: &str, files: &[u8]) -> Vec<u8> {
    let padded = align(json.len(), 4);
    let header_size = u32::try_from(8 + padded).unwrap();
    let mut data = Vec::new();
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&header_size.to_le_bytes());
    data.extend_from_slice(&(header_size - 4).to_le_bytes());
    data.extend_from_slice(&u32::try_from(json.len()).unwrap().to_le_bytes());
    data.extend_from_slice(json.as_bytes());
    data.resize(16 + padded, 0);
    data.extend_from_slice(files);
    data
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// One file `addon.node` holding `contents` at offset 0, with an integrity
/// hash of `hashed`.
fn asar_addon(contents: &[u8], hashed: &[u8]) -> Vec<u8> {
    let hash = sha256_hex(hashed);
    let json = serde_json::json!({
        "files": {
            "addon.node": {
                "size": contents.len(),
                "offset": "0",
                "integrity": {
                    "algorithm": "SHA256",
                    "hash": hash,
                    "blockSize": 4_194_304,
                    "blocks": [hash],
                },
            },
        },
    });
    asar(&json.to_string(), contents)
}

#[test]
fn asar_headers_written_with_whitespace_are_recognized() {
    let json = r#"{ "files": { "a.node": { "size": 256, "offset": "0" } } }"#;
    let data = asar(json, X86_64_ELF);
    assert_eq!(appbundle::detect(&data), Some(Layout::Asar));
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::Asar);
    assert_eq!(slice(&p, "a.node").isa, Isa::X86_64);
}

#[test]
fn asar_integrity_mismatches_are_noted() {
    let data = asar_addon(X86_64_ELF, b"other contents");
    let c = parse(&data, Layout::Asar);
    assert!(has_note(
        &c,
        "Integrity: 0 of 1 declared SHA-256 file hashes verified"
    ));
    assert!(has_note(&c, "SHA-256 mismatch for 1 file: addon.node"));
    let good = asar_addon(X86_64_ELF, X86_64_ELF);
    assert!(has_note(
        &parse(&good, Layout::Asar),
        "Integrity: 1 of 1 declared SHA-256 file hashes verified"
    ));
}

#[test]
fn asar_framing_must_agree_before_recognition() {
    let data = asar_addon(X86_64_ELF, X86_64_ELF);
    let mut size_payload = data.clone();
    put(&mut size_payload, 0, &5u32.to_le_bytes());
    assert_eq!(appbundle::detect(&size_payload), None);
    let mut header_payload = data.clone();
    put(&mut header_payload, 8, &3u32.to_le_bytes());
    assert_eq!(appbundle::detect(&header_payload), None);
    let mut length = data.clone();
    let declared = u32::from_le_bytes(data[12..16].try_into().unwrap());
    put(&mut length, 12, &(declared + 4).to_le_bytes());
    assert_eq!(appbundle::detect(&length), None);
    let not_files = asar(r#"{"file":{}}"#, b"");
    assert_eq!(appbundle::detect(&not_files), None);
    assert!(parse_error(&size_payload, Layout::Asar).contains("Invalid ASAR size pickle"));
    assert!(parse_error(&header_payload, Layout::Asar).contains("header pickle payload size"));
    assert!(parse_error(&length, Layout::Asar).contains("Invalid ASAR header string length"));
}

#[test]
fn asar_corrupt_trees_are_errors() {
    let cases = [
        (
            r#"{"files":{"a":{"size":1,"offset":"0"},}}"#,
            "Invalid ASAR header JSON",
        ),
        (
            r#"{"files":{"a/b":{"size":1,"offset":"0"}}}"#,
            "Invalid ASAR entry name a/b",
        ),
        (
            r#"{"files":{"..":{"files":{}}}}"#,
            "Invalid ASAR entry name ..",
        ),
        (
            r#"{"files":{"a":{"size":1,"offset":"0x1"}}}"#,
            "offset is not a decimal string",
        ),
        (
            r#"{"files":{"a":{"size":-1,"offset":"0"}}}"#,
            "size is not a non-negative integer",
        ),
        (
            r#"{"files":{"a":{"size":1.5,"offset":"0"}}}"#,
            "size is not a non-negative integer",
        ),
        (r#"{"files":{"a":{"size":1}}}"#, "neither a directory"),
        (
            r#"{"files":{"a":{"link":""}}}"#,
            "link is not a non-empty string",
        ),
        (r#"{"files":{"a":{"files":[]}}}"#, "files is not an object"),
        (
            r#"{"files":{"a":{"size":1,"offset":"0","executable":1}}}"#,
            "executable is not a boolean",
        ),
        (
            r#"{"files":{"a":{"size":1,"offset":"0","integrity":{"algorithm":"SHA256","hash":"00","blockSize":0,"blocks":[]}}}}"#,
            "integrity.blockSize is not a positive number",
        ),
        (
            r#"{"files":{"a":{"size":1,"offset":"300"}}}"#,
            "Invalid ASAR file range for /a",
        ),
        (
            r#"{"files":{"a":{"size":1,"offset":"18446744073709551615"}}}"#,
            "Invalid ASAR file range",
        ),
        (
            r#"{"files":{"a":{"size":1,"offset":"18446744073709551616"}}}"#,
            "offset does not fit",
        ),
    ];
    for (json, message) in cases {
        let data = asar(json, b"x");
        assert_eq!(appbundle::detect(&data), Some(Layout::Asar), "{json}");
        let error = parse_error(&data, Layout::Asar);
        assert!(error.contains(message), "{json}: {error}");
    }
    // 70 nested directories exceed the JSON parser's nesting limit.
    let deep = format!(
        "{{\"files\":{}{{}}{}}}",
        r#"{"d":{"files":"#.repeat(70),
        "}}".repeat(70)
    );
    let error = parse_error(&asar(&deep, b""), Layout::Asar);
    assert!(error.contains("Invalid ASAR header JSON"), "{error}");
}

#[test]
fn asar_truncations_and_mutations_are_bounded() {
    for end in 0..SAMPLE_ASAR.len() {
        assert!(
            container::parse(&SAMPLE_ASAR[..end], Kind::AppBundle(Layout::Asar)).is_err(),
            "prefix of {end} B parses"
        );
    }
    // A prefix that holds the whole header is still recognized as ASAR,
    // and becomes a parse error once a file range does not fit.
    let header_only = &SAMPLE_ASAR[..SAMPLE_DATA_START];
    assert_eq!(appbundle::detect(header_only), Some(Layout::Asar));
    mutation_sweep(SAMPLE_ASAR, Layout::Asar, 0..64, 3);
}

// --- .NET single-file bundles ---

/// The bundle signature (`bundle_marker.cpp`).
const BUNDLE_SIGNATURE: [u8; 32] = [
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];

/// Where the host keeps its 40-byte bundle marker.
const MARKER_AT: usize = 0x80;

/// `file_type_t` values.
const ASSEMBLY: u8 = 1;
const NATIVE_BINARY: u8 = 2;
const DEPS_JSON: u8 = 3;
const RUNTIME_CONFIG_JSON: u8 = 4;

/// One bundled file: relative path, type, contents, and whether it is
/// stored compressed (raw DEFLATE, version 6 only).
struct BundleFile {
    path: &'static str,
    kind: u8,
    contents: Vec<u8>,
    compress: bool,
}

fn bundle_file(path: &'static str, kind: u8, contents: &[u8], compress: bool) -> BundleFile {
    BundleFile {
        path,
        kind,
        contents: contents.to_vec(),
        compress,
    }
}

/// A `BinaryWriter` string: the 7-bit-encoded length, then UTF-8.
fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut length = value.len();
    while length >= 0x80 {
        out.push(u8::try_from(length & 0x7f).unwrap() | 0x80);
        length >>= 7;
    }
    out.push(u8::try_from(length).unwrap());
    out.extend_from_slice(value.as_bytes());
    out
}

/// The deterministic bundle ID: base64url of the SHA-256 over each file's
/// SHA-256, first 12 characters (`Manifest.GenerateDeterministicId`).
fn deterministic_id(files: &[BundleFile]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(Sha256::digest(&file.contents));
    }
    let digest = hasher.finalize();
    let mut id = String::new();
    for group in digest[..9].chunks(3) {
        let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        for shift in [18, 12, 6, 0] {
            id.push(char::from(ALPHABET[(bits >> shift & 0x3f) as usize]));
        }
    }
    id
}

/// A built bundle and where its parts landed.
struct Bundle {
    data: Vec<u8>,
    /// File offset of each file's stored bytes.
    offsets: Vec<usize>,
    /// File offset of the header.
    header: usize,
}

/// `host` with the bundle marker at [`MARKER_AT`] (the header offset, then
/// the signature), each file (assemblies aligned to 64 bytes, as
/// `Bundler.AddToBundle` aligns them on x64), then the header: major
/// version, minor version 0, file count, bundle ID, and from version 2 the
/// `deps.json` and `runtimeconfig.json` locations and zero flags; then one
/// entry per file: offset, size, from version 6 the compressed size, type,
/// path.
fn dotnet_bundle(host: &[u8], major: u32, id: &str, files: &[BundleFile]) -> Bundle {
    let mut data = host.to_vec();
    let mut offsets = Vec::new();
    let mut stored_sizes = Vec::new();
    for file in files {
        if file.kind == ASSEMBLY {
            data.resize(align(data.len(), 64), 0);
        }
        offsets.push(data.len());
        let stored = if file.compress {
            raw_deflate(&file.contents)
        } else {
            file.contents.clone()
        };
        stored_sizes.push(if file.compress { stored.len() } else { 0 });
        data.extend_from_slice(&stored);
    }
    let header = data.len();
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&i32::try_from(files.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&text(id));
    let location = |kind: u8| {
        files
            .iter()
            .position(|f| f.kind == kind)
            .map_or((0i64, 0i64), |i| {
                (offsets[i] as i64, files[i].contents.len() as i64)
            })
    };
    if major >= 2 {
        for kind in [DEPS_JSON, RUNTIME_CONFIG_JSON] {
            let (offset, size) = location(kind);
            data.extend_from_slice(&offset.to_le_bytes());
            data.extend_from_slice(&size.to_le_bytes());
        }
        data.extend_from_slice(&0u64.to_le_bytes());
    }
    for (i, file) in files.iter().enumerate() {
        data.extend_from_slice(&(offsets[i] as i64).to_le_bytes());
        data.extend_from_slice(&(file.contents.len() as i64).to_le_bytes());
        if major >= 6 {
            data.extend_from_slice(&(stored_sizes[i] as i64).to_le_bytes());
        }
        data.push(file.kind);
        data.extend_from_slice(&text(file.path));
    }
    put(&mut data, MARKER_AT, &(header as i64).to_le_bytes());
    put(&mut data, MARKER_AT + 8, &BUNDLE_SIGNATURE);
    Bundle {
        data,
        offsets,
        header,
    }
}

const DEPS: &[u8] = br#"{"runtimeTarget":{"name":".NETCoreApp,Version=v10.0"}}"#;
const RUNTIME_CONFIG: &[u8] = br#"{"runtimeOptions":{"tfm":"net10.0"}}"#;

/// A version 6 bundle: the managed app assembly, a native AArch64 library
/// compressed with raw DEFLATE, and the two configuration files.
fn net6_files() -> Vec<BundleFile> {
    vec![
        bundle_file("zraxapp.dll", ASSEMBLY, &il_only_assembly(), false),
        bundle_file("libzraxnative.so", NATIVE_BINARY, AARCH64_ELF, true),
        bundle_file(
            "zraxapp.runtimeconfig.json",
            RUNTIME_CONFIG_JSON,
            RUNTIME_CONFIG,
            false,
        ),
        bundle_file("zraxapp.deps.json", DEPS_JSON, DEPS, false),
    ]
}

fn net6_bundle() -> Bundle {
    let files = net6_files();
    dotnet_bundle(X86_64_ELF, 6, &deterministic_id(&files), &files)
}

#[test]
fn dotnet_bundle_host_keeps_its_format_and_the_members_classify_on_their_own() {
    let bundle = net6_bundle();
    let data = &bundle.data;
    assert_eq!(appbundle::detect(data), None);
    assert_eq!(appbundle::detect_embedded(data), Some(Layout::DotnetBundle));
    let p = classify(data);
    assert_eq!(p.format.format, FileFormat::Elf);
    assert_eq!(p.primary.isa, Isa::X86_64);

    let c = parse(data, Layout::DotnetBundle);
    assert_eq!(c.format, FileFormat::DotnetBundle);
    let files = net6_files();
    let id = deterministic_id(&files);
    assert!(has_note(
        &c,
        &format!(
        "Bundle version 6.0 (written for .NET 6 and later); bundle ID {id}; 4 files: 1 assembly, 1 \
         native binary, 0 symbol files, 2 configuration files and 0 other files"
    )
    ));
    assert!(has_note(
        &c,
        &format!("Bundle ID {id} matches the SHA-256 of the files' contents")
    ));
    assert!(has_note(
        &c,
        &format!("deps.json: zraxapp.deps.json ({} B)", DEPS.len())
    ));
    assert!(has_note(
        &c,
        &format!(
            "runtimeconfig.json: zraxapp.runtimeconfig.json ({} B)",
            RUNTIME_CONFIG.len()
        )
    ));
    assert!(has_note(&c, "1 file compressed with raw DEFLATE"));
    assert!(has_note(
        &c,
        &format!(
            "Bundle marker at 0x{MARKER_AT:X} in the apphost; manifest at 0x{:X}",
            bundle.header
        )
    ));
    assert_eq!(labels(&c), ["zraxapp.dll", "libzraxnative.so"]);
    let native = child(&c, "libzraxnative.so");
    assert_eq!(native.offset, bundle.offsets[1]);
    assert_eq!(native.stored_size, raw_deflate(AARCH64_ELF).len());
    assert_eq!(native.transform, Some("DEFLATE"));
    assert_eq!(&native.data[..], AARCH64_ELF);
    assert_eq!(child(&c, "zraxapp.dll").offset % 64, 0);

    // Classified as a container on its own (as a host hook would), the
    // managed assembly is CIL and the native library AArch64.
    let managed = classify(&child(&c, "zraxapp.dll").data);
    assert_eq!(managed.primary.isa, Isa::Clr);
    let native = classify(&child(&c, "libzraxnative.so").data);
    assert_eq!(native.primary.isa, Isa::AArch64);
}

#[test]
fn dotnet_bundle_versions_one_and_two_have_their_own_layouts() {
    let v2_files = vec![
        bundle_file("app.dll", ASSEMBLY, &il_only_assembly(), false),
        bundle_file("app.deps.json", DEPS_JSON, DEPS, false),
    ];
    let v2 = dotnet_bundle(X86_64_ELF, 2, "AbCdEfGhIjKl", &v2_files);
    let c = parse(&v2.data, Layout::DotnetBundle);
    assert!(has_note(&c, "Bundle version 2.0 (written for .NET 5)"));
    assert!(has_note(
        &c,
        "Bundle ID AbCdEfGhIjKl is not the SHA-256 of the files' contents"
    ));
    assert_eq!(labels(&c), ["app.dll"]);

    let v1_files = vec![
        bundle_file("app.dll", 0, &il_only_assembly(), false),
        bundle_file("libnative.so", 0, X86_64_ELF, false),
    ];
    let v1 = dotnet_bundle(AARCH64_ELF, 1, &deterministic_id(&v1_files), &v1_files);
    let c = parse(&v1.data, Layout::DotnetBundle);
    assert!(has_note(&c, "Bundle version 1.0 (written for .NET Core 3)"));
    assert!(has_note(&c, "0 configuration files and 2 other files"));
    assert_eq!(labels(&c), ["app.dll", "libnative.so"]);
    assert_eq!(classify(&v1.data).format.format, FileFormat::Elf);
}

#[test]
fn dotnet_bundle_corrupt_fields_are_errors() {
    let bundle = net6_bundle();
    let header = bundle.header;
    let id_size = 1 + 12;
    let entries = header + 12 + id_size + 40;

    let mut not_bundle = bundle.data.clone();
    put(&mut not_bundle, MARKER_AT, &0i64.to_le_bytes());
    assert_eq!(appbundle::detect_embedded(&not_bundle), None);
    assert!(parse_error(&not_bundle, Layout::DotnetBundle).contains("holds header offset 0"));

    let mut negative = bundle.data.clone();
    put(&mut negative, MARKER_AT, &(-8i64).to_le_bytes());
    assert!(
        parse_error(&negative, Layout::DotnetBundle).contains("Invalid bundle header offset -8")
    );

    let mut version = bundle.data.clone();
    put(&mut version, header, &7u32.to_le_bytes());
    assert_eq!(appbundle::detect_embedded(&version), None);
    assert_eq!(
        parse_error(&version, Layout::DotnetBundle),
        format!("Application bundle parse error: Unsupported bundle version 7.0 at 0x{header:X}")
    );

    let mut count = bundle.data.clone();
    put(&mut count, header + 8, &1000i32.to_le_bytes());
    assert!(parse_error(&count, Layout::DotnetBundle).contains("Invalid file count 1000"));
    let mut zero = bundle.data.clone();
    put(&mut zero, header + 8, &0i32.to_le_bytes());
    assert!(parse_error(&zero, Layout::DotnetBundle).contains("Invalid file count 0"));

    let mut overlap = bundle.data.clone();
    put(&mut overlap, entries + 8, &4096i64.to_le_bytes());
    assert!(parse_error(&overlap, Layout::DotnetBundle).contains("Invalid range"));

    let mut in_host = bundle.data.clone();
    put(&mut in_host, entries, &16i64.to_le_bytes());
    assert!(parse_error(&in_host, Layout::DotnetBundle).contains("bundle marker end"));

    let mut kind = bundle.data.clone();
    put(&mut kind, entries + 24, &[6]);
    assert!(parse_error(&kind, Layout::DotnetBundle).contains("Unknown file type 6"));

    let mut path = bundle.data.clone();
    put(&mut path, entries + 25, &[0x81, 0x80]);
    assert!(parse_error(&path, Layout::DotnetBundle).contains("more than two length bytes"));

    let mut empty_id = bundle.data.clone();
    put(&mut empty_id, header + 12, &[0]);
    assert!(parse_error(&empty_id, Layout::DotnetBundle).contains("Invalid bundle ID"));
}

#[test]
fn dotnet_bundle_inconsistencies_are_noted() {
    let bundle = net6_bundle();
    let header = bundle.header;
    let mut location = bundle.data.clone();
    // The header's deps.json size disagrees with its manifest entry.
    put(&mut location, header + 12 + 13 + 8, &1i64.to_le_bytes());
    let c = parse(&location, Layout::DotnetBundle);
    assert!(has_note(
        &c,
        "The header's deps.json location does not match the manifest's deps.json entry"
    ));

    let mut damaged = bundle.data.clone();
    let native = bundle.offsets[1];
    damaged[native] ^= 0xff;
    let c = parse(&damaged, Layout::DotnetBundle);
    assert!(has_note(
        &c,
        "1 file did not decode to the declared size: libzraxnative.so"
    ));
    assert!(has_note(&c, "not checked: not every file was decoded"));

    let mut contents = bundle.data.clone();
    contents[bundle.offsets[0] + 0x300] ^= 0x01;
    let c = parse(&contents, Layout::DotnetBundle);
    assert!(has_note(&c, "is not the SHA-256 of the files' contents"));
}

#[test]
fn dotnet_bundle_truncations_and_mutations_are_bounded() {
    let bundle = net6_bundle();
    for end in 0..bundle.data.len() {
        assert!(
            container::parse(&bundle.data[..end], Kind::AppBundle(Layout::DotnetBundle)).is_err(),
            "prefix of {end} B parses"
        );
    }
    mutation_sweep(
        &bundle.data,
        Layout::DotnetBundle,
        bundle.header..bundle.data.len(),
        9,
    );
    mutation_sweep(
        &bundle.data,
        Layout::DotnetBundle,
        MARKER_AT..MARKER_AT + 40,
        64,
    );
}

// --- Real samples ---

/// Regular files under `dir` (symbolic links followed) up to 600 MiB.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            files(&path, out);
        } else if meta.len() <= 600 << 20 {
            out.push(path);
        }
    }
}

/// Real bundles in `APPBUNDLE_SAMPLE_DIR` (read in place, never copied):
/// every standalone bundle and every bundle inside an executable parses
/// and lists members or notes, and an executable keeps its own format.
#[test]
fn bundles_in_appbundle_sample_dir_parse() {
    let Some(dir) = std::env::var_os("APPBUNDLE_SAMPLE_DIR").map(PathBuf::from) else {
        eprintln!("skipped: APPBUNDLE_SAMPLE_DIR is not set");
        return;
    };
    let mut all = Vec::new();
    files(&dir, &mut all);
    let mut parsed = 0;
    for path in &all {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        let name = path.display();
        let layout = match (appbundle::detect(&data), appbundle::detect_embedded(&data)) {
            (Some(layout), _) => {
                assert_eq!(classify(&data).format.format, layout.format(), "{name}");
                layout
            }
            (None, Some(layout)) => {
                let format = classify(&data).format.format;
                assert!(
                    matches!(
                        format,
                        FileFormat::Elf | FileFormat::Pe | FileFormat::MachO | FileFormat::MachOFat
                    ),
                    "{name}: host classified as {format}"
                );
                layout
            }
            (None, None) => continue,
        };
        let c = container::parse(&data, Kind::AppBundle(layout))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        eprintln!(
            "{name}: {layout:?}, {} children; {}",
            c.children.len(),
            c.notes.join(" | ")
        );
        parsed += 1;
    }
    eprintln!(
        "{parsed} of {} sample files are bundles and parse",
        all.len()
    );
}

/// IDA's test inputs (`IDA_INPUT_DIR`, read in place, never copied): no
/// input is a bundle, and executables with a synthetic PyInstaller archive
/// appended keep their format and ISA while the archive is found.
#[test]
fn ida_inputs_are_not_bundles_and_keep_their_classification_with_an_archive() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let mut all = Vec::new();
    files(&dir, &mut all);
    all.retain(|path| std::fs::metadata(path).is_ok_and(|m| m.len() <= 64 << 20));
    let archive = onefile_archive();
    let mut wrapped = 0;
    for path in &all {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        let name = path.display();
        assert_eq!(appbundle::detect(&data), None, "{name}");
        assert_eq!(appbundle::detect_embedded(&data), None, "{name}");
        if wrapped >= 40 {
            continue;
        }
        let Ok(own) = detect_payload(&data, &ClassifierOptions::new()) else {
            continue;
        };
        if !matches!(
            own.format.format,
            FileFormat::Elf | FileFormat::Pe | FileFormat::MachO | FileFormat::MachOFat
        ) {
            continue;
        }
        let mut host = data.clone();
        host.extend_from_slice(&archive);
        let with = classify(&host);
        assert_eq!(with.format.format, own.format.format, "{name}");
        assert_eq!(with.primary.isa, own.primary.isa, "{name}");
        assert_eq!(
            appbundle::detect_embedded(&host),
            Some(Layout::PyInstaller),
            "{name}"
        );
        wrapped += 1;
    }
    eprintln!(
        "{} IDA inputs checked: none is a bundle; {wrapped} executables wrapped",
        all.len()
    );
}
