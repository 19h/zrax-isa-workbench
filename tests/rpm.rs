//! RPM packages: the lead, the signature and main header structures and the
//! payload are parsed; payload files are listed when they are a recognized
//! format and classified on their own bytes, with the stored payload range
//! and the decoded size; the header architecture is not ISA evidence;
//! header and payload digests are verified; damaged, truncated and mutated
//! packages are errors or bounded results, never panics. Debian packages
//! (ar archives) reach the ELF in their `data.tar` member.

use sha2::{Digest, Sha256};
use std::io::Write as _;
use zrax::formats::checksum::{self, crc32};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::Kind;
use zrax::formats::{self, rpm, DetectedFormat};
use zrax::{
    detect_payload, ClassifierOptions, ContainedArch, DetectionPayload, FileFormat, Isa,
    MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

/// The synthetic x86-64 ELF header the compressed-stream fixtures share.
fn payload_elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

fn classify(data: &[u8]) -> zrax::Result<DetectionPayload> {
    detect_payload(data, &ClassifierOptions::new())
}

/// Options for the sweeps: raw-dump transforms are searched only for raw
/// input and would dominate the run time of inputs that lose recognition.
fn classify_without_transforms(data: &[u8]) -> zrax::Result<DetectionPayload> {
    let options = ClassifierOptions {
        try_transforms: false,
        ..ClassifierOptions::new()
    };
    detect_payload(data, &options)
}

fn metadata<'a>(payload: &'a DetectionPayload, key: &str) -> Option<&'a MetadataValue> {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| &m.value)
}

fn metadata_text(payload: &DetectionPayload, key: &str) -> String {
    metadata(payload, key)
        .unwrap_or_else(|| panic!("no metadata {key}"))
        .to_string()
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no slice {label}: {:?}", payload.slices))
}

fn error_text(data: &[u8]) -> String {
    classify(data)
        .expect_err("the package is rejected")
        .to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = checksum::Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finish())
}

// --- Header structures (rpm `docs/manual/format_header.md`, LSB 5.0
// section 25.2.2); every integer is big-endian ---------------------------

/// Lead magic, then the header structure magic (`8E AD E8`, version 1,
/// four reserved zero bytes).
const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];

/// Lead size; the signature header follows it.
const LEAD_SIZE: usize = 96;

/// Entry types (`rpmTagType` in `rpmtag.h`).
const RPM_INT16_TYPE: u32 = 3;
const RPM_INT32_TYPE: u32 = 4;
const RPM_INT64_TYPE: u32 = 5;
const RPM_STRING_TYPE: u32 = 6;
const RPM_BIN_TYPE: u32 = 7;
const RPM_STRING_ARRAY_TYPE: u32 = 8;
const RPM_I18NSTRING_TYPE: u32 = 9;

/// Region tags of the signature and main header.
const HEADER_SIGNATURES: u32 = 62;
const HEADER_IMMUTABLE: u32 = 63;

/// Signature tags.
const RPMSIGTAG_RSA: u32 = 268;
const RPMSIGTAG_SHA1: u32 = 269;
const RPMSIGTAG_SHA256: u32 = 272;
const RPMSIGTAG_SIZE: u32 = 1000;
const RPMSIGTAG_MD5: u32 = 1004;
const RPMSIGTAG_PAYLOADSIZE: u32 = 1007;

/// Main header tags.
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_SUMMARY: u32 = 1004;
const RPMTAG_OS: u32 = 1021;
const RPMTAG_ARCH: u32 = 1022;
const RPMTAG_FILEMODES: u32 = 1030;
const RPMTAG_FILEDIGESTS: u32 = 1035;
const RPMTAG_FILEFLAGS: u32 = 1037;
const RPMTAG_SOURCERPM: u32 = 1044;
const RPMTAG_FILEDEVICES: u32 = 1095;
const RPMTAG_FILEINODES: u32 = 1096;
const RPMTAG_DIRINDEXES: u32 = 1116;
const RPMTAG_BASENAMES: u32 = 1117;
const RPMTAG_DIRNAMES: u32 = 1118;
const RPMTAG_PAYLOADFORMAT: u32 = 1124;
const RPMTAG_PAYLOADCOMPRESSOR: u32 = 1125;
const RPMTAG_PAYLOADFLAGS: u32 = 1126;
const RPMTAG_LONGFILESIZES: u32 = 5008;
const RPMTAG_FILEDIGESTALGO: u32 = 5011;
const RPMTAG_PAYLOADSHA256: u32 = 5092;
const RPMTAG_PAYLOADSHA256ALGO: u32 = 5093;
const RPMTAG_PAYLOADSHA256ALT: u32 = 5097;
const RPMTAG_PAYLOADSIZE: u32 = 5112;
const RPMTAG_PAYLOADSIZEALT: u32 = 5113;
const RPMTAG_RPMFORMAT: u32 = 5114;

/// `RPM_HASH_SHA256` (`rpmcrypto.h`).
const RPM_HASH_SHA256: u32 = 8;

/// `RPMFILE_GHOST`: in the header, not in the payload.
const RPMFILE_GHOST: u32 = 1 << 6;

/// File modes.
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// One header entry: tag, type, value count and the stored data.
#[derive(Clone)]
struct Tag {
    tag: u32,
    kind: u32,
    count: u32,
    data: Vec<u8>,
}

/// A `STRING`: the text and its NUL.
fn string_tag(tag: u32, text: &str) -> Tag {
    let mut data = text.as_bytes().to_vec();
    data.push(0);
    Tag {
        tag,
        kind: RPM_STRING_TYPE,
        count: 1,
        data,
    }
}

/// An `I18NSTRING` with one (untranslated) string.
fn i18n_tag(tag: u32, text: &str) -> Tag {
    Tag {
        kind: RPM_I18NSTRING_TYPE,
        ..string_tag(tag, text)
    }
}

/// A `STRING_ARRAY`: each string and its NUL.
fn strings_tag(tag: u32, texts: &[&str]) -> Tag {
    let mut data = Vec::new();
    for text in texts {
        data.extend_from_slice(text.as_bytes());
        data.push(0);
    }
    Tag {
        tag,
        kind: RPM_STRING_ARRAY_TYPE,
        count: texts.len() as u32,
        data,
    }
}

fn int16_tag(tag: u32, values: &[u16]) -> Tag {
    Tag {
        tag,
        kind: RPM_INT16_TYPE,
        count: values.len() as u32,
        data: values.iter().flat_map(|v| v.to_be_bytes()).collect(),
    }
}

fn int32_tag(tag: u32, values: &[u32]) -> Tag {
    Tag {
        tag,
        kind: RPM_INT32_TYPE,
        count: values.len() as u32,
        data: values.iter().flat_map(|v| v.to_be_bytes()).collect(),
    }
}

fn int64_tag(tag: u32, values: &[u64]) -> Tag {
    Tag {
        tag,
        kind: RPM_INT64_TYPE,
        count: values.len() as u32,
        data: values.iter().flat_map(|v| v.to_be_bytes()).collect(),
    }
}

fn bin_tag(tag: u32, bytes: &[u8]) -> Tag {
    Tag {
        tag,
        kind: RPM_BIN_TYPE,
        count: bytes.len() as u32,
        data: bytes.to_vec(),
    }
}

/// Alignment of a type's values in the store.
fn alignment(kind: u32) -> usize {
    match kind {
        RPM_INT16_TYPE => 2,
        RPM_INT32_TYPE => 4,
        RPM_INT64_TYPE => 8,
        _ => 1,
    }
}

/// A header structure: intro (magic, entry count, store size), index
/// entries (tag, type, offset, count) sorted by tag, and the store with
/// each value aligned to its type. With `region`, the first entry is the
/// region tag (BIN, count 16) pointing at a trailer at the end of the
/// store that repeats the tag with the offset `-(16 * entries)`.
fn header(region: Option<u32>, tags: &[Tag]) -> Vec<u8> {
    let mut tags = tags.to_vec();
    tags.sort_by_key(|t| t.tag);
    let mut store = Vec::new();
    let mut index = Vec::new();
    for t in &tags {
        while store.len() % alignment(t.kind) != 0 {
            store.push(0);
        }
        index.push((t.tag, t.kind, store.len() as i32, t.count));
        store.extend_from_slice(&t.data);
    }
    if let Some(region_tag) = region {
        let entries = tags.len() as i32 + 1;
        index.insert(0, (region_tag, RPM_BIN_TYPE, store.len() as i32, 16));
        store.extend_from_slice(&region_tag.to_be_bytes());
        store.extend_from_slice(&RPM_BIN_TYPE.to_be_bytes());
        store.extend_from_slice(&(-16 * entries).to_be_bytes());
        store.extend_from_slice(&16u32.to_be_bytes());
    }
    let mut out = HEADER_MAGIC.to_vec();
    out.extend_from_slice(&(index.len() as u32).to_be_bytes());
    out.extend_from_slice(&(store.len() as u32).to_be_bytes());
    for (tag, kind, offset, count) in index {
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
    }
    out.extend_from_slice(&store);
    out
}

/// The 96-byte lead: magic, format version 3.0 (4.0 for v6), type (0
/// binary, 1 source), architecture number 0, name (66, NUL-padded), OS
/// number 0, signature type 5, reserved.
fn lead(lead_type: u16, major: u8, name: &str) -> Vec<u8> {
    let mut lead = vec![0u8; LEAD_SIZE];
    lead[..4].copy_from_slice(&LEAD_MAGIC);
    lead[4] = major;
    lead[6..8].copy_from_slice(&lead_type.to_be_bytes());
    lead[10..10 + name.len()].copy_from_slice(name.as_bytes());
    lead[78..80].copy_from_slice(&5u16.to_be_bytes());
    lead
}

/// Which digest tags a test package carries.
#[derive(Clone, Copy)]
struct Digests {
    /// `RPMSIGTAG_SHA256` and `RPMSIGTAG_SHA1` over the main header.
    header: bool,
    /// `RPMSIGTAG_MD5` over the main header and payload.
    md5: bool,
    /// `RPMTAG_PAYLOADSHA256` (stored) and `RPMTAG_PAYLOADSHA256ALT`
    /// (uncompressed) in the main header.
    payload: bool,
}

const ALL_DIGESTS: Digests = Digests {
    header: true,
    md5: true,
    payload: true,
};

const NO_DIGESTS: Digests = Digests {
    header: false,
    md5: false,
    payload: false,
};

/// Where a test package declares its size.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SizeTags {
    /// v4: `RPMSIGTAG_SIZE` (header and payload) and
    /// `RPMSIGTAG_PAYLOADSIZE` (uncompressed) in the signature header.
    Signature,
    /// v6: `RPMTAG_PAYLOADSIZE` and `RPMTAG_PAYLOADSIZEALT` in the main
    /// header.
    MainHeader,
    /// No size tags: the payload runs to the end of the file.
    None,
}

/// What a test package carries.
#[derive(Clone)]
struct Spec {
    /// Lead type: 0 binary, 1 source.
    lead_type: u16,
    /// Lead major version: 3 (v3, v4) or 4 (v6).
    lead_major: u8,
    /// Main header tags besides the payload digest and size tags.
    main: Vec<Tag>,
    /// Extra signature header tags.
    signature: Vec<Tag>,
    /// The payload as stored.
    payload: Vec<u8>,
    /// The uncompressed payload, for its size and digest.
    archive: Vec<u8>,
    digests: Digests,
    sizes: SizeTags,
    /// Both headers have immutable regions (v4 and later).
    regions: bool,
}

/// Main header tags of a binary package `hello-1.0-1` for `arch`:
/// identity, payload format `cpio`, the compressor (when named) and level
/// 9, and SHA-256 file digests for its two files.
fn binary_tags(arch: &str, compressor: Option<&str>) -> Vec<Tag> {
    let mut tags = vec![
        string_tag(RPMTAG_NAME, "hello"),
        string_tag(RPMTAG_VERSION, "1.0"),
        string_tag(RPMTAG_RELEASE, "1"),
        i18n_tag(RPMTAG_SUMMARY, "Synthetic test package"),
        string_tag(RPMTAG_OS, "linux"),
        string_tag(RPMTAG_ARCH, arch),
        string_tag(RPMTAG_SOURCERPM, "hello-1.0-1.src.rpm"),
        strings_tag(
            RPMTAG_FILEDIGESTS,
            &[&"ab".repeat(32), "", &"cd".repeat(32)],
        ),
        int32_tag(RPMTAG_FILEDIGESTALGO, &[RPM_HASH_SHA256]),
        string_tag(RPMTAG_PAYLOADFORMAT, "cpio"),
        string_tag(RPMTAG_PAYLOADFLAGS, "9"),
    ];
    if let Some(compressor) = compressor {
        tags.push(string_tag(RPMTAG_PAYLOADCOMPRESSOR, compressor));
    }
    tags
}

impl Spec {
    /// A v4 binary package with every digest, around a stored payload and
    /// the archive it decodes to.
    fn binary(arch: &str, compressor: Option<&str>, payload: Vec<u8>, archive: Vec<u8>) -> Self {
        Self {
            lead_type: 0,
            lead_major: 3,
            main: binary_tags(arch, compressor),
            signature: Vec::new(),
            payload,
            archive,
            digests: ALL_DIGESTS,
            sizes: SizeTags::Signature,
            regions: true,
        }
    }

    /// The gzip-compressed fixture archive.
    fn gzip() -> Self {
        Self::binary(
            "x86_64",
            Some("gzip"),
            fixture("rpm/payload.cpio.gz"),
            fixture("rpm/payload.cpio"),
        )
    }

    /// The main header as stored, with the payload digest and size tags.
    fn main_header(&self) -> Vec<u8> {
        let mut tags = self.main.clone();
        if self.digests.payload {
            tags.push(strings_tag(
                RPMTAG_PAYLOADSHA256,
                &[&sha256_hex(&self.payload)],
            ));
            tags.push(int32_tag(RPMTAG_PAYLOADSHA256ALGO, &[RPM_HASH_SHA256]));
            tags.push(strings_tag(
                RPMTAG_PAYLOADSHA256ALT,
                &[&sha256_hex(&self.archive)],
            ));
        }
        if self.sizes == SizeTags::MainHeader {
            tags.push(int64_tag(RPMTAG_PAYLOADSIZE, &[self.payload.len() as u64]));
            tags.push(int64_tag(
                RPMTAG_PAYLOADSIZEALT,
                &[self.archive.len() as u64],
            ));
        }
        header(self.regions.then_some(HEADER_IMMUTABLE), &tags)
    }

    /// An RPM package (rpm `docs/manual/format_v4.md`): lead, signature
    /// header zero-padded to 8 bytes, main header, payload.
    fn build(&self) -> Vec<u8> {
        let main = self.main_header();
        let mut covered = main.clone();
        covered.extend_from_slice(&self.payload);
        let mut tags = self.signature.clone();
        if self.sizes == SizeTags::Signature {
            tags.push(int32_tag(RPMSIGTAG_SIZE, &[covered.len() as u32]));
            tags.push(int32_tag(
                RPMSIGTAG_PAYLOADSIZE,
                &[self.archive.len() as u32],
            ));
        }
        if self.digests.header {
            tags.push(string_tag(RPMSIGTAG_SHA256, &sha256_hex(&main)));
            tags.push(string_tag(RPMSIGTAG_SHA1, &sha1_hex(&main)));
        }
        if self.digests.md5 {
            tags.push(bin_tag(RPMSIGTAG_MD5, &checksum::md5(&covered)));
        }
        // A signature header needs at least one entry.
        if tags.is_empty() && !self.regions {
            tags.push(bin_tag(RPMSIGTAG_RSA, &[0; 8]));
        }
        let signature = header(self.regions.then_some(HEADER_SIGNATURES), &tags);
        let mut out = lead(self.lead_type, self.lead_major, "hello-1.0-1");
        out.extend_from_slice(&signature);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&covered);
        out
    }

    /// File offset of the payload in [`Spec::build`]'s output.
    fn payload_offset(&self) -> usize {
        self.build().len() - self.payload.len()
    }

    /// File offset of the main header in [`Spec::build`]'s output.
    fn main_offset(&self) -> usize {
        self.payload_offset() - self.main_header().len()
    }
}

// --- Payload archives (rpm `lib/cpio.cc`, LSB 5.0 section 25.2.5) ---------

/// A newc entry: `070701`, 13 fields of 8 hex digits (inode, mode, uid,
/// gid, nlink, mtime, file size, device major and minor, rdev major and
/// minor, name size, checksum), the name with its NUL padded to 4 bytes
/// from the start of the archive, then the data padded to 4 bytes.
fn newc(archive: &mut Vec<u8>, name: &str, mode: u32, contents: &[u8]) {
    let fields = [
        1,
        mode,
        0,
        0,
        1,
        0,
        contents.len() as u32,
        0,
        0,
        0,
        0,
        name.len() as u32 + 1,
        0,
    ];
    archive.extend_from_slice(b"070701");
    for field in fields {
        archive.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    pad4(archive);
    archive.extend_from_slice(contents);
    pad4(archive);
}

/// rpm's stripped entry: `07070X`, the file index as 8 hex digits,
/// padding to 4 bytes, then the contents padded to 4 bytes.
fn stripped(archive: &mut Vec<u8>, index: u32, contents: &[u8]) {
    archive.extend_from_slice(b"07070X");
    archive.extend_from_slice(format!("{index:08x}").as_bytes());
    pad4(archive);
    archive.extend_from_slice(contents);
    pad4(archive);
}

/// The newc `TRAILER!!!` entry that ends every payload archive.
fn trailer(archive: &mut Vec<u8>) {
    newc(archive, "TRAILER!!!", 0, b"");
}

fn pad4(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    gzip_level(payload, 6)
}

fn gzip_level(payload: &[u8], level: u8) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, level));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    member
}

/// An ELF64 little-endian header with `e_machine` 183 (AArch64).
fn aarch64_elf() -> Vec<u8> {
    let mut elf = payload_elf();
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    elf
}

/// A gzip package whose archive holds only `README`.
fn text_only_package(arch: &str) -> Vec<u8> {
    let mut archive = Vec::new();
    newc(&mut archive, "./README", S_IFREG | 0o644, b"just text\n");
    trailer(&mut archive);
    Spec::binary(arch, Some("gzip"), gzip(&archive), archive).build()
}

// --- Detection and the gzip fixture -------------------------------------

#[test]
fn detection_needs_the_lead_and_the_signature_header_magic() {
    let data = Spec::gzip().build();
    assert_eq!(rpm::detect(&data), Some(rpm::Layout::Package));
    assert!(matches!(
        formats::detect_format(&data),
        DetectedFormat::Container {
            kind: Kind::Rpm(rpm::Layout::Package)
        }
    ));
    let mut no_header = data.clone();
    no_header[LEAD_SIZE + 3] = 2;
    assert_eq!(rpm::detect(&no_header), None);
    let mut no_lead = data;
    no_lead[0] = 0;
    assert_eq!(rpm::detect(&no_lead), None);
    assert_eq!(rpm::detect(&LEAD_MAGIC), None);
}

#[test]
fn gzip_payload_files_are_listed_with_the_stored_payload_range() {
    let spec = Spec::gzip();
    let data = spec.build();
    let p = classify(&data).unwrap();
    assert_eq!(p.format.format, FileFormat::Rpm);
    assert_eq!(p.format.variant_name.as_deref(), Some("RPM package"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 1, "{:?}", p.slices);
    let hello = slice(&p, "./usr/bin/hello");
    assert_eq!(hello.isa, Isa::X86_64);
    assert_eq!(hello.offset, spec.payload_offset() as u64);
    assert_eq!(hello.size, spec.payload.len() as u64);
    let decoded = hello.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "gzip");
    assert_eq!(decoded.size, 256);
    assert_eq!(metadata_text(&p, "rpm_name"), "hello");
    assert_eq!(metadata_text(&p, "rpm_arch"), "x86_64");
    assert_eq!(metadata_text(&p, "rpm_package_type"), "binary");
    assert_eq!(metadata_text(&p, "rpm_format_version"), "4");
    assert_eq!(metadata_text(&p, "rpm_payload_compressor"), "gzip");
    assert_eq!(
        metadata_text(&p, "rpm_payload_offset"),
        spec.payload_offset().to_string()
    );
    assert_eq!(
        metadata_text(&p, "rpm_payload_decoded_size"),
        spec.archive.len().to_string()
    );
    assert_eq!(
        metadata_text(&p, "rpm_header_offset"),
        spec.main_offset().to_string()
    );
    assert_eq!(metadata_text(&p, "rpm_image_size"), data.len().to_string());
    assert!(has_note(
        &p,
        "Binary package hello-1.0-1; header architecture x86_64, OS linux; package format v4"
    ));
    assert!(has_note(
        &p,
        "Digests verified: header SHA-256, header SHA-1, payload SHA-256, header and payload \
         MD5, uncompressed payload SHA-256"
    ));
    assert!(has_note(&p, "gzip-compressed cpio"));
    assert!(has_note(&p, "CRC-32 verified"));
    assert!(has_note(
        &p,
        "Payload archive of newc entries: 7 entries (2 regular files, 5 directories"
    ));
    assert!(has_note(
        &p,
        "1 of 2 regular files with contents are in a recognized format and listed"
    ));
    assert!(has_note(
        &p,
        "File digests (SHA-256) present for 2 files, not verified"
    ));
    assert!(has_note(&p, "The package is not signed"));
}

#[test]
fn every_payload_compressor_rpm_writes_is_decoded() {
    let archive = fixture("rpm/payload.cpio");
    for (compressor, file, transform) in [
        ("bzip2", "rpm/payload.cpio.bz2", "bzip2"),
        ("xz", "rpm/payload.cpio.xz", "xz"),
        ("lzma", "rpm/payload.cpio.lzma", "LZMA"),
        ("zstd", "rpm/payload.cpio.zst", "Zstandard"),
    ] {
        let spec = Spec::binary("x86_64", Some(compressor), fixture(file), archive.clone());
        let p = classify(&spec.build()).unwrap_or_else(|e| panic!("{compressor}: {e}"));
        assert_eq!(p.primary.isa, Isa::X86_64, "{compressor}");
        let hello = slice(&p, "./usr/bin/hello");
        assert_eq!(hello.offset, spec.payload_offset() as u64, "{compressor}");
        let decoded = hello.decoded.as_ref().expect("decoded range");
        assert_eq!(decoded.transform, transform);
        assert!(has_note(&p, "uncompressed payload SHA-256"), "{compressor}");
    }
}

#[test]
fn payloads_without_a_compressor_tag_read_through_the_gzip_path() {
    // `ufdio` packages store the archive as is and name no compressor.
    let archive = fixture("rpm/payload.cpio");
    let spec = Spec::binary("x86_64", None, archive.clone(), archive.clone());
    let p = classify(&spec.build()).unwrap();
    let hello = slice(&p, "./usr/bin/hello");
    let elf_at = archive
        .windows(4)
        .position(|w| w == b"\x7fELF")
        .expect("the archive holds the ELF");
    assert_eq!(hello.offset, (spec.payload_offset() + elf_at) as u64);
    assert_eq!(hello.size, 256);
    assert!(hello.decoded.is_none());
    assert!(has_note(&p, "uncompressed cpio"));

    // A gzip payload without the tag decodes as rpm's default.
    let spec = Spec::binary("x86_64", None, fixture("rpm/payload.cpio.gz"), archive);
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(&p, "the header names no compressor"));
}

#[test]
fn the_header_architecture_is_not_isa_evidence() {
    // The header says aarch64; the only executable is x86-64.
    let spec = Spec::binary(
        "aarch64",
        Some("gzip"),
        fixture("rpm/payload.cpio.gz"),
        fixture("rpm/payload.cpio"),
    );
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(metadata_text(&p, "rpm_arch"), "aarch64");
    assert!(has_note(&p, "name a build target, not an ISA"));

    // Without a recognized file, the package names no ISA.
    let p = classify(&text_only_package("x86_64")).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "0 of 1 regular files with contents"));
}

#[test]
fn source_packages_are_reported_as_source() {
    let mut spec = Spec::gzip();
    spec.lead_type = 1;
    spec.main.retain(|t| t.tag != RPMTAG_SOURCERPM);
    let p = classify(&spec.build()).unwrap();
    assert_eq!(metadata_text(&p, "rpm_package_type"), "source");
    assert!(has_note(&p, "Source package hello-1.0-1"));
    assert_eq!(p.primary.isa, Isa::X86_64);

    // The main header decides when the lead disagrees, as rpm does.
    let mut spec = Spec::gzip();
    spec.lead_type = 1;
    let p = classify(&spec.build()).unwrap();
    assert_eq!(metadata_text(&p, "rpm_package_type"), "binary");
    assert!(has_note(&p, "The lead says source package"));
}

#[test]
fn signatures_are_reported_and_never_verified() {
    let mut spec = Spec::gzip();
    spec.signature.push(bin_tag(RPMSIGTAG_RSA, &[0x89; 32]));
    let p = classify(&spec.build()).unwrap();
    assert!(has_note(
        &p,
        "Signatures present, not verified: RSA header signature"
    ));
    assert_eq!(metadata_text(&p, "rpm_signatures"), "RSA header signature");
}

// --- Stripped payloads (format v6 and v4 with files of 4 GiB or more) -----

/// Files of a v6 package: `/usr/bin` (directory), `/usr/bin/hello` and
/// `/usr/bin/hello2` (one hard-link set: device 1, inode 5), `/usr/bin/sh`
/// (symbolic link to `hello`) and `/var/log/hello.log` (a ghost).
fn v6_file_tags() -> Vec<Tag> {
    vec![
        strings_tag(RPMTAG_DIRNAMES, &["/usr/", "/usr/bin/", "/var/log/"]),
        strings_tag(
            RPMTAG_BASENAMES,
            &["bin", "hello", "hello2", "sh", "hello.log"],
        ),
        int32_tag(RPMTAG_DIRINDEXES, &[0, 1, 1, 1, 2]),
        int16_tag(
            RPMTAG_FILEMODES,
            &[0o040_755, 0o100_755, 0o100_755, 0o120_777, 0o100_644],
        ),
        int64_tag(RPMTAG_LONGFILESIZES, &[0, 256, 256, 5, 10]),
        int32_tag(RPMTAG_FILEFLAGS, &[0, 0, 0, 0, RPMFILE_GHOST]),
        int32_tag(RPMTAG_FILEINODES, &[2, 5, 5, 6, 7]),
        int32_tag(RPMTAG_FILEDEVICES, &[1, 1, 1, 1, 1]),
        int32_tag(RPMTAG_RPMFORMAT, &[6]),
    ]
}

/// The stripped archive rpm writes for [`v6_file_tags`]: files without
/// hard links in index order (the ghost is skipped), then the hard-link
/// set, where only the last member carries the contents.
fn v6_archive() -> Vec<u8> {
    let mut archive = Vec::new();
    stripped(&mut archive, 0, b"");
    stripped(&mut archive, 3, b"hello");
    stripped(&mut archive, 1, b"");
    stripped(&mut archive, 2, &payload_elf());
    trailer(&mut archive);
    archive
}

fn v6_spec() -> Spec {
    let archive = v6_archive();
    let mut main = binary_tags("x86_64", Some("gzip"));
    main.extend(v6_file_tags());
    Spec {
        lead_type: 0,
        lead_major: 4,
        main,
        signature: Vec::new(),
        payload: gzip(&archive),
        archive,
        digests: ALL_DIGESTS,
        sizes: SizeTags::MainHeader,
        regions: true,
    }
}

#[test]
fn stripped_payloads_take_names_sizes_and_hard_links_from_the_header() {
    let spec = v6_spec();
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 1, "{:?}", p.slices);
    let hello = slice(&p, "/usr/bin/hello2");
    assert_eq!(hello.offset, spec.payload_offset() as u64);
    assert_eq!(hello.decoded.as_ref().expect("decoded").size, 256);
    assert_eq!(metadata_text(&p, "rpm_format_version"), "6");
    assert!(has_note(&p, "package format v6; lead version 4.0"));
    assert!(has_note(&p, "(end from RPMTAG_PAYLOADSIZE)"));
    assert!(has_note(
        &p,
        "Payload archive of stripped (`07070X`) entries, indexed into the main header's file \
         table: 4 entries (2 regular files, 1 directory, 1 symbolic link, 0 other)"
    ));
}

#[test]
fn stripped_payloads_need_a_consistent_file_table() {
    let mut spec = v6_spec();
    spec.main.retain(|t| t.tag != RPMTAG_FILEMODES);
    let p = classify(&spec.build()).unwrap();
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "Missing RPMTAG_FILEMODES"));

    let mut spec = v6_spec();
    spec.main.retain(|t| t.tag != RPMTAG_DIRINDEXES);
    spec.main
        .push(int32_tag(RPMTAG_DIRINDEXES, &[0, 1, 1, 1, 9]));
    let p = classify(&spec.build()).unwrap();
    assert!(has_note(&p, "Invalid RPMTAG_DIRINDEXES: directory 9 of 3"));
}

// --- Damaged packages ---------------------------------------------------

#[test]
fn digest_mismatches_are_errors() {
    let spec = Spec::gzip();
    let data = spec.build();
    let mut header = data.clone();
    // A byte of the main header's store: the NAME string `hello`.
    let name_at = spec.main_offset()
        + data[spec.main_offset()..]
            .windows(6)
            .position(|w| w == b"hello\0")
            .expect("name in store");
    header[name_at] = b'j';
    assert!(error_text(&header).contains("Invalid header SHA-256 digest"));

    let mut payload = data.clone();
    let last = payload.len() - 1;
    payload[last] ^= 1;
    assert!(error_text(&payload).contains("Invalid payload SHA-256 digest"));

    let mut md5_only = Spec::gzip();
    md5_only.digests = Digests {
        md5: true,
        ..NO_DIGESTS
    };
    let mut data = md5_only.build();
    let last = data.len() - 1;
    data[last] ^= 1;
    assert!(error_text(&data).contains("Invalid header and payload MD5 digest"));

    // The uncompressed payload digest covers the decoded archive.
    let mut wrong = Spec::gzip();
    wrong.archive.push(0);
    wrong.digests.header = false;
    wrong.digests.md5 = false;
    assert!(error_text(&wrong.build()).contains("Invalid uncompressed payload SHA-256 digest"));
}

#[test]
fn declared_sizes_bound_the_package() {
    let data = Spec::gzip().build();
    assert!(error_text(&data[..data.len() - 1]).contains("Truncated package"));
    let mut padded = data.clone();
    padded.extend_from_slice(&[0; 64]);
    assert_eq!(
        classify(&padded).unwrap().primary.isa,
        Isa::X86_64,
        "zero padding after the package is accepted"
    );
    let mut junk = data;
    junk.extend_from_slice(b"junk");
    assert!(error_text(&junk).contains("Unexpected 4 B after the package"));

    // Without size tags the payload runs to the end of the file.
    let mut spec = Spec::gzip();
    spec.sizes = SizeTags::None;
    let p = classify(&spec.build()).unwrap();
    assert!(has_note(&p, "(to the end of the file; no size tag)"));
}

#[test]
fn header_structures_are_checked_as_rpm_checks_them() {
    let spec = Spec::gzip();
    let data = spec.build();
    let mut magic = data.clone();
    magic[spec.main_offset() + 4] = 1;
    assert!(error_text(&magic).contains("Missing main header magic"));

    // The signature header pads to 8 bytes with zeros.
    let sig_tags = [string_tag(RPMSIGTAG_SHA1, "x")];
    let unpadded = LEAD_SIZE + header(Some(HEADER_SIGNATURES), &sig_tags).len();
    assert_ne!(unpadded % 8, 0, "the test signature needs padding");
    let mut padding = lead(0, 3, "hello-1.0-1");
    padding.extend_from_slice(&header(Some(HEADER_SIGNATURES), &sig_tags));
    padding.extend_from_slice(&[0xaa; 8]);
    padding.extend_from_slice(&spec.main_header());
    assert!(error_text(&padding).contains("Invalid signature header padding"));

    // A main header region must span the header.
    let mut tags = binary_tags("x86_64", Some("gzip"));
    tags.push(string_tag(RPMTAG_SOURCERPM, "dup"));
    let main = header(Some(HEADER_IMMUTABLE), &tags);
    let mut partial = main.clone();
    // The trailer's offset field: one entry fewer than the index holds.
    let entries = u32::from_be_bytes(main[8..12].try_into().unwrap()) as i32;
    let trailer_offset_at = main.len() - 8;
    partial[trailer_offset_at..trailer_offset_at + 4]
        .copy_from_slice(&(-16 * (entries - 1)).to_be_bytes());
    let mut data = lead(0, 3, "hello-1.0-1");
    data.extend_from_slice(&header(
        Some(HEADER_SIGNATURES),
        &[int32_tag(RPMSIGTAG_SIZE, &[0])],
    ));
    while data.len() % 8 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&partial);
    let message = error_text(&data);
    assert!(message.contains("Invalid main header"), "{message}");
}

#[test]
fn legacy_headers_without_regions_are_format_v3() {
    let mut spec = Spec::gzip();
    spec.regions = false;
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(metadata_text(&p, "rpm_format_version"), "3");
    assert!(has_note(
        &p,
        "The main header has no immutable region (a legacy v3 layout)"
    ));
}

#[test]
fn payloads_that_cannot_be_read_are_opaque() {
    let archive = fixture("rpm/payload.cpio");
    let unsupported = Spec::binary(
        "x86_64",
        Some("lzip"),
        b"LZIP\x01".to_vec(),
        archive.clone(),
    );
    let p = classify(&unsupported.build()).unwrap();
    assert!(has_note(&p, "payload compressor `lzip` is not supported"));
    let payload = slice(&p, "Payload");
    assert!(matches!(payload.isa, Isa::Unknown(_)));
    assert_eq!(payload.offset, unsupported.payload_offset() as u64);

    let mut delta = Spec::gzip();
    delta.main.retain(|t| t.tag != RPMTAG_PAYLOADFORMAT);
    delta.main.push(string_tag(RPMTAG_PAYLOADFORMAT, "drpm"));
    let p = classify(&delta.build()).unwrap();
    assert!(has_note(&p, "payload format `drpm` is not cpio"));

    let mut corrupt = Spec::gzip();
    corrupt.digests = NO_DIGESTS;
    let crc_at = corrupt.payload.len() - 8;
    corrupt.payload[crc_at] ^= 1;
    let p = classify(&corrupt.build()).unwrap();
    assert!(has_note(&p, "it does not decode as gzip"));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn damaged_payload_archives_are_listed_up_to_the_damage() {
    let mut archive = Vec::new();
    newc(&mut archive, "./first", S_IFREG | 0o755, &payload_elf());
    let damaged_at = archive.len();
    newc(&mut archive, "./second", S_IFREG | 0o755, &aarch64_elf());
    trailer(&mut archive);
    archive[damaged_at] = b'x';
    let spec = Spec::binary("x86_64", Some("gzip"), gzip(&archive), archive);
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.slices.len(), 1);
    assert_eq!(slice(&p, "./first").isa, Isa::X86_64);
    assert!(has_note(
        &p,
        &format!("entry at archive offset 0x{damaged_at:X} is invalid (no cpio entry magic)")
    ));

    // An archive cut before its trailer.
    let mut archive = Vec::new();
    newc(&mut archive, "./first", S_IFREG | 0o755, &payload_elf());
    let spec = Spec::binary("x86_64", Some("gzip"), gzip(&archive), archive);
    let p = classify(&spec.build()).unwrap();
    assert_eq!(slice(&p, "./first").isa, Isa::X86_64);
    assert!(has_note(&p, "before a `TRAILER!!!` entry"));
}

#[test]
fn symlinks_directories_and_empty_files_are_counted_not_listed() {
    let mut archive = Vec::new();
    newc(&mut archive, "./bin", S_IFDIR | 0o755, b"");
    newc(&mut archive, "./bin/link", S_IFLNK | 0o777, b"\x7fELF");
    newc(&mut archive, "./bin/empty", S_IFREG | 0o644, b"");
    newc(&mut archive, "./bin/tool", S_IFREG | 0o755, &aarch64_elf());
    trailer(&mut archive);
    let spec = Spec::binary("aarch64", Some("gzip"), gzip(&archive), archive);
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices.len(), 1);
    assert!(has_note(
        &p,
        "newc entries: 4 entries (2 regular files, 1 directory, 1 symbolic link, 0 other)"
    ));
    assert!(has_note(&p, "1 of 1 regular files with contents"));
}

#[test]
fn payloads_beyond_the_extraction_limit_are_listed_from_their_prefix() {
    let mut archive = Vec::new();
    newc(&mut archive, "./first", S_IFREG | 0o755, &payload_elf());
    newc(
        &mut archive,
        "./zeros",
        S_IFREG | 0o644,
        &vec![0; formats::MAX_PAYLOAD],
    );
    newc(&mut archive, "./last", S_IFREG | 0o755, &aarch64_elf());
    trailer(&mut archive);
    let mut spec = Spec::binary("x86_64", Some("gzip"), gzip_level(&archive, 1), archive);
    // The uncompressed digest would cover bytes that are not decoded.
    spec.digests.payload = false;
    let p = classify(&spec.build()).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 1, "{:?}", p.slices);
    assert_eq!(slice(&p, "./first").isa, Isa::X86_64);
    assert!(has_note(
        &p,
        "decoding stopped at the 64 MiB extraction limit"
    ));
    assert!(has_note(&p, "The decoded prefix ends inside the entry"));
    assert_eq!(
        metadata_text(&p, "rpm_payload_decoded_size"),
        formats::MAX_PAYLOAD.to_string()
    );
}

#[test]
fn xz_streams_decode_as_a_prefix() {
    let archive = fixture("rpm/payload.cpio");
    let xz = fixture("rpm/payload.cpio.xz");
    let prefix = compressed::decode_prefix(Codec::Xz, &xz, 100).unwrap();
    assert_eq!(prefix, &archive[..100]);
    let whole = compressed::decode_prefix(Codec::Xz, &xz, 1 << 20).unwrap();
    assert_eq!(whole, archive);
    // Concatenated streams stop inside the second one.
    let elf = payload_elf();
    let concat = fixture("compressed/payload.elf.concat.xz");
    let prefix = compressed::decode_prefix(Codec::Xz, &concat, 300).unwrap();
    assert_eq!(prefix[..256], elf[..]);
    assert_eq!(prefix[256..], elf[..44]);
    // A whole decode is unchanged, and still fails past its limit.
    assert_eq!(compressed::decode(Codec::Xz, &xz).unwrap().data, archive);
    assert!(compressed::decode_limited(Codec::Xz, &xz, 100).is_err());
}

#[test]
fn every_prefix_of_a_package_is_rejected() {
    for spec in [Spec::gzip(), v6_spec()] {
        let data = spec.build();
        for end in 0..data.len() {
            let prefix = &data[..end];
            if rpm::detect(prefix).is_none() {
                assert!(end < LEAD_SIZE + HEADER_MAGIC.len(), "{end}");
                continue;
            }
            assert!(classify(prefix).is_err(), "prefix of {end} B parses");
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for spec in [Spec::gzip(), v6_spec()] {
        let data = spec.build();
        for i in 0..data.len() {
            for value in [0x00, 0xff, data[i] ^ 0x01] {
                let mut mutated = data.clone();
                mutated[i] = value;
                let _ = rpm::parse_container(&mutated, rpm::Layout::Package);
                let _ = classify_without_transforms(&mutated);
            }
        }
    }
    // Without digests, header mutations reach the later checks.
    for mut spec in [Spec::gzip(), v6_spec()] {
        spec.digests = NO_DIGESTS;
        let data = spec.build();
        for i in 0..data.len() {
            let mut mutated = data.clone();
            mutated[i] ^= 0x01;
            let _ = classify_without_transforms(&mutated);
        }
    }
    // Mutations behind the payload's compression reach the archive walk.
    let mut spec = v6_spec();
    spec.digests = NO_DIGESTS;
    let archive = spec.archive.clone();
    for i in 0..archive.len() {
        let mut mutated = archive.clone();
        mutated[i] ^= 0x01;
        spec.payload = gzip(&mutated);
        spec.archive = mutated;
        let _ = classify_without_transforms(&spec.build());
    }
}

// --- Debian packages (dpkg 1.22.21 `man/deb.pod`) ------------------------

/// A tar entry or ar member: its name and contents.
#[derive(Clone, Copy)]
struct Member<'a> {
    name: &'a str,
    contents: &'a [u8],
}

fn member<'a>(name: &'a str, contents: &'a [u8]) -> Member<'a> {
    Member { name, contents }
}

/// A ustar header block (POSIX.1-2024 `pax`, "ustar Interchange Format"):
/// name (100), mode, uid, gid (8 each), size, mtime (12 each, octal),
/// checksum (8), typeflag `0`, magic `ustar\0` and version `00` at 257,
/// then the data padded to 512 bytes; two zero blocks end the archive.
fn tar(entries: &[Member<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for &Member { name, contents } in entries {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        let octal = |block: &mut [u8; 512], at: usize, width: usize, value: u64| {
            let text = format!("{value:0w$o}\0", w = width - 1);
            block[at..at + width].copy_from_slice(text.as_bytes());
        };
        octal(&mut block, 100, 8, 0o755);
        octal(&mut block, 108, 8, 0);
        octal(&mut block, 116, 8, 0);
        octal(&mut block, 124, 12, contents.len() as u64);
        octal(&mut block, 136, 12, 0);
        block[148..156].copy_from_slice(b"        ");
        block[156] = b'0';
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&block);
        out.extend_from_slice(contents);
        out.resize(round_up(out.len(), 512), 0);
    }
    out.extend_from_slice(&[0; 1024]);
    out
}

/// `len` rounded up to a multiple of `block`.
fn round_up(len: usize, block: usize) -> usize {
    (len + block - 1) / block * block
}

/// An ar archive as deb(5) describes it: `!<arch>\n`, then per member a
/// 60-byte header (name with a trailing slash in 16, mtime 12, uid 6, gid
/// 6, octal mode 8, decimal size 10, then `` `\n ``) and the data, padded to
/// an even offset with `\n`.
fn ar(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for &Member { name, contents } in members {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            "100644",
            contents.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(contents);
        if contents.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// A Debian binary package: `debian-binary` (`2.0`), `control.tar.gz` (a
/// `control` file) and the data member `data_name` holding `data`.
fn deb(data_name: &str, data: &[u8]) -> Vec<u8> {
    let control = tar(&[member(
        "./control",
        b"Package: hello\nArchitecture: amd64\n",
    )]);
    ar(&[
        member("debian-binary", b"2.0\n"),
        member("control.tar.gz", &gzip(&control)),
        member(data_name, data),
    ])
}

fn zstd(payload: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(payload, ruzstd::encoding::CompressionLevel::Fastest)
}

fn bzip2(payload: &[u8]) -> Vec<u8> {
    let mut encoder = ::bzip2::write::BzEncoder::new(Vec::new(), ::bzip2::Compression::best());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn debian_packages_reach_the_elf_in_their_data_archive() {
    let elf = payload_elf();
    let data_tar = tar(&[member("./usr/bin/hello", &elf)]);
    for (name, member) in [
        ("data.tar", data_tar.clone()),
        ("data.tar.gz", gzip(&data_tar)),
        ("data.tar.xz", fixture("rpm/data.tar.xz")),
        ("data.tar.zst", zstd(&data_tar)),
        ("data.tar.bz2", bzip2(&data_tar)),
    ] {
        let package = deb(name, &member);
        let p = classify(&package).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::Archive, "{name}");
        assert_eq!(p.primary.isa, Isa::X86_64, "{name}");
        let data = slice(&p, name);
        assert_eq!(data.isa, Isa::X86_64, "{name}");
        assert_eq!(data.size, member.len() as u64, "{name}");
        assert!(has_note(&p, &format!("Primary ISA from member {name}")));
    }
}

#[test]
fn debian_members_that_fail_to_classify_do_not_hide_the_package() {
    // Before the fix, a recognized member whose classification failed
    // failed the whole archive.
    let elf = payload_elf();
    let data_tar = tar(&[member("./usr/bin/hello", &elf)]);
    let mut member = gzip(&data_tar);
    let crc_at = member.len() - 8;
    member[crc_at] ^= 1;
    let p = classify(&deb("data.tar.gz", &member)).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(matches!(slice(&p, "data.tar.gz").isa, Isa::Unknown(_)));
    assert!(matches!(slice(&p, "control.tar.gz").isa, Isa::Unknown(_)));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("data.tar.gz: ISA unknown (")));
}

// --- Real samples -------------------------------------------------------

/// Files under `dir`, recursively, whose extension is one of `extensions`.
fn sample_files(dir: &std::path::Path, extensions: &[&str], out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sample_files(&path, extensions, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e))
        {
            out.push(path);
        }
    }
}

#[test]
fn real_packages_in_package_sample_dir_classify() {
    // Real packages cannot be committed; point PACKAGE_SAMPLE_DIR at a
    // directory of `.rpm` and `.deb` files to run this test.
    let Some(dir) = std::env::var_os("PACKAGE_SAMPLE_DIR") else {
        eprintln!("PACKAGE_SAMPLE_DIR is not set; skipped");
        return;
    };
    let mut files = Vec::new();
    sample_files(std::path::Path::new(&dir), &["rpm", "deb"], &mut files);
    assert!(!files.is_empty(), "no .rpm or .deb files under {dir:?}");
    for path in files {
        let data = std::fs::read(&path).expect("readable");
        let p = classify(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let expected = if path.extension().is_some_and(|e| e == "rpm") {
            FileFormat::Rpm
        } else {
            FileFormat::Archive
        };
        assert_eq!(p.format.format, expected, "{}", path.display());
        eprintln!(
            "{}: {} {:?}, {} slices",
            path.display(),
            p.format.format,
            p.primary.isa,
            p.slices.len()
        );
    }
}

#[test]
fn ida_inputs_with_the_rpm_magics_classify_as_rpm() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR is not set; skipped");
        return;
    };
    let mut stack = vec![std::path::PathBuf::from(dir)];
    let mut found = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let mut head = [0u8; LEAD_SIZE + 8];
            let Ok(mut file) = std::fs::File::open(&path) else {
                continue;
            };
            if std::io::Read::read_exact(&mut file, &mut head).is_err()
                || rpm::detect(&head).is_none()
            {
                continue;
            }
            found += 1;
            let data = std::fs::read(&path).expect("readable");
            let p = classify(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(p.format.format, FileFormat::Rpm, "{}", path.display());
        }
    }
    eprintln!("{found} IDA inputs start with the RPM lead and header magics");
}
