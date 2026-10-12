//! Archive containers: ZIP, tar and CPIO members are listed only when they
//! are a recognized format and are classified on their own bytes; slices
//! keep stored offsets with decoded ranges; package layouts are labels
//! only; corrupt, truncated and mutated archives are errors or bounded
//! results, never panics.

use zrax::formats::checksum::crc32;
use zrax::formats::{self, archives, DetectedFormat};
use zrax::{
    detect_payload, ClassifierOptions, ContainedArch, DetectionPayload, Endianness, FileFormat,
    Isa, MetadataValue,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/archives");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> zrax::Result<DetectionPayload> {
    detect_payload(data, &ClassifierOptions::new())
}

/// Options for the sweeps: raw-dump transforms are searched only for raw
/// input, which the archive parsers never produce, and would dominate the
/// run time of mutated inputs that lose recognition.
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

fn detected_layout(data: &[u8]) -> Option<archives::Layout> {
    match formats::detect_format(data) {
        DetectedFormat::Container {
            kind: formats::container::Kind::Archive(layout),
        } => Some(layout),
        _ => None,
    }
}

/// ELF header (64 bytes): magic, class (1 = 32-bit, 2 = 64-bit), data
/// encoding (1 = little-endian, 2 = big-endian), version 1, `e_type` 2
/// (executable) and `e_machine` in the header byte order.
fn elf(class: u8, big_endian: bool, machine: u16) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = class;
    data[5] = if big_endian { 2 } else { 1 };
    data[6] = 1;
    let (kind, machine) = if big_endian {
        (2u16.to_be_bytes(), machine.to_be_bytes())
    } else {
        (2u16.to_le_bytes(), machine.to_le_bytes())
    };
    data[16..18].copy_from_slice(&kind);
    data[18..20].copy_from_slice(&machine);
    data
}

const EM_PPC: u16 = 20;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const EM_RISCV: u16 = 243;

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    member
}

/// `len` rounded up to a multiple of `block`.
fn round_up(len: usize, block: usize) -> usize {
    (len + block - 1) / block * block
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

// ZIP (PKWARE APPNOTE 6.3.10).

/// General purpose flags (4.4.4).
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

/// Compression methods (4.4.5).
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_PPMD: u16 = 98;

/// A data descriptor (4.3.9): optional signature `PK\7\8`, CRC-32, then
/// both sizes in 4 or 8 bytes.
#[derive(Clone, Copy)]
struct Descriptor {
    signature: bool,
    wide: bool,
}

/// One member as the ZIP builder writes it.
struct ZipMember {
    name: String,
    method: u16,
    flags: u16,
    /// CRC-32 written to the local header, descriptor and central header.
    crc: u32,
    /// Uncompressed size written to the headers.
    size: u64,
    /// The bytes stored in the archive.
    stored: Vec<u8>,
    descriptor: Option<Descriptor>,
}

impl ZipMember {
    fn stored(name: &str, contents: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            method: METHOD_STORED,
            flags: 0,
            crc: crc32(contents),
            size: contents.len() as u64,
            stored: contents.to_vec(),
            descriptor: None,
        }
    }

    fn deflated(name: &str, contents: &[u8]) -> Self {
        Self {
            method: METHOD_DEFLATE,
            stored: miniz_oxide::deflate::compress_to_vec(contents, 6),
            ..Self::stored(name, contents)
        }
    }

    fn with_descriptor(mut self, signature: bool, wide: bool) -> Self {
        self.flags |= FLAG_DATA_DESCRIPTOR;
        self.descriptor = Some(Descriptor { signature, wide });
        self
    }
}

/// A built archive and the file offset of each member's stored data.
struct BuiltZip {
    bytes: Vec<u8>,
    data_offsets: Vec<usize>,
}

/// ZIP archive (4.3.6): local records, the central directory and the end
/// of central directory record. With `zip64`, every size and offset in
/// the central directory is saturated and moved to a ZIP64 extra field
/// (4.5.3), local headers carry both sizes in a ZIP64 field, and a ZIP64
/// end record (4.3.14) and locator (4.3.15) precede the end record.
fn zip(members: &[ZipMember], zip64: bool) -> BuiltZip {
    let mut out = Vec::new();
    let mut local_offsets = Vec::new();
    let mut data_offsets = Vec::new();
    let version_needed: u16 = if zip64 { 45 } else { 20 };
    for member in members {
        local_offsets.push(out.len());
        let in_header = member.descriptor.is_none();
        // Local file header (4.3.7).
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, version_needed);
        push_u16(&mut out, member.flags);
        push_u16(&mut out, member.method);
        push_u16(&mut out, 0); // last mod time
        push_u16(&mut out, 0x21); // last mod date: 1980-01-01
        push_u32(&mut out, if in_header { member.crc } else { 0 });
        let (compressed, uncompressed) = match (zip64, in_header) {
            (true, _) => (u32::MAX, u32::MAX),
            (false, true) => (member.stored.len() as u32, member.size as u32),
            (false, false) => (0, 0),
        };
        push_u32(&mut out, compressed);
        push_u32(&mut out, uncompressed);
        push_u16(&mut out, member.name.len() as u16);
        push_u16(&mut out, if zip64 { 20 } else { 0 }); // extra field length
        out.extend_from_slice(member.name.as_bytes());
        if zip64 {
            // ZIP64 extra field: header ID 1, size 16, uncompressed and
            // compressed size.
            push_u16(&mut out, 1);
            push_u16(&mut out, 16);
            push_u64(&mut out, if in_header { member.size } else { 0 });
            push_u64(
                &mut out,
                if in_header {
                    member.stored.len() as u64
                } else {
                    0
                },
            );
        }
        data_offsets.push(out.len());
        out.extend_from_slice(&member.stored);
        if let Some(descriptor) = member.descriptor {
            if descriptor.signature {
                out.extend_from_slice(b"PK\x07\x08");
            }
            push_u32(&mut out, member.crc);
            if descriptor.wide {
                push_u64(&mut out, member.stored.len() as u64);
                push_u64(&mut out, member.size);
            } else {
                push_u32(&mut out, member.stored.len() as u32);
                push_u32(&mut out, member.size as u32);
            }
        }
    }
    let directory_offset = out.len();
    for (member, &local_offset) in members.iter().zip(&local_offsets) {
        // Central directory header (4.3.12).
        out.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut out, 0x031e); // made by UNIX, APPNOTE 3.0
        push_u16(&mut out, version_needed);
        push_u16(&mut out, member.flags);
        push_u16(&mut out, member.method);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0x21);
        push_u32(&mut out, member.crc);
        if zip64 {
            push_u32(&mut out, u32::MAX);
            push_u32(&mut out, u32::MAX);
        } else {
            push_u32(&mut out, member.stored.len() as u32);
            push_u32(&mut out, member.size as u32);
        }
        push_u16(&mut out, member.name.len() as u16);
        push_u16(&mut out, if zip64 { 28 } else { 0 }); // extra field length
        push_u16(&mut out, 0); // comment length
        push_u16(&mut out, 0); // disk number start
        push_u16(&mut out, 0); // internal attributes
        push_u32(&mut out, 0); // external attributes
        push_u32(&mut out, if zip64 { u32::MAX } else { local_offset as u32 });
        out.extend_from_slice(member.name.as_bytes());
        if zip64 {
            // ZIP64 extra field: uncompressed size, compressed size, local
            // header offset, in that order.
            push_u16(&mut out, 1);
            push_u16(&mut out, 24);
            push_u64(&mut out, member.size);
            push_u64(&mut out, member.stored.len() as u64);
            push_u64(&mut out, local_offset as u64);
        }
    }
    let directory_size = out.len() - directory_offset;
    let entries = members.len();
    if zip64 {
        let record_offset = out.len();
        // ZIP64 end of central directory record (4.3.14).
        out.extend_from_slice(b"PK\x06\x06");
        push_u64(&mut out, 44); // size of the rest of the record
        push_u16(&mut out, 0x031e);
        push_u16(&mut out, 45);
        push_u32(&mut out, 0); // this disk
        push_u32(&mut out, 0); // directory disk
        push_u64(&mut out, entries as u64);
        push_u64(&mut out, entries as u64);
        push_u64(&mut out, directory_size as u64);
        push_u64(&mut out, directory_offset as u64);
        // ZIP64 end of central directory locator (4.3.15).
        out.extend_from_slice(b"PK\x06\x07");
        push_u32(&mut out, 0);
        push_u64(&mut out, record_offset as u64);
        push_u32(&mut out, 1); // total disks
    }
    // End of central directory record (4.3.16).
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    let (entries16, size32, offset32) = if zip64 {
        (u16::MAX, u32::MAX, u32::MAX)
    } else {
        (
            entries as u16,
            directory_size as u32,
            directory_offset as u32,
        )
    };
    push_u16(&mut out, entries16);
    push_u16(&mut out, entries16);
    push_u32(&mut out, size32);
    push_u32(&mut out, offset32);
    push_u16(&mut out, 0); // comment length
    BuiltZip {
        bytes: out,
        data_offsets,
    }
}

/// The offset of the central directory, from the end record of an archive
/// without a comment.
fn zip_directory_offset(archive: &[u8]) -> usize {
    let end = archive.len() - 22;
    u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap()) as usize
}

#[test]
fn zip_fixtures_from_real_tools_decode_and_list_the_elf_member() {
    let payload = fixture("payload.elf");
    // Fixture, the codec named on the slice, and the encoder.
    let fixtures = [
        ("stored.zip", None),
        ("deflate.zip", Some("DEFLATE")),
        ("descriptor.zip", Some("DEFLATE")),
        ("zip64.zip", Some("DEFLATE")),
        ("bzip2.zip", Some("bzip2")),
        ("lzma.zip", Some("LZMA")),
        ("xz.zip", Some("xz")),
        ("zstd.zip", Some("Zstandard")),
    ];
    for (name, transform) in fixtures {
        let archive = fixture(name);
        assert_eq!(
            detected_layout(&archive),
            Some(archives::Layout::Zip),
            "{name}"
        );
        let p = classify(&archive).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::Zip, "{name}");
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (Isa::AArch64, 64, Endianness::Little),
            "{name}"
        );
        assert_eq!(p.slices.len(), 1, "{name}: only the ELF member is listed");
        let member = slice(&p, "bin/payload.elf");
        let stored = &archive[member.offset as usize..(member.offset + member.size) as usize];
        match transform {
            None => {
                assert!(member.decoded.is_none(), "{name}");
                assert_eq!(stored, payload.as_slice(), "{name}");
            }
            Some(codec) => {
                let decoded = member.decoded.as_ref().expect("decoded range");
                assert_eq!(decoded.transform, codec, "{name}");
                assert_eq!((decoded.offset, decoded.size), (0, 256), "{name}");
            }
        }
        assert!(
            has_note(&p, "CRC-32 verified for 2 of 2 file members"),
            "{name}"
        );
        assert!(has_note(
            &p,
            "1 of 2 file members are in a recognized format and listed"
        ));
        assert!(matches!(
            metadata(&p, "zip_crc_verified"),
            Some(MetadataValue::Integer(2))
        ));
    }
    let descriptor = classify(&fixture("descriptor.zip")).unwrap();
    assert!(has_note(
        &descriptor,
        "2 members use data descriptors (flag bit 3)"
    ));
    assert!(matches!(
        metadata(&descriptor, "zip_data_descriptors"),
        Some(MetadataValue::Integer(2))
    ));
    assert!(has_note(
        &classify(&fixture("zip64.zip")).unwrap(),
        "ZIP64 end records"
    ));
}

#[test]
fn encrypted_and_deflate64_members_are_opaque_and_noted() {
    for name in ["encrypted.zip", "aes.zip"] {
        let p = classify(&fixture(name)).unwrap();
        assert_eq!(p.format.format, FileFormat::Zip, "{name}");
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
        assert!(p.slices.is_empty(), "{name}");
        assert!(
            has_note(
                &p,
                "Encrypted members (flag bit 0) are opaque and were not analyzed: \
                 bin/payload.elf, notes.txt"
            ),
            "{name}: {:?}",
            p.notes
        );
        assert!(
            has_note(&p, "CRC-32 verified for 0 of 2 file members"),
            "{name}"
        );
    }
    let p = classify(&fixture("deflate64.zip")).unwrap();
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    assert!(has_note(
        &p,
        "Deflate64 members (method 9) are not decoded and are opaque: bin/payload.elf"
    ));

    // A flagged member stays opaque whatever its method, and an unknown
    // method is named.
    let mut encrypted = ZipMember::stored("x86.elf", &elf(2, false, EM_X86_64));
    encrypted.flags |= FLAG_ENCRYPTED;
    let mut ppmd = ZipMember::stored("ppmd.elf", &elf(2, false, EM_X86_64));
    ppmd.method = METHOD_PPMD;
    let p = classify(&zip(&[encrypted, ppmd], false).bytes).unwrap();
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "opaque and were not analyzed: x86.elf"));
    assert!(has_note(
        &p,
        "Members with unsupported compression methods are opaque: ppmd.elf (method 98)"
    ));
}

#[test]
fn zip_members_are_classified_on_their_own_bytes_with_stored_offsets() {
    let x86 = elf(2, false, EM_X86_64);
    let ppc = elf(1, true, EM_PPC);
    let members = [
        ZipMember::stored("readme.txt", b"not a recognized format"),
        ZipMember::stored("bin/x86.elf", &x86),
        ZipMember::deflated("bin/ppc.elf", &ppc),
    ];
    let built = zip(&members, false);
    let p = classify(&built.bytes).unwrap();
    assert_eq!(p.format.format, FileFormat::Zip);
    // The first recognized member supplies the primary ISA.
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 2);
    let x86_slice = slice(&p, "bin/x86.elf");
    assert_eq!(x86_slice.isa, Isa::X86_64);
    assert_eq!(x86_slice.offset as usize, built.data_offsets[1]);
    assert_eq!(x86_slice.size, 64);
    assert!(x86_slice.decoded.is_none());
    let ppc_slice = slice(&p, "bin/ppc.elf");
    assert_eq!(
        (ppc_slice.isa, ppc_slice.endianness),
        (Isa::Ppc, Endianness::Big)
    );
    assert_eq!(ppc_slice.offset as usize, built.data_offsets[2]);
    assert_eq!(ppc_slice.size as usize, members[2].stored.len());
    let decoded = ppc_slice.decoded.as_ref().expect("deflated member");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("DEFLATE", 64));
    assert!(matches!(
        metadata(&p, "zip_entries"),
        Some(MetadataValue::Integer(3))
    ));
    assert!(matches!(
        metadata(&p, "zip_central_directory_offset"),
        Some(MetadataValue::Integer(offset)) if *offset as usize == zip_directory_offset(&built.bytes)
    ));
    assert!(has_note(&p, "3 entries (3 files, 0 directories)"));
}

#[test]
fn zip_data_descriptors_in_every_form_match_the_central_directory() {
    let x86 = elf(2, false, EM_X86_64);
    for zip64 in [false, true] {
        for signature in [true, false] {
            for wide in [false, true] {
                let member = ZipMember::deflated("a.elf", &x86).with_descriptor(signature, wide);
                let built = zip(&[member], zip64);
                let case = format!("zip64 {zip64}, signature {signature}, wide {wide}");
                let p = classify(&built.bytes).unwrap_or_else(|e| panic!("{case}: {e}"));
                assert_eq!(p.primary.isa, Isa::X86_64, "{case}");
                assert!(has_note(&p, "1 member uses a data descriptor"), "{case}");
                assert_eq!(slice(&p, "a.elf").offset as usize, built.data_offsets[0]);
            }
        }
    }
    // A descriptor whose CRC-32 differs from the central directory.
    let mut member = ZipMember::deflated("a.elf", &x86).with_descriptor(true, false);
    let built = zip(std::slice::from_mut(&mut member), false);
    let mut corrupt = built.bytes.clone();
    let descriptor_crc = built.data_offsets[0] + member.stored.len() + 4;
    corrupt[descriptor_crc] ^= 0x01;
    let error = classify(&corrupt).unwrap_err().to_string();
    assert!(error.contains("Archive container parse error"), "{error}");
    assert!(
        error.contains("Invalid ZIP data descriptor for `a.elf`"),
        "{error}"
    );
}

#[test]
fn zip64_end_records_and_extra_fields_replace_saturated_fields() {
    let x86 = elf(2, false, EM_X86_64);
    let members = [
        ZipMember::stored("notes.txt", b"plain text"),
        ZipMember::deflated("x86.elf", &x86),
    ];
    let built = zip(&members, true);
    let p = classify(&built.bytes).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(&p, "ZIP64 end records"));
    assert_eq!(slice(&p, "x86.elf").offset as usize, built.data_offsets[1]);

    // A locator that points past itself, and a ZIP64 record whose size
    // field does not reach the locator.
    let locator = built.bytes.len() - 22 - 20;
    let mut bad_offset = built.bytes.clone();
    bad_offset[locator + 8..locator + 16].copy_from_slice(&(locator as u64).to_le_bytes());
    assert!(classify(&bad_offset)
        .unwrap_err()
        .to_string()
        .contains("Truncated ZIP64 end record"));
    let record = locator - 56;
    let mut bad_size = built.bytes.clone();
    bad_size[record + 4] = 43;
    assert!(classify(&bad_size)
        .unwrap_err()
        .to_string()
        .contains("Invalid ZIP64 end record size"));
}

#[test]
fn zip_member_crc_mismatches_are_noted_and_not_classified() {
    let x86 = elf(2, false, EM_X86_64);
    let mut member = ZipMember::deflated("x86.elf", &x86);
    member.crc ^= 0xdead_beef;
    let p = classify(&zip(&[member], false).bytes).unwrap();
    assert_eq!(p.format.format, FileFormat::Zip);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "CRC-32 verified for 0 of 1 file members"));
    assert!(has_note(
        &p,
        "Members that failed to decode or verify were not classified: x86.elf: CRC-32 0x"
    ));
}

#[test]
fn inconsistent_zip_structure_is_an_error() {
    let x86 = elf(2, false, EM_X86_64);
    let built = zip(&[ZipMember::stored("x86.elf", &x86)], false);
    let expect_error = |bytes: &[u8], text: &str| {
        let error = classify(bytes).unwrap_err().to_string();
        assert!(error.contains(text), "{error}");
    };

    // The local file name differs from the central directory's.
    let mut renamed = built.bytes.clone();
    renamed[30] = b'y';
    expect_error(&renamed, "file name differs from the central directory");

    // The local method differs.
    let mut method = built.bytes.clone();
    method[8] = 8;
    expect_error(&method, "method differs from the central directory");

    // The end record's directory offset is off by one.
    let mut offset = built.bytes.clone();
    let end = offset.len() - 22;
    offset[end + 16] += 1;
    expect_error(&offset, "Invalid ZIP central directory at 0x");

    // More entries than the directory can hold.
    let mut count = built.bytes.clone();
    count[end + 8] = 9;
    count[end + 10] = 9;
    expect_error(&count, "Invalid ZIP entry count 9");

    // A garbage comment length: no end record reaches the end of the file.
    let mut comment = built.bytes.clone();
    comment[end + 20] = 1;
    expect_error(&comment, "Invalid ZIP archive comment length");

    // Two central directory entries that share one local record.
    let one = ZipMember::stored("x86.elf", &x86);
    let two = ZipMember::stored("x86.elf", &x86);
    let mut shared = zip(&[one, two], false).bytes;
    let second_header = zip_directory_offset(&shared) + 46 + "x86.elf".len();
    shared[second_header + 42..second_header + 46].copy_from_slice(&0u32.to_le_bytes());
    expect_error(&shared, "overlaps `x86.elf` at 0x0");

    // Data after the end record that is not padding.
    let mut trailing = built.bytes.clone();
    trailing.extend_from_slice(b"junk");
    expect_error(&trailing, "Invalid ZIP archive comment length");
    let mut padded = built.bytes.clone();
    padded.extend_from_slice(&[0xff; 64]);
    let p = classify(&padded).unwrap();
    assert!(has_note(&p, "64 B of padding after the end record"));
}

#[test]
fn zip_extraction_limits_are_checked_before_decoding() {
    let mut member = ZipMember::deflated("huge.elf", &elf(2, false, EM_X86_64));
    // A declared size above the 64 MiB per-member limit.
    member.size = (64 << 20) + 1;
    let p = classify(&zip(&[member], false).bytes).unwrap();
    assert!(p.slices.is_empty());
    assert!(has_note(
        &p,
        "Members over the extraction limits (64 MiB per member, 256 MiB per archive) were not \
         decoded or classified: huge.elf (67108865 B)"
    ));
}

#[test]
fn package_layouts_are_labels_and_never_an_isa() {
    let text = |name: &str| ZipMember::stored(name, b"text, not a recognized format");
    let nordic_manifest = br#"{"manifest": {"application": {"bin_file": "app.bin"},
        "softdevice": {"bin_file": "sd.bin"}}}"#;
    let cases: [(&str, Vec<ZipMember>, &str, &str); 5] = [
        (
            "Android APK",
            vec![
                text("AndroidManifest.xml"),
                text("classes.dex"),
                text("META-INF/MANIFEST.MF"),
            ],
            "apk",
            "AndroidManifest.xml and classes.dex at the root",
        ),
        (
            "Java JAR",
            vec![text("META-INF/MANIFEST.MF"), text("a/B.class")],
            "jar",
            "META-INF",
        ),
        (
            "iOS IPA",
            vec![
                text("Payload/Demo.app/Info.plist"),
                text("Payload/Demo.app/Demo"),
            ],
            "ipa",
            "Payload/Demo.app/",
        ),
        (
            "Nordic DFU package",
            vec![
                ZipMember::stored("manifest.json", nordic_manifest),
                text("app.bin"),
            ],
            "nordic_dfu",
            "manifest.json names application, softdevice",
        ),
        (
            "ASAM ODX PDX package",
            vec![text("index.xml"), text("ecu.odx-f")],
            "pdx",
            "index.xml at the root and .odx* members",
        ),
    ];
    for (label, members, id, evidence) in cases {
        let p = classify(&zip(&members, false).bytes).unwrap();
        assert_eq!(p.format.format, FileFormat::Zip, "{label}");
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{label}");
        assert_eq!(p.primary.confidence, 0.0, "{label}");
        assert_eq!(
            p.primary.variant.as_ref().map(|v| v.name.as_str()),
            Some(label)
        );
        assert!(matches!(metadata(&p, "zip_package"), Some(MetadataValue::String(s)) if s == id));
        assert!(
            has_note(&p, &format!("Package layout: {label} ({evidence}")),
            "{label}: {:?}",
            p.notes
        );
        assert!(has_note(&p, "the package type does not determine an ISA"));
    }

    // An APK's native library supplies the ISA from its own ELF header.
    let members = [
        text("AndroidManifest.xml"),
        text("classes.dex"),
        ZipMember::deflated("lib/riscv64/libdemo.so", &elf(2, false, EM_RISCV)),
    ];
    let p = classify(&zip(&members, false).bytes).unwrap();
    assert_eq!(p.primary.isa, Isa::RiscV64);
    assert_eq!(slice(&p, "lib/riscv64/libdemo.so").isa, Isa::RiscV64);
    assert!(has_note(&p, "Package layout: Android APK"));

    // An APK Signing Block (APK Signature Scheme v2): its size (8 B,
    // excluding this field), ID-value pairs (none here), the size again and
    // the 16-byte magic, between the last member and the central directory.
    let apk = zip(&[text("AndroidManifest.xml"), text("classes.dex")], false).bytes;
    let directory = zip_directory_offset(&apk);
    let mut block = 24u64.to_le_bytes().to_vec();
    block.extend_from_slice(&24u64.to_le_bytes());
    block.extend_from_slice(b"APK Sig Block 42");
    let mut signed = apk[..directory].to_vec();
    signed.extend_from_slice(&block);
    signed.extend_from_slice(&apk[directory..]);
    let end = signed.len() - 22;
    let moved = (directory + block.len()) as u32;
    signed[end + 16..end + 20].copy_from_slice(&moved.to_le_bytes());
    let p = classify(&signed).unwrap();
    assert!(has_note(
        &p,
        "APK Signing Block before the central directory; signatures not verified"
    ));
}

#[test]
fn nested_archives_are_classified_as_members() {
    let inner = zip(
        &[ZipMember::deflated("x86.elf", &elf(2, false, EM_X86_64))],
        false,
    );
    let outer = zip(&[ZipMember::stored("inner.jar", &inner.bytes)], false);
    let p = classify(&outer.bytes).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    let member = slice(&p, "inner.jar");
    assert_eq!(member.offset as usize, outer.data_offsets[0]);
    assert_eq!(member.isa, Isa::X86_64);
}

// tar (POSIX.1-2024 pax "ustar Interchange Format"; GNU tar 1.35 tar.h).

/// The magic and version at offset 257.
#[derive(Clone, Copy)]
enum TarMagic {
    /// POSIX `ustar\0` and version `00`.
    Ustar,
    /// GNU `ustar  \0` over magic and version.
    Gnu,
}

/// How the 12-byte `size` field is written.
#[derive(Clone, Copy)]
enum TarSize {
    /// 11 octal digits and NUL.
    Octal(u64),
    /// GNU base-256: `0x80`, then the value big-endian in 11 bytes.
    Base256(u64),
}

/// The header fields the builder writes; everything else is zero.
struct TarHeader<'a> {
    name: &'a str,
    /// ustar `prefix` (345, 155), joined to `name` with `/`.
    prefix: &'a str,
    typeflag: u8,
    size: TarSize,
    magic: TarMagic,
}

impl<'a> TarHeader<'a> {
    fn file(name: &'a str, size: usize) -> Self {
        Self {
            name,
            prefix: "",
            typeflag: b'0',
            size: TarSize::Octal(size as u64),
            magic: TarMagic::Ustar,
        }
    }
}

/// Octal digits filling `field` but its last byte, then NUL.
fn put_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let digits = format!("{value:0width$o}");
    field[..width].copy_from_slice(digits.as_bytes());
    field[width] = 0;
}

/// A 512-byte header: name (0, 100), mode (100), uid (108), gid (116),
/// size (124, 12), mtime (136), chksum (148, 8), typeflag (156), magic and
/// version (257, 8), prefix (345, 155). The checksum is the sum of all
/// bytes with the checksum field counted as spaces, written as six octal
/// digits, NUL and space.
fn tar_header(header: &TarHeader<'_>) -> Vec<u8> {
    let mut block = vec![0u8; 512];
    block[..header.name.len()].copy_from_slice(header.name.as_bytes());
    put_octal(&mut block[100..108], 0o644);
    put_octal(&mut block[108..116], 0);
    put_octal(&mut block[116..124], 0);
    match header.size {
        TarSize::Octal(size) => put_octal(&mut block[124..136], size),
        TarSize::Base256(size) => {
            block[124] = 0x80;
            block[128..136].copy_from_slice(&size.to_be_bytes());
        }
    }
    put_octal(&mut block[136..148], 0);
    block[156] = header.typeflag;
    match header.magic {
        TarMagic::Ustar => block[257..265].copy_from_slice(b"ustar\x0000"),
        TarMagic::Gnu => block[257..265].copy_from_slice(b"ustar  \0"),
    }
    block[345..345 + header.prefix.len()].copy_from_slice(header.prefix.as_bytes());
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

/// A header followed by `contents` padded with zeros to whole blocks.
fn tar_entry(header: &TarHeader<'_>, contents: &[u8]) -> Vec<u8> {
    let mut entry = tar_header(header);
    entry.extend_from_slice(contents);
    entry.resize(round_up(entry.len(), 512), 0);
    entry
}

/// A pax record `"%d %s=%s\n"`, whose decimal length counts itself.
fn pax_record(key: &str, value: &str) -> String {
    let body = key.len() + value.len() + 3;
    let mut len = body + body.to_string().len();
    len = body + len.to_string().len();
    format!("{len} {key}={value}\n")
}

/// The end-of-archive marker: two zero blocks.
fn tar_end() -> Vec<u8> {
    vec![0; 1024]
}

#[test]
fn tar_fixtures_from_real_tools_list_both_elf_members() {
    let payload = fixture("payload.elf");
    let long = "long/dddddddddddddddddddddddddddddddddddddddddddddddddd/\
                eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/payload.elf";
    for (name, dialect, extra_note) in [
        ("ustar.tar", "POSIX ustar format", None),
        (
            "pax.tar",
            "pax format",
            Some("1 pax extended header; `path` and `size`"),
        ),
        (
            "gnu.tar",
            "GNU tar format",
            Some("1 GNU long name or link name header"),
        ),
    ] {
        let archive = fixture(name);
        assert_eq!(
            detected_layout(&archive),
            Some(archives::Layout::Tar),
            "{name}"
        );
        let p = classify(&archive).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::Tar, "{name}");
        assert_eq!(p.primary.isa, Isa::AArch64, "{name}");
        assert_eq!(p.slices.len(), 2, "{name}");
        for label in ["bin/payload.elf", long] {
            let member = slice(&p, label);
            let stored = &archive[member.offset as usize..(member.offset + member.size) as usize];
            assert_eq!(stored, payload.as_slice(), "{name}: {label}");
            assert!(member.decoded.is_none());
        }
        assert!(has_note(&p, dialect), "{name}: {:?}", p.notes);
        assert!(has_note(&p, "every header checksum verified"), "{name}");
        if let Some(note) = extra_note {
            assert!(has_note(&p, note), "{name}: {:?}", p.notes);
        }
        assert!(matches!(
            metadata(&p, "tar_regular_files"),
            Some(MetadataValue::Integer(3))
        ));
    }
}

#[test]
fn tar_long_names_pax_records_and_base256_sizes_apply_to_the_next_entry() {
    let x86 = elf(2, false, EM_X86_64);
    let aarch64 = elf(2, false, EM_AARCH64);
    let long_name = format!("{}/x86.elf", "n".repeat(120));
    let pax_path = format!("{}/aarch64.elf", "p".repeat(150));
    let mut archive = Vec::new();
    // GNU long name: `././@LongLink`, type L, the name and its NUL as data.
    let long_link = TarHeader {
        name: "././@LongLink",
        typeflag: b'L',
        magic: TarMagic::Gnu,
        ..TarHeader::file("", long_name.len() + 1)
    };
    archive.extend(tar_entry(&long_link, format!("{long_name}\0").as_bytes()));
    let truncated_name = TarHeader {
        magic: TarMagic::Gnu,
        ..TarHeader::file("nnnn", x86.len())
    };
    let x86_offset = archive.len() + 512;
    archive.extend(tar_entry(&truncated_name, &x86));
    // pax extended header with `path` and `size`; the entry's own size
    // field says 0.
    let records = format!(
        "{}{}{}",
        pax_record("path", &pax_path),
        pax_record("size", &aarch64.len().to_string()),
        pax_record("mtime", "1791763200.5")
    );
    let pax = TarHeader {
        name: "PaxHeaders/aarch64.elf",
        typeflag: b'x',
        ..TarHeader::file("", records.len())
    };
    archive.extend(tar_entry(&pax, records.as_bytes()));
    let aarch64_offset = archive.len() + 512;
    let mut entry = tar_header(&TarHeader::file("short", 0));
    entry.extend_from_slice(&aarch64);
    entry.resize(1024, 0);
    archive.extend(entry);
    // A base-256 size and a ustar prefix.
    let riscv = elf(2, false, EM_RISCV);
    let base256 = TarHeader {
        prefix: "opt/lib",
        size: TarSize::Base256(riscv.len() as u64),
        ..TarHeader::file("riscv.elf", 0)
    };
    let riscv_offset = archive.len() + 512;
    archive.extend(tar_entry(&base256, &riscv));
    archive.extend(tar_end());

    let p = classify(&archive).unwrap();
    assert_eq!(p.format.format, FileFormat::Tar);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(slice(&p, &long_name).offset as usize, x86_offset);
    let pax_member = slice(&p, &pax_path);
    assert_eq!(
        (pax_member.isa, pax_member.offset as usize),
        (Isa::AArch64, aarch64_offset)
    );
    assert_eq!(pax_member.size, 64);
    let prefixed = slice(&p, "opt/lib/riscv.elf");
    assert_eq!(
        (prefixed.isa, prefixed.offset as usize),
        (Isa::RiscV64, riscv_offset)
    );
    assert!(has_note(&p, "GNU tar format; 3 entries (3 regular files"));
    assert!(has_note(&p, "1 pax extended header"));
    assert!(has_note(&p, "1 size in GNU base-256 encoding"));
}

#[test]
fn tar_entries_without_data_and_sparse_members_are_counted_not_classified() {
    let x86 = elf(2, false, EM_X86_64);
    let mut archive = Vec::new();
    // POSIX stores no data for directories and symbolic links, whatever
    // their size field says.
    let directory = TarHeader {
        typeflag: b'5',
        ..TarHeader::file("bin/", 4096)
    };
    archive.extend(tar_header(&directory));
    let symlink = TarHeader {
        typeflag: b'2',
        ..TarHeader::file("bin/link", 99)
    };
    archive.extend(tar_header(&symlink));
    // A GNU sparse member holds fragments: listed in a note only.
    let sparse = TarHeader {
        typeflag: b'S',
        magic: TarMagic::Gnu,
        ..TarHeader::file("sparse.elf", x86.len())
    };
    archive.extend(tar_entry(&sparse, &x86));
    // A pax GNU sparse 1.0 member is a regular file whose data begins with
    // the sparse map.
    let records = pax_record("GNU.sparse.major", "1");
    let pax = TarHeader {
        typeflag: b'x',
        ..TarHeader::file("PaxHeaders/sparse", records.len())
    };
    archive.extend(tar_entry(&pax, records.as_bytes()));
    archive.extend(tar_entry(
        &TarHeader::file("GNUSparseFile.0/a.elf", x86.len()),
        &x86,
    ));
    archive.extend(tar_entry(&TarHeader::file("x86.elf", x86.len()), &x86));
    archive.extend(tar_end());

    let p = classify(&archive).unwrap();
    assert_eq!(p.slices.len(), 1);
    assert_eq!(slice(&p, "x86.elf").isa, Isa::X86_64);
    assert!(
        has_note(
            &p,
            "5 entries (1 regular file, 1 directory, 1 link, 2 other)"
        ),
        "{:?}",
        p.notes
    );
    assert!(has_note(
        &p,
        "Sparse members hold only their data fragments and were not classified: sparse.elf, \
         GNUSparseFile.0/a.elf"
    ));
}

#[test]
fn corrupt_tar_headers_are_errors_or_not_tar() {
    let x86 = elf(2, false, EM_X86_64);
    let mut archive = tar_entry(&TarHeader::file("a.elf", x86.len()), &x86);
    archive.extend(tar_entry(&TarHeader::file("b.elf", x86.len()), &x86));
    archive.extend(tar_end());
    assert_eq!(classify(&archive).unwrap().slices.len(), 2);

    // A bad first checksum loses tar recognition.
    let mut first = archive.clone();
    first[0] ^= 0x01;
    assert_eq!(detected_layout(&first), None);
    // A bad later checksum is an error naming the field.
    let mut second = archive.clone();
    second[1024] ^= 0x01;
    let error = classify(&second).unwrap_err().to_string();
    assert!(
        error.contains("Archive container parse error: Invalid tar header checksum at 0x494"),
        "{error}"
    );
    // A size field with a non-octal digit.
    let mut size = tar_header(&TarHeader::file("a.elf", x86.len()));
    size[130] = b'9';
    size[148..156].fill(b' ');
    let sum: u32 = size.iter().map(|b| u32::from(*b)).sum();
    size[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let error = classify(&size).unwrap_err().to_string();
    assert!(error.contains("Invalid tar size field at 0x7C"), "{error}");
    // Member data beyond the end of the file.
    let truncated = tar_header(&TarHeader::file("a.elf", 4096));
    let error = classify(&truncated).unwrap_err().to_string();
    assert!(
        error.contains("Truncated tar member `a.elf` at 0x200 + 4096 B"),
        "{error}"
    );
    // A malformed pax record.
    let pax = TarHeader {
        typeflag: b'x',
        ..TarHeader::file("PaxHeaders/a", 9)
    };
    let mut bad_pax = tar_entry(&pax, b"99 path=a");
    bad_pax.extend(tar_end());
    let error = classify(&bad_pax).unwrap_err().to_string();
    assert!(
        error.contains("Invalid pax extended header record at 0x200"),
        "{error}"
    );
}

#[test]
fn data_after_the_tar_end_is_padding_a_recognized_component_or_an_error() {
    let x86 = elf(2, false, EM_X86_64);
    let mut archive = tar_entry(&TarHeader::file("a.elf", x86.len()), &x86);
    archive.extend(tar_end());
    let end = archive.len();

    // Zero record padding belongs to the archive; erased flash follows it.
    let mut padded = archive.clone();
    padded.extend_from_slice(&[0u8; 8192]);
    padded.extend_from_slice(&[0xff; 8192]);
    let p = classify(&padded).unwrap();
    assert!(
        has_note(&p, "8192 B of padding after the archive"),
        "{:?}",
        p.notes
    );

    // A second archive appended after the first one's end blocks.
    let mut concatenated = archive.clone();
    concatenated.extend(tar_entry(
        &TarHeader::file("b.elf", 64),
        &elf(2, true, EM_PPC),
    ));
    concatenated.extend(tar_end());
    let p = classify(&concatenated).unwrap();
    let rest = slice(&p, "Data after the archive");
    assert_eq!((rest.offset as usize, rest.isa), (end, Isa::Ppc));
    assert!(has_note(&p, "are listed as a separate component"));

    let mut junk = archive.clone();
    junk.extend_from_slice(b"not padding");
    let error = classify(&junk).unwrap_err().to_string();
    assert!(error.contains(&format!(
        "Unexpected data after the tar archive at 0x{end:X}"
    )));

    // No end blocks at all is accepted and noted.
    let unterminated = tar_entry(&TarHeader::file("a.elf", x86.len()), &x86);
    let p = classify(&unterminated).unwrap();
    assert!(has_note(
        &p,
        "The archive ends with 0 zero blocks instead of 2"
    ));
}

#[test]
fn tar_hard_links_store_data_only_in_pax_archives() {
    let x86 = elf(2, false, EM_X86_64);
    // A ustar hard link whose `size` says 64 but which stores no data, as
    // some writers produce: the next header follows right after it.
    let link = TarHeader {
        typeflag: b'1',
        ..TarHeader::file("bin/link", x86.len())
    };
    let mut ustar = tar_header(&link);
    let x86_offset = ustar.len() + 512;
    ustar.extend(tar_entry(&TarHeader::file("bin/x86.elf", x86.len()), &x86));
    ustar.extend(tar_end());
    let p = classify(&ustar).unwrap();
    assert_eq!(slice(&p, "bin/x86.elf").offset as usize, x86_offset);
    assert!(has_note(
        &p,
        "2 entries (1 regular file, 0 directories, 1 link"
    ));

    // After a pax header, a hard link's `size` counts its data blocks.
    let records = pax_record("mtime", "1791763200");
    let pax = TarHeader {
        typeflag: b'x',
        ..TarHeader::file("PaxHeaders/link", records.len())
    };
    let mut archive = tar_entry(&pax, records.as_bytes());
    archive.extend(tar_entry(&link, &x86));
    let x86_offset = archive.len() + 512;
    archive.extend(tar_entry(&TarHeader::file("bin/x86.elf", x86.len()), &x86));
    archive.extend(tar_end());
    let p = classify(&archive).unwrap();
    assert_eq!(p.slices.len(), 1, "the link's data is not a listed member");
    assert_eq!(slice(&p, "bin/x86.elf").offset as usize, x86_offset);
}

#[test]
fn pax_global_headers_are_checked_but_not_applied() {
    // `git archive` starts with a global header holding a `comment` record.
    let x86 = elf(2, false, EM_X86_64);
    let records = format!(
        "{}{}",
        pax_record("comment", "0123456789abcdef0123456789abcdef01234567"),
        pax_record("path", "global/path")
    );
    let global = TarHeader {
        typeflag: b'g',
        ..TarHeader::file("pax_global_header", records.len())
    };
    let mut archive = tar_entry(&global, records.as_bytes());
    archive.extend(tar_entry(&TarHeader::file("x86.elf", x86.len()), &x86));
    archive.extend(tar_end());
    let p = classify(&archive).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(slice(&p, "x86.elf").isa, Isa::X86_64);
    assert!(has_note(&p, "pax format; 1 entry (1 regular file"));
    assert!(has_note(
        &p,
        "1 pax global header; global records are not applied"
    ));
}

#[test]
fn tar_member_listing_stops_at_the_component_limit() {
    let x86 = elf(2, false, EM_X86_64);
    let limit = formats::container::MAX_COMPONENTS;
    let mut archive = Vec::new();
    for i in 0..=limit {
        archive.extend(tar_entry(
            &TarHeader::file(&format!("m{i}.elf"), x86.len()),
            &x86,
        ));
    }
    archive.extend(tar_end());
    let p = classify(&archive).unwrap();
    assert_eq!(p.slices.len(), limit);
    assert!(has_note(
        &p,
        "Member listing stopped at 4096 recognized members; 1 further file member was not \
         examined"
    ));
}

// CPIO (libarchive v3.7.4 cpio.5).

const MODE_REGULAR: u32 = 0o100_644;
const MODE_DIRECTORY: u32 = 0o040_755;

/// newc (`070701`) or crc (`070702`) entry: the magic, 13 fields of 8 hex
/// digits (`c_ino`, `c_mode`, `c_uid`, `c_gid`, `c_nlink`, `c_mtime`,
/// `c_filesize`, `c_devmajor`, `c_devminor`, `c_rdevmajor`,
/// `c_rdevminor`, `c_namesize`, `c_check`), the name and its NUL padded to
/// 4 bytes, then the data padded to 4 bytes.
fn newc_entry(magic: &str, name: &str, mode: u32, contents: &[u8], check: u32) -> Vec<u8> {
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
        check,
    ];
    let mut entry = magic.as_bytes().to_vec();
    for field in fields {
        entry.extend_from_slice(format!("{field:08X}").as_bytes());
    }
    entry.extend_from_slice(name.as_bytes());
    entry.push(0);
    entry.resize(round_up(entry.len(), 4), 0);
    entry.extend_from_slice(contents);
    entry.resize(round_up(entry.len(), 4), 0);
    entry
}

/// The crc format checksum: the 32-bit sum of the data bytes.
fn byte_sum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |sum, b| sum.wrapping_add(u32::from(*b)))
}

/// A newc archive of `entries`, ended by `TRAILER!!!` and padded to 512.
fn newc_archive(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, mode, contents) in entries {
        archive.extend(newc_entry("070701", name, *mode, contents, 0));
    }
    archive.extend(newc_entry("070701", "TRAILER!!!", 0, b"", 0));
    archive.resize(round_up(archive.len(), 512), 0);
    archive
}

/// odc (`070707`) entry: the magic, `c_dev`, `c_ino`, `c_mode`, `c_uid`,
/// `c_gid`, `c_nlink`, `c_rdev` (6 octal digits each), `c_mtime` (11),
/// `c_namesize` (6), `c_filesize` (11); the name and the data follow
/// without padding.
fn odc_entry(name: &str, mode: u32, contents: &[u8]) -> Vec<u8> {
    let mut entry = format!(
        "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
        0,
        1,
        0,
        0,
        1,
        0,
        0,
        name.len() + 1,
        contents.len()
    )
    .into_bytes();
    entry.extend_from_slice(name.as_bytes());
    entry.push(0);
    entry.extend_from_slice(contents);
    entry
}

/// Old binary entry of 16-bit words in the archive byte order: `h_magic`
/// (0o070707), `h_dev`, `h_ino`, `h_mode`, `h_uid`, `h_gid`, `h_nlink`,
/// `h_rdev`, `h_mtime` (two words), `h_namesize`, `h_filesize` (two words,
/// most significant first); the name and the data padded to 2 bytes.
fn binary_entry(le: bool, name: &str, mode: u16, contents: &[u8]) -> Vec<u8> {
    let size = contents.len() as u32;
    let words = [
        0o070_707,
        0,
        1,
        mode,
        0,
        0,
        1,
        0,
        0,
        0,
        name.len() as u16 + 1,
        (size >> 16) as u16,
        size as u16,
    ];
    let mut entry = Vec::new();
    for word in words {
        let bytes = if le {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        };
        entry.extend_from_slice(&bytes);
    }
    entry.extend_from_slice(name.as_bytes());
    entry.push(0);
    entry.resize(round_up(entry.len(), 2), 0);
    entry.extend_from_slice(contents);
    entry.resize(round_up(entry.len(), 2), 0);
    entry
}

/// Offset of the first occurrence of `needle` in `data`.
fn find(data: &[u8], needle: &[u8]) -> usize {
    data.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present")
}

#[test]
fn cpio_fixtures_from_bsdcpio_list_the_elf_member() {
    let payload = fixture("payload.elf");
    for (name, layout, label, weak) in [
        (
            "newc.cpio",
            archives::Layout::CpioNewc,
            "CPIO newc archive",
            false,
        ),
        (
            "odc.cpio",
            archives::Layout::CpioOdc,
            "CPIO odc archive",
            false,
        ),
        (
            "binary.cpio",
            archives::Layout::CpioBinaryLe,
            "CPIO binary archive (little-endian)",
            true,
        ),
    ] {
        let archive = fixture(name);
        assert_eq!(detected_layout(&archive), Some(layout), "{name}");
        let p = classify(&archive).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::Cpio, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some(label), "{name}");
        assert_eq!(p.format.confidence < 1.0, weak, "{name}");
        assert_eq!(p.primary.isa, Isa::AArch64, "{name}");
        let member = slice(&p, "bin/payload.elf");
        assert_eq!(member.offset as usize, find(&archive, &payload), "{name}");
        assert_eq!(member.size, 256);
        assert!(has_note(
            &p,
            "3 entries (2 regular files, 1 directory, 0 symbolic links, 0 other) before \
             `TRAILER!!!`"
        ));
        assert!(has_note(&p, "archives carry no data checksum"), "{name}");
    }
}

#[test]
fn cpio_crc_checksums_are_verified_and_mismatches_are_not_classified() {
    let x86 = elf(2, false, EM_X86_64);
    let mut archive = newc_entry("070702", "bin", MODE_DIRECTORY, b"", 0);
    archive.extend(newc_entry(
        "070702",
        "bin/x86",
        MODE_REGULAR,
        &x86,
        byte_sum(&x86),
    ));
    archive.extend(newc_entry("070702", "TRAILER!!!", 0, b"", 0));
    assert_eq!(detected_layout(&archive), Some(archives::Layout::CpioCrc));
    let p = classify(&archive).unwrap();
    assert_eq!(p.format.variant_name.as_deref(), Some("CPIO crc archive"));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(has_note(
        &p,
        "crc format data checksums verified for 1 of 1 regular files"
    ));
    assert!(matches!(
        metadata(&p, "cpio_checksums_verified"),
        Some(MetadataValue::Integer(1))
    ));

    let mut corrupt = newc_entry("070702", "bin/x86", MODE_REGULAR, &x86, byte_sum(&x86) + 1);
    corrupt.extend(newc_entry("070702", "TRAILER!!!", 0, b"", 0));
    let p = classify(&corrupt).unwrap();
    assert!(p.slices.is_empty());
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "Members that failed the crc format checksum were not classified: bin/x86"
    ));
}

#[test]
fn binary_cpio_in_both_byte_orders_is_recognized_from_complete_structure() {
    let ppc = elf(1, true, EM_PPC);
    for (le, layout) in [
        (true, archives::Layout::CpioBinaryLe),
        (false, archives::Layout::CpioBinaryBe),
    ] {
        let mut archive = binary_entry(le, "boot/ppc.elf", 0o100_644, &ppc);
        let member_offset = 26 + "boot/ppc.elf".len() + 2;
        archive.extend(binary_entry(le, "TRAILER!!!", 0, b""));
        assert_eq!(detected_layout(&archive), Some(layout));
        let p = classify(&archive).unwrap();
        assert_eq!(p.format.format, FileFormat::Cpio);
        assert!(p.format.confidence < 1.0);
        let member = slice(&p, "boot/ppc.elf");
        assert_eq!(
            (member.isa, member.offset as usize),
            (Isa::Ppc, member_offset)
        );

        // Without the trailer, the two-byte magic is not enough.
        let unterminated = binary_entry(le, "boot/ppc.elf", 0o100_644, &ppc);
        assert_eq!(detected_layout(&unterminated), None);
        // Data after the trailer that is neither padding nor recognized.
        let mut junk = archive.clone();
        junk.extend_from_slice(b"junk");
        assert_eq!(detected_layout(&junk), None);
    }
}

#[test]
fn concatenated_cpio_archives_and_compressed_tails_are_followed() {
    let x86 = elf(2, false, EM_X86_64);
    let aarch64 = elf(2, false, EM_AARCH64);
    // An early archive, NUL padding, then a second archive in another
    // variant, as Linux initramfs images are built.
    let mut archive = newc_archive(&[("kernel/x86/microcode.bin", MODE_REGULAR, b"blob")]);
    archive.extend(odc_entry("sbin/init", MODE_REGULAR, &aarch64));
    archive.extend(odc_entry("TRAILER!!!", 0, b""));
    let p = classify(&archive).unwrap();
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(
        slice(&p, "sbin/init").offset as usize,
        find(&archive, &aarch64)
    );
    assert!(
        has_note(&p, "2 concatenated archives (newc, odc)"),
        "{:?}",
        p.notes
    );
    assert!(matches!(
        metadata(&p, "cpio_archives"),
        Some(MetadataValue::Integer(2))
    ));

    // An uncompressed early archive followed by a gzip-compressed one.
    let mut early = newc_archive(&[("early.elf", MODE_REGULAR, &x86)]);
    let tail_offset = early.len();
    early.extend(gzip(&newc_archive(&[("init", MODE_REGULAR, &aarch64)])));
    let p = classify(&early).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    let tail = slice(&p, "Data after the archive");
    assert_eq!(
        (tail.offset as usize, tail.isa),
        (tail_offset, Isa::AArch64)
    );

    // Anything else after the trailer is an error.
    let mut junk = newc_archive(&[("a", MODE_REGULAR, &x86)]);
    junk.extend_from_slice(b"junk");
    let error = classify(&junk).unwrap_err().to_string();
    assert!(
        error.contains("Unexpected data after the CPIO archive at 0x"),
        "{error}"
    );
}

#[test]
fn gzip_compressed_cpio_lists_the_member_with_its_decoded_range() {
    // The committed initramfs-style fixture: gzip -n -9 of newc.cpio.
    let stored = fixture("initramfs.cpio.gz");
    let decoded_offset = find(&fixture("newc.cpio"), &fixture("payload.elf"));
    let p = classify(&stored).unwrap();
    assert_eq!(p.format.format, FileFormat::Gzip);
    assert_eq!(p.primary.isa, Isa::AArch64);
    let member = slice(&p, "bin/payload.elf");
    assert_eq!((member.offset, member.size as usize), (0, stored.len()));
    let decoded = member.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "gzip");
    assert_eq!(
        (decoded.offset as usize, decoded.size),
        (decoded_offset, 256)
    );
    assert!(has_note(&p, "Decoded payload: CPIO"));

    // gzip(cpio(ELF)) built here from the layouts.
    let x86 = elf(2, false, EM_X86_64);
    let cpio = newc_archive(&[
        ("bin", MODE_DIRECTORY, b""),
        ("bin/x86", MODE_REGULAR, &x86),
    ]);
    let stored = gzip(&cpio);
    let p = classify(&stored).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    let member = slice(&p, "bin/x86");
    let decoded = member.decoded.as_ref().expect("decoded range");
    assert_eq!((member.offset, member.size as usize), (0, stored.len()));
    assert_eq!(
        (decoded.offset as usize, decoded.size),
        (find(&cpio, &x86), 64)
    );
}

#[test]
fn corrupt_cpio_headers_are_errors() {
    let x86 = elf(2, false, EM_X86_64);
    let archive = newc_archive(&[("a.elf", MODE_REGULAR, &x86)]);
    let expect_error = |bytes: &[u8], text: &str| {
        let error = classify(bytes).unwrap_err().to_string();
        assert!(error.contains("Archive container parse error"), "{error}");
        assert!(error.contains(text), "{error}");
    };
    // A non-hex digit in the second entry's `c_filesize`.
    let second = newc_entry("070701", "a.elf", MODE_REGULAR, &x86, 0).len();
    let mut size = archive.clone();
    size[second + 54] = b'z';
    expect_error(
        &size,
        &format!("Invalid CPIO header field at 0x{:X}", second + 54),
    );
    // The second entry's name does not end with NUL.
    let mut name = archive.clone();
    name[second + 110 + "TRAILER!!!".len()] = b'!';
    expect_error(
        &name,
        &format!("Invalid CPIO name size 11 at 0x{second:X}: the name must end with NUL"),
    );
    // A second entry whose data runs past the end of the file.
    let first = newc_entry("070701", "a.elf", MODE_REGULAR, &x86, 0);
    let mut overrun = first.clone();
    overrun.extend(newc_entry("070701", "b.elf", MODE_REGULAR, &x86, 0));
    overrun.truncate(overrun.len() - 8);
    let data_offset = first.len() + 116;
    expect_error(
        &overrun,
        &format!("Truncated CPIO member data at 0x{data_offset:X} + 64 B"),
    );
    // No trailer before the end of the file.
    expect_error(
        &first,
        &format!("Truncated CPIO newc header at 0x{:X} + 110 B", first.len()),
    );
    // A corrupt first header loses CPIO recognition.
    let mut header = archive.clone();
    header[6] = b'g';
    assert_eq!(detected_layout(&header), None);
    // A valid first header and name are enough for recognition, so a
    // first member cut off by the end of the file is an error, not raw code.
    let cut = &first[..first.len() - 8];
    assert_eq!(detected_layout(cut), Some(archives::Layout::CpioNewc));
    expect_error(cut, "Truncated CPIO member data at 0x74 + 64 B");
}

#[test]
fn members_larger_than_the_recognition_prefix_are_listed() {
    // A newc archive whose first member (8 KiB of data) ends past the 4 KiB
    // recognition prefix, stored as a tar member: the prefix holds only the
    // first header and name, which is enough to recognize it.
    let x86 = elf(2, false, EM_X86_64);
    let blob = vec![0x5a; 8 << 10];
    let cpio = newc_archive(&[
        ("blob.bin", MODE_REGULAR, &blob),
        ("bin/x86", MODE_REGULAR, &x86),
    ]);
    let mut archive = tar_entry(&TarHeader::file("initramfs.cpio", cpio.len()), &cpio);
    archive.extend(tar_end());
    let p = classify(&archive).unwrap();
    assert_eq!(p.primary.isa, Isa::X86_64);
    let member = slice(&p, "initramfs.cpio");
    assert_eq!(
        (member.offset, member.size as usize, member.isa),
        (512, cpio.len(), Isa::X86_64)
    );
}

// Sweeps over every layout.

/// Every committed archive fixture.
const ARCHIVE_FIXTURES: &[&str] = &[
    "stored.zip",
    "deflate.zip",
    "descriptor.zip",
    "zip64.zip",
    "bzip2.zip",
    "lzma.zip",
    "xz.zip",
    "zstd.zip",
    "deflate64.zip",
    "encrypted.zip",
    "aes.zip",
    "ustar.tar",
    "pax.tar",
    "gnu.tar",
    "newc.cpio",
    "odc.cpio",
    "binary.cpio",
];

/// Archives built from the layouts, for layouts no tool here writes.
fn built_archives() -> Vec<(&'static str, Vec<u8>)> {
    let x86 = elf(2, false, EM_X86_64);
    let mut crc = newc_entry("070702", "x86", MODE_REGULAR, &x86, byte_sum(&x86));
    crc.extend(newc_entry("070702", "TRAILER!!!", 0, b"", 0));
    let mut big_endian = binary_entry(false, "x86", 0o100_644, &x86);
    big_endian.extend(binary_entry(false, "TRAILER!!!", 0, b""));
    let zip64 = zip(
        &[ZipMember::deflated("x86", &x86).with_descriptor(true, true)],
        true,
    )
    .bytes;
    let mut gnu = tar_entry(
        &TarHeader {
            name: "././@LongLink",
            typeflag: b'L',
            magic: TarMagic::Gnu,
            ..TarHeader::file("", 4)
        },
        b"x86\0",
    );
    gnu.extend(tar_entry(
        &TarHeader {
            size: TarSize::Base256(64),
            ..TarHeader::file("x", 0)
        },
        &x86,
    ));
    gnu.extend(tar_end());
    vec![
        ("crc", crc),
        ("big-endian binary", big_endian),
        ("zip64", zip64),
        ("gnu", gnu),
    ]
}

/// Bytes worth mutating: tar fixtures end in kilobytes of record padding.
fn sweep_len(data: &[u8]) -> usize {
    let last = data.iter().rposition(|b| *b != 0).unwrap_or(0);
    (last + 1024).min(data.len())
}

#[test]
fn truncated_archives_never_claim_members_beyond_the_prefix() {
    let mut inputs: Vec<(String, Vec<u8>)> = ARCHIVE_FIXTURES
        .iter()
        .map(|name| (name.to_string(), fixture(name)))
        .collect();
    inputs.extend(
        built_archives()
            .into_iter()
            .map(|(name, data)| (name.to_string(), data)),
    );
    for (name, data) in &inputs {
        let is_zip = name.ends_with("zip");
        for end in 0..sweep_len(data) {
            let prefix = &data[..end];
            let Ok(p) = classify_without_transforms(prefix) else {
                continue;
            };
            // Without its end record a ZIP has no directory.
            assert!(
                !(is_zip && p.format.format == FileFormat::Zip),
                "{name} prefix {end}"
            );
            for member in &p.slices {
                assert!(
                    (member.offset + member.size) as usize <= end,
                    "{name} prefix {end}: {member:?}"
                );
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mut inputs: Vec<Vec<u8>> = ARCHIVE_FIXTURES.iter().map(|name| fixture(name)).collect();
    inputs.push(fixture("initramfs.cpio.gz"));
    inputs.extend(built_archives().into_iter().map(|(_, data)| data));
    for data in &inputs {
        for i in 0..sweep_len(data) {
            for value in [0x00, 0xff, data[i] ^ 0x01] {
                let mut mutated = data.clone();
                mutated[i] = value;
                let _ = classify_without_transforms(&mutated);
            }
        }
    }
}
