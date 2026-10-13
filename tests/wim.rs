//! Windows Imaging Format images: synthetic WIMs built from the documented
//! layout (Microsoft "Windows Imaging File Format (WIM)", wimlib v1.14.5)
//! with stored, XPRESS, LZX, LZMS and solid resources, several images, split
//! parts, integrity tables and encrypted-ESD markers; corrupted headers,
//! resources, digests and directory trees; limits; truncation and mutation
//! sweeps; the committed fixtures (one written by 7-Zip); and real WIMs
//! from the directory `WIM_SAMPLES_DIR` names, when it is set.

#[path = "support/lzms.rs"]
mod lzms;
#[path = "support/wim_image.rs"]
mod wim_image;
#[path = "support/wim_lzx.rs"]
mod wim_lzx;
#[path = "support/xpress.rs"]
mod xpress;

use wim_image::{build, dir, file, Built, Codec, Image, Node, Solid, Spec, Stream};
use zrax::formats::compressed::{self, Codec as Compression};
use zrax::formats::container::{self, Child, Classify, Container, Kind, MAX_COMPONENTS};
use zrax::formats::wim::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// ELF `e_machine` at offset 18, and the value for x86-64.
const E_MACHINE: usize = 18;
const EM_X86_64: u16 = 62;

const README: &[u8] = b"Release notes: nothing to see here.\r\n";
const NOTES: &[u8] = b"These notes carry a named stream.\r\n";

/// The minimal x86-64 PE32+ image of the UEFI fixtures (after the 4-byte
/// section header of `pe32-sections.bin`, 0x1AC bytes).
fn pe() -> Vec<u8> {
    let sections = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/uefi/pe32-sections.bin"
    ))
    .expect("fixture is committed");
    sections[4..0x1B0].to_vec()
}

/// The 256-byte AArch64 ELF of the archive fixtures.
fn elf() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/archives/payload.elf"
    ))
    .expect("fixture is committed")
}

/// The ELF with `e_machine` set to x86-64.
fn elf_x86() -> Vec<u8> {
    let mut elf = elf();
    elf[E_MACHINE..E_MACHINE + 2].copy_from_slice(&EM_X86_64.to_le_bytes());
    elf
}

/// The ELF followed by text with x86 `CALL` instructions (`E8` and a
/// 32-bit relative target) every 211 bytes, `size` bytes in all: more than
/// one 32 KiB chunk, compressible, and changed by E8 translation.
fn big_elf(size: usize) -> Vec<u8> {
    let phrase = b"The quick brown fox jumps over the lazy dog; ";
    let mut data = elf();
    while data.len() < size {
        if data.len() % 211 == 0 {
            data.push(0xe8);
            let target = 0x40 + (data.len() % 50) as i32;
            data.extend_from_slice(&target.to_le_bytes());
        } else {
            data.push(phrase[data.len() % phrase.len()]);
        }
    }
    data.truncate(size);
    data
}

/// A reparse point's data that is itself an ELF, which must not be listed.
fn reparse_data() -> Vec<u8> {
    let mut data = elf();
    data.push(0x52);
    data
}

/// An encrypted file's raw data that starts like a PE, which must not be
/// listed.
fn encrypted_data() -> Vec<u8> {
    let mut data = pe();
    data.push(0x45);
    data
}

/// The image tree of most tests. Walked in pre-order it lists
/// `Windows/System32/driver.efi`, `payload.elf`, `copy.efi` (a hard link
/// to the driver), the named stream `notes.txt:tools.elf` and
/// `unnamed.elf`, whose data is in an unnamed stream entry.
fn tree() -> Vec<Node> {
    vec![
        dir(
            "Windows",
            vec![dir("System32", vec![file("driver.efi", &pe())])],
        ),
        file("payload.elf", &elf()),
        file("readme.txt", README),
        file("copy.efi", &pe()),
        Node::File {
            name: "notes.txt".to_string(),
            data: NOTES.to_vec(),
            streams: vec![Stream {
                name: "tools.elf".to_string(),
                data: elf_x86(),
            }],
            unnamed_entry: false,
        },
        Node::Symlink {
            name: "link".to_string(),
            reparse: reparse_data(),
        },
        Node::Encrypted {
            name: "secret.efi".to_string(),
            data: encrypted_data(),
        },
        file("empty.bin", b""),
        Node::File {
            name: "unnamed.elf".to_string(),
            data: big_elf(40_000),
            streams: Vec::new(),
            unnamed_entry: true,
        },
    ]
}

const LABELS: [&str; 5] = [
    "/1/Windows/System32/driver.efi",
    "/1/payload.elf",
    "/1/copy.efi",
    "/1/notes.txt:tools.elf",
    "/1/unnamed.elf",
];

fn image(name: &str) -> Image {
    Image {
        name: name.to_string(),
        root: tree(),
    }
}

fn stored_spec() -> Spec {
    let mut spec = Spec::new(vec![image("Setup")]);
    spec.security_descriptor = true;
    spec
}

fn compressed_spec(codec: Codec, chunk_size: u32) -> Spec {
    let mut spec = stored_spec();
    spec.compression = Some(codec);
    spec.chunk_size = chunk_size;
    spec
}

fn solid_spec(codec: Option<Codec>, chunk_size: u32) -> Spec {
    let mut spec = stored_spec();
    spec.version = wim_image::VERSION_SOLID;
    spec.solid = Some(Solid { codec, chunk_size });
    spec
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8]) -> Container<'_> {
    let layout = wim::detect(data).expect("detected");
    container::parse(data, Kind::Wim(layout)).expect("parses")
}

fn parse_error(data: &[u8]) -> String {
    wim::parse_container(data, Layout::Image)
        .expect_err("is a parse error")
        .to_string()
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("child {label} in {:?}", labels(c)))
}

fn assert_note(c: &Container<'_>, text: &str) {
    assert!(
        c.notes.iter().any(|n| n.contains(text)),
        "no note {text:?} in {:#?}",
        c.notes
    );
}

fn metadata<'p>(p: &'p DetectionPayload, key: &str) -> &'p zrax::MetadataValue {
    &p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
}

/// Set the 20-byte `old` digest to `new` wherever the lookup table holds
/// it.
fn replace_hash(bytes: &mut [u8], built: &Built, old: [u8; 20], new: [u8; 20]) {
    let table = built.lookup.offset..built.lookup.offset + built.lookup.stored_size;
    let at = bytes[table.clone()]
        .windows(20)
        .position(|w| w == old)
        .expect("the lookup table holds the digest");
    bytes[table.start + at..table.start + at + 20].copy_from_slice(&new);
}

#[test]
fn stored_wims_list_recognized_files_by_path_at_their_stored_offsets() {
    let built = build(&stored_spec());
    assert_eq!(wim::detect(&built.bytes), Some(Layout::Image));
    let c = parse(&built.bytes);
    assert_eq!(c.format, FileFormat::Wim);
    assert_eq!(c.variant, "WIM image");
    assert_eq!(c.target, None, "a WIM names no CPU");
    assert_eq!(c.consumed, built.bytes.len());
    assert_eq!(labels(&c), LABELS);
    let pe = pe();
    let resource = built.resource(&pe);
    let driver = child(&c, LABELS[0]);
    assert_eq!(driver.offset, resource.offset);
    assert_eq!(driver.stored_size, pe.len());
    assert_eq!(driver.transform, None);
    assert_eq!(driver.classify, Classify::IfRecognized);
    assert_eq!(&*driver.data, &pe[..]);
    let copy = child(&c, "/1/copy.efi");
    assert_eq!(
        copy.offset, resource.offset,
        "a hard link names the same resource"
    );
    assert_eq!(&*child(&c, "/1/notes.txt:tools.elf").data, &elf_x86()[..]);
    assert_eq!(&*child(&c, "/1/unnamed.elf").data, &big_elf(40_000)[..]);
    assert_note(&c, "WIM version 1.13; resources not compressed; 1 image");
    assert_note(
        &c,
        "Lookup table: 9 entries: 8 file resources and 1 image metadata resource in this part",
    );
    assert_note(
        &c,
        "Image 1 (`Setup`): 3 directories and 9 files in the directory tree",
    );
    // The empty file has a zero hash and no stream entry, so it has no
    // stream to count.
    assert_note(
        &c,
        "5 of 7 data streams listed; 4 of 6 examined resources are in a recognized format",
    );
    assert_note(&c, "SHA-1 verified for 5 decoded resources");
    assert!(!c
        .notes
        .iter()
        .any(|n| n.starts_with("Data streams left out")));
    assert_note(&c, "1 reparse point's data is not listed");
    assert_note(&c, "1 encrypted file is not decoded");

    let p = classify(&built.bytes);
    assert_eq!(p.format.format, FileFormat::Wim);
    assert_eq!(p.format.variant_name.as_deref(), Some("WIM image"));
    assert_eq!(
        p.primary.isa,
        Isa::X86_64,
        "the first listed file is the PE"
    );
    assert_eq!(p.slices.len(), 5);
    assert_eq!(p.slices[0].label.as_deref(), Some(LABELS[0]));
    assert_eq!(p.slices[0].offset, resource.offset as u64);
    assert_eq!(p.slices[1].isa, Isa::AArch64);
    assert_eq!(p.slices[3].isa, Isa::X86_64);
    assert_eq!(metadata(&p, "wim_image_1_name").to_string(), "Setup");
    assert_eq!(metadata(&p, "wim_compression").to_string(), "none");
    assert_eq!(metadata(&p, "wim_part").to_string(), "1 of 1");
    assert_eq!(metadata(&p, "wim_streams_listed").to_string(), "5");
}

/// Check that every listed child of a compressed WIM decodes to the
/// original bytes: a decoded child names the resource that stores it, and
/// a resource whose chunks did not compress is borrowed where its bytes
/// are. The big ELF compresses.
fn assert_decoded_children(built: &Built, c: &Container<'_>, transform: &str) {
    assert_eq!(labels(c), LABELS);
    for (label, data) in [
        (LABELS[0], pe()),
        (LABELS[1], elf()),
        (LABELS[3], elf_x86()),
        (LABELS[4], big_elf(40_000)),
    ] {
        let child = child(c, label);
        assert_eq!(&*child.data, &data[..], "{label}");
        let resource = built.resource(&data);
        assert!(resource.compressed, "{label} is in a compressed resource");
        if child.transform.is_some() {
            assert_eq!(child.transform, Some(transform), "{label}");
            assert_eq!(child.offset, resource.offset, "{label}");
            assert_eq!(child.stored_size, resource.stored_size, "{label}");
        } else {
            assert_eq!(
                &built.bytes[child.offset..child.offset + data.len()],
                &data[..],
                "{label} is borrowed from its stored chunk"
            );
        }
    }
    assert!(
        child(c, LABELS[4]).transform.is_some(),
        "the big ELF compresses"
    );
}

#[test]
fn xpress_wims_decode_chunked_resources() {
    let built = build(&compressed_spec(Codec::Xpress, 32 << 10));
    let c = parse(&built.bytes);
    assert_decoded_children(&built, &c, "XPRESS");
    assert_note(
        &c,
        "WIM version 1.13; resources compressed with XPRESS in 32 KiB chunks; 1 image",
    );
    assert_note(&c, "SHA-1 verified for 5 decoded resources");
    let p = classify(&built.bytes);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let slice = &p.slices[4];
    assert_eq!(slice.label.as_deref(), Some(LABELS[4]));
    let decoded = slice.decoded.as_ref().expect("a decoded range");
    assert_eq!(decoded.transform, "XPRESS");
    assert_eq!(decoded.size, 40_000);
    assert_eq!(metadata(&p, "wim_chunk_size").to_string(), "32768");
}

#[test]
fn lzx_wims_decode_chunks_and_undo_e8_translation() {
    for chunk_size in [32 << 10, 64 << 10] {
        let built = build(&compressed_spec(Codec::Lzx, chunk_size));
        let c = parse(&built.bytes);
        assert_decoded_children(&built, &c, "LZX");
        assert_note(
            &c,
            &format!(
                "resources compressed with LZX in {} KiB chunks",
                chunk_size >> 10
            ),
        );
    }
}

#[test]
fn wim_lzx_chunks_mix_block_types_and_window_sizes() {
    let data = big_elf(60_000);
    for (bits, block) in [(15u8, 32_768), (15, 5_000), (16, 32_768), (16, 7_777)] {
        let size = data.len().min(1 << bits);
        let chunk = &data[..size];
        for mixed in [false, true] {
            let stream = wim_lzx::compress(chunk, bits, block, mixed);
            let decoded = compressed::decode_limited(
                Compression::LzxWim { window_bits: bits },
                &stream,
                size,
            )
            .unwrap_or_else(|e| panic!("window 2^{bits}, blocks of {block}: {e}"));
            assert_eq!(decoded.data, chunk, "window 2^{bits}, blocks of {block}");
            // The stream ends at a word boundary; the decoder counts the
            // bytes that hold used bits.
            let consumed = decoded.consumed.unwrap();
            assert!(consumed <= stream.len() && consumed + 2 > stream.len());
            for end in [0, 1, stream.len() / 2, stream.len() - 3] {
                assert!(compressed::decode_limited(
                    Compression::LzxWim { window_bits: bits },
                    &stream[..end],
                    size
                )
                .is_err());
            }
        }
    }
}

#[test]
fn xpress_streams_round_trip_through_the_codec() {
    for data in [
        big_elf(65_536),
        pe(),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaab".to_vec(),
    ] {
        let stream = xpress::compress(&data);
        let decoded =
            compressed::decode_limited(Compression::XpressHuffman, &stream, data.len()).unwrap();
        assert_eq!(decoded.data, data);
    }
    assert!(compressed::decode_limited(Compression::XpressHuffman, &[0; 300], 65_537).is_err());
}

#[test]
fn solid_resources_hold_several_blobs() {
    for (codec, transform) in [
        (Some(Codec::Lzx), Some("LZX")),
        (Some(Codec::Xpress), Some("XPRESS")),
    ] {
        let built = build(&solid_spec(codec, 32 << 10));
        let c = parse(&built.bytes);
        assert_eq!(labels(&c), LABELS);
        assert_note(&c, "WIM version 0xE00 (solid resources and LZMS)");
        assert_note(&c, "in 1 solid resource");
        let solid = built.resources[0];
        for (label, data) in [(LABELS[0], pe()), (LABELS[4], big_elf(40_000))] {
            let child = child(&c, label);
            assert_eq!(&*child.data, &data[..], "{label}");
            assert_eq!(child.transform, transform, "{label}");
            assert!(
                child.offset >= solid.offset,
                "{label} starts in the solid resource"
            );
            assert!(child.offset + child.stored_size <= solid.offset + solid.stored_size);
        }
        assert_note(&c, "SHA-1 verified for 5 decoded resources");
    }
    // Stored chunks: the blobs are borrowed at their own offsets.
    let built = build(&solid_spec(None, 32 << 10));
    let c = parse(&built.bytes);
    let pe_child = child(&c, LABELS[0]);
    assert_eq!(pe_child.transform, None);
    assert_eq!(&built.bytes[pe_child.offset..pe_child.offset + 2], b"MZ");
}

#[test]
fn lzms_wims_decode_chunked_and_solid_resources() {
    let mut spec = compressed_spec(Codec::Lzms, 128 << 10);
    spec.version = wim_image::VERSION_SOLID;
    let built = build(&spec);
    let c = parse(&built.bytes);
    assert_decoded_children(&built, &c, "LZMS");
    assert_note(
        &c,
        "WIM version 0xE00 (solid resources and LZMS); resources compressed with LZMS in 128 KiB \
         chunks",
    );
    let built = build(&solid_spec(Some(Codec::Lzms), 64 << 10));
    let c = parse(&built.bytes);
    assert_eq!(labels(&c), LABELS);
    for (label, data) in [(LABELS[0], pe()), (LABELS[4], big_elf(40_000))] {
        let child = child(&c, label);
        assert_eq!(&*child.data, &data[..], "{label}");
        assert_eq!(child.transform, Some("LZMS"), "{label}");
    }
    assert_note(&c, "SHA-1 verified for 5 decoded resources");
    assert_eq!(classify(&built.bytes).primary.isa, Isa::X86_64);
}

/// Items of every kind: literals, explicit and repeated LZ offsets
/// (taken one entry further after an LZ match, whose insertion is still
/// pending), explicit and repeated delta sources, with enough of each to
/// rebuild every adaptive code several times.
fn lzms_items() -> Vec<lzms::Item> {
    use lzms::Item;
    let mut items: Vec<Item> = (1..=8).map(Item::Literal).collect();
    items.push(Item::Delta {
        length: 20,
        power: 0,
        raw_offset: 2,
    });
    for k in 0..3000usize {
        items.push(Item::Literal((k % 61) as u8 + 1));
        match k % 9 {
            0 => items.push(Item::Lz {
                length: 3 + k % 40,
                offset: 1 + (k % 29) as u32,
            }),
            1 | 4 => items.push(Item::LzRep {
                length: 2 + k % 5,
                index: k % 3,
            }),
            2 => items.push(Item::Delta {
                length: 1 + k % 9,
                power: (k % 3) as u32,
                raw_offset: 1 + (k % 5) as u32,
            }),
            3 | 7 => items.push(Item::DeltaRep {
                length: 2 + k % 4,
                index: k % 3,
            }),
            5 => items.push(Item::Lz {
                length: 300 + k,
                offset: 7,
            }),
            _ => {}
        }
    }
    items
}

#[test]
fn lzms_items_of_every_kind_round_trip() {
    // First pass for the size, which sets the number of offset slots.
    let mut sizing = lzms::Encoder::new(1 << 20);
    for item in lzms_items() {
        sizing.item(item);
    }
    let size = sizing.out.len();
    let mut encoder = lzms::Encoder::new(size);
    for item in lzms_items() {
        encoder.item(item);
    }
    let mut expected = encoder.out.clone();
    lzms::x86_filter(&mut expected, true);
    let stream = encoder.finish();
    let decoded = compressed::decode_limited(Compression::Lzms, &stream, size).unwrap();
    assert_eq!(decoded.data.len(), size);
    assert!(decoded.data == expected, "LZMS items decode to their bytes");
    for end in [0, 2, 4, stream.len() / 2] {
        let prefix = compressed::decode_limited(Compression::Lzms, &stream[..end], size);
        assert!(prefix.map_or(true, |d| d.data != expected), "prefix {end}");
    }
    // The greedy compressor, with x86 calls that the filter translates.
    for data in [big_elf(100_000), pe(), b"abababababababababababab".to_vec()] {
        let stream = lzms::compress(&data);
        let decoded = compressed::decode_limited(Compression::Lzms, &stream, data.len()).unwrap();
        assert!(decoded.data == data, "{} B round trip", data.len());
    }
}

#[test]
fn images_share_resources_and_decode_each_once() {
    let mut spec = compressed_spec(Codec::Xpress, 32 << 10);
    spec.images.push(image("Second"));
    spec.boot_index = 2;
    let built = build(&spec);
    let c = parse(&built.bytes);
    assert_eq!(c.children.len(), 10);
    assert_eq!(c.children[5].label, "/2/Windows/System32/driver.efi");
    assert_eq!(c.children[5].offset, c.children[0].offset);
    assert_note(&c, "SHA-1 verified for 6 decoded resources");
    assert_note(
        &c,
        "10 of 14 data streams listed; 4 of 6 examined resources",
    );
    assert_note(&c, "Image 2 is marked bootable");
    assert_note(&c, "Image 2 (`Second`): 3 directories and 9 files");
    let p = classify(&built.bytes);
    assert_eq!(metadata(&p, "wim_image_2_name").to_string(), "Second");
    assert_eq!(metadata(&p, "wim_boot_index").to_string(), "2");
}

/// The second part of a split WIM: a header for part 2 of 2, `blobs` as
/// stored resources, their lookup table and the XML data.
fn part_two(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0u8; wim_image::HEADER_SIZE];
    let mut table = Vec::new();
    for blob in blobs {
        let offset = out.len() as u64;
        out.extend_from_slice(blob);
        table.extend(wim_image::lookup_entry(
            wim_image::reshdr(blob.len() as u64, 0, offset, blob.len() as u64),
            2,
            1,
            wim_image::sha1(blob),
        ));
    }
    let lookup_offset = out.len() as u64;
    out.extend_from_slice(&table);
    let xml = wim_image::xml_data(&Spec::new(vec![image("Setup")]));
    let xml_offset = out.len() as u64;
    out.extend_from_slice(&xml);
    out[..8].copy_from_slice(wim_image::MAGIC);
    out[8..12].copy_from_slice(&208u32.to_le_bytes());
    out[12..16].copy_from_slice(&wim_image::VERSION_DEFAULT.to_le_bytes());
    out[0x28..0x2A].copy_from_slice(&2u16.to_le_bytes());
    out[0x2A..0x2C].copy_from_slice(&2u16.to_le_bytes());
    out[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
    let lookup = wim_image::reshdr(table.len() as u64, 2, lookup_offset, table.len() as u64);
    out[0x30..0x48].copy_from_slice(&lookup);
    let xml_header = wim_image::reshdr(xml.len() as u64, 0, xml_offset, xml.len() as u64);
    out[0x48..0x60].copy_from_slice(&xml_header);
    out
}

#[test]
fn split_parts_are_noted_and_later_parts_list_resources_by_hash() {
    let built = build(&stored_spec());
    let mut first = built.bytes.clone();
    first[wim_image::TOTAL_PARTS_FIELD] = 2;
    // The payload ELF's entry names part 2.
    let hash = wim_image::sha1(&elf());
    let table = built.lookup.offset..built.lookup.offset + built.lookup.stored_size;
    let at = first[table.clone()]
        .windows(20)
        .position(|w| w == hash)
        .unwrap();
    let part_field = table.start + at - 6;
    first[part_field] = 2;
    assert_eq!(wim::detect(&first), Some(Layout::SplitPart));
    let c = parse(&first);
    assert_eq!(c.variant, "split WIM part");
    assert_note(&c, "Part 1 of 2 of a split WIM");
    assert_note(&c, "1 in other parts of the split WIM");
    assert_note(&c, "1 stored in other parts of the split WIM");
    assert!(!labels(&c).contains(&"/1/payload.elf".to_string()));

    let second = part_two(&[elf(), README.to_vec(), pe()]);
    let c = parse(&second);
    assert_note(&c, "Part 2 of 2 of a split WIM");
    assert_note(
        &c,
        "File names are in part 1; the 3 resources of this part are listed by SHA-1",
    );
    assert_eq!(
        labels(&c),
        [
            format!("resource {}", hex(&wim_image::sha1(&elf()))),
            format!("resource {}", hex(&wim_image::sha1(&pe()))),
        ]
    );
    let p = classify(&second);
    assert_eq!(p.format.format, FileFormat::Wim);
    assert_eq!(p.primary.isa, Isa::AArch64);
}

fn hex(hash: &[u8; 20]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn integrity_tables_are_verified() {
    let mut spec = stored_spec();
    spec.integrity_chunk = Some(256);
    let built = build(&spec);
    let c = parse(&built.bytes);
    let checked = built.lookup.offset + built.lookup.stored_size - 208;
    let entries = checked / 256 + usize::from(checked % 256 != 0);
    assert_note(
        &c,
        &format!(
            "Integrity table verified: {entries} SHA-1s of 256 B chunks from 0xD0 to the end of \
             the lookup table"
        ),
    );
    let mut damaged = built.bytes.clone();
    let readme = built.resource(README);
    damaged[readme.offset] ^= 1;
    let c = parse(&damaged);
    let chunk = (readme.offset - 208) / 256;
    assert_note(
        &c,
        &format!(
            "Integrity table mismatch: chunk {chunk} at 0x{:X} does not match its SHA-1",
            208 + chunk * 256
        ),
    );
    assert_eq!(c.children.len(), 5, "the readme is not listed either way");
}

#[test]
fn encrypted_esds_are_opaque() {
    let mut spec = compressed_spec(Codec::Lzx, 32 << 10);
    spec.xml_extra = "<ESD><ENCRYPTED>1</ENCRYPTED></ESD>".to_string();
    let built = build(&spec);
    let c = parse(&built.bytes);
    assert!(c.opaque);
    assert!(c.children.is_empty());
    assert_note(&c, "The XML data marks an encrypted ESD");
    let p = classify(&built.bytes);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

/// `bytes` with the 32-bit field at `at` set to `value`.
fn with_u32(bytes: &[u8], at: usize, value: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    out
}

#[test]
fn header_errors_are_parse_errors() {
    let built = build(&stored_spec());
    let bytes = &built.bytes;
    assert_eq!(wim::detect(&with_u32(bytes, 8, 0x60)), None);
    assert!(
        parse_error(&with_u32(bytes, wim_image::VERSION_FIELD, 0x10b00))
            .contains("Unsupported WIM version 0x00010B00")
    );
    let mut part = bytes.clone();
    part[wim_image::PART_NUMBER_FIELD] = 3;
    part[wim_image::TOTAL_PARTS_FIELD] = 2;
    assert!(parse_error(&part).contains("Invalid WIM part number 3 of 2"));
    part[wim_image::PART_NUMBER_FIELD] = 0;
    assert!(parse_error(&part).contains("Invalid WIM part number 0 of 2"));
    assert!(parse_error(&with_u32(bytes, wim_image::FLAGS_FIELD, 0x2))
        .contains("compression without a format"));
    let xpress = with_u32(bytes, wim_image::FLAGS_FIELD, 0x0002_0002);
    assert!(
        parse_error(&with_u32(&xpress, wim_image::CHUNK_SIZE_FIELD, 128 << 10))
            .contains("Unsupported WIM XPRESS chunk size 131072 B")
    );
    assert!(
        parse_error(&with_u32(&xpress, wim_image::CHUNK_SIZE_FIELD, 40_000))
            .contains("Unsupported WIM XPRESS chunk size 40000 B")
    );
    assert!(parse_error(&bytes[..207]).contains("Truncated WIM header at 0x0 + 208 B"));
    let lookup_size = wim_image::LOOKUP_FIELD;
    let mut beyond = bytes.clone();
    beyond[lookup_size..lookup_size + 7].copy_from_slice(&[0xff, 0xff, 0, 0, 0, 0, 0]);
    beyond[lookup_size + 16..lookup_size + 24].copy_from_slice(&0xffffu64.to_le_bytes());
    assert!(parse_error(&beyond).contains("Invalid WIM lookup table"));
}

#[test]
fn damaged_files_and_metadata_are_noted() {
    let built = build(&compressed_spec(Codec::Xpress, 32 << 10));
    // A digest that does not match the PE.
    let mut wrong = built.bytes.clone();
    let pe_hash = wim_image::sha1(&pe());
    replace_hash(&mut wrong, &built, pe_hash, [0x11; 20]);
    let c = parse(&wrong);
    assert!(!labels(&c).contains(&LABELS[0].to_string()));
    assert_note(&c, "2 not in the lookup table");
    // A damaged chunk of the big ELF.
    let mut damaged = built.bytes.clone();
    let big = built.resource(&big_elf(40_000));
    damaged[big.offset + 8] ^= 0xff;
    let c = parse(&damaged);
    assert!(!labels(&c).contains(&LABELS[4].to_string()));
    assert_note(&c, "`/1/unnamed.elf`: ");
    assert_note(&c, "1 not decoded or failed their SHA-1");
    // A digest mismatch of the metadata resource.
    let mut metadata = build(&stored_spec());
    let resource = metadata.metadata[0];
    metadata.bytes[resource.offset + 40] ^= 1;
    let c = parse(&metadata.bytes);
    assert!(c.children.is_empty());
    assert_note(
        &c,
        "Image 1 (`Setup`): metadata resource does not match its SHA-1; its files are not listed",
    );
}

#[test]
fn directory_loops_stop_the_walk() {
    let mut built = build(&stored_spec());
    let resource = built.metadata[0];
    // Security data of 40 B, the root entry of 104 B and its 8-byte end,
    // then the root's list at 152, whose first entry is `Windows`: point
    // its entry list back at the root's list.
    let root_list = 40 + 104 + 8;
    let windows = resource.offset + root_list;
    let subdir = windows + 0x10;
    built.bytes[subdir..subdir + 8].copy_from_slice(&(root_list as u64).to_le_bytes());
    let new = wim_image::sha1(&built.bytes[resource.offset..resource.offset + resource.size]);
    let old = resource.hash;
    let mut bytes = built.bytes.clone();
    replace_hash(&mut bytes, &built, old, new);
    let c = parse(&bytes);
    assert_note(&c, "the walk stopped early");
    assert!(c.children.len() <= MAX_COMPONENTS);
}

#[test]
fn listing_stops_at_the_component_limit() {
    let elf = elf();
    let files: Vec<Node> = (0..MAX_COMPONENTS + 10)
        .map(|i| file(&format!("f{i}.elf"), &elf))
        .collect();
    let built = build(&Spec::new(vec![Image {
        name: "Many".to_string(),
        root: files,
    }]));
    let c = parse(&built.bytes);
    assert_eq!(c.children.len(), MAX_COMPONENTS);
    assert_note(&c, "10 not examined: 4096 children were listed");
    assert_note(&c, "SHA-1 verified for 2 decoded resources");
}

#[test]
fn xml_names_and_architectures_become_metadata() {
    let mut spec = stored_spec();
    spec.images[0].name = "Windows 11 Pro".to_string();
    spec.xml_extra = String::new();
    let mut built = build(&spec);
    // Rewrite the XML with an architecture element, keeping its size.
    let xml = wim_image::utf16("<WINDOWS><ARCH>9</ARCH></WINDOWS>");
    let start = built.xml.offset + built.xml.stored_size - wim_image::utf16("</WIM>").len();
    let mut bytes = built.bytes[..start].to_vec();
    let image_end = wim_image::utf16("</IMAGE>");
    let close = bytes[built.xml.offset..]
        .windows(image_end.len())
        .position(|w| w == image_end)
        .unwrap()
        + built.xml.offset;
    bytes.splice(close..close, xml.iter().copied());
    bytes.extend_from_slice(&wim_image::utf16("</WIM>"));
    let size = (bytes.len() - built.xml.offset) as u64;
    bytes[wim_image::XML_FIELD..wim_image::XML_FIELD + 24].copy_from_slice(&wim_image::reshdr(
        size,
        0,
        built.xml.offset as u64,
        size,
    ));
    built.bytes = bytes;
    let p = classify(&built.bytes);
    assert_eq!(
        metadata(&p, "wim_image_1_name").to_string(),
        "Windows 11 Pro"
    );
    assert_eq!(metadata(&p, "wim_image_1_arch").to_string(), "9 (x64)");
    assert_eq!(p.primary.isa, Isa::X86_64, "from the PE, not from the XML");
    let c = parse(&built.bytes);
    assert_eq!(c.target, None);
}

/// Fixtures for the sweeps: stored, XPRESS, LZX and solid LZX WIMs with a
/// small image.
fn sweep_fixtures() -> Vec<Built> {
    let small = || Image {
        name: "Small".to_string(),
        root: vec![
            dir("bin", vec![file("tool.elf", &elf())]),
            file("driver.efi", &pe()),
            file("big.elf", &big_elf(33_000)),
        ],
    };
    let mut stored = Spec::new(vec![small()]);
    stored.integrity_chunk = Some(1024);
    let mut xpress = Spec::new(vec![small()]);
    xpress.compression = Some(Codec::Xpress);
    xpress.chunk_size = 32 << 10;
    let mut lzx = Spec::new(vec![small()]);
    lzx.compression = Some(Codec::Lzx);
    lzx.chunk_size = 32 << 10;
    let mut solid = Spec::new(vec![small()]);
    solid.version = wim_image::VERSION_SOLID;
    solid.solid = Some(Solid {
        codec: Some(Codec::Lzx),
        chunk_size: 32 << 10,
    });
    let mut lzms = Spec::new(vec![small()]);
    lzms.version = wim_image::VERSION_SOLID;
    lzms.solid = Some(Solid {
        codec: Some(Codec::Lzms),
        chunk_size: 64 << 10,
    });
    [stored, xpress, lzx, solid, lzms]
        .iter()
        .map(build)
        .collect()
}

#[test]
fn every_prefix_before_the_lookup_table_end_is_an_error() {
    for built in sweep_fixtures() {
        let image = &built.bytes;
        assert_eq!(parse(image).children.len(), 3);
        let lookup_end = built.lookup.offset + built.lookup.stored_size;
        for end in 0..image.len() {
            let prefix = &image[..end];
            if end < 12 {
                assert_eq!(wim::detect(prefix), None, "prefix of {end} B");
                continue;
            }
            assert!(wim::detect(prefix).is_some(), "prefix of {end} B");
            match wim::parse_container(prefix, Layout::Image) {
                Err(_) => {}
                Ok(c) => {
                    assert!(end >= lookup_end, "prefix of {end} B parses");
                    // Whatever is listed was decoded whole and verified.
                    for listed in &c.children {
                        assert!(container::is_recognized(&listed.data));
                    }
                }
            }
            if end < lookup_end && end % 13 == 0 {
                assert!(detect_payload(prefix, &ClassifierOptions::new()).is_err());
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for built in sweep_fixtures() {
        let image = &built.bytes;
        for i in 0..image.len() {
            // The big file's middle chunks repeat what the sweep already
            // covers; every byte of the structures is mutated.
            if i % 3 != 0
                && built
                    .resources
                    .iter()
                    .any(|r| i > r.offset + 64 && i < r.offset + r.stored_size)
            {
                continue;
            }
            for value in [0x00, 0xff, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = wim::parse_container(&mutated, Layout::Image);
                if i % 31 == 0 {
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
}

/// The committed fixtures: `7zip-stored.wim`, written by 7-Zip 26.03, and
/// the synthetic `xpress.wim`, `lzx.wim`, `solid-lzx.wim` and
/// `solid-lzms.wim` (see `tests/fixtures/wim/README.md`).
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/wim/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture is committed")
}

/// The synthetic fixtures' builds, which `generate.sh` writes.
fn committed_specs() -> Vec<(&'static str, Spec)> {
    let small = || Image {
        name: "Fixture".to_string(),
        root: vec![
            dir(
                "Windows",
                vec![dir("System32", vec![file("driver.efi", &pe())])],
            ),
            file("payload.elf", &elf()),
            file("readme.txt", README),
            file("tools.elf", &big_elf(20_000)),
            file("table.bin", &counters(2_000)),
        ],
    };
    let mut xpress = Spec::new(vec![small()]);
    xpress.compression = Some(Codec::Xpress);
    xpress.chunk_size = 32 << 10;
    let mut lzx = Spec::new(vec![small()]);
    lzx.compression = Some(Codec::Lzx);
    lzx.chunk_size = 32 << 10;
    let mut solid = Spec::new(vec![small()]);
    solid.version = wim_image::VERSION_SOLID;
    solid.solid = Some(Solid {
        codec: Some(Codec::Lzx),
        chunk_size: 32 << 10,
    });
    let mut lzms = Spec::new(vec![small()]);
    lzms.version = wim_image::VERSION_SOLID;
    lzms.solid = Some(Solid {
        codec: Some(Codec::Lzms),
        chunk_size: 64 << 10,
    });
    vec![
        ("xpress.wim", xpress),
        ("lzx.wim", lzx),
        ("solid-lzx.wim", solid),
        ("solid-lzms.wim", lzms),
    ]
}

/// A table of `count` 16-bit counters stepping by 3, which LZMS delta
/// matches code.
fn counters(count: u16) -> Vec<u8> {
    (0..count).flat_map(|i| (i * 3).to_le_bytes()).collect()
}

#[test]
fn committed_synthetic_fixtures_match_the_builder() {
    if let Ok(dir) = std::env::var("WIM_WRITE_FIXTURES") {
        for (name, spec) in committed_specs() {
            std::fs::write(format!("{dir}/{name}"), build(&spec).bytes).unwrap();
        }
    }
    for (name, spec) in committed_specs() {
        let bytes = fixture(name);
        assert_eq!(bytes, build(&spec).bytes, "{name} matches the builder");
        let c = parse(&bytes);
        assert_eq!(
            labels(&c),
            [
                "/1/Windows/System32/driver.efi",
                "/1/payload.elf",
                "/1/tools.elf"
            ],
            "{name}"
        );
        assert!(
            child(&c, "/1/tools.elf").transform.is_some(),
            "{name}: the big file is decoded"
        );
        assert_eq!(&*child(&c, "/1/tools.elf").data, &big_elf(20_000)[..]);
        assert_eq!(classify(&bytes).primary.isa, Isa::X86_64, "{name}");
    }
}

#[test]
fn the_seven_zip_fixture_lists_its_files() {
    let bytes = fixture("7zip-stored.wim");
    let c = parse(&bytes);
    assert_eq!(c.format, FileFormat::Wim);
    // 7-Zip orders a directory's entries by name without case.
    assert_eq!(
        labels(&c),
        ["/1/payload.elf", "/1/Windows/System32/driver.efi"]
    );
    assert_eq!(
        &*child(&c, "/1/Windows/System32/driver.efi").data,
        &pe()[..]
    );
    assert_note(&c, "WIM version 1.13; resources not compressed; 1 image");
    assert_note(
        &c,
        "Image 1 (`1`): 3 directories and 3 files in the directory tree",
    );
    assert_note(&c, "SHA-1 verified for 3 decoded resources");
    let p = classify(&bytes);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices[1].isa, Isa::X86_64);
    assert_eq!(metadata(&p, "wim_image_1_name").to_string(), "1");
}

#[test]
fn real_wims_from_wim_samples_dir() {
    let Ok(dir) = std::env::var("WIM_SAMPLES_DIR") else {
        eprintln!("WIM_SAMPLES_DIR is not set; skipped");
        return;
    };
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("WIM_SAMPLES_DIR is a directory") {
        let path = entry.unwrap().path();
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if wim::detect(&data).is_none() {
            continue;
        }
        seen += 1;
        let c = parse(&data);
        assert!(
            !c.notes
                .iter()
                .any(|n| n.contains("does not match") || n.contains("not read")),
            "{}: {:#?}",
            path.display(),
            c.notes
        );
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::Wim, "{}", path.display());
        eprintln!(
            "{}: {} children, primary {}; {:?}",
            path.display(),
            c.children.len(),
            p.primary.isa,
            c.notes
        );
    }
    assert!(seen > 0, "no WIMs in {dir}");
}
