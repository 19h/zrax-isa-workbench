//! Java runtime images: jimage fixtures written by the JDK's own jimage
//! writer (stored, big-endian, zip and compact-cp), a `jmod` fixture,
//! synthetic images built from the `imageFile.hpp` layout for both byte
//! orders, perfect-hash seeds, stacked and failing compressed resources and
//! the listing limit, index damage, and truncation and mutation sweeps.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use zrax::formats::container::{self, Child, Container, Kind};
use zrax::formats::javaimage::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(data: &[u8], layout: Layout) -> Container<'_> {
    container::parse(data, Kind::JavaImage(layout)).expect("parses")
}

fn parse_error(data: &[u8], layout: Layout) -> String {
    container::parse(data, Kind::JavaImage(layout))
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
        .unwrap_or_else(|| panic!("resource {label} in {:?}", labels(c)))
}

fn notes(c: &Container<'_>) -> String {
    c.notes.join("\n")
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|n| n.contains(text))
}

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// The JDK-written fixtures (tests/fixtures/javaimage/README.md)
// ---------------------------------------------------------------------------

/// The jimage fixtures, their layout and the transform of their decoded
/// class files (`None` when stored).
const IMAGES: [(&str, Layout, Option<&str>); 4] = [
    (
        "javaimage/sample-le.jimage",
        Layout::JimageLittleEndian,
        None,
    ),
    ("javaimage/sample-be.jimage", Layout::JimageBigEndian, None),
    (
        "javaimage/sample-zip.jimage",
        Layout::JimageLittleEndian,
        Some("jimage zip"),
    ),
    (
        "javaimage/sample-compact-cp.jimage",
        Layout::JimageLittleEndian,
        Some("jimage compact-cp"),
    ),
];

/// The recognized resources of every fixture, in file order: jlink stores
/// the classes first and `module-info.class` last.
const RESOURCES: [&str; 3] = [
    "/zrax.sample/zrax/sample/Hello.class",
    "/zrax.sample/zrax/sample/payload.elf",
    "/zrax.sample/module-info.class",
];

/// SHA-256 of the resources as the JDK's reader returns them (`DumpImage`
/// in the fixture directory), the same for every fixture.
const HELLO_SHA256: &str = "121b756f9b3a1134441a6c164b129e0bb507ac9f97af6840092e9ef4fcaf2393";
const MODULE_INFO_SHA256: &str = "cb9a24c6f73207c62e7ab8c18cae502301cc8075593d6b1da9be01f6837e5153";

/// Size of the root directory listing jlink writes after the resources:
/// the location offsets of `/modules` and `/packages`.
const ROOT_LISTING: usize = 8;

#[test]
fn jdk_fixtures_list_their_class_files_and_the_elf_resource() {
    for (name, layout, transform) in IMAGES {
        let image = fixture(name);
        let detected = detect_format(&image);
        assert!(
            matches!(detected, DetectedFormat::Container { kind: Kind::JavaImage(found) } if found == layout),
            "{name}: {detected:?}"
        );
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Jimage, "{name}");
        assert_eq!(
            p.format.variant_name.as_deref(),
            Some(layout.label()),
            "{name}"
        );
        assert_eq!(p.primary.isa, Isa::Jvm, "{name}");
        let slices: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
        assert_eq!(slices, RESOURCES, "{name}");
        let isas: Vec<Isa> = p.slices.iter().map(|s| s.isa).collect();
        assert_eq!(isas, [Isa::Jvm, Isa::X86_64, Isa::Jvm], "{name}");
        let hello = &p.slices[0];
        assert_eq!(
            hello.decoded.as_ref().map(|d| d.transform.as_str()),
            transform,
            "{name}"
        );
        if let Some(decoded) = &hello.decoded {
            assert_eq!(decoded.size, 995, "{name}");
        } else {
            assert_eq!(hello.size, 995, "{name}");
            // The stored offset holds the class file.
            let at = usize::try_from(hello.offset).unwrap();
            assert_eq!(image[at..at + 4], [0xca, 0xfe, 0xba, 0xbe], "{name}");
        }
    }
}

#[test]
fn decoded_resources_match_the_bytes_the_jdk_reader_returns() {
    let plain = fixture("javaimage/sample-le.jimage");
    let reference = parse(&plain, Layout::JimageLittleEndian);
    assert_eq!(sha256(&child(&reference, RESOURCES[0]).data), HELLO_SHA256);
    assert_eq!(
        sha256(&child(&reference, RESOURCES[2]).data),
        MODULE_INFO_SHA256
    );
    for (name, layout, transform) in IMAGES {
        let image = fixture(name);
        let c = parse(&image, layout);
        assert_eq!(labels(&c), RESOURCES, "{name}");
        for resource in RESOURCES {
            let decoded = child(&c, resource);
            assert_eq!(
                decoded.data,
                child(&reference, resource).data,
                "{name}: {resource}"
            );
        }
        let hello = child(&c, RESOURCES[0]);
        assert_eq!(hello.transform, transform, "{name}");
        // Stored coordinates stay in the file: the compressed resource
        // starts with its layer header.
        let stored = &image[hello.offset..hello.offset + hello.stored_size];
        if transform.is_some() {
            assert_eq!(stored[..4], 0xcafe_fafau32.to_le_bytes(), "{name}");
            assert!(hello.stored_size < 995, "{name}");
        } else {
            assert_eq!(stored, &hello.data[..], "{name}");
        }
    }
}

#[test]
fn notes_and_metadata_describe_the_index() {
    let image = fixture("javaimage/sample-le.jimage");
    let c = parse(&image, Layout::JimageLittleEndian);
    let text = notes(&c);
    assert!(
        has_note(
            &c,
            "jimage 1.0 with a little-endian index: 11 resources in 11 table slots; resources start at 0x18A"
        ),
        "{text}"
    );
    assert!(
        has_note(
            &c,
            "Perfect-hash index verified: all 11 locations are found through the redirect table"
        ),
        "{text}"
    );
    assert!(
        has_note(
            &c,
            "7 directory entries under /modules and /packages are index data and not examined"
        ),
        "{text}"
    );
    assert!(
        has_note(&c, "8 B at 0x76C list the root directory"),
        "{text}"
    );
    assert!(has_note(&c, "1 module: zrax.sample"), "{text}");
    assert!(
        has_note(&c, "3 of 4 resources are in a recognized format and listed"),
        "{text}"
    );
    assert_eq!(c.consumed, image.len());

    let p = classify(&image);
    let metadata = |key: &str| {
        p.metadata
            .iter()
            .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
            .map(|m| m.value.to_string())
            .unwrap_or_else(|| panic!("metadata {key}"))
    };
    assert_eq!(metadata("jimage_version"), "1.0");
    assert_eq!(metadata("jimage_resource_count"), "11");
    assert_eq!(metadata("jimage_table_length"), "11");
    assert_eq!(metadata("jimage_index_size"), "394");
    assert_eq!(metadata("jimage_resources"), "4");
    assert_eq!(metadata("jimage_directory_entries"), "7");
    assert_eq!(metadata("jimage_compressed_resources"), "0");
    assert_eq!(metadata("jimage_modules"), "1");
    assert_eq!(metadata("jimage_image_size"), image.len().to_string());

    let zip_image = fixture("javaimage/sample-zip.jimage");
    let zip = parse(&zip_image, Layout::JimageLittleEndian);
    assert!(
        has_note(
            &zip,
            "4 of 4 resources are compressed; 4 were decoded: 4 with zip (zlib)"
        ),
        "{}",
        notes(&zip)
    );
    let compact_image = fixture("javaimage/sample-compact-cp.jimage");
    let compact = parse(&compact_image, Layout::JimageLittleEndian);
    assert!(
        has_note(
            &compact,
            "2 of 4 resources are compressed; 2 were decoded: 2 with compact-cp"
        ),
        "{}",
        notes(&compact)
    );
}

#[test]
fn jdk_redirect_tables_use_seeds_and_direct_slots() {
    // The fixture's redirect table, read with the documented layout: both
    // kinds of entry occur, so both lookup paths were exercised above.
    let image = fixture("javaimage/sample-le.jimage");
    let table_length = le_u32(&image, 16) as usize;
    let redirect: Vec<i32> = (0..table_length)
        .map(|i| le_u32(&image, 28 + 4 * i) as i32)
        .collect();
    assert!(redirect.iter().any(|r| *r > 0), "{redirect:?}");
    assert!(redirect.iter().any(|r| *r < 0), "{redirect:?}");
}

#[test]
fn jmod_fixture_is_a_zip_archive_child_at_offset_4() {
    let jmod = fixture("javaimage/sample.jmod");
    assert!(matches!(
        detect_format(&jmod),
        DetectedFormat::Container {
            kind: Kind::JavaImage(Layout::Jmod)
        }
    ));
    let p = classify(&jmod);
    assert_eq!(p.format.format, FileFormat::Jmod);
    assert_eq!(p.format.variant_name.as_deref(), Some("JMOD"));
    assert_eq!(p.primary.isa, Isa::Jvm);
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].label.as_deref(), Some("ZIP archive"));
    assert_eq!(p.slices[0].offset, 4);
    assert_eq!(p.slices[0].size, jmod.len() as u64 - 4);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("JMOD 1.0; the ZIP archive at 0x4")));

    // The archive from offset 4 is a complete ZIP whose offsets count from
    // there, as `JmodOutputStream` writes it.
    let archive = classify(&jmod[4..]);
    assert_eq!(archive.format.format, FileFormat::Zip);
    let members: HashMap<&str, Isa> = archive
        .slices
        .iter()
        .filter_map(|s| s.label.as_deref().map(|label| (label, s.isa)))
        .collect();
    assert_eq!(
        members.get("classes/zrax/sample/Hello.class"),
        Some(&Isa::Jvm)
    );
    assert_eq!(members.get("classes/module-info.class"), Some(&Isa::Jvm));
    assert_eq!(members.get("lib/payload.elf"), Some(&Isa::X86_64));
}

#[test]
fn jmod_headers_are_checked_like_jmodfile_checks_them() {
    let jmod = fixture("javaimage/sample.jmod");
    let mut newer = jmod.clone();
    newer[3] = 1;
    assert!(!matches!(
        detect_format(&newer),
        DetectedFormat::Container {
            kind: Kind::JavaImage(_)
        }
    ));
    assert!(parse_error(&newer, Layout::Jmod).contains("Unsupported JMOD version 1.1"));
    newer[2] = 2;
    newer[3] = 0;
    assert!(parse_error(&newer, Layout::Jmod).contains("Unsupported JMOD version 2.0"));
    let mut no_zip = jmod.clone();
    no_zip[4] = b'X';
    assert!(parse_error(&no_zip, Layout::Jmod).contains("Missing ZIP local file header at 0x4"));
    assert!(parse_error(&jmod[..3], Layout::Jmod).contains("Truncated JMOD header"));
    // A damaged archive is still a JMOD, with an unknown ISA.
    let mut damaged = jmod.clone();
    let last = damaged.len() - 1;
    damaged.truncate(last - 10);
    let p = classify(&damaged);
    assert_eq!(p.format.format, FileFormat::Jmod);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

// ---------------------------------------------------------------------------
// Synthetic images built from the documented layout
// ---------------------------------------------------------------------------

/// The perfect-hash multiplier and default seed (`HASH_MULTIPLIER`).
const HASH_MULTIPLIER: u32 = 0x0100_0193;

/// `h = seed; h = h * 0x01000193 ^ byte` over the name, masked positive
/// (`ImageStrings::hash_code`).
fn hash(name: &[u8], seed: u32) -> u32 {
    name.iter()
        .fold(seed, |h, &b| h.wrapping_mul(HASH_MULTIPLIER) ^ u32::from(b))
        & 0x7fff_ffff
}

/// Location attribute kinds (`ImageLocation`).
const ATTRIBUTE_MODULE: u8 = 1;
const ATTRIBUTE_PARENT: u8 = 2;
const ATTRIBUTE_BASE: u8 = 3;
const ATTRIBUTE_EXTENSION: u8 = 4;
const ATTRIBUTE_OFFSET: u8 = 5;
const ATTRIBUTE_COMPRESSED: u8 = 6;
const ATTRIBUTE_UNCOMPRESSED: u8 = 7;

/// The compressed-resource layer magic (`CompressedResourceHeader.MAGIC`).
const LAYER_MAGIC: u32 = 0xcafe_fafa;

/// One location of a synthetic image.
struct Entry {
    /// String offsets of the name parts; 0 for an absent part.
    module: u32,
    parent: u32,
    base: u32,
    extension: u32,
    /// The full name the parts spell.
    name: Vec<u8>,
    /// Bytes stored in the content region.
    stored: Vec<u8>,
    /// `COMPRESSED` attribute: the stored size, or 0 when stored as is.
    compressed_size: u64,
    /// `UNCOMPRESSED` attribute.
    uncompressed_size: u64,
}

/// A synthetic jimage: string table, locations and content, written the
/// way `BasicImageWriter` lays them out.
struct ImageBuilder {
    /// NUL-terminated strings; offset 0 is the empty string, offset 1
    /// `class` (`ImageStringsWriter`).
    strings: Vec<u8>,
    string_offsets: HashMap<Vec<u8>, u32>,
    entries: Vec<Entry>,
}

impl ImageBuilder {
    fn new() -> Self {
        let mut builder = Self {
            strings: Vec::new(),
            string_offsets: HashMap::new(),
            entries: Vec::new(),
        };
        builder.string(b"");
        builder.string(b"class");
        builder
    }

    /// The offset of `text` in the string table, added when new.
    fn string(&mut self, text: &[u8]) -> u32 {
        if let Some(&offset) = self.string_offsets.get(text) {
            return offset;
        }
        let offset = u32::try_from(self.strings.len()).unwrap();
        self.strings.extend_from_slice(text);
        self.strings.push(0);
        self.string_offsets.insert(text.to_vec(), offset);
        offset
    }

    /// Split a `/module/parent/base.extension` path as
    /// `ImageLocationWriter.newLocation` does. It splits off the parent only
    /// when the last `/` is past index 1, so a one-character package stays
    /// in the base (`p/A`); the full name is the same either way.
    fn add(&mut self, path: &str, stored: Vec<u8>, compressed_size: u64, uncompressed_size: u64) {
        let rest = path.strip_prefix('/').expect("absolute path");
        let (module, rest) = rest.split_once('/').expect("module and resource");
        let (parent, file) = match rest.rfind('/') {
            Some(at) if at > 1 => (&rest[..at], &rest[at + 1..]),
            _ => ("", rest),
        };
        let (base, extension) = file.rsplit_once('.').unwrap_or((file, ""));
        let part = |builder: &mut Self, text: &str| {
            if text.is_empty() {
                0
            } else {
                builder.string(text.as_bytes())
            }
        };
        let entry = Entry {
            module: part(self, module),
            parent: part(self, parent),
            base: self.string(base.as_bytes()),
            extension: part(self, extension),
            name: path.as_bytes().to_vec(),
            stored,
            compressed_size,
            uncompressed_size,
        };
        self.entries.push(entry);
    }

    /// A resource stored as is.
    fn stored(&mut self, path: &str, contents: &[u8]) {
        self.add(path, contents.to_vec(), 0, contents.len() as u64);
    }

    /// The image, with every word in the byte order `le` selects.
    fn build(&self, le: bool) -> Vec<u8> {
        let word = |value: u32| {
            if le {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        };
        // Attribute streams; offset 0 holds an END byte, reserved for
        // empty slots.
        let mut locations = vec![0u8];
        let mut location_offsets = Vec::new();
        let mut content = Vec::new();
        for entry in &self.entries {
            location_offsets.push(u32::try_from(locations.len()).unwrap());
            let attributes = [
                (ATTRIBUTE_MODULE, u64::from(entry.module)),
                (ATTRIBUTE_PARENT, u64::from(entry.parent)),
                (ATTRIBUTE_BASE, u64::from(entry.base)),
                (ATTRIBUTE_EXTENSION, u64::from(entry.extension)),
                (ATTRIBUTE_OFFSET, content.len() as u64),
                (ATTRIBUTE_COMPRESSED, entry.compressed_size),
                (ATTRIBUTE_UNCOMPRESSED, entry.uncompressed_size),
            ];
            for (kind, value) in attributes {
                locations.extend_from_slice(&attribute(kind, value));
            }
            locations.push(0);
            content.extend_from_slice(&entry.stored);
        }
        let names: Vec<&[u8]> = self.entries.iter().map(|e| e.name.as_slice()).collect();
        let tables = perfect_hash(&names);
        let mut image = Vec::new();
        image.extend_from_slice(&word(0xcafe_dada));
        image.extend_from_slice(&word(1 << 16));
        image.extend_from_slice(&word(0)); // flags
        image.extend_from_slice(&word(u32::try_from(self.entries.len()).unwrap()));
        image.extend_from_slice(&word(u32::try_from(tables.redirect.len()).unwrap()));
        image.extend_from_slice(&word(u32::try_from(locations.len()).unwrap()));
        image.extend_from_slice(&word(u32::try_from(self.strings.len()).unwrap()));
        for value in &tables.redirect {
            image.extend_from_slice(&word(*value as u32));
        }
        for slot in &tables.order {
            image.extend_from_slice(&word(slot.map_or(0, |entry| location_offsets[entry])));
        }
        image.extend_from_slice(&locations);
        image.extend_from_slice(&self.strings);
        image.extend_from_slice(&content);
        image
    }
}

/// One attribute: header byte `kind << 3 | (length - 1)` and the value in
/// as few bytes as hold it, most significant first
/// (`ImageLocation.compress`); nothing for a zero value.
fn attribute(kind: u8, value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let n = (63 - value.leading_zeros()) / 8;
    let mut bytes = vec![(kind << 3) | u8::try_from(n).unwrap()];
    for i in (0..=n).rev() {
        bytes.push((value >> (i * 8)) as u8);
    }
    bytes
}

/// The perfect-hash tables of a synthetic image.
struct HashTables {
    /// Redirect table: a seed, `-1 - slot`, or 0 for an empty bucket.
    redirect: Vec<i32>,
    /// The entry in each slot of the offsets table.
    order: Vec<Option<usize>>,
}

/// Seeds `PerfectHashBuilder` tries for one collision bucket before it
/// grows the table (`RETRY_LIMIT`).
const RETRY_LIMIT: u32 = 1000;

/// The tables for `names`, built the way `PerfectHashBuilder.generate`
/// does: buckets by the default hash, the largest bucket first, each
/// collision bucket given the first seed above the multiplier that sends
/// its names to free slots, single names given free slots directly; the
/// table grows to `(n + 1) | 1` when packing fails.
fn perfect_hash(names: &[&[u8]]) -> HashTables {
    let mut count = names.len();
    loop {
        if let Some(tables) = pack(names, count) {
            return tables;
        }
        count = (count + 1) | 1;
    }
}

/// The slot `name` hashes to with `seed` in a table of `count` slots.
fn slot(name: &[u8], seed: u32, count: usize) -> usize {
    hash(name, seed) as usize % count
}

/// Pack `names` into `count` slots, or `None` when they do not fit.
fn pack(names: &[&[u8]], count: usize) -> Option<HashTables> {
    let mut tables = HashTables {
        redirect: vec![0; count],
        order: vec![None; count],
    };
    if count == 0 {
        return Some(tables);
    }
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (entry, name) in names.iter().enumerate() {
        buckets[slot(name, HASH_MULTIPLIER, count)].push(entry);
    }
    let mut sorted: Vec<usize> = (0..count).filter(|b| !buckets[*b].is_empty()).collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(buckets[*b].len()));
    let mut free = 0;
    for bucket in sorted {
        let entries = &buckets[bucket];
        if entries.len() > 1 {
            let seed = collision_seed(names, entries, &tables.order)?;
            for &entry in entries {
                tables.order[slot(names[entry], seed, count)] = Some(entry);
            }
            tables.redirect[bucket] = i32::try_from(seed).unwrap();
        } else {
            while free < count && tables.order[free].is_some() {
                free += 1;
            }
            if free >= count {
                return None;
            }
            tables.order[free] = Some(entries[0]);
            tables.redirect[bucket] = -1 - i32::try_from(free).unwrap();
        }
    }
    Some(tables)
}

/// The first seed above the multiplier that sends every entry of a
/// collision bucket to its own free slot.
fn collision_seed(names: &[&[u8]], entries: &[usize], order: &[Option<usize>]) -> Option<u32> {
    let count = order.len();
    (HASH_MULTIPLIER + 1..HASH_MULTIPLIER + 1 + RETRY_LIMIT).find(|&seed| {
        let mut taken = Vec::new();
        for &entry in entries {
            let target = slot(names[entry], seed, count);
            if order[target].is_some() || taken.contains(&target) {
                return false;
            }
            taken.push(target);
        }
        true
    })
}

/// A minimal class file: magic, minor 0, major 65 (Java 21) and a constant
/// pool count of 0x0101 (both bytes nonzero), then filler.
fn class_file(filler: &[u8]) -> Vec<u8> {
    let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0x01, 0x01];
    class.extend_from_slice(filler);
    class
}

/// A class file whose constant pool count is 1 (no entries), so a
/// `compact-cp` layer copies it unchanged.
fn empty_pool_class(filler: &[u8]) -> Vec<u8> {
    let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0x00, 0x01];
    class.extend_from_slice(filler);
    class
}

/// The synthetic ELF header of the compressed-stream fixtures.
fn elf() -> Vec<u8> {
    fixture("compressed/payload.elf")
}

/// One compressed-resource layer: magic, payload size, decoded size,
/// decompressor name offset, configuration offset (-1: none), last-layer
/// byte, payload; every field in the byte order `le` selects.
fn layer(le: bool, name: u32, decoded_size: u64, payload: &[u8]) -> Vec<u8> {
    let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let w64 = |v: u64| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut out = Vec::new();
    out.extend_from_slice(&w32(LAYER_MAGIC));
    out.extend_from_slice(&w64(payload.len() as u64));
    out.extend_from_slice(&w64(decoded_size));
    out.extend_from_slice(&w32(name));
    out.extend_from_slice(&w32(u32::MAX));
    out.push(1);
    out.extend_from_slice(payload);
    out
}

/// A `zip` layer holding `contents` as a zlib stream.
fn zip_layer(builder: &mut ImageBuilder, le: bool, contents: &[u8]) -> Vec<u8> {
    let name = builder.string(b"zip");
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(contents, 6);
    layer(le, name, contents.len() as u64, &stream)
}

/// Add a compressed resource whose stored bytes are `stored`.
fn add_compressed(builder: &mut ImageBuilder, path: &str, stored: Vec<u8>, size: usize) {
    let compressed_size = stored.len() as u64;
    builder.add(path, stored, compressed_size, size as u64);
}

#[test]
fn synthetic_images_parse_in_both_byte_orders() {
    for (le, layout) in [
        (true, Layout::JimageLittleEndian),
        (false, Layout::JimageBigEndian),
    ] {
        let mut builder = ImageBuilder::new();
        let class = class_file(b"synthetic class");
        builder.stored("/m.one/p/q/A.class", &class);
        builder.stored("/m.one/p/notes.txt", b"plain text");
        builder.stored("/m.two/top.elf", &elf());
        let zipped = zip_layer(&mut builder, le, &class);
        add_compressed(&mut builder, "/m.two/p/B.class", zipped, class.len());
        let image = builder.build(le);
        assert_eq!(javaimage::detect(&image), Some(layout));
        let c = parse(&image, layout);
        assert_eq!(
            labels(&c),
            ["/m.one/p/q/A.class", "/m.two/top.elf", "/m.two/p/B.class"],
            "{}",
            notes(&c)
        );
        assert_eq!(child(&c, "/m.two/p/B.class").data, class);
        assert_eq!(child(&c, "/m.two/p/B.class").transform, Some("jimage zip"));
        assert!(has_note(&c, "2 modules: m.one, m.two"), "{}", notes(&c));
        assert!(has_note(
            &c,
            "Perfect-hash index verified: all 4 locations are found"
        ));
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::Jimage);
        assert_eq!(p.primary.isa, Isa::Jvm);
        assert_eq!(p.slices[1].isa, Isa::X86_64);
    }
}

#[test]
fn names_without_module_parent_or_extension_follow_get_full_name() {
    let mut builder = ImageBuilder::new();
    builder.stored("/m/A.class", &class_file(b"no parent"));
    builder.stored("/m/p/README", &class_file(b"no extension"));
    let image = builder.build(true);
    let c = parse(&image, Layout::JimageLittleEndian);
    assert_eq!(labels(&c), ["/m/A.class", "/m/p/README"]);
}

#[test]
fn stacked_layers_unsupported_decompressors_and_bad_streams() {
    let le = true;
    let class = empty_pool_class(b"stacked layers");
    let mut builder = ImageBuilder::new();
    // compact-cp inside zip: the inner layer only copies (count 1: no
    // entries) and the outer one inflates.
    let compact_cp = builder.string(b"compact-cp");
    let inner = layer(le, compact_cp, class.len() as u64, &class);
    let outer = zip_layer(&mut builder, le, &inner);
    add_compressed(&mut builder, "/m/p/Stacked.class", outer, class.len());
    // An unknown decompressor.
    let lz4 = builder.string(b"lz4");
    let unknown = layer(le, lz4, class.len() as u64, &class);
    add_compressed(&mut builder, "/m/p/Lz4.class", unknown, class.len());
    // A zlib stream with a damaged Adler-32.
    let mut damaged = zip_layer(&mut builder, le, &class);
    let last = damaged.len() - 1;
    damaged[last] ^= 0xff;
    add_compressed(&mut builder, "/m/p/Damaged.class", damaged, class.len());
    // A location whose size disagrees with the decoded size.
    let short = zip_layer(&mut builder, le, &class);
    add_compressed(&mut builder, "/m/p/Short.class", short, class.len() + 1);
    // Marked compressed, but without a layer header: returned as stored.
    let plain = class.clone();
    add_compressed(&mut builder, "/m/p/Plain.class", plain, class.len());
    // Five nested layers.
    let mut nested = class.clone();
    for _ in 0..5 {
        nested = layer(le, compact_cp, nested.len() as u64, &nested);
    }
    add_compressed(&mut builder, "/m/p/Deep.class", nested, class.len());
    // A layer that names a payload size other than the bytes that follow.
    let mut mismatched = layer(le, compact_cp, class.len() as u64, &class);
    mismatched[4] += 1;
    add_compressed(&mut builder, "/m/p/Mismatch.class", mismatched, class.len());
    // A decoded size over the 64 MiB resource limit.
    let huge = zip_layer(&mut builder, le, &class);
    add_compressed(&mut builder, "/m/p/Huge.class", huge, (64 << 20) + 1);

    let image = builder.build(le);
    let c = parse(&image, Layout::JimageLittleEndian);
    assert_eq!(
        labels(&c),
        ["/m/p/Stacked.class", "/m/p/Plain.class"],
        "{}",
        notes(&c)
    );
    let stacked = child(&c, "/m/p/Stacked.class");
    assert_eq!(stacked.data, class);
    assert_eq!(stacked.transform, Some("jimage zip and compact-cp"));
    assert_eq!(child(&c, "/m/p/Plain.class").transform, None);
    let text = notes(&c);
    assert!(
        has_note(
            &c,
            "1 resources name an unsupported decompressor and were not decoded: lz4"
        ),
        "{text}"
    );
    assert!(
        has_note(&c, "4 compressed resources could not be decoded and are not listed; first: /m/p/Damaged.class"),
        "{text}"
    );
    assert!(
        has_note(
            &c,
            "1 compressed resources exceed the 64 MiB resource limit"
        ),
        "{text}"
    );
    assert!(
        has_note(
            &c,
            "8 of 8 resources are compressed; 2 were decoded: 1 with zip (zlib), 1 with compact-cp"
        ),
        "{text}"
    );
}

#[test]
fn compact_cp_rebuilds_externalized_strings_and_descriptors() {
    let le = false;
    let mut builder = ImageBuilder::new();
    let compact_cp = builder.string(b"compact-cp");
    let greeting = builder.string(b"Hello");
    let descriptor = builder.string(b"(L;I)V");
    let package = builder.string(b"java/lang");
    let class_name = builder.string(b"String");
    // A short compressed integer: 0x80 | 1 << 5 | value, for values below 32;
    // otherwise two bytes, 0x80 | 2 << 5 | high bits, then the low byte.
    let int = |value: u32| -> Vec<u8> {
        if value < 32 {
            vec![0xa0 | value as u8]
        } else {
            vec![0xc0 | (value >> 8) as u8, value as u8]
        }
    };
    // Constant pool count 4: an externalized string, an externalized
    // descriptor, and a UTF-8 entry kept in place; then the class body.
    let mut transformed = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 4];
    transformed.push(23);
    transformed.extend(int(greeting));
    transformed.push(25);
    transformed.extend(int(descriptor));
    let types: Vec<u8> = [int(package), int(class_name)].concat();
    transformed.extend(int(types.len() as u32));
    transformed.extend(&types);
    transformed.extend_from_slice(b"\x01\x00\x04Code");
    transformed.extend_from_slice(b"class body");
    let mut expected = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 4];
    expected.extend_from_slice(b"\x01\x00\x05Hello");
    expected.extend_from_slice(b"\x01\x00\x16(Ljava/lang/String;I)V");
    expected.extend_from_slice(b"\x01\x00\x04Code");
    expected.extend_from_slice(b"class body");
    let stored = layer(le, compact_cp, expected.len() as u64, &transformed);
    add_compressed(&mut builder, "/m/p/Cp.class", stored, expected.len());
    let image = builder.build(le);
    let c = parse(&image, Layout::JimageBigEndian);
    let cp = child(&c, "/m/p/Cp.class");
    assert_eq!(cp.data, expected);
    assert_eq!(cp.transform, Some("jimage compact-cp"));
}

#[test]
fn listing_stops_at_the_component_limit() {
    let mut builder = ImageBuilder::new();
    let limit = container::MAX_COMPONENTS;
    for i in 0..limit + 3 {
        builder.stored(&format!("/m/p/C{i}.class"), &class_file(b""));
    }
    let image = builder.build(true);
    let c = parse(&image, Layout::JimageLittleEndian);
    assert_eq!(c.children.len(), limit);
    assert!(
        has_note(
            &c,
            "Resource listing stopped at 4096 recognized resources; 3 further"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, &format!("all {} locations", limit + 3)));
}

#[test]
fn empty_images_and_padding_are_accepted() {
    let image = ImageBuilder::new().build(true);
    let c = parse(&image, Layout::JimageLittleEndian);
    assert!(c.children.is_empty());
    let mut padded = image.clone();
    padded.extend_from_slice(&[0; 16]);
    let c = parse(&padded, Layout::JimageLittleEndian);
    assert!(has_note(&c, "16 B of padding follow"), "{}", notes(&c));
    assert_eq!(c.consumed, image.len());
}

// ---------------------------------------------------------------------------
// Damage
// ---------------------------------------------------------------------------

/// Header field offsets.
const VERSION: usize = 4;
const TABLE_LENGTH: usize = 16;
const LOCATIONS_SIZE: usize = 20;

#[test]
fn header_and_index_damage_is_reported() {
    let image = fixture("javaimage/sample-le.jimage");
    let table_length = le_u32(&image, TABLE_LENGTH) as usize;
    let locations_size = le_u32(&image, LOCATIONS_SIZE) as usize;
    let offsets_at = 28 + 4 * table_length;
    let locations_at = offsets_at + 4 * table_length;
    let strings_at = locations_at + locations_size;

    let mut minor = image.clone();
    put_le32(&mut minor, VERSION, 0x0001_0001);
    assert!(
        parse_error(&minor, Layout::JimageLittleEndian).contains("Unsupported jimage version 1.1")
    );
    // Still recognized: the major version matches.
    assert_eq!(javaimage::detect(&minor), Some(Layout::JimageLittleEndian));
    let mut major = image.clone();
    put_le32(&mut major, VERSION, 0x0002_0000);
    assert_eq!(javaimage::detect(&major), None);

    assert!(parse_error(&image, Layout::JimageBigEndian).contains("Invalid jimage magic"));

    let mut long_table = image.clone();
    put_le32(&mut long_table, TABLE_LENGTH, 0x1000_0000);
    assert!(parse_error(&long_table, Layout::JimageLittleEndian).contains("Truncated jimage index"));

    let mut location_offset = image.clone();
    put_le32(&mut location_offset, offsets_at, locations_size as u32);
    assert!(parse_error(&location_offset, Layout::JimageLittleEndian)
        .contains("Invalid jimage location offset"));

    // The first location's first header byte: kind 1 (module).
    let first = locations_at + le_u32(&image, offsets_at) as usize;
    assert_eq!(image[first] >> 3, 1);
    let mut kind = image.clone();
    kind[first] = 8 << 3;
    assert!(parse_error(&kind, Layout::JimageLittleEndian)
        .contains("Invalid jimage location attribute kind 8"));
    let mut duplicate = image.clone();
    duplicate[first + 2] = duplicate[first];
    assert!(parse_error(&duplicate, Layout::JimageLittleEndian)
        .contains("Duplicate jimage location attribute kind 1"));
    let mut string = image.clone();
    string[first + 1] = 0xff;
    let message = parse_error(&string, Layout::JimageLittleEndian);
    assert!(
        message.contains("Invalid jimage string offset 0xFF") || message.contains("redirect table"),
        "{message}"
    );

    // Renaming a string breaks the perfect hash.
    let mut renamed = image.clone();
    let class_at = strings_at + 1;
    assert_eq!(&renamed[class_at..class_at + 5], b"class");
    renamed[class_at] = b'k';
    assert!(parse_error(&renamed, Layout::JimageLittleEndian)
        .contains("is not found through the redirect table"));
    let mut unterminated = image.clone();
    let strings_size = le_u32(&image, 24) as usize;
    for b in &mut unterminated[strings_at..strings_at + strings_size] {
        if *b == 0 {
            *b = b'x';
        }
    }
    assert!(parse_error(&unterminated, Layout::JimageLittleEndian).contains("jimage string"));

    let mut redirect = image.clone();
    for slot in 0..table_length {
        put_le32(&mut redirect, 28 + 4 * slot, 0);
    }
    assert!(parse_error(&redirect, Layout::JimageLittleEndian)
        .contains("is not found through the redirect table"));

    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing, Layout::JimageLittleEndian)
        .contains("Unexpected 4 B after the jimage resources at 0x774"));

    let short = &image[..image.len() - ROOT_LISTING - 1];
    assert!(parse_error(short, Layout::JimageLittleEndian).contains("Truncated jimage resource"));
}

// ---------------------------------------------------------------------------
// Sweeps
// ---------------------------------------------------------------------------

#[test]
fn every_truncation_of_an_image_is_an_error() {
    for (name, layout, _) in IMAGES {
        let image = fixture(name);
        // Without the root listing the image is complete: no location names
        // the root directory. Zero bytes of a cut big-endian listing are
        // padding.
        let without_root = image.len() - ROOT_LISTING;
        for end in 0..image.len() {
            let parsed = container::parse(&image[..end], Kind::JavaImage(layout));
            let complete = end >= without_root && image[without_root..end].iter().all(|b| *b == 0);
            if complete {
                assert_eq!(labels(&parsed.expect("complete")), RESOURCES, "{name}");
            } else {
                assert!(parsed.is_err(), "{name}: prefix of {end} B parsed");
            }
        }
    }
}

#[test]
fn every_truncation_of_a_jmod_leaves_the_isa_unknown() {
    let jmod = fixture("javaimage/sample.jmod");
    for end in 0..jmod.len() {
        let Ok(p) = detect_payload(&jmod[..end], &ClassifierOptions::new()) else {
            continue;
        };
        if p.format.format != FileFormat::Jmod {
            // Shorter than the header and the ZIP signature.
            assert!(end < 8, "prefix of {end} B: {:?}", p.format.format);
            continue;
        }
        assert!(
            matches!(p.primary.isa, Isa::Unknown(_)),
            "prefix of {end} B: {:?}",
            p.primary.isa
        );
    }
}

/// Byte values a mutation sweep writes: zero, erased flash and each
/// single-bit flip of the original byte.
fn mutations(original: u8) -> impl Iterator<Item = u8> {
    [0x00, 0xff]
        .into_iter()
        .chain((0..8).map(move |bit| original ^ (1 << bit)))
}

#[test]
fn byte_mutations_never_panic_the_parser() {
    for (name, layout, _) in IMAGES {
        let image = fixture(name);
        for at in 0..image.len() {
            for value in mutations(image[at]) {
                let mut mutated = image.clone();
                mutated[at] = value;
                let _ = container::parse(&mutated, Kind::JavaImage(layout));
            }
        }
    }
    let jmod = fixture("javaimage/sample.jmod");
    for at in 0..jmod.len() {
        for value in mutations(jmod[at]) {
            let mut mutated = jmod.clone();
            mutated[at] = value;
            let _ = container::parse(&mutated, Kind::JavaImage(Layout::Jmod));
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

#[test]
fn index_mutations_never_panic_the_classifier() {
    // The index only: mutated class bytes would reach the class file
    // parser, which is not under test here.
    for (name, layout, _) in IMAGES {
        let image = fixture(name);
        let index_size = javaimage_index_size(&image, layout);
        for at in 0..index_size {
            for value in mutations(image[at]) {
                let mut mutated = image.clone();
                mutated[at] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

/// Header, both tables, attribute streams and strings, from the header.
fn javaimage_index_size(image: &[u8], layout: Layout) -> usize {
    let word = |at: usize| {
        let bytes: [u8; 4] = image[at..at + 4].try_into().unwrap();
        if layout == Layout::JimageBigEndian {
            u32::from_be_bytes(bytes) as usize
        } else {
            u32::from_le_bytes(bytes) as usize
        }
    };
    28 + 8 * word(16) + word(20) + word(24)
}

// ---------------------------------------------------------------------------
// External images
// ---------------------------------------------------------------------------

/// `JIMAGE_REFERENCE` names a real `lib/modules`: it must parse with every
/// location verified. Skipped when unset.
#[test]
fn reference_image_parses_with_a_verified_index() {
    let Ok(path) = std::env::var("JIMAGE_REFERENCE") else {
        eprintln!("JIMAGE_REFERENCE not set; skipped");
        return;
    };
    let image = std::fs::read(&path).expect("reference image is readable");
    let layout = javaimage::detect(&image).expect("a jimage");
    let c = parse(&image, layout);
    assert!(has_note(&c, "Perfect-hash index verified"), "{}", notes(&c));
    assert!(!c.children.is_empty());
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Jvm);
}

/// `JIMAGE_COMPRESSED_REFERENCE` and `JIMAGE_PLAIN_REFERENCE` name two jlink
/// images of the same modules, one with `--compress`: every listed
/// resource must decode to the stored bytes of the other. Skipped when
/// unset.
#[test]
fn reference_compressed_image_decodes_to_the_plain_image() {
    let (Ok(compressed), Ok(plain)) = (
        std::env::var("JIMAGE_COMPRESSED_REFERENCE"),
        std::env::var("JIMAGE_PLAIN_REFERENCE"),
    ) else {
        eprintln!("JIMAGE_COMPRESSED_REFERENCE or JIMAGE_PLAIN_REFERENCE not set; skipped");
        return;
    };
    let compressed = std::fs::read(compressed).expect("compressed image is readable");
    let plain = std::fs::read(plain).expect("plain image is readable");
    let decoded = parse(
        &compressed,
        javaimage::detect(&compressed).expect("a jimage"),
    );
    let stored = parse(&plain, javaimage::detect(&plain).expect("a jimage"));
    let reference: HashMap<&str, &[u8]> = stored
        .children
        .iter()
        .map(|child| (child.label.as_str(), &child.data[..]))
        .collect();
    assert!(!decoded.children.is_empty());
    for child in &decoded.children {
        assert_eq!(
            Some(&&child.data[..]),
            reference.get(child.label.as_str()),
            "{}",
            child.label
        );
    }
}
