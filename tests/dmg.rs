//! Apple disk images: hdiutil-made UDIF images of an HFS+ volume in every
//! chunk codec it writes (UDZO, UDBZ, ULFO, ULMO, UDCO, UDRO), a FAT
//! volume image whose partition holds the synthetic ELF, an AES-128
//! encrypted image, synthetic images built from the documented layouts
//! (raw and zlib chunks, zero fill, data fork CRC-32, a binary resource
//! fork, an encrypted version 1 footer), corrupted fields and checksums,
//! and truncation and mutation sweeps.

use std::borrow::Cow;
use zrax::formats::checksum::{crc32, crc32_update};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{self, Child, Container, Kind};
use zrax::formats::dmg::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Bytes of a 512-byte sector.
const SECTOR: usize = 512;

/// Size of the UDIF trailer.
const TRAILER: usize = 512;

/// Chunk types (libdmg-hfsplus `includes/dmg/dmg.h`).
const CHUNK_ZERO: u32 = 0x0000_0000;
const CHUNK_RAW: u32 = 0x0000_0001;
const CHUNK_IGNORE: u32 = 0x0000_0002;
const CHUNK_ZLIB: u32 = 0x8000_0005;
const CHUNK_COMMENT: u32 = 0x7fff_fffe;
const CHUNK_END: u32 = 0xffff_ffff;

/// Checksum type 2: CRC-32.
const CHECKSUM_CRC32: u32 = 2;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// A fixture from `tests/fixtures/dmg`, without its `.gz`.
fn fixture(name: &str) -> Vec<u8> {
    compressed::decode(Codec::Gzip, &read(&format!("dmg/{name}.gz")))
        .expect("the fixture is a gzip stream")
        .data
}

/// The synthetic x86-64 ELF header every volume holds.
fn payload_elf() -> Vec<u8> {
    read("compressed/payload.elf")
}

/// The FAT12 volume of the FAT tests, which holds `payload.elf`.
fn fat12() -> Vec<u8> {
    read("fat/fat12.img")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse an image that must be valid.
fn parse(data: &[u8]) -> Container<'_> {
    let layout = dmg::detect(data).expect("detected as an Apple disk image");
    dmg::parse_container(data, layout).expect("parses")
}

/// The error text of an image that does not parse as `layout`.
fn parse_error(data: &[u8], layout: Layout) -> String {
    dmg::parse_container(data, layout)
        .expect_err("does not parse")
        .to_string()
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|note| note.message.contains(text))
}

/// The value of the metadata entry `key`.
fn metadata(c: &Container<'_>, key: &str) -> String {
    c.metadata()
        .into_iter()
        .find(|entry| format!("{:?}", entry.key).contains(&format!("\"{key}\"")))
        .map(|entry| entry.value.to_string())
        .unwrap_or_else(|| panic!("metadata {key}: {:?}", c.metadata()))
}

/// The child labeled `label`, if listed.
fn child<'c>(c: &'c Container<'_>, label: &str) -> Option<&'c Child<'c>> {
    c.children.iter().find(|child| child.label == label)
}

fn be_u64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Standard base64 (RFC 4648 section 4) with padding, wrapped at 52
/// characters per line as hdiutil-style property lists are.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::new();
    for (i, group) in bytes.chunks(3).enumerate() {
        if i > 0 && i % 13 == 0 {
            text.push_str("\n\t\t\t\t");
        }
        let value = group
            .iter()
            .enumerate()
            .fold(0u32, |v, (k, &b)| v | u32::from(b) << (16 - 8 * k));
        for k in 0..4 {
            if k <= group.len() {
                text.push(char::from(
                    ALPHABET[(value >> (18 - 6 * k) & 0x3f) as usize],
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}

// ---------------------------------------------------------------------
// Synthetic images from the documented layout (libdmg-hfsplus `dmg.h`)
// ---------------------------------------------------------------------

/// One chunk of a synthetic partition.
struct ChunkSpec {
    /// Chunk type.
    kind: u32,
    /// Sectors of 512 bytes the chunk covers.
    sectors: u64,
    /// Decoded bytes of a raw or compressed chunk (empty otherwise).
    decoded: Vec<u8>,
    /// Bytes stored in the data fork (empty for zero fill and free space).
    stored: Vec<u8>,
}

fn sectors_of(bytes: &[u8]) -> u64 {
    assert_eq!(bytes.len() % SECTOR, 0, "whole sectors");
    (bytes.len() / SECTOR) as u64
}

fn raw_chunk(bytes: &[u8]) -> ChunkSpec {
    ChunkSpec {
        kind: CHUNK_RAW,
        sectors: sectors_of(bytes),
        decoded: bytes.to_vec(),
        stored: bytes.to_vec(),
    }
}

fn zlib_chunk(bytes: &[u8]) -> ChunkSpec {
    ChunkSpec {
        kind: CHUNK_ZLIB,
        sectors: sectors_of(bytes),
        decoded: bytes.to_vec(),
        stored: miniz_oxide::deflate::compress_to_vec_zlib(bytes, 9),
    }
}

/// A zero fill, free space or comment chunk of `sectors` sectors.
fn empty_chunk(kind: u32, sectors: u64) -> ChunkSpec {
    ChunkSpec {
        kind,
        sectors,
        decoded: Vec::new(),
        stored: Vec::new(),
    }
}

/// Partitions larger than this get a table CRC-32 of 0 in synthetic
/// images: the parser cannot verify it (it decodes at most 64 MiB), and
/// computing it would take long.
const MAX_CRC_SIZE: u64 = 64 << 20;

/// The CRC-32 of a partition's decoded bytes, free space left out.
fn table_crc(chunks: &[ChunkSpec]) -> u32 {
    let size: u64 = chunks.iter().map(|c| c.sectors).sum::<u64>() * SECTOR as u64;
    if size > MAX_CRC_SIZE {
        return 0;
    }
    let zeros = [0u8; SECTOR];
    let mut crc = !0u32;
    for chunk in chunks {
        match chunk.kind {
            CHUNK_IGNORE | CHUNK_COMMENT => {}
            CHUNK_ZERO => {
                for _ in 0..chunk.sectors {
                    crc = crc32_update(crc, &zeros);
                }
            }
            _ => crc = crc32_update(crc, &chunk.decoded),
        }
    }
    !crc
}

/// A block table and the name it is listed under.
struct NamedTable {
    name: &'static str,
    table: Vec<u8>,
}

/// One synthetic partition: a name and its chunks.
struct PartitionSpec {
    name: &'static str,
    chunks: Vec<ChunkSpec>,
}

/// How a synthetic image is built.
#[derive(Clone, Copy, Default)]
struct ImageOptions {
    /// Store a data fork CRC-32 in the trailer.
    data_fork_crc: bool,
    /// Store the block tables in a binary resource fork instead of an XML
    /// property list.
    resource_fork: bool,
    /// Store this CRC-32 in the first table instead of the right one; the
    /// master checksum still matches the stored values.
    wrong_table_crc: Option<u32>,
}

/// A block table (`BLKXTable`): signature `mish`, version 1, first sector,
/// sector count, data start 0, decompress buffer size, descriptor,
/// reserved, a CRC-32 checksum record and the chunk records, then an end
/// chunk. `offsets` are the chunks' compressed offsets in the data fork.
fn block_table(first: u64, chunks: &[ChunkSpec], offsets: &[u64], crc: u32, id: u32) -> Vec<u8> {
    let sectors: u64 = chunks.iter().map(|c| c.sectors).sum();
    let mut table = vec![0u8; 204];
    put(&mut table, 0, b"mish");
    put(&mut table, 4, &1u32.to_be_bytes());
    put(&mut table, 8, &first.to_be_bytes());
    put(&mut table, 16, &sectors.to_be_bytes());
    put(&mut table, 32, &2048u32.to_be_bytes());
    put(&mut table, 36, &id.to_be_bytes());
    put(&mut table, 64, &CHECKSUM_CRC32.to_be_bytes());
    put(&mut table, 68, &32u32.to_be_bytes());
    put(&mut table, 72, &crc.to_be_bytes());
    put(&mut table, 200, &(chunks.len() as u32 + 1).to_be_bytes());
    let mut sector = 0u64;
    for (chunk, &offset) in chunks.iter().zip(offsets) {
        let count = chunk.sectors;
        table.extend_from_slice(&chunk.kind.to_be_bytes());
        table.extend_from_slice(&[0; 4]);
        table.extend_from_slice(&sector.to_be_bytes());
        table.extend_from_slice(&count.to_be_bytes());
        table.extend_from_slice(&offset.to_be_bytes());
        table.extend_from_slice(&(chunk.stored.len() as u64).to_be_bytes());
        sector += count;
    }
    table.extend_from_slice(&CHUNK_END.to_be_bytes());
    table.extend_from_slice(&[0; 4]);
    table.extend_from_slice(&sector.to_be_bytes());
    table.extend_from_slice(&[0; 24]);
    table
}

/// An XML property list with a `resource-fork` `blkx` array (7-Zip
/// `DmgHandler.cpp`): one entry per table with `Attributes`, `CFName`,
/// `Data`, `ID` and `Name`.
fn property_list(tables: &[NamedTable]) -> Vec<u8> {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\t<key>resource-fork</key>\n\t<dict>\n\
         \t\t<key>blkx</key>\n\t\t<array>\n",
    );
    for (i, NamedTable { name, table }) in tables.iter().enumerate() {
        xml.push_str(&format!(
            "\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\
             \t\t\t\t<key>CFName</key>\n\t\t\t\t<string>{name}</string>\n\
             \t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n\t\t\t\t{}\n\t\t\t\t</data>\n\
             \t\t\t\t<key>ID</key>\n\t\t\t\t<string>{}</string>\n\
             \t\t\t\t<key>Name</key>\n\t\t\t\t<string>{name}</string>\n\t\t\t</dict>\n",
            base64(table),
            i as i64 - 1
        ));
    }
    xml.push_str("\t\t</array>\n\t</dict>\n</dict>\n</plist>\n");
    xml.into_bytes()
}

/// A resource fork (Inside Macintosh: More Macintosh Toolbox, Figures 1-11
/// to 1-17): header, the tables as resource data, and a map with one type
/// (`blkx`), one reference per table and the names.
fn resource_fork(tables: &[NamedTable]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut data_offsets = Vec::new();
    for NamedTable { table, .. } in tables {
        data_offsets.push(data.len() as u32);
        data.extend_from_slice(&(table.len() as u32).to_be_bytes());
        data.extend_from_slice(table);
    }
    let type_list = 28usize;
    let references = 2 + 8;
    let names_at = type_list + references + 12 * tables.len();
    let mut map = vec![0u8; 24];
    map.extend_from_slice(&(type_list as u16).to_be_bytes());
    map.extend_from_slice(&(names_at as u16).to_be_bytes());
    map.extend_from_slice(&0u16.to_be_bytes()); // one type
    map.extend_from_slice(b"blkx");
    map.extend_from_slice(&(tables.len() as u16 - 1).to_be_bytes());
    map.extend_from_slice(&(references as u16).to_be_bytes());
    let mut names = Vec::new();
    for (i, NamedTable { name, .. }) in tables.iter().enumerate() {
        map.extend_from_slice(&(i as i16 - 1).to_be_bytes());
        map.extend_from_slice(&(names.len() as u16).to_be_bytes());
        map.extend_from_slice(&(0x5000_0000 | data_offsets[i]).to_be_bytes());
        map.extend_from_slice(&[0; 4]);
        names.push(name.len() as u8);
        names.extend_from_slice(name.as_bytes());
    }
    map.extend_from_slice(&names);
    let header = 256u32;
    let mut fork = Vec::new();
    fork.extend_from_slice(&header.to_be_bytes());
    fork.extend_from_slice(&(header + data.len() as u32).to_be_bytes());
    fork.extend_from_slice(&(data.len() as u32).to_be_bytes());
    fork.extend_from_slice(&(map.len() as u32).to_be_bytes());
    fork.resize(header as usize, 0);
    fork.extend_from_slice(&data);
    fork.extend_from_slice(&map);
    fork
}

/// A UDIF image: the data fork (every chunk's stored bytes in order), the
/// property list or resource fork, then the trailer (`UDIFResourceFile`):
/// `koly`, version 4, size 512, flags 1 (flattened), data fork at 0,
/// resource fork, segment 1 of 1, the data fork checksum at 80, the
/// property list at 216, the master CRC-32 at 352, image variant 1 and the
/// sector count at 492.
fn image(partitions: &[PartitionSpec], options: ImageOptions) -> Vec<u8> {
    let mut fork = Vec::new();
    let mut tables: Vec<NamedTable> = Vec::new();
    let mut first = 0u64;
    for (i, p) in partitions.iter().enumerate() {
        let mut offsets = Vec::new();
        for chunk in &p.chunks {
            offsets.push(fork.len() as u64);
            fork.extend_from_slice(&chunk.stored);
        }
        let crc = match options.wrong_table_crc {
            Some(wrong) if i == 0 => wrong,
            _ => table_crc(&p.chunks),
        };
        let table = block_table(first, &p.chunks, &offsets, crc, i as u32);
        first += p.chunks.iter().map(|c| c.sectors).sum::<u64>();
        tables.push(NamedTable {
            name: p.name,
            table,
        });
    }
    let master: Vec<u8> = tables
        .iter()
        .flat_map(|t| t.table[72..76].to_vec())
        .collect();
    let mut data = fork.clone();
    let metadata_at = data.len() as u64;
    let metadata = if options.resource_fork {
        resource_fork(&tables)
    } else {
        property_list(&tables)
    };
    data.extend_from_slice(&metadata);
    let mut trailer = vec![0u8; TRAILER];
    put(&mut trailer, 0, b"koly");
    put(&mut trailer, 4, &4u32.to_be_bytes());
    put(&mut trailer, 8, &512u32.to_be_bytes());
    put(&mut trailer, 12, &1u32.to_be_bytes());
    put(&mut trailer, 32, &(fork.len() as u64).to_be_bytes());
    let (metadata_field, length_field) = if options.resource_fork {
        (40, 48)
    } else {
        (216, 224)
    };
    put(&mut trailer, metadata_field, &metadata_at.to_be_bytes());
    put(
        &mut trailer,
        length_field,
        &(metadata.len() as u64).to_be_bytes(),
    );
    put(&mut trailer, 56, &1u32.to_be_bytes());
    put(&mut trailer, 60, &1u32.to_be_bytes());
    if options.data_fork_crc {
        put(&mut trailer, 80, &CHECKSUM_CRC32.to_be_bytes());
        put(&mut trailer, 84, &32u32.to_be_bytes());
        put(&mut trailer, 88, &crc32(&fork).to_be_bytes());
    }
    put(&mut trailer, 352, &CHECKSUM_CRC32.to_be_bytes());
    put(&mut trailer, 356, &32u32.to_be_bytes());
    put(&mut trailer, 360, &crc32(&master).to_be_bytes());
    put(&mut trailer, 488, &1u32.to_be_bytes());
    put(&mut trailer, 492, &first.to_be_bytes());
    data.extend_from_slice(&trailer);
    data
}

/// A FAT12 disk: an MBR-style map entry of one sector stored raw, then the
/// FAT12 volume in `volume` chunks.
fn fat_disk(volume: Vec<ChunkSpec>) -> Vec<PartitionSpec> {
    let mut mbr = vec![0u8; SECTOR];
    put(&mut mbr, 510, &[0x55, 0xaa]);
    vec![
        PartitionSpec {
            name: "Master Boot Record (MBR : 0)",
            chunks: vec![raw_chunk(&mbr)],
        },
        PartitionSpec {
            name: " (DOS_FAT_12 : 1)",
            chunks: volume,
        },
    ]
}

// ---------------------------------------------------------------------
// hdiutil images
// ---------------------------------------------------------------------

/// An HFS+ image hdiutil made, and the chunk kinds of its volume
/// partition.
struct HfsImage {
    name: &'static str,
    chunks: &'static str,
}

const HFS_IMAGES: &[HfsImage] = &[
    HfsImage {
        name: "hfs-udzo.dmg",
        chunks: "chunks: zlib 2, ignore 2",
    },
    HfsImage {
        name: "hfs-udbz.dmg",
        chunks: "chunks: bzip2 2, ignore 2",
    },
    HfsImage {
        name: "hfs-ulfo.dmg",
        chunks: "chunks: LZFSE 2, ignore 2",
    },
    HfsImage {
        name: "hfs-ulmo.dmg",
        chunks: "chunks: LZMA 2, ignore 2",
    },
    HfsImage {
        name: "hfs-udco.dmg",
        chunks: "chunks: ADC 2, ignore 2",
    },
    HfsImage {
        name: "hfs-udro.dmg",
        chunks: "zero 6, raw 7, ignore 2",
    },
];

/// The partitions hdiutil writes for a 1 MiB GPT disk, in table order.
const GPT_PARTITIONS: [&str; 8] = [
    "Protective Master Boot Record (MBR : 0)",
    "GPT Header (Primary GPT Header : 1)",
    "GPT Partition Data (Primary GPT Table : 2)",
    "(Apple_Free : 3)",
    "disk image (Apple_HFS : 4)",
    "(Apple_Free : 5)",
    "GPT Partition Data (Backup GPT Table : 6)",
    "GPT Header (Backup GPT Header : 7)",
];

const HFS_PARTITION: &str = "disk image (Apple_HFS : 4)";

#[test]
fn hdiutil_images_decode_every_codec_and_verify_every_crc() {
    for &HfsImage { name, chunks } in HFS_IMAGES {
        let data = fixture(name);
        assert_eq!(dmg::detect(&data), Some(Layout::Udif), "{name}");
        assert!(
            matches!(
                detect_format(&data),
                DetectedFormat::Container {
                    kind: Kind::Dmg(Layout::Udif)
                }
            ),
            "{name}"
        );
        let c = parse(&data);
        assert_eq!(c.format, FileFormat::AppleDmg, "{name}");
        assert_eq!(c.variant, "UDIF disk image", "{name}");
        assert!(c.target.is_none(), "{name}: disk images name no ISA");
        assert!(
            has_note(
                &c,
                "8 block tables in the XML property list; disk of 2048 sectors"
            ),
            "{name}: {:?}",
            c.notes
        );
        // Every partition decoded to bytes whose CRC-32 matches its table,
        // so every codec produced exactly what hdiutil compressed.
        assert!(
            has_note(&c, "Block table CRC-32 verified for every partition (8)"),
            "{name}: {:?}",
            c.notes
        );
        assert!(has_note(&c, "Master CRC-32 0x"), "{name}");
        assert!(has_note(&c, "No data fork checksum is stored"), "{name}");
        for (i, partition) in GPT_PARTITIONS.iter().enumerate() {
            let entry = c
                .metadata()
                .into_iter()
                .find(|e| format!("{:?}", e.key).contains(&format!("\"dmg_partition_{i}\"")))
                .expect("partition entry");
            assert_eq!(entry.label, *partition, "{name}");
        }
        let hfs = metadata(&c, "dmg_partition_4");
        assert!(
            hfs.starts_with("sectors 40-2007 (984 KiB); "),
            "{name}: {hfs}"
        );
        assert!(hfs.contains(chunks), "{name}: {hfs}");
        assert!(hfs.contains("verified"), "{name}: {hfs}");
        // The maps and free space are never children; the HFS+ volume is
        // one when a parser recognizes it, and holds `H+` at 1024 then.
        match child(&c, HFS_PARTITION) {
            Some(volume) => {
                assert_eq!(&volume.data[1024..1026], b"H+", "{name}");
                assert_eq!(volume.data.len(), 1968 * SECTOR, "{name}");
            }
            None => assert!(
                has_note(
                    &c,
                    "Not in a recognized format, so not classified: disk image"
                ),
                "{name}: {:?}",
                c.notes
            ),
        }
        assert!(
            c.children.iter().all(|child| child.label == HFS_PARTITION),
            "{name}"
        );
    }
}

#[test]
fn the_fat_image_yields_a_fat_child_with_its_elf_member() {
    let data = fixture("fat-udzo.dmg");
    let c = parse(&data);
    assert_eq!(c.children.len(), 1, "{:?}", c.notes);
    let volume = &c.children[0];
    assert_eq!(volume.label, "(DOS_FAT_32 : 1)");
    assert_eq!(volume.transform, Some("UDIF zlib chunks"));
    assert_eq!(volume.data.len(), 2047 * SECTOR);
    // The stored chunk follows the MBR's chunk in the data fork.
    assert_eq!(volume.offset, 0x1e);
    let DetectedFormat::Container { kind } = detect_format(&volume.data) else {
        panic!("the volume is a container format");
    };
    assert_eq!(kind.format(), FileFormat::Fat, "{kind:?}");
    let fat = container::parse(&volume.data, kind).expect("the FAT volume parses");
    let elf = payload_elf();
    let member = fat
        .children
        .iter()
        .find(|member| member.data == elf.as_slice())
        .unwrap_or_else(|| panic!("payload.elf is a member: {:?}", fat.notes));
    assert!(member.label.to_ascii_lowercase().ends_with("payload.elf"));

    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::AppleDmg);
    assert_eq!(p.primary.isa, Isa::X86_64, "from the ELF in the FAT volume");
    let slice = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("(DOS_FAT_32 : 1)"))
        .expect("the FAT volume is a slice");
    assert_eq!(slice.isa, Isa::X86_64);
    assert_eq!(slice.offset, 0x1e);
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "UDIF zlib chunks");
    assert_eq!(decoded.size, (2047 * SECTOR) as u64);
    assert!(payload_has_note(
        &p,
        "Primary ISA selected from (DOS_FAT_32 : 1)"
    ));
    assert!(payload_has_note(
        &p,
        "Disk images name no ISA; each partition is classified on its own"
    ));
}

#[test]
fn hdiutil_segments_parse_on_their_own() {
    // `hdiutil segment` splits hfs-udro.dmg: the first segment holds the
    // tables and the first 32 KiB of the data fork.
    let first = fixture("segmented.dmg");
    let c = parse(&first);
    assert!(
        has_note(&c, "8 block tables in the XML property list"),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "Segment 1 of 2: chunks stored in the other segment files are not available"
    ));
    assert!(
        has_note(
            &c,
            "disk image (Apple_HFS : 4) (a chunk is in another segment file)"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "Master CRC-32 0x"));
    assert!(c.children.is_empty());
    assert_eq!(metadata(&c, "dmg_segment"), "1 of 2");
    assert_eq!(metadata(&c, "dmg_data_fork"), "file 0x0; 32768 B");

    // The second segment repeats the master checksum but has an empty
    // `resource-fork` dictionary.
    let second = fixture("segmented.002.dmgpart");
    let c = parse(&second);
    assert!(
        has_note(&c, "0 block tables in the XML property list"),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "not verified: there are no block tables"));
    assert!(has_note(&c, "There are no block tables"));
    assert_eq!(metadata(&c, "dmg_segment"), "2 of 2");
    assert_eq!(metadata(&c, "dmg_running_data_fork_offset"), "32768");
    assert!(c.children.is_empty());
    assert!(matches!(classify(&second).primary.isa, Isa::Unknown(_)));
}

#[test]
fn the_encrypted_image_is_opaque() {
    let data = fixture("encrypted.dmg");
    assert_eq!(dmg::detect(&data), Some(Layout::EncryptedV2));
    let c = parse(&data);
    assert_eq!(c.variant, "Encrypted disk image (encrcdsa)");
    assert!(c.opaque);
    assert!(has_note(
        &c,
        "Encrypted Encoding version 2: AES-128 in blocks of 512 B"
    ));
    assert!(has_note(&c, "1 key protector"));
    let encrypted = &c.children[0];
    assert!(encrypted.opaque);
    assert_eq!(encrypted.offset as u64, be_u64(&data, 64));
    assert_eq!(encrypted.offset + encrypted.data.len(), data.len());
    assert_eq!(metadata(&c, "dmg_cipher"), "AES-128");

    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::AppleDmg);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(payload_has_note(&p, "Encrypted data: opaque"));
}

#[test]
fn json_format_id_is_appledmg() {
    assert_eq!(
        serde_json::to_value(FileFormat::AppleDmg).unwrap(),
        "appledmg"
    );
    assert_eq!(FileFormat::AppleDmg.to_string(), "Apple disk image");
    for layout in [Layout::Udif, Layout::EncryptedV2, Layout::EncryptedV1] {
        assert_eq!(layout.format(), FileFormat::AppleDmg);
        assert!(!layout.is_weak());
    }
}

// ---------------------------------------------------------------------
// Synthetic images
// ---------------------------------------------------------------------

#[test]
fn a_partition_in_one_raw_chunk_is_a_slice_of_the_file() {
    let volume = fat12();
    let data = image(&fat_disk(vec![raw_chunk(&volume)]), ImageOptions::default());
    let c = parse(&data);
    let fat = child(&c, "(DOS_FAT_12 : 1)").expect("the FAT volume is listed");
    assert_eq!(fat.transform, None);
    assert_eq!(fat.offset, SECTOR, "after the MBR's raw chunk");
    assert!(matches!(fat.data, Cow::Borrowed(_)));
    assert_eq!(&fat.data[..], &volume[..]);
    assert_eq!(c.children.len(), 1, "the MBR is a map entry");
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn zero_fill_comments_and_mixed_chunks_are_assembled() {
    let volume = fat12();
    let (head, tail) = volume.split_at(64 * SECTOR);
    let tail_end = tail.len() - 8 * SECTOR;
    assert!(
        tail[tail_end..].iter().all(|&b| b == 0),
        "the volume ends in zeros"
    );
    let data = image(
        &fat_disk(vec![
            zlib_chunk(head),
            empty_chunk(CHUNK_COMMENT, 0),
            raw_chunk(&tail[..tail_end]),
            empty_chunk(CHUNK_ZERO, 4),
            empty_chunk(CHUNK_IGNORE, 4),
        ]),
        ImageOptions {
            data_fork_crc: true,
            ..ImageOptions::default()
        },
    );
    let c = parse(&data);
    let fat = child(&c, "(DOS_FAT_12 : 1)").expect("listed");
    assert_eq!(fat.transform, Some("UDIF chunks"));
    assert_eq!(&fat.data[..], &volume[..]);
    assert!(has_note(&c, "Data fork CRC-32 0x"), "{:?}", c.notes);
    assert!(has_note(&c, "verified"));
    assert!(has_note(
        &c,
        "Block table CRC-32 verified for every partition (2)"
    ));
    assert!(metadata(&c, "dmg_partition_1").contains("chunks: zlib 1, raw 1, zero 1, ignore 1"));
}

#[test]
fn resource_fork_images_list_their_blkx_resources() {
    let volume = fat12();
    let data = image(
        &fat_disk(vec![zlib_chunk(&volume)]),
        ImageOptions {
            resource_fork: true,
            ..ImageOptions::default()
        },
    );
    assert_eq!(dmg::detect(&data), Some(Layout::Udif));
    let c = parse(&data);
    assert!(
        has_note(&c, "2 block tables in the resource fork"),
        "{:?}",
        c.notes
    );
    let fat = child(&c, "(DOS_FAT_12 : 1)").expect("listed");
    assert_eq!(&fat.data[..], &volume[..]);
    assert_eq!(classify(&data).primary.isa, Isa::X86_64);
}

#[test]
fn an_image_after_other_data_is_not_claimed() {
    let mut data = b"junk before the image".to_vec();
    data.extend_from_slice(&image(
        &fat_disk(vec![raw_chunk(&fat12())]),
        ImageOptions::default(),
    ));
    assert_eq!(dmg::detect(&data), None);
}

#[test]
fn checksum_mismatches_are_errors() {
    let disk = || fat_disk(vec![zlib_chunk(&fat12())]);
    let options = ImageOptions {
        data_fork_crc: true,
        ..ImageOptions::default()
    };
    // A flipped byte in the stored data.
    let mut data = image(&disk(), options);
    data[SECTOR + 40] ^= 0x01;
    assert!(
        parse_error(&data, Layout::Udif).contains("Invalid data fork CRC-32"),
        "{}",
        parse_error(&data, Layout::Udif)
    );
    // A wrong table CRC-32 that the master checksum covers.
    let data = image(
        &disk(),
        ImageOptions {
            wrong_table_crc: Some(0x1234_5678),
            ..ImageOptions::default()
        },
    );
    assert_eq!(
        parse_error(&data, Layout::Udif),
        "Apple disk image parse error: Invalid CRC-32 of Master Boot Record (MBR : 0): stored \
         0x12345678, computed 0x4365969F"
    );
    // A master checksum that does not cover the tables.
    let mut data = image(&disk(), ImageOptions::default());
    let master_at = data.len() - TRAILER + 360;
    data[master_at] ^= 0x80;
    assert!(parse_error(&data, Layout::Udif).contains("Invalid master CRC-32"));
}

#[test]
fn corrupted_trailers_tables_and_chunks_are_errors() {
    let good = image(
        &fat_disk(vec![zlib_chunk(&fat12())]),
        ImageOptions::default(),
    );
    let trailer = good.len() - TRAILER;
    let mutate = |at: usize, bytes: &[u8]| {
        let mut data = good.clone();
        put(&mut data, at, bytes);
        data
    };
    for (data, message) in [
        (
            mutate(trailer + 4, &5u32.to_be_bytes()),
            "Unsupported UDIF trailer version 5",
        ),
        (
            mutate(trailer + 8, &1024u32.to_be_bytes()),
            "Invalid UDIF trailer size 1024 B",
        ),
        (
            mutate(trailer + 32, &(good.len() as u64).to_be_bytes()),
            "Invalid UDIF data fork range 0x0 + ",
        ),
        (mutate(trailer, b"KOLY"), "Missing UDIF trailer signature"),
    ] {
        assert_eq!(dmg::detect(&data), None, "{message}");
        let error = parse_error(&data, Layout::Udif);
        assert!(error.contains(message), "{error}");
    }

    // A table whose signature is `Mish`: base64 `TWlz` for `bWlz`, which
    // keeps the property list's length and offsets.
    let mut data = good.clone();
    let at = data
        .windows(6)
        .position(|w| w == b"bWlzaA")
        .expect("the first table's base64");
    put(&mut data, at, b"TWlz");
    assert_eq!(dmg::detect(&data), Some(Layout::Udif));
    assert_eq!(
        parse_error(&data, Layout::Udif),
        "Apple disk image parse error: Missing block table signature in Master Boot Record \
         (MBR : 0)"
    );

    // An undocumented chunk type: the partition is listed as not decoded.
    let volume = fat12();
    let mut bad_table = fat_disk(vec![zlib_chunk(&volume)]);
    bad_table[1].chunks[0].kind = 0x8000_00ff;
    let data = image(&bad_table, ImageOptions::default());
    let c = parse(&data);
    assert!(
        has_note(
            &c,
            "Not decoded: (DOS_FAT_12 : 1) (unsupported chunk type 0x800000FF)"
        ),
        "{:?}",
        c.notes
    );
    assert!(c.children.is_empty());

    // A zlib chunk that decodes to less than its sectors.
    let mut short = fat_disk(vec![zlib_chunk(&volume)]);
    short[1].chunks[0].stored = miniz_oxide::deflate::compress_to_vec_zlib(&volume[..SECTOR], 9);
    let error = parse_error(&image(&short, ImageOptions::default()), Layout::Udif);
    assert!(
        error.contains("Invalid zlib chunk of (DOS_FAT_12 : 1) at 0x200"),
        "{error}"
    );

    // A raw chunk whose stored length is not its sector count.
    let mut raw = fat_disk(vec![raw_chunk(&volume)]);
    raw[1].chunks[0].stored.truncate(SECTOR);
    let error = parse_error(&image(&raw, ImageOptions::default()), Layout::Udif);
    assert!(
        error.contains("Invalid raw chunk of (DOS_FAT_12 : 1)"),
        "{error}"
    );

    // A chunk offset past the data fork.
    let mut data = image(&fat_disk(vec![raw_chunk(&volume)]), ImageOptions::default());
    let fork_length_at = data.len() - TRAILER + 32;
    let fork_length = be_u64(&data, fork_length_at);
    put(&mut data, fork_length_at, &(fork_length - 1).to_be_bytes());
    let error = parse_error(&data, Layout::Udif);
    assert!(
        error.contains("Truncated chunk of (DOS_FAT_12 : 1) at 0x200"),
        "{error}"
    );
}

#[test]
fn chunks_in_other_segments_leave_the_partition_undecoded() {
    let mut data = image(
        &fat_disk(vec![raw_chunk(&fat12())]),
        ImageOptions::default(),
    );
    let trailer = data.len() - TRAILER;
    // Segment 1 of 2, whose data fork holds only the MBR's chunk.
    put(&mut data, trailer + 32, &(SECTOR as u64).to_be_bytes());
    put(&mut data, trailer + 60, &2u32.to_be_bytes());
    let c = parse(&data);
    assert!(c.children.is_empty());
    assert!(
        has_note(
            &c,
            "Not decoded: (DOS_FAT_12 : 1) (a chunk is in another segment file)"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "Segment 1 of 2: chunks stored in the other segment files"
    ));
    assert_eq!(metadata(&c, "dmg_segment"), "1 of 2");
}

#[test]
fn partitions_beyond_the_extraction_limit_are_cut() {
    // A FAT12 volume stored raw, then 128 MiB of zero fill: the first
    // 64 MiB are decoded, and the CRC-32 cannot be verified.
    let volume = fat12();
    let disk = fat_disk(vec![
        raw_chunk(&volume),
        empty_chunk(CHUNK_ZERO, 256 * 1024),
    ]);
    let data = image(&disk, ImageOptions::default());
    let c = parse(&data);
    let fat = child(&c, "(DOS_FAT_12 : 1)").expect("the first 64 MiB hold the volume");
    assert_eq!(fat.data.len(), 64 << 20);
    assert_eq!(&fat.data[..volume.len()], &volume[..]);
    assert!(
        has_note(
            &c,
            "Only the first bytes were decoded and analyzed (64 MiB per partition"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "(DOS_FAT_12 : 1) (cut at the extraction limit)"
    ));
    assert!(metadata(&c, "dmg_partition_1").ends_with("first 64 MiB decoded"));
}

#[test]
fn layout_notes_report_gaps_and_code_signatures() {
    let mut data = image(
        &fat_disk(vec![raw_chunk(&fat12())]),
        ImageOptions::default(),
    );
    let trailer = data.len() - TRAILER;
    // One sector more than the tables cover, and a code signature pair in
    // the reserved area (7-Zip reads it at 296) naming the first sector.
    let sectors = be_u64(&data, trailer + 492);
    put(&mut data, trailer + 492, &(sectors + 1).to_be_bytes());
    put(&mut data, trailer + 296, &0u64.to_be_bytes());
    put(&mut data, trailer + 304, &(SECTOR as u64).to_be_bytes());
    let c = parse(&data);
    assert!(
        has_note(
            &c,
            "The block tables do not tile the disk: they end at sector 257 of 258"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "A code signature of 512 B is stored at 0x0; not verified"
    ));
    assert_eq!(
        metadata(&c, "dmg_code_signature"),
        "file 0x0; 512 B; not verified"
    );
}

/// Every `.dmg` file under `dir`, recursively.
fn dmg_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            dmg_files(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dmg"))
        {
            out.push(path);
        }
    }
}

#[test]
fn real_images_in_dmg_sample_dir_parse_and_match_their_checksums() {
    // Real disk images cannot be committed; point DMG_SAMPLE_DIR at a
    // directory of them (for example /Library/Developer/DeveloperDiskImages
    // on a Mac with Xcode) to run this test.
    let Some(dir) = std::env::var_os("DMG_SAMPLE_DIR") else {
        eprintln!("DMG_SAMPLE_DIR is not set; skipped");
        return;
    };
    let mut files = Vec::new();
    dmg_files(std::path::Path::new(&dir), &mut files);
    assert!(!files.is_empty(), "no .dmg files under {dir:?}");
    for path in files {
        let data = std::fs::read(&path).expect("readable");
        let Some(layout) = dmg::detect(&data) else {
            // Not every `.dmg` is UDIF: raw and sparse images exist.
            eprintln!("{}: not detected as an Apple disk image", path.display());
            continue;
        };
        let c = dmg::parse_container(&data, layout)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // A parse succeeds only when every CRC-32 that was checked matched.
        eprintln!("{}: {:?}", path.display(), c.notes);
    }
}

#[test]
fn encrypted_version_1_footers_are_opaque() {
    // 4 KiB of "encrypted" data, then the 1276-byte footer: UUID, block
    // size 4096 at 16, and `cdsaencr` at the end.
    let mut data = vec![0xa5u8; 4096];
    let mut footer = vec![0u8; 0x4fc];
    put(&mut footer, 16, &4096u32.to_be_bytes());
    put(&mut footer, 0x4fc - 8, b"cdsaencr");
    data.extend_from_slice(&footer);
    assert_eq!(dmg::detect(&data), Some(Layout::EncryptedV1));
    let c = parse(&data);
    assert!(c.opaque);
    assert!(has_note(
        &c,
        "Encrypted Encoding version 1: 4096 B of data in blocks of 4096 B"
    ));
    assert_eq!(c.children[0].data.len(), 4096);
    assert!(matches!(classify(&data).primary.isa, Isa::Unknown(_)));
}

#[test]
fn encrypted_version_2_headers_must_fit_the_file() {
    let data = fixture("encrypted.dmg");
    let mut bad = data.clone();
    put(&mut bad, 64, &(data.len() as u64).to_be_bytes());
    assert!(parse_error(&bad, Layout::EncryptedV2).contains("Truncated encrypted data"));
    let mut overlap = data.clone();
    put(&mut overlap, 72, &u32::MAX.to_be_bytes());
    assert!(parse_error(&overlap, Layout::EncryptedV2).contains("key protectors overlap"));
}

// ---------------------------------------------------------------------
// Sweeps
// ---------------------------------------------------------------------

/// An image for the sweeps and how densely it is mutated.
struct SweepImage {
    data: Vec<u8>,
    density: Density,
}

/// Every fixture, and two synthetic images (an XML property list with
/// mixed chunks and a data fork CRC-32, and a resource fork).
fn sweep_images() -> Vec<SweepImage> {
    let sparse = |data| SweepImage {
        data,
        density: SPARSE,
    };
    let mut images: Vec<SweepImage> = HFS_IMAGES
        .iter()
        .map(|image| sparse(fixture(image.name)))
        .collect();
    images.push(sparse(fixture("fat-udzo.dmg")));
    images.push(sparse(fixture("segmented.dmg")));
    images.push(sparse(fixture("segmented.002.dmgpart")));
    images.push(sparse(fixture("encrypted.dmg")));
    let volume = fat12();
    for options in [
        ImageOptions {
            data_fork_crc: true,
            ..ImageOptions::default()
        },
        ImageOptions {
            resource_fork: true,
            data_fork_crc: true,
            ..ImageOptions::default()
        },
    ] {
        let disk = fat_disk(vec![
            zlib_chunk(&volume[..64 * SECTOR]),
            raw_chunk(&volume[64 * SECTOR..]),
            empty_chunk(CHUNK_IGNORE, 2),
        ]);
        images.push(SweepImage {
            data: image(&disk, options),
            density: DENSE,
        });
    }
    images
}

#[test]
fn truncated_images_are_not_claimed_or_fail_to_parse() {
    for SweepImage { data, .. } in sweep_images() {
        let full = parse(&data);
        for end in 0..data.len() {
            let prefix = &data[..end];
            if let Some(layout) = dmg::detect(prefix) {
                // Only an encrypted header at offset 0 survives a cut; its
                // data must then be missing.
                assert_eq!(
                    layout,
                    Layout::EncryptedV2,
                    "prefix {end} of {}",
                    full.variant
                );
                assert!(
                    dmg::parse_container(prefix, layout).is_err(),
                    "prefix {end}"
                );
            }
        }
    }
}

/// How densely an image is mutated: every `trailer_step`th byte of the
/// trailer, every `metadata_step`th byte of the property list or resource
/// fork, and `fork_points` positions spread over the data fork.
#[derive(Clone, Copy)]
struct Density {
    trailer_step: usize,
    metadata_step: usize,
    fork_points: usize,
}

/// Each hdiutil image decodes a 1 MiB disk on every parse, so it is
/// mutated sparsely; the small synthetic image densely.
const SPARSE: Density = Density {
    trailer_step: 4,
    metadata_step: 64,
    fork_points: 16,
};
const DENSE: Density = Density {
    trailer_step: 1,
    metadata_step: 4,
    fork_points: 128,
};

fn mutation_points(data: &[u8], density: Density) -> Vec<usize> {
    let len = data.len();
    let trailer = len - TRAILER;
    let mut points: Vec<usize> = (trailer..len).step_by(density.trailer_step).collect();
    let xml_at = be_u64(data, trailer + 216) as usize;
    let rsrc_at = be_u64(data, trailer + 40) as usize;
    let metadata_at = if xml_at > 0 { xml_at } else { rsrc_at };
    points.extend((metadata_at..trailer).step_by(density.metadata_step));
    points.extend((0..metadata_at).step_by((metadata_at / density.fork_points).max(1)));
    points
}

#[test]
fn byte_mutations_never_panic() {
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xff, |b| b ^ 0x01];
    for SweepImage { mut data, density } in sweep_images() {
        let points = if data.starts_with(b"encrcdsa") {
            (0..1024).collect()
        } else {
            mutation_points(&data, density)
        };
        for at in points {
            let original = data[at];
            for mutate in mutations {
                data[at] = mutate(original);
                if let Some(layout) = dmg::detect(&data) {
                    let _ = dmg::parse_container(&data, layout);
                }
            }
            data[at] = original;
        }
        // The full classification on a sample of trailer mutations.
        let trailer = data.len() - TRAILER;
        for at in (trailer..data.len()).step_by(64) {
            data[at] ^= 0x80;
            let _ = detect_payload(&data, &ClassifierOptions::new());
            data[at] ^= 0x80;
        }
    }
}

#[test]
fn deterministic_noise_is_not_an_apple_disk_image() {
    let mut x: u32 = 0x9e37_79b9;
    let mut noise: Vec<u8> = (0..65536)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    for end in [0, 7, 512, 1276, 4096, noise.len()] {
        assert_eq!(dmg::detect(&noise[..end]), None, "{end}");
        let _ = dmg::parse_container(&noise[..end], Layout::Udif);
        let _ = dmg::parse_container(&noise[..end], Layout::EncryptedV1);
    }
    // A trailer at the end of noise: the forks do not fit or the property
    // list is not where it says.
    let len = noise.len();
    put(&mut noise, len - TRAILER, b"koly\0\0\0\x04\0\0\x02\0");
    assert_eq!(dmg::detect(&noise), None);
    let _ = dmg::parse_container(&noise, Layout::Udif);
}
