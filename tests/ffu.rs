//! Microsoft Full Flash Update images: synthetic V1 and V2 FFUs built from
//! the documented layout (Microsoft "FFU image format", in img2ffu's write
//! order) around a GPT disk whose FAT12 partition is the volume of
//! `tests/fixtures/fat/fat12.img`, write-descriptor placement from the
//! start and the end of the disk, device targeting entries, chunk hashes,
//! corrupted fields, and truncation and mutation sweeps.

use sha2::{Digest, Sha256};
use zrax::formats::checksum::{crc32, Sha1};
use zrax::formats::container::{Child, Classify, Container};
use zrax::formats::ffu::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat, MAX_PAYLOAD};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Bytes of a 512-byte sector.
const SECTOR: usize = 512;

/// Block and chunk size of the synthetic images: 4 KiB, equal as img2ffu
/// writes them.
const BLOCK: usize = 4096;
const CHUNK_KIB: u32 = 4;

/// `dwAlgId` values (Microsoft Learn "ALG_ID").
const CALG_SHA_256: u32 = 0x800C;
const CALG_SHA1: u32 = 0x8004;

/// `DISK_ACCESS_METHOD` values.
const DISK_BEGIN: u32 = 0;
const DISK_END: u32 = 2;

/// `STORE_HEADER_V1_0_SIZE`, and the V2 fields that follow it before the
/// device path.
const STORE_HEADER_SIZE: usize = 248;
const STORE_V2_FIELDS_SIZE: usize = 14;

/// The synthetic GPT disk: 320 sectors (160 KiB, 40 blocks), with the FAT12
/// volume as its one partition from LBA 8.
const DISK_SECTORS: usize = 320;
const FAT_FIRST_LBA: usize = 8;

const EFI_SYSTEM: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const DISK_GUID: &str = "5A524158-4646-5544-4953-4B0000000001";

const ISA_NOTE: &str = "FFU images name no ISA; each store's disk is classified on its own";

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// `tests/fixtures/fat/fat12.img` (README.md there): a 128 KiB FAT12
/// volume whose `/payload.elf` is a synthetic x86-64 ELF header.
fn fat12() -> Vec<u8> {
    fixture("fat/fat12.img")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// Detect and parse an image that must be valid.
fn parse(data: &[u8]) -> Container<'_> {
    let layout = ffu::detect(data).expect("detected as an FFU");
    ffu::parse_container(data, layout).expect("parses")
}

/// The error text of an image that does not parse.
fn parse_error(data: &[u8]) -> String {
    ffu::parse_container(data, Layout::Ffu)
        .expect_err("does not parse")
        .to_string()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("child {label}: {:?}", c.notes))
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn payload_has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|note| note.message.contains(text))
}

fn metadata(c: &Container<'_>, key: &str) -> String {
    c.metadata()
        .into_iter()
        .find(|entry| format!("{:?}", entry.key).contains(&format!("\"{key}\"")))
        .map(|entry| entry.value.to_string())
        .unwrap_or_else(|| panic!("metadata {key}"))
}

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    put(data, at, &value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    put(data, at, &value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    put(data, at, &value.to_le_bytes());
}

/// `bytes` padded with zeros to a multiple of `unit`.
fn pad(bytes: &mut Vec<u8>, unit: usize) {
    let len = bytes.len().div_euclid(unit) * unit;
    if len != bytes.len() {
        bytes.resize(len + unit, 0);
    }
}

// ---------------------------------------------------------------------------
// GPT disk builder (UEFI 2.10, section 5.3: Tables 5.5 and 5.6)
// ---------------------------------------------------------------------------

/// `EFI_GUID` bytes of a text GUID: the first three fields little-endian.
fn guid(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let bytes: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&[bytes[3], bytes[2], bytes[1], bytes[0]]);
    out[4..6].copy_from_slice(&[bytes[5], bytes[4]]);
    out[6..8].copy_from_slice(&[bytes[7], bytes[6]]);
    out[8..].copy_from_slice(&bytes[8..]);
    out
}

/// The entry array: four 128-byte entries (one sector). Entry 0 is the EFI
/// system partition "EFIESP" over `first..=last`: type GUID (0), unique GUID
/// (16), first and last LBA (32, 40), attributes (48), UTF-16LE name (56).
fn gpt_array(first: u64, last: u64) -> Vec<u8> {
    let mut array = vec![0u8; 4 * 128];
    put(&mut array, 0, &guid(EFI_SYSTEM));
    put(
        &mut array,
        16,
        &guid("5A524158-0000-4000-8000-000000000001"),
    );
    put64(&mut array, 32, first);
    put64(&mut array, 40, last);
    for (i, unit) in "EFIESP".encode_utf16().enumerate() {
        put16(&mut array, 56 + 2 * i, unit);
    }
    array
}

/// A 92-byte GPT header at `lba` for a disk of `sectors`: signature,
/// revision 1.0, header size 92, header CRC (16), MyLBA (24), AlternateLBA
/// (32), usable LBAs 3 to `sectors - 3` (40, 48), disk GUID (56), entry
/// array LBA (72), 4 entries (80) of 128 B (84) and the array CRC (88).
fn gpt_header(lba: u64, alternate: u64, entry_lba: u64, sectors: u64, array: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; SECTOR];
    put(&mut header, 0, b"EFI PART");
    put32(&mut header, 8, 0x0001_0000);
    put32(&mut header, 12, 92);
    put64(&mut header, 24, lba);
    put64(&mut header, 32, alternate);
    put64(&mut header, 40, 3);
    put64(&mut header, 48, sectors - 3);
    put(&mut header, 56, &guid(DISK_GUID));
    put64(&mut header, 72, entry_lba);
    put32(&mut header, 80, 4);
    put32(&mut header, 84, 128);
    put32(&mut header, 88, crc32(array));
    let crc = crc32(&header[..92]);
    put32(&mut header, 16, crc);
    header
}

/// The GPT disk: a protective MBR (one type 0xEE record from LBA 1 over
/// the rest of the disk, signature `55 AA`), the primary header at LBA 1
/// and its array at LBA 2, `partition` from [`FAT_FIRST_LBA`], and the
/// backup array and header in the last two sectors.
fn gpt_disk(partition: &[u8]) -> Vec<u8> {
    let sectors = DISK_SECTORS as u64;
    let mut disk = vec![0u8; DISK_SECTORS * SECTOR];
    disk[446 + 4] = 0xEE;
    put32(&mut disk, 446 + 8, 1);
    put32(&mut disk, 446 + 12, (sectors - 1) as u32);
    put(&mut disk, 510, &[0x55, 0xAA]);
    let first = FAT_FIRST_LBA as u64;
    let last = first + (partition.len() / SECTOR) as u64 - 1;
    let array = gpt_array(first, last);
    put(&mut disk, 2 * SECTOR, &array);
    put(&mut disk, (DISK_SECTORS - 2) * SECTOR, &array);
    put(
        &mut disk,
        SECTOR,
        &gpt_header(1, sectors - 1, 2, sectors, &array),
    );
    put(
        &mut disk,
        (DISK_SECTORS - 1) * SECTOR,
        &gpt_header(sectors - 1, 1, sectors - 2, sectors, &array),
    );
    put(&mut disk, FAT_FIRST_LBA * SECTOR, partition);
    disk
}

fn fat_disk() -> Vec<u8> {
    gpt_disk(&fat12())
}

// ---------------------------------------------------------------------------
// FFU builder (Microsoft "FFU image format"; img2ffu `Writer/FFUFactory.cs`)
// ---------------------------------------------------------------------------

/// A `DISK_LOCATION`: access method and block index.
#[derive(Debug, Clone, Copy)]
struct Location {
    method: u32,
    block: u32,
}

fn begin(block: u32) -> Location {
    Location {
        method: DISK_BEGIN,
        block,
    }
}

fn from_end(block: u32) -> Location {
    Location {
        method: DISK_END,
        block,
    }
}

/// A write descriptor (`BLOCK_DATA_ENTRY`) and the payload blocks it
/// writes: `dwBlockCount` is `blocks.len() / block size`.
#[derive(Debug, Clone)]
struct Write {
    blocks: Vec<u8>,
    locations: Vec<Location>,
}

/// A `VALIDATION_ENTRY`: sector index, sector offset and compare data.
#[derive(Debug, Clone)]
struct Validation {
    sector: u32,
    offset: u32,
    data: Vec<u8>,
}

/// One store.
#[derive(Debug, Clone)]
struct StoreSpec {
    /// `dwBlockSizeInBytes`.
    block_size: usize,
    writes: Vec<Write>,
    validations: Vec<Validation>,
    /// `DevicePath` (V2 only).
    device_path: &'static str,
}

/// A whole image.
#[derive(Debug, Clone)]
struct Spec {
    /// `MajorVersion` of every store header: 1 (V1) or 2 (V2).
    store_version: u16,
    /// `dwChunkSizeInKb`, also written as the image header's chunk size.
    chunk_kib: u32,
    /// `dwAlgId`.
    algorithm: u32,
    /// The bytes standing in for the signed catalog.
    catalog: Vec<u8>,
    manifest: String,
    stores: Vec<StoreSpec>,
}

/// A built image and the offsets of its parts.
#[derive(Debug, Clone)]
struct Built {
    file: Vec<u8>,
    image_offset: usize,
    store_offsets: Vec<usize>,
    payload_offset: usize,
}

/// The write descriptors img2ffu writes for a disk (`BlockPayloadsGenerator`
/// `GetGPTPayloads`): an empty block over both GPTs (block 0 and the last
/// block from the end), the primary GPT block, every other non-empty block
/// in order, the primary GPT block again and the backup GPT block from the
/// end.
fn img2ffu_writes(disk: &[u8], block_size: usize) -> Vec<Write> {
    let blocks: Vec<&[u8]> = disk.chunks(block_size).collect();
    let last = blocks.len() - 1;
    let mut writes = vec![
        Write {
            blocks: vec![0; block_size],
            locations: vec![begin(0), from_end(0)],
        },
        Write {
            blocks: blocks[0].to_vec(),
            locations: vec![begin(0)],
        },
    ];
    for (i, block) in blocks.iter().enumerate().take(last).skip(1) {
        if block.iter().any(|&b| b != 0) {
            writes.push(Write {
                blocks: block.to_vec(),
                locations: vec![begin(i as u32)],
            });
        }
    }
    writes.push(Write {
        blocks: blocks[0].to_vec(),
        locations: vec![begin(0)],
    });
    writes.push(Write {
        blocks: blocks[last].to_vec(),
        locations: vec![from_end(0)],
    });
    writes
}

/// An img2ffu-style manifest: `[FullFlash]`, then per store `[Store]` with
/// `IsMainOSStore`, `MinSectorCount` (left out when `None`) and
/// `SectorSize`, and its `[Partition]` sections.
fn manifest(stores: &[ManifestStore]) -> String {
    let mut text = String::from(
        "[FullFlash]\r\nOSVersion         = 10.0.26100.1\r\nVersion           = 2.0\r\n\
         DevicePlatformId0 = Zrax.Test.Platform\r\n\r\n[StoragePool]\r\nName = OSPool\r\n\r\n",
    );
    for store in stores {
        text.push_str("[Store]\r\n");
        text.push_str(&format!(
            "IsMainOSStore                 = {}\r\n",
            if store.main_os { "True" } else { "False" }
        ));
        if let Some(sectors) = store.sectors {
            text.push_str(&format!("MinSectorCount                = {sectors}\r\n"));
        }
        text.push_str("SectorSize                    = 512\r\n\r\n");
        for partition in store.partitions {
            text.push_str(&format!(
                "[Partition]\r\nName            = {}\r\nType            = {{{EFI_SYSTEM}}}\r\n\
                 TotalSectors    = {}\r\nFileSystem      = FAT\r\n\r\n",
                partition.name, partition.sectors
            ));
        }
    }
    text
}

/// One `[Store]` section of [`manifest`].
struct ManifestStore {
    main_os: bool,
    /// `MinSectorCount`.
    sectors: Option<usize>,
    partitions: &'static [ManifestPartition],
}

/// One `[Partition]` section: `Name` and `TotalSectors`.
struct ManifestPartition {
    name: &'static str,
    sectors: usize,
}

/// The FAT partition of the GPT disk.
const EFIESP: ManifestPartition = ManifestPartition {
    name: "EFIESP",
    sectors: 256,
};

/// The store header (248 B), with the V2 fields and the UTF-16LE device
/// path after it when `spec.store_version` is 2: update type 0, versions
/// (4-10), platform ID (12), block size (204), write descriptor count and
/// length (208, 212), validation count and length (216, 220), and the
/// initial, flash-only and final GPT tables (224-247).
fn store_header(spec: &Spec, i: usize, writes: &[u8], validations: &[u8], payload: u64) -> Vec<u8> {
    let store = &spec.stores[i];
    let mut header = vec![0u8; STORE_HEADER_SIZE];
    put16(&mut header, 4, spec.store_version);
    put16(&mut header, 8, 2);
    put(&mut header, 12, b"Zrax.Test.Platform\0Zrax.Other");
    put32(&mut header, 204, store.block_size as u32);
    put32(&mut header, 208, store.writes.len() as u32);
    put32(&mut header, 212, writes.len() as u32);
    put32(&mut header, 216, store.validations.len() as u32);
    put32(&mut header, 220, validations.len() as u32);
    put32(&mut header, 228, 1);
    put32(&mut header, 236, 1);
    put32(
        &mut header,
        240,
        (store.writes.len() as u32).saturating_sub(1),
    );
    put32(&mut header, 244, 1);
    if spec.store_version == 2 {
        let mut v2 = vec![0u8; STORE_V2_FIELDS_SIZE];
        put16(&mut v2, 0, spec.stores.len() as u16);
        put16(&mut v2, 2, i as u16 + 1);
        put64(&mut v2, 4, payload);
        let path: Vec<u16> = store.device_path.encode_utf16().collect();
        put16(&mut v2, 12, path.len() as u16);
        header.extend_from_slice(&v2);
        for unit in path {
            header.extend_from_slice(&unit.to_le_bytes());
        }
    }
    header
}

/// The write descriptor region: per descriptor its location count, block
/// count and locations.
fn write_descriptors(store: &StoreSpec) -> Vec<u8> {
    let mut bytes = Vec::new();
    for write in &store.writes {
        bytes.extend_from_slice(&(write.locations.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&((write.blocks.len() / store.block_size) as u32).to_le_bytes());
        for location in &write.locations {
            bytes.extend_from_slice(&location.method.to_le_bytes());
            bytes.extend_from_slice(&location.block.to_le_bytes());
        }
    }
    bytes
}

/// The validation region: per entry its sector index, sector offset, byte
/// count and compare data.
fn validation_entries(store: &StoreSpec) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in &store.validations {
        bytes.extend_from_slice(&entry.sector.to_le_bytes());
        bytes.extend_from_slice(&entry.offset.to_le_bytes());
        bytes.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&entry.data);
    }
    bytes
}

/// One digest per chunk of `region`: SHA-256 or SHA-1 for those
/// algorithms, 32 zero bytes otherwise.
fn hash_table(region: &[u8], chunk: usize, algorithm: u32) -> Vec<u8> {
    let mut table = Vec::new();
    for piece in region.chunks(chunk) {
        match algorithm {
            CALG_SHA_256 => table.extend_from_slice(&Sha256::digest(piece)),
            CALG_SHA1 => {
                let mut sha1 = Sha1::new();
                sha1.update(piece);
                table.extend_from_slice(&sha1.finish());
            }
            _ => table.extend_from_slice(&[0u8; 32]),
        }
    }
    table
}

/// Build an image in the documented order: the security header (`cbSize`
/// 32, `SignedImage `, chunk size, algorithm, catalog and hash table sizes),
/// catalog and hash table, padded to a chunk; the image header (24 B,
/// `ImageFlash  `, manifest length, chunk size) and manifest, padded to a
/// chunk; each store header with its validation entries and write
/// descriptors, padded to its block size; then the payloads in store
/// order. The image header starts on a chunk boundary, and every block size
/// divides the chunk size, so padding to a block boundary of the image
/// region is padding to one of the file.
fn build(spec: &Spec) -> Built {
    let chunk = spec.chunk_kib as usize * 1024;
    let mut image = vec![0u8; 24];
    put32(&mut image, 0, 24);
    put(&mut image, 4, b"ImageFlash  ");
    put32(&mut image, 16, spec.manifest.len() as u32);
    put32(&mut image, 20, spec.chunk_kib);
    image.extend_from_slice(spec.manifest.as_bytes());
    pad(&mut image, chunk);
    let mut store_offsets = Vec::new();
    for (i, store) in spec.stores.iter().enumerate() {
        assert_eq!(
            chunk % store.block_size,
            0,
            "block size divides the chunk size"
        );
        let writes = write_descriptors(store);
        let validations = validation_entries(store);
        let payload: usize = store.writes.iter().map(|w| w.blocks.len()).sum();
        store_offsets.push(image.len());
        image.extend(store_header(spec, i, &writes, &validations, payload as u64));
        image.extend(validations);
        image.extend(writes);
        pad(&mut image, store.block_size);
    }
    let payload_offset = image.len();
    for store in &spec.stores {
        for write in &store.writes {
            image.extend_from_slice(&write.blocks);
        }
    }
    let table = hash_table(&image, chunk, spec.algorithm);
    let mut file = vec![0u8; 32];
    put32(&mut file, 0, 32);
    put(&mut file, 4, b"SignedImage ");
    put32(&mut file, 16, spec.chunk_kib);
    put32(&mut file, 20, spec.algorithm);
    put32(&mut file, 24, spec.catalog.len() as u32);
    put32(&mut file, 28, table.len() as u32);
    file.extend_from_slice(&spec.catalog);
    file.extend_from_slice(&table);
    pad(&mut file, chunk);
    let image_offset = file.len();
    file.extend(image);
    Built {
        file,
        image_offset,
        store_offsets: store_offsets.iter().map(|at| at + image_offset).collect(),
        payload_offset: payload_offset + image_offset,
    }
}

/// Recompute the hash table of `built` after a change behind the security
/// region, so that the change reaches the later checks.
fn rehash(built: &mut Built) {
    let file = &mut built.file;
    let chunk = u32::from_le_bytes(file[16..20].try_into().unwrap()) as usize * 1024;
    let algorithm = u32::from_le_bytes(file[20..24].try_into().unwrap());
    let catalog = u32::from_le_bytes(file[24..28].try_into().unwrap()) as usize;
    let table = hash_table(&file[built.image_offset..], chunk, algorithm);
    put(file, 32 + catalog, &table);
}

/// The catalog stand-in: a DER SEQUENCE header and filler, not a real
/// signature.
fn catalog() -> Vec<u8> {
    let mut catalog = vec![0x30, 0x82, 0x00, 0x3C];
    catalog.resize(64, 0x5A);
    catalog
}

/// A V1 image of the FAT GPT disk, as img2ffu writes it, with the manifest
/// giving the 320-sector disk.
fn v1_spec() -> Spec {
    Spec {
        store_version: 1,
        chunk_kib: CHUNK_KIB,
        algorithm: CALG_SHA_256,
        catalog: catalog(),
        manifest: manifest(&[ManifestStore {
            main_os: true,
            sectors: Some(DISK_SECTORS),
            partitions: &[EFIESP],
        }]),
        stores: vec![StoreSpec {
            block_size: BLOCK,
            writes: img2ffu_writes(&fat_disk(), BLOCK),
            validations: Vec::new(),
            device_path: "",
        }],
    }
}

fn v1_image() -> Built {
    build(&v1_spec())
}

/// `tests/fixtures/compressed/payload.elf` with `e_machine` (at 18) set to
/// AArch64 (183): an ELF header standing in for a second store's disk.
fn aarch64_elf_block() -> Vec<u8> {
    let mut elf = fixture("compressed/payload.elf");
    put16(&mut elf, 18, 183);
    elf.resize(BLOCK, 0);
    elf
}

/// A V2 image: store 1 is a one-block disk that holds an AArch64 ELF
/// header (not the main OS store), store 2 the FAT GPT disk, which the
/// manifest marks as the main OS store.
fn v2_spec() -> Spec {
    Spec {
        store_version: 2,
        manifest: manifest(&[
            ManifestStore {
                main_os: false,
                sectors: Some(BLOCK / SECTOR),
                partitions: &[],
            },
            ManifestStore {
                main_os: true,
                sectors: Some(DISK_SECTORS),
                partitions: &[EFIESP],
            },
        ]),
        stores: vec![
            StoreSpec {
                block_size: BLOCK,
                writes: vec![Write {
                    blocks: aarch64_elf_block(),
                    locations: vec![begin(0)],
                }],
                validations: Vec::new(),
                device_path: "VenHw(860845C1-BE09-4355-8BC1-30D64FF8E63A)",
            },
            StoreSpec {
                block_size: BLOCK,
                writes: img2ffu_writes(&fat_disk(), BLOCK),
                validations: Vec::new(),
                device_path: "PciRoot(0x0)/Pci(0x1D,0x0)",
            },
        ],
        ..v1_spec()
    }
}

// ---------------------------------------------------------------------------
// V1 and V2 images
// ---------------------------------------------------------------------------

#[test]
fn v1_image_assembles_the_gpt_disk_whose_fat_partition_holds_the_elf() {
    let built = v1_image();
    let data = &built.file;
    assert_eq!(ffu::detect(data), Some(Layout::Ffu));
    assert!(matches!(
        detect_format(data),
        DetectedFormat::Container { kind } if kind.format() == FileFormat::Ffu
    ));
    let c = parse(data);
    assert_eq!(c.format, FileFormat::Ffu);
    assert_eq!(c.variant, "FFU v1");
    assert!(c.target.is_none(), "an FFU names no ISA");
    assert_eq!(c.children.len(), 1, "{:?}", c.notes);
    let disk = child(&c, "Store 1 disk");
    assert_eq!(&disk.data[..], &fat_disk()[..], "the assembled disk");
    assert_eq!(disk.transform, Some("FFU blocks"));
    assert_eq!(disk.offset, built.payload_offset);
    assert_eq!(disk.stored_size, data.len() - built.payload_offset);
    assert_eq!(disk.classify, Classify::IfRecognized);
    assert!(has_note(&c, "FFU v1: 1 store; 4 KiB chunks; payload of"));
    let spec = v1_spec();
    let block_writes: usize = spec.stores[0]
        .writes
        .iter()
        .map(|write| write.locations.len() * write.blocks.len() / BLOCK)
        .sum();
    assert!(has_note(
        &c,
        &format!(
            "Store 1 disk assembled from {block_writes} block writes, 2 from the end of the \
             disk: 160 KiB; disk size 160 KiB from the manifest (320 sectors of 512 B)"
        )
    ));
    assert!(has_note(
        &c,
        "Store 1 platform ID: Zrax.Test.Platform, Zrax.Other"
    ));
    assert!(has_note(
        &c,
        &format!(
            "Manifest: {} B; manifest version 2.0; OS version 10.0.26100.1; device platform \
             Zrax.Test.Platform; 1 store section; 1 partition: EFIESP",
            spec.manifest.len()
        )
    ));
    assert!(has_note(
        &c,
        "Signed security catalog: 64 B at 0x20; its signature is not verified"
    ));
    assert!(has_note(&c, "Chunk hashes: the SHA-256 of all"));
    assert!(has_note(&c, ISA_NOTE));
    assert_eq!(metadata(&c, "ffu_chunk_hashes"), "match");
    assert_eq!(metadata(&c, "ffu_store_1_disk_size"), "163840");
    assert_eq!(
        metadata(&c, "ffu_partition_0"),
        format!("EFIESP; type {{{EFI_SYSTEM}}}; 256 sectors; filesystem FAT")
    );

    let p = classify(data);
    assert_eq!(p.format.format, FileFormat::Ffu);
    assert_eq!(p.format.variant_name.as_deref(), Some("FFU image"));
    assert_eq!(
        p.primary.isa,
        Isa::X86_64,
        "from the ELF in the GPT disk's FAT partition"
    );
    let slice = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Store 1 disk"))
        .expect("disk slice");
    assert_eq!(slice.isa, Isa::X86_64);
    assert_eq!(slice.offset, built.payload_offset as u64);
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "FFU blocks");
    assert_eq!(decoded.size, (DISK_SECTORS * SECTOR) as u64);
    assert!(payload_has_note(
        &p,
        "Primary ISA selected from Store 1 disk"
    ));
}

#[test]
fn json_format_id_is_ffu() {
    assert_eq!(serde_json::to_value(FileFormat::Ffu).unwrap(), "ffu");
    assert_eq!(FileFormat::Ffu.to_string(), "Full Flash Update image");
}

#[test]
fn v2_image_lists_one_disk_per_store_with_the_main_os_store_first() {
    let built = build(&v2_spec());
    let c = parse(&built.file);
    assert_eq!(c.variant, "FFU v2");
    let labels: Vec<&str> = c
        .children
        .iter()
        .map(|child| child.label.as_str())
        .collect();
    assert_eq!(labels, ["Store 2 disk", "Store 1 disk"]);
    assert!(has_note(
        &c,
        "Store 2 is the main OS store (manifest `IsMainOSStore`), so its disk is listed first"
    ));
    assert!(has_note(
        &c,
        "Store 1 of 2: device path VenHw(860845C1-BE09-4355-8BC1-30D64FF8E63A)"
    ));
    assert!(has_note(
        &c,
        "Store 2 of 2: device path PciRoot(0x0)/Pci(0x1D,0x0)"
    ));
    assert_eq!(
        &child(&c, "Store 1 disk").data[..],
        &aarch64_elf_block()[..]
    );
    assert_eq!(&child(&c, "Store 2 disk").data[..], &fat_disk()[..]);
    // Store 1's payload is its one block, store 2's follows it.
    assert_eq!(child(&c, "Store 1 disk").offset, built.payload_offset);
    assert_eq!(child(&c, "Store 1 disk").stored_size, BLOCK);
    assert_eq!(
        child(&c, "Store 2 disk").offset,
        built.payload_offset + BLOCK
    );
    assert_eq!(metadata(&c, "ffu_store_count"), "2");
    assert_eq!(
        metadata(&c, "ffu_store_2_device_path"),
        "PciRoot(0x0)/Pci(0x1D,0x0)"
    );

    let p = classify(&built.file);
    assert_eq!(p.primary.isa, Isa::X86_64, "from the main OS store");
    let isa = |label: &str| {
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .map(|s| s.isa)
    };
    assert_eq!(isa("Store 1 disk"), Some(Isa::AArch64));
    assert_eq!(isa("Store 2 disk"), Some(Isa::X86_64));
}

#[test]
fn v2_store_counts_and_indices_must_agree() {
    let built = build(&v2_spec());
    let second = built.store_offsets[1];
    let mut data = built.file.clone();
    put16(&mut data, second + STORE_HEADER_SIZE, 3);
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Invalid store count 3 at 0x{:X}: store 1 gives 2",
            second + STORE_HEADER_SIZE
        )
    );
    let mut data = built.file.clone();
    put16(&mut data, second + STORE_HEADER_SIZE + 2, 1);
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Invalid store index 1 at 0x{:X}: store 2 expected",
            second + STORE_HEADER_SIZE + 2
        )
    );
    let mut data = built.file.clone();
    put16(&mut data, built.store_offsets[0] + STORE_HEADER_SIZE, 0);
    assert!(parse_error(&data).contains("Invalid store count 0"));
    // A V1 header after a V2 one.
    let mut data = built.file.clone();
    put16(&mut data, second + 4, 1);
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Invalid store 2 header version 1.0 at 0x{:X}: it follows a \
             V2 store",
            second + 4
        )
    );
    // A payload size field that disagrees with the descriptors is noted.
    let mut data = built.file;
    put64(&mut data, second + STORE_HEADER_SIZE + 4, 1);
    let c = parse(&data);
    assert!(has_note(
        &c,
        "Store 2 payload size field says 1 B; its write descriptors place"
    ));
}

// ---------------------------------------------------------------------------
// Write descriptor placement
// ---------------------------------------------------------------------------

/// A block of `byte`.
fn filled(byte: u8, blocks: usize) -> Vec<u8> {
    vec![byte; blocks * BLOCK]
}

/// A V1 image of one store with `writes` and a manifest that gives
/// `sectors` (or no size).
fn placement_image(writes: Vec<Write>, sectors: Option<usize>) -> Built {
    build(&Spec {
        manifest: manifest(&[ManifestStore {
            main_os: false,
            sectors,
            partitions: &[],
        }]),
        stores: vec![StoreSpec {
            block_size: BLOCK,
            writes,
            validations: Vec::new(),
            device_path: "",
        }],
        ..v1_spec()
    })
}

#[test]
fn later_writes_replace_earlier_ones_and_runs_fill_consecutive_blocks() {
    let built = placement_image(
        vec![
            // Three blocks of 0xA1 to blocks 1-3 and 10-12.
            Write {
                blocks: filled(0xA1, 3),
                locations: vec![begin(1), begin(10)],
            },
            // One block of 0xB2 over block 2.
            Write {
                blocks: filled(0xB2, 1),
                locations: vec![begin(2)],
            },
            // Two blocks of 0xC3 ending at the last block of the disk.
            Write {
                blocks: filled(0xC3, 2),
                locations: vec![from_end(1)],
            },
        ],
        Some(16 * BLOCK / SECTOR),
    );
    let c = parse(&built.file);
    let disk = &child(&c, "Store 1 disk").data;
    assert_eq!(disk.len(), 16 * BLOCK);
    let block = |i: usize| disk[i * BLOCK];
    let blocks: Vec<u8> = (0..16).map(block).collect();
    assert_eq!(
        blocks,
        [0, 0xA1, 0xB2, 0xA1, 0, 0, 0, 0, 0, 0, 0xA1, 0xA1, 0xA1, 0, 0xC3, 0xC3]
    );
    assert!(has_note(
        &c,
        "Store 1 disk does not start with a recognized format"
    ));
    assert!(has_note(
        &c,
        "Store 1 disk assembled from 9 block writes, 2 from the end of the disk: 64 KiB"
    ));
    // Not a recognized format: the disk is not classified or listed.
    let p = classify(&built.file);
    assert!(p.slices.is_empty(), "{:?}", p.slices);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn blocks_from_the_end_need_the_manifest_disk_size() {
    let mut spec = v1_spec();
    spec.manifest = manifest(&[ManifestStore {
        main_os: true,
        sectors: None,
        partitions: &[EFIESP],
    }]);
    let built = build(&spec);
    let c = parse(&built.file);
    assert!(has_note(
        &c,
        "Store 1: 2 blocks written back from the end of the disk were skipped, because the \
         manifest gives no disk size"
    ));
    assert!(has_note(
        &c,
        "no disk size in the manifest, so the disk ends with the last block written from its \
         start"
    ));
    // The disk ends with the last FAT block; the backup GPT is missing.
    let disk = &child(&c, "Store 1 disk").data;
    let fat_end = (FAT_FIRST_LBA * SECTOR + fat12().len()).div_euclid(BLOCK) * BLOCK;
    assert!(disk.len() <= fat_end + BLOCK);
    assert_eq!(&disk[..], &fat_disk()[..disk.len()]);
    // The disk is still a GPT disk, but its FAT partition is cut after the
    // last block written, so it yields no ISA.
    let p = classify(&built.file);
    assert_eq!(p.slices.len(), 1, "{:?}", p.slices);
    let variant = p.slices[0].variant.as_ref().map(|v| v.name.as_str());
    assert_eq!(variant, Some("GPT"));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn write_descriptors_must_stay_inside_the_manifest_disk() {
    let beyond = placement_image(
        vec![Write {
            blocks: filled(1, 1),
            locations: vec![begin(8)],
        }],
        Some(8 * BLOCK / SECTOR),
    );
    assert_eq!(
        parse_error(&beyond.file),
        "FFU image parse error: Invalid store 1 write descriptors: blocks from the start of the \
         disk reach 36864 B, beyond the 32768 B disk of the manifest"
    );
    let before_start = placement_image(
        vec![Write {
            blocks: filled(1, 1),
            locations: vec![from_end(8)],
        }],
        Some(8 * BLOCK / SECTOR),
    );
    assert!(parse_error(&before_start.file).contains("blocks from the end of the disk reach back"));
    let past_end = placement_image(
        vec![Write {
            blocks: filled(1, 2),
            locations: vec![from_end(0)],
        }],
        Some(8 * BLOCK / SECTOR),
    );
    assert!(parse_error(&past_end.file).contains("run past the end of the disk"));
    let mut sequential = placement_image(
        vec![Write {
            blocks: filled(1, 1),
            locations: vec![begin(0)],
        }],
        None,
    );
    let at = sequential.store_offsets[0] + STORE_HEADER_SIZE + 8;
    put32(&mut sequential.file, at, 1);
    assert_eq!(
        parse_error(&sequential.file),
        format!(
            "FFU image parse error: Unsupported disk access method 1 in store 1 write \
             descriptor 0 at 0x{:X}",
            at - 8
        )
    );
}

#[test]
fn stores_without_blocks_have_no_disk() {
    let built = placement_image(Vec::new(), Some(64));
    let c = parse(&built.file);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "Store 1 writes no blocks, so it has no disk to classify"
    ));
    // Blocks written only back from the end, with no disk size to place
    // them.
    let end_only = placement_image(
        vec![Write {
            blocks: filled(1, 1),
            locations: vec![from_end(0)],
        }],
        None,
    );
    let c = parse(&end_only.file);
    assert!(c.children.is_empty());
    assert!(has_note(
        &c,
        "Store 1 writes no blocks from the start of the disk and the manifest gives no disk \
         size, so it has no disk to classify"
    ));
}

#[test]
fn disks_larger_than_the_extraction_limit_are_cut_with_a_note() {
    // A 1 GiB disk with the GPT block at its start and a block at its end.
    let gpt_block = fat_disk()[..BLOCK].to_vec();
    let built = placement_image(
        vec![
            Write {
                blocks: gpt_block.clone(),
                locations: vec![begin(0)],
            },
            Write {
                blocks: filled(0xEE, 1),
                locations: vec![from_end(0)],
            },
        ],
        Some((1 << 30) / SECTOR),
    );
    let c = parse(&built.file);
    let disk = &child(&c, "Store 1 disk").data;
    assert_eq!(disk.len(), MAX_PAYLOAD);
    assert_eq!(&disk[..BLOCK], &gpt_block[..]);
    assert!(
        disk[BLOCK..].iter().all(|&b| b == 0),
        "the end block is outside the range"
    );
    assert!(has_note(
        &c,
        "Store 1 disk is 1 GiB; only the first 64 MiB were assembled and analyzed"
    ));
    assert_eq!(
        metadata(&c, "ffu_store_1_disk_analyzed"),
        MAX_PAYLOAD.to_string()
    );
}

#[test]
fn repeated_writes_of_the_same_blocks_are_bounded() {
    // 16 blocks written 5000 times over a 64 KiB disk: 312.5 MiB of copies.
    let built = placement_image(
        vec![Write {
            blocks: filled(7, 16),
            locations: vec![begin(0); 5000],
        }],
        Some(16 * BLOCK / SECTOR),
    );
    let message = parse_error(&built.file);
    assert!(
        message.starts_with(
            "FFU image parse error: Unsupported store 1 write descriptors: more than 256 MiB of \
             block writes fall in the first 64 KiB of the disk"
        ),
        "{message}"
    );
}

#[test]
fn validation_entries_are_counted_and_must_fill_their_region() {
    let mut spec = v1_spec();
    spec.stores[0].validations = vec![
        Validation {
            sector: 1,
            offset: 0,
            data: b"EFI PART".to_vec(),
        },
        Validation {
            sector: 0,
            offset: 510,
            data: vec![0x55, 0xAA],
        },
    ];
    let built = build(&spec);
    let c = parse(&built.file);
    assert!(has_note(&c, "2 validation entries; update type 0"));
    assert_eq!(&child(&c, "Store 1 disk").data[..], &fat_disk()[..]);
    let mut data = built.file;
    // The first entry's byte count overruns the 34-byte region.
    put32(
        &mut data,
        built.store_offsets[0] + STORE_HEADER_SIZE + 8,
        64,
    );
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Invalid store 1 validation entry 0 at 0x{:X}: 64 B of compare \
             data overrun the 34 B region",
            built.store_offsets[0] + STORE_HEADER_SIZE
        )
    );
}

// ---------------------------------------------------------------------------
// Image header extensions and chunk hashes
// ---------------------------------------------------------------------------

#[test]
fn device_targeting_entries_follow_the_manifest() {
    let spec = v1_spec();
    let plain = build(&spec);
    // Rebuild the image region with a 28-byte image header whose count is
    // 1, and one entry after the manifest (img2ffu `DeviceTargetInfo`):
    // seven lengths, then the strings.
    let mut built = plain.clone();
    let at = built.image_offset;
    let mut region = built.file[at..at + 24].to_vec();
    put32(&mut region, 0, 28);
    region.extend_from_slice(&1u32.to_le_bytes());
    region.extend_from_slice(spec.manifest.as_bytes());
    for len in [4u32, 6, 0, 0, 0, 0, 0] {
        region.extend_from_slice(&len.to_le_bytes());
    }
    region.extend_from_slice(b"ZraxBoards");
    assert!(
        region.len() <= BLOCK,
        "the entry fits in the manifest chunk"
    );
    region.resize(BLOCK, 0);
    put(&mut built.file, at, &region);
    rehash(&mut built);
    let c = parse(&built.file);
    assert!(has_note(
        &c,
        "Device targeting information: 1 entry after the manifest (img2ffu layout)"
    ));
    assert_eq!(
        metadata(&c, "ffu_device_target_0"),
        "manufacturer Zrax; family Boards"
    );
    assert_eq!(&child(&c, "Store 1 disk").data[..], &fat_disk()[..]);
    // A count the file cannot hold.
    put32(&mut built.file, at + 24, 0x0100_0000);
    assert!(parse_error(&built.file).contains(&format!(
        "Invalid device targeting count 16777216 at 0x{:X}",
        at + 24
    )));
}

#[test]
fn chunk_hashes_are_verified_with_the_named_algorithm() {
    let built = v1_image();
    let mut data = built.file.clone();
    // A byte of the fourth payload block changes after hashing.
    let chunk = (built.payload_offset - built.image_offset) / BLOCK + 3;
    data[built.payload_offset + 3 * BLOCK + 100] ^= 0x01;
    let c = parse(&data);
    assert!(has_note(
        &c,
        &format!(
            "Chunk hashes: 1 of {} checked chunks differ from their SHA-256 in the hash table, \
             the first at chunk {chunk} (0x{:X})",
            (data.len() - built.image_offset) / BLOCK,
            built.payload_offset + 3 * BLOCK
        )
    ));
    assert_eq!(metadata(&c, "ffu_chunk_hashes"), "mismatch");

    let mut sha1 = v1_spec();
    sha1.algorithm = CALG_SHA1;
    let sha1 = build(&sha1);
    let c = parse(&sha1.file);
    assert!(has_note(&c, "Chunk hashes: the SHA-1 of all"));

    let mut unknown = v1_spec();
    unknown.algorithm = 0x8003;
    let unknown = build(&unknown);
    let c = parse(&unknown.file);
    assert!(has_note(
        &c,
        "Chunk hashes not verified: hash algorithm 0x00008003 is neither SHA-1 nor SHA-256"
    ));
    assert_eq!(metadata(&c, "ffu_chunk_hashes"), "not verified");

    // A hash table of the wrong size is not used.
    let mut data = built.file;
    let size = u32::from_le_bytes(data[28..32].try_into().unwrap());
    put32(&mut data, 28, size - 32);
    let c = parse(&data);
    assert!(has_note(
        &c,
        "Chunk hashes not verified: the hash table holds"
    ));
}

#[test]
fn erased_padding_after_the_payload_is_noted_and_other_data_is_an_error() {
    let built = v1_image();
    let mut data = built.file.clone();
    data.extend_from_slice(&[0xFF; 100]);
    let c = parse(&data);
    assert!(has_note(
        &c,
        &format!(
            "100 B of erased-flash padding follow the payload at 0x{:X}",
            built.file.len()
        )
    ));
    assert_eq!(&child(&c, "Store 1 disk").data[..], &fat_disk()[..]);
    data.push(0x00);
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Invalid data after the payload at 0x{:X}: 101 B that are not \
             erased-flash padding",
            built.file.len()
        )
    );
}

// ---------------------------------------------------------------------------
// Header checks
// ---------------------------------------------------------------------------

/// A change to an image.
type Mutation = Box<dyn Fn(&mut Vec<u8>)>;

/// A header mutation and the start of the error it causes.
struct HeaderCase {
    expected: String,
    mutate: Mutation,
}

fn case(expected: &str, mutate: impl Fn(&mut Vec<u8>) + 'static) -> HeaderCase {
    HeaderCase {
        expected: expected.to_string(),
        mutate: Box::new(mutate),
    }
}

#[test]
fn security_and_image_header_errors_name_the_field() {
    let built = v1_image();
    let at = built.image_offset;
    let cases = [
        case("Invalid security header signature at 0x4", |d| d[4] = b's'),
        case("Invalid security header chunk size 0 KiB at 0x10", |d| {
            put32(d, 16, 0);
        }),
        case(
            "Invalid security header size 16 B at 0x0: it must hold the 32 B header and fit in \
             one 4 KiB chunk",
            |d| put32(d, 0, 16),
        ),
        case("Truncated catalog at 0x20 + 4294967295 B", |d| {
            put32(d, 24, u32::MAX);
        }),
        case("Truncated hash table at 0x60", |d| put32(d, 28, u32::MAX)),
        case(
            &format!("Invalid image header signature at 0x{:X}", at + 4),
            move |d| d[at + 4] = b'i',
        ),
        case(
            &format!(
                "Invalid image header size 8 B at 0x{at:X}: it must hold the 24 B header and fit \
                 in one 4 KiB chunk"
            ),
            move |d| put32(d, at, 8),
        ),
        case(
            &format!("Truncated manifest at 0x{:X}", at + 24),
            move |d| {
                put32(d, at + 16, u32::MAX);
            },
        ),
    ];
    for HeaderCase { expected, mutate } in cases {
        let mut data = built.file.clone();
        mutate(&mut data);
        let message = parse_error(&data);
        assert!(
            message.starts_with(&format!("FFU image parse error: {expected}")),
            "{expected}: {message}"
        );
    }
}

#[test]
fn store_header_errors_name_the_field() {
    let built = v1_image();
    let store = built.store_offsets[0];
    let mut data = built.file.clone();
    put16(&mut data, store + 8, 3);
    assert_eq!(
        parse_error(&data),
        format!(
            "FFU image parse error: Unsupported store 1 header version 1.0 (full flash 3.0) at \
             0x{:X}",
            store + 4
        )
    );
    let mut data = built.file.clone();
    put32(&mut data, store + 204, 256);
    assert!(parse_error(&data).starts_with(&format!(
        "FFU image parse error: Invalid store 1 block size 256 B at 0x{:X}",
        store + 204
    )));
    let mut data = built.file.clone();
    let count = u32::from_le_bytes(data[store + 208..store + 212].try_into().unwrap());
    put32(&mut data, store + 208, count - 1);
    assert!(parse_error(&data).contains("Invalid store 1 write descriptors at"));
    let mut data = built.file.clone();
    put32(&mut data, store + 212, u32::MAX);
    assert!(parse_error(&data).starts_with("FFU image parse error: Truncated write descriptors"));
    // One payload block too many: the second descriptor (after the first
    // one's 8 bytes and two locations) writes the primary GPT block twice.
    let mut data = built.file.clone();
    let second_blocks = store + STORE_HEADER_SIZE + 8 + 2 * 8 + 4;
    put32(&mut data, second_blocks, 2);
    assert!(parse_error(&data).starts_with(&format!(
        "FFU image parse error: Truncated store 1 payload at 0x{:X}",
        built.payload_offset
    )));
}

#[test]
fn detection_needs_the_signature_and_consistent_header_sizes() {
    let built = v1_image();
    let data = &built.file;
    assert_eq!(ffu::detect(&data[..32]), Some(Layout::Ffu));
    assert_eq!(ffu::detect(&data[..31]), None);
    for (at, value) in [(0, 31u32), (0, 4097), (16, 0)] {
        let mut header = data[..64].to_vec();
        put32(&mut header, at, value);
        assert_eq!(ffu::detect(&header), None, "field {at} = {value}");
    }
    let mut other = data[..64].to_vec();
    other[15] = b'_';
    assert_eq!(ffu::detect(&other), None);
    // The security header alone is detected and then fails as truncated.
    assert!(parse_error(&data[..64]).contains("Truncated"));

    let mut x: u32 = 0x9e37_79b9;
    let noise: Vec<u8> = (0..65536)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    for end in [0, 7, 32, 512, 4096, noise.len()] {
        assert_eq!(ffu::detect(&noise[..end]), None);
    }
    // The disk inside is not an FFU, and the FFU is not its GPT.
    assert_eq!(ffu::detect(&fat_disk()), None);
    assert!(matches!(
        detect_format(&fat_disk()),
        DetectedFormat::Container { kind } if kind.format() == FileFormat::Gpt
    ));
}

// ---------------------------------------------------------------------------
// Sweeps
// ---------------------------------------------------------------------------

/// Prefix lengths for a truncation sweep: every length up to 12 KiB (the
/// security, image and store regions), then at most 2048 lengths spread
/// over the payload, then every length in the last 2 KiB.
fn truncation_points(len: usize) -> Vec<usize> {
    let mut points: Vec<usize> = (0..len.min(3 * BLOCK)).collect();
    points.extend((3 * BLOCK..len).step_by(61.max(len / 2048)));
    points.extend(len.saturating_sub(2048).max(3 * BLOCK)..len);
    points
}

#[test]
fn every_truncated_image_fails() {
    for built in [v1_image(), build(&v2_spec())] {
        let data = &built.file;
        for end in truncation_points(data.len()) {
            let prefix = &data[..end];
            assert!(
                ffu::parse_container(prefix, Layout::Ffu).is_err(),
                "prefix {end} of {} parses",
                data.len()
            );
            let _ = ffu::detect(prefix);
        }
    }
}

/// Positions to mutate: the security header and the start of the catalog
/// and hash table, the image header and manifest, every store header and
/// its descriptors, and at most 256 positions spread over the payload.
fn mutation_points(built: &Built) -> Vec<usize> {
    let len = built.file.len();
    let mut points: Vec<usize> = (0..160).collect();
    points.extend(built.image_offset..built.image_offset + 512);
    for &store in &built.store_offsets {
        points.extend(store..store + 512);
    }
    points.extend((built.payload_offset..len).step_by(97.max(len / 256)));
    points.retain(|&at| at < len);
    points
}

#[test]
fn byte_mutations_never_panic() {
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xff, |b| b ^ 0x01];
    for mut built in [v1_image(), build(&v2_spec())] {
        let points = mutation_points(&built);
        let data = &mut built.file;
        for &at in &points {
            let original = data[at];
            for mutate in mutations {
                data[at] = mutate(original);
                if let Some(layout) = ffu::detect(data) {
                    let _ = ffu::parse_container(data, layout);
                }
            }
            data[at] = original;
        }
        // The full classification on a sample of header mutations.
        for &at in points.iter().step_by(16) {
            data[at] ^= 0x80;
            let _ = detect_payload(data, &ClassifierOptions::new());
            data[at] ^= 0x80;
        }
    }
}

// ---------------------------------------------------------------------------
// External inputs
// ---------------------------------------------------------------------------

/// Every input in `IDA_INPUT_DIR` (read-only) that is detected as an FFU
/// parses or fails with an error, without panicking. Skips without the
/// variable.
#[test]
fn ida_inputs_detected_as_ffu_parse_without_panicking() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    scan(&dir, "IDA_INPUT_DIR");
}

/// Every file in `FFU_SAMPLES_DIR` (FFU images read in place, never
/// committed) that is detected as an FFU parses or fails with an error,
/// without panicking. Skips without the variable.
#[test]
fn ffu_samples_parse_without_panicking() {
    let Ok(dir) = std::env::var("FFU_SAMPLES_DIR") else {
        eprintln!("skipped: FFU_SAMPLES_DIR is not set");
        return;
    };
    scan(&dir, "FFU_SAMPLES_DIR");
}

fn scan(dir: &str, variable: &str) {
    let mut detected = 0usize;
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(dir).unwrap_or_else(|_| panic!("{variable} is a directory")) {
        let path = entry.expect("directory entry").path();
        if !path.is_file() {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        scanned += 1;
        if let Some(layout) = ffu::detect(&data) {
            detected += 1;
            let outcome = ffu::parse_container(&data, layout)
                .map(|c| (c.variant.clone(), c.children.len(), c.notes.clone()));
            eprintln!("{}: {outcome:?}", path.display());
        }
    }
    eprintln!("{scanned} inputs scanned, {detected} detected as FFU images");
}
