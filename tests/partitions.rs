//! Partition tables: hdiutil-made MBR, GPT and Apple Partition Map images,
//! synthetic tables built from the UEFI 2.10 and Inside Macintosh layouts
//! (EBR chains, protective, hybrid and stale MBRs, 4096-byte GPT blocks,
//! backup recovery, BIOS boot partitions, APM boot code), partitions that
//! hold the ext fixtures, disk images inside tar and Android sparse images,
//! weak-detection refusals, corrupted fields and checksums, and truncation
//! and mutation sweeps.

use zrax::formats::checksum::crc32;
use zrax::formats::container::{Child, Classify, Container};
use zrax::formats::partitions::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// The contents of a gzip file written by `gzip -n` (RFC 1952): a 10-byte
/// header without optional fields, a DEFLATE stream and an 8-byte trailer.
fn gunzip(file: &[u8]) -> Vec<u8> {
    assert_eq!(&file[..4], &[0x1f, 0x8b, 8, 0], "gzip -n header");
    miniz_oxide::inflate::decompress_to_vec(&file[10..file.len() - 8]).expect("inflates")
}

/// An hdiutil image from `tests/fixtures/partitions` (README.md there).
fn hdiutil_image(name: &str) -> Vec<u8> {
    gunzip(&fixture(&format!("partitions/hdiutil-{name}.img.gz")))
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn detected(data: &[u8]) -> Option<Layout> {
    partitions::detect(data).or_else(|| partitions::detect_weak(data))
}

/// Detect and parse a table that must be valid.
fn parse(data: &[u8]) -> Container<'_> {
    let layout = detected(data).expect("detected as a partition table");
    partitions::parse_container(data, layout).expect("parses")
}

/// The error text of a table that is detected as `layout` but does not
/// parse.
fn parse_error(data: &[u8], layout: Layout) -> String {
    partitions::parse_container(data, layout)
        .expect_err("does not parse")
        .to_string()
}

fn labels(c: &Container<'_>) -> Vec<String> {
    c.children.iter().map(|child| child.label.clone()).collect()
}

fn child<'c>(c: &'c Container<'_>, label: &str) -> &'c Child<'c> {
    c.children
        .iter()
        .find(|child| child.label == label)
        .unwrap_or_else(|| panic!("{label} is listed: {:?}", labels(c)))
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

fn put(disk: &mut [u8], at: usize, bytes: &[u8]) {
    disk[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16_be(disk: &mut [u8], at: usize, value: u16) {
    put(disk, at, &value.to_be_bytes());
}

fn put32_be(disk: &mut [u8], at: usize, value: u32) {
    put(disk, at, &value.to_be_bytes());
}

fn put32(disk: &mut [u8], at: usize, value: u32) {
    put(disk, at, &value.to_le_bytes());
}

fn put64(disk: &mut [u8], at: usize, value: u64) {
    put(disk, at, &value.to_le_bytes());
}

fn le_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn le_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

const SECTOR: usize = 512;

fn round_up(n: usize, unit: usize) -> usize {
    (n + unit - 1) / unit * unit
}

// ---------------------------------------------------------------------------
// MBR builders (UEFI 2.10, Tables 5.1 and 5.2)
// ---------------------------------------------------------------------------

/// CHS placeholder for LBA-era records, as hdiutil writes it.
const CHS_UNUSED: [u8; 3] = [0xfe, 0xff, 0xff];

/// One partition record.
#[derive(Debug, Clone, Copy)]
struct MbrRecord {
    /// `BootIndicator`: `0x80` active, `0x00` inactive.
    boot: u8,
    /// `OSType`.
    os_type: u8,
    /// `StartingLBA`, relative to the table's base.
    start: u32,
    /// `SizeInLBA`.
    size: u32,
}

fn record(os_type: u8, start: u32, size: u32) -> MbrRecord {
    MbrRecord {
        boot: 0,
        os_type,
        start,
        size,
    }
}

/// An MBR or EBR sector: `code` at 0 (bootstrap code, at most 440 B), the
/// disk signature at 440, two zero bytes, the records at 446 (boot
/// indicator, starting CHS, OS type, ending CHS, starting LBA, size), and
/// the boot signature `55 AA` at 510.
fn boot_sector(code: &[u8], disk_signature: u32, records: &[MbrRecord]) -> Vec<u8> {
    let mut sector = vec![0u8; SECTOR];
    put(&mut sector, 0, code);
    put32(&mut sector, 440, disk_signature);
    for (i, r) in records.iter().enumerate() {
        let at = 446 + i * 16;
        sector[at] = r.boot;
        put(&mut sector, at + 1, &CHS_UNUSED);
        sector[at + 4] = r.os_type;
        put(&mut sector, at + 5, &CHS_UNUSED);
        put32(&mut sector, at + 8, r.start);
        put32(&mut sector, at + 12, r.size);
    }
    put(&mut sector, 510, &[0x55, 0xaa]);
    sector
}

/// A disk of `sectors` zero sectors with `mbr` in sector 0.
fn mbr_disk(mbr: &[u8], sectors: usize) -> Vec<u8> {
    let mut disk = vec![0u8; sectors * SECTOR];
    put(&mut disk, 0, mbr);
    disk
}

/// Real-mode x86 code in the style of an MBR loader: set up the stack at
/// 0x7C00, relocate to 0x0600, then print with INT 10h and halt. Padded
/// with zeros to the 440-byte bootstrap area.
fn x86_bootstrap() -> Vec<u8> {
    let mut code = vec![
        0xfa, // cli
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xd0, // mov ss, ax
        0xbc, 0x00, 0x7c, // mov sp, 0x7c00
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0xfb, // sti
        0xbe, 0x00, 0x7c, // mov si, 0x7c00
        0xbf, 0x00, 0x06, // mov di, 0x0600
        0xb9, 0x00, 0x01, // mov cx, 0x100
        0xfc, // cld
        0xf3, 0xa5, // rep movsw
        0xea, 0x1d, 0x06, 0x00, 0x00, // jmp 0000:061d
        0xbe, 0x40, 0x06, // mov si, 0x0640
        0xac, // lodsb
        0x84, 0xc0, // test al, al
        0x74, 0x06, // jz +6
        0xb4, 0x0e, // mov ah, 0x0e
        0xcd, 0x10, // int 0x10
        0xeb, 0xf5, // jmp -11
        0xf4, // hlt
        0xeb, 0xfd, // jmp -3
    ];
    code.extend_from_slice(b"Missing operating system\0");
    code.resize(440, 0);
    code
}

// ---------------------------------------------------------------------------
// GPT builder (UEFI 2.10, Tables 5.5 and 5.6)
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

const LINUX_FILESYSTEM: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
const BIOS_BOOT: &str = "21686148-6449-6E6F-744E-656564454649";
const EFI_SYSTEM: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

/// One partition entry.
#[derive(Debug, Clone)]
struct GptEntry {
    /// `PartitionTypeGUID` text.
    type_guid: &'static str,
    /// `StartingLBA`.
    first: u64,
    /// `EndingLBA`, inclusive.
    last: u64,
    /// `Attributes`.
    attributes: u64,
    /// `PartitionName`, at most 36 UTF-16 code units.
    name: &'static str,
}

fn entry(type_guid: &'static str, first: u64, last: u64, name: &'static str) -> GptEntry {
    GptEntry {
        type_guid,
        first,
        last,
        attributes: 0,
        name,
    }
}

/// The geometry of a synthetic GPT disk.
#[derive(Debug, Clone, Copy)]
struct GptGeometry {
    /// Logical block size in bytes.
    block: usize,
    /// Blocks on the disk; the backup header is in the last one.
    blocks: u64,
    /// `NumberOfPartitionEntries`.
    entry_count: u32,
    /// `SizeOfPartitionEntry`.
    entry_size: u32,
}

impl GptGeometry {
    fn array_blocks(self) -> u64 {
        let bytes = u64::from(self.entry_count) * u64::from(self.entry_size);
        let block = self.block as u64;
        (bytes + block - 1) / block
    }

    fn first_usable(self) -> u64 {
        2 + self.array_blocks()
    }

    fn last_usable(self) -> u64 {
        self.blocks - 2 - self.array_blocks()
    }

    fn backup_array_lba(self) -> u64 {
        self.blocks - 1 - self.array_blocks()
    }
}

const DISK_GUID: &str = "5A524158-4750-5444-4953-4B0000000001";

/// The entry array: each entry has its type GUID (0), a unique GUID (16)
/// derived from its number, first and last LBA (32, 40), attributes (48)
/// and its UTF-16LE name (56).
fn gpt_array(geometry: GptGeometry, entries: &[GptEntry]) -> Vec<u8> {
    let size = geometry.entry_size as usize;
    let mut array = vec![0u8; geometry.entry_count as usize * size];
    for (i, e) in entries.iter().enumerate() {
        let at = i * size;
        put(&mut array, at, &guid(e.type_guid));
        let unique = format!("5A524158-0000-4000-8000-{:012X}", i + 1);
        put(&mut array, at + 16, &guid(&unique));
        put64(&mut array, at + 32, e.first);
        put64(&mut array, at + 40, e.last);
        put64(&mut array, at + 48, e.attributes);
        for (j, unit) in e.name.encode_utf16().enumerate() {
            put(&mut array, at + 56 + j * 2, &unit.to_le_bytes());
        }
    }
    array
}

/// A 92-byte header at `lba` (Table 5.5) whose array is at `entry_lba`:
/// signature, revision 1.0, header size 92, header CRC (16), MyLBA,
/// AlternateLBA, usable range, disk GUID, entry LBA, count, size and the
/// array CRC (88).
fn gpt_header(
    geometry: GptGeometry,
    lba: u64,
    alternate: u64,
    entry_lba: u64,
    array: &[u8],
) -> Vec<u8> {
    let mut header = vec![0u8; geometry.block];
    put(&mut header, 0, b"EFI PART");
    put32(&mut header, 8, 0x0001_0000);
    put32(&mut header, 12, 92);
    put64(&mut header, 24, lba);
    put64(&mut header, 32, alternate);
    put64(&mut header, 40, geometry.first_usable());
    put64(&mut header, 48, geometry.last_usable());
    put(&mut header, 56, &guid(DISK_GUID));
    put64(&mut header, 72, entry_lba);
    put32(&mut header, 80, geometry.entry_count);
    put32(&mut header, 84, geometry.entry_size);
    put32(&mut header, 88, crc32(array));
    let crc = crc32(&header[..92]);
    put32(&mut header, 16, crc);
    header
}

/// A GPT disk: a protective MBR (type 0xEE from LBA 1 over the rest of the
/// disk), the primary header at LBA 1 with its array at LBA 2, and the
/// backup array and header at the end.
fn gpt_disk(geometry: GptGeometry, entries: &[GptEntry]) -> Vec<u8> {
    let block = geometry.block;
    let mut disk = vec![0u8; block * geometry.blocks as usize];
    let protective_size = u32::try_from(geometry.blocks - 1).unwrap_or(u32::MAX);
    put(
        &mut disk,
        0,
        &boot_sector(&[], 0, &[record(0xee, 1, protective_size)]),
    );
    let array = gpt_array(geometry, entries);
    let last = geometry.blocks - 1;
    put(&mut disk, 2 * block, &array);
    put(
        &mut disk,
        geometry.backup_array_lba() as usize * block,
        &array,
    );
    put(&mut disk, block, &gpt_header(geometry, 1, last, 2, &array));
    put(
        &mut disk,
        last as usize * block,
        &gpt_header(geometry, last, 1, geometry.backup_array_lba(), &array),
    );
    disk
}

/// Recompute the array CRC and then the header CRC of the header at `lba`
/// from the fields stored there, so a mutation reaches the later checks.
fn reseal_gpt(disk: &mut [u8], block: usize, lba: usize) {
    let at = lba * block;
    let entry_lba = le_u64(disk, at + 72) as usize;
    let size = le_u32(disk, at + 80) as usize * le_u32(disk, at + 84) as usize;
    if let Some(array) = disk
        .get(entry_lba.saturating_mul(block)..)
        .and_then(|rest| rest.get(..size))
    {
        let crc = crc32(array);
        put32(disk, at + 88, crc);
    }
    let header_size = (le_u32(disk, at + 12) as usize).clamp(92, block);
    put32(disk, at + 16, 0);
    let crc = crc32(&disk[at..at + header_size]);
    put32(disk, at + 16, crc);
}

/// A small GPT disk of 20 blocks of 512 bytes with four entries (one array
/// block, so the usable range is 3-17): blocks 3-6 for a Linux filesystem,
/// 7-10 for a BIOS boot partition with x86 code, the backup array at 18 and
/// the backup header at 19.
fn small_gpt() -> (GptGeometry, Vec<u8>) {
    let geometry = GptGeometry {
        block: SECTOR,
        blocks: 20,
        entry_count: 4,
        entry_size: 128,
    };
    let mut disk = gpt_disk(
        geometry,
        &[
            entry(LINUX_FILESYSTEM, 3, 6, "root"),
            entry(BIOS_BOOT, 7, 10, ""),
        ],
    );
    put(&mut disk, 7 * SECTOR, &x86_bootstrap());
    (geometry, disk)
}

// ---------------------------------------------------------------------------
// APM builder (Inside Macintosh: Devices, chapter 3)
// ---------------------------------------------------------------------------

/// One partition map entry.
#[derive(Debug, Clone)]
struct ApmEntry {
    /// `pmPartName`.
    name: &'static str,
    /// `pmParType`.
    kind: &'static str,
    /// `pmPyPartStart`, in blocks.
    start: u32,
    /// `pmPartBlkCnt`, in blocks.
    blocks: u32,
    /// `pmLgBootStart`, in blocks from the partition start.
    boot_start: u32,
    /// `pmBootSize`, in bytes.
    boot_size: u32,
    /// `pmProcessor`.
    processor: &'static str,
}

fn apm_entry(name: &'static str, kind: &'static str, start: u32, blocks: u32) -> ApmEntry {
    ApmEntry {
        name,
        kind,
        start,
        blocks,
        boot_start: 0,
        boot_size: 0,
        processor: "",
    }
}

/// An APM disk of `total` blocks of `block` bytes: the driver descriptor
/// record (`ER`, block size, block count, `sbDrvrCount` at 16 and the
/// driver triples from 18), then one entry per block from block 1 (`PM`,
/// map count at 4, start 8, blocks 12, name 16, type 48, data start 80,
/// data count 84, status 88, boot start 92, boot size 96, load address 100,
/// entry point 108, checksum 116, processor 120).
fn apm_disk(
    block: usize,
    total: u32,
    entries: &[ApmEntry],
    drivers: &[(u32, u16, u16)],
) -> Vec<u8> {
    let mut disk = vec![0u8; block * total as usize];
    put(&mut disk, 0, b"ER");
    put16_be(&mut disk, 2, block as u16);
    put32_be(&mut disk, 4, total);
    put16_be(&mut disk, 16, drivers.len() as u16);
    for (i, &(start, size, kind)) in drivers.iter().enumerate() {
        put32_be(&mut disk, 18 + i * 8, start);
        put16_be(&mut disk, 22 + i * 8, size);
        put16_be(&mut disk, 24 + i * 8, kind);
    }
    for (i, e) in entries.iter().enumerate() {
        let at = (i + 1) * block;
        put(&mut disk, at, b"PM");
        put32_be(&mut disk, at + 4, entries.len() as u32);
        put32_be(&mut disk, at + 8, e.start);
        put32_be(&mut disk, at + 12, e.blocks);
        put(&mut disk, at + 16, e.name.as_bytes());
        put(&mut disk, at + 48, e.kind.as_bytes());
        put32_be(&mut disk, at + 84, e.blocks);
        put32_be(&mut disk, at + 88, 0x33);
        put32_be(&mut disk, at + 92, e.boot_start);
        put32_be(&mut disk, at + 96, e.boot_size);
        put32_be(&mut disk, at + 100, 0x0001_0000);
        put32_be(&mut disk, at + 108, 0x0001_0000);
        put32_be(&mut disk, at + 116, 0x1234);
        put(&mut disk, at + 120, e.processor.as_bytes());
    }
    disk
}

/// 680x0 code: a function that links a frame, loads 1 into D0 and returns,
/// repeated to `len` bytes.
fn m68k_code(len: usize) -> Vec<u8> {
    let function = [
        0x4e, 0x56, 0x00, 0x00, // link a6, #0
        0x20, 0x3c, 0x00, 0x00, 0x00, 0x01, // move.l #1, d0
        0x4e, 0x71, // nop
        0x4e, 0x5e, // unlk a6
        0x4e, 0x75, // rts
    ];
    function.iter().copied().cycle().take(len).collect()
}

/// A small APM disk of 512-byte blocks: the map (blocks 1-3), a driver
/// partition with 64 B of boot code for a 68020 (blocks 4-5) and an HFS
/// partition (blocks 6-9).
fn small_apm() -> Vec<u8> {
    let driver = ApmEntry {
        boot_size: 64,
        processor: "68020",
        ..apm_entry("Macintosh", "Apple_Driver43", 4, 2)
    };
    let mut disk = apm_disk(
        SECTOR,
        10,
        &[
            apm_entry("Apple", "Apple_partition_map", 1, 3),
            driver,
            apm_entry("MacOS", "Apple_HFS", 6, 4),
        ],
        &[(4, 2, 1)],
    );
    put(&mut disk, 4 * SECTOR, &m68k_code(64));
    disk
}

// ---------------------------------------------------------------------------
// Container builders: tar (POSIX ustar) and Android sparse images
// ---------------------------------------------------------------------------

/// A ustar archive with one regular file: header (name, mode 0644, uid and
/// gid 0, octal size, mtime 0, checksum, type `0`, `ustar\0` and version
/// `00`), the contents padded to 512 B, and two zero end blocks.
fn tar_with(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 512];
    put(&mut header, 0, name.as_bytes());
    put(&mut header, 100, b"0000644\0");
    put(&mut header, 108, b"0000000\0");
    put(&mut header, 116, b"0000000\0");
    put(
        &mut header,
        124,
        format!("{:011o}\0", contents.len()).as_bytes(),
    );
    put(&mut header, 136, b"00000000000\0");
    header[156] = b'0';
    put(&mut header, 257, b"ustar\x0000");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    put(&mut header, 148, format!("{sum:06o}\0 ").as_bytes());
    let mut archive = header;
    archive.extend_from_slice(contents);
    archive.resize(round_up(archive.len(), 512) + 1024, 0);
    archive
}

/// An Android sparse image of `image` (libsparse `sparse_format.h`): the
/// 28-byte header (magic `0xED26FF3A`, version 1.0, header sizes 28 and 12,
/// block size, total blocks, chunk count, checksum 0), then a RAW chunk
/// (`0xCAC1`) for each block that holds data and a `DONT_CARE` chunk
/// (`0xCAC3`) for each zero block.
fn sparse_image(image: &[u8], block: usize) -> Vec<u8> {
    assert_eq!(image.len() % block, 0);
    let mut chunks = Vec::new();
    let mut count = 0u32;
    for data in image.chunks(block) {
        let raw = data.iter().any(|&b| b != 0);
        let mut header = vec![0u8; 12];
        put(
            &mut header,
            0,
            &(if raw { 0xcac1u16 } else { 0xcac3 }).to_le_bytes(),
        );
        put32(&mut header, 4, 1);
        put32(&mut header, 8, 12 + if raw { block as u32 } else { 0 });
        chunks.extend_from_slice(&header);
        if raw {
            chunks.extend_from_slice(data);
        }
        count += 1;
    }
    let mut sparse = vec![0u8; 28];
    put32(&mut sparse, 0, 0xed26_ff3a);
    put(&mut sparse, 4, &1u16.to_le_bytes());
    put(&mut sparse, 8, &28u16.to_le_bytes());
    put(&mut sparse, 10, &12u16.to_le_bytes());
    put32(&mut sparse, 12, block as u32);
    put32(&mut sparse, 16, (image.len() / block) as u32);
    put32(&mut sparse, 20, count);
    sparse.extend_from_slice(&chunks);
    sparse
}

/// An MBR disk whose partition 1 (Linux, sectors 8-519) holds the ext2
/// fixture: 520 sectors, a multiple of 4 KiB.
fn mbr_with_ext2() -> Vec<u8> {
    let ext2 = fixture("ext/ext2.img");
    let sectors = (ext2.len() / SECTOR) as u32;
    let mut disk = mbr_disk(
        &boot_sector(&[], 0x1234_5678, &[record(0x83, 8, sectors)]),
        520,
    );
    put(&mut disk, 8 * SECTOR, &ext2);
    disk
}

// ---------------------------------------------------------------------------
// hdiutil fixtures
// ---------------------------------------------------------------------------

#[test]
fn hdiutil_apm_image_lists_its_hfs_partition() {
    let image = hdiutil_image("apm");
    assert_eq!(partitions::detect(&image), Some(Layout::ApplePartitionMap));
    let c = parse(&image);
    assert_eq!(c.format, FileFormat::ApplePartitionMap);
    assert_eq!(c.consumed, 1 << 20);
    assert!(
        has_note(
            &c,
            "Apple Partition Map: 2 entries in 512 B blocks; the driver descriptor gives 2048 \
             blocks (1 MiB)"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(labels(&c), ["Partition 2 \"disk image\" (Apple_HFS)"]);
    let hfs = &c.children[0];
    assert_eq!((hfs.offset, hfs.stored_size), (64 * SECTOR, 1984 * SECTOR));
    assert_eq!(hfs.classify, Classify::IfRecognized);
    assert_eq!(
        metadata(&c, "partitions_apm_entry_1"),
        "\"Apple\"; Apple_partition_map; blocks 1+63; status 0x00000003"
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::ApplePartitionMap);
    assert!(
        p.slices.is_empty(),
        "the empty HFS partition is not a recognized format"
    );
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
}

#[test]
fn hdiutil_gpt_image_verifies_both_headers_and_entry_arrays() {
    let image = hdiutil_image("gpt");
    assert_eq!(partitions::detect(&image), Some(Layout::Gpt));
    let c = parse(&image);
    assert_eq!(c.format, FileFormat::Gpt);
    for note in [
        "GPT: 1 of 128 entries of 128 B in use, 512 B logical blocks; header and entry array \
         CRC-32 verified",
        "Backup GPT header at LBA 2047 and its entry array verified (CRC-32); they match the \
         primary",
        "Protective MBR at LBA 0 (type 0xEE)",
        "Bootstrap code area (440 B) is all zeros",
    ] {
        assert!(has_note(&c, note), "{note}: {:?}", c.notes);
    }
    assert_eq!(labels(&c), ["Partition 1 \"disk image\" (Apple HFS/HFS+)"]);
    let hfs = &c.children[0];
    assert_eq!((hfs.offset, hfs.stored_size), (40 * SECTOR, 1968 * SECTOR));
    assert_eq!(metadata(&c, "partitions_gpt_usable_lbas"), "34-2014");
    assert_eq!(c.consumed, 1 << 20);
    assert_eq!(classify(&image).format.format, FileFormat::Gpt);
}

#[test]
fn hdiutil_mbr_image_has_one_hfs_partition_from_sector_1() {
    let image = hdiutil_image("mbr");
    assert_eq!(partitions::detect(&image), None);
    assert_eq!(partitions::detect_weak(&image), Some(Layout::Mbr));
    let c = parse(&image);
    assert_eq!(labels(&c), ["Partition 1 (HFS / HFS+, type 0xAF)"]);
    let hfs = &c.children[0];
    assert_eq!((hfs.offset, hfs.stored_size), (SECTOR, 2047 * SECTOR));
    assert!(has_note(
        &c,
        "MBR partition table: 1 of 4 primary records in use"
    ));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Mbr);
    assert!(p.format.confidence < 1.0, "weak detection");
}

#[test]
fn truncated_hdiutil_gpt_dump_notes_the_backup_and_the_cut_partition() {
    let image = hdiutil_image("gpt");
    let head = &image[..64 * SECTOR];
    let c = parse(head);
    assert!(
        has_note(
            &c,
            "Backup GPT header at LBA 2047 lies beyond the end of the file; not verified"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(
        &c,
        "Partitions that end beyond the end of the file are classified from the bytes present: \
         Partition 1"
    ));
    assert_eq!(c.children[0].stored_size, 24 * SECTOR);
    // Shorter than the entry array, the primary cannot be checked.
    assert!(parse_error(&image[..20 * SECTOR], Layout::Gpt)
        .contains("Truncated GPT partition entry array"));
}

// ---------------------------------------------------------------------------
// MBR
// ---------------------------------------------------------------------------

#[test]
fn mbr_partition_holding_an_ext_filesystem_is_classified_on_its_own() {
    let disk = mbr_with_ext2();
    assert!(matches!(
        detect_format(&disk),
        DetectedFormat::Container {
            kind: zrax::formats::container::Kind::Partitions(Layout::Mbr)
        }
    ));
    let c = parse(&disk);
    assert_eq!(metadata(&c, "partitions_mbr_disk_signature"), "0x12345678");
    assert_eq!(
        metadata(&c, "partitions_mbr_partition_1"),
        "type 0x83; sectors 8-519"
    );
    let p = classify(&disk);
    assert_eq!(p.format.format, FileFormat::Mbr);
    assert_eq!(p.slices.len(), 1);
    let slice = &p.slices[0];
    assert_eq!(
        slice.label.as_deref(),
        Some("Partition 1 (Linux, type 0x83)")
    );
    assert_eq!(
        (slice.offset, slice.size),
        (8 * SECTOR as u64, 512 * SECTOR as u64)
    );
    assert_eq!(slice.isa, Isa::X86_64, "from the ext members");
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(
        payload_has_note(
            &p,
            "Primary ISA selected from Partition 1 (Linux, type 0x83)"
        ),
        "{:?}",
        p.notes
    );
}

#[test]
fn mbr_bootstrap_code_is_classified_as_16_bit_x86() {
    let mbr = boot_sector(
        &x86_bootstrap(),
        0,
        &[MbrRecord {
            boot: 0x80,
            ..record(0x0c, 1, 7)
        }],
    );
    let disk = mbr_disk(&mbr, 8);
    let c = parse(&disk);
    let bootstrap = child(&c, "MBR bootstrap code");
    assert_eq!((bootstrap.offset, bootstrap.stored_size), (0, 440));
    assert_eq!(bootstrap.classify, Classify::Code);
    assert!(
        child(&c, "Partition 1 (W95 FAT32 (LBA), type 0x0C, active)").classify
            == Classify::IfRecognized
    );
    assert!(has_note(
        &c,
        "Bootstrap code: 440 B at 0x0, classified as 16-bit x86 real-mode code"
    ));
    let p = classify(&disk);
    let slice = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("MBR bootstrap code"))
        .expect("bootstrap slice");
    assert_eq!((slice.isa, slice.bitwidth), (Isa::X86, 16));
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.slices.len(), 1, "the empty FAT partition is not listed");
}

#[test]
fn empty_bootstrap_area_is_noted_and_not_classified() {
    let disk = mbr_disk(&boot_sector(&[], 0, &[record(0x83, 1, 3)]), 4);
    let c = parse(&disk);
    assert!(c
        .children
        .iter()
        .all(|child| child.label != "MBR bootstrap code"));
    assert!(has_note(&c, "Bootstrap code area (440 B) is all zeros"));
    assert!(matches!(classify(&disk).primary.isa, Isa::Unknown(_)));
}

/// A disk with primary partition 1 (sectors 1-3) and an extended partition
/// 2 (sectors 4-23) holding three logical partitions in an EBR chain (EBRs
/// at 4, 10 and 16, each logical partition starting 2 sectors after its
/// EBR). With `link_back`, the second EBR's link has offset 0.
fn ebr_disk(link_back: bool) -> Vec<u8> {
    let mut disk = mbr_disk(
        &boot_sector(&[], 0, &[record(0x83, 1, 3), record(0x05, 4, 20)]),
        24,
    );
    // EBR 1: logical partition at +2 (sectors 6-9), link to the EBR at 10.
    put(
        &mut disk,
        4 * SECTOR,
        &boot_sector(&[], 0, &[record(0x83, 2, 4), record(0x05, 6, 6)]),
    );
    // EBR 2: logical partition at +2 (12-15), link to the EBR at 16 or back
    // to the first EBR.
    let next = if link_back {
        record(0x05, 0, 6)
    } else {
        record(0x05, 12, 8)
    };
    put(
        &mut disk,
        10 * SECTOR,
        &boot_sector(&[], 0, &[record(0x82, 2, 4), next]),
    );
    // EBR 3: logical partition at +2 (18-23), no link.
    put(
        &mut disk,
        16 * SECTOR,
        &boot_sector(&[], 0, &[record(0x83, 2, 6)]),
    );
    disk
}

#[test]
fn ebr_chains_list_logical_partitions_from_number_5() {
    let disk = ebr_disk(false);
    let c = parse(&disk);
    assert_eq!(
        labels(&c),
        [
            "Partition 1 (Linux, type 0x83)",
            "Partition 5 (Linux, type 0x83)",
            "Partition 6 (Linux swap / Solaris, type 0x82)",
            "Partition 7 (Linux, type 0x83)",
        ]
    );
    let offsets: Vec<(usize, usize)> = c
        .children
        .iter()
        .map(|child| (child.offset, child.stored_size))
        .collect();
    assert_eq!(
        offsets,
        [
            (512, 1536),
            (6 * 512, 2048),
            (12 * 512, 2048),
            (18 * 512, 3072)
        ]
    );
    assert!(
        has_note(
            &c,
            "Extended partition 2 (type 0x05) at sector 4: 3 logical partitions in 3 EBRs"
        ),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "2 of 4 primary records in use (1 extended), 3 logical partitions"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(
        metadata(&c, "partitions_mbr_partition_6"),
        "type 0x82; sectors 12-15"
    );
}

#[test]
fn ebr_chain_that_links_back_stops() {
    let disk = ebr_disk(true);
    let c = parse(&disk);
    // The zero-offset link back is ignored, as libblkid ignores it.
    assert_eq!(c.children.len(), 3, "{:?}", labels(&c));
    let mut looping = ebr_disk(false);
    // EBR 3 links to the EBR at 10 again (offset 6 from the extended start).
    put(
        &mut looping,
        16 * SECTOR,
        &boot_sector(&[], 0, &[record(0x83, 2, 6), record(0x05, 6, 6)]),
    );
    let c = parse(&looping);
    assert!(
        has_note(&c, "the EBR chain returns to sector 10; the walk stopped"),
        "{:?}",
        c.notes
    );
    assert_eq!(c.children.len(), 4);
}

#[test]
fn ebr_beyond_the_file_or_without_a_signature_ends_the_chain() {
    let disk = ebr_disk(false);
    let c = parse(&disk[..12 * SECTOR]);
    assert!(
        has_note(&c, "the EBR at sector 16 lies beyond the end of the file"),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "Partitions that start beyond the end of the file are not classified: Partition 6"
        ),
        "{:?}",
        c.notes
    );
    let mut unsigned = disk.clone();
    unsigned[10 * SECTOR + 510] = 0;
    let c = parse(&unsigned);
    assert!(
        has_note(&c, "no boot signature in the EBR at sector 10"),
        "{:?}",
        c.notes
    );
    assert_eq!(c.children.len(), 2);
}

#[test]
fn logical_partitions_that_overlap_a_listed_one_are_skipped() {
    let mut disk = ebr_disk(false);
    // EBR 3's logical partition starts at offset 0, on the EBR itself.
    put(
        &mut disk,
        16 * SECTOR,
        &boot_sector(&[], 0, &[record(0x83, 0, 6)]),
    );
    let c = parse(&disk);
    assert!(
        has_note(&c, "starts at the EBR itself; skipped"),
        "{:?}",
        c.notes
    );
    let mut overlapping = ebr_disk(false);
    put(
        &mut overlapping,
        16 * SECTOR,
        &boot_sector(&[], 0, &[record(0x83, 2, 6), record(0x83, 1, 2)]),
    );
    let c = parse(&overlapping);
    assert!(
        has_note(&c, "overlaps a listed partition; skipped"),
        "{:?}",
        c.notes
    );
}

#[test]
fn weak_detection_refuses_boot_sectors_and_inconsistent_tables() {
    let valid = boot_sector(&[], 0, &[record(0x83, 1, 3)]);
    assert_eq!(
        partitions::detect_weak(&mbr_disk(&valid, 4)),
        Some(Layout::Mbr)
    );

    let mut fat = mbr_disk(&valid, 4);
    put(&mut fat, 0, &[0xeb, 0x3c, 0x90]);
    put(&mut fat, 3, b"MSDOS5.0");
    put(&mut fat, 0x0b, &512u16.to_le_bytes());
    fat[0x0d] = 1;
    put(&mut fat, 0x0e, &1u16.to_le_bytes());
    fat[0x10] = 2;
    fat[0x15] = 0xf8;
    let mut ntfs = mbr_disk(&valid, 4);
    put(&mut ntfs, 3, b"NTFS    ");
    let mut exfat = mbr_disk(&valid, 4);
    put(&mut exfat, 3, b"EXFAT   ");
    let bad_indicator = mbr_disk(
        &boot_sector(
            &[],
            0,
            &[MbrRecord {
                boot: 0x01,
                ..record(0x83, 1, 3)
            }],
        ),
        4,
    );
    let overlapping = mbr_disk(
        &boot_sector(&[], 0, &[record(0x83, 1, 3), record(0x83, 3, 1)]),
        4,
    );
    let beyond = mbr_disk(&boot_sector(&[], 0, &[record(0x83, 4, 4)]), 4);
    let at_zero = mbr_disk(&boot_sector(&[], 0, &[record(0x83, 0, 4)]), 4);
    let empty = mbr_disk(&boot_sector(&[], 0, &[]), 4);
    let typeless = mbr_disk(&boot_sector(&[], 0, &[record(0x00, 1, 3)]), 4);
    let mut unsigned = mbr_disk(&valid, 4);
    unsigned[511] = 0;
    for (name, disk) in [
        ("FAT", &fat),
        ("NTFS", &ntfs),
        ("exFAT", &exfat),
        ("boot indicator", &bad_indicator),
        ("overlap", &overlapping),
        ("beyond", &beyond),
        ("sector 0", &at_zero),
        ("empty", &empty),
        ("type 0", &typeless),
        ("signature", &unsigned),
    ] {
        assert_eq!(partitions::detect_weak(disk), None, "{name}");
        assert!(
            !matches!(
                detect_format(disk),
                DetectedFormat::Container {
                    kind: zrax::formats::container::Kind::Partitions(_)
                }
            ),
            "{name}"
        );
    }
    assert!(parse_error(&fat, Layout::Mbr).contains("volume boot record"));
    assert!(
        parse_error(&overlapping, Layout::Mbr).contains("Invalid MBR: partitions 1 and 2 overlap")
    );
    assert!(parse_error(&beyond, Layout::Mbr).contains("beyond the end of the file"));
    assert!(parse_error(&bad_indicator, Layout::Mbr).contains("boot indicator 0x01"));
    assert!(parse_error(&empty, Layout::Mbr).contains("Missing partitions"));
    assert!(parse_error(&unsigned, Layout::Mbr).contains("Missing MBR boot signature"));
}

// ---------------------------------------------------------------------------
// GPT
// ---------------------------------------------------------------------------

#[test]
fn gpt_partitions_hold_an_ext_filesystem_and_bios_boot_code() {
    let ext4 = fixture("ext/ext4.img");
    let blocks = (ext4.len() / SECTOR) as u64;
    let geometry = GptGeometry {
        block: SECTOR,
        blocks: 2048 + blocks + 33 + 34,
        entry_count: 128,
        entry_size: 128,
    };
    let mut disk = gpt_disk(
        geometry,
        &[
            entry(BIOS_BOOT, 34, 2047, ""),
            entry(LINUX_FILESYSTEM, 2048, 2048 + blocks - 1, "root"),
            entry(EFI_SYSTEM, 2048 + blocks, 2048 + blocks + 33, "EFI"),
        ],
    );
    put(&mut disk, 34 * SECTOR, &x86_bootstrap());
    put(&mut disk, 2048 * SECTOR, &ext4);
    let c = parse(&disk);
    assert_eq!(
        labels(&c),
        [
            "Partition 1 (BIOS boot)",
            "Partition 2 \"root\" (Linux filesystem)",
            "Partition 3 \"EFI\" (EFI System)",
        ]
    );
    assert_eq!(c.children[0].classify, Classify::Always);
    assert!(c.children[0].target.is_none(), "no ISA from the type GUID");
    assert!(
        has_note(&c, "Partition 1 (BIOS boot): a BIOS boot partition"),
        "{:?}",
        c.notes
    );
    let p = classify(&disk);
    let root = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Partition 2 \"root\" (Linux filesystem)"))
        .expect("root slice");
    assert_eq!(root.isa, Isa::X86_64);
    assert_eq!((root.offset, root.size), (2048 * 512, ext4.len() as u64));
    assert!(p
        .slices
        .iter()
        .any(|s| s.label.as_deref() == Some("Partition 1 (BIOS boot)")));
    assert!(
        p.slices
            .iter()
            .all(|s| s.label.as_deref() != Some("Partition 3 \"EFI\" (EFI System)")),
        "an empty ESP is not listed"
    );
}

#[test]
fn gpt_with_4096_byte_blocks_is_found_at_0x1000() {
    // 128 entries of 128 B fill four blocks: usable LBAs 6-69 on 76 blocks.
    let geometry = GptGeometry {
        block: 4096,
        blocks: 76,
        entry_count: 128,
        entry_size: 128,
    };
    let ext2 = fixture("ext/ext2.img");
    let mut disk = gpt_disk(geometry, &[entry(LINUX_FILESYSTEM, 6, 69, "data")]);
    put(&mut disk, 6 * 4096, &ext2);
    assert_eq!(partitions::detect(&disk), Some(Layout::Gpt));
    let c = parse(&disk);
    assert!(has_note(&c, "4096 B logical blocks"), "{:?}", c.notes);
    assert_eq!(metadata(&c, "partitions_gpt_block_size"), "4096");
    let data = child(&c, "Partition 1 \"data\" (Linux filesystem)");
    assert_eq!((data.offset, data.stored_size), (6 * 4096, 64 * 4096));
    let p = classify(&disk);
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn gpt_metadata_names_guids_and_attributes() {
    let (geometry, _) = small_gpt();
    let mut flagged = entry(LINUX_FILESYSTEM, 3, 6, "root");
    flagged.attributes = 0b101 | (1 << 60);
    let disk = gpt_disk(geometry, &[flagged]);
    let c = parse(&disk);
    assert_eq!(metadata(&c, "partitions_gpt_disk_guid"), DISK_GUID);
    assert_eq!(
        metadata(&c, "partitions_gpt_entry_1"),
        format!(
            "type {LINUX_FILESYSTEM}; unique 5A524158-0000-4000-8000-000000000001; LBA 3-6; \
             attributes 0x1000000000000005 (required, legacy BIOS bootable)"
        )
    );
}

#[test]
fn protective_mbr_without_a_header_is_a_gpt_parse_error() {
    let protective = mbr_disk(&boot_sector(&[], 0, &[record(0xee, 1, 63)]), 64);
    assert_eq!(partitions::detect(&protective), None);
    assert_eq!(partitions::detect_weak(&protective), Some(Layout::Gpt));
    let error = parse_error(&protective, Layout::Gpt);
    assert!(
        error.starts_with("Partition table parse error: Missing GPT header"),
        "{error}"
    );
    let misplaced = mbr_disk(&boot_sector(&[], 0, &[record(0xee, 2, 62)]), 64);
    assert_eq!(
        partitions::detect_weak(&misplaced),
        None,
        "a 0xEE record not at LBA 1"
    );
}

#[test]
fn corrupt_primary_falls_back_to_a_valid_backup() {
    let (_, disk) = small_gpt();
    let mut damaged = disk.clone();
    damaged[SECTOR + 40] ^= 1;
    let c = parse(&damaged);
    assert!(
        has_note(
            &c,
            "The primary GPT header is not valid (Invalid GPT header CRC-32 at LBA 1"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "read from the backup header at LBA 19"));
    assert_eq!(c.children.len(), 2);
    // Without the signature at LBA 1, the protective MBR still leads here.
    let mut erased = disk.clone();
    erased[SECTOR..2 * SECTOR].fill(0);
    assert_eq!(detected(&erased), Some(Layout::Gpt));
    assert!(has_note(
        &parse(&erased),
        "no \"EFI PART\" signature at LBA 1"
    ));
    // With both copies damaged, the primary's error is reported.
    damaged[19 * SECTOR + 40] ^= 1;
    assert!(parse_error(&damaged, Layout::Gpt).contains("Invalid GPT header CRC-32 at LBA 1"));
}

/// A GPT field changed to an invalid value, and the error it causes.
struct FieldCase {
    name: &'static str,
    mutate: fn(&mut [u8]),
    message: &'static str,
}

#[test]
fn corrupted_gpt_fields_and_checksums_are_errors() {
    let (_, disk) = small_gpt();
    let mut array_crc = disk.clone();
    array_crc[2 * SECTOR + 60] ^= 1;
    array_crc[18 * SECTOR + 60] ^= 1;
    assert!(parse_error(&array_crc, Layout::Gpt)
        .contains("Invalid GPT partition entry array CRC-32 at LBA 2"));

    let cases = [
        FieldCase {
            name: "my lba",
            mutate: |d| put64(d, SECTOR + 24, 5),
            message: "MyLBA is 5",
        },
        FieldCase {
            name: "header size",
            mutate: |d| put32(d, SECTOR + 12, 91),
            message: "Invalid GPT header size 91 B",
        },
        FieldCase {
            name: "entry size",
            mutate: |d| put32(d, SECTOR + 84, 96),
            message: "Invalid GPT partition entry size 96 B",
        },
        FieldCase {
            name: "entry count",
            mutate: |d| put32(d, SECTOR + 80, 0),
            message: "no partition entries",
        },
        FieldCase {
            name: "usable range",
            mutate: |d| put64(d, SECTOR + 40, 18),
            message: "first usable LBA 18 after last usable LBA 17",
        },
        FieldCase {
            name: "array position",
            mutate: |d| put64(d, SECTOR + 72, 4),
            message: "Invalid GPT partition entry array at LBA 4",
        },
        FieldCase {
            name: "reversed entry",
            mutate: |d| put64(d, 2 * SECTOR + 32, 7),
            message: "first LBA 7 after last LBA 6",
        },
    ];
    for case in cases {
        let mut mutated = disk.clone();
        (case.mutate)(&mut mutated);
        reseal_gpt(&mut mutated, SECTOR, 1);
        // Damage the backup too, so the primary's error is the result.
        mutated[19 * SECTOR] = 0;
        let error = parse_error(&mutated, Layout::Gpt);
        assert!(error.contains(case.message), "{}: {error}", case.name);
    }
}

#[test]
fn overlapping_and_misplaced_entries_are_errors_and_late_ends_are_noted() {
    let geometry = GptGeometry {
        block: SECTOR,
        blocks: 20,
        entry_count: 4,
        entry_size: 128,
    };
    let overlapping = gpt_disk(
        geometry,
        &[
            entry(LINUX_FILESYSTEM, 3, 6, ""),
            entry(LINUX_FILESYSTEM, 6, 8, ""),
        ],
    );
    assert!(parse_error(&overlapping, Layout::Gpt)
        .contains("entries 1 and 2: their LBA ranges overlap"));
    let early = gpt_disk(geometry, &[entry(LINUX_FILESYSTEM, 2, 6, "")]);
    assert!(parse_error(&early, Layout::Gpt).contains("starts before the first usable LBA 3"));
    let late = gpt_disk(geometry, &[entry(LINUX_FILESYSTEM, 3, 40, "grow")]);
    let c = parse(&late);
    assert!(
        has_note(
            &c,
            "Partitions that end after the last usable LBA 17: Partition 1"
        ),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(&c, "Partitions that end beyond the end of the file"),
        "{:?}",
        c.notes
    );
}

#[test]
fn stale_gpt_behind_a_legacy_mbr_is_not_read() {
    let (_, mut disk) = small_gpt();
    put(&mut disk, 0, &boot_sector(&[], 0, &[record(0x83, 3, 8)]));
    assert_eq!(partitions::detect(&disk), None);
    assert_eq!(partitions::detect_weak(&disk), Some(Layout::Mbr));
    let c = parse(&disk);
    assert!(
        has_note(&c, "the GPT is treated as stale and not read"),
        "{:?}",
        c.notes
    );
    assert_eq!(labels(&c), ["Partition 1 (Linux, type 0x83)"]);
}

#[test]
fn hybrid_mbr_and_missing_mbr_are_noted() {
    let (_, mut disk) = small_gpt();
    put(
        &mut disk,
        0,
        &boot_sector(
            &x86_bootstrap(),
            0,
            &[record(0xee, 1, 2), record(0x0c, 3, 4)],
        ),
    );
    let c = parse(&disk);
    assert!(
        has_note(
            &c,
            "Hybrid MBR at LBA 0: a protective record and 1 further partition record, not listed"
        ),
        "{:?}",
        c.notes
    );
    assert_eq!(
        c.children[0].label, "MBR bootstrap code",
        "the protective MBR's code is classified"
    );
    let (_, mut bare) = small_gpt();
    bare[..SECTOR].fill(0);
    let c = parse(&bare);
    assert!(
        has_note(&c, "LBA 0 has no MBR boot signature"),
        "{:?}",
        c.notes
    );
}

#[test]
fn backup_problems_are_notes_not_errors() {
    let (_, disk) = small_gpt();
    let mut damaged = disk.clone();
    damaged[19 * SECTOR + 40] ^= 1;
    assert!(has_note(
        &parse(&damaged),
        "Backup GPT header at LBA 19 is not valid: Invalid GPT header CRC-32 at LBA 19"
    ));
    let mut differing = disk.clone();
    differing[18 * SECTOR + 100] ^= 1;
    reseal_gpt(&mut differing, SECTOR, 19);
    assert!(has_note(
        &parse(&differing),
        "its entry array differs from the primary's"
    ));
}

// ---------------------------------------------------------------------------
// Apple Partition Map
// ---------------------------------------------------------------------------

#[test]
fn apm_boot_code_is_classified_for_the_processor_it_names() {
    let disk = small_apm();
    let c = parse(&disk);
    assert_eq!(
        labels(&c),
        [
            "Partition 2 \"Macintosh\" (Apple_Driver43)",
            "Partition 2 \"Macintosh\" (Apple_Driver43) boot code",
            "Partition 3 \"MacOS\" (Apple_HFS)",
        ]
    );
    let boot = child(&c, "Partition 2 \"Macintosh\" (Apple_Driver43) boot code");
    assert_eq!((boot.offset, boot.stored_size), (4 * SECTOR, 64));
    assert_eq!(boot.classify, Classify::Code);
    assert_eq!(boot.target.map(|t| t.isa), Some(Isa::M68k));
    assert_eq!(boot.variant, Some("68020"));
    assert!(
        has_note(
            &c,
            "Driver descriptor lists 1 driver: block 4 (1 KiB, type 1)"
        ),
        "{:?}",
        c.notes
    );
    assert!(
        has_note(
            &c,
            "boot code 64 B at 0x800 (pmProcessor 68020), load address 0x00010000"
        ),
        "{:?}",
        c.notes
    );
    assert!(has_note(&c, "checksum 0x00001234 not verified"));
    let p = classify(&disk);
    let slice = p
        .slices
        .iter()
        .find(|s| {
            s.label.as_deref() == Some("Partition 2 \"Macintosh\" (Apple_Driver43) boot code")
        })
        .expect("boot slice");
    assert_eq!(slice.isa, Isa::M68k);
    assert_eq!(p.primary.isa, Isa::M68k);
}

#[test]
fn apm_boot_code_without_a_known_processor_goes_to_the_code_model() {
    let driver = ApmEntry {
        boot_size: 64,
        processor: "powerpc",
        ..apm_entry("Driver", "Apple_Driver", 2, 2)
    };
    let disk = apm_disk(SECTOR, 4, &[driver], &[]);
    let c = parse(&disk);
    let boot = child(&c, "Partition 1 \"Driver\" (Apple_Driver) boot code");
    assert_eq!(boot.target, None);
    assert_eq!(boot.classify, Classify::Code);
    let outside = ApmEntry {
        boot_size: 4096,
        ..apm_entry("Driver", "Apple_Driver", 2, 2)
    };
    let disk = apm_disk(SECTOR, 4, &[outside], &[]);
    let c = parse(&disk);
    assert!(
        has_note(&c, "lies outside the partition; not classified"),
        "{:?}",
        c.notes
    );
}

#[test]
fn apm_partition_holding_an_ext_filesystem_and_free_space() {
    let ext2 = fixture("ext/ext2.img");
    let blocks = (ext2.len() / SECTOR) as u32;
    let mut disk = apm_disk(
        SECTOR,
        8 + blocks + 8,
        &[
            apm_entry("Apple", "Apple_partition_map", 1, 7),
            apm_entry("root", "Linux", 8, blocks),
            apm_entry("Extra", "Apple_Free", 8 + blocks, 8),
        ],
        &[],
    );
    put(&mut disk, 8 * SECTOR, &ext2);
    let c = parse(&disk);
    assert_eq!(labels(&c), ["Partition 2 \"root\" (Linux)"]);
    assert!(has_note(
        &c,
        "Partition 3 \"Extra\" (Apple_Free): free space; not classified"
    ));
    assert_eq!(classify(&disk).primary.isa, Isa::X86_64);
}

#[test]
fn apm_with_2048_byte_blocks_reads_entries_at_that_stride() {
    let disk = apm_disk(
        2048,
        8,
        &[
            apm_entry("Apple", "Apple_partition_map", 1, 2),
            apm_entry("CD", "Apple_HFS", 3, 5),
        ],
        &[],
    );
    assert_eq!(partitions::detect(&disk), Some(Layout::ApplePartitionMap));
    let c = parse(&disk);
    let hfs = child(&c, "Partition 2 \"CD\" (Apple_HFS)");
    assert_eq!((hfs.offset, hfs.stored_size), (3 * 2048, 5 * 2048));
}

#[test]
fn corrupted_apm_fields_are_errors() {
    let disk = small_apm();
    let mut old = disk.clone();
    put(&mut old, SECTOR, b"TS");
    assert_eq!(partitions::detect(&old), Some(Layout::ApplePartitionMap));
    assert!(parse_error(&old, Layout::ApplePartitionMap)
        .contains("Unsupported old-format partition map (signature TS) at block 1"));

    let mut inconsistent = disk.clone();
    put32_be(&mut inconsistent, 2 * SECTOR + 4, 4);
    assert_eq!(
        partitions::detect(&inconsistent),
        None,
        "entries present disagree on the map size"
    );
    assert!(parse_error(&inconsistent, Layout::ApplePartitionMap)
        .contains("pmMapBlkCnt 4 differs from entry 1's 3"));

    let mut unsigned = disk.clone();
    put(&mut unsigned, 3 * SECTOR, b"XX");
    assert!(parse_error(&unsigned, Layout::ApplePartitionMap)
        .contains("Missing partition map entry signature PM at block 3 (0x600)"));

    let mut at_zero = disk.clone();
    put32_be(&mut at_zero, 3 * SECTOR + 8, 0);
    assert!(parse_error(&at_zero, Layout::ApplePartitionMap)
        .contains("starts at block 0, the driver descriptor record"));

    let mut overlapping = disk.clone();
    put32_be(&mut overlapping, 3 * SECTOR + 8, 5);
    assert!(parse_error(&overlapping, Layout::ApplePartitionMap)
        .contains("the partitions of entries 2 and 3 overlap"));

    let mut block_size = disk.clone();
    put16_be(&mut block_size, 2, 600);
    assert_eq!(partitions::detect(&block_size), None);
    assert!(parse_error(&block_size, Layout::ApplePartitionMap)
        .contains("Invalid driver descriptor block size 600 B"));

    let mut drivers = disk.clone();
    put16_be(&mut drivers, 16, 62);
    assert!(parse_error(&drivers, Layout::ApplePartitionMap).contains("62 drivers, at most 61"));

    let mut truncated_map = disk.clone();
    for number in 1..=3 {
        put32_be(&mut truncated_map, number * SECTOR + 4, 30);
    }
    assert!(parse_error(&truncated_map, Layout::ApplePartitionMap)
        .contains("Truncated partition map: 30 entries"));
    assert!(partitions::detect(&b"ERROR: this is text\n".repeat(64)).is_none());
}

// ---------------------------------------------------------------------------
// Disk images inside other containers
// ---------------------------------------------------------------------------

#[test]
fn gpt_disk_image_inside_a_tar_archive_is_classified() {
    let ext2 = fixture("ext/ext2.img");
    let blocks = (ext2.len() / SECTOR) as u64;
    let geometry = GptGeometry {
        block: SECTOR,
        blocks: 40 + blocks + 33,
        entry_count: 128,
        entry_size: 128,
    };
    let mut disk = gpt_disk(
        geometry,
        &[entry(LINUX_FILESYSTEM, 40, 40 + blocks - 1, "root")],
    );
    put(&mut disk, 40 * SECTOR, &ext2);
    let archive = tar_with("disk.img", &disk);
    let p = classify(&archive);
    assert_eq!(p.format.format, FileFormat::Tar);
    let member = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("disk.img"))
        .expect("disk image member");
    assert_eq!((member.offset, member.size), (512, disk.len() as u64));
    assert_eq!(member.isa, Isa::X86_64, "from the ext partition inside");
}

#[test]
fn mbr_member_is_listed_only_when_a_partition_starts_in_the_recognition_prefix() {
    // Archives check a member's first 4 KiB before the whole member, and an
    // MBR is recognized only when its partitions start inside the bytes
    // examined: sector 8 (4 KiB) is just outside.
    let late = tar_with("late.img", &mbr_with_ext2());
    assert!(classify(&late).slices.is_empty());
    let ext2 = fixture("ext/ext2.img");
    let sectors = (ext2.len() / SECTOR) as u32;
    let mut early = mbr_disk(&boot_sector(&[], 0, &[record(0x83, 2, sectors)]), 2 + 512);
    put(&mut early, 2 * SECTOR, &ext2);
    let p = classify(&tar_with("early.img", &early));
    let member = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("early.img"))
        .expect("listed");
    assert_eq!(member.isa, Isa::X86_64);
}

#[test]
fn mbr_disk_image_inside_an_android_sparse_image_is_classified() {
    let disk = mbr_with_ext2();
    let sparse = sparse_image(&disk, 4096);
    let p = classify(&sparse);
    assert_eq!(p.format.format, FileFormat::AndroidSparse);
    assert_eq!(p.primary.isa, Isa::X86_64, "{:?}", p.notes);
    assert!(
        payload_has_note(&p, "contained MBR partition table"),
        "{:?}",
        p.notes
    );
}

// ---------------------------------------------------------------------------
// Sweeps
// ---------------------------------------------------------------------------

/// The small synthetic tables of each layout.
fn sweep_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("ebr", ebr_disk(false)),
        ("gpt", small_gpt().1),
        ("apm", small_apm()),
        (
            "bootstrap",
            mbr_disk(&boot_sector(&x86_bootstrap(), 7, &[record(0x83, 1, 7)]), 8),
        ),
    ]
}

#[test]
fn every_prefix_errors_or_keeps_its_children_inside() {
    for (name, disk) in sweep_fixtures() {
        for end in 0..disk.len() {
            let prefix = &disk[..end];
            let Some(layout) = detected(prefix) else {
                continue;
            };
            let Ok(c) = partitions::parse_container(prefix, layout) else {
                continue;
            };
            for child in &c.children {
                assert!(
                    child.offset + child.stored_size <= end,
                    "{name} prefix {end}: {}",
                    child.label
                );
                assert_eq!(child.data.len(), child.stored_size);
            }
        }
        // The GPT entry array must be whole: no prefix shorter than its end
        // parses.
        if name == "gpt" {
            for end in 0..3 * SECTOR {
                assert!(
                    partitions::parse_container(&disk[..end], Layout::Gpt).is_err(),
                    "gpt prefix {end}"
                );
            }
        }
    }
}

#[test]
fn prefixes_classify_without_panicking() {
    let options = ClassifierOptions::new();
    for (_, disk) in sweep_fixtures() {
        for end in (0..disk.len()).step_by(7) {
            let _ = detect_payload(&disk[..end], &options);
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let options = ClassifierOptions::new();
    for (name, disk) in sweep_fixtures() {
        // Every byte of the tables (the first three sectors, the EBRs, the
        // GPT backup) and every 13th byte elsewhere.
        let is_table = |i: usize| i < 3 * SECTOR || [4, 10, 16, 17, 19].contains(&(i / SECTOR));
        for i in (0..disk.len()).filter(|&i| is_table(i) || i % 13 == 0) {
            for value in [0x00, 0xff, disk[i] ^ 0x01] {
                let mut mutated = disk.clone();
                mutated[i] = value;
                if let Some(layout) = detected(&mutated) {
                    let _ = partitions::parse_container(&mutated, layout);
                }
                if name == "gpt" && i < 3 * SECTOR {
                    reseal_gpt(&mut mutated, SECTOR, 1);
                    let _ = partitions::parse_container(&mutated, Layout::Gpt);
                }
                if i % 31 == 0 {
                    let _ = detect_payload(&mutated, &options);
                }
            }
        }
    }
}

#[test]
fn hdiutil_fixture_mutations_never_panic() {
    for name in ["apm", "gpt", "mbr"] {
        let image = hdiutil_image(name);
        let table = &image[..34 * SECTOR];
        for i in (0..table.len()).filter(|&i| i < 2 * SECTOR || i % 7 == 0) {
            for value in [0x00, 0xff, table[i] ^ 0x80] {
                let mut mutated = table.to_vec();
                mutated[i] = value;
                if let Some(layout) = detected(&mutated) {
                    let _ = partitions::parse_container(&mutated, layout);
                }
            }
        }
    }
}
