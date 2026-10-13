//! ISO 9660 images: bsdtar (libarchive) and hdiutil fixtures with Rock
//! Ridge, Joliet, El Torito and a UDF bridge; synthetic images built from
//! the ECMA-119, SUSP/RRIP and El Torito layouts for name sources, Rock
//! Ridge relocation and continuation areas, boot images of every platform
//! and emulation, multi-extent files, cycles and hybrid system areas;
//! descriptor, directory and catalog damage; and truncation and mutation
//! sweeps.

#[path = "support/truncated_volume.rs"]
mod truncated_volume;

use std::borrow::Cow;
use truncated_volume::{assert_members_inside, prefix_ends};
use zrax::formats::compressed::{self, Codec};
use zrax::formats::container::{self, Child, Classify, Container, Kind, Target};
use zrax::formats::iso9660::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::types::ContainedArch;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// A committed image, stored with `gzip -9 -n` (README.md).
fn iso_fixture(name: &str) -> Vec<u8> {
    let stored = fixture(&format!("iso9660/{name}.iso.gz"));
    compressed::decode(Codec::Gzip, &stored)
        .expect("fixture decompresses")
        .data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse(image: &[u8]) -> Container<'_> {
    container::parse(image, Kind::Iso9660(Layout::Iso9660)).expect("parses")
}

fn parse_error(image: &[u8]) -> String {
    container::parse(image, Kind::Iso9660(Layout::Iso9660))
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
        .unwrap_or_else(|| panic!("no child {label} in {:?}", labels(c)))
}

fn notes(c: &Container<'_>) -> String {
    c.notes.join("\n")
}

fn has_note(c: &Container<'_>, text: &str) -> bool {
    c.notes.iter().any(|note| note.contains(text))
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| {
            let found: Vec<_> = payload.slices.iter().map(|s| s.label.clone()).collect();
            panic!("no slice {label} in {found:?}")
        })
}

fn metadata(payload: &DetectionPayload, key: &str) -> String {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
        .unwrap_or_else(|| panic!("metadata {key}"))
}

fn is_detected(data: &[u8]) -> bool {
    matches!(
        detect_format(data),
        DetectedFormat::Container {
            kind: Kind::Iso9660(Layout::Iso9660)
        }
    )
}

// Wire layout: ECMA-119 4th edition (2019), SUSP and RRIP 1.12, El Torito
// 1.0. Logical sectors and blocks are 2048 bytes in every synthetic image.

const SECTOR: usize = 2048;

/// Volume descriptor types (ECMA-119 8.1.1).
const TYPE_BOOT_RECORD: u8 = 0;
const TYPE_PRIMARY: u8 = 1;
const TYPE_SUPPLEMENTARY: u8 = 2;
const TYPE_TERMINATOR: u8 = 255;

/// File flags (9.1.6, Table 10).
const FLAG_DIRECTORY: u8 = 0x02;
const FLAG_ASSOCIATED: u8 = 0x04;
const FLAG_MULTI_EXTENT: u8 = 0x80;

/// POSIX modes for `PX` (RRIP 4.1.1, Table 1).
const MODE_DIRECTORY: u32 = 0o040_755;
const MODE_REGULAR: u32 = 0o100_644;
const MODE_SYMLINK: u32 = 0o120_777;

/// El Torito catalog values (figures 2-5).
const PLATFORM_X86: u8 = 0;
const PLATFORM_POWERPC: u8 = 1;
const PLATFORM_EFI: u8 = 0xEF;
const MEDIA_NO_EMULATION: u8 = 0;
const MEDIA_FLOPPY_1440: u8 = 2;
const MEDIA_HARD_DISK: u8 = 4;

/// Sectors of the synthetic layout. Descriptors start at 16.
const PATH_L: u32 = 22;
const PATH_M: u32 = 23;
const ROOT: u32 = 24;
const BIN: u32 = 25;
const JOLIET_ROOT: u32 = 26;
const JOLIET_BIN: u32 = 27;
const CONTINUATION: u32 = 28;
const RR_MOVED: u32 = 29;
const DEEP: u32 = 30;
const CATALOG: u32 = 31;
const BOOT_X86: u32 = 32;
const BOOT_EFI: u32 = 33;
const README: u32 = 35;
const PAYLOAD: u32 = 36;
const PSX: u32 = 37;
const DEEP_ELF: u32 = 39;
const VOLUME_SECTORS: u32 = 40;

/// Size in bytes of the PS-X EXE member: a 0x800-byte header and one
/// 0x800-byte text sector.
const PSX_SIZE: usize = 2 * SECTOR;

/// x86 real-mode code of `fixtures/iso9660/boot.asm` (nasm 3.02): `cli`,
/// clear `ds`, `es`, `ss`, set `sp`, `sti`, `cld`, `mov si, message`, then
/// a `lodsb`/`int 10h` teletype loop and `hlt`.
const BOOT_CODE: [u8; 34] = [
    0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB, 0xFC, 0xBE, 0x22,
    0x7C, 0xAC, 0x84, 0xC0, 0x74, 0x09, 0xB4, 0x0E, 0xBB, 0x07, 0x00, 0xCD, 0x10, 0xEB, 0xF2, 0xF4,
    0xEB, 0xFD,
];

fn at(sector: u32) -> usize {
    sector as usize * SECTOR
}

/// A 16-bit number in both byte orders (ECMA-119 7.2.3).
fn both16(value: u16) -> Vec<u8> {
    [value.to_le_bytes(), value.to_be_bytes()].concat()
}

/// A 32-bit number in both byte orders (7.3.3).
fn both32(value: u32) -> Vec<u8> {
    [value.to_le_bytes(), value.to_be_bytes()].concat()
}

fn put(image: &mut [u8], offset: usize, bytes: &[u8]) {
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// A directory record (9.1, Table 8): length, EAR length 0, extent and
/// data length in both byte orders, a zero recording time, flags, no
/// interleaving, volume sequence number 1, identifier length and
/// identifier, a padding byte after an even-length identifier, then the
/// system use field.
fn record(identifier: &[u8], extent: u32, size: u32, flags: u8, system_use: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 33];
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(size));
    r[25] = flags;
    r[28..32].copy_from_slice(&both16(1));
    r[32] = u8::try_from(identifier.len()).unwrap();
    r.extend_from_slice(identifier);
    if identifier.len() % 2 == 0 {
        r.push(0);
    }
    r.extend_from_slice(system_use);
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r[0] = u8::try_from(r.len()).unwrap();
    r
}

/// A directory extent of one sector: the records in order, zero fill after
/// the last (6.8.1.1).
fn directory(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = records.concat();
    assert!(bytes.len() <= SECTOR, "a test directory fits in one sector");
    bytes.resize(SECTOR, 0);
    bytes
}

/// A SUSP entry (SUSP 4.1): signature, length, version 1, data.
fn sue(signature: &[u8; 2], data: &[u8]) -> Vec<u8> {
    let mut bytes = signature.to_vec();
    bytes.push(u8::try_from(4 + data.len()).unwrap());
    bytes.push(1);
    bytes.extend_from_slice(data);
    bytes
}

/// `SP` (SUSP 5.3): check bytes BE EF, no bytes skipped.
fn sp() -> Vec<u8> {
    sue(b"SP", &[0xBE, 0xEF, 0])
}

/// `CE` (SUSP 5.1): block, offset and length of the continuation area.
fn ce(block: u32, offset: u32, len: u32) -> Vec<u8> {
    sue(
        b"CE",
        &[both32(block), both32(offset), both32(len)].concat(),
    )
}

/// `ER` (SUSP 5.5): identifier length, no descriptor or source, version 1.
fn er(identifier: &[u8]) -> Vec<u8> {
    let mut data = vec![u8::try_from(identifier.len()).unwrap(), 0, 0, 1];
    data.extend_from_slice(identifier);
    sue(b"ER", &data)
}

/// `NM` (RRIP 4.1.4) with `flags` (bit 0 CONTINUE).
fn nm_with(flags: u8, name: &[u8]) -> Vec<u8> {
    let mut data = vec![flags];
    data.extend_from_slice(name);
    sue(b"NM", &data)
}

fn nm(name: &[u8]) -> Vec<u8> {
    nm_with(0, name)
}

/// `PX` (RRIP 4.1.1, 1.12 form): mode, links, uid, gid, serial number.
fn px(mode: u32) -> Vec<u8> {
    sue(
        b"PX",
        &[both32(mode), both32(1), both32(0), both32(0), both32(0)].concat(),
    )
}

/// `CL`, `PL` (RRIP 4.1.5.1-2): a directory location; `RE` (4.1.5.3).
fn cl(block: u32) -> Vec<u8> {
    sue(b"CL", &both32(block))
}

fn pl(block: u32) -> Vec<u8> {
    sue(b"PL", &both32(block))
}

fn re() -> Vec<u8> {
    sue(b"RE", &[])
}

/// A Joliet identifier: UCS-2, big-endian (ECMA-119 Annex C.3.4).
fn ucs2(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// A fixed-length character field padded with spaces (7.4.5).
fn padded(text: &[u8], len: usize) -> Vec<u8> {
    let mut field = text.to_vec();
    field.resize(len, b' ');
    field
}

/// The fields a volume descriptor in these tests varies.
struct VolumeFields<'a> {
    kind: u8,
    /// Escape sequences (offset 88), for supplementary descriptors.
    escape: &'a [u8],
    volume_id: Vec<u8>,
    root: u32,
    path_table_size: u32,
}

/// A primary or supplementary volume descriptor (Tables 4 and 6): system
/// identifier "ZRAX", volume space of [`VOLUME_SECTORS`] blocks, a set of
/// one volume, 2048-byte blocks, type L and M path tables at [`PATH_L`] and
/// [`PATH_M`], a one-sector root directory, a creation time, file structure
/// version 1.
fn volume_descriptor(fields: &VolumeFields<'_>) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = fields.kind;
    put(&mut d, 1, b"CD001");
    d[6] = 1;
    put(&mut d, 8, &padded(b"ZRAX", 32));
    put(&mut d, 40, &fields.volume_id);
    put(&mut d, 80, &both32(VOLUME_SECTORS));
    put(&mut d, 88, fields.escape);
    put(&mut d, 120, &both16(1));
    put(&mut d, 124, &both16(1));
    put(&mut d, 128, &both16(2048));
    put(&mut d, 132, &both32(fields.path_table_size));
    put(&mut d, 140, &PATH_L.to_le_bytes());
    put(&mut d, 148, &PATH_M.to_be_bytes());
    put(
        &mut d,
        156,
        &record(&[0], fields.root, 2048, FLAG_DIRECTORY, &[]),
    );
    put(&mut d, 318, &padded(b"ZRAX TESTS", 128));
    put(&mut d, 813, b"2026101300000000");
    d[881] = 1;
    d
}

/// The volume descriptor set terminator (Table 3).
fn terminator() -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = TYPE_TERMINATOR;
    put(&mut d, 1, b"CD001");
    d[6] = 1;
    d
}

/// An El Torito boot record (El Torito figure 7): the boot system
/// identifier and the catalog sector at 0x47.
fn boot_record(catalog: u32) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    d[0] = TYPE_BOOT_RECORD;
    put(&mut d, 1, b"CD001");
    d[6] = 1;
    put(&mut d, 7, b"EL TORITO SPECIFICATION");
    put(&mut d, 0x47, &catalog.to_le_bytes());
    d
}

/// A volume structure descriptor of ECMA-167 (2/9.1): type 0, the
/// identifier, version 1.
fn udf_descriptor(identifier: &[u8; 5]) -> Vec<u8> {
    let mut d = vec![0u8; SECTOR];
    put(&mut d, 1, identifier);
    d[6] = 1;
    d
}

/// A path table (9.4, Table 11) with records of identifier, extent and
/// parent number, in the byte order `le` selects.
fn path_table(records: &[(&[u8], u32, u16)], le: bool) -> Vec<u8> {
    let mut table = Vec::new();
    for &(identifier, extent, parent) in records {
        table.push(u8::try_from(identifier.len()).unwrap());
        table.push(0);
        if le {
            table.extend_from_slice(&extent.to_le_bytes());
            table.extend_from_slice(&parent.to_le_bytes());
        } else {
            table.extend_from_slice(&extent.to_be_bytes());
            table.extend_from_slice(&parent.to_be_bytes());
        }
        table.extend_from_slice(identifier);
        if identifier.len() % 2 == 1 {
            table.push(0);
        }
    }
    table
}

/// The path table records of the primary hierarchy: root, BIN, RR_MOVED
/// and RR_MOVED/DEEP (6.9.1 order).
const PATH_RECORDS: [(&[u8], u32, u16); 4] = [
    (&[0], ROOT, 1),
    (b"BIN", BIN, 1),
    (b"RR_MOVED", RR_MOVED, 1),
    (b"DEEP", DEEP, 3),
];

/// El Torito validation entry (figure 2) for `platform`, with the checksum
/// word that makes the 16 words sum to 0.
fn validation_entry(platform: u8) -> Vec<u8> {
    let mut entry = vec![0u8; 32];
    entry[0] = 1;
    entry[1] = platform;
    put(&mut entry, 4, b"ZRAX");
    entry[30] = 0x55;
    entry[31] = 0xAA;
    let sum = entry.chunks_exact(2).fold(0u16, |s, w| {
        s.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
    });
    put(&mut entry, 28, &0u16.wrapping_sub(sum).to_le_bytes());
    entry
}

/// A default or section entry (figures 3 and 5): boot indicator 0x88 or
/// 0x00, media type, load segment 0, sector count, load RBA.
fn boot_entry(bootable: bool, media: u8, sector_count: u16, load_rba: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 32];
    entry[0] = if bootable { 0x88 } else { 0x00 };
    entry[1] = media;
    put(&mut entry, 6, &sector_count.to_le_bytes());
    put(&mut entry, 8, &load_rba.to_le_bytes());
    entry
}

/// A section header (figure 4): 0x91 for the final one, platform, count.
fn section_header(last: bool, platform: u8, count: u16) -> Vec<u8> {
    let mut entry = vec![0u8; 32];
    entry[0] = if last { 0x91 } else { 0x90 };
    entry[1] = platform;
    put(&mut entry, 2, &count.to_le_bytes());
    put(&mut entry, 4, b"ZRAX SECTION");
    entry
}

/// The default catalog: an 80x86 validation entry, a bootable no-emulation
/// default entry loading 4 virtual sectors from [`BOOT_X86`], and a final
/// EFI section with one no-emulation entry of 8 virtual sectors at
/// [`BOOT_EFI`].
fn default_catalog() -> Vec<u8> {
    [
        validation_entry(PLATFORM_X86),
        boot_entry(true, MEDIA_NO_EMULATION, 4, BOOT_X86),
        section_header(true, PLATFORM_EFI, 1),
        boot_entry(true, MEDIA_NO_EMULATION, 8, BOOT_EFI),
    ]
    .concat()
}

/// An ELF64 little-endian header (`ET_EXEC`, `e_machine`) and nonzero
/// filler up to 256 bytes.
fn elf64(machine: u16) -> Vec<u8> {
    let mut data: Vec<u8> = (0..256).map(|i| (i % 251) as u8 | 1).collect();
    data[..64].fill(0);
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&machine.to_le_bytes());
    data
}

/// ELF `e_machine` values.
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// A PS-X EXE (psx-spx): ID, `pc0` and `t_addr` 0x80010000, `t_size`
/// 0x800, stack 0x801FFFF0 at 0x30, then one sector of MIPS I text (`lui`,
/// `addiu`, `jr ra`, `nop`, repeated).
fn psx_exe() -> Vec<u8> {
    let mut exe = vec![0u8; PSX_SIZE];
    put(&mut exe, 0, b"PS-X EXE");
    put(&mut exe, 0x10, &0x8001_0000u32.to_le_bytes());
    put(&mut exe, 0x18, &0x8001_0000u32.to_le_bytes());
    put(&mut exe, 0x1C, &0x800u32.to_le_bytes());
    put(&mut exe, 0x30, &0x801F_FFF0u32.to_le_bytes());
    put(
        &mut exe,
        0x4C,
        b"Sony Computer Entertainment Inc. for zrax tests",
    );
    let words: [u32; 4] = [0x3C08_8001, 0x2508_0010, 0x03E0_0008, 0x0000_0000];
    for (i, chunk) in exe[0x800..].chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&words[i % 4].to_le_bytes());
    }
    exe
}

/// Text that no format recognizes.
const README_TEXT: &[u8] = b"plain text that no format recognizes\n";

/// What a synthetic image holds besides the primary hierarchy.
#[derive(Debug, Clone, Copy, Default)]
struct Options {
    /// SUSP and Rock Ridge entries in the primary hierarchy: `SP` and a
    /// `CE` to the `ER` entry in the root, `NM` and `PX` everywhere, and
    /// the DEEP directory relocated into RR_MOVED with `CL`, `RE` and `PL`.
    rock_ridge: bool,
    /// A Joliet supplementary volume descriptor and hierarchy.
    joliet: bool,
    /// An El Torito boot record and [`default_catalog`].
    el_torito: bool,
}

/// System use for a Rock Ridge record, or nothing.
fn su(options: Options, entries: &[Vec<u8>]) -> Vec<u8> {
    if options.rock_ridge {
        entries.concat()
    } else {
        Vec::new()
    }
}

/// The primary hierarchy:
///
/// - root ([`ROOT`]): `BIN/`, `DEEP` (a zero-length file; with Rock Ridge
///   its `CL` names the moved directory), `README.TXT;1`, `RR_MOVED/`;
/// - `BIN` ([`BIN`]): `MAIN.EXE;1` (PS-X EXE), `PAYLOAD.ELF;1` (x86-64
///   ELF), Rock Ridge name `payload-with-a-long-name.elf`;
/// - `RR_MOVED` ([`RR_MOVED`]): `DEEP/` (`RE`);
/// - `DEEP` ([`DEEP`]): `DEEP.ELF;1` (AArch64 ELF).
fn primary_hierarchy(options: Options, image: &mut [u8]) {
    let dot = |extent: u32, extra: &[Vec<u8>]| {
        let mut entries = vec![px(MODE_DIRECTORY)];
        entries.extend_from_slice(extra);
        record(&[0], extent, 2048, FLAG_DIRECTORY, &su(options, &entries))
    };
    let parent = |extent: u32| record(&[1], extent, 2048, FLAG_DIRECTORY, &[]);
    let er_entry = er(b"RRIP_1991A");
    let er_len = u32::try_from(er_entry.len()).unwrap();
    let root_dot = if options.rock_ridge {
        let entries = [sp(), px(MODE_DIRECTORY), ce(CONTINUATION, 0, er_len)].concat();
        record(&[0], ROOT, 2048, FLAG_DIRECTORY, &entries)
    } else {
        dot(ROOT, &[])
    };
    let root = directory(&[
        root_dot,
        parent(ROOT),
        record(
            b"BIN",
            BIN,
            2048,
            FLAG_DIRECTORY,
            &su(options, &[nm(b"bin"), px(MODE_DIRECTORY)]),
        ),
        record(
            b"DEEP",
            0,
            0,
            0,
            &su(options, &[nm(b"deep"), px(MODE_DIRECTORY), cl(DEEP)]),
        ),
        record(
            b"README.TXT;1",
            README,
            README_TEXT.len() as u32,
            0,
            &su(options, &[nm(b"readme.txt"), px(MODE_REGULAR)]),
        ),
        record(
            b"RR_MOVED",
            RR_MOVED,
            2048,
            FLAG_DIRECTORY,
            &su(options, &[nm(b"rr_moved"), px(MODE_DIRECTORY)]),
        ),
    ]);
    put(image, at(ROOT), &root);
    let bin = directory(&[
        dot(BIN, &[]),
        parent(ROOT),
        record(
            b"MAIN.EXE;1",
            PSX,
            PSX_SIZE as u32,
            0,
            &su(options, &[nm(b"main.exe"), px(MODE_REGULAR)]),
        ),
        record(
            b"PAYLOAD.ELF;1",
            PAYLOAD,
            256,
            0,
            &su(
                options,
                &[nm(b"payload-with-a-long-name.elf"), px(MODE_REGULAR)],
            ),
        ),
    ]);
    put(image, at(BIN), &bin);
    let moved = directory(&[
        dot(RR_MOVED, &[]),
        parent(ROOT),
        record(
            b"DEEP",
            DEEP,
            2048,
            FLAG_DIRECTORY,
            &su(options, &[nm(b"deep"), px(MODE_DIRECTORY), re()]),
        ),
    ]);
    put(image, at(RR_MOVED), &moved);
    let deep_parent = record(
        &[1],
        RR_MOVED,
        2048,
        FLAG_DIRECTORY,
        &su(options, &[pl(ROOT)]),
    );
    let deep = directory(&[
        dot(DEEP, &[]),
        deep_parent,
        record(
            b"DEEP.ELF;1",
            DEEP_ELF,
            256,
            0,
            &su(options, &[nm(b"deep.elf"), px(MODE_REGULAR)]),
        ),
    ]);
    put(image, at(DEEP), &deep);
    if options.rock_ridge {
        put(image, at(CONTINUATION), &er_entry);
    }
}

/// The Joliet hierarchy: root ([`JOLIET_ROOT`]) with `bin` and
/// `readme.txt;1`; `bin` ([`JOLIET_BIN`]) with `main.exe;1` and
/// `payload-joliet.elf;1`, over the same file extents.
fn joliet_hierarchy(image: &mut [u8]) {
    let root = directory(&[
        record(&[0], JOLIET_ROOT, 2048, FLAG_DIRECTORY, &[]),
        record(&[1], JOLIET_ROOT, 2048, FLAG_DIRECTORY, &[]),
        record(&ucs2("bin"), JOLIET_BIN, 2048, FLAG_DIRECTORY, &[]),
        record(
            &ucs2("readme.txt;1"),
            README,
            README_TEXT.len() as u32,
            0,
            &[],
        ),
    ]);
    put(image, at(JOLIET_ROOT), &root);
    let bin = directory(&[
        record(&[0], JOLIET_BIN, 2048, FLAG_DIRECTORY, &[]),
        record(&[1], JOLIET_ROOT, 2048, FLAG_DIRECTORY, &[]),
        record(&ucs2("main.exe;1"), PSX, PSX_SIZE as u32, 0, &[]),
        record(&ucs2("payload-joliet.elf;1"), PAYLOAD, 256, 0, &[]),
    ]);
    put(image, at(JOLIET_BIN), &bin);
}

/// A synthetic image of [`VOLUME_SECTORS`] sectors: the primary volume
/// descriptor at 16, then the boot record and the Joliet descriptor when
/// requested, the terminator, path tables, hierarchies, the catalog and the
/// file data.
fn build(options: Options) -> Vec<u8> {
    let mut image = vec![0u8; at(VOLUME_SECTORS)];
    let path_l = path_table(&PATH_RECORDS, true);
    let path_m = path_table(&PATH_RECORDS, false);
    let path_size = u32::try_from(path_l.len()).unwrap();
    let mut descriptors = vec![volume_descriptor(&VolumeFields {
        kind: TYPE_PRIMARY,
        escape: &[],
        volume_id: padded(b"ZRAX_SYNTHETIC", 32),
        root: ROOT,
        path_table_size: path_size,
    })];
    if options.el_torito {
        descriptors.push(boot_record(CATALOG));
    }
    if options.joliet {
        let mut volume_id = ucs2("zrax joliet");
        volume_id.resize(32, 0);
        descriptors.push(volume_descriptor(&VolumeFields {
            kind: TYPE_SUPPLEMENTARY,
            escape: b"%/E",
            volume_id,
            root: JOLIET_ROOT,
            path_table_size: path_size,
        }));
    }
    descriptors.push(terminator());
    for (i, descriptor) in descriptors.iter().enumerate() {
        put(&mut image, (16 + i) * SECTOR, descriptor);
    }
    put(&mut image, at(PATH_L), &path_l);
    put(&mut image, at(PATH_M), &path_m);
    primary_hierarchy(options, &mut image);
    if options.joliet {
        joliet_hierarchy(&mut image);
    }
    if options.el_torito {
        put(&mut image, at(CATALOG), &default_catalog());
        put(&mut image, at(BOOT_X86), &BOOT_CODE);
        put(&mut image, at(BOOT_EFI), &elf64(EM_X86_64));
    }
    put(&mut image, at(README), README_TEXT);
    put(&mut image, at(PAYLOAD), &elf64(EM_X86_64));
    put(&mut image, at(PSX), &psx_exe());
    put(&mut image, at(DEEP_ELF), &elf64(EM_AARCH64));
    image
}

fn all_options() -> Options {
    Options {
        rock_ridge: true,
        joliet: true,
        el_torito: true,
    }
}

/// File offset of the record named `identifier` in the directory at
/// `sector`.
fn record_offset(image: &[u8], sector: u32, identifier: &[u8]) -> usize {
    let mut pos = at(sector);
    loop {
        let len = usize::from(image[pos]);
        assert!(len > 0, "record {identifier:?} not found");
        let name_len = usize::from(image[pos + 32]);
        if &image[pos + 33..pos + 33 + name_len] == identifier {
            return pos;
        }
        pos += len;
    }
}

/// Every truncation of `image` fails to parse, and the classifier never
/// reports a prefix as ISO 9660; every byte mutation of `positions`
/// classifies or fails without panicking.
fn sweep(image: &[u8], positions: &[usize]) {
    prefix_sweep("synthetic", image);
    for (n, &position) in positions.iter().enumerate() {
        for value in [0x00, 0xff, image[position] ^ 0x01] {
            let mut mutated = image.to_vec();
            mutated[position] = value;
            if let Some(layout) = iso9660::detect(&mutated) {
                let _ = iso9660::parse_container(&mutated, layout);
            }
            if n % 13 == 0 {
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

/// Every detected prefix of `image` is a truncated volume whose members lie
/// inside it, or lacks the descriptor set or the start of the root
/// directory that names the files and is the error it always was; once a
/// prefix is read, every longer prefix is read.
fn prefix_sweep(name: &str, image: &[u8]) {
    let whole = parse(image);
    let mut first_read = None;
    for cut in prefix_ends(image.len(), 0x8000 + 4 * SECTOR, 61, SECTOR) {
        let prefix = &image[..cut];
        if iso9660::detect(prefix).is_none() {
            assert_eq!(first_read, None, "{name}: prefix {cut} is not detected");
            continue;
        }
        match iso9660::parse_container(prefix, Layout::Iso9660) {
            Ok(c) => {
                first_read.get_or_insert(cut);
                assert!(has_note(&c, "Volume truncated: "), "{name}: prefix {cut}");
                assert_members_inside(name, &whole, &c, cut);
            }
            Err(e) => {
                let message = e.to_string();
                assert_eq!(first_read, None, "{name}: prefix {cut}: {message}");
                assert!(
                    message.contains("Truncated ISO 9660 volume: ")
                        || message.contains("Truncated volume descriptor set: "),
                    "{name}: prefix {cut}: {message}"
                );
            }
        }
    }
    assert!(first_read.is_some(), "{name}: no prefix is read");
    for cut in (0..image.len()).step_by(997) {
        if let Ok(p) = detect_payload(&image[..cut], &ClassifierOptions::new()) {
            for slice in &p.slices {
                assert!(
                    slice.offset + slice.size <= cut as u64,
                    "{name}: prefix {cut}"
                );
            }
        }
    }
}

#[test]
fn truncated_volumes_count_and_note_what_lies_past_the_input() {
    let image = build(all_options());
    let whole = parse(&image);
    let notes_of = |end: usize| {
        let c = parse(&image[..end]);
        assert_members_inside("synthetic", &whole, &c, end);
        notes(&c)
    };
    // The PlayStation executable (sectors 37-38) and DEEP.ELF (39).
    let text = notes_of(at(PSX));
    assert!(
        text.contains(
            "2 regular files were not listed: file data lies partly or wholly past the 74 KiB \
             present"
        ),
        "{text}"
    );
    // The boot images (32, 33) and then the boot catalog (31).
    let text = notes_of(at(BOOT_X86));
    assert!(
        text.contains("lies partly or wholly past the 64 KiB present"),
        "{text}"
    );
    let text = notes_of(at(CATALOG));
    assert!(
        text.contains(
            "the boot catalog sector 0x1F lies past the 62 KiB present; boot images are not \
             listed"
        ),
        "{text}"
    );
    // The directory that Rock Ridge relocated to sector 30.
    let text = notes_of(at(DEEP));
    assert!(
        text.contains(
            "1 directories lie partly or wholly past the 60 KiB present; their records past it \
             were not read"
        ),
        "{text}"
    );
    // The root's ER entry continues in sector 28: without it, whether the
    // names come from Rock Ridge is unknown.
    let end = at(CONTINUATION);
    assert_eq!(
        parse_error(&image[..end]),
        format!(
            "ISO 9660 parse error: Truncated ISO 9660 volume: 40 blocks of 2048 B need 81920 B, \
             {end} B present"
        )
    );
    // Joliet names need the Joliet root (sector 26).
    let joliet = build(Options {
        joliet: true,
        ..Options::default()
    });
    assert!(parse_error(&joliet[..at(JOLIET_ROOT)]).contains("Truncated ISO 9660 volume"));
    assert!(has_note(
        &parse(&joliet[..at(JOLIET_ROOT + 1)]),
        "names from the Joliet hierarchy"
    ));

    // A type L path table moved to sector 39 is not checked.
    let mut moved = image.clone();
    put(&mut moved, at(16) + 140, &39u32.to_le_bytes());
    let c = parse(&moved[..at(39)]);
    assert!(
        has_note(&c, "Type L path table: the table at block 39 ("),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "lies past the 78 KiB present; it is not checked"
    ));
}

#[test]
fn rock_ridge_entries_continued_past_the_input_skip_their_record() {
    let options = Options {
        rock_ridge: true,
        ..Options::default()
    };
    // One more sector (40) for the volume, which holds the continuation
    // of LONG.ELF's entries: its NM entry.
    let mut image = build(options);
    image.extend_from_slice(&[0; SECTOR]);
    put(&mut image, at(16) + 80, &both32(VOLUME_SECTORS + 1));
    let name = nm(b"long-name.elf");
    put(&mut image, at(VOLUME_SECTORS), &name);
    let continued = [
        px(MODE_REGULAR),
        ce(VOLUME_SECTORS, 0, u32::try_from(name.len()).unwrap()),
    ]
    .concat();
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(b"PAYLOAD.ELF;1", PAYLOAD, 256, 0, &nm(b"payload.elf")),
            record(b"LONG.ELF;1", PAYLOAD, 256, 0, &continued),
        ],
    );
    let whole = parse(&image);
    assert!(labels(&whole).contains(&"/bin/long-name.elf".to_string()));
    let end = at(VOLUME_SECTORS);
    let c = parse(&image[..end]);
    assert_members_inside("continued", &whole, &c, end);
    assert!(labels(&c).contains(&"/bin/payload.elf".to_string()));
    assert!(!labels(&c).contains(&"/bin/long-name.elf".to_string()));
    assert!(
        has_note(
            &c,
            "1 directory records carry Rock Ridge entries continued past the 80 KiB present; \
             they were not read"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn fixture_prefixes_are_truncated_volumes_that_list_only_members_inside_them() {
    for name in ["rockridge", "joliet", "hdiutil"] {
        prefix_sweep(name, &iso_fixture(name));
    }
}

// Fixtures written by real tools (tests/fixtures/iso9660/README.md).

#[test]
fn bsdtar_rock_ridge_fixture_lists_the_boot_image_and_members_by_alternate_name() {
    let image = iso_fixture("rockridge");
    assert!(is_detected(&image));
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/bin/payload-with-a-long-name.elf",
            "/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf",
            "El Torito default entry (80x86, no emulation)",
        ]
    );
    assert!(
        has_note(&c, "names from Rock Ridge NM entries (RRIP_1991A)"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "not used for names: Rock Ridge takes precedence"
    ));
    assert!(has_note(
        &c,
        "1 relocated directory records (Rock Ridge RE) are skipped"
    ));
    assert!(has_note(&c, "2 KiB from file /boot/boot.bin"));
    assert!(has_note(&c, "the type L and type M tables agree"));
    let boot = child(&c, "El Torito default entry (80x86, no emulation)");
    assert_eq!(boot.classify, Classify::Code);
    assert_eq!(
        boot.target,
        Some(Target::new(Isa::X86, 16, Endianness::Little))
    );
    assert_eq!(&boot.data[..BOOT_CODE.len()], BOOT_CODE);

    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Iso9660);
    // The member supplies the primary ISA; the boot image follows it.
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86_64, 64));
    let member = slice(&p, "/bin/payload-with-a-long-name.elf");
    assert_eq!(member.isa, Isa::X86_64);
    let offset = member.offset as usize;
    assert_eq!(&image[offset..offset + 4], b"\x7fELF");
    assert_eq!(metadata(&p, "iso9660_names"), "Rock Ridge");
    assert_eq!(metadata(&p, "iso9660_volume_id"), "ZRAX_RR");
    assert_eq!(metadata(&p, "iso9660_application"), "LIBARCHIVE 3.7.4");
    assert_eq!(metadata(&p, "iso9660_member_count"), "2");
}

#[test]
fn bsdtar_joliet_fixture_takes_names_from_the_joliet_hierarchy() {
    let image = iso_fixture("joliet");
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/bin/payload-with-a-long-name.elf",
            "El Torito default entry (80x86, no emulation)",
        ]
    );
    assert!(
        has_note(&c, "names from the Joliet hierarchy (UCS-2)"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "UCS-2 level 3; its hierarchy supplies the names"
    ));
    let p = classify(&image);
    assert_eq!(metadata(&p, "iso9660_names"), "Joliet");
    assert_eq!(metadata(&p, "iso9660_joliet_level"), "3");
}

#[test]
fn hdiutil_fixture_reports_the_udf_bridge_and_falls_back_to_iso_identifiers() {
    let image = iso_fixture("hdiutil");
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/BIN/PAYLOAD-WITH-A-LONG-NAME.ELF",
            "/DEEP/L1/L2/L3/L4/L5/L6/L7/L8/DEEP.ELF",
            "El Torito default entry (80x86, no emulation)",
        ]
    );
    assert!(
        has_note(&c, "UDF bridge: ECMA-167 recognition sequence BEA01 (extended area start) at sector 20, NSR02"),
        "{}",
        notes(&c)
    );
    // hdiutil writes SP, ER (IEEE_P1282), PX and TF but no NM entries.
    assert!(has_note(&c, "Rock Ridge NM entries (IEEE_P1282)"));
    assert!(has_note(
        &c,
        "entries carry no Rock Ridge NM entry; their ISO 9660 identifiers are used"
    ));
    assert!(has_note(&c, "from file /BOOT/BOOT.BIN"));
    let descriptors = c
        .metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == "iso9660_udf_descriptors"))
        .map(|m| m.value.to_string());
    assert_eq!(descriptors.as_deref(), Some("BEA01, NSR02, TEA01"));
    // Its UDF volume opens, so the classifier reports the disc as a UDF
    // bridge (tests/udf.rs); this reading is the ISO 9660 view.
    assert!(matches!(
        detect_format(&image),
        DetectedFormat::Container { kind: Kind::Udf(_) }
    ));
}

#[test]
fn fixture_mutations_of_the_metadata_never_panic() {
    for name in ["rockridge", "joliet", "hdiutil"] {
        let image = iso_fixture(name);
        // Descriptors, path tables, directories and the boot catalog lie
        // in the first sectors after the system area.
        let positions: Vec<usize> = (0x8000..0x8000 + 4 * SECTOR)
            .chain((0x8000 + 4 * SECTOR..(0x8000 + 48 * SECTOR).min(image.len())).step_by(7))
            .collect();
        for (n, &position) in positions.iter().enumerate() {
            for value in [0x00, 0xff, image[position] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[position] = value;
                if let Some(layout) = iso9660::detect(&mutated) {
                    let _ = iso9660::parse_container(&mutated, layout);
                }
                if n % 101 == 0 {
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
}

// Synthetic images.

#[test]
fn layout_metadata_and_detection() {
    assert_eq!(Layout::Iso9660.format(), FileFormat::Iso9660);
    assert_eq!(Layout::Iso9660.label(), "ISO 9660");
    assert!(!Layout::Iso9660.is_weak());
    let image = build(Options::default());
    assert!(is_detected(&image));
    assert_eq!(iso9660::detect(&image), Some(Layout::Iso9660));
    assert_eq!(
        serde_json::to_string(&FileFormat::Iso9660).unwrap(),
        "\"iso9660\""
    );
    assert_eq!(FileFormat::Iso9660.to_string(), "ISO 9660");
}

#[test]
fn plain_image_uses_iso_identifiers_without_version_numbers() {
    let image = build(Options::default());
    let c = parse(&image);
    assert_eq!(c.target, None);
    assert_eq!(c.consumed, image.len());
    assert_eq!(
        labels(&c),
        [
            "/BIN/MAIN.EXE",
            "/BIN/PAYLOAD.ELF",
            "/RR_MOVED/DEEP/DEEP.ELF"
        ]
    );
    assert!(
        has_note(&c, "names from ISO 9660 file identifiers"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "Path tables: 4 directories; the type L and type M tables agree"
    ));
    // DEEP is a zero-length file in the ISO 9660 view.
    assert!(has_note(
        &c,
        "5 regular files in 4 directories; 3 recognized members listed"
    ));
    let main = child(&c, "/BIN/MAIN.EXE");
    assert_eq!(main.offset, at(PSX));
    assert_eq!(main.stored_size, PSX_SIZE);
    assert_eq!(main.classify, Classify::IfRecognized);
    assert!(matches!(main.data, Cow::Borrowed(_)));

    let p = classify(&image);
    assert_eq!(slice(&p, "/BIN/MAIN.EXE").isa, Isa::Mips);
    assert_eq!(slice(&p, "/BIN/PAYLOAD.ELF").isa, Isa::X86_64);
    assert_eq!(slice(&p, "/RR_MOVED/DEEP/DEEP.ELF").isa, Isa::AArch64);
    assert_eq!(p.primary.isa, Isa::Mips);
    assert_eq!(metadata(&p, "iso9660_volume_id"), "ZRAX_SYNTHETIC");
    assert_eq!(metadata(&p, "iso9660_system_id"), "ZRAX");
    assert_eq!(metadata(&p, "iso9660_publisher"), "ZRAX TESTS");
    assert_eq!(
        metadata(&p, "iso9660_created"),
        "2026-10-13 00:00:00 GMT+00:00"
    );
    assert_eq!(metadata(&p, "iso9660_block_size"), "2048");
    assert_eq!(metadata(&p, "iso9660_volume_blocks"), "40");
}

#[test]
fn rock_ridge_names_relocation_and_continuation_areas() {
    let options = Options {
        rock_ridge: true,
        ..Options::default()
    };
    let image = build(options);
    let c = parse(&image);
    assert_eq!(
        labels(&c),
        [
            "/bin/main.exe",
            "/bin/payload-with-a-long-name.elf",
            "/deep/deep.elf"
        ]
    );
    // The ER entry is only in the continuation area named by the root's CE.
    assert!(
        has_note(&c, "names from Rock Ridge NM entries (RRIP_1991A)"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "1 relocated directory records (Rock Ridge RE) are skipped"
    ));
    assert_eq!(child(&c, "/deep/deep.elf").offset, at(DEEP_ELF));
}

#[test]
fn rock_ridge_takes_precedence_over_joliet_and_ieee_identifiers_count() {
    let image = build(all_options());
    let c = parse(&image);
    assert!(has_note(
        &c,
        "UCS-2 level 3; not used for names: Rock Ridge takes precedence"
    ));
    let mut ieee = build(Options {
        rock_ridge: true,
        ..Options::default()
    });
    put(&mut ieee, at(CONTINUATION) + 8, b"IEEE_P1282");
    assert!(has_note(
        &parse(&ieee),
        "Rock Ridge NM entries (IEEE_P1282)"
    ));
    // An unknown extension identifier is not Rock Ridge.
    let mut other = ieee.clone();
    put(&mut other, at(CONTINUATION) + 8, b"OTHER_EXT1");
    assert!(has_note(
        &parse(&other),
        "names from ISO 9660 file identifiers"
    ));
}

#[test]
fn joliet_names_when_rock_ridge_is_absent() {
    let image = build(Options {
        joliet: true,
        ..Options::default()
    });
    let c = parse(&image);
    assert_eq!(labels(&c), ["/bin/main.exe", "/bin/payload-joliet.elf"]);
    assert!(
        has_note(&c, "its hierarchy supplies the names"),
        "{}",
        notes(&c)
    );
    // A Joliet root outside the volume falls back to the primary hierarchy.
    let mut broken = image.clone();
    let svd = 17 * SECTOR;
    put(&mut broken, svd + 156 + 2, &both32(500));
    let c = parse(&broken);
    assert!(
        has_note(&c, "not used: its root directory record at 0x"),
        "{}",
        notes(&c)
    );
    assert_eq!(c.children[0].label, "/BIN/MAIN.EXE");
    // A Joliet descriptor whose both-byte-order fields disagree is not used.
    let mut invalid = image.clone();
    invalid[svd + 80] ^= 1;
    let c = parse(&invalid);
    assert!(
        has_note(
            &c,
            "Joliet descriptor at 0x8800 is invalid (Invalid volume space size"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn el_torito_x86_and_efi_images_become_children() {
    let image = build(all_options());
    let c = parse(&image);
    // The boot images follow the files.
    let labels = labels(&c);
    assert_eq!(
        labels[labels.len() - 2..],
        [
            "El Torito default entry (80x86, no emulation)",
            "El Torito section 1 entry 1 (EFI, no emulation)",
        ]
    );
    let x86 = child(&c, "El Torito default entry (80x86, no emulation)");
    assert_eq!(x86.offset, at(BOOT_X86));
    assert_eq!(x86.stored_size, 4 * 512);
    assert_eq!(x86.classify, Classify::Code);
    assert_eq!(
        x86.target,
        Some(Target::new(Isa::X86, 16, Endianness::Little))
    );
    let efi = child(&c, "El Torito section 1 entry 1 (EFI, no emulation)");
    assert_eq!(efi.offset, at(BOOT_EFI));
    assert_eq!(efi.stored_size, 8 * 512);
    assert_eq!(efi.classify, Classify::Always);
    assert_eq!(efi.target, None);
    assert!(
        has_note(&c, "El Torito boot catalog at sector 0x1F (file 0xF800): validation entry checksum verified; platform 80x86, ID \"ZRAX\"; 2 bootable entries, 0 not bootable"),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "4 virtual sectors loaded at segment 0x07C0"));
    assert!(has_note(&c, "2 KiB from the sector count"));

    let p = classify(&image);
    let x86 = slice(&p, "El Torito default entry (80x86, no emulation)");
    assert_eq!((x86.isa, x86.bitwidth), (Isa::X86, 16));
    // The EFI entry names no ISA; its bytes are an ELF here.
    let efi = slice(&p, "El Torito section 1 entry 1 (EFI, no emulation)");
    assert_eq!(efi.isa, Isa::X86_64);
    // A recognized file, not the boot code, supplies the primary ISA.
    assert_eq!(p.primary.isa, p.slices[0].isa);
    assert!(
        p.notes.iter().any(|n| n.message
            == "Primary ISA selected from /bin/main.exe; other components are listed separately"),
        "{:?}",
        p.notes
    );
    assert_eq!(
        metadata(&p, "iso9660_boot_catalog"),
        "sector 0x1F (file 0xF800)"
    );
    assert_eq!(metadata(&p, "iso9660_boot_entries"), "2");
}

#[test]
fn efi_images_with_a_sector_count_below_two_reach_the_volume_end() {
    let mut image = build(all_options());
    let entry = at(CATALOG) + 3 * 32;
    put(&mut image, entry + 6, &1u16.to_le_bytes());
    let c = parse(&image);
    let efi = child(&c, "El Torito section 1 entry 1 (EFI, no emulation)");
    assert_eq!(efi.stored_size, at(VOLUME_SECTORS) - at(BOOT_EFI));
    assert!(has_note(
        &c,
        "from the rest of the volume (sector count below 2)"
    ));
}

#[test]
fn powerpc_and_mac_entries_name_their_platform() {
    let mut image = build(all_options());
    put(&mut image, at(CATALOG) + 2 * 32 + 1, &[PLATFORM_POWERPC]);
    let c = parse(&image);
    let ppc = child(&c, "El Torito section 1 entry 1 (PowerPC, no emulation)");
    assert_eq!(ppc.target, Some(Target::without_byte_order(Isa::Ppc, 32)));
    assert_eq!(ppc.classify, Classify::Always);
    put(&mut image, at(CATALOG) + 2 * 32 + 1, &[2]);
    let c = parse(&image);
    let mac = child(&c, "El Torito section 1 entry 1 (Mac, no emulation)");
    assert_eq!(mac.target, None);
    assert!(has_note(&c, "boot image; the platform names no ISA"));
}

#[test]
fn an_invalid_validation_entry_leaves_the_filesystem_readable() {
    let image = build(all_options());
    let mut checksum = image.clone();
    checksum[at(CATALOG) + 4] ^= 1;
    let c = parse(&checksum);
    assert!(
        has_note(&c, "El Torito boot catalog at sector 0x1F (file 0xF800): invalid validation entry checksum: the words sum to 0x0001; boot images are not listed"),
        "{}",
        notes(&c)
    );
    assert_eq!(
        labels(&c),
        [
            "/bin/main.exe",
            "/bin/payload-with-a-long-name.elf",
            "/deep/deep.elf"
        ]
    );
    let mut key = image.clone();
    key[at(CATALOG) + 31] = 0;
    assert!(has_note(&parse(&key), "invalid validation entry key bytes"));
    let mut header = image.clone();
    header[at(CATALOG)] = 2;
    assert!(has_note(
        &parse(&header),
        "invalid validation entry header ID 0x02"
    ));
    let mut outside = image.clone();
    put(&mut outside, 17 * SECTOR + 0x47, &5000u32.to_le_bytes());
    assert!(has_note(
        &parse(&outside),
        "the boot catalog sector 0x1388 lies outside the volume"
    ));
}

#[test]
fn catalog_entries_that_cannot_be_read_are_noted() {
    let mut image = build(all_options());
    // Default entry: reserved media type; section entry: load RBA outside.
    image[at(CATALOG) + 32 + 1] = 7;
    put(&mut image, at(CATALOG) + 3 * 32 + 8, &900u32.to_le_bytes());
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "El Torito default entry: reserved media type 7; the entry is not listed"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "El Torito section 1 entry 1 is not listed: load RBA 0x384 lies outside the volume"
    ));
    assert!(!c
        .children
        .iter()
        .any(|child| child.label.starts_with("El Torito")));
    // A section announcing more entries than the catalog holds.
    let mut short = build(all_options());
    put(
        &mut short,
        at(CATALOG) + 2 * 32 + 2,
        &u16::MAX.to_le_bytes(),
    );
    let c = parse(&short);
    assert!(
        has_note(&c, "section 1: 65535 entries announced"),
        "{}",
        notes(&c)
    );
    // A non-bootable default entry is counted, not listed.
    let mut idle = build(all_options());
    idle[at(CATALOG) + 32] = 0;
    let c = parse(&idle);
    assert!(
        has_note(&c, "1 bootable entries, 1 not bootable"),
        "{}",
        notes(&c)
    );
}

#[test]
fn section_entry_extensions_are_skipped() {
    let mut image = build(all_options());
    let catalog = [
        validation_entry(PLATFORM_X86),
        boot_entry(true, MEDIA_NO_EMULATION, 4, BOOT_X86),
        section_header(true, PLATFORM_EFI, 1),
        boot_entry(true, MEDIA_NO_EMULATION | 0x20, 8, BOOT_EFI),
        {
            let mut extension = vec![0u8; 32];
            extension[0] = 0x44;
            extension
        },
    ]
    .concat();
    put(&mut image, at(CATALOG), &catalog);
    let c = parse(&image);
    assert!(c
        .children
        .iter()
        .any(|child| child.label == "El Torito section 1 entry 1 (EFI, no emulation)"));
}

#[test]
fn a_boot_image_file_gives_its_size_and_is_not_listed_as_a_member() {
    let mut image = build(all_options());
    // Point README.TXT at the EFI image: the file is then the boot image.
    let readme = record_offset(&image, ROOT, b"README.TXT;1");
    put(&mut image, readme + 2, &both32(BOOT_EFI));
    put(&mut image, readme + 10, &both32(3000));
    let c = parse(&image);
    let efi = child(&c, "El Torito section 1 entry 1 (EFI, no emulation)");
    assert_eq!(efi.stored_size, 3000);
    assert!(has_note(&c, "from file /readme.txt"), "{}", notes(&c));
    assert!(!labels(&c).contains(&"/readme.txt".to_string()));
}

#[test]
fn floppy_and_hard_disk_emulation_images_are_disk_images() {
    // A 1.44 MB floppy needs 720 sectors after the image start.
    let floppy_sectors = 720;
    let mut image = build(all_options());
    image.resize(at(VOLUME_SECTORS) + at(floppy_sectors), 0);
    let total = VOLUME_SECTORS + floppy_sectors;
    put(&mut image, 16 * SECTOR + 80, &both32(total));
    put(&mut image, 18 * SECTOR + 80, &both32(total));
    put(
        &mut image,
        at(CATALOG) + 3 * 32,
        &boot_entry(true, MEDIA_FLOPPY_1440, 1, VOLUME_SECTORS),
    );
    let mut boot_sector = vec![0u8; 512];
    boot_sector[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    put(&mut image, at(VOLUME_SECTORS), &boot_sector);
    let c = parse(&image);
    let floppy = child(
        &c,
        "El Torito section 1 entry 1 (EFI, 1.44 MB floppy emulation)",
    );
    assert_eq!(floppy.stored_size, 1_474_560);
    assert_eq!(floppy.classify, Classify::Always);
    assert_eq!(floppy.target, None);
    assert!(has_note(
        &c,
        "emulated disk image; classified from its own bytes"
    ));
    assert!(has_note(&c, "from the emulated floppy geometry"));

    let mut disk = build(all_options());
    put(
        &mut disk,
        at(CATALOG) + 3 * 32,
        &boot_entry(true, MEDIA_HARD_DISK, 1, BOOT_EFI),
    );
    let mut mbr = vec![0u8; 512];
    put(&mut mbr, 446 + 8, &1u32.to_le_bytes());
    put(&mut mbr, 446 + 12, &5u32.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    put(&mut disk, at(BOOT_EFI), &mbr);
    let c = parse(&disk);
    let hard_disk = child(&c, "El Torito section 1 entry 1 (EFI, hard disk emulation)");
    assert_eq!(hard_disk.stored_size, 6 * 512);
    assert!(has_note(&c, "from the MBR's first partition"));
    disk[at(BOOT_EFI) + 510] = 0;
    assert!(has_note(&parse(&disk), "the hard disk image has no MBR"));
}

/// Replace the records of the directory at `sector` with `records` after
/// its `.` and `..`.
fn rewrite_directory(image: &mut [u8], sector: u32, parent: u32, records: &[Vec<u8>]) {
    let mut all = vec![
        record(&[0], sector, 2048, FLAG_DIRECTORY, &[]),
        record(&[1], parent, 2048, FLAG_DIRECTORY, &[]),
    ];
    all.extend_from_slice(records);
    put(image, at(sector), &directory(&all));
}

#[test]
fn multi_extent_files_are_reassembled_or_borrowed() {
    let mut image = build(Options::default());
    let elf = elf64(EM_X86_64);
    put(&mut image, at(PAYLOAD), &elf[..128]);
    put(&mut image, at(DEEP_ELF), &elf[128..]);
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(b"SPLIT.ELF;1", PAYLOAD, 128, FLAG_MULTI_EXTENT, &[]),
            record(b"SPLIT.ELF;1", DEEP_ELF, 128, 0, &[]),
        ],
    );
    let c = parse(&image);
    let split = child(&c, "/BIN/SPLIT.ELF");
    assert_eq!(split.offset, at(PAYLOAD));
    assert_eq!(split.stored_size, 128);
    assert_eq!(split.transform, Some("ISO 9660 file sections"));
    assert_eq!(split.data.as_ref(), elf.as_slice());
    let p = classify(&image);
    let decoded = slice(&p, "/BIN/SPLIT.ELF")
        .decoded
        .as_ref()
        .expect("decoded range");
    assert_eq!(
        (decoded.transform.as_str(), decoded.size),
        ("ISO 9660 file sections", 256)
    );

    // A first section of whole blocks followed by the next block is
    // contiguous, so the member is borrowed.
    let mut contiguous = build(Options::default());
    let mut long = elf64(EM_X86_64);
    long.resize(SECTOR + 100, 0x41);
    put(&mut contiguous, at(PSX), &long);
    rewrite_directory(
        &mut contiguous,
        BIN,
        ROOT,
        &[
            record(b"LONG.ELF;1", PSX, 2048, FLAG_MULTI_EXTENT, &[]),
            record(b"LONG.ELF;1", PSX + 1, 100, 0, &[]),
        ],
    );
    let c = parse(&contiguous);
    let whole = child(&c, "/BIN/LONG.ELF");
    assert!(matches!(whole.data, Cow::Borrowed(_)));
    assert_eq!((whole.offset, whole.stored_size), (at(PSX), SECTOR + 100));
}

#[test]
fn interrupted_multi_extent_files_are_problems() {
    let mut image = build(Options::default());
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(b"A.ELF;1", PAYLOAD, 128, FLAG_MULTI_EXTENT, &[]),
            record(b"B.ELF;1", PAYLOAD, 256, 0, &[]),
            record(b"C.ELF;1", PAYLOAD, 128, FLAG_MULTI_EXTENT, &[]),
        ],
    );
    let c = parse(&image);
    assert!(
        has_note(&c, "/BIN: multi-extent file at 0x"),
        "{}",
        notes(&c)
    );
    assert_eq!(
        c.notes
            .iter()
            .filter(|n| n.contains("has no final section record"))
            .count(),
        2
    );
    assert!(labels(&c).contains(&"/BIN/B.ELF".to_string()));
}

#[test]
fn directory_cycles_and_repeated_directories_are_walked_once() {
    let mut image = build(Options::default());
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(b"LOOP", ROOT, 2048, FLAG_DIRECTORY, &[]),
            record(b"SELF", BIN, 2048, FLAG_DIRECTORY, &[]),
            record(b"PAYLOAD.ELF;1", PAYLOAD, 256, 0, &[]),
        ],
    );
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "2 directory records point at a directory already walked"
        ),
        "{}",
        notes(&c)
    );
    assert_eq!(
        c.children
            .iter()
            .filter(|child| child.offset == at(PAYLOAD))
            .count(),
        1
    );
}

#[test]
fn associated_hidden_and_interleaved_files() {
    let mut image = build(Options::default());
    let mut interleaved = record(b"WOVEN.ELF;1", PAYLOAD, 256, 0, &[]);
    interleaved[26] = 1;
    interleaved[27] = 1;
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(b"FORK.ELF;1", PAYLOAD, 256, FLAG_ASSOCIATED, &[]),
            record(b"HIDDEN.ELF;1", PAYLOAD, 256, 0x01, &[]),
            interleaved,
        ],
    );
    let c = parse(&image);
    assert!(
        has_note(&c, "1 associated files (file flag bit 2) are not read"),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "1 interleaved files (file unit or gap size set) are not read"
    ));
    assert!(labels(&c).contains(&"/BIN/HIDDEN.ELF".to_string()));
}

#[test]
fn rock_ridge_special_files_and_bad_names_are_not_listed() {
    let options = Options {
        rock_ridge: true,
        ..Options::default()
    };
    let mut image = build(options);
    // Two NM entries of 150 and 110 B, in a continuation area after the
    // root's ER entry: 260 B together.
    let long_name = [nm_with(1, &[b'a'; 150]), nm(&[b'b'; 110])].concat();
    put(&mut image, at(CONTINUATION) + 64, &long_name);
    let continued = [
        px(MODE_REGULAR),
        ce(CONTINUATION, 64, long_name.len() as u32),
    ]
    .concat();
    rewrite_directory(
        &mut image,
        BIN,
        ROOT,
        &[
            record(
                b"LINK.ELF;1",
                PAYLOAD,
                256,
                0,
                &[nm(b"link.elf"), px(MODE_SYMLINK)].concat(),
            ),
            record(
                b"PACKED.ELF;1",
                PAYLOAD,
                256,
                0,
                &[nm(b"packed.elf"), sue(b"ZF", &[0; 12])].concat(),
            ),
            record(
                b"SPARSE.ELF;1",
                PAYLOAD,
                256,
                0,
                &[nm(b"sparse.elf"), sue(b"SF", &[0; 17])].concat(),
            ),
            record(b"SLASH.ELF;1", PAYLOAD, 256, 0, &nm(b"a/b")),
            record(b"LONG.ELF;1", PAYLOAD, 256, 0, &continued),
        ],
    );
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "1 Rock Ridge symbolic links, devices, FIFOs or sockets are not read"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "1 zisofs-compressed files (ZF) are not decompressed and not listed"
    ));
    assert!(has_note(&c, "1 sparse files (Rock Ridge SF) are not read"));
    assert!(has_note(&c, "name \"a/b\" is not a path component"));
    assert!(has_note(
        &c,
        "is longer than 255 B; the ISO 9660 identifier is used"
    ));
    assert!(
        labels(&c).contains(&"/bin/LONG.ELF".to_string()),
        "{:?}",
        labels(&c)
    );
}

#[test]
fn rock_ridge_continuation_loops_are_bounded() {
    let options = Options {
        rock_ridge: true,
        ..Options::default()
    };
    // A continuation area at CONTINUATION + 64 whose CE names itself.
    let looping = ce(CONTINUATION, 64, 28);
    let mut member = build(options);
    put(&mut member, at(CONTINUATION) + 64, &looping);
    rewrite_directory(
        &mut member,
        BIN,
        ROOT,
        &[record(
            b"PAYLOAD.ELF;1",
            PAYLOAD,
            256,
            0,
            &[nm(b"payload.elf"), looping.clone()].concat(),
        )],
    );
    let c = parse(&member);
    assert!(
        has_note(&c, "/bin: Rock Ridge entries of the record at 0x"),
        "{}",
        notes(&c)
    );
    assert!(has_note(&c, "ignored: more than 32 continuation areas"));
    // The record's own entries are ignored too: its ISO identifier names it.
    assert!(
        labels(&c).contains(&"/bin/PAYLOAD.ELF".to_string()),
        "{:?}",
        labels(&c)
    );

    // When the root's CE loops, its ER is never reached: no Rock Ridge.
    let mut root = build(options);
    put(&mut root, at(CONTINUATION), &ce(CONTINUATION, 0, 28));
    let root_ce = record_offset(&root, ROOT, &[0]) + 34 + 7 + 44;
    put(&mut root, root_ce, &ce(CONTINUATION, 0, 28));
    assert!(
        has_note(&parse(&root), "names from ISO 9660 file identifiers"),
        "{}",
        notes(&parse(&root))
    );
    // A continuation area outside the volume is a problem for its record.
    let mut outside = member.clone();
    put(&mut outside, at(CONTINUATION) + 64, &ce(9000, 0, 28));
    assert!(has_note(
        &parse(&outside),
        "continuation area at 0x1194000 (28 B) lies outside the volume"
    ));
}

#[test]
fn byte_order_disagreement_in_records_uses_the_little_endian_half() {
    let mut image = build(Options::default());
    let payload = record_offset(&image, BIN, b"PAYLOAD.ELF;1");
    image[payload + 9] ^= 0x40;
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "1 directory records hold extent or length halves that disagree"
        ),
        "{}",
        notes(&c)
    );
    assert_eq!(child(&c, "/BIN/PAYLOAD.ELF").offset, at(PAYLOAD));
}

#[test]
fn path_table_damage_is_noted() {
    let image = build(Options::default());
    let mut differing = image.clone();
    differing[at(PATH_M) + 8 + 2 + 5] ^= 1;
    assert!(has_note(
        &parse(&differing),
        "Path tables disagree: type L holds 4 records, type M 4; first difference at record 2"
    ));
    let mut missing = image.clone();
    put(&mut missing, 16 * SECTOR + 148, &0u32.to_be_bytes());
    assert!(has_note(&parse(&missing), "no type M table is recorded"));
    let mut outside = image.clone();
    put(&mut outside, 16 * SECTOR + 140, &900u32.to_le_bytes());
    assert!(has_note(
        &parse(&outside),
        "Type L path table: the table at block 900"
    ));
    let mut root = image.clone();
    put(&mut root, at(PATH_L) + 2, &BIN.to_le_bytes());
    assert!(has_note(
        &parse(&root),
        "the first record is not the root directory"
    ));
}

#[test]
fn hybrid_system_areas_and_trailing_data() {
    let mut image = build(Options::default());
    image[446 + 4] = 0x17;
    image[510] = 0x55;
    image[511] = 0xAA;
    image.extend_from_slice(&[0x5A; 4096]);
    let c = parse(&image);
    assert!(
        has_note(
            &c,
            "Hybrid image: the system area holds an MBR (partition types 0x17)"
        ),
        "{}",
        notes(&c)
    );
    assert!(has_note(
        &c,
        "4096 B follow the volume at 0x14000; the system-area partition table may describe them"
    ));
    assert_eq!(c.consumed, at(VOLUME_SECTORS));
    put(&mut image, 512, b"EFI PART");
    assert!(has_note(
        &parse(&image),
        "a GPT header follows the MBR at 0x200"
    ));

    let mut garbage = build(Options::default());
    garbage.extend_from_slice(&[0x5A; 100]);
    assert_eq!(
        parse_error(&garbage),
        "ISO 9660 parse error: Invalid trailing data: 100 B after the volume at 0x14000 are not padding"
    );
    let mut padded = build(Options::default());
    padded.extend_from_slice(&[0; 300]);
    assert!(has_note(
        &parse(&padded),
        "Volume ends at 0x14000; 300 B of padding follow"
    ));
    let mut used = build(Options::default());
    used[100] = 1;
    assert!(has_note(
        &parse(&used),
        "The system area (sectors 0-15) holds data"
    ));
}

#[test]
fn udf_bridge_descriptors_follow_the_terminator() {
    let mut image = build(Options::default());
    put(&mut image, 18 * SECTOR, &udf_descriptor(b"BEA01"));
    put(&mut image, 19 * SECTOR, &udf_descriptor(b"NSR03"));
    put(&mut image, 20 * SECTOR, &udf_descriptor(b"TEA01"));
    let c = parse(&image);
    assert!(
        has_note(&c, "UDF bridge: ECMA-167 recognition sequence BEA01 (extended area start) at sector 18, NSR03 (ECMA-167 3rd edition volume) at sector 19, TEA01 (extended area end) at sector 20; the UDF structures are not parsed"),
        "{}",
        notes(&c)
    );
}

#[test]
fn other_descriptors_are_noted() {
    let mut image = build(Options::default());
    // Sector 17 becomes a non-Joliet supplementary descriptor, 18 an
    // enhanced one, 19 a partition descriptor, then the terminator.
    let mut other = volume_descriptor(&VolumeFields {
        kind: TYPE_SUPPLEMENTARY,
        escape: b"%/F",
        volume_id: padded(b"OTHER", 32),
        root: ROOT,
        path_table_size: 0,
    });
    put(&mut image, 17 * SECTOR, &other);
    other[6] = 2;
    put(&mut image, 18 * SECTOR, &other);
    let mut partition = terminator();
    partition[0] = 3;
    put(&mut image, 19 * SECTOR, &partition);
    put(&mut image, 20 * SECTOR, &terminator());
    let c = parse(&image);
    assert!(has_note(&c, "Not used for names: supplementary volume descriptor at 0x8800 with escape sequences \"%/F\""), "{}", notes(&c));
    assert!(has_note(
        &c,
        "1 enhanced volume descriptors (ECMA-119 8.5, version 2) are not used"
    ));
    assert!(has_note(&c, "1 volume partition descriptors"));
}

#[test]
fn primary_descriptor_damage_prevents_detection_or_is_a_parse_error() {
    let image = build(Options::default());
    let pvd = 16 * SECTOR;
    let mutate = |offset: usize, bytes: &[u8]| {
        let mut damaged = image.clone();
        put(&mut damaged, offset, bytes);
        damaged
    };
    for (damaged, message) in [
        (mutate(pvd + 84, &[0, 0, 0, 41]), "Invalid volume space size at 0x8050: little-endian 0x00000028 and big-endian 0x00000029 differ"),
        (mutate(pvd + 128, &both16(4096)), "Unsupported logical block size 4096 B at 0x8080"),
        (mutate(pvd + 6, &[2]), "Unsupported volume descriptor version 2 at 0x8000"),
        (mutate(pvd + 881, &[2]), "Unsupported file structure version 2 at 0x8371"),
        (mutate(pvd + 156, &[33]), "Invalid root directory record at 0x809C: length 33 B, expected 34"),
        (mutate(pvd + 156 + 25, &[0]), "Invalid root directory record at 0x809C: flags 0x00"),
        (mutate(pvd + 80, &both32(17)), "cannot hold the volume descriptors"),
        (mutate(pvd + 120, &[2, 0, 0, 1]), "Invalid volume set size"),
    ] {
        assert!(!is_detected(&damaged), "{message}");
        let error = parse_error(&damaged);
        assert!(error.contains(message), "{error}");
    }
}

#[test]
fn volume_and_root_damage_is_a_parse_error() {
    let image = build(Options::default());
    // One byte short, the volume is truncated with every member present;
    // without its root directory it is not listed.
    let cut = parse(&image[..image.len() - 1]);
    assert_eq!(labels(&cut), labels(&parse(&image)));
    assert!(has_note(
        &cut,
        "Volume truncated: 81919 B of 80 KiB present; files are listed only when all of their \
         data is present"
    ));
    assert_eq!(
        parse_error(&image[..at(ROOT)]),
        format!(
            "ISO 9660 parse error: Truncated ISO 9660 volume: 40 blocks of 2048 B need 81920 B, \
             {} B present",
            at(ROOT)
        )
    );
    let mut no_terminator = image.clone();
    no_terminator[17 * SECTOR + 1] = b'X';
    assert_eq!(
        parse_error(&no_terminator),
        "ISO 9660 parse error: Missing volume descriptor set terminator: sector 17 at 0x8800 does not hold CD001"
    );
    let mut endless = image.clone();
    for sector in 17..80 {
        let mut copy = volume_descriptor(&VolumeFields {
            kind: TYPE_PRIMARY,
            escape: &[],
            volume_id: padded(b"COPY", 32),
            root: ROOT,
            path_table_size: 0,
        });
        copy.truncate(SECTOR);
        if sector * SECTOR + SECTOR > endless.len() {
            endless.resize(sector * SECTOR + SECTOR, 0);
        }
        put(&mut endless, sector * SECTOR, &copy);
    }
    assert!(parse_error(&endless)
        .contains("Missing volume descriptor set terminator in sectors 16 to 79"));
    let mut root = image.clone();
    put(&mut root, 16 * SECTOR + 156 + 2, &both32(39));
    put(&mut root, 16 * SECTOR + 156 + 10, &both32(4096));
    assert!(parse_error(&root).contains(
        "Invalid root directory record at 0x809C: extent of 4096 B lies outside the volume"
    ));
}

#[test]
fn directory_damage_below_the_root_is_noted() {
    let mut image = build(Options::default());
    // An identifier length that passes the record end.
    let payload = record_offset(&image, BIN, b"PAYLOAD.ELF;1");
    image[payload + 32] = 250;
    let mut outside = build(Options::default());
    let bin = record_offset(&outside, ROOT, b"BIN");
    put(&mut outside, bin + 2, &both32(1000));
    let mut file = build(Options::default());
    let main = record_offset(&file, BIN, b"MAIN.EXE;1");
    put(&mut file, main + 10, &both32(1 << 20));
    let c = parse(&image);
    assert!(
        has_note(&c, "/BIN: Invalid directory record at 0x"),
        "{}",
        notes(&c)
    );
    let c = parse(&outside);
    assert!(
        has_note(
            &c,
            "/BIN: directory not walked: extent of 2048 B lies outside the volume"
        ),
        "{}",
        notes(&c)
    );
    let c = parse(&file);
    assert!(
        has_note(
            &c,
            "/BIN/MAIN.EXE: file section at block 37 (1048576 B) lies outside the volume"
        ),
        "{}",
        notes(&c)
    );
}

#[test]
fn synthetic_truncations_and_mutations_are_bounded() {
    let image = build(all_options());
    let positions: Vec<usize> = (16 * SECTOR..20 * SECTOR)
        .chain(at(PATH_L)..at(BOOT_X86) + 64)
        .chain((at(BOOT_X86)..image.len()).step_by(61))
        .collect();
    sweep(&image, &positions);
}
