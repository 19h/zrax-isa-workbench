//! UEFI firmware volumes (FFS files, sections, compression and GUID-defined
//! encapsulations), TE images and Intel flash descriptor images: per-image
//! ISAs from PE32 and TE machine fields, stored and decoded slice ranges,
//! checksums and CRCs, and truncation and mutation sweeps.

use zrax::formats::checksum::crc32;
use zrax::formats::compressed::{self, Codec};
use zrax::formats::uefi::{self, Layout};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa, MetadataKey};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/uefi");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(payload: &DetectionPayload, key: &str) -> Option<String> {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

/// The slice whose label contains `text`.
fn slice<'a>(payload: &'a DetectionPayload, text: &str) -> &'a zrax::ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref().is_some_and(|l| l.contains(text)))
        .unwrap_or_else(|| panic!("no slice {text}: {:?}", payload.slices))
}

// PE/COFF machine values.
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// Section types (PI 1.8 Vol. 3, 3.2.4).
const EFI_SECTION_COMPRESSION: u8 = 0x01;
const EFI_SECTION_GUID_DEFINED: u8 = 0x02;
const EFI_SECTION_PE32: u8 = 0x10;
const EFI_SECTION_TE: u8 = 0x12;
const EFI_SECTION_USER_INTERFACE: u8 = 0x15;
const EFI_SECTION_COMPATIBILITY16: u8 = 0x16;
const EFI_SECTION_FIRMWARE_VOLUME_IMAGE: u8 = 0x17;
const EFI_SECTION_RAW: u8 = 0x19;

// File types, attributes and states (PI 1.8 Vol. 3, 3.2.3).
const EFI_FV_FILETYPE_RAW: u8 = 0x01;
const EFI_FV_FILETYPE_PEIM: u8 = 0x06;
const EFI_FV_FILETYPE_DRIVER: u8 = 0x07;
const EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE: u8 = 0x0B;
const EFI_FV_FILETYPE_FFS_PAD: u8 = 0xF0;
const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
const FFS_ATTRIB_TAIL_PRESENT: u8 = 0x01;
const FFS_FIXED_CHECKSUM_FRAMEWORK: u8 = 0x5A;
const FFS_ATTRIB_CHECKSUM: u8 = 0x40;
const EFI_FILE_HEADER_CONSTRUCTION: u8 = 0x01;
const EFI_FILE_DATA_VALID: u8 = 0x04;
const EFI_FILE_DELETED: u8 = 0x10;

// Volume attributes.
const EFI_FVB2_ERASE_POLARITY: u32 = 0x0000_0800;

// GUID-defined section attributes.
const EFI_GUIDED_SECTION_PROCESSING_REQUIRED: u16 = 0x01;
const EFI_GUIDED_SECTION_AUTH_STATUS_VALID: u16 = 0x02;

// Intel flash descriptor signature and an unused region register.
const FLVALSIG: u32 = 0x0FF0_A55A;
const FLREG_UNUSED: u32 = 0x0000_7FFF;

/// On-disk bytes of a GUID: `data1`, `data2`, `data3` little-endian, then
/// `data4` in order.
fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&data1.to_le_bytes());
    out[4..6].copy_from_slice(&data2.to_le_bytes());
    out[6..8].copy_from_slice(&data3.to_le_bytes());
    out[8..].copy_from_slice(&data4);
    out
}

fn ffs2() -> [u8; 16] {
    guid(
        0x8C8C_E578,
        0x8A3D,
        0x4F1C,
        [0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3],
    )
}

fn ffs3() -> [u8; 16] {
    guid(
        0x5473_C07A,
        0x3DCB,
        0x4DCA,
        [0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A],
    )
}

/// Framework `EFI_FIRMWARE_FILE_SYSTEM_GUID` (`UEFITool` `common/ffs.h`).
fn ffs1() -> [u8; 16] {
    guid(
        0x7A93_54D9,
        0x0468,
        0x444A,
        [0x81, 0xCE, 0x0B, 0xF6, 0x17, 0xD8, 0x90, 0xDF],
    )
}

fn nvram() -> [u8; 16] {
    guid(
        0xFFF1_2B8D,
        0x7696,
        0x4C8B,
        [0xA9, 0x85, 0x27, 0x47, 0x07, 0x5B, 0x4F, 0x50],
    )
}

fn lzma_guid() -> [u8; 16] {
    guid(
        0xEE4E_5898,
        0x3914,
        0x4259,
        [0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF],
    )
}

fn lzma_f86_guid() -> [u8; 16] {
    guid(
        0xD42A_E6BD,
        0x1352,
        0x4BFB,
        [0x90, 0x9A, 0xCA, 0x72, 0xA6, 0xEA, 0xE8, 0x89],
    )
}

fn brotli_guid() -> [u8; 16] {
    guid(
        0x3D53_2050,
        0x5CDA,
        0x4FD0,
        [0x87, 0x9E, 0x0F, 0x7F, 0x63, 0x0D, 0x5A, 0xFB],
    )
}

fn crc32_guid() -> [u8; 16] {
    guid(
        0xFC1B_CDB0,
        0x7D31,
        0x49AA,
        [0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83],
    )
}

fn tiano_guid() -> [u8; 16] {
    guid(
        0xA312_80AD,
        0x481E,
        0x41B6,
        [0x95, 0xE8, 0x12, 0x7F, 0x4C, 0x98, 0x47, 0x79],
    )
}

/// A file name GUID ending in `n`.
fn file_name(n: u8) -> [u8; 16] {
    guid(0x5A1E_7E57, 0, 0x4000, [0x80, 0, 0, 0, 0, 0, 0, n])
}

/// The registry form of `file_name(n)`.
fn file_name_text(n: u8) -> String {
    format!("5A1E7E57-0000-4000-8000-0000000000{n:02X}")
}

/// A PE32+ image: DOS header (`MZ`, `e_lfanew` 0x40), `PE\0\0`, COFF header
/// (machine, one section, 0xF0-byte optional header), PE32+ optional header
/// (magic 0x20B, entry and base of code 0x180), one `.text` header, and
/// 16 B of code at 0x180.
fn pe_image(machine: u16) -> Vec<u8> {
    let mut image = vec![0u8; 0x190];
    image[..2].copy_from_slice(b"MZ");
    image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    image[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
    image[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    image[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
    image[0x56..0x58].copy_from_slice(&0x0022u16.to_le_bytes());
    let optional = 0x58;
    image[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    image[optional + 16..optional + 20].copy_from_slice(&0x180u32.to_le_bytes());
    image[optional + 20..optional + 24].copy_from_slice(&0x180u32.to_le_bytes());
    let text = optional + 0xF0;
    image[text..text + 5].copy_from_slice(b".text");
    image[text + 8..text + 12].copy_from_slice(&16u32.to_le_bytes());
    image[text + 12..text + 16].copy_from_slice(&0x180u32.to_le_bytes());
    image[text + 16..text + 20].copy_from_slice(&16u32.to_le_bytes());
    image[text + 20..text + 24].copy_from_slice(&0x180u32.to_le_bytes());
    image[text + 36..text + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    image[0x180..].fill(0xC3);
    image
}

/// A TE image converted from `pe_image`: `VZ`, machine, one section,
/// subsystem 11, stripped size 0x148 (the PE headers up to the end of the
/// optional header), entry and base of code 0x180, then the kept `.text`
/// header and the code at TE offset 0x60.
fn te_image(machine: u16) -> Vec<u8> {
    let mut image = vec![0u8; 0x70];
    image[..2].copy_from_slice(b"VZ");
    image[2..4].copy_from_slice(&machine.to_le_bytes());
    image[4] = 1;
    image[5] = 11;
    image[6..8].copy_from_slice(&0x148u16.to_le_bytes());
    image[8..12].copy_from_slice(&0x180u32.to_le_bytes());
    image[12..16].copy_from_slice(&0x180u32.to_le_bytes());
    image[0x28..0x2D].copy_from_slice(b".text");
    image[0x30..0x34].copy_from_slice(&16u32.to_le_bytes());
    image[0x34..0x38].copy_from_slice(&0x180u32.to_le_bytes());
    image[0x38..0x3C].copy_from_slice(&16u32.to_le_bytes());
    image[0x3C..0x40].copy_from_slice(&0x180u32.to_le_bytes());
    image[0x4C..0x50].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    image[0x60..].fill(0x90);
    image
}

/// A section: 24-bit size including the 4-byte header, type, body.
fn section(kind: u8, body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(body.len() + 4).expect("small section");
    let mut out = size.to_le_bytes()[..3].to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// An `EFI_COMMON_SECTION_HEADER2` section: size `0xFFFFFF`, type, then the
/// u32 size including the 8-byte header.
fn section2(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFF, 0xFF, kind];
    out.extend_from_slice(&u32::try_from(body.len() + 8).unwrap().to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// `len` rounded up to a multiple of `alignment` (a power of two).
fn align(len: usize, alignment: usize) -> usize {
    (len + alignment - 1) & !(alignment - 1)
}

/// Sections, each followed by zero padding to a 4-byte boundary.
fn sections(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item);
        out.resize(align(out.len(), 4), 0);
    }
    out
}

/// A USER_INTERFACE section: NUL-terminated UCS-2 name.
fn ui(name: &str) -> Vec<u8> {
    let mut body: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    body.extend_from_slice(&[0, 0]);
    section(EFI_SECTION_USER_INTERFACE, &body)
}

/// A GUID-defined section: GUID, `DataOffset` (0x18 plus the GUID-specific
/// fields), attributes, the GUID-specific fields, then the payload.
fn guid_defined(definition: [u8; 16], attributes: u16, fields: &[u8], payload: &[u8]) -> Vec<u8> {
    let data_offset = u16::try_from(0x18 + fields.len()).unwrap();
    let mut body = definition.to_vec();
    body.extend_from_slice(&data_offset.to_le_bytes());
    body.extend_from_slice(&attributes.to_le_bytes());
    body.extend_from_slice(fields);
    body.extend_from_slice(payload);
    section(EFI_SECTION_GUID_DEFINED, &body)
}

/// A compression section: `UncompressedLength`, `CompressionType`, data.
fn compression(kind: u8, uncompressed_length: usize, data: &[u8]) -> Vec<u8> {
    let mut body = u32::try_from(uncompressed_length)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    body.push(kind);
    body.extend_from_slice(data);
    section(EFI_SECTION_COMPRESSION, &body)
}

/// An FFS file with a 24-byte header: name, header checksum (sum of the
/// header with state and file checksum as zero is zero), data checksum
/// (with `FFS_ATTRIB_CHECKSUM`) or the fixed 0xAA, type, attributes,
/// 24-bit size, and `state` stored inverted (erase polarity 1).
fn ffs_file(name: [u8; 16], kind: u8, attributes: u8, data: &[u8], state: u8) -> Vec<u8> {
    let size = u32::try_from(24 + data.len()).unwrap();
    let mut header = name.to_vec();
    header.extend_from_slice(&[0, 0, kind, attributes]);
    header.extend_from_slice(&size.to_le_bytes()[..3]);
    header.push(0);
    finish_file(header, data, attributes, !state)
}

/// An FFSv3 large file: the 32-byte `EFI_FFS_FILE_HEADER2` with
/// `FFS_ATTRIB_LARGE_FILE`, a zero 24-bit size and the u64 extended size.
fn ffs_file2(name: [u8; 16], kind: u8, data: &[u8]) -> Vec<u8> {
    let mut header = name.to_vec();
    header.extend_from_slice(&[0, 0, kind, FFS_ATTRIB_LARGE_FILE, 0, 0, 0, 0]);
    header.extend_from_slice(&(32 + data.len() as u64).to_le_bytes());
    finish_file(header, data, FFS_ATTRIB_LARGE_FILE, !EFI_FILE_DATA_VALID)
}

/// A Framework file with a tail (`UEFITool` `FFS_ATTRIB_TAIL_PRESENT`,
/// bit 0): a 24-byte header whose size covers the tail, the fixed data
/// checksum 0x5A (`FFS_ATTRIB_CHECKSUM` clear), state `DATA_VALID` stored
/// inverted, the data, then the inverted `IntegrityCheck` (header and data
/// checksum bytes, u16 little-endian).
fn framework_file(name: [u8; 16], kind: u8, data: &[u8]) -> Vec<u8> {
    let size = u32::try_from(24 + data.len() + 2).unwrap();
    let mut file = name.to_vec();
    file.extend_from_slice(&[0, 0, kind, FFS_ATTRIB_TAIL_PRESENT]);
    file.extend_from_slice(&size.to_le_bytes()[..3]);
    file.push(0);
    let sum = file.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    file[0x10] = sum.wrapping_neg();
    file[0x11] = FFS_FIXED_CHECKSUM_FRAMEWORK;
    file[0x17] = !EFI_FILE_DATA_VALID;
    let integrity_check = u16::from_le_bytes([file[0x10], file[0x11]]);
    file.extend_from_slice(data);
    file.extend_from_slice(&(!integrity_check).to_le_bytes());
    file
}

/// Fill in both checksums and the stored state of a file header.
fn finish_file(mut header: Vec<u8>, data: &[u8], attributes: u8, stored_state: u8) -> Vec<u8> {
    let sum = header.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    header[0x10] = sum.wrapping_neg();
    header[0x11] = if attributes & FFS_ATTRIB_CHECKSUM == 0 {
        0xAA
    } else {
        data.iter()
            .fold(0u8, |s, b| s.wrapping_add(*b))
            .wrapping_neg()
    };
    header[0x17] = stored_state;
    header.extend_from_slice(data);
    header
}

/// A driver file holding a PE32 section and a UI section.
fn driver(n: u8, machine: u16, name: &str) -> Vec<u8> {
    let data = sections(&[section(EFI_SECTION_PE32, &pe_image(machine)), ui(name)]);
    ffs_file(
        file_name(n),
        EFI_FV_FILETYPE_DRIVER,
        FFS_ATTRIB_CHECKSUM,
        &data,
        EFI_FILE_DATA_VALID,
    )
}

/// A PI (revision 2) firmware volume of `length` bytes.
fn volume(file_system: [u8; 16], attributes: u32, files: &[Vec<u8>], length: usize) -> Vec<u8> {
    volume_of_revision(file_system, attributes, 2, files, length)
}

/// A firmware volume of `length` bytes: zero vector, file system GUID,
/// `FvLength`, `_FVH`, attributes, header length 0x48, checksum (the header
/// words sum to zero), no extended header, `revision`, one block-map entry
/// and the terminator; then the files on 8-byte boundaries and erased free
/// space.
fn volume_of_revision(
    file_system: [u8; 16],
    attributes: u32,
    revision: u8,
    files: &[Vec<u8>],
    length: usize,
) -> Vec<u8> {
    let erase = if attributes & EFI_FVB2_ERASE_POLARITY == 0 {
        0x00
    } else {
        0xFF
    };
    let mut fv = vec![0u8; 0x48];
    fv[0x10..0x20].copy_from_slice(&file_system);
    fv[0x20..0x28].copy_from_slice(&(length as u64).to_le_bytes());
    fv[0x28..0x2C].copy_from_slice(b"_FVH");
    fv[0x2C..0x30].copy_from_slice(&attributes.to_le_bytes());
    fv[0x30..0x32].copy_from_slice(&0x48u16.to_le_bytes());
    fv[0x37] = revision;
    fv[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
    fv[0x3C..0x40].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    let checksum = fv.chunks_exact(2).fold(0u16, |s, w| {
        s.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
    });
    fv[0x32..0x34].copy_from_slice(&checksum.wrapping_neg().to_le_bytes());
    for file in files {
        fv.resize(align(fv.len(), 8), erase);
        fv.extend_from_slice(file);
    }
    assert!(
        fv.len() <= length,
        "volume of {length} B holds {} B",
        fv.len()
    );
    fv.resize(length, erase);
    fv
}

/// An FFSv2 volume with erase polarity 1.
fn ffs2_volume(files: &[Vec<u8>], length: usize) -> Vec<u8> {
    volume(ffs2(), EFI_FVB2_ERASE_POLARITY, files, length)
}

/// A Framework volume: the `FFSv1` GUID, revision 1, erase polarity 1.
fn framework_volume(files: &[Vec<u8>], length: usize) -> Vec<u8> {
    volume_of_revision(ffs1(), EFI_FVB2_ERASE_POLARITY, 1, files, length)
}

/// A volume whose one driver file holds `items` as its sections.
fn volume_with_sections(items: &[Vec<u8>]) -> Vec<u8> {
    let data = sections(items);
    let file = ffs_file(
        file_name(9),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &data,
        EFI_FILE_DATA_VALID,
    );
    ffs2_volume(&[file], 0x1000)
}

/// A flash image: 16 B of 0xFF, `FLVALSIG` at 0x10, `FLMAP0` (FCBA 0x30,
/// FRBA 0x40), `FLMAP1` (FMBA 0x80, FPSBA 0x100), the 16 `FLREG` registers
/// at 0x40 (rest of the descriptor erased), then `body` from 0x1000.
fn flash(regions: [u32; 16], body: &[u8]) -> Vec<u8> {
    let mut image = vec![0xFF; 0x1000];
    image[0x10..0x14].copy_from_slice(&FLVALSIG.to_le_bytes());
    image[0x14..0x18].copy_from_slice(&0x0404_0003u32.to_le_bytes());
    image[0x18..0x1C].copy_from_slice(&0x1010_0208u32.to_le_bytes());
    for (i, flreg) in regions.iter().enumerate() {
        image[0x40 + 4 * i..0x44 + 4 * i].copy_from_slice(&flreg.to_le_bytes());
    }
    image.extend_from_slice(body);
    image
}

/// `FLREG` for the 4 KiB blocks `first..=last`.
fn flreg(first: u32, last: u32) -> u32 {
    first | last << 16
}

/// Descriptor 0x0-0xFFF, GbE 0x1000-0x1FFF, ME 0x2000-0x2FFF and BIOS
/// 0x3000-0x4FFF.
fn standard_regions() -> [u32; 16] {
    let mut regions = [FLREG_UNUSED; 16];
    regions[0] = flreg(0, 0);
    regions[1] = flreg(3, 4);
    regions[2] = flreg(2, 2);
    regions[3] = flreg(1, 1);
    regions
}

/// A flash image with the standard regions and `bios_volume` at the top of
/// the BIOS region.
fn flash_with_bios(bios_volume: &[u8]) -> Vec<u8> {
    let mut body = vec![0x5A; 0x1000];
    body.extend(b"synthetic ME bytes ".repeat(216));
    body.resize(0x2000, 0x4D);
    body.resize(0x4000 - bios_volume.len(), 0xFF);
    body.extend_from_slice(bios_volume);
    flash(standard_regions(), &body)
}

/// Writes bits most significant first.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    fn put(&mut self, count: u32, value: u32) {
        for i in (0..count).rev() {
            if self.bits % 8 == 0 {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

/// An EFI (`pbit` 4) or Tiano (`pbit` 5) stream of one block coding every
/// byte as an 8-bit literal (UEFI 2.10, 19.2): block size (16 bits); the
/// extra set as the single symbol 10 (5-bit count 0, 5-bit symbol), so every
/// char-and-length code length is 8 and takes no bits; a 9-bit count of
/// 256 lengths; a single-symbol position set (`pbit`-bit count 0 and symbol
/// 0); then the bytes. The header holds the compressed size (including the
/// terminating zero byte the EDK2 encoder writes) and the original size.
fn efi_literal_stream(data: &[u8], pbit: u32) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.put(16, u32::try_from(data.len()).expect("one block"));
    w.put(5, 0);
    w.put(5, 10);
    w.put(9, 256);
    w.put(pbit, 0);
    w.put(pbit, 0);
    for &b in data {
        w.put(8, u32::from(b));
    }
    let mut bits = w.bytes;
    bits.push(0);
    let mut out = u32::try_from(bits.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&bits);
    out
}

/// A PE32 section for `machine` with a UI name, as a section stream.
fn pe_sections(machine: u16, name: &str) -> Vec<u8> {
    sections(&[section(EFI_SECTION_PE32, &pe_image(machine)), ui(name)])
}

#[test]
fn volume_lists_pe32_images_with_their_machines_and_ui_names() {
    let fv = ffs2_volume(
        &[
            driver(1, IMAGE_FILE_MACHINE_AMD64, "X64Driver"),
            driver(2, IMAGE_FILE_MACHINE_ARM64, "Aa64Driver"),
        ],
        0x1000,
    );
    assert_eq!(uefi::detect(&fv), Some(Layout::FirmwareVolume));
    let p = classify(&fv);
    assert_eq!(p.format.format, FileFormat::UefiFv);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 2);
    let x64 = slice(
        &p,
        &format!("X64Driver ({}): PE32 image", file_name_text(1)),
    );
    assert_eq!(x64.isa, Isa::X86_64);
    // File at 0x48, 24-byte header, 4-byte section header.
    assert_eq!((x64.offset, x64.size), (0x48 + 24 + 4, 0x190));
    assert!(x64.decoded.is_none());
    let aa64 = slice(&p, "Aa64Driver");
    assert_eq!(aa64.isa, Isa::AArch64);
    assert!(has_note(
        &p,
        "FFSv2 file system; 4 KiB; revision 2; erase polarity 1"
    ));
    assert!(has_note(
        &p,
        "2 FFS files; header checksums valid; 2 data checksums valid"
    ));
    assert!(metadata(&p, "uefi_volume_0").is_some());
}

#[test]
fn committed_fixtures_classify_each_image() {
    let fd = classify(&fixture("sample.fd"));
    assert_eq!(fd.format.format, FileFormat::UefiFv);
    assert_eq!(fd.primary.isa, Isa::X86_64);
    let isas: Vec<_> = fd.slices.iter().map(|s| s.isa).collect();
    assert_eq!(isas, [Isa::X86_64, Isa::AArch64, Isa::X86_64, Isa::X86_64]);
    assert_eq!(
        slice(&fd, "TePeim").variant.as_ref().unwrap().name,
        "TE image"
    );
    let lzma = slice(&fd, "LzmaDxe");
    assert_eq!(lzma.decoded.as_ref().unwrap().transform, "LZMA");
    assert!(has_note(&fd, "1 pad file skipped"));
    assert!(has_note(&fd, "name 5A1E7E57-0000-4000-8000-0000000000A0"));

    let image = classify(&fixture("flash.bin"));
    assert_eq!(image.format.format, FileFormat::IntelIfd);
    assert_eq!(image.primary.isa, Isa::X86_64);
    let bios = slice(&image, "BIOS region firmware volume at 0x4000");
    assert_eq!(
        (bios.offset, bios.size, bios.isa),
        (0x4000, 0x1000, Isa::X86_64)
    );
    assert!(matches!(slice(&image, "ME region").isa, Isa::Unknown(_)));
    assert!(has_note(&image, "ME region: firmware of a separate engine"));
    assert!(has_note(
        &image,
        "regions Descriptor 0x0-0xFFF, GbE 0x1000-0x1FFF, ME 0x2000-0x2FFF, BIOS 0x3000-0x4FFF"
    ));
}

#[test]
fn lzma_guided_sections_decode_the_xz_fixture() {
    let stream = fixture("pe32-sections.bin");
    let stored = fixture("pe32-sections.bin.lzma");
    assert_eq!(
        compressed::decode(Codec::Lzma, &stored).unwrap().data,
        stream
    );
    let encapsulation = guid_defined(
        lzma_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &stored,
    );
    let fv = volume_with_sections(std::slice::from_ref(&encapsulation));
    let p = classify(&fv);
    let image = slice(&p, "LzmaDxe");
    assert_eq!(image.isa, Isa::X86_64);
    // The stored range is the GUID-defined section; the decoded range is
    // the PE32 image inside the LZMA output.
    assert_eq!(
        (image.offset, image.size),
        (0x48 + 24, encapsulation.len() as u64)
    );
    let decoded = image.decoded.as_ref().unwrap();
    // The generator's PE32+ image: 0x180 B of headers and 44 B of code.
    assert_eq!((decoded.transform.as_str(), decoded.size), ("LZMA", 0x1AC));

    let mut corrupt = stored.clone();
    corrupt[20] ^= 0x55;
    let bad = guid_defined(
        lzma_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &corrupt,
    );
    assert!(detect_payload(&volume_with_sections(&[bad]), &ClassifierOptions::new()).is_err());
}

#[test]
fn lzma_f86_sections_undo_the_x86_branch_filter() {
    let stream = fixture("pe32-sections.bin");
    let stored = fixture("pe32-sections.bin.x86.lzma");
    assert_eq!(
        compressed::decode(Codec::LzmaX86, &stored).unwrap().data,
        stream
    );
    assert_ne!(
        compressed::decode(Codec::Lzma, &stored).unwrap().data,
        stream
    );
    let encapsulation = guid_defined(
        lzma_f86_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &stored,
    );
    let p = classify(&volume_with_sections(&[encapsulation]));
    let image = slice(&p, "LzmaDxe");
    assert_eq!(image.isa, Isa::X86_64);
    assert_eq!(image.decoded.as_ref().unwrap().transform, "LZMA x86");
}

#[test]
fn brotli_sections_use_the_edk2_size_prefix() {
    let stream = fixture("pe32-sections.bin");
    let brotli = fixture("pe32-sections.bin.br");
    let mut payload = (stream.len() as u64).to_le_bytes().to_vec();
    payload.extend_from_slice(&0x1000u64.to_le_bytes());
    payload.extend_from_slice(&brotli);
    let encapsulation = guid_defined(
        brotli_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &payload,
    );
    let p = classify(&volume_with_sections(&[encapsulation]));
    assert_eq!(
        slice(&p, "LzmaDxe").decoded.as_ref().unwrap().transform,
        "Brotli"
    );

    payload[0] ^= 1;
    let wrong_size = guid_defined(
        brotli_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &payload,
    );
    assert!(detect_payload(
        &volume_with_sections(&[wrong_size]),
        &ClassifierOptions::new()
    )
    .is_err());
}

#[test]
fn crc32_sections_are_verified_before_their_stream_is_walked() {
    let inner = pe_sections(IMAGE_FILE_MACHINE_I386, "Crc32Pei");
    let crc = crc32(&inner).to_le_bytes();
    let good = guid_defined(
        crc32_guid(),
        EFI_GUIDED_SECTION_AUTH_STATUS_VALID,
        &crc,
        &inner,
    );
    let p = classify(&volume_with_sections(std::slice::from_ref(&good)));
    let image = slice(&p, "Crc32Pei");
    assert_eq!(image.isa, Isa::X86);
    // A CRC32 section's stream stays in file coordinates.
    assert!(image.decoded.is_none());
    assert_eq!(image.offset, 0x48 + 24 + 0x1C + 4);
    assert!(has_note(
        &p,
        "1 CRC32 GUID-defined section: CRC-32 verified"
    ));

    let mut bad = good;
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let err = detect_payload(&volume_with_sections(&[bad]), &ClassifierOptions::new()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Invalid CRC32 GUID-defined section"),
        "{err}"
    );
}

#[test]
fn standard_compression_tries_efi_then_tiano() {
    let inner = pe_sections(IMAGE_FILE_MACHINE_AMD64, "Compressed");
    let efi = compression(1, inner.len(), &efi_literal_stream(&inner, 4));
    let p = classify(&volume_with_sections(std::slice::from_ref(&efi)));
    let image = slice(&p, "Compressed");
    assert_eq!(
        (
            image.isa,
            image.decoded.as_ref().unwrap().transform.as_str()
        ),
        (Isa::X86_64, "EFI")
    );
    assert!(!has_note(&p, "holds Tiano data"));

    let tiano = compression(1, inner.len(), &efi_literal_stream(&inner, 5));
    let p = classify(&volume_with_sections(&[tiano]));
    assert_eq!(
        slice(&p, "Compressed").decoded.as_ref().unwrap().transform,
        "Tiano"
    );
    assert!(has_note(&p, "type 1 (EFI) holds Tiano data; inferred"));

    let guided = guid_defined(
        tiano_guid(),
        EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
        &[],
        &efi_literal_stream(&inner, 5),
    );
    let p = classify(&volume_with_sections(&[guided]));
    assert_eq!(
        slice(&p, "Compressed").decoded.as_ref().unwrap().transform,
        "Tiano"
    );

    // Type 0 stores the stream; it stays in file coordinates.
    let stored = compression(0, inner.len(), &inner);
    let p = classify(&volume_with_sections(&[stored]));
    assert!(slice(&p, "Compressed").decoded.is_none());

    let wrong_length = compression(1, inner.len() + 4, &efi_literal_stream(&inner, 4));
    assert!(detect_payload(
        &volume_with_sections(&[wrong_length]),
        &ClassifierOptions::new()
    )
    .is_err());
    let unsupported = compression(2, inner.len(), &inner);
    let p = classify(&volume_with_sections(&[unsupported]));
    assert!(has_note(&p, "uses unsupported type 0x02; opaque"));
    assert!(matches!(
        slice(&p, "compressed section").isa,
        Isa::Unknown(_)
    ));
}

#[test]
fn unknown_guided_sections_are_opaque_unless_processing_is_not_required() {
    let vendor = guid(0x1234_5678, 0x9ABC, 0xDEF0, [1, 2, 3, 4, 5, 6, 7, 8]);
    let inner = pe_sections(IMAGE_FILE_MACHINE_ARM64, "Plain");
    let plain = guid_defined(vendor, 0, &[], &inner);
    let p = classify(&volume_with_sections(&[plain]));
    assert_eq!(slice(&p, "Plain").isa, Isa::AArch64);

    let processed = guid_defined(vendor, EFI_GUIDED_SECTION_PROCESSING_REQUIRED, &[], &inner);
    let p = classify(&volume_with_sections(&[processed]));
    assert!(has_note(
        &p,
        "GUID-defined section 12345678-9ABC-DEF0-0102-030405060708"
    ));
    let opaque = slice(&p, "GUID-defined section");
    assert!(matches!(opaque.isa, Isa::Unknown(_)));
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));

    let mut bad_offset = guid_defined(vendor, 0, &[], &inner);
    bad_offset[0x14] = 0x10;
    assert!(detect_payload(
        &volume_with_sections(&[bad_offset]),
        &ClassifierOptions::new()
    )
    .is_err());
}

#[test]
fn nested_volume_images_are_walked_in_the_same_container() {
    let nested = ffs2_volume(&[driver(3, IMAGE_FILE_MACHINE_ARM64, "Nested")], 0x400);
    let fv_file = ffs_file(
        file_name(4),
        EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE,
        0,
        &sections(&[section(EFI_SECTION_FIRMWARE_VOLUME_IMAGE, &nested)]),
        EFI_FILE_DATA_VALID,
    );
    let raw_fv = ffs_file(
        file_name(5),
        EFI_FV_FILETYPE_RAW,
        0,
        &nested,
        EFI_FILE_DATA_VALID,
    );
    let fv = ffs2_volume(&[fv_file, raw_fv], 0x1000);
    let p = classify(&fv);
    let images: Vec<_> = p
        .slices
        .iter()
        .filter(|s| s.label.as_deref().is_some_and(|l| l.contains("Nested")))
        .collect();
    assert_eq!(images.len(), 2);
    assert!(images.iter().all(|s| s.isa == Isa::AArch64));
    // Outer volume, then the nested volume found twice.
    assert!(metadata(&p, "uefi_volume_2").is_some());
    assert!(has_note(&p, "Firmware volume at 0x"));
}

#[test]
fn te_and_compatibility16_sections_carry_their_targets() {
    let data = sections(&[
        section(EFI_SECTION_TE, &te_image(IMAGE_FILE_MACHINE_I386)),
        ui("TePeim"),
    ]);
    let peim = ffs_file(
        file_name(6),
        EFI_FV_FILETYPE_PEIM,
        0,
        &data,
        EFI_FILE_DATA_VALID,
    );
    // 16-bit code that happens to start with ELF magic: raw code is never
    // parsed as a nested container.
    let mut real_mode_code = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
    real_mode_code.resize(32, 0xEA);
    let csm = ffs_file(
        file_name(7),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &sections(&[section(EFI_SECTION_COMPATIBILITY16, &real_mode_code)]),
        EFI_FILE_DATA_VALID,
    );
    let p = classify(&ffs2_volume(&[peim, csm], 0x1000));
    let te = slice(&p, "TePeim");
    assert_eq!((te.isa, te.bitwidth), (Isa::X86, 32));
    let real_mode = slice(&p, "16-bit x86 image");
    assert_eq!((real_mode.isa, real_mode.bitwidth), (Isa::X86, 16));
    let label = format!("{}: 16-bit x86 image", file_name_text(7));
    let notes: Vec<_> = p
        .notes
        .iter()
        .filter(|n| n.message.starts_with(&label))
        .collect();
    assert!(!notes.is_empty());
    assert!(
        notes.iter().all(|n| !n.message.contains("ELF")),
        "{notes:?}"
    );
}

#[test]
fn raw_sections_hold_volumes_or_recognized_members() {
    let nested = ffs2_volume(&[driver(3, IMAGE_FILE_MACHINE_ARM64, "InRaw")], 0x400);
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1]);
    elf[16..20].copy_from_slice(&[2, 0, 0x3E, 0]);
    let file = ffs_file(
        file_name(10),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &sections(&[
            section(EFI_SECTION_RAW, &nested),
            section(EFI_SECTION_RAW, &elf),
            section(EFI_SECTION_RAW, b"opaque configuration bytes"),
        ]),
        EFI_FILE_DATA_VALID,
    );
    let p = classify(&ffs2_volume(&[file], 0x1000));
    // The volume in the first RAW section is walked in place; the ELF is
    // listed; the unrecognized bytes are not.
    assert_eq!(slice(&p, "InRaw").isa, Isa::AArch64);
    let member = slice(&p, &format!("{}: raw section", file_name_text(10)));
    assert_eq!((member.isa, member.size), (Isa::X86_64, 64));
    assert_eq!(p.slices.len(), 2);
}

#[test]
fn framework_volumes_use_tails_and_the_0x5a_fixed_checksum() {
    let data = pe_sections(IMAGE_FILE_MACHINE_I386, "FrameworkPei");
    let file = framework_file(file_name(11), EFI_FV_FILETYPE_PEIM, &data);
    let fv = framework_volume(std::slice::from_ref(&file), 0x1000);
    let p = classify(&fv);
    assert_eq!(p.format.format, FileFormat::UefiFv);
    assert_eq!(slice(&p, "FrameworkPei").isa, Isa::X86);
    assert!(has_note(
        &p,
        "Framework FFSv1 file system; 4 KiB; revision 1"
    ));
    assert!(has_note(&p, "1 file tail valid"));

    // The Framework rules come from UEFITool alone: a file that breaks them
    // ends the walk with a note instead of failing the volume.
    let mut bad_tail = file;
    let last = bad_tail.len() - 1;
    bad_tail[last] ^= 0xFF;
    let p = classify(&framework_volume(&[bad_tail], 0x1000));
    assert_eq!(p.format.format, FileFormat::UefiFv);
    assert!(has_note(&p, "file walk stopped: Invalid FFS file tail"));
    assert!(p.slices.is_empty());
}

#[test]
fn ffs_checksums_states_and_pad_files_are_enforced() {
    let good = driver(1, IMAGE_FILE_MACHINE_AMD64, "X64Driver");
    let mut bad_header = good.clone();
    bad_header[0x10] ^= 1;
    let err = detect_payload(
        &ffs2_volume(&[bad_header], 0x1000),
        &ClassifierOptions::new(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("Invalid FFS file header checksum at 0x48"),
        "{err}"
    );
    let mut bad_data = good.clone();
    bad_data[0x30] ^= 1;
    assert!(detect_payload(&ffs2_volume(&[bad_data], 0x1000), &ClassifierOptions::new()).is_err());
    let mut fixed = ffs_file(
        file_name(2),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &pe_sections(IMAGE_FILE_MACHINE_AMD64, "Fixed"),
        EFI_FILE_DATA_VALID,
    );
    fixed[0x11] = 0xAB;
    assert!(detect_payload(&ffs2_volume(&[fixed], 0x1000), &ClassifierOptions::new()).is_err());

    let deleted = ffs_file(
        file_name(3),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &pe_sections(IMAGE_FILE_MACHINE_ARM64, "Gone"),
        EFI_FILE_DELETED,
    );
    let pad = ffs_file(
        [0xFF; 16],
        EFI_FV_FILETYPE_FFS_PAD,
        0,
        &[0xFF; 8],
        EFI_FILE_DATA_VALID,
    );
    let constructing = ffs_file(
        file_name(4),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &[],
        EFI_FILE_HEADER_CONSTRUCTION,
    );
    let p = classify(&ffs2_volume(&[deleted, pad, constructing, good], 0x1000));
    assert_eq!(p.slices.len(), 1);
    assert!(has_note(&p, "1 FFS file; header checksums valid; 1 data checksum valid; 1 pad file skipped; 1 deleted file skipped; 1 incomplete or invalid header skipped"));

    // Erase polarity 0: states are stored as is and free space is zero.
    let data = pe_sections(IMAGE_FILE_MACHINE_ARM64, "Polarity0");
    let mut file = ffs_file(
        file_name(5),
        EFI_FV_FILETYPE_DRIVER,
        0,
        &data,
        EFI_FILE_DATA_VALID,
    );
    file[0x17] = EFI_FILE_DATA_VALID;
    let p = classify(&volume(ffs2(), 0, &[file], 0x1000));
    assert_eq!(slice(&p, "Polarity0").isa, Isa::AArch64);
    assert!(has_note(&p, "erase polarity 0"));
}

#[test]
fn large_files_need_an_ffs3_volume() {
    let data = sections(&[
        section2(EFI_SECTION_PE32, &pe_image(IMAGE_FILE_MACHINE_AMD64)),
        ui("Large"),
    ]);
    let file = ffs_file2(file_name(8), EFI_FV_FILETYPE_DRIVER, &data);
    let p = classify(&volume(
        ffs3(),
        EFI_FVB2_ERASE_POLARITY,
        std::slice::from_ref(&file),
        0x1000,
    ));
    let image = slice(&p, "Large");
    assert_eq!((image.isa, image.offset), (Isa::X86_64, 0x48 + 32 + 8));
    assert!(has_note(&p, "FFSv3 file system"));
    let err = detect_payload(&ffs2_volume(&[file], 0x1000), &ClassifierOptions::new()).unwrap_err();
    assert!(
        err.to_string().contains("Unsupported FFS large file"),
        "{err}"
    );
}

#[test]
fn volume_header_corruption_and_truncation_are_format_errors() {
    let fv = ffs2_volume(&[driver(1, IMAGE_FILE_MACHINE_AMD64, "X64Driver")], 0x400);
    for end in 0..fv.len() {
        let result = detect_payload(&fv[..end], &ClassifierOptions::new());
        if let Ok(p) = result {
            assert_ne!(p.format.format, FileFormat::UefiFv, "prefix {end}");
        }
    }
    for (at, value) in [(0x32, 0x00), (0x37, 0x03), (0x30, 0x49), (0x20, 0xFF)] {
        let mut bad = fv.clone();
        bad[at] ^= value | 1;
        assert!(
            detect_payload(&bad, &ClassifierOptions::new()).is_err(),
            "byte 0x{at:X}"
        );
    }
    let mut no_terminator = fv.clone();
    no_terminator[0x40] = 1;
    let fixup = u16::from_le_bytes([no_terminator[0x32], no_terminator[0x33]]).wrapping_sub(1);
    no_terminator[0x32..0x34].copy_from_slice(&fixup.to_le_bytes());
    let err = detect_payload(&no_terminator, &ClassifierOptions::new()).unwrap_err();
    assert!(
        err.to_string()
            .contains("Missing firmware volume block map terminator"),
        "{err}"
    );
}

#[test]
fn sequences_list_volumes_and_recognized_gaps() {
    let store = volume(nvram(), EFI_FVB2_ERASE_POLARITY, &[], 0x200);
    let code = ffs2_volume(&[driver(1, IMAGE_FILE_MACHINE_ARM64, "Second")], 0x1000);
    let mut image = store;
    image.extend_from_slice(&[0xFF; 0x100]);
    image.extend_from_slice(&code);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::UefiFv);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(has_note(&p, "NVRAM variable store (not interpreted)"));
    assert!(has_note(
        &p,
        "1 further firmware volume after the first one"
    ));

    // A recognized format between volumes is listed; padding is not.
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1]);
    elf[16..20].copy_from_slice(&[2, 0, 0x3E, 0]);
    let mut with_gap = volume(nvram(), EFI_FVB2_ERASE_POLARITY, &[], 0x200);
    with_gap.extend_from_slice(&elf);
    with_gap.extend_from_slice(&code);
    let p = classify(&with_gap);
    assert_eq!(slice(&p, "Data at 0x200").isa, Isa::X86_64);
}

#[test]
fn te_images_are_recognized_strongly_or_structurally() {
    let te = te_image(IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(uefi::detect(&te), Some(Layout::Te));
    let p = classify(&te);
    assert_eq!(p.format.format, FileFormat::UefiTe);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86_64, 64));
    assert!(has_note(&p, "TE image: machine 0x8664"));
    assert_eq!(
        metadata(&p, "uefi_te_stripped_size").as_deref(),
        Some("328")
    );

    let unknown = te_image(0x1234);
    assert_eq!(uefi::detect(&unknown), None);
    assert_eq!(uefi::detect_weak(&unknown), Some(Layout::TeStructural));
    let p = classify(&unknown);
    assert_eq!(p.format.format, FileFormat::UefiTe);
    assert!(has_note(
        &p,
        "Machine 0x1234 names no ISA in the PE/COFF machine table"
    ));

    for end in 0..te.len() {
        if let Ok(p) = detect_payload(&te[..end], &ClassifierOptions::new()) {
            assert_ne!(p.format.format, FileFormat::UefiTe, "prefix {end}");
        }
    }
    let mut overlapping = te.clone();
    overlapping[0x3C..0x40].copy_from_slice(&0x150u32.to_le_bytes());
    assert!(detect_payload(&overlapping, &ClassifierOptions::new()).is_err());
}

#[test]
fn flash_descriptors_list_regions_and_bios_volumes() {
    let code = ffs2_volume(&[driver(1, IMAGE_FILE_MACHINE_AMD64, "X64Driver")], 0x1000);
    let image = flash_with_bios(&code);
    assert_eq!(uefi::detect(&image), Some(Layout::FlashDescriptor));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::IntelIfd);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(
        slice(&p, "BIOS region firmware volume at 0x4000").isa,
        Isa::X86_64
    );
    assert_eq!(
        metadata(&p, "uefi_ifd_region_1").as_deref(),
        Some("0x3000-0x4FFF")
    );
    assert!(matches!(slice(&p, "GbE region").isa, Isa::Unknown(_)));

    // Legacy descriptors put the signature at offset 0.
    let mut legacy = image.clone();
    legacy[..0x10].copy_from_slice(&[0; 16]);
    legacy[..4].copy_from_slice(&FLVALSIG.to_le_bytes());
    legacy[0x04..0x08].copy_from_slice(&0x0404_0003u32.to_le_bytes());
    legacy[0x08..0x0C].copy_from_slice(&0x1010_0208u32.to_le_bytes());
    legacy[0x10..0x14].copy_from_slice(&[0xFF; 4]);
    assert_eq!(classify(&legacy).primary.isa, Isa::X86_64);

    let mut no_bios = standard_regions();
    no_bios[1] = FLREG_UNUSED;
    let err =
        detect_payload(&flash(no_bios, &image[0x1000..]), &ClassifierOptions::new()).unwrap_err();
    assert!(err.to_string().contains("Missing BIOS region"), "{err}");
    let mut overlap = standard_regions();
    overlap[2] = flreg(2, 3);
    let err =
        detect_payload(&flash(overlap, &image[0x1000..]), &ClassifierOptions::new()).unwrap_err();
    assert!(err.to_string().contains("overlaps"), "{err}");
    let mut outside = standard_regions();
    outside[8] = flreg(0x10, 0x10);
    let p = classify(&flash(outside, &image[0x1000..]));
    assert!(has_note(&p, "EC region at 0x10000 is outside the image"));

    for end in 0..image.len() {
        if let Ok(p) = detect_payload(&image[..end], &ClassifierOptions::new()) {
            assert_ne!(p.format.format, FileFormat::IntelIfd, "prefix {end}");
        }
    }
}

#[test]
fn zeroed_region_registers_are_unused_and_nr_is_only_reported() {
    // Old descriptors leave the registers after the last region zero; a
    // zero limit field would end inside the descriptor.
    let mut regions = standard_regions();
    regions[4..].fill(0);
    let code = ffs2_volume(&[driver(1, IMAGE_FILE_MACHINE_AMD64, "X64Driver")], 0x1000);
    let image = flash_with_bios(&code);
    let p = classify(&flash(regions, &image[0x1000..]));
    assert_eq!(p.format.format, FileFormat::IntelIfd);
    assert!(has_note(
        &p,
        "regions Descriptor 0x0-0xFFF, GbE 0x1000-0x1FFF, ME 0x2000-0x2FFF, BIOS 0x3000-0x4FFF;"
    ));
    // FLMAP0 0x04040003: FRBA 0x40, NR 4; FCBA 0x30 and FMBA 0x80 leave
    // room for 16 registers.
    assert!(has_note(
        &p,
        "16 FLREG registers at 0x40 read up to the next map structure; FLMAP0 NR field 4"
    ));
    assert_eq!(
        metadata(&p, "uefi_ifd_signature_offset").as_deref(),
        Some("0x10")
    );
}

#[test]
fn truncated_images_fail_to_parse_in_every_layout() {
    let layouts = [
        (fixture("sample.fd"), Layout::FirmwareVolume),
        (fixture("flash.bin"), Layout::FlashDescriptor),
        (te_image(IMAGE_FILE_MACHINE_AMD64), Layout::Te),
    ];
    for (image, layout) in &layouts {
        assert!(uefi::parse_container(image, *layout).is_ok(), "{layout:?}");
        for end in 0..image.len() {
            assert!(
                uefi::parse_container(&image[..end], *layout).is_err(),
                "{layout:?} prefix {end}"
            );
        }
    }
}

#[test]
fn efi_and_tiano_codecs_decode_hand_built_literal_streams() {
    let data = b"EFI and Tiano share one bitstream".to_vec();
    let efi = efi_literal_stream(&data, 4);
    let tiano = efi_literal_stream(&data, 5);
    assert_eq!(compressed::decode(Codec::Efi, &efi).unwrap().data, data);
    assert_eq!(compressed::decode(Codec::Tiano, &tiano).unwrap().data, data);
    // The position set count is one bit wider in Tiano streams.
    assert!(compressed::decode(Codec::Tiano, &efi).map_or(true, |d| d.data != data));
    assert!(compressed::decode_limited(Codec::Efi, &efi, data.len() - 1).is_err());
    for end in 0..efi.len() - 1 {
        assert!(
            compressed::decode(Codec::Efi, &efi[..end]).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn fixtures_survive_mutation_and_truncation_without_panicking() {
    let inner = pe_sections(IMAGE_FILE_MACHINE_AMD64, "Compressed");
    let images = [
        fixture("sample.fd"),
        volume_with_sections(&[
            compression(1, inner.len(), &efi_literal_stream(&inner, 5)),
            guid_defined(
                lzma_guid(),
                EFI_GUIDED_SECTION_PROCESSING_REQUIRED,
                &[],
                &fixture("pe32-sections.bin.lzma"),
            ),
        ]),
        te_image(IMAGE_FILE_MACHINE_ARM64),
    ];
    for image in &images {
        for end in (0..image.len()).step_by(7) {
            let _ = detect_payload(&image[..end], &ClassifierOptions::new());
        }
        for i in 0..image.len() {
            for mutation in [0x00, 0xFF, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = mutation;
                let _ = uefi::parse_container(&mutated, Layout::FirmwareVolume);
                let _ = uefi::parse_container(&mutated, Layout::Te);
            }
            let mut mutated = image.clone();
            mutated[i] ^= 0xFF;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
    let flash = fixture("flash.bin");
    for i in 0..flash.len() {
        for mutation in [0x00, 0xFF, flash[i] ^ 0x01] {
            let mut mutated = flash.clone();
            mutated[i] = mutation;
            let _ = uefi::parse_container(&mutated, Layout::FlashDescriptor);
        }
        if i % 3 == 0 {
            let mut mutated = flash.clone();
            mutated[i] ^= 0xFF;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
    let framework = framework_volume(
        &[framework_file(
            file_name(11),
            EFI_FV_FILETYPE_PEIM,
            &pe_sections(IMAGE_FILE_MACHINE_I386, "FrameworkPei"),
        )],
        0x400,
    );
    for i in 0..framework.len() {
        let mut mutated = framework.clone();
        mutated[i] ^= 0xFF;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
    }
}

/// A flash device image: an AArch64 branch to 0x1000 (`b #0x1000`), erased
/// bytes, then `volume` at 0x1000.
fn flash_device(volume: &[u8]) -> Vec<u8> {
    let mut image = 0x1400_0400u32.to_le_bytes().to_vec();
    image.resize(0x1000, 0xFF);
    image.extend_from_slice(volume);
    image
}

#[test]
fn flash_device_images_are_recognized_only_when_their_volumes_parse() {
    let fv = ffs2_volume(&[driver(1, IMAGE_FILE_MACHINE_ARM64, "Aa64Driver")], 0x1000);
    let image = flash_device(&fv);
    assert_eq!(uefi::detect(&image), None);
    assert_eq!(uefi::detect_weak(&image), Some(Layout::FlashDevice));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::UefiFv);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("PI flash device image")
    );
    let driver = slice(&p, "Aa64Driver");
    assert_eq!(
        (driver.isa, driver.offset),
        (Isa::AArch64, 0x1000 + 0x48 + 24 + 4)
    );
    assert!(has_note(
        &p,
        "4 KiB of leading data before the first firmware volume at 0x1000"
    ));

    // Weak: a broken file inside the volume means no recognition at all.
    let mut corrupt = image.clone();
    corrupt[0x1000 + 0x48 + 0x10] ^= 1;
    assert_eq!(uefi::detect_weak(&corrupt), None);
    // A volume that is not on a 4 KiB boundary is not looked for.
    let mut unaligned = vec![0xFF; 0x800];
    unaligned.extend_from_slice(&fv);
    assert_eq!(uefi::detect_weak(&unaligned), None);
}

/// The EFI images of the PCI option ROMs `efi-*.rom` in `EFI_ROM_DIR` (for
/// example the iPXE ROMs QEMU ships, whose EFI images EDK2 `EfiRom`
/// compresses). PCI Firmware Specification 3.0: each image starts with
/// `55 AA`; the `PCIR` pointer is at 0x18; `PCIR` holds the image length in
/// 512-byte units at 0x10, the code type at 0x14 (3 is EFI) and the
/// last-image bit 0x80 at 0x15. UEFI 2.10, 14.4.2: the EFI image header
/// holds the compression type at 0x0C (1 is EFI compression) and the image
/// offset at 0x16. Every compressed image must decode with the EFI codec to
/// a PE image of its original size, using the bitstream up to its last
/// data byte, and must fail to decode as Tiano.
#[test]
fn efi_compressed_option_rom_images_from_efi_rom_dir() {
    let Ok(dir) = std::env::var("EFI_ROM_DIR") else {
        eprintln!("skipped: EFI_ROM_DIR is not set");
        return;
    };
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("EFI_ROM_DIR is a directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("efi-") && name.ends_with(".rom"))
        })
        .collect();
    paths.sort();
    let mut decoded_images = 0;
    for path in paths {
        let rom = std::fs::read(&path).expect("readable ROM");
        let mut pos = 0;
        while let Some(image) = rom
            .get(pos..)
            .filter(|image| image.starts_with(&[0x55, 0xAA]))
        {
            let read_u16 = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
            let pcir = usize::from(read_u16(0x18));
            let length = usize::from(read_u16(pcir + 0x10)) * 512;
            let code_type = image[pcir + 0x14];
            let last = image[pcir + 0x15] & 0x80 != 0;
            if code_type == 3 && read_u16(0x0C) == 1 {
                let stream = &image[usize::from(read_u16(0x16))..length];
                let compressed_size = u32::from_le_bytes(stream[..4].try_into().unwrap());
                let original_size = u32::from_le_bytes(stream[4..8].try_into().unwrap());
                let decoded = compressed::decode(Codec::Efi, stream).expect("EFI decode");
                assert_eq!(
                    decoded.data.len(),
                    original_size as usize,
                    "{}",
                    path.display()
                );
                let p = classify(&decoded.data);
                assert_eq!(p.format.format, FileFormat::Pe, "{}", path.display());
                assert!(compressed::decode(Codec::Tiano, stream).is_err());
                // The encoder's last byte is a terminator; the byte before it
                // still holds code bits, so the decoder stayed in step.
                let end = 8 + compressed_size as usize;
                let mut short = stream[..end - 2].to_vec();
                short[..4].copy_from_slice(&(compressed_size - 2).to_le_bytes());
                assert!(compressed::decode(Codec::Efi, &short).is_err());
                decoded_images += 1;
            }
            if last || length == 0 {
                break;
            }
            pos += length;
        }
    }
    eprintln!("{decoded_images} EFI-compressed images decoded");
    assert!(decoded_images > 0, "no EFI-compressed images in {dir}");
}

/// Real EDK2 builds (for example the `edk2-*.fd` images QEMU ships) in the
/// directory `UEFI_FIRMWARE_DIR`: every image classifies as firmware
/// volumes, every image listed in a code image has the image's known
/// primary ISA, and variable stores list nothing.
#[test]
fn edk2_firmware_images_from_uefi_firmware_dir() {
    let Ok(dir) = std::env::var("UEFI_FIRMWARE_DIR") else {
        eprintln!("skipped: UEFI_FIRMWARE_DIR is not set");
        return;
    };
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("UEFI_FIRMWARE_DIR is a directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "fd"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no .fd files in {dir}");
    for path in paths {
        let data = std::fs::read(&path).expect("readable image");
        let p = classify(&data);
        let name = path.display();
        assert_eq!(p.format.format, FileFormat::UefiFv, "{name}");
        eprintln!(
            "{name}: {} slices, primary {}",
            p.slices.len(),
            p.primary.isa
        );
        if p.slices.is_empty() {
            assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
            continue;
        }
        // An EDK2 build targets one architecture, which every PE32 and TE
        // machine field names.
        assert!(!matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
        for s in &p.slices {
            assert_eq!(s.isa, p.primary.isa, "{name}: {:?}", s.label);
        }
    }
}
