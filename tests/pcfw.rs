//! PC firmware blobs: Intel microcode updates (explicit and default sizes,
//! extended signature tables, several updates per file), AMD microcode
//! containers, Intel ME flash partition tables (header versions 1.0, 2.0
//! and 2.1) with code partition directories and manifests, standalone code
//! partitions, AMD flash images with an Embedded Firmware Structure and
//! PSP, BIOS, second-level, ISH and combo directories, and standalone
//! directory tables. Every layout is recognized, reports an unknown ISA
//! with no candidates and opaque components, survives truncation and byte
//! mutation; corrupt strong layouts are format errors and corrupt weak ones
//! are not recognized; an Intel flash descriptor's ME region that holds a
//! partition table is classified as Intel ME.

use zrax::formats::checksum::crc32;
use zrax::formats::{container, detect_format, pcfw, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// Intel SDM Vol. 3A Table 12-7: header version and loader revision 1.
const MICROCODE_HEADER_VERSION: u32 = 1;
const MICROCODE_LOADER_REVISION: u32 = 1;
const MICROCODE_HEADER_SIZE: usize = 48;
/// Section 12.11.1: a data size of 0 means 2000 B of data.
const MICROCODE_DEFAULT_DATA_SIZE: usize = 2000;
/// 18 July 2023 as BCD `mmddyyyy` (Table 12-8).
const MICROCODE_DATE: u32 = 0x0718_2023;
/// Synthetic processor signatures and platform flags.
const SIGNATURE_A: u32 = 0x0009_06EA;
const SIGNATURE_B: u32 = 0x0009_06EB;
const SIGNATURE_C: u32 = 0x0009_06EC;
const PLATFORM_FLAGS: u32 = 0x22;

/// Linux `amd.c` `UCODE_MAGIC` (`DMA\0`), section types and sizes.
const AMD_MAGIC: u32 = 0x0041_4D44;
const AMD_EQUIVALENCE_TABLE_TYPE: u32 = 0;
const AMD_PATCH_TYPE: u32 = 1;
const AMD_PATCH_HEADER_SIZE: usize = 64;
const AMD_PATCH_SIZE: usize = 256;

/// coreboot `cse_fpt.h`: `FPT_ENTRY_VERSION`; `$FPT` entry flags (type in
/// bits 6:0, the valid byte in bits 31:24).
const FPT_ENTRY_VERSION: u8 = 0x10;
const FPT_TYPE_CODE: u32 = 0;
const FPT_TYPE_DATA: u32 = 1;
const FPT_ENTRY_INVALID: u32 = 0xFF << 24;
const ROM_BYPASS_SIZE: usize = 0x10;
const PARTITION_ALIGNMENT: usize = 0x1000;

/// coreboot `ifwitool.c`: `$CPD` entries and the Huffman flag (bit 25 of
/// the offset field, `subpart_entry_1.c`).
const CPD_ENTRY_SIZE: usize = 24;
const CPD_HUFFMAN_FLAG: u32 = 1 << 25;

/// coreboot `ifdtool`: `FLVALSIG`; an unused `FLREG` (base above limit).
const FLVALSIG: u32 = 0x0FF0_A55A;
const FLREG_UNUSED: u32 = 0x0000_7FFF;

/// coreboot `amdfwtool.h`: EFS signature, cookies, entry types, address
/// modes (in bits 63:62 of an entry address).
const EFS_SIGNATURE: u32 = 0x55AA_55AA;
const EFS_OFFSET: usize = 0x2_0000;
const MODE_PHYSICAL: u64 = 0;
const MODE_IMAGE: u64 = 1;
const MODE_TABLE: u64 = 2;
const PSP_BOOTLOADER: u8 = 0x01;
const PSP_SMU_FIRMWARE: u8 = 0x08;
const PSP_FUSE_CHAIN: u8 = 0x0B;
const PSP_RECOVERY_A: u8 = 0x48;
const PSP_BIOS_TABLE: u8 = 0x49;
const PSP_RECOVERY_B: u8 = 0x4A;
const BIOS_RTM_PUBKEY: u8 = 0x05;
const BIOS_APOB: u8 = 0x61;
const BIOS_BIN: u8 = 0x62;
const BIOS_UCODE: u8 = 0x66;
const BIOS_L2_POINTER: u8 = 0x70;
/// `additional_info`: version 0 keeps the address mode in bits 30:29,
/// version 1 (bit 31) in bits 25:24.
const INFO_V1: u32 = 1 << 31;
/// `SPI_ROM_BASE`.
const SPI_ROM_BASE: u32 = 0xFF00_0000;

/// A named way to damage a fixture.
type Corruption = (&'static str, fn(&mut Vec<u8>));

/// A named way to damage a fixture, with the error message it must cause.
type CorruptionWithError = (&'static str, fn(&mut Vec<u8>), &'static str);

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

fn is_pcfw(data: &[u8]) -> bool {
    matches!(
        detect_format(data),
        DetectedFormat::Container {
            kind: container::Kind::PcFw(_)
        }
    )
}

fn is_pcfw_format(format: FileFormat) -> bool {
    matches!(
        format,
        FileFormat::IntelMicrocode
            | FileFormat::AmdMicrocode
            | FileFormat::IntelMe
            | FileFormat::AmdPsp
    )
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Wrapping sum of little-endian DWORDs.
fn dword_sum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |sum, dword| {
        sum.wrapping_add(u32::from_le_bytes(dword.try_into().expect("4 bytes")))
    })
}

/// 8-bit sum with carries dropped.
fn byte_sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

/// `n` rounded up to a multiple of `align`.
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) / align * align
}

/// Synthetic bytes that never form a header.
fn synthetic(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

// Intel microcode.

/// One Intel microcode update (SDM Vol. 3A Tables 12-7 and 12-8): header
/// version 1 (0x00), update revision (0x04), BCD date (0x08), processor
/// signature (0x0C), checksum (0x10, chosen so the header and data sum to
/// 0), loader revision 1 (0x14), platform flags (0x18), data size (0x1C; 0
/// selects 2000 B), total size (0x20), 12 reserved bytes; then synthetic
/// data; then, when `extended` lists signatures, the extended signature
/// table (Tables 12-9 and 12-10): count, a checksum that makes the table
/// sum to 0, 12 reserved bytes, and per entry the signature, the flags and
/// the checksum that makes the update with them sum to 0. The caller picks
/// a data size that makes the total a multiple of 1024 B.
fn intel_update(revision: u32, data_size: u32, extended: &[(u32, u32)]) -> Vec<u8> {
    let data_len = if data_size == 0 {
        MICROCODE_DEFAULT_DATA_SIZE
    } else {
        data_size as usize
    };
    let body = MICROCODE_HEADER_SIZE + data_len;
    let table_len = if extended.is_empty() {
        0
    } else {
        20 + 12 * extended.len()
    };
    let total = body + table_len;
    let mut update = vec![0u8; total];
    put32(&mut update, 0x00, MICROCODE_HEADER_VERSION);
    put32(&mut update, 0x04, revision);
    put32(&mut update, 0x08, MICROCODE_DATE);
    put32(&mut update, 0x0C, SIGNATURE_A);
    put32(&mut update, 0x14, MICROCODE_LOADER_REVISION);
    put32(&mut update, 0x18, PLATFORM_FLAGS);
    put32(&mut update, 0x1C, data_size);
    let total_field = if data_size == 0 { 0 } else { total as u32 };
    put32(&mut update, 0x20, total_field);
    update[MICROCODE_HEADER_SIZE..body].copy_from_slice(&synthetic(data_len, 3));
    let checksum = 0u32.wrapping_sub(dword_sum(&update[..body]));
    put32(&mut update, 0x10, checksum);
    if !extended.is_empty() {
        put32(&mut update, body, extended.len() as u32);
        let primary = SIGNATURE_A
            .wrapping_add(PLATFORM_FLAGS)
            .wrapping_add(checksum);
        for (i, &(signature, flags)) in extended.iter().enumerate() {
            let at = body + 20 + 12 * i;
            put32(&mut update, at, signature);
            put32(&mut update, at + 4, flags);
            let entry_checksum = primary.wrapping_sub(signature).wrapping_sub(flags);
            put32(&mut update, at + 8, entry_checksum);
        }
        let table_checksum = 0u32.wrapping_sub(dword_sum(&update[body..]));
        put32(&mut update, body + 4, table_checksum);
    }
    update
}

/// A 1 KiB update: 976 B of data and no extended table.
fn intel_microcode() -> Vec<u8> {
    intel_update(0xF0, 976, &[])
}

/// A 2 KiB update with two extended signatures: 1956 B of data and a
/// 44 B table.
fn intel_microcode_extended() -> Vec<u8> {
    intel_update(
        0x2C,
        1956,
        &[(SIGNATURE_B, PLATFORM_FLAGS), (SIGNATURE_C, 0x01)],
    )
}

// AMD microcode.

/// An AMD microcode container (Linux `amd.c`): magic, section type 0, the
/// equivalence table length, 16-byte entries (installed CPU signature,
/// errata mask and compare 0, equivalence ID, reserved) ended by an
/// all-zero entry; then per patch a section header (type 1, size) and a
/// 256 B patch whose 64 B header holds the data code (0x00), patch ID
/// (0x04) and processor revision ID (0x18), followed by synthetic bytes.
fn amd_container(cpus: &[(u32, u16)], patches: &[(u32, u16)]) -> Vec<u8> {
    let mut table = Vec::new();
    for &(cpu, equivalence_id) in cpus.iter().chain([&(0, 0)]) {
        let mut entry = [0u8; 16];
        put32(&mut entry, 0, cpu);
        put16(&mut entry, 12, equivalence_id);
        table.extend_from_slice(&entry);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&AMD_MAGIC.to_le_bytes());
    out.extend_from_slice(&AMD_EQUIVALENCE_TABLE_TYPE.to_le_bytes());
    out.extend_from_slice(&(table.len() as u32).to_le_bytes());
    out.extend_from_slice(&table);
    for &(patch_id, equivalence_id) in patches {
        let mut patch = synthetic(AMD_PATCH_SIZE, 9);
        patch[..AMD_PATCH_HEADER_SIZE].fill(0);
        put32(&mut patch, 0x00, 0x2023_0307);
        put32(&mut patch, 0x04, patch_id);
        put16(&mut patch, 0x18, equivalence_id);
        out.extend_from_slice(&AMD_PATCH_TYPE.to_le_bytes());
        out.extend_from_slice(&(patch.len() as u32).to_le_bytes());
        out.extend_from_slice(&patch);
    }
    out
}

fn amd_microcode() -> Vec<u8> {
    amd_container(
        &[(0x00A2_0F10, 0xA210), (0x00A2_0F12, 0xA212)],
        &[(0x0A20_1016, 0xA210), (0x0A20_1210, 0xA212)],
    )
}

// Intel ME.

/// A `$MN2` manifest header (coreboot `ifwitool.c` `manifest_header`):
/// header type 4, header length 0xA1 dwords, header version 0x10000, flags
/// 0, vendor 0x8086, BCD date, size 0x40 dwords, the `$MN2` tag at 0x1C and
/// the version as four u16 at 0x24; the key and signature area synthetic.
fn manifest(version: [u16; 4]) -> Vec<u8> {
    let mut out = synthetic(0x100, 0x41);
    put32(&mut out, 0x00, 4);
    put32(&mut out, 0x04, 0xA1);
    put32(&mut out, 0x08, 0x1_0000);
    put32(&mut out, 0x0C, 0);
    put32(&mut out, 0x10, 0x8086);
    put32(&mut out, 0x14, 0x2023_0718);
    put32(&mut out, 0x18, 0x40);
    out[0x1C..0x20].copy_from_slice(b"$MN2");
    for (i, part) in version.iter().enumerate() {
        put16(&mut out, 0x24 + 2 * i, *part);
    }
    out
}

/// A module of a code partition: name, bytes, Huffman flag.
type Module = (&'static str, Vec<u8>, bool);

/// The FTPR modules: the manifest, a metadata file and a Huffman-flagged
/// code module.
fn ftpr_modules() -> Vec<Module> {
    vec![
        ("FTPR.man", manifest([11, 8, 50, 3399]), false),
        ("rbe.met", synthetic(0x30, 0x11), false),
        ("rbe", synthetic(0x80, 0x22), true),
    ]
}

/// A code partition directory (coreboot `ifwitool.c`, `subpart_hdr_1.c`,
/// `subpart_hdr_2.c`): `$CPD`, entry count, header version, entry version
/// 1, header length (0x10 or 0x14), the version 1 checksum (two's
/// complement of the 8-bit sum of header and entries) or a reserved byte,
/// the partition name, and in version 2 a CRC-32 of the header and entries
/// with the field zeroed; 24-byte entries (12-byte name, offset from the
/// directory with bit 25 for Huffman, length, reserved); then the modules,
/// each 16-byte aligned.
fn cpd(version: u8, name: &[u8; 4], modules: &[Module]) -> Vec<u8> {
    let header_size = if version == 1 { 0x10 } else { 0x14 };
    let table_size = header_size + CPD_ENTRY_SIZE * modules.len();
    let mut out = vec![0u8; table_size];
    out[..4].copy_from_slice(b"$CPD");
    put32(&mut out, 0x04, modules.len() as u32);
    out[0x08] = version;
    out[0x09] = 1;
    out[0x0A] = header_size as u8;
    out[0x0C..0x10].copy_from_slice(name);
    let mut offset = round_up(table_size, 16);
    for (i, (module_name, bytes, huffman)) in modules.iter().enumerate() {
        let at = header_size + CPD_ENTRY_SIZE * i;
        out[at..at + module_name.len()].copy_from_slice(module_name.as_bytes());
        let flag = if *huffman { CPD_HUFFMAN_FLAG } else { 0 };
        put32(&mut out, at + 0x0C, offset as u32 | flag);
        put32(&mut out, at + 0x10, bytes.len() as u32);
        offset = round_up(offset + bytes.len(), 16);
    }
    if version == 1 {
        out[0x0B] = 0u8.wrapping_sub(byte_sum(&out));
    } else {
        let checksum = crc32(&out);
        put32(&mut out, 0x10, checksum);
    }
    for (_, bytes, _) in modules {
        out.resize(round_up(out.len(), 16), 0);
        out.extend_from_slice(bytes);
    }
    out
}

/// A partition of an ME region: name, `$FPT` flags, bytes.
type Partition = (&'static [u8; 4], u32, Vec<u8>);

/// An ME region (coreboot `cse_fpt.c`, `fpt_hdr_20.c`, `fpt_hdr_21.c`;
/// `me_cleaner`; `UEFITool` `me.h`): a zero ROM bypass vector, the `$FPT`
/// header at 0x10 (entry count, `version`, entry version 0x10,
/// `header_length`, the 8-bit checksum at 0x1B for versions 0x10 and 0x20
/// or the CRC-32 at 0x24 for 0x21, FITC version 11.8.50.3399 at 0x28),
/// 32-byte entries (name, owner, offset from the region start, length,
/// reserved, flags), absent entries with the invalid flag, then each
/// partition at the next 4 KiB boundary. A header length of 0x30 makes the
/// 8-bit checksum cover the ROM bypass vector too.
fn me_region(
    version: u8,
    header_length: u8,
    partitions: &[Partition],
    absent: &[&[u8; 4]],
) -> Vec<u8> {
    let count = partitions.len() + absent.len();
    let mut out = vec![0u8; ROM_BYPASS_SIZE + 0x20 + 0x20 * count];
    out[0x10..0x14].copy_from_slice(b"$FPT");
    put32(&mut out, 0x14, count as u32);
    out[0x18] = version;
    out[0x19] = FPT_ENTRY_VERSION;
    out[0x1A] = header_length;
    put16(&mut out, 0x1C, 0x10);
    put16(&mut out, 0x1E, 0x20);
    for (i, part) in [11u16, 8, 50, 3399].iter().enumerate() {
        put16(&mut out, 0x28 + 2 * i, *part);
    }
    let mut offset = PARTITION_ALIGNMENT;
    for (i, (name, flags, bytes)) in partitions.iter().enumerate() {
        let at = 0x30 + 0x20 * i;
        out[at..at + 4].copy_from_slice(*name);
        put32(&mut out, at + 0x08, offset as u32);
        put32(&mut out, at + 0x0C, bytes.len() as u32);
        put32(&mut out, at + 0x1C, *flags);
        offset = round_up(offset + bytes.len(), PARTITION_ALIGNMENT);
    }
    for (i, name) in absent.iter().enumerate() {
        let at = 0x30 + 0x20 * (partitions.len() + i);
        out[at..at + 4].copy_from_slice(*name);
        put32(&mut out, at + 0x1C, FPT_ENTRY_INVALID);
    }
    match version {
        0x21 => {
            let checksum = fpt_crc(&out, count);
            put32(&mut out, 0x24, checksum);
        }
        _ => {
            let start = if header_length == 0x30 { 0 } else { 0x10 };
            let sum = byte_sum(&out[start..0x30]);
            out[0x1B] = 0u8.wrapping_sub(sum);
        }
    }
    for (_, _, bytes) in partitions {
        out.resize(round_up(out.len(), PARTITION_ALIGNMENT), 0xFF);
        out.extend_from_slice(bytes);
    }
    out.resize(round_up(out.len(), PARTITION_ALIGNMENT), 0xFF);
    out
}

/// The `$FPT` 2.1 CRC-32 (`MEA.py`) of a region whose header is at 0x10:
/// the 32-byte header with the CRC field (0x24) zeroed, then `entries`
/// 32-byte entries.
fn fpt_crc(region: &[u8], entries: usize) -> u32 {
    let mut covered = region[0x10..0x30 + 0x20 * entries].to_vec();
    covered[0x14..0x18].fill(0);
    crc32(&covered)
}

/// Recompute the 8-bit checksum of a version 0x20 header at 0x10.
fn fix_fpt_checksum(region: &mut [u8]) {
    region[0x1B] = 0;
    region[0x1B] = 0u8.wrapping_sub(byte_sum(&region[0x10..0x30]));
}

/// An ME 11-style region: FTPR (code, a version 1 `$CPD`), MFS (data) and
/// an invalid NFTP entry, header version 0x20.
fn me_region_v20() -> Vec<u8> {
    me_region(
        0x20,
        0x20,
        &[
            (b"FTPR", FPT_TYPE_CODE, cpd(1, b"FTPR", &ftpr_modules())),
            (b"MFS\0", FPT_TYPE_DATA, synthetic(0x200, 0x33)),
        ],
        &[b"NFTP"],
    )
}

/// A pre-ME 11 region: header version 0x10 with the ROM bypass vector in
/// the checksum, and an FTPR partition that starts with its manifest.
fn me_region_v10() -> Vec<u8> {
    me_region(
        0x10,
        0x30,
        &[(b"FTPR", FPT_TYPE_CODE, manifest([9, 1, 2, 1000]))],
        &[],
    )
}

/// A CSME 12+ region: header version 0x21 with its CRC-32, and an FTPR
/// partition with a version 2 `$CPD`.
fn me_region_v21() -> Vec<u8> {
    me_region(
        0x21,
        0x20,
        &[(b"FTPR", FPT_TYPE_CODE, cpd(2, b"FTPR", &ftpr_modules()))],
        &[],
    )
}

/// A flash image with an Intel flash descriptor (coreboot `ifdtool`):
/// `FLVALSIG` at 0x10, `FLMAP0` at 0x14 (FCBA 0x30, FRBA 0x40), `FLMAP1`
/// at 0x18 (FMBA 0x80, FPSBA 0x100), sixteen `FLREG` registers at 0x40
/// (base in bits 14:0 and limit in bits 30:16, 4 KiB units): descriptor
/// 0x0-0xFFF, the ME region from 0x1000, then an erased 4 KiB BIOS region.
fn flash_with_me(me: &[u8]) -> Vec<u8> {
    assert_eq!(me.len() % 0x1000, 0);
    let me_blocks = (me.len() / 0x1000) as u32;
    let mut image = vec![0xFF; 0x1000];
    put32(&mut image, 0x10, FLVALSIG);
    put32(&mut image, 0x14, 0x0004_0003);
    put32(&mut image, 0x18, 0x0010_0008);
    let mut registers = [FLREG_UNUSED; 16];
    registers[0] = 0;
    registers[1] = (me_blocks + 1) | (me_blocks + 1) << 16;
    registers[2] = 1 | me_blocks << 16;
    for (i, register) in registers.iter().enumerate() {
        put32(&mut image, 0x40 + 4 * i, *register);
    }
    image.extend_from_slice(me);
    image.resize(image.len() + 0x1000, 0xFF);
    image
}

// AMD PSP.

/// amdfwtool `fletcher32`: 16-bit little-endian words into two registers
/// that start at 0xFFFF, folded (end-around carry) after every 359 words
/// and once more at the end; `c1 << 16 | c0`.
fn fletcher32(bytes: &[u8]) -> u32 {
    let fold = |sum: u32| (sum & 0xFFFF) + (sum >> 16);
    let mut c0: u32 = 0xFFFF;
    let mut c1: u32 = 0xFFFF;
    for block in bytes.chunks(359 * 2) {
        for word in block.chunks_exact(2) {
            c0 = c0.wrapping_add(u32::from(u16::from_le_bytes([word[0], word[1]])));
            c1 = c1.wrapping_add(c0);
        }
        c0 = fold(c0);
        c1 = fold(c1);
    }
    (fold(c1) << 16) | fold(c0)
}

/// A PSP directory entry (`psp_directory_entry`): type, subprogram,
/// reserved u16, size, then the address with the address mode in bits
/// 63:62.
fn psp_entry(kind: u8, size: u32, address: u64, mode: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 16];
    entry[0] = kind;
    put32(&mut entry, 4, size);
    put64(&mut entry, 8, address | mode << 62);
    entry
}

/// A BIOS directory entry (`bios_directory_entry`): type, region type,
/// flags (bit 3 compressed, instance in bits 7:4), subprogram, size, the
/// source with the address mode in bits 63:62, the destination.
fn bios_entry(kind: u8, flags: u8, size: u32, source: u64, mode: u64, destination: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 24];
    entry[0] = kind;
    entry[2] = flags;
    put32(&mut entry, 4, size);
    put64(&mut entry, 8, source | mode << 62);
    put64(&mut entry, 16, destination);
    entry
}

/// A PSP or BIOS directory (`psp_directory_header`): cookie, the
/// Fletcher-32 checksum of everything after it, entry count, additional
/// info, entries.
fn directory(cookie: &[u8; 4], info: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    out[..4].copy_from_slice(cookie);
    put32(&mut out, 8, entries.len() as u32);
    put32(&mut out, 12, info);
    for entry in entries {
        out.extend_from_slice(entry);
    }
    let checksum = fletcher32(&out[8..]);
    put32(&mut out, 4, checksum);
    out
}

/// A combo directory (`psp_combo_header`): cookie, checksum, entry count,
/// lookup 0, 16 reserved bytes, then entries (ID select 0, PSP ID, the
/// directory pointer as u64).
fn combo_directory(cookie: &[u8; 4], pointers: &[u64]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[..4].copy_from_slice(cookie);
    put32(&mut out, 8, pointers.len() as u32);
    for &pointer in pointers {
        let mut entry = vec![0u8; 16];
        put32(&mut entry, 4, 0xBC0A_0000);
        put64(&mut entry, 8, pointer);
        out.extend_from_slice(&entry);
    }
    let checksum = fletcher32(&out[8..]);
    put32(&mut out, 4, checksum);
    out
}

/// An ISH directory (`ish_directory_table`): Fletcher-32 of the 28 bytes
/// after the checksum, boot priority, update retry count 2, glitch retry
/// count 0, the PSP L2 pointer, PSP ID, slot size 0x1000, reserved.
fn ish_directory(level2: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    put32(&mut out, 0x04, 0xFFFF_FFFF);
    put32(&mut out, 0x08, 2);
    put32(&mut out, 0x10, level2);
    put32(&mut out, 0x14, 0xBC0A_0000);
    put32(&mut out, 0x18, 0x1000);
    let checksum = fletcher32(&out[4..]);
    put32(&mut out, 0, checksum);
    out
}

/// The Embedded Firmware Structure (`embedded_firmware`, 0x50 B): the
/// signature, erased IMC/GEC/xHCI pointers, `psp_directory` (0x10),
/// `new_psp_directory` (0x14), erased `bios0`-`bios2` entries, `efs_gen`
/// with bit 0 clear (second generation, 0x24), `bios3_entry` (0x28), the
/// rest erased.
fn efs(psp: u32, combo: u32, bios: u32) -> Vec<u8> {
    let mut out = vec![0xFF; 0x50];
    put32(&mut out, 0x00, EFS_SIGNATURE);
    put32(&mut out, 0x10, psp);
    put32(&mut out, 0x14, combo);
    put32(&mut out, 0x24, 0xFFFF_FFFE);
    put32(&mut out, 0x28, bios);
    out
}

/// Image offsets of the AMD fixture (all after the EFS at 0x20000).
const PSP_L1: usize = 0x2_0100;
const PSP_L2_A: usize = 0x2_0200;
const ISH_A: usize = 0x2_0300;
const BIOS_L1: usize = 0x2_0400;
const BIOS_L2: usize = 0x2_0500;
const PSP_L2_B: usize = 0x2_0600;
const BOOTLOADER: usize = 0x2_0800;
const SMU_FIRMWARE: usize = 0x2_0900;
const BIOS_IMAGE: usize = 0x2_0A00;
const MICROCODE: usize = 0x2_0B00;
const AMD_IMAGE_END: usize = 0x2_0C00;

/// Place `bytes` at `at` in `image`.
fn place(image: &mut [u8], at: usize, bytes: &[u8]) {
    image[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A 0x20C00 B AMD flash image: erased flash, the EFS at 0x20000 with a
/// physical `psp_directory` and an image-relative `bios3_entry`;
///
/// - `$PSP` (address mode 1): a boot loader, the soft fuse chain value,
///   recovery A through an ISH directory to `$PL2` A, recovery B straight
///   to `$PL2` B, and the BIOS table link to `$BL2`;
/// - `$PL2` A (version 1 info, mode 2): SMU firmware at a table-relative
///   address;
/// - `$BHD` (mode 0, physical): the compressed BIOS image, an APOB with a
///   DRAM destination only, and the L2 link to the same `$BL2`;
/// - `$BL2` (mode 1): microcode instance 1, and an RTM key outside the
///   file;
/// - `$PL2` B (mode 1): the same boot loader again.
fn amd_image() -> Vec<u8> {
    let mut image = vec![0xFF; AMD_IMAGE_END];
    let physical = |offset: usize| u64::from(SPI_ROM_BASE) + offset as u64;
    place(
        &mut image,
        EFS_OFFSET,
        &efs(SPI_ROM_BASE + PSP_L1 as u32, 0, BIOS_L1 as u32),
    );
    let psp_l1 = directory(
        b"$PSP",
        1 << 29,
        &[
            psp_entry(PSP_BOOTLOADER, 0x100, BOOTLOADER as u64, MODE_IMAGE),
            psp_entry(PSP_FUSE_CHAIN, 0xFFFF_FFFF, 1, MODE_PHYSICAL),
            psp_entry(PSP_RECOVERY_A, 0x1000, ISH_A as u64, MODE_IMAGE),
            psp_entry(PSP_RECOVERY_B, 0x400, PSP_L2_B as u64, MODE_IMAGE),
            psp_entry(PSP_BIOS_TABLE, 0x400, BIOS_L2 as u64, MODE_IMAGE),
        ],
    );
    place(&mut image, PSP_L1, &psp_l1);
    let smu_relative = (SMU_FIRMWARE - PSP_L2_A) as u64;
    let psp_l2_a = directory(
        b"$PL2",
        INFO_V1 | 2 << 24,
        &[psp_entry(PSP_SMU_FIRMWARE, 0x80, smu_relative, MODE_TABLE)],
    );
    place(&mut image, PSP_L2_A, &psp_l2_a);
    place(&mut image, ISH_A, &ish_directory(PSP_L2_A as u32));
    let bios_l1 = directory(
        b"$BHD",
        0,
        &[
            bios_entry(
                BIOS_BIN,
                1 << 3,
                0x100,
                physical(BIOS_IMAGE),
                MODE_PHYSICAL,
                0x7600_0000,
            ),
            bios_entry(BIOS_APOB, 0, 0x1_0000, 0, MODE_PHYSICAL, 0x7500_0000),
            bios_entry(
                BIOS_L2_POINTER,
                0,
                0x400,
                physical(BIOS_L2),
                MODE_PHYSICAL,
                0,
            ),
        ],
    );
    place(&mut image, BIOS_L1, &bios_l1);
    let bios_l2 = directory(
        b"$BL2",
        1 << 29,
        &[
            bios_entry(
                BIOS_UCODE,
                1 << 4,
                0x40,
                MICROCODE as u64,
                MODE_IMAGE,
                u64::MAX,
            ),
            bios_entry(BIOS_RTM_PUBKEY, 0, 0x100, 0x3_0000, MODE_IMAGE, u64::MAX),
        ],
    );
    place(&mut image, BIOS_L2, &bios_l2);
    let psp_l2_b = directory(
        b"$PL2",
        1 << 29,
        &[psp_entry(
            PSP_BOOTLOADER,
            0x100,
            BOOTLOADER as u64,
            MODE_IMAGE,
        )],
    );
    place(&mut image, PSP_L2_B, &psp_l2_b);
    place(&mut image, BOOTLOADER, &synthetic(0x100, 0x51));
    place(&mut image, SMU_FIRMWARE, &synthetic(0x80, 0x52));
    place(&mut image, BIOS_IMAGE, &synthetic(0x100, 0x53));
    place(&mut image, MICROCODE, &synthetic(0x40, 0x54));
    image
}

/// A 0x20400 B AMD flash image whose EFS names only `new_psp_directory`: a
/// `2PSP` combo directory at 0x20100 that points to a `$PSP` at 0x20200
/// with one boot loader at 0x20300.
fn amd_combo_image() -> Vec<u8> {
    let mut image = vec![0xFF; 0x2_0400];
    place(&mut image, EFS_OFFSET, &efs(0, 0x2_0100, 0));
    place(&mut image, 0x2_0100, &combo_directory(b"2PSP", &[0x2_0200]));
    let psp = directory(
        b"$PSP",
        1 << 29,
        &[psp_entry(PSP_BOOTLOADER, 0x40, 0x2_0300, MODE_IMAGE)],
    );
    place(&mut image, 0x2_0200, &psp);
    place(&mut image, 0x2_0300, &synthetic(0x40, 0x61));
    image
}

/// A standalone `$PSP` directory (version 1 info, mode 2): a boot loader
/// at table-relative 0x40 inside the file and SMU firmware at an
/// image-relative address the file cannot resolve.
fn psp_table() -> Vec<u8> {
    let mut out = directory(
        b"$PSP",
        INFO_V1 | 2 << 24,
        &[
            psp_entry(PSP_BOOTLOADER, 0x20, 0x40, MODE_TABLE),
            psp_entry(PSP_SMU_FIRMWARE, 0x80, 0x2_0900, MODE_IMAGE),
        ],
    );
    out.resize(0x40, 0xFF);
    out.extend_from_slice(&synthetic(0x20, 0x71));
    out
}

/// Every fixture with its JSON format and variant name.
fn fixtures() -> Vec<(&'static str, Vec<u8>, FileFormat, &'static str)> {
    vec![
        (
            "intel-ucode",
            intel_microcode(),
            FileFormat::IntelMicrocode,
            "Intel microcode update",
        ),
        (
            "intel-ucode-extended",
            intel_microcode_extended(),
            FileFormat::IntelMicrocode,
            "Intel microcode update",
        ),
        (
            "amd-ucode",
            amd_microcode(),
            FileFormat::AmdMicrocode,
            "AMD microcode container",
        ),
        (
            "me-v20",
            me_region_v20(),
            FileFormat::IntelMe,
            "Intel ME flash partition table",
        ),
        (
            "me-v10",
            me_region_v10(),
            FileFormat::IntelMe,
            "Intel ME flash partition table",
        ),
        (
            "me-v21",
            me_region_v21(),
            FileFormat::IntelMe,
            "Intel ME flash partition table",
        ),
        (
            "cpd",
            cpd(1, b"FTPR", &ftpr_modules()),
            FileFormat::IntelMe,
            "Intel ME code partition directory",
        ),
        (
            "amd-efs",
            amd_image(),
            FileFormat::AmdPsp,
            "AMD flash image (Embedded Firmware Structure)",
        ),
        (
            "amd-combo",
            amd_combo_image(),
            FileFormat::AmdPsp,
            "AMD flash image (Embedded Firmware Structure)",
        ),
        (
            "psp-table",
            psp_table(),
            FileFormat::AmdPsp,
            "AMD PSP/BIOS directory table",
        ),
    ]
}

#[test]
fn every_layout_is_recognized_with_its_format_and_variant() {
    for (name, data, format, variant) in fixtures() {
        assert!(is_pcfw(&data), "{name}: {:?}", detect_format(&data));
        let p = classify(&data);
        assert_eq!(p.format.format, format, "{name}");
        assert_eq!(p.format.variant_name.as_deref(), Some(variant), "{name}");
    }
}

#[test]
fn pc_firmware_never_reaches_the_code_model() {
    for (name, data, _, _) in fixtures() {
        let p = classify(&data);
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
        assert_eq!(p.primary.confidence, 0.0, "{name}");
        assert!(p.candidates.is_empty(), "{name}: {:?}", p.candidates);
        assert!(p.extensions.is_empty(), "{name}");
        assert!(!p.slices.is_empty(), "{name}");
        for slice in &p.slices {
            assert!(matches!(slice.isa, Isa::Unknown(_)), "{name}: {slice:?}");
        }
        assert!(
            has_note(&p, "opaque; payload ISA analysis skipped"),
            "{name}"
        );
    }
}

#[test]
fn weak_layouts_are_reported_with_reduced_format_confidence() {
    for (name, data, _, _) in fixtures() {
        let p = classify(&data);
        let weak = matches!(
            name,
            "intel-ucode" | "intel-ucode-extended" | "amd-efs" | "amd-combo"
        );
        if weak {
            assert!(p.format.confidence < 1.0, "{name}");
        } else {
            assert_eq!(p.format.confidence, 1.0, "{name}");
        }
    }
}

#[test]
fn intel_updates_report_their_header_and_verified_checksums() {
    let data = intel_microcode_extended();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "Microcode update data: encrypted, with no executable code"
    ));
    assert!(has_note(
        &p,
        "Update 1 at 0x0: revision 0x2C, date 2023-07-18, processor signature 0x000906EA, platform flags 0x22; 1956 B of encrypted data in 2 KiB"
    ));
    assert!(has_note(
        &p,
        "2 extended signatures (0x000906EB, 0x000906EC), each checksum verified"
    ));
    assert_eq!(
        metadata(&p, "pcfw_microcode_0_date").as_deref(),
        Some("2023-07-18")
    );
    assert_eq!(
        metadata(&p, "pcfw_microcode_0_signature").as_deref(),
        Some("0x000906EA")
    );
    let update = slice(
        &p,
        "Microcode update 1 (processor signature 0x000906EA, revision 0x2C)",
    );
    assert_eq!((update.offset, update.size), (0, 2048));
}

#[test]
fn intel_updates_concatenate_and_take_the_default_size() {
    let mut data = intel_update(0x10, 0, &[]);
    assert_eq!(data.len(), 2048);
    data.extend_from_slice(&intel_microcode());
    data.extend_from_slice(&[0xFF; 0x400]);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::IntelMicrocode);
    assert_eq!(p.slices.len(), 2);
    assert_eq!((p.slices[1].offset, p.slices[1].size), (2048, 1024));
    assert!(has_note(
        &p,
        "2 updates; header version 1, loader revision 1"
    ));
    assert!(has_note(&p, "2000 B of encrypted data in 2 KiB"));
    assert!(has_note(&p, "1 KiB of erased-flash padding after 0xC00"));
}

#[test]
fn intel_microcode_is_recognized_only_when_every_check_passes() {
    let corruptions: [Corruption; 9] = [
        ("header version", |d| put32(d, 0x00, 2)),
        ("loader revision", |d| put32(d, 0x14, 2)),
        ("checksum", |d| d[0x40] ^= 1),
        ("BCD date", |d| put32(d, 0x08, 0x0718_20A3)),
        ("month", |d| put32(d, 0x08, 0x1318_2023)),
        ("total size", |d| put32(d, 0x20, 0x7FF)),
        ("data size", |d| put32(d, 0x1C, 975)),
        ("extended count", |d| {
            let at = 48 + 1956;
            put32(d, at, 3);
        }),
        ("trailing data", |d| {
            d.extend_from_slice(b"not an update header at all, 48 bytes long....")
        }),
    ];
    for (name, corrupt) in corruptions {
        let mut data = intel_microcode_extended();
        corrupt(&mut data);
        assert!(!is_pcfw(&data), "{name}: {:?}", detect_format(&data));
    }
    // An extended signature whose checksum no longer matches, in a table
    // that still sums to 0: the signature grows by one and a reserved
    // DWORD of the table header shrinks by one.
    let mut data = intel_microcode_extended();
    let table = 48 + 1956;
    let signature = u32::from_le_bytes(data[table + 20..table + 24].try_into().unwrap());
    put32(&mut data, table + 20, signature + 1);
    put32(&mut data, table + 8, u32::MAX);
    assert!(!is_pcfw(&data));
    assert!(!is_pcfw(&intel_microcode_extended()[..2047]));
}

#[test]
fn amd_containers_list_patches_and_the_equivalence_table() {
    let data = amd_microcode();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "Container 1 at 0x0: equivalence table with 2 processor signatures (0x00A20F10, 0x00A20F12); 2 patches"
    ));
    assert!(has_note(
        &p,
        "the container format has no checksum, and the patch checksum field is not verified"
    ));
    assert!(has_note(
        &p,
        "Patch 0x0A201016 at 0x44: 256 B, equivalence ID 0xA210"
    ));
    let first = slice(&p, "Microcode patch 0x0A201016 (equivalence ID 0xA210)");
    // 12 B header, 3 entries of 16 B, the 8 B section header.
    assert_eq!((first.offset, first.size), (0x44, 256));
    let second = slice(&p, "Microcode patch 0x0A201210 (equivalence ID 0xA212)");
    assert_eq!(second.offset, 0x44 + 256 + 8);
    assert_eq!(metadata(&p, "pcfw_amd_patch_count").as_deref(), Some("2"));
}

#[test]
fn amd_containers_glue_and_end_in_padding() {
    let mut data = amd_microcode();
    data.extend(amd_container(
        &[(0x0086_0F81, 0x8681)],
        &[(0x0860_010D, 0x8681)],
    ));
    data.extend_from_slice(&[0; 64]);
    let p = classify(&data);
    assert_eq!(p.slices.len(), 3);
    assert!(has_note(&p, "2 containers with 3 patch sections"));
    assert!(has_note(&p, "64 B of erased-flash padding"));
}

#[test]
fn corrupt_amd_containers_are_format_errors() {
    let mut wrong_type = amd_microcode();
    put32(&mut wrong_type, 4, 1);
    assert!(
        error_text(&wrong_type).contains("Invalid AMD microcode equivalence table type 1 at 0x4")
    );
    let mut short_table = amd_microcode();
    put32(&mut short_table, 8, 8);
    assert!(error_text(&short_table).contains("below one 16 B entry"));
    let mut bad_section = amd_microcode();
    put32(&mut bad_section, 0x3C, 7);
    assert!(error_text(&bad_section).contains("Invalid AMD microcode section type 0x7 at 0x3C"));
    let mut short_patch = amd_microcode();
    put32(&mut short_patch, 0x40, 16);
    assert!(error_text(&short_patch).contains("below the 64 B patch header"));
    let data = amd_microcode();
    assert!(error_text(&data[..data.len() - 1]).contains("Truncated AMD microcode patch"));
}

#[test]
fn partition_tables_list_partitions_with_their_code_directories() {
    let data = me_region_v20();
    let p = classify(&data);
    assert!(has_note(&p, "$FPT at 0x10: header version 0x20, entry version 0x10, header length 0x20, 3 entries; 8-bit header checksum over 0x10-0x2F verified"));
    assert!(has_note(
        &p,
        "whose processor these structures do not identify"
    ));
    assert!(has_note(
        &p,
        "FTPR partition: $CPD \"FTPR\" (header version 1), 3 modules: FTPR.man, rbe.met, rbe; 8-bit checksum verified; 1 module marked Huffman-compressed; manifest FTPR.man: $MN2 tag, version 11.8.50.3399; RSA signature present, not verified"
    ));
    assert!(has_note(
        &p,
        "Absent or invalid entries (zero offset or length, or the invalid flag): NFTP"
    ));
    let ftpr = slice(&p, "FTPR partition (code)");
    assert_eq!(ftpr.offset, 0x1000);
    let mfs = slice(&p, "MFS partition (data)");
    assert_eq!((mfs.offset, mfs.size), (0x2000, 0x200));
    assert_eq!(
        metadata(&p, "pcfw_cpd_0_modules").as_deref(),
        Some("FTPR.man, rbe.met, rbe")
    );
    assert_eq!(
        metadata(&p, "pcfw_fpt_header_version").as_deref(),
        Some("0x20")
    );
}

#[test]
fn pre_me11_checksums_cover_the_rom_bypass_vector() {
    let data = me_region_v10();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "header length 0x30, 1 entry; 8-bit header checksum over 0x0-0x2F verified"
    ));
    assert!(has_note(
        &p,
        "FTPR partition: $MN2 manifest at the partition start, version 9.1.2.1000"
    ));
    // The vector is in the checksum: changing it is an error.
    let mut bypass = data.clone();
    bypass[0] = 0xEA;
    assert!(error_text(&bypass).contains("Invalid $FPT header checksum at 0x1B"));
    // With a header length of 0x20 the vector is not covered.
    let mut data = me_region(
        0x20,
        0x20,
        &[(b"FTPR", FPT_TYPE_CODE, manifest([9, 1, 2, 1000]))],
        &[],
    );
    data[0] = 0xEA;
    let p = classify(&data);
    assert!(has_note(
        &p,
        "The 16-byte ROM bypass vector before the table is not padding; not analyzed"
    ));
}

#[test]
fn version_21_crcs_are_verified_or_noted() {
    let data = me_region_v21();
    let p = classify(&data);
    assert!(has_note(&p, "header version 0x21, entry version 0x10, header length 0x20, 1 entry; header and entry CRC-32 verified"));
    assert!(has_note(&p, "$CPD \"FTPR\" (header version 2), 3 modules"));
    assert!(has_note(
        &p,
        "CRC-32 verified; 1 module marked Huffman-compressed"
    ));
    let mut placeholder = data.clone();
    put32(&mut placeholder, 0x24, 0);
    let p = classify(&placeholder);
    assert_eq!(p.format.format, FileFormat::IntelMe);
    assert!(has_note(
        &p,
        "header CRC-32 0x00000000 does not match the computed"
    ));
    // A version 0x20 header in the 2.1 layout (its CRC matches, its 8-bit
    // sum does not) is accepted the way MEAnalyzer accepts it.
    // Flags bit 0 (0x1B) marks redundancy; the CRC covers it.
    let mut redundant = data.clone();
    redundant[0x1B] = 1;
    let checksum = fpt_crc(&redundant, 1);
    put32(&mut redundant, 0x24, checksum);
    let p = classify(&redundant);
    assert!(has_note(
        &p,
        "Redundancy flag set: a backup table may follow"
    ));
    assert!(has_note(&p, "header and entry CRC-32 verified"));
    let mut relabeled = data;
    relabeled[0x18] = 0x20;
    let checksum = fpt_crc(&relabeled, 1);
    put32(&mut relabeled, 0x24, checksum);
    assert_ne!(
        byte_sum(&relabeled[0x10..0x30]),
        0,
        "the 8-bit sum must fail"
    );
    let p = classify(&relabeled);
    assert!(has_note(
        &p,
        "header version 0x20 with the 2.1 layout: header and entry CRC-32 verified"
    ));
}

#[test]
fn corrupt_partition_tables_are_format_errors() {
    let cases: [CorruptionWithError; 5] = [
        (
            "checksum",
            |d| d[0x1C] ^= 1,
            "Invalid $FPT header checksum at 0x1B",
        ),
        (
            "version",
            |d| d[0x18] = 0x30,
            "Unsupported $FPT header version 0x30 at 0x18",
        ),
        (
            "header length",
            |d| d[0x1A] = 0x24,
            "Unsupported $FPT header length 0x24 at 0x1A",
        ),
        (
            "entry count",
            |d| put32(d, 0x14, 0x100),
            "Invalid $FPT entry count 256 at 0x14",
        ),
        (
            "entry table",
            |d| {
                put32(d, 0x14, 0xFF);
                fix_fpt_checksum(d);
                d.truncate(0x1000);
            },
            "Truncated $FPT entry table at 0x30",
        ),
    ];
    for (name, corrupt, message) in cases {
        let mut data = me_region_v20();
        corrupt(&mut data);
        let text = error_text(&data);
        assert!(text.contains("PC firmware parse error"), "{name}: {text}");
        assert!(text.contains(message), "{name}: {text}");
    }
}

#[test]
fn partitions_outside_the_image_or_over_the_table_are_noted() {
    let mut data = me_region_v20();
    // MFS: offset 0x8000 lies beyond the 0x3000 B region.
    put32(&mut data, 0x50 + 0x08, 0x8000);
    let p = classify(&data);
    assert!(has_note(
        &p,
        "MFS partition 0x8000 + 512 B lies outside the 12288 B image; not listed"
    ));
    let mut data = me_region_v20();
    put32(&mut data, 0x50 + 0x08, 0x40);
    // The 8-bit checksum does not cover entries.
    let p = classify(&data);
    assert!(has_note(
        &p,
        "MFS partition at 0x40 overlaps the partition table; not listed"
    ));
}

#[test]
fn standalone_code_partitions_list_opaque_modules() {
    let data = cpd(1, b"FTPR", &ftpr_modules());
    let p = classify(&data);
    let manifest = slice(&p, "Module FTPR.man");
    // Header 0x10 + 3 entries of 24 B = 0x58, aligned to 0x60.
    assert_eq!((manifest.offset, manifest.size), (0x60, 0x100));
    assert!(matches!(slice(&p, "Module rbe").isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "every module is opaque and excluded from ISA analysis"
    ));
    assert_eq!(
        metadata(&p, "pcfw_cpd_0_manifest").as_deref(),
        Some("FTPR.man: $MN2 tag, version 11.8.50.3399; RSA signature present, not verified")
    );
    // A mismatched checksum is reported, not enforced (ifwitool only warns).
    let mut bad = data.clone();
    bad[0x0B] ^= 1;
    let p = classify(&bad);
    assert!(has_note(&p, "8-bit checksum does not match"));
    let mut v2 = cpd(2, b"FTPR", &ftpr_modules());
    let p = classify(&v2);
    assert!(has_note(&p, "CRC-32 verified"));
    v2[0x10] ^= 1;
    assert!(has_note(&classify(&v2), "does not match the computed"));
    // Structural damage is an error.
    let mut bad_version = data.clone();
    bad_version[0x08] = 3;
    assert!(error_text(&bad_version).contains("Unsupported $CPD header version 3"));
    let mut bad_count = data;
    put32(&mut bad_count, 0x04, 1000);
    assert!(error_text(&bad_count).contains("Truncated $CPD entry table"));
}

#[test]
fn descriptor_me_regions_with_a_partition_table_are_classified_as_intel_me() {
    let image = flash_with_me(&me_region_v20());
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::IntelIfd);
    assert!(has_note(
        &p,
        "ME region: Intel ME flash partition table; classified as Intel ME firmware, every partition opaque"
    ));
    assert!(has_note(&p, "(contained Intel ME firmware)"));
    let me = slice(&p, "ME region");
    assert_eq!((me.offset, me.size), (0x1000, 0x3000));
    assert!(matches!(me.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    // The nested container's partitions are opaque too.
    let direct = classify(&me_region_v20());
    assert!(direct
        .slices
        .iter()
        .all(|s| matches!(s.isa, Isa::Unknown(_))));
}

#[test]
fn descriptor_me_regions_without_a_valid_table_stay_unanalyzed() {
    let mut region = me_region_v20();
    region[0x1C] ^= 1;
    let p = classify(&flash_with_me(&region));
    assert_eq!(p.format.format, FileFormat::IntelIfd);
    assert!(has_note(
        &p,
        "ME region: ISA unknown (PC firmware parse error: Invalid $FPT header checksum"
    ));
    assert!(matches!(slice(&p, "ME region").isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    // Without `$FPT`, the region is opaque as before.
    let mut region = me_region_v20();
    region[0x10..0x14].copy_from_slice(b"XXXX");
    let p = classify(&flash_with_me(&region));
    assert!(has_note(&p, "ME region: firmware of a separate engine"));
    assert!(p.candidates.is_empty());
    assert!(!pcfw::is_me_partition_table(&region));
    assert!(pcfw::is_me_partition_table(&me_region_v20()));
}

#[test]
fn amd_images_walk_every_directory_level() {
    let data = amd_image();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "Embedded Firmware Structure at 0x20000 (signature 0x55AA55AA), second-generation layout"
    ));
    assert!(has_note(
        &p,
        "$PSP directory at 0x20100: 5 entries; Fletcher-32 checksum verified; address mode 1"
    ));
    assert!(has_note(
        &p,
        "$PL2 directory at 0x20200: 1 entry; Fletcher-32 checksum verified; address mode 2"
    ));
    assert!(has_note(
        &p,
        "$BHD directory at 0x20400: 3 entries; Fletcher-32 checksum verified; address mode 0"
    ));
    assert!(has_note(&p, "$BL2 directory at 0x20500: 2 entries"));
    assert!(has_note(&p, "ISH directory at 0x20300: PSP ID 0xBC0A0000, PSP L2 pointer 0x00020200; Fletcher-32 checksum verified"));
    assert!(has_note(&p, "PSP L1 soft fuse value 0x1"));
    assert!(has_note(
        &p,
        "Directory at 0x20500 is referenced again; listed once"
    ));
    assert!(has_note(&p, "BIOS L2 entry 0x05 (AMD_BIOS_RTM_PUBKEY) not listed: 0x30000 + 256 B lies outside the 134144 B file"));
    assert!(has_note(&p, "Entries without stored bytes (zero or erased size, or a DRAM destination): BIOS L1 entry 0x61 (AMD_BIOS_APOB) (DRAM destination only)"));
    let boot = slice(&p, "PSP L1 entry 0x01 (AMD_FW_PSP_BOOTLOADER)");
    assert_eq!((boot.offset, boot.size), (BOOTLOADER as u64, 0x100));
    let smu = slice(&p, "PSP L2 entry 0x08 (AMD_FW_PSP_SMU_FIRMWARE)");
    assert_eq!((smu.offset, smu.size), (SMU_FIRMWARE as u64, 0x80));
    let bios = slice(&p, "BIOS L1 entry 0x62 (AMD_BIOS_BIN), compressed");
    assert_eq!((bios.offset, bios.size), (BIOS_IMAGE as u64, 0x100));
    let ucode = slice(&p, "BIOS L2 entry 0x66 (AMD_BIOS_UCODE) instance 1");
    assert_eq!((ucode.offset, ucode.size), (MICROCODE as u64, 0x40));
    assert_eq!(
        metadata(&p, "pcfw_psp_directory_count").as_deref(),
        Some("5")
    );
    assert_eq!(metadata(&p, "pcfw_efs_offset").as_deref(), Some("0x20000"));
}

#[test]
fn combo_directories_lead_to_their_psp_directories() {
    let p = classify(&amd_combo_image());
    assert!(has_note(
        &p,
        "2PSP directory at 0x20100: 1 entry; Fletcher-32 checksum verified"
    ));
    assert!(has_note(&p, "$PSP directory at 0x20200: 1 entry"));
    let boot = slice(&p, "PSP L1 entry 0x01 (AMD_FW_PSP_BOOTLOADER)");
    assert_eq!((boot.offset, boot.size), (0x2_0300, 0x40));
}

#[test]
fn damaged_amd_images_are_not_recognized() {
    let corruptions: [(&str, usize); 5] = [
        ("EFS signature", EFS_OFFSET),
        ("PSP L1 checksum", PSP_L1 + 4),
        ("PSP L2 entry", PSP_L2_A + 0x10),
        ("BIOS L2 cookie", BIOS_L2 + 1),
        ("BIOS L1 count", BIOS_L1 + 8),
    ];
    for (name, at) in corruptions {
        let mut data = amd_image();
        data[at] ^= 0x01;
        assert!(!is_pcfw(&data), "{name}: {:?}", detect_format(&data));
    }
    // An EFS that leads to no directory is not an AMD image either.
    let mut data = vec![0xFF; 0x2_0100];
    place(&mut data, EFS_OFFSET, &efs(0x2_0080, 0, 0));
    assert!(!is_pcfw(&data));
}

#[test]
fn standalone_directories_list_only_table_relative_entries() {
    let data = psp_table();
    let p = classify(&data);
    assert!(has_note(&p, "Standalone $PSP directory"));
    let boot = slice(&p, "PSP L1 entry 0x01 (AMD_FW_PSP_BOOTLOADER)");
    assert_eq!((boot.offset, boot.size), (0x40, 0x20));
    assert!(has_note(
        &p,
        "PSP L1 entry 0x08 (AMD_FW_PSP_SMU_FIRMWARE) not listed: image offset 0x20900; the flash image is not part of this file"
    ));
    let mut bad = data.clone();
    bad[0x04] ^= 1;
    assert!(error_text(&bad).contains("Invalid $PSP directory checksum at 0x4"));
    let mut truncated = data;
    put32(&mut truncated, 0x08, 9);
    assert!(error_text(&truncated).contains("Truncated $PSP directory at 0x0: 9 entries of 16 B"));
}

#[test]
fn efs_detection_yields_to_descriptors_maps_and_volumes() {
    // An Intel flash descriptor signature is claimed by the UEFI family.
    let mut descriptor = amd_image();
    put32(&mut descriptor, 0x10, FLVALSIG);
    assert!(matches!(
        detect_format(&descriptor),
        DetectedFormat::Container {
            kind: container::Kind::Uefi(_)
        }
    ));
    // A firmware volume signature at 0x28 likewise.
    let mut volume = amd_image();
    volume[0x28..0x2C].copy_from_slice(b"_FVH");
    assert!(matches!(
        detect_format(&volume),
        DetectedFormat::Container {
            kind: container::Kind::Uefi(_)
        }
    ));
    // An FMAP at 0 is claimed by its signature.
    let mut mapped = amd_image();
    place(&mut mapped, 0, &fmap(0));
    assert!(matches!(
        detect_format(&mapped),
        DetectedFormat::Container {
            kind: container::Kind::Coreboot(_)
        }
    ));
    // An FMAP found by search (coreboot builds for AMD carry one): both the
    // coreboot search and the EFS validate, and the EFS check, which runs
    // after the coreboot one, does not take the image.
    let mut embedded = amd_image();
    place(&mut embedded, 0x1000, &fmap(0x1000));
    assert!(zrax::formats::coreboot::detect_weak(&embedded).is_some());
    assert!(pcfw::detect_weak(&embedded).is_some());
    assert!(!is_pcfw(&embedded), "{:?}", detect_format(&embedded));
    // Without those, the image is an AMD PSP image.
    assert!(matches!(
        detect_format(&amd_image()),
        DetectedFormat::Container {
            kind: container::Kind::PcFw(pcfw::Layout::AmdEfs { offset: EFS_OFFSET })
        }
    ));
}

/// A Chromium FMAP for the AMD image (coreboot `fmap_serialized.h`):
/// `__FMAP__`, version 1.1, base address 0, the image size, the name
/// `FLASH`, two areas (offset, size, 32-byte name, flags): `FMAP` at `at`,
/// which holds the map, and `AMDFW` over the EFS and directories.
fn fmap(at: u32) -> Vec<u8> {
    let mut map = b"__FMAP__".to_vec();
    map.extend_from_slice(&[1, 1]);
    map.extend_from_slice(&0u64.to_le_bytes());
    map.extend_from_slice(&(AMD_IMAGE_END as u32).to_le_bytes());
    let mut name = [0u8; 32];
    name[..5].copy_from_slice(b"FLASH");
    map.extend_from_slice(&name);
    map.extend_from_slice(&2u16.to_le_bytes());
    let areas: [(u32, u32, &[u8]); 2] = [
        (at, 0x1000, b"FMAP"),
        (
            EFS_OFFSET as u32,
            (AMD_IMAGE_END - EFS_OFFSET) as u32,
            b"AMDFW",
        ),
    ];
    for (offset, size, area) in areas {
        map.extend_from_slice(&offset.to_le_bytes());
        map.extend_from_slice(&size.to_le_bytes());
        let mut field = [0u8; 32];
        field[..area.len()].copy_from_slice(area);
        map.extend_from_slice(&field);
        map.extend_from_slice(&0u16.to_le_bytes());
    }
    map
}

/// Prefix lengths to test: every length for small fixtures; for the AMD
/// images every length from the EFS on and every 4 KiB before it.
fn prefix_lengths(data: &[u8]) -> Vec<usize> {
    if data.len() < EFS_OFFSET {
        return (0..data.len()).collect();
    }
    (0..EFS_OFFSET)
        .step_by(0x1000)
        .chain(EFS_OFFSET..data.len())
        .collect()
}

#[test]
fn truncated_prefixes_never_claim_an_isa() {
    for (name, data, _, _) in fixtures() {
        for end in prefix_lengths(&data) {
            let prefix = &data[..end];
            if !is_pcfw(prefix) {
                continue;
            }
            let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) else {
                continue;
            };
            assert!(is_pcfw_format(p.format.format), "{name} {end}");
            assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name} {end}");
            assert!(p.candidates.is_empty(), "{name} {end}");
        }
    }
}

#[test]
fn truncated_strong_layouts_are_format_errors() {
    for (name, data, _, _) in fixtures() {
        if matches!(
            name,
            "intel-ucode" | "intel-ucode-extended" | "amd-efs" | "amd-combo"
        ) {
            continue;
        }
        for end in [data.len() / 2, data.len() - 1] {
            let prefix = &data[..end];
            if is_pcfw(prefix) {
                // The table may still be complete; it must not claim an ISA.
                if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
                    assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name} {end}");
                }
            }
        }
    }
    let amd = amd_microcode();
    assert!(error_text(&amd[..20]).contains("PC firmware parse error"));
    let me = me_region_v20();
    assert!(error_text(&me[..0x40]).contains("Truncated $FPT entry table at 0x30"));
}

/// The structures of the AMD fixtures (EFS, directories, ISH); their
/// blobs and erased flash are only sampled.
fn amd_structures(name: &str) -> &'static [(usize, usize)] {
    match name {
        "amd-efs" => &[
            (EFS_OFFSET, 0x50),
            (PSP_L1, 0x60),
            (PSP_L2_A, 0x20),
            (ISH_A, 0x20),
            (BIOS_L1, 0x58),
            (BIOS_L2, 0x40),
            (PSP_L2_B, 0x20),
        ],
        "amd-combo" => &[(EFS_OFFSET, 0x50), (0x2_0100, 0x30), (0x2_0200, 0x20)],
        _ => &[],
    }
}

/// Byte offsets to mutate: every byte for most fixtures; for the AMD
/// images every byte of their structures, every 64th byte of their blobs
/// and every 4 KiB of the erased flash before the EFS.
fn mutation_offsets(name: &str, data: &[u8]) -> Vec<usize> {
    let structures = amd_structures(name);
    if structures.is_empty() {
        return (0..data.len()).collect();
    }
    let mut offsets: Vec<usize> = (0..EFS_OFFSET)
        .step_by(0x1000)
        .chain((EFS_OFFSET..data.len()).step_by(64))
        .collect();
    for &(start, len) in structures {
        offsets.extend(start..start + len);
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Fixtures up to this size (a 1 KiB microcode update, the AMD container,
/// the code partition and the directory table) are classified after every
/// mutation; larger ones only while the mutated bytes are still
/// recognized, because raw input goes to the code model, which other
/// suites cover. Detection itself runs for every mutation.
const FULLY_CLASSIFIED_SIZE: usize = 0x400;

#[test]
fn byte_mutations_never_panic_or_claim_an_isa() {
    let mutations: [fn(u8) -> u8; 4] = [|b| b ^ 0xFF, |_| 0x00, |_| 0xFF, |b| b ^ 0x01];
    for (name, data, _, _) in fixtures() {
        for i in mutation_offsets(name, &data) {
            for mutate in mutations {
                let mut mutated = data.clone();
                mutated[i] = mutate(mutated[i]);
                if data.len() > FULLY_CLASSIFIED_SIZE && !is_pcfw(&mutated) {
                    continue;
                }
                let Ok(p) = detect_payload(&mutated, &ClassifierOptions::new()) else {
                    continue;
                };
                if is_pcfw_format(p.format.format) {
                    assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name} {i}");
                    assert!(p.candidates.is_empty(), "{name} {i}");
                }
            }
        }
    }
}

#[test]
fn mutated_descriptor_me_regions_never_reach_the_code_model() {
    let image = flash_with_me(&me_region_v20());
    for i in (0x1000..0x1100).chain(0x2000..0x2100) {
        let mut mutated = image.clone();
        mutated[i] ^= 0xFF;
        let Ok(p) = detect_payload(&mutated, &ClassifierOptions::new()) else {
            continue;
        };
        assert_eq!(p.format.format, FileFormat::IntelIfd, "{i}");
        let me = slice(&p, "ME region");
        assert!(matches!(me.isa, Isa::Unknown(_)), "{i}");
        assert!(p.candidates.is_empty(), "{i}");
    }
}
