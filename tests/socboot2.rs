//! SoC boot ROM images: Allwinner eGON.BT0 (A32 and RISC-V jump words,
//! stamp checksum) and TOC0, Rockchip RKFW/RKAF/RKBOOT and idbloaders (RC4
//! descrambling, RKCRC, v2 hashes), MediaTek preloaders (device header,
//! BRLYT, GFH, `GFH_BROM_CFG` AArch64 hand-off) and Qualcomm MBN headers
//! (80-byte SBL with `booting_image_config`, NAND preamble, magic-less
//! 40-byte version 3), with corruption, truncation and mutation sweeps.

use sha2::{Digest, Sha256};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa, MetadataKey,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).expect("fixture is committed")
}

/// clang-generated A32, AArch64 and RV64 machine code.
fn arm_code() -> Vec<u8> {
    fixture("socboot2/arm.text.bin")
}

fn aarch64_code() -> Vec<u8> {
    fixture("transforms/aarch64.text.bin")
}

fn riscv64_code() -> Vec<u8> {
    fixture("transforms/riscv64.text.bin")
}

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

fn put_u16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes"))
}

fn pad_to(data: &mut Vec<u8>, align: usize) {
    while data.len() % align != 0 {
        data.push(0);
    }
}

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

// ---------------------------------------------------------------------------
// Allwinner
// ---------------------------------------------------------------------------

/// `BROM_STAMP_VALUE` (U-Boot `sunxi_image.h`).
const BROM_STAMP: u32 = 0x5f0a_6c39;
/// U-Boot's jump words for a 0x60-byte header: A32 `B 0x60`, RISC-V `J 0x60`.
const ARM_JUMP_0X60: u32 = 0xea00_0016;
const RISCV_JUMP_0X60: u32 = 0x0600_006f;

/// The eGON stamp checksum: the wrapping sum of all little-endian words
/// with the checksum word (0x0C) replaced by the stamp.
fn stamp_checksum(image: &[u8], checksum_at: usize) -> u32 {
    image.chunks_exact(4).enumerate().fold(0u32, |sum, (i, w)| {
        let word = if i * 4 == checksum_at {
            BROM_STAMP
        } else {
            u32::from_le_bytes(w.try_into().expect("four bytes"))
        };
        sum.wrapping_add(word)
    })
}

/// `struct boot_file_head` (0x60 bytes): jump (0), `eGON.BT0` (4),
/// checksum (0x0C), length (0x10), `SPL` + version 0.2 (0x14), DT name
/// offset (0x20) pointing at the string pool (0x2C); the code at 0x60; the
/// image zero-padded to `align` bytes and checksummed.
fn egon(jump: u32, code: &[u8], align: usize) -> Vec<u8> {
    let mut data = vec![0u8; 0x60];
    put_u32(&mut data, 0, jump);
    data[4..12].copy_from_slice(b"eGON.BT0");
    data[0x14..0x17].copy_from_slice(b"SPL");
    data[0x17] = 0x02;
    put_u32(&mut data, 0x20, 0x2c);
    data[0x2c..0x2c + 19].copy_from_slice(b"sun20i-d1-nezha.dtb");
    data.extend_from_slice(code);
    pad_to(&mut data, align);
    let length = data.len() as u32;
    put_u32(&mut data, 0x10, length);
    let checksum = stamp_checksum(&data, 0x0c);
    put_u32(&mut data, 0x0c, checksum);
    data
}

/// `struct toc0_main_info` (0x30 bytes): `TOC0.GLH` (0), magic 0x89119800
/// (8), checksum (0x0C), item count (0x18), length (0x1C), `MIE;` (0x2C);
/// then 0x20-byte items (name, offset, length, load address at 0x14,
/// `IIE;` at 0x1C) and their data; padded to 512 bytes and checksummed.
fn toc0(items: &[(u32, &[u8])]) -> Vec<u8> {
    let mut data = vec![0u8; 0x30 + 0x20 * items.len()];
    data[..8].copy_from_slice(b"TOC0.GLH");
    put_u32(&mut data, 8, 0x8911_9800);
    put_u32(&mut data, 0x18, items.len() as u32);
    data[0x2c..0x30].copy_from_slice(b"MIE;");
    for (i, (name, bytes)) in items.iter().enumerate() {
        pad_to(&mut data, 32);
        let item = 0x30 + 0x20 * i;
        let offset = data.len() as u32;
        put_u32(&mut data, item, *name);
        put_u32(&mut data, item + 4, offset);
        put_u32(&mut data, item + 8, bytes.len() as u32);
        put_u32(&mut data, item + 0x14, 0x4000_0000);
        data[item + 0x1c..item + 0x20].copy_from_slice(b"IIE;");
        data.extend_from_slice(bytes);
    }
    pad_to(&mut data, 512);
    let length = data.len() as u32;
    put_u32(&mut data, 0x1c, length);
    let checksum = stamp_checksum(&data, 0x0c);
    put_u32(&mut data, 0x0c, checksum);
    data
}

#[test]
fn egon_a32_jump_names_arm_and_the_checksum_is_verified() {
    let image = egon(ARM_JUMP_0X60, &arm_code(), 8192);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AllwinnerEgon);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("eGON.BT0 boot image")
    );
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, "checksum 0x"));
    assert!(has_note(&p, "verified over 8 KiB"));
    assert!(has_note(&p, "A32 B to image offset 0x60"));
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Device tree name" && m.value.to_string() == "sun20i-d1-nezha.dtb"));
}

#[test]
fn egon_riscv_jump_names_riscv64_and_says_xlen_is_assumed() {
    let p = classify(&egon(RISCV_JUMP_0X60, &riscv64_code(), 8192));
    assert_eq!(p.format.format, FileFormat::AllwinnerEgon);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::RiscV64, 64));
    assert!(has_note(&p, "RISC-V JAL x0 to image offset 0x60"));
    assert!(has_note(&p, "64-bit is assumed"));
}

#[test]
fn egon_without_a_documented_jump_takes_the_isa_from_the_code() {
    // A jump word that is neither B nor JAL x0, and a B into the header.
    for jump in [0u32, 0xea00_0001] {
        let p = classify(&egon(jump, &aarch64_code(), 8192));
        assert_eq!(p.format.format, FileFormat::AllwinnerEgon);
        assert_eq!(p.primary.isa, Isa::AArch64, "jump 0x{jump:08X}");
        assert_ne!(p.primary.source, ClassificationSource::FileFormat);
        assert!(has_note(&p, "ISA from the code model"));
    }
}

#[test]
fn egon_spl_with_u_boot_after_it_lists_the_recognized_image() {
    let mut image = egon(ARM_JUMP_0X60, &arm_code(), 8192);
    image.resize(0x8000, 0xff);
    image.extend_from_slice(&elf_x86_64());
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Arm);
    let trailing = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Trailing data"))
        .expect("trailing image listed");
    assert_eq!((trailing.offset, trailing.isa), (0x8000, Isa::X86_64));
    // Unrecognized data after the image is not listed.
    let mut image = egon(ARM_JUMP_0X60, &arm_code(), 8192);
    image.extend_from_slice(&[0x5a; 600]);
    assert!(classify(&image).slices.is_empty());
}

#[test]
fn egon_corrupt_checksum_or_length_is_a_parse_error() {
    let image = egon(ARM_JUMP_0X60, &arm_code(), 8192);
    let mut bad = image.clone();
    bad[0x100] ^= 1;
    let message = error_text(&bad);
    assert!(
        message.starts_with("SoC loader parse error: Invalid eGON checksum"),
        "{message}"
    );
    let mut long = image.clone();
    put_u32(&mut long, 0x10, image.len() as u32 + 512);
    assert!(error_text(&long).contains("Truncated eGON image"));
    let mut unaligned = image;
    put_u32(&mut unaligned, 0x10, 0x62);
    assert!(error_text(&unaligned).contains("Invalid eGON length"));
}

#[test]
fn toc0_items_are_opaque_and_the_checksum_is_verified() {
    let firmware = arm_code();
    let image = toc0(&[
        (0x0001_0101, &[0x30; 64]),
        (0x0001_0202, &firmware),
        (0x0001_0303, &[0x30; 32]),
    ]);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::AllwinnerEgon);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("TOC0 secure boot image")
    );
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, ["Certificate", "Firmware", "Key"]);
    assert!(p.slices.iter().all(|s| s.isa == Isa::Unknown(0)));
    assert!(has_note(&p, "Firmware: opaque"));
    assert!(has_note(&p, "not verified"));
    let mut bad = image;
    bad[0x200] ^= 0x80;
    assert!(error_text(&bad).contains("Invalid TOC0 checksum"));
}

// ---------------------------------------------------------------------------
// Rockchip
// ---------------------------------------------------------------------------

/// The boot ROM RC4 key (`P_RC4`, `rc4_key`).
const RC4_KEY: [u8; 16] = [124, 78, 3, 4, 85, 5, 9, 7, 45, 44, 123, 56, 23, 13, 23, 17];

/// Standard RC4 with [`RC4_KEY`], key stream restarted per call.
fn rc4(bytes: &mut [u8]) {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + usize::from(s[i]) + usize::from(RC4_KEY[i % 16])) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for byte in bytes {
        i = (i + 1) % 256;
        j = (j + usize::from(s[i])) % 256;
        s.swap(i, j);
        *byte ^= s[(usize::from(s[i]) + usize::from(s[j])) % 256];
    }
}

/// RC4 per 512-byte block, each block restarting the key stream.
fn rc4_blocks(bytes: &mut [u8]) {
    for block in bytes.chunks_mut(512) {
        rc4(block);
    }
}

/// Rockchip CRC: MSB-first polynomial 0x04C10DB7, initial value 0, no
/// reflection or final XOR (`rkcrc.h`), computed bit by bit.
fn rkcrc(bytes: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &byte in bytes {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_0db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// An RKBOOT entry: type (1 = 0x471, 2 = 0x472, 4 = loader), name, data.
struct BootEntry<'a> {
    entry_type: u32,
    name: &'a str,
    data: &'a [u8],
}

/// `boot_merger` output: the 0x66-byte `rk_boot_header` (tag `BOOT`, size
/// 0x66, version 1.02 BCD, merger version, chip "3399" packed big-endian,
/// the three table descriptors at 0x19/0x1F/0x25), the 0x39-byte entries
/// (size, type, UTF-16LE name, data offset, data size, delay), the data
/// (0x471/0x472 padded to 2048 and RC4-scrambled as one stream, loaders
/// padded to 512 then 2048 and scrambled per 512-byte block) and the RKCRC.
fn rkboot(entries: &[BootEntry]) -> Vec<u8> {
    let mut data = vec![0u8; 0x66];
    data[..4].copy_from_slice(b"BOOT");
    put_u16(&mut data, 4, 0x66);
    put_u32(&mut data, 6, 0x0102);
    put_u32(&mut data, 0x0a, 0x0103_0000);
    data[0x15..0x19].copy_from_slice(b"9933");
    let mut table_offset = 0x66u32;
    for (descriptor, entry_type) in [(0x19, 1u32), (0x1f, 2), (0x25, 4)] {
        let count = entries
            .iter()
            .filter(|e| e.entry_type == entry_type)
            .count();
        data[descriptor] = count as u8;
        put_u32(&mut data, descriptor + 1, table_offset);
        data[descriptor + 5] = 0x39;
        table_offset += 0x39 * count as u32;
    }
    let mut ordered: Vec<&BootEntry> = Vec::new();
    for entry_type in [1, 2, 4] {
        ordered.extend(entries.iter().filter(|e| e.entry_type == entry_type));
    }
    let mut cursor = 0x66 + 0x39 * ordered.len();
    let mut blobs = Vec::new();
    for entry in &ordered {
        let mut record = vec![0u8; 0x39];
        record[0] = 0x39;
        put_u32(&mut record, 1, entry.entry_type);
        for (i, unit) in entry.name.encode_utf16().enumerate() {
            put_u16(&mut record, 5 + 2 * i, unit);
        }
        let mut blob = entry.data.to_vec();
        if entry.entry_type == 4 {
            pad_to(&mut blob, 512);
        }
        pad_to(&mut blob, 2048);
        if entry.entry_type == 4 {
            rc4_blocks(&mut blob);
        } else {
            rc4(&mut blob);
        }
        put_u32(&mut record, 0x2d, cursor as u32);
        put_u32(&mut record, 0x31, blob.len() as u32);
        cursor += blob.len();
        data.extend_from_slice(&record);
        blobs.push(blob);
    }
    for blob in blobs {
        data.extend_from_slice(&blob);
    }
    let crc = rkcrc(&data);
    data.extend_from_slice(&crc.to_le_bytes());
    data
}

/// A `PARM`/`KRNL` wrapper: magic, data length, data, RKCRC of the data.
fn wrapped(magic: &[u8; 4], contents: &[u8]) -> Vec<u8> {
    let mut data = magic.to_vec();
    data.extend_from_slice(&(contents.len() as u32).to_le_bytes());
    data.extend_from_slice(contents);
    data.extend_from_slice(&rkcrc(contents).to_le_bytes());
    data
}

/// `struct update_header` (0x800 bytes): `RKAF`, length (file size minus
/// the CRC), model at 8, manufacturer at 0x48, version at 0x84, part count
/// at 0x88, 0x70-byte parts at 0x8C (name, file name at 0x20, position at
/// 0x60, flash address at 0x64, padded size at 0x68, size at 0x6C); a
/// `SELF` part first; part data at 2048-byte boundaries; then the RKCRC.
fn rkaf(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = vec![0u8; 0x800];
    data[..4].copy_from_slice(b"RKAF");
    data[8..8 + 7].copy_from_slice(b"RK3399X");
    data[0x48..0x48 + 7].copy_from_slice(b"Example");
    put_u32(&mut data, 0x84, 0x0801_0000);
    put_u32(&mut data, 0x88, parts.len() as u32 + 1);
    data[0x8c..0x8c + 7].copy_from_slice(b"package");
    data[0x8c + 0x20..0x8c + 0x24].copy_from_slice(b"SELF");
    for (i, (name, bytes)) in parts.iter().enumerate() {
        pad_to(&mut data, 2048);
        let part = 0x8c + 0x70 * (i + 1);
        let position = data.len() as u32;
        data[part..part + name.len()].copy_from_slice(name.as_bytes());
        let filename = format!("Image/{name}.img");
        data[part + 0x20..part + 0x20 + filename.len()].copy_from_slice(filename.as_bytes());
        put_u32(&mut data, part + 0x60, position);
        put_u32(&mut data, part + 0x64, 0xffff_ffff);
        put_u32(
            &mut data,
            part + 0x68,
            ((bytes.len() + 2047) / 2048 * 2048) as u32,
        );
        put_u32(&mut data, part + 0x6c, bytes.len() as u32);
        data.extend_from_slice(bytes);
    }
    let length = data.len() as u32;
    put_u32(&mut data, 0x8c + 0x6c, length);
    put_u32(&mut data, 4, length);
    let crc = rkcrc(&data);
    data.extend_from_slice(&crc.to_le_bytes());
    data
}

/// `struct rkfw_header` (0x66 bytes): `RKFW`, header length 0x66, version
/// 8.1.0, code, build time 2026-10-12 12:00:00, chip 0x38 (rk35xx), loader
/// offset/length at 0x19/0x1D, RKAF offset/length at 0x21/0x25; the loader,
/// the RKAF image and a 32-character lowercase hex trailer (not a real MD5;
/// nothing verifies it).
fn rkfw(loader: &[u8], package: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x66];
    data[..4].copy_from_slice(b"RKFW");
    put_u16(&mut data, 4, 0x66);
    put_u32(&mut data, 6, 0x0801_0000);
    put_u32(&mut data, 0x0a, 0x0106_0000);
    put_u16(&mut data, 0x0e, 2026);
    data[0x10..0x15].copy_from_slice(&[10, 12, 12, 0, 0]);
    data[0x15] = 0x38;
    put_u32(&mut data, 0x19, 0x66);
    put_u32(&mut data, 0x1d, loader.len() as u32);
    put_u32(&mut data, 0x21, 0x66 + loader.len() as u32);
    put_u32(&mut data, 0x25, package.len() as u32);
    data.extend_from_slice(loader);
    data.extend_from_slice(package);
    data.extend_from_slice(b"0123456789abcdef0123456789abcdef");
    data
}

/// idbloader v1: the 512-byte `header0_info` (magic 0x0FF0AA55,
/// `disable_rc4` at 8, init offset 4 blocks at 0x0C, init size at 0x1FA,
/// init plus boot size at 0x1FC, in 512-byte blocks), RC4-scrambled as one
/// block; at 0x800 the tag `RK33` and the code, padded to 2 KiB and
/// scrambled per 512-byte block unless `plain`.
fn idbloader_v1(code: &[u8], plain: bool) -> Vec<u8> {
    let mut init = b"RK33".to_vec();
    init.extend_from_slice(code);
    pad_to(&mut init, 2048);
    let blocks = (init.len() / 512) as u16;
    let mut header = vec![0u8; 512];
    put_u32(&mut header, 0, 0x0ff0_aa55);
    put_u32(&mut header, 8, u32::from(plain));
    put_u16(&mut header, 0x0c, 4);
    put_u16(&mut header, 0x1fa, blocks);
    // U-Boot without a boot file reserves room it does not write.
    put_u16(&mut header, 0x1fc, blocks + 1024);
    rc4(&mut header);
    let mut data = header;
    data.resize(0x800, 0);
    if !plain {
        rc4_blocks(&mut init);
    }
    data.extend_from_slice(&init);
    data
}

/// idbloader v2: the 2048-byte `header0_info_v2` (`RKNS`, image count and
/// hash offset 384 words at 8, boot flag 1 = SHA-256 at 0x0C, 88-byte image
/// entries at 0x78: size and offset in sectors, address 0xFFFFFFFF,
/// counter, SHA-256 at 0x18), the header SHA-256 over [0, 0x600) at 0x600;
/// images from sector 4, padded to sectors.
fn idbloader_v2(images: &[&[u8]]) -> Vec<u8> {
    let mut data = vec![0u8; 2048];
    data[..4].copy_from_slice(b"RKNS");
    put_u32(&mut data, 8, ((images.len() as u32) << 16) + 384);
    put_u32(&mut data, 0x0c, 1);
    for (i, image) in images.iter().enumerate() {
        let mut padded = image.to_vec();
        pad_to(&mut padded, 512);
        let entry = 0x78 + 88 * i;
        let sectors = (padded.len() / 512) as u32;
        let first_sector = (data.len() / 512) as u32;
        put_u32(&mut data, entry, (sectors << 16) | first_sector);
        put_u32(&mut data, entry + 4, 0xffff_ffff);
        put_u32(&mut data, entry + 0x0c, i as u32 + 1);
        let digest = Sha256::digest(&padded);
        data[entry + 0x18..entry + 0x38].copy_from_slice(&digest);
        data.extend_from_slice(&padded);
    }
    let digest = Sha256::digest(&data[..0x600]);
    data[0x600..0x620].copy_from_slice(&digest);
    data
}

fn rkboot_fixture() -> Vec<u8> {
    let ddr = arm_code();
    let usb = arm_code();
    let spl = aarch64_code();
    rkboot(&[
        BootEntry {
            entry_type: 1,
            name: "rk3399_ddr",
            data: &ddr,
        },
        BootEntry {
            entry_type: 2,
            name: "rk3399_usbplug",
            data: &usb,
        },
        BootEntry {
            entry_type: 4,
            name: "FlashBoot",
            data: &spl,
        },
    ])
}

#[test]
fn rkboot_entries_are_descrambled_and_classified_on_their_own() {
    let loader = rkboot_fixture();
    let p = classify(&loader);
    assert_eq!(p.format.format, FileFormat::RockchipImage);
    assert_eq!(p.format.variant_name.as_deref(), Some("RKBOOT loader"));
    assert!(has_note(&p, "chip RK3399"));
    assert!(has_note(&p, "verified"));
    let isas: Vec<_> = p.slices.iter().map(|s| s.isa).collect();
    assert_eq!(isas, [Isa::Arm, Isa::Arm, Isa::AArch64]);
    let ddr = &p.slices[0];
    assert_eq!(ddr.label.as_deref(), Some("rk3399_ddr (0x471 DDR init)"));
    assert_eq!(ddr.offset, (0x66 + 3 * 0x39) as u64);
    let decoded = ddr.decoded.as_ref().expect("descrambled");
    assert_eq!(decoded.transform, "Rockchip RC4");
    assert_eq!(decoded.size, ddr.size);
    // The primary ISA comes from the first classified entry.
    assert_eq!(p.primary.isa, Isa::Arm);
    let mut bad = loader;
    bad[0x400] ^= 1;
    assert!(error_text(&bad).contains("Invalid RKBOOT CRC"));
}

#[test]
fn rkfw_wraps_the_loader_and_the_rkaf_package() {
    let parameter = wrapped(
        b"PARM",
        b"FIRMWARE_VER:8.1\nCMDLINE:mtdparts=rk29xxnand:...\n",
    );
    let kernel = wrapped(b"KRNL", &elf_x86_64());
    let uboot = aarch64_code();
    let package = rkaf(&[
        ("parameter", &parameter),
        ("uboot", &uboot),
        ("kernel", &kernel),
        ("misc", b"text only\n"),
    ]);
    let image = rkfw(&rkboot_fixture(), &package);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::RockchipImage);
    assert_eq!(p.format.variant_name.as_deref(), Some("RKFW update image"));
    assert!(has_note(&p, "rk35xx per rkunpack"));
    assert!(has_note(&p, "MD5 trailer present; not verified"));
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, ["Loader", "Firmware package (RKAF)"]);
    assert_eq!(p.slices[1].offset, (0x66 + rkboot_fixture().len()) as u64);

    let p = classify(&package);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("RKAF firmware package")
    );
    let find = |label: &str| {
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .unwrap_or_else(|| panic!("{label} listed"))
    };
    let parameter_slice = find("parameter (Image/parameter.img)");
    assert_eq!(parameter_slice.isa, Isa::Unknown(0));
    assert_eq!(parameter_slice.offset, 0x800 + 8);
    assert_eq!(find("uboot (Image/uboot.img)").isa, Isa::AArch64);
    let kernel_slice = find("kernel (Image/kernel.img)");
    assert_eq!(kernel_slice.isa, Isa::X86_64);
    assert_eq!(kernel_slice.size, 64);
    assert_eq!(find("misc (Image/misc.img)").isa, Isa::Unknown(0));
    assert!(has_note(&p, "parameter (Image/parameter.img): opaque"));

    let mut bad = package;
    bad[0x900] ^= 1;
    assert!(error_text(&bad).contains("Invalid RKAF CRC"));
}

#[test]
fn idbloader_v1_header_and_stages_are_descrambled() {
    for plain in [false, true] {
        let image = idbloader_v1(&arm_code(), plain);
        assert_eq!(&image[..4], &[0x3b, 0x8c, 0xdc, 0xfc]);
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::RockchipImage);
        assert_eq!(
            p.format.variant_name.as_deref(),
            Some("idbloader (header v1)")
        );
        assert!(has_note(&p, "SoC tag RK33"));
        assert!(has_note(&p, "reserves 512 KiB for a boot stage"));
        let init = &p.slices[0];
        assert_eq!((init.offset, init.isa), (0x800, Isa::Arm));
        assert_eq!(init.decoded.is_some(), !plain, "plain {plain}");
    }
}

#[test]
fn idbloader_v2_hashes_are_checked_but_a_mismatch_is_only_noted() {
    let spl = arm_code();
    let uboot = aarch64_code();
    let image = idbloader_v2(&[&spl, &uboot]);
    let p = classify(&image);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("idbloader (header v2)")
    );
    assert!(has_note(&p, "SHA-256 header hash verified"));
    assert!(has_note(&p, "SHA-256 image hashes verified"));
    let isas: Vec<_> = p.slices.iter().map(|s| (s.offset, s.isa)).collect();
    assert_eq!(isas, [(2048, Isa::Arm), (2048 + 6144, Isa::AArch64)]);
    let mut changed = image;
    changed[0x78 + 88 + 0x18] ^= 1;
    let p = classify(&changed);
    assert!(has_note(&p, "header hash field at 0x600 does not match"));
    assert!(has_note(&p, "hash does not match for image 2"));
}

// ---------------------------------------------------------------------------
// MediaTek
// ---------------------------------------------------------------------------

/// A GFH record header: `MMM` with version 1, size, type.
fn gfh_record(size: usize, record_type: u16) -> Vec<u8> {
    let mut record = vec![0u8; size];
    record[..4].copy_from_slice(b"MMM\x01");
    put_u16(&mut record, 4, size as u16);
    put_u16(&mut record, 6, record_type);
    record
}

/// A U-Boot style GFH image: `GFH_FILE_INFO` (name, file version 1, file
/// type 1, flash type 5, signature type 1 = SHA-256, load address of the
/// GFH, file length, maximum size, chain size, signature size 32, jump
/// offset), `GFH_BL_INFO` and `GFH_BROM_CFG` (`cfg_bits` 0x1000 and
/// `jump_bl_arm64` 0x64 at 0x55 when `arm64`); the code; a SHA-256 of
/// everything before it.
fn gfh_image(code: &[u8], arm64: bool) -> Vec<u8> {
    let mut info = gfh_record(0x38, 0);
    info[8..17].copy_from_slice(b"FILE_INFO");
    put_u32(&mut info, 0x14, 1);
    put_u16(&mut info, 0x18, 1);
    info[0x1a] = 5;
    info[0x1b] = 1;
    let mut brom_cfg = gfh_record(0x64, 7);
    if arm64 {
        put_u32(&mut brom_cfg, 8, 0x1000);
        brom_cfg[0x55] = 0x64;
    }
    let chain_size = info.len() + 0x0c + brom_cfg.len();
    let file_length = chain_size + code.len() + 32;
    put_u32(&mut info, 0x1c, 0x0020_1000 - chain_size as u32);
    put_u32(&mut info, 0x20, file_length as u32);
    put_u32(&mut info, 0x24, 0x0004_0000);
    put_u32(&mut info, 0x28, chain_size as u32);
    put_u32(&mut info, 0x2c, 32);
    put_u32(&mut info, 0x30, chain_size as u32);
    let mut data = info;
    data.extend(gfh_record(0x0c, 1));
    data.extend(brom_cfg);
    data.extend_from_slice(code);
    let digest = Sha256::digest(&data);
    data.extend_from_slice(&digest);
    data
}

/// `EMMC_BOOT` device header (0x200 bytes: name, version 1, size 0x200),
/// BRLYT at 0x200 (`BRLYT`, version 1, GFH address 0x600 at 0x0C and 0x1C,
/// image end at 0x10/0x20, magic `BBBB`, type 0x10005 eMMC), the GFH image
/// at 0x600.
fn emmc_boot(gfh: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x600];
    data[..9].copy_from_slice(b"EMMC_BOOT");
    put_u32(&mut data, 0x0c, 1);
    put_u32(&mut data, 0x10, 0x200);
    let brlyt = 0x200;
    data[brlyt..brlyt + 5].copy_from_slice(b"BRLYT");
    put_u32(&mut data, brlyt + 8, 1);
    put_u32(&mut data, brlyt + 0x0c, 0x600);
    put_u32(&mut data, brlyt + 0x10, (0x600 + gfh.len()) as u32);
    put_u32(&mut data, brlyt + 0x14, 0x4242_4242);
    put_u32(&mut data, brlyt + 0x18, 0x1_0005);
    put_u32(&mut data, brlyt + 0x1c, 0x600);
    put_u32(&mut data, brlyt + 0x20, (0x600 + gfh.len()) as u32);
    data.extend_from_slice(gfh);
    data
}

#[test]
fn mediatek_brom_cfg_aarch64_hand_off_names_aarch64() {
    let gfh = gfh_image(&aarch64_code(), true);
    let image = emmc_boot(&gfh);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::MediatekPreloader);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("EMMC_BOOT preloader")
    );
    assert_eq!(
        (p.primary.isa, p.primary.source),
        (Isa::AArch64, ClassificationSource::FileFormat)
    );
    assert!(has_note(&p, "requests an AArch64 hand-off"));
    assert!(has_note(&p, "SHA-256 hash over the image verified"));
    assert!(has_note(&p, "GFH records: FILE_INFO, BL_INFO, BROM_CFG"));
    let code = &p.slices[0];
    assert_eq!(code.label.as_deref(), Some("Preloader code"));
    assert_eq!(code.offset, 0x600 + 0x38 + 0x0c + 0x64);
    assert_eq!(code.size, aarch64_code().len() as u64);
    assert_eq!(p.primary.isa, code.isa);
    // Code entry: the GFH load address plus the jump offset.
    let entry = p
        .metadata
        .iter()
        .find(|m| m.key == MetadataKey::EntryPoint)
        .expect("entry");
    assert_eq!(entry.value.to_string(), "0x201000");
}

#[test]
fn mediatek_without_the_hand_off_takes_the_isa_from_the_code() {
    let gfh = gfh_image(&arm_code(), false);
    for image in [emmc_boot(&gfh), gfh.clone()] {
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::MediatekPreloader);
        assert_eq!(p.primary.isa, Isa::Arm);
        assert_ne!(p.primary.source, ClassificationSource::FileFormat);
        assert!(has_note(&p, "does not establish AArch32"));
    }
    assert_eq!(
        classify(&gfh).format.variant_name.as_deref(),
        Some("GFH preloader")
    );
    // A changed hash byte is noted, not an error; a broken BRLYT is.
    let mut changed = gfh.clone();
    *changed.last_mut().expect("hash") ^= 1;
    assert!(has_note(&classify(&changed), "does not match the image"));
    let mut broken = emmc_boot(&gfh);
    broken[0x214] ^= 1;
    assert!(error_text(&broken).contains("Missing BRLYT magic"));
    let mut short = gfh;
    put_u32(&mut short, 0x20, 0x40);
    assert!(error_text(&short).contains("Invalid GFH_FILE_INFO"));
}

// ---------------------------------------------------------------------------
// Qualcomm
// ---------------------------------------------------------------------------

/// `FLASH_CODE_WORD` and `MAGIC_NUM`.
const SBL_CODEWORD: u32 = 0x844b_dcd1;
const SBL_MAGIC: u32 = 0x73d7_1034;

/// The 80-byte SBL header (20 words): codeword, magic, image ID 21 (SBL1),
/// two reserved words, `image_src` (file offset of the code), destination
/// 0x0800_0000, image size, code size, signature pointer and size 256,
/// certificate chain pointer and size 0, root certificate fields,
/// `booting_image_config` at 0x3C, reserved words; at `header_at` in the
/// file, followed by the code and a 256-byte signature.
fn sbl(config: u32, code: &[u8], header_at: usize) -> Vec<u8> {
    let mut data = vec![0xffu8; header_at];
    let mut header = vec![0xffu8; 80];
    let dest = 0x0800_0000u32;
    let code_size = code.len() as u32;
    let words = [
        SBL_CODEWORD,
        SBL_MAGIC,
        21,
        0xffff_ffff,
        0xffff_ffff,
        (header_at + 80) as u32,
        dest,
        code_size + 256,
        code_size,
        dest + code_size,
        256,
        dest + code_size + 256,
        0,
        0,
        1,
        config,
    ];
    for (i, word) in words.iter().enumerate() {
        put_u32(&mut header, 4 * i, *word);
    }
    data.extend_from_slice(&header);
    data.extend_from_slice(code);
    data.extend_from_slice(&[0x5a; 256]);
    data
}

/// A NAND preamble: two 2048-byte pages that start with the codeword, the
/// magic and the autodetect magic 0x7D0B435A, the rest `0xFF`.
fn with_preamble(config: u32, code: &[u8]) -> Vec<u8> {
    let mut data = sbl(config, code, 4096);
    for page in [0usize, 2048] {
        put_u32(&mut data, page, SBL_CODEWORD);
        put_u32(&mut data, page + 4, SBL_MAGIC);
        put_u32(&mut data, page + 8, 0x7d0b_435a);
    }
    data
}

/// The 40-byte version 3 header (coreboot `ipqheader.py`): image ID 5
/// (APPSBL), version 3, image source 0, destination, image size, code
/// size, signature pointer and size, certificate pointer and size; then
/// code, signature and certificate chain.
fn mbn_v3(code: &[u8], sig: &[u8], certs: &[u8]) -> Vec<u8> {
    let dest = 0x4a90_0000u32;
    let code_size = code.len() as u32;
    let sig_size = sig.len() as u32;
    let total = code_size + sig_size + certs.len() as u32;
    let words = [
        5,
        3,
        0,
        dest,
        (total + 3) / 4 * 4,
        code_size,
        dest + code_size,
        sig_size,
        dest + code_size + sig_size,
        certs.len() as u32,
    ];
    let mut data = vec![0u8; 40];
    for (i, word) in words.iter().enumerate() {
        put_u32(&mut data, 4 * i, *word);
    }
    data.extend_from_slice(code);
    data.extend_from_slice(sig);
    data.extend_from_slice(certs);
    data
}

#[test]
fn sbl_booting_image_config_names_the_isa() {
    let p = classify(&sbl(0xf, &aarch64_code(), 0));
    assert_eq!(p.format.format, FileFormat::QualcommMbn);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("SBL MBN (80-byte header)")
    );
    assert_eq!(
        (p.primary.isa, p.primary.source),
        (Isa::AArch64, ClassificationSource::FileFormat)
    );
    assert!(has_note(&p, "Image ID 21 (SBL1) names a boot role"));
    assert!(has_note(
        &p,
        "Signature 256 B and certificate chain 0 B; not verified"
    ));
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, ["Code", "Signature"]);
    assert_eq!(p.slices[0].offset, 80);

    // Unset configuration: the code model answers.
    let p = classify(&sbl(0xffff_ffff, &arm_code(), 0));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(has_note(&p, "booting_image_config is unset"));
}

#[test]
fn sbl_after_a_nand_preamble_is_found_by_its_image_source() {
    let p = classify(&with_preamble(0xf, &aarch64_code()));
    assert_eq!(p.format.format, FileFormat::QualcommMbn);
    assert!(has_note(
        &p,
        "NAND preamble (autodetect magic 0x7D0B435A); SBL header at 0x1000"
    ));
    assert_eq!(p.slices[0].offset, 4096 + 80);
    let mut bad = sbl(0xf, &aarch64_code(), 0);
    put_u32(&mut bad, 0x14, 40);
    assert!(error_text(&bad).contains("Invalid SBL image_src"));
}

#[test]
fn mbn_v3_without_magic_is_recognized_only_when_consistent() {
    let code = arm_code();
    let image = mbn_v3(&code, &[0x11; 256], &[0x22; 6]);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::QualcommMbn);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("MBN (40-byte header)")
    );
    assert!(p.format.confidence < 1.0, "weak detection");
    assert_eq!(p.primary.isa, Isa::Arm);
    let labels: Vec<_> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, ["Code", "Signature", "Certificate chain"]);
    assert_eq!(p.slices[2].offset, (40 + code.len() + 256) as u64);

    // Each inconsistency leaves the file unrecognized.
    // Header version, image ID, image size, signature pointer and
    // certificate chain pointer.
    let corruptions: [(usize, u32); 5] = [
        (4, 5),
        (0, 99),
        (0x10, get_u32(&image, 0x10) + 4),
        (0x18, get_u32(&image, 0x18) + 4),
        (0x20, 0),
    ];
    for (at, value) in corruptions {
        let mut bad = image.clone();
        put_u32(&mut bad, at, value);
        let p = classify(&bad);
        assert_ne!(p.format.format, FileFormat::QualcommMbn, "field 0x{at:X}");
    }
    let mut trailing = image;
    trailing.extend_from_slice(b"more");
    assert_ne!(classify(&trailing).format.format, FileFormat::QualcommMbn);
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

/// Small instances of every layout, for the sweeps.
fn small_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let code = &arm_code()[..96];
    let aarch64 = &aarch64_code()[..96];
    vec![
        ("egon", egon(ARM_JUMP_0X60, code, 4)),
        ("toc0", toc0(&[(0x0001_0202, code)])),
        (
            "rkboot",
            rkboot(&[BootEntry {
                entry_type: 1,
                name: "ddr",
                data: code,
            }]),
        ),
        ("rkaf", rkaf(&[("uboot", aarch64)])),
        ("idbloader v1", idbloader_v1(code, false)),
        ("idbloader v2", idbloader_v2(&[code])),
        ("emmc", emmc_boot(&gfh_image(aarch64, true))),
        ("gfh", gfh_image(code, false)),
        ("sbl", sbl(0xf, aarch64, 0)),
        ("mbn", mbn_v3(code, &[0x11; 16], &[])),
    ]
}

#[test]
fn every_prefix_is_an_error_or_not_the_layout() {
    for (name, image) in small_fixtures() {
        let full = classify(&image);
        assert!(
            matches!(
                full.format.format,
                FileFormat::AllwinnerEgon
                    | FileFormat::RockchipImage
                    | FileFormat::MediatekPreloader
                    | FileFormat::QualcommMbn
            ),
            "{name}: {:?}",
            full.format.format
        );
        for end in 0..image.len() {
            if let Ok(p) = detect_payload(&image[..end], &ClassifierOptions::new()) {
                // Erased flash after an image is allowed, so a prefix that
                // cuts only padding may still parse.
                let only_padding = image[end..].iter().all(|&b| b == 0 || b == 0xff);
                assert!(
                    p.format.format != full.format.format || only_padding,
                    "{name}: prefix {end} still parses as {:?}",
                    p.format.format
                );
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mutations: [fn(u8) -> u8; 3] = [|_| 0x00, |_| 0xff, |b| b ^ 0x01];
    for (_, image) in small_fixtures() {
        for i in 0..image.len() {
            for mutate in mutations {
                let mut mutated = image.clone();
                mutated[i] = mutate(mutated[i]);
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

#[test]
fn json_ids_are_stable() {
    let ids = [
        (FileFormat::AllwinnerEgon, "\"allwinneregon\""),
        (FileFormat::RockchipImage, "\"rockchipimage\""),
        (FileFormat::MediatekPreloader, "\"mediatekpreloader\""),
        (FileFormat::QualcommMbn, "\"qualcommmbn\""),
    ];
    for (format, id) in ids {
        assert_eq!(serde_json::to_string(&format).expect("serializes"), id);
    }
}
