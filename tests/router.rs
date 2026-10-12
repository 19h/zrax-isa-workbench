//! Router firmware wrappers: Broadcom TRX v1/v2 CRCs and partition roles,
//! Netgear CHK checksums, D-Link SEAMA entities and seals, TP-Link
//! `mktplinkfw`/`mktplinkfw2` headers and SafeLoader factory images, with
//! raw LZMA kernels decoded, truncation and mutation sweeps.

use zrax::formats::checksum::crc32_update;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/router");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed")
}

/// The synthetic MIPS kernel ELF, raw LZMA-alone with `lc=1 lp=2 pb=2`.
fn lzma_kernel() -> Vec<u8> {
    fixture("kernel.elf.lzma")
}

fn rootfs() -> Vec<u8> {
    fixture("rootfs.bin")
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

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

/// A named way to damage a fixture.
type Corruption = (&'static str, fn(&mut Vec<u8>));

/// `n` rounded up to a multiple of `align`.
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) / align * align
}

fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// A 52-byte ELF32 big-endian MIPS header (`EM_MIPS` 8) and filler.
fn mips_elf() -> Vec<u8> {
    let mut data = vec![0u8; 128];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 2, 1]);
    data[16..20].copy_from_slice(&[0, 2, 0, 8]);
    data
}

// Broadcom TRX

/// CRC-32 with initial value `0xFFFFFFFF` and no final XOR (`crc32buf` in
/// `trx.c`): the raw register.
fn jamcrc(data: &[u8]) -> u32 {
    crc32_update(!0, data)
}

/// `trx.c` without the CRC: header (28 B for version 1, 32 B for version
/// 2), each part zero-padded to 4 B with its offset at 16 + 4 * i, the
/// image zero-padded to 4 KiB, magic, length and `version << 16`.
fn trx_unsealed(version: u16, parts: &[&[u8]]) -> Vec<u8> {
    let header_size = if version == 1 { 28 } else { 32 };
    let mut image = vec![0u8; header_size];
    let mut offsets = Vec::new();
    for part in parts {
        offsets.push(image.len());
        image.extend_from_slice(part);
        image.resize(round_up(image.len(), 4), 0);
    }
    image.resize(round_up(image.len(), 0x1000), 0);
    image[..4].copy_from_slice(b"HDR0");
    let length = image.len() as u32;
    put_le32(&mut image, 4, length);
    put_le32(&mut image, 12, u32::from(version) << 16);
    for (i, &offset) in offsets.iter().enumerate() {
        put_le32(&mut image, 16 + 4 * i, offset as u32);
    }
    image
}

/// Store the CRC over `12..end`, with the 8 bytes at `fill_at` counted as
/// `0xFF` (the `trx -2` bin header quirk).
fn set_trx_crc(image: &mut [u8], end: usize, fill_at: Option<usize>) {
    let mut covered = image[12..end].to_vec();
    if let Some(at) = fill_at {
        covered[at - 12..at - 4].fill(0xff);
    }
    let crc = jamcrc(&covered);
    put_le32(image, 8, crc);
}

/// A TRX as `trx.c` writes it: version 2 counts the 8 bytes at
/// `offsets[3] + 22` (the offset table entry at 28) as `0xFF`.
fn trx(version: u16, parts: &[&[u8]]) -> Vec<u8> {
    let mut image = trx_unsealed(version, parts);
    let fill_at = (version == 2).then(|| le32(&image, 28) as usize + 22);
    let end = image.len();
    set_trx_crc(&mut image, end, fill_at);
    image
}

/// A 32-byte Cybertan code header: magic `W54G`, date, version, `U2ND`,
/// and non-erased `stable`/`try` fields at 22..30.
fn cybertan_header() -> Vec<u8> {
    let mut header = vec![0u8; 32];
    header[..4].copy_from_slice(b"W54G");
    header[14..18].copy_from_slice(b"U2ND");
    header[22..30].fill(0x01);
    header
}

#[test]
fn trx_v1_roles_follow_the_linux_parser_and_the_lzma_kernel_is_decoded() {
    let image = fixture("image.trx");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Trx);
    assert_eq!(p.format.variant_name.as_deref(), Some("Broadcom TRX"));
    assert!(has_note(&p, "Broadcom TRX v1;"));
    assert_eq!(p.primary.isa, Isa::Mips);
    assert_eq!(p.slices.len(), 3);
    let loader = slice(&p, "Partition 1 (loader)");
    assert_eq!((loader.offset, loader.isa), (0x1c, Isa::Mips));
    let kernel = slice(&p, "Partition 2 (kernel)");
    assert_eq!((kernel.offset, kernel.isa), (0x68, Isa::Mips));
    let decoded = kernel.decoded.as_ref().expect("decoded kernel");
    assert_eq!((decoded.transform.as_str(), decoded.size), ("LZMA", 256));
    let rootfs = slice(&p, "Partition 3 (root filesystem)");
    assert_eq!((rootfs.offset, rootfs.size), (0xb8, 0x1000 - 0xb8));
    assert!(has_note(
        &p,
        "CRC-32 (initial value 0xFFFFFFFF, no final XOR) verified over 0xC-0x1000"
    ));
    assert!(has_note(&p, "properties 0x6D"));
}

#[test]
fn trx_v2_crc_counts_the_bin_header_fields_as_erased() {
    let image = fixture("image-v2.trx");
    let p = classify(&image);
    assert!(has_note(&p, "Broadcom TRX v2;"));
    assert_eq!(p.slices.len(), 4);
    let bin_header = slice(&p, "Partition 4 (bin header)");
    assert!(matches!(bin_header.isa, Isa::Unknown(_)));
    assert!(has_note(&p, "Partition 4 (bin header): opaque"));
    assert!(has_note(&p, "counted as 0xFF"));

    // Non-erased stable/try bytes: the quirk changes the CRC.
    let parts = [
        fixture("loader.gz"),
        lzma_kernel(),
        rootfs(),
        cybertan_header(),
    ];
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let quirk = trx(2, &parts);
    assert!(has_note(&classify(&quirk), "counted as 0xFF"));
    let mut plain = trx_unsealed(2, &parts);
    let end = plain.len();
    set_trx_crc(&mut plain, end, None);
    let p = classify(&plain);
    assert!(has_note(&p, "without the bin header quirk"));
    assert_eq!(slice(&p, "Partition 2 (kernel)").isa, Isa::Mips);

    // The quirk applies at offsets[3] + 22 even when offsets[3] is zero.
    let mut no_bin_header = trx_unsealed(2, &parts[..3]);
    let end = no_bin_header.len();
    set_trx_crc(&mut no_bin_header, end, Some(22));
    assert!(has_note(&classify(&no_bin_header), "bytes at 0x16 counted"));
}

#[test]
fn trx_crc_mismatch_is_a_format_error() {
    let mut image = fixture("image.trx");
    image[0x70] ^= 0x01;
    assert!(error_text(&image).contains("Router firmware parse error: Invalid TRX CRC-32"));
}

#[test]
fn trx_crc_may_run_to_the_end_of_the_file_as_asustrx_writes_it() {
    let mut image = trx_unsealed(1, &[&lzma_kernel(), &rootfs()]);
    image.extend_from_slice(b"\x01\x02\x03\x04RT-ZRAX\0\0\0\0\0");
    image.extend_from_slice(&[0; 48]);
    let end = image.len();
    set_trx_crc(&mut image, end, None);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Trx);
    assert!(has_note(&p, "as asustrx computes it"));
}

#[test]
fn trx_data_after_the_length_is_listed_only_when_recognized() {
    let base = trx(1, &[&lzma_kernel(), &rootfs()]);
    let mut appended = base.clone();
    appended.extend_from_slice(&fixture("loader.gz"));
    let p = classify(&appended);
    let data = slice(&p, "Data after the TRX length");
    assert_eq!((data.offset, data.isa), (0x1000, Isa::Mips));
    assert!(has_note(&p, "not covered by the CRC"));

    let mut junk = base;
    junk.extend_from_slice(&[0x5a; 64]);
    let p = classify(&junk);
    assert_eq!(p.slices.len(), 2);
}

#[test]
fn trx_header_fields_are_validated() {
    let valid = || trx_unsealed(1, &[&lzma_kernel(), &rootfs()]);
    let cases: [Corruption; 6] = [
        ("Unsupported TRX version 3", |image| {
            put_le32(image, 12, 3 << 16)
        }),
        ("inside the 28 B header", |image| put_le32(image, 16, 8)),
        ("not after partition 0", |image| put_le32(image, 20, 0x1c)),
        ("not before the image length", |image| {
            put_le32(image, 20, 0x1000)
        }),
        ("set after an unused offset", |image| {
            put_le32(image, 20, 0);
            put_le32(image, 24, 0x200);
        }),
        ("Truncated TRX image", |image| put_le32(image, 4, 0x2000)),
    ];
    for (expected, corrupt) in cases {
        let mut image = valid();
        corrupt(&mut image);
        let end = image.len();
        set_trx_crc(&mut image, end, None);
        let message = error_text(&image);
        assert!(message.contains(expected), "{expected}: {message}");
    }
}

/// A version 2 TRX with Broadcom's 36-byte `BCMTRXV2` header: magic,
/// length, CRC (plain, over 12 to the length), flags, version 2, then five
/// offsets (the fifth at 32), the parts from 36 zero-padded to 4 B, and the
/// image zero-padded to 4 KiB.
fn trx_bcm_v2(parts: &[&[u8]], fifth_offset: u32) -> Vec<u8> {
    let mut image = vec![0u8; 36];
    let mut offsets = Vec::new();
    for part in parts {
        offsets.push(image.len());
        image.extend_from_slice(part);
        image.resize(round_up(image.len(), 4), 0);
    }
    image.resize(round_up(image.len(), 0x1000), 0);
    image[..4].copy_from_slice(b"HDR0");
    let length = image.len() as u32;
    put_le32(&mut image, 4, length);
    put_le32(&mut image, 12, 2 << 16);
    for (i, &offset) in offsets.iter().enumerate() {
        put_le32(&mut image, 16 + 4 * i, offset as u32);
    }
    put_le32(&mut image, 32, fifth_offset);
    let end = image.len();
    set_trx_crc(&mut image, end, None);
    image
}

#[test]
fn trx_v2_after_a_36_byte_header_reports_the_unread_fifth_offset() {
    let image = trx_bcm_v2(&[&lzma_kernel(), &rootfs()], 0x0abc);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Trx);
    assert!(has_note(
        &p,
        "First partition at 0x24, after a 36-byte header as Broadcom's BCMTRXV2 layout defines it; its fifth offset 0xABC is not read"
    ));
    assert_eq!(slice(&p, "Partition 1 (kernel)").isa, Isa::Mips);

    // The OpenWrt 32-byte layout gets no such note.
    let parts = [
        fixture("loader.gz"),
        lzma_kernel(),
        rootfs(),
        cybertan_header(),
    ];
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    assert!(!has_note(&classify(&trx(2, &parts)), "BCMTRXV2"));
}

#[test]
fn trx_flags_are_named_without_claiming_their_meaning() {
    let mut image = trx_unsealed(1, &[&lzma_kernel(), &rootfs()]);
    put_le32(&mut image, 12, 1 << 16 | 0x0042);
    let end = image.len();
    set_trx_crc(&mut image, end, None);
    let p = classify(&image);
    assert!(has_note(
        &p,
        "Flags 0x0042: TRX_GZ_FILES, TRX_BOOTLOADER; the names come from Broadcom trxhdr.h"
    ));
    assert!(has_note(&p, "not established"));
}

#[test]
fn trx_kernel_with_default_lzma_properties_is_decoded() {
    let x86 = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/compressed/payload.elf.lzma"
    ))
    .expect("fixture is committed");
    let p = classify(&trx(1, &[&x86, &rootfs()]));
    let kernel = slice(&p, "Partition 1 (kernel)");
    assert_eq!(kernel.isa, Isa::X86_64);
    assert!(has_note(&p, "properties 0x5D"));
}

// Netgear CHK

/// `netgear_checksum_add` and `_fini` in `mkchkimg.c`.
fn netgear_checksum(data: &[u8]) -> u32 {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    for &b in data {
        c0 = c0.wrapping_add(u32::from(b));
        c1 = c1.wrapping_add(c0);
    }
    let fold = |sum: u32| {
        let folded = (sum & 0xffff) + (sum >> 16);
        ((folded >> 16) + folded) & 0xffff
    };
    (fold(c1) << 16) | fold(c0)
}

/// `mkchkimg.c`: magic, header length (40 + board ID), region 1 and
/// version digits, kernel and root filesystem checksums and lengths, image
/// checksum, header checksum (over the header with this field zero and
/// the board ID), board ID, kernel, root filesystem.
fn chk(board_id: &[u8], kernel: &[u8], rootfs: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 40];
    header[..4].copy_from_slice(&[0x2a, 0x23, 0x24, 0x5e]);
    put_be32(&mut header, 4, (40 + board_id.len()) as u32);
    header[8..16].copy_from_slice(&[1, 1, 0, 2, 3, 4, 5, 6]);
    put_be32(&mut header, 16, netgear_checksum(kernel));
    if !rootfs.is_empty() {
        put_be32(&mut header, 20, netgear_checksum(rootfs));
    }
    put_be32(&mut header, 24, kernel.len() as u32);
    put_be32(&mut header, 28, rootfs.len() as u32);
    put_be32(
        &mut header,
        32,
        netgear_checksum(&[kernel, rootfs].concat()),
    );
    let header_checksum = netgear_checksum(&[&header[..], board_id].concat());
    put_be32(&mut header, 36, header_checksum);
    [&header[..], board_id, kernel, rootfs].concat()
}

#[test]
fn chk_wraps_a_trx_and_verifies_every_checksum() {
    let image = fixture("image.chk");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::NetgearChk);
    assert_eq!(p.primary.isa, Isa::Mips);
    let kernel = slice(&p, "Kernel");
    assert_eq!((kernel.offset, kernel.size), (58, 4096));
    assert!(has_note(&p, "header, kernel and image checksums verified"));
    assert!(has_note(
        &p,
        "Board ID U12H072T00_NETGEAR; region code 1 (WW)"
    ));
    assert!(has_note(&p, "Kernel: mips (contained Broadcom TRX)"));
}

#[test]
fn chk_with_a_root_filesystem_lists_both_parts() {
    let kernel = lzma_kernel();
    let p = classify(&chk(b"ZRAX_BOARD", &kernel, &rootfs()));
    assert!(has_note(
        &p,
        "header, kernel, root filesystem and image checksums verified"
    ));
    assert!(has_note(&p, "version digits 1.0.2.3_4.5.6"));
    let header_len = 50;
    assert_eq!(slice(&p, "Kernel").offset, header_len);
    assert_eq!(slice(&p, "Kernel").isa, Isa::Mips);
    let rootfs_slice = slice(&p, "Root filesystem");
    assert_eq!(rootfs_slice.offset, header_len + kernel.len() as u64);
}

#[test]
fn chk_checksum_and_length_errors_name_the_field() {
    let kernel = lzma_kernel();
    let image = chk(b"ZRAX_BOARD", &kernel, &rootfs());
    let mut board = image.clone();
    board[45] ^= 0x01;
    assert!(error_text(&board).contains("Invalid CHK header checksum"));
    let mut payload = image.clone();
    payload[60] ^= 0x01;
    assert!(error_text(&payload).contains("Invalid CHK kernel checksum"));
    let mut tail = image.clone();
    *tail.last_mut().expect("non-empty") ^= 0x01;
    assert!(error_text(&tail).contains("Invalid CHK root filesystem checksum"));
    let mut header_len = image.clone();
    put_be32(&mut header_len, 4, 200);
    assert!(error_text(&header_len).contains("Invalid CHK header length 200 B"));
    let mut trailing = image;
    trailing.push(0x42);
    assert!(error_text(&trailing).contains("Unexpected 1 B after the CHK image"));
}

// D-Link SEAMA

/// NUL-terminated strings padded with NULs to 4 B (`seama.c`).
fn seama_meta(strings: &[&str]) -> Vec<u8> {
    let mut meta: Vec<u8> = strings.iter().flat_map(|s| s.bytes().chain([0])).collect();
    meta.resize(round_up(meta.len(), 4), 0);
    meta
}

/// An entity: magic, reserved, metadata size, image size, an MD5 field
/// (a fixed pattern: the parser does not verify it), metadata, image.
fn seama_entity(meta: &[&str], image: &[u8]) -> Vec<u8> {
    let meta = seama_meta(meta);
    let mut entity = vec![0x5e, 0xa3, 0xa4, 0x17, 0, 0];
    entity.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    entity.extend_from_slice(&(image.len() as u32).to_be_bytes());
    entity.extend_from_slice(&[0xa5; 16]);
    entity.extend_from_slice(&meta);
    entity.extend_from_slice(image);
    entity
}

/// A seal: a header with image size 0, metadata, then whole entities.
fn seama_seal(meta: &[&str], entities: &[Vec<u8>]) -> Vec<u8> {
    let meta = seama_meta(meta);
    let mut seal = vec![0x5e, 0xa3, 0xa4, 0x17, 0, 0];
    seal.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    seal.extend_from_slice(&[0; 4]);
    seal.extend_from_slice(&meta);
    for entity in entities {
        seal.extend_from_slice(entity);
    }
    seal
}

#[test]
fn seama_seal_entities_are_classified_as_nested_seama_images() {
    let image = fixture("image.seama");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Seama);
    assert_eq!(p.format.variant_name.as_deref(), Some("D-Link SEAMA"));
    assert_eq!(p.primary.isa, Isa::Mips);
    let entity = slice(&p, "Entity 1");
    assert_eq!((entity.offset, entity.size), (44, 143));
    assert!(has_note(&p, "D-Link SEAMA seal with 1 entity;"));
    assert!(has_note(&p, "Metadata: signature=zrax_router_fixture"));

    let inner = classify(&image[44..]);
    assert!(has_note(&inner, "D-Link SEAMA entity; 79 B image"));
    let payload = slice(&inner, "Image");
    assert_eq!((payload.offset, payload.isa), (64, Isa::Mips));
    assert!(has_note(&inner, "not verified (no MD5 implementation)"));
    assert!(has_note(
        &inner,
        "Metadata: dev=/dev/mtdblock/1; type=firmware"
    ));
}

#[test]
fn seama_nested_seals_recurse() {
    let entity = seama_entity(&["type=kernel"], &lzma_kernel());
    let inner_seal = seama_seal(&["signature=inner"], std::slice::from_ref(&entity));
    let outer = seama_seal(&["signature=outer"], &[entity, inner_seal]);
    let p = classify(&outer);
    assert_eq!(p.slices.len(), 2);
    assert!(has_note(&p, "seal with 2 entities"));
    assert_eq!(slice(&p, "Entity 2 (seal)").isa, Isa::Mips);
}

#[test]
fn seama_ranges_and_trailing_data_are_checked() {
    let entity = seama_entity(&["type=firmware"], &lzma_kernel());
    let mut trailing = entity.clone();
    trailing.extend_from_slice(b"junk");
    assert!(error_text(&trailing).contains("Unexpected 4 B after the SEAMA entity"));
    let mut padded = entity.clone();
    padded.extend_from_slice(&[0xff; 32]);
    assert_eq!(classify(&padded).format.format, FileFormat::Seama);
    let mut oversized = entity.clone();
    put_be32(&mut oversized, 8, 0x0100_0000);
    assert!(error_text(&oversized).contains("Truncated SEAMA image"));
    let mut seal = seama_seal(&[], &[entity]);
    seal[12] = 0;
    assert!(error_text(&seal).contains("Missing SEAMA magic at 0xC"));
}

// TP-Link mktplinkfw and mktplinkfw2

/// `mktplinkfw.c` v1 header (zero-filled, big-endian) at 0, the kernel at
/// 0x200 and the root filesystem at `rootfs_offset` in an `0xFF`-filled
/// image: version word 1, vendor, firmware version, hardware ID and
/// revision, a fixed MD5 pattern (not verified by the parser), load and
/// entry 0x80060000, firmware length, kernel offset and length, root
/// filesystem offset and length, version 1.0.0.
fn tplink_v1(kernel: &[u8], rootfs: &[u8], rootfs_offset: usize) -> Vec<u8> {
    let mut image = vec![0xffu8; (rootfs_offset + rootfs.len()).max(0x200 + kernel.len())];
    image[..0x200].fill(0);
    image[0x200..0x200 + kernel.len()].copy_from_slice(kernel);
    image[rootfs_offset..rootfs_offset + rootfs.len()].copy_from_slice(rootfs);
    put_be32(&mut image, 0x00, 0x0100_0000);
    image[0x04..0x04 + 20].copy_from_slice(b"TP-LINK Technologies");
    image[0x1c..0x1c + 8].copy_from_slice(b"ver. 1.0");
    put_be32(&mut image, 0x40, 0x5a52_0001);
    put_be32(&mut image, 0x44, 1);
    image[0x4c..0x5c].fill(0x5c);
    put_be32(&mut image, 0x74, 0x8006_0000);
    put_be32(&mut image, 0x78, 0x8006_0000);
    put_be32(&mut image, 0x7c, 0x003c_0000);
    put_be32(&mut image, 0x80, 0x200);
    put_be32(&mut image, 0x84, kernel.len() as u32);
    put_be32(&mut image, 0x88, rootfs_offset as u32);
    put_be32(&mut image, 0x8c, rootfs.len() as u32);
    image[0x98..0x9a].copy_from_slice(&1u16.to_be_bytes());
    image
}

/// `mktplinkfw2.c` header (`0xFF`-filled): version word 2, firmware
/// version string, hardware ID, revision and additional version, a fixed
/// MD5 pattern, `unk2` 0 and `unk3` all ones, load and entry, firmware
/// length, kernel offset and length, root filesystem offset and length,
/// bootloader offset and length, `0x55AA`, secondary version 1.0, `0xA5`,
/// version 1.0.0.
/// The `mktplinkfw2` root filesystem offset and length fields.
#[derive(Clone, Copy)]
struct RootFsFields {
    offset: u32,
    len: u32,
}

/// Combined images leave both fields at the `0xFF` header fill.
const UNSET_ROOTFS: RootFsFields = RootFsFields {
    offset: u32::MAX,
    len: u32::MAX,
};

fn tplink_v2_header(
    kernel_offset: usize,
    kernel_len: usize,
    rootfs: RootFsFields,
    boot_len: usize,
) -> Vec<u8> {
    let mut header = vec![0xffu8; 0x200];
    put_be32(&mut header, 0x00, 0x0200_0000);
    header[0x04..0x04 + 9].copy_from_slice(b"ver. 1.0\0");
    put_be32(&mut header, 0x34, 0x5a52_0001);
    put_be32(&mut header, 0x38, 1);
    put_be32(&mut header, 0x3c, 0);
    header[0x40..0x50].fill(0x5c);
    put_be32(&mut header, 0x50, 0);
    put_be32(&mut header, 0x68, 0x8006_0000);
    put_be32(&mut header, 0x6c, 0x8006_0000);
    put_be32(&mut header, 0x70, 0x003c_0000);
    put_be32(&mut header, 0x74, kernel_offset as u32);
    put_be32(&mut header, 0x78, kernel_len as u32);
    put_be32(&mut header, 0x7c, rootfs.offset);
    put_be32(&mut header, 0x80, rootfs.len);
    put_be32(&mut header, 0x84, 0);
    put_be32(&mut header, 0x88, boot_len as u32);
    header[0x8c..0x91].copy_from_slice(&[0x55, 0xaa, 1, 0, 0xa5]);
    header[0x91..0x94].copy_from_slice(&[1, 0, 0]);
    header
}

/// A `mktplinkfw2` image without a bootloader: header, kernel at 0x200,
/// and the root filesystem at file offset 0x1000 (none for a combined
/// image).
fn tplink_v2(kernel: &[u8], rootfs: Option<&[u8]>) -> Vec<u8> {
    const ROOTFS_OFFSET: usize = 0x1000;
    let fields = rootfs.map_or(UNSET_ROOTFS, |bytes| RootFsFields {
        offset: ROOTFS_OFFSET as u32,
        len: bytes.len() as u32,
    });
    let mut image = tplink_v2_header(0x200, kernel.len(), fields, 0);
    image.extend_from_slice(kernel);
    if let Some(bytes) = rootfs {
        image.resize(ROOTFS_OFFSET, 0xff);
        image.extend_from_slice(bytes);
    }
    image
}

#[test]
fn tplink_v1_header_names_no_isa_and_the_kernel_supplies_it() {
    let image = fixture("tplink-v1.bin");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::TpLink);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("TP-Link header (mktplinkfw layout)")
    );
    assert_eq!(p.primary.isa, Isa::Mips);
    let kernel = slice(&p, "Kernel");
    assert_eq!((kernel.offset, kernel.size), (0x200, 79));
    assert_eq!(kernel.decoded.as_ref().map(|d| d.size), Some(256));
    assert_eq!(slice(&p, "Root filesystem").offset, 0x1000);
    assert!(has_note(
        &p,
        "Vendor TP-LINK Technologies; firmware version string ver. 1.0"
    ));
    assert!(has_note(&p, "not verified (no MD5 implementation)"));
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Kernel load address" && m.value.to_string() == "0x80060000"));
}

#[test]
fn tplink_header_without_code_reports_an_unknown_isa() {
    // The load address 0x80060000 and the hardware ID are no ISA evidence.
    let p = classify(&tplink_v1(&[0u8; 64], &[], 0));
    assert_eq!(p.format.format, FileFormat::TpLink);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
}

#[test]
fn tplink_v2_layouts_cover_combined_and_bootloader_images() {
    let image = fixture("tplink-v2.bin");
    let p = classify(&image);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("TP-Link header (mktplinkfw2 layout)")
    );
    assert_eq!(slice(&p, "Kernel").isa, Isa::Mips);
    assert_eq!(slice(&p, "Root filesystem").offset, 0x1000);

    // Combined images leave the root filesystem fields at the 0xFF fill.
    let combined = classify(&tplink_v2(&lzma_kernel(), None));
    assert_eq!(combined.slices.len(), 1);
    assert!(has_note(&combined, "No root filesystem declared"));

    // `prepend_bootloader`: header, bootloader padded to 64 KiB, then a
    // complete second image whose root filesystem offset is its own.
    let kernel = lzma_kernel();
    let inner = tplink_v2(&kernel, Some(&rootfs()));
    let boot = mips_elf();
    let inner_base = 0x200 + 0x10000;
    let inner_rootfs = RootFsFields {
        offset: 0x1000,
        len: 512,
    };
    let mut outer = tplink_v2_header(inner_base + 0x200, kernel.len(), inner_rootfs, boot.len());
    outer.extend_from_slice(&boot);
    outer.resize(inner_base, 0xff);
    outer.extend_from_slice(&inner);
    let p = classify(&outer);
    assert_eq!(slice(&p, "Bootloader").offset, 0x200);
    assert_eq!(slice(&p, "Bootloader").isa, Isa::Mips);
    assert_eq!(slice(&p, "Kernel").offset, inner_base as u64 + 0x200);
    assert_eq!(
        slice(&p, "Root filesystem").offset,
        inner_base as u64 + 0x1000
    );
    assert!(has_note(&p, "the second image header at 0x10200"));
}

#[test]
fn tplink_weak_detection_requires_the_whole_structure() {
    let valid = tplink_v1(&lzma_kernel(), &rootfs(), 0x1000);
    assert_eq!(classify(&valid).format.format, FileFormat::TpLink);
    let corruptions: [Corruption; 7] = [
        ("version word", |image| put_be32(image, 0, 0x0400_0000)),
        ("vendor control byte", |image| image[0x06] = 0x01),
        ("empty firmware version", |image| image[0x1c] = 0),
        ("kernel offset", |image| put_be32(image, 0x80, 0x300)),
        ("kernel beyond the file", |image| {
            put_be32(image, 0x84, 0x10_0000)
        }),
        ("rootfs overlaps the kernel", |image| {
            put_be32(image, 0x88, 0x210)
        }),
        ("trailing data", |image| image.extend_from_slice(b"junk")),
    ];
    for (what, corrupt) in corruptions {
        let mut image = valid.clone();
        corrupt(&mut image);
        let format = detect_payload(&image, &ClassifierOptions::new()).map(|p| p.format.format);
        assert!(!matches!(format, Ok(FileFormat::TpLink)), "{what}");
    }
    // JFFS2 end marks at 4 KiB boundaries after the image are fill.
    let mut marked = valid;
    marked.resize(0x2000, 0xff);
    marked.extend_from_slice(&[0xde, 0xad, 0xc0, 0xde]);
    assert_eq!(classify(&marked).format.format, FileFormat::TpLink);

    let mut v2 = tplink_v2(&lzma_kernel(), None);
    v2[0x90] = 0xa4;
    let format = detect_payload(&v2, &ClassifierOptions::new()).map(|p| p.format.format);
    assert!(!matches!(format, Ok(FileFormat::TpLink)));
}

#[test]
fn tplink_undecodable_lzma_kernel_is_opaque() {
    let mut bogus = vec![0x6d, 0, 0, 0x80, 0];
    bogus.extend_from_slice(&[0xff; 8]);
    bogus.extend_from_slice(&[0x55; 64]);
    let p = classify(&tplink_v1(&bogus, &[], 0));
    assert!(has_note(
        &p,
        "Kernel: starts with an LZMA-alone header but does not decode"
    ));
    assert!(has_note(&p, "Kernel: opaque"));
    assert!(matches!(slice(&p, "Kernel").isa, Isa::Unknown(_)));
}

// TP-Link SafeLoader

/// What the 0x1000-byte SafeLoader header holds.
enum SafeLoaderHeader<'a> {
    Vendor(&'a [u8]),
    Cloud,
    Default,
    QNew,
}

/// `generate_factory_image`: `0xFF`-filled image, the image size, an MD5
/// pattern (not verified), the header, the `fwup-ptn` table at 0x1014
/// (bases relative to it, starting at 0x800, each line ending `\t\r\n`,
/// then a NUL), and the partitions.
fn safeloader(header: &SafeLoaderHeader<'_>, parts: &[(&str, &[u8])]) -> Vec<u8> {
    let size = 0x1814 + parts.iter().map(|(_, p)| p.len()).sum::<usize>();
    let mut image = vec![0xffu8; size];
    put_be32(&mut image, 0, size as u32);
    image[4..0x14].fill(0x5c);
    match header {
        SafeLoaderHeader::Vendor(text) => {
            put_be32(&mut image, 0x14, text.len() as u32);
            image[0x18..0x18 + text.len()].copy_from_slice(text);
        }
        SafeLoaderHeader::Cloud => image[0x14..0x21].copy_from_slice(b"fw-type:Cloud"),
        SafeLoaderHeader::Default => put_be32(&mut image, 0x14, 0x0010_0000),
        SafeLoaderHeader::QNew => image[0x14..0x18].copy_from_slice(b"?NEW"),
    }
    let mut table = String::new();
    let mut base = 0x800;
    for (name, data) in parts {
        table.push_str(&format!(
            "fwup-ptn {name} base 0x{base:05x} size 0x{:05x}\t\r\n",
            data.len()
        ));
        image[0x1014 + base..0x1014 + base + data.len()].copy_from_slice(data);
        base += data.len();
    }
    image[0x1014..0x1014 + table.len()].copy_from_slice(table.as_bytes());
    image[0x1014 + table.len()] = 0;
    image
}

#[test]
fn safeloader_partitions_are_classified_by_role() {
    let image = fixture("safeloader.bin");
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::TpLink);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("TP-Link SafeLoader factory image")
    );
    assert_eq!(p.primary.isa, Isa::Mips);
    let table = slice(&p, "Partition partition-table");
    assert_eq!((table.offset, table.size), (0x1814, 0x800));
    assert!(has_note(&p, "Partition partition-table: opaque"));
    assert!(has_note(
        &p,
        "Partition os-image: mips (contained TP-Link firmware)"
    ));
    assert!(has_note(
        &p,
        "Soft version 1.0.0, built 2026-10-12, revision 1"
    ));
    assert!(has_note(&p, "Support list: ZRAX-FIXTURE(ZRAX|UN|TEST):1.0"));
    assert!(has_note(&p, "vendor information header; 5 partitions"));
}

#[test]
fn safeloader_header_types_and_unknown_partitions() {
    let kernel = lzma_kernel();
    let parts: [(&str, &[u8]); 2] = [("os-image", &kernel), ("fs-uboot", &[0x5a; 32])];
    let cloud = classify(&safeloader(&SafeLoaderHeader::Cloud, &parts));
    assert!(has_note(&cloud, "cloud header"));
    assert_eq!(slice(&cloud, "Partition os-image").isa, Isa::Mips);
    assert!(has_note(&cloud, "Partitions fs-uboot have no role"));
    assert_eq!(cloud.slices.len(), 1);
    let default = classify(&safeloader(&SafeLoaderHeader::Default, &parts));
    assert!(has_note(&default, "default header"));
    let vendor = classify(&safeloader(
        &SafeLoaderHeader::Vendor(b"vendor:ZRAX\r\n"),
        &parts,
    ));
    assert!(has_note(&vendor, "Vendor information: vendor:ZRAX"));
    let qnew = safeloader(&SafeLoaderHeader::QNew, &parts);
    let format = detect_payload(&qnew, &ClassifierOptions::new()).map(|p| p.format.format);
    assert!(!matches!(format, Ok(FileFormat::TpLink)));
}

#[test]
fn safeloader_table_must_be_consistent() {
    let kernel = lzma_kernel();
    let valid = safeloader(&SafeLoaderHeader::Default, &[("os-image", &kernel)]);
    assert_eq!(classify(&valid).format.format, FileFormat::TpLink);
    let corruptions: [Corruption; 5] = [
        ("size beyond the file", |image| {
            put_be32(image, 0, 0x10_0000)
        }),
        ("base inside the table", |image| image[0x1014 + 27] = b'4'),
        ("malformed line", |image| image[0x1014 + 18] = b'x'),
        ("junk after the table", |image| image[0x1014 + 0x400] = b'x'),
        ("trailing data", |image| image.extend_from_slice(b"junk")),
    ];
    for (what, corrupt) in corruptions {
        let mut image = valid.clone();
        corrupt(&mut image);
        let format = detect_payload(&image, &ClassifierOptions::new()).map(|p| p.format.format);
        assert!(!matches!(format, Ok(FileFormat::TpLink)), "{what}");
    }
}

#[test]
fn bytes_valid_as_two_tp_link_layouts_are_reported_as_ambiguous() {
    // 16 MiB: the SafeLoader size 0x01000000 is also the v1 version word.
    let size = 0x0100_0000usize;
    let mut image = vec![0u8; size];
    put_be32(&mut image, 0, size as u32);
    image[0x04..0x0c].copy_from_slice(b"TP-LINK\0");
    put_be32(&mut image, 0x14, u32::MAX);
    image[0x1c..0x25].copy_from_slice(b"ver. 1.0\0");
    put_be32(&mut image, 0x80, 0x200);
    put_be32(&mut image, 0x84, (size - 0x200) as u32);
    let line = format!(
        "fwup-ptn file-system base 0x00800 size 0x{:05x}\t\r\n",
        size - 0x1814
    );
    image[0x1014..0x1014 + line.len()].copy_from_slice(line.as_bytes());
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::TpLink);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Ambiguous TP-Link image")
    );
    assert!(p.slices.is_empty());
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "validate as TP-Link header (mktplinkfw layout) and TP-Link SafeLoader factory image"
    ));
}

// Sweeps

fn committed_images() -> Vec<(&'static str, FileFormat, Vec<u8>)> {
    [
        ("image.trx", FileFormat::Trx),
        ("image-v2.trx", FileFormat::Trx),
        ("image.chk", FileFormat::NetgearChk),
        ("image.seama", FileFormat::Seama),
        ("tplink-v1.bin", FileFormat::TpLink),
        ("tplink-v2.bin", FileFormat::TpLink),
        ("safeloader.bin", FileFormat::TpLink),
    ]
    .into_iter()
    .map(|(name, format)| (name, format, fixture(name)))
    .collect()
}

#[test]
fn truncated_router_images_never_claim_their_payload() {
    for (name, format, image) in committed_images() {
        for end in 0..image.len() {
            let Ok(p) = detect_payload(&image[..end], &ClassifierOptions::new()) else {
                continue;
            };
            // A SEAMA seal cut at an entity boundary is a shorter seal.
            let claims = p.format.format == format
                && p.slices
                    .iter()
                    .any(|s| s.decoded.is_some() || s.isa == Isa::Mips);
            assert!(!claims, "{name} prefix {end}");
        }
    }
}

#[test]
fn router_images_survive_byte_mutations_without_panicking() {
    // Every header byte (the first 0x200 bytes and the SafeLoader table
    // lines) gets all three mutations; payload bytes get one each, cycling
    // through them.
    let is_header = |i: usize| i < 0x200 || (0x1014..0x1100).contains(&i);
    for (_, _, image) in committed_images() {
        for i in 0..image.len() {
            let values = [0x00, 0xff, image[i] ^ 0x01];
            let mutations = if is_header(i) {
                &values[..]
            } else {
                &values[i % 3..=i % 3]
            };
            for &value in mutations {
                let mut mutated = image.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
