//! Huawei UPDATE.APP packages: entries after the zero prefix become
//! partitions classified on their own, with stored offsets and 4-byte
//! alignment, and truncated or inconsistent entries are errors.

use zrax::formats::checksum::crc32;
use zrax::{detect_payload, ClassifierOptions, FileFormat, Isa};

/// A 64-byte ELF64 little-endian x86-64 header.
fn elf_x86_64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    data[16..20].copy_from_slice(&[2, 0, 0x3e, 0]);
    data
}

/// One entry: magic, header length (98 fixed + 2 B of block checksums),
/// unknown, hardware ID, sequence, data size, date, time, type, blank,
/// header checksum, block size, blank, checksums; data padded to 4 bytes.
fn entry(out: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let mut header = vec![0u8; 100];
    header[..4].copy_from_slice(&[0x55, 0xaa, 0x5a, 0xa5]);
    header[4..8].copy_from_slice(&100u32.to_le_bytes());
    header[12..20].copy_from_slice(b"HW7x3000");
    header[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[28..38].copy_from_slice(b"2026.10.12");
    header[44..52].copy_from_slice(b"12:00:00");
    header[60..60 + name.len()].copy_from_slice(name.as_bytes());
    header[94..96].copy_from_slice(&4096u16.to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// A package: 92 zero bytes, a 6-byte "BOOT" entry and an ELF "SYSTEM".
fn package() -> Vec<u8> {
    let mut data = vec![0u8; 92];
    entry(&mut data, "BOOT", b"kernel");
    entry(&mut data, "SYSTEM", &elf_x86_64());
    data
}

#[test]
fn partitions_are_listed_and_classified() {
    let data = package();
    let p = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, FileFormat::HuaweiUpdate);
    assert_eq!(p.primary.isa, Isa::X86_64);
    let system = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("SYSTEM"))
        .unwrap();
    // 92 + 100 + 6 rounded to 200, then a 100-byte header.
    assert_eq!(system.offset, 300);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("hardware ID HW7x3000")));
}

#[test]
fn truncated_packages_are_errors_and_mutations_never_panic() {
    let data = package();
    // Prefixes 198-200 end after the complete first entry and its padding,
    // which is itself a valid package.
    for end in (97..data.len() - 4).filter(|end| !(198..=200).contains(end)) {
        if let Ok(p) = detect_payload(&data[..end], &ClassifierOptions::new()) {
            assert_ne!(p.format.format, FileFormat::HuaweiUpdate, "prefix {end}");
        }
    }
    for i in 0..data.len() {
        let mut mutated = data.clone();
        mutated[i] ^= 0xff;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
    }
    assert_ne!(crc32(&data), 0);
}
