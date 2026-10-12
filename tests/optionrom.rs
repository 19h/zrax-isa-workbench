//! Option ROMs: PCI expansion ROMs name each image's code type (x86 real
//! mode, EFI with a PE machine, Open Firmware FCode), legacy ISA ROMs need
//! their checksum, and ROM images are never re-parsed as nested ROMs.

use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

/// A minimal PE image: DOS header with `e_lfanew` 0x40, `PE\0\0` and a COFF
/// header with the given machine and no sections.
fn pe(machine: u16) -> Vec<u8> {
    let mut data = vec![0u8; 0x40 + 24];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
    data
}

/// A PCI Data Structure at 0x1C: `PCIR`, vendor, device, length 0x18,
/// image length in 512-byte units, code type and indicator.
fn pcir(image: &mut [u8], code_type: u8, last: bool) {
    let blocks = (image.len() / 512) as u16;
    image[0x18..0x1a].copy_from_slice(&0x1cu16.to_le_bytes());
    image[0x1c..0x20].copy_from_slice(b"PCIR");
    image[0x20..0x22].copy_from_slice(&0x8086u16.to_le_bytes());
    image[0x22..0x24].copy_from_slice(&0x1234u16.to_le_bytes());
    image[0x26..0x28].copy_from_slice(&0x18u16.to_le_bytes());
    image[0x2c..0x2e].copy_from_slice(&blocks.to_le_bytes());
    image[0x30] = code_type;
    image[0x31] = if last { 0x80 } else { 0 };
}

/// A 512-byte x86 image: `55 AA`, size 1, a far jump, PCIR, real-mode code
/// and a final byte that makes the byte sum zero.
fn x86_image(last: bool) -> Vec<u8> {
    let mut image = vec![0u8; 512];
    image[..3].copy_from_slice(&[0x55, 0xaa, 1]);
    image[3..6].copy_from_slice(&[0xe9, 0x40, 0x00]);
    for (i, b) in image[0x40..0x1f0].iter_mut().enumerate() {
        *b = [
            0xb8, 0x00, 0x4f, 0xcd, 0x10, 0x3d, 0x4f, 0x00, 0x75, 0x02, 0xcb,
        ][i % 11];
    }
    pcir(&mut image, 0, last);
    let sum = image.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    image[511] = sum.wrapping_neg();
    image
}

/// A 512-byte EFI image: `55 AA`, initialization size, `0x0EF1`, boot
/// service driver subsystem, machine, compression, PE at 0x40, PCIR.
fn efi_image(machine: u16, compression: u16) -> Vec<u8> {
    let mut image = vec![0u8; 512];
    image[..2].copy_from_slice(&[0x55, 0xaa]);
    image[2..4].copy_from_slice(&1u16.to_le_bytes());
    image[4..8].copy_from_slice(&0x0ef1u32.to_le_bytes());
    image[8..10].copy_from_slice(&11u16.to_le_bytes());
    image[10..12].copy_from_slice(&machine.to_le_bytes());
    image[12..14].copy_from_slice(&compression.to_le_bytes());
    image[0x16..0x18].copy_from_slice(&0x40u16.to_le_bytes());
    let pe = pe(machine);
    image[0x40..0x40 + pe.len()].copy_from_slice(&pe);
    pcir(&mut image, 3, true);
    image
}

#[test]
fn pci_roms_list_each_image_with_its_code_type() {
    let mut rom = x86_image(false);
    rom.extend(efi_image(0x8664, 0));
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::PciOptionRom);
    assert_eq!(p.slices.len(), 2);
    assert_eq!((p.slices[0].isa, p.slices[0].bitwidth), (Isa::X86, 16));
    assert_eq!(p.slices[1].isa, Isa::X86_64);
    assert_eq!(p.slices[1].offset, 512 + 0x40);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("x86 image checksum verified")));
    assert!(p.notes.iter().any(|n| n.message == "PCI device 8086:1234"));
}

#[test]
fn compressed_efi_and_fcode_images_are_opaque() {
    let p = classify(&efi_image(0xaa64, 1));
    assert_eq!(p.slices[0].isa, Isa::Unknown(0));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("EFI-compressed image")));
    let mut fcode = x86_image(true);
    fcode[0x30] = 1;
    let p = classify(&fcode);
    assert!(p.notes.iter().any(|n| n.message.contains("FCode")));
}

#[test]
fn legacy_isa_roms_need_their_checksum() {
    let mut rom = x86_image(true);
    rom[0x18..0x1a].copy_from_slice(&0u16.to_le_bytes());
    rom[0x1c..0x20].copy_from_slice(&[0; 4]);
    let sum = rom[..511].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    rom[511] = sum.wrapping_neg();
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::PciOptionRom);
    assert_eq!(p.format.variant_name.as_deref(), Some("Legacy option ROM"));
    assert_eq!(p.primary.isa, Isa::X86);
    rom[100] ^= 1;
    if let Ok(p) = detect_payload(&rom, &ClassifierOptions::new()) {
        assert_ne!(p.format.format, FileFormat::PciOptionRom);
    }
}

#[test]
fn option_roms_survive_truncation_and_mutation() {
    let mut rom = x86_image(false);
    rom.extend(efi_image(0x8664, 0));
    for end in (0..rom.len()).step_by(3) {
        let _ = detect_payload(&rom[..end], &ClassifierOptions::new());
    }
    for i in 0..rom.len() {
        let mut mutated = rom.clone();
        mutated[i] ^= 0xff;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
    }
}
