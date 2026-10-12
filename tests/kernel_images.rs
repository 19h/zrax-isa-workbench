//! Kernel and boot images: uImage byte order and payload decoding,
//! multi-file uImages, x86 `XLF_KERNEL_64`, Arm zImage, FIT `/images`,
//! device trees and compressed kernel payloads classified from their
//! decoded bytes.

use zrax::formats::checksum::crc32;
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;
const EM_X86_64: u16 = 62;
const EM_MIPS: u16 = 8;

/// A 64-byte ELF header: class (1 = 32-bit, 2 = 64-bit), data encoding
/// (1 = little-endian, 2 = big-endian), version 1, executable, machine.
fn elf(class: u8, big_endian: bool, machine: u16) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = class;
    data[5] = if big_endian { 2 } else { 1 };
    data[6] = 1;
    let put16 = |data: &mut Vec<u8>, at: usize, v: u16| {
        let bytes = if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        data[at..at + 2].copy_from_slice(&bytes);
    };
    put16(&mut data, 16, 2);
    put16(&mut data, 18, machine);
    data
}

/// One gzip member (RFC 1952): fixed header, DEFLATE data, CRC-32, size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    member
}

/// uImage: magic, header CRC (computed with the field zeroed), timestamp,
/// data size, load 0x80008000, entry 0x80008000, data CRC, OS 5 (Linux),
/// architecture, type, compression, name; then the payload.
fn uimage(arch: u8, image_type: u8, compression: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    data[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    data[16..20].copy_from_slice(&0x8000_8000u32.to_be_bytes());
    data[20..24].copy_from_slice(&0x8000_8000u32.to_be_bytes());
    data[24..28].copy_from_slice(&crc32(payload).to_be_bytes());
    data[0x1c] = 5;
    data[0x1d] = arch;
    data[0x1e] = image_type;
    data[0x1f] = compression;
    data[0x20..0x26].copy_from_slice(b"kernel");
    let header_crc = crc32(&data);
    data[4..8].copy_from_slice(&header_crc.to_be_bytes());
    data.extend_from_slice(payload);
    data
}

const ARCH_ARM: u8 = 2;
const ARCH_MIPS: u8 = 5;
const TYPE_KERNEL: u8 = 2;
const TYPE_RAMDISK: u8 = 3;
const TYPE_MULTI: u8 = 4;
const COMP_NONE: u8 = 0;
const COMP_GZIP: u8 = 1;

/// x86 boot image: one setup sector after the boot sector, boot flag
/// 0xAA55, "HdrS", protocol, loadflags 1 (bzImage), xloadflags and the
/// payload location relative to the protected-mode code at 0x400.
fn bzimage(protocol: u16, xloadflags: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x400 + 0x100];
    data[0x1f1] = 1;
    data[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
    data[0x202..0x206].copy_from_slice(b"HdrS");
    data[0x206..0x208].copy_from_slice(&protocol.to_le_bytes());
    data[0x211] = 1;
    data[0x236..0x238].copy_from_slice(&xloadflags.to_le_bytes());
    data[0x248..0x24c].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x24c..0x250].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    data.extend_from_slice(payload);
    data
}

/// Arm zImage: eight NOP words and a branch, then the magic 0x016F2818, the
/// start and end addresses and the endianness flag; the compressed kernel
/// at 0x100.
fn zimage(endian_flag: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    for word in data[..0x24].chunks_exact_mut(4) {
        word.copy_from_slice(&0xe1a0_0000u32.to_le_bytes());
    }
    data[0x24..0x28].copy_from_slice(&0x016f_2818u32.to_le_bytes());
    let size = (0x100 + payload.len()) as u32;
    data[0x28..0x2c].copy_from_slice(&0u32.to_le_bytes());
    data[0x2c..0x30].copy_from_slice(&size.to_le_bytes());
    data[0x30..0x34].copy_from_slice(&endian_flag.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

/// A flattened device tree builder: structure tokens and a string table.
#[derive(Default)]
struct Fdt {
    structure: Vec<u8>,
    strings: Vec<u8>,
}

impl Fdt {
    fn token(&mut self, token: u32) {
        self.structure.extend_from_slice(&token.to_be_bytes());
    }

    fn pad(&mut self) {
        while self.structure.len() % 4 != 0 {
            self.structure.push(0);
        }
    }

    /// `FDT_BEGIN_NODE` (1) and the NUL-terminated, padded name.
    fn begin(&mut self, name: &str) -> &mut Self {
        self.token(1);
        self.structure.extend_from_slice(name.as_bytes());
        self.structure.push(0);
        self.pad();
        self
    }

    /// `FDT_END_NODE` (2).
    fn end(&mut self) -> &mut Self {
        self.token(2);
        self
    }

    /// `FDT_PROP` (3): value length, name offset, padded value.
    fn prop(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let name_offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.token(3);
        self.structure
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.structure.extend_from_slice(&name_offset.to_be_bytes());
        self.structure.extend_from_slice(value);
        self.pad();
        self
    }

    fn string(&mut self, name: &str, value: &str) -> &mut Self {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.prop(name, &bytes)
    }

    fn cell(&mut self, name: &str, value: u32) -> &mut Self {
        self.prop(name, &value.to_be_bytes())
    }

    /// Header (40 B, version 17): magic, total size, structure and string
    /// offsets, memory reservation map (one empty entry) at 40.
    fn finish(&mut self) -> Vec<u8> {
        self.token(9);
        let reserve = 40;
        let off_struct = reserve + 16;
        let off_strings = off_struct + self.structure.len();
        let total = off_strings + self.strings.len();
        let mut blob = Vec::with_capacity(total);
        for field in [
            0xd00d_feed,
            total as u32,
            off_struct as u32,
            off_strings as u32,
            reserve as u32,
            17,
            16,
            0,
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            blob.extend_from_slice(&field.to_be_bytes());
        }
        blob.extend_from_slice(&[0; 16]);
        blob.extend_from_slice(&self.structure);
        blob.extend_from_slice(&self.strings);
        blob
    }
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

#[test]
fn uimage_code_byte_order_comes_from_the_payload_not_the_header() {
    let little = classify(&uimage(
        ARCH_ARM,
        TYPE_KERNEL,
        COMP_NONE,
        &elf(1, false, EM_ARM),
    ));
    assert_eq!(little.format.format, FileFormat::UImage);
    assert_eq!(
        (little.primary.isa, little.primary.endianness),
        (Isa::Arm, Endianness::Little)
    );
    let big = classify(&uimage(
        ARCH_ARM,
        TYPE_KERNEL,
        COMP_NONE,
        &elf(1, true, EM_ARM),
    ));
    assert_eq!(
        (big.primary.isa, big.primary.endianness),
        (Isa::Arm, Endianness::Big)
    );
    assert_eq!(big.slices.len(), 1);
    assert_eq!((big.slices[0].offset, big.slices[0].size), (64, 64));
}

#[test]
fn uimage_gzip_payload_is_decoded_and_classified() {
    let kernel = elf(1, true, EM_MIPS);
    let image = uimage(ARCH_MIPS, TYPE_KERNEL, COMP_GZIP, &gzip(&kernel));
    let p = classify(&image);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::Mips, Endianness::Big)
    );
    let slice = &p.slices[0];
    assert_eq!(slice.offset, 64);
    let decoded = slice.decoded.as_ref().expect("decoded range");
    assert_eq!(
        (decoded.transform.as_str(), decoded.size),
        ("gzip", kernel.len() as u64)
    );
    assert_eq!(slice.isa, Isa::Mips);
}

#[test]
fn uimage_without_payload_evidence_reports_byte_order_as_undetermined() {
    let p = classify(&uimage(ARCH_ARM, TYPE_KERNEL, COMP_NONE, &[0u8; 64]));
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::BiEndian);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("could not be determined from the code")));
}

#[test]
fn uimage_multi_file_images_are_split() {
    // Sizes table (64, 6, 0), then a kernel and a six-byte RAM disk padded to 8.
    let kernel = elf(1, false, EM_ARM);
    let mut payload = Vec::new();
    for size in [64u32, 6, 0] {
        payload.extend_from_slice(&size.to_be_bytes());
    }
    payload.extend_from_slice(&kernel);
    payload.extend_from_slice(b"initrd\0\0");
    let p = classify(&uimage(ARCH_ARM, TYPE_MULTI, COMP_NONE, &payload));
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[0].offset, 64 + 12);
    assert_eq!(p.slices[1].offset, 64 + 12 + 64);
    assert_eq!(p.primary.endianness, Endianness::Little);
}

#[test]
fn uimage_ramdisk_is_not_classified_as_code() {
    let p = classify(&uimage(ARCH_ARM, TYPE_RAMDISK, COMP_NONE, &[0x5a; 128]));
    assert!(
        p.slices.is_empty(),
        "raw RAM disk bytes are not a recognized format"
    );
    assert!(p.candidates.is_empty());
}

#[test]
fn uimage_corruption_is_a_format_error() {
    let image = uimage(
        ARCH_ARM,
        TYPE_KERNEL,
        COMP_GZIP,
        &gzip(&elf(1, false, EM_ARM)),
    );
    for end in 64..image.len() {
        assert!(
            detect_payload(&image[..end], &ClassifierOptions::new()).is_err(),
            "prefix {end}"
        );
    }
    let mut bad = image.clone();
    bad[70] ^= 1;
    assert!(detect_payload(&bad, &ClassifierOptions::new()).is_err());
}

#[test]
fn bzimage_xlf_kernel_64_means_x86_64() {
    let p = classify(&bzimage(0x020f, 0x0001, &gzip(&elf(2, false, EM_X86_64))));
    assert_eq!(p.format.format, FileFormat::ZImage);
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::X86_64, 64));
    assert_eq!(p.slices[0].isa, Isa::X86_64);
    assert_eq!(p.slices[0].offset, 0x500);
    let header_only = classify(&bzimage(0x020f, 0x0001, &[]));
    assert_eq!(header_only.primary.isa, Isa::X86_64);
    let x86 = classify(&bzimage(0x020f, 0, &[]));
    assert_eq!((x86.primary.isa, x86.primary.bitwidth), (Isa::X86, 32));
}

/// PE header of an EFI stub in the unused boot sector: `MZ` at 0,
/// `e_lfanew` 0x40 at 0x3C, `PE\0\0` and the COFF machine at 0x40.
fn add_efi_stub(data: &mut [u8], machine: u16) {
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
}

#[test]
fn efi_stub_kernels_are_kernel_images_unless_only_headers_are_present() {
    let mut image = bzimage(0x020f, 0x0001, &gzip(&elf(2, false, EM_X86_64)));
    add_efi_stub(&mut image, 0x8664);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::ZImage);
    assert_eq!(p.slices[0].isa, Isa::X86_64);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message == "EFI stub: the image is also a PE/COFF executable (MZ header at 0)"));
    // The setup header names a payload beyond the file: the PE parser
    // takes the headers.
    let headers = &image[..0x480];
    assert_ne!(classify(headers).format.format, FileFormat::ZImage);
}

#[test]
fn bzimage_before_protocol_2_12_takes_the_isa_from_the_payload() {
    let p = classify(&bzimage(0x020a, 0, &gzip(&elf(2, false, EM_X86_64))));
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("Primary ISA selected from Kernel")));
}

#[test]
fn arm_zimage_is_recognized_with_its_endianness_flag() {
    let little = classify(&zimage(0x0403_0201, &gzip(&elf(1, false, EM_ARM))));
    assert_eq!(little.format.format, FileFormat::ZImage);
    assert_eq!(
        (little.primary.isa, little.primary.endianness),
        (Isa::Arm, Endianness::Little)
    );
    assert_eq!(little.slices.len(), 1);
    assert_eq!(little.slices[0].offset, 0x100);

    let big = classify(&zimage(0x0102_0304, &gzip(&elf(1, true, EM_ARM))));
    assert_eq!(
        (big.primary.isa, big.primary.endianness),
        (Isa::Arm, Endianness::Big)
    );

    let unknown_flag = zimage(0x1122_3344, &[]);
    assert!(!matches!(
        zrax::formats::detect_format(&unknown_flag),
        zrax::formats::DetectedFormat::Kernel { .. }
    ));
}

#[test]
fn arm_zimage_extension_table_bounds_the_payload_search() {
    // Table marker at 0x34 and table offset at 0x38; one KLSZ tag pointing
    // at the decompressed-size word after the compressed kernel.
    let kernel = elf(1, false, EM_ARM);
    let compressed = gzip(&kernel);
    let mut image = zimage(0x0403_0201, &compressed);
    image[0x34..0x38].copy_from_slice(&0x4545_4545u32.to_le_bytes());
    image[0x38..0x3c].copy_from_slice(&0x40u32.to_le_bytes());
    let size_word = image.len() as u32;
    for (i, word) in [6u32, 0x5a53_4c4b, size_word, 0, 0, 0, 0]
        .iter()
        .enumerate()
    {
        image[0x40 + 4 * i..0x44 + 4 * i].copy_from_slice(&word.to_le_bytes());
    }
    image.extend_from_slice(&(kernel.len() as u32).to_le_bytes());
    let end = image.len() as u32;
    image[0x2c..0x30].copy_from_slice(&end.to_le_bytes());
    let p = classify(&image);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("matches the zImage size word")));
}

#[test]
fn bzimage_image_crc_is_reported() {
    let mut image = bzimage(0x020f, 1, &gzip(&elf(2, false, EM_X86_64)));
    let crc = zrax::formats::checksum::crc32_update(!0, &image);
    image.extend_from_slice(&crc.to_le_bytes());
    // The appended CRC moved the end of the file; payload_length still fits.
    let p = classify(&image);
    assert!(p.notes.iter().any(|n| n.message == "Image CRC-32 verified"));
    let last = image.len() - 1;
    image[last] ^= 1;
    let p = classify(&image);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("Image CRC-32 does not match")));
}

/// A 64-byte AArch64 `Image` header: magic `ARM\x64` at 0x38.
fn arm64_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x100];
    image[0x38..0x3c].copy_from_slice(b"ARM\x64");
    image
}

/// EFI zboot: `MZ\0\0`, `zimg`, payload offset and size, the compression
/// name at 0x18, `LINUX_PE_MAGIC` at 0x38, PE header offset 0x40 (signature
/// and machine), then the compressed `Image` at 0x80.
fn zboot(machine: u16, compression: &str, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x80];
    data[0..8].copy_from_slice(b"MZ\0\0zimg");
    data[8..12].copy_from_slice(&0x80u32.to_le_bytes());
    data[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    data[0x18..0x18 + compression.len()].copy_from_slice(compression.as_bytes());
    data[0x38..0x3c].copy_from_slice(&0x8182_23cdu32.to_le_bytes());
    data[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"PE\0\0");
    data[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

#[test]
fn efi_zboot_images_decode_their_kernel_and_take_the_pe_machine() {
    let p = classify(&zboot(0xaa64, "gzip", &gzip(&arm64_image())));
    assert_eq!(p.format.format, FileFormat::ZImage);
    assert_eq!(p.format.variant_name.as_deref(), Some("LinuxZboot"));
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::AArch64, 64));
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].offset, 0x80);
    assert_eq!(p.slices[0].decoded.as_ref().unwrap().transform, "gzip");
    assert_eq!(p.slices[0].isa, Isa::AArch64);

    let unknown = classify(&zboot(0xaa64, "bogus", &[0; 32]));
    assert!(unknown
        .notes
        .iter()
        .any(|n| n.message.contains("not one zboot defines")));
    assert_eq!(unknown.primary.isa, Isa::AArch64);
    let truncated = zboot(0xaa64, "gzip", &gzip(&arm64_image()));
    assert!(detect_payload(&truncated[..truncated.len() - 1], &ClassifierOptions::new()).is_err());
}

#[test]
fn arm_zimage_size_beyond_the_file_is_an_error() {
    let mut image = zimage(0x0403_0201, &[0; 16]);
    image.truncate(0x80);
    assert!(detect_payload(&image, &ClassifierOptions::new()).is_err());
}

/// FIT with an inline gzip AArch64 kernel, an external FDT at
/// `data-offset` 0, an FPGA bitstream, and a default configuration.
fn fit() -> (Vec<u8>, Vec<u8>) {
    let kernel = gzip(&elf(2, false, EM_AARCH64));
    let external = elf(1, false, EM_ARM);
    let mut fdt = Fdt::default();
    fdt.begin("").string("description", "test FIT");
    fdt.begin("images");
    fdt.begin("kernel-1")
        .string("type", "kernel")
        .string("arch", "arm64")
        .string("compression", "gzip")
        .cell("load", 0x8008_0000)
        .cell("entry", 0x8008_0000)
        .prop("data", &kernel);
    fdt.begin("hash-1").string("algo", "sha256").end();
    fdt.end();
    fdt.begin("loadable-1")
        .string("type", "firmware")
        .string("arch", "arm")
        .cell("data-offset", 0)
        .cell("data-size", external.len() as u32)
        .end();
    fdt.begin("fpga-1")
        .string("type", "fpga")
        .prop("data", &[0xaa, 0x99, 0x55, 0x66])
        .end();
    fdt.end();
    fdt.begin("configurations").string("default", "conf-1");
    fdt.begin("conf-1").string("kernel", "kernel-1").end();
    fdt.end();
    fdt.end();
    let mut blob = fdt.finish();
    while blob.len() % 4 != 0 {
        blob.push(0);
    }
    blob.extend_from_slice(&external);
    (blob, external)
}

#[test]
fn fit_images_become_slices_with_their_own_architectures() {
    let (blob, _) = fit();
    let p = classify(&blob);
    assert_eq!(p.format.format, FileFormat::Fit);
    assert_eq!(
        (p.primary.isa, p.primary.endianness),
        (Isa::AArch64, Endianness::Little)
    );
    let labels: Vec<_> = p.slices.iter().map(|s| s.label.clone().unwrap()).collect();
    assert_eq!(
        labels,
        [
            "kernel-1 (kernel)",
            "loadable-1 (firmware)",
            "fpga-1 (fpga)"
        ]
    );
    assert_eq!(p.slices[0].isa, Isa::AArch64);
    assert_eq!(p.slices[0].decoded.as_ref().unwrap().transform, "gzip");
    assert_eq!(p.slices[1].isa, Isa::Arm);
    assert!(matches!(p.slices[2].isa, Isa::Unknown(_)));
    assert!(p.notes.iter().any(|n| n.message.contains("not verified")));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("fpga-1 (fpga): opaque")));
}

#[test]
fn fit_external_data_beyond_the_file_is_an_error() {
    let (blob, external) = fit();
    let truncated = &blob[..blob.len() - external.len() + 1];
    assert!(detect_payload(truncated, &ClassifierOptions::new()).is_err());
}

#[test]
fn device_trees_are_data_and_never_go_to_the_code_model() {
    let mut fdt = Fdt::default();
    fdt.begin("")
        .string("model", "Test board")
        .string("compatible", "vendor,board");
    fdt.begin("cpus").end();
    fdt.end();
    let blob = fdt.finish();
    let p = classify(&blob);
    assert_eq!(p.format.format, FileFormat::Dtb);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.candidates.is_empty());
    assert!(p.notes.iter().any(|n| n.message == "Model: Test board"));
}

#[test]
fn kernel_images_survive_mutation_and_truncation_without_panicking() {
    let (fit_blob, _) = fit();
    let images = [
        uimage(
            ARCH_ARM,
            TYPE_KERNEL,
            COMP_GZIP,
            &gzip(&elf(1, false, EM_ARM)),
        ),
        bzimage(0x020f, 1, &gzip(&elf(2, false, EM_X86_64))),
        zimage(0x0403_0201, &gzip(&elf(1, false, EM_ARM))),
        fit_blob,
    ];
    for image in &images {
        for end in (0..image.len()).step_by(7) {
            let _ = detect_payload(&image[..end], &ClassifierOptions::new());
        }
        for i in 0..image.len() {
            let mut mutated = image.clone();
            mutated[i] ^= 0xff;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}
