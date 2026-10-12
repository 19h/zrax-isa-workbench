//! SoC boot images: Xilinx Zynq-7000 and ZynqMP `BOOT.BIN` (boot header,
//! image header table, partition headers, destination CPUs, encryption and
//! family ambiguity), NXP i.MX HAB images at their documented IVT offsets
//! and AHAB containers, and NXP SB2.x and SB3.1 secure binaries, with
//! checksum, truncation and mutation sweeps.

use sha2::{Digest, Sha256, Sha384};
use zrax::formats::socboot::{self, Layout};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::types::{ContainedArch, MetadataKey};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, Endianness,
    FileFormat, Isa,
};

const AARCH64_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transforms/aarch64.text.bin"
);
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/arm32_arm-unknown-linux-gnueabi_O0_int_crc32.bin"
);

/// The first `len` bytes of a committed code fixture; `len` is a multiple
/// of 64 so that word lengths and 64-byte alignment hold.
fn code(path: &str, len: usize) -> Vec<u8> {
    let mut bytes = std::fs::read(path).expect("fixture is committed");
    assert!(bytes.len() >= len, "{path} holds {len} B");
    bytes.truncate(len);
    bytes
}

/// Deterministic filler (xorshift32) for encrypted or data bytes.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
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

fn align(value: usize, to: usize) -> usize {
    match value % to {
        0 => value,
        remainder => value + to - remainder,
    }
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label}: {:?}", payload.slices))
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

/// The displayed value of custom metadata entry `key`.
fn metadata(payload: &DetectionPayload, key: &str) -> String {
    payload
        .metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.into()))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
        .to_string()
}

// ---------------------------------------------------------------------------
// Xilinx BOOT.BIN
// ---------------------------------------------------------------------------

const WIDTH_DETECTION: u32 = 0xaa99_5566;
const XNLX: &[u8; 4] = b"XNLX";
const IHT_VERSION_1_2: u32 = 0x0102_0000;
const IHT_OFFSET: usize = 0x8c0;
const IMAGE_HEADERS: usize = 0x900;
const IMAGE_HEADER_SIZE: usize = 0x40;
const PARTITION_HEADER_SIZE: usize = 0x40;
const KEY_EFUSE_RED: u32 = 0xa5c3_c5a3;
/// Bootgen's Zynq-7000 QSPI configuration word at 0x44.
const QSPI_CONFIG_WORD: u32 = 1;
/// ZynqMP boot header CPU select (bits 11:10): A53 single, 64-bit.
const BH_A53_64: u32 = 2 << 10;

/// Partition attributes: ZynqMP destination CPU (11:8), device (6:4),
/// A53 AArch32 state (3), exception level (2:1), TrustZone (0), encryption
/// (7), big-endian (18); Zynq-7000 destination device (7:4).
const CPU_A53_0: u32 = 1 << 8;
const CPU_A53_1: u32 = 2 << 8;
const CPU_R5_0: u32 = 5 << 8;
const CPU_PMU: u32 = 8 << 8;
const DEVICE_PS: u32 = 1 << 4;
const DEVICE_PL: u32 = 2 << 4;
const AARCH32: u32 = 1 << 3;
const EL3: u32 = 3 << 1;
const TRUSTZONE: u32 = 1;
const ENCRYPTED: u32 = 1 << 7;
const BIG_ENDIAN: u32 = 1 << 18;

#[derive(Clone, Copy, PartialEq)]
enum Family {
    Zynq7000,
    ZynqMp,
}

/// One partition of a test boot image.
struct Part {
    name: &'static str,
    attributes: u32,
    load: u64,
    exec: u64,
    data: Vec<u8>,
    /// Original length when the stored data is longer (Zynq-7000 encryption
    /// overhead); `None` when they are equal.
    original_len: Option<usize>,
}

fn part(name: &'static str, attributes: u32, address: u64, data: Vec<u8>) -> Part {
    Part {
        name,
        attributes,
        load: address,
        exec: address,
        data,
        original_len: None,
    }
}

/// A boot image as Bootgen lays it out.
struct BootImage {
    family: Family,
    key_source: u32,
    /// ZynqMP boot header attributes, or the Zynq-7000 QSPI configuration
    /// word.
    word_0x44: u32,
    /// ZynqMP PMU firmware, stored ahead of the FSBL in the first partition.
    pmu: Vec<u8>,
    /// The first partition is the FSBL the boot header locates.
    partitions: Vec<Part>,
    /// Whether the image carries an image header table; without one, only
    /// the first partition's data follows the header at 0x9C0.
    tables: bool,
}

/// `~sum` of little-endian words.
fn word_checksum(bytes: &[u8]) -> u32 {
    !bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .fold(0u32, u32::wrapping_add)
}

/// An image name in zeroed bytes: four characters per word, each word
/// big-endian (character `i` at `(i & !3) + 3 - (i & 3)`); the zero bytes
/// after it hold the NUL.
fn put_name(data: &mut [u8], at: usize, name: &str) {
    for (i, b) in name.bytes().enumerate() {
        data[at + (i & !3) + (3 - (i & 3))] = b;
    }
}

impl BootImage {
    fn header_end(&self) -> usize {
        match self.family {
            Family::Zynq7000 => 0xa0 + 0x800,
            Family::ZynqMp => 0xb8 + 0x800,
        }
    }

    /// Partition header table offset: after the image headers, 64-byte
    /// aligned.
    fn pht(&self) -> usize {
        align(
            IMAGE_HEADERS + IMAGE_HEADER_SIZE * self.partitions.len(),
            64,
        )
    }

    /// File offsets of the partitions' data.
    fn data_offsets(&self) -> Vec<usize> {
        let mut offset = if self.tables {
            align(
                self.pht() + PARTITION_HEADER_SIZE * (self.partitions.len() + 1),
                0x1000,
            )
        } else {
            0x9c0
        };
        let mut offsets = Vec::new();
        for (i, partition) in self.partitions.iter().enumerate() {
            offsets.push(offset);
            let pmu = if i == 0 { self.pmu.len() } else { 0 };
            offset = align(offset + pmu + partition.data.len(), 64);
        }
        offsets
    }

    fn build(&self) -> Vec<u8> {
        let offsets = self.data_offsets();
        let stored = if self.tables {
            self.partitions.len()
        } else {
            1
        };
        let last = stored - 1;
        let pmu = if last == 0 { self.pmu.len() } else { 0 };
        let mut data = vec![0u8; offsets[last] + pmu + self.partitions[last].data.len()];
        self.boot_header(&mut data, offsets[0]);
        if self.tables {
            self.image_header_table(&mut data);
            self.image_headers(&mut data);
            self.partition_headers(&mut data, &offsets);
        }
        for (i, partition) in self.partitions.iter().enumerate() {
            let mut at = offsets[i];
            if i == 0 {
                data[at..at + self.pmu.len()].copy_from_slice(&self.pmu);
                at += self.pmu.len();
            }
            if i < stored {
                data[at..at + partition.data.len()].copy_from_slice(&partition.data);
            }
        }
        data
    }

    /// Boot header: vectors, width detection word, `XNLX`, key source, the
    /// family's FSBL fields, checksum, table offsets, register table with
    /// every address 0xFFFFFFFF.
    fn boot_header(&self, data: &mut [u8], source: usize) {
        let fsbl = &self.partitions[0];
        let vector = match self.family {
            Family::ZynqMp if self.word_0x44 & (3 << 10) == BH_A53_64 => 0x1400_0000,
            _ => 0xeaff_fffe,
        };
        for i in 0..8 {
            put32(data, i * 4, vector);
        }
        put32(data, 0x20, WIDTH_DETECTION);
        data[0x24..0x28].copy_from_slice(XNLX);
        put32(data, 0x28, self.key_source);
        let fsbl_len = fsbl.original_len.unwrap_or(fsbl.data.len()) as u32;
        match self.family {
            Family::Zynq7000 => {
                put32(data, 0x2c, 0x0101_0000);
                put32(data, 0x30, source as u32);
                put32(data, 0x34, fsbl_len);
                put32(data, 0x3c, fsbl.exec as u32);
                put32(data, 0x40, fsbl.data.len() as u32);
            }
            Family::ZynqMp => {
                put32(data, 0x2c, fsbl.exec as u32);
                put32(data, 0x30, source as u32);
                put32(data, 0x34, self.pmu.len() as u32);
                put32(data, 0x38, self.pmu.len() as u32);
                put32(data, 0x3c, fsbl_len);
                put32(data, 0x40, fsbl.data.len() as u32);
            }
        }
        put32(data, 0x44, self.word_0x44);
        let checksum = word_checksum(&data[0x20..0x48]);
        put32(data, 0x48, checksum);
        if self.tables {
            put32(data, 0x98, IHT_OFFSET as u32);
            put32(data, 0x9c, self.pht() as u32);
        }
        let table = self.header_end() - 0x800;
        for pair in 0..256 {
            put32(data, table + pair * 8, 0xffff_ffff);
        }
    }

    /// Image header table: version 1.2, partition count, first partition and
    /// image header word offsets, no header certificate; Zynq-7000 fills the
    /// rest with 0xFF, ZynqMP stores the boot device 0 and a checksum.
    fn image_header_table(&self, data: &mut [u8]) {
        let at = IHT_OFFSET;
        put32(data, at, IHT_VERSION_1_2);
        put32(data, at + 4, self.partitions.len() as u32);
        put32(data, at + 8, (self.pht() / 4) as u32);
        put32(data, at + 0x0c, (IMAGE_HEADERS / 4) as u32);
        match self.family {
            Family::Zynq7000 => data[at + 0x14..at + 0x40].fill(0xff),
            Family::ZynqMp => {
                let checksum = word_checksum(&data[at..at + 0x3c]);
                put32(data, at + 0x3c, checksum);
            }
        }
    }

    /// One image header per partition: next image header and partition
    /// header (word offsets), 0, partition count 1, the name.
    fn image_headers(&self, data: &mut [u8]) {
        for (i, partition) in self.partitions.iter().enumerate() {
            let at = IMAGE_HEADERS + IMAGE_HEADER_SIZE * i;
            data[at..at + IMAGE_HEADER_SIZE].fill(0xff);
            let next = if i + 1 < self.partitions.len() {
                (at + IMAGE_HEADER_SIZE) / 4
            } else {
                0
            };
            put32(data, at, next as u32);
            put32(
                data,
                at + 4,
                ((self.pht() + PARTITION_HEADER_SIZE * i) / 4) as u32,
            );
            put32(data, at + 8, 0);
            put32(data, at + 0x0c, 1);
            let name_end = align(partition.name.len() + 1, 4);
            data[at + 0x10..at + 0x10 + name_end].fill(0);
            put_name(data, at + 0x10, partition.name);
        }
    }

    /// Partition headers in the family's layout, then the null header.
    fn partition_headers(&self, data: &mut [u8], offsets: &[usize]) {
        let pht = self.pht();
        for (i, partition) in self.partitions.iter().enumerate() {
            let at = pht + PARTITION_HEADER_SIZE * i;
            let pmu = if i == 0 { self.pmu.len() } else { 0 };
            let stored = (partition.data.len() + pmu) / 4;
            let original = (partition.original_len.unwrap_or(partition.data.len()) + pmu) / 4;
            put32(data, at, stored as u32);
            put32(data, at + 4, original as u32);
            put32(data, at + 8, stored as u32);
            let image_header = (IMAGE_HEADERS + IMAGE_HEADER_SIZE * i) / 4;
            match self.family {
                Family::Zynq7000 => {
                    put32(data, at + 0x0c, partition.load as u32);
                    put32(data, at + 0x10, partition.exec as u32);
                    put32(data, at + 0x14, (offsets[i] / 4) as u32);
                    put32(data, at + 0x18, partition.attributes);
                    put32(data, at + 0x1c, 1);
                    put32(data, at + 0x24, image_header as u32);
                }
                Family::ZynqMp => {
                    let next = if i + 1 < self.partitions.len() {
                        (at + PARTITION_HEADER_SIZE) / 4
                    } else {
                        0
                    };
                    put32(data, at + 0x0c, next as u32);
                    put64(data, at + 0x10, partition.exec);
                    put64(data, at + 0x18, partition.load);
                    put32(data, at + 0x20, (offsets[i] / 4) as u32);
                    put32(data, at + 0x24, partition.attributes);
                    put32(data, at + 0x28, 1);
                    put32(data, at + 0x30, image_header as u32);
                    put32(data, at + 0x38, i as u32);
                }
            }
            let checksum = word_checksum(&data[at..at + 0x3c]);
            put32(data, at + 0x3c, checksum);
        }
        let null = pht + PARTITION_HEADER_SIZE * self.partitions.len();
        put32(data, null + 0x3c, 0xffff_ffff);
    }
}

/// PMU firmware stand-in: MicroBlaze `or r0, r0, r0` (NOP) and
/// `rtsd r15, 8` words.
fn pmu_firmware() -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..64 {
        let word: u32 = if i % 8 == 7 { 0xb60f_0008 } else { 0x8000_0000 };
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// ZynqMP image: PMU firmware and an A53-0 FSBL in the first partition,
/// an EL3 secure A53 image, an R5 image, an A53-1 AArch32 image and a PL
/// bitstream.
fn zynqmp_image() -> BootImage {
    BootImage {
        family: Family::ZynqMp,
        key_source: 0,
        word_0x44: BH_A53_64,
        pmu: pmu_firmware(),
        partitions: vec![
            part(
                "fsbl.elf",
                CPU_A53_0 | DEVICE_PS | EL3,
                0xfffc_0000,
                code(AARCH64_CODE, 1024),
            ),
            part(
                "bl31.elf",
                CPU_A53_0 | DEVICE_PS | EL3 | TRUSTZONE,
                0xfffe_a000,
                code(AARCH64_CODE, 2048),
            ),
            part("r5app.elf", CPU_R5_0 | DEVICE_PS, 0, code(ARM_CODE, 1024)),
            part(
                "app32.elf",
                CPU_A53_1 | DEVICE_PS | AARCH32,
                0x1000_0000,
                code(ARM_CODE, 1536),
            ),
            part("design.bit", DEVICE_PL, 0xffff_ffff, noise(512, 7)),
        ],
        tables: true,
    }
}

/// Zynq-7000 image: FSBL and application for the PS, and a PL bitstream.
fn zynq7000_image() -> BootImage {
    BootImage {
        family: Family::Zynq7000,
        key_source: 0,
        word_0x44: QSPI_CONFIG_WORD,
        pmu: Vec::new(),
        partitions: vec![
            part("fsbl.elf", DEVICE_PS, 0, code(ARM_CODE, 1024)),
            part("design.bit", DEVICE_PL, 0, noise(512, 9)),
            part("u-boot.elf", DEVICE_PS, 0x0400_0000, code(ARM_CODE, 2048)),
        ],
        tables: true,
    }
}

#[test]
fn zynqmp_partitions_take_their_destination_cpu_as_target() {
    let p = classify(&zynqmp_image().build());
    assert_eq!(p.format.format, FileFormat::XilinxBootBin);
    // The boot header names the FSBL CPU: A53 single, 64-bit.
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::AArch64, 64));
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(slice(&p, "PMU firmware").isa, Isa::MicroBlaze);
    assert_eq!(slice(&p, "FSBL").isa, Isa::AArch64);
    assert_eq!(slice(&p, "Partition 1: bl31.elf").isa, Isa::AArch64);
    let r5 = slice(&p, "Partition 2: r5app.elf");
    assert_eq!(
        (r5.isa, r5.bitwidth, r5.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(slice(&p, "Partition 3: app32.elf").isa, Isa::Arm);
    let bitstream = slice(&p, "Partition 4: design.bit");
    assert!(matches!(bitstream.isa, Isa::Unknown(_)));
    // The FSBL partition holds the PMU firmware and the FSBL and is not
    // listed a second time.
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("Partition 0: fsbl.elf")));
    assert!(has_note(
        &p,
        "holds the boot header's images, listed on their own"
    ));
    assert!(has_note(&p, "destination A53-0, AArch64"));
    assert!(has_note(&p, "EL3; TrustZone secure"));
    assert!(has_note(&p, "Partition 4: design.bit"));
    assert!(has_note(&p, "FPGA bitstream"));
    assert!(has_note(
        &p,
        "Boot header selects the FSBL CPU: Cortex-A53 single, AArch64"
    ));
    assert!(has_note(&p, "Partition 4: design.bit: opaque"));
    // Slices keep stored file offsets.
    let image = zynqmp_image();
    let offsets = image.data_offsets();
    assert_eq!(slice(&p, "PMU firmware").offset, offsets[0] as u64);
    let fsbl = slice(&p, "FSBL");
    assert_eq!(fsbl.offset, (offsets[0] + image.pmu.len()) as u64);
    assert_eq!(fsbl.size, 1024);
    assert_eq!(
        slice(&p, "Partition 2: r5app.elf").offset,
        offsets[2] as u64
    );
    assert_eq!(metadata(&p, "zynq_family"), "ZynqMP");
    assert_eq!(metadata(&p, "zynq_partition_count"), "5");
}

#[test]
fn zynqmp_big_endian_r5_partition_leaves_the_code_order_to_the_code() {
    let mut image = zynqmp_image();
    image.partitions[2].attributes |= BIG_ENDIAN;
    let p = classify(&image.build());
    let r5 = slice(&p, "Partition 2: r5app.elf");
    // Little-endian A32 code: the code model supplies the open byte order.
    assert_eq!((r5.isa, r5.endianness), (Isa::Arm, Endianness::Little));
    assert!(has_note(&p, "big-endian"));
}

#[test]
fn zynqmp_pmu_partition_is_microblaze_and_aarch32_boot_cpu_is_arm() {
    let mut image = zynqmp_image();
    image.word_0x44 = 1 << 10;
    image.partitions[3].attributes = CPU_PMU;
    let p = classify(&image.build());
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::Arm, 32));
    assert_eq!(slice(&p, "FSBL").isa, Isa::Arm);
    let pmu = slice(&p, "Partition 3: app32.elf");
    assert_eq!(
        (pmu.isa, pmu.endianness),
        (Isa::MicroBlaze, Endianness::Little)
    );
}

#[test]
fn zynq7000_ps_partitions_are_cortex_a9_and_pl_is_opaque() {
    let p = classify(&zynq7000_image().build());
    assert_eq!(p.format.format, FileFormat::XilinxBootBin);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Zynq-7000/ZynqMP boot image")
    );
    // The boot header names no CPU; the primary ISA comes from the FSBL,
    // which partition 0 sends to the PS.
    assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::Arm, 32));
    let fsbl = slice(&p, "FSBL");
    assert_eq!((fsbl.isa, fsbl.endianness), (Isa::Arm, Endianness::Little));
    assert_eq!(slice(&p, "Partition 2: u-boot.elf").isa, Isa::Arm);
    assert!(matches!(
        slice(&p, "Partition 1: design.bit").isa,
        Isa::Unknown(_)
    ));
    assert!(has_note(&p, "Zynq-7000 boot headers name no CPU"));
    assert!(has_note(&p, "destination PS (Cortex-A9) from partition 0"));
    assert_eq!(metadata(&p, "zynq_family"), "Zynq-7000");
}

#[test]
fn zynq7000_without_qspi_word_is_identified_by_its_table() {
    // A zero word at 0x44 is valid ZynqMP attributes; the unchecksummed,
    // 0xFF-filled image header table still rules ZynqMP out.
    let mut image = zynq7000_image();
    image.word_0x44 = 0;
    let p = classify(&image.build());
    assert_eq!(metadata(&p, "zynq_family"), "Zynq-7000");
}

#[test]
fn header_only_image_valid_as_both_families_is_ambiguous() {
    // U-Boot `mkimage -T zynqmpimage` style: no image header table, no PMU
    // firmware. Both families' readings validate.
    let image = BootImage {
        family: Family::ZynqMp,
        key_source: 0,
        word_0x44: BH_A53_64,
        pmu: Vec::new(),
        partitions: vec![part("fsbl", 0, 0xfffc_0000, code(AARCH64_CODE, 1024))],
        tables: false,
    };
    let p = classify(&image.build());
    assert_eq!(p.format.format, FileFormat::XilinxBootBin);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(p.slices.is_empty());
    assert!(has_note(&p, "validates as both Zynq-7000 and ZynqMP"));
}

#[test]
fn header_only_zynqmp_image_with_pmu_firmware_lists_both_images() {
    // With PMU firmware the Zynq-7000 reading takes the PMU length as the
    // FSBL length and the FSBL total as its stored size: only ZynqMP fits.
    let image = BootImage {
        family: Family::ZynqMp,
        key_source: 0,
        word_0x44: BH_A53_64,
        pmu: pmu_firmware(),
        partitions: vec![part("fsbl", 0, 0xfffc_0000, code(AARCH64_CODE, 128))],
        tables: false,
    };
    let p = classify(&image.build());
    assert_eq!(metadata(&p, "zynq_family"), "ZynqMP");
    assert_eq!(slice(&p, "PMU firmware").offset, 0x9c0);
    assert_eq!(slice(&p, "FSBL").offset, 0x9c0 + 256);
    assert!(has_note(&p, "No image header table"));
}

#[test]
fn encrypted_partitions_are_opaque_but_the_boot_cpu_still_reports() {
    let mut image = zynqmp_image();
    image.key_source = KEY_EFUSE_RED;
    for partition in &mut image.partitions[..2] {
        partition.attributes |= ENCRYPTED;
    }
    let p = classify(&image.build());
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(matches!(slice(&p, "FSBL").isa, Isa::Unknown(_)));
    assert!(matches!(slice(&p, "PMU firmware").isa, Isa::Unknown(_)));
    assert!(matches!(
        slice(&p, "Partition 1: bl31.elf").isa,
        Isa::Unknown(_)
    ));
    assert_eq!(slice(&p, "Partition 2: r5app.elf").isa, Isa::Arm);
    assert!(has_note(&p, "Boot images are encrypted (eFUSE red key)"));
}

#[test]
fn zynq7000_encrypted_partitions_are_stored_longer_than_their_original() {
    let mut image = zynq7000_image();
    image.key_source = KEY_EFUSE_RED;
    image.partitions[2].original_len = Some(2048 - 64);
    let p = classify(&image.build());
    assert!(matches!(
        slice(&p, "Partition 2: u-boot.elf").isa,
        Isa::Unknown(_)
    ));
    assert!(matches!(slice(&p, "FSBL").isa, Isa::Unknown(_)));
}

#[test]
fn partition_certificates_and_checksums_are_reported_not_verified() {
    /// Partition attributes: RSA certificate present (15), checksum type
    /// (14:12): 3 is SHA-3 on ZynqMP, 1 MD5 on Zynq-7000.
    const RSA_CERTIFICATE: u32 = 1 << 15;
    const CHECKSUM_SHA3: u32 = 3 << 12;
    const CHECKSUM_MD5: u32 = 1 << 12;
    let mut image = zynqmp_image();
    image.partitions[1].attributes |= RSA_CERTIFICATE | CHECKSUM_SHA3;
    let p = classify(&image.build());
    assert!(has_note(
        &p,
        "SHA-3 checksum not verified; authentication certificate not verified"
    ));
    // Signed partitions are not transformed: the code is still classified.
    assert_eq!(slice(&p, "Partition 1: bl31.elf").isa, Isa::AArch64);

    let mut image = zynq7000_image();
    image.partitions[2].attributes |= CHECKSUM_MD5;
    let p = classify(&image.build());
    assert!(has_note(&p, "MD5 checksum not verified"));
}

#[test]
fn corrupted_checksums_and_links_are_parse_errors() {
    let image = zynqmp_image().build();
    let parse = |data: &[u8]| socboot::parse_container(data, Layout::XilinxBootBin).map(|_| ());

    let mut header = image.clone();
    header[0x48] ^= 1;
    let e = parse(&header).unwrap_err().to_string();
    assert!(e.contains("Invalid boot header checksum"), "{e}");

    let mut table = image.clone();
    table[IHT_OFFSET + 0x3c] ^= 1;
    let e = parse(&table).unwrap_err().to_string();
    assert!(e.contains("Invalid image header table checksum"), "{e}");

    let pht = zynqmp_image().pht();
    let mut partition = image.clone();
    partition[pht + 0x40 + 0x3c] ^= 1;
    let e = parse(&partition).unwrap_err().to_string();
    assert!(e.contains("Invalid partition header checksum at 0x"), "{e}");

    // A damaged BOOT.BIN is a format error, not a raw ISA guess.
    assert!(detect_payload(&partition, &ClassifierOptions::new()).is_err());

    let mut loops = image.clone();
    let next = (pht / 4) as u32;
    put32(&mut loops, pht + 0x40 + 0x0c, next);
    let checksum = word_checksum(&loops[pht + 0x40..pht + 0x7c]);
    put32(&mut loops, pht + 0x40 + 0x3c, checksum);
    let e = parse(&loops).unwrap_err().to_string();
    assert!(e.contains("Partition header chain loops"), "{e}");
}

#[test]
fn boot_bin_truncations_are_errors() {
    for image in [zynqmp_image().build(), zynq7000_image().build()] {
        for end in 0..image.len() {
            assert!(
                socboot::parse_container(&image[..end], Layout::XilinxBootBin).is_err(),
                "prefix {end}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// NXP i.MX HAB images
// ---------------------------------------------------------------------------

/// Where an i.MX HAB image lives in the test file.
struct HabLayout {
    /// File offset of the IVT.
    ivt_offset: usize,
    /// IVT offset in the boot medium: the image start address is
    /// `self - flash_offset`.
    flash_offset: usize,
    /// IVT self address.
    self_address: u32,
    /// Application offset from the IVT.
    app_offset: usize,
    /// Bytes before the IVT in the file.
    prefix: Vec<u8>,
    csf: CsfLayout,
}

#[derive(Clone, Copy, PartialEq)]
enum CsfLayout {
    None,
    /// A CSF header (tag 0xD4) and 0x100 bytes of commands at the CSF pointer.
    Signed,
    /// The CSF pointer and size are set, the CSF is not in the file yet.
    Reserved,
}

/// U-Boot `imximage` layout: IVT (tag 0xD1, length 0x0020 big-endian,
/// version 0x41, entry, reserved, DCD, boot data, self, CSF, reserved),
/// boot data right after it (start, size, plugin 0), a DCD with one
/// write-data command (0xCC, address and value big-endian), the
/// application at `app_offset`, the image size rounded to 4 KiB, and an
/// optional CSF area after it.
fn hab_image(layout: &HabLayout, app: &[u8]) -> Vec<u8> {
    let start = layout.self_address - layout.flash_offset as u32;
    let entry = layout.self_address + layout.app_offset as u32;
    let body = align(layout.flash_offset + layout.app_offset + app.len(), 0x1000);
    let csf_address = start + body as u32;
    let size = body
        + if layout.csf == CsfLayout::None {
            0
        } else {
            0x2000
        };
    let file_body = body - (layout.flash_offset - layout.ivt_offset);
    let mut data = vec![0u8; file_body];
    data[..layout.prefix.len()].copy_from_slice(&layout.prefix);
    let ivt = layout.ivt_offset;
    data[ivt..ivt + 4].copy_from_slice(&[0xd1, 0x00, 0x20, 0x41]);
    put32(&mut data, ivt + 0x04, entry);
    put32(&mut data, ivt + 0x0c, layout.self_address + 0x2c);
    put32(&mut data, ivt + 0x10, layout.self_address + 0x20);
    put32(&mut data, ivt + 0x14, layout.self_address);
    if layout.csf != CsfLayout::None {
        put32(&mut data, ivt + 0x18, csf_address);
    }
    put32(&mut data, ivt + 0x20, start);
    put32(&mut data, ivt + 0x24, size as u32);
    // DCD: header (16 B), write-data command for one word.
    data[ivt + 0x2c..ivt + 0x30].copy_from_slice(&[0xd2, 0x00, 0x10, 0x41]);
    data[ivt + 0x30..ivt + 0x34].copy_from_slice(&[0xcc, 0x00, 0x0c, 0x04]);
    data[ivt + 0x34..ivt + 0x38].copy_from_slice(&0x020e_0000u32.to_be_bytes());
    data[ivt + 0x38..ivt + 0x3c].copy_from_slice(&0x0000_0001u32.to_be_bytes());
    let app_at = ivt + layout.app_offset;
    data[app_at..app_at + app.len()].copy_from_slice(app);
    if layout.csf == CsfLayout::Signed {
        let mut csf = vec![0u8; 0x100];
        csf[..4].copy_from_slice(&[0xd4, 0x00, 0x10, 0x41]);
        csf[4..].copy_from_slice(&noise(0xfc, 3));
        data.extend_from_slice(&csf);
    }
    data
}

/// `u-boot.imx`: the file starts at the IVT, written 1 KiB into the disk.
fn uboot_imx(csf: CsfLayout) -> HabLayout {
    HabLayout {
        ivt_offset: 0,
        flash_offset: 0x400,
        self_address: 0x877f_f400,
        app_offset: 0xc00,
        prefix: Vec::new(),
        csf,
    }
}

/// An SD card dump: the IVT at 0x400, the image start at file offset 0.
fn sd_dump() -> HabLayout {
    HabLayout {
        ivt_offset: 0x400,
        ..uboot_imx(CsfLayout::None)
    }
}

/// An i.MX RT FlexSPI NOR image: FCB (`FCFB`) at 0, IVT at 0x1000, the
/// application at 0x2000, executed in place.
fn flexspi_nor() -> HabLayout {
    let mut prefix = vec![0xffu8; 0x200];
    prefix[..8].copy_from_slice(&[0x46, 0x43, 0x46, 0x42, 0x00, 0x00, 0x01, 0x56]);
    HabLayout {
        ivt_offset: 0x1000,
        flash_offset: 0x1000,
        self_address: 0x6000_1000,
        app_offset: 0x1000,
        prefix,
        csf: CsfLayout::None,
    }
}

#[test]
fn imx_ivt_images_are_found_at_their_documented_offsets() {
    let app = code(ARM_CODE, 2048);
    for (name, layout) in [
        ("u-boot.imx", uboot_imx(CsfLayout::None)),
        ("SD dump", sd_dump()),
        ("FlexSPI NOR", flexspi_nor()),
    ] {
        let data = hab_image(&layout, &app);
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::ImxImage, "{name}");
        // No IVT field names an ISA: the code model answers from the
        // application bytes.
        assert_eq!(p.primary.isa, Isa::Arm, "{name}");
        assert_eq!(p.primary.source, ClassificationSource::Combined, "{name}");
        assert!(
            has_note(&p, "the IVT names no CPU or instruction set"),
            "{name}"
        );
        // The application bytes start after the IVT (32 B), boot data
        // (12 B) and DCD (16 B) and hold the entry point.
        let application = slice(&p, "Application image");
        assert_eq!(
            application.offset,
            (layout.ivt_offset + 0x3c) as u64,
            "{name}"
        );
        let entry = (layout.ivt_offset + layout.app_offset) as u64;
        assert!(
            (application.offset..application.offset + application.size).contains(&entry),
            "{name}"
        );
        assert!(
            has_note(&p, &format!("(file offset 0x{entry:X})")),
            "{name}"
        );
        assert_eq!(application.isa, Isa::Arm, "{name}");
        assert!(matches!(slice(&p, "DCD").isa, Isa::Unknown(_)), "{name}");
        assert!(has_note(&p, "DCD at 0x"), "{name}");
        assert!(has_note(&p, "No CSF: the image is not signed"), "{name}");
        assert_eq!(
            metadata(&p, "imx_ivt_offset"),
            layout.ivt_offset.to_string(),
            "{name}"
        );
    }
    let p = classify(&hab_image(&flexspi_nor(), &app));
    assert!(has_note(&p, "FlexSPI configuration block (FCFB) at 0x0"));
}

#[test]
fn imx_csf_is_opaque_and_not_verified() {
    let app = code(ARM_CODE, 2048);
    let p = classify(&hab_image(&uboot_imx(CsfLayout::Signed), &app));
    assert!(has_note(&p, "signatures and certificates not verified"));
    let csf = slice(&p, "CSF");
    assert!(matches!(csf.isa, Isa::Unknown(_)));
    assert_eq!(csf.size, 0x100);
    let p = classify(&hab_image(&uboot_imx(CsfLayout::Reserved), &app));
    assert!(has_note(&p, "lies after the end of the file"));
    assert!(has_note(
        &p,
        "Boot data declares 8192 B beyond the end of the file"
    ));
}

#[test]
fn imx_plugin_flag_and_dcd_are_reported() {
    let app = code(ARM_CODE, 2048);
    let mut image = hab_image(&uboot_imx(CsfLayout::None), &app);
    // Boot data plugin word (IVT + 0x20 + 8).
    put32(&mut image, 0x28, 1);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::ImxImage);
    assert!(has_note(&p, "Plugin image"));
    assert!(has_note(
        &p,
        "DCD at 0x2C: 16 B; device configuration commands are not interpreted"
    ));
    // The DCD is configuration data: listed, never analyzed as code.
    assert!(has_note(&p, "DCD: opaque"));
}

#[test]
fn imx_inconsistent_ivts_are_not_recognized() {
    let app = code(ARM_CODE, 2048);
    let image = hab_image(&uboot_imx(CsfLayout::None), &app);
    let is_imx = |data: &[u8]| {
        matches!(
            detect_format(data),
            DetectedFormat::Container { kind } if kind.format() == FileFormat::ImxImage
        )
    };
    assert!(is_imx(&image));
    // Entry outside the image.
    let mut entry = image.clone();
    put32(&mut entry, 0x04, 0x1000_0000);
    assert!(!is_imx(&entry));
    // Entry inside the IVT, boot data or DCD.
    let mut header_entry = image.clone();
    put32(&mut header_entry, 0x04, 0x877f_f410);
    assert!(!is_imx(&header_entry));
    // Self pointer that moves the boot data outside the file.
    let mut self_pointer = image.clone();
    put32(&mut self_pointer, 0x14, 0x9000_0000);
    assert!(!is_imx(&self_pointer));
    // Non-zero reserved word.
    let mut reserved = image.clone();
    put32(&mut reserved, 0x08, 1);
    assert!(!is_imx(&reserved));
    // An IVT at an undocumented offset is not probed.
    let mut shifted = vec![0u8; 0x200];
    shifted.extend_from_slice(&image);
    assert!(!is_imx(&shifted));
    // A DCD with the wrong tag is a parse error of the IVT image.
    let mut dcd = image.clone();
    dcd[0x2c] = 0xd3;
    assert!(!is_imx(&dcd));
}

#[test]
fn imx_truncations_lose_the_image_or_report_the_missing_bytes() {
    let app = code(ARM_CODE, 1024);
    let image = hab_image(&uboot_imx(CsfLayout::None), &app);
    for end in 0..image.len() {
        let parsed = socboot::parse_container(&image[..end], Layout::ImxIvt);
        if end <= 0xc00 {
            // The entry point is no longer in the file.
            assert!(parsed.is_err(), "prefix {end}");
            continue;
        }
        let c = parsed.unwrap_or_else(|e| panic!("prefix {end}: {e}"));
        let missing = format!(
            "Boot data declares {} B beyond the end of the file",
            image.len() - end
        );
        assert!(c.notes.contains(&missing), "prefix {end}: {:?}", c.notes);
        assert!(c
            .children
            .iter()
            .all(|child| child.offset + child.stored_size <= end));
    }
}

// ---------------------------------------------------------------------------
// i.MX AHAB containers
// ---------------------------------------------------------------------------

/// Image types and core IDs used by the AHAB fixtures.
const TYPE_EXECUTABLE: u32 = 3;
const TYPE_DATA: u32 = 4;
const TYPE_ELE: u32 = 6;

/// AHAB image array entry (128 B): offset from the container start, size,
/// load address, entry point, flags (type 3:0, core ID 7:4, hash 10:8 =
/// SHA-384), metadata 0, hash and IV zero.
fn ahab_entry(offset: u32, size: usize, load: u64, image_type: u32, core: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 0x80];
    put32(&mut entry, 0x00, offset);
    put32(&mut entry, 0x04, size as u32);
    put64(&mut entry, 0x08, load);
    put64(&mut entry, 0x10, load);
    put32(&mut entry, 0x18, image_type | (core << 4) | (1 << 8));
    entry
}

/// What the container header's length field covers.
#[derive(Clone, Copy)]
enum ContainerLength {
    /// U-Boot `imx8image`: header, entries and the signature block header.
    SignatureBlockHeader,
    /// SPSDK: header, entries and the whole signature block.
    SignatureBlock,
}

/// AHAB container header: version 0, length little-endian, tag 0x87,
/// flags, software version 1, fuse version 0, image count, signature block
/// offset right after the entries; the entries; the signature block
/// (version 0, length `signature_len` little-endian, tag 0x90, zero
/// offsets and contents).
fn ahab_header(entries: &[Vec<u8>], signature_len: usize, length: ContainerLength) -> Vec<u8> {
    let array_end = 0x10 + 0x80 * entries.len();
    let header_len = match length {
        ContainerLength::SignatureBlockHeader => array_end + 0x10,
        ContainerLength::SignatureBlock => array_end + signature_len,
    };
    let mut header = vec![0u8; array_end + signature_len];
    header[0] = 0;
    put16(&mut header, 1, header_len as u16);
    header[3] = 0x87;
    put16(&mut header, 8, 1);
    header[0x0b] = entries.len() as u8;
    put16(&mut header, 0x0c, array_end as u16);
    for (i, entry) in entries.iter().enumerate() {
        header[0x10 + 0x80 * i..0x90 + 0x80 * i].copy_from_slice(entry);
    }
    put16(&mut header, array_end + 1, signature_len as u16);
    header[array_end + 3] = 0x90;
    header
}

/// `flash.bin` as U-Boot `imx8image` lays it out: an ELE firmware
/// container at 0 (padded to 0x400), the boot container at 0x400 with an
/// A-core image, an M-core image and a data image; images from 0x2000.
/// The second container carries an SPSDK-style length and a 0x40-byte
/// signature block.
fn ahab_flash_bin() -> Vec<u8> {
    let ele = noise(0x200, 11);
    let a_core = code(AARCH64_CODE, 2048);
    let m_core = code(ARM_CODE, 1024);
    let config = noise(0x100, 13);
    let mut data = vec![0u8; 0x2000];
    let first = ahab_header(
        &[ahab_entry(0x2000, ele.len(), 0, TYPE_ELE, 6)],
        0x10,
        ContainerLength::SignatureBlockHeader,
    );
    data[..first.len()].copy_from_slice(&first);
    // Second container images: offsets relative to 0x400.
    let a_at = 0x2200;
    let m_at = a_at + a_core.len();
    let config_at = m_at + m_core.len();
    let second = ahab_header(
        &[
            ahab_entry(
                (a_at - 0x400) as u32,
                a_core.len(),
                0x8000_0000,
                TYPE_EXECUTABLE,
                2,
            ),
            ahab_entry(
                (m_at - 0x400) as u32,
                m_core.len(),
                0x34fe_0000,
                TYPE_EXECUTABLE,
                1,
            ),
            ahab_entry((config_at - 0x400) as u32, config.len(), 0, TYPE_DATA, 2),
        ],
        0x40,
        ContainerLength::SignatureBlock,
    );
    data[0x400..0x400 + second.len()].copy_from_slice(&second);
    data.extend_from_slice(&ele);
    data.extend_from_slice(&a_core);
    data.extend_from_slice(&m_core);
    data.extend_from_slice(&config);
    data
}

#[test]
fn ahab_executables_are_classified_from_their_own_bytes() {
    let data = ahab_flash_bin();
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::ImxImage);
    assert!(p.format.confidence < 1.0, "AHAB detection is structural");
    // Core IDs do not name an ISA; the first executable image's code does.
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.primary.source, ClassificationSource::Combined);
    assert!(has_note(&p, "no ISA is inferred from them"));
    assert!(matches!(
        slice(&p, "Container 0x0 image 0").isa,
        Isa::Unknown(_)
    ));
    let a_core = slice(&p, "Container 0x400 image 0");
    assert_eq!((a_core.isa, a_core.offset), (Isa::AArch64, 0x2200));
    assert_eq!(slice(&p, "Container 0x400 image 1").isa, Isa::Arm);
    assert!(matches!(
        slice(&p, "Container 0x400 image 2").isa,
        Isa::Unknown(_)
    ));
    assert!(has_note(&p, "SHA-384 digest not verified"));
    assert!(has_note(&p, "core ID 2"));
    assert!(has_note(&p, "signature block at 0x590: 64 B, not verified"));
    assert_eq!(metadata(&p, "imx_container_count"), "2");
    assert_eq!(metadata(&p, "imx_image_size"), data.len().to_string());
}

#[test]
fn ahab_needs_a_complete_header_to_be_recognized() {
    let data = ahab_flash_bin();
    assert!(socboot::detect_weak(&data).is_some());
    let mut bad_signature = data.clone();
    bad_signature[0x10 + 0x80 + 3] = 0x91;
    assert!(socboot::detect_weak(&bad_signature).is_none());
    let mut no_signature_block = data.clone();
    put16(&mut no_signature_block, 0x0c, 0);
    assert!(socboot::detect_weak(&no_signature_block).is_none());
    // A length that ends neither after the signature block header nor
    // after the whole block.
    let mut length = data.clone();
    put16(&mut length, 1, 0xa8);
    assert!(socboot::detect_weak(&length).is_none());
    let mut out_of_file = data.clone();
    put32(&mut out_of_file, 0x10 + 4, 0x10_0000);
    assert!(socboot::detect_weak(&out_of_file).is_none());
    let mut no_images = data.clone();
    no_images[0x0b] = 0;
    assert!(socboot::detect_weak(&no_images).is_none());
    // Only empty images: a version and tag byte are not enough evidence.
    let mut empty = data.clone();
    put32(&mut empty, 0x10 + 4, 0);
    assert!(socboot::detect_weak(&empty).is_none());
    assert!(socboot::parse_container(&empty, Layout::ImxAhab).is_ok());
    assert!(socboot::detect_weak(&[0u8; 0x400]).is_none());
    assert!(socboot::detect_weak(&noise(0x400, 5)).is_none());
}

#[test]
fn ahab_truncations_are_errors_or_lose_the_second_container() {
    let data = ahab_flash_bin();
    for end in 0..data.len() {
        let parsed = socboot::parse_container(&data[..end], Layout::ImxAhab);
        if end < 0x2000 + 0x200 {
            // The first container's image is cut.
            assert!(parsed.is_err(), "prefix {end}");
            continue;
        }
        // The second container is listed only when its images are whole.
        let c = parsed.unwrap_or_else(|e| panic!("prefix {end}: {e}"));
        assert!(c.consumed <= end, "prefix {end}");
        assert!(
            c.children
                .iter()
                .all(|child| !child.label.starts_with("Container 0x400")),
            "prefix {end}"
        );
    }
}

// ---------------------------------------------------------------------------
// NXP Secure Binary
// ---------------------------------------------------------------------------

/// SB2 header (0x60 B): nonce, padding, `STMP`, version 2.`minor`, flags,
/// image blocks, first boot tag block, first boot section ID, certificate
/// block offset, header blocks 6, key blob block 8, key blob blocks 5, max
/// section MAC count 1, `sgtl`, timestamp, product version 1.2.3
/// (byte-swapped BCD), component version, build number 7.
fn sb2_header(minor: u8, flags: u16, image_blocks: u32, boot_tag_block: u32) -> Vec<u8> {
    let mut header = noise(0x60, 21);
    header[0x10..0x14].fill(0);
    header[0x14..0x18].copy_from_slice(b"STMP");
    header[0x18] = 2;
    header[0x19] = minor;
    put16(&mut header, 0x1a, flags);
    put32(&mut header, 0x1c, image_blocks);
    put32(&mut header, 0x20, boot_tag_block);
    put32(&mut header, 0x24, 0);
    put32(&mut header, 0x28, if minor == 1 { 0xd0 } else { 0 });
    put16(&mut header, 0x2c, 6);
    put16(&mut header, 0x2e, 8);
    put16(&mut header, 0x30, 5);
    put16(&mut header, 0x32, 1);
    header[0x34..0x38].copy_from_slice(b"sgtl");
    put64(&mut header, 0x38, 0x0002_9b1d_4c00_0000);
    for (i, version) in [1u16, 2, 3].into_iter().enumerate() {
        put16(&mut header, 0x40 + i * 4, version.swap_bytes());
        put16(&mut header, 0x42 + i * 4, 0);
        put16(&mut header, 0x4c + i * 4, version.swap_bytes());
        put16(&mut header, 0x4e + i * 4, 0);
    }
    put32(&mut header, 0x58, 7);
    put32(&mut header, 0x5c, 0);
    header
}

/// SB2.1 certificate block V1 size: 32 B header, one certificate entry
/// (32-bit length and 61 B), the root key hash table (4 × 32 B), padded to
/// 16 B.
const SB21_CERT_BLOCK_LEN: usize = 240;
const SB21_SIGNATURE_LEN: usize = 256;

/// Whether an SB2.1 fixture carries the SHA-256 of its boot sections.
#[derive(Clone, Copy, PartialEq)]
enum SectionHash {
    Absent,
    Present,
}

/// SB2.1 as SPSDK `BootImageV21.export` writes it: header, HMAC (32 B),
/// key blob (80 B), certificate block V1 at 0xD0 (`cert`, version 1.0,
/// header size 32, flags 0, build number 7, image length, one certificate,
/// table length 65: the certificate's 32-bit length and 61 B; then the root
/// key hash table and zero padding to 16 B), with `SectionHash::Present`
/// the SHA-256 of the boot sections (flag 0x8000), an RSA-2048 signature
/// (256 B) and encrypted boot sections (128 B). SPSDK leaves the SHA-256
/// out of the header's image and first boot tag block counts.
fn sb21_with(hash: SectionHash) -> Vec<u8> {
    let hash_len = if hash == SectionHash::Present { 32 } else { 0 };
    let sections_at = 0xd0 + SB21_CERT_BLOCK_LEN + hash_len + SB21_SIGNATURE_LEN;
    let image_len = sections_at + 128;
    let flags = if hash == SectionHash::Present {
        0x8008
    } else {
        0x0008
    };
    let mut data = sb2_header(
        1,
        flags,
        ((image_len - hash_len) / 16) as u32,
        ((sections_at - hash_len) / 16) as u32,
    );
    data.extend_from_slice(&noise(32 + 80, 23));
    let mut cert = vec![0u8; SB21_CERT_BLOCK_LEN];
    cert[..4].copy_from_slice(b"cert");
    put16(&mut cert, 4, 1);
    put32(&mut cert, 8, 32);
    put32(&mut cert, 0x10, 7);
    put32(&mut cert, 0x14, 0x1000);
    put32(&mut cert, 0x18, 1);
    put32(&mut cert, 0x1c, 4 + 61);
    put32(&mut cert, 0x20, 61);
    cert[0x24..0x24 + 61].copy_from_slice(&noise(61, 41));
    cert[0x24 + 61..0x24 + 61 + 128].copy_from_slice(&noise(128, 43));
    data.extend_from_slice(&cert);
    data.extend_from_slice(&noise(hash_len + SB21_SIGNATURE_LEN, 25));
    data.extend_from_slice(&noise(128, 27));
    data
}

fn sb21() -> Vec<u8> {
    sb21_with(SectionHash::Absent)
}

/// SB2.0, unsigned (flags 0x04): header, header HMAC, key blob, boot
/// sections.
fn sb20() -> Vec<u8> {
    let image_len = 0xd0 + 0x80;
    let mut data = sb2_header(0, 0x0004, (image_len / 16) as u32, 0xd0 / 16);
    data.extend_from_slice(&noise(image_len - 0x60, 29));
    data
}

/// SB2.0, signed (flags 0x08) as SPSDK `BootImageV20.export` writes it:
/// header, header HMAC, key blob, encrypted certificate section (0x100 B),
/// boot sections (0x80 B), then a 256-byte signature that the header's
/// image block count leaves out.
fn sb20_signed() -> Vec<u8> {
    let sections_at = 0xd0 + 0x100;
    let image_len = sections_at + 0x80;
    let mut data = sb2_header(
        0,
        0x0008,
        (image_len / 16) as u32,
        (sections_at / 16) as u32,
    );
    data.extend_from_slice(&noise(image_len - 0x60 + 256, 31));
    data
}

/// SB3.1: header (`sbv3`, 1.3, flags, block count, block size, timestamp,
/// firmware version, block 0 length, image type 6, certificate block
/// offset 0x3C + hash, description), hash of block 1, certificate block
/// V2.1 (`chdr`, 64 B), ECDSA signature (64 or 96 B); then `blocks` data
/// blocks (block number, hash of the next block, 256 B payload), hashed
/// backwards.
fn sb31(sha384: bool, blocks: usize) -> Vec<u8> {
    let hash_len = if sha384 { 48 } else { 32 };
    let signature_len = if sha384 { 96 } else { 64 };
    let block_size = 4 + hash_len + 256;
    let cert_offset = 0x3c + hash_len;
    let cert_len = 64;
    let block0_len = cert_offset + cert_len + signature_len;
    let digest = |bytes: &[u8]| -> Vec<u8> {
        if sha384 {
            Sha384::digest(bytes).to_vec()
        } else {
            Sha256::digest(bytes).to_vec()
        }
    };
    let mut chain = Vec::new();
    let mut next_hash = vec![0u8; hash_len];
    for number in (1..=blocks).rev() {
        let mut block = Vec::new();
        block.extend_from_slice(&(number as u32).to_le_bytes());
        block.extend_from_slice(&next_hash);
        block.extend_from_slice(&noise(256, number as u32));
        next_hash = digest(&block);
        chain.insert(0, block);
    }
    let mut data = vec![0u8; block0_len];
    data[..4].copy_from_slice(b"sbv3");
    put16(&mut data, 4, 1);
    put16(&mut data, 6, 3);
    put32(&mut data, 8, 0);
    put32(&mut data, 0x0c, blocks as u32);
    put32(&mut data, 0x10, block_size as u32);
    put64(&mut data, 0x14, 0x1234);
    put32(&mut data, 0x1c, 5);
    put32(&mut data, 0x20, block0_len as u32);
    put32(&mut data, 0x24, 6);
    put32(&mut data, 0x28, cert_offset as u32);
    data[0x2c..0x2c + 9].copy_from_slice(b"Zrax test");
    data[0x3c..0x3c + hash_len].copy_from_slice(&next_hash);
    data[cert_offset..cert_offset + 4].copy_from_slice(b"chdr");
    put16(&mut data, cert_offset + 4, 1);
    put16(&mut data, cert_offset + 6, 2);
    put32(&mut data, cert_offset + 8, cert_len as u32);
    let signature_at = cert_offset + cert_len;
    data[signature_at..].copy_from_slice(&noise(signature_len, 31));
    for block in chain {
        data.extend_from_slice(&block);
    }
    data
}

#[test]
fn sb2_files_are_metadata_only() {
    for (name, data, version) in [
        ("SB2.1", sb21(), "2.1"),
        (
            "SB2.1 with section hash",
            sb21_with(SectionHash::Present),
            "2.1",
        ),
        ("SB2.0", sb20(), "2.0"),
        ("signed SB2.0", sb20_signed(), "2.0"),
    ] {
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::NxpSb, "{name}");
        assert!(matches!(p.primary.isa, Isa::Unknown(_)), "{name}");
        assert!(p.candidates.is_empty(), "{name}");
        assert!(
            p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))),
            "{name}"
        );
        assert!(has_note(&p, "Secure Binary headers name no CPU"), "{name}");
        assert!(has_note(&p, "not decrypted"), "{name}");
        assert!(!has_note(&p, "not described by its headers"), "{name}");
        assert_eq!(metadata(&p, "nxp_sb_version"), version, "{name}");
        assert_eq!(metadata(&p, "nxp_sb_product_version"), "1.2.3", "{name}");
        assert_eq!(
            metadata(&p, "nxp_sb_image_size"),
            data.len().to_string(),
            "{name}"
        );
        assert!(slice(&p, "Boot sections").size > 0, "{name}");
    }
}

#[test]
fn sb21_places_certificate_block_hash_and_signature() {
    let data = sb21();
    let p = classify(&data);
    assert!(has_note(&p, "Certificate block V1 at 0xD0: 240 B"));
    assert!(has_note(&p, "Boot section HMAC not verified"));
    assert_eq!(slice(&p, "Certificate block").offset, 0xd0);
    assert_eq!(slice(&p, "Certificate block").size, 240);
    let signature = slice(&p, "Signature");
    assert_eq!((signature.offset, signature.size), (0x1c0, 256));
    let sections = slice(&p, "Boot sections");
    assert_eq!(sections.offset + sections.size, data.len() as u64);

    // With flag 0x8000 the SHA-256 sits between the certificate block and
    // the signature, and the boot sections start 32 B after the header's
    // first boot tag block.
    let data = sb21_with(SectionHash::Present);
    let p = classify(&data);
    assert!(has_note(
        &p,
        "SHA-256 of the boot sections at 0x1C0; not verified"
    ));
    let signature = slice(&p, "Signature");
    assert_eq!((signature.offset, signature.size), (0x1e0, 256));
    assert_eq!(slice(&p, "Boot sections").offset, 0x2e0);
}

#[test]
fn signed_sb20_lists_the_certificate_section_and_trailing_signature() {
    let data = sb20_signed();
    let p = classify(&data);
    assert!(has_note(
        &p,
        "Signed SB2.0: encrypted certificate section at 0xD0"
    ));
    assert!(has_note(&p, "Header HMAC not verified"));
    let certificate = slice(&p, "Certificate section");
    assert_eq!((certificate.offset, certificate.size), (0xd0, 0x100));
    let signature = slice(&p, "Signature");
    assert_eq!((signature.offset, signature.size), (0x250, 256));
    // The signature follows the image the header counts; without it the
    // file is incomplete.
    let unsigned_length = 0x250;
    assert!(socboot::parse_container(&data[..unsigned_length], Layout::Sb2).is_err());
}

#[test]
fn sb2_layout_errors_are_reported() {
    let parse = |data: &[u8]| {
        socboot::parse_container(data, Layout::Sb2)
            .map(|_| ())
            .unwrap_err()
            .to_string()
    };
    let mut cert = sb21();
    put32(&mut cert, 0x28, 0xe0);
    assert!(parse(&cert).contains("Invalid SB2.1 certificate block offset 0xE0"));
    let mut magic = sb21();
    magic[0xd0] = b'C';
    assert!(parse(&magic).contains("Missing SB2.1 certificate block magic"));
    let mut header_size = sb21();
    put32(&mut header_size, 0xd0 + 8, 36);
    assert!(parse(&header_size).contains("Invalid SB2.1 certificate block header size 36 B"));
    let mut certificate = sb21();
    put32(&mut certificate, 0xd0 + 0x20, 62);
    assert!(parse(&certificate).contains("Invalid SB2.1 certificate 0 length 62 B"));
    let mut count = sb21();
    put32(&mut count, 0xd0 + 0x18, 0);
    assert!(parse(&count).contains("Invalid SB2.1 certificate count 0"));
    // A table that runs into the boot sections.
    let mut table = sb21();
    put32(&mut table, 0xd0 + 0x1c, 0x400);
    assert!(parse(&table).contains("Invalid SB2.1 certificate table"));
    let mut blocks = sb21();
    put16(&mut blocks, 0x2c, 7);
    assert!(parse(&blocks).contains("Invalid SB2 header block count 7"));
    let mut minor = sb21();
    minor[0x19] = 2;
    assert!(parse(&minor).contains("Unsupported SB2 minor version 2"));
    let data = sb21();
    assert!(parse(&data[..data.len() - 16]).contains("Truncated SB2 image"));
    // Without its signature the boot sections would follow the certificate
    // block directly.
    let mut no_signature = sb21();
    put32(
        &mut no_signature,
        0x20,
        ((0xd0 + SB21_CERT_BLOCK_LEN) / 16) as u32,
    );
    assert!(parse(&no_signature).contains("Missing SB2.1 signature"));
    // SB1 shares the magics but has major version 1 and is not recognized.
    let mut sb1 = sb21();
    sb1[0x18] = 1;
    assert!(socboot::detect(&sb1).is_none());
}

#[test]
fn sb31_hash_chain_is_verified() {
    for sha384 in [false, true] {
        let data = sb31(sha384, 3);
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::NxpSb);
        assert!(matches!(p.primary.isa, Isa::Unknown(_)));
        let hash = if sha384 { "SHA-384" } else { "SHA-256" };
        assert!(has_note(&p, &format!("{hash} block hash chain verified")));
        assert!(has_note(&p, "not verified"));
        let blocks = slice(&p, "Data blocks");
        assert_eq!(blocks.offset + blocks.size, data.len() as u64);
        let signature_len = if sha384 { 96 } else { 64 };
        assert_eq!(slice(&p, "Signature").size, signature_len);
        assert_eq!(metadata(&p, "nxp_sb_description"), "Zrax test");
        assert_eq!(metadata(&p, "nxp_sb_image_type"), "normal");
    }
    let empty = sb31(false, 0);
    assert!(socboot::parse_container(&empty, Layout::Sb31).is_ok());
}

#[test]
fn sb31_corruptions_are_parse_errors() {
    let data = sb31(false, 3);
    let block0 = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap()) as usize;
    let parse = |data: &[u8]| {
        socboot::parse_container(data, Layout::Sb31)
            .map(|_| ())
            .unwrap_err()
            .to_string()
    };
    let mut payload = data.clone();
    payload[block0 + 292 + 100] ^= 1;
    assert!(parse(&payload).contains("Invalid SB3.1 block 2"));
    let mut number = data.clone();
    put32(&mut number, block0, 9);
    assert!(parse(&number).contains("Invalid SB3.1 block number 9"));
    let mut size = data.clone();
    put32(&mut size, 0x10, 300);
    assert!(parse(&size).contains("Unsupported SB3.1 block size 300 B"));
    let mut cert = data.clone();
    put32(&mut cert, 0x28, 0x40);
    assert!(parse(&cert).contains("Invalid SB3.1 certificate block offset 0x40"));
    // A certificate block 16 B shorter leaves an 80 B signature.
    let mut signature = data.clone();
    put32(&mut signature, 0x5c + 8, 48);
    assert!(parse(&signature).contains("Invalid SB3.1 signature size 80 B"));
    assert!(parse(&data[..data.len() - 1]).contains("Truncated SB3.1 data blocks"));
    // A damaged secure binary is a format error, not a raw ISA guess.
    assert!(detect_payload(&payload, &ClassifierOptions::new()).is_err());
}

#[test]
fn secure_binary_truncations_are_errors() {
    for (data, layout) in [
        (sb21(), Layout::Sb2),
        (sb21_with(SectionHash::Present), Layout::Sb2),
        (sb20(), Layout::Sb2),
        (sb31(false, 2), Layout::Sb31),
        (sb31(true, 1), Layout::Sb31),
    ] {
        for end in 0..data.len() {
            assert!(
                socboot::parse_container(&data[..end], layout).is_err(),
                "prefix {end}"
            );
        }
    }
    // A signed SB2.0 signature has no length field: prefixes that keep part
    // of it still parse, every shorter one fails.
    let data = sb20_signed();
    for end in 0..=0x250 {
        assert!(
            socboot::parse_container(&data[..end], Layout::Sb2).is_err(),
            "prefix {end}"
        );
    }
}

// ---------------------------------------------------------------------------
// Mutation sweeps
// ---------------------------------------------------------------------------

/// Every byte set to 0x00 and 0xFF and bit-flipped: detection and parsing
/// never panic. Every seventh mutation also goes through the whole
/// classifier, children included.
#[test]
fn byte_mutations_never_panic() {
    let small_zynqmp = BootImage {
        partitions: vec![
            part(
                "fsbl.elf",
                CPU_A53_0 | DEVICE_PS,
                0xfffc_0000,
                code(AARCH64_CODE, 128),
            ),
            part("r5.elf", CPU_R5_0, 0, code(ARM_CODE, 64)),
            part("pl.bit", DEVICE_PL, 0, noise(64, 1)),
        ],
        pmu: pmu_firmware()[..64].to_vec(),
        ..zynqmp_image()
    };
    let small_zynq = BootImage {
        partitions: vec![
            part("fsbl.elf", DEVICE_PS, 0, code(ARM_CODE, 128)),
            part("pl.bit", DEVICE_PL, 0, noise(64, 2)),
        ],
        ..zynq7000_image()
    };
    let fixtures = [
        small_zynqmp.build(),
        small_zynq.build(),
        hab_image(&uboot_imx(CsfLayout::Signed), &code(ARM_CODE, 256)),
        hab_image(&flexspi_nor(), &code(ARM_CODE, 256)),
        ahab_flash_bin(),
        sb21(),
        sb21_with(SectionHash::Present),
        sb20(),
        sb20_signed(),
        sb31(false, 2),
        sb31(true, 1),
    ];
    let options = ClassifierOptions::new();
    for fixture in &fixtures {
        let mut count = 0usize;
        for i in 0..fixture.len() {
            for mutation in [0x00u8, 0xff, fixture[i] ^ 0x10] {
                let mut mutated = fixture.clone();
                mutated[i] = mutation;
                if let DetectedFormat::Container { kind } = detect_format(&mutated) {
                    let _ = zrax::formats::container::parse(&mutated, kind);
                }
                for layout in [
                    Layout::XilinxBootBin,
                    Layout::ImxIvt,
                    Layout::ImxAhab,
                    Layout::Sb2,
                    Layout::Sb31,
                ] {
                    let _ = socboot::parse_container(&mutated, layout);
                }
                count += 1;
                if count % 7 == 0 {
                    let _ = detect_payload(&mutated, &options);
                }
            }
        }
    }
}
