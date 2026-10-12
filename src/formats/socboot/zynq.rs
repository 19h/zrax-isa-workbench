//! Xilinx Zynq-7000 and `Zynq UltraScale+ MPSoC` (`ZynqMP`) `BOOT.BIN`.
//!
//! Layout (Bootgen `d93c3fa6` `zynq/include/bootheader-zynq.h`,
//! `zynqmp/include/bootheader-zynqmp.h`, `zynqmp/src/bootheader-zynqmp.cpp`
//! and the image and partition header structures in `zynq/include` and
//! `zynqmp/include`; UG1283 "Zynq-7000 `SoC` Boot Header", "Image Header
//! Table", "Image Header", "Partition Header", "Partition Attribute Bits"
//! and their `Zynq UltraScale+ MPSoC` counterparts; U-Boot `5e3b01c8`
//! `tools/zynqimage.c`, `tools/zynqmpimage.[ch]`):
//!
//! - All words are 32-bit little-endian. The boot header is shared in
//!   shape up to 0x48: vectors, width detection word `0xAA995566` at 0x20,
//!   `XNLX` at 0x24, key source at 0x28, checksum `~sum(words 0x20..0x44)`
//!   at 0x48. The image header table byte offset is at 0x98 and the
//!   partition header table byte offset at 0x9C. The fields between 0x2C
//!   and 0x44 differ by family, and the register initialization table
//!   starts at 0xA0 (Zynq-7000) or 0xB8 (`ZynqMP`).
//! - Offsets in the image header table, image headers and partition headers
//!   are word offsets from the start of the file, and partition lengths are
//!   in words. They are converted to bytes with checked arithmetic.
//! - The boot header locates the images the boot ROM loads itself: on
//!   `ZynqMP` the PMU firmware at the source offset followed by the FSBL
//!   (Bootgen appends the authentication certificate to the "FSBL + PMU
//!   partition"; U-Boot `zynqmpimage_pmufw` stores the PMU firmware right
//!   after the header and before the FSBL), on Zynq-7000 the FSBL alone.
//! - `ZynqMP` boot header attributes name the FSBL CPU (bits 11:10). `ZynqMP`
//!   partition headers carry 64-bit execution and load addresses, a `next`
//!   link and an attribute word whose destination CPU field (bits 11:8)
//!   names the core (A53-0..3, R5-0, R5-1, R5 lockstep, PMU) and whose bit 3
//!   selects the A53 execution state. Zynq-7000 partition headers name only
//!   a destination device (PS, PL). The Zynq-7000 PS is a Cortex-A9
//!   `MPCore` (a device fact; UG585 was not read here), so only partitions
//!   the format sends to the PS are given the 32-bit Arm target.
//!
//! Both families share the signature and checksum, so the family is decided
//! by validating the whole image under each layout. Bootgen's Zynq-7000 QSPI
//! configuration word (1 at 0x44) sets a bit the `ZynqMP` attribute word never
//! uses, its image header table carries no checksum, and `ZynqMP` partition
//! headers link to their image header at another offset than Zynq-7000
//! ones. An image without an image header table may validate as both and is
//! then reported as ambiguous.

use super::*;
use crate::formats::container::is_recognized;

/// Width detection word at 0x20 and header signature `XNLX` at 0x24
/// (Bootgen `bootheader.h` `WIDTH_DETECTION`, `HEADER_ID_WORD`).
const WIDTH_DETECTION: u32 = 0xaa99_5566;
const HEADER_SIGNATURE: [u8; 4] = *b"XNLX";
const WIDTH_DETECTION_OFFSET: usize = 0x20;
const HEADER_SIGNATURE_OFFSET: usize = 0x24;

/// Boot header fields at the same place in both families.
const KEY_SOURCE: usize = 0x28;
const SOURCE_OFFSET: usize = 0x30;
const HEADER_CHECKSUM: usize = 0x48;
const IMAGE_HEADER_TABLE_OFFSET: usize = 0x98;
const PARTITION_HEADER_TABLE_OFFSET: usize = 0x9c;

/// Zynq-7000 boot header fields (Bootgen `ZynqBootHeaderStructure`).
const ZYNQ_HEADER_VERSION: usize = 0x2c;
const ZYNQ_FSBL_LENGTH: usize = 0x34;
const ZYNQ_FSBL_EXEC: usize = 0x3c;
const ZYNQ_TOTAL_FSBL_LENGTH: usize = 0x40;
const ZYNQ_REGISTER_TABLE: usize = 0xa0;

/// `ZynqMP` boot header fields (Bootgen `ZynqMpBootHeaderStructure`).
const ZYNQMP_FSBL_EXEC: usize = 0x2c;
const ZYNQMP_PMU_LENGTH: usize = 0x34;
const ZYNQMP_TOTAL_PMU_LENGTH: usize = 0x38;
const ZYNQMP_FSBL_LENGTH: usize = 0x3c;
const ZYNQMP_TOTAL_FSBL_LENGTH: usize = 0x40;
const ZYNQMP_ATTRIBUTES: usize = 0x44;
const ZYNQMP_REGISTER_TABLE: usize = 0xb8;

/// Register initialization table: 256 (address, value) pairs; the boot ROM
/// stops at address `0xFFFFFFFF`.
const REGISTER_PAIRS: usize = 256;
const REGISTER_PAIR_SIZE: usize = 8;
const REGISTER_TABLE_SIZE: usize = REGISTER_PAIRS * REGISTER_PAIR_SIZE;
const REGISTER_UNUSED: u32 = 0xffff_ffff;

/// `ZynqMP` PUF helper data after the register table when boot header
/// attribute bits 7:6 are 3 (Bootgen `PUF_DATA_LENGTH`).
const PUF_HELPER_DATA_SIZE: usize = 1544;

/// UG1283 limits the original PMU firmware length to 128 KiB.
const MAX_PMU_FIRMWARE: u32 = 128 << 10;

/// `ZynqMP` boot header attribute fields (UG1283 "Boot Header Attribute
/// Bits"): CPU select at 11:10, hashing select at 9:8, PUF helper data
/// location at 7:6.
const BH_CPU_SELECT_SHIFT: u32 = 10;
const BH_HASH_SELECT_SHIFT: u32 = 8;
const BH_PUF_HD_SHIFT: u32 = 6;
const TWO_BIT_MASK: u32 = 0x3;
const PUF_HD_IN_BOOT_HEADER: u32 = 3;
const HASH_SELECT_SHA3: u32 = 3;

/// CPU select values (UG1283; Bootgen `Core`, U-Boot `HEADER_CPU_SELECT_*`).
const BOOT_CPU_R5_SINGLE: u32 = 0;
const BOOT_CPU_A53_AARCH32: u32 = 1;
const BOOT_CPU_A53_AARCH64: u32 = 2;

/// Bits UG1283 reserves that Bootgen never writes either: 31:18 and 1:0.
/// Bootgen writes its PUF mode at 17:16 and authentication options at 13:12
/// and 5:2. This mask is our reading of both sources.
const BH_UNUSED_BITS: u32 = 0xfffc_0003;

/// Image header table (0x40 bytes).
const IHT_SIZE: usize = 0x40;
const IHT_VERSION: usize = 0x00;
const IHT_PARTITION_COUNT: usize = 0x04;
const IHT_FIRST_PARTITION: usize = 0x08;
const IHT_FIRST_IMAGE: usize = 0x0c;
const IHT_AUTH_CERTIFICATE: usize = 0x10;
const IHT_BOOT_DEVICE: usize = 0x14;
const IHT_CHECKSUM: usize = 0x3c;

/// Image header table version 1.1 defines the fields up to 0x0C; 1.2 adds
/// the header authentication certificate at 0x10 (UG1283).
const IHT_VERSION_1_1: u32 = 0x0101_0000;
const IHT_VERSION_1_2: u32 = 0x0102_0000;

/// `ZynqMP` secondary boot devices (UG1283 image header table, 0x14).
const BOOT_DEVICES: [&str; 12] = [
    "same as primary",
    "QSPI32",
    "QSPI24",
    "NAND",
    "SD0",
    "SD1",
    "SD-LS",
    "MMC",
    "USB",
    "Ethernet",
    "PCIe",
    "SATA",
];

/// Image header: next image header and first partition header (word
/// offsets), two count words, then the name.
const IMAGE_NEXT: usize = 0x00;
const IMAGE_FIRST_PARTITION: usize = 0x04;
const IMAGE_NAME: usize = 0x10;

/// Bootgen's readers fail on image names longer than 256 bytes.
const MAX_IMAGE_NAME: usize = 256;

/// Partition headers are 0x40 bytes with `~sum(words 0x00..0x38)` at 0x3C;
/// the table ends with a header that is zero except for its checksum.
const PARTITION_HEADER_SIZE: usize = 0x40;
const PARTITION_CHECKSUM: usize = 0x3c;
const PH_ENCRYPTED_LENGTH: usize = 0x00;
const PH_UNENCRYPTED_LENGTH: usize = 0x04;
const PH_TOTAL_LENGTH: usize = 0x08;

/// Zynq-7000 partition header fields (UG1283 "Zynq-7000 `SoC` Partition
/// Header").
const ZYNQ_PH_LOAD: usize = 0x0c;
const ZYNQ_PH_EXEC: usize = 0x10;
const ZYNQ_PH_DATA: usize = 0x14;
const ZYNQ_PH_ATTRIBUTES: usize = 0x18;
const ZYNQ_PH_IMAGE_HEADER: usize = 0x24;

/// `ZynqMP` partition header fields (Bootgen
/// `ZynqMpPartitionHeaderTableStructure`).
const ZYNQMP_PH_NEXT: usize = 0x0c;
const ZYNQMP_PH_EXEC: usize = 0x10;
const ZYNQMP_PH_LOAD: usize = 0x18;
const ZYNQMP_PH_DATA: usize = 0x20;
const ZYNQMP_PH_ATTRIBUTES: usize = 0x24;
const ZYNQMP_PH_IMAGE_HEADER: usize = 0x30;

/// Bootgen's reader requires fewer than 0xFF partition headers; the same
/// bound limits the image header chain.
const MAX_PARTITIONS: usize = 0xfe;

/// Partition attribute fields both families define at the same place:
/// RSA certificate present (15), checksum type (14:12), owner (17:16).
const PA_RSA_CERTIFICATE: u32 = 1 << 15;
const PA_CHECKSUM_SHIFT: u32 = 12;
const PA_CHECKSUM_MASK: u32 = 0x7;
const PA_OWNER_SHIFT: u32 = 16;

/// Zynq-7000 destination device, bits 7:4: 0 none, 1 PS, 2 PL, 3 INT.
const ZYNQ_PA_DEVICE_SHIFT: u32 = 4;
const ZYNQ_PA_DEVICE_MASK: u32 = 0xf;
const ZYNQ_DEVICES: [&str; 4] = ["none", "PS", "PL", "INT"];

/// `ZynqMP` partition attributes (UG1283; Bootgen and U-Boot also define
/// destination devices 3 PMU and 4 XIP).
const ZYNQMP_PA_TRUSTZONE: u32 = 1 << 0;
const ZYNQMP_PA_EL_SHIFT: u32 = 1;
const ZYNQMP_PA_AARCH32: u32 = 1 << 3;
const ZYNQMP_PA_DEVICE_SHIFT: u32 = 4;
const ZYNQMP_PA_DEVICE_MASK: u32 = 0x7;
const ZYNQMP_PA_ENCRYPTED: u32 = 1 << 7;
const ZYNQMP_PA_CPU_SHIFT: u32 = 8;
const ZYNQMP_PA_CPU_MASK: u32 = 0xf;
const ZYNQMP_PA_BIG_ENDIAN: u32 = 1 << 18;
const ZYNQMP_PA_EARLY_HANDOFF: u32 = 1 << 19;
const ZYNQMP_DEVICES: [&str; 5] = ["none", "PS", "PL", "PMU", "XIP"];

/// Destination device 1 is the processing system.
const DEVICE_PS: u32 = 1;
/// Destination device 2 is the programmable logic: an FPGA bitstream.
const DEVICE_PL: u32 = 2;

/// `ZynqMP` destination CPUs (partition attribute bits 11:8).
const CPU_NONE: u32 = 0;
const CPU_A53_0: u32 = 1;
const CPU_A53_3: u32 = 4;
const CPU_R5_0: u32 = 5;
const CPU_R5_LOCKSTEP: u32 = 7;
const CPU_PMU: u32 = 8;
const ZYNQMP_CPUS: [&str; 9] = [
    "none",
    "A53-0",
    "A53-1",
    "A53-2",
    "A53-3",
    "R5-0",
    "R5-1",
    "R5 lockstep",
    "PMU",
];

/// Partition checksum types (UG1283): Zynq-7000 defines 0 none and 1 MD5;
/// `ZynqMP` defines 0 none and 3 SHA-3, and U-Boot adds 1 MD5 and 2 SHA-2.
const ZYNQ_CHECKSUMS: [&str; 2] = ["none", "MD5"];
const ZYNQMP_CHECKSUMS: [&str; 4] = ["none", "MD5", "SHA-2", "SHA-3"];

/// Owners: 0 FSBL, 1 U-Boot.
const OWNERS: [&str; 2] = ["FSBL", "U-Boot"];

/// The Zynq-7000 PS cores (Cortex-A9), A53 cores in `AArch32` state and
/// little-endian R5 partitions run little-endian instructions: ARMv7-A and
/// ARMv8-A big-endian modes are BE8, which swaps data only.
const ARM_LITTLE: Target = Target::new(Isa::Arm, 32, Endianness::Little);

/// A 64-bit Arm core in `AArch64` state; A64 instructions are little-endian.
const AARCH64: Target = Target::new(Isa::AArch64, 64, Endianness::Little);

/// A Cortex-R5 core whose instruction byte order the format leaves open:
/// the R5 boot CPU select, and R5 partitions with the big-endian attribute
/// (our reading: Cortex-R cores can be configured for big-endian
/// instructions, so the attribute alone does not fix the code order).
const CORTEX_R5: Target = Target::without_byte_order(Isa::Arm, 32);

/// The `ZynqMP` platform management unit is a little-endian `MicroBlaze`
/// core. UG1085 was not read here; Xilinx `embeddedsw`
/// `lib/sw_apps/zynqmp_pmufw/data/zynqmp_pmufw.tcl` accepts only the "PMU
/// Microblaze processor (`psu_pmu`)" and `src/Makefile` builds with
/// `-mlittle-endian -mcpu=v9.2` (master branch, read on 2026-10-13).
const PMU_MICROBLAZE: Target = Target::new(Isa::MicroBlaze, 32, Endianness::Little);

/// Key source 0: the boot images are not encrypted.
const KEY_SOURCE_NONE: u32 = 0;

/// Encryption key sources at 0x28 (Bootgen `bootheader.h`; UG1283).
/// Zynq-7000 defines only the first three.
struct KeySource {
    value: u32,
    name: &'static str,
    zynq7000: bool,
}

const fn key(value: u32, name: &'static str, zynq7000: bool) -> KeySource {
    KeySource {
        value,
        name,
        zynq7000,
    }
}

const KEY_SOURCES: [KeySource; 8] = [
    key(KEY_SOURCE_NONE, "none", true),
    key(0xa5c3_c5a3, "eFUSE red key", true),
    key(0x3a5c_3c5a, "BBRAM red key", true),
    key(0xa5c3_c5a5, "eFUSE black key", false),
    key(0xa35c_7c53, "boot header black key", false),
    key(0xa5c3_c5a7, "eFUSE obfuscated key", false),
    key(0xa35c_7ca5, "boot header obfuscated key", false),
    key(0xa3a5_c3c5, "boot header user key", false),
];

/// The two layouts that share the `BOOT.BIN` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Zynq7000,
    ZynqMp,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Zynq7000 => "Zynq-7000",
            Self::ZynqMp => "ZynqMP",
        }
    }

    fn variant(self) -> &'static str {
        match self {
            Self::Zynq7000 => "Zynq-7000 boot image",
            Self::ZynqMp => "ZynqMP boot image",
        }
    }

    fn register_table(self) -> usize {
        match self {
            Self::Zynq7000 => ZYNQ_REGISTER_TABLE,
            Self::ZynqMp => ZYNQMP_REGISTER_TABLE,
        }
    }

    fn checksums(self) -> &'static [&'static str] {
        match self {
            Self::Zynq7000 => &ZYNQ_CHECKSUMS,
            Self::ZynqMp => &ZYNQMP_CHECKSUMS,
        }
    }
}

/// An image the boot ROM loads from boot header fields.
struct Region {
    /// File offset.
    offset: usize,
    /// Original image size in bytes.
    size: usize,
    /// Stored size in bytes (with encryption overhead, certificate and
    /// padding).
    stored_size: usize,
}

impl Region {
    /// Whether the region shares bytes with a partition's data.
    fn overlaps(&self, partition: &Partition) -> bool {
        let partition_end = partition.data_offset.saturating_add(partition.total_size);
        let region_end = self.offset.saturating_add(self.stored_size);
        self.offset < partition_end && partition.data_offset < region_end
    }
}

/// Boot header fields this parser uses.
struct BootHeader {
    key_source: &'static KeySource,
    /// FSBL execution address.
    fsbl_entry: u32,
    /// PMU firmware loaded ahead of the FSBL (`ZynqMP`).
    pmu_firmware: Option<Region>,
    /// FSBL; `None` for execute-in-place images.
    fsbl: Option<Region>,
    /// `ZynqMP` boot header attributes; 0 for Zynq-7000.
    attributes: u32,
    /// Zynq-7000 header version word.
    header_version: Option<u32>,
    /// Byte offset of the image header table; 0 when there is none.
    image_header_table: usize,
    /// Byte offset of the partition header table; 0 when not recorded.
    partition_header_table: usize,
    /// Register initialization pairs before the terminator.
    register_writes: usize,
    /// End of the boot header, register table and PUF helper data.
    end: usize,
}

impl BootHeader {
    fn is_encrypted(&self) -> bool {
        self.key_source.value != KEY_SOURCE_NONE
    }
}

/// The FSBL CPU a `ZynqMP` boot header selects.
struct BootCpu {
    name: &'static str,
    target: Target,
}

/// Image header table fields, with word offsets converted to bytes.
struct ImageHeaderTable {
    version: u32,
    partition_count: usize,
    first_partition: usize,
    first_image: usize,
    /// Header authentication certificate (version 1.2); 0 when absent.
    auth_certificate: usize,
    /// `ZynqMP` secondary boot device.
    boot_device: Option<u32>,
}

/// An image name and the end of the word holding its terminator.
struct ImageName {
    text: String,
    end: usize,
}

/// One image header of the linked list.
struct ImageHeader {
    /// File offset of the header.
    offset: usize,
    /// File offset of its first partition header.
    first_partition: usize,
    /// End of the name and its terminator word.
    end: usize,
    name: String,
}

/// One partition header with sizes and offsets in bytes.
struct Partition {
    /// File offset of the header.
    header_offset: usize,
    /// Stored data size (ciphertext size when encrypted).
    encrypted_size: usize,
    /// Original data size.
    unencrypted_size: usize,
    /// Data, authentication certificate and padding.
    total_size: usize,
    load_address: u64,
    exec_address: u64,
    /// File offset of the data.
    data_offset: usize,
    attributes: u32,
    /// File offset of the image header the partition belongs to.
    image_header: usize,
    /// File offset of the next partition header (`ZynqMP`); 0 for the last.
    next: usize,
}

/// Partition headers in table order.
struct PartitionHeaders {
    partitions: Vec<Partition>,
    /// End of the last header read, the null header included.
    end: usize,
}

/// The validated image header table, image headers and partitions.
struct Tables {
    table: ImageHeaderTable,
    images: Vec<ImageHeader>,
    partitions: Vec<Partition>,
    /// End of the last table structure read (including a null header).
    end: usize,
}

/// What a partition's attributes say it is loaded for.
struct Destination {
    /// Display text (`A53-0, AArch64`, `PL`).
    description: String,
    /// Architecture the destination names.
    target: Option<Target>,
    /// Programmable-logic bitstream, never code.
    bitstream: bool,
}

/// Width detection word and `XNLX` signature.
pub(super) fn has_signature(data: &[u8]) -> bool {
    le_u32(data, WIDTH_DETECTION_OFFSET).is_ok_and(|w| w == WIDTH_DETECTION)
        && array::<4>(data, HEADER_SIGNATURE_OFFSET).is_ok_and(|s| s == HEADER_SIGNATURE)
}

/// `~sum` of little-endian words with 32-bit wraparound (Bootgen
/// `ComputeWordChecksum`).
fn word_checksum(bytes: &[u8]) -> u32 {
    !bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_le_bytes(
            word.try_into().expect("chunk has exactly 4 bytes"),
        ))
    })
}

/// A word count or word offset in bytes.
fn bytes_from_words(words: u32) -> Result<usize> {
    to_usize(u64::from(words) * 4, "word offset")
}

/// Fail unless `len` bytes of `what` are present at `offset`.
fn declared_range<'a>(data: &'a [u8], what: &str, offset: usize, len: usize) -> Result<&'a [u8]> {
    slice(data, offset, len).map_err(|_| {
        error(format!(
            "Truncated {what}: 0x{offset:X} + {len} B exceeds the {} B file",
            data.len()
        ))
    })
}

/// Fail when a table structure would overlap the boot header.
fn expect_after_header(what: &str, offset: usize, header_end: usize) -> Result<()> {
    if offset < header_end {
        return Err(error(format!(
            "Invalid {what} offset 0x{offset:X}: inside the boot header (0x{header_end:X} B)"
        )));
    }
    Ok(())
}

fn verify_header_checksum(data: &[u8]) -> Result<()> {
    let words = slice(
        data,
        WIDTH_DETECTION_OFFSET,
        HEADER_CHECKSUM - WIDTH_DETECTION_OFFSET,
    )?;
    let stored = le_u32(data, HEADER_CHECKSUM)?;
    let computed = word_checksum(words);
    if stored != computed {
        return Err(error(format!(
            "Invalid boot header checksum 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(())
}

/// Register initialization pairs before the first unused address.
fn register_writes(data: &[u8], table: usize) -> Result<usize> {
    let table = declared_range(
        data,
        "register initialization table",
        table,
        REGISTER_TABLE_SIZE,
    )?;
    Ok(table
        .chunks_exact(REGISTER_PAIR_SIZE)
        .take_while(|pair| pair[..4] != REGISTER_UNUSED.to_le_bytes())
        .count())
}

/// A boot-header image at `offset`; `None` when its original size is 0.
fn region(
    data: &[u8],
    what: &str,
    offset: usize,
    size: u32,
    stored_size: u32,
    header_end: usize,
) -> Result<Option<Region>> {
    if size == 0 {
        return Ok(None);
    }
    if stored_size < size {
        return Err(error(format!(
            "Invalid {what} length: {size} B original, {stored_size} B stored"
        )));
    }
    expect_after_header(what, offset, header_end)?;
    let stored_size = stored_size as usize;
    declared_range(data, what, offset, stored_size)?;
    Ok(Some(Region {
        offset,
        size: size as usize,
        stored_size,
    }))
}

/// Boot header: shared fields, then the family's FSBL (and PMU firmware)
/// fields, register table and PUF helper data.
fn boot_header(data: &[u8], family: Family) -> Result<BootHeader> {
    let key_value = le_u32(data, KEY_SOURCE)?;
    let key_source = KEY_SOURCES
        .iter()
        .find(|k| k.value == key_value && (k.zynq7000 || family == Family::ZynqMp))
        .ok_or_else(|| {
            error(format!(
                "Unknown {} key source 0x{key_value:08X}",
                family.name()
            ))
        })?;
    let source = le_u32(data, SOURCE_OFFSET)? as usize;
    let register_table = family.register_table();
    let mut header = BootHeader {
        key_source,
        fsbl_entry: 0,
        pmu_firmware: None,
        fsbl: None,
        attributes: 0,
        header_version: None,
        image_header_table: le_u32(data, IMAGE_HEADER_TABLE_OFFSET)? as usize,
        partition_header_table: le_u32(data, PARTITION_HEADER_TABLE_OFFSET)? as usize,
        register_writes: register_writes(data, register_table)?,
        end: register_table + REGISTER_TABLE_SIZE,
    };
    match family {
        Family::Zynq7000 => {
            header.header_version = Some(le_u32(data, ZYNQ_HEADER_VERSION)?);
            header.fsbl_entry = le_u32(data, ZYNQ_FSBL_EXEC)?;
            header.fsbl = region(
                data,
                "FSBL",
                source,
                le_u32(data, ZYNQ_FSBL_LENGTH)?,
                le_u32(data, ZYNQ_TOTAL_FSBL_LENGTH)?,
                header.end,
            )?;
        }
        Family::ZynqMp => {
            header.fsbl_entry = le_u32(data, ZYNQMP_FSBL_EXEC)?;
            header.attributes = le_u32(data, ZYNQMP_ATTRIBUTES)?;
            if header.attributes & BH_UNUSED_BITS != 0 {
                return Err(error(format!(
                    "Invalid ZynqMP boot header attributes 0x{:08X}: reserved bits set",
                    header.attributes
                )));
            }
            if (header.attributes >> BH_PUF_HD_SHIFT) & TWO_BIT_MASK == PUF_HD_IN_BOOT_HEADER {
                declared_range(data, "PUF helper data", header.end, PUF_HELPER_DATA_SIZE)?;
                header.end += PUF_HELPER_DATA_SIZE;
            }
            let pmu_size = le_u32(data, ZYNQMP_PMU_LENGTH)?;
            if pmu_size > MAX_PMU_FIRMWARE {
                return Err(error(format!(
                    "Invalid PMU firmware length {pmu_size} B: at most 128 KiB"
                )));
            }
            header.pmu_firmware = region(
                data,
                "PMU firmware",
                source,
                pmu_size,
                le_u32(data, ZYNQMP_TOTAL_PMU_LENGTH)?,
                header.end,
            )?;
            // The FSBL follows the PMU firmware when the ROM loads both.
            let fsbl_offset = match &header.pmu_firmware {
                Some(pmu) => end_of(source, pmu.stored_size)?,
                None => source,
            };
            header.fsbl = region(
                data,
                "FSBL",
                fsbl_offset,
                le_u32(data, ZYNQMP_FSBL_LENGTH)?,
                le_u32(data, ZYNQMP_TOTAL_FSBL_LENGTH)?,
                header.end,
            )?;
        }
    }
    Ok(header)
}

/// The boot CPU a `ZynqMP` boot header selects for the FSBL (attribute bits
/// 11:10: 0 R5 single, 1 A53 32-bit, 2 A53 64-bit, 3 R5 dual).
fn boot_cpu(attributes: u32) -> BootCpu {
    match (attributes >> BH_CPU_SELECT_SHIFT) & TWO_BIT_MASK {
        BOOT_CPU_R5_SINGLE => BootCpu {
            name: "Cortex-R5 single",
            target: CORTEX_R5,
        },
        BOOT_CPU_A53_AARCH32 => BootCpu {
            name: "Cortex-A53 single, AArch32",
            target: ARM_LITTLE,
        },
        BOOT_CPU_A53_AARCH64 => BootCpu {
            name: "Cortex-A53 single, AArch64",
            target: AARCH64,
        },
        // The field has two bits; 3 is R5 dual.
        _ => BootCpu {
            name: "Cortex-R5 dual (lockstep)",
            target: CORTEX_R5,
        },
    }
}

/// Image header table: version, partition count, first partition and image
/// header word offsets, header certificate (1.2), `ZynqMP` boot device and
/// checksum.
fn image_header_table(
    data: &[u8],
    header: &BootHeader,
    family: Family,
) -> Result<ImageHeaderTable> {
    let offset = header.image_header_table;
    expect_after_header("image header table", offset, header.end)?;
    let table = declared_range(data, "image header table", offset, IHT_SIZE)?;
    let version = le_u32(table, IHT_VERSION)?;
    if version != IHT_VERSION_1_1 && version != IHT_VERSION_1_2 {
        return Err(error(format!(
            "Unsupported image header table version 0x{version:08X}"
        )));
    }
    // Only Bootgen's ZynqMP writer fills the checksum; the Zynq-7000 table
    // is 0xFF-filled after its last field.
    if family == Family::ZynqMp {
        let stored = le_u32(table, IHT_CHECKSUM)?;
        let computed = word_checksum(&table[..IHT_CHECKSUM]);
        if stored != computed {
            return Err(error(format!(
                "Invalid image header table checksum 0x{stored:08X}, computed 0x{computed:08X}"
            )));
        }
    }
    let partition_count = le_u32(table, IHT_PARTITION_COUNT)? as usize;
    if partition_count == 0 || partition_count > MAX_PARTITIONS {
        return Err(error(format!(
            "Invalid image header table partition count {partition_count}"
        )));
    }
    let auth_certificate = if version == IHT_VERSION_1_2 {
        bytes_from_words(le_u32(table, IHT_AUTH_CERTIFICATE)?)?
    } else {
        0
    };
    let boot_device = match family {
        Family::ZynqMp => Some(le_u32(table, IHT_BOOT_DEVICE)?),
        Family::Zynq7000 => None,
    };
    Ok(ImageHeaderTable {
        version,
        partition_count,
        first_partition: bytes_from_words(le_u32(table, IHT_FIRST_PARTITION)?)?,
        first_image: bytes_from_words(le_u32(table, IHT_FIRST_IMAGE)?)?,
        auth_certificate,
        boot_device,
    })
}

/// An image name: ASCII stored four characters per word, each word
/// big-endian (Bootgen `SetImageName`), ending at the first NUL.
fn image_name(data: &[u8], at: usize) -> Result<ImageName> {
    let mut text = Vec::new();
    for group in 0..MAX_IMAGE_NAME / 4 {
        let word_offset = end_of(at, group * 4)?;
        let word: [u8; 4] = array(data, word_offset)?;
        for &b in word.iter().rev() {
            if b == 0 {
                return Ok(ImageName {
                    text: String::from_utf8_lossy(&text).into_owned(),
                    end: word_offset + 4,
                });
            }
            text.push(if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'?'
            });
        }
    }
    Err(error(format!(
        "Invalid image name at 0x{at:X}: no terminator within {MAX_IMAGE_NAME} B"
    )))
}

/// The image header list from `first`, bounded and checked for loops.
fn image_headers(data: &[u8], first: usize, header_end: usize) -> Result<Vec<ImageHeader>> {
    let mut images: Vec<ImageHeader> = Vec::new();
    let mut offset = first;
    loop {
        if images.iter().any(|image| image.offset == offset) {
            return Err(error(format!("Image header chain loops at 0x{offset:X}")));
        }
        if images.len() == MAX_PARTITIONS {
            return Err(error(format!(
                "Image header chain exceeds {MAX_PARTITIONS} headers"
            )));
        }
        expect_after_header("image header", offset, header_end)?;
        let header = declared_range(data, "image header", offset, IMAGE_NAME)?;
        let next = bytes_from_words(le_u32(header, IMAGE_NEXT)?)?;
        let first_partition = bytes_from_words(le_u32(header, IMAGE_FIRST_PARTITION)?)?;
        let name = image_name(data, offset + IMAGE_NAME)?;
        images.push(ImageHeader {
            offset,
            first_partition,
            end: name.end,
            name: name.text,
        });
        if next == 0 {
            return Ok(images);
        }
        offset = next;
    }
}

/// The partition header at `offset`, or `None` for the null header that
/// ends the table. Every header carries a checksum, the null one included.
fn partition_header(
    data: &[u8],
    offset: usize,
    family: Family,
    header_end: usize,
) -> Result<Option<Partition>> {
    expect_after_header("partition header", offset, header_end)?;
    let header = declared_range(data, "partition header", offset, PARTITION_HEADER_SIZE)?;
    let stored = le_u32(header, PARTITION_CHECKSUM)?;
    let computed = word_checksum(&header[..PARTITION_CHECKSUM]);
    if stored != computed {
        return Err(error(format!(
            "Invalid partition header checksum at 0x{offset:X}: 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    if header[..PARTITION_CHECKSUM].iter().all(|&b| b == 0) {
        return Ok(None);
    }
    let words = |at: usize| -> Result<usize> { bytes_from_words(le_u32(header, at)?) };
    let mut partition = Partition {
        header_offset: offset,
        encrypted_size: words(PH_ENCRYPTED_LENGTH)?,
        unencrypted_size: words(PH_UNENCRYPTED_LENGTH)?,
        total_size: words(PH_TOTAL_LENGTH)?,
        load_address: 0,
        exec_address: 0,
        data_offset: 0,
        attributes: 0,
        image_header: 0,
        next: 0,
    };
    match family {
        Family::Zynq7000 => {
            partition.load_address = u64::from(le_u32(header, ZYNQ_PH_LOAD)?);
            partition.exec_address = u64::from(le_u32(header, ZYNQ_PH_EXEC)?);
            partition.data_offset = words(ZYNQ_PH_DATA)?;
            partition.attributes = le_u32(header, ZYNQ_PH_ATTRIBUTES)?;
            partition.image_header = words(ZYNQ_PH_IMAGE_HEADER)?;
        }
        Family::ZynqMp => {
            partition.next = words(ZYNQMP_PH_NEXT)?;
            partition.exec_address = le_u64(header, ZYNQMP_PH_EXEC)?;
            partition.load_address = le_u64(header, ZYNQMP_PH_LOAD)?;
            partition.data_offset = words(ZYNQMP_PH_DATA)?;
            partition.attributes = le_u32(header, ZYNQMP_PH_ATTRIBUTES)?;
            partition.image_header = words(ZYNQMP_PH_IMAGE_HEADER)?;
        }
    }
    Ok(Some(partition))
}

/// Zynq-7000 partition headers: a contiguous array ending with the null
/// header.
fn zynq_partitions(data: &[u8], first: usize, header_end: usize) -> Result<PartitionHeaders> {
    let mut partitions = Vec::new();
    let mut offset = first;
    while let Some(partition) = partition_header(data, offset, Family::Zynq7000, header_end)? {
        if partitions.len() == MAX_PARTITIONS {
            return Err(error(format!(
                "Missing null partition header after {MAX_PARTITIONS} partition headers"
            )));
        }
        partitions.push(partition);
        offset = end_of(offset, PARTITION_HEADER_SIZE)?;
    }
    Ok(PartitionHeaders {
        partitions,
        end: offset + PARTITION_HEADER_SIZE,
    })
}

/// `ZynqMP` partition headers: the `next` chain from the first header, as
/// U-Boot reads it.
fn zynqmp_partitions(data: &[u8], first: usize, header_end: usize) -> Result<PartitionHeaders> {
    let mut partitions: Vec<Partition> = Vec::new();
    let mut offset = first;
    let mut end = first;
    loop {
        if partitions.iter().any(|p| p.header_offset == offset) {
            return Err(error(format!(
                "Partition header chain loops at 0x{offset:X}"
            )));
        }
        if partitions.len() == MAX_PARTITIONS {
            return Err(error(format!(
                "Partition header chain exceeds {MAX_PARTITIONS} headers"
            )));
        }
        let Some(partition) = partition_header(data, offset, Family::ZynqMp, header_end)? else {
            return Err(error(format!(
                "Invalid partition header chain: null header at 0x{offset:X}"
            )));
        };
        end = end.max(offset + PARTITION_HEADER_SIZE);
        let next = partition.next;
        partitions.push(partition);
        if next == 0 {
            return Ok(PartitionHeaders { partitions, end });
        }
        offset = next;
    }
}

/// Check one partition against the file and the image header list.
fn validate_partition(
    data: &[u8],
    index: usize,
    partition: &Partition,
    images: &[ImageHeader],
    header_end: usize,
) -> Result<()> {
    if partition.total_size > 0 {
        expect_after_header(
            &format!("partition {index} data"),
            partition.data_offset,
            header_end,
        )?;
    }
    declared_range(
        data,
        &format!("partition {index} data"),
        partition.data_offset,
        partition.total_size,
    )?;
    if partition.encrypted_size > partition.total_size
        || partition.unencrypted_size > partition.total_size
    {
        return Err(error(format!(
            "Invalid partition {index} lengths: {} B encrypted, {} B unencrypted, {} B total",
            partition.encrypted_size, partition.unencrypted_size, partition.total_size
        )));
    }
    if !images
        .iter()
        .any(|image| image.offset == partition.image_header)
    {
        return Err(error(format!(
            "Invalid partition {index}: image header 0x{:X} is not in the image header chain",
            partition.image_header
        )));
    }
    Ok(())
}

/// The image header table, image header chain and partition headers, each
/// partition linked to a listed image header and each image header to a
/// listed partition.
fn tables(data: &[u8], header: &BootHeader, family: Family) -> Result<Tables> {
    let table = image_header_table(data, header, family)?;
    if header.partition_header_table != 0 && header.partition_header_table != table.first_partition
    {
        return Err(error(format!(
            "Invalid partition header table offset 0x{:X}: the image header table names 0x{:X}",
            header.partition_header_table, table.first_partition
        )));
    }
    let images = image_headers(data, table.first_image, header.end)?;
    let headers = match family {
        Family::Zynq7000 => zynq_partitions(data, table.first_partition, header.end)?,
        Family::ZynqMp => zynqmp_partitions(data, table.first_partition, header.end)?,
    };
    let partitions = headers.partitions;
    let mut end = headers.end.max(header.image_header_table + IHT_SIZE);
    for image in &images {
        if !partitions
            .iter()
            .any(|p| p.header_offset == image.first_partition)
        {
            return Err(error(format!(
                "Invalid image header at 0x{:X}: partition header 0x{:X} is not in the table",
                image.offset, image.first_partition
            )));
        }
        end = end.max(image.end);
    }
    for (index, partition) in partitions.iter().enumerate() {
        validate_partition(data, index, partition, &images, header.end)?;
        end = end.max(partition.data_offset + partition.total_size);
    }
    Ok(Tables {
        table,
        images,
        partitions,
        end,
    })
}

fn zynq_destination(attributes: u32) -> Destination {
    let device = (attributes >> ZYNQ_PA_DEVICE_SHIFT) & ZYNQ_PA_DEVICE_MASK;
    let name = ZYNQ_DEVICES
        .get(device as usize)
        .map_or_else(|| format!("reserved device {device}"), |d| (*d).to_string());
    match device {
        // The Zynq-7000 processing system's CPUs are Cortex-A9 (ARMv7-A).
        DEVICE_PS => Destination {
            description: "PS (Cortex-A9)".into(),
            target: Some(ARM_LITTLE),
            bitstream: false,
        },
        DEVICE_PL => Destination {
            description: name,
            target: None,
            bitstream: true,
        },
        _ => Destination {
            description: name,
            target: None,
            bitstream: false,
        },
    }
}

fn zynqmp_destination(attributes: u32) -> Destination {
    let device = (attributes >> ZYNQMP_PA_DEVICE_SHIFT) & ZYNQMP_PA_DEVICE_MASK;
    let cpu = (attributes >> ZYNQMP_PA_CPU_SHIFT) & ZYNQMP_PA_CPU_MASK;
    let big_endian = attributes & ZYNQMP_PA_BIG_ENDIAN != 0;
    if device == DEVICE_PL {
        return Destination {
            description: "PL".into(),
            target: None,
            bitstream: true,
        };
    }
    let cpu_name = ZYNQMP_CPUS
        .get(cpu as usize)
        .map_or_else(|| format!("reserved CPU {cpu}"), |c| (*c).to_string());
    let (state, target) = match cpu {
        CPU_A53_0..=CPU_A53_3 if attributes & ZYNQMP_PA_AARCH32 != 0 => {
            (", AArch32", Some(ARM_LITTLE))
        }
        CPU_A53_0..=CPU_A53_3 => (", AArch64", Some(AARCH64)),
        // A big-endian partition leaves the R5 instruction order open.
        CPU_R5_0..=CPU_R5_LOCKSTEP if big_endian => ("", Some(CORTEX_R5)),
        CPU_R5_0..=CPU_R5_LOCKSTEP => ("", Some(ARM_LITTLE)),
        CPU_PMU => ("", Some(PMU_MICROBLAZE)),
        _ => ("", None),
    };
    let description = if cpu == CPU_NONE {
        let device_name = ZYNQMP_DEVICES
            .get(device as usize)
            .map_or_else(|| format!("reserved device {device}"), |d| (*d).to_string());
        format!("device {device_name}")
    } else {
        format!("{cpu_name}{state}")
    };
    Destination {
        description,
        target,
        bitstream: false,
    }
}

fn destination(family: Family, attributes: u32) -> Destination {
    match family {
        Family::Zynq7000 => zynq_destination(attributes),
        Family::ZynqMp => zynqmp_destination(attributes),
    }
}

/// Whether a partition's data is encrypted. `ZynqMP` partitions carry an
/// encryption bit. Zynq-7000 partitions have none: an encrypted partition
/// is stored larger than its original length, under the boot header's key.
fn is_encrypted(family: Family, header: &BootHeader, partition: &Partition) -> bool {
    match family {
        Family::ZynqMp => partition.attributes & ZYNQMP_PA_ENCRYPTED != 0,
        Family::Zynq7000 => {
            header.is_encrypted() && partition.encrypted_size != partition.unencrypted_size
        }
    }
}

/// Facts from a partition's attribute word, for its note.
fn attribute_details(attributes: u32, family: Family) -> Vec<String> {
    let mut details = Vec::new();
    if family == Family::ZynqMp {
        let cpu = (attributes >> ZYNQMP_PA_CPU_SHIFT) & ZYNQMP_PA_CPU_MASK;
        if (CPU_A53_0..=CPU_A53_3).contains(&cpu) {
            details.push(format!(
                "EL{}",
                (attributes >> ZYNQMP_PA_EL_SHIFT) & TWO_BIT_MASK
            ));
            if attributes & ZYNQMP_PA_TRUSTZONE != 0 {
                details.push("TrustZone secure".into());
            }
        }
        if attributes & ZYNQMP_PA_BIG_ENDIAN != 0 {
            details.push("big-endian".into());
        }
        if attributes & ZYNQMP_PA_EARLY_HANDOFF != 0 {
            details.push("early handoff".into());
        }
    }
    let owner = (attributes >> PA_OWNER_SHIFT) & TWO_BIT_MASK;
    if let Some(name) = OWNERS.get(owner as usize) {
        details.push(format!("owner {name}"));
    }
    let checksum = (attributes >> PA_CHECKSUM_SHIFT) & PA_CHECKSUM_MASK;
    if checksum != 0 {
        let name = family
            .checksums()
            .get(checksum as usize)
            .map_or_else(|| format!("type {checksum}"), |c| (*c).to_string());
        details.push(format!("{name} checksum not verified"));
    }
    if attributes & PA_RSA_CERTIFICATE != 0 {
        details.push("authentication certificate not verified".into());
    }
    details
}

/// A child for a boot-header image. Encrypted images are opaque and span
/// their stored size.
fn region_child<'a>(
    data: &'a [u8],
    label: &str,
    region: &Region,
    encrypted: bool,
    target: Option<Target>,
) -> Result<Child<'a>> {
    if encrypted {
        return opaque_child(data, label, region.offset, region.stored_size);
    }
    let child = stored_child(data, label, region.offset, region.size)?;
    Ok(with_destination(child, target))
}

/// Give a child the target its destination names. A recognized format
/// keeps its own evidence: an ELF names its machine and a device tree is
/// data, even when it is loaded for a CPU.
fn with_destination(child: Child<'_>, target: Option<Target>) -> Child<'_> {
    match target {
        Some(target) if !is_recognized(&child.data) => child.with_target(target),
        _ => child,
    }
}

/// The PMU firmware and FSBL the boot header locates, as children with the
/// targets the header (`ZynqMP`) or the partition holding the FSBL
/// (Zynq-7000) names.
fn push_boot_images<'a>(
    data: &'a [u8],
    c: &mut Container<'a>,
    family: Family,
    header: &BootHeader,
    partitions: &[Partition],
) -> Result<()> {
    if let Some(pmu) = &header.pmu_firmware {
        c.notes.push(format!(
            "PMU firmware: {} B at 0x{:X} for the platform management unit (MicroBlaze)",
            pmu.size, pmu.offset
        ));
        c.children.push(region_child(
            data,
            "PMU firmware",
            pmu,
            header.is_encrypted(),
            Some(PMU_MICROBLAZE),
        )?);
    }
    let Some(fsbl) = &header.fsbl else {
        c.notes
            .push("FSBL length is 0: execute in place or no FSBL".into());
        return Ok(());
    };
    let holder = partitions
        .iter()
        .enumerate()
        .find(|(_, partition)| fsbl.overlaps(partition));
    let mut details = vec![format!("FSBL: {} B at 0x{:X}", fsbl.size, fsbl.offset)];
    let target = match family {
        Family::ZynqMp => {
            let cpu = boot_cpu(header.attributes);
            details.push(format!("boot CPU {}", cpu.name));
            Some(cpu.target)
        }
        Family::Zynq7000 => {
            if let Some((index, partition)) = holder {
                let destination = zynq_destination(partition.attributes);
                details.push(format!(
                    "destination {} from partition {index}",
                    destination.description
                ));
                destination.target
            } else {
                details.push("no partition names its destination".into());
                None
            }
        }
    };
    let encrypted = header.is_encrypted()
        || holder.is_some_and(|(_, partition)| is_encrypted(family, header, partition));
    if encrypted {
        details.push("encrypted".into());
    }
    c.notes.push(details.join("; "));
    c.children
        .push(region_child(data, "FSBL", fsbl, encrypted, target)?);
    Ok(())
}

/// Note partition `index` and append it as a child, unless it holds the
/// boot header's images, which are listed on their own.
fn push_partition<'a>(
    data: &'a [u8],
    c: &mut Container<'a>,
    family: Family,
    header: &BootHeader,
    index: usize,
    partition: &Partition,
    images: &[ImageHeader],
) -> Result<()> {
    let image = images
        .iter()
        .find(|image| image.offset == partition.image_header)
        .expect("validated partition names a listed image header");
    let label = if image.name.is_empty() {
        format!("Partition {index}")
    } else {
        format!("Partition {index}: {}", image.name)
    };
    if partition.encrypted_size == 0 {
        c.notes.push(format!("{label}: no data"));
        return Ok(());
    }
    let destination = destination(family, partition.attributes);
    let encrypted = is_encrypted(family, header, partition);
    let mut details = vec![
        format!(
            "{label}: {} B at 0x{:X}",
            partition.encrypted_size, partition.data_offset
        ),
        format!("destination {}", destination.description),
        format!("load 0x{:X}", partition.load_address),
        format!("exec 0x{:X}", partition.exec_address),
    ];
    if encrypted {
        details.push("encrypted".into());
    }
    if destination.bitstream {
        details.push("FPGA bitstream".into());
    }
    details.extend(attribute_details(partition.attributes, family));
    let holds_boot_images = [&header.pmu_firmware, &header.fsbl]
        .into_iter()
        .flatten()
        .any(|region| region.overlaps(partition));
    if holds_boot_images {
        details.push("holds the boot header's images, listed on their own".into());
    }
    c.notes.push(details.join("; "));
    if holds_boot_images {
        return Ok(());
    }
    let child = if encrypted || destination.bitstream {
        opaque_child(data, label, partition.data_offset, partition.encrypted_size)?
    } else {
        let child = stored_child(data, label, partition.data_offset, partition.encrypted_size)?;
        with_destination(child, destination.target)
    };
    c.children.push(child);
    Ok(())
}

/// Notes and metadata from the boot header.
fn push_header_facts(c: &mut Container<'_>, family: Family, header: &BootHeader) {
    match family {
        Family::ZynqMp => {
            let cpu = boot_cpu(header.attributes);
            c.target = Some(cpu.target);
            c.notes.push(format!(
                "Boot header selects the FSBL CPU: {} (attribute bits 11:10)",
                cpu.name
            ));
        }
        Family::Zynq7000 => c.notes.push(
            "Zynq-7000 boot headers name no CPU; partitions name a destination device".into(),
        ),
    }
    c.push_metadata("zynq_family", "Family", family.name());
    if let Some(version) = header.header_version {
        c.push_metadata(
            "zynq_header_version",
            "Header version",
            format!("0x{version:08X}"),
        );
    }
    c.push_metadata("zynq_key_source", "Key source", header.key_source.name);
    c.push_metadata(
        "zynq_fsbl_entry",
        "FSBL execution address",
        format!("0x{:08X}", header.fsbl_entry),
    );
    if header.is_encrypted() {
        c.notes.push(format!(
            "Boot images are encrypted ({}); encrypted bytes are not analyzed",
            header.key_source.name
        ));
    }
    if header.register_writes > 0 {
        c.notes.push(format!(
            "Register initialization table: write count {}",
            header.register_writes
        ));
    }
    let hash_select = (header.attributes >> BH_HASH_SELECT_SHIFT) & TWO_BIT_MASK;
    if family == Family::ZynqMp && hash_select == HASH_SELECT_SHA3 {
        c.notes
            .push("FSBL SHA-3 integrity check selected; not verified".into());
    }
}

/// Notes and metadata from the image header table.
fn push_table_facts(c: &mut Container<'_>, tables: &Tables) {
    let table = &tables.table;
    // Bootgen writes the partition count; UG1283 calls the field the image
    // header count.
    let count_field = if table.partition_count == tables.partitions.len() {
        String::new()
    } else {
        format!("; table count field {}", table.partition_count)
    };
    c.notes.push(format!(
        "Image header table version {}.{}; image header count {}; partition count {}{count_field}",
        table.version >> 24,
        (table.version >> 16) & 0xff,
        tables.images.len(),
        tables.partitions.len()
    ));
    if let Some(device) = table.boot_device {
        let name = BOOT_DEVICES
            .get(device as usize)
            .map_or_else(|| format!("reserved {device}"), |d| (*d).to_string());
        c.push_metadata("zynq_boot_device", "Secondary boot device", name);
    }
    if table.auth_certificate != 0 {
        c.notes.push(format!(
            "Header authentication certificate at 0x{:X}; not verified",
            table.auth_certificate
        ));
    }
    c.push_metadata(
        "zynq_partition_count",
        "Partitions",
        tables.partitions.len() as u64,
    );
}

/// Parse `data` as one family. Every table must validate.
fn parse_family(data: &[u8], family: Family) -> Result<Container<'_>> {
    let header = boot_header(data, family)?;
    let tables = match header.image_header_table {
        0 => None,
        _ => Some(tables(data, &header, family)?),
    };
    let mut c = Container::new(FileFormat::XilinxBootBin, family.variant(), "zynq");
    c.entry = Some(u64::from(header.fsbl_entry));
    c.notes.push(format!(
        "Xilinx {} boot image; boot header checksum verified",
        family.name()
    ));
    push_header_facts(&mut c, family, &header);
    let partitions = tables.as_ref().map_or(&[][..], |t| t.partitions.as_slice());
    push_boot_images(data, &mut c, family, &header, partitions)?;
    let mut consumed = header.end;
    for region in [&header.pmu_firmware, &header.fsbl].into_iter().flatten() {
        consumed = consumed.max(region.offset + region.stored_size);
    }
    match &tables {
        None => c
            .notes
            .push("No image header table; only the boot header's images are listed".into()),
        Some(tables) => {
            push_table_facts(&mut c, tables);
            for (index, partition) in tables.partitions.iter().enumerate() {
                push_partition(
                    data,
                    &mut c,
                    family,
                    &header,
                    index,
                    partition,
                    &tables.images,
                )?;
            }
            consumed = consumed.max(tables.end);
        }
    }
    c.consumed = consumed;
    push_trailing(data, &mut c);
    Ok(c)
}

/// A boot header that validates as both families: the layout of the
/// fields after 0x28, and so the target and image boundaries, is not
/// determined.
fn ambiguous(data: &[u8]) -> Container<'_> {
    let mut c = Container::new(
        FileFormat::XilinxBootBin,
        "Ambiguous Zynq-7000/ZynqMP boot header",
        "zynq",
    );
    c.opaque = true;
    c.consumed = data.len();
    c.notes.push(
        "Boot header checksum verified; the image validates as both Zynq-7000 and ZynqMP, so the family, target and image boundaries are ambiguous"
            .into(),
    );
    c
}

/// Parse a `BOOT.BIN`, deciding the family by validating both layouts.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !has_signature(data) {
        return Err(error(
            "Missing boot header width detection word 0xAA995566 and XNLX signature",
        ));
    }
    verify_header_checksum(data)?;
    match (
        parse_family(data, Family::Zynq7000),
        parse_family(data, Family::ZynqMp),
    ) {
        (Ok(_), Ok(_)) => Ok(ambiguous(data)),
        (Ok(c), Err(_)) | (Err(_), Ok(c)) => Ok(c),
        (Err(zynq), Err(zynqmp)) => Err(error(format!(
            "Invalid boot image as Zynq-7000 ({}) and as ZynqMP ({})",
            message(zynq),
            message(zynqmp)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_checksum_is_the_complement_of_the_wrapping_sum() {
        let mut bytes = Vec::new();
        for word in [0xffff_ffffu32, 2, 0x8000_0000] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(word_checksum(&bytes), !0x8000_0001u32);
        assert_eq!(word_checksum(&[0; 8]), 0xffff_ffff);
    }

    #[test]
    fn image_names_are_stored_big_endian_per_word() {
        // "fsbl.elf" stored as "lbsf" "fle." then a NUL word.
        let data = b"lbsffle.\0\0\0\0";
        let name = image_name(data, 0).unwrap();
        assert_eq!((name.text.as_str(), name.end), ("fsbl.elf", 12));
        let unterminated = [b'a'; 300];
        assert!(image_name(&unterminated, 0).is_err());
    }

    #[test]
    fn word_offsets_convert_to_bytes() {
        assert_eq!(bytes_from_words(0x230).unwrap(), 0x8c0);
    }

    #[test]
    fn zynqmp_destinations_follow_cpu_and_execution_state() {
        let a53_64 = zynqmp_destination(CPU_A53_0 << ZYNQMP_PA_CPU_SHIFT);
        assert_eq!(a53_64.target, Some(AARCH64));
        let a53_32 = zynqmp_destination((CPU_A53_0 << ZYNQMP_PA_CPU_SHIFT) | ZYNQMP_PA_AARCH32);
        assert_eq!(a53_32.target, Some(ARM_LITTLE));
        let r5_big = zynqmp_destination((CPU_R5_0 << ZYNQMP_PA_CPU_SHIFT) | ZYNQMP_PA_BIG_ENDIAN);
        assert_eq!(r5_big.target, Some(CORTEX_R5));
        let pmu = zynqmp_destination(CPU_PMU << ZYNQMP_PA_CPU_SHIFT);
        assert_eq!(pmu.target, Some(PMU_MICROBLAZE));
        let pl = zynqmp_destination(DEVICE_PL << ZYNQMP_PA_DEVICE_SHIFT);
        assert!(pl.bitstream && pl.target.is_none());
        let reserved = zynqmp_destination(9 << ZYNQMP_PA_CPU_SHIFT);
        assert!(reserved.target.is_none());
    }

    #[test]
    fn zynq_destinations_name_the_cortex_a9_only_for_the_ps() {
        assert_eq!(
            zynq_destination(DEVICE_PS << ZYNQ_PA_DEVICE_SHIFT).target,
            Some(ARM_LITTLE)
        );
        assert!(zynq_destination(DEVICE_PL << ZYNQ_PA_DEVICE_SHIFT).bitstream);
        assert!(zynq_destination(3 << ZYNQ_PA_DEVICE_SHIFT).target.is_none());
    }

    #[test]
    fn boot_cpu_select_names_the_fsbl_core() {
        assert_eq!(
            boot_cpu(BOOT_CPU_A53_AARCH64 << BH_CPU_SELECT_SHIFT).target,
            AARCH64
        );
        assert_eq!(
            boot_cpu(BOOT_CPU_A53_AARCH32 << BH_CPU_SELECT_SHIFT).target,
            ARM_LITTLE
        );
        assert_eq!(boot_cpu(0).target, CORTEX_R5);
        assert_eq!(
            boot_cpu(3 << BH_CPU_SELECT_SHIFT).name,
            "Cortex-R5 dual (lockstep)"
        );
    }

    #[test]
    fn zynq_checksum_types_beyond_md5_are_reserved() {
        let details = attribute_details(2 << PA_CHECKSUM_SHIFT, Family::Zynq7000);
        assert!(details.contains(&"type 2 checksum not verified".to_string()));
        let details = attribute_details(3 << PA_CHECKSUM_SHIFT, Family::ZynqMp);
        assert!(details.contains(&"SHA-3 checksum not verified".to_string()));
    }
}
