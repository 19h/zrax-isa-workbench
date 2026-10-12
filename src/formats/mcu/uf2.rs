//! UF2 (USB Flashing Format): independent 512-byte blocks, every field a
//! little-endian `u32` except `data[476]`.
//!
//! Sources: microsoft/uf2 `README.md` ("File format", "Flags", "Family ID",
//! "File containers", "MD5 checksum", "Extension tags") and
//! `utils/uf2families.json` at commit
//! `90e9741f217f5a40c98ba74d663e408041037578` (78 family IDs); pico-sdk
//! 2.1.1 `boot/uf2.h` (flag names, `UF2_EXTENSION_RP2_IGNORE_BLOCK`); RP2350
//! datasheet (build `80d627281ed5`), section 5.5, Table 469 (RP2 family IDs)
//! and erratum RP2350-E10 (the absolute-family workaround block).
//!
//! The family ID is the format's own target field: the README calls it the
//! "board family ID", and a bootloader "should disregard the entire block"
//! when it does not match. The table maps each listed family to the ISA of
//! its application core; the core assignments come from the vendors'
//! product documents listed in `docs/mcu.md`, not from the UF2
//! specification. Families whose core was not established, and the RP2
//! `absolute` and `data` pseudo families, name no ISA.
//!
//! Blocks are independent, so the payload is a sparse address map: flash
//! blocks are grouped by family, checked for duplicate and overlapping
//! addresses, and merged into load sections where consecutive blocks are
//! address-contiguous. Gaps are never materialized.

use super::*;

/// Every block is 512 bytes.
const BLOCK_SIZE: usize = 512;

/// `magicStart0` (`UF2\n`), `magicStart1` and `magicEnd`.
const UF2_MAGIC_START0: u32 = 0x0a32_4655;
const UF2_MAGIC_START1: u32 = 0x9e5d_5157;
const UF2_MAGIC_END: u32 = 0x0ab1_6f30;

/// Header fields before `data[]`.
const HEADER_SIZE: usize = 32;

/// Size of `data[]`, the most a block can carry.
const DATA_SIZE: usize = 476;

/// Offset of `magicEnd`, right after `data[]`.
const MAGIC_END_OFFSET: usize = HEADER_SIZE + DATA_SIZE;

/// Block flags (README "Flags"; names from pico-sdk `uf2.h`).
const UF2_FLAG_NOT_MAIN_FLASH: u32 = 0x0000_0001;
const UF2_FLAG_FILE_CONTAINER: u32 = 0x0000_1000;
const UF2_FLAG_FAMILY_ID_PRESENT: u32 = 0x0000_2000;
const UF2_FLAG_MD5_PRESENT: u32 = 0x0000_4000;
const UF2_FLAG_EXTENSION_FLAGS_PRESENT: u32 = 0x0000_8000;

/// The only flags the specification defines.
const DEFINED_FLAGS: u32 = UF2_FLAG_NOT_MAIN_FLASH
    | UF2_FLAG_FILE_CONTAINER
    | UF2_FLAG_FAMILY_ID_PRESENT
    | UF2_FLAG_MD5_PRESENT
    | UF2_FLAG_EXTENSION_FLAGS_PRESENT;

/// The MD5 record (start address, length, digest) takes the last 24 bytes
/// of `data[]`.
const MD5_RECORD_SIZE: usize = 24;

/// Extension tag header: a size byte and a 24-bit type.
const TAG_HEADER_SIZE: usize = 4;

/// Extension tag types (README "Extension tags"; pico-sdk `uf2.h` for the
/// Raspberry Pi tag).
const TAG_FIRMWARE_VERSION: u32 = 0x009f_c7bc;
const TAG_DEVICE_DESCRIPTION: u32 = 0x0065_0d9d;
const TAG_PAGE_SIZE: u32 = 0x000b_e9f7;
const TAG_SHA2_CHECKSUM: u32 = 0x00b4_6db0;
const TAG_DEVICE_TYPE: u32 = 0x00c8_a729;
const UF2_EXTENSION_RP2_IGNORE_BLOCK: u32 = 0x0099_57e3;

/// Raspberry Pi pseudo families (RP2350 datasheet, Table 469): content for
/// any RP2 core written without partitions, and data partitions.
const RP2XXX_ABSOLUTE: u32 = 0xe48b_ff57;
const RP2XXX_DATA: u32 = 0xe48b_ff58;

/// picotool's RP2350-E10 workaround block claims to be block 0 of 2.
const E10_WORKAROUND_BLOCKS: u32 = 2;

/// Transform names for reassembled payloads.
const BLOCKS_TRANSFORM: &str = "UF2 blocks";
const FILE_TRANSFORM: &str = "UF2 file container";

/// Arm cores: M-profile (Thumb), ARM968E-S and Cortex-A9; little-endian code.
const ARM: Option<Target> = Some(Target::new(Isa::Arm, 32, Endianness::Little));
/// Tensilica Xtensa LX6/LX7/L106 cores as configured by Espressif.
const XTENSA: Option<Target> = Some(Target::new(Isa::Xtensa, 32, Endianness::Little));
/// 32-bit RISC-V cores.
const RISCV32: Option<Target> = Some(Target::new(Isa::RiscV32, 32, Endianness::Little));
/// 8-bit AVR.
const AVR: Option<Target> = Some(Target::new(Isa::Avr, 8, Endianness::Little));
/// Enhanced 8051 (multi-byte operands are big-endian).
const MCS51: Option<Target> = Some(Target::new(Isa::I8051, 8, Endianness::Big));
/// No ISA: pseudo families, and families whose core was not established.
const NO_TARGET: Option<Target> = None;

/// One `uf2families.json` entry and the ISA of its application core.
struct Family {
    id: u32,
    short_name: &'static str,
    description: &'static str,
    target: Option<Target>,
}

const fn family(
    id: u32,
    short_name: &'static str,
    target: Option<Target>,
    description: &'static str,
) -> Family {
    Family {
        id,
        short_name,
        description,
        target,
    }
}

/// `utils/uf2families.json` at the pinned commit, in file order, with the
/// ISA of each family's application core (evidence per row in
/// `docs/mcu.md`). Families with a coprocessor of another ISA (MAX32690,
/// MAX78002, the ESP32-S2/S3 ULP) map to their application core. CSK6 pairs
/// an Arm core with a Cadence `HiFi4` DSP and names neither; BK7251, KL32L2
/// and CSK4 have no established core.
#[rustfmt::skip]
const FAMILIES: &[Family] = &[
    family(0x1657_3617, "ATMEGA32",         AVR,       "Microchip (Atmel) ATmega32"),
    family(0x1851_780a, "SAML21",           ARM,       "Microchip (Atmel) SAML21"),
    family(0x1b57_745f, "NRF52",            ARM,       "Nordic NRF52"),
    family(0x1c5f_21b0, "ESP32",            XTENSA,    "ESP32"),
    family(0x1e1f_432d, "STM32L1",          ARM,       "ST STM32L1xx"),
    family(0x202e_3a91, "STM32L0",          ARM,       "ST STM32L0xx"),
    family(0x2146_0ff0, "STM32WL",          ARM,       "ST STM32WLxx"),
    family(0x22e0_d6fc, "RTL8710B",         ARM,       "Realtek AmebaZ RTL8710B"),
    family(0x2abc_77ec, "LPC55",            ARM,       "NXP LPC55xx"),
    family(0x300f_5633, "STM32G0",          ARM,       "ST STM32G0xx"),
    family(0x31d2_28c6, "GD32F350",         ARM,       "GD32F350"),
    family(0x3379_cfe2, "RTL8720D",         ARM,       "Realtek AmebaD RTL8720D"),
    family(0x0424_0bdf, "STM32L5",          ARM,       "ST STM32L5xx"),
    family(0x4c71_240a, "STM32G4",          ARM,       "ST STM32G4xx"),
    family(0x4fb2_d5bd, "MIMXRT10XX",       ARM,       "NXP i.MX RT10XX"),
    family(0x51e9_03a8, "XR809",            ARM,       "Xradiotech 809"),
    family(0x53b8_0f00, "STM32F7",          ARM,       "ST STM32F7xx"),
    family(0x5511_4460, "SAMD51",           ARM,       "Microchip (Atmel) SAMD51"),
    family(0x5775_5a57, "STM32F4",          ARM,       "ST STM32F4xx"),
    family(0x5a18_069b, "FX2",              MCS51,     "Cypress FX2"),
    family(0x5d1a_0a2e, "STM32F2",          ARM,       "ST STM32F2xx"),
    family(0x5ee2_1072, "STM32F1",          ARM,       "ST STM32F103"),
    family(0x621e_937a, "NRF52833",         ARM,       "Nordic NRF52833"),
    family(0x6478_24b6, "STM32F0",          ARM,       "ST STM32F0xx"),
    family(0x675a_40b0, "BK7231U",          ARM,       "Beken 7231U/7231T"),
    family(0x68ed_2b88, "SAMD21",           ARM,       "Microchip (Atmel) SAMD21"),
    family(0x6a82_cc42, "BK7251",           NO_TARGET, "Beken 7251/7252"),
    family(0x6b84_6188, "STM32F3",          ARM,       "ST STM32F3xx"),
    family(0x6d09_22fa, "STM32F407",        ARM,       "ST STM32F407"),
    family(0x4e8f_1c5d, "STM32H5",          ARM,       "ST STM32H5xx"),
    family(0x6db6_6082, "STM32H7",          ARM,       "ST STM32H7xx"),
    family(0x70d1_6653, "STM32WB",          ARM,       "ST STM32WBxx"),
    family(0x7b3e_f230, "BK7231N",          ARM,       "Beken 7231N"),
    family(0x7eab_61ed, "ESP8266",          XTENSA,    "ESP8266"),
    family(0x7f83_e793, "KL32L2",           NO_TARGET, "NXP KL32L2x"),
    family(0x8fb0_60fe, "STM32F407VG",      ARM,       "ST STM32F407VG"),
    family(0x9fff_d543, "RTL8710A",         ARM,       "Realtek Ameba1 RTL8710A"),
    family(0xada5_2840, "NRF52840",         ARM,       "Nordic NRF52840"),
    family(0x820d_9a5f, "NRF52820",         ARM,       "Nordic NRF52820_xxAA"),
    family(0xbfdd_4eee, "ESP32S2",          XTENSA,    "ESP32-S2"),
    family(0xc47e_5767, "ESP32S3",          XTENSA,    "ESP32-S3"),
    family(0xd42b_a06c, "ESP32C3",          RISCV32,   "ESP32-C3"),
    family(0x2b88_d29c, "ESP32C2",          RISCV32,   "ESP32-C2"),
    family(0x3327_26f6, "ESP32H2",          RISCV32,   "ESP32-H2"),
    family(0x540d_df62, "ESP32C6",          RISCV32,   "ESP32-C6"),
    family(0x3d30_8e94, "ESP32P4",          RISCV32,   "ESP32-P4"),
    family(0xf71c_0343, "ESP32C5",          RISCV32,   "ESP32-C5"),
    family(0x77d8_50c4, "ESP32C61",         RISCV32,   "ESP32-C61"),
    family(0xb6dd_00af, "ESP32H21",         RISCV32,   "ESP32-H21"),
    family(0x9e0b_aa8a, "ESP32H4",          RISCV32,   "ESP32-H4"),
    family(0x3101_f7c1, "ESP32S31",         RISCV32,   "ESP32-S31"),
    family(0xde12_70b7, "BL602",            RISCV32,   "Boufallo 602"),
    family(0xe08f_7564, "RTL8720C",         ARM,       "Realtek AmebaZ2 RTL8720C"),
    family(0xe48b_ff56, "RP2040",           ARM,       "Raspberry Pi RP2040"),
    family(0xe48b_ff57, "RP2XXX_ABSOLUTE",  NO_TARGET, "Raspberry Pi Microcontrollers: Absolute (unpartitioned) download"),
    family(0xe48b_ff58, "RP2XXX_DATA",      NO_TARGET, "Raspberry Pi Microcontrollers: Data partition download"),
    family(0xe48b_ff59, "RP2350_ARM_S",     ARM,       "Raspberry Pi RP2350, Secure Arm image"),
    family(0xe48b_ff5a, "RP2350_RISCV",     RISCV32,   "Raspberry Pi RP2350, RISC-V image"),
    family(0xe48b_ff5b, "RP2350_ARM_NS",    ARM,       "Raspberry Pi RP2350, Non-secure Arm image"),
    family(0x00ff_6919, "STM32L4",          ARM,       "ST STM32L4xx"),
    family(0x9af0_3e33, "GD32VF103",        RISCV32,   "GigaDevice GD32VF103"),
    family(0x4f6a_ce52, "CSK4",             NO_TARGET, "LISTENAI CSK300x/400x"),
    family(0x6e73_48a8, "CSK6",             NO_TARGET, "LISTENAI CSK60xx"),
    family(0x11de_784a, "M0SENSE",          RISCV32,   "M0SENSE BL702"),
    family(0x4b68_4d71, "MaixPlay-U4",      RISCV32,   "Sipeed MaixPlay-U4(BL618)"),
    family(0x9517_422f, "RZA1LU",           ARM,       "Renesas RZ/A1LU (R7S7210xx)"),
    family(0x2dc3_09c5, "STM32F411xE",      ARM,       "ST STM32F411xE"),
    family(0x06d1_097b, "STM32F411xC",      ARM,       "ST STM32F411xC"),
    family(0x7272_1d4e, "NRF52832xxAA",     ARM,       "Nordic NRF52832xxAA"),
    family(0x6f75_2678, "NRF52832xxAB",     ARM,       "Nordic NRF52832xxAB"),
    family(0xa0c9_7b8e, "AT32F415",         ARM,       "ArteryTek AT32F415"),
    family(0x699b_62ec, "CH32V",            RISCV32,   "WCH CH32V2xx and CH32V3xx"),
    family(0x7be8_976d, "RA4M1",            ARM,       "Renesas RA4M1"),
    family(0x7410_520a, "MAX32690",         ARM,       "Analog Devices MAX32690"),
    family(0xd63f_8632, "MAX32650",         ARM,       "Analog Devices MAX32650/1/2"),
    family(0xf0c3_0d71, "MAX32666",         ARM,       "Analog Devices MAX32665/6"),
    family(0x91d3_fd18, "MAX78002",         ARM,       "Analog Devices MAX78002"),
    family(0x7d7a_66ef, "PY32F071-UVK5-V3", ARM,       "Quansheng UV-K5 V3 amateur radio based on Puya Semiconductor PY32F071"),
];

fn family_by_id(id: u32) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.id == id)
}

/// Display name of a block group: the family's short name and description,
/// the bare ID for an unlisted family, or the absence of a family ID.
fn family_label(id: Option<u32>) -> String {
    match id {
        None => "Blocks without a family ID".to_string(),
        Some(id) => match family_by_id(id) {
            Some(f) => format!("{} ({})", f.short_name, f.description),
            None => format!("Family 0x{id:08X}"),
        },
    }
}

fn family_target(id: Option<u32>) -> Option<Target> {
    id.and_then(family_by_id).and_then(|f| f.target)
}

/// Whether the file starts with the two start magics of a UF2 block.
pub(super) fn has_magic(data: &[u8]) -> bool {
    le_u32(data, 0).is_ok_and(|word| word == UF2_MAGIC_START0)
        && le_u32(data, 4).is_ok_and(|word| word == UF2_MAGIC_START1)
}

/// A contained file named by a file-container block.
struct FileRef<'a> {
    /// File name bytes before the NUL terminator.
    name: &'a [u8],
    /// `fileSize`, in bytes.
    size: u32,
}

/// One extension tag.
struct Tag<'a> {
    /// 24-bit tag type.
    kind: u32,
    /// Tag bytes after the 4-byte header.
    value: &'a [u8],
}

/// A validated block.
struct Block<'a> {
    /// File offset of the block.
    offset: usize,
    /// `flags`.
    flags: u32,
    /// `targetAddr`: a flash byte address, or the offset within a
    /// contained file.
    target_address: u32,
    /// `data[..payloadSize]`.
    payload: &'a [u8],
    /// `blockNo`.
    number: u32,
    /// `numBlocks`.
    num_blocks: u32,
    /// `familyID`, when flagged.
    family: Option<u32>,
    /// File name and size, for file-container blocks.
    file: Option<FileRef<'a>>,
    /// Extension tags, when flagged.
    tags: Vec<Tag<'a>>,
}

impl Block<'_> {
    /// File offset of the block's payload bytes.
    fn payload_offset(&self) -> usize {
        self.offset + HEADER_SIZE
    }

    /// Byte address one past the payload.
    fn end_address(&self) -> u64 {
        u64::from(self.target_address) + self.payload.len() as u64
    }

    fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Raspberry Pi blocks tagged for the bootrom to skip entirely.
    fn is_ignored(&self) -> bool {
        self.tags
            .iter()
            .any(|t| t.kind == UF2_EXTENSION_RP2_IGNORE_BLOCK)
    }
}

/// What a block contributes to the analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Device flash content.
    Flash,
    /// `UF2_FLAG_NOT_MAIN_FLASH`: comments, sources or debug data.
    NotMainFlash,
    /// Part of a contained file.
    File,
    /// Tagged `UF2_EXTENSION_RP2_IGNORE_BLOCK`.
    Ignored,
    /// The RP2350-E10 absolute-family block picotool prepends.
    E10Workaround,
}

/// Block: `magicStart0`, `magicStart1` (4), `flags` (8), `targetAddr` (12),
/// `payloadSize` (16), `blockNo` (20), `numBlocks` (24), `fileSize` or
/// `familyID` (28), `data[476]` (32), `magicEnd` (508).
fn parse_block(data: &[u8], offset: usize) -> Result<Block<'_>> {
    let block = slice(data, offset, BLOCK_SIZE)?;
    for (at, magic, name) in [
        (0, UF2_MAGIC_START0, "magicStart0"),
        (4, UF2_MAGIC_START1, "magicStart1"),
        (MAGIC_END_OFFSET, UF2_MAGIC_END, "magicEnd"),
    ] {
        if le_u32(block, at)? != magic {
            return Err(error(format!("Invalid UF2 {name} at 0x{:X}", offset + at)));
        }
    }
    let flags = le_u32(block, 8)?;
    let is_file = flags & UF2_FLAG_FILE_CONTAINER != 0;
    let has_family = flags & UF2_FLAG_FAMILY_ID_PRESENT != 0;
    let has_md5 = flags & UF2_FLAG_MD5_PRESENT != 0;
    let has_tags = flags & UF2_FLAG_EXTENSION_FLAGS_PRESENT != 0;
    if is_file && (has_family || has_tags) {
        // fileSize and familyID share offset 28; the file name and the
        // extension tags both start at data[payloadSize].
        return Err(error(format!(
            "Ambiguous UF2 flags 0x{flags:08X} at 0x{:X}",
            offset + 8
        )));
    }
    // With an MD5 record, the last 24 bytes of data[] are reserved.
    let data_end = if has_md5 {
        MAGIC_END_OFFSET - MD5_RECORD_SIZE
    } else {
        MAGIC_END_OFFSET
    };
    let payload_size = le_u32(block, 16)?;
    let payload_end = usize::try_from(payload_size)
        .ok()
        .and_then(|size| size.checked_add(HEADER_SIZE))
        .filter(|end| *end <= data_end)
        .ok_or_else(|| {
            error(format!(
                "Invalid UF2 payloadSize {payload_size} B at 0x{:X}; at most {} B fit",
                offset + 16,
                data_end - HEADER_SIZE
            ))
        })?;
    let block_no = le_u32(block, 20)?;
    let num_blocks = le_u32(block, 24)?;
    if block_no >= num_blocks {
        return Err(error(format!(
            "Invalid UF2 blockNo {block_no} of numBlocks {num_blocks} at 0x{:X}",
            offset + 20
        )));
    }
    let target_address = le_u32(block, 12)?;
    let word28 = le_u32(block, 28)?;
    let payload = &block[HEADER_SIZE..payload_end];
    let file = if is_file {
        let name_area = &block[payload_end..data_end];
        Some(file_ref(
            offset,
            target_address,
            payload,
            name_area,
            word28,
        )?)
    } else {
        None
    };
    let tags = if has_tags {
        extension_tags(block, offset, payload_end, data_end)?
    } else {
        Vec::new()
    };
    Ok(Block {
        offset,
        flags,
        target_address,
        payload,
        number: block_no,
        num_blocks,
        family: has_family.then_some(word28),
        file,
        tags,
    })
}

/// File-container fields: `fileSize` at 28, `targetAddr` as the offset
/// within the file, and the NUL-terminated name at `data[payloadSize]`
/// (`name_area`, the rest of `data[]`). The README's reader forces a NUL at
/// `data[475]`, so a name never reaches the end magic.
fn file_ref<'a>(
    offset: usize,
    target_address: u32,
    payload: &[u8],
    name_area: &'a [u8],
    size: u32,
) -> Result<FileRef<'a>> {
    let end = u64::from(target_address) + payload.len() as u64;
    if end > u64::from(size) {
        return Err(error(format!(
            "Invalid UF2 file container block at 0x{offset:X}: targetAddr 0x{target_address:X} \
             + {} B exceeds fileSize {size} B",
            payload.len()
        )));
    }
    let name_area = name_area.get(..DATA_SIZE - 1).unwrap_or(name_area);
    Ok(FileRef {
        name: until_nul(name_area),
        size,
    })
}

/// Extension tags from `start`, rounded up to four bytes, before `end`.
/// Byte 0 of a tag is its size including the header but not the padding to
/// the next 4-byte boundary; bytes 1-3 are its type. A zero word ends the
/// list.
fn extension_tags(
    block: &[u8],
    block_offset: usize,
    start: usize,
    end: usize,
) -> Result<Vec<Tag<'_>>> {
    let mut tags = Vec::new();
    let mut pos = align4(start)?;
    while pos + TAG_HEADER_SIZE <= end {
        let word = le_u32(block, pos)?;
        if word == 0 {
            break;
        }
        let size = usize::from(block[pos]);
        if size < TAG_HEADER_SIZE || pos + size > end {
            return Err(error(format!(
                "Invalid UF2 extension tag size {size} B at 0x{:X}",
                block_offset + pos
            )));
        }
        tags.push(Tag {
            kind: word >> 8,
            value: &block[pos + TAG_HEADER_SIZE..pos + size],
        });
        pos = align4(pos + size)?;
    }
    Ok(tags)
}

/// An open run of blocks numbered from 0.
struct Run {
    /// Index of the run's first block.
    first: usize,
    /// `familyID` shared by the run.
    family: Option<u32>,
    /// `numBlocks` shared by the run.
    num_blocks: u32,
    /// Blocks seen so far, which is also the next expected `blockNo`.
    seen: u32,
}

/// Check `blockNo`/`numBlocks`: in file order, blocks form runs numbered
/// `0..numBlocks` with one family and one `numBlocks` per run. esptool
/// restarts the numbering for each file it adds, and concatenated
/// per-family files restart it per family. Ignored blocks do not take part.
/// Returns the first block of each RP2350-E10 workaround run, the only
/// incomplete run accepted.
fn check_numbering(blocks: &[Block<'_>]) -> Result<Vec<usize>> {
    let mut workarounds = Vec::new();
    let mut open: Option<Run> = None;
    for (i, block) in blocks.iter().enumerate() {
        if block.is_ignored() {
            continue;
        }
        let continues = open.as_ref().is_some_and(|run| {
            run.family == block.family
                && run.num_blocks == block.num_blocks
                && run.seen == block.number
        });
        if continues {
            if let Some(run) = open.as_mut() {
                run.seen += 1;
            }
        } else {
            if let Some(run) = open.take() {
                close_incomplete(blocks, &run, &mut workarounds)?;
            }
            if block.number != 0 {
                return Err(error(format!(
                    "Invalid UF2 blockNo {} at 0x{:X}; expected the start of a run",
                    block.number,
                    block.offset + 20
                )));
            }
            open = Some(Run {
                first: i,
                family: block.family,
                num_blocks: block.num_blocks,
                seen: 1,
            });
        }
        if open.as_ref().is_some_and(|run| run.seen == run.num_blocks) {
            open = None;
        }
    }
    if let Some(run) = open {
        close_incomplete(blocks, &run, &mut workarounds)?;
    }
    Ok(workarounds)
}

/// An incomplete run is an error, except picotool's RP2350-E10 workaround:
/// one `RP2XXX_ABSOLUTE` block numbered 0 of 2.
fn close_incomplete(blocks: &[Block<'_>], run: &Run, workarounds: &mut Vec<usize>) -> Result<()> {
    let is_e10_workaround = run.family == Some(RP2XXX_ABSOLUTE)
        && run.num_blocks == E10_WORKAROUND_BLOCKS
        && run.seen == 1;
    if !is_e10_workaround {
        return Err(error(format!(
            "Missing UF2 blocks: the run at 0x{:X} has {} of {} blocks",
            blocks[run.first].offset, run.seen, run.num_blocks
        )));
    }
    workarounds.push(run.first);
    Ok(())
}

fn role(block: &Block<'_>, index: usize, workarounds: &[usize]) -> Role {
    if block.is_ignored() {
        Role::Ignored
    } else if workarounds.contains(&index) {
        Role::E10Workaround
    } else if block.file.is_some() {
        // "The not main flash flag on blocks should be ignored when the
        // file container is set."
        Role::File
    } else if block.has_flag(UF2_FLAG_NOT_MAIN_FLASH) {
        Role::NotMainFlash
    } else {
        Role::Flash
    }
}

/// File offset of the first block and the size up to the end of the last.
fn stored_range(blocks: &[&Block<'_>]) -> (usize, usize) {
    match (blocks.first(), blocks.last()) {
        (Some(first), Some(last)) => (first.offset, last.offset + BLOCK_SIZE - first.offset),
        _ => (0, 0),
    }
}

/// Flash blocks of one family (or of none), in file order.
struct Group<'b, 'a> {
    family: Option<u32>,
    blocks: Vec<&'b Block<'a>>,
}

/// Group flash blocks by family ID in order of first appearance.
fn groups<'b, 'a>(flash: &[&'b Block<'a>]) -> Vec<Group<'b, 'a>> {
    let mut groups: Vec<Group<'b, 'a>> = Vec::new();
    for &block in flash {
        match groups.iter_mut().find(|g| g.family == block.family) {
            Some(group) => group.blocks.push(block),
            None => groups.push(Group {
                family: block.family,
                blocks: vec![block],
            }),
        }
    }
    groups
}

/// Reject flash blocks of one family that write the same bytes twice.
/// After sorting by start address, any overlap shows between neighbours.
fn check_overlaps(group: &Group<'_, '_>) -> Result<()> {
    let mut extents: Vec<(u64, u64, usize)> = group
        .blocks
        .iter()
        .filter(|b| !b.payload.is_empty())
        .map(|b| (u64::from(b.target_address), b.end_address(), b.offset))
        .collect();
    extents.sort_unstable();
    for pair in extents.windows(2) {
        let (start, end, offset) = pair[0];
        let (next_start, next_end, next_offset) = pair[1];
        if next_start < end {
            let defect = if (start, end) == (next_start, next_end) {
                "Duplicate"
            } else {
                "Overlapping"
            };
            return Err(error(format!(
                "{defect} UF2 blocks at 0x{offset:X} and 0x{next_offset:X} for address \
                 0x{next_start:X}"
            )));
        }
    }
    Ok(())
}

/// Address-contiguous payloads of blocks that follow each other in the
/// file.
struct Region<'b, 'a> {
    blocks: Vec<&'b Block<'a>>,
}

impl<'a> Region<'_, 'a> {
    fn address(&self) -> u64 {
        u64::from(self.blocks[0].target_address)
    }

    fn size(&self) -> usize {
        self.blocks.iter().map(|b| b.payload.len()).sum()
    }

    /// The region as a load section. A single block's payload is stored
    /// as-is; a longer run is reassembled from the blocks it spans.
    fn section(&self, index: usize) -> Section<'a> {
        let label = format!("Load section {}", index + 1);
        if let [only] = self.blocks.as_slice() {
            return stored_section(label, self.address(), only.payload_offset(), only.payload);
        }
        let (offset, stored_size) = stored_range(&self.blocks);
        transformed_section(
            label,
            self.address(),
            offset,
            stored_size,
            self.bytes(),
            BLOCKS_TRANSFORM,
        )
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        for block in &self.blocks {
            bytes.extend_from_slice(block.payload);
        }
        bytes
    }
}

/// Merge a group's non-empty payloads into regions: a block continues the
/// previous region when it is the next block in the file and its
/// `targetAddr` is the previous block's end. Address gaps are never filled.
fn regions<'b, 'a>(group: &Group<'b, 'a>) -> Vec<Region<'b, 'a>> {
    let mut regions: Vec<Region<'b, 'a>> = Vec::new();
    for &block in group.blocks.iter().filter(|b| !b.payload.is_empty()) {
        let continues = regions
            .last()
            .and_then(|r| r.blocks.last())
            .is_some_and(|prev| {
                prev.offset + BLOCK_SIZE == block.offset
                    && prev.end_address() == u64::from(block.target_address)
            });
        match regions.last_mut() {
            Some(region) if continues => region.blocks.push(block),
            _ => regions.push(Region {
                blocks: vec![block],
            }),
        }
    }
    regions
}

/// The blocks of one contained file, as named in its file-container blocks.
struct ContainedFile<'b, 'a> {
    name: &'a [u8],
    size: u32,
    blocks: Vec<&'b Block<'a>>,
}

impl ContainedFile<'_, '_> {
    fn label(&self) -> String {
        if self.name.is_empty() {
            "Unnamed file".to_string()
        } else {
            String::from_utf8_lossy(self.name).into_owned()
        }
    }

    /// The file's bytes when its blocks cover `0..fileSize` exactly once;
    /// `None` when bytes are missing.
    fn contents(&self) -> Result<Option<Vec<u8>>> {
        let mut blocks = self.blocks.clone();
        blocks.sort_by_key(|b| (b.target_address, b.offset));
        let mut covered = 0u64;
        for block in &blocks {
            let start = u64::from(block.target_address);
            if start < covered {
                return Err(error(format!(
                    "Overlapping UF2 file container blocks for {} at 0x{:X}",
                    self.label(),
                    block.offset
                )));
            }
            if start > covered {
                return Ok(None);
            }
            covered = block.end_address();
        }
        if covered != u64::from(self.size) {
            return Ok(None);
        }
        let mut contents = Vec::with_capacity(blocks.iter().map(|b| b.payload.len()).sum());
        for block in blocks {
            contents.extend_from_slice(block.payload);
        }
        Ok(Some(contents))
    }
}

/// Group file-container blocks by file name and size, in order of first
/// appearance.
fn contained_files<'b, 'a>(blocks: &[&'b Block<'a>]) -> Vec<ContainedFile<'b, 'a>> {
    let mut files: Vec<ContainedFile<'b, 'a>> = Vec::new();
    for &block in blocks {
        let Some(file) = &block.file else {
            continue;
        };
        match files
            .iter_mut()
            .find(|f| f.name == file.name && f.size == file.size)
        {
            Some(existing) => existing.blocks.push(block),
            None => files.push(ContainedFile {
                name: file.name,
                size: file.size,
                blocks: vec![block],
            }),
        }
    }
    files
}

/// Parse a UF2 file into load sections (one family) or one child per
/// family, plus contained files.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let partial = data.len() % BLOCK_SIZE;
    if data.is_empty() || partial != 0 {
        return Err(error(format!(
            "Truncated UF2 block at 0x{:X}: {partial} of {BLOCK_SIZE} B",
            data.len() - partial
        )));
    }
    let blocks = (0..data.len() / BLOCK_SIZE)
        .map(|i| parse_block(data, i * BLOCK_SIZE))
        .collect::<Result<Vec<_>>>()?;
    let workarounds = check_numbering(&blocks)?;
    let roles: Vec<Role> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| role(b, i, &workarounds))
        .collect();
    let flash = with_role(&blocks, &roles, Role::Flash);
    let flash_groups = groups(&flash);
    for group in &flash_groups {
        check_overlaps(group)?;
    }
    let flash_size: usize = flash.iter().map(|b| b.payload.len()).sum();
    if flash_size > MAX_PAYLOAD {
        return Err(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD });
    }

    let mut c = Container::new(
        FileFormat::Uf2,
        Layout::Uf2.label(),
        Layout::Uf2.key_prefix(),
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "UF2: {}; {flash_size} B of flash payload in {}",
        count(blocks.len(), "block", "blocks"),
        count(flash_groups.len(), "family", "families")
    ));
    c.push_metadata("uf2_block_count", "Blocks", blocks.len() as u64);
    match flash_groups.as_slice() {
        [] => c.notes.push("No main-flash payload".to_string()),
        [group] => single_family(&mut c, group),
        many => per_family_children(&mut c, many),
    }
    contained_file_children(&mut c, &with_role(&blocks, &roles, Role::File))?;
    skipped_block_notes(&mut c, &blocks, &roles);
    tag_metadata(&mut c, &blocks);
    Ok(c)
}

/// The blocks whose role is `wanted`, in file order.
fn with_role<'b, 'a>(blocks: &'b [Block<'a>], roles: &[Role], wanted: Role) -> Vec<&'b Block<'a>> {
    blocks
        .iter()
        .zip(roles)
        .filter(|(_, role)| **role == wanted)
        .map(|(block, _)| block)
        .collect()
}

/// One family: its regions are the container's load sections and its
/// family ID is the container's target.
fn single_family<'a>(c: &mut Container<'a>, group: &Group<'_, 'a>) {
    let mut sections = Sections::new();
    for (i, region) in regions(group).iter().enumerate() {
        sections.push(c, region.section(i));
    }
    sections.finish(c);
    if let Some(id) = group.family {
        c.push_metadata("uf2_family_id", "Family ID", format!("0x{id:08X}"));
        c.push_metadata("uf2_family", "Family", family_label(group.family));
    }
    c.notes.push(family_note(group.family));
    c.target = family_target(group.family);
    c.opaque = group.family == Some(RP2XXX_DATA);
}

/// Several families: one child per family with that family's regions
/// concatenated (gaps not materialized), so each is classified on its own.
fn per_family_children<'a>(c: &mut Container<'a>, groups: &[Group<'_, 'a>]) {
    for (i, group) in groups.iter().enumerate() {
        let label = family_label(group.family);
        let regions = regions(group);
        let mut bytes = Vec::new();
        for (j, region) in regions.iter().enumerate().take(MAX_COMPONENTS) {
            bytes.extend_from_slice(&region.bytes());
            c.push_metadata(
                format!("uf2_family_{i}_region_{j}"),
                format!("{label} region {}", j + 1),
                format!(
                    "file 0x{:X}; destination 0x{:X}; {} B",
                    region.blocks[0].offset,
                    region.address(),
                    region.size()
                ),
            );
        }
        if regions.len() > MAX_COMPONENTS {
            c.notes.push(format!(
                "{label}: {} not analyzed (limit {MAX_COMPONENTS})",
                count(
                    regions.len() - MAX_COMPONENTS,
                    "further region",
                    "further regions"
                )
            ));
        }
        let (offset, stored_size) = stored_range(&group.blocks);
        let mut child = Child::decoded(
            label,
            offset,
            stored_size,
            Cow::Owned(bytes),
            BLOCKS_TRANSFORM,
        );
        child.target = family_target(group.family);
        child.opaque = group.family == Some(RP2XXX_DATA);
        c.children.push(child);
        c.notes.push(family_note(group.family));
    }
}

/// How a group's family ID bears on the ISA.
fn family_note(id: Option<u32>) -> String {
    let Some(id) = id else {
        return "No family ID; ISA from the code model".to_string();
    };
    let Some(f) = family_by_id(id) else {
        return format!(
            "familyID 0x{id:08X} is not in the UF2 family list; ISA from the code model"
        );
    };
    let named = format!("familyID 0x{id:08X} ({}: {})", f.short_name, f.description);
    match f.target {
        Some(target) => format!("{named} names {} code", target.isa.name()),
        None if id == RP2XXX_DATA => format!("{named} marks a data download; not analyzed"),
        None => format!("{named} names no single ISA; ISA from the code model"),
    }
}

/// Contained files become children when their blocks cover them; they are
/// listed only if their bytes are a recognized format.
fn contained_file_children<'a>(c: &mut Container<'a>, blocks: &[&Block<'a>]) -> Result<()> {
    for (i, file) in contained_files(blocks).iter().enumerate() {
        let label = file.label();
        c.push_metadata(
            format!("uf2_file_{i}"),
            format!("Contained file {}", i + 1),
            format!(
                "{label}; {} B; {}",
                file.size,
                count(file.blocks.len(), "block", "blocks")
            ),
        );
        let Some(contents) = file.contents()? else {
            c.notes.push(format!(
                "Contained file {label}: blocks do not cover its {} B; not extracted",
                file.size
            ));
            continue;
        };
        if c.children.len() >= MAX_COMPONENTS {
            c.notes.push(format!(
                "Contained file {label}: component limit reached; not extracted"
            ));
            continue;
        }
        let (offset, stored_size) = stored_range(&file.blocks);
        c.children.push(
            Child::decoded(
                label,
                offset,
                stored_size,
                Cow::Owned(contents),
                FILE_TRANSFORM,
            )
            .if_recognized(),
        );
    }
    Ok(())
}

/// Notes for blocks that are not analyzed, undefined flags, and unverified
/// MD5 records.
fn skipped_block_notes(c: &mut Container<'_>, blocks: &[Block<'_>], roles: &[Role]) {
    let with = |wanted: Role| roles.iter().filter(|r| **r == wanted).count();
    let not_main_flash = with(Role::NotMainFlash);
    if not_main_flash > 0 {
        c.notes.push(format!(
            "{} flagged not main flash (comments, sources or debug data); not analyzed",
            count(not_main_flash, "block", "blocks")
        ));
    }
    let ignored = with(Role::Ignored);
    if ignored > 0 {
        c.notes.push(format!(
            "{} tagged UF2_EXTENSION_RP2_IGNORE_BLOCK; not analyzed",
            count(ignored, "block", "blocks")
        ));
    }
    for (block, _) in blocks
        .iter()
        .zip(roles)
        .filter(|(_, r)| **r == Role::E10Workaround)
    {
        c.notes.push(format!(
            "Block at 0x{:X} is the RP2350-E10 workaround (RP2XXX_ABSOLUTE block 0 of 2); \
             not part of the image",
            block.offset
        ));
    }
    let undefined = blocks
        .iter()
        .fold(0, |bits, b| bits | (b.flags & !DEFINED_FLAGS));
    if undefined != 0 {
        c.notes.push(format!(
            "Flags 0x{undefined:08X} are not defined by the UF2 specification; ignored"
        ));
    }
    let md5 = blocks
        .iter()
        .filter(|b| b.has_flag(UF2_FLAG_MD5_PRESENT))
        .count();
    if md5 > 0 {
        c.notes.push(format!(
            "MD5 records in {}; not verified",
            count(md5, "block", "blocks")
        ));
    }
}

/// Extension tags as metadata, first occurrence of each type.
fn tag_metadata(c: &mut Container<'_>, blocks: &[Block<'_>]) {
    let first = |kind: u32| {
        blocks
            .iter()
            .flat_map(|b| &b.tags)
            .find(|t| t.kind == kind)
            .map(|t| t.value)
    };
    let text = |value: &[u8]| String::from_utf8_lossy(until_nul(value)).into_owned();
    if let Some(value) = first(TAG_FIRMWARE_VERSION) {
        c.push_metadata("uf2_firmware_version", "Firmware version", text(value));
    }
    if let Some(value) = first(TAG_DEVICE_DESCRIPTION) {
        c.push_metadata("uf2_device_description", "Device description", text(value));
    }
    if let Some(value) = first(TAG_PAGE_SIZE) {
        if let Ok(size) = le_u32(value, 0) {
            c.push_metadata("uf2_page_size", "Target page size (B)", u64::from(size));
        }
    }
    if let Some(value) = first(TAG_DEVICE_TYPE) {
        c.push_metadata("uf2_device_type", "Device type ID", hex_string(value));
    }
    if first(TAG_SHA2_CHECKSUM).is_some() {
        c.notes
            .push("SHA-2 firmware checksum tag present; not verified".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_table_ids_are_unique_and_rp2_families_are_distinct() {
        for (i, f) in FAMILIES.iter().enumerate() {
            assert!(
                FAMILIES[i + 1..].iter().all(|g| g.id != f.id),
                "{}",
                f.short_name
            );
        }
        assert_eq!(FAMILIES.len(), 78);
        let isa = |id: u32| family_target(Some(id)).map(|t| t.isa);
        assert_eq!(isa(0xe48b_ff59), Some(Isa::Arm));
        assert_eq!(isa(0xe48b_ff5a), Some(Isa::RiscV32));
        assert_eq!(isa(0xe48b_ff5b), Some(Isa::Arm));
        assert_eq!(isa(0xc47e_5767), Some(Isa::Xtensa));
        assert_eq!(isa(0xd42b_a06c), Some(Isa::RiscV32));
        assert_eq!(isa(RP2XXX_ABSOLUTE), None);
        assert_eq!(isa(0x6e73_48a8), None);
        assert_eq!(isa(0x1234_5678), None);
    }

    #[test]
    fn extension_tags_skip_padding_and_stop_at_the_zero_word() {
        // README example: version "0.1.2" (size 9, three padding bytes),
        // device "ACME Toaster mk3" (size 20), terminator.
        let mut block = vec![0u8; 64];
        let tags = [
            &[
                0x09, 0xbc, 0xc7, 0x9f, b'0', b'.', b'1', b'.', b'2', 0, 0, 0,
            ][..],
            &[0x14, 0x9d, 0x0d, 0x65][..],
            b"ACME Toaster mk3",
        ]
        .concat();
        block[8..8 + tags.len()].copy_from_slice(&tags);
        let parsed = extension_tags(&block, 0, 8, block.len()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, TAG_FIRMWARE_VERSION);
        assert_eq!(parsed[0].value, b"0.1.2");
        assert_eq!(parsed[1].kind, TAG_DEVICE_DESCRIPTION);
        assert_eq!(parsed[1].value, b"ACME Toaster mk3");
        block[8] = 2;
        assert!(extension_tags(&block, 0, 8, block.len()).is_err());
    }

    #[test]
    fn file_names_stop_before_the_end_magic() {
        let area = [b'a'; DATA_SIZE];
        let file = file_ref(0, 0, &[], &area, 1).unwrap();
        assert_eq!(file.name.len(), DATA_SIZE - 1);
        assert!(file_ref(0, 1, &[0; 4], &area, 4).is_err());
    }
}
