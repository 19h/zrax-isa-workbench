//! Espressif chips: image chip IDs, architectures, memory maps, bootloader
//! offsets and flash parameter encodings.
//!
//! Chip IDs: ESP-IDF v5.5.1 `esp_app_format.h` (`esp_chip_id_t`), v6.1 for
//! ESP32-S31, and esptool v5.4.0 `IMAGE_CHIP_ID` (ESP32-E22, which no ESP-IDF
//! release lists). Architectures: ESP-IDF `Kconfig` (`select
//! IDF_TARGET_ARCH_XTENSA` or `IDF_TARGET_ARCH_RISCV` per target). Xtensa
//! cores: `XCHAL_HW_VERSION_NAME` in ESP-IDF
//! `components/xtensa/<chip>/include/xtensa/config/core-isa.h` (`LX6.0.3`,
//! `LX7.0.8`, `LX7.0.12`) and `ESP8266_RTOS_SDK` `core-isa.h`
//! (`XCHAL_CORE_ID` `lx106`, `LX3.0.1`); every one sets `XCHAL_HAVE_BE` 0.
//! Memory maps, bootloader offsets, flash sizes and frequencies: esptool
//! `targets/*.py` (`MEMORY_MAP`, `BOOTLOADER_FLASH_OFFSET`, `FLASH_SIZES`,
//! `FLASH_FREQUENCY`, inherited along the target class hierarchy).

use crate::formats::container::Target;
use crate::types::{Endianness, Isa};
use Role::{Data, Instruction, Padding};

/// What a memory region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    /// Instruction bus: IROM (flash-mapped or mask ROM), IRAM, RTC IRAM.
    Instruction,
    /// Data bus: DROM, DRAM, RTC DRAM, RTC slow memory, external RAM.
    Data,
    /// esptool `PADDING` (0x0-0xFFFF): padding segments, never loaded.
    Padding,
}

/// One `MEMORY_MAP` entry: `[start, end)` with esptool's name.
#[derive(Debug, Clone, Copy)]
pub(super) struct Region {
    start: u32,
    end: u32,
    name: &'static str,
    role: Role,
}

const fn region(start: u32, end: u32, name: &'static str, role: Role) -> Region {
    Region {
        start,
        end,
        name,
        role,
    }
}

/// esptool `PADDING`, listed for every chip of the ESP32 family.
const PADDING: Region = region(0x0000_0000, 0x0001_0000, "padding", Padding);

// The instruction and data regions of each `MEMORY_MAP`. Mask ROM,
// cache, `BYTE_ACCESSIBLE` and `MEM_INTERNAL` entries are left out: no
// segment is loaded there, or the entry overlaps a listed region.
#[rustfmt::skip]
const ESP32_MAP: &[Region] = &[
    PADDING,
    region(0x3F40_0000, 0x3F80_0000, "DROM", Data),
    region(0x3F80_0000, 0x3FC0_0000, "EXTRAM_DATA", Data),
    region(0x3FF8_0000, 0x3FF8_2000, "RTC_DRAM", Data),
    region(0x3FFA_E000, 0x4000_0000, "DRAM", Data),
    region(0x3FFE_0000, 0x3FFF_FFFC, "DIRAM_DRAM", Data),
    region(0x4000_0000, 0x4007_0000, "IROM", Instruction),
    region(0x4008_0000, 0x400A_0000, "IRAM", Instruction),
    region(0x400A_0000, 0x400B_FFFC, "DIRAM_IRAM", Instruction),
    region(0x400C_0000, 0x400C_2000, "RTC_IRAM", Instruction),
    region(0x400D_0000, 0x4040_0000, "IROM", Instruction),
    region(0x5000_0000, 0x5000_2000, "RTC_DATA", Data),
];

#[rustfmt::skip]
const ESP32S2_MAP: &[Region] = &[
    PADDING,
    region(0x3F00_0000, 0x3FF8_0000, "DROM", Data),
    region(0x3F50_0000, 0x3FF8_0000, "EXTRAM_DATA", Data),
    region(0x3FF9_E000, 0x3FFA_0000, "RTC_DRAM", Data),
    region(0x3FFB_0000, 0x4000_0000, "DRAM", Data),
    region(0x4002_0000, 0x4007_0000, "IRAM", Instruction),
    region(0x4007_0000, 0x4007_2000, "RTC_IRAM", Instruction),
    region(0x4008_0000, 0x4080_0000, "IROM", Instruction),
    region(0x5000_0000, 0x5000_2000, "RTC_DATA", Data),
];

#[rustfmt::skip]
const ESP32S3_MAP: &[Region] = &[
    PADDING,
    region(0x3C00_0000, 0x3D00_0000, "DROM", Data),
    region(0x3D00_0000, 0x3E00_0000, "EXTRAM_DATA", Data),
    region(0x600F_E000, 0x6010_0000, "RTC_DRAM", Data),
    region(0x3FC8_8000, 0x3FD0_0000, "DRAM", Data),
    region(0x4037_0000, 0x403E_0000, "IRAM", Instruction),
    region(0x600F_E000, 0x6010_0000, "RTC_IRAM", Instruction),
    region(0x4200_0000, 0x4280_0000, "IROM", Instruction),
    region(0x5000_0000, 0x5000_2000, "RTC_DATA", Data),
];

#[rustfmt::skip]
const ESP32C2_MAP: &[Region] = &[
    PADDING,
    region(0x3C00_0000, 0x3C40_0000, "DROM", Data),
    region(0x3FCA_0000, 0x3FCE_0000, "DRAM", Data),
    region(0x4200_0000, 0x4240_0000, "IROM", Instruction),
    region(0x4037_C000, 0x403C_0000, "IRAM", Instruction),
];

#[rustfmt::skip]
const ESP32C3_MAP: &[Region] = &[
    PADDING,
    region(0x3C00_0000, 0x3C80_0000, "DROM", Data),
    region(0x3FC8_0000, 0x3FCE_0000, "DRAM", Data),
    region(0x4200_0000, 0x4280_0000, "IROM", Instruction),
    region(0x4037_C000, 0x403E_0000, "IRAM", Instruction),
    region(0x5000_0000, 0x5000_2000, "RTC_IRAM", Instruction),
    region(0x5000_0000, 0x5000_2000, "RTC_DRAM", Data),
];

/// ESP32-C5 and ESP32-C61 (identical maps).
#[rustfmt::skip]
const ESP32C5_MAP: &[Region] = &[
    PADDING,
    region(0x4200_0000, 0x4400_0000, "DROM", Data),
    region(0x4080_0000, 0x4086_0000, "DRAM", Data),
    region(0x4200_0000, 0x4400_0000, "IROM", Instruction),
    region(0x4080_0000, 0x4086_0000, "IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_DRAM", Data),
];

/// ESP32-C6, and ESP32-H2 and ESP32-H21, which inherit it.
#[rustfmt::skip]
const ESP32C6_MAP: &[Region] = &[
    PADDING,
    region(0x4200_0000, 0x4300_0000, "DROM", Data),
    region(0x4080_0000, 0x4088_0000, "DRAM", Data),
    region(0x4200_0000, 0x4300_0000, "IROM", Instruction),
    region(0x4080_0000, 0x4088_0000, "IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_DRAM", Data),
];

#[rustfmt::skip]
const ESP32H4_MAP: &[Region] = &[
    PADDING,
    region(0x4200_0000, 0x4400_0000, "DROM", Data),
    region(0x4081_0000, 0x4086_0000, "DRAM", Data),
    region(0x4200_0000, 0x4400_0000, "IROM", Instruction),
    region(0x4081_0000, 0x4086_0000, "IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_IRAM", Instruction),
    region(0x5000_0000, 0x5000_4000, "RTC_DRAM", Data),
];

#[rustfmt::skip]
const ESP32P4_MAP: &[Region] = &[
    PADDING,
    region(0x4000_0000, 0x4C00_0000, "DROM", Data),
    region(0x4FF0_0000, 0x4FFA_0000, "DRAM", Data),
    region(0x4000_0000, 0x4C00_0000, "IROM", Instruction),
    region(0x4FF0_0000, 0x4FFA_0000, "IRAM", Instruction),
    region(0x5010_8000, 0x5011_0000, "RTC_IRAM", Instruction),
    region(0x5010_8000, 0x5011_0000, "RTC_DRAM", Data),
];

#[rustfmt::skip]
const ESP32S31_MAP: &[Region] = &[
    PADDING,
    region(0x4000_0000, 0x5400_0000, "DROM", Data),
    region(0x2F00_0000, 0x2F08_0000, "DRAM", Data),
    region(0x4000_0000, 0x5400_0000, "IROM", Instruction),
    region(0x2F00_0000, 0x2F08_0000, "IRAM", Instruction),
    region(0x2E00_0000, 0x2E00_8000, "RTC_IRAM", Instruction),
    region(0x2E00_0000, 0x2E00_8000, "RTC_DRAM", Data),
];

#[rustfmt::skip]
const ESP32E22_MAP: &[Region] = &[
    PADDING,
    region(0x3C00_0000, 0x4000_0000, "DROM", Data),
    region(0x3100_0000, 0x3120_0000, "DRAM", Data),
    region(0x3C00_0000, 0x4000_0000, "IROM", Instruction),
    region(0x30FE_0000, 0x3120_0000, "IRAM", Instruction),
    region(0xC000_0000, 0xC000_8000, "RTC_IRAM", Instruction),
    region(0xC000_0000, 0xC000_8000, "RTC_DRAM", Data),
];

/// ESP8266 (no padding region: its ROM loads every segment).
#[rustfmt::skip]
const ESP8266_MAP: &[Region] = &[
    region(0x3FFE_8000, 0x4000_0000, "DRAM", Data),
    region(0x4010_0000, 0x4010_8000, "IRAM", Instruction),
    region(0x4020_1010, 0x402E_1010, "IROM", Instruction),
];

/// Flash size codes (high nibble of header byte 3) of the ESP32 family,
/// shared by every target (esptool `ESP32ROM.FLASH_SIZES`, ESP-IDF
/// `esp_image_flash_size_t`).
#[rustfmt::skip]
const ESP32_FLASH_SIZES: &[(u8, &str)] = &[
    (0x0, "1 MiB"), (0x1, "2 MiB"), (0x2, "4 MiB"), (0x3, "8 MiB"),
    (0x4, "16 MiB"), (0x5, "32 MiB"), (0x6, "64 MiB"), (0x7, "128 MiB"),
];

/// ESP8266 flash size codes (esptool `ESP8266ROM.FLASH_SIZES`; `-c1` is the
/// alternative partition map).
#[rustfmt::skip]
const ESP8266_FLASH_SIZES: &[(u8, &str)] = &[
    (0x0, "512 KiB"), (0x1, "256 KiB"), (0x2, "1 MiB"), (0x3, "2 MiB"),
    (0x4, "4 MiB"), (0x5, "2 MiB (c1)"), (0x6, "4 MiB (c1)"), (0x8, "8 MiB"),
    (0x9, "16 MiB"),
];

/// Flash frequency codes (low nibble of header byte 3), by target.
#[rustfmt::skip]
const FREQUENCIES_80: &[(u8, &str)] = &[
    (0xF, "80 MHz"), (0x0, "40 MHz"), (0x1, "26 MHz"), (0x2, "20 MHz"),
];
#[rustfmt::skip]
const FREQUENCIES_C2: &[(u8, &str)] = &[
    (0xF, "60 MHz"), (0x0, "30 MHz"), (0x1, "20 MHz"), (0x2, "15 MHz"),
];
/// ESP32-C6: esptool encodes both 80 and 40 MHz as 0 ("workaround for wrong
/// mspi HS div value in ROM").
#[rustfmt::skip]
const FREQUENCIES_C6: &[(u8, &str)] = &[(0x0, "40 or 80 MHz"), (0x2, "20 MHz")];
#[rustfmt::skip]
const FREQUENCIES_C5: &[(u8, &str)] = &[(0xF, "80 MHz"), (0x0, "40 MHz"), (0x2, "20 MHz")];
#[rustfmt::skip]
const FREQUENCIES_H2: &[(u8, &str)] = &[
    (0xF, "48 MHz"), (0x0, "24 MHz"), (0x1, "16 MHz"), (0x2, "12 MHz"),
];

/// A chip's CPU architecture as ESP-IDF names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Architecture {
    /// Xtensa, little-endian, with the core the configuration header names.
    Xtensa {
        /// `XCHAL_HW_VERSION_NAME` (and `XCHAL_CORE_ID` for the ESP8266).
        core: &'static str,
    },
    /// 32-bit RISC-V; instruction parcels are always little-endian.
    RiscV,
}

/// One Espressif chip.
#[derive(Debug)]
pub(super) struct Chip {
    /// Name as Espressif writes it.
    pub(super) name: &'static str,
    /// Architecture, when ESP-IDF names it.
    pub(super) architecture: Option<Architecture>,
    /// Instruction, data and padding regions.
    regions: &'static [Region],
    /// Flash offset of the second-stage bootloader, in bytes.
    pub(super) bootloader_offset: usize,
    /// Flash size codes.
    flash_sizes: &'static [(u8, &'static str)],
    /// Flash frequency codes.
    flash_frequencies: &'static [(u8, &'static str)],
}

const fn chip(
    name: &'static str,
    architecture: Option<Architecture>,
    regions: &'static [Region],
    bootloader_offset: usize,
    flash_frequencies: &'static [(u8, &'static str)],
) -> Chip {
    Chip {
        name,
        architecture,
        regions,
        bootloader_offset,
        flash_sizes: ESP32_FLASH_SIZES,
        flash_frequencies,
    }
}

const LX6: Option<Architecture> = Some(Architecture::Xtensa { core: "Xtensa LX6" });
const LX7: Option<Architecture> = Some(Architecture::Xtensa { core: "Xtensa LX7" });
const RISCV: Option<Architecture> = Some(Architecture::RiscV);

/// The chips of the 24-byte image header, by `chip_id`.
#[rustfmt::skip]
const CHIPS: &[(u16, Chip)] = &[
    (0x0000, chip("ESP32", LX6, ESP32_MAP, 0x1000, FREQUENCIES_80)),
    (0x0002, chip("ESP32-S2", LX7, ESP32S2_MAP, 0x1000, FREQUENCIES_80)),
    (0x0005, chip("ESP32-C3", RISCV, ESP32C3_MAP, 0x0, FREQUENCIES_80)),
    (0x0009, chip("ESP32-S3", LX7, ESP32S3_MAP, 0x0, FREQUENCIES_80)),
    (0x000C, chip("ESP32-C2", RISCV, ESP32C2_MAP, 0x0, FREQUENCIES_C2)),
    (0x000D, chip("ESP32-C6", RISCV, ESP32C6_MAP, 0x0, FREQUENCIES_C6)),
    (0x0010, chip("ESP32-H2", RISCV, ESP32C6_MAP, 0x0, FREQUENCIES_H2)),
    (0x0012, chip("ESP32-P4", RISCV, ESP32P4_MAP, 0x2000, FREQUENCIES_80)),
    (0x0014, chip("ESP32-C61", RISCV, ESP32C5_MAP, 0x0, FREQUENCIES_C5)),
    (0x0017, chip("ESP32-C5", RISCV, ESP32C5_MAP, 0x2000, FREQUENCIES_C5)),
    (0x0019, chip("ESP32-H21", RISCV, ESP32C6_MAP, 0x0, FREQUENCIES_H2)),
    (0x001C, chip("ESP32-H4", RISCV, ESP32H4_MAP, 0x2000, FREQUENCIES_H2)),
    // esptool only: no ESP-IDF release names the ESP32-E22 architecture.
    (0x001F, chip("ESP32-E22", None, ESP32E22_MAP, 0x0, FREQUENCIES_80)),
    (0x0020, chip("ESP32-S31", RISCV, ESP32S31_MAP, 0x2000, FREQUENCIES_C5)),
];

/// The ESP8266, the only chip of the version 1 and version 2 layouts.
pub(super) const ESP8266: Chip = Chip {
    name: "ESP8266",
    architecture: Some(Architecture::Xtensa {
        core: "Xtensa lx106 (LX3.0.1)",
    }),
    regions: ESP8266_MAP,
    bootloader_offset: 0x0,
    flash_sizes: ESP8266_FLASH_SIZES,
    flash_frequencies: FREQUENCIES_80,
};

/// The chip an image header's `chip_id` names.
pub(super) fn by_id(chip_id: u16) -> Option<&'static Chip> {
    CHIPS
        .iter()
        .find(|(id, _)| *id == chip_id)
        .map(|(_, chip)| chip)
}

/// How a segment's load address is used on a chip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Placement {
    /// In an instruction region (possibly also a data region): analyzed as
    /// code.
    Code {
        /// esptool region name, `IROM/DROM` where the two coincide.
        region: String,
        /// The address also lies in a data region (unified memory).
        shared: bool,
    },
    /// In a data region only: opaque.
    Data {
        /// esptool region name.
        region: &'static str,
    },
    /// A padding segment, never loaded.
    Padding,
    /// In no documented region: opaque.
    Unmapped,
    /// The chip is not documented, so the role is unknown: analyzed as
    /// code.
    Unknown,
}

impl Chip {
    /// Where `address` lies on this chip, by its start address as esptool
    /// `get_memory_type` does.
    pub(super) fn placement(&self, address: u32) -> Placement {
        let containing = |role: Role| {
            self.regions
                .iter()
                .find(|r| r.role == role && (r.start..r.end).contains(&address))
                .map(|r| r.name)
        };
        match (containing(Instruction), containing(Data)) {
            (Some(code), Some(data)) => Placement::Code {
                region: format!("{code}/{data}"),
                shared: true,
            },
            (Some(code), None) => Placement::Code {
                region: code.to_string(),
                shared: false,
            },
            (None, Some(data)) => Placement::Data { region: data },
            (None, None) if containing(Padding).is_some() => Placement::Padding,
            (None, None) => Placement::Unmapped,
        }
    }

    /// The architecture as a container target.
    pub(super) fn target(&self) -> Option<Target> {
        self.architecture.map(|architecture| match architecture {
            Architecture::Xtensa { .. } => Target::new(Isa::Xtensa, 32, Endianness::Little),
            Architecture::RiscV => Target::new(Isa::RiscV32, 32, Endianness::Little),
        })
    }

    /// The Xtensa core, when the configuration header names one.
    pub(super) fn core(&self) -> Option<&'static str> {
        match self.architecture {
            Some(Architecture::Xtensa { core }) => Some(core),
            _ => None,
        }
    }

    /// The flash size a header code stands for.
    pub(super) fn flash_size(&self, code: u8) -> Option<&'static str> {
        lookup(self.flash_sizes, code)
    }

    /// The flash frequency a header code stands for.
    pub(super) fn flash_frequency(&self, code: u8) -> Option<&'static str> {
        lookup(self.flash_frequencies, code)
    }
}

/// Where `address` lies when the chip is not documented: esptool lists
/// the padding region for every ESP32-family chip; anything else has an
/// unknown role.
pub(super) fn undocumented_placement(address: u32) -> Placement {
    if (PADDING.start..PADDING.end).contains(&address) {
        Placement::Padding
    } else {
        Placement::Unknown
    }
}

/// The flash size a header code stands for when the chip is not
/// documented: ESP-IDF `esp_image_flash_size_t` is the same for the whole
/// ESP32 family.
pub(super) fn family_flash_size(code: u8) -> Option<&'static str> {
    lookup(ESP32_FLASH_SIZES, code)
}

fn lookup(table: &[(u8, &'static str)], code: u8) -> Option<&'static str> {
    table
        .iter()
        .find(|(value, _)| *value == code)
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_ids_name_their_architecture() {
        let esp32 = by_id(0x0000).expect("ESP32");
        assert_eq!(esp32.core(), Some("Xtensa LX6"));
        assert_eq!(esp32.bootloader_offset, 0x1000);
        let c3 = by_id(0x0005).expect("ESP32-C3");
        assert_eq!(
            c3.target(),
            Some(Target::new(Isa::RiscV32, 32, Endianness::Little))
        );
        assert_eq!(by_id(0x001F).expect("ESP32-E22").target(), None);
        assert!(by_id(0x0004).is_none());
    }

    #[test]
    fn placement_separates_code_data_and_shared_ranges() {
        let c3 = by_id(0x0005).expect("ESP32-C3");
        assert_eq!(
            c3.placement(0x3C0A_0020),
            Placement::Data { region: "DROM" }
        );
        assert_eq!(
            c3.placement(0x4038_0000),
            Placement::Code {
                region: "IRAM".into(),
                shared: false
            }
        );
        assert_eq!(
            c3.placement(0x5000_0000),
            Placement::Code {
                region: "RTC_IRAM/RTC_DRAM".into(),
                shared: true
            }
        );
        assert_eq!(c3.placement(0), Placement::Padding);
        assert_eq!(c3.placement(0x6000_0000), Placement::Unmapped);
        assert_eq!(ESP8266.placement(0), Placement::Unmapped);
        assert_eq!(undocumented_placement(0x10), Placement::Padding);
        assert_eq!(undocumented_placement(0x4000_0000), Placement::Unknown);
    }

    #[test]
    fn flash_codes_follow_the_chip_tables() {
        let c2 = by_id(0x000C).expect("ESP32-C2");
        assert_eq!(c2.flash_frequency(0xF), Some("60 MHz"));
        assert_eq!(c2.flash_size(0x2), Some("4 MiB"));
        assert_eq!(ESP8266.flash_size(0x2), Some("1 MiB"));
        assert_eq!(ESP8266.flash_size(0x7), None);
    }
}
