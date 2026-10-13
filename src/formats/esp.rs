//! Espressif firmware: application and bootloader images of the ESP32
//! family (24-byte header), ESP8266 version 1 and version 2 images, and
//! whole flash dumps with an ESP-IDF partition table.
//!
//! Sources:
//! - esptool v5.4.0 (`5ac7935ee036`): `esptool/bin_image.py` (image
//!   headers, segments, checksum, appended SHA-256, the ESP8266 v1, v2 and
//!   v3 layouts, `esp8266_crc32`), `esptool/loader.py` (`ESP_IMAGE_MAGIC`,
//!   `ESP_CHECKSUM_MAGIC`), `esptool/cmds.py` (`FLASH_MODES`, `image_info`,
//!   `_parse_app_info`, `_parse_bootloader_info`) and `esptool/targets/*.py`
//!   (`IMAGE_CHIP_ID`, `MEMORY_MAP`, `BOOTLOADER_FLASH_OFFSET`,
//!   `FLASH_SIZES`, `FLASH_FREQUENCY`).
//! - ESP-IDF v5.5.1 (`fcae32885b02`):
//!   `components/bootloader_support/include/esp_app_format.h`
//!   (`esp_image_header_t`, `esp_image_segment_header_t`, `esp_chip_id_t`),
//!   `components/esp_app_format/include/esp_app_desc.h` (`esp_app_desc_t`),
//!   `components/esp_bootloader_format/include/esp_bootloader_desc.h`,
//!   `components/bootloader_support/src/esp_image_format.c` (segment and
//!   checksum checks), `components/bootloader_support/include/esp_flash_partitions.h`
//!   and `src/flash_partitions.c` (partition table records, MD5 record,
//!   terminator), `components/partition_table/gen_esp32part.py`,
//!   `components/partition_table/Kconfig.projbuild` (table offset 0x8000),
//!   `components/bootloader/Kconfig.projbuild` (bootloader offsets),
//!   `Kconfig` (`IDF_TARGET_ARCH_XTENSA`, `IDF_TARGET_ARCH_RISCV`) and
//!   `components/xtensa/<chip>/include/xtensa/config/core-isa.h`
//!   (`XCHAL_HW_VERSION_NAME`, `XCHAL_HAVE_BE`).
//! - ESP-IDF v6.1 (`fff9895c82d7`): `Kconfig` and `esp_app_format.h` for the
//!   ESP32-S31 chip ID and architecture.
//! - `ESP8266_RTOS_SDK` v3.4 (`89a3f254b638`):
//!   `components/esp8266/include/xtensa/config/core-isa.h` (`lx106`).
//!
//! The chip ID of the 24-byte header is an explicit target field: ESP-IDF
//! `Kconfig` names each chip's architecture. The ESP8266 layouts are
//! specific to the ESP8266, whose core is the Xtensa lx106. Segments whose
//! load address lies in a documented instruction range of the chip (IROM,
//! IRAM, RTC IRAM) are load sections for the code model; data segments
//! are listed as opaque. A chip ID that no source documents names no
//! target, and the ISA then comes from the code.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;
use std::fmt::Write;

mod chips;
mod flash;
mod image;

/// First byte of an ESP32-family or ESP8266 version 1 image, and of the
/// second header of a version 2 image (`ESP_IMAGE_MAGIC`).
const IMAGE_MAGIC: u8 = 0xE9;

/// First byte of an ESP8266 version 2 image (`IMAGE_V2_MAGIC`).
const IMAGE_V2_MAGIC: u8 = 0xEA;

/// Prefix of generated and custom metadata keys.
const KEY_PREFIX: &str = "esp";

/// A recognized Espressif layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Application or bootloader image with the 24-byte header of the
    /// ESP32 family (`esp_image_header_t`).
    Image,
    /// ESP8266 version 1 image: the 8-byte common header, then segments.
    Esp8266,
    /// ESP8266 version 2 image: an `0xEA` header, the IROM segment, a
    /// second header and the RAM segments.
    Esp8266V2,
    /// An `0xE9` image that validates both with the 24-byte header and as
    /// an ESP8266 version 1 image; the ISA is not determined and nothing is
    /// analyzed.
    AmbiguousImage,
    /// Flash dump: bootloader, ESP-IDF partition table at 0x8000 and the
    /// partitions it lists.
    Flash,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Image | Self::Esp8266 | Self::Esp8266V2 | Self::AmbiguousImage => {
                FileFormat::EspFirmware
            }
            Self::Flash => FileFormat::EspFlash,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "ESP32-family image",
            Self::Esp8266 => "ESP8266 image (version 1)",
            Self::Esp8266V2 => "ESP8266 image (version 2)",
            Self::AmbiguousImage => "Ambiguous ESP image",
            Self::Flash => "ESP flash dump",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// images have a one-byte magic; the flash dump has a magic on every
    /// partition table record.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Image | Self::Esp8266 | Self::Esp8266V2 | Self::AmbiguousImage => true,
            Self::Flash => false,
        }
    }
}

/// Strong recognition: a flash dump whose partition table at 0x8000 has
/// the record magic on every record up to its terminator.
pub fn detect(data: &[u8]) -> Option<Layout> {
    flash::detect(data).then_some(Layout::Flash)
}

/// Weak recognition of an image: the one-byte magic, every segment inside
/// the file, the checksum, the SHA-256 digest when the header flags one,
/// the entry point inside a loaded segment and only erased flash after the
/// image (see [`image::validate`]).
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    image::validate(data).map(|found| found.layout)
}

/// Parse `data` as the given layout into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::EspParseError`] for a truncated or inconsistent
/// header, segment, checksum, digest or partition table.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Image => image::parse_extended(data),
        Layout::Esp8266 => image::parse_v1(data),
        Layout::Esp8266V2 => image::parse_v2(data),
        Layout::AmbiguousImage => image::parse_ambiguous(data),
        Layout::Flash => flash::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::EspParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at `start`.
fn slice<'a>(data: &'a [u8], what: &str, start: usize, len: usize) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X}: {len} B")))
}

fn array<const N: usize>(data: &[u8], what: &str, at: usize) -> Result<[u8; N]> {
    Ok(slice(data, what, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u16(data: &[u8], what: &str, at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, what, at)?))
}

fn le_u32(data: &[u8], what: &str, at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, what, at)?))
}

/// The value of an erased NOR flash byte.
const ERASED: u8 = 0xFF;

/// Erased flash or zero fill.
fn is_erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(*b, 0x00 | ERASED))
}

/// Erased flash only.
fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == ERASED)
}

/// `"{n} B"`, or `"{n} KiB"` / `"{n} MiB"` when `size` is a whole number
/// of them.
fn size_text(size: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    if size >= MIB && size % MIB == 0 {
        format!("{} MiB", size / MIB)
    } else if size >= KIB && size % KIB == 0 {
        format!("{} KiB", size / KIB)
    } else {
        format!("{size} B")
    }
}

/// A NUL-terminated string field, with bytes outside printable ASCII
/// replaced.
fn c_string(field: &[u8]) -> String {
    field
        .iter()
        .take_while(|b| **b != 0)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

/// Bytes as uppercase hex, without separators.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(text, "{b:02X}").expect("writing to a String cannot fail");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_binary_units_only_when_whole() {
        assert_eq!(size_text(0x1000), "4 KiB");
        assert_eq!(size_text(0x10_0000), "1 MiB");
        assert_eq!(size_text(0x1800), "6 KiB");
        assert_eq!(size_text(100), "100 B");
    }

    #[test]
    fn strings_stop_at_nul_and_replace_unprintable_bytes() {
        assert_eq!(c_string(b"v5.2\0junk"), "v5.2");
        assert_eq!(c_string(b"a\x01b"), "a\u{FFFD}b");
        assert_eq!(c_string(b""), "");
    }

    #[test]
    fn reads_report_the_truncated_offset() {
        let message = le_u32(&[1, 2, 3], "segment header", 1)
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Espressif image parse error: Truncated segment header at 0x1: 4 B"
        );
        assert_eq!(le_u16(&[0x34, 0x12], "chip ID", 0).unwrap(), 0x1234);
    }
}
