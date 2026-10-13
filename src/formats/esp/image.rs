//! Image layouts: the 24-byte header of the ESP32 family and the ESP8266
//! version 1 and version 2 layouts.
//!
//! Layouts: esptool `bin_image.py` (`ESP32FirmwareImage`,
//! `ESP8266ROMFirmwareImage`, `ESP8266V2FirmwareImage`,
//! `ESP8266V3FirmwareImage.save`, `esp8266_crc32`); ESP-IDF
//! `esp_app_format.h` and `esp_image_format.c` (segment length rules,
//! checksum position). Descriptors: ESP-IDF `esp_app_desc.h` and
//! `esp_bootloader_desc.h`; both start segment 0 (`esp_image_format.c`:
//! "always in segment #0"; `bin_image.py` moves `.dram0.bootdesc` "to the
//! top of the binary at 0x20 offset").

use super::*;
use crate::formats::checksum;
use crate::formats::container::{Child, Section};
use crate::types::MetadataValue;
use chips::{Chip, Placement};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// Common header: magic, segment count, SPI mode, flash size and
/// frequency, entry point.
const COMMON_HEADER_SIZE: usize = 8;

/// The ESP32-family header: the common header and the 16-byte extended
/// header (`esp_image_header_t`).
const EXTENDED_HEADER_SIZE: usize = 24;

/// Segment header: load address and data length.
const SEGMENT_HEADER_SIZE: usize = 8;

/// `ESP_IMAGE_MAX_SEGMENTS`.
const MAX_SEGMENTS: u8 = 16;

/// Segment lengths stay below 16 MiB (`ESP_IMAGE_MAX_FLASH_ADDR_SIZE`).
const MAX_SEGMENT_SIZE: u32 = 0x100_0000;

/// Segment lengths are multiples of 4 (`verify_segment_header`).
const SEGMENT_ALIGN: u32 = 4;

/// `ESP_CHECKSUM_MAGIC`: the seed of the XOR checksum.
const CHECKSUM_SEED: u8 = 0xEF;

/// The checksum is the last byte of a 16-byte block of the image.
const CHECKSUM_BLOCK: usize = 16;

/// Appended SHA-256 digest.
const DIGEST_SIZE: usize = 32;

/// Trailing CRC-32 of an ESP8266 version 2 image.
const CRC_SIZE: usize = 4;

/// `esp8266_crc32` inverts a CRC with this bit set and increments others.
const CRC_TOP_BIT: u32 = 0x8000_0000;

/// `WP_PIN_DISABLED`.
const WP_PIN_DISABLED: u8 = 0xEE;

/// `ESP_APP_DESC_MAGIC_WORD`.
const APP_DESC_MAGIC: u32 = 0xABCD_5432;

/// `sizeof(esp_app_desc_t)`.
const APP_DESC_SIZE: usize = 256;

/// `ESP_BOOTLOADER_DESC_MAGIC_BYTE` (80).
const BOOTLOADER_DESC_MAGIC: u8 = 0x50;

/// `sizeof(esp_bootloader_desc_t)`.
const BOOTLOADER_DESC_SIZE: usize = 80;

/// `esp_image_spi_mode_t`.
const SPI_MODES: [&str; 6] = ["QIO", "QOUT", "DIO", "DOUT", "FAST_READ", "SLOW_READ"];

/// The fields every image header starts with (`load_common_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommonHeader {
    segment_count: u8,
    spi_mode: u8,
    /// Flash size code in the high nibble, frequency code in the low one.
    flash_size_frequency: u8,
    entry: u32,
}

/// The extended header of the ESP32 family (bytes 8-23).
#[derive(Debug, Clone, Copy)]
struct ExtendedHeader {
    wp_pin: u8,
    /// Six 4-bit drive settings, two per byte: clk and q, d and cs0, hd and
    /// wp, low nibble first.
    pin_drive: [u8; 3],
    chip_id: u16,
    /// Legacy minimum revision (`min_chip_rev`).
    min_revision: u8,
    /// `major * 100 + minor`.
    min_revision_full: u16,
    /// `major * 100 + minor`.
    max_revision_full: u16,
    hash_appended: bool,
}

/// One stored segment.
#[derive(Debug, Clone, Copy)]
struct Segment {
    /// Load address; the ESP8266 version 2 IROM segment stores 0.
    address: u32,
    /// File offset of the data.
    offset: usize,
    /// Data length in bytes.
    size: usize,
}

impl Segment {
    /// The segment's data in `data`, which [`read_segment`] bounds-checked.
    fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.offset..self.offset + self.size)
            .unwrap_or_default()
    }
}

/// The segments a header counts and the offset after the last one.
#[derive(Debug)]
struct Walk {
    segments: Vec<Segment>,
    end: usize,
}

/// A validated image: its layout and its size in bytes, from offset 0
/// through the checksum and any digest or CRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Found {
    /// The layout.
    pub(super) layout: Layout,
    /// Image size in bytes.
    pub(super) size: usize,
}

/// What follows the checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Integrity {
    /// Nothing.
    None,
    /// A SHA-256 digest of the image, verified.
    Sha256 { offset: usize },
    /// The ESP8266 version 2 CRC-32 of the image, verified.
    Crc32 { value: u32 },
}

/// A validated image.
#[derive(Debug)]
struct Image {
    layout: Layout,
    /// The header that describes the loaded segments (the second header of
    /// a version 2 image).
    header: CommonHeader,
    extended: Option<ExtendedHeader>,
    /// The first header of a version 2 image.
    first_header: Option<CommonHeader>,
    /// The IROM segment of a version 2 image (not in the checksum).
    irom: Option<Segment>,
    segments: Vec<Segment>,
    checksum: u8,
    integrity: Integrity,
    /// End of the image: after the checksum and any digest or CRC.
    end: usize,
}

/// The layout of an image at the start of `data` and the image size, when
/// every check passes. An `0xE9` image that validates with both header
/// sizes is ambiguous.
pub(super) fn validate(data: &[u8]) -> Option<Found> {
    let found = |layout, size| Found { layout, size };
    match data.first().copied()? {
        IMAGE_V2_MAGIC => read_v2(data)
            .ok()
            .map(|image| found(Layout::Esp8266V2, image.end)),
        IMAGE_MAGIC => match (read_extended(data), read_v1(data)) {
            (Ok(image), Err(_)) => Some(found(Layout::Image, image.end)),
            (Err(_), Ok(image)) => Some(found(Layout::Esp8266, image.end)),
            (Ok(extended), Ok(v1)) => Some(found(Layout::AmbiguousImage, extended.end.max(v1.end))),
            (Err(_), Err(_)) => None,
        },
        _ => None,
    }
}

/// The chip an image of `layout` at the start of `data` is built for.
pub(super) fn chip(data: &[u8], layout: Layout) -> Option<&'static Chip> {
    match layout {
        Layout::Image => extended_header(data)
            .ok()
            .and_then(|extended| chips::by_id(extended.chip_id)),
        Layout::Esp8266 | Layout::Esp8266V2 => Some(&chips::ESP8266),
        Layout::AmbiguousImage | Layout::Flash => None,
    }
}

/// Parse an image with the 24-byte ESP32-family header.
pub(super) fn parse_extended(data: &[u8]) -> Result<Container<'_>> {
    let image = read_extended(data)?;
    let chip = image.extended.and_then(|e| chips::by_id(e.chip_id));
    Ok(build(data, &image, chip))
}

/// Parse an ESP8266 version 1 image.
pub(super) fn parse_v1(data: &[u8]) -> Result<Container<'_>> {
    let image = read_v1(data)?;
    Ok(build(data, &image, Some(&chips::ESP8266)))
}

/// Parse an ESP8266 version 2 image.
pub(super) fn parse_v2(data: &[u8]) -> Result<Container<'_>> {
    let image = read_v2(data)?;
    Ok(build(data, &image, Some(&chips::ESP8266)))
}

/// An image that validates with both header sizes: listed with both
/// readings, with no target and nothing analyzed.
pub(super) fn parse_ambiguous(data: &[u8]) -> Result<Container<'_>> {
    let extended = read_extended(data)?;
    let v1 = read_v1(data)?;
    let chip_id = extended.extended.map_or(0, |e| e.chip_id);
    let mut c = Container::new(
        FileFormat::EspFirmware,
        Layout::AmbiguousImage.label(),
        KEY_PREFIX,
    );
    c.consumed = extended.end.max(v1.end);
    c.notes.push(format!(
        "Validates as an ESP32-family image ({} segments, chip ID 0x{chip_id:04X}) and as an \
         ESP8266 version 1 image ({} segments); the layout and ISA are not determined and \
         nothing is analyzed",
        extended.segments.len(),
        v1.segments.len()
    ));
    Ok(c)
}

/// Read the 24-byte header, the segments, the checksum and the digest the
/// header flags.
fn read_extended(data: &[u8]) -> Result<Image> {
    let header = common_header(data, 0, IMAGE_MAGIC)?;
    let extended = extended_header(data)?;
    let mut computed = CHECKSUM_SEED;
    let walk = read_segments(
        data,
        EXTENDED_HEADER_SIZE,
        header.segment_count,
        &mut computed,
    )?;
    let checksum_offset = checksum_offset(walk.end);
    let checksum = verify_checksum(data, checksum_offset, computed)?;
    let mut end = checksum_offset + 1;
    let integrity = if extended.hash_appended {
        verify_digest(data, end)?;
        end += DIGEST_SIZE;
        Integrity::Sha256 {
            offset: checksum_offset + 1,
        }
    } else {
        Integrity::None
    };
    check_entry(header.entry, &walk.segments)?;
    check_trailing(data, end, integrity)?;
    Ok(Image {
        layout: Layout::Image,
        header,
        extended: Some(extended),
        first_header: None,
        irom: None,
        segments: walk.segments,
        checksum,
        integrity,
        end,
    })
}

/// Read an ESP8266 version 1 image: the common header, the segments and
/// the checksum. esptool's version 3 writer (`ESP8266V3FirmwareImage`)
/// uses the same header and appends a SHA-256 digest, which is accepted
/// when it matches.
fn read_v1(data: &[u8]) -> Result<Image> {
    let header = common_header(data, 0, IMAGE_MAGIC)?;
    let mut computed = CHECKSUM_SEED;
    let walk = read_segments(
        data,
        COMMON_HEADER_SIZE,
        header.segment_count,
        &mut computed,
    )?;
    let checksum_offset = checksum_offset(walk.end);
    let checksum = verify_checksum(data, checksum_offset, computed)?;
    let mut end = checksum_offset + 1;
    let integrity = if has_digest(data, end) {
        end += DIGEST_SIZE;
        Integrity::Sha256 {
            offset: checksum_offset + 1,
        }
    } else {
        Integrity::None
    };
    check_entry(header.entry, &walk.segments)?;
    check_trailing(data, end, integrity)?;
    Ok(Image {
        layout: Layout::Esp8266,
        header,
        extended: None,
        first_header: None,
        irom: None,
        segments: walk.segments,
        checksum,
        integrity,
        end,
    })
}

/// Read an ESP8266 version 2 image: the `0xEA` header, the IROM segment,
/// the second (`0xE9`) header, the RAM segments, the checksum over the RAM
/// segments and the CRC-32 that esptool appends to every version 2 image.
fn read_v2(data: &[u8]) -> Result<Image> {
    let first_header = common_header(data, 0, IMAGE_V2_MAGIC)?;
    let irom = read_segment(data, COMMON_HEADER_SIZE, "IROM segment")?;
    let second_at = irom.offset + irom.size;
    let header = common_header(data, second_at, IMAGE_MAGIC)?;
    let mut computed = CHECKSUM_SEED;
    let walk = read_segments(
        data,
        second_at + COMMON_HEADER_SIZE,
        header.segment_count,
        &mut computed,
    )?;
    let checksum_offset = checksum_offset(walk.end);
    let checksum = verify_checksum(data, checksum_offset, computed)?;
    let crc_offset = checksum_offset + 1;
    let value = verify_crc(data, crc_offset)?;
    let end = crc_offset + CRC_SIZE;
    let integrity = Integrity::Crc32 { value };
    check_entry(header.entry, &walk.segments)?;
    check_trailing(data, end, integrity)?;
    Ok(Image {
        layout: Layout::Esp8266V2,
        header,
        extended: None,
        first_header: Some(first_header),
        irom: Some(irom),
        segments: walk.segments,
        checksum,
        integrity,
        end,
    })
}

/// The common header at `at`, whose first byte must be `magic`.
fn common_header(data: &[u8], at: usize, magic: u8) -> Result<CommonHeader> {
    let header: [u8; COMMON_HEADER_SIZE] = array(data, "image header", at)?;
    if header[0] != magic {
        return Err(error(format!(
            "Invalid image magic 0x{:02X} at 0x{at:X} (expected 0x{magic:02X})",
            header[0]
        )));
    }
    Ok(CommonHeader {
        segment_count: header[1],
        spi_mode: header[2],
        flash_size_frequency: header[3],
        entry: le_u32(&header, "entry point", 4)?,
    })
}

/// The extended header at bytes 8-23: WP pin, pin drive settings, chip
/// ID, legacy minimum revision, minimum and maximum full revisions, four
/// reserved bytes and `hash_appended`, which esptool accepts only as 0 or
/// 1.
fn extended_header(data: &[u8]) -> Result<ExtendedHeader> {
    let header = slice(
        data,
        "extended header",
        COMMON_HEADER_SIZE,
        EXTENDED_HEADER_SIZE - COMMON_HEADER_SIZE,
    )?;
    let hash_appended = match header[15] {
        0 => false,
        1 => true,
        other => {
            return Err(error(format!(
                "Invalid hash_appended 0x{other:02X} at 0x17 (expected 0 or 1)"
            )))
        }
    };
    Ok(ExtendedHeader {
        wp_pin: header[0],
        pin_drive: [header[1], header[2], header[3]],
        chip_id: le_u16(header, "chip ID", 4)?,
        min_revision: header[6],
        min_revision_full: le_u16(header, "minimum chip revision", 7)?,
        max_revision_full: le_u16(header, "maximum chip revision", 9)?,
        hash_appended,
    })
}

/// `count` segments from `start`, with the XOR of their data folded into
/// `checksum`, and the offset after the last one.
fn read_segments(data: &[u8], start: usize, count: u8, checksum: &mut u8) -> Result<Walk> {
    if count == 0 || count > MAX_SEGMENTS {
        return Err(error(format!(
            "Invalid segment count {count} (1 to {MAX_SEGMENTS})"
        )));
    }
    let mut segments = Vec::with_capacity(usize::from(count));
    let mut pos = start;
    for index in 0..count {
        let segment = read_segment(data, pos, &format!("segment {index}"))?;
        *checksum = segment.bytes(data).iter().fold(*checksum, |sum, b| sum ^ b);
        pos = segment.offset + segment.size;
        segments.push(segment);
    }
    Ok(Walk { segments, end: pos })
}

/// The segment whose header is at `at`: its length must be a multiple of
/// 4 below 16 MiB, and its data must lie in the file.
fn read_segment(data: &[u8], at: usize, what: &str) -> Result<Segment> {
    let header_name = format!("{what} header");
    let address = le_u32(data, &header_name, at)?;
    let size = le_u32(data, &header_name, at + 4)?;
    if size % SEGMENT_ALIGN != 0 {
        return Err(error(format!(
            "Invalid {what} length 0x{size:X} at 0x{at:X}: not a multiple of {SEGMENT_ALIGN}"
        )));
    }
    if size >= MAX_SEGMENT_SIZE {
        return Err(error(format!(
            "Invalid {what} length 0x{size:X} at 0x{at:X}: 16 MiB or more"
        )));
    }
    let offset = at + SEGMENT_HEADER_SIZE;
    let size = usize::try_from(size).map_err(|_| error(format!("Invalid {what} length")))?;
    slice(data, what, offset, size)?;
    Ok(Segment {
        address,
        offset,
        size,
    })
}

/// The checksum offset for segments ending at `segments_end`: the last
/// byte of the 16-byte block (`align_file_position`, `process_checksum`).
fn checksum_offset(segments_end: usize) -> usize {
    segments_end + (CHECKSUM_BLOCK - 1 - segments_end % CHECKSUM_BLOCK)
}

/// The stored checksum at `offset`, which must equal `computed`.
fn verify_checksum(data: &[u8], offset: usize, computed: u8) -> Result<u8> {
    let stored = *data
        .get(offset)
        .ok_or_else(|| error(format!("Truncated checksum at 0x{offset:X}")))?;
    if stored != computed {
        return Err(error(format!(
            "Invalid image checksum 0x{stored:02X} at 0x{offset:X} (computed 0x{computed:02X})"
        )));
    }
    Ok(stored)
}

/// The SHA-256 digest at `end` must hash `data[..end]`.
fn verify_digest(data: &[u8], end: usize) -> Result<()> {
    let stored = slice(data, "SHA-256 digest", end, DIGEST_SIZE)?;
    if Sha256::digest(&data[..end]).as_slice() != stored {
        return Err(error(format!("Invalid SHA-256 digest at 0x{end:X}")));
    }
    Ok(())
}

/// Whether a SHA-256 digest of `data[..end]` follows at `end`.
fn has_digest(data: &[u8], end: usize) -> bool {
    verify_digest(data, end).is_ok()
}

/// The CRC-32 at `end`, which must be `esp8266_crc32` of `data[..end]`.
fn verify_crc(data: &[u8], end: usize) -> Result<u32> {
    let stored = le_u32(data, "CRC-32", end)?;
    let computed = esp8266_crc32(&data[..end]);
    if stored != computed {
        return Err(error(format!(
            "Invalid CRC-32 0x{stored:08X} at 0x{end:X} (computed 0x{computed:08X})"
        )));
    }
    Ok(stored)
}

/// The CRC-32 the ESP8266 SDK bootloader checks (`esp8266_crc32`): the
/// IEEE CRC-32, inverted when its top bit is set and incremented
/// otherwise.
fn esp8266_crc32(bytes: &[u8]) -> u32 {
    let crc = checksum::crc32(bytes);
    if crc & CRC_TOP_BIT != 0 {
        !crc
    } else {
        crc + 1
    }
}

/// The entry point must lie in a segment with a load address; a header
/// that points elsewhere is not an image the boot ROM can start.
fn check_entry(entry: u32, segments: &[Segment]) -> Result<()> {
    let entry = u64::from(entry);
    let inside = segments.iter().any(|s| {
        let start = u64::from(s.address);
        s.address != 0 && (start..start + s.size as u64).contains(&entry)
    });
    if inside {
        Ok(())
    } else {
        Err(error(format!(
            "Invalid entry point 0x{entry:08X}: outside every segment"
        )))
    }
}

/// Bytes after the image must be erased flash, unless a verified digest or
/// CRC ends the image: a one-byte checksum alone does not establish where
/// an image ends.
fn check_trailing(data: &[u8], end: usize, integrity: Integrity) -> Result<()> {
    let rest = &data[end..];
    if is_erased(rest) || integrity != Integrity::None {
        return Ok(());
    }
    Err(error(format!(
        "Invalid data after the image at 0x{end:X}: {} B that are not erased flash",
        rest.len()
    )))
}

/// The container for a validated image.
fn build<'a>(data: &'a [u8], image: &Image, chip: Option<&'static Chip>) -> Container<'a> {
    let variant = chip.and_then(Chip::core).unwrap_or(image.layout.label());
    let mut c = Container::new(FileFormat::EspFirmware, variant, KEY_PREFIX);
    c.target = chip.and_then(Chip::target);
    c.entry = Some(u64::from(image.header.entry));
    c.code_sections = true;
    c.consumed = image.end;
    c.notes.push(chip_note(image, chip));
    if let Some(segment) = image.segments.first() {
        push_descriptor(&mut c, data, image, segment);
    }
    push_flash(&mut c, image, chip);
    if let Some(extended) = image.extended {
        push_extended(&mut c, &extended, chip);
    }
    push_integrity(&mut c, data, image);
    push_segments(&mut c, data, image, chip);
    push_trailing(&mut c, data, image);
    c
}

fn chip_note(image: &Image, chip: Option<&Chip>) -> String {
    let Some(extended) = image.extended else {
        let version = match image.layout {
            Layout::Esp8266V2 => 2,
            _ => 1,
        };
        return format!(
            "ESP8266 version {version} image; esptool defines this layout only for the ESP8266 \
             (Xtensa lx106)"
        );
    };
    let id = extended.chip_id;
    match chip {
        Some(chip) => match chip.architecture {
            Some(chips::Architecture::Xtensa { core }) => {
                format!("{} image (chip ID 0x{id:04X}); {core}", chip.name)
            }
            Some(chips::Architecture::RiscV) => {
                format!("{} image (chip ID 0x{id:04X}); 32-bit RISC-V", chip.name)
            }
            None => format!(
                "{} image (chip ID 0x{id:04X}); no ESP-IDF release names its architecture, so \
                 the ISA comes from the code",
                chip.name
            ),
        },
        None => format!(
            "Chip ID 0x{id:04X} is not a documented chip; memory roles are unknown and the ISA \
             comes from the code"
        ),
    }
}

/// The application descriptor (any layout) or the bootloader descriptor
/// (24-byte header) at the start of segment 0.
fn push_descriptor(c: &mut Container<'_>, data: &[u8], image: &Image, segment: &Segment) {
    let bytes = segment.bytes(data);
    if let Some(app) = bytes
        .get(..APP_DESC_SIZE)
        .filter(|app| le_u32(app, "application descriptor", 0).ok() == Some(APP_DESC_MAGIC))
    {
        push_app_descriptor(c, app);
    } else if image.extended.is_some() {
        if let Some(desc) = bytes.get(..BOOTLOADER_DESC_SIZE) {
            push_bootloader_descriptor(c, desc);
        }
    }
}

/// `esp_app_desc_t`: magic, secure version (4), reserved (8), version
/// (0x10, 32), project name (0x30, 32), time (0x50, 16), date (0x60, 16),
/// ESP-IDF version (0x70, 32), ELF SHA-256 (0x90, 32), eFuse block
/// revisions (0xB0, 0xB2), MMU page size as log2 (0xB4).
fn push_app_descriptor(c: &mut Container<'_>, app: &[u8]) {
    let field = |at: usize, len: usize| c_string(&app[at..at + len]);
    let version = field(0x10, 32);
    let project = field(0x30, 32);
    let time = field(0x50, 16);
    let date = field(0x60, 16);
    let idf = field(0x70, 32);
    let secure_version = u32::from_le_bytes(app[4..8].try_into().expect("four bytes"));
    let mmu_page_log2 = app[0xB4];
    let mut facts = vec!["ESP-IDF application descriptor".to_string()];
    let named = [
        ("project", &project),
        ("version", &version),
        ("ESP-IDF", &idf),
    ];
    for (name, value) in named {
        if !value.is_empty() {
            facts.push(format!("{name} {value}"));
        }
    }
    let compiled = format!("{date} {time}");
    if !compiled.trim().is_empty() {
        facts.push(format!("compiled {}", compiled.trim()));
    }
    c.notes.push(facts.join("; "));
    let key = |name: &str| format!("{KEY_PREFIX}_app_{name}");
    c.push_metadata(key("project_name"), "Project name", project);
    c.push_metadata(key("version"), "Application version", version);
    c.push_metadata(key("idf_version"), "ESP-IDF version", idf);
    c.push_metadata(key("compile_date"), "Compile date", date);
    c.push_metadata(key("compile_time"), "Compile time", time);
    c.push_metadata(
        key("secure_version"),
        "Secure version",
        u64::from(secure_version),
    );
    c.push_metadata(
        key("elf_sha256"),
        "ELF SHA-256 (stored, not verified)",
        hex(&app[0x90..0xB0]),
    );
    if (1..32).contains(&mmu_page_log2) {
        c.push_metadata(
            key("mmu_page_size"),
            "MMU page size",
            size_text(1u64 << mmu_page_log2),
        );
    }
}

/// `esp_bootloader_desc_t`: magic byte 80, reserved (1, 2), secure
/// version (3), version (4), ESP-IDF version (8, 32), date and time (0x28,
/// 24). The magic is one byte, so both strings must also be printable and
/// NUL-terminated.
fn push_bootloader_descriptor(c: &mut Container<'_>, desc: &[u8]) {
    if desc[0] != BOOTLOADER_DESC_MAGIC {
        return;
    }
    let (Some(idf), Some(built)) = (
        terminated_text(&desc[0x08..0x28]),
        terminated_text(&desc[0x28..0x40]),
    ) else {
        return;
    };
    let version = u32::from_le_bytes(desc[4..8].try_into().expect("four bytes"));
    c.notes.push(format!(
        "ESP-IDF bootloader descriptor; version {version}; ESP-IDF {idf}; compiled {built}"
    ));
    let key = |name: &str| format!("{KEY_PREFIX}_bootloader_{name}");
    c.push_metadata(key("version"), "Bootloader version", u64::from(version));
    c.push_metadata(key("idf_version"), "ESP-IDF version", idf);
    c.push_metadata(key("compile_time"), "Compile date and time", built);
    c.push_metadata(
        key("secure_version"),
        "Bootloader secure version",
        u64::from(desc[3]),
    );
}

/// A non-empty, printable, NUL-terminated string field.
fn terminated_text(field: &[u8]) -> Option<String> {
    let len = field.iter().position(|b| *b == 0)?;
    let text = &field[..len];
    let printable = !text.is_empty() && text.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    printable.then(|| c_string(text))
}

/// SPI mode, flash size and frequency of the header.
fn push_flash(c: &mut Container<'_>, image: &Image, chip: Option<&Chip>) {
    let header = image.header;
    let mode = SPI_MODES.get(usize::from(header.spi_mode)).map_or_else(
        || format!("mode 0x{:02X}", header.spi_mode),
        |m| format!("{m} mode"),
    );
    let size_code = header.flash_size_frequency >> 4;
    let frequency_code = header.flash_size_frequency & 0x0F;
    let size = match chip {
        Some(chip) => chip.flash_size(size_code),
        None => chips::family_flash_size(size_code),
    }
    .map_or_else(|| format!("size code 0x{size_code:X}"), str::to_string);
    let frequency = chip
        .and_then(|chip| chip.flash_frequency(frequency_code))
        .map_or_else(
            || format!("frequency code 0x{frequency_code:X}"),
            str::to_string,
        );
    c.notes
        .push(format!("SPI flash: {mode}, {size}, {frequency}"));
    if let Some(first) = image.first_header {
        if (first.spi_mode, first.flash_size_frequency)
            != (header.spi_mode, header.flash_size_frequency)
        {
            c.notes.push(
                "The two headers give different flash parameters; the second is used, as \
                 esptool does"
                    .into(),
            );
        }
    }
    c.push_metadata(format!("{KEY_PREFIX}_spi_mode"), "SPI flash mode", mode);
    c.push_metadata(format!("{KEY_PREFIX}_flash_size"), "Flash size", size);
    c.push_metadata(
        format!("{KEY_PREFIX}_flash_frequency"),
        "Flash frequency",
        frequency,
    );
}

/// Chip ID, revisions, WP pin and pin drive settings.
fn push_extended(c: &mut Container<'_>, extended: &ExtendedHeader, chip: Option<&Chip>) {
    let revision = |full: u16| format!("v{}.{}", full / 100, full % 100);
    c.notes.push(format!(
        "Chip revision {} to {} (legacy minimum {})",
        revision(extended.min_revision_full),
        revision(extended.max_revision_full),
        extended.min_revision
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_chip_id"),
        "Chip ID",
        MetadataValue::Hex(u32::from(extended.chip_id)),
    );
    if let Some(chip) = chip {
        c.push_metadata(format!("{KEY_PREFIX}_chip"), "Chip", chip.name);
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_min_chip_revision"),
        "Minimum chip revision",
        revision(extended.min_revision_full),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_max_chip_revision"),
        "Maximum chip revision",
        revision(extended.max_revision_full),
    );
    let wp_pin = if extended.wp_pin == WP_PIN_DISABLED {
        format!("0x{:02X} (disabled)", extended.wp_pin)
    } else {
        format!("0x{:02X}", extended.wp_pin)
    };
    c.push_metadata(format!("{KEY_PREFIX}_wp_pin"), "WP pin", wp_pin);
    let [clk_q, d_cs, hd_wp] = extended.pin_drive;
    let nibbles = |b: u8| (b & 0x0F, b >> 4);
    let ((clk, q), (d, cs0), (hd, wp)) = (nibbles(clk_q), nibbles(d_cs), nibbles(hd_wp));
    c.push_metadata(
        format!("{KEY_PREFIX}_spi_pin_drive"),
        "SPI pin drive settings",
        format!("clk {clk}, q {q}, d {d}, cs0 {cs0}, hd {hd}, wp {wp}"),
    );
}

/// The checksum and the digest or CRC after it.
fn push_integrity(c: &mut Container<'_>, data: &[u8], image: &Image) {
    let checksum = image.checksum;
    let scope = if image.irom.is_some() {
        " (IROM segment excluded, as esptool computes it)"
    } else {
        ""
    };
    let trailer = match image.integrity {
        Integrity::Sha256 { offset } => {
            c.push_metadata(
                format!("{KEY_PREFIX}_sha256"),
                "SHA-256 digest (verified)",
                hex(&data[offset..offset + DIGEST_SIZE]),
            );
            "SHA-256 digest verified".to_string()
        }
        Integrity::Crc32 { value } => {
            c.push_metadata(
                format!("{KEY_PREFIX}_crc32"),
                "CRC-32 (verified)",
                MetadataValue::Hex(value),
            );
            format!("CRC-32 0x{value:08X} verified")
        }
        Integrity::None => "no SHA-256 digest appended".into(),
    };
    c.notes.push(format!(
        "Checksum 0x{checksum:02X} verified{scope}; {trailer}"
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_checksum"),
        "Checksum (verified)",
        MetadataValue::Hex(u32::from(checksum)),
    );
}

/// Segments in instruction regions become load sections; data and
/// unmapped segments become opaque children; padding is only counted.
fn push_segments<'a>(c: &mut Container<'a>, data: &'a [u8], image: &Image, chip: Option<&Chip>) {
    let mut tally = Tally::default();
    if let Some(irom) = image.irom {
        c.notes.push(format!(
            "IROM segment at 0x{:X}: {}; mapped from flash at an address that depends on where \
             the image is written",
            irom.offset,
            size_text(irom.size as u64)
        ));
        let placement = Placement::Code {
            region: "IROM".into(),
            shared: false,
        };
        let names = SegmentNames {
            label: "IROM segment".into(),
            key: "irom".into(),
        };
        push_segment(c, data, &names, &irom, &placement, &mut tally);
    }
    for (index, segment) in image.segments.iter().enumerate() {
        let placement = match chip {
            Some(chip) => chip.placement(segment.address),
            None => chips::undocumented_placement(segment.address),
        };
        let names = SegmentNames {
            label: format!("Segment {index}"),
            key: index.to_string(),
        };
        push_segment(c, data, &names, segment, &placement, &mut tally);
    }
    c.notes.push(tally.summary());
    if tally.shared {
        c.notes.push(format!(
            "On the {} instruction and data addresses coincide; segments there are analyzed as \
             code although they may hold data",
            chip.map_or("chip", |chip| chip.name)
        ));
    }
}

/// Segment counts by role, for the summary note.
#[derive(Default)]
struct Tally {
    code: usize,
    code_regions: Vec<String>,
    data: usize,
    data_regions: Vec<String>,
    padding: usize,
    shared: bool,
}

impl Tally {
    fn add_code(&mut self, region: &str) {
        self.code += 1;
        add_region(&mut self.code_regions, region);
    }

    fn add_data(&mut self, region: &str) {
        self.data += 1;
        add_region(&mut self.data_regions, region);
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.code > 0 {
            parts.push(format!(
                "{} analyzed as code ({})",
                self.code,
                self.code_regions.join(", ")
            ));
        }
        if self.data > 0 {
            parts.push(format!(
                "{} listed as opaque ({})",
                self.data,
                self.data_regions.join(", ")
            ));
        }
        if self.padding > 0 {
            parts.push(format!("{} padding, not loaded", self.padding));
        }
        format!("Segments: {}", parts.join("; "))
    }
}

/// Add `region` to `regions` once, in first-seen order.
fn add_region(regions: &mut Vec<String>, region: &str) {
    if !regions.iter().any(|r| r == region) {
        regions.push(region.to_string());
    }
}

/// How a segment is named in labels and metadata keys.
struct SegmentNames {
    /// Display label (`Segment 2`).
    label: String,
    /// Metadata key suffix (`2`).
    key: String,
}

/// One segment as a section, an opaque child or a padding count, with its
/// metadata entry.
fn push_segment<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    names: &SegmentNames,
    segment: &Segment,
    placement: &Placement,
    tally: &mut Tally,
) {
    let bytes = segment.bytes(data);
    let (region, role) = match placement {
        Placement::Code { region, shared } => {
            tally.shared |= *shared;
            tally.add_code(region);
            (region.clone(), "code")
        }
        Placement::Unknown => {
            tally.add_code("role unknown");
            ("role unknown".into(), "code")
        }
        Placement::Data { region } => {
            tally.add_data(region);
            ((*region).to_string(), "opaque data")
        }
        Placement::Unmapped => {
            tally.add_data("unmapped");
            ("unmapped".into(), "opaque")
        }
        Placement::Padding => {
            tally.padding += 1;
            ("padding".into(), "not loaded")
        }
    };
    let name = format!("{} ({region})", names.label);
    match placement {
        Placement::Code { .. } | Placement::Unknown => c.sections.push(Section {
            label: name.clone(),
            address: u64::from(segment.address),
            offset: segment.offset,
            stored_size: segment.size,
            data: Cow::Borrowed(bytes),
            transform: None,
        }),
        Placement::Data { .. } | Placement::Unmapped => {
            c.children
                .push(Child::opaque(name.clone(), segment.offset, bytes));
        }
        Placement::Padding => {}
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_segment_{}", names.key),
        name,
        format!(
            "file 0x{:X}; load 0x{:08X}; {} B; {role}",
            segment.offset, segment.address, segment.size
        ),
    );
}

/// Bytes after the image: erased flash is noted; anything else (allowed
/// only after a verified digest or CRC) is an opaque child.
fn push_trailing<'a>(c: &mut Container<'a>, data: &'a [u8], image: &Image) {
    let rest = &data[image.end..];
    if rest.is_empty() {
        return;
    }
    if is_erased(rest) {
        c.notes.push(format!(
            "{} of erased flash after the image",
            size_text(rest.len() as u64)
        ));
        return;
    }
    let signature = if image.extended.is_some() {
        "; ESP-IDF appends secure boot signatures after the digest (esp_app_format.h)"
    } else {
        ""
    };
    c.notes.push(format!(
        "{} after the image at 0x{:X} are not parsed or verified{signature}",
        size_text(rest.len() as u64),
        image.end
    ));
    c.children
        .push(Child::opaque("Data after the image", image.end, rest));
    c.consumed = data.len();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_ends_each_16_byte_block() {
        assert_eq!(checksum_offset(24), 31);
        assert_eq!(checksum_offset(31), 31);
        assert_eq!(checksum_offset(32), 47);
    }

    #[test]
    fn esp8266_crc_inverts_or_increments() {
        // IEEE CRC-32 of "123456789" is 0xCBF43926: top bit set, inverted.
        assert_eq!(esp8266_crc32(b"123456789"), 0xCBF4_3926 ^ 0xFFFF_FFFF);
        // CRC-32 of the empty message is 0: incremented.
        assert_eq!(esp8266_crc32(b""), 1);
    }

    #[test]
    fn entry_must_be_inside_a_loaded_segment() {
        let segment = Segment {
            address: 0x4008_0000,
            offset: 0x20,
            size: 0x10,
        };
        assert!(check_entry(0x4008_000C, &[segment]).is_ok());
        assert!(check_entry(0x4008_0010, &[segment]).is_err());
        let padding = Segment {
            address: 0,
            offset: 0x20,
            size: 0x10,
        };
        assert!(check_entry(0x4, &[padding]).is_err());
    }
}
