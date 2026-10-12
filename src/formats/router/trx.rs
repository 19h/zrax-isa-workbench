//! Broadcom TRX (`OpenWrt` firmware-utils `trx.c`, `otrx.c` and `asustrx.c`;
//! partition roles from Linux v6.12 `drivers/mtd/parsers/parser_trx.c`;
//! flag names from Broadcom `include/trxhdr.h`).
//!
//! Header, all fields little-endian: magic `HDR0` (0), image length
//! including the header (4), CRC-32 (8), flags (12, 16 bits), version (14,
//! 16 bits), then partition offsets from the start of the header: three in
//! version 1 (28-byte header) and four in version 2 as `trx -2` writes it
//! (32-byte header; the fourth partition is a Cybertan code header).
//! Broadcom's dongle `trxhdr.h` defines a 36-byte version 2 header with
//! five offsets; its fifth offset is not read here, and a first partition
//! right after 36 bytes is noted.

use super::*;
use crate::formats::checksum;

/// `HDR0` (`TRX_MAGIC` `0x30524448`, little-endian).
pub(super) const MAGIC: [u8; 4] = *b"HDR0";

/// Header fields.
const LENGTH: usize = 4;
const CRC: usize = 8;
const FLAGS: usize = 12;
const VERSION: usize = 14;
const OFFSETS: usize = 16;

/// The CRC covers the image from the flags/version word to its length
/// ("32-bit CRC from `flag_version` to end of file").
const CRC_START: usize = FLAGS;

/// `sizeof(struct trx_header) - 4` for version 1 in `trx.c`, and the full
/// structure with `offsets[4]` for version 2.
const V1_HEADER_SIZE: usize = 28;
const V2_HEADER_SIZE: usize = 32;
const V1_OFFSETS: usize = 3;
const V2_OFFSETS: usize = 4;

/// Broadcom's dongle `trxhdr.h` (`BCMTRXV2`, `TRX_V2_MAX_OFFSETS 5`) makes
/// the version 2 header 36 bytes, with a fifth offset at 32. A first
/// partition right after it is the sign of that layout.
const BCM_V2_HEADER_SIZE: usize = 36;
const BCM_V2_FIFTH_OFFSET: usize = 32;

/// Index of the version 2 bin header offset.
const BIN_HEADER_INDEX: usize = 3;

/// Version 2 CRC quirk in `trx.c` ("set stable and try1-3 to 0xFF for CRC
/// calculation like CFE does"): the 8 bytes at `offsets[3] + 22`, the
/// Cybertan `stable` and `try1`-`try3` fields, count as `0xFF`. `trx.c`
/// applies it even when `offsets[3]` is zero, which puts the bytes in the
/// header.
const BIN_HEADER_FLAGS: usize = 22;
const ERASED_FLAGS: [u8; 8] = [0xff; 8];

/// Flag bits named in Broadcom `trxhdr.h`. That header comes from dongle
/// firmware; whether router boot loaders honor them is not established.
const FLAG_NAMES: &[(u16, &str)] = &[
    (0x0002, "TRX_GZ_FILES"),
    (0x0008, "TRX_EMBED_UCODE"),
    (0x0010, "TRX_ROMSIM_IMAGE"),
    (0x0020, "TRX_UNCOMP_IMAGE"),
    (0x0040, "TRX_BOOTLOADER"),
];

/// The header version and the sizes it implies.
struct HeaderVersion {
    number: u16,
    header_size: usize,
    offset_count: usize,
}

fn header_version(header: &[u8]) -> Result<HeaderVersion> {
    match le_u16(header, VERSION)? {
        1 => Ok(HeaderVersion {
            number: 1,
            header_size: V1_HEADER_SIZE,
            offset_count: V1_OFFSETS,
        }),
        2 => Ok(HeaderVersion {
            number: 2,
            header_size: V2_HEADER_SIZE,
            offset_count: V2_OFFSETS,
        }),
        other => Err(error(format!("Unsupported TRX version {other}"))),
    }
}

/// The used partition offsets: a non-empty prefix of the offset table, each
/// past the header, before the image length and after the previous one.
fn partition_offsets(header: &[u8], version: &HeaderVersion, length: usize) -> Result<Vec<usize>> {
    let mut offsets: Vec<usize> = Vec::with_capacity(version.offset_count);
    let mut unused_seen = false;
    for i in 0..version.offset_count {
        let offset = to_usize(le_u32(header, OFFSETS + 4 * i)?);
        if offset == 0 {
            unused_seen = true;
            continue;
        }
        if unused_seen {
            return Err(error(format!(
                "Invalid TRX partition table: offset {i} is set after an unused offset"
            )));
        }
        if offset < version.header_size {
            return Err(error(format!(
                "Invalid TRX partition {i} offset 0x{offset:X}: inside the {} B header",
                version.header_size
            )));
        }
        if offset >= length {
            return Err(error(format!(
                "Invalid TRX partition {i} offset 0x{offset:X}: not before the image length 0x{length:X}"
            )));
        }
        if let Some(&previous) = offsets.last() {
            if offset <= previous {
                return Err(error(format!(
                    "Invalid TRX partition {i} offset 0x{offset:X}: not after partition {} at 0x{previous:X}",
                    i - 1
                )));
            }
        }
        offsets.push(offset);
    }
    if offsets.is_empty() {
        return Err(error("Missing TRX partition offsets"));
    }
    Ok(offsets)
}

/// `crc32buf` of `trx.c` (CRC-32/JAMCRC: the reflected IEEE register
/// starts at `0xFFFFFFFF` and is not complemented at the end) over
/// `data[CRC_START..end]`. With `fill_at`, the 8 bytes from there count as
/// `0xFF` where they fall inside the range. `end` must lie in
/// `CRC_START..=data.len()`.
fn image_crc(data: &[u8], end: usize, fill_at: Option<usize>) -> u32 {
    let Some(at) = fill_at else {
        return checksum::crc32_update(!0, &data[CRC_START..end]);
    };
    let fill_start = at.clamp(CRC_START, end);
    let fill_end = at.saturating_add(ERASED_FLAGS.len()).clamp(CRC_START, end);
    let crc = checksum::crc32_update(!0, &data[CRC_START..fill_start]);
    let crc = checksum::crc32_update(crc, &ERASED_FLAGS[..fill_end - fill_start]);
    checksum::crc32_update(crc, &data[fill_end..end])
}

/// One way a writer computes the CRC: where it ends and whether the
/// version 2 bin header fields count as erased.
#[derive(Debug, Clone, Copy)]
struct CrcRange {
    end: usize,
    fill_at: Option<usize>,
}

/// The CRC ranges writers use, most common first: up to the length
/// (`trx.c`, `otrx.c`), with the bin header quirk for version 2 and, for
/// other version 2 writers, without it; then to the end of the file,
/// because `asustrx` recomputes the CRC there without updating the length.
fn crc_ranges(data_len: usize, length: usize, fill_at: Option<usize>) -> Vec<CrcRange> {
    let mut ends = vec![length];
    if data_len > length {
        ends.push(data_len);
    }
    let mut ranges = Vec::with_capacity(4);
    for end in ends {
        if fill_at.is_some() {
            ranges.push(CrcRange { end, fill_at });
        }
        ranges.push(CrcRange { end, fill_at: None });
    }
    ranges
}

/// What a partition holds by convention; the header does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Loader,
    Kernel,
    RootFilesystem,
    BinHeader,
}

impl Role {
    /// Partition roles as Linux `parser_trx.c` assigns them: a third offset
    /// means the first partition is an LZMA loader. The fourth version 2
    /// partition is the bin header (`trx -2` in the `OpenWrt` bcm47xx
    /// recipes).
    fn of(index: usize, has_loader: bool) -> Self {
        match (index, has_loader) {
            (0, true) => Self::Loader,
            (0, false) | (1, true) => Self::Kernel,
            (1, false) | (2, _) => Self::RootFilesystem,
            _ => Self::BinHeader,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Kernel => "kernel",
            Self::RootFilesystem => "root filesystem",
            Self::BinHeader => "bin header",
        }
    }
}

/// Names of the set flag bits, and any bits `trxhdr.h` does not name.
fn flag_text(flags: u16) -> String {
    let mut names: Vec<String> = FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known = FLAG_NAMES.iter().fold(0u16, |mask, (bit, _)| mask | bit);
    if flags & !known != 0 {
        names.push(format!("unnamed bits 0x{:04X}", flags & !known));
    }
    names.join(", ")
}

/// A note when a version 2 image may use Broadcom's 36-byte header: its
/// first partition starts right after that header. The fifth offset is
/// reported, not used; the partition roles stay those of `trx -2`.
fn bcm_v2_note(data: &[u8], version: &HeaderVersion, offsets: &[usize]) -> Result<Option<String>> {
    if version.number != 2 || offsets.first() != Some(&BCM_V2_HEADER_SIZE) {
        return Ok(None);
    }
    let fifth = le_u32(data, BCM_V2_FIFTH_OFFSET)?;
    Ok(Some(format!(
        "First partition at 0x{BCM_V2_HEADER_SIZE:X}, after a 36-byte header as Broadcom's BCMTRXV2 layout defines it; its fifth offset 0x{fifth:X} is not read"
    )))
}

/// The CRC note: convention, range and quirk.
fn crc_note(version: u16, range: CrcRange, length: usize) -> String {
    let span = if range.end == length {
        format!("0xC-0x{:X}", range.end)
    } else {
        format!(
            "0xC to the end of the file (0x{:X}), past the length, as asustrx computes it",
            range.end
        )
    };
    let quirk = match range.fill_at {
        Some(at) => format!(" with the 8 bin header bytes at 0x{at:X} counted as 0xFF"),
        None if version == 2 => " without the bin header quirk of trx -2".to_string(),
        None => String::new(),
    };
    format!(
        "Broadcom TRX v{version}; CRC-32 (initial value 0xFFFFFFFF, no final XOR) verified over {span}{quirk}; integrity check only, not authenticated"
    )
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let fixed = slice(data, 0, V1_HEADER_SIZE, "TRX header")?;
    if fixed[..4] != MAGIC {
        return Err(error("Missing TRX magic"));
    }
    let version = header_version(fixed)?;
    let header = slice(data, 0, version.header_size, "TRX header")?;
    let length = to_usize(le_u32(header, LENGTH)?);
    if length < version.header_size {
        return Err(error(format!(
            "Invalid TRX length {length} B: shorter than the {} B header",
            version.header_size
        )));
    }
    if length > data.len() {
        return Err(error(format!(
            "Truncated TRX image: header declares {length} B, {} B present",
            data.len()
        )));
    }
    let offsets = partition_offsets(header, &version, length)?;
    let fill_at = match version.number {
        2 => Some(
            to_usize(le_u32(header, OFFSETS + 4 * BIN_HEADER_INDEX)?)
                .saturating_add(BIN_HEADER_FLAGS),
        ),
        _ => None,
    };

    let stored_crc = le_u32(header, CRC)?;
    let ranges = crc_ranges(data.len(), length, fill_at);
    let Some(range) = ranges
        .iter()
        .copied()
        .find(|range| image_crc(data, range.end, range.fill_at) == stored_crc)
    else {
        let computed = image_crc(data, length, fill_at);
        return Err(error(format!(
            "Invalid TRX CRC-32 0x{stored_crc:08X}, computed 0x{computed:08X} over 0xC-0x{length:X}"
        )));
    };

    let mut c = Container::new(
        FileFormat::Trx,
        format!("Broadcom TRX v{}", version.number),
        "trx",
    );
    c.consumed = length;
    c.notes.push(crc_note(version.number, range, length));
    let flags = le_u16(header, FLAGS)?;
    if flags != 0 {
        c.notes.push(format!(
            "Flags 0x{flags:04X}: {}; the names come from Broadcom trxhdr.h (dongle firmware) and their meaning to router boot loaders is not established",
            flag_text(flags)
        ));
    }
    if let Some(note) = bcm_v2_note(data, &version, &offsets)? {
        c.notes.push(note);
    }
    c.notes.push(
        "Partition roles follow Linux parser_trx.c; the header records offsets only and no architecture"
            .into(),
    );
    c.push_metadata("trx_version", "Header version", u64::from(version.number));
    c.push_metadata("trx_flags", "Flags", format!("0x{flags:04X}"));
    c.push_metadata("trx_crc32", "CRC-32", format!("0x{stored_crc:08X}"));

    let has_loader = offsets.len() > 2;
    let mut extractor = Extractor::default();
    for (i, &start) in offsets.iter().enumerate() {
        let end = offsets.get(i + 1).copied().unwrap_or(length);
        let role = Role::of(i, has_loader);
        let label = format!("Partition {} ({})", i + 1, role.name());
        // Offsets are increasing and below `length`, which is within `data`.
        let stored = &data[start..end];
        let child = if role == Role::BinHeader {
            // A 32-byte Cybertan code header and fill: data, never code.
            Child::opaque(label, start, stored)
        } else {
            extractor.component(label, start, stored, &mut c.notes)
        };
        c.children.push(child);
    }

    // `trx -F` appends a filesystem after the length, outside the CRC
    // unless asustrx extended it. Its role is not recorded.
    let rest = &data[length..];
    if !is_padding(rest) {
        if range.end == length {
            c.notes.push(format!(
                "{} after the TRX length are not covered by the CRC; listed only when they are a recognized format",
                size_text(rest.len())
            ));
        }
        c.children
            .push(Child::stored("Data after the TRX length", length, rest).if_recognized());
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_is_the_uncomplemented_ieee_register() {
        // CRC-32/JAMCRC check value for "123456789" behind a 12-byte prefix.
        let mut data = vec![0u8; CRC_START];
        data.extend_from_slice(b"123456789");
        assert_eq!(image_crc(&data, data.len(), None), 0x340b_c6d9);
    }

    #[test]
    fn version_2_fill_counts_eight_bytes_as_erased() {
        let mut data = vec![0u8; 64];
        data[40..48].fill(0xff);
        let filled = image_crc(&data, data.len(), None);
        data[40..48].fill(0x12);
        assert_eq!(image_crc(&data, data.len(), Some(40)), filled);
    }

    #[test]
    fn version_2_fill_is_clipped_to_the_crc_range() {
        let mut data = vec![0x12u8; 64];
        let plain = image_crc(&data, 60, None);
        assert_eq!(image_crc(&data, 60, Some(60)), plain);
        assert_eq!(image_crc(&data, 60, Some(usize::MAX)), plain);
        data[56..60].fill(0xff);
        let erased_tail = image_crc(&data, 60, None);
        data[56..60].fill(0x12);
        assert_eq!(image_crc(&data, 60, Some(56)), erased_tail);
    }

    #[test]
    fn crc_ranges_try_the_length_first() {
        let ranges = crc_ranges(100, 64, Some(40));
        let ends: Vec<_> = ranges.iter().map(|r| (r.end, r.fill_at)).collect();
        assert_eq!(
            ends,
            [(64, Some(40)), (64, None), (100, Some(40)), (100, None)]
        );
        assert_eq!(crc_ranges(64, 64, None).len(), 1);
    }

    #[test]
    fn roles_follow_the_linux_parser() {
        let with_loader: Vec<_> = (0..4).map(|i| Role::of(i, true).name()).collect();
        assert_eq!(
            with_loader,
            ["loader", "kernel", "root filesystem", "bin header"]
        );
        let without: Vec<_> = (0..2).map(|i| Role::of(i, false).name()).collect();
        assert_eq!(without, ["kernel", "root filesystem"]);
    }

    #[test]
    fn flags_name_known_and_unnamed_bits() {
        assert_eq!(flag_text(0x0042), "TRX_GZ_FILES, TRX_BOOTLOADER");
        assert_eq!(flag_text(0x8001), "unnamed bits 0x8001");
    }
}
