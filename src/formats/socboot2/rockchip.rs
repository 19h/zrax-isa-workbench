//! Rockchip images: RKFW update images (`update.img`), RKAF firmware
//! packages, RKBOOT loaders (`boot_merger` output) and idbloaders (the boot
//! ROM's ID block, header versions 1 and 2).
//!
//! Sources: rockchip-mkbootimg `rkrom.h` (`struct rkfw_header`), `rkafp.h`
//! (`struct update_header`, `struct update_part`), `rkcrc.h`, `afptool.c`
//! and `img_maker.c`; rkflashtool `rkunpack.c` and `rkcrc.c`;
//! rockchip-linux U-Boot `tools/rockchip/boot_merger.[ch]`
//! (`rk_boot_header`, `rk_boot_entry`, `writeFile`, `unpackEntry`,
//! `P_RC4`); U-Boot `tools/rkcommon.c` (`header0_info`, `header0_info_v2`,
//! `rc4_key`, `rkcommon_rc4_encode_spl`).
//!
//! RKBOOT entries are always RC4-scrambled in the loader file: `writeFile`
//! applies `P_RC4` unconditionally, to 0x471/0x472 entries as one stream
//! over the padded entry and to loader entries per 512-byte block, each
//! call restarting the key stream; `unpackEntry` reverses it the same way
//! without reading the header's `rc4Flag`. That flag only tells flashing
//! tools whether the ID block they build keeps the RC4 scrambling.

use super::*;
use crate::formats::container::MAX_EXTRACTED;
use crate::formats::MAX_PAYLOAD;
use sha2::{Digest, Sha256, Sha512};

/// RC4 key of the boot ROM scrambling (`P_RC4` in `boot_merger.c`,
/// `rc4_key` in `rkcommon.c`).
const RC4_KEY: [u8; 16] = [
    0x7c, 0x4e, 0x03, 0x04, 0x55, 0x05, 0x09, 0x07, 0x2d, 0x2c, 0x7b, 0x38, 0x17, 0x0d, 0x17, 0x11,
];

/// Block size of block-wise RC4 scrambling (`SMALL_PACKET`, `RK_BLK_SIZE`).
const RC4_BLOCK: usize = 512;

/// Transform name reported for descrambled components.
const RC4_TRANSFORM: &str = "Rockchip RC4";

/// MSB-first CRC polynomial of `rkcrc.h` (not the IEEE `0x04C11DB7`).
const RKCRC_POLYNOMIAL: u32 = 0x04c1_0db7;

/// Size of the little-endian RKCRC trailers.
const CRC_SIZE: usize = 4;

/// RKFW header (`struct rkfw_header`, packed, 0x66 bytes): magic (0),
/// header length (4, u16), version (6), code (0x0A), build time (0x0E:
/// year u16, month, day, hour, minute, second), chip (0x15), loader offset
/// and length (0x19, 0x1D), RKAF offset and length (0x21, 0x25), unknown
/// words (0x29, 0x2D), filesystem type (0x31), backup end (0x35).
const RKFW_MAGIC: &[u8; 4] = b"RKFW";
const RKFW_HEADER_SIZE: usize = 0x66;
const RKFW_HEAD_LEN: usize = 0x04;
const RKFW_VERSION: usize = 0x06;
const RKFW_BUILD_TIME: usize = 0x0e;
const RKFW_CHIP: usize = 0x15;
const RKFW_LOADER_OFFSET: usize = 0x19;
const RKFW_LOADER_LENGTH: usize = 0x1d;
const RKFW_IMAGE_OFFSET: usize = 0x21;
const RKFW_IMAGE_LENGTH: usize = 0x25;

/// `img_maker` appends the MD5 of all preceding bytes as 32 lowercase hex
/// characters (`append_md5sum`).
const MD5_HEX_SIZE: usize = 32;

/// The other loader magic `rkunpack` accepts inside an RKFW image. The
/// `LDR ` layout is not documented in the sources read.
const LDR_MAGIC: &[u8; 4] = b"LDR ";

/// RKFW chip byte at 0x15 as `rkunpack` names it.
const RKFW_CHIPS: &[(u8, &str)] = &[
    (0x50, "rk29xx"),
    (0x60, "rk30xx"),
    (0x70, "rk31xx"),
    (0x80, "rk32xx"),
    (0x41, "rk3368"),
    (0x36, "rv1106"),
    (0x38, "rk35xx"),
];

/// RKAF header (`struct update_header`, 0x800 bytes): magic (0), length
/// (4: file size minus the CRC), model (8, 0x22 B), ID (0x2A, 0x1E B),
/// manufacturer (0x48, 0x38 B), unknown (0x80), version (0x84), part count
/// (0x88), 16 part entries (0x8C).
const RKAF_MAGIC: &[u8; 4] = b"RKAF";
const RKAF_HEADER_SIZE: usize = 0x800;
const RKAF_LENGTH: usize = 0x04;
const RKAF_MODEL: usize = 0x08;
const RKAF_MODEL_SIZE: usize = 0x22;
const RKAF_MANUFACTURER: usize = 0x48;
const RKAF_MANUFACTURER_SIZE: usize = 0x38;
const RKAF_VERSION: usize = 0x84;
const RKAF_NUM_PARTS: usize = 0x88;
const RKAF_PARTS: usize = 0x8c;
const RKAF_MAX_PARTS: usize = 16;

/// RKAF part (`struct update_part`, 0x70 bytes): name (0, 32 B), file name
/// (0x20, 60 B), flash size (0x5C), position (0x60), flash address (0x64),
/// padded size (0x68), size (0x6C).
const RKAF_PART_SIZE: usize = 0x70;
const PART_NAME_SIZE: usize = 0x20;
const PART_FILENAME: usize = 0x20;
const PART_FILENAME_SIZE: usize = 60;
const PART_POSITION: usize = 0x60;
const PART_SIZE: usize = 0x6c;

/// A part whose file name is `SELF` is the package itself.
const RKAF_SELF: &str = "SELF";

/// The `parameter` part holds the flash partition table as text.
const PARAMETER_PART: &str = "parameter";

/// `PARM`/`KRNL` wrappers (`rkcrc.c`): magic, data length (u32), data,
/// RKCRC of the data.
const PARM_MAGIC: &[u8; 4] = b"PARM";
const KRNL_MAGIC: &[u8; 4] = b"KRNL";
const WRAPPER_LENGTH: usize = 4;
const WRAPPER_HEADER_SIZE: usize = 8;

/// RKBOOT header (`rk_boot_header`, packed, 0x66 bytes): tag (0), header
/// size (4, u16), version (6), merger version (0x0A), release time (0x0E),
/// chip type (0x15), then for 0x471, 0x472 and loader entries a count
/// (u8), table offset (u32) and entry size (u8) at 0x19, 0x1F and 0x25;
/// sign flag (0x2B), RC4 disable flag (0x2C).
const RKBOOT_TAG: &[u8; 4] = b"BOOT";
const RKBOOT_HEADER_SIZE: usize = 0x66;
const RKBOOT_SIZE: usize = 0x04;
const RKBOOT_VERSION: usize = 0x06;
const RKBOOT_CHIP_TYPE: usize = 0x15;
const RKBOOT_TABLES: [(EntryKind, usize); 3] = [
    (EntryKind::Code471, 0x19),
    (EntryKind::Code472, 0x1f),
    (EntryKind::Loader, 0x25),
];
const RKBOOT_SIGN_FLAG: usize = 0x2b;
const RKBOOT_RC4_FLAG: usize = 0x2c;

/// Offsets within an entry-table descriptor: count (u8), table offset
/// (u32), entry size (u8).
const TABLE_OFFSET: usize = 1;
const TABLE_ENTRY_SIZE: usize = 5;

/// RKBOOT entry (`rk_boot_entry`, packed, 0x39 bytes): size (0), type (1),
/// name (5, 20 UTF-16LE units), data offset (0x2D), data size (0x31),
/// delay in ms (0x35).
const ENTRY_SIZE: usize = 0x39;
const ENTRY_TYPE: usize = 0x01;
const ENTRY_NAME: usize = 0x05;
const ENTRY_NAME_UNITS: usize = 20;
const ENTRY_DATA_OFFSET: usize = 0x2d;
const ENTRY_DATA_SIZE: usize = 0x31;

/// `rk_entry_type` values.
const ENTRY_471: u32 = 1;
const ENTRY_472: u32 = 2;
const ENTRY_LOADER: u32 = 4;

/// Legacy RKBOOT chip types (`boot_merger.c`); other chips store the four
/// characters after "RK", packed big-endian.
const RKBOOT_CHIPS: &[(u32, &str)] = &[
    (0x10, "RK27"),
    (0x11, "RKCAYMAN"),
    (0x20, "RK28"),
    (0x21, "RK281X"),
    (0x22, "RKPANDA"),
    (0x30, "RKNANO"),
    (0x31, "RKSMART"),
    (0x40, "RKCROWN"),
    (0x50, "RK29"),
    (0x51, "RK292X"),
    (0x60, "RK30"),
    (0x61, "RK30B"),
    (0x70, "RK31"),
    (0x80, "RK32"),
];

/// idbloader header v1 (`header0_info`, 512 bytes, RC4-scrambled as one
/// block): magic (0), disable-RC4 flag (8), init offset in blocks (0x0C,
/// u16), init size in blocks (0x1FA, u16), init plus boot size in blocks
/// (0x1FC, u16).
const IDB_MAGIC: u32 = 0x0ff0_aa55;
const IDB_HEADER_SIZE: usize = 512;
const IDB_DISABLE_RC4: usize = 0x08;
const IDB_INIT_OFFSET: usize = 0x0c;
const IDB_INIT_SIZE: usize = 0x1fa;
const IDB_INIT_BOOT_SIZE: usize = 0x1fc;

/// The first four bytes of a stored v1 header: [`IDB_MAGIC`] XOR the first
/// four bytes of the [`RC4_KEY`] key stream (computed here, checked by a
/// unit test), so detection needs no key schedule.
const IDB_SCRAMBLED_MAGIC: [u8; 4] = [0x3b, 0x8c, 0xdc, 0xfc];

/// Size of the chip tag (`spl_hdr`, e.g. `RK33`) at the start of a v1 init
/// stage.
const SOC_TAG_SIZE: usize = 4;

/// idbloader header v2 (`header0_info_v2`, 2048 bytes, not scrambled):
/// magic (0), image count and hash offset (8: count in bits 31:16, offset
/// in 4-byte units in bits 15:0), boot flag (0x0C: hash type in bits 3:0),
/// four image entries (0x78), hash or signature (at the hash offset).
const IDB_V2_MAGIC: &[u8; 4] = b"RKNS";
const IDB_V2_HEADER_SIZE: usize = 2048;
const IDB_V2_SIZE_AND_NIMAGE: usize = 0x08;
const IDB_V2_BOOT_FLAG: usize = 0x0c;
const IDB_V2_IMAGES: usize = 0x78;
const IDB_V2_MAX_IMAGES: usize = 4;
const IDB_V2_HASH_TYPE_MASK: u32 = 0xf;
const IDB_V2_HASH_WORD_MASK: u32 = 0xffff;

/// idbloader v2 image entry (88 bytes): size and offset (0: size in
/// sectors in bits 31:16, offset in sectors from the header in bits 15:0),
/// load address (4), flag (8), counter (0x0C), reserved (0x10), hash
/// (0x18, 64 B).
const IDB_V2_IMAGE_SIZE: usize = 88;
const IDB_V2_IMAGE_ADDRESS: usize = 4;
const IDB_V2_IMAGE_HASH: usize = 0x18;
const IDB_V2_NO_ADDRESS: u32 = 0xffff_ffff;
const SECTOR_FIELD_MASK: u32 = 0xffff;

/// v2 hash types (`boot_flag` bits 3:0).
const HASH_NONE: u32 = 0;
const HASH_SHA256: u32 = 1;
const HASH_SHA512: u32 = 2;

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(..4)?;
    if magic == RKFW_MAGIC {
        return Some(Layout::Rkfw);
    }
    if magic == RKAF_MAGIC {
        return Some(Layout::Rkaf);
    }
    let header_size = le_u16(data, RKBOOT_SIZE).ok().map(usize::from);
    if magic == RKBOOT_TAG && header_size == Some(RKBOOT_HEADER_SIZE) {
        return Some(Layout::RkBoot);
    }
    if magic == IDB_V2_MAGIC {
        return Some(Layout::IdbloaderV2);
    }
    (magic == IDB_SCRAMBLED_MAGIC).then_some(Layout::IdbloaderV1)
}

/// XOR `bytes` with the RC4 key stream of [`RC4_KEY`]. The key schedule
/// restarts on every call, as `P_RC4` and `rc4_encode` do.
fn rc4(bytes: &mut [u8]) {
    let mut state = [0u8; 256];
    for (slot, value) in state.iter_mut().zip(0..=u8::MAX) {
        *slot = value;
    }
    let mut j = 0u8;
    for i in 0..state.len() {
        j = j
            .wrapping_add(state[i])
            .wrapping_add(RC4_KEY[i % RC4_KEY.len()]);
        state.swap(i, usize::from(j));
    }
    let mut i = 0u8;
    let mut j = 0u8;
    for byte in bytes {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[usize::from(i)]);
        state.swap(usize::from(i), usize::from(j));
        let index = state[usize::from(i)].wrapping_add(state[usize::from(j)]);
        *byte ^= state[usize::from(index)];
    }
}

/// Descramble `stored` as one RC4 stream.
fn descramble_stream(stored: &[u8]) -> Vec<u8> {
    let mut plain = stored.to_vec();
    rc4(&mut plain);
    plain
}

/// Descramble `stored` per 512-byte block, each block restarting the key
/// stream.
fn descramble_blocks(stored: &[u8]) -> Vec<u8> {
    let mut key_stream = [0u8; RC4_BLOCK];
    rc4(&mut key_stream);
    let mut plain = stored.to_vec();
    for block in plain.chunks_mut(RC4_BLOCK) {
        for (byte, key) in block.iter_mut().zip(key_stream) {
            *byte ^= key;
        }
    }
    plain
}

/// Byte-at-a-time table for [`RKCRC_POLYNOMIAL`].
const RKCRC_TABLE: [u32; 256] = rkcrc_table();

const fn rkcrc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i << 24;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ RKCRC_POLYNOMIAL
            };
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Rockchip's CRC: MSB first, initial value 0, no reflection, no final XOR.
fn rkcrc(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |crc, &byte| {
        let index = ((crc >> 24) ^ u32::from(byte)) & 0xff;
        (crc << 8) ^ RKCRC_TABLE[index as usize]
    })
}

/// Verify the RKCRC stored at `crc_at` over the bytes before it.
fn verify_rkcrc(data: &[u8], crc_at: usize, what: &str) -> Result<u32> {
    let body = range(data, 0, crc_at, what)?;
    let stored = le_u32(range(data, crc_at, CRC_SIZE, &format!("{what} CRC"))?, 0)?;
    let computed = rkcrc(body);
    if stored != computed {
        return Err(error(format!(
            "Invalid {what} CRC 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(stored)
}

/// Bytes after `end` must be erased flash.
fn expect_padding(data: &[u8], end: usize, what: &str) -> Result<()> {
    let rest = data.get(end..).unwrap_or_default();
    if is_padding(rest) {
        Ok(())
    } else {
        Err(error(format!(
            "Unexpected {} after the {what} at 0x{end:X}",
            size_text(rest.len())
        )))
    }
}

/// Printable ASCII text with line breaks and tabs.
fn is_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
}

/// `(a << 24) | (b << 16) | c` as `a.b.c`.
fn package_version(version: u32) -> String {
    format!(
        "{}.{}.{}",
        version >> 24,
        (version >> 16) & 0xff,
        version & 0xffff
    )
}

/// The `img_maker` MD5 trailer: 32 lowercase hex characters.
fn is_md5_hex(bytes: &[u8]) -> bool {
    bytes.len() == MD5_HEX_SIZE && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The RKFW build time (year u16, month, day, hour, minute, second) as
/// `YYYY-MM-DD hh:mm:ss`. `time` is the 7-byte field.
fn build_time(time: &[u8]) -> String {
    let year = u16::from_le_bytes([time[0], time[1]]);
    format!(
        "{year:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time[2], time[3], time[4], time[5], time[6]
    )
}

pub(super) fn parse_rkfw(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, RKFW_HEADER_SIZE, "RKFW header")?;
    if &header[..4] != RKFW_MAGIC {
        return Err(error("Missing RKFW magic"));
    }
    let head_len = le_u16(header, RKFW_HEAD_LEN)?;
    let version = le_u32(header, RKFW_VERSION)?;
    let chip = le_u32(header, RKFW_CHIP)?;
    let loader_offset = le_size(header, RKFW_LOADER_OFFSET)?;
    let loader_length = le_size(header, RKFW_LOADER_LENGTH)?;
    let image_offset = le_size(header, RKFW_IMAGE_OFFSET)?;
    let image_length = le_size(header, RKFW_IMAGE_LENGTH)?;
    let loader = range(data, loader_offset, loader_length, "RKFW loader")?;
    let image = range(data, image_offset, image_length, "RKFW firmware package")?;
    let loader_magic = loader.get(..4).unwrap_or_default();
    if loader_magic != RKBOOT_TAG && loader_magic != LDR_MAGIC {
        return Err(error(format!(
            "Invalid RKFW loader at 0x{loader_offset:X}: missing BOOT or LDR magic"
        )));
    }
    if image.get(..4) != Some(RKAF_MAGIC) {
        return Err(error(format!(
            "Invalid RKFW firmware package at 0x{image_offset:X}: missing RKAF magic"
        )));
    }
    // Both ranges lie inside `data`, so their ends cannot overflow.
    let end = (loader_offset + loader_length).max(image_offset + image_length);
    let has_md5 = data.get(end..end + MD5_HEX_SIZE).is_some_and(is_md5_hex);
    let consumed = if has_md5 { end + MD5_HEX_SIZE } else { end };
    expect_padding(data, consumed, "RKFW image")?;

    let mut c = Container::new(FileFormat::RockchipImage, Layout::Rkfw.label(), "rockchip");
    c.consumed = consumed;
    let chip_name = RKFW_CHIPS
        .iter()
        .find(|(code, _)| *code == header[RKFW_CHIP])
        .map_or(String::new(), |(_, name)| format!(" ({name} per rkunpack)"));
    c.notes.push(format!(
        "Rockchip RKFW update image, version {}; chip 0x{chip:08X}{chip_name}",
        package_version(version)
    ));
    c.notes.push(if has_md5 {
        "MD5 trailer present; not verified".into()
    } else {
        "No MD5 trailer".into()
    });
    c.notes
        .push("The chip code names a SoC family, not an instruction set".into());
    c.push_metadata(
        "rockchip_header_size",
        "Header length (B)",
        u64::from(head_len),
    );
    c.push_metadata(
        "rockchip_version",
        "Firmware version",
        package_version(version),
    );
    c.push_metadata("rockchip_chip", "Chip", format!("0x{chip:08X}"));
    c.push_metadata(
        "rockchip_build_time",
        "Build time",
        build_time(&header[RKFW_BUILD_TIME..RKFW_CHIP]),
    );
    let loader_child = if loader_magic == LDR_MAGIC {
        c.notes.push(
            "The LDR loader layout is not established in the sources; loader not analyzed".into(),
        );
        Child::opaque("Loader (LDR)", loader_offset, loader)
    } else {
        Child::stored("Loader", loader_offset, loader)
    };
    c.children.push(loader_child);
    c.children.push(Child::stored(
        "Firmware package (RKAF)",
        image_offset,
        image,
    ));
    c.children.sort_by_key(|child| child.offset);
    Ok(c)
}

/// The data inside a `PARM`/`KRNL` wrapper.
struct WrapperPayload<'a> {
    /// The declared number of bytes after the 8-byte wrapper header.
    bytes: &'a [u8],
    /// Whether the RKCRC stored after the data matches it.
    crc_matches: bool,
}

/// The data of a `PARM`/`KRNL` wrapper and whether its RKCRC matches, or
/// `None` when the declared length exceeds the part.
fn unwrap_rkcrc(bytes: &[u8]) -> Option<WrapperPayload<'_>> {
    let len = usize::try_from(le_u32(bytes, WRAPPER_LENGTH).ok()?).ok()?;
    let inner = bytes.get(WRAPPER_HEADER_SIZE..WRAPPER_HEADER_SIZE.checked_add(len)?)?;
    let stored = le_u32(bytes, WRAPPER_HEADER_SIZE + len).ok()?;
    Some(WrapperPayload {
        bytes: inner,
        crc_matches: stored == rkcrc(inner),
    })
}

/// One RKAF part as a component: a `PARM` wrapper, the `parameter` part
/// and text parts are opaque; a `KRNL` wrapper yields its contents.
fn rkaf_component<'a>(
    label: String,
    name: &str,
    offset: usize,
    bytes: &'a [u8],
    notes: &mut Vec<String>,
) -> Child<'a> {
    let wrapper = bytes.get(..4);
    let is_wrapper = wrapper == Some(KRNL_MAGIC) || wrapper == Some(PARM_MAGIC);
    if is_wrapper {
        if let Some(payload) = unwrap_rkcrc(bytes) {
            if !payload.crc_matches {
                notes.push(format!("{label}: wrapper RKCRC does not match"));
            }
            let inner_offset = offset + WRAPPER_HEADER_SIZE;
            if wrapper == Some(KRNL_MAGIC) {
                return Child::stored(label, inner_offset, payload.bytes);
            }
            return Child::opaque(label, inner_offset, payload.bytes);
        }
        notes.push(format!("{label}: wrapper length exceeds the part"));
    }
    if is_wrapper || name == PARAMETER_PART || is_text(bytes) {
        return Child::opaque(label, offset, bytes);
    }
    Child::stored(label, offset, bytes)
}

/// A part's display label: its name, with the package path when that
/// differs.
fn part_label(name: &str, filename: &str, index: usize) -> String {
    match (name.is_empty(), filename.is_empty() || filename == name) {
        (true, true) => format!("Part {index}"),
        (true, false) => filename.to_string(),
        (false, true) => name.to_string(),
        (false, false) => format!("{name} ({filename})"),
    }
}

pub(super) fn parse_rkaf(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, RKAF_HEADER_SIZE, "RKAF header")?;
    if &header[..4] != RKAF_MAGIC {
        return Err(error("Missing RKAF magic"));
    }
    // `afptool` reads the CRC at `length`; `rkunpack` requires the file to
    // end there.
    let length = le_size(header, RKAF_LENGTH)?;
    if length < RKAF_HEADER_SIZE {
        return Err(error(format!(
            "Invalid RKAF length {length} B: shorter than the 2048 B header"
        )));
    }
    let crc = verify_rkcrc(data, length, "RKAF")?;
    expect_padding(data, length + CRC_SIZE, "RKAF CRC")?;
    let count = le_size(header, RKAF_NUM_PARTS)?;
    if count > RKAF_MAX_PARTS {
        return Err(error(format!(
            "Invalid RKAF part count {count}: at most 16"
        )));
    }

    let mut c = Container::new(FileFormat::RockchipImage, Layout::Rkaf.label(), "rockchip");
    c.consumed = length + CRC_SIZE;
    let model = text_field(&header[RKAF_MODEL..RKAF_MODEL + RKAF_MODEL_SIZE]);
    let manufacturer =
        text_field(&header[RKAF_MANUFACTURER..RKAF_MANUFACTURER + RKAF_MANUFACTURER_SIZE]);
    let version = le_u32(header, RKAF_VERSION)?;
    c.notes.push(format!(
        "Rockchip RKAF firmware package, version {}; RKCRC 0x{crc:08X} verified",
        package_version(version)
    ));
    if !model.is_empty() || !manufacturer.is_empty() {
        c.notes
            .push(format!("Model: {model}; manufacturer: {manufacturer}"));
    }
    c.push_metadata(
        "rockchip_version",
        "Firmware version",
        package_version(version),
    );
    c.push_metadata("rockchip_parts", "Parts", count as u64);
    let package = &data[..length];
    for i in 0..count {
        // At most 16 entries of 0x70 bytes from 0x8C stay inside the
        // 0x800-byte header.
        let part_start = RKAF_PARTS + i * RKAF_PART_SIZE;
        let part = &header[part_start..part_start + RKAF_PART_SIZE];
        let name = text_field(&part[..PART_NAME_SIZE]);
        let filename = text_field(&part[PART_FILENAME..PART_FILENAME + PART_FILENAME_SIZE]);
        let position = le_size(part, PART_POSITION)?;
        let size = le_size(part, PART_SIZE)?;
        if filename == RKAF_SELF || size == 0 {
            // The package itself, or a reserved entry without a file.
            continue;
        }
        let label = part_label(&name, &filename, i);
        let what = format!("RKAF part {i} ({label})");
        let bytes = range(package, position, size, &what)?;
        let child = rkaf_component(label, &name, position, bytes, &mut c.notes);
        c.children.push(child);
    }
    Ok(c)
}

/// Which table an RKBOOT entry is listed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// Mask-ROM download stage 0x471 (DDR init).
    Code471,
    /// Mask-ROM download stage 0x472 (USB plug).
    Code472,
    /// Flash loader stage (`FlashData`, `FlashBoot`).
    Loader,
}

impl EntryKind {
    fn type_id(self) -> u32 {
        match self {
            Self::Code471 => ENTRY_471,
            Self::Code472 => ENTRY_472,
            Self::Loader => ENTRY_LOADER,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Code471 => "0x471 DDR init",
            Self::Code472 => "0x472 USB plug",
            Self::Loader => "loader",
        }
    }

    /// `writeFile` scrambles 0x471/0x472 entries as one RC4 stream and
    /// loader entries per 512-byte block.
    fn descramble(self, stored: &[u8]) -> Vec<u8> {
        match self {
            Self::Code471 | Self::Code472 => descramble_stream(stored),
            Self::Loader => descramble_blocks(stored),
        }
    }
}

/// An RKBOOT entry table.
struct EntryTable {
    kind: EntryKind,
    /// Number of entries.
    count: usize,
    /// File offset of the first entry.
    offset: usize,
    /// Size of one entry in bytes.
    entry_size: usize,
}

/// The entry-table descriptor at `at` in the RKBOOT header.
fn entry_table(header: &[u8], kind: EntryKind, at: usize) -> Result<EntryTable> {
    let table = EntryTable {
        kind,
        count: usize::from(header[at]),
        offset: le_size(header, at + TABLE_OFFSET)?,
        entry_size: usize::from(header[at + TABLE_ENTRY_SIZE]),
    };
    if table.count > 0 && table.entry_size < ENTRY_SIZE {
        return Err(error(format!(
            "Invalid RKBOOT {} entry size {} B: at least 57 B",
            kind.label(),
            table.entry_size
        )));
    }
    Ok(table)
}

/// An entry name: UTF-16LE units up to the first NUL. `entry` holds at
/// least [`ENTRY_SIZE`] bytes.
fn entry_name(entry: &[u8]) -> String {
    let units = entry[ENTRY_NAME..ENTRY_NAME + ENTRY_NAME_UNITS * 2]
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .take_while(|&unit| unit != 0);
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .trim()
        .to_string()
}

/// An RKBOOT chip type: a legacy enum value or four packed characters.
fn chip_type(value: u32) -> String {
    if let Some((_, name)) = RKBOOT_CHIPS.iter().find(|(code, _)| *code == value) {
        return (*name).to_string();
    }
    let chars = value.to_be_bytes();
    if chars.iter().all(u8::is_ascii_alphanumeric) {
        return format!("RK{}", String::from_utf8_lossy(&chars));
    }
    format!("0x{value:08X}")
}

/// One RKBOOT entry's data, still scrambled.
struct Entry<'a> {
    kind: EntryKind,
    label: String,
    offset: usize,
    stored: &'a [u8],
}

/// The entries of the three RKBOOT tables and where their data ends.
struct RkbootEntries<'a> {
    /// Every entry, in table order (0x471, 0x472, loader).
    entries: Vec<Entry<'a>>,
    /// File offset of the end of the last table or entry data, where
    /// `boot_merger` appends the CRC.
    content_end: usize,
}

/// Every entry of the three tables, and the end of the last table or entry
/// data, where `boot_merger` appends the CRC.
fn rkboot_entries<'a>(data: &'a [u8], header: &[u8]) -> Result<RkbootEntries<'a>> {
    let mut content_end = RKBOOT_HEADER_SIZE;
    let mut entries = Vec::new();
    for &(kind, at) in &RKBOOT_TABLES {
        let table = entry_table(header, kind, at)?;
        // An empty table's offset and entry size are not used.
        if table.count == 0 {
            continue;
        }
        let table_size = table
            .count
            .checked_mul(table.entry_size)
            .ok_or_else(|| error("Invalid RKBOOT entry table size"))?;
        let what = format!("RKBOOT {} entry table", kind.label());
        let bytes = range(data, table.offset, table_size, &what)?;
        content_end = content_end.max(table.offset + table_size);
        for (i, entry) in bytes.chunks_exact(table.entry_size).enumerate() {
            let entry_type = le_u32(entry, ENTRY_TYPE)?;
            let name = entry_name(entry);
            let label = if name.is_empty() {
                format!("Entry {i} ({})", kind.label())
            } else {
                format!("{name} ({})", kind.label())
            };
            if entry_type != table.kind.type_id() {
                return Err(error(format!(
                    "Invalid RKBOOT entry {label}: type {entry_type} in the {} table",
                    kind.label()
                )));
            }
            let offset = le_size(entry, ENTRY_DATA_OFFSET)?;
            let size = le_size(entry, ENTRY_DATA_SIZE)?;
            let stored = range(data, offset, size, &format!("RKBOOT entry {label}"))?;
            content_end = content_end.max(offset + size);
            entries.push(Entry {
                kind,
                label,
                offset,
                stored,
            });
        }
    }
    Ok(RkbootEntries {
        entries,
        content_end,
    })
}

pub(super) fn parse_rkboot(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, RKBOOT_HEADER_SIZE, "RKBOOT header")?;
    if &header[..4] != RKBOOT_TAG {
        return Err(error("Missing RKBOOT tag"));
    }
    let header_size = le_u16(header, RKBOOT_SIZE)?;
    if usize::from(header_size) != RKBOOT_HEADER_SIZE {
        return Err(error(format!(
            "Invalid RKBOOT header size {header_size} B: expected 102 B"
        )));
    }
    let RkbootEntries {
        entries,
        content_end,
    } = rkboot_entries(data, header)?;
    let crc = verify_rkcrc(data, content_end, "RKBOOT")?;
    expect_padding(data, content_end + CRC_SIZE, "RKBOOT CRC")?;

    let version = le_u32(header, RKBOOT_VERSION)?;
    let chip = chip_type(le_u32(header, RKBOOT_CHIP_TYPE)?);
    let sign_flag = header[RKBOOT_SIGN_FLAG];
    let rc4_flag = header[RKBOOT_RC4_FLAG];
    let mut c = Container::new(
        FileFormat::RockchipImage,
        Layout::RkBoot.label(),
        "rockchip",
    );
    c.consumed = content_end + CRC_SIZE;
    c.notes.push(format!(
        "Rockchip RKBOOT loader, version {:X}.{:02X}; chip {chip}; RKCRC 0x{crc:08X} verified",
        (version >> 8) & 0xff,
        version & 0xff
    ));
    c.notes.push(
        "Entries are RC4-scrambled in the file and were descrambled: 0x471/0x472 entries as one stream, loader entries per 512-byte block"
            .into(),
    );
    c.notes
        .push("The chip type names a SoC, not an instruction set".into());
    if sign_flag != 0 {
        c.notes.push(format!(
            "Sign flag 0x{sign_flag:02X}; signatures are not verified"
        ));
    }
    c.push_metadata("rockchip_chip", "Chip", chip);
    c.push_metadata(
        "rockchip_rc4_disable_flag",
        "RC4 disable flag (ID block)",
        u64::from(rc4_flag),
    );
    let mut extracted = 0usize;
    let mut left_out = 0usize;
    for entry in entries {
        let within_budget = entry.stored.len() <= MAX_PAYLOAD
            && extracted
                .checked_add(entry.stored.len())
                .is_some_and(|total| total <= MAX_EXTRACTED);
        if !within_budget {
            left_out += 1;
            c.children
                .push(Child::opaque(entry.label, entry.offset, entry.stored));
            continue;
        }
        extracted += entry.stored.len();
        let plain = entry.kind.descramble(entry.stored);
        c.children.push(Child::decoded(
            entry.label,
            entry.offset,
            entry.stored.len(),
            Cow::Owned(plain),
            RC4_TRANSFORM,
        ));
    }
    if left_out > 0 {
        c.notes.push(format!(
            "{left_out} entries were not descrambled: extraction limit of {} reached",
            size_text(MAX_EXTRACTED)
        ));
    }
    Ok(c)
}

/// A stage of an idbloader at `offset`, descrambled per block when
/// `scrambled`.
fn idb_stage<'a>(label: &str, offset: usize, stored: &'a [u8], scrambled: bool) -> Child<'a> {
    if scrambled {
        Child::decoded(
            label,
            offset,
            stored.len(),
            Cow::Owned(descramble_blocks(stored)),
            RC4_TRANSFORM,
        )
    } else {
        Child::stored(label, offset, stored)
    }
}

/// The chip tag at the start of a v1 init stage, as a note and metadata.
fn describe_soc_tag(c: &mut Container<'_>, init: &[u8]) {
    let tag = init.get(..SOC_TAG_SIZE).unwrap_or_default();
    if tag.len() == SOC_TAG_SIZE && tag.iter().all(u8::is_ascii_alphanumeric) {
        let tag = String::from_utf8_lossy(tag).into_owned();
        c.notes.push(format!(
            "SoC tag {tag}: names a SoC family, not an instruction set"
        ));
        c.push_metadata("rockchip_soc_tag", "SoC tag", tag);
    } else {
        c.notes.push(
            "The init stage does not start with an ASCII SoC tag; SPI images that use 2 KiB of every 4 KiB are not de-interleaved"
                .into(),
        );
    }
}

pub(super) fn parse_idbloader_v1(data: &[u8]) -> Result<Container<'_>> {
    let stored = range(data, 0, IDB_HEADER_SIZE, "idbloader header")?;
    let mut header = [0u8; IDB_HEADER_SIZE];
    header.copy_from_slice(stored);
    rc4(&mut header);
    if le_u32(&header, 0)? != IDB_MAGIC {
        return Err(error("Missing idbloader magic 0x0FF0AA55"));
    }
    let disable_rc4 = le_u32(&header, IDB_DISABLE_RC4)?;
    let init_offset = usize::from(le_u16(&header, IDB_INIT_OFFSET)?) * SECTOR;
    let init_size = usize::from(le_u16(&header, IDB_INIT_SIZE)?) * SECTOR;
    let init_boot_size = usize::from(le_u16(&header, IDB_INIT_BOOT_SIZE)?) * SECTOR;
    if init_offset < IDB_HEADER_SIZE || init_size == 0 || init_boot_size < init_size {
        return Err(error(format!(
            "Invalid idbloader stage layout: init at 0x{init_offset:X}, init {init_size} B, init and boot {init_boot_size} B"
        )));
    }
    let scrambled = disable_rc4 == 0;
    let init = range(data, init_offset, init_size, "idbloader init stage")?;
    let init_end = init_offset + init_size;
    let boot_size = init_boot_size - init_size;
    let boot_present = boot_size.min(data.len() - init_end);
    let boot = &data[init_end..init_end + boot_present];
    // Without a boot file, U-Boot reserves room for a boot stage it does
    // not write; erased or missing bytes there are no stage. Part of a
    // stage is truncation.
    let has_boot = boot_present > 0 && !is_padding(boot);
    if has_boot && boot_present < boot_size {
        return Err(error(format!(
            "Truncated idbloader boot stage at 0x{init_end:X}: {boot_size} B declared, {boot_present} B present"
        )));
    }

    let mut c = Container::new(
        FileFormat::RockchipImage,
        Layout::IdbloaderV1.label(),
        "rockchip",
    );
    c.consumed = if has_boot {
        init_end + boot_size
    } else {
        init_end
    };
    c.notes.push(format!(
        "Rockchip idbloader, header v1 (RC4-scrambled, descrambled); init stage {} at 0x{init_offset:X}",
        size_text(init_size)
    ));
    c.notes.push(if scrambled {
        "Stages are RC4-scrambled per 512-byte block and were descrambled".into()
    } else {
        "Stages are stored without RC4 scrambling (disable_rc4 set)".into()
    });
    let init_child = idb_stage("Init stage", init_offset, init, scrambled);
    describe_soc_tag(&mut c, &init_child.data);
    c.children.push(init_child);
    if has_boot {
        c.children
            .push(idb_stage("Boot stage", init_end, boot, scrambled));
    } else if boot_size > 0 {
        c.notes.push(format!(
            "The header reserves {} for a boot stage that the file does not contain",
            size_text(boot_size)
        ));
    }
    let end = c.consumed;
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

/// A v2 hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha256,
    Sha512,
}

impl HashKind {
    fn from_boot_flag(hash_type: u32) -> Option<Self> {
        match hash_type {
            HASH_SHA256 => Some(Self::Sha256),
            HASH_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Whether `expected` starts with the digest of `bytes`.
    fn matches(self, bytes: &[u8], expected: &[u8]) -> bool {
        let digest: Vec<u8> = match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        };
        expected.get(..digest.len()) == Some(digest.as_slice())
    }
}

/// One v2 image: its entry in the header and its bytes.
struct V2Image<'a> {
    /// The 88-byte entry in the header.
    entry: &'a [u8],
    offset: usize,
    bytes: &'a [u8],
}

/// The images a v2 header lists, in header order.
fn v2_images<'a>(data: &'a [u8], header: &'a [u8], count: usize) -> Result<Vec<V2Image<'a>>> {
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        // At most four 88-byte entries from 0x78 stay inside the header.
        let entry_start = IDB_V2_IMAGES + i * IDB_V2_IMAGE_SIZE;
        let entry = &header[entry_start..entry_start + IDB_V2_IMAGE_SIZE];
        let size_and_offset = le_u32(entry, 0)?;
        let offset = (size_and_offset & SECTOR_FIELD_MASK) as usize * SECTOR;
        let size = (size_and_offset >> 16) as usize * SECTOR;
        if offset < IDB_V2_HEADER_SIZE || size == 0 {
            return Err(error(format!(
                "Invalid idbloader v2 image {}: offset 0x{offset:X}, {size} B",
                i + 1
            )));
        }
        let bytes = range(data, offset, size, &format!("idbloader v2 image {}", i + 1))?;
        images.push(V2Image {
            entry,
            offset,
            bytes,
        });
    }
    Ok(images)
}

/// Check the header hash (over the bytes before the hash field) and the
/// image hashes, as notes. A mismatching header field may hold a
/// signature, which is not checked.
fn describe_v2_hashes(c: &mut Container<'_>, header: &[u8], hash_at: usize, images: &[V2Image]) {
    let hash_type = le_u32(header, IDB_V2_BOOT_FLAG).map_or(0, |flag| flag & IDB_V2_HASH_TYPE_MASK);
    let Some(kind) = HashKind::from_boot_flag(hash_type) else {
        c.notes.push(if hash_type == HASH_NONE {
            "No header or image hashes".to_string()
        } else {
            format!("Hash type {hash_type}; hashes or signatures not verified")
        });
        return;
    };
    let name = kind.name();
    let header_ok = header
        .get(hash_at..)
        .filter(|field| field.len() >= kind.digest_len())
        .is_some_and(|field| kind.matches(&header[..hash_at], field));
    let failed: Vec<String> = images
        .iter()
        .enumerate()
        .filter(|(_, image)| !kind.matches(image.bytes, &image.entry[IDB_V2_IMAGE_HASH..]))
        .map(|(i, _)| (i + 1).to_string())
        .collect();
    c.notes.push(if header_ok {
        format!("{name} header hash verified (integrity only; no signature is checked)")
    } else {
        format!(
            "{name} header hash field at 0x{hash_at:X} does not match; it may hold a signature, which is not verified"
        )
    });
    c.notes.push(if failed.is_empty() {
        format!("{name} image hashes verified")
    } else {
        format!(
            "{name} hash does not match for image {}; not verified",
            failed.join(", ")
        )
    });
}

pub(super) fn parse_idbloader_v2(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, IDB_V2_HEADER_SIZE, "idbloader v2 header")?;
    if &header[..4] != IDB_V2_MAGIC {
        return Err(error("Missing idbloader v2 magic RKNS"));
    }
    let size_and_nimage = le_u32(header, IDB_V2_SIZE_AND_NIMAGE)?;
    let count = (size_and_nimage >> 16) as usize;
    if count == 0 || count > IDB_V2_MAX_IMAGES {
        return Err(error(format!(
            "Invalid idbloader v2 image count {count}: 1 to 4"
        )));
    }
    let hash_at = (size_and_nimage & IDB_V2_HASH_WORD_MASK) as usize * 4;
    let images = v2_images(data, header, count)?;

    let mut c = Container::new(
        FileFormat::RockchipImage,
        Layout::IdbloaderV2.label(),
        "rockchip",
    );
    let plural = if count == 1 { "" } else { "s" };
    c.notes.push(format!(
        "Rockchip idbloader, header v2 (RKNS); {count} image{plural}"
    ));
    describe_v2_hashes(&mut c, header, hash_at, &images);
    let mut end = IDB_V2_HEADER_SIZE;
    for (i, image) in images.iter().enumerate() {
        let label = format!("Image {}", i + 1);
        let address = le_u32(image.entry, IDB_V2_IMAGE_ADDRESS)?;
        if address != IDB_V2_NO_ADDRESS {
            c.push_metadata(
                format!("rockchip_image_{}_address", i + 1),
                format!("{label} load address"),
                format!("0x{address:08X}"),
            );
        }
        end = end.max(image.offset + image.bytes.len());
        c.children
            .push(Child::stored(label, image.offset, image.bytes));
    }
    c.children.sort_by_key(|child| child.offset);
    c.consumed = end;
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RC4 with a caller-supplied key, for the published test vectors.
    fn rc4_with_key(key: &[u8], bytes: &mut [u8]) {
        let mut state: Vec<u8> = (0..=u8::MAX).collect();
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        let mut i = 0u8;
        let mut j = 0u8;
        for byte in bytes {
            i = i.wrapping_add(1);
            j = j.wrapping_add(state[usize::from(i)]);
            state.swap(usize::from(i), usize::from(j));
            let index = state[usize::from(i)].wrapping_add(state[usize::from(j)]);
            *byte ^= state[usize::from(index)];
        }
    }

    #[test]
    fn rc4_matches_the_reference_vectors_and_the_fixed_key() {
        // Wikipedia RC4 examples: ("Key", "Plaintext"), ("Wiki", "pedia").
        let mut text = *b"Plaintext";
        rc4_with_key(b"Key", &mut text);
        assert_eq!(text, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
        let mut text = *b"pedia";
        rc4_with_key(b"Wiki", &mut text);
        assert_eq!(text, [0x10, 0x21, 0xbf, 0x04, 0x20]);
        // The fixed-key function agrees with the general one.
        let mut fixed = [0u8; 600];
        let mut general = [0u8; 600];
        rc4(&mut fixed);
        rc4_with_key(&RC4_KEY, &mut general);
        assert_eq!(fixed, general);
    }

    #[test]
    fn scrambled_idbloader_magic_is_the_rc4_of_the_magic() {
        let mut magic = IDB_MAGIC.to_le_bytes();
        rc4(&mut magic);
        assert_eq!(magic, IDB_SCRAMBLED_MAGIC);
    }

    #[test]
    fn block_descrambling_restarts_the_key_stream() {
        let stored = vec![0u8; 1100];
        let plain = descramble_blocks(&stored);
        assert_eq!(plain[..512], plain[512..1024]);
        assert_eq!(plain[..76], plain[1024..]);
        assert_ne!(descramble_stream(&stored)[512..1024], plain[..512]);
    }

    #[test]
    fn rkcrc_table_matches_rkcrc_h() {
        assert_eq!(RKCRC_TABLE[1], 0x04c1_0db7);
        assert_eq!(RKCRC_TABLE[255], 0xb1f8_80b4);
        assert_eq!(rkcrc(&[]), 0);
        assert_eq!(rkcrc(&[1]), 0x04c1_0db7);
    }

    #[test]
    fn chip_types_decode_legacy_codes_and_packed_names() {
        assert_eq!(chip_type(0x60), "RK30");
        assert_eq!(chip_type(u32::from_be_bytes(*b"3399")), "RK3399");
        assert_eq!(chip_type(0x0102_0304), "0x01020304");
    }
}
