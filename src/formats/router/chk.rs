//! Netgear CHK (`OpenWrt` firmware-utils `mkchkimg.c`).
//!
//! Header, all integers big-endian: magic `0x2A23245E` (0), header length
//! (4: 40 B plus the board ID), eight reserved bytes (8: the region code,
//! then the seven version digits of `DEVICE-VA.B.C.D_E.F.G.chk`), kernel
//! checksum (16), root filesystem checksum (20), kernel length (24), root
//! filesystem length (28), image checksum (32), header checksum (36), then
//! the board ID (40, ASCII without a terminator). The kernel follows the
//! header and the root filesystem follows the kernel.

use super::*;

/// `*#$^` (`0x2A23245E`, big-endian).
pub(super) const MAGIC: [u8; 4] = [0x2a, 0x23, 0x24, 0x5e];

/// Header fields.
const HEADER_LEN: usize = 4;
const REGION: usize = 8;
const VERSION_DIGITS: usize = 9;
const VERSION_DIGIT_COUNT: usize = 7;
const KERNEL_CHECKSUM: usize = 16;
const ROOTFS_CHECKSUM: usize = 20;
const KERNEL_LEN: usize = 24;
const ROOTFS_LEN: usize = 28;
const IMAGE_CHECKSUM: usize = 32;
const HEADER_CHECKSUM: usize = 36;

/// `sizeof(struct chk_header)`, before the board ID.
const FIXED_HEADER_SIZE: usize = 40;

/// `MAX_BOARD_ID_LEN` in `mkchkimg.c`.
const MAX_BOARD_ID_LEN: usize = 64;

/// Region codes named in `mkchkimg.c`.
fn region_name(code: u8) -> &'static str {
    match code {
        1 => "WW",
        2 => "NA",
        _ => "unnamed",
    }
}

/// The Netgear checksum (`netgear_checksum_add` and `_fini`): two wrapping
/// byte sums, each folded to 16 bits with end-around carry.
#[derive(Debug, Default)]
struct NetgearChecksum {
    c0: u32,
    c1: u32,
}

impl NetgearChecksum {
    fn add(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.c0 = self.c0.wrapping_add(u32::from(b));
            self.c1 = self.c1.wrapping_add(self.c0);
        }
    }

    fn finish(&self) -> u32 {
        let fold = |sum: u32| {
            let folded = (sum & 0xffff) + (sum >> 16);
            ((folded >> 16) + folded) & 0xffff
        };
        (fold(self.c1) << 16) | fold(self.c0)
    }
}

/// The Netgear checksum of `parts` in order.
fn netgear_checksum(parts: &[&[u8]]) -> u32 {
    let mut checksum = NetgearChecksum::default();
    for part in parts {
        checksum.add(part);
    }
    checksum.finish()
}

/// Compare a stored checksum field with the computed one.
fn verify(name: &str, stored: u32, computed: u32) -> Result<()> {
    if stored == computed {
        Ok(())
    } else {
        Err(error(format!(
            "Invalid CHK {name} checksum 0x{stored:08X}, computed 0x{computed:08X}"
        )))
    }
}

/// The version digits `A.B.C.D_E.F.G` of the reserved field.
fn version_text(digits: [u8; VERSION_DIGIT_COUNT]) -> String {
    let text: Vec<String> = digits.iter().map(u8::to_string).collect();
    format!("{}_{}", text[..4].join("."), text[4..].join("."))
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let fixed = slice(data, 0, FIXED_HEADER_SIZE, "CHK header")?;
    if fixed[..4] != MAGIC {
        return Err(error("Missing CHK magic"));
    }
    let header_len = to_usize(be_u32(fixed, HEADER_LEN)?);
    let max_header_len = FIXED_HEADER_SIZE + MAX_BOARD_ID_LEN;
    if !(FIXED_HEADER_SIZE..=max_header_len).contains(&header_len) {
        return Err(error(format!(
            "Invalid CHK header length {header_len} B: expected 40 B plus a board ID of at most 64 B"
        )));
    }
    let board_id = slice(
        data,
        FIXED_HEADER_SIZE,
        header_len - FIXED_HEADER_SIZE,
        "CHK board ID",
    )?;
    // The header checksum covers the 40 header bytes with this field zero,
    // then the board ID.
    let mut zeroed: [u8; FIXED_HEADER_SIZE] = fixed.try_into().expect("40-byte header");
    zeroed[HEADER_CHECKSUM..].fill(0);
    verify(
        "header",
        be_u32(fixed, HEADER_CHECKSUM)?,
        netgear_checksum(&[&zeroed, board_id]),
    )?;

    let kernel_len = to_usize(be_u32(fixed, KERNEL_LEN)?);
    let rootfs_len = to_usize(be_u32(fixed, ROOTFS_LEN)?);
    if kernel_len == 0 {
        return Err(error("Invalid CHK kernel length 0 B"));
    }
    let kernel = slice(data, header_len, kernel_len, "CHK kernel")?;
    // In range: the kernel slice above ends there.
    let rootfs_offset = header_len + kernel_len;
    let rootfs = slice(data, rootfs_offset, rootfs_len, "CHK root filesystem")?;
    verify(
        "kernel",
        be_u32(fixed, KERNEL_CHECKSUM)?,
        netgear_checksum(&[kernel]),
    )?;
    if rootfs_len > 0 {
        verify(
            "root filesystem",
            be_u32(fixed, ROOTFS_CHECKSUM)?,
            netgear_checksum(&[rootfs]),
        )?;
    }
    verify(
        "image",
        be_u32(fixed, IMAGE_CHECKSUM)?,
        netgear_checksum(&[kernel, rootfs]),
    )?;
    let end = rootfs_offset + rootfs_len;
    let rest = &data[end..];
    if !is_padding(rest) {
        return Err(error(format!(
            "Unexpected {} after the CHK image at 0x{end:X}",
            size_text(rest.len())
        )));
    }

    let region = fixed[REGION];
    let version = version_text(array(fixed, VERSION_DIGITS)?);
    let board = display_text(board_id, MAX_BOARD_ID_LEN);
    let mut c = Container::new(FileFormat::NetgearChk, "Netgear CHK", "netgearchk");
    c.consumed = end;
    let checked = if rootfs_len > 0 {
        "header, kernel, root filesystem and image"
    } else {
        "header, kernel and image"
    };
    c.notes.push(format!(
        "Netgear CHK image; {checked} checksums verified; integrity checks only, not authenticated"
    ));
    c.notes.push(format!(
        "Board ID {board}; region code {region} ({}); version digits {version}; the board ID names no architecture",
        region_name(region)
    ));
    c.push_metadata("netgearchk_board_id", "Board ID", board);
    c.push_metadata("netgearchk_region", "Region code", u64::from(region));
    c.push_metadata("netgearchk_version", "Version digits", version);

    let mut extractor = Extractor::default();
    c.children
        .push(extractor.component("Kernel".into(), header_len, kernel, &mut c.notes));
    if rootfs_len > 0 {
        c.children.push(extractor.component(
            "Root filesystem".into(),
            rootfs_offset,
            rootfs,
            &mut c.notes,
        ));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netgear_checksum_matches_the_derived_check_value() {
        assert_eq!(netgear_checksum(&[b"123456789"]), 0x0915_01dd);
        assert_eq!(netgear_checksum(&[b"1234", b"56789"]), 0x0915_01dd);
        assert_eq!(netgear_checksum(&[]), 0);
    }

    #[test]
    fn netgear_checksum_folds_long_inputs_without_overflow() {
        let ones = vec![0xffu8; 1 << 16];
        let mut c0: u64 = 0;
        let mut c1: u64 = 0;
        for &b in &ones {
            c0 = (c0 + u64::from(b)) & 0xffff_ffff;
            c1 = (c1 + c0) & 0xffff_ffff;
        }
        let fold = |sum: u64| {
            let folded = (sum & 0xffff) + (sum >> 16);
            ((folded >> 16) + folded) & 0xffff
        };
        let expected = u32::try_from((fold(c1) << 16) | fold(c0)).expect("16-bit halves");
        assert_eq!(netgear_checksum(&[&ones]), expected);
    }

    #[test]
    fn version_digits_follow_the_file_name_pattern() {
        assert_eq!(version_text([1, 0, 2, 3, 4, 5, 6]), "1.0.2.3_4.5.6");
    }
}
