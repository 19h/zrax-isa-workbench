//! Allwinner boot ROM images: `eGON.BT0` boot0 / U-Boot SPL images and
//! TOC0 secure boot images (U-Boot `include/sunxi_image.h`,
//! `tools/sunxi_egon.c`, `tools/sunxi_toc0.c`; sunxi-tools `fel.c`).
//!
//! eGON header (`struct boot_file_head`, 0x60 bytes): jump instruction (0),
//! magic `eGON.BT0` (4), checksum (0x0C), length (0x10), U-Boot SPL
//! signature `SPL` and version byte (0x14..0x18), FEL script address
//! (0x18), FEL `uEnv` length (0x1C), DT name offset (0x20), DRAM size
//! (0x24), boot media (0x28), string pool (0x2C..0x60). Allwinner's own
//! boot0 keeps the first 0x14 bytes and continues with a private header.
//!
//! The checksum is the wrapping sum of the image's little-endian words over
//! `[0, length)`, computed with the checksum word replaced by
//! `BROM_STAMP_VALUE`. TOC0 images use the same sum.

use super::*;

/// eGON boot0 magic at offset 4, after the jump instruction
/// (`BOOT0_MAGIC`).
const EGON_MAGIC: &[u8; 8] = b"eGON.BT0";
const EGON_MAGIC_OFFSET: usize = 4;

/// eGON header fields.
const JUMP_INSTRUCTION: usize = 0;
const CHECKSUM: usize = 0x0c;
const LENGTH: usize = 0x10;
const SPL_SIGNATURE: usize = 0x14;
const SPL_VERSION: usize = 0x17;
const DT_NAME_OFFSET: usize = 0x20;
/// `string_pool`, where `mksunxiboot` stores the device tree name.
const STRING_POOL: usize = 0x2c;

/// Size of U-Boot's `struct boot_file_head`.
const EGON_HEADER_SIZE: usize = 0x60;

/// Jump, magic, checksum and length: the fields every eGON header shares
/// (U-Boot's and Allwinner's own). A jump into them is not a jump to code.
const EGON_COMMON_SIZE: usize = 0x14;

/// `BROM_STAMP_VALUE`: the checksum word's value while the sum is formed.
const BROM_STAMP: u32 = 0x5f0a_6c39;

/// U-Boot SPL signature at 0x14 (`SPL_SIGNATURE`); the version byte at
/// 0x17 is `(major << SPL_MINOR_BITS) | minor`.
const SPL_MAGIC: &[u8; 3] = b"SPL";
const SPL_MINOR_BITS: u8 = 5;
const SPL_MINOR_MASK: u8 = 0x1f;

/// `SPL_DT_HEADER_VERSION`, version 0.2: the header has a DT name offset.
const SPL_DT_HEADER_VERSION: u8 = 2;

/// Longest device tree name read from the string pool.
const MAX_DT_NAME: usize = 64;

/// A32 unconditional `B` as `egon_verify_header` checks it: condition AL
/// and opcode `1010` in the top byte, with a signed 24-bit word offset from
/// PC + 8.
const ARM_B_MASK: u32 = 0xff00_0000;
const ARM_B: u32 = 0xea00_0000;
const ARM_B_OFFSET_MASK: u32 = 0x00ff_ffff;
const ARM_B_OFFSET_BITS: u32 = 24;
const ARM_PC_AHEAD: i64 = 8;

/// RISC-V `JAL x0` (`j`) as `egon_verify_header` checks it: opcode `0x6F`
/// with destination register 0 in the low 12 bits; a 21-bit signed byte
/// offset.
const RISCV_JAL_MASK: u32 = 0x0000_0fff;
const RISCV_JAL_X0: u32 = 0x0000_006f;
const RISCV_JAL_OFFSET_BITS: u32 = 21;

/// U-Boot's mkimage requires lengths in whole 512-byte blocks
/// (`egon_verify_header`); sunxi-tools only requires whole words.
const EGON_LENGTH_ALIGN: usize = 512;

/// TOC0 main header (`struct toc0_main_info`, 0x30 bytes): name (0), magic
/// (8), checksum (0x0C), serial (0x10), status (0x14), item count (0x18),
/// length (0x1C), platform (0x20), reserved (0x24), end marker (0x2C).
const TOC0_NAME: &[u8; 8] = b"TOC0.GLH";
const TOC0_MAGIC: u32 = 0x8911_9800;
const TOC0_MAGIC_OFFSET: usize = 8;
const TOC0_CHECKSUM: usize = 0x0c;
const TOC0_NUM_ITEMS: usize = 0x18;
const TOC0_LENGTH: usize = 0x1c;
const TOC0_MAIN_END: usize = 0x2c;
const TOC0_MAIN_SIZE: usize = 0x30;
const TOC0_END: &[u8; 4] = b"MIE;";

/// TOC0 item (`struct toc0_item_info`, 0x20 bytes): name (0), offset (4),
/// length (8), status (0x0C), type (0x10), load address (0x14), reserved
/// (0x18), end marker (0x1C). Offsets are from the start of the image.
const TOC0_ITEM_SIZE: usize = 0x20;
const TOC0_ITEM_OFFSET: usize = 4;
const TOC0_ITEM_LENGTH: usize = 8;
const TOC0_ITEM_LOAD_ADDRESS: usize = 0x14;
const TOC0_ITEM_END_OFFSET: usize = 0x1c;
const TOC0_ITEM_END: &[u8; 4] = b"IIE;";

/// TOC0 item names (`TOC0_ITEM_INFO_NAME_*`).
const TOC0_ITEM_CERT: u32 = 0x0001_0101;
const TOC0_ITEM_FIRMWARE: u32 = 0x0001_0202;
const TOC0_ITEM_KEY: u32 = 0x0001_0303;

/// `toc0_verify` requires the length to be a multiple of 512 bytes.
const TOC0_LENGTH_ALIGN: usize = 512;

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic_end = EGON_MAGIC_OFFSET + EGON_MAGIC.len();
    if data.get(EGON_MAGIC_OFFSET..magic_end) == Some(EGON_MAGIC) {
        return Some(Layout::Egon);
    }
    let is_toc0 = data.get(..TOC0_NAME.len()) == Some(TOC0_NAME)
        && le_u32(data, TOC0_MAGIC_OFFSET).ok() == Some(TOC0_MAGIC);
    is_toc0.then_some(Layout::Toc0)
}

/// Wrapping sum of the little-endian words of `image`, with the word at
/// `checksum_at` replaced by [`BROM_STAMP`]. A partial final word is not
/// summed.
fn stamp_checksum(image: &[u8], checksum_at: usize) -> u32 {
    image
        .chunks_exact(4)
        .enumerate()
        .fold(0u32, |sum, (i, word)| {
            let value = if i * 4 == checksum_at {
                BROM_STAMP
            } else {
                u32::from_le_bytes(word.try_into().expect("chunk has exactly 4 bytes"))
            };
            sum.wrapping_add(value)
        })
}

/// Verify the `stored` stamp checksum of `image`, whose checksum word is at
/// `checksum_at`.
fn verify_checksum(image: &[u8], checksum_at: usize, stored: u32, what: &str) -> Result<()> {
    let computed = stamp_checksum(image, checksum_at);
    if stored != computed {
        return Err(error(format!(
            "Invalid {what} checksum 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(())
}

/// The instruction set of the boot ROM's first instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JumpKind {
    /// A32 `B`.
    Arm,
    /// RISC-V `JAL x0`.
    RiscV,
}

/// A decoded jump instruction and its target, as a byte offset from the
/// start of the image (negative for a backward branch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Jump {
    pub(crate) kind: JumpKind,
    pub(crate) target: i64,
}

/// Sign-extend the low `bits` bits of `value`.
pub(crate) fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// J-type immediate of a RISC-V `JAL`: `imm[20|10:1|11|19:12]` in
/// instruction bits 31, 30:21, 20 and 19:12.
fn jal_offset(word: u32) -> i64 {
    let imm_20 = (word >> 31) & 0x1;
    let imm_10_1 = (word >> 21) & 0x3ff;
    let imm_11 = (word >> 20) & 0x1;
    let imm_19_12 = (word >> 12) & 0xff;
    let imm = (imm_20 << 20) | (imm_19_12 << 12) | (imm_11 << 11) | (imm_10_1 << 1);
    sign_extend(imm, RISCV_JAL_OFFSET_BITS)
}

/// Decode the jump instruction at offset 0 the way `egon_verify_header`
/// classifies it: an A32 `B` or a RISC-V `JAL x0`. The barebox parser
/// (`bootmisc::barebox`) shares the A32 decoding.
pub(crate) fn decode_jump(word: u32) -> Option<Jump> {
    if word & ARM_B_MASK == ARM_B {
        let words = sign_extend(word & ARM_B_OFFSET_MASK, ARM_B_OFFSET_BITS);
        return Some(Jump {
            kind: JumpKind::Arm,
            target: ARM_PC_AHEAD + words * 4,
        });
    }
    if word & RISCV_JAL_MASK == RISCV_JAL_X0 {
        return Some(Jump {
            kind: JumpKind::RiscV,
            target: jal_offset(word),
        });
    }
    None
}

/// The target the jump instruction names, and the note that states it.
/// A jump counts as evidence only when it lands inside the image, past the
/// shared header fields.
fn jump_target(word: u32, length: usize) -> (Option<Target>, String) {
    let Some(jump) = decode_jump(word) else {
        return (
            None,
            format!(
                "Jump instruction 0x{word:08X} is neither an A32 B nor a RISC-V JAL x0; ISA from the code model"
            ),
        );
    };
    let (name, target, caveat) = match jump.kind {
        JumpKind::Arm => (
            "A32 B",
            Target::new(Isa::Arm, 32, Endianness::Little),
            "the boot ROM enters in AArch32; 64-bit SoCs may switch to AArch64 later",
        ),
        JumpKind::RiscV => (
            "RISC-V JAL x0",
            Target::new(Isa::RiscV64, 64, Endianness::Little),
            "the instruction does not encode XLEN; 64-bit is assumed",
        ),
    };
    let inside = usize::try_from(jump.target)
        .is_ok_and(|offset| (EGON_COMMON_SIZE..length).contains(&offset));
    if !inside {
        let note = format!(
            "Jump instruction 0x{word:08X} ({name}) targets image offset {}, outside the image code; ISA from the code model",
            jump.target
        );
        return (None, note);
    }
    let note = format!(
        "Boot ROM entry ISA from the jump instruction 0x{word:08X}: {name} to image offset 0x{:X}; {caveat}",
        jump.target
    );
    (Some(target), note)
}

/// `SPL` signature version as `(major, minor)`, when U-Boot wrote one.
/// `header` is the 0x60-byte eGON header.
fn spl_version(header: &[u8]) -> Option<(u8, u8)> {
    if &header[SPL_SIGNATURE..SPL_SIGNATURE + SPL_MAGIC.len()] != SPL_MAGIC {
        return None;
    }
    let version = header[SPL_VERSION];
    Some((version >> SPL_MINOR_BITS, version & SPL_MINOR_MASK))
}

/// The NUL-terminated device tree name an SPL header (version 0.2 and
/// later) points to, relative to the start of the image; normally the
/// string pool. Names that are not printable ASCII are ignored.
fn dt_name(image: &[u8], header: &[u8]) -> Option<String> {
    let offset = usize::try_from(le_u32(header, DT_NAME_OFFSET).ok()?).ok()?;
    if offset < STRING_POOL {
        return None;
    }
    let field = image.get(offset..)?;
    let name = text_field(&field[..field.len().min(MAX_DT_NAME)]);
    let printable = name.bytes().all(|b| b.is_ascii_graphic());
    (!name.is_empty() && printable).then_some(name)
}

/// SPL header version and device tree name, as notes and metadata.
fn describe_spl(c: &mut Container<'_>, image: &[u8], header: &[u8]) {
    let Some((major, minor)) = spl_version(header) else {
        return;
    };
    c.notes
        .push(format!("U-Boot SPL header version {major}.{minor}"));
    c.push_metadata(
        "allwinner_spl_version",
        "SPL header version",
        format!("{major}.{minor}"),
    );
    let has_dt_name = major > 0 || minor >= SPL_DT_HEADER_VERSION;
    if let Some(name) = dt_name(image, header).filter(|_| has_dt_name) {
        c.push_metadata("allwinner_dt_name", "Device tree name", name);
    }
}

pub(super) fn parse_egon(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, EGON_HEADER_SIZE, "eGON header")?;
    if &header[EGON_MAGIC_OFFSET..EGON_MAGIC_OFFSET + EGON_MAGIC.len()] != EGON_MAGIC {
        return Err(error("Missing eGON.BT0 magic"));
    }
    let length = le_size(header, LENGTH)?;
    if length % 4 != 0 || length < EGON_HEADER_SIZE {
        return Err(error(format!(
            "Invalid eGON length {length} B: not a whole number of words covering the 96 B header"
        )));
    }
    let image = range(data, 0, length, "eGON image")?;
    let checksum = le_u32(header, CHECKSUM)?;
    verify_checksum(image, CHECKSUM, checksum, "eGON")?;
    let word = le_u32(header, JUMP_INSTRUCTION)?;
    let (target, jump_note) = jump_target(word, length);

    let mut c = Container::new(FileFormat::AllwinnerEgon, Layout::Egon.label(), "allwinner");
    c.target = target;
    c.consumed = length;
    // The section is the image itself; it must never be detected again as
    // an eGON container.
    c.code_sections = true;
    c.notes.push(format!(
        "Allwinner eGON.BT0 boot image; checksum 0x{checksum:08X} verified over {}",
        size_text(length)
    ));
    c.notes.push(jump_note);
    c.notes.push(
        "The SRAM load address is not encoded; the section address is the image offset".into(),
    );
    if length % EGON_LENGTH_ALIGN != 0 {
        c.notes.push(format!(
            "Length {} is not a multiple of 512 B, which U-Boot's mkimage requires",
            size_text(length)
        ));
    }
    c.push_metadata("allwinner_length", "Checksummed length (B)", length as u64);
    c.push_metadata(
        "allwinner_checksum",
        "Checksum",
        format!("0x{checksum:08X} (verified)"),
    );
    c.push_metadata(
        "allwinner_jump_instruction",
        "Jump instruction",
        format!("0x{word:08X}"),
    );
    describe_spl(&mut c, image, header);
    c.sections.push(Section {
        label: "Boot image".into(),
        address: 0,
        offset: 0,
        stored_size: length,
        data: Cow::Borrowed(image),
        transform: None,
    });
    if let Some(member) = trailing_member(data, length, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

/// Display name of a TOC0 item.
fn toc0_item_name(name: u32) -> String {
    match name {
        TOC0_ITEM_CERT => "Certificate".into(),
        TOC0_ITEM_FIRMWARE => "Firmware".into(),
        TOC0_ITEM_KEY => "Key".into(),
        other => format!("Item 0x{other:08X}"),
    }
}

/// The TOC0 main header and its checksummed image, checked in the order of
/// U-Boot's `toc0_verify`: length against the file, name and magic,
/// checksum, length alignment, end marker.
fn toc0_image(data: &[u8]) -> Result<(&[u8], u32)> {
    let main = range(data, 0, TOC0_MAIN_SIZE, "TOC0 main header")?;
    let length = le_size(main, TOC0_LENGTH)?;
    let image = range(data, 0, length, "TOC0 image")?;
    if &main[..TOC0_NAME.len()] != TOC0_NAME || le_u32(main, TOC0_MAGIC_OFFSET)? != TOC0_MAGIC {
        return Err(error("Missing TOC0 name and magic"));
    }
    if length < TOC0_MAIN_SIZE {
        return Err(error(format!(
            "Invalid TOC0 length {length} B: shorter than the 48 B main header"
        )));
    }
    let checksum = le_u32(main, TOC0_CHECKSUM)?;
    verify_checksum(image, TOC0_CHECKSUM, checksum, "TOC0")?;
    if length % TOC0_LENGTH_ALIGN != 0 {
        return Err(error(format!(
            "Invalid TOC0 length {length} B: not a multiple of 512 B"
        )));
    }
    if &main[TOC0_MAIN_END..TOC0_MAIN_SIZE] != TOC0_END {
        return Err(error("Missing TOC0 main header end marker MIE;"));
    }
    Ok((image, checksum))
}

pub(super) fn parse_toc0(data: &[u8]) -> Result<Container<'_>> {
    let (image, checksum) = toc0_image(data)?;
    let length = image.len();
    let count = le_size(image, TOC0_NUM_ITEMS)?;
    if count > (length - TOC0_MAIN_SIZE) / TOC0_ITEM_SIZE {
        return Err(error(format!(
            "Invalid TOC0 item count {count}: the item table exceeds the {} image",
            size_text(length)
        )));
    }

    let mut c = Container::new(FileFormat::AllwinnerEgon, Layout::Toc0.label(), "allwinner");
    c.consumed = length;
    c.notes.push(format!(
        "Allwinner TOC0 secure boot image; checksum 0x{checksum:08X} verified over {}",
        size_text(length)
    ));
    c.notes.push(
        "Certificate signatures and the firmware digest are not verified; items are not analyzed because the parser does not establish whether they are encrypted"
            .into(),
    );
    c.push_metadata("allwinner_length", "Checksummed length (B)", length as u64);
    c.push_metadata("allwinner_toc0_items", "TOC0 items", count as u64);
    for i in 0..count {
        let item = range(
            image,
            TOC0_MAIN_SIZE + i * TOC0_ITEM_SIZE,
            TOC0_ITEM_SIZE,
            "TOC0 item",
        )?;
        let item_name = le_u32(item, 0)?;
        let name = toc0_item_name(item_name);
        let offset = le_size(item, TOC0_ITEM_OFFSET)?;
        let size = le_size(item, TOC0_ITEM_LENGTH)?;
        let bytes = range(image, offset, size, &format!("TOC0 item {i} ({name})"))?;
        // U-Boot writes the item end marker but does not check it.
        if &item[TOC0_ITEM_END_OFFSET..TOC0_ITEM_SIZE] != TOC0_ITEM_END {
            c.notes
                .push(format!("TOC0 item {i} ({name}) has no IIE; end marker"));
        }
        if item_name == TOC0_ITEM_FIRMWARE {
            let load = le_u32(item, TOC0_ITEM_LOAD_ADDRESS)?;
            c.push_metadata(
                "allwinner_toc0_load_address",
                "Firmware load address",
                format!("0x{load:08X}"),
            );
        }
        c.children.push(Child::opaque(name, offset, bytes));
    }
    if let Some(member) = trailing_member(data, length, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_words_decode_like_sunxi_egon() {
        // U-Boot's generated words for a 0x60-byte header.
        assert_eq!(
            decode_jump(0xea00_0016),
            Some(Jump {
                kind: JumpKind::Arm,
                target: 0x60
            })
        );
        assert_eq!(
            decode_jump(0x0600_006f),
            Some(Jump {
                kind: JumpKind::RiscV,
                target: 0x60
            })
        );
        // A32 B and RISC-V JAL with negative offsets.
        assert_eq!(decode_jump(0xeaff_fffe).map(|j| j.target), Some(0));
        assert_eq!(decode_jump(0xffdf_f06f).map(|j| j.target), Some(-4));
        // BL (link bit set) and JAL x1 are not the documented jumps.
        assert_eq!(decode_jump(0xeb00_0016), None);
        assert_eq!(decode_jump(0x0600_00ef), None);
    }

    #[test]
    fn jumps_outside_the_image_code_name_no_target() {
        // B to offset 0x10 lands in the checksum and length fields.
        assert!(jump_target(0xea00_0002, 0x200).0.is_none());
        // B to 0x60 in an image of exactly 0x60 bytes.
        assert!(jump_target(0xea00_0016, 0x60).0.is_none());
        assert_eq!(
            jump_target(0xea00_0016, 0x200).0,
            Some(Target::new(Isa::Arm, 32, Endianness::Little))
        );
    }

    #[test]
    fn stamp_checksum_replaces_the_checksum_word() {
        let mut image = vec![0u8; 16];
        image[0..4].copy_from_slice(&1u32.to_le_bytes());
        image[12..16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(stamp_checksum(&image, 12), 1u32.wrapping_add(BROM_STAMP));
    }
}
