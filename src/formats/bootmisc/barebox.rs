//! barebox ARM and `AArch64` images with the barebox head at offset 0.
//!
//! Layouts, from barebox v2024.10.0 `arch/arm/include/asm/barebox-arm-head.h`
//! (`__barebox_arm_head`, `ARM_HEAD_SPARE_OFS`, `ARM_HEAD_SPARE_MARKER`),
//! `arch/arm/cpu/head_64.S` (`__barebox_arm64_head`),
//! `arch/arm/include/asm/barebox-arm64.h` (`ENTRY_PROC`) and
//! `arch/arm/lib/pbl.lds.S` (`_barebox_image_size`, the image linked at 0).
//! Words are little-endian.
//!
//! Head: eight instruction words (0), the magic `barebox\0` (0x20), the
//! text base (0x28; `0xFFFFFFFF` in both `AArch64` heads), the image size
//! in bytes (0x2C), eight spare words reserved for the board or
//! system-on-chip (0x30, `0x55555555` when unused), then code (0x50).
//!
//! The first instruction names the instruction set, as the head defines
//! it: an A32 `B` over the head (`b 2f`), the A32 `adr r9, 1f + 1; bx r9`
//! pair that enters Thumb (`CONFIG_THUMB2_BAREBOX`), an A64 `B` over the
//! head (`ENTRY_PROC`) or an A64 `NOP` (`__barebox_arm64_head`). The
//! encodings were confirmed by assembling the heads with clang.

use super::*;
use crate::formats::socboot2::{decode_jump, sign_extend, Jump, JumpKind};
use std::borrow::Cow;

/// The magic after the instruction words.
const MAGIC: &[u8; 8] = b"barebox\0";
const MAGIC_OFFSET: usize = 0x20;

/// Head fields.
const SECOND_WORD: usize = 4;
const TEXT_BASE: usize = 0x28;
const IMAGE_SIZE: usize = 0x2c;
const SPARE_OFFSET: usize = 0x30;
const SPARE_WORDS: usize = 8;
const HEADER_SIZE: usize = 0x50;

/// `ARM_HEAD_SPARE_MARKER`: an unused spare word.
const SPARE_MARKER: u32 = 0x5555_5555;

/// Text base the `AArch64` heads store (`.word 0xffffffff`).
const NO_TEXT_BASE: u32 = 0xffff_ffff;

/// `adr r9, 1f + 1` (`add r9, pc, #1`) and `bx r9`: the A32 words that
/// enter the Thumb-2 head.
const A32_ADR_R9_PLUS_1: u32 = 0xe28f_9001;
const A32_BX_R9: u32 = 0xe12f_ff19;

/// A64 unconditional `B`: opcode `000101` in the top six bits and a
/// signed 26-bit word offset.
const A64_B_MASK: u32 = 0xfc00_0000;
const A64_B: u32 = 0x1400_0000;
const A64_B_OFFSET_MASK: u32 = 0x03ff_ffff;
const A64_B_OFFSET_BITS: u32 = 26;

/// A64 `NOP`.
const A64_NOP: u32 = 0xd503_201f;

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len())?;
    (magic == MAGIC).then_some(Layout::Barebox)
}

/// The barebox head the first instruction words select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A32 `B` to a byte offset from the image start.
    A32Branch(i64),
    /// A32 `adr r9` and `bx r9` into Thumb-2 code.
    Thumb2,
    /// A64 `B` to a byte offset from the image start.
    A64Branch(i64),
    /// A64 `NOP`, the start of `__barebox_arm64_head`.
    A64Nop,
    /// None of the documented heads.
    Unknown,
}

fn head(first: u32, second: u32) -> Head {
    if let Some(Jump {
        kind: JumpKind::Arm,
        target,
    }) = decode_jump(first)
    {
        return Head::A32Branch(target);
    }
    if first == A32_ADR_R9_PLUS_1 && second == A32_BX_R9 {
        return Head::Thumb2;
    }
    if first & A64_B_MASK == A64_B {
        let words = sign_extend(first & A64_B_OFFSET_MASK, A64_B_OFFSET_BITS);
        return Head::A64Branch(words * 4);
    }
    if first == A64_NOP {
        return Head::A64Nop;
    }
    Head::Unknown
}

/// Whether a branch from the head lands in the image code after the head.
fn lands_in_code(target: i64, size: usize) -> bool {
    usize::try_from(target).is_ok_and(|offset| (HEADER_SIZE..size).contains(&offset))
}

/// What the head establishes about the instruction set.
struct HeadTarget {
    /// The target the head names, or `None` when the code model decides.
    target: Option<Target>,
    /// The note that states where the ISA comes from.
    note: String,
}

/// The target the head names and the note that states it.
fn head_target(head: Head, text_base: u32, size: usize, first: u32) -> HeadTarget {
    let source = "barebox-arm-head.h";
    match head {
        Head::A32Branch(target) if lands_in_code(target, size) => HeadTarget {
            target: Some(arm_target(false)),
            note: format!(
                "ISA from the barebox head: A32 B 0x{first:08X} to image offset 0x{target:X} ({source})"
            ),
        },
        Head::Thumb2 => HeadTarget {
            target: Some(arm_target(false)),
            note: format!(
                "ISA from the barebox head: A32 adr r9 and bx r9 into Thumb-2 code (CONFIG_THUMB2_BAREBOX, {source})"
            ),
        },
        Head::A64Branch(target) if lands_in_code(target, size) => HeadTarget {
            target: Some(arm_target(true)),
            note: format!(
                "ISA from the barebox head: A64 B 0x{first:08X} to image offset 0x{target:X} (ENTRY_PROC, barebox-arm64.h)"
            ),
        },
        Head::A64Nop if text_base == NO_TEXT_BASE => HeadTarget {
            target: Some(arm_target(true)),
            note: "ISA from the barebox head: A64 NOP and text base 0xFFFFFFFF (__barebox_arm64_head, head_64.S)"
                .to_string(),
        },
        Head::A32Branch(target) | Head::A64Branch(target) => HeadTarget {
            target: None,
            note: format!(
                "Head branch 0x{first:08X} targets image offset {target}, outside the image code; ISA from the code model"
            ),
        },
        Head::A64Nop => HeadTarget {
            target: None,
            note: format!(
                "A64 NOP head with text base 0x{text_base:08X}, not 0xFFFFFFFF; ISA from the code model"
            ),
        },
        Head::Unknown => HeadTarget {
            target: None,
            note: format!(
                "First instruction 0x{first:08X} is not a documented barebox head; ISA from the code model"
            ),
        },
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, HEADER_SIZE, "barebox head")?;
    if &header[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] != MAGIC {
        return Err(error("Missing barebox magic"));
    }
    let size = le_u32(header, IMAGE_SIZE)? as usize;
    if size < HEADER_SIZE {
        return Err(error(format!(
            "Invalid barebox image size {size} B: shorter than the 80 B head"
        )));
    }
    let image = range(data, 0, size, "barebox image")?;
    let first = le_u32(header, 0)?;
    let second = le_u32(header, SECOND_WORD)?;
    let text_base = le_u32(header, TEXT_BASE)?;
    let from_head = head_target(head(first, second), text_base, size, first);

    let mut c = Container::new(FileFormat::BareboxImage, Layout::Barebox.label(), "barebox");
    c.target = from_head.target;
    c.consumed = size;
    // The section is the image itself; it must never be detected again as
    // a barebox container.
    c.code_sections = true;
    c.notes.push(format!(
        "barebox image: {} (image size field at 0x2C)",
        size_text(size)
    ));
    c.notes.push(from_head.note);
    c.notes
        .push("Execution starts at image offset 0; the load address is not encoded".into());
    if text_base != NO_TEXT_BASE {
        c.push_metadata(
            "barebox_text_base",
            "Text base",
            format!("0x{text_base:08X}"),
        );
    }
    let spare = range(header, SPARE_OFFSET, SPARE_WORDS * 4, "barebox spare words")?;
    let unused = spare
        .chunks_exact(4)
        .all(|w| u32::from_le_bytes(w.try_into().expect("four bytes")) == SPARE_MARKER);
    if !unused {
        c.notes.push(
            "The spare words at 0x30 hold board or system-on-chip data (not 0x55555555)".into(),
        );
    }
    c.push_metadata("barebox_image_size", "Image size (B)", size as u64);
    c.push_metadata(
        "barebox_first_word",
        "First instruction",
        format!("0x{first:08X}"),
    );
    c.sections.push(container::Section {
        label: "barebox image".into(),
        address: 0,
        offset: 0,
        stored_size: size,
        data: Cow::Borrowed(image),
        transform: None,
    });
    if let Some(member) = trailing_member(data, size, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_decode_like_the_assembled_words() {
        // Words assembled by clang from the barebox heads.
        assert_eq!(head(0xea00_0012, 0xeaff_fffe), Head::A32Branch(0x50));
        assert_eq!(head(A32_ADR_R9_PLUS_1, A32_BX_R9), Head::Thumb2);
        assert_eq!(head(0x1400_0014, A64_NOP), Head::A64Branch(0x50));
        assert_eq!(head(A64_NOP, 0x1000_0269), Head::A64Nop);
        assert_eq!(head(A32_ADR_R9_PLUS_1, 0), Head::Unknown);
        assert_eq!(head(0x17ff_ffff, 0), Head::A64Branch(-4));
        // A RISC-V JAL is not a barebox ARM head.
        assert_eq!(head(0x0600_006f, 0), Head::Unknown);
    }

    #[test]
    fn branches_must_land_after_the_head() {
        assert!(lands_in_code(0x50, 0x51));
        assert!(!lands_in_code(0x50, 0x50));
        assert!(!lands_in_code(0x30, 0x200));
        assert!(!lands_in_code(-4, 0x200));
        assert!(head_target(Head::A32Branch(0x50), 0, 0x200, 0)
            .target
            .is_some());
        assert!(head_target(Head::A64Nop, 0, 0x200, A64_NOP)
            .target
            .is_none());
    }
}
