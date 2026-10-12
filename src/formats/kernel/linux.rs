//! Linux kernel images: x86 `bzImage`/`zImage`, 32-bit Arm `zImage`, 64-bit
//! Arm and RISC-V `Image`.

use super::*;

/// x86 setup header fields (`Documentation/arch/x86/boot.rst`).
const SETUP_SECTS: usize = 0x1f1;
const BOOT_FLAG: usize = 0x1fe;
const HEADER_MAGIC: usize = 0x202;
const PROTOCOL: usize = 0x206;
const LOADFLAGS: usize = 0x211;
const XLOADFLAGS: usize = 0x236;
const PAYLOAD_OFFSET: usize = 0x248;
const PAYLOAD_LENGTH: usize = 0x24c;

/// End of the setup header fields read here.
const SETUP_HEADER_END: usize = 0x250;

/// `loadflags` bit 0: the protected-mode code loads at 1 MiB (bzImage).
const LOADED_HIGH: u8 = 0x01;

/// `xloadflags` bit 0: the kernel has a 64-bit entry point at 0x200.
const XLF_KERNEL_64: u16 = 0x0001;

/// First protocol with `xloadflags` and with `payload_offset`.
const PROTOCOL_XLOADFLAGS: u16 = 0x020c;
const PROTOCOL_PAYLOAD: u16 = 0x0208;

/// A zero `setup_sects` means four sectors (boot protocol, `setup_sects`).
const DEFAULT_SETUP_SECTS: usize = 4;
const SECTOR: usize = 512;

/// Arm zImage header (`arch/arm/boot/compressed/head.S`): magic at 0x24,
/// zImage start and end addresses at 0x28/0x2C, endianness flag at 0x30,
/// then optionally the table marker at 0x34 and the table offset at 0x38.
const ZIMAGE_MAGIC_OFFSET: usize = 0x24;
const ZIMAGE_START: usize = 0x28;
const ZIMAGE_END: usize = 0x2c;
const ZIMAGE_ENDIAN_FLAG: usize = 0x30;
const ZIMAGE_HEADER_END: usize = 0x34;
const ZIMAGE_TABLE_MARKER_OFFSET: usize = 0x34;
const ZIMAGE_TABLE_OFFSET: usize = 0x38;

/// `0x45454545` at 0x34 announces the extension table (`vmlinux.lds.S`).
const ZIMAGE_TABLE_MARKER: u32 = 0x4545_4545;

/// Extension table tag whose third word is the file offset of the
/// decompressed-size word at the end of the compressed kernel.
const ZIMAGE_TAG_KRNL_SIZE: u32 = 0x5a53_4c4b;

/// Most extension-table tags walked.
const ZIMAGE_MAX_TAGS: usize = 64;

/// The endianness flag reads 0x04030201 in the kernel's own byte order.
const ZIMAGE_LITTLE_ENDIAN: u32 = 0x0403_0201;
const ZIMAGE_BIG_ENDIAN: u32 = 0x0102_0304;

/// Most codec candidates tried when locating an Arm zImage's payload.
const MAX_PAYLOAD_CANDIDATES: usize = 64;

/// 64-bit Arm and RISC-V `Image` headers: text offset at 8, image size at 16,
/// flags at 24 (bit 0: big-endian kernel data).
const IMAGE_TEXT_OFFSET: usize = 8;
const IMAGE_SIZE: usize = 16;
const IMAGE_FLAGS: usize = 24;
const IMAGE_FLAG_BIG_ENDIAN: u64 = 0x1;
const IMAGE_HEADER_SIZE: usize = 0x40;

/// 64-bit Arm `Image` magic offset and RISC-V `Image` magic offsets.
const ARM64_MAGIC_OFFSET: usize = 0x38;
const RISCV_MAGIC_OFFSET: usize = 0x30;
const RISCV_MAGIC2_OFFSET: usize = 0x38;
const RISCV_MAGIC2: [u8; 4] = *b"RSC\x05";

pub(super) fn detect(data: &[u8]) -> Option<KernelFormat> {
    if data.len() >= IMAGE_HEADER_SIZE && le_u32(data, ARM64_MAGIC_OFFSET).ok()? == ARM64_MAGIC {
        return Some(KernelFormat::LinuxArm64);
    }
    if data.len() >= IMAGE_HEADER_SIZE
        && (data[RISCV_MAGIC_OFFSET..RISCV_MAGIC_OFFSET + 5] == RISCV_MAGIC[..5]
            || data[RISCV_MAGIC2_OFFSET..RISCV_MAGIC2_OFFSET + 4] == RISCV_MAGIC2)
    {
        return Some(KernelFormat::LinuxRiscv);
    }
    if data.len() >= ZIMAGE_HEADER_END {
        // Little-endian and BE8 kernels store the magic little-endian; BE8
        // leaves the flag in data order. BE32 kernels store every header
        // word big-endian.
        let flag = le_u32(data, ZIMAGE_ENDIAN_FLAG).ok()?;
        let byte_order = if le_u32(data, ZIMAGE_MAGIC_OFFSET).ok()? == ZIMAGE_MAGIC {
            match flag {
                ZIMAGE_LITTLE_ENDIAN => Some(ArmByteOrder::Little),
                ZIMAGE_BIG_ENDIAN => Some(ArmByteOrder::Be8),
                _ => None,
            }
        } else if be_u32(data, ZIMAGE_MAGIC_OFFSET).ok()? == ZIMAGE_MAGIC
            && be_u32(data, ZIMAGE_ENDIAN_FLAG).ok()? == ZIMAGE_LITTLE_ENDIAN
        {
            Some(ArmByteOrder::Be32)
        } else {
            None
        };
        if let Some(byte_order) = byte_order {
            return Some(KernelFormat::LinuxArm { byte_order });
        }
    }
    if data.len() >= SETUP_HEADER_END
        && le_u16(data, BOOT_FLAG).ok()? == BOOT_SIGNATURE
        && data[HEADER_MAGIC..HEADER_MAGIC + 4] == HDRS_MAGIC
    {
        return Some(KernelFormat::LinuxX86 {
            protocol_version: le_u16(data, PROTOCOL).ok()?,
        });
    }
    None
}

/// From protocol 2.08 the last four bytes hold a CRC-32 (reflected
/// polynomial, initial value all ones, no final XOR) of everything before
/// them (`arch/x86/boot/tools/build.c`). Signing tools append data after
/// it, so a mismatch is reported, not rejected.
fn image_crc_note(data: &[u8]) -> String {
    let Some(body_end) = data.len().checked_sub(4) else {
        return "Image CRC-32 not verified: image too short".into();
    };
    let stored = le_u32(data, body_end).unwrap_or_default();
    let computed = crate::formats::checksum::crc32_update(!0, &data[..body_end]);
    if stored == computed {
        "Image CRC-32 verified".into()
    } else {
        "Image CRC-32 does not match the last four bytes; the image may be signed or modified"
            .into()
    }
}

/// x86 boot image: real-mode setup sectors, then the protected-mode
/// kernel, whose compressed payload (an ELF `vmlinux`) the setup header
/// locates from protocol 2.08.
pub(super) fn x86(data: &[u8], protocol: u16) -> Result<Container<'_>> {
    slice(data, 0, SETUP_HEADER_END)?;
    let setup_sects = match usize::from(data[SETUP_SECTS]) {
        0 => DEFAULT_SETUP_SECTS,
        n => n,
    };
    let kernel_start = (setup_sects + 1) * SECTOR;
    if kernel_start > data.len() {
        return Err(error(format!(
            "Truncated x86 kernel image: setup code ends at 0x{kernel_start:X}"
        )));
    }
    let kind = if data[LOADFLAGS] & LOADED_HIGH != 0 {
        "bzImage (big zImage)"
    } else {
        "zImage"
    };
    let mut c = Container::new(FileFormat::ZImage, kind, "zimage");
    c.consumed = data.len();
    c.notes.push("Linux x86 boot image".into());
    c.notes.push(format!("Type: {kind}"));
    c.notes.push(format!(
        "Protocol version: {}.{}",
        protocol >> 8,
        protocol & 0xff
    ));
    c.notes.push(format!("Setup sectors: {setup_sects}"));
    if protocol >= PROTOCOL_XLOADFLAGS {
        let xloadflags = le_u16(data, XLOADFLAGS)?;
        c.target = Some(if xloadflags & XLF_KERNEL_64 != 0 {
            c.notes
                .push("64-bit kernel entry point present (XLF_KERNEL_64)".into());
            Target::new(Isa::X86_64, 64, Endianness::Little)
        } else {
            Target::new(Isa::X86, 32, Endianness::Little)
        });
    } else if protocol < PROTOCOL_PAYLOAD {
        // No payload location: the setup and decompressor code is x86,
        // but whether the kernel is 64-bit is not recorded.
        c.target = Some(Target::new(Isa::X86, 32, Endianness::Little));
        c.notes.push(
            "Boot protocol before 2.08 records neither a 64-bit entry point nor the payload location"
                .into(),
        );
    } else {
        c.notes.push(
            "Boot protocol before 2.12 does not record whether the kernel is 64-bit; ISA taken from the payload"
                .into(),
        );
    }
    if protocol >= PROTOCOL_PAYLOAD {
        c.notes.push(image_crc_note(data));
        let offset = le_u32(data, PAYLOAD_OFFSET)? as usize;
        let length = le_u32(data, PAYLOAD_LENGTH)? as usize;
        let start = kernel_start
            .checked_add(offset)
            .ok_or_else(|| error("Invalid x86 payload offset"))?;
        let stored = slice(data, start, length)?;
        let codec = kernel_codec(stored);
        if codec.is_none() {
            c.notes
                .push("Kernel payload compression is not recognized; payload not decoded".into());
        }
        let mut child = component("Kernel".into(), start, stored, codec, &mut c.notes);
        child.opaque |= codec.is_none();
        c.children.push(child);
    }
    Ok(c)
}

/// The first offset in `image[..end]` where a kernel codec decodes,
/// searched from the end of the zImage header. The zImage header does not
/// record where the compressed kernel starts.
fn find_payload(image: &[u8], end: usize) -> Option<(usize, Codec, compressed::Decoded)> {
    let mut tried = 0;
    for offset in ZIMAGE_HEADER_END..end {
        let candidate = &image[offset..end];
        let Some(codec) = kernel_codec(candidate) else {
            continue;
        };
        if let Ok(decoded) = compressed::decode(codec, candidate) {
            return Some((offset, codec, decoded));
        }
        tried += 1;
        if tried >= MAX_PAYLOAD_CANDIDATES {
            break;
        }
    }
    None
}

/// The file offset of the decompressed-size word from the `KLSZ` tag of
/// the extension table, when the header announces one. Tags are
/// `{size in words, tag, data...}` and end with a zero size.
fn size_word_offset(image: &[u8], word: &dyn Fn(usize) -> Result<u32>) -> Option<usize> {
    if word(ZIMAGE_TABLE_MARKER_OFFSET).ok()? != ZIMAGE_TABLE_MARKER {
        return None;
    }
    let mut offset = word(ZIMAGE_TABLE_OFFSET).ok()? as usize;
    for _ in 0..ZIMAGE_MAX_TAGS {
        let size = word(offset).ok()? as usize;
        if size == 0 {
            return None;
        }
        if word(offset + 4).ok()? == ZIMAGE_TAG_KRNL_SIZE {
            let size_word = word(offset + 8).ok()? as usize;
            return (size_word.checked_add(4)? <= image.len()).then_some(size_word);
        }
        offset = offset.checked_add(size.checked_mul(4)?)?;
    }
    None
}

/// 32-bit Arm zImage: a self-decompressing kernel. The header's magic
/// identifies Arm Linux; the magic's storage order and the endianness flag
/// give the byte order (see [`ArmByteOrder`]).
pub(super) fn arm(data: &[u8], byte_order: ArmByteOrder) -> Result<Container<'_>> {
    slice(data, 0, ZIMAGE_HEADER_END)?;
    let word = |at: usize| match byte_order {
        ArmByteOrder::Be32 => be_u32(data, at),
        ArmByteOrder::Little | ArmByteOrder::Be8 => le_u32(data, at),
    };
    let start = word(ZIMAGE_START)?;
    let end = word(ZIMAGE_END)?;
    let size = end
        .checked_sub(start)
        .ok_or_else(|| error("Invalid Arm zImage start/end addresses"))? as usize;
    if size < ZIMAGE_HEADER_END {
        return Err(error(format!("Invalid Arm zImage size {size} B")));
    }
    let image = data.get(..size).ok_or_else(|| {
        error(format!(
            "Truncated Arm zImage: header declares {size} B, {} B present",
            data.len()
        ))
    })?;
    let (data_order, instruction_order, description) = match byte_order {
        ArmByteOrder::Little => (Endianness::Little, Endianness::Little, "little-endian"),
        ArmByteOrder::Be8 => (
            Endianness::Big,
            Endianness::Little,
            "BE8 (big-endian data, little-endian instructions)",
        ),
        ArmByteOrder::Be32 => (Endianness::Big, Endianness::Big, "BE32 (big-endian)"),
    };
    let mut c = Container::new(FileFormat::ZImage, "Arm zImage", "zimage");
    c.consumed = size;
    c.target = Some(Target::new(Isa::Arm, 32, data_order));
    c.notes.push("Linux Arm zImage".into());
    c.notes.push(format!(
        "Kernel byte order: {description}; zImage size {size} B; load address 0x{start:08X}"
    ));
    c.push_section(u64::from(start), 0, Cow::Borrowed(image));
    c.code_sections = true;
    let size_word = size_word_offset(image, &word);
    let search_end = size_word.map_or(image.len(), |offset| offset + 4);
    let Some((offset, codec, decoded)) = find_payload(image, search_end) else {
        c.notes
            .push("No compressed kernel payload was found in the zImage".into());
        return Ok(c);
    };
    c.notes.push(format!(
        "Compressed kernel found at 0x{offset:X} by its {} header; the zImage header does not record its offset",
        codec.name()
    ));
    if let Some(at) = size_word {
        let declared = le_u32(image, at)? as usize;
        c.notes.push(if declared == decoded.data.len() {
            format!("Decompressed size {declared} B matches the zImage size word")
        } else {
            format!(
                "Decompressed size {} B differs from the zImage size word ({declared} B)",
                decoded.data.len()
            )
        });
    }
    let stored = decoded.consumed.unwrap_or(search_end - offset);
    c.children.push(
        Child::decoded(
            "Kernel",
            offset,
            stored,
            Cow::Owned(decoded.data),
            codec.name(),
        )
        .with_target(Target::new(Isa::Arm, 32, instruction_order)),
    );
    Ok(c)
}

/// The fields 64-bit Arm and RISC-V `Image` headers share, as notes.
fn image_notes(c: &mut Container<'_>, data: &[u8]) -> Result<bool> {
    let text_offset = le_u64(data, IMAGE_TEXT_OFFSET)?;
    let image_size = le_u64(data, IMAGE_SIZE)?;
    let flags = le_u64(data, IMAGE_FLAGS)?;
    c.notes.push(format!(
        "Text offset: 0x{text_offset:X}; image size: {image_size} B"
    ));
    let big_endian = flags & IMAGE_FLAG_BIG_ENDIAN != 0;
    if big_endian {
        c.notes.push(
            "Kernel data is big-endian; instructions are little-endian in either data byte order"
                .into(),
        );
    }
    Ok(big_endian)
}

/// 64-bit Arm `Image`: the header is the start of the kernel's own code.
pub(super) fn arm64(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, IMAGE_HEADER_SIZE)?;
    let mut c = Container::new(FileFormat::ZImage, "ARM64 Image", "zimage");
    c.consumed = data.len();
    c.target = Some(Target::new(Isa::AArch64, 64, Endianness::Little));
    c.notes.push("Linux ARM64 Image".into());
    image_notes(&mut c, data)?;
    c.push_section(0, 0, Cow::Borrowed(data));
    c.code_sections = true;
    Ok(c)
}

/// RISC-V `Image`. The header does not encode XLEN; the 64-bit reading is
/// the Linux default.
pub(super) fn riscv(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, IMAGE_HEADER_SIZE)?;
    let mut c = Container::new(FileFormat::ZImage, "RISC-V Image", "zimage");
    c.consumed = data.len();
    c.target = Some(Target::new(Isa::RiscV64, 64, Endianness::Little));
    c.notes.push("Linux RISC-V Image".into());
    image_notes(&mut c, data)?;
    c.notes
        .push("The Image header does not encode XLEN; 64-bit is assumed".into());
    c.push_section(0, 0, Cow::Borrowed(data));
    c.code_sections = true;
    Ok(c)
}
