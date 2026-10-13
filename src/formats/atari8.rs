//! Atari 8-bit disk images and executables: ATR disk images, with the OS
//! boot record and the Atari DOS 2.0S, 2.0D and 2.5 file system, and Atari
//! DOS binary load files (`.xex`, `.com`).
//!
//! Primary sources, by layout (pins and hashes in `docs/atari8.md`):
//! - ATR header and sector layout: atari800 5.2.0 `src/afile.h` and
//!   `src/sio.c` (`SIO_Mount`, `SIO_SizeOfSector`); Altirra 4.31
//!   `src/ATIO/source/diskimage.cpp` (`LoadATR`, `SaveATR`); `AtariSIO`
//!   `tools/AtrImage.cpp` at `bbccb152`; Jindroush, "ATR File Format
//!   Description". See [`atr`].
//! - OS boot record: Altirra Hardware Reference Manual (2026-01-02 edition)
//!   §10.1 "Boot sectors"; `AltirraOS` `src/Kernel/source/Shared/boot.s`;
//!   Chadwick, "Mapping the Atari" (1985) entries 12-13 and 576-579;
//!   Wilkinson, "Inside Atari DOS" (1982) chapters 20 and 21.
//! - DOS 2.x file system: "Inside Atari DOS" chapter 2; Altirra 4.31
//!   `src/ATIO/source/diskfsdos2.cpp`; `AtariSIO` `tools/Dos2xUtils.cpp`. See
//!   [`dos2`].
//! - Binary load files: "Mapping the Atari" entries 736-739; atari800
//!   `src/binload.c`; Altirra `src/Altirra/source/hleprogramloader.cpp`;
//!   `AtariSIO` `tools/ComBlock.cpp`; bw-atari8-tools `xex.5` (0.2.1). See
//!   [`xex`].
//!
//! The Atari 8-bit computers use a MOS 6502, or the 6502C ("Sally"), which
//! "uses the same NMOS 6502 core" (Altirra Hardware Reference Manual §2.1
//! and §3.6), and "the 6502 is a little endian processor" (§1.4). Both
//! formats exist only for this family, so the code they load is 6502 code:
//! a binary load file names the target for its segments and an ATR boot
//! record for itself. Other DOS files are listed as opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod atr;
mod dos2;
mod xex;

/// An Atari 8-bit layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// ATR disk image (`NICKATARI` header).
    Atr,
    /// Atari DOS binary load file.
    BinaryLoad,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Atr => FileFormat::Atr,
            Self::BinaryLoad => FileFormat::AtariXex,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Atr => "ATR disk image",
            Self::BinaryLoad => "Atari DOS binary load file",
        }
    }

    /// Recognized from complete structure rather than a magic value: a
    /// binary load file has only its two-byte marker.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::BinaryLoad)
    }
}

/// Strong recognition of ATR images: the magic, a documented sector size
/// and a declared size of 1 to 65535 whole sectors.
pub fn detect(data: &[u8]) -> Option<Layout> {
    atr::detect(data).then_some(Layout::Atr)
}

/// Recognition of binary load files from their complete structure: the
/// `FF FF` marker, then valid segments that tile the file exactly.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    xex::detect_program(data).then_some(Layout::BinaryLoad)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::Atari8ParseError`] for a truncated or inconsistent ATR
/// header, an image size that is not a whole number of sectors, trailing
/// data that is not padding, or a binary load segment that is truncated or
/// ends below its start.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Atr => atr::parse(data),
        Layout::BinaryLoad => xex::parse(data),
    }
}

/// 6502 code: 8-bit, little-endian operands.
const MOS_6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The instruction set of both the 6502 and the 6502C.
const CPU_VARIANT: &str = "6502";

/// Sector sizes that hold a DOS 2.x file system and short boot sectors.
const SINGLE_DENSITY: usize = 128;
const DOUBLE_DENSITY: usize = 256;

/// The 6502 address space.
const ADDRESS_SPACE: u32 = 0x1_0000;

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::Atari8ParseError {
        message: message.into(),
    }
}

/// The little-endian word at `at`, if present.
fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let word = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([word[0], word[1]]))
}

/// Erased media or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// `1 sector`, `2 sectors`.
fn count_text(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// A size in `B`, `KiB` or `MiB`, whichever divides it.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_binary_load_files_are_weak() {
        assert!(Layout::BinaryLoad.is_weak());
        assert!(!Layout::Atr.is_weak());
        assert_eq!(Layout::Atr.format(), FileFormat::Atr);
        assert_eq!(Layout::BinaryLoad.format(), FileFormat::AtariXex);
    }

    #[test]
    fn words_are_little_endian_and_bounded() {
        assert_eq!(le_u16(&[0x96, 0x02], 0), Some(0x0296));
        assert_eq!(le_u16(&[0x96], 0), None);
        assert_eq!(le_u16(&[0x96, 0x02], usize::MAX), None);
    }

    #[test]
    fn counts_agree_in_number() {
        assert_eq!(count_text(1, "segment"), "1 segment");
        assert_eq!(count_text(0, "file"), "0 files");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size_text(90 << 10), "90 KiB");
        assert_eq!(size_text(92_176), "92176 B");
        assert_eq!(size_text(1 << 20), "1 MiB");
    }
}
