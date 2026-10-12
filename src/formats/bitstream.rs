//! FPGA configuration bitstreams: Xilinx `.bit` files and headerless Xilinx
//! configuration data, Lattice iCE40 and ECP5/MachXO/Nexus bitstreams, and
//! Intel Cyclone V raw binary files and programmer object files.
//!
//! A bitstream configures programmable logic. None of these formats encodes
//! a CPU instruction set, so every layout is reported with an unknown ISA
//! and its configuration data is an opaque component that never reaches the
//! code model. What the bytes establish (design and part strings, sync word
//! and bus-width pattern positions, device IDCODEs, verified CRCs) goes into
//! notes and metadata.
//!
//! Sources, by layout:
//! - Xilinx `.bit` header: no vendor document specifies it. The tag-length
//!   layout follows openFPGALoader v1.1.1 `src/bitparser.cpp`
//!   (`BitParser::parseHeader`, commit `85be4fa0`) and U-Boot v2025.10
//!   `drivers/fpga/xilinx.c` (`fpga_loadbitstream`, commit `e50b1e87`).
//! - Xilinx configuration data: AMD UG470 v1.17 (2023-12-05), chapter 5:
//!   Table 5-19 (sample bitstream), "Bus Width Auto Detection", Tables 5-20
//!   to 5-23 (Type 1 and Type 2 packets, register addresses), and Table 1-1
//!   (IDCODEs). The byte-swapped word order is the one Linux v6.12
//!   `drivers/fpga/zynq-fpga.c` (`zynq_fpga_has_sync`) accepts.
//! - Lattice iCE40: Project `IceStorm` `docs/source/format.rst` and
//!   `icepack/icepack.cc` (`FpgaConfig::read_bits`), commit `b77a2d5b`.
//!   This is community documentation; Lattice TN1248 was not consulted.
//! - Lattice ECP5, MachXO2/3 and Nexus: prjtrellis
//!   `libtrellis/src/Bitstream.cpp` and `devices.json` (commit `a31ff704`),
//!   and openFPGALoader v1.1.1 `src/latticeBitParser.cpp` for the encrypted
//!   preamble keys.
//! - Intel Cyclone V `.rbf`: mistral `libmistral/cv-opt.cc` (`oram_save`)
//!   and `libmistral/cv-files.cc` (`crc16`), commit `d509238a`, community
//!   reverse engineering.
//! - Intel `.pof`: openFPGALoader v1.1.1 `src/pofParser.cpp` and
//!   `src/pofParser.hpp`, community reverse engineering.
//!
//! Intel `.sof` files and Arria 10 `.rbf` files are not recognized: no
//! public layout establishes a structure to recognize them by.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container};
use crate::types::FileFormat;

mod intel;
mod lattice;
mod xilinx;

/// Prefix of the generated and format-specific metadata keys.
const KEY_PREFIX: &str = "bitstream";

/// Label of the opaque configuration-data component.
const CONFIGURATION_DATA: &str = "Configuration data";

/// Label of the component that holds non-padding bytes after a bitstream.
const TRAILING_DATA: &str = "Data after the bitstream";

/// First note of every bitstream.
const FPGA_NOTE: &str = "FPGA configuration data, not CPU code; excluded from ISA analysis";

/// Most comment strings reported as notes and metadata. Own bound: tool
/// comment blocks hold about ten strings.
const MAX_COMMENT_STRINGS: usize = 32;

/// Most characters of one reported header or comment string. Own bound.
const MAX_STRING_CHARS: usize = 256;

/// A recognized bitstream layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Xilinx `.bit`: tag-length header, then configuration data.
    XilinxBit,
    /// Headerless Xilinx configuration data (`.bin`), 32-bit words in
    /// big-endian order as UG470 lists them.
    XilinxRaw,
    /// Headerless Xilinx configuration data with every 32-bit word
    /// byte-swapped, as the Zynq-7000 PCAP driver loads it.
    XilinxRawSwapped,
    /// Lattice iCE40 bitstream that starts with a comment block.
    Ice40,
    /// Lattice iCE40 bitstream that starts with the preamble.
    Ice40Bare,
    /// Lattice ECP5, MachXO2/3 or Nexus bitstream with a comment block.
    Ecp5,
    /// Intel Cyclone V raw binary file (`.rbf`) in the layout mistral
    /// writes.
    CycloneVRbf,
    /// Intel programmer object file (`.pof`).
    Pof,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::XilinxBit | Self::XilinxRaw | Self::XilinxRawSwapped => FileFormat::XilinxBit,
            Self::Ice40 | Self::Ice40Bare | Self::Ecp5 => FileFormat::LatticeBitstream,
            Self::CycloneVRbf | Self::Pof => FileFormat::IntelFpga,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::XilinxBit => "Xilinx BIT file",
            Self::XilinxRaw => "Xilinx raw bitstream",
            Self::XilinxRawSwapped => "Xilinx raw bitstream, byte-swapped words",
            Self::Ice40 => "Lattice iCE40 bitstream",
            Self::Ice40Bare => "Lattice iCE40 bitstream without comment block",
            Self::Ecp5 => "Lattice ECP5/MachXO/Nexus bitstream",
            Self::CycloneVRbf => "Intel Cyclone V raw binary file",
            Self::Pof => "Intel programmer object file",
        }
    }

    /// Recognized from a complete structure rather than a header or magic.
    pub fn is_weak(self) -> bool {
        matches!(
            self,
            Self::XilinxRaw | Self::XilinxRawSwapped | Self::Ice40Bare | Self::CycloneVRbf
        )
    }
}

/// Strong recognition: a Xilinx `.bit` header (the fixed 13-byte prefix and
/// the `a` key), the POF magic, or a Lattice comment block immediately
/// followed by its preamble. A file recognized here and damaged later is a
/// parse error, not raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if xilinx::is_bit_header(data) {
        return Some(Layout::XilinxBit);
    }
    if intel::is_pof(data) {
        return Some(Layout::Pof);
    }
    lattice::detect(data)
}

/// Weak recognition of headerless layouts. Each one must validate
/// completely: the Xilinx synchronization sequence and packet stream, the
/// iCE40 command stream with its CRC up to the wakeup command, or the
/// Cyclone V option frame with its CRC.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    xilinx::detect_raw(data)
        .or_else(|| lattice::detect_bare(data))
        .or_else(|| intel::detect_rbf(data))
}

/// Parse a bitstream as a container whose component is its opaque
/// configuration data.
///
/// # Errors
///
/// [`ClassifierError::BitstreamParseError`] for a truncated or inconsistent
/// header, command stream or packet stream, or a failed CRC.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::XilinxBit => xilinx::parse_bit(data),
        Layout::XilinxRaw | Layout::XilinxRawSwapped => xilinx::parse_raw(data, layout),
        Layout::Ice40 | Layout::Ice40Bare => lattice::parse_ice40(data, layout),
        Layout::Ecp5 => lattice::parse_ecp5(data),
        Layout::CycloneVRbf => intel::parse_rbf(data),
        Layout::Pof => intel::parse_pof(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::BitstreamParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated bitstream at 0x{start:X} + {len} B")))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    data.get(at)
        .copied()
        .ok_or_else(|| error(format!("Truncated bitstream at 0x{at:X} + 1 B")))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A string field: the bytes before the first NUL, as UTF-8 with invalid
/// sequences replaced, without surrounding whitespace, and cut at
/// [`MAX_STRING_CHARS`] characters.
fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .trim()
        .chars()
        .take(MAX_STRING_CHARS)
        .collect()
}

/// A device IDCODE that the configuration stream writes or verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Idcode {
    /// The 32-bit IDCODE.
    value: u32,
    /// File offset of the IDCODE word.
    offset: usize,
}

/// A container for the bitstream layout with the FPGA note first. Further
/// notes and the components are added by [`finish`].
fn new_container(layout: Layout) -> Container<'static> {
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.notes.push(FPGA_NOTE.to_string());
    c
}

/// Add the configuration data stored at `offset` as the opaque component
/// and account for the bytes after `end`, where the bitstream ends.
/// Erased-flash padding after it belongs to the container. Other bytes
/// (flash images often hold processor firmware after the bitstream) become
/// a separate component that is classified from its own bytes; only then is
/// the container itself not opaque.
fn finish<'a>(
    mut c: Container<'a>,
    data: &'a [u8],
    offset: usize,
    configuration: &'a [u8],
    end: usize,
) -> Container<'a> {
    c.children
        .push(Child::opaque(CONFIGURATION_DATA, offset, configuration));
    let rest = data.get(end..).unwrap_or_default();
    if is_padding(rest) {
        if !rest.is_empty() {
            c.notes.push(format!(
                "{} B of erased-flash padding after the bitstream at 0x{end:X}",
                rest.len()
            ));
        }
        c.consumed = data.len();
        c.opaque = true;
    } else {
        c.notes.push(format!(
            "{} B after the bitstream at 0x{end:X} are not padding; classified as a separate component",
            rest.len()
        ));
        c.children.push(Child::stored(TRAILING_DATA, end, rest));
        c.consumed = end;
    }
    c
}

/// Note and metadata for a device IDCODE, with the device `table` names
/// for it.
fn push_idcode(c: &mut Container<'_>, idcode: Idcode, device: Option<&str>, table: &str) {
    let Idcode { value, offset } = idcode;
    match device {
        Some(name) => {
            c.notes.push(format!(
                "Device IDCODE 0x{value:08X} at 0x{offset:X}: {name} ({table})"
            ));
        }
        None => c.notes.push(format!(
            "Device IDCODE 0x{value:08X} at 0x{offset:X}; not listed in {table}"
        )),
    }
    c.push_metadata(
        "bitstream_idcode",
        "Device IDCODE",
        format!("0x{value:08X}"),
    );
    c.push_metadata(
        "bitstream_idcode_offset",
        "Device IDCODE offset",
        offset as u64,
    );
    if let Some(name) = device {
        c.push_metadata("bitstream_device", "Device", name);
    }
}

/// `"1 packet"`, `"2 packets"`.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Notes and metadata for the strings of a comment block, at most
/// [`MAX_COMMENT_STRINGS`] of them.
fn push_comments(c: &mut Container<'_>, strings: &[String]) {
    c.notes.push(format!(
        "Comment block: {}",
        count(strings.len(), "string", "strings")
    ));
    for (i, value) in strings.iter().take(MAX_COMMENT_STRINGS).enumerate() {
        c.notes.push(format!("Comment: {value}"));
        c.push_metadata(
            format!("bitstream_comment_{i}"),
            format!("Comment {}", i + 1),
            value.as_str(),
        );
    }
    if strings.len() > MAX_COMMENT_STRINGS {
        c.notes.push(format!(
            "{} not listed",
            count(
                strings.len() - MAX_COMMENT_STRINGS,
                "further comment string",
                "further comment strings"
            )
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_map_to_their_family_formats() {
        assert_eq!(Layout::XilinxRawSwapped.format(), FileFormat::XilinxBit);
        assert_eq!(Layout::Ice40Bare.format(), FileFormat::LatticeBitstream);
        assert_eq!(Layout::Pof.format(), FileFormat::IntelFpga);
        assert!(Layout::XilinxRaw.is_weak());
        assert!(Layout::CycloneVRbf.is_weak());
        assert!(!Layout::XilinxBit.is_weak());
        assert!(!Layout::Ecp5.is_weak());
    }

    #[test]
    fn text_fields_stop_at_the_first_nul_and_are_bounded() {
        assert_eq!(text(b"7a35tcpg236\0"), "7a35tcpg236");
        assert_eq!(text(b" a \0b"), "a");
        assert_eq!(text(b""), "");
        assert_eq!(text(&[b'x'; 1000]).len(), MAX_STRING_CHARS);
    }

    #[test]
    fn counts_use_the_singular_for_one() {
        assert_eq!(count(1, "packet", "packets"), "1 packet");
        assert_eq!(count(0, "packet", "packets"), "0 packets");
    }

    #[test]
    fn reads_report_the_truncated_range() {
        let message = be_u32(&[0, 1, 2], 1).unwrap_err().to_string();
        assert_eq!(
            message,
            "FPGA bitstream parse error: Truncated bitstream at 0x1 + 4 B"
        );
        assert!(slice(&[], usize::MAX, 2).is_err());
        assert!(byte(&[], 0).is_err());
    }

    #[test]
    fn non_padding_after_the_bitstream_is_a_separate_component() {
        let data = [1, 2, 3, 4, 0xff, 0x90, 0x90];
        let c = finish(new_container(Layout::Ice40), &data, 0, &data[..4], 4);
        assert!(!c.opaque);
        assert_eq!(c.consumed, 4);
        assert_eq!(c.children.len(), 2);
        assert!(c.children[0].opaque);
        assert_eq!(c.children[1].offset, 4);
        assert!(!c.children[1].opaque);

        let padded = [1, 2, 3, 4, 0xff, 0x00];
        let c = finish(new_container(Layout::Ice40), &padded, 0, &padded[..4], 4);
        assert!(c.opaque);
        assert_eq!(c.consumed, padded.len());
        assert_eq!(c.children.len(), 1);
    }
}
