//! bFLT (Binary Flat Format) parser.
//!
//! bFLT is the uClinux executable for no-MMU systems (Linux v6.6
//! `include/uapi/linux/flat.h` and `fs/binfmt_flat.c`). The 64-byte header
//! is big-endian: magic `bFLT`, revision, entry, data start, data end, BSS
//! end, stack size, relocation start, relocation count, flags, build date.
//! Offsets are from the start of the file; text runs from the end of the
//! header to `data_start`. With `FLAT_FLAG_GZIP` everything after the
//! header is one gzip stream; with `FLAT_FLAG_GZDATA` only the data and
//! relocations are.
//!
//! The header names no architecture. Only the Blackfin-specific
//! `FLAT_FLAG_L1STK` identifies one; otherwise the ISA comes from the
//! text section.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Container, Target};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};
use std::borrow::Cow;

/// bFLT magic: "bFLT"
pub const BFLT_MAGIC: [u8; 4] = *b"bFLT";

/// bFLT header size.
pub const BFLT_HEADER_SIZE: usize = 64;

/// bFLT flags.
pub mod flags {
    /// Load entire program into RAM
    pub const RAM: u32 = 0x0001;
    /// PIC with GOT
    pub const GOTPIC: u32 = 0x0002;
    /// gzip compressed
    pub const GZIP: u32 = 0x0004;
    /// Only data compressed (for XIP)
    pub const GZDATA: u32 = 0x0008;
    /// Kernel tracing enabled
    pub const KTRACE: u32 = 0x0010;
    /// L1 scratch memory stack (Blackfin)
    pub const L1STK: u32 = 0x0020;
}

/// Flag names in bit order, for notes.
const FLAG_NAMES: &[(u32, &str)] = &[
    (flags::RAM, "RAM"),
    (flags::GOTPIC, "GOTPIC"),
    (flags::GZIP, "GZIP"),
    (flags::GZDATA, "GZDATA"),
    (flags::KTRACE, "KTRACE"),
    (flags::L1STK, "L1STK"),
];

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::BfltParseError {
        message: message.into(),
    }
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(at..at + 4)
        .ok_or_else(|| error(format!("Truncated bFLT header at 0x{at:X}")))?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

/// Detect bFLT format.
pub fn detect(data: &[u8]) -> bool {
    data.starts_with(&BFLT_MAGIC)
}

/// Parse a bFLT file into its text section.
///
/// # Errors
///
/// [`ClassifierError::BfltParseError`] for a truncated header, offsets
/// outside the file, or a compressed image that does not decode.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    if data.len() < BFLT_HEADER_SIZE {
        return Err(error(format!(
            "Truncated bFLT header: {} B of {BFLT_HEADER_SIZE} B",
            data.len()
        )));
    }
    let revision = be_u32(data, 4)?;
    let entry = be_u32(data, 8)?;
    let data_start = be_u32(data, 12)? as usize;
    let data_end = be_u32(data, 16)? as usize;
    let bss_end = be_u32(data, 20)? as usize;
    let stack_size = be_u32(data, 24)?;
    let reloc_count = be_u32(data, 32)?;
    let bflt_flags = be_u32(data, 36)?;
    if data_start < BFLT_HEADER_SIZE || data_end < data_start || bss_end < data_end {
        return Err(error(format!(
            "Invalid bFLT segment offsets: data 0x{data_start:X}-0x{data_end:X}, BSS end 0x{bss_end:X}"
        )));
    }
    let text_size = data_start - BFLT_HEADER_SIZE;

    let mut c = Container::new(FileFormat::Bflt, format!("v{revision}"), "bflt");
    c.entry = Some(u64::from(entry));
    c.consumed = data.len();
    c.notes.push("bFLT (Binary Flat Format)".into());
    c.notes.push(format!("Version: {revision}"));
    c.notes.push(format!("Entry point: 0x{entry:08X}"));
    c.notes.push(format!(
        "Text: {text_size} B; data: {} B; BSS: {} B; stack: {stack_size} B; relocations: {reloc_count}",
        data_end - data_start,
        bss_end - data_end
    ));
    let names: Vec<&str> = FLAG_NAMES
        .iter()
        .filter(|(bit, _)| bflt_flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if !names.is_empty() {
        c.notes.push(format!("Flags: {}", names.join(", ")));
    }
    c.push_metadata("bflt_flags", "Flags", format!("0x{bflt_flags:08X}"));
    if bflt_flags & flags::L1STK != 0 {
        // L1 scratch-pad stacks exist only on Blackfin (`fs/binfmt_flat.c`).
        c.target = Some(Target::new(Isa::Blackfin, 32, Endianness::Little));
    }

    let text = if bflt_flags & flags::GZIP != 0 {
        let stored = &data[BFLT_HEADER_SIZE..];
        let decoded = compressed::decode(Codec::Gzip, stored)
            .map_err(|e| error(format!("Invalid gzip-compressed bFLT image: {e}")))?;
        let text = decoded
            .data
            .get(..text_size)
            .ok_or_else(|| error("Decompressed bFLT image is shorter than its text"))?
            .to_vec();
        c.notes.push(format!(
            "Text decompressed from gzip ({} B stored)",
            stored.len()
        ));
        Cow::Owned(text)
    } else {
        let text = data.get(BFLT_HEADER_SIZE..data_start).ok_or_else(|| {
            error(format!(
                "Truncated bFLT text: ends at 0x{data_start:X}, file is {} B",
                data.len()
            ))
        })?;
        Cow::Borrowed(text)
    };
    let stored_size = if bflt_flags & flags::GZIP != 0 {
        data.len() - BFLT_HEADER_SIZE
    } else {
        text.len()
    };
    c.push_section(BFLT_HEADER_SIZE as u64, BFLT_HEADER_SIZE, text);
    if let Some(section) = c.sections.last_mut() {
        section.label = "Text".into();
        section.stored_size = stored_size;
        if bflt_flags & flags::GZIP != 0 {
            section.transform = Some(Codec::Gzip.name());
        }
    }
    c.code_sections = true;
    Ok(c)
}

/// Parse bFLT file.
///
/// # Errors
///
/// As [`parse_container`].
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    Ok(parse_container(data)?.classification())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header: version 4, entry 0x40, data at 0x50-0x60, BSS end 0x70,
    /// stack 0x1000, 10 relocations, GOTPIC; then 16 B text and 16 B data.
    fn make_bflt(flags: u32, text: &[u8; 16]) -> Vec<u8> {
        let mut data = vec![0u8; BFLT_HEADER_SIZE];
        data[0..4].copy_from_slice(&BFLT_MAGIC);
        data[4..8].copy_from_slice(&4u32.to_be_bytes());
        data[8..12].copy_from_slice(&0x40u32.to_be_bytes());
        data[12..16].copy_from_slice(&0x50u32.to_be_bytes());
        data[16..20].copy_from_slice(&0x60u32.to_be_bytes());
        data[20..24].copy_from_slice(&0x70u32.to_be_bytes());
        data[24..28].copy_from_slice(&0x1000u32.to_be_bytes());
        data[32..36].copy_from_slice(&10u32.to_be_bytes());
        data[36..40].copy_from_slice(&flags.to_be_bytes());
        data.extend_from_slice(text);
        data.extend_from_slice(&[0xaa; 16]);
        data
    }

    #[test]
    fn test_detect_bflt() {
        assert!(detect(&make_bflt(flags::GOTPIC, &[0; 16])));
        assert!(!detect(&[0x7F, b'E', b'L', b'F']));
    }

    #[test]
    fn bflt_names_no_isa_and_exposes_its_text() {
        let data = make_bflt(flags::GOTPIC, &[7; 16]);
        let c = parse_container(&data).unwrap();
        assert_eq!(c.entry, Some(0x40));
        assert_eq!(c.sections[0].data.as_ref(), &[7; 16]);
        assert!(matches!(c.classification().isa, Isa::Unknown(_)));
        assert_eq!(parse(&data).unwrap().format, FileFormat::Bflt);
    }

    #[test]
    fn bflt_l1_stack_flag_identifies_blackfin() {
        let data = make_bflt(flags::L1STK, &[0; 16]);
        assert_eq!(parse(&data).unwrap().isa, Isa::Blackfin);
    }

    #[test]
    fn gzip_bflt_text_is_decompressed() {
        let plain = make_bflt(flags::GZIP, &[9; 16]);
        let body = &plain[BFLT_HEADER_SIZE..];
        let mut stream = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        stream.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(body, 6));
        stream.extend_from_slice(&crate::formats::checksum::crc32(body).to_le_bytes());
        stream.extend_from_slice(&(body.len() as u32).to_le_bytes());
        let mut data = plain[..BFLT_HEADER_SIZE].to_vec();
        data.extend_from_slice(&stream);
        let c = parse_container(&data).unwrap();
        assert_eq!(c.sections[0].data.as_ref(), &[9; 16]);
        assert_eq!(c.sections[0].transform, Some("gzip"));
        let mut corrupt = data.clone();
        let last = corrupt.len() - 5;
        corrupt[last] ^= 1;
        assert!(parse_container(&corrupt).is_err());
    }

    #[test]
    fn bflt_truncation_and_bad_offsets_are_errors() {
        let data = make_bflt(0, &[0; 16]);
        for end in 0..0x50 {
            assert!(parse_container(&data[..end]).is_err(), "prefix {end}");
        }
        let mut bad = data.clone();
        bad[12..16].copy_from_slice(&0x10u32.to_be_bytes());
        assert!(parse_container(&bad).is_err());
    }
}
