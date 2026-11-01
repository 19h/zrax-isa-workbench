//! Microsoft cabinet files (`MSCF`): the header, folder and file tables, and
//! the data blocks of each folder, stored, MSZIP-compressed or
//! LZX-compressed. Files are the container's children, labeled by their
//! names and classified by their own parsers.
//!
//! Primary sources (pins and hashes in `docs/cab.md`):
//! - The Cabinet SDK documentation, "Microsoft Cabinet Format" (Microsoft
//!   Learn `bb267310(v=vs.85)`, 1997): CFHEADER, CFFOLDER, CFFILE, CFDATA,
//!   "Checksum Method", "UTF Encoding Method", "`MSZip` Format" and "LZX
//!   Format". The Open Specifications edition [MS-CAB] is no longer served.
//! - [MS-MCI] v20161017 section 2: MSZIP blocks keep the history of the
//!   blocks before them.
//! - libmspack commit `55d501976171397ccd5d5a7a1ca7da065b1d9a06`:
//!   `mspack/cabd.c` and `cab.h` (block size bounds, the checksum's header
//!   bytes, LZX folders as one stream of 32 KiB frames) and `lzxd.c` (see
//!   [`crate::formats::compressed`]).
//! - Wine commit `081042ede6a165a36bf9988350dd584b440d7a3d`
//!   `include/fdi.h`: the `typeCompress` type, window and level fields.
//! - osslsigncode commit `bf7533deb1311ccd80d241f668ed1a8ca586ea3c`
//!   `cab.c`: the reserve area of Authenticode-signed cabinets.
//!
//! A cabinet names no CPU, so the container target is always unknown and
//! the ISA comes from the files (PE drivers and executables, nested
//! cabinets). Every CFDATA checksum that is present is verified; the
//! Authenticode signature of a signed cabinet is reported, not verified.
//! Quantum folders are not decoded. Files that continue into another
//! cabinet of a set are named in notes and not joined.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{self, Child, Container};
use crate::formats::NamedRange;
use crate::types::FileFormat;

mod files;
mod folder;
mod header;

use header::Header;

/// The cabinet signature `MSCF` at offset 0.
const SIGNATURE: &[u8; 4] = b"MSCF";

/// Size of the fixed CFHEADER fields (SDK sample "00..23 CFHEADER";
/// libmspack `cfhead_SIZEOF`).
const CFHEADER_SIZE: usize = 0x24;

/// Fixed size of a CFFOLDER entry, before its reserve area.
const CFFOLDER_SIZE: usize = 8;

/// CFHEADER field offsets (SDK "CFHEADER").
const RESERVED1_FIELD: usize = 0x04;
const CABINET_SIZE_FIELD: usize = 0x08;
const RESERVED2_FIELD: usize = 0x0C;
const FILES_OFFSET_FIELD: usize = 0x10;
const RESERVED3_FIELD: usize = 0x14;
const FOLDER_COUNT_FIELD: usize = 0x1A;

/// Label of the child for recognized data after the cabinet.
const TRAILING_LABEL: &str = "Data after the cabinet";

/// A cabinet layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A cabinet file: `MSCF`, its header, folder and file tables, and the
    /// CFDATA blocks of its folders.
    Cabinet,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Cabinet => FileFormat::MsCab,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Cabinet => "MSCF cabinet",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// four-byte signature comes with three zero reserved fields and a file
    /// table offset that must lie between the folder table and the end of
    /// the cabinet, so the layout is strong.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Cabinet => false,
        }
    }
}

/// Strong recognition: `MSCF` at offset 0, `reserved1`, `reserved2` and
/// `reserved3` zero, and `coffFiles` at or after the end of the minimal
/// header and folder table and before `cbCabinet`. Every field lies in the
/// first 36 bytes, so a damaged cabinet is still recognized and becomes a
/// parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let header = data.get(..CFHEADER_SIZE)?;
    if &header[..4] != SIGNATURE {
        return None;
    }
    let reserved = [RESERVED1_FIELD, RESERVED2_FIELD, RESERVED3_FIELD];
    if reserved
        .iter()
        .any(|&at| le_u32(header, at).ok() != Some(0))
    {
        return None;
    }
    let cabinet_size = u64::from(le_u32(header, CABINET_SIZE_FIELD).ok()?);
    let files_offset = u64::from(le_u32(header, FILES_OFFSET_FIELD).ok()?);
    let folders = u64::from(le_u16(header, FOLDER_COUNT_FIELD).ok()?);
    let tables_start = CFHEADER_SIZE as u64 + folders * CFFOLDER_SIZE as u64;
    (files_offset >= tables_start && files_offset < cabinet_size).then_some(Layout::Cabinet)
}

/// Parse a cabinet into the shared container model: the header, folders
/// and checksums in notes and metadata, and every file in a recognized
/// format as a child labeled by its name, in folder order.
///
/// # Errors
///
/// [`ClassifierError::CabParseError`] for a missing signature, nonzero
/// reserved fields, a file shorter than `cbCabinet`, a cabinet without
/// folders or files, tables or names that run past the cabinet, a file
/// entry whose folder index names no folder or a cabinet the header does
/// not name, a CFDATA chain that runs past the cabinet, violates the block
/// size bounds or overlaps another folder's, or data after the cabinet
/// that is neither padding, the signature its header names nor a
/// recognized format. A folder that does not decode or fails a checksum is
/// not an error: its files are left out and named in a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Cabinet => parse(data, layout),
    }
}

/// The Authenticode signature after the cabinet as a stored range, when
/// the reserve area names one. The signature is located, not verified.
pub fn signature_range(data: &[u8]) -> Option<NamedRange> {
    let header = Header::read(data).ok()?;
    let signature = header.signature(data)?;
    Some(NamedRange {
        name: "CAB Authenticode signature".to_string(),
        offset: signature.offset as u64,
        size: signature.size as u64,
    })
}

fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = Header::read(data)?;
    let cabinet = &data[..header.cabinet_size];
    let folders = header::read_folders(cabinet, &header)?;
    let entries = header::read_files(cabinet, &header)?;
    let continuation = header::Continuation::of(&header, &entries)?;
    let chains = folder::read_chains(cabinet, &header, &folders, &continuation)?;
    let mut c = Container::new(layout.format(), layout.label(), "cab");
    c.consumed = header.cabinet_size;
    header.push_notes(&folders, entries.len(), &mut c);
    let signature = header.signature(data);
    folder::push_notes(&folders, &chains, &mut c);
    files::list(&header, &folders, &chains, &entries, &continuation, &mut c);
    if let Some(signature) = &signature {
        signature.push_notes(&mut c);
        c.consumed = signature.end;
    }
    push_trailing(data, c.consumed, &mut c)?;
    Ok(c)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CabParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at file offset `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range at 0x{start:X}")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// Little-endian 16-bit field at `at`.
fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2, "cabinet field")?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

/// Little-endian 32-bit field at `at`.
fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4, "cabinet field")?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// A 32-bit value as a file offset or size.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("32-bit values fit in usize")
}

/// The cabinet checksum (SDK "Checksum Method", `CSUMCompute`): the XOR of
/// the little-endian 32-bit words of `bytes` with `seed`, and of a last word
/// built from the 1-3 remaining bytes, the first of them most significant.
fn checksum(bytes: &[u8], seed: u32) -> u32 {
    let mut words = bytes.chunks_exact(4);
    let mut sum = seed;
    for word in &mut words {
        sum ^= u32::from_le_bytes(word.try_into().expect("chunk of 4 bytes"));
    }
    let tail = words
        .remainder()
        .iter()
        .fold(0u32, |value, &byte| value << 8 | u32::from(byte));
    sum ^ tail
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// `n` followed by the singular or plural noun, for notes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Handle the bytes after the cabinet (and its signature): padding is
/// accepted, a recognized format (another cabinet) is listed as a child,
/// and anything else is an error.
fn push_trailing<'a>(data: &'a [u8], offset: usize, c: &mut Container<'a>) -> Result<()> {
    let rest = data.get(offset..).unwrap_or_default();
    if is_padding(rest) {
        if !rest.is_empty() {
            c.notes.push(format!(
                "{} after the cabinet",
                count(rest.len(), "byte of padding", "bytes of padding")
            ));
        }
        return Ok(());
    }
    if !container::is_recognized(rest) {
        return Err(error(format!(
            "Unexpected data after the cabinet at 0x{offset:X}"
        )));
    }
    c.notes.push(format!(
        "{} B after the cabinet at 0x{offset:X} are listed as a separate component",
        rest.len()
    ));
    c.children
        .push(Child::stored(TRAILING_LABEL, offset, rest).if_recognized());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDK's sample cabinet ("A Sample Cabinet File"): two stored text
    /// files in one CFDATA block with checksum 0x30A65ABD.
    fn sdk_sample() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"MSCF\0\0\0\0\xfd\0\0\0\0\0\0\0\x2c\0\0\0\0\0\0\0");
        data.extend_from_slice(&[3, 1, 1, 0, 2, 0, 0, 0, 0x22, 0x06, 0, 0]);
        data.extend_from_slice(&[0x5e, 0, 0, 0, 1, 0, 0, 0]);
        data.extend_from_slice(&[
            0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x6c, 0x22, 0xba, 0x59, 0x20, 0,
        ]);
        data.extend_from_slice(b"hello.c\0");
        data.extend_from_slice(&[
            0x4a, 0, 0, 0, 0x4d, 0, 0, 0, 0, 0, 0x6c, 0x22, 0xe7, 0x59, 0x20, 0,
        ]);
        data.extend_from_slice(b"welcome.c\0");
        data.extend_from_slice(&[0xbd, 0x5a, 0xa6, 0x30, 0x97, 0, 0x97, 0]);
        data.extend_from_slice(
            b"#include <stdio.h>\r\n\r\nvoid main(void)\r\n{\r\n    printf(\"Hello, world!\\n\");\r\n}\r\n",
        );
        data.extend_from_slice(
            b"#include <stdio.h>\r\n\r\nvoid main(void)\r\n{\r\n    printf(\"Welcome!\\n\");\r\n}\r\n\r\n",
        );
        data
    }

    #[test]
    fn the_sdk_sample_is_detected_and_its_checksum_matches() {
        let data = sdk_sample();
        assert_eq!(data.len(), 0xfd);
        assert_eq!(detect(&data), Some(Layout::Cabinet));
        let block = &data[0x5e..];
        let data_sum = checksum(&block[8..], 0);
        assert_eq!(checksum(&block[4..8], data_sum), 0x30a6_5abd);
    }

    #[test]
    fn checksum_tails_put_the_first_byte_highest() {
        assert_eq!(checksum(&[1, 2, 3, 4], 0), 0x0403_0201);
        assert_eq!(checksum(&[1, 2, 3, 4, 5], 0), 0x0403_0201 ^ 5);
        assert_eq!(checksum(&[1, 2, 3, 4, 5, 6], 0), 0x0403_0201 ^ 0x0506);
        assert_eq!(checksum(&[5, 6, 7], 0xff), 0xff ^ 0x0005_0607);
    }

    #[test]
    fn detection_needs_zero_reserved_fields_and_a_consistent_files_offset() {
        let data = sdk_sample();
        for at in [RESERVED1_FIELD, RESERVED2_FIELD, RESERVED3_FIELD] {
            let mut changed = data.clone();
            changed[at] = 1;
            assert_eq!(detect(&changed), None, "reserved field at 0x{at:X}");
        }
        let mut inside_folders = data.clone();
        inside_folders[FILES_OFFSET_FIELD] = 0x28;
        assert_eq!(detect(&inside_folders), None);
        let mut past_end = data.clone();
        past_end[FILES_OFFSET_FIELD] = 0xfd;
        assert_eq!(detect(&past_end), None);
        assert_eq!(detect(&data[..CFHEADER_SIZE - 1]), None);
        assert_eq!(detect(&data[..CFHEADER_SIZE]), Some(Layout::Cabinet));
    }

    #[test]
    fn layouts_report_their_format_and_strength() {
        assert_eq!(Layout::Cabinet.format(), FileFormat::MsCab);
        assert_eq!(Layout::Cabinet.label(), "MSCF cabinet");
        assert!(!Layout::Cabinet.is_weak());
    }
}
