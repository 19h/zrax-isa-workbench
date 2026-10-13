//! System Use Sharing Protocol entries (IEEE P1281 1.12) and the Rock Ridge
//! entries carried in them (IEEE P1282 1.12): a directory record's system
//! use field holds entries of a two-byte signature, a length and a version;
//! a `CE` entry continues the area elsewhere.

use super::directory::Record;
use super::*;

/// Entry header: signature (2), length (1), version (1) (SUSP 4.1).
const ENTRY_HEADER_SIZE: usize = 4;

/// SUSP entries (SUSP 5.1-5.5).
const SIG_CE: [u8; 2] = *b"CE";
const SIG_SP: [u8; 2] = *b"SP";
const SIG_ST: [u8; 2] = *b"ST";
const SIG_ER: [u8; 2] = *b"ER";

/// Rock Ridge entries (RRIP 4.1). `RR` is the RRIP 1.09 entry that lists
/// the recorded entries (Linux `rock.h` `RR_RR_s`); `ZF` is the Linux
/// zisofs entry (`RR_ZF_s`), not part of RRIP.
const SIG_RR: [u8; 2] = *b"RR";
const SIG_PX: [u8; 2] = *b"PX";
const SIG_NM: [u8; 2] = *b"NM";
const SIG_CL: [u8; 2] = *b"CL";
const SIG_RE: [u8; 2] = *b"RE";
const SIG_SF: [u8; 2] = *b"SF";
const SIG_ZF: [u8; 2] = *b"ZF";

/// `SP` entry (SUSP 5.3): signature, length 7, version, check bytes `BE EF`
/// at 4, `LEN_SKP` at 6.
const SP_SIZE: usize = 7;
const SP_CHECK_OFFSET: usize = 4;
const SP_CHECK: [u8; 2] = [0xBE, 0xEF];
const SP_SKIP_OFFSET: usize = 6;

/// The `SP` entry is at byte 1 of the root's system use field, or at byte
/// 15 on CD-ROM XA discs, after the 14-byte XA information (SUSP 5.3).
const SP_POSITIONS: [usize; 2] = [0, 14];

/// `ER` identifiers of the Rock Ridge Interchange Protocol: `IEEE_P1282`
/// (RRIP 1.12, 4.3) and `RRIP_1991A` (RRIP 1.09 and 1.10, as libarchive and
/// mkisofs write it).
const RRIP_IDENTIFIERS: [&[u8]; 2] = [b"IEEE_P1282", b"RRIP_1991A"];

/// `ER` data before the identifier: identifier, descriptor and source
/// lengths and the extension version (SUSP 5.5).
const ER_LENGTHS_SIZE: usize = 4;

/// `NM` flags (RRIP 4.1.4, Table 4).
const NM_CONTINUE: u8 = 0x01;
const NM_CURRENT: u8 = 0x02;
const NM_PARENT: u8 = 0x04;

/// Longest alternate name kept (POSIX `NAME_MAX`; Linux truncates at 254).
const MAX_NAME: usize = 255;

/// POSIX file type bits of the `PX` mode and the regular-file type (RRIP
/// 4.1.1, Table 1).
const S_IFMT: u32 = 0o170_000;
pub(super) const S_IFREG: u32 = 0o100_000;

/// Most continuation areas followed for one record (Linux
/// `RR_MAX_CE_ENTRIES`).
const MAX_CONTINUATIONS: usize = 32;

/// Rock Ridge on a directory hierarchy.
#[derive(Debug, Clone)]
pub(super) struct RockRidge {
    /// Bytes skipped at the start of each system use field (`LEN_SKP`).
    skip: usize,
    /// What identified it: the `ER` identifier or the `RR` entry.
    pub(super) evidence: String,
}

/// One system use entry.
struct Entry<'a> {
    signature: [u8; 2],
    /// The bytes after the four-byte header.
    data: &'a [u8],
}

/// Visit the entries of the system use area `area` (at file offset
/// `offset`) and of the continuation areas its `CE` entries name. A
/// continuation is read after the current area (SUSP 5.1). Entries shorter
/// than their header end an area, as Linux treats them. A continuation
/// area past the end of a truncated volume's input is absent.
fn for_each_entry<'a>(
    image: Image<'a>,
    block_size: usize,
    area: &'a [u8],
    offset: usize,
    mut visit: impl FnMut(&Entry<'a>),
) -> std::result::Result<(), Fault> {
    let mut current = (area, offset);
    let mut hops = 0;
    loop {
        let (bytes, base) = current;
        let mut next = None;
        let mut pos = 0;
        while bytes.len() - pos >= ENTRY_HEADER_SIZE {
            let len = usize::from(bytes[pos + 2]);
            if len < ENTRY_HEADER_SIZE {
                break;
            }
            let Some(entry) = bytes.get(pos..pos + len) else {
                let defect = format!(
                    "system use entry at 0x{:X} ({len} B) overruns its area",
                    base + pos
                );
                return Err(Fault::Defect(defect));
            };
            let signature = [entry[0], entry[1]];
            let data = &entry[ENTRY_HEADER_SIZE..];
            match signature {
                SIG_ST => break,
                SIG_CE => next = Some(continuation(data, base + pos)?),
                _ => visit(&Entry { signature, data }),
            }
            pos += len;
        }
        let Some(Continuation {
            block,
            offset: start,
            length: len,
        }) = next
        else {
            return Ok(());
        };
        hops += 1;
        if hops > MAX_CONTINUATIONS {
            let defect =
                format!("more than {MAX_CONTINUATIONS} continuation areas from 0x{offset:X}");
            return Err(Fault::Defect(defect));
        }
        let at = block_offset(block, block_size)
            .and_then(|block_start| block_start.checked_add(start as usize))
            .ok_or_else(|| format!("continuation area at block {block} is outside the volume"))?;
        let len = len as usize;
        if !image.holds(at, len) {
            let defect = format!("continuation area at 0x{at:X} ({len} B) lies outside the volume");
            return Err(Fault::Defect(defect));
        }
        let bytes = image.present(at, len).ok_or(Fault::Absent)?;
        current = (bytes, at);
    }
}

/// Where a `CE` entry continues the system use entries.
struct Continuation {
    /// Logical block of the continuation area.
    block: u32,
    /// Byte offset of the area in that block.
    offset: u32,
    /// Length of the area in bytes.
    length: u32,
}

/// A `CE` entry's continuation area: block, offset and length, each in
/// both byte orders (SUSP 5.1, `CE` length 28).
fn continuation(data: &[u8], at: usize) -> std::result::Result<Continuation, String> {
    let field = |offset: usize| {
        both_u32_halves(data, offset)
            .ok()
            .and_then(BothOrders::agreed)
            .ok_or_else(|| format!("invalid CE entry at 0x{at:X}"))
    };
    Ok(Continuation {
        block: field(0)?,
        offset: field(8)?,
        length: field(16)?,
    })
}

/// Whether the root directory's first record (`.`) shows Rock Ridge: an
/// `SP` entry with its check bytes at the start of the system use field
/// (or after CD-ROM XA information), and an `ER` entry naming the RRIP or an
/// RRIP 1.09 `RR` entry in its system use area (SUSP 5.3, 5.5; Linux enables
/// Rock Ridge on the `ER` entry).
///
/// # Errors
///
/// Only [`Fault::Absent`]: a continuation area past the end of a truncated
/// volume's input, so that the answer is unknown. Damaged entries mean no
/// Rock Ridge.
pub(super) fn rock_ridge(
    image: Image<'_>,
    block_size: usize,
    root: &Record<'_>,
) -> std::result::Result<Option<RockRidge>, Fault> {
    let area = root.system_use;
    let Some(start) = SP_POSITIONS
        .into_iter()
        .find(|&at| area.get(at..at + SP_SIZE).is_some_and(is_sp))
    else {
        return Ok(None);
    };
    let skip = usize::from(area[start + SP_SKIP_OFFSET]);
    let mut evidence = None;
    let visited = for_each_entry(
        image,
        block_size,
        &area[start..],
        root.system_use_offset + start,
        |entry| match entry.signature {
            SIG_ER => {
                if let Some(identifier) = extension_identifier(entry.data) {
                    if RRIP_IDENTIFIERS.contains(&identifier) {
                        evidence = Some(String::from_utf8_lossy(identifier).into_owned());
                    }
                }
            }
            SIG_RR if evidence.is_none() => evidence = Some("RR entry".to_string()),
            _ => {}
        },
    );
    match visited {
        Ok(()) => Ok(evidence.map(|evidence| RockRidge { skip, evidence })),
        Err(Fault::Defect(_)) => Ok(None),
        Err(Fault::Absent) => Err(Fault::Absent),
    }
}

/// An `SP` entry: the signature, a length of at least [`SP_SIZE`] and the
/// check bytes.
fn is_sp(entry: &[u8]) -> bool {
    entry[..2] == SIG_SP
        && usize::from(entry[2]) >= SP_SIZE
        && entry[SP_CHECK_OFFSET..SP_CHECK_OFFSET + 2] == SP_CHECK
}

/// The extension identifier of an `ER` entry's data, when its lengths fit.
fn extension_identifier(data: &[u8]) -> Option<&[u8]> {
    let identifier_len = usize::from(*data.first()?);
    data.get(ER_LENGTHS_SIZE..ER_LENGTHS_SIZE + identifier_len)
}

/// A record's alternate name (`NM`).
#[derive(Debug)]
pub(super) enum AlternateName {
    /// The name, concatenated over its entries.
    Recorded(Vec<u8>),
    /// The content is longer than [`MAX_NAME`].
    TooLong,
}

/// How a file's data is recorded.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
    /// Stored as-is.
    #[default]
    Plain,
    /// Rock Ridge sparse file encoding (`SF`).
    Sparse,
    /// Linux zisofs compression (`ZF`).
    Zisofs,
}

/// What a record's Rock Ridge entries say about it.
#[derive(Debug, Default)]
pub(super) struct Attributes {
    pub(super) name: Option<AlternateName>,
    /// POSIX file type from `PX` (`S_IFMT` bits).
    pub(super) file_type: Option<u32>,
    /// `CL`: the record stands for a directory moved to this block.
    pub(super) child_link: Option<u32>,
    /// `RE`: the record is a moved directory, reached through its `CL`.
    pub(super) relocated: bool,
    pub(super) encoding: Encoding,
}

/// The Rock Ridge attributes of `record`, whose entries start `LEN_SKP`
/// bytes into its system use field (SUSP 4).
pub(super) fn attributes(
    image: Image<'_>,
    block_size: usize,
    rock: &RockRidge,
    record: &Record<'_>,
) -> std::result::Result<Attributes, Fault> {
    let mut attributes = Attributes::default();
    let Some(area) = record.system_use.get(rock.skip..) else {
        return Ok(attributes);
    };
    let mut name = Vec::new();
    let mut has_name = false;
    let mut too_long = false;
    let mut name_done = false;
    for_each_entry(
        image,
        block_size,
        area,
        record.system_use_offset + rock.skip,
        |entry| match entry.signature {
            SIG_NM => {
                let Some((&flags, content)) = entry.data.split_first() else {
                    return;
                };
                if name_done || flags & (NM_CURRENT | NM_PARENT) != 0 {
                    return;
                }
                if name.len() + content.len() > MAX_NAME {
                    too_long = true;
                } else {
                    name.extend_from_slice(content);
                }
                name_done = flags & NM_CONTINUE == 0;
                has_name = true;
            }
            SIG_PX => {
                if let Ok(mode) = le_u32(entry.data, 0) {
                    attributes.file_type = Some(mode & S_IFMT);
                }
            }
            SIG_CL => attributes.child_link = le_u32(entry.data, 0).ok(),
            SIG_RE => attributes.relocated = true,
            SIG_SF => attributes.encoding = Encoding::Sparse,
            SIG_ZF => attributes.encoding = Encoding::Zisofs,
            _ => {}
        },
    )?;
    attributes.name = match (has_name, too_long) {
        (false, _) => None,
        (true, false) => Some(AlternateName::Recorded(name)),
        (true, true) => Some(AlternateName::TooLong),
    };
    Ok(attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(signature: [u8; 2], data: &[u8]) -> Vec<u8> {
        let mut bytes = signature.to_vec();
        bytes.push(u8::try_from(ENTRY_HEADER_SIZE + data.len()).unwrap());
        bytes.push(1);
        bytes.extend_from_slice(data);
        bytes
    }

    fn both(value: u32) -> Vec<u8> {
        let mut bytes = value.to_le_bytes().to_vec();
        bytes.extend_from_slice(&value.to_be_bytes());
        bytes
    }

    #[test]
    fn entries_end_at_st_and_follow_continuations_last() {
        let mut image = vec![0u8; 4096];
        let continued = entry(SIG_NM, b"\0tail");
        image[2048..2048 + continued.len()].copy_from_slice(&continued);
        let mut ce = both(1);
        ce.extend(both(0));
        ce.extend(both(u32::try_from(continued.len()).unwrap()));
        let mut area = entry(SIG_CE, &ce);
        area.extend(entry(SIG_NM, b"\x01head"));
        area.extend(entry(SIG_ST, b""));
        area.extend(entry(SIG_NM, b"\0ignored"));
        let mut seen = Vec::new();
        let visit = |e: &Entry<'_>| seen.push(e.data.to_vec());
        for_each_entry(whole(&image), 2048, &area, 0, visit).unwrap();
        assert_eq!(seen, [b"\x01head".to_vec(), b"\0tail".to_vec()]);
        // With the volume cut before block 1, the continuation is absent.
        let truncated = Image {
            bytes: &image[..2048],
            size: image.len(),
        };
        let error = for_each_entry(truncated, 2048, &area, 0, |_| {});
        assert!(matches!(error, Err(Fault::Absent)), "{error:?}");
    }

    /// A volume whose bytes are all present.
    fn whole(bytes: &[u8]) -> Image<'_> {
        Image {
            bytes,
            size: bytes.len(),
        }
    }

    /// The defect text of a failed walk of entries.
    fn defect(result: std::result::Result<(), Fault>) -> String {
        match result {
            Err(Fault::Defect(defect)) => defect,
            other => panic!("a defect expected: {other:?}"),
        }
    }

    #[test]
    fn continuation_loops_are_bounded() {
        let mut image = vec![0u8; 2048];
        let mut ce = both(0);
        ce.extend(both(0));
        ce.extend(both(28));
        let looping = entry(SIG_CE, &ce);
        image[..looping.len()].copy_from_slice(&looping);
        let error = defect(for_each_entry(whole(&image), 2048, &looping, 0, |_| {}));
        assert!(error.contains("more than 32"), "{error}");
        let mut outside = both(9);
        outside.extend(both(0));
        outside.extend(both(28));
        let error = for_each_entry(whole(&image), 2048, &entry(SIG_CE, &outside), 0, |_| {});
        assert!(defect(error).contains("outside the volume"));
    }

    #[test]
    fn er_identifiers_need_their_lengths() {
        let mut data = vec![10, 0, 0, 1];
        data.extend_from_slice(b"IEEE_P1282");
        assert_eq!(extension_identifier(&data), Some(b"IEEE_P1282".as_slice()));
        assert_eq!(extension_identifier(&data[..8]), None);
        assert_eq!(extension_identifier(&[]), None);
    }
}
