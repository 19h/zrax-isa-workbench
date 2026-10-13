//! Atari ST SNDH tunes ("SNDH file structure, Revision 2.2", January 2026,
//! <https://sndh.atari.org/fileformat.php>, fetched 2026-10-13; the same
//! text is frno7/psgplay `doc/sndhv22.txt` at `6f1c39ff`) and Pack-Ice
//! packed files.
//!
//! An SNDH file is a 68000 program, "all values ... in MOTOROLA BIG ENDIAN
//! format": entries at offsets 0 (INIT, `bra.w`, subtune number in `d0.w`),
//! 4 (EXIT) and 8 (PLAY), `SNDH` at 12, then tags up to `HDNS`: the TITL,
//! COMM, RIPP, CONV and YEAR strings, the `##nn` subtune count, the
//! `TAnnn`, `TBnnn`, `TCnnn` and `TDnnn` timers and the `!Vnn` VBL rate,
//! the `#!nn` default subtune, `#!SN` subtune names, FRMS frame counts and
//! FLAG. The format gives no load address; the player calls the entries,
//! so the program is one section whose addresses are file offsets. The
//! entry branch targets are informational: `bra.w` is opcode 0x6000 with
//! a 16-bit displacement from the opcode address plus 2 (68000 encoding).
//!
//! Pack-Ice files start with `ICE!`, the packed size including the 12-byte
//! header and the unpacked size (4 + 4, big-endian; psgplay
//! `include/ice/ice.h` and `lib/ice/ice.c` at `6f1c39ff`). The only
//! depacker source found is GPL-2.0, and no independent test vectors were
//! available, so the packed data is not decoded and stays opaque.

use super::*;

/// `SNDH` follows the three entry branches; tags follow it.
const MAGIC: &[u8; 4] = b"SNDH";
const MAGIC_OFFSET: usize = 12;
const TAGS_OFFSET: usize = 16;

/// The end-of-header tag.
const END_TAG: &[u8; 4] = b"HDNS";

/// Entry slots and the `bra.w` opcode word.
const ENTRIES: [(usize, &str); 3] = [(0, "INIT"), (4, "EXIT"), (8, "PLAY")];
const BRA_W: u16 = 0x6000;
const BRANCH_BASE: i64 = 2;

/// NUL-terminated string tags and their meaning.
const STRING_TAGS: [(&[u8; 4], &str); 5] = [
    (b"TITL", "title"),
    (b"COMM", "composer"),
    (b"RIPP", "ripper"),
    (b"CONV", "converter"),
    (b"YEAR", "year"),
];

/// Two-digit tags: subtune count and default subtune.
const SUBTUNES: [u8; 2] = *b"##";
const DEFAULT_SUBTUNE: [u8; 2] = *b"#!";

/// Subtune names: a word offset table, then strings.
const SUBTUNE_NAMES: &[u8; 4] = b"#!SN";

/// Timer and VBL tags: a frequency in decimal digits.
const RATE_TAGS: [&[u8; 2]; 5] = [b"TA", b"TB", b"TC", b"TD", b"!V"];

/// Per-subtune tables: FRMS (a long word each) and the older TIME (a word
/// each, "replaced" by FRMS).
const FRAMES: &[u8; 4] = b"FRMS";
const FRAME_ENTRY: usize = 4;
const TIME: &[u8; 4] = b"TIME";
const TIME_ENTRY: usize = 2;

/// FLAG: `~` and flag letters, NUL-terminated.
const FLAGS: &[u8; 4] = b"FLAG";

/// Characters kept of a string tag.
const MAX_TEXT: usize = 120;

/// The Atari ST 68000.
const MC68000: Target = Target::new(Isa::M68k, 32, Endianness::Big);

/// Pack-Ice header: magic, packed size (including the header) and unpacked
/// size.
const ICE_MAGIC: &[u8; 4] = b"ICE!";
const ICE_HEADER_SIZE: usize = 12;
const ICE_PACKED_SIZE: usize = 4;
const ICE_UNPACKED_SIZE: usize = 8;

/// `SNDH` at offset 12, followed by a header tag this parser knows or by
/// `HDNS`. The tag check keeps other files with `SNDH` at offset 12 (a tar
/// member path such as `Music/Atari/SNDH/...`) from being taken for SNDH.
pub(super) fn detect(data: &[u8]) -> bool {
    has_magic(data) && data.get(TAGS_OFFSET..).is_some_and(is_tag_start)
}

/// `SNDH` at offset 12.
fn has_magic(data: &[u8]) -> bool {
    data.get(MAGIC_OFFSET..TAGS_OFFSET) == Some(MAGIC.as_slice())
}

/// Whether `rest` starts with `HDNS` or a tag [`read_tags`] reads.
fn is_tag_start(rest: &[u8]) -> bool {
    rest.starts_with(END_TAG)
        || STRING_TAGS.iter().any(|(id, _)| rest.starts_with(*id))
        || two_digits(rest, SUBTUNES).is_some()
        || two_digits(rest, DEFAULT_SUBTUNE).is_some()
        || rest.starts_with(SUBTUNE_NAMES)
        || RATE_TAGS
            .iter()
            .any(|id| rest.starts_with(*id) && rest.get(2).is_some_and(u8::is_ascii_digit))
        || rest.starts_with(FLAGS)
        || rest.starts_with(FRAMES)
        || rest.starts_with(TIME)
}

/// `ICE!` at offset 0.
pub(super) fn detect_pack_ice(data: &[u8]) -> bool {
    data.starts_with(ICE_MAGIC)
}

/// The header tags read before the first one this parser does not know.
#[derive(Default)]
struct Tags {
    strings: Vec<(&'static str, String)>,
    subtunes: Option<usize>,
    default_subtune: Option<usize>,
    rate: Option<String>,
    flags: Option<String>,
    /// Offset of `HDNS`.
    end: Option<usize>,
    /// Offset where reading stopped before `HDNS`.
    stopped: Option<usize>,
}

/// The NUL-terminated string at `at` and the offset after its NUL.
fn nul_string(data: &[u8], at: usize) -> (String, usize) {
    let rest = data.get(at..).unwrap_or_default();
    let len = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    (bounded_text(&rest[..len], MAX_TEXT), at + len + 1)
}

/// `prefix` and two decimal digits.
fn two_digits(rest: &[u8], prefix: [u8; 2]) -> Option<usize> {
    let digits = rest.strip_prefix(prefix.as_slice())?.get(..2)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// The tags from offset 16 up to `HDNS`. Every step advances, so the loop
/// ends with the file.
fn read_tags(data: &[u8]) -> Tags {
    let mut tags = Tags::default();
    let mut pos = TAGS_OFFSET;
    while pos < data.len() {
        let rest = &data[pos..];
        if rest.starts_with(END_TAG) {
            tags.end = Some(pos);
            return tags;
        }
        // NUL padding to an even boundary.
        if rest[0] == 0 {
            pos += 1;
            continue;
        }
        if let Some((_, field)) = STRING_TAGS.iter().find(|(id, _)| rest.starts_with(*id)) {
            let (text, next) = nul_string(data, pos + MAGIC.len());
            tags.strings.push((field, text));
            pos = next;
            continue;
        }
        if rest.starts_with(SUBTUNE_NAMES) {
            break;
        }
        if let Some(count) = two_digits(rest, SUBTUNES) {
            tags.subtunes = Some(count);
            pos += 4;
            continue;
        }
        if let Some(default) = two_digits(rest, DEFAULT_SUBTUNE) {
            tags.default_subtune = Some(default);
            pos += 4;
            continue;
        }
        if RATE_TAGS.iter().any(|id| rest.starts_with(*id)) {
            let digits = rest[2..].iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                break;
            }
            tags.rate = Some(String::from_utf8_lossy(&rest[..2 + digits]).into_owned());
            pos += 2 + digits;
            continue;
        }
        if rest.starts_with(FLAGS) {
            let (text, next) = nul_string(data, pos + FLAGS.len());
            tags.flags = Some(text);
            pos = next;
            continue;
        }
        let entry = if rest.starts_with(FRAMES) {
            FRAME_ENTRY
        } else if rest.starts_with(TIME) {
            TIME_ENTRY
        } else {
            break;
        };
        let Some(subtunes) = tags.subtunes else {
            break;
        };
        pos += FRAMES.len() + subtunes * entry;
    }
    if pos < data.len() {
        tags.stopped = Some(pos);
    }
    tags
}

/// The targets of the three entry branches, if all are `bra.w`.
fn entry_branches(data: &[u8]) -> Option<String> {
    let targets: Option<Vec<String>> = ENTRIES
        .iter()
        .map(|(at, name)| {
            if be_u16(data, *at).ok()? != BRA_W {
                return None;
            }
            let word = data.get(at + 2..at + 4)?;
            let displacement = i64::from(i16::from_be_bytes([word[0], word[1]]));
            let target = i64::try_from(*at).ok()? + BRANCH_BASE + displacement;
            Some(format!("{name} 0x{target:X}"))
        })
        .collect();
    targets.map(|targets| targets.join(", "))
}

/// Parse an SNDH file: one 68000 program section over the whole file.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !has_magic(data) {
        return Err(error("Missing SNDH tag at offset 12"));
    }
    let tags = read_tags(data);
    let mut c = Container::new(FileFormat::Sndh, Layout::Sndh.label(), "sndh");
    c.target = Some(MC68000);
    c.code_sections = true;
    c.consumed = data.len();
    c.entry = Some(0);
    let mut summary = vec!["SNDH 68000 program".to_string()];
    summary.extend(
        tags.strings
            .iter()
            .map(|(field, text)| format!("{field} \"{text}\"")),
    );
    if let Some(count) = tags.subtunes {
        let default = tags.default_subtune.unwrap_or(1);
        summary.push(format!("{count} subtunes, default {default}"));
    }
    if let Some(rate) = &tags.rate {
        summary.push(format!("replay {rate}"));
    }
    c.notes.push(summary.join("; "));
    c.notes.push(match entry_branches(data) {
        Some(targets) => format!(
            "Entry branches (bra.w): {targets}; addresses are file offsets"
        ),
        None => "The INIT, EXIT and PLAY entries are not all bra.w instructions; addresses are file offsets".into(),
    });
    if let Some(flags) = &tags.flags {
        c.notes.push(format!("FLAG {flags}"));
    }
    match (tags.end, tags.stopped) {
        (Some(_), _) => {}
        (None, Some(at)) => c.notes.push(format!(
            "Header tags read up to 0x{at:X}; no HDNS end tag before that"
        )),
        (None, None) => c.notes.push("No HDNS end-of-header tag".into()),
    }
    c.sections
        .push(borrowed_section("68000 program".into(), 0, 0, data));
    Ok(c)
}

/// Parse a Pack-Ice header; the packed data is listed as an opaque child.
pub(super) fn parse_pack_ice(data: &[u8]) -> Result<Container<'_>> {
    let header = data.get(..ICE_HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated Pack-Ice header: {} B of {ICE_HEADER_SIZE} B",
            data.len()
        ))
    })?;
    if !header.starts_with(ICE_MAGIC) {
        return Err(error("Missing Pack-Ice magic"));
    }
    let packed = be_u32(header, ICE_PACKED_SIZE)? as usize;
    let unpacked = be_u32(header, ICE_UNPACKED_SIZE)? as usize;
    if packed < ICE_HEADER_SIZE {
        return Err(error(format!(
            "Invalid Pack-Ice packed size {packed} B: smaller than the {ICE_HEADER_SIZE} B header"
        )));
    }
    if packed > data.len() {
        return Err(error(format!(
            "Truncated Pack-Ice data: {packed} B declared, {} B present",
            data.len()
        )));
    }
    if unpacked == 0 {
        return Err(error("Invalid Pack-Ice unpacked size 0"));
    }
    let mut c = Container::new(FileFormat::PackIce, Layout::PackIce.label(), "packice");
    c.consumed = packed;
    c.notes.push(format!(
        "Pack-Ice: {} packed, {} unpacked; no Pack-Ice decoder is implemented, so the packed content and its format are not analyzed",
        compressed::size_text(packed),
        compressed::size_text(unpacked)
    ));
    if packed < data.len() {
        c.notes.push(format!(
            "{} after the packed data; ignored",
            compressed::size_text(data.len() - packed)
        ));
    }
    c.children.push(Child::opaque(
        "Packed data",
        ICE_HEADER_SIZE,
        &data[ICE_HEADER_SIZE..packed],
    ));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_read_up_to_hdns_or_the_first_unknown_tag() {
        let mut file = vec![0u8; 12];
        file.extend_from_slice(b"SNDHTITLLed Storm\0COMMTim Follin\0##04TC50\0#!02\0\0HDNS");
        let tags = read_tags(&file);
        assert_eq!(
            tags.strings,
            [
                ("title", "Led Storm".to_string()),
                ("composer", "Tim Follin".to_string())
            ]
        );
        assert_eq!((tags.subtunes, tags.default_subtune), (Some(4), Some(2)));
        assert_eq!(tags.rate.as_deref(), Some("TC50"));
        assert_eq!(tags.end, Some(file.len() - 4));
        let mut unknown = vec![0u8; 12];
        unknown.extend_from_slice(b"SNDHXXXX");
        assert_eq!(read_tags(&unknown).stopped, Some(16));
    }
}
