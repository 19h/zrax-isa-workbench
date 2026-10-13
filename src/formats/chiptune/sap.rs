//! Atari 8-bit SAP tunes (Piotr Fusik, ASAP "SAP (Slight Atari Player) file
//! format specification", <https://asap.sourceforge.net/sap-format.html>,
//! fetched 2026-10-13).
//!
//! A plain-text header, then binary data. The header starts with the line
//! `SAP` and CR/LF; each further line holds one uppercase tag and an
//! optional argument after a single space. The binary part is an Atari
//! executable: blocks of `FF FF` (required for the first block, optional
//! for the others), the first and last load address (2 + 2, little-endian)
//! and the data. "Files that end in the middle of block data or the
//! addresses are considered malformed, but some SAP players accept them",
//! so such an end is noted and the bytes present are kept. `TYPE R` files
//! hold a raw POKEY register dump instead of a program.

use super::*;

/// The first header line, and the marker that starts a binary block.
const MAGIC: &[u8; 5] = b"SAP\r\n";
const BLOCK_MARKER: [u8; 2] = [0xff, 0xff];

/// Block header after the optional marker: first and last address.
const BLOCK_ADDRESSES: usize = 4;

/// Player types (`TYPE`).
const TYPE_B: u8 = b'B';
const TYPE_C: u8 = b'C';
const TYPE_D: u8 = b'D';
const TYPE_S: u8 = b'S';
const TYPE_R: u8 = b'R';
const PLAYER_TYPES: [u8; 5] = [TYPE_B, TYPE_C, TYPE_D, TYPE_S, TYPE_R];

/// TYPE C initializes the player through `PLAYER+3`.
const TYPE_C_INIT_OFFSET: u64 = 3;

/// ASAP 3.0.0 "supports FASTPLAY up to 32767".
const MAX_FASTPLAY: u16 = 32767;

/// Characters kept of a text argument ("should be limited to 120
/// characters"), and unknown tag names listed.
const MAX_TEXT: usize = 120;
const MAX_UNKNOWN_LISTED: usize = 8;

/// The Atari 8-bit 6502.
const MOS6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The tags the specification defines.
const KNOWN_TAGS: [&str; 14] = [
    "AUTHOR", "NAME", "DATE", "SONGS", "DEFSONG", "STEREO", "NTSC", "TYPE", "FASTPLAY", "INIT",
    "MUSIC", "PLAYER", "COVOX", "TIME",
];

/// `SAP` and CR/LF at offset 0, then a line that starts with a defined
/// tag. A text whose first line is just "SAP" is not taken for a corrupt
/// SAP file.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(rest) = data.strip_prefix(MAGIC.as_slice()) else {
        return false;
    };
    let name_len = rest.iter().take_while(|b| b.is_ascii_uppercase()).count();
    let name = &rest[..name_len];
    KNOWN_TAGS.iter().any(|tag| tag.as_bytes() == name)
        && matches!(rest.get(name_len), Some(b' ' | b'\r' | b'\n'))
}

/// The header tags this parser reads.
#[derive(Default)]
struct Header {
    author: Option<String>,
    name: Option<String>,
    date: Option<String>,
    songs: Option<u16>,
    default_song: Option<u16>,
    stereo: bool,
    ntsc: bool,
    player_type: Option<u8>,
    fastplay: Option<u16>,
    init: Option<u16>,
    music: Option<u16>,
    player: Option<u16>,
    covox: Option<u16>,
    times: usize,
    unknown: Vec<String>,
}

/// Printable ASCII starting with an uppercase tag name.
fn is_header_line(line: &[u8]) -> bool {
    line.first().is_some_and(u8::is_ascii_uppercase)
        && line.iter().all(|b| (b' '..=b'~').contains(b))
}

/// A decimal argument of one to five digits.
fn decimal(argument: &[u8]) -> Option<u16> {
    if argument.is_empty() || argument.len() > 5 || !argument.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(argument).ok()?.parse().ok()
}

/// A hexadecimal address of one to four digits ("players usually forgive
/// lowercase and fewer digits").
fn hex_address(argument: &[u8]) -> Option<u16> {
    if argument.is_empty() || argument.len() > 4 || !argument.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u16::from_str_radix(std::str::from_utf8(argument).ok()?, 16).ok()
}

/// A doublequoted string.
fn quoted(argument: &[u8]) -> Option<String> {
    let inner = argument.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    Some(bounded_text(inner, MAX_TEXT))
}

/// `TIME`: one or two minute digits, a colon, two second digits, an
/// optional fraction of one to three digits and an optional ` LOOP`.
fn is_time(argument: &[u8]) -> bool {
    let time = argument.strip_suffix(b" LOOP").unwrap_or(argument);
    let Some(colon) = time.iter().position(|b| *b == b':') else {
        return false;
    };
    let (minutes, rest) = (&time[..colon], &time[colon + 1..]);
    let (seconds, fraction) = match rest.iter().position(|b| *b == b'.') {
        Some(dot) => (&rest[..dot], Some(&rest[dot + 1..])),
        None => (rest, None),
    };
    let digits = |field: &[u8], range: std::ops::RangeInclusive<usize>| {
        range.contains(&field.len()) && field.iter().all(u8::is_ascii_digit)
    };
    digits(minutes, 1..=2) && digits(seconds, 2..=2) && fraction.map_or(true, |f| digits(f, 1..=3))
}

/// Apply one header line at file offset `at`.
fn apply_tag(header: &mut Header, line: &[u8], at: usize) -> Result<()> {
    let (name, argument) = match line.iter().position(|b| *b == b' ') {
        Some(space) => (&line[..space], Some(&line[space + 1..])),
        None => (line, None),
    };
    let name = String::from_utf8_lossy(name).into_owned();
    let invalid = || error(format!("Invalid SAP {name} tag at 0x{at:X}"));
    let required = || argument.ok_or_else(invalid);
    match name.as_str() {
        "AUTHOR" => header.author = Some(quoted(required()?).ok_or_else(invalid)?),
        "NAME" => header.name = Some(quoted(required()?).ok_or_else(invalid)?),
        "DATE" => header.date = Some(quoted(required()?).ok_or_else(invalid)?),
        "SONGS" => {
            header.songs = Some(
                decimal(required()?)
                    .filter(|n| *n > 0)
                    .ok_or_else(invalid)?,
            );
        }
        "DEFSONG" => header.default_song = Some(decimal(required()?).ok_or_else(invalid)?),
        "STEREO" | "NTSC" => {
            if argument.is_some() {
                return Err(invalid());
            }
            if name == "STEREO" {
                header.stereo = true;
            } else {
                header.ntsc = true;
            }
        }
        "TYPE" => {
            let letter = match required()? {
                [letter] if PLAYER_TYPES.contains(letter) => *letter,
                _ => return Err(invalid()),
            };
            header.player_type = Some(letter);
        }
        "FASTPLAY" => {
            let lines = decimal(required()?).filter(|n| (1..=MAX_FASTPLAY).contains(n));
            header.fastplay = Some(lines.ok_or_else(invalid)?);
        }
        "INIT" => header.init = Some(hex_address(required()?).ok_or_else(invalid)?),
        "MUSIC" => header.music = Some(hex_address(required()?).ok_or_else(invalid)?),
        "PLAYER" => header.player = Some(hex_address(required()?).ok_or_else(invalid)?),
        "COVOX" => header.covox = Some(hex_address(required()?).ok_or_else(invalid)?),
        "TIME" => {
            if !is_time(required()?) {
                return Err(invalid());
            }
            header.times += 1;
        }
        _ => header.unknown.push(name),
    }
    Ok(())
}

/// The header tags and where the binary part after them starts.
struct HeaderLines {
    /// The tags read from the header lines.
    header: Header,
    /// File offset of the binary part: the first block, or the `TYPE R`
    /// register dump.
    binary_at: usize,
}

/// The header lines after `SAP`; returns the header and the offset of the
/// binary part. For `TYPE R` the first line that is not a tag starts the
/// register dump.
fn read_header(data: &[u8]) -> Result<HeaderLines> {
    let mut header = Header::default();
    let mut pos = MAGIC.len();
    loop {
        let rest = &data[pos..];
        if rest.is_empty() || rest.starts_with(&BLOCK_MARKER) {
            return Ok(HeaderLines {
                header,
                binary_at: pos,
            });
        }
        let line_end = rest.iter().position(|b| *b == b'\n');
        let line = line_end.map_or(rest, |end| &rest[..end]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !is_header_line(line) {
            if header.player_type == Some(TYPE_R) {
                return Ok(HeaderLines {
                    header,
                    binary_at: pos,
                });
            }
            return Err(error(format!("Invalid SAP header line at 0x{pos:X}")));
        }
        let end =
            line_end.ok_or_else(|| error(format!("Truncated SAP header line at 0x{pos:X}")))?;
        apply_tag(&mut header, line, pos)?;
        pos += end + 1;
    }
}

/// The tags each player type requires (and `INIT`, which type C must not
/// have).
fn check_required(header: &Header) -> Result<u8> {
    let player_type = header
        .player_type
        .ok_or_else(|| error("Missing SAP TYPE tag"))?;
    let missing = |tag: &str| {
        error(format!(
            "Missing SAP {tag} tag for TYPE {}",
            char::from(player_type)
        ))
    };
    match player_type {
        TYPE_B => {
            header.init.ok_or_else(|| missing("INIT"))?;
            header.player.ok_or_else(|| missing("PLAYER"))?;
        }
        TYPE_C => {
            header.music.ok_or_else(|| missing("MUSIC"))?;
            header.player.ok_or_else(|| missing("PLAYER"))?;
            if header.init.is_some() {
                return Err(error("Invalid SAP INIT tag for TYPE C"));
            }
        }
        TYPE_D | TYPE_S => {
            header.init.ok_or_else(|| missing("INIT"))?;
        }
        _ => {}
    }
    let songs = header.songs.unwrap_or(1);
    if let Some(default) = header.default_song.filter(|d| *d >= songs) {
        return Err(error(format!(
            "Invalid SAP DEFSONG {default} for {songs} songs"
        )));
    }
    Ok(player_type)
}

/// Parse a SAP file: the 6502 program's blocks become load sections.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(MAGIC) {
        return Err(error("Missing SAP header line"));
    }
    let HeaderLines { header, binary_at } = read_header(data)?;
    let player_type = check_required(&header)?;
    let mut c = Container::new(FileFormat::Sap, Layout::Sap.label(), "sap");
    c.consumed = data.len();
    c.notes.push(summary(&header, player_type));
    if header.stereo {
        c.notes.push("STEREO: dual POKEY".into());
    }
    if header.ntsc {
        c.notes.push("NTSC: played on an NTSC machine".into());
    }
    if let Some(covox) = header.covox {
        c.notes.push(format!("COVOX at 0x{covox:04X}"));
    }
    if !header.unknown.is_empty() {
        let listed: Vec<&str> = header
            .unknown
            .iter()
            .take(MAX_UNKNOWN_LISTED)
            .map(String::as_str)
            .collect();
        c.notes
            .push(format!("Unknown SAP tags ignored: {}", listed.join(", ")));
    }
    let binary = &data[binary_at..];
    if player_type == TYPE_R {
        c.notes.push(format!(
            "TYPE R: the data is a raw POKEY register dump ({}), not a 6502 program",
            compressed::size_text(binary.len())
        ));
        return Ok(c);
    }
    c.target = Some(MOS6502);
    c.code_sections = true;
    c.entry = match player_type {
        TYPE_C => header
            .player
            .map(|player| u64::from(player) + TYPE_C_INIT_OFFSET),
        _ => header.init.map(u64::from),
    };
    blocks(&mut c, data, binary_at)?;
    Ok(c)
}

/// The first note: player type, title, author, date and song count, then
/// the 6502 entry points.
fn summary(header: &Header, player_type: u8) -> String {
    let text = |value: &Option<String>| value.as_deref().unwrap_or("<?>").to_string();
    let mut parts = vec![
        format!(
            "SAP TYPE {}: \"{}\" by \"{}\" ({})",
            char::from(player_type),
            text(&header.name),
            text(&header.author),
            text(&header.date)
        ),
        format!(
            "{} songs, {} TIME tags",
            header.songs.unwrap_or(1),
            header.times
        ),
    ];
    let address = |value: Option<u16>| value.map_or("none".to_string(), |a| format!("0x{a:04X}"));
    if player_type != TYPE_R {
        parts.push(format!(
            "6502 driver: init {}, player {}, music {}",
            address(header.init),
            address(header.player),
            address(header.music)
        ));
    }
    if let Some(lines) = header.fastplay {
        parts.push(format!("called every {lines} scanlines"));
    }
    parts.join("; ")
}

/// Atari executable blocks from `at` to the end of the file.
fn blocks<'a>(c: &mut Container<'a>, data: &'a [u8], at: usize) -> Result<()> {
    let mut pos = at;
    while pos < data.len() {
        if data[pos..].starts_with(&BLOCK_MARKER) {
            pos += BLOCK_MARKER.len();
        } else if pos == at {
            return Err(error(format!(
                "Missing SAP binary block marker FF FF at 0x{pos:X}"
            )));
        }
        let Some(addresses) = data.get(pos..pos + BLOCK_ADDRESSES) else {
            c.notes.push(format!(
                "File ends inside the block addresses at 0x{pos:X}; malformed"
            ));
            break;
        };
        let start = le_u16(addresses, 0)?;
        let end = le_u16(addresses, 2)?;
        if end < start {
            return Err(error(format!(
                "Invalid SAP block at 0x{pos:X}: last address 0x{end:04X} before first address 0x{start:04X}"
            )));
        }
        let body_at = pos + BLOCK_ADDRESSES;
        let declared = usize::from(end - start) + 1;
        let present = declared.min(data.len() - body_at);
        if present < declared {
            c.notes.push(format!(
                "Block 0x{start:04X}-0x{end:04X} at 0x{pos:X} holds {present} B of {declared} B; malformed"
            ));
        }
        if c.sections.len() == container::MAX_COMPONENTS {
            c.notes.push(format!(
                "Blocks after 0x{pos:X} were not listed (limit {})",
                container::MAX_COMPONENTS
            ));
            break;
        }
        c.sections.push(borrowed_section(
            format!("Block 0x{start:04X}-0x{end:04X}"),
            u64::from(start),
            body_at,
            &data[body_at..body_at + present],
        ));
        pos = body_at + present;
    }
    if c.sections.is_empty() {
        return Err(error("Missing SAP binary data"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_arguments_follow_the_specified_shape() {
        for good in [&b"06:37.62"[..], b"2:34.02 LOOP", b"00:15", b"1:05.123"] {
            assert!(is_time(good), "{good:?}");
        }
        for bad in [
            &b"637"[..],
            b"06:3",
            b"06:37.",
            b"06:37.1234",
            b"06:37 loop",
        ] {
            assert!(!is_time(bad), "{bad:?}");
        }
    }

    #[test]
    fn numeric_arguments_are_bounded() {
        assert_eq!(hex_address(b"0F80"), Some(0x0f80));
        assert_eq!(hex_address(b"f80"), Some(0x0f80));
        assert_eq!(hex_address(b"10000"), None);
        assert_eq!(decimal(b"312"), Some(312));
        assert_eq!(decimal(b"-1"), None);
        assert_eq!(quoted(b"\"Inside\""), Some("Inside".to_string()));
        assert_eq!(quoted(b"Inside"), None);
    }
}
