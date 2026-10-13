//! AY tunes of type `EMUL` (`ZXAYEMUL`): Z80 code for the ZX Spectrum and
//! Amstrad CPC (Sergey Bulba, AY-3-8910/12 Emulator documentation, "AY"
//! file format, after the format by Patrik Rak).
//!
//! All words are big-endian and every pointer is a signed 16-bit offset
//! from the pointer's own position. Header (20 bytes): `ZXAY` (4), type
//! `EMUL` (4), file version (1), player version (1), special player
//! pointer (2), author and misc string pointers (2 + 2), song count minus
//! one (1), first song (1, zero-based), song structure pointer (2). Each
//! song record is a name pointer and a song data pointer (2 + 2). Song
//! data: four channel numbers, song length, fade length (2 + 2), high and
//! low register halves (1 + 1), a pointer to the stack, init and interrupt
//! addresses (2 + 2 + 2), and a pointer to the data blocks: address,
//! length and relative offset (2 + 2 + 2) each, until an address of 0. The
//! documentation's offset column for the block list contradicts its "groups
//! by three word values"; Game Music Emu 0.6.5 (`Ay_Emu.cpp`) reads 6-byte
//! groups with the offset field at +4, as here.
//!
//! Loading rules from the documentation, which "enable to play corrupted
//! AY-files": a block reaching past 65536 or past the end of the file is
//! shortened. An init address of 0 means the first block's address.

use super::*;
use std::collections::HashSet;

/// Header magic (`ZXAY` and type `EMUL`) and fields.
const MAGIC: &[u8; 8] = b"ZXAYEMUL";
const HEADER_SIZE: usize = 20;
const FILE_VERSION: usize = 8;
const PLAYER_VERSION: usize = 9;
const SPECIAL_PLAYER: usize = 10;
const AUTHOR: usize = 12;
const MISC: usize = 14;
const SONG_COUNT: usize = 16;
const FIRST_SONG: usize = 17;
const SONGS: usize = 18;

/// Song record: name and song data pointers.
const SONG_RECORD_SIZE: usize = 4;
const SONG_NAME: usize = 0;
const SONG_DATA: usize = 2;

/// `EMUL` song data and its pointers.
const SONG_DATA_SIZE: usize = 14;
const POINTS: usize = 10;
const BLOCKS: usize = 12;

/// Pointers record: stack, init and interrupt addresses.
const POINTS_SIZE: usize = 6;
const STACK: usize = 0;
const INIT: usize = 2;
const INTERRUPT: usize = 4;

/// Data block: address, length and relative offset.
const BLOCK_SIZE: usize = 6;
const BLOCK_LENGTH: usize = 2;
const BLOCK_OFFSET: usize = 4;

/// The Z80 address space.
const Z80_SPACE: usize = 0x1_0000;

/// Most block records read across all songs; real files hold a few per
/// song.
const MAX_BLOCK_RECORDS: usize = container::MAX_COMPONENTS;

/// Characters kept of a string.
const MAX_TEXT: usize = 120;

/// The Z80, little-endian.
const Z80: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// `ZXAYEMUL` at offset 0.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

fn be_i16(data: &[u8], at: usize) -> Result<i16> {
    let bytes = slice(data, at, 2)?;
    Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The target of the relative pointer at `at`, or `None` for 0.
fn pointer(data: &[u8], at: usize) -> Result<Option<usize>> {
    let delta = be_i16(data, at).map_err(|_| error(format!("Truncated AY pointer at 0x{at:X}")))?;
    if delta == 0 {
        return Ok(None);
    }
    let target = i64::try_from(at).map_err(|_| error("File range overflow"))? + i64::from(delta);
    usize::try_from(target)
        .ok()
        .filter(|target| *target < data.len())
        .map(Some)
        .ok_or_else(|| {
            error(format!(
                "Invalid AY pointer at 0x{at:X}: target outside the file"
            ))
        })
}

/// A pointer that must not be 0.
fn required(data: &[u8], at: usize, what: &str) -> Result<usize> {
    pointer(data, at)?.ok_or_else(|| error(format!("Missing AY {what} at 0x{at:X}")))
}

/// The NUL-terminated string at the pointer at `at`.
fn string_at(data: &[u8], at: usize) -> Result<Option<String>> {
    Ok(pointer(data, at)?.map(|start| {
        let rest = &data[start..];
        let len = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        bounded_text(&rest[..len], MAX_TEXT)
    }))
}

/// One song's player addresses.
struct Song {
    name: Option<String>,
    stack: u16,
    init: u16,
    interrupt: u16,
}

/// Parse an AY file: each song's data blocks become load sections; blocks
/// shared by several songs are listed once.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = data.get(..HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated AY header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    if !header.starts_with(MAGIC) {
        return Err(error("Missing AY magic ZXAYEMUL"));
    }
    let song_count = usize::from(header[SONG_COUNT]) + 1;
    let first_song = usize::from(header[FIRST_SONG]);
    let songs_at = required(data, SONGS, "song structure")?;
    if songs_at + song_count * SONG_RECORD_SIZE > data.len() {
        return Err(error(format!(
            "Truncated AY song structure at 0x{songs_at:X}: {song_count} songs"
        )));
    }
    let mut c = Container::new(FileFormat::AyTune, Layout::Ay.label(), "ay");
    c.target = Some(Z80);
    c.code_sections = true;
    c.consumed = data.len();
    let mut blocks = Blocks::default();
    let mut first = None;
    for index in 0..song_count {
        let record = songs_at + index * SONG_RECORD_SIZE;
        let song = song(&mut c, data, record, index, &mut blocks)?;
        if index == first_song.min(song_count - 1) {
            first = Some(song);
        }
    }
    if c.sections.is_empty() {
        return Err(error("Missing AY data blocks"));
    }
    if blocks.truncated {
        c.notes.push(format!(
            "Block lists were cut short by the limits of {MAX_BLOCK_RECORDS} block records, {} sections and {} of data",
            container::MAX_COMPONENTS,
            compressed::size_text(MAX_PAYLOAD)
        ));
    }
    let first = first.expect("song_count is at least 1");
    c.entry = Some(u64::from(first.init));
    let author = string_at(data, AUTHOR)?.unwrap_or_default();
    let misc = string_at(data, MISC)?.unwrap_or_default();
    c.notes.insert(
        0,
        format!(
            "AY (ZXAYEMUL): {song_count} songs, first song {}; file version {}, player version {}; author \"{author}\"; misc \"{misc}\"",
            first_song + 1,
            header[FILE_VERSION],
            header[PLAYER_VERSION]
        ),
    );
    c.notes.insert(
        1,
        format!(
            "Z80 driver of song {}{}: init 0x{:04X}, interrupt 0x{:04X}, stack 0x{:04X}; addresses are Z80 addresses",
            first_song + 1,
            first.name.map_or(String::new(), |name| format!(" \"{name}\"")),
            first.init,
            first.interrupt,
            first.stack
        ),
    );
    if first_song >= song_count {
        c.notes.push(format!(
            "First song {} is beyond the {song_count} songs",
            first_song + 1
        ));
    }
    if be_i16(header, SPECIAL_PLAYER)? != 0 {
        c.notes
            .push("A 68000 special player is attached; ignored".into());
    }
    Ok(c)
}

/// Data blocks collected across all songs.
#[derive(Default)]
struct Blocks {
    /// File offset, length and address of every listed block.
    seen: HashSet<(usize, usize, u16)>,
    /// Bytes in listed blocks.
    loaded: usize,
    /// Block records read, bounded by [`MAX_BLOCK_RECORDS`].
    records: usize,
    /// A limit stopped the block lists.
    truncated: bool,
}

/// The song record at `record`: its pointers and data blocks.
fn song<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    record: usize,
    index: usize,
    blocks: &mut Blocks,
) -> Result<Song> {
    let name = string_at(data, record + SONG_NAME)?;
    let song_data_at = required(data, record + SONG_DATA, "song data")?;
    if data.len() - song_data_at < SONG_DATA_SIZE {
        return Err(error(format!(
            "Truncated AY song data of song {} at 0x{song_data_at:X}",
            index + 1
        )));
    }
    let points_at = required(data, song_data_at + POINTS, "pointers record")?;
    let points = data
        .get(points_at..points_at + POINTS_SIZE)
        .ok_or_else(|| error(format!("Truncated AY pointers record at 0x{points_at:X}")))?;
    let blocks_at = required(data, song_data_at + BLOCKS, "data blocks record")?;
    let first_address = block_list(c, data, blocks_at, index, blocks)?;
    let init = be_u16(points, INIT)?;
    Ok(Song {
        name,
        stack: be_u16(points, STACK)?,
        init: if init == 0 {
            first_address.unwrap_or(0)
        } else {
            init
        },
        interrupt: be_u16(points, INTERRUPT)?,
    })
}

/// The data block list at `at`, up to an address of 0; returns the first
/// block's address. Blocks already listed for another song are skipped.
fn block_list<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    at: usize,
    index: usize,
    blocks: &mut Blocks,
) -> Result<Option<u16>> {
    let mut first_address = None;
    let mut record = at;
    loop {
        let address = be_u16(data, record)
            .map_err(|_| error(format!("Truncated AY data block list at 0x{record:X}")))?;
        if address == 0 {
            return Ok(first_address);
        }
        if blocks.records == MAX_BLOCK_RECORDS {
            blocks.truncated = true;
            return Ok(first_address.or(Some(address)));
        }
        blocks.records += 1;
        first_address.get_or_insert(address);
        let declared = usize::from(
            be_u16(data, record + BLOCK_LENGTH)
                .map_err(|_| error(format!("Truncated AY data block at 0x{record:X}")))?,
        );
        let stored_at = required(data, record + BLOCK_OFFSET, "data block offset")?;
        let length = declared
            .min(Z80_SPACE - usize::from(address))
            .min(data.len() - stored_at);
        if length < declared {
            c.notes.push(format!(
                "Data block 0x{address:04X} of song {} shortened from {declared} B to {length} B",
                index + 1
            ));
        }
        let fits =
            c.sections.len() < container::MAX_COMPONENTS && blocks.loaded + length <= MAX_PAYLOAD;
        if !fits {
            blocks.truncated = true;
        } else if blocks.seen.insert((stored_at, length, address)) {
            blocks.loaded += length;
            c.sections.push(borrowed_section(
                format!("Block 0x{address:04X}"),
                u64::from(address),
                stored_at,
                &data[stored_at..stored_at + length],
            ));
        }
        record += BLOCK_SIZE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointers_are_signed_and_relative_to_their_own_position() {
        let mut data = vec![0u8; 16];
        data[4..6].copy_from_slice(&6i16.to_be_bytes());
        data[10..12].copy_from_slice(&(-8i16).to_be_bytes());
        assert_eq!(pointer(&data, 4).expect("valid"), Some(10));
        assert_eq!(pointer(&data, 10).expect("valid"), Some(2));
        assert_eq!(pointer(&data, 0).expect("valid"), None);
        data[0..2].copy_from_slice(&100i16.to_be_bytes());
        assert!(pointer(&data, 0).is_err());
    }
}
