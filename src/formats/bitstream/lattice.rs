//! Lattice bitstreams: iCE40 (Project `IceStorm` `docs/source/format.rst`
//! and `icepack/icepack.cc`, commit `b77a2d5b`) and ECP5, MachXO2/3 and
//! Nexus (prjtrellis `libtrellis/src/Bitstream.cpp` and `devices.json`,
//! commit `a31ff704`; openFPGALoader v1.1.1 `src/latticeBitParser.cpp`).
//!
//! Both families may start with a comment block: `FF 00`, NUL-terminated
//! strings, then a terminator. iCE40 ends the block with `00 FF` and the
//! preamble `7E AA 99 7E` follows; its command stream (one command byte
//! whose high nibble is the opcode and whose low nibble counts the
//! big-endian payload bytes) is walked to the wakeup command with its
//! CRC-16. ECP5-class files may carry an `LSCC` prefix, end the block with
//! `FF`, and continue with the preamble `FF FF BD B3` (`BF` or `BE` instead
//! of `BD` for encrypted bitstreams); only the opening commands up to
//! `VERIFY_ID` are read.

use super::*;
use crate::formats::checksum::crc16_ibm3740_update;

/// Start of a comment block.
const COMMENT_START: [u8; 2] = [0xff, 0x00];

/// Radiant `.bit` prefix before the ECP5-class comment block.
const LSCC_PREFIX: &[u8; 4] = b"LSCC";

/// iCE40 preamble (format.rst: "starts the actual bit stream").
const ICE40_PREAMBLE: [u8; 4] = [0x7e, 0xaa, 0x99, 0x7e];

/// Byte that ends a comment block, and the dummy byte of ECP5-class
/// command streams.
const FILL: u8 = 0xff;

/// ECP5-class preamble: two fill bytes, a key byte and `B3`.
const ECP5_PREAMBLE_SIZE: usize = 4;
const PREAMBLE_FILL_BYTES: usize = 2;
const PREAMBLE_END: u8 = 0xb3;
/// Key byte of an unencrypted bitstream.
const PREAMBLE_KEY_PLAIN: u8 = 0xbd;
/// Key byte of an encrypted bitstream (openFPGALoader).
const PREAMBLE_KEY_ENCRYPTED: u8 = 0xbf;
/// Key byte of an encrypted Nexus bitstream (openFPGALoader).
const PREAMBLE_KEY_NEXUS_ENCRYPTED: u8 = 0xbe;

/// Most bytes from the start of the file to the end of a comment block.
/// Own bound: tool comments are well under 1 KiB.
const MAX_COMMENT_SIZE: usize = 16 << 10;

/// Most bytes of comment text between an iCE40 `00 FF` terminator and the
/// preamble. format.rst: a Lattice tool "moves the terminating 0x00 0xFF a
/// few bytes into the comment string in some cases"; the bound is our own.
const MAX_TERMINATOR_SHIFT: usize = 16;

/// Most fill bytes between an ECP5-class comment block and the preamble's
/// key byte. Own bound: prjtrellis writes two (the preamble's), or six
/// after an `LSCC` prefix; `MachXO3D` files may have a few more.
const MAX_PREAMBLE_FILL: usize = 64;

/// Most dummy bytes after an ECP5-class preamble. Own bound: prjtrellis
/// writes 2 to 18 depending on the family.
const MAX_DUMMY_BYTES: usize = 64;

/// An iCE40 command byte holds the opcode in its high nibble and the
/// number of payload bytes in its low nibble (format.rst).
const OPCODE_SHIFT: u8 = 4;
const PAYLOAD_LEN_MASK: u8 = 0x0f;

/// iCE40 opcodes (format.rst).
const OPCODE_COMMAND: u8 = 0x0;
const OPCODE_BANK_NUMBER: u8 = 0x1;
const OPCODE_CRC_CHECK: u8 = 0x2;
const OPCODE_FREQUENCY_RANGE: u8 = 0x5;
const OPCODE_BANK_WIDTH: u8 = 0x6;
const OPCODE_BANK_HEIGHT: u8 = 0x7;
const OPCODE_BANK_OFFSET: u8 = 0x8;
const OPCODE_BOOT_MODE: u8 = 0x9;

/// Payloads of opcode 0 that icepack accepts.
const COMMAND_WRITE_CRAM: u32 = 0x01;
const COMMAND_WRITE_BRAM: u32 = 0x03;
const COMMAND_RESET_CRC: u32 = 0x05;
const COMMAND_WAKEUP: u32 = 0x06;

/// Most payload bytes of one iCE40 command. Own bound: commands carry one
/// or two bytes, and the payload is read as a 32-bit integer.
const MAX_COMMAND_PAYLOAD: usize = 4;

/// Boot mode bits (opcode 9; format.rst lists 0, 16 and 32, icepack also
/// accepts 1 and 33).
const BOOT_MODE_NOSLEEP: u32 = 0x01;
const BOOT_MODE_COLD_BOOT: u32 = 0x10;
const BOOT_MODE_WARM_BOOT: u32 = 0x20;

/// Oscillator frequency ranges (opcode 5).
const FREQUENCY_RANGES: [&str; 3] = ["low", "medium", "high"];

/// Initial value the reset command loads into the iCE40 CRC.
const CRC_RESET_VALUE: u16 = 0xffff;

/// CRAM geometry (width x height bits, height including the bank offset)
/// and the chip type icepack names for it.
const ICE40_CHIP_TYPES: &[(u64, u64, &str)] = &[
    (182, 80, "384"),
    (332, 144, "1k"),
    (872, 272, "8k"),
    (692, 336, "5k"),
    (692, 176, "u4k"),
    (656, 176, "lm4k"),
];

/// ECP5-class opcodes read before `VERIFY_ID` (prjtrellis
/// `Bitstream.cpp`): each takes three parameter bytes.
const OPCODE_SPI_MODE: u8 = 0x79;
const OPCODE_LSC_RESET_CRC: u8 = 0x3b;
const OPCODE_VERIFY_ID: u8 = 0xe2;
const COMMAND_PARAMETER_BYTES: usize = 3;

/// Most commands read before giving up on `VERIFY_ID`. prjtrellis writes
/// `SPI_MODE` (optional), `LSC_RESET_CRC`, then `VERIFY_ID`.
const MAX_OPENING_COMMANDS: usize = 4;

/// The table that names ECP5 devices by IDCODE.
const ECP5_IDCODE_TABLE: &str = "prjtrellis devices.json";

/// ECP5 IDCODEs (prjtrellis `devices.json`).
const ECP5_IDCODES: &[(u32, &str)] = &[
    (0x2111_1043, "LFE5U-12F"),
    (0x4111_1043, "LFE5U-25F"),
    (0x4111_2043, "LFE5U-45F"),
    (0x4111_3043, "LFE5U-85F"),
    (0x0111_1043, "LFE5UM-25F"),
    (0x0111_2043, "LFE5UM-45F"),
    (0x0111_3043, "LFE5UM-85F"),
    (0x8111_1043, "LFE5UM5G-25F"),
    (0x8111_2043, "LFE5UM5G-45F"),
    (0x8111_3043, "LFE5UM5G-85F"),
];

/// A comment block and the preamble after it.
#[derive(Debug)]
struct CommentBlock {
    /// The non-empty comment strings.
    strings: Vec<String>,
    /// File offset of the byte that ends the block.
    terminator: usize,
    /// File offset of the preamble.
    preamble: usize,
}

/// An ECP5-class header: optional `LSCC` prefix, comment block, preamble.
#[derive(Debug)]
struct Ecp5Header {
    lscc: bool,
    comment: CommentBlock,
    /// The preamble's key byte.
    key: u8,
}

/// The CRAM or BRAM bank that the next data command writes.
#[derive(Debug, Default, Clone, Copy)]
struct Bank {
    /// Bits per row.
    width: u64,
    /// Rows.
    height: u64,
    /// First row.
    offset: u64,
}

/// What a walk over an iCE40 command stream found.
#[derive(Debug, Default)]
struct Ice40Stream {
    cram_blocks: usize,
    bram_blocks: usize,
    /// Widest CRAM bank, in bits.
    cram_width: u64,
    /// Highest CRAM row written, plus one.
    cram_height: u64,
    /// CRC check commands, each verified.
    crc_checks: usize,
    frequency_range: Option<&'static str>,
    boot_mode: Option<u32>,
    /// File offset after the wakeup command.
    end: usize,
}

/// Strong recognition: a comment block at the start of the file followed
/// by its family's preamble.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if ice40_comment(data).is_some() {
        return Some(Layout::Ice40);
    }
    ecp5_header(data).map(|_| Layout::Ecp5)
}

/// Weak recognition of an iCE40 bitstream without a comment block: the
/// preamble at the start, then a command stream that reaches the wakeup
/// command with at least one CRAM bank and a verified CRC.
pub(super) fn detect_bare(data: &[u8]) -> Option<Layout> {
    if !data.starts_with(&ICE40_PREAMBLE) {
        return None;
    }
    let stream = walk_ice40(data, ICE40_PREAMBLE.len()).ok()?;
    is_complete(&stream).then_some(Layout::Ice40Bare)
}

/// Parse an iCE40 bitstream: the comment block (for [`Layout::Ice40`]),
/// the preamble and the command stream up to the wakeup command.
pub(super) fn parse_ice40(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let comment = match layout {
        Layout::Ice40 => Some(ice40_comment(data).ok_or_else(|| {
            error("Invalid iCE40 comment block: missing 00 FF terminator before the preamble")
        })?),
        _ => None,
    };
    let preamble = comment.as_ref().map_or(0, |block| block.preamble);
    if slice(data, preamble, ICE40_PREAMBLE.len())? != ICE40_PREAMBLE.as_slice() {
        return Err(error(format!(
            "Missing iCE40 preamble 0x7EAA997E at 0x{preamble:X}"
        )));
    }
    let stream = walk_ice40(data, preamble + ICE40_PREAMBLE.len())?;
    if layout == Layout::Ice40Bare && !is_complete(&stream) {
        return Err(error(
            "Missing iCE40 CRAM data or CRC check before the wakeup command",
        ));
    }

    let mut c = new_container(layout);
    if let Some(block) = &comment {
        push_comments(&mut c, &block.strings);
        let shift = block.preamble - block.terminator - 1;
        if shift > 0 {
            c.notes.push(format!(
                "Comment terminator 00 FF lies {shift} B before the preamble (Lattice tool quirk described in IceStorm format.rst)"
            ));
        }
    }
    c.notes
        .push(format!("Preamble 0x7EAA997E at 0x{preamble:X}"));
    c.push_metadata(
        "bitstream_preamble_offset",
        "Preamble offset",
        preamble as u64,
    );
    push_ice40_stream(&mut c, &stream);
    Ok(finish(
        c,
        data,
        preamble,
        &data[preamble..stream.end],
        stream.end,
    ))
}

/// Parse an ECP5-class bitstream: the header and, for an unencrypted
/// bitstream, the IDCODE that `VERIFY_ID` checks. Frames are not walked,
/// so everything from the preamble on is configuration data.
pub(super) fn parse_ecp5(data: &[u8]) -> Result<Container<'_>> {
    let header = ecp5_header(data).ok_or_else(|| {
        error("Invalid Lattice comment block: missing preamble 0xFFFFBDB3 after the terminator")
    })?;
    let preamble = header.comment.preamble;
    let key = header.key;

    let mut c = new_container(Layout::Ecp5);
    if header.lscc {
        c.notes.push("LSCC prefix (Radiant .bit)".into());
    }
    push_comments(&mut c, &header.comment.strings);
    c.notes.push(format!(
        "Preamble 0xFFFF{key:02X}{PREAMBLE_END:02X} at 0x{preamble:X}"
    ));
    c.push_metadata(
        "bitstream_preamble_offset",
        "Preamble offset",
        preamble as u64,
    );
    if key == PREAMBLE_KEY_PLAIN {
        match verify_id(data, preamble + ECP5_PREAMBLE_SIZE)? {
            Some(idcode) => {
                let device = ecp5_device(idcode.value);
                push_idcode(&mut c, idcode, device, ECP5_IDCODE_TABLE);
            }
            None => c.notes.push(
                "No VERIFY_ID command at the start of the command stream; device not identified"
                    .into(),
            ),
        }
        c.notes
            .push("Configuration frames not walked; frame CRC-16 not verified".into());
    } else {
        let family = if key == PREAMBLE_KEY_NEXUS_ENCRYPTED {
            " (Nexus)"
        } else {
            ""
        };
        c.notes.push(format!(
            "Encrypted bitstream{family}: preamble key 0x{key:02X}; command stream not read"
        ));
    }
    Ok(finish(c, data, preamble, &data[preamble..], data.len()))
}

/// The iCE40 comment block at the start of `data`: `FF 00`, comment text,
/// the terminator `00 FF`, then the preamble, which may follow up to
/// [`MAX_TERMINATOR_SHIFT`] bytes of further comment text.
fn ice40_comment(data: &[u8]) -> Option<CommentBlock> {
    let start = COMMENT_START.len();
    let terminator = comment_end(data, 0)?;
    // The terminator is `00 FF`; its `00` may not be the start's.
    if terminator <= start || data[terminator - 1] != 0x00 {
        return None;
    }
    let after = terminator + 1;
    let window_end = data
        .len()
        .min(after + MAX_TERMINATOR_SHIFT + ICE40_PREAMBLE.len());
    let shift = memchr::memmem::find(data.get(after..window_end)?, &ICE40_PREAMBLE)?;
    let shifted = &data[after..after + shift];
    if !shifted.iter().all(|&b| is_comment_byte(b)) {
        return None;
    }
    Some(CommentBlock {
        strings: comment_strings(&data[start..terminator]),
        terminator,
        preamble: after + shift,
    })
}

/// The ECP5-class header at the start of `data`: optional `LSCC`, `FF 00`,
/// comment text, the terminator `FF`, more fill, then the preamble's key
/// byte and `B3`.
fn ecp5_header(data: &[u8]) -> Option<Ecp5Header> {
    let lscc = data.starts_with(LSCC_PREFIX);
    let block_start = if lscc { LSCC_PREFIX.len() } else { 0 };
    let terminator = comment_end(data, block_start)?;
    let after = terminator + 1;
    let fill = data
        .iter()
        .skip(after)
        .take(MAX_PREAMBLE_FILL + 1)
        .take_while(|&&b| b == FILL)
        .count();
    if !(PREAMBLE_FILL_BYTES..=MAX_PREAMBLE_FILL).contains(&fill) {
        return None;
    }
    let key_at = after + fill;
    let key = *data.get(key_at)?;
    let is_key = matches!(
        key,
        PREAMBLE_KEY_PLAIN | PREAMBLE_KEY_ENCRYPTED | PREAMBLE_KEY_NEXUS_ENCRYPTED
    );
    if !is_key || data.get(key_at + 1) != Some(&PREAMBLE_END) {
        return None;
    }
    Some(Ecp5Header {
        lscc,
        comment: CommentBlock {
            strings: comment_strings(&data[block_start + COMMENT_START.len()..terminator]),
            terminator,
            preamble: key_at - PREAMBLE_FILL_BYTES,
        },
        key,
    })
}

/// The offset of the `FF` that ends the comment block starting at
/// `block_start`, when every byte before it is comment text and it lies
/// within [`MAX_COMMENT_SIZE`] bytes of the start of the file.
fn comment_end(data: &[u8], block_start: usize) -> Option<usize> {
    if !data.get(block_start..)?.starts_with(&COMMENT_START) {
        return None;
    }
    let text_start = block_start + COMMENT_START.len();
    let window = data.get(text_start..data.len().min(MAX_COMMENT_SIZE))?;
    let len = memchr::memchr(FILL, window)?;
    window[..len]
        .iter()
        .all(|&b| is_comment_byte(b))
        .then_some(text_start + len)
}

/// Comment text: printable ASCII, tab, line breaks, NUL separators and
/// bytes of non-ASCII encodings. Other control bytes do not occur in tool
/// comments and reject the block.
fn is_comment_byte(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | b'\r' | 0x20..=0x7e | 0x80..=0xfe)
}

/// The non-empty NUL-separated strings of a comment block.
fn comment_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .map(text)
        .filter(|s| !s.is_empty())
        .collect()
}

/// A weak iCE40 stream must have written CRAM and verified a CRC.
fn is_complete(stream: &Ice40Stream) -> bool {
    stream.cram_blocks > 0 && stream.crc_checks > 0
}

/// Walk the iCE40 command stream from `start` to the wakeup command. The
/// CRC-16 runs over every byte after a reset command; a CRC check command
/// stores the value that brings it to zero. Every command advances, so the
/// walk ends within the file.
fn walk_ice40(data: &[u8], start: usize) -> Result<Ice40Stream> {
    let mut stream = Ice40Stream::default();
    let mut bank = Bank::default();
    let mut crc: Option<u16> = None;
    let mut pos = start;
    loop {
        let at = pos;
        let command = data.get(at).copied().ok_or_else(|| {
            error(format!(
                "Truncated iCE40 command stream at 0x{at:X}: no wakeup command"
            ))
        })?;
        let opcode = command >> OPCODE_SHIFT;
        let payload_len = usize::from(command & PAYLOAD_LEN_MASK);
        if payload_len > MAX_COMMAND_PAYLOAD {
            return Err(unsupported(command, at));
        }
        let payload = slice(data, at + 1, payload_len)?
            .iter()
            .fold(0u32, |value, &b| (value << 8) | u32::from(b));
        pos = at + 1 + payload_len;
        match (opcode, payload) {
            (OPCODE_COMMAND, COMMAND_WRITE_CRAM | COMMAND_WRITE_BRAM) => {
                let is_cram = payload == COMMAND_WRITE_CRAM;
                pos = bank_data(data, pos, bank, is_cram)?;
                if is_cram {
                    stream.cram_blocks += 1;
                    stream.cram_width = stream.cram_width.max(bank.width);
                    stream.cram_height = stream.cram_height.max(bank.offset + bank.height);
                } else {
                    stream.bram_blocks += 1;
                }
            }
            (OPCODE_COMMAND, COMMAND_RESET_CRC | COMMAND_WAKEUP)
            | (OPCODE_BANK_NUMBER | OPCODE_CRC_CHECK, _) => {}
            (OPCODE_FREQUENCY_RANGE, range) => {
                let range = usize::try_from(range).ok();
                let name = range.and_then(|range| FREQUENCY_RANGES.get(range));
                stream.frequency_range = Some(*name.ok_or_else(|| unsupported(command, at))?);
            }
            (OPCODE_BANK_WIDTH, width) => bank.width = u64::from(width) + 1,
            (OPCODE_BANK_HEIGHT, height) => bank.height = u64::from(height),
            (OPCODE_BANK_OFFSET, offset) => bank.offset = u64::from(offset),
            (OPCODE_BOOT_MODE, mode) if mode & !boot_mode_bits() == 0 => {
                stream.boot_mode = Some(mode);
            }
            _ => return Err(unsupported(command, at)),
        }
        if let Some(value) = crc.as_mut() {
            *value = crc16_ibm3740_update(*value, &data[at..pos]);
        }
        match (opcode, payload) {
            (OPCODE_COMMAND, COMMAND_RESET_CRC) => crc = Some(CRC_RESET_VALUE),
            (OPCODE_COMMAND, COMMAND_WAKEUP) => {
                stream.end = pos;
                return Ok(stream);
            }
            (OPCODE_CRC_CHECK, _) => {
                check_crc(crc, at)?;
                stream.crc_checks += 1;
            }
            _ => {}
        }
    }
}

/// Every boot mode bit format.rst or icepack documents.
const fn boot_mode_bits() -> u32 {
    BOOT_MODE_NOSLEEP | BOOT_MODE_COLD_BOOT | BOOT_MODE_WARM_BOOT
}

/// The offset after the data of a CRAM or BRAM write at `pos`:
/// `width * height / 8` bytes (icepack truncates the division), then two
/// zero bytes.
fn bank_data(data: &[u8], pos: usize, bank: Bank, is_cram: bool) -> Result<usize> {
    let memory = if is_cram { "CRAM" } else { "BRAM" };
    let size = bank
        .width
        .checked_mul(bank.height)
        .map(|bits| bits / 8)
        .and_then(|size| usize::try_from(size).ok())
        .ok_or_else(|| error(format!("Invalid iCE40 {memory} bank size at 0x{pos:X}")))?;
    let present = data.len().saturating_sub(pos);
    if size > present {
        return Err(error(format!(
            "Truncated iCE40 {memory} data at 0x{pos:X}: {size} B declared, {present} B present"
        )));
    }
    let terminator = pos + size;
    if be_u16(data, terminator)? != 0 {
        return Err(error(format!(
            "Invalid iCE40 {memory} data terminator at 0x{terminator:X}: expected 0x0000"
        )));
    }
    Ok(terminator + 2)
}

/// A CRC check command at `at` passes when the running CRC, which now
/// includes the stored value, is zero.
fn check_crc(crc: Option<u16>, at: usize) -> Result<()> {
    match crc {
        Some(0) => Ok(()),
        Some(residue) => Err(error(format!(
            "Invalid iCE40 CRC-16 at 0x{at:X}: residue 0x{residue:04X} after the check"
        ))),
        None => Err(error(format!(
            "Invalid iCE40 CRC check at 0x{at:X}: no CRC reset before it"
        ))),
    }
}

fn unsupported(command: u8, at: usize) -> ClassifierError {
    error(format!(
        "Unsupported iCE40 command 0x{command:02X} at 0x{at:X}"
    ))
}

/// The opening commands of an unencrypted ECP5-class stream at `start`:
/// dummy bytes, then `SPI_MODE` and `LSC_RESET_CRC` until `VERIFY_ID`,
/// whose IDCODE follows its three parameter bytes.
fn verify_id(data: &[u8], start: usize) -> Result<Option<Idcode>> {
    let dummies = data
        .iter()
        .skip(start)
        .take(MAX_DUMMY_BYTES)
        .take_while(|&&b| b == FILL)
        .count();
    let mut pos = start + dummies;
    for _ in 0..MAX_OPENING_COMMANDS {
        match byte(data, pos)? {
            OPCODE_SPI_MODE | OPCODE_LSC_RESET_CRC => pos += 1 + COMMAND_PARAMETER_BYTES,
            OPCODE_VERIFY_ID => {
                let offset = pos + 1 + COMMAND_PARAMETER_BYTES;
                let value = be_u32(data, offset)?;
                return Ok(Some(Idcode { value, offset }));
            }
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// The ECP5 device whose IDCODE this is.
fn ecp5_device(idcode: u32) -> Option<&'static str> {
    ECP5_IDCODES
        .iter()
        .find(|(code, _)| *code == idcode)
        .map(|(_, name)| *name)
}

/// The chip type icepack names for a CRAM geometry.
fn ice40_chip_type(width: u64, height: u64) -> Option<&'static str> {
    ICE40_CHIP_TYPES
        .iter()
        .find(|(w, h, _)| (*w, *h) == (width, height))
        .map(|(_, _, name)| *name)
}

/// Notes and metadata for what the iCE40 command walk found.
fn push_ice40_stream(c: &mut Container<'_>, stream: &Ice40Stream) {
    c.notes.push(format!(
        "Command stream: {} CRAM and {} BRAM data blocks; wakeup command ends at 0x{:X}",
        stream.cram_blocks, stream.bram_blocks, stream.end
    ));
    if stream.cram_blocks > 0 {
        let (width, height) = (stream.cram_width, stream.cram_height);
        match ice40_chip_type(width, height) {
            Some(chip) => {
                c.notes.push(format!(
                    "CRAM geometry {width} x {height} bits; icepack chip type {chip}"
                ));
                c.push_metadata(
                    "bitstream_ice40_chip_type",
                    "iCE40 chip type (icepack)",
                    chip,
                );
            }
            None => c.notes.push(format!(
                "CRAM geometry {width} x {height} bits; not a chip type icepack knows"
            )),
        }
    }
    if let Some(range) = stream.frequency_range {
        c.notes.push(format!("Internal oscillator range: {range}"));
    }
    if let Some(mode) = stream.boot_mode {
        let flag = |bit: u32| if mode & bit != 0 { "on" } else { "off" };
        c.notes.push(format!(
            "Boot mode 0x{mode:02X}: warm boot {}, cold boot {}, nosleep {}",
            flag(BOOT_MODE_WARM_BOOT),
            flag(BOOT_MODE_COLD_BOOT),
            flag(BOOT_MODE_NOSLEEP)
        ));
    }
    c.notes.push(if stream.crc_checks > 0 {
        format!(
            "CRC-16 verified at {}",
            count(stream.crc_checks, "check command", "check commands")
        )
    } else {
        "No CRC check command; CRC not verified".into()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::checksum::crc16_ibm3740;

    /// Preamble, frequency range, CRC reset, a 16 x 2 CRAM bank of four
    /// bytes, the CRC check that zeroes the running CRC, then wakeup.
    fn stream() -> Vec<u8> {
        let mut data = ICE40_PREAMBLE.to_vec();
        data.extend_from_slice(&[0x51, 0x00, 0x01, 0x05]);
        let covered = data.len();
        data.extend_from_slice(&[0x62, 0x00, 0x0f, 0x72, 0x00, 0x02, 0x82, 0x00, 0x00]);
        data.extend_from_slice(&[0x11, 0x00, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
        data.push(0x22);
        let crc = crc16_ibm3740(&data[covered..]);
        data.extend_from_slice(&crc.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x06, 0x00]);
        data
    }

    #[test]
    fn ice40_walk_verifies_the_crc_and_stops_at_wakeup() {
        let data = stream();
        let walk = walk_ice40(&data, 4).expect("valid stream");
        assert_eq!(walk.crc_checks, 1);
        assert_eq!(walk.cram_blocks, 1);
        assert_eq!((walk.cram_width, walk.cram_height), (16, 2));
        assert_eq!(walk.end, data.len() - 1);
        assert_eq!(walk.frequency_range, Some("low"));
        assert_eq!(detect_bare(&data), Some(Layout::Ice40Bare));

        let mut corrupt = data.clone();
        corrupt[22] ^= 1;
        let message = walk_ice40(&corrupt, 4).unwrap_err().to_string();
        assert!(message.contains("Invalid iCE40 CRC-16"), "{message}");
    }

    #[test]
    fn ice40_rejects_unknown_commands_and_bad_terminators() {
        let mut reboot = stream();
        reboot[7] = 0x08;
        assert!(walk_ice40(&reboot, 4).is_err());
        let mut terminator = stream();
        terminator[25] = 0x01;
        assert!(walk_ice40(&terminator, 4).is_err());
        let mut long_payload = stream();
        long_payload[4] = 0x55;
        assert!(walk_ice40(&long_payload, 4).is_err());
    }

    #[test]
    fn ice40_comment_allows_a_shifted_terminator() {
        let mut data = vec![0xff, 0x00];
        data.extend_from_slice(b"Generated by test\0");
        data.extend_from_slice(&[0x00, 0xff]);
        data.extend_from_slice(b"ab\0");
        data.extend_from_slice(&ICE40_PREAMBLE);
        let block = ice40_comment(&data).expect("comment block");
        assert_eq!(block.strings, ["Generated by test"]);
        assert_eq!(block.preamble - block.terminator - 1, 3);

        let mut control = data.clone();
        control[4] = 0x01;
        assert!(ice40_comment(&control).is_none());
        assert!(ice40_comment(&[0xff, 0x00, 0xff, 0x7e, 0xaa, 0x99, 0x7e]).is_none());
    }

    #[test]
    fn ecp5_header_needs_the_preamble_after_the_terminator() {
        let mut data = LSCC_PREFIX.to_vec();
        data.extend_from_slice(&[0xff, 0x00]);
        data.extend_from_slice(b"Part: LFE5U-25F-6CABGA256\0");
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        data.extend_from_slice(&[0xff, 0xff, 0xbd, 0xb3]);
        let header = ecp5_header(&data).expect("header");
        assert!(header.lscc);
        assert_eq!(header.key, PREAMBLE_KEY_PLAIN);
        assert_eq!(header.comment.preamble, data.len() - 4);

        // The terminator and one fill byte leave no room for the
        // preamble's two fill bytes.
        let short_fill = [0xff, 0x00, b'x', 0x00, 0xff, 0xff, 0xbd, 0xb3];
        assert!(ecp5_header(&short_fill).is_none());
        let mut wrong_key = data.clone();
        let key_at = wrong_key.len() - 2;
        wrong_key[key_at] = 0xbc;
        assert!(ecp5_header(&wrong_key).is_none());
    }

    #[test]
    fn verify_id_follows_the_opening_commands() {
        let data = [
            0xff, 0xff, 0x3b, 0, 0, 0, 0xe2, 0, 0, 0, 0x41, 0x11, 0x10, 0x43,
        ];
        let idcode = verify_id(&data, 0).expect("reads").expect("IDCODE");
        assert_eq!(
            idcode,
            Idcode {
                value: 0x4111_1043,
                offset: 10
            }
        );
        assert_eq!(ecp5_device(idcode.value), Some("LFE5U-25F"));
        assert_eq!(verify_id(&[0x46, 0, 0, 0], 0).expect("reads"), None);
        assert!(verify_id(&data[..12], 0).is_err());
    }
}
