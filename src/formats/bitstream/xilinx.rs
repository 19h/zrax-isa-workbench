//! Xilinx `.bit` files (openFPGALoader v1.1.1 `src/bitparser.cpp`, U-Boot
//! v2025.10 `drivers/fpga/xilinx.c`) and headerless configuration data in
//! either word order (AMD UG470 v1.17, chapter 5; Linux v6.12
//! `drivers/fpga/zynq-fpga.c`).
//!
//! `.bit` header: the 13-byte prefix, then keys `a` (design name), `b`
//! (part), `c` (date) and `d` (time), each with a 16-bit big-endian length,
//! then `e` with the 32-bit big-endian length of the configuration data
//! that follows. Configuration data is a stream of 32-bit words: dummy
//! words, the bus-width auto-detection pattern, the sync word, then Type 1
//! and Type 2 packets.

use super::*;
use memchr::memmem;

/// Fixed start of a `.bit` file: the length (9) of the first field, the
/// nine bytes both parsers skip, then the length (1) of the key that
/// follows.
const BIT_PREFIX: [u8; 13] = [
    0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01,
];

/// Header key of the design name.
const KEY_DESIGN: u8 = b'a';
/// Header key of the part name.
const KEY_PART: u8 = b'b';
/// Header key of the date.
const KEY_DATE: u8 = b'c';
/// Header key of the time.
const KEY_TIME: u8 = b'd';
/// Header key of the configuration data length; the data follows it.
const KEY_DATA: u8 = b'e';

/// Sync word (UG470 Table 5-19).
const SYNC_WORD: u32 = 0xaa99_5566;

/// Bus-width auto-detection pattern (UG470 "Bus Width Auto Detection").
const BUS_WIDTH_PATTERN: [u32; 2] = [0x0000_00bb, 0x1122_0044];

/// Dummy word written before synchronization and between sequences.
const DUMMY_WORD: u32 = 0xffff_ffff;

/// Most `0xFF` padding before the bus-width pattern of a headerless file.
/// Own bound: UG470's sample bitstream has 32 B and flows differ.
const MAX_RAW_PADDING: usize = 4096;

/// Most dummy words between the bus-width pattern and the sync word. Own
/// bound: UG470 Table 5-19 has two, and not every flow writes them.
const MAX_SYNC_DUMMY_WORDS: usize = 16;

/// Configuration words are 32 bits.
const WORD_SIZE: usize = 4;

/// Packet header type field, bits 31-29 (UG470 Tables 5-20 and 5-22).
const PACKET_TYPE_SHIFT: u32 = 29;
/// Type 1 packet: register address and up to 2047 data words.
const PACKET_TYPE_1: u32 = 0b001;
/// Type 2 packet: a long word count for the preceding Type 1 register.
const PACKET_TYPE_2: u32 = 0b010;
/// Opcode field, bits 28-27.
const OPCODE_SHIFT: u32 = 27;
const OPCODE_MASK: u32 = 0b11;
/// Write opcode: the data words follow the header in the stream.
const OPCODE_WRITE: u32 = 0b10;
const OPCODE_RESERVED: u32 = 0b11;
/// Type 1 register address field, bits 26-13.
const REGISTER_SHIFT: u32 = 13;
const REGISTER_MASK: u32 = 0x3fff;
/// Type 1 word count, bits 10-0.
const TYPE_1_WORD_COUNT_MASK: u32 = 0x7ff;
/// Type 2 word count, bits 26-0.
const TYPE_2_WORD_COUNT_MASK: u32 = 0x07ff_ffff;

/// CRC register address (UG470 Table 5-23).
const REGISTER_CRC: u32 = 0b00000;
/// IDCODE register address (UG470 Table 5-23).
const REGISTER_IDCODE: u32 = 0b01100;

/// IDCODE bits 31-28 hold the device revision (UG470 Table 1-1).
const IDCODE_REVISION_MASK: u32 = 0x0fff_ffff;

/// Zynq boot images (`BOOT.BIN`) carry the width detection word
/// `0xAA995566` at 0x20 and the identification `XNLX` at 0x24. They are
/// another family's and never a headerless bitstream.
const BOOT_IMAGE_ID_OFFSET: usize = 0x24;
const BOOT_IMAGE_ID: &[u8; 4] = b"XNLX";

/// The table that names devices by IDCODE.
const IDCODE_TABLE: &str = "UG470 Table 1-1";

/// 7 series IDCODEs with the revision nibble cleared (UG470 v1.17, Table
/// 1-1). The XC7V2000T is left out because its IDCODE has further
/// don't-care bits.
const SERIES_7_IDCODES: &[(u32, &str)] = &[
    (0x0362_2093, "XC7S6"),
    (0x0362_0093, "XC7S15"),
    (0x037c_4093, "XC7S25"),
    (0x0362_f093, "XC7S50"),
    (0x037c_8093, "XC7S75"),
    (0x037c_7093, "XC7S100"),
    (0x037c_3093, "XC7A12T"),
    (0x0362_e093, "XC7A15T"),
    (0x037c_2093, "XC7A25T"),
    (0x0362_d093, "XC7A35T"),
    (0x0362_c093, "XC7A50T"),
    (0x0363_2093, "XC7A75T"),
    (0x0363_1093, "XC7A100T"),
    (0x0363_6093, "XC7A200T"),
    (0x0364_7093, "XC7K70T"),
    (0x0364_c093, "XC7K160T"),
    (0x0365_1093, "XC7K325T"),
    (0x0374_7093, "XC7K355T"),
    (0x0365_6093, "XC7K410T"),
    (0x0375_2093, "XC7K420T"),
    (0x0375_1093, "XC7K480T"),
    (0x0367_1093, "XC7V585T"),
    (0x0366_7093, "XC7VX330T"),
    (0x0368_2093, "XC7VX415T"),
    (0x0368_7093, "XC7VX485T"),
    (0x0369_2093, "XC7VX550T"),
    (0x0369_1093, "XC7VX690T"),
    (0x0369_6093, "XC7VX980T"),
    (0x036d_5093, "XC7VX1140T"),
    (0x036d_9093, "XC7VH580T"),
    (0x036d_b093, "XC7VH870T"),
];

/// Order of the bytes in each 32-bit configuration word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordOrder {
    /// Most significant byte first, as UG470 lists the words.
    BigEndian,
    /// Every word byte-swapped, as the Zynq-7000 PCAP driver loads it.
    Swapped,
}

impl WordOrder {
    /// The configuration word at file offset `at`.
    fn word(self, data: &[u8], at: usize) -> Result<u32> {
        match self {
            Self::BigEndian => be_u32(data, at),
            Self::Swapped => le_u32(data, at),
        }
    }

    /// The headerless layout stored in this order.
    fn raw_layout(self) -> Layout {
        match self {
            Self::BigEndian => Layout::XilinxRaw,
            Self::Swapped => Layout::XilinxRawSwapped,
        }
    }
}

/// The `.bit` header fields, strings without their NUL.
#[derive(Debug, Default)]
struct BitHeader {
    design: Option<String>,
    part: Option<String>,
    date: Option<String>,
    time: Option<String>,
    /// Keys other than `a` to `e`, skipped as openFPGALoader skips them.
    unknown_keys: usize,
    /// File offset of the configuration data.
    data_offset: usize,
    /// Declared size of the configuration data in bytes.
    data_size: usize,
}

/// Where the synchronization sequence of a headerless bitstream lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawStart {
    /// `0xFF` padding before the bus-width pattern, in bytes; also the file
    /// offset of the pattern.
    padding: usize,
    /// File offset of the sync word.
    sync: usize,
}

/// What a walk over the packet stream found.
#[derive(Debug, Default)]
struct PacketWalk {
    /// Type 1 and Type 2 packets, NOOPs included.
    packets: usize,
    /// Synchronized sequences, the first one included.
    sequences: usize,
    /// The first write to the IDCODE register.
    idcode: Option<Idcode>,
    /// Writes to the CRC register.
    crc_writes: usize,
    /// File offset where the bitstream ends: the end of the walked range,
    /// or the first word outside a synchronized sequence that is neither a
    /// dummy, zero nor bus-width word.
    end: usize,
}

/// Does `data` start with the fixed `.bit` prefix and the design-name key?
pub(super) fn is_bit_header(data: &[u8]) -> bool {
    data.starts_with(&BIT_PREFIX) && data.get(BIT_PREFIX.len()) == Some(&KEY_DESIGN)
}

/// Weak recognition of headerless configuration data in either word order:
/// the exact synchronization sequence after the padding, then a valid
/// packet stream with at least one packet.
pub(super) fn detect_raw(data: &[u8]) -> Option<Layout> {
    [WordOrder::BigEndian, WordOrder::Swapped]
        .into_iter()
        .find_map(|order| {
            let start = raw_start(data, order)?;
            let walk = walk_packets(data, start.sync + WORD_SIZE, order).ok()?;
            (walk.packets > 0).then_some(order.raw_layout())
        })
}

/// Parse a `.bit` file: the header, then configuration data that holds the
/// sync word.
pub(super) fn parse_bit(data: &[u8]) -> Result<Container<'_>> {
    if !is_bit_header(data) {
        return Err(error("Invalid BIT header prefix at 0x0"));
    }
    let header = parse_header(data)?;
    let end = header
        .data_offset
        .checked_add(header.data_size)
        .ok_or_else(|| error("Invalid configuration data size: range overflow"))?;
    let Some(configuration) = data.get(header.data_offset..end) else {
        return Err(error(format!(
            "Truncated configuration data at 0x{:X}: {} B declared, {} B present",
            header.data_offset,
            header.data_size,
            data.len().saturating_sub(header.data_offset)
        )));
    };
    let sync = memmem::find(configuration, &SYNC_WORD.to_be_bytes())
        .map(|at| header.data_offset + at)
        .ok_or_else(|| {
            error(format!(
                "Missing sync word 0x{SYNC_WORD:08X} in the configuration data"
            ))
        })?;
    let pattern = memmem::find(&data[header.data_offset..sync], &bus_width_pattern_bytes())
        .map(|at| header.data_offset + at);

    let mut c = new_container(Layout::XilinxBit);
    push_header(&mut c, &header);
    push_synchronization(&mut c, pattern, sync);
    // Older families (Spartan-6 uses 16-bit packets) keep the header and
    // sync word but not the 7 series packet syntax, so a walk that fails is
    // reported rather than rejected.
    match walk_packets(&data[..end], sync + WORD_SIZE, WordOrder::BigEndian) {
        Ok(walk) => {
            push_packets(&mut c, &walk);
            if walk.end < end {
                c.notes.push(format!(
                    "Packet walk stopped at 0x{:X}, outside a synchronized sequence",
                    walk.end
                ));
            }
        }
        Err(e) => c.notes.push(format!(
            "Packet stream does not follow the 7 series packet syntax ({}); not walked further",
            error_message(e)
        )),
    }
    Ok(finish(c, data, header.data_offset, configuration, end))
}

/// Parse headerless configuration data in the word order of `layout`.
pub(super) fn parse_raw(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let order = match layout {
        Layout::XilinxRawSwapped => WordOrder::Swapped,
        _ => WordOrder::BigEndian,
    };
    let start = raw_start(data, order).ok_or_else(|| {
        error("Missing bus-width auto-detection pattern and sync word after the padding")
    })?;
    let walk = walk_packets(data, start.sync + WORD_SIZE, order)?;
    if walk.packets == 0 {
        return Err(error(format!(
            "Missing packets after the sync word at 0x{:X}",
            start.sync
        )));
    }

    let mut c = new_container(layout);
    c.notes.push(format!(
        "Headerless configuration data; {} B of 0xFF padding before the bus-width pattern",
        start.padding
    ));
    if order == WordOrder::Swapped {
        c.notes.push(
            "Every 32-bit word is byte-swapped, as the Zynq-7000 PCAP driver loads it".into(),
        );
    }
    push_synchronization(&mut c, Some(start.padding), start.sync);
    push_packets(&mut c, &walk);
    Ok(finish(c, data, 0, &data[..walk.end], walk.end))
}

/// Header keys from offset 13 until `e`: one key byte, a 16-bit big-endian
/// length and the field; for `e`, the 32-bit big-endian length of the
/// configuration data that follows. Every step advances, so the loop ends
/// within the file.
fn parse_header(data: &[u8]) -> Result<BitHeader> {
    let mut header = BitHeader::default();
    let mut pos = BIT_PREFIX.len();
    loop {
        let Some(&key) = data.get(pos) else {
            return Err(error(format!(
                "Truncated BIT header at 0x{pos:X}: missing data length key 'e'"
            )));
        };
        if key == KEY_DATA {
            let size = be_u32(data, pos + 1)?;
            header.data_offset = pos + 1 + 4;
            header.data_size = usize::try_from(size)
                .map_err(|_| error("Invalid configuration data size: exceeds the address space"))?;
            return Ok(header);
        }
        let len = usize::from(be_u16(data, pos + 1)?);
        let value = text(slice(data, pos + 3, len)?);
        let field = match key {
            KEY_DESIGN => Some(&mut header.design),
            KEY_PART => Some(&mut header.part),
            KEY_DATE => Some(&mut header.date),
            KEY_TIME => Some(&mut header.time),
            _ => None,
        };
        match field {
            Some(Some(_)) => {
                return Err(error(format!(
                    "Duplicate BIT header key '{}' at 0x{pos:X}",
                    char::from(key)
                )))
            }
            Some(slot) => *slot = Some(value),
            None => header.unknown_keys += 1,
        }
        pos += 3 + len;
    }
}

/// The synchronization sequence of a headerless bitstream: whole words of
/// `0xFF` padding from the start of the file, the bus-width pattern, up to
/// [`MAX_SYNC_DUMMY_WORDS`] dummy words, then the sync word. A Zynq boot
/// image is never one.
fn raw_start(data: &[u8], order: WordOrder) -> Option<RawStart> {
    let boot_image_id = data.get(BOOT_IMAGE_ID_OFFSET..BOOT_IMAGE_ID_OFFSET + BOOT_IMAGE_ID.len());
    if boot_image_id == Some(BOOT_IMAGE_ID.as_slice()) {
        return None;
    }
    let padding = data
        .iter()
        .take(MAX_RAW_PADDING + 1)
        .take_while(|&&b| b == 0xff)
        .count();
    if padding > MAX_RAW_PADDING || padding % WORD_SIZE != 0 {
        return None;
    }
    let is_word = |at: usize, expected: u32| order.word(data, at).is_ok_and(|w| w == expected);
    let pattern_matches = BUS_WIDTH_PATTERN
        .iter()
        .enumerate()
        .all(|(i, &expected)| is_word(padding + i * WORD_SIZE, expected));
    if !pattern_matches {
        return None;
    }
    let mut sync = padding + BUS_WIDTH_PATTERN.len() * WORD_SIZE;
    for _ in 0..MAX_SYNC_DUMMY_WORDS {
        if !is_word(sync, DUMMY_WORD) {
            break;
        }
        sync += WORD_SIZE;
    }
    is_word(sync, SYNC_WORD).then_some(RawStart { padding, sync })
}

/// Walk the packets that follow a sync word, from `start` to the end of
/// `data`. A dummy word ends a synchronized sequence (it is not a valid
/// packet header); outside a sequence, dummy, zero and bus-width words may
/// appear before the next sync word, and any other word ends the
/// bitstream. Trailing erased flash is accepted. Every step advances by at
/// least one word.
fn walk_packets(data: &[u8], start: usize, order: WordOrder) -> Result<PacketWalk> {
    let mut walk = PacketWalk {
        sequences: 1,
        end: data.len(),
        ..PacketWalk::default()
    };
    let mut pos = start;
    let mut synchronized = true;
    let mut after_type_1 = false;
    while pos < data.len() {
        let rest = &data[pos..];
        if rest.len() < WORD_SIZE {
            if is_padding(rest) {
                break;
            }
            if synchronized {
                return Err(error(format!("Truncated packet header at 0x{pos:X}")));
            }
            walk.end = pos;
            break;
        }
        let word = order.word(data, pos)?;
        if !synchronized {
            if word == SYNC_WORD {
                synchronized = true;
                after_type_1 = false;
                walk.sequences += 1;
            } else if !is_unsynchronized_word(word) {
                walk.end = pos;
                break;
            }
            pos += WORD_SIZE;
            continue;
        }
        pos = match word >> PACKET_TYPE_SHIFT {
            PACKET_TYPE_1 => {
                after_type_1 = true;
                type_1_packet(data, pos, word, order, &mut walk)?
            }
            PACKET_TYPE_2 if after_type_1 => {
                after_type_1 = false;
                type_2_packet(data, pos, word, &mut walk)?
            }
            PACKET_TYPE_2 => {
                return Err(error(format!(
                    "Invalid Type 2 packet at 0x{pos:X}: no Type 1 packet before it"
                )))
            }
            _ if word == DUMMY_WORD => {
                synchronized = false;
                after_type_1 = false;
                pos + WORD_SIZE
            }
            _ if is_padding(rest) => break,
            _ => {
                return Err(error(format!(
                    "Invalid packet header 0x{word:08X} at 0x{pos:X}"
                )))
            }
        };
    }
    Ok(walk)
}

/// A Type 1 packet at `pos`: records IDCODE and CRC register writes and
/// returns the offset after it. Only writes carry data words in the
/// stream; a read names the words the device returns.
fn type_1_packet(
    data: &[u8],
    pos: usize,
    header: u32,
    order: WordOrder,
    walk: &mut PacketWalk,
) -> Result<usize> {
    let opcode = packet_opcode(pos, header)?;
    walk.packets += 1;
    if opcode != OPCODE_WRITE {
        return Ok(pos + WORD_SIZE);
    }
    let register = (header >> REGISTER_SHIFT) & REGISTER_MASK;
    let words = header & TYPE_1_WORD_COUNT_MASK;
    let next = skip_packet(data, pos, words)?;
    if register == REGISTER_IDCODE && words == 1 && walk.idcode.is_none() {
        let offset = pos + WORD_SIZE;
        walk.idcode = Some(Idcode {
            value: order.word(data, offset)?,
            offset,
        });
    }
    if register == REGISTER_CRC {
        walk.crc_writes += 1;
    }
    Ok(next)
}

/// A Type 2 packet at `pos`, which continues the register of the Type 1
/// packet before it; returns the offset after it.
fn type_2_packet(data: &[u8], pos: usize, header: u32, walk: &mut PacketWalk) -> Result<usize> {
    let opcode = packet_opcode(pos, header)?;
    walk.packets += 1;
    if opcode != OPCODE_WRITE {
        return Ok(pos + WORD_SIZE);
    }
    skip_packet(data, pos, header & TYPE_2_WORD_COUNT_MASK)
}

/// The opcode of the packet header at `pos`; the reserved opcode is an
/// error.
fn packet_opcode(pos: usize, header: u32) -> Result<u32> {
    let opcode = (header >> OPCODE_SHIFT) & OPCODE_MASK;
    if opcode == OPCODE_RESERVED {
        return Err(error(format!(
            "Invalid packet opcode in header 0x{header:08X} at 0x{pos:X}"
        )));
    }
    Ok(opcode)
}

/// The offset after the packet header at `pos` and its `words` data words.
fn skip_packet(data: &[u8], pos: usize, words: u32) -> Result<usize> {
    let overflow = || error(format!("Invalid packet size at 0x{pos:X}: range overflow"));
    let size = usize::try_from(words)
        .ok()
        .and_then(|words| words.checked_mul(WORD_SIZE))
        .ok_or_else(overflow)?;
    let body = pos + WORD_SIZE;
    let end = body.checked_add(size).ok_or_else(overflow)?;
    if end > data.len() {
        return Err(error(format!(
            "Truncated packet at 0x{pos:X}: {words} words declared, {} B present",
            data.len().saturating_sub(body)
        )));
    }
    Ok(end)
}

/// Words that may appear between synchronized sequences.
fn is_unsynchronized_word(word: u32) -> bool {
    word == DUMMY_WORD || word == 0 || BUS_WIDTH_PATTERN.contains(&word)
}

/// The bus-width pattern as stored in big-endian word order.
fn bus_width_pattern_bytes() -> [u8; 8] {
    let [first, second] = BUS_WIDTH_PATTERN.map(u32::to_be_bytes);
    let mut bytes = [0u8; 8];
    bytes[..WORD_SIZE].copy_from_slice(&first);
    bytes[WORD_SIZE..].copy_from_slice(&second);
    bytes
}

/// The 7 series device whose IDCODE this is, ignoring the revision.
fn series_7_device(idcode: u32) -> Option<&'static str> {
    SERIES_7_IDCODES
        .iter()
        .find(|(code, _)| *code == idcode & IDCODE_REVISION_MASK)
        .map(|(_, name)| *name)
}

/// The message of a parse error from this family, for use inside a note.
fn error_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::BitstreamParseError { message } => message,
        other => other.to_string(),
    }
}

/// Notes and metadata for the header strings and the configuration data.
fn push_header(c: &mut Container<'_>, header: &BitHeader) {
    let fields = [
        ("bitstream_design_name", "Design name", &header.design),
        ("bitstream_part", "Part", &header.part),
        ("bitstream_date", "Date", &header.date),
        ("bitstream_time", "Time", &header.time),
    ];
    for (key, label, value) in fields {
        if let Some(value) = value {
            c.notes.push(format!("{label}: {value}"));
            c.push_metadata(key, label, value.as_str());
        }
    }
    if header.unknown_keys > 0 {
        c.notes.push(format!(
            "{} skipped",
            count(
                header.unknown_keys,
                "unknown BIT header key",
                "unknown BIT header keys"
            )
        ));
    }
    c.notes.push(format!(
        "Configuration data: {} B at 0x{:X}",
        header.data_size, header.data_offset
    ));
    c.push_metadata(
        "bitstream_data_offset",
        "Configuration data offset",
        header.data_offset as u64,
    );
    c.push_metadata(
        "bitstream_data_size",
        "Configuration data size (B)",
        header.data_size as u64,
    );
}

/// Notes and metadata for the bus-width pattern and the sync word (file
/// offsets).
fn push_synchronization(c: &mut Container<'_>, pattern: Option<usize>, sync: usize) {
    let [first, second] = BUS_WIDTH_PATTERN;
    let sync_text = format!("sync word 0x{SYNC_WORD:08X} at 0x{sync:X}");
    c.notes.push(match pattern {
        Some(at) => format!(
            "Bus-width auto-detection pattern 0x{first:08X} 0x{second:08X} at 0x{at:X}; {sync_text}"
        ),
        None => format!("No bus-width auto-detection pattern before the {sync_text}"),
    });
    if let Some(at) = pattern {
        c.push_metadata(
            "bitstream_bus_width_pattern_offset",
            "Bus-width pattern offset",
            at as u64,
        );
    }
    c.push_metadata("bitstream_sync_offset", "Sync word offset", sync as u64);
}

/// Notes and metadata for what the packet walk found.
fn push_packets(c: &mut Container<'_>, walk: &PacketWalk) {
    c.notes.push(format!(
        "Packet stream: {}; {}",
        count(walk.packets, "packet", "packets"),
        count(
            walk.sequences,
            "synchronized sequence",
            "synchronized sequences"
        )
    ));
    match walk.idcode {
        Some(idcode) => push_idcode(c, idcode, series_7_device(idcode.value), IDCODE_TABLE),
        None => c.notes.push("No IDCODE register write".into()),
    }
    c.notes.push(if walk.crc_writes > 0 {
        format!(
            "CRC register writes: {}; configuration CRC not verified (UG470 does not state the polynomial)",
            walk.crc_writes
        )
    } else {
        "No CRC register write; configuration CRC not checked".into()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    /// Two dummy words, the synchronization sequence, a NOOP, an IDCODE
    /// write, a Type 1 FDRI write header with no words and a Type 2 packet
    /// of two words, then a dummy word that ends the sequence.
    fn raw() -> Vec<u8> {
        words(&[
            DUMMY_WORD,
            DUMMY_WORD,
            0x0000_00bb,
            0x1122_0044,
            DUMMY_WORD,
            DUMMY_WORD,
            SYNC_WORD,
            0x2000_0000,
            0x3001_8001,
            0x0362_d093,
            0x3000_4000,
            0x5000_0002,
            0x1234_5678,
            0x9abc_def0,
            DUMMY_WORD,
        ])
    }

    #[test]
    fn raw_start_finds_the_sequence_after_whole_word_padding() {
        let data = raw();
        let start = raw_start(&data, WordOrder::BigEndian).expect("sequence");
        assert_eq!(
            start,
            RawStart {
                padding: 8,
                sync: 24
            }
        );
        assert!(raw_start(&data[1..], WordOrder::BigEndian).is_none());
        assert!(raw_start(&data, WordOrder::Swapped).is_none());
    }

    #[test]
    fn raw_start_accepts_any_bounded_number_of_dummy_words() {
        let none = words(&[0x0000_00bb, 0x1122_0044, SYNC_WORD]);
        assert_eq!(
            raw_start(&none, WordOrder::BigEndian),
            Some(RawStart {
                padding: 0,
                sync: 8
            })
        );
        let mut many = words(&BUS_WIDTH_PATTERN);
        many.extend(words(&[DUMMY_WORD; MAX_SYNC_DUMMY_WORDS + 1]));
        many.extend(words(&[SYNC_WORD]));
        assert!(raw_start(&many, WordOrder::BigEndian).is_none());
    }

    #[test]
    fn packet_walk_records_the_idcode_and_rejects_bad_headers() {
        let data = raw();
        let walk = walk_packets(&data, 28, WordOrder::BigEndian).expect("valid stream");
        assert_eq!(walk.packets, 4);
        assert_eq!(walk.end, data.len());
        let idcode = walk.idcode.expect("IDCODE write");
        assert_eq!((idcode.value, idcode.offset), (0x0362_d093, 36));
        assert_eq!(series_7_device(idcode.value | 0x1000_0000), Some("XC7A35T"));

        let mut reserved = data.clone();
        reserved[28..32].copy_from_slice(&0x3800_0000u32.to_be_bytes());
        assert!(walk_packets(&reserved, 28, WordOrder::BigEndian).is_err());
        let mut orphan = data.clone();
        orphan[28..32].copy_from_slice(&0x5000_0000u32.to_be_bytes());
        assert!(walk_packets(&orphan, 28, WordOrder::BigEndian).is_err());
        assert!(walk_packets(&data[..50], 28, WordOrder::BigEndian).is_err());
    }

    #[test]
    fn read_packets_carry_no_data_words() {
        // Type 1 read of FDRO with a word count, then a NOOP.
        let data = words(&[0x2800_6005, 0x2000_0000]);
        let walk = walk_packets(&data, 0, WordOrder::BigEndian).expect("valid stream");
        assert_eq!(walk.packets, 2);
    }

    #[test]
    fn a_word_outside_a_sequence_ends_the_bitstream() {
        let mut data = raw();
        let end = data.len();
        data.extend(words(&[0x1234_5678, 0x9abc_def0]));
        let walk = walk_packets(&data, 28, WordOrder::BigEndian).expect("valid stream");
        assert_eq!(walk.end, end);
    }

    #[test]
    fn zynq_boot_images_are_not_headerless_bitstreams() {
        let mut data = vec![0xff; 0x20];
        data.extend_from_slice(&SYNC_WORD.to_le_bytes());
        data.extend_from_slice(BOOT_IMAGE_ID);
        data.extend_from_slice(&raw()[8..]);
        assert!(raw_start(&data, WordOrder::BigEndian).is_none());
        assert!(raw_start(&data, WordOrder::Swapped).is_none());
    }
}
