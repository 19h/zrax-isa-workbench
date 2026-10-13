//! LZMS, the compression of Windows 8 and later that WIM solid resources and
//! `.esd` files use. Microsoft has not documented it; this decoder follows
//! wimlib v1.14.5 (`src/lzms_decompress.c`, `src/lzms_common.c`,
//! `include/wimlib/lzms_constants.h`, `include/wimlib/lzms_common.h` and,
//! for the adaptive Huffman codes, `make_canonical_huffman_code` in
//! `src/compress_common.c`), cross-checked with 7-Zip 26.03
//! `CPP/7zip/Compress/LzmsDecoder.cpp`.
//!
//! Wire format (wimlib's description at the head of `lzms_decompress.c`):
//! - The stream is read in 16-bit little-endian units from both ends. From
//!   the front, a binary range decoder (range `0xFFFFFFFF`, code the first
//!   32 bits; when the range falls below 2^16 both shift left by 16 and the
//!   code takes the next unit) decodes the decisions between literals, LZ
//!   matches and delta matches, explicit and repeated offsets. From the
//!   back, a bitstream (each unit's bits most significant first) holds
//!   Huffman-coded symbols and verbatim bits. Past either end, zeros.
//! - Each decision class keeps 2^n probability entries (n = 4 for literal
//!   or match, 5 for LZ or delta, 6 otherwise), selected by the last n bits
//!   decoded in that class. An entry's probability of a 0 is the number of
//!   0 bits among the last 64 it coded, out of 64, kept between 1 and 63;
//!   it starts as 48 (recent bits `0x0000000055555555`).
//! - Five adaptive Huffman codes: literals (256 symbols, rebuilt every 1024
//!   symbols), LZ offset slots and delta offset slots (as many as the
//!   output size needs, every 1024), length slots (54, every 512) and delta
//!   powers (8, every 512). Every symbol's frequency starts at 1; a code is
//!   rebuilt from the frequencies, which are then halved and incremented. A
//!   code is the canonical code that the classic Huffman construction gives
//!   when frequency ties are broken in favor of leaves, with the longest
//!   codes going to the least frequent symbols and, among equal
//!   frequencies, to the lower symbols (at most 15 bits).
//! - An LZ match copies `length` bytes from `offset` back; a delta match
//!   with power `p` and raw offset `r` sets each byte to
//!   `B[i - r * 2^p] + B[i - 2^p] - B[i - r * 2^p - 2^p]`. Each kind has a
//!   queue of three repeated offsets (four entries, the fourth for the
//!   delayed insertion: a used entry moves to the front only after the next
//!   item), starting `1, 2, 3, 4`.
//! - After decoding, an x86 filter turns the absolute targets of likely
//!   `CALL`, `LEA`, `MOV`, `LOCK ADD` and indirect `CALL` instructions back
//!   into relative ones (`lzms_x86_filter`).
//!
//! The format has no magic and is decoded only where a WIM names it.
//! [`decode`] produces exactly `limit` bytes, the chunk size that the
//! resource states.

use super::huffman::{BitSource, Huffman};
use super::*;

/// Codec name in error messages.
const CODEC: &str = "LZMS";

/// Longest Huffman code (`LZMS_MAX_CODEWORD_LENGTH`).
const MAX_CODE_LENGTH: u32 = 15;

/// Probabilities are numerators over 64 (`LZMS_PROBABILITY_BITS`).
const PROBABILITY_BITS: u32 = 6;
const PROBABILITY_DENOMINATOR: u32 = 1 << PROBABILITY_BITS;

/// A new probability entry: 48 zeros among its last 64 bits
/// (`LZMS_INITIAL_PROBABILITY`, `LZMS_INITIAL_RECENT_BITS`).
const INITIAL_ZEROS: u32 = 48;
const INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

/// Probability entries per decision class (`LZMS_NUM_*_PROBS`).
const MAIN_STATES: usize = 16;
const MATCH_STATES: usize = 32;
const LZ_STATES: usize = 64;
const LZ_REP_STATES: usize = 64;
const DELTA_STATES: usize = 64;
const DELTA_REP_STATES: usize = 64;

/// Decisions that choose among the three repeated offsets.
const REP_DECISIONS: usize = 2;

/// The range is renormalized when it falls below 2^16.
const RANGE_TOP: u32 = 0xffff_0000;

/// Alphabet sizes and rebuild intervals of the adaptive codes
/// (`LZMS_NUM_*_SYMS`, `LZMS_*_CODE_REBUILD_FREQ`).
const LITERAL_SYMBOLS: usize = 256;
const LENGTH_SYMBOLS: usize = 54;
const DELTA_POWER_SYMBOLS: usize = 8;
const MAX_OFFSET_SYMBOLS: usize = 799;
const LITERAL_REBUILD: u32 = 1024;
const LZ_OFFSET_REBUILD: u32 = 1024;
const LENGTH_REBUILD: u32 = 512;
const DELTA_OFFSET_REBUILD: u32 = 1024;
const DELTA_POWER_REBUILD: u32 = 512;

/// Extra bits of the offset slots as runs (bits, slots): the
/// `lzms_extra_offset_bits` table of wimlib (the `k_PosRuns` of 7-Zip).
/// Slot bases start at 1 and grow by `1 << bits` (`lzms_offset_slot_base`).
#[rustfmt::skip]
const OFFSET_EXTRA_BITS_RUNS: [(u8, usize); 21] = [
    (0, 8), (2, 9), (3, 7), (4, 10), (5, 15), (6, 15), (7, 20), (8, 20), (9, 30),
    (10, 33), (11, 40), (12, 42), (13, 45), (14, 60), (15, 73), (16, 80), (17, 85),
    (18, 95), (19, 105), (20, 6), (30, 1),
];

/// Extra bits of the length slots (`lzms_extra_length_bits`).
#[rustfmt::skip]
const LENGTH_EXTRA_BITS: [u8; LENGTH_SYMBOLS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6,
    7, 8, 9, 10, 16, 30,
];

const OFFSET_EXTRA_BITS: [u8; MAX_OFFSET_SYMBOLS] = expand_runs();
const OFFSET_BASE: [u32; MAX_OFFSET_SYMBOLS + 1] = slot_bases(&OFFSET_EXTRA_BITS);
const LENGTH_BASE: [u32; LENGTH_SYMBOLS + 1] = slot_bases(&LENGTH_EXTRA_BITS);

/// x86 filter parameters (`LZMS_X86_ID_WINDOW_SIZE`,
/// `LZMS_X86_MAX_TRANSLATION_OFFSET`): a translation needs a likely
/// instruction within 1023 bytes, and two references to one 16-bit target
/// within 65535 bytes make an instruction likely.
const X86_ID_WINDOW: i32 = 65_535;
const X86_MAX_TRANSLATION_OFFSET: i32 = 1023;

/// No filtering in data of 17 bytes or fewer, nor for an opcode in the last
/// 16 bytes; the first byte is never an opcode.
const X86_MIN_SIZE: usize = 17;
const X86_TAIL: usize = 16;

/// The opcodes the x86 filter looks at, and the bytes that follow them.
const OPCODE_REX_W: u8 = 0x48;
const OPCODE_REX_WR: u8 = 0x4c;
const OPCODE_CALL: u8 = 0xe8;
const OPCODE_JMP: u8 = 0xe9;
const OPCODE_LOCK: u8 = 0xf0;
const OPCODE_GROUP5: u8 = 0xff;
const MODRM_CALL_INDIRECT: u8 = 0x15;
const OPCODE_LEA: u8 = 0x8d;
const OPCODE_MOV: u8 = 0x8b;
const OPCODE_ADD_IMM8: u8 = 0x83;
const MODRM_RIP_RELATIVE: u8 = 0x05;

const fn expand_runs() -> [u8; MAX_OFFSET_SYMBOLS] {
    let mut bits = [0u8; MAX_OFFSET_SYMBOLS];
    let mut at = 0;
    let mut run = 0;
    while run < OFFSET_EXTRA_BITS_RUNS.len() {
        let (value, count) = OFFSET_EXTRA_BITS_RUNS[run];
        let mut i = 0;
        while i < count {
            bits[at] = value;
            at += 1;
            i += 1;
        }
        run += 1;
    }
    bits
}

const fn slot_bases<const N: usize, const M: usize>(bits: &[u8; N]) -> [u32; M] {
    let mut bases = [0u32; M];
    bases[0] = 1;
    let mut slot = 1;
    while slot < M {
        bases[slot] = bases[slot - 1] + (1 << bits[slot - 1]);
        slot += 1;
    }
    bases
}

/// The offset slots that a buffer of `size` bytes needs: one past the slot
/// of `size - 1` (`lzms_get_num_offset_slots`).
fn offset_slots(size: usize) -> usize {
    if size < 2 {
        return 0;
    }
    let largest = u32::try_from(size - 1).unwrap_or(u32::MAX);
    OFFSET_BASE[..MAX_OFFSET_SYMBOLS].partition_point(|&base| base <= largest)
}

/// A probability entry: the last 64 bits it coded, newest lowest, and how
/// many of them are 0.
#[derive(Debug, Clone, Copy)]
struct Probability {
    zeros: u32,
    recent: u64,
}

impl Probability {
    const INITIAL: Self = Self {
        zeros: INITIAL_ZEROS,
        recent: INITIAL_RECENT_BITS,
    };

    /// The chance out of 64 that the next bit is 0, kept within 1 to 63
    /// (`lzms_get_probability`).
    fn of_zero(self) -> u32 {
        self.zeros.clamp(1, PROBABILITY_DENOMINATOR - 1)
    }

    /// Account for a decoded bit (`lzms_update_probability_entry`).
    fn update(&mut self, bit: u32) {
        let oldest = u32::try_from(self.recent >> 63).expect("one bit");
        self.zeros = self.zeros + oldest - bit;
        self.recent = (self.recent << 1) | u64::from(bit);
    }
}

/// The forward range decoder.
struct RangeDecoder<'a> {
    data: &'a [u8],
    next: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let unit = |at: usize| u32::from(u16::from_le_bytes([data[at], data[at + 1]]));
        Self {
            data,
            next: 4,
            range: u32::MAX,
            code: unit(0) << 16 | unit(2),
        }
    }

    /// Decode one bit with probability entry `entry` (`lzms_decode_bit`).
    fn bit(&mut self, entry: &mut Probability) -> u32 {
        let probability = entry.of_zero();
        if self.range & RANGE_TOP == 0 {
            self.range <<= 16;
            self.code <<= 16;
            if let Some(unit) = self.data.get(self.next..self.next + 2) {
                self.code |= u32::from(u16::from_le_bytes([unit[0], unit[1]]));
                self.next += 2;
            }
        }
        let bound = (self.range >> PROBABILITY_BITS) * probability;
        if self.code < bound {
            self.range = bound;
            entry.update(0);
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            entry.update(1);
            1
        }
    }
}

/// A decision class: probability entries and the recent bits that select
/// one.
struct Decision {
    state: usize,
    entries: Vec<Probability>,
}

impl Decision {
    fn new(states: usize) -> Self {
        Self {
            state: 0,
            entries: vec![Probability::INITIAL; states],
        }
    }

    /// Whether the next decision of this class is 1.
    fn decode(&mut self, rc: &mut RangeDecoder<'_>) -> bool {
        let mask = self.entries.len() - 1;
        let entry = &mut self.entries[self.state];
        let bit = rc.bit(entry);
        self.state = ((self.state << 1) | bit as usize) & mask;
        bit == 1
    }
}

/// The backward bitstream: 16-bit units from the end of the input towards
/// its start, each most significant bit first; zeros past the start.
struct BackwardBits<'a> {
    data: &'a [u8],
    /// The unit before this offset is read next.
    next: usize,
    buffer: u64,
    count: u32,
}

impl<'a> BackwardBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            next: data.len(),
            buffer: 0,
            count: 0,
        }
    }

    /// The next `n` bits (0 to 30) as a number.
    fn read(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill(n);
        let value = u32::try_from(self.buffer >> (64 - n)).expect("at most 30 bits");
        self.buffer <<= n;
        self.count -= n;
        value
    }

    /// Buffer at least `n` bits (at most 32).
    fn fill(&mut self, n: u32) {
        while self.count < n {
            let unit = if self.next >= 2 {
                self.next -= 2;
                u16::from_le_bytes([self.data[self.next], self.data[self.next + 1]])
            } else {
                0
            };
            self.buffer |= u64::from(unit) << (48 - self.count);
            self.count += 16;
        }
    }
}

impl BitSource for BackwardBits<'_> {
    fn ensure(&mut self, n: u32) -> Result<()> {
        self.fill(n);
        Ok(())
    }

    fn peek(&self, n: u32) -> u32 {
        u32::try_from(self.buffer >> (64 - n)).expect("at most 16 bits")
    }

    fn remove(&mut self, n: u32) {
        self.buffer <<= n;
        self.count -= n;
    }
}

/// An adaptive Huffman code, rebuilt from its symbol frequencies every
/// `rebuild` symbols.
struct AdaptiveCode {
    name: &'static str,
    freqs: Vec<u32>,
    rebuild: u32,
    until_rebuild: u32,
    code: Option<Huffman>,
}

impl AdaptiveCode {
    fn new(name: &'static str, symbols: usize, rebuild: u32) -> Result<Self> {
        let mut code = Self {
            name,
            freqs: vec![1; symbols],
            rebuild,
            until_rebuild: rebuild,
            code: None,
        };
        code.build()?;
        Ok(code)
    }

    /// Build the code from the frequencies (`lzms_build_huffman_code`).
    fn build(&mut self) -> Result<()> {
        let lengths = canonical_lengths(&self.freqs, MAX_CODE_LENGTH);
        self.code = Huffman::build(&lengths, CODEC, self.name, MAX_CODE_LENGTH)?;
        self.until_rebuild = self.rebuild;
        Ok(())
    }

    /// Decode one symbol, counting it and rebuilding the code when due
    /// (`lzms_decode_huffman_symbol`, `lzms_rebuild_huffman_code`).
    fn decode(&mut self, bits: &mut BackwardBits<'_>) -> Result<usize> {
        let code = self.code.as_ref().ok_or_else(|| {
            error(format!(
                "Invalid LZMS stream: the {} code is empty",
                self.name
            ))
        })?;
        let symbol = usize::from(code.decode(bits)?);
        let symbols = self.freqs.len();
        let freq = self.freqs.get_mut(symbol).ok_or_else(|| {
            error(format!(
                "Invalid LZMS {} symbol {symbol} of {symbols}",
                self.name
            ))
        })?;
        *freq += 1;
        self.until_rebuild -= 1;
        if self.until_rebuild == 0 {
            self.build()?;
            for freq in &mut self.freqs {
                *freq = (*freq >> 1) + 1;
            }
        }
        Ok(symbol)
    }
}

/// A node of the Huffman tree under construction: its frequency and the
/// index of its parent among the internal nodes.
#[derive(Debug, Clone, Copy, Default)]
struct Node {
    freq: u64,
    parent: usize,
}

/// Code lengths of the canonical Huffman code for `freqs`, as wimlib's
/// `make_canonical_huffman_code` builds it: symbols sorted by frequency,
/// then by value; internal nodes made from the two least frequent nodes,
/// a leaf taken first when its frequency ties an internal node's; depths
/// counted per length, limited to `max_length`; lengths given longest
/// first in sorted order. A single used symbol and symbol 0 or 1 get
/// codes of 1 bit.
fn canonical_lengths(freqs: &[u32], max_length: u32) -> Vec<u8> {
    let mut lengths = vec![0u8; freqs.len().max(2)];
    let mut sorted: Vec<(u32, usize)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &freq)| freq > 0)
        .map(|(symbol, &freq)| (freq, symbol))
        .collect();
    sorted.sort_unstable();
    match sorted.len() {
        0 => return lengths,
        1 => {
            let used = sorted[0].1;
            // The second 1-bit code goes to symbol 0, or to 1 when 0 is used.
            let other = usize::from(used == 0);
            lengths[used] = 1;
            lengths[other] = 1;
            return lengths;
        }
        _ => {}
    }
    let leaves = sorted.len();
    // `build_tree`: internal nodes in creation order; the root is last.
    let mut nodes = vec![Node::default(); leaves - 1];
    let (mut leaf, mut first_open, mut made) = (0, 0, 0);
    let leaf_freq = |i: usize| u64::from(sorted[i].0);
    while made < leaves - 1 {
        let freq = if leaf + 1 < leaves
            && (first_open == made || leaf_freq(leaf + 1) <= nodes[first_open].freq)
        {
            leaf += 2;
            leaf_freq(leaf - 2) + leaf_freq(leaf - 1)
        } else if first_open + 2 <= made
            && (leaf >= leaves || nodes[first_open + 1].freq < leaf_freq(leaf))
        {
            nodes[first_open].parent = made;
            nodes[first_open + 1].parent = made;
            first_open += 2;
            nodes[first_open - 2].freq + nodes[first_open - 1].freq
        } else {
            nodes[first_open].parent = made;
            first_open += 1;
            leaf += 1;
            leaf_freq(leaf - 1) + nodes[first_open - 1].freq
        };
        nodes[made].freq = freq;
        made += 1;
    }
    // `compute_length_counts`: both children of the root start as leaves of
    // length 1; each internal node below the root turns a leaf at its
    // depth into two leaves one deeper.
    let max = max_length as usize;
    let mut counts = vec![0usize; max + 1];
    counts[1] = 2;
    let mut depths = vec![0usize; leaves - 1];
    for node in (0..leaves - 2).rev() {
        let depth = depths[nodes[node].parent] + 1;
        depths[node] = depth;
        let mut length = depth;
        if length >= max {
            length = max;
            loop {
                length -= 1;
                if counts[length] != 0 {
                    break;
                }
            }
        }
        counts[length] -= 1;
        counts[length + 1] += 2;
    }
    // `gen_codewords`: the longest lengths to the least frequent symbols.
    let mut next = 0;
    for length in (1..=max).rev() {
        for _ in 0..counts[length] {
            lengths[sorted[next].1] = u8::try_from(length).expect("at most 15");
            next += 1;
        }
    }
    lengths
}

/// The repeated offsets of LZ matches, and the (power, raw offset) pairs of
/// delta matches, each with a fourth entry for the delayed insertion.
struct Queues {
    lz: [u32; 4],
    delta: [DeltaSource; 4],
}

/// The source of a delta match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeltaSource {
    power: u32,
    raw_offset: u32,
}

/// What the previous item was, for the delayed queue insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    Literal,
    Lz,
    Delta,
}

/// The decoder's codes and decisions.
struct Decoder<'a> {
    rc: RangeDecoder<'a>,
    bits: BackwardBits<'a>,
    main: Decision,
    match_kind: Decision,
    lz: Decision,
    lz_rep: [Decision; REP_DECISIONS],
    delta: Decision,
    delta_rep: [Decision; REP_DECISIONS],
    literals: AdaptiveCode,
    lz_offsets: AdaptiveCode,
    lengths: AdaptiveCode,
    delta_offsets: AdaptiveCode,
    delta_powers: AdaptiveCode,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8], size: usize) -> Result<Self> {
        let slots = offset_slots(size);
        Ok(Self {
            rc: RangeDecoder::new(data),
            bits: BackwardBits::new(data),
            main: Decision::new(MAIN_STATES),
            match_kind: Decision::new(MATCH_STATES),
            lz: Decision::new(LZ_STATES),
            lz_rep: [Decision::new(LZ_REP_STATES), Decision::new(LZ_REP_STATES)],
            delta: Decision::new(DELTA_STATES),
            delta_rep: [
                Decision::new(DELTA_REP_STATES),
                Decision::new(DELTA_REP_STATES),
            ],
            literals: AdaptiveCode::new("literal", LITERAL_SYMBOLS, LITERAL_REBUILD)?,
            lz_offsets: AdaptiveCode::new("LZ offset", slots, LZ_OFFSET_REBUILD)?,
            lengths: AdaptiveCode::new("length", LENGTH_SYMBOLS, LENGTH_REBUILD)?,
            delta_offsets: AdaptiveCode::new("delta offset", slots, DELTA_OFFSET_REBUILD)?,
            delta_powers: AdaptiveCode::new(
                "delta power",
                DELTA_POWER_SYMBOLS,
                DELTA_POWER_REBUILD,
            )?,
        })
    }

    /// The repeat index 0-2 that the two repeat decisions of a class give.
    fn repeat_index(rc: &mut RangeDecoder<'_>, decisions: &mut [Decision; REP_DECISIONS]) -> usize {
        if !decisions[0].decode(rc) {
            0
        } else if !decisions[1].decode(rc) {
            1
        } else {
            2
        }
    }

    /// A slot's base plus its verbatim extra bits.
    fn slot_value(&mut self, slot: usize, bases: &[u32], extra: &[u8]) -> u32 {
        let bits = u32::from(extra[slot]);
        bases[slot].wrapping_add(self.bits.read(bits))
    }

    /// The offset of an LZ match, updating the queue
    /// (`lzms_decompress`: explicit offsets shift the queue; a repeated
    /// offset is taken from one entry further when the previous item was
    /// an LZ match, whose insertion is pending).
    fn lz_offset(&mut self, queues: &mut Queues, previous: Item) -> Result<u32> {
        let offset = if self.lz.decode(&mut self.rc) {
            let index = Self::repeat_index(&mut self.rc, &mut self.lz_rep)
                + usize::from(previous == Item::Lz);
            let offset = queues.lz[index];
            queues.lz.copy_within(0..index, 1);
            offset
        } else {
            let slot = self.lz_offsets.decode(&mut self.bits)?;
            let offset = self.slot_value(slot, &OFFSET_BASE, &OFFSET_EXTRA_BITS);
            queues.lz.copy_within(0..3, 1);
            offset
        };
        queues.lz[0] = offset;
        Ok(offset)
    }

    /// The source of a delta match, updating its queue as
    /// [`Self::lz_offset`] does.
    fn delta_source(&mut self, queues: &mut Queues, previous: Item) -> Result<DeltaSource> {
        let source = if self.delta.decode(&mut self.rc) {
            let index = Self::repeat_index(&mut self.rc, &mut self.delta_rep)
                + usize::from(previous == Item::Delta);
            let source = queues.delta[index];
            queues.delta.copy_within(0..index, 1);
            source
        } else {
            let power = u32::try_from(self.delta_powers.decode(&mut self.bits)?).expect("below 8");
            let slot = self.delta_offsets.decode(&mut self.bits)?;
            let raw_offset = self.slot_value(slot, &OFFSET_BASE, &OFFSET_EXTRA_BITS);
            queues.delta.copy_within(0..3, 1);
            DeltaSource { power, raw_offset }
        };
        queues.delta[0] = source;
        Ok(source)
    }

    /// A match length.
    fn length(&mut self) -> Result<usize> {
        let slot = self.lengths.decode(&mut self.bits)?;
        let length = self.slot_value(slot, &LENGTH_BASE, &LENGTH_EXTRA_BITS);
        Ok(usize::try_from(length).unwrap_or(usize::MAX))
    }
}

/// Copy an LZ match of `length` bytes from `offset` back.
fn copy_lz(out: &mut Vec<u8>, offset: u32, length: usize, limit: usize) -> Result<()> {
    let offset = offset as usize;
    if offset == 0 || offset > out.len() || length > limit - out.len() {
        return Err(error(format!(
            "Invalid LZMS match of {length} B from {offset} B back at output 0x{:X}",
            out.len()
        )));
    }
    let start = out.len() - offset;
    for i in 0..length {
        let byte = out[start + i];
        out.push(byte);
    }
    Ok(())
}

/// Copy a delta match: each byte is its source plus the difference that
/// the bytes one span before them have.
fn copy_delta(out: &mut Vec<u8>, source: DeltaSource, length: usize, limit: usize) -> Result<()> {
    let span = 1u64 << source.power;
    let offset = u64::from(source.raw_offset) << source.power;
    if offset == 0 || offset + span > out.len() as u64 || length > limit - out.len() {
        return Err(error(format!(
            "Invalid LZMS delta match of {length} B (raw offset {}, power {}) at output 0x{:X}",
            source.raw_offset,
            source.power,
            out.len()
        )));
    }
    let span = usize::try_from(span).expect("at most 128");
    let offset = usize::try_from(offset).expect("below the output size");
    for _ in 0..length {
        let at = out.len();
        let byte = out[at - offset]
            .wrapping_add(out[at - span])
            .wrapping_sub(out[at - offset - span]);
        out.push(byte);
    }
    Ok(())
}

/// Decode exactly `limit` bytes of an LZMS stream.
///
/// # Errors
///
/// An odd-sized stream or one shorter than 4 bytes, an invalid symbol, a
/// match that reaches before the output or past `limit`, or output beyond
/// [`MAX_PAYLOAD`].
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    if limit == 0 {
        return Ok(Decoded {
            data: Vec::new(),
            consumed: Some(0),
            check: None,
        });
    }
    if data.len() % 2 != 0 || data.len() < 4 {
        return Err(error(format!(
            "Invalid LZMS stream of {} B: an even size of at least 4 B is needed",
            data.len()
        )));
    }
    let mut decoder = Decoder::new(data, limit)?;
    let mut queues = Queues {
        lz: [1, 2, 3, 4],
        delta: [1, 2, 3, 4].map(|raw_offset| DeltaSource {
            power: 0,
            raw_offset,
        }),
    };
    let mut previous = Item::Literal;
    let mut out = Vec::new();
    while out.len() < limit {
        if !decoder.main.decode(&mut decoder.rc) {
            let literal = decoder.literals.decode(&mut decoder.bits)?;
            out.push(u8::try_from(literal).expect("256 literal symbols"));
            previous = Item::Literal;
        } else if !decoder.match_kind.decode(&mut decoder.rc) {
            let offset = decoder.lz_offset(&mut queues, previous)?;
            previous = Item::Lz;
            let length = decoder.length()?;
            copy_lz(&mut out, offset, length, limit)?;
        } else {
            let source = decoder.delta_source(&mut queues, previous)?;
            previous = Item::Delta;
            let length = decoder.length()?;
            copy_delta(&mut out, source, length, limit)?;
        }
    }
    undo_x86_translation(&mut out);
    Ok(Decoded {
        data: out,
        consumed: None,
        check: None,
    })
}

/// Undo the x86 filter (`lzms_x86_filter` with `undo`): find likely
/// relative-addressing instructions and turn their 32-bit targets back from
/// absolute to relative while a likely instruction was seen within 1023
/// bytes (511 for `CALL`).
fn undo_x86_translation(data: &mut [u8]) {
    if data.len() <= X86_MIN_SIZE {
        return;
    }
    let tail = data.len() - X86_TAIL;
    let mut last_target_usages = vec![-X86_ID_WINDOW - 1; 1 << 16];
    let mut last_x86_position = -X86_MAX_TRANSLATION_OFFSET - 1;
    let mut p = 1;
    loop {
        while p < tail && !is_potential_opcode(data[p]) {
            p += 1;
        }
        if p >= tail {
            break;
        }
        p = translate(data, p, &mut last_x86_position, &mut last_target_usages);
    }
}

fn is_potential_opcode(byte: u8) -> bool {
    matches!(
        byte,
        OPCODE_REX_W | OPCODE_REX_WR | OPCODE_CALL | OPCODE_JMP | OPCODE_LOCK | OPCODE_GROUP5
    )
}

/// The length of the opcode at `p` whose 32-bit operand may be translated,
/// and the farthest distance from the last likely instruction at which it
/// is; `None` when the bytes are not such an instruction
/// (`translate_if_needed`).
fn translated_opcode(data: &[u8], p: usize) -> Option<TranslatedOpcode> {
    let full = TranslatedOpcode {
        size: 0,
        max_offset: X86_MAX_TRANSLATION_OFFSET,
    };
    match data[p] {
        OPCODE_GROUP5 if data[p + 1] == MODRM_CALL_INDIRECT => {
            Some(TranslatedOpcode { size: 2, ..full })
        }
        OPCODE_LOCK if data[p + 1] == OPCODE_ADD_IMM8 && data[p + 2] == MODRM_RIP_RELATIVE => {
            Some(TranslatedOpcode { size: 3, ..full })
        }
        // A REX prefix and an opcode whose ModR/M R/M field is 5 (the
        // format tests only R/M, not Mod).
        prefix @ (OPCODE_REX_W | OPCODE_REX_WR) if data[p + 2] & 0x07 == MODRM_RIP_RELATIVE => {
            let lea = data[p + 1] == OPCODE_LEA;
            let mov = data[p + 1] == OPCODE_MOV && prefix & 0x04 == 0 && data[p + 2] & 0xf0 == 0;
            (lea || mov).then_some(TranslatedOpcode { size: 3, ..full })
        }
        OPCODE_CALL => Some(TranslatedOpcode {
            size: 1,
            max_offset: X86_MAX_TRANSLATION_OFFSET >> 1,
        }),
        _ => None,
    }
}

/// An instruction whose operand the x86 filter translates.
struct TranslatedOpcode {
    size: usize,
    max_offset: i32,
}

/// Handle the potential opcode at `p`, returning where scanning resumes.
fn translate(
    data: &mut [u8],
    p: usize,
    last_x86_position: &mut i32,
    last_target_usages: &mut [i32],
) -> usize {
    if data[p] == OPCODE_JMP {
        // Relative jumps are explicitly not translated: skip the operand.
        return p + 5;
    }
    let Some(opcode) = translated_opcode(data, p) else {
        return p + 1;
    };
    let position = i32::try_from(p).expect("LZMS chunks are below 2 GiB");
    let operand = p + opcode.size;
    if position - *last_x86_position <= opcode.max_offset {
        let bytes: [u8; 4] = data[operand..operand + 4].try_into().expect("4 bytes");
        let offset = u32::try_from(p).expect("LZMS chunks are below 2 GiB");
        let relative = u32::from_le_bytes(bytes).wrapping_sub(offset);
        data[operand..operand + 4].copy_from_slice(&relative.to_le_bytes());
    }
    // The target's low 16 bits: the absolute operand's low half plus the
    // position, modulo 2^16.
    let low = u16::from_le_bytes([data[operand], data[operand + 1]]);
    let target = (usize::from(low) + p) & usize::from(u16::MAX);
    let end = position + i32::try_from(opcode.size).expect("at most 3") + 3;
    if end - last_target_usages[target] <= X86_ID_WINDOW {
        *last_x86_position = end;
    }
    last_target_usages[target] = end;
    operand + 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_tables_match_wimlib() {
        assert_eq!(OFFSET_BASE[9], 0x0d);
        assert_eq!(OFFSET_BASE[100], 0x0000_20a5);
        assert_eq!(OFFSET_BASE[798], 0x065b_e4a5);
        assert_eq!(OFFSET_BASE[799], 0x465b_e4a5);
        assert_eq!(LENGTH_BASE[27], 0x1d);
        assert_eq!(LENGTH_BASE[53], 0x0001_08ab);
        assert_eq!(LENGTH_BASE[54], 0x4001_08ab);
        assert_eq!(offset_slots(0), 0);
        assert_eq!(offset_slots(2), 1);
        assert_eq!(offset_slots(9), 8);
        assert_eq!(offset_slots(10), 9);
        assert_eq!(offset_slots(32 << 10), 142);
        assert_eq!(offset_slots(64 << 10), 171);
        assert_eq!(offset_slots(64 << 20), 729);
        assert_eq!(offset_slots(1 << 30), 799);
    }

    #[test]
    fn probabilities_follow_the_last_64_bits() {
        let mut entry = Probability::INITIAL;
        assert_eq!(entry.of_zero(), 48);
        for _ in 0..64 {
            entry.update(0);
        }
        assert_eq!(entry.zeros, 64);
        assert_eq!(entry.of_zero(), 63);
        for _ in 0..64 {
            entry.update(1);
        }
        assert_eq!(entry.zeros, 0);
        assert_eq!(entry.of_zero(), 1);
    }

    #[test]
    fn canonical_lengths_break_ties_towards_leaves() {
        // Equal frequencies: a complete code, longest codes to the lowest
        // symbols.
        assert_eq!(canonical_lengths(&[1, 1, 1], 15), [2, 2, 1]);
        assert_eq!(canonical_lengths(&[1; 4], 15), [2; 4]);
        // Leaves 1, 1, 2, 2: the first internal node (2) ties the next
        // leaves and the leaves are joined first, giving lengths 2, 2, 2, 2
        // rather than 3, 3, 2, 1.
        assert_eq!(canonical_lengths(&[1, 1, 2, 2], 15), [2, 2, 2, 2]);
        // Five symbols of frequency 1 and one of 5: lengths 4, 4, 3, 3, 3
        // and 1, the longest to the lowest of the least frequent symbols.
        assert_eq!(
            canonical_lengths(&[5, 1, 1, 1, 1, 1], 15),
            [1, 4, 4, 3, 3, 3]
        );
        assert_eq!(canonical_lengths(&[0, 7], 15), [1, 1]);
        assert_eq!(canonical_lengths(&[7], 15), [1, 1]);
        for size in [2usize, 8, 54, 256, 799] {
            let lengths = canonical_lengths(&vec![1; size], 15);
            let kraft: u64 = lengths.iter().map(|&l| 1u64 << (15 - l)).sum();
            assert_eq!(kraft, 1 << 15, "{size} symbols fill the code space");
        }
    }

    #[test]
    fn short_and_odd_streams_are_invalid() {
        assert!(decode(&[0; 3], 1).is_err());
        assert!(decode(&[0; 5], 1).is_err());
        assert_eq!(decode(&[], 0).unwrap().data, b"");
    }

    #[test]
    fn x86_translation_needs_a_likely_instruction_nearby() {
        // Two CALLs to the target 0x1000 a few bytes apart, before any
        // likely instruction, so stored relative: the second makes the
        // region likely x86 code, so the third, stored absolute, is turned
        // back into the relative 0x1000 - 24. A CALL in the last 16 bytes
        // stays.
        let mut data = vec![0u8; 64];
        for (at, operand) in [
            (8usize, 0x1000u32 - 8),
            (16, 0x1000 - 16),
            (24, 0x1000),
            (50, 0x1000),
        ] {
            data[at] = OPCODE_CALL;
            data[at + 1..at + 5].copy_from_slice(&operand.to_le_bytes());
        }
        let mut undone = data.clone();
        undo_x86_translation(&mut undone);
        assert_eq!(&undone[..25], &data[..25]);
        assert_eq!(&undone[25..29], &(0x1000u32 - 24).to_le_bytes());
        assert_eq!(&undone[29..], &data[29..]);
    }

    #[test]
    fn noise_never_panics() {
        let mut x: u32 = 0x2545_f491;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x.to_le_bytes()[1]
            })
            .collect();
        for end in [4, 6, 64, 1000, noise.len()] {
            for limit in [1, 100, 70_000] {
                let _ = decode(&noise[..end], limit);
            }
        }
    }
}
