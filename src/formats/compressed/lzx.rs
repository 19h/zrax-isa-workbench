//! LZX as Microsoft cabinet folders store it (`typeCompress` 3).
//!
//! Sources: the Cabinet SDK's "Microsoft LZX Data Compression Format"
//! (Microsoft Learn `bb267310(v=vs.85)`, 1997), corrected by [MS-PATCH]
//! "LZX DELTA Compression and Decompression" v20250819 sections 2.1-2.7
//! (LZX DELTA extends this format) and by libmspack `mspack/lzxd.c` at
//! commit `55d501976171397ccd5d5a7a1ca7da065b1d9a06`, whose header lists
//! the SDK's errata. Where the documents leave a case open, libmspack's
//! behavior is followed, since cabextract decodes real cabinets with it.
//!
//! Wire format:
//! - The bitstream is a sequence of 16-bit little-endian words whose bits
//!   are read most significant first. Past the end of the input, libmspack
//!   supplies one word of zeros (`read_input`), so the last code can be
//!   peeked at with 16 bits; reading beyond that is an error.
//! - Once per stream: one bit, and if it is set a 32-bit E8 translation
//!   size read as two 16-bit fields, high half first.
//! - Blocks: a 3-bit type (1 verbatim, 2 aligned offset, 3 uncompressed)
//!   and a 24-bit uncompressed size. An aligned offset block starts with
//!   eight 3-bit aligned-tree lengths; verbatim and aligned blocks then
//!   code the main tree (256 literals plus 8 symbols per position slot) in
//!   two parts and the 249-symbol length tree, each part as deltas from the
//!   previous block's lengths through a 20-symbol pretree. An uncompressed
//!   block drops to the next 16-bit boundary (a whole word when already
//!   aligned), stores the three repeated offsets as little-endian 32-bit
//!   values and then its bytes; after an odd-sized one a pad byte precedes
//!   the next block header.
//! - Output comes in 32 KiB frames, the last one shorter. After each frame
//!   the bitstream realigns to a 16-bit boundary, and no match may cross a
//!   frame or block end.
//! - When the translation size is not zero, every frame of the first
//!   32,768 that is longer than 10 bytes has its x86 `CALL` targets turned
//!   back from absolute to relative; the window keeps the untranslated
//!   bytes that later matches copy.
//!
//! The format has no magic and is decoded only where a cabinet folder
//! names it, with the window size (2^15 to 2^21 bytes) its `typeCompress`
//! field gives. [`decode`] produces exactly `limit` bytes: the cabinet
//! states its folder's size, and only the folder's last frame is short.

use super::*;

/// Cabinet LZX windows are 2^15 to 2^21 bytes (SDK "Window Size";
/// libmspack `lzxd_init`).
pub(super) const MIN_WINDOW_BITS: u8 = 15;
pub(super) const MAX_WINDOW_BITS: u8 = 21;

/// Output frame size (SDK "Cab Block Size"; [MS-PATCH] 2.2.1).
const FRAME_SIZE: usize = 32 << 10;

/// E8 translation applies to the first 32,768 frames, 1 GiB of output
/// ([MS-PATCH] 2.2.2).
const E8_FRAMES: usize = 32_768;

/// E8 translation skips the last 10 bytes of a frame, and frames of 10
/// bytes or fewer (libmspack `lzxd_decompress`).
const E8_TAIL: usize = 10;

/// The x86 `CALL rel32` opcode that E8 translation rewrites.
const E8_OPCODE: u8 = 0xe8;

/// Block types ([MS-PATCH] 2.3.1.1).
const BLOCK_VERBATIM: u32 = 1;
const BLOCK_ALIGNED: u32 = 2;
const BLOCK_UNCOMPRESSED: u32 = 3;

/// Field widths of the block header ([MS-PATCH] 2.3.1).
const BLOCK_TYPE_BITS: u32 = 3;
const BLOCK_SIZE_HIGH_BITS: u32 = 16;
const BLOCK_SIZE_LOW_BITS: u32 = 8;

/// Literal symbols of the main tree.
const NUM_CHARS: usize = 256;

/// Shortest match ([MS-PATCH] 2.1.5).
const MIN_MATCH: usize = 2;

/// Length headers 0-6 code lengths 2-8; header 7 adds a length-tree
/// symbol (libmspack `LZX_NUM_PRIMARY_LENGTHS`, which the SDK omits).
const NUM_PRIMARY_LENGTHS: usize = 7;

/// Elements of the length tree that the stream codes.
const NUM_SECONDARY_LENGTHS: usize = 249;

/// Main-tree symbols per position slot: one per length header.
const SYMBOLS_PER_SLOT: usize = 8;

/// The pretree: 20 symbols with 4-bit lengths ([MS-PATCH] 2.5).
const PRETREE_SYMBOLS: usize = 20;
const PRETREE_LENGTH_BITS: u32 = 4;

/// The aligned offset tree: 8 symbols with 3-bit lengths ([MS-PATCH]
/// 2.3.2.3), coding the low 3 bits of a footer.
const ALIGNED_SYMBOLS: usize = 8;
const ALIGNED_LENGTH_BITS: u32 = 3;
const ALIGNED_BITS: u32 = 3;

/// Pretree codes 17-19 are runs ([MS-PATCH] 2.5): 4 + read(4) zeros,
/// 20 + read(5) zeros, or 4 + read(1) copies of one delta-coded length.
const PRETREE_ZEROS: u16 = 17;
const PRETREE_MORE_ZEROS: u16 = 18;
const PRETREE_SAME: u16 = 19;
const ZEROS_BITS: u32 = 4;
const ZEROS_BASE: usize = 4;
const MORE_ZEROS_BITS: u32 = 5;
const MORE_ZEROS_BASE: usize = 20;
const SAME_BITS: u32 = 1;
const SAME_BASE: usize = 4;

/// Code lengths are deltas modulo 17 ([MS-PATCH] 2.5).
const LENGTH_MODULUS: u16 = 17;

/// Longest Huffman code ([MS-PATCH] 2.5).
const MAX_CODE_LENGTH: u32 = 16;

/// Codes up to this length are decoded by one table lookup.
const TABLE_BITS: u32 = 10;

/// libmspack builds its main and length tables over more symbols than a
/// cabinet stream codes: the main tree over the 290 position slots of the
/// largest LZX DELTA window (`LZX_MAINTREE_MAXSYMBOLS`) and the length tree
/// over 250 symbols (`LZX_LENGTH_MAXSYMBOLS`). The extra entries are zero
/// unless a run code writes past a tree's end into them.
const POSITION_SLOT_LIMIT: usize = 290;
const MAIN_TABLE_SYMBOLS: usize = NUM_CHARS + POSITION_SLOT_LIMIT * SYMBOLS_PER_SLOT;
const LENGTH_TABLE_SYMBOLS: usize = NUM_SECONDARY_LENGTHS + 1;

/// Room for run codes that run past a tree's end (`LZX_LENTABLE_SAFETY`):
/// a run starts before the end and writes at most 51 elements.
const LENGTH_SAFETY: usize = 64;

/// Position slots per window size from 2^15 to 2^21 (libmspack
/// `position_slots`; [MS-PATCH] 2.1.6).
const POSITION_SLOTS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];

/// Footer bits of each position slot below 36; every later slot has 17
/// (libmspack `extra_bits`; [MS-PATCH] 2.6.2).
#[rustfmt::skip]
const EXTRA_BITS: [u8; 36] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
];
const MAX_EXTRA_BITS: u8 = 17;

/// Base formatted offset of each position slot: each slot starts where the
/// previous one's footer range ends.
const POSITION_BASE: [u32; POSITION_SLOT_LIMIT] = position_bases();

/// The repeated offsets R0, R1 and R2 start as 1 ([MS-PATCH] 2.1.4).
const INITIAL_REPEATED: [u32; 3] = [1, 1, 1];

/// Zero bytes the bit reader supplies after the end of the input (one
/// 16-bit word, libmspack `read_input`).
const END_PADDING: usize = 2;

const fn extra_bits(slot: usize) -> u8 {
    if slot < EXTRA_BITS.len() {
        EXTRA_BITS[slot]
    } else {
        MAX_EXTRA_BITS
    }
}

const fn position_bases() -> [u32; POSITION_SLOT_LIMIT] {
    let mut bases = [0u32; POSITION_SLOT_LIMIT];
    let mut slot = 1;
    while slot < POSITION_SLOT_LIMIT {
        bases[slot] = bases[slot - 1] + (1 << extra_bits(slot - 1));
        slot += 1;
    }
    bases
}

fn truncated(pos: usize) -> ClassifierError {
    error(format!("Truncated LZX stream at 0x{pos:X}"))
}

/// The bitstream reader.
struct Bits<'a> {
    data: &'a [u8],
    /// Next unread byte; at most [`END_PADDING`] past the input's end.
    pos: usize,
    /// Buffered bits, most significant first.
    buffer: u32,
    /// Number of buffered bits.
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buffer: 0,
            count: 0,
        }
    }

    /// The next byte of the byte stream, or a padding zero.
    fn byte(&mut self) -> Result<u8> {
        let byte = match self.data.get(self.pos) {
            Some(&byte) => byte,
            None if self.pos < self.data.len() + END_PADDING => 0,
            None => return Err(truncated(self.pos)),
        };
        self.pos += 1;
        Ok(byte)
    }

    /// Buffer at least `n` bits (at most 17), a 16-bit word at a time.
    fn ensure(&mut self, n: u32) -> Result<()> {
        while self.count < n {
            let low = self.byte()?;
            let high = self.byte()?;
            let word = u32::from(u16::from_le_bytes([low, high]));
            self.buffer |= word << (16 - self.count);
            self.count += 16;
        }
        Ok(())
    }

    /// The next `n` bits (1 to 16) without consuming them; call
    /// [`Self::ensure`] first.
    fn peek(&self, n: u32) -> u32 {
        self.buffer >> (32 - n)
    }

    fn remove(&mut self, n: u32) {
        self.buffer = if n >= 32 { 0 } else { self.buffer << n };
        self.count -= n;
    }

    /// The next `n` bits (0 to 17) as a number.
    fn read(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure(n)?;
        let value = self.peek(n);
        self.remove(n);
        Ok(value)
    }

    /// Drop the rest of the current 16-bit word, as at every frame end.
    fn align_frame(&mut self) -> Result<()> {
        if self.count > 0 {
            self.ensure(16)?;
        }
        self.remove(self.count & 15);
        Ok(())
    }

    /// Switch to the byte stream of an uncompressed block: drop 1-16 bits,
    /// a whole word when the stream is already aligned.
    fn start_bytes(&mut self) -> Result<()> {
        if self.count == 0 {
            self.ensure(16)?;
        }
        self.buffer = 0;
        self.count = 0;
        Ok(())
    }

    /// Copy `out.len()` bytes of the byte stream into `out`.
    fn copy_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(out.len())
            .filter(|&end| end <= self.data.len() + END_PADDING)
            .ok_or_else(|| truncated(self.pos))?;
        let available = self.data.len().min(end).saturating_sub(self.pos);
        out[..available].copy_from_slice(&self.data[self.pos..self.pos + available]);
        out[available..].fill(0);
        self.pos = end;
        Ok(())
    }

    /// A little-endian 32-bit value from the byte stream.
    fn le_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.copy_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Input bytes consumed, without a buffered word that was not used.
    fn consumed(&self) -> usize {
        let buffered = usize::try_from(self.count / 8).unwrap_or(0);
        self.pos.saturating_sub(buffered).min(self.data.len())
    }
}

/// One entry of a decoding table.
#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    symbol: u16,
    /// Code length; 0 when the code is longer than [`TABLE_BITS`].
    length: u8,
}

/// A canonical Huffman code: codes are assigned shortest first and, within
/// a length, by increasing symbol, read most significant bit first.
struct Huffman {
    /// Indexed by the next [`TABLE_BITS`] bits.
    table: Vec<Entry>,
    /// Per code length: the first code, the number of codes and the index
    /// of the first symbol in `sorted`.
    first_code: [u32; 17],
    count: [u32; 17],
    first_index: [usize; 17],
    /// Symbols ordered by code length, then by value.
    sorted: Vec<u16>,
}

impl Huffman {
    /// The code with these lengths (0 means unused). `None` when every
    /// length is zero. A code that is incomplete or over-subscribed is an
    /// error, as in libmspack's `make_decode_table`.
    fn build(lengths: &[u8], tree: &str) -> Result<Option<Self>> {
        let mut count = [0u32; 17];
        for &length in lengths {
            *count.get_mut(usize::from(length)).ok_or_else(|| {
                error(format!("Invalid LZX {tree} tree: code length {length}"))
            })? += 1;
        }
        count[0] = 0;
        if count.iter().all(|&n| n == 0) {
            return Ok(None);
        }
        // Kraft: the codes must fill the code space exactly.
        let mut left: i64 = 1;
        for &n in &count[1..] {
            left = left * 2 - i64::from(n);
            if left < 0 {
                return Err(error(format!(
                    "Invalid LZX {tree} tree: over-subscribed code"
                )));
            }
        }
        if left != 0 {
            return Err(error(format!("Invalid LZX {tree} tree: incomplete code")));
        }
        let mut first_code = [0u32; 17];
        let mut first_index = [0usize; 17];
        let mut code = 0u32;
        let mut index = 0usize;
        for length in 1..17 {
            code = (code + count[length - 1]) << 1;
            first_code[length] = code;
            first_index[length] = index;
            index += count[length] as usize;
        }
        let mut sorted = vec![0u16; index];
        let mut next = first_index;
        for (symbol, &length) in lengths.iter().enumerate() {
            if length > 0 {
                let slot = &mut next[usize::from(length)];
                sorted[*slot] =
                    u16::try_from(symbol).expect("tables have fewer than 65536 symbols");
                *slot += 1;
            }
        }
        let mut table = vec![Entry::default(); 1 << TABLE_BITS];
        for length in 1..=TABLE_BITS as usize {
            let start = first_index[length];
            for (i, &symbol) in sorted[start..start + count[length] as usize]
                .iter()
                .enumerate()
            {
                let code = first_code[length] as usize + i;
                let shift = TABLE_BITS as usize - length;
                let entry = Entry {
                    symbol,
                    length: u8::try_from(length).expect("lengths are at most 16"),
                };
                table[code << shift..(code + 1) << shift].fill(entry);
            }
        }
        Ok(Some(Self {
            table,
            first_code,
            count,
            first_index,
            sorted,
        }))
    }

    /// Decode one symbol.
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        bits.ensure(MAX_CODE_LENGTH)?;
        let next = bits.peek(MAX_CODE_LENGTH);
        let entry = self.table[(next >> (MAX_CODE_LENGTH - TABLE_BITS)) as usize];
        if entry.length > 0 {
            bits.remove(u32::from(entry.length));
            return Ok(entry.symbol);
        }
        for length in TABLE_BITS + 1..=MAX_CODE_LENGTH {
            let code = next >> (MAX_CODE_LENGTH - length);
            let at = length as usize;
            let index = code.wrapping_sub(self.first_code[at]);
            if code >= self.first_code[at] && index < self.count[at] {
                bits.remove(length);
                return Ok(self.sorted[self.first_index[at] + index as usize]);
            }
        }
        // Unreachable for a complete code, which `build` requires.
        Err(error("Invalid LZX code"))
    }
}

/// The kind of the current block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    /// No block read yet.
    None,
    Verbatim,
    Aligned,
    Uncompressed,
}

/// The decoder's state across blocks and frames.
struct Decoder<'a> {
    bits: Bits<'a>,
    /// The sliding window, a power of two in size; matches copy from it.
    window: Vec<u8>,
    /// Write position in the window.
    window_pos: usize,
    /// Bytes decoded so far, which bounds match offsets.
    decoded: usize,
    /// Position slots of this window size.
    position_slots: usize,
    /// Code lengths, kept between blocks for the delta coding, with room
    /// for runs past a tree's end.
    main_lengths: Vec<u8>,
    length_lengths: Vec<u8>,
    main: Option<Huffman>,
    length: Option<Huffman>,
    aligned: Option<Huffman>,
    /// R0, R1, R2.
    repeated: [u32; 3],
    kind: BlockKind,
    /// The current block's size and the bytes of it still to decode.
    block_size: usize,
    block_remaining: usize,
    /// The E8 translation size from the stream header; 0 when disabled.
    e8_file_size: i32,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8], window_bits: u8) -> Self {
        let slots = POSITION_SLOTS[usize::from(window_bits - MIN_WINDOW_BITS)];
        Self {
            bits: Bits::new(data),
            window: vec![0; 1 << window_bits],
            window_pos: 0,
            decoded: 0,
            position_slots: slots,
            main_lengths: vec![0; MAIN_TABLE_SYMBOLS + LENGTH_SAFETY],
            length_lengths: vec![0; LENGTH_TABLE_SYMBOLS + LENGTH_SAFETY],
            main: None,
            length: None,
            aligned: None,
            repeated: INITIAL_REPEATED,
            kind: BlockKind::None,
            block_size: 0,
            block_remaining: 0,
            e8_file_size: 0,
        }
    }

    /// The stream header: the E8 flag and translation size.
    fn read_header(&mut self) -> Result<()> {
        if self.bits.read(1)? == 1 {
            let high = self.bits.read(16)?;
            let low = self.bits.read(16)?;
            self.e8_file_size = i32::from_le_bytes((high << 16 | low).to_le_bytes());
        }
        Ok(())
    }

    /// Decode `size` more bytes into the window: one frame.
    fn fill_frame(&mut self, size: usize) -> Result<()> {
        let mut needed = size;
        while needed > 0 {
            if self.block_remaining == 0 {
                self.start_block()?;
                continue;
            }
            let run = self.block_remaining.min(needed);
            match self.kind {
                BlockKind::Verbatim | BlockKind::Aligned => self.decode_tokens(run)?,
                BlockKind::Uncompressed => self.copy_uncompressed(run)?,
                BlockKind::None => return Err(error("Invalid LZX stream: no block")),
            }
            self.block_remaining -= run;
            needed -= run;
        }
        Ok(())
    }

    /// Read a block header and the block's trees or repeated offsets.
    fn start_block(&mut self) -> Result<()> {
        if self.kind == BlockKind::Uncompressed && self.block_size % 2 == 1 {
            self.bits.byte()?;
        }
        let at = self.bits.pos;
        let kind = self.bits.read(BLOCK_TYPE_BITS)?;
        let high = self.bits.read(BLOCK_SIZE_HIGH_BITS)?;
        let low = self.bits.read(BLOCK_SIZE_LOW_BITS)?;
        let size = usize::try_from(high << BLOCK_SIZE_LOW_BITS | low).expect("24-bit size");
        self.kind = match kind {
            BLOCK_VERBATIM => {
                self.read_trees()?;
                BlockKind::Verbatim
            }
            BLOCK_ALIGNED => {
                let mut lengths = [0u8; ALIGNED_SYMBOLS];
                for length in &mut lengths {
                    *length =
                        u8::try_from(self.bits.read(ALIGNED_LENGTH_BITS)?).expect("3-bit length");
                }
                self.aligned = Some(
                    Huffman::build(&lengths, "aligned offset")?
                        .ok_or_else(|| error("Invalid LZX aligned offset tree: no codes"))?,
                );
                self.read_trees()?;
                BlockKind::Aligned
            }
            BLOCK_UNCOMPRESSED => {
                self.bits.start_bytes()?;
                for r in &mut self.repeated {
                    *r = self.bits.le_u32()?;
                }
                BlockKind::Uncompressed
            }
            other => {
                return Err(error(format!(
                    "Invalid LZX block type {other} near 0x{at:X}"
                )))
            }
        };
        self.block_size = size;
        self.block_remaining = size;
        Ok(())
    }

    /// The main tree in its two parts, then the length tree, which may be
    /// empty when the block has no long matches.
    fn read_trees(&mut self) -> Result<()> {
        let main_end = NUM_CHARS + self.position_slots * SYMBOLS_PER_SLOT;
        read_lengths(&mut self.bits, &mut self.main_lengths, 0, NUM_CHARS)?;
        read_lengths(&mut self.bits, &mut self.main_lengths, NUM_CHARS, main_end)?;
        self.main = Some(
            Huffman::build(&self.main_lengths[..MAIN_TABLE_SYMBOLS], "main")?
                .ok_or_else(|| error("Invalid LZX main tree: no codes"))?,
        );
        read_lengths(
            &mut self.bits,
            &mut self.length_lengths,
            0,
            NUM_SECONDARY_LENGTHS,
        )?;
        self.length = Huffman::build(&self.length_lengths[..LENGTH_TABLE_SYMBOLS], "length")?;
        Ok(())
    }

    /// Decode `run` bytes of literals and matches; a match may not run past
    /// them, since they end at a frame or block end.
    fn decode_tokens(&mut self, run: usize) -> Result<()> {
        let mut left = run;
        while left > 0 {
            let main = self
                .main
                .as_ref()
                .ok_or_else(|| error("Invalid LZX stream: no main tree"))?;
            let symbol = usize::from(main.decode(&mut self.bits)?);
            if let Ok(literal) = u8::try_from(symbol) {
                // A frame never runs past the window end, and this byte is
                // inside the frame.
                *self
                    .window
                    .get_mut(self.window_pos)
                    .ok_or_else(|| error("Invalid LZX literal: past the window end"))? = literal;
                self.window_pos += 1;
                self.decoded += 1;
                left -= 1;
                continue;
            }
            let element = symbol - NUM_CHARS;
            let mut length = element % SYMBOLS_PER_SLOT;
            if length == NUM_PRIMARY_LENGTHS {
                let tree = self
                    .length
                    .as_ref()
                    .ok_or_else(|| error("Invalid LZX match: the length tree is empty"))?;
                length += usize::from(tree.decode(&mut self.bits)?);
            }
            length += MIN_MATCH;
            let offset = self.match_offset(element / SYMBOLS_PER_SLOT)?;
            if length > left {
                return Err(error(format!(
                    "Invalid LZX match of {length} B at output 0x{:X}: it crosses a frame or \
                     block end",
                    self.decoded
                )));
            }
            self.copy_match(offset, length)?;
            left -= length;
        }
        Ok(())
    }

    /// The match offset of position slot `slot`, updating R0-R2.
    fn match_offset(&mut self, slot: usize) -> Result<usize> {
        let [r0, r1, r2] = self.repeated;
        let offset = match slot {
            0 => r0,
            1 => {
                self.repeated = [r1, r0, r2];
                r1
            }
            2 => {
                self.repeated = [r2, r1, r0];
                r2
            }
            _ => {
                let extra = u32::from(extra_bits(slot));
                let base = *POSITION_BASE
                    .get(slot)
                    .ok_or_else(|| error("Invalid LZX position slot"))?;
                let mut offset = base - 2;
                if self.kind == BlockKind::Aligned && extra >= ALIGNED_BITS {
                    offset += self.bits.read(extra - ALIGNED_BITS)? << ALIGNED_BITS;
                    let aligned = self
                        .aligned
                        .as_ref()
                        .ok_or_else(|| error("Invalid LZX stream: no aligned offset tree"))?;
                    offset += u32::from(aligned.decode(&mut self.bits)?);
                } else {
                    offset += self.bits.read(extra)?;
                }
                self.repeated = [offset, r0, r1];
                offset
            }
        };
        usize::try_from(offset).map_err(|_| error("Invalid LZX match offset"))
    }

    /// Copy `length` bytes from `offset` bytes back; the source may wrap
    /// around the window, the destination may not.
    fn copy_match(&mut self, offset: usize, length: usize) -> Result<()> {
        let size = self.window.len();
        if offset == 0 || offset > size || offset > self.decoded {
            return Err(error(format!(
                "Invalid LZX match offset {offset} at output 0x{:X}",
                self.decoded
            )));
        }
        if self.window_pos + length > size {
            return Err(error("Invalid LZX match: it runs past the window end"));
        }
        let mask = size - 1;
        let mut from = (self.window_pos + size - offset) & mask;
        for _ in 0..length {
            self.window[self.window_pos] = self.window[from];
            self.window_pos += 1;
            from = (from + 1) & mask;
        }
        self.decoded += length;
        Ok(())
    }

    /// Copy `run` bytes of an uncompressed block.
    fn copy_uncompressed(&mut self, run: usize) -> Result<()> {
        let end = self.window_pos + run;
        if end > self.window.len() {
            return Err(error("Invalid LZX block: it runs past the window end"));
        }
        self.bits
            .copy_bytes(&mut self.window[self.window_pos..end])?;
        self.window_pos = end;
        self.decoded += run;
        Ok(())
    }
}

/// Read code lengths `first..last` of a tree as deltas from the lengths it
/// holds, through a pretree read first. Runs may write past `last` into the
/// safety area, as libmspack's `lzxd_read_lens` does, so the next part's
/// deltas start from what they wrote.
fn read_lengths(bits: &mut Bits<'_>, lengths: &mut [u8], first: usize, last: usize) -> Result<()> {
    let mut pretree_lengths = [0u8; PRETREE_SYMBOLS];
    for length in &mut pretree_lengths {
        *length = u8::try_from(bits.read(PRETREE_LENGTH_BITS)?).expect("4-bit length");
    }
    let pretree = Huffman::build(&pretree_lengths, "pretree")?
        .ok_or_else(|| error("Invalid LZX pretree: no codes"))?;
    let mut x = first;
    while x < last {
        let code = pretree.decode(bits)?;
        let (run, delta) = match code {
            PRETREE_ZEROS => (ZEROS_BASE + bits.read(ZEROS_BITS)? as usize, None),
            PRETREE_MORE_ZEROS => (MORE_ZEROS_BASE + bits.read(MORE_ZEROS_BITS)? as usize, None),
            PRETREE_SAME => {
                let run = SAME_BASE + bits.read(SAME_BITS)? as usize;
                let delta = pretree.decode(bits)?;
                if delta >= PRETREE_ZEROS {
                    return Err(error(format!(
                        "Invalid LZX pretree run: code {delta} after a repeat code"
                    )));
                }
                (run, Some(delta))
            }
            delta => (1, Some(delta)),
        };
        // A repeated value is the delta from the run's first element.
        let previous = *lengths
            .get(x)
            .ok_or_else(|| error("Invalid LZX tree: lengths run past the table"))?;
        let value = delta.map_or(0, |delta| delta_length(previous, delta));
        let end = x + run;
        lengths
            .get_mut(x..end)
            .ok_or_else(|| error("Invalid LZX tree: lengths run past the table"))?
            .fill(value);
        x = end;
    }
    Ok(())
}

/// The new length for pretree delta `delta` from `previous` (0-16):
/// `(previous - delta) mod 17` ([MS-PATCH] 2.5; libmspack
/// `z = lens[x] - z; if (z < 0) z += 17`).
fn delta_length(previous: u8, delta: u16) -> u8 {
    let value = (u16::from(previous) + LENGTH_MODULUS - delta) % LENGTH_MODULUS;
    u8::try_from(value).expect("a length below 17")
}

/// Turn the absolute `CALL` targets in one frame back into relative ones.
/// `frame_offset` is the frame's offset in the output, which is below
/// 1 GiB for every frame that is translated.
fn undo_e8(frame: &mut [u8], frame_offset: usize, file_size: i32) {
    let Some(end) = frame.len().checked_sub(E8_TAIL) else {
        return;
    };
    let mut current = i32::try_from(frame_offset).expect("translated frames start below 1 GiB");
    let mut i = 0;
    while i < end {
        if frame[i] != E8_OPCODE {
            i += 1;
            current += 1;
            continue;
        }
        let operand = &mut frame[i + 1..i + 5];
        let value = i32::from_le_bytes(operand.try_into().expect("4 bytes"));
        if value >= -current && value < file_size {
            let relative = if value >= 0 {
                value - current
            } else {
                value.wrapping_add(file_size)
            };
            operand.copy_from_slice(&relative.to_le_bytes());
        }
        i += 5;
        current += 5;
    }
}

/// Decode exactly `limit` bytes of an LZX stream with a window of
/// 2^`window_bits` bytes.
///
/// # Errors
///
/// An unsupported window size, an invalid block, tree or match, or a
/// stream that ends before `limit` bytes are decoded.
pub(super) fn decode(data: &[u8], window_bits: u8, limit: usize) -> Result<Decoded> {
    if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&window_bits) {
        return Err(error(format!(
            "Unsupported LZX window of 2^{window_bits} B (cabinets use 2^15 to 2^21 B)"
        )));
    }
    let mut decoder = Decoder::new(data, window_bits);
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(Decoded {
            data: out,
            consumed: Some(0),
            check: None,
        });
    }
    decoder.read_header()?;
    let mut frame = 0usize;
    while out.len() < limit {
        let frame_size = (limit - out.len()).min(FRAME_SIZE);
        let frame_start = decoder.window_pos;
        decoder.fill_frame(frame_size)?;
        decoder.bits.align_frame()?;
        let offset = out.len();
        out.extend_from_slice(&decoder.window[frame_start..frame_start + frame_size]);
        if decoder.e8_file_size != 0 && frame < E8_FRAMES && frame_size > E8_TAIL {
            undo_e8(&mut out[offset..], offset, decoder.e8_file_size);
        }
        frame += 1;
        if decoder.window_pos == decoder.window.len() {
            decoder.window_pos = 0;
        }
    }
    Ok(Decoded {
        data: out,
        consumed: Some(decoder.bits.consumed()),
        check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-PATCH] section 3: "abc" in one uncompressed block, without the
    /// LZX DELTA chunk-size prefix (`14 00`), which cabinets do not have:
    /// E8 bit 0, block type 3, size 3, 4 padding bits, R0-R2 = 1, the
    /// bytes, one pad byte.
    const ABC: [u8; 20] = [
        0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x61, 0x62, 0x63, 0x00,
    ];

    #[test]
    fn the_ms_patch_example_decodes_to_abc() {
        let decoded = decode(&ABC, 17, 3).unwrap();
        assert_eq!(decoded.data, b"abc");
        assert_eq!(decoded.consumed, Some(19));
        assert_eq!(decoded.check, None);
    }

    #[test]
    fn decoding_needs_the_exact_size_and_a_cabinet_window() {
        assert!(decode(&ABC, 17, 4).is_err());
        assert!(decode(&ABC, 14, 3).is_err());
        assert!(decode(&ABC, 22, 3).is_err());
        assert_eq!(decode(&ABC, 15, 0).unwrap().data, b"");
        for end in 0..16 {
            assert!(decode(&ABC[..end], 15, 3).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn position_slots_follow_the_specification_table() {
        assert_eq!(POSITION_BASE[3], 3);
        assert_eq!(POSITION_BASE[4], 4);
        assert_eq!(POSITION_BASE[29], 24576);
        assert_eq!(POSITION_BASE[36], 262_144);
        assert_eq!(POSITION_BASE[49], 1_966_080);
        assert_eq!(POSITION_BASE[289], 33_423_360);
        assert_eq!(extra_bits(35), 16);
        assert_eq!(extra_bits(36), 17);
        // The slots of each window reach its largest formatted offset,
        // window size - 1 ([MS-PATCH] 2.1.4: real offset window size - 3).
        for (i, &slots) in POSITION_SLOTS.iter().enumerate() {
            let window = 1u64 << (15 + i);
            let end = u64::from(POSITION_BASE[slots - 1]) + (1 << extra_bits(slots - 1));
            assert!(end >= window, "window 2^{}", 15 + i);
        }
    }

    #[test]
    fn huffman_codes_must_be_complete() {
        assert!(Huffman::build(&[1, 1], "test").unwrap().is_some());
        assert!(Huffman::build(&[0, 0, 0], "test").unwrap().is_none());
        assert!(Huffman::build(&[1], "test").is_err());
        assert!(Huffman::build(&[1, 1, 1], "test").is_err());
        assert!(Huffman::build(&[1, 2, 3, 3], "test").unwrap().is_some());
    }

    #[test]
    fn canonical_codes_decode_short_and_long_symbols() {
        // Lengths 1, 2, ..., 15, 16, 16: codes 0, 10, 110, ..., 1111111111111110,
        // 1111111111111111 (MSB first).
        let mut lengths: Vec<u8> = (1..=16).collect();
        lengths.push(16);
        let code = Huffman::build(&lengths, "test").unwrap().unwrap();
        // Symbol 0 (`0`), symbol 1 (`10`), symbol 16 (sixteen ones), then
        // symbol 12 (twelve ones and a zero): the words 0101111111111111
        // and 1111111111111110, stored little-endian; the last decode
        // peeks into the padding word.
        let stream = [0xff, 0x5f, 0xfe, 0xff];
        let mut bits = Bits::new(&stream);
        assert_eq!(code.decode(&mut bits).unwrap(), 0);
        assert_eq!(code.decode(&mut bits).unwrap(), 1);
        assert_eq!(code.decode(&mut bits).unwrap(), 16);
        assert_eq!(code.decode(&mut bits).unwrap(), 12);
    }

    #[test]
    fn the_bit_reader_pads_one_word_and_then_fails() {
        let mut bits = Bits::new(&[0x34, 0x12]);
        assert_eq!(bits.read(4).unwrap(), 0x1);
        assert_eq!(bits.read(12).unwrap(), 0x234);
        assert_eq!(bits.read(16).unwrap(), 0);
        assert!(bits.read(1).is_err());
    }

    #[test]
    fn length_deltas_are_taken_modulo_17() {
        assert_eq!(delta_length(0, 0), 0);
        assert_eq!(delta_length(0, 1), 16);
        assert_eq!(delta_length(5, 3), 2);
        assert_eq!(delta_length(16, 16), 0);
        assert_eq!(delta_length(3, 12), 8);
    }

    #[test]
    fn e8_translation_is_reversed_within_the_frame() {
        // An absolute target 0x1000 at a CALL at output offset 0x20 + 5
        // becomes 0x1000 - 0x25; a negative value -0x10 becomes
        // -0x10 + file size; values out of range and the tail stay.
        let mut frame = vec![0u8; 64];
        frame[5] = E8_OPCODE;
        frame[6..10].copy_from_slice(&0x1000i32.to_le_bytes());
        frame[20] = E8_OPCODE;
        frame[21..25].copy_from_slice(&(-0x10i32).to_le_bytes());
        frame[30] = E8_OPCODE;
        frame[31..35].copy_from_slice(&0x7000_0000i32.to_le_bytes());
        frame[56] = E8_OPCODE;
        frame[57..61].copy_from_slice(&0x1000i32.to_le_bytes());
        undo_e8(&mut frame, 0x20, 0x10_0000);
        assert_eq!(&frame[6..10], &(0x1000i32 - 0x25).to_le_bytes());
        assert_eq!(&frame[21..25], &(0x10_0000i32 - 0x10).to_le_bytes());
        assert_eq!(&frame[31..35], &0x7000_0000i32.to_le_bytes());
        assert_eq!(&frame[57..61], &0x1000i32.to_le_bytes());
    }

    #[test]
    fn noise_never_panics() {
        let mut x: u32 = 0x9e37_79b9;
        let noise: Vec<u8> = (0..8192)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x.to_le_bytes()[0]
            })
            .collect();
        for window in MIN_WINDOW_BITS..=MAX_WINDOW_BITS {
            for end in [0, 1, 2, 7, 64, 1000, noise.len()] {
                let _ = decode(&noise[..end], window, 70_000);
            }
        }
    }
}
