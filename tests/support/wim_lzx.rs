//! A small encoder for LZX as WIM chunks store it, for tests, written from
//! [MS-PATCH] v20250819 sections 2.1-2.6 (blocks, trees, position slots)
//! and wimlib v1.14.5's reading of WIM chunks (`src/lzx_decompress.c`
//! `lzx_read_block_header`, `src/lzx_common.c` `lzx_e8_filter`): no E8
//! header, a block size of one set bit for 32 KiB or a clear bit and 16
//! bits (and 8 more bits with windows of 2^16 or more), E8 translation
//! applied to the whole chunk with the translation size 12,000,000, and no
//! frame realignment. No LZX encoder is installed. Matches are found
//! greedily and coded with explicit offsets or the repeated offset R0;
//! each block's codes are complete balanced codes over the symbols it uses,
//! and code lengths are written as pretree deltas with zero runs.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

/// The WIM translation size of E8 translation (wimlib
/// `LZX_WIM_MAGIC_FILESIZE`).
const E8_FILE_SIZE: i32 = 12_000_000;

/// No translation starts in the last 10 bytes of a chunk.
const E8_TAIL: usize = 10;

/// The block size that a set bit codes.
const DEFAULT_BLOCK_SIZE: usize = 32_768;

/// Position slots per window size from 2^15 to 2^21 ([MS-PATCH] 2.1.6).
const POSITION_SLOTS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];

const NUM_CHARS: usize = 256;
const MIN_MATCH: usize = 2;
const MAX_MATCH: usize = 257;
const LENGTH_SYMBOLS: usize = 249;

/// One block of a chunk.
#[derive(Debug, Clone)]
pub enum Block {
    /// Bytes coded with literals and matches.
    Verbatim(Vec<u8>),
    /// Bytes stored as they are.
    Uncompressed(Vec<u8>),
}

/// Footer bits of a position slot ([MS-PATCH] 2.6.2).
fn footer_bits(slot: usize) -> u32 {
    match slot {
        0..=3 => 0,
        4..=35 => (slot / 2 - 1) as u32,
        _ => 17,
    }
}

/// The base formatted offset of a position slot.
fn slot_base(slot: usize) -> u32 {
    (0..slot).map(|s| 1u32 << footer_bits(s)).sum()
}

/// Apply E8 translation, as the compressor does before coding: relative
/// `CALL` targets become absolute (wimlib `do_translate_target`).
pub fn e8_translate(data: &mut [u8]) {
    if data.len() <= E8_TAIL {
        return;
    }
    let end = data.len() - E8_TAIL;
    let mut i = 0;
    while i < end {
        if data[i] != 0xe8 {
            i += 1;
            continue;
        }
        let position = i as i32;
        let operand: [u8; 4] = data[i + 1..i + 5].try_into().unwrap();
        let relative = i32::from_le_bytes(operand);
        if relative >= -position && relative < E8_FILE_SIZE {
            let absolute = if relative < E8_FILE_SIZE - position {
                relative + position
            } else {
                relative - E8_FILE_SIZE
            };
            data[i + 1..i + 5].copy_from_slice(&absolute.to_le_bytes());
        }
        i += 5;
    }
}

/// Writes 16-bit little-endian words, most significant bit first.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    word: u32,
    count: u32,
}

impl Writer {
    fn bits(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            self.word = (self.word << 1) | ((value >> i) & 1);
            self.count += 1;
            if self.count == 16 {
                self.bytes
                    .extend_from_slice(&(self.word as u16).to_le_bytes());
                self.word = 0;
                self.count = 0;
            }
        }
    }

    fn align(&mut self) {
        if self.count > 0 {
            self.bits(0, 16 - self.count);
        }
    }
}

/// A complete code with lengths differing by at most one over the symbols
/// with a nonzero count; a single symbol gets a partner.
fn balanced(counts: &[usize]) -> Vec<u8> {
    let mut used: Vec<usize> = (0..counts.len()).filter(|&s| counts[s] > 0).collect();
    let mut lengths = vec![0u8; counts.len()];
    if used.is_empty() {
        return lengths;
    }
    if used.len() == 1 {
        used.push(if used[0] == 0 { 1 } else { 0 });
        used.sort_unstable();
    }
    let k = used.len();
    let depth = (usize::BITS - (k - 1).leading_zeros()) as u8;
    let short = (1usize << depth) - k;
    for (i, &symbol) in used.iter().enumerate() {
        lengths[symbol] = if i < short { depth - 1 } else { depth };
    }
    lengths
}

/// Canonical codes for `lengths`.
fn codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &l in lengths {
        count[usize::from(l)] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 17];
    let mut code = 0;
    for bits in 1..17 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                return 0;
            }
            let c = next[usize::from(l)];
            next[usize::from(l)] += 1;
            c
        })
        .collect()
}

/// Write the lengths `new[first..last]` as pretree codes against `old`:
/// zero runs with codes 17 and 18, other lengths as deltas
/// `(old - new) mod 17`.
fn write_lengths(w: &mut Writer, old: &[u8], new: &[u8], first: usize, last: usize) {
    // (pretree code, extra value, extra bits)
    let mut items: Vec<(usize, u32, u32)> = Vec::new();
    let mut x = first;
    while x < last {
        let run = (x..last).take_while(|&y| new[y] == 0).count();
        if run >= 20 {
            let n = run.min(51);
            items.push((18, (n - 20) as u32, 5));
            x += n;
        } else if run >= 4 {
            let n = run.min(19);
            items.push((17, (n - 4) as u32, 4));
            x += n;
        } else {
            let delta = (usize::from(old[x]) + 17 - usize::from(new[x])) % 17;
            items.push((delta, 0, 0));
            x += 1;
        }
    }
    let mut counts = [0usize; 20];
    for &(code, _, _) in &items {
        counts[code] += 1;
    }
    let lengths = balanced(&counts);
    let pretree = codes(&lengths);
    for &l in &lengths {
        w.bits(u32::from(l), 4);
    }
    for &(code, value, bits) in &items {
        w.bits(pretree[code], u32::from(lengths[code]));
        w.bits(value, bits);
    }
}

/// A coded match or literal.
struct Item {
    main: usize,
    length_symbol: Option<usize>,
    /// Footer value and bit count.
    footer: Option<(u32, u32)>,
}

/// Encodes one WIM chunk.
pub struct Encoder {
    window_bits: u8,
    slots: usize,
    w: Writer,
    main_lengths: Vec<u8>,
    length_lengths: Vec<u8>,
    r0: u32,
    /// The chunk so far, E8-translated, for matching.
    window: Vec<u8>,
    pad_pending: bool,
}

impl Encoder {
    pub fn new(window_bits: u8) -> Self {
        let slots = POSITION_SLOTS[usize::from(window_bits - 15)];
        Self {
            window_bits,
            slots,
            w: Writer::default(),
            main_lengths: vec![0; NUM_CHARS + slots * 8],
            length_lengths: vec![0; LENGTH_SYMBOLS],
            r0: 1,
            window: Vec::new(),
            pad_pending: false,
        }
    }

    fn header(&mut self, kind: u32, size: usize) {
        if self.pad_pending {
            assert_eq!(self.w.count, 0);
            self.w.bytes.push(0);
            self.pad_pending = false;
        }
        self.w.bits(kind, 3);
        if size == DEFAULT_BLOCK_SIZE {
            self.w.bits(1, 1);
        } else {
            self.w.bits(0, 1);
            if self.window_bits >= 16 {
                self.w.bits((size >> 8) as u32, 16);
                self.w.bits((size & 0xff) as u32, 8);
            } else {
                self.w.bits(size as u32, 16);
            }
        }
    }

    /// The length of a match at `i` from `offset` back, within `end`.
    fn match_length(&self, i: usize, offset: usize, end: usize) -> usize {
        // Formatted offsets (offset + 2) reach the window size - 1.
        let farthest = (1usize << self.window_bits) - 3;
        if offset == 0 || offset > i || offset > farthest {
            return 0;
        }
        (0..MAX_MATCH.min(end - i))
            .take_while(|&k| self.window[i + k] == self.window[i + k - offset])
            .count()
    }

    /// Greedy items for `bytes`, which follow the window: the longer of a
    /// match at R0 and one at the last position with the same 3 bytes.
    fn items(&mut self, bytes: &[u8]) -> Vec<Item> {
        let start = self.window.len();
        self.window.extend_from_slice(bytes);
        let mut heads: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
        for at in 0..start.saturating_sub(2) {
            heads.insert(
                [self.window[at], self.window[at + 1], self.window[at + 2]],
                at,
            );
        }
        let mut items = Vec::new();
        let mut i = start;
        let end = self.window.len();
        while i < end {
            let repeat = self.match_length(i, self.r0 as usize, end);
            let key = (i + 2 < self.window.len())
                .then(|| [self.window[i], self.window[i + 1], self.window[i + 2]]);
            let hashed = key
                .and_then(|key| heads.get(&key).copied())
                .map_or((0, 0), |at| (self.match_length(i, i - at, end), i - at));
            let (length, offset) = if repeat >= hashed.0 {
                (repeat, self.r0 as usize)
            } else {
                hashed
            };
            let step = if length >= 3 { length } else { 1 };
            for at in i..(i + step).min(self.window.len().saturating_sub(2)) {
                heads.insert(
                    [self.window[at], self.window[at + 1], self.window[at + 2]],
                    at,
                );
            }
            if length < 3 {
                items.push(Item {
                    main: usize::from(self.window[i]),
                    length_symbol: None,
                    footer: None,
                });
                i += 1;
                continue;
            }
            let offset = offset as u32;
            let (slot, footer) = if offset == self.r0 {
                (0, None)
            } else {
                let formatted = offset + 2;
                let slot = (3..self.slots)
                    .take_while(|&s| slot_base(s) <= formatted)
                    .last()
                    .unwrap();
                (slot, Some((formatted - slot_base(slot), footer_bits(slot))))
            };
            self.r0 = offset;
            let header = (length - MIN_MATCH).min(7);
            items.push(Item {
                main: NUM_CHARS + slot * 8 + header,
                length_symbol: (header == 7).then(|| length - MIN_MATCH - 7),
                footer,
            });
            i += length;
        }
        items
    }

    /// Write one block.
    pub fn block(&mut self, block: &Block) {
        match block {
            Block::Uncompressed(bytes) => self.uncompressed(bytes),
            Block::Verbatim(bytes) => self.verbatim(bytes),
        }
    }

    fn uncompressed(&mut self, bytes: &[u8]) {
        self.header(3, bytes.len());
        if self.w.count == 0 {
            self.w.bits(0, 16);
        } else {
            self.w.align();
        }
        // R0 is the repeated offset this encoder uses; R1 and R2 stay 1.
        for r in [self.r0, 1, 1] {
            self.w.bytes.extend_from_slice(&r.to_le_bytes());
        }
        self.w.bytes.extend_from_slice(bytes);
        self.window.extend_from_slice(bytes);
        self.pad_pending = bytes.len() % 2 == 1;
    }

    fn verbatim(&mut self, bytes: &[u8]) {
        let items = self.items(bytes);
        let main_size = NUM_CHARS + self.slots * 8;
        let mut main_counts = vec![0usize; main_size];
        let mut length_counts = vec![0usize; LENGTH_SYMBOLS];
        for item in &items {
            main_counts[item.main] += 1;
            if let Some(symbol) = item.length_symbol {
                length_counts[symbol] += 1;
            }
        }
        let main = balanced(&main_counts);
        let length = balanced(&length_counts);
        self.header(1, bytes.len());
        write_lengths(&mut self.w, &self.main_lengths, &main, 0, NUM_CHARS);
        write_lengths(&mut self.w, &self.main_lengths, &main, NUM_CHARS, main_size);
        write_lengths(
            &mut self.w,
            &self.length_lengths,
            &length,
            0,
            LENGTH_SYMBOLS,
        );
        let main_codes = codes(&main);
        let length_codes = codes(&length);
        for item in &items {
            self.w
                .bits(main_codes[item.main], u32::from(main[item.main]));
            if let Some(symbol) = item.length_symbol {
                self.w.bits(length_codes[symbol], u32::from(length[symbol]));
            }
            if let Some((value, bits)) = item.footer {
                self.w.bits(value, bits);
            }
        }
        self.main_lengths = main;
        self.length_lengths = length;
    }

    /// End the chunk at a 16-bit boundary.
    pub fn finish(mut self) -> Vec<u8> {
        self.w.align();
        self.w.bytes
    }
}

/// Encode a chunk of `data` (E8-translated here) in blocks of at most
/// `block` bytes, alternating verbatim and uncompressed blocks when
/// `mixed`, with a window of 2^`window_bits` bytes.
pub fn compress(data: &[u8], window_bits: u8, block: usize, mixed: bool) -> Vec<u8> {
    let mut translated = data.to_vec();
    e8_translate(&mut translated);
    let mut encoder = Encoder::new(window_bits);
    for (i, part) in translated.chunks(block).enumerate() {
        if mixed && i % 2 == 1 {
            encoder.block(&Block::Uncompressed(part.to_vec()));
        } else {
            encoder.block(&Block::Verbatim(part.to_vec()));
        }
    }
    encoder.finish()
}
