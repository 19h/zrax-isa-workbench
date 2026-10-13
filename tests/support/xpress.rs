//! A small XPRESS (LZ77+Huffman) encoder for tests, written from [MS-XCA]
//! v20240423 section 2.1 ("LZ77+Huffman Compression Algorithm Details"),
//! since no XPRESS encoder is installed. It finds matches greedily with a
//! hash of three bytes, and its Huffman code is a complete balanced code
//! over the symbols it uses (lengths differ by at most one), which fits
//! the 15-bit limit for any alphabet of 512 symbols. It ends the stream
//! with the end-of-data symbol 256 and the flush of [MS-XCA] 2.1.4.3.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

/// Symbols of the alphabet and the size of the length table.
const NUM_SYMBOLS: usize = 512;
const TABLE_SIZE: usize = NUM_SYMBOLS / 2;

/// The end-of-data symbol ([MS-XCA] 2.1.4.3).
const END_OF_DATA: usize = 256;

/// Shortest and longest match, and the farthest offset.
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 65_538;
const MAX_OFFSET: usize = 65_535;

/// One literal or match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Literal(u8),
    /// Copy `length` bytes (3 to 65,538) from `offset` bytes back (1 to
    /// 65,535).
    Match {
        length: usize,
        offset: usize,
    },
}

/// Greedy LZ77 tokens for `data`.
pub fn tokens(data: &[u8]) -> Vec<Token> {
    let mut heads: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let key = data.get(i..i + MIN_MATCH).map(|k| [k[0], k[1], k[2]]);
        let candidate = key.and_then(|key| heads.get(&key).copied());
        let found = candidate.filter(|&at| i - at <= MAX_OFFSET).map(|at| {
            let length = data[i..]
                .iter()
                .zip(&data[at..])
                .take(MAX_MATCH)
                .take_while(|(a, b)| a == b)
                .count();
            (length, i - at)
        });
        if let Some(key) = key {
            heads.insert(key, i);
        }
        match found {
            Some((length, offset)) if length >= MIN_MATCH => {
                out.push(Token::Match { length, offset });
                for j in i + 1..(i + length).min(data.len().saturating_sub(MIN_MATCH - 1)) {
                    heads.insert([data[j], data[j + 1], data[j + 2]], j);
                }
                i += length;
            }
            _ => {
                out.push(Token::Literal(data[i]));
                i += 1;
            }
        }
    }
    out
}

/// The symbol of a match: `256 + 16 * high bit of the offset + min(length
/// - 3, 15)` ([MS-XCA] 2.1.4.1).
fn match_symbol(length: usize, offset: usize) -> usize {
    let offset_bits = (usize::BITS - 1 - offset.leading_zeros()) as usize;
    256 + 16 * offset_bits + (length - MIN_MATCH).min(15)
}

/// Code lengths of a complete code over the used symbols whose lengths
/// differ by at most one.
fn balanced_lengths(used: &[bool]) -> Vec<u8> {
    let mut symbols: Vec<usize> = (0..used.len()).filter(|&s| used[s]).collect();
    if symbols.len() == 1 {
        symbols.push(if symbols[0] == 0 { 1 } else { 0 });
        symbols.sort_unstable();
    }
    let k = symbols.len();
    let depth = (usize::BITS - (k - 1).leading_zeros()) as u8;
    let short = (1usize << depth) - k;
    let mut lengths = vec![0u8; used.len()];
    for (i, &symbol) in symbols.iter().enumerate() {
        lengths[symbol] = if i < short { depth - 1 } else { depth };
    }
    lengths
}

/// Canonical codes for `lengths`: shortest first, then by symbol.
fn canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 17];
    for &length in lengths {
        count[usize::from(length)] += 1;
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
        .map(|&length| {
            if length == 0 {
                return 0;
            }
            let c = next[usize::from(length)];
            next[usize::from(length)] += 1;
            c
        })
        .collect()
}

/// The bitstream of [MS-XCA] 2.1.4.3: two word slots are reserved ahead of
/// the bytes, a full word goes into its slot when the next bit arrives, and
/// the flush writes the last word and leaves a zero word.
struct Writer {
    out: Vec<u8>,
    slot: usize,
    next_slot: usize,
    word: u32,
    filled: u32,
}

impl Writer {
    fn new(table: &[u8]) -> Self {
        let mut out = table.to_vec();
        out.extend_from_slice(&[0; 4]);
        Self {
            out,
            slot: TABLE_SIZE,
            next_slot: TABLE_SIZE + 2,
            word: 0,
            filled: 0,
        }
    }

    fn bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            if self.filled == 16 {
                self.flush_word();
            }
            self.word = (self.word << 1) | ((value >> i) & 1);
            self.filled += 1;
        }
    }

    fn flush_word(&mut self) {
        let word = (self.word & 0xffff) as u16;
        self.out[self.slot..self.slot + 2].copy_from_slice(&word.to_le_bytes());
        self.slot = self.next_slot;
        self.next_slot = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        self.word = 0;
        self.filled = 0;
    }

    fn finish(mut self) -> Vec<u8> {
        let word = ((self.word << (16 - self.filled)) & 0xffff) as u16;
        self.out[self.slot..self.slot + 2].copy_from_slice(&word.to_le_bytes());
        self.out
    }
}

/// Encode `tokens` into one XPRESS stream (at most 64 KiB of output).
pub fn encode_tokens(tokens: &[Token]) -> Vec<u8> {
    let mut used = vec![false; NUM_SYMBOLS];
    used[END_OF_DATA] = true;
    for token in tokens {
        match *token {
            Token::Literal(b) => used[usize::from(b)] = true,
            Token::Match { length, offset } => used[match_symbol(length, offset)] = true,
        }
    }
    let lengths = balanced_lengths(&used);
    let codes = canonical_codes(&lengths);
    let table: Vec<u8> = lengths
        .chunks_exact(2)
        .map(|pair| pair[0] | (pair[1] << 4))
        .collect();
    let mut w = Writer::new(&table);
    let put = |w: &mut Writer, symbol: usize| w.bits(codes[symbol], u32::from(lengths[symbol]));
    for token in tokens {
        match *token {
            Token::Literal(b) => put(&mut w, usize::from(b)),
            Token::Match { length, offset } => {
                put(&mut w, match_symbol(length, offset));
                let adjusted = length - MIN_MATCH;
                if adjusted >= 15 {
                    let rest = adjusted - 15;
                    if rest < 255 {
                        w.out.push(rest as u8);
                    } else {
                        w.out.push(255);
                        w.out.extend_from_slice(&(adjusted as u16).to_le_bytes());
                    }
                }
                let offset_bits = usize::BITS - 1 - offset.leading_zeros();
                w.bits((offset - (1 << offset_bits)) as u32, offset_bits);
            }
        }
    }
    put(&mut w, END_OF_DATA);
    w.finish()
}

/// Compress `data` (at most 64 KiB) with greedy matches.
pub fn compress(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= 64 << 10,
        "one XPRESS block holds at most 64 KiB"
    );
    encode_tokens(&tokens(data))
}
