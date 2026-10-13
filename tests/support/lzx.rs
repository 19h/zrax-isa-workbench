//! A small LZX encoder for tests, written from the documented layout
//! ([MS-PATCH] v20250819 sections 2.1-2.6, the Cabinet SDK's "LZX Format"
//! with the corrections that libmspack `mspack/lzxd.c` lists), since no
//! LZX encoder is available. It does not search for matches: callers give
//! the literals and matches, and each block's Huffman codes are complete
//! balanced codes over the symbols it uses. Code lengths are written as
//! pretree deltas with the zero-run (17, 18) and same-length (19) codes.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

/// Output frame size: the bitstream realigns after every 32 KiB.
pub const FRAME: usize = 32 << 10;

/// One literal or match.
#[derive(Debug, Clone, Copy)]
pub enum Token {
    Literal(u8),
    /// Copy `length` (2-257) bytes from `offset` bytes back. Offsets equal
    /// to a repeated offset are coded as that repeated offset.
    Match {
        length: usize,
        offset: u32,
    },
}

/// One block of the stream.
#[derive(Debug, Clone)]
pub enum Block {
    Verbatim(Vec<Token>),
    /// Like a verbatim block, with the low 3 footer bits of offsets with 3
    /// or more footer bits coded by the aligned offset tree.
    Aligned(Vec<Token>),
    /// Bytes stored as they are, with the current repeated offsets.
    Uncompressed(Vec<u8>),
}

/// An encoded stream.
pub struct Stream {
    /// The bitstream bytes.
    pub bytes: Vec<u8>,
    /// For each frame, where its bytes end in `bytes`.
    pub frame_ends: Vec<usize>,
    /// The decoded bytes, before any E8 translation is undone.
    pub window: Vec<u8>,
}

impl Stream {
    /// The bytes of each frame, which cabinets store one per CFDATA block.
    pub fn frames(&self) -> Vec<Vec<u8>> {
        let mut start = 0;
        self.frame_ends
            .iter()
            .map(|&end| {
                let frame = self.bytes[start..end].to_vec();
                start = end;
                frame
            })
            .collect()
    }
}

/// Position slots per window size from 2^15 to 2^21 ([MS-PATCH] 2.1.6).
const POSITION_SLOTS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];

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

/// Main-tree size libmspack keeps (256 + 290 * 8) and length-tree size
/// (249 + 1), so the previous lengths match what the decoder keeps.
const MAIN_LENGTHS: usize = 256 + 290 * 8;
const LENGTH_LENGTHS: usize = 250;

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

    /// Pad with zero bits to the next 16-bit boundary.
    fn align(&mut self) {
        if self.count > 0 {
            self.bits(0, 16 - self.count);
        }
    }
}

/// A complete canonical code: lengths and codes per symbol.
struct Code {
    lengths: Vec<u8>,
    codes: Vec<u32>,
}

impl Code {
    /// A balanced complete code over the symbols with a nonzero count; a
    /// single symbol gets a partner so that the code has two codes.
    fn balanced(counts: &[usize]) -> Code {
        let mut used: Vec<usize> = (0..counts.len()).filter(|&s| counts[s] > 0).collect();
        if used.len() == 1 {
            used.push(if used[0] == 0 { 1 } else { 0 });
            used.sort_unstable();
        }
        let mut lengths = vec![0u8; counts.len()];
        if !used.is_empty() {
            let k = used.len();
            let depth = usize::BITS - (k - 1).leading_zeros();
            let short = (1usize << depth) - k;
            for (i, &symbol) in used.iter().enumerate() {
                lengths[symbol] = if i < short { depth - 1 } else { depth } as u8;
            }
        }
        Code::from_lengths(lengths)
    }

    /// Canonical codes for `lengths`: shortest first, then by symbol.
    fn from_lengths(lengths: Vec<u8>) -> Code {
        let mut count = [0u32; 17];
        for &l in &lengths {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 17];
        let mut code = 0;
        for bits in 1..17 {
            code = (code + count[bits - 1]) << 1;
            next[bits] = code;
        }
        let codes = lengths
            .iter()
            .map(|&l| {
                if l == 0 {
                    return 0;
                }
                let c = next[usize::from(l)];
                next[usize::from(l)] += 1;
                c
            })
            .collect();
        Code { lengths, codes }
    }

    fn put(&self, w: &mut Writer, symbol: usize) {
        assert!(self.lengths[symbol] > 0, "symbol {symbol} has no code");
        w.bits(self.codes[symbol], u32::from(self.lengths[symbol]));
    }
}

/// One pretree code and its extra bits.
struct TreeCode {
    code: usize,
    extra: Option<(u32, u32)>,
    /// The delta code after a same-length run code (19).
    then: Option<usize>,
}

/// Code lengths `first..last` of `new` as pretree codes against `old`.
fn tree_codes(old: &[u8], new: &[u8], first: usize, last: usize) -> Vec<TreeCode> {
    // The decoder sets `(old - code) mod 17` ([MS-PATCH] 2.5).
    let delta = |x: usize, value: u8| (usize::from(old[x]) + 17 - usize::from(value)) % 17;
    let mut codes = Vec::new();
    let mut x = first;
    while x < last {
        let run = (x..last).take_while(|&y| new[y] == new[x]).count();
        if new[x] == 0 && run >= 20 {
            let n = run.min(51);
            codes.push(TreeCode {
                code: 18,
                extra: Some(((n - 20) as u32, 5)),
                then: None,
            });
            x += n;
        } else if new[x] == 0 && run >= 4 {
            let n = run.min(19);
            codes.push(TreeCode {
                code: 17,
                extra: Some(((n - 4) as u32, 4)),
                then: None,
            });
            x += n;
        } else if run >= 4 {
            // The run's value is the delta from its first element's old
            // length (libmspack `lzxd_read_lens`).
            let n = run.min(5);
            codes.push(TreeCode {
                code: 19,
                extra: Some(((n - 4) as u32, 1)),
                then: Some(delta(x, new[x])),
            });
            x += n;
        } else {
            codes.push(TreeCode {
                code: delta(x, new[x]),
                extra: None,
                then: None,
            });
            x += 1;
        }
    }
    codes
}

/// Write a pretree and the codes of one tree part.
fn write_tree(w: &mut Writer, codes: &[TreeCode]) {
    let mut counts = [0usize; 20];
    for c in codes {
        counts[c.code] += 1;
        if let Some(then) = c.then {
            counts[then] += 1;
        }
    }
    if counts.iter().all(|&n| n == 0) {
        counts[0] = 1;
    }
    let pretree = Code::balanced(&counts);
    for &l in &pretree.lengths {
        w.bits(u32::from(l), 4);
    }
    for c in codes {
        pretree.put(w, c.code);
        if let Some((value, bits)) = c.extra {
            w.bits(value, bits);
        }
        if let Some(then) = c.then {
            pretree.put(w, then);
        }
    }
}

/// A token with its symbols resolved against the repeated offsets.
struct Coded {
    main: usize,
    length_footer: Option<usize>,
    /// Footer value and bits (for slots 3 and up).
    footer: Option<(u32, u32)>,
    output: usize,
    offset: u32,
}

/// The encoder state that persists across blocks.
pub struct Encoder {
    window_bits: u8,
    slots: usize,
    w: Writer,
    main_lengths: Vec<u8>,
    length_lengths: Vec<u8>,
    repeated: [u32; 3],
    window: Vec<u8>,
    frame_ends: Vec<usize>,
    /// An odd-sized uncompressed block ended; a pad byte precedes the next
    /// block.
    pad_pending: bool,
}

impl Encoder {
    /// A stream with a window of 2^`window_bits` bytes; `e8_file_size`
    /// enables E8 translation with that translation size.
    pub fn new(window_bits: u8, e8_file_size: Option<u32>) -> Self {
        let mut w = Writer::default();
        match e8_file_size {
            Some(size) => {
                w.bits(1, 1);
                w.bits(size >> 16, 16);
                w.bits(size & 0xFFFF, 16);
            }
            None => w.bits(0, 1),
        }
        Self {
            window_bits,
            slots: POSITION_SLOTS[usize::from(window_bits - 15)],
            w,
            main_lengths: vec![0; MAIN_LENGTHS],
            length_lengths: vec![0; LENGTH_LENGTHS],
            repeated: [1, 1, 1],
            window: Vec::new(),
            frame_ends: Vec::new(),
            pad_pending: false,
        }
    }

    /// After `n` more output bytes: end the frame at a 32 KiB boundary.
    fn advance(&mut self, n: usize, bit_mode: bool) {
        let before = self.window.len() - n;
        assert!(
            before / FRAME == (self.window.len() - 1) / FRAME,
            "a token crosses a frame boundary at output {before}"
        );
        if self.window.len() % FRAME == 0 {
            if bit_mode {
                self.w.align();
            }
            self.frame_ends.push(self.w.bytes.len());
        }
    }

    fn header(&mut self, kind: u32, size: usize) {
        if self.pad_pending {
            assert_eq!(self.w.count, 0);
            self.w.bytes.push(0);
            self.pad_pending = false;
        }
        self.w.bits(kind, 3);
        self.w.bits(size as u32, 24);
    }

    /// Resolve tokens to symbols, updating the repeated offsets.
    fn code_tokens(&mut self, tokens: &[Token]) -> Vec<Coded> {
        let mut coded = Vec::new();
        for &token in tokens {
            match token {
                Token::Literal(b) => coded.push(Coded {
                    main: usize::from(b),
                    length_footer: None,
                    footer: None,
                    output: 1,
                    offset: 0,
                }),
                Token::Match { length, offset } => {
                    assert!((2..=257).contains(&length));
                    let [r0, r1, r2] = self.repeated;
                    let (slot, footer) = if offset == r0 {
                        (0, None)
                    } else if offset == r1 {
                        self.repeated = [r1, r0, r2];
                        (1, None)
                    } else if offset == r2 {
                        self.repeated = [r2, r1, r0];
                        (2, None)
                    } else {
                        let formatted = offset + 2;
                        let slot = (3..self.slots)
                            .take_while(|&s| slot_base(s) <= formatted)
                            .last()
                            .expect("offset within the window");
                        self.repeated = [offset, r0, r1];
                        (slot, Some((formatted - slot_base(slot), footer_bits(slot))))
                    };
                    let header = (length - 2).min(7);
                    coded.push(Coded {
                        main: 256 + slot * 8 + header,
                        length_footer: (header == 7).then(|| length - 9),
                        footer,
                        output: length,
                        offset,
                    });
                }
            }
        }
        coded
    }

    /// Write one block.
    pub fn block(&mut self, block: &Block) {
        match block {
            Block::Uncompressed(bytes) => self.uncompressed(bytes),
            Block::Verbatim(tokens) => self.compressed(tokens, false),
            Block::Aligned(tokens) => self.compressed(tokens, true),
        }
    }

    fn uncompressed(&mut self, bytes: &[u8]) {
        self.header(3, bytes.len());
        // 1-16 bits of padding: a whole word when already aligned.
        if self.w.count == 0 {
            self.w.bits(0, 16);
        } else {
            self.w.align();
        }
        for r in self.repeated {
            self.w.bytes.extend_from_slice(&r.to_le_bytes());
        }
        for &b in bytes {
            self.w.bytes.push(b);
            self.window.push(b);
            self.advance(1, false);
        }
        self.pad_pending = bytes.len() % 2 == 1;
    }

    fn compressed(&mut self, tokens: &[Token], aligned: bool) {
        let size: usize = tokens
            .iter()
            .map(|t| match t {
                Token::Literal(_) => 1,
                Token::Match { length, .. } => *length,
            })
            .sum();
        let coded = self.code_tokens(tokens);
        let main_end = 256 + self.slots * 8;
        let mut main_counts = vec![0usize; main_end];
        let mut length_counts = vec![0usize; 249];
        let mut aligned_counts = [0usize; 8];
        for c in &coded {
            main_counts[c.main] += 1;
            if let Some(footer) = c.length_footer {
                length_counts[footer] += 1;
            }
            if let Some((value, bits)) = c.footer {
                if aligned && bits >= 3 {
                    aligned_counts[(value & 7) as usize] += 1;
                }
            }
        }
        let main = Code::balanced(&main_counts);
        let length = Code::balanced(&length_counts);
        let mut aligned_code = Code::balanced(&aligned_counts);
        if aligned_counts.iter().all(|&n| n == 0) {
            aligned_code = Code::from_lengths(vec![3; 8]);
        }
        self.header(if aligned { 2 } else { 1 }, size);
        if aligned {
            for &l in &aligned_code.lengths {
                self.w.bits(u32::from(l), 3);
            }
        }
        let mut new_main = self.main_lengths.clone();
        new_main[..main_end].copy_from_slice(&main.lengths);
        let part1 = tree_codes(&self.main_lengths, &new_main, 0, 256);
        write_tree(&mut self.w, &part1);
        let part2 = tree_codes(&self.main_lengths, &new_main, 256, main_end);
        write_tree(&mut self.w, &part2);
        self.main_lengths = new_main;
        let mut new_length = self.length_lengths.clone();
        new_length[..249].copy_from_slice(&length.lengths);
        let lengths = tree_codes(&self.length_lengths, &new_length, 0, 249);
        write_tree(&mut self.w, &lengths);
        self.length_lengths = new_length;
        for c in &coded {
            main.put(&mut self.w, c.main);
            if let Some(footer) = c.length_footer {
                length.put(&mut self.w, footer);
            }
            if let Some((value, bits)) = c.footer {
                if aligned && bits >= 3 {
                    self.w.bits(value >> 3, bits - 3);
                    aligned_code.put(&mut self.w, (value & 7) as usize);
                } else {
                    self.w.bits(value, bits);
                }
            }
            if c.main < 256 {
                self.window.push(c.main as u8);
            } else {
                let from = self.window.len() - c.offset as usize;
                for i in 0..c.output {
                    let b = self.window[from + i];
                    self.window.push(b);
                }
            }
            self.advance(c.output, true);
        }
    }

    /// End the stream: the last, short frame ends at a 16-bit boundary.
    pub fn finish(mut self) -> Stream {
        if self.window.len() % FRAME != 0 {
            self.w.align();
            self.frame_ends.push(self.w.bytes.len());
        }
        Stream {
            bytes: self.w.bytes,
            frame_ends: self.frame_ends,
            window: self.window,
        }
    }
}

/// Encode `blocks` into one stream.
pub fn encode(window_bits: u8, e8_file_size: Option<u32>, blocks: &[Block]) -> Stream {
    let mut encoder = Encoder::new(window_bits, e8_file_size);
    for block in blocks {
        encoder.block(block);
    }
    encoder.finish()
}

/// The literals of `bytes`.
pub fn literals(bytes: &[u8]) -> Vec<Token> {
    bytes.iter().map(|&b| Token::Literal(b)).collect()
}
