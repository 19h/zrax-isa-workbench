//! A small LZMS encoder for tests, written from wimlib v1.14.5's description
//! of the format (`src/lzms_decompress.c`) and its compressor's range
//! encoder, backward bitstream and finalization (`src/lzms_compress.c`),
//! code construction (`make_canonical_huffman_code`, `src/compress_common.c`)
//! and x86 filter (`lzms_x86_filter`, `src/lzms_common.c`), since no LZMS
//! encoder is installed. 7-Zip 26.03 decodes its output (see
//! `tests/fixtures/wim/README.md`). Callers give items, or `compress` finds
//! LZ matches greedily (explicit offsets and the repeated offsets of the
//! queue).

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

const MAX_CODE_LENGTH: usize = 15;
const PROBABILITY_BITS: u32 = 6;
const LITERAL_SYMBOLS: usize = 256;
const LENGTH_SYMBOLS: usize = 54;
const DELTA_POWER_SYMBOLS: usize = 8;
const MAX_OFFSET_SYMBOLS: usize = 799;

/// Extra bits of the offset slots as runs (bits, slots), and of the length
/// slots (`lzms_extra_offset_bits`, `lzms_extra_length_bits`).
const OFFSET_EXTRA_BITS_RUNS: [(u32, usize); 21] = [
    (0, 8),
    (2, 9),
    (3, 7),
    (4, 10),
    (5, 15),
    (6, 15),
    (7, 20),
    (8, 20),
    (9, 30),
    (10, 33),
    (11, 40),
    (12, 42),
    (13, 45),
    (14, 60),
    (15, 73),
    (16, 80),
    (17, 85),
    (18, 95),
    (19, 105),
    (20, 6),
    (30, 1),
];
const LENGTH_EXTRA_BITS: [u32; LENGTH_SYMBOLS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30,
];

fn offset_extra_bits() -> Vec<u32> {
    OFFSET_EXTRA_BITS_RUNS
        .iter()
        .flat_map(|&(bits, count)| std::iter::repeat(bits).take(count))
        .collect()
}

/// Slot bases: 1, then each grows by `1 << bits` of the slot before.
fn bases(extra: &[u32]) -> Vec<u64> {
    let mut out = vec![1u64];
    for &bits in extra {
        out.push(out.last().unwrap() + (1 << bits));
    }
    out
}

/// The slot of `value` and its extra bits.
fn slot(value: u64, bases: &[u64]) -> usize {
    bases.partition_point(|&base| base <= value) - 1
}

/// One item of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    Literal(u8),
    /// An LZ match with an explicit offset.
    Lz {
        length: usize,
        offset: u32,
    },
    /// An LZ match with the queue's repeated offset `index` (0-2).
    LzRep {
        length: usize,
        index: usize,
    },
    /// A delta match with an explicit power and raw offset.
    Delta {
        length: usize,
        power: u32,
        raw_offset: u32,
    },
    /// A delta match with the queue's repeated source `index` (0-2).
    DeltaRep {
        length: usize,
        index: usize,
    },
}

/// A probability entry and the decision class states, as the decoder keeps
/// them.
#[derive(Clone, Copy)]
struct Probability {
    zeros: u32,
    recent: u64,
}

impl Probability {
    const INITIAL: Self = Self {
        zeros: 48,
        recent: 0x5555_5555,
    };

    fn of_zero(self) -> u32 {
        self.zeros.clamp(1, 63)
    }

    fn update(&mut self, bit: u32) {
        self.zeros = self.zeros + (self.recent >> 63) as u32 - bit;
        self.recent = (self.recent << 1) | u64::from(bit);
    }
}

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

    fn encode(&mut self, rc: &mut RangeEncoder, bit: bool) {
        let bit = u32::from(bit);
        let entry = &mut self.entries[self.state];
        let probability = entry.of_zero();
        entry.update(bit);
        self.state = ((self.state << 1) | bit as usize) & (self.entries.len() - 1);
        rc.encode(bit, probability);
    }
}

/// The range encoder of `lzms_compress.c`: 16-bit units, delayed for
/// carries.
struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u16,
    cache_size: u32,
    out: Vec<u16>,
    /// The first unit is a placeholder that is never written.
    started: bool,
}

impl RangeEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
            started: false,
        }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xffff_0000 || (self.low >> 32) != 0 {
            loop {
                if self.started {
                    self.out
                        .push(self.cache.wrapping_add((self.low >> 32) as u16));
                }
                self.started = true;
                self.cache = 0xffff;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 16) & 0xffff) as u16;
        }
        self.cache_size += 1;
        self.low = (self.low & 0xffff) << 16;
    }

    fn encode(&mut self, bit: u32, probability: u32) {
        if self.range <= 0xffff {
            self.range <<= 16;
            self.shift_low();
        }
        let bound = (self.range >> PROBABILITY_BITS) * probability;
        if bit == 0 {
            self.range = bound;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
        }
    }

    fn finish(mut self) -> Vec<u16> {
        for _ in 0..4 {
            self.shift_low();
        }
        self.out
    }
}

/// The backward bitstream: units in the order written, which is from the
/// end of the stream towards its start.
#[derive(Default)]
struct BitWriter {
    buffer: u64,
    count: u32,
    units: Vec<u16>,
}

impl BitWriter {
    fn bits(&mut self, value: u64, n: u32) {
        if n == 0 {
            return;
        }
        self.buffer = (self.buffer << n) | value;
        self.count += n;
        while self.count >= 16 {
            self.count -= 16;
            self.units.push((self.buffer >> self.count) as u16);
        }
    }

    fn finish(mut self) -> Vec<u16> {
        if self.count != 0 {
            self.units.push((self.buffer << (16 - self.count)) as u16);
        }
        self.units
    }
}

/// Canonical code lengths as wimlib's `make_canonical_huffman_code` builds
/// them (see the decoder): leaves before internal nodes on frequency ties,
/// longest codes to the least frequent and then lowest symbols.
pub fn canonical_lengths(freqs: &[u32]) -> Vec<u8> {
    let mut lengths = vec![0u8; freqs.len().max(2)];
    let mut sorted: Vec<(u32, usize)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(s, &f)| (f, s))
        .collect();
    sorted.sort_unstable();
    if sorted.len() < 2 {
        if let Some(&(_, symbol)) = sorted.first() {
            lengths[symbol] = 1;
            lengths[if symbol == 0 { 1 } else { 0 }] = 1;
        }
        return lengths;
    }
    let n = sorted.len();
    let mut freq = vec![0u64; n - 1];
    let mut parent = vec![0usize; n - 1];
    let (mut i, mut b, mut e) = (0, 0, 0);
    let leaf = |k: usize| u64::from(sorted[k].0);
    while e < n - 1 {
        let f = if i + 1 < n && (b == e || leaf(i + 1) <= freq[b]) {
            i += 2;
            leaf(i - 2) + leaf(i - 1)
        } else if b + 2 <= e && (i >= n || freq[b + 1] < leaf(i)) {
            parent[b] = e;
            parent[b + 1] = e;
            b += 2;
            freq[b - 2] + freq[b - 1]
        } else {
            parent[b] = e;
            b += 1;
            i += 1;
            leaf(i - 1) + freq[b - 1]
        };
        freq[e] = f;
        e += 1;
    }
    let mut counts = [0usize; MAX_CODE_LENGTH + 1];
    counts[1] = 2;
    let mut depth = vec![0usize; n - 1];
    for node in (0..n - 2).rev() {
        depth[node] = depth[parent[node]] + 1;
        let mut length = depth[node];
        if length >= MAX_CODE_LENGTH {
            length = MAX_CODE_LENGTH;
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
    let mut next = 0;
    for length in (1..=MAX_CODE_LENGTH).rev() {
        for _ in 0..counts[length] {
            lengths[sorted[next].1] = length as u8;
            next += 1;
        }
    }
    lengths
}

/// Canonical codewords for `lengths`.
fn codewords(lengths: &[u8]) -> Vec<u32> {
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

/// An adaptive code: frequencies start at 1, and the code is rebuilt every
/// `rebuild` symbols, after which the frequencies are halved and
/// incremented.
struct AdaptiveCode {
    freqs: Vec<u32>,
    rebuild: u32,
    until: u32,
    lengths: Vec<u8>,
    codes: Vec<u32>,
}

impl AdaptiveCode {
    fn new(symbols: usize, rebuild: u32) -> Self {
        let mut code = Self {
            freqs: vec![1; symbols],
            rebuild,
            until: rebuild,
            lengths: Vec::new(),
            codes: Vec::new(),
        };
        code.build();
        code
    }

    fn build(&mut self) {
        self.lengths = canonical_lengths(&self.freqs);
        self.codes = codewords(&self.lengths);
        self.until = self.rebuild;
    }

    fn encode(&mut self, w: &mut BitWriter, symbol: usize) {
        assert!(self.lengths[symbol] > 0, "symbol {symbol} has a code");
        w.bits(
            u64::from(self.codes[symbol]),
            u32::from(self.lengths[symbol]),
        );
        self.freqs[symbol] += 1;
        self.until -= 1;
        if self.until == 0 {
            self.build();
            for f in &mut self.freqs {
                *f = (*f >> 1) + 1;
            }
        }
    }
}

/// The source of a delta match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeltaSource {
    power: u32,
    raw_offset: u32,
}

/// What the previous item was, for the delayed queue insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Literal,
    Lz,
    Delta,
}

/// Encodes items and keeps the decoded bytes (before the x86 filter is
/// undone).
pub struct Encoder {
    rc: RangeEncoder,
    w: BitWriter,
    main: Decision,
    match_kind: Decision,
    lz: Decision,
    lz_rep: [Decision; 2],
    delta: Decision,
    delta_rep: [Decision; 2],
    literals: AdaptiveCode,
    lz_offsets: AdaptiveCode,
    lengths: AdaptiveCode,
    delta_offsets: AdaptiveCode,
    delta_powers: AdaptiveCode,
    lz_queue: [u32; 4],
    delta_queue: [DeltaSource; 4],
    previous: Kind,
    offset_bases: Vec<u64>,
    offset_extra: Vec<u32>,
    length_bases: Vec<u64>,
    /// The output so far, as the decoder produces it.
    pub out: Vec<u8>,
}

impl Encoder {
    /// An encoder for a buffer of `size` bytes, which sets the number of
    /// offset slots.
    pub fn new(size: usize) -> Self {
        let offset_extra = offset_extra_bits();
        let offset_bases = bases(&offset_extra);
        let slots = if size < 2 {
            0
        } else {
            slot((size - 1) as u64, &offset_bases[..MAX_OFFSET_SYMBOLS]) + 1
        };
        Self {
            rc: RangeEncoder::new(),
            w: BitWriter::default(),
            main: Decision::new(16),
            match_kind: Decision::new(32),
            lz: Decision::new(64),
            lz_rep: [Decision::new(64), Decision::new(64)],
            delta: Decision::new(64),
            delta_rep: [Decision::new(64), Decision::new(64)],
            literals: AdaptiveCode::new(LITERAL_SYMBOLS, 1024),
            lz_offsets: AdaptiveCode::new(slots, 1024),
            lengths: AdaptiveCode::new(LENGTH_SYMBOLS, 512),
            delta_offsets: AdaptiveCode::new(slots, 1024),
            delta_powers: AdaptiveCode::new(DELTA_POWER_SYMBOLS, 512),
            lz_queue: [1, 2, 3, 4],
            delta_queue: [1, 2, 3, 4].map(|raw_offset| DeltaSource {
                power: 0,
                raw_offset,
            }),
            previous: Kind::Literal,
            offset_bases,
            offset_extra,
            length_bases: bases(&LENGTH_EXTRA_BITS),
            out: Vec::new(),
        }
    }

    fn repeat(rc: &mut RangeEncoder, decisions: &mut [Decision; 2], index: usize) {
        for decision in decisions.iter_mut().take(index) {
            decision.encode(rc, true);
        }
        if index < 2 {
            decisions[index].encode(rc, false);
        }
    }

    fn offset_value(&mut self, value: u32, delta: bool) {
        let slot = slot(u64::from(value), &self.offset_bases);
        let code = if delta {
            &mut self.delta_offsets
        } else {
            &mut self.lz_offsets
        };
        code.encode(&mut self.w, slot);
        self.w.bits(
            u64::from(value) - self.offset_bases[slot],
            self.offset_extra[slot],
        );
    }

    fn length(&mut self, length: usize) {
        let slot = slot(length as u64, &self.length_bases);
        self.lengths.encode(&mut self.w, slot);
        self.w.bits(
            length as u64 - self.length_bases[slot],
            LENGTH_EXTRA_BITS[slot],
        );
    }

    /// The LZ offset that repeat index `index` names now.
    pub fn lz_rep_offset(&self, index: usize) -> u32 {
        self.lz_queue[index + usize::from(self.previous == Kind::Lz)]
    }

    /// The delta source that repeat index `index` names now.
    fn delta_rep_source(&self, index: usize) -> DeltaSource {
        self.delta_queue[index + usize::from(self.previous == Kind::Delta)]
    }

    /// Encode one item and append its bytes to `out`.
    pub fn item(&mut self, item: Item) {
        match item {
            Item::Literal(byte) => {
                self.main.encode(&mut self.rc, false);
                self.literals.encode(&mut self.w, usize::from(byte));
                self.out.push(byte);
                self.previous = Kind::Literal;
            }
            Item::Lz { length, offset } => {
                self.main.encode(&mut self.rc, true);
                self.match_kind.encode(&mut self.rc, false);
                self.lz.encode(&mut self.rc, false);
                self.offset_value(offset, false);
                self.lz_queue.copy_within(0..3, 1);
                self.lz_queue[0] = offset;
                self.previous = Kind::Lz;
                self.length(length);
                self.copy(offset as usize, length);
            }
            Item::LzRep { length, index } => {
                self.main.encode(&mut self.rc, true);
                self.match_kind.encode(&mut self.rc, false);
                self.lz.encode(&mut self.rc, true);
                Self::repeat(&mut self.rc, &mut self.lz_rep, index);
                let at = index + usize::from(self.previous == Kind::Lz);
                let offset = self.lz_queue[at];
                self.lz_queue.copy_within(0..at, 1);
                self.lz_queue[0] = offset;
                self.previous = Kind::Lz;
                self.length(length);
                self.copy(offset as usize, length);
            }
            Item::Delta {
                length,
                power,
                raw_offset,
            } => {
                self.main.encode(&mut self.rc, true);
                self.match_kind.encode(&mut self.rc, true);
                self.delta.encode(&mut self.rc, false);
                self.delta_powers.encode(&mut self.w, power as usize);
                self.offset_value(raw_offset, true);
                let source = DeltaSource { power, raw_offset };
                self.delta_queue.copy_within(0..3, 1);
                self.delta_queue[0] = source;
                self.previous = Kind::Delta;
                self.length(length);
                self.copy_delta(source, length);
            }
            Item::DeltaRep { length, index } => {
                self.main.encode(&mut self.rc, true);
                self.match_kind.encode(&mut self.rc, true);
                self.delta.encode(&mut self.rc, true);
                Self::repeat(&mut self.rc, &mut self.delta_rep, index);
                let at = index + usize::from(self.previous == Kind::Delta);
                let source = self.delta_queue[at];
                self.delta_queue.copy_within(0..at, 1);
                self.delta_queue[0] = source;
                self.previous = Kind::Delta;
                self.length(length);
                self.copy_delta(source, length);
            }
        }
    }

    fn copy(&mut self, offset: usize, length: usize) {
        let start = self.out.len() - offset;
        for i in 0..length {
            let byte = self.out[start + i];
            self.out.push(byte);
        }
    }

    fn copy_delta(&mut self, source: DeltaSource, length: usize) {
        let span = 1usize << source.power;
        let offset = (source.raw_offset as usize) << source.power;
        for _ in 0..length {
            let at = self.out.len();
            let byte = self.out[at - offset]
                .wrapping_add(self.out[at - span])
                .wrapping_sub(self.out[at - offset - span]);
            self.out.push(byte);
        }
    }

    /// The stream: the range encoder's units, then the bitstream's units
    /// in reverse order of writing (`lzms_finalize`).
    pub fn finish(self) -> Vec<u8> {
        let forward = self.rc.finish();
        let mut backward = self.w.finish();
        backward.reverse();
        forward
            .iter()
            .chain(&backward)
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }
}

/// The x86 filter of `lzms_x86_filter`: compressing (`undo` false),
/// relative targets of likely instructions become absolute; decompressing,
/// they become relative again.
pub fn x86_filter(data: &mut [u8], undo: bool) {
    if data.len() <= 17 {
        return;
    }
    let tail = data.len() - 16;
    let mut usages = vec![-65_536i32; 1 << 16];
    let mut last = -1024i32;
    let mut p = 1;
    loop {
        while p < tail && !matches!(data[p], 0x48 | 0x4c | 0xe8 | 0xe9 | 0xf0 | 0xff) {
            p += 1;
        }
        if p >= tail {
            break;
        }
        let (size, max) = match data[p] {
            0xff if data[p + 1] == 0x15 => (2, 1023),
            0xf0 if data[p + 1] == 0x83 && data[p + 2] == 0x05 => (3, 1023),
            0x48 | 0x4c
                if data[p + 2] & 7 == 5
                    && (data[p + 1] == 0x8d
                        || (data[p + 1] == 0x8b
                            && data[p] & 4 == 0
                            && data[p + 2] & 0xf0 == 0)) =>
            {
                (3, 1023)
            }
            0xe8 => (1, 511),
            0xe9 => {
                p += 5;
                continue;
            }
            _ => {
                p += 1;
                continue;
            }
        };
        let i = p as i32;
        let operand = p + size;
        let low = |data: &[u8]| u16::from_le_bytes([data[operand], data[operand + 1]]);
        let mut target = (i as u16).wrapping_add(low(data));
        if i - last <= max {
            let n = u32::from_le_bytes(data[operand..operand + 4].try_into().unwrap());
            let n = if undo {
                n.wrapping_sub(i as u32)
            } else {
                n.wrapping_add(i as u32)
            };
            data[operand..operand + 4].copy_from_slice(&n.to_le_bytes());
            if undo {
                target = (i as u16).wrapping_add(low(data));
            }
        }
        let end = i + size as i32 + 3;
        if end - usages[usize::from(target)] <= 65_535 {
            last = end;
        }
        usages[usize::from(target)] = end;
        p = operand + 4;
    }
}

/// The length of a delta match at `i` with span `1 << power` and offset
/// `raw_offset << power`.
fn delta_length(data: &[u8], i: usize, power: u32, raw_offset: u32) -> usize {
    let span = 1usize << power;
    let offset = (raw_offset as usize) << power;
    if offset == 0 || offset + span > i {
        return 0;
    }
    (0..data.len() - i)
        .take_while(|&k| {
            let at = i + k;
            data[at]
                == data[at - offset]
                    .wrapping_add(data[at - span])
                    .wrapping_sub(data[at - offset - span])
        })
        .count()
}

/// Powers and raw offsets of the delta matches `compress` tries.
const DELTA_POWERS: u32 = 3;
const DELTA_RAW_OFFSETS: u32 = 4;

/// Compress `data` with greedy matches, after the x86 filter: LZ matches
/// with explicit offsets from a hash of three bytes or with the repeated
/// offsets, and delta matches with small powers and raw offsets, explicit
/// or repeated, when they are longer.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut filtered = data.to_vec();
    x86_filter(&mut filtered, false);
    let mut encoder = Encoder::new(filtered.len());
    let mut heads: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
    let mut i = 0;
    let match_length = |i: usize, offset: usize| {
        if offset == 0 || offset > i {
            return 0;
        }
        (0..filtered.len() - i)
            .take_while(|&k| filtered[i + k] == filtered[i + k - offset])
            .count()
    };
    while i < filtered.len() {
        let mut best = (0usize, None::<usize>, 0usize);
        for index in 0..3 {
            let offset = encoder.lz_rep_offset(index) as usize;
            let length = match_length(i, offset);
            if length > best.0 {
                best = (length, Some(index), offset);
            }
        }
        if let Some(at) = filtered
            .get(i..i + 3)
            .and_then(|k| heads.get(&[k[0], k[1], k[2]]).copied())
        {
            let length = match_length(i, i - at);
            if length > best.0 + 1 {
                best = (length, None, i - at);
            }
        }
        let (length, rep, offset) = best;
        let mut delta = None;
        for index in 0..3 {
            let source = encoder.delta_rep_source(index);
            let found = delta_length(&filtered, i, source.power, source.raw_offset);
            if found > length.max(delta.map_or(0, |(l, _)| l)) + 2 {
                delta = Some((
                    found,
                    Item::DeltaRep {
                        length: found,
                        index,
                    },
                ));
            }
        }
        for power in 0..DELTA_POWERS {
            for raw_offset in 1..=DELTA_RAW_OFFSETS {
                let found = delta_length(&filtered, i, power, raw_offset);
                if found > length.max(delta.map_or(0, |(l, _)| l)) + 4 {
                    delta = Some((
                        found,
                        Item::Delta {
                            length: found,
                            power,
                            raw_offset,
                        },
                    ));
                }
            }
        }
        if let Some((found, item)) = delta {
            for at in i..(i + found).min(filtered.len().saturating_sub(2)) {
                heads.insert([filtered[at], filtered[at + 1], filtered[at + 2]], at);
            }
            encoder.item(item);
            i += found;
            continue;
        }
        let step = if length >= 3 { length } else { 1 };
        for at in i..(i + step).min(filtered.len().saturating_sub(2)) {
            heads.insert([filtered[at], filtered[at + 1], filtered[at + 2]], at);
        }
        match (length >= 3, rep) {
            (true, Some(index)) => encoder.item(Item::LzRep { length, index }),
            (true, None) => encoder.item(Item::Lz {
                length,
                offset: offset as u32,
            }),
            (false, _) => encoder.item(Item::Literal(filtered[i])),
        }
        i += step;
    }
    assert_eq!(encoder.out, filtered);
    encoder.finish()
}
