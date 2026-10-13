//! EFI 1.1 and Tiano compression: the LZ77 and Huffman format of the UEFI
//! decompress protocol and of PI compression sections.
//!
//! Bitstream: UEFI 2.10, chapter 19 "Compression Algorithm Specification",
//! section 19.2 (data format). Decoder behavior: EDK2 edk2-stable202408
//! (commit `b158dad150bf02879668f72ce306445250838201`)
//! `MdePkg/Library/BaseUefiDecompressLib/BaseUefiDecompressLib.c`, which
//! also implements the Tiano variant: the same format with a 5-bit position
//! set size field (`mPBit` 5) instead of a 4-bit one. The order of the
//! table fields follows that decoder; UEFI 2.10 Table 19.1 lists them in a
//! garbled order.
//!
//! Header: compressed size (u32 LE, the bytes after the header) and
//! original size (u32 LE). Blocks follow until the original size has been
//! produced. Each block holds its symbol count (16 bits), the extra set
//! code lengths, the char-and-length code lengths and the position set code
//! lengths, then the symbols. Bits are read most significant first.
//!
//! The decoder is stricter than EDK2 where EDK2 relies on unchecked or
//! undefined behavior: incomplete or oversubscribed codes, length counts
//! larger than their alphabet, single-symbol codes outside the alphabet,
//! back-references before the start of the output, a zero block size and
//! reads past the compressed size are errors.

use super::*;

/// Header: compressed size and original size.
const HEADER_SIZE: usize = 8;

/// Longest match (`MAXMATCH`).
const MAX_MATCH: usize = 256;

/// Shortest match (`THRESHOLD`).
const THRESHOLD: usize = 3;

/// Longest Huffman code (`CODE_BIT`).
const MAX_CODE_LENGTH: usize = 16;

/// Bits peeked to decode one symbol: the longest code.
const CODE_WINDOW_BITS: u32 = 16;

/// Char-and-length alphabet: 256 literals, then match lengths 3 to 256
/// (`NC`, 510 symbols).
const NC: usize = 0xFF + MAX_MATCH + 2 - THRESHOLD;

/// First char-and-length symbol that encodes a match.
const FIRST_MATCH_SYMBOL: usize = 256;

/// Width of the char-and-length code length count (`CBIT`).
const CBIT: u32 = 9;

/// Extra set alphabet: three zero-run codes, then code lengths 1 to 16
/// (`NT`, 19 symbols).
const NT: usize = MAX_CODE_LENGTH + 3;

/// Width of the extra set code length count (`TBIT`).
const TBIT: u32 = 5;

/// Position set alphabet: bit lengths of the position value, 0 to 30
/// (`MAXNP`, 31 symbols, sized for the Tiano variant).
const MAXNP: usize = 31;

/// The extra set code lengths carry a two-bit zero-run count after the
/// third length (`special` 3 in `ReadPTLen`).
const EXTRA_SET_SPECIAL: usize = 3;

/// Width of the block symbol count.
const BLOCK_SIZE_BITS: u32 = 16;

/// Width of a stored code length; the value 7 starts a unary extension.
const LENGTH_BITS: u32 = 3;
const LENGTH_ESCAPE: u32 = 7;

/// Width of the zero-run count in the extra set.
const ZERO_RUN_BITS: u32 = 2;

/// Char-and-length zero-run codes: one zero, 3 to 18 zeros (4-bit count),
/// 20 to 531 zeros (9-bit count).
const RUN_ONE: u16 = 0;
const RUN_SHORT: u16 = 1;
const RUN_LONG: u16 = 2;
const RUN_SHORT_BITS: u32 = 4;
const RUN_SHORT_BASE: usize = 3;
const RUN_LONG_BASE: usize = 20;

/// Extra set symbols above the zero-run codes encode a code length plus
/// this offset.
const LENGTH_SYMBOL_OFFSET: u16 = 2;

/// Lookup table widths, as in the EDK2 decoder: 12 bits for the
/// char-and-length code and 8 bits for the extra and position sets.
const C_TABLE_BITS: u32 = 12;
const PT_TABLE_BITS: u32 = 8;

/// Width of the position set code length count (`mPBit`): 4 for EFI 1.1,
/// 5 for Tiano.
const EFI_PBIT: u32 = 4;
const TIANO_PBIT: u32 = 5;

/// The bit reader assembles a peek window of 40 bits (5 bytes), enough
/// for 32 bits at any bit offset.
const WINDOW_BITS: u32 = 40;
const WINDOW_BYTES: usize = (WINDOW_BITS / 8) as usize;

/// The two variants differ only in the width of the position set code
/// length count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Variant {
    /// EFI 1.1 / UEFI compression (`mPBit` 4).
    Efi,
    /// Tiano compression (`mPBit` 5).
    Tiano,
}

impl Variant {
    fn position_bits(self) -> u32 {
        match self {
            Self::Efi => EFI_PBIT,
            Self::Tiano => TIANO_PBIT,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Efi => Codec::Efi.name(),
            Self::Tiano => Codec::Tiano.name(),
        }
    }
}

/// Reads bits most significant first from the compressed bytes. Peeking
/// past the end yields zero bits, as in EDK2; consuming past the end is an
/// error, because a complete stream never needs those bits.
struct BitReader<'a> {
    bytes: &'a [u8],
    /// Bits consumed so far.
    position: u64,
    variant: Variant,
}

impl BitReader<'_> {
    /// The next `count` bits (at most 32) without consuming them.
    fn peek(&self, count: u32) -> u32 {
        let first = usize::try_from(self.position / 8).unwrap_or(usize::MAX);
        let shift = self.position % 8;
        let window = (0..WINDOW_BYTES).fold(0u64, |window, i| {
            let byte = first
                .checked_add(i)
                .and_then(|at| self.bytes.get(at))
                .copied()
                .unwrap_or(0);
            (window << 8) | u64::from(byte)
        });
        // Drop the consumed bits above the window, then keep `count` bits.
        let bits = (window << shift) >> (WINDOW_BITS - count);
        let mask = (1u64 << count) - 1;
        u32::try_from(bits & mask).expect("masked to at most 32 bits")
    }

    fn skip(&mut self, count: u32) -> Result<()> {
        self.position += u64::from(count);
        if self.position > (self.bytes.len() as u64) * 8 {
            return Err(error(format!(
                "Truncated {} stream: bits past the compressed size",
                self.variant.name()
            )));
        }
        Ok(())
    }

    fn bits(&mut self, count: u32) -> Result<u32> {
        let value = self.peek(count);
        self.skip(count)?;
        Ok(value)
    }

    fn invalid(&self, what: &str) -> ClassifierError {
        error(format!("Invalid {} {what}", self.variant.name()))
    }
}

/// A prefix code over a small alphabet, or a single symbol that takes no
/// bits (a code length count of 0 in the stream).
enum Code {
    Single(u16),
    Canonical(Canonical),
}

/// A canonical Huffman code: codes of each length are consecutive, shorter
/// codes come first, and symbols of one length are in increasing order
/// (`MakeTable` in EDK2).
struct Canonical {
    /// Width of the lookup table: the longest code, at most the EDK2 table
    /// width, so a block with short codes does not fill a 4096-entry table.
    table_bits: u32,
    /// Symbol and code length for every `table_bits`-bit prefix of a code
    /// that fits; a length of 0 marks the prefix of a longer code.
    table: Vec<(u16, u8)>,
    /// Number of codes of each length 1 to 16.
    counts: [u16; MAX_CODE_LENGTH + 1],
    /// Symbols ordered by code length, then by symbol.
    symbols: Vec<u16>,
}

impl Code {
    /// Build the code for `lengths`, which must describe a complete prefix
    /// code (the Kraft sum is exactly one). The work is linear in the
    /// alphabet plus the table size, because a stream can start a new
    /// block (and new codes) every few dozen bits.
    fn canonical(lengths: &[u8], max_table_bits: u32, reader: &BitReader<'_>) -> Result<Self> {
        let mut counts = [0u16; MAX_CODE_LENGTH + 1];
        for &length in lengths {
            let length = usize::from(length);
            if length > MAX_CODE_LENGTH {
                return Err(reader.invalid("code length"));
            }
            counts[length] += 1;
        }
        counts[0] = 0;
        let kraft: u32 = (1..=MAX_CODE_LENGTH)
            .map(|length| u32::from(counts[length]) << (MAX_CODE_LENGTH - length))
            .sum();
        if kraft != 1 << MAX_CODE_LENGTH {
            return Err(reader.invalid("Huffman table"));
        }
        // First code of each length, and where each length's symbols start
        // in the sorted symbol list.
        let mut first_code = [0u32; MAX_CODE_LENGTH + 2];
        let mut first_index = [0usize; MAX_CODE_LENGTH + 2];
        for length in 1..=MAX_CODE_LENGTH {
            first_code[length + 1] = (first_code[length] + u32::from(counts[length])) << 1;
            first_index[length + 1] = first_index[length] + usize::from(counts[length]);
        }
        let mut symbols = vec![0u16; first_index[MAX_CODE_LENGTH + 1]];
        let mut next_index = first_index;
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let slot = &mut next_index[usize::from(length)];
                symbols[*slot] = u16::try_from(symbol).expect("alphabets have at most NC symbols");
                *slot += 1;
            }
        }
        let longest = (1..=MAX_CODE_LENGTH)
            .rev()
            .find(|&length| counts[length] != 0)
            .expect("a complete code has at least one code");
        let table_bits = max_table_bits.min(u32::try_from(longest).expect("at most 16"));
        let mut table = vec![(0u16, 0u8); 1 << table_bits];
        for length in 1..=MAX_CODE_LENGTH {
            let bits = u32::try_from(length).expect("at most 16");
            if bits > table_bits {
                break;
            }
            let span = 1usize << (table_bits - bits);
            let entry_length = u8::try_from(length).expect("at most 16");
            let codes = first_index[length]..first_index[length + 1];
            for (code, &symbol) in (first_code[length]..).zip(&symbols[codes]) {
                // The Kraft check keeps every code below 2^length, so the
                // span ends inside the table.
                let first = usize::try_from(code).expect("below 2^16") * span;
                table[first..first + span].fill((symbol, entry_length));
            }
        }
        Ok(Self::Canonical(Canonical {
            table_bits,
            table,
            counts,
            symbols,
        }))
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16> {
        let code = match self {
            Self::Single(symbol) => return Ok(*symbol),
            Self::Canonical(code) => code,
        };
        let window = reader.peek(CODE_WINDOW_BITS);
        let prefix = usize::try_from(window >> (CODE_WINDOW_BITS - code.table_bits))
            .expect("at most 16 bits");
        let (symbol, length) = code.table[prefix];
        if length != 0 {
            reader.skip(u32::from(length))?;
            return Ok(symbol);
        }
        // A code longer than the table: walk the canonical code one bit at
        // a time (codes of one length are consecutive values, and in a
        // complete code a prefix never falls below the first code of its
        // length without having matched a shorter code).
        let mut value = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for length in 1..=CODE_WINDOW_BITS {
            value |= (window >> (CODE_WINDOW_BITS - length)) & 1;
            let count = u32::from(code.counts[length as usize]);
            if let Some(offset) = value.checked_sub(first).filter(|&offset| offset < count) {
                reader.skip(length)?;
                let symbol = index + offset as usize;
                return code
                    .symbols
                    .get(symbol)
                    .copied()
                    .ok_or_else(|| reader.invalid("Huffman code"));
            }
            index += count as usize;
            first = (first + count) << 1;
            value <<= 1;
        }
        Err(reader.invalid("Huffman code"))
    }
}

/// One code length: three bits, or 7 followed by a unary extension (each
/// further 1 bit adds one, a 0 bit ends it).
fn code_length(reader: &mut BitReader<'_>) -> Result<u8> {
    let mut length = reader.bits(LENGTH_BITS)?;
    if length == LENGTH_ESCAPE {
        while reader.bits(1)? == 1 {
            length += 1;
            if length as usize > MAX_CODE_LENGTH {
                return Err(reader.invalid("code length"));
            }
        }
    }
    Ok(u8::try_from(length).expect("at most 16"))
}

/// The extra set or position set code (`ReadPTLen`): a length count of
/// `count_bits` bits, then that many code lengths; the extra set has a
/// zero-run count after its third length.
fn read_pt_code(
    reader: &mut BitReader<'_>,
    alphabet: usize,
    count_bits: u32,
    special: Option<usize>,
) -> Result<Code> {
    let number = reader.bits(count_bits)? as usize;
    if number == 0 {
        let symbol = reader.bits(count_bits)?;
        if symbol as usize >= alphabet {
            return Err(reader.invalid("single-symbol code"));
        }
        return Ok(Code::Single(
            u16::try_from(symbol).expect("below the alphabet size"),
        ));
    }
    if number > alphabet {
        return Err(reader.invalid("code length count"));
    }
    let mut lengths = [0u8; MAXNP];
    let mut index = 0;
    while index < number {
        lengths[index] = code_length(reader)?;
        index += 1;
        if special == Some(index) {
            let zeros = reader.bits(ZERO_RUN_BITS)? as usize;
            index = (index + zeros).min(MAXNP);
        }
    }
    Code::canonical(&lengths[..alphabet], PT_TABLE_BITS, reader)
}

/// The char-and-length code (`ReadCLen`): a 9-bit length count, then the
/// lengths, each an extra set symbol: a zero run or a length plus two.
fn read_c_code(reader: &mut BitReader<'_>, extra: &Code) -> Result<Code> {
    let number = reader.bits(CBIT)? as usize;
    if number == 0 {
        let symbol = reader.bits(CBIT)?;
        if symbol as usize >= NC {
            return Err(reader.invalid("single-symbol code"));
        }
        return Ok(Code::Single(u16::try_from(symbol).expect("below NC")));
    }
    if number > NC {
        return Err(reader.invalid("code length count"));
    }
    let mut lengths = [0u8; NC];
    let mut index = 0;
    while index < number {
        let symbol = extra.decode(reader)?;
        let zeros = match symbol {
            RUN_ONE => 1,
            RUN_SHORT => reader.bits(RUN_SHORT_BITS)? as usize + RUN_SHORT_BASE,
            RUN_LONG => reader.bits(CBIT)? as usize + RUN_LONG_BASE,
            length => {
                lengths[index] = u8::try_from(length - LENGTH_SYMBOL_OFFSET)
                    .expect("extra set symbols are below NT");
                index += 1;
                continue;
            }
        };
        // Zero lengths are already in place; runs stop at the alphabet end.
        index = (index + zeros).min(NC);
    }
    Code::canonical(&lengths, C_TABLE_BITS, reader)
}

/// A position value: its bit length from the position code, then the bits
/// below the leading one.
fn read_position(reader: &mut BitReader<'_>, code: &Code) -> Result<usize> {
    let bits = u32::from(code.decode(reader)?);
    if bits <= 1 {
        return Ok(bits as usize);
    }
    let low = reader.bits(bits - 1)?;
    Ok(((1u32 << (bits - 1)) + low) as usize)
}

/// Decode an EFI 1.1 or Tiano stream into at most `limit` bytes.
pub(super) fn decode(data: &[u8], variant: Variant, limit: usize) -> Result<Decoded> {
    let name = variant.name();
    let compressed_size = usize::try_from(le_u32(data, 0)?)
        .map_err(|_| error(format!("Invalid {name} compressed size")))?;
    let original_size = usize::try_from(le_u32(data, 4)?)
        .map_err(|_| error(format!("Invalid {name} original size")))?;
    let available = data.len().saturating_sub(HEADER_SIZE);
    let stored = data
        .get(HEADER_SIZE..)
        .and_then(|rest| rest.get(..compressed_size))
        .ok_or_else(|| {
            error(format!(
                "Truncated {name} stream: compressed size {compressed_size} B, {available} B present"
            ))
        })?;
    if original_size > limit {
        return Err(exceeds(limit));
    }
    let consumed = Some(HEADER_SIZE + compressed_size);
    let mut out = Vec::with_capacity(original_size.min(stored.len().saturating_mul(8)));
    let mut reader = BitReader {
        bytes: stored,
        position: 0,
        variant,
    };
    let mut block_left = 0u32;
    let mut codes: Option<(Code, Code)> = None;
    while out.len() < original_size {
        if block_left == 0 {
            block_left = reader.bits(BLOCK_SIZE_BITS)?;
            if block_left == 0 {
                return Err(reader.invalid("block size 0"));
            }
            let extra = read_pt_code(&mut reader, NT, TBIT, Some(EXTRA_SET_SPECIAL))?;
            let chars = read_c_code(&mut reader, &extra)?;
            let positions = read_pt_code(&mut reader, MAXNP, variant.position_bits(), None)?;
            codes = Some((chars, positions));
        }
        block_left -= 1;
        let (chars, positions) = codes.as_ref().expect("read with the block header");
        let symbol = usize::from(chars.decode(&mut reader)?);
        if symbol < FIRST_MATCH_SYMBOL {
            out.push(u8::try_from(symbol).expect("literal symbols are bytes"));
            continue;
        }
        let length = symbol + THRESHOLD - FIRST_MATCH_SYMBOL;
        let distance = read_position(&mut reader, positions)? + 1;
        if distance > out.len() {
            return Err(error(format!(
                "Invalid {name} back-reference {distance} B before output offset 0x{:X}",
                out.len()
            )));
        }
        let from = out.len() - distance;
        for i in 0..length.min(original_size - out.len()) {
            // `from + i` stays below the current length: the copy source
            // starts `distance` (at least one) bytes before the end.
            out.push(out[from + i]);
        }
    }
    Ok(Decoded {
        data: out,
        consumed,
        check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes bits most significant first.
    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        bits: usize,
    }

    impl BitWriter {
        fn put(&mut self, count: u32, value: u32) {
            for i in (0..count).rev() {
                if self.bits % 8 == 0 {
                    self.bytes.push(0);
                }
                if (value >> i) & 1 == 1 {
                    let last = self.bytes.len() - 1;
                    self.bytes[last] |= 0x80 >> (self.bits % 8);
                }
                self.bits += 1;
            }
        }
    }

    /// A literal or a match of `length` bytes `distance` bytes back.
    #[derive(Clone, Copy)]
    enum Token {
        Literal(u8),
        Match { length: usize, distance: usize },
    }

    /// Canonical code of each symbol for `lengths` (as `MakeTable`).
    fn canonical_codes(lengths: &[u8]) -> Vec<u32> {
        let mut counts = [0u32; 18];
        for &l in lengths {
            counts[usize::from(l)] += 1;
        }
        counts[0] = 0;
        let mut next = [0u32; 18];
        for l in 1..17 {
            next[l + 1] = (next[l] + counts[l]) << 1;
        }
        lengths
            .iter()
            .map(|&l| {
                let code = next[usize::from(l)];
                next[usize::from(l)] += 1;
                code
            })
            .collect()
    }

    /// Complete code lengths for the used symbols: with `n` used symbols
    /// and `2^(k-1) < n <= 2^k`, `2^k - n` of them get `k - 1` bits and
    /// the rest `k` bits.
    fn flat_lengths(alphabet: usize, used: &[usize]) -> Vec<u8> {
        let n = used.len();
        let k = usize::BITS - (n - 1).leading_zeros();
        let short = (1usize << k) - n;
        let long = u8::try_from(k).expect("at most 9 bits");
        let mut lengths = vec![0u8; alphabet];
        for (i, &symbol) in used.iter().enumerate() {
            lengths[symbol] = if i < short { long - 1 } else { long };
        }
        lengths
    }

    /// A test value as a bit field value.
    fn bits32(value: usize) -> u32 {
        u32::try_from(value).expect("test values fit in 32 bits")
    }

    /// `ReadPTLen` input for `lengths` (no zero-run compression beyond a
    /// zero count at the special position), or the single-symbol form.
    fn put_pt_code(w: &mut BitWriter, lengths: &[u8], count_bits: u32, special: Option<usize>) {
        let used: Vec<usize> = (0..lengths.len()).filter(|&i| lengths[i] > 0).collect();
        if used.is_empty() {
            unreachable!("callers pass at least one symbol");
        }
        let number = used.last().unwrap() + 1;
        w.put(count_bits, bits32(number));
        for (i, &length) in lengths[..number].iter().enumerate() {
            if length < 7 {
                w.put(3, u32::from(length));
            } else {
                w.put(3, 7);
                for _ in 7..length {
                    w.put(1, 1);
                }
                w.put(1, 0);
            }
            if special == Some(i + 1) {
                w.put(2, 0);
            }
        }
    }

    fn put_single(w: &mut BitWriter, count_bits: u32, symbol: usize) {
        w.put(count_bits, 0);
        w.put(count_bits, bits32(symbol));
    }

    /// A prefix code the test encoder writes symbols with.
    struct EncoderCode {
        /// Code length of each symbol in bits; 0 for an unused symbol.
        lengths: Vec<u8>,
        /// Canonical code of each symbol, `lengths[symbol]` bits wide.
        codes: Vec<u32>,
    }

    /// A code over `used` symbols: written as a single symbol when only one
    /// is used, else as flat lengths. Returns the lengths and codes.
    fn code_for(alphabet: usize, used: &[usize]) -> Option<EncoderCode> {
        (used.len() > 1).then(|| {
            let lengths = flat_lengths(alphabet, used);
            let codes = canonical_codes(&lengths);
            EncoderCode { lengths, codes }
        })
    }

    fn put_symbol(w: &mut BitWriter, code: Option<&EncoderCode>, symbol: usize) {
        if let Some(code) = code {
            w.put(u32::from(code.lengths[symbol]), code.codes[symbol]);
        }
    }

    fn position_symbol(position: usize) -> usize {
        (usize::BITS - position.leading_zeros()) as usize
    }

    /// One block holding `tokens`, with explicit char-and-length lengths
    /// when given (else flat lengths over the used symbols).
    fn put_block(
        w: &mut BitWriter,
        tokens: &[Token],
        variant: Variant,
        c_lengths: Option<Vec<u8>>,
    ) {
        let c_symbol = |t: &Token| match *t {
            Token::Literal(b) => usize::from(b),
            Token::Match { length, .. } => length + FIRST_MATCH_SYMBOL - THRESHOLD,
        };
        let mut c_used: Vec<usize> = tokens.iter().map(c_symbol).collect();
        c_used.sort_unstable();
        c_used.dedup();
        let mut p_used: Vec<usize> = tokens
            .iter()
            .filter_map(|t| match *t {
                Token::Match { distance, .. } => Some(position_symbol(distance - 1)),
                Token::Literal(_) => None,
            })
            .collect();
        p_used.sort_unstable();
        p_used.dedup();
        if p_used.is_empty() {
            p_used.push(0);
        }
        w.put(16, bits32(tokens.len()));
        let c_code = match c_lengths {
            Some(lengths) => {
                let codes = canonical_codes(&lengths);
                Some(EncoderCode { lengths, codes })
            }
            None => code_for(NC, &c_used),
        };
        match &c_code {
            None => {
                // Single char-and-length symbol; the extra set is unused.
                put_single(w, TBIT, 0);
                put_single(w, CBIT, c_used[0]);
            }
            Some(EncoderCode { lengths, .. }) => {
                let number = lengths.iter().rposition(|&l| l > 0).unwrap() + 1;
                let mut t_used: Vec<usize> = lengths[..number]
                    .iter()
                    .map(|&l| if l == 0 { 0 } else { usize::from(l) + 2 })
                    .collect();
                t_used.sort_unstable();
                t_used.dedup();
                let t_code = code_for(NT, &t_used);
                match &t_code {
                    None => put_single(w, TBIT, t_used[0]),
                    Some(code) => put_pt_code(w, &code.lengths, TBIT, Some(3)),
                }
                w.put(CBIT, bits32(number));
                for &l in &lengths[..number] {
                    let symbol = if l == 0 { 0 } else { usize::from(l) + 2 };
                    put_symbol(w, t_code.as_ref(), symbol);
                }
            }
        }
        let p_code = code_for(MAXNP, &p_used);
        match &p_code {
            None => put_single(w, variant.position_bits(), p_used[0]),
            Some(code) => put_pt_code(w, &code.lengths, variant.position_bits(), None),
        }
        for t in tokens {
            put_symbol(w, c_code.as_ref(), c_symbol(t));
            if let Token::Match { distance, .. } = *t {
                let position = distance - 1;
                let symbol = position_symbol(position);
                put_symbol(w, p_code.as_ref(), symbol);
                if symbol > 1 {
                    w.put(bits32(symbol - 1), bits32(position - (1 << (symbol - 1))));
                }
            }
        }
    }

    /// Header (compressed size including the terminating zero byte, as the
    /// EDK2 encoder writes it, and original size), then the bitstream.
    fn stream(w: BitWriter, original_size: usize) -> Vec<u8> {
        let mut bytes = w.bytes;
        bytes.push(0);
        let mut out = bits32(bytes.len()).to_le_bytes().to_vec();
        out.extend_from_slice(&bits32(original_size).to_le_bytes());
        out.extend_from_slice(&bytes);
        out
    }

    fn expand(tokens: &[Token]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in tokens {
            match *t {
                Token::Literal(b) => out.push(b),
                Token::Match { length, distance } => {
                    for _ in 0..length {
                        out.push(out[out.len() - distance]);
                    }
                }
            }
        }
        out
    }

    fn sample_tokens() -> Vec<Token> {
        let mut tokens: Vec<Token> = b"UEFI compression "
            .iter()
            .map(|&b| Token::Literal(b))
            .collect();
        tokens.push(Token::Match {
            length: 17,
            distance: 17,
        });
        tokens.push(Token::Literal(b'!'));
        tokens.push(Token::Match {
            length: 256,
            distance: 1,
        });
        tokens.push(Token::Match {
            length: 5,
            distance: 280,
        });
        tokens
    }

    fn encode(tokens: &[Token], variant: Variant) -> Vec<u8> {
        let mut w = BitWriter::default();
        put_block(&mut w, tokens, variant, None);
        stream(w, expand(tokens).len())
    }

    #[test]
    fn literals_and_matches_round_trip_in_both_variants() {
        let tokens = sample_tokens();
        let expected = expand(&tokens);
        for variant in [Variant::Efi, Variant::Tiano] {
            let encoded = encode(&tokens, variant);
            let decoded = decode(&encoded, variant, MAX_PAYLOAD).unwrap();
            assert_eq!(decoded.data, expected, "{variant:?}");
            assert_eq!(decoded.consumed, Some(encoded.len()));
        }
    }

    #[test]
    fn tiano_positions_beyond_the_efi_alphabet_decode() {
        // Position symbol 20 needs a length count above 15, which only the
        // 5-bit Tiano field can express.
        let mut tokens: Vec<Token> = (0..=255u8).map(Token::Literal).collect();
        let filler = Token::Match {
            length: 256,
            distance: 256,
        };
        tokens.extend(std::iter::repeat(filler).take(4100));
        tokens.push(Token::Match {
            length: 3,
            distance: (1 << 19) + 77,
        });
        let expected = expand(&tokens);
        let encoded = encode(&tokens, Variant::Tiano);
        assert_eq!(
            decode(&encoded, Variant::Tiano, MAX_PAYLOAD).unwrap().data,
            expected
        );
        assert!(decode(&encoded, Variant::Efi, MAX_PAYLOAD).is_err());
    }

    #[test]
    fn single_symbol_codes_take_no_bits() {
        // One block of 10 symbols: extra set unused, char-and-length code
        // is the single symbol 'A', position code the single symbol 0.
        let mut w = BitWriter::default();
        w.put(16, 10);
        put_single(&mut w, TBIT, 0);
        put_single(&mut w, CBIT, usize::from(b'A'));
        put_single(&mut w, Variant::Efi.position_bits(), 0);
        let encoded = stream(w, 10);
        assert_eq!(
            decode(&encoded, Variant::Efi, 64).unwrap().data,
            b"AAAAAAAAAA"
        );
    }

    #[test]
    fn codes_longer_than_the_lookup_tables_decode() {
        // Char-and-length lengths 1, 2, ..., 16, 16 over 17 literals make
        // codes longer than the 12-bit table; their extra set lengths
        // (symbols 0 and 3 to 18) are again a 1, 2, ..., 16, 16 chain.
        let literals: Vec<u8> = (b'a'..=b'q').collect();
        let mut c_lengths = vec![0u8; NC];
        for (i, &b) in literals.iter().enumerate() {
            c_lengths[usize::from(b)] = u8::try_from((i + 1).min(16)).expect("at most 16");
        }
        let mut tokens: Vec<Token> = literals.iter().map(|&b| Token::Literal(b)).collect();
        tokens.extend(literals.iter().rev().map(|&b| Token::Literal(b)));
        let mut w = BitWriter::default();
        put_block(&mut w, &tokens, Variant::Efi, Some(c_lengths));
        let encoded = stream(w, tokens.len());
        assert_eq!(
            decode(&encoded, Variant::Efi, MAX_PAYLOAD).unwrap().data,
            expand(&tokens)
        );
    }

    #[test]
    fn invalid_streams_are_rejected() {
        let tokens = sample_tokens();
        let encoded = encode(&tokens, Variant::Efi);
        // Every truncation either fails the size check or runs out of bits.
        for end in 0..encoded.len() - 1 {
            assert!(
                decode(&encoded[..end], Variant::Efi, MAX_PAYLOAD).is_err(),
                "prefix {end}"
            );
        }
        // A compressed size that cuts the bitstream short.
        let mut short = encoded.clone();
        short[0] = 4;
        assert!(decode(&short, Variant::Efi, MAX_PAYLOAD).is_err());
        // An original size above the limit.
        assert!(decode(&encoded, Variant::Efi, 16).is_err());
        // A back-reference before the start of the output.
        let mut w = BitWriter::default();
        put_block(
            &mut w,
            &[
                Token::Literal(b'x'),
                Token::Match {
                    length: 3,
                    distance: 2,
                },
            ],
            Variant::Efi,
            None,
        );
        assert!(decode(&stream(w, 4), Variant::Efi, 64).is_err());
        // A zero block size.
        assert!(decode(&stream(BitWriter::default(), 4), Variant::Efi, 64).is_err());
        // An incomplete code: two literals with lengths 1 and 2.
        let mut c_lengths = vec![0u8; NC];
        c_lengths[usize::from(b'a')] = 1;
        c_lengths[usize::from(b'b')] = 2;
        let mut w = BitWriter::default();
        put_block(
            &mut w,
            &[Token::Literal(b'a'), Token::Literal(b'b')],
            Variant::Efi,
            Some(c_lengths),
        );
        assert!(decode(&stream(w, 2), Variant::Efi, 64).is_err());
    }

    #[test]
    fn empty_original_size_decodes_to_nothing() {
        let header = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = decode(&header, Variant::Tiano, 64).unwrap();
        assert_eq!(decoded.data, b"");
        assert_eq!(decoded.consumed, Some(9));
    }
}
