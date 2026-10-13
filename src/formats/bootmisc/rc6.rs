//! The RC6-32/20/32 block cipher (32-bit words, 20 rounds, 256-bit keys),
//! as Allwinner `IMAGEWTY` images use it: each 16-byte block on its own
//! (ECB), words little-endian.
//!
//! Algorithm: R. L. Rivest, M. J. B. Robshaw, R. Sidney and Y. L. Yin,
//! "The RC6 Block Cipher", version 1.1 (1998), sections 2.1-2.3 (key
//! schedule, encryption, decryption). `Ithamar/awutils`
//! `3f1cbb2c67752b392a88b252c51158d13d8809b5` `rc6.c` implements the same
//! cipher and `awimage.c` (`crypto_init`) calls it with 20 rounds and
//! 256-bit keys. Only decryption is needed outside the tests.

/// Rounds (`rc6_init` uses 20).
const ROUNDS: usize = 20;

/// Round keys: `2r + 4`.
const ROUND_KEYS: usize = 2 * ROUNDS + 4;

/// Key size in bytes, and in 32-bit words.
pub(super) const KEY_SIZE: usize = 32;
const KEY_WORDS: usize = KEY_SIZE / 4;

/// Block size in bytes.
pub(super) const BLOCK_SIZE: usize = 16;

/// The magic constants `P32` (from e) and `Q32` (from the golden ratio).
const P32: u32 = 0xb7e1_5163;
const Q32: u32 = 0x9e37_79b9;

/// `lg w` for 32-bit words: the rotation applied to `x(2x + 1)`.
const LG_W: u32 = 5;

/// An expanded key.
pub(super) struct Schedule {
    keys: [u32; ROUND_KEYS],
}

/// Rotate left by the low five bits of `amount`, as RC6 data-dependent
/// rotations do.
const fn rotl(value: u32, amount: u32) -> u32 {
    value.rotate_left(amount % 32)
}

/// Rotate right by the low five bits of `amount`.
const fn rotr(value: u32, amount: u32) -> u32 {
    value.rotate_right(amount % 32)
}

/// `x(2x + 1)` rotated left by `lg w`, the round function's mixing term.
const fn mix(x: u32) -> u32 {
    rotl(x.wrapping_mul(x.wrapping_mul(2).wrapping_add(1)), LG_W)
}

impl Schedule {
    /// The key schedule (section 2.1): `S[0] = P32`, `S[i] = S[i-1] + Q32`,
    /// then `3 * max(c, 2r + 4)` mixing steps over the key words `L`.
    /// A `const fn`, so fixed keys are expanded at compile time.
    pub(super) const fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut words = [0u32; KEY_WORDS];
        let mut i = 0;
        while i < KEY_WORDS {
            words[i] =
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i += 1;
        }
        let mut keys = [0u32; ROUND_KEYS];
        keys[0] = P32;
        let mut i = 1;
        while i < ROUND_KEYS {
            keys[i] = keys[i - 1].wrapping_add(Q32);
            i += 1;
        }
        let steps = 3 * if KEY_WORDS > ROUND_KEYS {
            KEY_WORDS
        } else {
            ROUND_KEYS
        };
        // The paper's `A` and `B`: the round key and the key word last
        // written.
        let mut last_key = 0u32;
        let mut last_word = 0u32;
        let mut i = 0;
        let mut j = 0;
        let mut step = 0;
        while step < steps {
            last_key = rotl(keys[i].wrapping_add(last_key).wrapping_add(last_word), 3);
            keys[i] = last_key;
            let sum = last_key.wrapping_add(last_word);
            last_word = rotl(words[j].wrapping_add(sum), sum);
            words[j] = last_word;
            i = (i + 1) % ROUND_KEYS;
            j = (j + 1) % KEY_WORDS;
            step += 1;
        }
        Self { keys }
    }

    /// Decrypt one block in place (section 2.3).
    pub(super) fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut reg = Registers::load(block);
        reg.c = reg.c.wrapping_sub(self.keys[2 * ROUNDS + 3]);
        reg.a = reg.a.wrapping_sub(self.keys[2 * ROUNDS + 2]);
        for round in (1..=ROUNDS).rev() {
            // (A, B, C, D) = (D, A, B, C)
            reg = Registers {
                a: reg.d,
                b: reg.a,
                c: reg.b,
                d: reg.c,
            };
            let mix_d = mix(reg.d);
            let mix_b = mix(reg.b);
            reg.c = rotr(reg.c.wrapping_sub(self.keys[2 * round + 1]), mix_b) ^ mix_d;
            reg.a = rotr(reg.a.wrapping_sub(self.keys[2 * round]), mix_d) ^ mix_b;
        }
        reg.d = reg.d.wrapping_sub(self.keys[1]);
        reg.b = reg.b.wrapping_sub(self.keys[0]);
        reg.store(block);
    }

    /// Decrypt every whole block of `bytes` in place; a partial final
    /// block is left as stored.
    pub(super) fn decrypt(&self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_exact_mut(BLOCK_SIZE) {
            let block: &mut [u8; BLOCK_SIZE] =
                chunk.try_into().expect("chunk has exactly 16 bytes");
            self.decrypt_block(block);
        }
    }

    /// Encrypt one block in place (section 2.2), for the tests' fixtures.
    #[cfg(test)]
    pub(super) fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut reg = Registers::load(block);
        reg.b = reg.b.wrapping_add(self.keys[0]);
        reg.d = reg.d.wrapping_add(self.keys[1]);
        for round in 1..=ROUNDS {
            let mix_b = mix(reg.b);
            let mix_d = mix(reg.d);
            let new_a = rotl(reg.a ^ mix_b, mix_d).wrapping_add(self.keys[2 * round]);
            let new_c = rotl(reg.c ^ mix_d, mix_b).wrapping_add(self.keys[2 * round + 1]);
            // (A, B, C, D) = (B, C, D, A)
            reg = Registers {
                a: reg.b,
                b: new_c,
                c: reg.d,
                d: new_a,
            };
        }
        reg.a = reg.a.wrapping_add(self.keys[2 * ROUNDS + 2]);
        reg.c = reg.c.wrapping_add(self.keys[2 * ROUNDS + 3]);
        reg.store(block);
    }
}

/// The paper's four working registers `A`, `B`, `C` and `D`: the block's
/// little-endian words in order.
#[derive(Clone, Copy)]
struct Registers {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Registers {
    fn load(block: &[u8; BLOCK_SIZE]) -> Self {
        let word = |at: usize| {
            let bytes: [u8; 4] = block[at..at + 4]
                .try_into()
                .expect("a block holds four words");
            u32::from_le_bytes(bytes)
        };
        Self {
            a: word(0),
            b: word(4),
            c: word(8),
            d: word(12),
        }
    }

    fn store(self, block: &mut [u8; BLOCK_SIZE]) {
        let words = [self.a, self.b, self.c, self.d];
        for (bytes, word) in block.chunks_exact_mut(4).zip(words) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(text: &str) -> [u8; N] {
        hex::decode(text)
            .expect("hex test vector")
            .try_into()
            .expect("test vector size")
    }

    /// The 256-bit test vectors of "The RC6 Block Cipher" v1.1, appendix.
    #[test]
    fn published_256_bit_vectors_round_trip() {
        let vectors = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "8f5fbd0510d15fa893fa3fda6e857ec2",
            ),
            (
                "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe",
                "02132435465768798a9bacbdcedfe0f1",
                "c8241816f0d7e48920ad16a1674e5d48",
            ),
        ];
        for (key, plaintext, ciphertext) in vectors {
            let schedule = Schedule::new(&bytes(key));
            let mut block: [u8; BLOCK_SIZE] = bytes(plaintext);
            schedule.encrypt_block(&mut block);
            assert_eq!(hex::encode(block), ciphertext, "key {key}");
            schedule.decrypt_block(&mut block);
            assert_eq!(hex::encode(block), plaintext, "key {key}");
        }
    }

    #[test]
    fn partial_final_blocks_are_left_as_stored() {
        let schedule = Schedule::new(&[7; KEY_SIZE]);
        let mut data = [0xa5u8; 20];
        schedule.decrypt(&mut data);
        assert_eq!(data[16..], [0xa5; 4]);
        assert_ne!(data[..16], [0xa5; 16]);
    }
}
