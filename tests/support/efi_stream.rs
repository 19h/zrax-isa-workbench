//! A hand-built EFI or Tiano compressed stream for tests: one block that
//! codes every byte as a literal, since no EFI encoder is available.

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

/// An EFI (`pbit` 4) or Tiano (`pbit` 5) stream of one block coding every
/// byte as an 8-bit literal (UEFI 2.10, 19.2): block size (16 bits); the
/// extra set as the single symbol 10 (5-bit count 0, 5-bit symbol), so every
/// char-and-length code length is 8 and takes no bits; a 9-bit count of
/// 256 lengths; a single-symbol position set (`pbit`-bit count 0 and symbol
/// 0); then the bytes. The header holds the compressed size (including the
/// terminating zero byte the EDK2 encoder writes) and the original size.
pub fn efi_literal_stream(data: &[u8], pbit: u32) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.put(16, u32::try_from(data.len()).expect("one block"));
    w.put(5, 0);
    w.put(5, 10);
    w.put(9, 256);
    w.put(pbit, 0);
    w.put(pbit, 0);
    for &b in data {
        w.put(8, u32::from(b));
    }
    let mut bits = w.bytes;
    bits.push(0);
    let mut out = u32::try_from(bits.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&bits);
    out
}
