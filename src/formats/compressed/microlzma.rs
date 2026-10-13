//! `MicroLZMA` streams, as Linux v6.11 `include/linux/xz.h`
//! (`xz_dec_microlzma_alloc`) and `lib/xz/xz_dec_lzma2.c`
//! (`xz_dec_microlzma_run`) define them: a raw LZMA stream whose first
//! range-coder byte, always 0x00, is replaced by the bitwise NOT of the
//! properties byte (lc/lp/pb, with `lc + lp <= 4`). There is no dictionary
//! size, no size field and no end marker; the container states the
//! compressed and uncompressed sizes. EROFS stores its LZMA pclusters this
//! way. [`decode`] decodes exactly `limit` bytes, the uncompressed size
//! its caller passes.

use super::*;
use lzma_rust2::LzmaReader;

/// Largest properties byte: `(pb * 5 + lp) * 9 + lc` with `lc <= 8`,
/// `lp <= 4` and `pb <= 4`.
const LZMA_PROPERTIES_MAX: u8 = 9 * 5 * 5 - 1;

/// `lc + lp` may not exceed 4 (the LZMA2 rule `xz_dec_microlzma_run`
/// applies through `lzma_props`).
const MAX_LITERAL_BITS: u8 = 4;

/// Smallest LZMA dictionary.
const DICT_MIN: u32 = 4096;

/// Decode a `MicroLZMA` stream into exactly `limit` bytes.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    let Some((&first, rest)) = data.split_first() else {
        return Err(error("Truncated MicroLZMA stream at 0x0"));
    };
    let properties = !first;
    if properties > LZMA_PROPERTIES_MAX {
        return Err(error(format!(
            "Invalid MicroLZMA properties 0x{properties:02X}"
        )));
    }
    let literal_context_bits = properties % 9;
    let literal_position_bits = properties / 9 % 5;
    if literal_context_bits + literal_position_bits > MAX_LITERAL_BITS {
        return Err(error(format!(
            "Invalid MicroLZMA properties 0x{properties:02X}: lc + lp exceeds 4"
        )));
    }
    // A dictionary as large as the output holds every match distance.
    let dict = u32::try_from(limit).unwrap_or(u32::MAX).max(DICT_MIN);
    // The range coder starts with the 0x00 byte the format replaced.
    let input = Read::chain(&[0u8][..], rest);
    let reader = LzmaReader::new_with_props(input, limit as u64, properties, dict, None)
        .map_err(|e| error(format!("Invalid MicroLZMA stream: {e}")))?;
    let out = read_capped(reader, limit, "MicroLZMA")?;
    if out.len() != limit {
        return Err(error(format!(
            "Truncated MicroLZMA stream: {} B of {limit} B decoded",
            out.len()
        )));
    }
    Ok(Decoded {
        data: out,
        consumed: None,
        check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tests/fixtures/compressed/payload.elf.lzma` (`lzma -9`): a 13-byte
    /// LZMA-alone header (properties, dictionary size, unknown size), then
    /// the range-coder data, whose first byte is 0x00.
    const LZMA_ALONE: &[u8] = include_bytes!("../../../tests/fixtures/compressed/payload.elf.lzma");
    const PAYLOAD: &[u8] = include_bytes!("../../../tests/fixtures/compressed/payload.elf");
    const LZMA_HEADER_SIZE: usize = 13;

    /// The fixture as `MicroLZMA`: the first range-coder byte replaced by the
    /// NOT of the properties byte.
    fn micro() -> Vec<u8> {
        let mut stream = LZMA_ALONE[LZMA_HEADER_SIZE..].to_vec();
        assert_eq!(stream[0], 0);
        stream[0] = !LZMA_ALONE[0];
        stream
    }

    #[test]
    fn lzma_alone_data_with_the_negated_properties_decodes() {
        let decoded = decode(&micro(), PAYLOAD.len()).unwrap();
        assert_eq!(decoded.data, PAYLOAD);
        // A shorter uncompressed size decodes a prefix.
        assert_eq!(decode(&micro(), 64).unwrap().data, &PAYLOAD[..64]);
    }

    #[test]
    fn invalid_properties_and_truncation_are_errors() {
        let mut stream = micro();
        stream[0] = !0xe1;
        assert!(decode(&stream, PAYLOAD.len()).is_err());
        // lc 4, lp 1.
        stream[0] = !(9 + 4);
        assert!(decode(&stream, PAYLOAD.len()).is_err());
        assert!(decode(&micro()[..8], PAYLOAD.len()).is_err());
        assert!(decode(&[], 16).is_err());
    }
}
