//! Apple LZSS kernelcache compression (`complzss`) and the LZVN variant
//! (`complzvn`).
//!
//! Header layout (all fields big-endian), as read by Apple boot loaders and
//! by img4lib (`lzss.c`, xerub): signature `comp` (4), compression type
//! `lzss`/`lzvn` (4), Adler-32 of the decoded data (4), decoded size (4),
//! stored size (4), reserved (44), platform name (64), root path (256); data
//! starts at `0x180`. The LZSS bitstream is Okumura's LZSS with a 4 KiB ring
//! initialized to spaces, 18-byte maximum matches and a match threshold of
//! two, as in the Apple boot loader source `BootX/sl.subproj/lzss.c`.

use super::*;

/// `comp` followed by `lzss`.
pub(super) const LZSS_MAGIC: &[u8; 8] = b"complzss";

/// `comp` followed by `lzvn`.
pub(super) const LZVN_MAGIC: &[u8; 8] = b"complzvn";

/// Offset of the compressed data.
const HEADER_SIZE: usize = 0x180;

/// Ring buffer size.
const RING: usize = 4096;

/// Longest match.
const MAX_MATCH: usize = 18;

/// Matches encode lengths above this threshold.
const THRESHOLD: usize = 2;

/// LZVN block framing understood by the LZFSE decoder: magic, decoded size,
/// payload size (little-endian), payload, then the end-of-stream block.
const LZVN_BLOCK: &[u8; 4] = b"bvxn";
const END_BLOCK: &[u8; 4] = b"bvx$";

/// Decode a `complzss` or `complzvn` image.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    let lzvn = data.starts_with(LZVN_MAGIC);
    if !lzvn && !data.starts_with(LZSS_MAGIC) {
        return Err(error("Missing complzss signature"));
    }
    let adler = be_u32(data, 8)?;
    let decoded_size =
        usize::try_from(be_u32(data, 12)?).map_err(|_| error("Invalid complzss decoded size"))?;
    let stored_size =
        usize::try_from(be_u32(data, 16)?).map_err(|_| error("Invalid complzss stored size"))?;
    if decoded_size > limit {
        return Err(exceeds(limit));
    }
    let stored = slice(data, HEADER_SIZE, stored_size)?;
    let out = if lzvn {
        lzvn_payload(stored, decoded_size)?
    } else {
        lzss(stored, decoded_size)
    };
    if out.len() != decoded_size {
        return Err(error(format!(
            "Invalid complzss payload: decoded {} B, header declares {decoded_size} B",
            out.len()
        )));
    }
    let computed = checksum::adler32(&out);
    if computed != adler {
        return Err(error(format!(
            "Invalid complzss Adler-32 0x{adler:08X}, computed 0x{computed:08X}"
        )));
    }
    Ok(Decoded {
        data: out,
        consumed: Some(HEADER_SIZE + stored_size),
        check: Some("Adler-32"),
    })
}

/// Okumura LZSS: a flag byte selects, bit by bit from the least significant,
/// a literal (1) or a 12-bit ring position plus 4-bit length (0). Decoding
/// stops at the end of the input or at `limit` bytes.
pub(super) fn lzss(input: &[u8], limit: usize) -> Vec<u8> {
    let mut ring = [b' '; RING + MAX_MATCH - 1];
    let mut r = RING - MAX_MATCH;
    let mut out = Vec::with_capacity(limit.min(input.len().saturating_mul(8)));
    let mut bytes = input.iter().copied();
    let mut flags: u32 = 0;
    while out.len() < limit {
        flags >>= 1;
        if flags & 0x100 == 0 {
            let Some(c) = bytes.next() else { break };
            flags = u32::from(c) | 0xff00;
        }
        if flags & 1 != 0 {
            let Some(c) = bytes.next() else { break };
            out.push(c);
            ring[r] = c;
            r = (r + 1) & (RING - 1);
        } else {
            let (Some(low), Some(high)) = (bytes.next(), bytes.next()) else {
                break;
            };
            let position = usize::from(low) | ((usize::from(high) & 0xf0) << 4);
            let length = (usize::from(high) & 0x0f) + THRESHOLD;
            for k in 0..=length {
                if out.len() >= limit {
                    break;
                }
                let c = ring[(position + k) & (RING - 1)];
                out.push(c);
                ring[r] = c;
                r = (r + 1) & (RING - 1);
            }
        }
    }
    out
}

/// Frame a raw LZVN payload as one `bvxn` block and decode it with the
/// LZFSE decoder, which validates the LZVN opcode stream.
fn lzvn_payload(stored: &[u8], decoded_size: usize) -> Result<Vec<u8>> {
    let decoded = u32::try_from(decoded_size).map_err(|_| error("Invalid LZVN decoded size"))?;
    let payload = u32::try_from(stored.len()).map_err(|_| error("Invalid LZVN stored size"))?;
    let mut framed = Vec::with_capacity(stored.len() + 16);
    framed.extend_from_slice(LZVN_BLOCK);
    framed.extend_from_slice(&decoded.to_le_bytes());
    framed.extend_from_slice(&payload.to_le_bytes());
    framed.extend_from_slice(stored);
    framed.extend_from_slice(END_BLOCK);
    Ok(super::lzfse(&framed, decoded_size)?.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzss_decodes_literals_and_ring_matches() {
        // Flags 0b0000_0111: three literals "abc", then a match at ring
        // position 0xFEE (where "abc" was written), length 0 + 2 + 1 = 3.
        let stream = [0x07, b'a', b'b', b'c', 0xee, 0xf0];
        assert_eq!(lzss(&stream, 64), b"abcabc");
    }

    #[test]
    fn lzss_stops_at_the_output_limit() {
        let stream = [0x07, b'a', b'b', b'c', 0xee, 0xf0];
        assert_eq!(lzss(&stream, 4), b"abca");
    }

    #[test]
    fn complzss_header_is_validated() {
        let payload = [0x07, b'a', b'b', b'c', 0xee, 0xf0];
        let mut image = vec![0u8; HEADER_SIZE];
        image[..8].copy_from_slice(LZSS_MAGIC);
        image[8..12].copy_from_slice(&checksum::adler32(b"abcabc").to_be_bytes());
        image[12..16].copy_from_slice(&6u32.to_be_bytes());
        image[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        image.extend_from_slice(&payload);
        let decoded = decode(&image, MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.data, b"abcabc");
        assert_eq!(decoded.consumed, Some(image.len()));

        let mut corrupt = image.clone();
        corrupt[8] ^= 1;
        assert!(decode(&corrupt, MAX_PAYLOAD).is_err());
        for end in 0..image.len() {
            assert!(decode(&image[..end], MAX_PAYLOAD).is_err(), "prefix {end}");
        }
    }
}
