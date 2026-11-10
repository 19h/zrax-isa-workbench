//! File-bound proof of work, client side.
//!
//! Source: fwdonor `src/pow.rs`.
//!
//! ```text
//! token  = rand16 ‖ expiry_u64be ‖ bits_u8 ‖ HMAC-SHA256(key, those 25 bytes)[..16]
//! seed   = SHA256(token ‖ file_sha256)
//! accept = leading_zero_bits(SHA256(seed ‖ nonce_u64be)) >= bits
//! ```
//!
//! Zero bits are counted MSB-first from byte 0. The token travels as
//! unpadded URL-safe base64. Only the server can make or check a token; a
//! client hashes the decoded token bytes as they are.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

/// Nonces tried between two looks at the cancellation token.
const NONCES_PER_CANCEL_CHECK: u64 = 4096;

/// Why no proof of work was produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolveError {
    /// The challenge token is not unpadded URL-safe base64.
    #[error("Invalid proof-of-work challenge token")]
    InvalidToken,
    /// The search was cancelled.
    #[error("Proof of work cancelled")]
    Cancelled,
    /// Every 64-bit nonce was tried.
    #[error("No proof of work found")]
    Exhausted,
}

/// Number of leading zero bits of `hash`, MSB-first from byte 0.
pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// The value a file's nonces are hashed with: `SHA256(token ‖ file_sha256)`.
pub fn seed(token: &[u8], file_sha256: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(token)
        .chain_update(file_sha256)
        .finalize()
        .into()
}

/// `SHA256(seed ‖ nonce_u64be)`.
pub fn work_hash(seed: &[u8; 32], nonce: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(seed)
        .chain_update(nonce.to_be_bytes())
        .finalize()
        .into()
}

/// The first nonce whose work hash has at least `bits` leading zero bits.
/// CPU-bound: about `2^bits` hashes. Run it off the async executor.
///
/// # Errors
///
/// [`SolveError::InvalidToken`] for a token that is not base64,
/// [`SolveError::Cancelled`] once `cancel` is cancelled.
pub fn solve(
    token_base64: &str,
    file_sha256: &[u8; 32],
    bits: u8,
    cancel: &CancellationToken,
) -> Result<u64, SolveError> {
    let token = URL_SAFE_NO_PAD
        .decode(token_base64)
        .map_err(|_| SolveError::InvalidToken)?;
    let seed = seed(&token, file_sha256);
    let bits = u32::from(bits);
    for nonce in 0..=u64::MAX {
        if nonce % NONCES_PER_CANCEL_CHECK == 0 && cancel.is_cancelled() {
            return Err(SolveError::Cancelled);
        }
        if leading_zero_bits(&work_hash(&seed, nonce)) >= bits {
            return Ok(nonce);
        }
    }
    Err(SolveError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fwdonor `src/pow.rs` `shared_test_vector`, also in its
    /// `tests/pow.test.mjs`: token 41 × 0x11, file hash 32 × 0x22.
    const SHARED_TOKEN: [u8; 41] = [0x11; 41];
    const SHARED_FILE_SHA256: [u8; 32] = [0x22; 32];
    const SHARED_SEED_HEX: &str =
        "dbc6fdbf9aa7073991a41989beb2d94337580fb52a8e5b345441762a1a59d48e";
    const SHARED_NONCE_12_BITS: u64 = 449;

    #[test]
    fn solves_the_vector_shared_with_the_server_and_the_page() {
        assert_eq!(
            hex::encode(seed(&SHARED_TOKEN, &SHARED_FILE_SHA256)),
            SHARED_SEED_HEX
        );
        let token = URL_SAFE_NO_PAD.encode(SHARED_TOKEN);
        let nonce = solve(&token, &SHARED_FILE_SHA256, 12, &CancellationToken::new());
        assert_eq!(nonce, Ok(SHARED_NONCE_12_BITS));
    }

    #[test]
    fn counts_zero_bits_msb_first() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0, 0x0f]), 12);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn rejects_a_malformed_token_and_stops_when_cancelled() {
        let live = CancellationToken::new();
        assert_eq!(
            solve("not base64!", &SHARED_FILE_SHA256, 1, &live),
            Err(SolveError::InvalidToken)
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let token = URL_SAFE_NO_PAD.encode(SHARED_TOKEN);
        assert_eq!(
            solve(&token, &SHARED_FILE_SHA256, 64, &cancelled),
            Err(SolveError::Cancelled)
        );
    }
}
