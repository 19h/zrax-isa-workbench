//! Bounded Image4 AES-CBC/CTR and compression trials. AES handling adapts
//! `img4-dump/src/crypto.rs` and `src/main.rs::run_auto` at
//! `27f0f624d646bcabde913ee3facc4ff8671466fa` (MIT, Kenan Sulayman).
//! CBC uses no padding; CTR uses the IV as a big-endian 128-bit counter.
//! Structural recognition is evidence for a candidate, not authentication.

use crate::error::{ClassifierError, Result};
use crate::formats::{
    self,
    compressed::{self, Codec},
    container::Kind,
    DetectedFormat, MAX_PAYLOAD,
};
use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use ctr::cipher::StreamCipher;

const AES_BLOCK_SIZE: usize = 16;
/// Headerless codecs tried only when their decoded bytes identify a valid
/// structured format. Candidates are bounded and are not accepted on entropy.
const RAW_CODECS: &[Codec] = &[Codec::Deflate, Codec::Lz4Block, Codec::Brotli];

/// AES interpretation selected for a payload trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// AES-CBC with no padding removal.
    Cbc,
    /// AES-CTR with a big-endian 128-bit counter initialized from the IV.
    Ctr,
}

impl Mode {
    /// Display name also used as the decoded child's transform.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cbc => "AES-CBC",
            Self::Ctr => "AES-CTR",
        }
    }
}

/// One decrypted payload, possibly followed by a validated decompression.
#[derive(Debug)]
pub struct Trial {
    /// Bytes in the new subfile's own coordinate system, starting at zero.
    pub data: Vec<u8>,
    /// AES mode applied before any decompression.
    pub mode: Mode,
    /// Codec applied after AES, when a bounded candidate decoded successfully.
    pub codec: Option<&'static str>,
    /// A recognized format parsed successfully; this is not authentication.
    pub recognized: bool,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AppleParseError {
        message: message.into(),
    }
}

/// Apply AES to an Image4 ciphertext. Key lengths are 16, 24 or 32 B; the
/// IV is exactly 16 B. CBC requires a nonempty whole number of AES blocks.
/// Output is bounded to 64 MiB and no key or IV is logged or persisted.
///
/// # Errors
///
/// [`ClassifierError::AppleParseError`] for unsupported key/IV sizes or
/// empty/unaligned ciphertext; [`ClassifierError::PayloadLimit`] beyond 64 MiB.
pub fn decrypt(data: &[u8], key: &[u8], iv: &[u8], mode: Mode) -> Result<Vec<u8>> {
    if data.len() > MAX_PAYLOAD {
        return Err(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD });
    }
    if data.is_empty() {
        return Err(error("Missing Image4 ciphertext"));
    }
    if iv.len() != AES_BLOCK_SIZE {
        return Err(error("Invalid AES IV size; expected 16 B"));
    }
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(error("Invalid AES key size; expected 16, 24 or 32 B"));
    }
    if mode == Mode::Cbc && data.len() % AES_BLOCK_SIZE != 0 {
        return Err(error(
            "Invalid AES-CBC ciphertext size; expected a multiple of 16 B",
        ));
    }
    let mut output = data.to_vec();
    match (mode, key.len()) {
        (Mode::Cbc, 16) => cbc::<Aes128>(&mut output, key, iv)?,
        (Mode::Cbc, 24) => cbc::<Aes192>(&mut output, key, iv)?,
        (Mode::Cbc, 32) => cbc::<Aes256>(&mut output, key, iv)?,
        (Mode::Ctr, 16) => ctr::<Aes128>(&mut output, key, iv)?,
        (Mode::Ctr, 24) => ctr::<Aes192>(&mut output, key, iv)?,
        (Mode::Ctr, 32) => ctr::<Aes256>(&mut output, key, iv)?,
        _ => return Err(error("Unsupported AES mode or key size")),
    }
    Ok(output)
}

fn cbc<C>(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()>
where
    C: cbc::cipher::BlockCipher + cbc::cipher::BlockDecryptMut + cbc::cipher::KeyInit,
{
    cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| error("Invalid AES-CBC key or IV"))?
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|_| error("Invalid AES-CBC ciphertext"))?;
    Ok(())
}

fn ctr<C>(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()>
where
    C: ctr::cipher::BlockEncryptMut
        + ctr::cipher::BlockCipher<BlockSize = aes::cipher::consts::U16>
        + ctr::cipher::KeyInit,
{
    ctr::Ctr128BE::<C>::new_from_slices(key, iv)
        .map_err(|_| error("Invalid AES-CTR key or IV"))?
        .try_apply_keystream(data)
        .map_err(|_| error("Invalid AES-CTR counter extent"))
}

/// Check a structured format without running the raw code model. Image4
/// candidates are excluded here to prevent recursive keybag trials during
/// recognition. A manually selected AES mode can still open such output.
pub(crate) fn recognized(data: &[u8]) -> bool {
    let detected = formats::detect_format(data);
    if matches!(
        detected,
        DetectedFormat::Raw
            | DetectedFormat::Container {
                kind: Kind::Apple(_)
            }
    ) {
        return false;
    }
    formats::parse_detected(data, &detected).is_ok()
}

/// A codec trial with named fields, shared with the Image4 container parser.
pub(crate) struct DecodedCandidate {
    /// Codec used to produce the decoded bytes.
    pub(crate) codec: Codec,
    /// Bounded output, consumed input extent and integrity-check result.
    pub(crate) decoded: compressed::Decoded,
}

/// Try framed compression first, then bounded headerless alternatives.
/// Headerless candidates must yield a fully parsed structured file. No
/// candidate is accepted merely because its decoder produced some bytes.
pub(crate) fn decompress(data: &[u8]) -> Option<DecodedCandidate> {
    if let Some(codec) = compressed::sniff(data) {
        return compressed::decode(codec, data)
            .ok()
            .filter(|decoded| has_only_padding_after(data, decoded))
            .map(|decoded| DecodedCandidate { codec, decoded });
    }
    // A valid format takes precedence over speculative headerless codecs.
    if recognized(data) {
        return None;
    }
    let mut selected: Option<DecodedCandidate> = None;
    for &codec in RAW_CODECS {
        let Ok(decoded) = compressed::decode(codec, data) else {
            continue;
        };
        if !has_only_padding_after(data, &decoded) || !recognized(&decoded.data) {
            continue;
        }
        if let Some(first) = &selected {
            if first.decoded.data != decoded.data {
                return None;
            }
        } else {
            selected = Some(DecodedCandidate { codec, decoded });
        }
    }
    selected
}

/// A codec trial cannot silently discard an appended image or other data.
/// Decoders without a consumed-byte count retain their documented boundary.
fn has_only_padding_after(data: &[u8], decoded: &compressed::Decoded) -> bool {
    let consumed = decoded.consumed.unwrap_or(data.len());
    data.get(consumed..)
        .is_some_and(|trailing| trailing.iter().all(|byte| matches!(byte, 0 | 0xff)))
}

/// Decrypt and try compression. `recognized` is true only when the resulting
/// bytes parse as a supported structured file, or as a complete framed
/// compressed stream. It never means cryptographic authentication.
///
/// # Errors
///
/// As [`decrypt`].
pub fn trial(data: &[u8], key: &[u8], iv: &[u8], mode: Mode) -> Result<Trial> {
    let plaintext = decrypt(data, key, iv, mode)?;
    if let Some(candidate) = decompress(&plaintext) {
        return Ok(Trial {
            data: candidate.decoded.data,
            mode,
            codec: Some(candidate.codec.name()),
            recognized: true,
        });
    }
    let recognized = recognized(&plaintext);
    Ok(Trial {
        data: plaintext,
        mode,
        codec: None,
        recognized,
    })
}

/// Try CBC and CTR and return a unique structurally recognized output.
/// Unknown raw plaintext requires selecting an explicit mode via [`trial`].
///
/// # Errors
///
/// [`ClassifierError::AppleParseError`] when neither mode yields recognized
/// structure, or both yield different valid-looking results.
pub fn automatic(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Trial> {
    let mut selected: Option<Trial> = None;
    for mode in [Mode::Cbc, Mode::Ctr] {
        let Ok(candidate) = trial(data, key, iv, mode) else {
            continue;
        };
        selected = select_candidate(selected, candidate)?;
    }
    selected.ok_or_else(|| error("Unknown Image4 plaintext; check key and IV or select CBC or CTR to inspect an unverified candidate"))
}

/// Apply one uniqueness rule across modes and keybags. An ambiguous earlier
/// interpretation must not disappear merely because a later keybag succeeds.
pub(crate) fn select_candidate(selected: Option<Trial>, candidate: Trial) -> Result<Option<Trial>> {
    if !candidate.recognized {
        return Ok(selected);
    }
    match selected {
        Some(first) if first.data != candidate.data => {
            Err(error("Ambiguous Image4 decryption candidates"))
        }
        Some(first) => Ok(Some(first)),
        None => Ok(Some(candidate)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(value: u8, mode: Mode, recognized: bool) -> Trial {
        Trial {
            data: vec![value],
            mode,
            codec: None,
            recognized,
        }
    }

    #[test]
    fn selection_rejects_conflicting_recognized_outputs_across_trials() {
        let first = select_candidate(None, candidate(1, Mode::Cbc, true)).unwrap();
        assert!(select_candidate(first, candidate(2, Mode::Ctr, true)).is_err());
        let first = select_candidate(None, candidate(1, Mode::Cbc, true)).unwrap();
        assert!(select_candidate(first, candidate(2, Mode::Cbc, true)).is_err());
    }

    #[test]
    fn identical_or_unrecognized_outputs_do_not_create_false_ambiguity() {
        let first = select_candidate(None, candidate(1, Mode::Cbc, true)).unwrap();
        let same = select_candidate(first, candidate(1, Mode::Ctr, true)).unwrap();
        let chosen = select_candidate(same, candidate(2, Mode::Ctr, false))
            .unwrap()
            .unwrap();
        assert_eq!(chosen.data, [1]);
        assert_eq!(chosen.mode, Mode::Cbc);
    }
}
