//! The hash table: "the actual hashes for each chunk of the base image.
//! Chunk validation begins at the image header and ends at the end of the
//! FFU" (Microsoft "FFU image format", "Hash table data"). One digest per
//! chunk of `dwChunkSizeInKb` KiB, in file order from the image header
//! (img2ffu `Writer/FFUFactory.cs` `GenerateHashTable` and
//! `Reader/Data/SignedImage.cs` `VerifyFFU`), with the algorithm `dwAlgId`
//! names (Microsoft Learn "`ALG_ID`": `CALG_SHA_256` is `0x800C`, `CALG_SHA1`
//! `0x8004`). The signed catalog holds the hash of the hash table; its
//! signature is not verified, so matching chunk hashes show that the image
//! is intact, not who made it.

use super::*;
use crate::formats::checksum::Sha1;
use sha2::{Digest, Sha256};

/// `dwAlgId` values (Microsoft Learn "`ALG_ID`").
const CALG_SHA1: u32 = 0x0000_8004;
const CALG_SHA_256: u32 = 0x0000_800C;

/// Most bytes hashed: the first 64 MiB of chunks (`MAX_PAYLOAD`), so a large
/// image is checked in bounded time; the chunks after them are reported as
/// not verified.
const MAX_HASHED: u64 = MAX_PAYLOAD as u64;

/// A hash algorithm the hash table may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
}

impl Algorithm {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            CALG_SHA1 => Some(Self::Sha1),
            CALG_SHA_256 => Some(Self::Sha256),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }

    /// Digest size in bytes.
    fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn matches(self, chunk: &[u8], expected: &[u8]) -> bool {
        match self {
            Self::Sha1 => {
                let mut sha1 = Sha1::new();
                sha1.update(chunk);
                sha1.finish().as_slice() == expected
            }
            Self::Sha256 => Sha256::digest(chunk).as_slice() == expected,
        }
    }
}

/// The outcome of the chunk hash check.
#[derive(Debug)]
pub(super) struct HashReport {
    /// `match`, `mismatch` or `not verified`, for the metadata.
    pub(super) status: &'static str,
    pub(super) note: String,
}

/// Check the chunks from the image header to `end`, the end of the last
/// payload, against the hash table; the last chunk may run on into erased
/// padding after the payload.
pub(super) fn check(data: &[u8], security: &SecurityHeader, end: usize) -> HashReport {
    let Some(algorithm) = Algorithm::from_id(security.algorithm) else {
        return not_verified(&format!(
            "hash algorithm 0x{:08X} is neither SHA-1 nor SHA-256",
            security.algorithm
        ));
    };
    let chunk_size = security.chunk_size;
    let start = security.image_offset as u64;
    let covered = (end as u64).saturating_sub(start);
    let chunks = covered / chunk_size + u64::from(covered % chunk_size != 0);
    let hashed_end = start + chunks * chunk_size;
    if hashed_end > data.len() as u64 {
        return not_verified(&format!(
            "the last of the {chunks} chunks from 0x{start:X} ends at 0x{hashed_end:X}, after \
             the end of the file"
        ));
    }
    let digest_size = algorithm.digest_size() as u64;
    if chunks * digest_size != security.hash_table_size as u64 {
        return not_verified(&format!(
            "the hash table holds {} B, but {} hashes of the {chunks} chunks from 0x{start:X} \
             take {} B",
            security.hash_table_size,
            algorithm.name(),
            chunks * digest_size
        ));
    }
    let table = data
        .get(security.hash_table_offset..)
        .and_then(|rest| rest.get(..security.hash_table_size))
        .unwrap_or_default();
    // Every chunk lies before `hashed_end`, inside `data`, and the table
    // holds `chunks` digests, so these slices are in bounds.
    let chunk_len = usize::try_from(chunk_size).expect("a chunk lies inside the file");
    let digest_len = algorithm.digest_size();
    let start = security.image_offset;
    let mut checked = 0u64;
    let mut mismatched = 0u64;
    let mut first_mismatch = None;
    for (i, expected) in table.chunks_exact(digest_len).enumerate() {
        if checked * chunk_size >= MAX_HASHED {
            break;
        }
        let at = start + i * chunk_len;
        let chunk = &data[at..at + chunk_len];
        if !algorithm.matches(chunk, expected) {
            mismatched += 1;
            first_mismatch.get_or_insert(i);
        }
        checked += 1;
    }
    let signature = "the catalog signature over the hash table is not verified";
    if let Some(first) = first_mismatch {
        return HashReport {
            status: "mismatch",
            note: format!(
                "Chunk hashes: {mismatched} of {checked} checked chunks differ from their {} in \
                 the hash table, the first at chunk {first} (0x{:X}); the image differs from the \
                 one that was hashed",
                algorithm.name(),
                start + first * chunk_len
            ),
        };
    }
    let note = if checked == chunks {
        format!(
            "Chunk hashes: the {} of all {chunks} chunks from 0x{start:X} to 0x{hashed_end:X} \
             match the hash table; {signature}",
            algorithm.name()
        )
    } else {
        format!(
            "Chunk hashes: the {} of the first {checked} of {chunks} chunks ({}) match the hash \
             table; the other chunks were not verified; {signature}",
            algorithm.name(),
            size_text(checked * chunk_size)
        )
    };
    HashReport {
        status: "match",
        note,
    }
}

fn not_verified(reason: &str) -> HashReport {
    HashReport {
        status: "not verified",
        note: format!("Chunk hashes not verified: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithms_are_the_alg_id_values() {
        assert_eq!(Algorithm::from_id(0x800C), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::from_id(0x8004), Some(Algorithm::Sha1));
        assert_eq!(Algorithm::from_id(0x8003), None);
        // FIPS 180-4 test vector "abc".
        let abc_sha1 = hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        assert!(Algorithm::Sha1.matches(b"abc", &abc_sha1));
        let abc_sha256 =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert!(Algorithm::Sha256.matches(b"abc", &abc_sha256));
        assert!(!Algorithm::Sha256.matches(b"abd", &abc_sha256));
    }
}
