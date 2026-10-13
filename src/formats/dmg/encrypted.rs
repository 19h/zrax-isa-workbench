//! Encrypted disk images (`CEncryptedEncoding`), every field big-endian.
//!
//! Version 2 (libdmg-hfsplus `includes/dmg/filevault.h`
//! `FileVaultV2Header`; dmg2img `vfdecrypt.h`; apfs-fuse
//! `ApfsLib/DiskImageFile.cpp` `DmgCryptHeaderV2`; keramics
//! `cdsaencr.md`): at offset 0, signature `encrcdsa` (8), version 2 (4),
//! block IV size (4), block cipher mode (4), block cipher algorithm (4), key
//! size in bits (4), HMAC algorithm (4), HMAC key size in bits (4), UUID
//! (16), block size (4) at 52, data size (8) at 56, data offset (8) at 64
//! and the number of key protectors (4) at 72, followed by 20-byte key
//! protector descriptors.
//!
//! Version 1 (apfs-fuse `DmgCryptHeaderV1`, 0x4FC bytes; keramics
//! "Encrypted container footer"): a 1276-byte footer at the end of the file
//! that starts with a UUID (16) and the block size (4) and ends with the
//! signature `cdsaencr` (8); the encrypted data precedes it from offset 0.
//!
//! The data (a UDIF image, sparse image or raw disk, keramics) is
//! encrypted block by block under a key wrapped by a passphrase, a public
//! key or a keybag. Nothing here unwraps or decrypts: the image is opaque.

use super::*;
use crate::formats::container::{Child, Container};

/// Version 2 header signature and version.
const V2_SIGNATURE: &[u8; 8] = b"encrcdsa";
const V2_VERSION: u32 = 2;

/// Version 2 header fields read here: up to the key protector count.
const V2_HEADER_SIZE: usize = 76;

/// Bytes of one key protector descriptor: unlock type (4), offset (8) and
/// size (8).
const KEY_PROTECTOR_SIZE: u64 = 20;

/// Version 1 footer signature and size.
const V1_SIGNATURE: &[u8; 8] = b"cdsaencr";
const V1_FOOTER_SIZE: usize = 0x4fc;

/// `CSSM_ALGID_AES` (keramics `cdsaencr.md`, "Algorithm identifiers").
const CSSM_ALGID_AES: u32 = 0x8000_0001;

const NOT_DECRYPTED: &str =
    "The encrypted data (a UDIF image, sparse image or raw disk) is not decrypted, so it is opaque";

/// Is this an Encrypted Encoding version 2 image: `encrcdsa` and version 2
/// at offset 0?
pub(super) fn is_v2(data: &[u8]) -> bool {
    data.starts_with(V2_SIGNATURE) && be_u32(data, 8).is_ok_and(|version| version == V2_VERSION)
}

/// Is this an Encrypted Encoding version 1 image: a footer that ends the
/// file with `cdsaencr`?
pub(super) fn is_v1(data: &[u8]) -> bool {
    data.len() >= V1_FOOTER_SIZE && data.ends_with(V1_SIGNATURE)
}

/// `AES-128` for the AES algorithm ID, else the ID and key size.
fn cipher_text(algorithm: u32, key_bits: u32) -> String {
    if algorithm == CSSM_ALGID_AES {
        format!("AES-{key_bits}")
    } else {
        format!("algorithm 0x{algorithm:08X} with {key_bits}-bit keys")
    }
}

/// A version 2 image: the header, then the encrypted data at the offset it
/// names, which must lie in the file.
pub(super) fn parse_v2(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, V2_HEADER_SIZE, "encrcdsa header")?;
    if !is_v2(header) {
        return Err(error("Missing encrcdsa signature or version 2"));
    }
    let algorithm = be_u32(header, 20)?;
    let key_bits = be_u32(header, 24)?;
    let block_size = be_u32(header, 52)?;
    let data_size = be_u64(header, 56)?;
    let data_offset = be_u64(header, 64)?;
    let protectors = be_u32(header, 72)?;
    let descriptors_end = u64::from(protectors) * KEY_PROTECTOR_SIZE + V2_HEADER_SIZE as u64;
    if descriptors_end > data_offset {
        return Err(error(format!(
            "Invalid encrcdsa header: {protectors} key protectors overlap the data at \
             0x{data_offset:X}"
        )));
    }
    if block_size == 0 {
        return Err(error("Invalid encrcdsa block size 0 B"));
    }
    // The data is encrypted in whole blocks (dmg2img `vfdecrypt.c` reads
    // block by block), so the last block is stored whole.
    let block = u64::from(block_size);
    let stored_size = (data_size / block + u64::from(data_size % block != 0)).checked_mul(block);
    let available = (data.len() as u64).saturating_sub(data_offset);
    let fits = matches!(stored_size, Some(size) if size <= available);
    if data_offset > data.len() as u64 || !fits {
        return Err(error(format!(
            "Truncated encrypted data at 0x{data_offset:X}: {data_size} B in blocks of \
             {block_size} B, the file has {} B",
            data.len()
        )));
    }
    let offset = usize::try_from(data_offset).expect("the data offset lies in the input");
    let mut c = Container::new(
        FileFormat::AppleDmg,
        Layout::EncryptedV2.label(),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.opaque = true;
    c.notes.push(format!(
        "Encrypted Encoding version 2: {} in blocks of {block_size} B; {data_size} B of data at \
         0x{data_offset:X}; {}",
        cipher_text(algorithm, key_bits),
        counted(protectors as usize, "key protector", "key protectors")
    ));
    c.notes.push(NOT_DECRYPTED.into());
    c.push_metadata("dmg_encryption_version", "Encrypted Encoding version", 2u64);
    c.push_metadata(
        "dmg_cipher",
        "Block cipher",
        cipher_text(algorithm, key_bits),
    );
    c.push_metadata(
        "dmg_block_size",
        "Encryption block size (B)",
        u64::from(block_size),
    );
    c.push_metadata("dmg_encrypted_size", "Encrypted data size (B)", data_size);
    c.push_metadata(
        "dmg_key_protectors",
        "Key protectors",
        u64::from(protectors),
    );
    c.children
        .push(Child::opaque("Encrypted data", offset, &data[offset..]));
    Ok(c)
}

/// A version 1 image: the encrypted data, then the footer.
pub(super) fn parse_v1(data: &[u8]) -> Result<Container<'_>> {
    if !is_v1(data) {
        return Err(error("Missing cdsaencr footer"));
    }
    let footer_at = data.len() - V1_FOOTER_SIZE;
    let footer = &data[footer_at..];
    let block_size = be_u32(footer, 16)?;
    let mut c = Container::new(
        FileFormat::AppleDmg,
        Layout::EncryptedV1.label(),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.opaque = true;
    c.notes.push(format!(
        "Encrypted Encoding version 1: {footer_at} B of data in blocks of {block_size} B before \
         the footer at 0x{footer_at:X}"
    ));
    c.notes.push(NOT_DECRYPTED.into());
    c.push_metadata("dmg_encryption_version", "Encrypted Encoding version", 1u64);
    c.push_metadata(
        "dmg_block_size",
        "Encryption block size (B)",
        u64::from(block_size),
    );
    c.push_metadata(
        "dmg_encrypted_size",
        "Encrypted data size (B)",
        footer_at as u64,
    );
    c.children
        .push(Child::opaque("Encrypted data", 0, &data[..footer_at]));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_need_their_version_or_footer_size() {
        let mut v2 = V2_SIGNATURE.to_vec();
        v2.extend_from_slice(&2u32.to_be_bytes());
        assert!(is_v2(&v2));
        v2[11] = 1;
        assert!(!is_v2(&v2));
        let mut v1 = vec![0u8; V1_FOOTER_SIZE - 8];
        v1.extend_from_slice(V1_SIGNATURE);
        assert!(is_v1(&v1));
        assert!(!is_v1(&v1[1..]));
    }

    #[test]
    fn ciphers_are_named_only_for_the_aes_id() {
        assert_eq!(cipher_text(CSSM_ALGID_AES, 256), "AES-256");
        assert_eq!(
            cipher_text(17, 192),
            "algorithm 0x00000011 with 192-bit keys"
        );
    }
}
