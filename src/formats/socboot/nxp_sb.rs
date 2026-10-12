//! NXP Secure Binary files: SB2.0 and SB2.1 (`LPC55xx`, i.MX RT5xx/6xx and
//! Kinetis secure update images) and SB3.1 (`LPC55S3x`, MCX, i.MX `RT11xx`
//! provisioning and update images).
//!
//! Layout (SPSDK `fb0f666d` `spsdk/sbfile/sb2/headers.py` `ImageHeaderV2`,
//! `sb2/images.py` `BootImageV20`/`BootImageV21` `export`, `update`,
//! `raw_size` and `parse`, `spsdk/image/cert_block/cert_block_v1.py`
//! `CertBlockV1`, `cert_block/rkht.py` `RKHTv1`;
//! `spsdk/sbfile/sb31/images.py` `SecureBinary31Header` and
//! `process_cmd_blocks_to_export`, `spsdk/image/cert_block/cert_block_v21.py`):
//!
//! - SB2: a 0x60-byte little-endian header with `STMP` at 0x14, major
//!   version 2 at 0x18, `sgtl` at 0x34 and sizes in 16-byte cipher blocks,
//!   a 32-byte HMAC and the AES-wrapped key blob (80 bytes).
//!   - SB2.0 then holds the encrypted certificate section when signed, the
//!     encrypted boot sections, and when signed a signature after the
//!     `image_blocks` the header counts.
//!   - SB2.1 holds certificate block V1 (`cert`) at 0xD0 (header, length-
//!     prefixed certificates, a 128-byte root key hash table, aligned to 16
//!     bytes), an optional SHA-256 of the boot sections (flag 0x8000), the
//!     signature and the AES-CTR encrypted boot sections. SPSDK leaves the
//!     SHA-256 out of the header's first boot tag block and image block
//!     count, so with that flag both lie 32 bytes after what the header
//!     counts.
//! - SB3.1: a 0x3C-byte header (`sbv3`, minor 1, major 3) followed by the
//!   hash of data block 1, certificate block V2.1 (`chdr`) and the ECDSA
//!   signature (64 or 96 bytes); this is block 0. Data blocks of 292
//!   (SHA-256) or 308 (SHA-384) bytes follow, each a block number, the hash
//!   of the next block and 256 bytes of AES-encrypted payload. The hash
//!   chain is verified here; signatures are not.
//!
//! No Secure Binary header names a CPU or instruction set, and the commands
//! are encrypted, so the containers are metadata-only.

use super::*;
use sha2::{Digest, Sha256, Sha384};

/// SB2 header magics and version (SPSDK `ImageHeaderV2`).
const STMP: [u8; 4] = *b"STMP";
const SGTL: [u8; 4] = *b"sgtl";
const SB2_STMP_OFFSET: usize = 0x14;
const SB2_SGTL_OFFSET: usize = 0x34;
const SB2_MAJOR: u8 = 2;

/// SB2 header fields.
const SB2_MAJOR_VERSION: usize = 0x18;
const SB2_MINOR_VERSION: usize = 0x19;
const SB2_FLAGS: usize = 0x1a;
const SB2_IMAGE_BLOCKS: usize = 0x1c;
const SB2_FIRST_BOOT_TAG_BLOCK: usize = 0x20;
const SB2_CERT_BLOCK_OFFSET: usize = 0x28;
const SB2_HEADER_BLOCKS: usize = 0x2c;
const SB2_KEY_BLOB_BLOCK: usize = 0x2e;
const SB2_KEY_BLOB_BLOCK_COUNT: usize = 0x30;
const SB2_TIMESTAMP: usize = 0x38;
const SB2_PRODUCT_VERSION: usize = 0x40;
const SB2_BUILD_NUMBER: usize = 0x58;

/// The SB2 header is 0x60 bytes, six 16-byte cipher blocks, followed by a
/// 32-byte HMAC.
const SB2_HEADER_SIZE: usize = 0x60;
const SB2_HEADER_BLOCK_COUNT: u16 = 6;
const CIPHER_BLOCK_SIZE: usize = 16;
const SB2_HMAC_SIZE: usize = 32;

/// SB2 minor versions 0 and 1.
const SB20_MINOR: u8 = 0;
const SB21_MINOR: u8 = 1;

/// SB2 header flags: SB2.0 signed (0x08) or unsigned (0x04); SB2.1 signed
/// and encrypted (0x0008) and SHA-256 of the boot sections present
/// (0x8000).
const SB2_SIGNED: u16 = 0x0008;
const SB21_SECTION_HASH: u16 = 0x8000;
const SECTION_HASH_SIZE: usize = 32;

/// SB2.1 certificate block V1 follows the header, HMAC and key blob
/// (SPSDK `update`: header size + HMAC size + key blob size).
const SB21_CERT_BLOCK: usize = 0xd0;

/// Certificate block V1 header (`"<4s2H6I"`, 32 bytes): magic, version,
/// header size 0x08 (SPSDK writes the 32-byte header size), flags, build
/// number, total image length, certificate count 0x18, certificate table
/// length 0x1C. The table holds each certificate as a 32-bit length and the
/// certificate bytes; the root key hash table (four SHA-256 values) follows
/// it, and the block is aligned to 16 bytes.
const CERT_BLOCK_V1_MAGIC: [u8; 4] = *b"cert";
const CERT_BLOCK_V1_HEADER_SIZE: usize = 32;
const CERT_V1_HEADER_LENGTH: usize = 0x08;
const CERT_V1_COUNT: usize = 0x18;
const CERT_V1_TABLE_LENGTH: usize = 0x1c;
const CERT_LENGTH_SIZE: usize = 4;
const ROOT_KEY_HASH_TABLE_SIZE: usize = 4 * 32;
const CERT_BLOCK_V1_ALIGNMENT: usize = 16;

/// SB3.1 header (`"<4s2H3LQ4L16s"`, 0x3C bytes).
const SB31_MAGIC: [u8; 4] = *b"sbv3";
const SB31_MINOR_VERSION: usize = 0x04;
const SB31_MAJOR_VERSION: usize = 0x06;
const SB31_FLAGS: usize = 0x08;
const SB31_BLOCK_COUNT: usize = 0x0c;
const SB31_BLOCK_SIZE: usize = 0x10;
const SB31_TIMESTAMP: usize = 0x14;
const SB31_FIRMWARE_VERSION: usize = 0x1c;
const SB31_IMAGE_TOTAL_LENGTH: usize = 0x20;
const SB31_IMAGE_TYPE: usize = 0x24;
const SB31_CERT_BLOCK_OFFSET: usize = 0x28;
const SB31_DESCRIPTION: usize = 0x2c;
const SB31_DESCRIPTION_SIZE: usize = 16;
const SB31_HEADER_SIZE: usize = 0x3c;
const SB31_MAJOR: u16 = 3;
const SB31_MINOR: u16 = 1;

/// Data block: block number, hash of the next block, 256 payload bytes.
const BLOCK_NUMBER_SIZE: usize = 4;
const BLOCK_PAYLOAD_SIZE: usize = 256;

/// SB3.1 image types (SPSDK `SecureBinary31Header`).
const SB31_IMAGE_TYPES: [(u32, &str); 2] = [(6, "normal"), (7, "NXP provisioning")];

/// Certificate block V2.1 header (`"<4s2HL"`): magic, minor, major, size of
/// the whole block 0x08.
const CERT_BLOCK_V21_MAGIC: [u8; 4] = *b"chdr";
const CERT_V21_BLOCK_SIZE: usize = 0x08;
const CERT_BLOCK_V21_HEADER_SIZE: usize = 12;

/// The hash that links SB3.1 blocks, chosen by the block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockHash {
    Sha256,
    Sha384,
}

impl BlockHash {
    /// Block sizes 292 (SHA-256) and 308 (SHA-384): block number, hash and
    /// payload.
    fn from_block_size(size: usize) -> Option<Self> {
        [Self::Sha256, Self::Sha384]
            .into_iter()
            .find(|hash| hash.block_size() == size)
    }

    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn block_size(self) -> usize {
        BLOCK_NUMBER_SIZE + self.len() + BLOCK_PAYLOAD_SIZE
    }

    /// ECDSA signature size SPSDK appends to block 0: P-256 with SHA-256,
    /// P-384 with SHA-384.
    fn signature_size(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha384 => 96,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
        }
    }

    fn matches(self, bytes: &[u8], expected: &[u8]) -> bool {
        match self {
            Self::Sha256 => Sha256::digest(bytes).as_slice() == expected,
            Self::Sha384 => Sha384::digest(bytes).as_slice() == expected,
        }
    }
}

/// `STMP` and `sgtl` with major version 2. SB1 (major version 1) shares
/// the magics and is not recognized.
pub(super) fn has_sb2_magic(data: &[u8]) -> bool {
    array::<4>(data, SB2_STMP_OFFSET).is_ok_and(|m| m == STMP)
        && array::<4>(data, SB2_SGTL_OFFSET).is_ok_and(|m| m == SGTL)
        && byte(data, SB2_MAJOR_VERSION).is_ok_and(|v| v == SB2_MAJOR)
}

/// `sbv3` with major version 3.
pub(super) fn has_sb31_magic(data: &[u8]) -> bool {
    data.starts_with(&SB31_MAGIC) && le_u16(data, SB31_MAJOR_VERSION).is_ok_and(|v| v == SB31_MAJOR)
}

/// A 16-byte block count or index in bytes.
fn blocks(count: u64) -> Result<usize> {
    to_usize(count * CIPHER_BLOCK_SIZE as u64, "block count")
}

/// `len` rounded up to the 16-byte certificate block alignment.
fn align_cert_block(len: usize) -> Result<usize> {
    let padded = end_of(len, CERT_BLOCK_V1_ALIGNMENT - 1)?;
    Ok(padded / CERT_BLOCK_V1_ALIGNMENT * CERT_BLOCK_V1_ALIGNMENT)
}

/// A product version: three BCD numbers, each stored byte-swapped in a
/// 16-bit word followed by a zero word (SPSDK `swap16`).
fn product_version(data: &[u8], at: usize) -> Result<String> {
    let mut parts = Vec::new();
    for index in 0..3 {
        let value = le_u16(data, at + index * 4)?.swap_bytes();
        let digits = format!("{value:X}");
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(format!("not BCD: 0x{value:04X} at 0x{:X}", at + index * 4));
        }
        parts.push(digits);
    }
    Ok(parts.join("."))
}

/// Fail unless `len` bytes of `what` at `offset` lie before `end`.
fn expect_within(what: &str, offset: usize, len: usize, end: usize) -> Result<()> {
    if end_of(offset, len)? > end {
        return Err(error(format!(
            "Invalid {what}: 0x{offset:X} + {len} B exceeds 0x{end:X}"
        )));
    }
    Ok(())
}

/// A certificate block's file range.
struct CertificateBlock {
    offset: usize,
    length: usize,
    /// Certificate count, which only certificate block V1 records.
    certificates: Option<u32>,
}

/// SB2 header fields that place the parts of the image, in bytes.
struct Sb2Layout {
    minor: u8,
    flags: u16,
    key_blob: usize,
    key_blob_size: usize,
    /// File offset of the first boot section.
    sections: usize,
    /// End of the image the header describes.
    image_size: usize,
}

impl Sb2Layout {
    fn version(&self) -> String {
        format!("2.{}", self.minor)
    }

    fn is_sb21(&self) -> bool {
        self.minor == SB21_MINOR
    }

    fn has_section_hash(&self) -> bool {
        has_section_hash(self.minor, self.flags)
    }
}

/// SB2.1 with the SHA-256 of the boot sections.
fn has_section_hash(minor: u8, flags: u16) -> bool {
    minor == SB21_MINOR && flags & SB21_SECTION_HASH != 0
}

/// SB2 header checks and the key blob and boot section offsets.
fn sb2_layout(data: &[u8]) -> Result<Sb2Layout> {
    if !has_sb2_magic(data) {
        return Err(error("Missing SB2 header magics STMP and sgtl"));
    }
    let minor = byte(data, SB2_MINOR_VERSION)?;
    if minor != SB20_MINOR && minor != SB21_MINOR {
        return Err(error(format!("Unsupported SB2 minor version {minor}")));
    }
    let header_blocks = le_u16(data, SB2_HEADER_BLOCKS)?;
    if header_blocks != SB2_HEADER_BLOCK_COUNT {
        return Err(error(format!(
            "Invalid SB2 header block count {header_blocks}: expected {SB2_HEADER_BLOCK_COUNT}"
        )));
    }
    let flags = le_u16(data, SB2_FLAGS)?;
    let mut image_size = blocks(u64::from(le_u32(data, SB2_IMAGE_BLOCKS)?))?;
    let mut sections = blocks(u64::from(le_u32(data, SB2_FIRST_BOOT_TAG_BLOCK)?))?;
    let key_blob = blocks(u64::from(le_u16(data, SB2_KEY_BLOB_BLOCK)?))?;
    let key_blob_size = blocks(u64::from(le_u16(data, SB2_KEY_BLOB_BLOCK_COUNT)?))?;
    // SPSDK's `update` leaves the SHA-256 that `export` writes in front of
    // the signature out of both block counts.
    if has_section_hash(minor, flags) {
        image_size = end_of(image_size, SECTION_HASH_SIZE)?;
        sections = end_of(sections, SECTION_HASH_SIZE)?;
    }
    if image_size > data.len() {
        return Err(error(format!(
            "Truncated SB2 image: header declares {image_size} B, {} B present",
            data.len()
        )));
    }
    if key_blob < SB2_HEADER_SIZE + SB2_HMAC_SIZE || key_blob_size == 0 {
        return Err(error(format!(
            "Invalid SB2 key blob at 0x{key_blob:X}: {key_blob_size} B"
        )));
    }
    expect_within("SB2 key blob", key_blob, key_blob_size, image_size)?;
    let key_blob_end = key_blob + key_blob_size;
    if sections < key_blob_end || sections >= image_size {
        return Err(error(format!(
            "Invalid SB2 first boot tag block at 0x{sections:X}: the key blob ends at 0x{key_blob_end:X} and the image at 0x{image_size:X}"
        )));
    }
    Ok(Sb2Layout {
        minor,
        flags,
        key_blob,
        key_blob_size,
        sections,
        image_size,
    })
}

/// The certificate table of certificate block V1: `count` entries, each a
/// 32-bit length and the certificate bytes, inside `table_length` bytes.
fn expect_certificate_table(
    image: &[u8],
    start: usize,
    count: u32,
    table_length: usize,
) -> Result<()> {
    let max_entries = table_length / CERT_LENGTH_SIZE;
    if count == 0 || usize::try_from(count).map_or(true, |count| count > max_entries) {
        return Err(error(format!(
            "Invalid SB2.1 certificate count {count} for a {table_length} B certificate table"
        )));
    }
    let table_end = start + table_length;
    let mut position = start;
    for index in 0..count {
        if position + CERT_LENGTH_SIZE > table_end {
            return Err(error(format!(
                "Truncated SB2.1 certificate table: certificate {index} at 0x{position:X}"
            )));
        }
        let length = le_u32(image, position)? as usize;
        let certificate = position + CERT_LENGTH_SIZE;
        if end_of(certificate, length)? > table_end {
            return Err(error(format!(
                "Invalid SB2.1 certificate {index} length {length} B at 0x{position:X}: exceeds the certificate table"
            )));
        }
        position = certificate + length;
    }
    Ok(())
}

/// SB2.1 certificate block V1 at 0xD0, which must end before `end`.
fn sb21_certificate_block(image: &[u8], end: usize) -> Result<CertificateBlock> {
    if array::<4>(image, SB21_CERT_BLOCK)? != CERT_BLOCK_V1_MAGIC {
        return Err(error(format!(
            "Missing SB2.1 certificate block magic cert at 0x{SB21_CERT_BLOCK:X}"
        )));
    }
    let header = slice(image, SB21_CERT_BLOCK, CERT_BLOCK_V1_HEADER_SIZE)?;
    let header_length = le_u32(header, CERT_V1_HEADER_LENGTH)? as usize;
    if header_length != CERT_BLOCK_V1_HEADER_SIZE {
        return Err(error(format!(
            "Invalid SB2.1 certificate block header size {header_length} B: expected {CERT_BLOCK_V1_HEADER_SIZE} B"
        )));
    }
    let count = le_u32(header, CERT_V1_COUNT)?;
    let table_length = le_u32(header, CERT_V1_TABLE_LENGTH)? as usize;
    let table = SB21_CERT_BLOCK + CERT_BLOCK_V1_HEADER_SIZE;
    expect_within("SB2.1 certificate table", table, table_length, end)?;
    expect_certificate_table(image, table, count, table_length)?;
    let unaligned = end_of(
        CERT_BLOCK_V1_HEADER_SIZE + ROOT_KEY_HASH_TABLE_SIZE,
        table_length,
    )?;
    let length = align_cert_block(unaligned)?;
    expect_within("SB2.1 certificate block", SB21_CERT_BLOCK, length, end)?;
    Ok(CertificateBlock {
        offset: SB21_CERT_BLOCK,
        length,
        certificates: Some(count),
    })
}

/// SB2.1: certificate block V1, the optional boot section hash and the
/// signature, in that order between the key blob and the boot sections.
fn push_sb21_signed_area<'a>(
    data: &[u8],
    image: &'a [u8],
    c: &mut Container<'a>,
    layout: &Sb2Layout,
) -> Result<()> {
    let cert_offset = le_u32(data, SB2_CERT_BLOCK_OFFSET)? as usize;
    if cert_offset != SB21_CERT_BLOCK {
        return Err(error(format!(
            "Invalid SB2.1 certificate block offset 0x{cert_offset:X}: expected 0x{SB21_CERT_BLOCK:X}"
        )));
    }
    let certificate = sb21_certificate_block(image, layout.sections)?;
    let mut signature = certificate.offset + certificate.length;
    if layout.has_section_hash() {
        expect_within(
            "SB2.1 boot section hash",
            signature,
            SECTION_HASH_SIZE,
            layout.sections,
        )?;
        c.notes.push(format!(
            "SHA-256 of the boot sections at 0x{signature:X}; not verified"
        ));
        signature += SECTION_HASH_SIZE;
    }
    if signature >= layout.sections {
        return Err(error(format!(
            "Missing SB2.1 signature: the boot sections start at 0x{:X}, right after the certificate block",
            layout.sections
        )));
    }
    let signature_size = layout.sections - signature;
    c.notes.push(format!(
        "Certificate block V1 at 0x{:X}: {} B, certificate count {}, root key hash table 128 B; signature {signature_size} B at 0x{signature:X}; certificates and signature not verified",
        certificate.offset,
        certificate.length,
        certificate.certificates.unwrap_or_default(),
    ));
    c.children.push(opaque_child(
        image,
        "Certificate block",
        certificate.offset,
        certificate.length,
    )?);
    c.children
        .push(opaque_child(image, "Signature", signature, signature_size)?);
    c.notes.push(
        "Boot section HMAC not verified; boot sections are AES-CTR encrypted with the key blob's data key and are not decrypted"
            .into(),
    );
    Ok(())
}

/// SB2.0: the encrypted certificate section between the key blob and the
/// boot sections and the signature after the image, when signed.
fn push_sb20_signed_area<'a>(
    data: &'a [u8],
    c: &mut Container<'a>,
    layout: &Sb2Layout,
) -> Result<()> {
    let key_blob_end = layout.key_blob + layout.key_blob_size;
    if layout.flags & SB2_SIGNED == 0 {
        c.notes.push("Unsigned SB2.0".into());
    } else {
        // SPSDK `BootImageV20.parse` checks the signature over the image
        // against the bytes after the `image_blocks` it counts.
        let signature_size = data.len() - layout.image_size;
        if signature_size == 0 {
            return Err(error(format!(
                "Missing SB2.0 signature after the image at 0x{:X}",
                layout.image_size
            )));
        }
        c.notes.push(format!(
            "Signed SB2.0: encrypted certificate section at 0x{key_blob_end:X}; signature {signature_size} B at 0x{:X}; not verified",
            layout.image_size
        ));
        if layout.sections > key_blob_end {
            c.children.push(opaque_child(
                data,
                "Certificate section",
                key_blob_end,
                layout.sections - key_blob_end,
            )?);
        }
        c.children.push(opaque_child(
            data,
            "Signature",
            layout.image_size,
            signature_size,
        )?);
        c.consumed = data.len();
    }
    c.notes.push(
        "Header HMAC not verified; boot sections are AES-CTR encrypted with the key blob's data key and are not decrypted"
            .into(),
    );
    Ok(())
}

/// Parse an SB2.0 or SB2.1 file: header checks, key blob, certificate
/// block or section and signature ranges, and the encrypted boot sections
/// as opaque children.
pub(super) fn parse_sb2(data: &[u8]) -> Result<Container<'_>> {
    let layout = sb2_layout(data)?;
    let image = &data[..layout.image_size];
    let version = layout.version();
    let mut c = Container::new(
        FileFormat::NxpSb,
        format!("SB{version} secure binary"),
        "nxp_sb",
    );
    c.opaque = true;
    c.consumed = layout.image_size;
    c.notes.push(format!(
        "NXP SB{version} secure binary: {} B in 16-byte cipher blocks; flags 0x{:04X}",
        layout.image_size, layout.flags
    ));
    c.notes
        .push("Secure Binary headers name no CPU or instruction set".into());
    c.children.push(opaque_child(
        image,
        "Key blob",
        layout.key_blob,
        layout.key_blob_size,
    )?);
    if layout.is_sb21() {
        push_sb21_signed_area(data, image, &mut c, &layout)?;
    } else {
        push_sb20_signed_area(data, &mut c, &layout)?;
    }
    c.children.push(opaque_child(
        image,
        "Boot sections",
        layout.sections,
        layout.image_size - layout.sections,
    )?);
    c.push_metadata("nxp_sb_version", "Secure Binary version", version);
    c.push_metadata(
        "nxp_sb_product_version",
        "Product version",
        product_version(data, SB2_PRODUCT_VERSION)?,
    );
    c.push_metadata(
        "nxp_sb_build_number",
        "Build number",
        u64::from(le_u32(data, SB2_BUILD_NUMBER)?),
    );
    c.push_metadata(
        "nxp_sb_timestamp",
        "Timestamp (microseconds since 2000-01-01)",
        le_u64(data, SB2_TIMESTAMP)?,
    );
    push_trailing(data, &mut c);
    Ok(c)
}

/// SB3.1 certificate block V2.1 at `offset`, inside block 0.
fn sb31_certificate_block(
    data: &[u8],
    offset: usize,
    block0_end: usize,
) -> Result<CertificateBlock> {
    if array::<4>(data, offset)? != CERT_BLOCK_V21_MAGIC {
        return Err(error(format!(
            "Missing SB3.1 certificate block magic chdr at 0x{offset:X}"
        )));
    }
    let length = le_u32(data, offset + CERT_V21_BLOCK_SIZE)? as usize;
    if length < CERT_BLOCK_V21_HEADER_SIZE {
        return Err(error(format!(
            "Invalid SB3.1 certificate block size {length} B"
        )));
    }
    expect_within("SB3.1 certificate block", offset, length, block0_end)?;
    Ok(CertificateBlock {
        offset,
        length,
        certificates: None,
    })
}

/// Verify the SB3.1 hash chain: block 0 holds the hash of block 1, each
/// block the hash of the next, and the last block zeros.
fn verify_hash_chain(data: &[u8], hash: BlockHash, first_block: usize, count: usize) -> Result<()> {
    let mut expected = slice(data, SB31_HEADER_SIZE, hash.len())?;
    for index in 0..count {
        let offset = first_block + index * hash.block_size();
        let block = slice(data, offset, hash.block_size())?;
        let number = le_u32(block, 0)?;
        if usize::try_from(number).ok() != Some(index + 1) {
            return Err(error(format!(
                "Invalid SB3.1 block number {number} at 0x{offset:X}: expected {}",
                index + 1
            )));
        }
        if !hash.matches(block, expected) {
            return Err(error(format!(
                "Invalid SB3.1 block {} at 0x{offset:X}: {} does not match the previous block",
                index + 1,
                hash.name()
            )));
        }
        expected = &block[BLOCK_NUMBER_SIZE..BLOCK_NUMBER_SIZE + hash.len()];
    }
    if expected.iter().any(|&b| b != 0) {
        return Err(error(
            "Invalid SB3.1 last block: the next-block hash is not zero",
        ));
    }
    Ok(())
}

/// The SB3.1 description: ASCII, zero padded; other bytes shown as `?`.
fn description(header: &[u8]) -> Result<String> {
    let field = slice(header, SB31_DESCRIPTION, SB31_DESCRIPTION_SIZE)?;
    Ok(field
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect())
}

/// Parse an SB3.1 file: header, block 0 layout and the data block hash
/// chain; the encrypted data blocks are opaque.
pub(super) fn parse_sb31(data: &[u8]) -> Result<Container<'_>> {
    if !has_sb31_magic(data) {
        return Err(error("Missing SB3.1 magic sbv3 and major version 3"));
    }
    let header = slice(data, 0, SB31_HEADER_SIZE)?;
    let minor = le_u16(header, SB31_MINOR_VERSION)?;
    if minor != SB31_MINOR {
        return Err(error(format!("Unsupported SB3 minor version {minor}")));
    }
    let block_size = le_u32(header, SB31_BLOCK_SIZE)? as usize;
    let hash = BlockHash::from_block_size(block_size)
        .ok_or_else(|| error(format!("Unsupported SB3.1 block size {block_size} B")))?;
    let cert_offset = le_u32(header, SB31_CERT_BLOCK_OFFSET)? as usize;
    if cert_offset != SB31_HEADER_SIZE + hash.len() {
        return Err(error(format!(
            "Invalid SB3.1 certificate block offset 0x{cert_offset:X}: expected 0x{:X}",
            SB31_HEADER_SIZE + hash.len()
        )));
    }
    let block0_end = le_u32(header, SB31_IMAGE_TOTAL_LENGTH)? as usize;
    if block0_end > data.len() {
        return Err(error(format!(
            "Truncated SB3.1 block 0: header declares {block0_end} B, {} B present",
            data.len()
        )));
    }
    let certificate = sb31_certificate_block(data, cert_offset, block0_end)?;
    let signature = certificate.offset + certificate.length;
    let signature_size = block0_end - signature;
    if signature_size != hash.signature_size() {
        return Err(error(format!(
            "Invalid SB3.1 signature size {signature_size} B at 0x{signature:X}: expected {} B for {}",
            hash.signature_size(),
            hash.name()
        )));
    }
    let count = le_u32(header, SB31_BLOCK_COUNT)? as usize;
    let available = (data.len() - block0_end) / block_size;
    if count > available {
        return Err(error(format!(
            "Truncated SB3.1 data blocks: header declares {count} blocks of {block_size} B, {available} present"
        )));
    }
    verify_hash_chain(data, hash, block0_end, count)?;
    let blocks_size = count * block_size;
    let mut c = Container::new(FileFormat::NxpSb, "SB3.1 secure binary", "nxp_sb");
    c.opaque = true;
    c.consumed = block0_end + blocks_size;
    c.notes.push(format!(
        "NXP SB3.1 secure binary: data block count {count}, {block_size} B each; {} block hash chain verified",
        hash.name()
    ));
    c.notes
        .push("Secure Binary headers name no CPU or instruction set".into());
    c.notes.push(format!(
        "Certificate block V2.1 at 0x{:X}: {} B; signature {signature_size} B at 0x{signature:X}; not verified",
        certificate.offset, certificate.length
    ));
    c.notes.push(
        "Data block payloads are encrypted with keys derived from the device key and are not decrypted"
            .into(),
    );
    c.children.push(opaque_child(
        data,
        "Certificate block",
        certificate.offset,
        certificate.length,
    )?);
    c.children
        .push(opaque_child(data, "Signature", signature, signature_size)?);
    if blocks_size > 0 {
        c.children
            .push(opaque_child(data, "Data blocks", block0_end, blocks_size)?);
    }
    let image_type = le_u32(header, SB31_IMAGE_TYPE)?;
    let type_name = SB31_IMAGE_TYPES
        .iter()
        .find(|(value, _)| *value == image_type)
        .map_or_else(
            || format!("type {image_type}"),
            |(_, name)| (*name).to_string(),
        );
    let description = description(header)?;
    c.push_metadata("nxp_sb_version", "Secure Binary version", "3.1");
    c.push_metadata("nxp_sb_image_type", "Image type", type_name);
    c.push_metadata(
        "nxp_sb_flags",
        "Flags",
        format!("0x{:08X}", le_u32(header, SB31_FLAGS)?),
    );
    c.push_metadata(
        "nxp_sb_firmware_version",
        "Firmware version",
        u64::from(le_u32(header, SB31_FIRMWARE_VERSION)?),
    );
    c.push_metadata(
        "nxp_sb_timestamp",
        "Timestamp",
        le_u64(header, SB31_TIMESTAMP)?,
    );
    if !description.is_empty() {
        c.push_metadata("nxp_sb_description", "Description", description);
    }
    push_trailing(data, &mut c);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_sizes_select_the_chain_hash() {
        assert_eq!(BlockHash::from_block_size(292), Some(BlockHash::Sha256));
        assert_eq!(BlockHash::from_block_size(308), Some(BlockHash::Sha384));
        assert_eq!(BlockHash::from_block_size(300), None);
        assert_eq!(BlockHash::Sha384.signature_size(), 96);
    }

    #[test]
    fn product_versions_are_byte_swapped_bcd() {
        // 1.2.10: 0x0001 -> 00 01, 0x0002 -> 00 02, 0x0010 -> 00 10.
        let data = [0, 1, 0, 0, 0, 2, 0, 0, 0, 0x10, 0, 0];
        assert_eq!(product_version(&data, 0).unwrap(), "1.2.10");
        let data = [0, 0xab, 0, 0, 0, 2, 0, 0, 0, 0x10, 0, 0];
        assert_eq!(product_version(&data, 0).unwrap(), "not BCD: 0x00AB at 0x0");
    }

    #[test]
    fn certificate_blocks_align_to_16_bytes() {
        assert_eq!(align_cert_block(32 + 128 + 68).unwrap(), 240);
        assert_eq!(align_cert_block(256).unwrap(), 256);
        assert!(align_cert_block(usize::MAX).is_err());
    }

    #[test]
    fn certificate_tables_must_hold_their_entries() {
        // Two entries: 4 + 8 and 4 + 4 bytes in a 24-byte table.
        let mut table = vec![0u8; 24];
        table[..4].copy_from_slice(&8u32.to_le_bytes());
        table[12..16].copy_from_slice(&4u32.to_le_bytes());
        assert!(expect_certificate_table(&table, 0, 2, 20).is_ok());
        assert!(expect_certificate_table(&table, 0, 2, 19).is_err());
        assert!(expect_certificate_table(&table, 0, 0, 20).is_err());
        assert!(expect_certificate_table(&table, 0, u32::MAX, 20).is_err());
    }
}
