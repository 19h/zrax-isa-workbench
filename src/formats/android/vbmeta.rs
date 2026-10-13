//! AVB vbmeta images (`vbmeta.img`, `vbmeta_system.img`, and the vbmeta
//! image an AVB footer points to): `AvbVBMetaImageHeader` and the
//! descriptors of AOSP `platform/external/avb` at `76117860`
//! (`libavb/avb_vbmeta_image.h`, `avb_descriptor.h`,
//! `avb_property_descriptor.h`, `avb_hashtree_descriptor.h`,
//! `avb_hash_descriptor.h`, `avb_kernel_cmdline_descriptor.h`,
//! `avb_chain_partition_descriptor.h`), with the checks of
//! `avb_vbmeta_image_verify` and the descriptors'
//! `*_validate_and_byteswap` functions.
//!
//! A 256-byte header is followed by the authentication block (hash and
//! signature) and the auxiliary block (public key, public key metadata
//! and descriptors). Every field is big-endian. The image is metadata: it
//! is summarized in notes and never analyzed as code. The hash over the
//! header and the auxiliary block is recomputed; the RSA signature and the
//! descriptors' partition digests are not verified.

use super::*;
use sha2::{Digest, Sha256, Sha512};

/// `AVB_VBMETA_IMAGE_HEADER_SIZE`.
const HEADER_SIZE: usize = 256;

/// libavb version at the pinned revision (`AVB_VERSION_MAJOR`,
/// `AVB_VERSION_MINOR`).
const AVB_VERSION_MAJOR: u32 = 1;
const AVB_VERSION_MINOR: u32 = 3;

/// `release_string[AVB_RELEASE_STRING_SIZE]` at 128; its last byte must be
/// NUL.
const RELEASE_STRING_OFFSET: usize = 128;
const AVB_RELEASE_STRING_SIZE: usize = 48;

/// The authentication and auxiliary block sizes are multiples of 64.
const BLOCK_ALIGNMENT: u64 = 64;

/// Header flags (`AvbVBMetaImageFlags`).
const AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: u32 = 1 << 0;
const AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: u32 = 1 << 1;

/// `AvbDescriptor`: `tag` and `num_bytes_following` (u64 each); the total
/// size is a multiple of 8.
const DESCRIPTOR_HEADER_SIZE: usize = 16;
const DESCRIPTOR_ALIGNMENT: u64 = 8;

/// Descriptor tags (`AvbDescriptorTag`).
const AVB_DESCRIPTOR_TAG_PROPERTY: u64 = 0;
const AVB_DESCRIPTOR_TAG_HASHTREE: u64 = 1;
const AVB_DESCRIPTOR_TAG_HASH: u64 = 2;
const AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE: u64 = 3;
const AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: u64 = 4;

/// Sizes of the descriptor structs, including the 16-byte header.
const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const HASHTREE_DESCRIPTOR_SIZE: usize = 180;
const HASH_DESCRIPTOR_SIZE: usize = 132;
const KERNEL_CMDLINE_DESCRIPTOR_SIZE: usize = 24;
const CHAIN_PARTITION_DESCRIPTOR_SIZE: usize = 92;

/// `hash_algorithm[32]` in hashtree and hash descriptors.
const HASH_ALGORITHM_SIZE: usize = 32;

/// Descriptors summarized one by one; further ones are counted.
const MAX_DESCRIPTOR_NOTES: usize = 64;

/// Longest property value or command line quoted in a note.
const MAX_QUOTED: usize = 256;

/// The digest an algorithm uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    fn size(self) -> u64 {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }

    /// The digest of `header` followed by `auxiliary`.
    fn digest(self, header: &[u8], auxiliary: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::new()
                .chain_update(header)
                .chain_update(auxiliary)
                .finalize()
                .to_vec(),
            Self::Sha512 => Sha512::new()
                .chain_update(header)
                .chain_update(auxiliary)
                .finalize()
                .to_vec(),
        }
    }
}

/// `AvbAlgorithmType` values, names and digests; `NONE` has no hash.
const ALGORITHMS: [(u32, &str, Option<HashAlgorithm>); 7] = [
    (0, "NONE", None),
    (1, "SHA256_RSA2048", Some(HashAlgorithm::Sha256)),
    (2, "SHA256_RSA4096", Some(HashAlgorithm::Sha256)),
    (3, "SHA256_RSA8192", Some(HashAlgorithm::Sha256)),
    (4, "SHA512_RSA2048", Some(HashAlgorithm::Sha512)),
    (5, "SHA512_RSA4096", Some(HashAlgorithm::Sha512)),
    (6, "SHA512_RSA8192", Some(HashAlgorithm::Sha512)),
];

/// `AvbVBMetaImageHeader` fields after the magic. Offsets of the hash and
/// signature are in the authentication block; those of the public key,
/// its metadata and the descriptors in the auxiliary block.
struct Header {
    version_major: u32,
    version_minor: u32,
    authentication_size: u64,
    auxiliary_size: u64,
    algorithm_type: u32,
    hash_offset: u64,
    hash_size: u64,
    signature_offset: u64,
    signature_size: u64,
    public_key_offset: u64,
    public_key_size: u64,
    public_key_metadata_offset: u64,
    public_key_metadata_size: u64,
    descriptors_offset: u64,
    descriptors_size: u64,
    rollback_index: u64,
    flags: u32,
    rollback_index_location: u32,
    release_string: String,
}

/// Header: magic, required libavb version (4, 8), block sizes (12, 20),
/// algorithm (28), hash, signature, public key, public key metadata and
/// descriptor ranges (32 to 104), rollback index (112), flags (120),
/// rollback index location (124), release string (128).
fn header(data: &[u8]) -> Result<Header> {
    let bytes = slice(data, 0, HEADER_SIZE, "vbmeta header")?;
    if !bytes.starts_with(AVB_VBMETA_MAGIC) {
        return Err(error("Missing vbmeta magic"));
    }
    let release = &bytes[RELEASE_STRING_OFFSET..RELEASE_STRING_OFFSET + AVB_RELEASE_STRING_SIZE];
    let header = Header {
        version_major: be_u32(bytes, 4)?,
        version_minor: be_u32(bytes, 8)?,
        authentication_size: be_u64(bytes, 12)?,
        auxiliary_size: be_u64(bytes, 20)?,
        algorithm_type: be_u32(bytes, 28)?,
        hash_offset: be_u64(bytes, 32)?,
        hash_size: be_u64(bytes, 40)?,
        signature_offset: be_u64(bytes, 48)?,
        signature_size: be_u64(bytes, 56)?,
        public_key_offset: be_u64(bytes, 64)?,
        public_key_size: be_u64(bytes, 72)?,
        public_key_metadata_offset: be_u64(bytes, 80)?,
        public_key_metadata_size: be_u64(bytes, 88)?,
        descriptors_offset: be_u64(bytes, 96)?,
        descriptors_size: be_u64(bytes, 104)?,
        rollback_index: be_u64(bytes, 112)?,
        flags: be_u32(bytes, 120)?,
        rollback_index_location: be_u32(bytes, 124)?,
        release_string: asciiz(release),
    };
    if header.version_major != AVB_VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported vbmeta required libavb version {}.{}",
            header.version_major, header.version_minor
        )));
    }
    if release[AVB_RELEASE_STRING_SIZE - 1] != 0 {
        return Err(error("Invalid vbmeta release string: no NUL terminator"));
    }
    if header.authentication_size % BLOCK_ALIGNMENT != 0
        || header.auxiliary_size % BLOCK_ALIGNMENT != 0
    {
        return Err(error(format!(
            "Invalid vbmeta block sizes {} B and {} B: not multiples of 64",
            header.authentication_size, header.auxiliary_size
        )));
    }
    Ok(header)
}

/// Whether `offset + size` fits in a block of `block_size` bytes.
fn is_inside(offset: u64, size: u64, block_size: u64) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| end <= block_size)
}

/// The two blocks after the header.
struct Blocks<'a> {
    /// Hash and signature.
    authentication: &'a [u8],
    /// Public key, public key metadata and descriptors.
    auxiliary: &'a [u8],
}

/// The authentication and auxiliary blocks, after the range checks of
/// `avb_vbmeta_image_verify`.
fn blocks<'a>(data: &'a [u8], header: &Header) -> Result<Blocks<'a>> {
    let authentication = slice64(
        data,
        HEADER_SIZE as u64,
        header.authentication_size,
        "vbmeta authentication block",
    )?;
    let auxiliary_at = HEADER_SIZE + authentication.len();
    let auxiliary = slice64(
        data,
        auxiliary_at as u64,
        header.auxiliary_size,
        "vbmeta auxiliary block",
    )?;
    let ranges = [
        (
            header.hash_offset,
            header.hash_size,
            header.authentication_size,
            "hash",
        ),
        (
            header.signature_offset,
            header.signature_size,
            header.authentication_size,
            "signature",
        ),
        (
            header.public_key_offset,
            header.public_key_size,
            header.auxiliary_size,
            "public key",
        ),
        (
            header.descriptors_offset,
            header.descriptors_size,
            header.auxiliary_size,
            "descriptors",
        ),
    ];
    for (offset, size, block_size, what) in ranges {
        if !is_inside(offset, size, block_size) {
            return Err(error(format!(
                "Invalid vbmeta {what} range 0x{offset:X} + {size} B outside its {block_size} B block"
            )));
        }
    }
    if header.public_key_metadata_size > 0
        && !is_inside(
            header.public_key_metadata_offset,
            header.public_key_metadata_size,
            header.auxiliary_size,
        )
    {
        return Err(error(format!(
            "Invalid vbmeta public key metadata range 0x{:X} + {} B outside its {} B block",
            header.public_key_metadata_offset,
            header.public_key_metadata_size,
            header.auxiliary_size
        )));
    }
    Ok(Blocks {
        authentication,
        auxiliary,
    })
}

/// The `size` bytes at `offset` in `block`, which [`blocks`] has checked.
fn part(block: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = usize::try_from(offset).expect("checked against the block");
    let len = usize::try_from(size).expect("checked against the block");
    &block[start..start + len]
}

/// What the hash check established.
enum HashCheck {
    /// `NONE`: the image is not signed.
    NotSigned,
    Verified(HashAlgorithm),
    Mismatch(HashAlgorithm),
}

/// The algorithm and what recomputing its hash established.
struct Signing {
    /// `AvbAlgorithmType` name.
    algorithm: &'static str,
    hash: HashCheck,
}

/// The algorithm's name and the result of recomputing the hash.
fn check_hash(header: &Header, header_bytes: &[u8], blocks: &Blocks<'_>) -> Result<Signing> {
    let Some(&(_, name, digest)) = ALGORITHMS
        .iter()
        .find(|&&(id, _, _)| id == header.algorithm_type)
    else {
        return Err(error(format!(
            "Unknown vbmeta algorithm type {}",
            header.algorithm_type
        )));
    };
    let Some(digest) = digest else {
        return Ok(Signing {
            algorithm: name,
            hash: HashCheck::NotSigned,
        });
    };
    if header.hash_size != digest.size() {
        return Err(error(format!(
            "Invalid vbmeta hash size {} B for {name}",
            header.hash_size
        )));
    }
    let stored = part(blocks.authentication, header.hash_offset, header.hash_size);
    let hash = if digest.digest(header_bytes, blocks.auxiliary) == stored {
        HashCheck::Verified(digest)
    } else {
        HashCheck::Mismatch(digest)
    };
    Ok(Signing {
        algorithm: name,
        hash,
    })
}

/// One descriptor: its tag and the bytes after the 16-byte header.
struct Descriptor<'a> {
    tag: u64,
    /// The whole descriptor, header included.
    bytes: &'a [u8],
}

/// Walk the descriptor area as `avb_descriptor_foreach` does: each
/// descriptor's total size is a multiple of 8 and fits the area.
fn descriptors(area: &[u8]) -> Result<Vec<Descriptor<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < area.len() {
        let header = slice(area, pos, DESCRIPTOR_HEADER_SIZE, "vbmeta descriptor")?;
        let tag = be_u64(header, 0)?;
        let following = be_u64(header, 8)?;
        let total = following
            .checked_add(DESCRIPTOR_HEADER_SIZE as u64)
            .filter(|total| total % DESCRIPTOR_ALIGNMENT == 0)
            .ok_or_else(|| {
                error(format!(
                    "Invalid vbmeta descriptor length {following} B at descriptor offset 0x{pos:X}"
                ))
            })?;
        let bytes = slice64(area, pos as u64, total, "vbmeta descriptor")?;
        out.push(Descriptor { tag, bytes });
        pos += bytes.len();
    }
    Ok(out)
}

/// A UTF-8 field, lossily decoded and cut at [`MAX_QUOTED`] characters.
fn quoted(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.chars().count() <= MAX_QUOTED {
        return text.into_owned();
    }
    let cut: String = text.chars().take(MAX_QUOTED).collect();
    format!("{cut}...")
}

/// The trailing fields of a descriptor, each `len` bytes after `start`,
/// which must fit in the descriptor (`expected_size <=
/// num_bytes_following`).
fn trailing<'a>(
    descriptor: &Descriptor<'a>,
    start: usize,
    lengths: &[u64],
    what: &str,
) -> Result<Vec<&'a [u8]>> {
    let mut out = Vec::with_capacity(lengths.len());
    let mut at = start as u64;
    for &len in lengths {
        let field = slice64(descriptor.bytes, at, len, what).map_err(|_| {
            error(format!(
                "Invalid vbmeta {what}: fields exceed its {} B",
                descriptor.bytes.len()
            ))
        })?;
        out.push(field);
        at += len;
    }
    Ok(out)
}

/// The fixed part of a descriptor of `size` bytes.
fn fixed<'a>(descriptor: &Descriptor<'a>, size: usize, what: &str) -> Result<&'a [u8]> {
    slice(descriptor.bytes, 0, size, what).map_err(|_| {
        error(format!(
            "Invalid vbmeta {what}: {} B, the fixed part needs {size} B",
            descriptor.bytes.len()
        ))
    })
}

/// A note summarizing one descriptor, after its validity checks.
fn describe(descriptor: &Descriptor<'_>) -> Result<String> {
    match descriptor.tag {
        AVB_DESCRIPTOR_TAG_PROPERTY => {
            let what = "property descriptor";
            let bytes = fixed(descriptor, PROPERTY_DESCRIPTOR_SIZE, what)?;
            let key_len = be_u64(bytes, 16)?;
            let value_len = be_u64(bytes, 24)?;
            // Key and value are each followed by a NUL byte.
            let key_end = key_len.saturating_add(1);
            let fields = trailing(
                descriptor,
                PROPERTY_DESCRIPTOR_SIZE,
                &[key_end, value_len.saturating_add(1)],
                what,
            )?;
            let key = &fields[0][..fields[0].len() - 1];
            let value = &fields[1][..fields[1].len() - 1];
            Ok(format!("Property {} = {}", quoted(key), quoted(value)))
        }
        AVB_DESCRIPTOR_TAG_HASHTREE => {
            let what = "hashtree descriptor";
            let bytes = fixed(descriptor, HASHTREE_DESCRIPTOR_SIZE, what)?;
            let lengths = [
                u64::from(be_u32(bytes, 104)?),
                u64::from(be_u32(bytes, 108)?),
                u64::from(be_u32(bytes, 112)?),
            ];
            let fields = trailing(descriptor, HASHTREE_DESCRIPTOR_SIZE, &lengths, what)?;
            let algorithm = asciiz(&bytes[72..72 + HASH_ALGORITHM_SIZE]);
            let fec = match be_u32(bytes, 52)? {
                0 => "no FEC".to_string(),
                roots => format!(
                    "FEC {roots} roots at 0x{:X} ({} B)",
                    be_u64(bytes, 56)?,
                    be_u64(bytes, 64)?
                ),
            };
            Ok(format!(
                "Hashtree descriptor for {}: dm-verity v{}, {} B image, {algorithm}, {} B data and {} B hash blocks, tree at 0x{:X} ({} B), {fec}; root digest {} B, not verified",
                quoted(fields[0]),
                be_u32(bytes, 16)?,
                be_u64(bytes, 20)?,
                be_u32(bytes, 44)?,
                be_u32(bytes, 48)?,
                be_u64(bytes, 28)?,
                be_u64(bytes, 36)?,
                lengths[2]
            ))
        }
        AVB_DESCRIPTOR_TAG_HASH => {
            let what = "hash descriptor";
            let bytes = fixed(descriptor, HASH_DESCRIPTOR_SIZE, what)?;
            let lengths = [
                u64::from(be_u32(bytes, 56)?),
                u64::from(be_u32(bytes, 60)?),
                u64::from(be_u32(bytes, 64)?),
            ];
            let fields = trailing(descriptor, HASH_DESCRIPTOR_SIZE, &lengths, what)?;
            let algorithm = asciiz(&bytes[24..24 + HASH_ALGORITHM_SIZE]);
            Ok(format!(
                "Hash descriptor for {}: {algorithm} over {} B; digest {} B, not verified",
                quoted(fields[0]),
                be_u64(bytes, 16)?,
                lengths[2]
            ))
        }
        AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE => {
            let what = "kernel cmdline descriptor";
            let bytes = fixed(descriptor, KERNEL_CMDLINE_DESCRIPTOR_SIZE, what)?;
            let length = u64::from(be_u32(bytes, 20)?);
            let fields = trailing(descriptor, KERNEL_CMDLINE_DESCRIPTOR_SIZE, &[length], what)?;
            Ok(format!(
                "Kernel cmdline descriptor (flags 0x{:X}): {}",
                be_u32(bytes, 16)?,
                quoted(fields[0])
            ))
        }
        AVB_DESCRIPTOR_TAG_CHAIN_PARTITION => {
            let what = "chain partition descriptor";
            let bytes = fixed(descriptor, CHAIN_PARTITION_DESCRIPTOR_SIZE, what)?;
            let location = be_u32(bytes, 16)?;
            if location < 1 {
                return Err(error(
                    "Invalid vbmeta chain partition descriptor: rollback index location 0",
                ));
            }
            let lengths = [u64::from(be_u32(bytes, 20)?), u64::from(be_u32(bytes, 24)?)];
            let fields = trailing(descriptor, CHAIN_PARTITION_DESCRIPTOR_SIZE, &lengths, what)?;
            Ok(format!(
                "Chain partition descriptor for {}: rollback index location {location}, {} B public key",
                quoted(fields[0]),
                lengths[1]
            ))
        }
        tag => Ok(format!(
            "Descriptor with unknown tag {tag} ({} B)",
            descriptor.bytes.len()
        )),
    }
}

/// Parse a vbmeta image into an opaque, metadata-only container.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = header(data)?;
    let blocks = blocks(data, &header)?;
    let signing = check_hash(&header, &data[..HEADER_SIZE], &blocks)?;
    let algorithm = signing.algorithm;
    let area = part(
        blocks.auxiliary,
        header.descriptors_offset,
        header.descriptors_size,
    );
    let descriptors = descriptors(area)?;
    let summaries = descriptors
        .iter()
        .map(describe)
        .collect::<Result<Vec<_>>>()?;
    let end = HEADER_SIZE + blocks.authentication.len() + blocks.auxiliary.len();

    let mut c = Container::new(
        FileFormat::AndroidVbmeta,
        format!(
            "vbmeta image (libavb {}.{})",
            header.version_major, header.version_minor
        ),
        KEY_PREFIX,
    );
    c.consumed = end;
    c.opaque = true;
    c.notes.push(format!(
        "AVB vbmeta image: requires libavb {}.{}; {algorithm}; rollback index {} at location {}; {}",
        header.version_major,
        header.version_minor,
        header.rollback_index,
        header.rollback_index_location,
        counted(descriptors.len(), "descriptor", "descriptors")
    ));
    if header.version_minor > AVB_VERSION_MINOR {
        c.notes.push(format!(
            "The image requires libavb {}.{}; the reference reader is libavb {AVB_VERSION_MAJOR}.{AVB_VERSION_MINOR}",
            header.version_major, header.version_minor
        ));
    }
    c.notes.push(match signing.hash {
        HashCheck::NotSigned => "Algorithm NONE: the image is not signed".to_string(),
        HashCheck::Verified(digest) => format!(
            "{} of the header and auxiliary block matches the stored hash; RSA signature not verified",
            digest.name()
        ),
        HashCheck::Mismatch(digest) => format!(
            "{} of the header and auxiliary block does not match the stored hash; RSA signature not verified",
            digest.name()
        ),
    });
    if header.flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED != 0 {
        c.notes.push("Flag: hashtree verification disabled".into());
    }
    if header.flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED != 0 {
        c.notes.push("Flag: verification disabled".into());
    }
    let listed = summaries.len().min(MAX_DESCRIPTOR_NOTES);
    c.notes.extend(summaries.iter().take(listed).cloned());
    if summaries.len() > listed {
        c.notes.push(format!(
            "{} further descriptors were not summarized",
            summaries.len() - listed
        ));
    }
    let rest = &data[end..];
    if !is_padding(rest) {
        c.notes.push(format!(
            "{} after the auxiliary block are not described by the header",
            size_text(rest.len())
        ));
    }
    push_vbmeta_metadata(&mut c, &header, algorithm, descriptors.len());
    Ok(c)
}

/// Header fields as metadata.
fn push_vbmeta_metadata(c: &mut Container<'_>, header: &Header, algorithm: &str, count: usize) {
    c.push_metadata(
        "android_vbmeta_required_version",
        "Required libavb version",
        format!("{}.{}", header.version_major, header.version_minor),
    );
    c.push_metadata(
        "android_vbmeta_algorithm",
        "Algorithm",
        algorithm.to_string(),
    );
    c.push_metadata(
        "android_vbmeta_rollback_index",
        "Rollback index",
        header.rollback_index,
    );
    c.push_metadata(
        "android_vbmeta_rollback_index_location",
        "Rollback index location",
        u64::from(header.rollback_index_location),
    );
    c.push_metadata(
        "android_vbmeta_flags",
        "Flags",
        format!("0x{:X}", header.flags),
    );
    if !header.release_string.is_empty() {
        c.push_metadata(
            "android_vbmeta_release_string",
            "Release string",
            header.release_string.clone(),
        );
    }
    c.push_metadata(
        "android_vbmeta_authentication_size",
        "Authentication block (B)",
        header.authentication_size,
    );
    c.push_metadata(
        "android_vbmeta_auxiliary_size",
        "Auxiliary block (B)",
        header.auxiliary_size,
    );
    c.push_metadata(
        "android_vbmeta_signature_size",
        "Signature (B)",
        header.signature_size,
    );
    c.push_metadata(
        "android_vbmeta_public_key_size",
        "Public key (B)",
        header.public_key_size,
    );
    c.push_metadata(
        "android_vbmeta_descriptor_count",
        "Descriptors",
        count as u64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_walk_needs_8_byte_multiples_inside_the_area() {
        let mut area = vec![0u8; 32];
        area[7] = 9; // tag 9
        area[15] = 16; // 16 bytes follow
        let walked = descriptors(&area).unwrap();
        assert_eq!((walked.len(), walked[0].tag), (1, 9));
        assert_eq!(
            describe(&walked[0]).unwrap(),
            "Descriptor with unknown tag 9 (32 B)"
        );
        area[15] = 12;
        assert!(descriptors(&area).is_err());
        area[15] = 24;
        assert!(descriptors(&area).is_err());
        assert!(descriptors(&area[..8]).is_err());
    }

    #[test]
    fn long_fields_are_cut_when_quoted() {
        assert_eq!(quoted(b"ro.build"), "ro.build");
        let long = vec![b'a'; MAX_QUOTED + 1];
        assert!(quoted(&long).ends_with("..."));
        assert!(is_inside(0, 64, 64));
        assert!(!is_inside(1, 64, 64));
        assert!(!is_inside(u64::MAX, 2, 64));
    }
}
