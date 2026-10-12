//! dyld shared cache headers (`struct dyld_cache_header`).
//!
//! Layout: dyld-1378 `include/mach-o/dyld_cache_format.h`, with the field
//! gates of `common/DyldSharedCache.cpp` and `other-tools/dsc_extractor.cpp`.
//! `mappingOffset` is both the offset of the mapping table and the header
//! size, so it decides which fields exist (dyld-97.1 writes 0x28,
//! dyld-210.2.3 0x48, dyld-360.22 0x70, dyld-519.2.2 0x98, dyld-1378
//! 0x228):
//!
//! ```text
//! 0x000 magic[16]            "dyld_v1", spaces, architecture token, NUL
//! 0x010 mappingOffset u32    0x014 mappingCount u32
//! 0x018 imagesOffsetOld u32  0x01C imagesCountOld u32
//! 0x028 codeSignatureOffset u64  0x030 codeSignatureSize u64
//! 0x048 localSymbolsOffset u64   0x050 localSymbolsSize u64
//! 0x058 uuid[16]             0x0D8 platform u32
//! 0x188 subCacheArrayOffset u32  0x18C subCacheArrayCount u32
//! 0x190 symbolFileUUID[16]   0x1C0 imagesOffset u32  0x1C4 imagesCount u32
//! ```
//!
//! Tables: `dyld_cache_mapping_info` (32 B: `address`, `size`, `fileOffset`
//! u64; `maxProt`, `initProt` u32), `dyld_cache_image_info` (32 B: `address`
//! u64 at 0x00, `pathFileOffset` u32 at 0x18), `dyld_subcache_entry_v1`
//! (24 B) and `dyld_subcache_entry` (56 B, `fileSuffix[32]` at 0x18).
//! Integers use the cache's byte order: little-endian, except the
//! big-endian PowerPC caches of dyld-97.1 (`launch-cache/Architectures.hpp`).
//!
//! An image's Mach-O header lies at its unslid address; the file offset is
//! the containing mapping's `fileOffset` plus the distance from the
//! mapping's `address`. Images of a split cache live in other files, so
//! only images whose header maps into this file are listed as slices.

use super::*;
use crate::formats::magic::{MACHO_32_BE, MACHO_32_LE, MACHO_64_BE, MACHO_64_LE};

/// Bytes of the magic field.
const MAGIC_SIZE: usize = 16;

/// The magic's version prefix (`SubCache.cpp` `writeCacheHeader`).
const MAGIC_PREFIX: &[u8; 7] = b"dyld_v1";

/// Header fields, by offset.
const MAPPING_OFFSET: usize = 0x10;
const MAPPING_COUNT: usize = 0x14;
const IMAGES_OFFSET_OLD: usize = 0x18;
const IMAGES_COUNT_OLD: usize = 0x1c;
const CODE_SIGNATURE_OFFSET: usize = 0x28;
const CODE_SIGNATURE_SIZE: usize = 0x30;
const LOCAL_SYMBOLS_OFFSET: usize = 0x48;
const LOCAL_SYMBOLS_SIZE: usize = 0x50;
const UUID: usize = 0x58;
const PLATFORM: usize = 0xd8;
const SUBCACHE_ARRAY_OFFSET: usize = 0x188;
const SUBCACHE_ARRAY_COUNT: usize = 0x18c;
const SYMBOL_FILE_UUID: usize = 0x190;
const IMAGES_OFFSET: usize = 0x1c0;
const IMAGES_COUNT: usize = 0x1c4;
const CACHE_SUB_TYPE: usize = 0x1c8;

/// UUID fields are 16 bytes.
const UUID_SIZE: usize = 16;

/// The smallest known header (dyld-97.1 ends after `dyldBaseAddress`).
const MIN_HEADER_SIZE: u32 = 0x28;

/// dyld's sanity limits (`DyldSharedCache.cpp` `forEachRegion`): at most
/// 1024 header bytes and 20 mappings.
const MAX_HEADER_SIZE: u32 = 1024;
const MAX_MAPPINGS: u32 = 20;

/// Table entry sizes.
const MAPPING_INFO_SIZE: usize = 32;
const IMAGE_INFO_SIZE: usize = 32;
const SUBCACHE_ENTRY_V1_SIZE: usize = 24;
const SUBCACHE_ENTRY_SIZE: usize = 56;

/// `pathFileOffset` in `dyld_cache_image_info`.
const IMAGE_PATH_OFFSET: usize = 0x18;

/// `fileSuffix` in `dyld_subcache_entry`.
const SUBCACHE_SUFFIX: usize = 0x18;
const SUBCACHE_SUFFIX_SIZE: usize = 32;

/// `VM_PROT_*` bits (xnu `osfmk/mach/vm_prot.h`).
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;

/// `mach_header` sizes and the `sizeofcmds` field (xnu
/// `EXTERNAL_HEADERS/mach-o/loader.h`).
const MACH_HEADER_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;
const MACH_SIZEOFCMDS: usize = 20;

/// Longest image path read, including the NUL (Darwin `PATH_MAX`; our
/// bound).
const MAX_PATH_SIZE: usize = 1024;

/// Most image table entries read per cache. A cache holds thousands of
/// dylibs, so this stays well below `MAX_COMPONENTS`; the rest are counted
/// in a note (our bound).
const MAX_LISTED_IMAGES: usize = 256;

/// Most paths of images outside this file recorded in metadata (our bound).
const MAX_LISTED_UNMAPPED: usize = 16;

/// Most subcache file suffixes named in the notes (our bound).
const MAX_LISTED_SUFFIXES: usize = 8;

/// An architecture token of the cache magic and the target it names.
struct Arch {
    token: &'static str,
    target: Target,
    /// The header and tables are big-endian.
    big_endian: bool,
    /// What the token adds to the ISA, when anything.
    detail: Option<&'static str>,
}

const fn little(token: &'static str, isa: Isa, bits: u8, detail: Option<&'static str>) -> Arch {
    Arch {
        token,
        target: Target::new(isa, bits, Endianness::Little),
        big_endian: false,
        detail,
    }
}

const fn big(token: &'static str, isa: Isa, bits: u8) -> Arch {
    Arch {
        token,
        target: Target::new(isa, bits, Endianness::Big),
        big_endian: true,
        detail: Some("PowerPC cache; big-endian header and tables"),
    }
}

/// Architecture tokens the cache builders write (dyld-1378
/// `mach_o/Architecture.cpp` and `dsc_extractor.cpp`; dyld-210.2.3 and
/// dyld-360.22 `archName`; dyld-97.1 for PowerPC). Every Arm and x86 cache
/// is little-endian. Tokens that old builders could produce but no reader
/// lists (`armv4t`, `arm`) are not mapped.
const ARCHES: &[Arch] = &[
    little("i386", Isa::X86, 32, None),
    little("x86_64", Isa::X86_64, 64, None),
    little(
        "x86_64h",
        Isa::X86_64,
        64,
        Some("x86_64h: x86-64 with the Haswell feature subset (CPU_SUBTYPE_X86_64_H)"),
    ),
    little("armv5", Isa::Arm, 32, None),
    little("armv6", Isa::Arm, 32, None),
    little("armv7", Isa::Arm, 32, None),
    little("armv7f", Isa::Arm, 32, None),
    little("armv7s", Isa::Arm, 32, None),
    little("armv7k", Isa::Arm, 32, None),
    little("arm64", Isa::AArch64, 64, None),
    little(
        "arm64e",
        Isa::AArch64,
        64,
        Some("arm64e: AArch64 with the pointer-authentication ABI"),
    ),
    little(
        "arm64_32",
        Isa::AArch64,
        32,
        Some(
            "arm64_32: AArch64 instructions with 32-bit pointers (ILP32); bit width reported as 32, as for Mach-O CPU_TYPE_ARM64_32",
        ),
    ),
    big("ppc", Isa::Ppc, 32),
    big("ppc64", Isa::Ppc64, 64),
];

/// `PLATFORM_*` values (xnu `EXTERNAL_HEADERS/mach-o/loader.h`; 11 to 14
/// from the macOS 27.2 SDK `mach-o/loader.h`). The platform is not ISA
/// evidence.
const PLATFORMS: &[(u32, &str)] = &[
    (1, "macOS"),
    (2, "iOS"),
    (3, "tvOS"),
    (4, "watchOS"),
    (5, "bridgeOS"),
    (6, "Mac Catalyst"),
    (7, "iOS simulator"),
    (8, "tvOS simulator"),
    (9, "watchOS simulator"),
    (10, "DriverKit"),
    (11, "visionOS"),
    (12, "visionOS simulator"),
    (13, "firmware"),
    (14, "sepOS"),
];

/// One `dyld_cache_mapping_info` entry.
struct Mapping {
    /// Unslid start address.
    address: u64,
    /// Size in bytes.
    size: u64,
    /// File offset of the mapped bytes.
    file_offset: u64,
    max_prot: u32,
    init_prot: u32,
}

impl Mapping {
    /// File offset of `address`, when this mapping contains it.
    fn file_offset_of(&self, address: u64) -> Option<u64> {
        let delta = address.checked_sub(self.address)?;
        if delta >= self.size {
            return None;
        }
        self.file_offset.checked_add(delta)
    }

    /// File offset just past the mapped bytes; checked when parsed.
    fn file_end(&self) -> u64 {
        self.file_offset + self.size
    }
}

fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn u64_at(data: &[u8], at: usize, le: bool) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn usize_at(data: &[u8], at: usize, le: bool) -> Result<usize> {
    usize::try_from(u32_at(data, at, le)?).map_err(|_| error("Invalid dyld cache table field"))
}

/// Strong recognition: the `dyld_v1` prefix of the magic.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC_PREFIX)
}

/// The architecture token: the bytes between the prefix and the NUL at
/// byte 15, after the padding spaces (`SubCache.cpp` right-aligns it).
fn magic_token(data: &[u8]) -> Result<&str> {
    let magic = slice(data, 0, MAGIC_SIZE)?;
    if !magic.starts_with(MAGIC_PREFIX) {
        return Err(error("Missing dyld cache magic"));
    }
    if magic[MAGIC_SIZE - 1] != 0 {
        return Err(error(format!(
            "Invalid dyld cache magic: byte 15 is 0x{:02X}, expected NUL",
            magic[MAGIC_SIZE - 1]
        )));
    }
    let field = &magic[MAGIC_PREFIX.len()..MAGIC_SIZE - 1];
    let start = field.iter().position(|&b| b != b' ').unwrap_or(field.len());
    let token = &field[start..];
    let valid = !token.is_empty()
        && token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !valid {
        return Err(error(format!(
            "Invalid dyld cache architecture token \"{}\"",
            printable(field, field.len())
        )));
    }
    Ok(std::str::from_utf8(token).expect("token is ASCII"))
}

/// `mappingOffset`, which is the header size: at least the dyld-97.1
/// header, at most dyld's limit, and present in full.
fn header_size(data: &[u8], le: bool) -> Result<usize> {
    let size = u32_at(data, MAPPING_OFFSET, le)?;
    if !(MIN_HEADER_SIZE..=MAX_HEADER_SIZE).contains(&size) {
        return Err(error(format!(
            "Invalid dyld cache mappingOffset 0x{size:X}: expected 0x{MIN_HEADER_SIZE:X} to 0x{MAX_HEADER_SIZE:X}"
        )));
    }
    let size = usize::try_from(size).map_err(|_| error("Invalid dyld cache mappingOffset"))?;
    slice(data, 0, size)?;
    Ok(size)
}

/// Whether a header of `header_size` bytes holds the `size`-byte field at
/// `offset`.
fn has_field(header_size: usize, offset: usize, size: usize) -> bool {
    header_size >= offset + size
}

/// The `count` entries of `entry_size` bytes at `offset`, which must lie in
/// the file.
fn table<'a>(
    data: &'a [u8],
    offset: usize,
    count: usize,
    entry_size: usize,
    what: &str,
) -> Result<&'a [u8]> {
    let available = data.len().saturating_sub(offset);
    if count > available / entry_size {
        return Err(error(format!(
            "Truncated dyld cache {what} table at 0x{offset:X}: {count} entries of {entry_size} B, {available} B available"
        )));
    }
    slice(data, offset, count * entry_size)
}

/// The mapping table at `mappingOffset`. A mapping whose range wraps is an
/// error; one that extends past the file is kept and reported.
fn mappings(data: &[u8], header_size: usize, le: bool) -> Result<Vec<Mapping>> {
    let count = u32_at(data, MAPPING_COUNT, le)?;
    if count > MAX_MAPPINGS {
        return Err(error(format!(
            "Invalid dyld cache mappingCount {count}: dyld accepts at most {MAX_MAPPINGS}"
        )));
    }
    let count = usize::try_from(count).map_err(|_| error("Invalid dyld cache mappingCount"))?;
    let entries = table(data, header_size, count, MAPPING_INFO_SIZE, "mapping")?;
    let mut mappings = Vec::with_capacity(count);
    for (i, entry) in entries.chunks_exact(MAPPING_INFO_SIZE).enumerate() {
        let mapping = Mapping {
            address: u64_at(entry, 0x00, le)?,
            size: u64_at(entry, 0x08, le)?,
            file_offset: u64_at(entry, 0x10, le)?,
            max_prot: u32_at(entry, 0x18, le)?,
            init_prot: u32_at(entry, 0x1c, le)?,
        };
        let wraps = mapping.address.checked_add(mapping.size).is_none()
            || mapping.file_offset.checked_add(mapping.size).is_none();
        if wraps {
            return Err(error(format!(
                "Invalid dyld cache mapping {i} at 0x{:X}: address or file range overflows",
                header_size + i * MAPPING_INFO_SIZE
            )));
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}

/// `VM_PROT_*` bits as `rwx`.
fn protection(prot: u32) -> String {
    [
        (VM_PROT_READ, 'r'),
        (VM_PROT_WRITE, 'w'),
        (VM_PROT_EXECUTE, 'x'),
    ]
    .iter()
    .map(|&(bit, name)| if prot & bit != 0 { name } else { '-' })
    .collect()
}

/// A UUID as `8-4-4-4-12` uppercase hex.
fn uuid_text(uuid: &[u8; UUID_SIZE]) -> String {
    let text = hex(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &text[0..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..32]
    )
}

fn push_mappings(c: &mut Container<'_>, data: &[u8], mappings: &[Mapping]) {
    if mappings.is_empty() {
        c.notes
            .push("Header declares no mappings; this file maps no code".to_string());
        return;
    }
    let file_size = data.len() as u64;
    let beyond = mappings.iter().filter(|m| m.file_end() > file_size).count();
    let listed = counted(mappings.len(), "mapping", "mappings");
    c.notes.push(if beyond == 0 {
        listed
    } else {
        format!(
            "{listed}; {beyond} extending beyond the end of this {} B file, which may be truncated",
            data.len()
        )
    });
    for (i, m) in mappings.iter().enumerate() {
        c.push_metadata(
            format!("apple_dyld_mapping_{i}"),
            format!("Mapping {}", i + 1),
            format!(
                "address 0x{:X}; {} B; file 0x{:X}; max {}; initial {}",
                m.address,
                m.size,
                m.file_offset,
                protection(m.max_prot),
                protection(m.init_prot)
            ),
        );
    }
}

/// UUID, platform, code signature and local-symbol fields, where the header
/// version has them.
fn push_header_fields(c: &mut Container<'_>, header: &[u8], le: bool) -> Result<()> {
    let header_size = header.len();
    if has_field(header_size, UUID, UUID_SIZE) {
        let uuid = slice(header, UUID, UUID_SIZE)?
            .try_into()
            .expect("slice has exactly 16 bytes");
        c.push_metadata("apple_dyld_uuid", "Cache UUID", uuid_text(uuid));
    }
    if has_field(header_size, PLATFORM, 4) {
        let platform = u32_at(header, PLATFORM, le)?;
        let name = PLATFORMS
            .iter()
            .find(|(id, _)| *id == platform)
            .map_or_else(
                || format!("platform {platform}"),
                |(_, name)| (*name).to_string(),
            );
        c.push_metadata("apple_dyld_platform", "Platform", name);
    }
    if has_field(header_size, CODE_SIGNATURE_SIZE, 8) {
        let offset = u64_at(header, CODE_SIGNATURE_OFFSET, le)?;
        let size = u64_at(header, CODE_SIGNATURE_SIZE, le)?;
        if offset != 0 {
            // A size of zero means "to the end of the file".
            let extent = if size == 0 {
                "to the end of the file".to_string()
            } else {
                format!("{size} B")
            };
            c.notes.push(format!(
                "Code signature at file 0x{offset:X}, {extent}; not verified"
            ));
        }
    }
    if has_field(header_size, LOCAL_SYMBOLS_SIZE, 8) {
        let offset = u64_at(header, LOCAL_SYMBOLS_OFFSET, le)?;
        let size = u64_at(header, LOCAL_SYMBOLS_SIZE, le)?;
        if offset != 0 {
            c.notes
                .push(format!("Local symbols at file 0x{offset:X}, {size} B"));
        }
    }
    if has_field(header_size, SYMBOL_FILE_UUID, UUID_SIZE) {
        let uuid: &[u8; UUID_SIZE] = slice(header, SYMBOL_FILE_UUID, UUID_SIZE)?
            .try_into()
            .expect("slice has exactly 16 bytes");
        if uuid.iter().any(|&b| b != 0) {
            c.notes.push(format!(
                "Local symbols are in a separate .symbols file (UUID {})",
                uuid_text(uuid)
            ));
        }
    }
    Ok(())
}

/// The suffix of subcache `index`: `.<n>` (1-based decimal) for version-1
/// entries, the stored `fileSuffix` otherwise.
fn subcache_suffix(entries: &[u8], index: usize, entry_size: usize) -> Result<String> {
    if entry_size == SUBCACHE_ENTRY_V1_SIZE {
        return Ok(format!(".{}", index + 1));
    }
    let suffix = slice(
        entries,
        index * entry_size + SUBCACHE_SUFFIX,
        SUBCACHE_SUFFIX_SIZE,
    )?;
    let len = memchr::memchr(0, suffix).unwrap_or(suffix.len());
    if len == 0 {
        return Ok("no suffix".to_string());
    }
    Ok(printable(&suffix[..len], SUBCACHE_SUFFIX_SIZE))
}

/// The subcache array of a split cache, where the header version has it.
fn push_subcaches(c: &mut Container<'_>, data: &[u8], header_size: usize, le: bool) -> Result<()> {
    // dyld: no subcaches unless the header extends past `subCacheArrayCount`.
    if header_size <= SUBCACHE_ARRAY_COUNT {
        return Ok(());
    }
    let offset = usize_at(data, SUBCACHE_ARRAY_OFFSET, le)?;
    let count = usize_at(data, SUBCACHE_ARRAY_COUNT, le)?;
    if count == 0 {
        return Ok(());
    }
    // Entries carry a file suffix once the header extends past `cacheSubType`.
    let entry_size = if header_size > CACHE_SUB_TYPE {
        SUBCACHE_ENTRY_SIZE
    } else {
        SUBCACHE_ENTRY_V1_SIZE
    };
    let entries = table(data, offset, count, entry_size, "subcache")?;
    let listed = count.min(MAX_LISTED_SUFFIXES);
    let mut suffixes = Vec::with_capacity(listed);
    for i in 0..listed {
        suffixes.push(subcache_suffix(entries, i, entry_size)?);
    }
    let more = if count > listed {
        format!(" and {} more", count - listed)
    } else {
        String::new()
    };
    c.notes.push(format!(
        "Split cache: {count} subcache files ({}{more}); their mappings and images are not in this file",
        suffixes.join(", ")
    ));
    c.push_metadata("apple_dyld_subcaches", "Subcache files", count as u64);
    Ok(())
}

/// The Mach-O header and load commands of the image at `address`, or
/// `None` when no mapping in this file holds them or the bytes there are
/// not a Mach-O header.
fn macho_image<'a>(
    data: &'a [u8],
    mappings: &[Mapping],
    address: u64,
) -> Option<(usize, &'a [u8])> {
    let mapping = mappings
        .iter()
        .find(|m| m.file_offset_of(address).is_some())?;
    let offset = usize::try_from(mapping.file_offset_of(address)?).ok()?;
    let magic: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    let (header_size, le) = match magic {
        MACHO_64_LE => (MACH_HEADER_64_SIZE, true),
        MACHO_32_LE => (MACH_HEADER_SIZE, true),
        MACHO_64_BE => (MACH_HEADER_64_SIZE, false),
        MACHO_32_BE => (MACH_HEADER_SIZE, false),
        _ => return None,
    };
    let commands_size = usize_at(data, offset.checked_add(MACH_SIZEOFCMDS)?, le).ok()?;
    let end = offset
        .checked_add(header_size)?
        .checked_add(commands_size)?;
    // The header and load commands must lie inside the mapping's bytes.
    if u64::try_from(end).ok()? > mapping.file_end() {
        return None;
    }
    Some((offset, data.get(offset..end)?))
}

/// The NUL-terminated path at file offset `offset`.
fn image_path(data: &[u8], offset: usize, index: usize) -> Result<String> {
    let rest = data
        .get(offset..)
        .filter(|rest| !rest.is_empty())
        .ok_or_else(|| {
            error(format!(
                "Invalid dyld cache image {index} path offset 0x{offset:X}: beyond the end of the file"
            ))
        })?;
    let window = &rest[..rest.len().min(MAX_PATH_SIZE)];
    let len = memchr::memchr(0, window).ok_or_else(|| {
        error(format!(
            "Invalid dyld cache image {index} path at 0x{offset:X}: no NUL within {MAX_PATH_SIZE} B"
        ))
    })?;
    Ok(printable(&window[..len], MAX_PATH_SIZE))
}

/// The image table. Of the first [`MAX_LISTED_IMAGES`] entries, images
/// whose Mach-O header maps into this file become members labelled with
/// their paths; the paths of the first [`MAX_LISTED_UNMAPPED`] others go to
/// metadata.
fn push_images<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header_size: usize,
    le: bool,
    mappings: &[Mapping],
) -> Result<()> {
    // dyld reads the new table once `mappingOffset` reaches `imagesCount`,
    // and the old fields before (`DyldSharedCache.cpp`).
    let (offset_field, count_field, location) = if header_size >= IMAGES_COUNT {
        (IMAGES_OFFSET, IMAGES_COUNT, "imagesOffset")
    } else {
        (IMAGES_OFFSET_OLD, IMAGES_COUNT_OLD, "imagesOffsetOld")
    };
    let offset = usize_at(data, offset_field, le)?;
    let count = usize_at(data, count_field, le)?;
    c.push_metadata("apple_dyld_image_count", "Images", count as u64);
    if count == 0 {
        c.notes.push(format!("Header lists no images ({location})"));
        return Ok(());
    }
    let entries = table(data, offset, count, IMAGE_INFO_SIZE, "image")?;
    // dyld (`hasImagePath`) reads paths only in a cache whose first mapping
    // starts at file offset 0, where they are file offsets.
    if mappings.first().map_or(true, |m| m.file_offset != 0) {
        c.notes.push(format!(
            "{} ({location}); the first mapping does not start at file offset 0, so image paths are not read",
            counted(count, "image", "images")
        ));
        return Ok(());
    }
    let listed = count.min(MAX_LISTED_IMAGES);
    let mut mapped = 0usize;
    let mut unmapped = 0usize;
    for (i, entry) in entries
        .chunks_exact(IMAGE_INFO_SIZE)
        .take(listed)
        .enumerate()
    {
        let address = u64_at(entry, 0, le)?;
        let path = image_path(data, usize_at(entry, IMAGE_PATH_OFFSET, le)?, i)?;
        if let Some((image_offset, header)) = macho_image(data, mappings, address) {
            let mut child = Child::stored(path, image_offset, header).if_recognized();
            if let Some(target) = c.target {
                child = child.with_target(target);
            }
            c.children.push(child);
            mapped += 1;
            continue;
        }
        if unmapped < MAX_LISTED_UNMAPPED {
            c.push_metadata(
                format!("apple_dyld_unmapped_image_{unmapped}"),
                path,
                format!("image {i}; address 0x{address:X}; Mach-O header not in this file"),
            );
        }
        unmapped += 1;
    }
    let mut parts = vec![
        format!("{} ({location})", counted(count, "image", "images")),
        format!("{listed} read"),
        format!("Mach-O header in this file: {mapped}, listed with header and load commands"),
        format!("Mach-O header not in this file (for example in a subcache file): {unmapped}"),
    ];
    if count > listed {
        parts.push(format!(
            "{} not read (limit {MAX_LISTED_IMAGES})",
            count - listed
        ));
    }
    c.notes.push(parts.join("; "));
    Ok(())
}

/// Parse a dyld shared cache file: magic, header, mappings, then the
/// optional fields, subcaches and images the header version has.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let token = magic_token(data)?;
    let arch = ARCHES.iter().find(|a| a.token == token);
    let le = !arch.is_some_and(|a| a.big_endian);
    let header_size = header_size(data, le)?;
    let mappings = mappings(data, header_size, le)?;

    let mut c = Container::new(
        FileFormat::DyldCache,
        format!("dyld shared cache ({token})"),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.target = arch.map(|a| a.target);
    let byte_order = if le { "little-endian" } else { "big-endian" };
    c.notes.push(format!(
        "dyld shared cache; architecture token {token}; {header_size} B {byte_order} header"
    ));
    match arch {
        Some(Arch {
            detail: Some(detail),
            ..
        }) => c.notes.push((*detail).to_string()),
        Some(_) => {}
        None => c.notes.push(format!(
            "Unknown architecture token {token}; header read as little-endian; ISA taken from the images"
        )),
    }
    c.push_metadata("apple_dyld_architecture", "Architecture token", token);
    c.push_metadata(
        "apple_dyld_header_size",
        "Header size (mappingOffset, B)",
        header_size as u64,
    );
    push_mappings(&mut c, data, &mappings);
    push_header_fields(&mut c, slice(data, 0, header_size)?, le)?;
    push_subcaches(&mut c, data, header_size, le)?;
    push_images(&mut c, data, header_size, le, &mappings)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_tokens_are_right_aligned_and_nul_terminated() {
        assert_eq!(magic_token(b"dyld_v1  arm64e\0").unwrap(), "arm64e");
        assert_eq!(magic_token(b"dyld_v1arm64_32\0").unwrap(), "arm64_32");
        assert_eq!(magic_token(b"dyld_v1    i386\0").unwrap(), "i386");
        assert!(magic_token(b"dyld_v1  arm64e!").is_err());
        assert!(magic_token(b"dyld_v1        \0").is_err());
        assert!(magic_token(b"dyld_v1 arm 64e\0").is_err());
        assert!(magic_token(b"dyld_v1   ").is_err());
    }

    #[test]
    fn every_token_is_listed_once() {
        for arch in ARCHES {
            let matches = ARCHES.iter().filter(|a| a.token == arch.token).count();
            assert_eq!(matches, 1, "{}", arch.token);
            assert!(
                MAGIC_PREFIX.len() + arch.token.len() < MAGIC_SIZE,
                "{}",
                arch.token
            );
        }
    }

    #[test]
    fn mappings_translate_addresses_to_file_offsets() {
        let mapping = Mapping {
            address: 0x1_8000_0000,
            size: 0x4000,
            file_offset: 0x1000,
            max_prot: VM_PROT_READ | VM_PROT_EXECUTE,
            init_prot: VM_PROT_READ,
        };
        assert_eq!(mapping.file_offset_of(0x1_8000_0010), Some(0x1010));
        assert_eq!(mapping.file_offset_of(0x1_8000_4000), None);
        assert_eq!(mapping.file_offset_of(0x1_7fff_ffff), None);
        assert_eq!(protection(mapping.max_prot), "r-x");
        assert_eq!(protection(mapping.init_prot), "r--");
    }

    #[test]
    fn uuids_are_grouped() {
        let bytes: [u8; UUID_SIZE] =
            std::array::from_fn(|i| u8::try_from(i).expect("UUID index fits"));
        assert_eq!(uuid_text(&bytes), "00010203-0405-0607-0809-0A0B0C0D0E0F");
    }
}
