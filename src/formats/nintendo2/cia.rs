//! 3DS CTR importable archives (CIA): 3dbrew "CIA" (oldid 22475), "Title
//! metadata" (oldid 21319), "Template:Signature Types" (oldid 5790),
//! "Certificates" (oldid 21325) and "Ticket" (oldid 21072); makerom
//! `cia.c` and `tmd.c`; ctrtool `cia.h`, `CiaFsSnapshotGenerator.cpp`,
//! `CiaProcess.cpp` and libbroadon-es `es_tmd.h`, `es_sign.h`.
//!
//! The little-endian header (0x2020 B) holds the header size, type and
//! format version, the certificate chain, ticket, TMD, meta and content
//! sizes, and a content index bitmap (index `i` is bit `0x80 >> (i % 8)` of
//! byte `i / 8`, makerom `BuildCiaHdr`). The sections follow in that order,
//! each at the previous end aligned to 64 B; the meta section is optional.
//! A CIA has no magic, so it is recognized only when all of this is
//! consistent with the file size and the TMD validates.
//!
//! The TMD is big-endian: a signature block whose size the signature type
//! fixes, a 0xC4-byte header (version, title ID, content count, the
//! SHA-256 of the content info records), 64 content info records (a count
//! and the SHA-256 of that many further content chunk records), then one
//! 0x30-byte content chunk record per content (ID, index, type, size,
//! SHA-256). The contents whose index bit is set follow each other in TMD
//! order at 16-byte-aligned positions of the content section (ctrtool
//! `kCiaContentAlignment`). A content with type bit 0 set is AES-128-CBC
//! encrypted with the ticket's title key and is opaque; any other content
//! is classified on its own (an NCCH, or a `DSi` SRL in a TWL title).

use super::*;

/// Prefix of this layout's metadata keys.
const KEY_PREFIX: &str = "cia";

/// Header fields.
const HEADER_SIZE: usize = 0x2020;
const HEADER_TYPE: usize = 0x04;
const FORMAT_VERSION: usize = 0x06;
const CERTIFICATE_CHAIN_SIZE: usize = 0x08;
const TICKET_SIZE: usize = 0x0c;
const TMD_SIZE: usize = 0x10;
const META_SIZE: usize = 0x14;
const CONTENT_SIZE: usize = 0x18;
const CONTENT_INDEX: usize = 0x20;

/// Header type and format versions (ctrtool `CiaHeader`).
const TYPE_NORMAL: u16 = 0;
const FORMAT_VERSION_DEFAULT: u16 = 0;
const FORMAT_VERSION_SIMPLE_CIA: u16 = 0xff;

/// Section and content alignment (makerom `CIA_ALIGN_SIZE`,
/// `CIA_CONTENT_ALIGN`).
const SECTION_ALIGNMENT: u64 = 64;
const CONTENT_ALIGNMENT: u64 = 16;

/// Signature types (3dbrew "Template:Signature Types"; libbroadon-es
/// `ESSigType`).
const RSA_4096_SHA1: u32 = 0x0001_0000;
const RSA_2048_SHA1: u32 = 0x0001_0001;
const ECDSA_SHA1: u32 = 0x0001_0002;
const RSA_4096_SHA256: u32 = 0x0001_0003;
const RSA_2048_SHA256: u32 = 0x0001_0004;
const ECDSA_SHA256: u32 = 0x0001_0005;

/// Signature sizes and padding: each block is the type word, the signature
/// and padding that aligns the block to 0x40 bytes.
const RSA_4096_BLOCK: usize = 4 + 0x200 + 0x3c;
const RSA_2048_BLOCK: usize = 4 + 0x100 + 0x3c;
const ECDSA_BLOCK: usize = 4 + 0x3c + 0x40;

/// TMD header fields, after the signature block.
const TMD_HEADER_SIZE: usize = 0xc4;
const TMD_VERSION: usize = 0x40;
const TMD_TITLE_ID: usize = 0x4c;
const TMD_TITLE_TYPE: usize = 0x54;
const TMD_TITLE_VERSION: usize = 0x9c;
const TMD_CONTENT_COUNT: usize = 0x9e;
const TMD_INFO_RECORDS_HASH: usize = 0xa4;

/// The TMD version with content info records (ctrtool
/// `CiaFsSnapshotGenerator` accepts only this one).
const TMD_VERSION_1: u8 = 1;

/// Content info records: a content index offset (2), a command count (2)
/// and the SHA-256 of that many content chunk records.
const CONTENT_INFO_RECORDS: usize = 64;
const CONTENT_INFO_RECORD_SIZE: usize = 0x24;
const INFO_RECORD_COUNT: usize = 2;
const INFO_RECORD_HASH: usize = 4;

/// Content chunk records.
const CONTENT_CHUNK_RECORD_SIZE: usize = 0x30;
const CHUNK_ID: usize = 0;
const CHUNK_INDEX: usize = 4;
const CHUNK_TYPE: usize = 6;
const CHUNK_SIZE: usize = 8;
const CHUNK_HASH: usize = 0x10;

/// Content type bit 0 (3dbrew "Title metadata"; makerom
/// `content_Encrypted`).
const CONTENT_TYPE_ENCRYPTED: u16 = 0x0001;

/// Meta: 48 dependency title IDs (8 each), the core version at 0x300, the
/// icon from 0x400 (3dbrew "CIA"; ctrtool `CiaFooter`).
const META_DEPENDENCIES: usize = 48;
const META_CORE_VERSION: usize = 0x300;
const META_ICON: usize = 0x400;

/// Weak recognition: the whole archive structure validates.
pub(super) fn detect(data: &[u8]) -> bool {
    archive(data).is_ok()
}

/// A documented signature type.
#[derive(Debug, Clone, Copy)]
struct SignatureType {
    name: &'static str,
    /// The type word, the signature and its padding, in bytes.
    block_size: usize,
}

fn signature_type(value: u32) -> Option<SignatureType> {
    let (name, block_size) = match value {
        RSA_4096_SHA1 => ("RSA-4096 SHA-1", RSA_4096_BLOCK),
        RSA_2048_SHA1 => ("RSA-2048 SHA-1", RSA_2048_BLOCK),
        ECDSA_SHA1 => ("ECDSA SHA-1", ECDSA_BLOCK),
        RSA_4096_SHA256 => ("RSA-4096 SHA-256", RSA_4096_BLOCK),
        RSA_2048_SHA256 => ("RSA-2048 SHA-256", RSA_2048_BLOCK),
        ECDSA_SHA256 => ("ECDSA SHA-256", ECDSA_BLOCK),
        _ => return None,
    };
    Some(SignatureType { name, block_size })
}

/// The signature type that starts `section`, which must be documented.
fn signature(section: &[u8], what: &str) -> Result<SignatureType> {
    let value = be_u32(section, 0)?;
    signature_type(value)
        .ok_or_else(|| error(format!("Unsupported {what} signature type 0x{value:08X}")))
}

/// A section placed at the previous end aligned to 64 B, in file
/// coordinates; `offset + size` does not overflow.
#[derive(Debug, Clone, Copy)]
struct Placed {
    offset: u64,
    size: u64,
}

impl Placed {
    fn end(self) -> u64 {
        self.offset + self.size
    }
}

fn place(previous_end: u64, size: u64) -> Result<Placed> {
    align_up(previous_end, SECTION_ALIGNMENT)
        .filter(|offset| offset.checked_add(size).is_some())
        .map(|offset| Placed { offset, size })
        .ok_or_else(|| error("Invalid CIA section sizes: they overflow"))
}

/// The sections of an archive, inside the file.
struct Sections {
    certificates: Region,
    ticket: Region,
    tmd: Region,
    content: Region,
    /// Empty when the archive has no meta section.
    meta: Region,
}

/// The header checks of makerom `IsCia` and ctrtool, then the section
/// layout against the file size: the file ends at the last section, or at
/// that end aligned to 64 B with zero padding (the size ctrtool's
/// `CiaFsSnapshotGenerator` computes when there is no meta section).
fn sections(data: &[u8]) -> Result<Sections> {
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated CIA header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    }
    let header_size = le_u32(data, 0)?;
    if header_size as usize != HEADER_SIZE {
        return Err(error(format!(
            "Invalid CIA header size 0x{header_size:X}: not 0x{HEADER_SIZE:X}"
        )));
    }
    let header_type = le_u16(data, HEADER_TYPE)?;
    if header_type != TYPE_NORMAL {
        return Err(error(format!("Unsupported CIA type {header_type}")));
    }
    let version = le_u16(data, FORMAT_VERSION)?;
    if version != FORMAT_VERSION_DEFAULT {
        let simple = if version == FORMAT_VERSION_SIMPLE_CIA {
            " (simple CIA without a TMD)"
        } else {
            ""
        };
        return Err(error(format!(
            "Unsupported CIA format version 0x{version:04X}{simple}"
        )));
    }
    let size = |at: usize| le_u32(data, at).map(u64::from);
    let certificate_size = size(CERTIFICATE_CHAIN_SIZE)?;
    let ticket_size = size(TICKET_SIZE)?;
    let tmd_size = size(TMD_SIZE)?;
    let meta_size = size(META_SIZE)?;
    let content_size = le_u64(data, CONTENT_SIZE)?;
    for (what, size) in [
        ("certificate chain", certificate_size),
        ("ticket", ticket_size),
        ("TMD", tmd_size),
        ("content section", content_size),
    ] {
        if size == 0 {
            return Err(error(format!("Missing CIA {what}")));
        }
    }
    let certificates = place(HEADER_SIZE as u64, certificate_size)?;
    let ticket = place(certificates.end(), ticket_size)?;
    let tmd = place(ticket.end(), tmd_size)?;
    let content = place(tmd.end(), content_size)?;
    let meta = place(content.end(), meta_size)?;
    let end = if meta_size == 0 {
        content.end()
    } else {
        meta.end()
    };
    expect_file_end(data, end)?;
    let region = |placed: Placed| {
        region_within(placed.offset, placed.size, data.len()).expect("the file holds every section")
    };
    Ok(Sections {
        certificates: region(certificates),
        ticket: region(ticket),
        tmd: region(tmd),
        content: region(content),
        meta: if meta_size == 0 {
            Region {
                offset: data.len(),
                size: 0,
            }
        } else {
            region(meta)
        },
    })
}

/// The file must end at `end`, or at `end` aligned to 64 B with zeros in
/// between.
fn expect_file_end(data: &[u8], end: u64) -> Result<()> {
    let file_size = data.len() as u64;
    if file_size == end {
        return Ok(());
    }
    let is_padded = align_up(end, SECTION_ALIGNMENT) == Some(file_size)
        && usize::try_from(end)
            .ok()
            .and_then(|end| data.get(end..))
            .is_some_and(|padding| padding.iter().all(|b| *b == 0));
    if is_padded {
        return Ok(());
    }
    Err(error(format!(
        "Invalid CIA size: the sections end at 0x{end:X}, the file has {} B",
        data.len()
    )))
}

/// A content chunk record.
#[derive(Debug, Clone, Copy)]
struct ContentRecord {
    id: u32,
    index: u16,
    content_type: u16,
    size: u64,
    sha256: [u8; SHA256_SIZE],
}

impl ContentRecord {
    fn is_encrypted(self) -> bool {
        self.content_type & CONTENT_TYPE_ENCRYPTED != 0
    }
}

/// The TMD fields this parser uses.
struct Tmd {
    signature: SignatureType,
    title_id: u64,
    title_type: u32,
    title_version: u16,
    records: Vec<ContentRecord>,
}

/// Parse and validate the TMD: a documented signature type, version 1,
/// content info records whose SHA-256 matches the header, and content
/// chunk records hashed, in order, by the info records.
fn tmd(bytes: &[u8]) -> Result<Tmd> {
    let signature = signature(bytes, "TMD")?;
    let header_at = signature.block_size;
    let info_at = header_at + TMD_HEADER_SIZE;
    let chunks_at = info_at + CONTENT_INFO_RECORDS * CONTENT_INFO_RECORD_SIZE;
    if bytes.len() < chunks_at {
        return Err(error(format!(
            "Truncated TMD: {} B of at least {chunks_at} B",
            bytes.len()
        )));
    }
    let header = &bytes[header_at..info_at];
    let version = header[TMD_VERSION];
    if version != TMD_VERSION_1 {
        return Err(error(format!("Unsupported TMD version {version}")));
    }
    let count = usize::from(be_u16(header, TMD_CONTENT_COUNT)?);
    let chunks_size = count * CONTENT_CHUNK_RECORD_SIZE;
    if chunks_size > bytes.len() - chunks_at {
        return Err(error(format!(
            "Truncated TMD content chunk records: {count} records need {chunks_size} B, {} B remain",
            bytes.len() - chunks_at
        )));
    }
    let info = &bytes[info_at..chunks_at];
    if !sha256_matches(info, slice(header, TMD_INFO_RECORDS_HASH, SHA256_SIZE)?) {
        return Err(error("Invalid TMD content info records: SHA-256 mismatch"));
    }
    let chunks = &bytes[chunks_at..chunks_at + chunks_size];
    check_chunk_hashes(info, chunks, count)?;
    let records = chunks
        .chunks_exact(CONTENT_CHUNK_RECORD_SIZE)
        .map(content_record)
        .collect::<Result<Vec<_>>>()?;
    Ok(Tmd {
        signature,
        title_id: be_u64(header, TMD_TITLE_ID)?,
        title_type: be_u32(header, TMD_TITLE_TYPE)?,
        title_version: be_u16(header, TMD_TITLE_VERSION)?,
        records,
    })
}

/// Each content info record with a nonzero count hashes "the next k
/// content records that have not been hashed yet" (3dbrew); together they
/// must hash every content chunk record.
fn check_chunk_hashes(info: &[u8], chunks: &[u8], count: usize) -> Result<()> {
    let mut hashed = 0usize;
    for (record_index, record) in info.chunks_exact(CONTENT_INFO_RECORD_SIZE).enumerate() {
        let k = usize::from(be_u16(record, INFO_RECORD_COUNT)?);
        if k == 0 {
            continue;
        }
        let end = hashed + k;
        if end > count {
            return Err(error(format!(
                "Invalid TMD content info record {record_index}: {k} records after the first {hashed} exceed the {count} content chunk records"
            )));
        }
        let range = &chunks[hashed * CONTENT_CHUNK_RECORD_SIZE..end * CONTENT_CHUNK_RECORD_SIZE];
        if !sha256_matches(range, &record[INFO_RECORD_HASH..]) {
            return Err(error(format!(
                "Invalid TMD content chunk records {hashed} to {}: SHA-256 mismatch",
                end - 1
            )));
        }
        hashed = end;
    }
    if hashed != count {
        return Err(error(format!(
            "Invalid TMD: the content info records hash {hashed} of {count} content chunk records"
        )));
    }
    Ok(())
}

fn content_record(record: &[u8]) -> Result<ContentRecord> {
    Ok(ContentRecord {
        id: be_u32(record, CHUNK_ID)?,
        index: be_u16(record, CHUNK_INDEX)?,
        content_type: be_u16(record, CHUNK_TYPE)?,
        size: be_u64(record, CHUNK_SIZE)?,
        sha256: array(record, CHUNK_HASH)?,
    })
}

/// A content present in the archive.
struct Content {
    record: ContentRecord,
    region: Region,
}

/// Whether the content index bitmap marks `index` as present.
fn is_present(bitmap: &[u8], index: u16) -> bool {
    let index = usize::from(index);
    bitmap[index / 8] & (0x80 >> (index % 8)) != 0
}

/// The present contents, in TMD order at 16-byte-aligned positions, which
/// must fill the content section exactly.
fn contents(data: &[u8], content: Region, records: &[ContentRecord]) -> Result<Vec<Content>> {
    let bitmap = &data[CONTENT_INDEX..HEADER_SIZE];
    let section_size = content.size as u64;
    let mut position = 0u64;
    let mut present = Vec::new();
    for record in records.iter().filter(|r| is_present(bitmap, r.index)) {
        let start = align_up(position, CONTENT_ALIGNMENT)
            .filter(|start| {
                start
                    .checked_add(record.size)
                    .is_some_and(|end| end <= section_size)
            })
            .ok_or_else(|| {
                error(format!(
                    "Invalid CIA content {}: {} B at 0x{position:X} beyond the 0x{section_size:X}-byte content section",
                    record.index, record.size
                ))
            })?;
        position = start + record.size;
        let region = region_within(content.offset as u64 + start, record.size, content.end())
            .expect("the content lies in the content section");
        present.push(Content {
            record: *record,
            region,
        });
    }
    let filled = align_up(position, CONTENT_ALIGNMENT).unwrap_or(u64::MAX);
    if filled != section_size {
        return Err(error(format!(
            "Invalid CIA content section size 0x{section_size:X}: the present contents end at 0x{filled:X}"
        )));
    }
    Ok(present)
}

/// A validated archive.
struct Archive {
    sections: Sections,
    certificate_signature: SignatureType,
    ticket_signature: SignatureType,
    tmd: Tmd,
    contents: Vec<Content>,
}

fn archive(data: &[u8]) -> Result<Archive> {
    let sections = sections(data)?;
    let certificate_signature = signature(sections.certificates.bytes(data), "certificate chain")?;
    let ticket_signature = signature(sections.ticket.bytes(data), "ticket")?;
    let tmd = tmd(sections.tmd.bytes(data))?;
    let contents = contents(data, sections.content, &tmd.records)?;
    Ok(Archive {
        sections,
        certificate_signature,
        ticket_signature,
        tmd,
        contents,
    })
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let archive = archive(data)?;
    let mut c = Container::new(FileFormat::Cia, Layout::Cia.label(), KEY_PREFIX);
    c.consumed = data.len();
    push_archive_notes(&mut c, &archive);
    let sections = &archive.sections;
    let mut members = Members::new(data.len());
    for (label, region) in [
        ("Certificate chain", sections.certificates),
        ("Ticket", sections.ticket),
        ("TMD", sections.tmd),
    ] {
        members.push_opaque(label.to_string(), region.offset, region.bytes(data));
    }
    let mut hashes = ContentHashes::default();
    for content in &archive.contents {
        let record = content.record;
        let label = format!("Content {} (ID 0x{:08X})", record.index, record.id);
        let bytes = content.region.bytes(data);
        if record.is_encrypted() {
            hashes.encrypted += 1;
            members.push_opaque(format!("{label}, encrypted"), content.region.offset, bytes);
            continue;
        }
        if sha256_matches(bytes, &record.sha256) {
            hashes.verified += 1;
        } else {
            hashes.mismatched.push(record.index);
        }
        members.offer(label, content.region.offset, bytes);
    }
    if sections.meta.size > 0 {
        push_meta_notes(&mut c, sections.meta.bytes(data));
        members.push_opaque(
            "Meta".to_string(),
            sections.meta.offset,
            sections.meta.bytes(data),
        );
    }
    hashes.push_notes(&mut c, archive.contents.len());
    members.finish(&mut c, "member", "members");
    Ok(c)
}

/// What the content hashes showed.
#[derive(Default)]
struct ContentHashes {
    verified: usize,
    mismatched: Vec<u16>,
    encrypted: usize,
}

impl ContentHashes {
    fn push_notes(&self, c: &mut Container<'_>, present: usize) {
        let unencrypted = present - self.encrypted;
        if unencrypted > 0 {
            let mismatch = if self.mismatched.is_empty() {
                String::new()
            } else {
                let indexes: Vec<String> = self.mismatched.iter().map(u16::to_string).collect();
                format!("; mismatch for content {}", bounded_list(&indexes))
            };
            c.notes.push(format!(
                "Content SHA-256 verified for {} of {unencrypted} unencrypted contents{mismatch}",
                self.verified
            ));
        }
        if self.encrypted > 0 {
            c.notes.push(format!(
                "{} of {present} contents are AES-128-CBC encrypted with the ticket's title key (TMD content type bit 0) and are opaque; the title key is not decrypted, and their SHA-256, which covers the decrypted bytes, is not verified",
                self.encrypted
            ));
        }
    }
}

fn push_archive_notes(c: &mut Container<'_>, archive: &Archive) {
    let tmd = &archive.tmd;
    c.notes.push(format!(
        "3DS CIA; title ID 0x{:016X}; title version {}; title type 0x{:08X}; {} in the TMD, {} in the archive; the container names no CPU",
        tmd.title_id,
        tmd.title_version,
        tmd.title_type,
        counted(tmd.records.len(), "content", "contents"),
        archive.contents.len()
    ));
    c.notes.push(format!(
        "TMD content info and content chunk record SHA-256 verified; signatures (certificate chain {}, ticket {}, TMD {}) are not verified",
        archive.certificate_signature.name,
        archive.ticket_signature.name,
        tmd.signature.name
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_title_id"),
        "Title ID",
        format!("0x{:016X}", tmd.title_id),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_title_version"),
        "Title version",
        u64::from(tmd.title_version),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_contents"),
        "Contents in the archive",
        archive.contents.len() as u64,
    );
}

/// The meta section's core version, dependency count and icon size.
fn push_meta_notes(c: &mut Container<'_>, meta: &[u8]) {
    if meta.len() < META_ICON {
        c.notes.push(format!(
            "Meta section of {} is shorter than its 0x{META_ICON:X}-byte header and is not parsed",
            size_text(meta.len())
        ));
        return;
    }
    let core_version =
        le_u32(meta, META_CORE_VERSION).expect("the meta section holds its 0x400-byte header");
    let dependencies = meta[..META_DEPENDENCIES * 8]
        .chunks_exact(8)
        .filter(|id| id.iter().any(|b| *b != 0))
        .count();
    let icon = meta.len().saturating_sub(META_ICON);
    c.notes.push(format!(
        "Meta: core version 0x{core_version:08X}; {}; icon data {}",
        counted(dependencies, "dependency", "dependencies"),
        size_text(icon)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_blocks_follow_the_documented_sizes() {
        assert_eq!(signature_type(RSA_4096_SHA256).unwrap().block_size, 0x240);
        assert_eq!(signature_type(RSA_2048_SHA256).unwrap().block_size, 0x140);
        assert_eq!(signature_type(ECDSA_SHA1).unwrap().block_size, 0x80);
        assert!(signature_type(0x0001_0006).is_none());
    }

    #[test]
    fn bitmap_bits_count_from_the_most_significant_bit() {
        let mut bitmap = vec![0u8; 0x2000];
        bitmap[0] = 0x80;
        bitmap[1] = 0x01;
        assert!(is_present(&bitmap, 0));
        assert!(!is_present(&bitmap, 1));
        assert!(is_present(&bitmap, 15));
        assert!(!is_present(&bitmap, 0xffff));
    }

    #[test]
    fn sections_are_placed_at_64_byte_boundaries() {
        let ticket = place(0x2020, 0x350).unwrap();
        assert_eq!((ticket.offset, ticket.end()), (0x2040, 0x2390));
        assert!(place(u64::MAX - 8, 1).is_err());
    }
}
