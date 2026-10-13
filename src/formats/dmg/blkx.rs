//! UDIF block tables (`BLKXTable`, signature `mish`) and their chunks
//! (`BLKXRun`), every field big-endian (libdmg-hfsplus
//! `includes/dmg/dmg.h`; validation as 7-Zip `DmgHandler.cpp`
//! `CFile::Parse`).
//!
//! Table header (204 bytes): signature `mish` (4), version 1 (4), first
//! sector (8), sector count (8), data start (8), decompress buffer size in
//! sectors (4), blocks descriptor (4), reserved (24), checksum (136) at 64,
//! chunk count (4) at 200. Chunk (40 bytes): type (4), comment (4), first
//! sector relative to the table's (8), sector count (8), compressed offset
//! (8) and compressed length (8). A chunk's stored bytes are at data fork
//! offset + data start + compressed offset (7-Zip `CHandler::Extract`;
//! darling-dmg `src/DMGPartition.cpp`).

use super::*;
use crate::formats::compressed::Codec;

/// Table signature.
const SIGNATURE: &[u8; 4] = b"mish";

/// The only table version readers accept (7-Zip `CFile::Parse`).
const VERSION: u32 = 1;

/// Table header and chunk sizes.
const HEADER_SIZE: usize = 204;
const CHUNK_SIZE: usize = 40;

/// The table's checksum record.
const CHECKSUM_OFFSET: usize = 64;

/// Chunk types (libdmg-hfsplus `BLOCK_*`, 7-Zip `METHOD_*`).
const CHUNK_ZERO: u32 = 0x0000_0000;
const CHUNK_RAW: u32 = 0x0000_0001;
const CHUNK_IGNORE: u32 = 0x0000_0002;
const CHUNK_ADC: u32 = 0x8000_0004;
const CHUNK_ZLIB: u32 = 0x8000_0005;
const CHUNK_BZIP2: u32 = 0x8000_0006;
const CHUNK_LZFSE: u32 = 0x8000_0007;
/// LZMA: 7-Zip decodes it as xz, and `hdiutil` ULMO chunks are xz streams.
const CHUNK_LZMA: u32 = 0x8000_0008;
const CHUNK_COMMENT: u32 = 0x7fff_fffe;
const CHUNK_END: u32 = 0xffff_ffff;

/// What a chunk holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Zero fill (type 0).
    Zero,
    /// Raw sectors (type 1).
    Raw,
    /// Free space (type 2): reads as zeros, left out of the table CRC.
    Ignore,
    /// A compressed run.
    Compressed(Codec),
    /// A type no reader documents.
    Unknown(u32),
}

impl Kind {
    fn from_type(chunk_type: u32) -> Self {
        match chunk_type {
            CHUNK_ZERO => Self::Zero,
            CHUNK_RAW => Self::Raw,
            CHUNK_IGNORE => Self::Ignore,
            CHUNK_ADC => Self::Compressed(Codec::Adc),
            CHUNK_ZLIB => Self::Compressed(Codec::Zlib),
            CHUNK_BZIP2 => Self::Compressed(Codec::Bzip2),
            CHUNK_LZFSE => Self::Compressed(Codec::Lzfse),
            CHUNK_LZMA => Self::Compressed(Codec::Xz),
            other => Self::Unknown(other),
        }
    }

    /// Name in notes and metadata.
    pub(super) fn name(self) -> String {
        match self {
            Self::Zero => "zero".into(),
            Self::Raw => "raw".into(),
            Self::Ignore => "ignore".into(),
            Self::Compressed(Codec::Xz) => "LZMA".into(),
            Self::Compressed(codec) => codec.name().into(),
            Self::Unknown(chunk_type) => format!("type 0x{chunk_type:08X}"),
        }
    }

    /// Whether the chunk's bytes are stored in the file.
    pub(super) fn is_stored(self) -> bool {
        matches!(self, Self::Raw | Self::Compressed(_))
    }
}

/// One data chunk; comment and end chunks are not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Chunk {
    pub(super) kind: Kind,
    /// First sector, relative to the table's first sector.
    pub(super) sector: u64,
    /// Sectors of 512 bytes.
    pub(super) sectors: u64,
    /// File offset of the stored bytes.
    pub(super) offset: u64,
    /// Stored bytes.
    pub(super) length: u64,
}

impl Chunk {
    /// Decoded bytes the chunk covers.
    pub(super) fn size(&self) -> u64 {
        self.sectors * SECTOR_SIZE
    }
}

/// A block table: one partition of the disk.
#[derive(Debug, Clone)]
pub(super) struct Table {
    /// First sector of the partition on the disk.
    pub(super) first_sector: u64,
    /// Sectors of 512 bytes.
    pub(super) sector_count: u64,
    /// CRC-32 of the decoded bytes, ignore chunks left out.
    pub(super) checksum: koly::Checksum,
    pub(super) chunks: Vec<Chunk>,
}

impl Table {
    /// Decoded size in bytes.
    pub(super) fn size(&self) -> u64 {
        self.sector_count * SECTOR_SIZE
    }

    /// Whether any chunk may store bytes in the file: anything but zero
    /// fill and free space, undocumented types included.
    pub(super) fn has_stored_data(&self) -> bool {
        self.chunks
            .iter()
            .any(|c| !matches!(c.kind, Kind::Zero | Kind::Ignore))
    }

    /// `zlib 2, ignore 2`: each chunk kind and how many chunks have it, in
    /// order of first use.
    pub(super) fn chunk_summary(&self) -> String {
        let mut kinds: Vec<(Kind, usize)> = Vec::new();
        for chunk in &self.chunks {
            match kinds.iter_mut().find(|(kind, _)| *kind == chunk.kind) {
                Some((_, count)) => *count += 1,
                None => kinds.push((chunk.kind, 1)),
            }
        }
        let parts: Vec<String> = kinds
            .iter()
            .map(|(kind, count)| format!("{} {count}", kind.name()))
            .collect();
        parts.join(", ")
    }
}

/// Sectors may not exceed what a 64-bit byte count holds (7-Zip
/// `kSectorNumber_LIMIT`), so `sectors * 512` cannot overflow.
const SECTOR_LIMIT: u64 = 1 << (63 - 9);

/// Parse the block table `bytes` of the partition `name`, whose chunk
/// offsets are relative to `data_fork_offset` plus the table's data start.
/// The chunks must cover the partition in order (each starts where the
/// previous one ended) and end with an end chunk.
pub(super) fn table(bytes: &[u8], name: &str, data_fork_offset: u64) -> Result<Table> {
    let header = slice(bytes, 0, HEADER_SIZE, "block table").map_err(|_| {
        error(format!(
            "Truncated block table of {name}: {} B",
            bytes.len()
        ))
    })?;
    if &header[..4] != SIGNATURE {
        return Err(error(format!("Missing block table signature in {name}")));
    }
    let version = be_u32(header, 4)?;
    if version != VERSION {
        return Err(error(format!(
            "Unsupported block table version {version} in {name}"
        )));
    }
    let first_sector = be_u64(header, 8)?;
    let sector_count = be_u64(header, 16)?;
    let data_start = be_u64(header, 24)?;
    if first_sector >= SECTOR_LIMIT || sector_count >= SECTOR_LIMIT {
        return Err(error(format!(
            "Invalid block table of {name}: sector {first_sector} + {sector_count}"
        )));
    }
    let count = be_u32(header, 200)? as usize;
    if Some(bytes.len() - HEADER_SIZE) != count.checked_mul(CHUNK_SIZE) {
        return Err(error(format!(
            "Invalid block table size of {name}: {} B for {count} chunks",
            bytes.len()
        )));
    }
    let base = data_fork_offset
        .checked_add(data_start)
        .ok_or_else(|| error(format!("Invalid data start 0x{data_start:X} in {name}")))?;
    let mut chunks = Vec::new();
    let mut covered = 0u64;
    for (i, record) in bytes[HEADER_SIZE..].chunks_exact(CHUNK_SIZE).enumerate() {
        let chunk_type = be_u32(record, 0)?;
        let sector = be_u64(record, 8)?;
        let sectors = be_u64(record, 16)?;
        if sector != covered {
            return Err(error(format!(
                "Invalid chunk {i} of {name}: it starts at sector {sector}, expected {covered}"
            )));
        }
        if chunk_type == CHUNK_END {
            if i + 1 != count {
                return Err(error(format!(
                    "Invalid chunk {i} of {name}: the end chunk is not the last"
                )));
            }
            break;
        }
        if chunk_type == CHUNK_COMMENT {
            continue;
        }
        covered = covered
            .checked_add(sectors)
            .filter(|&covered| covered <= sector_count)
            .ok_or_else(|| {
                error(format!(
                    "Invalid chunk {i} of {name}: {sectors} sectors at {sector} exceed the \
                     partition's {sector_count}"
                ))
            })?;
        let offset = base
            .checked_add(be_u64(record, 24)?)
            .ok_or_else(|| error(format!("Invalid compressed offset of chunk {i} of {name}")))?;
        chunks.push(Chunk {
            kind: Kind::from_type(chunk_type),
            sector,
            sectors,
            offset,
            length: be_u64(record, 32)?,
        });
    }
    let ends =
        bytes.len() > HEADER_SIZE && be_u32(&bytes[bytes.len() - CHUNK_SIZE..], 0)? == CHUNK_END;
    if !ends {
        return Err(error(format!(
            "Missing end chunk in the block table of {name}"
        )));
    }
    if covered != sector_count {
        return Err(error(format!(
            "Invalid block table of {name}: chunks cover {covered} of {sector_count} sectors"
        )));
    }
    Ok(Table {
        first_sector,
        sector_count,
        checksum: koly::Checksum::read(header, CHECKSUM_OFFSET)?,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of `sectors` sectors starting at `first`, with these
    /// chunks (type, sectors, compressed offset, compressed length) and an
    /// end chunk.
    fn table_bytes(first: u64, sectors: u64, chunks: &[(u32, u64, u64, u64)]) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_SIZE];
        out[..4].copy_from_slice(SIGNATURE);
        out[4..8].copy_from_slice(&VERSION.to_be_bytes());
        out[8..16].copy_from_slice(&first.to_be_bytes());
        out[16..24].copy_from_slice(&sectors.to_be_bytes());
        let records = u32::try_from(chunks.len() + 1).expect("a few chunks");
        out[200..204].copy_from_slice(&records.to_be_bytes());
        let mut sector = 0u64;
        for &(chunk_type, count, offset, length) in
            chunks.iter().chain([(CHUNK_END, 0, 0, 0)].iter())
        {
            out.extend_from_slice(&chunk_type.to_be_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&sector.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
            if chunk_type != CHUNK_COMMENT {
                sector += count;
            }
        }
        out
    }

    #[test]
    fn chunks_cover_the_partition_and_are_offset_by_the_data_fork() {
        let bytes = table_bytes(
            40,
            8,
            &[
                (CHUNK_ZLIB, 4, 0x10, 30),
                (CHUNK_COMMENT, 0, 0, 0),
                (CHUNK_IGNORE, 4, 0, 0),
            ],
        );
        let t = table(&bytes, "test", 0x200).unwrap();
        assert_eq!(t.first_sector, 40);
        assert_eq!(t.size(), 4096);
        assert_eq!(t.chunks.len(), 2);
        assert_eq!(t.chunks[0].kind, Kind::Compressed(Codec::Zlib));
        assert_eq!(t.chunks[0].offset, 0x210);
        assert_eq!(t.chunks[1].sector, 4);
        assert_eq!(t.chunk_summary(), "zlib 1, ignore 1");
        assert!(t.has_stored_data());
    }

    #[test]
    fn gaps_overruns_and_missing_end_chunks_are_errors() {
        let mut gap = table_bytes(0, 8, &[(CHUNK_RAW, 4, 0, 2048), (CHUNK_ZERO, 4, 0, 0)]);
        gap[HEADER_SIZE + CHUNK_SIZE + 8..HEADER_SIZE + CHUNK_SIZE + 16]
            .copy_from_slice(&5u64.to_be_bytes());
        assert_eq!(
            table(&gap, "p", 0).unwrap_err().to_string(),
            "Apple disk image parse error: Invalid chunk 1 of p: it starts at sector 5, expected 4"
        );
        let over = table_bytes(0, 4, &[(CHUNK_RAW, 8, 0, 4096)]);
        assert!(table(&over, "p", 0).is_err());
        let short = table_bytes(0, 8, &[(CHUNK_RAW, 4, 0, 2048)]);
        assert!(table(&short, "p", 0).is_err());
        let mut no_end = table_bytes(0, 4, &[(CHUNK_RAW, 4, 0, 2048)]);
        no_end.truncate(no_end.len() - CHUNK_SIZE);
        no_end[200..204].copy_from_slice(&1u32.to_be_bytes());
        assert!(table(&no_end, "p", 0).is_err());
        let mut bad_size = table_bytes(0, 4, &[(CHUNK_RAW, 4, 0, 2048)]);
        bad_size.push(0);
        assert!(table(&bad_size, "p", 0).is_err());
        let mut bad_signature = table_bytes(0, 4, &[(CHUNK_RAW, 4, 0, 2048)]);
        bad_signature[0] = b'M';
        assert!(table(&bad_signature, "p", 0).is_err());
    }

    #[test]
    fn unknown_chunk_types_are_kept_as_such() {
        let bytes = table_bytes(0, 1, &[(0x8000_00ff, 1, 0, 16)]);
        let t = table(&bytes, "p", 0).unwrap();
        assert_eq!(t.chunks[0].kind, Kind::Unknown(0x8000_00ff));
        assert_eq!(t.chunk_summary(), "type 0x800000FF 1");
    }
}
