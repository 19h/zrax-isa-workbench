//! CFDATA blocks and folder decoding (SDK "CFDATA", "Checksum Method",
//! "`MSZip` Format", "LZX Format"; [MS-MCI] section 2).
//!
//! CFDATA: `csum` (0), `cbData` (4), `cbUncomp` (6), `cbCFData` reserve
//! bytes, then `cbData` data bytes. A folder's first block is at its
//! `coffCabStart` and the others follow it. Every block decodes to 32 KiB
//! except the folder's last, and a block whose `cbUncomp` is 0 continues
//! as the first block of the next cabinet.
//!
//! A stored folder's blocks hold its bytes. Each MSZIP block is `CK` and a
//! DEFLATE stream that may copy from the blocks before it. An LZX folder is
//! one LZX stream whose 32 KiB frames are its blocks, which is how
//! libmspack (`cabd.c`, "Notes on compliance with cabinet specification")
//! decodes it; a folder whose inner blocks are not 32 KiB is not decoded.

use super::header::{Compression, Continuation, Folder};
use super::*;
use crate::formats::compressed::{self, Codec};
use std::borrow::Cow;

/// Uncompressed bytes of a full CFDATA block, which is also an LZX frame
/// (SDK "Cab Block Size"; libmspack `CAB_BLOCKMAX`).
const BLOCK_SIZE: usize = 32 << 10;

/// Largest data size of a block: 32 KiB plus the 6 KiB that LZX may add
/// (SDK "Cab Block Size"; libmspack `CAB_INPUTMAX`).
const MAX_BLOCK_DATA: usize = BLOCK_SIZE + (6 << 10);

/// Fixed size of a CFDATA header, before its reserve area.
const CFDATA_SIZE: usize = 8;

/// The MSZIP block signature ([MS-MCI] section 2).
const MSZIP_SIGNATURE: &[u8; 2] = b"CK";

/// The transform of a stored file reassembled from several blocks.
const STORED_TRANSFORM: &str = "CFDATA blocks";

/// The transform of files in an MSZIP folder.
const MSZIP_TRANSFORM: &str = "MSZIP";

/// Folders described one by one in the metadata; the rest are counted in a
/// note, so the metadata stays small for any cabinet.
const FOLDER_METADATA: usize = 64;

/// Why a folder's files cannot be extracted, for a note.
pub(super) type Problem = String;

/// A folder-level outcome: the value, or why the folder's files are left
/// out.
pub(super) type Outcome<T> = std::result::Result<T, Problem>;

/// One CFDATA block.
#[derive(Debug)]
pub(super) struct Block<'a> {
    /// File offset of the CFDATA header.
    pub offset: usize,
    /// The stored `cbData` and `cbUncomp`, which the checksum covers.
    sizes: [u8; 4],
    /// File offset of the data bytes.
    pub data_offset: usize,
    pub data: &'a [u8],
    /// `cbUncomp`: 0 for a block that continues in the next cabinet.
    pub uncompressed: usize,
}

impl Block<'_> {
    /// The checksum over the data, then over `cbData` and `cbUncomp`: the
    /// SDK's `CSUMCompute(&cbData, sizeof(CFDATA) - sizeof(csum), ...)`,
    /// where `sizeof(CFDATA)` counts only the fixed 8 bytes, as libmspack
    /// computes it (`cabd_checksum(&hdr[4], 4, sum2)`).
    fn computed_checksum(&self) -> u32 {
        checksum(&self.sizes, checksum(self.data, 0))
    }
}

/// A checksum that does not match.
#[derive(Debug, Clone, Copy)]
pub(super) struct Mismatch {
    /// File offset of the block.
    pub offset: usize,
    pub stored: u32,
    pub computed: u32,
}

/// The CFDATA blocks of one folder in this cabinet.
#[derive(Debug)]
pub(super) struct Chain<'a> {
    pub blocks: Vec<Block<'a>>,
    /// Offset of each block in the folder's uncompressed bytes.
    starts: Vec<usize>,
    /// Uncompressed bytes of the complete blocks.
    pub uncompressed: usize,
    /// Stored bytes from the first block's header to the last block's end.
    pub stored: usize,
    /// The last block continues in the next cabinet (`cbUncomp` 0).
    pub split: bool,
    /// Blocks whose checksum matches, blocks without one, and the first
    /// that does not match.
    pub verified: usize,
    pub unchecked: usize,
    pub mismatches: usize,
    pub first_mismatch: Option<Mismatch>,
}

/// Where a range of a folder's uncompressed bytes is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Extent {
    /// File offset of the first stored byte.
    pub offset: usize,
    /// Stored bytes up to the last one, CFDATA headers between included.
    pub size: usize,
}

/// The bytes of a stored file and where they lie.
pub(super) struct StoredBytes<'a> {
    pub extent: Extent,
    /// Borrowed when one block holds them, reassembled otherwise.
    pub bytes: Cow<'a, [u8]>,
}

impl<'a> StoredBytes<'a> {
    /// The child for these bytes: stored as-is, or reassembled from blocks.
    pub fn into_child(self, label: String) -> Child<'a> {
        match self.bytes {
            Cow::Borrowed(bytes) => Child::stored(label, self.extent.offset, bytes),
            reassembled @ Cow::Owned(_) => Child::decoded(
                label,
                self.extent.offset,
                self.extent.size,
                reassembled,
                STORED_TRANSFORM,
            ),
        }
    }
}

/// The blocks that hold a range of uncompressed bytes, by index.
struct Covering {
    first: usize,
    last: usize,
}

impl<'a> Chain<'a> {
    /// The blocks that hold uncompressed bytes `start..end`, which must lie
    /// within [`Chain::uncompressed`] with `start < end`.
    fn covering(&self, start: usize, end: usize) -> Covering {
        Covering {
            first: self.starts.partition_point(|&s| s <= start) - 1,
            last: self.starts.partition_point(|&s| s < end) - 1,
        }
    }

    /// The stored extent of uncompressed bytes `start..end` of a compressed
    /// folder: from the data of the block that holds `start` to the end of
    /// the data of the block that holds the last byte.
    pub fn extent(&self, start: usize, end: usize) -> Extent {
        let Covering { first, last } = self.covering(start, end);
        let offset = self.blocks[first].data_offset;
        let last = &self.blocks[last];
        Extent {
            offset,
            size: last.data_offset + last.data.len() - offset,
        }
    }

    /// Uncompressed bytes `start..end` of a stored folder: borrowed when
    /// one block holds them, otherwise reassembled.
    pub fn stored_bytes(&self, start: usize, end: usize) -> StoredBytes<'a> {
        let Covering { first, last } = self.covering(start, end);
        let first_block = &self.blocks[first];
        let last_block = &self.blocks[last];
        let offset = first_block.data_offset + (start - self.starts[first]);
        let end_offset = last_block.data_offset + (end - self.starts[last]);
        let extent = Extent {
            offset,
            size: end_offset - offset,
        };
        if first == last {
            let at = start - self.starts[first];
            return StoredBytes {
                extent,
                bytes: Cow::Borrowed(&first_block.data[at..at + (end - start)]),
            };
        }
        let mut bytes = Vec::with_capacity(end - start);
        for (i, block) in self.blocks[first..=last].iter().enumerate() {
            let block_start = self.starts[first + i];
            let from = start.saturating_sub(block_start);
            let to = (end - block_start).min(block.data.len());
            bytes.extend_from_slice(&block.data[from..to]);
        }
        StoredBytes {
            extent,
            bytes: Cow::Owned(bytes),
        }
    }
}

/// Read the CFDATA chain of every folder, and check that no two chains
/// overlap.
pub(super) fn read_chains<'a>(
    cabinet: &'a [u8],
    header: &Header<'_>,
    folders: &[Folder],
    continuation: &Continuation,
) -> Result<Vec<Chain<'a>>> {
    let chains = folders
        .iter()
        .enumerate()
        .map(|(index, folder)| read_chain(cabinet, header, index, folder, continuation))
        .collect::<Result<Vec<_>>>()?;
    check_overlaps(folders, &chains)?;
    Ok(chains)
}

/// Read folder `index`'s blocks (`csum` at 0, `cbData` at 4, `cbUncomp` at
/// 6, then `cbCFData` reserve bytes and the data): each within the cabinet,
/// at most 32 KiB
/// uncompressed and 38 KiB stored (libmspack's bounds), `cbUncomp` 0 only
/// for the last block of a folder that continues in the next cabinet, and
/// a stored block's sizes equal unless the block is split across cabinets.
fn read_chain<'a>(
    cabinet: &'a [u8],
    header: &Header<'_>,
    index: usize,
    folder: &Folder,
    continuation: &Continuation,
) -> Result<Chain<'a>> {
    let header_size = CFDATA_SIZE + header.data_reserve;
    let available = cabinet.len().saturating_sub(folder.data_offset);
    if folder.block_count > available / header_size {
        return Err(error(format!(
            "Truncated CFDATA chain of folder {index} at 0x{:X}: {} need more than the {available} \
             B left",
            folder.data_offset,
            count(folder.block_count, "block", "blocks")
        )));
    }
    let starts_before = continuation.starts_before(index);
    let continues_after = continuation.continues_after(index, header.folder_count);
    let mut chain = Chain {
        blocks: Vec::with_capacity(folder.block_count),
        starts: Vec::with_capacity(folder.block_count),
        uncompressed: 0,
        stored: 0,
        split: false,
        verified: 0,
        unchecked: 0,
        mismatches: 0,
        first_mismatch: None,
    };
    let mut pos = folder.data_offset;
    for i in 0..folder.block_count {
        let fixed = slice(cabinet, pos, CFDATA_SIZE, "CFDATA")?;
        let stored_checksum = le_u32(fixed, 0)?;
        let data_size = usize::from(le_u16(fixed, 4)?);
        let uncompressed = usize::from(le_u16(fixed, 6)?);
        let data_offset = pos + header_size;
        let data = slice(cabinet, data_offset, data_size, "CFDATA data")?;
        if uncompressed > BLOCK_SIZE {
            return Err(error(format!(
                "Invalid CFDATA at 0x{pos:X}: cbUncomp {uncompressed} B exceeds 32 KiB"
            )));
        }
        if data_size > MAX_BLOCK_DATA {
            return Err(error(format!(
                "Invalid CFDATA at 0x{pos:X}: cbData {data_size} B exceeds 38 KiB"
            )));
        }
        let last = i + 1 == folder.block_count;
        if uncompressed == 0 {
            if !(last && continues_after) {
                return Err(error(format!(
                    "Invalid CFDATA at 0x{pos:X}: cbUncomp 0 outside a block that continues in \
                     the next cabinet"
                )));
            }
            chain.split = true;
        }
        let split_part = uncompressed == 0 || (i == 0 && starts_before);
        if folder.compression == Compression::None && data_size != uncompressed && !split_part {
            return Err(error(format!(
                "Invalid CFDATA at 0x{pos:X}: a stored block of {data_size} B declares \
                 {uncompressed} B uncompressed"
            )));
        }
        let block = Block {
            offset: pos,
            sizes: fixed[4..8].try_into().expect("4 bytes"),
            data_offset,
            data,
            uncompressed,
        };
        if stored_checksum == 0 {
            chain.unchecked += 1;
        } else {
            let computed = block.computed_checksum();
            if computed == stored_checksum {
                chain.verified += 1;
            } else {
                chain.mismatches += 1;
                chain.first_mismatch.get_or_insert(Mismatch {
                    offset: pos,
                    stored: stored_checksum,
                    computed,
                });
            }
        }
        chain.starts.push(chain.uncompressed);
        chain.uncompressed += uncompressed;
        chain.blocks.push(block);
        pos = data_offset + data_size;
    }
    chain.stored = pos - folder.data_offset;
    Ok(chain)
}

/// Two folders may not share stored bytes: overlapping chains would let
/// one stored block be decoded and classified many times.
fn check_overlaps(folders: &[Folder], chains: &[Chain<'_>]) -> Result<()> {
    let mut order: Vec<usize> = (0..folders.len())
        .filter(|&i| !chains[i].blocks.is_empty())
        .collect();
    order.sort_by_key(|&i| folders[i].data_offset);
    for pair in order.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if folders[second].data_offset < folders[first].data_offset + chains[first].stored {
            return Err(error(format!(
                "Invalid CFFOLDER {second} at 0x{:X}: its CFDATA blocks at 0x{:X} overlap those of \
                 folder {first}",
                folders[second].entry_offset, folders[second].data_offset
            )));
        }
    }
    Ok(())
}

/// A folder's uncompressed bytes from its start.
pub(super) enum Contents {
    /// A stored folder, read from its blocks.
    Stored,
    /// Decoded bytes: the whole folder or the first part a limit allowed.
    Decoded {
        data: Vec<u8>,
        transform: &'static str,
    },
}

impl Contents {
    /// At most the first `len` decoded bytes.
    fn truncated(mut self, len: usize) -> Self {
        if let Self::Decoded { data, .. } = &mut self {
            data.truncate(len);
        }
        self
    }
}

/// Decode the first `wanted` uncompressed bytes of a folder (fewer when its
/// complete blocks hold fewer), unless a checksum failed or the folder's
/// compression is not decoded. Codecs decode whole blocks or frames; the
/// bytes past `wanted` are dropped, so the result never exceeds it.
pub(super) fn decode(folder: &Folder, chain: &Chain<'_>, wanted: usize) -> Outcome<Contents> {
    if let Some(mismatch) = chain.first_mismatch {
        return Err(format!(
            "CFDATA checksum 0x{:08X} at 0x{:X} does not match the computed 0x{:08X}",
            mismatch.stored, mismatch.offset, mismatch.computed
        ));
    }
    match folder.compression {
        Compression::None => Ok(Contents::Stored),
        Compression::MsZip => decode_mszip(chain, wanted).map(|c| c.truncated(wanted)),
        Compression::Lzx { window_bits } => {
            decode_lzx(chain, window_bits, wanted).map(|c| c.truncated(wanted))
        }
        Compression::Quantum { .. } => Err("Quantum compression is not decoded".into()),
        Compression::Unknown(kind) => Err(format!(
            "compression type {kind} is not defined, so the folder is not decoded"
        )),
    }
}

/// The message of a codec error.
fn reason(e: ClassifierError) -> Problem {
    match e {
        ClassifierError::CompressedParseError { message } => message,
        other => other.to_string(),
    }
}

/// Decode MSZIP blocks until `wanted` bytes are out. Each block is `CK`
/// and one DEFLATE stream that ends with a final block and may copy from
/// the blocks before it ([MS-MCI] section 2), and must decode to exactly
/// its `cbUncomp`.
fn decode_mszip(chain: &Chain<'_>, wanted: usize) -> Outcome<Contents> {
    let mut out = Vec::new();
    for block in &chain.blocks {
        if out.len() >= wanted || block.uncompressed == 0 {
            break;
        }
        let Some(stream) = block.data.strip_prefix(MSZIP_SIGNATURE) else {
            return Err(format!(
                "the MSZIP block at 0x{:X} does not start with the signature CK",
                block.offset
            ));
        };
        let before = out.len();
        compressed::inflate_continuing(stream, &mut out, block.uncompressed).map_err(|e| {
            format!(
                "the MSZIP block at 0x{:X} does not decode: {}",
                block.offset,
                reason(e)
            )
        })?;
        let decoded = out.len() - before;
        if decoded != block.uncompressed {
            return Err(format!(
                "the MSZIP block at 0x{:X} decodes to {decoded} B; its cbUncomp is {} B",
                block.offset, block.uncompressed
            ));
        }
    }
    Ok(Contents::Decoded {
        data: out,
        transform: MSZIP_TRANSFORM,
    })
}

/// Decode the first frames of an LZX folder: at least `wanted` bytes,
/// rounded up to whole 32 KiB frames, at most the complete blocks. The
/// blocks are one stream, so every block but the last must be a whole
/// frame.
fn decode_lzx(chain: &Chain<'_>, window_bits: u8, wanted: usize) -> Outcome<Contents> {
    let complete = if chain.split {
        &chain.blocks[..chain.blocks.len() - 1]
    } else {
        &chain.blocks[..]
    };
    let inner = &complete[..complete.len().saturating_sub(1)];
    if let Some(short) = inner.iter().find(|b| b.uncompressed != BLOCK_SIZE) {
        return Err(format!(
            "the LZX block at 0x{:X} decodes to {} B; only a folder's last block may be shorter \
             than 32 KiB",
            short.offset, short.uncompressed
        ));
    }
    let size = if wanted >= chain.uncompressed {
        chain.uncompressed
    } else {
        round_up_to_frame(wanted).min(chain.uncompressed)
    };
    // The frames' blocks, and one more in case a frame's last bits are
    // stored in the next block.
    let frames = round_up_to_frame(size) / BLOCK_SIZE;
    let blocks = &complete[..(frames + 1).min(complete.len())];
    let stream: Vec<u8> = blocks.iter().flat_map(|b| b.data.iter().copied()).collect();
    let decoded = compressed::decode_limited(Codec::Lzx { window_bits }, &stream, size)
        .map_err(|e| format!("the LZX stream does not decode: {}", reason(e)))?;
    Ok(Contents::Decoded {
        data: decoded.data,
        transform: Codec::Lzx { window_bits }.name(),
    })
}

/// `n` rounded up to whole 32 KiB frames.
fn round_up_to_frame(n: usize) -> usize {
    let frames = n / BLOCK_SIZE + usize::from(n % BLOCK_SIZE != 0);
    frames * BLOCK_SIZE
}

/// Per-folder metadata and the checksum totals.
pub(super) fn push_notes(folders: &[Folder], chains: &[Chain<'_>], c: &mut Container<'_>) {
    let mut verified = 0;
    let mut unchecked = 0;
    let mut mismatches = 0;
    let mut blocks = 0;
    for (i, (folder, chain)) in folders.iter().zip(chains).enumerate() {
        verified += chain.verified;
        unchecked += chain.unchecked;
        mismatches += chain.mismatches;
        blocks += chain.blocks.len();
        if i >= FOLDER_METADATA {
            continue;
        }
        let split = if chain.split {
            "; last block continues in the next cabinet"
        } else {
            ""
        };
        c.push_metadata(
            format!("cab_folder_{i}"),
            format!("Folder {i}"),
            format!(
                "{}; typeCompress 0x{:04X}; {} at 0x{:X}; {} B stored; {} B uncompressed{split}",
                folder.compression,
                folder.type_compress,
                count(chain.blocks.len(), "CFDATA block", "CFDATA blocks"),
                folder.data_offset,
                chain.stored,
                chain.uncompressed
            ),
        );
    }
    if folders.len() > FOLDER_METADATA {
        c.notes.push(format!(
            "Folder metadata describes the first {FOLDER_METADATA} of {} folders",
            folders.len()
        ));
    }
    if blocks == 0 {
        return;
    }
    let mut note = vec![format!(
        "CFDATA checksums verified for {verified} of {blocks} blocks"
    )];
    if unchecked > 0 {
        note.push(format!(
            "{} no checksum (csum 0)",
            count(unchecked, "block carries", "blocks carry")
        ));
    }
    if mismatches > 0 {
        note.push(format!("{} not match", count(mismatches, "does", "do")));
    }
    c.notes.push(note.join("; "));
    c.push_metadata(
        "cab_checksums_verified",
        "CFDATA checksums verified",
        verified as u64,
    );
}
