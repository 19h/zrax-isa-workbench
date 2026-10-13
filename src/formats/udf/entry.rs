//! File entries (ECMA-167 4/14.9) and extended file entries (4/14.17): the
//! ICB tag (4/14.6), ICB indirection for strategy 4096 (4/14.7; UDF 2.60
//! 2.3.5.1, 6.6), and the allocation descriptors of the data space
//! (4/12, 4/14.5, 4/14.14): short, long and extended descriptors with
//! continuation extents, or data recorded in the entry itself.

use super::partition::{BlockBytes, Partitions, SectorRun};
use super::*;

/// The ICB tag follows the descriptor tag (4/14.6 figure 4/15): strategy
/// type (4), file type (11) and flags (18).
const ICB_TAG: usize = 16;
const ICB_STRATEGY: usize = ICB_TAG + 4;
const ICB_FILE_TYPE: usize = ICB_TAG + 11;
const ICB_FLAGS: usize = ICB_TAG + 18;

/// ICB strategies UDF records (UDF 2.60 2.3.5.1): a single direct entry,
/// or a chain of ICBs linked by indirect entries.
const STRATEGY_DIRECT: u16 = 4;
const STRATEGY_CHAINED: u16 = 4096;

/// ICB flags bits 0-2 select the allocation descriptors (4/14.6.8).
const FLAGS_ALLOCATION: u16 = 0x0007;
const ALLOCATION_SHORT: u16 = 0;
const ALLOCATION_LONG: u16 = 1;
const ALLOCATION_EXTENDED: u16 = 2;
const ALLOCATION_EMBEDDED: u16 = 3;

/// ICB flags bit 11: the recorded bytes were transformed in a way ECMA-167
/// does not specify (4/14.6.8; UDF 2.60 2.3.5.4 requires 0).
const FLAG_TRANSFORMED: u16 = 1 << 11;

/// File types (4/14.6.6 figure 4/17; UDF 2.60 2.3.5.2).
const FILE_TYPE_UNSPECIFIED: u8 = 0;
const FILE_TYPE_DIRECTORY: u8 = 4;
const FILE_TYPE_BYTES: u8 = 5;

/// Information length at 56 in both entries; the extended attribute and
/// allocation descriptor lengths and the first extended attribute byte
/// (4/14.9 figure 4/21, 4/14.17 figure 4/48).
const INFORMATION_LENGTH: usize = 56;
const FILE_ENTRY_LENGTHS: usize = 168;
const FILE_ENTRY_HEADER: usize = 176;
const EXTENDED_ENTRY_LENGTHS: usize = 208;
const EXTENDED_ENTRY_HEADER: usize = 216;

/// The stream directory ICB of an extended file entry (4/14.17.19).
const STREAM_DIRECTORY_ICB: usize = 152;

/// The indirect ICB of an indirect entry (4/14.7 figure 4/19).
const INDIRECT_ICB: usize = 36;

/// Most ICB indirections followed (Linux `UDF_MAX_ICB_NESTING`).
const MAX_INDIRECTIONS: usize = 1024;

/// Allocation descriptor sizes (4/14.14.1-14.14.3).
const SHORT_AD_SIZE: usize = 8;
const EXTENDED_AD_SIZE: usize = 20;

/// Extent types (4/14.14.1.1 figure 4/42).
const EXTENT_RECORDED: u8 = 0;
const EXTENT_CONTINUATION: u8 = 3;

/// An allocation extent descriptor: tag, previous location (16), length of
/// its allocation descriptors (20), which start at 24 (4/14.5; UDF 2.60
/// 2.3.11).
const AED_LENGTH: usize = 20;
const AED_HEADER: usize = 24;

/// Most continuation extents and most extents of one data space. Ours:
/// a 64 MiB file of single 512-byte blocks needs 131072 extents.
const MAX_CONTINUATIONS: usize = 1 << 14;
const MAX_EXTENTS: usize = 1 << 18;

/// One extent of a data space, in file order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DataExtent {
    /// Recorded data; otherwise the extent reads as zero bytes (4/12).
    pub(super) recorded: bool,
    pub(super) address: Address,
    /// Bytes of the data space in the extent.
    pub(super) length: u32,
}

/// Where an entry's data space is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DataSpace {
    /// In the allocation descriptor field of the entry itself: the file
    /// offset of the data and its length (4/8.8.2).
    Embedded { offset: usize, length: usize },
    /// In extents of logical blocks, covering the information length.
    Extents(Vec<DataExtent>),
}

/// A file entry or extended file entry, after ICB indirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    /// Where the entry was read.
    pub(super) address: Address,
    /// File type from the ICB tag.
    pub(super) file_type: u8,
    /// File size in bytes (4/14.9.10).
    pub(super) information_length: u64,
    pub(super) data: DataSpace,
    /// The ICB transformed flag is set, or extended allocation descriptors
    /// record fewer bytes than they hold: the bytes are not the file's.
    pub(super) transformed: bool,
    /// An extended file entry names a stream directory.
    pub(super) has_streams: bool,
}

impl Entry {
    /// Read the entry at `address`, following indirect entries of strategy
    /// 4096 as Linux `udf_read_inode` does: when the block after the entry
    /// holds an indirect entry with a nonzero extent length, the entry it
    /// names replaces this one.
    pub(super) fn read(
        disc: &Disc<'_>,
        partitions: &Partitions,
        address: Address,
    ) -> ReadResult<Self> {
        let mut current = address;
        for _ in 0..=MAX_INDIRECTIONS {
            let block = partitions.descriptor(disc, current)?;
            disc.charge(block.bytes.len())?;
            let tag = read_tag(block.bytes, block.offset, Some(current.block))?;
            if !matches!(tag.identifier, TAG_FILE_ENTRY | TAG_EXTENDED_FILE_ENTRY) {
                return invalid(format!(
                    "Invalid file entry at {current} (0x{:X}): tag identifier {}",
                    block.offset, tag.identifier
                ));
            }
            let strategy = le_u16(block.bytes, ICB_STRATEGY)?;
            match strategy {
                STRATEGY_DIRECT => {}
                STRATEGY_CHAINED => {
                    if let Some(next) = indirect_target(disc, partitions, current) {
                        current = next;
                        continue;
                    }
                }
                _ => {
                    return invalid(format!(
                        "Unsupported ICB strategy type {strategy} at 0x{:X}",
                        block.offset
                    ))
                }
            }
            let extended = tag.identifier == TAG_EXTENDED_FILE_ENTRY;
            return Self::parse(disc, partitions, current, block, extended);
        }
        invalid(format!(
            "Invalid ICB hierarchy at {address}: more than {MAX_INDIRECTIONS} indirect entries"
        ))
    }

    /// Parse the entry in `block`, the block at `address`.
    fn parse(
        disc: &Disc<'_>,
        partitions: &Partitions,
        address: Address,
        block: BlockBytes<'_>,
        extended: bool,
    ) -> ReadResult<Self> {
        let BlockBytes { bytes, offset } = block;
        let (lengths, header) = if extended {
            (EXTENDED_ENTRY_LENGTHS, EXTENDED_ENTRY_HEADER)
        } else {
            (FILE_ENTRY_LENGTHS, FILE_ENTRY_HEADER)
        };
        let ea_length = le_u32(bytes, lengths)? as usize;
        let ad_length = le_u32(bytes, lengths + 4)? as usize;
        let field_start = header.checked_add(ea_length);
        let field = field_start.and_then(|start| bytes.get(start..start.checked_add(ad_length)?));
        // An entry does not exceed one logical block (4/13; UDF 2.60
        // 2.3.6); Linux `udf_read_inode` checks the same.
        let (Some(field_start), Some(field)) = (field_start, field) else {
            return invalid(format!(
                "Invalid file entry at 0x{offset:X}: {ea_length} B of extended attributes and \
                 {ad_length} B of allocation descriptors exceed the {} B block",
                bytes.len()
            ));
        };
        let flags = le_u16(bytes, ICB_FLAGS)?;
        let information_length = le_u64(bytes, INFORMATION_LENGTH)?;
        let mut transformed = flags & FLAG_TRANSFORMED != 0;
        let data = match flags & FLAGS_ALLOCATION {
            ALLOCATION_EMBEDDED => {
                if information_length != ad_length as u64 {
                    return invalid(format!(
                        "Invalid file entry at 0x{offset:X}: {information_length} B of \
                         information recorded in a {ad_length} B field"
                    ));
                }
                DataSpace::Embedded {
                    offset: offset + field_start,
                    length: ad_length,
                }
            }
            kind @ (ALLOCATION_SHORT | ALLOCATION_LONG | ALLOCATION_EXTENDED) => {
                let descriptors = AllocationDescriptors {
                    kind,
                    own: address.reference,
                };
                let allocation = descriptors.read(disc, partitions, field, information_length)?;
                transformed |= allocation.transformed;
                DataSpace::Extents(allocation.extents)
            }
            other => {
                return invalid(format!(
                    "Unsupported allocation descriptor type {other} in the file entry at \
                     0x{offset:X}"
                ))
            }
        };
        let has_streams = extended && LongAd::read(bytes, STREAM_DIRECTORY_ICB)?.length > 0;
        Ok(Self {
            address,
            file_type: byte(bytes, ICB_FILE_TYPE)?,
            information_length,
            data,
            transformed,
            has_streams,
        })
    }

    /// A directory (file type 4).
    pub(super) fn is_directory(&self) -> bool {
        self.file_type == FILE_TYPE_DIRECTORY
    }

    /// A file of bytes: file type 5, or 0 ("not specified"), which Linux
    /// reads as a regular file too.
    pub(super) fn is_regular(&self) -> bool {
        matches!(self.file_type, FILE_TYPE_BYTES | FILE_TYPE_UNSPECIFIED)
    }
}

/// The ICB that an indirect entry in the block after `address` names, if
/// that block holds one with a nonzero extent length.
fn indirect_target(disc: &Disc<'_>, partitions: &Partitions, address: Address) -> Option<Address> {
    let next = Address {
        block: address.block.checked_add(1)?,
        ..address
    };
    let block = partitions.descriptor(disc, next).ok()?;
    let tag = read_tag(block.bytes, block.offset, Some(next.block)).ok()?;
    if tag.identifier != TAG_INDIRECT_ENTRY {
        return None;
    }
    let target = LongAd::read(block.bytes, INDIRECT_ICB).ok()?;
    (target.length > 0).then_some(target.location)
}

/// The allocation descriptors of one entry.
#[derive(Debug, Clone, Copy)]
struct AllocationDescriptors {
    /// `ALLOCATION_SHORT`, `ALLOCATION_LONG` or `ALLOCATION_EXTENDED`.
    kind: u16,
    /// The entry's partition reference number, which short descriptors use.
    own: u16,
}

/// The extents an entry's allocation descriptors record.
#[derive(Debug, Default)]
struct Allocation {
    extents: Vec<DataExtent>,
    /// Extended descriptors whose recorded or information length differs
    /// from the extent length.
    transformed: bool,
}

/// One allocation descriptor.
#[derive(Debug, Clone, Copy)]
struct Descriptor {
    /// Extent type (4/14.14.1.1).
    kind: u8,
    /// Extent length in bytes.
    length: u32,
    address: Address,
    /// Bytes of information in the extent: the extent length, or an
    /// extended descriptor's information length.
    information: u32,
    /// An extended descriptor's recorded length differs from its extent
    /// length.
    partly_recorded: bool,
}

impl AllocationDescriptors {
    fn size(self) -> usize {
        match self.kind {
            ALLOCATION_SHORT => SHORT_AD_SIZE,
            ALLOCATION_LONG => LONG_AD_SIZE,
            _ => EXTENDED_AD_SIZE,
        }
    }

    /// Decode the descriptor at `at`: `short_ad` length (0) and block (4) in
    /// the entry's partition; `long_ad` length (0) and `lb_addr` (4);
    /// `ext_ad` length (0), recorded length (4), information length (8)
    /// and `lb_addr` (12).
    fn decode(self, field: &[u8], at: usize) -> Result<Descriptor> {
        let raw = le_u32(field, at)?;
        let length = raw & EXTENT_LENGTH_MASK;
        let (address, information, recorded) = match self.kind {
            ALLOCATION_SHORT => (
                Address {
                    block: le_u32(field, at + 4)?,
                    reference: self.own,
                },
                length,
                length,
            ),
            ALLOCATION_LONG => (Address::read(field, at + 4)?, length, length),
            _ => (
                Address::read(field, at + 12)?,
                le_u32(field, at + 8)?,
                le_u32(field, at + 4)? & EXTENT_LENGTH_MASK,
            ),
        };
        let kind = extent_type(raw);
        Ok(Descriptor {
            kind,
            length,
            address,
            information,
            partly_recorded: kind == EXTENT_RECORDED
                && (recorded != length || information != length),
        })
    }

    /// Read the descriptors in `field` and the continuation extents they
    /// name, up to the extents that cover `information_length`; the rest
    /// is the file tail (4/12.1). A zero extent length or the end of a field
    /// ends a sequence (4/12).
    fn read(
        self,
        disc: &Disc<'_>,
        partitions: &Partitions,
        field: &[u8],
        information_length: u64,
    ) -> ReadResult<Allocation> {
        let mut allocation = Allocation::default();
        let mut covered = 0u64;
        let mut current: &[u8] = field;
        let mut continuations = 0;
        let mut pos = 0;
        while covered < information_length {
            if pos + self.size() > current.len() {
                break;
            }
            let descriptor = self.decode(current, pos)?;
            pos += self.size();
            if descriptor.length == 0 {
                break;
            }
            if descriptor.kind == EXTENT_CONTINUATION {
                continuations += 1;
                if continuations > MAX_CONTINUATIONS {
                    return invalid(format!(
                        "Invalid allocation: more than {MAX_CONTINUATIONS} continuation extents"
                    ));
                }
                current = continuation(disc, partitions, descriptor.address)?;
                pos = 0;
                continue;
            }
            if allocation.extents.len() == MAX_EXTENTS {
                return invalid(format!(
                    "Invalid allocation: more than {MAX_EXTENTS} extents"
                ));
            }
            allocation.transformed |= descriptor.partly_recorded;
            allocation.extents.push(DataExtent {
                recorded: descriptor.kind == EXTENT_RECORDED,
                address: descriptor.address,
                length: descriptor.information,
            });
            covered += u64::from(descriptor.information);
        }
        if covered < information_length {
            return invalid(format!(
                "Invalid allocation: the extents hold {covered} B of the {information_length} B \
                 information length"
            ));
        }
        Ok(allocation)
    }
}

/// The allocation descriptors of the continuation extent at `address`: an
/// allocation extent descriptor and the descriptors after it.
fn continuation<'a>(
    disc: &Disc<'a>,
    partitions: &Partitions,
    address: Address,
) -> ReadResult<&'a [u8]> {
    let block = partitions.descriptor(disc, address)?;
    disc.charge(block.bytes.len())?;
    let tag = read_tag(block.bytes, block.offset, Some(address.block))?;
    expect_identifier(
        tag,
        TAG_ALLOCATION_EXTENT,
        "allocation extent descriptor",
        block.offset,
    )?;
    let length = le_u32(block.bytes, AED_LENGTH)? as usize;
    match block
        .bytes
        .get(AED_HEADER..)
        .and_then(|rest| rest.get(..length))
    {
        Some(descriptors) => Ok(descriptors),
        None => invalid(format!(
            "Invalid allocation extent descriptor at 0x{:X}: {length} B of descriptors in a {} \
             B block",
            block.offset,
            block.bytes.len()
        )),
    }
}

/// A piece of a data space in file coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Piece {
    /// Bytes stored at a file offset (which may lie past the end of the
    /// input of a truncated volume).
    Stored { offset: u64, length: u64 },
    /// An unrecorded extent, read as zero bytes (4/12).
    Zeros { length: u64 },
}

impl Piece {
    pub(super) fn length(self) -> u64 {
        match self {
            Self::Stored { length, .. } | Self::Zeros { length } => length,
        }
    }
}

/// The pieces that hold the first `limit` bytes of `entry`'s data space
/// (at most its information length), in order, with stored pieces that
/// continue each other merged.
pub(super) fn pieces(
    disc: &Disc<'_>,
    partitions: &Partitions,
    entry: &Entry,
    limit: u64,
) -> ReadResult<Vec<Piece>> {
    let mut remaining = entry.information_length.min(limit);
    let mut pieces = Vec::new();
    let extents = match &entry.data {
        DataSpace::Embedded { offset, .. } => {
            if remaining > 0 {
                pieces.push(Piece::Stored {
                    offset: *offset as u64,
                    length: remaining,
                });
            }
            return Ok(pieces);
        }
        DataSpace::Extents(extents) => extents,
    };
    let block_size = disc.sector_size as u64;
    let mut runs = Vec::new();
    for extent in extents {
        if remaining == 0 {
            break;
        }
        let take = u64::from(extent.length).min(remaining);
        remaining -= take;
        if !extent.recorded {
            push_piece(&mut pieces, Piece::Zeros { length: take });
            continue;
        }
        let blocks = u32::try_from(blocks_for(take, block_size))
            .expect("a 32-bit length in blocks has 32 bits");
        runs.clear();
        partitions.runs(extent.address, blocks, &mut runs)?;
        let mut left = take;
        for SectorRun { sector, count } in runs.iter().copied() {
            let length = (count * block_size).min(left);
            left -= length;
            push_piece(
                &mut pieces,
                Piece::Stored {
                    offset: sector * block_size,
                    length,
                },
            );
        }
    }
    Ok(pieces)
}

/// Append `piece`, merging it into the last piece when it continues it.
fn push_piece(pieces: &mut Vec<Piece>, piece: Piece) {
    match (pieces.last_mut(), piece) {
        (
            Some(Piece::Stored { offset, length }),
            Piece::Stored {
                offset: next,
                length: more,
            },
        ) if *offset + *length == next => *length += more,
        (Some(Piece::Zeros { length }), Piece::Zeros { length: more }) => *length += more,
        _ => pieces.push(piece),
    }
}

/// Whether every stored piece lies in the input.
pub(super) fn is_present(data: &[u8], pieces: &[Piece]) -> bool {
    pieces.iter().all(|piece| match *piece {
        Piece::Stored { offset, length } => stored(data, offset, length).is_ok(),
        Piece::Zeros { .. } => true,
    })
}

/// The bytes of `pieces`, all of which must lie in the input. Their
/// presence is checked before anything is allocated.
pub(super) fn assemble(data: &[u8], pieces: &[Piece]) -> ReadResult<Vec<u8>> {
    if !is_present(data, pieces) {
        return Err(Fault::Absent);
    }
    let total: u64 = pieces.iter().map(|piece| piece.length()).sum();
    let mut bytes = Vec::with_capacity(usize::try_from(total).map_err(|_| Fault::Absent)?);
    for piece in pieces {
        match *piece {
            Piece::Stored { offset, length } => {
                bytes.extend_from_slice(stored(data, offset, length)?);
            }
            Piece::Zeros { length } => {
                let length = usize::try_from(length).map_err(|_| Fault::Absent)?;
                bytes.resize(bytes.len() + length, 0);
            }
        }
    }
    Ok(bytes)
}

/// The `length` bytes at file offset `offset`; absent when they pass the end
/// of the input.
pub(super) fn stored(data: &[u8], offset: u64, length: u64) -> ReadResult<&[u8]> {
    let start = usize::try_from(offset).map_err(|_| Fault::Absent)?;
    let len = usize::try_from(length).map_err(|_| Fault::Absent)?;
    let end = start.checked_add(len).ok_or(Fault::Absent)?;
    data.get(start..end).ok_or(Fault::Absent)
}

/// The whole data space of `entry`, whose information length may not pass
/// `limit` bytes.
pub(super) fn read_data(
    disc: &Disc<'_>,
    partitions: &Partitions,
    entry: &Entry,
    limit: usize,
) -> ReadResult<Vec<u8>> {
    if entry.information_length > limit as u64 {
        return invalid(format!(
            "Invalid {}: {} B of data exceed the {} read",
            entry.address,
            entry.information_length,
            size_text(limit)
        ));
    }
    let pieces = pieces(disc, partitions, entry, entry.information_length)?;
    assemble(disc.data, &pieces)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_decode_short_long_and_extended_forms() {
        let short = AllocationDescriptors {
            kind: ALLOCATION_SHORT,
            own: 2,
        };
        let mut field = [0u8; EXTENDED_AD_SIZE];
        field[0..4].copy_from_slice(&0x4000_0800u32.to_le_bytes());
        field[4..8].copy_from_slice(&9u32.to_le_bytes());
        let decoded = short.decode(&field, 0).expect("8 bytes");
        assert_eq!(decoded.kind, 1);
        assert_eq!(decoded.length, 0x800);
        assert_eq!(
            decoded.address,
            Address {
                block: 9,
                reference: 2
            }
        );

        let extended = AllocationDescriptors {
            kind: ALLOCATION_EXTENDED,
            own: 0,
        };
        let mut field = [0u8; EXTENDED_AD_SIZE];
        field[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        field[4..8].copy_from_slice(&0x800u32.to_le_bytes());
        field[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        field[12..16].copy_from_slice(&5u32.to_le_bytes());
        field[16..18].copy_from_slice(&1u16.to_le_bytes());
        let decoded = extended.decode(&field, 0).expect("20 bytes");
        assert!(decoded.partly_recorded);
        assert_eq!(decoded.address.reference, 1);
    }

    #[test]
    fn pieces_merge_when_they_continue_each_other() {
        let mut pieces = Vec::new();
        push_piece(
            &mut pieces,
            Piece::Stored {
                offset: 0,
                length: 4,
            },
        );
        push_piece(
            &mut pieces,
            Piece::Stored {
                offset: 4,
                length: 4,
            },
        );
        push_piece(&mut pieces, Piece::Zeros { length: 2 });
        push_piece(&mut pieces, Piece::Zeros { length: 2 });
        push_piece(
            &mut pieces,
            Piece::Stored {
                offset: 20,
                length: 1,
            },
        );
        assert_eq!(
            pieces,
            [
                Piece::Stored {
                    offset: 0,
                    length: 8
                },
                Piece::Zeros { length: 4 },
                Piece::Stored {
                    offset: 20,
                    length: 1
                }
            ]
        );
        let data: Vec<u8> = (1..=32).collect();
        let bytes = assemble(&data, &pieces).expect("present");
        assert_eq!(bytes, [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 21]);
        assert!(assemble(&data[..16], &pieces).is_err());
    }
}
