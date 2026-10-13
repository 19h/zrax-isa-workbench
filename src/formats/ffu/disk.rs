//! Disk assembly: one store's payload blocks placed where its write
//! descriptors say, in descriptor order, so that a later write replaces an
//! earlier one (Microsoft "FFU image format": "It is possible to write a
//! single area of the disk more than once"; the img2ffu reader keeps the
//! last write). `DISK_BEGIN` locations count blocks from the start of the
//! disk and `DISK_END` locations back from its last block, index 0 being
//! the last block (img2ffu reader: `(Length / blockSize) - 1 - BlockIndex`;
//! emmcdl: `-(dwBlockIndex + 1) x dwBlockSizeInBytes` from the end).
//!
//! The store header gives no disk size; the manifest's `MinSectorCount` x
//! `SectorSize` does (the smallest disk the store is for). Without it,
//! `DISK_END` blocks cannot be placed and are skipped, and the disk ends
//! with the last block written from its start. At most the first
//! [`MAX_PAYLOAD`] bytes are assembled; blocks that are not written read as
//! zeros.

use super::*;
use manifest::DiskGeometry;
use store::Access;

/// Most bytes the write descriptors of one store may copy into its
/// analyzed range: a bound of this parser. Images write each block about
/// once (img2ffu writes the primary GPT block three times), so four times
/// the largest range leaves room, while a descriptor table that writes the
/// same blocks over and over cannot make assembly quadratic.
const MAX_WRITTEN: u64 = 4 * MAX_PAYLOAD as u64;

/// The disk range one store's assembly covers.
#[derive(Debug)]
pub(super) struct Plan {
    /// The disk size from the manifest.
    disk: Option<DiskGeometry>,
    /// The disk size used: the manifest's, or the end of the last block
    /// written from the start of the disk.
    size: u64,
    /// Bytes assembled and analyzed: `min(size, MAX_PAYLOAD)`.
    pub(super) limit: usize,
}

/// An assembled disk.
#[derive(Debug)]
pub(super) struct Disk {
    /// The first [`Plan::limit`] bytes of the disk.
    pub(super) image: Vec<u8>,
    /// Blocks written, one per block and location, in or out of the range.
    block_writes: u64,
    /// Of those, blocks written back from the end of the disk.
    end_writes: u64,
    /// Blocks at `DISK_END` locations that were skipped for lack of a disk
    /// size.
    end_skipped: u64,
}

impl Plan {
    /// Check that the write descriptors stay inside the disk the manifest
    /// gives, and choose the range to assemble.
    pub(super) fn new(store: &Store<'_>, disk: Option<DiskGeometry>) -> Result<Self> {
        let block = u64::from(store.block_size);
        let begin = store.extent.begin_blocks * block;
        let size = match disk {
            Some(geometry) => {
                if begin > geometry.bytes {
                    return Err(error(format!(
                        "Invalid store {} write descriptors: blocks from the start of the disk \
                         reach {begin} B, beyond the {} B disk of the manifest",
                        store.number, geometry.bytes
                    )));
                }
                let end = store.extent.end_blocks * block;
                if end > geometry.bytes {
                    return Err(error(format!(
                        "Invalid store {} write descriptors: blocks from the end of the disk \
                         reach back {end} B, beyond the {} B disk of the manifest",
                        store.number, geometry.bytes
                    )));
                }
                geometry.bytes
            }
            None => begin,
        };
        let limit = usize::try_from(size).map_or(MAX_PAYLOAD, |size| size.min(MAX_PAYLOAD));
        Ok(Self { disk, size, limit })
    }

    /// Copy every block write that reaches the analyzed range into a zeroed
    /// image of [`Plan::limit`] bytes.
    pub(super) fn assemble(&self, data: &[u8], store: &Store<'_>) -> Result<Disk> {
        let block = u64::from(store.block_size);
        let mut disk = Disk {
            image: vec![0; self.limit],
            block_writes: 0,
            end_writes: 0,
            end_skipped: 0,
        };
        let mut written = 0u64;
        // The payload block that holds the descriptor's first block.
        let mut first_block = 0u64;
        for descriptor in store.writes.iter() {
            let count = u64::from(descriptor.block_count);
            let run = count * block;
            let source = store.payload_offset as u64 + first_block * block;
            for location in descriptor.locations() {
                let index = u64::from(location.block_index);
                let start = match (location.access, self.disk) {
                    (Access::Begin, _) => index * block,
                    (Access::End, Some(geometry)) => {
                        disk.end_writes += count;
                        // `Plan::new` checked the run against the disk size.
                        geometry.bytes.saturating_sub((index + 1) * block)
                    }
                    (Access::End, None) => {
                        disk.end_skipped += count;
                        continue;
                    }
                };
                disk.block_writes += count;
                written += copy_clipped(&mut disk.image, data, start, source, run)?;
                if written > MAX_WRITTEN {
                    return Err(error(format!(
                        "Unsupported store {} write descriptors: more than {} of block writes \
                         fall in the first {} of the disk (descriptor at 0x{:X})",
                        store.number,
                        size_text(MAX_WRITTEN),
                        size_text(self.limit as u64),
                        descriptor.offset
                    )));
                }
            }
            first_block += count;
        }
        Ok(disk)
    }

    /// Notes and metadata on the assembled disk.
    pub(super) fn push_notes(&self, c: &mut Container<'_>, store: &Store<'_>, disk: &Disk) {
        let n = store.number;
        let source = match self.disk {
            Some(geometry) => format!(
                "disk size {} from the manifest ({} sectors of {} B)",
                size_text(geometry.bytes),
                geometry.sectors,
                geometry.sector_size
            ),
            None => "no disk size in the manifest, so the disk ends with the last block written \
                     from its start"
                .to_string(),
        };
        let from_end = if disk.end_writes > 0 {
            format!(", {} from the end of the disk", disk.end_writes)
        } else {
            String::new()
        };
        c.notes.push(format!(
            "Store {n} disk assembled from {}{from_end}: {}; {source}",
            counted(disk.block_writes, "block write", "block writes"),
            size_text(self.limit as u64)
        ));
        if disk.end_skipped > 0 {
            c.notes.push(format!(
                "Store {n}: {} written back from the end of the disk were skipped, because the \
                 manifest gives no disk size",
                counted(disk.end_skipped, "block", "blocks")
            ));
        }
        if (self.limit as u64) < self.size {
            c.notes.push(format!(
                "Store {n} disk is {}; only the first {} were assembled and analyzed",
                size_text(self.size),
                size_text(self.limit as u64)
            ));
        }
        c.push_metadata(
            format!("ffu_store_{n}_disk_analyzed"),
            format!("Store {n} disk bytes analyzed (B)"),
            self.limit as u64,
        );
    }
}

/// Copy the part of the `run` bytes at file offset `source` that falls in
/// `image` when written at disk offset `start`, and return how many bytes
/// that is.
fn copy_clipped(image: &mut [u8], data: &[u8], start: u64, source: u64, run: u64) -> Result<u64> {
    let limit = image.len() as u64;
    if start >= limit || run == 0 {
        return Ok(0);
    }
    let len = run.min(limit - start);
    let start = usize::try_from(start).expect("start is below the image length");
    let len = usize::try_from(len).expect("len is at most the image length");
    let bytes = slice(
        data,
        to_usize(source, "payload block")?,
        len,
        "payload block",
    )?;
    image[start..start + len].copy_from_slice(bytes);
    Ok(len as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_are_clipped_to_the_image() {
        let data: Vec<u8> = (1..=16).collect();
        let mut image = vec![0u8; 8];
        assert_eq!(copy_clipped(&mut image, &data, 6, 0, 4).unwrap(), 2);
        assert_eq!(image, [0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(copy_clipped(&mut image, &data, 8, 0, 4).unwrap(), 0);
        assert_eq!(copy_clipped(&mut image, &data, 0, 4, 0).unwrap(), 0);
        assert_eq!(copy_clipped(&mut image, &data, 0, 10, 4).unwrap(), 4);
        assert_eq!(image, [11, 12, 13, 14, 0, 0, 1, 2]);
        assert!(copy_clipped(&mut image, &data, 0, 14, 4).is_err());
    }
}
