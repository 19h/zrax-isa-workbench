//! Forks: the extents of a fork in fork order, from its fork data record
//! and, beyond the first eight, from the extents overflow B-tree
//! ([TN1150] "Fork Data Structure", "Extents Overflow File Usage"), and
//! reads of fork bytes through those extents.

use super::header::Extent;
use super::*;
use std::borrow::Cow;

/// A fork's allocation-block runs in fork order.
#[derive(Debug, Clone)]
pub(super) struct Fork {
    /// `logicalSize`: bytes of valid data in the fork.
    pub(super) logical_size: u64,
    /// Runs in fork order. They cover at least the bytes the fork was
    /// resolved for, which may be less than the logical size.
    runs: Vec<Extent>,
    /// CNID of the file, for messages.
    file_id: u32,
}

/// Bytes read from a fork, borrowed when one run holds them all.
pub(super) struct ForkBytes<'a> {
    /// The bytes read.
    pub(super) bytes: Cow<'a, [u8]>,
    /// The first stored run of the bytes read, if any were requested.
    pub(super) first_run: Option<StoredRun>,
}

/// Bytes stored contiguously in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StoredRun {
    /// File offset.
    pub(super) offset: usize,
    /// Size in bytes.
    pub(super) size: usize,
}

/// Allocation blocks of `block_size` bytes that hold `size` bytes.
pub(super) fn blocks_for(size: u64, block_size: u64) -> u64 {
    size / block_size + u64::from(size % block_size != 0)
}

/// Resolve the extents of the fork of `file_id` described by `data` far
/// enough to read its first `need` bytes (at most its logical size). The
/// extents overflow records continue the fork at the block count covered
/// so far; each must add blocks.
pub(super) fn resolve(
    vol: &Volume<'_>,
    extents: Option<&BTree>,
    data: &ForkData,
    file_id: u32,
    fork_type: u8,
    need: u64,
) -> Result<Fork> {
    let needed_blocks = blocks_for(need.min(data.logical_size), vol.block_size());
    let mut fork = Fork {
        logical_size: data.logical_size,
        runs: Vec::new(),
        file_id,
    };
    let mut covered = fork.push_runs(vol, &data.extents, 0)?;
    while covered < needed_blocks {
        let start_block = u32::try_from(covered).map_err(|_| {
            error(format!(
                "Invalid fork of CNID {file_id}: more than 2^32 allocation blocks"
            ))
        })?;
        let record = match extents {
            Some(tree) => tree.extent_record(vol, file_id, fork_type, start_block)?,
            None => None,
        };
        let Some(record) = record else {
            return Err(error(format!(
                "Missing extents overflow record for CNID {file_id} {} fork at block \
                 {start_block}",
                fork_name(fork_type)
            )));
        };
        let after = fork.push_runs(vol, &record, covered)?;
        if after == covered {
            return Err(error(format!(
                "Invalid extents overflow record for CNID {file_id} at block {start_block}: no \
                 blocks"
            )));
        }
        covered = after;
    }
    Ok(fork)
}

/// `data` or `resource`, for messages.
pub(super) fn fork_name(fork_type: u8) -> &'static str {
    if fork_type == RESOURCE_FORK {
        "resource"
    } else {
        "data"
    }
}

impl Fork {
    /// Append the used descriptors of an extent record, which end at the
    /// first descriptor without blocks, and return the blocks covered.
    fn push_runs(&mut self, vol: &Volume<'_>, record: &[Extent], covered: u64) -> Result<u64> {
        let mut covered = covered;
        for &extent in record {
            if extent.block_count == 0 {
                break;
            }
            // Checks that the run lies inside the volume.
            vol.blocks(extent.start_block, extent.block_count)
                .map_err(|_| {
                    error(format!(
                        "Invalid extent of CNID {}: blocks 0x{:X} + {} beyond the {} blocks of \
                         the volume",
                        self.file_id,
                        extent.start_block,
                        extent.block_count,
                        vol.header.total_blocks
                    ))
                })?;
            self.runs.push(extent);
            covered += u64::from(extent.block_count);
        }
        Ok(covered)
    }

    /// File offset of fork byte `position`, if a resolved run holds it.
    pub(super) fn file_offset(&self, vol: &Volume<'_>, position: u64) -> Option<usize> {
        let block_size = vol.block_size();
        let mut run_start = 0u64;
        for run in &self.runs {
            let run_end = run_start + u64::from(run.block_count) * block_size;
            if position < run_end {
                let volume_offset = u64::from(run.start_block) * block_size + position - run_start;
                return usize::try_from(volume_offset)
                    .ok()
                    .map(|at| vol.file_offset(at));
            }
            run_start = run_end;
        }
        None
    }
}

impl<'a> Volume<'a> {
    /// The `len` bytes of `fork` at fork offset `offset`, which must lie
    /// within its logical size and its resolved runs.
    pub(super) fn read_fork(&self, fork: &Fork, offset: u64, len: usize) -> Result<ForkBytes<'a>> {
        let end = offset
            .checked_add(len as u64)
            .filter(|&end| end <= fork.logical_size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid read of CNID {} at 0x{offset:X} + {len} B beyond its logical size of \
                     {} B",
                    fork.file_id, fork.logical_size
                ))
            })?;
        let block_size = self.block_size();
        let mut pieces: Vec<&'a [u8]> = Vec::new();
        let mut first_run = None;
        let mut read = 0usize;
        let mut run_start = 0u64;
        for run in &fork.runs {
            if run_start >= end {
                break;
            }
            let run_end = run_start + u64::from(run.block_count) * block_size;
            if run_end > offset {
                let stored = self.blocks(run.start_block, run.block_count)?;
                // Both bounds lie inside this run, so they fit in usize.
                let from = usize::try_from(offset.max(run_start) - run_start)
                    .expect("offset inside the run");
                let to = usize::try_from(end.min(run_end) - run_start).expect("end inside the run");
                let piece = &stored[from..to];
                if first_run.is_none() {
                    let volume_offset = usize::try_from(u64::from(run.start_block) * block_size)
                        .expect("block offset is in the volume");
                    first_run = Some(StoredRun {
                        offset: self.file_offset(volume_offset + from),
                        size: piece.len(),
                    });
                }
                read += piece.len();
                pieces.push(piece);
            }
            run_start = run_end;
        }
        if read < len {
            return Err(error(format!(
                "Truncated fork of CNID {}: its extents hold {read} of the {len} B at 0x{offset:X}",
                fork.file_id
            )));
        }
        let bytes = match pieces[..] {
            [] => Cow::Borrowed(&[][..]),
            [piece] => Cow::Borrowed(piece),
            _ => Cow::Owned(pieces.concat()),
        };
        Ok(ForkBytes { bytes, first_run })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_counts_round_up() {
        assert_eq!(blocks_for(0, 4096), 0);
        assert_eq!(blocks_for(1, 4096), 1);
        assert_eq!(blocks_for(4096, 4096), 1);
        assert_eq!(blocks_for(4097, 4096), 2);
    }
}
