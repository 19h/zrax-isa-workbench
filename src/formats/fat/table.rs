//! File allocation tables and the cluster heap: FAT12, FAT16 and FAT32
//! entries ([FATGEN] "FAT Type Determination"), exFAT entries ([EXFAT]
//! 4.1), cluster chains and the file offsets of clusters ([FATGEN] "FAT
//! Data Structure"; [EXFAT] 5.1).

use super::*;
use std::collections::HashSet;

/// FAT32 entries are 28 bits; the high 4 bits are reserved.
const FAT32_ENTRY_MASK: u32 = 0x0fff_ffff;

/// The first cluster of the heap; entries 0 and 1 are reserved.
pub(super) const FIRST_CLUSTER: u32 = 2;

/// The width and special values of a FAT's entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryKind {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl EntryKind {
    /// Bits per entry as stored.
    fn bits(self) -> u64 {
        match self {
            Self::Fat12 => 12,
            Self::Fat16 => 16,
            Self::Fat32 | Self::ExFat => 32,
        }
    }

    /// Bytes that `entries` entries occupy, rounded up.
    pub(super) fn table_size(self, entries: u64) -> u64 {
        div_round_up(entries * self.bits(), 8)
    }

    /// Bits that carry the entry value.
    pub(super) fn mask(self) -> u32 {
        match self {
            Self::Fat12 => 0x0fff,
            Self::Fat16 => 0xffff,
            Self::Fat32 => FAT32_ENTRY_MASK,
            Self::ExFat => u32::MAX,
        }
    }

    /// The bad-cluster mark.
    fn bad(self) -> u32 {
        match self {
            Self::Fat12 => 0x0ff7,
            Self::Fat16 => 0xfff7,
            Self::Fat32 => 0x0fff_fff7,
            Self::ExFat => 0xffff_fff7,
        }
    }

    /// End-of-chain marks: any value from 0xFF8 (FAT12), 0xFFF8 (FAT16) or
    /// 0x0FFFFFF8 (FAT32) up; exFAT allows only 0xFFFFFFFF.
    fn is_end(self, value: u32) -> bool {
        match self {
            Self::Fat12 => value >= 0x0ff8,
            Self::Fat16 => value >= 0xfff8,
            Self::Fat32 => value >= 0x0fff_fff8,
            Self::ExFat => value == u32::MAX,
        }
    }
}

/// What a FAT entry says about the cluster after its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Link {
    /// The next cluster of the chain.
    Next(u32),
    /// An end-of-chain mark.
    End,
    /// A free cluster.
    Free,
    /// The bad-cluster mark.
    Bad,
    /// A value that is neither a cluster of the heap nor a mark.
    Reserved(u32),
}

/// One FAT: `bytes` covers at least the entries of clusters 0 to
/// `cluster_count + 1`.
pub(super) struct Table<'a> {
    bytes: &'a [u8],
    kind: EntryKind,
    cluster_count: u32,
}

impl<'a> Table<'a> {
    pub(super) fn new(bytes: &'a [u8], kind: EntryKind, cluster_count: u32) -> Self {
        Self {
            bytes,
            kind,
            cluster_count,
        }
    }

    /// The highest cluster number of the heap.
    pub(super) fn last_cluster(&self) -> u32 {
        self.cluster_count + 1
    }

    /// Whether `cluster` is a cluster of the heap.
    pub(super) fn is_cluster(&self, cluster: u32) -> bool {
        (FIRST_CLUSTER..=self.last_cluster()).contains(&cluster)
    }

    /// Entry `n`, without the reserved bits of FAT32 entries, or `None`
    /// when the table does not hold it. A FAT12 entry is the low 12 bits
    /// of the word at `n + n / 2` for even `n` and the high 12 bits for odd
    /// `n`.
    pub(super) fn entry(&self, n: u32) -> Option<u32> {
        let n = usize::try_from(n).ok()?;
        let value = match self.kind {
            EntryKind::Fat12 => {
                let at = n.checked_add(n / 2)?;
                let word = u16::from_le_bytes([*self.bytes.get(at)?, *self.bytes.get(at + 1)?]);
                if n % 2 == 1 {
                    u32::from(word >> 4)
                } else {
                    u32::from(word & 0x0fff)
                }
            }
            EntryKind::Fat16 => {
                let at = n.checked_mul(2)?;
                u32::from(u16::from_le_bytes(
                    self.bytes.get(at..at + 2)?.try_into().ok()?,
                ))
            }
            EntryKind::Fat32 | EntryKind::ExFat => {
                let at = n.checked_mul(4)?;
                u32::from_le_bytes(self.bytes.get(at..at + 4)?.try_into().ok()?)
            }
        };
        Some(value & self.kind.mask())
    }

    /// What the entry of `cluster` links to. The table holds the entry of
    /// every cluster of the heap; any other number reads as reserved.
    pub(super) fn link(&self, cluster: u32) -> Link {
        let Some(value) = self.entry(cluster) else {
            return Link::Reserved(cluster);
        };
        if value == 0 {
            Link::Free
        } else if value == self.kind.bad() {
            Link::Bad
        } else if self.kind.is_end(value) {
            Link::End
        } else if self.is_cluster(value) {
            Link::Next(value)
        } else {
            Link::Reserved(value)
        }
    }
}

/// Clusters `first` to `first + clusters - 1`, contiguous in the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Run {
    pub(super) first: u32,
    pub(super) clusters: u32,
}

/// Clusters of a chain, merged into contiguous runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Chain {
    pub(super) runs: Vec<Run>,
    /// Clusters in all runs.
    pub(super) clusters: u32,
    /// The entry of the last cluster is an end-of-chain mark.
    pub(super) terminated: bool,
}

impl Chain {
    /// `clusters` contiguous clusters from `first`, which need no FAT
    /// (exFAT `NoFatChain`).
    pub(super) fn contiguous(table: &Table<'_>, first: u32, clusters: u32) -> Walk<Self> {
        let last = clusters
            .checked_sub(1)
            .and_then(|extra| first.checked_add(extra))
            .filter(|&last| table.is_cluster(first) && last <= table.last_cluster());
        if last.is_none() {
            return Err(format!(
                "clusters {first} + {clusters} lie outside the cluster heap"
            ));
        }
        Ok(Self {
            runs: vec![Run { first, clusters }],
            clusters,
            terminated: true,
        })
    }

    /// The chain from `first`, at most `limit` clusters of it. A chain
    /// that reaches a free, bad or reserved entry, or a cluster it already
    /// holds, is an error.
    pub(super) fn follow(table: &Table<'_>, first: u32, limit: u32) -> Walk<Self> {
        Self::follow_claiming(table, first, limit, |_| Ok(()))
    }

    /// [`Chain::follow`], with `claim` called on each cluster before it
    /// joins the chain; an error from `claim` ends the chain with it.
    pub(super) fn follow_claiming(
        table: &Table<'_>,
        first: u32,
        limit: u32,
        mut claim: impl FnMut(u32) -> Walk<()>,
    ) -> Walk<Self> {
        if !table.is_cluster(first) {
            return Err(format!("first cluster {first} is not in the cluster heap"));
        }
        let mut chain = Self {
            runs: Vec::new(),
            clusters: 0,
            terminated: false,
        };
        let mut seen = HashSet::new();
        let mut cluster = first;
        while chain.clusters < limit {
            claim(cluster)?;
            seen.insert(cluster);
            chain.push(cluster);
            match table.link(cluster) {
                Link::End => {
                    chain.terminated = true;
                    return Ok(chain);
                }
                Link::Next(next) if seen.contains(&next) => {
                    return Err(format!(
                        "the cluster chain loops back from cluster {cluster} to {next}"
                    ));
                }
                Link::Next(next) => cluster = next,
                Link::Free => {
                    return Err(format!("cluster {cluster} links to a free cluster"));
                }
                Link::Bad => return Err(format!("cluster {cluster} links to a bad cluster")),
                Link::Reserved(value) => {
                    return Err(format!(
                        "cluster {cluster} has the invalid FAT entry 0x{value:X}"
                    ));
                }
            }
        }
        chain.terminated = false;
        Ok(chain)
    }

    fn push(&mut self, cluster: u32) {
        self.clusters += 1;
        if let Some(run) = self.runs.last_mut() {
            if run.first.checked_add(run.clusters) == Some(cluster) {
                run.clusters += 1;
                return;
            }
        }
        self.runs.push(Run {
            first: cluster,
            clusters: 1,
        });
    }
}

/// The cluster heap: cluster 2 starts at `offset` in the input. The heap
/// lies inside the volume (the cluster count is derived from, or checked
/// against, the volume size), so a cluster past the end of the input lies
/// past the end of a truncated volume's input.
pub(super) struct Heap<'a> {
    pub(super) data: &'a [u8],
    pub(super) offset: u64,
    pub(super) cluster_size: u64,
}

impl<'a> Heap<'a> {
    /// File offset of `cluster`, a cluster of the heap.
    pub(super) fn cluster_offset(&self, cluster: u32) -> u64 {
        self.offset + u64::from(cluster.saturating_sub(FIRST_CLUSTER)) * self.cluster_size
    }

    /// The first `len` stored bytes of `run` (at most the whole run), with
    /// their file offset; absent when they pass the end of the input.
    pub(super) fn read(&self, run: Run, len: u64) -> ReadResult<(usize, &'a [u8])> {
        let run_size = u64::from(run.clusters) * self.cluster_size;
        let start = self.cluster_offset(run.first);
        let end = start + len.min(run_size);
        let range = usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .filter(|&(_, end)| end <= self.data.len());
        match range {
            Some((start, end)) => Ok((start, &self.data[start..end])),
            None => Err(Fault::Absent),
        }
    }

    /// The first clusters of `run` that lie wholly in the input.
    pub(super) fn present_part(&self, run: Run) -> Run {
        let available = (self.data.len() as u64).saturating_sub(self.cluster_offset(run.first));
        let clusters = u32::try_from(available / self.cluster_size)
            .map_or(run.clusters, |clusters| clusters.min(run.clusters));
        Run {
            first: run.first,
            clusters,
        }
    }

    /// File offset of `cluster`, at most the input size.
    pub(super) fn cluster_offset_in_input(&self, cluster: u32) -> usize {
        usize::try_from(self.cluster_offset(cluster))
            .unwrap_or(usize::MAX)
            .min(self.data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat12_entries_share_bytes() {
        // Entries 0-3: 0xFF8, 0xFFF, 0x003, 0xFFF.
        let bytes = [0xf8, 0xff, 0xff, 0x03, 0xf0, 0xff];
        let table = Table::new(&bytes, EntryKind::Fat12, 2);
        assert_eq!(table.entry(0), Some(0xff8));
        assert_eq!(table.entry(1), Some(0xfff));
        assert_eq!(table.entry(2), Some(0x003));
        assert_eq!(table.entry(3), Some(0xfff));
        assert_eq!(table.entry(4), None);
        assert_eq!(table.link(2), Link::Next(3));
        assert_eq!(table.link(3), Link::End);
    }

    #[test]
    fn fat32_entries_ignore_the_reserved_bits() {
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&0xf000_0003u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x3fff_fff7u32.to_le_bytes());
        let table = Table::new(&bytes, EntryKind::Fat32, 2);
        assert_eq!(table.link(2), Link::Next(3));
        assert_eq!(table.link(3), Link::Bad);
    }

    #[test]
    fn exfat_ends_chains_only_with_all_ones() {
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&0xffff_fff8u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        let table = Table::new(&bytes, EntryKind::ExFat, 2);
        assert_eq!(table.link(2), Link::Reserved(0xffff_fff8));
        assert_eq!(table.link(3), Link::End);
    }

    #[test]
    fn chains_merge_runs_and_reject_loops() {
        // FAT16 entries 2..=6: 3, 5, 0, 6, end.
        let entries: [u16; 7] = [0xfff8, 0xffff, 3, 5, 0, 6, 0xffff];
        let bytes: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        let table = Table::new(&bytes, EntryKind::Fat16, 5);
        let chain = Chain::follow(&table, 2, 10).unwrap();
        assert_eq!(
            chain.runs,
            [
                Run {
                    first: 2,
                    clusters: 2
                },
                Run {
                    first: 5,
                    clusters: 2
                }
            ]
        );
        assert!(chain.terminated);
        let limited = Chain::follow(&table, 2, 3).unwrap();
        assert_eq!((limited.clusters, limited.terminated), (3, false));
        assert!(Chain::follow(&table, 4, 10).unwrap_err().contains("free"));

        let looped: [u16; 4] = [0xfff8, 0xffff, 3, 2];
        let bytes: Vec<u8> = looped.iter().flat_map(|e| e.to_le_bytes()).collect();
        let table = Table::new(&bytes, EntryKind::Fat16, 2);
        assert!(Chain::follow(&table, 2, 10).unwrap_err().contains("loops"));
        assert!(Chain::follow(&table, 7, 10).is_err());
    }
}
