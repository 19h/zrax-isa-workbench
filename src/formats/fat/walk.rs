//! What the FAT and exFAT walks share: directory paths, the clusters of
//! directories (each cluster read as a directory at most once, which ends
//! loops and cross-links), regular files read through their cluster
//! chains and listed when they start with a recognized format, and the
//! census of what the walk found and left out.

use super::table::{Chain, Heap, Table};
use super::*;
use crate::formats::container::{self, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// Deepest directory level below the root that the walk enters.
pub(super) const MAX_DEPTH: usize = 64;

/// Bytes at the start of a regular file read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: u64 = 4096;

/// Most regular files examined in one volume.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// The transform of an exFAT file whose bytes past `ValidDataLength` read
/// as zeros ([EXFAT] 7.6.5).
const VALID_DATA_TRANSFORM: &str = "exFAT valid data length";

/// Stored directory bytes: a run of clusters, or the FAT12/FAT16 root
/// directory region.
#[derive(Debug, Clone, Copy)]
pub(super) struct Extent<'a> {
    /// File offset.
    pub(super) offset: usize,
    pub(super) bytes: &'a [u8],
}

/// The entries of `extents` in order, with their file offsets.
pub(super) fn entries<'e, 'a>(
    extents: &'e [Extent<'a>],
) -> impl Iterator<Item = (usize, &'a [u8])> + 'e {
    extents.iter().flat_map(|extent| {
        extent
            .bytes
            .chunks_exact(DIRECTORY_ENTRY_SIZE)
            .enumerate()
            .map(move |(i, entry)| (extent.offset + i * DIRECTORY_ENTRY_SIZE, entry))
    })
}

/// How far a directory's clusters extend.
#[derive(Debug, Clone, Copy)]
pub(super) enum Span {
    /// Along the FAT chain to its end, at most `max_size` bytes.
    Chain { max_size: u64 },
    /// `size` bytes, along the FAT chain or `contiguous`.
    Sized { size: u64, contiguous: bool },
}

/// A directory's stored bytes.
#[derive(Debug)]
pub(super) struct DirectoryData<'a> {
    pub(super) extents: Vec<Extent<'a>>,
    /// The chain continues past the size limit; the rest was not read.
    pub(super) cut: bool,
}

/// Where a regular file's data is.
#[derive(Debug, Clone, Copy)]
pub(super) struct FileRef {
    pub(super) first_cluster: u32,
    /// Size in bytes.
    pub(super) size: u64,
    /// Bytes written; later bytes read as zeros (exFAT
    /// `ValidDataLength`; the size for FAT).
    pub(super) valid_size: u64,
    /// The clusters are contiguous and the FAT does not chain them (exFAT
    /// `NoFatChain`).
    pub(super) contiguous: bool,
}

/// A walked directory's name and parent, from which paths are built.
/// Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// Bytes read from a file.
struct FileData<'a> {
    bytes: Cow<'a, [u8]>,
    /// File offset and size of the first stored run.
    offset: usize,
    stored_size: usize,
    /// How the bytes were assembled when they are owned.
    transform: &'static str,
    /// The last cluster's FAT entry ends the chain.
    terminated: bool,
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
pub(super) struct Census {
    pub(super) directories: usize,
    pub(super) files: usize,
    pub(super) members: usize,
    /// Deleted entries (FAT `0xE5` short entries, exFAT File entries with
    /// `InUse` 0).
    pub(super) deleted: usize,
    /// FAT long-name sets that were orphaned, damaged, or whose checksum
    /// did not match their short entry.
    pub(super) unused_long_names: usize,
    pub(super) invalid_entries: usize,
    /// exFAT entry sets whose `SetChecksum` did not match.
    pub(super) checksum_failures: usize,
    /// exFAT entry sets with an unrecognized critical secondary entry.
    pub(super) unrecognized_sets: usize,
    pub(super) too_deep: usize,
    pub(super) unexamined: usize,
    pub(super) too_large: usize,
    pub(super) over_budget: usize,
    /// Files whose chain continues past the clusters their size needs.
    pub(super) long_chains: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

pub(super) struct Walker<'v, 'a> {
    table: &'v Table<'a>,
    heap: &'v Heap<'a>,
    /// Transform of a file reassembled from several runs.
    chain_transform: &'static str,
    nodes: Vec<PathNode>,
    pub(super) census: Census,
    extracted: usize,
    /// One bit per cluster read as a directory.
    directory_clusters: Vec<u64>,
}

impl<'v, 'a> Walker<'v, 'a> {
    pub(super) fn new(
        table: &'v Table<'a>,
        heap: &'v Heap<'a>,
        chain_transform: &'static str,
    ) -> Self {
        let clusters = usize::try_from(table.last_cluster()).unwrap_or(usize::MAX);
        Self {
            table,
            heap,
            chain_transform,
            nodes: vec![PathNode {
                parent: 0,
                name: String::new(),
            }],
            census: Census::default(),
            extracted: 0,
            directory_clusters: vec![0; clusters / 64 + 1],
        }
    }

    /// Record a directory named `name` in the directory at `parent`;
    /// returns its node.
    pub(super) fn add_node(&mut self, parent: usize, name: &str) -> usize {
        self.nodes.push(PathNode {
            parent,
            name: name.to_string(),
        });
        self.nodes.len() - 1
    }

    /// The path of `name` in the directory at `node`, from the root.
    pub(super) fn path(&self, node: usize, name: &str) -> String {
        let mut parts = Vec::new();
        if !name.is_empty() {
            parts.push(name.to_string());
        }
        let mut current = node;
        // Parents precede their children in `nodes`, so this ends at the root.
        while current != 0 {
            parts.push(self.nodes[current].name.clone());
            current = self.nodes[current].parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// Record a problem below the root.
    pub(super) fn problem(&mut self, text: String) {
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census.problems.push(text);
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// The stored bytes of the directory at `first`. Each cluster is
    /// claimed as it is reached and can be claimed once per walk, so a
    /// loop back to an ancestor or two directories sharing clusters end at
    /// the first shared cluster, and following directory chains costs at
    /// most one step per cluster and per directory entry.
    pub(super) fn directory(&mut self, first: u32, span: Span) -> Walk<DirectoryData<'a>> {
        let cluster_size = self.heap.cluster_size;
        let claimed = &mut self.directory_clusters;
        let claim = |cluster: u32| claim_directory_cluster(claimed, cluster);
        let (chain, size) = match span {
            Span::Chain { max_size } => {
                // A chain holds at most the clusters of the heap.
                let limit = u32::try_from(div_round_up(max_size, cluster_size))
                    .unwrap_or(u32::MAX)
                    .min(self.table.last_cluster() - 1);
                let chain = Chain::follow_claiming(self.table, first, limit, claim)?;
                let size = u64::from(chain.clusters) * cluster_size;
                (chain, size)
            }
            Span::Sized { size, contiguous } => {
                let needed = clusters_for(size, cluster_size, self.table)?;
                let chain = if contiguous {
                    let chain = Chain::contiguous(self.table, first, needed)?;
                    (first..first + needed).try_for_each(claim)?;
                    chain
                } else {
                    Chain::follow_claiming(self.table, first, needed, claim)?
                };
                if chain.clusters < needed {
                    return Err(format!(
                        "the cluster chain ends after {} clusters; {size} B need {needed}",
                        chain.clusters
                    ));
                }
                (chain, size)
            }
        };
        let mut extents = Vec::with_capacity(chain.runs.len());
        let mut remaining = size;
        for run in &chain.runs {
            let (offset, bytes) = self.heap.read(*run, remaining)?;
            remaining -= bytes.len() as u64;
            extents.push(Extent { offset, bytes });
        }
        let cut = matches!(span, Span::Chain { .. }) && !chain.terminated;
        Ok(DirectoryData { extents, cut })
    }

    /// The first `len` bytes of `file` (at most its size).
    fn read(&self, file: &FileRef, len: u64) -> Walk<FileData<'a>> {
        let needed = clusters_for(len, self.heap.cluster_size, self.table)?;
        let chain = if file.contiguous {
            Chain::contiguous(self.table, file.first_cluster, needed)?
        } else {
            Chain::follow(self.table, file.first_cluster, needed)?
        };
        if chain.clusters < needed {
            return Err(format!(
                "the cluster chain ends after {} clusters; {} B need {}",
                chain.clusters,
                file.size,
                clusters_for(file.size, self.heap.cluster_size, self.table)?
            ));
        }
        let written = len.min(file.valid_size);
        let mut stored = Vec::with_capacity(chain.runs.len());
        let mut remaining = written;
        for run in &chain.runs {
            if remaining == 0 {
                break;
            }
            let (offset, bytes) = self.heap.read(*run, remaining)?;
            remaining -= bytes.len() as u64;
            stored.push((offset, bytes));
        }
        let (offset, stored_size) = stored.first().map_or(
            (self.heap.cluster_offset_in_input(file.first_cluster), 0),
            |&(offset, bytes)| (offset, bytes.len()),
        );
        let terminated = chain.terminated;
        if let [(_, bytes)] = stored.as_slice() {
            if written == len {
                return Ok(FileData {
                    bytes: Cow::Borrowed(*bytes),
                    offset,
                    stored_size,
                    transform: self.chain_transform,
                    terminated,
                });
            }
        }
        let len = usize::try_from(len).map_err(|_| format!("{len} B exceed the address space"))?;
        let mut bytes = Vec::with_capacity(len);
        for (_, run) in &stored {
            bytes.extend_from_slice(run);
        }
        bytes.resize(len, 0);
        let transform = if stored.len() > 1 {
            self.chain_transform
        } else {
            VALID_DATA_TRANSFORM
        };
        Ok(FileData {
            bytes: Cow::Owned(bytes),
            offset,
            stored_size,
            transform,
            terminated,
        })
    }

    /// The bytes of `file` (an exFAT up-case table).
    pub(super) fn contents(&self, file: &FileRef) -> Walk<Cow<'a, [u8]>> {
        self.read(file, file.size).map(|contents| contents.bytes)
    }

    /// List a regular file when its first bytes are a recognized format and
    /// the limits allow its extraction.
    pub(super) fn file(&mut self, path: String, file: &FileRef, c: &mut Container<'a>) {
        self.census.files += 1;
        if c.children.len() >= MAX_COMPONENTS || self.census.files > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        // An empty file, or one whose bytes all read as zeros, is not a
        // recognized format.
        if file.size == 0 || file.valid_size == 0 {
            return;
        }
        let prefix = match self.read(file, file.size.min(RECOGNITION_PREFIX)) {
            Ok(prefix) => prefix,
            Err(defect) => {
                self.problem(format!("Skipped {path}: {defect}"));
                return;
            }
        };
        if !container::is_recognized(&prefix.bytes) {
            return;
        }
        let Some(size) = usize::try_from(file.size)
            .ok()
            .filter(|&size| size <= MAX_PAYLOAD)
        else {
            self.census.too_large += 1;
            return;
        };
        if self.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return;
        }
        // Charged before reading, so that reads which fail late (a long
        // chain shared by many entries that breaks) count as well.
        self.extracted += size;
        let contents = if prefix.bytes.len() == size {
            prefix
        } else {
            match self.read(file, file.size) {
                Ok(contents) => contents,
                Err(defect) => {
                    self.problem(format!("Skipped {path}: {defect}"));
                    return;
                }
            }
        };
        if !contents.terminated {
            self.census.long_chains += 1;
        }
        let stored_size = contents.stored_size.min(size);
        let child = match contents.bytes {
            Cow::Borrowed(bytes) => Child::stored(path, contents.offset, bytes),
            Cow::Owned(bytes) => Child::decoded(
                path,
                contents.offset,
                stored_size,
                Cow::Owned(bytes),
                contents.transform,
            ),
        };
        c.children.push(child.if_recognized());
        self.census.members += 1;
    }
}

/// Claim `cluster` for a directory in the bit set `claimed`: an error when
/// a directory already holds it.
fn claim_directory_cluster(claimed: &mut [u64], cluster: u32) -> Walk<()> {
    let bit = usize::try_from(cluster).unwrap_or(usize::MAX);
    let Some(word) = claimed.get_mut(bit / 64) else {
        return Err(format!("cluster {cluster} is not in the cluster heap"));
    };
    let mask = 1u64 << (bit % 64);
    if *word & mask != 0 {
        return Err(format!(
            "cluster {cluster} is already part of another directory (a loop or a cross-link)"
        ));
    }
    *word |= mask;
    Ok(())
}

/// Clusters that hold `size` bytes, which must fit in the heap.
fn clusters_for(size: u64, cluster_size: u64, table: &Table<'_>) -> Walk<u32> {
    let clusters = div_round_up(size, cluster_size);
    u32::try_from(clusters)
        .ok()
        .filter(|&clusters| clusters < table.last_cluster())
        .ok_or_else(|| format!("{size} B need more clusters than the volume has"))
}

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    pub(super) fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Directory walk: {}, {}; members in a recognized format: {}",
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        if self.deleted > 0 {
            c.notes.push(format!(
                "{} ignored",
                counted(self.deleted, "deleted entry", "deleted entries")
            ));
        }
        if self.unused_long_names > 0 {
            c.notes.push(format!(
                "{} not used (orphaned, damaged, or with a short-name checksum that does not \
                 match); the short names were used",
                counted(
                    self.unused_long_names,
                    "long-name entry set was",
                    "long-name entry sets were"
                )
            ));
        }
        if self.invalid_entries > 0 {
            c.notes.push(format!(
                "{} skipped",
                counted(
                    self.invalid_entries,
                    "invalid directory entry",
                    "invalid directory entries"
                )
            ));
        }
        if self.checksum_failures > 0 {
            c.notes.push(format!(
                "{} SetChecksum and skipped",
                counted(
                    self.checksum_failures,
                    "directory entry set failed its",
                    "directory entry sets failed their"
                )
            ));
        }
        if self.unrecognized_sets > 0 {
            c.notes.push(format!(
                "{} unrecognized critical entries and skipped",
                counted(
                    self.unrecognized_sets,
                    "directory entry set holds",
                    "directory entry sets hold"
                )
            ));
        }
        if self.long_chains > 0 {
            c.notes.push(format!(
                "{} longer than the file size needs",
                counted(
                    self.long_chains,
                    "member's cluster chain is",
                    "members' cluster chains are"
                )
            ));
        }
        self.limit_notes(c);
        c.notes.extend(self.problems);
        if self.unlisted_problems > 0 {
            c.notes.push(format!(
                "{} not listed",
                counted(
                    self.unlisted_problems,
                    "further problem was",
                    "further problems were"
                )
            ));
        }
        let prefix = c.key_prefix;
        c.push_metadata(
            format!("{prefix}_directory_count"),
            "Directories walked",
            self.directories as u64,
        );
        c.push_metadata(
            format!("{prefix}_regular_file_count"),
            "Regular files",
            self.files as u64,
        );
        c.push_metadata(
            format!("{prefix}_member_count"),
            "Members",
            self.members as u64,
        );
        c.push_metadata(
            format!("{prefix}_deleted_entry_count"),
            "Deleted entries",
            self.deleted as u64,
        );
    }

    /// Notes for what the walk's limits left out.
    fn limit_notes(&self, c: &mut Container<'_>) {
        if self.too_deep > 0 {
            c.notes.push(format!(
                "{} not walked",
                counted(
                    self.too_deep,
                    &format!("directory deeper than {MAX_DEPTH} levels was"),
                    &format!("directories deeper than {MAX_DEPTH} levels were")
                )
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "{} not examined: at most {MAX_COMPONENTS} members are listed and \
                 {MAX_FILES_EXAMINED} files examined",
                counted(self.unexamined, "regular file was", "regular files were")
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} the {} extraction limit; not extracted",
                counted(
                    self.too_large,
                    "recognized file exceeds",
                    "recognized files exceed"
                ),
                size_text(MAX_PAYLOAD as u64)
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "{} not extracted: the {} total extraction limit was reached",
                counted(
                    self.over_budget,
                    "recognized file was",
                    "recognized files were"
                ),
                size_text(MAX_EXTRACTED as u64)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::EntryKind;
    use super::*;

    /// A FAT16 table for clusters 2-5 (2 -> 3 -> end, 4 -> 5 -> end) and a
    /// heap of four 512-byte clusters at 0x200.
    fn volume() -> (Vec<u8>, Vec<u8>) {
        let entries: [u16; 6] = [0xfff8, 0xffff, 3, 0xffff, 5, 0xffff];
        let table: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        let mut data = vec![0u8; 0x200 + 4 * 512];
        for (cluster, fill) in data[0x200..].chunks_mut(512).zip(b'a'..) {
            cluster.fill(fill);
        }
        (table, data)
    }

    #[test]
    fn directories_are_read_once() {
        let (table_bytes, data) = volume();
        let table = Table::new(&table_bytes, EntryKind::Fat16, 4);
        let heap = Heap {
            data: &data,
            offset: 0x200,
            cluster_size: 512,
        };
        let mut walker = Walker::new(&table, &heap, "FAT cluster chain");
        let directory = walker
            .directory(2, Span::Chain { max_size: 1 << 21 })
            .unwrap();
        assert_eq!(directory.extents.len(), 1);
        assert_eq!(directory.extents[0].offset, 0x200);
        assert_eq!(directory.extents[0].bytes.len(), 1024);
        assert!(!directory.cut);
        assert!(walker
            .directory(3, Span::Chain { max_size: 1 << 21 })
            .unwrap_err()
            .contains("already part of another directory"));
        let cut = walker.directory(4, Span::Chain { max_size: 512 }).unwrap();
        assert!(cut.cut);
    }

    #[test]
    fn files_shorter_than_their_valid_size_read_zeros() {
        let (table_bytes, data) = volume();
        let table = Table::new(&table_bytes, EntryKind::Fat16, 4);
        let heap = Heap {
            data: &data,
            offset: 0x200,
            cluster_size: 512,
        };
        let walker = Walker::new(&table, &heap, "exFAT cluster chain");
        let file = FileRef {
            first_cluster: 4,
            size: 1000,
            valid_size: 600,
            contiguous: true,
        };
        let contents = walker.read(&file, 1000).unwrap();
        assert_eq!(contents.transform, VALID_DATA_TRANSFORM);
        assert_eq!(contents.bytes.len(), 1000);
        assert_eq!(contents.bytes[599], b'd');
        assert_eq!(contents.bytes[600], 0);
        // The stored bytes are the written ones, from the first run.
        assert_eq!((contents.offset, contents.stored_size), (0x600, 600));
        let whole = FileRef {
            valid_size: 1000,
            ..file
        };
        let contents = walker.read(&whole, 1000).unwrap();
        assert!(matches!(contents.bytes, Cow::Borrowed(_)));
    }
}
