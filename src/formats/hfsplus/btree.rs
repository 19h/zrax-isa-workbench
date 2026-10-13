//! B-trees ([TN1150] "B-Trees"; [HFS] `BTNodeDescriptor`, `BTHeaderRec`):
//! the header node, node descriptors and record offsets, keyed records,
//! and the search that [HFS] `SearchTree` performs, followed by a walk
//! along the leaf chain.

use super::fork::Fork;
use super::header::{extent_record, Extent, EXTENT_DENSITY};
use super::*;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;

/// Node descriptor size; the first record starts here.
const NODE_DESCRIPTOR_SIZE: usize = 14;

/// Header record fields read: `treeDepth` (0), `rootNode` (2),
/// `leafRecords` (6), `firstLeafNode` (10), `lastLeafNode` (14),
/// `nodeSize` (18), `maxKeyLength` (20), `totalNodes` (22), `freeNodes`
/// (26), `reserved1` (30), `clumpSize` (32), `btreeType` (36),
/// `keyCompareType` (37), `attributes` (38).
const HEADER_RECORD_SIZE: usize = 106;

/// Node kinds (`kBTLeafNode`, `kBTIndexNode`, `kBTHeaderNode`,
/// `kBTMapNode`).
const LEAF_NODE: i8 = -1;
const INDEX_NODE: i8 = 0;
const HEADER_NODE: i8 = 1;
const MAP_NODE: i8 = 2;

/// Node sizes: "a power of two, from 512 through 32,768"; the catalog and
/// attributes B-trees need at least 4 KiB (`kHFSPlusCatalogMinNodeSize`,
/// `kHFSPlusAttrMinNodeSize`; [TN1150] "Node Sizes").
const MIN_NODE_SIZE: usize = 512;
const MAX_NODE_SIZE: usize = 32_768;
const MIN_CATALOG_NODE_SIZE: usize = 4096;

/// `kMaxTreeDepth` ([HFS] `BTreesPrivate.h`).
const MAX_TREE_DEPTH: u16 = 16;

/// `btreeType` of the catalog, extents and attributes B-trees
/// (`kHFSBTreeType`).
const HFS_BTREE_TYPE: u8 = 0;

/// `attributes` bits: 16-bit key lengths, which every HFS Plus B-tree uses,
/// and index keys of their own length rather than `maxKeyLength`.
const BIG_KEYS: u32 = 0x0000_0002;
const VARIABLE_INDEX_KEYS: u32 = 0x0000_0004;

/// `keyCompareType` values of an HFSX catalog (`kHFSCaseFolding`,
/// `kHFSBinaryCompare`).
pub(super) const CASE_FOLDING: u8 = 0xcf;
pub(super) const BINARY_COMPARE: u8 = 0xbc;

/// Extent keys: `keyLength` 10 (`kHFSPlusExtentKeyMaximumLength`), then
/// `forkType` (0), `pad` (1), `fileID` (2), `startBlock` (6) within the key.
const EXTENT_KEY_LENGTH: usize = 10;

/// Size of an extent record (`HFSPlusExtentRecord`).
const EXTENT_RECORD_SIZE: usize = 64;

/// Which B-tree, for messages and the node size rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TreeKind {
    Extents,
    Catalog,
    Attributes,
}

impl TreeKind {
    fn name(self) -> &'static str {
        match self {
            Self::Extents => "extents overflow",
            Self::Catalog => "catalog",
            Self::Attributes => "attributes",
        }
    }

    fn min_node_size(self) -> usize {
        match self {
            Self::Extents => MIN_NODE_SIZE,
            Self::Catalog | Self::Attributes => MIN_CATALOG_NODE_SIZE,
        }
    }
}

/// An opened B-tree: its fork and header record.
#[derive(Debug)]
pub(super) struct BTree {
    kind: TreeKind,
    fork: Fork,
    /// `nodeSize` in bytes.
    pub(super) node_size: usize,
    /// `totalNodes`.
    pub(super) total_nodes: u32,
    /// `rootNode`.
    root: u32,
    /// `treeDepth`: the root node's height; 0 for an empty tree.
    pub(super) depth: u16,
    /// `maxKeyLength`.
    max_key_length: usize,
    /// `kBTVariableIndexKeysMask` is set.
    variable_index_keys: bool,
    /// `keyCompareType`.
    pub(super) key_compare_type: u8,
}

/// A node, after the descriptor and record offset checks.
pub(super) struct Node<'a> {
    number: u32,
    bytes: Cow<'a, [u8]>,
    /// `fLink`: the next node at this level, 0 for the last.
    f_link: u32,
    /// `kind`.
    kind: i8,
    /// `height`.
    height: u8,
    /// Record start offsets, then the start of free space.
    offsets: Vec<usize>,
}

impl Node<'_> {
    fn record_count(&self) -> usize {
        self.offsets.len() - 1
    }
}

/// A keyed record: its key (without the `keyLength` field) and its data.
pub(super) struct Record<'n> {
    /// The key bytes.
    pub(super) key: &'n [u8],
    /// The record data, from its 2-byte aligned start to the record end.
    pub(super) data: &'n [u8],
    /// Offset of the data in the node.
    pub(super) data_offset: usize,
    /// The node the record is in.
    pub(super) node: u32,
}

/// A position in the leaf chain, from which records are read in key order.
pub(super) struct Cursor<'a> {
    node: Node<'a>,
    index: usize,
    /// Leaf nodes visited, so a cycle in the chain ends the walk.
    visited: HashSet<u32>,
}

impl BTree {
    /// Open the B-tree in `fork`: read and check its header node.
    pub(super) fn open(vol: &Volume<'_>, kind: TreeKind, fork: Fork) -> Result<Self> {
        let name = kind.name();
        // `nodeSize` is at a fixed place in the header node, which comes
        // first whatever the node size ([TN1150] "Node Sizes").
        let prefix = vol.read_fork(&fork, 0, NODE_DESCRIPTOR_SIZE + HEADER_RECORD_SIZE)?;
        let node_size = usize::from(be_u16(&prefix.bytes, NODE_DESCRIPTOR_SIZE + 18)?);
        if !node_size.is_power_of_two()
            || !(kind.min_node_size()..=MAX_NODE_SIZE).contains(&node_size)
        {
            return Err(error(format!(
                "Invalid {name} B-tree node size {node_size}"
            )));
        }
        let header = read_node(vol, kind, &fork, node_size, 1, 0)?;
        if header.kind != HEADER_NODE || header.height != 0 || header.record_count() < 3 {
            return Err(error(format!(
                "Invalid {name} B-tree header node: kind {}, height {}, {} records",
                header.kind,
                header.height,
                header.record_count()
            )));
        }
        let record = &header.bytes[header.offsets[0]..header.offsets[1]];
        if record.len() < HEADER_RECORD_SIZE {
            return Err(error(format!(
                "Invalid {name} B-tree header record of {} B",
                record.len()
            )));
        }
        let depth = be_u16(record, 0)?;
        let root = be_u32(record, 2)?;
        let max_key_length = usize::from(be_u16(record, 20)?);
        let total_nodes = be_u32(record, 22)?;
        let btree_type = record[36];
        let key_compare_type = record[37];
        let attributes = be_u32(record, 38)?;
        if btree_type != HFS_BTREE_TYPE {
            return Err(error(format!("Invalid {name} B-tree type {btree_type}")));
        }
        if attributes & BIG_KEYS == 0 {
            return Err(error(format!(
                "Unsupported {name} B-tree without 16-bit key lengths (attributes 0x{attributes:X})"
            )));
        }
        let nodes_size = u64::from(total_nodes) * node_size as u64;
        if total_nodes == 0 || nodes_size > fork.logical_size {
            return Err(error(format!(
                "Invalid {name} B-tree: {total_nodes} nodes of {node_size} B exceed its file of {} B",
                fork.logical_size
            )));
        }
        if depth > MAX_TREE_DEPTH || (depth == 0) != (root == 0) || root >= total_nodes {
            return Err(error(format!(
                "Invalid {name} B-tree: depth {depth}, root node {root} of {total_nodes}"
            )));
        }
        if max_key_length + 2 > node_size {
            return Err(error(format!(
                "Invalid {name} B-tree maxKeyLength {max_key_length}"
            )));
        }
        Ok(Self {
            kind,
            fork,
            node_size,
            total_nodes,
            root,
            depth,
            max_key_length,
            variable_index_keys: attributes & VARIABLE_INDEX_KEYS != 0,
            key_compare_type,
        })
    }

    /// Node `number`, read and checked. Charged to the metadata budget.
    fn node<'a>(&self, vol: &Volume<'a>, number: u32) -> Result<Node<'a>> {
        read_node(
            vol,
            self.kind,
            &self.fork,
            self.node_size,
            self.total_nodes,
            number,
        )
    }

    /// Record `index` of a leaf or index node, split into key and data. In
    /// leaf nodes, and in index nodes with variable index keys, the key
    /// occupies `keyLength` bytes; otherwise index keys occupy
    /// `maxKeyLength` bytes. The data starts on a 2-byte boundary.
    fn record<'n>(&self, node: &'n Node<'_>, index: usize) -> Result<Record<'n>> {
        let start = node.offsets[index];
        let raw = &node.bytes[start..node.offsets[index + 1]];
        let key_length = usize::from(be_u16(raw, 0)?);
        let key_size = if node.kind == INDEX_NODE && !self.variable_index_keys {
            self.max_key_length.max(key_length)
        } else {
            key_length
        };
        let key_end = 2 + key_size;
        let data_start = key_end + key_end % 2;
        if data_start > raw.len() {
            return Err(error(format!(
                "Invalid {} B-tree node {} record {index}: key of {key_size} B overruns the \
                 record",
                self.kind.name(),
                node.number
            )));
        }
        Ok(Record {
            key: &raw[2..2 + key_length],
            data: &raw[data_start..],
            data_offset: start + data_start,
            node: node.number,
        })
    }

    /// Search for the first leaf record whose key is not below the target,
    /// as [HFS] `SearchTree` descends: from the root at level `treeDepth`,
    /// each node's height must be its level, level 1 must be a leaf and
    /// other levels index nodes, node 0 is never in the path, and an index
    /// node leads through its greatest key not above the target. `order`
    /// returns how a key compares with the target. `None` for an empty
    /// tree.
    pub(super) fn lower_bound<'a>(
        &self,
        vol: &Volume<'a>,
        order: &dyn Fn(&[u8]) -> Result<Ordering>,
    ) -> Result<Option<Cursor<'a>>> {
        let name = self.kind.name();
        let mut number = self.root;
        let mut level = self.depth;
        while level > 0 {
            if number == 0 {
                return Err(error(format!(
                    "Invalid {name} B-tree: node 0 in the search path"
                )));
            }
            let node = self.node(vol, number)?;
            let expected = if level == 1 { LEAF_NODE } else { INDEX_NODE };
            if u16::from(node.height) != level || node.kind != expected {
                return Err(error(format!(
                    "Invalid {name} B-tree node {number}: kind {} height {} at level {level}",
                    node.kind, node.height
                )));
            }
            let mut index = node.record_count();
            let mut exact = false;
            for i in 0..node.record_count() {
                match order(self.record(&node, i)?.key)? {
                    Ordering::Less => {}
                    Ordering::Equal => {
                        index = i;
                        exact = true;
                        break;
                    }
                    Ordering::Greater => {
                        index = i;
                        break;
                    }
                }
            }
            if level == 1 {
                return Ok(Some(Cursor {
                    visited: HashSet::from([number]),
                    node,
                    index,
                }));
            }
            if node.record_count() == 0 {
                return Err(error(format!(
                    "Invalid {name} B-tree index node {number}: no records"
                )));
            }
            let chosen = if exact {
                index
            } else {
                index.saturating_sub(1)
            };
            number = be_u32(self.record(&node, chosen)?.data, 0)?;
            level -= 1;
        }
        Ok(None)
    }

    /// The extent record keyed (`file_id`, `fork_type`, `start_block`), if
    /// the extents overflow B-tree holds it. Keys compare by `fileID`, then
    /// `forkType`, then `startBlock` ([TN1150] "Extents Overflow File
    /// Key").
    pub(super) fn extent_record(
        &self,
        vol: &Volume<'_>,
        file_id: u32,
        fork_type: u8,
        start_block: u32,
    ) -> Result<Option<[Extent; EXTENT_DENSITY]>> {
        let target = ExtentKey {
            file_id,
            fork_type,
            start_block,
        };
        let order = |key: &[u8]| Ok(ExtentKey::parse(key)?.cmp(&target));
        let Some(mut cursor) = self.lower_bound(vol, &order)? else {
            return Ok(None);
        };
        let Some(record) = cursor.next(self, vol)? else {
            return Ok(None);
        };
        if ExtentKey::parse(record.key)? != target {
            return Ok(None);
        }
        if record.data.len() < EXTENT_RECORD_SIZE {
            return Err(error(format!(
                "Invalid extents overflow record for CNID {file_id}: {} B",
                record.data.len()
            )));
        }
        extent_record(record.data, 0).map(Some)
    }

    /// File offset of byte `offset` of node `number`.
    pub(super) fn file_offset(
        &self,
        vol: &Volume<'_>,
        number: u32,
        offset: usize,
    ) -> Option<usize> {
        let position = u64::from(number) * self.node_size as u64 + offset as u64;
        self.fork.file_offset(vol, position)
    }
}

/// Node `number` of a B-tree of `total_nodes` nodes of `node_size` bytes
/// in `fork`, after the descriptor and record offset checks. Charged to the
/// metadata budget.
fn read_node<'a>(
    vol: &Volume<'a>,
    kind: TreeKind,
    fork: &Fork,
    node_size: usize,
    total_nodes: u32,
    number: u32,
) -> Result<Node<'a>> {
    let name = kind.name();
    if number >= total_nodes {
        return Err(error(format!(
            "Invalid {name} B-tree node {number} of {total_nodes}"
        )));
    }
    vol.charge(node_size)?;
    let at = u64::from(number) * node_size as u64;
    let bytes = vol.read_fork(fork, at, node_size)?.bytes;
    let f_link = be_u32(&bytes, 0)?;
    let node_kind = i8::from_be_bytes([bytes[8]]);
    let height = bytes[9];
    let count = usize::from(be_u16(&bytes, 10)?);
    if !matches!(node_kind, LEAF_NODE | INDEX_NODE | HEADER_NODE | MAP_NODE) {
        return Err(error(format!(
            "Invalid {name} B-tree node {number}: kind {node_kind}"
        )));
    }
    // numRecords + 1 offsets at the node end, in reverse order: the first
    // record starts after the descriptor, each record ends where the next
    // starts, and the last offset is the start of free space, before the
    // offsets themselves ([TN1150] "Node Structure").
    let table = 2 * (count + 1);
    if NODE_DESCRIPTOR_SIZE + table > node_size {
        return Err(error(format!(
            "Invalid {name} B-tree node {number}: {count} records do not fit"
        )));
    }
    let mut offsets = Vec::with_capacity(count + 1);
    for i in 0..=count {
        offsets.push(usize::from(be_u16(&bytes, node_size - 2 * (i + 1))?));
    }
    let ordered = offsets[0] == NODE_DESCRIPTOR_SIZE
        && offsets.windows(2).all(|w| w[0] < w[1])
        && offsets[count] <= node_size - table;
    if !ordered {
        return Err(error(format!(
            "Invalid {name} B-tree node {number}: record offsets out of order"
        )));
    }
    Ok(Node {
        number,
        bytes,
        f_link,
        kind: node_kind,
        height,
        offsets,
    })
}

/// An extent key, ordered as the extents overflow B-tree orders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ExtentKey {
    file_id: u32,
    fork_type: u8,
    start_block: u32,
}

impl ExtentKey {
    fn parse(key: &[u8]) -> Result<Self> {
        if key.len() < EXTENT_KEY_LENGTH {
            return Err(error(format!(
                "Invalid extents overflow key of {} B",
                key.len()
            )));
        }
        Ok(Self {
            file_id: be_u32(key, 2)?,
            fork_type: key[0],
            start_block: be_u32(key, 6)?,
        })
    }
}

impl<'a> Cursor<'a> {
    /// The next leaf record in key order, following `fLink` from one leaf
    /// to the next. Each leaf is read once; the next one must be a leaf.
    pub(super) fn next(&mut self, tree: &BTree, vol: &Volume<'a>) -> Result<Option<Record<'_>>> {
        while self.index >= self.node.record_count() {
            let next = self.node.f_link;
            if next == 0 {
                return Ok(None);
            }
            if !self.visited.insert(next) {
                return Err(error(format!(
                    "Invalid {} B-tree: the leaf chain returns to node {next}",
                    tree.kind.name()
                )));
            }
            let node = tree.node(vol, next)?;
            if node.kind != LEAF_NODE || node.height != 1 {
                return Err(error(format!(
                    "Invalid {} B-tree node {next}: kind {} height {} in the leaf chain",
                    tree.kind.name(),
                    node.kind,
                    node.height
                )));
            }
            self.node = node;
            self.index = 0;
        }
        let index = self.index;
        self.index += 1;
        tree.record(&self.node, index).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_keys_order_by_file_then_fork_then_block() {
        let key = |file_id, fork_type, start_block| ExtentKey {
            file_id,
            fork_type,
            start_block,
        };
        assert!(key(16, RESOURCE_FORK, 0) < key(17, DATA_FORK, 0));
        assert!(key(16, DATA_FORK, 100) < key(16, RESOURCE_FORK, 0));
        assert!(key(16, DATA_FORK, 8) < key(16, DATA_FORK, 13));
        let raw = [0xff, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x08];
        assert_eq!(ExtentKey::parse(&raw).unwrap(), key(16, RESOURCE_FORK, 8));
    }
}
