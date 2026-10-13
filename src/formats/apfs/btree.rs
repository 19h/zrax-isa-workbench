//! B-trees ([REF] "B-Trees"): nodes with a table of contents of variable
//! (`kvloc_t`) or fixed (`kvoff_t`) entries, the tree information in the
//! root node, and a cursor that seeks from the root (nodes have no parent
//! or sibling links) and walks the leaves in key order. Child nodes are
//! physical blocks or virtual objects resolved through an object map.
//!
//! Traversal is bounded: every node read counts against the disk's object
//! budget, a tree has at most [`MAX_TREE_LEVELS`] levels, each child must
//! be exactly one level below its parent (so a descent cannot cycle), and
//! the leaves must yield their keys in ascending order.

use super::object::Object;
use super::omap::Omap;
use super::*;

/// `btree_node_phys_t`: flags (32), level (34), key count (36), table of
/// contents location (40, offset and length), then `btn_data` (56).
const BTN_FLAGS: usize = 32;
const BTN_LEVEL: usize = 34;
const BTN_NKEYS: usize = 36;
const BTN_TABLE_SPACE: usize = 40;
const BTN_DATA: usize = 56;

/// `btree_info_t` at the end of a root node: `bt_flags`, `bt_node_size`,
/// `bt_key_size`, `bt_val_size`, `bt_longest_key`, `bt_longest_val` (4 B
/// each), `bt_key_count`, `bt_node_count` (8 B each).
const BTREE_INFO_SIZE: usize = 40;

/// Node flags ([REF] "B-Tree Node Flags").
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;
const BTNODE_HASHED: u16 = 0x0008;
const BTNODE_NOHEADER: u16 = 0x0010;

/// Tree flags ([REF] "B-Tree Flags").
const BTREE_EPHEMERAL: u32 = 0x0000_0008;
const BTREE_PHYSICAL: u32 = 0x0000_0010;
const BTREE_HASHED: u32 = 0x0000_0080;
const BTREE_NOHEADER: u32 = 0x0000_0100;

/// `BTOFF_INVALID`: a value offset of a ghost entry, which has no value.
const BTOFF_INVALID: u16 = 0xffff;

/// Table of contents entries: `kvloc_t` (8 B) or `kvoff_t` (4 B).
const KVLOC_SIZE: usize = 8;
const KVOFF_SIZE: usize = 4;

/// The value of an index entry is the child's object identifier.
const CHILD_OID_SIZE: usize = 8;

/// Most levels a tree may have. The bound is ours; with 4 KiB nodes even
/// a few levels hold more records than a container has room for.
const MAX_TREE_LEVELS: u16 = 16;

/// How virtual child (or root) identifiers are resolved: through `omap` as
/// of transaction `xid`.
#[derive(Clone, Copy)]
pub(super) struct Lookup<'o> {
    pub(super) omap: &'o Omap,
    pub(super) xid: u64,
}

/// `btree_info_t`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Info {
    pub(super) flags: u32,
    pub(super) node_size: u32,
    /// Key size of fixed-size entries, 0 when keys vary.
    pub(super) key_size: u32,
    /// Value size of fixed-size leaf entries, 0 when values vary.
    pub(super) value_size: u32,
    pub(super) key_count: u64,
    pub(super) node_count: u64,
}

/// An open B-tree: its root and its information.
#[derive(Debug)]
pub(super) struct Tree {
    /// Block of the root node.
    root_paddr: u64,
    /// Object identifier of the root node.
    root_oid: u64,
    /// `o_subtype` of every node: what the records are.
    subtype: u32,
    pub(super) info: Info,
    /// The root's level: the tree has `levels + 1` levels.
    pub(super) levels: u16,
    /// Whether child identifiers are virtual (resolved through an object
    /// map) rather than block addresses.
    virtual_children: bool,
}

/// A node read from one block.
#[derive(Debug, Clone, Copy)]
struct Node<'a> {
    object: Object<'a>,
    flags: u16,
    level: u16,
    count: usize,
    /// Offset of the table of contents in the node.
    toc: usize,
    /// Offset of the key area in the node.
    key_start: usize,
    /// End of the value area: the node end, or the start of the tree
    /// information in a root node.
    value_end: usize,
}

/// A record of a node.
#[derive(Debug, Clone, Copy)]
pub(super) struct Record<'a> {
    pub(super) key: &'a [u8],
    /// The value; `None` for a ghost.
    pub(super) value: Option<&'a [u8]>,
    /// File offset of the value (or of the value area's end for a ghost).
    pub(super) value_offset: usize,
}

/// A node on the cursor's path and the next entry to visit in it.
#[derive(Debug)]
struct Position<'a> {
    node: Node<'a>,
    next: usize,
}

/// A cursor over the leaf records from a seek position.
#[derive(Debug)]
pub(super) struct Cursor<'a> {
    path: Vec<Position<'a>>,
    /// Sort key of the last record returned, to check the order.
    last: Option<SortKey>,
}

/// Where a table of contents entry puts its key and value.
#[derive(Debug, Clone, Copy)]
struct Location {
    /// Key offset from the start of the key area.
    key_offset: u16,
    key_length: usize,
    /// Value offset back from the end of the value area, or
    /// `BTOFF_INVALID`.
    value_offset: u16,
    value_length: usize,
}

/// The leading part of a record's key that every tree sorts by first
/// ([REF] "Key Comparison"): the object identifier and transaction of an
/// object map key, or the object identifier and record type of a
/// file-system key. Names and logical addresses sort after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SortKey {
    major: u64,
    minor: u64,
}

impl SortKey {
    fn of(subtype: u32, key: &[u8]) -> Result<Self> {
        if subtype == OBJECT_TYPE_OMAP {
            return Ok(Self {
                major: le_u64(key, 0)?,
                minor: le_u64(key, 8)?,
            });
        }
        let header = le_u64(key, 0)?;
        Ok(Self {
            major: header & records::OBJ_ID_MASK,
            minor: header >> records::OBJ_TYPE_SHIFT,
        })
    }
}

impl Tree {
    /// Open the tree whose root has identifier `root_oid`: a block address,
    /// or a virtual identifier resolved through `root_lookup`.
    pub(super) fn open(
        disk: &Disk<'_>,
        root_oid: u64,
        subtype: u32,
        root_lookup: Option<Lookup<'_>>,
    ) -> Result<Self> {
        let root_paddr = match root_lookup {
            Some(lookup) => lookup.omap.resolve(disk, root_oid, lookup.xid)?,
            None => root_oid,
        };
        let object = disk.object(root_paddr, root_oid)?;
        if object.header.kind() != OBJECT_TYPE_BTREE || object.header.subtype != subtype {
            return Err(error(format!(
                "Invalid B-tree root in block 0x{root_paddr:X}: type 0x{:X}, subtype 0x{:X}",
                object.header.object_type, object.header.subtype
            )));
        }
        let bytes = object.bytes;
        let info_at = bytes.len() - BTREE_INFO_SIZE;
        let info = Info {
            flags: le_u32(bytes, info_at)?,
            node_size: le_u32(bytes, info_at + 4)?,
            key_size: le_u32(bytes, info_at + 8)?,
            value_size: le_u32(bytes, info_at + 12)?,
            key_count: le_u64(bytes, info_at + 24)?,
            node_count: le_u64(bytes, info_at + 32)?,
        };
        if info.node_size as usize != disk.block_size() {
            return Err(error(format!(
                "Unsupported B-tree node size of {} B in blocks of {}",
                info.node_size,
                size_text(disk.block_size())
            )));
        }
        if info.flags & (BTREE_HASHED | BTREE_NOHEADER | BTREE_EPHEMERAL) != 0 {
            return Err(error(format!(
                "Unsupported B-tree flags 0x{:X} (hashed, headerless or ephemeral)",
                info.flags
            )));
        }
        let virtual_children = info.flags & BTREE_PHYSICAL == 0;
        if virtual_children && root_lookup.is_none() {
            return Err(error(
                "Unsupported B-tree: virtual child nodes without an object map",
            ));
        }
        let tree = Self {
            root_paddr,
            root_oid,
            subtype,
            info,
            levels: 0,
            virtual_children,
        };
        let root = tree.node(object, None)?;
        if root.level >= MAX_TREE_LEVELS {
            return Err(error(format!(
                "Unsupported B-tree of {} levels (at most {MAX_TREE_LEVELS})",
                root.level + 1
            )));
        }
        Ok(Self {
            levels: root.level,
            ..tree
        })
    }

    /// Check the node header of `object` and locate its areas. `level` is
    /// the level a child must have; `None` for the root.
    fn node<'a>(&self, object: Object<'a>, level: Option<u16>) -> Result<Node<'a>> {
        let bytes = object.bytes;
        let paddr = object.paddr;
        let is_root = level.is_none();
        let expected_kind = if is_root {
            OBJECT_TYPE_BTREE
        } else {
            OBJECT_TYPE_BTREE_NODE
        };
        if object.header.kind() != expected_kind || object.header.subtype != self.subtype {
            return Err(error(format!(
                "Invalid B-tree node in block 0x{paddr:X}: type 0x{:X}, subtype 0x{:X}",
                object.header.object_type, object.header.subtype
            )));
        }
        let flags = le_u16(bytes, BTN_FLAGS)?;
        let node_level = le_u16(bytes, BTN_LEVEL)?;
        if level.is_some_and(|expected| expected != node_level) {
            return Err(error(format!(
                "Invalid B-tree node in block 0x{paddr:X}: level {node_level}, {} expected",
                level.unwrap_or_default()
            )));
        }
        let is_leaf = node_level == 0;
        if (flags & BTNODE_ROOT != 0) != is_root || (flags & BTNODE_LEAF != 0) != is_leaf {
            return Err(error(format!(
                "Invalid B-tree node flags 0x{flags:X} in block 0x{paddr:X} at level \
                 {node_level}"
            )));
        }
        if flags & (BTNODE_HASHED | BTNODE_NOHEADER) != 0 {
            return Err(error(format!(
                "Unsupported B-tree node flags 0x{flags:X} in block 0x{paddr:X}"
            )));
        }
        let count = le_u32(bytes, BTN_NKEYS)? as usize;
        let table_offset = usize::from(le_u16(bytes, BTN_TABLE_SPACE)?);
        let table_length = usize::from(le_u16(bytes, BTN_TABLE_SPACE + 2)?);
        let toc = BTN_DATA + table_offset;
        let key_start = toc + table_length;
        let value_end = if is_root {
            bytes.len() - BTREE_INFO_SIZE
        } else {
            bytes.len()
        };
        let entry_size = if flags & BTNODE_FIXED_KV_SIZE != 0 {
            KVOFF_SIZE
        } else {
            KVLOC_SIZE
        };
        let fits = count
            .checked_mul(entry_size)
            .is_some_and(|size| size <= table_length);
        if key_start > value_end || !fits {
            return Err(error(format!(
                "Invalid B-tree node in block 0x{paddr:X}: {count} entries in a table of \
                 {table_length} B at 0x{toc:X}"
            )));
        }
        let node = Node {
            object,
            flags,
            level: node_level,
            count,
            toc,
            key_start,
            value_end,
        };
        self.check_key_order(&node)?;
        Ok(node)
    }

    /// Every key of `node` must lie in the node, and the keys must not
    /// decrease, so that a seek can stop at the first key past its target.
    fn check_key_order(&self, node: &Node<'_>) -> Result<()> {
        let mut last: Option<SortKey> = None;
        for index in 0..node.count {
            let key = self.key(node, index)?;
            let sort_key = SortKey::of(self.subtype, key)?;
            if last.is_some_and(|last| sort_key < last) {
                return Err(error(format!(
                    "Invalid B-tree: keys out of order in block 0x{:X}",
                    node.object.paddr
                )));
            }
            last = Some(sort_key);
        }
        Ok(())
    }

    /// Read child `oid` of a node at level `level + 1`.
    fn child<'a>(
        &self,
        disk: &Disk<'a>,
        lookup: Option<Lookup<'_>>,
        oid: u64,
        level: u16,
    ) -> Result<Node<'a>> {
        let paddr = if self.virtual_children {
            let lookup = lookup.ok_or_else(|| {
                error("Unsupported B-tree: virtual child nodes without an object map")
            })?;
            lookup.omap.resolve(disk, oid, lookup.xid)?
        } else {
            oid
        };
        let object = disk.object(paddr, oid)?;
        self.node(object, Some(level))
    }

    /// The root node.
    fn root<'a>(&self, disk: &Disk<'a>) -> Result<Node<'a>> {
        let object = disk.object(self.root_paddr, self.root_oid)?;
        self.node(object, None)
    }

    /// The table of contents entry `index` of `node`: a `kvoff_t` whose
    /// lengths are the tree's fixed sizes (a child identifier for index
    /// values), or a `kvloc_t` with its own lengths.
    fn location(&self, node: &Node<'_>, index: usize) -> Result<Location> {
        let bytes = node.object.bytes;
        if node.flags & BTNODE_FIXED_KV_SIZE != 0 {
            let at = node.toc + KVOFF_SIZE * index;
            let value_length = if node.level == 0 {
                self.info.value_size as usize
            } else {
                CHILD_OID_SIZE
            };
            return Ok(Location {
                key_offset: le_u16(bytes, at)?,
                key_length: self.info.key_size as usize,
                value_offset: le_u16(bytes, at + 2)?,
                value_length,
            });
        }
        let at = node.toc + KVLOC_SIZE * index;
        Ok(Location {
            key_offset: le_u16(bytes, at)?,
            key_length: usize::from(le_u16(bytes, at + 2)?),
            value_offset: le_u16(bytes, at + 4)?,
            value_length: usize::from(le_u16(bytes, at + 6)?),
        })
    }

    /// The key of entry `index` of `node`.
    fn key<'a>(&self, node: &Node<'a>, index: usize) -> Result<&'a [u8]> {
        let location = self.location(node, index)?;
        Self::key_in(node, index, &location)
    }

    /// The key that `location` (entry `index`) places in the key area,
    /// which must end before the value area does.
    fn key_in<'a>(node: &Node<'a>, index: usize, location: &Location) -> Result<&'a [u8]> {
        let key_at = node.key_start + usize::from(location.key_offset);
        let key_end = key_at + location.key_length;
        node.object
            .bytes
            .get(key_at..key_end)
            .filter(|_| key_end <= node.value_end)
            .ok_or_else(|| {
                error(format!(
                    "Invalid B-tree entry {index} in block 0x{:X}: key at 0x{key_at:X} + {} B",
                    node.object.paddr, location.key_length
                ))
            })
    }

    /// Entry `index` of `node`.
    fn record<'a>(&self, disk: &Disk<'a>, node: &Node<'a>, index: usize) -> Result<Record<'a>> {
        let bytes = node.object.bytes;
        let paddr = node.object.paddr;
        let location = self.location(node, index)?;
        let key = Self::key_in(node, index, &location)?;
        let Location {
            value_offset,
            value_length,
            ..
        } = location;
        let base = disk.file_offset(paddr);
        if value_offset == BTOFF_INVALID {
            return Ok(Record {
                key,
                value: None,
                value_offset: base + node.value_end,
            });
        }
        let value_at = node
            .value_end
            .checked_sub(usize::from(value_offset))
            .filter(|&at| at >= node.key_start && at + value_length <= node.value_end)
            .ok_or_else(|| {
                error(format!(
                    "Invalid B-tree entry {index} in block 0x{paddr:X}: value offset \
                     0x{value_offset:X} + {value_length} B"
                ))
            })?;
        Ok(Record {
            key,
            value: Some(&bytes[value_at..value_at + value_length]),
            value_offset: base + value_at,
        })
    }

    /// The child identifier stored in index entry `index`.
    fn child_oid(&self, disk: &Disk<'_>, node: &Node<'_>, index: usize) -> Result<u64> {
        let record = self.record(disk, node, index)?;
        let value = record.value.ok_or_else(|| {
            error(format!(
                "Invalid B-tree index entry {index} in block 0x{:X}: no child",
                node.object.paddr
            ))
        })?;
        le_u64(value, 0)
    }

    /// A cursor at the first leaf record for which `is_before` is false.
    /// `is_before` must be true for a prefix of the keys in order and false
    /// for the rest.
    pub(super) fn seek<'a>(
        &self,
        disk: &Disk<'a>,
        lookup: Option<Lookup<'_>>,
        is_before: &dyn Fn(&[u8]) -> Result<bool>,
    ) -> Result<Cursor<'a>> {
        let mut path = Vec::new();
        let mut node = self.root(disk)?;
        loop {
            if node.level > 0 && node.count == 0 {
                return Err(error(format!(
                    "Invalid B-tree: empty index node in block 0x{:X}",
                    node.object.paddr
                )));
            }
            let mut first_after = node.count;
            for index in 0..node.count {
                let record = self.record(disk, &node, index)?;
                if !is_before(record.key)? {
                    first_after = index;
                    break;
                }
            }
            if node.level == 0 {
                path.push(Position {
                    node,
                    next: first_after,
                });
                break;
            }
            // The last child whose first key is before the target holds the
            // first record that is not; with none, the first child does.
            let index = first_after.saturating_sub(1);
            let oid = self.child_oid(disk, &node, index)?;
            let level = node.level - 1;
            path.push(Position {
                node,
                next: index + 1,
            });
            node = self.child(disk, lookup, oid, level)?;
        }
        Ok(Cursor { path, last: None })
    }
}

impl<'a> Cursor<'a> {
    /// The next leaf record in key order, or `None` at the end of the tree.
    pub(super) fn next(
        &mut self,
        tree: &Tree,
        disk: &Disk<'a>,
        lookup: Option<Lookup<'_>>,
    ) -> Result<Option<Record<'a>>> {
        loop {
            let Some(top) = self.path.last_mut() else {
                return Ok(None);
            };
            if top.next >= top.node.count {
                self.path.pop();
                continue;
            }
            let index = top.next;
            top.next += 1;
            let node = top.node;
            if node.level == 0 {
                let record = tree.record(disk, &node, index)?;
                let key = SortKey::of(tree.subtype, record.key)?;
                if self.last.is_some_and(|last| key < last) {
                    return Err(error(format!(
                        "Invalid B-tree: keys out of order in block 0x{:X}",
                        node.object.paddr
                    )));
                }
                self.last = Some(key);
                return Ok(Some(record));
            }
            let oid = tree.child_oid(disk, &node, index)?;
            let child = tree.child(disk, lookup, oid, node.level - 1)?;
            self.path.push(Position {
                node: child,
                next: 0,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An object map key (`omap_key_t`: oid, xid).
    fn omap_key(oid: u64, xid: u64) -> Vec<u8> {
        let mut key = oid.to_le_bytes().to_vec();
        key.extend(xid.to_le_bytes());
        key
    }

    /// A `j_key_t` of `oid` and record type `kind`.
    fn fs_key(oid: u64, kind: u64) -> Vec<u8> {
        (oid | kind << records::OBJ_TYPE_SHIFT)
            .to_le_bytes()
            .to_vec()
    }

    #[test]
    fn object_map_keys_sort_by_identifier_then_transaction() {
        let of = |key: Vec<u8>| SortKey::of(OBJECT_TYPE_OMAP, &key).unwrap();
        assert!(of(omap_key(1026, 9)) < of(omap_key(1027, 1)));
        assert!(of(omap_key(1026, 1)) < of(omap_key(1026, 2)));
        assert!(SortKey::of(OBJECT_TYPE_OMAP, &[0; 15]).is_err());
    }

    #[test]
    fn file_system_keys_sort_by_object_then_record_type() {
        let of = |key: Vec<u8>| SortKey::of(OBJECT_TYPE_FSTREE, &key).unwrap();
        // The type in the top four bits does not outweigh the identifier.
        assert!(of(fs_key(2, 9)) < of(fs_key(3, 3)));
        assert!(of(fs_key(16, 3)) < of(fs_key(16, 8)));
        assert_eq!(of(fs_key(16, 9)), of(fs_key(16, 9)));
    }
}
