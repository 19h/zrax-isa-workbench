//! Object maps ([REF] "Object Maps"): `omap_phys_t` and its B-tree of
//! `omap_key_t` (object identifier, transaction) to `omap_val_t` (flags,
//! size, block address). A virtual object is found under the key with its
//! identifier and the largest transaction not after the one wanted.

use super::btree::Tree;
use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

/// `omap_phys_t`: flags (32), snapshot count (36), tree type (40),
/// snapshot tree type (44), tree identifier (48).
const OM_SNAP_COUNT: usize = 36;
const OM_TREE_TYPE: usize = 40;
const OM_TREE_OID: usize = 48;

/// `omap_val_t` flags ([REF] "Object Map Value Flags").
const OMAP_VAL_DELETED: u32 = 0x0000_0001;
const OMAP_VAL_ENCRYPTED: u32 = 0x0000_0004;
const OMAP_VAL_NOHEADER: u32 = 0x0000_0008;

/// `omap_key_t` and `omap_val_t` are 16 bytes each.
const OMAP_ENTRY_SIZE: usize = 16;

/// Most lookups remembered per object map. The bound is ours; a walk
/// resolves each node of a tree once per visit.
const MAX_CACHED_MAPPINGS: usize = 1 << 16;

/// An object map value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Mapping {
    /// `ov_flags`.
    pub(super) flags: u32,
    /// `ov_size` in bytes.
    pub(super) size: u32,
    /// `ov_paddr`: the object's block.
    pub(super) paddr: u64,
}

/// A lookup key: a virtual identifier as of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Version {
    oid: u64,
    xid: u64,
}

/// An open object map.
#[derive(Debug)]
pub(super) struct Omap {
    tree: Tree,
    /// `om_snap_count`.
    pub(super) snapshot_count: u32,
    cache: RefCell<HashMap<Version, Option<Mapping>>>,
}

impl Omap {
    /// The object map in block `paddr` (a physical object).
    pub(super) fn open(disk: &Disk<'_>, paddr: u64) -> Result<Self> {
        let object = disk.object(paddr, paddr)?;
        if object.header.kind() != OBJECT_TYPE_OMAP {
            return Err(error(format!(
                "Invalid object map in block 0x{paddr:X}: type 0x{:X}",
                object.header.object_type
            )));
        }
        let bytes = object.bytes;
        let tree_type = le_u32(bytes, OM_TREE_TYPE)?;
        if tree_type != OBJ_PHYSICAL | OBJECT_TYPE_BTREE {
            return Err(error(format!(
                "Unsupported object map tree type 0x{tree_type:X}"
            )));
        }
        let tree = Tree::open(disk, le_u64(bytes, OM_TREE_OID)?, OBJECT_TYPE_OMAP, None)?;
        let fixed = tree.info.key_size as usize == OMAP_ENTRY_SIZE
            && tree.info.value_size as usize == OMAP_ENTRY_SIZE;
        if !fixed {
            return Err(error(format!(
                "Invalid object map tree: keys of {} B and values of {} B",
                tree.info.key_size, tree.info.value_size
            )));
        }
        Ok(Self {
            tree,
            snapshot_count: le_u32(bytes, OM_SNAP_COUNT)?,
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// The mapping of `oid` as of transaction `xid`; `None` when there is
    /// none or the latest one marks the object deleted.
    pub(super) fn lookup(&self, disk: &Disk<'_>, oid: u64, xid: u64) -> Result<Option<Mapping>> {
        let version = Version { oid, xid };
        if let Some(cached) = self.cache.borrow().get(&version) {
            return Ok(*cached);
        }
        let found = self.search(disk, version)?;
        let mut cache = self.cache.borrow_mut();
        if cache.len() < MAX_CACHED_MAPPINGS {
            cache.insert(version, found);
        }
        Ok(found)
    }

    fn search(&self, disk: &Disk<'_>, version: Version) -> Result<Option<Mapping>> {
        let is_before = |key: &[u8]| -> Result<bool> { Ok(le_u64(key, 0)? < version.oid) };
        let mut cursor = self.tree.seek(disk, None, &is_before)?;
        let mut best: Option<Mapping> = None;
        while let Some(record) = cursor.next(&self.tree, disk, None)? {
            let oid = le_u64(record.key, 0)?;
            let xid = le_u64(record.key, 8)?;
            if oid != version.oid || xid > version.xid {
                break;
            }
            let Some(value) = record.value else {
                continue;
            };
            best = Some(Mapping {
                flags: le_u32(value, 0)?,
                size: le_u32(value, 4)?,
                paddr: le_u64(value, 8)?,
            });
        }
        Ok(best.filter(|mapping| mapping.flags & OMAP_VAL_DELETED == 0))
    }

    /// The block of virtual object `oid` as of `xid`, which must be mapped
    /// to one block holding an object with a header.
    pub(super) fn resolve(&self, disk: &Disk<'_>, oid: u64, xid: u64) -> Result<u64> {
        let mapping = self.lookup(disk, oid, xid)?.ok_or_else(|| {
            error(format!(
                "Missing object map entry for object 0x{oid:X} as of transaction {xid}"
            ))
        })?;
        if mapping.flags & OMAP_VAL_ENCRYPTED != 0 {
            return Err(error(format!("Unsupported encrypted object 0x{oid:X}")));
        }
        if mapping.flags & OMAP_VAL_NOHEADER != 0 {
            return Err(error(format!(
                "Unsupported object 0x{oid:X} stored without a header"
            )));
        }
        if mapping.size as usize != disk.block_size() {
            return Err(error(format!(
                "Unsupported object 0x{oid:X} of {} B in blocks of {}",
                mapping.size,
                size_text(disk.block_size())
            )));
        }
        Ok(mapping.paddr)
    }
}
