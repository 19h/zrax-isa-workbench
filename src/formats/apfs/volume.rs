//! Volume superblocks `apfs_superblock_t` ([REF] "Volumes"): name, role,
//! flags, features, object map and file-system tree identifiers, and the
//! counts the superblock keeps.

use super::*;

/// `APFS_MAGIC` (`'BSPA'`), which reads `APSB` on disk.
const APFS_MAGIC: &[u8; 4] = b"APSB";

/// `apfs_superblock_t` field offsets ([REF]; checked against [LIBFS]
/// `fsapfs_volume_superblock.h`): index (36), incompatible features (56),
/// root tree type (116), object map (128), root tree (136), counts of
/// files, directories, symlinks and snapshots (184, 192, 200, 216), flags
/// (264), name (704, 256 B), role (964), integrity metadata (1024), file
/// extent tree (1032).
const APFS_FS_INDEX: usize = 36;
const APFS_INCOMPATIBLE_FEATURES: usize = 56;
const APFS_ROOT_TREE_TYPE: usize = 116;
const APFS_OMAP_OID: usize = 128;
const APFS_ROOT_TREE_OID: usize = 136;
const APFS_NUM_FILES: usize = 184;
const APFS_NUM_DIRECTORIES: usize = 192;
const APFS_NUM_SYMLINKS: usize = 200;
const APFS_NUM_SNAPSHOTS: usize = 216;
const APFS_FS_FLAGS: usize = 264;
const APFS_VOLNAME: usize = 704;
const APFS_VOLNAME_LEN: usize = 256;
const APFS_ROLE: usize = 964;
const APFS_INTEGRITY_META_OID: usize = 1024;
const APFS_FEXT_TREE_OID: usize = 1032;

/// `APFS_FS_UNENCRYPTED` in `apfs_fs_flags`.
const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;

/// Incompatible volume features ([REF] "Incompatible Volume Feature
/// Flags").
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x0000_0001;
const APFS_INCOMPAT_DATALESS_SNAPS: u64 = 0x0000_0002;
const APFS_INCOMPAT_ENC_ROLLED: u64 = 0x0000_0004;
const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x0000_0008;
const APFS_INCOMPAT_INCOMPLETE_RESTORE: u64 = 0x0000_0010;
const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x0000_0020;

/// The incompatible features the walk reads volumes with.
const READABLE_INCOMPAT: u64 = APFS_INCOMPAT_CASE_INSENSITIVE
    | APFS_INCOMPAT_DATALESS_SNAPS
    | APFS_INCOMPAT_ENC_ROLLED
    | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE
    | APFS_INCOMPAT_INCOMPLETE_RESTORE;

/// `APFS_VOLUME_ENUM_SHIFT`: roles above the six single-bit roles are
/// numbered in the bits from 6.
const APFS_VOLUME_ENUM_SHIFT: u16 = 6;

/// Volume roles ([REF] "Volume Roles"): the single-bit roles, then the
/// enumerated ones by number.
const SINGLE_BIT_ROLES: [(u16, &str); 6] = [
    (0x0001, "system"),
    (0x0002, "user"),
    (0x0004, "recovery"),
    (0x0008, "VM"),
    (0x0010, "preboot"),
    (0x0020, "installer"),
];
const ENUMERATED_ROLES: [(u16, &str); 8] = [
    (1, "data"),
    (2, "baseband"),
    (3, "update"),
    (4, "xART"),
    (5, "hardware"),
    (6, "backup"),
    (9, "enterprise"),
    (11, "prelogin"),
];

/// A volume superblock.
#[derive(Debug, Clone)]
pub(super) struct VolumeSuperblock {
    /// Block of the superblock.
    pub(super) paddr: u64,
    /// `o_xid`: the transaction of the volume's object map lookups.
    pub(super) xid: u64,
    /// `apfs_fs_index`.
    pub(super) fs_index: u32,
    incompatible: u64,
    fs_flags: u64,
    role: u16,
    /// `apfs_volname`.
    pub(super) name: String,
    /// `apfs_omap_oid` (physical).
    pub(super) omap_oid: u64,
    /// `apfs_root_tree_oid`.
    pub(super) root_tree_oid: u64,
    /// `apfs_root_tree_type`.
    root_tree_type: u32,
    num_files: u64,
    num_directories: u64,
    num_symlinks: u64,
    num_snapshots: u64,
    integrity_meta_oid: u64,
    fext_tree_oid: u64,
}

impl VolumeSuperblock {
    /// The superblock of virtual object `oid` in block `paddr`.
    pub(super) fn read(disk: &Disk<'_>, paddr: u64, oid: u64) -> Result<Self> {
        let object = disk.object(paddr, oid)?;
        let bytes = object.bytes;
        if object.header.kind() != OBJECT_TYPE_FS || slice(bytes, NX_MAGIC_OFFSET, 4)? != APFS_MAGIC
        {
            return Err(error(format!(
                "Invalid volume superblock in block 0x{paddr:X}: type 0x{:X}",
                object.header.object_type
            )));
        }
        Ok(Self {
            paddr,
            xid: object.header.xid,
            fs_index: le_u32(bytes, APFS_FS_INDEX)?,
            incompatible: le_u64(bytes, APFS_INCOMPATIBLE_FEATURES)?,
            fs_flags: le_u64(bytes, APFS_FS_FLAGS)?,
            role: le_u16(bytes, APFS_ROLE)?,
            name: records::name_text(slice(bytes, APFS_VOLNAME, APFS_VOLNAME_LEN)?),
            omap_oid: le_u64(bytes, APFS_OMAP_OID)?,
            root_tree_oid: le_u64(bytes, APFS_ROOT_TREE_OID)?,
            root_tree_type: le_u32(bytes, APFS_ROOT_TREE_TYPE)?,
            num_files: le_u64(bytes, APFS_NUM_FILES)?,
            num_directories: le_u64(bytes, APFS_NUM_DIRECTORIES)?,
            num_symlinks: le_u64(bytes, APFS_NUM_SYMLINKS)?,
            num_snapshots: le_u64(bytes, APFS_NUM_SNAPSHOTS)?,
            integrity_meta_oid: le_u64(bytes, APFS_INTEGRITY_META_OID)?,
            fext_tree_oid: le_u64(bytes, APFS_FEXT_TREE_OID)?,
        })
    }

    /// `APFS_FS_UNENCRYPTED` is clear: the file-system tree and the file
    /// contents are encrypted ([REF] "Encryption").
    pub(super) fn is_encrypted(&self) -> bool {
        self.fs_flags & APFS_FS_UNENCRYPTED == 0
    }

    /// A sealed volume keeps its file extents in the file extent tree.
    pub(super) fn is_sealed(&self) -> bool {
        self.incompatible & APFS_INCOMPAT_SEALED_VOLUME != 0
            || self.integrity_meta_oid != 0
            || self.fext_tree_oid != 0
    }

    /// Incompatible features the walk does not know.
    pub(super) fn unknown_incompatible(&self) -> u64 {
        self.incompatible & !(READABLE_INCOMPAT | APFS_INCOMPAT_SEALED_VOLUME)
    }

    /// Directory entry keys are hashed on case- or normalization-
    /// insensitive volumes ([FUSE] `ApfsDir`).
    pub(super) fn has_hashed_names(&self) -> bool {
        self.incompatible
            & (APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE)
            != 0
    }

    /// Whether the root tree identifier is a block address rather than a
    /// virtual identifier.
    pub(super) fn has_physical_root(&self) -> bool {
        self.root_tree_type & OBJ_STORAGETYPE_MASK == OBJ_PHYSICAL
    }

    /// The number of snapshots the superblock counts.
    pub(super) fn snapshots(&self) -> u64 {
        self.num_snapshots
    }

    /// The role's name, or its number when it has none.
    pub(super) fn role_text(&self) -> String {
        if self.role == 0 {
            return "none".into();
        }
        if let Some((_, name)) = SINGLE_BIT_ROLES.iter().find(|(bit, _)| *bit == self.role) {
            return (*name).to_string();
        }
        let number = self.role >> APFS_VOLUME_ENUM_SHIFT;
        let enumerated = self.role & ((1 << APFS_VOLUME_ENUM_SHIFT) - 1) == 0;
        match ENUMERATED_ROLES.iter().find(|(n, _)| *n == number) {
            Some((_, name)) if enumerated => (*name).to_string(),
            _ => format!("0x{:X}", self.role),
        }
    }

    /// The volume's name rules.
    pub(super) fn case_text(&self) -> &'static str {
        if self.incompatible & APFS_INCOMPAT_CASE_INSENSITIVE != 0 {
            "case-insensitive"
        } else {
            "case-sensitive"
        }
    }

    /// The counts the superblock keeps, for the volume note.
    pub(super) fn counts_text(&self) -> String {
        format!(
            "{}, {}, {} (superblock counts)",
            counted(
                usize::try_from(self.num_files).unwrap_or(usize::MAX),
                "file",
                "files"
            ),
            counted(
                usize::try_from(self.num_directories).unwrap_or(usize::MAX),
                "directory",
                "directories"
            ),
            counted(
                usize::try_from(self.num_symlinks).unwrap_or(usize::MAX),
                "symbolic link",
                "symbolic links"
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(role: u16) -> VolumeSuperblock {
        VolumeSuperblock {
            paddr: 0,
            xid: 1,
            fs_index: 0,
            incompatible: 0,
            fs_flags: APFS_FS_UNENCRYPTED,
            role,
            name: String::new(),
            omap_oid: 0,
            root_tree_oid: 0,
            root_tree_type: 0,
            num_files: 0,
            num_directories: 0,
            num_symlinks: 0,
            num_snapshots: 0,
            integrity_meta_oid: 0,
            fext_tree_oid: 0,
        }
    }

    #[test]
    fn roles_are_named_by_bit_or_number() {
        assert_eq!(volume(0).role_text(), "none");
        assert_eq!(volume(0x0001).role_text(), "system");
        assert_eq!(volume(1 << 6).role_text(), "data");
        assert_eq!(volume(11 << 6).role_text(), "prelogin");
        assert_eq!(volume(7 << 6).role_text(), "0x1C0");
        assert_eq!(volume(0x0041).role_text(), "0x41");
    }

    #[test]
    fn flags_decide_encryption_and_name_hashing() {
        let mut v = volume(0);
        assert!(!v.is_encrypted());
        assert!(!v.has_hashed_names());
        v.fs_flags = 0x8;
        v.incompatible = APFS_INCOMPAT_NORMALIZATION_INSENSITIVE;
        assert!(v.is_encrypted());
        assert!(v.has_hashed_names());
        assert_eq!(v.case_text(), "case-sensitive");
        v.incompatible |= 0x80;
        assert_eq!(v.unknown_incompatible(), 0x80);
    }
}
