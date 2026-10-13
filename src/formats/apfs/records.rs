//! File-system records ([REF] "File-System Objects", "File-System
//! Constants", "Data Streams", "Extended Fields"): the `j_key_t` header,
//! inodes and their data stream size, directory entries (hashed and plain
//! keys), extended attributes (embedded or in a data stream) and file
//! extents.

use super::*;

/// `OBJ_ID_MASK` and `OBJ_TYPE_SHIFT` of `j_key_t.obj_id_and_type`.
pub(super) const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
pub(super) const OBJ_TYPE_SHIFT: u32 = 60;

/// Record types (`j_obj_types`).
pub(super) const APFS_TYPE_INODE: u64 = 3;
pub(super) const APFS_TYPE_XATTR: u64 = 4;
pub(super) const APFS_TYPE_FILE_EXTENT: u64 = 8;
pub(super) const APFS_TYPE_DIR_REC: u64 = 9;

/// The `j_key_t` header that starts every key.
const J_KEY_SIZE: usize = 8;

/// `j_inode_val_t` fields: `parent_id` (0), `private_id` (8),
/// `internal_flags` (48), `nlink` (56), `bsd_flags` (68), `mode` (80),
/// then the extended fields (92).
const INODE_PRIVATE_ID: usize = 8;
const INODE_BSD_FLAGS: usize = 68;
const INODE_MODE: usize = 80;
const INODE_XFIELDS: usize = 92;

/// `xf_blob_t` (`xf_num_exts`, `xf_used_data`) and `x_field_t` (`x_type`,
/// `x_flags`, `x_size`) sizes; field data is padded to 8 bytes.
const XF_BLOB_SIZE: usize = 4;
const X_FIELD_SIZE: usize = 4;
const XF_DATA_ALIGNMENT: usize = 8;

/// `INO_EXT_TYPE_DSTREAM`: the inode's `j_dstream_t`, whose first field is
/// the data size.
const INO_EXT_TYPE_DSTREAM: u8 = 8;

/// `j_dstream_t` is five 64-bit fields.
const J_DSTREAM_SIZE: usize = 40;

/// `j_drec_val_t`: `file_id` (0), `date_added` (8), `flags` (16).
const DREC_FILE_ID: usize = 0;
const DREC_FLAGS: usize = 16;
const DREC_VALUE_SIZE: usize = 18;

/// `DREC_TYPE_MASK` of the directory entry flags.
const DREC_TYPE_MASK: u16 = 0x000f;

/// `J_DREC_LEN_MASK` of `name_len_and_hash`.
const J_DREC_LEN_MASK: u32 = 0x0000_03ff;

/// `j_xattr_val_t`: `flags` (0), `xdata_len` (2), `xdata` (4).
const XATTR_FLAGS: usize = 0;
const XATTR_DATA_LENGTH: usize = 2;
const XATTR_DATA: usize = 4;

/// `j_xattr_flags`.
const XATTR_DATA_STREAM: u16 = 0x0001;
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

/// `j_xattr_dstream_t`: `xattr_obj_id` (0), then `j_dstream_t` whose
/// `size` is at 8.
const XATTR_STREAM_ID: usize = 0;
const XATTR_STREAM_SIZE: usize = 8;

/// `j_file_extent_key_t.logical_addr` (after the header) and
/// `j_file_extent_val_t`: `len_and_flags` (0), `phys_block_num` (8).
const EXTENT_LOGICAL: usize = 8;
const EXTENT_LENGTH: usize = 0;
const EXTENT_BLOCK: usize = 8;

/// `J_FILE_EXTENT_LEN_MASK`: the extent length in bytes.
const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

/// File types of directory entries (`DT_*`, [REF] "Directory Entry File
/// Types").
pub(super) const DT_UNKNOWN: u8 = 0;
pub(super) const DT_DIR: u8 = 4;
pub(super) const DT_REG: u8 = 8;
pub(super) const DT_LNK: u8 = 10;

/// File modes (`S_IFMT` and the file types, [REF] "File Modes").
pub(super) const S_IFMT: u16 = 0o170_000;
pub(super) const S_IFDIR: u16 = 0o040_000;
pub(super) const S_IFREG: u16 = 0o100_000;
pub(super) const S_IFLNK: u16 = 0o120_000;

/// The `j_key_t` header of a record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeyHeader {
    /// Object identifier (`obj_id_and_type & OBJ_ID_MASK`).
    pub(super) oid: u64,
    /// Record type (the top four bits).
    pub(super) kind: u64,
}

impl KeyHeader {
    pub(super) fn parse(key: &[u8]) -> Result<Self> {
        let header = le_u64(key, 0)?;
        Ok(Self {
            oid: header & OBJ_ID_MASK,
            kind: header >> OBJ_TYPE_SHIFT,
        })
    }
}

/// Whether a key's (object, type) sorts before `(oid, kind)`: the seek
/// predicate for the first record of that object and type.
pub(super) fn is_before(key: &[u8], oid: u64, kind: u64) -> Result<bool> {
    let header = KeyHeader::parse(key)?;
    Ok((header.oid, header.kind) < (oid, kind))
}

/// An inode record (`j_inode_val_t`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Inode {
    /// The data stream identifier that file extents are keyed by.
    pub(super) private_id: u64,
    /// `bsd_flags` (`UF_COMPRESSED` marks decmpfs files).
    pub(super) bsd_flags: u32,
    /// `mode`.
    pub(super) mode: u16,
    /// The data size from the `INO_EXT_TYPE_DSTREAM` field; 0 without one.
    pub(super) size: u64,
}

impl Inode {
    pub(super) fn parse(value: &[u8]) -> Result<Self> {
        if value.len() < INODE_XFIELDS {
            return Err(error(format!("Invalid inode record of {} B", value.len())));
        }
        Ok(Self {
            private_id: le_u64(value, INODE_PRIVATE_ID)?,
            bsd_flags: le_u32(value, INODE_BSD_FLAGS)?,
            mode: le_u16(value, INODE_MODE)?,
            size: dstream_size(&value[INODE_XFIELDS..])?,
        })
    }

    pub(super) fn file_type(&self) -> u16 {
        self.mode & S_IFMT
    }
}

/// The size in the `INO_EXT_TYPE_DSTREAM` extended field of `xfields`, or
/// 0 when there is none.
fn dstream_size(xfields: &[u8]) -> Result<u64> {
    if xfields.is_empty() {
        return Ok(0);
    }
    let count = usize::from(le_u16(xfields, 0)?);
    let mut data_at = XF_BLOB_SIZE + X_FIELD_SIZE * count;
    for i in 0..count {
        let field = XF_BLOB_SIZE + X_FIELD_SIZE * i;
        let field_type = *slice(xfields, field, 1)?.first().expect("one byte");
        let size = usize::from(le_u16(xfields, field + 2)?);
        if field_type == INO_EXT_TYPE_DSTREAM {
            if size < J_DSTREAM_SIZE {
                return Err(error(format!(
                    "Invalid inode data stream field of {size} B"
                )));
            }
            return le_u64(xfields, data_at)
                .map_err(|_| error("Truncated inode data stream field"));
        }
        let padded = size
            .checked_add(XF_DATA_ALIGNMENT - 1)
            .ok_or_else(|| error("Invalid inode extended field size"))?
            & !(XF_DATA_ALIGNMENT - 1);
        data_at = data_at
            .checked_add(padded)
            .ok_or_else(|| error("Invalid inode extended field size"))?;
    }
    Ok(0)
}

/// A directory entry (`j_drec_val_t` with its key's name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirEntry {
    pub(super) name: String,
    /// The inode the entry names.
    pub(super) file_id: u64,
    /// `DT_*` type from the flags.
    pub(super) file_type: u8,
}

impl DirEntry {
    /// The entry of `key` and `value`. A hashed key (`j_drec_hashed_key_t`)
    /// holds a 32-bit length and hash, a plain key (`j_drec_key_t`) a 16-bit
    /// length; [FUSE] uses the hashed form on case- or
    /// normalization-insensitive volumes.
    pub(super) fn parse(key: &[u8], value: &[u8], hashed: bool) -> Result<Self> {
        let (name_at, length) = if hashed {
            (
                J_KEY_SIZE + 4,
                (le_u32(key, J_KEY_SIZE)? & J_DREC_LEN_MASK) as usize,
            )
        } else {
            (J_KEY_SIZE + 2, usize::from(le_u16(key, J_KEY_SIZE)?))
        };
        let name = slice(key, name_at, length)
            .ok()
            .filter(|_| name_at + length == key.len())
            .ok_or_else(|| {
                error(format!(
                    "Invalid directory entry key of {} B with a name of {length} B",
                    key.len()
                ))
            })?;
        if value.len() < DREC_VALUE_SIZE {
            return Err(error(format!(
                "Invalid directory entry value of {} B",
                value.len()
            )));
        }
        let file_type = (le_u16(value, DREC_FLAGS)? & DREC_TYPE_MASK) as u8;
        Ok(Self {
            name: name_text(name),
            file_id: le_u64(value, DREC_FILE_ID)? & OBJ_ID_MASK,
            file_type,
        })
    }
}

/// A NUL-terminated UTF-8 name as text: up to the first NUL, with invalid
/// sequences replaced and a `/` (which a path cannot show) as `:`.
pub(super) fn name_text(name: &[u8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).replace('/', ":")
}

/// Where an extended attribute's data is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum XattrData<'a> {
    /// In the record, at file offset `offset`.
    Embedded { bytes: &'a [u8], offset: usize },
    /// In data stream `id` of `size` bytes, whose extents are keyed by `id`.
    Stream { id: u64, size: u64 },
}

/// An extended attribute record (`j_xattr_key_t`, `j_xattr_val_t`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Xattr<'a> {
    /// The name without its NUL.
    pub(super) name: &'a [u8],
    pub(super) data: XattrData<'a>,
}

impl<'a> Xattr<'a> {
    /// The attribute of `key` and `value`; `value_offset` is the value's
    /// file offset.
    pub(super) fn parse(key: &'a [u8], value: &'a [u8], value_offset: usize) -> Result<Self> {
        let length = usize::from(le_u16(key, J_KEY_SIZE)?);
        let name = slice(key, J_KEY_SIZE + 2, length)
            .map_err(|_| error(format!("Invalid attribute key of {} B", key.len())))?;
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        let flags = le_u16(value, XATTR_FLAGS)?;
        let data_length = usize::from(le_u16(value, XATTR_DATA_LENGTH)?);
        let data = match (
            flags & XATTR_DATA_EMBEDDED != 0,
            flags & XATTR_DATA_STREAM != 0,
        ) {
            (true, false) => XattrData::Embedded {
                bytes: slice(value, XATTR_DATA, data_length).map_err(|_| {
                    error(format!(
                        "Truncated attribute: {data_length} B in a value of {} B",
                        value.len()
                    ))
                })?,
                offset: value_offset + XATTR_DATA,
            },
            (false, true) => XattrData::Stream {
                id: le_u64(value, XATTR_DATA + XATTR_STREAM_ID)? & OBJ_ID_MASK,
                size: le_u64(value, XATTR_DATA + XATTR_STREAM_SIZE)?,
            },
            _ => {
                return Err(error(format!(
                    "Invalid attribute flags 0x{flags:X}: exactly one of embedded and stream"
                )))
            }
        };
        Ok(Self { name, data })
    }
}

/// A file extent (`j_file_extent_key_t`, `j_file_extent_val_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Extent {
    /// Offset in the stream, in bytes.
    pub(super) logical: u64,
    /// Length in bytes.
    pub(super) length: u64,
    /// First block; 0 is a hole read as zeros ([FUSE] `ReadFile`).
    pub(super) block: u64,
}

impl Extent {
    pub(super) fn parse(key: &[u8], value: &[u8]) -> Result<Self> {
        Ok(Self {
            logical: le_u64(key, EXTENT_LOGICAL)?,
            length: le_u64(value, EXTENT_LENGTH)? & J_FILE_EXTENT_LEN_MASK,
            block: le_u64(value, EXTENT_BLOCK)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `j_key_t` of `oid` and `kind`, followed by `rest`.
    fn key(oid: u64, kind: u64, rest: &[u8]) -> Vec<u8> {
        let mut key = (oid | kind << OBJ_TYPE_SHIFT).to_le_bytes().to_vec();
        key.extend_from_slice(rest);
        key
    }

    #[test]
    fn keys_sort_by_object_then_type() {
        let inode = key(17, APFS_TYPE_INODE, b"");
        assert!(is_before(&inode, 17, APFS_TYPE_XATTR).unwrap());
        assert!(!is_before(&inode, 17, APFS_TYPE_INODE).unwrap());
        assert!(is_before(&key(16, APFS_TYPE_DIR_REC, b""), 17, APFS_TYPE_INODE).unwrap());
    }

    #[test]
    fn directory_entries_read_hashed_and_plain_names() {
        let mut value = 0x11u64.to_le_bytes().to_vec();
        value.extend(0u64.to_le_bytes());
        value.extend(u16::from(DT_REG).to_le_bytes());
        // Hashed: length 12 in the low 10 bits, an arbitrary hash above.
        let length_and_hash: u32 = 0xabcd << 10 | 0x00c;
        let mut rest = length_and_hash.to_le_bytes().to_vec();
        rest.extend_from_slice(b"payload.elf\0");
        let entry = DirEntry::parse(&key(2, APFS_TYPE_DIR_REC, &rest), &value, true).unwrap();
        assert_eq!(entry.name, "payload.elf");
        assert_eq!(entry.file_id, 0x11);
        assert_eq!(entry.file_type, DT_REG);
        let mut plain = 6u16.to_le_bytes().to_vec();
        plain.extend_from_slice(b"a/b.o\0");
        let entry = DirEntry::parse(&key(2, APFS_TYPE_DIR_REC, &plain), &value, false).unwrap();
        assert_eq!(entry.name, "a:b.o");
        // The hashed reading of a plain key does not fit.
        assert!(DirEntry::parse(&key(2, APFS_TYPE_DIR_REC, &plain), &value, true).is_err());
    }

    #[test]
    fn the_data_stream_field_follows_padded_fields() {
        // Two fields: a 5-byte name (padded to 8) and the data stream.
        let mut xfields = 2u16.to_le_bytes().to_vec();
        xfields.extend(53u16.to_le_bytes());
        xfields.extend([4, 0]);
        xfields.extend(5u16.to_le_bytes());
        xfields.extend([INO_EXT_TYPE_DSTREAM, 0]);
        xfields.extend(40u16.to_le_bytes());
        xfields.extend(b"name\0\0\0\0");
        xfields.extend(0x1234u64.to_le_bytes());
        xfields.extend([0; 32]);
        assert_eq!(dstream_size(&xfields).unwrap(), 0x1234);
        assert_eq!(dstream_size(&[]).unwrap(), 0);
        assert!(dstream_size(&xfields[..20]).is_err());
    }

    #[test]
    fn attributes_are_embedded_or_streams() {
        let attribute_key = key(26, APFS_TYPE_XATTR, b"\x12\0com.apple.decmpfs\0");
        let mut embedded = 2u16.to_le_bytes().to_vec();
        embedded.extend(3u16.to_le_bytes());
        embedded.extend(b"abc");
        let xattr = Xattr::parse(&attribute_key, &embedded, 0x100).unwrap();
        assert_eq!(xattr.name, b"com.apple.decmpfs");
        assert_eq!(
            xattr.data,
            XattrData::Embedded {
                bytes: b"abc",
                offset: 0x104
            }
        );
        let mut stream = 1u16.to_le_bytes().to_vec();
        stream.extend(48u16.to_le_bytes());
        stream.extend(28u64.to_le_bytes());
        stream.extend(300u64.to_le_bytes());
        stream.extend([0; 32]);
        let xattr = Xattr::parse(&attribute_key, &stream, 0).unwrap();
        assert_eq!(xattr.data, XattrData::Stream { id: 28, size: 300 });
        let mut both = stream.clone();
        both[0] = 3;
        assert!(Xattr::parse(&attribute_key, &both, 0).is_err());
    }
}
