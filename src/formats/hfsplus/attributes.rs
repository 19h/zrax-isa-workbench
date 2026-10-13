//! The attributes B-tree ([HFS] `HFSPlusAttrKey`, `HFSPlusAttrData`): the
//! `com.apple.decmpfs` attribute of a decmpfs (`AppleFSCompression`) file,
//! whose data the shared decoder in `formats::decmpfs` reads.

use super::catalog::name_text;
use super::*;
use crate::formats::decmpfs::DECMPFS_XATTR_NAME;
use std::cmp::Ordering;

/// Attribute record types (`kHFSPlusAttrInlineData`, `kHFSPlusAttrForkData`).
const ATTR_INLINE_DATA: u32 = 0x10;
const ATTR_FORK_DATA: u32 = 0x20;

/// `HFSPlusAttrData`: `recordType` (0), `reserved[2]` (4), `attrSize`
/// (12), `attrData` (16).
const ATTR_DATA_SIZE_FIELD: usize = 12;
const ATTR_DATA_OFFSET: usize = 16;

/// `HFSPlusAttrKey` after `keyLength`: `pad` (0), `fileID` (2),
/// `startBlock` (6), `attrNameLen` (10), `attrName` (12).
const ATTR_KEY_FILE_ID: usize = 2;
const ATTR_KEY_NAME_LENGTH: usize = 10;
const ATTR_KEY_NAME: usize = 12;

/// A file's `com.apple.decmpfs` attribute.
pub(super) struct Attribute {
    /// The attribute's bytes (`attrData`).
    pub(super) bytes: Vec<u8>,
    /// File offset of the attribute's first byte, when its node is mapped.
    pub(super) offset: Option<usize>,
}

/// An attribute key: the file and the attribute name (UTF-16BE).
struct AttributeKey<'k> {
    file_id: u32,
    name: &'k [u8],
}

impl<'k> AttributeKey<'k> {
    fn parse(key: &'k [u8]) -> Result<Self> {
        let length = usize::from(be_u16(key, ATTR_KEY_NAME_LENGTH)?);
        let name = slice(key, ATTR_KEY_NAME, 2 * length)
            .map_err(|_| error(format!("Invalid attribute key of {} B", key.len())))?;
        Ok(Self {
            file_id: be_u32(key, ATTR_KEY_FILE_ID)?,
            name,
        })
    }
}

impl Filesystem<'_> {
    /// The `com.apple.decmpfs` attribute of `file_id`. Attribute keys sort
    /// by `fileID` first, so a file's attributes are consecutive from the
    /// first key with its `fileID`.
    pub(super) fn decmpfs_attribute(&self, file_id: u32) -> ReadResult<Option<Attribute>> {
        let Some(tree) = &self.attributes else {
            return Ok(None);
        };
        let order = |key: &[u8]| {
            let key = AttributeKey::parse(key)?;
            Ok(key.file_id.cmp(&file_id).then(if key.name.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }))
        };
        let Some(mut cursor) = tree.lower_bound(&self.vol, &order)? else {
            return Ok(None);
        };
        while let Some(record) = cursor.next(tree, &self.vol)? {
            let key = AttributeKey::parse(record.key)?;
            if key.file_id != file_id {
                return Ok(None);
            }
            if name_text(key.name) != DECMPFS_XATTR_NAME {
                continue;
            }
            let record_type = be_u32(record.data, 0)?;
            if record_type == ATTR_FORK_DATA {
                return invalid(format!(
                    "Unsupported {DECMPFS_XATTR_NAME} attribute stored in extents"
                ));
            }
            if record_type != ATTR_INLINE_DATA {
                return invalid(format!(
                    "Invalid {DECMPFS_XATTR_NAME} attribute record type 0x{record_type:X}"
                ));
            }
            let size = be_u32(record.data, ATTR_DATA_SIZE_FIELD)? as usize;
            let bytes = slice(record.data, ATTR_DATA_OFFSET, size).map_err(|_| {
                error(format!(
                    "Truncated {DECMPFS_XATTR_NAME} attribute: {size} B in a record of {} B",
                    record.data.len()
                ))
            })?;
            let offset = tree.file_offset(
                &self.vol,
                record.node,
                record.data_offset + ATTR_DATA_OFFSET,
            );
            return Ok(Some(Attribute {
                bytes: bytes.to_vec(),
                offset,
            }));
        }
        Ok(None)
    }
}
