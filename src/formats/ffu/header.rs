//! The security header (`SECURITY_HEADER`) with the signed catalog and the
//! hash table that follow it, and the image header (`IMAGE_HEADER`) with the
//! manifest and img2ffu's device targeting entries.
//!
//! Security header (Microsoft "FFU image format", "Security header
//! region"): `cbSize` (0), `signature` (4, 12 B), `dwChunkSizeInKb` (16),
//! `dwAlgId` (20), `dwCatalogSize` (24), `dwHashTableSize` (28). The catalog
//! starts at `cbSize` (`WPinternals` reads the region from offset 0 with
//! `cbSize` counted in), the hash table follows it, and padding fills the
//! region to a chunk boundary, where the image header starts.
//!
//! Image header ("Image header region"): `cbSize` (0; 24 B, or 28 B when
//! img2ffu stores a device targeting count at 24), `Signature` (4, 12 B),
//! `ManifestLength` (16), `dwChunkSize` (20, in KiB). The manifest starts at
//! `cbSize`; img2ffu's device targeting entries follow it, and padding fills
//! the region to a chunk boundary, where the first store header starts.

use super::*;

/// `sizeof(ImageHeader)` in Microsoft's declaration.
const IMAGE_HEADER_SIZE: usize = 24;

/// The image header size img2ffu writes when the device targeting count
/// follows at offset 24 (img2ffu `Writer/Data/ImageHeader.cs`; the reader
/// looks for the count only at this size). Not in Microsoft's declaration.
const IMAGE_HEADER_WITH_TARGETS_SIZE: u32 = 28;

/// The device targeting count's offset in the image header.
const DEVICE_TARGET_COUNT_OFFSET: usize = 24;

/// What the seven strings of a device targeting entry hold, in order
/// (img2ffu `Writer/Data/DeviceTargetInfo.cs`).
const DEVICE_TARGET_FIELDS: [&str; 7] = [
    "manufacturer",
    "family",
    "product name",
    "product version",
    "SKU number",
    "baseboard manufacturer",
    "baseboard product",
];

/// A device targeting entry starts with one 32-bit length per string.
const DEVICE_TARGET_LENGTHS_SIZE: usize = 4 * DEVICE_TARGET_FIELDS.len();

/// Is `data` a security header: the signature, a `cbSize` of at least the
/// 32-byte header and a non-zero chunk size that holds it?
pub(super) fn is_security_header(data: &[u8]) -> bool {
    let Some(header) = data.get(..SECURITY_HEADER_SIZE) else {
        return false;
    };
    let (Ok(size), Ok(chunk_kib)) = (le_u32(header, 0), le_u32(header, 16)) else {
        return false;
    };
    header.get(4..16) == Some(SECURITY_SIGNATURE.as_slice())
        && chunk_kib != 0
        && is_header_size_valid(size, chunk_kib)
}

/// A `cbSize` that covers the 32 fields and fits in the first chunk.
fn is_header_size_valid(size: u32, chunk_kib: u32) -> bool {
    size as usize >= SECURITY_HEADER_SIZE && u64::from(size) <= u64::from(chunk_kib) * KIB
}

/// The security header and where the regions after it lie.
#[derive(Debug)]
pub(super) struct SecurityHeader {
    /// `dwChunkSizeInKb`.
    pub(super) chunk_kib: u32,
    /// The chunk size in bytes.
    pub(super) chunk_size: u64,
    /// `dwAlgId`: the hash algorithm of the hash table.
    pub(super) algorithm: u32,
    /// File offset of the signed catalog (`cbSize`).
    pub(super) catalog_offset: usize,
    /// `dwCatalogSize`, in bytes.
    pub(super) catalog_size: usize,
    /// File offset of the hash table, after the catalog.
    pub(super) hash_table_offset: usize,
    /// `dwHashTableSize`, in bytes.
    pub(super) hash_table_size: usize,
    /// File offset of the image header: the first chunk boundary after the
    /// hash table.
    pub(super) image_offset: usize,
}

impl SecurityHeader {
    /// Read the header at offset 0 and check that the catalog and hash
    /// table lie in the file.
    pub(super) fn read(data: &[u8]) -> Result<Self> {
        let header = slice(data, 0, SECURITY_HEADER_SIZE, "security header")?;
        if header.get(4..16) != Some(SECURITY_SIGNATURE.as_slice()) {
            return Err(error("Invalid security header signature at 0x4"));
        }
        let header_size = le_u32(header, 0)?;
        let chunk_kib = le_u32(header, 16)?;
        if chunk_kib == 0 {
            return Err(error("Invalid security header chunk size 0 KiB at 0x10"));
        }
        let chunk_size = u64::from(chunk_kib) * KIB;
        if !is_header_size_valid(header_size, chunk_kib) {
            return Err(error(format!(
                "Invalid security header size {header_size} B at 0x0: it must hold the \
                 {SECURITY_HEADER_SIZE} B header and fit in one {} chunk",
                size_text(chunk_size)
            )));
        }
        let algorithm = le_u32(header, 20)?;
        let catalog_offset = header_size as usize;
        let catalog = slice(
            data,
            catalog_offset,
            le_u32(header, 24)? as usize,
            "catalog",
        )?;
        // Both regions lie in `data`, so these sums cannot overflow.
        let hash_table_offset = catalog_offset + catalog.len();
        let hash_table = slice(
            data,
            hash_table_offset,
            le_u32(header, 28)? as usize,
            "hash table",
        )?;
        let region_end = (hash_table_offset + hash_table.len()) as u64;
        let image_offset = round_up(region_end, chunk_size)
            .ok_or_else(|| error("Invalid security region size"))?;
        Ok(Self {
            chunk_kib,
            chunk_size,
            algorithm,
            catalog_offset,
            catalog_size: catalog.len(),
            hash_table_offset,
            hash_table_size: hash_table.len(),
            image_offset: to_usize(image_offset, "image header")?,
        })
    }

    /// Notes and metadata on the catalog and the hash table fields.
    pub(super) fn push_notes(&self, c: &mut Container<'_>) {
        if self.catalog_size == 0 {
            c.notes
                .push("The security catalog is empty (0 B): the image carries no signature".into());
        } else {
            c.notes.push(format!(
                "Signed security catalog: {} B at 0x{:X}; its signature is not verified",
                self.catalog_size, self.catalog_offset
            ));
        }
        c.push_metadata(
            "ffu_catalog_size",
            "Security catalog size (B)",
            self.catalog_size as u64,
        );
        c.push_metadata(
            "ffu_hash_algorithm",
            "Hash algorithm (ALG_ID)",
            MetadataValue::Hex(self.algorithm),
        );
        c.push_metadata(
            "ffu_hash_table_size",
            "Hash table size (B)",
            self.hash_table_size as u64,
        );
    }
}

/// One device targeting entry: its seven strings, in
/// [`DEVICE_TARGET_FIELDS`] order.
#[derive(Debug)]
pub(super) struct DeviceTarget {
    fields: Vec<String>,
}

impl DeviceTarget {
    /// The non-empty fields as `name value` pairs joined with `; `.
    fn describe(&self) -> String {
        let parts: Vec<String> = DEVICE_TARGET_FIELDS
            .iter()
            .zip(&self.fields)
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, value)| format!("{name} {value}"))
            .collect();
        parts.join("; ")
    }
}

/// The device targeting entries after the manifest and where they end.
#[derive(Debug)]
struct DeviceTargets {
    list: Vec<DeviceTarget>,
    end: usize,
}

/// The image header and where the regions after it lie.
#[derive(Debug)]
pub(super) struct ImageHeader {
    /// `dwChunkSize`, in KiB as img2ffu writes it.
    chunk_kib: u32,
    /// File offset and size of the manifest.
    manifest_offset: usize,
    manifest_size: usize,
    /// img2ffu's device targeting entries.
    device_targets: Vec<DeviceTarget>,
    /// File offset of the first store header: the first chunk boundary
    /// after the manifest and the device targeting entries.
    pub(super) stores_offset: usize,
}

impl ImageHeader {
    /// Read the image header at the security header's `image_offset` and
    /// check that the manifest and the device targeting entries lie in the
    /// file. The security header's chunk size places the store header, as
    /// `WPinternals` and emmcdl do.
    pub(super) fn read(data: &[u8], security: &SecurityHeader) -> Result<Self> {
        let offset = security.image_offset;
        let header = slice(data, offset, IMAGE_HEADER_SIZE, "image header")?;
        if header.get(4..16) != Some(IMAGE_SIGNATURE.as_slice()) {
            return Err(error(format!(
                "Invalid image header signature at 0x{:X}",
                offset + 4
            )));
        }
        let header_size = le_u32(header, 0)?;
        if (header_size as usize) < IMAGE_HEADER_SIZE
            || u64::from(header_size) > security.chunk_size
        {
            return Err(error(format!(
                "Invalid image header size {header_size} B at 0x{offset:X}: it must hold the \
                 {IMAGE_HEADER_SIZE} B header and fit in one {} chunk",
                size_text(security.chunk_size)
            )));
        }
        let target_count = if header_size == IMAGE_HEADER_WITH_TARGETS_SIZE {
            let extended = slice(data, offset, header_size as usize, "image header")?;
            le_u32(extended, DEVICE_TARGET_COUNT_OFFSET)?
        } else {
            0
        };
        // `offset` lies in `data` and `header_size` fits in one chunk.
        let manifest_offset = offset
            .checked_add(header_size as usize)
            .ok_or_else(|| error("Invalid manifest offset"))?;
        let manifest = slice(
            data,
            manifest_offset,
            le_u32(header, 16)? as usize,
            "manifest",
        )?;
        let targets = read_device_targets(
            data,
            manifest_offset + manifest.len(),
            DeviceTargetCount {
                count: target_count,
                field_offset: offset + DEVICE_TARGET_COUNT_OFFSET,
            },
        )?;
        let stores_offset = round_up(targets.end as u64, security.chunk_size)
            .ok_or_else(|| error("Invalid image header region size"))?;
        Ok(Self {
            chunk_kib: le_u32(header, 20)?,
            manifest_offset,
            manifest_size: manifest.len(),
            device_targets: targets.list,
            stores_offset: to_usize(stores_offset, "store header")?,
        })
    }

    /// The manifest bytes, which [`ImageHeader::read`] found in `data`.
    pub(super) fn manifest<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.manifest_offset..self.manifest_offset + self.manifest_size)
            .unwrap_or_default()
    }

    /// Notes and metadata on the chunk size field and the device targeting
    /// entries.
    pub(super) fn push_notes(&self, c: &mut Container<'_>, security: &SecurityHeader) {
        if self.chunk_kib != security.chunk_kib {
            c.notes.push(format!(
                "Image header chunk size {} KiB differs from the security header's {} KiB; the \
                 security header's chunk size places the store headers",
                self.chunk_kib, security.chunk_kib
            ));
        }
        if self.device_targets.is_empty() {
            return;
        }
        c.notes.push(format!(
            "Device targeting information: {} after the manifest (img2ffu layout)",
            counted(self.device_targets.len() as u64, "entry", "entries")
        ));
        for (i, target) in self.device_targets.iter().enumerate() {
            c.push_metadata(
                format!("ffu_device_target_{i}"),
                format!("Device target {}", i + 1),
                target.describe(),
            );
        }
    }
}

/// The device targeting count and the file offset of its field.
#[derive(Debug, Clone, Copy)]
struct DeviceTargetCount {
    count: u32,
    field_offset: usize,
}

/// The device targeting entries from `offset`: seven 32-bit lengths, then
/// that many ASCII bytes for each string. Each entry takes at least
/// [`DEVICE_TARGET_LENGTHS_SIZE`] bytes, so the count is checked against the
/// file before any entry is read.
fn read_device_targets(
    data: &[u8],
    offset: usize,
    targets: DeviceTargetCount,
) -> Result<DeviceTargets> {
    let count = targets.count;
    let available = data.len().saturating_sub(offset) / DEVICE_TARGET_LENGTHS_SIZE;
    if count as usize > available {
        return Err(error(format!(
            "Invalid device targeting count {count} at 0x{:X}: the file holds at most {} after \
             the manifest",
            targets.field_offset,
            counted(available as u64, "entry", "entries")
        )));
    }
    let mut list = Vec::new();
    let mut at = offset;
    for _ in 0..count {
        let lengths = slice(
            data,
            at,
            DEVICE_TARGET_LENGTHS_SIZE,
            "device targeting entry",
        )?;
        let mut text_at = at + DEVICE_TARGET_LENGTHS_SIZE;
        let mut fields = Vec::with_capacity(DEVICE_TARGET_FIELDS.len());
        for i in 0..DEVICE_TARGET_FIELDS.len() {
            let len = le_u32(lengths, i * 4)? as usize;
            let text = slice(data, text_at, len, "device targeting string")?;
            fields.push(byte_text(text));
            text_at += text.len();
        }
        list.push(DeviceTarget { fields });
        at = text_at;
    }
    Ok(DeviceTargets { list, end: at })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security_header(size: u32, chunk_kib: u32) -> Vec<u8> {
        let mut header = vec![0u8; 64];
        header[..4].copy_from_slice(&size.to_le_bytes());
        header[4..16].copy_from_slice(SECURITY_SIGNATURE);
        header[16..20].copy_from_slice(&chunk_kib.to_le_bytes());
        header
    }

    #[test]
    fn security_headers_need_the_signature_and_consistent_sizes() {
        assert!(is_security_header(&security_header(32, 128)));
        assert!(is_security_header(&security_header(1024, 1)));
        assert!(!is_security_header(&security_header(31, 128)));
        assert!(!is_security_header(&security_header(32, 0)));
        assert!(!is_security_header(&security_header(1025, 1)));
        assert!(!is_security_header(&security_header(32, 128)[..31]));
        let mut other = security_header(32, 128);
        other[15] = b'_';
        assert!(!is_security_header(&other));
    }

    #[test]
    fn device_target_counts_are_checked_against_the_file() {
        let mut entry = Vec::new();
        for len in [4u32, 0, 3, 0, 0, 0, 0] {
            entry.extend_from_slice(&len.to_le_bytes());
        }
        entry.extend_from_slice(b"ZraxABC");
        let count = |count| DeviceTargetCount {
            count,
            field_offset: 0x1018,
        };
        let targets = read_device_targets(&entry, 0, count(1)).unwrap();
        assert_eq!(targets.end, entry.len());
        assert_eq!(
            targets.list[0].describe(),
            "manufacturer Zrax; product name ABC"
        );
        let message = read_device_targets(&entry, 0, count(2))
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "FFU image parse error: Invalid device targeting count 2 at 0x1018: the file holds \
             at most 1 entry after the manifest"
        );
        assert!(read_device_targets(&entry[..30], 0, count(1)).is_err());
    }
}
