//! The WIM header (MSWIM `WIMHEADER_V1_PACKED`; wimlib `struct
//! wim_header_disk`) and resource headers (MSWIM `RESHDR_DISK_SHORT`;
//! wimlib `struct wim_reshdr_disk`).
//!
//! Header: magic (8), header size (4), version (4), flags (4), chunk size
//! (4), GUID (16), part number (2), total parts (2), image count (4), then
//! the resource headers of the lookup table, the XML data and the bootable
//! image's metadata, the boot index (4), the integrity table's resource
//! header and 60 reserved bytes, 208 bytes in all, little-endian.

use super::*;
use crate::types::MetadataValue;

/// Header field offsets (wimlib `struct wim_header_disk`).
const VERSION_FIELD: usize = 0x0C;
const FLAGS_FIELD: usize = 0x10;
const CHUNK_SIZE_FIELD: usize = 0x14;
const GUID_FIELD: usize = 0x18;
const PART_NUMBER_FIELD: usize = 0x28;
const IMAGE_COUNT_FIELD: usize = 0x2C;
const LOOKUP_TABLE_FIELD: usize = 0x30;
const XML_DATA_FIELD: usize = 0x48;
const BOOT_METADATA_FIELD: usize = 0x60;
const BOOT_INDEX_FIELD: usize = 0x78;
const INTEGRITY_FIELD: usize = 0x7C;

/// Versions that wimlib reads: 1.13 and the version of solid resources
/// and LZMS (wimlib `WIM_VERSION_DEFAULT`, `WIM_VERSION_SOLID`).
const VERSION_DEFAULT: u32 = 0x0001_0D00;
pub(super) const VERSION_SOLID: u32 = 0x0000_0E00;

/// Header flags (MSWIM `FLAG_HEADER_*`; wimlib `WIM_HDR_FLAG_*`).
const FLAG_COMPRESSION: u32 = 0x0000_0002;
const FLAG_READONLY: u32 = 0x0000_0004;
const FLAG_SPANNED: u32 = 0x0000_0008;
const FLAG_RESOURCE_ONLY: u32 = 0x0000_0010;
const FLAG_METADATA_ONLY: u32 = 0x0000_0020;
const FLAG_WRITE_IN_PROGRESS: u32 = 0x0000_0040;
const FLAG_RP_FIX: u32 = 0x0000_0080;
const FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
const FLAG_COMPRESS_LZX: u32 = 0x0004_0000;
/// wimlib only: LZMS, valid with [`VERSION_SOLID`].
const FLAG_COMPRESS_LZMS: u32 = 0x0008_0000;
/// wimlib only, "XPRESS, with small chunk size???"; wimlib reads it as
/// XPRESS, and so does this parser.
const FLAG_COMPRESS_XPRESS_2: u32 = 0x0020_0000;

/// Flags noted by name, in bit order.
const NOTED_FLAGS: [(u32, &str); 6] = [
    (FLAG_READONLY, "read-only"),
    (FLAG_SPANNED, "spanned"),
    (FLAG_RESOURCE_ONLY, "resource-only"),
    (FLAG_METADATA_ONLY, "metadata-only"),
    (FLAG_WRITE_IN_PROGRESS, "write in progress"),
    (FLAG_RP_FIX, "reparse point fixup"),
];

/// The chunk size of a compressed WIM whose header gives 0 (7-Zip
/// `kChunkSizeBits`; MSWIM: data "is stored into 32K chunks").
const DEFAULT_CHUNK_SIZE: u32 = 32 << 10;

/// Resource header flags (MSWIM `RESHDR_FLAG_*`; wimlib
/// `WIM_RESHDR_FLAG_*`, which adds the solid flag).
pub(super) const RESOURCE_METADATA: u8 = 0x02;
pub(super) const RESOURCE_COMPRESSED: u8 = 0x04;
pub(super) const RESOURCE_SOLID: u8 = 0x10;

/// A resource header: size in the WIM (7 bytes), flags (1), offset (8)
/// and uncompressed size (8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct ResourceHeader {
    /// Bytes the resource occupies in the file, its chunk table included.
    pub(super) stored_size: u64,
    /// `RESHDR_FLAG_*` bits.
    pub(super) flags: u8,
    /// File offset of the resource.
    pub(super) offset: u64,
    /// Uncompressed size in bytes.
    pub(super) size: u64,
}

impl ResourceHeader {
    /// Size of a resource header on disk.
    pub(super) const SIZE: usize = 24;

    /// The resource header at `at`.
    pub(super) fn read(data: &[u8], at: usize) -> Result<Self> {
        let header = slice(data, at, Self::SIZE, "WIM resource header")?;
        let size_and_flags = le_u64(header, 0)?;
        Ok(Self {
            stored_size: size_and_flags & 0x00ff_ffff_ffff_ffff,
            flags: header[7],
            offset: le_u64(header, 8)?,
            size: le_u64(header, 16)?,
        })
    }

    pub(super) fn is_compressed(&self) -> bool {
        self.flags & RESOURCE_COMPRESSED != 0
    }

    pub(super) fn is_solid(&self) -> bool {
        self.flags & RESOURCE_SOLID != 0
    }

    pub(super) fn is_metadata(&self) -> bool {
        self.flags & RESOURCE_METADATA != 0
    }

    /// An all-zero header: the resource is absent.
    pub(super) fn is_absent(&self) -> bool {
        *self == Self::default()
    }

    /// The file offset just past the resource, if it does not overflow.
    pub(super) fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.stored_size)
    }
}

/// A compression format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Compression {
    Xpress,
    Lzx,
    Lzms,
}

impl Compression {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Xpress => "XPRESS",
            Self::Lzx => "LZX",
            Self::Lzms => "LZMS",
        }
    }

    /// Smallest and largest chunk sizes (wimlib `wim_ctype_info`).
    fn min_chunk_size(self) -> u32 {
        match self {
            Self::Xpress => 4 << 10,
            Self::Lzx | Self::Lzms => 32 << 10,
        }
    }

    fn max_chunk_size(self) -> u32 {
        match self {
            Self::Xpress => 64 << 10,
            Self::Lzx => 2 << 20,
            Self::Lzms => 1 << 30,
        }
    }

    /// The compression format number of a solid resource header: 0 none,
    /// 1 XPRESS, 2 LZX, 3 LZMS (wimlib `alt_chunk_table_header_disk`, the
    /// WIMGAPI numbering).
    pub(super) fn from_number(number: u32) -> Result<Option<Self>> {
        match number {
            0 => Ok(None),
            1 => Ok(Some(Self::Xpress)),
            2 => Ok(Some(Self::Lzx)),
            3 => Ok(Some(Self::Lzms)),
            other => Err(error(format!(
                "Unsupported WIM solid resource compression format {other}"
            ))),
        }
    }

    /// A chunk size must be a power of two within the format's bounds
    /// (wimlib `wim_chunk_size_valid`).
    pub(super) fn check_chunk_size(self, size: u32) -> Result<()> {
        if size.is_power_of_two() && (self.min_chunk_size()..=self.max_chunk_size()).contains(&size)
        {
            return Ok(());
        }
        Err(error(format!(
            "Unsupported WIM {} chunk size {size} B (a power of two from {} to {})",
            self.name(),
            size_text(self.min_chunk_size() as usize),
            size_text(self.max_chunk_size() as usize)
        )))
    }
}

/// The parsed header.
#[derive(Debug)]
pub(super) struct Header {
    pub(super) version: u32,
    pub(super) flags: u32,
    /// The format of resources marked compressed, if the WIM is compressed.
    pub(super) compression: Option<Compression>,
    /// Chunk size of compressed non-solid resources in bytes; 0 when the
    /// WIM is not compressed.
    pub(super) chunk_size: u32,
    /// The chunk size field as stored.
    stored_chunk_size: u32,
    guid: [u8; 16],
    /// 1-based part number and part count.
    pub(super) part_number: u16,
    pub(super) total_parts: u16,
    pub(super) image_count: u32,
    pub(super) lookup: ResourceHeader,
    pub(super) xml: ResourceHeader,
    pub(super) boot_metadata: ResourceHeader,
    /// 1-based index of the bootable image; 0 for none.
    pub(super) boot_index: u32,
    pub(super) integrity: ResourceHeader,
}

impl Header {
    /// Read and validate the header at offset 0.
    pub(super) fn read(data: &[u8]) -> Result<Self> {
        let header = slice(data, 0, HEADER_SIZE, "WIM header")?;
        if !header.starts_with(MAGIC) {
            return Err(error("Missing WIM magic `MSWIM`"));
        }
        let header_size = le_u32(header, HEADER_SIZE_FIELD)?;
        if header_size as usize != HEADER_SIZE {
            return Err(error(format!(
                "Invalid WIM header size {header_size} B (expected {HEADER_SIZE} B)"
            )));
        }
        let version = le_u32(header, VERSION_FIELD)?;
        if version != VERSION_DEFAULT && version != VERSION_SOLID {
            return Err(error(format!(
                "Unsupported WIM version 0x{version:08X} (1.13 0x{VERSION_DEFAULT:08X} and \
                 0x{VERSION_SOLID:08X} are read)"
            )));
        }
        let part_number = le_u16(header, PART_NUMBER_FIELD)?;
        let total_parts = le_u16(header, TOTAL_PARTS_FIELD)?;
        if part_number == 0 || part_number > total_parts {
            return Err(error(format!(
                "Invalid WIM part number {part_number} of {total_parts}"
            )));
        }
        let flags = le_u32(header, FLAGS_FIELD)?;
        let compression = compression(flags)?;
        let stored_chunk_size = le_u32(header, CHUNK_SIZE_FIELD)?;
        let chunk_size = match compression {
            None => 0,
            Some(_) if stored_chunk_size == 0 => DEFAULT_CHUNK_SIZE,
            Some(compression) => {
                compression.check_chunk_size(stored_chunk_size)?;
                stored_chunk_size
            }
        };
        Ok(Self {
            version,
            flags,
            compression,
            chunk_size,
            stored_chunk_size,
            guid: slice(header, GUID_FIELD, 16, "WIM GUID")?
                .try_into()
                .expect("slice has exactly 16 bytes"),
            part_number,
            total_parts,
            image_count: le_u32(header, IMAGE_COUNT_FIELD)?,
            lookup: ResourceHeader::read(header, LOOKUP_TABLE_FIELD)?,
            xml: ResourceHeader::read(header, XML_DATA_FIELD)?,
            boot_metadata: ResourceHeader::read(header, BOOT_METADATA_FIELD)?,
            boot_index: le_u32(header, BOOT_INDEX_FIELD)?,
            integrity: ResourceHeader::read(header, INTEGRITY_FIELD)?,
        })
    }

    /// Whether solid resources may occur (wimlib ignores the solid flag in
    /// other versions).
    pub(super) fn allows_solid(&self) -> bool {
        self.version == VERSION_SOLID
    }

    /// Header facts in notes and metadata.
    pub(super) fn push_notes(&self, c: &mut Container<'_>) {
        let version = if self.version == VERSION_SOLID {
            "WIM version 0xE00 (solid resources and LZMS)".to_string()
        } else {
            "WIM version 1.13".to_string()
        };
        let compression = match self.compression {
            Some(compression) => format!(
                "resources compressed with {} in {} chunks",
                compression.name(),
                size_text(self.chunk_size as usize)
            ),
            None => "resources not compressed".to_string(),
        };
        c.notes.push(format!(
            "{version}; {compression}; {}",
            count(self.image_count as usize, "image", "images")
        ));
        if self.total_parts > 1 {
            c.notes.push(format!(
                "Part {} of {} of a split WIM; part 1 holds the metadata of every image",
                self.part_number, self.total_parts
            ));
        }
        if self.compression.is_some() && self.stored_chunk_size == 0 {
            c.notes.push(format!(
                "The header gives no chunk size; {} is used, as 7-Zip does",
                size_text(DEFAULT_CHUNK_SIZE as usize)
            ));
        }
        if self.compression.is_none() && self.stored_chunk_size != 0 {
            c.notes.push(format!(
                "The header gives a chunk size of {} B for uncompressed resources; it is not used",
                self.stored_chunk_size
            ));
        }
        if self.compression == Some(Compression::Lzms) && !self.allows_solid() {
            c.notes
                .push("LZMS compression in a version 1.13 header".to_string());
        }
        let named: Vec<&str> = NOTED_FLAGS
            .iter()
            .filter(|(flag, _)| self.flags & flag != 0)
            .map(|(_, name)| *name)
            .collect();
        if !named.is_empty() {
            c.notes.push(format!("Header flags: {}", named.join(", ")));
        }
        if self.boot_index > self.image_count {
            c.notes.push(format!(
                "Boot index {} names no image and is ignored, as wimlib does",
                self.boot_index
            ));
        } else if self.boot_index > 0 {
            c.notes
                .push(format!("Image {} is marked bootable", self.boot_index));
        }
        c.push_metadata(
            "wim_version",
            "WIM version",
            MetadataValue::Hex(self.version),
        );
        c.push_metadata("wim_flags", "Header flags", MetadataValue::Hex(self.flags));
        c.push_metadata(
            "wim_compression",
            "Compression",
            self.compression.map_or("none", Compression::name),
        );
        if self.compression.is_some() {
            c.push_metadata(
                "wim_chunk_size",
                "Chunk size (B)",
                u64::from(self.chunk_size),
            );
        }
        c.push_metadata("wim_guid", "GUID", guid_text(&self.guid));
        c.push_metadata(
            "wim_part",
            "Part",
            format!("{} of {}", self.part_number, self.total_parts),
        );
        c.push_metadata("wim_image_count", "Images", u64::from(self.image_count));
        c.push_metadata("wim_boot_index", "Boot index", u64::from(self.boot_index));
    }
}

/// The compression of resources marked compressed: with
/// `FLAG_HEADER_COMPRESSION` set, LZX, then XPRESS, then LZMS, as wimlib's
/// `begin_read` tests them.
fn compression(flags: u32) -> Result<Option<Compression>> {
    if flags & FLAG_COMPRESSION == 0 {
        return Ok(None);
    }
    if flags & FLAG_COMPRESS_LZX != 0 {
        Ok(Some(Compression::Lzx))
    } else if flags & (FLAG_COMPRESS_XPRESS | FLAG_COMPRESS_XPRESS_2) != 0 {
        Ok(Some(Compression::Xpress))
    } else if flags & FLAG_COMPRESS_LZMS != 0 {
        Ok(Some(Compression::Lzms))
    } else {
        Err(error(format!(
            "Invalid WIM header flags 0x{flags:08X}: compression without a format"
        )))
    }
}

/// A GUID in its binary form (Microsoft `GUID`): `Data1`, `Data2` and
/// `Data3` little-endian, `Data4` as stored.
fn guid_text(bytes: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut tail = String::with_capacity(16);
    for byte in &bytes[8..] {
        write!(tail, "{byte:02X}").expect("writing to a String succeeds");
    }
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{}-{}",
        &tail[..4],
        &tail[4..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_flags_are_tested_in_wimlib_order() {
        assert_eq!(compression(0).unwrap(), None);
        assert_eq!(compression(FLAG_COMPRESS_LZX).unwrap(), None);
        assert_eq!(
            compression(FLAG_COMPRESSION | FLAG_COMPRESS_LZX | FLAG_COMPRESS_XPRESS).unwrap(),
            Some(Compression::Lzx)
        );
        assert_eq!(
            compression(FLAG_COMPRESSION | FLAG_COMPRESS_XPRESS_2).unwrap(),
            Some(Compression::Xpress)
        );
        assert_eq!(
            compression(FLAG_COMPRESSION | FLAG_COMPRESS_LZMS).unwrap(),
            Some(Compression::Lzms)
        );
        assert!(compression(FLAG_COMPRESSION).is_err());
    }

    #[test]
    fn chunk_sizes_follow_the_wimlib_bounds() {
        assert!(Compression::Xpress.check_chunk_size(4096).is_ok());
        assert!(Compression::Xpress.check_chunk_size(65536).is_ok());
        assert!(Compression::Xpress.check_chunk_size(131_072).is_err());
        assert!(Compression::Lzx.check_chunk_size(16_384).is_err());
        assert!(Compression::Lzx.check_chunk_size(2 << 20).is_ok());
        assert!(Compression::Lzx.check_chunk_size(40_000).is_err());
        assert!(Compression::Lzms.check_chunk_size(1 << 30).is_ok());
        assert!(Compression::from_number(4).is_err());
        assert_eq!(Compression::from_number(0).unwrap(), None);
    }

    #[test]
    fn resource_headers_split_the_seven_byte_size_and_flags() {
        let mut bytes = vec![0u8; ResourceHeader::SIZE];
        bytes[..7].copy_from_slice(&[0x10, 0x20, 0, 0, 0, 0, 0x01]);
        bytes[7] = RESOURCE_COMPRESSED | RESOURCE_METADATA;
        bytes[8] = 0xd0;
        bytes[16] = 0x40;
        let header = ResourceHeader::read(&bytes, 0).unwrap();
        assert_eq!(header.stored_size, 0x0001_0000_0000_2010);
        assert!(header.is_compressed() && header.is_metadata() && !header.is_solid());
        assert_eq!(header.offset, 0xd0);
        assert_eq!(header.size, 0x40);
        assert!(!header.is_absent());
        assert!(ResourceHeader::default().is_absent());
    }

    #[test]
    fn guids_print_in_registry_form() {
        let bytes = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(guid_text(&bytes), "00112233-4455-6677-8899-AABBCCDDEEFF");
    }
}
