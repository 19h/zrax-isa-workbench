//! The UDIF trailer (`UDIFResourceFile`, the `koly` block): 512 bytes at
//! the end of the file, every field big-endian (libdmg-hfsplus
//! `includes/dmg/dmg.h`; 7-Zip `DmgHandler.cpp` `CHandler::Open2`).
//!
//! Layout: signature `koly` (4), version 4 (4), header size 512 (4), flags
//! (4), running data fork offset (8), data fork offset (8) and length (8),
//! resource fork offset (8) and length (8), segment number (4) and count
//! (4), segment ID (16), data fork checksum (136) at 80, XML property list
//! offset (8) and length (8) at 216, reserved (120; 7-Zip reads a code
//! signature offset and length at 296), master checksum (136) at 352, image
//! variant (4) at 488, sector count (8) at 492, reserved (12). A checksum is
//! a type (4; 2 is CRC-32), a size in bits (4) and 128 bytes of value.

use super::*;

/// Trailer size and the header size field's only value.
pub(super) const TRAILER_SIZE: usize = 512;

const SIGNATURE: &[u8; 4] = b"koly";

/// The only trailer version readers accept (7-Zip `k_Signature`).
const VERSION: u32 = 4;

/// Checksum type 2: CRC-32 (libdmg-hfsplus `CHECKSUM_CRC32`).
pub(super) const CHECKSUM_CRC32: u32 = 2;

/// Bits of a CRC-32 checksum value.
const CRC32_BITS: u32 = 32;

/// Size of a checksum record: type, size in bits and 128 value bytes.
const CHECKSUM_SIZE: usize = 136;

/// Bytes a checksum value holds.
const CHECKSUM_VALUE_SIZE: usize = 128;

/// `kUDIFFlagsFlattened`: the resource fork is stored in the file.
const FLAG_FLATTENED: u32 = 1;

/// Image variants (`kUDIFDeviceImageType`, `kUDIFPartitionImageType`).
const DEVICE_IMAGE: u32 = 1;
const PARTITION_IMAGE: u32 = 2;

/// Where an XML property list starts; 7-Zip tests for it to tell an image
/// from one embedded at an offset.
const XML_PREFIX: &[u8] = b"<?xml version";

/// Trailer field offsets.
const DATA_FORK_CHECKSUM_OFFSET: usize = 80;
const XML_OFFSET: usize = 216;
const CODE_SIGNATURE_OFFSET: usize = 296;
const MASTER_CHECKSUM_OFFSET: usize = 352;
const IMAGE_VARIANT_OFFSET: usize = 488;
const SECTOR_COUNT_OFFSET: usize = 492;

/// A byte range of the file that the trailer names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Fork {
    /// File offset.
    pub(super) offset: u64,
    /// Length in bytes.
    pub(super) length: u64,
}

impl Fork {
    /// Offset and length at `at` in `bytes`.
    fn read(bytes: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            offset: be_u64(bytes, at)?,
            length: be_u64(bytes, at + 8)?,
        })
    }

    pub(super) fn is_empty(self) -> bool {
        self.length == 0
    }

    /// The fork's end, when it lies at or before `limit` (7-Zip
    /// `CForkPair::UpdateTop`: `offset <= limit && length <= limit -
    /// offset`).
    fn end_within(self, limit: u64) -> Option<u64> {
        if self.offset <= limit && self.length <= limit - self.offset {
            Some(self.offset + self.length)
        } else {
            None
        }
    }

    /// The fork's bytes in `data`.
    pub(super) fn bytes<'a>(self, data: &'a [u8], what: &str) -> Result<&'a [u8]> {
        range(data, self.offset, self.length, what)
    }

    /// `file 0x16D7; 8089 B`, for metadata.
    pub(super) fn describe(self) -> String {
        format!("file 0x{:X}; {} B", self.offset, self.length)
    }
}

/// A checksum record: type, size in bits and value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Checksum {
    pub(super) kind: u32,
    pub(super) bits: u32,
    pub(super) value: [u8; CHECKSUM_VALUE_SIZE],
}

impl Checksum {
    /// The record at `at` in `bytes`.
    pub(super) fn read(bytes: &[u8], at: usize) -> Result<Self> {
        let record = slice(bytes, at, CHECKSUM_SIZE, "checksum")?;
        Ok(Self {
            kind: be_u32(record, 0)?,
            bits: be_u32(record, 4)?,
            value: array(record, 8)?,
        })
    }

    /// The stored CRC-32, when the record holds one (type 2, 32 bits;
    /// 7-Zip `CChecksum::IsCrc32`).
    pub(super) fn crc32(&self) -> Option<u32> {
        (self.kind == CHECKSUM_CRC32 && self.bits == CRC32_BITS).then(|| {
            u32::from_be_bytes([self.value[0], self.value[1], self.value[2], self.value[3]])
        })
    }

    /// No checksum: type and size both zero.
    pub(super) fn is_absent(&self) -> bool {
        self.kind == 0 && self.bits == 0
    }

    /// The value bytes the size in bits covers, when it is a whole number
    /// of bytes the record can hold (7-Zip's master checksum input).
    pub(super) fn value_bytes(&self) -> Option<&[u8]> {
        let bits = usize::try_from(self.bits).ok()?;
        (bits % 8 == 0 && bits / 8 <= CHECKSUM_VALUE_SIZE).then(|| &self.value[..bits / 8])
    }

    /// `type 4, 128 bits`, for notes about checksums that are not checked.
    pub(super) fn describe(&self) -> String {
        format!("type {}, {} bits", self.kind, self.bits)
    }
}

/// The trailer fields this parser uses.
#[derive(Debug, Clone)]
pub(super) struct Trailer {
    /// File offset of the trailer.
    pub(super) offset: usize,
    pub(super) flags: u32,
    /// Offset of this segment's data in the whole image's data stream.
    pub(super) running_data_fork_offset: u64,
    pub(super) data_fork: Fork,
    pub(super) resource_fork: Fork,
    /// 1 for the first segment; 0 when not set.
    pub(super) segment_number: u32,
    /// 0 when not set.
    pub(super) segment_count: u32,
    pub(super) data_fork_checksum: Checksum,
    pub(super) xml: Fork,
    /// The code signature blob 7-Zip reads from the reserved area; it may
    /// hold garbage in old images, so it is used only when it fits.
    pub(super) code_signature: Fork,
    pub(super) master_checksum: Checksum,
    pub(super) image_variant: u32,
    /// Sectors of 512 bytes in the whole disk.
    pub(super) sector_count: u64,
}

impl Trailer {
    /// `0x00000001 (flattened)`, for metadata.
    pub(super) fn flags_text(&self) -> String {
        if self.flags & FLAG_FLATTENED != 0 {
            format!("0x{:08X} (flattened)", self.flags)
        } else {
            format!("0x{:08X}", self.flags)
        }
    }

    /// The image variant's name, when it is a documented one.
    pub(super) fn variant_text(&self) -> String {
        match self.image_variant {
            DEVICE_IMAGE => "device image (1)".into(),
            PARTITION_IMAGE => "partition image (2)".into(),
            other => format!("unknown ({other})"),
        }
    }

    /// Whether the code signature pair names bytes before the trailer.
    pub(super) fn has_code_signature(&self) -> bool {
        !self.code_signature.is_empty()
            && self.code_signature.end_within(self.offset as u64).is_some()
    }
}

/// Read and validate the trailer: signature, version, header size, and
/// data fork, XML property list and resource fork ranges that end at or
/// before the trailer.
pub(super) fn trailer(data: &[u8]) -> Result<Trailer> {
    let Some(offset) = data.len().checked_sub(TRAILER_SIZE) else {
        return Err(error(format!(
            "Truncated UDIF image: {} B, the trailer needs {TRAILER_SIZE} B",
            data.len()
        )));
    };
    let bytes = &data[offset..];
    if &bytes[..4] != SIGNATURE {
        return Err(error(format!(
            "Missing UDIF trailer signature at 0x{offset:X}"
        )));
    }
    let version = be_u32(bytes, 4)?;
    if version != VERSION {
        return Err(error(format!("Unsupported UDIF trailer version {version}")));
    }
    let header_size = be_u32(bytes, 8)?;
    if header_size as usize != TRAILER_SIZE {
        return Err(error(format!("Invalid UDIF trailer size {header_size} B")));
    }
    let t = Trailer {
        offset,
        flags: be_u32(bytes, 12)?,
        running_data_fork_offset: be_u64(bytes, 16)?,
        data_fork: Fork::read(bytes, 24)?,
        resource_fork: Fork::read(bytes, 40)?,
        segment_number: be_u32(bytes, 56)?,
        segment_count: be_u32(bytes, 60)?,
        data_fork_checksum: Checksum::read(bytes, DATA_FORK_CHECKSUM_OFFSET)?,
        xml: Fork::read(bytes, XML_OFFSET)?,
        code_signature: Fork::read(bytes, CODE_SIGNATURE_OFFSET)?,
        master_checksum: Checksum::read(bytes, MASTER_CHECKSUM_OFFSET)?,
        image_variant: be_u32(bytes, IMAGE_VARIANT_OFFSET)?,
        sector_count: be_u64(bytes, SECTOR_COUNT_OFFSET)?,
    };
    for (fork, what) in [
        (t.data_fork, "data fork"),
        (t.xml, "XML property list"),
        (t.resource_fork, "resource fork"),
    ] {
        if fork.end_within(offset as u64).is_none() {
            return Err(error(format!(
                "Invalid UDIF {what} range 0x{:X} + {} B: the trailer is at 0x{offset:X}",
                fork.offset, fork.length
            )));
        }
    }
    Ok(t)
}

/// Is this a UDIF image: a valid trailer whose block tables are where it
/// says? A file that only ends with a UDIF image (an image appended to
/// other data) has its forks at offsets relative to the image, so the XML
/// property list must start where the trailer puts it, as 7-Zip tests; an
/// image without one must have a binary resource fork whose header fits.
pub(super) fn is_present(data: &[u8]) -> bool {
    let Ok(t) = trailer(data) else {
        return false;
    };
    if !t.xml.is_empty() {
        return t
            .xml
            .bytes(data, "XML property list")
            .is_ok_and(|xml| xml.starts_with(XML_PREFIX));
    }
    !t.resource_fork.is_empty()
        && t.resource_fork
            .bytes(data, "resource fork")
            .is_ok_and(rsrc::header_fits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trailer after `body`, with the XML property list `xml_length`
    /// bytes at `xml_offset`.
    fn image(body: &[u8], xml_offset: u64, xml_length: u64) -> Vec<u8> {
        let mut data = body.to_vec();
        let mut trailer = [0u8; TRAILER_SIZE];
        trailer[..4].copy_from_slice(SIGNATURE);
        trailer[4..8].copy_from_slice(&VERSION.to_be_bytes());
        trailer[8..12].copy_from_slice(&512u32.to_be_bytes());
        trailer[XML_OFFSET..XML_OFFSET + 8].copy_from_slice(&xml_offset.to_be_bytes());
        trailer[XML_OFFSET + 8..XML_OFFSET + 16].copy_from_slice(&xml_length.to_be_bytes());
        data.extend_from_slice(&trailer);
        data
    }

    #[test]
    fn the_property_list_must_be_where_the_trailer_says() {
        let xml = b"<?xml version=\"1.0\"?><plist/>";
        assert!(is_present(&image(xml, 0, xml.len() as u64)));
        // The same image after other data: the offsets no longer fit it.
        let mut shifted = b"junk".to_vec();
        shifted.extend_from_slice(xml);
        assert!(!is_present(&image(&shifted, 0, xml.len() as u64)));
        // No property list and no resource fork: nothing to read.
        assert!(!is_present(&image(xml, 0, 0)));
    }

    #[test]
    fn forks_must_end_before_the_trailer() {
        let body = [0u8; 64];
        assert!(trailer(&image(&body, 0, 64)).is_ok());
        let message = trailer(&image(&body, 0, 65)).unwrap_err().to_string();
        assert_eq!(
            message,
            "Apple disk image parse error: Invalid UDIF XML property list range 0x0 + 65 B: \
             the trailer is at 0x40"
        );
        assert!(trailer(&image(&body, u64::MAX, 2)).is_err());
    }

    #[test]
    fn crc32_records_need_type_2_and_32_bits() {
        let mut record = [0u8; CHECKSUM_SIZE];
        record[..4].copy_from_slice(&CHECKSUM_CRC32.to_be_bytes());
        record[4..8].copy_from_slice(&32u32.to_be_bytes());
        record[8..12].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let checksum = Checksum::read(&record, 0).unwrap();
        assert_eq!(checksum.crc32(), Some(0x1234_5678));
        assert_eq!(checksum.value_bytes(), Some(&[0x12, 0x34, 0x56, 0x78][..]));
        record[4..8].copy_from_slice(&128u32.to_be_bytes());
        assert_eq!(Checksum::read(&record, 0).unwrap().crc32(), None);
    }
}
