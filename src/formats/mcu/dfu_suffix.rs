//! USB DFU files: any firmware followed by the DFU suffix, whose last 16
//! bytes are `bcdDevice`, `idProduct`, `idVendor`, `bcdDFU`,
//! `ucDfuSignature`, `bLength` and `dwCRC`, every multi-byte field
//! little-endian in file order. The suffix reader here is shared with the
//! `DfuSe` layout ([`super::dfuse`]), whose files end in the same suffix.
//!
//! Sources: USB Device Class Specification for Device Firmware Upgrade,
//! version 1.1 (2004-08-05), Appendix B "DFU File Suffix" and its sample
//! program (`_filecrc`); dfu-util v0.11 `src/dfu_file.c` (`dfu_load_file`,
//! `dfu_store_file`), `src/suffix.c` (the `bcdDFU` values it writes) and
//! `src/dfuse.c` (`dfuse_do_dnload`, which refuses to send a `0x011A` file
//! raw).
//!
//! `dwCRC` is the reflected IEEE CRC-32 register (initial value
//! `0xFFFFFFFF`) over every byte but the last four, stored without the final
//! inversion. The suffix is "never sent to the device": the firmware is the
//! file without its last `bLength` bytes, and it is classified on its own.
//! `idVendor`/`idProduct` are USB IDs and name no ISA.

use super::*;
use crate::formats::checksum;

/// The standard suffix: `bcdDevice`, `idProduct` (2), `idVendor` (4),
/// `bcdDFU` (6), `ucDfuSignature` (8), `bLength` (11), `dwCRC` (12).
pub(super) const SUFFIX_SIZE: usize = 16;

/// Offset of `ucDfuSignature` in the standard suffix.
const SIGNATURE_OFFSET: usize = 8;

/// Offset of `bLength` in the standard suffix.
const LENGTH_OFFSET: usize = 11;

/// Offset of `bcdDFU` in the standard suffix.
const BCD_DFU_OFFSET: usize = 6;

/// `ucDfuSignature` in file order (the specification's `44h 46h 55h`,
/// stored reversed).
const DFU_SIGNATURE: &[u8; 3] = b"UFD";

/// `dwCRC` takes the last four bytes of the file.
const CRC_SIZE: usize = 4;

/// `bcdDFU` "as of this revision of the specification", representing DFU
/// 1.0; DFU 1.1 files and dfu-suffix's default keep it.
const BCD_DFU_1_0: u16 = 0x0100;

/// `bcdDFU` of `DfuSe` 1.1a files, which start with the `DfuSe` prefix.
pub(super) const BCD_DFU_DFUSE: u16 = 0x011a;

/// The wildcard `idVendor`, `idProduct` and `bcdDevice` value.
const ANY_ID: u16 = 0xffff;

/// The DFU suffix fields.
pub(super) struct Suffix {
    /// `bcdDevice`.
    pub(super) device: u16,
    /// `idProduct`.
    pub(super) product: u16,
    /// `idVendor`.
    pub(super) vendor: u16,
    /// `bcdDFU`.
    pub(super) bcd_dfu: u16,
    /// `bLength`: suffix size in bytes, at least 16. A longer suffix holds
    /// vendor fields before the standard ones.
    pub(super) size: usize,
    /// File offset of the standard 16-byte suffix.
    pub(super) offset: usize,
}

impl Suffix {
    /// File offset of `bcdDFU`.
    pub(super) fn bcd_dfu_offset(&self) -> usize {
        self.offset + BCD_DFU_OFFSET
    }
}

/// The CRC-32 register over every byte before `dwCRC`, which ends the file
/// at `crc_at`.
fn computed_crc(data: &[u8], crc_at: usize) -> u32 {
    checksum::crc32_update(!0, &data[..crc_at])
}

/// Whether the file ends in a DFU suffix: the signature at its place and a
/// matching `dwCRC`, the two criteria the specification gives the host.
pub(super) fn is_valid(data: &[u8]) -> bool {
    let Some(start) = data.len().checked_sub(SUFFIX_SIZE) else {
        return false;
    };
    let signature = &data[start + SIGNATURE_OFFSET..start + LENGTH_OFFSET];
    let crc_at = data.len() - CRC_SIZE;
    signature == DFU_SIGNATURE
        && le_u32(data, crc_at).is_ok_and(|stored| stored == computed_crc(data, crc_at))
}

/// Read the suffix at the end of `data`, which must hold at least
/// [`SUFFIX_SIZE`] bytes: the signature, a `bLength` of 16 to `max_size`
/// bytes, then `dwCRC`.
pub(super) fn read(data: &[u8], max_size: usize) -> Result<Suffix> {
    let start = data
        .len()
        .checked_sub(SUFFIX_SIZE)
        .ok_or_else(|| error(format!("Truncated DFU suffix: {} B", data.len())))?;
    let fields = &data[start..];
    if &fields[SIGNATURE_OFFSET..LENGTH_OFFSET] != DFU_SIGNATURE {
        return Err(error(format!(
            "Missing DFU suffix signature at 0x{:X}",
            start + SIGNATURE_OFFSET
        )));
    }
    let size = usize::from(fields[LENGTH_OFFSET]);
    if size < SUFFIX_SIZE || size > max_size {
        return Err(error(format!(
            "Invalid DFU suffix bLength {size} B at 0x{:X}",
            start + LENGTH_OFFSET
        )));
    }
    let crc_at = data.len() - CRC_SIZE;
    let stored = le_u32(data, crc_at)?;
    let computed = computed_crc(data, crc_at);
    if stored != computed {
        return Err(error(format!(
            "Invalid DFU suffix CRC-32 0x{stored:08X} at 0x{crc_at:X}; computed 0x{computed:08X}"
        )));
    }
    Ok(Suffix {
        device: le_u16(fields, 0)?,
        product: le_u16(fields, 2)?,
        vendor: le_u16(fields, 4)?,
        bcd_dfu: le_u16(fields, BCD_DFU_OFFSET)?,
        size,
        offset: start,
    })
}

/// Parse a DFU file: the firmware before the suffix is one child.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() <= SUFFIX_SIZE {
        return Err(error(format!(
            "Truncated DFU file: {} B cannot hold firmware and the DFU suffix",
            data.len()
        )));
    }
    // At least one byte of firmware precedes the suffix.
    let suffix = read(data, data.len() - 1)?;
    match suffix.bcd_dfu {
        BCD_DFU_1_0 => {}
        BCD_DFU_DFUSE => {
            return Err(error(format!(
                "Missing DfuSe prefix for DFU suffix bcdDFU 0x{BCD_DFU_DFUSE:04X} at 0x{:X}",
                suffix.bcd_dfu_offset()
            )))
        }
        other => {
            return Err(error(format!(
                "Unsupported DFU suffix bcdDFU 0x{other:04X} at 0x{:X}; DFU 1.1 files use \
                 0x{BCD_DFU_1_0:04X}",
                suffix.bcd_dfu_offset()
            )))
        }
    }
    let firmware = &data[..data.len() - suffix.size];
    let mut c = Container::new(
        FileFormat::DfuSuffix,
        Layout::DfuSuffix.label(),
        Layout::DfuSuffix.key_prefix(),
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "DFU suffix: bcdDFU 0x{BCD_DFU_1_0:04X}; CRC-32 verified; {} B of firmware before the \
         {} B suffix",
        firmware.len(),
        suffix.size
    ));
    if suffix.size > SUFFIX_SIZE {
        c.notes.push(format!(
            "bLength {} B: {} B of vendor suffix fields before the standard 16 B; not interpreted",
            suffix.size,
            suffix.size - SUFFIX_SIZE
        ));
    }
    c.notes.push(device_note(&suffix));
    c.children.push(Child::stored("DFU firmware", 0, firmware));
    c.push_metadata(
        "dfu_vendor_id",
        "USB vendor ID",
        format!("0x{:04X}", suffix.vendor),
    );
    c.push_metadata(
        "dfu_product_id",
        "USB product ID",
        format!("0x{:04X}", suffix.product),
    );
    c.push_metadata(
        "dfu_device_version",
        "bcdDevice",
        format!("0x{:04X}", suffix.device),
    );
    c.push_metadata(
        "dfu_suffix_length",
        "DFU suffix length (B)",
        suffix.size as u64,
    );
    Ok(c)
}

/// What the USB IDs say: a device to match, or any device.
fn device_note(suffix: &Suffix) -> String {
    if suffix.vendor == ANY_ID {
        return "USB vendor 0xFFFF: the file may be sent to any device; the suffix names no ISA"
            .to_string();
    }
    let product = if suffix.product == ANY_ID {
        "any product".to_string()
    } else {
        format!("product 0x{:04X}", suffix.product)
    };
    format!(
        "USB vendor 0x{:04X}, {product} name the device, not an ISA",
        suffix.vendor
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DFU 1.1 sample suffix (`bcdDFU` 0x0100, `UFD`, `bLength` 16)
    /// after `firmware`, with the un-inverted CRC-32 register.
    fn with_suffix(firmware: &[u8]) -> Vec<u8> {
        let mut file = firmware.to_vec();
        file.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01]);
        file.extend_from_slice(b"UFD\x10");
        let crc = checksum::crc32_update(!0, &file);
        file.extend_from_slice(&crc.to_le_bytes());
        file
    }

    #[test]
    fn suffix_crc_is_the_uninverted_register() {
        let file = with_suffix(b"123456789");
        assert!(is_valid(&file));
        let suffix = read(&file, file.len() - 1).unwrap();
        assert_eq!(
            (suffix.vendor, suffix.bcd_dfu, suffix.size),
            (0xffff, 0x0100, 16)
        );
        let mut bad = file.clone();
        bad[0] ^= 1;
        assert!(!is_valid(&bad));
    }

    #[test]
    fn short_or_unsigned_files_have_no_suffix() {
        assert!(!is_valid(b""));
        assert!(!is_valid(&[0; 15]));
        assert!(!is_valid(&[0; 16]));
        assert!(read(&[0; 15], 16).is_err());
        let file = with_suffix(b"x");
        assert!(parse(&file[1..]).is_err());
    }
}
