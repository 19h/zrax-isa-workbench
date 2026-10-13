//! STM32 `DfuSe` files: an 11-byte `DfuSe` prefix, `bTargets` target images
//! of address/size elements, and the 16-byte DFU suffix. Every integer is
//! little-endian.
//!
//! Sources: dfu-util v0.11 `src/dfuse.c` (`dfuse_do_dfuse_dnload`) and
//! `src/dfu_file.c` (`dfu_load_file`), `MicroPython` v1.24.0
//! `tools/pydfu.py` (`read_dfu_file`) and `tools/dfu.py`, and the USB Device
//! Firmware Upgrade Specification 1.1 (2004-08-05), Appendix B "DFU File
//! Suffix". ST UM0391 itself was not available, so its wording is not
//! relied on.
//!
//! The suffix is read by [`super::dfu_suffix`]: its CRC is the DFU
//! convention, the reflected IEEE CRC-32 register (initial value
//! `0xFFFFFFFF`) over every byte but the last four, stored without the final
//! inversion (DFU 1.1 sample code, `_filecrc`). The file names no ISA:
//! `idVendor`/`idProduct` are USB IDs, and element addresses are byte
//! addresses in a memory the alternate setting selects.

use super::dfu_suffix::{self, Suffix, BCD_DFU_DFUSE, SUFFIX_SIZE};
use super::*;

/// `szSignature` of the `DfuSe` prefix.
const DFUSE_SIGNATURE: &[u8; 5] = b"DfuSe";

/// `bVersion`: dfu-util rejects any other value.
const DFUSE_VERSION: u8 = 0x01;

/// Prefix: signature, `bVersion` (5), `DFUImageSize` (6), `bTargets` (10).
const PREFIX_SIZE: usize = 11;

/// `szSignature` of a target prefix.
const TARGET_SIGNATURE: &[u8; 6] = b"Target";

/// Target prefix: signature, `bAlternateSetting` (6), `bTargetNamed` (7),
/// `szTargetName[255]` (11), `dwTargetSize` (266), `dwNbElements` (270).
const TARGET_PREFIX_SIZE: usize = 274;
const TARGET_NAME_OFFSET: usize = 11;
const TARGET_NAME_SIZE: usize = 255;

/// Image element header: `dwElementAddress`, `dwElementSize`.
const ELEMENT_HEADER_SIZE: usize = 8;

/// Whether the file starts with the `DfuSe` signature.
pub(super) fn has_magic(data: &[u8]) -> bool {
    data.starts_with(DFUSE_SIGNATURE)
}

/// Read the suffix at the end of the file, verify its CRC-32 and require
/// the `DfuSe` `bcdDFU`; the prefix must fit before it.
fn suffix(data: &[u8]) -> Result<Suffix> {
    if data.len() < PREFIX_SIZE + SUFFIX_SIZE {
        return Err(error(format!(
            "Truncated DfuSe file: {} B cannot hold the prefix and the DFU suffix",
            data.len()
        )));
    }
    let suffix = dfu_suffix::read(data, data.len() - PREFIX_SIZE)?;
    if suffix.bcd_dfu != BCD_DFU_DFUSE {
        return Err(error(format!(
            "Unsupported DFU suffix bcdDFU 0x{:04X} at 0x{:X}; DfuSe files use \
             0x{BCD_DFU_DFUSE:04X}",
            suffix.bcd_dfu,
            suffix.bcd_dfu_offset()
        )));
    }
    Ok(suffix)
}

/// Parse a `DfuSe` file: each element is a load section at its address.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let prefix = slice(data, 0, PREFIX_SIZE)?;
    if prefix[5] != DFUSE_VERSION {
        return Err(error(format!(
            "Unsupported DfuSe bVersion {} at 0x5",
            prefix[5]
        )));
    }
    let image_size = le_u32(prefix, 6)?;
    let target_count = prefix[10];
    let suffix = suffix(data)?;
    let body = &data[..data.len() - suffix.size];

    let mut c = Container::new(
        FileFormat::Dfuse,
        Layout::Dfuse.label(),
        Layout::Dfuse.key_prefix(),
    );
    c.consumed = data.len();
    let mut sections = Sections::new();
    let mut element_count = 0;
    let mut pos = PREFIX_SIZE;
    for index in 0..target_count {
        let target = parse_target(&mut c, &mut sections, body, pos, index)?;
        element_count += target.elements;
        pos = target.end;
    }
    if pos != body.len() {
        return Err(error(format!(
            "Unexpected {} B after the last DfuSe target at 0x{pos:X}",
            body.len() - pos
        )));
    }
    c.notes.push(format!(
        "DfuSe: {}, {}; DFU suffix CRC-32 verified",
        count(usize::from(target_count), "target", "targets"),
        count(element_count, "element", "elements")
    ));
    sections.finish(&mut c);
    if u64::from(image_size) != body.len() as u64 {
        c.notes.push(format!(
            "DFUImageSize {image_size} B differs from the {} B before the suffix",
            body.len()
        ));
    }
    c.notes.push(format!(
        "USB vendor 0x{:04X}, product 0x{:04X} name the device, not an ISA; element addresses \
         are byte addresses in the memory each alternate setting selects, which is not encoded",
        suffix.vendor, suffix.product
    ));
    c.push_metadata(
        "dfuse_vendor_id",
        "USB vendor ID",
        format!("0x{:04X}", suffix.vendor),
    );
    c.push_metadata(
        "dfuse_product_id",
        "USB product ID",
        format!("0x{:04X}", suffix.product),
    );
    c.push_metadata(
        "dfuse_device_version",
        "bcdDevice",
        format!("0x{:04X}", suffix.device),
    );
    c.push_metadata("dfuse_target_count", "Targets", u64::from(target_count));
    Ok(c)
}

/// A parsed target image.
struct TargetImage {
    /// Number of elements.
    elements: usize,
    /// File offset after the target.
    end: usize,
}

/// Parse the target prefix at `pos` and its elements.
fn parse_target<'a>(
    c: &mut Container<'a>,
    sections: &mut Sections,
    body: &'a [u8],
    pos: usize,
    index: u8,
) -> Result<TargetImage> {
    let prefix = slice(body, pos, TARGET_PREFIX_SIZE)?;
    if &prefix[..TARGET_SIGNATURE.len()] != TARGET_SIGNATURE {
        return Err(error(format!(
            "Missing DfuSe Target signature at 0x{pos:X}"
        )));
    }
    let alternate = prefix[6];
    // pydfu reads bTargetNamed as a 32-bit boolean; dfu-util tests byte 7.
    let named = le_u32(prefix, 7)? != 0;
    let name = until_nul(&prefix[TARGET_NAME_OFFSET..TARGET_NAME_OFFSET + TARGET_NAME_SIZE]);
    let target_size = le_u32(prefix, 266)?;
    let element_count = le_u32(prefix, 270)?;
    let start = pos + TARGET_PREFIX_SIZE;
    let contents = usize::try_from(target_size)
        .ok()
        .and_then(|size| body.get(start..)?.get(..size))
        .ok_or_else(|| {
            error(format!(
                "Truncated DfuSe target {index} at 0x{pos:X}: dwTargetSize {target_size} B"
            ))
        })?;
    // Each element needs at least its 8-byte header.
    let element_count = usize::try_from(element_count)
        .ok()
        .filter(|count| *count <= contents.len() / ELEMENT_HEADER_SIZE)
        .ok_or_else(|| {
            error(format!(
                "Invalid DfuSe dwNbElements {element_count} at 0x{:X} for dwTargetSize \
                 {target_size} B",
                pos + 270
            ))
        })?;
    let mut at = 0;
    for element in 0..element_count {
        let element_offset = start + at;
        if contents.len() - at < ELEMENT_HEADER_SIZE {
            return Err(error(format!(
                "Truncated DfuSe element {element} header of target {index} at \
                 0x{element_offset:X}"
            )));
        }
        let address = le_u32(contents, at)?;
        let size = le_u32(contents, at + 4)?;
        let element_data = usize::try_from(size)
            .ok()
            .and_then(|size| contents.get(at + ELEMENT_HEADER_SIZE..)?.get(..size))
            .ok_or_else(|| {
                error(format!(
                    "Truncated DfuSe element {element} of target {index} at \
                     0x{element_offset:X}: dwElementSize {size} B"
                ))
            })?;
        sections.push(
            c,
            stored_section(
                format!("Target {alternate} element {}", element + 1),
                u64::from(address),
                element_offset + ELEMENT_HEADER_SIZE,
                element_data,
            ),
        );
        at += ELEMENT_HEADER_SIZE + element_data.len();
    }
    if at != contents.len() {
        return Err(error(format!(
            "Invalid DfuSe target {index} at 0x{pos:X}: elements hold {at} B of dwTargetSize \
             {target_size} B"
        )));
    }
    let name_text = if named {
        format!("named \"{}\"", String::from_utf8_lossy(name))
    } else {
        "unnamed".to_string()
    };
    c.push_metadata(
        format!("dfuse_target_{index}"),
        format!("Target {index}"),
        format!(
            "alternate setting {alternate}; {name_text}; {}; {target_size} B",
            count(element_count, "element", "elements")
        ),
    );
    Ok(TargetImage {
        elements: element_count,
        end: start + contents.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DFU 1.1 suffix CRC is the raw register, the complement of the
    /// zlib CRC-32 (CRC-32/JAMCRC check value).
    #[test]
    fn suffix_crc_is_the_uninverted_register() {
        use crate::formats::checksum;
        assert_eq!(checksum::crc32_update(!0, b"123456789"), 0x340b_c6d9);
        assert_eq!(
            checksum::crc32_update(!0, b"123456789"),
            !checksum::crc32(b"123456789")
        );
    }

    #[test]
    fn short_files_are_truncated_not_misread() {
        assert!(parse(b"DfuSe\x01").is_err());
        assert!(parse(b"DfuSe\x02\0\0\0\0\0").is_err());
        assert!(parse(&[b"DfuSe\x01\0\0\0\0\0".as_slice(), &[0; 16]].concat()).is_err());
    }
}
