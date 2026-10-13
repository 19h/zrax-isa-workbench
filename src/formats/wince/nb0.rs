//! Raw ROM images (`.nb0`): the image bytes from `physfirst` on, without a
//! file header (BLCOMMON loads a download without a sync as "a raw .nb0
//! file"; the Device Emulator calls it "a contiguous sequence of
//! instructions").
//!
//! Nothing says where the file is loaded, so the ROMHDR is found by its own
//! consistency: `ECEC` at offset 0x40 is followed by the ROMHDR's runtime
//! address, and the ROMHDR at file offset `o` must hold `physfirst` with
//! `o + physfirst == pointer` (`dumprom.cpp` `DetermineLoadOffset` searches
//! for the same identity). The ROMHDR is a structure of 32-bit fields, so
//! only 4-byte-aligned offsets are tried (our inference; `dumprom.cpp`
//! assumes 4 KiB-aligned bases).

use super::memory::{Memory, Region};
use super::rom::{self, Rom, RomHeader, Translation};
use super::*;
use crate::formats::container::{Container, Section};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// First file offset a ROMHDR may start at: after the signature and the
/// pointer.
const FIRST_HEADER_OFFSET: usize = 0x48;
/// Alignment of the ROMHDR offsets tried.
const HEADER_ALIGNMENT: usize = 4;
/// Most self-consistent ROMHDR positions examined in full. More than one
/// valid position is ambiguous anyway, so this only bounds the work.
const MAX_CANDIDATES: usize = 8;

/// A raw image whose ROM structure validated.
struct RawRom<'a> {
    /// The image, `physfirst` to `physlast`.
    image: &'a [u8],
    memory: Memory<'a>,
    rom: Rom,
}

/// ROMHDR positions consistent with `pointer` whose header fields fit the
/// file: `physfirst` below `physlast`, the image inside the file, the
/// ROMHDR and its tables inside the image, and at least one module.
fn candidates(data: &[u8], pointer: u32) -> Result<Vec<(usize, RomHeader)>> {
    let mut found = Vec::new();
    let mut offset = FIRST_HEADER_OFFSET;
    while offset + rom::ROMHDR_SIZE <= data.len() {
        let phys_first = le_u32(data, offset + 8)?;
        let address = u64::from(phys_first) + to_u64(offset);
        if address == u64::from(pointer) {
            let header = RomHeader::parse(&data[offset..], address)?;
            if fits(data, offset, &header) {
                if found.len() == MAX_CANDIDATES {
                    return Err(error(format!(
                        "Ambiguous raw ROM image: more than {MAX_CANDIDATES} ROMHDR positions are consistent with the pointer 0x{pointer:08X}"
                    )));
                }
                found.push((offset, header));
            }
        }
        offset += HEADER_ALIGNMENT;
    }
    Ok(found)
}

/// The cheap checks of [`candidates`].
fn fits(data: &[u8], offset: usize, header: &RomHeader) -> bool {
    let Some(size) = header.phys_last.checked_sub(header.phys_first) else {
        return false;
    };
    let size = u64::from(size);
    let tables_end = to_u64(offset + rom::ROMHDR_SIZE) + header.tables_size();
    size > 0 && size <= to_u64(data.len()) && tables_end <= size && header.module_count > 0
}

/// Validate a candidate ROMHDR that [`fits`]: only padding after the image,
/// and module and file tables that read completely.
fn validate(data: &[u8], header: RomHeader) -> Result<RawRom<'_>> {
    // `fits` established `physfirst < physlast` and an image inside the file.
    let size = to_usize(header.phys_last - header.phys_first);
    let (image, rest) = data.split_at(size);
    if !is_padding(rest) {
        return Err(error(format!(
            "Unexpected data after the raw ROM image at 0x{size:X}"
        )));
    }
    let memory = Memory::new(vec![Region {
        address: u64::from(header.phys_first),
        offset: 0,
        bytes: image,
    }]);
    let rom = rom::read(&memory, header, Translation::IDENTITY)?;
    Ok(RawRom { image, memory, rom })
}

/// The one consistent ROM structure of a raw image.
fn locate(data: &[u8]) -> Result<RawRom<'_>> {
    if le_u32(data, rom::ROM_SIGNATURE_OFFSET)? != rom::ROM_SIGNATURE {
        return Err(error("Missing ROM signature ECEC at 0x40"));
    }
    let pointer = le_u32(data, rom::ROM_TOC_POINTER_OFFSET)?;
    let found = candidates(data, pointer)?;
    // A single candidate reports why it fails; several must leave exactly
    // one valid structure.
    if let [(_, header)] = found.as_slice() {
        return validate(data, *header);
    }
    let mut valid: Vec<RawRom<'_>> = found
        .into_iter()
        .filter_map(|(_, header)| validate(data, header).ok())
        .collect();
    match valid.len() {
        0 => Err(error(format!(
            "Invalid raw ROM image: no ROMHDR is consistent with its position for the pointer 0x{pointer:08X}"
        ))),
        1 => Ok(valid.remove(0)),
        n => Err(error(format!(
            "Ambiguous raw ROM image: {n} ROMHDR positions validate for the pointer 0x{pointer:08X}"
        ))),
    }
}

/// Whether `data` is a raw ROM image with exactly one consistent ROM
/// structure.
pub(super) fn is_valid(data: &[u8]) -> bool {
    // Most inputs fail on the signature; test it before building errors.
    let signature = data.get(rom::ROM_SIGNATURE_OFFSET..rom::ROM_TOC_POINTER_OFFSET);
    signature == Some(&rom::ROM_SIGNATURE.to_le_bytes()[..]) && locate(data).is_ok()
}

/// Parse a raw ROM image: the image as one load section, and the ROM's
/// target, modules and files.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let raw = locate(data)?;
    let size = raw.image.len();
    let mut c = Container::new(FileFormat::WinCeImage, Layout::RawRom.label(), KEY_PREFIX);
    c.consumed = data.len();
    // The section is the file itself; it goes to the code model, never
    // back to detection.
    c.code_sections = true;
    let analyzed = &raw.image[..size.min(MAX_PAYLOAD)];
    c.sections.push(Section {
        label: "ROM image".into(),
        address: u64::from(raw.rom.header().phys_first),
        offset: 0,
        stored_size: analyzed.len(),
        data: Cow::Borrowed(analyzed),
        transform: None,
    });
    c.notes.push(format!(
        "Raw ROM image of {} loaded at 0x{:08X} (physfirst); no file header or checksums, and the image does not encode an entry point",
        size_text(to_u64(size)),
        raw.rom.header().phys_first
    ));
    if size > MAX_PAYLOAD {
        c.notes.push(format!(
            "Only the first {} of the image are analyzed as code",
            size_text(to_u64(MAX_PAYLOAD))
        ));
    }
    if data.len() > size {
        c.notes.push(format!(
            "{} of padding after the image",
            size_text(to_u64(data.len() - size))
        ));
    }
    rom::report(&mut c, &raw.rom, &raw.memory);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POINTER: u32 = 0x8000_0100;

    /// A ROMHDR at `offset` that is consistent with [`POINTER`]: `physfirst`
    /// (8), `physlast` (0xC) and `nummods` (0x10).
    fn put_header(data: &mut [u8], offset: usize, size: u32) {
        let phys_first = POINTER - u32::try_from(offset).expect("small offset");
        data[offset + 8..offset + 12].copy_from_slice(&phys_first.to_le_bytes());
        data[offset + 12..offset + 16].copy_from_slice(&(phys_first + size).to_le_bytes());
        data[offset + 16..offset + 20].copy_from_slice(&1u32.to_le_bytes());
    }

    #[test]
    fn candidates_must_fit_the_file_and_stay_few() {
        let mut data = vec![0u8; 0x1000];
        put_header(&mut data, 0x100, 0x1000);
        put_header(&mut data, 0x204, 0);
        put_header(&mut data, 0x308, 0x2000);
        let found = candidates(&data, POINTER).unwrap();
        assert_eq!(found.iter().map(|(o, _)| *o).collect::<Vec<_>>(), [0x100]);
        for i in 0..=MAX_CANDIDATES {
            put_header(&mut data, 0x400 + i * 0x80, 0x1000);
        }
        let message = candidates(&data, POINTER).unwrap_err().to_string();
        assert!(
            message.contains("more than 8 ROMHDR positions"),
            "{message}"
        );
    }

    #[test]
    fn weak_detection_needs_the_signature_first() {
        let mut data = vec![0u8; 0x200];
        put_header(&mut data, 0x100, 0x200);
        assert!(!is_valid(&data));
        assert!(locate(&data).is_err());
        data[0x40..0x44].copy_from_slice(&rom::ROM_SIGNATURE.to_le_bytes());
        data[0x44..0x48].copy_from_slice(&POINTER.to_le_bytes());
        // The header is consistent, but its one module entry is empty.
        assert!(!is_valid(&data));
        assert!(locate(&data).is_err());
    }
}
