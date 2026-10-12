//! TE (terse executable) images: `EFI_TE_IMAGE_HEADER` (PI 1.8 Vol. 1,
//! 15.2.1; EDK2 `MdePkg/Include/IndustryStandard/PeImage.h`), validated as
//! the EDK2 loader does (`MdePkg/Library/BasePeCoffLib/BasePeCoff.c`).
//!
//! Header (40 B): `VZ`, machine (u16, 0x02, copied from the PE COFF
//! header), section count (u8), subsystem (u8), stripped size (u16),
//! entry point RVA (u32, 0x08), base of code (u32, 0x0C), image base (u64,
//! 0x10), then the base-relocation and debug data directories. The PE
//! section headers follow at 0x28: EDK2 `GenFw` keeps them although PI 1.8
//! describes them as stripped. TE file offset `x` corresponds to original
//! file offset `x + stripped size - 40`.

use super::*;
use crate::formats::container::Section;
use crate::formats::pe;

/// `EFI_TE_IMAGE_HEADER_SIGNATURE`.
const TE_SIGNATURE: [u8; 2] = *b"VZ";
const TE_HEADER_SIZE: usize = 40;

/// `EFI_IMAGE_SECTION_HEADER`.
const SECTION_HEADER_SIZE: usize = 40;

/// The PE/COFF section limit the loader assumes.
const MAX_SECTIONS: usize = 96;

/// Section characteristics marking code.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// UEFI subsystems (EDK2 `PeImage.h`).
const EFI_APPLICATION: u8 = 10;
const EFI_BOOT_SERVICE_DRIVER: u8 = 11;
const EFI_RUNTIME_DRIVER: u8 = 12;
const SAL_RUNTIME_DRIVER: u8 = 13;

/// A data directory: RVA and size.
#[derive(Debug, Clone, Copy)]
struct Directory {
    address: u32,
    size: u32,
}

/// The fixed TE header.
#[derive(Debug)]
struct TeHeader {
    machine: u16,
    section_count: usize,
    subsystem: u8,
    stripped_size: u32,
    entry: u32,
    base_of_code: u32,
    image_base: u64,
    relocations: Directory,
    debug: Directory,
}

/// One section header, with offsets already translated to TE file
/// offsets.
#[derive(Debug)]
struct TeSection {
    name: String,
    virtual_address: u32,
    raw_offset: usize,
    raw_size: usize,
    characteristics: u32,
}

/// A validated image.
#[derive(Debug)]
struct TeImage {
    header: TeHeader,
    sections: Vec<TeSection>,
    /// `SizeOfHeaders` as EDK2 computes it for TE images.
    size_of_headers: usize,
    /// The entry point lies in the raw data of a section.
    entry_in_section: bool,
}

fn header(data: &[u8]) -> Result<TeHeader> {
    let fixed = data
        .get(..TE_HEADER_SIZE)
        .ok_or_else(|| error(format!("Truncated TE header: {} B present", data.len())))?;
    if fixed[..2] != TE_SIGNATURE {
        return Err(error("Missing TE signature"));
    }
    let directory = |at: usize| -> Result<Directory> {
        Ok(Directory {
            address: le_u32(fixed, at)?,
            size: le_u32(fixed, at + 4)?,
        })
    };
    Ok(TeHeader {
        machine: le_u16(fixed, 0x02)?,
        section_count: usize::from(fixed[0x04]),
        subsystem: fixed[0x05],
        stripped_size: u32::from(le_u16(fixed, 0x06)?),
        entry: le_u32(fixed, 0x08)?,
        base_of_code: le_u32(fixed, 0x0C)?,
        image_base: le_u64(fixed, 0x10)?,
        relocations: directory(0x18)?,
        debug: directory(0x20)?,
    })
}

/// The ISA the PE/COFF machine table gives for `machine`.
fn machine_target(machine: u16) -> Option<Target> {
    let (isa, bits, endianness, _) = pe::machine_to_isa(machine);
    (!matches!(isa, Isa::Unknown(_))).then_some(Target::new(isa, bits, endianness))
}

/// The ISA named by the machine field of the TE header at `data`.
pub(super) fn target(data: &[u8]) -> Option<Target> {
    header(data).ok().and_then(|h| machine_target(h.machine))
}

/// Strong recognition: `VZ`, a known machine, one to 96 sections whose
/// headers are present, and the stripped size and base of code the EDK2
/// loader requires.
pub(super) fn has_consistent_header(data: &[u8]) -> bool {
    let Ok(h) = header(data) else {
        return false;
    };
    machine_target(h.machine).is_some()
        && (1..=MAX_SECTIONS).contains(&h.section_count)
        && h.stripped_size as usize > TE_HEADER_SIZE
        && h.base_of_code > h.stripped_size
        && TE_HEADER_SIZE + h.section_count * SECTION_HEADER_SIZE <= data.len()
}

/// Weak recognition: every loader check passes and the entry point lies in
/// section data.
pub(super) fn is_complete_image(data: &[u8]) -> bool {
    validate(data).is_ok_and(|image| image.entry_in_section)
}

/// The checks of `PeCoffLoaderGetPeHeader` and the section checks of
/// `PeCoffLoaderGetImageInfo` for TE images, in that order.
fn validate(data: &[u8]) -> Result<TeImage> {
    let h = header(data)?;
    if h.section_count == 0 || h.section_count > MAX_SECTIONS {
        return Err(error(format!(
            "Invalid TE section count {}",
            h.section_count
        )));
    }
    if h.stripped_size as usize <= TE_HEADER_SIZE {
        return Err(error(format!(
            "Invalid TE stripped size 0x{:X}: not larger than the TE header",
            h.stripped_size
        )));
    }
    if h.base_of_code <= h.stripped_size {
        return Err(error(format!(
            "Invalid TE base of code 0x{:X}: not above the stripped size 0x{:X}",
            h.base_of_code, h.stripped_size
        )));
    }
    // TE file offset 0 corresponds to original offset `stripped - 40`.
    let stripped_offset = h.stripped_size as usize - TE_HEADER_SIZE;
    let size_of_headers = to_usize(h.base_of_code - h.stripped_size, "TE base of code")?
        .checked_add(TE_HEADER_SIZE)
        .ok_or_else(|| error("Invalid TE base of code: header size overflows"))?;
    if size_of_headers > data.len() {
        return Err(error(format!(
            "Truncated TE image: headers end at 0x{size_of_headers:X}, {} B present",
            data.len()
        )));
    }
    for (name, directory) in [("relocation", h.relocations), ("debug", h.debug)] {
        if directory.size != 0 && directory.address == 0 {
            return Err(error(format!(
                "Invalid TE {name} directory: {} B at RVA 0",
                directory.size
            )));
        }
    }
    let table_end = TE_HEADER_SIZE + h.section_count * SECTION_HEADER_SIZE;
    let table = data.get(TE_HEADER_SIZE..table_end).ok_or_else(|| {
        error(format!(
            "Truncated TE section headers: {} headers end at 0x{table_end:X}",
            h.section_count
        ))
    })?;
    let mut sections = Vec::with_capacity(h.section_count);
    for raw in table.chunks_exact(SECTION_HEADER_SIZE) {
        let section = section(raw, stripped_offset, size_of_headers, data.len())?;
        sections.push(section);
    }
    let entry_in_section = sections.iter().any(|s| {
        s.raw_size > 0
            && h.entry >= s.virtual_address
            && u64::from(h.entry) < u64::from(s.virtual_address) + s.raw_size as u64
    });
    Ok(TeImage {
        header: h,
        sections,
        size_of_headers,
        entry_in_section,
    })
}

/// One section header: name, virtual size, virtual address, raw size, raw
/// pointer (original file offset), relocation and line-number fields, then
/// characteristics (0x24).
fn section(
    raw: &[u8],
    stripped_offset: usize,
    size_of_headers: usize,
    image_size: usize,
) -> Result<TeSection> {
    let name_bytes = &raw[..8];
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
    let virtual_address = le_u32(raw, 0x0C)?;
    let raw_size = le_u32(raw, 0x10)?;
    let raw_pointer = le_u32(raw, 0x14)?;
    let characteristics = le_u32(raw, 0x24)?;
    let mut section = TeSection {
        name,
        virtual_address,
        raw_offset: 0,
        raw_size: raw_size as usize,
        characteristics,
    };
    if raw_size == 0 {
        return Ok(section);
    }
    let virtual_offset = te_offset(virtual_address, stripped_offset, size_of_headers);
    let raw_offset = te_offset(raw_pointer, stripped_offset, size_of_headers);
    let (Some(_), Some(raw_offset)) = (virtual_offset, raw_offset) else {
        return Err(error(format!(
            "Invalid TE section {}: data overlaps the headers",
            section.name
        )));
    };
    let raw_end = raw_offset.checked_add(section.raw_size);
    if raw_pointer.checked_add(raw_size).is_none() || raw_end.map_or(true, |end| end > image_size) {
        return Err(error(format!(
            "Truncated TE section {}: 0x{raw_offset:X} + {raw_size} B beyond {image_size} B",
            section.name
        )));
    }
    section.raw_offset = raw_offset;
    Ok(section)
}

/// The TE file offset of an original file offset or RVA (EDK2
/// `PeCoffLoaderAdjustOffsetForTeImage`), when it lies after the headers.
fn te_offset(value: u32, stripped_offset: usize, size_of_headers: usize) -> Option<usize> {
    usize::try_from(value)
        .ok()?
        .checked_sub(stripped_offset)
        .filter(|&offset| offset >= size_of_headers)
}

fn subsystem_name(subsystem: u8) -> String {
    match subsystem {
        EFI_APPLICATION => "EFI application".into(),
        EFI_BOOT_SERVICE_DRIVER => "EFI boot service driver".into(),
        EFI_RUNTIME_DRIVER => "EFI runtime driver".into(),
        SAL_RUNTIME_DRIVER => "SAL runtime driver".into(),
        other => format!("subsystem {other}"),
    }
}

/// Parse a standalone TE image. The machine field names the target; the
/// executable sections are the code the code model checks for byte order
/// and extensions.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let image = validate(data)?;
    let h = &image.header;
    let mut c = Container::new(FileFormat::UefiTe, layout.label(), KEY_PREFIX);
    c.target = machine_target(h.machine);
    c.entry = Some(u64::from(h.entry));
    c.code_sections = true;
    c.notes.push(format!(
        "TE image: machine 0x{:04X} ({}); {}; {} B of PE headers stripped; {} section headers; entry point RVA 0x{:X}",
        h.machine,
        pe::machine_description(h.machine),
        subsystem_name(h.subsystem),
        h.stripped_size,
        h.section_count,
        h.entry
    ));
    if c.target.is_none() {
        c.notes.push(format!(
            "Machine 0x{:04X} names no ISA in the PE/COFF machine table; the ISA comes from the code",
            h.machine
        ));
    }
    if !image.entry_in_section {
        c.notes
            .push("The entry point is outside the section data".into());
    }
    let mut end = image.size_of_headers;
    for s in &image.sections {
        if s.raw_size == 0 {
            continue;
        }
        end = end.max(s.raw_offset + s.raw_size);
        let executable = s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0;
        if executable {
            c.sections.push(Section {
                label: s.name.clone(),
                address: h.image_base.wrapping_add(u64::from(s.virtual_address)),
                offset: s.raw_offset,
                stored_size: s.raw_size,
                data: Cow::Borrowed(&data[s.raw_offset..s.raw_offset + s.raw_size]),
                transform: None,
            });
        }
    }
    c.consumed = end;
    c.push_metadata(
        format!("{KEY_PREFIX}_te_machine"),
        "TE machine",
        format!("0x{:04X}", h.machine),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_te_stripped_size"),
        "Stripped size (B)",
        u64::from(h.stripped_size),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_te_image_base"),
        "Image base",
        format!("0x{:X}", h.image_base),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_te_subsystem"),
        "Subsystem",
        subsystem_name(h.subsystem),
    );
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TE header for `machine` with one `.text` section of 16 B at RVA
    /// 0x1C0: the PE headers up to the end of the optional header (0x188 B)
    /// are stripped, so TE offset = RVA - 0x160 and the headers end at 0x60.
    fn te_image(machine: u16) -> Vec<u8> {
        let mut image = vec![0u8; TE_HEADER_SIZE];
        image[..2].copy_from_slice(&TE_SIGNATURE);
        image[2..4].copy_from_slice(&machine.to_le_bytes());
        image[4] = 1;
        image[5] = EFI_BOOT_SERVICE_DRIVER;
        image[6..8].copy_from_slice(&0x188u16.to_le_bytes());
        image[8..12].copy_from_slice(&0x1C0u32.to_le_bytes());
        image[12..16].copy_from_slice(&0x1C0u32.to_le_bytes());
        let mut header = [0u8; SECTION_HEADER_SIZE];
        header[..5].copy_from_slice(b".text");
        header[0x08..0x0C].copy_from_slice(&16u32.to_le_bytes());
        header[0x0C..0x10].copy_from_slice(&0x1C0u32.to_le_bytes());
        header[0x10..0x14].copy_from_slice(&16u32.to_le_bytes());
        header[0x14..0x18].copy_from_slice(&0x1C0u32.to_le_bytes());
        let code = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
        header[0x24..0x28].copy_from_slice(&code.to_le_bytes());
        image.extend_from_slice(&header);
        image.resize(0x60, 0);
        image.resize(0x70, 0xC3);
        image
    }

    #[test]
    fn edk2_offsets_place_sections_after_the_kept_headers() {
        let image = te_image(pe::machine::AMD64);
        assert!(has_consistent_header(&image));
        let parsed = validate(&image).unwrap();
        assert_eq!(parsed.size_of_headers, 0x60);
        assert_eq!(parsed.sections[0].raw_offset, 0x60);
        assert!(parsed.entry_in_section);
        assert_eq!(target(&image).map(|t| t.isa), Some(Isa::X86_64));
    }

    #[test]
    fn unknown_machines_are_only_structurally_recognized() {
        let image = te_image(0x1234);
        assert!(!has_consistent_header(&image));
        assert!(is_complete_image(&image));
        assert!(target(&image).is_none());
        let mut overlapping = te_image(pe::machine::AMD64);
        overlapping[0x28 + 0x14..0x28 + 0x18].copy_from_slice(&0x1A0u32.to_le_bytes());
        assert!(validate(&overlapping).is_err());
    }
}
