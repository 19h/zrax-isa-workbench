//! The executable sections of a dumped module, read from the PE headers at
//! its base address when the dump holds them.
//!
//! Source: Microsoft "PE Format" (MicrosoftDocs/win32 commit `ca8274de`,
//! `desktop-src/Debug/pe-format.md`): "MS-DOS Stub (Image Only)" (the PE
//! signature offset at 0x3C),
//! "Signature (Image Only)" (`PE\0\0`), "COFF File Header (Object and
//! Image)" (`NumberOfSections` at 2, `SizeOfOptionalHeader` at 16 of the
//! 20-byte header), "Section Table (Section Headers)" (40-byte entries:
//! `VirtualSize` at 8, `VirtualAddress` at 12, `SizeOfRawData` at 16,
//! `Characteristics` at 36; "the Windows loader limits the number of
//! sections to 96") and "Section Flags" (`IMAGE_SCN_CNT_CODE`,
//! `IMAGE_SCN_MEM_EXECUTE`). A loaded section starts at the image base plus
//! its `VirtualAddress`. PE headers are little-endian whatever the dump's
//! byte order.

/// `IMAGE_DOS_SIGNATURE`.
const DOS_SIGNATURE: &[u8; 2] = b"MZ";

/// `e_lfanew`: the file offset of the PE signature.
const PE_OFFSET_FIELD: usize = 0x3c;

/// The PE signature before the COFF file header.
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";

/// COFF file header size and the offsets of `NumberOfSections` and
/// `SizeOfOptionalHeader` in it.
const COFF_HEADER_SIZE: usize = 20;
const NUMBER_OF_SECTIONS_OFFSET: usize = 2;
const SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 16;

/// Section header size and the offsets of the fields read from it.
const SECTION_HEADER_SIZE: usize = 40;
const VIRTUAL_SIZE_OFFSET: usize = 8;
const VIRTUAL_ADDRESS_OFFSET: usize = 12;
const SIZE_OF_RAW_DATA_OFFSET: usize = 16;
const CHARACTERISTICS_OFFSET: usize = 36;

/// The Windows loader's section limit.
const MAX_SECTIONS: usize = 96;

/// Section flags that mark code: "The section contains executable code"
/// and "The section can be executed as code".
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// An executable section's `[start, end)` target addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Section {
    pub(super) start: u64,
    pub(super) end: u64,
}

impl Section {
    /// Whether the section shares an address with `[start, end)`.
    pub(super) fn overlaps(self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

/// The executable sections of the image loaded at `base` whose first bytes
/// are `header`, or `None` when `header` is not a complete PE header: no
/// `MZ` or PE signature, more sections than the loader accepts, or a
/// section table that ends past `header`. An image whose sections are all
/// data gives an empty list.
pub(super) fn executable_sections(header: &[u8], base: u64) -> Option<Vec<Section>> {
    if header.get(..DOS_SIGNATURE.len())? != DOS_SIGNATURE {
        return None;
    }
    let pe_offset = usize::try_from(le_u32(header, PE_OFFSET_FIELD)?).ok()?;
    let coff = pe_offset.checked_add(PE_SIGNATURE.len())?;
    if header.get(pe_offset..coff)? != PE_SIGNATURE {
        return None;
    }
    let section_count = usize::from(le_u16(header, coff + NUMBER_OF_SECTIONS_OFFSET)?);
    if section_count > MAX_SECTIONS {
        return None;
    }
    let optional_size = usize::from(le_u16(header, coff + SIZE_OF_OPTIONAL_HEADER_OFFSET)?);
    let table_start = coff
        .checked_add(COFF_HEADER_SIZE)?
        .checked_add(optional_size)?;
    let table_end = table_start.checked_add(section_count * SECTION_HEADER_SIZE)?;
    let table = header.get(table_start..table_end)?;
    let sections = table
        .chunks_exact(SECTION_HEADER_SIZE)
        .filter_map(|entry| executable_section(entry, base))
        .collect();
    Some(sections)
}

/// The section a section header describes, if it is executable. A loaded
/// section spans `VirtualSize` bytes; the larger of it and `SizeOfRawData`
/// is used, so that a linker that leaves `VirtualSize` 0 does not hide the
/// section.
fn executable_section(entry: &[u8], base: u64) -> Option<Section> {
    let characteristics = le_u32(entry, CHARACTERISTICS_OFFSET)?;
    if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
        return None;
    }
    let virtual_size = le_u32(entry, VIRTUAL_SIZE_OFFSET)?;
    let raw_size = le_u32(entry, SIZE_OF_RAW_DATA_OFFSET)?;
    let start = base.checked_add(u64::from(le_u32(entry, VIRTUAL_ADDRESS_OFFSET)?))?;
    let end = start.checked_add(u64::from(virtual_size.max(raw_size)))?;
    Some(Section { start, end })
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `MZ` header with `e_lfanew` 0x80, the PE signature, a COFF header
    /// with `section_count` sections and a 0xF0-byte optional header, then
    /// the given section headers (`VirtualSize`, `VirtualAddress`,
    /// `SizeOfRawData`, `Characteristics`).
    fn header(section_count: u16, sections: &[[u32; 4]]) -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        data[..2].copy_from_slice(DOS_SIGNATURE);
        data[PE_OFFSET_FIELD..PE_OFFSET_FIELD + 4].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(PE_SIGNATURE);
        data[0x86..0x88].copy_from_slice(&section_count.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let table = 0x84 + COFF_HEADER_SIZE + 0xF0;
        for (i, [virtual_size, address, raw_size, characteristics]) in sections.iter().enumerate() {
            let entry = table + i * SECTION_HEADER_SIZE;
            data[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
            data[entry + 12..entry + 16].copy_from_slice(&address.to_le_bytes());
            data[entry + 16..entry + 20].copy_from_slice(&raw_size.to_le_bytes());
            data[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
        }
        data
    }

    const TEXT: u32 = 0x6000_0020;
    const DATA: u32 = 0xC000_0040;

    #[test]
    fn executable_sections_are_placed_at_the_image_base() {
        let data = header(
            3,
            &[
                [0x1800, 0x1000, 0x2000, TEXT],
                [0x100, 0x3000, 0x200, DATA],
                [0, 0x4000, 0x200, TEXT],
            ],
        );
        let sections = executable_sections(&data, 0x40_0000).expect("valid header");
        assert_eq!(
            sections,
            [
                Section {
                    start: 0x40_1000,
                    end: 0x40_3000
                },
                Section {
                    start: 0x40_4000,
                    end: 0x40_4200
                },
            ]
        );
        assert!(sections[0].overlaps(0x40_2FFF, 0x40_3001));
        assert!(!sections[0].overlaps(0x40_3000, 0x40_3100));
        assert!(!sections[0].overlaps(0x40_0000, 0x40_1000));
    }

    #[test]
    fn incomplete_headers_give_no_section_list() {
        let valid = header(1, &[[0x100, 0x1000, 0x200, TEXT]]);
        assert!(executable_sections(&valid, 0).is_some());
        let mut no_mz = valid.clone();
        no_mz[0] = b'Z';
        assert_eq!(executable_sections(&no_mz, 0), None);
        let mut no_pe = valid.clone();
        no_pe[0x80] = 0;
        assert_eq!(executable_sections(&no_pe, 0), None);
        let mut far_pe = valid.clone();
        far_pe[PE_OFFSET_FIELD..PE_OFFSET_FIELD + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(executable_sections(&far_pe, 0), None);
        assert_eq!(executable_sections(&header(97, &[]), 0), None);
        let table_end = 0x84 + COFF_HEADER_SIZE + 0xF0 + SECTION_HEADER_SIZE;
        assert_eq!(executable_sections(&valid[..table_end - 1], 0), None);
        assert!(executable_sections(&valid[..table_end], 0).is_some());
        assert_eq!(
            executable_sections(&header(1, &[[0x100, 0x1000, 0x200, DATA]]), 0),
            Some(Vec::new())
        );
    }

    #[test]
    fn section_addresses_that_overflow_are_dropped() {
        let data = header(1, &[[0x100, 0x1000, 0x200, TEXT]]);
        assert_eq!(
            executable_sections(&data, u64::MAX - 0x800),
            Some(Vec::new())
        );
    }
}
