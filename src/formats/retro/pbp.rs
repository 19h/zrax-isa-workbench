//! PSP `EBOOT.PBP` packages (PSPSDK `tools/pack-pbp.c` at `e2b2b313`;
//! PPSSPP `Core/ELF/PBPReader.cpp`, `Core/ELF/PrxDecrypter.h` and
//! `Core/ELF/ParamSFO.cpp` at `b419238f`).
//!
//! Header (0x28 bytes, little-endian): magic `\0PBP`, version (4,
//! 0x00010000), then the file offsets of eight subfiles: `PARAM.SFO`,
//! `ICON0.PNG`, `ICON1.PMF`, `PIC0.PNG`, `PIC1.PNG`, `SND0.AT3`, `DATA.PSP`
//! and `DATA.PSAR`. A subfile ends where the next one starts (the last at
//! the end of the file), so equal offsets mark an absent subfile.
//!
//! `DATA.PSP` is the executable: a plain ELF or PRX in homebrew, or an
//! encrypted `~PSP` module (0x150-byte header: attribute (2) at 4,
//! compression attribute (2) at 6, module name (28) at 0x0A, decrypted ELF
//! size (4) at 0x28, module size (4) at 0x2C), optionally inside a `~SCE`
//! wrapper whose second word is its header size. PPSSPP falls back to a
//! plain ELF stored at 0x150 of a `~PSP` module.
//!
//! `PARAM.SFO` is a PSF table: magic `\0PSF`, version, key table offset,
//! data table offset and entry count (4 each), then 16-byte index entries.

use super::*;

/// `\0PBP` at offset 0.
const MAGIC: &[u8; 4] = b"\0PBP";

/// Header size: magic, version and eight subfile offsets.
const HEADER_SIZE: usize = 0x28;
const VERSION: usize = 4;
const OFFSETS: usize = 8;

/// The version pack-pbp writes.
const VERSION_1_0: u32 = 0x0001_0000;

/// Subfiles, in header order.
const SUBFILES: [&str; 8] = [
    "PARAM.SFO",
    "ICON0.PNG",
    "ICON1.PMF",
    "PIC0.PNG",
    "PIC1.PNG",
    "SND0.AT3",
    "DATA.PSP",
    "DATA.PSAR",
];
const PARAM_SFO: usize = 0;
const DATA_PSP: usize = 6;

/// ELF magic, for a plain `DATA.PSP`.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// Encrypted module header (`PSP_Header`) and the fields reported.
const PSP_MODULE_MAGIC: &[u8; 4] = b"~PSP";
const PSP_HEADER_SIZE: usize = 0x150;
const PSP_COMP_ATTRIBUTE: usize = 0x06;
const PSP_MODNAME: usize = 0x0a;
const PSP_MODNAME_SIZE: usize = 28;
const PSP_ELF_SIZE: usize = 0x28;
const PSP_MODULE_SIZE: usize = 0x2c;

/// `comp_attribute` bit 0: the decrypted payload is compressed.
const PSP_COMPRESSED: u16 = 0x1;

/// Outer `~SCE` wrapper: magic, then its header size.
const SCE_WRAPPER_MAGIC: &[u8; 4] = b"~SCE";
const SCE_HEADER_SIZE: usize = 4;

/// PSF (`PARAM.SFO`) header: magic, version, key table offset, data table
/// offset and entry count.
const PSF_MAGIC: &[u8; 4] = b"\0PSF";
const PSF_KEY_TABLE: usize = 8;
const PSF_DATA_TABLE: usize = 12;
const PSF_ENTRY_COUNT: usize = 16;
const PSF_HEADER_SIZE: usize = 20;

/// PSF index entry: key offset (2), data format (2), data length (4),
/// maximum data length (4), data offset (4). This layout is PPSSPP's
/// `IndexTable` in `ParamSFO.cpp`, from the implementer's reading; the
/// collected spec notes give only the PSF header.
const PSF_ENTRY_SIZE: usize = 16;
const PSF_ENTRY_DATA_LENGTH: usize = 4;
const PSF_ENTRY_DATA_OFFSET: usize = 12;

/// PSF keys reported in notes.
const PSF_TITLE: &str = "TITLE";
const PSF_CATEGORY: &str = "CATEGORY";
const PSF_DISC_ID: &str = "DISC_ID";

/// The PSP CPU, a little-endian MIPS32 core (PSPSDK and PPSSPP read every
/// PSP ELF as little-endian MIPS).
const ALLEGREX: Target = Target::new(Isa::Mips, 32, Endianness::Little);

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// The byte ranges of the eight subfiles; absent subfiles are empty.
fn subfile_regions(data: &[u8]) -> Result<[Region; 8]> {
    let mut offsets = [0usize; 8];
    for (index, offset) in offsets.iter_mut().enumerate() {
        let at = OFFSETS + 4 * index;
        *offset = usize::try_from(le_u32(data, at)?)
            .map_err(|_| error(format!("Invalid PBP {} offset", SUBFILES[index])))?;
    }
    let mut previous = HEADER_SIZE;
    for (index, &offset) in offsets.iter().enumerate() {
        if offset < previous || offset > data.len() {
            return Err(error(format!(
                "Invalid PBP {} offset 0x{offset:X}: offsets must increase from 0x{HEADER_SIZE:X} and stay within the {} file",
                SUBFILES[index],
                size_text(data.len())
            )));
        }
        previous = offset;
    }
    let mut regions = [Region { offset: 0, size: 0 }; 8];
    for (index, region) in regions.iter_mut().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(data.len());
        *region = Region {
            offset: offsets[index],
            size: end - offsets[index],
        };
    }
    Ok(regions)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated PBP header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing PBP magic"));
    }
    let version = le_u32(data, VERSION)?;
    let regions = subfile_regions(data)?;

    let mut c = Container::new(FileFormat::PspPbp, "Allegrex", "psp");
    c.target = Some(ALLEGREX);
    c.consumed = data.len();
    let present = regions.iter().filter(|region| region.size > 0).count();
    c.notes.push(format!(
        "PSP EBOOT.PBP version 0x{version:08X}; {present} of 8 subfiles present"
    ));
    if version != VERSION_1_0 {
        c.notes.push(format!(
            "PBP version 0x{version:08X} differs from the 0x{VERSION_1_0:08X} pack-pbp writes"
        ));
    }
    for (index, region) in regions.into_iter().enumerate() {
        if region.size == 0 {
            continue;
        }
        let start = region.offset;
        let bytes = &data[start..region.end()];
        match index {
            PARAM_SFO => {
                push_param_sfo_notes(&mut c, bytes);
                c.children
                    .push(Child::opaque(SUBFILES[index], start, bytes));
            }
            DATA_PSP => push_data_psp(&mut c, start, bytes),
            _ => c
                .children
                .push(Child::opaque(SUBFILES[index], start, bytes)),
        }
    }
    c.notes.push(
        "The PBP header names no CPU; the PSP CPU is the little-endian MIPS32 Allegrex".to_string(),
    );
    Ok(c)
}

/// `DATA.PSP`: a plain ELF is classified from its own header; an encrypted
/// `~PSP` module is opaque unless it stores a plain ELF at 0x150.
fn push_data_psp<'a>(c: &mut Container<'a>, offset: usize, bytes: &'a [u8]) {
    let label = SUBFILES[DATA_PSP];
    if bytes.starts_with(ELF_MAGIC) {
        c.notes
            .push("DATA.PSP is a plain ELF; its own header names the ISA".to_string());
        c.children.push(Child::stored(label, offset, bytes));
        return;
    }
    let module_offset = sce_wrapped_module(bytes);
    let module = &bytes[module_offset..];
    if !module.starts_with(PSP_MODULE_MAGIC) {
        c.notes
            .push("DATA.PSP is neither an ELF nor a ~PSP module; not analyzed".to_string());
        c.children.push(Child::opaque(label, offset, bytes));
        return;
    }
    push_module_note(c, module, module_offset);
    let elf_end = le_u32(module, PSP_MODULE_SIZE)
        .ok()
        .and_then(|size| usize::try_from(size).ok())
        .map_or(module.len(), |size| size.min(module.len()));
    let has_plain_elf = elf_end > PSP_HEADER_SIZE
        && module
            .get(PSP_HEADER_SIZE..)
            .is_some_and(|rest| rest.starts_with(ELF_MAGIC));
    if !has_plain_elf {
        c.children.push(Child::opaque(label, offset, bytes));
        return;
    }
    let elf_offset = module_offset + PSP_HEADER_SIZE;
    c.notes.push(format!(
        "DATA.PSP stores a plain ELF at 0x{elf_offset:X} after the ~PSP header"
    ));
    c.children.push(Child::opaque(
        "DATA.PSP header",
        offset,
        &bytes[..elf_offset],
    ));
    c.children.push(Child::stored(
        "DATA.PSP ELF",
        offset + elf_offset,
        &module[PSP_HEADER_SIZE..elf_end],
    ));
}

/// Where the `~PSP` module starts: after a `~SCE` wrapper's header, if one
/// is present and its size stays inside the subfile; otherwise at 0.
fn sce_wrapped_module(bytes: &[u8]) -> usize {
    if !bytes.starts_with(SCE_WRAPPER_MAGIC) {
        return 0;
    }
    le_u32(bytes, SCE_HEADER_SIZE)
        .ok()
        .and_then(|size| usize::try_from(size).ok())
        .filter(|size| *size <= bytes.len())
        .unwrap_or(0)
}

fn push_module_note(c: &mut Container<'_>, module: &[u8], module_offset: usize) {
    let wrapper = if module_offset > 0 {
        format!(" inside a ~SCE wrapper ({module_offset} B header)")
    } else {
        String::new()
    };
    let name = slice(module, PSP_MODNAME, PSP_MODNAME_SIZE).map_or_else(|_| String::new(), text);
    let sizes = match (
        le_u32(module, PSP_ELF_SIZE),
        le_u32(module, PSP_MODULE_SIZE),
    ) {
        (Ok(elf_size), Ok(module_size)) => {
            format!("; module {module_size} B, decrypted ELF {elf_size} B")
        }
        _ => "; truncated ~PSP header".to_string(),
    };
    let compressed = match le_u16(module, PSP_COMP_ATTRIBUTE) {
        Ok(attribute) if attribute & PSP_COMPRESSED != 0 => "; payload compressed",
        _ => "",
    };
    c.notes.push(format!(
        "DATA.PSP is an encrypted ~PSP module{wrapper}; name {name}{sizes}{compressed}; not decrypted"
    ));
}

/// Title, category and disc ID from `PARAM.SFO`, when it is a readable
/// PSF table.
fn push_param_sfo_notes(c: &mut Container<'_>, sfo: &[u8]) {
    let Some(entries) = psf_entries(sfo) else {
        c.notes
            .push("PARAM.SFO is not a readable PSF table".to_string());
        return;
    };
    let value = |key: &str| {
        entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value.clone())
    };
    let mut fields = Vec::new();
    for (key, label) in [
        (PSF_TITLE, "title"),
        (PSF_CATEGORY, "category"),
        (PSF_DISC_ID, "disc ID"),
    ] {
        if let Some(text) = value(key) {
            fields.push(format!("{label} {text}"));
        }
    }
    if let Some(title) = value(PSF_TITLE) {
        c.push_metadata("psp_title", "Title", title);
    }
    if !fields.is_empty() {
        c.notes.push(format!("PARAM.SFO: {}", fields.join("; ")));
    }
}

/// A PSF entry with a text key and its value as text (UTF-8, up to the
/// first NUL).
struct PsfEntry {
    key: String,
    value: String,
}

/// The entries of a PSF table, or `None` when the header or an entry
/// points outside it. The entry count is checked against the table size
/// before anything is read.
fn psf_entries(sfo: &[u8]) -> Option<Vec<PsfEntry>> {
    if !sfo.starts_with(PSF_MAGIC) {
        return None;
    }
    let key_table = usize::try_from(le_u32(sfo, PSF_KEY_TABLE).ok()?).ok()?;
    let data_table = usize::try_from(le_u32(sfo, PSF_DATA_TABLE).ok()?).ok()?;
    let count = usize::try_from(le_u32(sfo, PSF_ENTRY_COUNT).ok()?).ok()?;
    if count > sfo.len().saturating_sub(PSF_HEADER_SIZE) / PSF_ENTRY_SIZE {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry = slice(
            sfo,
            PSF_HEADER_SIZE + index * PSF_ENTRY_SIZE,
            PSF_ENTRY_SIZE,
        )
        .ok()?;
        let key_offset = usize::from(le_u16(entry, 0).ok()?);
        let length = usize::try_from(le_u32(entry, PSF_ENTRY_DATA_LENGTH).ok()?).ok()?;
        let data_offset = usize::try_from(le_u32(entry, PSF_ENTRY_DATA_OFFSET).ok()?).ok()?;
        let key = sfo.get(key_table.checked_add(key_offset)?..)?;
        let value_at = data_table.checked_add(data_offset)?;
        let value = slice(sfo, value_at, length).ok()?;
        entries.push(PsfEntry {
            key: nul_terminated(key),
            value: nul_terminated(value),
        });
    }
    Some(entries)
}

/// UTF-8 text up to the first NUL, with control characters removed.
fn nul_terminated(bytes: &[u8]) -> String {
    let end = memchr::memchr(0, bytes).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subfile_offsets_must_increase_and_stay_inside_the_file() {
        let mut header = vec![0u8; HEADER_SIZE + 4];
        header[..4].copy_from_slice(MAGIC);
        for index in 0..8 {
            let offset = if index == 0 {
                HEADER_SIZE
            } else {
                HEADER_SIZE + 4
            };
            header[OFFSETS + 4 * index..OFFSETS + 4 * index + 4].copy_from_slice(
                &u32::try_from(offset)
                    .expect("test offset fits")
                    .to_le_bytes(),
            );
        }
        let regions = subfile_regions(&header).unwrap();
        assert_eq!(
            regions[0],
            Region {
                offset: HEADER_SIZE,
                size: 4
            }
        );
        assert_eq!(regions[7].size, 0);
        header[OFFSETS + 4..OFFSETS + 8].copy_from_slice(&0x20u32.to_le_bytes());
        assert!(subfile_regions(&header).is_err());
    }

    #[test]
    fn psf_entry_counts_beyond_the_table_are_refused() {
        let mut sfo = vec![0u8; PSF_HEADER_SIZE];
        sfo[..4].copy_from_slice(PSF_MAGIC);
        sfo[PSF_ENTRY_COUNT..PSF_ENTRY_COUNT + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(psf_entries(&sfo).is_none());
        assert!(psf_entries(&sfo[..3]).is_none());
    }
}
