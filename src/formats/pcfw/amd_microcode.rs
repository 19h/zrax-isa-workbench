//! AMD microcode container files, as Linux v6.12
//! `arch/x86/kernel/cpu/microcode/amd.c` reads them (`verify_container`,
//! `verify_equivalence_table`, `__verify_patch_section`, `verify_patch`,
//! `parse_container`, `scan_containers`): the magic, an equivalence table
//! section, then patch sections, with further containers glued after the
//! last patch.
//!
//! The container format defines no checksum. The patch header carries a
//! checksum field whose algorithm Linux does not check and no source read
//! here documents, so it is reported as not verified.

use super::*;
use std::fmt::Write as _;

/// `UCODE_MAGIC`: `DMA\0` read as a little-endian u32.
const MAGIC: u32 = 0x0041_4D44;

/// `UCODE_EQUIV_CPU_TABLE_TYPE` and `UCODE_UCODE_TYPE`.
const EQUIVALENCE_TABLE_TYPE: u32 = 0;
const PATCH_TYPE: u32 = 1;

/// `CONTAINER_HDR_SZ`: magic, equivalence table type and table length.
const CONTAINER_HEADER_SIZE: usize = 12;

/// `SECTION_HDR_SIZE`: section type and size.
const SECTION_HEADER_SIZE: usize = 8;

/// `struct equiv_cpu_entry`: installed CPU signature (0), fixed errata
/// mask (4) and compare (8), equivalence ID (0xC, u16), reserved (0xE).
const EQUIVALENCE_ENTRY_SIZE: usize = 16;

/// `struct microcode_header_amd`: data code (0x00), patch ID (0x04),
/// patch data ID, length and init flag (0x08), patch data checksum (0x0C),
/// northbridge device ID (0x10), southbridge device ID (0x14), processor
/// revision ID (0x18, u16), northbridge and southbridge revision IDs, BIOS
/// API revision, reserved, then eight match registers (0x20).
const PATCH_HEADER_SIZE: usize = 64;

/// First note of every AMD microcode container.
const MICROCODE_NOTE: &str =
    "Microcode patch data for the processor's patch loader; excluded from ISA analysis";

/// The container magic at offset 0.
pub(super) fn has_magic(data: &[u8]) -> bool {
    le_u32(data, 0).ok() == Some(MAGIC)
}

/// One patch section.
#[derive(Debug)]
struct Patch<'a> {
    /// File offset of the patch, after its section header.
    offset: usize,
    bytes: &'a [u8],
    id: u32,
    data_code: u32,
    /// `processor_rev_id`: the equivalence ID the patch is for.
    equivalence_id: u16,
    /// A northbridge or southbridge device ID is set; Linux rejects such
    /// chipset-specific patches.
    chipset_specific: bool,
}

/// One container: its equivalence table and patches.
#[derive(Debug)]
struct Section<'a> {
    offset: usize,
    /// Installed-CPU signatures of the equivalence table, up to the
    /// all-zero entry that ends it.
    signatures: Vec<u32>,
    /// The table length is not a whole number of entries.
    partial_entry: bool,
    patches: Vec<Patch<'a>>,
    /// File offset after the last patch.
    end: usize,
}

/// Every container in `data` and where the last one ends.
fn sections(data: &[u8]) -> Result<(Vec<Section<'_>>, usize)> {
    let mut list: Vec<Section<'_>> = Vec::new();
    let mut pos = 0;
    while let Some(rest) = data.get(pos..).filter(|rest| !rest.is_empty()) {
        if !list.is_empty() && is_padding(rest) {
            break;
        }
        let section = parse_section(data, pos)?;
        // A container is at least its 12 B header and a 16 B entry.
        pos = section.end;
        list.push(section);
    }
    if list.is_empty() {
        return Err(error("Missing AMD microcode container header"));
    }
    Ok((list, pos))
}

/// The container at `offset`: header, equivalence table, then patch
/// sections up to the next container magic, padding or the end of the file.
fn parse_section(data: &[u8], offset: usize) -> Result<Section<'_>> {
    let header = field(
        data,
        offset,
        CONTAINER_HEADER_SIZE,
        "AMD microcode container header",
    )?;
    let magic = le_u32(header, 0)?;
    if magic != MAGIC {
        return Err(error(format!(
            "Invalid AMD microcode container magic 0x{magic:08X} at 0x{offset:X}"
        )));
    }
    let table_type = le_u32(header, 4)?;
    if table_type != EQUIVALENCE_TABLE_TYPE {
        return Err(error(format!(
            "Invalid AMD microcode equivalence table type {table_type} at 0x{:X}",
            offset + 4
        )));
    }
    let table_size = to_usize(le_u32(header, 8)?);
    if table_size < EQUIVALENCE_ENTRY_SIZE {
        return Err(error(format!(
            "Invalid AMD microcode equivalence table length {table_size} B at 0x{:X}: below one 16 B entry",
            offset + 8
        )));
    }
    let table_offset = offset + CONTAINER_HEADER_SIZE;
    let table = field(
        data,
        table_offset,
        table_size,
        "AMD microcode equivalence table",
    )?;
    let signatures = table
        .chunks_exact(EQUIVALENCE_ENTRY_SIZE)
        .map(|entry| u32::from_le_bytes(entry[..4].try_into().expect("entry has 16 bytes")))
        .take_while(|&cpu| cpu != 0)
        .collect();
    let mut section = Section {
        offset,
        signatures,
        partial_entry: table_size % EQUIVALENCE_ENTRY_SIZE != 0,
        patches: Vec::new(),
        end: table_offset + table_size,
    };
    while let Some(rest) = data.get(section.end..).filter(|rest| !rest.is_empty()) {
        if has_magic(rest) || is_padding(rest) {
            break;
        }
        let patch = parse_patch(data, section.end)?;
        section.end = patch.offset + patch.bytes.len();
        section.patches.push(patch);
    }
    Ok(section)
}

/// The patch section at `offset`: type 1, a size of at least the 64 B
/// patch header, and the patch inside the file.
fn parse_patch(data: &[u8], offset: usize) -> Result<Patch<'_>> {
    let header = field(
        data,
        offset,
        SECTION_HEADER_SIZE,
        "AMD microcode patch section header",
    )?;
    let section_type = le_u32(header, 0)?;
    if section_type != PATCH_TYPE {
        return Err(error(format!(
            "Invalid AMD microcode section type 0x{section_type:X} at 0x{offset:X}"
        )));
    }
    let size = to_usize(le_u32(header, 4)?);
    if size < PATCH_HEADER_SIZE {
        return Err(error(format!(
            "Invalid AMD microcode patch size {size} B at 0x{:X}: below the 64 B patch header",
            offset + 4
        )));
    }
    let patch_offset = offset + SECTION_HEADER_SIZE;
    let bytes = field(data, patch_offset, size, "AMD microcode patch")?;
    Ok(Patch {
        offset: patch_offset,
        bytes,
        data_code: le_u32(bytes, 0x00)?,
        id: le_u32(bytes, 0x04)?,
        equivalence_id: le_u16(bytes, 0x18)?,
        chipset_specific: le_u32(bytes, 0x10)? != 0 || le_u32(bytes, 0x14)? != 0,
    })
}

/// Parse a file of AMD microcode containers into a container whose
/// components are the opaque patches.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let (sections, end) = sections(data)?;
    let mut c = Container::new(
        FileFormat::AmdMicrocode,
        Layout::AmdMicrocode.label(),
        KEY_PREFIX,
    );
    c.notes.push(MICROCODE_NOTE.to_string());
    let patch_count: usize = sections.iter().map(|s| s.patches.len()).sum();
    c.notes.push(format!(
        "{} with {}; the container format has no checksum, and the patch checksum field is not verified",
        plural(sections.len(), "container", "containers"),
        plural(patch_count, "patch section", "patch sections")
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_amd_container_count"),
        "AMD microcode containers",
        sections.len() as u64,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_amd_patch_count"),
        "AMD microcode patches",
        patch_count as u64,
    );
    let mut listing = Listing::default();
    let mut patch_index = 0;
    for (i, section) in sections.iter().enumerate() {
        listing.note(&mut c, describe_section(i, section));
        for patch in &section.patches {
            if listing.admits_detail() {
                c.notes.push(describe_patch(patch, section));
                push_patch_metadata(&mut c, patch_index, patch);
            }
            let label = format!(
                "Microcode patch 0x{:08X} (equivalence ID 0x{:04X})",
                patch.id, patch.equivalence_id
            );
            listing.push(&mut c, Child::opaque(label, patch.offset, patch.bytes));
            patch_index += 1;
        }
    }
    c.notes.extend(padding_note(data, end));
    c.consumed = data.len();
    c.opaque = true;
    listing.finish(&mut c);
    Ok(c)
}

fn describe_section(index: usize, section: &Section<'_>) -> String {
    let signatures: Vec<String> = section
        .signatures
        .iter()
        .map(|s| format!("0x{s:08X}"))
        .collect();
    let mut note = format!(
        "Container {} at 0x{:X}: equivalence table with {}",
        index + 1,
        section.offset,
        plural(
            section.signatures.len(),
            "processor signature",
            "processor signatures"
        )
    );
    if !signatures.is_empty() {
        let _ = write!(note, " ({})", listed(&signatures));
    }
    if section.partial_entry {
        note.push_str("; the table length is not a multiple of 16 B");
    }
    let _ = write!(
        note,
        "; {}",
        plural(section.patches.len(), "patch", "patches")
    );
    note
}

fn describe_patch(patch: &Patch<'_>, section: &Section<'_>) -> String {
    let mut note = format!(
        "Patch 0x{:08X} at 0x{:X}: {}, equivalence ID 0x{:04X}, data code 0x{:08X}",
        patch.id,
        patch.offset,
        size_text(patch.bytes.len()),
        patch.equivalence_id,
        patch.data_code
    );
    if patch.chipset_specific {
        note.push_str("; names a northbridge or southbridge device (chipset-specific, which Linux does not load)");
    }
    if section.signatures.is_empty() {
        note.push_str("; the equivalence table is empty");
    }
    note
}

fn push_patch_metadata(c: &mut Container<'_>, index: usize, patch: &Patch<'_>) {
    let ordinal = index + 1;
    c.push_metadata(
        format!("{KEY_PREFIX}_amd_patch_{index}_id"),
        format!("Patch {ordinal} ID"),
        format!("0x{:08X}", patch.id),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_amd_patch_{index}_equivalence_id"),
        format!("Patch {ordinal} equivalence ID"),
        format!("0x{:04X}", patch.equivalence_id),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_reads_as_dma() {
        assert!(has_magic(b"DMA\0rest"));
        assert!(!has_magic(b"DMA"));
        assert_eq!(MAGIC.to_le_bytes(), *b"DMA\0");
    }

    #[test]
    fn short_patch_sizes_are_rejected() {
        let mut section = vec![1, 0, 0, 0, 63, 0, 0, 0];
        section.resize(8 + 63, 0);
        let message = parse_patch(&section, 0).unwrap_err().to_string();
        assert!(message.contains("below the 64 B patch header"), "{message}");
    }
}
