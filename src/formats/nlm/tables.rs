//! The module dependency list (`binutils/nlmconv.c`), the relocation
//! fixups and import records (`read_reloc` and `read_import` of
//! `bfd/nlm32-*.c`), the export and debug records (`bfd/nlmcode.h`
//! `nlm_slurp_symbol_table`) and the Cygnus section table
//! (`nlm_swap_auxiliary_headers_in`).
//!
//! Each table is walked record by record, so a count that does not match
//! the stored records is an error. Counts are first checked against the
//! bytes after the table's offset, divided by the smallest record.

use super::*;

/// Smallest module dependency record: the length byte of an empty name.
const MIN_DEPENDENCY_SIZE: usize = 1;
/// Smallest import record: the name length byte and the relocation count.
const MIN_EXTERNAL_SIZE: usize = 1 + WORD_SIZE;
/// Smallest export record: the name length byte and the offset word.
const MIN_PUBLIC_SIZE: usize = 1 + WORD_SIZE;
/// Smallest debug record: type byte, value word and name length byte.
const MIN_DEBUG_RECORD_SIZE: usize = 2 + WORD_SIZE;

/// Cygnus section names, with their NUL, are padded to this boundary.
const CYGNUS_NAME_ALIGNMENT: usize = 4;
/// Each Cygnus section name is followed by its file position and size.
const CYGNUS_ENTRY_WORDS: usize = 2;

/// The module dependency list.
pub(super) struct Dependencies {
    /// The first [`MAX_LISTED_DEPENDENCIES`] names.
    pub(super) names: Vec<String>,
    /// Dependencies after those.
    pub(super) unlisted: u64,
    /// File offset just past the list, or 0 when it is empty.
    pub(super) end: usize,
}

/// A cursor at the first record of a non-empty table whose count fits the
/// bytes after its offset; `None` for an empty table, whose offset is not
/// checked (writers point it at the end of the file).
fn records<'a>(
    reader: Reader<'a>,
    table: Table,
    min_record: usize,
    what: &str,
) -> Result<Option<Cursor<'a>>> {
    if table.count == 0 {
        return Ok(None);
    }
    let offset = to_usize(table.offset);
    let Some(remaining) = reader.data.len().checked_sub(offset) else {
        return Err(error(format!("Truncated {what} at 0x{offset:X}")));
    };
    if to_usize(table.count) > remaining / min_record {
        return Err(error(format!(
            "Invalid {what} count {} at 0x{offset:X} ({remaining} B remain)",
            table.count
        )));
    }
    Ok(Some(Cursor::new(reader, offset)))
}

/// Module dependencies: a length byte and the name, without a NUL.
pub(super) fn module_dependencies(reader: Reader<'_>, table: Table) -> Result<Dependencies> {
    let mut dependencies = Dependencies {
        names: Vec::new(),
        unlisted: 0,
        end: 0,
    };
    let what = "module dependencies";
    let Some(mut cursor) = records(reader, table, MIN_DEPENDENCY_SIZE, what)? else {
        return Ok(dependencies);
    };
    for _ in 0..table.count {
        let name = cursor.counted("module dependency name")?;
        if dependencies.names.len() < MAX_LISTED_DEPENDENCIES {
            dependencies.names.push(display_text(name));
        } else {
            dependencies.unlisted += 1;
        }
    }
    dependencies.end = cursor.pos;
    Ok(dependencies)
}

/// Relocation fixups: fixed-size records of the target's relocation
/// format. Returns the end of the table, or 0 when it is empty.
pub(super) fn relocation_fixups(
    reader: Reader<'_>,
    table: Table,
    backend: &Backend,
) -> Result<usize> {
    let what = "relocation fixups";
    let Some(mut cursor) = records(reader, table, backend.reloc_size, what)? else {
        return Ok(0);
    };
    // The count check above bounds the product by the file size.
    cursor.bytes(to_usize(table.count) * backend.reloc_size, what)?;
    Ok(cursor.pos)
}

/// Import records: the name and a relocation count (SPARC stores the count
/// first), then that many relocation records. Returns the end of the
/// table, or 0 when it is empty.
pub(super) fn external_references(
    reader: Reader<'_>,
    table: Table,
    backend: &Backend,
) -> Result<usize> {
    let what = "external references";
    let Some(mut cursor) = records(reader, table, MIN_EXTERNAL_SIZE, what)? else {
        return Ok(0);
    };
    for _ in 0..table.count {
        let relocations = if backend.count_before_name {
            let relocations = cursor.word("external reference relocation count")?;
            cursor.counted("external reference name")?;
            relocations
        } else {
            cursor.counted("external reference name")?;
            cursor.word("external reference relocation count")?
        };
        let at = cursor.pos;
        let size = to_usize(relocations)
            .checked_mul(backend.reloc_size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid external reference relocation count {relocations} at 0x{at:X}"
                ))
            })?;
        cursor.bytes(size, "external reference relocations")?;
    }
    Ok(cursor.pos)
}

/// Export records: the name and an offset word. Returns the end of the
/// table, or 0 when it is empty.
pub(super) fn publics(reader: Reader<'_>, table: Table) -> Result<usize> {
    let Some(mut cursor) = records(reader, table, MIN_PUBLIC_SIZE, "publics")? else {
        return Ok(0);
    };
    for _ in 0..table.count {
        cursor.counted("public name")?;
        cursor.word("public offset")?;
    }
    Ok(cursor.pos)
}

/// Debug records: a type byte (0 data, 1 code, otherwise absolute), a
/// value word and the name. Returns the end of the table, or 0 when it is
/// empty.
pub(super) fn debug_records(reader: Reader<'_>, table: Table) -> Result<usize> {
    let what = "debug records";
    let Some(mut cursor) = records(reader, table, MIN_DEBUG_RECORD_SIZE, what)? else {
        return Ok(0);
    };
    for _ in 0..table.count {
        cursor.byte("debug record type")?;
        cursor.word("debug record value")?;
        cursor.counted("debug record name")?;
    }
    Ok(cursor.pos)
}

/// Entries of a `CyGnUsEx` section table stored at file offset `offset`:
/// a NUL-terminated name padded with zeros to a 4-byte boundary, then the
/// section's file position and size.
pub(super) fn cygnus_sections(table: &[u8], offset: u32) -> Result<usize> {
    let mut pos = 0;
    let mut sections = 0;
    while let Some(entry) = table.get(pos..).filter(|entry| !entry.is_empty()) {
        // The table lies in the file, so its offsets fit in `usize`.
        let at = to_usize(offset) + pos;
        let Some(name_len) = entry.iter().position(|&b| b == 0) else {
            return Err(error(format!(
                "Missing NUL after the Cygnus section name at 0x{at:X}"
            )));
        };
        // The name and its NUL, padded, then the two words.
        let entry_size = align_up(name_len + 1) + CYGNUS_ENTRY_WORDS * WORD_SIZE;
        if entry_size > entry.len() {
            return Err(error(format!(
                "Truncated Cygnus section table entry at 0x{at:X} + {entry_size} B"
            )));
        }
        pos += entry_size;
        sections += 1;
    }
    Ok(sections)
}

/// `size` rounded up to [`CYGNUS_NAME_ALIGNMENT`], a power of two; `size`
/// is at most the table size, so this cannot overflow.
fn align_up(size: usize) -> usize {
    (size + CYGNUS_NAME_ALIGNMENT - 1) & !(CYGNUS_NAME_ALIGNMENT - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(data: &[u8]) -> Reader<'_> {
        Reader::new(data, false)
    }

    fn table(offset: u32, count: u32) -> Table {
        Table { offset, count }
    }

    #[test]
    fn empty_tables_are_not_located() {
        let reader = le(&[]);
        let backend = Layout::I386.backend();
        assert_eq!(
            relocation_fixups(reader, table(u32::MAX, 0), backend).unwrap(),
            0
        );
        assert_eq!(publics(reader, table(u32::MAX, 0)).unwrap(), 0);
        assert_eq!(module_dependencies(reader, table(9, 0)).unwrap().end, 0);
    }

    #[test]
    fn counts_are_checked_against_the_remaining_bytes() {
        let data = [0u8; 16];
        assert_eq!(
            external_references(le(&data), table(6, 3), Layout::I386.backend())
                .unwrap_err()
                .to_string(),
            "NetWare module parse error: Invalid external references count 3 at 0x6 (10 B remain)"
        );
        assert_eq!(
            publics(le(&data), table(17, 1)).unwrap_err().to_string(),
            "NetWare module parse error: Truncated publics at 0x11"
        );
        assert_eq!(
            relocation_fixups(le(&data), table(4, 4), Layout::Sparc.backend())
                .unwrap_err()
                .to_string(),
            "NetWare module parse error: Invalid relocation fixups count 4 at 0x4 (12 B remain)"
        );
    }

    #[test]
    fn import_records_follow_the_target_layout() {
        // i386: name, count 2, two 4-byte relocations.
        let mut i386 = vec![3];
        i386.extend_from_slice(b"Foo");
        i386.extend_from_slice(&2u32.to_le_bytes());
        i386.extend_from_slice(&[0; 8]);
        let end = external_references(le(&i386), table(0, 1), Layout::I386.backend());
        assert_eq!(end.unwrap(), i386.len());
        // SPARC: count 1 first, then the name and one 12-byte relocation.
        let mut sparc = 1u32.to_be_bytes().to_vec();
        sparc.extend_from_slice(b"\x03Foo");
        sparc.extend_from_slice(&[0; 12]);
        let reader = Reader::new(&sparc, true);
        let end = external_references(reader, table(0, 1), Layout::Sparc.backend());
        assert_eq!(end.unwrap(), sparc.len());
        assert!(external_references(
            le(&sparc[..sparc.len() - 1]),
            table(0, 1),
            Layout::Sparc.backend()
        )
        .is_err());
    }

    #[test]
    fn dependency_names_are_listed_up_to_the_bound() {
        let mut data = Vec::new();
        for i in 0..20u8 {
            data.push(2);
            data.extend_from_slice(&[b'A' + i, b'X']);
        }
        let dependencies = module_dependencies(le(&data), table(0, 20)).unwrap();
        assert_eq!(dependencies.names.len(), MAX_LISTED_DEPENDENCIES);
        assert_eq!(dependencies.names[0], "AX");
        assert_eq!(dependencies.unlisted, 4);
        assert_eq!(dependencies.end, data.len());
    }

    #[test]
    fn cygnus_entries_are_padded_names_and_two_words() {
        let mut data = b".text\0\0\0".to_vec();
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(b".data\0\0\0");
        data.extend_from_slice(&[0; 8]);
        assert_eq!(cygnus_sections(&data, 0x100).unwrap(), 2);
        assert_eq!(cygnus_sections(&[], 0x100).unwrap(), 0);
        assert_eq!(
            cygnus_sections(&data[..data.len() - 2], 0x100)
                .unwrap_err()
                .to_string(),
            "NetWare module parse error: Truncated Cygnus section table entry at 0x110 + 16 B"
        );
        assert_eq!(
            cygnus_sections(b".text", 0x100).unwrap_err().to_string(),
            "NetWare module parse error: Missing NUL after the Cygnus section name at 0x100"
        );
    }
}
