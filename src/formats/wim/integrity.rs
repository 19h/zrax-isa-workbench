//! The integrity table (MSWIM "Integrity Table" `WIMHASH`; wimlib
//! `src/integrity.c`): its size (4), the number of entries (4) and the
//! chunk size (4), then one SHA-1 per chunk of the bytes from the end of
//! the header to the end of the lookup table, the last chunk shorter. The
//! size must equal the resource's size and `12 + 20 * entries`, and the
//! entries must cover those bytes exactly (wimlib `read_integrity_table`,
//! `check_wim_integrity`).

use super::resource::{self, Reader};
use super::*;
use crate::formats::checksum::Sha1;

/// The table's fixed fields.
const SIZE_FIELD: usize = 0;
const ENTRIES_FIELD: usize = 4;
const CHUNK_SIZE_FIELD: usize = 8;
const FIXED_SIZE: usize = 12;

/// Check the integrity table, if there is one, and note the outcome.
pub(super) fn check(data: &[u8], header: &Header, c: &mut Container<'_>) {
    if header.integrity.is_absent() {
        return;
    }
    let outcome = match verify(data, header) {
        Ok(outcome) => outcome,
        Err(e) => format!("not verified: {}", resource::message(&e)),
    };
    c.notes.push(format!("Integrity table {outcome}"));
    c.push_metadata("wim_integrity", "Integrity table", outcome);
}

/// `verified ...` or `mismatch ...` for a table that is well formed.
fn verify(data: &[u8], header: &Header) -> Result<String> {
    let resource = header.integrity;
    let size = to_usize(resource.size, "WIM integrity table size")?;
    if size < FIXED_SIZE || size > data.len() {
        return Err(error(format!("Invalid WIM integrity table of {size} B")));
    }
    let bytes = Reader::new(data, header, &[]).read_resource(&resource, size)?;
    let table = &bytes.data;
    let stated = le_u32(table, SIZE_FIELD)? as usize;
    let entries = le_u32(table, ENTRIES_FIELD)? as usize;
    let chunk_size = le_u32(table, CHUNK_SIZE_FIELD)? as usize;
    let expected = entries
        .checked_mul(HASH_SIZE)
        .and_then(|hashes| hashes.checked_add(FIXED_SIZE));
    if stated != size || expected != Some(size) || chunk_size == 0 {
        return Err(error(format!(
            "Invalid WIM integrity table: {stated} B stated, {entries} entries of {chunk_size} B \
             chunks in {size} B"
        )));
    }
    let end = header
        .lookup
        .end()
        .and_then(|end| usize::try_from(end).ok())
        .filter(|&end| end >= HEADER_SIZE && end <= data.len())
        .ok_or_else(|| {
            error("Invalid WIM integrity range: the lookup table ends outside the file")
        })?;
    let checked = &data[HEADER_SIZE..end];
    let needed = checked.len() / chunk_size + usize::from(checked.len() % chunk_size != 0);
    if needed != entries {
        return Err(error(format!(
            "Invalid WIM integrity table: {entries} entries for {} in {} chunks",
            size_text(checked.len()),
            size_text(chunk_size)
        )));
    }
    let hashes = &table[FIXED_SIZE..];
    for (index, (chunk, stored)) in checked
        .chunks(chunk_size)
        .zip(hashes.chunks_exact(HASH_SIZE))
        .enumerate()
    {
        let mut sha1 = Sha1::new();
        sha1.update(chunk);
        if sha1.finish() != stored {
            return Ok(format!(
                "mismatch: chunk {index} at 0x{:X} does not match its SHA-1",
                HEADER_SIZE + index * chunk_size
            ));
        }
    }
    Ok(format!(
        "verified: {} of {} chunks from 0x{HEADER_SIZE:X} to the end of the lookup table",
        count(entries, "SHA-1", "SHA-1s"),
        size_text(chunk_size)
    ))
}
