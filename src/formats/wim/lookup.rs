//! The lookup table (MSWIM "Lookup Table", `RESHDR_DISK`; wimlib `struct
//! blob_descriptor_disk` and `read_blob_table`): 50-byte entries of a
//! resource header (24), a part number (2), a reference count (4) and the
//! SHA-1 of the uncompressed data (20).
//!
//! As wimlib reads it:
//! - entries with an all-zero hash or a size of 0 are skipped, and so are
//!   entries of other parts of a split WIM;
//! - metadata entries are the images' metadata resources in table order,
//!   those with a reference count of 0 skipped;
//! - a later entry with the hash of an earlier one is skipped;
//! - in version 0xE00, a run of entries with the solid flag describes solid
//!   resources (uncompressed size `0x1_0000_0000`) and the blobs in them,
//!   whose offset counts from the start of the run's first resource's
//!   data and whose size is the stored size field; a blob belongs to the
//!   first resource of the run that holds all of it. The solid flag is
//!   ignored in version 1.13.

use super::header::{Compression, ResourceHeader};
use super::resource::{
    Reader, SOLID_CHUNK_SIZE_FIELD, SOLID_FORMAT_FIELD, SOLID_HEADER_SIZE, SOLID_SIZE_FIELD,
};
use super::*;
use crate::formats::container::MAX_EXTRACTED;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

/// Entry layout.
const ENTRY_SIZE: usize = 50;
const PART_FIELD: usize = 24;
const REFERENCE_COUNT_FIELD: usize = 26;
const HASH_FIELD: usize = 30;

/// The uncompressed size that marks a solid resource entry in a solid run
/// (wimlib `SOLID_RESOURCE_MAGIC_NUMBER`).
const SOLID_RESOURCE_MARKER: u64 = 0x1_0000_0000;

/// Where a blob's bytes are.
#[derive(Debug, Clone, Copy)]
pub(super) enum Location {
    /// A resource of its own.
    Resource(ResourceHeader),
    /// `offset` bytes into the uncompressed data of solid resource
    /// `resource` (an index into [`Table::solid`]).
    Solid { resource: usize, offset: u64 },
}

/// A blob of the lookup table.
#[derive(Debug, Clone, Copy)]
pub(super) struct Blob {
    pub(super) hash: Hash,
    /// Uncompressed size in bytes.
    pub(super) size: u64,
    pub(super) location: Location,
}

/// A solid resource, with its own header's fields.
#[derive(Debug, Clone, Copy)]
pub(super) struct SolidResource {
    /// Where the resource is stored.
    pub(super) header: ResourceHeader,
    /// Uncompressed size, chunk size and compression from the resource's
    /// own header.
    pub(super) size: u64,
    pub(super) chunk_size: u32,
    pub(super) compression: Option<Compression>,
}

/// What the table skipped, as wimlib skips it.
#[derive(Debug, Default)]
struct Skipped {
    zero_hash: usize,
    empty: usize,
    other_parts: usize,
    duplicates: usize,
    unreferenced_metadata: usize,
    surplus_metadata: usize,
    solid_metadata: usize,
    metadata_in_later_part: usize,
}

/// The parsed lookup table.
#[derive(Debug)]
pub(super) struct Table {
    /// Blobs of this part by hash, the first entry of each hash.
    pub(super) blobs: HashMap<Hash, Blob>,
    /// The hashes of `blobs` in table order.
    pub(super) order: Vec<Hash>,
    /// The images' metadata resources, in table order.
    pub(super) metadata: Vec<Blob>,
    pub(super) solid: Vec<SolidResource>,
    /// Hashes of blobs stored in other parts of a split WIM.
    pub(super) other_parts: HashSet<Hash>,
    entries: usize,
    /// Bytes after the last whole entry.
    remainder: usize,
    /// Metadata entries whose reference count is not 1 (wimlib rejects them).
    shared_metadata: usize,
    skipped: Skipped,
    /// The end of the furthest resource an entry names.
    furthest: u64,
}

/// Read the lookup table.
pub(super) fn read(data: &[u8], header: &Header) -> Result<Table> {
    let resource = &header.lookup;
    let size = to_usize(resource.size, "WIM lookup table size")?;
    if size > MAX_EXTRACTED {
        return Err(error(format!(
            "Unsupported WIM lookup table of {} (more than {})",
            size_text(size),
            size_text(MAX_EXTRACTED)
        )));
    }
    let mut reader = Reader::new(data, header, &[]);
    let bytes = reader.read_resource(resource, size).map_err(|e| {
        error(format!(
            "Invalid WIM lookup table at 0x{:X}: {}",
            resource.offset,
            resource::message(&e)
        ))
    })?;
    let mut table = Table {
        blobs: HashMap::new(),
        order: Vec::new(),
        metadata: Vec::new(),
        solid: Vec::new(),
        other_parts: HashSet::new(),
        entries: bytes.data.len() / ENTRY_SIZE,
        remainder: bytes.data.len() % ENTRY_SIZE,
        shared_metadata: 0,
        skipped: Skipped::default(),
        furthest: 0,
    };
    // The solid resources of the current run of solid entries, loaded at
    // the run's first entry (wimlib `load_solid_info`).
    let mut run: Option<Vec<usize>> = None;
    let entries: Vec<&[u8]> = bytes.data.chunks_exact(ENTRY_SIZE).collect();
    for (index, &entry) in entries.iter().enumerate() {
        let mut resource = ResourceHeader::read(entry, 0)?;
        if !header.allows_solid() {
            resource.flags &= !header::RESOURCE_SOLID;
        }
        if !resource.is_solid() {
            run = None;
        } else if run.is_none() {
            run = Some(table.load_run(data, &entries[index..])?);
        }
        table.add(
            header,
            index,
            entry,
            resource,
            run.as_deref().unwrap_or_default(),
        )?;
    }
    Ok(table)
}

impl Table {
    /// Load the solid resources of the run of solid entries that starts
    /// `entries`, returning their indices in [`Self::solid`].
    fn load_run(&mut self, data: &[u8], entries: &[&[u8]]) -> Result<Vec<usize>> {
        let mut run = Vec::new();
        for &entry in entries {
            let resource = ResourceHeader::read(entry, 0)?;
            if !resource.is_solid() {
                break;
            }
            if resource.size != SOLID_RESOURCE_MARKER {
                continue;
            }
            let offset = to_usize(resource.offset, "WIM solid resource offset")?;
            let own = slice(data, offset, SOLID_HEADER_SIZE, "WIM solid resource header")?;
            let chunk_size = le_u32(own, SOLID_CHUNK_SIZE_FIELD)?;
            let compression = Compression::from_number(le_u32(own, SOLID_FORMAT_FIELD)?)?;
            if let Some(compression) = compression {
                compression.check_chunk_size(chunk_size)?;
            } else if !chunk_size.is_power_of_two() {
                return Err(error(format!(
                    "Invalid WIM solid resource at 0x{offset:X}: chunk size {chunk_size} B"
                )));
            }
            run.push(self.solid.len());
            self.solid.push(SolidResource {
                header: resource,
                size: le_u64(own, SOLID_SIZE_FIELD)?,
                chunk_size,
                compression,
            });
        }
        Ok(run)
    }

    /// Add entry `index`, whose resource header is `resource`; `run` is the
    /// current solid run.
    fn add(
        &mut self,
        header: &Header,
        index: usize,
        entry: &[u8],
        resource: ResourceHeader,
        run: &[usize],
    ) -> Result<()> {
        let part = le_u16(entry, PART_FIELD)?;
        let references = le_u32(entry, REFERENCE_COUNT_FIELD)?;
        let hash = hash_at(entry, HASH_FIELD)?;
        if resource.is_solid() && resource.size == SOLID_RESOURCE_MARKER {
            self.furthest = self.furthest.max(resource.end().unwrap_or(u64::MAX));
            return Ok(());
        }
        let blob = if resource.is_solid() {
            self.solid_blob(index, hash, resource, run)?
        } else {
            if !resource.is_compressed() && resource.stored_size != resource.size {
                return Err(error(format!(
                    "Invalid WIM lookup table entry {index}: a stored resource of {} B with a \
                     size of {} B",
                    resource.stored_size, resource.size
                )));
            }
            if part == header.part_number {
                self.furthest = self.furthest.max(resource.end().unwrap_or(u64::MAX));
            }
            Blob {
                hash,
                size: resource.size,
                location: Location::Resource(resource),
            }
        };
        if hash == [0; HASH_SIZE] {
            self.skipped.zero_hash += 1;
        } else if blob.size == 0 {
            self.skipped.empty += 1;
        } else if part != header.part_number {
            self.skipped.other_parts += 1;
            self.other_parts.insert(hash);
        } else if resource.is_metadata() {
            self.add_metadata(header, blob, resource, references);
        } else {
            match self.blobs.entry(hash) {
                Entry::Occupied(_) => self.skipped.duplicates += 1,
                Entry::Vacant(vacant) => {
                    vacant.insert(blob);
                    self.order.push(hash);
                }
            }
        }
        Ok(())
    }

    /// A blob in the current solid run: its offset counts from the start
    /// of the run's first resource, and it belongs to the first resource
    /// that holds all of it (wimlib `assign_blob_to_solid_resource`).
    fn solid_blob(
        &self,
        index: usize,
        hash: Hash,
        resource: ResourceHeader,
        run: &[usize],
    ) -> Result<Blob> {
        let size = resource.stored_size;
        let mut offset = resource.offset;
        for &solid in run {
            let holder = &self.solid[solid];
            if offset
                .checked_add(size)
                .is_some_and(|end| end <= holder.size)
            {
                return Ok(Blob {
                    hash,
                    size,
                    location: Location::Solid {
                        resource: solid,
                        offset,
                    },
                });
            }
            let Some(rest) = offset.checked_sub(holder.size) else {
                break;
            };
            offset = rest;
        }
        Err(error(format!(
            "Invalid WIM lookup table entry {index}: a blob of {size} B at 0x{:X} lies outside \
             its solid resources",
            resource.offset
        )))
    }

    /// Add an image's metadata resource as wimlib does: unreferenced ones,
    /// solid ones, ones in later parts and ones beyond the image count are
    /// skipped.
    fn add_metadata(
        &mut self,
        header: &Header,
        blob: Blob,
        resource: ResourceHeader,
        references: u32,
    ) {
        if references == 0 {
            self.skipped.unreferenced_metadata += 1;
        } else if resource.is_solid() {
            self.skipped.solid_metadata += 1;
        } else if header.part_number != 1 {
            self.skipped.metadata_in_later_part += 1;
        } else if self.metadata.len() >= header.image_count as usize {
            self.skipped.surplus_metadata += 1;
        } else {
            if references != 1 {
                self.shared_metadata += 1;
            }
            self.metadata.push(blob);
        }
    }

    /// The end of the furthest structure the header and the table name.
    pub(super) fn furthest_end(&self, header: &Header) -> usize {
        let structures = [
            header.lookup,
            header.xml,
            header.boot_metadata,
            header.integrity,
        ];
        let end = structures
            .iter()
            .map(|resource| resource.end().unwrap_or(u64::MAX))
            .fold(self.furthest.max(HEADER_SIZE as u64), u64::max);
        usize::try_from(end).unwrap_or(usize::MAX)
    }

    /// The table's census in notes and metadata.
    pub(super) fn push_notes(&self, header: &Header, c: &mut Container<'_>) {
        let solid = if self.solid.is_empty() {
            String::new()
        } else {
            format!(
                " in {}",
                count(self.solid.len(), "solid resource", "solid resources")
            )
        };
        c.notes.push(format!(
            "Lookup table: {}: {}{solid} and {} in this part",
            count(self.entries, "entry", "entries"),
            count(self.blobs.len(), "file resource", "file resources"),
            count(
                self.metadata.len(),
                "image metadata resource",
                "image metadata resources"
            ),
        ));
        let skipped = &self.skipped;
        let reasons = [
            (skipped.zero_hash, "with an all-zero hash"),
            (skipped.empty, "of 0 B"),
            (skipped.other_parts, "in other parts of the split WIM"),
            (skipped.duplicates, "repeating an earlier hash"),
            (skipped.unreferenced_metadata, "for unreferenced metadata"),
            (skipped.solid_metadata, "for metadata in solid resources"),
            (
                skipped.metadata_in_later_part,
                "for metadata in a part other than 1",
            ),
            (
                skipped.surplus_metadata,
                "for metadata beyond the image count",
            ),
        ];
        let listed: Vec<String> = reasons
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, why)| format!("{n} {why}"))
            .collect();
        if !listed.is_empty() {
            c.notes.push(format!(
                "Lookup table entries skipped as wimlib skips them: {}",
                listed.join(", ")
            ));
        }
        if self.shared_metadata > 0 {
            c.notes.push(format!(
                "{} a reference count other than 1, which wimlib rejects",
                count(
                    self.shared_metadata,
                    "metadata resource has",
                    "metadata resources have"
                )
            ));
        }
        if self.remainder > 0 {
            c.notes.push(format!(
                "{} B after the last whole lookup table entry",
                self.remainder
            ));
        }
        if header.part_number == 1 && self.metadata.len() != header.image_count as usize {
            c.notes.push(format!(
                "The header counts {} but the lookup table has {}",
                count(header.image_count as usize, "image", "images"),
                count(
                    self.metadata.len(),
                    "metadata resource",
                    "metadata resources"
                )
            ));
        }
        c.push_metadata(
            "wim_lookup_entries",
            "Lookup table entries",
            self.entries as u64,
        );
        c.push_metadata(
            "wim_file_resources",
            "File resources in this part",
            self.blobs.len() as u64,
        );
    }
}
