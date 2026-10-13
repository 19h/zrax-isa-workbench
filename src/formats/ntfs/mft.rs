//! The master file table: `$MFT` (record 0) read where the boot sector
//! points, its `$DATA` runlist with the extents that its attribute list
//! places in extension records ([NTFS-3G] `ntfs_mft_load`), reads of
//! records by number through that runlist, and the attributes of a file
//! across its base and extension records ([LAYOUT] `ATTR_LIST_ENTRY`;
//! [DOCS] `attributes/attribute_list.html`).

use super::data::{Body, Extents, Stream};
use super::record::{Attribute, FileName, Form, NonResident, Piece};
use super::runlist::{self, Run};
use super::*;
use std::cell::Cell;
use std::collections::HashMap;

/// Bytes of MFT records and attribute lists parsed are limited to this many
/// times the bytes of the volume present (at least 1 MiB). A consistent
/// volume parses each record about three times (both walk passes, and once
/// more as an extension record) and each attribute list twice; attribute
/// lists that name the same records over and over, or that share their
/// clusters, would otherwise make the walk unbounded. The factor is ours.
pub(super) const METADATA_READ_FACTOR: u64 = 16;
pub(super) const MIN_METADATA_BASIS: usize = 1 << 20;

/// An attribute list value is at most 256 KiB ([LAYOUT] `ATTR_LIST_ENTRY`:
/// "imposed by the Windows cache manager"; [NTFS-3G] `ntfs_mft_load`).
const MAX_ATTRIBUTE_LIST_SIZE: usize = 0x40000;

/// Fixed part of an attribute list entry; the name follows.
const LIST_ENTRY_HEADER_SIZE: usize = 26;

/// The name of the logged utility stream of an encrypted file.
const EFS_STREAM_NAME: &str = "$EFS";

/// The `$MFT` runlist and record geometry.
#[derive(Debug)]
pub(super) struct Mft {
    /// Runs of `$MFT`'s `$DATA`, in VCN order from VCN 0.
    runs: Vec<Run>,
    record_size: usize,
    /// Records in `data_size`.
    record_count: u64,
    /// Records in `initialized_size`; later ones hold no data yet.
    initialized_records: u64,
    /// Bytes of records and attribute lists the reader may still parse; see
    /// [`Mft::charge`].
    budget: Cell<u64>,
    /// The budget's basis, the bytes of the volume present, for messages.
    present: usize,
}

/// A record's stored bytes and where they are.
struct RawRecord {
    bytes: Vec<u8>,
    pieces: Vec<Piece>,
}

/// One extent of a non-resident attribute, with its decoded runs.
struct Extent {
    header: NonResident,
    runs: Vec<Run>,
}

/// An entry of an attribute list.
#[derive(Debug, Clone)]
struct ListEntry {
    kind: u32,
    name: String,
    lowest_vcn: u64,
    reference: Reference,
    instance: u16,
}

/// An attribute of a file: which of the file's records holds it, and its
/// index there.
#[derive(Debug, Clone, Copy)]
struct Located {
    record: usize,
    attribute: usize,
}

/// A file or directory: the attributes of its base record and of the
/// extension records its attribute list names.
#[derive(Debug)]
pub(super) struct File {
    /// Base record number.
    pub(super) number: u64,
    /// Base record sequence number.
    pub(super) sequence: u16,
    /// The base record's directory flag.
    pub(super) is_directory: bool,
    /// `$FILE_NAME` values in attribute order.
    pub(super) names: Vec<FileName>,
    /// `$STANDARD_INFORMATION` file attributes.
    pub(super) attribute_flags: u32,
    /// `$DATA` streams in attribute order.
    pub(super) streams: Vec<Stream>,
    /// The `$REPARSE_POINT` value, if any.
    pub(super) reparse_point: Option<Stream>,
    /// Whether a `$LOGGED_UTILITY_STREAM` named `$EFS` is present.
    pub(super) has_efs: bool,
}

impl File {
    /// The first name that is not a DOS alias, or failing that the first
    /// name.
    pub(super) fn primary_name(&self) -> Option<&FileName> {
        self.names
            .iter()
            .find(|name| !name.is_dos_alias())
            .or_else(|| self.names.first())
    }

    /// Names that are not DOS aliases: one per hard link.
    pub(super) fn link_count(&self) -> usize {
        self.names
            .iter()
            .filter(|name| !name.is_dos_alias())
            .count()
    }
}

/// The error for the `$MFT` itself.
fn mft_error(problem: impl std::fmt::Display) -> Fault {
    Fault::Invalid(error(format!("Invalid $MFT: {problem}")))
}

impl Mft {
    /// Read `$MFT` from the cluster the boot sector names and resolve its
    /// `$DATA` runlist.
    ///
    /// # Errors
    ///
    /// An invalid or empty record 0, a `$DATA` attribute that is resident,
    /// compressed, encrypted, sparse, or does not start at the boot
    /// sector's cluster, overlapping runs, fewer than 16 records, or record
    /// 0 past the end of a truncated volume's input.
    pub(super) fn open(vol: &Volume<'_>) -> ReadResult<Self> {
        let boot = &vol.boot;
        let record_size = boot.record_size;
        // Record 0 is read where the boot sector points, before its
        // runlist is known ([NTFS-3G] `ntfs_mft_load`).
        let clusters = div_ceil(record_size as u64, vol.cluster_size());
        let first = vol.clusters(boot.mft_lcn, clusters)?;
        let offset = usize::try_from(boot.mft_lcn * vol.cluster_size())
            .expect("present bytes are addressable");
        let piece = Piece {
            offset: 0,
            file_offset: offset,
            len: record_size,
        };
        let record = Record::parse(MFT_RECORD, first[..record_size].to_vec(), vec![piece])?
            .ok_or_else(|| mft_error("MFT record 0 is empty"))?;
        if !record.is_in_use() || !record.is_base() {
            return Err(mft_error("MFT record 0 is not a base record in use"));
        }
        let basis = vol.data.len().max(MIN_METADATA_BASIS);
        let mut mft = Self {
            runs: Vec::new(),
            record_size,
            record_count: 0,
            initialized_records: 0,
            budget: Cell::new((basis as u64).saturating_mul(METADATA_READ_FACTOR)),
            present: vol.data.len(),
        };
        let extents = mft.own_extents(vol, &record)?;
        let first_lcn = extents.runs.first().and_then(|run| run.lcn);
        if first_lcn != Some(boot.mft_lcn) {
            return Err(mft_error(format!(
                "its runlist starts at cluster {}, the boot sector names 0x{:X}",
                first_lcn.map_or_else(|| "none".to_string(), |lcn| format!("0x{lcn:X}")),
                boot.mft_lcn
            )));
        }
        check_own_runs(vol, &extents)?;
        mft.record_count = extents.data_size / record_size as u64;
        mft.initialized_records =
            extents.initialized_size.min(extents.data_size) / record_size as u64;
        mft.runs = extents.runs;
        if mft.record_count < FIRST_USER_RECORD {
            return Err(mft_error(format!(
                "{} records, fewer than the {FIRST_USER_RECORD} system records",
                mft.record_count
            )));
        }
        Ok(mft)
    }

    /// Records in `$MFT`'s `data_size`.
    pub(super) fn record_count(&self) -> u64 {
        self.record_count
    }

    /// The unnamed `$DATA` of record 0, with the extents its attribute list
    /// places in extension records. Each extension record is read through
    /// the runs known so far, as ntfs-3g reads them.
    fn own_extents(&mut self, vol: &Volume<'_>, record: &Record) -> ReadResult<Extents> {
        let list = record
            .attributes
            .iter()
            .find(|attribute| attribute.kind == AT_ATTRIBUTE_LIST);
        let Some(list) = list else {
            let extents = record
                .attributes
                .iter()
                .filter(|attribute| attribute.kind == AT_DATA && attribute.name.is_empty())
                .map(|attribute| own_extent(vol, record, attribute))
                .collect::<ReadResult<Vec<_>>>()?;
            return merge(MFT_RECORD, AT_DATA, &extents, vol);
        };
        let value = attribute_value(vol, record, list, MAX_ATTRIBUTE_LIST_SIZE)?;
        self.charge(value.len())?;
        let entries = list_entries(MFT_RECORD, &value)?;
        let mut extents = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AT_DATA && entry.name.is_empty())
        {
            if entry.reference.record == MFT_RECORD {
                let attribute = find_listed(record, entry)
                    .ok_or_else(|| mft_error("its attribute list names a missing $DATA extent"))?;
                extents.push(own_extent(vol, record, attribute)?);
                continue;
            }
            // The extension record must lie in the part of the MFT that the
            // extents so far map.
            self.runs = merged_runs(&extents);
            self.record_count = runlist::end_vcn(&self.runs).saturating_mul(vol.cluster_size())
                / self.record_size as u64;
            self.initialized_records = self.record_count;
            let extension = self.record(vol, entry.reference.record)?.ok_or_else(|| {
                mft_error(format!(
                    "its $DATA extension record {} is empty",
                    entry.reference.record
                ))
            })?;
            check_extension(&extension, record)?;
            let attribute = find_listed(&extension, entry).ok_or_else(|| {
                mft_error(format!(
                    "extension record {} lacks the $DATA extent at VCN 0x{:X}",
                    entry.reference.record, entry.lowest_vcn
                ))
            })?;
            extents.push(own_extent(vol, &extension, attribute)?);
        }
        merge(MFT_RECORD, AT_DATA, &extents, vol)
    }

    /// The stored bytes of record `number`, read through the runs, in
    /// pieces where it spans runs; `None` past `initialized_size`, where a
    /// record reads as zeros and holds nothing.
    fn raw(&self, vol: &Volume<'_>, number: u64) -> ReadResult<Option<RawRecord>> {
        if number >= self.record_count {
            return invalid(format!(
                "Invalid MFT reference: record {number} beyond the {} records of $MFT",
                self.record_count
            ));
        }
        if number >= self.initialized_records {
            return Ok(None);
        }
        let cluster = vol.cluster_size();
        let start = number * self.record_size as u64;
        let end = start + self.record_size as u64;
        // Allocated as pieces are found, so that a record past the end of a
        // truncated volume's input costs no allocation.
        let mut bytes = Vec::new();
        let mut pieces = Vec::new();
        let mut position = start;
        let first = self.runs.partition_point(|run| {
            run.vcn.saturating_add(run.length).saturating_mul(cluster) <= start
        });
        for run in &self.runs[first..] {
            if position >= end {
                break;
            }
            // Before the runlist is checked (while $MFT's own extension
            // records are read), a run may be sparse or very long.
            let Some(lcn) = run.lcn else {
                return Err(mft_error(format!("record {number} lies in a sparse run")));
            };
            let run_start = run.vcn.saturating_mul(cluster);
            let run_end = run.vcn.saturating_add(run.length).saturating_mul(cluster);
            if run_start > position {
                break;
            }
            let to = end.min(run_end);
            let at = lcn * cluster + (position - run_start);
            let stored = vol.present(at, to - position)?;
            pieces.push(Piece {
                offset: bytes.len(),
                file_offset: usize::try_from(at).expect("present bytes are addressable"),
                len: stored.len(),
            });
            bytes.extend_from_slice(stored);
            position = to;
        }
        if position < end {
            return invalid(format!("Invalid $MFT: its runs do not map record {number}"));
        }
        Ok(Some(RawRecord { bytes, pieces }))
    }

    /// Record `number`, parsed; `None` for an empty slot.
    pub(super) fn record(&self, vol: &Volume<'_>, number: u64) -> ReadResult<Option<Record>> {
        match self.raw(vol, number)? {
            Some(raw) => {
                self.charge(raw.bytes.len())?;
                Ok(Record::parse(number, raw.bytes, raw.pieces)?)
            }
            None => Ok(None),
        }
    }

    /// Account for `size` bytes of metadata about to be parsed.
    fn charge(&self, size: usize) -> ReadResult<()> {
        let Some(left) = self.budget.get().checked_sub(size as u64) else {
            self.budget.set(0);
            return invalid(format!(
                "Invalid metadata: more than {} B of MFT records and attribute lists read \
                 ({METADATA_READ_FACTOR} times the {} present, at least {})",
                (self.present.max(MIN_METADATA_BASIS) as u64).saturating_mul(METADATA_READ_FACTOR),
                size_text(self.present),
                size_text(MIN_METADATA_BASIS)
            ));
        };
        self.budget.set(left);
        Ok(())
    }

    /// Whether the metadata read limit was reached; the walk stops.
    pub(super) fn is_exhausted(&self) -> bool {
        self.budget.get() == 0
    }

    /// The fixed-up bytes of record `number`, for comparing copies.
    pub(super) fn fixed_up_record(&self, vol: &Volume<'_>, number: u64) -> ReadResult<Vec<u8>> {
        let raw = self
            .raw(vol, number)?
            .ok_or_else(|| mft_error(format!("record {number} lies past its initialized size")))?;
        Ok(Record::fixed_up(number, raw.bytes)?)
    }

    /// The attributes of the file whose base record is `base`, from the
    /// extension records its attribute list names.
    ///
    /// # Errors
    ///
    /// An invalid attribute list, a listed attribute or extension record
    /// that is missing or belongs to another file, or extents that do not
    /// join.
    pub(super) fn file(&self, vol: &Volume<'_>, base: Record) -> ReadResult<File> {
        let mut records = vec![base];
        let located = self.locate_attributes(vol, &mut records)?;
        let base = &records[0];
        let mut file = File {
            number: base.number,
            sequence: base.sequence,
            is_directory: base.is_directory(),
            names: Vec::new(),
            attribute_flags: 0,
            streams: Vec::new(),
            reparse_point: None,
            has_efs: false,
        };
        let mut extents: Vec<StreamExtents> = Vec::new();
        for place in located {
            let record = &records[place.record];
            let attribute = &record.attributes[place.attribute];
            match attribute.kind {
                AT_STANDARD_INFORMATION => {
                    let value = record.resident_value(attribute).unwrap_or_default();
                    file.attribute_flags = le_u32(value, 32).unwrap_or(0);
                }
                AT_FILE_NAME => {
                    if let Some(name) = record.resident_value(attribute).and_then(FileName::read) {
                        file.names.push(name);
                    }
                }
                AT_DATA | AT_REPARSE_POINT => {
                    add_extent(vol, record, attribute, &mut extents)?;
                }
                AT_LOGGED_UTILITY_STREAM if attribute.name == EFS_STREAM_NAME => {
                    file.has_efs = true;
                }
                _ => {}
            }
        }
        for stream in extents {
            let stream = stream.finish(file.number, vol)?;
            if stream.kind == AT_REPARSE_POINT {
                file.reparse_point = Some(stream);
            } else {
                file.streams.push(stream);
            }
        }
        Ok(file)
    }

    /// The file's attributes in attribute list order, loading the extension
    /// records it names into `records` (the base record first); without a
    /// list, the base record's attributes in record order.
    fn locate_attributes(
        &self,
        vol: &Volume<'_>,
        records: &mut Vec<Record>,
    ) -> ReadResult<Vec<Located>> {
        let base = &records[0];
        let Some(list) = base
            .attributes
            .iter()
            .find(|attribute| attribute.kind == AT_ATTRIBUTE_LIST)
        else {
            return Ok((0..base.attributes.len())
                .map(|attribute| Located {
                    record: 0,
                    attribute,
                })
                .collect());
        };
        let value = attribute_value(vol, base, list, MAX_ATTRIBUTE_LIST_SIZE)?;
        self.charge(value.len())?;
        let entries = list_entries(base.number, &value)?;
        let mut loaded: HashMap<u64, usize> = HashMap::from([(base.number, 0)]);
        let mut located = Vec::with_capacity(entries.len());
        for entry in &entries {
            let index = if let Some(&index) = loaded.get(&entry.reference.record) {
                index
            } else {
                let number = entry.reference.record;
                let extension = self.record(vol, number)?.ok_or_else(|| {
                    Fault::Invalid(error(format!(
                        "Invalid attribute list of MFT record {}: extension record {number} is \
                         empty",
                        records[0].number
                    )))
                })?;
                check_extension(&extension, &records[0])?;
                records.push(extension);
                loaded.insert(number, records.len() - 1);
                records.len() - 1
            };
            let attribute = records[index]
                .attributes
                .iter()
                .position(|attribute| listed(attribute, entry))
                .ok_or_else(|| {
                    Fault::Invalid(error(format!(
                        "Invalid attribute list of MFT record {}: record {} lacks attribute \
                         0x{:X} (instance {}, VCN 0x{:X})",
                        records[0].number,
                        entry.reference.record,
                        entry.kind,
                        entry.instance,
                        entry.lowest_vcn
                    )))
                })?;
            located.push(Located {
                record: index,
                attribute,
            });
        }
        Ok(located)
    }
}

/// `$MFT` runs must be stored and must not overlap ([NTFS-3G]: "$MFT must
/// be uncompressed and unencrypted"); a sparse or overlapping MFT would let
/// one record's bytes stand for many.
fn check_own_runs(vol: &Volume<'_>, extents: &Extents) -> ReadResult<()> {
    if extents.runs.iter().any(|run| run.lcn.is_none()) {
        return Err(mft_error("its runlist has a sparse run"));
    }
    let mut by_cluster: Vec<&Run> = extents.runs.iter().collect();
    by_cluster.sort_by_key(|run| run.lcn);
    let overlap = by_cluster.windows(2).any(|w| {
        let first = w[0].lcn.expect("checked stored");
        let second = w[1].lcn.expect("checked stored");
        first + w[0].length > second
    });
    if overlap {
        return Err(mft_error("its runs overlap"));
    }
    let mapped = runlist::end_vcn(&extents.runs).saturating_mul(vol.cluster_size());
    if mapped < extents.data_size {
        return Err(mft_error(format!(
            "its runs map {mapped} B of its {} B",
            extents.data_size
        )));
    }
    Ok(())
}

/// An extension record must be in use and name `base` as its base record
/// ([LAYOUT] `MFT_RECORD.base_mft_record`).
fn check_extension(extension: &Record, base: &Record) -> ReadResult<()> {
    if extension.is_in_use()
        && extension.base.record == base.number
        && extension.base.names(base.sequence)
    {
        return Ok(());
    }
    invalid(format!(
        "Invalid attribute list of MFT record {}: record {} is not its extension record in use",
        base.number, extension.number
    ))
}

/// Whether `attribute` is the one a list entry names: the same type and
/// name, and the same instance for a first extent or the same lowest VCN
/// for a later one ([LAYOUT] `ATTR_LIST_ENTRY.instance`: "If `lowest_vcn` =
/// 0, the instance of the attribute being referenced; otherwise 0").
fn listed(attribute: &Attribute, entry: &ListEntry) -> bool {
    if attribute.kind != entry.kind || attribute.name != entry.name {
        return false;
    }
    match &attribute.form {
        Form::NonResident(extent) if entry.lowest_vcn > 0 => extent.lowest_vcn == entry.lowest_vcn,
        _ => entry.lowest_vcn == 0 && attribute.instance == entry.instance,
    }
}

/// The attribute of `record` that `entry` names.
fn find_listed<'r>(record: &'r Record, entry: &ListEntry) -> Option<&'r Attribute> {
    record
        .attributes
        .iter()
        .find(|attribute| listed(attribute, entry))
}

/// Parse an attribute list value.
///
/// Entry layout: type (4), length (2), `name_length` (1), `name_offset`
/// (1), `lowest_vcn` (8) at 8, `mft_reference` (8) at 16, `instance` (2) at
/// 24, the name.
fn list_entries(number: u64, value: &[u8]) -> ReadResult<Vec<ListEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let problem = |what: String| {
            Fault::Invalid(error(format!(
                "Invalid attribute list of MFT record {number}: entry at 0x{pos:X} {what}"
            )))
        };
        let entry = value
            .get(pos..)
            .filter(|rest| rest.len() >= LIST_ENTRY_HEADER_SIZE)
            .ok_or_else(|| problem("is cut short".to_string()))?;
        let length = usize::from(le_u16(entry, 4)?);
        if length < LIST_ENTRY_HEADER_SIZE || length > entry.len() {
            return Err(problem(format!("has length {length} B")));
        }
        let name_length = usize::from(entry[6]);
        let name_offset = usize::from(entry[7]);
        let name = entry
            .get(name_offset..name_offset + 2 * name_length)
            .filter(|_| name_offset + 2 * name_length <= length)
            .ok_or_else(|| problem("has a name past its end".to_string()))?;
        let lowest_vcn = le_i64(entry, 8)?;
        if lowest_vcn < 0 {
            return Err(problem(format!("has lowest VCN {lowest_vcn}")));
        }
        entries.push(ListEntry {
            kind: le_u32(entry, 0)?,
            name: utf16_text(name),
            lowest_vcn: lowest_vcn.unsigned_abs(),
            reference: Reference::from_raw(le_u64(entry, 16)?),
            instance: le_u16(entry, 24)?,
        });
        pos += length;
    }
    Ok(entries)
}

/// The value of a resident attribute, or of an uncompressed non-resident
/// one of at most `limit` bytes, which must lie in its record's runs.
fn attribute_value(
    vol: &Volume<'_>,
    record: &Record,
    attribute: &Attribute,
    limit: usize,
) -> ReadResult<Vec<u8>> {
    if let Some(value) = record.resident_value(attribute) {
        return Ok(value.to_vec());
    }
    let mut streams = Vec::new();
    add_extent(vol, record, attribute, &mut streams)?;
    let stream = streams
        .pop()
        .expect("one extent added")
        .finish(record.number, vol)?;
    let size = stream.size();
    if size > limit as u64 || stream.compression_method() != 0 {
        return invalid(format!(
            "Invalid attribute 0x{:X} of MFT record {}: {size} B, at most {} uncompressed",
            attribute.kind,
            record.number,
            size_text(limit)
        ));
    }
    let size = usize::try_from(size).expect("at most the limit");
    Ok(stream.read(vol, size)?.bytes.into_owned())
}

/// Decode the runs of one extent of `$MFT`'s own `$DATA`.
fn own_extent(vol: &Volume<'_>, record: &Record, attribute: &Attribute) -> ReadResult<Extent> {
    if attribute.flags & (ATTR_COMPRESSION_MASK | ATTR_IS_ENCRYPTED) != 0 {
        return Err(mft_error("its $DATA is compressed or encrypted"));
    }
    match &attribute.form {
        Form::NonResident(header) => decode_extent(vol, record, attribute.kind, header),
        Form::Resident(_) => Err(mft_error("its $DATA is resident")),
    }
}

/// Decode the mapping pairs of one extent.
fn decode_extent(
    vol: &Volume<'_>,
    record: &Record,
    kind: u32,
    header: &NonResident,
) -> ReadResult<Extent> {
    let runs = runlist::decode(
        record.mapping_pairs(header),
        header.lowest_vcn,
        header.highest_vcn,
        vol.boot.cluster_count,
    )
    .map_err(|problem| {
        error(format!(
            "Invalid runlist of attribute 0x{kind:X} in MFT record {}: {problem}",
            record.number
        ))
    })?;
    Ok(Extent {
        header: header.clone(),
        runs,
    })
}

/// The runs of extents in order, joined.
fn merged_runs(extents: &[Extent]) -> Vec<Run> {
    extents
        .iter()
        .flat_map(|extent| extent.runs.iter().copied())
        .collect()
}

/// Join the extents of one attribute: the first starts at VCN 0 and holds
/// the sizes, each later one starts where the one before ends, and the
/// runs map no more than the allocated size ([NTFS-3G]
/// `ntfs_mapping_pairs_decompress_i`: "There are more VCNs in the runlist
/// than expected").
fn merge(number: u64, kind: u32, extents: &[Extent], vol: &Volume<'_>) -> ReadResult<Extents> {
    let problem = |what: String| {
        Fault::Invalid(error(format!(
            "Invalid attribute 0x{kind:X} of MFT record {number}: {what}"
        )))
    };
    let Some(first) = extents.first() else {
        return Err(problem("no extent".to_string()));
    };
    if first.header.lowest_vcn != 0 {
        return Err(problem(format!(
            "its first extent starts at VCN 0x{:X}",
            first.header.lowest_vcn
        )));
    }
    let sizes = first.header.clone();
    let mut runs = Vec::new();
    let mut next_vcn = 0;
    for extent in extents {
        if extent.header.lowest_vcn != next_vcn {
            return Err(problem(format!(
                "an extent starts at VCN 0x{:X}, not 0x{next_vcn:X}",
                extent.header.lowest_vcn
            )));
        }
        runs.extend_from_slice(&extent.runs);
        next_vcn = runlist::end_vcn(&runs).max(next_vcn);
    }
    let allocated_clusters = div_ceil(sizes.allocated_size, vol.cluster_size());
    if runlist::end_vcn(&runs) > allocated_clusters {
        return Err(problem(format!(
            "its runs map {} clusters, more than its allocated {} B",
            runlist::end_vcn(&runs),
            sizes.allocated_size
        )));
    }
    Ok(Extents {
        runs,
        data_size: sizes.data_size,
        initialized_size: sizes.initialized_size.min(sizes.data_size),
        compression_unit: sizes.compression_unit,
    })
}

/// The extents of one stream (a `$DATA` or `$REPARSE_POINT` attribute)
/// collected across records, or its resident value.
struct StreamExtents {
    kind: u32,
    name: String,
    flags: u16,
    resident: Option<Body>,
    extents: Vec<Extent>,
}

impl StreamExtents {
    /// The stream, its extents joined.
    fn finish(self, number: u64, vol: &Volume<'_>) -> ReadResult<Stream> {
        let body = match self.resident {
            Some(body) => body,
            None => Body::NonResident(merge(number, self.kind, &self.extents, vol)?),
        };
        Ok(Stream {
            kind: self.kind,
            name: self.name,
            flags: self.flags,
            body,
        })
    }
}

/// Add one attribute record to the stream of its type and name.
fn add_extent(
    vol: &Volume<'_>,
    record: &Record,
    attribute: &Attribute,
    streams: &mut Vec<StreamExtents>,
) -> ReadResult<()> {
    let existing = streams
        .iter()
        .position(|stream| stream.kind == attribute.kind && stream.name == attribute.name);
    let index = existing.unwrap_or_else(|| {
        streams.push(StreamExtents {
            kind: attribute.kind,
            name: attribute.name.clone(),
            flags: attribute.flags,
            resident: None,
            extents: Vec::new(),
        });
        streams.len() - 1
    });
    let stream = &mut streams[index];
    match &attribute.form {
        Form::Resident(range) => {
            if stream.resident.is_some() || !stream.extents.is_empty() {
                return invalid(format!(
                    "Invalid MFT record {}: attribute 0x{:X} \"{}\" appears twice",
                    record.number, attribute.kind, attribute.name
                ));
            }
            stream.resident = Some(Body::Resident {
                value: record
                    .resident_value(attribute)
                    .unwrap_or_default()
                    .to_vec(),
                offset: record.file_offset(range.start),
                stored_as_is: record.stored_offset(range).is_some(),
            });
        }
        Form::NonResident(header) => {
            if stream.resident.is_some() {
                return invalid(format!(
                    "Invalid MFT record {}: attribute 0x{:X} \"{}\" is resident and non-resident",
                    record.number, attribute.kind, attribute.name
                ));
            }
            let extent = decode_extent(vol, record, attribute.kind, header)?;
            stream.extents.push(extent);
        }
    }
    Ok(())
}
