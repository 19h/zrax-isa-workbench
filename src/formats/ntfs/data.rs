//! Data streams: the value of a `$DATA` (or other) attribute, resident in
//! its record or stored in runs, and reads of it: stored runs, sparse runs,
//! bytes past `initialized_size` (zeros), and LZNT1 compression units
//! ([LAYOUT] "Attribute compression"; [NTFS-3G]
//! `ntfs_compressed_attr_pread`, `ntfs_is_cb_compressed`; [DOCS]
//! `concepts/compression.html`).
//!
//! A compressed attribute is divided into compression units of
//! `2^compression_unit` clusters (16 on Windows, and the only value ntfs-3g
//! reads). A unit whose first cluster is sparse holds zeros; a unit whose
//! clusters are all stored holds its bytes as they are; otherwise its
//! stored clusters, followed by sparse ones, hold LZNT1 chunks that decode
//! to the unit.

use super::runlist::Run;
use super::*;
use crate::formats::compressed::{self, Codec};
use std::borrow::Cow;

/// `STANDARD_COMPRESSION_UNIT` and `MAX_COMPRESSION_CLUSTER_SIZE`
/// ([LAYOUT] `param.h`): Windows compresses in units of 16 clusters, on
/// volumes with clusters of at most 4 KiB.
pub(super) const STANDARD_COMPRESSION_UNIT: u8 = 4;
pub(super) const MAX_COMPRESSION_CLUSTER_SIZE: u32 = 4096;

/// Transforms of members whose bytes are not stored as they are.
const RUNS_TRANSFORM: &str = "NTFS runs";
const FIXUP_TRANSFORM: &str = "NTFS update sequence";
const LZNT1_TRANSFORM: &str = "NTFS LZNT1";

/// Bytes stored contiguously in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StoredRun {
    /// File offset.
    pub(super) offset: usize,
    /// Size in bytes.
    pub(super) size: usize,
}

/// The runs and sizes of a non-resident attribute, all extents merged.
#[derive(Debug, Clone)]
pub(super) struct Extents {
    /// Runs in VCN order, starting at VCN 0 and contiguous.
    pub(super) runs: Vec<Run>,
    /// `data_size` in bytes.
    pub(super) data_size: u64,
    /// `initialized_size` in bytes; bytes after it read as zero.
    pub(super) initialized_size: u64,
    /// `compression_unit`.
    pub(super) compression_unit: u8,
}

/// Where a stream's value is.
#[derive(Debug, Clone)]
pub(super) enum Body {
    /// In an MFT record.
    Resident {
        /// The value, fixed up.
        value: Vec<u8>,
        /// File offset of the value's first byte.
        offset: Option<usize>,
        /// Whether the input stores the value as it is (in one piece of the
        /// record and clear of the stride ends that fixups restore).
        stored_as_is: bool,
    },
    /// In clusters.
    NonResident(Extents),
}

/// One attribute's value: a data stream.
#[derive(Debug, Clone)]
pub(super) struct Stream {
    /// Attribute type code.
    pub(super) kind: u32,
    /// Stream name; empty for the unnamed `$DATA` stream.
    pub(super) name: String,
    /// Attribute flags of the first extent.
    pub(super) flags: u16,
    pub(super) body: Body,
}

/// Bytes read from a stream.
pub(super) struct StreamBytes<'a> {
    /// The bytes, borrowed when the input stores them as they are.
    pub(super) bytes: Cow<'a, [u8]>,
    /// The first stored run of the bytes read, if any.
    pub(super) first_run: Option<StoredRun>,
    /// What produced owned bytes from the stored ones.
    pub(super) transform: Option<&'static str>,
}

/// How a compression unit is stored.
enum Unit {
    /// Its first cluster is sparse: zeros.
    Sparse,
    /// All of its clusters are stored: its bytes as they are.
    Stored,
    /// Stored clusters followed by sparse ones: LZNT1 chunks.
    Compressed,
}

/// The stored or sparse clusters of a compression unit, in VCN order.
struct Segment {
    lcn: Option<u64>,
    clusters: u64,
}

impl Stream {
    /// `data_size`, or the resident value's length.
    pub(super) fn size(&self) -> u64 {
        match &self.body {
            Body::Resident { value, .. } => value.len() as u64,
            Body::NonResident(extents) => extents.data_size,
        }
    }

    /// The compression method in the attribute flags; 0 when not
    /// compressed.
    pub(super) fn compression_method(&self) -> u16 {
        match &self.body {
            Body::Resident { .. } => 0,
            Body::NonResident(_) => self.flags & ATTR_COMPRESSION_MASK,
        }
    }

    pub(super) fn is_encrypted(&self) -> bool {
        self.flags & ATTR_IS_ENCRYPTED != 0
    }

    pub(super) fn is_sparse(&self) -> bool {
        self.flags & ATTR_IS_SPARSE != 0
    }

    pub(super) fn is_resident(&self) -> bool {
        matches!(self.body, Body::Resident { .. })
    }

    /// The first `len` bytes of the stream, at most its size.
    pub(super) fn read<'a>(&self, vol: &Volume<'a>, len: usize) -> ReadResult<StreamBytes<'a>> {
        let len = len.min(usize::try_from(self.size()).unwrap_or(usize::MAX));
        match &self.body {
            Body::Resident {
                value,
                offset,
                stored_as_is,
            } => Ok(resident_bytes(vol, &value[..len], *offset, *stored_as_is)),
            Body::NonResident(extents) if self.compression_method() == ATTR_IS_COMPRESSED => {
                if extents.compression_unit != STANDARD_COMPRESSION_UNIT
                    || vol.boot.cluster_size > MAX_COMPRESSION_CLUSTER_SIZE
                {
                    return invalid(format!(
                        "Unsupported compression unit of 2^{} clusters of {}",
                        extents.compression_unit,
                        size_text(vol.boot.cluster_size as usize)
                    ));
                }
                read_compressed(vol, extents, len)
            }
            Body::NonResident(extents) => read_runs(vol, extents, len),
        }
    }
}

/// A resident value: borrowed from the input when it stores the value as
/// it is, otherwise the fixed-up copy.
fn resident_bytes<'a>(
    vol: &Volume<'a>,
    value: &[u8],
    offset: Option<usize>,
    stored_as_is: bool,
) -> StreamBytes<'a> {
    let first_run = offset.map(|offset| StoredRun {
        offset,
        size: value.len(),
    });
    let borrowed = offset
        .filter(|_| stored_as_is)
        .and_then(|offset| vol.data.get(offset..offset + value.len()));
    match borrowed {
        Some(stored) => StreamBytes {
            bytes: Cow::Borrowed(stored),
            first_run,
            transform: None,
        },
        None => StreamBytes {
            bytes: Cow::Owned(value.to_vec()),
            first_run,
            transform: Some(FIXUP_TRANSFORM),
        },
    }
}

/// The bytes of an uncompressed attribute: stored runs, zeros for sparse
/// runs and past `initialized_size`.
fn read_runs<'a>(vol: &Volume<'a>, extents: &Extents, len: usize) -> ReadResult<StreamBytes<'a>> {
    let cluster = vol.cluster_size();
    let wanted = len as u64;
    let readable = extents.initialized_size.min(wanted);
    let mut pieces: Vec<Cow<'a, [u8]>> = Vec::new();
    let mut first_run = None;
    let mut position = 0u64;
    for run in &extents.runs {
        if position >= readable {
            break;
        }
        // Sparse runs may map any number of clusters, so the byte positions
        // saturate; only positions below `readable` are used.
        let run_start = run.vcn.saturating_mul(cluster);
        let run_end = run_start.saturating_add(run.length.saturating_mul(cluster));
        if run_end <= position {
            continue;
        }
        let end = run_end.min(readable);
        let size = end - position;
        match run.lcn {
            None => pieces.push(Cow::Owned(vec![
                0;
                usize::try_from(size)
                    .expect("at most the requested length")
            ])),
            Some(lcn) => {
                let at = lcn * cluster + (position - run_start);
                let stored = vol.present(at, size)?;
                if first_run.is_none() {
                    first_run = Some(StoredRun {
                        offset: usize::try_from(at).expect("present bytes are addressable"),
                        size: stored.len(),
                    });
                }
                pieces.push(Cow::Borrowed(stored));
            }
        }
        position = end;
    }
    if position < readable {
        return invalid(format!(
            "Invalid runlist: {} clusters mapped, {readable} B to read",
            runlist::end_vcn(&extents.runs)
        ));
    }
    if readable == wanted && pieces.len() == 1 {
        if let Some(Cow::Borrowed(stored)) = pieces.pop() {
            return Ok(StreamBytes {
                bytes: Cow::Borrowed(stored),
                first_run,
                transform: None,
            });
        }
    }
    let mut bytes = pieces.concat();
    bytes.resize(len, 0);
    Ok(StreamBytes {
        bytes: Cow::Owned(bytes),
        first_run,
        transform: Some(RUNS_TRANSFORM),
    })
}

/// The bytes of an LZNT1-compressed attribute, decoded unit by unit.
fn read_compressed<'a>(
    vol: &Volume<'a>,
    extents: &Extents,
    len: usize,
) -> ReadResult<StreamBytes<'a>> {
    let cluster = vol.cluster_size();
    let unit_clusters = 1u64 << extents.compression_unit;
    let unit_size = usize::try_from(unit_clusters * cluster).expect("units are at most 64 KiB");
    let readable = usize::try_from(extents.initialized_size).map_or(len, |size| size.min(len));
    let mut out: Vec<u8> = Vec::with_capacity(readable);
    let mut first_run = None;
    let mut unit = 0u64;
    while out.len() < readable {
        let needed = unit_size.min(readable - out.len());
        let segments = unit_segments(extents, unit * unit_clusters, unit_clusters)?;
        let kind = unit_kind(&segments);
        // A stored unit needs only the clusters that hold the bytes wanted;
        // a compressed one all of its stored clusters.
        let mut wanted = match kind {
            Unit::Stored => needed as u64,
            Unit::Sparse | Unit::Compressed => u64::MAX,
        };
        let mut stored = Vec::new();
        for segment in segments.iter().take_while(|segment| segment.lcn.is_some()) {
            if wanted == 0 {
                break;
            }
            let lcn = segment.lcn.expect("taken while stored");
            let size = (segment.clusters * cluster).min(wanted);
            let bytes = vol.present(lcn * cluster, size)?;
            if first_run.is_none() {
                first_run = Some(StoredRun {
                    offset: usize::try_from(lcn * cluster).expect("present bytes are addressable"),
                    size: bytes.len(),
                });
            }
            stored.extend_from_slice(bytes);
            wanted -= size;
        }
        let start = out.len();
        match kind {
            Unit::Sparse => out.resize(start + needed, 0),
            Unit::Stored => out.extend_from_slice(&stored[..needed]),
            Unit::Compressed => {
                let decoded =
                    compressed::decode_prefix(Codec::Lznt1, &stored, needed).map_err(|e| {
                        error(format!("Invalid compression unit {unit}: {}", message(e)))
                    })?;
                out.extend_from_slice(&decoded);
                out.resize(start + needed, 0);
            }
        }
        unit += 1;
    }
    out.resize(len, 0);
    Ok(StreamBytes {
        bytes: Cow::Owned(out),
        first_run,
        transform: Some(LZNT1_TRANSFORM),
    })
}

/// How a unit is stored, by its segments ([NTFS-3G]
/// `ntfs_is_cb_compressed`).
fn unit_kind(segments: &[Segment]) -> Unit {
    match segments.first() {
        Some(Segment { lcn: None, .. }) | None => Unit::Sparse,
        Some(_) if segments.iter().all(|segment| segment.lcn.is_some()) => Unit::Stored,
        Some(_) => Unit::Compressed,
    }
}

/// The segments of the `count` clusters from virtual cluster `first`.
fn unit_segments(extents: &Extents, first: u64, count: u64) -> ReadResult<Vec<Segment>> {
    let end = first + count;
    let mut segments = Vec::new();
    let mut vcn = first;
    for run in &extents.runs {
        let run_end = run.vcn + run.length;
        if run_end <= vcn || run.vcn >= end {
            continue;
        }
        let from = vcn.max(run.vcn);
        let to = end.min(run_end);
        segments.push(Segment {
            lcn: run.lcn.map(|lcn| lcn + (from - run.vcn)),
            clusters: to - from,
        });
        vcn = to;
    }
    if vcn < end {
        return invalid(format!(
            "Invalid runlist: compression unit at VCN 0x{first:X} is mapped to VCN 0x{vcn:X} only"
        ));
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(lcn: Option<u64>, clusters: u64) -> Segment {
        Segment { lcn, clusters }
    }

    #[test]
    fn units_are_sparse_stored_or_compressed_by_their_runs() {
        assert!(matches!(unit_kind(&[segment(None, 16)]), Unit::Sparse));
        assert!(matches!(
            unit_kind(&[segment(Some(4), 10), segment(Some(40), 6)]),
            Unit::Stored
        ));
        assert!(matches!(
            unit_kind(&[segment(Some(4), 3), segment(None, 13)]),
            Unit::Compressed
        ));
    }

    #[test]
    fn unit_segments_split_runs_at_unit_boundaries() {
        let extents = Extents {
            runs: vec![
                Run {
                    vcn: 0,
                    length: 20,
                    lcn: Some(100),
                },
                Run {
                    vcn: 20,
                    length: 12,
                    lcn: None,
                },
            ],
            data_size: 32 * 4096,
            initialized_size: 32 * 4096,
            compression_unit: 4,
        };
        let second = unit_segments(&extents, 16, 16).unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].lcn, Some(116));
        assert_eq!(second[0].clusters, 4);
        assert_eq!(second[1].lcn, None);
        assert!(unit_segments(&extents, 32, 16).is_err());
    }
}
