//! Runlists: the mapping pairs arrays of non-resident attributes
//! ([NTFS-3G] `ntfs_mapping_pairs_decompress_i`; [DOCS]
//! `concepts/data_runs.html`).
//!
//! Each pair starts with a header byte whose low nibble is the size of the
//! run length field and whose high nibble is the size of the LCN delta
//! field. The run length (in clusters) and the delta follow, little-endian
//! and sign-extended; the delta is relative to the previous run's first
//! cluster, and the first one to cluster 0. A run without a delta field is
//! sparse: it maps virtual clusters to no stored clusters. A header byte of
//! 0 ends the array, and it must lie inside the attribute.

/// The widest field a 64-bit cluster number or length can be read from.
const MAX_FIELD_SIZE: usize = 8;

/// The low nibble of a header byte sizes the length, the high nibble the
/// delta.
const LENGTH_SIZE_MASK: u8 = 0x0f;
const DELTA_SIZE_SHIFT: u32 = 4;

/// ntfs-3g reads an LCN of -1 as a hole ([NTFS-3G] "On NTFS 1.2-,
/// apparently can have lcn == -1 to indicate a hole").
const HOLE_LCN: i64 = -1;

/// Clusters of an attribute mapped to the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Run {
    /// First virtual cluster number.
    pub(super) vcn: u64,
    /// Clusters in the run.
    pub(super) length: u64,
    /// First logical cluster number; `None` for a sparse run.
    pub(super) lcn: Option<u64>,
}

/// A little-endian, sign-extended field of one to eight bytes.
fn signed_field(bytes: &[u8]) -> i64 {
    let (&top, rest) = bytes.split_last().expect("fields have at least one byte");
    rest.iter()
        .rev()
        .fold(i64::from(i8::from_le_bytes([top])), |value, &b| {
            value << 8 | i64::from(b)
        })
}

/// Decode the mapping pairs of an extent that maps virtual clusters
/// `lowest_vcn` to `highest_vcn`. Stored runs must lie inside the volume's
/// `cluster_count` clusters. Zero-length sparse runs are dropped, as
/// ntfs-3g drops them.
///
/// # Errors
///
/// A run without a length, with a negative length, with fields wider than
/// eight bytes, starting below cluster 0, of zero clusters, or past the
/// volume; a missing end marker; or runs that do not end at `highest_vcn`
/// (when it is not 0, which ntfs-3g does not check).
pub(super) fn decode(
    pairs: &[u8],
    lowest_vcn: u64,
    highest_vcn: i64,
    cluster_count: u64,
) -> std::result::Result<Vec<Run>, String> {
    let mut runs = Vec::new();
    let mut vcn = lowest_vcn;
    let mut lcn: i64 = 0;
    let mut pos = 0;
    loop {
        let &header = pairs
            .get(pos)
            .ok_or("the mapping pairs array has no end marker")?;
        if header == 0 {
            break;
        }
        let length_size = usize::from(header & LENGTH_SIZE_MASK);
        let delta_size = usize::from(header >> DELTA_SIZE_SHIFT);
        if length_size == 0 || length_size > MAX_FIELD_SIZE || delta_size > MAX_FIELD_SIZE {
            return Err(format!("the run at 0x{pos:X} has header 0x{header:02X}"));
        }
        let fields = pairs
            .get(pos + 1..pos + 1 + length_size + delta_size)
            .ok_or_else(|| format!("the run at 0x{pos:X} passes the attribute's end"))?;
        let length = signed_field(&fields[..length_size]);
        if length < 0 {
            return Err(format!("the run at 0x{pos:X} has a negative length"));
        }
        let length = length.unsigned_abs();
        let start = if delta_size == 0 {
            None
        } else {
            lcn = lcn
                .checked_add(signed_field(&fields[length_size..]))
                .ok_or_else(|| format!("the run at 0x{pos:X} overflows the LCN"))?;
            if lcn < HOLE_LCN {
                return Err(format!("the run at 0x{pos:X} starts at LCN {lcn}"));
            }
            (lcn != HOLE_LCN).then_some(lcn.unsigned_abs())
        };
        if let Some(start) = start {
            if length == 0 {
                return Err(format!("the run at 0x{pos:X} has no clusters"));
            }
            if start
                .checked_add(length)
                .map_or(true, |end| end > cluster_count)
            {
                return Err(format!(
                    "the run at 0x{pos:X} maps clusters 0x{start:X} + {length} beyond the \
                     {cluster_count} clusters of the volume"
                ));
            }
        }
        if length > 0 {
            runs.push(Run {
                vcn,
                length,
                lcn: start,
            });
        }
        vcn = vcn
            .checked_add(length)
            .ok_or_else(|| format!("the run at 0x{pos:X} passes the last VCN"))?;
        pos += 1 + length_size + delta_size;
    }
    if highest_vcn != 0 && i128::from(vcn) - 1 != i128::from(highest_vcn) {
        return Err(format!(
            "the runs end at VCN 0x{:X}, but highest_vcn is 0x{highest_vcn:X}",
            i128::from(vcn) - 1
        ));
    }
    Ok(runs)
}

/// The clusters after the last run: the attribute's mapped cluster count.
pub(super) fn end_vcn(runs: &[Run]) -> u64 {
    runs.last().map_or(0, |run| run.vcn + run.length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_examples_decode() {
        // [DOCS] Example 2: three runs, the later LCNs relative.
        let pairs = [
            0x31, 0x38, 0x73, 0x25, 0x34, 0x32, 0x14, 0x01, 0xe5, 0x11, 0x02, 0x31, 0x42, 0xaa,
            0x00, 0x03, 0x00,
        ];
        let runs = decode(&pairs, 0, 0x18d, 1 << 24).unwrap();
        let summary: Vec<(u64, Option<u64>)> = runs.iter().map(|r| (r.length, r.lcn)).collect();
        assert_eq!(
            summary,
            [
                (0x38, Some(0x34_2573)),
                (0x114, Some(0x36_3758)),
                (0x42, Some(0x39_3802))
            ]
        );
        // Example 3: a negative delta (0xE0 is -0x20).
        let runs = decode(
            &[
                0x11, 0x30, 0x60, 0x21, 0x10, 0x00, 0x01, 0x11, 0x20, 0xe0, 0x00,
            ],
            0,
            0x5f,
            0x1000,
        )
        .unwrap();
        assert_eq!(runs[2].lcn, Some(0x140));
        assert_eq!(runs[2].vcn, 0x40);
        // Example 4: a sparse run in the middle.
        let runs = decode(
            &[0x11, 0x30, 0x20, 0x01, 0x60, 0x11, 0x10, 0x30, 0x00],
            0,
            0x9f,
            0x100,
        )
        .unwrap();
        assert_eq!(
            runs[1],
            Run {
                vcn: 0x30,
                length: 0x60,
                lcn: None
            }
        );
        assert_eq!(runs[2].lcn, Some(0x50));
        assert_eq!(end_vcn(&runs), 0xa0);
    }

    #[test]
    fn malformed_pairs_are_errors() {
        // No end marker, no length, a run past the volume, a zero-length
        // stored run, a mismatched highest_vcn.
        assert!(decode(&[0x11, 0x01, 0x05], 0, 0, 100).is_err());
        assert!(decode(&[0x10, 0x05, 0x00], 0, 0, 100).is_err());
        assert!(decode(&[0x11, 0x10, 0x60, 0x00], 0, 0, 100).is_err());
        assert!(decode(&[0x11, 0x00, 0x05, 0x00], 0, 0, 100).is_err());
        assert!(decode(&[0x11, 0x02, 0x05, 0x00], 0, 5, 100).is_err());
        // A delta that leads below cluster -1.
        assert!(decode(&[0x11, 0x01, 0xfe, 0x00], 0, 0, 100).is_err());
        // A later extent starts at its lowest VCN.
        let runs = decode(&[0x11, 0x02, 0x05, 0x00], 8, 9, 100).unwrap();
        assert_eq!(runs[0].vcn, 8);
    }
}
