//! Transforms that undo how a raw dump was read, so that code bytes are back
//! in execution order: byte-lane interleaving of 8-bit memories on 16- and
//! 32-bit buses, 16- and 32-bit byte swaps by programmers and readers, and
//! removal of NAND spare (OOB/ECC) areas.
//!
//! Nothing in the bytes declares these transforms, so they are not
//! containers. The classifier tries them only after a top-level raw input is
//! inconclusive (or a container fails to parse, for spare-area removal), and
//! every attempt pays the union-bound penalty of
//! [`crate::heuristics::analyze_detailed_with_trials`]: with `k` readings
//! tried, each window needs `log2(k)` more bits of margin and the
//! weak-window false-alarm allowance is multiplied by `k`.
//!
//! Spare-area geometries are common NAND page layouts, given as data bytes
//! plus spare bytes per page (the two quantities an ONFI parameter page
//! reports): 512+16, 2048+64, 4096+128, 4096+224 and 8192+448 bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::MAX_PAYLOAD;

/// Fewest NAND pages for spare-area removal to be tried.
const MIN_NAND_PAGES: usize = 4;

/// Fewest bytes per lane for a lane interleave to be tried.
const MIN_LANE_SIZE: usize = 256;

/// Bytes of one lane compared at a time by [`Transform::lanes_agree`].
const LANE_WINDOW: usize = 512;
/// A lane window whose most common byte covers this many tenths is fill.
const LANE_FILL_TENTHS: usize = 9;

/// One way of rearranging stored bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    /// Swap the two bytes of every 16-bit word. A trailing partial word (a
    /// byte a dump tool appended) is kept as stored.
    Swap16,
    /// Reverse the four bytes of every 32-bit word, keeping a trailing
    /// partial word as stored.
    Swap32,
    /// The file holds `lanes` equal byte lanes one after another (two 8-bit
    /// memories on a 16-bit bus, four on a 32-bit bus); interleave them.
    /// `reversed` takes the last lane as byte 0 of each bus word.
    Interleave {
        /// Number of byte lanes (2 or 4).
        lanes: usize,
        /// Lanes are stored in reverse bus order.
        reversed: bool,
    },
    /// Remove the `spare` bytes stored after every `page` data bytes.
    NandSpare {
        /// Data bytes per page.
        page: usize,
        /// Spare bytes per page.
        spare: usize,
    },
}

/// Where transformed bytes are held in the stored input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRange {
    /// Offset in the stored input, in bytes.
    pub offset: usize,
    /// Size in the stored input, in bytes, including any spare areas
    /// inside the range.
    pub size: usize,
}

/// Every reading tried for an inconclusive raw input, in order.
pub const CANDIDATES: &[Transform] = &[
    Transform::Swap16,
    Transform::Swap32,
    Transform::Interleave {
        lanes: 2,
        reversed: false,
    },
    Transform::Interleave {
        lanes: 2,
        reversed: true,
    },
    Transform::Interleave {
        lanes: 4,
        reversed: false,
    },
    Transform::Interleave {
        lanes: 4,
        reversed: true,
    },
    Transform::NandSpare {
        page: 512,
        spare: 16,
    },
    Transform::NandSpare {
        page: 2048,
        spare: 64,
    },
    Transform::NandSpare {
        page: 4096,
        spare: 128,
    },
    Transform::NandSpare {
        page: 4096,
        spare: 224,
    },
    Transform::NandSpare {
        page: 8192,
        spare: 448,
    },
];

impl Transform {
    /// Short name, used in notes, metadata and slice transforms.
    pub fn name(self) -> String {
        match self {
            Self::Swap16 => "16-bit byte swap".into(),
            Self::Swap32 => "32-bit byte swap".into(),
            Self::Interleave {
                lanes,
                reversed: false,
            } => format!("{lanes}-lane interleave"),
            Self::Interleave {
                lanes,
                reversed: true,
            } => format!("{lanes}-lane interleave, lanes reversed"),
            Self::NandSpare { page, spare } => {
                format!("NAND spare removal ({page}+{spare} B pages)")
            }
        }
    }

    /// Whether the transform is defined for an input of `len` bytes.
    pub fn applies(self, len: usize) -> bool {
        if len > MAX_PAYLOAD {
            return false;
        }
        match self {
            Self::Swap16 => len >= 2,
            Self::Swap32 => len >= 4,
            Self::Interleave { lanes, .. } => len % lanes == 0 && len / lanes >= MIN_LANE_SIZE,
            Self::NandSpare { page, spare } => {
                len % (page + spare) == 0 && len / (page + spare) >= MIN_NAND_PAGES
            }
        }
    }

    /// Whether the stored bytes can be the lanes of one program. Every lane
    /// of a split memory holds one byte of each bus word, so all lanes carry
    /// content in the same places; a file whose first half is zero fill
    /// and whose second half holds data is no 2-lane split (Qualcomm data
    /// segments read as ARM after interleaving, fw1 audit 2026-11-04).
    /// Content in a lane window means its most common byte covers less than
    /// nine tenths of it; every lane must hold content in at least half of
    /// the windows where any lane does. Transforms other than interleaves
    /// always agree.
    pub fn lanes_agree(self, data: &[u8]) -> bool {
        let Self::Interleave { lanes, .. } = self else {
            return true;
        };
        if !self.applies(data.len()) {
            return false;
        }
        let lane_size = data.len() / lanes;
        let lanes: Vec<&[u8]> = data.chunks_exact(lane_size).collect();
        let mut any_content = 0usize;
        let mut all_content = 0usize;
        for start in (0..lane_size).step_by(LANE_WINDOW) {
            let end = (start + LANE_WINDOW).min(lane_size);
            let content = lanes
                .iter()
                .filter(|lane| !is_fill(&lane[start..end]))
                .count();
            if content > 0 {
                any_content += 1;
            }
            if content == lanes.len() {
                all_content += 1;
            }
        }
        any_content > 0 && 2 * all_content >= any_content
    }

    /// The rearranged bytes, or `None` when the transform does not apply.
    pub fn apply(self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.applies(data.len()) {
            return None;
        }
        Some(match self {
            Self::Swap16 => swap_words(data, 2),
            Self::Swap32 => swap_words(data, 4),
            Self::Interleave { lanes, reversed } => {
                let lane_size = data.len() / lanes;
                let mut parts: Vec<&[u8]> = data.chunks_exact(lane_size).collect();
                if reversed {
                    parts.reverse();
                }
                interleave_lanes(&parts)
            }
            Self::NandSpare { page, spare } => data
                .chunks_exact(page + spare)
                .flat_map(|chunk| &chunk[..page])
                .copied()
                .collect(),
        })
    }

    /// The stored range that holds `size` transformed bytes at `offset`,
    /// for spare-area removal; other transforms permute bytes across the
    /// whole input, so the stored range is the input itself.
    pub fn stored_range(self, offset: usize, size: usize, input_len: usize) -> StoredRange {
        match self {
            Self::NandSpare { page, spare } if size > 0 => {
                let stored = |o: usize| (o / page) * (page + spare) + o % page;
                let start = stored(offset);
                StoredRange {
                    offset: start,
                    size: stored(offset + size - 1) + 1 - start,
                }
            }
            _ => StoredRange {
                offset: 0,
                size: input_len,
            },
        }
    }
}

/// `data` with the bytes of every whole `width`-byte word reversed; a
/// trailing partial word is kept as stored.
fn swap_words(data: &[u8], width: usize) -> Vec<u8> {
    let words = data.chunks_exact(width);
    let tail = words.remainder();
    let mut out: Vec<u8> = words.flat_map(|w| w.iter().rev().copied()).collect();
    out.extend_from_slice(tail);
    out
}

/// Whether one byte value covers [`LANE_FILL_TENTHS`] of the bytes.
fn is_fill(bytes: &[u8]) -> bool {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let most = counts.iter().copied().max().unwrap_or(0);
    most * 10 >= bytes.len() * LANE_FILL_TENTHS
}

/// Interleave equal-length lanes: byte `i` of lane `j` becomes byte
/// `i * lanes + j`.
fn interleave_lanes(lanes: &[&[u8]]) -> Vec<u8> {
    let lane_size = lanes.first().map_or(0, |lane| lane.len());
    let mut out = Vec::with_capacity(lane_size * lanes.len());
    for i in 0..lane_size {
        for lane in lanes {
            out.push(lane[i]);
        }
    }
    out
}

/// Interleave separately dumped byte lanes (for example the even and odd
/// EPROMs of a 16-bit bus) into one image, lane 0 first.
///
/// # Errors
///
/// [`ClassifierError::ConfigError`] unless there are two to eight lanes of
/// equal, non-zero length whose total fits in [`MAX_PAYLOAD`].
pub fn interleave(lanes: &[&[u8]]) -> Result<Vec<u8>> {
    let invalid = |message: String| ClassifierError::ConfigError { message };
    if !(2..=8).contains(&lanes.len()) {
        return Err(invalid(format!(
            "Invalid lane count {}: interleaving needs 2 to 8 files",
            lanes.len()
        )));
    }
    let lane_size = lanes[0].len();
    if lane_size == 0 || lanes.iter().any(|lane| lane.len() != lane_size) {
        return Err(invalid(
            "Invalid lanes: interleaved files must be non-empty and the same size".into(),
        ));
    }
    if lane_size
        .checked_mul(lanes.len())
        .map_or(true, |total| total > MAX_PAYLOAD)
    {
        return Err(invalid("Interleaved image exceeds 64 MiB".into()));
    }
    Ok(interleave_lanes(lanes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_and_interleaves_rearrange_bytes() {
        let data: Vec<u8> = (0..8).collect();
        assert_eq!(
            Transform::Swap16.apply(&data).unwrap(),
            [1, 0, 3, 2, 5, 4, 7, 6]
        );
        assert_eq!(
            Transform::Swap32.apply(&data).unwrap(),
            [3, 2, 1, 0, 7, 6, 5, 4]
        );
        let lanes = interleave(&[&[0, 2, 4], &[1, 3, 5]]).unwrap();
        assert_eq!(lanes, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn lanes_agree_only_when_every_lane_holds_content_where_the_others_do() {
        let transform = Transform::Interleave {
            lanes: 2,
            reversed: false,
        };
        let code: Vec<u8> = (0..4096u32)
            .map(|i| u8::try_from((i * 37 + i / 7) % 251).expect("below 251"))
            .collect();
        assert!(transform.lanes_agree(&code));
        // First half zero fill, second half data: no split program.
        let mut split = vec![0u8; 2048];
        split.extend_from_slice(&code[..2048]);
        assert!(!transform.lanes_agree(&split));
        // All fill: no lane holds content.
        assert!(!transform.lanes_agree(&[0xff; 4096]));
        assert!(Transform::Swap16.lanes_agree(&split));
    }

    #[test]
    fn interleave_transform_matches_separate_lanes() {
        let even: Vec<u8> = (0..=255).collect();
        let odd: Vec<u8> = (0..=255).rev().collect();
        let mut file = even.clone();
        file.extend_from_slice(&odd);
        let transform = Transform::Interleave {
            lanes: 2,
            reversed: false,
        };
        assert_eq!(
            transform.apply(&file).unwrap(),
            interleave(&[&even, &odd]).unwrap()
        );
        let reversed = Transform::Interleave {
            lanes: 2,
            reversed: true,
        };
        assert_eq!(
            reversed.apply(&file).unwrap(),
            interleave(&[&odd, &even]).unwrap()
        );
    }

    #[test]
    fn nand_spare_removal_keeps_page_data_and_maps_offsets_back() {
        let transform = Transform::NandSpare {
            page: 512,
            spare: 16,
        };
        let mut dump = Vec::new();
        for page in 0..4u8 {
            dump.extend_from_slice(&[page; 512]);
            dump.extend_from_slice(&[0xff; 16]);
        }
        let data = transform.apply(&dump).unwrap();
        assert_eq!(data.len(), 2048);
        assert!(data.iter().all(|b| *b != 0xff));
        assert_eq!(
            transform.stored_range(512, 512, dump.len()),
            StoredRange {
                offset: 528,
                size: 512
            }
        );
        assert_eq!(
            transform.stored_range(500, 24, dump.len()),
            StoredRange {
                offset: 500,
                size: 40
            }
        );
        assert!(transform.apply(&dump[..dump.len() - 1]).is_none());
    }

    #[test]
    fn byte_swaps_keep_a_trailing_partial_word() {
        // A 68000 ROM dumped byte-swapped with one byte appended.
        let dump = [0x75, 0x4E, 0x71, 0x4E, 0x00];
        assert_eq!(
            Transform::Swap16.apply(&dump).unwrap(),
            [0x4E, 0x75, 0x4E, 0x71, 0x00]
        );
        assert_eq!(
            Transform::Swap32.apply(&[1, 2, 3, 4, 5, 6]).unwrap(),
            [4, 3, 2, 1, 5, 6]
        );
    }

    #[test]
    fn transforms_refuse_inputs_they_do_not_fit() {
        assert!(!Transform::Swap16.applies(1));
        assert!(!Transform::Swap32.applies(3));
        assert!(!Transform::Interleave {
            lanes: 2,
            reversed: false
        }
        .applies(100));
        assert!(interleave(&[&[1, 2], &[3]]).is_err());
        assert!(interleave(&[&[1]]).is_err());
    }
}
