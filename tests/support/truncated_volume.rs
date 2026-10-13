//! Checks for the parse of a prefix of a filesystem volume, which the
//! filesystem families read as a truncated volume: every member it lists is
//! a member of the whole volume with the same bytes, and its stored bytes
//! lie inside the prefix.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

use std::borrow::Cow;
use zrax::formats::container::Container;

/// Prefix lengths for a sweep over an image of `len` bytes: every length
/// below `dense`, then every `stride`th length, every multiple of `block`
/// and the lengths one byte before and after each multiple.
pub fn prefix_ends(len: usize, dense: usize, stride: usize, block: usize) -> Vec<usize> {
    (0..len)
        .filter(|&end| {
            let near_block = matches!(end % block, 0 | 1) || end % block == block - 1;
            end < dense || end % stride == 0 || near_block
        })
        .collect()
}

/// Every member of `prefix`, a parse of the first `end` bytes of an image
/// whose whole parse is `whole`, is listed in `whole` with the same label
/// and bytes, and its stored bytes lie inside the prefix: a prefix never
/// claims missing bytes.
pub fn assert_members_inside(
    name: &str,
    whole: &Container<'_>,
    prefix: &Container<'_>,
    end: usize,
) {
    for member in &prefix.children {
        let full = whole
            .children
            .iter()
            .find(|c| c.label == member.label)
            .unwrap_or_else(|| panic!("{name}: prefix {end} lists {}", member.label));
        assert_eq!(
            member.data, full.data,
            "{name}: prefix {end} {}",
            member.label
        );
        assert_eq!(
            member.offset, full.offset,
            "{name}: prefix {end} {}",
            member.label
        );
        assert!(
            member.offset + member.stored_size <= end,
            "{name}: prefix {end} {}",
            member.label
        );
        if let Cow::Borrowed(bytes) = member.data {
            assert!(member.offset + bytes.len() <= end, "{name}: prefix {end}");
        }
    }
}
