//! The loaded image as a map from storage addresses to stored bytes: one
//! region per BIN record, or the image part of a raw ROM file. Address gaps
//! are never materialized; a read that crosses a gap fails.

use super::*;
use std::borrow::Cow;

/// Bytes stored for one address range.
#[derive(Debug, Clone, Copy)]
pub(super) struct Region<'a> {
    /// Storage address of `bytes[0]`.
    pub(super) address: u64,
    /// File offset of `bytes[0]`.
    pub(super) offset: usize,
    /// The stored bytes.
    pub(super) bytes: &'a [u8],
}

impl Region<'_> {
    /// First storage address after the region.
    fn end(&self) -> u64 {
        self.address + to_u64(self.bytes.len())
    }
}

/// Non-overlapping, non-empty regions sorted by address.
#[derive(Debug)]
pub(super) struct Memory<'a> {
    regions: Vec<Region<'a>>,
    size: u64,
}

impl<'a> Memory<'a> {
    /// A map of `regions`, which the caller has checked do not overlap.
    /// Empty regions are dropped.
    pub(super) fn new(mut regions: Vec<Region<'a>>) -> Self {
        regions.retain(|r| !r.bytes.is_empty());
        regions.sort_unstable_by_key(|r| r.address);
        let size = regions.iter().map(|r| to_u64(r.bytes.len())).sum();
        Self { regions, size }
    }

    /// Total stored bytes.
    pub(super) fn size(&self) -> u64 {
        self.size
    }

    /// Index of the region that holds `address`.
    fn index(&self, address: u64) -> Option<usize> {
        let i = self.regions.partition_point(|r| r.end() <= address);
        let region = self.regions.get(i)?;
        (region.address <= address).then_some(i)
    }

    /// Stored bytes from `address` (inside region `first`) on without a
    /// gap, counted up to `limit`.
    fn contiguous(&self, first: usize, address: u64, limit: u64) -> u64 {
        let mut end = self.regions[first].end();
        for region in &self.regions[first + 1..] {
            if end - address >= limit || region.address != end {
                break;
            }
            end = region.end();
        }
        (end - address).min(limit)
    }

    /// Bytes stored from `address` on without a gap, at most `max`.
    pub(super) fn prefix(&self, address: u64, max: usize) -> Option<Cow<'a, [u8]>> {
        let first = self.index(address)?;
        let region = self.regions[first];
        let start = usize::try_from(address - region.address).ok()?;
        let head = &region.bytes[start..];
        if head.len() >= max {
            return Some(Cow::Borrowed(&head[..max]));
        }
        let available = usize::try_from(self.contiguous(first, address, to_u64(max))).ok()?;
        if available == head.len() {
            return Some(Cow::Borrowed(head));
        }
        let mut bytes = Vec::with_capacity(available);
        bytes.extend_from_slice(head);
        for region in &self.regions[first + 1..] {
            let wanted = available - bytes.len();
            if wanted == 0 {
                break;
            }
            bytes.extend_from_slice(&region.bytes[..region.bytes.len().min(wanted)]);
        }
        Some(Cow::Owned(bytes))
    }

    /// Exactly `len` bytes at `address`, which may continue across
    /// address-contiguous regions.
    pub(super) fn read(&self, address: u64, len: usize) -> Option<Cow<'a, [u8]>> {
        self.prefix(address, len).filter(|bytes| bytes.len() == len)
    }

    /// Whether `len` bytes from `address` on are stored without a gap.
    pub(super) fn covers(&self, address: u64, len: u64) -> bool {
        len == 0
            || self
                .index(address)
                .is_some_and(|first| self.contiguous(first, address, len) == len)
    }

    /// The `len` bytes at `address` when one region holds them all: their
    /// file offset and the stored bytes.
    pub(super) fn stored(&self, address: u64, len: usize) -> Option<(usize, &'a [u8])> {
        let region = self.regions[self.index(address)?];
        let start = usize::try_from(address - region.address).ok()?;
        let bytes = region.bytes.get(start..start.checked_add(len)?)?;
        Some((region.offset + start, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(address: u64, offset: usize, bytes: &[u8]) -> Region<'_> {
        Region {
            address,
            offset,
            bytes,
        }
    }

    #[test]
    fn reads_cross_contiguous_regions_but_not_gaps() {
        let low = [1u8, 2, 3, 4];
        let high = [5u8, 6];
        let far = [9u8; 4];
        let memory = Memory::new(vec![
            region(0x1004, 0x40, &high),
            region(0x1000, 0x10, &low),
            region(0x2000, 0x80, &far),
            region(0x3000, 0x90, &[]),
        ]);
        assert_eq!(memory.size(), 10);
        assert_eq!(memory.read(0x1002, 4).as_deref(), Some(&[3u8, 4, 5, 6][..]));
        assert_eq!(memory.read(0x1000, 4).as_deref(), Some(&low[..]));
        assert_eq!(memory.read(0x1002, 5), None);
        assert_eq!(memory.read(0x0fff, 1), None);
        assert_eq!(memory.read(0x3000, 1), None);
        assert_eq!(memory.prefix(0x1003, 64).as_deref(), Some(&[4u8, 5, 6][..]));
        assert_eq!(memory.prefix(0x1003, 2).as_deref(), Some(&[4u8, 5][..]));
        assert!(memory.covers(0x1000, 6));
        assert!(!memory.covers(0x1000, 7));
        assert!(memory.covers(0x1800, 0));
        assert!(!memory.covers(0x1800, 1));
        assert_eq!(memory.stored(0x1001, 2), Some((0x11, &low[1..3])));
        assert_eq!(memory.stored(0x1003, 2), None);
        assert_eq!(memory.stored(0x2002, 2), Some((0x82, &far[2..])));
    }
}
