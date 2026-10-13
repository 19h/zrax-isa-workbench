//! Address ranges looked up by containment: module images and thread
//! stacks, for deciding which dumped memory is module code and for naming
//! memory ranges.

/// One `[start, end)` address range and its position in the caller's list.
#[derive(Debug, Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
    index: usize,
}

/// Address ranges sorted by start for containment queries in logarithmic
/// time, so a dump with many modules and memory ranges stays linear.
///
/// Ranges may overlap in a hostile dump. A query then looks at the ranges
/// that start at or before it and takes the one reaching furthest, which
/// contains the query whenever any of them does.
#[derive(Debug)]
pub(super) struct Regions {
    /// Ranges sorted by start (ties in list order).
    sorted: Vec<Region>,
    /// For each position in `sorted`, the position of the range with the
    /// greatest end among `sorted[..=position]` (the first on ties).
    furthest: Vec<usize>,
}

impl Regions {
    /// Index the `[start, end)` ranges, in the caller's list order.
    pub(super) fn new(ranges: impl Iterator<Item = (u64, u64)>) -> Self {
        let mut sorted: Vec<Region> = ranges
            .enumerate()
            .map(|(index, (start, end))| Region { start, end, index })
            .collect();
        sorted.sort_by_key(|r| (r.start, r.index));
        let mut furthest = Vec::with_capacity(sorted.len());
        let mut best = 0;
        for (position, region) in sorted.iter().enumerate() {
            if region.end > sorted[best].end {
                best = position;
            }
            furthest.push(best);
        }
        Self { sorted, furthest }
    }

    /// The list index of a range that contains all of `[start, end)`.
    pub(super) fn containing(&self, start: u64, end: u64) -> Option<usize> {
        let starting_before = self.sorted.partition_point(|r| r.start <= start);
        let last = starting_before.checked_sub(1)?;
        let candidate = self.sorted[self.furthest[last]];
        (candidate.end >= end).then_some(candidate.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_needs_the_whole_range() {
        let regions = Regions::new([(0x1000, 0x2000), (0x4000, 0x5000)].into_iter());
        assert_eq!(regions.containing(0x1000, 0x2000), Some(0));
        assert_eq!(regions.containing(0x1800, 0x1900), Some(0));
        assert_eq!(regions.containing(0x4000, 0x4001), Some(1));
        assert_eq!(regions.containing(0x1800, 0x2001), None);
        assert_eq!(regions.containing(0x0800, 0x1100), None);
        assert_eq!(regions.containing(0x3000, 0x3100), None);
        assert_eq!(regions.containing(0x6000, 0x6100), None);
    }

    #[test]
    fn overlapping_ranges_find_the_one_that_contains() {
        // A long range listed first, and a short one starting inside it.
        let regions = Regions::new([(0x1000, 0x9000), (0x2000, 0x2100)].into_iter());
        assert_eq!(regions.containing(0x3000, 0x3100), Some(0));
        assert_eq!(regions.containing(0x2000, 0x2080), Some(0));
        let empty = Regions::new(std::iter::empty());
        assert_eq!(empty.containing(0, 1), None);
    }
}
