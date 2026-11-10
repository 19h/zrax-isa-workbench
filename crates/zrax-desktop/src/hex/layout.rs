//! Geometry of the hex grid: where each byte and glyph sits in a row, and
//! which byte a point falls on.
//!
//! Source: the `.hex-*` rules of `web/workbench.css`. All lengths are in
//! `rem`, measured from the left edge of a row.

/// Height of a byte row.
pub const ROW_REMS: f32 = 1.25;
/// Height of the column-header row.
pub const HEAD_REMS: f32 = 1.75;
/// Font size of the grid.
pub const FONT_REMS: f32 = 0.75;
/// Padding left and right of the rows.
pub const PADDING_REMS: f32 = 0.75;

const OFFSET_REMS: f32 = 5.5;
/// Width of a byte cell.
pub const BYTE_REMS: f32 = 1.375;
const GROUP_GAP_REMS: f32 = 0.5;
/// Space on each side of the divider between bytes and text.
const DIVIDER_GAP_REMS: f32 = 0.75;
/// Width of the glyph of one byte in the text column.
pub const CHAR_REMS: f32 = 0.5625;

/// The part of a row a point falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// The hex digits of the byte in this column.
    Bytes(usize),
    /// The text glyph of the byte in this column.
    Text(usize),
}

impl Area {
    /// The byte column, whichever side was hit.
    pub fn column(self) -> usize {
        match self {
            Area::Bytes(column) | Area::Text(column) => column,
        }
    }
}

/// The layout of one row for a column count and grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridLayout {
    /// Bytes per row.
    pub columns: usize,
    /// Bytes per visual group; a gap follows each full group.
    pub group: usize,
}

// Column counts are at most 32, exact in f32.
#[allow(clippy::cast_precision_loss)]
impl GridLayout {
    /// Left edge of the byte cell in `column`.
    pub fn byte_left(self, column: usize) -> f32 {
        let gaps_before = column / self.group.max(1);
        PADDING_REMS + OFFSET_REMS + column as f32 * BYTE_REMS + gaps_before as f32 * GROUP_GAP_REMS
    }

    /// Right edge of the last byte cell.
    pub fn bytes_right(self) -> f32 {
        self.byte_left(self.columns.saturating_sub(1)) + BYTE_REMS
    }

    /// Horizontal position of the divider between bytes and text.
    pub fn divider(self) -> f32 {
        self.bytes_right() + DIVIDER_GAP_REMS
    }

    /// Left edge of the text glyph of the byte in `column`.
    pub fn char_left(self, column: usize) -> f32 {
        self.divider() + DIVIDER_GAP_REMS + column as f32 * CHAR_REMS
    }

    /// What `x` falls on. A group gap belongs to the byte before it, so a
    /// drag across a row never passes over dead space.
    pub fn area_at(self, x: f32) -> Option<Area> {
        if x >= self.char_left(0) {
            // Non-negative and at most a few thousand.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let column = ((x - self.char_left(0)) / CHAR_REMS) as usize;
            return (column < self.columns).then_some(Area::Text(column));
        }
        if x < self.byte_left(0) || x >= self.bytes_right() {
            return None;
        }
        (0..self.columns)
            .rev()
            .find(|column| x >= self.byte_left(*column))
            .map(Area::Bytes)
    }
}

/// Rows needed for `size` bytes at `columns` per row; at least one.
pub fn row_count(size: u64, columns: usize) -> u64 {
    size.div_ceil(columns.max(1) as u64).max(1)
}

/// The first row to show so that `row` is visible in a viewport of
/// `visible` rows currently starting at `top`: unchanged when it already
/// is, otherwise scrolled just far enough.
pub fn top_row_showing(row: u64, top: u64, visible: u64, total: u64) -> u64 {
    let visible = visible.max(1);
    let top = if row < top {
        row
    } else if row >= top + visible {
        row + 1 - visible
    } else {
        top
    };
    top.min(total.saturating_sub(visible))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: GridLayout = GridLayout {
        columns: 16,
        group: 4,
    };

    #[test]
    fn groups_are_separated_by_a_gap_but_the_row_does_not_end_with_one() {
        assert_eq!(LAYOUT.byte_left(0), 6.25);
        assert_eq!(LAYOUT.byte_left(3), 6.25 + 3.0 * 1.375);
        assert_eq!(LAYOUT.byte_left(4), 6.25 + 4.0 * 1.375 + 0.5);
        assert_eq!(LAYOUT.bytes_right(), 6.25 + 16.0 * 1.375 + 3.0 * 0.5);
        assert_eq!(LAYOUT.char_left(0), LAYOUT.bytes_right() + 1.5);
    }

    #[test]
    fn points_map_to_bytes_text_or_nothing() {
        assert_eq!(LAYOUT.area_at(0.0), None);
        assert_eq!(LAYOUT.area_at(6.24), None);
        assert_eq!(LAYOUT.area_at(6.25), Some(Area::Bytes(0)));
        assert_eq!(
            LAYOUT.area_at(LAYOUT.byte_left(4) - 0.1),
            Some(Area::Bytes(3))
        );
        assert_eq!(
            LAYOUT.area_at(LAYOUT.byte_left(15) + 0.2),
            Some(Area::Bytes(15))
        );
        assert_eq!(LAYOUT.area_at(LAYOUT.bytes_right() + 0.1), None);
        assert_eq!(LAYOUT.area_at(LAYOUT.char_left(0)), Some(Area::Text(0)));
        assert_eq!(
            LAYOUT.area_at(LAYOUT.char_left(15) + 0.1),
            Some(Area::Text(15))
        );
        assert_eq!(LAYOUT.area_at(LAYOUT.char_left(16)), None);
    }

    #[test]
    fn rows_cover_the_file_and_an_empty_file_has_one() {
        assert_eq!(row_count(0, 16), 1);
        assert_eq!(row_count(16, 16), 1);
        assert_eq!(row_count(17, 16), 2);
        assert_eq!(row_count(72_080, 16), 4505);
    }

    #[test]
    fn scrolling_follows_the_cursor_only_as_far_as_needed() {
        assert_eq!(top_row_showing(5, 0, 25, 4505), 0);
        assert_eq!(top_row_showing(25, 0, 25, 4505), 1);
        assert_eq!(top_row_showing(3, 10, 25, 4505), 3);
        assert_eq!(top_row_showing(4504, 0, 25, 4505), 4480);
        assert_eq!(top_row_showing(0, 0, 25, 3), 0);
    }
}
