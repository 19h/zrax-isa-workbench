//! The hex tab: a virtual byte grid with a text column, an entropy scroll
//! track and the data inspector (`renderHex` and `renderDataInspector` in
//! the browser).
//!
//! The grid is painted directly: only the visible rows exist, whatever the
//! file size, and positions are plain arithmetic over
//! [`crate::hex::layout`], which also resolves pointer positions to bytes.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use gpui::{
    actions, canvas, div, fill, font, outline, point, prelude::*, px, rems, size, App, BorderStyle,
    Bounds, ClipboardItem, Context, Div, Entity, FocusHandle, Focusable, Hsla, KeyBinding,
    MouseButton, MouseDownEvent, MouseMoveEvent, Pixels, Point, Rgba, ScrollEvent, SharedString,
    Subscription, TextAlign, TextRun, Window,
};
use zrax::types::Endianness;
use zrax::workbench::Engine;

use super::text_field::{TextField, TextFieldEvent};
use super::widgets::{bar, key_cap, small, spacer, text_button};
use crate::hex::codec::{self, TextEncoding};
use crate::hex::inspector;
use crate::hex::layout::{self, Area, GridLayout};
use crate::model::entry::EntryId;
use crate::model::session::{Session, SessionEvent};
use crate::{format, palette, theme};

/// Key context of the grid: navigation keys are bound here.
const KEY_CONTEXT: &str = "HexGrid";

/// Where the grid's keys apply: not while the goto field has focus.
const GRID_CONTEXT: &str = "HexGrid && !TextField";

/// Longest text the goto field takes: a signed 64-bit hex offset and spare.
const GOTO_CHARS: usize = 24;

/// Column counts offered by the toolbar.
const COLUMN_CHOICES: [usize; 4] = [8, 16, 24, 32];
/// Group sizes offered by the toolbar.
const GROUP_CHOICES: [usize; 4] = [1, 2, 4, 8];

/// Largest selection copied to the clipboard as hex text, in bytes.
const MAX_COPY_BYTES: u64 = 1024 * 1024;

/// Rows shown before the viewport has been measured.
const DEFAULT_VISIBLE_ROWS: usize = 25;

/// Width of the entropy scroll track.
const TRACK_REMS: f32 = 0.875;
/// Smallest height of the track's thumb.
const MIN_THUMB_REMS: f32 = 0.375;
/// Height of the cursor tick on the track.
const TICK_REMS: f32 = 0.125;

actions!(
    hex,
    [
        /// Move the cursor one byte back.
        MoveLeft,
        /// Move the cursor one byte forward.
        MoveRight,
        /// Move the cursor one row up.
        MoveUp,
        /// Move the cursor one row down.
        MoveDown,
        /// Move the cursor one page up.
        MovePageUp,
        /// Move the cursor one page down.
        MovePageDown,
        /// Move the cursor to the start of its row.
        MoveRowStart,
        /// Move the cursor to the end of its row.
        MoveRowEnd,
        /// Extend the selection one byte back.
        SelectLeft,
        /// Extend the selection one byte forward.
        SelectRight,
        /// Extend the selection one row up.
        SelectUp,
        /// Extend the selection one row down.
        SelectDown,
        /// Extend the selection one page up.
        SelectPageUp,
        /// Extend the selection one page down.
        SelectPageDown,
        /// Extend the selection to the start of the row.
        SelectRowStart,
        /// Extend the selection to the end of the row.
        SelectRowEnd,
        /// Drop the selection.
        ClearSelection,
        /// Copy the selected bytes as hex text.
        CopySelection,
        /// Put the keyboard focus in the goto field.
        FocusGoto,
    ]
);

#[cfg(target_os = "macos")]
const COPY_CHORD: &str = "cmd-c";
#[cfg(not(target_os = "macos"))]
const COPY_CHORD: &str = "ctrl-c";

/// Bind the grid's navigation keys (`web/workbench.js`, hex key handler).
pub fn bind_keys(cx: &mut App) {
    let context = Some(GRID_CONTEXT);
    cx.bind_keys([
        KeyBinding::new("g", FocusGoto, context),
        KeyBinding::new("left", MoveLeft, context),
        KeyBinding::new("right", MoveRight, context),
        KeyBinding::new("up", MoveUp, context),
        KeyBinding::new("down", MoveDown, context),
        KeyBinding::new("pageup", MovePageUp, context),
        KeyBinding::new("pagedown", MovePageDown, context),
        KeyBinding::new("home", MoveRowStart, context),
        KeyBinding::new("end", MoveRowEnd, context),
        KeyBinding::new("shift-left", SelectLeft, context),
        KeyBinding::new("shift-right", SelectRight, context),
        KeyBinding::new("shift-up", SelectUp, context),
        KeyBinding::new("shift-down", SelectDown, context),
        KeyBinding::new("shift-pageup", SelectPageUp, context),
        KeyBinding::new("shift-pagedown", SelectPageDown, context),
        KeyBinding::new("shift-home", SelectRowStart, context),
        KeyBinding::new("shift-end", SelectRowEnd, context),
        KeyBinding::new("escape", ClearSelection, context),
        KeyBinding::new(COPY_CHORD, CopySelection, context),
    ]);
}

/// How row offsets are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffsetBase {
    Hex,
    Decimal,
}

/// A cursor movement, in bytes or rows.
#[derive(Debug, Clone, Copy)]
enum Motion {
    Bytes(i64),
    Rows(i64),
    Pages(i64),
    RowStart,
    RowEnd,
}

/// Uppercase two-digit hex of every byte value, shaped once and reused.
fn byte_text(byte: u8) -> SharedString {
    static TEXTS: OnceLock<Vec<SharedString>> = OnceLock::new();
    TEXTS.get_or_init(|| {
        (0..=u8::MAX)
            .map(|value| SharedString::from(format::hex(u64::from(value), 2)))
            .collect()
    })[usize::from(byte)]
    .clone()
}

fn byte_color(byte: u8) -> Rgba {
    match byte {
        0x00 => theme::byte::ZERO,
        0xFF => theme::byte::FULL,
        0x01..=0x1F | 0x7F => theme::byte::CONTROL,
        0x20..=0x7E => theme::byte::ASCII,
        _ => theme::byte::HIGH,
    }
}

/// Everything the grid's paint pass needs, detached from the view.
struct GridFrame {
    engine: Engine,
    layout: GridLayout,
    encoding: TextEncoding,
    offset_base: OffsetBase,
    top_row: u64,
    cursor: u64,
    /// Inclusive byte range of the selection.
    selection: Option<(u64, u64)>,
}

/// Paint `text` with its left edge at `origin`, or centered in a cell of
/// `cell_width` starting there.
fn paint_text(
    text: SharedString,
    origin: Point<Pixels>,
    cell_width: Option<Pixels>,
    color: Rgba,
    row_height: Pixels,
    window: &mut Window,
    cx: &mut App,
) {
    if text.is_empty() {
        return;
    }
    let font_size = window.rem_size() * layout::FONT_REMS;
    let run = TextRun {
        len: text.len(),
        font: font(theme::FONT_MONO),
        color: Hsla::from(color),
        background_color: None,
        underline: None,
        strikethrough: None,
    };
    let line = window
        .text_system()
        .shape_line(text, font_size, &[run], None);
    let x = match cell_width {
        Some(cell_width) => origin.x + (cell_width - line.width) / 2.0,
        None => origin.x,
    };
    // Painting a shaped line fails only when its glyphs cannot be
    // rasterized; the cell then stays empty.
    let _ = line.paint(
        point(x, origin.y),
        row_height,
        TextAlign::Left,
        None,
        window,
        cx,
    );
}

impl GridFrame {
    fn is_selected(&self, offset: u64) -> bool {
        self.selection
            .is_some_and(|(first, last)| (first..=last).contains(&offset))
    }

    /// Text and background colors of the cell at `offset` holding `byte`.
    fn cell_colors(&self, offset: u64, byte: u8) -> (Rgba, Option<Rgba>) {
        if offset == self.cursor {
            (theme::TEXT_INVERSE, Some(theme::ACCENT))
        } else if self.is_selected(offset) {
            (byte_color(byte), Some(theme::ACCENT_WASH))
        } else {
            (byte_color(byte), None)
        }
    }

    fn paint(&self, bounds: Bounds<Pixels>, window: &mut Window, cx: &mut App) {
        let rem = window.rem_size();
        let row_height = rem * layout::ROW_REMS;
        let head_height = rem * layout::HEAD_REMS;
        let columns = self.layout.columns;
        let x = |rems: f32| bounds.origin.x + rem * rems;

        // Header: column numbers and the encoding.
        let head_top = bounds.origin.y + (head_height - row_height) / 2.0;
        paint_text(
            "offset".into(),
            point(x(layout::PADDING_REMS), head_top),
            None,
            theme::TEXT_MUTED,
            row_height,
            window,
            cx,
        );
        for column in 0..columns {
            // A column index below 32 fits a byte.
            #[allow(clippy::cast_possible_truncation)]
            let label = byte_text(column as u8);
            paint_text(
                label,
                point(x(self.layout.byte_left(column)), head_top),
                Some(rem * layout::BYTE_REMS),
                theme::TEXT_MUTED,
                row_height,
                window,
                cx,
            );
        }
        paint_text(
            self.encoding.id().into(),
            point(x(self.layout.char_left(0)), head_top),
            None,
            theme::TEXT_MUTED,
            row_height,
            window,
            cx,
        );
        let head_line = Bounds::new(
            point(bounds.origin.x, bounds.origin.y + head_height - px(1.0)),
            size(bounds.size.width, px(1.0)),
        );
        window.paint_quad(fill(head_line, theme::LINE_DEFAULT));
        let divider = Bounds::new(
            point(x(self.layout.divider()), bounds.origin.y),
            size(px(1.0), bounds.size.height),
        );
        window.paint_quad(fill(divider, theme::LINE_HAIRLINE));

        // Rows.
        let data = self.engine.data();
        let size_bytes = data.len() as u64;
        let rows_top = bounds.origin.y + head_height;
        let visible_height = bounds.size.height - head_height;
        // A viewport holds at most a few hundred rows.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let visible_rows = (visible_height / row_height).ceil().max(0.0) as u64;
        let offset_width = size_bytes.to_string().len();
        for visible_row in 0..visible_rows {
            let row = self.top_row + visible_row;
            let Some(row_offset) = row.checked_mul(columns as u64) else {
                break;
            };
            if row_offset >= size_bytes {
                break;
            }
            // In bounds: `row_offset < size_bytes`, a length that fits usize.
            #[allow(clippy::cast_possible_truncation)]
            let start = row_offset as usize;
            let bytes = &data[start..data.len().min(start + columns)];
            #[allow(clippy::cast_precision_loss)]
            let top = rows_top + row_height * visible_row as f32;

            let holds_cursor = (row_offset..row_offset + columns as u64).contains(&self.cursor);
            let offset_text = match self.offset_base {
                OffsetBase::Hex => format::hex(row_offset, 8),
                OffsetBase::Decimal => format!("{row_offset:>offset_width$}"),
            };
            paint_text(
                offset_text.into(),
                point(x(layout::PADDING_REMS), top),
                None,
                if holds_cursor {
                    theme::ACCENT
                } else {
                    theme::TEXT_MUTED
                },
                row_height,
                window,
                cx,
            );

            for (column, &byte) in bytes.iter().enumerate() {
                let offset = row_offset + column as u64;
                let (color, background) = self.cell_colors(offset, byte);
                let left = x(self.layout.byte_left(column));
                let width = rem * layout::BYTE_REMS;
                if let Some(background) = background {
                    let cell = Bounds::new(point(left, top), size(width, row_height));
                    window.paint_quad(fill(cell, background));
                }
                paint_text(
                    byte_text(byte),
                    point(left, top),
                    Some(width),
                    color,
                    row_height,
                    window,
                    cx,
                );
            }
            self.paint_text_column(bytes, row_offset, point(bounds.origin.x, top), window, cx);
        }
    }

    /// Paint the text glyphs of one row: one per byte, or one per two
    /// bytes for UTF-16.
    fn paint_text_column(
        &self,
        bytes: &[u8],
        row_offset: u64,
        row_origin: Point<Pixels>,
        window: &mut Window,
        cx: &mut App,
    ) {
        let rem = window.rem_size();
        let row_height = rem * layout::ROW_REMS;
        let top = row_origin.y;
        let unit = self.encoding.unit_bytes();
        // One or two bytes per glyph.
        #[allow(clippy::cast_precision_loss)]
        let glyph_width = rem * (layout::CHAR_REMS * unit as f32);
        for (index, chunk) in bytes.chunks(unit).enumerate() {
            let column = index * unit;
            let offset = row_offset + column as u64;
            let glyph = match (self.encoding, chunk) {
                (TextEncoding::Utf16Le, [low, high]) => {
                    codec::utf16_glyph(u16::from_le_bytes([*low, *high]))
                }
                (TextEncoding::Utf16Be, [high, low]) => {
                    codec::utf16_glyph(u16::from_be_bytes([*high, *low]))
                }
                (TextEncoding::Utf16Le | TextEncoding::Utf16Be, _) => codec::UNPRINTABLE,
                (encoding, _) => codec::byte_glyph(encoding, chunk[0]),
            };
            // The glyph of a UTF-16 unit is under the cursor on either byte.
            let holds_cursor = (offset..offset + unit as u64).contains(&self.cursor);
            let (color, background) = if holds_cursor {
                (theme::TEXT_INVERSE, Some(theme::ACCENT))
            } else {
                self.cell_colors(offset, chunk[0])
            };
            let left = row_origin.x + rem * self.layout.char_left(column);
            if let Some(background) = background {
                let cell = Bounds::new(point(left, top), size(glyph_width, row_height));
                window.paint_quad(fill(cell, background));
            }
            let mut text = String::new();
            text.push(glyph);
            paint_text(
                text.into(),
                point(left, top),
                Some(glyph_width),
                color,
                row_height,
                window,
                cx,
            );
        }
    }
}

/// The hex tab of the selected file.
pub struct HexView {
    session: Entity<Session>,
    focus: FocusHandle,
    columns: usize,
    group: usize,
    offset_base: OffsetBase,
    encoding: TextEncoding,
    /// The other end of the selection; the cursor is the moving end.
    anchor: Option<u64>,
    top_row: u64,
    /// Whole rows that fit the viewport, measured while painting.
    visible_rows: Rc<Cell<usize>>,
    reveal_after_measurement: bool,
    /// Where the grid and the track were last painted, for hit testing.
    grid_bounds: Rc<Cell<Bounds<Pixels>>>,
    track_bounds: Rc<Cell<Bounds<Pixels>>>,
    /// The user's byte-order choice; `None` follows the classification.
    is_little_endian: Option<bool>,
    /// The byte a drag started on, while the button is down.
    drag_origin: Option<u64>,
    is_dragging_track: bool,
    /// Wheel movement not yet amounting to a whole row, in pixels.
    scroll_remainder: Pixels,
    goto_field: Entity<TextField>,
    /// Whether the last submitted goto text could not be read.
    is_goto_invalid: bool,
    _subscriptions: Vec<Subscription>,
}

impl Focusable for HexView {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl HexView {
    /// A hex view over the selected entry of `session`.
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let goto_field = cx.new(|cx| {
            let accepts = |c: char| c.is_ascii_hexdigit() || "xXhH+-%._ ".contains(c);
            TextField::new("", "0x… / +16 / 50%", GOTO_CHARS, accepts, cx)
        });
        let subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe(&goto_field, |this, field, event: &TextFieldEvent, cx| {
                let text = field.read(cx).text().to_string();
                this.on_goto_event(&text, *event, cx);
            }),
            cx.subscribe(&session, |this, _, event: &SessionEvent, cx| {
                if *event == SessionEvent::SelectionChanged {
                    this.anchor = None;
                    this.is_little_endian = None;
                    this.drag_origin = None;
                    this.reveal_cursor(cx);
                }
            }),
        ];
        Self {
            session,
            focus: cx.focus_handle(),
            columns: 16,
            group: 4,
            offset_base: OffsetBase::Hex,
            encoding: TextEncoding::Ascii,
            anchor: None,
            top_row: 0,
            visible_rows: Rc::new(Cell::new(DEFAULT_VISIBLE_ROWS)),
            reveal_after_measurement: false,
            grid_bounds: Rc::new(Cell::new(Bounds::default())),
            track_bounds: Rc::new(Cell::new(Bounds::default())),
            is_little_endian: None,
            drag_origin: None,
            is_dragging_track: false,
            scroll_remainder: px(0.0),
            goto_field,
            is_goto_invalid: false,
            _subscriptions: subscriptions,
        }
    }

    /// React to the goto field: jump to the typed offset when it is
    /// submitted.
    fn on_goto_event(&mut self, text: &str, event: TextFieldEvent, cx: &mut Context<Self>) {
        match event {
            TextFieldEvent::Changed => self.is_goto_invalid = false,
            TextFieldEvent::Cancelled => {}
            TextFieldEvent::Submitted => {
                let Some((_, size_bytes, cursor)) = self.target(cx) else {
                    return;
                };
                let parsed = codec::parse_goto(text, cursor, size_bytes);
                self.is_goto_invalid = parsed.is_none();
                if let Some(offset) = parsed {
                    // Out-of-file targets land on the nearest end.
                    let last = i128::from(size_bytes.saturating_sub(1));
                    let offset = u64::try_from(offset.clamp(0, last)).unwrap_or(0);
                    self.set_cursor(offset, false, cx);
                    // Show the target a third of the way down, with context.
                    let row = offset / self.columns as u64;
                    let lead = self.visible_rows.get() as u64 / 3;
                    self.top_row = self.clamp_top_row(row.saturating_sub(lead), size_bytes);
                }
            }
        }
        cx.notify();
    }

    fn layout(&self) -> GridLayout {
        GridLayout {
            columns: self.columns,
            group: self.group,
        }
    }

    /// Id, size and cursor of the selected entry.
    fn target(&self, cx: &App) -> Option<(EntryId, u64, u64)> {
        let entry = self.session.read(cx).selected()?;
        Some((entry.id, entry.size, entry.cursor))
    }

    fn total_rows(&self, size_bytes: u64) -> u64 {
        layout::row_count(size_bytes, self.columns)
    }

    fn clamp_top_row(&self, top_row: u64, size_bytes: u64) -> u64 {
        let visible = self.visible_rows.get().max(1) as u64;
        top_row.min(self.total_rows(size_bytes).saturating_sub(visible))
    }

    /// Scroll just far enough that the cursor's row is visible.
    fn reveal_cursor(&mut self, cx: &mut Context<Self>) {
        if let Some((_, size_bytes, cursor)) = self.target(cx) {
            self.top_row = layout::top_row_showing(
                cursor / self.columns as u64,
                self.top_row,
                self.visible_rows.get() as u64,
                self.total_rows(size_bytes),
            );
        }
        cx.notify();
    }

    /// Reveal the byte selected by another inspection tab.
    pub(super) fn jump_to_cursor(&mut self, cx: &mut Context<Self>) {
        self.anchor = None;
        self.reveal_after_measurement = true;
        self.reveal_cursor(cx);
    }

    /// Put the cursor on `offset` (clamped to the file). `extend` keeps or
    /// starts a selection from the previous cursor.
    fn set_cursor(&mut self, offset: u64, extend: bool, cx: &mut Context<Self>) {
        let Some((id, size_bytes, cursor)) = self.target(cx) else {
            return;
        };
        self.anchor = if extend {
            Some(self.anchor.unwrap_or(cursor))
        } else {
            None
        };
        let offset = offset.min(size_bytes.saturating_sub(1));
        self.session
            .update(cx, |session, cx| session.set_cursor(id, offset, cx));
        self.reveal_cursor(cx);
    }

    fn move_cursor(&mut self, motion: Motion, extend: bool, cx: &mut Context<Self>) {
        let Some((_, _, cursor)) = self.target(cx) else {
            return;
        };
        let columns = self.columns as u64;
        let page = self.visible_rows.get().max(1) as u64 * columns;
        let step = |cursor: u64, delta: i64, unit: u64| {
            let distance = delta.unsigned_abs().saturating_mul(unit);
            if delta < 0 {
                cursor.saturating_sub(distance)
            } else {
                cursor.saturating_add(distance)
            }
        };
        let target = match motion {
            Motion::Bytes(delta) => step(cursor, delta, 1),
            Motion::Rows(delta) => step(cursor, delta, columns),
            Motion::Pages(delta) => step(cursor, delta, page),
            Motion::RowStart => cursor - cursor % columns,
            Motion::RowEnd => cursor - cursor % columns + columns - 1,
        };
        self.set_cursor(target, extend, cx);
    }

    /// A handler for action `A` that moves the cursor by `motion`.
    fn motion<A>(
        motion: Motion,
        extend: bool,
    ) -> impl Fn(&mut Self, &A, &mut Window, &mut Context<Self>) {
        move |this, _, _, cx| this.move_cursor(motion, extend, cx)
    }

    /// The inclusive byte range of the selection.
    fn selection(&self, cursor: u64) -> Option<(u64, u64)> {
        self.anchor
            .map(|anchor| (anchor.min(cursor), anchor.max(cursor)))
    }

    /// The byte under a window position, if it is on the grid.
    fn byte_at(&self, position: Point<Pixels>, window: &Window, cx: &App) -> Option<(u64, Area)> {
        let (_, size_bytes, _) = self.target(cx)?;
        let bounds = self.grid_bounds.get();
        let rem = window.rem_size();
        let rows_top = bounds.origin.y + rem * layout::HEAD_REMS;
        if position.y < rows_top || !bounds.contains(&position) {
            return None;
        }
        let x_rems = (position.x - bounds.origin.x) / rem;
        let area = self.layout().area_at(x_rems)?;
        // Within the viewport: a small non-negative row index.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let visible_row = ((position.y - rows_top) / (rem * layout::ROW_REMS)) as u64;
        let offset = (self.top_row + visible_row)
            .checked_mul(self.columns as u64)?
            .checked_add(area.column() as u64)?;
        (offset < size_bytes).then_some((offset, area))
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus, cx);
        if let Some((offset, _)) = self.byte_at(event.position, window, cx) {
            self.drag_origin = Some(offset);
            self.set_cursor(offset, event.modifiers.shift, cx);
        }
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.pressed_button != Some(MouseButton::Left) {
            self.drag_origin = None;
            self.is_dragging_track = false;
            return;
        }
        if self.is_dragging_track {
            self.scroll_track_to(event.position, cx);
            return;
        }
        let Some(origin) = self.drag_origin else {
            return;
        };
        if let Some((offset, _)) = self.byte_at(event.position, window, cx) {
            let is_dragged = offset != origin || self.anchor.is_some();
            if is_dragged {
                self.anchor.get_or_insert(origin);
                self.set_cursor(offset, true, cx);
            }
        }
    }

    fn on_scroll(&mut self, event: &ScrollEvent, window: &mut Window, cx: &mut Context<Self>) {
        let Some((_, size_bytes, _)) = self.target(cx) else {
            return;
        };
        let row_height = window.rem_size() * layout::ROW_REMS;
        // Scrolling down gives a negative delta.
        self.scroll_remainder -= event.delta.pixel_delta(row_height).y;
        let rows = (self.scroll_remainder / row_height).trunc();
        self.scroll_remainder -= row_height * rows;
        // A wheel event moves a handful of rows.
        #[allow(clippy::cast_possible_truncation)]
        let top_row = self.top_row.saturating_add_signed(rows as i64);
        self.top_row = self.clamp_top_row(top_row, size_bytes);
        cx.notify();
    }

    /// Center the viewport on the row at a vertical position of the track.
    fn scroll_track_to(&mut self, position: Point<Pixels>, cx: &mut Context<Self>) {
        let Some((_, size_bytes, _)) = self.target(cx) else {
            return;
        };
        let bounds = self.track_bounds.get();
        if bounds.size.height <= px(0.0) {
            return;
        }
        let fraction = ((position.y - bounds.origin.y) / bounds.size.height).clamp(0.0, 1.0);
        let total_rows = self.total_rows(size_bytes);
        // A row index of a file below 2^53 bytes: exact in f64.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let row = (f64::from(fraction) * total_rows as f64) as u64;
        let half_page = self.visible_rows.get() as u64 / 2;
        self.top_row = self.clamp_top_row(row.saturating_sub(half_page), size_bytes);
        cx.notify();
    }

    /// Copy the selection as space-separated hex, up to [`MAX_COPY_BYTES`].
    fn copy_selection(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let Some(entry) = session.selected() else {
            return;
        };
        let (Some(analysis), Some((first, last))) = (&entry.analysis, self.selection(entry.cursor))
        else {
            return;
        };
        let length = (last - first + 1).min(MAX_COPY_BYTES);
        // Both fit usize: the file is resident.
        #[allow(clippy::cast_possible_truncation)]
        let bytes = &analysis.engine.data()[first as usize..(first + length) as usize];
        let text: Vec<String> = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
        cx.write_to_clipboard(ClipboardItem::new_string(text.join(" ")));
    }

    fn render_toolbar(&self, cx: &mut Context<Self>) -> Div {
        let choice = |label: String, is_active: bool| {
            small()
                .px(rems(0.5))
                .py(rems(0.125))
                .cursor_pointer()
                .map(|segment| {
                    if is_active {
                        segment.bg(theme::ACCENT_WASH).text_color(theme::ACCENT)
                    } else {
                        segment
                            .text_color(theme::TEXT_MUTED)
                            .hover(|style| style.bg(theme::SURFACE_HOVER))
                    }
                })
                .child(label)
        };
        let segments = || {
            div()
                .flex()
                .flex_none()
                .border_1()
                .border_color(theme::LINE_DEFAULT)
        };
        let label = |text: &'static str| small().text_color(theme::TEXT_MUTED).child(text);

        let columns = segments().children(COLUMN_CHOICES.into_iter().map(|columns| {
            choice(columns.to_string(), columns == self.columns)
                .id(("hex-columns", columns))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.columns = columns;
                    this.reveal_cursor(cx);
                }))
        }));
        let groups = segments().children(GROUP_CHOICES.into_iter().map(|group| {
            choice(group.to_string(), group == self.group)
                .id(("hex-group", group))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.group = group;
                    cx.notify();
                }))
        }));
        let bases = segments().children(
            [(OffsetBase::Hex, "hex"), (OffsetBase::Decimal, "dec")]
                .into_iter()
                .map(|(base, name)| {
                    choice(name.to_string(), base == self.offset_base)
                        .id(SharedString::from(format!("hex-offset-{name}")))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.offset_base = base;
                            cx.notify();
                        }))
                }),
        );
        let encodings = segments().children(TextEncoding::ALL.into_iter().map(|encoding| {
            choice(encoding.label().to_string(), encoding == self.encoding)
                .id(SharedString::from(format!(
                    "hex-encoding-{}",
                    encoding.id()
                )))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.encoding = encoding;
                    cx.notify();
                }))
        }));
        div()
            .flex()
            .flex_none()
            .flex_wrap()
            .items_center()
            .gap_x(rems(0.5))
            .gap_y(rems(0.375))
            .min_h(rems(2.25))
            .px(rems(0.75))
            .py(rems(0.375))
            .border_b_1()
            .border_color(theme::LINE_DEFAULT)
            .child(label("columns"))
            .child(columns)
            .child(label("group"))
            .child(groups)
            .child(label("offset"))
            .child(bases)
            .child(label("text"))
            .child(encodings)
            .child(label("goto"))
            .child(self.goto_field.clone())
            .when(self.is_goto_invalid, |toolbar| {
                toolbar.child(
                    small()
                        .text_color(theme::SIGNAL_ERROR)
                        .child("not an offset"),
                )
            })
    }

    /// The scroll track: the entropy profile top to bottom, the viewport
    /// as an outlined thumb and the cursor as a tick.
    fn render_track(
        &self,
        profile: Arc<[f32]>,
        size_bytes: u64,
        cursor: u64,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let track_bounds = self.track_bounds.clone();
        let total_rows = self.total_rows(size_bytes);
        let top_row = self.top_row;
        let visible_rows = self.visible_rows.get() as u64;
        let painted = canvas(
            move |bounds, _, _| track_bounds.set(bounds),
            move |bounds, (), window, _| {
                let height = f32::from(bounds.size.height);
                // A track is at most a few thousand pixels tall.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let lines = height.ceil().max(1.0) as usize;
                #[allow(clippy::cast_precision_loss)]
                let line_height = height / lines as f32;
                if !profile.is_empty() {
                    for line in 0..lines {
                        let bin = (line * profile.len() + profile.len() / 2) / lines;
                        let [r, g, b] = palette::entropy_color(profile[bin.min(profile.len() - 1)]);
                        let color = Rgba {
                            r: f32::from(r) / 255.0,
                            g: f32::from(g) / 255.0,
                            b: f32::from(b) / 255.0,
                            a: 1.0,
                        };
                        #[allow(clippy::cast_precision_loss)]
                        let top = bounds.origin.y + px(line as f32 * line_height);
                        let strip = Bounds::new(
                            point(bounds.origin.x, top),
                            size(bounds.size.width, px(line_height + 0.5)),
                        );
                        window.paint_quad(fill(strip, color));
                    }
                }
                // Fractions of the file; f32 is ample for pixel positions.
                #[allow(clippy::cast_precision_loss)]
                let fraction = |part: u64, whole: u64| part as f32 / whole.max(1) as f32;
                let rem = window.rem_size();
                let thumb_height = (bounds.size.height * fraction(visible_rows, total_rows))
                    .max(rem * MIN_THUMB_REMS)
                    .min(bounds.size.height);
                let thumb_top = (bounds.origin.y
                    + bounds.size.height * fraction(top_row, total_rows))
                .min(bounds.origin.y + bounds.size.height - thumb_height);
                let thumb = Bounds::new(
                    point(bounds.origin.x, thumb_top),
                    size(bounds.size.width, thumb_height),
                );
                window.paint_quad(outline(thumb, theme::TEXT_PRIMARY, BorderStyle::Solid));
                let tick = Bounds::new(
                    point(
                        bounds.origin.x,
                        bounds.origin.y + bounds.size.height * fraction(cursor, size_bytes),
                    ),
                    size(bounds.size.width, rem * TICK_REMS),
                );
                window.paint_quad(fill(tick, theme::ACCENT));
            },
        )
        .size_full();
        div()
            .id("hex-track")
            .flex_none()
            .w(rems(TRACK_REMS))
            .h_full()
            .border_l_1()
            .border_color(theme::LINE_DEFAULT)
            .cursor_ns_resize()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, event: &MouseDownEvent, _, cx| {
                    this.is_dragging_track = true;
                    this.scroll_track_to(event.position, cx);
                }),
            )
            .child(painted)
    }

    fn render_inspector(
        &self,
        engine: &Engine,
        cursor: u64,
        classified: Option<Endianness>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let classified_little = classified != Some(Endianness::Big);
        let is_little = self.is_little_endian.unwrap_or(classified_little);
        let is_overridden = self
            .is_little_endian
            .is_some_and(|chosen| classified.is_some() && chosen != classified_little);
        let order = |is_little: bool| if is_little { "little" } else { "big" };
        let note = format!(
            "{}-endian interpretation · {}{}",
            order(is_little),
            match classified {
                Some(Endianness::Big) => "classified big-endian",
                Some(Endianness::Little) => "classified little-endian",
                Some(Endianness::BiEndian) => "classified bi-endian",
                None => "unclassified",
            },
            if is_overridden { " · overridden" } else { "" }
        );
        let order_button = |name: &'static str, little: bool| {
            small()
                .id(name)
                .px(rems(0.5))
                .py(rems(0.125))
                .cursor_pointer()
                .map(|button| {
                    if little == is_little {
                        button.bg(theme::ACCENT_WASH).text_color(theme::ACCENT)
                    } else {
                        button
                            .text_color(theme::TEXT_MUTED)
                            .hover(|style| style.bg(theme::SURFACE_HOVER))
                    }
                })
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.is_little_endian = Some(little);
                    cx.notify();
                }))
                .child(name)
        };
        // The cursor is inside the resident file, so it fits usize.
        #[allow(clippy::cast_possible_truncation)]
        let window_bytes = engine.bytes(cursor as usize, inspector::WINDOW_BYTES);
        let rows = inspector::values(window_bytes, is_little)
            .into_iter()
            .map(|value| {
                div()
                    .flex()
                    .gap(rems(0.5))
                    .px(rems(0.75))
                    .py(rems(0.25))
                    .border_b_1()
                    .border_color(theme::LINE_HAIRLINE)
                    .child(
                        small()
                            .w(rems(3.25))
                            .flex_none()
                            .text_color(theme::TEXT_MUTED)
                            .child(value.kind),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_size(rems(0.75))
                            .child(value.text)
                            .when_some(value.detail, |cell, detail| {
                                cell.child(small().text_color(theme::TEXT_MUTED).child(detail))
                            }),
                    )
            });
        let header = bar()
            .child(small().child("[ DATA INSPECTOR ]"))
            .child(spacer())
            .child(
                div()
                    .flex()
                    .border_1()
                    .border_color(theme::LINE_DEFAULT)
                    .child(order_button("le", true))
                    .child(
                        order_button("be", false)
                            .border_l_1()
                            .border_color(theme::LINE_DEFAULT),
                    ),
            );
        div()
            .id("data-inspector")
            .flex()
            .flex_col()
            .flex_none()
            .w(rems(18.75))
            .h_full()
            .border_l_1()
            .border_color(theme::LINE_DEFAULT)
            .overflow_y_scroll()
            .child(header)
            .child(
                small()
                    .px(rems(0.75))
                    .py(rems(0.5))
                    .border_b_1()
                    .border_color(theme::LINE_DEFAULT)
                    .text_color(theme::TEXT_MUTED)
                    .child(note),
            )
            .children(rows)
    }
}

impl Render for HexView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let session = self.session.read(cx);
        let Some(entry) = session.selected() else {
            return div().into_any_element();
        };
        let Some(analysis) = &entry.analysis else {
            return div()
                .p(rems(1.5))
                .text_color(theme::TEXT_MUTED)
                .child(
                    entry
                        .error_message()
                        .unwrap_or("Bytes are shown once the file has been read.")
                        .to_string(),
                )
                .into_any_element();
        };
        let (size_bytes, cursor) = (entry.size, entry.cursor);
        let classified = entry.payload().map(|payload| payload.primary.endianness);
        let engine = analysis.engine.clone();
        let profile = analysis.profile.clone();
        let selection = self.selection(cursor);
        let total_rows = self.total_rows(size_bytes);
        self.top_row = self.clamp_top_row(self.top_row, size_bytes);

        let frame = GridFrame {
            engine: engine.clone(),
            layout: self.layout(),
            encoding: self.encoding,
            offset_base: self.offset_base,
            top_row: self.top_row,
            cursor,
            selection,
        };
        let grid_bounds = self.grid_bounds.clone();
        let visible_rows = self.visible_rows.clone();
        let reveal = std::mem::take(&mut self.reveal_after_measurement);
        let view = cx.entity();
        let grid = canvas(
            move |bounds, window, _| {
                grid_bounds.set(bounds);
                let rem = window.rem_size();
                let rows_height = bounds.size.height - rem * layout::HEAD_REMS;
                // A viewport holds at most a few hundred rows.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let rows = (rows_height / (rem * layout::ROW_REMS)).floor().max(1.0) as usize;
                if visible_rows.replace(rows) != rows {
                    // The scroll limits depend on the measured height.
                    window.on_next_frame(move |_, cx| {
                        view.update(cx, |view, cx| {
                            if reveal {
                                view.reveal_cursor(cx);
                            } else {
                                cx.notify();
                            }
                        });
                    });
                }
            },
            move |bounds, (), window, cx| frame.paint(bounds, window, cx),
        )
        .size_full();

        let location = if size_bytes == 0 {
            "empty file".to_string()
        } else {
            format!("cursor {} · {cursor}", format::offset(cursor))
        };
        let row_info = format!(
            "row {} of {} · {} × {} visible",
            format::grouped(cursor / self.columns as u64),
            format::grouped(total_rows),
            self.columns,
            self.visible_rows.get()
        );
        let footer = bar()
            .border_b_0()
            .border_t_1()
            .text_size(rems(theme::TEXT_SMALL_REMS))
            .child(location)
            .child(div().text_color(theme::TEXT_MUTED).child(row_info))
            .when_some(selection, |footer, (first, last)| {
                footer.child(
                    div()
                        .text_color(theme::ACCENT)
                        .child(format!("sel {} bytes", format::grouped(last - first + 1))),
                )
            })
            .when(selection.is_some(), |footer| {
                footer.child(
                    text_button("hex-copy", "copy hex")
                        .on_click(cx.listener(|this, _, _, cx| this.copy_selection(cx))),
                )
            })
            .child(spacer())
            .child(key_cap("shift"))
            .child(div().text_color(theme::TEXT_MUTED).child("select"))
            .child(key_cap("pgup/pgdn"))
            .child(div().text_color(theme::TEXT_MUTED).child("page"))
            .child(key_cap("g"))
            .child(div().text_color(theme::TEXT_MUTED).child("goto"));

        let content = div()
            .flex()
            .flex_1()
            .min_h(rems(6.25))
            .overflow_hidden()
            .bg(theme::SURFACE_INSET)
            .child(
                div()
                    .id("hex-grid")
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .overflow_hidden()
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
                    .on_scroll(cx.listener(Self::on_scroll))
                    .child(grid),
            )
            .child(self.render_track(profile, size_bytes, cursor, cx));

        div()
            .id("hex-view")
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .flex()
            .size_full()
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .on_action(cx.listener(Self::motion::<MoveLeft>(Motion::Bytes(-1), false)))
            .on_action(cx.listener(Self::motion::<MoveRight>(Motion::Bytes(1), false)))
            .on_action(cx.listener(Self::motion::<MoveUp>(Motion::Rows(-1), false)))
            .on_action(cx.listener(Self::motion::<MoveDown>(Motion::Rows(1), false)))
            .on_action(cx.listener(Self::motion::<MovePageUp>(Motion::Pages(-1), false)))
            .on_action(cx.listener(Self::motion::<MovePageDown>(Motion::Pages(1), false)))
            .on_action(cx.listener(Self::motion::<MoveRowStart>(Motion::RowStart, false)))
            .on_action(cx.listener(Self::motion::<MoveRowEnd>(Motion::RowEnd, false)))
            .on_action(cx.listener(Self::motion::<SelectLeft>(Motion::Bytes(-1), true)))
            .on_action(cx.listener(Self::motion::<SelectRight>(Motion::Bytes(1), true)))
            .on_action(cx.listener(Self::motion::<SelectUp>(Motion::Rows(-1), true)))
            .on_action(cx.listener(Self::motion::<SelectDown>(Motion::Rows(1), true)))
            .on_action(cx.listener(Self::motion::<SelectPageUp>(Motion::Pages(-1), true)))
            .on_action(cx.listener(Self::motion::<SelectPageDown>(Motion::Pages(1), true)))
            .on_action(cx.listener(Self::motion::<SelectRowStart>(Motion::RowStart, true)))
            .on_action(cx.listener(Self::motion::<SelectRowEnd>(Motion::RowEnd, true)))
            .on_action(cx.listener(|this, _: &ClearSelection, _, cx| {
                this.anchor = None;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &CopySelection, _, cx| this.copy_selection(cx)))
            .on_action(cx.listener(|this, _: &FocusGoto, window, cx| {
                let focus = this.goto_field.focus_handle(cx);
                window.focus(&focus, cx);
            }))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .child(self.render_toolbar(cx))
                    .child(content)
                    .child(footer),
            )
            .child(self.render_inspector(&engine, cursor, classified, cx))
            .into_any_element()
    }
}
