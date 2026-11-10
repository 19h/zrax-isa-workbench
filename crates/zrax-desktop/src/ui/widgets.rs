//! Small building blocks every view shares: bars, bracketed panels,
//! key/value rows, tables, badges, icon buttons.
//!
//! Dimensions are the browser stylesheet's (`web/workbench.css`), in `rem`.

use gpui::{
    div, prelude::*, relative, rems, svg, AnyElement, App, Div, Rgba, SharedString, Stateful,
    Window,
};

use crate::theme;

/// Text at the small size (labels, hints, table headers).
pub fn small() -> Div {
    div().text_size(rems(theme::TEXT_SMALL_REMS))
}

/// A horizontal bar with a bottom border: headers and footers.
pub fn bar() -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .gap(rems(0.625))
        .min_h(rems(2.25))
        .px(rems(0.75))
        .border_b_1()
        .border_color(theme::LINE_DEFAULT)
        .whitespace_nowrap()
        .overflow_hidden()
}

/// An element that takes the remaining space of a row.
pub fn spacer() -> Div {
    div().flex_1()
}

/// A key cap: `j/k`, `o`, `1–6`.
pub fn key_cap(keys: impl Into<SharedString>) -> Div {
    small()
        .px(rems(0.125))
        .border_1()
        .border_color(theme::LINE_HAIRLINE)
        .whitespace_nowrap()
        .child(keys.into())
}

/// An outlined uppercase state label in `color`.
pub fn badge(text: &str, color: Rgba) -> Div {
    small()
        .flex_none()
        .px(rems(0.25))
        .border_1()
        .border_color(color)
        .text_color(color)
        .line_height(rems(1.125))
        .child(text.to_uppercase())
}

/// A small outlined tag: an extension name, a certificate property.
pub fn tag(text: impl Into<SharedString>) -> Div {
    small()
        .px(rems(0.3125))
        .border_1()
        .border_color(theme::LINE_DEFAULT)
        .child(text.into())
}

/// The floating label of an icon-only control.
struct Tooltip(SharedString);

impl Render for Tooltip {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        small()
            .px(rems(0.375))
            .py(rems(0.125))
            .bg(theme::SURFACE_PANEL)
            .border_1()
            .border_color(theme::LINE_DEFAULT)
            .text_color(theme::TEXT_PRIMARY)
            .font_family(theme::FONT_MONO)
            .child(self.0.clone())
    }
}

/// A tooltip builder showing `label`, for `.tooltip(..)` of an icon-only
/// control.
pub fn text_tooltip(label: &'static str) -> impl Fn(&mut Window, &mut App) -> gpui::AnyView {
    move |_window, cx| cx.new(|_| Tooltip(label.into())).into()
}

/// Size of an icon button.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IconSize {
    /// Rail buttons: 2 rem.
    Regular,
    /// Buttons inside a bar: 1.5 rem.
    Small,
}

/// A square button showing only an icon. `label` names it in a tooltip;
/// `active` paints it in the accent color.
pub fn icon_button(
    id: &'static str,
    icon: &'static str,
    label: &'static str,
    size: IconSize,
    active: bool,
) -> Stateful<Div> {
    let (button_rems, glyph_rems) = match size {
        IconSize::Regular => (2.0, 1.25),
        IconSize::Small => (1.5, 1.0),
    };
    let color = if active {
        theme::TEXT_INVERSE
    } else {
        theme::TEXT_SECONDARY
    };
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .size(rems(button_rems))
        .cursor_pointer()
        .when(active, |button| button.bg(theme::ACCENT))
        .when(!active, |button| {
            button.hover(|style| style.bg(theme::SURFACE_HOVER))
        })
        .child(svg().path(icon).size(rems(glyph_rems)).text_color(color))
        .tooltip(text_tooltip(label))
}

/// A text button: `clear`, `browse`, `open …`.
pub fn text_button(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
) -> Stateful<Div> {
    div()
        .id(id)
        .flex_none()
        .px(rems(0.5))
        .py(rems(0.125))
        .cursor_pointer()
        .hover(|style| style.bg(theme::SURFACE_HOVER))
        .child(label.into())
}

/// A bordered panel with a bracketed uppercase title, as `[ METADATA ]`,
/// and an optional note at the right of its header (a count, a measure).
pub fn section(title: &str, trailing: Option<SharedString>, body: impl IntoElement) -> Div {
    let header = small()
        .flex()
        .justify_between()
        .gap(rems(0.75))
        .px(rems(0.75))
        .py(rems(0.5))
        .border_b_1()
        .border_color(theme::LINE_HAIRLINE)
        .child(format!("[ {} ]", title.to_uppercase()))
        .when_some(trailing, |header, trailing| {
            header.child(div().text_color(theme::TEXT_MUTED).child(trailing))
        });
    div()
        .flex()
        .flex_col()
        .border_1()
        .border_color(theme::LINE_DEFAULT)
        .bg(theme::SURFACE_PAGE)
        .child(header)
        .child(body)
}

/// The padded body of a [`section`] that holds rows.
pub fn section_body() -> Div {
    div()
        .flex()
        .flex_col()
        .px(rems(1.0))
        .pt(rems(0.5))
        .pb(rems(0.75))
}

/// A `key  value` row with a hairline below.
pub fn key_value_row(key: impl Into<SharedString>, value: impl IntoElement) -> Div {
    div()
        .flex()
        .gap(rems(0.75))
        .py(rems(0.3125))
        .border_b_1()
        .border_color(theme::LINE_HAIRLINE)
        .child(
            div()
                .w(rems(7.5))
                .flex_none()
                .text_color(theme::TEXT_MUTED)
                .child(key.into()),
        )
        .child(div().flex_1().min_w_0().child(value))
}

/// A table column: its header and its share of the table's width.
#[derive(Clone, Copy)]
pub struct Column {
    /// Header text.
    pub title: &'static str,
    /// Width relative to the other columns.
    pub weight: f32,
}

/// Narrowest width of a column of weight 1.0, in `rem`.
const MIN_COLUMN_REMS_PER_WEIGHT: f32 = 5.0;

/// A [`section`] holding a table. Every row has one cell per column.
pub fn table_section(title: &str, columns: &[Column], rows: Vec<Vec<AnyElement>>) -> Div {
    let total_weight: f32 = columns.iter().map(|column| column.weight).sum();
    let cell = |column: &Column| {
        div()
            .w(relative(column.weight / total_weight))
            .min_w_0()
            .px(rems(0.75))
            .overflow_hidden()
    };
    let header = small()
        .flex()
        .py(rems(0.375))
        .bg(theme::SURFACE_PANEL)
        .border_b_1()
        .border_color(theme::LINE_HAIRLINE)
        .text_color(theme::TEXT_MUTED)
        .children(
            columns
                .iter()
                .map(|column| cell(column).whitespace_nowrap().child(column.title)),
        );
    let count = rows.len();
    let body = rows.into_iter().enumerate().map(|(index, cells)| {
        div()
            .flex()
            .items_center()
            .py(rems(0.375))
            .when(index + 1 < count, |row| {
                row.border_b_1().border_color(theme::LINE_HAIRLINE)
            })
            .children(
                columns
                    .iter()
                    .zip(cells)
                    .map(|(column, content)| cell(column).child(content)),
            )
    });
    // Columns keep a readable width; a narrow window scrolls the table
    // sideways instead of cutting every cell short.
    let grid = div()
        .flex()
        .flex_col()
        .min_w(rems(total_weight * MIN_COLUMN_REMS_PER_WEIGHT))
        .child(header)
        .children(body);
    section(
        title,
        Some(count.to_string().into()),
        div()
            .id(SharedString::from(format!("table-{title}")))
            .overflow_x_scroll()
            .child(grid),
    )
}

/// A horizontal meter: `fraction` (0.0..=1.0) of the track in the accent
/// color.
pub fn meter(fraction: f32) -> Div {
    div()
        .h(rems(0.5))
        .bg(theme::SURFACE_INSET)
        .border_1()
        .border_color(theme::LINE_HAIRLINE)
        .child(
            div()
                .h_full()
                .w(relative(fraction.clamp(0.0, 1.0)))
                .bg(theme::ACCENT),
        )
}
