//! The status bar: mode, selected file, cursor, counts and engine.

use gpui::{div, prelude::*, rems, Context, Div, SharedString};

use super::widgets::spacer;
use super::Workbench;
use crate::{format, theme};

/// A status-bar cell with a hairline to its right.
fn cell(text: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .h_full()
        .px(rems(0.5))
        .border_r_1()
        .border_color(theme::LINE_DEFAULT)
        .child(text.into())
}

impl Workbench {
    pub(super) fn render_status_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let session = self.session.read(cx);
        let counts = session.counts();
        let selected = session.selected();
        let mode = div()
            .flex()
            .flex_none()
            .items_center()
            .h_full()
            .px(rems(0.5))
            .bg(theme::ACCENT)
            .text_color(theme::TEXT_INVERSE)
            .child(self.tab.mode());
        div()
            .flex()
            .flex_none()
            .items_center()
            .h(rems(1.375))
            .border_t_1()
            .border_color(theme::LINE_DEFAULT)
            .bg(theme::SURFACE_INSET)
            .text_size(rems(theme::TEXT_SMALL_REMS))
            .whitespace_nowrap()
            .overflow_hidden()
            .child(mode)
            .map(|status_bar| match selected {
                Some(entry) => status_bar
                    .child(cell(entry.name.clone()))
                    .child(cell(entry.summary()))
                    .child(cell(format!("cursor {}", format::offset(entry.cursor)))),
                None => status_bar.child(cell("no file")),
            })
            .child(spacer())
            .child(
                cell(format!(
                    "{} files · {} done · {} failed",
                    counts.files, counts.done, counts.failed
                ))
                .border_l_1(),
            )
            .child(
                cell(format!("zrax {} · Apeiron/native", zrax::version()))
                    .border_r_0()
                    .text_color(theme::TEXT_MUTED),
            )
    }
}
