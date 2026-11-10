//! The files panel: brand, drop target, counts and the list of entries.

use gpui::{div, prelude::*, rems, uniform_list, Context, Div, SharedString, Stateful};

use super::widgets::{bar, key_cap, small, spacer, text_button};
use super::{AddFiles, ClearFiles, Workbench};
use crate::model::entry::{Entry, Status};
use crate::model::session::Session;
use crate::{format, theme};

/// Indent per nesting level of an extracted member, in `rem`.
const DEPTH_INDENT_REMS: f32 = 0.75;

fn status_color(status: Status) -> gpui::Rgba {
    match status {
        Status::Queued => theme::TEXT_DISABLED,
        Status::Analyzing => theme::ACCENT,
        Status::Done => theme::SIGNAL_OK,
        Status::Failed => theme::SIGNAL_ERROR,
    }
}

/// One row of the list: status glyph, name over summary, size.
fn file_row(entry: &Entry, is_selected: bool) -> Stateful<Div> {
    // Depth is at most MAX_SUBFILE_DEPTH, exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let indent = 0.625 + DEPTH_INDENT_REMS * entry.depth as f32;
    let name_color = if is_selected {
        theme::TEXT_PRIMARY
    } else {
        theme::TEXT_SECONDARY
    };
    div()
        .id(("file", entry.id.0))
        .flex()
        .gap(rems(0.5))
        .w_full()
        .pl(rems(indent))
        .pr(rems(0.75))
        .py(rems(0.375))
        .border_l_2()
        .border_b_1()
        .border_color(theme::LINE_HAIRLINE)
        .line_height(rems(1.25))
        .cursor_pointer()
        .map(|row| {
            if is_selected {
                row.bg(theme::SURFACE_SELECTED).border_color(theme::ACCENT)
            } else {
                row.hover(|style| style.bg(theme::SURFACE_HOVER))
            }
        })
        .child(
            small()
                .w(rems(1.5))
                .flex_none()
                .line_height(rems(1.25))
                .text_color(status_color(entry.status))
                .child(entry.status.glyph()),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(
                    div()
                        .truncate()
                        .text_color(name_color)
                        .child(entry.name.clone()),
                )
                .child(
                    small()
                        .truncate()
                        .line_height(rems(1.0))
                        .text_color(theme::TEXT_MUTED)
                        .child(entry.summary()),
                ),
        )
        .child(
            small()
                .flex_none()
                .line_height(rems(1.25))
                .text_color(theme::TEXT_MUTED)
                .child(format::size(entry.size)),
        )
}

impl Workbench {
    pub(super) fn render_files_panel(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let session = self.session.read(cx);
        let counts = session.counts();
        let entry_count = session.entries().len();
        let heading_counts: SharedString =
            format!("{} done · {} failed", counts.done, counts.failed).into();

        let brand = bar()
            .child(
                div()
                    .font_family(theme::FONT_DISPLAY)
                    .font_weight(gpui::FontWeight::MEDIUM)
                    .child("zrax"),
            )
            .child(small().text_color(theme::TEXT_MUTED).child(zrax::version()));

        let drop_target = div()
            .id("dropzone")
            .flex()
            .flex_col()
            .gap(rems(0.125))
            .m(rems(0.75))
            .px(rems(0.75))
            .py(rems(0.625))
            .border_1()
            .border_dashed()
            .border_color(theme::LINE_DEFAULT)
            .text_color(theme::TEXT_SECONDARY)
            .cursor_pointer()
            .hover(|style| style.bg(theme::SURFACE_HOVER))
            .on_click(|_, window, cx| window.dispatch_action(Box::new(AddFiles), cx))
            .child(
                div()
                    .flex()
                    .gap(rems(0.4))
                    .child("drop files or")
                    .child(div().text_color(theme::ACCENT).child("browse")),
            )
            .child(
                small()
                    .text_color(theme::TEXT_MUTED)
                    .child("runs locally · nothing is uploaded unless you donate"),
            );

        let heading = small()
            .flex()
            .justify_between()
            .gap(rems(0.5))
            .px(rems(0.75))
            .pb(rems(0.5))
            .text_color(theme::TEXT_SECONDARY)
            .child(format!("[ FILES ] {}", counts.files))
            .child(div().text_color(theme::TEXT_MUTED).child(heading_counts));

        let list = uniform_list(
            "file-list",
            entry_count,
            cx.processor(|this, range: std::ops::Range<usize>, _window, cx| {
                let session_entity = this.session.clone();
                let session: &Session = this.session.read(cx);
                let selected = session.selected_id();
                session.entries()[range]
                    .iter()
                    .map(|entry| {
                        let id = entry.id;
                        let session_entity = session_entity.clone();
                        file_row(entry, selected == Some(id)).on_click(move |_, _, cx| {
                            session_entity.update(cx, |session, cx| session.select(id, cx));
                        })
                    })
                    .collect()
            }),
        )
        .track_scroll(&self.file_list_scroll)
        .flex_1()
        .min_h_0()
        .border_t_1()
        .border_color(theme::LINE_HAIRLINE);

        let footer = bar()
            .border_b_0()
            .border_t_1()
            .child(key_cap("j/k"))
            .child(div().text_color(theme::TEXT_MUTED).child("select"))
            .child(spacer())
            .child(
                text_button("clear-files", "clear")
                    .text_size(rems(theme::TEXT_SMALL_REMS))
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(ClearFiles), cx)),
            );

        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(rems(16.5))
            .min_h_0()
            .bg(theme::SURFACE_PAGE)
            .border_r_1()
            .border_color(theme::LINE_DEFAULT)
            .child(brand)
            .child(drop_target)
            .child(heading)
            .child(list)
            .child(footer)
    }
}
