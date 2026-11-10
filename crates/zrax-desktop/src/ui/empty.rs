//! The main area while no file is selected.

use gpui::{div, prelude::*, rems};

use super::widgets::{key_cap, small};
use super::AddFiles;
use crate::theme;

/// The drop target and hints shown before any file is added.
pub(super) fn empty_view() -> impl IntoElement {
    let prompt = div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap(rems(0.4))
        .text_color(theme::TEXT_SECONDARY)
        .child("one file opens in the workbench; several fill the file list. press")
        .child(key_cap("o"))
        .child("to browse.");
    let drop_target = div()
        .id("empty-drop")
        .flex()
        .flex_col()
        .gap(rems(0.5))
        .px(rems(1.5))
        .py(rems(2.0))
        .border_1()
        .border_dashed()
        .border_color(theme::LINE_DEFAULT)
        .cursor_pointer()
        .hover(|style| style.bg(theme::SURFACE_HOVER))
        .on_click(|_, window, cx| window.dispatch_action(Box::new(AddFiles), cx))
        .child(
            div()
                .font_family(theme::FONT_DISPLAY)
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_size(rems(1.0))
                .line_height(gpui::relative(1.3))
                .child("drop binaries anywhere"),
        )
        .child(prompt)
        .child(small().text_color(theme::TEXT_MUTED).child(
            "classification and entropy run locally · nothing is uploaded unless you donate",
        ));
    div()
        .flex()
        .flex_col()
        .gap(rems(1.0))
        .p(rems(1.5))
        .max_w(rems(47.5))
        .child(
            small()
                .font_weight(gpui::FontWeight::MEDIUM)
                .child("[ NO FILES ]"),
        )
        .child(drop_target)
        .child(
            div()
                .text_color(theme::TEXT_MUTED)
                .child("engine ready · ELF, PE, Mach-O, firmware, or any binary blob"),
        )
}
