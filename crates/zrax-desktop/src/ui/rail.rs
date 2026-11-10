//! The icon rail at the window's left edge.

use gpui::{div, prelude::*, rems, Context};

use super::widgets::{icon_button, spacer, IconSize};
use super::{AddFiles, ToggleFilesPanel, ToggleLog, Workbench};
use crate::assets::icon;
use crate::theme;

impl Workbench {
    pub(super) fn render_rail(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let has_selection = self.session.read(cx).selected().is_some();
        div()
            .flex()
            .flex_col()
            .flex_none()
            .items_center()
            .gap(rems(0.25))
            .w(rems(2.75))
            .py(rems(0.5))
            .bg(theme::SURFACE_INSET)
            .border_r_1()
            .border_color(theme::LINE_DEFAULT)
            .child(icon_button(
                "rail-workbench",
                icon::WORKBENCH,
                "File workbench",
                IconSize::Regular,
                has_selection && !self.is_donations_open,
            ))
            .child(
                icon_button(
                    "rail-files",
                    icon::FILES,
                    "Files panel (f)",
                    IconSize::Regular,
                    self.is_files_panel_open,
                )
                .on_click(|_, window, cx| window.dispatch_action(Box::new(ToggleFilesPanel), cx)),
            )
            .child(spacer())
            .child(
                icon_button(
                    "rail-donate",
                    icon::DONATE,
                    "Donate firmware",
                    IconSize::Regular,
                    self.is_donations_open,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.is_donations_open = !this.is_donations_open;
                    cx.notify();
                })),
            )
            .child(
                icon_button(
                    "rail-add",
                    icon::ADD,
                    "Add files (o)",
                    IconSize::Regular,
                    false,
                )
                .on_click(|_, window, cx| window.dispatch_action(Box::new(AddFiles), cx)),
            )
            .child(
                icon_button(
                    "rail-log",
                    icon::LOG,
                    "Log (`)",
                    IconSize::Regular,
                    self.is_log_open,
                )
                .on_click(|_, window, cx| window.dispatch_action(Box::new(ToggleLog), cx)),
            )
    }
}
