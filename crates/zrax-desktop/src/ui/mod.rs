//! The workbench window: an icon rail, the files panel, the main area and
//! a status bar, as in the browser workbench (`web/index.html`).

mod classification;
mod donate_panel;
mod empty;
mod entropy_view;
mod file_view;
mod files_panel;
mod hex_view;
mod json_view;
mod rail;
mod status_bar;
mod strip;
mod text_field;
pub mod widgets;

use std::path::PathBuf;

use gpui::{
    actions, div, prelude::*, relative, rems, App, Context, Entity, ExternalPaths, FocusHandle,
    Focusable, KeyBinding, PathPromptOptions, ScrollHandle, Subscription, UniformListScrollHandle,
    Window,
};

use crate::donate::Donations;
use crate::model::session::{LogTone, Session, SessionEvent};
use crate::{paths, theme};
use text_field::{TextField, TextFieldEvent};

/// Key context of the workbench root.
const KEY_CONTEXT: &str = "Workbench";

/// Where the single-letter shortcuts apply: anywhere in the workbench
/// except while a text field has focus.
const SHORTCUT_CONTEXT: &str = "Workbench && !TextField";

/// Longest donor name the server keeps, in characters.
const DONOR_NAME_CHARS: usize = 32;

actions!(
    workbench,
    [
        /// Choose files or folders to analyze.
        AddFiles,
        /// Show or hide the files panel.
        ToggleFilesPanel,
        /// Show or hide the analysis log.
        ToggleLog,
        /// Collapse the file header to one line, or expand it again.
        ToggleHeader,
        /// Select the next file in the list.
        NextFile,
        /// Select the previous file in the list.
        PreviousFile,
        /// Remove the selected file and its members.
        RemoveFile,
        /// Remove every file.
        ClearFiles,
        /// Show the classification tab.
        ShowClassification,
        /// Show the entropy tab.
        ShowEntropy,
        /// Show the hex tab.
        ShowHex,
        /// Show the JSON tab.
        ShowJson,
        /// Show the strings tab.
        ShowStrings,
        /// Show the certificates tab.
        ShowCertificates,
        /// Quit the application.
        Quit,
    ]
);

/// The tabs of the file view, in display and shortcut order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Format, ISA, members, extensions, candidates and notes.
    Classification,
    /// The entropy map and its inspector.
    Entropy,
    /// The hex grid and the data inspector.
    Hex,
    /// The detection payload as JSON.
    Json,
    /// Printable strings.
    Strings,
    /// X.509 certificates.
    Certificates,
}

impl Tab {
    /// Every tab, in order.
    pub const ALL: [Tab; 6] = [
        Tab::Classification,
        Tab::Entropy,
        Tab::Hex,
        Tab::Json,
        Tab::Strings,
        Tab::Certificates,
    ];

    /// The tab's label.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Classification => "classification",
            Tab::Entropy => "entropy",
            Tab::Hex => "hex",
            Tab::Json => "json",
            Tab::Strings => "strings",
            Tab::Certificates => "certificates",
        }
    }

    /// The mode word at the left of the status bar.
    pub fn mode(self) -> &'static str {
        match self {
            Tab::Classification => "CLASSIFY",
            Tab::Entropy => "ENTROPY",
            Tab::Hex => "HEX",
            Tab::Json => "JSON",
            Tab::Strings => "STRINGS",
            Tab::Certificates => "CERTS",
        }
    }
}

/// The platform's chords for opening files and quitting: Command on macOS,
/// Control elsewhere. `KeyBinding::new` takes literal keystrokes and does
/// not resolve gpui's `secondary-` modifier.
#[cfg(target_os = "macos")]
const OPEN_CHORD: &str = "cmd-o";
#[cfg(target_os = "macos")]
const QUIT_CHORD: &str = "cmd-q";
#[cfg(not(target_os = "macos"))]
const OPEN_CHORD: &str = "ctrl-o";
#[cfg(not(target_os = "macos"))]
const QUIT_CHORD: &str = "ctrl-q";

/// Bind the workbench's keyboard shortcuts (`web/workbench.js`, global
/// key handler), plus the platform's open and quit chords.
pub fn bind_keys(cx: &mut App) {
    let context = Some(SHORTCUT_CONTEXT);
    hex_view::bind_keys(cx);
    cx.bind_keys([
        KeyBinding::new("o", AddFiles, context),
        KeyBinding::new(OPEN_CHORD, AddFiles, context),
        KeyBinding::new("f", ToggleFilesPanel, context),
        KeyBinding::new("`", ToggleLog, context),
        KeyBinding::new("j", NextFile, context),
        KeyBinding::new("k", PreviousFile, context),
        KeyBinding::new("delete", RemoveFile, context),
        KeyBinding::new("1", ShowClassification, context),
        KeyBinding::new("2", ShowEntropy, context),
        KeyBinding::new("3", ShowHex, context),
        KeyBinding::new("4", ShowJson, context),
        KeyBinding::new("5", ShowStrings, context),
        KeyBinding::new("6", ShowCertificates, context),
        KeyBinding::new(QUIT_CHORD, Quit, None),
    ]);
}

/// The root view of a workbench window.
// The flags are independent panel toggles, not states of one machine.
#[allow(clippy::struct_excessive_bools)]
pub struct Workbench {
    session: Entity<Session>,
    focus: FocusHandle,
    tab: Tab,
    is_files_panel_open: bool,
    is_log_open: bool,
    /// Whether the classification band is reduced to one line. The same on
    /// every tab; only the user changes it.
    is_header_collapsed: bool,
    log_scroll: ScrollHandle,
    donations: Entity<Donations>,
    donor_field: Entity<TextField>,
    is_donations_open: bool,
    entropy_view: Entity<entropy_view::EntropyView>,
    hex_view: Entity<hex_view::HexView>,
    /// The JSON tab's text for the entry it was last shown for.
    json: Option<json_view::JsonText>,
    /// Set when the tab changed: its view takes focus on the next render.
    should_focus_tab: bool,
    file_list_scroll: UniformListScrollHandle,
    classification_scroll: ScrollHandle,
    _subscriptions: Vec<Subscription>,
}

impl Workbench {
    /// A workbench over `session`.
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        let donations = cx.new(|_| Donations::new());
        let donor_field = cx.new(|cx| {
            let accepts = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '@');
            TextField::new("", "anonymous", DONOR_NAME_CHARS, accepts, cx)
        });
        let subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe(&session, Self::on_session_event),
            cx.observe(&donations, |_, _, cx| cx.notify()),
            cx.subscribe(&donor_field, |this, field, event: &TextFieldEvent, cx| {
                if *event == TextFieldEvent::Changed {
                    let name = field.read(cx).text().to_string();
                    this.donations
                        .update(cx, |donations, cx| donations.set_donor(&name, cx));
                }
            }),
        ];
        let entropy_view = cx.new(|cx| entropy_view::EntropyView::new(session.clone(), cx));
        let hex_view = cx.new(|cx| hex_view::HexView::new(session.clone(), cx));
        Self {
            session,
            focus,
            donations,
            donor_field,
            is_donations_open: false,
            entropy_view,
            hex_view,
            json: None,
            should_focus_tab: false,
            tab: Tab::Classification,
            is_files_panel_open: true,
            is_log_open: false,
            is_header_collapsed: false,
            log_scroll: ScrollHandle::new(),
            file_list_scroll: UniformListScrollHandle::new(),
            classification_scroll: ScrollHandle::new(),
            _subscriptions: subscriptions,
        }
    }

    fn on_session_event(
        &mut self,
        _session: Entity<Session>,
        event: &SessionEvent,
        cx: &mut Context<Self>,
    ) {
        if let SessionEvent::Analyzed(_) = event {
            // Learn what the server takes, so analyzed files can be offered.
            self.donations.update(cx, Donations::connect);
        }
        if *event == SessionEvent::SelectionChanged {
            let session = self.session.read(cx);
            let selected_row = session
                .selected_id()
                .and_then(|id| session.entries().iter().position(|entry| entry.id == id));
            if let Some(row) = selected_row {
                self.file_list_scroll
                    .scroll_to_item(row, gpui::ScrollStrategy::Center);
            }
        }
    }

    /// Show the entropy tab's map in the mode named `mode` at `zoom`.
    #[cfg(feature = "screenshots")]
    pub fn show_map(&mut self, mode: &str, zoom: f64, cx: &mut Context<Self>) {
        use crate::entropy::scene::MapMode;
        if let Some(mode) = MapMode::ALL.into_iter().find(|m| m.short_name() == mode) {
            self.entropy_view
                .update(cx, |view, cx| view.show(mode, zoom, cx));
        }
    }

    /// Do what a click on the selected file's **donate** button does, once
    /// the offer is there. Returns how the selected file's donation ended,
    /// or `None` while it has not.
    #[cfg(feature = "screenshots")]
    pub fn donate_selected(&mut self, cx: &mut Context<Self>) -> Option<String> {
        let (entry_id, request) = {
            let session = self.session.read(cx);
            let entry = session.selected()?;
            let donations = self.donations.read(cx);
            if let Some(donation) = donations.donation(entry.id) {
                return donation.outcome.as_ref().map(|_| donation.status_text());
            }
            (entry.id, donations.request_for(entry))
        };
        let _ = entry_id;
        if let Some(request) = request {
            self.donations
                .update(cx, |donations, cx| donations.donate(request, cx));
        }
        None
    }

    /// Collapse the file header, as its toggle does.
    #[cfg(feature = "screenshots")]
    pub fn collapse_header(&mut self, cx: &mut Context<Self>) {
        self.is_header_collapsed = true;
        cx.notify();
    }

    /// Show the donations panel in place of the file view.
    #[cfg(feature = "screenshots")]
    pub fn show_donations(&mut self, cx: &mut Context<Self>) {
        self.is_donations_open = true;
        cx.notify();
    }

    /// Switch the file view to `tab`.
    pub fn show_tab(&mut self, tab: Tab, cx: &mut Context<Self>) {
        self.tab = tab;
        self.should_focus_tab = true;
        cx.notify();
    }

    /// Ask for files or folders and queue what the user picks.
    fn prompt_for_files(cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: true,
            multiple: true,
            prompt: None,
        });
        cx.spawn(async move |workbench, cx| {
            // A cancelled dialog and a closed window both mean: nothing to add.
            if let Ok(Ok(Some(picked))) = picked.await {
                let _ = workbench.update(cx, |workbench, cx| workbench.open_paths(picked, cx));
            }
        })
        .detach();
    }

    /// Queue dropped or picked paths. Folders are walked off the main
    /// thread; symbolic links inside them are not followed.
    fn open_paths(&mut self, picked: Vec<PathBuf>, cx: &mut Context<Self>) {
        let session = self.session.downgrade();
        cx.spawn(async move |_, cx| {
            let expanded = cx
                .background_executor()
                .spawn(async move { paths::expand(&picked) })
                .await;
            let _ = session.update(cx, |session, cx| {
                if expanded.is_truncated {
                    session.log_line(
                        LogTone::Error,
                        format!(
                            "more than {} files; the rest were not added",
                            paths::MAX_FILES_PER_ADD
                        ),
                    );
                }
                session.add_files(expanded.files, cx);
            });
        })
        .detach();
    }

    /// The analysis log: what was added, analyzed and failed, newest last.
    fn render_log(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let lines: Vec<_> = self
            .session
            .read(cx)
            .log()
            .map(|line| {
                let color = match line.tone {
                    LogTone::Command => theme::ACCENT,
                    LogTone::Info => theme::TEXT_SECONDARY,
                    LogTone::Done => theme::SIGNAL_OK,
                    LogTone::Error => theme::SIGNAL_ERROR,
                };
                div()
                    .text_color(color)
                    .whitespace_nowrap()
                    .child(line.text.clone())
            })
            .collect();
        self.log_scroll.scroll_to_bottom();
        div()
            .id("analysis-log")
            .flex_none()
            .h(rems(10.0))
            .overflow_y_scroll()
            .track_scroll(&self.log_scroll)
            .px(rems(0.75))
            .py(rems(0.5))
            .bg(theme::SURFACE_INSET)
            .border_t_1()
            .border_color(theme::LINE_DEFAULT)
            .text_size(rems(theme::TEXT_SMALL_REMS))
            .children(lines)
    }

    fn render_main(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let has_selection = self.session.read(cx).selected().is_some();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .map(|main| {
                if self.is_donations_open {
                    main.child(self.render_donations(cx))
                } else if has_selection {
                    main.child(self.render_file_view(cx))
                } else {
                    main.child(empty::empty_view())
                }
            })
            .when(self.is_log_open, |main| main.child(self.render_log(cx)))
    }
}

impl Render for Workbench {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if std::mem::take(&mut self.should_focus_tab) {
            // Tabs without keyboard handling of their own leave focus on
            // the workbench, so its shortcuts keep working.
            let target = match self.tab {
                Tab::Entropy => self.entropy_view.focus_handle(cx),
                Tab::Hex => self.hex_view.focus_handle(cx),
                _ => self.focus.clone(),
            };
            window.focus(&target, cx);
        }
        let session = self.session.clone();
        div()
            .id("workbench")
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .flex_col()
            .bg(theme::SURFACE_PAGE)
            .text_color(theme::TEXT_PRIMARY)
            .font_family(theme::FONT_MONO)
            .text_size(rems(theme::TEXT_BODY_REMS))
            .line_height(relative(theme::LINE_HEIGHT))
            .on_action(cx.listener(|_, _: &AddFiles, _, cx| Self::prompt_for_files(cx)))
            .on_action(cx.listener(|this, _: &ToggleFilesPanel, _, cx| {
                this.is_files_panel_open = !this.is_files_panel_open;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleHeader, _, cx| {
                this.is_header_collapsed = !this.is_header_collapsed;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleLog, _, cx| {
                this.is_log_open = !this.is_log_open;
                cx.notify();
            }))
            .on_action({
                let session = session.clone();
                move |_: &NextFile, _, cx| session.update(cx, |s, cx| s.select_relative(1, cx))
            })
            .on_action({
                let session = session.clone();
                move |_: &PreviousFile, _, cx| session.update(cx, |s, cx| s.select_relative(-1, cx))
            })
            .on_action({
                let session = session.clone();
                move |_: &RemoveFile, _, cx| {
                    session.update(cx, |session, cx| {
                        if let Some(id) = session.selected_id() {
                            session.remove(id, cx);
                        }
                    });
                }
            })
            .on_action({
                let session = session.clone();
                move |_: &ClearFiles, _, cx| session.update(cx, Session::clear)
            })
            .on_action(cx.listener(|this, _: &ShowClassification, _, cx| {
                this.show_tab(Tab::Classification, cx);
            }))
            .on_action(cx.listener(|this, _: &ShowEntropy, _, cx| this.show_tab(Tab::Entropy, cx)))
            .on_action(cx.listener(|this, _: &ShowHex, _, cx| this.show_tab(Tab::Hex, cx)))
            .on_action(cx.listener(|this, _: &ShowJson, _, cx| this.show_tab(Tab::Json, cx)))
            .on_action(cx.listener(|this, _: &ShowStrings, _, cx| this.show_tab(Tab::Strings, cx)))
            .on_action(cx.listener(|this, _: &ShowCertificates, _, cx| {
                this.show_tab(Tab::Certificates, cx);
            }))
            .on_drop(cx.listener(|this, dropped: &ExternalPaths, _, cx| {
                this.open_paths(dropped.paths().to_vec(), cx);
            }))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(self.render_rail(cx))
                    .when(self.is_files_panel_open, |workspace| {
                        workspace.child(self.render_files_panel(cx))
                    })
                    .child(self.render_main(cx)),
            )
            .child(self.render_status_bar(cx))
    }
}
