//! The native zrax workbench.
//!
//! One window over a [`model::session::Session`]: files are classified and
//! profiled on background threads and inspected in the same views as the
//! browser workbench (`web/`). See `docs/desktop.md`.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]

mod analysis;
mod assets;
mod donate;
mod entropy;
mod format;
mod hex;
mod model;
mod names;
mod palette;
mod paths;
#[cfg(feature = "screenshots")]
mod screenshot;
mod theme;
mod ui;

use std::path::PathBuf;

use gpui::{
    prelude::*, px, size, App, Bounds, Menu, MenuItem, TitlebarOptions, WindowBounds, WindowOptions,
};

use crate::model::session::Session;
use crate::ui::Workbench;

/// Initial window size in pixels.
const WINDOW_WIDTH: f32 = 1760.0;
const WINDOW_HEIGHT: f32 = 1000.0;

/// Smallest window the layout is designed for.
const MIN_WINDOW_WIDTH: f32 = 800.0;
const MIN_WINDOW_HEIGHT: f32 = 480.0;

/// Analyses to run at once: one core stays free for the interface.
fn analysis_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |cores| cores.get().saturating_sub(1).max(1))
}

fn main() {
    // Files named on the command line open at start.
    let initial_files: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();

    gpui_platform::application()
        .with_assets(assets::Assets)
        .run(move |cx: &mut App| {
            if let Err(error) = assets::load_fonts(cx) {
                eprintln!("zrax-desktop: cannot load the embedded fonts: {error}");
            }
            ui::bind_keys(cx);
            cx.on_action(|_: &ui::Quit, cx| cx.quit());
            cx.set_menus([
                Menu::new("zrax").items([MenuItem::action("Quit zrax", ui::Quit)]),
                Menu::new("File").items([
                    MenuItem::action("Add Files…", ui::AddFiles),
                    MenuItem::separator(),
                    MenuItem::action("Remove File", ui::RemoveFile),
                    MenuItem::action("Clear Files", ui::ClearFiles),
                ]),
                Menu::new("View").items([
                    MenuItem::action("Files Panel", ui::ToggleFilesPanel),
                    MenuItem::action("Collapse or Expand Header", ui::ToggleHeader),
                    MenuItem::action("Log", ui::ToggleLog),
                    MenuItem::separator(),
                    MenuItem::action("Classification", ui::ShowClassification),
                    MenuItem::action("Entropy", ui::ShowEntropy),
                    MenuItem::action("Hex", ui::ShowHex),
                    MenuItem::action("JSON", ui::ShowJson),
                    MenuItem::action("Strings", ui::ShowStrings),
                    MenuItem::action("Certificates", ui::ShowCertificates),
                ]),
            ]);

            let bounds = Bounds::centered(None, size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT)), cx);
            // A screenshot run must not appear on screen, take the focus or
            // receive the user's input while it renders.
            #[cfg(feature = "screenshots")]
            let is_visible = screenshot::requested().is_none();
            #[cfg(not(feature = "screenshots"))]
            let is_visible = true;
            let options = WindowOptions {
                show: is_visible,
                focus: is_visible,
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(MIN_WINDOW_WIDTH), px(MIN_WINDOW_HEIGHT))),
                titlebar: Some(TitlebarOptions {
                    title: Some("zrax".into()),
                    ..TitlebarOptions::default()
                }),
                ..WindowOptions::default()
            };
            let session = cx.new(|_| Session::new(analysis_threads()));
            if !initial_files.is_empty() {
                let expanded = paths::expand(&initial_files);
                session.update(cx, |session, cx| {
                    session.add_files(expanded.files, cx);
                });
            }
            let opened = cx.open_window(options, {
                let session = session.clone();
                move |window, cx| {
                    window.set_rem_size(px(theme::REM_PIXELS));
                    cx.new(|cx| Workbench::new(session, window, cx))
                }
            });
            let window = match opened {
                Ok(window) => window,
                Err(error) => {
                    eprintln!("zrax-desktop: cannot open a window: {error}");
                    cx.quit();
                    return;
                }
            };
            if is_visible {
                cx.activate(true);
            }

            #[cfg(feature = "screenshots")]
            if let Some(output) = screenshot::requested() {
                if let Some(tab) = screenshot::requested_tab() {
                    // The window was opened a moment ago; it cannot be gone.
                    let _ = window.update(cx, |workbench, _, cx| workbench.show_tab(tab, cx));
                }
                if let Some((mode, zoom)) = screenshot::requested_map() {
                    let _ =
                        window.update(cx, |workbench, _, cx| workbench.show_map(&mode, zoom, cx));
                }
                if screenshot::wants_collapsed_header() {
                    let _ = window.update(cx, |workbench, _, cx| workbench.collapse_header(cx));
                }
                if screenshot::wants_donations() {
                    let _ = window.update(cx, |workbench, _, cx| workbench.show_donations(cx));
                }
                screenshot::capture_when_idle(output, window.into(), session, cx);
            }
            #[cfg(not(feature = "screenshots"))]
            let _ = (window, session);
        });
}
