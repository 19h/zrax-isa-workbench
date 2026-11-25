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
#[cfg(target_os = "macos")]
mod macos;
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
    prelude::*, px, size, App, Bounds, Entity, Menu, MenuItem, TitlebarOptions, WindowBounds,
    WindowHandle, WindowOptions,
};

use crate::model::session::Session;
use crate::ui::Workbench;

const APP_NAME: &str = "Zrax Workbench";

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

fn open_workbench(
    session: Entity<Session>,
    is_visible: bool,
    cx: &mut App,
) -> anyhow::Result<WindowHandle<Workbench>> {
    let mut window_size = size(px(WINDOW_WIDTH), px(WINDOW_HEIGHT));
    let display = cx.primary_display();
    if let Some(display) = &display {
        let available = display.visible_bounds();
        window_size.width = window_size
            .width
            .min((available.size.width * 0.9).max(px(MIN_WINDOW_WIDTH)));
        window_size.height = window_size
            .height
            .min((available.size.height * 0.9).max(px(MIN_WINDOW_HEIGHT)));
    }
    let bounds = Bounds::centered(display.map(|display| display.id()), window_size, cx);
    let options = WindowOptions {
        show: is_visible,
        focus: is_visible,
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(MIN_WINDOW_WIDTH), px(MIN_WINDOW_HEIGHT))),
        titlebar: Some(TitlebarOptions {
            title: Some(APP_NAME.into()),
            ..TitlebarOptions::default()
        }),
        ..WindowOptions::default()
    };
    cx.open_window(options, move |window, cx| {
        window.set_rem_size(px(theme::REM_PIXELS));
        cx.new(|cx| Workbench::new(session, window, cx))
    })
}

fn view_menu() -> Menu {
    let items = [
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
    ];
    #[cfg(target_os = "macos")]
    let items = items.into_iter().chain([
        MenuItem::separator(),
        MenuItem::action("Toggle Full Screen", macos::ToggleFullScreen),
    ]);
    Menu::new("View").items(items)
}

fn main() {
    // Files named on the command line open at start.
    let initial_files: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();

    let application = gpui_platform::application().with_assets(assets::Assets);
    #[cfg(target_os = "macos")]
    let open_requests = macos::register_launch_events(&application);
    application.run(move |cx: &mut App| {
        if let Err(error) = assets::load_fonts(cx) {
            eprintln!("zrax-desktop: cannot load the embedded fonts: {error}");
        }
        ui::bind_keys(cx);
        cx.on_action(|_: &ui::Quit, cx| cx.quit());
        #[cfg(not(target_os = "macos"))]
        cx.set_menus([
            Menu::new("zrax").items([MenuItem::action("Quit zrax", ui::Quit)]),
            Menu::new("File").items([
                MenuItem::action("Add Files…", ui::AddFiles),
                MenuItem::separator(),
                MenuItem::action("Remove File", ui::RemoveFile),
                MenuItem::action("Clear Files", ui::ClearFiles),
            ]),
            view_menu(),
        ]);

        // A screenshot run must not appear on screen, take the focus or
        // receive the user's input while it renders.
        #[cfg(feature = "screenshots")]
        let is_visible = screenshot::requested().is_none();
        #[cfg(not(feature = "screenshots"))]
        let is_visible = true;
        let session = cx.new(|_| Session::new(analysis_threads()));
        #[cfg(target_os = "macos")]
        macos::configure(session.clone(), open_requests, cx);

        if !initial_files.is_empty() {
            let expanded = paths::expand(&initial_files);
            session.update(cx, |session, cx| {
                session.add_files(expanded.files, cx);
            });
        }
        let window = match open_workbench(session.clone(), is_visible, cx) {
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
                let _ = window.update(cx, |workbench, _, cx| workbench.show_map(&mode, zoom, cx));
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
