//! Development aid: render the window to a PNG and exit (`screenshots`
//! feature).
//!
//! `ZRAX_SCREENSHOT=<file.png>` names the output. `ZRAX_SCREENSHOT_TAB`
//! (`classification`, `entropy`, `hex`, …) selects the tab to capture and
//! `ZRAX_SCREENSHOT_VIEW=donations` the donations panel;
//! `ZRAX_SCREENSHOT_HEADER=collapsed` collapses the file header;
//! `ZRAX_SCREENSHOT_MAP=<mode>[@<zoom>]` picks the entropy map's mode. The
//! frame is taken from gpui's renderer, so it needs no screen-recording
//! permission and matches what the window shows.

use std::path::PathBuf;
use std::time::Duration;

use gpui::{AnyWindowHandle, App, Entity};

use crate::model::session::Session;
use crate::ui::Tab;

/// How often to check whether analysis has finished.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Time for the views to draw the finished state before the capture,
/// unless `ZRAX_SCREENSHOT_SETTLE_MS` says otherwise (the map's slower
/// modes compute in the background).
const SETTLE_TIME: Duration = Duration::from_millis(400);

/// Give up waiting for analysis after this many polls (one minute).
const MAX_POLLS: u32 = 1200;

/// The requested output path, if any.
pub fn requested() -> Option<PathBuf> {
    std::env::var_os("ZRAX_SCREENSHOT").map(PathBuf::from)
}

/// The tab named by `ZRAX_SCREENSHOT_TAB`.
pub fn requested_tab() -> Option<Tab> {
    let name = std::env::var("ZRAX_SCREENSHOT_TAB").ok()?;
    Tab::ALL.into_iter().find(|tab| tab.label() == name)
}

/// Whether `ZRAX_SCREENSHOT_VIEW=donations` asks for the donations panel.
pub fn wants_donations() -> bool {
    std::env::var("ZRAX_SCREENSHOT_VIEW").is_ok_and(|view| view == "donations")
}

/// The map mode and zoom named by `ZRAX_SCREENSHOT_MAP=<mode>[@<zoom>]`,
/// for example `kol` or `hil@8`.
pub fn requested_map() -> Option<(String, f64)> {
    let request = std::env::var("ZRAX_SCREENSHOT_MAP").ok()?;
    let (mode, zoom) = request.split_once('@').unwrap_or((&request, "1"));
    Some((mode.to_string(), zoom.parse().unwrap_or(1.0)))
}

/// Whether `ZRAX_SCREENSHOT_HEADER=collapsed` asks for the one-line header.
pub fn wants_collapsed_header() -> bool {
    std::env::var("ZRAX_SCREENSHOT_HEADER").is_ok_and(|header| header == "collapsed")
}

/// `ZRAX_SCREENSHOT_DONATE`: donate the selected file as a click on its
/// offer would, and wait (up to a minute) for the outcome, which is
/// printed. Meant for a local `fwdonor serve`, named with
/// `ZRAX_DONATE_SERVER`.
async fn donate_and_wait(
    workbench: &gpui::WindowHandle<crate::ui::Workbench>,
    cx: &mut gpui::AsyncApp,
) {
    for _ in 0..MAX_POLLS {
        let outcome = workbench.update(cx, |workbench, _, cx| workbench.donate_selected(cx));
        match outcome {
            Ok(Some(outcome)) => {
                println!("zrax-desktop: donation outcome: {outcome}");
                return;
            }
            Ok(None) => cx.background_executor().timer(POLL_INTERVAL).await,
            Err(_) => return,
        }
    }
    println!("zrax-desktop: donation did not finish in time");
}

/// Produce a frame of `window` without presenting it.
fn draw(window: &mut gpui::Window, cx: &mut App) {
    window.refresh();
    window.draw(cx).clear(cx);
}

/// Wait until every entry of `session` is analyzed, render `window` to
/// `output`, and quit.
pub fn capture_when_idle(
    output: PathBuf,
    window: AnyWindowHandle,
    session: Entity<Session>,
    cx: &mut App,
) {
    cx.spawn(async move |cx| {
        for _ in 0..MAX_POLLS {
            cx.background_executor().timer(POLL_INTERVAL).await;
            let is_idle = session.read_with(cx, |session, _| {
                let counts = session.counts();
                counts.done + counts.failed == counts.files
            });
            if is_idle {
                break;
            }
        }
        if std::env::var_os("ZRAX_SCREENSHOT_DONATE").is_some() {
            if let Some(workbench) = window.downcast::<crate::ui::Workbench>() {
                donate_and_wait(&workbench, cx).await;
            }
        }
        let settle = std::env::var("ZRAX_SCREENSHOT_SETTLE_MS")
            .ok()
            .and_then(|millis| millis.parse().ok())
            .map_or(SETTLE_TIME, Duration::from_millis);
        // The window is hidden, so the platform never asks it for a frame.
        // Draw it by hand while the views settle: each draw lets them start
        // the background work whose result the next draw shows.
        let draws = (settle.as_millis() / POLL_INTERVAL.as_millis()).max(2);
        for _ in 0..draws {
            let _ = window.update(cx, |_, window, cx| draw(window, cx));
            cx.background_executor().timer(POLL_INTERVAL).await;
        }
        let rendered = window.update(cx, |_, window, cx| {
            draw(window, cx);
            window.render_to_image()
        });
        match rendered {
            Ok(Ok(image)) => {
                if let Err(error) = image.save(&output) {
                    eprintln!("zrax-desktop: cannot write {}: {error}", output.display());
                }
            }
            Ok(Err(error)) => eprintln!("zrax-desktop: cannot render the window: {error}"),
            Err(error) => eprintln!("zrax-desktop: the window is gone: {error}"),
        }
        cx.update(|cx| cx.quit());
    })
    .detach();
}
