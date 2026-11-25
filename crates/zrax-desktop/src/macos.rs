//! `AppKit` integration for the GPUI workbench. GPUI receives Finder's open
//! events and owns the window. Foundation supplies file URLs and preferences.

use std::path::PathBuf;

use gpui::{
    actions, Action, App, Application, Entity, Global, KeyBinding, Menu, MenuItem, SystemMenuType,
    WindowHandle,
};
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSMenu};
use objc2_foundation::{ns_string, NSString, NSUserDefaults, NSURL};
use tokio::sync::mpsc;

use crate::model::session::Session;
use crate::ui::{self, Workbench};
use crate::{open_workbench, view_menu, APP_NAME};

const MAX_RECENT: usize = 10;

actions!(
    macos,
    [
        About,
        ClearRecent,
        CloseWindow,
        Hide,
        HideOthers,
        Minimize,
        ProjectWebsite,
        ShowAll,
        ShowWorkbench,
        ToggleFullScreen,
        Zoom,
    ]
);

#[derive(Action, Clone, PartialEq)]
#[action(namespace = macos, no_json)]
struct OpenRecent {
    index: usize,
}

struct DesktopSession(Entity<Session>);
impl Global for DesktopSession {}

/// Finder may deliver document URLs before the first window exists. Queue
/// them until GPUI has a session and can process them on its main executor.
pub(crate) fn register_launch_events(
    application: &Application,
) -> mpsc::UnboundedReceiver<Vec<String>> {
    let (sender, receiver) = mpsc::unbounded_channel();
    application.on_open_urls(move |urls| {
        let _ = sender.send(urls);
    });
    application.on_reopen(|cx| {
        show_workbench(cx);
    });
    receiver
}

pub(crate) fn configure(
    session: Entity<Session>,
    mut open_requests: mpsc::UnboundedReceiver<Vec<String>>,
    cx: &mut App,
) {
    cx.set_global(DesktopSession(session));
    cx.bind_keys([
        KeyBinding::new("cmd-o", ui::AddFiles, None),
        KeyBinding::new("cmd-shift-e", ui::ExportJson, None),
        KeyBinding::new("cmd-shift-r", ui::RevealInFinder, None),
        KeyBinding::new("cmd-alt-c", ui::CopyFilePath, None),
        KeyBinding::new("cmd-w", CloseWindow, None),
        KeyBinding::new("cmd-m", Minimize, None),
        KeyBinding::new("cmd-h", Hide, None),
        KeyBinding::new("cmd-alt-h", HideOthers, None),
        KeyBinding::new("ctrl-cmd-f", ToggleFullScreen, None),
    ]);
    cx.on_action(|_: &About, _| {
        if let Some(main_thread) = MainThreadMarker::new() {
            NSApplication::sharedApplication(main_thread).orderFrontStandardAboutPanel(None);
        }
    });
    cx.on_action(|_: &Hide, cx| cx.hide());
    cx.on_action(|_: &HideOthers, cx| cx.hide_other_apps());
    cx.on_action(|_: &ShowAll, cx| cx.unhide_other_apps());
    cx.on_action(|_: &ProjectWebsite, cx| cx.open_url(env!("CARGO_PKG_REPOSITORY")));
    cx.on_action(|_: &ShowWorkbench, cx| {
        cx.defer(|cx| {
            show_workbench(cx);
        });
    });
    cx.on_action(|_: &ui::AddFiles, cx| {
        cx.defer(|cx| {
            if let Some(window) = show_workbench(cx) {
                let _ = window.update(cx, |_, _, cx| Workbench::prompt_for_files(cx));
            }
        });
    });
    cx.on_action(|action: &OpenRecent, cx| {
        if let Some(path) = recent_paths().get(action.index).cloned() {
            // GPUI is still dispatching this menu action through the window.
            cx.defer(|cx| open_paths(vec![path], cx));
        }
    });
    cx.on_action(|_: &ClearRecent, _| {
        let defaults = NSUserDefaults::standardUserDefaults();
        for index in 0..MAX_RECENT {
            defaults.removeObjectForKey(&recent_key(index));
        }
        refresh_recent_menu(&[]);
    });
    cx.set_dock_menu(vec![
        MenuItem::action("Show Workbench", ShowWorkbench),
        MenuItem::action("Open Files or Folders…", ui::AddFiles),
    ]);
    set_menus(cx);
    refresh_recent_menu(&recent_paths());

    cx.spawn(async move |cx| {
        while let Some(urls) = open_requests.recv().await {
            let paths = urls
                .iter()
                .filter_map(|url| {
                    let url = NSURL::URLWithString(&NSString::from_str(url))?;
                    local_file_path(&url)
                })
                .collect::<Vec<_>>();
            if !paths.is_empty() {
                cx.update(|cx| open_paths(paths, cx));
            }
        }
    })
    .detach();
}

fn show_workbench(cx: &mut App) -> Option<WindowHandle<Workbench>> {
    if !cx.has_global::<DesktopSession>() {
        return None;
    }
    let existing = cx
        .windows()
        .into_iter()
        .find_map(|window| window.downcast::<Workbench>());
    let window = if let Some(window) = existing {
        let _ = window.update(cx, |_, window, _| window.activate_window());
        window
    } else {
        let session = cx.global::<DesktopSession>().0.clone();
        match open_workbench(session, true, cx) {
            Ok(window) => window,
            Err(error) => {
                eprintln!("zrax-desktop: cannot reopen the workbench: {error}");
                return None;
            }
        }
    };
    cx.activate(true);
    Some(window)
}

fn open_paths(paths: Vec<PathBuf>, cx: &mut App) {
    if let Some(window) = show_workbench(cx) {
        let _ = window.update(cx, |workbench, _, cx| workbench.open_paths(paths, cx));
    }
}

fn local_file_path(url: &NSURL) -> Option<PathBuf> {
    if !url.isFileURL()
        || url.host().is_some_and(|host| {
            !host.is_empty() && !host.to_string().eq_ignore_ascii_case("localhost")
        })
    {
        return None;
    }
    url.to_file_path().filter(|path| path.is_absolute())
}

fn recent_key(index: usize) -> objc2::rc::Retained<NSString> {
    NSString::from_str(&format!("ZraxRecentItem{index}"))
}

fn recent_paths() -> Vec<PathBuf> {
    let defaults = NSUserDefaults::standardUserDefaults();
    (0..MAX_RECENT)
        .filter_map(|index| {
            let url = defaults.URLForKey(&recent_key(index))?;
            local_file_path(&url)
        })
        .collect()
}

pub(crate) fn recent_candidates(picked: &[PathBuf]) -> Vec<PathBuf> {
    picked
        .iter()
        .filter(|path| path.is_absolute())
        .take(MAX_RECENT)
        .cloned()
        .collect()
}

/// Remember each selected file or folder, with one slot per requested path.
/// A large folder therefore takes one slot regardless of how many files it contains.
pub(crate) fn remember_paths(paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    let mut recent = recent_paths();
    for path in paths.into_iter().rev() {
        recent.retain(|existing| *existing != path);
        recent.insert(0, path);
    }
    recent.truncate(MAX_RECENT);

    let defaults = NSUserDefaults::standardUserDefaults();
    for (index, path) in recent.iter().enumerate() {
        let url = NSURL::from_file_path(path);
        defaults.setURL_forKey(url.as_deref(), &recent_key(index));
    }
    refresh_recent_menu(&recent);
}

fn recent_menu() -> Menu {
    let mut items: Vec<_> = (0..MAX_RECENT)
        .map(|index| MenuItem::action("Recent Item", OpenRecent { index }))
        .collect();
    items.extend([
        MenuItem::action("No Recent Items", gpui::NoAction).disabled(true),
        MenuItem::separator(),
        MenuItem::action("Clear Menu", ClearRecent),
    ]);
    Menu::new("Open Recent").items(items)
}

fn native_recent_menu() -> Option<objc2::rc::Retained<NSMenu>> {
    let app = NSApplication::sharedApplication(MainThreadMarker::new()?);
    app.mainMenu()?
        .itemWithTitle(ns_string!("File"))?
        .submenu()?
        .itemWithTitle(ns_string!("Open Recent"))?
        .submenu()
}

fn refresh_recent_menu(paths: &[PathBuf]) {
    let Some(menu) = native_recent_menu() else {
        return;
    };
    // Keep the action registrations fixed. GPUI's macOS backend retains
    // every action it registers when it constructs a new menu bar.
    let menu_items = menu.itemArray();
    let mut items = menu_items.iter();
    for (index, item) in items.by_ref().take(MAX_RECENT).enumerate() {
        let path = paths.get(index);
        item.setHidden(path.is_none());
        if let Some(path) = path {
            let name = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy();
            let label = match path.parent() {
                Some(parent) => format!("{name}  —  {}", parent.display()),
                None => name.into_owned(),
            };
            item.setTitle(&NSString::from_str(&label));
        }
    }
    if let Some(empty_label) = items.next() {
        empty_label.setHidden(!paths.is_empty());
    }
    for item in items {
        item.setHidden(paths.is_empty());
    }
}

fn set_menus(cx: &mut App) {
    cx.set_menus([
        Menu::new(APP_NAME).items([
            MenuItem::action("About Zrax Workbench", About),
            MenuItem::separator(),
            MenuItem::os_submenu("Services", SystemMenuType::Services),
            MenuItem::separator(),
            MenuItem::action("Hide Zrax Workbench", Hide),
            MenuItem::action("Hide Others", HideOthers),
            MenuItem::action("Show All", ShowAll),
            MenuItem::separator(),
            MenuItem::action("Quit Zrax Workbench", ui::Quit),
        ]),
        Menu::new("File").items([
            MenuItem::action("Open Files or Folders…", ui::AddFiles),
            MenuItem::submenu(recent_menu()),
            MenuItem::action("Close Window", CloseWindow),
            MenuItem::separator(),
            MenuItem::action("Export Classification JSON…", ui::ExportJson),
            MenuItem::action("Reveal in Finder", ui::RevealInFinder),
            MenuItem::action("Copy File Path", ui::CopyFilePath),
            MenuItem::separator(),
            MenuItem::action("Remove File", ui::RemoveFile),
            MenuItem::action("Clear Files", ui::ClearFiles),
        ]),
        view_menu(),
        Menu::new("Window").items([
            MenuItem::action("Minimize", Minimize),
            MenuItem::action("Zoom", Zoom),
            MenuItem::separator(),
            MenuItem::action("Show Workbench", ShowWorkbench),
        ]),
        Menu::new("Help").items([MenuItem::action("Zrax Workbench on GitHub", ProjectWebsite)]),
    ]);
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn finder_urls_decode_escaped_paths_and_reject_remote_urls() {
        for (url, expected) in [
            (
                "file:///tmp/A%20B%23%25%20firmware.bin",
                Some(Path::new("/tmp/A B#% firmware.bin")),
            ),
            (
                "file://localhost/tmp/firmware.bin",
                Some(Path::new("/tmp/firmware.bin")),
            ),
            ("file://remote.example/tmp/firmware.bin", None),
            ("https://example.com/file.bin", None),
        ] {
            let url = NSURL::URLWithString(&NSString::from_str(url)).expect("valid test URL");
            assert_eq!(local_file_path(&url).as_deref(), expected);
        }
    }
}
