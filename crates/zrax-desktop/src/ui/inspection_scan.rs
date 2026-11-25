//! Shared lifecycle for background inspection of the selected resident file.
//! The file and its optional regions come from `workbench::Engine`.

use std::io::{self, BufWriter, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gpui::{div, prelude::*, rems, Context, Div, Entity, Task, Window};
use zrax::inspection::{self, Region};
use zrax::workbench::Engine;

use super::ShowHexAtCursor;
use crate::model::entry::{Entry, EntryId};
use crate::model::session::{LogTone, Session};
use crate::theme;

pub(super) struct Report<T> {
    pub(super) data: T,
    pub(super) regions: Vec<Region>,
}

pub(super) enum Scan<T> {
    Idle,
    Running { _active: ActiveScan },
    Ready(Result<Arc<Report<T>>, &'static str>),
}

pub(super) struct ActiveScan {
    cancelled: Arc<AtomicBool>,
    _task: Task<()>,
}

impl Drop for ActiveScan {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

impl<T: Send + Sync + 'static> Scan<T> {
    pub(super) fn start<V: 'static>(
        engine: Engine,
        scan: impl FnOnce(&[u8], &AtomicBool) -> T + Send + 'static,
        state: fn(&mut V) -> &mut Self,
        cx: &Context<V>,
    ) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        let task = cx.spawn(async move |view, cx| {
            let worker_stop = stop.clone();
            let result = cx
                .background_executor()
                .spawn(async move {
                    catch_unwind(AssertUnwindSafe(|| {
                        let data = scan(engine.data(), &worker_stop);
                        let regions = if worker_stop.load(Ordering::Relaxed) {
                            Vec::new()
                        } else {
                            engine.regions().unwrap_or_default()
                        };
                        Arc::new(Report { data, regions })
                    }))
                    .map_err(|_| "Scan failed on this file")
                })
                .await;
            if !stop.load(Ordering::Relaxed) {
                let _ = view.update(cx, |view, cx| {
                    *state(view) = Self::Ready(result);
                    cx.notify();
                });
            }
        });
        Self::Running {
            _active: ActiveScan {
                cancelled,
                _task: task,
            },
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    pub(super) fn message<'a>(&self, entry: &'a Entry, scanning: &'a str) -> &'a str {
        match self {
            Self::Idle => entry.error_message().unwrap_or("Waiting for file bytes"),
            Self::Running { .. } => scanning,
            Self::Ready(Err(error)) => error,
            Self::Ready(Ok(_)) => "",
        }
    }
}

pub(super) fn message(text: impl Into<gpui::SharedString>) -> Div {
    div()
        .p(rems(0.875))
        .text_color(theme::TEXT_MUTED)
        .child(text.into())
}

pub(super) fn region(regions: &[Region], offset: u64, size: u64) -> Option<&str> {
    inspection::enclosing(regions, offset, size)
        .last()
        .map(|region| region.label.as_str())
}

pub(super) fn show_hex(
    session: &Entity<Session>,
    entry: EntryId,
    offset: u64,
    window: &mut Window,
    cx: &mut gpui::App,
) {
    if session.read(cx).selected_id() != Some(entry) {
        return;
    }
    session.update(cx, |session, cx| session.set_cursor(entry, offset, cx));
    window.dispatch_action(Box::new(ShowHexAtCursor), cx);
}

pub(super) fn export<V: 'static>(
    session: &Entity<Session>,
    input_path: Option<&Path>,
    name: &str,
    write: impl FnOnce(&mut BufWriter<std::fs::File>) -> io::Result<()> + Send + 'static,
    cx: &Context<V>,
) {
    let directory = input_path
        .and_then(Path::parent)
        .filter(|path| path.is_absolute())
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Documents")))
        .unwrap_or_default();
    let filename = name.replace(['/', '\\'], "_");
    let destination = cx.prompt_for_new_path(&directory, Some(&filename));
    let session = session.downgrade();
    cx.spawn(async move |_, cx| {
        let Ok(Ok(Some(path))) = destination.await else {
            return;
        };
        let target = path.clone();
        let result = cx
            .background_executor()
            .spawn(async move {
                let mut file = BufWriter::new(std::fs::File::create(target)?);
                write(&mut file)?;
                file.flush()
            })
            .await;
        let _ = session.update(cx, |session, cx| {
            match result {
                Ok(()) => session.log_line(LogTone::Info, format!("saved {}", path.display())),
                Err(error) => session.log_line(
                    LogTone::Error,
                    format!("Write failed: {}: {error}", path.display()),
                ),
            }
            cx.notify();
        });
    })
    .detach();
}
