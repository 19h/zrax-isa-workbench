//! The session: every file the user added, in list order, with the queue
//! that analyzes them.
//!
//! Entries are kept in display order: a member extracted from a file sits
//! directly after its parent and that parent's earlier members, indented by
//! its depth. Analysis runs on the background executor, a bounded number of
//! files at a time, and reports back to this entity.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;

use gpui::{Context, EventEmitter, SharedString};

use crate::analysis::{self, Request};
use crate::model::entry::{Analysis, Entry, EntryId, Origin, Source, Status};

/// Deepest nesting of extracted members, as in the browser workbench and
/// the classifier (`MAX_NESTING` in `src/lib.rs`).
pub const MAX_SUBFILE_DEPTH: usize = 6;

/// Lines the analysis log keeps.
const MAX_LOG_LINES: usize = 400;

/// What a log line reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTone {
    /// A command the user gave.
    Command,
    /// Progress.
    Info,
    /// A finished analysis.
    Done,
    /// A failure.
    Error,
}

/// One line of the analysis log.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// What the line reports.
    pub tone: LogTone,
    /// The text.
    pub text: SharedString,
}

/// Something views other than the list react to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Another entry became the selected one (or none is).
    SelectionChanged,
    /// An entry's analysis finished, successfully or not.
    Analyzed(EntryId),
    /// An entry and its members were removed.
    Removed(EntryId),
}

/// Counts shown in the files heading and the status bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// All entries.
    pub files: usize,
    /// Entries whose analysis finished.
    pub done: usize,
    /// Entries that could not be analyzed.
    pub failed: usize,
}

/// The files of one window.
pub struct Session {
    entries: Vec<Entry>,
    selected: Option<EntryId>,
    next_id: u64,
    /// Analyses running right now.
    running: usize,
    /// Most analyses to run at once.
    max_running: usize,
    log: VecDeque<LogLine>,
}

impl EventEmitter<SessionEvent> for Session {}

impl Session {
    /// An empty session that analyzes up to `max_running` files at once.
    pub fn new(max_running: usize) -> Self {
        Self {
            entries: Vec::new(),
            selected: None,
            next_id: 1,
            running: 0,
            max_running: max_running.max(1),
            log: VecDeque::new(),
        }
    }

    /// Every entry in display order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry with `id`.
    pub fn entry(&self, id: EntryId) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    fn entry_mut(&mut self, id: EntryId) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.id == id)
    }

    /// The selected entry.
    pub fn selected(&self) -> Option<&Entry> {
        self.entry(self.selected?)
    }

    /// The selected entry's id.
    pub fn selected_id(&self) -> Option<EntryId> {
        self.selected
    }

    /// The log, oldest line first.
    pub fn log(&self) -> impl Iterator<Item = &LogLine> {
        self.log.iter()
    }

    /// File, done and failed counts.
    pub fn counts(&self) -> Counts {
        let mut counts = Counts {
            files: self.entries.len(),
            ..Counts::default()
        };
        for entry in &self.entries {
            match entry.status {
                Status::Done => counts.done += 1,
                Status::Failed => counts.failed += 1,
                Status::Queued | Status::Analyzing => {}
            }
        }
        counts
    }

    /// Append a line to the log, dropping the oldest beyond the limit.
    pub fn log_line(&mut self, tone: LogTone, text: impl Into<SharedString>) {
        if self.log.len() == MAX_LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            tone,
            text: text.into(),
        });
    }

    /// Queue files the user added. The first becomes the selection when
    /// nothing is selected. Returns the new entries' ids.
    pub fn add_files(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) -> Vec<EntryId> {
        let mut added = Vec::with_capacity(paths.len());
        for path in paths {
            let name = path.file_name().map_or_else(
                || path.to_string_lossy().into_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
            let size = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
            let id = self.allocate_id();
            self.entries.push(Entry {
                id,
                name: name.into(),
                source: Source::File(path),
                size,
                status: Status::Queued,
                analysis: None,
                error: None,
                parent: None,
                origin: Origin::Added,
                depth: 0,
                opaque: false,
                cursor: 0,
            });
            added.push(id);
        }
        if !added.is_empty() {
            self.log_line(LogTone::Command, format!("add {} file(s)", added.len()));
        }
        if self.selected.is_none() {
            if let Some(first) = added.first() {
                self.select(*first, cx);
            }
        }
        self.start_queued(cx);
        cx.notify();
        added
    }

    /// Queue bytes derived from `parent` (an extracted member, a decrypted
    /// payload) as a nested entry and select it. `None` when the parent is
    /// gone or the nesting limit is reached.
    pub fn add_derived(
        &mut self,
        parent: EntryId,
        origin: Origin,
        name: impl Into<SharedString>,
        data: Arc<[u8]>,
        opaque: bool,
        cx: &mut Context<Self>,
    ) -> Option<EntryId> {
        let parent_index = self.entries.iter().position(|entry| entry.id == parent)?;
        let depth = self.entries[parent_index].depth + 1;
        if depth > MAX_SUBFILE_DEPTH {
            return None;
        }
        // After the parent and everything already nested under it.
        let insert_at = self.entries[parent_index + 1..]
            .iter()
            .position(|entry| entry.depth < depth)
            .map_or(self.entries.len(), |offset| parent_index + 1 + offset);
        let id = self.allocate_id();
        let size = data.len() as u64;
        self.entries.insert(
            insert_at,
            Entry {
                id,
                name: name.into(),
                source: Source::Memory(data),
                size,
                status: Status::Queued,
                analysis: None,
                error: None,
                parent: Some(parent),
                origin,
                depth,
                opaque,
                cursor: 0,
            },
        );
        self.select(id, cx);
        self.start_queued(cx);
        cx.notify();
        Some(id)
    }

    /// The entry derived from `parent` in the way `origin` describes.
    pub fn derived(&self, parent: EntryId, origin: Origin) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.parent == Some(parent) && entry.origin == origin)
    }

    /// The ancestors of `id`, outermost first.
    pub fn ancestors(&self, id: EntryId) -> Vec<&Entry> {
        let mut path = Vec::new();
        let mut parent = self.entry(id).and_then(|entry| entry.parent);
        while let Some(entry) = parent.and_then(|parent| self.entry(parent)) {
            path.push(entry);
            parent = entry.parent;
        }
        path.reverse();
        path
    }

    /// Open member `index` of `parent` as an entry of its own: select it if
    /// it is already open, otherwise extract it off the main thread and
    /// queue it.
    pub fn open_subfile(&mut self, parent: EntryId, index: usize, cx: &mut Context<Self>) {
        let origin = Origin::Subfile(index);
        if let Some(existing) = self.derived(parent, origin) {
            let id = existing.id;
            self.select(id, cx);
            return;
        }
        let Some(analysis) = self.entry(parent).and_then(|entry| entry.analysis.as_ref()) else {
            return;
        };
        let Some(member) = analysis.subfiles.iter().find(|file| file.index == index) else {
            return;
        };
        let name: SharedString = if member.label.is_empty() {
            format!("member {index}").into()
        } else {
            member.label.clone().into()
        };
        let opaque = member.opaque;
        let engine = analysis.engine.clone();
        self.log_line(LogTone::Command, format!("open {name}"));
        cx.spawn(async move |session, cx| {
            let extracted = cx
                .background_executor()
                .spawn(async move { engine.subfile(index).map(Arc::<[u8]>::from) })
                .await;
            let _ = session.update(cx, |session, cx| match extracted {
                Ok(data) => {
                    // The user may have opened it again while it was extracted.
                    if session.derived(parent, origin).is_none() {
                        session.add_derived(parent, origin, name, data, opaque, cx);
                    }
                }
                Err(error) => {
                    session.log_line(LogTone::Error, format!("{name} · {error}"));
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Make `id` the selected entry.
    pub fn select(&mut self, id: EntryId, cx: &mut Context<Self>) {
        if self.selected == Some(id) || self.entry(id).is_none() {
            return;
        }
        self.selected = Some(id);
        cx.emit(SessionEvent::SelectionChanged);
        cx.notify();
    }

    /// Select the entry `step` rows after (or before) the selected one,
    /// stopping at the ends of the list.
    pub fn select_relative(&mut self, step: isize, cx: &mut Context<Self>) {
        if self.entries.is_empty() {
            return;
        }
        let last = self.entries.len() - 1;
        let current = self
            .selected
            .and_then(|id| self.entries.iter().position(|entry| entry.id == id));
        let target = match current {
            Some(index) => index.saturating_add_signed(step).min(last),
            None => 0,
        };
        self.select(self.entries[target].id, cx);
    }

    /// Remember where the views of `id` are looking.
    pub fn set_cursor(&mut self, id: EntryId, cursor: u64, cx: &mut Context<Self>) {
        if let Some(entry) = self.entry_mut(id) {
            entry.cursor = cursor.min(entry.size.saturating_sub(1));
            cx.notify();
        }
    }

    /// Remove an entry and everything extracted from it. The selection
    /// moves to the row that takes its place.
    pub fn remove(&mut self, id: EntryId, cx: &mut Context<Self>) {
        let Some(index) = self.entries.iter().position(|entry| entry.id == id) else {
            return;
        };
        let depth = self.entries[index].depth;
        let end = self.entries[index + 1..]
            .iter()
            .position(|entry| entry.depth <= depth)
            .map_or(self.entries.len(), |offset| index + 1 + offset);
        let removed: Vec<EntryId> = self
            .entries
            .drain(index..end)
            .map(|entry| entry.id)
            .collect();
        if self
            .selected
            .is_some_and(|selected| removed.contains(&selected))
        {
            let next = self.entries.get(index).or_else(|| self.entries.last());
            self.selected = next.map(|entry| entry.id);
            cx.emit(SessionEvent::SelectionChanged);
        }
        cx.emit(SessionEvent::Removed(id));
        cx.notify();
    }

    /// Remove every entry. Analyses still running are discarded when they
    /// report back.
    pub fn clear(&mut self, cx: &mut Context<Self>) {
        let removed: Vec<EntryId> = self
            .entries
            .iter()
            .filter(|entry| entry.depth == 0)
            .map(|entry| entry.id)
            .collect();
        self.entries.clear();
        self.selected = None;
        self.log_line(LogTone::Command, "clear");
        for id in removed {
            cx.emit(SessionEvent::Removed(id));
        }
        cx.emit(SessionEvent::SelectionChanged);
        cx.notify();
    }

    fn allocate_id(&mut self) -> EntryId {
        let id = EntryId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Start queued entries while analysis slots are free.
    fn start_queued(&mut self, cx: &mut Context<Self>) {
        while self.running < self.max_running {
            let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| entry.status == Status::Queued)
            else {
                return;
            };
            entry.status = Status::Analyzing;
            let id = entry.id;
            let request = Request {
                source: entry.source.clone(),
                opaque: entry.opaque,
            };
            self.running += 1;
            cx.spawn(async move |session, cx| {
                let result = cx
                    .background_executor()
                    .spawn(async move { analysis::run(&request) })
                    .await;
                // The window may be gone by now; there is nobody to tell.
                let _ = session.update(cx, |session, cx| session.finish(id, result, cx));
            })
            .detach();
        }
    }

    fn finish(&mut self, id: EntryId, result: Result<Analysis, String>, cx: &mut Context<Self>) {
        self.running = self.running.saturating_sub(1);
        // A removed entry's result is dropped; its slot is free again.
        if let Some(index) = self.entries.iter().position(|entry| entry.id == id) {
            let line = self.record(index, result);
            self.log_line(line.tone, line.text);
            cx.emit(SessionEvent::Analyzed(id));
        }
        self.start_queued(cx);
        cx.notify();
    }

    /// Store an analysis result in the entry at `index`; the log line that
    /// reports it.
    fn record(&mut self, index: usize, result: Result<Analysis, String>) -> LogLine {
        let entry = &mut self.entries[index];
        match result {
            Ok(analysis) => {
                entry.size = analysis.engine.data().len() as u64;
                let elapsed_ms = analysis.elapsed_ms;
                // A file zrax cannot classify still has entropy, bytes and
                // strings to inspect, so its analysis is kept.
                let is_classified = analysis.error.is_none();
                entry.status = if is_classified {
                    Status::Done
                } else {
                    Status::Failed
                };
                entry.analysis = Some(analysis);
                LogLine {
                    tone: if is_classified {
                        LogTone::Done
                    } else {
                        LogTone::Error
                    },
                    text: format!("{} · {} · {elapsed_ms:.1} ms", entry.name, entry.summary())
                        .into(),
                }
            }
            Err(message) => {
                entry.status = Status::Failed;
                let text = format!("{} · {message}", entry.name).into();
                entry.error = Some(message);
                LogLine {
                    tone: LogTone::Error,
                    text,
                }
            }
        }
    }
}
