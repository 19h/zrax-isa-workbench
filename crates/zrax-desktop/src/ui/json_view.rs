//! The JSON tab: the detection payload as the CLI and the WASM build
//! serialize it, with copy and save.

use std::sync::Arc;

use gpui::{div, prelude::*, rems, uniform_list, ClipboardItem, Context, SharedString};

use super::widgets::{bar, small, spacer, text_button};
use super::Workbench;
use crate::model::entry::{Entry, EntryId};
use crate::{format, theme};

/// The pretty-printed payload of one entry, split into lines for the
/// virtual list.
pub(super) struct JsonText {
    entry: EntryId,
    /// Whether the entry had its analysis when the text was built.
    is_analyzed: bool,
    text: Arc<str>,
    lines: Arc<[SharedString]>,
}

/// The JSON for `entry`: its payload, or an `error` object as the browser
/// workbench shows for a file without a classification.
fn payload_json(entry: &Entry) -> String {
    let value = match entry.payload() {
        Some(payload) => serde_json::to_value(payload),
        None => Ok(serde_json::json!({
            "error": entry.error_message().unwrap_or("Classification pending."),
        })),
    };
    value
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|error| format!("{{\n  \"error\": \"serialization failed: {error}\"\n}}"))
}

impl Workbench {
    /// The cached JSON of the selected entry, rebuilt when the selection or
    /// its analysis state changed.
    fn json_text(&mut self, cx: &mut Context<Self>) -> Option<&JsonText> {
        let session = self.session.read(cx);
        let entry = session.selected()?;
        let is_analyzed = entry.analysis.is_some();
        let is_current = self
            .json
            .as_ref()
            .is_some_and(|json| json.entry == entry.id && json.is_analyzed == is_analyzed);
        if !is_current {
            let text = payload_json(entry);
            let lines = text.lines().map(|line| line.to_string().into()).collect();
            self.json = Some(JsonText {
                entry: entry.id,
                is_analyzed,
                text: text.into(),
                lines,
            });
        }
        self.json.as_ref()
    }

    /// Ask where to save the selected entry's JSON and write it there.
    pub(super) fn save_json(&mut self, cx: &mut Context<Self>) {
        let Some(text) = self.json_text(cx).map(|json| json.text.clone()) else {
            return;
        };
        let Some(entry) = self.session.read(cx).selected() else {
            return;
        };
        let name = entry.name.replace(['/', '\\'], "_");
        #[cfg(target_os = "macos")]
        let directory = entry
            .path()
            .and_then(std::path::Path::parent)
            .filter(|path| path.is_absolute())
            .map(std::path::Path::to_path_buf)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join("Documents"))
            })
            .unwrap_or_default();
        #[cfg(not(target_os = "macos"))]
        let directory = std::env::current_dir().unwrap_or_default();
        let chosen = cx.prompt_for_new_path(&directory, Some(&format!("{name}.json")));
        let session = self.session.downgrade();
        cx.spawn(async move |_, cx| {
            let Ok(Ok(Some(path))) = chosen.await else {
                return;
            };
            let destination = path.clone();
            let written = cx
                .background_executor()
                .spawn(async move { std::fs::write(destination, text.as_bytes()) })
                .await;
            let _ = session.update(cx, |session, cx| {
                use crate::model::session::LogTone;
                match written {
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

    pub(super) fn render_json(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(name) = self
            .session
            .read(cx)
            .selected()
            .map(|entry| entry.name.clone())
        else {
            return div().into_any_element();
        };
        let Some(json) = self.json_text(cx) else {
            return div().into_any_element();
        };
        let (text, lines) = (json.text.clone(), json.lines.clone());
        let meta = format!(
            "{name}.json · {} chars",
            format::grouped(text.chars().count() as u64)
        );
        let header = bar()
            .child(small().text_color(theme::TEXT_MUTED).child(meta))
            .child(spacer())
            .child(
                text_button("json-copy", "copy")
                    .text_size(rems(theme::TEXT_SMALL_REMS))
                    .on_click(move |_, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(text.to_string()));
                    }),
            )
            .child(
                text_button("json-save", "↓ json")
                    .text_size(rems(theme::TEXT_SMALL_REMS))
                    .on_click(cx.listener(|this, _, _, cx| this.save_json(cx))),
            );
        let line_count = lines.len();
        let body = uniform_list("json-lines", line_count, move |range, _, _| {
            lines[range]
                .iter()
                .map(|line| {
                    div()
                        .px(rems(1.0))
                        .whitespace_nowrap()
                        .text_size(rems(0.75))
                        .child(line.clone())
                })
                .collect()
        })
        .flex_1()
        .min_h_0()
        .py(rems(0.75))
        .bg(theme::SURFACE_INSET);
        div()
            .flex()
            .flex_col()
            .size_full()
            .child(header)
            .child(body)
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::model::entry::{Origin, Source, Status};

    #[test]
    fn an_entry_without_a_payload_serializes_as_an_error_object() {
        let entry = Entry {
            id: EntryId(1),
            name: "pending".into(),
            source: Source::Memory(Arc::from(&b""[..])),
            size: 0,
            status: Status::Queued,
            analysis: None,
            error: None,
            parent: None,
            origin: Origin::Added,
            depth: 0,
            opaque: false,
            cursor: 0,
        };
        assert_eq!(
            payload_json(&entry),
            "{\n  \"error\": \"Classification pending.\"\n}"
        );
    }
}
