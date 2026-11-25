//! Printable strings using `zrax::strings`. Encoding rules and tags are
//! shared with the CLI and browser (see `docs/strings.md`).

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gpui::{
    div, prelude::*, relative, rems, uniform_list, ClipboardItem, Context, Div, Entity,
    ScrollStrategy, Subscription, Task, UniformListScrollHandle, Window,
};
use regex::RegexBuilder;
use zrax::strings::{self, Encodings, Extraction, FoundString, Options, Tags};

use super::inspection_scan::{self, Report, Scan};
use super::text_field::{TextField, TextFieldEvent};
use super::widgets::{bar, small, spacer, tag, text_button};
use crate::model::entry::Entry;
use crate::model::session::{Session, SessionEvent};
use crate::{format, theme};

const SCAN_CHUNK_BYTES: usize = 64 << 10;
const MAX_ROWS: usize = 100_000;
const TEXT_BUDGET_BYTES: usize = 16 << 20;
const MAX_PENDING_ROWS: usize = 1_024;
const MAX_QUERY_CHARS: usize = 256;
const FILTER_DELAY: Duration = Duration::from_millis(120);
const ROW_PREVIEW_CHARS: usize = 160;

fn retain_rows(
    pending: &mut Vec<FoundString>,
    rows: &mut Vec<FoundString>,
    budget: &mut usize,
) -> bool {
    for row in pending.drain(..) {
        if rows.len() == MAX_ROWS || row.text.len() > *budget {
            return false;
        }
        *budget -= row.text.len();
        rows.push(row);
    }
    true
}

fn scan_strings(data: &[u8], options: Options, cancelled: &AtomicBool) -> Extraction {
    let mut scanner = strings::Scanner::new(options);
    let mut output = Extraction::default();
    let mut pending = Vec::new();
    let mut budget = TEXT_BUDGET_BYTES;
    for chunk in data.chunks(SCAN_CHUNK_BYTES) {
        if cancelled.load(Ordering::Relaxed) {
            return Extraction::default();
        }
        scanner.push(chunk, &mut pending);
        if !retain_rows(&mut pending, &mut output.strings, &mut budget)
            || (scanner.pending_len() >= MAX_PENDING_ROWS && scanner.position() < data.len() as u64)
        {
            output.truncated = true;
            return output;
        }
    }
    scanner.finish(&mut pending);
    output.truncated = !retain_rows(&mut pending, &mut output.strings, &mut budget);
    output
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Offset,
    Length,
    Text,
}

#[derive(Clone)]
struct Filter {
    query: String,
    is_regex: bool,
    tag: Option<Tags>,
    sort: Sort,
    descending: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            query: String::new(),
            is_regex: false,
            tag: None,
            sort: Sort::Offset,
            descending: false,
        }
    }
}

impl Filter {
    fn apply(&self, rows: &[FoundString]) -> Result<Vec<usize>, String> {
        let pattern = if self.is_regex {
            self.query.clone()
        } else {
            regex::escape(&self.query)
        };
        let expression = if pattern.is_empty() {
            None
        } else {
            Some(
                RegexBuilder::new(&pattern)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|error| error.to_string())?,
            )
        };
        let mut indices: Vec<_> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                self.tag.is_none_or(|tag| row.tags.contains(tag))
                    && expression
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&row.text))
            })
            .map(|(index, _)| index)
            .collect();
        match self.sort {
            Sort::Offset => {}
            Sort::Length => indices.sort_unstable_by_key(|index| (rows[*index].chars, *index)),
            Sort::Text => indices.sort_unstable_by(|&left, &right| {
                rows[left]
                    .text
                    .cmp(&rows[right].text)
                    .then(left.cmp(&right))
            }),
        }
        if self.descending {
            indices.reverse();
        }
        Ok(indices)
    }
}

#[derive(Clone, Copy)]
enum Export {
    Text,
    Csv,
    Json,
}

impl Export {
    fn suffix(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }

    fn write(self, file: &mut dyn Write, output: &Extraction, indices: &[usize]) -> io::Result<()> {
        match self {
            Self::Text => {
                for &index in indices {
                    writeln!(file, "{}", output.strings[index].text)?;
                }
            }
            Self::Csv => {
                writeln!(file, "offset,size,chars,encoding,tags,clipped,text")?;
                for &index in indices {
                    let row = &output.strings[index];
                    writeln!(
                        file,
                        "{},{},{},{},\"{}\",{},\"{}\"",
                        row.offset,
                        row.size,
                        row.chars,
                        row.encoding.id(),
                        tags(row.tags),
                        row.clipped,
                        row.text.replace('"', "\"\"")
                    )?;
                }
            }
            Self::Json => {
                #[derive(serde::Serialize)]
                struct Exported<'a> {
                    strings: Vec<&'a FoundString>,
                    truncated: bool,
                }
                let exported = Exported {
                    strings: indices
                        .iter()
                        .map(|&index| &output.strings[index])
                        .collect(),
                    truncated: output.truncated,
                };
                serde_json::to_writer_pretty(file, &exported).map_err(io::Error::other)?;
            }
        }
        Ok(())
    }
}

pub(super) struct StringsView {
    session: Entity<Session>,
    scan: Scan<Extraction>,
    filter: Filter,
    indices: Option<Result<Arc<[usize]>, String>>,
    filter_task: Option<Task<()>>,
    selected: Option<usize>,
    scroll: UniformListScrollHandle,
    query_field: Entity<TextField>,
    minimum_field: Entity<TextField>,
    minimum: usize,
    encodings: Encodings,
    invalid_minimum: bool,
    show_tags: bool,
    _subscriptions: [Subscription; 4],
}

impl StringsView {
    pub(super) fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let minimum = strings::DEFAULT_MIN_CHARS;
        let query_field = cx.new(|cx| {
            TextField::new(
                "",
                "Search strings",
                MAX_QUERY_CHARS,
                |ch| !ch.is_control(),
                cx,
            )
        });
        let minimum_field = cx.new(|cx| {
            TextField::new(minimum.to_string(), "4", 3, |ch| ch.is_ascii_digit(), cx)
                .with_min_width(2.5)
        });
        let subscriptions = [
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe(&session, |view, _, event: &SessionEvent, cx| {
                if *event == SessionEvent::SelectionChanged {
                    view.reset_scan(cx);
                }
            }),
            cx.subscribe(&query_field, |view, field, event, cx| {
                if *event == TextFieldEvent::Changed {
                    view.filter.query = field.read(cx).text().to_owned();
                    view.reset_filter(cx);
                }
            }),
            cx.subscribe(&minimum_field, |view, _, event, cx| match event {
                TextFieldEvent::Submitted => view.set_minimum(cx),
                TextFieldEvent::Changed => {
                    view.invalid_minimum = false;
                    cx.notify();
                }
                TextFieldEvent::Cancelled => {}
            }),
        ];
        Self {
            session,
            scan: Scan::Idle,
            filter: Filter::default(),
            indices: None,
            filter_task: None,
            selected: None,
            scroll: UniformListScrollHandle::new(),
            query_field,
            minimum_field,
            minimum,
            encodings: Options::default().encodings(),
            invalid_minimum: false,
            show_tags: false,
            _subscriptions: subscriptions,
        }
    }

    fn set_minimum(&mut self, cx: &mut Context<Self>) {
        let parsed = self.minimum_field.read(cx).text().parse::<usize>().ok();
        if let Some(minimum) =
            parsed.filter(|min| (strings::MIN_MIN_CHARS..=strings::MAX_MIN_CHARS).contains(min))
        {
            self.invalid_minimum = false;
            if self.minimum != minimum {
                self.minimum = minimum;
                self.reset_scan(cx);
            }
        } else {
            self.invalid_minimum = true;
        }
        cx.notify();
    }

    fn reset_scan(&mut self, cx: &mut Context<Self>) {
        self.scan = Scan::Idle;
        self.reset_filter(cx);
    }

    fn reset_filter(&mut self, cx: &mut Context<Self>) {
        self.indices = None;
        self.filter_task = None;
        self.selected = None;
        self.scroll.scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    fn start_filter(&mut self, rows: Arc<Report<Extraction>>, cx: &Context<Self>) {
        let filter = self.filter.clone();
        self.filter_task = Some(cx.spawn(async move |view, cx| {
            cx.background_executor().timer(FILTER_DELAY).await;
            let result = cx
                .background_executor()
                .spawn(async move { filter.apply(&rows.data.strings).map(Arc::from) })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.selected = result
                    .as_ref()
                    .ok()
                    .and_then(|indices: &Arc<[usize]>| indices.first().copied());
                view.indices = Some(result);
                view.filter_task = None;
                cx.notify();
            });
        }));
    }

    fn export(
        &self,
        entry: &Entry,
        report: Arc<Report<Extraction>>,
        indices: Arc<[usize]>,
        kind: Export,
        cx: &Context<Self>,
    ) {
        let name = format!("{}.strings.{}", entry.name, kind.suffix());
        inspection_scan::export(
            &self.session,
            entry.path(),
            &name,
            move |file| kind.write(file, &report.data, &indices),
            cx,
        );
    }

    fn controls(&self, cx: &Context<Self>) -> Div {
        let encodings = strings::ENCODINGS.into_iter().map(|encoding| {
            let flag = encoding.flag();
            filter_button(encoding.id(), self.encodings.contains(flag)).on_click(cx.listener(
                move |view, _, _, cx| {
                    let next = view.encodings ^ flag;
                    if !next.is_empty() {
                        view.encodings = next;
                        view.reset_scan(cx);
                    }
                },
            ))
        });
        bar()
            .flex_wrap()
            .whitespace_normal()
            .child(
                div()
                    .flex_none()
                    .w(rems(12.0))
                    .child(self.query_field.clone()),
            )
            .child(
                filter_button("regex", self.filter.is_regex).on_click(cx.listener(
                    |view, _, _, cx| {
                        view.filter.is_regex = !view.filter.is_regex;
                        view.reset_filter(cx);
                    },
                )),
            )
            .child(small().text_color(theme::TEXT_MUTED).child("min chars"))
            .child(
                div()
                    .flex_none()
                    .w(rems(3.0))
                    .child(self.minimum_field.clone()),
            )
            .child(
                text_button("apply-minimum", "apply")
                    .on_click(cx.listener(|view, _, _, cx| view.set_minimum(cx))),
            )
            .children(encodings)
            .child(
                filter_button("tags", self.show_tags || self.filter.tag.is_some()).on_click(
                    cx.listener(|view, _, _, cx| {
                        view.show_tags = !view.show_tags;
                        cx.notify();
                    }),
                ),
            )
            .when(self.invalid_minimum, |line| {
                line.child(small().text_color(theme::SIGNAL_ERROR).child(format!(
                    "Enter {}–{}",
                    strings::MIN_MIN_CHARS,
                    strings::MAX_MIN_CHARS
                )))
            })
    }

    fn tag_filters(&self, cx: &Context<Self>) -> Div {
        bar()
            .flex_wrap()
            .whitespace_normal()
            .child(
                filter_button("all tags", self.filter.tag.is_none()).on_click(cx.listener(
                    |view, _, _, cx| {
                        view.filter.tag = None;
                        view.reset_filter(cx);
                    },
                )),
            )
            .children(strings::TAG_NAMES.iter().map(|&(tag, name)| {
                filter_button(name, self.filter.tag == Some(tag)).on_click(cx.listener(
                    move |view, _, _, cx| {
                        view.filter.tag = (view.filter.tag != Some(tag)).then_some(tag);
                        view.reset_filter(cx);
                    },
                ))
            }))
    }

    fn sort_button(
        &self,
        label: &'static str,
        width: f32,
        sort: Sort,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let arrow = if self.filter.sort == sort {
            if self.filter.descending {
                " ↓"
            } else {
                " ↑"
            }
        } else {
            ""
        };
        text_button(label, format!("{label}{arrow}"))
            .w(rems(width))
            .on_click(cx.listener(move |view, _, _, cx| {
                view.filter.descending = view.filter.sort == sort && !view.filter.descending;
                view.filter.sort = sort;
                view.reset_filter(cx);
            }))
    }

    fn render_list(
        &self,
        report: Arc<Report<Extraction>>,
        indices: Arc<[usize]>,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let selected = self.selected;
        let view = cx.entity().downgrade();
        let list = uniform_list("string-rows", indices.len(), move |range, _, _| {
            range
                .map(|row_index| {
                    let index = indices[row_index];
                    let row = &report.data.strings[index];
                    let view = view.clone();
                    small()
                        .id(("string-row", index))
                        .flex()
                        .items_center()
                        .w_full()
                        .h(rems(1.55))
                        .px(rems(0.5))
                        .border_b_1()
                        .border_color(theme::LINE_HAIRLINE)
                        .cursor_pointer()
                        .hover(|style| style.bg(theme::SURFACE_HOVER))
                        .when(Some(index) == selected, |row| {
                            row.bg(theme::SURFACE_SELECTED)
                        })
                        .child(
                            div()
                                .w(rems(5.5))
                                .flex_none()
                                .text_color(theme::ACCENT)
                                .child(format::offset(row.offset)),
                        )
                        .child(
                            div()
                                .w(rems(4.1))
                                .flex_none()
                                .text_color(theme::TEXT_MUTED)
                                .child(row.encoding.id()),
                        )
                        .child(div().w(rems(4.0)).flex_none().child(row.chars.to_string()))
                        .child(div().flex_1().min_w_0().truncate().child(preview(row)))
                        .on_click(move |_, _, cx| {
                            let _ = view.update(cx, |view, cx| {
                                view.selected = Some(index);
                                cx.notify();
                            });
                        })
                })
                .collect()
        })
        .track_scroll(&self.scroll)
        .flex_1()
        .min_h_0();
        div()
            .flex()
            .flex_col()
            .min_h_0()
            .flex_1()
            .child(
                small()
                    .flex()
                    .flex_none()
                    .items_center()
                    .border_b_1()
                    .border_color(theme::LINE_DEFAULT)
                    .child(self.sort_button("offset", 5.5, Sort::Offset, cx))
                    .child(
                        div()
                            .w(rems(4.1))
                            .flex_none()
                            .pl(rems(0.5))
                            .child("encoding"),
                    )
                    .child(self.sort_button("chars", 4.0, Sort::Length, cx))
                    .child(self.sort_button("text", 5.0, Sort::Text, cx)),
            )
            .child(list)
    }

    fn details(
        &self,
        entry: &Entry,
        report: &Report<Extraction>,
        row: &FoundString,
    ) -> impl IntoElement {
        let text = row.text.clone();
        let session = self.session.clone();
        let entry_id = entry.id;
        let offset = row.offset;
        div()
            .flex()
            .flex_col()
            .flex_none()
            .max_h(relative(0.42))
            .min_h_0()
            .border_t_1()
            .border_color(theme::LINE_DEFAULT)
            .child(
                bar()
                    .flex_wrap()
                    .whitespace_normal()
                    .child(small().child(format!(
                        "{} · {} · {}",
                        format::offset(offset),
                        format::size(row.size),
                        row.encoding.id()
                    )))
                    .when_some(
                        inspection_scan::region(&report.regions, row.offset, row.size),
                        |bar, region| {
                            bar.child(
                                small()
                                    .text_color(theme::TEXT_MUTED)
                                    .child(region.to_owned()),
                            )
                        },
                    )
                    .children(row.tags.ids().map(tag))
                    .when(row.clipped, |bar| bar.child(tag("text clipped")))
                    .child(spacer())
                    .child(
                        text_button("string-copy", "copy").on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                        }),
                    )
                    .child(text_button("string-hex", "show in hex").on_click(
                        move |_, window, cx| {
                            inspection_scan::show_hex(&session, entry_id, offset, window, cx);
                        },
                    )),
            )
            .child(
                small()
                    .id(("string-details", offset))
                    .min_h_0()
                    .overflow_scroll()
                    .px(rems(0.75))
                    .py(rems(0.35))
                    .whitespace_nowrap()
                    .child(row.text.clone()),
            )
    }
}

impl Render for StringsView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(entry) = self.session.read(cx).selected() else {
            return inspection_scan::message("Select a file").into_any_element();
        };
        if self.scan.is_idle() {
            if let Some(analysis) = &entry.analysis {
                let options = Options::new(self.minimum, self.encodings)
                    .expect("minimum is valid and at least one encoding is selected");
                self.scan = Scan::start(
                    analysis.engine.clone(),
                    move |data, cancelled| scan_strings(data, options, cancelled),
                    |view| &mut view.scan,
                    cx,
                );
            }
        }
        let panel = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .child(self.controls(cx))
            .when(self.show_tags, |panel| panel.child(self.tag_filters(cx)));
        let Scan::Ready(Ok(report)) = &self.scan else {
            return panel
                .child(inspection_scan::message(
                    self.scan
                        .message(entry, "Scanning for printable strings…")
                        .to_owned(),
                ))
                .into_any_element();
        };
        let report = report.clone();
        let indices = match &self.indices {
            Some(Ok(indices)) => indices.clone(),
            Some(Err(error)) => {
                return panel
                    .child(inspection_scan::message(error.clone()))
                    .into_any_element()
            }
            None => {
                if self.filter_task.is_none() {
                    self.start_filter(report, cx);
                }
                return panel
                    .child(inspection_scan::message("Filtering strings…"))
                    .into_any_element();
            }
        };
        let mut toolbar = bar()
            .flex_wrap()
            .whitespace_normal()
            .child(small().child(format!(
                "{} of {} strings",
                indices.len(),
                report.data.strings.len()
            )))
            .when(report.data.truncated, |bar| {
                bar.child(
                    small()
                        .text_color(theme::SIGNAL_ERROR)
                        .child("scan limit reached · partial results"),
                )
            })
            .child(spacer());
        if !indices.is_empty() {
            for (label, kind) in [
                ("save TXT", Export::Text),
                ("save CSV", Export::Csv),
                ("save JSON", Export::Json),
            ] {
                let (report, indices) = (report.clone(), indices.clone());
                toolbar = toolbar.child(text_button(label, label).on_click(cx.listener(
                    move |view, _, _, cx| {
                        if let Some(entry) = view.session.read(cx).selected() {
                            view.export(entry, report.clone(), indices.clone(), kind, cx);
                        }
                    },
                )));
            }
        }
        let panel = panel.child(toolbar);
        if indices.is_empty() {
            return panel
                .child(inspection_scan::message("No matching strings"))
                .into_any_element();
        }
        panel
            .child(self.render_list(report.clone(), indices, cx))
            .when_some(
                self.selected
                    .and_then(|index| report.data.strings.get(index)),
                |panel, row| panel.child(self.details(entry, &report, row)),
            )
            .into_any_element()
    }
}

fn filter_button(label: &'static str, active: bool) -> gpui::Stateful<Div> {
    text_button(label, label)
        .text_size(rems(theme::TEXT_SMALL_REMS))
        .when(active, |button| {
            button.bg(theme::ACCENT_WASH).text_color(theme::ACCENT)
        })
}

fn tags(tags: Tags) -> String {
    tags.ids().collect::<Vec<_>>().join(", ")
}

fn preview(row: &FoundString) -> String {
    let mut chars = row.text.chars();
    let mut preview: String = chars.by_ref().take(ROW_PREVIEW_CHARS).collect();
    if chars.next().is_some() || row.clipped {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_search_matches_regex_metacharacters_verbatim() {
        let scanned = scan_strings(
            b"ab.cd\0Abxcd\0ordinary",
            Options::new(4, Encodings::ASCII).expect("valid options"),
            &AtomicBool::new(false),
        );
        let mut filter = Filter {
            query: "AB.CD".into(),
            ..Filter::default()
        };
        let literal = filter.apply(&scanned.strings).expect("escaped pattern");
        assert_eq!(literal.len(), 1);
        assert_eq!(scanned.strings[literal[0]].offset, 0);
        filter.is_regex = true;
        assert_eq!(
            filter.apply(&scanned.strings).expect("valid regex").len(),
            2
        );
    }

    #[test]
    fn streaming_preserves_a_string_across_a_chunk_boundary() {
        let mut data = vec![0; SCAN_CHUNK_BYTES - 3];
        data.extend(b"across boundary");
        let options = Options::new(4, Encodings::ASCII).expect("valid options");
        let result = scan_strings(&data, options, &AtomicBool::new(false));
        assert_eq!(result, strings::extract(&data, &options, MAX_ROWS));
    }
}
