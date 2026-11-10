//! The classification tab: members, format, metadata, contained
//! architectures, extensions, heuristic candidates, notes and the entropy
//! profile (`renderClassification` and `subfilePanel` in the browser).

use gpui::{div, prelude::*, rems, AnyElement, Context, Div, Entity, SharedString};
use zrax::inspection::Subfile;
use zrax::types::{
    ContainedArch, DetectionPayload, Endianness, ExtensionCategory, FileFormat, Isa, NoteLevel,
};

use super::strip::profile_strip;
use super::widgets::{
    key_value_row, meter, section, section_body, small, table_section, tag, text_button, Column,
};
use super::{ShowEntropy, Workbench};
use crate::model::entry::{architecture_id, Entry, EntryId, Origin, Status};
use crate::model::session::{Session, MAX_SUBFILE_DEPTH};
use crate::{format, names, theme};

/// The placeholder of a table cell without a value.
const NO_VALUE: &str = "—";

const SUBFILE_COLUMNS: &[Column] = &[
    Column {
        title: "member",
        weight: 2.2,
    },
    Column {
        title: "ISA",
        weight: 1.0,
    },
    Column {
        title: "bits",
        weight: 0.6,
    },
    Column {
        title: "endian",
        weight: 0.9,
    },
    Column {
        title: "format",
        weight: 1.0,
    },
    Column {
        title: "confidence",
        weight: 1.1,
    },
    Column {
        title: "size",
        weight: 1.0,
    },
    Column {
        title: "stored size",
        weight: 1.2,
    },
    Column {
        title: "parent offset",
        weight: 1.4,
    },
    Column {
        title: "transform",
        weight: 1.0,
    },
    Column {
        title: "inspection",
        weight: 1.6,
    },
];

const SLICE_COLUMNS: &[Column] = &[
    Column {
        title: "member",
        weight: 2.2,
    },
    Column {
        title: "ISA",
        weight: 1.0,
    },
    Column {
        title: "bits",
        weight: 0.8,
    },
    Column {
        title: "endian",
        weight: 1.0,
    },
    Column {
        title: "stored size",
        weight: 1.4,
    },
    Column {
        title: "parent offset",
        weight: 1.6,
    },
    Column {
        title: "variant",
        weight: 1.4,
    },
];

/// What is known about the code in one member: from the member's own
/// analysis when it is open, else from the parent's matching slice.
struct Evidence {
    isa: Isa,
    bitwidth: u8,
    endianness: Endianness,
    /// Known only once the member has been analyzed on its own.
    format: Option<FileFormat>,
    confidence: Option<f64>,
}

fn text_cell(text: impl Into<SharedString>) -> AnyElement {
    div().truncate().child(text.into()).into_any_element()
}

/// Evidence for `member` of `entry`. A slice is joined only on the
/// immediate stored range and label: nested slices and duplicate member
/// names must not lend another component their ISA.
fn subfile_evidence(session: &Session, entry: &Entry, member: &Subfile) -> Option<Evidence> {
    if member.opaque {
        return None;
    }
    let opened = session
        .derived(entry.id, Origin::Subfile(member.index))
        .and_then(Entry::payload);
    if let Some(payload) = opened {
        return Some(Evidence {
            isa: payload.primary.isa,
            bitwidth: payload.primary.bitwidth,
            endianness: payload.primary.endianness,
            format: Some(payload.format.format),
            confidence: Some(payload.primary.confidence),
        });
    }
    let slice = entry.payload()?.slices.iter().find(|slice| {
        slice.label.as_deref() == Some(member.label.as_str())
            && slice.offset == member.offset as u64
            && slice.size == member.stored_size as u64
    })?;
    Some(Evidence {
        isa: slice.isa,
        bitwidth: slice.bitwidth,
        endianness: slice.endianness,
        format: None,
        confidence: None,
    })
}

fn subfile_row(
    session_entity: &Entity<Session>,
    session: &Session,
    entry: &Entry,
    member: &Subfile,
) -> Vec<AnyElement> {
    let evidence = subfile_evidence(session, entry, member);
    let known = evidence
        .as_ref()
        .filter(|evidence| !matches!(evidence.isa, Isa::Unknown(_)) && evidence.bitwidth > 0);
    let is_at_depth_limit = entry.depth >= MAX_SUBFILE_DEPTH;
    let inspection = if !member.available {
        "exceeds the 64 MiB inspection limit"
    } else if is_at_depth_limit {
        "nesting limit reached"
    } else if member.opaque {
        "opaque; hex and entropy only"
    } else {
        "available"
    };
    let isa = if member.opaque {
        "not analyzed".to_string()
    } else {
        evidence.as_ref().map_or_else(
            || "unknown".to_string(),
            |evidence| names::isa_name(evidence.isa),
        )
    };
    let label = if member.label.is_empty() {
        format!("member {}", member.index)
    } else {
        member.label.clone()
    };

    let can_open = member.available && !is_at_depth_limit;
    let open = if can_open {
        let session_entity = session_entity.clone();
        let (parent, index): (EntryId, usize) = (entry.id, member.index);
        text_button(("open-subfile", index), format!("open {label}"))
            .truncate()
            .text_color(theme::ACCENT)
            .on_click(move |_, _, cx| {
                session_entity.update(cx, |session, cx| session.open_subfile(parent, index, cx));
            })
            .into_any_element()
    } else {
        div()
            .truncate()
            .text_color(theme::TEXT_DISABLED)
            .child(label)
            .into_any_element()
    };

    vec![
        open,
        text_cell(isa),
        text_cell(known.map_or_else(|| NO_VALUE.into(), |e| e.bitwidth.to_string())),
        text_cell(known.map_or(NO_VALUE, |e| format::endianness_short(e.endianness))),
        text_cell(
            evidence
                .as_ref()
                .and_then(|e| e.format)
                .map_or_else(|| NO_VALUE.into(), names::format_name),
        ),
        text_cell(
            evidence
                .as_ref()
                .and_then(|e| e.confidence)
                .map_or_else(|| NO_VALUE.into(), format::percent),
        ),
        text_cell(format::size(member.size as u64)),
        text_cell(format::size(member.stored_size as u64)),
        text_cell(format::offset(member.offset as u64)),
        text_cell(member.transform.unwrap_or(NO_VALUE)),
        text_cell(inspection),
    ]
}

fn slice_row(slice: &ContainedArch) -> Vec<AnyElement> {
    let has_bitwidth = slice.bitwidth > 0;
    vec![
        text_cell(slice.label.clone().unwrap_or_else(|| NO_VALUE.into())),
        text_cell(names::isa_name(slice.isa)),
        text_cell(if has_bitwidth {
            slice.bitwidth.to_string()
        } else {
            NO_VALUE.into()
        }),
        text_cell(if has_bitwidth {
            format::endianness_short(slice.endianness)
        } else {
            NO_VALUE
        }),
        text_cell(format::size(slice.size)),
        text_cell(format::offset(slice.offset)),
        text_cell(
            slice
                .variant
                .as_ref()
                .map_or_else(|| NO_VALUE.into(), format::variant),
        ),
    ]
}

fn format_section(payload: &DetectionPayload) -> Div {
    let detection = &payload.format;
    let body = section_body()
        .child(key_value_row(
            "format",
            names::format_name(detection.format),
        ))
        .child(key_value_row(
            "confidence",
            format::percent(detection.confidence),
        ))
        .when_some(detection.magic_offset, |body, magic_offset| {
            body.child(key_value_row(
                "magic offset",
                format::offset(magic_offset as u64),
            ))
        })
        .when_some(detection.variant_name.clone(), |body, variant| {
            body.child(key_value_row("variant", variant))
        });
    section("format", None, body)
}

fn metadata_section(payload: &DetectionPayload) -> Div {
    let rows = payload
        .metadata
        .iter()
        .map(|entry| key_value_row(entry.label.clone(), format::metadata_value(entry)));
    section(
        "metadata",
        Some(payload.metadata.len().to_string().into()),
        section_body().children(rows),
    )
}

/// Extensions grouped by category, in order of first appearance.
fn extensions_section(payload: &DetectionPayload) -> Div {
    let mut groups: Vec<(ExtensionCategory, Vec<&str>)> = Vec::new();
    for extension in &payload.extensions {
        match groups
            .iter_mut()
            .find(|(category, _)| *category == extension.category)
        {
            Some((_, extension_names)) => extension_names.push(&extension.name),
            None => groups.push((extension.category, vec![&extension.name])),
        }
    }
    let rows = groups.into_iter().map(|(category, extension_names)| {
        key_value_row(
            names::category_name(category).to_lowercase(),
            div().flex().flex_wrap().gap(rems(0.25)).children(
                extension_names
                    .into_iter()
                    .map(|name| tag(name.to_string())),
            ),
        )
    });
    section(
        "isa extensions",
        Some(payload.extensions.len().to_string().into()),
        section_body().children(rows),
    )
}

fn candidates_section(payload: &DetectionPayload) -> Div {
    let largest_score = payload
        .candidates
        .iter()
        .map(|candidate| candidate.raw_score.unsigned_abs())
        .max()
        .unwrap_or(0)
        .max(1);
    let rows = payload.candidates.iter().map(|candidate| {
        // A share of the largest score, for the bar only.
        #[allow(clippy::cast_precision_loss)]
        let share = candidate.raw_score.unsigned_abs() as f32 / largest_score as f32;
        let sign = if candidate.raw_score < 0 { "-" } else { "" };
        let score = format!(
            "{sign}{} bits",
            format::grouped(candidate.raw_score.unsigned_abs())
        );
        div()
            .flex()
            .items_center()
            .gap(rems(1.0))
            .px(rems(1.0))
            .py(rems(0.375))
            .border_b_1()
            .border_color(theme::LINE_HAIRLINE)
            .child(
                div()
                    .w(rems(10.0))
                    .flex_none()
                    .truncate()
                    .child(architecture_id(candidate.isa)),
            )
            .child(
                small()
                    .w(rems(6.5))
                    .flex_none()
                    .text_color(theme::TEXT_MUTED)
                    .child(format!(
                        "{}-bit {}",
                        candidate.bitwidth,
                        names::serde_id(&candidate.endianness)
                    )),
            )
            .child(div().flex_1().min_w(rems(5.0)).child(meter(share)))
            .child(small().w(rems(6.25)).flex_none().text_right().child(score))
            .child(
                small()
                    .w(rems(3.25))
                    .flex_none()
                    .text_right()
                    .text_color(theme::TEXT_MUTED)
                    .child(format::percent(candidate.confidence)),
            )
    });
    section(
        "heuristic candidates",
        Some(payload.candidates.len().to_string().into()),
        div().flex().flex_col().pb(rems(0.75)).children(rows),
    )
}

fn notes_section(payload: &DetectionPayload) -> Div {
    let rows = payload.notes.iter().map(|note| {
        let level_color = if note.level == NoteLevel::Error {
            theme::SIGNAL_ERROR
        } else {
            theme::TEXT_MUTED
        };
        div()
            .flex()
            .flex_wrap()
            .gap(rems(0.4))
            .px(rems(1.0))
            .py(rems(0.375))
            .border_b_1()
            .border_color(theme::LINE_HAIRLINE)
            .child(
                div()
                    .flex_none()
                    .text_color(level_color)
                    .child(format!("[{}]", names::serde_id(&note.level))),
            )
            .child(div().flex_1().min_w_0().child(note.message.clone()))
            .when_some(note.context.clone(), |row, context| {
                row.child(
                    div()
                        .text_color(theme::TEXT_MUTED)
                        .child(format!("({context})")),
                )
            })
    });
    section(
        "notes",
        Some(payload.notes.len().to_string().into()),
        div().flex().flex_col().pb(rems(0.75)).children(rows),
    )
}

/// The panel shown instead of results while there is no classification.
fn unclassified_section(entry: &Entry) -> Div {
    let is_error = entry.status == Status::Failed;
    let message = entry
        .error_message()
        .unwrap_or("This file is queued for analysis.")
        .to_string();
    let body = section_body()
        .gap(rems(0.5))
        .child(
            div()
                .text_color(if is_error {
                    theme::SIGNAL_ERROR
                } else {
                    theme::TEXT_MUTED
                })
                .child(message),
        )
        .child(div().text_color(theme::TEXT_MUTED).child(
            "Entropy and hex inspection are available independently of architecture classification.",
        ))
        .child(
            div().flex().child(
                text_button("inspect-entropy", "inspect entropy")
                    .border_1()
                    .border_color(theme::LINE_DEFAULT)
                    .on_click(|_, window, cx| window.dispatch_action(Box::new(ShowEntropy), cx)),
            ),
        );
    section(
        if is_error {
            "classification failed"
        } else {
            "classification pending"
        },
        None,
        body,
    )
}

impl Workbench {
    pub(super) fn render_classification(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let session_entity = self.session.clone();
        let session = self.session.read(cx);
        let Some(entry) = session.selected() else {
            return div().into_any_element();
        };
        let analysis = entry.analysis.as_ref();

        let mut sections: Vec<Div> = Vec::new();
        if entry.payload().is_none() {
            sections.push(unclassified_section(entry));
        }
        if let Some(analysis) = analysis {
            if !analysis.subfiles.is_empty() {
                let rows = analysis
                    .subfiles
                    .iter()
                    .map(|member| subfile_row(&session_entity, session, entry, member))
                    .collect();
                sections.push(table_section("subfiles", SUBFILE_COLUMNS, rows));
            } else if let Some(error) = &analysis.subfile_error {
                sections.push(section(
                    "subfiles",
                    None,
                    section_body()
                        .text_color(theme::SIGNAL_ERROR)
                        .child(error.clone()),
                ));
            }
        }
        if let Some(payload) = entry.payload() {
            let mut grid = div()
                .flex()
                .flex_wrap()
                .items_stretch()
                .gap(rems(1.0))
                .child(format_section(payload).flex_1().min_w(rems(20.0)));
            if !payload.metadata.is_empty() {
                grid = grid.child(metadata_section(payload).flex_1().min_w(rems(20.0)));
            }
            sections.push(grid);
            if !payload.slices.is_empty() {
                let rows = payload.slices.iter().map(slice_row).collect();
                sections.push(table_section(
                    "contained architectures",
                    SLICE_COLUMNS,
                    rows,
                ));
            }
            if !payload.extensions.is_empty() {
                sections.push(extensions_section(payload));
            }
            if !payload.candidates.is_empty() {
                sections.push(candidates_section(payload));
            }
            if !payload.notes.is_empty() {
                sections.push(notes_section(payload));
            }
        }

        let mean_text: SharedString = match analysis.and_then(|analysis| analysis.mean_entropy) {
            Some(mean) => format!("SAMPLED MEAN {mean:.4} BITS/BYTE").into(),
            None => "WAITING FOR ANALYSIS".into(),
        };
        let strip = analysis.map(|analysis| {
            profile_strip(analysis.profile.clone())
                .w_full()
                .h(rems(1.5))
        });
        sections.push(section(
            "entropy profile",
            Some(mean_text),
            section_body().child(
                div()
                    .w_full()
                    .h(rems(1.5))
                    .bg(theme::SURFACE_INSET)
                    .children(strip),
            ),
        ));

        div()
            .id("classification-view")
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.classification_scroll)
            .p(rems(1.5))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(rems(1.0))
                    .max_w(rems(70.0))
                    .children(sections),
            )
            .into_any_element()
    }
}
