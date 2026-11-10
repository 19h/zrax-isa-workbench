//! The view of the selected file: header, breadcrumb, classification band,
//! tabs and the active tab's panel.

use gpui::{div, prelude::*, relative, rems, svg, Context, Div, FontWeight, SharedString};

use super::widgets::{badge, bar, icon_button, key_cap, small, spacer, text_button, IconSize};
use super::{widgets, RemoveFile, Tab, ToggleHeader, Workbench};
use crate::assets::icon;
use crate::model::entry::{architecture_id, architecture_label, Entry, Status};
use crate::{format, names, theme};

/// One labelled value of the classification band.
#[derive(Debug, PartialEq)]
struct BandField {
    label: &'static str,
    value: String,
    detail: Option<String>,
}

/// The text of the classification band for one entry.
#[derive(Debug, PartialEq)]
struct BandText {
    /// The large line: the architecture tag, or the state.
    title: String,
    /// The line below: ISA names, or why there is no classification.
    sub: String,
    /// Whether the title reports a failure.
    is_error: bool,
    fields: Vec<BandField>,
}

/// What the band says about `entry` (`renderSelected` in the browser).
fn band_text(entry: &Entry) -> BandText {
    let Some(payload) = entry.payload() else {
        let is_error = entry.status == Status::Failed;
        let mut fields = vec![BandField {
            label: "size",
            value: format::size(entry.size),
            detail: None,
        }];
        if let Some(analysis) = &entry.analysis {
            fields.push(BandField {
                label: "analyzed in",
                value: format!("{:.1} ms", analysis.elapsed_ms),
                detail: None,
            });
        }
        return BandText {
            title: if is_error {
                "unclassified".into()
            } else {
                entry.status.label().into()
            },
            sub: entry
                .error_message()
                .unwrap_or("waiting for classification")
                .into(),
            is_error,
            fields,
        };
    };

    let primary = &payload.primary;
    // The distinct concrete ISAs of the members, or of the file itself.
    let mut architectures = Vec::new();
    let member_isas: Vec<_> = if payload.slices.is_empty() {
        vec![primary.isa]
    } else {
        payload.slices.iter().map(|slice| slice.isa).collect()
    };
    for isa in member_isas {
        let is_concrete = !matches!(isa, zrax::types::Isa::Unknown(_));
        if is_concrete && !architectures.contains(&isa) {
            architectures.push(isa);
        }
    }
    let is_mixed = architectures.len() > 1;

    let title = match architectures.as_slice() {
        [single] => architecture_id(*single),
        [] => architecture_label(payload),
        _ => "multiple ISAs".into(),
    };
    let sub = if architectures.is_empty() {
        names::isa_name(primary.isa)
    } else {
        let isa_names: Vec<String> = architectures
            .iter()
            .map(|isa| names::isa_name(*isa))
            .collect();
        isa_names.join(" · ")
    };
    let per_member = || "per member".to_string();
    let mut fields = vec![
        BandField {
            label: "bitwidth",
            value: if is_mixed {
                per_member()
            } else {
                format!("{}-bit", primary.bitwidth)
            },
            detail: None,
        },
        BandField {
            label: "endianness",
            value: if is_mixed {
                per_member()
            } else {
                format::endianness(primary.endianness).to_lowercase()
            },
            detail: None,
        },
        BandField {
            label: "format",
            value: names::format_name(payload.format.format).to_lowercase(),
            detail: None,
        },
        BandField {
            label: if is_mixed {
                "primary confidence"
            } else {
                "confidence"
            },
            value: format::percent(primary.confidence),
            detail: Some(format!(
                "via {}",
                format::source(primary.source).to_lowercase()
            )),
        },
    ];
    if !payload.extensions.is_empty() {
        fields.push(BandField {
            label: "extensions",
            value: payload.extensions.len().to_string(),
            detail: None,
        });
    }
    BandText {
        title,
        sub,
        is_error: false,
        fields,
    }
}

fn status_color(status: Status) -> gpui::Rgba {
    match status {
        Status::Queued => theme::TEXT_DISABLED,
        Status::Analyzing => theme::ACCENT,
        Status::Done => theme::SIGNAL_OK,
        Status::Failed => theme::SIGNAL_ERROR,
    }
}

fn label(text: &str) -> Div {
    small()
        .text_color(theme::TEXT_MUTED)
        .child(text.to_uppercase())
}

/// The band on the classification tab: a hero block and one block per
/// field.
fn full_band(text: BandText) -> Div {
    let hero = div()
        .flex_grow(1.0)
        .flex_shrink(1.0)
        .flex_basis(rems(17.5))
        .min_w_0()
        .px(rems(1.0))
        .py(rems(0.75))
        .border_r_1()
        .border_color(theme::LINE_HAIRLINE)
        .child(label("instruction set architecture"))
        .child(
            div()
                .font_family(theme::FONT_DISPLAY)
                .font_weight(FontWeight::MEDIUM)
                .text_size(rems(1.75))
                .line_height(relative(1.3))
                .when(text.is_error, |title| title.text_color(theme::SIGNAL_ERROR))
                .child(text.title),
        )
        .child(div().text_color(theme::TEXT_SECONDARY).child(text.sub));
    let fields = text.fields.into_iter().map(|field| {
        div()
            .flex_grow(1.0)
            .flex_shrink(1.0)
            .flex_basis(rems(7.8125))
            .min_w_0()
            .px(rems(1.0))
            .py(rems(0.75))
            .border_r_1()
            .border_color(theme::LINE_HAIRLINE)
            .child(label(field.label))
            .child(div().text_size(rems(1.0)).child(field.value))
            .when_some(field.detail, |block, detail| {
                block.child(small().text_color(theme::TEXT_MUTED).child(detail))
            })
    });
    div()
        .flex()
        .flex_none()
        .flex_wrap()
        .items_stretch()
        .bg(theme::SURFACE_PANEL)
        .border_b_1()
        .border_color(theme::LINE_DEFAULT)
        .child(hero)
        .children(fields)
}

/// The band on every other tab: one baseline-aligned row.
fn compact_band(text: BandText) -> Div {
    let hero = div()
        .flex()
        .items_baseline()
        .gap(rems(0.625))
        .pr(rems(0.875))
        .child(
            div()
                .font_family(theme::FONT_DISPLAY)
                .font_weight(FontWeight::MEDIUM)
                .text_size(rems(0.9375))
                .when(text.is_error, |title| title.text_color(theme::SIGNAL_ERROR))
                .child(text.title),
        )
        .child(
            div()
                .text_size(rems(0.75))
                .text_color(theme::TEXT_SECONDARY)
                .child(text.sub),
        );
    let fields = text.fields.into_iter().map(|field| {
        div()
            .flex()
            .items_baseline()
            .gap(rems(0.3125))
            .px(rems(0.625))
            .border_l_1()
            .border_color(theme::LINE_HAIRLINE)
            .child(div().text_size(rems(0.75)).child(field.value))
            .when_some(field.detail, |block, detail| {
                block.child(small().text_color(theme::TEXT_MUTED).child(detail))
            })
    });
    div()
        .flex()
        .flex_none()
        .flex_wrap()
        .items_baseline()
        .px(rems(0.75))
        .py(rems(0.5))
        .bg(theme::SURFACE_PANEL)
        .border_b_1()
        .border_color(theme::LINE_DEFAULT)
        .whitespace_nowrap()
        .overflow_hidden()
        .child(hero)
        .children(fields)
}

impl Workbench {
    pub(super) fn render_file_view(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let session = self.session.read(cx);
        let Some(entry) = session.selected() else {
            return div();
        };

        let header = bar()
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .font_family(theme::FONT_DISPLAY)
                    .font_weight(FontWeight::MEDIUM)
                    .child(entry.name.clone()),
            )
            .child(
                small()
                    .flex_none()
                    .text_color(theme::TEXT_MUTED)
                    .child(format::size(entry.size)),
            )
            .child(badge(entry.status.label(), status_color(entry.status)))
            .child(spacer())
            .child(key_cap("1–6"))
            .child(small().text_color(theme::TEXT_MUTED).child("tabs"))
            .child(
                icon_button(
                    "remove-file",
                    icon::REMOVE,
                    "Remove file",
                    IconSize::Small,
                    false,
                )
                .on_click(|_, window, cx| window.dispatch_action(Box::new(RemoveFile), cx)),
            );

        let ancestors = session.ancestors(entry.id);
        let breadcrumb = (!ancestors.is_empty()).then(|| {
            let session_entity = self.session.clone();
            let mut trail = small()
                .flex()
                .flex_none()
                .flex_wrap()
                .items_center()
                .gap(rems(0.25))
                .px(rems(0.75))
                .py(rems(0.25))
                .border_b_1()
                .border_color(theme::LINE_HAIRLINE)
                .text_color(theme::TEXT_MUTED);
            for ancestor in ancestors {
                let id = ancestor.id;
                let session_entity = session_entity.clone();
                trail = trail
                    .child(
                        text_button(("breadcrumb", id.0), ancestor.name.clone())
                            .text_color(theme::ACCENT)
                            .on_click(move |_, _, cx| {
                                session_entity.update(cx, |session, cx| session.select(id, cx));
                            }),
                    )
                    .child("/");
            }
            trail.child(
                div()
                    .px(rems(0.5))
                    .text_color(theme::TEXT_PRIMARY)
                    .child(entry.name.clone()),
            )
        });

        // The band looks the same on every tab. Its right edge is a
        // control that collapses it to one line and expands it again.
        let text = band_text(entry);
        let is_collapsed = self.is_header_collapsed;
        let (toggle_icon, toggle_label) = if is_collapsed {
            (icon::EXPAND, "Expand header")
        } else {
            (icon::COLLAPSE, "Collapse header")
        };
        let toggle = div()
            .id("toggle-header")
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .w(rems(2.25))
            .bg(theme::SURFACE_PANEL)
            .border_l_1()
            .border_b_1()
            .border_color(theme::LINE_DEFAULT)
            .cursor_pointer()
            .hover(|style| style.bg(theme::SURFACE_HOVER))
            .on_click(|_, window, cx| window.dispatch_action(Box::new(ToggleHeader), cx))
            .tooltip(widgets::text_tooltip(toggle_label))
            .child(
                svg()
                    .path(toggle_icon)
                    .size(rems(1.0))
                    .text_color(theme::TEXT_SECONDARY),
            );
        let band = div()
            .flex()
            .flex_none()
            .child(
                if is_collapsed {
                    compact_band(text)
                } else {
                    full_band(text)
                }
                .flex_1()
                .min_w_0(),
            )
            .child(toggle);

        let active_tab = self.tab;
        let tabs = div()
            .flex()
            .flex_none()
            .min_w_0()
            .border_b_1()
            .border_color(theme::LINE_DEFAULT)
            .children(Tab::ALL.into_iter().map(|tab| {
                let is_active = tab == active_tab;
                div()
                    .id(SharedString::from(format!("tab-{}", tab.label())))
                    .px(rems(0.75))
                    .py(rems(0.5))
                    .border_b_2()
                    .whitespace_nowrap()
                    .cursor_pointer()
                    .map(|button| {
                        if is_active {
                            button.border_color(theme::ACCENT).text_color(theme::ACCENT)
                        } else {
                            button
                                .border_color(gpui::transparent_black())
                                .text_color(theme::TEXT_MUTED)
                                .hover(|style| {
                                    style
                                        .bg(theme::SURFACE_HOVER)
                                        .text_color(theme::TEXT_PRIMARY)
                                })
                        }
                    })
                    .on_click(cx.listener(move |this, _, _, cx| this.show_tab(tab, cx)))
                    .child(tab.label())
            }));

        let panel = match self.tab {
            Tab::Classification => self.render_classification(cx).into_any_element(),
            Tab::Entropy => self.entropy_view.clone().into_any_element(),
            Tab::Hex => self.hex_view.clone().into_any_element(),
            Tab::Json => self.render_json(cx).into_any_element(),
            other => div()
                .p(rems(1.5))
                .text_color(theme::TEXT_MUTED)
                .child(format!("The {} view is not built yet.", other.label()))
                .into_any_element(),
        };

        let offer = self.render_donation_offer(cx);
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .child(header)
            .children(breadcrumb)
            .child(band)
            .children(offer)
            .child(tabs)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(panel),
            )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analysis::{self, Request};
    use crate::model::entry::{EntryId, Origin, Source};

    fn analyzed(bytes: &[u8]) -> Entry {
        let source = Source::Memory(Arc::from(bytes));
        let analysis = analysis::run(&Request {
            source: source.clone(),
            opaque: false,
        })
        .unwrap();
        let status = if analysis.error.is_none() {
            Status::Done
        } else {
            Status::Failed
        };
        Entry {
            id: EntryId(1),
            name: "fixture".into(),
            source,
            size: bytes.len() as u64,
            status,
            analysis: Some(analysis),
            error: None,
            parent: None,
            origin: Origin::Added,
            depth: 0,
            opaque: false,
            cursor: 0,
        }
    }

    /// A minimal little-endian ELF64 header for `e_machine` 183 (64-bit
    /// ARM): `e_ident`, `e_type` (`ET_EXEC`), `e_machine`, `e_version` and
    /// `e_ehsize`.
    fn elf_header() -> Vec<u8> {
        let mut header = vec![0u8; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2; // EI_CLASS: ELFCLASS64
        header[5] = 1; // EI_DATA: little-endian
        header[6] = 1; // EI_VERSION
        header[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type
        header[18..20].copy_from_slice(&183u16.to_le_bytes()); // e_machine
        header[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        header
    }

    #[test]
    fn a_classified_file_shows_its_tag_names_and_fields() {
        let text = band_text(&analyzed(&elf_header()));
        assert_eq!(text.title, "aarch64");
        assert_eq!(text.sub, "AArch64");
        assert!(!text.is_error);
        let labels: Vec<&str> = text.fields.iter().map(|field| field.label).collect();
        assert_eq!(
            labels[..4],
            ["bitwidth", "endianness", "format", "confidence"]
        );
        assert_eq!(text.fields[0].value, "64-bit");
        assert_eq!(text.fields[1].value, "little-endian");
        assert_eq!(text.fields[2].value, "elf");
        assert_eq!(text.fields[3].detail.as_deref(), Some("via file format"));
    }

    #[test]
    fn an_unclassified_file_shows_the_reason_and_its_size() {
        let text = band_text(&analyzed(&[0u8; 4096]));
        assert_eq!(text.title, "unclassified");
        assert!(text.is_error);
        assert_ne!(text.sub, "");
        assert_eq!(text.fields[0].label, "size");
        assert_eq!(text.fields[0].value, "4.0 KiB");
        assert_eq!(text.fields[1].label, "analyzed in");
    }
}
