//! Per-file DER and PEM inspection using `zrax::certificates` (RFC 5280
//! and RFC 7468) and the stored regions of the workbench engine.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gpui::{
    div, prelude::*, relative, rems, uniform_list, ClipboardItem, Context, Div, Entity,
    ScrollStrategy, Subscription, UniformListScrollHandle, Window,
};
use zrax::certificates::{self, Certificate, Encoding};

use super::inspection_scan::{self, Report, Scan};
use super::widgets::{bar, key_value_row, small, spacer, text_button};
use super::ShowHexAtCursor;
use crate::model::entry::{Entry, EntryId, Origin};
use crate::model::session::{Session, SessionEvent};
use crate::{format, theme};

const REPORT_WINDOW_BYTES: usize = 1 << 20;
const DER_BUDGET_BYTES: usize = 16 << 20;

fn scan_certificates(data: &[u8], cancelled: &AtomicBool) -> certificates::Report {
    let mut scan = certificates::Scan::with_der_budget(DER_BUDGET_BYTES);
    for offset in (0..data.len()).step_by(REPORT_WINDOW_BYTES) {
        if scan.is_truncated() || cancelled.load(Ordering::Relaxed) {
            break;
        }
        let end = data
            .len()
            .min(offset + REPORT_WINDOW_BYTES + certificates::WINDOW_OVERLAP);
        scan.push_window(&data[offset..end], offset as u64, REPORT_WINDOW_BYTES);
    }
    if cancelled.load(Ordering::Relaxed) {
        return certificates::Report::default();
    }
    scan.finish()
}

#[derive(Clone, Copy)]
enum Export {
    Der,
    Pem,
    Report,
}

impl Export {
    fn suffix(self) -> &'static str {
        match self {
            Self::Der => "der",
            Self::Pem => "pem",
            Self::Report => "certificates.json",
        }
    }
}

pub(super) struct CertificatesView {
    session: Entity<Session>,
    scan: Scan<certificates::Report>,
    selected: usize,
    scroll: UniformListScrollHandle,
    _subscriptions: [Subscription; 2],
}

impl CertificatesView {
    pub(super) fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let subscriptions = [
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe(&session, |view, _, event: &SessionEvent, cx| {
                if *event == SessionEvent::SelectionChanged {
                    view.scan = Scan::Idle;
                    view.selected = 0;
                    view.scroll = UniformListScrollHandle::new();
                    cx.notify();
                }
            }),
        ];
        Self {
            session,
            scan: Scan::Idle,
            selected: 0,
            scroll: UniformListScrollHandle::new(),
            _subscriptions: subscriptions,
        }
    }

    fn select(&mut self, index: usize, cx: &mut Context<Self>) {
        self.selected = index;
        self.scroll.scroll_to_item(index, ScrollStrategy::Nearest);
        cx.notify();
    }

    fn export(
        &self,
        entry: &Entry,
        report: Arc<Report<certificates::Report>>,
        format: Export,
        cx: &Context<Self>,
    ) {
        let index = self.selected;
        let name = match format {
            Export::Report => format!("{}.{}", entry.name, format.suffix()),
            _ => format!("{}.cert-{}.{}", entry.name, index + 1, format.suffix()),
        };
        inspection_scan::export(
            &self.session,
            entry.path(),
            &name,
            move |file| {
                let cert = &report.data.certificates[index];
                match format {
                    Export::Der => file.write_all(&cert.der),
                    Export::Pem => file.write_all(cert.pem.as_bytes()),
                    Export::Report => serde_json::to_writer_pretty(file, &report.data)
                        .map_err(std::io::Error::other),
                }
            },
            cx,
        );
    }

    fn render_list(
        &self,
        report: Arc<Report<certificates::Report>>,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let selected = self.selected;
        let view = cx.entity().downgrade();
        uniform_list(
            "certificate-rows",
            report.data.certificates.len(),
            move |range, _, _| {
                range
                    .map(|index| {
                        let cert = &report.data.certificates[index];
                        let view = view.clone();
                        small()
                            .id(("certificate", index))
                            .flex()
                            .items_center()
                            .w_full()
                            .h(rems(1.7))
                            .gap(rems(0.45))
                            .px(rems(0.6))
                            .border_b_1()
                            .border_color(theme::LINE_HAIRLINE)
                            .cursor_pointer()
                            .when(index == selected, |row| row.bg(theme::SURFACE_SELECTED))
                            .hover(|style| style.bg(theme::SURFACE_HOVER))
                            .child(
                                div()
                                    .flex_none()
                                    .text_color(theme::ACCENT)
                                    .child(format::offset(cert.offset)),
                            )
                            .child(
                                div()
                                    .flex_none()
                                    .text_color(theme::TEXT_MUTED)
                                    .child(encoding(cert.encoding)),
                            )
                            .child(div().min_w_0().truncate().child(subject(cert).to_owned()))
                            .on_click(move |_, _, cx| {
                                let _ = view.update(cx, |view, cx| view.select(index, cx));
                            })
                    })
                    .collect()
            },
        )
        .track_scroll(&self.scroll)
        .flex_1()
        .min_h_0()
        .min_w_0()
    }

    fn render_details(
        &self,
        session_entry: EntryId,
        report: &Arc<Report<certificates::Report>>,
        cert: &Certificate,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let offset = cert.offset;
        let session = self.session.clone();
        let source_report = report.clone();
        let index = cert.index;
        let origin = Origin::Certificate(offset);
        let name = format!("certificate-{offset:X}.der");
        let source_session = session.clone();
        let nav = bar()
            .flex_wrap()
            .whitespace_normal()
            .child(
                text_button("certificate-hex", "show in hex").on_click(move |_, window, cx| {
                    inspection_scan::show_hex(&source_session, session_entry, offset, window, cx);
                }),
            )
            .child(
                text_button("certificate-open", "open DER").on_click(move |_, window, cx| {
                    let opened = session.update(cx, |session, cx| {
                        if let Some(id) =
                            session.derived(session_entry, origin).map(|entry| entry.id)
                        {
                            session.select(id, cx);
                            return Some(id);
                        }
                        session.add_derived(
                            session_entry,
                            origin,
                            name.clone(),
                            Arc::from(source_report.data.certificates[index].der.as_slice()),
                            true,
                            cx,
                        )
                    });
                    if opened.is_some() {
                        window.dispatch_action(Box::new(ShowHexAtCursor), cx);
                    }
                }),
            )
            .when_some(cert.issuer_index, |nav, issuer| {
                nav.child(
                    text_button("certificate-issuer", "go to issuer")
                        .on_click(cx.listener(move |view, _, _, cx| view.select(issuer, cx))),
                )
            })
            .when_some(cert.duplicate_of, |nav, first| {
                nav.child(
                    text_button("certificate-first", "go to first copy")
                        .on_click(cx.listener(move |view, _, _, cx| view.select(first, cx))),
                )
            });
        let mut details = small()
            .flex()
            .flex_col()
            .px(rems(0.75))
            .child(value(
                "location",
                format!(
                    "{} · {} · {}",
                    format::offset(offset),
                    format::size(cert.stored_size),
                    encoding(cert.encoding)
                ),
            ))
            .child(value(
                "enclosing region",
                inspection_scan::region(&report.regions, offset, cert.stored_size).unwrap_or("—"),
            ))
            .child(value("DER size", format::size(cert.der_size as u64)))
            .child(value("SHA-256", &cert.sha256))
            .when(cert.self_issued, |details| {
                details.child(value("issuer link", "Self-issued"))
            })
            .when_some(cert.error.as_deref(), |details, error| {
                details.child(value("decode error", error))
            });
        if let Some(summary) = &cert.summary {
            let key = summary.public_key_bits.map_or_else(
                || summary.public_key_algorithm.clone(),
                |bits| format!("{} · {bits} bits", summary.public_key_algorithm),
            );
            details = details
                .child(value("subject", &summary.subject))
                .child(value("issuer", &summary.issuer))
                .child(value("valid from", &summary.not_before))
                .child(value("valid until", &summary.not_after))
                .child(value("version", summary.version.to_string()))
                .child(value("serial", &summary.serial))
                .child(value(
                    "public key",
                    format!("{key} · {}", summary.public_key_oid),
                ))
                .when_some(summary.curve.as_deref(), |details, curve| {
                    details.child(value("curve", curve))
                })
                .child(value(
                    "signature",
                    format!(
                        "{} · {}",
                        summary.signature_algorithm, summary.signature_oid
                    ),
                ))
                .when_some(summary.is_ca, |details, is_ca| {
                    details.child(value("CA", is_ca.to_string()))
                })
                .when_some(summary.path_len, |details, path_len| {
                    details.child(value("path length", path_len.to_string()))
                })
                .when_some(summary.subject_key_id.as_deref(), |details, id| {
                    details.child(value("subject key ID", id))
                })
                .when_some(summary.authority_key_id.as_deref(), |details, id| {
                    details.child(value("authority key ID", id))
                })
                .when(!summary.key_usage.is_empty(), |details| {
                    details.child(value("key usage", summary.key_usage.join(", ")))
                })
                .when(!summary.extended_key_usage.is_empty(), |details| {
                    details.child(value(
                        "extended usage",
                        summary.extended_key_usage.join(", "),
                    ))
                })
                .children(
                    summary
                        .subject_alt_names
                        .iter()
                        .map(|name| value("alternate name", name)),
                )
                .children(summary.extensions.iter().map(|extension| {
                    let critical = if extension.critical {
                        " · critical"
                    } else {
                        ""
                    };
                    value(
                        "extension",
                        format!("{} · {}{critical}", extension.name, extension.oid),
                    )
                }));
        }
        div()
            .flex()
            .flex_col()
            .min_h_0()
            .min_w_0()
            .flex_1()
            .child(nav)
            .child(
                div()
                    .id(("certificate-detail", cert.index))
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .overflow_x_scroll()
                    .child(details),
            )
    }
}

impl Render for CertificatesView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(entry) = self.session.read(cx).selected() else {
            return inspection_scan::message("Select a file").into_any_element();
        };
        if self.scan.is_idle() {
            if let Some(analysis) = &entry.analysis {
                self.scan = Scan::start(
                    analysis.engine.clone(),
                    scan_certificates,
                    |view| &mut view.scan,
                    cx,
                );
            }
        }
        let Scan::Ready(Ok(report)) = &self.scan else {
            return inspection_scan::message(
                self.scan
                    .message(entry, "Scanning for X.509 certificates…")
                    .to_owned(),
            )
            .into_any_element();
        };
        let Some(cert) = report.data.certificates.get(self.selected) else {
            return inspection_scan::message("No DER or PEM certificates found").into_any_element();
        };
        let report = report.clone();
        let title = format!("{} certificates", report.data.certificates.len());
        let mut toolbar = bar()
            .flex_wrap()
            .whitespace_normal()
            .child(title)
            .child(spacer());
        for (label, export) in [
            ("save DER", Export::Der),
            ("save PEM", Export::Pem),
            ("save JSON", Export::Report),
        ] {
            let report = report.clone();
            toolbar = toolbar.child(text_button(label, label).on_click(cx.listener(
                move |view, _, _, cx| {
                    if let Some(entry) = view.session.read(cx).selected() {
                        view.export(entry, report.clone(), export, cx);
                    }
                },
            )));
        }
        let selected = cert.index;
        let pem_report = report.clone();
        toolbar = toolbar.child(
            text_button("copy-pem", "copy PEM").on_click(move |_, _, cx| {
                let pem = &pem_report.data.certificates[selected].pem;
                cx.write_to_clipboard(ClipboardItem::new_string(pem.clone()));
            }),
        );
        let is_narrow = window.viewport_size().width < window.rem_size() * 54.0;
        let list = div()
            .flex()
            .flex_col()
            .min_h_0()
            .min_w_0()
            .border_color(theme::LINE_DEFAULT)
            .map(|list| {
                if is_narrow {
                    list.h(relative(0.32)).border_b_1()
                } else {
                    list.w(relative(0.42)).border_r_1()
                }
            })
            .child(self.render_list(report.clone(), cx));
        let details = self.render_details(entry.id, &report, cert, cx);
        div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .child(toolbar)
            .child(
                small()
                    .px(rems(0.75))
                    .py(rems(0.3))
                    .text_color(theme::TEXT_MUTED)
                    .child(report.data.notes.join(" · ")),
            )
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .when(is_narrow, gpui::Styled::flex_col)
                    .child(list)
                    .child(details),
            )
            .into_any_element()
    }
}

fn value(label: &'static str, value: impl Into<String>) -> Div {
    key_value_row(label, div().child(value.into()))
}

fn encoding(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Der => "DER",
        Encoding::Pem => "PEM",
    }
}

fn subject(cert: &Certificate) -> &str {
    cert.summary
        .as_ref()
        .map_or("Malformed certificate", |summary| {
            summary.subject_cn.as_deref().unwrap_or(&summary.subject)
        })
}
