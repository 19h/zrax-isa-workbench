//! Donation in the interface: the offer shown for an analyzed file the
//! server would take, and the donations panel with the donor name, the
//! queue and the collection's most wanted architectures.

use gpui::{div, prelude::*, rems, AnyElement, Context, Div, SharedString};
use zrax_donate::api::Stats;

use super::widgets::{
    bar, key_value_row, meter, section, section_body, small, spacer, text_button,
};
use super::Workbench;
use crate::donate::{Connection, Donation, Donations, OfferState, DISCLOSURE};
use crate::model::entry::EntryId;
use crate::{format, theme};

/// Images of an ISA below which the collection asks for more.
const WANTED_BELOW_IMAGES: u64 = 5;
/// ISAs listed once every one has that many.
const FEWEST_LISTED: usize = 10;

/// The raw-code ISAs the collection has fewest images of: those below
/// [`WANTED_BELOW_IMAGES`], or else the [`FEWEST_LISTED`] with the fewest
/// (more on a tie), as the donation page lists them.
fn most_wanted(stats: &Stats) -> Vec<(String, u64)> {
    let mut raw: Vec<(String, u64)> = stats
        .isas
        .iter()
        .filter(|isa| isa.raw)
        .map(|isa| (isa.name.clone(), isa.files))
        .collect();
    raw.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let scarce = raw
        .iter()
        .take_while(|(_, files)| *files < WANTED_BELOW_IMAGES)
        .count();
    if scarce > 0 {
        raw.truncate(scarce);
        return raw;
    }
    let Some(cutoff) = raw.get(FEWEST_LISTED - 1).map(|(_, files)| *files) else {
        return raw;
    };
    raw.retain(|(_, files)| *files <= cutoff);
    raw
}

fn outlined_button(
    id: impl Into<gpui::ElementId>,
    label: impl Into<SharedString>,
) -> gpui::Stateful<Div> {
    text_button(id, label)
        .border_1()
        .border_color(theme::LINE_DEFAULT)
}

fn donation_row(donation: &Donation, on_cancel: impl Fn(&mut gpui::App) + 'static) -> Div {
    let is_running = donation.outcome.is_none();
    let entry = donation.entry;
    div()
        .flex()
        .flex_col()
        .gap(rems(0.25))
        .px(rems(1.0))
        .py(rems(0.5))
        .border_b_1()
        .border_color(theme::LINE_HAIRLINE)
        .child(
            div()
                .flex()
                .items_center()
                .gap(rems(0.75))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .child(donation.name.clone()),
                )
                .child(
                    small()
                        .flex_none()
                        .text_color(theme::TEXT_MUTED)
                        .child(format::size(donation.size)),
                )
                .when(is_running, |row| {
                    row.child(
                        outlined_button(("cancel-donation", entry.0), "cancel")
                            .text_size(rems(theme::TEXT_SMALL_REMS))
                            .on_click(move |_, _, cx| on_cancel(cx)),
                    )
                }),
        )
        .child(
            small()
                .text_color(theme::TEXT_SECONDARY)
                .child(donation.status_text()),
        )
        .when_some(donation.progress(), |row, fraction| {
            row.child(meter(fraction))
        })
        .when_some(donation.notice.clone(), |row, notice| {
            row.child(small().text_color(theme::TEXT_MUTED).child(notice))
        })
}

impl Workbench {
    /// The offer for the selected entry, when the server would take it.
    pub(super) fn render_donation_offer(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let (entry_id, state): (EntryId, OfferState) = {
            let session = self.session.read(cx);
            let entry = session.selected()?;
            (entry.id, self.donations.read(cx).offer_state(entry))
        };
        let note = match state {
            OfferState::Hidden => return None,
            OfferState::Note { text, can_retry } => Some((text, can_retry)),
            OfferState::Offer => None,
        };
        if let Some((note, can_retry)) = note {
            let donations = self.donations.clone();
            // No offer: say why in one line, and where the details are.
            let line = small()
                .flex()
                .flex_none()
                .items_center()
                .gap(rems(0.75))
                .px(rems(0.75))
                .py(rems(0.25))
                .border_b_1()
                .border_color(theme::LINE_HAIRLINE)
                .text_color(theme::TEXT_MUTED)
                .child(div().flex_1().min_w_0().truncate().child(note))
                .when(can_retry, |line| {
                    line.child(
                        text_button("offer-retry", "ask again")
                            .text_color(theme::ACCENT)
                            .on_click(move |_, _, cx| donations.update(cx, Donations::connect)),
                    )
                })
                .child(
                    text_button("offer-details", "donations")
                        .text_color(theme::ACCENT)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.is_donations_open = true;
                            cx.notify();
                        })),
                );
            return Some(line.into_any_element());
        }
        let donations = self.donations.clone();
        let session = self.session.clone();
        let donate = {
            let (donations, session) = (donations.clone(), session.clone());
            move |_: &gpui::ClickEvent, _: &mut gpui::Window, cx: &mut gpui::App| {
                let request = session
                    .read(cx)
                    .entry(entry_id)
                    .and_then(|entry| donations.read(cx).request_for(entry));
                if let Some(request) = request {
                    donations.update(cx, |donations, cx| donations.donate(request, cx));
                }
            }
        };
        let offer = div()
            .flex()
            .flex_none()
            .flex_wrap()
            .items_center()
            .gap(rems(0.75))
            .px(rems(0.75))
            .py(rems(0.5))
            .bg(theme::ACCENT_WASH)
            .border_b_1()
            .border_color(theme::LINE_DEFAULT)
            .child(
                div()
                    .flex_1()
                    .min_w(rems(20.0))
                    .child("donate this image to the zrax firmware collection?")
                    .child(small().text_color(theme::TEXT_SECONDARY).child(DISCLOSURE)),
            )
            .child(
                outlined_button("offer-donate", "donate")
                    .border_color(theme::ACCENT)
                    .text_color(theme::ACCENT)
                    .on_click(donate),
            )
            .child(
                outlined_button("offer-decline", "not this file").on_click(move |_, _, cx| {
                    donations.update(cx, |donations, cx| donations.decline(entry_id, cx));
                }),
            );
        Some(offer.into_any_element())
    }

    /// The donations panel, shown in place of the file view.
    pub(super) fn render_donations(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let donations_entity = self.donations.clone();
        let donations: &Donations = self.donations.read(cx);

        let (status, can_retry) = match donations.connection() {
            Connection::Unavailable(reason) => (format!("donation is off: {reason}"), false),
            Connection::Idle => ("the server has not been contacted yet".to_string(), true),
            Connection::Connecting => ("asking the server what it accepts…".to_string(), false),
            Connection::Ready(session) => {
                let policy = session.policy();
                let state = if policy.paused {
                    "donations are paused"
                } else {
                    "ready"
                };
                (
                    format!(
                        "{state} · files from {} to {} · classified with zrax {}",
                        format::size(policy.min_file_bytes),
                        format::size(policy.max_file_bytes),
                        session.zrax_label()
                    ),
                    false,
                )
            }
            Connection::Failed(reason) => (format!("not connected: {reason}"), true),
        };
        let donor_error = donations.donor_name().err().map(|error| error.to_string());

        let server = section(
            "donation server",
            None,
            section_body()
                .child(key_value_row("server", donations.server().to_string()))
                .child(key_value_row("this build", Donations::build_revision()))
                .child(key_value_row(
                    "status",
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(rems(0.75))
                        .child(status)
                        .when(can_retry, |row| {
                            row.child(outlined_button("donate-connect", "connect").on_click({
                                let donations = donations_entity.clone();
                                move |_, _, cx| donations.update(cx, Donations::connect)
                            }))
                        }),
                )),
        );

        let donor = section(
            "donor",
            None,
            section_body()
                .gap(rems(0.5))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(rems(0.75))
                        .child(div().text_color(theme::TEXT_MUTED).child("name"))
                        .child(self.donor_field.clone()),
                )
                .child(match donor_error {
                    Some(error) => small().text_color(theme::SIGNAL_ERROR).child(error),
                    None => small()
                        .text_color(theme::TEXT_MUTED)
                        .child("shown in the Telegram post; leave empty to donate as anonymous"),
                })
                .child(small().text_color(theme::TEXT_SECONDARY).child(DISCLOSURE)),
        );

        let rows: Vec<Div> = donations
            .donations()
            .iter()
            .rev()
            .map(|donation| {
                let (donations, entry) = (donations_entity.clone(), donation.entry);
                donation_row(donation, move |cx| {
                    donations.update(cx, |donations, _| donations.cancel(entry));
                })
            })
            .collect();
        let queue = section(
            "donations",
            Some(rows.len().to_string().into()),
            if rows.is_empty() {
                section_body().text_color(theme::TEXT_MUTED).child(
                    "nothing donated in this session; open an analyzed file to see whether the server would take it",
                )
            } else {
                div().flex().flex_col().children(rows)
            },
        );

        let wanted = donations.stats().map(|stats| {
            let rows = most_wanted(stats).into_iter().map(|(name, files)| {
                key_value_row(
                    name,
                    format!("{files} image{}", if files == 1 { "" } else { "s" }),
                )
            });
            section(
                "most wanted",
                Some(
                    format!(
                        "{} images · {}",
                        format::grouped(stats.files),
                        format::size(stats.bytes)
                    )
                    .into(),
                ),
                section_body().children(rows),
            )
        });

        div()
            .flex()
            .flex_col()
            .size_full()
            .child(
                bar()
                    .child(
                        div()
                            .font_family(theme::FONT_DISPLAY)
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .child("donate firmware"),
                    )
                    .child(spacer())
                    .child(
                        text_button("donations-close", "back to files")
                            .text_size(rems(theme::TEXT_SMALL_REMS))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.is_donations_open = false;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .id("donations-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(rems(1.5))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(rems(1.0))
                            .max_w(rems(70.0))
                            .child(server)
                            .child(donor)
                            .child(queue)
                            .children(wanted),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zrax_donate::api::IsaStats;

    fn stats(files: &[(&str, u64, bool)]) -> Stats {
        Stats {
            files: 0,
            bytes: 0,
            donors: 0,
            isas: files
                .iter()
                .map(|(name, files, raw)| IsaStats {
                    isa: name.to_lowercase(),
                    name: (*name).to_string(),
                    files: *files,
                    bytes: 0,
                    raw: *raw,
                })
                .collect(),
        }
    }

    #[test]
    fn scarce_raw_isas_are_wanted_first() {
        let wanted = most_wanted(&stats(&[
            ("ARM", 900, true),
            ("Z80", 0, true),
            ("AVR", 4, true),
            ("JVM", 0, false),
            ("MIPS", 5, true),
        ]));
        assert_eq!(wanted, [("Z80".to_string(), 0), ("AVR".to_string(), 4)]);
    }

    #[test]
    fn once_none_is_scarce_the_ten_fewest_are_listed_with_ties() {
        let names: Vec<String> = (0..13).map(|index| format!("ISA{index:02}")).collect();
        // Counts 5, 6, …, 13, then 14 three times, then 20.
        let counts = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14, 14, 20];
        let rows: Vec<(&str, u64, bool)> = names
            .iter()
            .zip(counts)
            .map(|(name, count)| (name.as_str(), count, true))
            .collect();
        let wanted = most_wanted(&stats(&rows));
        assert_eq!(wanted.len(), 12);
        assert_eq!(wanted.last().map(|(_, files)| *files), Some(14));
    }
}
