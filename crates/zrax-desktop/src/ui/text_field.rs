//! A one-line text field for short ASCII input: a donor name, an offset.
//!
//! gpui provides the plumbing for text input but no widget. The fields of
//! this application take a few characters from a restricted alphabet, so
//! this field handles typed characters, backspace and paste itself and
//! keeps the caret at the end. It does not support input methods.

use gpui::{
    div, prelude::*, rems, App, Context, EventEmitter, FocusHandle, Focusable, KeyDownEvent,
    SharedString, Window,
};

use crate::theme;

/// Key context of a focused field. The workbench's single-letter shortcuts
/// exclude it, so typing a name does not switch tabs.
pub const KEY_CONTEXT: &str = "TextField";

/// What a field reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFieldEvent {
    /// The text changed.
    Changed,
    /// Enter was pressed.
    Submitted,
    /// Escape was pressed.
    Cancelled,
}

/// Append the characters of `input` that `accepts` allows to `text`, until
/// it holds `max_chars` characters. Returns whether `text` changed.
fn append_accepted(
    text: &mut String,
    input: &str,
    max_chars: usize,
    accepts: fn(char) -> bool,
) -> bool {
    let before = text.len();
    let remaining = max_chars.saturating_sub(text.chars().count());
    text.extend(input.chars().filter(|c| accepts(*c)).take(remaining));
    text.len() != before
}

/// A one-line text field.
pub struct TextField {
    focus: FocusHandle,
    text: String,
    placeholder: SharedString,
    /// Longest text accepted, in characters.
    max_chars: usize,
    /// Which characters may be typed or pasted.
    accepts: fn(char) -> bool,
}

impl EventEmitter<TextFieldEvent> for TextField {}

impl Focusable for TextField {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl TextField {
    /// A field holding `text`, taking up to `max_chars` characters that
    /// `accepts` allows.
    pub fn new(
        text: impl Into<String>,
        placeholder: impl Into<SharedString>,
        max_chars: usize,
        accepts: fn(char) -> bool,
        cx: &mut Context<Self>,
    ) -> Self {
        Self {
            focus: cx.focus_handle(),
            text: text.into(),
            placeholder: placeholder.into(),
            max_chars,
            accepts,
        }
    }

    /// The current text.
    pub fn text(&self) -> &str {
        &self.text
    }

    fn insert(&mut self, input: &str) -> bool {
        append_accepted(&mut self.text, input, self.max_chars, self.accepts)
    }

    fn on_key_down(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        let has_command = keystroke.modifiers.platform || keystroke.modifiers.control;
        let changed = match keystroke.key.as_str() {
            "enter" => {
                cx.emit(TextFieldEvent::Submitted);
                false
            }
            "escape" => {
                cx.emit(TextFieldEvent::Cancelled);
                false
            }
            "backspace" => self.text.pop().is_some(),
            "v" if has_command => {
                let pasted = cx.read_from_clipboard().and_then(|item| item.text());
                pasted.is_some_and(|text| self.insert(&text))
            }
            _ if has_command => return,
            _ => keystroke
                .key_char
                .as_deref()
                .is_some_and(|typed| self.insert(typed)),
        };
        // The key belongs to the field either way.
        cx.stop_propagation();
        if changed {
            cx.emit(TextFieldEvent::Changed);
            cx.notify();
        }
    }
}

impl Render for TextField {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let is_focused = self.focus.is_focused(window);
        let focus = self.focus.clone();
        let content = if self.text.is_empty() && !is_focused {
            div()
                .text_color(theme::TEXT_DISABLED)
                .child(self.placeholder.clone())
        } else {
            div().child(self.text.clone())
        };
        div()
            .id("text-field")
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .flex()
            .items_center()
            .min_w(rems(8.0))
            .px(rems(0.375))
            .py(rems(0.1875))
            .bg(theme::SURFACE_INSET)
            .border_1()
            .border_color(if is_focused {
                theme::ACCENT
            } else {
                theme::LINE_DEFAULT
            })
            .cursor_text()
            .on_click(move |_, window, cx| window.focus(&focus, cx))
            .on_key_down(cx.listener(Self::on_key_down))
            .child(content)
            .when(is_focused, |field| {
                // The caret: always at the end of the text.
                field.child(div().w(rems(0.4)).h(rems(1.0)).bg(theme::ACCENT))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_name_character(character: char) -> bool {
        character.is_ascii_alphanumeric() || character == '_'
    }

    #[test]
    fn typed_and_pasted_text_is_filtered_and_bounded() {
        let mut text = String::from("ab");
        assert!(append_accepted(
            &mut text,
            "c d\n_é!e",
            6,
            is_name_character
        ));
        assert_eq!(text, "abcd_e");
        assert!(!append_accepted(&mut text, "more", 6, is_name_character));
        assert!(!append_accepted(&mut text, " !", 99, is_name_character));
        assert_eq!(text, "abcd_e");
    }
}
