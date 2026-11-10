//! Design tokens of the workbench.
//!
//! Source: the custom properties at the top of `web/workbench.css`. The
//! browser ships one theme (dark); so does the desktop. Colors are named by
//! role, as there; the raw ink, paper and magenta steps stay private.

use gpui::Rgba;

/// Pixels per `rem`. The browser workbench sets the root font size to 125 %
/// of 16 px, and every size in its stylesheet is in `rem`.
pub const REM_PIXELS: f32 = 20.0;

/// Body font.
pub const FONT_MONO: &str = "DM Mono";
/// Display font: brand, file name, hero ISA, large numbers.
pub const FONT_DISPLAY: &str = "Martian Mono";

/// Body text size in `rem`.
pub const TEXT_BODY_REMS: f32 = 0.8125;
/// Small text size in `rem`: labels, hints, table headers.
pub const TEXT_SMALL_REMS: f32 = 0.6875;
/// Body line height as a multiple of the font size.
pub const LINE_HEIGHT: f32 = 1.5;

/// An opaque color from `0xRRGGBB`.
// Each channel is masked to 8 bits before the conversion, so it is exact.
#[allow(clippy::cast_precision_loss)]
const fn rgb(hex: u32) -> Rgba {
    Rgba {
        r: ((hex >> 16) & 0xFF) as f32 / 255.0,
        g: ((hex >> 8) & 0xFF) as f32 / 255.0,
        b: (hex & 0xFF) as f32 / 255.0,
        a: 1.0,
    }
}

const VOID: Rgba = rgb(0x08_0706);
const INK_900: Rgba = rgb(0x12_100e);
const INK_800: Rgba = rgb(0x1a_1714);
const INK_600: Rgba = rgb(0x2e_2823);
const INK_500: Rgba = rgb(0x3d_352e);
const INK_400: Rgba = rgb(0x4d_443c);
const INK_300: Rgba = rgb(0x6b_6058);
const PAPER_000: Rgba = rgb(0xff_ffff);
const PAPER_100: Rgba = rgb(0xf5_efe8);
const PAPER_300: Rgba = rgb(0xb8_ada1);
const PAPER_400: Rgba = rgb(0x8c_8177);
const PAPER_500: Rgba = rgb(0x6b_6058);
const MAGENTA_500: Rgba = rgb(0xff_3d8b);
const MAGENTA_900: Rgba = rgb(0x3d_0f24);

/// Window background.
pub const SURFACE_PAGE: Rgba = INK_900;
/// Bands and panels raised above the page.
pub const SURFACE_PANEL: Rgba = INK_800;
/// Wells: the rail, the hex grid, canvases.
pub const SURFACE_INSET: Rgba = VOID;
/// Hovered controls.
pub const SURFACE_HOVER: Rgba = INK_600;
/// The selected file and other selected rows.
pub const SURFACE_SELECTED: Rgba = MAGENTA_900;

/// Primary text.
pub const TEXT_PRIMARY: Rgba = PAPER_100;
/// Secondary text: values that are not the focus.
pub const TEXT_SECONDARY: Rgba = PAPER_300;
/// Labels and hints.
pub const TEXT_MUTED: Rgba = PAPER_400;
/// Disabled text and queued states.
pub const TEXT_DISABLED: Rgba = INK_300;
/// Text on an accent background.
pub const TEXT_INVERSE: Rgba = VOID;

/// Dividers inside a panel.
pub const LINE_HAIRLINE: Rgba = INK_600;
/// Panel and region borders.
pub const LINE_DEFAULT: Rgba = INK_500;

/// The accent: selection, active tabs, links, the cursor.
pub const ACCENT: Rgba = MAGENTA_500;
/// A faint accent fill: active segments, selections.
pub const ACCENT_WASH: Rgba = MAGENTA_900;

/// Done, verified, valid.
pub const SIGNAL_OK: Rgba = rgb(0x4a_de5e);
/// Failed, expired, rejected.
pub const SIGNAL_ERROR: Rgba = rgb(0xff_4d3d);
/// Hex byte classes (`web/workbench.css`, `.hex-byte.*`).
pub mod byte {
    use super::{Rgba, INK_400, PAPER_000, PAPER_100, PAPER_300, PAPER_500};

    /// `0x00`.
    pub const ZERO: Rgba = INK_400;
    /// Control bytes `0x01..=0x1F` and `0x7F`.
    pub const CONTROL: Rgba = PAPER_500;
    /// Printable ASCII.
    pub const ASCII: Rgba = PAPER_100;
    /// `0x80..=0xFE`.
    pub const HIGH: Rgba = PAPER_300;
    /// `0xFF`.
    pub const FULL: Rgba = PAPER_000;
}
