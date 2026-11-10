//! Color utility functions for visualization.
//!
//! Consolidates all color conversion and mapping functions used throughout
//! the application, eliminating duplication between modules.
//!
//! DESIGN SYSTEM: MIL-SPEC TECHNO-BRUTALISM
//! Classification: APEIRON-UI-SPEC // REV.03

use crate::compat::Color32;

// =============================================================================
// MIL-SPEC COLOR PALETTE
// =============================================================================

/// Void black - Primary background
pub const VOID_BLACK: Color32 = Color32::from_rgb(10, 10, 10); // #0A0A0A

/// Panel dark - Secondary panels, toolbars
pub const PANEL_DARK: Color32 = Color32::from_rgb(26, 26, 26); // #1A1A1A

/// Interface gray - Interactive elements, borders
pub const INTERFACE_GRAY: Color32 = Color32::from_rgb(45, 45, 45); // #2D2D2D

/// Data white - Primary text, critical data
pub const DATA_WHITE: Color32 = Color32::from_rgb(229, 229, 229); // #E5E5E5

/// Muted text - Secondary labels, inactive states
pub const MUTED_TEXT: Color32 = Color32::from_rgb(120, 120, 130); // Subdued

// =============================================================================
// TACTICAL ACCENT COLORS
// =============================================================================

/// Tactical cyan - PRIMARY ACCENT (data, surveillance, analysis)
pub const TACTICAL_CYAN: Color32 = Color32::from_rgb(0, 240, 255); // #00F0FF

/// Alert red - Critical warnings, malware detection
pub const ALERT_RED: Color32 = Color32::from_rgb(255, 51, 51); // #FF3333

/// Caution amber - Warnings, suspicious indicators
pub const CAUTION_AMBER: Color32 = Color32::from_rgb(255, 184, 0); // #FFB800

/// Operational green - Systems nominal, clean status
pub const OPERATIONAL_GREEN: Color32 = Color32::from_rgb(0, 255, 102); // #00FF66

/// Dim cyan - Muted accent for secondary elements
pub const DIM_CYAN: Color32 = Color32::from_rgb(0, 140, 160); // Subdued cyan

/// Convert HSV color to RGB Color32.
///
/// # Arguments
/// * `hue` - Hue in degrees (0-360)
/// * `saturation` - Saturation (0.0-1.0)
/// * `value` - Value/brightness (0.0-1.0)
///
/// # Returns
/// An egui Color32 value
pub fn hsv_to_color32(hue: f64, saturation: f64, value: f64) -> Color32 {
    let (r, g, b) = hsv_to_rgb_f32(hue as f32, saturation as f32, value as f32);
    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// Convert HSV to RGB as floating point values (0.0-1.0).
///
/// # Arguments
/// * `h` - Hue in degrees (0-360)
/// * `s` - Saturation (0.0-1.0)
/// * `v` - Value/brightness (0.0-1.0)
///
/// # Returns
/// A tuple of (r, g, b) values in the range 0.0-1.0
#[inline]
pub fn hsv_to_rgb_f32(h: f32, s: f32, v: f32) -> (f32, f32, f32) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (r + m, g + m, b + m)
}

/// Convert HSV to RGB as u8 tuple.
///
/// # Arguments
/// * `h` - Hue in degrees (0-360)
/// * `s` - Saturation (0.0-1.0)
/// * `v` - Value/brightness (0.0-1.0)
///
/// # Returns
/// A tuple of (r, g, b) values in the range 0-255
#[inline]
pub fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let (r, g, b) = hsv_to_rgb_f32(h, s, v);
    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// Map entropy value (0-8) to a MIL-SPEC tactical color.
///
/// Uses cyan-dominant colormap for tactical visualization:
/// - 0-2 (low): Dark/dim - structured/padding (void to dim cyan)
/// - 2-5 (medium): Cyan tones - code/data (tactical cyan)
/// - 5-7 (high): Amber transition - compressed (caution)
/// - 7-8 (very high): Alert red - encrypted/random (critical)
pub fn entropy_to_color32(entropy: f64) -> Color32 {
    let t = (entropy / 8.0).clamp(0.0, 1.0);

    // MIL-SPEC colormap: dark -> dim cyan -> tactical cyan -> amber -> alert red
    let (r, g, b) = if t < 0.25 {
        // Void to dim cyan (low entropy - structured)
        let s = t / 0.25;
        (0.0, s * 0.55, s * 0.63)
    } else if t < 0.5 {
        // Dim cyan to tactical cyan (medium-low - code/text)
        let s = (t - 0.25) / 0.25;
        (0.0, 0.55 + s * 0.39, 0.63 + s * 0.37)
    } else if t < 0.75 {
        // Tactical cyan to caution amber (medium-high - compressed)
        let s = (t - 0.5) / 0.25;
        (s * 1.0, 0.94 - s * 0.22, 1.0 - s * 1.0)
    } else {
        // Caution amber to alert red (very high - encrypted/random)
        let s = (t - 0.75) / 0.25;
        (1.0, 0.72 - s * 0.52, s * 0.2)
    };

    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// Convert entropy value to RGB color for Hilbert rendering (full precision).
///
/// MIL-SPEC tactical color mapping for progressive rendering.
pub fn entropy_to_rgb(entropy: f32) -> (u8, u8, u8) {
    let t = entropy.clamp(0.0, 1.0);

    // MIL-SPEC: dark -> cyan -> amber -> red
    if t < 0.33 {
        let s = t / 0.33;
        (0, (s * 200.0) as u8, (s * 220.0) as u8)
    } else if t < 0.66 {
        let s = (t - 0.33) / 0.33;
        (
            (s * 255.0) as u8,
            (200.0 + s * 40.0) as u8,
            (220.0 - s * 220.0) as u8,
        )
    } else {
        let s = (t - 0.66) / 0.34;
        (255, (240.0 - s * 190.0) as u8, (s * 51.0) as u8)
    }
}

/// Convert entropy value to RGB color (coarse/preview quality).
/// Slightly dimmer to indicate lower precision.
pub fn entropy_to_rgb_preview(entropy: f32) -> (u8, u8, u8) {
    let (r, g, b) = entropy_to_rgb(entropy);
    // Dim by 30% for preview
    (
        (r as f32 * 0.7) as u8,
        (g as f32 * 0.7) as u8,
        (b as f32 * 0.7) as u8,
    )
}

/// Generate an animated pulse color for uncomputed regions.
///
/// Creates a tactical cyan pulse effect for "scanning" indication.
pub fn placeholder_pulse_color(time_seconds: f64) -> (u8, u8, u8) {
    // Tactical pulse: 0.5 Hz oscillation
    let pulse = ((time_seconds * std::f64::consts::PI).sin() * 0.5 + 0.5) as f32;
    let base: f32 = 15.0;
    let range: f32 = 20.0;
    let v = (base + pulse * range) as u8;
    // Tactical cyan tint to indicate "scanning"
    (v / 4, v, (v as f32 * 1.1).min(255.0) as u8)
}

/// Map similarity value (0-1) to color for recurrence plots.
/// MIL-SPEC tactical scheme: void -> cyan gradient -> white
///
/// - 0 (dissimilar): Void black
/// - 0.5 (moderate): Dim cyan
/// - 1.0 (identical): Bright tactical cyan/white
/// - Diagonal elements get bright cyan highlighting
pub fn similarity_to_color32(similarity: f64, is_diagonal: bool) -> Color32 {
    // Apply gamma curve to enhance contrast in the mid-range
    let t = similarity.clamp(0.0, 1.0).powf(0.5);

    if is_diagonal {
        // Diagonal elements (self-comparison) - bright tactical cyan
        return TACTICAL_CYAN;
    }

    // MIL-SPEC: void black -> dim cyan -> tactical cyan -> bright white
    let (r, g, b) = if t < 0.3 {
        // Void to dim cyan
        let s = t / 0.3;
        (0.0, s * 0.35, s * 0.4)
    } else if t < 0.6 {
        // Dim cyan to tactical cyan
        let s = (t - 0.3) / 0.3;
        (0.0, 0.35 + s * 0.59, 0.4 + s * 0.6)
    } else if t < 0.85 {
        // Tactical cyan to bright cyan-white
        let s = (t - 0.6) / 0.25;
        (s * 0.5, 0.94, 1.0)
    } else {
        // Bright to white
        let s = (t - 0.85) / 0.15;
        (0.5 + s * 0.5, 0.94 + s * 0.06, 1.0)
    };

    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// Get color for a byte value based on its characteristics.
/// MIL-SPEC high-contrast scheme for hex view.
pub fn byte_color(byte: u8) -> Color32 {
    if byte == 0 {
        Color32::from_rgb(60, 70, 80) // Null - dim interface gray
    } else if (0x20..=0x7e).contains(&byte) {
        DATA_WHITE // Printable ASCII - data white
    } else if byte == 0xff {
        ALERT_RED // 0xFF - alert red
    } else if byte > 0x7f {
        CAUTION_AMBER // High bytes - caution amber
    } else {
        DIM_CYAN // Control chars - dim cyan
    }
}

/// Get color for entropy value in the inspector panel.
/// Uses MIL-SPEC status colors.
pub fn entropy_indicator_color(entropy: f64) -> Color32 {
    if entropy > 7.0 {
        ALERT_RED // Critical - encrypted/random
    } else if entropy > 5.0 {
        CAUTION_AMBER // Warning - compressed
    } else if entropy > 3.0 {
        TACTICAL_CYAN // Nominal - code/data
    } else {
        OPERATIONAL_GREEN // Clean - structured
    }
}

/// Get color for Kolmogorov complexity value (0-1).
/// MIL-SPEC tactical gradient: green -> cyan -> amber -> red
pub fn complexity_color(complexity: f64) -> Color32 {
    let t = complexity.clamp(0.0, 1.0);

    // MIL-SPEC: operational green -> dim cyan -> tactical cyan -> amber -> alert red
    let (r, g, b) = if t < 0.25 {
        // Operational green to dim cyan (simple/compressible)
        let s = t / 0.25;
        (0.0, 1.0 - s * 0.45, 0.4 + s * 0.23)
    } else if t < 0.5 {
        // Dim cyan to tactical cyan (moderate complexity)
        let s = (t - 0.25) / 0.25;
        (0.0, 0.55 + s * 0.39, 0.63 + s * 0.37)
    } else if t < 0.75 {
        // Tactical cyan to caution amber (complex)
        let s = (t - 0.5) / 0.25;
        (s * 1.0, 0.94 - s * 0.22, 1.0 - s * 1.0)
    } else {
        // Caution amber to alert red (random/encrypted)
        let s = (t - 0.75) / 0.25;
        (1.0, 0.72 - s * 0.52, s * 0.2)
    };

    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsv_to_rgb() {
        // Red
        let (r, g, b) = hsv_to_rgb(0.0, 1.0, 1.0);
        assert_eq!(r, 255);
        assert!(g < 5);
        assert!(b < 5);

        // Green
        let (r, g, b) = hsv_to_rgb(120.0, 1.0, 1.0);
        assert!(r < 5);
        assert_eq!(g, 255);
        assert!(b < 5);

        // Blue
        let (r, g, b) = hsv_to_rgb(240.0, 1.0, 1.0);
        assert!(r < 5);
        assert!(g < 5);
        assert_eq!(b, 255);
    }

    #[test]
    fn test_entropy_colors() {
        let low = entropy_to_rgb(0.0);
        let high = entropy_to_rgb(1.0);
        // MIL-SPEC color scheme:
        // Low entropy (0.0) starts at black/dark
        // High entropy (1.0) is alert red/amber
        assert_eq!(low, (0, 0, 0)); // Low entropy starts dark
        assert_eq!(high.0, 255); // High entropy has full red (alert)
    }

    #[test]
    fn test_placeholder_color() {
        let (r, g, b) = placeholder_pulse_color(0.0);
        // Tactical cyan scheme: (v/4, v, v*1.1)
        // At time 0.0: pulse = sin(0)*0.5 + 0.5 = 0.5, v = 15 + 0.5*20 = 25
        assert!(g >= 15 && g <= 40); // Green is the primary channel
        assert!(b > g); // Cyan tint means blue >= green

        let (r2, g2, b2) = placeholder_pulse_color(0.5);
        // Should be different due to pulse
        assert!(r != r2 || g != g2 || b != b2);
    }
}
