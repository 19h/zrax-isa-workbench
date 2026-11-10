//! Colors of entropy values and byte classes.
//!
//! Source: `web/canvas.js`. Entropy runs from near-black ink to paper below
//! the high-entropy threshold and through magenta above it, so compressed
//! or encrypted regions stand out from code and data.

use std::sync::OnceLock;

/// An sRGB color, 8 bits per channel.
pub type Rgb = [u8; 3];

/// Entropy in bits per byte from which data is shown in magenta.
pub const HIGH_ENTROPY_BITS: f32 = 7.2;

/// Largest entropy of a byte window, in bits per byte.
pub const MAX_ENTROPY_BITS: f32 = 8.0;

/// Entropy below which a window is drawn as empty.
const VOID_ENTROPY_BITS: f32 = 0.06;

/// Palette steps per bit of entropy.
const STEPS_PER_BIT: f32 = 100.0;
const PALETTE_LEN: usize = 801;

/// Exponent of the ink-to-paper ramp: keeps low entropies dark.
const RAMP_EXPONENT: f32 = 1.8;

const VOID: Rgb = [8, 7, 6];
const INK: Rgb = [36, 31, 27];
const PAPER: Rgb = [216, 206, 195];
const MAGENTA_DARK: Rgb = [217, 43, 113];
const MAGENTA: Rgb = [255, 61, 139];
const MAGENTA_LIGHT: Rgb = [255, 106, 165];

/// Histogram bars.
pub const HISTOGRAM_BAR: Rgb = [0x8c, 0x81, 0x77];
/// The histogram bar of the byte under the cursor.
pub const HISTOGRAM_PROBE: Rgb = MAGENTA;

fn blend(from: Rgb, to: Rgb, t: f32) -> Rgb {
    let channel = |index: usize| {
        let value = f32::from(from[index]) + (f32::from(to[index]) - f32::from(from[index])) * t;
        // Clamped to the channel range first, so the cast is exact.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = value.round().clamp(0.0, 255.0) as u8;
        byte
    };
    [channel(0), channel(1), channel(2)]
}

fn palette() -> &'static [Rgb; PALETTE_LEN] {
    static PALETTE: OnceLock<[Rgb; PALETTE_LEN]> = OnceLock::new();
    PALETTE.get_or_init(|| {
        let mut colors = [VOID; PALETTE_LEN];
        let high_span = MAX_ENTROPY_BITS - HIGH_ENTROPY_BITS;
        let high_midpoint = f32::midpoint(MAX_ENTROPY_BITS, HIGH_ENTROPY_BITS);
        for (step, color) in colors.iter_mut().enumerate() {
            // At most 800, exact in f32.
            #[allow(clippy::cast_precision_loss)]
            let bits = step as f32 / STEPS_PER_BIT;
            let above_threshold = (bits - HIGH_ENTROPY_BITS) / high_span * 2.0;
            *color = if bits < VOID_ENTROPY_BITS {
                VOID
            } else if bits < HIGH_ENTROPY_BITS {
                blend(INK, PAPER, (bits / HIGH_ENTROPY_BITS).powf(RAMP_EXPONENT))
            } else if bits < high_midpoint {
                blend(MAGENTA_DARK, MAGENTA, above_threshold)
            } else {
                blend(MAGENTA, MAGENTA_LIGHT, above_threshold - 1.0)
            };
        }
        colors
    })
}

/// The color of `bits` of entropy per byte (clamped to 0..=8).
pub fn entropy_color(bits: f32) -> Rgb {
    let clamped = if bits.is_nan() {
        0.0
    } else {
        bits.clamp(0.0, MAX_ENTROPY_BITS)
    };
    // In 0..=800 after the clamp.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let step = (clamped * STEPS_PER_BIT).round() as usize;
    palette()[step.min(PALETTE_LEN - 1)]
}

/// What an entropy value says about a window, in the inspector's words.
pub fn entropy_class(bits: f64) -> &'static str {
    if bits < 0.5 {
        "zero fill / low diversity"
    } else if bits < 3.0 {
        "sparse / structured"
    } else if bits < 5.0 {
        "moderate byte diversity"
    } else if bits < f64::from(HIGH_ENTROPY_BITS) {
        "mixed byte distribution"
    } else {
        "high byte diversity"
    }
}

/// What a raw-DEFLATE ratio says about a window.
pub fn complexity_class(ratio: f64) -> &'static str {
    if ratio < 0.3 {
        "highly compressible"
    } else if ratio < 0.65 {
        "structured"
    } else if ratio < 0.92 {
        "dense"
    } else {
        "incompressible at this window"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ramp_runs_from_void_through_paper_to_magenta() {
        assert_eq!(entropy_color(0.0), VOID);
        assert_eq!(entropy_color(0.05), VOID);
        assert_eq!(
            entropy_color(0.06),
            blend(INK, PAPER, (0.06f32 / 7.2).powf(1.8))
        );
        assert_eq!(entropy_color(7.2), MAGENTA_DARK);
        assert_eq!(entropy_color(7.6), MAGENTA);
        assert_eq!(entropy_color(8.0), MAGENTA_LIGHT);
        assert_eq!(entropy_color(99.0), MAGENTA_LIGHT);
        assert_eq!(entropy_color(-1.0), VOID);
        assert_eq!(entropy_color(f32::NAN), VOID);
    }

    #[test]
    fn brightness_rises_with_entropy_below_the_threshold() {
        let brightness = |bits: f32| u32::from(entropy_color(bits)[0]);
        assert!(brightness(1.0) < brightness(3.0));
        assert!(brightness(3.0) < brightness(7.0));
    }

    #[test]
    fn inspector_classes_follow_the_documented_boundaries() {
        assert_eq!(entropy_class(2.0679), "sparse / structured");
        assert_eq!(entropy_class(7.2), "high byte diversity");
        assert_eq!(complexity_class(0.5994), "structured");
        assert_eq!(complexity_class(0.92), "incompressible at this window");
    }
}
