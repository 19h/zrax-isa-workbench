//! The entropy profile as a strip of color: one sample per device column.

use std::sync::Arc;

use gpui::{canvas, fill, point, px, size, Bounds, Canvas, Rgba};

use crate::palette;

/// Paint `profile` (entropy in bits per byte per bin) across the element's
/// width. Each pixel column takes the bin under its center, as the
/// browser's `image-rendering: pixelated` strip does.
pub fn profile_strip(profile: Arc<[f32]>) -> Canvas<()> {
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            if profile.is_empty() {
                return;
            }
            let width = f32::from(bounds.size.width);
            // A strip is at most a few thousand pixels wide.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let columns = width.ceil().max(1.0) as usize;
            #[allow(clippy::cast_precision_loss)]
            let column_width = width / columns as f32;
            for column in 0..columns {
                let bin = (column * profile.len() + profile.len() / 2) / columns;
                let [r, g, b] = palette::entropy_color(profile[bin.min(profile.len() - 1)]);
                let color = Rgba {
                    r: f32::from(r) / 255.0,
                    g: f32::from(g) / 255.0,
                    b: f32::from(b) / 255.0,
                    a: 1.0,
                };
                #[allow(clippy::cast_precision_loss)]
                let left = bounds.origin.x + px(column as f32 * column_width);
                let cell = Bounds::new(
                    point(left, bounds.origin.y),
                    // Overlap by a hair so rounding leaves no seams.
                    size(px(column_width + 0.5), bounds.size.height),
                );
                window.paint_quad(fill(cell, color));
            }
        },
    )
}
