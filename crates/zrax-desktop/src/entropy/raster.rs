//! Analyzed map cells as pixels.
//!
//! The engine returns six numbers per cell ([`zrax::workbench::CELL_VALUES`]):
//! entropy, then five byte-class fractions. A cell beyond the end of the
//! file has negative entropy and stays transparent. The map is colored by
//! entropy; the class fractions are not drawn.

use zrax::workbench::CELL_VALUES;

use crate::palette;

/// Bytes per pixel of the output.
const PIXEL_BYTES: usize = 4;

/// Enlarge a `width` × `height` image of 4-byte pixels by the whole factor
/// `factor`, repeating each pixel, so a small fixed-resolution texture
/// keeps hard edges when it fills a larger frame.
pub fn upscale_nearest(pixels: &[u8], width: usize, height: usize, factor: usize) -> Vec<u8> {
    if factor <= 1 {
        return pixels.to_vec();
    }
    let row_bytes = width * PIXEL_BYTES;
    let mut enlarged = Vec::with_capacity(pixels.len() * factor * factor);
    for row in pixels.chunks_exact(row_bytes.max(1)).take(height) {
        let start = enlarged.len();
        for pixel in row.as_chunks::<PIXEL_BYTES>().0 {
            for _ in 0..factor {
                enlarged.extend_from_slice(pixel);
            }
        }
        for _ in 1..factor {
            enlarged.extend_from_within(start..start + row_bytes * factor);
        }
    }
    enlarged
}

/// Rasterize `cells` (row-major, `width` cells per row) to BGRA pixels,
/// each cell drawn as `upscale` × `upscale` pixels so that magnified maps
/// keep hard cell edges. Returns the pixels and the image side lengths.
pub fn rasterize(cells: &[f32], width: usize, upscale: usize) -> (Vec<u8>, usize, usize) {
    let upscale = upscale.max(1);
    let cell_count = cells.len() / CELL_VALUES;
    let height = cell_count.checked_div(width).unwrap_or(0);
    let image_width = width * upscale;
    let image_height = height * upscale;
    let mut pixels = vec![0u8; image_width * image_height * PIXEL_BYTES];
    for row in 0..height {
        for column in 0..width {
            let cell = &cells[(row * width + column) * CELL_VALUES..][..CELL_VALUES];
            if cell[0] < 0.0 {
                continue;
            }
            let [red, green, blue] = palette::entropy_color(cell[0]);
            let pixel = [blue, green, red, u8::MAX];
            for y in row * upscale..(row + 1) * upscale {
                let line = &mut pixels[(y * image_width + column * upscale) * PIXEL_BYTES..]
                    [..upscale * PIXEL_BYTES];
                for target in line.as_chunks_mut::<PIXEL_BYTES>().0 {
                    *target = pixel;
                }
            }
        }
    }
    (pixels, image_width, image_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two cells: full-entropy bytes, then a hole past the end of the file.
    const CELLS: [f32; 12] = [
        8.0, 0.0, 0.0, 0.5, 0.5, 0.0, //
        -1.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ];

    #[test]
    fn cells_become_bgra_blocks_and_holes_stay_transparent() {
        let (pixels, width, height) = rasterize(&CELLS, 2, 2);
        assert_eq!((width, height), (4, 2));
        let [red, green, blue] = palette::entropy_color(8.0);
        for y in 0..2 {
            let row = &pixels[y * 16..][..16];
            assert_eq!(row[..4], [blue, green, red, 255]);
            assert_eq!(row[4..8], [blue, green, red, 255]);
            assert_eq!(row[8..], [0; 8]);
        }
    }

    #[test]
    fn an_empty_map_is_an_empty_image() {
        assert_eq!(rasterize(&[], 0, 4), (Vec::new(), 0, 0));
    }

    #[test]
    fn upscaling_repeats_each_pixel_in_both_directions() {
        // A 2 × 1 image: pixel A then pixel B.
        let image = [1, 1, 1, 1, 2, 2, 2, 2];
        let enlarged = upscale_nearest(&image, 2, 1, 2);
        let row = [1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2];
        assert_eq!(enlarged, [row, row].concat());
        assert_eq!(upscale_nearest(&image, 2, 1, 1), image);
    }
}
