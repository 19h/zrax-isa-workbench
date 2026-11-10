//! Stand-ins for the two egui types apeiron's generators use, so the core
//! builds without a UI toolkit. Only the operations the vendored code
//! calls are provided, with egui's semantics.

/// An sRGB color with alpha, 8 bits per channel (egui `Color32`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Color32([u8; 4]);

impl Color32 {
    /// Opaque black.
    pub const BLACK: Color32 = Color32::from_rgb(0, 0, 0);

    /// An opaque color.
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self([r, g, b, 255])
    }

    /// A color from straight (unmultiplied) RGBA.
    pub const fn from_rgba_unmultiplied(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self([r, g, b, a])
    }

    /// Red channel.
    pub const fn r(&self) -> u8 {
        self.0[0]
    }

    /// Green channel.
    pub const fn g(&self) -> u8 {
        self.0[1]
    }

    /// Blue channel.
    pub const fn b(&self) -> u8 {
        self.0[2]
    }

    /// Alpha channel.
    pub const fn a(&self) -> u8 {
        self.0[3]
    }

    /// `[r, g, b, a]`.
    pub const fn to_array(&self) -> [u8; 4] {
        self.0
    }
}

/// A two-dimensional vector (egui `Vec2`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec2 {
    /// Horizontal component.
    pub x: f32,
    /// Vertical component.
    pub y: f32,
}

impl Vec2 {
    /// The zero vector.
    pub const ZERO: Vec2 = Vec2 { x: 0.0, y: 0.0 };

    /// A vector from its components.
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}
