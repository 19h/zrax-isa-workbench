//! Fonts and icons compiled into the binary.
//!
//! The fonts are the browser workbench's own files (`web/fonts`, OFL; see
//! the license texts there). The icons are the paths of `web/index.html`
//! with the stroke attributes its stylesheet applies.

use std::borrow::Cow;

use gpui::{App, AssetSource, SharedString};

/// Icon asset paths, as passed to `gpui::svg().path(..)`.
pub mod icon {
    /// File workbench (four squares).
    pub const WORKBENCH: &str = "icons/workbench.svg";
    /// Files panel (a document).
    pub const FILES: &str = "icons/files.svg";
    /// Batch table (a list).
    pub const BATCH: &str = "icons/batch.svg";
    /// Certificates in all files.
    pub const CERTIFICATES: &str = "icons/certificates.svg";
    /// Add files.
    pub const ADD: &str = "icons/add.svg";
    /// Analysis log.
    pub const LOG: &str = "icons/log.svg";
    /// Remove a file.
    pub const REMOVE: &str = "icons/remove.svg";
    /// Donations.
    pub const DONATE: &str = "icons/donate.svg";
    /// Collapse the file header (a chevron pointing up).
    pub const COLLAPSE: &str = "icons/collapse.svg";
    /// Expand the file header (a chevron pointing down).
    pub const EXPAND: &str = "icons/expand.svg";
}

/// Every embedded asset by path.
const ASSETS: &[(&str, &[u8])] = &[
    (
        icon::WORKBENCH,
        include_bytes!("../assets/icons/workbench.svg"),
    ),
    (icon::FILES, include_bytes!("../assets/icons/files.svg")),
    (icon::BATCH, include_bytes!("../assets/icons/batch.svg")),
    (
        icon::CERTIFICATES,
        include_bytes!("../assets/icons/certificates.svg"),
    ),
    (icon::ADD, include_bytes!("../assets/icons/add.svg")),
    (icon::LOG, include_bytes!("../assets/icons/log.svg")),
    (icon::REMOVE, include_bytes!("../assets/icons/remove.svg")),
    (icon::DONATE, include_bytes!("../assets/icons/donate.svg")),
    (
        icon::COLLAPSE,
        include_bytes!("../assets/icons/collapse.svg"),
    ),
    (icon::EXPAND, include_bytes!("../assets/icons/expand.svg")),
];

/// DM Mono (body) and Martian Mono (display), regular and medium.
const FONTS: &[&[u8]] = &[
    include_bytes!("../../../web/fonts/dm-mono-regular.ttf"),
    include_bytes!("../../../web/fonts/dm-mono-medium.ttf"),
    include_bytes!("../../../web/fonts/martian-mono-regular.ttf"),
    include_bytes!("../../../web/fonts/martian-mono-medium.ttf"),
];

/// The application's asset source.
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> anyhow::Result<Option<Cow<'static, [u8]>>> {
        Ok(ASSETS
            .iter()
            .find(|(asset_path, _)| *asset_path == path)
            .map(|(_, bytes)| Cow::Borrowed(*bytes)))
    }

    fn list(&self, path: &str) -> anyhow::Result<Vec<SharedString>> {
        Ok(ASSETS
            .iter()
            .filter(|(asset_path, _)| asset_path.starts_with(path))
            .map(|(asset_path, _)| SharedString::from(*asset_path))
            .collect())
    }
}

/// Register the embedded fonts with the text system.
///
/// # Errors
///
/// The platform's error when a font file cannot be loaded.
pub fn load_fonts(cx: &App) -> anyhow::Result<()> {
    let fonts = FONTS.iter().map(|bytes| Cow::Borrowed(*bytes)).collect();
    cx.text_system().add_fonts(fonts)
}
