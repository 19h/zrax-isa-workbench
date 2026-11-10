//! Apeiron's analysis and visualization core, without its application.
//!
//! A snapshot of <https://github.com/19h/apeiron> (MIT, see `LICENSE`) at
//! the commit named in `README.md`: the analysis kernels, the Hilbert
//! curve and its progressive refiner, the CPU pixel generators for all
//! seven visualization modes and the wgpu compute renderer. The egui
//! application is not part of it. `README.md` lists every change made to
//! the vendored files.
//!
//! The code is kept as published so that it can be compared with and
//! updated from upstream; the lints of the surrounding workspace do not
//! apply to it.

#![allow(missing_docs, unused, clippy::all, clippy::pedantic)]

pub mod analysis;
pub mod background;
pub mod compat;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod hilbert;
pub mod types;
pub mod util;
pub mod viz;
