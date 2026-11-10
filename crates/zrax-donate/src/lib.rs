//! Client for the fwdonor firmware donation service.
//!
//! The service (`https://fwdonor.zr.ax`) accepts firmware images that zrax
//! recognizes, re-classifies them with the same zrax revision, posts them to
//! a Telegram group and keeps a public copy. This crate is everything a
//! client needs to take part:
//!
//! - [`policy`]: the accept rule the server applies, so a file the server
//!   would reject never leaves the machine;
//! - [`pow`]: the file-bound proof of work;
//! - [`api`]: the HTTP API, typed;
//! - [`Session`]: one file from "is it known?" to "the server kept it",
//!   with progress [`Event`]s and cancellation.
//!
//! Nothing here prints or reads the terminal. The command-line client and
//! the desktop workbench are both thin layers over [`Session`].
//!
//! # Revisions
//!
//! The server only takes uploads from clients built from the zrax revision
//! it runs (or one it replaced less than a week ago), because a verdict that
//! differs from the server's counts against the uploader's address. The
//! caller states its revision in [`ClientConfig::zrax_rev`], and
//! [`Session::connect`] refuses to continue when the server does not accept
//! it.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod api;
mod donate;
mod donor;
mod events;
pub mod policy;
pub mod pow;

pub use donate::{Candidate, ClientConfig, ConnectError, Session, DEFAULT_SERVER};
pub use donor::{DonorName, InvalidDonorName, ANONYMOUS};
pub use events::{Event, EventSender, Outcome, Stage};
pub use tokio_util::sync::CancellationToken;
