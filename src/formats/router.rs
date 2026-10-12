//! Router firmware wrappers: Broadcom TRX (`HDR0`, header versions 1 and 2),
//! Netgear CHK, D-Link SEAMA entities and seals, TP-Link firmware headers
//! (the `mktplinkfw` v1 layout and the `mktplinkfw2` v2/v3 layout) and
//! TP-Link `SafeLoader` factory images.
//!
//! Sources:
//! - `OpenWrt` firmware-utils at `a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7`,
//!   `src/`: `trx.c`, `otrx.c` and `asustrx.c` (TRX), `mkchkimg.c` (CHK),
//!   `seama.h`, `seama.c` and `oseama.c` (SEAMA), `mktplinkfw.c`,
//!   `mktplinkfw2.c` and `mktplinkfw-lib.c` (TP-Link headers),
//!   `tplink-safeloader.c` (`SafeLoader`).
//! - Linux v6.12 `drivers/mtd/parsers/parser_trx.c` (TRX partition roles).
//! - `OpenWrt` v24.10.0 `include/image-commands.mk` (`Build/lzma`),
//!   `target/linux/bcm47xx/image/Makefile` and
//!   `target/linux/ath79/image/common-tp-link.mk`: how `OpenWrt` fills these
//!   wrappers (an LZMA loader, a raw LZMA-alone kernel and a root
//!   filesystem).
//!
//! None of these headers names an architecture. Board IDs, hardware IDs,
//! vendor strings and kernel load addresses are not ISA evidence, so every
//! container leaves its target open and the ISA comes from the components,
//! each classified from its own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt::Write;

mod chk;
mod safeloader;
mod seama;
mod tplink;
mod trx;

/// LZMA properties byte of `lc=1 lp=2 pb=2` (`(pb * 5 + lp) * 9 + lc`),
/// which `OpenWrt` passes to `lzma e` for router kernels (`Build/lzma` in
/// `include/image-commands.mk`, and the bcm47xx `vmlinux.lzma` recipe).
const OPENWRT_LZMA_PROPERTIES: u8 = 0x6d;

/// A router firmware layout recognized by [`detect`] or [`detect_weak`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Broadcom TRX image, header version 1 (three partition offsets) or 2
    /// (four).
    Trx,
    /// Netgear CHK image: header, board ID, kernel and root filesystem.
    NetgearChk,
    /// D-Link SEAMA entity (image with an MD5 digest) or seal (a sequence of
    /// entities).
    Seama,
    /// TP-Link firmware header in the `mktplinkfw` layout (version word 1,
    /// or 2 with `-m 2`).
    TpLinkV1,
    /// TP-Link firmware header in the `mktplinkfw2` layout (version word 2
    /// or 3).
    TpLinkV2,
    /// TP-Link `SafeLoader` factory image with an `fwup-ptn` partition table.
    TpLinkSafeLoader,
    /// Bytes that validate as more than one magic-less TP-Link layout.
    TpLinkAmbiguous,
}

/// The magic-less layouts, in the order [`detect_weak`] tries them.
const WEAK_LAYOUTS: [Layout; 3] = [Layout::TpLinkV1, Layout::TpLinkV2, Layout::TpLinkSafeLoader];

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Trx => FileFormat::Trx,
            Self::NetgearChk => FileFormat::NetgearChk,
            Self::Seama => FileFormat::Seama,
            Self::TpLinkV1 | Self::TpLinkV2 | Self::TpLinkSafeLoader | Self::TpLinkAmbiguous => {
                FileFormat::TpLink
            }
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Trx => "Broadcom TRX",
            Self::NetgearChk => "Netgear CHK",
            Self::Seama => "D-Link SEAMA",
            Self::TpLinkV1 => "TP-Link header (mktplinkfw layout)",
            Self::TpLinkV2 => "TP-Link header (mktplinkfw2 layout)",
            Self::TpLinkSafeLoader => "TP-Link SafeLoader factory image",
            Self::TpLinkAmbiguous => "Ambiguous TP-Link image",
        }
    }

    /// Recognized from complete header structure rather than a magic value.
    pub fn is_weak(self) -> bool {
        matches!(
            self,
            Self::TpLinkV1 | Self::TpLinkV2 | Self::TpLinkSafeLoader | Self::TpLinkAmbiguous
        )
    }
}

/// Strong recognition: the TRX, CHK and SEAMA magics at offset 0. A file
/// with one of them is reported as that format even when the rest is
/// broken, so a damaged wrapper becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(..4)?;
    if magic == trx::MAGIC {
        Some(Layout::Trx)
    } else if magic == chk::MAGIC {
        Some(Layout::NetgearChk)
    } else if magic == seama::MAGIC {
        Some(Layout::Seama)
    } else {
        None
    }
}

/// Weak recognition of the magic-less TP-Link layouts: the header structure
/// must validate completely (version word, strings, constant fields, every
/// range inside the file, only padding after the image). Their MD5 digests
/// cannot be checked, so the structure is the only evidence. Bytes that
/// validate as two layouts are reported as ambiguous.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    let mut valid = WEAK_LAYOUTS
        .iter()
        .copied()
        .filter(|&layout| is_valid_weak(data, layout));
    let first = valid.next()?;
    if valid.next().is_some() {
        Some(Layout::TpLinkAmbiguous)
    } else {
        Some(first)
    }
}

/// Whether `data` validates completely as the magic-less `layout`.
fn is_valid_weak(data: &[u8], layout: Layout) -> bool {
    match layout {
        Layout::TpLinkV1 => tplink::is_valid(data, tplink::Generation::V1),
        Layout::TpLinkV2 => tplink::is_valid(data, tplink::Generation::V2),
        Layout::TpLinkSafeLoader => safeloader::is_valid(data),
        Layout::Trx | Layout::NetgearChk | Layout::Seama | Layout::TpLinkAmbiguous => false,
    }
}

/// Parse `data` as the given router layout.
///
/// # Errors
///
/// [`ClassifierError::RouterImageParseError`] for a truncated or
/// inconsistent header, a failed checksum or a range outside the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Trx => trx::parse(data),
        Layout::NetgearChk => chk::parse(data),
        Layout::Seama => seama::parse(data),
        Layout::TpLinkV1 => tplink::parse(data, tplink::Generation::V1),
        Layout::TpLinkV2 => tplink::parse(data, tplink::Generation::V2),
        Layout::TpLinkSafeLoader => safeloader::parse(data),
        Layout::TpLinkAmbiguous => ambiguous(data),
    }
}

/// An image whose header validates as two TP-Link layouts: reported with
/// the layouts it matches, an unknown ISA and nothing extracted.
fn ambiguous(data: &[u8]) -> Result<Container<'_>> {
    let matches: Vec<&str> = WEAK_LAYOUTS
        .iter()
        .filter(|&&layout| is_valid_weak(data, layout))
        .map(|layout| layout.label())
        .collect();
    if matches.len() < 2 {
        return Err(error(
            "Invalid ambiguous TP-Link image: fewer than two layouts validate",
        ));
    }
    let mut c = Container::new(
        FileFormat::TpLink,
        Layout::TpLinkAmbiguous.label(),
        "tplink",
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Ambiguous TP-Link image: the bytes validate as {}; no layout is chosen and nothing is extracted",
        matches.join(" and ")
    ));
    Ok(c)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::RouterImageParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "header field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, at)?))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, at)?))
}

fn be_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// The text of a fixed-size string field: printable ASCII up to the first
/// NUL (or the whole field). `None` when it holds anything else.
fn ascii_field(field: &[u8]) -> Option<&str> {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let text = &field[..len];
    if !text.iter().all(|b| (0x20..0x7f).contains(b)) {
        return None;
    }
    std::str::from_utf8(text).ok()
}

/// Display form of untrusted text: printable ASCII as-is, other bytes as
/// `\xNN`, cut after `max_chars` bytes.
fn display_text(bytes: &[u8], max_chars: usize) -> String {
    let mut text = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if i == max_chars {
            text.push_str("...");
            break;
        }
        if (0x20..0x7f).contains(&b) {
            text.push(char::from(b));
        } else {
            let _ = write!(text, "\\x{b:02X}");
        }
    }
    text
}

/// Hex digits of a digest field, uppercase.
fn hex_digest(digest: &[u8]) -> String {
    digest.iter().fold(String::new(), |mut text, b| {
        let _ = write!(text, "{b:02X}");
        text
    })
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// Does `stored` start with an LZMA-alone header these wrappers carry: the
/// xz-utils and LZMA SDK default ([`compressed::is_plausible_lzma`]) or
/// `OpenWrt`'s `lc=1 lp=2 pb=2`, each with a power-of-two dictionary?
fn is_router_lzma(stored: &[u8]) -> bool {
    compressed::is_plausible_lzma(stored)
        || compressed::has_lzma_header(stored, OPENWRT_LZMA_PROPERTIES)
}

/// Builds the firmware components of one container and keeps their decoded
/// total within [`MAX_EXTRACTED`].
#[derive(Debug, Default)]
struct Extractor {
    decoded: usize,
}

impl Extractor {
    /// A firmware component stored at `offset`, classified from its own
    /// bytes. `OpenWrt` stores router kernels as raw LZMA-alone streams,
    /// which have no magic (`lzma e` in the bcm47xx TRX recipe and in
    /// `Build/lzma` for TP-Link images). That is a convention of the
    /// wrapper's producer, not a header field, so a component is decoded
    /// only when it has no codec magic and starts with an LZMA-alone header
    /// of [`is_router_lzma`]. A stream that then does not decode is listed
    /// as opaque with a note: it is most likely compressed data, which must
    /// not reach the code model.
    fn component<'a>(
        &mut self,
        label: String,
        offset: usize,
        stored: &'a [u8],
        notes: &mut Vec<String>,
    ) -> Child<'a> {
        if compressed::sniff(stored).is_some() || !is_router_lzma(stored) {
            return Child::stored(label, offset, stored);
        }
        // `is_router_lzma` read the five header bytes.
        let properties = stored[0];
        let remaining = MAX_EXTRACTED.saturating_sub(self.decoded);
        if remaining == 0 {
            notes.push(format!(
                "{label}: LZMA-alone header; not decoded because the container extraction limit of {} was reached",
                size_text(MAX_EXTRACTED)
            ));
            return Child::opaque(label, offset, stored);
        }
        match compressed::decode_limited(Codec::Lzma, stored, remaining) {
            Ok(decoded) => {
                self.decoded += decoded.data.len();
                notes.push(format!(
                    "{label}: raw LZMA-alone stream (properties 0x{properties:02X}), {} decoded; decoded by the OpenWrt convention for router kernels, not a header field; LZMA-alone has no integrity check",
                    size_text(decoded.data.len())
                ));
                Child::decoded(
                    label,
                    offset,
                    stored.len(),
                    Cow::Owned(decoded.data),
                    Codec::Lzma.name(),
                )
            }
            Err(e) => {
                notes.push(format!(
                    "{label}: starts with an LZMA-alone header but does not decode ({e}); listed as opaque"
                ));
                Child::opaque(label, offset, stored)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_fields_stop_at_nul_and_reject_control_bytes() {
        assert_eq!(ascii_field(b"TP-LINK\0\0\0"), Some("TP-LINK"));
        assert_eq!(ascii_field(b"full"), Some("full"));
        assert_eq!(ascii_field(b"\0garbage"), Some(""));
        assert_eq!(ascii_field(b"bad\x01\0"), None);
        assert_eq!(ascii_field(b"high\xff\0"), None);
    }

    #[test]
    fn display_text_escapes_and_truncates() {
        assert_eq!(display_text(b"a=b\n", 16), "a=b\\x0A");
        assert_eq!(display_text(b"abcdef", 3), "abc...");
        assert_eq!(hex_digest(&[0x0a, 0xbc]), "0ABC");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size_text(4096), "4 KiB");
        assert_eq!(size_text(3 << 20), "3 MiB");
        assert_eq!(size_text(1000), "1000 B");
    }

    #[test]
    fn strong_detection_needs_only_the_magic() {
        assert_eq!(detect(b"HDR0"), Some(Layout::Trx));
        assert_eq!(
            detect(&[0x2a, 0x23, 0x24, 0x5e, 0]),
            Some(Layout::NetgearChk)
        );
        assert_eq!(detect(&[0x5e, 0xa3, 0xa4, 0x17]), Some(Layout::Seama));
        assert_eq!(detect(b"HDR"), None);
        assert_eq!(detect(b"HDR1"), None);
    }

    #[test]
    fn router_lzma_accepts_the_default_and_openwrt_properties() {
        let dictionary = (1u32 << 23).to_le_bytes();
        for properties in [0x5d, OPENWRT_LZMA_PROPERTIES] {
            let mut header = vec![properties];
            header.extend_from_slice(&dictionary);
            assert!(is_router_lzma(&header), "0x{properties:02X}");
        }
        let mut other = vec![0x5e];
        other.extend_from_slice(&dictionary);
        assert!(!is_router_lzma(&other));
        assert!(
            !is_router_lzma(&[0x6d, 0, 0x08, 0, 0]),
            "dictionary below 4 KiB"
        );
    }

    #[test]
    fn plausible_lzma_that_does_not_decode_is_opaque() {
        let mut extractor = Extractor::default();
        let mut notes = Vec::new();
        let mut bogus = vec![0x6d, 0, 0, 0x80, 0];
        bogus.extend_from_slice(&[0xff; 8]);
        bogus.extend_from_slice(&[0x55; 32]);
        let child = extractor.component("Kernel".into(), 0x40, &bogus, &mut notes);
        assert!(child.transform.is_none());
        assert!(child.opaque);
        assert_eq!(extractor.decoded, 0);
        assert!(notes[0].contains("does not decode"), "{notes:?}");
    }

    #[test]
    fn magic_bearing_payloads_are_not_decoded_here() {
        let mut extractor = Extractor::default();
        let mut notes = Vec::new();
        let gzip = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0, 0];
        let child = extractor.component("Loader".into(), 0, &gzip, &mut notes);
        assert!(child.transform.is_none());
        assert!(!child.opaque);
        assert_eq!(notes, Vec::<String>::new());
    }

    #[test]
    fn extraction_stops_at_the_container_limit() {
        let mut extractor = Extractor {
            decoded: MAX_EXTRACTED,
        };
        let mut notes = Vec::new();
        let header = [0x5d, 0, 0, 0x80, 0];
        let child = extractor.component("Kernel".into(), 0, &header, &mut notes);
        assert!(child.opaque);
        assert!(notes[0].contains("extraction limit"), "{notes:?}");
    }
}
