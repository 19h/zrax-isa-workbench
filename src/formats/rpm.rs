//! RPM packages: the 96-byte lead, the signature header, the main header
//! and the payload, a cpio archive that is usually compressed.
//!
//! Primary sources (pins in `docs/rpm.md`):
//! - rpm `rpm-6.0.0-release`: `docs/manual/format_v4.md`, `format_v6.md`,
//!   `format_lead.md`, `format_header.md` and `signatures_digests.md`;
//!   `lib/rpmlead.cc` and `lib/rpmlead.hh` (lead), `lib/header.cc`
//!   (`hdrblobRead`, `hdrblobVerifyLengths`, `hdrblobVerifyRegion`,
//!   `hdrblobVerifyInfo`, `hdrblobDigestUpdate`), `lib/signature.cc` and
//!   `lib/package.cc` (how packages read both headers),
//!   `include/rpm/rpmtag.h` (tags and types), `lib/cpio.cc` (payload
//!   entries, the stripped `07070X` header), `lib/rpmfi.cc` (stripped entry
//!   sizes and hard links), `build/pack.cc` (payload compressors and
//!   digests) and `lib/rpmte.cc` (gzip as the default compressor).
//! - Linux Standard Base Core Specification 5.0, Generic Part, section
//!   25.2 "Package File Format" (lead, header structure, signature and
//!   header tags, payload).
//! - zlib 1.3.1 `zlib.h` (`gzread` reads non-gzip input directly, which is
//!   how rpm's default gzip path reads an uncompressed payload).
//!
//! All integers are big-endian. The package names its build architecture
//! (`RPMTAG_ARCH`, such as `x86_64` or `noarch`) and the lead an
//! architecture number, but neither is ISA evidence: no documented mapping
//! ties them to an instruction set, `noarch` packages may hold any code,
//! and the lead number is ambiguous (rpm's `rpmrc` gives 1 to both i386
//! and x86-64). The container therefore names no target. The payload's
//! regular files are children, each classified from its own bytes and
//! listed only when it is a recognized format.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, size_text, Codec};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS};
use crate::formats::{checksum, MAX_PAYLOAD};
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt::Write;

mod digest;
mod header;
mod payload;

use header::{Header, HeaderKind};

/// Lead magic (`RPMLEAD_MAGIC0` to `RPMLEAD_MAGIC3`).
const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

/// Lead size (`RPMLEAD_SIZE`); the signature header follows it.
const LEAD_SIZE: usize = 96;

/// Lead `type` of a source package (`RPMLEAD_SOURCE`); 0 is binary.
const LEAD_SOURCE: u16 = 1;

/// Lead `signature_type` of a header-style signature
/// (`RPMSIGTYPE_HEADERSIG`), the only kind rpm 4 and 6 write.
const SIGNATURE_TYPE_HEADER: u16 = 5;

/// The signature header is padded to a multiple of 8 bytes
/// (`hdrblobRead`).
const SIGNATURE_ALIGNMENT: usize = 8;

/// Signature tags (`rpmSigTag` in `rpmtag.h`).
const RPMSIGTAG_SIZE: u32 = 1000;
const RPMSIGTAG_PAYLOADSIZE: u32 = 1007;
const RPMSIGTAG_LONGSIZE: u32 = 270;
const RPMSIGTAG_LONGARCHIVESIZE: u32 = 271;

/// Main header tags (`rpmTag` in `rpmtag.h`).
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_OS: u32 = 1021;
const RPMTAG_ARCH: u32 = 1022;
const RPMTAG_SOURCERPM: u32 = 1044;
const RPMTAG_ARCHIVESIZE: u32 = 1046;
const RPMTAG_PAYLOADSIZE: u32 = 5112;
const RPMTAG_PAYLOADSIZEALT: u32 = 5113;
const RPMTAG_RPMFORMAT: u32 = 5114;

/// Most characters of untrusted text shown in a note or metadata value.
const MAX_TEXT: usize = 256;

/// An RPM layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A package: lead, signature header (padded to 8 bytes), main header
    /// and payload. Binary and source packages and package format versions
    /// 3, 4 and 6 share it.
    Package,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Package => FileFormat::Rpm,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Package => "RPM package",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// package carries two magics.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition: the lead magic at offset 0 and the eight-byte
/// header structure magic of the signature header right after the lead.
/// A file with both is reported as an RPM package even when the rest is
/// broken, so a damaged package becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let has_signature_header = data
        .get(LEAD_SIZE..LEAD_SIZE + header::HEADER_MAGIC.len())
        .is_some_and(|magic| magic == header::HEADER_MAGIC);
    (data.starts_with(&LEAD_MAGIC) && has_signature_header).then_some(Layout::Package)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::RpmParseError`] for a truncated or inconsistent lead
/// or header structure, a declared package size the file does not hold,
/// data after the package that is not padding, or a header or payload
/// digest that does not match.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Package => parse_package(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::RpmParseError {
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

/// The `N` bytes at `at` of a structure that was read whole before.
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

fn be_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(bytes, at)?))
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// Round `value` up to a multiple of `alignment`, a power of two.
fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|value| value & !mask)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// The bytes of a fixed-size text field up to its first NUL.
fn until_nul(field: &[u8]) -> &[u8] {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..len]
}

/// Display form of untrusted text: printable ASCII as-is, other bytes as
/// `\xNN`, cut after [`MAX_TEXT`] bytes.
fn display_text(bytes: &[u8]) -> String {
    let mut text = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if i == MAX_TEXT {
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

/// `n` with the singular or plural noun.
fn counted(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// The lead (96 B): magic (4), major and minor format version (1 each),
/// type, architecture number (2 each), name (66, NUL-terminated), OS
/// number, signature type (2 each), reserved (16). rpm reads only the
/// magic; the rest is historical (`format_v4.md`).
struct Lead<'a> {
    major: u8,
    minor: u8,
    /// 0 binary, 1 source.
    package_type: u16,
    /// `rpmrc` `arch_canon` number; 0 in packages rpm 4 and 6 write.
    archnum: u16,
    /// Name-version-release, cut to 65 characters.
    name: &'a [u8],
    /// `rpmrc` `os_canon` number; 0 in packages rpm 4 and 6 write.
    osnum: u16,
    signature_type: u16,
}

fn lead(data: &[u8]) -> Result<Lead<'_>> {
    let lead = slice(data, 0, LEAD_SIZE, "lead")?;
    if lead[..LEAD_MAGIC.len()] != LEAD_MAGIC {
        return Err(error("Missing RPM lead magic at 0x0"));
    }
    Ok(Lead {
        major: lead[4],
        minor: lead[5],
        package_type: be_u16(lead, 6)?,
        archnum: be_u16(lead, 8)?,
        name: until_nul(&lead[10..76]),
        osnum: be_u16(lead, 76)?,
        signature_type: be_u16(lead, 78)?,
    })
}

/// Where the main header and the payload lie in the file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    /// File offset of the main header.
    header: usize,
    /// File offset of the payload: the end of the main header.
    payload: usize,
    /// File offset after the payload: the end the package declares, or the
    /// file size when it declares none.
    end: usize,
    /// The tag that declared the end, for notes.
    declared_by: Option<&'static str>,
}

/// The file offset of the main header: after the signature header and its
/// zero padding to 8 bytes.
fn main_header_offset(data: &[u8], signature: &Header<'_>) -> Result<usize> {
    let end = signature.offset + signature.size;
    let padded =
        align_up(end, SIGNATURE_ALIGNMENT).ok_or_else(|| error("Invalid signature header size"))?;
    let padding = slice(data, end, padded - end, "signature header padding")?;
    if padding.iter().any(|&b| b != 0) {
        return Err(error(format!(
            "Invalid signature header padding at 0x{end:X}: not zero"
        )));
    }
    Ok(padded)
}

/// The package extent: the signature header's size of header and payload
/// (`RPMSIGTAG_LONGSIZE`, else `RPMSIGTAG_SIZE`), else the main header's
/// compressed payload size (`RPMTAG_PAYLOADSIZE`, v6), else the file size.
/// Only padding may follow a declared end.
fn extent(data: &[u8], signature: &Header<'_>, main: &Header<'_>) -> Result<Extent> {
    let header_offset = main.offset;
    let payload_offset = main.offset + main.size;
    let declared = if let Some(size) = signature.number(RPMSIGTAG_LONGSIZE)? {
        Some((header_offset, size, "RPMSIGTAG_LONGSIZE"))
    } else if let Some(size) = signature.number(RPMSIGTAG_SIZE)? {
        Some((header_offset, size, "RPMSIGTAG_SIZE"))
    } else {
        main.number(RPMTAG_PAYLOADSIZE)?
            .map(|size| (payload_offset, size, "RPMTAG_PAYLOADSIZE"))
    };
    let Some((start, size, tag)) = declared else {
        return Ok(Extent {
            header: header_offset,
            payload: payload_offset,
            end: data.len(),
            declared_by: None,
        });
    };
    let end = usize::try_from(size)
        .ok()
        .and_then(|size| start.checked_add(size))
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated package: {tag} declares {size} B from 0x{start:X}, the file has {} B",
                data.len()
            ))
        })?;
    if end < payload_offset {
        return Err(error(format!(
            "Invalid {tag} {size} B: the main header alone ends at 0x{payload_offset:X}"
        )));
    }
    let rest = &data[end..];
    if !is_padding(rest) {
        return Err(error(format!(
            "Unexpected {} after the package at 0x{end:X}",
            size_text(rest.len())
        )));
    }
    Ok(Extent {
        header: header_offset,
        payload: payload_offset,
        end,
        declared_by: Some(tag),
    })
}

/// What the main header says about the package as a whole.
struct Package<'h> {
    name: Option<&'h [u8]>,
    version: Option<&'h [u8]>,
    release: Option<&'h [u8]>,
    epoch: Option<u64>,
    arch: Option<&'h [u8]>,
    os: Option<&'h [u8]>,
    /// The source package a binary package was built from; absent in
    /// source packages (rpm's `headerIsSource`).
    source_rpm: Option<&'h [u8]>,
    /// Package format version: `RPMTAG_RPMFORMAT` (6), else 4 for a main
    /// header with an immutable region, else 3.
    format_version: u64,
}

fn package<'h>(main: &Header<'h>) -> Result<Package<'h>> {
    let format_version = match main.number(RPMTAG_RPMFORMAT)? {
        Some(version) => version,
        None if main.region => 4,
        None => 3,
    };
    Ok(Package {
        name: main.string(RPMTAG_NAME)?,
        version: main.string(RPMTAG_VERSION)?,
        release: main.string(RPMTAG_RELEASE)?,
        epoch: main.number(RPMTAG_EPOCH)?,
        arch: main.string(RPMTAG_ARCH)?,
        os: main.string(RPMTAG_OS)?,
        source_rpm: main.string(RPMTAG_SOURCERPM)?,
        format_version,
    })
}

impl Package<'_> {
    fn is_source(&self) -> bool {
        self.source_rpm.is_none()
    }

    /// `binary` or `source`, as rpm decides it.
    fn kind(&self) -> &'static str {
        if self.is_source() {
            "source"
        } else {
            "binary"
        }
    }

    /// `name-[epoch:]version-release`, from what the header holds.
    fn nevr(&self) -> String {
        let mut nevr = self.name.map(display_text).unwrap_or_default();
        let version = self.version.map(display_text).unwrap_or_default();
        let release = self.release.map(display_text).unwrap_or_default();
        let _ = match self.epoch {
            Some(epoch) => write!(nevr, "-{epoch}:{version}-{release}"),
            None => write!(nevr, "-{version}-{release}"),
        };
        nevr
    }
}

/// The uncompressed payload size the headers declare: the signature's
/// `RPMSIGTAG_LONGARCHIVESIZE` or `RPMSIGTAG_PAYLOADSIZE`, else the main
/// header's `RPMTAG_PAYLOADSIZEALT` (v6) or `RPMTAG_ARCHIVESIZE`.
fn declared_archive_size(signature: &Header<'_>, main: &Header<'_>) -> Result<Option<u64>> {
    for (header, tag) in [
        (signature, RPMSIGTAG_LONGARCHIVESIZE),
        (signature, RPMSIGTAG_PAYLOADSIZE),
        (main, RPMTAG_PAYLOADSIZEALT),
        (main, RPMTAG_ARCHIVESIZE),
    ] {
        if let Some(size) = header.number(tag)? {
            return Ok(Some(size));
        }
    }
    Ok(None)
}

fn parse_package(data: &[u8]) -> Result<Container<'_>> {
    let lead = lead(data)?;
    let signature = header::parse(data, LEAD_SIZE, HeaderKind::Signature)?;
    let main_offset = main_header_offset(data, &signature)?;
    let main = header::parse(data, main_offset, HeaderKind::Main)?;
    let extent = extent(data, &signature, &main)?;
    let package = package(&main)?;
    let mut digests = digest::verify(data, &signature, &main, extent)?;
    let payload = payload::read(data, &main, extent)?;
    if let Some(archive) = payload.complete_archive() {
        digests.add_verified(digest::verify_decoded(&main, archive)?);
    }

    let variant = format!("RPM v{} {} package", package.format_version, package.kind());
    let mut c = Container::new(FileFormat::Rpm, variant, "rpm");
    c.consumed = extent.end;
    push_package_notes(&lead, &package, &mut c);
    push_header_notes(&signature, &main, extent, &mut c);
    digests.push_notes(&mut c);
    push_metadata(&lead, &package, &signature, &main, &mut c);
    let declared_size = declared_archive_size(&signature, &main)?;
    payload.push(&main, declared_size, &mut c)?;
    Ok(c)
}

/// The package identity and why its architecture is not ISA evidence.
fn push_package_notes(lead: &Lead<'_>, package: &Package<'_>, c: &mut Container<'_>) {
    let kind = if package.is_source() {
        "Source"
    } else {
        "Binary"
    };
    let arch = package
        .arch
        .map_or_else(|| "none".to_string(), display_text);
    let os = package.os.map_or_else(|| "none".to_string(), display_text);
    c.notes.push(format!(
        "{kind} package {}; header architecture {arch}, OS {os}; package format v{}; lead \
         version {}.{}",
        package.nevr(),
        package.format_version,
        lead.major,
        lead.minor
    ));
    c.notes.push(
        "The header architecture and the lead architecture number name a build target, not an \
         ISA; each payload file is classified from its own bytes"
            .to_string(),
    );
    let lead_type = if lead.package_type == LEAD_SOURCE {
        "source"
    } else {
        "binary"
    };
    if (lead.package_type == LEAD_SOURCE) != package.is_source() {
        c.notes.push(format!(
            "The lead says {lead_type} package; the main header {} `RPMTAG_SOURCERPM`, so rpm \
             treats it as a {} package",
            if package.is_source() { "has no" } else { "has" },
            package.kind()
        ));
    }
    if lead.signature_type != SIGNATURE_TYPE_HEADER {
        c.notes.push(format!(
            "Lead signature type {} is not 5 (header-style); the signature header is read anyway",
            lead.signature_type
        ));
    }
}

/// Where the headers and payload lie, and whether the headers have
/// immutable regions.
fn push_header_notes(
    signature: &Header<'_>,
    main: &Header<'_>,
    extent: Extent,
    c: &mut Container<'_>,
) {
    c.notes.push(format!(
        "Signature header at 0x{:X}: {}; main header at 0x{:X}: {}; payload at 0x{:X}: {}{}",
        signature.offset,
        counted(signature.len(), "tag", "tags"),
        main.offset,
        counted(main.len(), "tag", "tags"),
        extent.payload,
        size_text(extent.end - extent.payload),
        match extent.declared_by {
            Some(tag) => format!(" (end from {tag})"),
            None => " (to the end of the file; no size tag)".to_string(),
        }
    ));
    for header in [signature, main] {
        if !header.region {
            c.notes.push(format!(
                "The {} has no immutable region (a legacy v3 layout)",
                header.kind.name()
            ));
        }
    }
}

fn push_metadata(
    lead: &Lead<'_>,
    package: &Package<'_>,
    signature: &Header<'_>,
    main: &Header<'_>,
    c: &mut Container<'_>,
) {
    let texts = [
        ("rpm_name", "Name", package.name),
        ("rpm_version", "Version", package.version),
        ("rpm_release", "Release", package.release),
        (
            "rpm_arch",
            "Header architecture (not ISA evidence)",
            package.arch,
        ),
        ("rpm_os", "Header OS", package.os),
        ("rpm_source_rpm", "Source package", package.source_rpm),
    ];
    for (key, label, value) in texts {
        if let Some(value) = value {
            c.push_metadata(key, label, display_text(value));
        }
    }
    if let Some(epoch) = package.epoch {
        c.push_metadata("rpm_epoch", "Epoch", epoch);
    }
    c.push_metadata("rpm_package_type", "Package type", package.kind());
    c.push_metadata(
        "rpm_format_version",
        "Package format version",
        package.format_version,
    );
    c.push_metadata(
        "rpm_lead_version",
        "Lead version",
        format!("{}.{}", lead.major, lead.minor),
    );
    c.push_metadata("rpm_lead_name", "Lead name", display_text(lead.name));
    c.push_metadata(
        "rpm_lead_archnum",
        "Lead architecture number (not ISA evidence)",
        u64::from(lead.archnum),
    );
    c.push_metadata("rpm_lead_osnum", "Lead OS number", u64::from(lead.osnum));
    c.push_metadata(
        "rpm_signature_tags",
        "Signature header tags",
        signature.len() as u64,
    );
    c.push_metadata(
        "rpm_header_offset",
        "Main header offset",
        main.offset as u64,
    );
    c.push_metadata("rpm_header_tags", "Main header tags", main.len() as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lead: magic, version 3.0, binary, archnum 1, name, OS 1,
    /// signature type 5.
    fn lead_bytes(name: &[u8]) -> Vec<u8> {
        let mut lead = vec![0u8; LEAD_SIZE];
        lead[..4].copy_from_slice(&LEAD_MAGIC);
        lead[4] = 3;
        lead[8..10].copy_from_slice(&1u16.to_be_bytes());
        lead[10..10 + name.len()].copy_from_slice(name);
        lead[76..78].copy_from_slice(&1u16.to_be_bytes());
        lead[78..80].copy_from_slice(&SIGNATURE_TYPE_HEADER.to_be_bytes());
        lead
    }

    #[test]
    fn detection_needs_both_magics() {
        let mut data = lead_bytes(b"hello-1.0-1");
        assert_eq!(detect(&data), None);
        data.extend_from_slice(&header::HEADER_MAGIC);
        assert_eq!(detect(&data), Some(Layout::Package));
        data[100] = 1;
        assert_eq!(detect(&data), None);
        data[100] = 0;
        data[0] ^= 1;
        assert_eq!(detect(&data), None);
    }

    #[test]
    fn leads_report_their_fields() {
        let data = lead_bytes(b"hello-1.0-1");
        let lead = lead(&data).unwrap();
        assert_eq!((lead.major, lead.minor), (3, 0));
        assert_eq!(lead.package_type, 0);
        assert_eq!(lead.archnum, 1);
        assert_eq!(lead.name, b"hello-1.0-1");
        assert_eq!(lead.osnum, 1);
        assert_eq!(lead.signature_type, SIGNATURE_TYPE_HEADER);
        assert!(super::lead(&data[..LEAD_SIZE - 1]).is_err());
    }

    #[test]
    fn layout_reports_format_and_strength() {
        assert_eq!(Layout::Package.format(), FileFormat::Rpm);
        assert_eq!(Layout::Package.label(), "RPM package");
        assert!(!Layout::Package.is_weak());
    }

    #[test]
    fn helpers_escape_text_and_round_up() {
        assert_eq!(display_text(b"x86_64"), "x86_64");
        assert_eq!(display_text(b"a\nb"), "a\\x0Ab");
        assert_eq!(display_text(&[b'x'; MAX_TEXT + 4]).len(), MAX_TEXT + 3);
        assert_eq!(until_nul(b"name\0rest"), b"name");
        assert_eq!(align_up(13, 8), Some(16));
        assert_eq!(align_up(16, 8), Some(16));
        assert_eq!(align_up(usize::MAX, 4), None);
        assert_eq!(counted(1, "tag", "tags"), "1 tag");
        assert_eq!(counted(3, "tag", "tags"), "3 tags");
    }
}
