//! `MikroTik` `RouterOS` packages (NPK).
//!
//! Layout (tenable/routeros `ls_npk/src/main.cpp`; `MikroTikPatch` `npk.py`
//! `NovaPackage.load`), all integers little-endian: magic `0xBAD0F11E`
//! (4), the size of everything after the size field (4), then parts that
//! tile the declared size. A part is a type (2), a payload size (4) and
//! the payload.
//!
//! Parts read here (`MikroTikPatch` `NpkPartID`):
//! - `NAME_INFO` (0x01): package name (16, NUL-padded), version bytes
//!   revision, build, minor, major (4), build time (4, Unix seconds), then
//!   unknown bytes (`NpkNameInfo`, `<16s4sI12s`).
//! - `FILE_CONTAINER` (0x04): a zlib stream of file entries
//!   (`NpkFileContainer`, `<BB6sIBBBBIIIH`; kost/mikrotik-npk
//!   `unpacknpk.py`): permission bits (1) and file type (1), the low and
//!   high bytes of `st_mode`; user and group (6); modification time (4);
//!   version bytes (4); creation time (4); unknown (4); data size (4); name
//!   size (2); the name; the data.
//! - `SQUASHFS` (0x15): a `SquashFS` image.
//! - `SIGNATURE` (0x09): a SHA-1 digest (20) of the package's parts before
//!   it, a KCDSA signature (48) and optionally an `EdDSA` signature (64)
//!   (`NovaPackage.sign`, `verify`, `get_digest`).
//! - `PKG_FEATURES` (0x14) marks a bundle, whose member packages each start
//!   with a `NAME_INFO` part (`NovaPackage.__init__`).

use super::*;
use crate::formats::checksum::Sha1;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::MAX_EXTRACTED;
use crate::formats::MAX_PAYLOAD;

/// Package magic, stored little-endian (`1E F1 D0 BA`).
const NPK_MAGIC: u32 = 0xbad0_f11e;

/// Magic and package size.
const HEADER_SIZE: usize = 8;

/// Part type (2) and payload size (4).
const PART_HEADER_SIZE: usize = 6;

/// Part types used by the parser (`MikroTikPatch` `NpkPartID`).
const NAME_INFO: u16 = 0x01;
const DESCRIPTION: u16 = 0x02;
const FILE_CONTAINER: u16 = 0x04;
const SIGNATURE: u16 = 0x09;
const ARCHITECTURE: u16 = 0x10;
const PKG_INFO: u16 = 0x12;
const PKG_FEATURES: u16 = 0x14;
const SQUASHFS: u16 = 0x15;
/// Excluded from the digest (`get_digest` skips `NpkPartID.HEADER`).
const HEADER: u16 = 0x19;

/// A documented part type and its name.
#[derive(Debug)]
struct PartType {
    id: u16,
    name: &'static str,
}

const fn documented(id: u16, name: &'static str) -> PartType {
    PartType { id, name }
}

/// Every documented part type: `MikroTikPatch` `NpkPartID` and tenable
/// `ls_npk` `section_name` (which names 0x05 and 0x06 and calls 0x0A-0x0F
/// unused).
const PART_TYPES: &[PartType] = &[
    documented(0x01, "package information"),
    documented(0x02, "description"),
    documented(0x03, "dependencies"),
    documented(0x04, "file container"),
    documented(0x05, "install script (libinstall)"),
    documented(0x06, "uninstall script (libinstall)"),
    documented(0x07, "install script"),
    documented(0x08, "uninstall script"),
    documented(0x09, "signature"),
    documented(0x10, "architecture"),
    documented(0x11, "package conflicts"),
    documented(0x12, "bundle information"),
    documented(0x13, "features"),
    documented(0x14, "package features"),
    documented(0x15, "SquashFS image"),
    documented(0x16, "zero padding"),
    documented(0x17, "Git commit"),
    documented(0x18, "channel"),
    documented(0x19, "header"),
];

/// Most parts one package may hold. Real packages hold a few dozen.
const MAX_PARTS: usize = MAX_COMPONENTS;

/// `NAME_INFO` and `PKG_INFO` payloads: name (16), version (4), build
/// time (4), then bytes the parser does not read.
const INFO_NAME_SIZE: usize = 16;
const INFO_VERSION: usize = 16;
const INFO_BUILD_TIME: usize = 20;
const INFO_MIN_SIZE: usize = 24;

/// Version build codes (`MikroTikPatch` `NpkInfo.decode_version`).
const BUILD_ALPHA: u8 = 97;
const BUILD_BETA: u8 = 98;
const BUILD_RC: u8 = 99;
const BUILD_FINAL: u8 = 102;
/// With [`BUILD_FINAL`], revision bit 7 marks a testing build.
const REVISION_TEST: u8 = 0x80;

/// File container entry header (`NpkFileContainer._format`).
const ENTRY_HEADER_SIZE: usize = 30;
const ENTRY_TYPE: usize = 1;
const ENTRY_DATA_SIZE: usize = 24;
const ENTRY_NAME_SIZE: usize = 28;

/// File types: the high byte of `st_mode` (kost/mikrotik-npk
/// `unpacknpk.py`: 65 directory, 129 file, 161 symbolic link).
const TYPE_DIRECTORY: u8 = 0x41;
const TYPE_FILE: u8 = 0x81;
const TYPE_SYMLINK: u8 = 0xa1;

/// `SquashFS` superblock magics, little- and big-endian (`MikroTikPatch`
/// `set_null_block` checks both).
const SQUASHFS_MAGICS: [&[u8; 4]; 2] = [b"hsqs", b"sqsh"];

/// Signature payload: the SHA-1 digest, then a KCDSA signature and
/// optionally an `EdDSA` signature (`MikroTikPatch` `sign`: `20+48+64`).
const SHA1_SIZE: usize = 20;
const KCDSA_SIZE: usize = 48;
const EDDSA_SIZE: usize = 64;

/// One part: its type, the file offset of its 6-byte header and of its
/// payload, and the payload size.
#[derive(Debug, Clone, Copy)]
struct Part {
    kind: u16,
    header_offset: usize,
    offset: usize,
    size: usize,
}

impl Part {
    /// The payload; parts are built inside the package.
    fn payload(self, data: &[u8]) -> &[u8] {
        &data[self.offset..self.offset + self.size]
    }

    /// The 6-byte part header.
    fn header(self, data: &[u8]) -> &[u8] {
        &data[self.header_offset..self.offset]
    }
}

/// The name of a documented part type.
fn part_name(id: u16) -> Option<&'static str> {
    PART_TYPES.iter().find(|t| t.id == id).map(|t| t.name)
}

/// The magic, then a first part header of a documented type whose payload
/// fits the declared package size.
pub(super) fn detect(data: &[u8]) -> bool {
    let (Ok(magic), Ok(declared), Ok(first_type), Ok(first_size)) = (
        le_u32(data, 0),
        le_u32(data, 4),
        le_u16(data, HEADER_SIZE),
        le_u32(data, HEADER_SIZE + 2),
    ) else {
        return false;
    };
    magic == NPK_MAGIC
        && part_name(first_type).is_some()
        && to_usize(declared)
            .checked_sub(PART_HEADER_SIZE)
            .is_some_and(|room| to_usize(first_size) <= room)
}

/// Parse an NPK package: walk its parts, decode its file containers, list
/// its recognized files and `SquashFS` images, and check its SHA-1 digests.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, HEADER_SIZE, "NPK header")?;
    let magic = le_u32(header, 0)?;
    if magic != NPK_MAGIC {
        return Err(error(format!("Invalid NPK magic 0x{magic:08X}")));
    }
    let declared = to_usize(le_u32(header, 4)?);
    let available = data.len() - HEADER_SIZE;
    if declared > available {
        return Err(error(format!(
            "Truncated NPK package: {declared} B declared after the header, {available} B present"
        )));
    }
    let end = HEADER_SIZE + declared;
    let parts = parts(data, end)?;
    expect_padding(data, end, "NPK package")?;

    let mut c = Container::new(FileFormat::MikrotikNpk, Layout::MikrotikNpk.label(), "npk");
    c.consumed = end;
    let mut reader = Reader::default();
    for &part in &parts {
        reader.read(data, part, &mut c);
    }
    reader.finish(parts.len(), &mut c);
    Ok(c)
}

/// The parts that tile `data[HEADER_SIZE..end]`.
fn parts(data: &[u8], end: usize) -> Result<Vec<Part>> {
    let package = &data[..end];
    let mut parts = Vec::new();
    let mut pos = HEADER_SIZE;
    while pos < end {
        if parts.len() == MAX_PARTS {
            return Err(error(format!(
                "Unsupported NPK package: more than {MAX_PARTS} parts"
            )));
        }
        let header = slice(package, pos, PART_HEADER_SIZE, "NPK part header")?;
        let kind = le_u16(header, 0)?;
        let size = to_usize(le_u32(header, 2)?);
        let offset = pos + PART_HEADER_SIZE;
        let left = end - offset;
        if size > left {
            return Err(error(format!(
                "Truncated NPK part 0x{kind:02X} at 0x{pos:X}: {size} B declared, {left} B left in the package"
            )));
        }
        parts.push(Part {
            kind,
            header_offset: pos,
            offset,
            size,
        });
        pos = offset + size;
    }
    Ok(parts)
}

/// Name, version and build time of a `NAME_INFO` or `PKG_INFO` part.
#[derive(Debug)]
struct PackageInfo {
    name: String,
    version: String,
    build_time: u32,
}

/// The package information in `payload`, when it holds at least the name,
/// version and build time.
fn package_info(payload: &[u8]) -> Option<PackageInfo> {
    if payload.len() < INFO_MIN_SIZE {
        return None;
    }
    let version: [u8; 4] = array(payload, INFO_VERSION).ok()?;
    Some(PackageInfo {
        name: display_text(until_nul(&payload[..INFO_NAME_SIZE])),
        version: version_text(version),
        build_time: le_u32(payload, INFO_BUILD_TIME).ok()?,
    })
}

/// A version from its bytes revision, build code, minor and major, written
/// the way `MikroTikPatch` `decode_version` does: `7.15` and `7.15.1` for
/// final builds, `7.16beta3`, `7.15rc2`, `7.16alpha1` and `7.15test2`
/// otherwise.
fn version_text(version: [u8; 4]) -> String {
    let [revision, build, minor, major] = version;
    let base = format!("{major}.{minor}");
    match build {
        BUILD_ALPHA => format!("{base}alpha{revision}"),
        BUILD_BETA => format!("{base}beta{revision}"),
        BUILD_RC => format!("{base}rc{revision}"),
        BUILD_FINAL if revision & REVISION_TEST != 0 => {
            format!("{base}test{}", revision & !REVISION_TEST)
        }
        BUILD_FINAL if revision == 0 => base,
        BUILD_FINAL => format!("{base}.{revision}"),
        _ => format!("{base}.{revision} (build code {build})"),
    }
}

/// Counts of file container entries by type.
#[derive(Debug, Default)]
struct EntryCounts {
    files: usize,
    directories: usize,
    symlinks: usize,
    other: usize,
}

impl EntryCounts {
    fn total(&self) -> usize {
        self.files + self.directories + self.symlinks + self.other
    }
}

impl std::fmt::Display for EntryCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}, {}, {}",
            counted(self.total(), "entry", "entries"),
            counted(self.files, "file", "files"),
            counted(self.directories, "directory", "directories"),
            counted(self.symlinks, "symbolic link", "symbolic links")
        )?;
        if self.other > 0 {
            write!(f, ", {} of another type", self.other)?;
        }
        Ok(())
    }
}

/// The running SHA-1 over the parts of the current package
/// (`MikroTikPatch` `get_digest`).
#[derive(Debug, Default)]
struct PackageDigest {
    hasher: Sha1,
}

impl PackageDigest {
    /// Start a new package's digest.
    fn restart(&mut self) {
        self.hasher = Sha1::new();
    }

    /// Add a part before the signature: its header and payload. `HEADER`
    /// parts are not covered.
    fn add(&mut self, data: &[u8], part: Part) {
        if part.kind == HEADER {
            return;
        }
        self.hasher.update(part.header(data));
        self.hasher.update(part.payload(data));
    }

    /// The digest of the parts so far and the signature part's own header;
    /// the next package starts after it.
    fn finish(&mut self, data: &[u8], signature: Part) -> [u8; SHA1_SIZE] {
        self.hasher.update(signature.header(data));
        std::mem::take(&mut self.hasher).finish()
    }
}

/// State while the parts are read in order.
#[derive(Debug, Default)]
struct Reader {
    /// A `PKG_FEATURES` part was seen: later `NAME_INFO` parts start
    /// member packages.
    bundle: bool,
    /// The bundle's own information (`PKG_INFO`).
    bundle_info: Option<PackageInfo>,
    /// Packages in part order (`NAME_INFO`).
    packages: Vec<PackageInfo>,
    digest: PackageDigest,
    /// Decoded file container bytes, counted against [`MAX_EXTRACTED`].
    decoded: usize,
    members: Members,
    /// Architecture part values, in part order, without repeats.
    architectures: Vec<String>,
    description: Option<String>,
    /// Part types not documented by the sources, with their file offsets.
    undocumented: Vec<String>,
}

impl Reader {
    /// The label prefix of a member of the current package: its name in a
    /// bundle, nothing otherwise.
    fn prefix(&self) -> String {
        match self.packages.last() {
            Some(package) if self.bundle => format!("{}/", package.name),
            _ => String::new(),
        }
    }

    fn read<'a>(&mut self, data: &'a [u8], part: Part, c: &mut Container<'a>) {
        let payload = part.payload(data);
        match part.kind {
            NAME_INFO => {
                if self.bundle {
                    self.digest.restart();
                }
                match package_info(payload) {
                    Some(info) => self.packages.push(info),
                    None => c.notes.push(format!(
                        "Package information part at 0x{:X} holds {} B, too few for a name and version",
                        part.header_offset,
                        payload.len()
                    )),
                }
            }
            PKG_INFO => self.bundle_info = package_info(payload),
            PKG_FEATURES => self.bundle = true,
            DESCRIPTION if self.description.is_none() => {
                self.description = Some(display_text(until_nul(payload)));
            }
            ARCHITECTURE => {
                let architecture = display_text(until_nul(payload));
                if !self.architectures.contains(&architecture) {
                    self.architectures.push(architecture);
                }
            }
            FILE_CONTAINER => self.file_container(data, part, c),
            SQUASHFS => self.squashfs(part, payload, c),
            SIGNATURE => self.signature(data, part, c),
            kind if part_name(kind).is_none() => self
                .undocumented
                .push(format!("0x{kind:02X} at 0x{:X}", part.header_offset)),
            _ => {}
        }
        if part.kind != SIGNATURE {
            self.digest.add(data, part);
        }
    }

    /// Decode a file container and list its recognized files. A stream
    /// that does not decode is listed as opaque with a note, so the rest
    /// of the package still reports.
    fn file_container<'a>(&mut self, data: &'a [u8], part: Part, c: &mut Container<'a>) {
        let stored = part.payload(data);
        let label = format!("{}File container", self.prefix());
        let limit = MAX_EXTRACTED.saturating_sub(self.decoded).min(MAX_PAYLOAD);
        let (decoded, complete) = match compressed::decode_limited(Codec::Zlib, stored, limit) {
            Ok(decoded) => (decoded.data, true),
            Err(e) => match compressed::decode_prefix(Codec::Zlib, stored, limit) {
                Ok(prefix) if prefix.len() == limit => (prefix, false),
                _ => {
                    c.notes.push(format!(
                        "{label} at 0x{:X}: does not decode as zlib ({e}); listed as opaque",
                        part.offset
                    ));
                    c.children.push(Child::opaque(label, part.offset, stored));
                    return;
                }
            },
        };
        self.decoded += decoded.len();
        let counts = self.entries(&decoded, complete, part, c);
        let check = if complete {
            "Adler-32 verified"
        } else {
            "decoding stopped at the extraction limit, so later entries are not listed and no integrity check was verified"
        };
        c.notes.push(format!(
            "{label} at 0x{:X}: {} stored, {} decoded; {check}; {counts}",
            part.offset,
            size_text(stored.len()),
            size_text(decoded.len())
        ));
    }

    /// Walk the entries of a decoded file container and offer its regular
    /// files as members. In a prefix (`complete` false) the last entry may
    /// be cut off; in a whole stream every entry must fit.
    fn entries(
        &mut self,
        decoded: &[u8],
        complete: bool,
        part: Part,
        c: &mut Container<'_>,
    ) -> EntryCounts {
        let prefix = self.prefix();
        let mut counts = EntryCounts::default();
        let mut pos = 0;
        while pos < decoded.len() {
            let Some(entry) = file_entry(decoded, pos) else {
                if complete {
                    c.notes.push(format!(
                        "File container at 0x{:X}: entry at decoded offset 0x{pos:X} is truncated; the rest is not listed",
                        part.offset
                    ));
                }
                break;
            };
            match entry.file_type {
                TYPE_FILE => {
                    counts.files += 1;
                    let member = DecodedMember {
                        label: format!("{prefix}{}", display_text(entry.name)),
                        contents: entry.contents,
                    };
                    self.members
                        .offer(c, member, part.offset, part.size, Codec::Zlib.name());
                }
                TYPE_DIRECTORY => counts.directories += 1,
                TYPE_SYMLINK => counts.symlinks += 1,
                _ => counts.other += 1,
            }
            pos = entry.end;
        }
        counts
    }

    /// List a `SquashFS` part: as a component when it starts with a `SquashFS`
    /// magic, otherwise as opaque bytes.
    fn squashfs<'a>(&mut self, part: Part, payload: &'a [u8], c: &mut Container<'a>) {
        let label = format!("{}SquashFS image", self.prefix());
        if payload.is_empty() {
            c.notes.push(format!(
                "{label} part at 0x{:X} is empty",
                part.header_offset
            ));
            return;
        }
        if SQUASHFS_MAGICS
            .iter()
            .any(|magic| payload.starts_with(*magic))
        {
            c.children.push(Child::stored(label, part.offset, payload));
            return;
        }
        c.notes.push(format!(
            "{label} part at 0x{:X} does not start with a SquashFS magic; listed as opaque",
            part.header_offset
        ));
        c.children.push(Child::opaque(label, part.offset, payload));
    }

    /// Check a signature part's SHA-1 digest against the package's parts.
    /// A mismatch is noted, not rejected: the digest's coverage comes from
    /// one tool (see the module documentation). The KCDSA and `EdDSA`
    /// signatures need `MikroTik`'s keys and are not verified.
    fn signature(&mut self, data: &[u8], part: Part, c: &mut Container<'_>) {
        let computed = self.digest.finish(data, part);
        let payload = part.payload(data);
        let owner = match self.packages.last() {
            Some(package) => format!("Package {}", package.name),
            None => "Package".to_string(),
        };
        let Some(stored) = payload.get(..SHA1_SIZE) else {
            c.notes.push(format!(
                "{owner}: signature part at 0x{:X} holds {} B, too few for a SHA-1 digest; not verified",
                part.header_offset,
                payload.len()
            ));
            return;
        };
        let digest = if stored == computed {
            "SHA-1 digest verified"
        } else {
            "SHA-1 digest does not match the parts before it"
        };
        let signatures = match payload.len() - SHA1_SIZE {
            KCDSA_SIZE => format!("KCDSA signature ({KCDSA_SIZE} B) present, not verified"),
            n if n == KCDSA_SIZE + EDDSA_SIZE => format!(
                "KCDSA ({KCDSA_SIZE} B) and EdDSA ({EDDSA_SIZE} B) signatures present, not verified"
            ),
            0 => "no signature after the digest".to_string(),
            n => format!("{n} B of signature data after the digest, not verified"),
        };
        c.notes.push(format!("{owner}: {digest}; {signatures}"));
    }

    /// Summary notes and metadata.
    fn finish(&self, part_count: usize, c: &mut Container<'_>) {
        let mut summary = format!("MikroTik NPK: {}", counted(part_count, "part", "parts"));
        if let Some(bundle) = &self.bundle_info {
            let _ = write!(summary, "; bundle {} {}", bundle.name, bundle.version);
        }
        if !self.packages.is_empty() {
            let names: Vec<String> = self
                .packages
                .iter()
                .map(|p| format!("{} {}", p.name, p.version))
                .collect();
            let noun = if names.len() == 1 {
                "package"
            } else {
                "packages"
            };
            let _ = write!(summary, "; {noun}: {}", bounded_list(&names));
        }
        c.notes.insert(0, summary);
        if !self.architectures.is_empty() {
            c.notes.push(format!(
                "Architecture part names {}; the NPK format does not document which ISA a name stands for, so the ISA comes from the contained files",
                bounded_list(&self.architectures)
            ));
        }
        if !self.undocumented.is_empty() {
            c.notes.push(format!(
                "Undocumented part types: {}",
                bounded_list(&self.undocumented)
            ));
        }
        self.members.push_notes(c);
        let info = self.bundle_info.as_ref().or(self.packages.first());
        if let Some(info) = info {
            c.push_metadata("npk_package_name", "Package name", info.name.clone());
            c.push_metadata("npk_version", "Version", info.version.clone());
            c.push_metadata(
                "npk_build_time",
                "Build time (Unix seconds)",
                u64::from(info.build_time),
            );
        }
        if !self.architectures.is_empty() {
            c.push_metadata(
                "npk_architecture",
                "Architecture part",
                bounded_list(&self.architectures),
            );
        }
        if let Some(description) = &self.description {
            c.push_metadata("npk_description", "Description", description.clone());
        }
        c.push_metadata("npk_part_count", "Parts", part_count as u64);
    }
}

/// One file container entry, in decoded coordinates.
#[derive(Debug)]
struct FileEntry<'d> {
    file_type: u8,
    name: &'d [u8],
    contents: &'d [u8],
    /// Decoded offset just past the entry.
    end: usize,
}

/// The entry at `pos` of a decoded file container, if it lies whole in
/// `decoded`.
fn file_entry(decoded: &[u8], pos: usize) -> Option<FileEntry<'_>> {
    let header = decoded.get(pos..pos.checked_add(ENTRY_HEADER_SIZE)?)?;
    let data_size = to_usize(le_u32(header, ENTRY_DATA_SIZE).ok()?);
    let name_size = usize::from(le_u16(header, ENTRY_NAME_SIZE).ok()?);
    let name_start = pos + ENTRY_HEADER_SIZE;
    let data_start = name_start.checked_add(name_size)?;
    let end = data_start.checked_add(data_size)?;
    Some(FileEntry {
        file_type: header[ENTRY_TYPE],
        name: decoded.get(name_start..data_start)?,
        contents: decoded.get(data_start..end)?,
        end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_read_like_routeros_names_them() {
        assert_eq!(version_text([1, BUILD_FINAL, 15, 7]), "7.15.1");
        assert_eq!(version_text([0, BUILD_FINAL, 15, 7]), "7.15");
        assert_eq!(version_text([3, BUILD_BETA, 16, 7]), "7.16beta3");
        assert_eq!(version_text([2, BUILD_RC, 15, 7]), "7.15rc2");
        assert_eq!(version_text([1, BUILD_ALPHA, 16, 7]), "7.16alpha1");
        assert_eq!(version_text([0x82, BUILD_FINAL, 15, 7]), "7.15test2");
        assert_eq!(version_text([4, 1, 49, 6]), "6.49.4 (build code 1)");
    }

    #[test]
    fn detection_needs_a_documented_first_part_that_fits() {
        let mut header = NPK_MAGIC.to_le_bytes().to_vec();
        header.extend_from_slice(&42u32.to_le_bytes());
        header.extend_from_slice(&NAME_INFO.to_le_bytes());
        header.extend_from_slice(&36u32.to_le_bytes());
        assert!(detect(&header));
        let mut undocumented = header.clone();
        undocumented[8] = 0x0b;
        assert!(!detect(&undocumented));
        let mut oversized = header.clone();
        oversized[10] = 37;
        assert!(!detect(&oversized));
        assert!(!detect(&header[..13]));
    }

    #[test]
    fn file_entries_must_lie_whole_in_the_stream() {
        let mut entry = vec![0u8; ENTRY_HEADER_SIZE];
        entry[ENTRY_TYPE] = TYPE_FILE;
        entry[ENTRY_DATA_SIZE] = 3;
        entry[ENTRY_NAME_SIZE] = 2;
        entry.extend_from_slice(b"ab123");
        let parsed = file_entry(&entry, 0).expect("whole entry");
        assert_eq!(parsed.name, b"ab");
        assert_eq!(parsed.contents, b"123");
        assert_eq!(parsed.end, entry.len());
        assert!(file_entry(&entry[..entry.len() - 1], 0).is_none());
    }
}
