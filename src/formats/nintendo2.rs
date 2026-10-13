//! Nintendo 3DS and Switch containers: 3DS NCSD images (CTR cart images
//! and NAND images), 3DS CTR importable archives (CIA), and Switch
//! `PartitionFs` archives (`PFS0`, the NSP package format) and gamecard
//! images (XCI) with their `HFS0` partitions.
//!
//! Primary sources (pins and hashes in `docs/nintendo2.md`):
//! - 3DS: 3dbrew "NCSD" (oldid 22570), "CIA" (oldid 22475), "Title
//!   metadata" (oldid 21319), "Template:Signature Types" (oldid 5790),
//!   "Certificates" (oldid 21325), "Ticket" (oldid 21072) and "Flash
//!   Filesystem" (oldid 23624); `Project_CTR` at `d52c2b0e`: makerom
//!   `makerom/src/cia.c`, `tmd.c` and `ncsd.c` with their headers, and
//!   ctrtool `deps/libnintendo-n3ds` (`cia.h`, `cci.h`,
//!   `CiaFsSnapshotGenerator.cpp`, `CciFsSnapshotGenerator.cpp`),
//!   `src/CiaProcess.cpp` and `deps/libbroadon-es` (`es_tmd.h`,
//!   `es_sign.h`).
//! - Switch: switchbrew "XCI" (oldid 13628) and "NCA" (oldid 14983: the
//!   PFS0 layout and the NCA header); hactool at `1d64a834`: `xci.c`,
//!   `hfs0.c` and `pfs0.c` with their headers, and `utils.c`; nstool at
//!   `cfb826ca`: `README.md` (an NSP is a `PartitionFs`) and
//!   `src/GameCardProcess.cpp`.
//!
//! None of these containers names a CPU, so the container target is always
//! unknown and the ISA comes from the members: NCCH partitions and contents
//! are classified by the NCCH parser (`retro::n3ds`), NSO and NRO files by
//! `console.rs`. Members that are not a recognized format (encrypted
//! contents, NCAs, tickets, certificates, metadata) are opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS};
use crate::types::FileFormat;
use sha2::{Digest, Sha256};

mod cia;
mod ncsd;
mod partition_fs;
mod pfs0;
mod xci;

/// A Nintendo 3DS or Switch container layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 3DS NCSD image (`NCSD` at 0x100): a CTR cart image (CCI) or a NAND
    /// image.
    Ncsd,
    /// 3DS CTR importable archive (CIA): no magic.
    Cia,
    /// Switch `PartitionFs` (`PFS0` at 0): an NSP package or an `ExeFS`.
    Pfs0,
    /// Switch gamecard image (XCI): `HEAD` at 0x100 and a root `HFS0`.
    Xci,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Ncsd => FileFormat::Ncsd,
            Self::Cia => FileFormat::Cia,
            Self::Pfs0 => FileFormat::Pfs0,
            Self::Xci => FileFormat::Xci,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ncsd => "3DS NCSD",
            Self::Cia => "3DS CIA",
            Self::Pfs0 => "Switch PFS0",
            Self::Xci => "Switch XCI",
        }
    }

    /// Recognized from complete structure rather than a magic value. A CIA
    /// has no magic; the other layouts carry one.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Cia => true,
            Self::Ncsd | Self::Pfs0 | Self::Xci => false,
        }
    }
}

/// Strong recognition: `NCSD` at 0x100 with a whole header, `HEAD` at
/// 0x100 with an `HFS0` header at the root partition offset the card
/// header names, or `PFS0` at 0 with an entry table and string table that
/// fit in the file.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if ncsd::detect(data) {
        Some(Layout::Ncsd)
    } else if xci::detect(data) {
        Some(Layout::Xci)
    } else if pfs0::detect(data) {
        Some(Layout::Pfs0)
    } else {
        None
    }
}

/// Weak recognition of a CIA: the 0x2020-byte header, the 64-byte-aligned
/// sections against the file size, a TMD with a documented signature type
/// whose content record hashes match, and contents that fill the content
/// section exactly.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    cia::detect(data).then_some(Layout::Cia)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::Nintendo2ParseError`] for a truncated or inconsistent
/// header, a partition, section, content or file outside the image, an
/// unsupported layout version, or data after the image that is not
/// padding.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Ncsd => ncsd::parse(data),
        Layout::Cia => cia::parse(data),
        Layout::Pfs0 => pfs0::parse(data),
        Layout::Xci => xci::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::Nintendo2ParseError {
        message: message.into(),
    }
}

/// Bytes of a member that are probed for a recognized format before the
/// whole member is checked.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// The NCA magics (switchbrew "NCA"): the header normally stores them
/// AES-XTS encrypted, so a plaintext magic means a decrypted header.
const NCA_MAGICS: [&[u8; 4]; 4] = [b"NCA3", b"NCA2", b"NCA1", b"NCA0"];
const NCA_MAGIC_OFFSET: usize = 0x200;

/// The file name extension of an NCA (switchbrew "XCI": `.cnmt.nca` and
/// `.nca` files). Names only select an explanatory note; they never decide
/// how a member is classified.
const NCA_EXTENSION: &str = ".nca";

/// A SHA-256 digest.
const SHA256_SIZE: usize = 32;

/// Most items one note names (mismatched hashes); the rest are counted.
const NOTE_LIST_LIMIT: usize = 8;

/// A byte range of the input: `offset` and `size` in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    offset: usize,
    size: usize,
}

impl Region {
    /// One past the last byte; callers construct regions inside the input,
    /// so the sum does not overflow.
    fn end(self) -> usize {
        self.offset + self.size
    }

    /// The bytes of the region; callers construct regions inside `data`.
    fn bytes(self, data: &[u8]) -> &[u8] {
        &data[self.offset..self.end()]
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

/// The `N` bytes at `at`, as an array.
fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(data, at)?))
}

/// The region `offset..offset + size` read from the image, if it lies in
/// the first `limit` bytes.
fn region_within(offset: u64, size: u64, limit: usize) -> Option<Region> {
    let end = offset.checked_add(size)?;
    if end > u64::try_from(limit).ok()? {
        return None;
    }
    Some(Region {
        offset: usize::try_from(offset).ok()?,
        size: usize::try_from(size).ok()?,
    })
}

/// `value` rounded up to a multiple of `alignment` (a power of two), or
/// `None` on overflow.
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    Some(value.checked_add(alignment - 1)? & !(alignment - 1))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Whether the SHA-256 of `bytes` is `expected`.
fn sha256_matches(bytes: &[u8], expected: &[u8]) -> bool {
    Sha256::digest(bytes).as_slice() == expected
}

/// A name from a string table: bytes up to the first NUL, invalid UTF-8
/// shown with replacement characters.
fn name_text(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Items listed in a note: at most [`NOTE_LIST_LIMIT`], then how many more.
fn bounded_list(items: &[String]) -> String {
    let shown = items[..items.len().min(NOTE_LIST_LIMIT)].join(", ");
    match items.len().checked_sub(NOTE_LIST_LIMIT) {
        Some(more) if more > 0 => format!("{shown} and {more} more"),
        _ => shown,
    }
}

/// `n` with the singular or plural noun.
fn counted(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// Whether `bytes` carries an NCA magic at 0x200 in plaintext.
fn has_plaintext_nca_magic(bytes: &[u8]) -> bool {
    bytes
        .get(NCA_MAGIC_OFFSET..NCA_MAGIC_OFFSET + 4)
        .is_some_and(|magic| NCA_MAGICS.iter().any(|m| magic == m.as_slice()))
}

/// What the recognition check found for a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recognition {
    /// A format the classifier recognizes.
    Recognized,
    /// No recognized format.
    Unrecognized,
    /// The prefix passed, but checking the whole member would exceed the
    /// examination budget.
    OverBudget,
}

/// The members of a container (partitions, contents, files), listed as
/// children: a member that is a recognized format is classified on its own,
/// any other member is opaque, and at most [`MAX_COMPONENTS`] are listed.
/// Members are stored contiguously, so each borrows its bytes. A member is
/// checked in full only while the bytes checked in full stay within the
/// container size, so members that overlap (PFS0 entries may) cannot
/// multiply the work.
struct Members<'a> {
    children: Vec<Child<'a>>,
    /// Bytes that may be checked in full: the container size.
    budget: usize,
    /// Bytes checked in full so far.
    examined: usize,
    /// Members found, listed or not.
    found: usize,
    /// Listed members that are a recognized format.
    recognized: usize,
    /// Listed members that are opaque because they are no recognized
    /// format.
    unrecognized: usize,
    /// Opaque members with a plaintext NCA magic.
    plaintext_nca: usize,
    /// Opaque members named like NCAs, without a plaintext magic.
    named_nca: usize,
    /// Listed members left opaque because of the budget.
    unexamined: usize,
    /// Members not listed because of [`MAX_COMPONENTS`].
    unlisted: usize,
}

impl<'a> Members<'a> {
    fn new(budget: usize) -> Self {
        Self {
            children: Vec::new(),
            budget,
            examined: 0,
            found: 0,
            recognized: 0,
            unrecognized: 0,
            plaintext_nca: 0,
            named_nca: 0,
            unexamined: 0,
            unlisted: 0,
        }
    }

    /// Probe the first [`RECOGNITION_PREFIX`] bytes of a member, then, within
    /// the budget, the whole member.
    fn recognition(&mut self, bytes: &[u8]) -> Recognition {
        let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
        if bytes.is_empty() || !container::is_recognized(prefix) {
            return Recognition::Unrecognized;
        }
        match self.examined.checked_add(bytes.len()) {
            Some(total) if total <= self.budget => {
                self.examined = total;
                if container::is_recognized(bytes) {
                    Recognition::Recognized
                } else {
                    Recognition::Unrecognized
                }
            }
            _ => Recognition::OverBudget,
        }
    }

    /// Whether another member may be listed; counts the member either way.
    fn admit(&mut self) -> bool {
        self.found += 1;
        if self.children.len() >= MAX_COMPONENTS {
            self.unlisted += 1;
            return false;
        }
        true
    }

    /// List `bytes`, stored at `offset`, under `label`: classified on its
    /// own when it is a recognized format, opaque otherwise.
    fn offer(&mut self, label: String, offset: usize, bytes: &'a [u8]) {
        if !self.admit() {
            return;
        }
        match self.recognition(bytes) {
            Recognition::Recognized => {
                self.recognized += 1;
                self.children.push(Child::stored(label, offset, bytes));
                return;
            }
            Recognition::OverBudget => {
                self.unexamined += 1;
                self.children.push(Child::opaque(label, offset, bytes));
                return;
            }
            Recognition::Unrecognized => {}
        }
        self.unrecognized += 1;
        if has_plaintext_nca_magic(bytes) {
            self.plaintext_nca += 1;
        } else if label.to_ascii_lowercase().ends_with(NCA_EXTENSION) {
            self.named_nca += 1;
        }
        self.children.push(Child::opaque(label, offset, bytes));
    }

    /// List bytes that the container's own fields mark as encrypted or as
    /// data.
    fn push_opaque(&mut self, label: String, offset: usize, bytes: &'a [u8]) {
        if self.admit() {
            self.children.push(Child::opaque(label, offset, bytes));
        }
    }

    /// Move the listed members into `c` and record what was found, what is
    /// opaque, and what was left out, counting members with `singular` and
    /// `plural`.
    fn finish(self, c: &mut Container<'a>, singular: &str, plural: &str) {
        c.notes.push(format!(
            "{}; {} in a recognized format, classified on their own",
            counted(self.found, singular, plural),
            self.recognized
        ));
        if self.unrecognized > 0 {
            c.notes.push(format!(
                "{} not in a recognized format listed as opaque",
                counted(self.unrecognized, singular, plural)
            ));
        }
        if self.named_nca > 0 {
            c.notes.push(format!(
                "Opaque {plural} named {NCA_EXTENSION}: {}; NCA content archives are AES-XTS encrypted (switchbrew NCA) and are not decrypted, so their code is not analyzed",
                self.named_nca
            ));
        }
        if self.plaintext_nca > 0 {
            c.notes.push(format!(
                "{} with a plaintext NCA magic at 0x{NCA_MAGIC_OFFSET:X} (a decrypted NCA header); NCA sections are not parsed",
                counted(self.plaintext_nca, singular, plural)
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "Not examined: {} past the examination budget of {} (the container size), listed as opaque",
                counted(self.unexamined, singular, plural),
                size_text(self.budget)
            ));
        }
        if self.unlisted > 0 {
            c.notes.push(format!(
                "Member limit reached ({MAX_COMPONENTS} members); not listed: {}",
                counted(self.unlisted, singular, plural)
            ));
        }
        c.children.extend(self.children);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_HEADER: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";

    #[test]
    fn regions_must_lie_within_the_limit() {
        assert_eq!(
            region_within(4, 12, 16),
            Some(Region {
                offset: 4,
                size: 12
            })
        );
        assert_eq!(region_within(4, 13, 16), None);
        assert_eq!(region_within(u64::MAX, 2, 16), None);
        assert!(slice(&[0u8; 4], usize::MAX, 2).is_err());
    }

    #[test]
    fn alignment_rounds_up_and_detects_overflow() {
        assert_eq!(align_up(0x2020, 64), Some(0x2040));
        assert_eq!(align_up(0x2040, 64), Some(0x2040));
        assert_eq!(align_up(0, 16), Some(0));
        assert_eq!(align_up(u64::MAX, 16), None);
    }

    #[test]
    fn names_stop_at_nul_and_replace_invalid_utf8() {
        assert_eq!(name_text(b"main\0npdm"), "main");
        assert_eq!(name_text(b"a\xffb"), "a\u{FFFD}b");
        assert_eq!(name_text(b""), "");
    }

    #[test]
    fn plaintext_nca_magic_is_read_at_0x200() {
        let mut header = vec![0u8; 0x204];
        assert!(!has_plaintext_nca_magic(&header));
        header[0x200..].copy_from_slice(b"NCA3");
        assert!(has_plaintext_nca_magic(&header));
        assert!(!has_plaintext_nca_magic(&header[..0x203]));
    }

    #[test]
    fn members_classify_recognized_bytes_and_keep_the_rest_opaque() {
        let mut data = [0u8; 64];
        data[..ELF_HEADER.len()].copy_from_slice(ELF_HEADER);
        let mut members = Members::new(data.len());
        members.offer("elf".into(), 0, &data[..32]);
        members.offer("zeros".into(), 32, &data[32..]);
        members.push_opaque("ticket".into(), 0, &data[..4]);
        assert_eq!(
            (members.found, members.recognized, members.unrecognized),
            (3, 1, 1)
        );
        assert!(!members.children[0].opaque);
        assert!(members.children[1].opaque);
        assert!(members.children[2].opaque);
        let mut c = Container::new(FileFormat::Pfs0, "test", "test");
        members.finish(&mut c, "file", "files");
        assert_eq!(c.children.len(), 3);
        assert_eq!(
            c.notes[0],
            "3 files; 1 in a recognized format, classified on their own"
        );
        assert_eq!(
            c.notes[1],
            "1 file not in a recognized format listed as opaque"
        );
    }

    #[test]
    fn counts_take_the_right_noun() {
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(0, "file", "files"), "0 files");
    }

    #[test]
    fn note_lists_name_the_first_items_and_count_the_rest() {
        let items: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        assert_eq!(bounded_list(&items[..2]), "0, 1");
        assert_eq!(bounded_list(&items[..8]), "0, 1, 2, 3, 4, 5, 6, 7");
        assert_eq!(bounded_list(&items), "0, 1, 2, 3, 4, 5, 6, 7 and 2 more");
        assert_eq!(bounded_list(&[]), "");
    }
}
