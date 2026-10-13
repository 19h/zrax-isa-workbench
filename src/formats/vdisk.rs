//! Virtual disk images: QEMU QCOW2 (versions 2 and 3), `VMware` VMDK hosted
//! sparse extents (monolithic sparse and stream-optimized), Microsoft VHD
//! (fixed, dynamic and differencing) and VHDX, and `VirtualBox` VDI.
//!
//! Sources (pins and hashes in `docs/vdisk.md`):
//! - QCOW2: QEMU `v11.1.1` `docs/interop/qcow2.rst` (header, header
//!   extensions, cluster mapping, compressed clusters, extended L2 entries)
//!   and `block/qcow2.h` (reserved-bit masks, cluster size limit). See
//!   [`qcow2`].
//! - VMDK: `VMware` Technical Note "Virtual Disk Format 5.0" (EN-000777-00,
//!   2011-12-20), "Hosted Sparse Extents" and "Stream-Optimized
//!   Compressed"; QEMU `v11.1.1` `block/vmdk.c` (version 3, zlib grains,
//!   footer position). See [`vmdk`].
//! - VHD: Microsoft "Virtual Hard Disk Image Format Specification" 1.0
//!   (2006-10-11): hard disk footer, dynamic disk header, block allocation
//!   table and data blocks; QEMU `v11.1.1` `block/vpc.c`; `VirtualBox`
//!   `v7.2.20` `src/VBox/Storage/VHD.cpp` (parent name byte order, sector
//!   bitmap bit order). See [`vhd`].
//! - VHDX: [MS-VHDX] protocol revision 8.0 (2024-04-23), sections 2.2 to
//!   2.6; QEMU `v11.1.1` `block/vhdx.c` and `block/vhdx.h` (BAT entry count,
//!   header choice). See [`vhdx`].
//! - VDI: `VirtualBox` `v7.2.20` `src/VBox/Storage/VDICore.h`, `VDI.cpp`
//!   (`vdiValidatePreHeader`, `vdiValidateHeader`) and `include/VBox/vd.h`;
//!   QEMU `v11.1.1` `block/vdi.c`. See [`vdi`].
//!
//! A virtual disk stores a guest disk, not code, and none of these formats
//! names an ISA. The guest-visible disk is the container's one child at
//! offset 0: the stored bytes themselves when they lie in one contiguous
//! run (a fixed VHD, or any layout whose blocks happen to be stored in
//! order), otherwise the first `min(virtual size, MAX_PAYLOAD)` bytes
//! assembled from the allocation tables, with unallocated blocks as zeros.
//! The child is listed when it holds a recognized partition table or
//! filesystem, which then reports itself. Data that lives in a parent or
//! backing image is not present and reads as zeros here; encrypted guest
//! data is opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{self, Child, Container};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;
use std::borrow::Cow;
use std::fmt::Write;

mod qcow2;
mod vdi;
mod vhd;
mod vhdx;
mod vmdk;

/// Prefix of generated metadata keys.
const KEY_PREFIX: &str = "vdisk";

/// Bytes of the 512-byte sectors that VHD, VMDK and VDI count in.
const SECTOR_SIZE: u64 = 512;

/// Label of the guest disk child.
const GUEST_LABEL: &str = "Guest disk";

/// Longest string field shown in notes and metadata, in characters.
const MAX_TEXT: usize = 256;

/// A virtual disk layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// QEMU copy-on-write image, version 2 or 3 (magic `QFI\xfb`).
    Qcow2,
    /// `VMware` hosted sparse extent (magic `KDMV`): monolithic sparse or
    /// stream-optimized.
    Vmdk,
    /// Microsoft Virtual PC / Virtual Server disk: a `conectix` footer at
    /// the end (fixed) or a footer copy at offset 0 (dynamic, differencing).
    Vhd,
    /// Microsoft VHDX image (`vhdxfile` at offset 0).
    Vhdx,
    /// `VirtualBox` disk image (signature `0xBEDA107F` at 0x40).
    Vdi,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Qcow2 => FileFormat::Qcow2,
            Self::Vmdk => FileFormat::Vmdk,
            Self::Vhd => FileFormat::Vhd,
            Self::Vhdx => FileFormat::Vhdx,
            Self::Vdi => FileFormat::Vdi,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Qcow2 => "QCOW2 image",
            Self::Vmdk => "VMDK sparse extent",
            Self::Vhd => "VHD image",
            Self::Vhdx => "VHDX image",
            Self::Vdi => "VDI image",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout carries a magic of at least 64 bits (with its version) or a
    /// checksummed footer, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Qcow2 | Self::Vmdk | Self::Vhd | Self::Vhdx | Self::Vdi => false,
        }
    }
}

/// Strong recognition. VHD comes first: a fixed VHD is recognized by the
/// checksummed footer at its end (which must describe the file), and its
/// first sector is the guest's, so a guest that is itself an image must
/// not decide the format. Then the
/// magics at offset 0 with their versions: QCOW2 version 2 or 3, VMDK
/// `KDMV` version 1 to 3, `vhdxfile`, and the VDI signature at 0x40 with
/// header version 1 (or the old 0.2).
pub fn detect(data: &[u8]) -> Option<Layout> {
    if vhd::is_present(data) {
        return Some(Layout::Vhd);
    }
    if qcow2::is_present(data) {
        return Some(Layout::Qcow2);
    }
    if vmdk::is_present(data) {
        return Some(Layout::Vmdk);
    }
    if vhdx::is_present(data) {
        return Some(Layout::Vhdx);
    }
    if vdi::is_present(data) {
        return Some(Layout::Vdi);
    }
    None
}

/// Parse a virtual disk into the shared container model: one guest disk
/// child, notes and metadata.
///
/// # Errors
///
/// [`ClassifierError::VirtualDiskParseError`] for a truncated or
/// inconsistent header, table or block: a bad signature or checksum, an
/// unsupported version or feature, a table that does not fit in the file,
/// or a block that lies beyond its end.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Qcow2 => qcow2::parse(data),
        Layout::Vmdk => vmdk::parse(data),
        Layout::Vhd => vhd::parse(data),
        Layout::Vhdx => vhdx::parse(data),
        Layout::Vdi => vdi::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::VirtualDiskParseError {
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

/// The `len` bytes at the 64-bit file offset `start`.
fn range<'a>(data: &'a [u8], start: u64, len: u64, what: &str) -> Result<&'a [u8]> {
    match (usize::try_from(start), usize::try_from(len)) {
        (Ok(start), Ok(len)) => slice(data, start, len, what),
        _ => Err(error(format!("Truncated {what} at 0x{start:X} + {len} B"))),
    }
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "header field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

fn be_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(bytes, at)?))
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(bytes, at)?))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(bytes, at)?))
}

fn le_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(bytes, at)?))
}

/// `n / unit`, rounded up; `unit` is not zero.
fn div_ceil(n: u64, unit: u64) -> u64 {
    n / unit + u64::from(n % unit != 0)
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 30 && n % (1 << 30) == 0 {
        format!("{} GiB", n >> 30)
    } else if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `n` and the noun in the number it takes: "1 L1 entry", "6 L1 entries".
fn counted(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Display form of untrusted text: up to the first NUL, control
/// characters as `?`, cut after [`MAX_TEXT`] characters.
fn display_text(chars: impl IntoIterator<Item = char>) -> String {
    let mut text = String::new();
    for (i, ch) in chars.into_iter().take_while(|&ch| ch != '\0').enumerate() {
        if i == MAX_TEXT {
            text.push_str("...");
            break;
        }
        text.push(if ch.is_control() { '?' } else { ch });
    }
    text
}

/// An 8-bit string field (UTF-8 where valid) for display.
fn byte_text(bytes: &[u8]) -> String {
    display_text(String::from_utf8_lossy(bytes).chars())
}

/// A UTF-16 string field for display; `le` is true for little-endian code
/// units.
fn utf16_text(bytes: &[u8], le: bool) -> String {
    let units = bytes.chunks_exact(2).map(|unit| {
        let pair = [unit[0], unit[1]];
        if le {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        }
    });
    display_text(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)))
}

/// A GUID in its binary form (Microsoft `GUID`, IPRT `RTUUID`): `Data1`,
/// `Data2` and `Data3` little-endian, `Data4` as stored.
fn guid_text(bytes: [u8; 16]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = hex_digits(&bytes[8..]);
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{}-{}",
        &tail[..4],
        &tail[4..]
    )
}

/// A UUID stored in RFC 4122 byte order (big-endian fields).
fn uuid_text(bytes: [u8; 16]) -> String {
    let hex = hex_digits(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Two uppercase hex digits per byte.
fn hex_digits(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, b| {
        let _ = write!(text, "{b:02X}");
        text
    })
}

/// The image a differencing disk or overlay depends on, as its format
/// names it, for notes about the data it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parent {
    /// What the format calls it: "backing file", "parent disk".
    role: &'static str,
    /// Its name or identifier, as stored.
    reference: String,
}

/// Where a run of the guest disk comes from.
#[derive(Debug, Clone, Copy)]
enum Source<'a> {
    /// Stored bytes at this file offset.
    Stored(usize),
    /// Zeros: a block marked zero, or an unallocated block with no parent.
    Zero,
    /// Not in this file: the parent or backing image holds it. It reads as
    /// zeros here.
    Parent,
    /// Part of a compressed block, decoded when the disk is assembled.
    Compressed(CompressedBlock<'a>),
}

/// A compressed block of the guest disk.
#[derive(Debug, Clone, Copy)]
struct CompressedBlock<'a> {
    /// What the format calls the block, for errors.
    what: &'static str,
    /// File offset of the stored bytes.
    offset: usize,
    /// The stored bytes; the stream may end before them.
    stored: &'a [u8],
    /// Codecs to try, in order.
    codecs: &'static [Codec],
    /// Decoded size of the whole block, in bytes.
    block_size: usize,
    /// Offset in the decoded block where the run starts.
    skip: usize,
}

/// A contiguous run of the guest disk.
#[derive(Debug)]
struct Run<'a> {
    /// Guest bytes.
    length: usize,
    source: Source<'a>,
}

/// Guest bytes by where they come from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Coverage {
    /// Stored as-is in the file.
    stored: u64,
    /// Decoded from compressed blocks.
    compressed: u64,
    /// Zero blocks, and unallocated blocks with no parent.
    zero: u64,
    /// Held by the parent or backing image.
    parent: u64,
}

/// The guest disk, mapped run by run from guest offset 0 up to
/// `min(virtual size, MAX_PAYLOAD)`. Layouts map their blocks in guest
/// order; every push is cut at that limit.
#[derive(Debug)]
struct Guest<'a> {
    /// The whole input file.
    file: &'a [u8],
    /// Virtual disk size in bytes.
    virtual_size: u64,
    /// Guest bytes that are mapped and analyzed.
    limit: usize,
    /// Guest bytes mapped so far.
    mapped: usize,
    /// The extraction limit cut the virtual disk short.
    capped: bool,
    runs: Vec<Run<'a>>,
    coverage: Coverage,
}

impl<'a> Guest<'a> {
    fn new(file: &'a [u8], virtual_size: u64) -> Self {
        let limit = usize::try_from(virtual_size).map_or(MAX_PAYLOAD, |size| size.min(MAX_PAYLOAD));
        Self {
            file,
            virtual_size,
            limit,
            mapped: 0,
            capped: (limit as u64) < virtual_size,
            runs: Vec::new(),
            coverage: Coverage::default(),
        }
    }

    /// A guest disk that is the `length` bytes stored at `offset`, whole
    /// (a fixed VHD). It is a slice of the file, so the extraction limit
    /// does not apply.
    fn flat(file: &'a [u8], offset: usize, length: usize, virtual_size: u64) -> Self {
        Self {
            file,
            virtual_size,
            limit: length,
            mapped: length,
            capped: false,
            runs: vec![Run {
                length,
                source: Source::Stored(offset),
            }],
            coverage: Coverage {
                stored: length as u64,
                ..Coverage::default()
            },
        }
    }

    /// Blocks of `block_size` bytes that cover the mapped range.
    fn block_count(&self, block_size: u64) -> u64 {
        div_ceil(self.limit as u64, block_size)
    }

    /// `length` cut to what is left to map.
    fn clip(&self, length: u64) -> usize {
        let left = self.limit - self.mapped;
        usize::try_from(length).map_or(left, |length| length.min(left))
    }

    /// Map `length` guest bytes stored at file offset `offset`.
    fn stored(&mut self, offset: u64, length: u64, what: &str) -> Result<()> {
        let length = self.clip(length);
        if length == 0 {
            return Ok(());
        }
        range(self.file, offset, length as u64, what)?;
        let offset = usize::try_from(offset).expect("range checked the offset");
        self.coverage.stored += length as u64;
        self.push(length, Source::Stored(offset));
        Ok(())
    }

    /// Map `length` guest bytes of zeros.
    fn zero(&mut self, length: u64) {
        let length = self.clip(length);
        self.coverage.zero += length as u64;
        self.push(length, Source::Zero);
    }

    /// Map `length` guest bytes that the parent image holds.
    fn parent(&mut self, length: u64) {
        let length = self.clip(length);
        self.coverage.parent += length as u64;
        self.push(length, Source::Parent);
    }

    /// Map `length` guest bytes from a compressed block.
    fn compressed(&mut self, block: CompressedBlock<'a>, length: u64) {
        let length = self.clip(length);
        self.coverage.compressed += length as u64;
        self.push(length, Source::Compressed(block));
    }

    /// Append a run, extending the last one when it continues it.
    fn push(&mut self, length: usize, source: Source<'a>) {
        if length == 0 {
            return;
        }
        self.mapped += length;
        if let Some(last) = self.runs.last_mut() {
            let continues = match (last.source, source) {
                (Source::Stored(start), Source::Stored(next)) => start + last.length == next,
                (Source::Zero, Source::Zero) | (Source::Parent, Source::Parent) => true,
                _ => false,
            };
            if continues {
                last.length += length;
                return;
            }
        }
        self.runs.push(Run { length, source });
    }

    /// The guest disk as one child: a stored slice when it is one stored
    /// run, otherwise the assembled bytes, with `transform` naming the
    /// layout's blocks.
    fn child(&self, transform: &'static str) -> Result<Child<'a>> {
        if let [Run {
            length,
            source: Source::Stored(offset),
        }] = self.runs[..]
        {
            if length == self.limit {
                let bytes = slice(self.file, offset, length, "guest disk")?;
                return Ok(Child::stored(GUEST_LABEL, offset, bytes).if_recognized());
            }
        }
        let mut image = vec![0u8; self.limit];
        let mut at = 0usize;
        for run in &self.runs {
            let out = &mut image[at..at + run.length];
            match run.source {
                Source::Stored(offset) => {
                    out.copy_from_slice(slice(self.file, offset, run.length, "guest data")?);
                }
                Source::Zero | Source::Parent => {}
                Source::Compressed(block) => {
                    let decoded = decode_block(&block)?;
                    let part = decoded
                        .get(block.skip..block.skip + run.length)
                        .ok_or_else(|| {
                            error(format!(
                                "Invalid {} at 0x{:X}: too short",
                                block.what, block.offset
                            ))
                        })?;
                    out.copy_from_slice(part);
                }
            }
            at += run.length;
        }
        Ok(Child::decoded(
            GUEST_LABEL,
            0,
            self.file.len(),
            Cow::Owned(image),
            transform,
        )
        .if_recognized())
    }

    /// Push the guest disk child and its notes and metadata to `c`. A
    /// `parent` names the image that holds unallocated blocks.
    fn finish(
        self,
        c: &mut Container<'a>,
        transform: &'static str,
        parent: Option<&Parent>,
    ) -> Result<()> {
        c.push_metadata(
            "vdisk_virtual_size",
            "Virtual disk size (B)",
            self.virtual_size,
        );
        if self.limit == 0 {
            c.notes
                .push("Virtual disk size is 0 B: there is no guest disk to classify".into());
            return Ok(());
        }
        // Each layout checks that its tables cover the virtual size; this
        // keeps a gap from reading as zeros if one does not.
        if self.mapped != self.limit {
            return Err(error(format!(
                "Invalid {transform} map: it covers {} of {} B",
                self.mapped, self.limit
            )));
        }
        let child = self.child(transform)?;
        let coverage = self.coverage;
        if child.transform.is_none() {
            c.notes.push(format!(
                "Guest disk: {} stored contiguously at 0x{:X}",
                size_text(self.limit as u64),
                child.offset
            ));
        } else {
            c.notes.push(format!(
                "Guest disk assembled from {transform}: {} ({} B stored, {} B from compressed \
                 blocks, {} B zero or unallocated{})",
                size_text(self.limit as u64),
                coverage.stored,
                coverage.compressed,
                coverage.zero,
                if coverage.parent > 0 {
                    format!(", {} B in the parent", coverage.parent)
                } else {
                    String::new()
                }
            ));
        }
        if let Some(parent) = parent.filter(|_| coverage.parent > 0) {
            c.notes.push(format!(
                "{} B of the guest disk are not in this file: the {} {} holds them, so they read \
                 as zeros here",
                coverage.parent, parent.role, parent.reference
            ));
        }
        if self.capped {
            c.notes.push(format!(
                "Virtual disk is {}; only the first {} were assembled and analyzed",
                size_text(self.virtual_size),
                size_text(self.limit as u64)
            ));
        }
        if !container::is_recognized(&child.data) {
            c.notes.push(
                "The guest disk does not start with a recognized format (such as a partition \
                 table or filesystem), so it is not classified"
                    .into(),
            );
        }
        c.notes.push(ISA_NOTE.into());
        c.push_metadata(
            "vdisk_guest_size",
            "Guest bytes analyzed (B)",
            self.limit as u64,
        );
        c.push_metadata(
            "vdisk_stored_size",
            "Guest bytes stored (B)",
            coverage.stored,
        );
        if coverage.compressed > 0 {
            c.push_metadata(
                "vdisk_compressed_size",
                "Guest bytes from compressed blocks (B)",
                coverage.compressed,
            );
        }
        if coverage.parent > 0 {
            c.push_metadata(
                "vdisk_parent_size",
                "Guest bytes in the parent (B)",
                coverage.parent,
            );
        }
        c.children.push(child);
        Ok(())
    }
}

/// Metadata and the ISA note of a container whose guest data cannot be
/// read from this file (encrypted, or stored in another file).
fn push_unreadable(c: &mut Container<'_>, virtual_size: u64) {
    c.push_metadata("vdisk_virtual_size", "Virtual disk size (B)", virtual_size);
    c.notes.push(ISA_NOTE.into());
}

/// Why a virtual disk reports no ISA of its own.
const ISA_NOTE: &str = "Virtual disk formats name no ISA; the guest disk is classified on its own";

/// The decoded bytes of a compressed block, which must fill the block. The
/// stored bytes may run on past the end of the stream (a QCOW2 cluster's
/// last sector can hold the start of the next one), so the decode stops at
/// the block size.
fn decode_block(block: &CompressedBlock<'_>) -> Result<Vec<u8>> {
    let mut failure = String::new();
    for &codec in block.codecs {
        match compressed::decode_prefix(codec, block.stored, block.block_size) {
            Ok(decoded) if decoded.len() == block.block_size => return Ok(decoded),
            Ok(decoded) => {
                failure = format!(
                    "{} decodes to {} B of {} B",
                    codec.name(),
                    decoded.len(),
                    block.block_size
                );
            }
            Err(e) => failure = e.to_string(),
        }
    }
    Err(error(format!(
        "Invalid {} at 0x{:X}: {failure}",
        block.what, block.offset
    )))
}

/// A container of `layout` with the variant `variant` that spans `data`.
fn container_for<'a>(data: &[u8], layout: Layout, variant: impl Into<String>) -> Container<'a> {
    let mut c = Container::new(layout.format(), variant, KEY_PREFIX);
    c.consumed = data.len();
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_runs_merge_and_stop_at_the_virtual_size() {
        let file = [7u8; 4096];
        let mut guest = Guest::new(&file, 3000);
        guest.stored(0, 1024, "block").unwrap();
        guest.stored(1024, 1024, "block").unwrap();
        guest.zero(512);
        guest.parent(256);
        guest.zero(512);
        // Nothing is left to map, so this push is dropped.
        guest.stored(0, 4096, "block").unwrap();
        assert_eq!(guest.mapped, 3000);
        let lengths: Vec<usize> = guest.runs.iter().map(|run| run.length).collect();
        assert_eq!(lengths, [2048, 512, 256, 184]);
        assert_eq!(guest.coverage.stored, 2048);
        assert_eq!(guest.coverage.zero, 696);
        assert_eq!(guest.coverage.parent, 256);
    }

    #[test]
    fn one_stored_run_is_a_slice_and_others_are_assembled() {
        let file: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let mut flat = Guest::new(&file, 1024);
        flat.stored(512, 1024, "block").unwrap();
        let child = flat.child("test blocks").unwrap();
        assert_eq!(child.transform, None);
        assert_eq!(child.offset, 512);
        assert_eq!(&child.data[..], &file[512..1536]);

        let mut sparse = Guest::new(&file, 1024);
        sparse.zero(512);
        sparse.stored(0, 512, "block").unwrap();
        let child = sparse.child("test blocks").unwrap();
        assert_eq!(child.transform, Some("test blocks"));
        assert_eq!(&child.data[..512], &[0u8; 512][..]);
        assert_eq!(&child.data[512..], &file[..512]);
    }

    #[test]
    fn stored_runs_beyond_the_file_are_truncation_errors() {
        let file = [0u8; 1024];
        let mut guest = Guest::new(&file, 4096);
        let message = guest
            .stored(512, 1024, "data block")
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Virtual disk parse error: Truncated data block at 0x200 + 1024 B"
        );
        assert!(guest.stored(u64::MAX, 1, "data block").is_err());
    }

    #[test]
    fn compressed_blocks_must_fill_the_block() {
        let block: Vec<u8> = b"virtual disk block ".repeat(30)[..512].to_vec();
        let stream = miniz_oxide::deflate::compress_to_vec(&block, 6);
        let mut file = stream.clone();
        file.extend_from_slice(&[0xAB; 64]);
        let compressed = CompressedBlock {
            what: "test block",
            offset: 0,
            stored: &file,
            codecs: &[Codec::Deflate],
            block_size: 512,
            skip: 0,
        };
        assert_eq!(decode_block(&compressed).unwrap(), block);
        let short = CompressedBlock {
            block_size: 1024,
            ..compressed
        };
        assert!(decode_block(&short)
            .unwrap_err()
            .to_string()
            .contains("Invalid test block at 0x0"));
    }

    #[test]
    fn text_fields_stop_at_nul_and_hide_control_characters() {
        assert_eq!(byte_text(b"disk\x01.img\0junk"), "disk?.img");
        assert_eq!(utf16_text(&[b'a', 0, b'b', 0, 0, 0, b'c', 0], true), "ab");
        assert_eq!(utf16_text(&[0, b'a', 0, b'b'], false), "ab");
        assert_eq!(byte_text(&[b'x'; 300]).len(), MAX_TEXT + 3);
    }

    #[test]
    fn guids_and_uuids_are_formatted_from_their_byte_order() {
        let bat = [
            0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd,
            0x4a, 0x08,
        ];
        assert_eq!(guid_text(bat), "2DC27766-F623-4200-9D64-115E9BFD4A08");
        assert_eq!(uuid_text(bat), "6677C22D-23F6-0042-9D64-115E9BFD4A08");
        assert_eq!(size_text(3 << 30), "3 GiB");
        assert_eq!(size_text(174_080), "170 KiB");
        assert_eq!(div_ceil(1025, 512), 3);
    }
}
