//! Console disc images: `GameCube` and Wii disc images, and Xbox and Xbox
//! 360 game discs in the XDVDFS filesystem (XISO images and full XGD1,
//! XGD2 and XGD3 disc images).
//!
//! Sources (pins and hashes in `docs/discs.md`):
//! - `GameCube` and Wii: Dolphin tag `2606` (`6094cfcf7b8f`),
//!   `Source/Core/DiscIO/DiscUtils.h` and `DiscUtils.cpp` (magics, header
//!   addresses, DOL, FST and apploader sizes, partition types),
//!   `Volume.cpp` (detection order), `VolumeDisc.cpp` (header fields),
//!   `VolumeGC.cpp`, `VolumeWii.cpp` (partition table, offset shift),
//!   `VolumeVerifier.cpp` (partition header data size, normal positions),
//!   `FileSystemGCWii.cpp` and `.h` (FST layout and validation),
//!   `Enums.h` (region codes), `Core/Boot/DolReader.h` (DOL header) and
//!   `Core/Boot/Boot_BS2Emu.cpp` (how the apploader is loaded and run);
//!   YAGCD chapter 13 "DVD Structure" (disc header, `bi2.bin`, apploader
//!   header, FST entries). See [`gamecube`] and [`wii`].
//! - XDVDFS: extract-xiso `3f5b62cfe68f` `extract-xiso.c`
//!   (`verify_xiso`, `traverse_xiso`, partition offsets); xdvdfs
//!   `6b05af7fba79` `xdvdfs-core/src/layout/*.rs`, `blockdev/offset.rs` and
//!   `read/dirent_table.rs`; xenia `1a8068b151bf`
//!   `src/xenia/vfs/devices/disc_image_device.cc`; `XboxDevWiki` "XDVDFS"
//!   (oldid 7031). See [`xdvdfs`].
//!
//! None of these formats names an ISA. The `GameCube` apploader is the one
//! exception the sources establish: Dolphin loads it to 0x81200000 and runs
//! it on the emulated PowerPC in big-endian mode, so that child carries a
//! PowerPC target. Executables (the boot DOL, XBE and XEX files) are
//! classified by their own parsers, and Wii partitions are encrypted and
//! never reach the code model.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;

mod gamecube;
mod wii;
mod xdvdfs;

/// Disc header size, `boot.bin` (`DISCHEADER_SIZE`).
const DISC_HEADER_SIZE: usize = 0x440;

/// Game code (4 characters) and maker code (2): Dolphin's game ID.
const GAME_ID_SIZE: usize = 6;

/// Disc number and version bytes of the disc header.
const DISC_NUMBER_OFFSET: usize = 6;
const VERSION_OFFSET: usize = 7;

/// The game name: 0x3E0 bytes at 0x20 (YAGCD 13.1), NUL-terminated.
const TITLE_OFFSET: usize = 0x20;
const TITLE_SIZE: usize = 0x3E0;

/// Deepest directory nesting that is walked.
const MAX_DEPTH: usize = 64;

/// Longest member path that is listed (Linux `PATH_MAX`, as for the
/// other filesystem families).
const MAX_PATH: usize = 4096;

/// Bytes of a file that are probed for a recognized format before the
/// whole file is checked.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Where an XDVDFS game partition starts in the image (xdvdfs
/// `XDVDFSOffsets`; extract-xiso `GLOBAL_LSEEK_OFFSET`, `XGD3_LSEEK_OFFSET`
/// and `XGD1_LSEEK_OFFSET`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdvdfsImage {
    /// An XISO image: the game partition alone, starting at 0.
    Xiso,
    /// A full XGD1 (Xbox) disc image: the game partition at 0x18300000.
    Xgd1,
    /// A full XGD2 (Xbox 360) disc image: the game partition at 0xFD90000.
    Xgd2,
    /// A full XGD3 (Xbox 360) disc image: the game partition at 0x2080000.
    Xgd3,
}

impl XdvdfsImage {
    /// Every image kind, in the order xdvdfs tries them.
    const ALL: [Self; 4] = [Self::Xiso, Self::Xgd1, Self::Xgd2, Self::Xgd3];

    /// File offset of the game partition, in bytes.
    pub fn partition_offset(self) -> usize {
        match self {
            Self::Xiso => 0,
            Self::Xgd1 => 0x1830_0000,
            Self::Xgd2 => 0x0FD9_0000,
            Self::Xgd3 => 0x0208_0000,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Xiso => "XDVDFS image",
            Self::Xgd1 => "XGD1 disc image",
            Self::Xgd2 => "XGD2 disc image",
            Self::Xgd3 => "XGD3 disc image",
        }
    }
}

/// A console disc image layout recognized by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `GameCube` disc image (magic 0xC2339F3D at 0x1C).
    GameCube,
    /// Wii disc image (magic 0x5D1C9EA3 at 0x18).
    Wii,
    /// Xbox or Xbox 360 XDVDFS image (`MICROSOFT*XBOX*MEDIA` at sector 32
    /// of the game partition).
    Xdvdfs(XdvdfsImage),
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::GameCube => FileFormat::GameCubeDisc,
            Self::Wii => FileFormat::WiiDisc,
            Self::Xdvdfs(_) => FileFormat::XboxDvd,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::GameCube => "GameCube disc image",
            Self::Wii => "Wii disc image",
            Self::Xdvdfs(image) => image.label(),
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic of 4 or 20 bytes, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::GameCube | Self::Wii | Self::Xdvdfs(_) => false,
        }
    }
}

/// Strong recognition: the Wii magic at 0x18, then the `GameCube` magic at
/// 0x1C (the order of Dolphin's `TryCreateDisc`), then the XDVDFS volume
/// descriptor magic at each documented game partition start.
pub fn detect(data: &[u8]) -> Option<Layout> {
    wii::detect(data)
        .or_else(|| gamecube::detect(data))
        .or_else(|| xdvdfs::detect(data))
}

/// Parse a console disc image into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::ConsoleDiscParseError`] for a truncated or
/// inconsistent disc header, apploader, boot DOL, FST, partition table,
/// partition header, volume descriptor or directory table. A file whose
/// bytes lie outside a truncated image is not an error; it is left out and
/// counted in a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::GameCube => gamecube::parse(data),
        Layout::Wii => wii::parse(data),
        Layout::Xdvdfs(image) => xdvdfs::parse(data, image),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ConsoleDiscParseError {
        message: message.into(),
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

/// The bytes `start..start + len` for a range read from the image, or
/// `None` when it does not lie in `data`.
fn range(data: &[u8], start: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(start).ok()?;
    let len = usize::try_from(len).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
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

/// A file offset read from the image, as `usize`.
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// Text up to the first NUL of `raw`: ASCII kept, every other byte shown
/// as U+FFFD. Disc headers and `GameCube` FST names may be Shift-JIS, which
/// is not decoded.
fn ascii_text(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// The fields `GameCube` and Wii disc headers share (YAGCD 13.1; Dolphin
/// `VolumeDisc`).
struct DiscHeader {
    /// Game code and maker code (Dolphin's game ID).
    game_id: String,
    /// Disc number, 0 for the first disc.
    disc_number: u8,
    /// Version (Dolphin's revision).
    version: u8,
    /// Game name.
    title: String,
}

/// The shared disc header fields; the image must hold the whole 0x440-byte
/// header.
fn disc_header(data: &[u8]) -> Result<DiscHeader> {
    if data.len() < DISC_HEADER_SIZE {
        return Err(error(format!(
            "Truncated disc header: {} B of {DISC_HEADER_SIZE} B",
            data.len()
        )));
    }
    Ok(DiscHeader {
        game_id: ascii_text(slice(data, 0, GAME_ID_SIZE)?),
        disc_number: data[DISC_NUMBER_OFFSET],
        version: data[VERSION_OFFSET],
        title: ascii_text(slice(data, TITLE_OFFSET, TITLE_SIZE)?)
            .trim()
            .to_string(),
    })
}

/// Notes and metadata for the shared disc header fields.
fn push_disc_header(c: &mut Container<'_>, header: &DiscHeader) {
    let prefix = c.key_prefix;
    c.notes.push(format!(
        "Game ID {}; disc {}; version {}; title \"{}\"",
        header.game_id,
        u16::from(header.disc_number) + 1,
        header.version,
        header.title
    ));
    c.push_metadata(
        format!("{prefix}_game_id"),
        "Game ID",
        header.game_id.clone(),
    );
    c.push_metadata(
        format!("{prefix}_disc_number"),
        "Disc number (0 = first disc)",
        u64::from(header.disc_number),
    );
    c.push_metadata(
        format!("{prefix}_version"),
        "Version",
        u64::from(header.version),
    );
    c.push_metadata(format!("{prefix}_title"), "Title", header.title.clone());
}

/// Name of a region code (Dolphin `Enums.h`, `Region`).
fn region_name(code: u32) -> &'static str {
    match code {
        0 => "NTSC-J",
        1 => "NTSC-U",
        2 => "PAL",
        3 => "region free",
        4 => "NTSC-K",
        _ => "unknown",
    }
}

/// Note and metadata for a region code.
fn push_region(c: &mut Container<'_>, code: u32) {
    let prefix = c.key_prefix;
    c.notes
        .push(format!("Region code {code} ({})", region_name(code)));
    c.push_metadata(format!("{prefix}_region"), "Region code", u64::from(code));
}

/// `n` with the singular or plural noun.
fn counted(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// Whether a directory at `depth` with path `path` is walked.
fn is_walkable(depth: usize, path: &str) -> bool {
    depth <= MAX_DEPTH && path.len() <= MAX_PATH
}

/// Whether the first bytes of `bytes` are a recognized format: the probe
/// that keeps unrecognized files from being run through every detector in
/// full.
fn is_prefix_recognized(bytes: &[u8]) -> bool {
    container::is_recognized(&bytes[..bytes.len().min(RECOGNITION_PREFIX)])
}

/// Lists the files of a disc filesystem that are a recognized format, as
/// children, within the component and extraction limits, and counts what
/// it left out. Files are stored contiguously, so listing one borrows its
/// bytes. The work is still bounded by [`MAX_EXTRACTED`]: every probe is
/// charged one recognition prefix, and every file checked in full (and
/// then classified when listed) its whole size, before the work happens.
struct Members<'a> {
    /// Whether a file's bytes deserve the full recognition check.
    probe: fn(&[u8]) -> bool,
    listed: Vec<Child<'a>>,
    /// Bytes charged so far against [`MAX_EXTRACTED`].
    charged: usize,
    /// Files the walk found.
    files: usize,
    /// Files not examined once [`MAX_COMPONENTS`] were listed.
    over_component_limit: usize,
    /// Files not examined or not listed because of [`MAX_EXTRACTED`].
    over_extraction_limit: usize,
    /// Files that passed the probe but are larger than [`MAX_PAYLOAD`].
    too_large: usize,
    /// Files whose bytes lie outside the image.
    outside: usize,
    /// The first file outside the image.
    first_outside: Option<String>,
    /// Directories not walked because of [`MAX_DEPTH`] or [`MAX_PATH`].
    unwalked_directories: usize,
}

impl<'a> Members<'a> {
    fn new(probe: fn(&[u8]) -> bool) -> Self {
        Self {
            probe,
            listed: Vec::new(),
            charged: 0,
            files: 0,
            over_component_limit: 0,
            over_extraction_limit: 0,
            too_large: 0,
            outside: 0,
            first_outside: None,
            unwalked_directories: 0,
        }
    }

    /// Examine the file `path` stored at `offset` with `size` bytes, and
    /// list it when it is a recognized format.
    fn offer(&mut self, data: &'a [u8], path: &str, offset: u64, size: u64) {
        self.files += 1;
        let Some(bytes) = range(data, offset, size) else {
            self.outside += 1;
            if self.first_outside.is_none() {
                self.first_outside = Some(format!("{path} at 0x{offset:X} + {size} B"));
            }
            return;
        };
        if bytes.is_empty() {
            return;
        }
        if self.listed.len() >= MAX_COMPONENTS {
            self.over_component_limit += 1;
            return;
        }
        if !self.charge(RECOGNITION_PREFIX) {
            self.over_extraction_limit += 1;
            return;
        }
        if !(self.probe)(bytes) {
            return;
        }
        if bytes.len() > MAX_PAYLOAD {
            self.too_large += 1;
            return;
        }
        if !self.charge(bytes.len()) {
            self.over_extraction_limit += 1;
            return;
        }
        if container::is_recognized(bytes) {
            let offset = usize::try_from(offset).expect("the range lies in the image");
            self.listed
                .push(Child::stored(path, offset, bytes).if_recognized());
        }
    }

    /// Charge `size` bytes of work, or return false once [`MAX_EXTRACTED`]
    /// would pass.
    fn charge(&mut self, size: usize) -> bool {
        match self.charged.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.charged = total;
                true
            }
            _ => false,
        }
    }

    /// Move the listed members into `c` and record what was found and
    /// what was left out.
    fn finish(self, c: &mut Container<'a>) {
        let prefix = c.key_prefix;
        c.notes.push(format!(
            "{}; {} in a recognized format listed",
            counted(self.files, "file", "files"),
            self.listed.len()
        ));
        if self.over_component_limit > 0 {
            c.notes.push(format!(
                "Member limit reached ({MAX_COMPONENTS} members); not examined: {}",
                counted(self.over_component_limit, "further file", "further files")
            ));
        }
        if self.over_extraction_limit > 0 {
            c.notes.push(format!(
                "Extraction limit reached ({}); not examined or not listed: {}",
                size_text(MAX_EXTRACTED),
                counted(self.over_extraction_limit, "file", "files")
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "Not examined: {} over the {} member limit",
                counted(self.too_large, "file", "files"),
                size_text(MAX_PAYLOAD)
            ));
        }
        if let Some(first) = &self.first_outside {
            c.notes.push(format!(
                "Not listed: {} outside the image; first: {first}",
                counted(self.outside, "file", "files")
            ));
        }
        if self.unwalked_directories > 0 {
            c.notes.push(format!(
                "Not walked: {} nested deeper than {MAX_DEPTH} levels or {MAX_PATH} B",
                counted(self.unwalked_directories, "directory", "directories")
            ));
        }
        c.push_metadata(format!("{prefix}_files"), "Files", self.files as u64);
        c.children.extend(self.listed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_HEADER: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";

    #[test]
    fn ascii_text_stops_at_nul_and_replaces_other_bytes() {
        assert_eq!(ascii_text(b"ZELDA\0junk"), "ZELDA");
        assert_eq!(ascii_text(b"A\x82\xA0B"), "A\u{FFFD}\u{FFFD}B");
        assert_eq!(ascii_text(b""), "");
    }

    #[test]
    fn ranges_outside_the_image_are_none() {
        let data = [0u8; 16];
        assert_eq!(range(&data, 4, 12).map(<[u8]>::len), Some(12));
        assert!(range(&data, 4, 13).is_none());
        assert!(range(&data, u64::MAX, 2).is_none());
        assert!(slice(&data, usize::MAX, 2).is_err());
    }

    #[test]
    fn members_list_recognized_files_and_count_the_rest() {
        let mut data = vec![0u8; 64];
        data[..ELF_HEADER.len()].copy_from_slice(ELF_HEADER);
        let mut members = Members::new(is_prefix_recognized);
        members.offer(&data, "/elf", 0, 32);
        members.offer(&data, "/zeros", 32, 32);
        members.offer(&data, "/outside", 48, 32);
        assert_eq!(members.files, 3);
        assert_eq!(members.listed.len(), 1);
        assert_eq!(members.listed[0].label, "/elf");
        assert_eq!(members.outside, 1);
        assert_eq!(
            members.first_outside.as_deref(),
            Some("/outside at 0x30 + 32 B")
        );
    }

    #[test]
    fn members_charge_probes_and_listings_to_the_extraction_limit() {
        let mut data = vec![0u8; 64];
        data[..ELF_HEADER.len()].copy_from_slice(ELF_HEADER);
        let mut members = Members::new(is_prefix_recognized);
        members.offer(&data, "/elf", 0, 32);
        assert_eq!(members.charged, RECOGNITION_PREFIX + 32);
        // Room for the probe of the next file, not for checking it in full.
        members.charged = MAX_EXTRACTED - RECOGNITION_PREFIX;
        members.offer(&data, "/elf", 0, 32);
        assert_eq!(members.over_extraction_limit, 1);
        // No room for a probe.
        members.offer(&data, "/elf", 0, 32);
        assert_eq!(members.over_extraction_limit, 2);
        assert_eq!(members.listed.len(), 1);
        assert!(!members.charge(usize::MAX));
    }

    #[test]
    fn counts_take_the_right_noun() {
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(0, "file", "files"), "0 files");
        assert_eq!(counted(2, "directory", "directories"), "2 directories");
    }

    #[test]
    fn walk_limits_cover_depth_and_path_length() {
        assert!(is_walkable(MAX_DEPTH, "/a"));
        assert!(!is_walkable(MAX_DEPTH + 1, "/a"));
        assert!(!is_walkable(1, &"a".repeat(MAX_PATH + 1)));
    }

    #[test]
    fn xdvdfs_partition_offsets_match_the_sources() {
        assert_eq!(XdvdfsImage::Xiso.partition_offset(), 0);
        assert_eq!(XdvdfsImage::Xgd1.partition_offset(), 405_798_912);
        assert_eq!(XdvdfsImage::Xgd2.partition_offset(), 265_879_552);
        assert_eq!(XdvdfsImage::Xgd3.partition_offset(), 34_078_720);
    }
}
