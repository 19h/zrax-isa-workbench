//! ATR disk images.
//!
//! A 16-byte little-endian header: the magic `96 02` (0x0296, the sum of
//! the letters of `NICKATARI`) at 0, the image size in 16-byte paragraphs
//! (bits 0-15 at 2, bits 16-23 at 6) and the sector size (2) at 4 (atari800
//! `afile.h` and `SIO_Mount`; Altirra `LoadATR` and `SaveATR`; `AtariSIO`
//! `AtrImage.cpp`; Jindroush). Byte 7 is the top of the paragraph count to
//! atari800 and `AtariSIO` but part of an APE checksum to Jindroush, and the
//! write-protect flag is byte 15 to atari800 and a bit of byte 8 to
//! `AtariSIO`; none of them is interpreted.
//!
//! The sectors follow, numbered from 1. "By convention, the first three
//! sectors of a double-density disk are only 128 bytes long since the OS
//! boot loader can only load sectors of that size" (Altirra Hardware
//! Reference Manual §10.1). A 256-byte-sector image stores them as 128 bytes
//! (an image of 384 + (n - 3) * 256 bytes) or in 256-byte slots: in the
//! first half of each slot ("physical") or packed into the first 384 bytes
//! followed by 384 unused bytes ("SIO2PC"). atari800 `SIO_Mount` takes the
//! layout as physical "if there's a non-zero byte in bytes 0x190-0x30f of
//! the ATR file". Images with sectors of 512 bytes or more have no short
//! boot sectors (Altirra `LoadATR`; §10.1).
//!
//! The OS boots from sector 1: flags (copied to DFLAGS), the number of boot
//! sectors (DBSECT; 0 loads 256), the load address (BOOTAD) and the
//! initialization address (DOSINI) ("Mapping the Atari" entries 12 and
//! 576-579; `AltirraOS` `boot.s`). It copies that many 128-byte sectors,
//! from sector 1 on, to consecutive memory at the load address and calls
//! the loader at the load address + 6 (`boot.s` `BootRunLoader`; "Inside
//! Atari DOS" chapter 20). The boot sectors are therefore 6502 code, unless
//! sector 1 is empty (only 0x00 or 0xFF: no boot record) or the record
//! would load beyond the 64 KiB address space (listed as opaque). They are
//! pushed after the files, so a DOS boot loader never decides the ISA of a
//! disk that holds programs.

use super::*;
use crate::formats::container::Child;
use std::borrow::Cow;
use std::ops::Range;

/// The header magic, 0x0296 little-endian.
const MAGIC: [u8; 2] = [0x96, 0x02];

/// Header fields.
const HEADER_SIZE: usize = 16;
const PARAGRAPHS_LOW: usize = 2;
const SECTOR_SIZE: usize = 4;
const PARAGRAPHS_HIGH: usize = 6;
const PARAGRAPH_SIZE: usize = 16;

/// Sector sizes: 128 and 256 (atari800, Jindroush) and the larger powers of
/// two `AtariSIO` accepts (Altirra accepts any size up to 8192).
const SECTOR_SIZES: [usize; 7] = [128, 256, 512, 1024, 2048, 4096, 8192];

/// "Since logical sector numbers are 16-bit unsigned values, the maximum
/// disk size accessible through standard commands is 65535 sectors"
/// (§10.1).
const MAX_SECTORS: usize = 65_535;

/// The short boot sectors of a double-density image.
const BOOT_SECTOR_SIZE: usize = 128;
const SHORT_SECTORS: usize = 3;

/// Image offset of sector 4 when sectors 1-3 occupy 256-byte slots.
const SLOTS_SIZE: usize = SHORT_SECTORS * DOUBLE_DENSITY;

/// Image bytes atari800 examines to tell physical from SIO2PC slots (file
/// offsets 0x190-0x30F).
const PHYSICAL_PROBE: Range<usize> = 0x180..0x300;

/// Boot record fields in sector 1.
const BOOT_FLAGS: usize = 0;
const BOOT_COUNT: usize = 1;
const BOOT_LOAD: usize = 2;
const BOOT_INIT: usize = 4;

/// DBSECT 0 loads 256 sectors (`AltirraOS` `boot.s`: "note that 0 means to
/// load 256 sectors!").
const BOOT_COUNT_FOR_ZERO: usize = 256;

/// The loader starts 6 bytes into the boot record (`boot.s`: "loader is at
/// load address + 6").
const LOADER_OFFSET: u16 = 6;

/// Transform of boot sectors gathered from 256-byte slots.
const BOOT_SLOTS_TRANSFORM: &str = "ATR boot sector slots";

/// How sectors 1-3 are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootSlots {
    /// As 128 bytes each: single density, and double density by convention.
    Short,
    /// In the first half of 256-byte slots.
    Physical,
    /// In the first 384 bytes, followed by 384 unused bytes.
    Sio2pc,
    /// As full sectors: sector sizes of 512 bytes and more.
    Full,
}

/// The sector geometry of an ATR image.
pub(super) struct Disk<'a> {
    /// The whole file.
    file: &'a [u8],
    sector_size: usize,
    sector_count: usize,
    boot_slots: BootSlots,
}

/// A logical sector as the computer reads it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Sector<'a> {
    /// File offset.
    pub(super) offset: usize,
    /// 128 bytes for the boot sectors of a double-density image, the sector
    /// size otherwise.
    pub(super) bytes: &'a [u8],
}

impl<'a> Disk<'a> {
    /// The geometry of the `declared` image bytes after the header.
    fn new(file: &'a [u8], sector_size: usize, declared: usize) -> Result<Self> {
        let boot_slots = match sector_size {
            SINGLE_DENSITY => BootSlots::Short,
            // 384 + (n - 3) * 256 bytes leave 128 over a multiple of 256.
            DOUBLE_DENSITY if declared % DOUBLE_DENSITY == BOOT_SECTOR_SIZE => BootSlots::Short,
            DOUBLE_DENSITY => slot_layout(file, declared / DOUBLE_DENSITY),
            _ => BootSlots::Full,
        };
        let Some(sector_count) = sector_count(declared, sector_size) else {
            return Err(error(format!(
                "Invalid ATR image size {declared} B: not a whole number of {sector_size}-byte sectors"
            )));
        };
        if sector_count > MAX_SECTORS {
            return Err(error(format!(
                "Unsupported ATR sector count {sector_count}: sector numbers are 16-bit"
            )));
        }
        Ok(Self {
            file,
            sector_size,
            sector_count,
            boot_slots,
        })
    }

    pub(super) fn sector_size(&self) -> usize {
        self.sector_size
    }

    pub(super) fn sector_count(&self) -> usize {
        self.sector_count
    }

    /// Image offset of sector `number` (1-based, at most the sector count).
    fn image_offset(&self, number: usize) -> usize {
        let index = number - 1;
        let slot = match self.boot_slots {
            BootSlots::Short | BootSlots::Sio2pc => BOOT_SECTOR_SIZE,
            BootSlots::Physical => DOUBLE_DENSITY,
            BootSlots::Full => self.sector_size,
        };
        if index < SHORT_SECTORS {
            return index * slot;
        }
        let full_start = match self.boot_slots {
            BootSlots::Short => SHORT_SECTORS * BOOT_SECTOR_SIZE,
            BootSlots::Physical | BootSlots::Sio2pc => SLOTS_SIZE,
            BootSlots::Full => SHORT_SECTORS * self.sector_size,
        };
        full_start + (index - SHORT_SECTORS) * self.sector_size
    }

    /// Sector `number` (1-based), if the disk has it.
    pub(super) fn sector(&self, number: usize) -> Option<Sector<'a>> {
        if number == 0 || number > self.sector_count {
            return None;
        }
        let len = if number <= SHORT_SECTORS && self.boot_slots != BootSlots::Full {
            BOOT_SECTOR_SIZE.min(self.sector_size)
        } else {
            self.sector_size
        };
        let offset = HEADER_SIZE + self.image_offset(number);
        let bytes = self.file.get(offset..offset.checked_add(len)?)?;
        Some(Sector { offset, bytes })
    }

    /// How sectors 1-3 are stored, for the notes.
    fn layout_text(&self) -> &'static str {
        match self.boot_slots {
            BootSlots::Short if self.sector_size == DOUBLE_DENSITY => {
                "; sectors 1-3 stored as 128 B"
            }
            BootSlots::Short | BootSlots::Full => "",
            BootSlots::Physical => "; sectors 1-3 stored in the first half of 256-byte slots",
            BootSlots::Sio2pc => "; sectors 1-3 packed into the first 384 B, 384 B unused",
        }
    }
}

/// The number of sectors in `declared` image bytes of `sector_size`-byte
/// sectors, if it is whole.
fn sector_count(declared: usize, sector_size: usize) -> Option<usize> {
    if sector_size == DOUBLE_DENSITY && declared % DOUBLE_DENSITY == BOOT_SECTOR_SIZE {
        // Up to three 128-byte boot sectors, then 256-byte sectors.
        let short = SHORT_SECTORS.min(declared / BOOT_SECTOR_SIZE);
        let rest = declared - short * BOOT_SECTOR_SIZE;
        return (rest % DOUBLE_DENSITY == 0).then_some(short + rest / DOUBLE_DENSITY);
    }
    (declared % sector_size == 0).then_some(declared / sector_size)
}

/// Physical or SIO2PC slots for a double-density image of `count` 256-byte
/// slots, by atari800's test.
fn slot_layout(file: &[u8], count: usize) -> BootSlots {
    if count < SHORT_SECTORS {
        return BootSlots::Physical;
    }
    let probe = (HEADER_SIZE + PHYSICAL_PROBE.start)..(HEADER_SIZE + PHYSICAL_PROBE.end);
    match file.get(probe) {
        Some(bytes) if bytes.iter().all(|&b| b == 0) => BootSlots::Sio2pc,
        _ => BootSlots::Physical,
    }
}

/// The sector size field, if it is a documented size.
fn sector_size(header: &[u8]) -> Option<usize> {
    let size = usize::from(le_u16(header, SECTOR_SIZE)?);
    SECTOR_SIZES.contains(&size).then_some(size)
}

/// The image size the header declares, in bytes.
fn declared_size(header: &[u8]) -> Option<usize> {
    let low = usize::from(le_u16(header, PARAGRAPHS_LOW)?);
    let high = usize::from(*header.get(PARAGRAPHS_HIGH)?);
    Some(((high << 16) | low) * PARAGRAPH_SIZE)
}

/// The magic, a documented sector size and a declared size of 1 to 65535
/// whole sectors. The file may be shorter than declared, so a truncated
/// image is reported as one, and an image is recognized from the first
/// bytes of an archive member.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(header) = data.get(..HEADER_SIZE) else {
        return false;
    };
    let (Some(sector_size), Some(declared)) = (sector_size(header), declared_size(header)) else {
        return false;
    };
    header.starts_with(&MAGIC)
        && sector_count(declared, sector_size)
            .is_some_and(|count| (1..=MAX_SECTORS).contains(&count))
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = data.get(..HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated ATR header: {} B of {HEADER_SIZE}",
            data.len()
        ))
    })?;
    if !header.starts_with(&MAGIC) {
        return Err(error("Missing ATR magic 96 02 at 0x0"));
    }
    let sector_size = sector_size(header).ok_or_else(|| {
        let field = le_u16(header, SECTOR_SIZE).unwrap_or_default();
        error(format!(
            "Unsupported ATR sector size {field} B at 0x{SECTOR_SIZE:X}"
        ))
    })?;
    let declared = declared_size(header).unwrap_or_default();
    if declared == 0 {
        return Err(error(format!(
            "Invalid ATR image size 0 B at 0x{PARAGRAPHS_LOW:X}"
        )));
    }
    let available = data.len() - HEADER_SIZE;
    if declared > available {
        return Err(error(format!(
            "Truncated ATR image: the header declares {declared} B, {available} B follow it"
        )));
    }
    let disk = Disk::new(data, sector_size, declared)?;
    let end = HEADER_SIZE + declared;
    let trailer = &data[end..];
    if !is_padding(trailer) {
        return Err(error(format!(
            "Invalid trailing data: {} B at 0x{end:X} after the declared ATR image",
            trailer.len()
        )));
    }

    let mut c = Container::new(FileFormat::Atr, Layout::Atr.label(), "atr");
    c.consumed = data.len();
    c.notes.push(format!(
        "ATR image: {} of {sector_size} B, {}{}",
        count_text(disk.sector_count, "sector"),
        size_text(declared as u64),
        disk.layout_text()
    ));
    if !trailer.is_empty() {
        c.notes.push(format!(
            "{} of padding after the declared image",
            size_text(trailer.len() as u64)
        ));
    }
    c.push_metadata("atr_sector_size", "Sector size (B)", sector_size as u64);
    c.push_metadata("atr_sector_count", "Sectors", disk.sector_count as u64);
    dos2::push_files(&disk, &mut c);
    push_boot_record(&disk, &mut c);
    Ok(c)
}

/// The boot record in sector 1, as the OS boot loader reads it.
struct BootRecord {
    flags: u8,
    /// Sectors the OS loads.
    count: usize,
    load: u16,
    init: u16,
}

impl BootRecord {
    fn read(sector: &Sector<'_>) -> Option<Self> {
        let count = match *sector.bytes.get(BOOT_COUNT)? {
            0 => BOOT_COUNT_FOR_ZERO,
            count => usize::from(count),
        };
        Some(Self {
            flags: *sector.bytes.get(BOOT_FLAGS)?,
            count,
            load: le_u16(sector.bytes, BOOT_LOAD)?,
            init: le_u16(sector.bytes, BOOT_INIT)?,
        })
    }

    /// Whether the loaded sectors fit below 64 KiB.
    fn fits_address_space(&self) -> bool {
        let size = u32::try_from(self.count * BOOT_SECTOR_SIZE).unwrap_or(u32::MAX);
        u32::from(self.load).saturating_add(size) <= ADDRESS_SPACE
    }
}

/// List the boot sectors after the files: as 6502 code, or as opaque bytes
/// when the boot record would load beyond the address space. An empty
/// sector 1 holds no boot record.
fn push_boot_record<'a>(disk: &Disk<'a>, c: &mut Container<'a>) {
    if disk.sector_size > DOUBLE_DENSITY {
        c.notes.push(format!(
            "Boot sectors of {}-byte-sector images are not interpreted",
            disk.sector_size
        ));
        return;
    }
    let Some(first) = disk.sector(1) else {
        return;
    };
    if is_padding(first.bytes) {
        c.notes
            .push("Sector 1 holds only 0x00 or 0xFF bytes: no boot record".into());
        return;
    }
    let Some(record) = BootRecord::read(&first) else {
        return;
    };
    // The OS loads 128 bytes per boot sector; a double-density image has
    // three of them.
    let limit = if disk.sector_size == DOUBLE_DENSITY {
        SHORT_SECTORS
    } else {
        disk.sector_count
    };
    let sectors: Vec<Sector<'a>> = (1..=record.count.min(limit))
        .map_while(|number| disk.sector(number))
        .collect();
    let listed = sectors.len();
    c.notes.push(format!(
        "Boot record: {} loaded at 0x{:04X}, loader at 0x{:04X}, initialization address 0x{:04X}, \
            flags 0x{:02X}",
        count_text(record.count, "sector"),
        record.load,
        record.load.wrapping_add(LOADER_OFFSET),
        record.init,
        record.flags
    ));
    if listed < record.count {
        let reason = if disk.sector_size == DOUBLE_DENSITY {
            "a double-density image has three 128-byte boot sectors".to_string()
        } else {
            format!("the image has {}", count_text(disk.sector_count, "sector"))
        };
        c.notes.push(format!(
            "The boot record declares {}; {listed} are listed: {reason}",
            count_text(record.count, "sector")
        ));
    }
    c.push_metadata("atr_boot_sectors", "Boot sectors", record.count as u64);
    c.push_metadata(
        "atr_boot_load_address",
        "Boot load address",
        format!("0x{:04X}", record.load),
    );
    c.push_metadata(
        "atr_boot_init_address",
        "Boot initialization address",
        format!("0x{:04X}", record.init),
    );
    let label = if listed == 1 {
        "Boot sector 1".to_string()
    } else {
        format!("Boot sectors 1-{listed}")
    };
    let child = boot_child(disk, &sectors, label);
    let child = if record.fits_address_space() {
        child
            .with_target(MOS_6502)
            .with_variant(CPU_VARIANT)
            .as_code()
    } else {
        c.notes.push(format!(
            "The boot record loads {} at 0x{:04X}, beyond the 64 KiB address space; not analyzed \
                as code",
            count_text(record.count, "sector"),
            record.load
        ));
        Child {
            opaque: true,
            ..child
        }
    };
    c.children.push(child);
}

/// The boot sectors as the OS loads them: stored bytes when they are
/// contiguous in the file, gathered from their slots otherwise.
fn boot_child<'a>(disk: &Disk<'a>, sectors: &[Sector<'a>], label: String) -> Child<'a> {
    let first = sectors.first().map_or(HEADER_SIZE, |s| s.offset);
    let contiguous = sectors
        .iter()
        .enumerate()
        .all(|(i, s)| s.offset == first + i * BOOT_SECTOR_SIZE);
    let size = sectors.len() * BOOT_SECTOR_SIZE;
    if contiguous {
        let bytes = disk.file.get(first..first + size).unwrap_or_default();
        return Child::stored(label, first, bytes);
    }
    let gathered: Vec<u8> = sectors
        .iter()
        .flat_map(|s| s.bytes.iter().copied())
        .collect();
    let stored = sectors
        .last()
        .map_or(0, |s| s.offset + s.bytes.len() - first);
    Child::decoded(
        label,
        first,
        stored,
        Cow::Owned(gathered),
        BOOT_SLOTS_TRANSFORM,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ATR header for `declared` image bytes of `sector_size`-byte
    /// sectors.
    fn header(declared: usize, sector_size: u16) -> Vec<u8> {
        let paragraphs = declared / PARAGRAPH_SIZE;
        let mut header = vec![0; HEADER_SIZE];
        header[..2].copy_from_slice(&MAGIC);
        header[2..4].copy_from_slice(&u16::try_from(paragraphs & 0xffff).unwrap().to_le_bytes());
        header[4..6].copy_from_slice(&sector_size.to_le_bytes());
        header[6] = u8::try_from(paragraphs >> 16).unwrap();
        header
    }

    fn image(declared: usize, sector_size: u16) -> Vec<u8> {
        let mut data = header(declared, sector_size);
        data.resize(HEADER_SIZE + declared, 0);
        data
    }

    #[test]
    fn single_density_sectors_are_contiguous() {
        let data = image(720 * 128, 128);
        let disk = Disk::new(&data, 128, 720 * 128).unwrap();
        assert_eq!(disk.sector_count(), 720);
        assert_eq!(disk.sector(1).unwrap().offset, 16);
        assert_eq!(disk.sector(360).unwrap().offset, 16 + 359 * 128);
        assert!(disk.sector(0).is_none());
        assert!(disk.sector(721).is_none());
    }

    #[test]
    fn double_density_boot_sectors_are_short_or_slotted() {
        let declared = 384 + 717 * 256;
        let data = image(declared, 256);
        let disk = Disk::new(&data, 256, declared).unwrap();
        assert_eq!(
            (disk.sector_count(), disk.boot_slots),
            (720, BootSlots::Short)
        );
        assert_eq!(disk.sector(3).unwrap().bytes.len(), 128);
        assert_eq!(disk.sector(4).unwrap().offset, 16 + 384);

        let mut data = image(720 * 256, 256);
        let disk = Disk::new(&data, 256, 720 * 256).unwrap();
        assert_eq!(disk.boot_slots, BootSlots::Sio2pc);
        assert_eq!(disk.sector(2).unwrap().offset, 16 + 128);
        assert_eq!(disk.sector(4).unwrap().offset, 16 + 768);
        data[16 + 0x200] = 1;
        let disk = Disk::new(&data, 256, 720 * 256).unwrap();
        assert_eq!(disk.boot_slots, BootSlots::Physical);
        assert_eq!(disk.sector(3).unwrap().offset, 16 + 512);
    }

    #[test]
    fn partial_sectors_and_huge_counts_are_rejected() {
        let data = image(200, 128);
        assert!(Disk::new(&data, 128, 200).is_err());
        let declared = 65_536 * 128;
        assert!(Disk::new(&[], 128, declared).is_err());
    }

    #[test]
    fn detection_needs_a_documented_sector_size_and_whole_sectors() {
        assert!(detect(&image(1024, 128)));
        assert!(!detect(&image(1024, 100)));
        assert!(!detect(&image(1040, 128)));
        assert!(!detect(&header(0, 128)));
        assert!(!detect(&header(65_536 * 128, 128)));
        assert!(detect(&header(384 + 256, 256)));
        // A truncated image is still recognized, to be reported as truncated.
        let mut short = image(1024, 128);
        short.pop();
        assert!(detect(&short));
        assert!(!detect(&short[..HEADER_SIZE - 1]));
    }
}
