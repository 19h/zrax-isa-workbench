//! The volume descriptor set (ECMA-119 6.7.1, clause 8), the UDF volume
//! recognition sequence that may follow it (ECMA-167 2/8.3), the path
//! tables (ECMA-119 6.9, 9.4) and the system area (sectors 0-15), which a
//! hybrid image fills with an MBR or GPT partition table.

use super::directory::Record;
use super::*;

/// Volume descriptor types (ECMA-119 8.1.1).
const TYPE_BOOT_RECORD: u8 = 0;
const TYPE_PRIMARY: u8 = 1;
const TYPE_SUPPLEMENTARY: u8 = 2;
const TYPE_PARTITION: u8 = 3;
const TYPE_TERMINATOR: u8 = 255;

/// Descriptor version of the boot record, the primary and supplementary
/// volume descriptors and the terminator (8.2.3, 8.4.3, 8.5.2, 8.3.3).
const VERSION_1: u8 = 1;

/// Version of an enhanced volume descriptor, which shares type 2 with the
/// supplementary one (8.5.2).
const VERSION_ENHANCED: u8 = 2;

/// File structure version of a primary or supplementary volume descriptor
/// (8.4.30).
const FILE_STRUCTURE_VERSION: u8 = 1;

/// Most descriptors read from sector 16: the volume descriptor set and the
/// UDF recognition sequence after it. Linux reads sectors 16 to 99.
const MAX_DESCRIPTORS: usize = 64;

/// Logical block sizes a CD-ROM volume can have: 2^(n+9), at most the
/// 2048-byte logical sector (6.2.2), as Linux `isofs_fill_super` accepts.
const BLOCK_SIZES: [usize; 3] = [512, 1024, 2048];

/// Offset of the root directory record in a primary or supplementary
/// volume descriptor (8.4.18, 8.5.12).
pub(super) const ROOT_RECORD_OFFSET: usize = 156;

/// Smallest volume: the system area, a primary volume descriptor and a
/// terminator.
const MIN_VOLUME_SIZE: usize = (FIRST_DESCRIPTOR_SECTOR + 2) * SECTOR_SIZE;

/// Joliet escape sequences in a supplementary volume descriptor, by UCS-2
/// level (ECMA-119 Annex C.3.1, Table C.1).
const JOLIET_ESCAPES: [([u8; 3], u8); 3] = [(*b"%/@", 1), (*b"%/C", 2), (*b"%/E", 3)];

/// Boot system identifier of the El Torito boot record (El Torito 1.0,
/// figure 7), padded with NUL bytes to 32.
const EL_TORITO_ID: &[u8] = b"EL TORITO SPECIFICATION";

/// Offset of the boot catalog sector in the El Torito boot record.
const BOOT_CATALOG_POINTER: usize = 0x47;

/// Identifiers of the ECMA-167 volume structure descriptors that may follow
/// the ECMA-119 set (ECMA-167 2/9.1.2, figure 2/3), with what they mean.
const UDF_DESCRIPTORS: [(&str, &str); 6] = [
    ("BEA01", "extended area start"),
    ("NSR02", "ECMA-167 2nd edition volume"),
    ("NSR03", "ECMA-167 3rd edition volume"),
    ("BOOT2", "boot descriptor"),
    ("CDW02", "ECMA-168 volume"),
    ("TEA01", "extended area end"),
];

/// MBR signature at the end of sector 0 of the system area (libisofs
/// `boot_sectors.txt`, "Master Boot Record").
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// The four 16-byte MBR partition entries start at 446; the type byte is at
/// entry offset 4.
const MBR_PARTITIONS_OFFSET: usize = 446;
const MBR_PARTITION_SIZE: usize = 16;
const MBR_PARTITION_COUNT: usize = 4;
const MBR_PARTITION_TYPE: usize = 4;

/// GPT header signature at LBA 1 of 512-byte blocks.
const GPT_HEADER_OFFSET: usize = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Path table record header: identifier length, EAR length, extent (4),
/// parent number (2) (ECMA-119 9.4, Table 11).
const PATH_RECORD_HEADER: usize = 8;

/// Text encoding of a volume descriptor's identifier fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
    /// a- and d-characters (ECMA-6).
    Ascii,
    /// Joliet UCS-2, big-endian.
    Ucs2,
}

/// The fields of a primary or supplementary volume descriptor that the
/// reader uses, after the checks of [`Volume::parse`].
#[derive(Debug, Clone)]
pub(super) struct Volume {
    /// File offset of the descriptor.
    pub(super) offset: usize,
    pub(super) system_id: String,
    pub(super) identifier: String,
    /// Volume space size in logical blocks.
    pub(super) space_blocks: u32,
    pub(super) set_size: u16,
    pub(super) sequence_number: u16,
    /// Logical block size in bytes: 512, 1024 or 2048.
    pub(super) block_size: usize,
    /// Path table size in bytes.
    path_table_size: u32,
    /// Logical block of the type L (little-endian) path table.
    path_table_l: u32,
    /// Logical block of the type M (big-endian) path table; 0 when absent.
    path_table_m: u32,
    /// First logical block of the root directory (record at offset 156).
    pub(super) root_extent: u32,
    /// File offset of the root directory's data, if it fits in `usize`.
    pub(super) root_offset: Option<usize>,
    /// Root directory size in bytes.
    pub(super) root_size: u32,
    pub(super) set_id: String,
    pub(super) publisher: String,
    pub(super) preparer: String,
    pub(super) application: String,
    /// Volume creation time, when recorded.
    pub(super) created: Option<String>,
}

impl Volume {
    /// Parse the descriptor at file offset `at`. Layout (ECMA-119 Table 4,
    /// Table 6): type (0), `CD001` (1), version (6), volume flags (7),
    /// system identifier (8, 32 B), volume identifier (40, 32 B), volume
    /// space size (80, 7.3.3), escape sequences (88, 32 B), volume set size
    /// (120, 7.2.3), volume sequence number (124, 7.2.3), logical block size
    /// (128, 7.2.3), path table size (132, 7.3.3), type L path table (140,
    /// LE), optional type L (144), type M path table (148, BE), optional
    /// type M (152), root directory record (156, 34 B), volume set
    /// identifier (190, 128 B), publisher (318, 128 B), data preparer (446,
    /// 128 B), application (574, 128 B), creation time (813, 17 B), file
    /// structure version (881).
    fn parse(data: &[u8], at: usize, charset: Charset) -> Result<Self> {
        let descriptor = slice(data, at, SECTOR_SIZE)?;
        let version = descriptor[6];
        if version != VERSION_1 {
            return Err(error(format!(
                "Unsupported volume descriptor version {version} at 0x{at:X}"
            )));
        }
        let structure_version = descriptor[881];
        if structure_version != FILE_STRUCTURE_VERSION {
            return Err(error(format!(
                "Unsupported file structure version {structure_version} at 0x{:X}",
                at + 881
            )));
        }
        let space_blocks = both_u32(data, at + 80, "volume space size")?;
        let set_size = both_u16(data, at + 120, "volume set size")?;
        let sequence_number = both_u16(data, at + 124, "volume sequence number")?;
        let block_size = usize::from(both_u16(data, at + 128, "logical block size")?);
        if !BLOCK_SIZES.contains(&block_size) {
            return Err(error(format!(
                "Unsupported logical block size {block_size} B at 0x{:X}",
                at + 128
            )));
        }
        let volume_size = u64::from(space_blocks) * block_size as u64;
        if volume_size < MIN_VOLUME_SIZE as u64 {
            return Err(error(format!(
                "Invalid volume space size at 0x{:X}: {space_blocks} blocks of {block_size} B \
                 cannot hold the volume descriptors",
                at + 80
            )));
        }
        let path_table_size = both_u32(data, at + 132, "path table size")?;
        let root = Record::parse_root(data, at + ROOT_RECORD_OFFSET)?;
        let text = |start: usize, len: usize| match charset {
            Charset::Ascii => text_field(&descriptor[start..start + len]),
            Charset::Ucs2 => ucs2_text(&descriptor[start..start + len])
                .trim_end_matches([' ', '\0'])
                .to_string(),
        };
        Ok(Self {
            offset: at,
            system_id: text(8, 32),
            identifier: text(40, 32),
            space_blocks,
            set_size,
            sequence_number,
            block_size,
            path_table_size,
            path_table_l: le_u32(data, at + 140)?,
            path_table_m: be_u32(data, at + 148)?,
            root_extent: root.extent,
            root_offset: root.data_offset(block_size),
            root_size: root.data_len,
            set_id: text(190, 128),
            publisher: text(318, 128),
            preparer: text(446, 128),
            application: text(574, 128),
            created: date_text(&descriptor[813..830]),
        })
    }

    /// Volume size in bytes.
    pub(super) fn size(&self) -> Result<usize> {
        usize::try_from(u64::from(self.space_blocks) * self.block_size as u64).map_err(|_| {
            error(format!(
                "Unsupported volume size: {} blocks of {} B",
                self.space_blocks, self.block_size
            ))
        })
    }
}

/// A 17-byte date and time (ECMA-119 8.4.26.1, Table 5): 16 ASCII digits
/// `YYYYMMDDHHMMSScc` and a signed offset from GMT in 15-minute units. All
/// zero digits mean "not specified".
fn date_text(field: &[u8]) -> Option<String> {
    let digits = field.get(..16)?;
    if !digits.iter().all(u8::is_ascii_digit) || digits.iter().all(|d| *d == b'0') {
        return None;
    }
    let part = |range: std::ops::Range<usize>| String::from_utf8_lossy(&digits[range]).into_owned();
    let quarter_hours = i32::from(i8::from_le_bytes([*field.get(16)?]));
    let sign = if quarter_hours < 0 { '-' } else { '+' };
    let minutes = quarter_hours.abs() * 15;
    Some(format!(
        "{}-{}-{} {}:{}:{} GMT{sign}{:02}:{:02}",
        part(0..4),
        part(4..6),
        part(6..8),
        part(8..10),
        part(10..12),
        part(12..14),
        minutes / 60,
        minutes % 60
    ))
}

/// A Joliet supplementary volume descriptor.
#[derive(Debug, Clone)]
pub(super) struct Joliet {
    pub(super) volume: Volume,
    /// UCS-2 level 1, 2 or 3.
    pub(super) level: u8,
}

/// An El Torito boot record.
#[derive(Debug, Clone, Copy)]
pub(super) struct BootRecord {
    /// File offset of the descriptor.
    pub(super) offset: usize,
    /// First sector of the boot catalog, in 2048-byte sectors.
    pub(super) catalog_sector: u32,
}

/// The volume descriptor set and the recognition sequence after it.
#[derive(Debug)]
pub(super) struct DescriptorSet {
    pub(super) primary: Volume,
    pub(super) joliet: Option<Joliet>,
    pub(super) el_torito: Option<BootRecord>,
    /// Supplementary descriptors that are not Joliet, or Joliet ones that
    /// are not valid, with the reason.
    other_supplementary: Vec<String>,
    /// Enhanced volume descriptors (version 2), not used.
    enhanced: usize,
    /// Volume partition descriptors.
    partitions: usize,
    /// Boot records of other boot systems, by identifier.
    other_boot_records: Vec<String>,
    /// Further primary volume descriptors (copies).
    primary_copies: usize,
    /// Descriptors of the reserved types 4-254.
    reserved: usize,
    /// ECMA-167 descriptors after the terminator: identifier and sector.
    udf: Vec<(&'static str, &'static str, usize)>,
}

/// The type and version bytes of the descriptor in `sector`, if it carries
/// `CD001`.
fn descriptor_header(data: &[u8], sector: usize) -> Result<Option<(u8, u8)>> {
    let at = sector * SECTOR_SIZE;
    let header = slice(data, at, SECTOR_SIZE).map_err(|_| {
        error(format!(
            "Truncated volume descriptor set: sector {sector} at 0x{at:X} is not present"
        ))
    })?;
    if &header[STANDARD_ID_OFFSET..STANDARD_ID_OFFSET + STANDARD_ID.len()] != STANDARD_ID {
        return Ok(None);
    }
    Ok(Some((header[0], header[6])))
}

/// The first primary volume descriptor of the set, for detection. Reads no
/// further than the primary descriptor or the terminator.
pub(super) fn find_primary(data: &[u8]) -> Result<Volume> {
    for sector in FIRST_DESCRIPTOR_SECTOR..FIRST_DESCRIPTOR_SECTOR + MAX_DESCRIPTORS {
        match descriptor_header(data, sector)? {
            Some((TYPE_PRIMARY, _)) => {
                return Volume::parse(data, sector * SECTOR_SIZE, Charset::Ascii)
            }
            Some((TYPE_TERMINATOR, _)) | None => break,
            Some(_) => {}
        }
    }
    Err(error("Missing primary volume descriptor"))
}

/// Read the volume descriptor set from sector 16 to its terminator, then
/// the UDF recognition sequence, if any.
pub(super) fn read_set(data: &[u8]) -> Result<DescriptorSet> {
    let mut seen_primary = false;
    let mut set = DescriptorSet {
        primary: find_primary(data)?,
        joliet: None,
        el_torito: None,
        other_supplementary: Vec::new(),
        enhanced: 0,
        partitions: 0,
        other_boot_records: Vec::new(),
        primary_copies: 0,
        reserved: 0,
        udf: Vec::new(),
    };
    let last = FIRST_DESCRIPTOR_SECTOR + MAX_DESCRIPTORS;
    let mut terminator = None;
    for sector in FIRST_DESCRIPTOR_SECTOR..last {
        let at = sector * SECTOR_SIZE;
        let Some((kind, version)) = descriptor_header(data, sector)? else {
            return Err(error(format!(
                "Missing volume descriptor set terminator: sector {sector} at 0x{at:X} does not \
                 hold CD001"
            )));
        };
        match kind {
            TYPE_PRIMARY if !seen_primary => seen_primary = true,
            TYPE_PRIMARY => set.primary_copies += 1,
            TYPE_SUPPLEMENTARY if version == VERSION_ENHANCED => set.enhanced += 1,
            TYPE_SUPPLEMENTARY => set.supplementary(data, at),
            TYPE_BOOT_RECORD => set.boot_record(data, at, version)?,
            TYPE_PARTITION => set.partitions += 1,
            TYPE_TERMINATOR => {
                terminator = Some(sector);
                break;
            }
            _ => set.reserved += 1,
        }
    }
    let Some(terminator) = terminator else {
        return Err(error(format!(
            "Missing volume descriptor set terminator in sectors {FIRST_DESCRIPTOR_SECTOR} to {}",
            last - 1
        )));
    };
    set.udf = recognition_sequence(data, terminator + 1, last);
    Ok(set)
}

impl DescriptorSet {
    /// A supplementary volume descriptor: Joliet when its escape sequences
    /// name UCS-2 and its fields are valid.
    fn supplementary(&mut self, data: &[u8], at: usize) {
        // `descriptor_header` read the whole sector at `at`.
        let escapes = &data[at + 88..at + 120];
        let level = JOLIET_ESCAPES
            .iter()
            .find(|(sequence, _)| escapes.starts_with(sequence))
            .map(|&(_, level)| level);
        let Some(level) = level else {
            self.other_supplementary.push(format!(
                "supplementary volume descriptor at 0x{at:X} with escape sequences {}",
                escape_text(escapes)
            ));
            return;
        };
        if self.joliet.is_some() {
            self.other_supplementary
                .push(format!("further Joliet descriptor at 0x{at:X}"));
            return;
        }
        let valid = Volume::parse(data, at, Charset::Ucs2).and_then(|volume| {
            if volume.block_size == self.primary.block_size {
                Ok(volume)
            } else {
                Err(error(format!(
                    "logical block size {} B differs from the primary volume's {} B",
                    volume.block_size, self.primary.block_size
                )))
            }
        });
        match valid {
            Ok(volume) => self.joliet = Some(Joliet { volume, level }),
            Err(e) => self.other_supplementary.push(format!(
                "Joliet descriptor at 0x{at:X} is invalid ({}) and is not used",
                message(e)
            )),
        }
    }

    /// A boot record (ECMA-119 8.2): El Torito when its boot system
    /// identifier is `EL TORITO SPECIFICATION` (figure 7).
    fn boot_record(&mut self, data: &[u8], at: usize, version: u8) -> Result<()> {
        let system_id = slice(data, at + 7, 32)?;
        let is_el_torito = system_id.starts_with(EL_TORITO_ID)
            && system_id[EL_TORITO_ID.len()..].iter().all(|b| *b == 0);
        if is_el_torito && version == VERSION_1 && self.el_torito.is_none() {
            self.el_torito = Some(BootRecord {
                offset: at,
                catalog_sector: le_u32(data, at + BOOT_CATALOG_POINTER)?,
            });
        } else {
            self.other_boot_records.push(format!(
                "\"{}\" at 0x{at:X}",
                text_field(system_id).escape_debug()
            ));
        }
        Ok(())
    }

    /// Notes for the descriptors that are recorded but not used.
    pub(super) fn describe_extras(&self, c: &mut Container<'_>) {
        if !self.udf.is_empty() {
            let listed: Vec<String> = self
                .udf
                .iter()
                .map(|(id, meaning, sector)| format!("{id} ({meaning}) at sector {sector}"))
                .collect();
            c.notes.push(format!(
                "UDF bridge: ECMA-167 recognition sequence {}; the UDF structures are not parsed",
                listed.join(", ")
            ));
            let ids: Vec<&str> = self.udf.iter().map(|(id, _, _)| *id).collect();
            c.push_metadata("iso9660_udf_descriptors", "UDF descriptors", ids.join(", "));
        }
        for other in &self.other_supplementary {
            c.notes.push(format!("Not used for names: {other}"));
        }
        if self.enhanced > 0 {
            c.notes.push(format!(
                "{} enhanced volume descriptors (ECMA-119 8.5, version 2) are not used",
                self.enhanced
            ));
        }
        if self.partitions > 0 {
            c.notes.push(format!(
                "{} volume partition descriptors; partition contents are not specified by \
                 ECMA-119 and are not read",
                self.partitions
            ));
        }
        if !self.other_boot_records.is_empty() {
            c.notes.push(format!(
                "Boot records of other boot systems are not read: {}",
                self.other_boot_records.join(", ")
            ));
        }
        if self.primary_copies > 0 {
            c.notes.push(format!(
                "{} further primary volume descriptors; the first one is used",
                self.primary_copies
            ));
        }
        if self.reserved > 0 {
            c.notes.push(format!(
                "{} volume descriptors of reserved types are skipped",
                self.reserved
            ));
        }
    }
}

/// The text of a parse error without the family prefix.
pub(super) fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::Iso9660ParseError { message } => message,
        other => other.to_string(),
    }
}

/// Escape sequences as printable text, up to the first NUL.
fn escape_text(escapes: &[u8]) -> String {
    let end = escapes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(escapes.len());
    if end == 0 {
        return "none".to_string();
    }
    format!(
        "\"{}\"",
        String::from_utf8_lossy(&escapes[..end]).escape_debug()
    )
}

/// The ECMA-167 volume structure descriptors from sector `first`: type 0,
/// version 1 and a known identifier (2/9.1). The sequence ends at the
/// first sector that is not one (2/8.3.1, note 1); further ECMA-119
/// terminators are skipped.
fn recognition_sequence(
    data: &[u8],
    first: usize,
    last: usize,
) -> Vec<(&'static str, &'static str, usize)> {
    let mut found = Vec::new();
    for sector in first..last {
        let Some(header) = data.get(sector * SECTOR_SIZE..sector * SECTOR_SIZE + 7) else {
            break;
        };
        let identifier = &header[STANDARD_ID_OFFSET..STANDARD_ID_OFFSET + STANDARD_ID.len()];
        if header[0] == TYPE_TERMINATOR && identifier == STANDARD_ID {
            continue;
        }
        let known = UDF_DESCRIPTORS
            .iter()
            .find(|(id, _)| identifier == id.as_bytes());
        match known {
            Some(&(id, meaning)) if header[0] == 0 && header[6] == VERSION_1 => {
                found.push((id, meaning, sector));
            }
            _ => break,
        }
    }
    found
}

/// What the system area (sectors 0-15, ECMA-119 6.2.1) holds.
pub(super) struct SystemArea {
    /// Partition types of the non-empty MBR entries, when sector 0 ends
    /// with the MBR signature.
    mbr_partitions: Option<Vec<u8>>,
    /// A GPT header signature at 0x200.
    gpt: bool,
    /// Any nonzero byte.
    used: bool,
}

impl SystemArea {
    pub(super) fn read(data: &[u8]) -> Self {
        let area = data.get(..DESCRIPTOR_SET_OFFSET).unwrap_or_default();
        let mbr_partitions = (area.get(MBR_SIGNATURE_OFFSET..MBR_SIGNATURE_OFFSET + 2)
            == Some(MBR_SIGNATURE.as_slice()))
        .then(|| {
            (0..MBR_PARTITION_COUNT)
                .map(|i| area[MBR_PARTITIONS_OFFSET + i * MBR_PARTITION_SIZE + MBR_PARTITION_TYPE])
                .filter(|kind| *kind != 0)
                .collect()
        });
        Self {
            mbr_partitions,
            gpt: area.get(GPT_HEADER_OFFSET..GPT_HEADER_OFFSET + GPT_SIGNATURE.len())
                == Some(GPT_SIGNATURE.as_slice()),
            used: area.iter().any(|b| *b != 0),
        }
    }

    /// An MBR with at least one partition, or a GPT header: the image is a
    /// hybrid whose partitions may lie after the ISO 9660 volume.
    pub(super) fn has_partition_table(&self) -> bool {
        self.gpt
            || self
                .mbr_partitions
                .as_ref()
                .is_some_and(|types| !types.is_empty())
    }

    /// Notes for the system area and the bytes after the volume.
    pub(super) fn describe(&self, volume_size: usize, trailing: &[u8], c: &mut Container<'_>) {
        if let Some(types) = &self.mbr_partitions {
            let listed: Vec<String> = types.iter().map(|kind| format!("0x{kind:02X}")).collect();
            let partitions = if listed.is_empty() {
                "no partitions".to_string()
            } else {
                format!("partition types {}", listed.join(", "))
            };
            c.notes.push(format!(
                "Hybrid image: the system area holds an MBR ({partitions}); its boot code and \
                 partitions are not parsed"
            ));
        }
        if self.gpt {
            c.notes.push(
                "Hybrid image: a GPT header follows the MBR at 0x200; it is not parsed".to_string(),
            );
        }
        if self.used && self.mbr_partitions.is_none() && !self.gpt {
            c.notes.push(
                "The system area (sectors 0-15) holds data that ISO 9660 does not specify; it \
                 is not interpreted"
                    .to_string(),
            );
        }
        if trailing.is_empty() {
            return;
        }
        if is_padding(trailing) {
            c.notes.push(format!(
                "Volume ends at 0x{volume_size:X}; {} B of padding follow",
                trailing.len()
            ));
        } else {
            c.notes.push(format!(
                "{} B follow the volume at 0x{volume_size:X}; the system-area partition table may \
                 describe them (not parsed)",
                trailing.len()
            ));
        }
    }
}

/// One path table record: extent, parent number, identifier.
#[derive(Debug, PartialEq, Eq)]
struct PathRecord<'a> {
    extent: u32,
    parent: u16,
    identifier: &'a [u8],
}

/// The records of the path table at logical block `location`, read with
/// the byte order `le` selects (true means type L, little-endian).
fn path_table<'a>(
    image: Image<'a>,
    volume: &Volume,
    location: u32,
    le: bool,
) -> std::result::Result<Vec<PathRecord<'a>>, String> {
    let size = volume.path_table_size as usize;
    let start = block_offset(location, volume.block_size)
        .filter(|&start| image.holds(start, size))
        .ok_or_else(|| {
            format!("the table at block {location} ({size} B) lies outside the volume")
        })?;
    let table = image.present(start, size).ok_or_else(|| {
        format!(
            "the table at block {location} ({size} B) lies past the {} present; it is not \
             checked",
            image.present_text()
        )
    })?;
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < table.len() {
        let header = table.get(pos..pos + PATH_RECORD_HEADER).ok_or_else(|| {
            format!(
                "record {} at table offset 0x{pos:X} is truncated",
                records.len() + 1
            )
        })?;
        let identifier_len = usize::from(header[0]);
        let extent_bytes = [header[2], header[3], header[4], header[5]];
        let parent_bytes = [header[6], header[7]];
        let (extent, parent) = if le {
            (
                u32::from_le_bytes(extent_bytes),
                u16::from_le_bytes(parent_bytes),
            )
        } else {
            (
                u32::from_be_bytes(extent_bytes),
                u16::from_be_bytes(parent_bytes),
            )
        };
        let start = pos + PATH_RECORD_HEADER;
        let identifier = table
            .get(start..start + identifier_len)
            .filter(|_| identifier_len > 0)
            .ok_or_else(|| {
                format!(
                    "record {} at table offset 0x{pos:X} is invalid",
                    records.len() + 1
                )
            })?;
        records.push(PathRecord {
            extent,
            parent,
            identifier,
        });
        // The identifier is padded to an even length (9.4.6).
        pos = start + identifier_len + identifier_len % 2;
    }
    Ok(records)
}

/// Check the type L and type M path tables against each other and against
/// the root directory, and note the result. ECMA-119 requires both tables
/// (6.9.2); Linux and libarchive do not read them, so damage is noted, not
/// an error.
pub(super) fn check_path_tables(image: Image<'_>, volume: &Volume, c: &mut Container<'_>) {
    let little = path_table(image, volume, volume.path_table_l, true);
    let big =
        (volume.path_table_m != 0).then(|| path_table(image, volume, volume.path_table_m, false));
    let note = match (little, big) {
        (Err(e), _) => format!("Type L path table: {e}"),
        (Ok(records), _) if records.first().map(|r| r.extent) != Some(volume.root_extent) => {
            "Type L path table: the first record is not the root directory".to_string()
        }
        (Ok(records), None) => format!(
            "Path table: {} directories in the type L table; no type M table is recorded",
            records.len()
        ),
        (Ok(_), Some(Err(e))) => format!("Type M path table: {e}"),
        (Ok(little), Some(Ok(big))) if little == big => format!(
            "Path tables: {} directories; the type L and type M tables agree",
            little.len()
        ),
        (Ok(little), Some(Ok(big))) => {
            let first = little
                .iter()
                .zip(&big)
                .position(|(l, m)| l != m)
                .unwrap_or(little.len().min(big.len()));
            format!(
                "Path tables disagree: type L holds {} records, type M {}; first difference at \
                 record {}",
                little.len(),
                big.len(),
                first + 1
            )
        }
    };
    c.notes.push(note);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_need_digits_and_carry_the_gmt_offset() {
        assert_eq!(
            date_text(b"2026101304390000\x04").as_deref(),
            Some("2026-10-13 04:39:00 GMT+01:00")
        );
        assert_eq!(
            date_text(b"1995052212000000\xEC").as_deref(),
            Some("1995-05-22 12:00:00 GMT-05:00")
        );
        assert_eq!(date_text(b"0000000000000000\0"), None);
        assert_eq!(date_text(b"20261013        \0"), None);
    }

    #[test]
    fn escape_sequences_print_up_to_the_first_nul() {
        assert_eq!(escape_text(b"%/E\0\0"), "\"%/E\"");
        assert_eq!(escape_text(&[0; 32]), "none");
    }

    #[test]
    fn recognition_sequence_stops_at_the_first_unknown_sector() {
        let mut data = vec![0u8; 4 * SECTOR_SIZE];
        for (sector, id) in [(0, b"BEA01"), (1, b"NSR03"), (2, b"TEA01")] {
            let at = sector * SECTOR_SIZE;
            data[at + 1..at + 6].copy_from_slice(id);
            data[at + 6] = 1;
        }
        let found = recognition_sequence(&data, 0, 4);
        let ids: Vec<&str> = found.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(ids, ["BEA01", "NSR03", "TEA01"]);
    }
}
