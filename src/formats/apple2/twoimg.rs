//! 2IMG images ([2IMG]; [CP2] `TwoIMG-notes.md`, `TwoIMG.cs`). All fields
//! are little-endian: magic `2IMG` (4), creator (4), header length (2;
//! [2IMG] says 52, writers use 64), version (2; 1), image format (4; 0 DOS
//! order, 1 `ProDOS` order, 2 nibbles), flags (4; bit 31 locked, bit 8 set
//! when bits 0-7 hold the DOS volume number), blocks (4; for format 1),
//! data offset and length (4 + 4), comment offset and length (4 + 4),
//! creator data offset and length (4 + 4), 16 reserved bytes. The data,
//! comment and creator chunks follow in that order.

use super::*;

const MAGIC: &[u8; 4] = b"2IMG";

/// The header of every version-1 file ([2IMG]: "pads header to 64 bytes").
const HEADER_SIZE: usize = 64;

/// The header length the original description gives ([2IMG]: "52 bytes as
/// of this writing"); such files still put the data at 64 ([CP2]
/// `TwoIMG.Header.ALT_LENGTH`).
const OLD_HEADER_LENGTH: usize = 52;

const VERSION_1: u16 = 1;

/// Header fields.
const CREATOR: usize = 0x04;
const HEADER_LENGTH: usize = 0x08;
const VERSION: usize = 0x0a;
const IMAGE_FORMAT: usize = 0x0c;
const FLAGS: usize = 0x10;
const BLOCK_COUNT: usize = 0x14;
const DATA_OFFSET: usize = 0x18;
const DATA_LENGTH: usize = 0x1c;
const COMMENT_OFFSET: usize = 0x20;
const COMMENT_LENGTH: usize = 0x24;
const CREATOR_DATA_OFFSET: usize = 0x28;
const CREATOR_DATA_LENGTH: usize = 0x2c;

/// The bytes [`detect`] checks: magic, creator, header length, version and
/// image format.
const DETECTION_SIZE: usize = 0x10;

/// Image formats ([2IMG] `image_format`).
const FORMAT_DOS_ORDER: u32 = 0;
const FORMAT_PRODOS_ORDER: u32 = 1;
const FORMAT_NIBBLES: u32 = 2;

/// Flags ([2IMG] `flags`).
const FLAG_LOCKED: u32 = 1 << 31;
const FLAG_VOLUME_NUMBER: u32 = 1 << 8;
const VOLUME_NUMBER_MASK: u32 = 0xff;
const RESERVED_FLAGS: u32 = !(FLAG_LOCKED | FLAG_VOLUME_NUMBER | VOLUME_NUMBER_MASK);

/// "If V is zero, then the volume number is not specified and 254 is
/// assumed" ([2IMG]).
const DEFAULT_VOLUME_NUMBER: u32 = 254;

/// ".NIB images are made up of 35 tracks. Each track has $1A00 (6656)
/// bytes" ([2IMG]).
const NIBBLE_TRACKS: usize = 35;
const NIBBLE_TRACK_SIZE: usize = 0x1a00;

/// Some images by creator `WOOF` (Bernie ][ The Rescue in [2IMG], Sweet 16
/// in [CP2]) have data length 0 and a valid block count ([CP2]
/// `TwoIMG.ValidateHeader`).
const CREATOR_WOOF: &[u8; 4] = b"WOOF";

/// Most comment characters quoted in the notes.
const MAX_COMMENT_NOTE: usize = 256;

/// The magic, a header length of 52 or at least 64, version 1 and a known
/// image format: 16 bytes of the header, so a stray `2IMG` is not enough.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(start): Option<&[u8; DETECTION_SIZE]> = data
        .get(..DETECTION_SIZE)
        .and_then(|bytes| bytes.try_into().ok())
    else {
        return false;
    };
    let header_length = usize::from(le_u16(start, HEADER_LENGTH));
    let version = le_u16(start, VERSION);
    let format = le_u32(start, IMAGE_FORMAT);
    start.starts_with(MAGIC)
        && (header_length == OLD_HEADER_LENGTH || header_length >= HEADER_SIZE)
        && version == VERSION_1
        && format <= FORMAT_NIBBLES
}

/// The little-endian 32-bit field at `at` of a fixed-size record.
fn le_u32<const N: usize>(record: &[u8; N], at: usize) -> u32 {
    u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
}

/// A chunk of the file: offset and length as the header gives them.
#[derive(Debug, Clone, Copy)]
struct Chunk {
    offset: usize,
    len: usize,
}

impl Chunk {
    fn at(header: &[u8; HEADER_SIZE], offset_field: usize, length_field: usize) -> Self {
        Self {
            offset: usize::try_from(le_u32(header, offset_field)).unwrap_or(usize::MAX),
            len: usize::try_from(le_u32(header, length_field)).unwrap_or(usize::MAX),
        }
    }

    fn is_present(self) -> bool {
        self.offset != 0 && self.len != 0
    }

    /// The end of the chunk, if it is in a file of `size` bytes.
    fn end_within(self, size: usize) -> Option<usize> {
        self.offset.checked_add(self.len).filter(|&end| end <= size)
    }
}

/// A validated 2IMG header.
#[derive(Debug)]
struct Header {
    creator: String,
    format: u32,
    flags: u32,
    blocks: u32,
    data: Chunk,
    comment: Chunk,
    creator_data: Chunk,
}

impl Header {
    /// Validate the header and the data chunk as [CP2]
    /// `TwoIMG.ValidateHeader` does; a damaged comment or creator chunk is
    /// left to the notes.
    fn parse(data: &[u8]) -> Result<Self> {
        let header: &[u8; HEADER_SIZE] = data
            .get(..HEADER_SIZE)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                error(format!(
                    "Truncated 2IMG header: {} B, {HEADER_SIZE} B expected",
                    data.len()
                ))
            })?;
        if !header.starts_with(MAGIC) {
            return Err(error("Missing 2IMG magic"));
        }
        let header_length = usize::from(le_u16(header, HEADER_LENGTH));
        if header_length != OLD_HEADER_LENGTH && header_length < HEADER_SIZE {
            return Err(error(format!(
                "Invalid 2IMG header length {header_length} B"
            )));
        }
        let version = le_u16(header, VERSION);
        if version != VERSION_1 {
            return Err(error(format!("Unsupported 2IMG version {version}")));
        }
        let format = le_u32(header, IMAGE_FORMAT);
        if format > FORMAT_NIBBLES {
            return Err(error(format!("Unsupported 2IMG image format {format}")));
        }
        let creator = header[CREATOR..CREATOR + 4].to_vec();
        let blocks = le_u32(header, BLOCK_COUNT);
        let mut chunk = Chunk::at(header, DATA_OFFSET, DATA_LENGTH);
        if creator == CREATOR_WOOF && chunk.len == 0 && format != FORMAT_NIBBLES {
            chunk.len = usize::try_from(blocks)
                .unwrap_or(usize::MAX)
                .saturating_mul(BLOCK_SIZE);
        }
        if !chunk.is_present() {
            return Err(error(format!(
                "Missing 2IMG data: offset 0x{:X}, length {} B",
                chunk.offset, chunk.len
            )));
        }
        if chunk.offset < header_length {
            return Err(error(format!(
                "Invalid 2IMG data offset 0x{:X}: inside the {header_length} B header",
                chunk.offset
            )));
        }
        if chunk.end_within(data.len()).is_none() {
            return Err(error(format!(
                "Truncated 2IMG data: 0x{:X} + {} B exceed the {} B file",
                chunk.offset,
                chunk.len,
                data.len()
            )));
        }
        check_data_size(format, blocks, chunk.len)?;
        Ok(Self {
            creator: creator.iter().map(|&b| printable(b)).collect(),
            format,
            flags: le_u32(header, FLAGS),
            blocks,
            data: chunk,
            comment: Chunk::at(header, COMMENT_OFFSET, COMMENT_LENGTH),
            creator_data: Chunk::at(header, CREATOR_DATA_OFFSET, CREATOR_DATA_LENGTH),
        })
    }
}

/// The data size each image format needs ([CP2] `TwoIMG.ValidateHeader`):
/// whole blocks matching the block count in `ProDOS` order, whole 16-sector
/// tracks in DOS order, 35 nibble tracks.
fn check_data_size(format: u32, blocks: u32, len: usize) -> Result<()> {
    let valid = match format {
        FORMAT_PRODOS_ORDER => {
            blocks != 0
                && usize::try_from(blocks)
                    .ok()
                    .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE))
                    == Some(len)
        }
        FORMAT_DOS_ORDER => len % TRACK_SIZE == 0,
        _ => len == NIBBLE_TRACKS * NIBBLE_TRACK_SIZE,
    };
    if valid {
        Ok(())
    } else {
        Err(error(format!(
            "Invalid 2IMG data length {len} B for {} with {blocks} blocks",
            format_name(format)
        )))
    }
}

fn format_name(format: u32) -> &'static str {
    match format {
        FORMAT_DOS_ORDER => "DOS order",
        FORMAT_PRODOS_ORDER => "ProDOS order",
        _ => "nibbles",
    }
}

/// A byte of a creator code or comment as text; others show as `?`.
fn printable(b: u8) -> char {
    if b == b' ' || b.is_ascii_graphic() {
        char::from(b)
    } else {
        '?'
    }
}

/// Parse a 2IMG image: the header in notes and metadata, then the DOS 3.3
/// or `ProDOS` filesystem in the data chunk in the order the header names.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = Header::parse(data)?;
    let data_end = header.data.offset + header.data.len;
    let mut c = Container::new(FileFormat::TwoImg, Layout::TwoImg.label(), KEY_PREFIX);
    c.notes.push(format!(
        "2IMG image by creator '{}'; {}; {} B of data at 0x{:X}",
        header.creator,
        format_name(header.format),
        header.data.len,
        header.data.offset
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_twoimg_creator"),
        "2IMG creator",
        header.creator.clone(),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_twoimg_image_format"),
        "2IMG image format",
        format_name(header.format),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_twoimg_data_offset"),
        "2IMG data offset",
        header.data.offset as u64,
    );
    describe_flags(&header, &mut c);
    if header.format == FORMAT_DOS_ORDER
        && header.blocks != 0
        && usize::try_from(header.blocks)
            .ok()
            .and_then(|b| b.checked_mul(BLOCK_SIZE))
            != Some(header.data.len)
    {
        c.notes.push(format!(
            "The block count {} does not match the {} B of DOS-order data (the field is defined \
             for ProDOS order only)",
            header.blocks, header.data.len
        ));
    }
    let end = describe_chunks(data, &header, &mut c);
    c.consumed = end;
    if end < data.len() {
        c.notes.push(format!(
            "{} B after the last chunk at 0x{end:X}",
            data.len() - end
        ));
    }
    let order = match header.format {
        FORMAT_DOS_ORDER => Order::Dos,
        FORMAT_PRODOS_ORDER => Order::ProDos,
        _ => {
            c.notes.push(
                "Nibble data: 35 tracks of 6656 B; nibble decoding is not implemented".to_string(),
            );
            c.children.push(Child::opaque(
                "Nibble data",
                header.data.offset,
                &data[header.data.offset..data_end],
            ));
            return Ok(c);
        }
    };
    let disk = Disk::new(data, header.data.offset, header.data.len, order)
        .expect("the data size was checked for the order");
    push_filesystem(disk, &mut c);
    Ok(c)
}

/// The other sector order.
fn other(order: Order) -> Order {
    match order {
        Order::Dos => Order::ProDos,
        Order::ProDos => Order::Dos,
    }
}

/// The lock flag, the DOS volume number and reserved bits.
fn describe_flags(header: &Header, c: &mut Container<'_>) {
    let volume = if header.flags & FLAG_VOLUME_NUMBER != 0 {
        header.flags & VOLUME_NUMBER_MASK
    } else {
        DEFAULT_VOLUME_NUMBER
    };
    let locked = if header.flags & FLAG_LOCKED != 0 {
        "locked"
    } else {
        "not locked"
    };
    c.notes.push(format!(
        "2IMG flags 0x{:08X}: {locked}; sector volume number {volume}",
        header.flags
    ));
    if header.flags & RESERVED_FLAGS != 0 {
        c.notes.push(format!(
            "Reserved 2IMG flag bits are set: 0x{:08X}",
            header.flags & RESERVED_FLAGS
        ));
    }
}

/// Notes for the comment and creator chunks; returns the end of the last
/// valid chunk. A chunk that overlaps an earlier one or leaves the file is
/// noted and ignored ([CP2] `TwoIMG.ValidateHeader`).
fn describe_chunks(data: &[u8], header: &Header, c: &mut Container<'_>) -> usize {
    let mut end = header.data.offset + header.data.len;
    if header.comment.is_present() {
        match header.comment.end_within(data.len()) {
            Some(comment_end) if header.comment.offset >= end => {
                let text: String = data[header.comment.offset..comment_end]
                    .iter()
                    .map(|&b| {
                        if b == b'\r' || b == b'\n' {
                            ' '
                        } else {
                            printable(b)
                        }
                    })
                    .take(MAX_COMMENT_NOTE)
                    .collect();
                let text = text.trim_end().to_string();
                c.notes.push(format!("2IMG comment: {text}"));
                c.push_metadata(format!("{KEY_PREFIX}_twoimg_comment"), "2IMG comment", text);
                end = comment_end;
            }
            _ => c.notes.push(format!(
                "The 2IMG comment chunk 0x{:X} + {} B overlaps the data or leaves the file; \
                 ignored",
                header.comment.offset, header.comment.len
            )),
        }
    }
    if header.creator_data.is_present() {
        match header.creator_data.end_within(data.len()) {
            Some(creator_end) if header.creator_data.offset >= end => {
                c.notes.push(format!(
                    "2IMG creator data: {} B at 0x{:X}; not interpreted",
                    header.creator_data.len, header.creator_data.offset
                ));
                end = creator_end;
            }
            _ => c.notes.push(format!(
                "The 2IMG creator data chunk 0x{:X} + {} B overlaps an earlier chunk or leaves \
                 the file; ignored",
                header.creator_data.offset, header.creator_data.len
            )),
        }
    }
    end
}

/// List the DOS 3.3 or `ProDOS` filesystem of the data chunk. Like [CP2]
/// `AnalyzeFileSystem`, 16-sector floppy data is also tried in the other
/// sector order, the header's order first: a DOS 3.3 catalog by its chain
/// ([`Dos33Evidence::order`], the header winning ties), a `ProDOS` volume
/// directory when it validates only in the other order. When neither
/// filesystem is found, the data is a member that is listed only when it
/// is a recognized format.
fn push_filesystem<'a>(disk: Disk<'a>, c: &mut Container<'a>) {
    let declared = disk.order;
    let floppy = dos33::is_image_size(disk.size);
    let evidence = Dos33Evidence::gather(disk.input, disk.start, disk.size);
    if let Some(OrderChoice::Found(order)) = evidence.as_ref().map(|e| e.order(Some(declared))) {
        let found = Disk { order, ..disk };
        if let Ok(catalog) = dos33::open(found) {
            c.variant = format!("2IMG, DOS 3.3, {}", order.name());
            let order_note = (order != declared).then(|| {
                format!(
                    "The header names {}, but the catalog is read in {}; its chain is {}",
                    declared.name(),
                    order.name(),
                    evidence
                        .as_ref()
                        .map(Dos33Evidence::counts)
                        .unwrap_or_default()
                )
            });
            dos33::push_volume(found, &catalog, order_note, c);
            return;
        }
    }
    let tries = if floppy { 2 } else { 1 };
    for order in [declared, other(declared)].into_iter().take(tries) {
        let Some(candidate) = Disk::new(disk.input, disk.start, disk.size, order) else {
            continue;
        };
        if let Ok(volume) = prodos::open(candidate, prodos::Fit::Within) {
            c.variant = format!("2IMG, ProDOS, {}", order.name());
            if order != declared {
                c.notes.push(format!(
                    "The header names {}, but the volume directory validates only in {}",
                    declared.name(),
                    order.name()
                ));
            }
            prodos::push_volume(candidate, &volume, c);
            return;
        }
    }
    let dos = dos33::open(disk);
    let prodos = prodos::open(disk, prodos::Fit::Within);
    let reason = |result: Result<()>| match result {
        Err(ClassifierError::Apple2ParseError { message }) => message,
        Err(failure) => failure.to_string(),
        Ok(()) => String::new(),
    };
    c.notes.push(format!(
        "No DOS 3.3 catalog or ProDOS volume directory validates in {} (DOS 3.3: {}; ProDOS: {})",
        disk.order.name(),
        reason(dos.map(|_| ())),
        reason(prodos.map(|_| ()))
    ));
    let bytes = &disk.input[disk.start..disk.start + disk.size];
    c.children
        .push(Child::stored("Disk data", disk.start, bytes).if_recognized());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(header_length: u16, version: u16, format: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[CREATOR..CREATOR + 4].copy_from_slice(b"CPII");
        bytes[HEADER_LENGTH..HEADER_LENGTH + 2].copy_from_slice(&header_length.to_le_bytes());
        bytes[VERSION..VERSION + 2].copy_from_slice(&version.to_le_bytes());
        bytes[IMAGE_FORMAT..IMAGE_FORMAT + 4].copy_from_slice(&format.to_le_bytes());
        bytes
    }

    #[test]
    fn detection_needs_the_magic_header_length_version_and_format() {
        assert!(detect(&header(64, 1, 1)));
        assert!(detect(&header(52, 1, 0)));
        assert!(detect(&header(64, 1, 2)[..DETECTION_SIZE]));
        assert!(!detect(&header(48, 1, 1)));
        assert!(!detect(&header(64, 2, 1)));
        assert!(!detect(&header(64, 1, 3)));
        assert!(!detect(&header(64, 1, 1)[..DETECTION_SIZE - 1]));
        let mut other = header(64, 1, 1);
        other[0] = b'3';
        assert!(!detect(&other));
    }

    #[test]
    fn data_sizes_follow_the_image_format() {
        assert!(check_data_size(FORMAT_PRODOS_ORDER, 280, 280 * 512).is_ok());
        assert!(check_data_size(FORMAT_PRODOS_ORDER, 0, 280 * 512).is_err());
        assert!(check_data_size(FORMAT_PRODOS_ORDER, 279, 280 * 512).is_err());
        assert!(check_data_size(FORMAT_DOS_ORDER, 0, 35 * TRACK_SIZE).is_ok());
        assert!(check_data_size(FORMAT_DOS_ORDER, 0, 35 * TRACK_SIZE + 256).is_err());
        assert!(check_data_size(FORMAT_NIBBLES, 0, 35 * 6656).is_ok());
        assert!(check_data_size(FORMAT_NIBBLES, 0, 35 * 6384).is_err());
    }
}
