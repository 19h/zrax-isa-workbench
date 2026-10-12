//! UBI images: an erase-counter header (`UBI#`) at the start of every PEB,
//! a volume-identifier header (`UBI!`) in every mapped PEB, the volume table
//! in the two LEBs of the layout volume, and each volume rebuilt from its
//! LEBs (Linux v6.11 `drivers/mtd/ubi/ubi-media.h`, `io.c`, `attach.c`,
//! `vtbl.c`).
//!
//! All header fields are big-endian, and every CRC is
//! `crc32(UBI_CRC32_INIT, ...)` without final inversion. The PEB size is not
//! stored: it is the smallest power of two at which the next valid
//! erase-counter header with the same geometry follows. Headers whose CRC
//! fails are skipped as the kernel's attach does; a header whose CRC matches
//! but whose fields are inconsistent is an error, as it is for the kernel.

use super::*;

/// Erase-counter header magic `UBI#` (`UBI_EC_HDR_MAGIC`).
pub(super) const EC_HDR_MAGIC: [u8; 4] = *b"UBI#";

/// Volume-identifier header magic `UBI!` (`UBI_VID_HDR_MAGIC`).
const VID_HDR_MAGIC: [u8; 4] = *b"UBI!";

/// The only on-flash format version (`UBI_VERSION`).
const UBI_VERSION: u8 = 1;

/// Both headers are 64 bytes; the CRC covers the first 60
/// (`UBI_EC_HDR_SIZE`, `UBI_VID_HDR_SIZE`, `UBI_*_HDR_SIZE_CRC`).
const UBI_HDR_SIZE: usize = 64;
const UBI_HDR_SIZE_CRC: usize = 60;

/// Largest valid erase counter (`UBI_MAX_ERASECOUNTER`).
const UBI_MAX_ERASECOUNTER: u64 = 0x7FFF_FFFF;

/// Volume types in VID headers and volume table records.
const UBI_VID_DYNAMIC: u8 = 1;
const UBI_VID_STATIC: u8 = 2;

/// Internal-volume compatibility flags (`UBI_COMPAT_*`).
const UBI_COMPAT_DELETE: u8 = 1;
const UBI_COMPAT_RO: u8 = 2;
const UBI_COMPAT_PRESERVE: u8 = 4;
const UBI_COMPAT_REJECT: u8 = 5;

/// First internal volume ID; the layout volume has this ID
/// (`UBI_INTERNAL_VOL_START`, `UBI_LAYOUT_VOLUME_ID`).
const UBI_INTERNAL_VOL_START: u32 = 0x7FFF_EFFF;
const UBI_LAYOUT_VOLUME_ID: u32 = UBI_INTERNAL_VOL_START;

/// Fastmap superblock and data volumes (`UBI_FM_SB_VOLUME_ID`,
/// `UBI_FM_DATA_VOLUME_ID`).
const UBI_FM_SB_VOLUME_ID: u32 = UBI_LAYOUT_VOLUME_ID + 1;
const UBI_FM_DATA_VOLUME_ID: u32 = UBI_LAYOUT_VOLUME_ID + 2;

/// LEBs of the layout volume, each a full copy of the volume table
/// (`UBI_LAYOUT_VOLUME_EBS`).
const UBI_LAYOUT_VOLUME_EBS: u32 = 2;

/// Volume table limits (`UBI_MAX_VOLUMES`, `UBI_VOL_NAME_MAX`), and the
/// name field: offset in the record and size including the NUL.
const UBI_MAX_VOLUMES: usize = 128;
const UBI_VOL_NAME_MAX: usize = 127;
const UBI_VTBL_NAME_OFFSET: usize = 16;
const UBI_VOL_NAME_SIZE: usize = UBI_VOL_NAME_MAX + 1;

/// Volume table record size and the bytes its CRC covers
/// (`UBI_VTBL_RECORD_SIZE`, `UBI_VTBL_RECORD_SIZE_CRC`).
const UBI_VTBL_RECORD_SIZE: usize = 172;
const UBI_VTBL_RECORD_SIZE_CRC: usize = 168;

/// CRC of an empty (all-zero) volume table record (`empty_vtbl_record`).
const EMPTY_VTBL_RECORD_CRC: u32 = 0xF116_C36B;

/// Smallest and largest PEB sizes tried, as powers of two (own bounds:
/// 512 B holds both headers and a volume table record; NAND erase blocks
/// do not exceed 16 MiB).
const MIN_PEB_SHIFT: u32 = 9;
const MAX_PEB_SHIFT: u32 = 24;

/// The geometry fields of an erase-counter header that every PEB repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EcHeader {
    version: u8,
    erase_counter: u64,
    vid_hdr_offset: usize,
    data_offset: usize,
    image_seq: u32,
}

/// What the start of a PEB holds.
enum EcSlot {
    /// An erase-counter header whose CRC matches.
    Header(EcHeader),
    /// Erased flash: a PEB that was never written.
    Erased,
    /// A header whose CRC fails, or a bad block.
    Corrupt,
}

/// Erase-counter header: magic, version (4), padding, erase counter (8),
/// VID header offset (16), data offset (20), image sequence (24), padding,
/// header CRC (60).
fn ec_slot(header: &[u8]) -> Result<EcSlot> {
    let header = slice(header, 0, UBI_HDR_SIZE)?;
    if is_erased(header) {
        return Ok(EcSlot::Erased);
    }
    if header[..4] != EC_HDR_MAGIC
        || crc32_ones(&header[..UBI_HDR_SIZE_CRC]) != be_u32(header, UBI_HDR_SIZE_CRC)?
    {
        return Ok(EcSlot::Corrupt);
    }
    Ok(EcSlot::Header(EcHeader {
        version: header[4],
        erase_counter: be_u64(header, 8)?,
        vid_hdr_offset: be_u32(header, 16)? as usize,
        data_offset: be_u32(header, 20)? as usize,
        image_seq: be_u32(header, 24)?,
    }))
}

/// Whether `other` places its headers as `first` does (`validate_ec_hdr`).
fn same_geometry(first: &EcHeader, other: &EcHeader) -> bool {
    other.vid_hdr_offset == first.vid_hdr_offset && other.data_offset == first.data_offset
}

/// The first PEB's header must describe a usable layout: version 1, the VID
/// header after the erase-counter header, and the data after the VID
/// header (`validate_ec_hdr`, `io_init`).
fn check_first_header(header: &EcHeader) -> Result<()> {
    if header.version != UBI_VERSION {
        return Err(error(format!(
            "Unsupported UBI version {} at 0x0",
            header.version
        )));
    }
    if header.vid_hdr_offset < UBI_HDR_SIZE
        || header.data_offset < header.vid_hdr_offset.saturating_add(UBI_HDR_SIZE)
    {
        return Err(error(format!(
            "Invalid UBI header offsets: VID header at 0x{:X}, data at 0x{:X}",
            header.vid_hdr_offset, header.data_offset
        )));
    }
    if header.erase_counter > UBI_MAX_ERASECOUNTER {
        return Err(error(format!(
            "Invalid UBI erase counter 0x{:X} at 0x0",
            header.erase_counter
        )));
    }
    Ok(())
}

/// Whether a valid erase-counter header with the geometry of `first`
/// starts at `offset`.
fn has_matching_header(data: &[u8], offset: usize, first: &EcHeader) -> bool {
    let Some(header) = data
        .get(offset..)
        .filter(|rest| rest.starts_with(&EC_HDR_MAGIC))
    else {
        return false;
    };
    matches!(ec_slot(header), Ok(EcSlot::Header(next)) if same_geometry(first, &next))
}

/// The PEB size: the smallest power of two with a valid erase-counter
/// header of PEB 0's geometry at an odd multiple of it. Headers of a larger
/// PEB size only occur at even multiples, and looking past the first
/// multiple tolerates bad or erased PEBs. The image sequence is not
/// compared here; [`scan_pebs`] checks it on every PEB.
fn peb_size(data: &[u8], first: &EcHeader) -> Result<usize> {
    for shift in MIN_PEB_SHIFT..=MAX_PEB_SHIFT {
        let size = 1usize << shift;
        if size >= data.len() {
            break;
        }
        if size < first.data_offset.saturating_add(UBI_VTBL_RECORD_SIZE) {
            continue;
        }
        let mut odd_multiples = (size..data.len()).step_by(2 * size);
        if odd_multiples.any(|offset| has_matching_header(data, offset, first)) {
            return Ok(size);
        }
    }
    Err(error(
        "Missing second UBI erase-counter header: the PEB size cannot be determined",
    ))
}

/// A mapped LEB: one PEB's volume-identifier header and data.
#[derive(Debug, Clone, Copy)]
struct Leb<'a> {
    vol_id: u32,
    lnum: u32,
    vol_type: u8,
    copy_flag: bool,
    compat: u8,
    data_size: usize,
    used_ebs: u32,
    data_pad: usize,
    data_crc: u32,
    sqnum: u64,
    /// File offset of the PEB.
    peb_offset: usize,
    /// The LEB: the PEB bytes after `data_offset`.
    data: &'a [u8],
}

impl Leb<'_> {
    /// Whether the first `data_size` bytes match `data_crc`.
    fn data_crc_matches(&self) -> bool {
        self.data
            .get(..self.data_size)
            .is_some_and(|bytes| crc32_ones(bytes) == self.data_crc)
    }

    /// File offset of the LEB data.
    fn data_offset(&self, geometry: &EcHeader) -> usize {
        self.peb_offset + geometry.data_offset
    }
}

/// What a PEB's volume-identifier header slot holds.
enum VidSlot<'a> {
    Leb(Leb<'a>),
    /// Erased: a free PEB.
    Free,
    /// A header whose CRC fails.
    Corrupt,
}

/// Volume-identifier header: magic, version (4), volume type (5), copy flag
/// (6), compat (7), volume ID (8), LEB number (12), padding, data size
/// (20), used LEBs (24), data padding (28), data CRC (32), padding,
/// sequence number (40), padding, header CRC (60). Fields are checked as
/// `validate_vid_hdr` (`io.c`) does; `leb_size` is the PEB size minus the
/// data offset.
fn vid_slot<'a>(peb: &'a [u8], peb_offset: usize, geometry: &EcHeader) -> Result<VidSlot<'a>> {
    let header = slice(peb, geometry.vid_hdr_offset, UBI_HDR_SIZE)?;
    if is_erased(header) {
        return Ok(VidSlot::Free);
    }
    if header[..4] != VID_HDR_MAGIC
        || crc32_ones(&header[..UBI_HDR_SIZE_CRC]) != be_u32(header, UBI_HDR_SIZE_CRC)?
    {
        return Ok(VidSlot::Corrupt);
    }
    let at = peb_offset + geometry.vid_hdr_offset;
    let leb_size = peb.len() - geometry.data_offset;
    let leb = Leb {
        vol_id: be_u32(header, 8)?,
        lnum: be_u32(header, 12)?,
        vol_type: header[5],
        copy_flag: header[6] == 1,
        compat: header[7],
        data_size: be_u32(header, 20)? as usize,
        used_ebs: be_u32(header, 24)?,
        data_pad: be_u32(header, 28)? as usize,
        data_crc: be_u32(header, 32)?,
        sqnum: be_u64(header, 40)?,
        peb_offset,
        data: &peb[geometry.data_offset..],
    };
    let invalid = |what: &str| error(format!("Invalid UBI VID header at 0x{at:X}: {what}"));
    if header[4] != UBI_VERSION {
        return Err(invalid("unsupported version"));
    }
    if header[6] > 1 {
        return Err(invalid("copy flag is not 0 or 1"));
    }
    // The kernel reads these fields as signed and rejects negative values.
    let signed_limit = 1u64 << 31;
    if [leb.vol_id, leb.lnum, leb.used_ebs]
        .iter()
        .any(|v| u64::from(*v) >= signed_limit)
        || leb.data_size as u64 >= signed_limit
        || leb.data_pad as u64 >= signed_limit
    {
        return Err(invalid("negative field"));
    }
    let internal = leb.vol_id >= UBI_INTERNAL_VOL_START;
    let compat = leb.compat;
    if !internal && leb.vol_id as usize >= UBI_MAX_VOLUMES {
        return Err(invalid("volume ID out of range"));
    }
    let valid_compat = if internal {
        matches!(
            compat,
            UBI_COMPAT_DELETE | UBI_COMPAT_RO | UBI_COMPAT_PRESERVE | UBI_COMPAT_REJECT
        )
    } else {
        compat == 0
    };
    if !valid_compat {
        return Err(invalid("bad compat"));
    }
    if leb.vol_type != UBI_VID_DYNAMIC && leb.vol_type != UBI_VID_STATIC {
        return Err(invalid("bad volume type"));
    }
    if leb.data_pad >= leb_size / 2 || leb.data_size > leb_size {
        return Err(invalid("data size or padding exceeds the LEB"));
    }
    if leb.vol_type == UBI_VID_STATIC {
        if leb.used_ebs == 0 || leb.data_size == 0 {
            return Err(invalid("static volume with no data"));
        }
        let last = leb.used_ebs - 1;
        if leb.lnum > last || (leb.lnum < last && leb.data_size != leb_size - leb.data_pad) {
            return Err(invalid("static LEB size disagrees with used_ebs"));
        }
    } else {
        let empty_copy = leb.copy_flag && leb.data_size == 0;
        let stray_data = !leb.copy_flag && (leb.data_crc != 0 || leb.data_size != 0);
        if empty_copy || stray_data || leb.used_ebs != 0 {
            return Err(invalid("dynamic volume fields are not zero"));
        }
    }
    Ok(VidSlot::Leb(leb))
}

/// Keep the current copy of a LEB, as `ubi_compare_lebs` decides: the
/// higher sequence number, unless that copy was written by wear levelling
/// (copy flag) and its data CRC fails.
fn newer<'a>(a: Leb<'a>, b: Leb<'a>) -> Result<Leb<'a>> {
    if a.sqnum == b.sqnum {
        return Err(error(format!(
            "Unsupported UBI image: PEBs at 0x{:X} and 0x{:X} hold LEB {} of volume {} with the same sequence number",
            a.peb_offset, b.peb_offset, a.lnum, a.vol_id
        )));
    }
    let (newest, older) = if b.sqnum > a.sqnum { (b, a) } else { (a, b) };
    if newest.copy_flag && !newest.data_crc_matches() {
        return Ok(older);
    }
    Ok(newest)
}

/// Counts of PEBs that hold no LEB.
#[derive(Debug, Default)]
struct PebCounts {
    /// The image sequence of the first PEB that records one (nonzero).
    image_seq: u32,
    total: usize,
    erased: usize,
    free: usize,
    corrupt: usize,
    first_corrupt: Option<usize>,
    /// Superseded copies of LEBs.
    stale: usize,
}

/// Every mapped LEB, the current copy of each, keyed by volume ID and LEB
/// number.
fn scan_pebs<'a>(
    data: &'a [u8],
    geometry: &EcHeader,
    peb_size: usize,
    counts: &mut PebCounts,
) -> Result<BTreeMap<(u32, u32), Leb<'a>>> {
    let mut lebs: BTreeMap<(u32, u32), Leb<'a>> = BTreeMap::new();
    for (index, peb) in data.chunks_exact(peb_size).enumerate() {
        let peb_offset = index * peb_size;
        counts.total += 1;
        let header = match ec_slot(peb)? {
            EcSlot::Header(header) => header,
            EcSlot::Erased => {
                counts.erased += 1;
                continue;
            }
            EcSlot::Corrupt => {
                counts.corrupt += 1;
                counts.first_corrupt.get_or_insert(peb_offset);
                continue;
            }
        };
        if header.version != UBI_VERSION
            || !same_geometry(geometry, &header)
            || header.erase_counter > UBI_MAX_ERASECOUNTER
        {
            return Err(error(format!(
                "Invalid UBI erase-counter header at 0x{peb_offset:X}: version, offsets or erase counter disagree with PEB 0"
            )));
        }
        // `scan_peb` in `attach.c`: the first nonzero image sequence is the
        // image's, and every other nonzero one must match it.
        if counts.image_seq == 0 {
            counts.image_seq = header.image_seq;
        } else if header.image_seq != 0 && header.image_seq != counts.image_seq {
            return Err(error(format!(
                "Invalid UBI image sequence 0x{:08X} at 0x{peb_offset:X}: expected 0x{:08X}",
                header.image_seq, counts.image_seq
            )));
        }
        let leb = match vid_slot(peb, peb_offset, geometry)? {
            VidSlot::Leb(leb) => leb,
            VidSlot::Free => {
                counts.free += 1;
                continue;
            }
            VidSlot::Corrupt => {
                counts.corrupt += 1;
                counts.first_corrupt.get_or_insert(peb_offset);
                continue;
            }
        };
        let key = (leb.vol_id, leb.lnum);
        let current = match lebs.remove(&key) {
            Some(previous) => {
                counts.stale += 1;
                newer(previous, leb)?
            }
            None => leb,
        };
        lebs.insert(key, current);
    }
    Ok(lebs)
}

/// A used volume table record.
#[derive(Debug, Clone)]
struct Volume {
    vol_id: u32,
    reserved_pebs: u32,
    data_pad: usize,
    vol_type: u8,
    upd_marker: bool,
    name: String,
}

/// Why a volume table copy cannot be used.
enum VtblFault {
    /// A record CRC fails, or its name length disagrees with the name:
    /// `vtbl_check` calls the copy corrupt, and the other copy is used.
    Corrupt,
    /// A record is invalid although its CRC matches: an error.
    Invalid(String),
}

/// Volume table record: reserved PEBs, alignment (4), data padding (8),
/// volume type (12), update marker (13), name length (14), name (16, 128
/// bytes), flags (144), padding, CRC (168). Checked as `vtbl_check` does,
/// except for the alignment's relation to the minimum I/O size and the
/// reserved PEBs' relation to the device size, which an image does not
/// record.
fn volume_table(
    copy: &[u8],
    slots: usize,
    leb_size: usize,
) -> std::result::Result<Vec<Volume>, VtblFault> {
    let mut volumes = Vec::new();
    for slot in 0..slots {
        let at = slot * UBI_VTBL_RECORD_SIZE;
        let record = &copy[at..at + UBI_VTBL_RECORD_SIZE];
        let field = |offset: usize| {
            u32::from_be_bytes(record[offset..offset + 4].try_into().expect("4 bytes"))
        };
        if crc32_ones(&record[..UBI_VTBL_RECORD_SIZE_CRC]) != field(UBI_VTBL_RECORD_SIZE_CRC) {
            return Err(VtblFault::Corrupt);
        }
        let invalid = |what: &str| {
            VtblFault::Invalid(format!("Invalid UBI volume table record {slot}: {what}"))
        };
        let reserved_pebs = field(0);
        if reserved_pebs == 0 {
            let empty = record[..UBI_VTBL_RECORD_SIZE_CRC].iter().all(|b| *b == 0)
                && field(UBI_VTBL_RECORD_SIZE_CRC) == EMPTY_VTBL_RECORD_CRC;
            if !empty {
                return Err(invalid("unused record is not empty"));
            }
            continue;
        }
        let alignment = field(4) as usize;
        let data_pad = field(8) as usize;
        let vol_type = record[12];
        let upd_marker = record[13];
        let name_len = usize::from(u16::from_be_bytes([record[14], record[15]]));
        let name = &record[UBI_VTBL_NAME_OFFSET..UBI_VTBL_NAME_OFFSET + UBI_VOL_NAME_SIZE];
        if [field(0), field(4), field(8)].iter().any(|v| *v >= 1 << 31) {
            return Err(invalid("negative field"));
        }
        if alignment == 0 || alignment > leb_size {
            return Err(invalid("bad alignment"));
        }
        if data_pad != leb_size % alignment {
            return Err(invalid("data padding disagrees with the alignment"));
        }
        if vol_type != UBI_VID_DYNAMIC && vol_type != UBI_VID_STATIC {
            return Err(invalid("bad volume type"));
        }
        if upd_marker > 1 {
            return Err(invalid("bad update marker"));
        }
        if name_len > UBI_VOL_NAME_MAX || name[0] == 0 {
            return Err(invalid("bad name length"));
        }
        let stored_len = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        if stored_len != name_len {
            return Err(VtblFault::Corrupt);
        }
        let name = String::from_utf8_lossy(&name[..name_len]).into_owned();
        if volumes.iter().any(|v: &Volume| v.name == name) {
            return Err(invalid("duplicate volume name"));
        }
        volumes.push(Volume {
            vol_id: u32::try_from(slot).expect("at most 128 slots"),
            reserved_pebs,
            data_pad,
            vol_type,
            upd_marker: upd_marker == 1,
            name,
        });
    }
    Ok(volumes)
}

/// The volume table from the layout volume's two copies, chosen as
/// `process_lvol` does: copy 0 when it is valid, else copy 1.
fn read_volume_table(
    lebs: &BTreeMap<(u32, u32), Leb<'_>>,
    leb_size: usize,
    notes: &mut Vec<String>,
) -> Result<Vec<Volume>> {
    let slots = (leb_size / UBI_VTBL_RECORD_SIZE).min(UBI_MAX_VOLUMES);
    let vtbl_size = slots * UBI_VTBL_RECORD_SIZE;
    let copies: Vec<Option<&[u8]>> = (0..UBI_LAYOUT_VOLUME_EBS)
        .map(|lnum| {
            lebs.get(&(UBI_LAYOUT_VOLUME_ID, lnum))
                .map(|leb| &leb.data[..vtbl_size])
        })
        .collect();
    let mut corrupt = 0usize;
    for (index, copy) in copies.iter().enumerate() {
        let Some(copy) = copy else {
            continue;
        };
        match volume_table(copy, slots, leb_size) {
            Ok(volumes) => {
                if index == 1 {
                    notes.push("Volume table copy 0 is missing or corrupt; copy 1 used".into());
                } else if copies[1].is_some_and(|other| other != *copy) {
                    notes.push("Volume table copies differ; copy 0 used".into());
                }
                return Ok(volumes);
            }
            Err(VtblFault::Invalid(message)) => return Err(error(message)),
            Err(VtblFault::Corrupt) => corrupt += 1,
        }
    }
    if corrupt > 0 {
        Err(error("Invalid UBI volume table: no copy is intact"))
    } else {
        Err(error("Missing UBI layout volume"))
    }
}

/// The LEBs of one volume, after the attach-time consistency checks
/// (`validate_vid_hdr` in `attach.c`, `check_av`).
fn volume_lebs<'a, 'b>(
    lebs: &'b BTreeMap<(u32, u32), Leb<'a>>,
    volume: &Volume,
) -> Result<Vec<&'b Leb<'a>>> {
    let mapped: Vec<&Leb<'a>> = lebs
        .range((volume.vol_id, 0)..=(volume.vol_id, u32::MAX))
        .map(|(_, leb)| leb)
        .collect();
    let invalid = |what: &str| {
        error(format!(
            "Invalid UBI volume {} \"{}\": {what}",
            volume.vol_id, volume.name
        ))
    };
    let Some(first) = mapped.first() else {
        return Ok(mapped);
    };
    if mapped.iter().any(|leb| {
        leb.vol_type != first.vol_type
            || leb.used_ebs != first.used_ebs
            || leb.data_pad != first.data_pad
    }) {
        return Err(invalid(
            "VID headers disagree on type, used LEBs or padding",
        ));
    }
    let highest = mapped.last().map_or(0, |leb| leb.lnum);
    if highest >= volume.reserved_pebs || first.used_ebs > volume.reserved_pebs {
        return Err(invalid("LEB number beyond the reserved PEBs"));
    }
    if first.vol_type != volume.vol_type || first.data_pad != volume.data_pad {
        return Err(invalid("VID headers disagree with the volume table"));
    }
    Ok(mapped)
}

/// The stored range of a volume's LEBs: from the first LEB's data in the
/// file to the end of the last one's, `used` bytes of each.
fn lebs_span(mapped: &[&Leb<'_>], geometry: &EcHeader, used: impl Fn(&Leb<'_>) -> usize) -> Span {
    let start = mapped
        .iter()
        .map(|leb| leb.data_offset(geometry))
        .min()
        .unwrap_or(0);
    let end = mapped
        .iter()
        .map(|leb| leb.data_offset(geometry) + used(leb))
        .max()
        .unwrap_or(start);
    Span {
        offset: start,
        size: end - start,
    }
}

/// Contents of a volume, or why they are not extracted.
enum Contents {
    Extracted(Vec<u8>),
    Opaque(String),
}

/// A dynamic volume: every LEB up to the highest mapped one, `leb_size -
/// data_pad` bytes each; unmapped LEBs read as erased flash.
fn dynamic_contents(mapped: &[&Leb<'_>], usable: usize, budget: usize) -> Contents {
    let count = mapped.last().map_or(0, |leb| leb.lnum as usize + 1);
    let Some(size) = count
        .checked_mul(usable)
        .filter(|size| *size <= MAX_PAYLOAD)
    else {
        return Contents::Opaque(format!(
            "{count} LEBs exceed the {} extraction limit",
            size_text(MAX_PAYLOAD)
        ));
    };
    if size > budget {
        return Contents::Opaque(format!(
            "extraction stopped at {}",
            size_text(MAX_EXTRACTED)
        ));
    }
    let mut out = vec![0xff; size];
    for leb in mapped {
        let at = leb.lnum as usize * usable;
        out[at..at + usable].copy_from_slice(&leb.data[..usable]);
    }
    Contents::Extracted(out)
}

/// A static volume: `data_size` bytes of each LEB from 0 to `used_ebs - 1`,
/// each verified against its data CRC.
fn static_contents(mapped: &[&Leb<'_>], budget: usize) -> Contents {
    let used_ebs = mapped.first().map_or(0, |leb| leb.used_ebs);
    if mapped.len() != used_ebs as usize {
        return Contents::Opaque(format!("{} of {used_ebs} LEBs present", mapped.len()));
    }
    if let Some(bad) = mapped.iter().find(|leb| !leb.data_crc_matches()) {
        return Contents::Opaque(format!("data CRC-32 of LEB {} fails", bad.lnum));
    }
    let size: usize = mapped.iter().map(|leb| leb.data_size).sum();
    if size > MAX_PAYLOAD {
        return Contents::Opaque(format!("{} exceeds the extraction limit", size_text(size)));
    }
    if size > budget {
        return Contents::Opaque(format!(
            "extraction stopped at {}",
            size_text(MAX_EXTRACTED)
        ));
    }
    let mut out = Vec::with_capacity(size);
    for leb in mapped {
        out.extend_from_slice(&leb.data[..leb.data_size]);
    }
    Contents::Extracted(out)
}

/// Add one volume as a child, with a note describing it.
fn push_volume<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    geometry: &EcHeader,
    leb_size: usize,
    volume: &Volume,
    mapped: &[&Leb<'a>],
    extracted: &mut usize,
) {
    let label = volume.name.clone();
    let budget = MAX_EXTRACTED - *extracted;
    let usable = leb_size - volume.data_pad;
    let is_static = volume.vol_type == UBI_VID_STATIC;
    let kind = if is_static { "static" } else { "dynamic" };
    if mapped.is_empty() {
        c.notes.push(format!(
            "Volume {} \"{label}\": {kind}, {} LEBs reserved, none mapped",
            volume.vol_id, volume.reserved_pebs
        ));
        return;
    }
    let span = if is_static {
        lebs_span(mapped, geometry, |leb| leb.data_size)
    } else {
        lebs_span(mapped, geometry, |_| usable)
    };
    let contents = if volume.upd_marker {
        Contents::Opaque("update marker set, so the contents are incomplete".into())
    } else if is_static {
        static_contents(mapped, budget)
    } else {
        dynamic_contents(mapped, usable, budget)
    };
    let summary = format!(
        "Volume {} \"{label}\": {kind}, {} of {} reserved LEBs mapped",
        volume.vol_id,
        mapped.len(),
        volume.reserved_pebs
    );
    match contents {
        Contents::Extracted(bytes) => {
            let check = if is_static {
                "; data CRC-32 verified"
            } else {
                ""
            };
            c.notes
                .push(format!("{summary}; {}{check}", size_text(bytes.len())));
            *extracted += bytes.len();
            c.children.push(Child::decoded(
                label,
                span.offset,
                span.size,
                Cow::Owned(bytes),
                "UBI volume",
            ));
        }
        Contents::Opaque(reason) => {
            c.notes.push(format!("{summary}; {reason}; not analyzed"));
            let stored = &data[span.offset..span.offset + span.size];
            c.children.push(Child::opaque(label, span.offset, stored));
        }
    }
}

/// Internal volumes other than the layout volume: fastmap is ignored, as
/// a full scan does not need it; other internal volumes are ignored unless
/// their compat flag demands that the image be rejected.
fn check_internal_volumes(
    lebs: &BTreeMap<(u32, u32), Leb<'_>>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let internal = lebs
        .range((UBI_LAYOUT_VOLUME_ID + 1, 0)..)
        .map(|(_, leb)| leb);
    let mut fastmap = 0usize;
    let mut ignored = 0usize;
    for leb in internal {
        if leb.vol_id == UBI_FM_SB_VOLUME_ID || leb.vol_id == UBI_FM_DATA_VOLUME_ID {
            fastmap += 1;
        } else if leb.compat == UBI_COMPAT_REJECT {
            return Err(error(format!(
                "Unsupported UBI internal volume 0x{:X} at 0x{:X}",
                leb.vol_id, leb.peb_offset
            )));
        } else {
            ignored += 1;
        }
    }
    if fastmap > 0 {
        notes.push(format!(
            "{fastmap} fastmap PEBs ignored; every PEB was scanned"
        ));
    }
    if ignored > 0 {
        notes.push(format!(
            "{ignored} PEBs of unknown internal volumes ignored"
        ));
    }
    Ok(())
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let geometry = match ec_slot(slice(data, 0, UBI_HDR_SIZE)?)? {
        EcSlot::Header(header) => header,
        EcSlot::Erased | EcSlot::Corrupt => {
            return Err(error("Invalid UBI erase-counter header CRC-32 at 0x0"));
        }
    };
    check_first_header(&geometry)?;
    let peb_size = peb_size(data, &geometry)?;
    let leb_size = peb_size - geometry.data_offset;
    let trailing = &data[data.len() - data.len() % peb_size..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Truncated UBI PEB at 0x{:X}: {} of {} present",
            data.len() - trailing.len(),
            size_text(trailing.len()),
            size_text(peb_size)
        )));
    }
    let mut counts = PebCounts::default();
    let lebs = scan_pebs(data, &geometry, peb_size, &mut counts)?;

    let mut c = Container::new(FileFormat::Ubi, Layout::Ubi.label(), "ubi");
    c.consumed = data.len();
    c.notes.push(format!(
        "{} PEBs of {}; VID headers at 0x{:X}, LEB data at 0x{:X}; image sequence 0x{:08X}",
        counts.total,
        size_text(peb_size),
        geometry.vid_hdr_offset,
        geometry.data_offset,
        counts.image_seq
    ));
    c.notes.push(
        "PEB size inferred from the spacing of erase-counter headers; erase-counter and VID header CRC-32 values verified"
            .into(),
    );
    if counts.free + counts.erased > 0 {
        c.notes.push(format!(
            "{} free PEBs, {} erased PEBs",
            counts.free, counts.erased
        ));
    }
    if let Some(first) = counts.first_corrupt {
        c.notes.push(format!(
            "{} PEBs with a corrupt header skipped (first at 0x{first:X})",
            counts.corrupt
        ));
    }
    if counts.stale > 0 {
        c.notes.push(format!(
            "{} superseded LEB copies ignored (lower sequence number)",
            counts.stale
        ));
    }
    let user_lebs = lebs
        .keys()
        .filter(|(vol_id, _)| *vol_id < UBI_INTERNAL_VOL_START)
        .count();
    let has_layout = lebs.contains_key(&(UBI_LAYOUT_VOLUME_ID, 0))
        || lebs.contains_key(&(UBI_LAYOUT_VOLUME_ID, 1));
    let volumes = if !has_layout && user_lebs == 0 {
        c.notes.push("No volumes: the UBI device is empty".into());
        Vec::new()
    } else {
        let volumes = read_volume_table(&lebs, leb_size, &mut c.notes)?;
        c.notes.push(format!(
            "Volume table: {} volumes; record CRC-32 values verified",
            volumes.len()
        ));
        volumes
    };
    check_internal_volumes(&lebs, &mut c.notes)?;

    let slots = (leb_size / UBI_VTBL_RECORD_SIZE).min(UBI_MAX_VOLUMES);
    if let Some(((vol_id, _), _)) = lebs
        .iter()
        .find(|((vol_id, _), _)| *vol_id < UBI_INTERNAL_VOL_START && *vol_id as usize >= slots)
    {
        return Err(error(format!(
            "Invalid UBI volume ID {vol_id}: the volume table has {slots} slots"
        )));
    }
    let removed = lebs
        .keys()
        .filter(|(vol_id, _)| {
            *vol_id < UBI_INTERNAL_VOL_START && !volumes.iter().any(|v| v.vol_id == *vol_id)
        })
        .count();
    if removed > 0 {
        c.notes.push(format!(
            "{removed} LEBs of volumes missing from the volume table ignored"
        ));
    }

    let mut extracted = 0usize;
    for volume in &volumes {
        let mapped = volume_lebs(&lebs, volume)?;
        push_volume(
            &mut c,
            data,
            &geometry,
            leb_size,
            volume,
            &mapped,
            &mut extracted,
        );
    }
    c.push_metadata("ubi_peb_size", "PEB size (B)", peb_size as u64);
    c.push_metadata(
        "ubi_vid_header_offset",
        "VID header offset (B)",
        geometry.vid_hdr_offset as u64,
    );
    c.push_metadata(
        "ubi_data_offset",
        "LEB data offset (B)",
        geometry.data_offset as u64,
    );
    c.push_metadata(
        "ubi_image_sequence",
        "Image sequence number",
        MetadataValue::Hex(counts.image_seq),
    );
    c.push_metadata("ubi_peb_count", "PEBs", counts.total as u64);
    c.push_metadata("ubi_volume_count", "Volumes", volumes.len() as u64);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An erase-counter header with the given offsets and its CRC.
    fn ec_header(vid_hdr_offset: u32, data_offset: u32, image_seq: u32) -> Vec<u8> {
        let mut header = vec![0u8; UBI_HDR_SIZE];
        header[..4].copy_from_slice(&EC_HDR_MAGIC);
        header[4] = UBI_VERSION;
        header[16..20].copy_from_slice(&vid_hdr_offset.to_be_bytes());
        header[20..24].copy_from_slice(&data_offset.to_be_bytes());
        header[24..28].copy_from_slice(&image_seq.to_be_bytes());
        let crc = crc32_ones(&header[..UBI_HDR_SIZE_CRC]);
        header[60..].copy_from_slice(&crc.to_be_bytes());
        header
    }

    #[test]
    fn peb_size_is_the_first_power_of_two_with_a_matching_header() {
        let mut data = vec![0xffu8; 8192];
        data[..64].copy_from_slice(&ec_header(64, 128, 7));
        // A header with other offsets at 1 KiB does not count.
        data[1024..1088].copy_from_slice(&ec_header(512, 1024, 7));
        data[4096..4160].copy_from_slice(&ec_header(64, 128, 7));
        let EcSlot::Header(first) = ec_slot(&data).unwrap() else {
            panic!("valid header");
        };
        assert_eq!(peb_size(&data, &first).unwrap(), 4096);
        data[4096] ^= 1;
        assert!(peb_size(&data, &first).is_err());
    }

    #[test]
    fn peb_size_discovery_skips_bad_blocks() {
        // PEB 1 of four 4 KiB PEBs is bad; PEB 3 still fixes the size, and
        // PEB 2's header at 8 KiB does not make it 8 KiB.
        let mut data = vec![0xffu8; 4 * 4096];
        for peb in [0, 2, 3] {
            data[peb * 4096..peb * 4096 + 64].copy_from_slice(&ec_header(64, 128, 7));
        }
        data[4096..8192].fill(0);
        let EcSlot::Header(first) = ec_slot(&data).unwrap() else {
            panic!("valid header");
        };
        assert_eq!(peb_size(&data, &first).unwrap(), 4096);
    }

    #[test]
    fn empty_volume_table_records_have_the_documented_crc() {
        assert_eq!(
            crc32_ones(&[0u8; UBI_VTBL_RECORD_SIZE_CRC]),
            EMPTY_VTBL_RECORD_CRC
        );
    }
}
