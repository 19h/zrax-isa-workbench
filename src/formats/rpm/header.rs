//! The header structure that both the signature and the main header use
//! (rpm `docs/manual/format_header.md`; LSB 5.0 section 25.2.2): a 16-byte
//! intro (magic `8E AD E8 01`, four reserved zero bytes, the index entry
//! count and the data store size), the index entries (tag, type, offset,
//! count; 4 bytes each) and the data store.
//!
//! The checks are rpm's own (`lib/header.cc`): the count and size limits
//! of `hdrblobVerifyLengths`, the immutable region of
//! `hdrblobVerifyRegion`, and the per-entry checks of `hdrblobVerifyInfo`
//! (tag, type, count, alignment, data inside the store, no overlap with
//! the previous entry's data or with the region trailer).

use super::*;

/// Header structure magic: `8E AD E8`, header version 1 and four reserved
/// zero bytes (`rpm_header_magic`; `hdrblobRead` compares all eight).
pub(super) const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];

/// Intro size: magic, index entry count, data store size.
const INTRO_SIZE: usize = 16;

/// Index entry size: tag, type, offset, count.
const ENTRY_SIZE: usize = 16;

/// Entry types (`rpmTagType`; `RPM_MIN_TYPE` 1 to `RPM_MAX_TYPE` 9).
pub(super) const RPM_CHAR_TYPE: u32 = 1;
pub(super) const RPM_INT8_TYPE: u32 = 2;
pub(super) const RPM_INT16_TYPE: u32 = 3;
pub(super) const RPM_INT32_TYPE: u32 = 4;
pub(super) const RPM_INT64_TYPE: u32 = 5;
pub(super) const RPM_STRING_TYPE: u32 = 6;
pub(super) const RPM_BIN_TYPE: u32 = 7;
pub(super) const RPM_STRING_ARRAY_TYPE: u32 = 8;
pub(super) const RPM_I18NSTRING_TYPE: u32 = 9;

/// Region tags (`HEADER_IMAGE`, `HEADER_SIGNATURES`, `HEADER_IMMUTABLE`).
const HEADER_IMAGE: u32 = 61;
const HEADER_SIGNATURES: u32 = 62;
const HEADER_IMMUTABLE: u32 = 63;

/// Tags below this are reserved for regions (`HEADER_I18NTABLE`,
/// `hdrchkTag`).
const HEADER_I18NTABLE: u32 = 100;

/// A region entry and its trailer are BIN entries of 16 bytes
/// (`REGION_TAG_TYPE`, `REGION_TAG_COUNT`).
const REGION_TAG_COUNT: usize = 16;

/// Most index entries and data store bytes of a signature header and of
/// any other header (`hdrblobVerifyLengths`).
const SIGNATURE_MAX_ENTRIES: usize = 32;
const SIGNATURE_MAX_STORE: usize = 64 << 20;
const HEADER_MAX_ENTRIES: usize = 0xffff;
const HEADER_MAX_STORE: usize = 0x0fff_ffff;

/// Largest header blob rpm reads: count and size fields, index and store
/// (`headerMaxbytes`).
const HEADER_MAX_BYTES: usize = 256 << 20;

/// Most values in an entry that is not BIN (`HEADER_ARRAY_MAX`).
const HEADER_ARRAY_MAX: usize = 0x000f_ffff;

/// Which header a structure is, for its region tag and limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeaderKind {
    /// The signature header after the lead.
    Signature,
    /// The main header after the signature header.
    Main,
}

impl HeaderKind {
    /// Name in notes and errors.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Signature => "signature header",
            Self::Main => "main header",
        }
    }

    fn region_tag(self) -> u32 {
        match self {
            Self::Signature => HEADER_SIGNATURES,
            Self::Main => HEADER_IMMUTABLE,
        }
    }

    fn max_entries(self) -> usize {
        match self {
            Self::Signature => SIGNATURE_MAX_ENTRIES,
            Self::Main => HEADER_MAX_ENTRIES,
        }
    }

    fn max_store(self) -> usize {
        match self {
            Self::Signature => SIGNATURE_MAX_STORE,
            Self::Main => HEADER_MAX_STORE,
        }
    }

    /// A package's main header region must span the whole header
    /// (`exact_size` in `package.cc`); the signature region need not.
    fn region_spans_header(self) -> bool {
        self == Self::Main
    }
}

/// One validated index entry.
#[derive(Debug, Clone, Copy)]
struct Entry {
    tag: u32,
    kind: u32,
    /// Offset of the data in the store.
    offset: usize,
    count: usize,
    /// Length of the data in the store.
    len: usize,
}

/// A parsed header structure.
#[derive(Debug)]
pub(super) struct Header<'a> {
    /// Which header this is.
    pub(super) kind: HeaderKind,
    /// File offset of the intro.
    pub(super) offset: usize,
    /// Stored size: intro, index and store.
    pub(super) size: usize,
    /// The stored bytes, which the header digests cover.
    pub(super) bytes: &'a [u8],
    /// The first entry is a valid immutable region.
    pub(super) region: bool,
    store: &'a [u8],
    entries: Vec<Entry>,
}

/// An index entry as stored: tag, type, offset (signed), count.
#[derive(Debug, Clone, Copy)]
struct RawEntry {
    tag: u32,
    kind: u32,
    offset: i32,
    count: u32,
}

impl RawEntry {
    fn read(index: &[u8], i: usize) -> Result<Self> {
        let at = i * ENTRY_SIZE;
        Ok(Self {
            tag: be_u32(index, at)?,
            kind: be_u32(index, at + 4)?,
            offset: i32::from_be_bytes(array(index, at + 8)?),
            count: be_u32(index, at + 12)?,
        })
    }
}

/// The immutable region the first entry describes.
#[derive(Debug, Clone, Copy)]
struct Region {
    /// Store bytes up to the end of the region trailer (`rdl`).
    store_size: usize,
}

/// Parse the header structure at `offset`.
///
/// # Errors
///
/// A missing magic, counts or sizes beyond rpm's limits, a structure that
/// does not fit the file, an invalid region or an invalid entry.
pub(super) fn parse(data: &[u8], offset: usize, kind: HeaderKind) -> Result<Header<'_>> {
    let name = kind.name();
    let intro = slice(data, offset, INTRO_SIZE, name)?;
    if intro[..HEADER_MAGIC.len()] != HEADER_MAGIC {
        return Err(error(format!("Missing {name} magic at 0x{offset:X}")));
    }
    let count = to_usize(be_u32(intro, 8)?);
    let store_size = to_usize(be_u32(intro, 12)?);
    if count == 0 || count > kind.max_entries() {
        return Err(error(format!(
            "Invalid {name} entry count {count} at 0x{:X} (1 to {})",
            offset + 8,
            kind.max_entries()
        )));
    }
    if store_size > kind.max_store() {
        return Err(error(format!(
            "Invalid {name} data size {store_size} B at 0x{:X} (at most {})",
            offset + 12,
            size_text(kind.max_store())
        )));
    }
    // Both limits keep this far below the address space.
    let size = INTRO_SIZE + count * ENTRY_SIZE + store_size;
    if size - HEADER_MAGIC.len() >= HEADER_MAX_BYTES {
        return Err(error(format!(
            "Invalid {name} size {size} B at 0x{offset:X} (under {})",
            size_text(HEADER_MAX_BYTES)
        )));
    }
    let bytes = slice(data, offset, size, name)?;
    let index = &bytes[INTRO_SIZE..INTRO_SIZE + count * ENTRY_SIZE];
    let store = &bytes[INTRO_SIZE + count * ENTRY_SIZE..];
    let raw = (0..count)
        .map(|i| RawEntry::read(index, i))
        .collect::<Result<Vec<_>>>()?;
    let region = region(&raw, store, kind, offset)?;
    let skipped = usize::from(region.is_some());
    let entries = entries(&raw[skipped..], store, region, kind, offset + INTRO_SIZE)?;
    Ok(Header {
        kind,
        offset,
        size,
        bytes,
        region: region.is_some(),
        store,
        entries,
    })
}

/// The immutable region, when the first entry carries the region tag
/// (`hdrblobVerifyRegion`). A first entry with another tag is a legacy
/// header without a region, which rpm accepts.
fn region(
    raw: &[RawEntry],
    store: &[u8],
    kind: HeaderKind,
    offset: usize,
) -> Result<Option<Region>> {
    let name = kind.name();
    let first = raw[0];
    if first.tag != kind.region_tag() {
        return Ok(None);
    }
    let entry_at = offset + INTRO_SIZE;
    if first.kind != RPM_BIN_TYPE || to_usize(first.count) != REGION_TAG_COUNT {
        return Err(error(format!(
            "Invalid {name} region entry at 0x{entry_at:X}: type {} count {}",
            first.kind, first.count
        )));
    }
    let trailer_at = usize::try_from(first.offset)
        .ok()
        .filter(|at| {
            at.checked_add(REGION_TAG_COUNT)
                .is_some_and(|end| end <= store.len())
        })
        .ok_or_else(|| {
            error(format!(
                "Invalid {name} region offset {} at 0x{entry_at:X}",
                first.offset
            ))
        })?;
    let trailer = RawEntry::read(&store[trailer_at..trailer_at + REGION_TAG_COUNT], 0)?;
    // Some old packages carry `HEADER_IMAGE` in the signature trailer.
    let trailer_tag_ok = trailer.tag == kind.region_tag()
        || (kind == HeaderKind::Signature && trailer.tag == HEADER_IMAGE);
    let trailer_file_offset = offset + INTRO_SIZE + raw.len() * ENTRY_SIZE + trailer_at;
    if !trailer_tag_ok
        || trailer.kind != RPM_BIN_TYPE
        || to_usize(trailer.count) != REGION_TAG_COUNT
    {
        return Err(error(format!(
            "Invalid {name} region trailer at 0x{trailer_file_offset:X}: tag {} type {} count {}",
            trailer.tag, trailer.kind, trailer.count
        )));
    }
    // The trailer's offset is the negated size of the region's index
    // entries.
    let index_size = usize::try_from(trailer.offset.unsigned_abs())
        .expect("usize holds a u32 on supported targets");
    let entry_count = index_size / ENTRY_SIZE;
    let store_size = trailer_at + REGION_TAG_COUNT;
    if trailer.offset > 0 || index_size % ENTRY_SIZE != 0 || entry_count > raw.len() {
        return Err(error(format!(
            "Invalid {name} region size at 0x{trailer_file_offset:X}: {entry_count} of {} \
             entries",
            raw.len()
        )));
    }
    if kind.region_spans_header() && (entry_count != raw.len() || store_size != store.len()) {
        return Err(error(format!(
            "Invalid {name} region at 0x{trailer_file_offset:X}: it covers {entry_count} of {} \
             entries and {store_size} of {} data bytes",
            raw.len(),
            store.len()
        )));
    }
    Ok(Some(Region { store_size }))
}

/// Validate every entry after the region entry, in index order, as
/// `hdrblobVerifyInfo` does. Each entry's data must start at or after the
/// end of the previous entry's, which is checked before the data is
/// measured, so measuring walks every store byte at most once.
fn entries(
    raw: &[RawEntry],
    store: &[u8],
    region: Option<Region>,
    kind: HeaderKind,
    index_offset: usize,
) -> Result<Vec<Entry>> {
    let skipped = usize::from(region.is_some());
    let mut entries = Vec::with_capacity(raw.len());
    let mut previous_end = 0usize;
    for (i, raw) in raw.iter().enumerate() {
        let entry_at = index_offset + (i + skipped) * ENTRY_SIZE;
        let entry = entry(*raw, store, kind, entry_at, previous_end)?;
        let end = entry.offset + entry.len;
        if let Some(region) = region {
            let trailer = region.store_size - REGION_TAG_COUNT;
            if end > trailer && entry.offset < region.store_size {
                return Err(error(format!(
                    "Invalid {} entry at 0x{entry_at:X}: tag {} data overlaps the region trailer",
                    kind.name(),
                    entry.tag
                )));
            }
        }
        previous_end = end;
        entries.push(entry);
    }
    Ok(entries)
}

/// One entry's checks: tag, type, count, data offset at or after
/// `previous_end`, alignment, and the data inside the store.
fn entry(
    raw: RawEntry,
    store: &[u8],
    kind: HeaderKind,
    entry_at: usize,
    previous_end: usize,
) -> Result<Entry> {
    let invalid = |what: String| {
        error(format!(
            "Invalid {} entry at 0x{entry_at:X}: tag {} {what}",
            kind.name(),
            raw.tag
        ))
    };
    if raw.tag < HEADER_I18NTABLE {
        return Err(invalid("is reserved for regions".to_string()));
    }
    let Some(element_size) = element_size(raw.kind) else {
        return Err(invalid(format!("has unknown type {}", raw.kind)));
    };
    let count = to_usize(raw.count);
    if count == 0 || count > store.len() {
        return Err(invalid(format!("has count {count}")));
    }
    if raw.kind != RPM_BIN_TYPE && count > HEADER_ARRAY_MAX {
        return Err(invalid(format!(
            "has {count} values (at most {HEADER_ARRAY_MAX})"
        )));
    }
    let offset = usize::try_from(raw.offset)
        .ok()
        .filter(|offset| *offset <= store.len())
        .ok_or_else(|| invalid(format!("has data offset {} outside the store", raw.offset)))?;
    if offset < previous_end {
        return Err(invalid(format!(
            "data at {offset} overlaps the previous entry's"
        )));
    }
    if element_size > 1 && offset % element_size != 0 {
        return Err(invalid(format!(
            "has data offset {offset} not aligned to {element_size} bytes"
        )));
    }
    let len = data_len(raw.kind, &store[offset..], count, element_size)
        .ok_or_else(|| invalid(format!("data at {offset} does not fit the store")))?;
    Ok(Entry {
        tag: raw.tag,
        kind: raw.kind,
        offset,
        count,
        len,
    })
}

/// Size of one value of a fixed-size type, 1 for strings and binary data;
/// `None` for an unknown type.
fn element_size(kind: u32) -> Option<usize> {
    match kind {
        RPM_CHAR_TYPE
        | RPM_INT8_TYPE
        | RPM_BIN_TYPE
        | RPM_STRING_TYPE
        | RPM_STRING_ARRAY_TYPE
        | RPM_I18NSTRING_TYPE => Some(1),
        RPM_INT16_TYPE => Some(2),
        RPM_INT32_TYPE => Some(4),
        RPM_INT64_TYPE => Some(8),
        _ => None,
    }
}

/// Length of an entry's data at the start of `rest` (`dataLength`): a
/// fixed-size array, or `count` NUL-terminated strings (a STRING has
/// exactly one). `None` when the data does not fit.
fn data_len(kind: u32, rest: &[u8], count: usize, element_size: usize) -> Option<usize> {
    match kind {
        RPM_STRING_TYPE | RPM_STRING_ARRAY_TYPE | RPM_I18NSTRING_TYPE => {
            if kind == RPM_STRING_TYPE && count != 1 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..count {
                let nul = memchr::memchr(0, rest.get(len..)?)?;
                len += nul + 1;
            }
            Some(len)
        }
        _ => count
            .checked_mul(element_size)
            .filter(|len| *len <= rest.len()),
    }
}

impl<'a> Header<'a> {
    /// Number of index entries, the region entry included.
    pub(super) fn len(&self) -> usize {
        self.entries.len() + usize::from(self.region)
    }

    /// Whether the header has an entry for `tag`.
    pub(super) fn contains(&self, tag: u32) -> bool {
        self.find(tag).is_some()
    }

    fn find(&self, tag: u32) -> Option<&Entry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    /// The entry for `tag`, which must have one of the `kinds`.
    fn typed(&self, tag: u32, kinds: &[u32]) -> Result<Option<&Entry>> {
        let Some(entry) = self.find(tag) else {
            return Ok(None);
        };
        if !kinds.contains(&entry.kind) {
            return Err(error(format!(
                "Invalid {} tag {tag}: type {}, expected {}",
                self.kind.name(),
                entry.kind,
                kinds
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(" or ")
            )));
        }
        Ok(Some(entry))
    }

    fn data(&self, entry: &Entry) -> &'a [u8] {
        &self.store[entry.offset..entry.offset + entry.len]
    }

    /// The text of a `STRING` entry, or the first string of an
    /// `I18NSTRING` or `STRING_ARRAY` entry, without its NUL.
    pub(super) fn string(&self, tag: u32) -> Result<Option<&'a [u8]>> {
        let kinds = [RPM_STRING_TYPE, RPM_I18NSTRING_TYPE, RPM_STRING_ARRAY_TYPE];
        Ok(self
            .typed(tag, &kinds)?
            .map(|entry| until_nul(self.data(entry))))
    }

    /// The strings of a `STRING_ARRAY` or `I18NSTRING` entry, without NULs.
    pub(super) fn strings(&self, tag: u32) -> Result<Option<Vec<&'a [u8]>>> {
        let kinds = [RPM_STRING_ARRAY_TYPE, RPM_I18NSTRING_TYPE];
        let Some(entry) = self.typed(tag, &kinds)? else {
            return Ok(None);
        };
        let data = self.data(entry);
        // Validation found exactly `count` NUL-terminated strings.
        let strings = data[..data.len() - 1].split(|&b| b == 0).collect();
        Ok(Some(strings))
    }

    /// The bytes of a BIN entry.
    pub(super) fn bin(&self, tag: u32) -> Result<Option<&'a [u8]>> {
        Ok(self
            .typed(tag, &[RPM_BIN_TYPE])?
            .map(|entry| self.data(entry)))
    }

    /// The values of an INT16 array entry.
    pub(super) fn u16s(&self, tag: u32) -> Result<Option<Vec<u16>>> {
        let Some(entry) = self.typed(tag, &[RPM_INT16_TYPE])? else {
            return Ok(None);
        };
        let values = self
            .data(entry)
            .chunks_exact(2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
            .collect();
        Ok(Some(values))
    }

    /// The values of an INT32 array entry.
    pub(super) fn u32s(&self, tag: u32) -> Result<Option<Vec<u32>>> {
        let Some(entry) = self.typed(tag, &[RPM_INT32_TYPE])? else {
            return Ok(None);
        };
        let values = self
            .data(entry)
            .chunks_exact(4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            .collect();
        Ok(Some(values))
    }

    /// The values of an INT64 array entry.
    pub(super) fn u64s(&self, tag: u32) -> Result<Option<Vec<u64>>> {
        let Some(entry) = self.typed(tag, &[RPM_INT64_TYPE])? else {
            return Ok(None);
        };
        let data = self.data(entry);
        let values = (0..entry.count)
            .map(|i| be_u64(data, i * 8))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(values))
    }

    /// The first value of an INT16, INT32 or INT64 entry, such as a size.
    pub(super) fn number(&self, tag: u32) -> Result<Option<u64>> {
        let kinds = [RPM_INT16_TYPE, RPM_INT32_TYPE, RPM_INT64_TYPE];
        let Some(entry) = self.typed(tag, &kinds)? else {
            return Ok(None);
        };
        let data = self.data(entry);
        let value = match entry.kind {
            RPM_INT16_TYPE => u64::from(be_u16(data, 0)?),
            RPM_INT32_TYPE => u64::from(be_u32(data, 0)?),
            _ => be_u64(data, 0)?,
        };
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One index entry as stored.
    #[derive(Clone, Copy)]
    struct Index {
        tag: u32,
        kind: u32,
        offset: i32,
        count: u32,
    }

    const fn index(tag: u32, kind: u32, offset: i32, count: u32) -> Index {
        Index {
            tag,
            kind,
            offset,
            count,
        }
    }

    fn be_len(len: usize) -> [u8; 4] {
        u32::try_from(len)
            .expect("test sizes fit in 32 bits")
            .to_be_bytes()
    }

    /// A header structure: magic, entry count, store size, the entries
    /// (tag, type, offset, count) and the store.
    fn structure(entries: &[Index], store: &[u8]) -> Vec<u8> {
        let mut out = HEADER_MAGIC.to_vec();
        out.extend_from_slice(&be_len(entries.len()));
        out.extend_from_slice(&be_len(store.len()));
        for entry in entries {
            out.extend_from_slice(&entry.tag.to_be_bytes());
            out.extend_from_slice(&entry.kind.to_be_bytes());
            out.extend_from_slice(&entry.offset.to_be_bytes());
            out.extend_from_slice(&entry.count.to_be_bytes());
        }
        out.extend_from_slice(store);
        out
    }

    /// The 16-byte region trailer for `entries` index entries.
    fn trailer(tag: u32, entries: i32) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&RPM_BIN_TYPE.to_be_bytes());
        out.extend_from_slice(&(-entries * 16).to_be_bytes());
        out.extend_from_slice(&16u32.to_be_bytes());
        out
    }

    /// A main header with a region over a NAME string and an INT32 SIZE.
    fn main_header() -> Vec<u8> {
        let mut store = b"hello\0\0\0".to_vec();
        store.extend_from_slice(&1234u32.to_be_bytes());
        let trailer_at = i32::try_from(store.len()).expect("small store");
        store.extend_from_slice(&trailer(HEADER_IMMUTABLE, 3));
        structure(
            &[
                index(HEADER_IMMUTABLE, RPM_BIN_TYPE, trailer_at, 16),
                index(1000, RPM_STRING_TYPE, 0, 1),
                index(1009, RPM_INT32_TYPE, 8, 1),
            ],
            &store,
        )
    }

    #[test]
    fn regions_and_typed_values_are_read() {
        let data = main_header();
        let header = parse(&data, 0, HeaderKind::Main).unwrap();
        assert!(header.region);
        assert_eq!(header.len(), 3);
        assert_eq!(header.size, data.len());
        assert_eq!(header.string(1000).unwrap(), Some(&b"hello"[..]));
        assert_eq!(header.number(1009).unwrap(), Some(1234));
        assert_eq!(header.u32s(1009).unwrap(), Some(vec![1234]));
        assert_eq!(header.string(1001).unwrap(), None);
        assert!(header.number(1000).is_err());
        assert!(header.contains(1009));
    }

    #[test]
    fn main_header_regions_must_span_the_header() {
        let mut data = main_header();
        // Trailer offset: region of 2 entries.
        let trailer_offset_at = data.len() - 8;
        data[trailer_offset_at..trailer_offset_at + 4].copy_from_slice(&(-32i32).to_be_bytes());
        let message = parse(&data, 0, HeaderKind::Main).unwrap_err().to_string();
        assert!(message.contains("it covers 2 of 3 entries"), "{message}");
    }

    #[test]
    fn headers_without_a_region_are_legacy() {
        let data = structure(&[index(1000, RPM_STRING_TYPE, 0, 1)], b"name\0");
        let header = parse(&data, 0, HeaderKind::Main).unwrap();
        assert!(!header.region);
        assert_eq!(header.len(), 1);
    }

    #[test]
    fn entries_are_checked_as_rpm_checks_them() {
        let cases: [(&[Index], &[u8], &str); 7] = [
            (
                &[index(99, RPM_STRING_TYPE, 0, 1)],
                b"a\0",
                "reserved for regions",
            ),
            (&[index(1000, 10, 0, 1)], b"a\0", "unknown type 10"),
            (&[index(1000, RPM_INT32_TYPE, 2, 1)], &[0; 8], "not aligned"),
            (
                &[index(1000, RPM_STRING_TYPE, 0, 1)],
                b"abc",
                "does not fit",
            ),
            (
                &[index(1000, RPM_STRING_TYPE, 0, 2)],
                b"a\0b\0",
                "does not fit",
            ),
            (&[index(1000, RPM_INT32_TYPE, 0, 0)], &[0; 4], "count 0"),
            (
                &[
                    index(1000, RPM_STRING_TYPE, 2, 1),
                    index(1001, RPM_STRING_TYPE, 0, 1),
                ],
                b"a\0b\0",
                "overlaps",
            ),
        ];
        for (entries, store, expected) in cases {
            let data = structure(entries, store);
            let message = parse(&data, 0, HeaderKind::Main).unwrap_err().to_string();
            assert!(message.contains(expected), "{expected}: {message}");
        }
    }

    #[test]
    fn counts_sizes_and_magic_are_bounded() {
        let mut data = structure(&[index(1000, RPM_STRING_TYPE, 0, 1)], b"a\0");
        data[11] = 33;
        assert!(parse(&data, 0, HeaderKind::Signature).is_err());
        let mut data = structure(&[index(1000, RPM_STRING_TYPE, 0, 1)], b"a\0");
        data[4] = 1;
        assert!(parse(&data, 0, HeaderKind::Main)
            .unwrap_err()
            .to_string()
            .contains("Missing main header magic"));
        let data = main_header();
        for end in 0..data.len() {
            assert!(parse(&data[..end], 0, HeaderKind::Main).is_err(), "{end}");
        }
    }

    #[test]
    fn string_arrays_split_into_their_strings() {
        let data = structure(&[index(1117, RPM_STRING_ARRAY_TYPE, 0, 3)], b"a\0\0bc\0");
        let header = parse(&data, 0, HeaderKind::Main).unwrap();
        let strings = header.strings(1117).unwrap().unwrap();
        assert_eq!(strings, [&b"a"[..], b"", b"bc"]);
    }
}
