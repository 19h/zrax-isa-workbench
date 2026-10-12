//! Chromium flash maps: a 56-byte little-endian header (`struct fmap`)
//! followed by 42-byte area records (`struct fmap_area`), as defined by
//! flashmap `lib/fmap.h` and coreboot `fmap_serialized.h`.
//!
//! Validation follows flashrom `is_valid_fmap` (major version 1, an image
//! at least as large as the map, a NUL-terminated printable name shorter
//! than 32 bytes), then cbfstool's rule that the image must not be larger
//! than the file and coreboot's bound of every area by the image size.
//!
//! Area offsets are taken as file offsets: fmaptool writes absolute flash
//! offsets, so the file must be the whole flash image. When the map has an
//! area named `FMAP`, that area must contain the header's file offset,
//! which checks the assumption. A map past offset 0 is found the way
//! flashmap's linear search finds it, at any byte offset, but only in
//! inputs no other format claims and with at most 64 candidates validated.
//!
//! Areas are reported by role. An area that contains a code area only
//! groups it; an area named as data (the map, GBB, VPD, version strings,
//! verified-boot blocks, ...) or as Intel ME or IE firmware is listed but
//! never analyzed; erased areas are skipped. Every other area is classified
//! on its own bytes, so a `COREBOOT` area that holds a CBFS is parsed as
//! one and raw EC firmware goes to the code model.

use super::*;
use crate::formats::container::{self, Child};

/// `"__FMAP__"`, without a terminator.
pub(super) const SIGNATURE: &[u8; 8] = b"__FMAP__";

/// `FMAP_VER_MAJOR`.
const VERSION_MAJOR: u8 = 1;

/// `sizeof(struct fmap)` and `sizeof(struct fmap_area)`.
const HEADER_SIZE: usize = 56;
const AREA_RECORD_SIZE: usize = 42;

/// `FMAP_STRLEN`: name fields, including the terminator.
const NAME_SIZE: usize = 32;

/// `FMAP_AREA_*` flags.
const AREA_STATIC: u16 = 0x1;
const AREA_COMPRESSED: u16 = 0x2;
const AREA_RO: u16 = 0x4;
const AREA_PRESERVE: u16 = 0x8;

/// Flag names, in bit order, for metadata.
const AREA_FLAGS: &[(u16, &str)] = &[
    (AREA_STATIC, "static"),
    (AREA_COMPRESSED, "compressed"),
    (AREA_RO, "read-only"),
    (AREA_PRESERVE, "preserve"),
];

/// Most `__FMAP__` signatures the search validates before it gives up.
const MAX_CANDIDATES: usize = 64;

/// Bytes of an area checked by `container::is_recognized` when the area is
/// flagged compressed.
const RECOGNITION_PREFIX: usize = 4096;

/// Name of the area that holds the map itself (`SECTION_NAME_FMAP`).
const FMAP_AREA: &str = "FMAP";

/// Underscore-separated words that mark an area as data: the map, Google
/// Binary Block (keys, HWID, bitmaps), vital product data, firmware ID
/// strings, verified-boot blocks, keys and signatures, NV storage, event
/// logs, memory-training caches, consoles and unused space. Only `FMAP` is
/// confirmed by coreboot (`cbfs_sections.h`); the Chrome OS and EC names come
/// from our reading of common images and are unconfirmed.
const DATA_AREA_WORDS: &[&str] = &[
    "FMAP", "GBB", "VPD", "FRID", "FWID", "VBLOCK", "KEY", "SIG", "NVRAM", "ELOG", "SMMSTORE",
    "CACHE", "CONSOLE", "RBVER", "ROLLBACK", "PSTATE", "GSCVD", "SHARED", "PRESERVE", "UNUSED",
];

/// ifdtool region names that hold configuration rather than code: the
/// descriptor, Gigabit Ethernet configuration, and platform data.
const DATA_AREA_NAMES: &[&str] = &["SI_DESC", "SI_GBE", "SI_PDR", "SI_10GBE0", "SI_10GBE1"];

/// ifdtool names of the Intel ME and IE regions. They hold firmware for a
/// processor other than the host, in a partition layout this parser does
/// not read, so they are listed but not analyzed rather than handed to the
/// code model whole.
const ENGINE_AREA_NAMES: &[&str] = &["SI_ME", "SI_IE"];

/// A validated `struct fmap` header.
struct Header<'a> {
    major: u8,
    minor: u8,
    /// `base`: the flash base address, reported only.
    base_address: u64,
    /// `size`: the image size in bytes.
    image_size: usize,
    name: &'a str,
    area_count: usize,
}

/// A validated `struct fmap_area`. Offsets and sizes are bytes; validation
/// bounds `end` by the image size.
struct Area<'a> {
    /// Position in the area table.
    index: usize,
    offset: usize,
    size: usize,
    end: usize,
    name: &'a str,
    flags: u16,
}

impl Area<'_> {
    /// The area's bytes; validation bounded the area by the image, and the
    /// image by the file.
    fn bytes<'d>(&self, data: &'d [u8]) -> &'d [u8] {
        &data[self.offset..self.end]
    }

    fn label(&self) -> String {
        area_label(self.index, self.offset, self.name)
    }
}

/// The area's name, or its table position and offset when it has none.
fn area_label(index: usize, offset: usize, name: &str) -> String {
    if name.is_empty() {
        format!("Area {index} at 0x{offset:X}")
    } else {
        name.to_string()
    }
}

/// A validated map and the file offset of its header.
struct Map<'a> {
    at: usize,
    header: Header<'a>,
    areas: Vec<Area<'a>>,
}

/// How an area is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Size 0.
    Empty,
    /// Groups other areas and has no bytes of its own to classify.
    Parent,
    /// Every byte is `0x00` or `0xFF`.
    Erased,
    /// Data by name: listed, never analyzed.
    Data,
    /// Intel ME or IE firmware by name: listed, never analyzed.
    Engine,
    /// Classified on its own bytes.
    Classified,
    /// Would be classified, but overlaps an area that already is.
    Overlapping,
    /// Past the component or scan limits.
    Omitted,
}

impl Role {
    fn text(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Parent => "contains other areas",
            Self::Erased => "erased",
            Self::Data => "data",
            Self::Engine => "ME or IE firmware, not parsed",
            Self::Classified => "classified",
            Self::Overlapping => "overlaps a classified area",
            Self::Omitted => "not extracted",
        }
    }
}

/// A NUL-terminated name of printable, non-space ASCII, as flashrom
/// requires of the map name; `None` otherwise.
fn name(field: &[u8]) -> Option<&str> {
    let name = c_string(field)?;
    if !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    std::str::from_utf8(name).ok()
}

/// Header: signature (8), `ver_major` (1), `ver_minor` (1), `base` (u64),
/// `size` (u32), `name` (32), `nareas` (u16); all little-endian.
fn header(data: &[u8], at: usize) -> Result<Header<'_>> {
    let bytes = field(data, at, HEADER_SIZE, "FMAP header")?;
    if !bytes.starts_with(SIGNATURE) {
        return Err(error(format!("Missing FMAP signature at 0x{at:X}")));
    }
    let major = bytes[8];
    let minor = bytes[9];
    if major != VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported FMAP version {major}.{minor} at 0x{at:X}"
        )));
    }
    let base_address = le_u64(bytes, 10)?;
    let image_size = le_u32(bytes, 18)? as usize;
    let name = name(&bytes[22..22 + NAME_SIZE]).ok_or_else(|| {
        error(format!(
            "Invalid FMAP name at 0x{:X}: not a NUL-terminated printable word",
            at + 22
        ))
    })?;
    let area_count = usize::from(le_u16(bytes, 54)?);
    let map_size = HEADER_SIZE + area_count * AREA_RECORD_SIZE;
    if image_size < map_size {
        return Err(error(format!(
            "Invalid FMAP image size {image_size} B at 0x{:X}: smaller than the {map_size} B map",
            at + 18
        )));
    }
    let room = (data.len() - at - HEADER_SIZE) / AREA_RECORD_SIZE;
    if area_count > room {
        return Err(error(format!(
            "Truncated FMAP area table at 0x{:X}: {area_count} areas declared, room for {room}",
            at + HEADER_SIZE
        )));
    }
    Ok(Header {
        major,
        minor,
        base_address,
        image_size,
        name,
        area_count,
    })
}

/// Area record at `at`: `offset` (u32), `size` (u32), `name` (32),
/// `flags` (u16); all little-endian.
fn area(data: &[u8], at: usize, index: usize, image_size: usize) -> Result<Area<'_>> {
    let record = field(data, at, AREA_RECORD_SIZE, "FMAP area")?;
    let offset = le_u32(record, 0)? as usize;
    let size = le_u32(record, 4)? as usize;
    let name = name(&record[8..8 + NAME_SIZE]).ok_or_else(|| {
        error(format!(
            "Invalid FMAP area {index} name at 0x{:X}: not a NUL-terminated printable word",
            at + 8
        ))
    })?;
    let flags = le_u16(record, 40)?;
    let end = offset
        .checked_add(size)
        .filter(|end| *end <= image_size)
        .ok_or_else(|| {
            error(format!(
                "Invalid FMAP area {}: 0x{offset:X} + {size} B is outside the {} image",
                area_label(index, offset, name),
                size_text(image_size)
            ))
        })?;
    Ok(Area {
        index,
        offset,
        size,
        end,
        name,
        flags,
    })
}

/// The map at `at`, validated against the file: header, every area, the
/// image size, the `FMAP` area and the bytes after the image.
fn validate(data: &[u8], at: usize) -> Result<Map<'_>> {
    let header = header(data, at)?;
    if header.image_size > data.len() {
        return Err(error(format!(
            "Truncated FMAP image: the map at 0x{at:X} declares {}, {} B present",
            size_text(header.image_size),
            data.len()
        )));
    }
    let areas = (0..header.area_count)
        .map(|i| {
            area(
                data,
                at + HEADER_SIZE + i * AREA_RECORD_SIZE,
                i,
                header.image_size,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let map_end = at + HEADER_SIZE + header.area_count * AREA_RECORD_SIZE;
    if map_end > header.image_size {
        return Err(error(format!(
            "Invalid FMAP at 0x{at:X}: the map ends past the {} image it describes",
            size_text(header.image_size)
        )));
    }
    let fmap_areas: Vec<&Area<'_>> = areas.iter().filter(|a| a.name == FMAP_AREA).collect();
    let holds_header = |a: &&Area<'_>| a.offset <= at && at < a.end;
    if !fmap_areas.is_empty() && !fmap_areas.iter().any(holds_header) {
        return Err(error(format!(
            "Invalid FMAP: no area named {FMAP_AREA} contains the map header at file offset 0x{at:X}"
        )));
    }
    let image_size = header.image_size;
    let trailing = &data[image_size..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Invalid trailing data: {} B after the FMAP image at 0x{image_size:X} are not erased flash",
            trailing.len()
        )));
    }
    Ok(Map { at, header, areas })
}

/// File offset of the first FMAP in `data` that validates completely. Like
/// flashmap's `fmap_find`, every byte offset is a candidate; at most
/// [`MAX_CANDIDATES`] signatures are validated.
pub(super) fn find(data: &[u8]) -> Option<usize> {
    memchr::memmem::find_iter(data, SIGNATURE)
        .take(MAX_CANDIDATES)
        .find(|&at| validate(data, at).is_ok())
}

/// Whether the name marks an area that holds data rather than code.
fn is_data_area(name: &str) -> bool {
    DATA_AREA_NAMES.contains(&name) || name.split('_').any(|word| DATA_AREA_WORDS.contains(&word))
}

/// Whether `inner` lies inside `outer`. Of two areas with the same range,
/// the later one counts as inside the earlier, because fmaptool lists a
/// parent before its children.
fn is_inside(inner: &Area<'_>, outer: &Area<'_>) -> bool {
    inner.index != outer.index
        && inner.size > 0
        && outer.offset <= inner.offset
        && inner.end <= outer.end
        && (inner.size < outer.size || inner.index > outer.index)
}

/// Whether the bytes of `area` outside the areas in `inside` are all
/// erased flash.
fn own_bytes_are_padding(area: &Area<'_>, inside: &[&Area<'_>], data: &[u8]) -> bool {
    let mut covered: Vec<(usize, usize)> = inside.iter().map(|a| (a.offset, a.end)).collect();
    covered.sort_unstable();
    let mut cursor = area.offset;
    for (start, end) in covered {
        if start > cursor && !is_padding(&data[cursor..start]) {
            return false;
        }
        cursor = cursor.max(end);
    }
    is_padding(&data[cursor..area.end])
}

/// How `area` is reported. An area is classified when it has bytes of its
/// own: it contains no area except data areas (EC images nest the version
/// string and the map inside the code areas), and what those leave
/// uncovered is not erased. Data areas are listed when they contain no
/// other area.
fn role(area: &Area<'_>, areas: &[Area<'_>], data: &[u8], budget: &mut Budget) -> Role {
    if area.size == 0 {
        return Role::Empty;
    }
    let inside: Vec<&Area<'_>> = areas.iter().filter(|a| is_inside(a, area)).collect();
    let data_area = is_data_area(area.name);
    if (data_area && !inside.is_empty()) || inside.iter().any(|a| !is_data_area(a.name)) {
        return Role::Parent;
    }
    if !budget.spend(area.size) {
        return Role::Omitted;
    }
    if data_area {
        return if is_padding(area.bytes(data)) {
            Role::Erased
        } else {
            Role::Data
        };
    }
    if own_bytes_are_padding(area, &inside, data) {
        return if inside.is_empty() {
            Role::Erased
        } else {
            Role::Parent
        };
    }
    if ENGINE_AREA_NAMES.contains(&area.name) {
        return Role::Engine;
    }
    Role::Classified
}

/// Mark classified areas that overlap an earlier classified one (in offset
/// order) as overlapping. Classified areas then never share bytes, so a
/// map cannot have the same bytes, possibly another map, classified many
/// times at every nesting level. Data areas may overlap: they are never
/// analyzed.
fn exclude_overlaps(areas: &[Area<'_>], roles: &mut [Role]) {
    let mut order: Vec<usize> = (0..areas.len())
        .filter(|&i| roles[i] == Role::Classified)
        .collect();
    order.sort_by_key(|&i| (areas[i].offset, areas[i].index));
    let mut classified_end = 0;
    for i in order {
        if areas[i].offset < classified_end {
            roles[i] = Role::Overlapping;
        } else {
            classified_end = areas[i].end;
        }
    }
}

/// `"static, read-only"`, or `"none"`.
fn flags_text(flags: u16) -> String {
    let mut names: Vec<String> = AREA_FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let unknown = flags & !AREA_FLAGS.iter().fold(0, |all, (bit, _)| all | bit);
    if unknown != 0 {
        names.push(format!("0x{unknown:04X}"));
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

/// A classified area: stored bytes, unless the area is flagged compressed
/// and its bytes are not a recognized format, which leaves the codec
/// unnamed.
fn classified_child<'a>(area: &Area<'_>, data: &'a [u8], notes: &mut Vec<String>) -> Child<'a> {
    let bytes = area.bytes(data);
    let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
    if area.flags & AREA_COMPRESSED != 0 && !container::is_recognized(prefix) {
        notes.push(format!(
            "{}: flagged compressed and the codec is not named; not analyzed",
            area.label()
        ));
        return Child::opaque(area.label(), area.offset, bytes);
    }
    Child::stored(area.label(), area.offset, bytes)
}

/// Parse the flash image whose FMAP header is at file offset `at`.
pub(super) fn parse(data: &[u8], at: usize, layout: Layout) -> Result<Container<'_>> {
    let Map { at, header, areas } = validate(data, at)?;
    let mut c = Container::new(layout.format(), layout.label(), "fmap");
    c.consumed = header.image_size;
    c.notes.push(format!(
        "FMAP {}.{} \"{}\" at 0x{at:X}: {} areas over a {} image; flash base address 0x{:X}",
        header.major,
        header.minor,
        header.name,
        areas.len(),
        size_text(header.image_size),
        header.base_address
    ));
    c.notes.push(
        "Area offsets are taken as file offsets (absolute flash offsets); FMAP names no ISA".into(),
    );
    c.push_metadata("fmap_offset", "FMAP header offset", at as u64);
    c.push_metadata(
        "fmap_version",
        "FMAP version",
        format!("{}.{}", header.major, header.minor),
    );
    c.push_metadata("fmap_name", "FMAP name", header.name);
    c.push_metadata(
        "fmap_base_address",
        "Flash base address",
        format!("0x{:X}", header.base_address),
    );

    // Containment is quadratic in the area count, so only the first
    // MAX_COMPONENTS areas take part.
    let considered = &areas[..areas.len().min(MAX_COMPONENTS)];
    let mut budget = Budget::new();
    let mut roles: Vec<Role> = considered
        .iter()
        .map(|area| role(area, considered, data, &mut budget))
        .collect();
    exclude_overlaps(considered, &mut roles);
    for (area, role) in considered.iter().zip(&roles) {
        c.push_metadata(
            format!("fmap_area_{}", area.index),
            area.label(),
            format!(
                "0x{:X} + {} B; flags {}; {}",
                area.offset,
                area.size,
                flags_text(area.flags),
                role.text()
            ),
        );
    }
    if areas.len() > considered.len() {
        c.notes.push(format!(
            "{} areas after the first {MAX_COMPONENTS} were validated but not interpreted",
            areas.len() - considered.len()
        ));
    }

    let mut listed: Vec<(&Area<'_>, Role)> = considered
        .iter()
        .zip(roles.iter().copied())
        .filter(|(_, role)| matches!(role, Role::Data | Role::Engine | Role::Classified))
        .collect();
    listed.sort_by_key(|(area, _)| (area.offset, area.index));
    for (area, role) in listed {
        if !budget.admit() {
            continue;
        }
        let child = match role {
            Role::Classified => classified_child(area, data, &mut c.notes),
            Role::Engine => {
                c.notes.push(format!(
                    "{}: Intel ME or IE region by its ifdtool name; its layout is not parsed",
                    area.label()
                ));
                Child::opaque(area.label(), area.offset, area.bytes(data))
            }
            // Data areas: the filter above keeps no other role.
            _ => Child::opaque(area.label(), area.offset, area.bytes(data)),
        };
        c.children.push(child);
    }
    let erased = roles.iter().filter(|r| **r == Role::Erased).count();
    if erased > 0 {
        c.notes
            .push(format!("{erased} erased areas were not classified"));
    }
    let overlapping = roles.iter().filter(|r| **r == Role::Overlapping).count();
    if overlapping > 0 {
        c.notes.push(format!(
            "{overlapping} areas overlap an area that is already classified and were not classified"
        ));
    }
    c.notes.extend(budget.note());
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(index: usize, offset: usize, size: usize, name: &'static str) -> Area<'static> {
        Area {
            index,
            offset,
            size,
            end: offset + size,
            name,
            flags: 0,
        }
    }

    #[test]
    fn data_areas_are_recognized_by_name_words() {
        for name in [
            "FMAP",
            "GBB",
            "RO_VPD",
            "RW_FWID_A",
            "RO_FRID",
            "RW_MRC_CACHE",
            "SI_DESC",
        ] {
            assert!(is_data_area(name), "{name}");
        }
        for name in [
            "COREBOOT",
            "EC_RO",
            "EC_RW",
            "FW_MAIN_A",
            "BOOTBLOCK",
            "SI_ME",
            "SIGNAL",
        ] {
            assert!(!is_data_area(name), "{name}");
        }
    }

    #[test]
    fn identical_ranges_nest_in_table_order() {
        let parent = area(0, 0, 0x100, "RW_SECTION");
        let child = area(1, 0, 0x100, "FW_MAIN");
        assert!(is_inside(&child, &parent));
        assert!(!is_inside(&parent, &child));
        assert!(!is_inside(&area(2, 0, 0, "EMPTY"), &parent));
        assert!(!is_inside(&area(3, 0x80, 0x100, "OVERLAP"), &parent));
    }

    #[test]
    fn code_areas_with_nested_data_keep_their_own_bytes() {
        let mut data = vec![0xffu8; 0x100];
        data[..0x10].fill(0x13);
        let areas = [area(0, 0, 0x100, "EC_RO"), area(1, 0x80, 0x20, "RO_FRID")];
        let mut budget = Budget::new();
        assert_eq!(
            role(&areas[0], &areas, &data, &mut budget),
            Role::Classified
        );
        data[..0x10].fill(0xff);
        assert_eq!(role(&areas[0], &areas, &data, &mut budget), Role::Parent);
        assert_eq!(role(&areas[1], &areas, &data, &mut budget), Role::Erased);
    }

    #[test]
    fn classified_areas_never_share_bytes() {
        let areas = [
            area(0, 0, 0x100, "A"),
            area(1, 0x80, 0x100, "B"),
            area(2, 0x100, 0x80, "C"),
        ];
        let mut roles = [Role::Classified; 3];
        exclude_overlaps(&areas, &mut roles);
        assert_eq!(
            roles,
            [Role::Classified, Role::Overlapping, Role::Classified]
        );
    }

    #[test]
    fn flags_are_named() {
        assert_eq!(flags_text(AREA_STATIC | AREA_RO), "static, read-only");
        assert_eq!(flags_text(0), "none");
        assert_eq!(flags_text(0x8010), "0x8010");
    }
}
