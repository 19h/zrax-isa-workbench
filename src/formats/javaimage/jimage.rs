//! jimage files (`imageFile.hpp`, `OpenJDK` `jdk-21+35`).
//!
//! Layout, every word in the image byte order:
//!
//! ```text
//! header     magic 0xCAFEDADA, version (major << 16 | minor), flags,
//!            resource count, table length, locations size, strings size
//! redirect   s4[table length]   perfect-hash redirect table
//! offsets    u4[table length]   location offset per slot, 0 = empty
//! locations  attribute streams
//! strings    NUL-terminated modified UTF-8
//! resources  stored at index size + location offset
//! ```
//!
//! Every slot's location is decoded, its name built and looked up through
//! the redirect table the way `ImageStrings::find` does, and its stored
//! range checked against the file. Resources are then examined in file
//! order; the `/modules` and `/packages` directory entries jlink adds
//! (`ImageResourcesTree.java`) are index data and never examined.

use super::resource;
use super::*;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// The magic, `IMAGE_MAGIC`.
const IMAGE_MAGIC: u32 = 0xcafe_dada;

/// Header: seven u32 words (`ImageHeader.java`, `HEADER_SLOTS`).
const HEADER_SIZE: usize = 28;

/// The only version either reader accepts (`MAJOR_VERSION`,
/// `MINOR_VERSION`).
const MAJOR_VERSION: u32 = 1;
const MINOR_VERSION: u32 = 0;

/// Bytes per redirect-table and per offsets-table slot.
const SLOT_SIZE: usize = 4;

/// Location attribute kinds (`ImageLocation`). A header byte holds the
/// kind in its upper five bits and the value length less one in its lower
/// three; values are most significant byte first.
const ATTRIBUTE_END: u8 = 0;
const ATTRIBUTE_MODULE: u8 = 1;
const ATTRIBUTE_PARENT: u8 = 2;
const ATTRIBUTE_BASE: u8 = 3;
const ATTRIBUTE_EXTENSION: u8 = 4;
const ATTRIBUTE_OFFSET: u8 = 5;
const ATTRIBUTE_COMPRESSED: u8 = 6;
const ATTRIBUTE_UNCOMPRESSED: u8 = 7;
const ATTRIBUTE_COUNT: u8 = 8;
const ATTRIBUTE_LENGTH_MASK: u8 = 0x07;
const ATTRIBUTE_KIND_SHIFT: u8 = 3;

/// Perfect-hash multiplier and default seed (`HASH_MULTIPLIER`), and the
/// mask that keeps hash values positive (`POSITIVE_MASK`).
const HASH_MULTIPLIER: u32 = 0x0100_0193;
const POSITIVE_MASK: u32 = 0x7fff_ffff;

/// Longest resource name, `IMAGE_MAX_PATH` ("Max path length limit
/// independent of platform").
const MAX_PATH: usize = 4096;

/// Most resource-name bytes built while walking one index. Each location's
/// name is built and hashed once; this bounds the work for an index whose
/// slots all name long paths. Our own limit: the 28,738 resource names of
/// a JDK 21 image with every module take 1.7 MiB.
const MAX_NAME_BYTES: usize = 64 << 20;

/// The directory entries jlink adds after the resources
/// (`ImageResourcesTree.isTreeInfoResource`): `/modules`, `/packages` and
/// the paths below them.
const TREE_ROOTS: [&[u8]; 2] = [b"/modules", b"/packages"];

/// Strong recognition: the magic in either byte order, with the major
/// version both readers require.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let version: [u8; 4] = data.get(4..8)?.try_into().ok()?;
    let (layout, version) = if magic == IMAGE_MAGIC.to_le_bytes() {
        (Layout::JimageLittleEndian, u32::from_le_bytes(version))
    } else if magic == IMAGE_MAGIC.to_be_bytes() {
        (Layout::JimageBigEndian, u32::from_be_bytes(version))
    } else {
        return None;
    };
    (version >> 16 == MAJOR_VERSION).then_some(layout)
}

/// The image header.
#[derive(Debug)]
struct Header {
    major_version: u32,
    minor_version: u32,
    /// "various image wide flags (future)": none is defined.
    flags: u32,
    /// Locations the writer stored, directory entries included.
    resource_count: u32,
    /// Slots in the redirect and offsets tables.
    table_length: u32,
    /// Bytes of location attribute streams.
    locations_size: u32,
    /// Bytes of strings.
    strings_size: u32,
}

impl Header {
    /// Header: magic, version, flags, resource count, table length,
    /// locations size and strings size, each a u32 at 4-byte steps.
    fn read(data: &[u8], le: bool) -> Result<Self> {
        let header = slice(data, 0, HEADER_SIZE, "jimage header")?;
        let word = |at: usize| u32_at(header, at, le, "jimage header");
        if word(0)? != IMAGE_MAGIC {
            return Err(error(format!(
                "Invalid jimage magic 0x{:08X} for the {} byte order",
                word(0)?,
                if le { "little-endian" } else { "big-endian" }
            )));
        }
        let version = word(4)?;
        Ok(Self {
            major_version: version >> 16,
            minor_version: version & 0xffff,
            flags: word(8)?,
            resource_count: word(12)?,
            table_length: word(16)?,
            locations_size: word(20)?,
            strings_size: word(24)?,
        })
    }

    /// Header, both tables, attribute streams and strings, in bytes.
    fn index_size(&self) -> u64 {
        let tables = u64::from(self.table_length) * 2 * SLOT_SIZE as u64;
        HEADER_SIZE as u64 + tables + u64::from(self.locations_size) + u64::from(self.strings_size)
    }
}

/// The index regions, as slices of the file.
struct Index<'a> {
    le: bool,
    table_length: u32,
    redirect: &'a [u8],
    offsets: &'a [u8],
    locations: &'a [u8],
    /// File offset of the location attribute region.
    locations_offset: usize,
    strings: Strings<'a>,
    /// Index size: the file offset where resources start.
    size: usize,
}

impl<'a> Index<'a> {
    fn new(data: &'a [u8], header: &Header, le: bool) -> Result<Self> {
        let size = usize::try_from(header.index_size())
            .ok()
            .filter(|size| *size <= data.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated jimage index: {} B declared, {} B present",
                    header.index_size(),
                    data.len()
                ))
            })?;
        // Every region lies inside the index, which the file holds.
        let table_size = header.table_length as usize * SLOT_SIZE;
        let offsets_offset = HEADER_SIZE + table_size;
        let locations_offset = offsets_offset + table_size;
        let strings_offset = locations_offset + header.locations_size as usize;
        Ok(Self {
            le,
            table_length: header.table_length,
            redirect: slice(data, HEADER_SIZE, table_size, "jimage redirect table")?,
            offsets: slice(data, offsets_offset, table_size, "jimage offsets table")?,
            locations: slice(
                data,
                locations_offset,
                header.locations_size as usize,
                "jimage location attributes",
            )?,
            locations_offset,
            strings: Strings::new(
                slice(
                    data,
                    strings_offset,
                    header.strings_size as usize,
                    "jimage strings",
                )?,
                strings_offset,
            ),
            size,
        })
    }

    /// The location offset in `slot`, 0 for an empty slot.
    fn location_offset(&self, slot: u32) -> Result<u32> {
        u32_at(
            self.offsets,
            slot as usize * SLOT_SIZE,
            self.le,
            "jimage offsets table",
        )
    }

    /// The slot the redirect table gives for `name` (`ImageStrings::find`),
    /// or `None` when the name is not in the table. The table length is
    /// not zero: a slot holds the location being looked up.
    fn lookup(&self, name: &[u8]) -> Result<Option<u64>> {
        let table_length = u64::from(self.table_length);
        let bucket = u64::from(hash(name, HASH_MULTIPLIER)) % table_length;
        let bucket = usize::try_from(bucket).expect("bucket is below the table length");
        let redirect = i32_at(
            self.redirect,
            bucket * SLOT_SIZE,
            self.le,
            "jimage redirect table",
        )?;
        Ok(match redirect.cmp(&0) {
            // The two's complement of the slot: `-1 - redirect`.
            Ordering::Less => u64::try_from(-1 - i64::from(redirect)).ok(),
            // A seed that rehashes the name to its slot.
            Ordering::Greater => {
                let seed = redirect.unsigned_abs();
                Some(u64::from(hash(name, seed)) % table_length)
            }
            Ordering::Equal => None,
        })
    }
}

/// The perfect-hash function (`ImageStrings::hash_code`): FNV-style over
/// the name's modified UTF-8 bytes, kept positive.
fn hash(name: &[u8], seed: u32) -> u32 {
    name.iter()
        .fold(seed, |h, &b| h.wrapping_mul(HASH_MULTIPLIER) ^ u32::from(b))
        & POSITIVE_MASK
}

/// The string region: NUL-terminated modified UTF-8 accessed by offset;
/// offset 0 is the empty string.
pub(super) struct Strings<'a> {
    bytes: &'a [u8],
    /// File offset of the region.
    offset: usize,
}

impl<'a> Strings<'a> {
    /// The string region `bytes`, found at file offset `offset`.
    pub(super) fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    /// The string at `offset`, without its NUL, at most `max_len` bytes
    /// long.
    pub(super) fn get(&self, offset: u64, max_len: usize) -> Result<&'a [u8]> {
        let start = usize::try_from(offset)
            .ok()
            .filter(|start| *start < self.bytes.len())
            .ok_or_else(|| {
                error(format!(
                    "Invalid jimage string offset 0x{offset:X}: the string region is {} B",
                    self.bytes.len()
                ))
            })?;
        let rest = &self.bytes[start..];
        let scanned = &rest[..rest.len().min(max_len.saturating_add(1))];
        match scanned.iter().position(|&b| b == 0) {
            Some(end) => Ok(&rest[..end]),
            None if scanned.len() < rest.len() => Err(error(format!(
                "Invalid jimage string at 0x{:X}: longer than {max_len} B",
                self.offset + start
            ))),
            None => Err(error(format!(
                "Unterminated jimage string at 0x{:X}",
                self.offset + start
            ))),
        }
    }
}

/// One location's attributes. String offsets of 0 mean the name part is
/// absent.
#[derive(Debug, Default, Clone, Copy)]
struct Location {
    module: u64,
    parent: u64,
    base: u64,
    extension: u64,
    /// Byte offset of the stored resource from the end of the index.
    content_offset: u64,
    /// Stored size when compressed; 0 when stored as is.
    compressed_size: u64,
    /// Size in memory; also the stored size when not compressed.
    uncompressed_size: u64,
}

impl Location {
    /// Decode the attribute stream at `offset` in the location region
    /// (`ImageLocation.decompress`). The stream ends at an END header byte
    /// or at the end of the region. The writer emits each kind once, so a
    /// repeated kind is rejected; that also bounds the stream to 64 B.
    fn read(index: &Index<'_>, offset: u32) -> Result<Self> {
        let locations = index.locations;
        let start = offset as usize;
        if start >= locations.len() {
            return Err(error(format!(
                "Invalid jimage location offset 0x{offset:X}: the attribute region is {} B",
                locations.len()
            )));
        }
        let mut values = [0u64; ATTRIBUTE_COUNT as usize];
        let mut seen = 0u8;
        let mut pos = start;
        while let Some(&header) = locations.get(pos) {
            let at = index.locations_offset + pos;
            let kind = header >> ATTRIBUTE_KIND_SHIFT;
            if kind == ATTRIBUTE_END {
                break;
            }
            if kind >= ATTRIBUTE_COUNT {
                return Err(error(format!(
                    "Invalid jimage location attribute kind {kind} at 0x{at:X}"
                )));
            }
            if seen & (1 << kind) != 0 {
                return Err(error(format!(
                    "Duplicate jimage location attribute kind {kind} at 0x{at:X}"
                )));
            }
            seen |= 1 << kind;
            let length = usize::from(header & ATTRIBUTE_LENGTH_MASK) + 1;
            let value = slice(locations, pos + 1, length, "jimage location attribute")
                .map_err(|_| error(format!("Truncated jimage location attribute at 0x{at:X}")))?;
            values[usize::from(kind)] = value.iter().fold(0, |v, &b| (v << 8) | u64::from(b));
            pos += 1 + length;
        }
        Ok(Self {
            module: values[usize::from(ATTRIBUTE_MODULE)],
            parent: values[usize::from(ATTRIBUTE_PARENT)],
            base: values[usize::from(ATTRIBUTE_BASE)],
            extension: values[usize::from(ATTRIBUTE_EXTENSION)],
            content_offset: values[usize::from(ATTRIBUTE_OFFSET)],
            compressed_size: values[usize::from(ATTRIBUTE_COMPRESSED)],
            uncompressed_size: values[usize::from(ATTRIBUTE_UNCOMPRESSED)],
        })
    }

    fn is_compressed(&self) -> bool {
        self.compressed_size != 0
    }

    /// Bytes stored in the image.
    fn stored_size(&self) -> u64 {
        if self.is_compressed() {
            self.compressed_size
        } else {
            self.uncompressed_size
        }
    }

    /// Write the full name into `out` (`ImageLocation.getFullName`):
    /// `/module/` when the module offset is set, `parent/` when the parent
    /// offset is set, the base, and `.extension` when the extension offset
    /// is set.
    fn write_name(&self, strings: &Strings<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        if self.module != 0 {
            out.push(b'/');
            out.extend_from_slice(strings.get(self.module, MAX_PATH)?);
            out.push(b'/');
        }
        if self.parent != 0 {
            out.extend_from_slice(strings.get(self.parent, MAX_PATH)?);
            out.push(b'/');
        }
        out.extend_from_slice(strings.get(self.base, MAX_PATH)?);
        if self.extension != 0 {
            out.push(b'.');
            out.extend_from_slice(strings.get(self.extension, MAX_PATH)?);
        }
        Ok(())
    }

    /// The full name for labels and notes. Names are modified UTF-8;
    /// invalid UTF-8 is shown with replacement characters.
    fn name(&self, strings: &Strings<'_>) -> Result<String> {
        let mut name = Vec::new();
        self.write_name(strings, &mut name)?;
        Ok(String::from_utf8_lossy(&name).into_owned())
    }
}

/// Whether `name` is one of the directory entries jlink adds: `/modules`,
/// `/packages` or a path below them.
fn is_tree_entry(name: &[u8]) -> bool {
    TREE_ROOTS.iter().any(|root| {
        name.strip_prefix(*root)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
    })
}

/// A resource to examine: its slot, attributes and stored range.
struct Resource {
    slot: u32,
    location: Location,
    /// File offset of the stored bytes.
    offset: usize,
    /// Stored size in bytes.
    stored_size: usize,
}

/// What the index walk found.
#[derive(Default)]
struct Walk {
    resources: Vec<Resource>,
    /// Non-empty slots.
    locations: usize,
    /// `/modules` and `/packages` directory entries.
    tree_entries: usize,
    /// Location offsets of `/modules` and `/packages` themselves, in
    /// [`TREE_ROOTS`] order.
    roots: [Option<u32>; 2],
    /// String offsets of the resources' module names.
    modules: BTreeSet<u64>,
    /// Resources stored compressed.
    compressed: usize,
    /// End of the last stored range, or of the index.
    end: usize,
}

/// Walk every slot of the offsets table: decode the location, build its
/// name, check that the redirect table leads back to the slot, and check
/// the stored range.
fn walk_index(data: &[u8], index: &Index<'_>) -> Result<Walk> {
    let mut walk = Walk {
        end: index.size,
        ..Walk::default()
    };
    let mut name = Vec::new();
    let mut name_bytes = 0usize;
    for slot in 0..index.table_length {
        let offset = index.location_offset(slot)?;
        if offset == 0 {
            continue;
        }
        walk.locations += 1;
        let location = Location::read(index, offset)?;
        location.write_name(&index.strings, &mut name)?;
        if name.len() > MAX_PATH {
            return Err(error(format!(
                "Invalid jimage resource name in slot {slot}: longer than {MAX_PATH} B"
            )));
        }
        name_bytes += name.len();
        if name_bytes > MAX_NAME_BYTES {
            return Err(error(format!(
                "Unsupported jimage index: resource names exceed {}",
                size_text(MAX_NAME_BYTES)
            )));
        }
        if index.lookup(&name)? != Some(u64::from(slot)) {
            return Err(error(format!(
                "Invalid jimage index: {} in slot {slot} is not found through the redirect table",
                String::from_utf8_lossy(&name)
            )));
        }
        let stored = StoredRange::new(data, index, &location, &name)?;
        walk.end = walk.end.max(stored.offset + stored.size);
        if is_tree_entry(&name) {
            walk.tree_entries += 1;
            if let Some(root) = TREE_ROOTS.iter().position(|root| name == *root) {
                walk.roots[root] = Some(offset);
            }
            continue;
        }
        if location.is_compressed() {
            walk.compressed += 1;
        }
        if location.module != 0 {
            walk.modules.insert(location.module);
        }
        walk.resources.push(Resource {
            slot,
            location,
            offset: stored.offset,
            stored_size: stored.size,
        });
    }
    Ok(walk)
}

/// Where a location's stored bytes are in the file.
struct StoredRange {
    /// File offset.
    offset: usize,
    /// Size in bytes.
    size: usize,
}

impl StoredRange {
    /// The range of `location`, named `name`, which the file must hold.
    fn new(data: &[u8], index: &Index<'_>, location: &Location, name: &[u8]) -> Result<Self> {
        let start = (index.size as u64).checked_add(location.content_offset);
        let end = start.and_then(|start| start.checked_add(location.stored_size()));
        match (start, end) {
            (Some(start), Some(end)) if end <= data.len() as u64 => Ok(Self {
                offset: usize::try_from(start).expect("start is within the file"),
                size: usize::try_from(location.stored_size()).expect("size is within the file"),
            }),
            _ => Err(error(format!(
                "Truncated jimage resource {} at 0x{:X} + {} B: the file is {} B",
                String::from_utf8_lossy(name),
                (index.size as u64).saturating_add(location.content_offset),
                location.stored_size(),
                data.len()
            ))),
        }
    }
}

/// Lists an image's recognized resources as children, within the component
/// and extraction limits, and counts what it left out.
#[derive(Default)]
struct Listing {
    budget: Budget,
    /// Resources checked for a recognized format.
    examined: usize,
    /// Compressed resources decoded, and those with a `zip` and with a
    /// `compact-cp` layer.
    decoded: usize,
    zip_decoded: usize,
    compact_cp_decoded: usize,
    /// Resources not examined because [`MAX_COMPONENTS`] were listed.
    over_component_limit: usize,
    /// Compressed resources not decoded because [`MAX_EXTRACTED`] would
    /// pass.
    over_extraction_limit: usize,
    /// Compressed resources larger than [`MAX_PAYLOAD`].
    too_large: usize,
    /// Compressed resources whose decompressor is not implemented, and
    /// the first [`NOTE_NAMES`] distinct decompressor names.
    unsupported: usize,
    unsupported_names: BTreeSet<String>,
    /// Compressed resources that did not decode, and the first reason.
    failed: usize,
    first_failure: Option<String>,
}

impl Listing {
    /// Examine one resource: list it when its contents, decoded when it
    /// is compressed, are a recognized format.
    fn examine<'a>(
        &mut self,
        data: &'a [u8],
        index: &Index<'a>,
        resource: &Resource,
        c: &mut Container<'a>,
    ) -> Result<()> {
        if c.children.len() >= MAX_COMPONENTS {
            self.over_component_limit += 1;
            return Ok(());
        }
        self.examined += 1;
        let stored = slice(
            data,
            resource.offset,
            resource.stored_size,
            "jimage resource",
        )?;
        let child = if resource.location.is_compressed() {
            self.decode(stored, index, resource)?
        } else if is_member(stored) {
            let label = resource.location.name(&index.strings)?;
            Some(Child::stored(label, resource.offset, stored))
        } else {
            None
        };
        if let Some(child) = child {
            c.children.push(child.if_recognized());
        }
        Ok(())
    }

    /// A compressed resource as a child when it decodes to a recognized
    /// format. A resource that does not decode is counted, not an error.
    fn decode<'a>(
        &mut self,
        stored: &'a [u8],
        index: &Index<'a>,
        resource: &Resource,
    ) -> Result<Option<Child<'a>>> {
        let location = &resource.location;
        let Some(size) = usize::try_from(location.uncompressed_size)
            .ok()
            .filter(|size| *size <= MAX_PAYLOAD)
        else {
            self.too_large += 1;
            return Ok(None);
        };
        let decoded = match resource::decode(
            stored,
            resource.offset,
            size,
            &index.strings,
            index.le,
            &mut self.budget,
        ) {
            Ok(decoded) => decoded,
            Err(resource::Undecoded::Limit) => {
                self.over_extraction_limit += 1;
                return Ok(None);
            }
            Err(resource::Undecoded::Unsupported(name)) => {
                self.unsupported += 1;
                if self.unsupported_names.len() < NOTE_NAMES {
                    self.unsupported_names.insert(name);
                }
                return Ok(None);
            }
            Err(resource::Undecoded::Invalid(e)) => {
                self.failed += 1;
                if self.first_failure.is_none() {
                    let label = location.name(&index.strings)?;
                    self.first_failure = Some(format!("{label} ({e})"));
                }
                return Ok(None);
            }
        };
        self.decoded += 1;
        self.zip_decoded += usize::from(decoded.applied.zip);
        self.compact_cp_decoded += usize::from(decoded.applied.compact_cp);
        if !is_member(&decoded.data) {
            return Ok(None);
        }
        let label = location.name(&index.strings)?;
        Ok(Some(match decoded.applied.transform() {
            Some(transform) => Child::decoded(
                label,
                resource.offset,
                stored.len(),
                decoded.data,
                transform,
            ),
            // Marked compressed but without a compressed-resource header:
            // both readers return the stored bytes.
            None => Child::stored(label, resource.offset, stored),
        }))
    }

    /// How many resources are compressed and how many were decoded, by
    /// decompressor.
    fn push_compression_note(&self, walk: &Walk, c: &mut Container<'_>) {
        if walk.compressed == 0 {
            return;
        }
        let mut layers = Vec::new();
        if self.zip_decoded > 0 {
            layers.push(format!("{} with zip (zlib)", self.zip_decoded));
        }
        if self.compact_cp_decoded > 0 {
            layers.push(format!(
                "{} with compact-cp (constant-pool strings from the string table)",
                self.compact_cp_decoded
            ));
        }
        let by_layer = if layers.is_empty() {
            String::new()
        } else {
            format!(": {}", layers.join(", "))
        };
        c.notes.push(format!(
            "{} of {} resources are compressed; {} were decoded{by_layer}",
            walk.compressed,
            walk.resources.len(),
            self.decoded
        ));
    }

    /// How many examined resources were listed, and notes for the limits
    /// that were reached and the resources that did not decode.
    fn push_notes(&self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "{} of {} resources are in a recognized format and listed",
            c.children.len(),
            self.examined
        ));
        if self.over_component_limit > 0 {
            c.notes.push(format!(
                "Resource listing stopped at {MAX_COMPONENTS} recognized resources; {} further \
                 resources were not examined",
                self.over_component_limit
            ));
        }
        if self.over_extraction_limit > 0 {
            c.notes.push(format!(
                "Extraction limit reached ({}); {} compressed resources were not decoded",
                size_text(MAX_EXTRACTED),
                self.over_extraction_limit
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} compressed resources exceed the {} resource limit and were not decoded",
                self.too_large,
                size_text(MAX_PAYLOAD)
            ));
        }
        if self.unsupported > 0 {
            let names: Vec<&str> = self.unsupported_names.iter().map(String::as_str).collect();
            c.notes.push(format!(
                "{} resources name an unsupported decompressor and were not decoded: {}",
                self.unsupported,
                names.join(", ")
            ));
        }
        if let Some(first) = &self.first_failure {
            c.notes.push(format!(
                "{} compressed resources could not be decoded and are not listed; first: {first}",
                self.failed
            ));
        }
    }
}

/// Parse a jimage whose index is in the byte order `le` selects.
pub(super) fn parse(data: &[u8], le: bool) -> Result<Container<'_>> {
    let header = Header::read(data, le)?;
    if header.major_version != MAJOR_VERSION || header.minor_version != MINOR_VERSION {
        return Err(error(format!(
            "Unsupported jimage version {}.{}",
            header.major_version, header.minor_version
        )));
    }
    let index = Index::new(data, &header, le)?;
    let mut walk = walk_index(data, &index)?;
    let tail = Tail::read(data, &walk, le)?;
    let layout = if le {
        Layout::JimageLittleEndian
    } else {
        Layout::JimageBigEndian
    };
    let mut c = Container::new(FileFormat::Jimage, layout.label(), "jimage");
    c.consumed = tail.end;
    push_header_notes(&header, &index, &walk, &mut c);
    tail.push_root_note(walk.end, &mut c);
    push_module_note(&index, &walk, &mut c)?;
    // File order, the order jlink wrote the resources in.
    walk.resources
        .sort_by_key(|resource| (resource.offset, resource.slot));
    let mut listing = Listing::default();
    for resource in &walk.resources {
        listing.examine(data, &index, resource, &mut c)?;
    }
    listing.push_compression_note(&walk, &mut c);
    listing.push_notes(&mut c);
    tail.push_padding_note(data, &mut c);
    push_metadata(&header, &index, &walk, &mut c);
    Ok(c)
}

/// What follows the last stored range.
struct Tail {
    /// Bytes of the root directory listing.
    root_listing: usize,
    /// End of the image: the last stored range and the root listing.
    end: usize,
}

impl Tail {
    /// The root directory listing, when present, then only padding. jlink
    /// writes the root node's entries (`ImageResourcesTree.computeContent`:
    /// the location offsets of `/modules` and `/packages`, one u32 each in
    /// the image byte order) after the last resource, although no location
    /// names the root itself.
    fn read(data: &[u8], walk: &Walk, le: bool) -> Result<Self> {
        let listing: Vec<u8> = walk
            .roots
            .iter()
            .flatten()
            .flat_map(|offset| {
                if le {
                    offset.to_le_bytes()
                } else {
                    offset.to_be_bytes()
                }
            })
            .collect();
        let rest = data.get(walk.end..).unwrap_or_default();
        let root_listing = if !listing.is_empty() && rest.starts_with(&listing) {
            listing.len()
        } else {
            0
        };
        let end = walk.end + root_listing;
        let trailing = data.get(end..).unwrap_or_default();
        if !is_padding(trailing) {
            return Err(error(format!(
                "Unexpected {} B after the jimage resources at 0x{end:X}",
                trailing.len()
            )));
        }
        Ok(Self { root_listing, end })
    }

    fn push_root_note(&self, at: usize, c: &mut Container<'_>) {
        if self.root_listing > 0 {
            c.notes.push(format!(
                "{} B at 0x{at:X} list the root directory (/modules, /packages), which no \
                 location names, as jlink writes them",
                self.root_listing
            ));
        }
    }

    fn push_padding_note(&self, data: &[u8], c: &mut Container<'_>) {
        let padding = data.len() - self.end;
        if padding > 0 {
            c.notes.push(format!(
                "Image ends at 0x{:X}; {padding} B of padding follow",
                self.end
            ));
        }
    }
}

/// Notes on the header and the index.
fn push_header_notes(header: &Header, index: &Index<'_>, walk: &Walk, c: &mut Container<'_>) {
    c.notes.push(format!(
        "jimage {}.{} with a {} index: {} resources in {} table slots; resources start at 0x{:X}",
        header.major_version,
        header.minor_version,
        if index.le {
            "little-endian"
        } else {
            "big-endian"
        },
        header.resource_count,
        header.table_length,
        index.size
    ));
    if header.flags != 0 {
        c.notes.push(format!(
            "Header flags 0x{:08X}; the format defines none",
            header.flags
        ));
    }
    if walk.locations != header.resource_count as usize {
        c.notes.push(format!(
            "The header counts {} resources; the offsets table holds {} locations",
            header.resource_count, walk.locations
        ));
    }
    if walk.locations > 0 {
        c.notes.push(format!(
            "Perfect-hash index verified: all {} locations are found through the redirect table",
            walk.locations
        ));
    }
    if walk.tree_entries > 0 {
        c.notes.push(format!(
            "{} directory entries under /modules and /packages are index data and not examined",
            walk.tree_entries
        ));
    }
}

/// A note naming the modules the resources belong to.
fn push_module_note(index: &Index<'_>, walk: &Walk, c: &mut Container<'_>) -> Result<()> {
    let mut names = Vec::with_capacity(walk.modules.len());
    for &offset in &walk.modules {
        names.push(String::from_utf8_lossy(index.strings.get(offset, MAX_PATH)?).into_owned());
    }
    names.sort();
    let mut modules = NameList::default();
    for name in names {
        modules.push(name);
    }
    if !modules.is_empty() {
        let noun = if modules.total == 1 {
            "module"
        } else {
            "modules"
        };
        c.notes
            .push(format!("{} {noun}: {}", modules.total, modules.text()));
    }
    Ok(())
}

fn push_metadata(header: &Header, index: &Index<'_>, walk: &Walk, c: &mut Container<'_>) {
    c.push_metadata(
        "jimage_version",
        "jimage version",
        format!("{}.{}", header.major_version, header.minor_version),
    );
    c.push_metadata(
        "jimage_resource_count",
        "Resource count (header)",
        u64::from(header.resource_count),
    );
    c.push_metadata(
        "jimage_table_length",
        "Index table slots",
        u64::from(header.table_length),
    );
    c.push_metadata("jimage_index_size", "Index size (B)", index.size as u64);
    c.push_metadata("jimage_resources", "Resources", walk.resources.len() as u64);
    c.push_metadata(
        "jimage_directory_entries",
        "Directory entries",
        walk.tree_entries as u64,
    );
    c.push_metadata(
        "jimage_compressed_resources",
        "Compressed resources",
        walk.compressed as u64,
    );
    c.push_metadata("jimage_modules", "Modules", walk.modules.len() as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_follow_the_reference_function() {
        // h = seed; h = h * 0x01000193 ^ byte; masked positive.
        let expected =
            (HASH_MULTIPLIER.wrapping_mul(HASH_MULTIPLIER) ^ u32::from(b'a')) & POSITIVE_MASK;
        assert_eq!(hash(b"a", HASH_MULTIPLIER), expected);
        assert_eq!(hash(b"", 7), 7);
        assert_eq!(hash(b"", u32::MAX), POSITIVE_MASK);
    }

    #[test]
    fn tree_entries_are_the_modules_and_packages_directories() {
        assert!(is_tree_entry(b"/modules"));
        assert!(is_tree_entry(b"/modules/java.base/java/lang"));
        assert!(is_tree_entry(b"/packages/java.lang"));
        assert!(!is_tree_entry(b"/modulesx/a.class"));
        assert!(!is_tree_entry(b"/java.base/java/lang/Object.class"));
    }

    #[test]
    fn strings_are_nul_terminated_and_bounded() {
        let strings = Strings::new(b"\0class\0abcdef", 0x100);
        assert_eq!(strings.get(0, 16).unwrap(), b"");
        assert_eq!(strings.get(1, 16).unwrap(), b"class");
        assert_eq!(strings.get(2, 16).unwrap(), b"lass");
        let unterminated = strings.get(7, 16).unwrap_err().to_string();
        assert!(unterminated.contains("Unterminated jimage string at 0x107"));
        let long = strings.get(7, 3).unwrap_err().to_string();
        assert!(long.contains("longer than 3 B"));
        assert!(strings.get(13, 16).is_err());
        assert!(strings.get(u64::MAX, 16).is_err());
    }

    #[test]
    fn detection_needs_the_magic_and_major_version() {
        let mut le = vec![0xda, 0xda, 0xfe, 0xca, 0, 0, 1, 0];
        assert_eq!(detect(&le), Some(Layout::JimageLittleEndian));
        le[6] = 2;
        assert_eq!(detect(&le), None);
        let be = [0xca, 0xfe, 0xda, 0xda, 0, 1, 0, 0];
        assert_eq!(detect(&be), Some(Layout::JimageBigEndian));
        assert_eq!(detect(&be[..7]), None);
        assert_eq!(detect(b"\xca\xfe\xba\xbe\0\0\0\x41"), None);
    }
}
