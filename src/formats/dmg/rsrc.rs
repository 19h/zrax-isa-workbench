//! The binary resource fork of old UDIF images, which holds the block
//! tables as `blkx` resources when the trailer names no XML property list
//! (7-Zip `DmgHandler.cpp` `CHandler::Open2`, "RSRC mode").
//!
//! Layout from Apple, *Inside Macintosh: More Macintosh Toolbox* (1993),
//! "Resource File Format", Figures 1-11 to 1-17; every field is
//! big-endian. The fork starts with the resource header: offset to the
//! resource data (4), offset to the resource map (4), data length (4) and
//! map length (4), all relative to the fork. Each resource's data is a
//! length (4) and that many bytes. The map holds a copy of the header
//! (16), a handle (4), a file reference number (2), attributes (2), the
//! offsets from the map to the type list (2) and to the name list (2). The
//! type list is a count minus one (2) and 8-byte items: type (4), resource
//! count minus one (2) and the offset from the type list to the type's
//! reference list (2). A reference is 12 bytes: ID (2), the offset from the
//! name list to the name (2; 0xFFFF for none), attributes (1), the offset
//! from the resource data to the resource (3) and a handle (4). A name is a
//! length byte and that many characters.

use super::*;

/// The resource header: four 32-bit offsets and lengths.
const HEADER_SIZE: usize = 16;

/// The map fields before the type list: the header copy, handle, file
/// reference number, attributes and the two list offsets.
const MAP_FIXED_SIZE: usize = 28;

/// The `blkx` resource type.
const BLKX_TYPE: &[u8; 4] = b"blkx";

/// Type list items and reference list entries.
const TYPE_ITEM_SIZE: usize = 8;
const REFERENCE_SIZE: usize = 12;

/// A reference without a name.
const NO_NAME: u16 = 0xffff;

/// The 24-bit data offset of a reference.
const DATA_OFFSET_MASK: u32 = 0x00ff_ffff;

/// One `blkx` resource.
#[derive(Debug)]
pub(super) struct Resource<'a> {
    /// Resource ID.
    pub(super) id: i16,
    /// Resource name, when it has one: characters 0x20-0x7E kept, others
    /// shown as `?`.
    pub(super) name: Option<String>,
    /// The resource data: a block table.
    pub(super) data: &'a [u8],
}

/// The resource header fields.
struct Header {
    data_offset: usize,
    map_offset: usize,
    data_length: usize,
    map_length: usize,
}

/// The resource header at the start of `fork`: data and map ranges that
/// fit the fork.
fn header(fork: &[u8]) -> Result<Header> {
    let field = |at: usize| -> Result<usize> {
        usize::try_from(be_u32(fork, at)?).map_err(|_| error("Invalid resource fork header"))
    };
    let h = Header {
        data_offset: field(0)?,
        map_offset: field(4)?,
        data_length: field(8)?,
        map_length: field(12)?,
    };
    slice(fork, h.data_offset, h.data_length, "resource data")?;
    slice(fork, h.map_offset, h.map_length, "resource map")?;
    if h.map_length < MAP_FIXED_SIZE {
        return Err(error(format!(
            "Invalid resource map size {} B",
            h.map_length
        )));
    }
    Ok(h)
}

/// Whether `fork` starts with a resource header whose data and map lie in
/// the fork.
pub(super) fn header_fits(fork: &[u8]) -> bool {
    fork.len() >= HEADER_SIZE && header(fork).is_ok()
}

/// A resource name: a length byte and that many characters.
fn name(names: &[u8], at: usize) -> Result<String> {
    let length = usize::from(
        *slice(names, at, 1, "resource name")?
            .first()
            .expect("one byte"),
    );
    let text = slice(names, at + 1, length, "resource name")?;
    Ok(text
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect())
}

/// The `blkx` resources of a resource fork, in reference list order.
pub(super) fn blkx_resources(fork: &[u8]) -> Result<Vec<Resource<'_>>> {
    let h = header(fork)?;
    let data = &fork[h.data_offset..h.data_offset + h.data_length];
    let map = &fork[h.map_offset..h.map_offset + h.map_length];
    let type_list_offset = usize::from(be_u16(map, 24)?);
    let name_list_offset = usize::from(be_u16(map, 26)?);
    let type_list = map.get(type_list_offset..).ok_or_else(|| {
        error(format!(
            "Truncated resource type list at 0x{type_list_offset:X}"
        ))
    })?;
    let names = map.get(name_list_offset..).unwrap_or_default();
    let type_count = usize::from(be_u16(type_list, 0)?) + 1;
    let mut resources = Vec::new();
    for t in 0..type_count {
        let item = slice(
            type_list,
            2 + t * TYPE_ITEM_SIZE,
            TYPE_ITEM_SIZE,
            "resource type list",
        )?;
        if &item[..4] != BLKX_TYPE {
            continue;
        }
        let count = usize::from(be_u16(item, 4)?) + 1;
        let references_at = usize::from(be_u16(item, 6)?);
        let references = slice(
            type_list,
            references_at,
            count * REFERENCE_SIZE,
            "resource reference list",
        )?;
        for reference in references.chunks_exact(REFERENCE_SIZE) {
            let id = i16::from_be_bytes([reference[0], reference[1]]);
            let name_at = be_u16(reference, 2)?;
            let data_at = (be_u32(reference, 4)? & DATA_OFFSET_MASK) as usize;
            let length = usize::try_from(be_u32(data, data_at)?)
                .map_err(|_| error("Invalid resource data length"))?;
            if resources.len() >= MAX_TABLES {
                return Err(error(format!(
                    "Unsupported UDIF resource fork: more than {MAX_TABLES} block tables"
                )));
            }
            resources.push(Resource {
                id,
                name: if name_at == NO_NAME {
                    None
                } else {
                    Some(name(names, usize::from(name_at))?)
                },
                data: slice(data, data_at + 4, length, "resource data")?,
            });
        }
    }
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be16(value: usize) -> [u8; 2] {
        u16::try_from(value).expect("small").to_be_bytes()
    }

    fn be32(value: usize) -> [u8; 4] {
        u32::try_from(value).expect("small").to_be_bytes()
    }

    /// A resource fork with one `blkx` resource named `name` holding
    /// `table`, laid out as Inside Macintosh Figures 1-11 to 1-17 show.
    fn fork(name: &[u8], table: &[u8]) -> Vec<u8> {
        let mut data = be32(table.len()).to_vec();
        data.extend_from_slice(table);
        let mut map = vec![0u8; 24];
        // Type list right after the fixed part; names after the one
        // reference.
        let names_at = MAP_FIXED_SIZE + 2 + TYPE_ITEM_SIZE + REFERENCE_SIZE;
        map.extend_from_slice(&be16(MAP_FIXED_SIZE));
        map.extend_from_slice(&be16(names_at));
        map.extend_from_slice(&0u16.to_be_bytes()); // one type
        map.extend_from_slice(BLKX_TYPE);
        map.extend_from_slice(&0u16.to_be_bytes()); // one resource
        map.extend_from_slice(&be16(2 + TYPE_ITEM_SIZE));
        map.extend_from_slice(&(-1i16).to_be_bytes()); // ID
        map.extend_from_slice(&0u16.to_be_bytes()); // name at 0
        map.extend_from_slice(&0x5000_0000u32.to_be_bytes()); // attributes, data at 0
        map.extend_from_slice(&[0; 4]);
        map.push(u8::try_from(name.len()).expect("short name"));
        map.extend_from_slice(name);
        let mut out = Vec::new();
        out.extend_from_slice(&be32(HEADER_SIZE));
        out.extend_from_slice(&be32(HEADER_SIZE + data.len()));
        out.extend_from_slice(&be32(data.len()));
        out.extend_from_slice(&be32(map.len()));
        out.extend_from_slice(&data);
        out.extend_from_slice(&map);
        out
    }

    #[test]
    fn blkx_resources_carry_their_id_name_and_data() {
        let fork = fork(b"Driver Descriptor Map (DDM : 0)", b"mish table");
        assert!(header_fits(&fork));
        let resources = blkx_resources(&fork).unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].id, -1);
        assert_eq!(
            resources[0].name.as_deref(),
            Some("Driver Descriptor Map (DDM : 0)")
        );
        assert_eq!(resources[0].data, b"mish table");
    }

    #[test]
    fn truncated_forks_are_errors() {
        let fork = fork(b"x", b"mish");
        for end in 0..fork.len() {
            assert!(blkx_resources(&fork[..end]).is_err(), "prefix {end}");
        }
        assert!(!header_fits(&fork[..HEADER_SIZE]));
    }
}
