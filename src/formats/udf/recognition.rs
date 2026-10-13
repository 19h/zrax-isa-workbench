//! The volume recognition sequence (ECMA-167 2/8.3, 2/9) and the anchor
//! volume descriptor pointer (3/8.4.2.1, 3/10.2), which together recognize
//! a UDF volume and give its logical sector size.

use super::*;

/// Byte offset of the volume recognition area: the first sector that
/// begins after byte 32767 (ECMA-167 2/8.3), for sectors of up to 32 KiB.
const RECOGNITION_OFFSET: usize = 32768;

/// Size of a volume structure descriptor (2/9.1 figure 2/2).
const DESCRIPTOR_SIZE: usize = 2048;

/// Offset of the standard identifier in a volume structure descriptor.
const IDENTIFIER_OFFSET: usize = 1;

/// Most volume structure descriptors read. Ours: Linux reads up to byte
/// 0x800000 (`VSD_MAX_SECTOR_OFFSET`); a bridge disc's ECMA-119 set and
/// the extended area take a handful.
const MAX_DESCRIPTORS: usize = 64;

/// Logical sector sizes tried, as Linux `udf_fill_super` tries block sizes
/// from the device's 512 B up to 4096 B.
const SECTOR_SIZES: [usize; 4] = [512, 1024, 2048, 4096];

/// Sector size above which each descriptor of the sequence takes a whole
/// sector (2/8.3.1); smaller sectors hold one 2048-byte descriptor in
/// several sectors.
const LARGE_SECTOR: usize = 4096;

/// The first anchor point (3/8.4.2.1); UDF records anchors at 256, N - 256
/// and N, at least two of them (UDF 2.60 2.2.3).
const ANCHOR_SECTOR: u32 = 256;

/// Distance of the second anchor point from the last sector N.
const ANCHOR_FROM_END: u64 = 256;

/// Standard identifiers of volume structure descriptors (2/9.1.2 figure
/// 2/3), with what they mean.
const IDENTIFIERS: [(&[u8; 5], &str); 7] = [
    (b"BEA01", "extended area start"),
    (b"BOOT2", "boot descriptor"),
    (b"CD001", "ECMA-119 descriptor"),
    (b"CDW02", "ECMA-168 descriptor"),
    (b"NSR02", "ECMA-167 2nd edition volume"),
    (b"NSR03", "ECMA-167 3rd edition volume"),
    (b"TEA01", "extended area end"),
];

/// The identifiers that mark a volume recorded according to ECMA-167 Part
/// 3 and 4 (3/9.1; NSR02 for the 2nd edition).
const NSR_IDENTIFIERS: [&str; 2] = ["NSR02", "NSR03"];

const ECMA119_IDENTIFIER: &str = "CD001";
const TERMINATING_IDENTIFIER: &str = "TEA01";

/// ECMA-119 volume descriptor type of a boot record (ECMA-119 8.1.1), and
/// the El Torito boot system identifier at offset 7 of one (El Torito 1.0,
/// figure 7).
const ECMA119_BOOT_RECORD: u8 = 0;
const EL_TORITO_ID: &[u8] = b"EL TORITO SPECIFICATION";

/// One descriptor of the recognition sequence.
#[derive(Debug, Clone, Copy)]
pub(super) struct Descriptor {
    /// Standard identifier, one of [`IDENTIFIERS`].
    identifier: &'static str,
    /// What the identifier means, from [`IDENTIFIERS`].
    meaning: &'static str,
    /// File offset.
    offset: usize,
    /// Structure type (byte 0).
    structure_type: u8,
}

/// The volume recognition sequence.
#[derive(Debug, Clone)]
pub(super) struct Sequence {
    descriptors: Vec<Descriptor>,
    /// The NSR descriptor that marks the volume as UDF.
    nsr: Option<&'static str>,
    /// File offset of an ECMA-119 El Torito boot record in the sequence.
    el_torito: Option<usize>,
}

impl Sequence {
    /// A bridge disc: an ECMA-119 descriptor set precedes the extended
    /// area (2/8.3.1.1; UDF 2.60 6.11.4).
    pub(super) fn is_bridge(&self) -> bool {
        self.descriptors
            .iter()
            .any(|d| d.identifier == ECMA119_IDENTIFIER)
    }

    /// `NSR02` or `NSR03`.
    pub(super) fn nsr_identifier(&self) -> &'static str {
        self.nsr.unwrap_or("none")
    }
}

/// Read the recognition sequence from 0x8000 with descriptors `stride`
/// bytes apart. It ends at the first sector that holds no known identifier
/// (2/8.3.1 note 1). As Linux `udf_check_vsd`, an NSR descriptor counts
/// when it comes before the first `TEA01`, and with 4096-byte sectors an
/// NSR descriptor in the second half of a sector counts too (Windows 10
/// writes the sequence 2048 bytes apart on such disks).
fn read_sequence(data: &[u8], stride: usize) -> Sequence {
    let mut sequence = Sequence {
        descriptors: Vec::new(),
        nsr: None,
        el_torito: None,
    };
    let mut terminated = false;
    for index in 0..MAX_DESCRIPTORS {
        let offset = RECOGNITION_OFFSET + index * stride;
        let Some(descriptor) = known_descriptor(data, offset) else {
            break;
        };
        if descriptor.identifier == TERMINATING_IDENTIFIER {
            terminated = true;
        }
        if !terminated && NSR_IDENTIFIERS.contains(&descriptor.identifier) {
            sequence.nsr.get_or_insert(descriptor.identifier);
        }
        if is_el_torito(data, &descriptor) {
            sequence.el_torito.get_or_insert(offset);
        }
        sequence.descriptors.push(descriptor);
        if stride == LARGE_SECTOR && !terminated {
            let half = known_descriptor(data, offset + DESCRIPTOR_SIZE)
                .filter(|d| NSR_IDENTIFIERS.contains(&d.identifier));
            if let Some(half) = half {
                sequence.nsr.get_or_insert(half.identifier);
                sequence.descriptors.push(half);
            }
        }
    }
    sequence
}

/// The descriptor at `offset`, if its standard identifier is known.
fn known_descriptor(data: &[u8], offset: usize) -> Option<Descriptor> {
    let header = data.get(offset..offset + IDENTIFIER_OFFSET + 5)?;
    let identifier = &header[IDENTIFIER_OFFSET..];
    let &(known, meaning) = IDENTIFIERS
        .iter()
        .find(|(known, _)| identifier == known.as_slice())?;
    Some(Descriptor {
        identifier: std::str::from_utf8(known).expect("ASCII identifier"),
        meaning,
        offset,
        structure_type: header[0],
    })
}

/// An ECMA-119 boot record naming the El Torito boot system.
fn is_el_torito(data: &[u8], descriptor: &Descriptor) -> bool {
    let at = descriptor.offset + 7;
    descriptor.identifier == ECMA119_IDENTIFIER
        && descriptor.structure_type == ECMA119_BOOT_RECORD
        && data.get(at..at + EL_TORITO_ID.len()) == Some(EL_TORITO_ID)
}

/// An anchor volume descriptor pointer (3/10.2 figure 3/8): tag (0), main
/// volume descriptor sequence extent (16), reserve extent (24).
#[derive(Debug, Clone, Copy)]
pub(super) struct Anchor {
    pub(super) main: SectorExtent,
    pub(super) reserve: SectorExtent,
}

/// Read and verify the anchor at logical sector `sector`.
fn read_anchor(data: &[u8], sector_size: usize, sector: u64) -> Result<Anchor> {
    let offset = usize::try_from(sector * sector_size as u64)
        .map_err(|_| error(format!("Invalid anchor sector {sector}")))?;
    let descriptor = slice(data, offset, sector_size).map_err(|_| {
        error(format!(
            "Truncated UDF volume: the anchor at sector {sector} (0x{offset:X}) lies past the end \
             of the {} input",
            size_text(data.len())
        ))
    })?;
    let location = u32::try_from(sector).map_err(|_| error("Invalid anchor sector"))?;
    let tag = read_tag(descriptor, offset, Some(location))?;
    expect_identifier(tag, TAG_ANCHOR, "anchor volume descriptor pointer", offset)?;
    Ok(Anchor {
        main: SectorExtent::read(descriptor, 16)?,
        reserve: SectorExtent::read(descriptor, 24)?,
    })
}

/// A recognized volume: the recognition sequence, the sector size whose
/// anchor validates at sector 256, and that anchor.
#[derive(Debug, Clone)]
pub(super) struct Recognized {
    pub(super) sequence: Sequence,
    /// Logical sector size in bytes.
    pub(super) sector_size: usize,
    pub(super) anchor: Anchor,
    /// Further anchor points that hold a valid anchor, as notes text.
    backup_anchors: Vec<String>,
}

/// Recognize a UDF volume: an NSR descriptor in the recognition sequence
/// and a valid anchor at sector 256, trying the sector sizes 512, 1024,
/// 2048 and 4096 B in turn.
///
/// # Errors
///
/// No NSR descriptor in the sequence, or no anchor that validates.
pub(super) fn recognize(data: &[u8]) -> Result<Recognized> {
    let narrow = read_sequence(data, DESCRIPTOR_SIZE);
    let wide = read_sequence(data, LARGE_SECTOR);
    if narrow.nsr.is_none() && wide.nsr.is_none() {
        return Err(error(format!(
            "Missing NSR02 or NSR03 descriptor in the volume recognition sequence at \
             0x{RECOGNITION_OFFSET:X}"
        )));
    }
    let mut first_error = None;
    for sector_size in SECTOR_SIZES {
        let sequence = if sector_size < LARGE_SECTOR {
            &narrow
        } else {
            &wide
        };
        if sequence.nsr.is_none() {
            continue;
        }
        match read_anchor(data, sector_size, u64::from(ANCHOR_SECTOR)) {
            Ok(anchor) => {
                return Ok(Recognized {
                    sequence: sequence.clone(),
                    sector_size,
                    anchor,
                    backup_anchors: backup_anchors(data, sector_size),
                })
            }
            // The 2048-byte reading describes optical media, the common
            // case; otherwise the first size tried.
            Err(e) if sector_size == 2048 || first_error.is_none() => first_error = Some(e),
            Err(_) => {}
        }
    }
    let detail = first_error.map_or_else(String::new, message);
    Err(error(format!(
        "Missing anchor volume descriptor pointer at sector {ANCHOR_SECTOR} for 512, 1024, 2048 \
         and 4096 B sectors ({detail})"
    )))
}

/// The anchor points N - 256 and N, N being the last whole sector of the
/// input, that hold a valid anchor.
fn backup_anchors(data: &[u8], sector_size: usize) -> Vec<String> {
    let sectors = (data.len() / sector_size) as u64;
    let Some(last) = sectors.checked_sub(1) else {
        return Vec::new();
    };
    let points = [
        (last.checked_sub(ANCHOR_FROM_END), "N - 256"),
        (Some(last), "N"),
    ];
    points
        .into_iter()
        .filter_map(|(sector, name)| Some((sector?, name)))
        .filter(|&(sector, _)| sector > u64::from(ANCHOR_SECTOR))
        .filter(|&(sector, _)| read_anchor(data, sector_size, sector).is_ok())
        .map(|(sector, name)| format!("{sector} ({name})"))
        .collect()
}

impl Recognized {
    /// Notes and metadata for the recognition sequence and the anchors.
    pub(super) fn describe(&self, c: &mut Container<'_>) {
        let listed: Vec<String> = self
            .sequence
            .descriptors
            .iter()
            .map(|d| format!("{} ({}) at 0x{:X}", d.identifier, d.meaning, d.offset))
            .collect();
        c.notes.push(format!(
            "Volume recognition sequence: {}",
            listed.join(", ")
        ));
        let anchors = match self.backup_anchors.as_slice() {
            [] => format!(
                "Anchor volume descriptor pointer at sector {ANCHOR_SECTOR}; none at N - 256 or N \
                 of the input (the input may end before the volume does)"
            ),
            [backup] => {
                format!("Anchor volume descriptor pointers at sectors {ANCHOR_SECTOR} and {backup}")
            }
            [first, last] => format!(
                "Anchor volume descriptor pointers at sectors {ANCHOR_SECTOR}, {first} and {last}"
            ),
            more => format!(
                "Anchor volume descriptor pointers at sectors {ANCHOR_SECTOR}, {}",
                more.join(", ")
            ),
        };
        c.notes.push(anchors);
        if self.sequence.is_bridge() {
            let boot = match self.sequence.el_torito {
                Some(offset) => format!(
                    "; it holds an El Torito boot record at 0x{offset:X}, whose boot images the \
                     ISO 9660 reading lists"
                ),
                None => String::new(),
            };
            c.notes.push(format!(
                "UDF bridge disc: an ECMA-119 (ISO 9660) volume descriptor set precedes the UDF \
                 extended area; its hierarchy is not read here{boot}"
            ));
        }
        let ids: Vec<&str> = self
            .sequence
            .descriptors
            .iter()
            .map(|d| d.identifier)
            .collect();
        c.push_metadata(
            "udf_recognition_sequence",
            "Volume recognition sequence",
            ids.join(", "),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ids` written as volume structure descriptors from 0x8000, `stride`
    /// bytes apart.
    fn sequence_image(ids: &[&[u8; 5]], stride: usize) -> Vec<u8> {
        let mut data = vec![0u8; RECOGNITION_OFFSET + (ids.len() + 1) * stride];
        for (i, id) in ids.iter().enumerate() {
            let at = RECOGNITION_OFFSET + i * stride;
            data[at + 1..at + 6].copy_from_slice(id.as_slice());
            data[at + 6] = 1;
        }
        data
    }

    #[test]
    fn the_sequence_ends_at_the_first_unknown_sector() {
        let data = sequence_image(&[b"BEA01", b"NSR03", b"TEA01"], DESCRIPTOR_SIZE);
        let sequence = read_sequence(&data, DESCRIPTOR_SIZE);
        let ids: Vec<&str> = sequence.descriptors.iter().map(|d| d.identifier).collect();
        assert_eq!(ids, ["BEA01", "NSR03", "TEA01"]);
        assert_eq!(sequence.nsr, Some("NSR03"));
        assert!(!sequence.is_bridge());
    }

    #[test]
    fn an_nsr_descriptor_after_the_terminator_does_not_count() {
        let data = sequence_image(&[b"BEA01", b"TEA01", b"NSR02"], DESCRIPTOR_SIZE);
        assert_eq!(read_sequence(&data, DESCRIPTOR_SIZE).nsr, None);
    }

    #[test]
    fn large_sectors_accept_a_sequence_written_2048_bytes_apart() {
        // BEA01 at 0x8000 and NSR03 at 0x8800 share the first 4096-byte
        // sector, as Windows 10 writes them.
        let data = sequence_image(&[b"BEA01", b"NSR03", b"TEA01"], DESCRIPTOR_SIZE);
        assert_eq!(read_sequence(&data, LARGE_SECTOR).nsr, Some("NSR03"));
        let bridge = sequence_image(&[b"CD001", b"CD001", b"BEA01", b"NSR02"], DESCRIPTOR_SIZE);
        assert!(read_sequence(&bridge, DESCRIPTOR_SIZE).is_bridge());
    }

    #[test]
    fn recognition_needs_an_nsr_descriptor_and_an_anchor() {
        let data = sequence_image(&[b"BEA01", b"TEA01"], DESCRIPTOR_SIZE);
        let missing = recognize(&data).unwrap_err().to_string();
        assert!(missing.contains("Missing NSR02 or NSR03"), "{missing}");
        let data = sequence_image(&[b"BEA01", b"NSR02", b"TEA01"], DESCRIPTOR_SIZE);
        let no_anchor = recognize(&data).unwrap_err().to_string();
        assert!(no_anchor.contains("Missing anchor"), "{no_anchor}");
    }
}
