//! Silicon Labs (Ember) EBL files, the update images of the legacy Ember
//! bootloaders: a stream of tags, each a big-endian 16-bit tag ID and
//! length followed by the payload, from the header tag to the end tag.
//!
//! Sources: Silicon Labs UG103.6 "Bootloader Fundamentals" rev. 1.6,
//! chapter 5 (Tables 5.1-5.3: tag IDs and order; Table 5.2: CRCs; Figures
//! 5.1 and 5.2: plain and encrypted layouts); Gecko SDK Suite v2.6
//! `platform/base/hal/micro/cortexm3/common/ebl.h` (tag IDs, structures,
//! minimum sizes, `IMAGE_SIGNATURE`, `EBL_MAJOR_VERSION`, byte order) and
//! `bootloader-ccm.h` (nonce and MAC sizes), and `micro-types.h` (platform
//! and micro IDs), read from the `tomyqg/gecko_sdk_suite` mirror at
//! `095c36313756a5954964785851d576bd81f35c02`; `gecko_sdk` v4.5.1
//! (`8a2efd2cb191cb250fd4c1e655b16b8a80be1997`)
//! `platform/service/legacy_hal/inc/bootloader-common.h` and
//! `platform/bootloader/api/ember_btl_interface.h` (application address
//! table), `ember_btl_common.c` (`APP_ADDRESS_TABLE_TYPE`) and
//! `sl_legacy_bootloader_device_info.h.jinja` (EFR32 builds set platform 4,
//! micro 24); Simplicity Commander "EBL Commands" (`ebl print` output).
//!
//! "EBL data fields are stored in network (big) endian order however, fields
//! referenced within the aat of the ebl header are stored in native (little)
//! endian order" (`ebl.h`); the end tag's CRC is little-endian. The header
//! carries the first 128 bytes of the application address table (AAT),
//! whose `platInfo` byte names the platform; platform 4 (`CortexM3`, also
//! set by EFR32 builds) is the only one with an established Arm Cortex-M
//! core, and it is the only one mapped to an ISA.

use super::*;
use crate::formats::checksum;

/// Tag ID and length.
const TAG_HEADER_SIZE: usize = 4;

/// `IMAGE_SIGNATURE` in the header and the encryption header.
const IMAGE_SIGNATURE: u16 = 0xe350;

/// "The major version is verified by the ebl processing code of the
/// bootloader."
const EBL_MAJOR_VERSION: u16 = 0x0200;
const EBL_MAJOR_VERSION_MASK: u16 = 0xff00;

/// Header payload (`EBL_HEADER_MIN_SIZE` bytes before the AAT): `version`,
/// `signature` (2), `flashAddr` (4), `aatCrc` (8), then the AAT bytes.
const HEADER_MIN_SIZE: usize = 12;
const HEADER_SIGNATURE_OFFSET: usize = 2;

/// "Only the first 128 bytes of the AAT can be referenced as part of the
/// ebl header."
const AAT_MAX_SIZE: usize = 128;

/// Program tags: `flashAddr`, then at least two data bytes.
const FLASH_ADDRESS_SIZE: usize = 4;

/// Program data "must be multiple of 2" (`eblProg3xx_t`).
const PROGRAM_DATA_ALIGNMENT: usize = 2;

/// `eblEnd_t`: `eblCrc`.
const END_SIZE: usize = 4;

/// `eblEncHdr3xx_t`: `version`, `encType` (2), `signature` (4).
const ENC_HEADER_SIZE: usize = 6;
const ENC_SIGNATURE_OFFSET: usize = 4;

/// `encType` values.
const ENC_TYPE_NONE: u16 = 0x0000;
const ENC_TYPE_CCM: u16 = 0x0001;

/// `eblEncInit3xx_t`: `msgLen` and the nonce (`NONCE_LENGTH` 12), then
/// optional associated data.
const ENC_INIT_MIN_SIZE: usize = 4 + 12;

/// `MAC_LENGTH`.
const MAC_SIZE: usize = 16;

/// AAT fields (`HalAppAddressTableType`, little-endian): `resetVector` (4),
/// `type` (16), `platInfo` (24), `microInfo` (25), `phyInfo` (26),
/// `softwareVersion` (28), `customerApplicationVersion` (88).
const AAT_RESET_VECTOR_OFFSET: usize = 4;
const AAT_TYPE_OFFSET: usize = 16;
const AAT_PLATFORM_OFFSET: usize = 24;
const AAT_MICRO_OFFSET: usize = 25;
const AAT_PHY_OFFSET: usize = 26;
const AAT_SOFTWARE_VERSION_OFFSET: usize = 28;
const AAT_CUSTOMER_VERSION_OFFSET: usize = 88;

/// `APP_ADDRESS_TABLE_TYPE`: the AAT fields above are defined for this
/// table type only.
const APP_ADDRESS_TABLE_TYPE: u16 = 0x0aa7;

/// `EMBER_PLATFORM_CORTEXM3`.
const EMBER_PLATFORM_CORTEXM3: u8 = 4;

/// The code of a `CortexM3` platform part: Arm Thumb, little-endian (the
/// AAT's native byte order).
const CORTEX_M: Target = Target::new(Isa::Arm, 32, Endianness::Little);

/// `EMBER_PLATFORM_STRINGS`, indexed by `platInfo`.
const PLATFORMS: &[&str] = &[
    "Unknown",
    "Test",
    "XAP2b",
    "obsolete_3",
    "CortexM3",
    "C8051",
    "FFD",
];

/// `micro-types.h` names of the `CortexM3` micros, indexed by `microInfo`.
#[rustfmt::skip]
const CORTEXM3_MICROS: &[&str] = &[
    "Unknown", "em350", "em360", "em357", "em367", "em351", "em35x",
    "obsolete_cortexm3_7", "em3588", "em359", "em3581", "em3582", "em3585",
    "em3586", "em3587", "sky66107", "em3597", "em356", "em3598", "em3591",
    "em3592", "em3595", "em3596", "em317", "efr32", "obsolete_cortexm3_25",
    "obsolete_cortexm3_26", "em346", "obsolete_cortexm3_28",
    "obsolete_cortexm3_29", "em355", "em3555", "obsolete_cortexm3_32",
    "obsolete_cortexm3_33", "obsolete_cortexm3_34",
];

/// What a tag carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Header,
    Metadata,
    Program,
    MfgProgram,
    End,
    EncHeader,
    EncInit,
    EncData,
    Mac,
}

/// One row of the `ebl.h` tag table.
struct TagInfo {
    id: u16,
    kind: Kind,
    name: &'static str,
    /// Smallest payload, in bytes.
    min_size: usize,
    /// The payload has exactly `min_size` bytes.
    exact: bool,
}

const fn tag(id: u16, kind: Kind, name: &'static str, min_size: usize, exact: bool) -> TagInfo {
    TagInfo {
        id,
        kind,
        name,
        min_size,
        exact,
    }
}

/// Tag IDs (`ebl.h` `EBLTAG_*`).
const EBLTAG_HEADER: u16 = 0x0000;
const EBLTAG_METADATA: u16 = 0xf608;
const EBLTAG_PROG: u16 = 0xfe01;
const EBLTAG_MFGPROG: u16 = 0x02fe;
const EBLTAG_ERASEPROG: u16 = 0xfd03;
const EBLTAG_END: u16 = 0xfc04;
const EBLTAG_ENC_HEADER: u16 = 0xfb05;
const EBLTAG_ENC_INIT: u16 = 0xfa06;
const EBLTAG_ENC_EBL_DATA: u16 = 0xf907;
const EBLTAG_ENC_MAC: u16 = 0xf709;

/// Smallest payloads `ebl.h` gives the metadata, program and encrypted data
/// tags (`METADATA_MIN_SIZE`, `PROGRAM_MIN_SIZE`,
/// `EBL_ENC_DATA_SIZE`).
const METADATA_MIN_SIZE: usize = 1;
const PROGRAM_MIN_SIZE: usize = 6;
const ENC_DATA_MIN_SIZE: usize = 4;

/// `EBLTAG_INFO_STRUCT_CONTENTS` of `ebl.h`: tag IDs, minimum serialized
/// payload sizes and whether a payload may be longer.
#[rustfmt::skip]
const TAGS: &[TagInfo] = &[
    //  tagId                kind             name                       minimum payload    exact
    tag(EBLTAG_HEADER,       Kind::Header,     "header",                  HEADER_MIN_SIZE,   false),
    tag(EBLTAG_METADATA,     Kind::Metadata,   "metadata",                METADATA_MIN_SIZE, false),
    tag(EBLTAG_PROG,         Kind::Program,    "program data",            PROGRAM_MIN_SIZE,  false),
    tag(EBLTAG_MFGPROG,      Kind::MfgProgram, "manufacturing data",      PROGRAM_MIN_SIZE,  false),
    tag(EBLTAG_ERASEPROG,    Kind::Program,    "erase then program data", PROGRAM_MIN_SIZE,  false),
    tag(EBLTAG_END,          Kind::End,        "end",                     END_SIZE,          true),
    tag(EBLTAG_ENC_HEADER,   Kind::EncHeader,  "encryption header",       ENC_HEADER_SIZE,   true),
    tag(EBLTAG_ENC_INIT,     Kind::EncInit,    "encryption init",         ENC_INIT_MIN_SIZE, false),
    tag(EBLTAG_ENC_EBL_DATA, Kind::EncData,    "encrypted data",          ENC_DATA_MIN_SIZE, false),
    tag(EBLTAG_ENC_MAC,      Kind::Mac,        "MAC",                     MAC_SIZE,          true),
];

fn tag_info(id: u16) -> Option<&'static TagInfo> {
    TAGS.iter().find(|t| t.id == id)
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

/// Strong recognition: a plain or an encryption header tag at offset 0.
pub(super) fn has_magic(data: &[u8]) -> bool {
    match be_u16(data, 0) {
        Ok(EBLTAG_HEADER) => is_plain_header(data),
        Ok(EBLTAG_ENC_HEADER) => is_encryption_header(data),
        _ => false,
    }
}

/// The header tag's ID is 0x0000, which many files start with, so the
/// signature alone would leave a 16-bit key. The tag length must also fit
/// the header (12 B and at most 128 AAT bytes) and the major version must
/// be the one the bootloader accepts, as `parse` requires.
fn is_plain_header(data: &[u8]) -> bool {
    let header_sizes = HEADER_MIN_SIZE..=HEADER_MIN_SIZE + AAT_MAX_SIZE;
    let version_at = TAG_HEADER_SIZE;
    let signature_at = TAG_HEADER_SIZE + HEADER_SIGNATURE_OFFSET;
    be_u16(data, 2).is_ok_and(|length| header_sizes.contains(&usize::from(length)))
        && be_u16(data, version_at)
            .is_ok_and(|version| version & EBL_MAJOR_VERSION_MASK == EBL_MAJOR_VERSION)
        && be_u16(data, signature_at).is_ok_and(|signature| signature == IMAGE_SIGNATURE)
}

/// The encryption header tag: its exact length, then the signature after
/// the version and encryption type.
fn is_encryption_header(data: &[u8]) -> bool {
    let signature_at = TAG_HEADER_SIZE + ENC_SIGNATURE_OFFSET;
    be_u16(data, 2).is_ok_and(|length| usize::from(length) == ENC_HEADER_SIZE)
        && be_u16(data, signature_at).is_ok_and(|signature| signature == IMAGE_SIGNATURE)
}

/// Where the walk is in the tag sequence (UG103.6 Figures 5.1 and 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// After the header: program, metadata or end tags.
    Plain,
    /// After the encryption header: the encryption init tag.
    EncryptionInit,
    /// After the encryption init: encrypted data or the MAC.
    EncryptedData,
    /// After the MAC: the end tag.
    AfterMac,
}

impl Stage {
    /// Whether a tag of `kind` may come next.
    fn accepts(self, kind: Kind) -> bool {
        match self {
            Self::Plain => matches!(
                kind,
                Kind::Program | Kind::MfgProgram | Kind::Metadata | Kind::End
            ),
            Self::EncryptionInit => kind == Kind::EncInit,
            Self::EncryptedData => matches!(kind, Kind::EncData | Kind::Mac),
            Self::AfterMac => kind == Kind::End,
        }
    }

    /// The stage after a tag of `kind`.
    fn after(self, kind: Kind) -> Self {
        match kind {
            Kind::EncInit => Self::EncryptedData,
            Kind::Mac => Self::AfterMac,
            _ => self,
        }
    }
}

/// Walk state between tags.
struct Walk {
    stage: Stage,
    sections: Sections,
    /// Children left out at [`MAX_COMPONENTS`].
    unlisted: usize,
    /// Encrypted data tags seen.
    encrypted_tags: usize,
}

/// One tag, bounds-checked.
struct Tag<'a> {
    info: &'static TagInfo,
    /// File offset of the tag ID.
    offset: usize,
    /// File offset of the payload.
    payload_offset: usize,
    payload: &'a [u8],
}

/// The tag at `pos`: ID and length inside the file, a known ID, the payload
/// inside the file and of a size `ebl.h` allows.
fn read_tag(data: &[u8], pos: usize) -> Result<Tag<'_>> {
    if data.len() - pos < TAG_HEADER_SIZE {
        return Err(error(format!(
            "Missing EBL end tag: truncated tag at 0x{pos:X}"
        )));
    }
    let id = be_u16(data, pos)?;
    let length = usize::from(be_u16(data, pos + 2)?);
    let info =
        tag_info(id).ok_or_else(|| error(format!("Unknown EBL tag 0x{id:04X} at 0x{pos:X}")))?;
    let payload_offset = pos + TAG_HEADER_SIZE;
    let payload = data
        .get(payload_offset..)
        .and_then(|rest| rest.get(..length))
        .ok_or_else(|| {
            error(format!(
                "Truncated EBL {} tag at 0x{pos:X}: length {length} B",
                info.name
            ))
        })?;
    let size_ok = if info.exact {
        length == info.min_size
    } else {
        length >= info.min_size
    };
    if !size_ok {
        let expected = if info.exact { "exactly" } else { "at least" };
        return Err(error(format!(
            "Invalid EBL {} tag length {length} B at 0x{:X}; expected {expected} {} B",
            info.name,
            pos + 2,
            info.min_size
        )));
    }
    Ok(Tag {
        info,
        offset: pos,
        payload_offset,
        payload,
    })
}

/// Parse an EBL file: plain program tags become load sections at their
/// flash addresses; manufacturing data, metadata and encrypted data are
/// opaque children.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(
        FileFormat::SilabsEbl,
        Layout::Ebl.label(),
        Layout::Ebl.key_prefix(),
    );
    let first = read_tag(data, 0)?;
    let stage = match first.info.kind {
        Kind::Header => {
            header(&mut c, first.payload)?;
            Stage::Plain
        }
        Kind::EncHeader => {
            encryption_header(&mut c, first.payload)?;
            Stage::EncryptionInit
        }
        _ => {
            return Err(error(format!(
                "Missing EBL header tag at 0x0: {} tag",
                first.info.name
            )))
        }
    };
    let mut walk = Walk {
        stage,
        sections: Sections::new(),
        unlisted: 0,
        encrypted_tags: 0,
    };
    let mut pos = first.payload_offset + first.payload.len();
    loop {
        let tag = read_tag(data, pos)?;
        if !walk.stage.accepts(tag.info.kind) {
            return Err(error(format!(
                "Invalid EBL tag order: {} tag at 0x{pos:X}",
                tag.info.name
            )));
        }
        if tag.info.kind == Kind::End {
            finish(&mut c, data, &tag, walk)?;
            return Ok(c);
        }
        walk.stage = walk.stage.after(tag.info.kind);
        apply_tag(&mut c, &mut walk, &tag)?;
        pos = tag.payload_offset + tag.payload.len();
    }
}

/// Header payload: `version` (BE), `signature` (BE), `flashAddr` (BE),
/// `aatCrc` (BE), then at most 128 AAT bytes (LE fields).
fn header(c: &mut Container<'_>, payload: &[u8]) -> Result<()> {
    if payload.len() > HEADER_MIN_SIZE + AAT_MAX_SIZE {
        return Err(error(format!(
            "Invalid EBL header tag length {} B at 0x2; at most {} B",
            payload.len(),
            HEADER_MIN_SIZE + AAT_MAX_SIZE
        )));
    }
    let signature = be_u16(payload, HEADER_SIGNATURE_OFFSET)?;
    if signature != IMAGE_SIGNATURE {
        return Err(error(format!(
            "Invalid EBL header signature 0x{signature:04X} at 0x6"
        )));
    }
    let version = be_u16(payload, 0)?;
    if version & EBL_MAJOR_VERSION_MASK != EBL_MAJOR_VERSION {
        return Err(error(format!(
            "Unsupported EBL version 0x{version:04X} at 0x4"
        )));
    }
    let flash_address = be_u32(payload, 4)?;
    let aat_crc = be_u32(payload, 8)?;
    c.push_metadata("ebl_version", "EBL version", format!("0x{version:04X}"));
    c.push_metadata(
        "ebl_aat_address",
        "AAT flash address",
        format!("0x{flash_address:08X}"),
    );
    c.push_metadata(
        "ebl_aat_crc",
        "AAT CRC (not verified)",
        format!("0x{aat_crc:08X}"),
    );
    application_address_table(c, &payload[HEADER_MIN_SIZE..]);
    Ok(())
}

/// The AAT in the header: the platform names the target when the table is
/// an application address table; the reset vector is the entry point.
fn application_address_table(c: &mut Container<'_>, aat: &[u8]) {
    let Ok(table_type) = le_u16(aat, AAT_TYPE_OFFSET) else {
        c.notes.push(format!(
            "The header holds {} B of the application address table, too few for its type; the \
             format names no ISA",
            aat.len()
        ));
        return;
    };
    if table_type != APP_ADDRESS_TABLE_TYPE {
        c.notes.push(format!(
            "AAT type 0x{table_type:04X} is not the application address table \
             (0x{APP_ADDRESS_TABLE_TYPE:04X}); platform not read, the format names no ISA"
        ));
        return;
    }
    if let Ok(reset_vector) = le_u32(aat, AAT_RESET_VECTOR_OFFSET) {
        c.entry = Some(u64::from(reset_vector));
    }
    let Some(&platform) = aat.get(AAT_PLATFORM_OFFSET) else {
        c.notes
            .push("The header's AAT ends before platInfo; the format names no ISA".to_string());
        return;
    };
    let platform_name = PLATFORMS
        .get(usize::from(platform))
        .copied()
        .unwrap_or("unlisted");
    c.push_metadata(
        "ebl_platform",
        "AAT platform",
        format!("{platform} ({platform_name})"),
    );
    if let Some(&micro) = aat.get(AAT_MICRO_OFFSET) {
        let micro_text = match CORTEXM3_MICROS.get(usize::from(micro)) {
            Some(name) if platform == EMBER_PLATFORM_CORTEXM3 => format!("{micro} ({name})"),
            _ => micro.to_string(),
        };
        c.push_metadata("ebl_micro", "AAT micro", micro_text);
    }
    if let Some(&phy) = aat.get(AAT_PHY_OFFSET) {
        c.push_metadata("ebl_phy", "AAT PHY", u64::from(phy));
    }
    if let Ok(version) = le_u16(aat, AAT_SOFTWARE_VERSION_OFFSET) {
        c.push_metadata(
            "ebl_software_version",
            "Stack software version",
            format!("0x{version:04X}"),
        );
    }
    if let Ok(version) = le_u32(aat, AAT_CUSTOMER_VERSION_OFFSET) {
        c.push_metadata(
            "ebl_customer_version",
            "Customer application version",
            format!("0x{version:08X}"),
        );
    }
    if platform == EMBER_PLATFORM_CORTEXM3 {
        c.target = Some(CORTEX_M);
        c.notes.push(
            "AAT platform 4 (CortexM3) names an Arm Cortex-M core; the entry point is the AAT \
             reset vector (bit 0 selects Thumb state)"
                .to_string(),
        );
    } else {
        c.notes.push(format!(
            "AAT platform {platform} ({platform_name}) is not mapped to an ISA"
        ));
    }
}

/// Encryption header: `version`, `encType`, `signature`, all big-endian.
fn encryption_header(c: &mut Container<'_>, payload: &[u8]) -> Result<()> {
    let signature = be_u16(payload, ENC_SIGNATURE_OFFSET)?;
    if signature != IMAGE_SIGNATURE {
        return Err(error(format!(
            "Invalid EBL encryption header signature 0x{signature:04X} at 0x8"
        )));
    }
    let version = be_u16(payload, 0)?;
    let encryption = match be_u16(payload, 2)? {
        ENC_TYPE_NONE => "none".to_string(),
        ENC_TYPE_CCM => "AES-CCM".to_string(),
        other => format!("0x{other:04X}"),
    };
    c.push_metadata("ebl_version", "EBL version", format!("0x{version:04X}"));
    c.push_metadata("ebl_encryption", "Encryption type", encryption);
    c.opaque = true;
    Ok(())
}

/// Record one tag between the first tag and the end tag.
fn apply_tag<'a>(c: &mut Container<'a>, walk: &mut Walk, tag: &Tag<'a>) -> Result<()> {
    match tag.info.kind {
        Kind::Program => {
            let program = program_data(tag)?;
            let label = format!("Load section {}", c.sections.len() + 1);
            walk.sections.push(
                c,
                stored_section(label, program.address, program.offset, program.data),
            );
        }
        Kind::MfgProgram => {
            let program = program_data(tag)?;
            let label = format!("Manufacturing data at 0x{:X}", program.address);
            let child = Child::opaque(label, program.offset, program.data);
            push_child(c, walk, child);
        }
        Kind::Metadata => {
            let child = Child::opaque("Metadata", tag.payload_offset, tag.payload);
            push_child(c, walk, child);
        }
        Kind::EncInit => {
            let message_length = be_u32(tag.payload, 0)?;
            c.push_metadata(
                "ebl_encrypted_length",
                "Encrypted message length (B)",
                u64::from(message_length),
            );
        }
        Kind::EncData => {
            walk.encrypted_tags += 1;
            let child = Child::opaque("Encrypted EBL data", tag.payload_offset, tag.payload);
            push_child(c, walk, child);
        }
        Kind::Mac => c
            .notes
            .push("AES-CCM MAC present; not verified".to_string()),
        // The stage table admits neither here: headers only start a file
        // and the end tag finishes the walk.
        Kind::Header | Kind::EncHeader | Kind::End => {}
    }
    Ok(())
}

/// The bytes a program tag writes.
struct ProgramData<'a> {
    /// `flashAddr`: flash byte address.
    address: u64,
    /// File offset of the data.
    offset: usize,
    data: &'a [u8],
}

/// A program tag's `flashAddr` (BE) and data, whose length must be even.
fn program_data<'a>(tag: &Tag<'a>) -> Result<ProgramData<'a>> {
    let address = u64::from(be_u32(tag.payload, 0)?);
    let data = &tag.payload[FLASH_ADDRESS_SIZE..];
    if data.len() % PROGRAM_DATA_ALIGNMENT != 0 {
        return Err(error(format!(
            "Invalid EBL {} tag at 0x{:X}: {} B of data is not a multiple of \
             {PROGRAM_DATA_ALIGNMENT} B",
            tag.info.name,
            tag.offset,
            data.len()
        )));
    }
    Ok(ProgramData {
        address,
        offset: tag.payload_offset + FLASH_ADDRESS_SIZE,
        data,
    })
}

/// List a child unless [`MAX_COMPONENTS`] is reached.
fn push_child<'a>(c: &mut Container<'a>, walk: &mut Walk, child: Child<'a>) {
    if c.children.len() < MAX_COMPONENTS {
        c.children.push(child);
    } else {
        walk.unlisted += 1;
    }
}

/// End tag: `eblCrc` (LE) is the zlib CRC-32 of every byte before it (the
/// running CRC over the file then leaves the residue `0xDEBB20E3`); only
/// erased-flash padding may follow.
fn finish(c: &mut Container<'_>, data: &[u8], tag: &Tag<'_>, walk: Walk) -> Result<()> {
    let crc_at = tag.payload_offset;
    let stored = le_u32(data, crc_at)?;
    let computed = checksum::crc32(&data[..crc_at]);
    if stored != computed {
        return Err(error(format!(
            "Invalid EBL end tag CRC-32 0x{stored:08X} at 0x{crc_at:X}; computed 0x{computed:08X}"
        )));
    }
    let end = crc_at + END_SIZE;
    if !is_padding(&data[end..]) {
        return Err(error(format!(
            "Unexpected {} B after the EBL end tag at 0x{end:X}",
            data.len() - end
        )));
    }
    c.consumed = end;
    let isa_text = if c.target.is_some() {
        "the AAT names the platform"
    } else {
        "the format names no ISA"
    };
    c.notes.insert(
        0,
        format!(
            "EBL: {}; end-tag CRC-32 verified; {isa_text}",
            count(c.sections.len(), "program section", "program sections")
        ),
    );
    walk.sections.finish(c);
    if c.opaque {
        c.notes.push(format!(
            "Encrypted EBL: {}; the key is not in the file",
            count(
                walk.encrypted_tags,
                "encrypted data tag",
                "encrypted data tags"
            )
        ));
    }
    if walk.unlisted > 0 {
        c.notes.push(format!(
            "{} not listed (limit {MAX_COMPONENTS})",
            count(walk.unlisted, "further tag", "further tags")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_table_ids_are_unique_and_start_tags_are_known() {
        for (i, t) in TAGS.iter().enumerate() {
            assert!(TAGS[i + 1..].iter().all(|u| u.id != t.id), "{}", t.name);
        }
        assert_eq!(tag_info(EBLTAG_HEADER).unwrap().kind, Kind::Header);
        assert_eq!(tag_info(EBLTAG_ENC_HEADER).unwrap().kind, Kind::EncHeader);
        assert_eq!(PLATFORMS[usize::from(EMBER_PLATFORM_CORTEXM3)], "CortexM3");
        assert_eq!(CORTEXM3_MICROS[24], "efr32");
    }

    #[test]
    fn stages_follow_the_plain_and_encrypted_layouts() {
        assert!(Stage::Plain.accepts(Kind::Program));
        assert!(Stage::Plain.accepts(Kind::End));
        assert!(!Stage::Plain.accepts(Kind::EncData));
        assert!(!Stage::EncryptionInit.accepts(Kind::EncData));
        assert_eq!(
            Stage::EncryptionInit.after(Kind::EncInit),
            Stage::EncryptedData
        );
        assert!(!Stage::EncryptedData.accepts(Kind::End));
        assert_eq!(Stage::EncryptedData.after(Kind::Mac), Stage::AfterMac);
        assert!(Stage::AfterMac.accepts(Kind::End));
        assert!(!Stage::AfterMac.accepts(Kind::EncData));
    }

    #[test]
    fn magic_needs_the_signature_after_the_first_tag() {
        assert!(has_magic(&[0, 0, 0, 0x8c, 2, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0, 0, 0x8c, 2, 1, 0x50, 0xe3]));
        assert!(has_magic(&[0xfb, 0x05, 0, 6, 2, 1, 0, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0xfb, 0x05, 0, 6, 2, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0]));
    }

    #[test]
    fn magic_needs_a_header_length_and_major_version_the_parser_accepts() {
        assert!(has_magic(&[0, 0, 0, 12, 2, 0, 0xe3, 0x50]));
        assert!(has_magic(&[0, 0, 0, 140, 2, 0xff, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0, 0, 11, 2, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0, 0, 141, 2, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0, 1, 0x8c, 2, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0, 0, 0, 0x8c, 3, 1, 0xe3, 0x50]));
        assert!(!has_magic(&[0xfb, 0x05, 0, 7, 2, 1, 0, 1, 0xe3, 0x50]));
    }
}
