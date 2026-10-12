//! FFS file sections: `EFI_COMMON_SECTION_HEADER` and
//! `EFI_COMMON_SECTION_HEADER2` (PI 1.8 Vol. 3, 3.2.4; EDK2
//! `PiFirmwareFile.h`), the encapsulation sections `EFI_SECTION_COMPRESSION`
//! and `EFI_SECTION_GUID_DEFINED` (PI 1.8 Vol. 3, 3.2.5; EDK2
//! `Core/Pei/FwVol/FwVol.c` `ProcessSection`, `Core/DxeIplPeim/DxeLoad.c`
//! and the LZMA, LZMA F86, Brotli, Tiano and CRC32 extraction libraries),
//! and the leaf sections that hold images.
//!
//! Common header: 24-bit size including the header, then the type; a size
//! of `0xFFFFFF` means a u32 extended size follows (8-byte header).
//! Sections start on 4-byte boundaries relative to the file data, and an
//! encapsulation's output is again a section stream.

use super::*;
use crate::formats::checksum;

const SECTION_HEADER_SIZE: usize = 4;
const SECTION_HEADER2_SIZE: usize = 8;

/// A 24-bit size of `0xFFFFFF` selects the extended size field.
const SECTION_SIZE_EXTENDED: u32 = 0x00FF_FFFF;

const SECTION_ALIGNMENT: usize = 4;

/// `EFI_SECTION_*` types.
const EFI_SECTION_COMPRESSION: u8 = 0x01;
const EFI_SECTION_GUID_DEFINED: u8 = 0x02;
const EFI_SECTION_DISPOSABLE: u8 = 0x03;
const EFI_SECTION_PE32: u8 = 0x10;
const EFI_SECTION_PIC: u8 = 0x11;
const EFI_SECTION_TE: u8 = 0x12;
const EFI_SECTION_DXE_DEPEX: u8 = 0x13;
const EFI_SECTION_VERSION: u8 = 0x14;
const EFI_SECTION_USER_INTERFACE: u8 = 0x15;
const EFI_SECTION_COMPATIBILITY16: u8 = 0x16;
const EFI_SECTION_FIRMWARE_VOLUME_IMAGE: u8 = 0x17;
const EFI_SECTION_FREEFORM_SUBTYPE_GUID: u8 = 0x18;
const EFI_SECTION_RAW: u8 = 0x19;
const EFI_SECTION_PEI_DEPEX: u8 = 0x1B;
const EFI_SECTION_MM_DEPEX: u8 = 0x1C;

/// Vendor sections holding a u32 POST code (`UEFITool` `common/ffs.h`
/// `INSYDE_SECTION_POSTCODE` and `PHOENIX_SECTION_POSTCODE`; no
/// specification defines them).
const INSYDE_SECTION_POSTCODE: u8 = 0x20;
const PHOENIX_SECTION_POSTCODE: u8 = 0xF0;

/// Section types PI 1.8 defines and the vendor POST code sections; anything
/// else is reserved.
const DEFINED_SECTION_TYPES: &[u8] = &[
    EFI_SECTION_COMPRESSION,
    EFI_SECTION_GUID_DEFINED,
    EFI_SECTION_DISPOSABLE,
    EFI_SECTION_PE32,
    EFI_SECTION_PIC,
    EFI_SECTION_TE,
    EFI_SECTION_DXE_DEPEX,
    EFI_SECTION_VERSION,
    EFI_SECTION_USER_INTERFACE,
    EFI_SECTION_COMPATIBILITY16,
    EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
    EFI_SECTION_FREEFORM_SUBTYPE_GUID,
    EFI_SECTION_RAW,
    EFI_SECTION_PEI_DEPEX,
    EFI_SECTION_MM_DEPEX,
    INSYDE_SECTION_POSTCODE,
    PHOENIX_SECTION_POSTCODE,
];

/// `EFI_COMPRESSION_SECTION` after the common header: `UncompressedLength`
/// (u32) and `CompressionType` (u8).
const COMPRESSION_FIELDS_SIZE: usize = 5;
const EFI_NOT_COMPRESSED: u8 = 0x00;
const EFI_STANDARD_COMPRESSION: u8 = 0x01;

/// `EFI_GUID_DEFINED_SECTION` after the common header:
/// `SectionDefinitionGuid`, `DataOffset` (u16, from the section start) and
/// `Attributes` (u16).
const GUID_DEFINED_FIELDS_SIZE: usize = 20;
const EFI_GUIDED_SECTION_PROCESSING_REQUIRED: u16 = 0x0001;

/// `CRC32_SECTION_HEADER`: a u32 CRC after the GUID-defined fields.
const CRC32_FIELD_SIZE: usize = 4;

/// EDK2 Brotli payload prefix: decoded size (u64) and scratch size (u64).
const BROTLI_HEADER_SIZE: usize = 16;

/// LZMA-alone header: properties (1 B), dictionary size (u32), decoded size
/// (u64, all ones when unknown).
const LZMA_SIZE_OFFSET: usize = 5;
const LZMA_SIZE_UNKNOWN: u64 = u64::MAX;

/// EFI/Tiano header: compressed size (u32), original size (u32).
const EFI_ORIGINAL_SIZE_OFFSET: usize = 4;

/// `FREEFORM_SUBTYPE_GUID` sections start with the subtype GUID.
const SUBTYPE_GUID_SIZE: usize = 16;

/// UI names are cut at this many UCS-2 code units.
const MAX_NAME_UNITS: usize = 256;

/// `gLzmaCustomDecompressGuid` (EDK2 `MdeModulePkg.dec`).
const LZMA_CUSTOM_DECOMPRESS_GUID: Guid = Guid::new(
    0xEE4E_5898,
    0x3914,
    0x4259,
    [0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF],
);

/// `gLzmaF86CustomDecompressGuid`: LZMA, then the x86 BCJ decode filter.
const LZMA_F86_CUSTOM_DECOMPRESS_GUID: Guid = Guid::new(
    0xD42A_E6BD,
    0x1352,
    0x4BFB,
    [0x90, 0x9A, 0xCA, 0x72, 0xA6, 0xEA, 0xE8, 0x89],
);

/// `gBrotliCustomDecompressGuid`.
const BROTLI_CUSTOM_DECOMPRESS_GUID: Guid = Guid::new(
    0x3D53_2050,
    0x5CDA,
    0x4FD0,
    [0x87, 0x9E, 0x0F, 0x7F, 0x63, 0x0D, 0x5A, 0xFB],
);

/// `gTianoCustomDecompressGuid`.
const TIANO_CUSTOM_DECOMPRESS_GUID: Guid = Guid::new(
    0xA312_80AD,
    0x481E,
    0x41B6,
    [0x95, 0xE8, 0x12, 0x7F, 0x4C, 0x98, 0x47, 0x79],
);

/// `gEfiCrc32GuidedSectionExtractionGuid`.
const CRC32_GUIDED_SECTION_EXTRACTION_GUID: Guid = Guid::new(
    0xFC1B_CDB0,
    0x7D31,
    0x49AA,
    [0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83],
);

/// `gEfiFirmwareContentsSignedGuid`: a certificate, then a plain section
/// stream.
const FIRMWARE_CONTENTS_SIGNED_GUID: Guid = Guid::new(
    0x0F9D_89E8,
    0x9259,
    0x4F76,
    [0xA5, 0xAF, 0x0C, 0x89, 0xE3, 0x40, 0x23, 0xDF],
);

/// The images of one FFS file, labeled once the file's UI section (which
/// may follow them, or sit inside an encapsulation) has been seen.
#[derive(Debug)]
pub(super) struct FileContext {
    name: Guid,
    ui_name: Option<String>,
    /// Index into the container's children and the image kind.
    leaves: Vec<(usize, &'static str)>,
}

impl FileContext {
    pub(super) fn new(name: Guid) -> Self {
        Self {
            name,
            ui_name: None,
            leaves: Vec::new(),
        }
    }

    /// List `stream` as an image of this file.
    fn push_leaf<'a>(
        &mut self,
        c: &mut Container<'a>,
        budget: &mut Budget,
        kind: &'static str,
        stream: Stream<'a, '_>,
        leaf: Leaf,
    ) {
        if c.children.len() >= MAX_COMPONENTS {
            budget.unlisted += 1;
            return;
        }
        let mut child = stream.child();
        match leaf {
            Leaf::Image(target) => child.target = target,
            Leaf::Code(target) => child = child.with_target(target).as_code(),
            Leaf::Member => child = child.if_recognized(),
            Leaf::Opaque => child.opaque = true,
        }
        self.leaves.push((c.children.len(), kind));
        budget.push(c, child);
    }

    /// Label this file's images `<UI name> (<GUID>): <kind>`.
    pub(super) fn finish(self, c: &mut Container<'_>) {
        for (index, kind) in self.leaves {
            let label = match &self.ui_name {
                Some(name) => format!("{name} ({}): {kind}", self.name),
                None => format!("{}: {kind}", self.name),
            };
            if let Some(child) = c.children.get_mut(index) {
                child.label = label;
            }
        }
    }
}

/// How a leaf section is classified.
#[derive(Debug, Clone, Copy)]
enum Leaf {
    /// An executable image with its own header, and the target its machine
    /// field names when the image header does not parse.
    Image(Option<Target>),
    /// Raw code without a header, for the target its section type
    /// documents; never parsed as a nested container.
    Code(Target),
    /// Data that is listed only when it is a recognized format.
    Member,
    /// Data that never reaches the code model.
    Opaque,
}

/// One common section header.
#[derive(Debug)]
struct SectionHeader {
    section_type: u8,
    /// 4 or 8 bytes.
    header_size: usize,
    /// The whole section, header included.
    size: usize,
}

/// The header at `pos`, with its size checked against the stream.
fn section_header(stream: &Stream<'_, '_>, pos: usize) -> Result<SectionHeader> {
    let bytes = stream.bytes();
    let truncated = || error(format!("Truncated section header at {}", stream.place(pos)));
    let size24 = le_u24(bytes, pos).map_err(|_| truncated())?;
    let section_type = byte_at(bytes, pos + 3).map_err(|_| truncated())?;
    let (header_size, size) = if size24 == SECTION_SIZE_EXTENDED {
        let extended = le_u32(bytes, pos + 4).map_err(|_| truncated())?;
        (SECTION_HEADER2_SIZE, to_usize(extended, "section size")?)
    } else {
        (SECTION_HEADER_SIZE, to_usize(size24, "section size")?)
    };
    if size < header_size {
        return Err(error(format!(
            "Invalid section size 0x{size:X} at {}",
            stream.place(pos)
        )));
    }
    if size > bytes.len() - pos {
        return Err(error(format!(
            "Truncated section at {}: {size} B declared, {} B left",
            stream.place(pos),
            bytes.len() - pos
        )));
    }
    Ok(SectionHeader {
        section_type,
        header_size,
        size,
    })
}

/// Whether `rest` starts with fill rather than a header: four equal bytes
/// of `0x00` or `0xFF` (a size of 0 is invalid, and `0xFFFFFFFF` would
/// name the undefined type `0xFF`), or fewer than four bytes.
fn starts_with_fill(rest: &[u8]) -> bool {
    let head = &rest[..rest.len().min(SECTION_HEADER_SIZE)];
    head.len() < SECTION_HEADER_SIZE || (is_padding(head) && head.iter().all(|&b| b == head[0]))
}

/// Whether `bytes` is a complete section stream of defined section types,
/// optionally followed by fill. Used to tell sectioned from raw data and
/// to check a decoder's output.
pub(super) fn is_section_stream(bytes: &[u8]) -> bool {
    let stream = Stream::Stored { bytes, base: 0 };
    let mut pos = 0;
    while pos < bytes.len() {
        let rest = &bytes[pos..];
        if starts_with_fill(rest) {
            return is_padding(rest);
        }
        let Ok(header) = section_header(&stream, pos) else {
            return false;
        };
        if !DEFINED_SECTION_TYPES.contains(&header.section_type) {
            return false;
        }
        let Ok(next) = align_up(pos + header.size, SECTION_ALIGNMENT) else {
            return false;
        };
        pos = next;
    }
    true
}

/// Walk the section stream `stream` of `file`.
pub(super) fn walk_sections<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    stream: Stream<'a, '_>,
    depth: usize,
) -> Result<()> {
    if depth > fv::MAX_DEPTH {
        budget.note(
            c,
            format!(
                "Sections at {} are nested deeper than {} levels; not walked",
                stream.place(0),
                fv::MAX_DEPTH
            ),
        );
        return Ok(());
    }
    let bytes = stream.bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let rest = &bytes[pos..];
        if starts_with_fill(rest) {
            // Alignment padding or erased bytes after the last section.
            if is_padding(rest) {
                break;
            }
            return Err(error(format!(
                "Invalid section header at {}",
                stream.place(pos)
            )));
        }
        let header = section_header(&stream, pos)?;
        let section = stream.sub(pos, pos + header.size)?;
        walk_section(c, budget, file, section, &header, depth)?;
        pos = align_up(pos + header.size, SECTION_ALIGNMENT)?;
    }
    Ok(())
}

/// Handle one section; `section` covers it, header included.
fn walk_section<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    section: Stream<'a, '_>,
    header: &SectionHeader,
    depth: usize,
) -> Result<()> {
    let body = section.sub(header.header_size, header.size)?;
    match header.section_type {
        EFI_SECTION_COMPRESSION => compression(c, budget, file, section, header, depth)?,
        EFI_SECTION_GUID_DEFINED => guid_defined(c, budget, file, section, header, depth)?,
        EFI_SECTION_PE32 => file.push_leaf(c, budget, "PE32 image", body, Leaf::Image(None)),
        EFI_SECTION_PIC => file.push_leaf(c, budget, "PIC image", body, Leaf::Image(None)),
        EFI_SECTION_TE => {
            // The TE machine field names the ISA even when the rest of the
            // image does not validate.
            let target = te::target(body.bytes());
            file.push_leaf(c, budget, "TE image", body, Leaf::Image(target));
        }
        EFI_SECTION_COMPATIBILITY16 => {
            // PI 1.8 Vol. 3, 3.2.5.4: "an IA-32 16-bit executable image", a
            // documented role; the bytes carry no header or machine field.
            let target = Target::new(Isa::X86, 16, Endianness::Little);
            file.push_leaf(c, budget, "16-bit x86 image", body, Leaf::Code(target));
        }
        EFI_SECTION_FIRMWARE_VOLUME_IMAGE => {
            fv::walk_volume(c, budget, body, depth + 1)?;
        }
        EFI_SECTION_FREEFORM_SUBTYPE_GUID => {
            let length = body.bytes().len();
            if length < SUBTYPE_GUID_SIZE {
                return Err(error(format!(
                    "Truncated freeform subtype section at {}",
                    section.place(0)
                )));
            }
            let data = body.sub(SUBTYPE_GUID_SIZE, length)?;
            raw_data(c, budget, file, data, "freeform data", depth)?;
        }
        EFI_SECTION_RAW => raw_data(c, budget, file, body, "raw section", depth)?,
        EFI_SECTION_USER_INTERFACE => file.ui_name = ucs2_name(body.bytes()),
        // Dependency expressions, versions, POST codes and discardable data
        // hold no images.
        EFI_SECTION_DISPOSABLE
        | EFI_SECTION_DXE_DEPEX
        | EFI_SECTION_VERSION
        | EFI_SECTION_PEI_DEPEX
        | EFI_SECTION_MM_DEPEX
        | INSYDE_SECTION_POSTCODE
        | PHOENIX_SECTION_POSTCODE => {}
        other => budget.note(
            c,
            format!(
                "Section type 0x{other:02X} at {} is not defined by PI 1.8; not interpreted",
                section.place(0)
            ),
        ),
    }
    Ok(())
}

/// Raw bytes (RAW files, RAW and freeform sections): a firmware volume is
/// walked in place; anything else is listed when it is a recognized
/// format.
pub(super) fn raw_data<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    data: Stream<'a, '_>,
    kind: &'static str,
    depth: usize,
) -> Result<()> {
    if fv::header(data.bytes(), "").is_ok() {
        fv::walk_volume(c, budget, data, depth + 1)?;
    } else if data.is_listable() {
        file.push_leaf(c, budget, kind, data, Leaf::Member);
    }
    Ok(())
}

/// The NUL-terminated UCS-2 name of a `USER_INTERFACE` section.
fn ucs2_name(bytes: &[u8]) -> Option<String> {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .take(MAX_NAME_UNITS);
    let name: String = char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .filter(|ch| !ch.is_control())
        .collect();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// `EFI_SECTION_COMPRESSION`: stored (type 0) or EFI standard compression
/// (type 1), whose output is a section stream.
fn compression<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    section: Stream<'a, '_>,
    header: &SectionHeader,
    depth: usize,
) -> Result<()> {
    let place = section.place(0);
    let fields = slice(section.bytes(), header.header_size, COMPRESSION_FIELDS_SIZE)
        .map_err(|_| error(format!("Truncated compression section header at {place}")))?;
    let uncompressed_length = to_usize(le_u32(fields, 0)?, "uncompressed length")?;
    let compression_type = fields[4];
    let payload = section.sub(header.header_size + COMPRESSION_FIELDS_SIZE, header.size)?;
    match compression_type {
        EFI_NOT_COMPRESSED => {
            // EDK2 copies `UncompressedLength` bytes without checking them
            // against the section.
            if uncompressed_length > payload.bytes().len() {
                return Err(error(format!(
                    "Invalid compression section at {place}: UncompressedLength {uncompressed_length} B exceeds the {} B stored",
                    payload.bytes().len()
                )));
            }
            walk_sections(
                c,
                budget,
                file,
                payload.sub(0, uncompressed_length)?,
                depth + 1,
            )
        }
        EFI_STANDARD_COMPRESSION => {
            standard_compression(c, budget, file, section, header, uncompressed_length, depth)
        }
        other => {
            budget.note(
                c,
                format!(
                    "Compression section at {place} uses unsupported type 0x{other:02X}; opaque"
                ),
            );
            file.push_leaf(c, budget, "compressed section", payload, Leaf::Opaque);
            Ok(())
        }
    }
}

/// Decode `payload` with `codec` into exactly `expected` bytes that form a
/// section stream.
fn decode_section_stream(codec: Codec, payload: &[u8], expected: usize) -> Result<Vec<u8>> {
    let decoded =
        compressed::decode_limited(codec, payload, expected).map_err(|e| error(bare_message(e)))?;
    if decoded.data.len() != expected {
        return Err(error(format!(
            "{} original size {} B differs from UncompressedLength {expected} B",
            codec.name(),
            decoded.data.len()
        )));
    }
    if !is_section_stream(&decoded.data) {
        return Err(error(format!(
            "{} output is not a section stream",
            codec.name()
        )));
    }
    Ok(decoded.data)
}

/// Compression type 1 names EFI 1.1 compression (`mPBit` 4), but some
/// vendor images store Tiano data (`mPBit` 5) under it. Both decoders are
/// tried, as `UEFITool` does; the variant whose output is a section stream
/// of the declared length is used, and two different valid outputs are
/// ambiguous.
fn standard_compression<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    section: Stream<'a, '_>,
    header: &SectionHeader,
    uncompressed_length: usize,
    depth: usize,
) -> Result<()> {
    let place = section.place(0);
    let payload = section.sub(header.header_size + COMPRESSION_FIELDS_SIZE, header.size)?;
    if uncompressed_length > budget.remaining() {
        budget.undecoded += 1;
        return Ok(());
    }
    let efi = decode_section_stream(Codec::Efi, payload.bytes(), uncompressed_length);
    let tiano = decode_section_stream(Codec::Tiano, payload.bytes(), uncompressed_length);
    let (codec, decoded) = match (efi, tiano) {
        (Ok(efi), Ok(tiano)) if efi == tiano => (Codec::Efi, efi),
        (Ok(_), Ok(_)) => {
            budget.note(
                c,
                format!("Ambiguous compression section at {place}: EFI and Tiano decoding both yield section streams; opaque"),
            );
            file.push_leaf(c, budget, "compressed section", payload, Leaf::Opaque);
            return Ok(());
        }
        (Ok(efi), Err(_)) => (Codec::Efi, efi),
        (Err(_), Ok(tiano)) => {
            budget.note(
                c,
                format!("Compression section at {place}: type 1 (EFI) holds Tiano data; inferred because only the Tiano decoder yields a section stream"),
            );
            (Codec::Tiano, tiano)
        }
        (Err(efi), Err(_)) => {
            return Err(error(format!(
                "Invalid compression section at {place}: {}",
                bare_message(efi)
            )));
        }
    };
    budget.extracted += decoded.len();
    let inner = section.decoded(0, header.size, codec.name(), &decoded);
    walk_sections(c, budget, file, inner, depth + 1)
}

/// `EFI_SECTION_GUID_DEFINED`: the GUID names how the data at `DataOffset`
/// becomes a section stream.
fn guid_defined<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    section: Stream<'a, '_>,
    header: &SectionHeader,
    depth: usize,
) -> Result<()> {
    let place = section.place(0);
    let fields = slice(
        section.bytes(),
        header.header_size,
        GUID_DEFINED_FIELDS_SIZE,
    )
    .map_err(|_| error(format!("Truncated GUID-defined section header at {place}")))?;
    let guid = Guid::read(fields, 0)?;
    let data_offset = usize::from(le_u16(fields, 16)?);
    let attributes = le_u16(fields, 18)?;
    let fields_end = header.header_size + GUID_DEFINED_FIELDS_SIZE;
    if data_offset < fields_end || data_offset > header.size {
        return Err(error(format!(
            "Invalid GUID-defined section DataOffset 0x{data_offset:X} at {place}"
        )));
    }
    let payload = section.sub(data_offset, header.size)?;
    let encapsulation = Encapsulation {
        section,
        size: header.size,
        payload,
        depth,
    };
    let stored = payload.bytes();
    match guid {
        LZMA_CUSTOM_DECOMPRESS_GUID => {
            let declared = lzma_size(stored);
            decode_and_walk(
                c,
                budget,
                file,
                &encapsulation,
                Codec::Lzma,
                stored,
                declared,
            )
        }
        LZMA_F86_CUSTOM_DECOMPRESS_GUID => {
            let declared = lzma_size(stored);
            decode_and_walk(
                c,
                budget,
                file,
                &encapsulation,
                Codec::LzmaX86,
                stored,
                declared,
            )
        }
        TIANO_CUSTOM_DECOMPRESS_GUID => {
            let declared = le_u32(stored, EFI_ORIGINAL_SIZE_OFFSET)
                .ok()
                .and_then(|size| usize::try_from(size).ok());
            decode_and_walk(
                c,
                budget,
                file,
                &encapsulation,
                Codec::Tiano,
                stored,
                declared,
            )
        }
        BROTLI_CUSTOM_DECOMPRESS_GUID => brotli(c, budget, file, &encapsulation),
        CRC32_GUIDED_SECTION_EXTRACTION_GUID => {
            crc32(c, budget, file, &encapsulation, fields_end, data_offset)
        }
        FIRMWARE_CONTENTS_SIGNED_GUID => {
            // The certificate sits in the GUID-specific fields; the data is
            // signed, not transformed.
            budget.note(
                c,
                format!("Signed section at {place}: signature not verified"),
            );
            walk_sections(c, budget, file, payload, depth + 1)
        }
        // Without the processing flag the data is a plain section stream.
        _ if attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED == 0 => {
            walk_sections(c, budget, file, payload, depth + 1)
        }
        _ => {
            budget.note(
                c,
                format!("GUID-defined section {guid} at {place} needs an extractor that is not supported; opaque"),
            );
            file.push_leaf(c, budget, "GUID-defined section", payload, Leaf::Opaque);
            Ok(())
        }
    }
}

/// A GUID-defined section and the data at its `DataOffset`.
struct Encapsulation<'a, 'b> {
    /// The whole section, header included.
    section: Stream<'a, 'b>,
    size: usize,
    payload: Stream<'a, 'b>,
    depth: usize,
}

/// The decoded size an LZMA-alone header declares, when known.
fn lzma_size(payload: &[u8]) -> Option<usize> {
    le_u64(payload, LZMA_SIZE_OFFSET)
        .ok()
        .filter(|size| *size != LZMA_SIZE_UNKNOWN)
        .and_then(|size| usize::try_from(size).ok())
}

/// Decode `stored` with `codec` (exactly `declared` bytes when the stream
/// states its size) and walk the output as a section stream.
fn decode_and_walk<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    encapsulation: &Encapsulation<'a, '_>,
    codec: Codec,
    stored: &[u8],
    declared: Option<usize>,
) -> Result<()> {
    let place = encapsulation.section.place(0);
    let available = budget.remaining();
    let limit = match declared {
        Some(size) if size > available => {
            budget.undecoded += 1;
            return Ok(());
        }
        Some(size) => size,
        None => available,
    };
    let decoded = compressed::decode_limited(codec, stored, limit).map_err(|e| {
        error(format!(
            "Invalid {} GUID-defined section at {place}: {}",
            codec.name(),
            bare_message(e)
        ))
    })?;
    if let Some(size) = declared {
        if decoded.data.len() != size {
            return Err(error(format!(
                "Invalid {} GUID-defined section at {place}: {} B decoded, {size} B declared",
                codec.name(),
                decoded.data.len()
            )));
        }
    }
    budget.extracted += decoded.data.len();
    let inner = encapsulation
        .section
        .decoded(0, encapsulation.size, codec.name(), &decoded.data);
    walk_sections(c, budget, file, inner, encapsulation.depth + 1)
}

/// EDK2 Brotli sections: a 16-byte prefix with the decoded size (u64) and
/// the scratch size (u64, unused here), then the Brotli stream.
fn brotli<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    encapsulation: &Encapsulation<'a, '_>,
) -> Result<()> {
    let payload = encapsulation.payload.bytes();
    let place = encapsulation.section.place(0);
    let stored = payload
        .get(BROTLI_HEADER_SIZE..)
        .ok_or_else(|| error(format!("Truncated Brotli section header at {place}")))?;
    let decoded_size = le_u64(payload, 0)?;
    // A size beyond the address space is above every limit.
    let declared = usize::try_from(decoded_size).unwrap_or(usize::MAX);
    decode_and_walk(
        c,
        budget,
        file,
        encapsulation,
        Codec::Brotli,
        stored,
        Some(declared),
    )
}

/// CRC32 GUID-defined sections: the CRC-32 after the GUID-defined fields
/// covers the stored section stream at `DataOffset`, which is verified and
/// then walked.
fn crc32<'a>(
    c: &mut Container<'a>,
    budget: &mut Budget,
    file: &mut FileContext,
    encapsulation: &Encapsulation<'a, '_>,
    fields_end: usize,
    data_offset: usize,
) -> Result<()> {
    let place = encapsulation.section.place(0);
    if data_offset < fields_end + CRC32_FIELD_SIZE {
        return Err(error(format!(
            "Invalid CRC32 GUID-defined section at {place}: DataOffset 0x{data_offset:X} leaves no room for the CRC"
        )));
    }
    let stored = le_u32(encapsulation.section.bytes(), fields_end)?;
    let computed = checksum::crc32(encapsulation.payload.bytes());
    if stored != computed {
        return Err(error(format!(
            "Invalid CRC32 GUID-defined section at {place}: stored 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    budget.crc_verified += 1;
    walk_sections(
        c,
        budget,
        file,
        encapsulation.payload,
        encapsulation.depth + 1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section: 24-bit size including the 4-byte header, type, body.
    fn section(section_type: u8, body: &[u8]) -> Vec<u8> {
        let size = u32::try_from(body.len() + SECTION_HEADER_SIZE).expect("small section");
        let mut out = size.to_le_bytes()[..3].to_vec();
        out.push(section_type);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn section_streams_need_defined_types_and_aligned_sizes() {
        let mut stream = section(EFI_SECTION_RAW, b"abc");
        stream.push(0);
        stream.extend(section(EFI_SECTION_USER_INTERFACE, b"A\0\0\0"));
        assert!(is_section_stream(&stream));
        assert!(is_section_stream(&[]));
        assert!(!is_section_stream(&section(0x1A, b"x")));
        assert!(!is_section_stream(&[0x02, 0, 0, EFI_SECTION_RAW]));
        let mut padded = section(EFI_SECTION_RAW, b"abcd");
        padded.extend_from_slice(&[0xFF; 12]);
        assert!(is_section_stream(&padded));
    }

    #[test]
    fn ui_names_stop_at_the_terminator() {
        assert_eq!(
            ucs2_name(&[b'S', 0, b'h', 0, 0, 0, b'x', 0]).as_deref(),
            Some("Sh")
        );
        assert_eq!(ucs2_name(&[0, 0]), None);
    }
}
