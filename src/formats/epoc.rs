//! Symbian OS E32 image files: the executables (`.exe`), libraries (`.dll`,
//! `.app`) and device drivers (`.ldd`, `.pdd`) that the Symbian loader runs,
//! called EPOC images after the `EPOC` signature in their header.
//!
//! Sources (line numbers, retrieval and the assumption register in
//! `docs/epoc.md`):
//! - Symbian Foundation `kernelhwsrv` (EPL 1.0), commit
//!   `0c3208650587ac0230aed8a74e9bddb5288023eb`:
//!   `userlibandfileserver/fileserver/inc/f32image.h` (`TCpu`,
//!   `KImageCrcInitialiser`, the `iFlags` bits, `E32ImageHeader`,
//!   `E32ImageHeaderComp`, `E32ImageHeaderV` and
//!   `E32ImageHeaderV::ValidateHeader`), `kernel/eka/euser/us_func.cpp`
//!   (`TCheckedUid::Check`, `Mem::Crc`, `Mem::Crc32`),
//!   `kernel/eka/include/e32ldr_private.h` (compression UIDs),
//!   `kernel/eka/include/e32uid.h` (UID1 values) and
//!   `userlibandfileserver/fileserver/sfile/sf_deflate.h` (the loader's own
//!   deflate coding).
//! - Symbian Foundation `rndtools` (EPL 1.0), commit
//!   `29f348bac14c2472f9a0e371ca2b4493b7bb2974`,
//!   `launcher/inc/e32imageheaders.h`: the accessors for the header formats
//!   used before Symbian OS 8.1b (`HdrFmtFromFlags`, `CpuIdentifier`,
//!   `CompressionType`, `TotalSize`, `KImageOldJFlag`, `KImageOldElfFlag`).
//! - Symbian Foundation Carbide.c++ (EPL 1.0), commit
//!   `4420f338bc4e522c563f8899d81201857236a66a`,
//!   `SymbianE32BinaryObject.java`: the field order of the original (EKA1)
//!   header (`iCpu`, `iCheckSumCode`, `iCheckSumData`).
//!
//! Every header field is little-endian. The first 0x7C bytes are shared by
//! the three header formats that `iFlags` at 0x2C selects. The V format
//! (every executable since Symbian OS 8.1b) has the header CRC at 0x14, the
//! compression type at 0x1C and the CPU at 0x7A, followed by the
//! uncompressed size and the security information up to at least 0x9C. The
//! J and original formats have the CPU at 0x14; only J has a compression
//! type. The CPU identifier names the ISA. Code and data are byte ranges at
//! file offsets; `iCodeBase` and `iDataBase` are their link addresses.
//! Compressed contents (the loader's own deflate coding or byte-pair) are
//! opaque: no codec of this classifier decodes them.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Section, Target};
use crate::formats::sis::{uid_checksum, UIDS_SIZE};
use crate::formats::{checksum, MAX_PAYLOAD};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa, MetadataValue};
use std::borrow::Cow;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "epoc";

/// Variant of an image whose CPU identifier names no known CPU.
const LABEL: &str = "Symbian E32 image";

/// `iSignature`, which "Contains 'EPOC'" (`ValidateHeader` compares it with
/// 0x434F5045).
const SIGNATURE: [u8; 4] = *b"EPOC";

/// `iSignature` read as a little-endian word.
pub const EPOC_MARKER_LE: u32 = 0x434F_5045;

/// `sizeof(E32ImageHeader)`: the fields every header format shares.
const BASE_HEADER_SIZE: usize = 0x7C;
/// `sizeof(E32ImageHeaderComp)`: where the compressed contents of a J image
/// start (`TotalSize` in `e32imageheaders.h`).
const COMP_HEADER_SIZE: usize = 0x80;
/// `sizeof(E32ImageHeaderV)`, the smallest V header.
const V_HEADER_SIZE: usize = 0x9C;

// `E32ImageHeader` fields.
const UID1: usize = 0x00;
const UID2: usize = 0x04;
const UID3: usize = 0x08;
const UID_CHECKSUM: usize = 0x0C;
const SIGNATURE_OFFSET: usize = 0x10;
/// `iHeaderCrc` in the V format; `iCpu` in the J and original formats.
const HEADER_CRC: usize = 0x14;
/// `iModuleVersion` in the V format; `iCheckSumCode` in the original
/// format.
const MODULE_VERSION: usize = 0x18;
/// `iCompressionType` in the J and V formats; `iCheckSumData` in the
/// original format.
const COMPRESSION_TYPE: usize = 0x1C;
/// `iToolsVersion` (`iVersion` in the original format): a `TVersion`.
const TOOLS_VERSION: usize = 0x20;
const FLAGS: usize = 0x2C;
const CODE_SIZE: usize = 0x30;
const DATA_SIZE: usize = 0x34;
const BSS_SIZE: usize = 0x44;
const ENTRY_POINT: usize = 0x48;
const CODE_BASE: usize = 0x4C;
const DATA_BASE: usize = 0x50;
const TEXT_SIZE: usize = 0x60;
/// `iCodeOffset`, "Also doubles the as header size".
const CODE_OFFSET: usize = 0x64;
const DATA_OFFSET: usize = 0x68;
/// `iCpuIdentifier`, a 16-bit field of the V format.
const CPU_IDENTIFIER: usize = 0x7A;

// `E32ImageHeaderComp` and `E32ImageHeaderV` fields.
const UNCOMPRESSED_SIZE: usize = 0x7C;
const SECURE_ID: usize = 0x80;
const VENDOR_ID: usize = 0x84;
/// `iS.iCaps`: two 32-bit words, the low word first.
const CAPABILITIES: usize = 0x88;
/// `iExportDescSize`, a 16-bit field.
const EXPORT_DESC_SIZE: usize = 0x98;
/// `iExportDescType`, a byte.
const EXPORT_DESC_TYPE: usize = 0x9A;
/// `iExportDescSize` and `iExportDescType` precede the export description,
/// which the V header ends with, padded to 4 bytes
/// (`ValidateExportDescription`).
const EXPORT_DESC_FIELDS: usize = 3;
const HEADER_ALIGNMENT: usize = 4;

/// Value of `iHeaderCrc` while the header CRC is computed.
const IMAGE_CRC_INITIALISER: u32 = 0xC90F_DAA2;

// `iFlags` bits (`f32image.h`; the two old flags from `e32imageheaders.h`).
const IMAGE_DLL: u32 = 0x0000_0001;
/// J format for images built with tools before 2.00, whose header format
/// bits are 0.
const IMAGE_OLD_J_FLAG: u32 = 0x0000_0008;
/// ELF-derived imports and the EABI for images built with tools before
/// 2.00.
const IMAGE_OLD_ELF_FLAG: u32 = 0x0000_0010;
const IMAGE_ABI_MASK: u32 = 0x0000_0018;
const IMAGE_ABI_GCC98R2: u32 = 0x0000_0000;
const IMAGE_ABI_EABI: u32 = 0x0000_0008;
const IMAGE_EPT_MASK: u32 = 0x0000_00E0;
const IMAGE_EPT_EKA1: u32 = 0x0000_0000;
const IMAGE_EPT_EKA2: u32 = 0x0000_0020;
const IMAGE_HW_FLOAT_MASK: u32 = 0x00F0_0000;
const IMAGE_HW_FLOAT_SHIFT: u32 = 20;
const IMAGE_HDR_FMT_MASK: u32 = 0x0F00_0000;
const IMAGE_HDR_FMT_J: u32 = 0x0100_0000;
const IMAGE_HDR_FMT_V: u32 = 0x0200_0000;
const IMAGE_IMP_FMT_MASK: u32 = 0xF000_0000;
const IMAGE_IMP_FMT_PE: u32 = 0x0000_0000;
const IMAGE_IMP_FMT_ELF: u32 = 0x1000_0000;
const IMAGE_IMP_FMT_PE2: u32 = 0x2000_0000;

// `TFloatingPointType` (`e32const.h`), in the hardware floating-point bits.
const FP_TYPE_NONE: u32 = 0;
const FP_TYPE_VFPV2: u32 = 1;
const FP_TYPE_VFPV3: u32 = 2;
const FP_TYPE_VFPV3_D16: u32 = 3;

// `TCpu` values.
const CPU_UNKNOWN: u32 = 0x0000;
const CPU_X86: u32 = 0x1000;
const CPU_ARM_V4: u32 = 0x2000;
const CPU_ARM_V5: u32 = 0x2001;
const CPU_ARM_V6: u32 = 0x2002;
const CPU_MCORE: u32 = 0x4000;

// `iCompressionType` values (`e32ldr_private.h`).
const FORMAT_NOT_COMPRESSED: u32 = 0;
const UID_COMPRESSION_DEFLATE: u32 = 0x101F_7AFC;
const UID_COMPRESSION_BYTE_PAIR: u32 = 0x1028_22AA;

// UID1 values (`e32uid.h`).
const DYNAMIC_LIBRARY_UID: u32 = 0x1000_0079;
const EXECUTABLE_IMAGE_UID: u32 = 0x1000_007A;

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::EpocParseError {
        message: message.into(),
    }
}

/// Strong recognition: the `EPOC` signature (`iSignature`) at 0x10, which
/// every E32 image header format carries. The rest of the header is checked
/// by the parser, so a damaged image is a parse error. Files without the
/// signature are not E32 images: the loader rejects them (`ValidateHeader`).
pub fn detect(data: &[u8]) -> bool {
    data.get(SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE.len()) == Some(SIGNATURE.as_slice())
}

/// Parse an E32 image into its classification.
///
/// # Errors
///
/// As [`parse_container`].
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    Ok(parse_container(data)?.classification())
}

/// Parse an E32 image: the CPU identifier as the target, the code and data
/// parts as sections, or compressed contents as an opaque component.
///
/// # Errors
///
/// [`ClassifierError::EpocParseError`] when the header is truncated, lacks
/// the signature or has an undefined header format, when its size, the
/// export description, the text size or the entry point are inconsistent,
/// or when the code or data part lies outside the image.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    let header = Header::read(data)?;
    let stored_header_size = header.stored_header_size(data.len())?;
    header.check_code_fields()?;
    let cpu = Cpu::from_id(header.cpu_id);
    let mut c = Container::new(FileFormat::Epoc, cpu.variant().unwrap_or(LABEL), KEY_PREFIX);
    c.target = cpu.target();
    c.code_sections = true;
    c.consumed = data.len();
    c.entry = Some(u64::from(header.code_base) + u64::from(header.entry_point));
    push_header_notes(&mut c, &header, cpu, &data[..stored_header_size]);
    match header.compression() {
        Compression::None => load_sections(&mut c, data, &header)?,
        compression => load_compressed(&mut c, data, &header, compression, stored_header_size)?,
    }
    c.notes
        .push("Import, export and relocation sections are not parsed".into());
    push_metadata(&mut c, &header, cpu);
    Ok(c)
}

/// The header format that `iFlags` selects (`HdrFmtFromFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderFormat {
    /// `KImageHdrFmt_Original` (EKA1): CPU at 0x14, code and data checksums
    /// at 0x18 and 0x1C, no compression.
    Original,
    /// `KImageHdrFmt_J`: CPU at 0x14, compression type at 0x1C.
    J,
    /// `KImageHdrFmt_V`: header CRC at 0x14, module version at 0x18,
    /// compression type at 0x1C, CPU at 0x7A and the `E32ImageHeaderV`
    /// fields.
    V,
}

impl HeaderFormat {
    /// The header format bits when they are set; otherwise J when the old J
    /// flag is set, else the original format.
    fn from_flags(flags: u32) -> Result<Self> {
        match flags & IMAGE_HDR_FMT_MASK {
            0 if flags & IMAGE_OLD_J_FLAG != 0 => Ok(Self::J),
            0 => Ok(Self::Original),
            IMAGE_HDR_FMT_J => Ok(Self::J),
            IMAGE_HDR_FMT_V => Ok(Self::V),
            other => Err(error(format!(
                "Unsupported E32 header format 0x{other:08X} in iFlags 0x{flags:08X} at 0x{FLAGS:X}"
            ))),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::J => "J",
            Self::V => "V",
        }
    }

    /// The smallest header (`iCodeOffset`) of this format.
    fn min_size(self) -> usize {
        match self {
            Self::Original | Self::J => BASE_HEADER_SIZE,
            Self::V => V_HEADER_SIZE,
        }
    }
}

/// The `E32ImageHeaderV` fields after `E32ImageHeader`.
#[derive(Debug)]
struct VFields {
    /// "Uncompressed size of file data after the header", in bytes.
    uncompressed_size: u32,
    secure_id: u32,
    vendor_id: u32,
    capabilities: u64,
    export_desc_size: u16,
    export_desc_type: u8,
}

/// The header fields this parser uses.
#[derive(Debug)]
struct Header {
    format: HeaderFormat,
    uids: [u8; UIDS_SIZE],
    uid_checksum: u32,
    /// `iCpuIdentifier` (V) or `iCpu` (J, original).
    cpu_id: u32,
    /// `iHeaderCrc`, V only.
    stored_crc: Option<u32>,
    /// The word at 0x18: `iModuleVersion` (V) or `iCheckSumCode`
    /// (original); not interpreted for J.
    word_18: u32,
    /// The word at 0x1C: `iCompressionType` (J, V) or `iCheckSumData`
    /// (original).
    word_1c: u32,
    tools_version: Version,
    flags: u32,
    /// Bytes of the code part: text, import address table, constants and
    /// export directory.
    code_size: u32,
    /// Bytes of initialised data.
    data_size: u32,
    /// Bytes of uninitialised data.
    bss_size: u32,
    /// Offset of the entry point into the code part.
    entry_point: u32,
    /// Link address of the code part.
    code_base: u32,
    /// Link address of the data part.
    data_base: u32,
    /// Bytes of the text section at the start of the code part.
    text_size: u32,
    /// File offset of the code part; also the header size.
    code_offset: u32,
    /// File offset of the data part, 0 when there is none.
    data_offset: u32,
    v: Option<VFields>,
}

impl Header {
    /// Read the header: the 0x7C shared bytes, the signature and the header
    /// format, then the format's own fields.
    fn read(data: &[u8]) -> Result<Self> {
        if data.len() < BASE_HEADER_SIZE {
            return Err(error(format!(
                "Truncated E32 image header: {} B of {BASE_HEADER_SIZE} B",
                data.len()
            )));
        }
        if data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE.len()] != SIGNATURE {
            return Err(error(format!(
                "Missing E32 signature EPOC at 0x{SIGNATURE_OFFSET:X}"
            )));
        }
        let flags = le_u32(data, FLAGS)?;
        let format = HeaderFormat::from_flags(flags)?;
        if format == HeaderFormat::V && data.len() < V_HEADER_SIZE {
            return Err(error(format!(
                "Truncated E32 V header: {} B of {V_HEADER_SIZE} B",
                data.len()
            )));
        }
        let is_v = format == HeaderFormat::V;
        let cpu_id = if is_v {
            u32::from(le_u16(data, CPU_IDENTIFIER)?)
        } else {
            le_u32(data, HEADER_CRC)?
        };
        let stored_crc = if is_v {
            Some(le_u32(data, HEADER_CRC)?)
        } else {
            None
        };
        let v = if is_v {
            Some(VFields::read(data)?)
        } else {
            None
        };
        let uids = data[UID1..UID1 + UIDS_SIZE]
            .try_into()
            .expect("the header holds the three UIDs");
        Ok(Self {
            format,
            uids,
            uid_checksum: le_u32(data, UID_CHECKSUM)?,
            cpu_id,
            stored_crc,
            word_18: le_u32(data, MODULE_VERSION)?,
            word_1c: le_u32(data, COMPRESSION_TYPE)?,
            tools_version: Version::read(data, TOOLS_VERSION)?,
            flags,
            code_size: le_u32(data, CODE_SIZE)?,
            data_size: le_u32(data, DATA_SIZE)?,
            bss_size: le_u32(data, BSS_SIZE)?,
            entry_point: le_u32(data, ENTRY_POINT)?,
            code_base: le_u32(data, CODE_BASE)?,
            data_base: le_u32(data, DATA_BASE)?,
            text_size: le_u32(data, TEXT_SIZE)?,
            code_offset: le_u32(data, CODE_OFFSET)?,
            data_offset: le_u32(data, DATA_OFFSET)?,
            v,
        })
    }

    fn uid(&self, at: usize) -> u32 {
        le_u32(&self.uids, at).expect("the UIDs hold three words")
    }

    /// `CompressionType`: the compression type of the J and V formats; the
    /// original format has none.
    fn compression(&self) -> Compression {
        if self.format == HeaderFormat::Original {
            Compression::None
        } else {
            Compression::from_type(self.word_1c)
        }
    }

    /// The bytes before the stored contents (`TotalSize`):
    /// `sizeof(E32ImageHeaderComp)` for a compressed J image, else
    /// `iCodeOffset`, which must hold the format's header (and, for V, end
    /// with the export description) and lie inside the file.
    fn stored_header_size(&self, file_size: usize) -> Result<usize> {
        let header_size = to_usize(self.code_offset);
        let min = self.format.min_size();
        if header_size < min {
            return Err(error(format!(
                "Invalid E32 header size 0x{header_size:X} (iCodeOffset at 0x{CODE_OFFSET:X}): \
                 less than the {min} B {} header",
                self.format.label()
            )));
        }
        if let Some(v) = &self.v {
            let end = EXPORT_DESC_SIZE
                + round_up(
                    usize::from(v.export_desc_size) + EXPORT_DESC_FIELDS,
                    HEADER_ALIGNMENT,
                );
            if end != header_size {
                return Err(error(format!(
                    "Invalid E32 export description: {} B end the header at 0x{end:X}, but \
                     iCodeOffset is 0x{header_size:X}",
                    v.export_desc_size
                )));
            }
        }
        let stored = if self.format == HeaderFormat::J && self.compression() != Compression::None {
            COMP_HEADER_SIZE
        } else {
            header_size
        };
        if stored > file_size {
            return Err(error(format!(
                "Truncated E32 image header: {stored} B in the {file_size} B file"
            )));
        }
        Ok(stored)
    }

    /// The text section and the entry point lie inside the code part.
    fn check_code_fields(&self) -> Result<()> {
        if self.text_size > self.code_size {
            return Err(error(format!(
                "Invalid E32 text size {} B: exceeds the {} B code part",
                self.text_size, self.code_size
            )));
        }
        if self.entry_point >= self.code_size {
            return Err(error(format!(
                "Invalid E32 entry point offset 0x{:X}: outside the {} B code part",
                self.entry_point, self.code_size
            )));
        }
        Ok(())
    }

    fn is_dll(&self) -> bool {
        self.flags & IMAGE_DLL != 0
    }

    /// Whether the header format bits are set; the ABI, entry point and
    /// import format bits are only defined then.
    fn has_format_bits(&self) -> bool {
        self.flags & IMAGE_HDR_FMT_MASK != 0
    }
}

impl VFields {
    fn read(data: &[u8]) -> Result<Self> {
        let caps_low = le_u32(data, CAPABILITIES)?;
        let caps_high = le_u32(data, CAPABILITIES + 4)?;
        Ok(Self {
            uncompressed_size: le_u32(data, UNCOMPRESSED_SIZE)?,
            secure_id: le_u32(data, SECURE_ID)?,
            vendor_id: le_u32(data, VENDOR_ID)?,
            capabilities: (u64::from(caps_high) << 32) | u64::from(caps_low),
            export_desc_size: le_u16(data, EXPORT_DESC_SIZE)?,
            export_desc_type: data
                .get(EXPORT_DESC_TYPE)
                .copied()
                .ok_or_else(|| truncated_at(EXPORT_DESC_TYPE))?,
        })
    }
}

/// A `TVersion`: signed 8-bit major and minor numbers and a 16-bit build.
#[derive(Debug, Clone, Copy)]
struct Version {
    major: i8,
    minor: i8,
    build: i16,
}

impl Version {
    fn read(data: &[u8], at: usize) -> Result<Self> {
        let bytes: [u8; 4] = data
            .get(at..at + 4)
            .ok_or_else(|| truncated_at(at))?
            .try_into()
            .expect("slice has 4 bytes");
        Ok(Self {
            major: i8::from_le_bytes([bytes[0]]),
            minor: i8::from_le_bytes([bytes[1]]),
            build: i16::from_le_bytes([bytes[2], bytes[3]]),
        })
    }
}

/// A `TCpu` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cpu {
    Unknown,
    X86,
    ArmV4,
    ArmV5,
    ArmV6,
    MCore,
    /// A value `TCpu` does not define.
    Undefined(u32),
}

impl Cpu {
    fn from_id(id: u32) -> Self {
        match id {
            CPU_UNKNOWN => Self::Unknown,
            CPU_X86 => Self::X86,
            CPU_ARM_V4 => Self::ArmV4,
            CPU_ARM_V5 => Self::ArmV5,
            CPU_ARM_V6 => Self::ArmV6,
            CPU_MCORE => Self::MCore,
            other => Self::Undefined(other),
        }
    }

    /// The `TCpu` enumerator.
    fn name(self) -> Option<&'static str> {
        match self {
            Self::Unknown => Some("ECpuUnknown"),
            Self::X86 => Some("ECpuX86"),
            Self::ArmV4 => Some("ECpuArmV4"),
            Self::ArmV5 => Some("ECpuArmV5"),
            Self::ArmV6 => Some("ECpuArmV6"),
            Self::MCore => Some("ECpuMCore"),
            Self::Undefined(_) => None,
        }
    }

    fn id(self) -> u32 {
        match self {
            Self::Unknown => CPU_UNKNOWN,
            Self::X86 => CPU_X86,
            Self::ArmV4 => CPU_ARM_V4,
            Self::ArmV5 => CPU_ARM_V5,
            Self::ArmV6 => CPU_ARM_V6,
            Self::MCore => CPU_MCORE,
            Self::Undefined(id) => id,
        }
    }

    fn is_arm(self) -> bool {
        matches!(self, Self::ArmV4 | Self::ArmV5 | Self::ArmV6)
    }

    /// The architecture the CPU names. The loader reads the header in place
    /// as a native structure, so the target has the header's (little-endian)
    /// byte order.
    fn target(self) -> Option<Target> {
        let isa = match self {
            Self::X86 => Isa::X86,
            Self::ArmV4 | Self::ArmV5 | Self::ArmV6 => Isa::Arm,
            // M*CORE is reported as C-SKY, as `EM_MCORE` is in the ELF table.
            Self::MCore => Isa::Csky,
            Self::Unknown | Self::Undefined(_) => return None,
        };
        Some(Target::new(isa, 32, Endianness::Little))
    }

    /// The CPU variant reported for the image.
    fn variant(self) -> Option<&'static str> {
        match self {
            Self::X86 => Some("x86"),
            Self::ArmV4 => Some("ARMv4"),
            Self::ArmV5 => Some("ARMv5"),
            Self::ArmV6 => Some("ARMv6"),
            Self::MCore => Some("M*CORE"),
            Self::Unknown | Self::Undefined(_) => None,
        }
    }

    /// `"CPU 0x2001 (ECpuArmV5): 32-bit little-endian ARM"`.
    fn describe(self) -> String {
        let id = self.id();
        match (self.name(), self) {
            (Some(name), Self::X86) => format!("CPU 0x{id:X} ({name}): 32-bit x86"),
            (Some(name), Self::MCore) => format!(
                "CPU 0x{id:X} ({name}): Motorola M*CORE, reported as C-SKY (its derivative, as \
                 for EM_MCORE in ELF); little-endian like the header"
            ),
            (Some(name), Self::Unknown) => {
                format!("CPU 0x{id:X} ({name}): the header names no ISA")
            }
            (Some(name), _) => format!("CPU 0x{id:X} ({name}): 32-bit little-endian ARM"),
            (None, _) => format!("CPU 0x{id:X} is not a TCpu value: the header names no ISA"),
        }
    }
}

/// An `iCompressionType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    None,
    /// The loader's deflate: Huffman-coded LZ77 with a 4 KiB window and its
    /// own code tables (`sf_deflate.h`), not RFC 1951.
    Deflate,
    BytePair,
    /// A compression UID the loader does not support.
    Unknown(u32),
}

impl Compression {
    fn from_type(value: u32) -> Self {
        match value {
            FORMAT_NOT_COMPRESSED => Self::None,
            UID_COMPRESSION_DEFLATE => Self::Deflate,
            UID_COMPRESSION_BYTE_PAIR => Self::BytePair,
            other => Self::Unknown(other),
        }
    }

    /// `"Symbian deflate (0x101F7AFC)"`.
    fn describe(self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::Deflate => format!("Symbian deflate (0x{UID_COMPRESSION_DEFLATE:08X})"),
            Self::BytePair => format!("byte-pair (0x{UID_COMPRESSION_BYTE_PAIR:08X})"),
            Self::Unknown(value) => format!("unknown compression 0x{value:08X}"),
        }
    }
}

/// A part of the image: a byte range at an offset of the image the header
/// describes (the file, or the uncompressed image).
struct Part {
    offset: u64,
    size: u64,
}

impl Part {
    fn end(&self) -> u64 {
        self.offset + self.size
    }
}

/// The code and data parts, checked against an image of `image_size` bytes
/// (`ValidateHeader`): the code part inside it, and the data part, unless
/// absent (offset and size 0), after the code part and inside it.
struct Parts {
    code: Part,
    data: Option<Part>,
}

impl Parts {
    fn check(header: &Header, image_size: u64, image: &str) -> Result<Self> {
        let code = Part {
            offset: u64::from(header.code_offset),
            size: u64::from(header.code_size),
        };
        if code.end() > image_size {
            return Err(error(format!(
                "Truncated E32 code part at 0x{:X} ({} B) in the {image_size} B {image}",
                code.offset, code.size
            )));
        }
        if header.data_offset == 0 {
            if header.data_size != 0 {
                return Err(error(format!(
                    "Invalid E32 data part: {} B without a data offset",
                    header.data_size
                )));
            }
            return Ok(Self { code, data: None });
        }
        let data = Part {
            offset: u64::from(header.data_offset),
            size: u64::from(header.data_size),
        };
        if data.offset < code.end() {
            return Err(error(format!(
                "Invalid E32 data offset 0x{:X}: inside the code part, which ends at 0x{:X}",
                data.offset,
                code.end()
            )));
        }
        if data.end() > image_size {
            return Err(error(format!(
                "Truncated E32 data part at 0x{:X} ({} B) in the {image_size} B {image}",
                data.offset, data.size
            )));
        }
        Ok(Self {
            code,
            data: Some(data),
        })
    }
}

/// An uncompressed image: the code part at `iCodeBase` and the data part at
/// `iDataBase` as load sections.
fn load_sections<'a>(c: &mut Container<'a>, data: &'a [u8], header: &Header) -> Result<()> {
    let parts = Parts::check(header, data.len() as u64, "file")?;
    let code = bytes(data, &parts.code);
    push_section(c, "Code part", header.code_base, &parts.code, code);
    let mut summary = vec![format!(
        "Code part {} B at 0x{:X} (text {} B), linked at 0x{:08X}; entry point offset 0x{:X}",
        parts.code.size, parts.code.offset, header.text_size, header.code_base, header.entry_point
    )];
    if let Some(part) = &parts.data {
        let contents = bytes(data, part);
        push_section(c, "Data part", header.data_base, part, contents);
        summary.push(format!(
            "data part {} B at 0x{:X}, linked at 0x{:08X}",
            part.size, part.offset, header.data_base
        ));
    }
    if header.bss_size != 0 {
        summary.push(format!("{} B of uninitialised data", header.bss_size));
    }
    c.notes.push(summary.join("; "));
    Ok(())
}

/// The bytes of a part that [`Parts::check`] placed inside `data`.
fn bytes<'a>(data: &'a [u8], part: &Part) -> &'a [u8] {
    &data[to_usize_u64(part.offset)..to_usize_u64(part.end())]
}

/// Append a load section, unless the sections would exceed [`MAX_PAYLOAD`];
/// an empty part is skipped.
fn push_section<'a>(
    c: &mut Container<'a>,
    label: &str,
    address: u32,
    part: &Part,
    contents: &'a [u8],
) {
    if contents.is_empty() {
        return;
    }
    let loaded: usize = c.sections.iter().map(|s| s.stored_size).sum();
    if loaded.saturating_add(contents.len()) > MAX_PAYLOAD {
        c.notes.push(format!(
            "{label} ({} B at 0x{:X}) is not analyzed: the sections would exceed the {} MiB \
             payload limit",
            contents.len(),
            part.offset,
            MAX_PAYLOAD >> 20
        ));
        return;
    }
    c.sections.push(Section {
        label: label.to_string(),
        address: u64::from(address),
        offset: to_usize_u64(part.offset),
        stored_size: contents.len(),
        data: Cow::Borrowed(contents),
        transform: None,
    });
}

/// A compressed image: the contents after the stored header are opaque. A
/// V header's code and data parts must fit the uncompressed image
/// (`ValidateHeader`); the J format's uncompressed size is not interpreted.
fn load_compressed<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    header: &Header,
    compression: Compression,
    stored_header_size: usize,
) -> Result<()> {
    let uncompressed = match &header.v {
        Some(v) => {
            let image_size = u64::from(header.code_offset) + u64::from(v.uncompressed_size);
            let parts = Parts::check(header, image_size, "uncompressed image")?;
            let data_part = parts.data.as_ref().map_or(String::new(), |part| {
                format!("; data part {} B at 0x{:X}", part.size, part.offset)
            });
            format!(
                "{} B uncompressed after the header; code part {} B at 0x{:X}{data_part} in \
                 the uncompressed image",
                v.uncompressed_size, parts.code.size, parts.code.offset
            )
        }
        None => format!(
            "code part {} B, data part {} B in the uncompressed image",
            header.code_size, header.data_size
        ),
    };
    let contents = &data[stored_header_size..];
    let codec = match compression {
        Compression::Unknown(_) => "an unknown method the loader does not support",
        _ => "a Symbian coding that no codec of this classifier decodes",
    };
    c.notes.push(format!(
        "Contents compressed with {}: {} B at 0x{stored_header_size:X}, {uncompressed}; {codec}, \
         so the contents are opaque and the code is not analyzed",
        compression.describe(),
        contents.len()
    ));
    if !contents.is_empty() {
        c.children.push(Child::opaque(
            "Compressed contents",
            stored_header_size,
            contents,
        ));
    }
    Ok(())
}

/// The header format and UID1, the CPU, the UIDs and their checksum, the
/// header CRC, the flags and the tool and module versions.
fn push_header_notes(c: &mut Container<'_>, header: &Header, cpu: Cpu, header_bytes: &[u8]) {
    let era = match header.format {
        HeaderFormat::Original => "original header format (EKA1; no compression)",
        HeaderFormat::J => "J header format (before Symbian OS 8.1b; compression support)",
        HeaderFormat::V => "V header format (Symbian OS 8.1b and later)",
    };
    let uid1 = header.uid(UID1);
    let kind = match uid1 {
        DYNAMIC_LIBRARY_UID => "dynamic library",
        EXECUTABLE_IMAGE_UID => "executable",
        _ => "neither KDynamicLibraryUid nor KExecutableImageUid",
    };
    c.notes.push(format!(
        "Symbian E32 image, {era}; UID1 0x{uid1:08X} ({kind})"
    ));
    c.notes.push(cpu.describe());
    let computed = uid_checksum(&header.uids);
    let verdict = if computed == header.uid_checksum {
        "matches".to_string()
    } else {
        format!("does not match the computed 0x{computed:08X}; the loader rejects the image")
    };
    c.notes.push(format!(
        "UIDs 0x{uid1:08X}, 0x{:08X}, 0x{:08X}; UID checksum 0x{:08X} {verdict}",
        header.uid(UID2),
        header.uid(UID3),
        header.uid_checksum
    ));
    c.notes.push(integrity_text(header, header_bytes));
    c.notes.push(flags_text(header, cpu));
    let version = header.tools_version;
    let tools = format!(
        "Tools version {}.{} (build {})",
        version.major, version.minor, version.build
    );
    c.notes.push(if header.format == HeaderFormat::V {
        format!(
            "{tools}; module version {}.{}",
            header.word_18 >> 16,
            header.word_18 & 0xFFFF
        )
    } else {
        tools
    });
    if header.format == HeaderFormat::V && is_uid1_mismatch(header) {
        c.notes.push(format!(
            "UID1 0x{uid1:08X} does not match the KImageDll flag ({}); the loader rejects the \
             image",
            if header.is_dll() { "DLL" } else { "EXE" }
        ));
    }
}

/// A V image that is flagged as a DLL needs `KDynamicLibraryUid`, any other
/// `KExecutableImageUid` (`ValidateHeader`).
fn is_uid1_mismatch(header: &Header) -> bool {
    let expected = if header.is_dll() {
        DYNAMIC_LIBRARY_UID
    } else {
        EXECUTABLE_IMAGE_UID
    };
    header.uid(UID1) != expected
}

/// The V header CRC and whether it matches, or the original format's
/// unverified checksums.
fn integrity_text(header: &Header, header_bytes: &[u8]) -> String {
    match (header.format, header.stored_crc) {
        (HeaderFormat::V, Some(stored)) => {
            let computed = header_crc(header_bytes);
            if computed == stored {
                format!(
                    "Header CRC-32 0x{stored:08X} matches (over {} B)",
                    header_bytes.len()
                )
            } else {
                format!(
                    "Header CRC-32 0x{stored:08X} does not match the computed 0x{computed:08X} \
                     (over {} B); the loader rejects the image",
                    header_bytes.len()
                )
            }
        }
        (HeaderFormat::Original, _) => format!(
            "The original header has no header CRC; code checksum 0x{:08X} and data checksum \
             0x{:08X} not verified",
            header.word_18, header.word_1c
        ),
        _ => "The J header has no header CRC".to_string(),
    }
}

/// `Mem::Crc32` (reflected polynomial `0xEDB88320`, register 0, no final
/// XOR) over the header with `iHeaderCrc` set to `KImageCrcInitialiser`.
fn header_crc(header_bytes: &[u8]) -> u32 {
    let crc_end = HEADER_CRC + 4;
    let crc = checksum::crc32_update(0, &header_bytes[..HEADER_CRC]);
    let crc = checksum::crc32_update(crc, &IMAGE_CRC_INITIALISER.to_le_bytes());
    checksum::crc32_update(crc, &header_bytes[crc_end..])
}

/// `"Flags 0x1200002A: EXE; EABI; EKA2 entry point; ELF-derived imports"`.
fn flags_text(header: &Header, cpu: Cpu) -> String {
    let flags = header.flags;
    let mut parts = vec![if header.is_dll() { "DLL" } else { "EXE" }.to_string()];
    if cpu.is_arm() {
        parts.push(abi_text(header));
        parts.push(entry_point_text(header));
    }
    parts.push(import_format_text(header));
    if header.has_format_bits() {
        let fp = (flags & IMAGE_HW_FLOAT_MASK) >> IMAGE_HW_FLOAT_SHIFT;
        match fp {
            FP_TYPE_NONE => {}
            FP_TYPE_VFPV2 => parts.push("VFPv2 floating point".into()),
            FP_TYPE_VFPV3 => parts.push("VFPv3 floating point (with Advanced SIMD)".into()),
            FP_TYPE_VFPV3_D16 => parts.push("VFPv3-D16 floating point".into()),
            other => parts.push(format!("undefined floating-point type {other}")),
        }
    }
    format!("Flags 0x{flags:08X}: {}", parts.join("; "))
}

/// `ABIFromFlags`: the ABI bits, or `KImageOldElfFlag` without header
/// format bits.
fn abi_text(header: &Header) -> String {
    let abi = if header.has_format_bits() {
        header.flags & IMAGE_ABI_MASK
    } else if header.flags & IMAGE_OLD_ELF_FLAG != 0 {
        IMAGE_ABI_EABI
    } else {
        IMAGE_ABI_GCC98R2
    };
    match abi {
        IMAGE_ABI_GCC98R2 => "GCC98r2 ABI".to_string(),
        IMAGE_ABI_EABI => "EABI".to_string(),
        other => format!("undefined ABI bits 0x{other:02X}"),
    }
}

/// `EptFromFlags`: the entry point bits, or `KImageOldJFlag` without header
/// format bits.
fn entry_point_text(header: &Header) -> String {
    let entry_type = if header.has_format_bits() {
        header.flags & IMAGE_EPT_MASK
    } else if header.flags & IMAGE_OLD_J_FLAG != 0 {
        IMAGE_EPT_EKA2
    } else {
        IMAGE_EPT_EKA1
    };
    match entry_type {
        IMAGE_EPT_EKA1 => "EKA1 entry point".to_string(),
        IMAGE_EPT_EKA2 => "EKA2 entry point".to_string(),
        other => format!("undefined entry point type 0x{other:02X}"),
    }
}

/// `ImpFmtFromFlags`: the import format bits, or `KImageOldElfFlag` without
/// header format bits.
fn import_format_text(header: &Header) -> String {
    let import_format = if header.has_format_bits() {
        header.flags & IMAGE_IMP_FMT_MASK
    } else if header.flags & IMAGE_OLD_ELF_FLAG != 0 {
        IMAGE_IMP_FMT_ELF
    } else {
        IMAGE_IMP_FMT_PE
    };
    match import_format {
        IMAGE_IMP_FMT_PE => "PE-derived imports".to_string(),
        IMAGE_IMP_FMT_ELF => "ELF-derived imports".to_string(),
        IMAGE_IMP_FMT_PE2 => "PE-derived imports without ordinals (PE2)".to_string(),
        other => format!("undefined import format 0x{other:08X}"),
    }
}

/// The UIDs, header format, CPU, flags, compression, link addresses and, for
/// V, the security information.
fn push_metadata(c: &mut Container<'_>, header: &Header, cpu: Cpu) {
    for (key, label, at) in [
        ("epoc_uid1", "UID1", UID1),
        ("epoc_uid2", "UID2", UID2),
        ("epoc_uid3", "UID3", UID3),
    ] {
        c.push_metadata(key, label, MetadataValue::Hex(header.uid(at)));
    }
    c.push_metadata(
        "epoc_header_format",
        "E32 header format",
        header.format.label(),
    );
    let cpu_name = cpu.name().unwrap_or("not a TCpu value");
    c.push_metadata(
        "epoc_cpu",
        "CPU identifier",
        format!("0x{:X} ({cpu_name})", cpu.id()),
    );
    c.push_metadata("epoc_flags", "Flags", MetadataValue::Hex(header.flags));
    c.push_metadata(
        "epoc_compression",
        "Compression",
        header.compression().describe(),
    );
    c.push_metadata(
        "epoc_code_base",
        "Code link address",
        MetadataValue::Address(u64::from(header.code_base)),
    );
    c.push_metadata(
        "epoc_data_base",
        "Data link address",
        MetadataValue::Address(u64::from(header.data_base)),
    );
    c.push_metadata(
        "epoc_entry_offset",
        "Entry point offset in the code part",
        MetadataValue::Address(u64::from(header.entry_point)),
    );
    let Some(v) = &header.v else {
        return;
    };
    c.push_metadata(
        "epoc_uncompressed_size",
        "Uncompressed size after the header (B)",
        u64::from(v.uncompressed_size),
    );
    c.push_metadata(
        "epoc_secure_id",
        "Secure ID",
        MetadataValue::Hex(v.secure_id),
    );
    c.push_metadata(
        "epoc_vendor_id",
        "Vendor ID",
        MetadataValue::Hex(v.vendor_id),
    );
    c.push_metadata(
        "epoc_capabilities",
        "Capabilities",
        format!("0x{:016X}", v.capabilities),
    );
    c.push_metadata(
        "epoc_export_description",
        "Export description",
        format!("type {}; {} B", v.export_desc_type, v.export_desc_size),
    );
}

fn truncated_at(at: usize) -> ClassifierError {
    error(format!("Truncated E32 image header at 0x{at:X}"))
}

/// The little-endian word at `at`.
fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(at..at + 4)
        .ok_or_else(|| truncated_at(at))?
        .try_into()
        .expect("slice has 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// The little-endian 16-bit field at `at`.
fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(at..at + 2)
        .ok_or_else(|| truncated_at(at))?
        .try_into()
        .expect("slice has 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

/// A header value as a byte count; saturates on targets whose `usize` is
/// narrower than 32 bits, which then fails every bounds check.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// An offset already checked against a slice length.
fn to_usize_u64(value: u64) -> usize {
    usize::try_from(value).expect("offset was checked against the input length")
}

/// `value` rounded up to a multiple of `alignment`; both are small header
/// quantities.
fn round_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) / alignment * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_format_follows_the_format_bits_then_the_old_j_flag() {
        assert_eq!(
            HeaderFormat::from_flags(0x1200_002A).ok(),
            Some(HeaderFormat::V)
        );
        assert_eq!(
            HeaderFormat::from_flags(0x0100_0003).ok(),
            Some(HeaderFormat::J)
        );
        assert_eq!(
            HeaderFormat::from_flags(IMAGE_OLD_J_FLAG).ok(),
            Some(HeaderFormat::J)
        );
        assert_eq!(
            HeaderFormat::from_flags(0x0000_0003).ok(),
            Some(HeaderFormat::Original)
        );
        assert!(HeaderFormat::from_flags(0x0300_0000).is_err());
    }

    #[test]
    fn cpu_identifiers_map_to_targets_and_variants() {
        let arm = Target::new(Isa::Arm, 32, Endianness::Little);
        assert_eq!(Cpu::from_id(0x2000).target(), Some(arm));
        assert_eq!(Cpu::from_id(0x2001).variant(), Some("ARMv5"));
        assert_eq!(Cpu::from_id(0x2002).variant(), Some("ARMv6"));
        assert_eq!(
            Cpu::from_id(0x1000).target(),
            Some(Target::new(Isa::X86, 32, Endianness::Little))
        );
        assert_eq!(
            Cpu::from_id(0x4000).target().map(|t| t.isa),
            Some(Isa::Csky)
        );
        assert_eq!(Cpu::from_id(0).target(), None);
        assert_eq!(Cpu::from_id(0x2003), Cpu::Undefined(0x2003));
        assert_eq!(Cpu::from_id(0x2003).target(), None);
    }

    #[test]
    fn header_crc_replaces_the_stored_crc_with_the_initialiser() {
        // 0x14 bytes of 0x11, the CRC field (any value), 8 bytes of 0x22.
        // Expected value from an independent bitwise CRC-32 (reflected
        // 0xEDB88320, register 0, no final XOR) over the bytes with
        // C90FDAA2 at 0x14.
        let mut header = vec![0x11; HEADER_CRC];
        header.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        header.extend_from_slice(&[0x22; 8]);
        let expected = header_crc_reference(&header);
        assert_eq!(header_crc(&header), expected);
        header[HEADER_CRC] ^= 0xFF;
        assert_eq!(header_crc(&header), expected);
    }

    /// Bit-at-a-time `Mem::Crc32` over `header` with the CRC field set to
    /// the initialiser, for comparison with the table-driven helper.
    fn header_crc_reference(header: &[u8]) -> u32 {
        let mut bytes = header.to_vec();
        bytes[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&IMAGE_CRC_INITIALISER.to_le_bytes());
        let mut crc = 0u32;
        for byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xEDB8_8320
                };
            }
        }
        crc
    }

    #[test]
    fn export_descriptions_round_to_four_bytes() {
        assert_eq!(
            EXPORT_DESC_SIZE + round_up(EXPORT_DESC_FIELDS, HEADER_ALIGNMENT),
            V_HEADER_SIZE
        );
        assert_eq!(round_up(5 + EXPORT_DESC_FIELDS, HEADER_ALIGNMENT), 8);
    }
}
