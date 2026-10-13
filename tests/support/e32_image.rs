//! Hand-built Symbian E32 image files for tests, written from the documented
//! header layout (Symbian Foundation `kernelhwsrv` commit
//! `0c3208650587ac0230aed8a74e9bddb5288023eb`,
//! `userlibandfileserver/fileserver/inc/f32image.h`; the pre-8.1b formats
//! from `rndtools` `launcher/inc/e32imageheaders.h`). The UID checksum and
//! the header CRC are computed here, bit by bit, independently of the
//! parser under test.

// Each test crate that includes this module uses a different part of it.
#![allow(dead_code)]

/// `KExecutableImageUidValue`.
pub const EXECUTABLE_UID: u32 = 0x1000_007A;
/// `KDynamicLibraryUidValue`.
pub const DLL_UID: u32 = 0x1000_0079;
/// A UID2 that applications carry (`KUidApp`).
pub const APP_UID2: u32 = 0x1000_39CE;

// `TCpu` values.
pub const CPU_UNKNOWN: u32 = 0x0000;
pub const CPU_X86: u32 = 0x1000;
pub const CPU_ARM_V4: u32 = 0x2000;
pub const CPU_ARM_V5: u32 = 0x2001;
pub const CPU_ARM_V6: u32 = 0x2002;
pub const CPU_MCORE: u32 = 0x4000;

// `iCompressionType` values.
pub const COMPRESSION_NONE: u32 = 0;
pub const COMPRESSION_DEFLATE: u32 = 0x101F_7AFC;
pub const COMPRESSION_BYTE_PAIR: u32 = 0x1028_22AA;

// `iFlags` bits.
pub const FLAG_DLL: u32 = 0x0000_0001;
pub const FLAG_OLD_J: u32 = 0x0000_0008;
pub const FLAG_ABI_EABI: u32 = 0x0000_0008;
pub const FLAG_EPT_EKA2: u32 = 0x0000_0020;
pub const FLAG_HW_FLOAT_VFPV2: u32 = 0x0010_0000;
pub const FLAG_HDR_FMT_J: u32 = 0x0100_0000;
pub const FLAG_HDR_FMT_V: u32 = 0x0200_0000;
pub const FLAG_IMP_FMT_ELF: u32 = 0x1000_0000;
/// The flags of an ARM EABI executable built for EKA2: EABI, EKA2 entry
/// point, ELF-derived imports (the V format bits are added by
/// [`Image::build`]).
pub const ARM_EKA2_FLAGS: u32 = FLAG_ABI_EABI | FLAG_EPT_EKA2 | FLAG_IMP_FMT_ELF;

// Header field offsets.
pub const UID_CHECKSUM: usize = 0x0C;
pub const SIGNATURE: usize = 0x10;
pub const HEADER_CRC: usize = 0x14;
pub const COMPRESSION_TYPE: usize = 0x1C;
pub const FLAGS: usize = 0x2C;
pub const CODE_SIZE: usize = 0x30;
pub const DATA_SIZE: usize = 0x34;
pub const ENTRY_POINT: usize = 0x48;
pub const TEXT_SIZE: usize = 0x60;
pub const CODE_OFFSET: usize = 0x64;
pub const DATA_OFFSET: usize = 0x68;
pub const CPU_IDENTIFIER: usize = 0x7A;
pub const UNCOMPRESSED_SIZE: usize = 0x7C;
pub const EXPORT_DESC_SIZE: usize = 0x98;

/// `sizeof(E32ImageHeader)`, the header of the original and J formats.
pub const BASE_HEADER_SIZE: usize = 0x7C;
/// `sizeof(E32ImageHeaderComp)`: a compressed J image's stored header.
pub const COMP_HEADER_SIZE: usize = 0x80;
/// `sizeof(E32ImageHeaderV)` with an empty export description.
pub const V_HEADER_SIZE: usize = 0x9C;

/// `KImageCrcInitialiser`.
const IMAGE_CRC_INITIALISER: u32 = 0xC90F_DAA2;

/// The header format, which decides where the CPU and the compression type
/// are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// EKA1 original: CPU word at 0x14, code and data checksums at 0x18
    /// and 0x1C.
    Original,
    /// J: CPU word at 0x14, compression type at 0x1C, header format bits
    /// `0x01000000`.
    J,
    /// V: header CRC at 0x14, compression type at 0x1C, CPU at 0x7A, header
    /// format bits `0x02000000`, `E32ImageHeaderV` fields to 0x9C.
    V,
}

/// The fields of an image; [`Image::build`] lays them out.
#[derive(Debug, Clone)]
pub struct Image {
    pub format: Format,
    /// UID1 at 0x0.
    pub uid1: u32,
    /// UID2 at 0x4.
    pub uid2: u32,
    /// UID3 at 0x8; also the V secure ID at 0x80.
    pub uid3: u32,
    /// `iFlags` at 0x2C without the header format bits.
    pub flags: u32,
    /// The `TCpu` value: a 16-bit field at 0x7A for V, the word at 0x14
    /// otherwise.
    pub cpu: u32,
    /// `iCompressionType` at 0x1C (J and V).
    pub compression: u32,
    /// The code part (`iCodeSize`, `iTextSize`) at `iCodeOffset`, the end
    /// of the header.
    pub code: Vec<u8>,
    /// The data part (`iDataSize`) right after the code part; no data
    /// offset when empty.
    pub data: Vec<u8>,
    /// `iBssSize` at 0x44.
    pub bss_size: u32,
    /// `iEntryPoint` at 0x48, an offset into the code part.
    pub entry_point: u32,
    /// `iCodeBase` at 0x4C.
    pub code_base: u32,
    /// `iDataBase` at 0x50.
    pub data_base: u32,
    /// For a compressed image: the stored bytes after the header, written
    /// instead of `code` and `data`, which then only give the sizes.
    pub stored: Option<Vec<u8>>,
}

impl Image {
    /// An ARMv5 EABI executable for EKA2 in the V format with UID2
    /// `KUidApp`, code linked at 0x8000 and data at 0x400000.
    pub fn arm_v5(uid3: u32, code: &[u8]) -> Self {
        Self {
            format: Format::V,
            uid1: EXECUTABLE_UID,
            uid2: APP_UID2,
            uid3,
            flags: ARM_EKA2_FLAGS,
            cpu: CPU_ARM_V5,
            compression: COMPRESSION_NONE,
            code: code.to_vec(),
            data: Vec::new(),
            bss_size: 0,
            entry_point: 0,
            code_base: 0x8000,
            data_base: 0x0040_0000,
            stored: None,
        }
    }

    /// An EKA1 executable in the original format, linked at 0x10000000.
    pub fn original(cpu: u32, code: &[u8]) -> Self {
        Self {
            format: Format::Original,
            flags: 0,
            cpu,
            code_base: 0x1000_0000,
            data_base: 0,
            ..Self::arm_v5(0x1000_5B91, code)
        }
    }

    /// The header size, which is also `iCodeOffset` (in the uncompressed
    /// image for a compressed J image).
    fn code_offset(&self) -> usize {
        match self.format {
            Format::V => V_HEADER_SIZE,
            Format::Original | Format::J => BASE_HEADER_SIZE,
        }
    }

    /// The image file: header, then the code and data parts or the stored
    /// compressed bytes; the UID checksum and (V) header CRC are sealed.
    pub fn build(&self) -> Vec<u8> {
        let code_offset = self.code_offset();
        let code_size = self.code.len();
        let data_offset = if self.data.is_empty() {
            0
        } else {
            code_offset + code_size
        };
        let format_bits = match self.format {
            Format::Original => 0,
            Format::J => FLAG_HDR_FMT_J,
            Format::V => FLAG_HDR_FMT_V,
        };
        let mut header = Vec::new();
        put(&mut header, self.uid1);
        put(&mut header, self.uid2);
        put(&mut header, self.uid3);
        put(&mut header, 0); // UID checksum, sealed below
        header.extend_from_slice(b"EPOC");
        // 0x14: the header CRC (sealed below) or the CPU word.
        put(
            &mut header,
            if self.format == Format::V {
                0
            } else {
                self.cpu
            },
        );
        // 0x18: module version 10.0 (V), the code checksum (original; the
        // parser does not verify it) or an unused word (J).
        let word_18 = match self.format {
            Format::V => 0x000A_0000,
            Format::Original => word_sum(&self.code),
            Format::J => 0,
        };
        put(&mut header, word_18);
        // 0x1C: the compression type, or the data checksum (original).
        let word_1c = match self.format {
            Format::Original => word_sum(&self.data),
            Format::J | Format::V => self.compression,
        };
        put(&mut header, word_1c);
        // 0x20: tools version 2.1, build 549 (`TVersion`).
        header.extend_from_slice(&[2, 1]);
        header.extend_from_slice(&549u16.to_le_bytes());
        put(&mut header, 0); // 0x24: time, low word
        put(&mut header, 0); // 0x28: time, high word
        put(&mut header, self.flags | format_bits); // 0x2C
        put(&mut header, size(code_size)); // 0x30: iCodeSize
        put(&mut header, size(self.data.len())); // 0x34: iDataSize
        put(&mut header, 0x1000); // 0x38: iHeapSizeMin
        put(&mut header, 0x10_0000); // 0x3C: iHeapSizeMax
        put(&mut header, 0x2000); // 0x40: iStackSize
        put(&mut header, self.bss_size); // 0x44
        put(&mut header, self.entry_point); // 0x48
        put(&mut header, self.code_base); // 0x4C
        put(&mut header, self.data_base); // 0x50
        put(&mut header, 0); // 0x54: iDllRefTableCount
        put(&mut header, 0); // 0x58: iExportDirOffset
        put(&mut header, 0); // 0x5C: iExportDirCount
        put(&mut header, size(code_size)); // 0x60: iTextSize
        put(&mut header, size(code_offset)); // 0x64: iCodeOffset
        put(&mut header, size(data_offset)); // 0x68: iDataOffset
        put(&mut header, 0); // 0x6C: iImportOffset
        put(&mut header, 0); // 0x70: iCodeRelocOffset
        put(&mut header, 0); // 0x74: iDataRelocOffset
        let uncompressed = size(code_size + self.data.len());
        match self.format {
            Format::V => {
                header.extend_from_slice(&350u16.to_le_bytes()); // 0x78: priority
                header.extend_from_slice(&u16::try_from(self.cpu).unwrap().to_le_bytes());
                put(&mut header, uncompressed); // 0x7C: iUncompressedSize
                put(&mut header, self.uid3); // 0x80: iSecureId
                put(&mut header, 0x7000_0001); // 0x84: iVendorId
                put(&mut header, 0x000F_FFFF); // 0x88: capabilities, low word
                put(&mut header, 0); // 0x8C: capabilities, high word
                put(&mut header, 0); // 0x90: iExceptionDescriptor
                put(&mut header, 0); // 0x94: iSpare2
                header.extend_from_slice(&0u16.to_le_bytes()); // 0x98: iExportDescSize
                header.push(0); // 0x9A: iExportDescType, no holes
                header.push(0); // 0x9B: padding to 0x9C
            }
            Format::Original | Format::J => {
                put(&mut header, 350); // 0x78: priority (a 32-bit enum)
                if self.format == Format::J && self.stored.is_some() {
                    put(&mut header, uncompressed); // 0x7C: iUncompressedSize
                }
            }
        }
        let mut image = header;
        match &self.stored {
            Some(stored) => image.extend_from_slice(stored),
            None => {
                image.extend_from_slice(&self.code);
                image.extend_from_slice(&self.data);
            }
        }
        seal(&mut image);
        image
    }
}

/// Recompute the UID checksum and, for a V header, the header CRC over the
/// `iCodeOffset` header bytes, after a test changed header fields.
pub fn seal(image: &mut [u8]) {
    let checksum = uid_checksum(&image[..12]);
    image[UID_CHECKSUM..UID_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());
    let flags = word(image, FLAGS);
    if flags & 0x0F00_0000 != FLAG_HDR_FMT_V {
        return;
    }
    let header_size = (word(image, CODE_OFFSET) as usize).min(image.len());
    let crc = header_crc(&image[..header_size]);
    image[HEADER_CRC..HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
}

/// `TCheckedUid::Check`: CRC-16 (polynomial 0x1021, initial value 0) of
/// the odd UID bytes in the high half, of the even bytes in the low half.
pub fn uid_checksum(uids: &[u8]) -> u32 {
    let even: Vec<u8> = uids.iter().step_by(2).copied().collect();
    let odd: Vec<u8> = uids.iter().skip(1).step_by(2).copied().collect();
    (u32::from(crc16(&odd)) << 16) | u32::from(crc16(&even))
}

/// `Mem::Crc`: CRC-16, polynomial 0x1021, register 0, most significant bit
/// first, no final XOR.
fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            };
        }
    }
    crc
}

/// `Mem::Crc32` over the header with `iHeaderCrc` set to
/// `KImageCrcInitialiser`: reflected polynomial 0xEDB88320, register 0, no
/// final XOR.
pub fn header_crc(header: &[u8]) -> u32 {
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

/// Overwrite the little-endian word at `at`.
pub fn set_word(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// The little-endian word at `at`.
pub fn word(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
}

fn put(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn size(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}

/// The sum of the little-endian 32-bit words (the original format's
/// checksums, as IDA's EKA1 samples carry them).
fn word_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .fold(0u32, u32::wrapping_add)
}
