//! AOR AR-DV10 firmware records, checksum validation, and CPU decoding.
//!
//! Independently implemented from the supplied DV10_firmware_extractor.py v2.0.
//! FPGA and DSP data are retained as records, never treated as CPU instructions.

use std::borrow::Cow;

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, Endianness, FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue,
};

const REVISION_SIZE: usize = 16;
const RECORD_SIZE: usize = 10;
const KEY_SIZE: usize = 128;

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::D10ParseError {
        message: message.into(),
    }
}

fn has_revision(data: &[u8]) -> bool {
    data.len() >= REVISION_SIZE
        && data[..4].iter().all(u8::is_ascii_digit)
        && data[4].is_ascii_uppercase()
        && data[5..10].iter().all(|&b| b == b' ')
        && data[10..16].iter().all(u8::is_ascii_digit)
}

/// Recognize the observed revision/build header and an initial record ID.
/// Checksums and complete record bounds are validated separately by the parser.
pub fn detect(data: &[u8]) -> bool {
    has_revision(data) && data.len() >= 18 && data[16] < 6 && data[17] < 2
}

/// One stored D10 record. Offsets refer to payload bytes in the original file.
#[derive(Debug)]
pub struct Block<'a> {
    /// Component: 0 FPGA, 1-4 DSP, 5 CPU.
    pub section: u8,
    /// Block within the component: 0 or 1.
    pub block: u8,
    /// Flash address from the big-endian record header.
    pub flash_address: u32,
    /// Payload offset in the container, in bytes.
    pub offset: usize,
    /// Stored payload; CPU records may be XOR encoded.
    pub data: &'a [u8],
}

/// A bounded, checksum-validated D10 container with borrowed component data.
#[derive(Debug)]
pub struct Container<'a> {
    /// Complete 16-byte ASCII revision/build header.
    pub revision: &'a str,
    /// Validated trailer CRC, stored little-endian.
    pub checksum: u16,
    /// CPU XOR encoding selected by byte 0x7f of CPU block 1.
    pub cpu_encrypted: bool,
    /// Records in their original file order.
    pub blocks: Vec<Block<'a>>,
}

impl<'a> Container<'a> {
    /// Retrieve a component record by its ID.
    pub fn block(&self, section: u8, block: u8) -> Option<&Block<'a>> {
        self.blocks
            .iter()
            .find(|b| b.section == section && b.block == block)
    }

    /// Decode CPU code only; plain firmware does not require a payload copy.
    pub fn cpu_code(&self) -> Cow<'a, [u8]> {
        let data = self.block(5, 0).expect("validated CPU code record").data;
        if !self.cpu_encrypted {
            return Cow::Borrowed(data);
        }
        let mut decoded = data.to_vec();
        xor(&mut decoded);
        Cow::Owned(decoded)
    }

    /// Decode the vector tail at bytes 128..256, preserving all other bytes.
    pub fn cpu_vectors(&self) -> Cow<'a, [u8]> {
        let data = self.block(5, 1).expect("validated CPU vector record").data;
        if !self.cpu_encrypted {
            return Cow::Borrowed(data);
        }
        let mut decoded = data.to_vec();
        xor(&mut decoded[128..256]);
        Cow::Owned(decoded)
    }

    /// Container metadata; the D10 header does not declare a CPU ISA.
    pub fn classification(&self) -> ClassificationResult {
        let mut result = ClassificationResult::from_format(
            Isa::Unknown(0),
            0,
            Endianness::Little,
            FileFormat::D10,
        );
        result.confidence = 0.0;
        result.metadata.section_count = Some(self.blocks.len());
        result.metadata.code_size = Some(self.block(5, 0).unwrap().data.len() as u64);
        result
            .metadata
            .notes
            .push(format!("AOR AR-DV10 firmware {}", self.revision.trim()));
        result
            .metadata
            .notes
            .push(format!("D10 CRC16 verified: 0x{:04X}", self.checksum));
        result.metadata.notes.push(if self.cpu_encrypted {
            "CPU XOR encoding decoded using the AOR! 128-byte keystream".into()
        } else {
            "CPU payload is plaintext".into()
        });
        result
    }

    /// Revision, CPU encoding state, checksum and each component's file/flash range.
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let custom = |key: &str, label: &str, value: String| {
            MetadataEntry::new(
                MetadataKey::Custom(key.into()),
                MetadataValue::String(value),
                label,
            )
        };
        let mut entries = vec![
            custom(
                "d10_revision",
                "Firmware revision / build",
                self.revision.into(),
            ),
            custom(
                "d10_checksum",
                "D10 CRC16",
                format!("0x{:04X} (verified)", self.checksum),
            ),
            custom(
                "d10_cpu_encoding",
                "CPU encoding",
                if self.cpu_encrypted {
                    "XOR (decoded for classification)"
                } else {
                    "Plaintext"
                }
                .into(),
            ),
        ];
        for b in &self.blocks {
            let component = match b.section {
                0 => "FPGA",
                5 => "CPU",
                _ => "DSP",
            };
            entries.push(custom(
                &format!("d10_block_{}_{}", b.section, b.block),
                &format!("{component} {}:{}", b.section, b.block),
                format!(
                    "file 0x{:X}; flash 0x{:08X}; {} B",
                    b.offset,
                    b.flash_address,
                    b.data.len()
                ),
            ));
        }
        entries
    }
}

/// Validate records and the CRC before exposing or decoding any CPU bytes.
/// Empty FPGA/DSP records and reordered records are supported; duplicate IDs
/// and missing CPU records are rejected.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    if !has_revision(data) {
        return Err(error("Invalid revision/build header"));
    }
    if data.len() < REVISION_SIZE + 2 {
        return Err(error("Missing CRC trailer"));
    }
    let end = data.len() - 2;
    let mut pos = REVISION_SIZE;
    let mut seen = [[false; 2]; 6];
    let mut blocks = Vec::with_capacity(12);
    while pos < end {
        if end - pos < RECORD_SIZE {
            return Err(error(format!("Truncated record header at 0x{pos:X}")));
        }
        let section = data[pos];
        let block = data[pos + 1];
        if section >= 6 || block >= 2 {
            return Err(error(format!("Invalid record ID {section}:{block}")));
        }
        if seen[section as usize][block as usize] {
            return Err(error(format!("Duplicate record {section}:{block}")));
        }
        seen[section as usize][block as usize] = true;
        let flash_address = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap());
        let size = u32::from_be_bytes(data[pos + 6..pos + 10].try_into().unwrap()) as usize;
        pos += RECORD_SIZE;
        if size > end - pos {
            return Err(error(format!(
                "Truncated payload for record {section}:{block}: {size} B at 0x{pos:X}"
            )));
        }
        if u64::from(flash_address) + size as u64 > (1u64 << 32) {
            return Err(error(format!(
                "Flash range exceeds 32 bits for record {section}:{block}"
            )));
        }
        blocks.push(Block {
            section,
            block,
            flash_address,
            offset: pos,
            data: &data[pos..pos + size],
        });
        pos += size;
    }
    let stored = u16::from_le_bytes(data[end..].try_into().unwrap());
    let calculated = checksum(&data[..end]);
    if stored != calculated {
        return Err(ClassifierError::InvalidChecksum {
            expected: format!("D10 CRC16 0x{stored:04X}"),
            actual: format!("0x{calculated:04X}"),
        });
    }
    if !seen[5][0] || !seen[5][1] {
        return Err(error("Missing CPU code or vector record"));
    }
    let vectors = blocks
        .iter()
        .find(|b| b.section == 5 && b.block == 1)
        .unwrap()
        .data;
    if vectors.len() < 128 {
        return Err(error("CPU vector record is shorter than 128 B"));
    }
    let cpu_encrypted = vectors[127] == 0;
    if cpu_encrypted && vectors.len() < 256 {
        return Err(error("Encoded CPU vector record is shorter than 256 B"));
    }
    Ok(Container {
        revision: std::str::from_utf8(&data[..16]).unwrap(),
        checksum: stored,
        cpu_encrypted,
        blocks,
    })
}

/// Parse container metadata without assigning an ISA to FPGA/DSP/CPU data.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    Ok(parse_container(data)?.classification())
}

const fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// D10 CRC16: reflected polynomial 0x8408, init/xorout 0xffff.
pub fn checksum(data: &[u8]) -> u16 {
    const TABLE: [u16; 256] = crc_table();
    let mut crc = 0xffff;
    for &byte in data {
        crc = TABLE[((crc ^ u16::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff
}

fn xor(data: &mut [u8]) {
    let mut key = [0u8; KEY_SIZE];
    let mut state = 0u8;
    for (i, byte) in key.iter_mut().enumerate() {
        state = state.wrapping_add(b"AOR!"[i % 4]).wrapping_add(i as u8);
        *byte = state;
    }
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % KEY_SIZE];
    }
}
