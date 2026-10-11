//! TI C55x serial boot tables produced by `hex55 -boot -v5505 -serial8 -b`.
//!
//! Layout: TI SPRABL7D, section 3.1, Table 2 (July 2018):
//! <https://www.ti.com/lit/pdf/SPRABL7>. Program addresses are bytes; load
//! destinations and sizes are 16-bit words. Section address plus payload is
//! padded to a multiple of four words, independently of the file offset.
//! CPU address widths and instruction ordering: SWPU073E, chapter 3:
//! <https://www.ti.com/lit/pdf/SWPU073>.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationResult, Endianness, FileFormat, Isa, MetadataEntry, MetadataKey, MetadataValue,
};

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::TiC55xBootParseError {
        message: message.into(),
    }
}

fn word(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| error(format!("Truncated 16-bit word at file offset 0x{offset:X}")))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn address(data: &[u8], offset: usize) -> Result<u32> {
    Ok((u32::from(word(data, offset)?) << 16) | u32::from(word(data, offset + 2)?))
}

/// A load section; payload bytes exclude the boot-table header and padding.
#[derive(Debug)]
pub struct Section<'a> {
    /// Destination in the CPU's 16-bit word-addressed data space.
    pub word_address: u32,
    /// Original file offset of the first payload byte.
    pub offset: usize,
    /// Borrowed code/data bytes in program-space byte order.
    pub data: &'a [u8],
}

impl Section<'_> {
    /// Destination expressed in byte-addressed program space.
    pub fn byte_address(&self) -> u32 {
        self.word_address * 2
    }
}

/// Validated boot table with borrowed register records and section data.
#[derive(Debug)]
pub struct Container<'a> {
    /// Program-space byte address at which execution begins.
    pub entry_point: u32,
    /// Four-byte register address/value records; address 0xffff denotes a delay.
    pub register_configs: &'a [u8],
    /// Load sections in boot order, including possible overlapping writes.
    pub sections: Vec<Section<'a>>,
    /// Number of bytes through and including the zero-word terminator.
    pub image_size: usize,
}

impl Container<'_> {
    /// Locate the entry point in the last section that writes its address.
    /// An entry in pre-existing memory (for example ROM) has no file offset.
    pub fn entry_file_offset(&self) -> Option<usize> {
        self.sections.iter().rev().find_map(|s| {
            let delta = self.entry_point.checked_sub(s.byte_address())? as usize;
            (delta < s.data.len()).then_some(s.offset + delta)
        })
    }

    /// Identify the C55x family from the validated processor-specific table.
    /// The table has no device-model field and no code/data section flags.
    pub fn classification(&self) -> ClassificationResult {
        let mut result = ClassificationResult::from_format(
            Isa::TiC5500,
            16,
            Endianness::Big,
            FileFormat::TiC55xBoot,
        );
        result.metadata.entry_point = Some(u64::from(self.entry_point));
        result.metadata.section_count = Some(self.sections.len());
        result
            .metadata
            .notes
            .push("TI C55x serial boot table (0x09AA); exact device model is not encoded".into());
        result.metadata.notes.push(
            "Entry point uses byte addresses; load destinations and counts use 16-bit words. Sections may contain code or data".into(),
        );
        result
    }

    /// Register configuration count, load ranges, and entry-point file mapping.
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let custom = |key: String, label: String, value: MetadataValue| {
            MetadataEntry::new(MetadataKey::Custom(key), value, label)
        };
        let mut entries = vec![custom(
            "ti_c55x_register_count".into(),
            "Register configuration count".into(),
            MetadataValue::Integer((self.register_configs.len() / 4) as u64),
        )];
        if let Some(offset) = self.entry_file_offset() {
            entries.push(custom(
                "ti_c55x_entry_file_offset".into(),
                "Entry point file offset (B)".into(),
                MetadataValue::Address(offset as u64),
            ));
        }
        entries.push(custom(
            "ti_c55x_image_size".into(),
            "Boot table size (B)".into(),
            MetadataValue::Integer(self.image_size as u64),
        ));
        for (i, s) in self.sections.iter().enumerate() {
            entries.push(custom(
                format!("ti_c55x_section_{}", i + 1),
                format!("Load section {} (code/data)", i + 1),
                MetadataValue::String(format!(
                    "file 0x{:X}; destination word 0x{:06X} / byte 0x{:06X}; {} words / {} B",
                    s.offset,
                    s.word_address,
                    s.byte_address(),
                    s.data.len() / 2,
                    s.data.len(),
                )),
            ));
        }
        entries
    }
}

/// Recognize a complete, bounded table rather than a two-byte signature alone.
pub fn detect(data: &[u8]) -> bool {
    data.starts_with(&[0x09, 0xAA]) && parse_container(data).is_ok()
}

/// Validate the header, records, 64-bit block padding, addresses and terminator.
/// Zero/erased-flash bytes may follow the terminator. Padding inside blocks may
/// have any value. Entry points outside loaded sections and overlapping writes
/// are retained, because the ROM loader can execute from pre-existing memory.
/// Runs in O(S + T) time and O(S) auxiliary space for S sections and T tail bytes;
/// payloads and register records are borrowed, without allocating a memory map.
pub fn parse_container(data: &[u8]) -> Result<Container<'_>> {
    if word(data, 0)? != 0x09AA {
        return Err(error("Invalid boot signature (expected 0x09AA)"));
    }
    let entry_point = address(data, 2)?;
    if entry_point >= (1 << 24) {
        return Err(error("Entry point exceeds 24-bit byte address space"));
    }
    let register_count = usize::from(word(data, 6)?);
    let mut pos = 8 + register_count * 4;
    let register_configs = data
        .get(8..pos)
        .ok_or_else(|| error("Truncated register configuration records"))?;
    let mut sections = Vec::new();
    loop {
        let count = usize::from(word(data, pos)?);
        if count == 0 {
            pos += 2;
            if sections.is_empty() {
                return Err(error("Boot table has no load sections"));
            }
            if data[pos..].iter().any(|&b| b != 0 && b != 0xFF) {
                return Err(error("Unexpected data after boot-table terminator"));
            }
            return Ok(Container {
                entry_point,
                register_configs,
                sections,
                image_size: pos,
            });
        }
        let word_address = address(data, pos + 2)?;
        if u64::from(word_address) + count as u64 > (1 << 23) {
            return Err(error(format!(
                "Load section {} exceeds 23-bit word address space",
                sections.len() + 1
            )));
        }
        let offset = pos + 6;
        // The count word is outside the aligned block: 1 + ceil((count+2)/4)*4 words.
        let next = pos + 2 + ((count + 5) & !3) * 2;
        if next > data.len() {
            return Err(error(format!(
                "Truncated payload or padding for load section {}",
                sections.len() + 1
            )));
        }
        sections.push(Section {
            word_address,
            offset,
            data: &data[offset..offset + count * 2],
        });
        pos = next;
    }
}

/// Parse and classify a complete boot table without applying raw-code models.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    Ok(parse_container(data)?.classification())
}
