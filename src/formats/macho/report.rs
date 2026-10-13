//! Notes and metadata that describe an image's load commands.

use super::commands::{command_name, LC_BUILD_VERSION};
use super::*;

/// `VM_PROT_*` bits (xnu `osfmk/mach/vm_prot.h`).
const VM_PROT_READ: u32 = 0x1;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;

impl Image {
    /// The file type's `loader.h` name, or its value in hex.
    fn file_type_label(&self) -> String {
        self.header.file_type_name().map_or_else(
            || format!("file type 0x{:X}", self.header.file_type),
            String::from,
        )
    }

    /// The entry point's target address: the `LC_UNIXTHREAD` program
    /// counter, or the address the segments map `LC_MAIN`'s file offset to.
    pub fn entry_address(&self) -> Option<u64> {
        match self.entry? {
            Entry::Main { file_offset } => self.address_of(self.main_file_offset(file_offset)?),
            Entry::Thread { address, .. } => address,
        }
    }

    /// `LC_MAIN`'s `entryoff` as a file offset of the input: it counts
    /// from the image's header.
    fn main_file_offset(&self, entry_offset: u64) -> Option<u64> {
        (self.header.offset as u64).checked_add(entry_offset)
    }

    /// The target address the first segment that maps file offset
    /// `offset` gives it; `None` when no segment maps it or the address
    /// would overflow.
    fn address_of(&self, offset: u64) -> Option<u64> {
        let segment = self
            .segments
            .iter()
            .find(|s| offset >= s.file_offset && offset - s.file_offset < s.file_size)?;
        segment.vm_address.checked_add(offset - segment.file_offset)
    }

    /// Fill the generic metadata fields: entry point, section count and
    /// header flags.
    pub fn annotate(&self, metadata: &mut ClassificationMetadata) {
        metadata.entry_point = self.entry_address();
        metadata.section_count = Some(self.section_count());
        metadata.flags = Some(self.header.flags);
    }

    /// Notes on the load commands, most important first. `input_size` is
    /// the size of the input that holds the image.
    pub fn notes(&self, input_size: usize) -> Vec<String> {
        let mut notes = vec![format!(
            "{}; {} ({} B); {}, {}",
            self.file_type_label(),
            counted(
                self.header.command_count as usize,
                "load command",
                "load commands"
            ),
            self.header.commands_size,
            counted(self.segments.len(), "segment", "segments"),
            counted(self.section_count(), "section", "sections")
        )];
        if !self.offsets_in_input {
            notes.push(
                "MH_DYLIB_IN_CACHE: the image's file offsets refer to the dyld shared cache or \
                 kernel collection that holds it; its sections are not read from these bytes"
                    .to_string(),
            );
        }
        notes.extend(self.build_versions.iter().map(build_version_note));
        if let Some(note) = self.entry_note() {
            notes.push(note);
        }
        if let Some(signature) = self.code_signature {
            notes.push(format!(
                "Code signature present (LC_CODE_SIGNATURE at 0x{:X}, {} B{}); not verified",
                signature.offset,
                signature.size,
                self.past_end(signature, input_size)
            ));
        }
        if let Some(encryption) = self.encryption {
            notes.push(encryption_note(encryption));
        }
        if let Some(fixups) = self.chained_fixups {
            notes.push(format!(
                "Chained fixups present (LC_DYLD_CHAINED_FIXUPS at 0x{:X}, {} B{})",
                fixups.offset,
                fixups.size,
                self.past_end(fixups, input_size)
            ));
        }
        if let Some(note) = self.truncated_segments_note(input_size) {
            notes.push(note);
        }
        if self.header.is_fileset() || !self.fileset.is_empty() {
            notes.push(format!(
                "{} (LC_FILESET_ENTRY)",
                counted(self.fileset.len(), "fileset entry", "fileset entries")
            ));
        }
        notes.extend(self.listing_note());
        notes.extend(self.remarks.iter().cloned());
        notes
    }

    /// `"; extends past the end of the input"` for a blob that does.
    fn past_end(&self, range: DataRange, input_size: usize) -> &'static str {
        let end = u64::from(range.offset) + u64::from(range.size);
        if self.offsets_in_input && end > input_size as u64 {
            "; extends past the end of the input"
        } else {
            ""
        }
    }

    /// The entry point, or why it was not read.
    fn entry_note(&self) -> Option<String> {
        let note = match self.entry? {
            Entry::Main { file_offset } => match self.entry_address() {
                Some(address) => {
                    format!("Entry point 0x{address:X} (LC_MAIN file offset 0x{file_offset:X})")
                }
                None => format!("LC_MAIN file offset 0x{file_offset:X} lies in no segment"),
            },
            Entry::Thread {
                address: Some(address),
                flavor_name: Some(name),
                ..
            } => format!("Entry point 0x{address:X} (LC_UNIXTHREAD {name} program counter)"),
            Entry::Thread { flavor, .. } => format!(
                "LC_UNIXTHREAD thread state flavor {flavor} is not decoded for this CPU type; \
                 entry point not read"
            ),
        };
        Some(note)
    }

    /// Segments whose file bytes extend past the input (a truncated file).
    fn truncated_segments_note(&self, input_size: usize) -> Option<String> {
        if !self.offsets_in_input {
            return None;
        }
        let input_end = input_size as u64;
        let mut cut = self
            .segments
            .iter()
            .filter(|s| s.file_offset.saturating_add(s.file_size) > input_end);
        let first = cut.next()?;
        let others = cut.count();
        let more = if others > 0 {
            format!(" and {others} more extend")
        } else {
            " extends".to_string()
        };
        Some(format!(
            "Segment {} (file 0x{:X}, {} B){more} past the end of the input ({input_size} B)",
            segment_label(&first.name),
            first.file_offset,
            first.file_size
        ))
    }

    /// How many segments and sections the metadata leaves out.
    fn listing_note(&self) -> Option<String> {
        let segments = self.segments.len();
        let sections = self.section_count();
        if segments <= MAX_LISTED_SEGMENTS && sections <= MAX_LISTED_SECTIONS {
            return None;
        }
        Some(format!(
            "Metadata lists {} of {segments} segments and {} of {sections} sections",
            segments.min(MAX_LISTED_SEGMENTS),
            sections.min(MAX_LISTED_SECTIONS)
        ))
    }

    /// Metadata entries: file type, load commands, UUID, platforms, entry,
    /// signature, encryption, fixups, then segments, sections and fileset
    /// entries.
    pub fn metadata(&self) -> Vec<MetadataEntry> {
        let mut entries = vec![
            custom("file_type", "File type", self.file_type_label()),
            custom(
                "load_commands",
                "Load commands",
                u64::from(self.header.command_count),
            ),
        ];
        if let Some(uuid) = self.uuid {
            entries.push(custom("uuid", "UUID", uuid_text(&uuid)));
        }
        for (i, version) in self.build_versions.iter().enumerate() {
            let suffix = if i == 0 {
                String::new()
            } else {
                format!("_{i}")
            };
            entries.push(custom(
                &format!("platform{suffix}"),
                "Platform",
                version.platform_label(),
            ));
            entries.push(custom(
                &format!("min_os{suffix}"),
                "Minimum OS",
                platform::version_text(version.min_os),
            ));
            if version.sdk != 0 {
                entries.push(custom(
                    &format!("sdk{suffix}"),
                    "SDK",
                    platform::version_text(version.sdk),
                ));
            }
        }
        if let Some(Entry::Main { file_offset }) = self.entry {
            entries.push(custom(
                "entry_file_offset",
                "LC_MAIN file offset (B)",
                file_offset,
            ));
        }
        if let Some(signature) = self.code_signature {
            entries.push(custom(
                "code_signature",
                "Code signature (not verified)",
                range_text(signature),
            ));
        }
        if let Some(encryption) = self.encryption {
            entries.push(custom(
                "encryption",
                "Encryption",
                format!(
                    "cryptid {}; file 0x{:X}; {} B",
                    encryption.id, encryption.offset, encryption.size
                ),
            ));
        }
        if let Some(fixups) = self.chained_fixups {
            entries.push(custom(
                "chained_fixups",
                "Chained fixups",
                range_text(fixups),
            ));
        }
        self.push_segments(&mut entries);
        for (i, entry) in self
            .fileset
            .iter()
            .take(crate::formats::container::MAX_COMPONENTS)
            .enumerate()
        {
            entries.push(custom(
                &format!("fileset_entry_{i}"),
                &entry.id,
                format!(
                    "vm 0x{:X}; file 0x{:X}",
                    entry.vm_address, entry.file_offset
                ),
            ));
        }
        entries
    }

    /// One entry per listed segment and section.
    fn push_segments(&self, entries: &mut Vec<MetadataEntry>) {
        for (i, segment) in self.segments.iter().take(MAX_LISTED_SEGMENTS).enumerate() {
            entries.push(custom(
                &format!("segment_{i}"),
                &segment_label(&segment.name),
                format!(
                    "vm 0x{:X}, {} B; file 0x{:X}, {} B; {}/{}; {}",
                    segment.vm_address,
                    segment.vm_size,
                    segment.file_offset,
                    segment.file_size,
                    protection_text(segment.initial_protection),
                    protection_text(segment.max_protection),
                    counted(segment.sections.len(), "section", "sections")
                ),
            ));
        }
        let sections = self.segments.iter().flat_map(|s| &s.sections);
        for (i, section) in sections.take(MAX_LISTED_SECTIONS).enumerate() {
            let kind = if section.has_instructions() {
                "; instructions"
            } else if section.is_zero_fill() {
                "; zero fill"
            } else {
                ""
            };
            entries.push(custom(
                &format!("section_{i}"),
                &format!("{},{}", section.segment_name, section.name),
                format!(
                    "vm 0x{:X}; file 0x{:X}; {} B; flags 0x{:08X}{kind}",
                    section.address, section.offset, section.size, section.flags
                ),
            ));
        }
    }
}

/// `1 segment`, `2 segments`.
fn counted(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// A `macho_<key>` metadata entry.
fn custom(key: &str, label: &str, value: impl Into<MetadataValue>) -> MetadataEntry {
    MetadataEntry::new(
        MetadataKey::Custom(format!("{KEY_PREFIX}_{key}")),
        value.into(),
        label,
    )
}

/// A segment name, or `(unnamed)` for the empty name of `MH_OBJECT` files.
fn segment_label(name: &str) -> String {
    if name.is_empty() {
        "(unnamed)".to_string()
    } else {
        name.to_string()
    }
}

/// `r-x` style protection text.
fn protection_text(protection: u32) -> String {
    let bit = |mask: u32, c: char| if protection & mask != 0 { c } else { '-' };
    [
        bit(VM_PROT_READ, 'r'),
        bit(VM_PROT_WRITE, 'w'),
        bit(VM_PROT_EXECUTE, 'x'),
    ]
    .iter()
    .collect()
}

/// `file 0x...; N B` for a linkedit blob.
fn range_text(range: DataRange) -> String {
    format!("file 0x{:X}; {} B", range.offset, range.size)
}

/// The UUID in the 8-4-4-4-12 form `otool` prints.
fn uuid_text(uuid: &[u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode_upper(&uuid[..4]),
        hex::encode_upper(&uuid[4..6]),
        hex::encode_upper(&uuid[6..8]),
        hex::encode_upper(&uuid[8..10]),
        hex::encode_upper(&uuid[10..])
    )
}

/// `Platform macOS (LC_BUILD_VERSION); minimum OS 14.0; SDK 15.2`.
fn build_version_note(version: &BuildVersion) -> String {
    let source = if version.command == LC_BUILD_VERSION {
        "LC_BUILD_VERSION"
    } else {
        command_name(version.command).unwrap_or("LC_VERSION_MIN_*")
    };
    let note = format!(
        "Platform {} ({source}); minimum OS {}",
        version.platform_label(),
        platform::version_text(version.min_os)
    );
    if version.sdk == 0 {
        return note;
    }
    format!("{note}; SDK {}", platform::version_text(version.sdk))
}

/// The encryption record as a note.
fn encryption_note(encryption: Encryption) -> String {
    let name = command_name(encryption.command).unwrap_or("LC_ENCRYPTION_INFO");
    if encryption.is_encrypted() {
        format!(
            "Encrypted range at 0x{:X}, {} B ({name} cryptid {}); left out of extension detection",
            encryption.offset, encryption.size, encryption.id
        )
    } else {
        format!("{name} cryptid 0: the range is not encrypted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protections_and_uuids_read_like_otool() {
        assert_eq!(protection_text(5), "r-x");
        assert_eq!(protection_text(3), "rw-");
        assert_eq!(protection_text(0), "---");
        let uuid = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(uuid_text(&uuid), "00010203-0405-0607-0809-0A0B0C0D0E0F");
    }
}
