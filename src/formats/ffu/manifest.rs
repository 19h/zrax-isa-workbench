//! The image manifest: text that "contains the description of the device
//! layout and the payload included in the FFU" (Microsoft "FFU image
//! format", "Manifest data"). Microsoft does not publish its keys; this
//! reader follows the INI sections and keys that img2ffu writes
//! (`Writer/Manifest/ManifestIni.cs`) and reads
//! (`Reader/FullFlashUpdateReaderStream.cs`): `[FullFlash]` (`Version`,
//! `OSVersion`, `DevicePlatformId0` to `DevicePlatformId3`, ...), one
//! `[Store]` per store (`SectorSize`, `MinSectorCount`, `IsMainOSStore`,
//! `DevicePath`, ...) and `[Partition]` sections (`Name`, `Type`,
//! `TotalSectors`, `FileSystem`, ...) after their store. Lines are
//! `Key = Value`; section names and keys compare without regard to ASCII
//! case, as img2ffu compares them.
//!
//! The manifest is descriptive: text that does not parse is ignored, never
//! an error. Only a store's disk size (`MinSectorCount` x `SectorSize`)
//! feeds the disk assembly.

use super::*;

/// Most sections and key-value entries kept from one manifest: bounds of
/// this parser, so that a large manifest of short lines cannot multiply
/// into memory. The manifests img2ffu writes hold a few sections per
/// partition.
const MAX_SECTIONS: usize = 4096;
const MAX_ENTRIES: usize = 16384;

/// Most partitions listed in metadata, and named in the summary note.
const MAX_LISTED_PARTITIONS: usize = 256;
const MAX_NAMED_PARTITIONS: usize = 16;

/// One `Key = Value` line, both sides trimmed and made displayable.
#[derive(Debug)]
struct Entry {
    key: String,
    value: String,
}

/// The entries of one section, in text order.
#[derive(Debug, Default)]
struct Entries {
    list: Vec<Entry>,
}

impl Entries {
    /// The value of the first entry named `key`, compared without regard to
    /// ASCII case.
    fn get(&self, key: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|entry| entry.key.eq_ignore_ascii_case(key))
            .map(|entry| entry.value.as_str())
            .filter(|value| !value.is_empty())
    }
}

/// A store's disk size from its manifest section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DiskGeometry {
    /// `MinSectorCount`.
    pub(super) sectors: u64,
    /// `SectorSize`, in bytes.
    pub(super) sector_size: u64,
    /// The product, in bytes: the smallest disk the store is for.
    pub(super) bytes: u64,
}

/// What a store section says about the disk size.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DiskSize {
    /// Both keys are present and give a non-zero size.
    Known(DiskGeometry),
    /// A key is missing.
    Missing,
    /// The keys do not give a size; the text says why.
    Invalid(String),
}

/// A `[Store]` section and the `[Partition]` sections after it.
#[derive(Debug, Default)]
pub(super) struct StoreSection {
    entries: Entries,
    partitions: Vec<Entries>,
    /// Created for `[Partition]` sections that come before any `[Store]`;
    /// the first `[Store]` section then fills it.
    implicit: bool,
}

impl StoreSection {
    /// The disk size as `MinSectorCount` x `SectorSize`, as the img2ffu
    /// reader computes it.
    pub(super) fn disk_size(&self) -> DiskSize {
        let (Some(count), Some(size)) = (
            self.entries.get("MinSectorCount"),
            self.entries.get("SectorSize"),
        ) else {
            return DiskSize::Missing;
        };
        let (Ok(sectors), Ok(sector_size)) = (count.parse::<u64>(), size.parse::<u64>()) else {
            return DiskSize::Invalid(format!(
                "manifest `MinSectorCount = {count}` and `SectorSize = {size}` are not both \
                 decimal numbers"
            ));
        };
        match sectors.checked_mul(sector_size) {
            Some(bytes) if bytes > 0 => DiskSize::Known(DiskGeometry {
                sectors,
                sector_size,
                bytes,
            }),
            _ => DiskSize::Invalid(format!(
                "manifest `MinSectorCount = {sectors}` x `SectorSize = {sector_size}` is zero or \
                 overflows"
            )),
        }
    }

    /// Whether the section says `IsMainOSStore = True`.
    pub(super) fn is_main_os(&self) -> bool {
        self.entries
            .get("IsMainOSStore")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }
}

/// The section a line belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Current {
    FullFlash,
    Store,
    Partition,
    Other,
}

/// The parsed manifest.
#[derive(Debug, Default)]
pub(super) struct Manifest {
    /// `ManifestLength`, in bytes.
    size: usize,
    full_flash: Entries,
    stores: Vec<StoreSection>,
    /// Section headers read, of any name.
    sections: usize,
    /// Parsing stopped at [`MAX_SECTIONS`] or [`MAX_ENTRIES`].
    cut: bool,
}

impl Manifest {
    /// Parse the manifest text line by line.
    pub(super) fn parse(text: &[u8]) -> Self {
        let mut manifest = Self {
            size: text.len(),
            ..Self::default()
        };
        let mut current = Current::Other;
        let mut kept = 0usize;
        for raw in text.split(|&b| b == b'\n') {
            let line = trim(raw);
            if line.is_empty() || line.starts_with(b";") || line.starts_with(b"#") {
                continue;
            }
            if let Some(name) = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")) {
                if manifest.sections == MAX_SECTIONS {
                    manifest.cut = true;
                    break;
                }
                manifest.sections += 1;
                current = manifest.start_section(trim(name));
                continue;
            }
            let Some(equals) = line.iter().position(|&b| b == b'=') else {
                continue;
            };
            if kept == MAX_ENTRIES {
                manifest.cut = true;
                break;
            }
            kept += 1;
            let entry = Entry {
                key: byte_text(trim(&line[..equals])),
                value: byte_text(trim(&line[equals + 1..])),
            };
            manifest.push_entry(current, entry);
        }
        manifest
    }

    /// The section of store `i` (0-based, in manifest order).
    pub(super) fn store(&self, i: usize) -> Option<&StoreSection> {
        self.stores.get(i)
    }

    /// Begin the section named `name`.
    fn start_section(&mut self, name: &[u8]) -> Current {
        if name.eq_ignore_ascii_case(b"FullFlash") {
            Current::FullFlash
        } else if name.eq_ignore_ascii_case(b"Store") {
            match self.stores.as_mut_slice() {
                [only] if only.implicit => only.implicit = false,
                _ => self.stores.push(StoreSection::default()),
            }
            Current::Store
        } else if name.eq_ignore_ascii_case(b"Partition") {
            if self.stores.is_empty() {
                self.stores.push(StoreSection {
                    implicit: true,
                    ..StoreSection::default()
                });
            }
            if let Some(store) = self.stores.last_mut() {
                store.partitions.push(Entries::default());
            }
            Current::Partition
        } else {
            Current::Other
        }
    }

    fn push_entry(&mut self, current: Current, entry: Entry) {
        let entries = match current {
            Current::FullFlash => Some(&mut self.full_flash),
            Current::Store => self.stores.last_mut().map(|store| &mut store.entries),
            Current::Partition => self
                .stores
                .last_mut()
                .and_then(|store| store.partitions.last_mut()),
            Current::Other => None,
        };
        if let Some(entries) = entries {
            entries.list.push(entry);
        }
    }

    /// The summary note and the metadata: the `[FullFlash]` version, OS
    /// version and platform IDs, and one entry per partition.
    pub(super) fn push_notes(&self, c: &mut Container<'_>) {
        c.push_metadata("ffu_manifest_size", "Manifest size (B)", self.size as u64);
        if self.size == 0 {
            c.notes.push("The manifest is empty".into());
            return;
        }
        let platform_ids: Vec<&str> = (0..4)
            .filter_map(|i| self.full_flash.get(&format!("DevicePlatformId{i}")))
            .collect();
        let mut parts = vec![format!("Manifest: {} B", self.size)];
        if let Some(version) = self.full_flash.get("Version") {
            parts.push(format!("manifest version {version}"));
            c.push_metadata("ffu_manifest_version", "Manifest version", version);
        }
        if let Some(os_version) = self.full_flash.get("OSVersion") {
            parts.push(format!("OS version {os_version}"));
            c.push_metadata("ffu_os_version", "OS version", os_version);
        }
        if !platform_ids.is_empty() {
            let ids = platform_ids.join(", ");
            parts.push(format!("device platform {ids}"));
            c.push_metadata("ffu_device_platform_ids", "Device platform IDs", ids);
        }
        parts.push(counted(
            self.stores.len() as u64,
            "store section",
            "store sections",
        ));
        let partitions: Vec<&Entries> = self
            .stores
            .iter()
            .flat_map(|store| &store.partitions)
            .collect();
        parts.push(partition_summary(&partitions));
        c.notes.push(parts.join("; "));
        for (i, partition) in partitions.iter().take(MAX_LISTED_PARTITIONS).enumerate() {
            c.push_metadata(
                format!("ffu_partition_{i}"),
                format!("Manifest partition {}", i + 1),
                describe_partition(partition),
            );
        }
        if self.cut {
            c.notes.push(format!(
                "Manifest parsing stopped after {MAX_SECTIONS} sections or {MAX_ENTRIES} entries"
            ));
        }
    }
}

/// "3 partitions: `EFIESP`, `MainOS`, `Data`", naming at most
/// [`MAX_NAMED_PARTITIONS`].
fn partition_summary(partitions: &[&Entries]) -> String {
    let count = counted(partitions.len() as u64, "partition", "partitions");
    let names: Vec<&str> = partitions
        .iter()
        .take(MAX_NAMED_PARTITIONS)
        .map(|partition| partition.get("Name").unwrap_or("(unnamed)"))
        .collect();
    if names.is_empty() {
        return count;
    }
    let more = partitions.len() - names.len();
    if more > 0 {
        format!("{count}: {} and {more} more", names.join(", "))
    } else {
        format!("{count}: {}", names.join(", "))
    }
}

/// A partition's name, type, size and filesystem, as the manifest gives
/// them.
fn describe_partition(partition: &Entries) -> String {
    let mut parts = vec![partition.get("Name").unwrap_or("(unnamed)").to_string()];
    if let Some(kind) = partition.get("Type") {
        parts.push(format!("type {kind}"));
    }
    if let Some(sectors) = partition.get("TotalSectors") {
        parts.push(format!("{sectors} sectors"));
    }
    if let Some(filesystem) = partition.get("FileSystem") {
        parts.push(format!("filesystem {filesystem}"));
    }
    parts.join("; ")
}

/// `bytes` without leading and trailing ASCII whitespace (CR included).
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] = b"[FullFlash]\r\nVersion           = 2.0\r\nOSVersion = 10.0.1\r\n\
        DevicePlatformId0 = Zrax.Test\r\n\r\n[StoragePool]\r\nName = OSPool\r\n\r\n\
        [Store]\r\nIsMainOSStore = True\r\nMinSectorCount = 320\r\nSectorSize = 512\r\n\r\n\
        [Partition]\r\nName = EFIESP\r\nType = {C12A7328-F81F-11D2-BA4B-00A0C93EC93B}\r\n\
        TotalSectors = 256\r\nFileSystem = FAT\r\n\r\n[store]\r\nsectorsize = 4096\r\n";

    #[test]
    fn store_sections_give_the_disk_size_and_main_os_flag() {
        let manifest = Manifest::parse(MANIFEST);
        assert_eq!(manifest.sections, 5);
        let first = manifest.store(0).unwrap();
        assert_eq!(
            first.disk_size(),
            DiskSize::Known(DiskGeometry {
                sectors: 320,
                sector_size: 512,
                bytes: 163_840
            })
        );
        assert!(first.is_main_os());
        let second = manifest.store(1).unwrap();
        assert_eq!(second.disk_size(), DiskSize::Missing);
        assert!(!second.is_main_os());
        assert!(manifest.store(2).is_none());
        assert_eq!(
            describe_partition(&first.partitions[0]),
            "EFIESP; type {C12A7328-F81F-11D2-BA4B-00A0C93EC93B}; 256 sectors; filesystem FAT"
        );
    }

    #[test]
    fn invalid_sizes_are_reported_not_used() {
        let manifest = Manifest::parse(b"[Store]\nMinSectorCount = 0x10\nSectorSize = 512\n");
        assert!(matches!(
            manifest.store(0).unwrap().disk_size(),
            DiskSize::Invalid(_)
        ));
        let zero = Manifest::parse(b"[Store]\nMinSectorCount = 0\nSectorSize = 512\n");
        assert!(matches!(
            zero.store(0).unwrap().disk_size(),
            DiskSize::Invalid(_)
        ));
    }

    #[test]
    fn partitions_before_any_store_belong_to_the_first_store() {
        let manifest = Manifest::parse(b"[Partition]\nName = A\n[Store]\nSectorSize = 512\n");
        assert_eq!(manifest.stores.len(), 1);
        assert_eq!(manifest.stores[0].partitions.len(), 1);
        assert_eq!(manifest.stores[0].entries.get("sectorsize"), Some("512"));
    }

    #[test]
    fn partition_summaries_name_a_bounded_number() {
        let entries: Vec<Entries> = (0..20)
            .map(|i| Entries {
                list: vec![Entry {
                    key: "Name".into(),
                    value: format!("P{i}"),
                }],
            })
            .collect();
        let refs: Vec<&Entries> = entries.iter().collect();
        assert_eq!(partition_summary(&refs[..2]), "2 partitions: P0, P1");
        assert!(partition_summary(&refs).ends_with("P15 and 4 more"));
        assert_eq!(partition_summary(&[]), "0 partitions");
    }

    #[test]
    fn trim_removes_ascii_whitespace_and_carriage_returns() {
        assert_eq!(trim(b"  Key = Value\r"), b"Key = Value");
        assert_eq!(trim(b" \r\t"), b"");
        assert_eq!(trim(b""), b"");
    }
}
