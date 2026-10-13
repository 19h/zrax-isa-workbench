//! Code partition directories (`$CPD`) and the `$MN2` manifests they list:
//! coreboot 25.09 `util/cbfstool/ifwitool.c` (`struct subpart_dir_header`,
//! `struct subpart_dir_entry`, `calc_checksum`, `struct manifest_header`),
//! `bpdt_formats/subpart_hdr_1.c`, `subpart_hdr_2.c` and
//! `subpart_entry_1.c` (the 25-bit offset and the Huffman flag), the
//! vendored `util/me_cleaner/me_cleaner.py` (the `.man` entry and
//! `check_mn2_tag`), and `MEAnalyzer` `MEA.py` (`CPD_Header_R2`, `cpd_chk`)
//! for the version 2 CRC-32.
//!
//! `ifwitool` only reports a checksum mismatch and `MEAnalyzer` keeps a
//! list of Intel images with known-bad `$CPD` checksums, so a mismatch is
//! a note rather than an error. Modules are listed by name; their contents
//! (code for the engine, compressed or signed) are opaque.

use super::*;
use crate::formats::checksum::crc32_update;
use std::fmt::Write as _;

/// `SUBPART_DIR_MARKER`.
const MARKER: &[u8; 4] = b"$CPD";

/// Header: marker, entry count (0x04), header version (0x08), entry
/// version (0x09), header length (0x0A), the version 1 checksum or a
/// reserved byte (0x0B), partition name (0x0C), and in version 2 the
/// CRC-32 (0x10).
const HEADER_SIZE_V1: usize = 0x10;
const HEADER_SIZE_V2: usize = 0x14;
const HEADER_VERSION_1: u8 = 1;
const HEADER_VERSION_2: u8 = 2;
const CRC_OFFSET: usize = 0x10;

/// `SUBPART_DIR_ENTRY_VERSION_SUPPORTED`.
const ENTRY_VERSION: u8 = 1;

/// Entry: name (12 bytes, not always NUL-terminated), offset and flags
/// (0x0C), length (0x10), reserved (0x14).
const ENTRY_SIZE: usize = 0x18;
const ENTRY_NAME_SIZE: usize = 12;

/// `SUBPART_OFFSET_MASK` and `SUBPART_COMPRESSED_SHIFT`: bits 24:0 are the
/// offset from the directory, bit 25 marks a Huffman-compressed module.
const OFFSET_MASK: u32 = 0x01FF_FFFF;
const HUFFMAN_FLAG: u32 = 1 << 25;

/// `MANIFEST_ID_MAGIC` at 0x1C of a manifest, and the version (four u16:
/// major, minor, hotfix, build) at 0x24 (`me_cleaner`, `MEA.py`).
pub(super) const MANIFEST_TAG: &[u8] = b"$MN2";
const MANIFEST_TAG_OFFSET: usize = 0x1C;
const MANIFEST_VERSION_OFFSET: usize = 0x24;
const MANIFEST_VERSION_END: usize = MANIFEST_VERSION_OFFSET + 8;

/// Partition manifests are the entries named `<partition>.man`.
const MANIFEST_SUFFIX: &str = ".man";

/// First note of a standalone code partition.
const PARTITION_NOTE: &str = "Code partition modules are firmware for the management engine, whose processor this directory does not identify; every module is opaque and excluded from ISA analysis";

/// The directory marker at offset 0.
pub(super) fn has_marker(data: &[u8]) -> bool {
    data.starts_with(MARKER)
}

/// One directory entry.
#[derive(Debug)]
struct Module {
    name: String,
    /// Offset from the start of the directory.
    offset: usize,
    length: usize,
    huffman: bool,
}

/// A parsed directory.
#[derive(Debug)]
pub(super) struct Directory {
    /// The partition name in the header.
    name: String,
    version: u8,
    modules: Vec<Module>,
    /// How the checksum was checked.
    checksum: String,
    /// The partition manifest: entry name and what its header says.
    manifest: Option<(String, String)>,
    /// Modules whose range lies outside the directory's bytes.
    outside: Vec<String>,
}

impl Directory {
    /// One line for a note: name, modules, checksum and manifest.
    pub(super) fn summary(&self) -> String {
        let names: Vec<String> = self.modules.iter().map(|m| m.name.clone()).collect();
        let mut summary = format!(
            "$CPD \"{}\" (header version {}), {}: {}; {}",
            self.name,
            self.version,
            plural(self.modules.len(), "module", "modules"),
            listed(&names),
            self.checksum
        );
        let huffman = self.modules.iter().filter(|m| m.huffman).count();
        if huffman > 0 {
            let _ = write!(
                summary,
                "; {} marked Huffman-compressed",
                plural(huffman, "module", "modules")
            );
        }
        match &self.manifest {
            Some((name, description)) => {
                let _ = write!(summary, "; manifest {name}: {description}");
            }
            None => summary.push_str("; no .man entry"),
        }
        if !self.outside.is_empty() {
            let _ = write!(
                summary,
                "; outside the partition: {}",
                listed(&self.outside)
            );
        }
        summary
    }

    /// Metadata for the `index`-th directory of a container.
    pub(super) fn push_metadata(&self, c: &mut Container<'_>, index: usize) {
        let names: Vec<String> = self.modules.iter().map(|m| m.name.clone()).collect();
        c.push_metadata(
            format!("{KEY_PREFIX}_cpd_{index}_name"),
            "Code partition name",
            self.name.clone(),
        );
        c.push_metadata(
            format!("{KEY_PREFIX}_cpd_{index}_modules"),
            format!("{} modules", self.name),
            listed(&names),
        );
        if let Some((name, description)) = &self.manifest {
            c.push_metadata(
                format!("{KEY_PREFIX}_cpd_{index}_manifest"),
                format!("{} manifest", self.name),
                format!("{name}: {description}"),
            );
        }
    }
}

/// Parse the directory at the start of `bytes`, a code partition.
pub(super) fn describe(bytes: &[u8]) -> Result<Directory> {
    let header = field(bytes, 0, HEADER_SIZE_V1, "$CPD header")?;
    if !has_marker(header) {
        return Err(error("Missing $CPD marker"));
    }
    let count = to_usize(le_u32(header, 0x04)?);
    let version = header[0x08];
    let entry_version = header[0x09];
    let length = usize::from(header[0x0A]);
    let header_size = match version {
        HEADER_VERSION_1 => HEADER_SIZE_V1,
        HEADER_VERSION_2 => HEADER_SIZE_V2,
        _ => {
            return Err(error(format!(
                "Unsupported $CPD header version {version} at 0x8"
            )))
        }
    };
    if length != header_size {
        return Err(error(format!(
            "Invalid $CPD header length 0x{length:02X} at 0xA: version {version} headers are 0x{header_size:02X} B"
        )));
    }
    if entry_version != ENTRY_VERSION {
        return Err(error(format!(
            "Unsupported $CPD entry version {entry_version} at 0x9"
        )));
    }
    let available = bytes.len().saturating_sub(header_size) / ENTRY_SIZE;
    if count > available {
        return Err(error(format!(
            "Truncated $CPD entry table: {count} entries of 24 B, room for {available}"
        )));
    }
    let table = field(
        bytes,
        0,
        header_size + count * ENTRY_SIZE,
        "$CPD entry table",
    )?;
    let checksum = match version {
        HEADER_VERSION_1 => sum8_status(table),
        _ => crc_status(table)?,
    };
    let entries = table.get(header_size..).unwrap_or_default();
    let mut modules = Vec::with_capacity(count);
    let mut outside = Vec::new();
    for entry in entries.chunks_exact(ENTRY_SIZE) {
        let raw_offset = le_u32(entry, 0x0C)?;
        let module = Module {
            name: ascii_name(&entry[..ENTRY_NAME_SIZE]),
            offset: to_usize(raw_offset & OFFSET_MASK),
            length: to_usize(le_u32(entry, 0x10)?),
            huffman: raw_offset & HUFFMAN_FLAG != 0,
        };
        if module_bytes(bytes, &module).is_none() {
            outside.push(module.name.clone());
        }
        modules.push(module);
    }
    let manifest = modules
        .iter()
        .find(|m| m.name.ends_with(MANIFEST_SUFFIX))
        .map(|m| (m.name.clone(), manifest_description(bytes, m)));
    Ok(Directory {
        name: ascii_name(&header[0x0C..0x10]),
        version,
        modules,
        checksum,
        manifest,
        outside,
    })
}

/// A module's bytes, when its range lies inside `bytes`.
fn module_bytes<'a>(bytes: &'a [u8], module: &Module) -> Option<&'a [u8]> {
    let end = module.offset.checked_add(module.length)?;
    bytes.get(module.offset..end)
}

/// Version 1: the header and entries sum to 0 (`ifwitool`
/// `calc_checksum`, two's complement of the 8-bit sum).
fn sum8_status(table: &[u8]) -> String {
    let sum = sum8(table);
    if sum == 0 {
        "8-bit checksum verified".to_string()
    } else {
        format!("8-bit checksum does not match (the directory sums to 0x{sum:02X}); not verified")
    }
}

/// Version 2: IEEE CRC-32 of the header and entries with the CRC field
/// zeroed (`MEA.py` `cpd_chk`).
fn crc_status(table: &[u8]) -> Result<String> {
    let stored = le_u32(table, CRC_OFFSET)?;
    let mut crc = crc32_update(!0, &table[..CRC_OFFSET]);
    crc = crc32_update(crc, &[0; 4]);
    let computed = !crc32_update(crc, &table[CRC_OFFSET + 4..]);
    Ok(if computed == stored {
        "CRC-32 verified".to_string()
    } else {
        format!("CRC-32 0x{stored:08X} does not match the computed 0x{computed:08X}; not verified")
    })
}

/// What the manifest module's header says: the `$MN2` tag and version, or
/// why it could not be read.
fn manifest_description(bytes: &[u8], module: &Module) -> String {
    let Some(manifest) = module_bytes(bytes, module) else {
        return "outside the partition".to_string();
    };
    if manifest.get(MANIFEST_TAG_OFFSET..MANIFEST_TAG_OFFSET + 4) != Some(MANIFEST_TAG) {
        return "no $MN2 tag at 0x1C".to_string();
    }
    match manifest_version(manifest, 0) {
        Some(version) => {
            format!("$MN2 tag, version {version}; RSA signature present, not verified")
        }
        None => "$MN2 tag; header truncated before the version".to_string(),
    }
}

/// The manifest version at `offset + 0x24`: major, minor, hotfix and build
/// as four u16.
pub(super) fn manifest_version(bytes: &[u8], offset: usize) -> Option<String> {
    let start = offset.checked_add(MANIFEST_VERSION_OFFSET)?;
    let end = offset.checked_add(MANIFEST_VERSION_END)?;
    let version = bytes.get(start..end)?;
    let parts: Vec<String> = version
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]).to_string())
        .collect();
    Some(parts.join("."))
}

/// Parse a standalone code partition: the directory, with every module
/// inside the file listed as an opaque component.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let directory = describe(data)?;
    let mut c = Container::new(FileFormat::IntelMe, Layout::IntelCpd.label(), KEY_PREFIX);
    c.notes.push(PARTITION_NOTE.to_string());
    c.notes.push(directory.summary());
    directory.push_metadata(&mut c, 0);
    let mut listing = Listing::default();
    for module in &directory.modules {
        let Some(bytes) = module_bytes(data, module) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let label = format!("Module {}", module.name);
        listing.push(&mut c, Child::opaque(label, module.offset, bytes));
    }
    c.consumed = data.len();
    listing.finish(&mut c);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_versions_are_four_u16() {
        let mut manifest = vec![0u8; 0x2C];
        for (i, part) in [11u16, 8, 50, 3399].iter().enumerate() {
            let at = MANIFEST_VERSION_OFFSET + 2 * i;
            manifest[at..at + 2].copy_from_slice(&part.to_le_bytes());
        }
        assert_eq!(
            manifest_version(&manifest, 0).as_deref(),
            Some("11.8.50.3399")
        );
        assert_eq!(manifest_version(&manifest[..0x2B], 0), None);
    }

    #[test]
    fn version_1_checksums_are_reported_not_enforced() {
        assert_eq!(sum8_status(&[0x01, 0xFF]), "8-bit checksum verified");
        assert!(sum8_status(&[0x01]).contains("does not match"));
    }
}
