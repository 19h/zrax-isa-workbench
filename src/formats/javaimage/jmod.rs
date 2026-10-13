//! JMOD files (`JmodFile.java`, `JmodOutputStream.java`, `OpenJDK`
//! `jdk-21+35`).
//!
//! Layout: `JM` (`4A 4D`), major version 1, minor version 0, then a ZIP
//! archive to the end of the file. `JmodOutputStream` writes the four
//! header bytes to the underlying stream after creating its
//! `ZipOutputStream`, so the archive's own offsets count from file offset
//! 4 and the bytes from there are a complete ZIP. Its entries are
//! `<section>/<path>` with the sections `classes`, `conf`, `include`,
//! `legal`, `man`, `lib` and `bin` (`JmodFile.Section`).
//!
//! The ZIP archive is one child, which the ZIP parser lists; the JMOD
//! header names no ISA.

use super::*;

/// `JMOD_MAGIC_NUMBER`: `JM` and version 1.0.
const JMOD_MAGIC: [u8; 2] = *b"JM";
const JMOD_MAJOR_VERSION: u8 = 1;
const JMOD_MINOR_VERSION: u8 = 0;

/// JMOD header size; the ZIP archive starts here.
const HEADER_SIZE: usize = 4;

/// ZIP local file header signature (PKWARE APPNOTE.TXT 6.3.10, 4.3.7), the
/// first record of the archive `JmodOutputStream` writes.
const ZIP_LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";

/// Label of the ZIP archive child.
const ARCHIVE_LABEL: &str = "ZIP archive";

/// Strong recognition: `JM`, version 1.0 and a ZIP local file header.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let version_1_0 = [
        JMOD_MAGIC[0],
        JMOD_MAGIC[1],
        JMOD_MAJOR_VERSION,
        JMOD_MINOR_VERSION,
    ];
    let is_jmod =
        data.starts_with(&version_1_0) && data.get(HEADER_SIZE..)?.starts_with(&ZIP_LOCAL_HEADER);
    is_jmod.then_some(Layout::Jmod)
}

/// Parse a JMOD file: the header, which `JmodFile.checkMagic` accepts up
/// to version 1.0, and the ZIP archive after it.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, HEADER_SIZE, "JMOD header")?;
    if header[..2] != JMOD_MAGIC {
        return Err(error(format!(
            "Invalid JMOD magic {:02X} {:02X}",
            header[0], header[1]
        )));
    }
    let (major, minor) = (header[2], header[3]);
    if major > JMOD_MAJOR_VERSION || (major == JMOD_MAJOR_VERSION && minor > JMOD_MINOR_VERSION) {
        return Err(error(format!("Unsupported JMOD version {major}.{minor}")));
    }
    let archive = &data[HEADER_SIZE..];
    if !archive.starts_with(&ZIP_LOCAL_HEADER) {
        return Err(error(format!(
            "Missing ZIP local file header at 0x{HEADER_SIZE:X}"
        )));
    }
    let mut c = Container::new(FileFormat::Jmod, Layout::Jmod.label(), "jmod");
    c.consumed = data.len();
    c.notes.push(format!(
        "JMOD {major}.{minor}; the ZIP archive at 0x{HEADER_SIZE:X} ({} B) holds the module's \
         sections (classes, conf, include, legal, man, lib, bin)",
        archive.len()
    ));
    c.push_metadata("jmod_version", "JMOD version", format!("{major}.{minor}"));
    c.push_metadata(
        "jmod_archive_offset",
        "ZIP archive offset",
        HEADER_SIZE as u64,
    );
    c.children
        .push(Child::stored(ARCHIVE_LABEL, HEADER_SIZE, archive));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_version_1_0_and_a_zip_local_header() {
        assert_eq!(detect(b"JM\x01\x00PK\x03\x04"), Some(Layout::Jmod));
        assert_eq!(detect(b"JM\x01\x01PK\x03\x04"), None);
        assert_eq!(detect(b"JM\x01\x00PK\x05\x06"), None);
        assert_eq!(detect(b"JM\x01\x00"), None);
    }

    #[test]
    fn newer_versions_and_missing_archives_are_errors() {
        let newer = parse(b"JM\x01\x01PK\x03\x04").unwrap_err().to_string();
        assert!(newer.contains("Unsupported JMOD version 1.1"), "{newer}");
        let missing = parse(b"JM\x01\x00junk").unwrap_err().to_string();
        assert!(
            missing.contains("Missing ZIP local file header at 0x4"),
            "{missing}"
        );
        assert!(parse(b"JM\x01").is_err());
        assert!(parse(b"XX\x01\x00PK\x03\x04").is_err());
    }

    #[test]
    fn the_archive_is_one_child_at_offset_4() {
        let c = parse(b"JM\x00\x09PK\x03\x04rest").unwrap();
        assert_eq!(c.children.len(), 1);
        assert_eq!(c.children[0].label, ARCHIVE_LABEL);
        assert_eq!(c.children[0].offset, 4);
        assert_eq!(&c.children[0].data[..], b"PK\x03\x04rest");
        assert!(c.notes[0].starts_with("JMOD 0.9;"), "{}", c.notes[0]);
    }
}
