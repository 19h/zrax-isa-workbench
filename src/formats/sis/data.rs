//! `SISData`: the data units and their stored files (specification
//! section 4.5), and the files in a recognized format as children labeled
//! by the target path of the `SISFileDescription` that names them.

use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use controller::FileDescription;
use std::collections::BTreeMap;

/// Bytes at the start of a file that are decoded and checked for a
/// recognized format before the whole file is.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// A `SISDataUnit`: the stored files of one controller (section 4.5.2).
#[derive(Debug)]
pub(super) struct DataUnit<'a> {
    /// Each `SISFileData`'s `SISCompressed`, in file-index order.
    pub(super) files: Vec<Compressed<'a>>,
}

/// The data units of `SISData`: a `SISArray<SISDataUnit>`, each unit a
/// `SISArray<SISFileData>`, each file a `SISCompressed` stored with its
/// type (the installer's `CFileData` reads it with `EReadType`).
pub(super) fn units<'a>(file: Buffer<'a>, data: &Field<'a>) -> Result<Vec<DataUnit<'a>>> {
    let mut units = Vec::new();
    for unit in Members::of(file, data).array(FieldType::DATA_UNIT)? {
        let mut files = Vec::new();
        for file_data in Members::of(file, &unit).array(FieldType::FILE_DATA)? {
            let stored = Members::of(file, &file_data).field(FieldType::COMPRESSED)?;
            files.push(Compressed::read(file, &stored)?);
        }
        units.push(DataUnit { files });
    }
    Ok(units)
}

/// A stored file: its absolute data unit and its index in that unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileKey {
    unit: u64,
    index: u64,
}

/// Every file description of `package` and its embedded controllers by the
/// file it names. A controller's data unit is the sum of the data indices
/// from the outermost controller down to it (specification sections 2.8
/// and 4.1.12). The first description of a file names it.
fn descriptions<'p>(
    package: &'p Controller,
    base: u64,
    out: &mut BTreeMap<FileKey, &'p FileDescription>,
) {
    let unit = base.saturating_add(u64::from(package.data_index));
    for description in &package.files {
        let key = FileKey {
            unit,
            index: u64::from(description.file_index),
        };
        out.entry(key).or_insert(description);
    }
    for embedded in &package.embedded {
        descriptions(embedded, unit, out);
    }
}

/// The bytes of a file to classify and the codec that produced them.
#[derive(Debug)]
struct Contents<'a> {
    data: Cow<'a, [u8]>,
    transform: Option<&'static str>,
}

/// What listing the stored files found, for notes.
#[derive(Debug, Default)]
pub(super) struct Summary {
    /// Stored files in all data units.
    stored: usize,
    /// File descriptions in all controllers.
    described: usize,
    /// Targets of the file descriptions.
    targets: NameList,
    /// File descriptions that name no stored file.
    unmatched: usize,
    /// Stored files checked for a recognized format.
    examined: usize,
    /// Stored files listed as children.
    listed: usize,
    /// Stored files not examined because [`MAX_COMPONENTS`] were listed.
    unexamined: usize,
    /// Decoded bytes so far, counted against [`MAX_EXTRACTED`].
    decoded_size: usize,
    /// Files over the extraction limits.
    undecoded: NameList,
    /// Files whose stored bytes do not decode to their declared size.
    failed: NameList,
    /// Files stored with an algorithm other than none or deflate.
    unsupported: NameList,
    /// Listed files whose SHA-1 equals their `SISHash`.
    hashes_matched: usize,
    /// Listed files whose SHA-1 differs from their `SISHash`.
    hashes_differ: NameList,
}

/// List the stored files in a recognized format as children: the package's
/// own data unit first, then the units of embedded packages in stored
/// order.
pub(super) fn extract<'a>(
    c: &mut Container<'a>,
    units: &[DataUnit<'a>],
    package: &Controller,
) -> Summary {
    let mut named = BTreeMap::new();
    descriptions(package, 0, &mut named);
    let mut summary = Summary {
        described: controller::description_count(package),
        ..Summary::default()
    };
    for description in named.values() {
        if !description.target.is_empty() {
            summary.targets.push(description.target.clone());
        }
    }
    summary.unmatched = named
        .keys()
        .filter(|key| stored_file(units, **key).is_none())
        .count();
    let main = usize::try_from(package.data_index)
        .ok()
        .filter(|unit| *unit < units.len());
    let others = (0..units.len()).filter(|unit| Some(*unit) != main);
    for unit in main.into_iter().chain(others) {
        for (index, stored) in units[unit].files.iter().enumerate() {
            let key = FileKey {
                unit: unit as u64,
                index: index as u64,
            };
            summary.offer(c, key, stored, named.get(&key).copied());
        }
    }
    summary
}

/// The stored file `key` names, if there is one.
fn stored_file<'u, 'a>(units: &'u [DataUnit<'a>], key: FileKey) -> Option<&'u Compressed<'a>> {
    let unit = units.get(usize::try_from(key.unit).ok()?)?;
    unit.files.get(usize::try_from(key.index).ok()?)
}

/// The child label: the description's target, or the file's place when no
/// description installs it.
fn label(key: FileKey, description: Option<&FileDescription>) -> String {
    match description {
        Some(description) if !description.target.is_empty() => description.target.clone(),
        Some(description) if description.logo => {
            format!("Logo (data unit {} file {})", key.unit, key.index)
        }
        _ => format!("Data unit {} file {}", key.unit, key.index),
    }
}

impl Summary {
    /// List the stored file `key` when its first bytes, and then its whole
    /// contents, are a recognized format, within the component and
    /// extraction limits.
    fn offer<'a>(
        &mut self,
        c: &mut Container<'a>,
        key: FileKey,
        stored: &Compressed<'a>,
        description: Option<&FileDescription>,
    ) {
        self.stored += 1;
        if c.children.len() >= MAX_COMPONENTS {
            self.unexamined += 1;
            return;
        }
        let label = label(key, description);
        let Some(contents) = self.contents(stored, &label) else {
            return;
        };
        if let Some(expected) = description.and_then(|description| description.sha1) {
            let mut sha1 = checksum::Sha1::new();
            sha1.update(&contents.data);
            if sha1.finish() == expected {
                self.hashes_matched += 1;
            } else {
                self.hashes_differ.push(label.clone());
            }
        }
        let child = match contents.transform {
            Some(transform) => Child::decoded(
                label,
                stored.offset,
                stored.bytes.len(),
                contents.data,
                transform,
            ),
            None => Child::stored(label, stored.offset, stored.bytes),
        };
        c.children.push(child.if_recognized());
        self.listed += 1;
    }

    /// The file's bytes when they are a recognized format: stored files as
    /// they are, deflated files decoded to exactly their declared size.
    /// Other files give `None`; failures and limits are tallied.
    fn contents<'a>(&mut self, stored: &Compressed<'a>, label: &str) -> Option<Contents<'a>> {
        match stored.algorithm {
            COMPRESS_NONE => {
                self.examined += 1;
                self.stored_contents(stored, label)
            }
            COMPRESS_DEFLATE => {
                self.examined += 1;
                self.deflated_contents(stored, label)
            }
            other => {
                self.unsupported
                    .push(format!("{label} (algorithm {other})"));
                None
            }
        }
    }

    /// An uncompressed file, which must store exactly its declared size as
    /// the installer requires (`KErrSISFieldLengthInvalid`).
    fn stored_contents<'a>(
        &mut self,
        stored: &Compressed<'a>,
        label: &str,
    ) -> Option<Contents<'a>> {
        if stored.uncompressed_size != stored.bytes.len() as u64 {
            self.failed.push(format!(
                "{label} (stores {} B, declares {} B)",
                stored.bytes.len(),
                stored.uncompressed_size
            ));
            return None;
        }
        let prefix = &stored.bytes[..stored.bytes.len().min(RECOGNITION_PREFIX)];
        if !container::is_recognized(prefix) || !container::is_recognized(stored.bytes) {
            return None;
        }
        Some(Contents {
            data: Cow::Borrowed(stored.bytes),
            transform: None,
        })
    }

    /// A zlib-compressed file: its first bytes are decoded and checked
    /// before the whole file is decoded within the extraction limits.
    fn deflated_contents<'a>(
        &mut self,
        stored: &Compressed<'a>,
        label: &str,
    ) -> Option<Contents<'a>> {
        let prefix = match compressed::decode_prefix(Codec::Zlib, stored.bytes, RECOGNITION_PREFIX)
        {
            Ok(prefix) => prefix,
            Err(e) => {
                self.failed.push(format!("{label} ({})", codec_message(&e)));
                return None;
            }
        };
        if !container::is_recognized(&prefix) {
            return None;
        }
        let size = self.reserve(label, stored.uncompressed_size)?;
        let decoded = match compressed::decode_limited(Codec::Zlib, stored.bytes, size) {
            Ok(decoded) => decoded.data,
            Err(e) => {
                self.failed.push(format!("{label} ({})", codec_message(&e)));
                return None;
            }
        };
        if decoded.len() != size {
            self.failed.push(format!(
                "{label} (decodes to {} B, declares {size} B)",
                decoded.len()
            ));
            return None;
        }
        if !container::is_recognized(&decoded) {
            return None;
        }
        Some(Contents {
            data: Cow::Owned(decoded),
            transform: Some(Codec::Zlib.name()),
        })
    }

    /// Reserve `size` decoded bytes for `label`. `None`, with the file
    /// recorded as not decoded, when the file exceeds [`MAX_PAYLOAD`] or the
    /// package would exceed [`MAX_EXTRACTED`].
    fn reserve(&mut self, label: &str, size: u64) -> Option<usize> {
        let reserved = usize::try_from(size)
            .ok()
            .filter(|size| *size <= MAX_PAYLOAD)
            .filter(|size| {
                self.decoded_size
                    .checked_add(*size)
                    .is_some_and(|total| total <= MAX_EXTRACTED)
            });
        let Some(reserved) = reserved else {
            self.undecoded.push(format!("{label} ({size} B)"));
            return None;
        };
        self.decoded_size += reserved;
        Some(reserved)
    }

    /// Notes for the descriptions, the listed files, their hashes, and the
    /// limits and failures met.
    pub(super) fn push_notes(&self, c: &mut Container<'_>, units: usize) {
        if units == 0 {
            c.notes
                .push("Stub package: SISData holds no data units, so no files".to_string());
        } else {
            c.notes.push(format!(
                "{} in {}; {}",
                count(self.stored, "stored file", "stored files"),
                count(units, "data unit", "data units"),
                count(self.described, "file description", "file descriptions")
            ));
        }
        if !self.targets.is_empty() {
            c.notes.push(format!("Install targets: {}", self.targets));
        }
        if self.examined > 0 {
            c.notes.push(format!(
                "{} of {} examined stored files are in a recognized format and listed",
                self.listed, self.examined
            ));
        }
        if self.hashes_matched > 0 {
            c.notes.push(format!(
                "SHA-1 of {} matches the SISHash",
                count(self.hashes_matched, "listed file", "listed files")
            ));
        }
        if !self.hashes_differ.is_empty() {
            c.notes.push(format!(
                "SHA-1 does not match the SISHash for: {}",
                self.hashes_differ
            ));
        }
        if self.unmatched > 0 {
            c.notes.push(format!(
                "{} no stored file",
                count(
                    self.unmatched,
                    "file description names",
                    "file descriptions name"
                )
            ));
        }
        if !self.failed.is_empty() {
            c.notes
                .push(format!("Stored files that do not decode: {}", self.failed));
        }
        if !self.unsupported.is_empty() {
            c.notes.push(format!(
                "Stored files with an unsupported SISCompressed algorithm were not examined: {}",
                self.unsupported
            ));
        }
        if !self.undecoded.is_empty() {
            c.notes.push(format!(
                "Stored files over the extraction limits ({} MiB per file, {} MiB per package) \
                 were not decoded or classified: {}",
                MAX_PAYLOAD >> 20,
                MAX_EXTRACTED >> 20,
                self.undecoded
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "File listing stopped at {MAX_COMPONENTS} listed files; {} not examined",
                count(
                    self.unexamined,
                    "further stored file was",
                    "further stored files were"
                )
            ));
        }
    }

    /// Stored files in all data units.
    pub(super) fn stored(&self) -> usize {
        self.stored
    }
}
