//! `SISController`: package identity, install blocks with their file
//! descriptions, embedded packages, signatures and the data index
//! (specification sections 4.2.4-4.4.3; the installer's
//! `CController::ConstructL`, `CInfo`, `CInstallBlock`, `CIf`, `CElseIf`
//! and `CFileDescription`).

use super::*;

/// The most levels of embedded `SISController`s the installer processes
/// (specification sections 2.5 and 2.11).
const MAX_EMBEDDING: usize = 8;

/// The most nested `SISIf`/`SISElseIf` install blocks in one controller.
/// Our bound: the specification sets none, and each level is a recursion.
const MAX_BLOCK_DEPTH: usize = 32;

/// `TInstallType` names (`installtypes.h`), with the package-file
/// abbreviations of specification section 4.2.5.8.
const INSTALL_TYPES: [&str; 5] = [
    "SA (installation)",
    "SP (augmentation)",
    "PU (partial upgrade)",
    "PA (preinstalled application)",
    "PP (preinstalled patch)",
];

/// `ESISHashAlgSHA1`, the only `TSISHashAlgorithm`.
const HASH_SHA1: u32 = 1;

/// A `SISVersion`: major, minor and build, each -1 for "any" (section
/// 4.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Version {
    major: i32,
    minor: i32,
    build: i32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

/// A `SISDateTime` in UTC (sections 4.1.6-4.1.8). Months count from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DateTime {
    year: u16,
    month: u8,
    day: u8,
    hours: u8,
    minutes: u8,
    seconds: u8,
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year,
            u16::from(self.month) + 1,
            self.day,
            self.hours,
            self.minutes,
            self.seconds
        )
    }
}

/// `SISInfo` (section 4.2.5).
#[derive(Debug)]
pub(super) struct Info {
    /// The package UID (`SISUid`).
    pub(super) uid: u32,
    /// The non-localized vendor name.
    pub(super) unique_vendor: String,
    /// The package name in the first supported language.
    pub(super) name: Option<String>,
    /// The vendor name in the first supported language.
    pub(super) vendor_name: Option<String>,
    pub(super) version: Version,
    /// Creation time; not a secure time stamp (section 4.2.5.7).
    pub(super) created: DateTime,
    pub(super) install_type: u8,
    pub(super) install_flags: u8,
}

impl Info {
    /// The install type with its package-file abbreviation.
    pub(super) fn install_type_text(&self) -> String {
        INSTALL_TYPES
            .get(usize::from(self.install_type))
            .map_or_else(
                || format!("{} (unknown)", self.install_type),
                |name| (*name).to_string(),
            )
    }
}

/// A `SISFileDescription` (section 4.2.14).
#[derive(Debug)]
pub(super) struct FileDescription {
    /// Install path; empty when the file is not installed.
    pub(super) target: String,
    /// SHA-1 of the uncompressed file, when the `SISHash` is SHA-1.
    pub(super) sha1: Option<[u8; 20]>,
    /// Index of the `SISFileData` in the controller's data unit.
    pub(super) file_index: u32,
    /// The description of the installation logo (`SISLogo`).
    pub(super) logo: bool,
}

/// A parsed `SISController` and the controllers embedded in it.
#[derive(Debug)]
pub(super) struct Controller {
    pub(super) info: Info,
    /// Entries of `SISSupportedLanguages`.
    pub(super) languages: usize,
    /// File descriptions of every install block, the logo's first.
    pub(super) files: Vec<FileDescription>,
    /// Embedded packages, in install-block order.
    pub(super) embedded: Vec<Controller>,
    pub(super) signature_chains: usize,
    /// `SISDataIndex`: relative to the embedding controller's data unit.
    pub(super) data_index: u32,
}

/// How deep the reader is in embedded controllers and conditional install
/// blocks.
#[derive(Debug, Clone, Copy)]
struct Nesting {
    embedding: usize,
    blocks: usize,
}

/// Parse the decoded `SISController`.
pub(super) fn parse(bytes: &[u8]) -> Result<Controller> {
    let buffer = Buffer::controller(bytes);
    let field = buffer.field(0, bytes.len(), Header::Typed(FieldType::CONTROLLER))?;
    controller(buffer, &field, 0)
}

/// A controller's members in the order the installer reads them: the
/// logo is optional, then any number of signature certificate chains end
/// at the data index.
fn controller(buffer: Buffer<'_>, field: &Field<'_>, embedding: usize) -> Result<Controller> {
    let mut members = Members::of(buffer, field);
    let info = info(buffer, &members.field(FieldType::INFO)?)?;
    members.field(FieldType::SUPPORTED_OPTIONS)?;
    let languages = Members::of(buffer, &members.field(FieldType::SUPPORTED_LANGUAGES)?)
        .array(FieldType::LANGUAGE)?
        .len();
    members.field(FieldType::PREREQUISITES)?;
    members.field(FieldType::PROPERTIES)?;
    let mut contents = BlockContents::default();
    if let Some(logo) = members.optional(FieldType::LOGO)? {
        let description = Members::of(buffer, &logo).field(FieldType::FILE_DESCRIPTION)?;
        contents
            .files
            .push(file_description(buffer, &description, true)?);
    }
    let install_block = members.field(FieldType::INSTALL_BLOCK)?;
    let nesting = Nesting {
        embedding,
        blocks: 0,
    };
    read_install_block(buffer, &install_block, nesting, &mut contents)?;
    let mut signature_chains = 0;
    while members
        .optional(FieldType::SIGNATURE_CERTIFICATE_CHAIN)?
        .is_some()
    {
        signature_chains += 1;
    }
    let data_index = Members::of(buffer, &members.field(FieldType::DATA_INDEX)?)
        .u32(FieldType::DATA_INDEX.name())?;
    Ok(Controller {
        info,
        languages,
        files: contents.files,
        embedded: contents.embedded,
        signature_chains,
        data_index,
    })
}

/// `SISInfo`: the UID, the vendor's unique name, the localized names and
/// vendor names, the version, the creation time, the install type and
/// flags.
fn info(buffer: Buffer<'_>, field: &Field<'_>) -> Result<Info> {
    let mut members = Members::of(buffer, field);
    let uid = Members::of(buffer, &members.field(FieldType::UID)?).u32(FieldType::UID.name())?;
    let unique_vendor = text(buffer, &members.field(FieldType::STRING)?)?;
    let name = first_text(buffer, &members.array(FieldType::STRING)?)?;
    let vendor_name = first_text(buffer, &members.array(FieldType::STRING)?)?;
    let version = version(buffer, &members.field(FieldType::VERSION)?)?;
    let created = date_time(buffer, &members.field(FieldType::DATE_TIME)?)?;
    let install_type = members.u8("SISInfo install type")?;
    let install_flags = members.u8("SISInfo install flags")?;
    Ok(Info {
        uid,
        unique_vendor,
        name,
        vendor_name,
        version,
        created,
        install_type,
        install_flags,
    })
}

/// The first of a `SISArray<SISString>`, after checking every element is a
/// valid string as the installer does.
fn first_text(buffer: Buffer<'_>, strings: &[Field<'_>]) -> Result<Option<String>> {
    for string in strings {
        check_string(buffer, string)?;
    }
    strings.first().map(|first| text(buffer, first)).transpose()
}

fn version(buffer: Buffer<'_>, field: &Field<'_>) -> Result<Version> {
    let mut members = Members::of(buffer, field);
    let mut component = |what: &str| -> Result<i32> {
        let bytes = members.bytes(4, what)?;
        Ok(i32::from_le_bytes(
            bytes.try_into().expect("bytes returns exactly 4 bytes"),
        ))
    };
    Ok(Version {
        major: component("SISVersion major")?,
        minor: component("SISVersion minor")?,
        build: component("SISVersion build")?,
    })
}

/// `SISDateTime`: a `SISDate` (u16 year, u8 month, u8 day) and a `SISTime`
/// (u8 hours, minutes, seconds).
fn date_time(buffer: Buffer<'_>, field: &Field<'_>) -> Result<DateTime> {
    let mut members = Members::of(buffer, field);
    let mut date = Members::of(buffer, &members.field(FieldType::DATE)?);
    let year = date.u16("SISDate year")?;
    let month = date.u8("SISDate month")?;
    let day = date.u8("SISDate day")?;
    let mut time = Members::of(buffer, &members.field(FieldType::TIME)?);
    Ok(DateTime {
        year,
        month,
        day,
        hours: time.u8("SISTime hours")?,
        minutes: time.u8("SISTime minutes")?,
        seconds: time.u8("SISTime seconds")?,
    })
}

/// What one controller's install blocks hold, collected across its
/// conditional blocks.
#[derive(Debug, Default)]
struct BlockContents {
    files: Vec<FileDescription>,
    embedded: Vec<Controller>,
}

/// `SISInstallBlock`: file descriptions, embedded controllers and `SISIf`
/// blocks, each `SISIf` with an expression, an install block and its
/// `SISElseIf`s. Every branch is collected: which one installs depends on
/// the device.
fn read_install_block(
    buffer: Buffer<'_>,
    field: &Field<'_>,
    nesting: Nesting,
    out: &mut BlockContents,
) -> Result<()> {
    if nesting.blocks > MAX_BLOCK_DEPTH {
        return Err(error(format!(
            "Unsupported SISInstallBlock nesting deeper than {MAX_BLOCK_DEPTH} levels at {}",
            buffer.at(field.start)
        )));
    }
    let mut members = Members::of(buffer, field);
    for description in members.array(FieldType::FILE_DESCRIPTION)? {
        out.files
            .push(file_description(buffer, &description, false)?);
    }
    for embedded in members.array(FieldType::CONTROLLER)? {
        if nesting.embedding >= MAX_EMBEDDING {
            return Err(error(format!(
                "Unsupported SIS embedding deeper than {MAX_EMBEDDING} levels at {}",
                buffer.at(embedded.start)
            )));
        }
        out.embedded
            .push(controller(buffer, &embedded, nesting.embedding + 1)?);
    }
    let deeper = Nesting {
        blocks: nesting.blocks + 1,
        ..nesting
    };
    for condition in members.array(FieldType::IF)? {
        let mut parts = Members::of(buffer, &condition);
        parts.field(FieldType::EXPRESSION)?;
        read_install_block(buffer, &parts.field(FieldType::INSTALL_BLOCK)?, deeper, out)?;
        for alternative in parts.array(FieldType::ELSE_IF)? {
            let mut parts = Members::of(buffer, &alternative);
            parts.field(FieldType::EXPRESSION)?;
            read_install_block(buffer, &parts.field(FieldType::INSTALL_BLOCK)?, deeper, out)?;
        }
    }
    Ok(())
}

/// `SISFileDescription`: target, MIME type, the optional capabilities, the
/// hash, operation and options, the stored and uncompressed lengths and
/// the file index.
fn file_description(buffer: Buffer<'_>, field: &Field<'_>, logo: bool) -> Result<FileDescription> {
    let mut members = Members::of(buffer, field);
    let target = text(buffer, &members.field(FieldType::STRING)?)?;
    check_string(buffer, &members.field(FieldType::STRING)?)?;
    if let Some(capabilities) = members.optional(FieldType::CAPABILITIES)? {
        // A bit field in 32-bit words (section 4.2.15; the installer
        // rejects other lengths).
        if capabilities.value.len() % 4 != 0 {
            return Err(error(format!(
                "Invalid SISCapabilities length {} B at {}: not a multiple of 4",
                capabilities.value.len(),
                buffer.at(capabilities.start)
            )));
        }
    }
    let sha1 = hash(buffer, &members.field(FieldType::HASH)?)?;
    members.u32("SISFileDescription operation")?;
    members.u32("SISFileDescription operation options")?;
    members.u64("SISFileDescription length")?;
    members.u64("SISFileDescription uncompressed length")?;
    let file_index = members.u32("SISFileDescription file index")?;
    Ok(FileDescription {
        target,
        sha1,
        file_index,
        logo,
    })
}

/// `SISHash`: the algorithm and a `SISBlob` with the digest. Only SHA-1 is
/// defined (section 4.2.16).
fn hash(buffer: Buffer<'_>, field: &Field<'_>) -> Result<Option<[u8; 20]>> {
    let mut members = Members::of(buffer, field);
    let algorithm = members.u32("SISHash algorithm")?;
    let digest = members.field(FieldType::BLOB)?;
    Ok((algorithm == HASH_SHA1)
        .then(|| <[u8; 20]>::try_from(digest.value).ok())
        .flatten())
}

/// File descriptions in `package` and every controller embedded in it.
pub(super) fn description_count(package: &Controller) -> usize {
    package.files.len()
        + package
            .embedded
            .iter()
            .map(description_count)
            .sum::<usize>()
}

/// Controllers embedded in `package`, at any depth.
pub(super) fn embedded_count(package: &Controller) -> usize {
    package.embedded.len() + package.embedded.iter().map(embedded_count).sum::<usize>()
}

/// Names, UIDs and versions of the controllers embedded directly in
/// `package`, for a note.
pub(super) fn embedded_names(package: &Controller) -> NameList {
    let mut names = NameList::default();
    for embedded in &package.embedded {
        names.push(format!(
            "\"{}\" (UID 0x{:08X}, version {})",
            embedded.info.name.as_deref().unwrap_or_default(),
            embedded.info.uid,
            embedded.info.version
        ));
    }
    names
}
