//! Symbian OS v9 SIS packages: the file header and its UID checksum, the
//! `SISField` encoding, compressed and stored controllers, install blocks
//! with conditional branches and logos, embedded packages and their summed
//! data indices, files listed as children under their target paths with
//! stored offsets and decoded ranges, CRC-16 and SHA-1 checks, signature
//! reporting, structure errors, component and extraction limits, and
//! truncation and mutation sweeps. IDA's SIS test inputs are read from
//! `IDA_INPUT_DIR` when it is set.

#[path = "support/e32_image.rs"]
mod e32;

use std::path::PathBuf;
use zrax::formats::checksum::Sha1;
use zrax::formats::sis;
use zrax::{
    detect_payload, ClassifierOptions, ContainedArch, DetectionPayload, Endianness, FileFormat,
    Isa, MetadataKey,
};

/// Compiled little-endian 32-bit Arm code from the repository's testbins.
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/arm32_arm-unknown-linux-gnueabi_O0_call_nested.bin"
);

// SISField types (specification Appendix A).
const SIS_STRING: u32 = 1;
const SIS_ARRAY: u32 = 2;
const SIS_COMPRESSED: u32 = 3;
const SIS_VERSION: u32 = 4;
const SIS_DATE: u32 = 6;
const SIS_TIME: u32 = 7;
const SIS_DATE_TIME: u32 = 8;
const SIS_UID: u32 = 9;
const SIS_LANGUAGE: u32 = 11;
const SIS_CONTENTS: u32 = 12;
const SIS_CONTROLLER: u32 = 13;
const SIS_INFO: u32 = 14;
const SIS_SUPPORTED_LANGUAGES: u32 = 15;
const SIS_SUPPORTED_OPTIONS: u32 = 16;
const SIS_PREREQUISITES: u32 = 17;
const SIS_DEPENDENCY: u32 = 18;
const SIS_PROPERTIES: u32 = 19;
const SIS_PROPERTY: u32 = 20;
const SIS_CERTIFICATE_CHAIN: u32 = 22;
const SIS_LOGO: u32 = 23;
const SIS_FILE_DESCRIPTION: u32 = 24;
const SIS_HASH: u32 = 25;
const SIS_IF: u32 = 26;
const SIS_ELSE_IF: u32 = 27;
const SIS_INSTALL_BLOCK: u32 = 28;
const SIS_EXPRESSION: u32 = 29;
const SIS_DATA: u32 = 30;
const SIS_DATA_UNIT: u32 = 31;
const SIS_FILE_DATA: u32 = 32;
const SIS_SUPPORTED_OPTION: u32 = 33;
const SIS_CONTROLLER_CHECKSUM: u32 = 34;
const SIS_DATA_CHECKSUM: u32 = 35;
const SIS_SIGNATURE: u32 = 36;
const SIS_BLOB: u32 = 37;
const SIS_SIGNATURE_ALGORITHM: u32 = 38;
const SIS_SIGNATURE_CERTIFICATE_CHAIN: u32 = 39;
const SIS_DATA_INDEX: u32 = 40;
const SIS_CAPABILITIES: u32 = 41;

/// UID1 of every SIS 9 file (specification section 3.1.1).
const SISX_UID1: u32 = 0x1020_1A7A;
/// `TCompressionAlgorithm`.
const COMPRESS_NONE: u32 = 0;
const COMPRESS_DEFLATE: u32 = 1;
/// `ESISHashAlgSHA1`.
const HASH_SHA1: u32 = 1;
/// `TSISFileOperation`: install the file, or display it as text.
const OP_INSTALL: u32 = 1;
const OP_TEXT: u32 = 4;
/// `TLanguage` `ELangEnglish`.
const ENGLISH: u32 = 1;
/// `TOperator` `EPrimTypeNumber`: a constant expression.
const PRIM_TYPE_NUMBER: u32 = 16;
/// "SHA-1 with RSA signature" (specification section 4.3.4.1).
const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";

const PACKAGE_UID: u32 = 0xA000_1234;
const EXE_TARGET: &str = "!:\\sys\\bin\\hello.exe";
const RSC_TARGET: &str = "!:\\resource\\apps\\hello.rsc";

fn arm_code() -> Vec<u8> {
    std::fs::read(ARM_CODE).expect("testbin is committed")
}

/// CRC-16 with polynomial 0x1021, initial value 0, no reflection and no
/// final XOR: the "ZModem" CRC that MakeSIS's `DoTheCrc` documents.
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

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

/// Zero padding to the next 4-byte boundary (specification section 2.12.2).
fn pad(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}

/// A `SISArray` element: a 31-bit little-endian length, the value and its
/// padding, without the type (section 4.1.2).
fn element(value: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(value.len())
        .expect("small test field")
        .to_le_bytes()
        .to_vec();
    out.extend_from_slice(value);
    pad(&mut out);
    out
}

/// A `SISField`: the 32-bit type, then the element form (section 2.12).
fn field(kind: u32, value: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend(element(value));
    out
}

/// A `SISArray`: the element type, then each element's value without its
/// type (section 4.1.2).
fn array(element_type: u32, values: &[Vec<u8>]) -> Vec<u8> {
    let mut value = element_type.to_le_bytes().to_vec();
    for item in values {
        value.extend(element(item));
    }
    field(SIS_ARRAY, &value)
}

/// UCS-2 little-endian text, the value of a `SISString` (section 4.1.1).
fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn string(text: &str) -> Vec<u8> {
    field(SIS_STRING, &utf16(text))
}

/// The UID checksum: CRC-16 of the UIDs' odd bytes in the high half, of
/// their even bytes in the low half (section 3.1.4; `Parser::CheckUidCrc`).
fn uid_checksum(uids: &[u8]) -> u32 {
    let even: Vec<u8> = uids.iter().step_by(2).copied().collect();
    let odd: Vec<u8> = uids.iter().skip(1).step_by(2).copied().collect();
    (u32::from(crc16(&odd)) << 16) | u32::from(crc16(&even))
}

/// The Symbian file header: UID1 `0x10201A7A`, UID2 0, UID3 and the UID
/// checksum (section 3.1).
fn file_header(uid3: u32) -> Vec<u8> {
    let mut header = SISX_UID1.to_le_bytes().to_vec();
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&uid3.to_le_bytes());
    let checksum = uid_checksum(&header);
    header.extend_from_slice(&checksum.to_le_bytes());
    header
}

/// A synthetic E32 executable: a V header (UID1 0x1000007A, UID2
/// 0x100039CE, UID3, a valid UID checksum and header CRC, CPU
/// `ECpuArmV5`) followed by `code` as the code part
/// (`tests/support/e32_image.rs`).
fn e32_image(uid3: u32, code: &[u8]) -> Vec<u8> {
    e32::Image::arm_v5(uid3, code).build()
}

/// A compiled resource file: the resource UID 0x101F4A6B and data, in no
/// format the classifier recognizes.
fn resource_file() -> Vec<u8> {
    let mut file = 0x101F_4A6Bu32.to_le_bytes().to_vec();
    file.extend_from_slice(&[0, 0, 0, 0]);
    file.extend(b"Hello resource strings".iter().map(|b| b ^ 0x5A));
    file
}

/// A `SISFileDescription` value (section 4.2.14).
struct Description {
    target: &'static str,
    mime_type: &'static str,
    /// Adds a 4-byte `SISCapabilities`, as for executables.
    capabilities: bool,
    /// SHA-1 of the uncompressed file.
    sha1: [u8; 20],
    operation: u32,
    stored_size: u64,
    size: u64,
    file_index: u32,
}

impl Description {
    fn of(target: &'static str, file: &[u8], file_index: u32) -> Self {
        Self {
            target,
            mime_type: "",
            capabilities: target.ends_with(".exe"),
            sha1: sha1(file),
            operation: OP_INSTALL,
            stored_size: file.len() as u64,
            size: file.len() as u64,
            file_index,
        }
    }

    /// Target, MIME type, capabilities, `SISHash` (algorithm and a
    /// `SISBlob` digest), operation, options, stored and uncompressed
    /// lengths, file index.
    fn value(&self) -> Vec<u8> {
        let mut value = string(self.target);
        value.extend(string(self.mime_type));
        if self.capabilities {
            value.extend(field(SIS_CAPABILITIES, &0x0000_1000u32.to_le_bytes()));
        }
        let mut hash = HASH_SHA1.to_le_bytes().to_vec();
        hash.extend(field(SIS_BLOB, &self.sha1));
        value.extend(field(SIS_HASH, &hash));
        value.extend_from_slice(&self.operation.to_le_bytes());
        value.extend_from_slice(&0u32.to_le_bytes());
        value.extend_from_slice(&self.stored_size.to_le_bytes());
        value.extend_from_slice(&self.size.to_le_bytes());
        value.extend_from_slice(&self.file_index.to_le_bytes());
        value
    }
}

/// A `SISExpression` value: the constant number 1 (operator, integer
/// value), which is always true.
fn true_expression() -> Vec<u8> {
    let mut value = PRIM_TYPE_NUMBER.to_le_bytes().to_vec();
    value.extend_from_slice(&1i32.to_le_bytes());
    field(SIS_EXPRESSION, &value)
}

/// A `SISInstallBlock` value: file descriptions, embedded controllers and
/// `SISIf` blocks (section 4.4.3).
fn install_block(files: &[Vec<u8>], embedded: &[Vec<u8>], conditions: &[Vec<u8>]) -> Vec<u8> {
    let mut value = array(SIS_FILE_DESCRIPTION, files);
    value.extend(array(SIS_CONTROLLER, embedded));
    value.extend(array(SIS_IF, conditions));
    value
}

/// A `SISIf` value: expression, install block and `SISElseIf`s, each an
/// expression and an install block (sections 4.4.1-4.4.2).
fn condition(block: &[u8], alternatives: &[Vec<u8>]) -> Vec<u8> {
    let mut value = true_expression();
    value.extend(field(SIS_INSTALL_BLOCK, block));
    let alternatives: Vec<Vec<u8>> = alternatives
        .iter()
        .map(|block| {
            let mut value = true_expression();
            value.extend(field(SIS_INSTALL_BLOCK, block));
            value
        })
        .collect();
    value.extend(array(SIS_ELSE_IF, &alternatives));
    value
}

/// A `SISSignatureCertificateChain` value: one `SISSignature` (algorithm
/// identifier string and a `SISBlob`) and a `SISCertificateChain` blob.
fn signature_chain() -> Vec<u8> {
    let mut signature = field(SIS_SIGNATURE_ALGORITHM, &string(SHA1_WITH_RSA));
    signature.extend(field(SIS_BLOB, &[0xA5; 16]));
    let mut value = array(SIS_SIGNATURE, &[signature]);
    value.extend(field(
        SIS_CERTIFICATE_CHAIN,
        &field(SIS_BLOB, &[0x30, 0x82]),
    ));
    value
}

/// The package a controller describes.
struct Package {
    uid: u32,
    name: &'static str,
    vendor: &'static str,
    version: [i32; 3],
    install_type: u8,
    files: Vec<Vec<u8>>,
    embedded: Vec<Vec<u8>>,
    conditions: Vec<Vec<u8>>,
    logo: Option<Vec<u8>>,
    /// A whole `SISInstallBlock` value in place of `files`, `embedded`
    /// and `conditions`.
    block: Option<Vec<u8>>,
    signatures: usize,
    data_index: u32,
}

impl Package {
    fn new(uid: u32, name: &'static str) -> Self {
        Self {
            uid,
            name,
            vendor: "Example Vendor",
            version: [1, 2, 3],
            install_type: 0,
            files: Vec::new(),
            embedded: Vec::new(),
            conditions: Vec::new(),
            logo: None,
            block: None,
            signatures: 0,
            data_index: 0,
        }
    }

    /// `SISInfo`: UID, unique vendor name, names and vendor names (one
    /// language), version, creation time 2024-03-05 06:07:08 (months count
    /// from 0), install type and flags (section 4.2.5).
    fn info(&self) -> Vec<u8> {
        let mut value = field(SIS_UID, &self.uid.to_le_bytes());
        value.extend(string(self.vendor));
        value.extend(array(SIS_STRING, &[utf16(self.name)]));
        value.extend(array(SIS_STRING, &[utf16("Vendor-EN")]));
        let version: Vec<u8> = self.version.iter().flat_map(|n| n.to_le_bytes()).collect();
        value.extend(field(SIS_VERSION, &version));
        let mut date = 2024u16.to_le_bytes().to_vec();
        date.extend_from_slice(&[2, 5]);
        let mut date_time = field(SIS_DATE, &date);
        date_time.extend(field(SIS_TIME, &[6, 7, 8]));
        value.extend(field(SIS_DATE_TIME, &date_time));
        value.extend_from_slice(&[self.install_type, 0]);
        value
    }

    /// The `SISController` value: info, options, languages, prerequisites,
    /// properties, the optional logo, the install block, signature chains
    /// and the data index (section 4.2.4).
    fn controller_value(&self) -> Vec<u8> {
        let mut value = field(SIS_INFO, &self.info());
        value.extend(field(
            SIS_SUPPORTED_OPTIONS,
            &array(SIS_SUPPORTED_OPTION, &[]),
        ));
        value.extend(field(
            SIS_SUPPORTED_LANGUAGES,
            &array(SIS_LANGUAGE, &[ENGLISH.to_le_bytes().to_vec()]),
        ));
        let mut prerequisites = array(SIS_DEPENDENCY, &[]);
        prerequisites.extend(array(SIS_DEPENDENCY, &[]));
        value.extend(field(SIS_PREREQUISITES, &prerequisites));
        value.extend(field(SIS_PROPERTIES, &array(SIS_PROPERTY, &[])));
        if let Some(logo) = &self.logo {
            value.extend(field(SIS_LOGO, &field(SIS_FILE_DESCRIPTION, logo)));
        }
        let block = self
            .block
            .clone()
            .unwrap_or_else(|| install_block(&self.files, &self.embedded, &self.conditions));
        value.extend(field(SIS_INSTALL_BLOCK, &block));
        for _ in 0..self.signatures {
            value.extend(field(SIS_SIGNATURE_CERTIFICATE_CHAIN, &signature_chain()));
        }
        value.extend(field(SIS_DATA_INDEX, &self.data_index.to_le_bytes()));
        value
    }

    fn controller(&self) -> Vec<u8> {
        field(SIS_CONTROLLER, &self.controller_value())
    }
}

/// A file as `SISFileData` stores it: the algorithm and the file.
struct Stored {
    algorithm: u32,
    file: Vec<u8>,
}

impl Stored {
    fn deflated(file: &[u8]) -> Self {
        Self {
            algorithm: COMPRESS_DEFLATE,
            file: file.to_vec(),
        }
    }

    fn plain(file: &[u8]) -> Self {
        Self {
            algorithm: COMPRESS_NONE,
            file: file.to_vec(),
        }
    }

    /// The stored bytes: a zlib stream for deflate, as MakeSIS writes.
    fn bytes(&self) -> Vec<u8> {
        if self.algorithm == COMPRESS_DEFLATE {
            miniz_oxide::deflate::compress_to_vec_zlib(&self.file, 6)
        } else {
            self.file.clone()
        }
    }
}

/// A `SISCompressed` field: algorithm, uncompressed size (u64), the stored
/// bytes (section 4.1.3).
fn compressed(algorithm: u32, size: u64, stored: &[u8]) -> Vec<u8> {
    let mut value = algorithm.to_le_bytes().to_vec();
    value.extend_from_slice(&size.to_le_bytes());
    value.extend_from_slice(stored);
    field(SIS_COMPRESSED, &value)
}

/// `SISData`: an array of data units, each an array of `SISFileData`, each
/// a typed `SISCompressed` (section 4.5).
fn data_field(units: &[Vec<Stored>]) -> Vec<u8> {
    let units: Vec<Vec<u8>> = units
        .iter()
        .map(|files| {
            let files: Vec<Vec<u8>> = files
                .iter()
                .map(|f| compressed(f.algorithm, f.file.len() as u64, &f.bytes()))
                .collect();
            array(SIS_FILE_DATA, &files)
        })
        .collect();
    field(SIS_DATA, &array(SIS_DATA_UNIT, &units))
}

/// The package's `SISController` in a `SISCompressed` of `algorithm`.
fn controller_field(package: &Package, algorithm: u32) -> Vec<u8> {
    let controller = Stored {
        algorithm,
        file: package.controller(),
    };
    compressed(algorithm, controller.file.len() as u64, &controller.bytes())
}

/// A whole file: the header with `uid3`, then `SISContents` with the
/// controller and data checksums (CRC-16 of each whole field, padding
/// included) when `checksums`, the compressed controller field and the
/// `SISData` field (section 4.2.1).
fn assemble(uid3: u32, controller: &[u8], data: &[u8], checksums: bool) -> Vec<u8> {
    let mut contents = Vec::new();
    if checksums {
        contents.extend(field(
            SIS_CONTROLLER_CHECKSUM,
            &crc16(controller).to_le_bytes(),
        ));
        contents.extend(field(SIS_DATA_CHECKSUM, &crc16(data).to_le_bytes()));
    }
    contents.extend_from_slice(controller);
    contents.extend_from_slice(data);
    let mut file = file_header(uid3);
    file.extend(field(SIS_CONTENTS, &contents));
    file
}

/// A whole package with its controller compressed by
/// `controller_algorithm` and `units` as its data.
fn sis_file(
    package: &Package,
    controller_algorithm: u32,
    units: &[Vec<Stored>],
    checksums: bool,
) -> Vec<u8> {
    assemble(
        package.uid,
        &controller_field(package, controller_algorithm),
        &data_field(units),
        checksums,
    )
}

/// The application package most tests use: a deflated executable and a
/// stored resource file, both installed.
struct App {
    file: Vec<u8>,
    exe: Vec<u8>,
}

fn app_package() -> App {
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let rsc = resource_file();
    let mut package = Package::new(PACKAGE_UID, "Hello");
    package.files = vec![
        Description::of(EXE_TARGET, &exe, 0).value(),
        Description::of(RSC_TARGET, &rsc, 1).value(),
    ];
    let units = [vec![Stored::deflated(&exe), Stored::plain(&rsc)]];
    App {
        file: sis_file(&package, COMPRESS_DEFLATE, &units, true),
        exe,
    }
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

/// Whether `data` is reported as a SIS package, or fails as one.
fn is_claimed(data: &[u8]) -> bool {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => p.format.format == FileFormat::SymbianSis,
        Err(e) => e.to_string().starts_with("Symbian SIS parse error"),
    }
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn slice<'a>(p: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    p.slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label} in {:?}", p.slices))
}

/// Offset of `needle`'s only occurrence in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> usize {
    let mut hits = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at);
    let at = hits.next().expect("needle is present");
    assert_eq!(hits.next(), None, "needle is unique");
    at
}

/// Overwrite the bytes at `at`, for tests that damage a field at a known
/// place.
fn patch(file: &mut [u8], at: usize, bytes: &[u8]) {
    file[at..at + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn packages_list_executables_under_their_target_paths() {
    let app = app_package();
    let p = classify(&app.file);
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Symbian OS v9 SIS package")
    );
    // The package names no processor: the ISA is the executable's.
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert!(has_note(
        &p,
        &format!("Primary ISA selected from {EXE_TARGET}")
    ));

    // The executable is listed with its stored (deflated) range and its
    // decoded size; the resource file is not a recognized format.
    assert_eq!(p.slices.len(), 1);
    let exe = slice(&p, EXE_TARGET);
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(&app.exe, 6);
    assert_eq!(exe.isa, Isa::Arm);
    assert_eq!(exe.offset, find(&app.file, &stream) as u64);
    assert_eq!(exe.size, stream.len() as u64);
    let decoded = exe.decoded.as_ref().expect("deflated file");
    assert_eq!(decoded.transform, "zlib");
    assert_eq!((decoded.offset, decoded.size), (0, app.exe.len() as u64));

    let messages: Vec<&str> = p.notes.iter().map(|n| n.message.as_str()).collect();
    let expected = [
        "Package \"Hello\"; UID 0xA0001234; version 1.2.3; vendor \"Example Vendor\"",
        "Install type SA (installation); flags 0x00; 1 language",
        "SIS packages name no processor; each listed file is classified from its own bytes",
        "2 stored files in 1 data unit; 2 file descriptions",
        "Install targets: !:\\sys\\bin\\hello.exe, !:\\resource\\apps\\hello.rsc",
        "1 of 2 examined stored files are in a recognized format and listed",
        "SHA-1 of 1 listed file matches the SISHash",
        "Unsigned: the SISController has no SISSignatureCertificateChain",
    ];
    for note in expected {
        assert!(messages.contains(&note), "{note} in {messages:?}");
    }
    assert!(messages
        .iter()
        .any(|m| m.starts_with("Controller CRC-16 0x")
            && m.contains("matches; data CRC-16 0x")
            && m.ends_with(" matches")));

    assert_eq!(
        metadata(&p, "sis_package_uid").as_deref(),
        Some("0xA0001234")
    );
    assert_eq!(metadata(&p, "sis_package_name").as_deref(), Some("Hello"));
    assert_eq!(
        metadata(&p, "sis_vendor").as_deref(),
        Some("Example Vendor")
    );
    assert_eq!(
        metadata(&p, "sis_vendor_name").as_deref(),
        Some("Vendor-EN")
    );
    assert_eq!(metadata(&p, "sis_version").as_deref(), Some("1.2.3"));
    assert_eq!(
        metadata(&p, "sis_creation_time").as_deref(),
        Some("2024-03-05 06:07:08 UTC")
    );
    assert_eq!(
        metadata(&p, "sis_controller_compression").as_deref(),
        Some("zlib")
    );
    assert_eq!(metadata(&p, "sis_signature_chains").as_deref(), Some("0"));
    assert_eq!(metadata(&p, "sis_file_descriptions").as_deref(), Some("2"));
    assert_eq!(metadata(&p, "sis_stored_files").as_deref(), Some("2"));
    assert_eq!(metadata(&p, "sis_data_units").as_deref(), Some("1"));
    assert_eq!(
        metadata(&p, "sis_image_size"),
        Some(app.file.len().to_string())
    );
    assert!(metadata(&p, "sis_controller_crc").is_some_and(|v| v.ends_with("(matches)")));
}

#[test]
fn stored_controllers_and_files_keep_their_stored_bytes() {
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let mut package = Package::new(PACKAGE_UID, "Plain");
    package.files = vec![Description::of(EXE_TARGET, &exe, 0).value()];
    let file = sis_file(&package, COMPRESS_NONE, &[vec![Stored::plain(&exe)]], false);
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    let listed = slice(&p, EXE_TARGET);
    assert_eq!(listed.decoded, None);
    assert_eq!(
        (listed.offset, listed.size),
        (find(&file, &exe) as u64, exe.len() as u64)
    );
    assert_eq!(listed.isa, Isa::Arm);
    assert!(has_note(&p, "No controller CRC-16; no data CRC-16"));
    assert_eq!(
        metadata(&p, "sis_controller_compression").as_deref(),
        Some("none")
    );
    assert_eq!(metadata(&p, "sis_data_crc").as_deref(), Some("absent"));
}

#[test]
fn signature_chains_are_reported_present_and_not_verified() {
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let mut package = Package::new(PACKAGE_UID, "Signed");
    package.files = vec![Description::of(EXE_TARGET, &exe, 0).value()];
    package.signatures = 2;
    let file = sis_file(
        &package,
        COMPRESS_DEFLATE,
        &[vec![Stored::deflated(&exe)]],
        true,
    );
    let p = classify(&file);
    assert!(has_note(
        &p,
        "2 signature certificate chains present; signatures and certificates are not verified"
    ));
    assert_eq!(metadata(&p, "sis_signature_chains").as_deref(), Some("2"));
}

#[test]
fn embedded_packages_use_summed_data_indices_and_list_the_main_unit_first() {
    let main_exe = e32_image(PACKAGE_UID, &arm_code());
    let inner_exe = e32_image(0xA000_5678, &arm_code()[..64]);
    let deep_exe = e32_image(0xA000_9ABC, &arm_code()[..32]);

    // The embedded package's own data index is 1; the package it embeds
    // has 1 too, so its absolute unit is 0 + 1 + 1 = 2 (section 2.8).
    let mut deep = Package::new(0xA000_9ABC, "Deep");
    deep.files = vec![Description::of("!:\\sys\\bin\\deep.exe", &deep_exe, 0).value()];
    deep.data_index = 1;
    let mut inner = Package::new(0xA000_5678, "Inner");
    inner.files = vec![Description::of("!:\\sys\\bin\\inner.exe", &inner_exe, 0).value()];
    inner.embedded = vec![deep.controller_value()];
    inner.data_index = 1;

    // The main package's data unit is stored last, after the embedded
    // packages' units.
    let mut package = Package::new(PACKAGE_UID, "Suite");
    package.files = vec![Description::of(EXE_TARGET, &main_exe, 0).value()];
    package.embedded = vec![inner.controller_value()];
    package.data_index = 0;
    let units = [
        vec![Stored::deflated(&main_exe)],
        vec![Stored::deflated(&inner_exe)],
        vec![Stored::plain(&deep_exe)],
    ];
    let file = sis_file(&package, COMPRESS_DEFLATE, &units, true);
    let p = classify(&file);
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(
        labels,
        [
            EXE_TARGET,
            "!:\\sys\\bin\\inner.exe",
            "!:\\sys\\bin\\deep.exe"
        ]
    );
    assert!(has_note(
        &p,
        "Embedded packages: \"Inner\" (UID 0xA0005678, version 1.2.3)"
    ));
    assert!(has_note(
        &p,
        "3 stored files in 3 data units; 3 file descriptions"
    ));
    assert_eq!(metadata(&p, "sis_embedded_packages").as_deref(), Some("2"));

    // With the main package's data index pointing at the last unit, its
    // file still comes first.
    let mut package = Package::new(PACKAGE_UID, "Suite");
    package.files = vec![Description::of(EXE_TARGET, &main_exe, 0).value()];
    package.data_index = 1;
    let units = [
        vec![Stored::plain(&inner_exe)],
        vec![Stored::plain(&main_exe)],
    ];
    let p = classify(&sis_file(&package, COMPRESS_NONE, &units, false));
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(labels, [EXE_TARGET, "Data unit 0 file 0"]);
}

#[test]
fn conditional_blocks_and_logos_name_their_files() {
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let alternative = e32_image(PACKAGE_UID, &arm_code()[..128]);
    let license = b"License text".to_vec();
    let logo = e32_image(PACKAGE_UID, &arm_code()[..16]);

    let mut text = Description::of("", &license, 0);
    text.operation = OP_TEXT;
    let branch = install_block(&[Description::of(EXE_TARGET, &exe, 1).value()], &[], &[]);
    let other = install_block(
        &[Description::of("!:\\sys\\bin\\other.exe", &alternative, 2).value()],
        &[],
        &[],
    );
    let mut package = Package::new(PACKAGE_UID, "Branches");
    package.files = vec![text.value()];
    package.conditions = vec![condition(&branch, &[other])];
    package.logo = Some(Description::of("", &logo, 3).value());
    let units = [vec![
        Stored::deflated(&license),
        Stored::deflated(&exe),
        Stored::deflated(&alternative),
        Stored::deflated(&logo),
    ]];
    let p = classify(&sis_file(&package, COMPRESS_DEFLATE, &units, true));
    let labels: Vec<&str> = p.slices.iter().filter_map(|s| s.label.as_deref()).collect();
    assert_eq!(
        labels,
        [
            EXE_TARGET,
            "!:\\sys\\bin\\other.exe",
            "Logo (data unit 0 file 3)"
        ]
    );
    assert!(has_note(
        &p,
        "4 stored files in 1 data unit; 4 file descriptions"
    ));
    assert!(has_note(
        &p,
        "3 of 4 examined stored files are in a recognized format and listed"
    ));
    assert!(has_note(&p, "SHA-1 of 3 listed files matches the SISHash"));
}

#[test]
fn checksum_and_hash_mismatches_are_noted_not_rejected() {
    let mut app = app_package();
    // The controller CRC-16 is the first checksum's value at 0x20.
    assert_eq!(app.file[0x18..0x1C], SIS_CONTROLLER_CHECKSUM.to_le_bytes());
    let stored = u16::from_le_bytes([app.file[0x20], app.file[0x21]]);
    patch(&mut app.file, 0x20, &(stored ^ 0x0101).to_le_bytes());
    let p = classify(&app.file);
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    assert!(has_note(
        &p,
        &format!(
            "Controller CRC-16 0x{:04X} does not match the computed 0x{stored:04X}",
            stored ^ 0x0101
        )
    ));
    assert!(has_note(&p, "the installer does not check these CRCs"));

    // A wrong SHA-1 in the file description is noted; the file is listed.
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let mut description = Description::of(EXE_TARGET, &exe, 0);
    description.sha1 = [0x11; 20];
    let mut package = Package::new(PACKAGE_UID, "Tampered");
    package.files = vec![description.value()];
    let p = classify(&sis_file(
        &package,
        COMPRESS_DEFLATE,
        &[vec![Stored::deflated(&exe)]],
        true,
    ));
    assert!(has_note(
        &p,
        &format!("SHA-1 does not match the SISHash for: {EXE_TARGET}")
    ));
    assert_eq!(slice(&p, EXE_TARGET).isa, Isa::Arm);
}

#[test]
fn sha1_is_compared_with_an_independently_computed_digest() {
    // SHA-1 of this 160-byte E32 image, computed with Python's hashlib over
    // the image built there from the documented header layout.
    const DIGEST: [u8; 20] = [
        0x35, 0x5e, 0x1e, 0x80, 0x77, 0x76, 0xa5, 0x7a, 0x1d, 0xf5, 0xc6, 0x67, 0xb5, 0x4c, 0xe0,
        0x34, 0xfb, 0x4b, 0xad, 0x90,
    ];
    let exe = e32_image(PACKAGE_UID, &[0x1E, 0xFF, 0x2F, 0xE1]);
    assert_eq!(exe.len(), 160);
    let mut description = Description::of(EXE_TARGET, &exe, 0);
    description.sha1 = DIGEST;
    let mut package = Package::new(PACKAGE_UID, "Pinned");
    package.files = vec![description.value()];
    let p = classify(&sis_file(
        &package,
        COMPRESS_NONE,
        &[vec![Stored::plain(&exe)]],
        false,
    ));
    assert!(has_note(&p, "SHA-1 of 1 listed file matches the SISHash"));
}

#[test]
fn stub_packages_and_undecodable_files_are_described() {
    // A preinstalled-application stub: no data units.
    let mut package = Package::new(PACKAGE_UID, "Stub");
    package.install_type = 3;
    package.files = vec![Description::of(EXE_TARGET, &[0; 4], 0).value()];
    let p = classify(&sis_file(&package, COMPRESS_DEFLATE, &[], true));
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "Stub package: SISData holds no data units, so no files"
    ));
    assert!(has_note(&p, "Install type PA (preinstalled application)"));
    assert!(has_note(&p, "1 file description names no stored file"));

    // A deflated file whose declared size is wrong, one whose stream is
    // corrupt after a valid start, and one with an undefined algorithm.
    let exe = e32_image(PACKAGE_UID, &arm_code());
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(&exe, 6);
    let mut corrupt = stream.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    let mut package = Package::new(PACKAGE_UID, "Broken");
    package.files = vec![
        Description::of("!:\\sys\\bin\\short.exe", &exe, 0).value(),
        Description::of("!:\\sys\\bin\\corrupt.exe", &exe, 1).value(),
        Description::of("!:\\sys\\bin\\odd.exe", &exe, 2).value(),
    ];
    let files = [
        compressed(COMPRESS_DEFLATE, exe.len() as u64 + 1, &stream),
        compressed(COMPRESS_DEFLATE, exe.len() as u64, &corrupt),
        compressed(7, exe.len() as u64, &exe),
    ];
    let data = field(
        SIS_DATA,
        &array(SIS_DATA_UNIT, &[array(SIS_FILE_DATA, &files)]),
    );
    let controller = controller_field(&package, COMPRESS_DEFLATE);
    let p = classify(&assemble(PACKAGE_UID, &controller, &data, false));
    assert_eq!(p.slices.len(), 0);
    assert!(has_note(
        &p,
        &format!(
            "Stored files that do not decode: !:\\sys\\bin\\short.exe (decodes to {} B, declares {} B), !:\\sys\\bin\\corrupt.exe (",
            exe.len(),
            exe.len() + 1
        )
    ));
    assert!(has_note(
        &p,
        "Stored files with an unsupported SISCompressed algorithm were not examined: !:\\sys\\bin\\odd.exe (algorithm 7)"
    ));
}

#[test]
fn header_and_structure_errors_are_parse_errors() {
    let app = app_package();

    let mut wrong = app.file.clone();
    wrong[0x0C] ^= 1;
    assert!(error_text(&wrong).starts_with("Symbian SIS parse error: Invalid UID checksum"));

    // The controller must decode, with a known algorithm, to its size,
    // and start with a `SISController` field.
    let package = Package::new(PACKAGE_UID, "Wrong");
    let controller = package.controller();
    let check = |algorithm: u32, size: u64, stored: &[u8]| {
        let field = compressed(algorithm, size, stored);
        error_text(&assemble(PACKAGE_UID, &field, &data_field(&[]), false))
    };
    let mut info_first = controller.clone();
    info_first[..4].copy_from_slice(&SIS_INFO.to_le_bytes());
    assert_eq!(
        check(COMPRESS_NONE, controller.len() as u64, &info_first),
        "Symbian SIS parse error: Missing SISController at controller offset 0x0 (field type 14)"
    );
    assert_eq!(
        check(2, controller.len() as u64, &controller),
        "Symbian SIS parse error: Unsupported SISCompressed algorithm 2 for the SISController at 0x18"
    );
    assert_eq!(
        check(COMPRESS_NONE, controller.len() as u64 + 4, &controller),
        format!(
            "Symbian SIS parse error: Invalid SISCompressed at 0x18: the SISController is {} B, the header says {} B",
            controller.len(),
            controller.len() + 4
        )
    );
    assert!(
        check(COMPRESS_DEFLATE, controller.len() as u64, &controller)
            .starts_with("Symbian SIS parse error: Invalid SISController zlib stream at 0x18")
    );
    assert_eq!(
        check(COMPRESS_DEFLATE, 1 << 40, &controller),
        "Symbian SIS parse error: Unsupported SISController size 1099511627776 B at 0x18: exceeds 64 MiB"
    );

    // An odd-length name: the names array element's length word precedes
    // the text.
    let mut odd = controller.clone();
    let at = find(&odd, &utf16("Wrong"));
    patch(&mut odd, at - 4, &9u32.to_le_bytes());
    assert!(check(COMPRESS_NONE, odd.len() as u64, &odd)
        .contains("Invalid SISString at controller offset 0x"));

    // An array whose element type is not the one the structure holds: the
    // supported languages array holding `SISString`s.
    let mut languages = controller.clone();
    let languages_array = [
        SIS_ARRAY.to_le_bytes(),
        12u32.to_le_bytes(),
        SIS_LANGUAGE.to_le_bytes(),
        4u32.to_le_bytes(),
        ENGLISH.to_le_bytes(),
    ]
    .concat();
    let at = find(&languages, &languages_array);
    patch(&mut languages, at + 8, &SIS_STRING.to_le_bytes());
    assert!(check(COMPRESS_NONE, languages.len() as u64, &languages)
        .contains("Invalid SISArray element type 1 at controller offset 0x"));

    // Data after SISContents must be padding.
    let mut padded = app.file.clone();
    padded.extend_from_slice(&[0xFF; 6]);
    assert!(has_note(
        &classify(&padded),
        "6 B of padding after SISContents"
    ));
    let mut junk = app.file.clone();
    junk.extend_from_slice(b"junk");
    assert_eq!(
        error_text(&junk),
        format!(
            "Symbian SIS parse error: Unexpected 4 B after SISContents at 0x{:X}",
            app.file.len()
        )
    );
}

#[test]
fn embedding_and_block_nesting_are_bounded() {
    // Nine levels of embedded packages: one more than the installer
    // processes.
    let mut innermost = Package::new(0xA000_0009, "Level 9").controller_value();
    for level in (1..=8).rev() {
        let mut package = Package::new(0xA000_0000 + level, "Level");
        package.embedded = vec![innermost];
        innermost = package.controller_value();
    }
    let mut package = Package::new(PACKAGE_UID, "Top");
    package.embedded = vec![innermost];
    let text = error_text(&sis_file(&package, COMPRESS_DEFLATE, &[], false));
    assert!(
        text.starts_with(
            "Symbian SIS parse error: Unsupported SIS embedding deeper than 8 levels at controller offset 0x"
        ),
        "{text}"
    );

    // Eight levels parse.
    let mut innermost = Package::new(0xA000_0008, "Level 8").controller_value();
    for level in (1..=7).rev() {
        let mut package = Package::new(0xA000_0000 + level, "Level");
        package.embedded = vec![innermost];
        innermost = package.controller_value();
    }
    let mut package = Package::new(PACKAGE_UID, "Top");
    package.embedded = vec![innermost];
    let p = classify(&sis_file(&package, COMPRESS_DEFLATE, &[], false));
    assert_eq!(metadata(&p, "sis_embedded_packages").as_deref(), Some("8"));

    // 33 nested SISIf blocks.
    let mut block = install_block(&[], &[], &[]);
    for _ in 0..33 {
        block = install_block(&[], &[], &[condition(&block, &[])]);
    }
    let mut package = Package::new(PACKAGE_UID, "Deep");
    package.block = Some(block);
    assert!(
        error_text(&sis_file(&package, COMPRESS_DEFLATE, &[], false)).starts_with(
            "Symbian SIS parse error: Unsupported SISInstallBlock nesting deeper than 32 levels"
        )
    );

    // 32 levels parse.
    let mut block = install_block(&[], &[], &[]);
    for _ in 0..32 {
        block = install_block(&[], &[], &[condition(&block, &[])]);
    }
    package.block = Some(block);
    let p = classify(&sis_file(&package, COMPRESS_DEFLATE, &[], false));
    assert_eq!(p.format.format, FileFormat::SymbianSis);
}

#[test]
fn listing_stops_at_the_component_limit_and_large_files_are_not_decoded() {
    const FILES: u32 = 4097;
    let exe = e32_image(PACKAGE_UID, &[0x1E, 0xFF, 0x2F, 0xE1]);
    let mut package = Package::new(PACKAGE_UID, "Many");
    package.files = (0..FILES)
        .map(|index| {
            let mut description = Description::of(EXE_TARGET, &exe, index);
            description.capabilities = false;
            description.value()
        })
        .collect();
    let units = [(0..FILES).map(|_| Stored::plain(&exe)).collect::<Vec<_>>()];
    let p = classify(&sis_file(&package, COMPRESS_DEFLATE, &units, false));
    assert_eq!(p.slices.len(), 4096);
    assert!(has_note(
        &p,
        "File listing stopped at 4096 listed files; 1 further stored file was not examined"
    ));

    // Declared sizes over 64 MiB per file or 256 MiB per package are not
    // decoded; nothing that large is allocated.
    let stream = miniz_oxide::deflate::compress_to_vec_zlib(&exe, 6);
    let sizes = [
        65u64 << 20,
        60 << 20,
        60 << 20,
        60 << 20,
        60 << 20,
        60 << 20,
    ];
    let files: Vec<Vec<u8>> = sizes
        .iter()
        .map(|size| compressed(COMPRESS_DEFLATE, *size, &stream))
        .collect();
    let package = Package::new(PACKAGE_UID, "Large");
    let data = field(
        SIS_DATA,
        &array(SIS_DATA_UNIT, &[array(SIS_FILE_DATA, &files)]),
    );
    let p = classify(&assemble(
        PACKAGE_UID,
        &controller_field(&package, COMPRESS_NONE),
        &data,
        false,
    ));
    assert!(has_note(
        &p,
        "Stored files over the extraction limits (64 MiB per file, 256 MiB per package) were not \
         decoded or classified: Data unit 0 file 0 (68157440 B), Data unit 0 file 5 (62914560 B)"
    ));
}

#[test]
fn every_truncation_errors_or_is_not_claimed() {
    let app = app_package();
    for end in 0..app.file.len() {
        let prefix = &app.file[..end];
        assert!(
            sis::parse_container(prefix, sis::Layout::Sis9).is_err(),
            "prefix of {end} B parses"
        );
        if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
            assert_ne!(p.format.format, FileFormat::SymbianSis, "prefix of {end} B");
        }
    }
    assert!(is_claimed(&app.file[..20]));
    assert!(!is_claimed(&app.file[..19]));
}

#[test]
fn byte_mutations_never_panic() {
    let exe = e32_image(PACKAGE_UID, &[0x1E, 0xFF, 0x2F, 0xE1]);
    let mut package = Package::new(PACKAGE_UID, "M");
    package.files = vec![Description::of(EXE_TARGET, &exe, 0).value()];
    package.signatures = 1;
    package.logo = Some(Description::of("", &exe, 0).value());
    let deflated = sis_file(
        &package,
        COMPRESS_DEFLATE,
        &[vec![Stored::deflated(&exe)]],
        true,
    );
    let stored = sis_file(&package, COMPRESS_NONE, &[vec![Stored::plain(&exe)]], true);
    for file in [deflated, stored] {
        for at in 0..file.len() {
            let original = file[at];
            let mut values = vec![0x00, 0xFF];
            values.extend((0..8).map(|bit| original ^ (1 << bit)));
            for value in values {
                let mut mutated = file.clone();
                mutated[at] = value;
                let _ = sis::parse_container(&mutated, sis::Layout::Sis9);
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}

/// IDA's SIS 9 test inputs (`IDA_INPUT_DIR`), read in place: the valid and
/// tampered packages classify, the damaged ones fail with bounded errors,
/// and the damaged E32 image with a SIS UID1 is an EPOC parse error.
/// Skipped without the variable.
#[test]
fn ida_input_packages_parse_or_fail_with_bounded_errors() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IDA_INPUT_DIR is not set");
        return;
    };
    let read = |name: &str| std::fs::read(dir.join(name)).expect("IDA input is present");

    let p = classify(&read("arm_logexportv11_sis9.epoc"));
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    assert_eq!(p.primary.isa, Isa::Arm);
    let exe = slice(&p, "!:\\sys\\bin\\LogExport.exe");
    assert_eq!((exe.offset, exe.size), (0x74C, 22_407));
    assert_eq!(exe.decoded.as_ref().map(|d| d.size), Some(30_933));
    assert!(has_note(
        &p,
        "Package \"LogExport\"; UID 0xA0001C61; version 1.1.0; vendor \"Vendor\""
    ));
    assert!(has_note(
        &p,
        "Controller CRC-16 0xDCAA matches; data CRC-16 0x15A2 matches"
    ));
    assert!(has_note(&p, "SHA-1 of 1 listed file matches the SISHash"));
    assert!(has_note(&p, "1 signature certificate chain present"));

    // A tampered package: its data CRC and the executable's SHA-1 differ,
    // and one deflated file does not decode to its declared size. The
    // executable's own header is damaged (code size 0xFFFFFFFF, a wrong
    // header CRC), so the EPOC parser rejects it and its ISA is unknown.
    let p = classify(&read("arm_bad_impend.epoc"));
    assert_eq!(p.format.format, FileFormat::SymbianSis);
    assert!(matches!(
        slice(&p, "!:\\sys\\bin\\Slick.exe").isa,
        Isa::Unknown(_)
    ));
    assert!(has_note(
        &p,
        "!:\\sys\\bin\\Slick.exe: ISA unknown (Symbian E32 image parse error: Truncated E32 code \
         part at 0x9C (4294967295 B) in the 5096 B uncompressed image)"
    ));
    assert!(has_note(
        &p,
        "data CRC-16 0xAD48 does not match the computed 0xE95F"
    ));
    assert!(has_note(
        &p,
        "SHA-1 does not match the SISHash for: !:\\sys\\bin\\Slick.exe"
    ));
    assert!(has_note(
        &p,
        "Stored files that do not decode: !:\\private\\a0000bcf\\Messenger\\Data.dta"
    ));

    let damaged = [
        (
            "arm_bad_stkovr.epoc",
            "Symbian SIS parse error: Invalid SISController zlib stream at 0x30: Invalid zlib stream",
        ),
        (
            "arm_bad_uncompressed_size.epoc",
            "Symbian SIS parse error: Invalid SISFileData length 8856124964279871944 B at 0x52A8: \
             exceeds its enclosing field",
        ),
    ];
    for (name, expected) in damaged {
        assert_eq!(error_text(&read(name)), expected, "{name}");
    }

    // UID1 0x10201A7A with `EPOC` at 0x10 and a wrong UID checksum: an E32
    // image header, which the EPOC parser keeps and rejects as damaged.
    assert_eq!(
        error_text(&read("arm_bad_huffman.epoc")),
        "Symbian E32 image parse error: Invalid E32 export description: 738 B end the header at \
         0x380, but iCodeOffset is 0xA3D4AC56"
    );
}
