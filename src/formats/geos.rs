//! PC/GEOS geodes: the `.geo` executables (applications, libraries and
//! drivers) of PC/GEOS 1.x and of PC/GEOS 2.0 and later.
//!
//! Sources, from the PC/GEOS source release `github.com/bluewaysw/pcgeos` at
//! commit `8f0ca5d8f1cdd57d60438f813203eabb0a8cff55` (checksums in
//! `docs/geos.md`):
//! - `Include/Internal/fileStr.def` (`GeosFileHeader`, `GeosFileHeaderOld`)
//!   and `Tools/include/os90File.h` (`GeosFileHeader2`, the 1.x
//!   `GeosFileHeader`): the two signatures, the 256-byte 2.x and 200-byte
//!   1.x file headers, and for 2.x "All file offsets are from the end of
//!   this header".
//! - `Include/file.def`: `GeosFileType`, `GeosFileHeaderFlags`,
//!   `FileLongName`, `FileDate`, `FileTime`.
//! - `Include/Internal/geodeStr.def` and `Tools/include/geode.h`:
//!   `ExecutableFileHeader`, the core block (`GeodeHeader` up to
//!   `GH_endOfVariablesFromFile`), `ImportedLibraryEntry`,
//!   `GeodeRelocationEntry` and the `RESF_*` resource flags;
//!   `Include/geode.def` (`GeodeAttrs`) and `Include/heap.def` (`HeapFlags`,
//!   `HeapAllocFlags`).
//! - `Tools/glue/geo.c`, the linker that writes geodes: the header, the
//!   imported library table, the exported entry table, the four resource
//!   arrays, then each resource padded to a paragraph and followed by its
//!   relocations; both copies of each count are set from one value.
//! - `Library/Kernel/Geodes/geodesLoad.asm` and `geodesResource.asm`: how
//!   the kernel reads the tables and resources; resource 0 is the core block
//!   and resource 1 dgroup.
//! - `Tools/geodump/geodump.c`, `geos.h` and `geos2.h`: an independent
//!   reader of both header versions (`GEOS_ID 0x53CF45C7`, `GEOS2_ID
//!   0x53C145C7`).
//! - `TechDocs/ascii/Concepts/cmemory.txt` section 15.2 ("real mode memory
//!   addressing", "the segmented addressing scheme used by the 80x86
//!   processors") and `TechDocs/ascii/Esp/eintro.txt` section 1.1 ("Esp is
//!   an 80x86 assembly language specially designed for GEOS programming").
//!
//! No header field names a processor; the platform fixes it. Resources
//! whose allocation flags carry `HAF_CODE` are reported as 16-bit x86
//! real-mode code. Every other resource (dgroup, local-memory and object
//! blocks, other data) is opaque. Every field is little-endian.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target, MAX_COMPONENTS};
use crate::types::{Endianness, FileFormat, Isa};

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "geos";

/// `GFH_signature`: `'G' or 0x80, 'E', 'A' or 0x80, 'S'` (PC/GEOS 2.0 and
/// later).
const SIGNATURE_2: [u8; 4] = [0xC7, 0x45, 0xC1, 0x53];

/// `GFHO_signature`: `'G' or 0x80, 'E', 'O' or 0x80, 'S'` (PC/GEOS 1.x).
const SIGNATURE_1: [u8; 4] = [0xC7, 0x45, 0xCF, 0x53];

/// `GFT_EXECUTABLE`, the 2.x file type of a geode.
const GFT_EXECUTABLE: u16 = 1;

/// `GFTO_EXECUTABLE`, the 1.x file type of a geode (`GFT_EXECUTABLE` minus
/// `GFT_RELEASE_1_OFFSET`).
const GFTO_EXECUTABLE: u16 = 0;

/// `GFHF_DBCS`: the long name is in 16-bit characters.
const GFHF_DBCS: u16 = 0x0400;

/// `FILE_LONGNAME_BUFFER_SIZE`.
const LONGNAME_SIZE: usize = 36;

/// `GFH_NOTICE_SIZE`, the copyright notice that `glue` writes.
const NOTICE_SIZE: usize = 32;

/// `TOKEN_CHARS_LENGTH`: a `GeodeToken` is four characters and a
/// manufacturer ID word.
const TOKEN_CHARS_SIZE: usize = 4;

/// `ExecutableFileHeader` after the file header: attributes, file type,
/// heap space (2.x) or kernel protocol (1.x), resource, imported library and
/// exported entry counts, udata size, process class and application object.
const EXECUTABLE_HEADER_SIZE: usize = 24;
const EFH_ATTRIBUTES: usize = 0;
const EFH_FILE_TYPE: usize = 2;
const EFH_HEAP_SPACE: usize = 4;
const EFH_KERNEL_PROTOCOL: usize = 4;
const EFH_RESOURCE_COUNT: usize = 8;
const EFH_IMPORT_LIBRARY_COUNT: usize = 10;
const EFH_EXPORT_ENTRY_COUNT: usize = 12;
const EFH_UDATA_SIZE: usize = 14;
const EFH_CLASS_PTR: usize = 16;
const EFH_APP_OBJ: usize = 20;

/// The core block as stored in the file: `GeodeHeader` up to (not
/// including) `GH_geoHandle` (`GEODE_FILE_TABLE_SIZE`).
const CORE_BLOCK_SIZE: usize = 64;
const GH_GEODE_ATTR: usize = 2;
const GH_GEODE_FILE_TYPE: usize = 4;
const GH_GEODE_RELEASE: usize = 6;
const GH_GEODE_PROTOCOL: usize = 14;
const GH_GEODE_SERIAL: usize = 18;
const GH_GEODE_NAME: usize = 20;
const GH_GEODE_NAME_EXT: usize = 28;
const GH_DRIVER_TAB: usize = 40;
const GH_LIB_ENTRY: usize = 44;
const GH_EXPORT_ENTRY_COUNT: usize = 50;
const GH_LIB_COUNT: usize = 52;
const GH_RES_COUNT: usize = 56;

/// `GEODE_NAME_SIZE` and `GEODE_NAME_EXT_SIZE`.
const GEODE_NAME_SIZE: usize = 8;
const GEODE_NAME_EXT_SIZE: usize = 4;

/// `ImportedLibraryEntry`: name (8), attributes (2), protocol (4).
const IMPORTED_LIBRARY_SIZE: usize = 14;

/// An exported entry point: offset word, resource word.
const EXPORT_ENTRY_SIZE: usize = 4;

/// Resource table bytes per resource: size (2), file position (4),
/// relocation table size (2) and allocation flags (2), in four arrays.
const RESOURCE_ENTRY_SIZE: usize = 10;

/// `GeodeRelocationEntry`: info, extra, offset.
const RELOCATION_ENTRY_SIZE: usize = 4;

/// Resource data is padded to a paragraph before its relocations.
const PARAGRAPH: usize = 16;

/// Resource 0 is the core block and resource 1 dgroup; `glue` refuses to
/// build a geode without dgroup.
const DGROUP_RESOURCE: usize = 1;
const MIN_RESOURCES: usize = 2;

/// `HeapFlags` (low byte) and `HeapAllocFlags` (high byte) bits that name
/// what a resource holds.
const HF_FIXED: u16 = 0x0080;
const HF_LMEM: u16 = 0x0008;
const HAF_OBJECT_RESOURCE: u16 = 0x0400;
const HAF_CODE: u16 = 0x0200;

/// `GeodeAttrs`, most significant bit first.
const GA_PROCESS: u16 = 0x8000;
const GA_LIBRARY: u16 = 0x4000;
const GA_DRIVER: u16 = 0x2000;
const GA_APPLICATION: u16 = 0x0200;
const GEODE_ATTRIBUTES: [(u16, &str); 15] = [
    (GA_PROCESS, "process"),
    (GA_LIBRARY, "library"),
    (GA_DRIVER, "driver"),
    (0x1000, "keep file open"),
    (0x0800, "system"),
    (0x0400, "multi-launchable"),
    (GA_APPLICATION, "application"),
    (0x0100, "driver initialized"),
    (0x0080, "library initialized"),
    (0x0040, "geode initialized"),
    (0x0020, "uses coprocessor"),
    (0x0010, "requires coprocessor"),
    (0x0008, "general consumer mode"),
    (0x0004, "entry points in C"),
    (0x0002, "XIP"),
];

/// `GeodeType` values.
const GEODE_TYPES: [(u16, &str); 3] = [(1, "application"), (2, "library"), (3, "driver")];

/// 2.x `GeosFileType` values.
const FILE_TYPES_2: [(u16, &str); 6] = [
    (0, "not a GEOS file"),
    (GFT_EXECUTABLE, "executable"),
    (2, "VM file"),
    (3, "data file"),
    (4, "directory"),
    (5, "1.x VM file"),
];

/// 1.x `GeosFileTypeOld` values.
const FILE_TYPES_1: [(u16, &str); 2] = [(GFTO_EXECUTABLE, "executable"), (1, "VM file")];

/// Most imported geodes named in the note and metadata.
const MAX_LISTED_IMPORTS: usize = 32;

/// PC/GEOS runs on 80x86 processors in real mode.
const X86_REAL_MODE: Target = Target::new(Isa::X86, 16, Endianness::Little);

/// A geode layout, by file header version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// PC/GEOS 2.0 and later: the 256-byte `GeosFileHeader2` (signature
    /// `C7 45 C1 53`); resource positions exclude it.
    Geos2,
    /// PC/GEOS 1.x: the 200-byte `GeosFileHeader` (signature `C7 45 CF 53`);
    /// resource positions are file offsets.
    Geos1,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::GeosGeode
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Geos2 => "PC/GEOS 2.0+ geode",
            Self::Geos1 => "PC/GEOS 1.x geode",
        }
    }

    /// Both layouts carry a signature.
    pub fn is_weak(self) -> bool {
        false
    }

    /// Where this version's file header keeps its fields.
    fn header(self) -> &'static FileHeaderLayout {
        match self {
            Self::Geos2 => &HEADER_2,
            Self::Geos1 => &HEADER_1,
        }
    }
}

/// Byte offsets of the file header fields.
struct FileHeaderLayout {
    /// Header size; the executable header follows it.
    size: usize,
    /// What resource file positions are relative to.
    position_base: usize,
    /// The file type of a geode.
    executable_type: u16,
    /// Names of the file type values.
    file_types: &'static [(u16, &'static str)],
    long_name: usize,
    file_type: usize,
    flags: usize,
    release: usize,
    protocol: usize,
    token: usize,
    creator: usize,
    notice: usize,
    /// `FileDate` and `FileTime` words, 2.x only.
    created: Option<usize>,
}

/// `GeosFileHeader2` (`Tools/include/os90File.h`).
const HEADER_2: FileHeaderLayout = FileHeaderLayout {
    size: 256,
    position_base: 256,
    executable_type: GFT_EXECUTABLE,
    file_types: &FILE_TYPES_2,
    long_name: 0x04,
    file_type: 0x28,
    flags: 0x2A,
    release: 0x2C,
    protocol: 0x34,
    token: 0x38,
    creator: 0x3E,
    notice: 0xA8,
    created: Some(0xC8),
};

/// The 1.x `GeosFileHeader`: `GeosFileHeaderCore`, user notes, and the
/// reserved bytes where `glue` writes the copyright notice.
const HEADER_1: FileHeaderLayout = FileHeaderLayout {
    size: 200,
    position_base: 0,
    executable_type: GFTO_EXECUTABLE,
    file_types: &FILE_TYPES_1,
    long_name: 0x20,
    file_type: 0x04,
    flags: 0x06,
    release: 0x08,
    protocol: 0x10,
    token: 0x14,
    creator: 0x1A,
    notice: 0xA8,
    created: None,
};

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::GeosParseError {
        message: message.into(),
    }
}

/// Strong recognition: either file header signature at offset 0. The
/// signature starts every PC/GEOS file on a DOS filesystem; the parser
/// rejects files that are not geodes.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(&SIGNATURE_2) {
        Some(Layout::Geos2)
    } else if data.starts_with(&SIGNATURE_1) {
        Some(Layout::Geos1)
    } else {
        None
    }
}

/// The `len` bytes of `what` at `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} ({len} B)")))
}

/// A little-endian word inside a slice already read through [`slice`].
fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// A little-endian doubleword inside a slice already read through [`slice`].
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The name of `value` in a `(value, name)` table.
fn name_of(table: &[(u16, &'static str)], value: u16) -> Option<&'static str> {
    table
        .iter()
        .find(|(known, _)| *known == value)
        .map(|(_, name)| *name)
}

/// An 8-bit text field up to its first NUL, without trailing blanks.
/// Printable ASCII is kept; other bytes (control characters and the upper
/// half of the GEOS character set) are shown as `\xNN`.
fn sbcs_text(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let text: String = field[..end].iter().map(|&b| sbcs_char(b)).collect();
    text.trim_end_matches(' ').to_string()
}

fn sbcs_char(b: u8) -> String {
    if b == b' ' || b.is_ascii_graphic() {
        char::from(b).to_string()
    } else {
        format!("\\x{b:02X}")
    }
}

/// A DBCS text field: 16-bit little-endian Unicode characters
/// (`Include/unicode.def`) up to the first NUL. Control characters and
/// unpaired surrogates are shown as `\u{XXXX}`.
fn dbcs_text(field: &[u8]) -> String {
    let text: String = field
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .map(dbcs_char)
        .collect();
    text.trim_end_matches(' ').to_string()
}

fn dbcs_char(unit: u16) -> String {
    match char::from_u32(u32::from(unit)).filter(|c| !c.is_control()) {
        Some(c) => c.to_string(),
        None => format!("\\u{{{unit:04X}}}"),
    }
}

/// `ReleaseNumber`, shown as `major.minor.change.engineering`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Release {
    major: u16,
    minor: u16,
    change: u16,
    engineering: u16,
}

impl Release {
    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            major: word(bytes, at),
            minor: word(bytes, at + 2),
            change: word(bytes, at + 4),
            engineering: word(bytes, at + 6),
        }
    }
}

impl std::fmt::Display for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.change, self.engineering
        )
    }
}

/// `ProtocolNumber`, shown as `major.minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Protocol {
    major: u16,
    minor: u16,
}

impl Protocol {
    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            major: word(bytes, at),
            minor: word(bytes, at + 2),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// `GeodeToken`, shown as `chars/manufacturer`.
fn token_text(bytes: &[u8], at: usize) -> String {
    let chars = sbcs_text(&bytes[at..at + TOKEN_CHARS_SIZE]);
    let manufacturer = word(bytes, at + TOKEN_CHARS_SIZE);
    format!("{chars}/{manufacturer}")
}

/// A far pointer into the geode: offset and resource ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourcePointer {
    offset: u16,
    resource: u16,
}

impl ResourcePointer {
    fn read(bytes: &[u8], at: usize) -> Self {
        Self {
            offset: word(bytes, at),
            resource: word(bytes, at + 2),
        }
    }

    fn is_null(self) -> bool {
        self.offset == 0 && self.resource == 0
    }
}

impl std::fmt::Display for ResourcePointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "resource {}, offset 0x{:04X}",
            self.resource, self.offset
        )
    }
}

/// The fields of the file header that the parser reports.
struct FileHeader {
    long_name: String,
    flags: u16,
    release: Release,
    protocol: Protocol,
    token: String,
    creator: String,
    notice: String,
    /// 2.x only.
    created: Option<FileTimestamp>,
}

/// `FileDate` and `FileTime` words.
#[derive(Debug, Clone, Copy)]
struct FileTimestamp {
    date: u16,
    time: u16,
}

/// File header: signature, then the fields at the offsets of
/// [`FileHeaderLayout`]. Files of other types share the signature and are
/// rejected.
fn parse_file_header(data: &[u8], layout: Layout) -> Result<FileHeader> {
    let fields = layout.header();
    let header = slice(data, 0, fields.size, "PC/GEOS file header")?;
    let file_type = word(header, fields.file_type);
    if file_type != fields.executable_type {
        let name = name_of(fields.file_types, file_type).unwrap_or("unknown type");
        return Err(error(format!(
            "Unsupported PC/GEOS file type {file_type} ({name}); only geodes are parsed"
        )));
    }
    let flags = word(header, fields.flags);
    let long_name = &header[fields.long_name..fields.long_name + LONGNAME_SIZE];
    let long_name = if layout == Layout::Geos2 && flags & GFHF_DBCS != 0 {
        dbcs_text(long_name)
    } else {
        sbcs_text(long_name)
    };
    Ok(FileHeader {
        long_name,
        flags,
        release: Release::read(header, fields.release),
        protocol: Protocol::read(header, fields.protocol),
        token: token_text(header, fields.token),
        creator: token_text(header, fields.creator),
        notice: sbcs_text(&header[fields.notice..fields.notice + NOTICE_SIZE]),
        created: fields.created.map(|at| FileTimestamp {
            date: word(header, at),
            time: word(header, at + 2),
        }),
    })
}

/// `ExecutableFileHeader`.
struct ExecutableHeader {
    attributes: u16,
    file_type: u16,
    /// 2.x: heap space requirement in paragraphs.
    heap_space: Option<u16>,
    /// 1.x: the kernel protocol the geode expects.
    kernel_protocol: Option<Protocol>,
    resource_count: u16,
    import_library_count: u16,
    export_entry_count: u16,
    udata_size: u16,
    class: ResourcePointer,
    /// `EFH_appObj`: chunk handle, then the resource of the block.
    app_object: ResourcePointer,
}

/// Executable file header, right after the file header (layout at
/// [`EXECUTABLE_HEADER_SIZE`]).
fn parse_executable_header(data: &[u8], layout: Layout) -> Result<ExecutableHeader> {
    let at = layout.header().size;
    let header = slice(data, at, EXECUTABLE_HEADER_SIZE, "geode executable header")?;
    let (heap_space, kernel_protocol) = match layout {
        Layout::Geos2 => (Some(word(header, EFH_HEAP_SPACE)), None),
        Layout::Geos1 => (None, Some(Protocol::read(header, EFH_KERNEL_PROTOCOL))),
    };
    Ok(ExecutableHeader {
        attributes: word(header, EFH_ATTRIBUTES),
        file_type: word(header, EFH_FILE_TYPE),
        heap_space,
        kernel_protocol,
        resource_count: word(header, EFH_RESOURCE_COUNT),
        import_library_count: word(header, EFH_IMPORT_LIBRARY_COUNT),
        export_entry_count: word(header, EFH_EXPORT_ENTRY_COUNT),
        udata_size: word(header, EFH_UDATA_SIZE),
        class: ResourcePointer::read(header, EFH_CLASS_PTR),
        app_object: ResourcePointer::read(header, EFH_APP_OBJ),
    })
}

/// The core block fields the parser reports or checks.
struct CoreBlock {
    attributes: u16,
    file_type: u16,
    release: Release,
    protocol: Protocol,
    serial: u16,
    name: String,
    extension: String,
    driver_table: ResourcePointer,
    library_entry: ResourcePointer,
    export_entry_count: u16,
    library_count: u16,
    resource_count: u16,
}

/// Core block, right after the executable header (layout at
/// [`CORE_BLOCK_SIZE`]).
fn parse_core_block(data: &[u8], at: usize) -> Result<CoreBlock> {
    let core = slice(data, at, CORE_BLOCK_SIZE, "geode core block")?;
    Ok(CoreBlock {
        attributes: word(core, GH_GEODE_ATTR),
        file_type: word(core, GH_GEODE_FILE_TYPE),
        release: Release::read(core, GH_GEODE_RELEASE),
        protocol: Protocol::read(core, GH_GEODE_PROTOCOL),
        serial: word(core, GH_GEODE_SERIAL),
        name: sbcs_text(&core[GH_GEODE_NAME..GH_GEODE_NAME + GEODE_NAME_SIZE]),
        extension: sbcs_text(&core[GH_GEODE_NAME_EXT..GH_GEODE_NAME_EXT + GEODE_NAME_EXT_SIZE]),
        driver_table: ResourcePointer::read(core, GH_DRIVER_TAB),
        library_entry: ResourcePointer::read(core, GH_LIB_ENTRY),
        export_entry_count: word(core, GH_EXPORT_ENTRY_COUNT),
        library_count: word(core, GH_LIB_COUNT),
        resource_count: word(core, GH_RES_COUNT),
    })
}

/// The kernel sizes the core block from the executable header's counts and
/// lays out its tables from the core block's, and `glue` writes both from
/// one value, so they must agree.
fn check_counts(executable: &ExecutableHeader, core: &CoreBlock) -> Result<()> {
    let pairs = [
        ("resource", executable.resource_count, core.resource_count),
        (
            "imported library",
            executable.import_library_count,
            core.library_count,
        ),
        (
            "exported entry point",
            executable.export_entry_count,
            core.export_entry_count,
        ),
    ];
    for (what, in_header, in_core) in pairs {
        if in_header != in_core {
            return Err(error(format!(
                "Invalid geode header: {what} count {in_header} in the executable header, \
                 {in_core} in the core block"
            )));
        }
    }
    if usize::from(executable.resource_count) < MIN_RESOURCES {
        return Err(error(format!(
            "Invalid resource count {}: a geode has at least the core block and dgroup",
            executable.resource_count
        )));
    }
    Ok(())
}

/// `ImportedLibraryEntry`.
struct ImportedLibrary {
    name: String,
    attributes: u16,
    protocol: Protocol,
}

/// `count` imported library entries at `at`: name (8, blank padded),
/// attributes (2), expected protocol (4).
fn parse_imports(data: &[u8], at: usize, count: u16) -> Result<Vec<ImportedLibrary>> {
    let size = usize::from(count) * IMPORTED_LIBRARY_SIZE;
    let table = slice(data, at, size, "imported library table")?;
    Ok(table
        .chunks_exact(IMPORTED_LIBRARY_SIZE)
        .map(|entry| ImportedLibrary {
            name: sbcs_text(&entry[..GEODE_NAME_SIZE]),
            attributes: word(entry, GEODE_NAME_SIZE),
            protocol: Protocol::read(entry, GEODE_NAME_SIZE + 2),
        })
        .collect())
}

/// `count` exported entry points at `at`, each an offset and a resource
/// ID; an empty slot is 0, 0. Every other entry must name a resource.
fn check_exports(data: &[u8], at: usize, count: u16, resource_count: u16) -> Result<()> {
    let size = usize::from(count) * EXPORT_ENTRY_SIZE;
    let table = slice(data, at, size, "exported entry table")?;
    for (i, entry) in table.chunks_exact(EXPORT_ENTRY_SIZE).enumerate() {
        let pointer = ResourcePointer::read(entry, 0);
        if !pointer.is_null() && pointer.resource >= resource_count {
            return Err(error(format!(
                "Invalid exported entry point {i}: resource {} is not one of the \
                 {resource_count} resources",
                pointer.resource
            )));
        }
    }
    Ok(())
}

/// One resource: its data, its relocation table size and where it ends in
/// the file.
struct Resource<'a> {
    index: usize,
    offset: usize,
    bytes: &'a [u8],
    relocation_size: usize,
    /// End of the relocation table, or of the paragraph-padded data (as far
    /// as the file holds it) when there are no relocations.
    end: usize,
    flags: u16,
}

impl Resource<'_> {
    fn is_code(&self) -> bool {
        self.flags & HAF_CODE != 0
    }

    /// What the allocation flags say the resource holds.
    fn kind(&self) -> &'static str {
        if self.is_code() {
            "code"
        } else if self.index == DGROUP_RESOURCE {
            "dgroup"
        } else if self.flags & HAF_OBJECT_RESOURCE != 0 {
            "object block"
        } else if self.flags & HF_LMEM != 0 {
            "LMem block"
        } else if self.flags & HF_FIXED != 0 {
            "fixed data"
        } else {
            "data"
        }
    }
}

/// `size`, a resource size word, rounded up to a paragraph.
fn paragraph_align(size: usize) -> usize {
    (size + PARAGRAPH - 1) & !(PARAGRAPH - 1)
}

/// The resource table at `at` (sizes, file positions, relocation table
/// sizes and allocation flags, `count` entries each) and the ranges it
/// names. Every resource lies after the tables (`tables_end`) and inside
/// the file; its relocations follow its data padded to a paragraph. The
/// padding of a resource without relocations may be missing at the end of
/// the file.
fn parse_resources(
    data: &[u8],
    at: usize,
    count: u16,
    position_base: usize,
) -> Result<Vec<Resource<'_>>> {
    let count = usize::from(count);
    let table = slice(data, at, count * RESOURCE_ENTRY_SIZE, "resource table")?;
    let tables_end = at + table.len();
    let mut resources = Vec::with_capacity(count);
    for index in 0..count {
        let size = usize::from(word(table, 2 * index));
        let position = dword(table, 2 * count + 4 * index);
        let relocation_size = usize::from(word(table, 6 * count + 2 * index));
        let flags = word(table, 8 * count + 2 * index);
        let offset = usize::try_from(position)
            .ok()
            .and_then(|position| position.checked_add(position_base))
            .ok_or_else(|| error(format!("Invalid resource {index} position 0x{position:X}")))?;
        if relocation_size % RELOCATION_ENTRY_SIZE != 0 {
            return Err(error(format!(
                "Invalid relocation table size {relocation_size} B for resource {index}"
            )));
        }
        if offset < tables_end && size + relocation_size > 0 {
            return Err(error(format!(
                "Invalid resource {index} position 0x{position:X}: file offset 0x{offset:X} \
                 lies inside the geode header or tables"
            )));
        }
        let bytes = slice(data, offset, size, &format!("resource {index}"))?;
        // The resource fits in the file, so its padded end cannot overflow.
        let padded_end = offset + paragraph_align(size);
        let end = if relocation_size == 0 {
            padded_end.min(data.len())
        } else {
            let what = format!("relocation table of resource {index}");
            slice(data, padded_end, relocation_size, &what)?;
            padded_end + relocation_size
        };
        resources.push(Resource {
            index,
            offset,
            bytes,
            relocation_size,
            end,
            flags,
        });
    }
    Ok(resources)
}

/// The names of the set `GeodeAttrs` bits.
fn attribute_text(attributes: u16) -> String {
    let names: Vec<&str> = GEODE_ATTRIBUTES
        .iter()
        .filter(|(bit, _)| attributes & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        format!("0x{attributes:04X}")
    } else {
        format!("0x{attributes:04X} ({})", names.join(", "))
    }
}

/// The name of a `GeodeType` value.
fn geode_type_text(file_type: u16) -> String {
    name_of(&GEODE_TYPES, file_type)
        .map_or_else(|| format!("unknown type {file_type}"), ToString::to_string)
}

/// `FileDate` (year since 1980, month, day) and `FileTime` (hour, minute,
/// 2-second) as `YYYY-MM-DD hh:mm:ss`, or `None` when both are zero or a
/// field is out of range.
fn timestamp_text(stamp: FileTimestamp) -> Option<String> {
    let FileTimestamp { date, time } = stamp;
    if date == 0 && time == 0 {
        return None;
    }
    let year = 1980 + (date >> 9);
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = time >> 11;
    let minute = (time >> 5) & 0x3F;
    let second = (time & 0x1F) * 2;
    let valid = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60;
    valid.then(|| format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"))
}

/// Imported geodes as `name major.minor`, drivers marked, at most
/// [`MAX_LISTED_IMPORTS`] of them.
fn imports_text(imports: &[ImportedLibrary]) -> String {
    let mut listed: Vec<String> = imports
        .iter()
        .take(MAX_LISTED_IMPORTS)
        .map(|library| {
            let driver = if library.attributes & GA_DRIVER != 0 {
                " (driver)"
            } else {
                ""
            };
            format!("{} {}{driver}", library.name, library.protocol)
        })
        .collect();
    if imports.len() > MAX_LISTED_IMPORTS {
        listed.push(format!("and {} more", imports.len() - MAX_LISTED_IMPORTS));
    }
    listed.join(", ")
}

/// Where the geode's entry points are, from the attributes.
fn entry_text(executable: &ExecutableHeader, core: &CoreBlock) -> Vec<String> {
    let mut entries = Vec::new();
    if executable.attributes & GA_PROCESS != 0 {
        entries.push(format!("process class at {}", executable.class));
        if !executable.app_object.is_null() {
            entries.push(format!(
                "application object at resource {}, chunk 0x{:04X}",
                executable.app_object.resource, executable.app_object.offset
            ));
        }
    }
    if executable.attributes & GA_LIBRARY != 0 && !core.library_entry.is_null() {
        entries.push(format!("library entry routine at {}", core.library_entry));
    }
    if executable.attributes & GA_DRIVER != 0 {
        entries.push(format!("driver table at {}", core.driver_table));
    }
    entries
}

/// Parse a geode into the shared container model: one child per resource
/// with data, code resources as 16-bit x86, the rest opaque.
///
/// # Errors
///
/// [`ClassifierError::GeosParseError`] when the file is not a geode, a
/// header or table is truncated, the header's two copies of a count
/// disagree, or a resource or relocation table lies outside the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let file = parse_file_header(data, layout)?;
    let executable = parse_executable_header(data, layout)?;
    let core_at = layout.header().size + EXECUTABLE_HEADER_SIZE;
    let core = parse_core_block(data, core_at)?;
    check_counts(&executable, &core)?;
    let imports_at = core_at + CORE_BLOCK_SIZE;
    let imports = parse_imports(data, imports_at, executable.import_library_count)?;
    let exports_at = imports_at + imports.len() * IMPORTED_LIBRARY_SIZE;
    check_exports(
        data,
        exports_at,
        executable.export_entry_count,
        executable.resource_count,
    )?;
    let resources_at = exports_at + usize::from(executable.export_entry_count) * EXPORT_ENTRY_SIZE;
    let resources = parse_resources(
        data,
        resources_at,
        executable.resource_count,
        layout.header().position_base,
    )?;
    let tables_end = resources_at + resources.len() * RESOURCE_ENTRY_SIZE;
    let consumed = resources
        .iter()
        .map(|resource| resource.end)
        .fold(tables_end, usize::max);
    expect_padding(data, consumed)?;

    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = consumed;
    push_children(&mut c, &resources);
    if c.children.iter().any(|child| child.target.is_some()) {
        c.target = Some(X86_REAL_MODE);
    }
    push_notes(&mut c, &file, &executable, &core, &imports, &resources);
    if data.len() > consumed {
        c.notes.push(format!(
            "{} B of padding after the last resource",
            data.len() - consumed
        ));
    }
    push_metadata(&mut c, &file, &executable, &core, &imports);
    Ok(c)
}

/// Bytes after the last resource may only be zero or erased fill.
/// `consumed` is the end of a bounds-checked table or resource, so it lies
/// inside the file.
fn expect_padding(data: &[u8], consumed: usize) -> Result<()> {
    let trailing = &data[consumed..];
    if trailing.iter().all(|&b| b == 0x00 || b == 0xFF) {
        Ok(())
    } else {
        Err(error(format!(
            "Invalid trailing data at 0x{consumed:X}: {} B after the last resource",
            trailing.len()
        )))
    }
}

/// One child per resource that holds data: code resources go to the code
/// model as 16-bit x86, everything else is opaque.
fn push_children<'a>(c: &mut Container<'a>, resources: &[Resource<'a>]) {
    let mut unlisted = 0usize;
    for resource in resources.iter().filter(|r| !r.bytes.is_empty()) {
        if c.children.len() >= MAX_COMPONENTS {
            unlisted += 1;
            continue;
        }
        let label = format!("Resource {} ({})", resource.index, resource.kind());
        let child = if resource.is_code() {
            Child::stored(label, resource.offset, resource.bytes)
                .as_code()
                .with_target(X86_REAL_MODE)
        } else {
            Child::opaque(label, resource.offset, resource.bytes)
        };
        c.children.push(child);
    }
    if unlisted > 0 {
        c.notes.push(format!(
            "{unlisted} further resources were not listed (limit {MAX_COMPONENTS})"
        ));
    }
}

/// Notes: identity, attributes and versions, imports, entry points,
/// resources and the ISA rule, then anything inconsistent.
fn push_notes(
    c: &mut Container<'_>,
    file: &FileHeader,
    executable: &ExecutableHeader,
    core: &CoreBlock,
    imports: &[ImportedLibrary],
    resources: &[Resource<'_>],
) {
    c.notes.push(format!(
        "{} geode \"{}\"; permanent name \"{}\", extension \"{}\"",
        capitalized(&geode_type_text(executable.file_type)),
        file.long_name,
        core.name,
        core.extension
    ));
    c.notes.push(format!(
        "Attributes {}",
        attribute_text(executable.attributes)
    ));
    c.notes.push(format!(
        "Release {}; protocol {}; token {}; creator {}",
        file.release, file.protocol, file.token, file.creator
    ));
    if let Some(protocol) = executable.kernel_protocol {
        c.notes.push(format!("Expected kernel protocol {protocol}"));
    }
    if !imports.is_empty() {
        c.notes.push(format!(
            "Imports {} (expected protocol): {}",
            counted(imports.len(), "geode"),
            imports_text(imports)
        ));
    }
    let mut entries = vec![counted(
        usize::from(executable.export_entry_count),
        "exported entry point",
    )];
    entries.extend(entry_text(executable, core));
    c.notes.push(capitalized(&entries.join("; ")));
    let code: Vec<&Resource<'_>> = resources.iter().filter(|r| r.is_code()).collect();
    let code_size: usize = code.iter().map(|r| r.bytes.len()).sum();
    let relocations: usize = resources
        .iter()
        .map(|r| r.relocation_size / RELOCATION_ENTRY_SIZE)
        .sum();
    c.notes.push(format!(
        "{} ({} code, {code_size} B); {}, not applied; {} B of uninitialized data after dgroup",
        counted(resources.len(), "resource"),
        code.len(),
        counted(relocations, "relocation"),
        executable.udata_size
    ));
    if code.is_empty() {
        c.notes
            .push("No resource is marked as code (HAF_CODE); ISA analysis was not applied".into());
    } else {
        c.notes.push(
            "Code resources (HAF_CODE) are 16-bit x86 real-mode code: PC/GEOS runs on 80x86 \
             processors in real mode; other resources are data"
                .into(),
        );
    }
    if let Some(paragraphs) = executable.heap_space.filter(|&p| p > 0) {
        c.notes.push(format!(
            "Heap space requirement {paragraphs} paragraphs ({} B)",
            usize::from(paragraphs) * PARAGRAPH
        ));
    }
    push_inconsistencies(c, file, executable, core);
}

/// Copies in the core block that differ from the headers they copy.
fn push_inconsistencies(
    c: &mut Container<'_>,
    file: &FileHeader,
    executable: &ExecutableHeader,
    core: &CoreBlock,
) {
    if core.attributes != executable.attributes {
        c.notes.push(format!(
            "Core block attributes 0x{:04X} differ from the executable header's 0x{:04X}",
            core.attributes, executable.attributes
        ));
    }
    if core.file_type != executable.file_type {
        c.notes.push(format!(
            "Core block geode type {} differs from the executable header's {}",
            core.file_type, executable.file_type
        ));
    }
    if core.release != file.release || core.protocol != file.protocol {
        c.notes.push(format!(
            "Core block release {} and protocol {} differ from the file header's",
            core.release, core.protocol
        ));
    }
}

/// `n` and `noun`, with a plural `s` unless `n` is 1.
fn counted(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Metadata entries for the identity and counts.
fn push_metadata(
    c: &mut Container<'_>,
    file: &FileHeader,
    executable: &ExecutableHeader,
    core: &CoreBlock,
    imports: &[ImportedLibrary],
) {
    c.push_metadata("geos_long_name", "Long name", file.long_name.clone());
    c.push_metadata(
        "geos_permanent_name",
        "Permanent name",
        format!("{}.{}", core.name, core.extension),
    );
    c.push_metadata(
        "geos_geode_type",
        "Geode type",
        geode_type_text(executable.file_type),
    );
    c.push_metadata(
        "geos_attributes",
        "Geode attributes",
        format!("0x{:04X}", executable.attributes),
    );
    c.push_metadata("geos_release", "Release", file.release.to_string());
    c.push_metadata("geos_protocol", "Protocol", file.protocol.to_string());
    c.push_metadata("geos_token", "Token", file.token.clone());
    c.push_metadata("geos_creator", "Creator token", file.creator.clone());
    c.push_metadata(
        "geos_file_flags",
        "File header flags",
        format!("0x{:04X}", file.flags),
    );
    c.push_metadata(
        "geos_serial",
        "Serial (time stamp)",
        format!("0x{:04X}", core.serial),
    );
    c.push_metadata(
        "geos_resource_count",
        "Resources",
        u64::from(executable.resource_count),
    );
    c.push_metadata(
        "geos_export_count",
        "Exported entry points",
        u64::from(executable.export_entry_count),
    );
    c.push_metadata(
        "geos_import_count",
        "Imported geodes",
        u64::from(executable.import_library_count),
    );
    if !imports.is_empty() {
        c.push_metadata("geos_imports", "Imported geodes", imports_text(imports));
    }
    if !file.notice.is_empty() {
        c.push_metadata("geos_notice", "Copyright notice", file.notice.clone());
    }
    if let Some(created) = file.created.and_then(timestamp_text) {
        c.push_metadata("geos_created", "Created (file header)", created);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_fields_stop_at_nul_and_escape_non_ascii() {
        assert_eq!(sbcs_text(b"dhcp    "), "dhcp");
        assert_eq!(sbcs_text(b"DHCP Library\0junk"), "DHCP Library");
        assert_eq!(sbcs_text(&[b'A', 0x80, b'\t']), "A\\x80\\x09");
        assert_eq!(dbcs_text(&[b'G', 0, 0xE9, 0, 0, 0, b'x', 0]), "G\u{e9}");
        assert_eq!(dbcs_text(&[0x00, 0xD8, 0x0A, 0x00]), "\\u{D800}\\u{000A}");
    }

    #[test]
    fn signatures_name_the_header_version() {
        assert_eq!(detect(&[0xC7, 0x45, 0xC1, 0x53, 0]), Some(Layout::Geos2));
        assert_eq!(detect(&[0xC7, 0x45, 0xCF, 0x53]), Some(Layout::Geos1));
        assert_eq!(detect(&[0xC7, 0x45, 0xC1]), None);
        assert_eq!(detect(b"GEOS"), None);
    }

    #[test]
    fn timestamps_decode_dos_date_and_time_or_are_left_out() {
        let stamp = |date, time| timestamp_text(FileTimestamp { date, time });
        assert_eq!(
            stamp(0x2565, 0x1E21).as_deref(),
            Some("1998-11-05 03:49:02")
        );
        assert_eq!(stamp(0, 0), None);
        assert_eq!(stamp(0x2560, 0), None);
    }

    #[test]
    fn relocations_follow_data_padded_to_a_paragraph() {
        assert_eq!(paragraph_align(0), 0);
        assert_eq!(paragraph_align(0x3CE), 0x3D0);
        assert_eq!(paragraph_align(0x10), 0x10);
        assert_eq!(paragraph_align(0xFFFF), 0x1_0000);
    }

    #[test]
    fn attributes_and_types_are_named() {
        assert_eq!(attribute_text(0x5000), "0x5000 (library, keep file open)");
        assert_eq!(attribute_text(0x0001), "0x0001");
        assert_eq!(geode_type_text(3), "driver");
        assert_eq!(geode_type_text(9), "unknown type 9");
    }
}
