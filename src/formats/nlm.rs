//! `NetWare` Loadable Modules (NLMs): the fixed, variable and auxiliary
//! headers (`VeRsIoN#`, `CoPyRiGhT=`, `MeSsAgEs`, `CuStHeAd` with the
//! `CyGnUsEx` section table), the code and data images, and the module
//! dependency, fixup, import, export and debug tables, for the four NLM
//! targets GNU binutils defines (i386, SPARC, PowerPC, Alpha).
//!
//! Sources (pinned with checksums in `docs/nlm.md`), GNU binutils tag
//! `binutils-2_24` (commit `237df3fa4a1d`):
//! - `include/nlm/common.h`: signature, module name and text limits,
//!   `NLM_HEADER_VERSION`, the Alpha prefix magic.
//! - `include/nlm/internal.h` and `include/nlm/external.h`: field meanings,
//!   the variable header and the auxiliary header layouts.
//! - `include/nlm/i386-ext.h`, `sparc32-ext.h`, `ppc-ext.h`, `alpha-ext.h`:
//!   each target's fixed header (SPARC, PowerPC and Alpha pad the module
//!   name to 16 bytes) and the Alpha prefix header.
//! - `bfd/nlmcode.h`: `nlm_object_p` (prefix, signature, version sanity
//!   check), `nlm_swap_variable_header_in`, `nlm_swap_auxiliary_headers_in`
//!   and `nlm_slurp_symbol_table` (export and debug records).
//! - `bfd/nlm32-i386.c`, `nlm32-sparc.c`, `nlm32-ppc.c`, `nlm32-alpha.c`:
//!   signatures, architectures, relocation and import records;
//!   `bfd/nlm-target.h`: header and data byte order per target.
//! - `binutils/nlmconv.c` (module dependency list, module name) and
//!   `binutils/nlmheader.y` (the `flags` keyword bits).
//!
//! The 24-byte signature "depends upon the NLM target" (`internal.h`), and
//! binutils selects the backend, and with it the architecture, by matching
//! it. The signature is therefore the format's target field: the
//! `NetWare Loadable Module` signature is the `nlm32-i386` target, and the
//! SPARC, PowerPC and Alpha targets each carry their own. Every word is in
//! the target's byte order: little-endian for i386 and Alpha, big-endian
//! for SPARC and PowerPC. Offsets are file offsets; the code and data
//! images are relocatable (binutils loads both at address 0) and the
//! procedure offsets are relative to the code image.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Section, Target};
use crate::types::{Endianness, FileFormat, Isa, MetadataValue};
use std::borrow::Cow;

mod header;
mod tables;

use header::{AuxiliaryHeaders, CustomHeader, ExtendedHeader, FixedHeader, VariableHeader};

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "nlm";

/// `NLM_SIGNATURE_SIZE`.
const SIGNATURE_SIZE: usize = 24;

/// `NLM_TARGET_LONG_SIZE`: every header and table word of the 32-bit NLM
/// targets is 4 bytes.
const WORD_SIZE: usize = 4;

/// `nlm32-i386` signature: `NetWare Loadable Module` and `0x1A`.
const I386_SIGNATURE: &[u8; SIGNATURE_SIZE] = b"NetWare Loadable Module\x1a";
/// `nlm32-sparc` signature.
const SPARC_SIGNATURE: &[u8; SIGNATURE_SIZE] = b"NetWare SPARC Module   \x1a";
/// `nlm32-powerpc` signature.
const POWERPC_SIGNATURE: &[u8; SIGNATURE_SIZE] = b"NetWare PowerPC Module \x1a";
/// `nlm32-alpha` signature, after the Alpha prefix header.
const ALPHA_SIGNATURE: &[u8; SIGNATURE_SIZE] = b"NetWare Alpha Module   \x1a";

/// `NLM32_ALPHA_MAGIC`, the first word of the Alpha prefix header.
const NLM32_ALPHA_MAGIC: u32 = 0x8356_1840;
/// Size of `nlm32_alpha_external_prefix_header`: magic, format, size and
/// padding words.
const ALPHA_PREFIX_SIZE: usize = 16;
/// Offset of the prefix header's `size` word, which binutils seeks to
/// before it reads the fixed header.
const ALPHA_PREFIX_SIZE_FIELD: usize = 8;

/// `NLM_HEADER_VERSION`: "At this time, the highest version number is 4".
const NLM_HEADER_VERSION: u32 = 4;
/// Bit 7 of the header version (our name). Set, over a documented version,
/// in a Novell-built module whose image and table ranges lie beyond the end
/// of the file; binutils does not define it (see `docs/nlm.md`).
const VERSION_HIGH_BIT: u32 = 0x80;

/// `flags` bits that `nlmheader.y` sets for its keywords.
const FLAG_KEYWORDS: [(u32, &str); 5] = [
    (0x01, "REENTRANT"),
    (0x02, "MULTIPLE"),
    (0x04, "SYNCHRONIZE"),
    (0x08, "PSEUDOPREEMPTION"),
    (0x10, "OS_DOMAIN"),
];

/// Most module dependency names listed (our bound); the rest are counted.
const MAX_LISTED_DEPENDENCIES: usize = 16;

/// An NLM target recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `nlm32-i386`: `NetWare Loadable Module` signature.
    I386,
    /// `nlm32-sparc`: `NetWare SPARC Module` signature.
    Sparc,
    /// `nlm32-powerpc`: `NetWare PowerPC Module` signature (the current
    /// format, without the `AppleNLM` prefix of binutils' `OLDFORMAT`).
    PowerPc,
    /// `nlm32-alpha`: a prefix header with `NLM32_ALPHA_MAGIC`, then the
    /// `NetWare Alpha Module` signature.
    Alpha,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::NetWareNlm
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::I386 => "NetWare NLM (i386)",
            Self::Sparc => "NetWare NLM (SPARC)",
            Self::PowerPc => "NetWare NLM (PowerPC)",
            Self::Alpha => "NetWare NLM (Alpha)",
        }
    }

    /// Every target is recognized by its signature.
    pub fn is_weak(self) -> bool {
        false
    }

    /// The binutils backend that defines this target.
    fn backend(self) -> &'static Backend {
        BACKENDS
            .iter()
            .find(|backend| backend.layout == self)
            .expect("every layout has a backend")
    }
}

/// What a binutils NLM backend defines for its target.
struct Backend {
    layout: Layout,
    /// binutils target name.
    name: &'static str,
    /// Processor named in notes.
    processor: &'static str,
    signature: &'static [u8; SIGNATURE_SIZE],
    /// Header and data byte order (`TARGET_BIG_SYM` in `nlm-target.h`).
    big_endian: bool,
    /// The fixed header follows a prefix header.
    has_prefix: bool,
    /// Padding after the 14-byte module name in the fixed header.
    name_padding: usize,
    /// Size of one relocation record (`nlm_*_read_reloc`).
    reloc_size: usize,
    /// Import records store the relocation count before the name
    /// (`nlm_sparc_read_import`) instead of after it.
    count_before_name: bool,
    /// The processor the backend's architecture names.
    target: Target,
}

/// The binutils NLM backends (`bfd/nlm32-*.c`).
const BACKENDS: [Backend; 4] = [
    Backend {
        layout: Layout::I386,
        name: "nlm32-i386",
        processor: "i386",
        signature: I386_SIGNATURE,
        big_endian: false,
        has_prefix: false,
        name_padding: 0,
        reloc_size: 4,
        count_before_name: false,
        target: Target::new(Isa::X86, 32, Endianness::Little),
    },
    Backend {
        layout: Layout::Sparc,
        name: "nlm32-sparc",
        processor: "SPARC",
        signature: SPARC_SIGNATURE,
        big_endian: true,
        has_prefix: false,
        name_padding: 2,
        reloc_size: 12,
        count_before_name: true,
        target: Target::new(Isa::Sparc, 32, Endianness::Big),
    },
    Backend {
        layout: Layout::PowerPc,
        name: "nlm32-powerpc",
        processor: "PowerPC",
        signature: POWERPC_SIGNATURE,
        big_endian: true,
        has_prefix: false,
        name_padding: 2,
        reloc_size: 4,
        count_before_name: false,
        target: Target::new(Isa::Ppc, 32, Endianness::Big),
    },
    Backend {
        layout: Layout::Alpha,
        name: "nlm32-alpha",
        processor: "Alpha",
        signature: ALPHA_SIGNATURE,
        big_endian: false,
        has_prefix: true,
        name_padding: 2,
        reloc_size: 16,
        count_before_name: false,
        target: Target::new(Isa::Alpha, 64, Endianness::Little),
    },
];

/// Strong recognition: a target signature at offset 0, or the Alpha prefix
/// magic followed by the Alpha signature at the offset the prefix names.
/// The headers and tables are checked by the parser, so a damaged module
/// is a parse error rather than raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let at_start = BACKENDS
        .iter()
        .find(|backend| !backend.has_prefix && data.starts_with(backend.signature));
    if let Some(backend) = at_start {
        return Some(backend.layout);
    }
    alpha_header_offset(data).ok().map(|_| Layout::Alpha)
}

/// File offset of an Alpha module's fixed header: the prefix header's
/// `size` word, which must locate the Alpha signature.
fn alpha_header_offset(data: &[u8]) -> Result<usize> {
    let reader = Reader::new(data, false);
    reader.bytes(0, ALPHA_PREFIX_SIZE, "Alpha prefix header")?;
    if reader.word(0, "Alpha prefix header")? != NLM32_ALPHA_MAGIC {
        return Err(error("Missing NLM32_ALPHA_MAGIC at 0x0"));
    }
    let offset = to_usize(reader.word(ALPHA_PREFIX_SIZE_FIELD, "Alpha prefix header")?);
    if offset < ALPHA_PREFIX_SIZE {
        return Err(error(format!(
            "Invalid Alpha prefix header size {offset} B (at least {ALPHA_PREFIX_SIZE} B)"
        )));
    }
    if reader.bytes(offset, SIGNATURE_SIZE, "signature")? != ALPHA_SIGNATURE {
        return Err(error(format!("Missing Alpha signature at 0x{offset:X}")));
    }
    Ok(offset)
}

/// File offset of the fixed header, after checking the target signature.
fn header_offset(data: &[u8], backend: &Backend) -> Result<usize> {
    if backend.has_prefix {
        return alpha_header_offset(data);
    }
    if Reader::new(data, false).bytes(0, SIGNATURE_SIZE, "signature")? != backend.signature {
        return Err(error(format!("Missing {} signature at 0x0", backend.name)));
    }
    Ok(0)
}

/// Parse `data` as the given NLM target.
///
/// # Errors
///
/// [`ClassifierError::NlmParseError`] for a missing signature, a truncated
/// or inconsistent header, an unsupported header version, or an image or
/// table that does not fit the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let backend = layout.backend();
    let reader = Reader::new(data, backend.big_endian);
    let start = header_offset(data, backend)?;
    let fixed = FixedHeader::parse(reader, start, backend)?;
    let documented = is_documented_version(fixed.version)?;
    let module_name = fixed.module_name()?;
    let variable = VariableHeader::parse(reader, fixed.end)?;
    let auxiliary = AuxiliaryHeaders::parse(reader, variable.end)?;

    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.target = Some(backend.target);
    let byte_order = if backend.big_endian {
        "big-endian"
    } else {
        "little-endian"
    };
    // An undocumented version is reported in its own note below.
    let version = if documented {
        format!("; header version {}", fixed.version)
    } else {
        String::new()
    };
    c.notes.push(format!(
        "The signature names the {} target (binutils {}){version}; {byte_order} header fields",
        backend.processor, backend.name
    ));
    c.notes.push(identity_note(module_name, &variable));
    if let Some(version) = &auxiliary.version {
        c.notes.push(format!("Module {}", version.describe()));
    }
    push_header_metadata(&mut c, &fixed, module_name, &variable, &auxiliary);
    if documented {
        load(&mut c, reader, backend, &fixed, &auxiliary)?;
    } else {
        c.opaque = true;
        c.consumed = data.len();
        c.notes.push(format!(
            "Header version 0x{:X} is not documented (binutils documents versions up to \
             {NLM_HEADER_VERSION}); the image and table ranges are not checked and the code \
             image is not analyzed",
            fixed.version
        ));
    }
    Ok(c)
}

/// Whether `version` is a documented header version (1 to 4). A
/// documented version with bit 7 set is accepted without its images; any
/// other value is an error.
fn is_documented_version(version: u32) -> Result<bool> {
    let documented = 1..=NLM_HEADER_VERSION;
    if documented.contains(&version) {
        return Ok(true);
    }
    if version & VERSION_HIGH_BIT != 0 && documented.contains(&(version & !VERSION_HIGH_BIT)) {
        return Ok(false);
    }
    Err(error(format!("Unsupported header version 0x{version:X}")))
}

/// `"Module IPTRACE.NLM: <description>"`.
fn identity_note(module_name: &[u8], variable: &VariableHeader<'_>) -> String {
    let name = display_text(module_name);
    let description = display_text(variable.description);
    if description.is_empty() {
        format!("Module {name}; no description")
    } else {
        format!("Module {name}: {description}")
    }
}

/// Metadata from the headers, recorded for every header version.
fn push_header_metadata(
    c: &mut Container<'_>,
    fixed: &FixedHeader<'_>,
    module_name: &[u8],
    variable: &VariableHeader<'_>,
    auxiliary: &AuxiliaryHeaders<'_>,
) {
    c.push_metadata(
        "nlm_header_version",
        "Header version",
        u64::from(fixed.version),
    );
    c.push_metadata("nlm_module_name", "Module name", display_text(module_name));
    c.push_metadata(
        "nlm_description",
        "Description",
        display_text(variable.description),
    );
    c.push_metadata(
        "nlm_stack_size",
        "Stack size (B)",
        u64::from(variable.stack_size),
    );
    if !variable.screen_name.is_empty() {
        c.push_metadata(
            "nlm_screen_name",
            "Screen name",
            display_text(variable.screen_name),
        );
    }
    if !variable.thread_name.is_empty() {
        c.push_metadata(
            "nlm_thread_name",
            "Thread name",
            display_text(variable.thread_name),
        );
    }
    c.push_metadata(
        "nlm_module_type",
        "Module type",
        u64::from(fixed.module_type),
    );
    c.push_metadata("nlm_flags", "Flags", MetadataValue::Hex(fixed.flags));
    if let Some(version) = &auxiliary.version {
        c.push_metadata("nlm_module_version", "Module version", version.describe());
    }
    if let Some(copyright) = auxiliary.copyright {
        c.push_metadata("nlm_copyright", "Copyright", display_text(copyright));
    }
    if let Some(extended) = &auxiliary.extended {
        c.push_metadata(
            "nlm_language_id",
            "Language ID",
            u64::from(extended.language_id),
        );
        if extended.product_id != 0 {
            c.push_metadata(
                "nlm_product_id",
                "Product ID",
                MetadataValue::Hex(extended.product_id),
            );
        }
    }
}

/// Check and describe a module with a documented header version: the
/// images, tables and procedure offsets, then every range an auxiliary
/// header names.
fn load<'a>(
    c: &mut Container<'a>,
    reader: Reader<'a>,
    backend: &Backend,
    fixed: &FixedHeader<'_>,
    auxiliary: &AuxiliaryHeaders<'_>,
) -> Result<()> {
    let code = reader.extent(fixed.code_image, "code image")?;
    let data_image = reader.extent(fixed.data_image, "data image")?;
    let custom_data = reader.extent(fixed.custom_data, "custom data")?;
    let dependencies = tables::module_dependencies(reader, fixed.module_dependencies)?;
    let fixups_end = tables::relocation_fixups(reader, fixed.relocation_fixups, backend)?;
    let externals_end = tables::external_references(reader, fixed.external_references, backend)?;
    let publics_end = tables::publics(reader, fixed.publics)?;
    let debug_end = tables::debug_records(reader, fixed.debug_records)?;
    check_procedures(fixed)?;
    let auxiliary_end = check_auxiliary_ranges(c, reader, auxiliary)?;

    let ends = [
        auxiliary.end,
        code.end,
        data_image.end,
        custom_data.end,
        dependencies.end,
        fixups_end,
        externals_end,
        publics_end,
        debug_end,
        auxiliary_end,
    ];
    c.consumed = ends.into_iter().max().unwrap_or(0);
    if !code.bytes.is_empty() {
        c.sections.push(Section {
            label: "Code image".into(),
            address: 0,
            offset: to_usize(fixed.code_image.offset),
            stored_size: code.bytes.len(),
            data: Cow::Borrowed(code.bytes),
            transform: None,
        });
    }
    c.code_sections = true;
    c.entry = Some(u64::from(fixed.code_start));
    push_image_notes(c, fixed);
    push_table_notes(c, fixed, &dependencies);
    push_load_metadata(c, fixed, &dependencies);
    push_trailing_note(c, reader.data);
    Ok(())
}

/// The start, exit and check-unload procedures are offsets into the code
/// image. A zero offset is not checked: `nlmconv` leaves the zeroed
/// check-unload field when no `CHECK` procedure is given.
fn check_procedures(fixed: &FixedHeader<'_>) -> Result<()> {
    let procedures = [
        ("code start", fixed.code_start),
        ("exit procedure", fixed.exit_procedure),
        ("check-unload procedure", fixed.check_unload_procedure),
    ];
    let code_size = fixed.code_image.size;
    for (what, offset) in procedures {
        if offset != 0 && offset >= code_size {
            return Err(error(format!(
                "Invalid {what} offset 0x{offset:X} (the code image is {code_size} B)"
            )));
        }
    }
    Ok(())
}

/// Check that every range the extended and custom headers name lies in
/// the file, record the ranges, and return the end of the last one.
fn check_auxiliary_ranges(
    c: &mut Container<'_>,
    reader: Reader<'_>,
    auxiliary: &AuxiliaryHeaders<'_>,
) -> Result<usize> {
    let mut end = 0;
    if let Some(extended) = &auxiliary.extended {
        end = check_extended_ranges(c, reader, extended)?;
    }
    for (i, custom) in auxiliary.custom.iter().enumerate() {
        end = end.max(check_custom_header(c, reader, i, custom)?);
    }
    Ok(end)
}

/// The message file, help file, RPC data and shared images of a
/// `MeSsAgEs` header.
fn check_extended_ranges(
    c: &mut Container<'_>,
    reader: Reader<'_>,
    extended: &ExtendedHeader,
) -> Result<usize> {
    let ranges = [
        (
            "message file",
            "nlm_message_file",
            "Message file",
            extended.message_file,
        ),
        (
            "help file",
            "nlm_help_file",
            "Help file",
            extended.help_file,
        ),
        ("RPC data", "nlm_rpc_data", "RPC data", extended.rpc_data),
        (
            "shared code image",
            "nlm_shared_code",
            "Shared code image",
            extended.shared_code,
        ),
        (
            "shared data image",
            "nlm_shared_data",
            "Shared data image",
            extended.shared_data,
        ),
    ];
    let mut end = 0;
    for (what, key, label, extent) in ranges {
        let stored = reader.extent(extent, what)?;
        if stored.bytes.is_empty() {
            continue;
        }
        end = end.max(stored.end);
        c.push_metadata(key, label, extent_text(extent));
    }
    if extended.message_file.size != 0 {
        c.push_metadata(
            "nlm_message_count",
            "Messages",
            u64::from(extended.message_count),
        );
    }
    Ok(end)
}

/// A `CuStHeAd` header's data range; for a `CyGnUsEx` header, the section
/// table of the original object file.
fn check_custom_header(
    c: &mut Container<'_>,
    reader: Reader<'_>,
    index: usize,
    custom: &CustomHeader<'_>,
) -> Result<usize> {
    if custom.is_cygnus() {
        let table = reader.extent(custom.data, "Cygnus section table")?;
        let sections = tables::cygnus_sections(table.bytes, custom.data.offset)?;
        c.push_metadata(
            "nlm_cygnus_sections",
            "Cygnus section table",
            format!(
                "{}; {}",
                extent_text(custom.data),
                count(to_u64(sections), "section", "sections")
            ),
        );
        return Ok(table.end);
    }
    let data = reader.extent(custom.data, "custom header data")?;
    c.push_metadata(
        format!("nlm_custom_header_{index}"),
        "Custom header",
        format!(
            "header 0x{:X}; data {}; data stamp {}",
            custom.offset,
            extent_text(custom.data),
            display_text(custom.data_stamp)
        ),
    );
    Ok(data.end)
}

/// Notes on the code and data images, the uninitialized data and the
/// flags.
fn push_image_notes(c: &mut Container<'_>, fixed: &FixedHeader<'_>) {
    let check_unload = if fixed.check_unload_procedure == 0 {
        String::new()
    } else {
        format!(
            ", check-unload procedure at 0x{:X}",
            fixed.check_unload_procedure
        )
    };
    c.notes.push(format!(
        "Code image: {} at 0x{:X}, relocatable (analyzed at address 0); start procedure at \
         0x{:X}, exit procedure at 0x{:X}{check_unload} (code image offsets)",
        size_text(u64::from(fixed.code_image.size)),
        fixed.code_image.offset,
        fixed.code_start,
        fixed.exit_procedure
    ));
    let uninitialized = if fixed.uninitialized_data_size == 0 {
        String::new()
    } else {
        format!(
            "; {} of uninitialized data follow it at load time",
            size_text(u64::from(fixed.uninitialized_data_size))
        )
    };
    c.notes.push(format!(
        "Data image: {} at 0x{:X}, not analyzed as code{uninitialized}",
        size_text(u64::from(fixed.data_image.size)),
        fixed.data_image.offset
    ));
    if fixed.flags != 0 {
        c.notes.push(format!(
            "Flags 0x{:X}: {}",
            fixed.flags,
            flag_text(fixed.flags)
        ));
    }
}

/// Notes on the module dependencies and the symbol tables.
fn push_table_notes(
    c: &mut Container<'_>,
    fixed: &FixedHeader<'_>,
    dependencies: &tables::Dependencies,
) {
    let dependency_count = u64::from(fixed.module_dependencies.count);
    if dependency_count == 0 {
        c.notes.push("No module dependencies".into());
    } else {
        c.notes.push(format!(
            "{}: {}",
            count(dependency_count, "module dependency", "module dependencies"),
            dependency_list(dependencies)
        ));
    }
    c.notes.push(format!(
        "{}, {}, {}, {}",
        count(
            u64::from(fixed.relocation_fixups.count),
            "relocation fixup",
            "relocation fixups"
        ),
        count(
            u64::from(fixed.external_references.count),
            "external reference",
            "external references"
        ),
        count(u64::from(fixed.publics.count), "public", "publics"),
        count(
            u64::from(fixed.debug_records.count),
            "debug record",
            "debug records"
        )
    ));
}

/// Metadata on the images, tables and procedures of a documented module.
fn push_load_metadata(
    c: &mut Container<'_>,
    fixed: &FixedHeader<'_>,
    dependencies: &tables::Dependencies,
) {
    c.push_metadata(
        "nlm_data_image",
        "Data image",
        extent_text(fixed.data_image),
    );
    c.push_metadata(
        "nlm_uninitialized_data_size",
        "Uninitialized data size (B)",
        u64::from(fixed.uninitialized_data_size),
    );
    if fixed.custom_data.size != 0 {
        c.push_metadata(
            "nlm_custom_data",
            "Custom data",
            extent_text(fixed.custom_data),
        );
    }
    c.push_metadata(
        "nlm_code_start",
        "Start procedure (code offset)",
        MetadataValue::Address(u64::from(fixed.code_start)),
    );
    c.push_metadata(
        "nlm_exit_procedure",
        "Exit procedure (code offset)",
        MetadataValue::Address(u64::from(fixed.exit_procedure)),
    );
    if fixed.check_unload_procedure != 0 {
        c.push_metadata(
            "nlm_check_unload_procedure",
            "Check-unload procedure (code offset)",
            MetadataValue::Address(u64::from(fixed.check_unload_procedure)),
        );
    }
    if fixed.module_dependencies.count != 0 {
        c.push_metadata(
            "nlm_module_dependencies",
            "Module dependencies",
            dependency_list(dependencies),
        );
    }
    let counts = [
        (
            "nlm_relocation_fixups",
            "Relocation fixups",
            fixed.relocation_fixups,
        ),
        (
            "nlm_external_references",
            "External references",
            fixed.external_references,
        ),
        ("nlm_publics", "Publics", fixed.publics),
        ("nlm_debug_records", "Debug records", fixed.debug_records),
    ];
    for (key, label, table) in counts {
        c.push_metadata(key, label, u64::from(table.count));
    }
}

/// Module dependency names, the first [`MAX_LISTED_DEPENDENCIES`] of them.
fn dependency_list(dependencies: &tables::Dependencies) -> String {
    let names = dependencies.names.join(", ");
    if dependencies.unlisted == 0 {
        names
    } else {
        format!("{names} and {} more", dependencies.unlisted)
    }
}

/// A note for bytes after the last structure the headers describe. NLMs
/// define no trailer, but a linker may append data (debug information), so
/// the bytes are reported rather than rejected; they are never analyzed.
fn push_trailing_note(c: &mut Container<'_>, data: &[u8]) {
    let trailing = data.get(c.consumed..).unwrap_or_default();
    if !trailing.iter().all(|&b| b == 0x00 || b == 0xff) {
        c.notes.push(format!(
            "{} after 0x{:X} are not described by the headers and are not analyzed",
            size_text(to_u64(trailing.len())),
            c.consumed
        ));
    }
}

/// Keyword names of the set `flags` bits, and any other bits in hex.
fn flag_text(flags: u32) -> String {
    let mut names: Vec<String> = FLAG_KEYWORDS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect();
    let known = FLAG_KEYWORDS.iter().fold(0, |bits, (bit, _)| bits | bit);
    let other = flags & !known;
    if other != 0 {
        names.push(format!("other bits 0x{other:X}"));
    }
    names.join(", ")
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::NlmParseError {
        message: message.into(),
    }
}

/// A stored range named by an offset word and a size word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Extent {
    /// File offset.
    offset: u32,
    /// Size in bytes.
    size: u32,
}

/// A table named by an offset word and a record count word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Table {
    /// File offset of the first record.
    offset: u32,
    /// Number of records.
    count: u32,
}

/// The bytes of a checked [`Extent`].
struct Stored<'a> {
    bytes: &'a [u8],
    /// File offset just past the bytes, or 0 for an empty extent.
    end: usize,
}

/// `"file 0x41E2; 1945 B"`.
fn extent_text(extent: Extent) -> String {
    format!("file 0x{:X}; {} B", extent.offset, extent.size)
}

/// Bounds-checked reads of words in the target's byte order.
#[derive(Debug, Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], big_endian: bool) -> Self {
        Self { data, big_endian }
    }

    /// The `len` bytes at `at`; `what` names them in the error.
    fn bytes(self, at: usize, len: usize, what: &str) -> Result<&'a [u8]> {
        let end = at
            .checked_add(len)
            .ok_or_else(|| error(format!("Invalid {what} range 0x{at:X} + {len} B")))?;
        self.data
            .get(at..end)
            .ok_or_else(|| error(format!("Truncated {what} at 0x{at:X} + {len} B")))
    }

    fn word(self, at: usize, what: &str) -> Result<u32> {
        let field: [u8; WORD_SIZE] = self
            .bytes(at, WORD_SIZE, what)?
            .try_into()
            .expect("slice has exactly 4 bytes");
        Ok(if self.big_endian {
            u32::from_be_bytes(field)
        } else {
            u32::from_le_bytes(field)
        })
    }

    /// The bytes of a stored range. An empty range is not checked:
    /// writers point empty ranges at the end of the file or leave them 0.
    fn extent(self, extent: Extent, what: &str) -> Result<Stored<'a>> {
        if extent.size == 0 {
            return Ok(Stored { bytes: &[], end: 0 });
        }
        let offset = to_usize(extent.offset);
        let bytes = self.bytes(offset, to_usize(extent.size), what)?;
        Ok(Stored {
            bytes,
            end: offset + bytes.len(),
        })
    }
}

/// Sequential reads from `pos` through a [`Reader`].
struct Cursor<'a> {
    reader: Reader<'a>,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(reader: Reader<'a>, pos: usize) -> Self {
        Self { reader, pos }
    }

    fn bytes(&mut self, len: usize, what: &str) -> Result<&'a [u8]> {
        let bytes = self.reader.bytes(self.pos, len, what)?;
        self.pos += len;
        Ok(bytes)
    }

    fn byte(&mut self, what: &str) -> Result<u8> {
        Ok(self.bytes(1, what)?[0])
    }

    fn word(&mut self, what: &str) -> Result<u32> {
        let word = self.reader.word(self.pos, what)?;
        self.pos += WORD_SIZE;
        Ok(word)
    }

    /// An offset word and a size word.
    fn extent(&mut self, what: &str) -> Result<Extent> {
        let offset = self.word(what)?;
        let size = self.word(what)?;
        Ok(Extent { offset, size })
    }

    /// An offset word and a record count word.
    fn table(&mut self, what: &str) -> Result<Table> {
        let offset = self.word(what)?;
        let count = self.word(what)?;
        Ok(Table { offset, count })
    }

    /// A length byte and that many bytes of text, without a terminator.
    fn counted(&mut self, what: &str) -> Result<&'a [u8]> {
        let len = self.byte(what)?;
        self.bytes(usize::from(len), what)
    }
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// A byte count as `u64`.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).expect("u64 holds a usize on supported targets")
}

/// Untrusted header text: printable ASCII as-is, other bytes as `.`,
/// trimmed.
fn display_text(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    text.trim().to_string()
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `"1 public"`, `"2 publics"`.
fn count(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_select_the_target() {
        assert_eq!(detect(I386_SIGNATURE), Some(Layout::I386));
        assert_eq!(detect(SPARC_SIGNATURE), Some(Layout::Sparc));
        assert_eq!(detect(POWERPC_SIGNATURE), Some(Layout::PowerPc));
        assert_eq!(detect(&I386_SIGNATURE[..23]), None);
        assert_eq!(detect(b"NetWare Loadable Module\x1b"), None);
        // The Alpha signature only counts after the prefix header.
        assert_eq!(detect(ALPHA_SIGNATURE), None);
    }

    #[test]
    fn alpha_prefix_locates_the_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(&NLM32_ALPHA_MAGIC.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(ALPHA_SIGNATURE);
        assert_eq!(detect(&data), Some(Layout::Alpha));
        assert_eq!(alpha_header_offset(&data).unwrap(), 20);
        data[ALPHA_PREFIX_SIZE_FIELD] = 16;
        assert_eq!(detect(&data), None);
        data[ALPHA_PREFIX_SIZE_FIELD] = 8;
        assert_eq!(
            alpha_header_offset(&data).unwrap_err().to_string(),
            "NetWare module parse error: Invalid Alpha prefix header size 8 B (at least 16 B)"
        );
    }

    #[test]
    fn layouts_report_one_format_and_strong_detection() {
        for backend in &BACKENDS {
            assert_eq!(backend.layout.format(), FileFormat::NetWareNlm);
            assert!(!backend.layout.is_weak());
            assert_eq!(backend.layout.backend().name, backend.name);
        }
    }

    #[test]
    fn header_versions_up_to_four_are_documented() {
        assert!(is_documented_version(1).unwrap());
        assert!(is_documented_version(4).unwrap());
        assert!(!is_documented_version(0x84).unwrap());
        for version in [0, 5, 0x49, 0x80, 0x85, 0x1_0004] {
            assert_eq!(
                is_documented_version(version).unwrap_err().to_string(),
                format!("NetWare module parse error: Unsupported header version 0x{version:X}")
            );
        }
    }

    #[test]
    fn readers_use_the_target_byte_order_and_name_the_range() {
        let data = [1, 2, 3, 4, 5];
        assert_eq!(
            Reader::new(&data, false).word(0, "field").unwrap(),
            0x0403_0201
        );
        assert_eq!(
            Reader::new(&data, true).word(1, "field").unwrap(),
            0x0203_0405
        );
        assert_eq!(
            Reader::new(&data, false)
                .word(2, "field")
                .unwrap_err()
                .to_string(),
            "NetWare module parse error: Truncated field at 0x2 + 4 B"
        );
        let empty = Extent {
            offset: u32::MAX,
            size: 0,
        };
        let stored = Reader::new(&data, false).extent(empty, "image").unwrap();
        assert_eq!(stored.bytes, b"");
        assert_eq!(stored.end, 0);
        let image = Extent { offset: 1, size: 3 };
        let stored = Reader::new(&data, false).extent(image, "image").unwrap();
        assert_eq!(stored.bytes, &[2, 3, 4]);
        assert_eq!(stored.end, 4);
    }

    #[test]
    fn flags_name_the_nlmheader_keywords() {
        assert_eq!(flag_text(0x10), "OS_DOMAIN");
        assert_eq!(flag_text(0x05), "REENTRANT, SYNCHRONIZE");
        assert_eq!(flag_text(0x1_0002), "MULTIPLE, other bits 0x10000");
    }

    #[test]
    fn text_and_sizes_are_display_safe() {
        assert_eq!(display_text(b" IPTRACE.NLM\0"), "IPTRACE.NLM.");
        assert_eq!(display_text(b"\x93\xe2 NetWare 386 "), ".. NetWare 386");
        assert_eq!(size_text(2 << 30), "2048 MiB");
        assert_eq!(size_text(8192), "8 KiB");
        assert_eq!(size_text(9404), "9404 B");
        assert_eq!(count(1, "public", "publics"), "1 public");
        assert_eq!(count(0, "public", "publics"), "0 publics");
    }
}
