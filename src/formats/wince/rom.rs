//! The ROM header (`ROMHDR`), the module table of contents that follows it
//! (`TOCentry`, with each module's `e32_rom` and `o32_rom` table) and the
//! file table after the modules (`FILESentry`), read through a [`Memory`]
//! map; and how a parsed ROM is reported: target, notes, metadata and
//! components.
//!
//! Layouts: Windows Embedded Compact 7 `romldr.h` (`ROM_SIGNATURE*`,
//! `ROMHDR_*` offsets, `SIZEOF_ROMHDR`, `SIZEOF_TOCentry`, `FILESentry`,
//! `o32_rom`) and `pehdr.h` (`IMAGE_SCN_*`, `IMAGE_FILE_DLL`); the Windows
//! CE 2.11 `romldr.h` for the `e32_rom` fields that every version shares.
//! BLCOMMON `IsKernelRegion` reads the TOC right after the ROMHDR and
//! translates its pointers by the ROM offset; `dumprom.cpp` reads the FILES
//! entries right after the TOC.

use super::memory::{Memory, Region};
use super::*;
use crate::formats::coff;
use crate::formats::container::{self, Child, Container, Target, MAX_COMPONENTS};
use crate::types::{Isa, MetadataValue};

/// `ROM_SIGNATURE`: the bytes `ECEC` at [`ROM_SIGNATURE_OFFSET`].
pub(super) const ROM_SIGNATURE: u32 = 0x4345_4345;
/// `ROM_SIGNATURE_OFFSET`: from the image start (`physfirst`).
pub(super) const ROM_SIGNATURE_OFFSET: usize = 0x40;
/// `ROM_TOC_POINTER_OFFSET`: where the ROMHDR's runtime address is stored,
/// from the image start.
pub(super) const ROM_TOC_POINTER_OFFSET: usize = 0x44;
/// `SIZEOF_ROMHDR`.
pub(super) const ROMHDR_SIZE: usize = 84;
/// `SIZEOF_TOCentry`.
const TOC_ENTRY_SIZE: usize = 32;
/// `sizeof(FILESentry)`: attributes, `FILETIME`, two sizes, name pointer
/// and load offset.
const FILES_ENTRY_SIZE: usize = 28;
/// The `e32_rom` fields that every version shares, `e32_objcnt` to
/// `e32_vsize`.
const E32_PREFIX_SIZE: usize = 24;
/// `sizeof(o32_rom)`.
const O32_SIZE: usize = 24;
/// `IMAGE_SCN_CNT_CODE`.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_COMPRESSED`: "Section is compressed".
const IMAGE_SCN_COMPRESSED: u32 = 0x0000_2000;
/// `IMAGE_SCN_MEM_EXECUTE`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_FILE_DLL` in `e32_imageflags`.
const IMAGE_FILE_DLL: u16 = 0x2000;
/// Longest module or file name read, without its terminator. Our own bound
/// (the Windows `MAX_PATH`), not a `romldr.h` limit.
const MAX_NAME_LEN: usize = 260;
/// First bytes of a file that [`container::is_recognized`] checks before
/// the whole file.
const RECOGNITION_PREFIX: usize = 4096;
/// Module names a note lists before it counts the rest.
const NOTE_NAMES: usize = 16;

/// Maps the ROM's runtime pointers to storage addresses: BLCOMMON's
/// `g_dwROMOffset`, the record address minus the runtime address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Translation {
    rom_offset: i64,
}

impl Translation {
    /// Pointers are storage addresses.
    pub(super) const IDENTITY: Self = Self { rom_offset: 0 };

    /// Record addresses are runtime addresses plus `rom_offset`.
    pub(super) fn new(rom_offset: i64) -> Self {
        Self { rom_offset }
    }

    /// The storage address of a runtime `pointer`.
    pub(super) fn storage(self, pointer: u32) -> Option<u64> {
        let address = i64::from(pointer).checked_add(self.rom_offset)?;
        u64::try_from(address).ok()
    }
}

/// The ROMHDR fields this module uses.
#[derive(Debug, Clone, Copy)]
pub(super) struct RomHeader {
    /// Storage address of the header.
    pub(super) address: u64,
    /// `physfirst`: runtime address of the image start.
    pub(super) phys_first: u32,
    /// `physlast`: runtime address of the image end.
    pub(super) phys_last: u32,
    /// `nummods`: TOC entries.
    pub(super) module_count: u32,
    ram_start: u32,
    ram_free: u32,
    ram_end: u32,
    copy_entries: u32,
    /// `numfiles`: FILES entries.
    pub(super) file_count: u32,
    kernel_flags: u32,
    /// `usCPUType`: an `IMAGE_FILE_MACHINE_*` value.
    pub(super) cpu_type: u16,
    misc_flags: u16,
}

impl RomHeader {
    /// ROMHDR: `dllfirst`, `dlllast`, `physfirst` (8), `physlast` (0xC),
    /// `nummods` (0x10), `ulRAMStart` (0x14), `ulRAMFree` (0x18),
    /// `ulRAMEnd` (0x1C), `ulCopyEntries` (0x20), `ulCopyOffset`,
    /// `ulProfileLen`, `ulProfileOffset`, `numfiles` (0x30),
    /// `ulKernelFlags` (0x34), `ulFSRamPercent`, `ulDrivglobStart`,
    /// `ulDrivglobLen`, `usCPUType` (0x44), `usMiscFlags` (0x46),
    /// `pExtensions`, `ulTrackingStart`, `ulTrackingLen`.
    pub(super) fn parse(bytes: &[u8], address: u64) -> Result<Self> {
        let fields = slice(bytes, 0, ROMHDR_SIZE, "ROMHDR")?;
        Ok(Self {
            address,
            phys_first: le_u32(fields, 0x08)?,
            phys_last: le_u32(fields, 0x0C)?,
            module_count: le_u32(fields, 0x10)?,
            ram_start: le_u32(fields, 0x14)?,
            ram_free: le_u32(fields, 0x18)?,
            ram_end: le_u32(fields, 0x1C)?,
            copy_entries: le_u32(fields, 0x20)?,
            file_count: le_u32(fields, 0x30)?,
            kernel_flags: le_u32(fields, 0x34)?,
            cpu_type: le_u16(fields, 0x44)?,
            misc_flags: le_u16(fields, 0x46)?,
        })
    }

    /// Bytes the module and file tables occupy after the header.
    pub(super) fn tables_size(&self) -> u64 {
        u64::from(self.module_count) * to_u64(TOC_ENTRY_SIZE)
            + u64::from(self.file_count) * to_u64(FILES_ENTRY_SIZE)
    }
}

/// The version-stable `e32_rom` prefix of a module.
#[derive(Debug)]
struct E32 {
    object_count: u16,
    image_flags: u16,
    entry_rva: u32,
    base: u32,
    virtual_size: u32,
}

impl E32 {
    /// `e32_rom`: `e32_objcnt`, `e32_imageflags` (2), `e32_entryrva` (4),
    /// `e32_vbase` (8), `e32_subsysmajor`, `e32_subsysminor`,
    /// `e32_stackmax`, `e32_vsize` (20). Later fields move between
    /// versions and are not read.
    fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            object_count: le_u16(bytes, 0)?,
            image_flags: le_u16(bytes, 2)?,
            entry_rva: le_u32(bytes, 4)?,
            base: le_u32(bytes, 8)?,
            virtual_size: le_u32(bytes, 20)?,
        })
    }
}

/// One `o32_rom` entry.
#[derive(Debug)]
struct O32 {
    virtual_size: u32,
    rva: u32,
    stored_size: u32,
    data_pointer: u32,
    flags: u32,
}

impl O32 {
    /// `o32_rom`: `o32_vsize`, `o32_rva` (4), `o32_psize` (8),
    /// `o32_dataptr` (12), `o32_realaddr` (16), `o32_flags` (20).
    fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            virtual_size: le_u32(bytes, 0)?,
            rva: le_u32(bytes, 4)?,
            stored_size: le_u32(bytes, 8)?,
            data_pointer: le_u32(bytes, 12)?,
            flags: le_u32(bytes, 20)?,
        })
    }

    /// Bytes stored at `o32_dataptr`: `min(o32_vsize, o32_psize)`, as
    /// `dumprom.cpp` extracts them.
    fn data_size(&self) -> u32 {
        self.virtual_size.min(self.stored_size)
    }

    fn is_code(&self) -> bool {
        self.flags & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
    }

    fn is_compressed(&self) -> bool {
        self.flags & IMAGE_SCN_COMPRESSED != 0
    }
}

/// A module of the TOC.
#[derive(Debug)]
struct Module {
    name: String,
    file_size: u32,
    e32: E32,
    sections: Vec<O32>,
}

impl Module {
    fn kind(&self) -> &'static str {
        if self.e32.image_flags & IMAGE_FILE_DLL != 0 {
            "DLL"
        } else {
            "EXE"
        }
    }
}

/// A FILES entry.
#[derive(Debug)]
struct RomFile {
    name: String,
    real_size: u32,
    stored_size: u32,
    load_pointer: u32,
}

impl RomFile {
    /// `dumprom.cpp` decompresses a file whose stored size differs from its
    /// real size.
    fn is_compressed(&self) -> bool {
        self.stored_size != self.real_size
    }
}

/// A validated ROM: header, modules and files.
#[derive(Debug)]
pub(super) struct Rom {
    header: RomHeader,
    translation: Translation,
    modules: Vec<Module>,
    files: Vec<RomFile>,
}

impl Rom {
    /// The ROM's header.
    pub(super) fn header(&self) -> &RomHeader {
        &self.header
    }
}

/// Bytes the tables may still claim. Entries are charged for their own
/// size and for the names, `e32_rom` and `o32_rom` tables they point to,
/// so the work and memory of reading a TOC stay proportional to the stored
/// image even when entries share pointers.
struct Budget {
    left: u64,
}

impl Budget {
    fn claim(&mut self, size: usize) -> bool {
        let size = to_u64(size);
        if size > self.left {
            return false;
        }
        self.left -= size;
        true
    }
}

/// Read and validate the module and file tables of `header`.
///
/// # Errors
///
/// When the tables do not fit the image, a pointer does not resolve to
/// stored bytes, a name is not printable ASCII, or a section's or file's
/// data is not stored.
pub(super) fn read(
    memory: &Memory<'_>,
    header: RomHeader,
    translation: Translation,
) -> Result<Rom> {
    let tables = header.tables_size();
    let mut budget = Budget {
        left: memory.size(),
    };
    if tables > budget.left {
        return Err(error(format!(
            "Invalid ROMHDR at 0x{:X}: {} and {} do not fit in the {} image",
            header.address,
            count(to_usize(header.module_count), "module", "modules"),
            count(to_usize(header.file_count), "file", "files"),
            size_text(memory.size())
        )));
    }
    budget.left -= tables;
    let toc = header.address + to_u64(ROMHDR_SIZE);
    let mut modules = Vec::with_capacity(to_usize(header.module_count));
    for index in 0..header.module_count {
        let at = toc + u64::from(index) * to_u64(TOC_ENTRY_SIZE);
        let entry = memory
            .read(at, TOC_ENTRY_SIZE)
            .ok_or_else(|| error(format!("Truncated TOC entry {index} at 0x{at:X}")))?;
        modules.push(read_module(
            memory,
            translation,
            index,
            &entry,
            &mut budget,
        )?);
    }
    let files_at = toc + u64::from(header.module_count) * to_u64(TOC_ENTRY_SIZE);
    let mut files = Vec::with_capacity(to_usize(header.file_count));
    for index in 0..header.file_count {
        let at = files_at + u64::from(index) * to_u64(FILES_ENTRY_SIZE);
        let entry = memory
            .read(at, FILES_ENTRY_SIZE)
            .ok_or_else(|| error(format!("Truncated FILES entry {index} at 0x{at:X}")))?;
        files.push(read_file(memory, translation, index, &entry, &mut budget)?);
    }
    Ok(Rom {
        header,
        translation,
        modules,
        files,
    })
}

/// TOC entry: `dwFileAttributes`, `ftTime` (4, 8 B), `nFileSize` (12),
/// `lpszFileName` (16), `ulE32Offset` (20), `ulO32Offset` (24),
/// `ulLoadOffset` (28). The three pointers are runtime addresses.
fn read_module(
    memory: &Memory<'_>,
    translation: Translation,
    index: u32,
    entry: &[u8],
    budget: &mut Budget,
) -> Result<Module> {
    let name_pointer = le_u32(entry, 16)?;
    let name = read_name(memory, translation, name_pointer, budget).ok_or_else(|| {
        error(format!(
            "Invalid TOC entry {index}: the module name at 0x{name_pointer:08X} is not a stored, NUL-terminated ASCII name"
        ))
    })?;
    let e32_pointer = le_u32(entry, 20)?;
    if !budget.claim(E32_PREFIX_SIZE) {
        return Err(error(format!(
            "Invalid TOC entry {index} ({name}): its e32_rom exceeds the image"
        )));
    }
    let e32_bytes = translation
        .storage(e32_pointer)
        .and_then(|address| memory.read(address, E32_PREFIX_SIZE))
        .ok_or_else(|| {
            error(format!(
                "Truncated e32_rom of {name} at 0x{e32_pointer:08X}"
            ))
        })?;
    let e32 = E32::parse(&e32_bytes)?;
    let o32_pointer = le_u32(entry, 24)?;
    let table_size = usize::from(e32.object_count) * O32_SIZE;
    if !budget.claim(table_size) {
        return Err(error(format!(
            "Invalid e32_rom of {name}: {} o32_rom entries exceed the image",
            e32.object_count
        )));
    }
    let table = translation
        .storage(o32_pointer)
        .and_then(|address| memory.read(address, table_size))
        .ok_or_else(|| {
            error(format!(
                "Truncated o32_rom table of {name} at 0x{o32_pointer:08X}: {} entries",
                e32.object_count
            ))
        })?;
    let sections = table
        .chunks_exact(O32_SIZE)
        .map(O32::parse)
        .collect::<Result<Vec<_>>>()?;
    for (i, section) in sections.iter().enumerate() {
        let size = u64::from(section.data_size());
        if !is_stored(memory, translation, section.data_pointer, size) {
            return Err(error(format!(
                "Invalid o32_rom {i} of {name}: data at 0x{:08X} + {size} B is not stored in the image",
                section.data_pointer
            )));
        }
    }
    Ok(Module {
        name,
        file_size: le_u32(entry, 12)?,
        e32,
        sections,
    })
}

/// FILES entry: `dwFileAttributes`, `ftTime` (4, 8 B), `nRealFileSize`
/// (12), `nCompFileSize` (16), `lpszFileName` (20), `ulLoadOffset` (24),
/// the runtime address of the stored data.
fn read_file(
    memory: &Memory<'_>,
    translation: Translation,
    index: u32,
    entry: &[u8],
    budget: &mut Budget,
) -> Result<RomFile> {
    let name_pointer = le_u32(entry, 20)?;
    let name = read_name(memory, translation, name_pointer, budget).ok_or_else(|| {
        error(format!(
            "Invalid FILES entry {index}: the file name at 0x{name_pointer:08X} is not a stored, NUL-terminated ASCII name"
        ))
    })?;
    let file = RomFile {
        name,
        real_size: le_u32(entry, 12)?,
        stored_size: le_u32(entry, 16)?,
        load_pointer: le_u32(entry, 24)?,
    };
    if !is_stored(
        memory,
        translation,
        file.load_pointer,
        u64::from(file.stored_size),
    ) {
        return Err(error(format!(
            "Invalid FILES entry {index} ({}): data at 0x{:08X} + {} B is not stored in the image",
            file.name, file.load_pointer, file.stored_size
        )));
    }
    Ok(file)
}

/// Whether the `size` bytes at the runtime address `pointer` are stored
/// without a gap. Empty data (an uninitialized section, an empty file)
/// stores nothing, whatever its pointer.
fn is_stored(memory: &Memory<'_>, translation: Translation, pointer: u32, size: u64) -> bool {
    size == 0
        || translation
            .storage(pointer)
            .is_some_and(|address| memory.covers(address, size))
}

/// The non-empty, printable ASCII name at `pointer`, terminated by NUL
/// within [`MAX_NAME_LEN`] bytes. Charges the name to `budget`.
fn read_name(
    memory: &Memory<'_>,
    translation: Translation,
    pointer: u32,
    budget: &mut Budget,
) -> Option<String> {
    let bytes = memory.prefix(translation.storage(pointer)?, MAX_NAME_LEN + 1)?;
    let len = bytes.iter().position(|&b| b == 0)?;
    let name = &bytes[..len];
    if name.is_empty() || !name.iter().all(|b| (0x20..0x7f).contains(b)) || !budget.claim(len + 1) {
        return None;
    }
    String::from_utf8(name.to_vec()).ok()
}

/// The architecture `usCPUType` names, when the PE/COFF machine table
/// knows it.
pub(super) fn target(cpu_type: u16) -> Option<Target> {
    let (isa, bits, endianness, _) = coff::machine_to_isa(cpu_type);
    (!matches!(isa, Isa::Unknown(_))).then(|| Target::new(isa, bits, endianness))
}

/// A signed ROM offset as `0x..` or `-0x..`.
fn signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:X}", value.unsigned_abs())
    } else {
        format!("0x{value:X}")
    }
}

/// Report the ROMHDR: the container target, a note and metadata.
pub(super) fn report_header(c: &mut Container<'_>, header: &RomHeader, translation: Translation) {
    let cpu = header.cpu_type;
    c.target = target(cpu);
    c.notes.push(format!(
        "ROMHDR at 0x{:X}: usCPUType 0x{cpu:04X} ({}); image 0x{:08X} to 0x{:08X}; {}, {}",
        header.address,
        coff::machine_description(cpu),
        header.phys_first,
        header.phys_last,
        count(to_usize(header.module_count), "module", "modules"),
        count(to_usize(header.file_count), "file", "files")
    ));
    if c.target.is_none() {
        c.notes.push(format!(
            "usCPUType 0x{cpu:04X} names no architecture in the PE machine table; the ISA comes from the code"
        ));
    }
    if translation.rom_offset != 0 {
        c.notes.push(format!(
            "Records are stored at the ROM's runtime addresses plus a ROM offset of {} (BLCOMMON g_dwROMOffset)",
            signed_hex(translation.rom_offset)
        ));
        c.push_metadata(
            format!("{KEY_PREFIX}_rom_offset"),
            "ROM offset (record minus runtime address)",
            signed_hex(translation.rom_offset),
        );
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_romhdr"),
        "ROMHDR address",
        MetadataValue::Address(header.address),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_cpu_type"),
        "ROMHDR usCPUType",
        MetadataValue::Hex(u32::from(cpu)),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_physfirst"),
        "ROMHDR physfirst",
        MetadataValue::Address(u64::from(header.phys_first)),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_physlast"),
        "ROMHDR physlast",
        MetadataValue::Address(u64::from(header.phys_last)),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_ram"),
        "ROMHDR RAM (ulRAMStart, ulRAMFree, ulRAMEnd)",
        format!(
            "0x{:08X} to 0x{:08X}; free from 0x{:08X}",
            header.ram_start, header.ram_end, header.ram_free
        ),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_kernel_flags"),
        "ROMHDR ulKernelFlags",
        MetadataValue::Hex(header.kernel_flags),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_misc_flags"),
        "ROMHDR usMiscFlags",
        MetadataValue::Hex(u32::from(header.misc_flags)),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_copy_entries"),
        "ROMHDR ulCopyEntries",
        u64::from(header.copy_entries),
    );
}

/// Report a validated ROM: the header, the modules and files in notes and
/// metadata, and their components.
pub(super) fn report<'a>(c: &mut Container<'a>, rom: &Rom, memory: &Memory<'a>) {
    report_header(c, &rom.header, rom.translation);
    if !rom.modules.is_empty() {
        c.notes.push(module_names(&rom.modules));
    }
    for (i, module) in rom.modules.iter().take(MAX_COMPONENTS).enumerate() {
        c.push_metadata(
            format!("{KEY_PREFIX}_module_{i}"),
            module.name.clone(),
            module_summary(module),
        );
    }
    for (i, file) in rom.files.iter().take(MAX_COMPONENTS).enumerate() {
        c.push_metadata(
            format!("{KEY_PREFIX}_file_{i}"),
            file.name.clone(),
            file_summary(file),
        );
    }
    let unlisted = rom.modules.len().saturating_sub(MAX_COMPONENTS)
        + rom.files.len().saturating_sub(MAX_COMPONENTS);
    if unlisted > 0 {
        c.notes.push(format!(
            "Metadata lists the first {MAX_COMPONENTS} modules and files of each table; {} not listed",
            count(unlisted, "further entry is", "further entries are")
        ));
    }
    let mut components = Components::default();
    for module in &rom.modules {
        components.module(c, module, rom.translation, memory);
    }
    for file in &rom.files {
        components.file(c, file, rom.translation, memory);
    }
    components.finish(c);
}

/// `"Modules: nk.exe, coredll.dll and 3 more"`.
fn module_names(modules: &[Module]) -> String {
    let names: Vec<&str> = modules
        .iter()
        .take(NOTE_NAMES)
        .map(|m| m.name.as_str())
        .collect();
    let rest = modules.len().saturating_sub(NOTE_NAMES);
    if rest > 0 {
        format!("Modules: {} and {rest} more", names.join(", "))
    } else {
        format!("Modules: {}", names.join(", "))
    }
}

/// A module's `e32_rom` and section summary for its metadata entry.
fn module_summary(module: &Module) -> String {
    let e32 = &module.e32;
    let code = module.sections.iter().filter(|s| s.is_code()).count();
    let compressed = module.sections.iter().filter(|s| s.is_compressed()).count();
    format!(
        "{}; entry RVA 0x{:X}; base 0x{:08X}; virtual size {} B; {} ({code} code, {compressed} compressed); image flags 0x{:04X}; file size {} B",
        module.kind(),
        e32.entry_rva,
        e32.base,
        e32.virtual_size,
        count(module.sections.len(), "section", "sections"),
        e32.image_flags,
        module.file_size
    )
}

/// A file's sizes for its metadata entry.
fn file_summary(file: &RomFile) -> String {
    if file.is_compressed() {
        format!(
            "{} B; stored compressed in {} B at 0x{:08X}",
            file.real_size, file.stored_size, file.load_pointer
        )
    } else {
        format!("{} B stored at 0x{:08X}", file.real_size, file.load_pointer)
    }
}

/// Builds a ROM's components and counts what it leaves out.
#[derive(Debug, Default)]
struct Components {
    /// Code sections listed as opaque because they are compressed.
    compressed_code: usize,
    /// Code sections whose data spans more than one record.
    split_code: usize,
    /// FILES entries examined, listed, compressed and split.
    files: usize,
    listed_files: usize,
    compressed_files: usize,
    split_files: usize,
    /// Components not listed because of [`MAX_COMPONENTS`].
    left_out: usize,
}

impl Components {
    /// Whether the component list is full; counts the component if so.
    fn is_full(&mut self, c: &Container<'_>) -> bool {
        let full = c.children.len() >= MAX_COMPONENTS;
        if full {
            self.left_out += 1;
        }
        full
    }

    /// One component per code section of `module`: raw code with the ROM's
    /// target, or opaque when the section is compressed.
    fn module<'a>(
        &mut self,
        c: &mut Container<'a>,
        module: &Module,
        translation: Translation,
        memory: &Memory<'a>,
    ) {
        for (i, section) in module.sections.iter().enumerate() {
            let size = to_usize(section.data_size());
            if !section.is_code() || size == 0 {
                continue;
            }
            let located = translation
                .storage(section.data_pointer)
                .and_then(|address| memory.stored(address, size));
            let Some(Region { offset, bytes, .. }) = located else {
                self.split_code += 1;
                continue;
            };
            if self.is_full(c) {
                continue;
            }
            let label = format!("{} o32 {i} (RVA 0x{:X})", module.name, section.rva);
            let child = if section.is_compressed() {
                self.compressed_code += 1;
                Child::opaque(label, offset, bytes)
            } else {
                let code = Child::stored(label, offset, bytes).as_code();
                match c.target {
                    Some(target) => code.with_target(target),
                    None => code,
                }
            };
            c.children.push(child);
        }
    }

    /// A component for `file` when it is stored uncompressed in one record
    /// and its bytes are a recognized format.
    fn file<'a>(
        &mut self,
        c: &mut Container<'a>,
        file: &RomFile,
        translation: Translation,
        memory: &Memory<'a>,
    ) {
        self.files += 1;
        if file.is_compressed() {
            self.compressed_files += 1;
            return;
        }
        if file.stored_size == 0 {
            return;
        }
        let located = translation
            .storage(file.load_pointer)
            .and_then(|address| memory.stored(address, to_usize(file.stored_size)));
        let Some(Region { offset, bytes, .. }) = located else {
            self.split_files += 1;
            return;
        };
        let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
        if !container::is_recognized(prefix) || !container::is_recognized(bytes) {
            return;
        }
        if self.is_full(c) {
            return;
        }
        c.children
            .push(Child::stored(file.name.clone(), offset, bytes).if_recognized());
        self.listed_files += 1;
    }

    /// Notes for what was left out.
    fn finish(self, c: &mut Container<'_>) {
        if self.compressed_code > 0 {
            c.notes.push(format!(
                "{} stored compressed (IMAGE_SCN_COMPRESSED) and listed as opaque; Windows CE ROM compression is not decoded",
                count(self.compressed_code, "code section is", "code sections are")
            ));
        }
        if self.split_code > 0 {
            c.notes.push(format!(
                "{} not stored in one record and not listed",
                count(self.split_code, "code section is", "code sections are")
            ));
        }
        if self.files > 0 {
            c.notes.push(format!(
                "{} of {} in a recognized format and listed",
                self.listed_files,
                count(self.files, "file is", "files are")
            ));
        }
        if self.compressed_files > 0 {
            c.notes.push(format!(
                "{} stored compressed (nCompFileSize differs from nRealFileSize) and not analyzed",
                count(self.compressed_files, "file is", "files are")
            ));
        }
        if self.split_files > 0 {
            c.notes.push(format!(
                "{} not stored in one record and not examined",
                count(self.split_files, "file is", "files are")
            ));
        }
        if self.left_out > 0 {
            c.notes.push(format!(
                "Component listing stopped at {MAX_COMPONENTS}; {} not listed",
                count(
                    self.left_out,
                    "further component was",
                    "further components were"
                )
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_applies_the_rom_offset_without_wrapping() {
        assert_eq!(
            Translation::IDENTITY.storage(0x8000_0000),
            Some(0x8000_0000)
        );
        let down = Translation::new(-0x8000_0000);
        assert_eq!(down.storage(0x8000_1000), Some(0x1000));
        assert_eq!(down.storage(0x1000), None);
        let up = Translation::new(0x1000);
        assert_eq!(up.storage(u32::MAX), Some(0x1_0000_0FFF));
        assert_eq!(signed_hex(-0x10), "-0x10");
        assert_eq!(signed_hex(0x10), "0x10");
    }

    #[test]
    fn cpu_types_map_through_the_pe_machine_table() {
        let arm = target(0x01C0).expect("ARM");
        assert_eq!(arm.isa, Isa::Arm);
        assert_eq!(target(0x014C).map(|t| t.isa), Some(Isa::X86));
        assert_eq!(target(0x0166).map(|t| t.isa), Some(Isa::Mips));
        assert_eq!(target(0x01A6).map(|t| t.isa), Some(Isa::Sh4));
        assert_eq!(target(0), None);
        assert_eq!(target(0x1234), None);
    }

    #[test]
    fn section_flags_and_sizes_follow_pehdr_and_dumprom() {
        let section = O32 {
            virtual_size: 0x100,
            rva: 0x1000,
            stored_size: 0x200,
            data_pointer: 0,
            flags: IMAGE_SCN_CNT_CODE | IMAGE_SCN_COMPRESSED,
        };
        assert_eq!(section.data_size(), 0x100);
        assert!(section.is_code());
        assert!(section.is_compressed());
        let data = O32 {
            flags: 0x4000_0040,
            ..section
        };
        assert!(!data.is_code());
        assert!(!data.is_compressed());
    }

    #[test]
    fn module_names_are_capped_in_the_note() {
        let module = |i: usize| Module {
            name: format!("m{i}.dll"),
            file_size: 0,
            e32: E32 {
                object_count: 0,
                image_flags: IMAGE_FILE_DLL,
                entry_rva: 0,
                base: 0,
                virtual_size: 0,
            },
            sections: Vec::new(),
        };
        let modules: Vec<Module> = (0..NOTE_NAMES + 2).map(module).collect();
        let note = module_names(&modules);
        assert!(note.starts_with("Modules: m0.dll, m1.dll"), "{note}");
        assert!(note.ends_with("and 2 more"), "{note}");
        assert_eq!(modules[0].kind(), "DLL");
    }
}
