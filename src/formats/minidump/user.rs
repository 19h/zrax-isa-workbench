//! User-mode minidumps: the `MINIDUMP_HEADER`, the stream directory, and
//! the container built from the system information, thread, module,
//! exception and memory streams.
//!
//! Header (32 B): `Signature` (0), `Version` (4; low word
//! `MINIDUMP_VERSION`, high word implementation-specific),
//! `NumberOfStreams` (8), `StreamDirectoryRva` (0xC), `CheckSum` (0x10),
//! `TimeDateStamp` (0x14), `Flags` (0x18, u64 `MINIDUMP_TYPE`). Directory
//! entries (12 B): `StreamType`, `DataSize`, `Rva`.

use super::image::{executable_sections, Section};
use super::regions::Regions;
use super::streams::{
    Exception, MemoryRange, Module, Stream, SystemInfo, Thread, EXCEPTION_STREAM,
    MEMORY64_LIST_STREAM, MEMORY_LIST_STREAM, MODULE_LIST_STREAM, SYSTEM_INFO_STREAM,
    THREAD_LIST_STREAM,
};
use super::*;
use crate::formats::container::{Child, MAX_COMPONENTS};
use crate::types::MetadataValue;

const HEADER_SIZE: usize = 32;
const DIRECTORY_ENTRY_SIZE: usize = 12;

/// `UnusedStream`: a directory entry without content.
const UNUSED_STREAM: u32 = 0;

/// Stream types that may appear once. Breakpad `minidump.cc` rejects a
/// second stream of these types; a parser that picked one would report
/// only part of the dump.
const SINGLE_STREAMS: [u32; 6] = [
    THREAD_LIST_STREAM,
    MODULE_LIST_STREAM,
    MEMORY_LIST_STREAM,
    EXCEPTION_STREAM,
    SYSTEM_INFO_STREAM,
    MEMORY64_LIST_STREAM,
];

/// `MINIDUMP_STREAM_TYPE` names (`minidumpapiset.h`), for the stream list.
const STREAM_NAMES: &[(u32, &str)] = &[
    (THREAD_LIST_STREAM, "thread list"),
    (MODULE_LIST_STREAM, "module list"),
    (MEMORY_LIST_STREAM, "memory list"),
    (EXCEPTION_STREAM, "exception"),
    (SYSTEM_INFO_STREAM, "system info"),
    (8, "thread ex list"),
    (MEMORY64_LIST_STREAM, "memory64 list"),
    (10, "ANSI comment"),
    (11, "Unicode comment"),
    (12, "handle data"),
    (13, "function table"),
    (14, "unloaded module list"),
    (15, "misc info"),
    (16, "memory info list"),
    (17, "thread info list"),
    (18, "handle operation list"),
    (19, "token"),
    (20, "JavaScript data"),
    (21, "system memory info"),
    (22, "process VM counters"),
    (23, "IPT trace"),
    (24, "thread names"),
];

/// Most stream types named in the stream list metadata entry.
const STREAM_LIST_LIMIT: usize = 32;

/// The `MINIDUMP_HEADER` fields after the signature.
#[derive(Debug)]
struct Header {
    version: u32,
    stream_count: u32,
    directory_rva: u32,
    checksum: u32,
    timestamp: u32,
    flags: u64,
}

/// Everything the streams say, decoded before the container is built.
struct Streams {
    directory: Vec<Stream>,
    system: Option<SystemInfo>,
    threads: Option<Vec<Thread>>,
    modules: Option<Vec<Module>>,
    exception: Option<Exception>,
    memory: Vec<MemoryRange>,
}

/// Parse a user-mode minidump.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let reader = Reader {
        data,
        big_endian: layout == Layout::MinidumpBigEndian,
    };
    let header = header(reader)?;
    let streams = decode_streams(reader, &header)?;
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    report_header(&mut c, layout, &header, &streams.directory);
    report_system(&mut c, streams.system.as_ref());
    let modules = streams.modules.as_deref().unwrap_or_default();
    let threads = streams.threads.as_deref().unwrap_or_default();
    let map = AddressMap::new(reader, modules, threads, &streams.memory);
    if let Some(threads) = &streams.threads {
        report_threads(&mut c, threads);
    }
    if let Some(exception) = &streams.exception {
        report_exception(&mut c, exception, &map);
    }
    report_modules(&mut c, streams.modules.as_deref());
    push_memory(&mut c, reader, &streams.memory, &map)?;
    Ok(c)
}

/// Read and check the header: signature, version word and size.
fn header(reader: Reader<'_>) -> Result<Header> {
    reader.bytes(0, HEADER_SIZE, "header")?;
    let signature = reader.field::<4>(0)?;
    let expected = if reader.big_endian {
        MINIDUMP_MAGIC_SWAPPED
    } else {
        MINIDUMP_MAGIC
    };
    if &signature != expected {
        return Err(error("Invalid minidump signature"));
    }
    let version = reader.u32(4)?;
    let version_word = version & 0xffff;
    if version_word != u32::from(MINIDUMP_VERSION) {
        return Err(error(format!(
            "Unsupported minidump version 0x{version_word:04X}"
        )));
    }
    Ok(Header {
        version,
        stream_count: reader.u32(8)?,
        directory_rva: reader.u32(0xc)?,
        checksum: reader.u32(0x10)?,
        timestamp: reader.u32(0x14)?,
        flags: reader.u64(0x18)?,
    })
}

/// Read the directory, then the streams the classifier reports, in a fixed
/// order: system info, threads, modules, exception, memory, 64-bit memory.
fn decode_streams(reader: Reader<'_>, header: &Header) -> Result<Streams> {
    let directory = directory(reader, header)?;
    let find = |stream_type: u32| directory.iter().find(|s| s.kind == stream_type);
    let system = find(SYSTEM_INFO_STREAM)
        .map(|s| streams::system_info(reader, s))
        .transpose()?;
    let threads = find(THREAD_LIST_STREAM)
        .map(|s| streams::thread_list(reader, s))
        .transpose()?;
    let modules = find(MODULE_LIST_STREAM)
        .map(|s| streams::module_list(reader, s))
        .transpose()?;
    let exception = find(EXCEPTION_STREAM)
        .map(|s| streams::exception(reader, s))
        .transpose()?;
    let mut memory = Vec::new();
    if let Some(stream) = find(MEMORY_LIST_STREAM) {
        memory = streams::memory_list(reader, stream)?;
    }
    if let Some(stream) = find(MEMORY64_LIST_STREAM) {
        memory.extend(streams::memory64_list(reader, stream)?);
    }
    Ok(Streams {
        directory,
        system,
        threads,
        modules,
        exception,
        memory,
    })
}

/// The stream directory. Every entry's location must lie inside the file,
/// and the streams the classifier reads may appear only once.
fn directory(reader: Reader<'_>, header: &Header) -> Result<Vec<Stream>> {
    let count = to_usize(header.stream_count);
    let offset = to_usize(header.directory_rva);
    let size = count
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .ok_or_else(|| error(format!("Invalid stream directory size for {count} streams")))?;
    reader.bytes(offset, size, "stream directory")?;
    let mut directory: Vec<Stream> = Vec::with_capacity(count);
    for index in 0..count {
        let at = offset + index * DIRECTORY_ENTRY_SIZE;
        let stream_type = reader.u32(at)?;
        let size = to_usize(reader.u32(at + 4)?);
        let rva = to_usize(reader.u32(at + 8)?);
        if reader.bytes(rva, size, "stream").is_err() {
            return Err(error(format!(
                "Truncated stream {index} (type 0x{stream_type:X}) at 0x{rva:X} + {size} B"
            )));
        }
        if SINGLE_STREAMS.contains(&stream_type) {
            if let Some(first) = directory.iter().find(|s| s.kind == stream_type) {
                return Err(error(format!(
                    "Duplicate {} stream (directory entries {} and {index})",
                    stream_name(stream_type).unwrap_or("known"),
                    first.index
                )));
            }
        }
        directory.push(Stream {
            index,
            kind: stream_type,
            offset: rva,
            size,
        });
    }
    Ok(directory)
}

fn stream_name(stream_type: u32) -> Option<&'static str> {
    STREAM_NAMES
        .iter()
        .find(|(id, _)| *id == stream_type)
        .map(|(_, name)| *name)
}

/// The streams in directory order, unused entries counted at the end:
/// `"thread list, module list, 0x47670001, 2 unused"`.
fn stream_list(directory: &[Stream]) -> String {
    let used: Vec<&Stream> = directory
        .iter()
        .filter(|s| s.kind != UNUSED_STREAM)
        .collect();
    let mut parts: Vec<String> = used
        .iter()
        .take(STREAM_LIST_LIMIT)
        .map(|s| match stream_name(s.kind) {
            Some(name) => name.to_string(),
            None => format!("0x{:X}", s.kind),
        })
        .collect();
    if used.len() > STREAM_LIST_LIMIT {
        parts.push(format!("{} more", used.len() - STREAM_LIST_LIMIT));
    }
    let unused = directory.len() - used.len();
    if unused > 0 {
        parts.push(format!("{unused} unused"));
    }
    parts.join(", ")
}

/// Notes and metadata from the header and directory.
fn report_header(c: &mut Container<'_>, layout: Layout, header: &Header, directory: &[Stream]) {
    if layout == Layout::MinidumpBigEndian {
        c.notes
            .push("Fields are big-endian: the signature is stored byte-swapped".into());
    }
    if header.checksum != 0 {
        c.notes.push(format!(
            "Header checksum 0x{:08X} not verified",
            header.checksum
        ));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_version_high"),
        "Implementation-specific version word",
        MetadataValue::Hex(header.version >> 16),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_flags"),
        "MINIDUMP_TYPE flags",
        format!("0x{:X}", header.flags),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_timestamp"),
        "Time stamp (time_t)",
        u64::from(header.timestamp),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_checksum"),
        "Header checksum (not verified)",
        MetadataValue::Hex(header.checksum),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_streams"),
        "Streams",
        stream_list(directory),
    );
}

/// The target, a note and metadata from the system information stream.
fn report_system(c: &mut Container<'_>, system: Option<&SystemInfo>) {
    let Some(info) = system else {
        c.notes.push(
            "No system information stream: the processor architecture is not recorded; the ISA comes from module memory"
                .into(),
        );
        return;
    };
    let id = info.architecture;
    let architecture = architecture_by_id(id);
    let name = architecture.map_or("not a known value", |a| a.name);
    c.target = architecture.and_then(|a| a.target);
    c.notes.push(format!(
        "Processor architecture {id} ({name}); OS version {}.{}.{} (platform ID {}); {}",
        info.major_version,
        info.minor_version,
        info.build_number,
        info.platform_id,
        count(usize::from(info.processors), "processor", "processors")
    ));
    if c.target.is_none() {
        c.notes.push(format!(
            "Processor architecture {id} names no CPU ISA; the ISA comes from module memory"
        ));
    }
    let entries: [(&str, &str, MetadataValue); 7] = [
        (
            "processor_architecture",
            "Processor architecture",
            MetadataValue::Integer(u64::from(id)),
        ),
        (
            "processor_level",
            "Processor level",
            MetadataValue::Integer(u64::from(info.level)),
        ),
        (
            "processor_revision",
            "Processor revision",
            MetadataValue::Hex(u32::from(info.revision)),
        ),
        (
            "processors",
            "Processors",
            MetadataValue::Integer(u64::from(info.processors)),
        ),
        (
            "os_version",
            "OS version",
            MetadataValue::String(format!(
                "{}.{}.{}",
                info.major_version, info.minor_version, info.build_number
            )),
        ),
        (
            "platform_id",
            "Platform ID",
            MetadataValue::Integer(u64::from(info.platform_id)),
        ),
        (
            "product_type",
            "Product type",
            MetadataValue::Integer(u64::from(info.product_type)),
        ),
    ];
    for (key, label, value) in entries {
        c.push_metadata(format!("{KEY_PREFIX}_{key}"), label, value);
    }
    if let Some(csd) = info.csd_version.as_deref().filter(|s| !s.is_empty()) {
        c.push_metadata(
            format!("{KEY_PREFIX}_csd_version"),
            "Service pack (CSD version)",
            csd,
        );
    }
}

/// Modules and thread stacks, for naming dumped memory.
struct AddressMap<'m> {
    modules: &'m [Module],
    module_images: Regions,
    /// Per module, the executable sections its dumped PE headers list, or
    /// `None` when the headers are not in the dump (or not a PE header).
    module_code: Vec<Option<Vec<Section>>>,
    threads: &'m [Thread],
    stacks: Regions,
}

impl<'m> AddressMap<'m> {
    fn new(
        reader: Reader<'_>,
        modules: &'m [Module],
        threads: &'m [Thread],
        memory: &[MemoryRange],
    ) -> Self {
        let module_images = Regions::new(modules.iter().map(|m| (m.base, m.end())));
        let stacks = Regions::new(threads.iter().map(|t| {
            let end = t.stack_address.saturating_add(u64::from(t.stack_size));
            (t.stack_address, end)
        }));
        Self {
            modules,
            module_images,
            module_code: module_code(reader, modules, memory),
            threads,
            stacks,
        }
    }

    /// Whether `range`, inside the image of module `index`, may hold code:
    /// it overlaps an executable section, or the module's section table is
    /// not known.
    fn may_hold_code(&self, index: usize, range: &MemoryRange) -> bool {
        match self.module_code.get(index) {
            Some(Some(sections)) => sections
                .iter()
                .any(|s| s.overlaps(range.address, range.end())),
            _ => true,
        }
    }

    /// The list index of the module whose image contains `[start, end)`.
    fn module_index(&self, start: u64, end: u64) -> Option<usize> {
        self.module_images.containing(start, end)
    }

    /// The thread whose stack contains `[start, end)`.
    fn stack_owner(&self, start: u64, end: u64) -> Option<&'m Thread> {
        let threads = self.threads;
        self.stacks
            .containing(start, end)
            .map(|index| &threads[index])
    }
}

/// The executable sections of the first [`MAX_COMPONENTS`] modules, read
/// from the PE headers in the memory range that holds each module's base
/// address. The cap bounds the section lists a dump of many modules that
/// share one header can make. A range whose bytes are not in the file is
/// skipped here; `push_memory` reports it in list order.
fn module_code(
    reader: Reader<'_>,
    modules: &[Module],
    memory: &[MemoryRange],
) -> Vec<Option<Vec<Section>>> {
    let ranges = Regions::new(memory.iter().map(|r| (r.address, r.end())));
    modules
        .iter()
        .take(MAX_COMPONENTS)
        .map(|module| dumped_sections(reader, &ranges, memory, module))
        .collect()
}

/// The executable sections of `module`, from the PE headers at its base
/// address in the dumped memory, if the dump holds them.
fn dumped_sections(
    reader: Reader<'_>,
    ranges: &Regions,
    memory: &[MemoryRange],
    module: &Module,
) -> Option<Vec<Section>> {
    let index = ranges.containing(module.base, module.base.checked_add(1)?)?;
    let range = &memory[index];
    let bytes = reader
        .bytes(range.offset, range.size, "memory range")
        .ok()?;
    let skip = usize::try_from(module.base - range.address).ok()?;
    executable_sections(bytes.get(skip..)?, module.base)
}

/// The thread count note and metadata.
fn report_threads(c: &mut Container<'_>, threads: &[Thread]) {
    c.notes.push(count(threads.len(), "thread", "threads"));
    c.push_metadata(
        format!("{KEY_PREFIX}_thread_count"),
        "Threads",
        to_u64(threads.len()),
    );
}

/// A module's display name: its file name, or its list position.
fn module_label(module: &Module, index: usize) -> String {
    module
        .file_name()
        .map_or_else(|| format!("module {index}"), str::to_string)
}

/// The note and metadata for the exception stream.
fn report_exception(c: &mut Container<'_>, exception: &Exception, map: &AddressMap<'_>) {
    let address = exception.address;
    let inside = map
        .module_index(address, address.saturating_add(1))
        .and_then(|index| map.modules[index].file_name())
        .map(|name| format!(" (inside {name})"))
        .unwrap_or_default();
    c.notes.push(format!(
        "Exception 0x{:08X} at 0x{address:X}{inside} in thread 0x{:X}",
        exception.code, exception.thread_id
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_exception_code"),
        "Exception code",
        MetadataValue::Hex(exception.code),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_exception_flags"),
        "Exception flags",
        MetadataValue::Hex(exception.flags),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_exception_address"),
        "Exception address",
        MetadataValue::Address(address),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_exception_thread"),
        "Exception thread ID",
        u64::from(exception.thread_id),
    );
}

/// The module count note and one metadata entry per module (name, base,
/// size, file version), up to [`MAX_COMPONENTS`].
fn report_modules(c: &mut Container<'_>, modules: Option<&[Module]>) {
    let Some(modules) = modules else {
        c.notes
            .push("No module list: no dumped memory is attributed to module code".into());
        return;
    };
    c.notes.push(count(modules.len(), "module", "modules"));
    c.push_metadata(
        format!("{KEY_PREFIX}_module_count"),
        "Modules",
        to_u64(modules.len()),
    );
    for (i, module) in modules.iter().enumerate().take(MAX_COMPONENTS) {
        let mut value = format!(
            "{}; base 0x{:X}; {} B",
            module.name.as_deref().unwrap_or("(no name)"),
            module.base,
            module.size
        );
        if let Some(version) = &module.file_version {
            value.push_str("; version ");
            value.push_str(version);
        }
        c.push_metadata(
            format!("{KEY_PREFIX}_module_{i}"),
            module_label(module, i),
            value,
        );
    }
    if modules.len() > MAX_COMPONENTS {
        c.notes.push(format!(
            "{} further modules are not listed in the metadata (limit {MAX_COMPONENTS})",
            modules.len() - MAX_COMPONENTS
        ));
    }
}

/// How the dumped memory ranges were listed.
#[derive(Debug, Default)]
struct MemoryTally {
    code: usize,
    /// Ranges inside a module image but outside its executable sections.
    module_data: usize,
    opaque: usize,
    empty: usize,
    unlisted: usize,
    unlisted_size: u64,
    total_size: u64,
}

/// One child per non-empty memory range, at its stored offset. Ranges
/// inside a module image are code for the dump's target, unless the
/// module's PE headers place them outside every executable section; those
/// and the rest (stacks, heaps, mapped data) are opaque.
fn push_memory<'a>(
    c: &mut Container<'a>,
    reader: Reader<'a>,
    ranges: &[MemoryRange],
    map: &AddressMap<'_>,
) -> Result<()> {
    let mut tally = MemoryTally::default();
    for range in ranges {
        let size = to_u64(range.size);
        tally.total_size = tally.total_size.saturating_add(size);
        if range.size == 0 {
            tally.empty += 1;
            continue;
        }
        if c.children.len() >= MAX_COMPONENTS {
            tally.unlisted += 1;
            tally.unlisted_size = tally.unlisted_size.saturating_add(size);
            continue;
        }
        let bytes = reader.bytes(range.offset, range.size, "memory range")?;
        let place = format!("Memory at 0x{:X}", range.address);
        let child = if let Some(index) = map.module_index(range.address, range.end()) {
            let label = format!("{place} ({})", module_label(&map.modules[index], index));
            if map.may_hold_code(index, range) {
                tally.code += 1;
                let code = Child::stored(label, range.offset, bytes).as_code();
                match c.target {
                    Some(target) => code.with_target(target),
                    None => code,
                }
            } else {
                tally.module_data += 1;
                Child::opaque(label, range.offset, bytes)
            }
        } else {
            let label = match map.stack_owner(range.address, range.end()) {
                Some(thread) => format!("{place} (thread 0x{:X} stack)", thread.id),
                None => place,
            };
            tally.opaque += 1;
            Child::opaque(label, range.offset, bytes)
        };
        c.children.push(child);
    }
    report_memory(c, ranges.len(), &tally);
    Ok(())
}

fn report_memory(c: &mut Container<'_>, ranges: usize, tally: &MemoryTally) {
    c.notes.push(format!(
        "{} ({} B): {} inside module images classified as code, {} other ranges (stacks, heaps, data) opaque",
        count(ranges, "memory range", "memory ranges"),
        tally.total_size,
        tally.code,
        tally.opaque
    ));
    if tally.module_data > 0 {
        c.notes.push(format!(
            "{} inside module images but outside the executable sections their PE headers list opaque",
            count(tally.module_data, "range", "ranges")
        ));
    }
    if tally.empty > 0 {
        c.notes
            .push(format!("{} empty memory ranges skipped", tally.empty));
    }
    if tally.unlisted > 0 {
        c.notes.push(format!(
            "{} further memory ranges ({} B) were not listed (limit {MAX_COMPONENTS})",
            tally.unlisted, tally.unlisted_size
        ));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_memory_ranges"),
        "Memory ranges",
        to_u64(ranges),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_memory_size"),
        "Dumped memory (B)",
        tally.total_size,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(stream_type: u32) -> Stream {
        Stream {
            index: 0,
            kind: stream_type,
            offset: 0,
            size: 0,
        }
    }

    #[test]
    fn stream_list_names_known_types_and_counts_unused() {
        let directory = [
            entry(THREAD_LIST_STREAM),
            entry(0x4767_0001),
            entry(UNUSED_STREAM),
            entry(15),
            entry(UNUSED_STREAM),
        ];
        assert_eq!(
            stream_list(&directory),
            "thread list, 0x47670001, misc info, 2 unused"
        );
        let many: Vec<Stream> = (0..40).map(|_| entry(15)).collect();
        assert!(stream_list(&many).ends_with(", 8 more"));
    }
}
