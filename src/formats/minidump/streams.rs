//! Minidump stream decoders: system information, the thread, module and
//! memory lists, the 64-bit memory list and the exception stream.
//!
//! Layouts (Microsoft `minidumpapiset.h`; sizes from the Win32 metadata's
//! 4-byte packed structures and Breakpad `minidump_format.h`):
//! - `MINIDUMP_SYSTEM_INFO`, 56 B: `ProcessorArchitecture` (0),
//!   `ProcessorLevel` (2), `ProcessorRevision` (4), `NumberOfProcessors`
//!   (6), `ProductType` (7), `MajorVersion` (8), `MinorVersion` (0xC),
//!   `BuildNumber` (0x10), `PlatformId` (0x14), `CSDVersionRva` (0x18).
//! - `MINIDUMP_THREAD`, 48 B: `ThreadId` (0), `Stack` memory descriptor
//!   (0x18: start address, then size and RVA).
//! - `MINIDUMP_MODULE`, 108 B: `BaseOfImage` (0), `SizeOfImage` (8),
//!   `ModuleNameRva` (0x14), `VersionInfo` (0x18: `dwSignature`, struct
//!   version, `dwFileVersionMS`, `dwFileVersionLS`, ...).
//! - `MINIDUMP_MEMORY_DESCRIPTOR`, 16 B: start address, `DataSize` (u32),
//!   `Rva` (u32). `MINIDUMP_MEMORY64_LIST`: range count (u64), `BaseRva`
//!   (u64), then 16-byte descriptors (start address, `DataSize` u64) whose
//!   data follows `BaseRva` in descriptor order.
//! - `MINIDUMP_EXCEPTION_STREAM`, 168 B: `ThreadId` (0), then
//!   `MINIDUMP_EXCEPTION` at 8: `ExceptionCode` (8), `ExceptionFlags`
//!   (0xC), `ExceptionAddress` (0x18).
//! - `MINIDUMP_STRING`: `Length` in bytes without the terminator (u32),
//!   then UTF-16 code units in the dump's byte order.

use super::*;

/// `MINIDUMP_STREAM_TYPE` values this parser reads.
pub(super) const THREAD_LIST_STREAM: u32 = 3;
pub(super) const MODULE_LIST_STREAM: u32 = 4;
pub(super) const MEMORY_LIST_STREAM: u32 = 5;
pub(super) const EXCEPTION_STREAM: u32 = 6;
pub(super) const SYSTEM_INFO_STREAM: u32 = 7;
pub(super) const MEMORY64_LIST_STREAM: u32 = 9;

/// Fixed record sizes.
const SYSTEM_INFO_SIZE: usize = 56;
const THREAD_SIZE: usize = 48;
const MODULE_SIZE: usize = 108;
const MEMORY_DESCRIPTOR_SIZE: usize = 16;
const MEMORY64_LIST_HEADER_SIZE: usize = 16;
const EXCEPTION_STREAM_SIZE: usize = 168;

/// The 32-bit count that starts the thread, module and memory lists, and
/// the padding Breakpad and rust-minidump accept after it ("may be padded
/// with 4 bytes on 64bit ABIs for alignment", Breakpad `minidump.cc`).
const LIST_COUNT_SIZE: usize = 4;
const LIST_PADDING: usize = 4;

/// `MINIDUMP_STRING.Length`, the field before the UTF-16 text.
const STRING_LENGTH_SIZE: usize = 4;

/// `VS_FIXEDFILEINFO.dwSignature` (`VS_FFI_SIGNATURE`).
const VS_FFI_SIGNATURE: u32 = 0xfeef_04bd;

/// Longest `MINIDUMP_STRING` accepted, in bytes: the longest Windows path,
/// 32,767 UTF-16 units. Our own bound; Breakpad stops at 1,024 units.
const MAX_STRING_SIZE: usize = 32_767 * 2;

/// Most UTF-16 units of a string that are decoded for display (Breakpad's
/// `max_string_length_`); longer strings are cut there and end with `…`.
/// With [`MAX_NAMED_MODULES`] this bounds the text a dump can make the
/// parser allocate, whatever its string RVAs share.
const MAX_DECODED_UNITS: usize = 1024;

/// Modules whose names are read; later modules are listed without a name.
const MAX_NAMED_MODULES: usize = crate::formats::container::MAX_COMPONENTS;

/// One stream directory entry whose location lies inside the file.
#[derive(Debug, Clone, Copy)]
pub(super) struct Stream {
    /// Position in the directory.
    pub(super) index: usize,
    /// `MINIDUMP_STREAM_TYPE` or an application-defined type.
    pub(super) kind: u32,
    /// File offset (RVA) of the stream.
    pub(super) offset: usize,
    /// Stream size in bytes.
    pub(super) size: usize,
}

/// `MINIDUMP_SYSTEM_INFO`.
#[derive(Debug)]
pub(super) struct SystemInfo {
    pub(super) architecture: u16,
    pub(super) level: u16,
    pub(super) revision: u16,
    pub(super) processors: u8,
    pub(super) product_type: u8,
    pub(super) major_version: u32,
    pub(super) minor_version: u32,
    pub(super) build_number: u32,
    pub(super) platform_id: u32,
    /// The service pack string, when `CSDVersionRva` is set.
    pub(super) csd_version: Option<String>,
}

/// One `MINIDUMP_THREAD`: its ID and the address range of its stack.
#[derive(Debug)]
pub(super) struct Thread {
    pub(super) id: u32,
    pub(super) stack_address: u64,
    /// Stack size in bytes.
    pub(super) stack_size: u32,
}

/// One `MINIDUMP_MODULE`.
#[derive(Debug)]
pub(super) struct Module {
    /// `BaseOfImage`: the image's address in the dumped process.
    pub(super) base: u64,
    /// `SizeOfImage` in bytes.
    pub(super) size: u32,
    /// The module path, when `ModuleNameRva` is set.
    pub(super) name: Option<String>,
    /// `a.b.c.d` from `VS_FIXEDFILEINFO`, when its signature is present.
    pub(super) file_version: Option<String>,
}

impl Module {
    /// The end of the image (exclusive). The list decoder rejects images
    /// whose end overflows.
    pub(super) fn end(&self) -> u64 {
        self.base.saturating_add(u64::from(self.size))
    }

    /// The last path component of the module name.
    pub(super) fn file_name(&self) -> Option<&str> {
        let name = self.name.as_deref()?;
        name.rsplit(['\\', '/']).next()
    }
}

/// One dumped memory range: its address in the process and where its
/// bytes are stored.
#[derive(Debug)]
pub(super) struct MemoryRange {
    pub(super) address: u64,
    /// File offset of the stored bytes.
    pub(super) offset: usize,
    /// Size in bytes.
    pub(super) size: usize,
}

impl MemoryRange {
    /// The end address (exclusive). The list decoders reject ranges whose
    /// end overflows.
    pub(super) fn end(&self) -> u64 {
        self.address.saturating_add(to_u64(self.size))
    }
}

/// The `MINIDUMP_EXCEPTION_STREAM` fields the classifier reports.
#[derive(Debug)]
pub(super) struct Exception {
    pub(super) thread_id: u32,
    pub(super) code: u32,
    pub(super) flags: u32,
    pub(super) address: u64,
}

/// The stream's offset after checking that it holds `needed` bytes.
fn fixed_record(stream: &Stream, needed: usize, what: &str) -> Result<usize> {
    if stream.size < needed {
        return Err(error(format!(
            "Truncated {what} stream at 0x{:X}: {} B, {needed} B needed",
            stream.offset, stream.size
        )));
    }
    Ok(stream.offset)
}

/// Where the entries of a list with a 32-bit count lie.
#[derive(Debug)]
struct ListEntries {
    count: usize,
    /// File offset of the first entry.
    first: usize,
}

/// The count of a thread, module or memory list and where its entries
/// start: the stream holds exactly the count and the entries, optionally
/// with 4 padding bytes after the count.
fn list_entries(
    reader: Reader<'_>,
    stream: &Stream,
    entry_size: usize,
    what: &str,
) -> Result<ListEntries> {
    let offset = fixed_record(stream, LIST_COUNT_SIZE, what)?;
    let count = to_usize(reader.u32(offset)?);
    let invalid_size = || {
        error(format!(
            "Invalid {what} stream size {} B for {count} entries of {entry_size} B",
            stream.size
        ))
    };
    let unpadded = count
        .checked_mul(entry_size)
        .and_then(|entries| entries.checked_add(LIST_COUNT_SIZE))
        .ok_or_else(invalid_size)?;
    let padding = match stream.size.checked_sub(unpadded) {
        Some(0) => 0,
        Some(LIST_PADDING) => LIST_PADDING,
        _ => return Err(invalid_size()),
    };
    Ok(ListEntries {
        count,
        first: offset + LIST_COUNT_SIZE + padding,
    })
}

/// Decode the system information stream.
pub(super) fn system_info(reader: Reader<'_>, stream: &Stream) -> Result<SystemInfo> {
    let at = fixed_record(stream, SYSTEM_INFO_SIZE, "system info")?;
    let csd_version_rva = reader.u32(at + 0x18)?;
    let csd_version = if csd_version_rva == 0 {
        None
    } else {
        Some(string(reader, csd_version_rva, "CSD version string")?)
    };
    Ok(SystemInfo {
        architecture: reader.u16(at)?,
        level: reader.u16(at + 2)?,
        revision: reader.u16(at + 4)?,
        processors: reader.field::<1>(at + 6)?[0],
        product_type: reader.field::<1>(at + 7)?[0],
        major_version: reader.u32(at + 8)?,
        minor_version: reader.u32(at + 0xc)?,
        build_number: reader.u32(at + 0x10)?,
        platform_id: reader.u32(at + 0x14)?,
        csd_version,
    })
}

/// Decode the thread list.
pub(super) fn thread_list(reader: Reader<'_>, stream: &Stream) -> Result<Vec<Thread>> {
    let list = list_entries(reader, stream, THREAD_SIZE, "thread list")?;
    let mut threads = Vec::with_capacity(list.count);
    for i in 0..list.count {
        let at = list.first + i * THREAD_SIZE;
        threads.push(Thread {
            id: reader.u32(at)?,
            stack_address: reader.u64(at + 0x18)?,
            stack_size: reader.u32(at + 0x20)?,
        });
    }
    Ok(threads)
}

/// Decode the module list, with each module's file version and, for the
/// first [`MAX_NAMED_MODULES`], its name.
pub(super) fn module_list(reader: Reader<'_>, stream: &Stream) -> Result<Vec<Module>> {
    let list = list_entries(reader, stream, MODULE_SIZE, "module list")?;
    let mut modules = Vec::with_capacity(list.count);
    for i in 0..list.count {
        let at = list.first + i * MODULE_SIZE;
        let base = reader.u64(at)?;
        let size = reader.u32(at + 8)?;
        if base.checked_add(u64::from(size)).is_none() {
            return Err(error(format!(
                "Invalid module {i} image range 0x{base:X} + {size} B"
            )));
        }
        let name_rva = reader.u32(at + 0x14)?;
        let name = if name_rva == 0 || i >= MAX_NAMED_MODULES {
            None
        } else {
            Some(string(reader, name_rva, &format!("module {i} name"))?)
        };
        modules.push(Module {
            base,
            size,
            name,
            file_version: file_version(reader, at + 0x18)?,
        });
    }
    Ok(modules)
}

/// `a.b.c.d` from a `VS_FIXEDFILEINFO` at `at`, when its signature is set.
fn file_version(reader: Reader<'_>, at: usize) -> Result<Option<String>> {
    if reader.u32(at)? != VS_FFI_SIGNATURE {
        return Ok(None);
    }
    let most = reader.u32(at + 8)?;
    let least = reader.u32(at + 12)?;
    Ok(Some(format!(
        "{}.{}.{}.{}",
        most >> 16,
        most & 0xffff,
        least >> 16,
        least & 0xffff
    )))
}

/// Decode the memory list. Every range's bytes must lie in the file.
pub(super) fn memory_list(reader: Reader<'_>, stream: &Stream) -> Result<Vec<MemoryRange>> {
    let list = list_entries(reader, stream, MEMORY_DESCRIPTOR_SIZE, "memory list")?;
    let mut ranges = Vec::with_capacity(list.count);
    for i in 0..list.count {
        let at = list.first + i * MEMORY_DESCRIPTOR_SIZE;
        let address = reader.u64(at)?;
        let size = to_usize(reader.u32(at + 8)?);
        let offset = to_usize(reader.u32(at + 12)?);
        ranges.push(memory_range(
            reader,
            address,
            offset,
            size,
            "memory range",
            i,
        )?);
    }
    Ok(ranges)
}

/// Decode the 64-bit memory list: range `i`'s bytes follow range `i - 1`'s,
/// starting at `BaseRva`.
pub(super) fn memory64_list(reader: Reader<'_>, stream: &Stream) -> Result<Vec<MemoryRange>> {
    let at = fixed_record(stream, MEMORY64_LIST_HEADER_SIZE, "memory64 list")?;
    let declared = reader.u64(at)?;
    let base_rva = reader.u64(at + 8)?;
    let entries = stream.size - MEMORY64_LIST_HEADER_SIZE;
    let count = usize::try_from(declared)
        .ok()
        .filter(|count| count.checked_mul(MEMORY_DESCRIPTOR_SIZE) == Some(entries))
        .ok_or_else(|| {
            error(format!(
                "Invalid memory64 list stream size {} B for {declared} entries of {MEMORY_DESCRIPTOR_SIZE} B",
                stream.size
            ))
        })?;
    let mut ranges = Vec::with_capacity(count);
    let mut position = base_rva;
    for i in 0..count {
        let descriptor = at + MEMORY64_LIST_HEADER_SIZE + i * MEMORY_DESCRIPTOR_SIZE;
        let address = reader.u64(descriptor)?;
        let declared_size = reader.u64(descriptor + 8)?;
        let truncated = || {
            error(format!(
                "Truncated memory64 range {i} at 0x{position:X} + {declared_size} B"
            ))
        };
        let offset = usize::try_from(position).map_err(|_| truncated())?;
        let size = usize::try_from(declared_size).map_err(|_| truncated())?;
        let range = memory_range(reader, address, offset, size, "memory64 range", i)?;
        position = to_u64(offset + range.size);
        ranges.push(range);
    }
    Ok(ranges)
}

/// A memory range whose stored bytes lie in the file and whose address
/// range does not overflow.
fn memory_range(
    reader: Reader<'_>,
    address: u64,
    offset: usize,
    size: usize,
    what: &str,
    index: usize,
) -> Result<MemoryRange> {
    if reader.bytes(offset, size, what).is_err() {
        return Err(error(format!(
            "Truncated {what} {index} at 0x{offset:X} + {size} B"
        )));
    }
    if address.checked_add(to_u64(size)).is_none() {
        return Err(error(format!(
            "Invalid {what} {index} address range 0x{address:X} + {size} B"
        )));
    }
    Ok(MemoryRange {
        address,
        offset,
        size,
    })
}

/// Decode the exception stream.
pub(super) fn exception(reader: Reader<'_>, stream: &Stream) -> Result<Exception> {
    let at = fixed_record(stream, EXCEPTION_STREAM_SIZE, "exception")?;
    Ok(Exception {
        thread_id: reader.u32(at)?,
        code: reader.u32(at + 8)?,
        flags: reader.u32(at + 0xc)?,
        address: reader.u64(at + 0x18)?,
    })
}

/// The `MINIDUMP_STRING` at `rva`, decoded from UTF-16 with unpaired
/// surrogates replaced and cut after [`MAX_DECODED_UNITS`] units.
fn string(reader: Reader<'_>, rva: u32, what: &str) -> Result<String> {
    let offset = to_usize(rva);
    let length = to_usize(reader.u32(offset).map_err(|_| {
        error(format!(
            "Truncated {what} at 0x{offset:X} + {STRING_LENGTH_SIZE} B"
        ))
    })?);
    if length % 2 != 0 || length > MAX_STRING_SIZE {
        return Err(error(format!(
            "Invalid {what} length {length} B at 0x{offset:X}"
        )));
    }
    let text_offset = offset
        .checked_add(STRING_LENGTH_SIZE)
        .ok_or_else(|| error(format!("Invalid {what} offset 0x{offset:X}")))?;
    let text = reader.bytes(text_offset, length, what)?;
    let units: Vec<u16> = text
        .chunks_exact(2)
        .take(MAX_DECODED_UNITS)
        .map(|pair| {
            let pair = [pair[0], pair[1]];
            if reader.big_endian {
                u16::from_be_bytes(pair)
            } else {
                u16::from_le_bytes(pair)
            }
        })
        .collect();
    let mut decoded = String::from_utf16_lossy(&units);
    if length / 2 > MAX_DECODED_UNITS {
        decoded.push('…');
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(offset: usize, size: usize) -> Stream {
        Stream {
            index: 0,
            kind: MODULE_LIST_STREAM,
            offset,
            size,
        }
    }

    fn reader(data: &[u8]) -> Reader<'_> {
        Reader {
            data,
            big_endian: false,
        }
    }

    #[test]
    fn lists_accept_exact_or_four_padding_bytes_only() {
        // Count 2, entries of 8 B.
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&[0; 20]);
        let r = reader(&data);
        let exact = list_entries(r, &stream(0, 20), 8, "test").unwrap();
        assert_eq!((exact.count, exact.first), (2, 4));
        let padded = list_entries(r, &stream(0, 24), 8, "test").unwrap();
        assert_eq!(padded.first, 8);
        assert_eq!(
            list_entries(r, &stream(0, 22), 8, "test")
                .unwrap_err()
                .to_string(),
            "Minidump parse error: Invalid test stream size 22 B for 2 entries of 8 B"
        );
        assert!(list_entries(r, &stream(0, 3), 8, "test").is_err());
    }

    #[test]
    fn strings_are_utf16_in_the_dump_byte_order() {
        // Length 4, "Hi".
        let le = [4, 0, 0, 0, b'H', 0, b'i', 0];
        assert_eq!(string(reader(&le), 0, "name").unwrap(), "Hi");
        let be = [0, 0, 0, 4, 0, b'H', 0, b'i'];
        let big = Reader {
            data: &be,
            big_endian: true,
        };
        assert_eq!(string(big, 0, "name").unwrap(), "Hi");
        let mut long = vec![0u8; 4];
        long[..4].copy_from_slice(&4000u32.to_le_bytes());
        long.extend(std::iter::repeat([b'a', 0]).take(2000).flatten());
        let cut = string(reader(&long), 0, "name").unwrap();
        assert_eq!(cut.chars().count(), MAX_DECODED_UNITS + 1);
        assert!(cut.ends_with('…'));
        let odd = [3, 0, 0, 0, b'H', 0, b'i'];
        assert!(string(reader(&odd), 0, "name").is_err());
        assert!(string(reader(&le[..6]), 0, "name").is_err());
        assert!(string(reader(&le), 6, "name").is_err());
    }

    #[test]
    fn module_file_names_drop_the_directory() {
        let module = Module {
            base: 0,
            size: 0,
            name: Some("C:\\Windows\\System32\\ntdll.dll".into()),
            file_version: None,
        };
        assert_eq!(module.file_name(), Some("ntdll.dll"));
        let unix = Module {
            name: Some("/usr/lib/libc.so.6".into()),
            ..module
        };
        assert_eq!(unix.file_name(), Some("libc.so.6"));
    }
}
