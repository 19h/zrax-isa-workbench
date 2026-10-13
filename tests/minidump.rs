//! Windows minidumps and kernel crash dumps: the header, stream directory and
//! streams (system information, threads, modules with names and file versions,
//! the exception, the memory and 64-bit memory lists), the processor
//! architecture as target, module memory as code components (limited to
//! executable sections when the module's PE headers are dumped) and other
//! memory as opaque components, byte-swapped dumps, corrupted fields, kernel
//! dump headers, truncation and mutation sweeps, and the real samples in
//! `IDA_INPUT_DIR`.

use zrax::{
    detect_payload, ClassifierOptions, ContainedArch, DetectionPayload, Endianness, FileFormat,
    Isa, MetadataKey,
};

/// Compiled x86-64, AArch64, i686 and big-endian MIPS32 code from the
/// repository's testbins.
const X86_64_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/x86_64_x86_64-unknown-linux-gnu_O0_call_nested.bin"
);
const AARCH64_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/aarch64_aarch64-unknown-linux-gnu_O0_call_nested.bin"
);
const X86_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/x86_i686-unknown-linux-gnu_O0_call_nested.bin"
);
const MIPS_BE_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips32_be_mips-unknown-linux-gnu_O0_call_nested.bin"
);

// Wire constants: Microsoft `minidumpapiset.h`, `winnt.h` (through the
// Win32 metadata) and Breakpad `minidump_format.h`.

/// `MINIDUMP_SIGNATURE` ("MDMP" in little-endian bytes).
const MINIDUMP_SIGNATURE: u32 = 0x504D_444D;
/// `MINIDUMP_VERSION`, the low word of `Version`.
const MINIDUMP_VERSION: u32 = 0xA793;
/// An implementation-specific high version word.
const IMPLEMENTATION_VERSION: u32 = 0x0001;
const THREAD_LIST_STREAM: u32 = 3;
const MODULE_LIST_STREAM: u32 = 4;
const MEMORY_LIST_STREAM: u32 = 5;
const EXCEPTION_STREAM: u32 = 6;
const SYSTEM_INFO_STREAM: u32 = 7;
const MEMORY64_LIST_STREAM: u32 = 9;
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_ARCHITECTURE_MIPS: u16 = 1;
const PROCESSOR_ARCHITECTURE_MSIL: u16 = 8;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
const PROCESSOR_ARCHITECTURE_UNKNOWN: u16 = 0xFFFF;
/// `VER_PLATFORM_WIN32_NT`.
const PLATFORM_WIN32_NT: u32 = 2;
/// `VS_FIXEDFILEINFO.dwSignature` and `dwStrucVersion`.
const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;
const VS_FFI_STRUCVERSION: u32 = 0x0001_0000;
/// `EXCEPTION_ACCESS_VIOLATION`.
const ACCESS_VIOLATION: u32 = 0xC000_0005;
/// `MiniDumpWithFullMemory`.
const MINIDUMP_WITH_FULL_MEMORY: u64 = 0x2;
/// `IMAGE_FILE_MACHINE_AMD64` and `IMAGE_FILE_MACHINE_I386`.
const MACHINE_AMD64: u32 = 0x8664;
const MACHINE_I386: u32 = 0x014C;
/// `DUMP_TYPE_FULL`.
const DUMP_TYPE_FULL: u32 = 1;

/// Fixed sizes of the header, a directory entry and `MINIDUMP_THREAD`,
/// `MINIDUMP_MODULE` and `MINIDUMP_MEMORY_DESCRIPTOR`.
const HEADER_SIZE: usize = 32;
const DIRECTORY_ENTRY_SIZE: usize = 12;
const MODULE_SIZE: usize = 108;

// The synthetic process.
const APP_BASE: u64 = 0x1_4000_0000;
const APP_SIZE: u32 = 0x10000;
const NTDLL_BASE: u64 = 0x7FF8_1000_0000;
const NTDLL_SIZE: u32 = 0x20000;
const CODE_ADDRESS: u64 = APP_BASE + 0x1000;
const STACK_ADDRESS: u64 = 0x9F_0000;
const STACK_SIZE: u32 = 0x1000;
const THREAD_ID: u32 = 0x1234;
const HEAP_ADDRESS: u64 = 0x50_0000;
const CODE_LABEL: &str = "Memory at 0x140001000 (app.exe)";
const STACK_LABEL: &str = "Memory at 0x9F0800 (thread 0x1234 stack)";
const HEAP_LABEL: &str = "Memory at 0x500000";

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("testbin is committed")
}

/// Fields written in the dump's byte order.
struct Writer {
    bytes: Vec<u8>,
    big_endian: bool,
}

impl Writer {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&bytes);
    }

    fn u32(&mut self, value: u32) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&bytes);
    }

    fn u64(&mut self, value: u64) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&bytes);
    }

    fn zeros(&mut self, n: usize) {
        self.bytes.resize(self.bytes.len() + n, 0);
    }

    fn rva(&self) -> u32 {
        u32::try_from(self.len()).expect("fixture fits in 4 GiB")
    }

    fn patch_u32(&mut self, at: usize, value: u32) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes[at..at + 4].copy_from_slice(&bytes);
    }

    fn patch_u64(&mut self, at: usize, value: u64) {
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes[at..at + 8].copy_from_slice(&bytes);
    }

    /// `MINIDUMP_STRING`: `Length` in bytes without the terminator, then
    /// UTF-16 units and a NUL unit.
    fn string(&mut self, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        self.u32(u32::try_from(units.len() * 2).expect("short string"));
        for unit in units {
            self.u16(unit);
        }
        self.u16(0);
    }
}

struct ModuleSpec {
    base: u64,
    size: u32,
    name: &'static str,
}

struct ThreadSpec {
    id: u32,
    stack_address: u64,
    stack_size: u32,
}

struct RangeSpec {
    address: u64,
    bytes: Vec<u8>,
}

struct ExceptionSpec {
    thread_id: u32,
    code: u32,
    address: u64,
}

#[derive(Clone, Copy, PartialEq)]
enum MemoryStream {
    /// `MemoryListStream`: a descriptor with its own RVA per range.
    List,
    /// `Memory64ListStream`: one `BaseRva`, ranges stored back to back.
    List64,
}

struct DumpSpec {
    big_endian: bool,
    /// `ProcessorArchitecture`; `None` leaves out the system info stream.
    architecture: Option<u16>,
    threads: Vec<ThreadSpec>,
    /// `None` leaves out the module list.
    modules: Option<Vec<ModuleSpec>>,
    exception: Option<ExceptionSpec>,
    memory: Vec<RangeSpec>,
    memory_stream: MemoryStream,
    /// Four padding bytes after each 32-bit list count.
    list_padding: bool,
}

/// A built dump and where its memory ranges are stored.
struct Dump {
    data: Vec<u8>,
    /// File offset of each range's bytes, in `memory` order.
    range_offsets: Vec<usize>,
    /// File offset of each stream, by stream type.
    streams: Vec<(u32, usize)>,
    /// File offset of the first memory byte: everything before it is
    /// structure.
    memory_start: usize,
}

impl Dump {
    fn stream(&self, stream_type: u32) -> usize {
        self.streams
            .iter()
            .find(|(t, _)| *t == stream_type)
            .map(|(_, offset)| *offset)
            .expect("stream is present")
    }
}

/// The default process: an AMD64 dump with two modules, one thread, an
/// access violation inside `app.exe`, and three memory ranges (x86-64 code
/// inside `app.exe`, part of the thread's stack, and heap bytes).
fn amd64_spec() -> DumpSpec {
    DumpSpec {
        big_endian: false,
        architecture: Some(PROCESSOR_ARCHITECTURE_AMD64),
        threads: vec![ThreadSpec {
            id: THREAD_ID,
            stack_address: STACK_ADDRESS,
            stack_size: STACK_SIZE,
        }],
        modules: Some(vec![
            ModuleSpec {
                base: APP_BASE,
                size: APP_SIZE,
                name: "C:\\Program Files\\App\\app.exe",
            },
            ModuleSpec {
                base: NTDLL_BASE,
                size: NTDLL_SIZE,
                name: "C:\\Windows\\System32\\ntdll.dll",
            },
        ]),
        exception: Some(ExceptionSpec {
            thread_id: THREAD_ID,
            code: ACCESS_VIOLATION,
            address: CODE_ADDRESS + 0x10,
        }),
        memory: vec![
            RangeSpec {
                address: CODE_ADDRESS,
                bytes: read(X86_64_CODE),
            },
            RangeSpec {
                address: STACK_ADDRESS + 0x800,
                bytes: (0..=255u8).collect(),
            },
            RangeSpec {
                address: HEAP_ADDRESS,
                bytes: vec![0x5A; 128],
            },
        ],
        memory_stream: MemoryStream::List,
        list_padding: false,
    }
}

/// Stream types in directory order.
fn stream_types(spec: &DumpSpec) -> Vec<u32> {
    let mut types = Vec::new();
    if spec.architecture.is_some() {
        types.push(SYSTEM_INFO_STREAM);
    }
    types.push(THREAD_LIST_STREAM);
    if spec.modules.is_some() {
        types.push(MODULE_LIST_STREAM);
    }
    if spec.exception.is_some() {
        types.push(EXCEPTION_STREAM);
    }
    types.push(match spec.memory_stream {
        MemoryStream::List => MEMORY_LIST_STREAM,
        MemoryStream::List64 => MEMORY64_LIST_STREAM,
    });
    types
}

/// The 32-bit count of a thread, module or memory list, with the optional
/// 4 padding bytes after it.
fn list_count(w: &mut Writer, spec: &DumpSpec, count: usize) {
    w.u32(u32::try_from(count).expect("small list"));
    if spec.list_padding {
        w.zeros(4);
    }
}

/// Build a minidump from the documented layout: the header at 0, the
/// directory at 0x20, the streams in [`stream_types`] order, then the
/// strings the streams point to, then the memory bytes.
fn minidump(spec: &DumpSpec) -> Dump {
    let mut w = Writer {
        bytes: Vec::new(),
        big_endian: spec.big_endian,
    };
    let types = stream_types(spec);
    // MINIDUMP_HEADER: Signature, Version, NumberOfStreams,
    // StreamDirectoryRva, CheckSum, TimeDateStamp, Flags.
    w.u32(MINIDUMP_SIGNATURE);
    w.u32((IMPLEMENTATION_VERSION << 16) | MINIDUMP_VERSION);
    w.u32(u32::try_from(types.len()).expect("few streams"));
    w.u32(u32::try_from(HEADER_SIZE).expect("small"));
    w.u32(0);
    w.u32(0x6000_0000);
    w.u64(if spec.memory_stream == MemoryStream::List64 {
        MINIDUMP_WITH_FULL_MEMORY
    } else {
        0
    });
    let directory_at = w.len();
    w.zeros(types.len() * DIRECTORY_ENTRY_SIZE);
    // RVA fields to patch once their targets are written.
    let mut strings: Vec<(usize, String)> = Vec::new();
    let mut range_rvas: Vec<usize> = Vec::new();
    let mut base_rva_at = None;
    let mut streams = Vec::new();
    for (i, &stream_type) in types.iter().enumerate() {
        let start = w.len();
        match stream_type {
            SYSTEM_INFO_STREAM => {
                // MINIDUMP_SYSTEM_INFO: ProcessorArchitecture,
                // ProcessorLevel, ProcessorRevision, NumberOfProcessors,
                // ProductType, MajorVersion, MinorVersion, BuildNumber,
                // PlatformId, CSDVersionRva, SuiteMask, Reserved2, Cpu.
                w.u16(spec.architecture.expect("system info"));
                w.u16(6);
                w.u16(0x9E09);
                w.u8(4);
                w.u8(1);
                w.u32(10);
                w.u32(0);
                w.u32(19041);
                w.u32(PLATFORM_WIN32_NT);
                strings.push((w.len(), "Service Pack 1".into()));
                w.u32(0);
                w.u16(0x0100);
                w.u16(0);
                w.zeros(24);
            }
            THREAD_LIST_STREAM => {
                list_count(&mut w, spec, spec.threads.len());
                for thread in &spec.threads {
                    // MINIDUMP_THREAD: ThreadId, SuspendCount,
                    // PriorityClass, Priority, Teb, Stack (start, size,
                    // RVA), ThreadContext (size, RVA).
                    w.u32(thread.id);
                    w.u32(0);
                    w.u32(0x20);
                    w.u32(0);
                    w.u64(0x7FF_FFFD_E000);
                    w.u64(thread.stack_address);
                    w.u32(thread.stack_size);
                    w.u32(0);
                    w.u32(0);
                    w.u32(0);
                }
            }
            MODULE_LIST_STREAM => {
                let modules = spec.modules.as_ref().expect("module list");
                list_count(&mut w, spec, modules.len());
                for (n, module) in modules.iter().enumerate() {
                    // MINIDUMP_MODULE: BaseOfImage, SizeOfImage, CheckSum,
                    // TimeDateStamp, ModuleNameRva, VersionInfo
                    // (VS_FIXEDFILEINFO: signature, struct version, file
                    // version MS and LS, 9 more fields), CvRecord,
                    // MiscRecord, Reserved0, Reserved1.
                    let entry = w.len();
                    w.u64(module.base);
                    w.u32(module.size);
                    w.u32(0);
                    w.u32(0x5F00_0000);
                    strings.push((w.len(), module.name.into()));
                    w.u32(0);
                    w.u32(VS_FFI_SIGNATURE);
                    w.u32(VS_FFI_STRUCVERSION);
                    w.u32(0x000A_0000);
                    w.u32((19041 << 16) | u32::try_from(n).expect("few modules"));
                    w.zeros(9 * 4);
                    w.zeros(8 + 8 + 8 + 8);
                    assert_eq!(w.len() - entry, MODULE_SIZE);
                }
            }
            EXCEPTION_STREAM => {
                let exception = spec.exception.as_ref().expect("exception");
                // MINIDUMP_EXCEPTION_STREAM: ThreadId, alignment, then
                // MINIDUMP_EXCEPTION (ExceptionCode, ExceptionFlags,
                // ExceptionRecord, ExceptionAddress, NumberParameters,
                // alignment, 15 ExceptionInformation words), ThreadContext.
                w.u32(exception.thread_id);
                w.u32(0);
                w.u32(exception.code);
                w.u32(0);
                w.u64(0);
                w.u64(exception.address);
                w.u32(2);
                w.u32(0);
                w.u64(1);
                w.u64(exception.address);
                w.zeros(13 * 8);
                w.zeros(8);
            }
            MEMORY_LIST_STREAM => {
                list_count(&mut w, spec, spec.memory.len());
                for range in &spec.memory {
                    // MINIDUMP_MEMORY_DESCRIPTOR: StartOfMemoryRange,
                    // DataSize, Rva.
                    w.u64(range.address);
                    w.u32(u32::try_from(range.bytes.len()).expect("small range"));
                    range_rvas.push(w.len());
                    w.u32(0);
                }
            }
            MEMORY64_LIST_STREAM => {
                // MINIDUMP_MEMORY64_LIST: NumberOfMemoryRanges, BaseRva,
                // then (StartOfMemoryRange, DataSize) per range.
                w.u64(spec.memory.len() as u64);
                base_rva_at = Some(w.len());
                w.u64(0);
                for range in &spec.memory {
                    w.u64(range.address);
                    w.u64(range.bytes.len() as u64);
                }
            }
            _ => unreachable!("builder writes only known streams"),
        }
        // MINIDUMP_DIRECTORY: StreamType, DataSize, Rva.
        let entry = directory_at + i * DIRECTORY_ENTRY_SIZE;
        let size = u32::try_from(w.len() - start).expect("small stream");
        let rva = u32::try_from(start).expect("small dump");
        w.patch_u32(entry, stream_type);
        w.patch_u32(entry + 4, size);
        w.patch_u32(entry + 8, rva);
        streams.push((stream_type, start));
    }
    for (at, text) in strings {
        let rva = w.rva();
        w.patch_u32(at, rva);
        w.string(&text);
    }
    let memory_start = w.len();
    if let Some(at) = base_rva_at {
        w.patch_u64(at, memory_start as u64);
    }
    let mut range_offsets = Vec::new();
    for (i, range) in spec.memory.iter().enumerate() {
        if let Some(&at) = range_rvas.get(i) {
            let rva = w.rva();
            w.patch_u32(at, rva);
        }
        range_offsets.push(w.len());
        w.bytes.extend_from_slice(&range.bytes);
    }
    Dump {
        data: w.bytes,
        range_offsets,
        streams,
        memory_start,
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

fn put_u32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn amd64_minidump_names_its_target_and_classifies_module_memory_as_code() {
    let dump = minidump(&amd64_spec());
    let p = classify(&dump.data);
    assert_eq!(p.format.format, FileFormat::Minidump);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("MDMP, little-endian")
    );
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.primary.bitwidth, 64);
    assert_eq!(p.primary.endianness, Endianness::Little);

    let code = slice(&p, CODE_LABEL);
    assert_eq!(code.isa, Isa::X86_64);
    assert_eq!(code.offset, dump.range_offsets[0] as u64);
    assert_eq!(code.size, read(X86_64_CODE).len() as u64);
    let stack = slice(&p, STACK_LABEL);
    assert!(matches!(stack.isa, Isa::Unknown(_)));
    assert_eq!(
        (stack.offset, stack.size),
        (dump.range_offsets[1] as u64, 256)
    );
    let heap = slice(&p, HEAP_LABEL);
    assert!(matches!(heap.isa, Isa::Unknown(_)));
    assert_eq!(heap.offset, dump.range_offsets[2] as u64);

    assert!(has_note(
        &p,
        "Processor architecture 9 (AMD64); OS version 10.0.19041 (platform ID 2); 4 processors"
    ));
    assert!(has_note(&p, "1 thread"));
    assert!(has_note(
        &p,
        "Exception 0xC0000005 at 0x140001010 (inside app.exe) in thread 0x1234"
    ));
    assert!(has_note(&p, "2 modules"));
    let memory_size = read(X86_64_CODE).len() + 256 + 128;
    assert!(has_note(&p, &format!("3 memory ranges ({memory_size} B)")));
    assert!(has_note(
        &p,
        "1 inside module images classified as code, 2 other ranges (stacks, heaps, data) opaque"
    ));
    assert!(has_note(&p, &format!("{STACK_LABEL}: opaque")));

    assert_eq!(
        metadata(&p, "minidump_module_0").as_deref(),
        Some("C:\\Program Files\\App\\app.exe; base 0x140000000; 65536 B; version 10.0.19041.0")
    );
    assert_eq!(metadata(&p, "minidump_module_count").as_deref(), Some("2"));
    assert_eq!(metadata(&p, "minidump_thread_count").as_deref(), Some("1"));
    assert_eq!(
        metadata(&p, "minidump_csd_version").as_deref(),
        Some("Service Pack 1")
    );
    assert_eq!(
        metadata(&p, "minidump_os_version").as_deref(),
        Some("10.0.19041")
    );
    assert_eq!(
        metadata(&p, "minidump_exception_code").as_deref(),
        Some("0xC0000005")
    );
    assert_eq!(
        metadata(&p, "minidump_streams").as_deref(),
        Some("system info, thread list, module list, exception, memory list")
    );
    assert_eq!(
        metadata(&p, "minidump_image_size").as_deref(),
        Some(dump.data.len().to_string().as_str())
    );
}

#[test]
fn memory64_ranges_follow_the_base_rva_in_descriptor_order() {
    let spec = DumpSpec {
        architecture: Some(PROCESSOR_ARCHITECTURE_ARM64),
        memory_stream: MemoryStream::List64,
        memory: vec![
            RangeSpec {
                address: HEAP_ADDRESS,
                bytes: vec![0; 0x40],
            },
            RangeSpec {
                address: NTDLL_BASE + 0x1000,
                bytes: read(AARCH64_CODE),
            },
            RangeSpec {
                address: STACK_ADDRESS,
                bytes: vec![0x11; 0x80],
            },
        ],
        exception: None,
        ..amd64_spec()
    };
    let dump = minidump(&spec);
    assert_eq!(dump.range_offsets[0], dump.memory_start);
    assert_eq!(dump.range_offsets[1], dump.memory_start + 0x40);
    let p = classify(&dump.data);
    assert_eq!(p.format.format, FileFormat::Minidump);
    assert_eq!(p.primary.isa, Isa::AArch64);
    let code = slice(&p, "Memory at 0x7FF810001000 (ntdll.dll)");
    assert_eq!(code.isa, Isa::AArch64);
    assert_eq!(code.offset, (dump.memory_start + 0x40) as u64);
    let stack = slice(&p, "Memory at 0x9F0000 (thread 0x1234 stack)");
    assert_eq!(
        stack.offset,
        (dump.memory_start + 0x40 + read(AARCH64_CODE).len()) as u64
    );
    assert_eq!(metadata(&p, "minidump_flags").as_deref(), Some("0x2"));
    assert_eq!(metadata(&p, "minidump_memory_ranges").as_deref(), Some("3"));
}

#[test]
fn byte_swapped_dump_reads_big_endian_and_takes_code_order_from_the_code() {
    let spec = DumpSpec {
        big_endian: true,
        architecture: Some(PROCESSOR_ARCHITECTURE_MIPS),
        memory: vec![RangeSpec {
            address: CODE_ADDRESS,
            bytes: read(MIPS_BE_CODE),
        }],
        ..amd64_spec()
    };
    let dump = minidump(&spec);
    assert_eq!(&dump.data[..4], b"PMDM");
    let p = classify(&dump.data);
    assert_eq!(p.format.format, FileFormat::Minidump);
    assert_eq!(p.format.variant_name.as_deref(), Some("MDMP, big-endian"));
    assert_eq!(p.primary.isa, Isa::Mips);
    // PROCESSOR_ARCHITECTURE_MIPS leaves the byte order open; the code
    // supplies it.
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert!(has_note(&p, "Fields are big-endian"));
    assert!(has_note(
        &p,
        "Exception 0xC0000005 at 0x140001010 (inside app.exe)"
    ));
    assert_eq!(
        metadata(&p, "minidump_module_1").as_deref(),
        Some(
            "C:\\Windows\\System32\\ntdll.dll; base 0x7FF810000000; 131072 B; version 10.0.19041.1"
        )
    );
    assert_eq!(slice(&p, CODE_LABEL).isa, Isa::Mips);
}

#[test]
fn architectures_without_a_cpu_leave_the_isa_to_module_memory() {
    for architecture in [
        PROCESSOR_ARCHITECTURE_UNKNOWN,
        PROCESSOR_ARCHITECTURE_MSIL,
        0x1234,
    ] {
        let dump = minidump(&DumpSpec {
            architecture: Some(architecture),
            ..amd64_spec()
        });
        let p = classify(&dump.data);
        assert_eq!(p.format.format, FileFormat::Minidump);
        assert!(
            has_note(
                &p,
                &format!("Processor architecture {architecture} names no CPU ISA")
            ),
            "{:?}",
            p.notes
        );
        // The code model answers from the module memory.
        assert_eq!(p.primary.isa, Isa::X86_64, "{architecture}");
        assert!(has_note(
            &p,
            &format!("Primary ISA selected from {CODE_LABEL}")
        ));
    }
    let dump = minidump(&DumpSpec {
        architecture: None,
        ..amd64_spec()
    });
    let p = classify(&dump.data);
    assert!(has_note(&p, "No system information stream"));
    assert_eq!(p.primary.isa, Isa::X86_64);
}

#[test]
fn the_architecture_field_names_the_isa_whatever_the_code_holds() {
    // An x86 dump whose module memory holds x86-64 code: the field names
    // the ISA, and the disagreement is reported.
    let dump = minidump(&DumpSpec {
        architecture: Some(PROCESSOR_ARCHITECTURE_INTEL),
        ..amd64_spec()
    });
    let p = classify(&dump.data);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(p.primary.bitwidth, 32);
    let x86 = minidump(&DumpSpec {
        architecture: Some(PROCESSOR_ARCHITECTURE_INTEL),
        memory: vec![RangeSpec {
            address: CODE_ADDRESS,
            bytes: read(X86_CODE),
        }],
        ..amd64_spec()
    });
    let p = classify(&x86.data);
    assert_eq!(p.primary.isa, Isa::X86);
    assert_eq!(slice(&p, CODE_LABEL).isa, Isa::X86);
}

#[test]
fn memory_outside_modules_is_opaque_and_without_modules_nothing_is_code() {
    let dump = minidump(&DumpSpec {
        modules: None,
        exception: None,
        ..amd64_spec()
    });
    let p = classify(&dump.data);
    assert!(has_note(&p, "No module list"));
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
    // The named target still reports, with an undetermined code check.
    assert_eq!(p.primary.isa, Isa::X86_64);
    // A range that straddles the end of a module image is not module code.
    let straddling = minidump(&DumpSpec {
        memory: vec![RangeSpec {
            address: APP_BASE + u64::from(APP_SIZE) - 0x100,
            bytes: read(X86_64_CODE),
        }],
        ..amd64_spec()
    });
    let p = classify(&straddling.data);
    assert!(p.slices.iter().all(|s| matches!(s.isa, Isa::Unknown(_))));
}

/// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ` and
/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
/// IMAGE_SCN_MEM_WRITE` (Microsoft "PE Format", "Section Flags").
const SECTION_TEXT: u32 = 0x6000_0020;
const SECTION_DATA: u32 = 0xC000_0040;
/// Where the PE header page's section table starts: `e_lfanew` 0x80, the
/// 4-byte signature, the 20-byte COFF header and a 0xF0-byte optional
/// header.
const SECTION_TABLE: usize = 0x80 + 4 + 20 + 0xF0;

/// One section header: `VirtualAddress` relative to the image base,
/// `VirtualSize` and `Characteristics`.
struct PeSection {
    address: u32,
    size: u32,
    characteristics: u32,
}

/// The first page of a loaded PE image (Microsoft "PE Format"): `MZ`,
/// `e_lfanew` 0x80 at 0x3C, `PE\0\0` at 0x80, the COFF header
/// (`Machine` AMD64, `NumberOfSections`, `SizeOfOptionalHeader` 0xF0),
/// then 40-byte section headers (`VirtualSize` at 8, `VirtualAddress` at
/// 12, `SizeOfRawData` at 16, `Characteristics` at 36).
fn pe_header_page(sections: &[PeSection]) -> Vec<u8> {
    let mut page = vec![0u8; 0x1000];
    page[..2].copy_from_slice(b"MZ");
    put_u32(&mut page, 0x3C, 0x80);
    page[0x80..0x84].copy_from_slice(b"PE\0\0");
    page[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    let count = u16::try_from(sections.len()).expect("few sections");
    page[0x86..0x88].copy_from_slice(&count.to_le_bytes());
    page[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    for (i, section) in sections.iter().enumerate() {
        let entry = SECTION_TABLE + i * 40;
        put_u32(&mut page, entry + 8, section.size);
        put_u32(&mut page, entry + 12, section.address);
        put_u32(&mut page, entry + 16, section.size);
        put_u32(&mut page, entry + 36, section.characteristics);
    }
    page
}

/// The default process with `app.exe`'s header page dumped, and a data
/// page at `APP_BASE + 0x3000`: `.text` covers the code range, `.data`
/// the data page.
fn dump_with_app_headers(sections: &[PeSection]) -> Dump {
    let mut spec = amd64_spec();
    spec.memory.insert(
        0,
        RangeSpec {
            address: APP_BASE,
            bytes: pe_header_page(sections),
        },
    );
    spec.memory.push(RangeSpec {
        address: APP_BASE + 0x3000,
        bytes: vec![0; 0x200],
    });
    minidump(&spec)
}

fn app_sections() -> [PeSection; 2] {
    [
        PeSection {
            address: 0x1000,
            size: 0x2000,
            characteristics: SECTION_TEXT,
        },
        PeSection {
            address: 0x3000,
            size: 0x1000,
            characteristics: SECTION_DATA,
        },
    ]
}

#[test]
fn dumped_pe_headers_limit_module_code_to_executable_sections() {
    let dump = dump_with_app_headers(&app_sections());
    let p = classify(&dump.data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(slice(&p, CODE_LABEL).isa, Isa::X86_64);
    let header = slice(&p, "Memory at 0x140000000 (app.exe)");
    assert!(matches!(header.isa, Isa::Unknown(_)));
    assert_eq!(header.offset, dump.range_offsets[0] as u64);
    let data = slice(&p, "Memory at 0x140003000 (app.exe)");
    assert!(matches!(data.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "1 inside module images classified as code, 2 other ranges (stacks, heaps, data) opaque"
    ));
    assert!(has_note(
        &p,
        "2 ranges inside module images but outside the executable sections their PE headers list opaque"
    ));
    assert!(!p.notes.iter().any(|n| n.message.contains("ISA unknown")));
}

#[test]
fn module_memory_stays_code_without_a_usable_section_table() {
    // No executable section: the code range is module data.
    let data_only = dump_with_app_headers(&[PeSection {
        address: 0x3000,
        size: 0x1000,
        characteristics: SECTION_DATA,
    }]);
    let p = classify(&data_only.data);
    assert!(matches!(slice(&p, CODE_LABEL).isa, Isa::Unknown(_)));
    assert!(has_note(&p, "3 ranges inside module images but outside"));
    // A header page without `MZ` says nothing: every module range is code.
    let mut spec = amd64_spec();
    spec.memory.insert(
        0,
        RangeSpec {
            address: APP_BASE,
            bytes: vec![0; 0x1000],
        },
    );
    let p = classify(&minidump(&spec).data);
    assert_eq!(slice(&p, CODE_LABEL).isa, Isa::X86_64);
    assert!(has_note(&p, "2 inside module images classified as code"));
    assert!(!has_note(&p, "outside the executable sections"));
}

#[test]
fn pe_header_mutations_never_panic() {
    let dump = dump_with_app_headers(&app_sections());
    let header = dump.range_offsets[0];
    let end = header + SECTION_TABLE + 2 * 40;
    for at in header..end {
        for value in [0x00, 0xFF, dump.data[at] ^ 0x01, dump.data[at] ^ 0x80] {
            let mut mutated = dump.data.clone();
            mutated[at] = value;
            let p = classify(&mutated);
            assert_eq!(p.format.format, FileFormat::Minidump, "byte 0x{at:X}");
        }
    }
}

#[test]
fn list_counts_may_carry_four_padding_bytes() {
    let dump = minidump(&DumpSpec {
        list_padding: true,
        ..amd64_spec()
    });
    let p = classify(&dump.data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(slice(&p, CODE_LABEL).offset, dump.range_offsets[0] as u64);
    assert_eq!(metadata(&p, "minidump_thread_count").as_deref(), Some("1"));
}

#[test]
fn corrupted_structure_is_a_minidump_parse_error() {
    let dump = minidump(&amd64_spec());
    let modules = dump.stream(MODULE_LIST_STREAM);
    let memory = dump.stream(MEMORY_LIST_STREAM);
    let directory_entry = |stream_type: u32| {
        let index = dump
            .streams
            .iter()
            .position(|(t, _)| *t == stream_type)
            .expect("stream");
        HEADER_SIZE + index * DIRECTORY_ENTRY_SIZE
    };

    let mut many_streams = dump.data.clone();
    put_u32(&mut many_streams, 8, 0x0100_0000);
    assert!(
        error_text(&many_streams).starts_with("Minidump parse error: Truncated stream directory")
    );

    let mut stream_outside = dump.data.clone();
    put_u32(
        &mut stream_outside,
        directory_entry(MODULE_LIST_STREAM) + 8,
        0xFFFF_0000,
    );
    assert_eq!(
        error_text(&stream_outside),
        format!(
            "Minidump parse error: Truncated stream 2 (type 0x4) at 0xFFFF0000 + {} B",
            4 + 2 * MODULE_SIZE
        )
    );

    let mut count = dump.data.clone();
    put_u32(&mut count, modules, 3);
    assert_eq!(
        error_text(&count),
        format!(
            "Minidump parse error: Invalid module list stream size {} B for 3 entries of 108 B",
            4 + 2 * MODULE_SIZE
        )
    );

    let mut duplicate = dump.data.clone();
    put_u32(
        &mut duplicate,
        directory_entry(EXCEPTION_STREAM),
        MODULE_LIST_STREAM,
    );
    assert_eq!(
        error_text(&duplicate),
        "Minidump parse error: Duplicate module list stream (directory entries 2 and 3)"
    );

    let mut range_outside = dump.data.clone();
    put_u32(&mut range_outside, memory + 4 + 12, 0x7FFF_0000);
    assert!(error_text(&range_outside)
        .starts_with("Minidump parse error: Truncated memory range 0 at 0x7FFF0000"));

    let mut address_overflow = dump.data.clone();
    address_overflow[memory + 4..memory + 12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(error_text(&address_overflow)
        .starts_with("Minidump parse error: Invalid memory range 0 address range"));

    let mut module_overflow = dump.data.clone();
    module_overflow[modules + 4..modules + 12].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    assert!(error_text(&module_overflow)
        .starts_with("Minidump parse error: Invalid module 0 image range 0xFFFFFFFFFFFFFFFE"));

    let mut odd_name = dump.data.clone();
    let name_rva = u32::from_le_bytes(
        dump.data[modules + 4 + 0x14..modules + 4 + 0x18]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    put_u32(&mut odd_name, name_rva, 5);
    assert!(
        error_text(&odd_name).starts_with("Minidump parse error: Invalid module 0 name length 5 B")
    );

    let mut short_system = dump.data.clone();
    put_u32(
        &mut short_system,
        directory_entry(SYSTEM_INFO_STREAM) + 4,
        40,
    );
    assert!(error_text(&short_system)
        .starts_with("Minidump parse error: Truncated system info stream at"));

    let mut short_exception = dump.data.clone();
    put_u32(
        &mut short_exception,
        directory_entry(EXCEPTION_STREAM) + 4,
        100,
    );
    assert!(error_text(&short_exception)
        .starts_with("Minidump parse error: Truncated exception stream at"));
}

#[test]
fn memory64_list_size_must_match_its_count() {
    let dump = minidump(&DumpSpec {
        memory_stream: MemoryStream::List64,
        ..amd64_spec()
    });
    let list = dump.stream(MEMORY64_LIST_STREAM);
    let mut count = dump.data.clone();
    count[list..list + 8].copy_from_slice(&4u64.to_le_bytes());
    assert_eq!(
        error_text(&count),
        "Minidump parse error: Invalid memory64 list stream size 64 B for 4 entries of 16 B"
    );
    let mut base = dump.data.clone();
    base[list + 8..list + 16].copy_from_slice(&(dump.data.len() as u64).to_le_bytes());
    assert!(error_text(&base).starts_with("Minidump parse error: Truncated memory64 range 0"));
}

#[test]
fn wrong_version_word_is_not_a_minidump_and_a_short_header_is_an_error() {
    let dump = minidump(&amd64_spec());
    let mut version = dump.data.clone();
    version[4] ^= 1;
    let p = detect_payload(&version, &ClassifierOptions::new());
    assert!(!matches!(p, Ok(p) if p.format.format == FileFormat::Minidump));
    assert_eq!(
        error_text(&dump.data[..20]),
        "Minidump parse error: Truncated header at 0x0 + 32 B"
    );
}

#[test]
fn every_prefix_errors_or_is_not_a_minidump() {
    let dump = minidump(&amd64_spec());
    for end in 0..dump.data.len() {
        if let Ok(p) = detect_payload(&dump.data[..end], &ClassifierOptions::new()) {
            assert!(
                end < 8 && p.format.format != FileFormat::Minidump,
                "prefix {end} classified as {:?}",
                p.format.format
            );
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    for spec in [
        amd64_spec(),
        DumpSpec {
            memory_stream: MemoryStream::List64,
            big_endian: true,
            ..amd64_spec()
        },
    ] {
        let dump = minidump(&spec);
        // Every structure byte, and every 16th memory byte.
        let positions =
            (0..dump.memory_start).chain((dump.memory_start..dump.data.len()).step_by(16));
        for at in positions {
            for mutation in [0x00, 0xFF, dump.data[at] ^ 0x01, dump.data[at] ^ 0x80] {
                let mut data = dump.data.clone();
                data[at] = mutation;
                let _ = detect_payload(&data, &ClassifierOptions::new());
            }
        }
    }
}

/// Field offsets of the kernel dump headers (Win32 metadata `DUMP_HEADER32`
/// and `DUMP_HEADER64`, C layout).
struct KernelLayout {
    size: usize,
    valid_dump: &'static [u8; 4],
    machine_image_type: usize,
    number_processors: usize,
    bug_check_code: usize,
    bug_check_parameters: usize,
    parameter_size: usize,
    dump_type: usize,
    required_dump_space: usize,
}

const KERNEL32: KernelLayout = KernelLayout {
    size: 0x1000,
    valid_dump: b"DUMP",
    machine_image_type: 0x20,
    number_processors: 0x24,
    bug_check_code: 0x28,
    bug_check_parameters: 0x2C,
    parameter_size: 4,
    dump_type: 0xF88,
    required_dump_space: 0xFA0,
};

const KERNEL64: KernelLayout = KernelLayout {
    size: 0x2000,
    valid_dump: b"DU64",
    machine_image_type: 0x30,
    number_processors: 0x34,
    bug_check_code: 0x38,
    bug_check_parameters: 0x40,
    parameter_size: 8,
    dump_type: 0xF98,
    required_dump_space: 0xFA0,
};

/// A kernel dump header filled with the "PAGE" pattern, then
/// `Signature`, `ValidDump`, `MajorVersion` 0xF, `MinorVersion` 19041,
/// `MachineImageType`, `NumberProcessors` 2, bug check 0xD1 with
/// parameters 1-4, `DumpType` full and `RequiredDumpSpace`, followed by
/// `body` (physical memory pages in a full dump).
fn kernel_dump(layout: &KernelLayout, machine: u32, body: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = b"PAGE".iter().copied().cycle().take(layout.size).collect();
    data[4..8].copy_from_slice(layout.valid_dump);
    put_u32(&mut data, 8, 0xF);
    put_u32(&mut data, 0xC, 19041);
    put_u32(&mut data, layout.machine_image_type, machine);
    put_u32(&mut data, layout.number_processors, 2);
    put_u32(&mut data, layout.bug_check_code, 0xD1);
    for i in 0..4 {
        let at = layout.bug_check_parameters + i * layout.parameter_size;
        data[at..at + layout.parameter_size].fill(0);
        data[at] = u8::try_from(i + 1).expect("small");
    }
    put_u32(&mut data, layout.dump_type, DUMP_TYPE_FULL);
    let required = (layout.size + body.len()) as u64;
    data[layout.required_dump_space..layout.required_dump_space + 8]
        .copy_from_slice(&required.to_le_bytes());
    data.extend_from_slice(body);
    data
}

#[test]
fn kernel_dumps_name_the_machine_and_keep_physical_memory_opaque() {
    let body = read(X86_64_CODE);
    for (layout, machine, isa, variant) in [
        (
            &KERNEL64,
            MACHINE_AMD64,
            Isa::X86_64,
            "PAGEDU64, 64-bit header",
        ),
        (&KERNEL32, MACHINE_I386, Isa::X86, "PAGEDUMP, 32-bit header"),
    ] {
        let data = kernel_dump(layout, machine, &body);
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::WindowsKernelDump);
        assert_eq!(p.format.variant_name.as_deref(), Some(variant));
        assert_eq!(p.primary.isa, isa);
        assert_eq!(p.primary.endianness, Endianness::Little);
        assert!(has_note(&p, &format!("MachineImageType 0x{machine:X} (")));
        assert!(has_note(&p, "2 processors"));
        assert!(has_note(&p, "Bug check 0x000000D1 (0x1, 0x2, 0x3, 0x4)"));
        assert!(has_note(&p, "Dump type 1 (full)"));
        let body_slice = slice(&p, "Dump data after the header");
        assert!(matches!(body_slice.isa, Isa::Unknown(_)));
        assert_eq!(
            (body_slice.offset, body_slice.size),
            (layout.size as u64, body.len() as u64)
        );
        assert_eq!(
            metadata(&p, "minidump_kernel_version").as_deref(),
            Some("15.19041")
        );
        assert_eq!(metadata(&p, "minidump_dump_type").as_deref(), Some("1"));
    }
}

#[test]
fn kernel_dump_with_unknown_machine_or_short_header() {
    let data = kernel_dump(&KERNEL64, 0x4547_4150, &[]);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::WindowsKernelDump);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "names no architecture in the PE machine table"
    ));
    assert!(p.slices.is_empty());

    let mut short = kernel_dump(&KERNEL32, MACHINE_I386, &[]);
    put_u32(&mut short, KERNEL32.required_dump_space, 0x10_0000);
    let p = classify(&short);
    assert!(has_note(
        &p,
        "RequiredDumpSpace is 1048576 B; the file holds 4096 B"
    ));
    assert_eq!(
        error_text(&short[..0x800]),
        "Minidump parse error: Truncated kernel dump header at 0x0 + 4096 B"
    );
    for end in 8..KERNEL64.size {
        assert!(
            detect_payload(&data[..end], &ClassifierOptions::new()).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn kernel_dump_mutations_never_panic() {
    let data = kernel_dump(&KERNEL32, MACHINE_I386, &[0x90; 64]);
    for at in (0..data.len()).step_by(3) {
        for mutation in [0x00, 0xFF, data[at] ^ 0x01] {
            let mut mutated = data.clone();
            mutated[at] = mutation;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

/// The real minidumps among IDA's test inputs (`IDA_INPUT_DIR`, read-only):
/// every `*.windmp` file is classified without panicking; the ones that
/// start with `MDMP` report their documented architecture, and every
/// prefix of them errors.
#[test]
fn ida_windows_dump_samples() {
    let Some(dir) = std::env::var_os("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR is not set; skipping the real minidump samples");
        return;
    };
    let expected = [
        ("pc_windbg_windmp.windmp", Isa::X86),
        ("pc_windbg_windmp_highdll.windmp", Isa::X86),
        ("pc_windbg_bitness_64.windmp", Isa::X86_64),
    ];
    let mut checked = 0;
    let entries = std::fs::read_dir(&dir).expect("IDA_INPUT_DIR is readable");
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("windmp") {
            continue;
        }
        let data = std::fs::read(&path).expect("sample is readable");
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let result = detect_payload(&data, &ClassifierOptions::new());
        if !data.starts_with(b"MDMP") {
            continue;
        }
        let p = result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.format.format, FileFormat::Minidump, "{name}");
        if let Some((_, isa)) = expected.iter().find(|(n, _)| *n == name) {
            assert_eq!(p.primary.isa, *isa, "{name}");
        }
        assert!(!p.slices.is_empty(), "{name}");
        for end in (8..data.len()).step_by(data.len() / 64 + 1) {
            assert!(
                detect_payload(&data[..end], &ClassifierOptions::new()).is_err(),
                "{name} prefix {end}"
            );
        }
        checked += 1;
    }
    eprintln!("checked {checked} minidump samples");
}
