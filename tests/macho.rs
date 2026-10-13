//! Mach-O load commands: segments and sections, platforms, entry points,
//! UUIDs and code-signature, encryption and chained-fixup records, the
//! extension scan limited to instruction sections, `MH_FILESET` entries
//! classified on their own, fat slices, clang-built executables and
//! objects, corrupted commands, and truncation and mutation sweeps; and,
//! when `IDA_INPUT_DIR` or `MACHO_HOST_DIR` is set, IDA Pro's kernel
//! collections and this machine's binaries, read in place.

use zrax::formats::compressed::{self, Codec};
use zrax::formats::macho;
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, ExtensionSource, FileFormat,
    Isa, MetadataKey,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/macho");

// Wire constants: xnu-12377.121.6 `EXTERNAL_HEADERS/mach-o/loader.h`,
// `mach/machine.h` CPU types and cctools `thread_status.h` flavors.
const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const CPU_SUBTYPE_ARM_V7: u32 = 9;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_DSYM: u32 = 0xA;
const MH_KEXT_BUNDLE: u32 = 0xB;
const MH_FILESET: u32 = 0xC;
const MH_PIE: u32 = 0x20_0000;
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1B;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_MAIN: u32 = 0x8000_0028;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_FILESET_ENTRY: u32 = 0x8000_0035;
const S_REGULAR: u32 = 0x0;
const S_ZEROFILL: u32 = 0x1;
const S_CSTRING_LITERALS: u32 = 0x2;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const CODE: u32 = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
const VM_PROT_RW: u32 = 0x3;
const VM_PROT_RX: u32 = 0x5;
const VM_PROT_R: u32 = 0x1;
const PLATFORM_MACOS: u32 = 1;
const PLATFORM_MACCATALYST: u32 = 6;
const PLATFORM_IOSSIMULATOR: u32 = 7;
const PLATFORM_DRIVERKIT: u32 = 10;
const PLATFORM_XROS: u32 = 11;
const TOOL_LD: u32 = 3;
const X86_THREAD_STATE64: u32 = 4;
const X86_THREAD_STATE64_COUNT: usize = 42;
const ARM_THREAD_STATE: u32 = 1;
const ARM_THREAD_STATE_COUNT: usize = 17;
const ARM_THREAD_STATE64: u32 = 6;
const ARM_THREAD_STATE64_COUNT: usize = 68;
const PPC_THREAD_STATE: u32 = 1;
const PPC_THREAD_STATE_COUNT: usize = 40;
/// `ppc_thread_state64` under `#pragma pack(4)`: 304 B.
const PPC_THREAD_STATE64: u32 = 5;
const PPC_THREAD_STATE64_COUNT: usize = 76;

/// AArch64 `ret` and x86 `ret`, the synthetic code.
const AARCH64_RET: u32 = 0xD65F_03C0;
const X86_RET: u8 = 0xC3;

/// `xxxx.yy.zz` version nibbles.
const fn version(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

fn fixture(name: &str) -> Vec<u8> {
    let stored = std::fs::read(format!("{FIXTURES}/{name}")).expect("fixture is committed");
    compressed::decode(Codec::Gzip, &stored)
        .expect("the fixture is a gzip stream")
        .data
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn notes(p: &DetectionPayload) -> Vec<&str> {
    p.notes.iter().map(|n| n.message.as_str()).collect()
}

fn assert_note(p: &DetectionPayload, expected: &str) {
    assert!(
        notes(p).contains(&expected),
        "missing note {expected:?}: {:#?}",
        notes(p)
    );
}

fn assert_note_containing(p: &DetectionPayload, needle: &str) {
    assert!(
        notes(p).iter().any(|n| n.contains(needle)),
        "no note contains {needle:?}: {:#?}",
        notes(p)
    );
}

fn custom<'a>(p: &'a DetectionPayload, key: &str) -> Option<&'a zrax::MetadataEntry> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
}

fn custom_text(p: &DetectionPayload, key: &str) -> String {
    custom(p, key)
        .unwrap_or_else(|| panic!("metadata {key}: {:#?}", p.metadata))
        .value
        .to_string()
}

/// A generic metadata entry's value as text.
fn generic(p: &DetectionPayload, key: &MetadataKey) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| &m.key == key)
        .map(|m| m.value.to_string())
}

fn code_extensions(p: &DetectionPayload) -> Vec<String> {
    p.extensions
        .iter()
        .filter(|e| e.source == ExtensionSource::CodePattern)
        .map(|e| e.name.clone())
        .collect()
}

fn names(extensions: &[zrax::Extension]) -> Vec<String> {
    extensions.iter().map(|e| e.name.clone()).collect()
}

// Fixture builders, from the `loader.h` layouts.

/// Bytes in one byte order.
struct Writer {
    bytes: Vec<u8>,
    little_endian: bool,
}

impl Writer {
    fn new(le: bool) -> Self {
        Self {
            bytes: Vec::new(),
            little_endian: le,
        }
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        let bytes = if self.little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        self.bytes.extend_from_slice(&bytes);
        self
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        let bytes = if self.little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        self.bytes.extend_from_slice(&bytes);
        self
    }

    /// A 4-byte or 8-byte address field.
    fn word(&mut self, value: u64, is_64: bool) -> &mut Self {
        if is_64 {
            self.u64(value)
        } else {
            self.u32(u32::try_from(value).expect("32-bit field"))
        }
    }

    /// A 16-byte NUL-padded name.
    fn name(&mut self, name: &str) -> &mut Self {
        let mut field = [0u8; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(&field);
        self
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// A section record.
struct SectionSpec {
    name: &'static str,
    segment: &'static str,
    /// `addr`: target address.
    address: u64,
    /// `size` in bytes.
    size: u64,
    /// `offset`: file offset.
    offset: u32,
    /// `flags`: type and attributes.
    flags: u32,
}

/// A segment command and its sections.
struct SegmentSpec {
    name: &'static str,
    vm_address: u64,
    vm_size: u64,
    file_offset: u64,
    file_size: u64,
    /// `initprot`; `maxprot` is the same.
    protection: u32,
    sections: Vec<SectionSpec>,
}

/// `segment_command_64` (72 B) or `segment_command` (56 B): `cmd`,
/// `cmdsize`, `segname[16]`, `vmaddr`, `vmsize`, `fileoff`, `filesize`
/// (words), `maxprot`, `initprot`, `nsects`, `flags`; then each `section_64`
/// (80 B) or `section` (68 B): `sectname[16]`, `segname[16]`, `addr`,
/// `size` (words), `offset`, `align`, `reloff`, `nreloc`, `flags`,
/// `reserved1`, `reserved2` (and `reserved3` in 64-bit).
fn segment(spec: &SegmentSpec, is_64: bool, le: bool) -> Vec<u8> {
    let (cmd, command_size, section_size) = if is_64 {
        (LC_SEGMENT_64, 72, 80)
    } else {
        (LC_SEGMENT, 56, 68)
    };
    let nsects = u32::try_from(spec.sections.len()).expect("few sections");
    let mut w = Writer::new(le);
    w.u32(cmd)
        .u32(command_size + nsects * section_size)
        .name(spec.name)
        .word(spec.vm_address, is_64)
        .word(spec.vm_size, is_64)
        .word(spec.file_offset, is_64)
        .word(spec.file_size, is_64)
        .u32(spec.protection)
        .u32(spec.protection)
        .u32(nsects)
        .u32(0);
    for section in &spec.sections {
        w.name(section.name)
            .name(section.segment)
            .word(section.address, is_64)
            .word(section.size, is_64)
            .u32(section.offset)
            .u32(2)
            .u32(0)
            .u32(0)
            .u32(section.flags)
            .u32(0)
            .u32(0);
        if is_64 {
            w.u32(0);
        }
    }
    w.take()
}

/// `build_version_command` (24 B): `platform`, `minos`, `sdk`, `ntools`,
/// then one `build_tool_version` (`tool`, `version`) per tool.
fn build_version(le: bool, platform: u32, min_os: u32, sdk: u32, tools: &[u32]) -> Vec<u8> {
    let count = u32::try_from(tools.len()).expect("few tools");
    let mut w = Writer::new(le);
    w.u32(LC_BUILD_VERSION)
        .u32(24 + 8 * count)
        .u32(platform)
        .u32(min_os)
        .u32(sdk)
        .u32(count);
    for &tool in tools {
        w.u32(tool).u32(version(1, 0, 0));
    }
    w.take()
}

/// `version_min_command` (16 B): `version`, `sdk`.
fn version_min(le: bool, cmd: u32, min_os: u32, sdk: u32) -> Vec<u8> {
    Writer::new(le).u32(cmd).u32(16).u32(min_os).u32(sdk).take()
}

/// `entry_point_command` (24 B): `entryoff`, `stacksize`.
fn main_command(le: bool, entry_offset: u64) -> Vec<u8> {
    Writer::new(le)
        .u32(LC_MAIN)
        .u32(24)
        .u64(entry_offset)
        .u64(0)
        .take()
}

/// `thread_command`: one `flavor`, `count` and `count` zero words with the
/// program counter written at byte `pc_offset` (4 or 8 bytes wide).
fn unix_thread(
    le: bool,
    flavor: u32,
    count: usize,
    pc_offset: usize,
    pc: u64,
    wide: bool,
) -> Vec<u8> {
    let mut state = Writer::new(le);
    for _ in 0..count {
        state.u32(0);
    }
    let mut state = state.take();
    let mut pc_bytes = Writer::new(le);
    pc_bytes.word(pc, wide);
    let pc_bytes = pc_bytes.take();
    state[pc_offset..pc_offset + pc_bytes.len()].copy_from_slice(&pc_bytes);
    let mut w = Writer::new(le);
    w.u32(LC_UNIXTHREAD)
        .u32(u32::try_from(16 + state.len()).expect("small state"))
        .u32(flavor)
        .u32(u32::try_from(count).expect("small count"));
    w.bytes.extend_from_slice(&state);
    w.take()
}

/// `uuid_command` (24 B).
fn uuid_command(le: bool, uuid: [u8; 16]) -> Vec<u8> {
    let mut w = Writer::new(le);
    w.u32(LC_UUID).u32(24);
    w.bytes.extend_from_slice(&uuid);
    w.take()
}

/// `linkedit_data_command` (16 B): `dataoff`, `datasize`.
fn linkedit(le: bool, cmd: u32, offset: u32, size: u32) -> Vec<u8> {
    Writer::new(le)
        .u32(cmd)
        .u32(16)
        .u32(offset)
        .u32(size)
        .take()
}

/// `encryption_info_command` (20 B) or `encryption_info_command_64` (24 B,
/// with `pad`): `cryptoff`, `cryptsize`, `cryptid`.
fn encryption(le: bool, is_64: bool, offset: u32, size: u32, id: u32) -> Vec<u8> {
    let mut w = Writer::new(le);
    if is_64 {
        w.u32(LC_ENCRYPTION_INFO_64).u32(24);
    } else {
        w.u32(LC_ENCRYPTION_INFO).u32(20);
    }
    w.u32(offset).u32(size).u32(id);
    if is_64 {
        w.u32(0);
    }
    w.take()
}

/// `fileset_entry_command` (32 B): `vmaddr`, `fileoff`, `entry_id` (offset
/// 32 from the command start), `reserved`, then the NUL-terminated ID
/// padded to 8 bytes.
fn fileset_entry(le: bool, vm_address: u64, file_offset: u64, id: &str) -> Vec<u8> {
    let mut text = id.as_bytes().to_vec();
    text.push(0);
    while text.len() % 8 != 0 {
        text.push(0);
    }
    let mut w = Writer::new(le);
    w.u32(LC_FILESET_ENTRY)
        .u32(u32::try_from(32 + text.len()).expect("short ID"))
        .u64(vm_address)
        .u64(file_offset)
        .u32(32)
        .u32(0);
    w.bytes.extend_from_slice(&text);
    w.take()
}

/// A Mach-O header and its load commands.
struct ImageSpec {
    is_64: bool,
    little_endian: bool,
    cpu_type: u32,
    cpu_subtype: u32,
    file_type: u32,
    flags: u32,
    commands: Vec<Vec<u8>>,
}

/// `mach_header_64` (32 B) or `mach_header` (28 B): `magic`, `cputype`,
/// `cpusubtype`, `filetype`, `ncmds`, `sizeofcmds`, `flags` (and
/// `reserved`), followed by the load commands.
fn image(spec: &ImageSpec) -> Vec<u8> {
    let sizeofcmds: usize = spec.commands.iter().map(Vec::len).sum();
    let mut w = Writer::new(spec.little_endian);
    w.u32(if spec.is_64 { MH_MAGIC_64 } else { MH_MAGIC })
        .u32(spec.cpu_type)
        .u32(spec.cpu_subtype)
        .u32(spec.file_type)
        .u32(u32::try_from(spec.commands.len()).expect("few commands"))
        .u32(u32::try_from(sizeofcmds).expect("small commands"))
        .u32(spec.flags);
    if spec.is_64 {
        w.u32(0);
    }
    for command in &spec.commands {
        w.bytes.extend_from_slice(command);
    }
    w.take()
}

/// Copy `bytes` to `offset`, growing `data` with zeros.
fn place(data: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
    if data.len() < offset + bytes.len() {
        data.resize(offset + bytes.len(), 0);
    }
    data[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// `count` AArch64 `ret` instructions.
fn aarch64_code(count: usize) -> Vec<u8> {
    AARCH64_RET.to_le_bytes().repeat(count)
}

/// The header of `data` with no load commands: what the classifier knew
/// before it read load commands.
fn header_only(data: &[u8]) -> Vec<u8> {
    let is_64 = data[..4] == MH_MAGIC_64.to_le_bytes() || data[..4] == MH_MAGIC_64.to_be_bytes();
    let mut header = data[..if is_64 { 32 } else { 28 }].to_vec();
    header[16..24].fill(0);
    header
}

/// The primary classification must be the header's alone.
fn assert_primary_from_header(p: &DetectionPayload, data: &[u8]) {
    let before = classify(&header_only(data));
    assert_eq!(p.primary.isa, before.primary.isa);
    assert_eq!(p.primary.bitwidth, before.primary.bitwidth);
    assert_eq!(p.primary.endianness, before.primary.endianness);
    assert_eq!(p.primary.variant, before.primary.variant);
    assert_eq!(p.primary.source, before.primary.source);
    assert_eq!(p.notes[0].message, before.notes[0].message);
}

/// 64-bit little-endian arm64 executable, 0x5100 B: `__PAGEZERO`; `__TEXT`
/// (file 0..0x4000 at 0x1_0000_0000) with `__text` (64 B of `ret` at
/// 0x1000) and `__cstring` (16 B at 0x1040); `__DATA` (file 0x4000..0x5000)
/// with `__data` (32 B) and a zero-fill `__bss`; `__LINKEDIT` (file
/// 0x5000..0x5100) holding the chained fixups (56 B at 0x5000) and the code
/// signature (192 B at 0x5040); `LC_BUILD_VERSION` macOS 14.0, SDK 15.2,
/// one tool; `LC_MAIN` at file offset 0x1000; `LC_UUID` 00..0F.
fn arm64_executable_spec() -> ImageSpec {
    let base = 0x1_0000_0000;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: base,
        vm_size: 0x4000,
        file_offset: 0,
        file_size: 0x4000,
        protection: VM_PROT_RX,
        sections: vec![
            SectionSpec {
                name: "__text",
                segment: "__TEXT",
                address: base + 0x1000,
                size: 0x40,
                offset: 0x1000,
                flags: CODE,
            },
            SectionSpec {
                name: "__cstring",
                segment: "__TEXT",
                address: base + 0x1040,
                size: 0x10,
                offset: 0x1040,
                flags: S_CSTRING_LITERALS,
            },
        ],
    };
    let data_segment = SegmentSpec {
        name: "__DATA",
        vm_address: base + 0x4000,
        vm_size: 0x1000,
        file_offset: 0x4000,
        file_size: 0x1000,
        protection: VM_PROT_RW,
        sections: vec![
            SectionSpec {
                name: "__data",
                segment: "__DATA",
                address: base + 0x4000,
                size: 0x20,
                offset: 0x4000,
                flags: S_REGULAR,
            },
            SectionSpec {
                name: "__bss",
                segment: "__DATA",
                address: base + 0x4020,
                size: 0x100,
                offset: 0,
                flags: S_ZEROFILL,
            },
        ],
    };
    let pagezero = SegmentSpec {
        name: "__PAGEZERO",
        vm_address: 0,
        vm_size: base,
        file_offset: 0,
        file_size: 0,
        protection: 0,
        sections: Vec::new(),
    };
    let linkedit_segment = SegmentSpec {
        name: "__LINKEDIT",
        vm_address: base + 0x5000,
        vm_size: 0x1000,
        file_offset: 0x5000,
        file_size: 0x100,
        protection: VM_PROT_R,
        sections: Vec::new(),
    };
    let le = true;
    ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_EXECUTE,
        flags: MH_PIE,
        commands: vec![
            segment(&pagezero, true, le),
            segment(&text, true, le),
            segment(&data_segment, true, le),
            segment(&linkedit_segment, true, le),
            linkedit(le, LC_DYLD_CHAINED_FIXUPS, 0x5000, 0x38),
            build_version(
                le,
                PLATFORM_MACOS,
                version(14, 0, 0),
                version(15, 2, 0),
                &[TOOL_LD],
            ),
            main_command(le, 0x1000),
            uuid_command(le, core::array::from_fn(|i| i as u8)),
            linkedit(le, LC_CODE_SIGNATURE, 0x5040, 0xC0),
        ],
    }
}

fn arm64_executable() -> Vec<u8> {
    let mut data = image(&arm64_executable_spec());
    place(&mut data, 0x1000, &aarch64_code(16));
    place(&mut data, 0x1040, b"hello, mach-o\0\0\0");
    place(&mut data, 0x5000, &[0xEE; 0x100]);
    data
}

#[test]
fn arm64_executable_reports_segments_platform_entry_and_signature() {
    let data = arm64_executable();
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::MachO);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.primary.bitwidth, 64);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_primary_from_header(&p, &data);
    let sizeofcmds: usize = arm64_executable_spec().commands.iter().map(Vec::len).sum();
    assert_note(&p, "CPU subtype: 0x00000000");
    assert_note(
        &p,
        &format!("MH_EXECUTE; 9 load commands ({sizeofcmds} B); 4 segments, 4 sections"),
    );
    assert_note(
        &p,
        "Platform macOS (LC_BUILD_VERSION); minimum OS 14.0; SDK 15.2",
    );
    assert_note(&p, "Entry point 0x100001000 (LC_MAIN file offset 0x1000)");
    assert_note(
        &p,
        "Code signature present (LC_CODE_SIGNATURE at 0x5040, 192 B); not verified",
    );
    assert_note(
        &p,
        "Chained fixups present (LC_DYLD_CHAINED_FIXUPS at 0x5000, 56 B)",
    );
    assert_note(&p, "Extensions scanned in 1 instruction section (64 B)");

    assert_eq!(
        generic(&p, &MetadataKey::EntryPoint),
        Some("0x100001000".to_string())
    );
    assert_eq!(
        generic(&p, &MetadataKey::SectionCount),
        Some("4".to_string())
    );
    assert_eq!(generic(&p, &MetadataKey::CodeSize), Some("64".to_string()));
    assert_eq!(
        generic(&p, &MetadataKey::Flags),
        Some(format!("0x{MH_PIE:08X}"))
    );
    assert_eq!(custom_text(&p, "macho_file_type"), "MH_EXECUTE");
    assert_eq!(custom_text(&p, "macho_load_commands"), "9");
    assert_eq!(
        custom_text(&p, "macho_uuid"),
        "00010203-0405-0607-0809-0A0B0C0D0E0F"
    );
    assert_eq!(custom_text(&p, "macho_platform"), "macOS");
    assert_eq!(custom_text(&p, "macho_min_os"), "14.0");
    assert_eq!(custom_text(&p, "macho_sdk"), "15.2");
    assert_eq!(custom_text(&p, "macho_entry_file_offset"), "4096");
    assert_eq!(
        custom_text(&p, "macho_code_signature"),
        "file 0x5040; 192 B"
    );
    assert_eq!(custom_text(&p, "macho_chained_fixups"), "file 0x5000; 56 B");
    let text = custom(&p, "macho_segment_1").expect("__TEXT is listed");
    assert_eq!(text.label, "__TEXT");
    assert_eq!(
        text.value.to_string(),
        "vm 0x100000000, 16384 B; file 0x0, 16384 B; r-x/r-x; 2 sections"
    );
    let pagezero = custom(&p, "macho_segment_0").expect("__PAGEZERO is listed");
    assert_eq!(
        pagezero.value.to_string(),
        "vm 0x0, 4294967296 B; file 0x0, 0 B; ---/---; 0 sections"
    );
    let code = custom(&p, "macho_section_0").expect("__text is listed");
    assert_eq!(code.label, "__TEXT,__text");
    assert_eq!(
        code.value.to_string(),
        "vm 0x100001000; file 0x1000; 64 B; flags 0x80000400; instructions"
    );
    let bss = custom(&p, "macho_section_3").expect("__bss is listed");
    assert_eq!(bss.label, "__DATA,__bss");
    assert!(bss.value.to_string().ends_with("; zero fill"));
}

#[test]
fn parse_image_exposes_the_commands_it_read() {
    let data = arm64_executable();
    let image = macho::parse_image(&data).expect("parses");
    assert_eq!(image.header.file_type, MH_EXECUTE);
    assert!(image.header.is_64 && image.header.little_endian);
    assert_eq!(image.segments.len(), 4);
    assert_eq!(image.segments[1].sections[0].name, "__text");
    assert!(image.segments[1].sections[0].has_instructions());
    assert!(!image.segments[1].sections[1].has_instructions());
    assert!(image.segments[2].sections[1].is_zero_fill());
    assert_eq!(image.build_versions[0].platform, PLATFORM_MACOS);
    assert_eq!(
        image.entry,
        Some(macho::Entry::Main {
            file_offset: 0x1000
        })
    );
    assert_eq!(image.entry_address(), Some(0x1_0000_1000));
    assert_eq!(
        image.code_signature,
        Some(macho::DataRange {
            offset: 0x5040,
            size: 0xC0
        })
    );
    let code = image.code(&data).expect("offsets locate the code");
    assert_eq!(&code.bytes[..], &aarch64_code(16)[..]);
    assert_eq!(code.sections, 1);
}

/// 32-bit big-endian PowerPC executable: `LC_SEGMENT` `__TEXT` (file
/// 0..0x2000 at 0x1000) with `__text` (256 B at 0x1000),
/// `LC_UNIXTHREAD` `PPC_THREAD_STATE` with `srr0` 0x1A40 and
/// `LC_VERSION_MIN_MACOSX` 10.4, SDK 10.4.11.
fn powerpc_executable() -> Vec<u8> {
    let le = false;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0x1000,
        vm_size: 0x2000,
        file_offset: 0,
        file_size: 0x2000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x2000,
            size: 0x100,
            offset: 0x1000,
            flags: CODE,
        }],
    };
    let spec = ImageSpec {
        is_64: false,
        little_endian: le,
        cpu_type: CPU_TYPE_POWERPC,
        cpu_subtype: 0,
        file_type: MH_EXECUTE,
        flags: 0,
        commands: vec![
            segment(&text, false, le),
            unix_thread(
                le,
                PPC_THREAD_STATE,
                PPC_THREAD_STATE_COUNT,
                0,
                0x1A40,
                false,
            ),
            version_min(
                le,
                LC_VERSION_MIN_MACOSX,
                version(10, 4, 0),
                version(10, 4, 11),
            ),
        ],
    };
    let mut data = image(&spec);
    // `blr` (0x4E800020), big-endian.
    place(&mut data, 0x1000, &0x4E80_0020u32.to_be_bytes().repeat(64));
    place(&mut data, 0x1FFF, &[0]);
    data
}

#[test]
fn big_endian_powerpc_image_reads_32_bit_segments_and_thread_entry() {
    let data = powerpc_executable();
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(p.primary.bitwidth, 32);
    assert_primary_from_header(&p, &data);
    assert_note(
        &p,
        "Entry point 0x1A40 (LC_UNIXTHREAD PPC_THREAD_STATE program counter)",
    );
    assert_note(
        &p,
        "Platform macOS (LC_VERSION_MIN_MACOSX); minimum OS 10.4; SDK 10.4.11",
    );
    assert_note(&p, "Extensions scanned in 1 instruction section (256 B)");
    assert_eq!(
        custom(&p, "macho_section_0").map(|m| m.value.to_string()),
        Some("vm 0x2000; file 0x1000; 256 B; flags 0x80000400; instructions".to_string())
    );
    assert_eq!(
        generic(&p, &MetadataKey::EntryPoint),
        Some("0x1A40".to_string())
    );
}

/// A 64-bit executable in byte order `le` of `cpu_type` with one `__TEXT`
/// segment (file 0..0x2000) holding `__text` (`code` at 0x1000) and an
/// `LC_UNIXTHREAD` of `flavor`.
fn thread_executable(
    le: bool,
    cpu_type: u32,
    flavor: u32,
    count: usize,
    pc_offset: usize,
    pc: u64,
) -> Vec<u8> {
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0x10_0000,
        vm_size: 0x2000,
        file_offset: 0,
        file_size: 0x2000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x10_1000,
            size: 0x40,
            offset: 0x1000,
            flags: CODE,
        }],
    };
    let spec = ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type,
        cpu_subtype: 0,
        file_type: MH_EXECUTE,
        flags: 0,
        commands: vec![
            segment(&text, true, le),
            unix_thread(le, flavor, count, pc_offset, pc, true),
        ],
    };
    let mut data = image(&spec);
    place(&mut data, 0x1000, &aarch64_code(16));
    place(&mut data, 0x1FFF, &[0]);
    data
}

#[test]
fn unix_thread_program_counters_are_read_per_cpu_type_and_flavor() {
    let x86 = classify(&thread_executable(
        true,
        CPU_TYPE_X86_64,
        X86_THREAD_STATE64,
        X86_THREAD_STATE64_COUNT,
        128,
        0x10_1000,
    ));
    assert_eq!(x86.primary.isa, Isa::X86_64);
    assert_note(
        &x86,
        "Entry point 0x101000 (LC_UNIXTHREAD x86_THREAD_STATE64 program counter)",
    );
    let arm64 = classify(&thread_executable(
        true,
        CPU_TYPE_ARM64,
        ARM_THREAD_STATE64,
        ARM_THREAD_STATE64_COUNT,
        256,
        0xFFFF_FFF0_0700_4000,
    ));
    assert_note(
        &arm64,
        "Entry point 0xFFFFFFF007004000 (LC_UNIXTHREAD ARM_THREAD_STATE64 program counter)",
    );
    // An x86-64 flavor in an arm64 image is not decoded.
    let mismatched = classify(&thread_executable(
        true,
        CPU_TYPE_ARM64,
        X86_THREAD_STATE64,
        X86_THREAD_STATE64_COUNT,
        128,
        0x1000,
    ));
    assert_eq!(mismatched.primary.isa, Isa::AArch64);
    assert_note(
        &mismatched,
        "LC_UNIXTHREAD thread state flavor 4 is not decoded for this CPU type; entry point not read",
    );
    assert_eq!(generic(&mismatched, &MetadataKey::EntryPoint), None);
    let powerpc64 = classify(&thread_executable(
        false,
        CPU_TYPE_POWERPC64,
        PPC_THREAD_STATE64,
        PPC_THREAD_STATE64_COUNT,
        0,
        0x1_0000_1000,
    ));
    assert_eq!(powerpc64.primary.isa, Isa::Ppc64);
    assert_eq!(powerpc64.primary.endianness, Endianness::Big);
    assert_note(
        &powerpc64,
        "Entry point 0x100001000 (LC_UNIXTHREAD PPC_THREAD_STATE64 program counter)",
    );
    assert_note(
        &powerpc64,
        "Extensions scanned in 1 instruction section (64 B)",
    );
}

/// 32-bit little-endian ARMv7 iOS executable whose `__text` (256 B at
/// 0x1000) lies in the `LC_ENCRYPTION_INFO` range (0x1000, 4096 B, cryptid
/// 1): `LC_SEGMENT` `__TEXT` (file 0..0x2000 at 0x4000),
/// `LC_UNIXTHREAD` `ARM_THREAD_STATE` with `pc` 0x5000, and
/// `LC_VERSION_MIN_IPHONEOS` 6.0.
fn encrypted_arm_executable(cryptid: u32) -> Vec<u8> {
    let le = true;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0x4000,
        vm_size: 0x2000,
        file_offset: 0,
        file_size: 0x2000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x5000,
            size: 0x100,
            offset: 0x1000,
            flags: CODE,
        }],
    };
    let spec = ImageSpec {
        is_64: false,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM,
        cpu_subtype: CPU_SUBTYPE_ARM_V7,
        file_type: MH_EXECUTE,
        flags: MH_PIE,
        commands: vec![
            segment(&text, false, le),
            unix_thread(
                le,
                ARM_THREAD_STATE,
                ARM_THREAD_STATE_COUNT,
                60,
                0x5000,
                false,
            ),
            version_min(
                le,
                LC_VERSION_MIN_IPHONEOS,
                version(6, 0, 0),
                version(6, 1, 0),
            ),
            encryption(le, false, 0x1000, 0x1000, cryptid),
        ],
    };
    let mut data = image(&spec);
    place(&mut data, 0x1000, &[0x5A; 0x1000]);
    data
}

#[test]
fn encrypted_instruction_bytes_are_left_out_of_extension_detection() {
    let encrypted = classify(&encrypted_arm_executable(1));
    assert_eq!(encrypted.primary.isa, Isa::Arm);
    assert_eq!(
        encrypted.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv7")
    );
    assert_note(
        &encrypted,
        "Encrypted range at 0x1000, 4096 B (LC_ENCRYPTION_INFO cryptid 1); left out of extension detection",
    );
    assert_note(
        &encrypted,
        "Extensions scanned in 1 instruction section (0 B); 256 B encrypted and left out",
    );
    assert_note(
        &encrypted,
        "Entry point 0x5000 (LC_UNIXTHREAD ARM_THREAD_STATE program counter)",
    );
    assert_note(
        &encrypted,
        "Platform iOS (LC_VERSION_MIN_IPHONEOS); minimum OS 6.0; SDK 6.1",
    );
    assert_eq!(code_extensions(&encrypted), Vec::<String>::new());
    assert_eq!(
        custom_text(&encrypted, "macho_encryption"),
        "cryptid 1; file 0x1000; 4096 B"
    );

    let plain = classify(&encrypted_arm_executable(0));
    assert_note(
        &plain,
        "LC_ENCRYPTION_INFO cryptid 0: the range is not encrypted",
    );
    assert_note(
        &plain,
        "Extensions scanned in 1 instruction section (256 B)",
    );
}

/// A 64-bit little-endian arm64 dylib with only `LC_BUILD_VERSION`
/// records for `platforms`.
fn platform_image(platforms: &[u32]) -> Vec<u8> {
    let le = true;
    let commands = platforms
        .iter()
        .map(|&platform| build_version(le, platform, version(17, 0, 0), 0, &[]))
        .collect();
    image(&ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_DYLIB,
        flags: 0,
        commands,
    })
}

#[test]
fn build_versions_name_simulator_driverkit_vision_and_unknown_platforms() {
    let p = classify(&platform_image(&[
        PLATFORM_IOSSIMULATOR,
        PLATFORM_DRIVERKIT,
        PLATFORM_XROS,
        99,
    ]));
    assert_note(
        &p,
        "Platform iOS Simulator (LC_BUILD_VERSION); minimum OS 17.0",
    );
    assert_note(&p, "Platform DriverKit (LC_BUILD_VERSION); minimum OS 17.0");
    assert_note(&p, "Platform visionOS (LC_BUILD_VERSION); minimum OS 17.0");
    assert_note(
        &p,
        "Platform 0x63 (not a known PLATFORM_* value) (LC_BUILD_VERSION); minimum OS 17.0",
    );
    assert_eq!(custom_text(&p, "macho_platform"), "iOS Simulator");
    assert_eq!(custom_text(&p, "macho_platform_1"), "DriverKit");
    assert_eq!(custom_text(&p, "macho_platform_2"), "visionOS");
    assert_eq!(custom_text(&p, "macho_min_os_3"), "17.0");
    assert!(
        custom(&p, "macho_sdk").is_none(),
        "an SDK of 0 is not reported"
    );

    // A zippered Mac Catalyst library carries two records.
    let zippered = classify(&platform_image(&[PLATFORM_MACOS, PLATFORM_MACCATALYST]));
    assert_eq!(custom_text(&zippered, "macho_platform"), "macOS");
    assert_eq!(custom_text(&zippered, "macho_platform_1"), "Mac Catalyst");
    assert_note(
        &zippered,
        "No instruction section has stored bytes; no code is scanned for extensions",
    );
}

// The clang-built fixtures (tests/fixtures/macho/README.md).

/// `__text` of `hello-x86_64`: file offset 0x340, 0x41E B (`otool -l`).
const X86_TEXT_OFFSET: usize = 0x340;
const X86_TEXT_SIZE: usize = 0x41E;

#[test]
fn clang_x86_64_executable_reports_its_build_and_scans_its_text() {
    let data = fixture("hello-x86_64.gz");
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::MachO);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_primary_from_header(&p, &data);
    assert_note(
        &p,
        "Platform macOS (LC_BUILD_VERSION); minimum OS 10.15; SDK 27.2",
    );
    assert_note(&p, "Entry point 0x1000006A0 (LC_MAIN file offset 0x6A0)");
    assert_note(
        &p,
        &format!("Extensions scanned in 1 instruction section ({X86_TEXT_SIZE} B)"),
    );
    assert_eq!(
        custom_text(&p, "macho_uuid"),
        "AF8030DB-A967-39E2-B3ED-CB22EAC1D7A6"
    );
    // The code-pattern extensions are exactly those of `__text`.
    let text = &data[X86_TEXT_OFFSET..X86_TEXT_OFFSET + X86_TEXT_SIZE];
    let format_derived: Vec<String> = p
        .extensions
        .iter()
        .filter(|e| e.source == ExtensionSource::FormatAttribute)
        .map(|e| e.name.clone())
        .collect();
    let expected: Vec<String> = names(&zrax::extensions::detect_from_code(
        text,
        Isa::X86_64,
        Endianness::Little,
    ))
    .into_iter()
    .filter(|name| !format_derived.contains(name))
    .collect();
    assert!(expected.contains(&"AVX2".to_string()), "{expected:?}");
    assert_eq!(code_extensions(&p), expected);
}

/// A 64-bit x86-64 executable whose `__text` is 16 `ret`s at 0x1000 and
/// whose `__DATA,__const` (0x2000) holds the AVX2 code of
/// `hello-x86_64`'s `__text`.
fn code_in_data_section() -> Vec<u8> {
    let le = true;
    let hello = fixture("hello-x86_64.gz");
    let avx2 = &hello[X86_TEXT_OFFSET..X86_TEXT_OFFSET + X86_TEXT_SIZE];
    let size = avx2.len() as u64;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0x1_0000_0000,
        vm_size: 0x2000,
        file_offset: 0,
        file_size: 0x2000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x1_0000_1000,
            size: 16,
            offset: 0x1000,
            flags: CODE,
        }],
    };
    let data_segment = SegmentSpec {
        name: "__DATA",
        vm_address: 0x1_0000_2000,
        vm_size: 0x1000,
        file_offset: 0x2000,
        file_size: 0x1000,
        protection: VM_PROT_RW,
        sections: vec![SectionSpec {
            name: "__const",
            segment: "__DATA",
            address: 0x1_0000_2000,
            size,
            offset: 0x2000,
            flags: S_REGULAR,
        }],
    };
    let mut data = image(&ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_X86_64,
        cpu_subtype: CPU_SUBTYPE_X86_64_ALL,
        file_type: MH_EXECUTE,
        flags: 0,
        commands: vec![segment(&text, true, le), segment(&data_segment, true, le)],
    });
    place(&mut data, 0x1000, &[X86_RET; 16]);
    place(&mut data, 0x2000, avx2);
    place(&mut data, 0x2FFF, &[0]);
    data
}

#[test]
fn code_outside_instruction_sections_supplies_no_extensions() {
    let data = code_in_data_section();
    // Scanning the whole file would find the AVX2 code in `__DATA`.
    let whole = names(&zrax::extensions::detect_from_code(
        &data,
        Isa::X86_64,
        Endianness::Little,
    ));
    assert!(whole.contains(&"AVX2".to_string()), "{whole:?}");
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_note(&p, "Extensions scanned in 1 instruction section (16 B)");
    assert!(
        !code_extensions(&p).contains(&"AVX2".to_string()),
        "{:?}",
        p.extensions
    );
}

#[test]
fn clang_arm64_executable_reports_signature_fixups_and_entry() {
    let data = fixture("hello-arm64.gz");
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_primary_from_header(&p, &data);
    assert_note(
        &p,
        "MH_EXECUTE; 16 load commands (744 B); 3 segments, 2 sections",
    );
    assert_note(
        &p,
        "Platform macOS (LC_BUILD_VERSION); minimum OS 12.0; SDK 27.2",
    );
    assert_note(&p, "Entry point 0x100000554 (LC_MAIN file offset 0x554)");
    assert_note(
        &p,
        "Code signature present (LC_CODE_SIGNATURE at 0x4120, 280 B); not verified",
    );
    assert_note(
        &p,
        "Chained fixups present (LC_DYLD_CHAINED_FIXUPS at 0x4000, 56 B)",
    );
    assert_note(&p, "Extensions scanned in 1 instruction section (616 B)");
    assert_eq!(
        custom_text(&p, "macho_uuid"),
        "DCB4CF0B-F814-38AE-AE23-A8C9FF0C7F49"
    );
}

#[test]
fn clang_object_has_one_unnamed_segment_with_its_text() {
    let data = fixture("hello-arm64.o.gz");
    assert_eq!(&data[12..16], &MH_OBJECT.to_le_bytes(), "filetype");
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_note(
        &p,
        "MH_OBJECT; 4 load commands (360 B); 1 segment, 2 sections",
    );
    assert_note(&p, "Extensions scanned in 1 instruction section (616 B)");
    let segment = custom(&p, "macho_segment_0").expect("the object's segment");
    assert_eq!(segment.label, "(unnamed)");
    assert_eq!(
        segment.value.to_string(),
        "vm 0x0, 744 B; file 0x188, 744 B; rwx/rwx; 2 sections"
    );
    assert_eq!(
        custom(&p, "macho_section_1").map(|m| m.label.clone()),
        Some("__LD,__compact_unwind".to_string())
    );
}

/// A fat binary (`fat_header`, big-endian: `magic`, `nfat_arch`; then 20 B
/// `fat_arch` records: `cputype`, `cpusubtype`, `offset`, `size`, `align`)
/// holding `slices` at 16 KiB-aligned offsets.
fn fat(slices: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut header = Writer::new(false);
    header
        .u32(FAT_MAGIC)
        .u32(u32::try_from(slices.len()).expect("few slices"));
    let mut offset = 0x4000usize;
    let mut placed = Vec::new();
    for &(cpu_type, cpu_subtype, bytes) in slices {
        header
            .u32(cpu_type)
            .u32(cpu_subtype)
            .u32(u32::try_from(offset).expect("small fat"))
            .u32(u32::try_from(bytes.len()).expect("small slice"))
            .u32(14);
        placed.push(offset);
        offset = (offset + bytes.len() + 0x3FFF) & !0x3FFF;
    }
    let mut data = header.take();
    for (&at, &(_, _, bytes)) in placed.iter().zip(slices) {
        place(&mut data, at, bytes);
    }
    data
}

#[test]
fn fat_slices_scan_their_own_text_and_the_first_slice_adds_its_notes() {
    let x86 = fixture("hello-x86_64.gz");
    let arm64 = fixture("hello-arm64.gz");
    let data = fat(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, &x86),
        (CPU_TYPE_ARM64, 0, &arm64),
    ]);
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::MachOFat);
    assert_eq!(p.primary.isa, Isa::X86_64);
    assert_eq!(p.slices.len(), 2);
    assert_eq!(p.slices[0].isa, Isa::X86_64);
    assert_eq!(p.slices[1].isa, Isa::AArch64);
    assert!(p.slices[0]
        .extensions
        .iter()
        .any(|e| e.name == "AVX2" && e.source == ExtensionSource::CodePattern));
    assert!(p.slices[1].extensions.iter().all(|e| e.name != "AVX2"));
    assert_note(&p, "Universal binary containing 2 architectures");
    assert_note(
        &p,
        "First slice: Platform macOS (LC_BUILD_VERSION); minimum OS 10.15; SDK 27.2",
    );
    assert_note(
        &p,
        &format!("First slice: Extensions scanned in 1 instruction section ({X86_TEXT_SIZE} B)"),
    );
    assert_eq!(custom_text(&p, "macho_platform"), "macOS");
    assert!(code_extensions(&p).contains(&"AVX2".to_string()));
}

// MH_FILESET.

/// Load commands of fileset entry `com.apple.kernel`: an arm64e
/// `MH_EXECUTE` with `MH_DYLIB_IN_CACHE` whose `__TEXT` maps file
/// 0x4000..0x6000 (fileset coordinates) at 0xFFFF_FFF0_0700_4000, with
/// `__text` (64 B of `ret` at 0x5000) and an `ARM_THREAD_STATE64` entry
/// there.
fn kernel_entry_spec() -> ImageSpec {
    let le = true;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0xFFFF_FFF0_0700_4000,
        vm_size: 0x2000,
        file_offset: 0x4000,
        file_size: 0x2000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0xFFFF_FFF0_0700_5000,
            size: 0x40,
            offset: 0x5000,
            flags: CODE,
        }],
    };
    ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: CPU_SUBTYPE_ARM64E,
        file_type: MH_EXECUTE,
        flags: MH_DYLIB_IN_CACHE | MH_PIE,
        commands: vec![
            segment(&text, true, le),
            unix_thread(
                le,
                ARM_THREAD_STATE64,
                ARM_THREAD_STATE64_COUNT,
                256,
                0xFFFF_FFF0_0700_5000,
                true,
            ),
        ],
    }
}

/// Load commands of fileset entry `com.example.driver`: an x86-64
/// `MH_KEXT_BUNDLE` with `MH_DYLIB_IN_CACHE` whose `__TEXT` maps file
/// 0x8000..0x9000 with `__text` (`code` at 0x8800, fileset coordinates).
/// A real kernel collection holds one architecture; the second ISA shows
/// that each entry is classified from its own header.
fn driver_entry_spec(code_size: u64) -> ImageSpec {
    let le = true;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0xFFFF_FFF0_0700_8000,
        vm_size: 0x1000,
        file_offset: 0x8000,
        file_size: 0x1000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0xFFFF_FFF0_0700_8800,
            size: code_size,
            offset: 0x8800,
            flags: CODE,
        }],
    };
    ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_X86_64,
        cpu_subtype: CPU_SUBTYPE_X86_64_ALL,
        file_type: MH_KEXT_BUNDLE,
        flags: MH_DYLIB_IN_CACHE,
        commands: vec![segment(&text, true, le)],
    }
}

/// A synthetic `MH_FILESET` (arm64, 0x9000 B): its own `__TEXT` (file
/// 0..0x4000) and `__TEXT_EXEC` (file 0x4000..0x9000, no sections),
/// `LC_UUID`, and two `LC_FILESET_ENTRY` commands, `com.apple.kernel` at
/// file 0x4000 and `com.example.driver` at 0x8000; then the entries'
/// headers and code at those offsets. The driver's `__text` is the AVX2
/// code of `hello-x86_64`.
fn fileset() -> Vec<u8> {
    let le = true;
    let hello = fixture("hello-x86_64.gz");
    let driver_code = &hello[X86_TEXT_OFFSET..X86_TEXT_OFFSET + X86_TEXT_SIZE];
    let own_text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0xFFFF_FFF0_0700_0000,
        vm_size: 0x4000,
        file_offset: 0,
        file_size: 0x4000,
        protection: VM_PROT_R,
        sections: Vec::new(),
    };
    let exec = SegmentSpec {
        name: "__TEXT_EXEC",
        vm_address: 0xFFFF_FFF0_0700_4000,
        vm_size: 0x5000,
        file_offset: 0x4000,
        file_size: 0x5000,
        protection: VM_PROT_RX,
        sections: Vec::new(),
    };
    let mut data = image(&ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_FILESET,
        flags: 0,
        commands: vec![
            segment(&own_text, true, le),
            segment(&exec, true, le),
            uuid_command(le, [0xAB; 16]),
            fileset_entry(le, 0xFFFF_FFF0_0700_4000, 0x4000, "com.apple.kernel"),
            fileset_entry(le, 0xFFFF_FFF0_0700_8000, 0x8000, "com.example.driver"),
        ],
    });
    place(&mut data, 0x4000, &image(&kernel_entry_spec()));
    place(&mut data, 0x5000, &aarch64_code(16));
    place(
        &mut data,
        0x8000,
        &image(&driver_entry_spec(driver_code.len() as u64)),
    );
    place(&mut data, 0x8800, driver_code);
    place(&mut data, 0x8FFF, &[0]);
    data
}

/// Bytes of a 64-bit header and its load commands.
fn commands_size(spec: &ImageSpec) -> u64 {
    32 + spec.commands.iter().map(|c| c.len() as u64).sum::<u64>()
}

#[test]
fn fileset_entries_are_children_classified_from_their_own_headers() {
    let data = fileset();
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::MachO);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.primary.variant, None);
    assert_primary_from_header(&p, &data);
    assert_eq!(p.slices.len(), 2, "{:#?}", p.slices);

    let kernel = &p.slices[0];
    assert_eq!(kernel.label.as_deref(), Some("com.apple.kernel"));
    assert_eq!(kernel.isa, Isa::AArch64);
    assert_eq!(
        kernel.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv8.3+ (PAC)")
    );
    assert_eq!(kernel.offset, 0x4000);
    assert_eq!(kernel.size, commands_size(&kernel_entry_spec()));

    let driver = &p.slices[1];
    assert_eq!(driver.label.as_deref(), Some("com.example.driver"));
    assert_eq!(driver.isa, Isa::X86_64);
    assert_eq!(driver.offset, 0x8000);
    assert_eq!(
        driver.size,
        commands_size(&driver_entry_spec(X86_TEXT_SIZE as u64))
    );
    // The driver's own `__text`, read in fileset coordinates, is scanned
    // with its own ISA.
    assert!(
        driver
            .extensions
            .iter()
            .any(|e| e.name == "AVX2" && e.source == ExtensionSource::CodePattern),
        "{:?}",
        driver.extensions
    );

    // The primary extensions are the kernel entry's (arm64e, so PAC).
    assert!(p.extensions.iter().any(|e| e.name == "PAC"));
    assert!(p.extensions.iter().all(|e| e.name != "AVX2"));
    assert_note(
        &p,
        "MH_FILESET; 5 load commands (280 B); 2 segments, 0 sections",
    );
    assert_note(&p, "2 fileset entries (LC_FILESET_ENTRY)");
    assert_note_containing(&p, "Fileset entries are classified from their own headers");
    let entry = custom(&p, "macho_fileset_entry_0").expect("entry listed");
    assert_eq!(entry.label, "com.apple.kernel");
    assert_eq!(
        entry.value.to_string(),
        "vm 0xFFFFFFF007004000; file 0x4000"
    );
    assert_eq!(
        custom_text(&p, "macho_fileset_entry_1"),
        "vm 0xFFFFFFF007008000; file 0x8000"
    );
}

#[test]
fn fileset_entries_parse_in_fileset_coordinates() {
    let data = fileset();
    let fileset = macho::parse_image(&data).expect("fileset parses");
    assert!(fileset.header.is_fileset());
    assert_eq!(fileset.fileset.len(), 2);
    let kernel = macho::parse_fileset_entry(&data, &fileset.fileset[0]).expect("entry parses");
    assert_eq!(kernel.header.offset, 0x4000);
    assert!(kernel.offsets_in_input);
    assert_eq!(kernel.entry_address(), Some(0xFFFF_FFF0_0700_5000));
    let code = kernel
        .code(&data)
        .expect("fileset coordinates locate the code");
    assert_eq!(&code.bytes[..], &aarch64_code(16)[..]);
    // Read on its own, the in-cache entry's offsets do not locate its code.
    let alone = macho::parse_image(&data[0x4000..]).expect("entry header parses alone");
    assert!(!alone.offsets_in_input);
    assert!(alone.code(&data[0x4000..]).is_none());
}

#[test]
fn damaged_fileset_entries_are_warned_about_and_not_listed() {
    let le = true;
    let mut data = image(&ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_FILESET,
        flags: 0,
        commands: vec![
            fileset_entry(le, 0x4000, 0x4000, "com.apple.kernel"),
            fileset_entry(le, 0x9000, 0x9_0000, "com.example.missing"),
            fileset_entry(le, 0, 0, "com.example.self"),
        ],
    });
    place(&mut data, 0x4000, &image(&kernel_entry_spec()));
    place(&mut data, 0x5000, &aarch64_code(16));
    place(&mut data, 0x5FFF, &[0]);
    let p = classify(&data);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.slices.len(), 1);
    assert_note(
        &p,
        "1 of 3 fileset entries start past the end of the input (24576 B) and are not classified; \
         the first is com.example.missing at 0x90000",
    );
    assert_note(
        &p,
        "com.example.self: ISA unknown (Mach-O parse error: Invalid fileset entry com.example.self: file offset 0x0)",
    );
}

#[test]
fn an_in_cache_image_read_on_its_own_scans_the_whole_input_as_before() {
    let mut spec = arm64_executable_spec();
    spec.flags |= MH_DYLIB_IN_CACHE;
    let mut data = image(&spec);
    place(&mut data, 0x1000, &aarch64_code(16));
    place(&mut data, 0x50FF, &[0]);
    let p = classify(&data);
    assert_note_containing(&p, "MH_DYLIB_IN_CACHE: the image's file offsets refer to");
    assert!(!notes(&p)
        .iter()
        .any(|n| n.starts_with("Extensions scanned")));
    assert_eq!(generic(&p, &MetadataKey::CodeSize), None);
}

#[test]
fn a_dsym_without_section_bytes_scans_no_code() {
    let le = true;
    let text = SegmentSpec {
        name: "__TEXT",
        vm_address: 0x1_0000_0000,
        vm_size: 0x4000,
        file_offset: 0,
        file_size: 0,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x1_0000_1000,
            size: 0x100,
            offset: 0x1000,
            flags: CODE,
        }],
    };
    let mut data = image(&ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_DSYM,
        flags: 0,
        commands: vec![segment(&text, true, le)],
    });
    place(&mut data, 0x1000, &aarch64_code(64));
    let p = classify(&data);
    assert_note(&p, "MH_DSYM; 1 load command (152 B); 1 segment, 1 section");
    assert_note(
        &p,
        "No instruction section has stored bytes; no code is scanned for extensions",
    );
    assert_eq!(code_extensions(&p), Vec::<String>::new());
}

#[test]
fn a_truncated_file_notes_segments_past_its_end_and_scans_what_is_present() {
    let data = arm64_executable();
    let cut = &data[..0x1020];
    let p = classify(cut);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_note(
        &p,
        "Segment __TEXT (file 0x0, 16384 B) and 2 more extend past the end of the input (4128 B)",
    );
    assert_note(
        &p,
        "Extensions scanned in 1 instruction section (32 B); 32 B past the end of the input left out",
    );
    assert_note(
        &p,
        "Code signature present (LC_CODE_SIGNATURE at 0x5040, 192 B; extends past the end of the input); not verified",
    );
}

#[test]
fn repeated_and_conflicting_commands_keep_the_first() {
    let le = true;
    let spec = ImageSpec {
        is_64: true,
        little_endian: le,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_EXECUTE,
        flags: 0,
        commands: vec![
            uuid_command(le, [1; 16]),
            uuid_command(le, [2; 16]),
            main_command(le, 0x40),
            unix_thread(
                le,
                ARM_THREAD_STATE64,
                ARM_THREAD_STATE64_COUNT,
                256,
                0x1000,
                true,
            ),
        ],
    };
    let p = classify(&image(&spec));
    assert_note(&p, "Duplicate LC_UUID at 0x38 (load command 1) ignored");
    assert_note(
        &p,
        "Duplicate LC_UNIXTHREAD at 0x68 (load command 3) ignored",
    );
    assert_note(&p, "LC_MAIN file offset 0x40 lies in no segment");
    assert_eq!(
        custom_text(&p, "macho_uuid"),
        "01010101-0101-0101-0101-010101010101"
    );
}

/// A 64-bit arm64 executable whose single load command is `command`, with
/// `sizeofcmds` and `ncmds` as given.
fn one_command(command: &[u8], ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
    let mut data = image(&ImageSpec {
        is_64: true,
        little_endian: true,
        cpu_type: CPU_TYPE_ARM64,
        cpu_subtype: 0,
        file_type: MH_EXECUTE,
        flags: 0,
        commands: vec![command.to_vec()],
    });
    data[16..20].copy_from_slice(&ncmds.to_le_bytes());
    data[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    data
}

#[test]
fn corrupted_load_commands_are_reported_and_leave_the_header_result() {
    let le = true;
    let uuid = uuid_command(le, [0; 16]);
    let mut small_uuid = uuid.clone();
    small_uuid[4..8].copy_from_slice(&16u32.to_le_bytes());
    let mut tiny = uuid.clone();
    tiny[4..8].copy_from_slice(&4u32.to_le_bytes());
    let mut unaligned = uuid.clone();
    unaligned[4..8].copy_from_slice(&22u32.to_le_bytes());
    let mut long = uuid.clone();
    long[4..8].copy_from_slice(&32u32.to_le_bytes());
    let mut nsects = segment(&arm64_text_segment(), true, le);
    nsects[64..68].copy_from_slice(&2u32.to_le_bytes());
    let mut tools = build_version(le, PLATFORM_MACOS, version(14, 0, 0), 0, &[TOOL_LD]);
    tools[20..24].copy_from_slice(&5u32.to_le_bytes());
    let mut unterminated = fileset_entry(le, 0, 0x4000, "com.apple.kernel");
    let id_end = unterminated.len();
    unterminated[32..id_end].fill(b'x');
    let mut id_offset = fileset_entry(le, 0, 0x4000, "com.apple.kernel");
    id_offset[24..28].copy_from_slice(&8u32.to_le_bytes());
    let mut thread = unix_thread(
        le,
        ARM_THREAD_STATE64,
        ARM_THREAD_STATE64_COUNT,
        256,
        0,
        true,
    );
    thread[12..16].copy_from_slice(&100u32.to_le_bytes());

    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            one_command(&uuid, 1, 4096),
            "Truncated load commands: sizeofcmds 4096 B at 0x20 exceeds the input (56 B)",
        ),
        (
            one_command(&uuid, 4, 24),
            "Invalid ncmds 4: sizeofcmds 24 B holds at most 3 load commands",
        ),
        (
            one_command(&uuid, 2, 24),
            "Truncated load command 1 at 0x38: extends past sizeofcmds",
        ),
        (
            one_command(&small_uuid, 1, 24),
            "Invalid LC_UUID at 0x20: cmdsize 16 B is smaller than its 24 B structure",
        ),
        (
            one_command(&tiny, 1, 24),
            "Invalid load command 0 at 0x20: cmdsize 4 B is smaller than 8 B",
        ),
        (
            one_command(&unaligned, 1, 24),
            "Invalid load command 0 at 0x20: cmdsize 22 B is not a multiple of 4",
        ),
        (
            one_command(&long, 1, 24),
            "Invalid load command 0 at 0x20: cmdsize 32 B extends past sizeofcmds",
        ),
        (
            one_command(&nsects, 1, nsects.len() as u32),
            "Invalid LC_SEGMENT_64 at 0x20: cmdsize 152 B does not match nsects 2",
        ),
        (
            one_command(&tools, 1, tools.len() as u32),
            "Invalid LC_BUILD_VERSION at 0x20: ntools 5 does not fit cmdsize 32 B",
        ),
        (
            one_command(&unterminated, 1, unterminated.len() as u32),
            "Invalid LC_FILESET_ENTRY at 0x20: entry_id is not NUL-terminated",
        ),
        (
            one_command(&id_offset, 1, id_offset.len() as u32),
            "Invalid LC_FILESET_ENTRY at 0x20: entry_id offset 8 is outside the 56 B command",
        ),
        (
            one_command(&thread, 1, thread.len() as u32),
            "Truncated LC_UNIXTHREAD at 0x20: flavor 6 count 100 extends past cmdsize 288 B",
        ),
    ];
    for (data, message) in cases {
        let p = classify(&data);
        assert_eq!(p.primary.isa, Isa::AArch64, "{message}");
        assert_primary_from_header(&p, &data);
        let expected = format!(
            "Mach-O load commands not read (Mach-O parse error: {message}); extensions are scanned in the whole file"
        );
        assert_note(&p, &expected);
        assert!(p
            .notes
            .iter()
            .any(|n| n.message == expected && n.level == zrax::NoteLevel::Warning));
        assert!(custom(&p, "macho_file_type").is_none(), "{message}");
    }
}

/// A `__TEXT` segment with one `__text` section, as in [`arm64_executable_spec`].
fn arm64_text_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT",
        vm_address: 0x1_0000_0000,
        vm_size: 0x4000,
        file_offset: 0,
        file_size: 0x4000,
        protection: VM_PROT_RX,
        sections: vec![SectionSpec {
            name: "__text",
            segment: "__TEXT",
            address: 0x1_0000_1000,
            size: 0x40,
            offset: 0x1000,
            flags: CODE,
        }],
    }
}

/// Every fixture of this file.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("arm64 executable", arm64_executable()),
        ("PowerPC executable", powerpc_executable()),
        ("encrypted ARM executable", encrypted_arm_executable(1)),
        ("fileset", fileset()),
        ("code in data", code_in_data_section()),
        ("clang x86-64", fixture("hello-x86_64.gz")),
        ("clang object", fixture("hello-arm64.o.gz")),
    ]
}

/// Default options without the raw-input transform search, which only
/// slows the sweeps down: extension detection stays on.
fn sweep_options() -> ClassifierOptions {
    ClassifierOptions {
        try_transforms: false,
        ..ClassifierOptions::new()
    }
}

/// The ISA the header of `data` names, if `data` has a known Mach-O header.
fn header_isa(data: &[u8]) -> Option<Isa> {
    let header = macho::Header::read(data, 0).ok()?;
    let (isa, _, _) = macho::cpu_type_to_isa(header.cpu_type, header.cpu_subtype);
    (!matches!(isa, Isa::Unknown(_))).then_some(isa)
}

#[test]
fn truncated_images_keep_the_header_isa_and_list_only_entries_inside() {
    for (name, data) in fixtures() {
        for end in 0..data.len() {
            let prefix = &data[..end];
            let Ok(p) = detect_payload(prefix, &sweep_options()) else {
                continue;
            };
            if p.format.format != FileFormat::MachO {
                continue;
            }
            if let Some(isa) = header_isa(prefix) {
                assert_eq!(p.primary.isa, isa, "{name} cut at {end}");
            }
            for slice in &p.slices {
                assert!(
                    slice.offset + slice.size <= end as u64,
                    "{name} cut at {end}"
                );
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic_and_never_change_the_header_isa() {
    for (name, data) in fixtures() {
        let commands_end = macho::Header::read(&data, 0)
            .map(|h| usize::try_from(h.size_with_commands()).expect("small"))
            .expect("fixture header");
        let positions: Vec<usize> = (0..commands_end)
            .chain((commands_end..data.len()).step_by(61))
            .collect();
        for pos in positions {
            for value in [0x00, 0xFF, data[pos] ^ (1 << (pos % 8))] {
                let mut mutated = data.clone();
                mutated[pos] = value;
                let Ok(p) = detect_payload(&mutated, &sweep_options()) else {
                    continue;
                };
                if p.format.format != FileFormat::MachO {
                    continue;
                }
                if let Some(isa) = header_isa(&mutated) {
                    assert_eq!(p.primary.isa, isa, "{name} byte {pos} = 0x{value:02X}");
                }
            }
        }
    }
}

// Real samples, read in place and never committed.

/// The two x86-64 kernel collections among IDA Pro's test inputs, when
/// `IDA_INPUT_DIR` names them: each kext is a slice classified from its own
/// header and instruction sections.
#[test]
fn ida_kernel_collections_list_their_entries_when_provided() {
    let Ok(dir) = std::env::var("IDA_INPUT_DIR") else {
        eprintln!("IDA_INPUT_DIR not set; skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    // Name, entries, first entry ID and its file offset.
    let collections = [
        (
            "pc_kernelcache_osx_11_0_64.macho",
            220,
            "com.apple.kernel",
            0xC000,
        ),
        (
            "pc_kernelcache_osx_11_0_aux_64.macho",
            14,
            "com.vmware.kext.vmioplug.18.7.0",
            0x2_0000,
        ),
    ];
    for (name, entries, first, offset) in collections {
        let path = dir.join(name);
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("{} not found; skipped", path.display());
            continue;
        };
        let p = classify(&data);
        assert_eq!(p.format.format, FileFormat::MachO, "{name}");
        assert_eq!(p.primary.isa, Isa::X86_64, "{name}");
        assert_primary_from_header(&p, &data);
        assert_eq!(p.slices.len(), entries, "{name}");
        assert_eq!(p.slices[0].label.as_deref(), Some(first), "{name}");
        assert_eq!(p.slices[0].offset, offset, "{name}");
        assert!(p.slices.iter().all(|s| s.isa == Isa::X86_64), "{name}");
        assert_note(&p, &format!("{entries} fileset entries (LC_FILESET_ENTRY)"));
    }
    let Ok(data) = std::fs::read(dir.join("pc_kernelcache_osx_11_0_64.macho")) else {
        return;
    };
    let p = classify(&data);
    assert_note(
        &p,
        "Entry point 0xFFFFFF8000100000 (LC_UNIXTHREAD x86_THREAD_STATE64 program counter)",
    );
    let corecrypto = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("com.apple.kec.corecrypto"))
        .expect("corecrypto is an entry");
    assert!(corecrypto
        .extensions
        .iter()
        .any(|e| e.name == "AES-NI" && e.source == ExtensionSource::CodePattern));
}

/// The Mach-O and fat files of a directory of this machine, when
/// `MACHO_HOST_DIR` names one (such as `/usr/bin`), read in place: the
/// primary ISA and every slice's ISA stay those of the headers.
#[test]
fn host_binaries_keep_their_header_isa_when_provided() {
    let Ok(dir) = std::env::var("MACHO_HOST_DIR") else {
        eprintln!("MACHO_HOST_DIR not set; skipped");
        return;
    };
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("MACHO_HOST_DIR is a directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    let mut checked = 0;
    for path in entries.into_iter().take(400) {
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        if data.len() < 32 {
            continue;
        }
        let Ok(p) = detect_payload(&data, &sweep_options()) else {
            continue;
        };
        match p.format.format {
            FileFormat::MachO => {
                if let Some(isa) = header_isa(&data) {
                    assert_eq!(p.primary.isa, isa, "{}", path.display());
                }
                assert_primary_from_header(&p, &data);
            }
            FileFormat::MachOFat => {
                let fat_isas: Vec<Isa> = macho::parse_fat_all(&data, false)
                    .expect("fat header parses")
                    .iter()
                    .map(|e| e.classification.isa)
                    .collect();
                let slice_isas: Vec<Isa> = p.slices.iter().map(|s| s.isa).collect();
                assert_eq!(slice_isas, fat_isas, "{}", path.display());
                assert_eq!(p.primary.isa, fat_isas[0], "{}", path.display());
            }
            _ => continue,
        }
        checked += 1;
    }
    eprintln!("{checked} Mach-O and fat files checked in {dir}");
}
