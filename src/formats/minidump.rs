//! Windows crash dumps: user-mode minidumps (`MDMP`, also byte-swapped as
//! Breakpad writes them on big-endian hosts) and kernel crash dumps
//! (`PAGEDUMP`, `PAGEDU64`).
//!
//! Sources (pinned revisions and checksums in `docs/minidump.md`):
//! - Microsoft Learn, `minidumpapiset.h` reference (MicrosoftDocs/sdk-api
//!   commit `656e9656`): `MINIDUMP_HEADER`, `MINIDUMP_DIRECTORY`,
//!   `MINIDUMP_STREAM_TYPE`, `MINIDUMP_LOCATION_DESCRIPTOR`, the thread,
//!   module and memory lists, `MINIDUMP_MEMORY64_LIST` (remarks: data
//!   follows `BaseRva` in descriptor order), `MINIDUMP_EXCEPTION_STREAM`,
//!   `MINIDUMP_SYSTEM_INFO` and `MINIDUMP_STRING`; `sysinfoapi.h`
//!   `SYSTEM_INFO` for `PROCESSOR_ARCHITECTURE_ARM64`.
//! - Microsoft Win32 metadata as generated into `windows-rs` 0.58.0
//!   (`Win32/System/Diagnostics/Debug`, `Win32/System/SystemInformation`):
//!   `MINIDUMP_VERSION`, the packed (4-byte) structure layouts,
//!   `PROCESSOR_ARCHITECTURE_*` 0-14, `DUMP_HEADER32`, `DUMP_HEADER64` and
//!   `DUMP_TYPE_*`.
//! - Google Breakpad v2024.02.16 `src/google_breakpad/common/minidump_format.h`
//!   (`MD_HEADER_SIGNATURE`, `MD_MODULE_SIZE`, the Breakpad-defined
//!   architectures 0x8001-0x8006) and `src/processor/minidump.cc` (the
//!   signature as byte-order marker, 4-byte list padding, duplicate
//!   streams).
//! - rust-minidump v0.22.0 `minidump-common/src/format.rs` and
//!   `minidump/src/minidump.rs` (byte-swapped dumps, the `Memory64List`
//!   reader).
//! - QEMU v8.2.0 `include/qemu/win_dump_defs.h` and `dump/win_dump.c`
//!   (the `PAGE`/`DUMP`/`DU64` signatures and the 64-bit header offsets).
//!
//! The format and the ISA are separate: `MINIDUMP_SYSTEM_INFO`'s
//! `ProcessorArchitecture` is the dump's own target field, and a kernel
//! dump's `MachineImageType` is read as an `IMAGE_FILE_MACHINE_*` value
//! (an assumption recorded in `docs/minidump.md`). Memory that lies inside
//! a listed module image goes to the code model under that target, unless
//! the module's PE headers are in the dump and place the range outside its
//! executable sections; that memory and every other range (stacks, heaps,
//! mapped data) is opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod image;
mod kernel;
mod regions;
mod streams;
mod user;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "minidump";

/// `MINIDUMP_SIGNATURE` as the first four bytes of a little-endian dump.
const MINIDUMP_MAGIC: &[u8; 4] = b"MDMP";

/// `MINIDUMP_SIGNATURE` stored byte-swapped: a big-endian dump.
const MINIDUMP_MAGIC_SWAPPED: &[u8; 4] = b"PMDM";

/// `MINIDUMP_VERSION`, the low word of the header's `Version`.
const MINIDUMP_VERSION: u16 = 0xa793;

/// Kernel dump `Signature` and the `ValidDump` values of the 32-bit and
/// 64-bit headers.
const KERNEL_SIGNATURE: &[u8; 4] = b"PAGE";
const KERNEL_VALID_DUMP32: &[u8; 4] = b"DUMP";
const KERNEL_VALID_DUMP64: &[u8; 4] = b"DU64";

/// A Windows crash dump layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// User-mode minidump with little-endian fields (`MDMP`).
    Minidump,
    /// User-mode minidump with big-endian fields: the signature reads
    /// byte-swapped (`PMDM`).
    MinidumpBigEndian,
    /// Kernel crash dump with the 4 KiB `DUMP_HEADER32` (`PAGEDUMP`).
    KernelDump32,
    /// Kernel crash dump with the 8 KiB `DUMP_HEADER64` (`PAGEDU64`).
    KernelDump64,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Minidump | Self::MinidumpBigEndian => FileFormat::Minidump,
            Self::KernelDump32 | Self::KernelDump64 => FileFormat::WindowsKernelDump,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Minidump => "MDMP, little-endian",
            Self::MinidumpBigEndian => "MDMP, big-endian",
            Self::KernelDump32 => "PAGEDUMP, 32-bit header",
            Self::KernelDump64 => "PAGEDU64, 64-bit header",
        }
    }

    /// Every layout carries a signature.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// Strong recognition: `MDMP` with the `MINIDUMP_VERSION` low word, the
/// same signature and version read big-endian, or the kernel dump
/// signatures `PAGEDUMP` and `PAGEDU64`. The structure is checked by the
/// parser, so a damaged dump is a parse error rather than raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let signature = data.get(..4)?;
    let second: [u8; 4] = data.get(4..8)?.try_into().ok()?;
    let version_le = u16::from_le_bytes([second[0], second[1]]);
    let version_be = u16::from_be_bytes([second[2], second[3]]);
    if signature == MINIDUMP_MAGIC && version_le == MINIDUMP_VERSION {
        return Some(Layout::Minidump);
    }
    if signature == MINIDUMP_MAGIC_SWAPPED && version_be == MINIDUMP_VERSION {
        return Some(Layout::MinidumpBigEndian);
    }
    if signature != KERNEL_SIGNATURE {
        return None;
    }
    match &second {
        KERNEL_VALID_DUMP32 => Some(Layout::KernelDump32),
        KERNEL_VALID_DUMP64 => Some(Layout::KernelDump64),
        _ => None,
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::MinidumpParseError`] for a truncated header,
/// directory, stream, string or memory range, a list whose size does not
/// match its count, a duplicate stream, or an address range that
/// overflows.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Minidump | Layout::MinidumpBigEndian => user::parse(data, layout),
        Layout::KernelDump32 | Layout::KernelDump64 => kernel::parse(data, layout),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::MinidumpParseError {
        message: message.into(),
    }
}

/// Bounds-checked reads in the dump's byte order. Offsets are file
/// offsets (minidump RVAs).
#[derive(Debug, Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    big_endian: bool,
}

impl<'a> Reader<'a> {
    /// The `len` bytes at `offset`; `what` names them in the error.
    fn bytes(self, offset: usize, len: usize, what: &str) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| error(format!("Invalid {what} range 0x{offset:X} + {len} B")))?;
        self.data
            .get(offset..end)
            .ok_or_else(|| error(format!("Truncated {what} at 0x{offset:X} + {len} B")))
    }

    /// The `N` bytes at `offset`, for a field of a record whose bounds the
    /// caller has checked.
    fn field<const N: usize>(self, offset: usize) -> Result<[u8; N]> {
        let bytes = self.bytes(offset, N, "field")?;
        Ok(bytes.try_into().expect("slice has exactly N bytes"))
    }

    fn u16(self, offset: usize) -> Result<u16> {
        let bytes = self.field(offset)?;
        Ok(if self.big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    }

    fn u32(self, offset: usize) -> Result<u32> {
        let bytes = self.field(offset)?;
        Ok(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    fn u64(self, offset: usize) -> Result<u64> {
        let bytes = self.field(offset)?;
        Ok(if self.big_endian {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        })
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

/// `"1 thread"`, `"2 threads"`.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// `MINIDUMP_SYSTEM_INFO.ProcessorArchitecture` values (`winnt.h` via the
/// Win32 metadata; 0x8001-0x8006 are Breakpad-defined).
const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_ARCHITECTURE_MIPS: u16 = 1;
const PROCESSOR_ARCHITECTURE_ALPHA: u16 = 2;
const PROCESSOR_ARCHITECTURE_PPC: u16 = 3;
const PROCESSOR_ARCHITECTURE_SHX: u16 = 4;
const PROCESSOR_ARCHITECTURE_ARM: u16 = 5;
const PROCESSOR_ARCHITECTURE_IA64: u16 = 6;
const PROCESSOR_ARCHITECTURE_ALPHA64: u16 = 7;
const PROCESSOR_ARCHITECTURE_MSIL: u16 = 8;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const PROCESSOR_ARCHITECTURE_IA32_ON_WIN64: u16 = 10;
const PROCESSOR_ARCHITECTURE_NEUTRAL: u16 = 11;
const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
const PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64: u16 = 13;
const PROCESSOR_ARCHITECTURE_IA32_ON_ARM64: u16 = 14;
const BREAKPAD_ARCHITECTURE_SPARC: u16 = 0x8001;
const BREAKPAD_ARCHITECTURE_PPC64: u16 = 0x8002;
const BREAKPAD_ARCHITECTURE_ARM64_OLD: u16 = 0x8003;
const BREAKPAD_ARCHITECTURE_MIPS64: u16 = 0x8004;
const BREAKPAD_ARCHITECTURE_RISCV: u16 = 0x8005;
const BREAKPAD_ARCHITECTURE_RISCV64: u16 = 0x8006;
const PROCESSOR_ARCHITECTURE_UNKNOWN: u16 = 0xffff;

/// One `ProcessorArchitecture` value, its name and the target it names.
/// No source states a code byte order per value, so it is fixed only where
/// the ISA fixes the instruction order and left to the code otherwise.
struct Architecture {
    id: u16,
    name: &'static str,
    target: Option<Target>,
}

/// An architecture that names a CPU.
const fn cpu(id: u16, name: &'static str, target: Target) -> Architecture {
    Architecture {
        id,
        name,
        target: Some(target),
    }
}

/// An architecture that names no CPU ISA.
const fn no_cpu(id: u16, name: &'static str) -> Architecture {
    Architecture {
        id,
        name,
        target: None,
    }
}

const fn little(isa: Isa, bits: u8) -> Target {
    Target::new(isa, bits, Endianness::Little)
}

const fn big(isa: Isa, bits: u8) -> Target {
    Target::new(isa, bits, Endianness::Big)
}

const fn open_order(isa: Isa, bits: u8) -> Target {
    Target::without_byte_order(isa, bits)
}

/// Every known `ProcessorArchitecture`. MSIL and the neutral architecture
/// name no CPU; `WoW64` and emulated x86 processes run x86 code.
const ARCHITECTURES: &[Architecture] = &[
    cpu(PROCESSOR_ARCHITECTURE_INTEL, "x86", little(Isa::X86, 32)),
    cpu(
        PROCESSOR_ARCHITECTURE_MIPS,
        "MIPS",
        open_order(Isa::Mips, 32),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_ALPHA,
        "Alpha",
        little(Isa::Alpha, 64),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_PPC,
        "PowerPC",
        open_order(Isa::Ppc, 32),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_SHX,
        "SuperH",
        open_order(Isa::Sh, 32),
    ),
    cpu(PROCESSOR_ARCHITECTURE_ARM, "ARM", open_order(Isa::Arm, 32)),
    cpu(PROCESSOR_ARCHITECTURE_IA64, "IA-64", little(Isa::Ia64, 64)),
    cpu(
        PROCESSOR_ARCHITECTURE_ALPHA64,
        "Alpha64",
        little(Isa::Alpha, 64),
    ),
    no_cpu(PROCESSOR_ARCHITECTURE_MSIL, "MSIL"),
    cpu(
        PROCESSOR_ARCHITECTURE_AMD64,
        "AMD64",
        little(Isa::X86_64, 64),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_IA32_ON_WIN64,
        "IA32 on Win64",
        little(Isa::X86, 32),
    ),
    no_cpu(PROCESSOR_ARCHITECTURE_NEUTRAL, "neutral"),
    cpu(
        PROCESSOR_ARCHITECTURE_ARM64,
        "ARM64",
        little(Isa::AArch64, 64),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64,
        "ARM32 on Win64",
        open_order(Isa::Arm, 32),
    ),
    cpu(
        PROCESSOR_ARCHITECTURE_IA32_ON_ARM64,
        "IA32 on ARM64",
        little(Isa::X86, 32),
    ),
    cpu(BREAKPAD_ARCHITECTURE_SPARC, "SPARC", big(Isa::Sparc, 32)),
    cpu(
        BREAKPAD_ARCHITECTURE_PPC64,
        "PPC64",
        open_order(Isa::Ppc64, 64),
    ),
    cpu(
        BREAKPAD_ARCHITECTURE_ARM64_OLD,
        "ARM64 (Breakpad)",
        little(Isa::AArch64, 64),
    ),
    cpu(
        BREAKPAD_ARCHITECTURE_MIPS64,
        "MIPS64",
        open_order(Isa::Mips64, 64),
    ),
    cpu(
        BREAKPAD_ARCHITECTURE_RISCV,
        "RISC-V",
        little(Isa::RiscV32, 32),
    ),
    cpu(
        BREAKPAD_ARCHITECTURE_RISCV64,
        "RISC-V 64",
        little(Isa::RiscV64, 64),
    ),
    no_cpu(PROCESSOR_ARCHITECTURE_UNKNOWN, "unknown"),
];

fn architecture_by_id(id: u16) -> Option<&'static Architecture> {
    ARCHITECTURES.iter().find(|a| a.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_signature_and_version_word() {
        assert_eq!(detect(b"MDMP\x93\xa7\x00\x00"), Some(Layout::Minidump));
        assert_eq!(
            detect(b"PMDM\x00\x00\xa7\x93"),
            Some(Layout::MinidumpBigEndian)
        );
        assert_eq!(detect(b"MDMP\x93\xa8\x00\x00"), None);
        assert_eq!(detect(b"PMDM\x93\xa7\x00\x00"), None);
        assert_eq!(detect(b"MDMP\x93\xa7"), None);
        assert_eq!(detect(b"PAGEDUMP"), Some(Layout::KernelDump32));
        assert_eq!(detect(b"PAGEDU64"), Some(Layout::KernelDump64));
        assert_eq!(detect(b"PAGEPAGE"), None);
    }

    #[test]
    fn layouts_report_their_format_and_strength() {
        assert_eq!(Layout::Minidump.format(), FileFormat::Minidump);
        assert_eq!(Layout::MinidumpBigEndian.format(), FileFormat::Minidump);
        assert_eq!(Layout::KernelDump32.format(), FileFormat::WindowsKernelDump);
        assert_eq!(Layout::KernelDump64.format(), FileFormat::WindowsKernelDump);
        for layout in [
            Layout::Minidump,
            Layout::MinidumpBigEndian,
            Layout::KernelDump32,
            Layout::KernelDump64,
        ] {
            assert!(!layout.is_weak());
        }
    }

    #[test]
    fn reader_follows_the_byte_order_and_names_truncation() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let le = Reader {
            data: &data,
            big_endian: false,
        };
        let be = Reader {
            data: &data,
            big_endian: true,
        };
        assert_eq!(le.u16(0).unwrap(), 0x0201);
        assert_eq!(be.u16(0).unwrap(), 0x0102);
        assert_eq!(le.u32(4).unwrap(), 0x0807_0605);
        assert_eq!(be.u64(0).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(
            le.bytes(6, 4, "stream").unwrap_err().to_string(),
            "Minidump parse error: Truncated stream at 0x6 + 4 B"
        );
        assert!(le.bytes(usize::MAX, 2, "stream").is_err());
    }

    #[test]
    fn architecture_ids_are_unique_and_unknowns_name_no_target() {
        for (i, a) in ARCHITECTURES.iter().enumerate() {
            assert!(
                ARCHITECTURES[..i].iter().all(|b| b.id != a.id),
                "{}",
                a.name
            );
        }
        let amd64 = architecture_by_id(PROCESSOR_ARCHITECTURE_AMD64).expect("AMD64");
        assert_eq!(amd64.target.map(|t| t.isa), Some(Isa::X86_64));
        assert!(
            architecture_by_id(PROCESSOR_ARCHITECTURE_UNKNOWN).is_some_and(|a| a.target.is_none())
        );
        assert!(architecture_by_id(0x1234).is_none());
    }
}
