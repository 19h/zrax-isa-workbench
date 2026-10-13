//! Kernel crash dumps: the `DUMP_HEADER32` (4 KiB) or `DUMP_HEADER64`
//! (8 KiB) that starts a `PAGEDUMP` or `PAGEDU64` file.
//!
//! Field order and types come from the Win32 metadata (`windows-rs`
//! 0.58.0, `#[repr(C)]`); the offsets follow from C layout and match QEMU
//! v8.2.0 `win_dump_defs.h` for the 64-bit header:
//! - 32-bit: `MajorVersion` (8), `MinorVersion` (0xC), `MachineImageType`
//!   (0x20), `NumberProcessors` (0x24), `BugCheckCode` (0x28), four u32
//!   `BugCheckParameter`s (0x2C), `DumpType` (0xF88),
//!   `RequiredDumpSpace` (0xFA0).
//! - 64-bit: the same version fields, `MachineImageType` (0x30),
//!   `NumberProcessors` (0x34), `BugCheckCode` (0x38), four u64
//!   `BugCheckParameter`s (0x40), `DumpType` (0xF98),
//!   `RequiredDumpSpace` (0xFA0).
//!
//! What follows the header (physical memory runs, a bitmap or triage data,
//! depending on `DumpType`) is listed as one opaque component: physical
//! pages are not mapped to modules, so no byte of it is known to be code.

use super::*;
use crate::formats::coff;
use crate::formats::container::Child;
use crate::types::MetadataValue;

/// Where one header layout keeps the fields the classifier reports.
struct HeaderLayout {
    /// Header size in bytes.
    size: usize,
    machine_image_type: usize,
    number_processors: usize,
    bug_check_code: usize,
    bug_check_parameters: usize,
    /// Size of each bug check parameter in bytes.
    parameter_size: usize,
    dump_type: usize,
    required_dump_space: usize,
}

const HEADER32: HeaderLayout = HeaderLayout {
    size: 0x1000,
    machine_image_type: 0x20,
    number_processors: 0x24,
    bug_check_code: 0x28,
    bug_check_parameters: 0x2c,
    parameter_size: 4,
    dump_type: 0xf88,
    required_dump_space: 0xfa0,
};

const HEADER64: HeaderLayout = HeaderLayout {
    size: 0x2000,
    machine_image_type: 0x30,
    number_processors: 0x34,
    bug_check_code: 0x38,
    bug_check_parameters: 0x40,
    parameter_size: 8,
    dump_type: 0xf98,
    required_dump_space: 0xfa0,
};

/// `MajorVersion` and `MinorVersion`, common to both layouts.
const MAJOR_VERSION: usize = 0x08;
const MINOR_VERSION: usize = 0x0c;

/// Number of `BugCheckParameter` fields.
const BUG_CHECK_PARAMETERS: usize = 4;

/// `DUMP_TYPE` values (Win32 metadata). 0 is `DUMP_TYPE_UNKNOWN` and
/// 0xFFFFFFFF (-1) `DUMP_TYPE_INVALID`.
const DUMP_TYPES: &[(u32, &str)] = &[
    (0, "unknown"),
    (1, "full"),
    (2, "summary"),
    (3, "header"),
    (4, "triage"),
    (5, "bitmap full"),
    (6, "bitmap kernel"),
    (7, "automatic"),
    (0xffff_ffff, "invalid"),
];

fn header_layout(layout: Layout) -> &'static HeaderLayout {
    match layout {
        Layout::KernelDump64 => &HEADER64,
        _ => &HEADER32,
    }
}

/// The header fields the classifier reports.
struct KernelHeader {
    major_version: u32,
    minor_version: u32,
    machine: u32,
    processors: u32,
    bug_check_code: u32,
    bug_check_parameters: [u64; BUG_CHECK_PARAMETERS],
    dump_type: u32,
    required_dump_space: u64,
}

/// Parse a kernel crash dump header.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let fields = header_layout(layout);
    let reader = Reader {
        data,
        big_endian: false,
    };
    let header = read_header(reader, layout, fields)?;
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.target = machine_target(header.machine);
    report(&mut c, &header, data.len());
    let body = &data[fields.size..];
    if !body.is_empty() {
        c.children.push(Child::opaque(
            "Dump data after the header",
            fields.size,
            body,
        ));
    }
    Ok(c)
}

fn read_header(reader: Reader<'_>, layout: Layout, fields: &HeaderLayout) -> Result<KernelHeader> {
    reader.bytes(0, fields.size, "kernel dump header")?;
    let valid_dump = if layout == Layout::KernelDump64 {
        KERNEL_VALID_DUMP64
    } else {
        KERNEL_VALID_DUMP32
    };
    if &reader.field::<4>(0)? != KERNEL_SIGNATURE || &reader.field::<4>(4)? != valid_dump {
        return Err(error("Invalid kernel dump signature"));
    }
    let mut bug_check_parameters = [0u64; BUG_CHECK_PARAMETERS];
    for (i, parameter) in bug_check_parameters.iter_mut().enumerate() {
        let at = fields.bug_check_parameters + i * fields.parameter_size;
        *parameter = if fields.parameter_size == 8 {
            reader.u64(at)?
        } else {
            u64::from(reader.u32(at)?)
        };
    }
    Ok(KernelHeader {
        major_version: reader.u32(MAJOR_VERSION)?,
        minor_version: reader.u32(MINOR_VERSION)?,
        machine: reader.u32(fields.machine_image_type)?,
        processors: reader.u32(fields.number_processors)?,
        bug_check_code: reader.u32(fields.bug_check_code)?,
        bug_check_parameters,
        dump_type: reader.u32(fields.dump_type)?,
        required_dump_space: reader.u64(fields.required_dump_space)?,
    })
}

/// The architecture `MachineImageType` names, read as an
/// `IMAGE_FILE_MACHINE_*` value through the PE machine table.
fn machine_target(machine: u32) -> Option<Target> {
    let machine = u16::try_from(machine).ok()?;
    let (isa, bits, endianness, _) = coff::machine_to_isa(machine);
    (!matches!(isa, Isa::Unknown(_))).then(|| Target::new(isa, bits, endianness))
}

fn dump_type_name(dump_type: u32) -> Option<&'static str> {
    DUMP_TYPES
        .iter()
        .find(|(id, _)| *id == dump_type)
        .map(|(_, name)| *name)
}

/// Notes and metadata for the header.
fn report(c: &mut Container<'_>, header: &KernelHeader, file_size: usize) {
    let machine = header.machine;
    let description = u16::try_from(machine).map_or("unknown", coff::machine_description);
    c.notes.push(format!(
        "MachineImageType 0x{machine:X} ({description}); {}",
        count(to_usize(header.processors), "processor", "processors")
    ));
    if c.target.is_none() {
        c.notes.push(format!(
            "MachineImageType 0x{machine:X} names no architecture in the PE machine table; the ISA is not determined"
        ));
    }
    let parameters: Vec<String> = header
        .bug_check_parameters
        .iter()
        .map(|p| format!("0x{p:X}"))
        .collect();
    c.notes.push(format!(
        "Bug check 0x{:08X} ({})",
        header.bug_check_code,
        parameters.join(", ")
    ));
    let dump_type = header.dump_type;
    c.notes.push(match dump_type_name(dump_type) {
        Some(name) => format!("Dump type {dump_type} ({name})"),
        None => format!("Dump type 0x{dump_type:X} is not a DUMP_TYPE value"),
    });
    if header.required_dump_space > to_u64(file_size) {
        c.notes.push(format!(
            "RequiredDumpSpace is {} B; the file holds {file_size} B",
            header.required_dump_space
        ));
    }
    c.notes.push(
        "Physical memory after the header is not mapped to modules and is not analyzed".into(),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_kernel_version"),
        "Header version (major.minor)",
        format!("{}.{}", header.major_version, header.minor_version),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_machine_image_type"),
        "MachineImageType",
        MetadataValue::Hex(machine),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_processors"),
        "Processors",
        u64::from(header.processors),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_bug_check_code"),
        "Bug check code",
        MetadataValue::Hex(header.bug_check_code),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_bug_check_parameters"),
        "Bug check parameters",
        parameters.join(", "),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_dump_type"),
        "Dump type",
        u64::from(dump_type),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_required_dump_space"),
        "RequiredDumpSpace (B)",
        header.required_dump_space,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_end_at_their_header_size() {
        for fields in [&HEADER32, &HEADER64] {
            let last = fields.required_dump_space + 8;
            assert!(last <= fields.size);
            let parameters_end =
                fields.bug_check_parameters + BUG_CHECK_PARAMETERS * fields.parameter_size;
            assert!(parameters_end <= fields.size);
        }
        assert_eq!(header_layout(Layout::KernelDump64).size, 0x2000);
        assert_eq!(header_layout(Layout::KernelDump32).size, 0x1000);
    }

    #[test]
    fn machine_types_map_through_the_pe_table() {
        assert_eq!(machine_target(0x8664).map(|t| t.isa), Some(Isa::X86_64));
        assert_eq!(machine_target(0x014c).map(|t| t.isa), Some(Isa::X86));
        assert_eq!(machine_target(0xaa64).map(|t| t.isa), Some(Isa::AArch64));
        assert!(machine_target(0).is_none());
        assert!(machine_target(0x4547_4150).is_none());
        assert_eq!(dump_type_name(1), Some("full"));
        assert_eq!(dump_type_name(0x4547_4150), None);
    }
}
