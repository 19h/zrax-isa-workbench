//! `LC_UNIXTHREAD`: the initial thread state and its program counter.
//!
//! `thread_command` is `cmd` and `cmdsize`, then repeated `flavor` (4),
//! `count` (4, in 32-bit words) and `count` words of state, as xnu
//! `load_threadstate` walks them. The state layouts are cctools
//! `include/mach/{i386,arm,ppc}/_structs.h`; only flavors whose program
//! counter field is listed in [`PC_FIELDS`] are decoded.

use super::commands::Command;
use super::*;

/// `flavor` and `count` before each state.
const STATE_HEADER_SIZE: usize = 8;

/// `cmd` and `cmdsize`.
const THREAD_COMMAND_SIZE: usize = 8;

/// Thread-state flavors (`thread_status.h`).
const X86_THREAD_STATE32: u32 = 1;
const X86_THREAD_STATE64: u32 = 4;
const ARM_THREAD_STATE: u32 = 1;
const ARM_THREAD_STATE64: u32 = 6;
const PPC_THREAD_STATE: u32 = 1;
const PPC_THREAD_STATE64: u32 = 5;

/// Where a thread state keeps the program counter.
struct PcField {
    /// `cputype` the flavor belongs to.
    cpu_type: u32,
    /// Thread-state flavor.
    flavor: u32,
    /// The flavor's `thread_status.h` name.
    name: &'static str,
    /// Byte offset of the program counter in the state.
    offset: usize,
    /// The program counter is 8 bytes (otherwise 4).
    wide: bool,
}

/// Program counters: `eip` after 10 words of `x86_thread_state32`, `rip`
/// after 16 quadwords of `x86_thread_state64`, `pc` after `r[13]`, `sp` and
/// `lr` of `arm_thread_state`, `pc` after `x[29]`, `fp`, `lr` and `sp` of
/// `arm_thread_state64`, and `srr0` first in both PowerPC states.
const PC_FIELDS: &[PcField] = &[
    PcField {
        cpu_type: cpu_type::X86,
        flavor: X86_THREAD_STATE32,
        name: "x86_THREAD_STATE32",
        offset: 40,
        wide: false,
    },
    PcField {
        cpu_type: cpu_type::X86_64,
        flavor: X86_THREAD_STATE64,
        name: "x86_THREAD_STATE64",
        offset: 128,
        wide: true,
    },
    PcField {
        cpu_type: cpu_type::ARM,
        flavor: ARM_THREAD_STATE,
        name: "ARM_THREAD_STATE",
        offset: 60,
        wide: false,
    },
    PcField {
        cpu_type: cpu_type::ARM64,
        flavor: ARM_THREAD_STATE64,
        name: "ARM_THREAD_STATE64",
        offset: 256,
        wide: true,
    },
    PcField {
        cpu_type: cpu_type::POWERPC,
        flavor: PPC_THREAD_STATE,
        name: "PPC_THREAD_STATE",
        offset: 0,
        wide: false,
    },
    PcField {
        cpu_type: cpu_type::POWERPC64,
        flavor: PPC_THREAD_STATE64,
        name: "PPC_THREAD_STATE64",
        offset: 0,
        wide: true,
    },
];

/// Read an `LC_UNIXTHREAD`: walk its states and take the program counter
/// of the first one decoded for `cpu_type`. Every state must fit `cmdsize`.
pub(super) fn read_unix_thread(command: &Command<'_>, cpu_type: u32) -> Result<Entry> {
    let bytes = command.bytes;
    let mut pos = THREAD_COMMAND_SIZE;
    let mut first_flavor = None;
    let mut decoded = None;
    while pos < bytes.len() {
        if bytes.len() - pos < STATE_HEADER_SIZE {
            return Err(error(format!(
                "Truncated LC_UNIXTHREAD at 0x{:X}: thread state header at +0x{pos:X} extends past cmdsize",
                command.offset
            )));
        }
        let flavor = command.u32_at(pos)?;
        let count = command.u32_at(pos + 4)?;
        let state_start = pos + STATE_HEADER_SIZE;
        let state = (count as usize)
            .checked_mul(4)
            .and_then(|size| state_start.checked_add(size))
            .and_then(|end| bytes.get(state_start..end))
            .ok_or_else(|| {
                error(format!(
                    "Truncated LC_UNIXTHREAD at 0x{:X}: flavor {flavor} count {count} extends past cmdsize {} B",
                    command.offset,
                    bytes.len()
                ))
            })?;
        first_flavor.get_or_insert(flavor);
        if decoded.is_none() {
            decoded = program_counter(state, cpu_type, flavor, command.little_endian)?;
        }
        pos = state_start + state.len();
    }
    let flavor = first_flavor.ok_or_else(|| {
        error(format!(
            "Invalid LC_UNIXTHREAD at 0x{:X}: no thread state",
            command.offset
        ))
    })?;
    Ok(Entry::Thread {
        flavor,
        address: decoded.as_ref().map(|pc| pc.address),
        flavor_name: decoded.map(|pc| pc.name),
    })
}

/// A decoded program counter and the flavor it came from.
struct DecodedPc {
    address: u64,
    name: &'static str,
}

/// The program counter of `state` when its flavor is listed for
/// `cpu_type` and the state is long enough to hold it.
fn program_counter(
    state: &[u8],
    cpu_type: u32,
    flavor: u32,
    le: bool,
) -> Result<Option<DecodedPc>> {
    let Some(field) = PC_FIELDS
        .iter()
        .find(|f| f.cpu_type == cpu_type && f.flavor == flavor)
    else {
        return Ok(None);
    };
    let size = if field.wide { 8 } else { 4 };
    if state.len() < field.offset + size {
        return Ok(None);
    }
    let address = if field.wide {
        read_u64(state, field.offset, le)?
    } else {
        u64::from(read_u32(state, field.offset, le)?)
    };
    Ok(Some(DecodedPc {
        address,
        name: field.name,
    }))
}
