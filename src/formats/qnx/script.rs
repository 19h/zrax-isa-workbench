//! The boot script file (`union script_cmd` in `sys/image.h`, written by
//! mkxfs `parse_script_cmd` and listed by dumpifs `display_script`).
//!
//! Commands follow each other; each starts with a little-endian size pair
//! (`size_lo`, `size_hi`: the whole command, rounded up to four bytes), a
//! type and a spare byte. A size of zero or the end of the file ends the
//! script. The script is configuration, never code: it is summarized in a
//! note and its component is opaque.

use super::*;

/// Size of `struct script_hdr`: `size_lo`, `size_hi`, `type`, `spare`.
const SCRIPT_HDR_SIZE: usize = 4;

/// Command types (`SCRIPT_TYPE_*`).
const SCRIPT_TYPE_EXTERNAL: u8 = 0;
const SCRIPT_TYPE_WAITFOR: u8 = 1;
const SCRIPT_TYPE_REOPEN: u8 = 2;
const SCRIPT_TYPE_DISPLAY_MSG: u8 = 3;
const SCRIPT_TYPE_PROCMGR_SYMLINK: u8 = 4;
const SCRIPT_TYPE_EXTSCHED_APS: u8 = 5;

/// Offset of `args` in `struct script_external`: the command name, then
/// its arguments and environment strings.
const EXTERNAL_ARGS_OFFSET: usize = 12;

/// Program names quoted in the note before the rest are only counted.
const NOTE_PROGRAMS: usize = 8;

/// Longest program name quoted in a note.
const MAX_PROGRAM_NAME: usize = 64;

/// The command types in note order, with their buildfile names.
const COMMAND_NAMES: [(u8, &str); 6] = [
    (SCRIPT_TYPE_EXTERNAL, "external"),
    (SCRIPT_TYPE_WAITFOR, "waitfor"),
    (SCRIPT_TYPE_REOPEN, "reopen"),
    (SCRIPT_TYPE_DISPLAY_MSG, "display_msg"),
    (SCRIPT_TYPE_PROCMGR_SYMLINK, "procmgr_symlink"),
    (SCRIPT_TYPE_EXTSCHED_APS, "sched_aps"),
];

/// What the commands of a script are.
#[derive(Default)]
struct Summary {
    /// Commands per entry of [`COMMAND_NAMES`].
    counts: [usize; COMMAND_NAMES.len()],
    /// Commands of a type no source defines.
    unknown: usize,
    /// Names of the external programs, in order, up to [`NOTE_PROGRAMS`].
    programs: Vec<String>,
    /// External programs beyond [`NOTE_PROGRAMS`].
    more_programs: usize,
    /// Offset of a command whose size does not fit the script, if any.
    malformed_at: Option<usize>,
}

/// A one-line summary of the boot script `label`.
pub(super) fn summary(label: &str, script: &[u8]) -> String {
    let summary = walk(script);
    let total: usize = summary.counts.iter().sum::<usize>() + summary.unknown;
    let mut kinds: Vec<String> = COMMAND_NAMES
        .iter()
        .zip(summary.counts)
        .filter(|(_, count)| *count > 0)
        .map(|((_, name), count)| format!("{count} {name}"))
        .collect();
    if summary.unknown > 0 {
        kinds.push(format!("{} of unknown type", summary.unknown));
    }
    let counts = if kinds.is_empty() {
        format!("Boot script {label}: {total} commands")
    } else {
        format!(
            "Boot script {label}: {total} commands ({})",
            kinds.join(", ")
        )
    };
    let mut parts = vec![counts];
    if !summary.programs.is_empty() {
        let more = match summary.more_programs {
            0 => String::new(),
            n => format!(" and {n} more"),
        };
        parts.push(format!("programs: {}{more}", summary.programs.join(", ")));
    }
    if let Some(at) = summary.malformed_at {
        parts.push(format!(
            "command at 0x{at:X} does not fit the script, rest not decoded"
        ));
    }
    parts.join("; ")
}

/// Walk the commands of `script`. Every command is at least
/// [`SCRIPT_HDR_SIZE`] bytes, so the walk is bounded by the script size.
fn walk(script: &[u8]) -> Summary {
    let mut summary = Summary::default();
    let mut pos = 0;
    while pos < script.len() {
        // The size pair is little-endian in every target byte order.
        let Ok(size) = u16_at(script, pos, true) else {
            summary.malformed_at = Some(pos);
            break;
        };
        let size = usize::from(size);
        if size == 0 {
            break;
        }
        let command = slice(script, pos, size)
            .ok()
            .filter(|_| size >= SCRIPT_HDR_SIZE);
        let Some(command) = command else {
            summary.malformed_at = Some(pos);
            break;
        };
        let kind = command[2];
        match COMMAND_NAMES.iter().position(|(id, _)| *id == kind) {
            Some(index) => summary.counts[index] += 1,
            None => summary.unknown += 1,
        }
        if kind == SCRIPT_TYPE_EXTERNAL {
            record_program(&mut summary, command);
        }
        pos += size;
    }
    summary
}

/// Record the program an external command runs: the first string of its
/// `args`.
fn record_program(summary: &mut Summary, command: &[u8]) {
    let args = command.get(EXTERNAL_ARGS_OFFSET..).unwrap_or_default();
    let name = args.split(|b| *b == 0).next().unwrap_or_default();
    if name.is_empty() {
        return;
    }
    if summary.programs.len() >= NOTE_PROGRAMS {
        summary.more_programs += 1;
        return;
    }
    summary.programs.push(printable(name));
}

/// `name` as printable ASCII of at most [`MAX_PROGRAM_NAME`] characters,
/// other bytes replaced by `?`.
fn printable(name: &[u8]) -> String {
    name.iter()
        .take(MAX_PROGRAM_NAME)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One command: size pair, type, spare, then `body`, zero-padded to a
    /// multiple of four bytes.
    fn command(kind: u8, body: &[u8]) -> Vec<u8> {
        let size = round_up4(SCRIPT_HDR_SIZE + body.len()).unwrap();
        let [size_lo, size_hi] = u16::try_from(size).unwrap().to_le_bytes();
        let mut out = vec![size_lo, size_hi, kind, 0];
        out.extend_from_slice(body);
        out.resize(size, 0);
        out
    }

    /// An external command: cpu, flags, extsched, policy, priority, argc 1,
    /// envc 0, then the command and its argv[0].
    fn external(name: &str) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0, 0, 0, 1, 0];
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        command(SCRIPT_TYPE_EXTERNAL, &body)
    }

    #[test]
    fn commands_are_counted_by_type_and_programs_named() {
        let mut script = external("devc-ser8250");
        script.extend(command(SCRIPT_TYPE_WAITFOR, b"\x32\x00/dev/ser1\0"));
        script.extend(command(SCRIPT_TYPE_DISPLAY_MSG, b"hello\0"));
        script.extend(external("esh"));
        script.extend(command(9, b""));
        script.extend([0, 0, 0, 0]);
        assert_eq!(
            summary("/proc/boot/.script", &script),
            "Boot script /proc/boot/.script: 5 commands (2 external, 1 waitfor, \
             1 display_msg, 1 of unknown type); programs: devc-ser8250, esh"
        );
    }

    #[test]
    fn a_command_that_overruns_the_script_stops_the_walk() {
        let mut script = external("ls");
        script.extend([0x40, 0x00, SCRIPT_TYPE_EXTERNAL, 0]);
        let note = summary("s", &script);
        assert!(note.ends_with("command at 0x14 does not fit the script, rest not decoded"));
        assert!(summary("s", &[2, 0, 0, 0]).contains("does not fit"));
        assert!(summary("s", &[4, 0]).contains("does not fit"));
        assert_eq!(summary("s", b""), "Boot script s: 0 commands");
    }

    #[test]
    fn program_names_are_bounded_and_printable() {
        let mut script = Vec::new();
        for _ in 0..NOTE_PROGRAMS + 2 {
            script.extend(external("p\u{7}q"));
        }
        let note = summary("s", &script);
        assert!(note.contains("p?q, p?q"), "{note}");
        assert!(note.ends_with("and 2 more"), "{note}");
        assert_eq!(printable(&[b'a'; 100]).len(), MAX_PROGRAM_NAME);
    }
}
