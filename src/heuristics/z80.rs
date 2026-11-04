//! Z80 instruction lengths and prefix-group instructions, for telling Z80
//! code from 8080/8085 code: the Z80 executes the 8080 instruction set and
//! adds relative jumps, `DJNZ`, the alternate register set and the `CB`,
//! `ED`, `DD` and `FD` prefix groups ("Z80 CPU User Manual", Zilog UM0080,
//! opcode tables).
//!
//! Only the prefix groups are evidence. The 8085 executes an instruction at
//! every other Z80-only opcode: `RIM` (`0x20`) and `SIM` (`0x30`), and the
//! undocumented `DSUB` (`0x08`), `ARHL` (`0x10`), `RDEL` (`0x18`), `LDHI`
//! (`0x28`), `LDSI` (`0x38`) and `SHLX` (`0xD9`), which 8085 ROMs use: the
//! Toshiba T200 boot ROM holds 47 `RDEL`s. Its undocumented `RSTV`, `LHLX`,
//! `JNX5` and `JX5` sit at the prefix bytes themselves, so a prefix counts
//! only when the byte after it continues a defined Z80 instruction of its
//! group.

/// Prefix bytes of the Z80-only instruction groups.
const PREFIX_CB: u8 = 0xCB;
const PREFIX_ED: u8 = 0xED;
const PREFIX_IX: u8 = 0xDD;
const PREFIX_IY: u8 = 0xFD;

/// One instruction of a linear decode.
struct Instruction {
    /// Length in bytes.
    length: usize,
    /// Whether it is a prefix-group instruction with a defined second byte.
    is_prefix_group: bool,
}

/// Length in bytes of the unprefixed instruction with opcode `op`.
fn base_length(op: u8) -> usize {
    match op {
        // LD r,n; arithmetic with an immediate byte; JR and DJNZ;
        // OUT (n),A; IN A,(n)
        0x06 | 0x0E | 0x16 | 0x1E | 0x26 | 0x2E | 0x36 | 0x3E | 0xC6 | 0xCE | 0xD6 | 0xDE
        | 0xE6 | 0xEE | 0xF6 | 0xFE | 0x10 | 0x18 | 0x20 | 0x28 | 0x30 | 0x38 | 0xD3 | 0xDB => 2,
        // LD rr,nn; LD (nn),HL; LD HL,(nn); LD (nn),A; LD A,(nn); JP; CALL
        0x01 | 0x11 | 0x21 | 0x31 | 0x22 | 0x2A | 0x32 | 0x3A | 0xC2 | 0xC3 | 0xCA | 0xD2
        | 0xDA | 0xE2 | 0xEA | 0xF2 | 0xFA | 0xC4 | 0xCC | 0xCD | 0xD4 | 0xDC | 0xE4 | 0xEC
        | 0xF4 | 0xFC => 3,
        _ => 1,
    }
}

/// Whether unprefixed opcode `op` addresses memory through `(HL)`, which an
/// `IX`/`IY` prefix turns into `(IX+d)`/`(IY+d)` with a displacement byte.
fn uses_hl_indirect(op: u8) -> bool {
    matches!(
        op,
        0x34 | 0x35 | 0x36 | 0x46 | 0x4E | 0x56 | 0x5E | 0x66 | 0x6E | 0x7E
    ) || ((0x70..=0x77).contains(&op) && op != 0x76)
        || ((0x80..=0xBF).contains(&op) && op & 0x07 == 0x06)
}

/// Whether `second` after `ED` is a defined instruction: the `0x40`-`0x7F`
/// group (I/O through `C`, 16-bit `ADC`/`SBC`, `LD` with `I`/`R` and memory,
/// `NEG`, `RETN`, `RETI`, `IM`, `RRD`, `RLD`) or a block transfer, compare,
/// input or output instruction.
fn is_ed_instruction(second: u8) -> bool {
    matches!(second, 0x40..=0x7F | 0xA0..=0xA3 | 0xA8..=0xAB | 0xB0..=0xB3 | 0xB8..=0xBB)
}

/// Whether `second` after `DD`/`FD` is a documented index-register
/// instruction: an `(HL)` instruction made `(IX+d)`, `ADD IX,rr`,
/// `LD IX,nn`, `LD (nn),IX`, `LD IX,(nn)`, `INC`/`DEC IX`, `POP`/`PUSH IX`,
/// `EX (SP),IX`, `JP (IX)`, `LD SP,IX`, or the `CB` bit group.
fn is_index_instruction(second: u8) -> bool {
    uses_hl_indirect(second)
        || matches!(
            second,
            0x09 | 0x19
                | 0x29
                | 0x39
                | 0x21
                | 0x22
                | 0x2A
                | 0x23
                | 0x2B
                | 0xE1
                | 0xE3
                | 0xE5
                | 0xE9
                | 0xF9
                | PREFIX_CB
        )
}

/// The instruction at `at`.
fn decode(code: &[u8], at: usize) -> Instruction {
    let op = code[at];
    let next = code.get(at + 1).copied().unwrap_or(0);
    let (length, is_prefix_group) = match op {
        // ED 43/4B/53/5B/63/6B/73/7B: LD (nn),rr and LD rr,(nn)
        PREFIX_ED if next & 0xC7 == 0x43 => (4, true),
        // CB: bit operations, all 256 second bytes defined
        PREFIX_CB => (2, true),
        PREFIX_ED => (2, is_ed_instruction(next)),
        PREFIX_IX | PREFIX_IY if next == PREFIX_CB => (4, true),
        PREFIX_IX | PREFIX_IY => {
            let length = 1 + base_length(next) + usize::from(uses_hl_indirect(next));
            (length, is_index_instruction(next))
        }
        _ => (base_length(op), false),
    };
    Instruction {
        length,
        is_prefix_group,
    }
}

/// Share of the instructions in a linear decode of `code` that are Z80
/// prefix-group instructions; bytes `0x00` and `0xFF` (fill, `NOP`,
/// `RST 38h`) are not counted. 0 for no instructions.
pub(crate) fn prefix_group_share(code: &[u8]) -> f64 {
    let mut at = 0;
    let mut total = 0u32;
    let mut prefix_group = 0u32;
    while at < code.len() {
        let instruction = decode(code, at);
        if !matches!(code[at], 0x00 | 0xFF) {
            total += 1;
            prefix_group += u32::from(instruction.is_prefix_group);
        }
        at += instruction.length;
    }
    if total == 0 {
        0.0
    } else {
        f64::from(prefix_group) / f64::from(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eighty_eighty_code_has_no_prefix_group_instructions() {
        // LXI SP,F000h; MVI A,12h; CALL 0112h; MOV B,A; SHLD E089h; RET
        let code = [
            0x31, 0x00, 0xF0, 0x3E, 0x12, 0xCD, 0x12, 0x01, 0x47, 0x22, 0x89, 0xE0, 0xC9,
        ];
        assert!(prefix_group_share(&code).abs() < f64::EPSILON);
    }

    #[test]
    fn undocumented_8085_opcodes_are_not_z80_evidence() {
        // RIM; SIM; DSUB; ARHL; RDEL; LDHI 10h; LDSI 02h; SHLX; RET
        let code = [
            0x20, 0x30, 0x08, 0x10, 0x18, 0x28, 0x10, 0x38, 0x02, 0xD9, 0xC9,
        ];
        assert!(prefix_group_share(&code).abs() < f64::EPSILON);
        // LHLX followed by MVI A,1 and RET: ED 3E is no Z80 instruction.
        assert!(prefix_group_share(&[0xED, 0x3E, 0x01, 0xC9]).abs() < f64::EPSILON);
    }

    #[test]
    fn z80_code_is_recognized_by_its_prefix_groups() {
        // LD IX,4000h; LD A,(IX+5); DJNZ -2; LDIR; BIT 7,A; JR NZ,-4; RET
        let code = [
            0xDD, 0x21, 0x00, 0x40, 0xDD, 0x7E, 0x05, 0x10, 0xFE, 0xED, 0xB0, 0xCB, 0x7F, 0x20,
            0xFC, 0xC9,
        ];
        let share = prefix_group_share(&code);
        assert!((share - 4.0 / 7.0).abs() < 1e-9, "{share}");
        assert!(prefix_group_share(&[]).abs() < f64::EPSILON);
    }
}
