//! 65816 native-mode instructions, for telling W65C816 code from 6502 code:
//! the 65816 runs the 6502 instruction set and adds a native mode with
//! 16-bit registers, long addressing and new instructions ("W65C816S 8/16-bit
//! Microprocessor" data sheet, Western Design Center, opcode matrix).
//!
//! Native-mode code enters the mode with `CLC; XCE` and sets the register
//! widths with `REP`/`SEP` of the `M` and `X` flags. The 6502 executes none
//! of these as such: on the NMOS 6502, `0xC2` and `0xE2` are undocumented
//! two-byte NOPs and `0xFB` is the undocumented `ISC abs,Y`; on the 65C02 all
//! three are NOPs. Counting them at instruction starts of a linear decode
//! keeps operand bytes out (`LDA $C2` followed by `JSR` holds `C2 20`).

/// `REP #imm`, `SEP #imm` and `XCE`.
const REP: u8 = 0xC2;
const SEP: u8 = 0xE2;
const XCE: u8 = 0xFB;
/// `CLC` and `SEC`, which set the carry `XCE` exchanges with the
/// emulation flag.
const CLC: u8 = 0x18;
const SEC: u8 = 0x38;
/// Processor status flags `M` (accumulator width) and `X` (index width).
const FLAG_M: u8 = 0x20;
const FLAG_X: u8 = 0x10;

/// Length in bytes of the instruction with opcode `op`, with 8-bit
/// accumulator and index registers (emulation mode, and the 6502's own
/// lengths for the opcodes the two share). Columns of the opcode matrix by
/// low nibble: implied and accumulator 1; direct page, its indexed and
/// indirect forms, stack-relative and branches 2; absolute 3; long 4.
fn length(op: u8) -> usize {
    match (op & 0x0F, op) {
        (0x8 | 0xA | 0xB, _) => 1,
        (0x0, 0x40 | 0x60) => 1,         // RTI, RTS
        (0x0, 0x20) => 3,                // JSR abs
        (0x2, 0x22) => 4,                // JSL long
        (0x2, 0x62 | 0x82) => 3,         // PER, BRL
        (0x4, 0x44 | 0x54 | 0xF4) => 3,  // MVP, MVN, PEA
        (0x9, _) if op & 0x10 != 0 => 3, // abs,Y
        (0xC, 0x5C) => 4,                // JML long
        (0xC..=0xE, _) => 3,
        (0xF, _) => 4,
        _ => 2,
    }
}

/// Native-mode instructions in a linear decode of `code`, and the
/// instructions counted (bytes `0x00` and `0xFF` are not: fill, `BRK`).
pub(crate) struct NativeModeCount {
    /// `REP`/`SEP` of only the `M` and `X` flags, and `XCE` after `CLC` or
    /// `SEC`.
    pub(crate) native: u32,
    /// Instructions counted.
    pub(crate) instructions: u32,
}

/// Count native-mode instructions in a linear decode of `code`.
pub(crate) fn native_mode_count(code: &[u8]) -> NativeModeCount {
    let mut count = NativeModeCount {
        native: 0,
        instructions: 0,
    };
    let mut at = 0;
    let mut previous = None;
    while at < code.len() {
        let op = code[at];
        if !matches!(op, 0x00 | 0xFF) {
            count.instructions += 1;
        }
        let is_width_change = matches!(op, REP | SEP)
            && code
                .get(at + 1)
                .is_some_and(|&flags| flags != 0 && flags & !(FLAG_M | FLAG_X) == 0);
        let is_mode_switch = op == XCE && matches!(previous, Some(CLC | SEC));
        count.native += u32::from(is_width_change || is_mode_switch);
        previous = Some(op);
        at += length(op);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_mode_code_is_counted_at_instruction_starts() {
        // CLC; XCE; REP #$30; LDA $1234; SEP #$20; RTL
        let code = [0x18, 0xFB, 0xC2, 0x30, 0xAD, 0x34, 0x12, 0xE2, 0x20, 0x6B];
        let count = native_mode_count(&code);
        assert_eq!(count.native, 3);
    }

    #[test]
    fn operands_and_other_flags_are_not_native_mode() {
        // LDA $C2; JSR $8211; SEP #$08 (decimal flag); XCE without CLC/SEC; RTS
        let code = [0xA5, 0xC2, 0x20, 0x11, 0x82, 0xE2, 0x08, 0xEA, 0xFB, 0x60];
        let count = native_mode_count(&code);
        assert_eq!(count.native, 0);
        assert_eq!(count.instructions, 6);
        assert_eq!(native_mode_count(&[]).instructions, 0);
    }
}
