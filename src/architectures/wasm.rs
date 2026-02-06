//! WebAssembly (WASM) bytecode analysis.
//!
//! WebAssembly is a stack-based virtual machine with a compact binary format.
//! Instructions are variable length with LEB128-encoded immediates.
//! The format is little-endian for numeric values.

/// WebAssembly opcode constants.
pub mod opcode {
    // Control flow
    /// Unreachable trap.
    pub const UNREACHABLE: u8 = 0x00;
    /// No operation.
    pub const NOP: u8 = 0x01;
    /// Begin block.
    pub const BLOCK: u8 = 0x02;
    /// Begin loop.
    pub const LOOP: u8 = 0x03;
    /// Begin if.
    pub const IF: u8 = 0x04;
    /// Else branch.
    pub const ELSE: u8 = 0x05;
    /// End block/loop/if/function.
    pub const END: u8 = 0x0B;
    /// Branch to label.
    pub const BR: u8 = 0x0C;
    /// Conditional branch.
    pub const BR_IF: u8 = 0x0D;
    /// Table branch.
    pub const BR_TABLE: u8 = 0x0E;
    /// Return from function.
    pub const RETURN: u8 = 0x0F;

    // Call operators
    /// Call function.
    pub const CALL: u8 = 0x10;
    /// Indirect call through table.
    pub const CALL_INDIRECT: u8 = 0x11;

    // Reference types (since WASM 2.0)
    /// Return call (tail call).
    pub const RETURN_CALL: u8 = 0x12;
    /// Return indirect call.
    pub const RETURN_CALL_INDIRECT: u8 = 0x13;

    // Parametric operators
    /// Drop top value.
    pub const DROP: u8 = 0x1A;
    /// Select value based on condition.
    pub const SELECT: u8 = 0x1B;
    /// Typed select.
    pub const SELECT_T: u8 = 0x1C;

    // Variable access
    /// Get local variable.
    pub const LOCAL_GET: u8 = 0x20;
    /// Set local variable.
    pub const LOCAL_SET: u8 = 0x21;
    /// Tee local variable (set and keep on stack).
    pub const LOCAL_TEE: u8 = 0x22;
    /// Get global variable.
    pub const GLOBAL_GET: u8 = 0x23;
    /// Set global variable.
    pub const GLOBAL_SET: u8 = 0x24;

    // Table access
    /// Get table element.
    pub const TABLE_GET: u8 = 0x25;
    /// Set table element.
    pub const TABLE_SET: u8 = 0x26;

    // Memory operators
    /// Load i32.
    pub const I32_LOAD: u8 = 0x28;
    /// Load i64.
    pub const I64_LOAD: u8 = 0x29;
    /// Load f32.
    pub const F32_LOAD: u8 = 0x2A;
    /// Load f64.
    pub const F64_LOAD: u8 = 0x2B;
    /// Load i32 from i8.
    pub const I32_LOAD8_S: u8 = 0x2C;
    /// Load i32 from u8.
    pub const I32_LOAD8_U: u8 = 0x2D;
    /// Load i32 from i16.
    pub const I32_LOAD16_S: u8 = 0x2E;
    /// Load i32 from u16.
    pub const I32_LOAD16_U: u8 = 0x2F;
    /// Load i64 from i8.
    pub const I64_LOAD8_S: u8 = 0x30;
    /// Load i64 from u8.
    pub const I64_LOAD8_U: u8 = 0x31;
    /// Load i64 from i16.
    pub const I64_LOAD16_S: u8 = 0x32;
    /// Load i64 from u16.
    pub const I64_LOAD16_U: u8 = 0x33;
    /// Load i64 from i32.
    pub const I64_LOAD32_S: u8 = 0x34;
    /// Load i64 from u32.
    pub const I64_LOAD32_U: u8 = 0x35;
    /// Store i32.
    pub const I32_STORE: u8 = 0x36;
    /// Store i64.
    pub const I64_STORE: u8 = 0x37;
    /// Store f32.
    pub const F32_STORE: u8 = 0x38;
    /// Store f64.
    pub const F64_STORE: u8 = 0x39;
    /// Store i32 as i8.
    pub const I32_STORE8: u8 = 0x3A;
    /// Store i32 as i16.
    pub const I32_STORE16: u8 = 0x3B;
    /// Store i64 as i8.
    pub const I64_STORE8: u8 = 0x3C;
    /// Store i64 as i16.
    pub const I64_STORE16: u8 = 0x3D;
    /// Store i64 as i32.
    pub const I64_STORE32: u8 = 0x3E;
    /// Get memory size.
    pub const MEMORY_SIZE: u8 = 0x3F;
    /// Grow memory.
    pub const MEMORY_GROW: u8 = 0x40;

    // Constants
    /// i32 constant.
    pub const I32_CONST: u8 = 0x41;
    /// i64 constant.
    pub const I64_CONST: u8 = 0x42;
    /// f32 constant.
    pub const F32_CONST: u8 = 0x43;
    /// f64 constant.
    pub const F64_CONST: u8 = 0x44;

    // Comparison operators (i32)
    /// i32 equal to zero.
    pub const I32_EQZ: u8 = 0x45;
    /// i32 equal.
    pub const I32_EQ: u8 = 0x46;
    /// i32 not equal.
    pub const I32_NE: u8 = 0x47;
    /// i32 less than (signed).
    pub const I32_LT_S: u8 = 0x48;
    /// i32 less than (unsigned).
    pub const I32_LT_U: u8 = 0x49;
    /// i32 greater than (signed).
    pub const I32_GT_S: u8 = 0x4A;
    /// i32 greater than (unsigned).
    pub const I32_GT_U: u8 = 0x4B;
    /// i32 less or equal (signed).
    pub const I32_LE_S: u8 = 0x4C;
    /// i32 less or equal (unsigned).
    pub const I32_LE_U: u8 = 0x4D;
    /// i32 greater or equal (signed).
    pub const I32_GE_S: u8 = 0x4E;
    /// i32 greater or equal (unsigned).
    pub const I32_GE_U: u8 = 0x4F;

    // Comparison operators (i64)
    /// i64 equal to zero.
    pub const I64_EQZ: u8 = 0x50;
    /// i64 equal.
    pub const I64_EQ: u8 = 0x51;
    /// i64 not equal.
    pub const I64_NE: u8 = 0x52;
    /// i64 less than (signed).
    pub const I64_LT_S: u8 = 0x53;
    /// i64 less than (unsigned).
    pub const I64_LT_U: u8 = 0x54;
    /// i64 greater than (signed).
    pub const I64_GT_S: u8 = 0x55;
    /// i64 greater than (unsigned).
    pub const I64_GT_U: u8 = 0x56;
    /// i64 less or equal (signed).
    pub const I64_LE_S: u8 = 0x57;
    /// i64 less or equal (unsigned).
    pub const I64_LE_U: u8 = 0x58;
    /// i64 greater or equal (signed).
    pub const I64_GE_S: u8 = 0x59;
    /// i64 greater or equal (unsigned).
    pub const I64_GE_U: u8 = 0x5A;

    // Comparison operators (f32)
    /// f32 equal.
    pub const F32_EQ: u8 = 0x5B;
    /// f32 not equal.
    pub const F32_NE: u8 = 0x5C;
    /// f32 less than.
    pub const F32_LT: u8 = 0x5D;
    /// f32 greater than.
    pub const F32_GT: u8 = 0x5E;
    /// f32 less or equal.
    pub const F32_LE: u8 = 0x5F;
    /// f32 greater or equal.
    pub const F32_GE: u8 = 0x60;

    // Comparison operators (f64)
    /// f64 equal.
    pub const F64_EQ: u8 = 0x61;
    /// f64 not equal.
    pub const F64_NE: u8 = 0x62;
    /// f64 less than.
    pub const F64_LT: u8 = 0x63;
    /// f64 greater than.
    pub const F64_GT: u8 = 0x64;
    /// f64 less or equal.
    pub const F64_LE: u8 = 0x65;
    /// f64 greater or equal.
    pub const F64_GE: u8 = 0x66;

    // Numeric operators (i32)
    /// i32 count leading zeros.
    pub const I32_CLZ: u8 = 0x67;
    /// i32 count trailing zeros.
    pub const I32_CTZ: u8 = 0x68;
    /// i32 population count.
    pub const I32_POPCNT: u8 = 0x69;
    /// i32 add.
    pub const I32_ADD: u8 = 0x6A;
    /// i32 subtract.
    pub const I32_SUB: u8 = 0x6B;
    /// i32 multiply.
    pub const I32_MUL: u8 = 0x6C;
    /// i32 divide (signed).
    pub const I32_DIV_S: u8 = 0x6D;
    /// i32 divide (unsigned).
    pub const I32_DIV_U: u8 = 0x6E;
    /// i32 remainder (signed).
    pub const I32_REM_S: u8 = 0x6F;
    /// i32 remainder (unsigned).
    pub const I32_REM_U: u8 = 0x70;
    /// i32 bitwise and.
    pub const I32_AND: u8 = 0x71;
    /// i32 bitwise or.
    pub const I32_OR: u8 = 0x72;
    /// i32 bitwise xor.
    pub const I32_XOR: u8 = 0x73;
    /// i32 shift left.
    pub const I32_SHL: u8 = 0x74;
    /// i32 shift right (signed).
    pub const I32_SHR_S: u8 = 0x75;
    /// i32 shift right (unsigned).
    pub const I32_SHR_U: u8 = 0x76;
    /// i32 rotate left.
    pub const I32_ROTL: u8 = 0x77;
    /// i32 rotate right.
    pub const I32_ROTR: u8 = 0x78;

    // Numeric operators (i64)
    /// i64 count leading zeros.
    pub const I64_CLZ: u8 = 0x79;
    /// i64 count trailing zeros.
    pub const I64_CTZ: u8 = 0x7A;
    /// i64 population count.
    pub const I64_POPCNT: u8 = 0x7B;
    /// i64 add.
    pub const I64_ADD: u8 = 0x7C;
    /// i64 subtract.
    pub const I64_SUB: u8 = 0x7D;
    /// i64 multiply.
    pub const I64_MUL: u8 = 0x7E;
    /// i64 divide (signed).
    pub const I64_DIV_S: u8 = 0x7F;
    /// i64 divide (unsigned).
    pub const I64_DIV_U: u8 = 0x80;
    /// i64 remainder (signed).
    pub const I64_REM_S: u8 = 0x81;
    /// i64 remainder (unsigned).
    pub const I64_REM_U: u8 = 0x82;
    /// i64 bitwise and.
    pub const I64_AND: u8 = 0x83;
    /// i64 bitwise or.
    pub const I64_OR: u8 = 0x84;
    /// i64 bitwise xor.
    pub const I64_XOR: u8 = 0x85;
    /// i64 shift left.
    pub const I64_SHL: u8 = 0x86;
    /// i64 shift right (signed).
    pub const I64_SHR_S: u8 = 0x87;
    /// i64 shift right (unsigned).
    pub const I64_SHR_U: u8 = 0x88;
    /// i64 rotate left.
    pub const I64_ROTL: u8 = 0x89;
    /// i64 rotate right.
    pub const I64_ROTR: u8 = 0x8A;

    // Numeric operators (f32)
    /// f32 absolute value.
    pub const F32_ABS: u8 = 0x8B;
    /// f32 negation.
    pub const F32_NEG: u8 = 0x8C;
    /// f32 ceiling.
    pub const F32_CEIL: u8 = 0x8D;
    /// f32 floor.
    pub const F32_FLOOR: u8 = 0x8E;
    /// f32 truncate.
    pub const F32_TRUNC: u8 = 0x8F;
    /// f32 nearest integer.
    pub const F32_NEAREST: u8 = 0x90;
    /// f32 square root.
    pub const F32_SQRT: u8 = 0x91;
    /// f32 add.
    pub const F32_ADD: u8 = 0x92;
    /// f32 subtract.
    pub const F32_SUB: u8 = 0x93;
    /// f32 multiply.
    pub const F32_MUL: u8 = 0x94;
    /// f32 divide.
    pub const F32_DIV: u8 = 0x95;
    /// f32 minimum.
    pub const F32_MIN: u8 = 0x96;
    /// f32 maximum.
    pub const F32_MAX: u8 = 0x97;
    /// f32 copy sign.
    pub const F32_COPYSIGN: u8 = 0x98;

    // Numeric operators (f64)
    /// f64 absolute value.
    pub const F64_ABS: u8 = 0x99;
    /// f64 negation.
    pub const F64_NEG: u8 = 0x9A;
    /// f64 ceiling.
    pub const F64_CEIL: u8 = 0x9B;
    /// f64 floor.
    pub const F64_FLOOR: u8 = 0x9C;
    /// f64 truncate.
    pub const F64_TRUNC: u8 = 0x9D;
    /// f64 nearest integer.
    pub const F64_NEAREST: u8 = 0x9E;
    /// f64 square root.
    pub const F64_SQRT: u8 = 0x9F;
    /// f64 add.
    pub const F64_ADD: u8 = 0xA0;
    /// f64 subtract.
    pub const F64_SUB: u8 = 0xA1;
    /// f64 multiply.
    pub const F64_MUL: u8 = 0xA2;
    /// f64 divide.
    pub const F64_DIV: u8 = 0xA3;
    /// f64 minimum.
    pub const F64_MIN: u8 = 0xA4;
    /// f64 maximum.
    pub const F64_MAX: u8 = 0xA5;
    /// f64 copy sign.
    pub const F64_COPYSIGN: u8 = 0xA6;

    // Conversions
    /// i32 wrap i64.
    pub const I32_WRAP_I64: u8 = 0xA7;
    /// i32 truncate f32 (signed).
    pub const I32_TRUNC_F32_S: u8 = 0xA8;
    /// i32 truncate f32 (unsigned).
    pub const I32_TRUNC_F32_U: u8 = 0xA9;
    /// i32 truncate f64 (signed).
    pub const I32_TRUNC_F64_S: u8 = 0xAA;
    /// i32 truncate f64 (unsigned).
    pub const I32_TRUNC_F64_U: u8 = 0xAB;
    /// i64 extend i32 (signed).
    pub const I64_EXTEND_I32_S: u8 = 0xAC;
    /// i64 extend i32 (unsigned).
    pub const I64_EXTEND_I32_U: u8 = 0xAD;
    /// i64 truncate f32 (signed).
    pub const I64_TRUNC_F32_S: u8 = 0xAE;
    /// i64 truncate f32 (unsigned).
    pub const I64_TRUNC_F32_U: u8 = 0xAF;
    /// i64 truncate f64 (signed).
    pub const I64_TRUNC_F64_S: u8 = 0xB0;
    /// i64 truncate f64 (unsigned).
    pub const I64_TRUNC_F64_U: u8 = 0xB1;
    /// f32 convert i32 (signed).
    pub const F32_CONVERT_I32_S: u8 = 0xB2;
    /// f32 convert i32 (unsigned).
    pub const F32_CONVERT_I32_U: u8 = 0xB3;
    /// f32 convert i64 (signed).
    pub const F32_CONVERT_I64_S: u8 = 0xB4;
    /// f32 convert i64 (unsigned).
    pub const F32_CONVERT_I64_U: u8 = 0xB5;
    /// f32 demote f64.
    pub const F32_DEMOTE_F64: u8 = 0xB6;
    /// f64 convert i32 (signed).
    pub const F64_CONVERT_I32_S: u8 = 0xB7;
    /// f64 convert i32 (unsigned).
    pub const F64_CONVERT_I32_U: u8 = 0xB8;
    /// f64 convert i64 (signed).
    pub const F64_CONVERT_I64_S: u8 = 0xB9;
    /// f64 convert i64 (unsigned).
    pub const F64_CONVERT_I64_U: u8 = 0xBA;
    /// f64 promote f32.
    pub const F64_PROMOTE_F32: u8 = 0xBB;

    // Reinterpretations
    /// i32 reinterpret f32.
    pub const I32_REINTERPRET_F32: u8 = 0xBC;
    /// i64 reinterpret f64.
    pub const I64_REINTERPRET_F64: u8 = 0xBD;
    /// f32 reinterpret i32.
    pub const F32_REINTERPRET_I32: u8 = 0xBE;
    /// f64 reinterpret i64.
    pub const F64_REINTERPRET_I64: u8 = 0xBF;

    // Sign extension (WASM 1.1+)
    /// i32 extend 8-bit signed.
    pub const I32_EXTEND8_S: u8 = 0xC0;
    /// i32 extend 16-bit signed.
    pub const I32_EXTEND16_S: u8 = 0xC1;
    /// i64 extend 8-bit signed.
    pub const I64_EXTEND8_S: u8 = 0xC2;
    /// i64 extend 16-bit signed.
    pub const I64_EXTEND16_S: u8 = 0xC3;
    /// i64 extend 32-bit signed.
    pub const I64_EXTEND32_S: u8 = 0xC4;

    // Reference types
    /// Null reference.
    pub const REF_NULL: u8 = 0xD0;
    /// Check if reference is null.
    pub const REF_IS_NULL: u8 = 0xD1;
    /// Get function reference.
    pub const REF_FUNC: u8 = 0xD2;

    // Multibyte opcode prefixes
    /// Saturating truncation and bulk memory prefix.
    pub const PREFIX_FC: u8 = 0xFC;
    /// SIMD prefix.
    pub const PREFIX_FD: u8 = 0xFD;
    /// Atomics prefix.
    pub const PREFIX_FE: u8 = 0xFE;
}

/// WASM section IDs.
pub mod section {
    /// Custom section.
    pub const CUSTOM: u8 = 0;
    /// Type section.
    pub const TYPE: u8 = 1;
    /// Import section.
    pub const IMPORT: u8 = 2;
    /// Function section.
    pub const FUNCTION: u8 = 3;
    /// Table section.
    pub const TABLE: u8 = 4;
    /// Memory section.
    pub const MEMORY: u8 = 5;
    /// Global section.
    pub const GLOBAL: u8 = 6;
    /// Export section.
    pub const EXPORT: u8 = 7;
    /// Start section.
    pub const START: u8 = 8;
    /// Element section.
    pub const ELEMENT: u8 = 9;
    /// Code section.
    pub const CODE: u8 = 10;
    /// Data section.
    pub const DATA: u8 = 11;
    /// Data count section.
    pub const DATA_COUNT: u8 = 12;
}

/// WASM value types.
pub mod valtype {
    /// 32-bit integer.
    pub const I32: u8 = 0x7F;
    /// 64-bit integer.
    pub const I64: u8 = 0x7E;
    /// 32-bit float.
    pub const F32: u8 = 0x7D;
    /// 64-bit float.
    pub const F64: u8 = 0x7C;
    /// 128-bit vector.
    pub const V128: u8 = 0x7B;
    /// Function reference.
    pub const FUNCREF: u8 = 0x70;
    /// External reference.
    pub const EXTERNREF: u8 = 0x6F;
}

/// Read unsigned LEB128 value.
///
/// Returns (value, bytes_consumed) or None if invalid.
pub fn read_leb128_u32(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut i = offset;

    loop {
        if i >= data.len() {
            return None;
        }

        let byte = data[i];
        i += 1;

        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            break;
        }

        if shift >= 35 {
            return None; // Overflow
        }
    }

    Some((result, i - offset))
}

/// Read signed LEB128 value.
///
/// Returns (value, bytes_consumed) or None if invalid.
pub fn read_leb128_i32(data: &[u8], offset: usize) -> Option<(i32, usize)> {
    let mut result: i32 = 0;
    let mut shift = 0;
    let mut i = offset;

    loop {
        if i >= data.len() {
            return None;
        }

        let byte = data[i];
        i += 1;

        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            // Sign extend if needed
            if shift < 32 && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            break;
        }

        if shift >= 35 {
            return None; // Overflow
        }
    }

    Some((result, i - offset))
}

/// Read signed LEB128 i64 value.
pub fn read_leb128_i64(data: &[u8], offset: usize) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut i = offset;

    loop {
        if i >= data.len() {
            return None;
        }

        let byte = data[i];
        i += 1;

        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            break;
        }

        if shift >= 70 {
            return None;
        }
    }

    Some((result, i - offset))
}

/// Check if opcode is a control flow instruction.
pub fn is_control(op: u8) -> bool {
    matches!(
        op,
        opcode::UNREACHABLE
            | opcode::NOP
            | opcode::BLOCK
            | opcode::LOOP
            | opcode::IF
            | opcode::ELSE
            | opcode::END
            | opcode::BR
            | opcode::BR_IF
            | opcode::BR_TABLE
            | opcode::RETURN
    )
}

/// Check if opcode is a call instruction.
pub fn is_call(op: u8) -> bool {
    matches!(
        op,
        opcode::CALL | opcode::CALL_INDIRECT | opcode::RETURN_CALL | opcode::RETURN_CALL_INDIRECT
    )
}

/// Check if opcode is a local/global variable access.
pub fn is_variable(op: u8) -> bool {
    matches!(
        op,
        opcode::LOCAL_GET
            | opcode::LOCAL_SET
            | opcode::LOCAL_TEE
            | opcode::GLOBAL_GET
            | opcode::GLOBAL_SET
    )
}

/// Check if opcode is a memory instruction.
pub fn is_memory(op: u8) -> bool {
    matches!(op, opcode::I32_LOAD..=opcode::MEMORY_GROW)
}

/// Check if opcode is an i32 numeric instruction.
pub fn is_i32_numeric(op: u8) -> bool {
    matches!(op, opcode::I32_CLZ..=opcode::I32_ROTR)
}

/// Check if opcode is an i64 numeric instruction.
pub fn is_i64_numeric(op: u8) -> bool {
    matches!(op, opcode::I64_CLZ..=opcode::I64_ROTR)
}

/// Check if opcode is a comparison instruction.
pub fn is_comparison(op: u8) -> bool {
    matches!(op, opcode::I32_EQZ..=opcode::F64_GE)
}

/// Check if opcode is a conversion instruction.
pub fn is_conversion(op: u8) -> bool {
    matches!(op, opcode::I32_WRAP_I64..=opcode::F64_REINTERPRET_I64)
}

/// Estimate instruction length for a basic opcode.
///
/// Returns 0 for variable-length or prefixed instructions.
pub fn estimate_instruction_length(data: &[u8], offset: usize) -> usize {
    if offset >= data.len() {
        return 0;
    }

    let op = data[offset];

    match op {
        // Single byte instructions (no immediates)
        opcode::UNREACHABLE
        | opcode::NOP
        | opcode::ELSE
        | opcode::END
        | opcode::RETURN
        | opcode::DROP
        | opcode::SELECT
        | opcode::I32_EQZ..=opcode::I64_EXTEND32_S
        | opcode::REF_IS_NULL => 1,

        // Block/loop/if need block type (LEB128)
        opcode::BLOCK | opcode::LOOP | opcode::IF => {
            if offset + 1 < data.len() {
                // Block type is either 0x40 (empty) or a valtype
                let bt = data[offset + 1];
                if bt == 0x40
                    || matches!(
                        bt,
                        valtype::I32 | valtype::I64 | valtype::F32 | valtype::F64
                    )
                {
                    2
                } else {
                    // Signed LEB128 type index
                    0
                }
            } else {
                0
            }
        }

        // Branch/call with LEB128 index
        opcode::BR | opcode::BR_IF | opcode::CALL | opcode::REF_FUNC => {
            if let Some((_, len)) = read_leb128_u32(data, offset + 1) {
                1 + len
            } else {
                0
            }
        }

        // Local/global access with LEB128 index
        opcode::LOCAL_GET
        | opcode::LOCAL_SET
        | opcode::LOCAL_TEE
        | opcode::GLOBAL_GET
        | opcode::GLOBAL_SET => {
            if let Some((_, len)) = read_leb128_u32(data, offset + 1) {
                1 + len
            } else {
                0
            }
        }

        // Memory instructions: align + offset (2 LEB128)
        opcode::I32_LOAD..=opcode::I64_STORE32 => {
            let mut pos = offset + 1;
            if let Some((_, len1)) = read_leb128_u32(data, pos) {
                pos += len1;
                if let Some((_, len2)) = read_leb128_u32(data, pos) {
                    1 + len1 + len2
                } else {
                    0
                }
            } else {
                0
            }
        }

        // memory.size and memory.grow have a 0x00 byte
        opcode::MEMORY_SIZE | opcode::MEMORY_GROW => 2,

        // Constants with LEB128 or fixed immediates
        opcode::I32_CONST => {
            if let Some((_, len)) = read_leb128_i32(data, offset + 1) {
                1 + len
            } else {
                0
            }
        }
        opcode::I64_CONST => {
            if let Some((_, len)) = read_leb128_i64(data, offset + 1) {
                1 + len
            } else {
                0
            }
        }
        opcode::F32_CONST => 5, // 1 + 4 bytes
        opcode::F64_CONST => 9, // 1 + 8 bytes

        // Reference null with type
        opcode::REF_NULL => 2,

        // Prefixed instructions (variable)
        opcode::PREFIX_FC | opcode::PREFIX_FD | opcode::PREFIX_FE => 0,

        // br_table is highly variable
        opcode::BR_TABLE => 0,

        // call_indirect has two LEB128s
        opcode::CALL_INDIRECT => 0,

        // Typed select
        opcode::SELECT_T => 0,

        _ => 0,
    }
}

/// Score likelihood of WebAssembly bytecode.
///
/// Analyzes raw bytes for patterns characteristic of WASM code sections:
/// - Valid opcode sequences
/// - Proper block structure (block/loop/if with end)
/// - Common instruction patterns
pub fn score(data: &[u8]) -> i64 {
    let mut total_score: i64 = 0;
    let mut i = 0;
    let mut block_depth = 0i32;
    let mut valid_count = 0u32;
    let mut end_count = 0u32;
    let mut call_count = 0u32;
    let mut return_count = 0u32;
    let mut block_count = 0u32;

    while i < data.len() {
        let op = data[i];
        let len = estimate_instruction_length(data, i);

        // Count valid vs invalid
        if len > 0 && i + len <= data.len() {
            valid_count += 1;
        }

        // Track block structure
        match op {
            opcode::BLOCK | opcode::LOOP | opcode::IF => {
                block_depth += 1;
                block_count += 1;
                total_score += 3;
            }
            opcode::END => {
                end_count += 1;
                if block_depth > 0 {
                    block_depth -= 1;
                    total_score += 3;
                }
            }
            _ => {}
        }

        // Score common patterns
        match op {
            // Very common: local variable access
            opcode::LOCAL_GET => total_score += 4,
            opcode::LOCAL_SET | opcode::LOCAL_TEE => total_score += 3,

            // Common: constants
            opcode::I32_CONST => total_score += 4,
            opcode::I64_CONST => total_score += 3,

            // Common: arithmetic
            opcode::I32_ADD | opcode::I32_SUB | opcode::I32_MUL => total_score += 3,
            opcode::I64_ADD | opcode::I64_SUB => total_score += 2,

            // Common: comparisons
            opcode::I32_EQZ | opcode::I32_EQ | opcode::I32_NE => total_score += 2,
            opcode::I32_LT_S..=opcode::I32_GE_U => total_score += 2,

            // Common: control flow
            opcode::BR | opcode::BR_IF => total_score += 3,
            opcode::RETURN => { total_score += 5; return_count += 1; }

            // Common: calls
            opcode::CALL => { total_score += 5; call_count += 1; }
            opcode::CALL_INDIRECT => { total_score += 4; call_count += 1; }

            // Common: memory access
            opcode::I32_LOAD | opcode::I32_STORE => total_score += 3,
            opcode::I64_LOAD | opcode::I64_STORE => total_score += 2,

            // Less common but valid
            opcode::GLOBAL_GET | opcode::GLOBAL_SET => total_score += 2,
            opcode::DROP => total_score += 2,
            opcode::SELECT => total_score += 2,

            // NOP is rare but valid
            opcode::NOP => total_score += 1,

            _ => {}
        }

        if len > 0 {
            i += len;
        } else {
            i += 1;
        }
    }

    // Bonus for balanced block structure
    if block_depth == 0 && end_count > 0 {
        total_score += (end_count as i64) * 2;
    }

    // Penalty for unbalanced blocks
    if block_depth != 0 {
        total_score -= block_depth.abs() as i64 * 5;
    }

    // Structural requirement: WASM code must have calls, returns, or block structure
    if data.len() > 80 {
        let distinctive = call_count + return_count;
        if distinctive == 0 && block_count == 0 {
            total_score = (total_score as f64 * 0.10) as i64;
        } else if distinctive == 0 {
            total_score = (total_score as f64 * 0.25) as i64;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128_u32() {
        // Single byte
        assert_eq!(read_leb128_u32(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_leb128_u32(&[0x7F], 0), Some((127, 1)));

        // Two bytes
        assert_eq!(read_leb128_u32(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(read_leb128_u32(&[0xFF, 0x01], 0), Some((255, 2)));

        // Multi-byte
        assert_eq!(read_leb128_u32(&[0xE5, 0x8E, 0x26], 0), Some((624485, 3)));
    }

    #[test]
    fn test_leb128_i32() {
        // Positive
        assert_eq!(read_leb128_i32(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_leb128_i32(&[0x3F], 0), Some((63, 1)));

        // Negative (sign extended)
        assert_eq!(read_leb128_i32(&[0x7F], 0), Some((-1, 1)));
        assert_eq!(read_leb128_i32(&[0x40], 0), Some((-64, 1)));
    }

    #[test]
    fn test_estimate_length() {
        // Single byte instructions
        assert_eq!(estimate_instruction_length(&[opcode::NOP], 0), 1);
        assert_eq!(estimate_instruction_length(&[opcode::RETURN], 0), 1);
        assert_eq!(estimate_instruction_length(&[opcode::END], 0), 1);
        assert_eq!(estimate_instruction_length(&[opcode::I32_ADD], 0), 1);

        // Block with empty type
        assert_eq!(estimate_instruction_length(&[opcode::BLOCK, 0x40], 0), 2);

        // local.get with index 0
        assert_eq!(
            estimate_instruction_length(&[opcode::LOCAL_GET, 0x00], 0),
            2
        );

        // i32.const with value 42
        assert_eq!(
            estimate_instruction_length(&[opcode::I32_CONST, 0x2A], 0),
            2
        );

        // f32.const (1 + 4 bytes)
        assert_eq!(
            estimate_instruction_length(&[opcode::F32_CONST, 0, 0, 0, 0], 0),
            5
        );
    }

    #[test]
    fn test_is_control() {
        assert!(is_control(opcode::BLOCK));
        assert!(is_control(opcode::LOOP));
        assert!(is_control(opcode::IF));
        assert!(is_control(opcode::END));
        assert!(is_control(opcode::BR));
        assert!(!is_control(opcode::I32_ADD));
        assert!(!is_control(opcode::LOCAL_GET));
    }

    #[test]
    fn test_is_call() {
        assert!(is_call(opcode::CALL));
        assert!(is_call(opcode::CALL_INDIRECT));
        assert!(!is_call(opcode::BR));
        assert!(!is_call(opcode::RETURN));
    }

    #[test]
    fn test_score_simple_function() {
        // Simple function: local.get 0, i32.const 1, i32.add, return
        let code = [
            opcode::LOCAL_GET,
            0x00,
            opcode::I32_CONST,
            0x01,
            opcode::I32_ADD,
            opcode::RETURN,
        ];
        let s = score(&code);
        assert!(s > 0, "Valid WASM code should score positive");
    }

    #[test]
    fn test_score_block_structure() {
        // block, i32.const 1, br_if 0, end
        let code = [
            opcode::BLOCK,
            0x40, // Empty block
            opcode::I32_CONST,
            0x01,
            opcode::BR_IF,
            0x00,
            opcode::END,
        ];
        let s = score(&code);
        assert!(s > 5, "Block structure should score well");
    }

    #[test]
    fn test_score_unbalanced() {
        // Unbalanced: block without end
        let code = [opcode::BLOCK, 0x40, opcode::I32_CONST, 0x01];
        let s = score(&code);
        // Should have penalty but not crash
        assert!(s >= 0);
    }
}
