//! Dalvik VM bytecode analysis (Android).
//!
//! Dalvik uses a register-based architecture with 16-bit code units.
//! Instructions range from 1 to 5 code units (2-10 bytes).
//! Bytecode is little-endian, with opcodes in the low 8 bits of the first unit.

/// Dalvik opcode constants.
pub mod opcode {
    // Data movement (0x00-0x0D)
    /// No operation.
    pub const NOP: u8 = 0x00;
    /// Move vA, vB (4-bit regs).
    pub const MOVE: u8 = 0x01;
    /// Move from 16-bit reg.
    pub const MOVE_FROM16: u8 = 0x02;
    /// Move 16-bit regs.
    pub const MOVE_16: u8 = 0x03;
    /// Move wide (64-bit).
    pub const MOVE_WIDE: u8 = 0x04;
    /// Move wide from 16-bit reg.
    pub const MOVE_WIDE_FROM16: u8 = 0x05;
    /// Move wide 16-bit regs.
    pub const MOVE_WIDE_16: u8 = 0x06;
    /// Move object reference.
    pub const MOVE_OBJECT: u8 = 0x07;
    /// Move object from 16-bit reg.
    pub const MOVE_OBJECT_FROM16: u8 = 0x08;
    /// Move object 16-bit regs.
    pub const MOVE_OBJECT_16: u8 = 0x09;
    /// Move result to register.
    pub const MOVE_RESULT: u8 = 0x0A;
    /// Move wide result.
    pub const MOVE_RESULT_WIDE: u8 = 0x0B;
    /// Move object result.
    pub const MOVE_RESULT_OBJECT: u8 = 0x0C;
    /// Move exception to register.
    pub const MOVE_EXCEPTION: u8 = 0x0D;

    // Returns (0x0E-0x11)
    /// Return void.
    pub const RETURN_VOID: u8 = 0x0E;
    /// Return 32-bit value.
    pub const RETURN: u8 = 0x0F;
    /// Return 64-bit value.
    pub const RETURN_WIDE: u8 = 0x10;
    /// Return object reference.
    pub const RETURN_OBJECT: u8 = 0x11;

    // Constants (0x12-0x1C)
    /// Const 4-bit signed literal.
    pub const CONST_4: u8 = 0x12;
    /// Const 16-bit signed literal.
    pub const CONST_16: u8 = 0x13;
    /// Const 32-bit literal.
    pub const CONST: u8 = 0x14;
    /// Const high 16 bits.
    pub const CONST_HIGH16: u8 = 0x15;
    /// Const wide 16-bit.
    pub const CONST_WIDE_16: u8 = 0x16;
    /// Const wide 32-bit.
    pub const CONST_WIDE_32: u8 = 0x17;
    /// Const wide 64-bit.
    pub const CONST_WIDE: u8 = 0x18;
    /// Const wide high 16 bits.
    pub const CONST_WIDE_HIGH16: u8 = 0x19;
    /// Const string reference.
    pub const CONST_STRING: u8 = 0x1A;
    /// Const string jumbo.
    pub const CONST_STRING_JUMBO: u8 = 0x1B;
    /// Const class reference.
    pub const CONST_CLASS: u8 = 0x1C;

    // Monitor/Type operations (0x1D-0x27)
    /// Enter monitor.
    pub const MONITOR_ENTER: u8 = 0x1D;
    /// Exit monitor.
    pub const MONITOR_EXIT: u8 = 0x1E;
    /// Check cast.
    pub const CHECK_CAST: u8 = 0x1F;
    /// Instance of check.
    pub const INSTANCE_OF: u8 = 0x20;
    /// Array length.
    pub const ARRAY_LENGTH: u8 = 0x21;
    /// New instance.
    pub const NEW_INSTANCE: u8 = 0x22;
    /// New array.
    pub const NEW_ARRAY: u8 = 0x23;
    /// Filled new array.
    pub const FILLED_NEW_ARRAY: u8 = 0x24;
    /// Filled new array range.
    pub const FILLED_NEW_ARRAY_RANGE: u8 = 0x25;
    /// Fill array data.
    pub const FILL_ARRAY_DATA: u8 = 0x26;
    /// Throw exception.
    pub const THROW: u8 = 0x27;

    // Control flow (0x28-0x3D)
    /// Goto (8-bit offset).
    pub const GOTO: u8 = 0x28;
    /// Goto 16-bit offset.
    pub const GOTO_16: u8 = 0x29;
    /// Goto 32-bit offset.
    pub const GOTO_32: u8 = 0x2A;
    /// Packed switch.
    pub const PACKED_SWITCH: u8 = 0x2B;
    /// Sparse switch.
    pub const SPARSE_SWITCH: u8 = 0x2C;

    // Comparisons (0x2D-0x31)
    /// Compare long less.
    pub const CMPL_FLOAT: u8 = 0x2D;
    /// Compare float greater.
    pub const CMPG_FLOAT: u8 = 0x2E;
    /// Compare double less.
    pub const CMPL_DOUBLE: u8 = 0x2F;
    /// Compare double greater.
    pub const CMPG_DOUBLE: u8 = 0x30;
    /// Compare long.
    pub const CMP_LONG: u8 = 0x31;

    // If tests (0x32-0x37)
    /// If equal.
    pub const IF_EQ: u8 = 0x32;
    /// If not equal.
    pub const IF_NE: u8 = 0x33;
    /// If less than.
    pub const IF_LT: u8 = 0x34;
    /// If greater or equal.
    pub const IF_GE: u8 = 0x35;
    /// If greater than.
    pub const IF_GT: u8 = 0x36;
    /// If less or equal.
    pub const IF_LE: u8 = 0x37;

    // If-zero tests (0x38-0x3D)
    /// If equal to zero.
    pub const IF_EQZ: u8 = 0x38;
    /// If not equal to zero.
    pub const IF_NEZ: u8 = 0x39;
    /// If less than zero.
    pub const IF_LTZ: u8 = 0x3A;
    /// If greater or equal to zero.
    pub const IF_GEZ: u8 = 0x3B;
    /// If greater than zero.
    pub const IF_GTZ: u8 = 0x3C;
    /// If less or equal to zero.
    pub const IF_LEZ: u8 = 0x3D;

    // Array access (0x44-0x51)
    /// Get int from array.
    pub const AGET: u8 = 0x44;
    /// Get wide from array.
    pub const AGET_WIDE: u8 = 0x45;
    /// Get object from array.
    pub const AGET_OBJECT: u8 = 0x46;
    /// Get boolean from array.
    pub const AGET_BOOLEAN: u8 = 0x47;
    /// Get byte from array.
    pub const AGET_BYTE: u8 = 0x48;
    /// Get char from array.
    pub const AGET_CHAR: u8 = 0x49;
    /// Get short from array.
    pub const AGET_SHORT: u8 = 0x4A;
    /// Put int to array.
    pub const APUT: u8 = 0x4B;
    /// Put wide to array.
    pub const APUT_WIDE: u8 = 0x4C;
    /// Put object to array.
    pub const APUT_OBJECT: u8 = 0x4D;
    /// Put boolean to array.
    pub const APUT_BOOLEAN: u8 = 0x4E;
    /// Put byte to array.
    pub const APUT_BYTE: u8 = 0x4F;
    /// Put char to array.
    pub const APUT_CHAR: u8 = 0x50;
    /// Put short to array.
    pub const APUT_SHORT: u8 = 0x51;

    // Instance field access (0x52-0x5F)
    /// Get instance field (int).
    pub const IGET: u8 = 0x52;
    /// Get instance field (wide).
    pub const IGET_WIDE: u8 = 0x53;
    /// Get instance field (object).
    pub const IGET_OBJECT: u8 = 0x54;
    /// Get instance field (boolean).
    pub const IGET_BOOLEAN: u8 = 0x55;
    /// Get instance field (byte).
    pub const IGET_BYTE: u8 = 0x56;
    /// Get instance field (char).
    pub const IGET_CHAR: u8 = 0x57;
    /// Get instance field (short).
    pub const IGET_SHORT: u8 = 0x58;
    /// Put instance field (int).
    pub const IPUT: u8 = 0x59;
    /// Put instance field (wide).
    pub const IPUT_WIDE: u8 = 0x5A;
    /// Put instance field (object).
    pub const IPUT_OBJECT: u8 = 0x5B;
    /// Put instance field (boolean).
    pub const IPUT_BOOLEAN: u8 = 0x5C;
    /// Put instance field (byte).
    pub const IPUT_BYTE: u8 = 0x5D;
    /// Put instance field (char).
    pub const IPUT_CHAR: u8 = 0x5E;
    /// Put instance field (short).
    pub const IPUT_SHORT: u8 = 0x5F;

    // Static field access (0x60-0x6D)
    /// Get static field (int).
    pub const SGET: u8 = 0x60;
    /// Get static field (wide).
    pub const SGET_WIDE: u8 = 0x61;
    /// Get static field (object).
    pub const SGET_OBJECT: u8 = 0x62;
    /// Get static field (boolean).
    pub const SGET_BOOLEAN: u8 = 0x63;
    /// Get static field (byte).
    pub const SGET_BYTE: u8 = 0x64;
    /// Get static field (char).
    pub const SGET_CHAR: u8 = 0x65;
    /// Get static field (short).
    pub const SGET_SHORT: u8 = 0x66;
    /// Put static field (int).
    pub const SPUT: u8 = 0x67;
    /// Put static field (wide).
    pub const SPUT_WIDE: u8 = 0x68;
    /// Put static field (object).
    pub const SPUT_OBJECT: u8 = 0x69;
    /// Put static field (boolean).
    pub const SPUT_BOOLEAN: u8 = 0x6A;
    /// Put static field (byte).
    pub const SPUT_BYTE: u8 = 0x6B;
    /// Put static field (char).
    pub const SPUT_CHAR: u8 = 0x6C;
    /// Put static field (short).
    pub const SPUT_SHORT: u8 = 0x6D;

    // Invoke operations (0x6E-0x78)
    /// Invoke virtual method.
    pub const INVOKE_VIRTUAL: u8 = 0x6E;
    /// Invoke super method.
    pub const INVOKE_SUPER: u8 = 0x6F;
    /// Invoke direct method.
    pub const INVOKE_DIRECT: u8 = 0x70;
    /// Invoke static method.
    pub const INVOKE_STATIC: u8 = 0x71;
    /// Invoke interface method.
    pub const INVOKE_INTERFACE: u8 = 0x72;
    /// Invoke virtual range.
    pub const INVOKE_VIRTUAL_RANGE: u8 = 0x74;
    /// Invoke super range.
    pub const INVOKE_SUPER_RANGE: u8 = 0x75;
    /// Invoke direct range.
    pub const INVOKE_DIRECT_RANGE: u8 = 0x76;
    /// Invoke static range.
    pub const INVOKE_STATIC_RANGE: u8 = 0x77;
    /// Invoke interface range.
    pub const INVOKE_INTERFACE_RANGE: u8 = 0x78;

    // Unary operations (0x7B-0x8F)
    /// Negate int.
    pub const NEG_INT: u8 = 0x7B;
    /// Not int.
    pub const NOT_INT: u8 = 0x7C;
    /// Negate long.
    pub const NEG_LONG: u8 = 0x7D;
    /// Not long.
    pub const NOT_LONG: u8 = 0x7E;
    /// Negate float.
    pub const NEG_FLOAT: u8 = 0x7F;
    /// Negate double.
    pub const NEG_DOUBLE: u8 = 0x80;
    /// Int to long.
    pub const INT_TO_LONG: u8 = 0x81;
    /// Int to float.
    pub const INT_TO_FLOAT: u8 = 0x82;
    /// Int to double.
    pub const INT_TO_DOUBLE: u8 = 0x83;
    /// Long to int.
    pub const LONG_TO_INT: u8 = 0x84;
    /// Long to float.
    pub const LONG_TO_FLOAT: u8 = 0x85;
    /// Long to double.
    pub const LONG_TO_DOUBLE: u8 = 0x86;
    /// Float to int.
    pub const FLOAT_TO_INT: u8 = 0x87;
    /// Float to long.
    pub const FLOAT_TO_LONG: u8 = 0x88;
    /// Float to double.
    pub const FLOAT_TO_DOUBLE: u8 = 0x89;
    /// Double to int.
    pub const DOUBLE_TO_INT: u8 = 0x8A;
    /// Double to long.
    pub const DOUBLE_TO_LONG: u8 = 0x8B;
    /// Double to float.
    pub const DOUBLE_TO_FLOAT: u8 = 0x8C;
    /// Int to byte.
    pub const INT_TO_BYTE: u8 = 0x8D;
    /// Int to char.
    pub const INT_TO_CHAR: u8 = 0x8E;
    /// Int to short.
    pub const INT_TO_SHORT: u8 = 0x8F;

    // Binary operations (0x90-0xAF)
    /// Add int.
    pub const ADD_INT: u8 = 0x90;
    /// Sub int.
    pub const SUB_INT: u8 = 0x91;
    /// Mul int.
    pub const MUL_INT: u8 = 0x92;
    /// Div int.
    pub const DIV_INT: u8 = 0x93;
    /// Rem int.
    pub const REM_INT: u8 = 0x94;
    /// And int.
    pub const AND_INT: u8 = 0x95;
    /// Or int.
    pub const OR_INT: u8 = 0x96;
    /// Xor int.
    pub const XOR_INT: u8 = 0x97;
    /// Shl int.
    pub const SHL_INT: u8 = 0x98;
    /// Shr int.
    pub const SHR_INT: u8 = 0x99;
    /// Ushr int.
    pub const USHR_INT: u8 = 0x9A;
    /// Add long.
    pub const ADD_LONG: u8 = 0x9B;
    /// Sub long.
    pub const SUB_LONG: u8 = 0x9C;
    /// Mul long.
    pub const MUL_LONG: u8 = 0x9D;
    /// Div long.
    pub const DIV_LONG: u8 = 0x9E;
    /// Rem long.
    pub const REM_LONG: u8 = 0x9F;
    /// And long.
    pub const AND_LONG: u8 = 0xA0;
    /// Or long.
    pub const OR_LONG: u8 = 0xA1;
    /// Xor long.
    pub const XOR_LONG: u8 = 0xA2;
    /// Shl long.
    pub const SHL_LONG: u8 = 0xA3;
    /// Shr long.
    pub const SHR_LONG: u8 = 0xA4;
    /// Ushr long.
    pub const USHR_LONG: u8 = 0xA5;
    /// Add float.
    pub const ADD_FLOAT: u8 = 0xA6;
    /// Sub float.
    pub const SUB_FLOAT: u8 = 0xA7;
    /// Mul float.
    pub const MUL_FLOAT: u8 = 0xA8;
    /// Div float.
    pub const DIV_FLOAT: u8 = 0xA9;
    /// Rem float.
    pub const REM_FLOAT: u8 = 0xAA;
    /// Add double.
    pub const ADD_DOUBLE: u8 = 0xAB;
    /// Sub double.
    pub const SUB_DOUBLE: u8 = 0xAC;
    /// Mul double.
    pub const MUL_DOUBLE: u8 = 0xAD;
    /// Div double.
    pub const DIV_DOUBLE: u8 = 0xAE;
    /// Rem double.
    pub const REM_DOUBLE: u8 = 0xAF;

    // 2-addr binary operations (0xB0-0xCF)
    /// Add int 2-addr.
    pub const ADD_INT_2ADDR: u8 = 0xB0;
    /// Sub int 2-addr.
    pub const SUB_INT_2ADDR: u8 = 0xB1;
    /// Mul int 2-addr.
    pub const MUL_INT_2ADDR: u8 = 0xB2;
    /// Div int 2-addr.
    pub const DIV_INT_2ADDR: u8 = 0xB3;
    /// Rem int 2-addr.
    pub const REM_INT_2ADDR: u8 = 0xB4;
    /// And int 2-addr.
    pub const AND_INT_2ADDR: u8 = 0xB5;
    /// Or int 2-addr.
    pub const OR_INT_2ADDR: u8 = 0xB6;
    /// Xor int 2-addr.
    pub const XOR_INT_2ADDR: u8 = 0xB7;
    /// Shl int 2-addr.
    pub const SHL_INT_2ADDR: u8 = 0xB8;
    /// Shr int 2-addr.
    pub const SHR_INT_2ADDR: u8 = 0xB9;
    /// Ushr int 2-addr.
    pub const USHR_INT_2ADDR: u8 = 0xBA;
    /// Add long 2-addr.
    pub const ADD_LONG_2ADDR: u8 = 0xBB;
    /// Sub long 2-addr.
    pub const SUB_LONG_2ADDR: u8 = 0xBC;
    /// Mul long 2-addr.
    pub const MUL_LONG_2ADDR: u8 = 0xBD;
    /// Div long 2-addr.
    pub const DIV_LONG_2ADDR: u8 = 0xBE;
    /// Rem long 2-addr.
    pub const REM_LONG_2ADDR: u8 = 0xBF;
    /// And long 2-addr.
    pub const AND_LONG_2ADDR: u8 = 0xC0;
    /// Or long 2-addr.
    pub const OR_LONG_2ADDR: u8 = 0xC1;
    /// Xor long 2-addr.
    pub const XOR_LONG_2ADDR: u8 = 0xC2;
    /// Shl long 2-addr.
    pub const SHL_LONG_2ADDR: u8 = 0xC3;
    /// Shr long 2-addr.
    pub const SHR_LONG_2ADDR: u8 = 0xC4;
    /// Ushr long 2-addr.
    pub const USHR_LONG_2ADDR: u8 = 0xC5;
    /// Add float 2-addr.
    pub const ADD_FLOAT_2ADDR: u8 = 0xC6;
    /// Sub float 2-addr.
    pub const SUB_FLOAT_2ADDR: u8 = 0xC7;
    /// Mul float 2-addr.
    pub const MUL_FLOAT_2ADDR: u8 = 0xC8;
    /// Div float 2-addr.
    pub const DIV_FLOAT_2ADDR: u8 = 0xC9;
    /// Rem float 2-addr.
    pub const REM_FLOAT_2ADDR: u8 = 0xCA;
    /// Add double 2-addr.
    pub const ADD_DOUBLE_2ADDR: u8 = 0xCB;
    /// Sub double 2-addr.
    pub const SUB_DOUBLE_2ADDR: u8 = 0xCC;
    /// Mul double 2-addr.
    pub const MUL_DOUBLE_2ADDR: u8 = 0xCD;
    /// Div double 2-addr.
    pub const DIV_DOUBLE_2ADDR: u8 = 0xCE;
    /// Rem double 2-addr.
    pub const REM_DOUBLE_2ADDR: u8 = 0xCF;

    // Literal operations (0xD0-0xE2)
    /// Add int lit16.
    pub const ADD_INT_LIT16: u8 = 0xD0;
    /// Rsub int lit16.
    pub const RSUB_INT: u8 = 0xD1;
    /// Mul int lit16.
    pub const MUL_INT_LIT16: u8 = 0xD2;
    /// Div int lit16.
    pub const DIV_INT_LIT16: u8 = 0xD3;
    /// Rem int lit16.
    pub const REM_INT_LIT16: u8 = 0xD4;
    /// And int lit16.
    pub const AND_INT_LIT16: u8 = 0xD5;
    /// Or int lit16.
    pub const OR_INT_LIT16: u8 = 0xD6;
    /// Xor int lit16.
    pub const XOR_INT_LIT16: u8 = 0xD7;
    /// Add int lit8.
    pub const ADD_INT_LIT8: u8 = 0xD8;
    /// Rsub int lit8.
    pub const RSUB_INT_LIT8: u8 = 0xD9;
    /// Mul int lit8.
    pub const MUL_INT_LIT8: u8 = 0xDA;
    /// Div int lit8.
    pub const DIV_INT_LIT8: u8 = 0xDB;
    /// Rem int lit8.
    pub const REM_INT_LIT8: u8 = 0xDC;
    /// And int lit8.
    pub const AND_INT_LIT8: u8 = 0xDD;
    /// Or int lit8.
    pub const OR_INT_LIT8: u8 = 0xDE;
    /// Xor int lit8.
    pub const XOR_INT_LIT8: u8 = 0xDF;
    /// Shl int lit8.
    pub const SHL_INT_LIT8: u8 = 0xE0;
    /// Shr int lit8.
    pub const SHR_INT_LIT8: u8 = 0xE1;
    /// Ushr int lit8.
    pub const USHR_INT_LIT8: u8 = 0xE2;

    // Extended operations (0xFA-0xFF)
    /// Invoke polymorphic.
    pub const INVOKE_POLYMORPHIC: u8 = 0xFA;
    /// Invoke polymorphic range.
    pub const INVOKE_POLYMORPHIC_RANGE: u8 = 0xFB;
    /// Invoke custom.
    pub const INVOKE_CUSTOM: u8 = 0xFC;
    /// Invoke custom range.
    pub const INVOKE_CUSTOM_RANGE: u8 = 0xFD;
    /// Const method handle.
    pub const CONST_METHOD_HANDLE: u8 = 0xFE;
    /// Const method type.
    pub const CONST_METHOD_TYPE: u8 = 0xFF;
}

/// Pseudo-instruction payload identifiers.
pub mod payload {
    /// Packed-switch payload identifier.
    pub const PACKED_SWITCH: u16 = 0x0100;
    /// Sparse-switch payload identifier.
    pub const SPARSE_SWITCH: u16 = 0x0200;
    /// Fill-array-data payload identifier.
    pub const FILL_ARRAY_DATA: u16 = 0x0300;
}

/// Get the size of a Dalvik instruction in 16-bit code units.
///
/// Returns 0 for invalid opcodes.
pub fn instruction_size(op: u8) -> usize {
    match op {
        // Format 10x, 10t, 11n, 11x, 12x (1 unit = 2 bytes)
        opcode::NOP
        | opcode::MOVE
        | opcode::MOVE_WIDE
        | opcode::MOVE_OBJECT
        | opcode::MOVE_RESULT
        | opcode::MOVE_RESULT_WIDE
        | opcode::MOVE_RESULT_OBJECT
        | opcode::MOVE_EXCEPTION
        | opcode::RETURN_VOID
        | opcode::RETURN
        | opcode::RETURN_WIDE
        | opcode::RETURN_OBJECT
        | opcode::CONST_4
        | opcode::MONITOR_ENTER
        | opcode::MONITOR_EXIT
        | opcode::ARRAY_LENGTH
        | opcode::THROW
        | opcode::GOTO
        | opcode::NEG_INT..=opcode::INT_TO_SHORT
        | opcode::ADD_INT_2ADDR..=opcode::REM_DOUBLE_2ADDR => 1,

        // Format 20t, 21c, 21h, 21s, 21t, 22b, 22c, 22s, 22t, 22x, 23x (2 units = 4 bytes)
        opcode::MOVE_FROM16
        | opcode::MOVE_WIDE_FROM16
        | opcode::MOVE_OBJECT_FROM16
        | opcode::CONST_16
        | opcode::CONST_HIGH16
        | opcode::CONST_WIDE_16
        | opcode::CONST_WIDE_HIGH16
        | opcode::CONST_STRING
        | opcode::CONST_CLASS
        | opcode::CHECK_CAST
        | opcode::INSTANCE_OF
        | opcode::NEW_INSTANCE
        | opcode::NEW_ARRAY
        | opcode::GOTO_16
        | opcode::IF_EQ..=opcode::IF_LEZ
        | opcode::AGET..=opcode::APUT_SHORT
        | opcode::IGET..=opcode::SPUT_SHORT
        | opcode::ADD_INT..=opcode::REM_DOUBLE
        | opcode::ADD_INT_LIT16..=opcode::XOR_INT_LIT16
        | opcode::ADD_INT_LIT8..=opcode::USHR_INT_LIT8
        | opcode::CONST_METHOD_HANDLE
        | opcode::CONST_METHOD_TYPE => 2,

        // Format 31i, 31t, 32x, 35c, 3rc (3 units = 6 bytes)
        opcode::MOVE_16
        | opcode::MOVE_WIDE_16
        | opcode::MOVE_OBJECT_16
        | opcode::CONST
        | opcode::CONST_WIDE_32
        | opcode::CONST_STRING_JUMBO
        | opcode::FILLED_NEW_ARRAY
        | opcode::FILLED_NEW_ARRAY_RANGE
        | opcode::FILL_ARRAY_DATA
        | opcode::PACKED_SWITCH
        | opcode::SPARSE_SWITCH
        | opcode::GOTO_32
        | opcode::CMPL_FLOAT..=opcode::CMP_LONG
        | opcode::INVOKE_VIRTUAL..=opcode::INVOKE_INTERFACE
        | opcode::INVOKE_VIRTUAL_RANGE..=opcode::INVOKE_INTERFACE_RANGE
        | opcode::INVOKE_POLYMORPHIC
        | opcode::INVOKE_POLYMORPHIC_RANGE
        | opcode::INVOKE_CUSTOM
        | opcode::INVOKE_CUSTOM_RANGE => 3,

        // Format 51l (5 units = 10 bytes)
        opcode::CONST_WIDE => 5,

        // Invalid/unused opcodes
        _ => 0,
    }
}

/// Check if opcode is a return instruction.
pub fn is_return(op: u8) -> bool {
    matches!(
        op,
        opcode::RETURN_VOID | opcode::RETURN | opcode::RETURN_WIDE | opcode::RETURN_OBJECT
    )
}

/// Check if opcode is a branch instruction.
pub fn is_branch(op: u8) -> bool {
    matches!(
        op,
        opcode::GOTO
            | opcode::GOTO_16
            | opcode::GOTO_32
            | opcode::PACKED_SWITCH
            | opcode::SPARSE_SWITCH
            | opcode::IF_EQ..=opcode::IF_LEZ
    )
}

/// Check if opcode is an invoke instruction.
pub fn is_invoke(op: u8) -> bool {
    matches!(
        op,
        opcode::INVOKE_VIRTUAL..=opcode::INVOKE_INTERFACE
            | opcode::INVOKE_VIRTUAL_RANGE..=opcode::INVOKE_INTERFACE_RANGE
            | opcode::INVOKE_POLYMORPHIC..=opcode::INVOKE_CUSTOM_RANGE
    )
}

/// Check if opcode is a move instruction.
pub fn is_move(op: u8) -> bool {
    matches!(op, opcode::MOVE..=opcode::MOVE_EXCEPTION)
}

/// Check if opcode is an arithmetic instruction.
pub fn is_arithmetic(op: u8) -> bool {
    matches!(
        op,
        opcode::ADD_INT..=opcode::REM_DOUBLE
            | opcode::ADD_INT_2ADDR..=opcode::REM_DOUBLE_2ADDR
            | opcode::ADD_INT_LIT16..=opcode::USHR_INT_LIT8
    )
}

/// Check if opcode is a field access instruction.
pub fn is_field_access(op: u8) -> bool {
    matches!(op, opcode::IGET..=opcode::SPUT_SHORT)
}

/// Check if opcode is an array access instruction.
pub fn is_array_access(op: u8) -> bool {
    matches!(op, opcode::AGET..=opcode::APUT_SHORT)
}

/// Score likelihood of Dalvik bytecode.
///
/// Analyzes raw bytes for patterns characteristic of Dalvik:
/// - Valid opcode sequences
/// - 2-byte aligned instructions
/// - Common instruction patterns
pub fn score(data: &[u8]) -> i64 {
    if data.len() < 2 {
        return 0;
    }

    let mut total_score: i64 = 0;
    let mut i = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;

    // Dalvik bytecode is 2-byte aligned
    while i + 1 < data.len() {
        let op = data[i];
        let size = instruction_size(op);

        if size == 0 {
            invalid_count += 1;
            i += 2; // Skip one code unit
            continue;
        }

        let byte_size = size * 2;
        if i + byte_size > data.len() {
            break;
        }

        valid_count += 1;

        // Score common patterns
        match op {
            // Very common: return instructions
            opcode::RETURN_VOID => total_score += 10,
            opcode::RETURN | opcode::RETURN_OBJECT => total_score += 8,

            // Very common: invoke instructions
            opcode::INVOKE_VIRTUAL | opcode::INVOKE_DIRECT => total_score += 8,
            opcode::INVOKE_STATIC => total_score += 7,
            opcode::INVOKE_INTERFACE | opcode::INVOKE_SUPER => total_score += 6,

            // Common: field access
            opcode::IGET..=opcode::IPUT_SHORT => total_score += 5,
            opcode::SGET..=opcode::SPUT_SHORT => total_score += 4,

            // Common: move instructions
            opcode::MOVE_RESULT | opcode::MOVE_RESULT_OBJECT => total_score += 5,
            opcode::MOVE..=opcode::MOVE_OBJECT_16 => total_score += 3,

            // Common: constants
            opcode::CONST_4 | opcode::CONST_16 => total_score += 4,
            opcode::CONST_STRING => total_score += 5,
            opcode::CONST_CLASS => total_score += 5,

            // Common: control flow
            opcode::IF_EQ..=opcode::IF_LEZ => total_score += 4,
            opcode::GOTO => total_score += 3,

            // Common: object operations
            opcode::NEW_INSTANCE => total_score += 6,
            opcode::CHECK_CAST => total_score += 4,
            opcode::INSTANCE_OF => total_score += 4,

            // Common: arithmetic (2-addr forms are very common)
            opcode::ADD_INT_2ADDR..=opcode::REM_DOUBLE_2ADDR => total_score += 3,
            opcode::ADD_INT..=opcode::REM_DOUBLE => total_score += 2,

            // NOP is valid but should be rare
            opcode::NOP => total_score += 1,

            _ => {}
        }

        i += byte_size;
    }

    // Adjust based on validity ratio
    if valid_count + invalid_count > 0 {
        let validity_ratio = valid_count as f64 / (valid_count + invalid_count) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus for high validity
        if validity_ratio > 0.85 && valid_count > 10 {
            total_score += 15;
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_size() {
        assert_eq!(instruction_size(opcode::NOP), 1);
        assert_eq!(instruction_size(opcode::RETURN_VOID), 1);
        assert_eq!(instruction_size(opcode::CONST_16), 2);
        assert_eq!(instruction_size(opcode::INVOKE_VIRTUAL), 3);
        assert_eq!(instruction_size(opcode::CONST_WIDE), 5);
        assert_eq!(instruction_size(0x73), 0); // Unused opcode
    }

    #[test]
    fn test_is_return() {
        assert!(is_return(opcode::RETURN_VOID));
        assert!(is_return(opcode::RETURN));
        assert!(is_return(opcode::RETURN_OBJECT));
        assert!(!is_return(opcode::GOTO));
    }

    #[test]
    fn test_is_invoke() {
        assert!(is_invoke(opcode::INVOKE_VIRTUAL));
        assert!(is_invoke(opcode::INVOKE_STATIC));
        assert!(is_invoke(opcode::INVOKE_DIRECT_RANGE));
        assert!(!is_invoke(opcode::RETURN_VOID));
    }

    #[test]
    fn test_score_simple_method() {
        // Simple method: const/4 v0, 0; return-void
        let bytecode = [
            0x12, 0x00, // const/4 v0, #0
            0x0E, 0x00, // return-void
        ];
        let s = score(&bytecode);
        assert!(s > 0, "Valid Dalvik code should score positive");
    }

    #[test]
    fn test_score_invoke_pattern() {
        // invoke-virtual {v0}, method@0001; return-void
        let bytecode = [
            0x6E, 0x10, 0x01, 0x00, 0x00, 0x00, // invoke-virtual
            0x0E, 0x00, // return-void
        ];
        let s = score(&bytecode);
        assert!(s > 5, "Invoke + return should score well");
    }

    #[test]
    fn test_score_invalid() {
        // All unused opcodes (0x73)
        let bytecode = [0x73, 0x73, 0x73, 0x73];
        let s = score(&bytecode);
        assert_eq!(s, 0, "Invalid bytecode should score 0");
    }
}
