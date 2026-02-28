//! Java Virtual Machine (JVM) bytecode analysis.
//!
//! JVM bytecode is a stack-based instruction set used by the Java Virtual Machine.
//! Instructions are variable length (1-5+ bytes), with single-byte opcodes and
//! optional operands. The bytecode is big-endian.

/// JVM opcode constants.
pub mod opcode {
    // Constants
    /// Push null reference onto stack.
    pub const ACONST_NULL: u8 = 0x01;
    /// Push int constant -1.
    pub const ICONST_M1: u8 = 0x02;
    /// Push int constant 0.
    pub const ICONST_0: u8 = 0x03;
    /// Push int constant 1.
    pub const ICONST_1: u8 = 0x04;
    /// Push int constant 2.
    pub const ICONST_2: u8 = 0x05;
    /// Push int constant 3.
    pub const ICONST_3: u8 = 0x06;
    /// Push int constant 4.
    pub const ICONST_4: u8 = 0x07;
    /// Push int constant 5.
    pub const ICONST_5: u8 = 0x08;
    /// Push long constant 0.
    pub const LCONST_0: u8 = 0x09;
    /// Push long constant 1.
    pub const LCONST_1: u8 = 0x0A;
    /// Push float constant 0.0.
    pub const FCONST_0: u8 = 0x0B;
    /// Push float constant 1.0.
    pub const FCONST_1: u8 = 0x0C;
    /// Push float constant 2.0.
    pub const FCONST_2: u8 = 0x0D;
    /// Push double constant 0.0.
    pub const DCONST_0: u8 = 0x0E;
    /// Push double constant 1.0.
    pub const DCONST_1: u8 = 0x0F;
    /// Push byte as int.
    pub const BIPUSH: u8 = 0x10;
    /// Push short as int.
    pub const SIPUSH: u8 = 0x11;
    /// Push from constant pool (1-byte index).
    pub const LDC: u8 = 0x12;
    /// Push from constant pool (2-byte index).
    pub const LDC_W: u8 = 0x13;
    /// Push long/double from constant pool.
    pub const LDC2_W: u8 = 0x14;

    // Loads
    /// Load int from local variable.
    pub const ILOAD: u8 = 0x15;
    /// Load long from local variable.
    pub const LLOAD: u8 = 0x16;
    /// Load float from local variable.
    pub const FLOAD: u8 = 0x17;
    /// Load double from local variable.
    pub const DLOAD: u8 = 0x18;
    /// Load reference from local variable.
    pub const ALOAD: u8 = 0x19;
    /// Load int from local 0.
    pub const ILOAD_0: u8 = 0x1A;
    /// Load int from local 1.
    pub const ILOAD_1: u8 = 0x1B;
    /// Load int from local 2.
    pub const ILOAD_2: u8 = 0x1C;
    /// Load int from local 3.
    pub const ILOAD_3: u8 = 0x1D;
    /// Load long from local 0.
    pub const LLOAD_0: u8 = 0x1E;
    /// Load long from local 1.
    pub const LLOAD_1: u8 = 0x1F;
    /// Load long from local 2.
    pub const LLOAD_2: u8 = 0x20;
    /// Load long from local 3.
    pub const LLOAD_3: u8 = 0x21;
    /// Load float from local 0.
    pub const FLOAD_0: u8 = 0x22;
    /// Load float from local 1.
    pub const FLOAD_1: u8 = 0x23;
    /// Load float from local 2.
    pub const FLOAD_2: u8 = 0x24;
    /// Load float from local 3.
    pub const FLOAD_3: u8 = 0x25;
    /// Load double from local 0.
    pub const DLOAD_0: u8 = 0x26;
    /// Load double from local 1.
    pub const DLOAD_1: u8 = 0x27;
    /// Load double from local 2.
    pub const DLOAD_2: u8 = 0x28;
    /// Load double from local 3.
    pub const DLOAD_3: u8 = 0x29;
    /// Load reference from local 0.
    pub const ALOAD_0: u8 = 0x2A;
    /// Load reference from local 1.
    pub const ALOAD_1: u8 = 0x2B;
    /// Load reference from local 2.
    pub const ALOAD_2: u8 = 0x2C;
    /// Load reference from local 3.
    pub const ALOAD_3: u8 = 0x2D;
    /// Load int from array.
    pub const IALOAD: u8 = 0x2E;
    /// Load long from array.
    pub const LALOAD: u8 = 0x2F;
    /// Load float from array.
    pub const FALOAD: u8 = 0x30;
    /// Load double from array.
    pub const DALOAD: u8 = 0x31;
    /// Load reference from array.
    pub const AALOAD: u8 = 0x32;
    /// Load byte from array.
    pub const BALOAD: u8 = 0x33;
    /// Load char from array.
    pub const CALOAD: u8 = 0x34;
    /// Load short from array.
    pub const SALOAD: u8 = 0x35;

    // Stores
    /// Store int to local variable.
    pub const ISTORE: u8 = 0x36;
    /// Store long to local variable.
    pub const LSTORE: u8 = 0x37;
    /// Store float to local variable.
    pub const FSTORE: u8 = 0x38;
    /// Store double to local variable.
    pub const DSTORE: u8 = 0x39;
    /// Store reference to local variable.
    pub const ASTORE: u8 = 0x3A;
    /// Store int to local 0.
    pub const ISTORE_0: u8 = 0x3B;
    /// Store int to local 1.
    pub const ISTORE_1: u8 = 0x3C;
    /// Store int to local 2.
    pub const ISTORE_2: u8 = 0x3D;
    /// Store int to local 3.
    pub const ISTORE_3: u8 = 0x3E;
    /// Store long to local 0.
    pub const LSTORE_0: u8 = 0x3F;
    /// Store long to local 1.
    pub const LSTORE_1: u8 = 0x40;
    /// Store long to local 2.
    pub const LSTORE_2: u8 = 0x41;
    /// Store long to local 3.
    pub const LSTORE_3: u8 = 0x42;
    /// Store float to local 0.
    pub const FSTORE_0: u8 = 0x43;
    /// Store float to local 1.
    pub const FSTORE_1: u8 = 0x44;
    /// Store float to local 2.
    pub const FSTORE_2: u8 = 0x45;
    /// Store float to local 3.
    pub const FSTORE_3: u8 = 0x46;
    /// Store double to local 0.
    pub const DSTORE_0: u8 = 0x47;
    /// Store double to local 1.
    pub const DSTORE_1: u8 = 0x48;
    /// Store double to local 2.
    pub const DSTORE_2: u8 = 0x49;
    /// Store double to local 3.
    pub const DSTORE_3: u8 = 0x4A;
    /// Store reference to local 0.
    pub const ASTORE_0: u8 = 0x4B;
    /// Store reference to local 1.
    pub const ASTORE_1: u8 = 0x4C;
    /// Store reference to local 2.
    pub const ASTORE_2: u8 = 0x4D;
    /// Store reference to local 3.
    pub const ASTORE_3: u8 = 0x4E;
    /// Store int to array.
    pub const IASTORE: u8 = 0x4F;
    /// Store long to array.
    pub const LASTORE: u8 = 0x50;
    /// Store float to array.
    pub const FASTORE: u8 = 0x51;
    /// Store double to array.
    pub const DASTORE: u8 = 0x52;
    /// Store reference to array.
    pub const AASTORE: u8 = 0x53;
    /// Store byte to array.
    pub const BASTORE: u8 = 0x54;
    /// Store char to array.
    pub const CASTORE: u8 = 0x55;
    /// Store short to array.
    pub const SASTORE: u8 = 0x56;

    // Stack operations
    /// Pop top stack value.
    pub const POP: u8 = 0x57;
    /// Pop top two stack values (or one category 2).
    pub const POP2: u8 = 0x58;
    /// Duplicate top stack value.
    pub const DUP: u8 = 0x59;
    /// Duplicate top and insert below second.
    pub const DUP_X1: u8 = 0x5A;
    /// Duplicate top and insert below third.
    pub const DUP_X2: u8 = 0x5B;
    /// Duplicate top two and insert below.
    pub const DUP2: u8 = 0x5C;
    /// Duplicate top two and insert below third.
    pub const DUP2_X1: u8 = 0x5D;
    /// Duplicate top two and insert below fourth.
    pub const DUP2_X2: u8 = 0x5E;
    /// Swap top two stack values.
    pub const SWAP: u8 = 0x5F;

    // Arithmetic
    /// Add int.
    pub const IADD: u8 = 0x60;
    /// Add long.
    pub const LADD: u8 = 0x61;
    /// Add float.
    pub const FADD: u8 = 0x62;
    /// Add double.
    pub const DADD: u8 = 0x63;
    /// Subtract int.
    pub const ISUB: u8 = 0x64;
    /// Subtract long.
    pub const LSUB: u8 = 0x65;
    /// Subtract float.
    pub const FSUB: u8 = 0x66;
    /// Subtract double.
    pub const DSUB: u8 = 0x67;
    /// Multiply int.
    pub const IMUL: u8 = 0x68;
    /// Multiply long.
    pub const LMUL: u8 = 0x69;
    /// Multiply float.
    pub const FMUL: u8 = 0x6A;
    /// Multiply double.
    pub const DMUL: u8 = 0x6B;
    /// Divide int.
    pub const IDIV: u8 = 0x6C;
    /// Divide long.
    pub const LDIV: u8 = 0x6D;
    /// Divide float.
    pub const FDIV: u8 = 0x6E;
    /// Divide double.
    pub const DDIV: u8 = 0x6F;
    /// Remainder int.
    pub const IREM: u8 = 0x70;
    /// Remainder long.
    pub const LREM: u8 = 0x71;
    /// Remainder float.
    pub const FREM: u8 = 0x72;
    /// Remainder double.
    pub const DREM: u8 = 0x73;
    /// Negate int.
    pub const INEG: u8 = 0x74;
    /// Negate long.
    pub const LNEG: u8 = 0x75;
    /// Negate float.
    pub const FNEG: u8 = 0x76;
    /// Negate double.
    pub const DNEG: u8 = 0x77;
    /// Shift left int.
    pub const ISHL: u8 = 0x78;
    /// Shift left long.
    pub const LSHL: u8 = 0x79;
    /// Arithmetic shift right int.
    pub const ISHR: u8 = 0x7A;
    /// Arithmetic shift right long.
    pub const LSHR: u8 = 0x7B;
    /// Logical shift right int.
    pub const IUSHR: u8 = 0x7C;
    /// Logical shift right long.
    pub const LUSHR: u8 = 0x7D;
    /// Bitwise AND int.
    pub const IAND: u8 = 0x7E;
    /// Bitwise AND long.
    pub const LAND: u8 = 0x7F;
    /// Bitwise OR int.
    pub const IOR: u8 = 0x80;
    /// Bitwise OR long.
    pub const LOR: u8 = 0x81;
    /// Bitwise XOR int.
    pub const IXOR: u8 = 0x82;
    /// Bitwise XOR long.
    pub const LXOR: u8 = 0x83;
    /// Increment local variable by constant.
    pub const IINC: u8 = 0x84;

    // Conversions
    /// Convert int to long.
    pub const I2L: u8 = 0x85;
    /// Convert int to float.
    pub const I2F: u8 = 0x86;
    /// Convert int to double.
    pub const I2D: u8 = 0x87;
    /// Convert long to int.
    pub const L2I: u8 = 0x88;
    /// Convert long to float.
    pub const L2F: u8 = 0x89;
    /// Convert long to double.
    pub const L2D: u8 = 0x8A;
    /// Convert float to int.
    pub const F2I: u8 = 0x8B;
    /// Convert float to long.
    pub const F2L: u8 = 0x8C;
    /// Convert float to double.
    pub const F2D: u8 = 0x8D;
    /// Convert double to int.
    pub const D2I: u8 = 0x8E;
    /// Convert double to long.
    pub const D2L: u8 = 0x8F;
    /// Convert double to float.
    pub const D2F: u8 = 0x90;
    /// Convert int to byte.
    pub const I2B: u8 = 0x91;
    /// Convert int to char.
    pub const I2C: u8 = 0x92;
    /// Convert int to short.
    pub const I2S: u8 = 0x93;

    // Comparisons
    /// Compare long.
    pub const LCMP: u8 = 0x94;
    /// Compare float (NaN -> -1).
    pub const FCMPL: u8 = 0x95;
    /// Compare float (NaN -> 1).
    pub const FCMPG: u8 = 0x96;
    /// Compare double (NaN -> -1).
    pub const DCMPL: u8 = 0x97;
    /// Compare double (NaN -> 1).
    pub const DCMPG: u8 = 0x98;
    /// Branch if int equals zero.
    pub const IFEQ: u8 = 0x99;
    /// Branch if int not equal to zero.
    pub const IFNE: u8 = 0x9A;
    /// Branch if int less than zero.
    pub const IFLT: u8 = 0x9B;
    /// Branch if int greater than or equal to zero.
    pub const IFGE: u8 = 0x9C;
    /// Branch if int greater than zero.
    pub const IFGT: u8 = 0x9D;
    /// Branch if int less than or equal to zero.
    pub const IFLE: u8 = 0x9E;
    /// Branch if ints equal.
    pub const IF_ICMPEQ: u8 = 0x9F;
    /// Branch if ints not equal.
    pub const IF_ICMPNE: u8 = 0xA0;
    /// Branch if int less than.
    pub const IF_ICMPLT: u8 = 0xA1;
    /// Branch if int greater or equal.
    pub const IF_ICMPGE: u8 = 0xA2;
    /// Branch if int greater than.
    pub const IF_ICMPGT: u8 = 0xA3;
    /// Branch if int less or equal.
    pub const IF_ICMPLE: u8 = 0xA4;
    /// Branch if references equal.
    pub const IF_ACMPEQ: u8 = 0xA5;
    /// Branch if references not equal.
    pub const IF_ACMPNE: u8 = 0xA6;

    // Control
    /// Branch unconditionally.
    pub const GOTO: u8 = 0xA7;
    /// Jump subroutine (deprecated).
    pub const JSR: u8 = 0xA8;
    /// Return from subroutine (deprecated).
    pub const RET: u8 = 0xA9;
    /// Table switch.
    pub const TABLESWITCH: u8 = 0xAA;
    /// Lookup switch.
    pub const LOOKUPSWITCH: u8 = 0xAB;
    /// Return int.
    pub const IRETURN: u8 = 0xAC;
    /// Return long.
    pub const LRETURN: u8 = 0xAD;
    /// Return float.
    pub const FRETURN: u8 = 0xAE;
    /// Return double.
    pub const DRETURN: u8 = 0xAF;
    /// Return reference.
    pub const ARETURN: u8 = 0xB0;
    /// Return void.
    pub const RETURN: u8 = 0xB1;

    // References
    /// Get static field.
    pub const GETSTATIC: u8 = 0xB2;
    /// Put static field.
    pub const PUTSTATIC: u8 = 0xB3;
    /// Get instance field.
    pub const GETFIELD: u8 = 0xB4;
    /// Put instance field.
    pub const PUTFIELD: u8 = 0xB5;
    /// Invoke virtual method.
    pub const INVOKEVIRTUAL: u8 = 0xB6;
    /// Invoke special method (init, super, private).
    pub const INVOKESPECIAL: u8 = 0xB7;
    /// Invoke static method.
    pub const INVOKESTATIC: u8 = 0xB8;
    /// Invoke interface method.
    pub const INVOKEINTERFACE: u8 = 0xB9;
    /// Invoke dynamic method.
    pub const INVOKEDYNAMIC: u8 = 0xBA;
    /// Create new object.
    pub const NEW: u8 = 0xBB;
    /// Create new array of primitives.
    pub const NEWARRAY: u8 = 0xBC;
    /// Create new array of references.
    pub const ANEWARRAY: u8 = 0xBD;
    /// Get array length.
    pub const ARRAYLENGTH: u8 = 0xBE;
    /// Throw exception.
    pub const ATHROW: u8 = 0xBF;
    /// Check cast.
    pub const CHECKCAST: u8 = 0xC0;
    /// Check instance of.
    pub const INSTANCEOF: u8 = 0xC1;
    /// Enter monitor.
    pub const MONITORENTER: u8 = 0xC2;
    /// Exit monitor.
    pub const MONITOREXIT: u8 = 0xC3;

    // Extended
    /// Wide prefix (extends local var index to 2 bytes).
    pub const WIDE: u8 = 0xC4;
    /// Create multidimensional array.
    pub const MULTIANEWARRAY: u8 = 0xC5;
    /// Branch if reference is null.
    pub const IFNULL: u8 = 0xC6;
    /// Branch if reference is not null.
    pub const IFNONNULL: u8 = 0xC7;
    /// Branch unconditionally (wide).
    pub const GOTO_W: u8 = 0xC8;
    /// Jump subroutine (wide, deprecated).
    pub const JSR_W: u8 = 0xC9;

    // Reserved
    /// Breakpoint (for debuggers).
    pub const BREAKPOINT: u8 = 0xCA;
    /// Implementation-dependent 1.
    pub const IMPDEP1: u8 = 0xFE;
    /// Implementation-dependent 2.
    pub const IMPDEP2: u8 = 0xFF;
}

/// Array type codes for NEWARRAY instruction.
pub mod array_type {
    /// boolean array.
    pub const T_BOOLEAN: u8 = 4;
    /// char array.
    pub const T_CHAR: u8 = 5;
    /// float array.
    pub const T_FLOAT: u8 = 6;
    /// double array.
    pub const T_DOUBLE: u8 = 7;
    /// byte array.
    pub const T_BYTE: u8 = 8;
    /// short array.
    pub const T_SHORT: u8 = 9;
    /// int array.
    pub const T_INT: u8 = 10;
    /// long array.
    pub const T_LONG: u8 = 11;
}

/// Get the length of a JVM bytecode instruction.
///
/// Returns 0 for invalid opcodes or variable-length instructions that
/// need more context (tableswitch, lookupswitch, wide).
pub fn instruction_length(bytecode: &[u8], offset: usize) -> usize {
    if offset >= bytecode.len() {
        return 0;
    }

    let op = bytecode[offset];

    match op {
        // 1-byte instructions (no operands)
        opcode::ACONST_NULL
        | opcode::ICONST_M1..=opcode::ICONST_5
        | opcode::LCONST_0..=opcode::LCONST_1
        | opcode::FCONST_0..=opcode::FCONST_2
        | opcode::DCONST_0..=opcode::DCONST_1
        | opcode::ILOAD_0..=opcode::ALOAD_3
        | opcode::IALOAD..=opcode::SALOAD
        | opcode::ISTORE_0..=opcode::ASTORE_3
        | opcode::IASTORE..=opcode::SASTORE
        | opcode::POP..=opcode::SWAP
        | opcode::IADD..=opcode::LXOR
        | opcode::I2L..=opcode::I2S
        | opcode::LCMP..=opcode::DCMPG
        | opcode::IRETURN..=opcode::RETURN
        | opcode::ARRAYLENGTH
        | opcode::ATHROW
        | opcode::MONITORENTER
        | opcode::MONITOREXIT
        | 0x00 => 1, // NOP is 0x00

        // 2-byte instructions (1 byte operand)
        opcode::BIPUSH
        | opcode::LDC
        | opcode::ILOAD
        | opcode::LLOAD
        | opcode::FLOAD
        | opcode::DLOAD
        | opcode::ALOAD
        | opcode::ISTORE
        | opcode::LSTORE
        | opcode::FSTORE
        | opcode::DSTORE
        | opcode::ASTORE
        | opcode::RET
        | opcode::NEWARRAY => 2,

        // 3-byte instructions (2 byte operand)
        opcode::SIPUSH
        | opcode::LDC_W
        | opcode::LDC2_W
        | opcode::IINC
        | opcode::IFEQ..=opcode::IF_ACMPNE
        | opcode::GOTO
        | opcode::JSR
        | opcode::GETSTATIC..=opcode::INVOKESTATIC
        | opcode::NEW
        | opcode::ANEWARRAY
        | opcode::CHECKCAST
        | opcode::INSTANCEOF
        | opcode::IFNULL
        | opcode::IFNONNULL => 3,

        // 4-byte instructions
        opcode::MULTIANEWARRAY => 4,

        // 5-byte instructions
        opcode::INVOKEINTERFACE | opcode::INVOKEDYNAMIC | opcode::GOTO_W | opcode::JSR_W => 5,

        // Variable-length instructions
        opcode::TABLESWITCH | opcode::LOOKUPSWITCH => {
            // These need alignment and have variable number of entries
            // Return 0 to indicate variable length
            0
        }

        opcode::WIDE => {
            // Wide prefix: depends on the following opcode
            if offset + 1 >= bytecode.len() {
                return 0;
            }
            let wide_op = bytecode[offset + 1];
            match wide_op {
                opcode::ILOAD
                | opcode::LLOAD
                | opcode::FLOAD
                | opcode::DLOAD
                | opcode::ALOAD
                | opcode::ISTORE
                | opcode::LSTORE
                | opcode::FSTORE
                | opcode::DSTORE
                | opcode::ASTORE
                | opcode::RET => 4, // wide + opcode + 2-byte index
                opcode::IINC => 6, // wide + opcode + 2-byte index + 2-byte const
                _ => 0,
            }
        }

        // Reserved/invalid
        _ => 0,
    }
}

/// Check if opcode is a return instruction.
pub fn is_return(op: u8) -> bool {
    matches!(
        op,
        opcode::IRETURN
            | opcode::LRETURN
            | opcode::FRETURN
            | opcode::DRETURN
            | opcode::ARETURN
            | opcode::RETURN
    )
}

/// Check if opcode is a branch instruction.
pub fn is_branch(op: u8) -> bool {
    matches!(
        op,
        opcode::IFEQ
            ..=opcode::IF_ACMPNE
                | opcode::GOTO
                | opcode::JSR
                | opcode::IFNULL
                | opcode::IFNONNULL
                | opcode::GOTO_W
                | opcode::JSR_W
    )
}

/// Check if opcode is an invoke instruction.
pub fn is_invoke(op: u8) -> bool {
    matches!(
        op,
        opcode::INVOKEVIRTUAL
            | opcode::INVOKESPECIAL
            | opcode::INVOKESTATIC
            | opcode::INVOKEINTERFACE
            | opcode::INVOKEDYNAMIC
    )
}

/// Check if opcode is a load instruction.
pub fn is_load(op: u8) -> bool {
    matches!(
        op,
        opcode::ILOAD..=opcode::ALOAD_3 | opcode::IALOAD..=opcode::SALOAD
    )
}

/// Check if opcode is a store instruction.
pub fn is_store(op: u8) -> bool {
    matches!(
        op,
        opcode::ISTORE..=opcode::ASTORE_3 | opcode::IASTORE..=opcode::SASTORE
    )
}

/// Check if opcode is an arithmetic instruction.
pub fn is_arithmetic(op: u8) -> bool {
    matches!(op, opcode::IADD..=opcode::LXOR)
}

/// Check if opcode is a stack manipulation instruction.
pub fn is_stack_op(op: u8) -> bool {
    matches!(op, opcode::POP..=opcode::SWAP)
}

/// Score likelihood of JVM bytecode.
///
/// Analyzes raw bytes for patterns characteristic of JVM bytecode:
/// - Valid opcode sequences
/// - Common instruction patterns
/// - Method structure (load this, invoke, return)
pub fn score(data: &[u8]) -> i64 {
    let mut total_score: i64 = 0;
    let mut i = 0;
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    let mut return_count = 0u32;
    let mut invoke_count = 0u32;

    // Cross-architecture penalties
    // JVM bytecodes cover 78% of byte space, so almost any data looks valid.
    // Penalize distinctive patterns from ISAs JVM commonly steals from.
    {
        // 32-bit BE patterns (MIPS, SPARC, PPC)
        let mut j = 0;
        while j + 3 < data.len() {
            let be32 = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            if be32 == 0x03E00008 {
                total_score -= 20;
            } // MIPS JR $ra
            if (be32 & 0xFFFF0000) == 0x27BD0000 {
                total_score -= 10;
            } // MIPS ADDIU $sp
            if (be32 & 0xFFFF0000) == 0xAFBF0000 {
                total_score -= 10;
            } // MIPS SW $ra
            if (be32 & 0xFFFF0000) == 0x8FBF0000 {
                total_score -= 10;
            } // MIPS LW $ra
            if be32 == 0x4E800020 {
                total_score -= 15;
            } // PPC BLR
            if be32 == 0x81C7E008 {
                total_score -= 15;
            } // SPARC RET
              // MIPS BE generic opcodes (bits 31:26)
            {
                let mips_op = (be32 >> 26) & 0x3F;
                match mips_op {
                    0x23 => total_score -= 4, // LW
                    0x2B => total_score -= 4, // SW
                    0x09 => total_score -= 3, // ADDIU
                    0x0F => total_score -= 4, // LUI
                    0x03 => total_score -= 5, // JAL
                    _ => {}
                }
            }
            j += 4;
        }
        // 32-bit LE patterns (MIPS LE, RISC-V, LoongArch, AArch64)
        j = 0;
        while j + 3 < data.len() {
            let le32 = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
            // AArch64
            if le32 == 0xD65F03C0 {
                total_score -= 15;
            } // AArch64 RET
            if le32 == 0xD503201F {
                total_score -= 10;
            } // AArch64 NOP
              // LoongArch
            if le32 == 0x4C000020 {
                total_score -= 12;
            } // LoongArch JIRL ra (RET)
            if le32 == 0x03400000 {
                total_score -= 10;
            } // LoongArch NOP
              // MIPS LE
            if le32 == 0x03E00008 {
                total_score -= 20;
            } // MIPS JR $ra
            if (le32 & 0xFFFF0000) == 0x27BD0000 {
                total_score -= 10;
            } // MIPS ADDIU $sp,$sp,N
            if (le32 & 0xFFFF0000) == 0xAFBF0000 {
                total_score -= 10;
            } // MIPS SW $ra,N($sp)
            if (le32 & 0xFFFF0000) == 0x8FBF0000 {
                total_score -= 10;
            } // MIPS LW $ra,N($sp)
              // MIPS generic opcodes (bits 31:26) - common instructions
            {
                let mips_op = (le32 >> 26) & 0x3F;
                match mips_op {
                    0x23 => total_score -= 4, // LW (any register)
                    0x2B => total_score -= 4, // SW (any register)
                    0x09 => total_score -= 3, // ADDIU (any register)
                    0x0F => total_score -= 4, // LUI
                    0x03 => total_score -= 5, // JAL
                    _ => {}
                }
            }
            // RISC-V
            if le32 == 0x00000013 {
                total_score -= 12;
            } // RISC-V NOP (addi x0,x0,0)
            if le32 == 0x00008067 {
                total_score -= 15;
            } // RISC-V RET (jalr x0,ra,0)
            j += 4;
        }
        // 16-bit LE patterns (Thumb, MSP430)
        j = 0;
        while j + 1 < data.len() {
            let hw = u16::from_le_bytes([data[j], data[j + 1]]);
            if hw == 0x4770 {
                total_score -= 12;
            } // Thumb BX LR
            if hw == 0x4130 {
                total_score -= 12;
            } // MSP430 RET
            if hw == 0xBF00 {
                total_score -= 6;
            } // Thumb NOP
            if hw == 0x4303 {
                total_score -= 6;
            } // MSP430 NOP
            if hw == 0x1300 {
                total_score -= 10;
            } // MSP430 RETI
            if (hw & 0xFF00) == 0xB500 {
                total_score -= 5;
            } // Thumb PUSH {.., LR}
            if (hw & 0xFF00) == 0xBD00 {
                total_score -= 5;
            } // Thumb POP {.., PC}
            j += 2;
        }
    }

    let mut zero_run = 0u32;

    while i < data.len() {
        let op = data[i];
        let len = instruction_length(data, i);

        if len == 0 {
            // Invalid or variable-length instruction
            invalid_count += 1;
            i += 1;
            continue;
        }

        if i + len > data.len() {
            break;
        }

        valid_count += 1;

        // Score common patterns
        match op {
            // Very common: load this (aload_0) at method start
            opcode::ALOAD_0 => total_score += 5,

            // Common: other local loads/stores
            opcode::ILOAD_0..=opcode::ALOAD_3 => total_score += 2,
            opcode::ISTORE_0..=opcode::ASTORE_3 => total_score += 2,

            // Common: returns
            opcode::RETURN => {
                total_score += 8;
                return_count += 1;
            }
            opcode::IRETURN..=opcode::ARETURN => {
                total_score += 6;
                return_count += 1;
            }

            // Common: invocations
            opcode::INVOKEVIRTUAL | opcode::INVOKESPECIAL => {
                total_score += 7;
                invoke_count += 1;
            }
            opcode::INVOKESTATIC => {
                total_score += 6;
                invoke_count += 1;
            }
            opcode::INVOKEINTERFACE => {
                total_score += 5;
                invoke_count += 1;
            }

            // Common: field access
            opcode::GETFIELD | opcode::PUTFIELD => total_score += 5,
            opcode::GETSTATIC | opcode::PUTSTATIC => total_score += 4,

            // Common: constants
            opcode::ICONST_0..=opcode::ICONST_5 => total_score += 3,
            opcode::ACONST_NULL => total_score += 4,

            // Common: stack ops
            opcode::DUP => total_score += 3,
            opcode::POP => total_score += 2,

            // Common: branches
            opcode::IFEQ..=opcode::IFLE => total_score += 3,
            opcode::IF_ICMPEQ..=opcode::IF_ACMPNE => total_score += 3,
            opcode::GOTO => total_score += 2,

            // Common: arithmetic
            opcode::IADD..=opcode::DADD => total_score += 2,
            opcode::ISUB..=opcode::DSUB => total_score += 2,

            // Common: new object/array
            opcode::NEW => total_score += 5,
            opcode::NEWARRAY | opcode::ANEWARRAY => total_score += 4,

            // Less common but valid
            opcode::CHECKCAST | opcode::INSTANCEOF => total_score += 3,
            opcode::ATHROW => total_score += 4,
            opcode::MONITORENTER | opcode::MONITOREXIT => total_score += 3,

            // NOP is valid but rare — penalize long runs (MIPS NOP sleds are all zeros)
            0x00 => {
                zero_run += 1;
                if zero_run <= 4 {
                    total_score += 1;
                } else {
                    total_score -= 1;
                }
            }

            // Penalize unrecognized opcodes more heavily
            _ => {
                total_score -= 2;
            }
        }

        if op != 0x00 {
            zero_run = 0;
        }

        i += len;
    }

    // Adjust score based on validity ratio
    if valid_count + invalid_count > 0 {
        let validity_ratio = valid_count as f64 / (valid_count + invalid_count) as f64;
        total_score = (total_score as f64 * validity_ratio) as i64;

        // Bonus for high validity (strict threshold)
        if validity_ratio > 0.95 && valid_count > 20 {
            total_score += 20;
        }

        // Structural requirement: real JVM bytecode must have returns and invokes.
        // Count these during the actual instruction walk (not raw byte scan) to avoid
        // false positives from other ISA data containing those byte values as operands.
        if valid_count > 20 {
            if return_count == 0 && invoke_count == 0 {
                total_score = (total_score as f64 * 0.15) as i64;
            } else if return_count == 0 {
                // Invokes but no returns - suspicious
                total_score = (total_score as f64 * 0.40) as i64;
            }
        }
    }

    total_score.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_length() {
        // 1-byte instructions
        assert_eq!(instruction_length(&[0x00], 0), 1); // nop
        assert_eq!(instruction_length(&[opcode::ACONST_NULL], 0), 1);
        assert_eq!(instruction_length(&[opcode::RETURN], 0), 1);
        assert_eq!(instruction_length(&[opcode::IADD], 0), 1);

        // 2-byte instructions
        assert_eq!(instruction_length(&[opcode::BIPUSH, 0x42], 0), 2);
        assert_eq!(instruction_length(&[opcode::LDC, 0x01], 0), 2);

        // 3-byte instructions
        assert_eq!(instruction_length(&[opcode::SIPUSH, 0x00, 0x01], 0), 3);
        assert_eq!(instruction_length(&[opcode::GOTO, 0x00, 0x10], 0), 3);
        assert_eq!(
            instruction_length(&[opcode::INVOKEVIRTUAL, 0x00, 0x01], 0),
            3
        );

        // 5-byte instructions
        assert_eq!(
            instruction_length(&[opcode::INVOKEINTERFACE, 0, 0, 0, 0], 0),
            5
        );
    }

    #[test]
    fn test_is_return() {
        assert!(is_return(opcode::RETURN));
        assert!(is_return(opcode::IRETURN));
        assert!(is_return(opcode::ARETURN));
        assert!(!is_return(opcode::GOTO));
        assert!(!is_return(opcode::INVOKEVIRTUAL));
    }

    #[test]
    fn test_is_branch() {
        assert!(is_branch(opcode::GOTO));
        assert!(is_branch(opcode::IFEQ));
        assert!(is_branch(opcode::IFNULL));
        assert!(!is_branch(opcode::RETURN));
        assert!(!is_branch(opcode::IADD));
    }

    #[test]
    fn test_is_invoke() {
        assert!(is_invoke(opcode::INVOKEVIRTUAL));
        assert!(is_invoke(opcode::INVOKESPECIAL));
        assert!(is_invoke(opcode::INVOKESTATIC));
        assert!(!is_invoke(opcode::RETURN));
        assert!(!is_invoke(opcode::GOTO));
    }

    #[test]
    fn test_score_simple_method() {
        // Simple method: aload_0, getfield #1, ireturn
        let bytecode = [
            opcode::ALOAD_0,  // Load this
            opcode::GETFIELD, // Get field
            0x00,
            0x01,
            opcode::IRETURN, // Return int
        ];
        let s = score(&bytecode);
        assert!(s > 0, "Score should be positive for valid bytecode");
    }

    #[test]
    fn test_score_constructor() {
        // Typical constructor pattern: aload_0, invokespecial <init>, return
        let bytecode = [
            opcode::ALOAD_0,       // Load this
            opcode::INVOKESPECIAL, // Call super.<init>
            0x00,
            0x01,
            opcode::RETURN, // Return void
        ];
        let s = score(&bytecode);
        assert!(s > 10, "Constructor pattern should score well");
    }

    #[test]
    fn test_score_invalid() {
        // Invalid bytecode (all 0xFE = impdep1)
        let bytecode = [0xFE, 0xFE, 0xFE, 0xFE];
        let s = score(&bytecode);
        assert_eq!(s, 0, "Invalid bytecode should score 0");
    }
}
