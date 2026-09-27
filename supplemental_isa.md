# Supplementary ISA Encoding Reference: Six Architectures

This document provides comprehensive instruction set architecture encoding reference data for Dalvik, Blackfin, IA-64/Itanium, VAX, Intel i860, and Cell SPU—matching the detail level of established architecture references.

---

## Dalvik (Android VM Bytecode)

The Dalvik virtual machine uses a register-based architecture with **16-bit code units** as the fundamental storage element. All bytecode is little-endian within each unit, with opcodes occupying the low 8 bits of the first unit.

### Bytecode structure and register model

Dalvik instructions consist of one to five 16-bit code units. The opcode always resides in the low 8 bits of the first unit, enabling rapid dispatch. Registers are 32-bit wide, with adjacent pairs used for 64-bit values. The virtual register space spans **v0–v65535**, though instruction format constraints limit accessible registers in most operations.

Parameter registers map to the last N registers of an invocation frame, with `this` passed as p0 in instance methods. Register field widths vary by format: 4-bit fields access v0–v15, 8-bit fields access v0–v255, and 16-bit fields span the full range.

### Instruction format types

| Format | Layout | Description |
|--------|--------|-------------|
| **10x** | `ØØ\|op` | No arguments (nop, return-void) |
| **10t** | `AA\|op` | 8-bit signed branch offset |
| **11n** | `B\|A\|op` | 4-bit register + 4-bit signed literal |
| **11x** | `AA\|op` | Single 8-bit register reference |
| **12x** | `B\|A\|op` | Two 4-bit register references |
| **20t** | `ØØ\|op AAAA` | 16-bit signed branch offset |
| **21c** | `AA\|op BBBB` | 8-bit register + 16-bit constant pool index |
| **21h** | `AA\|op BBBB` | 8-bit register + 16-bit high literal |
| **21s** | `AA\|op BBBB` | 8-bit register + 16-bit signed literal |
| **21t** | `AA\|op BBBB` | 8-bit register + 16-bit branch offset |
| **22b** | `AA\|op CC\|BB` | 8-bit dest + 8-bit src + 8-bit literal |
| **22c** | `B\|A\|op CCCC` | Two 4-bit registers + 16-bit pool index |
| **22s** | `B\|A\|op CCCC` | Two 4-bit registers + 16-bit signed literal |
| **22t** | `B\|A\|op CCCC` | Two 4-bit registers + 16-bit branch |
| **22x** | `AA\|op BBBB` | 8-bit + 16-bit register references |
| **23x** | `AA\|op CC\|BB` | Three 8-bit register references |
| **31i** | `AA\|op BBBBlo BBBBhi` | 8-bit register + 32-bit literal |
| **31t** | `AA\|op BBBBlo BBBBhi` | 8-bit register + 32-bit branch offset |
| **32x** | `ØØ\|op AAAA BBBB` | Two 16-bit register references |
| **35c** | `A\|G\|op BBBB F\|E\|D\|C` | Variable-count invoke (up to 5 args) |
| **3rc** | `AA\|op BBBB CCCC` | Range invoke (8-bit count + register range) |
| **51l** | `AA\|op BBBB×4` | 8-bit register + 64-bit literal |

### Complete opcode map (0x00–0xFF)

**Data movement (0x00–0x0D):**
```
0x00 nop            0x01 move vA,vB        0x02 move/from16       0x03 move/16
0x04 move-wide      0x05 move-wide/from16  0x06 move-wide/16      0x07 move-object
0x08 move-obj/from16 0x09 move-obj/16      0x0A move-result       0x0B move-result-wide
0x0C move-result-obj 0x0D move-exception
```

**Returns (0x0E–0x11):**
```
0x0E return-void    0x0F return            0x10 return-wide       0x11 return-object
```

**Constants (0x12–0x1C):**
```
0x12 const/4        0x13 const/16          0x14 const             0x15 const/high16
0x16 const-wide/16  0x17 const-wide/32     0x18 const-wide        0x19 const-wide/high16
0x1A const-string   0x1B const-string/jumbo 0x1C const-class
```

**Type operations (0x1D–0x27):**
```
0x1D monitor-enter  0x1E monitor-exit      0x1F check-cast        0x20 instance-of
0x21 array-length   0x22 new-instance      0x23 new-array         0x24 filled-new-array
0x25 filled-new-array/range               0x26 fill-array-data    0x27 throw
```

**Control flow (0x28–0x3D):**
```
0x28 goto           0x29 goto/16           0x2A goto/32           0x2B packed-switch
0x2C sparse-switch  0x2D-0x31 cmpkind      0x32-0x37 if-test      0x38-0x3D if-testz
```

**Array access (0x44–0x51):** aget/aput variants for int, wide, object, boolean, byte, char, short

**Field access (0x52–0x6D):** iget/iput and sget/sput variants for all types

**Invoke operations (0x6E–0x78):**
```
0x6E invoke-virtual   0x6F invoke-super      0x70 invoke-direct    0x71 invoke-static
0x72 invoke-interface 0x74-0x78 invoke-*/range variants
```

**Arithmetic (0x7B–0xE2):** Unary ops (0x7B–0x8F), binary ops (0x90–0xAF), 2-addr forms (0xB0–0xCF), literal forms (0xD0–0xE2)

**Extended operations (0xFA–0xFF):**
```
0xFA invoke-polymorphic  0xFB invoke-polymorphic/range
0xFC invoke-custom       0xFD invoke-custom/range
0xFE const-method-handle 0xFF const-method-type
```

### Pseudo-instruction payloads

Switch and fill-array payloads use alignment-sensitive formats:

**Packed-switch (ident 0x0100):** `size` entries starting at `first_key`, each with 32-bit relative target  
**Sparse-switch (ident 0x0200):** `size` key-target pairs, keys sorted ascending  
**Fill-array-data (ident 0x0300):** `element_width` × `size` bytes of raw data

---

## Blackfin DSP (Analog Devices)

The Blackfin architecture employs variable-length instructions (**16, 32, or 64 bits**) optimized for signal processing. The 64-bit format enables **multi-issue execution** of up to three operations in parallel.

### Instruction encoding formats

**16-bit format:**
```
┌─────────────────────────────────────────────┐
│  Bits 15-12   │   Bits 11-0               │
│   OPCODE      │   OPERANDS/IMMEDIATES      │
└─────────────────────────────────────────────┘
```

**32-bit format:**
```
┌─────────────────────────────────────────────────────────────────┐
│ Bits 31-24  │ Bits 23-20  │ Bits 19-16  │ Bits 15-0           │
│  OPCODE     │   SUBOP     │   REGS      │   OPERANDS/IMM       │
└─────────────────────────────────────────────────────────────────┘
```

**64-bit multi-issue packet:**
```
┌─────────────────┬─────────────────┬─────────────────────────────┐
│ Bits 63-48      │ Bits 47-32      │ Bits 31-0                   │
│ 16-bit (slot2)  │ 16-bit (slot1)  │ 32-bit DSP32 (slot0)        │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### Register encoding

**Data registers (3-bit):** R0–R7 encoded as 000–111  
**Pointer registers (3-bit):** P0–P5 (000–101), SP (110), FP (111)  
**Index registers (2-bit):** I0–I3 encoded as 00–11  
**Modify registers (2-bit):** M0–M3 encoded as 00–11

### Opcode maps by instruction class

**16-bit opcode ranges:**
| Range | Class |
|-------|-------|
| 0x0000–0x0FFF | System control, NOP, returns |
| 0x1000–0x1FFF | Conditional branches |
| 0x2000–0x2FFF | Short jumps (JUMP.S, pcrel13m2) |
| 0x3000–0x3FFF | Short calls (CALL.S) |
| 0x4000–0x4FFF | ALU operations, bit manipulations |
| 0x5000–0x5FFF | Pointer/register arithmetic |
| 0x9000–0x9FFF | Load/store (Preg, Ireg addressing) |

**32-bit opcode ranges:**
| Range | Class |
|-------|-------|
| 0xC0xxxxxx | MAC/DSP multiply-accumulate |
| 0xC1xxxxxx | Dual MAC operations |
| 0xC2xxxxxx | Vector ALU (parallel add/sub) |
| 0xC6xxxxxx | Bit manipulation (deposit, extract) |
| 0xC8xxxxxx | Video pixel operations |
| 0xC9xxxxxx | SAA (sum of absolute differences) |
| 0xE0xxxxxx | Load/store with large offset |
| 0xE2xxxxxx | Long jump (JUMP.L, pcrel25m2) |
| 0xE3xxxxxx | Long call (CALL.L) |

### MAC instruction encoding

**32-bit MAC format:**
```
┌────────────────────────────────────────────────────────────────────┐
│ Bits 31-24 │ 23-20  │ 19-18 │ 17-15 │ 14-12 │ 11-8    │ 7-0      │
│ 0xC0-0xC3  │ AccMode│ AccSel│ Src1  │ Src2  │Modifiers│ Options  │
└────────────────────────────────────────────────────────────────────┘
AccMode: 00=assign, 01=add, 10=subtract, 11=A1 operation
AccSel: A0 (0) or A1 (1)
Modifiers: M(fractional), FU(unsigned), IS(saturate), W32(width), IH(half)
```

### Parallel issue slot encoding

| Slot | Width | Instruction Types | Addressing |
|------|-------|-------------------|------------|
| Slot0 | 32-bit | MAC, dual-16 ALU, vector, SIMD | N/A |
| Slot1 | 16-bit | Register loads | I-reg or P-reg |
| Slot2 | 16-bit | Register loads/stores | P-reg or I-reg |

Parallel syntax: `instr1 || instr2 || instr3 ;`

### Memory access encoding

**Addressing mode bits:**
| Mode | Encoding | Pattern |
|------|----------|---------|
| Indirect | 00 | [Preg] |
| Post-increment | 01 | [Preg++] |
| Post-decrement | 10 | [Preg--] |
| Indexed | 11 | [Preg + offset] |

**DAG circular buffer registers:** Each set (0–3) contains I (index), L (length), B (base), M (modify) registers. When L ≠ 0, automatic modulo addressing occurs.

---

## IA-64 / Itanium

Itanium uses a **VLIW-style EPIC architecture** with 128-bit instruction bundles containing three 41-bit instruction slots plus a 5-bit template field.

### Bundle format (128 bits)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                 128-bit Bundle                                        │
├───────────────────────┬───────────────────────┬───────────────────────┬──────────────┤
│   Instruction Slot 2  │   Instruction Slot 1  │   Instruction Slot 0  │   Template   │
│       (41 bits)       │       (41 bits)       │       (41 bits)       │   (5 bits)   │
│     bits 127:87       │      bits 86:46       │       bits 45:5       │   bits 4:0   │
└───────────────────────┴───────────────────────┴───────────────────────┴──────────────┘
```

Bundles are **16-byte aligned**; branches target only slot 0 of a bundle.

### Template encoding (bits 0–4)

| Template | Hex | Slot 0 | Slot 1 | Slot 2 | Stops |
|----------|-----|--------|--------|--------|-------|
| 00000 | 0x00 | M | I | I | none |
| 00001 | 0x01 | M | I | I | after 2 |
| 00010 | 0x02 | M | I | I | after 1 |
| 00011 | 0x03 | M | I | I | after 1,2 |
| 00100 | 0x04 | M | L | X | none (MLX) |
| 00101 | 0x05 | M | L | X | after 2 |
| 01000 | 0x08 | M | M | I | none |
| 01001 | 0x09 | M | M | I | after 2 |
| 01010 | 0x0A | M | M | I | after 0 |
| 01011 | 0x0B | M | M | I | after 0,2 |
| 01100 | 0x0C | M | F | I | none |
| 01101 | 0x0D | M | F | I | after 2 |
| 01110 | 0x0E | M | M | F | none |
| 01111 | 0x0F | M | M | F | after 2 |
| 10000 | 0x10 | M | I | B | none |
| 10001 | 0x11 | M | I | B | after 2 |
| 10010 | 0x12 | M | B | B | none |
| 10011 | 0x13 | M | B | B | after 2 |
| 10110 | 0x16 | B | B | B | none |
| 10111 | 0x17 | B | B | B | after 2 |
| 11000 | 0x18 | M | M | B | none |
| 11001 | 0x19 | M | M | B | after 2 |
| 11100 | 0x1C | M | F | B | none |
| 11101 | 0x1D | M | F | B | after 2 |

**Execution unit types:**
- **M** – Memory unit (loads, stores, semaphores, some ALU)
- **I** – Integer unit (shifts, multimedia, complex integer)
- **A** – ALU (executes in M or I unit)
- **F** – Floating-point unit
- **B** – Branch unit
- **L+X** – Long immediate (82-bit double-slot, e.g., `movl`)

### Instruction slot format (41 bits)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Major Opcode │     Instruction-Specific Fields     │ Qualifying Predicate │
│   (4 bits)   │            (31 bits)                │       (6 bits)       │
│  bits 40:37  │           bits 36:6                 │      bits 5:0        │
└─────────────────────────────────────────────────────────────────────────┘
```

**ALU/A-unit format:**
```
Bits: 40-37 │ 36-33 │ 32-27 │ 26-20 │ 19-13 │ 12-6  │ 5-0
       Op   │ x2a   │  r3   │  r2   │  r1   │ x2b   │  qp
```

**Memory (M-unit) load format:**
```
Bits: 40-37 │ 36-31 │ 30-27 │ 26-20 │ 19-13 │ 12-6  │ 5-0
       4    │  x6   │   r3  │ hint  │  r1   │   x   │  qp
```

**Branch (B-unit) format:**
```
Bits: 40-37 │ 36-35 │ 34-33 │ 32-13 │ 12-9 │ 8 │ 7 │ 6 │ 5-0
       Op   │ btype │  wh   │ imm20 │  s   │ p │ 0 │ d │  qp
```

### Major opcode assignments

| Opcode | M-Unit | I-Unit | F-Unit | B-Unit |
|--------|--------|--------|--------|--------|
| 0 | System/MemMgmt | Misc I | Misc FP | IP-rel Branch |
| 1 | System/MemMgmt | — | — | IP-rel Branch |
| 4 | Load/Store | Load/Store | — | Indirect Br |
| 5 | Load/Store | Deposit/Shift | — | Indirect Call |
| 7 | Variable/MM | Variable/MM | — | Nop/Hint |
| 8 | Int ALU | Int ALU | FP Mult/Add | — |
| 9 | Int ALU | Int ALU | FP Mult/Sub | — |
| A | Int ALU/MM | Shift/Add | FP Neg Mult | — |
| C | Int Compare | Int Compare | — | — |
| D | Int Compare | Int Compare | — | — |
| E | FP Compare | FP Compare | FP Compare | — |

### Predicate and register encoding

**Qualifying predicate (qp):** 6 bits (bits 0–5), encoding p0–p63. **p0 is hardwired TRUE**.

**General registers:** 7-bit field encodes r0–r127
- r0 always reads as zero
- r0–r31: Static registers
- r32–r127: Stacked/rotating (managed by RSE)

**Current Frame Marker (CFM):**
```
Bits: 37-32 │ 31-25 │ 24-18 │ 17-14 │ 13-7 │ 6-0
     rrb.pr │rrb.fr │rrb.gr│  sor  │ sol  │ sof
```
- **sof:** Size of frame (0–96)
- **sol:** Size of locals
- **sor:** Size of rotating region (×8)
- **rrb.gr/fr/pr:** Rotating register bases

### Speculation encoding

Load speculation uses the **x6 extension** field:

| x6 Value | Load Type | Description |
|----------|-----------|-------------|
| 0x00 | ld.none | Normal load |
| 0x01 | ld.s | Speculative (control) |
| 0x02 | ld.a | Advanced (data) |
| 0x03 | ld.sa | Speculative advanced |
| 0x05–0x07 | ld.acq | Acquire (ordering) |

**NaT (Not a Thing) bit:** Each GR has a 1-bit NaT flag, set on speculative load failure. Check instructions (chk.s, chk.a) test NaT and branch to recovery code.

---

## VAX (DEC)

VAX features a **variable-length CISC design** with instructions ranging from 1 to 37 bytes. The architecture provides orthogonal addressing modes encoded consistently across all instructions.

### Opcode format

**Single-byte opcodes (0x00–0xFB):** Primary instruction space  
**Two-byte opcodes (0xFD–0xFF prefix):** Extended instruction space for G/H floating-point

```
Single-byte:     ┌──────────────┐
                 │  opcode (8b) │
                 └──────────────┘

Two-byte:        ┌──────────┬──────────┐
                 │ FD/FE/FF │ opcode2  │
                 └──────────┴──────────┘
```

### Primary opcode map (selected ranges)

**System/Control (0x00–0x0F):**
```
00 HALT    01 NOP     02 REI     03 BPT     04 RET     05 RSB
06 LDPCTX  07 SVPCTX  08 CVTPS   09 CVTSP   0A INDEX   0B CRC
0C PROBER  0D PROBEW  0E INSQUE  0F REMQUE
```

**Branches (0x10–0x1F):** Byte displacement conditionals
```
10 BSBB    11 BRB     12 BNEQ    13 BEQL    14 BGTR    15 BLEQ
16 JSB     17 JMP     18 BGEQ    19 BLSS    1A BGTRU   1B BLEQU
1C BVC     1D BVS     1E BCC     1F BCS
```

**Byte operations (0x80–0x9F):**
```
80 ADDB2   81 ADDB3   82 SUBB2   83 SUBB3   84 MULB2   85 MULB3
86 DIVB2   87 DIVB3   88 BISB2   89 BISB3   8A BICB2   8B BICB3
8C XORB2   8D XORB3   8E MNEGB   8F CASEB   90 MOVB    91 CMPB
92 MCOMB   93 BITB    94 CLRB    95 TSTB    96 INCB    97 DECB
```

**Word operations (0xA0–0xBF):** Same pattern as byte, data type = word  
**Longword operations (0xC0–0xDF):** Same pattern, data type = longword

**Bit field/branches (0xE0–0xF9):**
```
E0 BBS     E1 BBC     E2 BBSS    E3 BBCS    E4 BBSC    E5 BBCC
EA FFS     EB FFC     EC CMPV    ED CMPZV   EE EXTV    EF EXTZV
F0 INSV    F1 ACBL    F2 AOBLSS  F3 AOBLEQ  F4 SOBGEQ  F5 SOBGTR
```

**Escape prefixes (0xFD–0xFF):**
```
FC XFC (extended function call)
FD xx (G/H floating-point extended)
FE xx (reserved)
FF xx (customer-defined)
```

### FD-prefix extended opcodes

**G_floating operations:**
```
FD 40 ADDG2   FD 41 ADDG3   FD 42 SUBG2   FD 43 SUBG3
FD 44 MULG2   FD 45 MULG3   FD 46 DIVG2   FD 47 DIVG3
FD 50 MOVG    FD 51 CMPG    FD 52 MNEGG   FD 53 TSTG
```

**H_floating operations:**
```
FD 60 ADDH2   FD 61 ADDH3   FD 62 SUBH2   FD 63 SUBH3
FD 64 MULH2   FD 65 MULH3   FD 66 DIVH2   FD 67 DIVH3
FD 70 MOVH    FD 71 CMPH    FD 72 MNEGH   FD 73 TSTH
```

### Operand specifier encoding

Each operand uses an 8-bit specifier byte:
```
┌──────────────────────────────┐
│ Mode [7:4]  │ Register [3:0] │
└──────────────────────────────┘
```

**Addressing mode encoding:**

| Mode | Bits 7:4 | Name | Format | Extension |
|------|----------|------|--------|-----------|
| 0–3 | 0000–0011 | Literal | 6-bit literal | none |
| 4 | 0100 | Indexed | [Rx][base] | +base spec |
| 5 | 0101 | Register | Rn | none |
| 6 | 0110 | Register Deferred | (Rn) | none |
| 7 | 0111 | Autodecrement | -(Rn) | none |
| 8 | 1000 | Autoincrement | (Rn)+ | none |
| 9 | 1001 | Autoincrement Deferred | @(Rn)+ | none |
| A | 1010 | Byte Displacement | d(Rn) | +1 byte |
| B | 1011 | Byte Disp. Deferred | @d(Rn) | +1 byte |
| C | 1100 | Word Displacement | d(Rn) | +2 bytes |
| D | 1101 | Word Disp. Deferred | @d(Rn) | +2 bytes |
| E | 1110 | Long Displacement | d(Rn) | +4 bytes |
| F | 1111 | Long Disp. Deferred | @d(Rn) | +4 bytes |

**PC-relative modes (Register = 15):**
| Specifier | Mode | Description |
|-----------|------|-------------|
| 0x8F | Immediate | Literal follows instruction |
| 0x9F | Absolute | 32-bit address follows |
| 0xAF | Byte Relative | PC + 8-bit signed |
| 0xCF | Word Relative | PC + 16-bit signed |
| 0xEF | Long Relative | PC + 32-bit |

### Variable-length instruction structure

```
┌─────────┬────────────┬────────────┬─────┬────────────┐
│ Opcode  │ Operand 1  │ Operand 2  │ ... │ Operand N  │
│(1-2 B)  │ Specifier  │ Specifier  │     │ Specifier  │
└─────────┴────────────┴────────────┴─────┴────────────┘
```

**Operand count by instruction type:**
- No operands: HALT, NOP, REI, RET, RSB
- One operand: CLRx, TSTx, INCx, DECx, JMP
- Two operands: MOVx, CMPx, ADDx2, BISx2
- Three operands: ADDx3, MULx3, MOVC3
- Four operands: ADDP4, EDIV, EMUL
- Five operands: MOVC5, CMPC5
- Six operands: ADDP6, INDEX, MOVTUC

**Maximum instruction length:** 37 bytes (limited by 6 operands × ~6 bytes each + 1 byte opcode)

---

## Intel i860

The i860 uses a **fixed 32-bit instruction format** with dual-instruction mode capability, allowing simultaneous execution of one core instruction and one FPU/graphics instruction.

### Instruction format types

**Register-Register (R-type):**
```
┌────────┬────────┬────────┬────────┬─────────────┐
│ OPCODE │  src2  │  dest  │  src1  │    func     │
│ 6 bits │ 5 bits │ 5 bits │ 5 bits │   11 bits   │
│ 31-26  │ 25-21  │ 20-16  │ 15-11  │    10-0     │
└────────┴────────┴────────┴────────┴─────────────┘
```

**Register-Immediate (I-type):**
```
┌────────┬────────┬────────┬──────────────────────┐
│ OPCODE │  src2  │  dest  │     immediate        │
│ 6 bits │ 5 bits │ 5 bits │      16 bits         │
│ 31-26  │ 25-21  │ 20-16  │        15-0          │
└────────┴────────┴────────┴──────────────────────┘
```

**Control Transfer:**
```
┌────────┬────────────────────────────────────────┐
│ OPCODE │            26-bit offset               │
│ 6 bits │              (target)                  │
│ 31-26  │               25-0                     │
└────────┴────────────────────────────────────────┘
```

**FPU Instruction Format:**
```
┌────────┬────────┬────────┬────────┬───┬───┬─────┬────────┐
│ OPCODE │ fsrc2  │ fdest  │ fsrc1  │ P │ D │ S R │  func  │
│ 6 bits │ 5 bits │ 5 bits │ 5 bits │ 1 │ 1 │ 2b  │ 6 bits │
│ 31-26  │ 25-21  │ 20-16  │ 15-11  │10 │ 9 │ 8-7 │  5-0   │
└────────┴────────┴────────┴────────┴───┴───┴─────┴────────┘

P = Pipeline mode (1=pipelined, 0=scalar)
D = Dual-instruction mode toggle
S = Source precision (0=single, 1=double)
R = Result precision (0=single, 1=double)
```

### Primary opcode map (bits 31–26)

| Opcode | Hex | Instruction Class |
|--------|-----|-------------------|
| 000000–001111 | 0x00–0x0F | Load/Store Integer |
| 010000–010111 | 0x10–0x17 | Core Arithmetic |
| 011000–011111 | 0x18–0x1F | Control Transfer |
| 100000–100111 | 0x20–0x27 | Load/Store Floating-Point |
| 101000–101111 | 0x28–0x2F | Load FP Pipelined |
| 110000–110111 | 0x30–0x37 | FPU Instructions |
| 111000–111111 | 0x38–0x3F | Graphics/Extended |

### Dual-instruction mode

**D-bit (bit 9 in FPU instructions):**
- D=1: Toggle dual-instruction mode
- D=0: Maintain current mode

**PSR dual-mode bits:**
- **DIM (bit 23):** Dual Instruction Mode active flag
- **DS (bit 24):** Delayed Switch pending flag

**Dual-mode operation:** When active, the processor fetches 64 bits per cycle. Lower 32 bits execute in the integer unit; upper 32 bits execute in the FPU.

### Pipeline control

**P-bit (bit 10):** Controls FPU pipeline behavior
- P=1: Pipelined execution (throughput: 1 result/cycle after fill)
- P=0: Scalar execution (result after full latency)

**Pipeline depths:** FP Multiplier: 3 stages; FP Adder: 3 stages

**Pipeline result selector (bits 7–6 in dual-ops):**
| Value | Result Source |
|-------|---------------|
| 00 | Multiplier stage 3 |
| 01 | Adder stage 3 |
| 10 | Intermediate |
| 11 | Reserved |

### FPU opcode breakdown

| Opcode | Mnemonic | Description |
|--------|----------|-------------|
| 110000 | FADD | Floating Add |
| 110001 | FSUB | Floating Subtract |
| 110010 | FMUL | Floating Multiply |
| 110011 | FMLOW | Floating Multiply Low |
| 110100 | FRCP | Floating Reciprocal |
| 110101 | FRSQR | Floating Reciprocal Sqrt |
| 110110 | PFADD | Pipelined FP Add |
| 110111 | PFSUB | Pipelined FP Subtract |
| 111000 | PFMUL | Pipelined FP Multiply |

**Precision encoding (bits 8–7):**
| S | R | Operation |
|---|---|-----------|
| 0 | 0 | Single → Single |
| 0 | 1 | Single → Double |
| 1 | 0 | Double → Single |
| 1 | 1 | Double → Double |

### Graphics instruction formats

**Z-buffer operations (opcode 111100):**
```
┌────────┬────────┬────────┬────────┬──────────┬────────┐
│ 111100 │  src2  │  dest  │  src1  │ reserved │  func  │
│        │ 5 bits │ 5 bits │ 5 bits │  5 bits  │ 5 bits │
└────────┴────────┴────────┴────────┴──────────┴────────┘
func: 00xxx = FZCHKL (less), 01xxx = FZCHKS (less/same)
```

**Pixel operations (opcode 111101):**
```
┌────────┬────────┬────────┬────────┬──────┬─────────┐
│ 111101 │  src2  │  dest  │  src1  │  PS  │  func   │
│        │ 5 bits │ 5 bits │ 5 bits │ 3b   │  5 bits │
└────────┴────────┴────────┴────────┴──────┴─────────┘
PS (bits 10-8): Pixel size (00=8-bit, 01=16-bit, 10=32-bit)
```

### Register encoding

**Integer registers (5-bit):** r0–r31 (r0 always reads as 0)  
**FP registers (5-bit):** f0–f31 (f0/f1 always read as 0.0)

**Double precision pairing:** Even/odd pairs (f0:f1, f2:f3, ... f30:f31)  
**Quad alignment:** f0, f4, f8, f12, f16, f20, f24, f28

---

## Cell SPU (Synergistic Processing Unit)

The Cell SPU uses **six fixed 32-bit instruction formats** with a 128-bit SIMD architecture. All 128 registers are 128 bits wide, enabling massive parallel data processing.

### Instruction format types

**RR Format (Register-Register):**
```
┌────────────┬─────────┬─────────┬─────────┐
│   OPCODE   │   RB    │   RA    │   RT    │
│  (11 bits) │ (7 bits)│ (7 bits)│ (7 bits)│
│   bits 0-10│  11-17  │  18-24  │  25-31  │
└────────────┴─────────┴─────────┴─────────┘
```

**RRR Format (Three Register Operands):**
```
┌─────────┬─────────┬─────────┬─────────┬─────────┐
│ OPCODE  │   RT    │   RB    │   RA    │   RC    │
│ (4 bits)│ (7 bits)│ (7 bits)│ (7 bits)│ (7 bits)│
│  0-3    │  4-10   │  11-17  │  18-24  │  25-31  │
└─────────┴─────────┴─────────┴─────────┴─────────┘
```

**RI7 Format (7-bit Immediate):**
```
┌────────────┬─────────┬─────────┬─────────┐
│   OPCODE   │   I7    │   RA    │   RT    │
│  (11 bits) │ (7 bits)│ (7 bits)│ (7 bits)│
│   0-10     │  11-17  │  18-24  │  25-31  │
└────────────┴─────────┴─────────┴─────────┘
```

**RI10 Format (10-bit Immediate):**
```
┌──────────┬──────────┬─────────┬─────────┐
│  OPCODE  │   I10    │   RA    │   RT    │
│ (8 bits) │ (10 bits)│ (7 bits)│ (7 bits)│
│   0-7    │   8-17   │  18-24  │  25-31  │
└──────────┴──────────┴─────────┴─────────┘
```

**RI16 Format (16-bit Immediate):**
```
┌──────────┬──────────────────┬─────────┐
│  OPCODE  │       I16        │   RT    │
│ (9 bits) │    (16 bits)     │ (7 bits)│
│   0-8    │      9-24        │  25-31  │
└──────────┴──────────────────┴─────────┘
```

**RI18 Format (18-bit Immediate):**
```
┌─────────┬───────────────────┬─────────┐
│ OPCODE  │        I18        │   RT    │
│ (7 bits)│     (18 bits)     │ (7 bits)│
│   0-6   │       7-24        │  25-31  │
└─────────┴───────────────────┴─────────┘
```

### Opcode map by instruction class

**Load/Store Instructions:**
| Mnemonic | Opcode (Binary) | Format |
|----------|-----------------|--------|
| lqd | 00110100 | RI10 |
| lqx | 00111000100 | RR |
| lqa | 001100001 | RI16 |
| lqr | 001100111 | RI16 |
| stqd | 00100100 | RI10 |
| stqx | 00101000100 | RR |
| stqa | 001000001 | RI16 |
| stqr | 001000111 | RI16 |

**Constant Formation:**
| Mnemonic | Opcode | Format | Description |
|----------|--------|--------|-------------|
| il | 010000001 | RI16 | Load word immediate |
| ilh | 010000011 | RI16 | Load halfword immediate |
| ilhu | 010000010 | RI16 | Load halfword upper |
| ila | 0100001 | RI18 | Load address (18-bit) |
| iohl | 011000001 | RI16 | OR halfword lower |
| fsmbi | 001100101 | RI16 | Form select mask bytes |

**Integer Arithmetic:**
| Mnemonic | Opcode | Format |
|----------|--------|--------|
| a | 00011000000 | RR |
| ai | 00011100 | RI10 |
| ah | 00011001000 | RR |
| ahi | 00011101 | RI10 |
| sf | 00001000000 | RR |
| sfi | 00001100 | RI10 |
| mpy | 01111000100 | RR |
| mpyi | 01110100 | RI10 |
| mpya | 1100 | RRR |

**Logical Operations:**
| Mnemonic | Opcode | Format |
|----------|--------|--------|
| and | 00011000001 | RR |
| andi | 00010100 | RI10 |
| or | 00001000001 | RR |
| ori | 00000100 | RI10 |
| xor | 01001000001 | RR |
| xori | 01000100 | RI10 |
| nand | 00011001001 | RR |
| nor | 00001001001 | RR |
| selb | 1000 | RRR |
| shufb | 1011 | RRR |

**Shift/Rotate:**
| Mnemonic | Opcode | Format |
|----------|--------|--------|
| shl | 00001011011 | RR |
| shli | 00001111011 | RI7 |
| rot | 00001011000 | RR |
| roti | 00001111000 | RI7 |
| rotqby | 00111011100 | RR |
| rotqbyi | 00111111100 | RI7 |
| shlqby | 00111011111 | RR |
| shlqbyi | 00111111111 | RI7 |

**Branch Instructions:**
| Mnemonic | Opcode | Format | Description |
|----------|--------|--------|-------------|
| br | 001100100 | RI16 | Branch relative |
| bra | 001100000 | RI16 | Branch absolute |
| brsl | 001100110 | RI16 | Branch and set link |
| brasl | 001100010 | RI16 | Branch abs and set link |
| bi | 00110101000 | RR | Branch indirect |
| bisl | 00110101001 | RR | Branch indirect set link |
| brz | 001000000 | RI16 | Branch if zero |
| brnz | 001000010 | RI16 | Branch if not zero |
| biz | 00100101000 | RR | Branch indirect if zero |

**Floating-Point:**
| Mnemonic | Opcode | Format |
|----------|--------|--------|
| fa | 01011000100 | RR |
| fs | 01011000101 | RR |
| fm | 01011000110 | RR |
| fma | 1110 | RRR |
| fms | 1111 | RRR |
| fnms | 1101 | RRR |
| dfa | 01011001100 | RR |
| dfm | 01011001110 | RR |
| frest | 00110111000 | RR |
| frsqest | 00110111001 | RR |

### SIMD element organization

SPU operations work on 128-bit vectors with element sizes:
- **Byte:** 16 elements (ceqb, cgtb, avgb, absdb, sumb)
- **Halfword:** 8 elements (ah, sfh, ceqh, cgth, roth, shlh)
- **Word:** 4 elements (a, sf, mpy, ceq, cgt, rot, shl, fa, fm)
- **Doubleword:** 2 elements (dfa, dfs, dfm, dfceq, dfcgt)
- **Quadword:** 1 element (rotqby, shlqby, lqd, stqd)

**Shuffle bytes (shufb) control encoding:**
- 0x00–0x7F: Select byte from RA||RB concatenation
- 0x80–0xBF: Fill with 0x00
- 0xC0–0xDF: Fill with 0xFF
- 0xE0–0xFF: Fill with 0x80

### Channel instruction encoding

**rdch (Read Channel):**
```
Opcode: 00000001101 | CA[11:17] | /// | RT[25:31]
```

**wrch (Write Channel):**
```
Opcode: 00100001101 | CA[11:17] | RA[18:24] | ///
```

**rchcnt (Read Channel Count):**
```
Opcode: 00000001111 | CA[11:17] | /// | RT[25:31]
```

**Key channel numbers:**
| Channel | Mnemonic | Function |
|---------|----------|----------|
| 0 | SPU_RdEventStat | Read event status |
| 3 | SPU_RdSigNotify1 | Signal notification 1 |
| 4 | SPU_RdSigNotify2 | Signal notification 2 |
| 28 | SPU_WrOutMbox | Write outbound mailbox |
| 29 | SPU_RdInMbox | Read inbound mailbox |
| 16–21 | MFC_LSA–MFC_Cmd | DMA command setup |
| 24 | MFC_RdTagStat | Read DMA tag status |

### Branch hint encoding

**hbr (Hint for Branch):**
```
Opcode: 0011010110 | P | RO[11:17] | RA[18:24] | ///
P = Prefetch bit; RO = offset to branch; RA = target register
```

**hbra (Hint absolute):**
```
Opcode: 0001000 | RO[7:15,16:17] | I16[9:24]
```

**hbrr (Hint relative):**
```
Opcode: 0001001 | RO[7:15,16:17] | I16[9:24]
```

### Stop and signal

**stop:**
```
Opcode: 00000000000 | TYPE[11:24] | ///
TYPE: 14-bit signal type (0x0000–0x3FFF)
```

**stopd:**
```
Opcode: 00101000000 | RC[11:17] | RB[18:24] | RA[25:31]
Waits for register dependencies before stopping
```

**nop:** Opcode 01000000001 (execute pipe)  
**lnop:** Opcode 00000000001 (load pipe)

### Dual-issue pipeline assignment

| Even Pipeline (Pipe 0) | Odd Pipeline (Pipe 1) |
|------------------------|----------------------|
| FP operations | Loads/stores |
| Byte operations | Branches |
| Shifts/rotates | Hints |
| Immediate loads | Channel operations |
| Logical/compare | Shuffle/select |

**Alignment:** Even at address mod 8 = 0; Odd at address mod 8 = 4 (or reversed)

---

## Conclusion

This reference covers the essential encoding details for six architectures spanning embedded VMs, DSPs, VLIW processors, classical CISC, early superscalar designs, and modern SIMD engines. Each architecture demonstrates distinct encoding philosophies—from Dalvik's compact bytecode to Itanium's explicit parallelism, from VAX's orthogonal addressing to SPU's massive SIMD registers.

Key architectural patterns emerge across these designs: the trade-off between instruction density and decode complexity, the encoding of parallelism hints versus hardware detection, and the balance between regular formats and specialized instructions for domain-specific operations.
