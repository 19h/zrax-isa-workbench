# Supplementary Opcode Reference Tables

## x86/x86-64 Opcode Maps

### One-Byte Opcode Map (No Prefix)

| 0x | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 0A | 0B | 0C | 0D | 0E | 0F |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| 00 | ADD | ADD | ADD | ADD | ADD | ADD | PUSH ES | POP ES | OR | OR | OR | OR | OR | OR | PUSH CS | 2-byte |
| 10 | ADC | ADC | ADC | ADC | ADC | ADC | PUSH SS | POP SS | SBB | SBB | SBB | SBB | SBB | SBB | PUSH DS | POP DS |
| 20 | AND | AND | AND | AND | AND | AND | ES: | DAA | SUB | SUB | SUB | SUB | SUB | SUB | CS: | DAS |
| 30 | XOR | XOR | XOR | XOR | XOR | XOR | SS: | AAA | CMP | CMP | CMP | CMP | CMP | CMP | DS: | AAS |
| 40 | INC/REX | INC/REX | INC/REX | INC/REX | INC/REX | INC/REX | INC/REX | INC/REX | DEC/REX | DEC/REX | DEC/REX | DEC/REX | DEC/REX | DEC/REX | DEC/REX | DEC/REX |
| 50 | PUSH | PUSH | PUSH | PUSH | PUSH | PUSH | PUSH | PUSH | POP | POP | POP | POP | POP | POP | POP | POP |
| 60 | PUSHA | POPA | BOUND | ARPL/MOVSXD | FS: | GS: | 66: | 67: | PUSH | IMUL | PUSH | IMUL | INS | INS | OUTS | OUTS |
| 70 | JO | JNO | JB | JNB | JZ | JNZ | JBE | JNBE | JS | JNS | JP | JNP | JL | JNL | JLE | JNLE |
| 80 | Grp1 | Grp1 | Grp1 | Grp1 | TEST | TEST | XCHG | XCHG | MOV | MOV | MOV | MOV | MOV | LEA | MOV | POP |
| 90 | NOP/XCHG | XCHG | XCHG | XCHG | XCHG | XCHG | XCHG | XCHG | CBW | CWD | CALL | WAIT | PUSHF | POPF | SAHF | LAHF |
| A0 | MOV | MOV | MOV | MOV | MOVS | MOVS | CMPS | CMPS | TEST | TEST | STOS | STOS | LODS | LODS | SCAS | SCAS |
| B0 | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV | MOV |
| C0 | Grp2 | Grp2 | RET | RET | LES | LDS | MOV | MOV | ENTER | LEAVE | RETF | RETF | INT3 | INT | INTO | IRET |
| D0 | Grp2 | Grp2 | Grp2 | Grp2 | AAM | AAD | - | XLAT | ESC | ESC | ESC | ESC | ESC | ESC | ESC | ESC |
| E0 | LOOPNZ | LOOPZ | LOOP | JCXZ | IN | IN | OUT | OUT | CALL | JMP | JMP | JMP | IN | IN | OUT | OUT |
| F0 | LOCK | - | REPNZ | REPZ | HLT | CMC | Grp3 | Grp3 | CLC | STC | CLI | STI | CLD | STD | Grp4 | Grp5 |

### Two-Byte Opcode Map (0F prefix)

| 0x | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 0A | 0B | 0C | 0D | 0E | 0F |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| 00 | Grp6 | Grp7 | LAR | LSL | - | SYSCALL | CLTS | SYSRET | INVD | WBINVD | - | UD2 | - | prefetch | FEMMS | 3DNow! |
| 10 | movups | movups | movlps | movlps | unpcklps | unpckhps | movhps | movhps | prefetch | NOP | NOP | NOP | NOP | NOP | NOP | NOP |
| 20 | MOV CR | MOV DR | MOV CR | MOV DR | - | - | - | - | movaps | movaps | cvtpi2ps | movntps | cvttps2pi | cvtps2pi | ucomiss | comiss |
| 30 | WRMSR | RDTSC | RDMSR | RDPMC | SYSENTER | SYSEXIT | - | GETSEC | 3-byte | - | 3-byte | - | - | - | - | - |
| 40 | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc | CMOVcc |
| 50 | movmskps | sqrtps | rsqrtps | rcpps | andps | andnps | orps | xorps | addps | mulps | cvtps2pd | cvtdq2ps | subps | minps | divps | maxps |
| 60 | punpcklbw | punpcklwd | punpckldq | packsswb | pcmpgtb | pcmpgtw | pcmpgtd | packuswb | punpckhbw | punpckhwd | punpckhdq | packssdw | punpcklqdq | punpckhqdq | movd | movq |
| 70 | pshufw | Grp12 | Grp13 | Grp14 | pcmpeqb | pcmpeqw | pcmpeqd | emms | VMREAD | VMWRITE | - | - | haddpd | hsubpd | movd | movq |
| 80 | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc | Jcc |
| 90 | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc | SETcc |
| A0 | PUSH FS | POP FS | CPUID | BT | SHLD | SHLD | - | - | PUSH GS | POP GS | RSM | BTS | SHRD | SHRD | Grp15 | IMUL |
| B0 | CMPXCHG | CMPXCHG | LSS | BTR | LFS | LGS | MOVZX | MOVZX | - | Grp10 | Grp8 | BTC | BSF | BSR | MOVSX | MOVSX |
| C0 | XADD | XADD | cmpps | movnti | pinsrw | pextrw | shufps | Grp9 | BSWAP | BSWAP | BSWAP | BSWAP | BSWAP | BSWAP | BSWAP | BSWAP |
| D0 | addsubpd | psrlw | psrld | psrlq | paddq | pmullw | movq | pmovmskb | psubusb | psubusw | pminub | pand | paddusb | paddusw | pmaxub | pandn |
| E0 | pavgb | psraw | psrad | pavgw | pmulhuw | pmulhw | cvttpd2dq | movntq | psubsb | psubsw | pminsw | por | paddsb | paddsw | pmaxsw | pxor |
| F0 | lddqu | psllw | pslld | psllq | pmuludq | pmaddwd | psadbw | maskmovq | psubb | psubw | psubd | psubq | paddb | paddw | paddd | - |

### VEX/EVEX Prefix Detection

```
VEX 2-byte (C5):
  Byte 0: C5
  Byte 1: [R̄][vvvv][L][pp]
    R̄ = inverted REX.R
    vvvv = inverted register specifier
    L = 0=128-bit, 1=256-bit
    pp = 00=none, 01=66, 10=F3, 11=F2

VEX 3-byte (C4):
  Byte 0: C4
  Byte 1: [R̄][X̄][B̄][mmmmm]
    mmmmm = map select (01=0F, 02=0F38, 03=0F3A)
  Byte 2: [W][vvvv][L][pp]

EVEX 4-byte (62):
  Byte 0: 62
  Byte 1: [R̄][X̄][B̄][R'̄][00][mm]
  Byte 2: [W][vvvv][1][pp]
  Byte 3: [z][L'L][b][V'̄][aaa]
    z = zeroing/merging
    L'L = 00=128, 01=256, 10=512
    b = broadcast
    aaa = opmask register k0-k7
```

---

## AArch64 Instruction Encoding

### Top-Level Encoding (bits [28:25])

| Bits | Encoding Group |
|------|----------------|
| 100x | Data Processing - Immediate |
| x101 | Branches, Exception, System |
| x1x0 | Loads and Stores |
| x111 | Data Processing - Register |
| 0111 | Data Processing - SIMD/FP |

### Branch Instructions (bits [31:26])

| Pattern | Instruction |
|---------|-------------|
| 000101 | B (unconditional) |
| 100101 | BL (branch with link) |
| 010101 | B.cond (conditional) |
| 110101 | CB{N}Z (compare and branch) |
| 011011 | TB{N}Z (test and branch) |

### System Instructions

| Encoding | Instruction |
|----------|-------------|
| D503201F | NOP |
| D503203F | YIELD |
| D503205F | WFE |
| D503207F | WFI |
| D50320BF | SEV |
| D50320DF | SEVL |
| D503233F | PACIASP |
| D50323BF | AUTIASP |
| D503241F | BTI |
| D503245F | BTI C |
| D503249F | BTI J |
| D50324DF | BTI JC |

### Load/Store Encodings

| Size | Opc | V | Instruction |
|------|-----|---|-------------|
| 00 | 00 | 0 | STRB |
| 00 | 01 | 0 | LDRB |
| 01 | 00 | 0 | STRH |
| 01 | 01 | 0 | LDRH |
| 10 | 00 | 0 | STR (32) |
| 10 | 01 | 0 | LDR (32) |
| 11 | 00 | 0 | STR (64) |
| 11 | 01 | 0 | LDR (64) |

---

## RISC-V Instruction Formats

### Base Instruction Formats (32-bit)

```
R-type: [31:25 funct7][24:20 rs2][19:15 rs1][14:12 funct3][11:7 rd][6:0 opcode]
I-type: [31:20 imm[11:0]][19:15 rs1][14:12 funct3][11:7 rd][6:0 opcode]
S-type: [31:25 imm[11:5]][24:20 rs2][19:15 rs1][14:12 funct3][11:7 imm[4:0]][6:0 opcode]
B-type: [31 imm[12]][30:25 imm[10:5]][24:20 rs2][19:15 rs1][14:12 funct3][11:8 imm[4:1]][7 imm[11]][6:0 opcode]
U-type: [31:12 imm[31:12]][11:7 rd][6:0 opcode]
J-type: [31 imm[20]][30:21 imm[10:1]][20 imm[11]][19:12 imm[19:12]][11:7 rd][6:0 opcode]
```

### Compressed Instruction Formats (16-bit)

```
CR: [15:12 funct4][11:7 rd/rs1][6:2 rs2][1:0 op]
CI: [15:13 funct3][12 imm][11:7 rd/rs1][6:2 imm][1:0 op]
CSS: [15:13 funct3][12:7 imm][6:2 rs2][1:0 op]
CIW: [15:13 funct3][12:5 imm][4:2 rd'][1:0 op]
CL: [15:13 funct3][12:10 imm][9:7 rs1'][6:5 imm][4:2 rd'][1:0 op]
CS: [15:13 funct3][12:10 imm][9:7 rs1'][6:5 imm][4:2 rs2'][1:0 op]
CA: [15:10 funct6][9:7 rd'/rs1'][6:5 funct2][4:2 rs2'][1:0 op]
CB: [15:13 funct3][12:10 offset][9:7 rs1'][6:2 offset][1:0 op]
CJ: [15:13 funct3][12:2 jump target][1:0 op]
```

### Standard Extension Opcodes

| Extension | Opcode | funct3 | funct7 | Operations |
|-----------|--------|--------|--------|------------|
| M | 0110011 | 0-3 | 0000001 | MUL, MULH, MULHSU, MULHU |
| M | 0110011 | 4-7 | 0000001 | DIV, DIVU, REM, REMU |
| A | 0101111 | 010 | varies | LR.W, SC.W, AMO*.W |
| A | 0101111 | 011 | varies | LR.D, SC.D, AMO*.D |
| F | 0000111 | 010 | - | FLW |
| F | 0100111 | 010 | - | FSW |
| F | 1010011 | varies | 00xxxxx | FP single ops |
| D | 0000111 | 011 | - | FLD |
| D | 0100111 | 011 | - | FSD |
| D | 1010011 | varies | 01xxxxx | FP double ops |
| V | 0000111 | varies | - | Vector loads |
| V | 0100111 | varies | - | Vector stores |
| V | 1010111 | varies | - | Vector ops |

---

## MIPS Instruction Encoding

### R-Type Format
```
[31:26 opcode=0][25:21 rs][20:16 rt][15:11 rd][10:6 shamt][5:0 funct]
```

### R-Type Function Codes (opcode=0)

| funct | Instruction |
|-------|-------------|
| 0x00 | SLL |
| 0x02 | SRL |
| 0x03 | SRA |
| 0x04 | SLLV |
| 0x06 | SRLV |
| 0x07 | SRAV |
| 0x08 | JR |
| 0x09 | JALR |
| 0x0A | MOVZ |
| 0x0B | MOVN |
| 0x0C | SYSCALL |
| 0x0D | BREAK |
| 0x0F | SYNC |
| 0x10 | MFHI |
| 0x11 | MTHI |
| 0x12 | MFLO |
| 0x13 | MTLO |
| 0x18 | MULT |
| 0x19 | MULTU |
| 0x1A | DIV |
| 0x1B | DIVU |
| 0x20 | ADD |
| 0x21 | ADDU |
| 0x22 | SUB |
| 0x23 | SUBU |
| 0x24 | AND |
| 0x25 | OR |
| 0x26 | XOR |
| 0x27 | NOR |
| 0x2A | SLT |
| 0x2B | SLTU |

### I-Type Primary Opcodes

| Opcode | Instruction |
|--------|-------------|
| 0x04 | BEQ |
| 0x05 | BNE |
| 0x06 | BLEZ |
| 0x07 | BGTZ |
| 0x08 | ADDI |
| 0x09 | ADDIU |
| 0x0A | SLTI |
| 0x0B | SLTIU |
| 0x0C | ANDI |
| 0x0D | ORI |
| 0x0E | XORI |
| 0x0F | LUI |
| 0x20 | LB |
| 0x21 | LH |
| 0x22 | LWL |
| 0x23 | LW |
| 0x24 | LBU |
| 0x25 | LHU |
| 0x26 | LWR |
| 0x28 | SB |
| 0x29 | SH |
| 0x2A | SWL |
| 0x2B | SW |
| 0x2E | SWR |
| 0x30 | LL |
| 0x38 | SC |

---

## PowerPC Instruction Encoding

### Primary Opcode Map (bits 0-5 in BE)

| Opcode | Instruction Type |
|--------|------------------|
| 2 | TDI |
| 3 | TWI |
| 7 | MULLI |
| 8 | SUBFIC |
| 10 | CMPLI |
| 11 | CMPI |
| 12 | ADDIC |
| 13 | ADDIC. |
| 14 | ADDI |
| 15 | ADDIS |
| 16 | BCx |
| 17 | SC |
| 18 | Bx |
| 19 | CR ops |
| 20 | RLWIMI |
| 21 | RLWINM |
| 23 | RLWNM |
| 24 | ORI |
| 25 | ORIS |
| 26 | XORI |
| 27 | XORIS |
| 28 | ANDI. |
| 29 | ANDIS. |
| 30 | Rotate/Shift (64) |
| 31 | Extended ops |
| 32 | LWZ |
| 33 | LWZU |
| 34 | LBZ |
| 35 | LBZU |
| 36 | STW |
| 37 | STWU |
| 38 | STB |
| 39 | STBU |
| 40 | LHZ |
| 41 | LHZU |
| 42 | LHA |
| 43 | LHAU |
| 44 | STH |
| 45 | STHU |
| 46 | LMW |
| 47 | STMW |
| 48 | LFS |
| 49 | LFSU |
| 50 | LFD |
| 51 | LFDU |
| 52 | STFS |
| 53 | STFSU |
| 54 | STFD |
| 55 | STFDU |
| 58 | LD/LDU/LWA |
| 62 | STD/STDU |
| 59 | FP single |
| 63 | FP double |

---

## s390x Instruction Formats

### Opcode Length Detection

| First byte bits [7:6] | Length |
|-----------------------|--------|
| 00 | 2 bytes |
| 01 | 4 bytes |
| 10 | 4 bytes |
| 11 | 6 bytes |

### Common Opcodes

| Opcode | Mnemonic | Format |
|--------|----------|--------|
| 04 | SPM | RR |
| 05 | BALR | RR |
| 06 | BCTR | RR |
| 07 | BCR | RR |
| 0A | SVC | I |
| 0D | BASR | RR |
| 10-13 | LPR-LNR | RR |
| 14 | NR | RR |
| 15 | CLR | RR |
| 16 | OR | RR |
| 17 | XR | RR |
| 18 | LR | RR |
| 19 | CR | RR |
| 1A | AR | RR |
| 1B | SR | RR |
| 1C | MR | RR |
| 1D | DR | RR |
| 1E | ALR | RR |
| 1F | SLR | RR |
| 41 | LA | RX |
| 43 | IC | RX |
| 44 | EX | RX |
| 45 | BAL | RX |
| 46 | BCT | RX |
| 47 | BC | RX |
| 48 | LH | RX |
| 49 | CH | RX |
| 4A | AH | RX |
| 4B | SH | RX |
| 4C | MH | RX |
| 4D | BAS | RX |
| 4E | CVD | RX |
| 4F | CVB | RX |
| 50 | ST | RX |
| 54 | N | RX |
| 55 | CL | RX |
| 56 | O | RX |
| 57 | X | RX |
| 58 | L | RX |
| 59 | C | RX |
| 5A | A | RX |
| 5B | S | RX |
| 5C | M | RX |
| 5D | D | RX |
| 5E | AL | RX |
| 5F | SL | RX |

### Extended Opcodes (E3xx, ECxx, EDxx)

| Prefix | Extended Opcode | Mnemonic |
|--------|-----------------|----------|
| E3 | 04 | LG |
| E3 | 14 | LGF |
| E3 | 24 | STG |
| E3 | 71 | LAY |
| E3 | 90 | LLGC |
| E3 | 91 | LLGH |
| EC | 54 | RNSBG |
| EC | 55 | RISBG |
| EC | 56 | ROSBG |
| EC | 57 | RXSBG |
| ED | 04 | LDEB |
| ED | 05 | LXDB |
| ED | 14 | SQEB |
| ED | 15 | SQDB |

---

## SPARC Instruction Encoding

### Format Field (bits 31:30)

| Format | Type |
|--------|------|
| 00 | Branches, SETHI |
| 01 | CALL |
| 10 | Arithmetic |
| 11 | Load/Store |

### op3 Field for Format 10 (Arithmetic)

| op3 | Instruction |
|-----|-------------|
| 000000 | ADD |
| 000001 | AND |
| 000010 | OR |
| 000011 | XOR |
| 000100 | SUB |
| 000101 | ANDN |
| 000110 | ORN |
| 000111 | XNOR |
| 001000 | ADDX |
| 001010 | UMUL |
| 001011 | SMUL |
| 001100 | SUBX |
| 001110 | UDIV |
| 001111 | SDIV |
| 010000 | ADDcc |
| 010001 | ANDcc |
| 010010 | ORcc |
| 010011 | XORcc |
| 010100 | SUBcc |
| 011000 | ADDXcc |
| 011100 | SUBXcc |
| 100101 | SLL |
| 100110 | SRL |
| 100111 | SRA |
| 111000 | JMPL |
| 111001 | RETT |
| 111010 | Ticc |
| 111100 | SAVE |
| 111101 | RESTORE |

### op3 Field for Format 11 (Load/Store)

| op3 | Instruction |
|-----|-------------|
| 000000 | LD |
| 000001 | LDUB |
| 000010 | LDUH |
| 000011 | LDD |
| 000100 | ST |
| 000101 | STB |
| 000110 | STH |
| 000111 | STD |
| 001001 | LDSB |
| 001010 | LDSH |
| 001011 | LDSTUB |
| 001111 | SWAP |
| 010000 | LDA |
| 010011 | LDDA |
| 010100 | STA |
| 010111 | STDA |

---

## Embedded Architecture Quick Reference

### AVR Instruction Patterns

| Pattern | Instruction |
|---------|-------------|
| 0000 0000 0000 0000 | NOP |
| 1001 0101 0000 1000 | RET |
| 1001 0101 0001 1000 | RETI |
| 1001 010d dddd 1100 | JMP (32-bit) |
| 1001 010d dddd 1110 | CALL (32-bit) |
| 1100 kkkk kkkk kkkk | RJMP |
| 1101 kkkk kkkk kkkk | RCALL |
| 1001 0101 1001 1000 | BREAK |

### MSP430 Instruction Formats

| Type | Format |
|------|--------|
| Single-op | [15:12] opcode [11:7] - [6] B/W [5:4] As [3:0] reg |
| Two-op | [15:12] opcode [11:8] src [7] Ad [6] B/W [5:4] As [3:0] dst |
| Jump | [15:13] 001 [12:10] cond [9:0] offset |

### Hexagon VLIW Packet Structure

```
Packet: 1-4 instructions, 4-16 bytes
Each instruction: 32 bits

Parse bits (bits 15:14):
  00, 01, 10 = Not end of packet
  11 = End of packet

Instruction classes (bits 31:28):
  0-3 = ALU32
  4-7 = XTYPE/Memory
  8-B = ALU64/M (multiply)
  C-F = Extended
```

---

**END OF SUPPLEMENTARY REFERENCE**
