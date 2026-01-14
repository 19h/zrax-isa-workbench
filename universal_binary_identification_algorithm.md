# Universal Binary Identification Algorithm
## Complete Reference for All ISAs and Extensions

This document provides an exhaustive algorithm for identifying processor architectures, instruction set variants, and extensions from binary files.

---

# Part 1: File Format Detection

## 1.1 Magic Byte Signatures

```
OFFSET 0x00: Read first 16 bytes

ELF:
  [0x00-0x03] = 7F 45 4C 46 ("\x7fELF")
  
PE/COFF:
  [0x00-0x01] = 4D 5A ("MZ")
  At PE offset: 50 45 00 00 ("PE\0\0")

Mach-O:
  [0x00-0x03] = FE ED FA CE (32-bit BE)
  [0x00-0x03] = CE FA ED FE (32-bit LE)
  [0x00-0x03] = FE ED FA CF (64-bit BE)
  [0x00-0x03] = CF FA ED FE (64-bit LE)
  [0x00-0x03] = CA FE BA BE (Universal/Fat binary BE)
  [0x00-0x03] = BE BA FE CA (Universal/Fat binary LE)

XCOFF (AIX):
  [0x00-0x01] = 01 DF (32-bit)
  [0x00-0x01] = 01 F7 (64-bit)

ECOFF (MIPS/Alpha):
  [0x00-0x01] = 01 60 (MIPS LE)
  [0x00-0x01] = 60 01 (MIPS BE)
  [0x00-0x01] = 01 83 (Alpha)
```

---

# Part 2: Complete ELF e_machine Reference

## 2.1 All e_machine Values

| Value | Hex | Name | Architecture |
|-------|-----|------|--------------|
| 0 | 0x00 | EM_NONE | No machine |
| 1 | 0x01 | EM_M32 | AT&T WE 32100 |
| 2 | 0x02 | EM_SPARC | SPARC V7/V8 |
| 3 | 0x03 | EM_386 | Intel 80386 (x86) |
| 4 | 0x04 | EM_68K | Motorola 68000 |
| 5 | 0x05 | EM_88K | Motorola 88000 |
| 6 | 0x06 | EM_IAMCU | Intel MCU |
| 7 | 0x07 | EM_860 | Intel 80860 |
| 8 | 0x08 | EM_MIPS | MIPS I |
| 9 | 0x09 | EM_S370 | IBM System/370 |
| 10 | 0x0A | EM_MIPS_RS3_LE | MIPS RS3000 LE |
| 15 | 0x0F | EM_PARISC | HP PA-RISC |
| 17 | 0x11 | EM_VPP500 | Fujitsu VPP500 |
| 18 | 0x12 | EM_SPARC32PLUS | SPARC V8+ |
| 19 | 0x13 | EM_960 | Intel 80960 |
| 20 | 0x14 | EM_PPC | PowerPC 32-bit |
| 21 | 0x15 | EM_PPC64 | PowerPC 64-bit |
| 22 | 0x16 | EM_S390 | IBM S/390 |
| 23 | 0x17 | EM_SPU | IBM SPU/SPC |
| 36 | 0x24 | EM_V800 | NEC V800 |
| 37 | 0x25 | EM_FR20 | Fujitsu FR20 |
| 38 | 0x26 | EM_RH32 | TRW RH-32 |
| 39 | 0x27 | EM_RCE | Motorola RCE |
| 40 | 0x28 | EM_ARM | ARM 32-bit |
| 41 | 0x29 | EM_ALPHA | DEC Alpha (unofficial) |
| 42 | 0x2A | EM_SH | Hitachi SuperH |
| 43 | 0x2B | EM_SPARCV9 | SPARC V9 64-bit |
| 44 | 0x2C | EM_TRICORE | Siemens TriCore |
| 45 | 0x2D | EM_ARC | ARC (ARCv1) |
| 46 | 0x2E | EM_H8_300 | Hitachi H8/300 |
| 47 | 0x2F | EM_H8_300H | Hitachi H8/300H |
| 48 | 0x30 | EM_H8S | Hitachi H8S |
| 49 | 0x31 | EM_H8_500 | Hitachi H8/500 |
| 50 | 0x32 | EM_IA_64 | Intel IA-64 |
| 51 | 0x33 | EM_MIPS_X | Stanford MIPS-X |
| 52 | 0x34 | EM_COLDFIRE | Motorola ColdFire |
| 53 | 0x35 | EM_68HC12 | Motorola M68HC12 |
| 54 | 0x36 | EM_MMA | Fujitsu MMA |
| 55 | 0x37 | EM_PCP | Siemens PCP |
| 56 | 0x38 | EM_NCPU | Sony nCPU |
| 57 | 0x39 | EM_NDR1 | Denso NDR1 |
| 58 | 0x3A | EM_STARCORE | Motorola StarCore |
| 59 | 0x3B | EM_ME16 | Toyota ME16 |
| 60 | 0x3C | EM_ST100 | STMicro ST100 |
| 61 | 0x3D | EM_TINYJ | TinyJ |
| 62 | 0x3E | EM_X86_64 | AMD x86-64 |
| 63 | 0x3F | EM_PDSP | Sony DSP |
| 64 | 0x40 | EM_PDP10 | DEC PDP-10 |
| 65 | 0x41 | EM_PDP11 | DEC PDP-11 |
| 66 | 0x42 | EM_FX66 | Siemens FX66 |
| 67 | 0x43 | EM_ST9PLUS | STMicro ST9+ |
| 68 | 0x44 | EM_ST7 | STMicro ST7 |
| 69 | 0x45 | EM_68HC16 | Motorola MC68HC16 |
| 70 | 0x46 | EM_68HC11 | Motorola MC68HC11 |
| 71 | 0x47 | EM_68HC08 | Motorola MC68HC08 |
| 72 | 0x48 | EM_68HC05 | Motorola MC68HC05 |
| 73 | 0x49 | EM_SVX | Silicon Graphics SVx |
| 74 | 0x4A | EM_ST19 | STMicro ST19 |
| 75 | 0x4B | EM_VAX | DEC VAX |
| 76 | 0x4C | EM_CRIS | Axis CRIS |
| 77 | 0x4D | EM_JAVELIN | Infineon |
| 78 | 0x4E | EM_FIREPATH | Element 14 |
| 79 | 0x4F | EM_ZSP | LSI Logic DSP |
| 80 | 0x50 | EM_MMIX | MMIX |
| 81 | 0x51 | EM_HUANY | Harvard |
| 82 | 0x52 | EM_PRISM | SiTera Prism |
| 83 | 0x53 | EM_AVR | Atmel AVR |
| 84 | 0x54 | EM_FR30 | Fujitsu FR30 |
| 85 | 0x55 | EM_D10V | Mitsubishi D10V |
| 86 | 0x56 | EM_D30V | Mitsubishi D30V |
| 87 | 0x57 | EM_V850 | NEC V850 |
| 88 | 0x58 | EM_M32R | Mitsubishi M32R |
| 89 | 0x59 | EM_MN10300 | Matsushita MN10300 |
| 90 | 0x5A | EM_MN10200 | Matsushita MN10200 |
| 91 | 0x5B | EM_PJ | picoJava |
| 92 | 0x5C | EM_OPENRISC | OpenRISC |
| 93 | 0x5D | EM_ARC_COMPACT | ARC ARCompact |
| 94 | 0x5E | EM_XTENSA | Tensilica Xtensa |
| 95 | 0x5F | EM_VIDEOCORE | Alphamosaic VideoCore |
| 96 | 0x60 | EM_TMM_GPP | Thompson GPP |
| 97 | 0x61 | EM_NS32K | NS 32000 |
| 98 | 0x62 | EM_TPC | Tenor Network TPC |
| 99 | 0x63 | EM_SNP1K | Trebia SNP 1000 |
| 100 | 0x64 | EM_ST200 | STMicro ST200 |
| 101 | 0x65 | EM_IP2K | Ubicom IP2xxx |
| 102 | 0x66 | EM_MAX | MAX Processor |
| 103 | 0x67 | EM_CR | NS CompactRISC |
| 104 | 0x68 | EM_F2MC16 | Fujitsu F2MC16 |
| 105 | 0x69 | EM_MSP430 | TI MSP430 |
| 106 | 0x6A | EM_BLACKFIN | Analog Devices Blackfin |
| 107 | 0x6B | EM_SE_C33 | Seiko Epson S1C33 |
| 108 | 0x6C | EM_SEP | Sharp embedded |
| 109 | 0x6D | EM_ARCA | Arca RISC |
| 110 | 0x6E | EM_UNICORE | PKU UniCore |
| 111 | 0x6F | EM_EXCESS | eXcess |
| 112 | 0x70 | EM_DXP | Icera Deep Execution |
| 113 | 0x71 | EM_ALTERA_NIOS2 | Altera Nios II |
| 114 | 0x72 | EM_CRX | NS CompactRISC CRX |
| 115 | 0x73 | EM_XGATE | Motorola XGATE |
| 116 | 0x74 | EM_C166 | Infineon C16x |
| 117 | 0x75 | EM_M16C | Renesas M16C |
| 118 | 0x76 | EM_DSPIC30F | Microchip dsPIC30F |
| 119 | 0x77 | EM_CE | Freescale CE |
| 120 | 0x78 | EM_M32C | Renesas M32C |
| 131 | 0x83 | EM_TSK3000 | Altium TSK3000 |
| 132 | 0x84 | EM_RS08 | Freescale RS08 |
| 133 | 0x85 | EM_SHARC | Analog Devices SHARC |
| 134 | 0x86 | EM_ECOG2 | Cyan eCOG2 |
| 135 | 0x87 | EM_SCORE7 | Sunplus S+core7 |
| 136 | 0x88 | EM_DSP24 | NJR 24-bit DSP |
| 137 | 0x89 | EM_VIDEOCORE3 | Broadcom VideoCore III |
| 138 | 0x8A | EM_LATTICEMICO32 | Lattice RISC |
| 139 | 0x8B | EM_SE_C17 | Seiko Epson C17 |
| 140 | 0x8C | EM_TI_C6000 | TI TMS320C6000 |
| 141 | 0x8D | EM_TI_C2000 | TI TMS320C2000 |
| 142 | 0x8E | EM_TI_C5500 | TI TMS320C55x |
| 143 | 0x8F | EM_TI_ARP32 | TI ARP32 |
| 144 | 0x90 | EM_TI_PRU | TI PRU |
| 160 | 0xA0 | EM_MMDSP_PLUS | STMicro VLIW DSP |
| 161 | 0xA1 | EM_CYPRESS_M8C | Cypress M8C |
| 162 | 0xA2 | EM_R32C | Renesas R32C |
| 163 | 0xA3 | EM_TRIMEDIA | NXP TriMedia |
| 164 | 0xA4 | EM_HEXAGON | Qualcomm Hexagon |
| 165 | 0xA5 | EM_8051 | Intel 8051 |
| 166 | 0xA6 | EM_STXP7X | STMicro STxP7x |
| 167 | 0xA7 | EM_NDS32 | Andes NDS32 |
| 168 | 0xA8 | EM_ECOG1 | Cyan eCOG1X |
| 169 | 0xA9 | EM_MAXQ30 | Dallas MAXQ30 |
| 170 | 0xAA | EM_XIMO16 | NJR 16-bit DSP |
| 171 | 0xAB | EM_MANIK | M2000 RISC |
| 172 | 0xAC | EM_CRAYNV2 | Cray NV2 |
| 173 | 0xAD | EM_RX | Renesas RX |
| 174 | 0xAE | EM_METAG | Imagination META |
| 175 | 0xAF | EM_MCST_ELBRUS | MCST Elbrus |
| 176 | 0xB0 | EM_ECOG16 | Cyan eCOG16 |
| 177 | 0xB1 | EM_CR16 | NS CompactRISC CR16 |
| 178 | 0xB2 | EM_ETPU | Freescale ETPU |
| 179 | 0xB3 | EM_SLE9X | Infineon SLE9X |
| 180 | 0xB4 | EM_L10M | Intel L10M |
| 181 | 0xB5 | EM_K10M | Intel K10M |
| 183 | 0xB7 | EM_AARCH64 | ARM 64-bit |
| 185 | 0xB9 | EM_AVR32 | Atmel AVR32 |
| 186 | 0xBA | EM_STM8 | STMicro STM8 |
| 187 | 0xBB | EM_TILE64 | Tilera TILE64 |
| 188 | 0xBC | EM_TILEPRO | Tilera TILEPro |
| 189 | 0xBD | EM_MICROBLAZE | Xilinx MicroBlaze |
| 190 | 0xBE | EM_CUDA | NVIDIA CUDA |
| 191 | 0xBF | EM_TILEGX | Tilera TILE-Gx |
| 192 | 0xC0 | EM_CLOUDSHIELD | CloudShield |
| 193 | 0xC1 | EM_COREA_1ST | KIPO Core-A 1st |
| 194 | 0xC2 | EM_COREA_2ND | KIPO Core-A 2nd |
| 195 | 0xC3 | EM_ARC_COMPACT2 | Synopsys ARCv2 |
| 196 | 0xC4 | EM_OPEN8 | Open8 RISC |
| 197 | 0xC5 | EM_RL78 | Renesas RL78 |
| 198 | 0xC6 | EM_VIDEOCORE5 | Broadcom VideoCore V |
| 199 | 0xC7 | EM_78KOR | Renesas 78KOR |
| 200 | 0xC8 | EM_56800EX | Freescale 56800EX |
| 201 | 0xC9 | EM_BA1 | Beyond BA1 |
| 202 | 0xCA | EM_BA2 | Beyond BA2 |
| 203 | 0xCB | EM_XCORE | XMOS xCORE |
| 204 | 0xCC | EM_MCHP_PIC | Microchip PIC |
| 210 | 0xD2 | EM_KM32 | KM211 KM32 |
| 211 | 0xD3 | EM_KMX32 | KM211 KMX32 |
| 212 | 0xD4 | EM_KMX16 | KM211 KMX16 |
| 213 | 0xD5 | EM_KMX8 | KM211 KMX8 |
| 214 | 0xD6 | EM_KVARC | KM211 KVARC |
| 215 | 0xD7 | EM_CDP | Paneve CDP |
| 216 | 0xD8 | EM_COGE | Cognitive |
| 217 | 0xD9 | EM_COOL | Bluechip CoolEngine |
| 218 | 0xDA | EM_NORC | Nanoradio RISC |
| 219 | 0xDB | EM_CSR_KALIMBA | CSR Kalimba |
| 220 | 0xDC | EM_Z80 | Zilog Z80 |
| 221 | 0xDD | EM_VISIUM | VISIUMcore |
| 222 | 0xDE | EM_FT32 | FTDI FT32 |
| 223 | 0xDF | EM_MOXIE | Moxie |
| 224 | 0xE0 | EM_AMDGPU | AMD GPU |
| 243 | 0xF3 | EM_RISCV | RISC-V |
| 244 | 0xF4 | EM_LANAI | Lanai |
| 245 | 0xF5 | EM_CEVA | CEVA |
| 246 | 0xF6 | EM_CEVA_X2 | CEVA X2 |
| 247 | 0xF7 | EM_BPF | Linux BPF |
| 248 | 0xF8 | EM_GRAPHCORE_IPU | Graphcore IPU |
| 249 | 0xF9 | EM_IMG1 | Imagination |
| 250 | 0xFA | EM_NFP | Netronome NFP |
| 251 | 0xFB | EM_VE | NEC VE |
| 252 | 0xFC | EM_CSKY | C-SKY |
| 253 | 0xFD | EM_ARC_COMPACT3_64 | ARCv2.3 64-bit |
| 254 | 0xFE | EM_MCS6502 | MOS 6502 |
| 255 | 0xFF | EM_ARC_COMPACT3 | ARCv2.3 32-bit |
| 256 | 0x100 | EM_KVX | Kalray VLIW |
| 257 | 0x101 | EM_65816 | WDC 65816 |
| 258 | 0x102 | EM_LOONGARCH | LoongArch |
| 259 | 0x103 | EM_KF32 | ChipON KungFu32 |
| 0x9026 | - | EM_ALPHA_EXP | DEC Alpha (actual) |

---

# Part 3: PE/COFF Machine Types

| Value | Name | Architecture |
|-------|------|--------------|
| 0x0000 | IMAGE_FILE_MACHINE_UNKNOWN | Unknown |
| 0x014C | IMAGE_FILE_MACHINE_I386 | x86 |
| 0x0162 | IMAGE_FILE_MACHINE_R3000 | MIPS R3000 |
| 0x0166 | IMAGE_FILE_MACHINE_R4000 | MIPS R4000 |
| 0x0168 | IMAGE_FILE_MACHINE_R10000 | MIPS R10000 |
| 0x0169 | IMAGE_FILE_MACHINE_WCEMIPSV2 | MIPS WCE v2 |
| 0x0184 | IMAGE_FILE_MACHINE_ALPHA | DEC Alpha |
| 0x01A2 | IMAGE_FILE_MACHINE_SH3 | SH-3 |
| 0x01A3 | IMAGE_FILE_MACHINE_SH3DSP | SH-3 DSP |
| 0x01A4 | IMAGE_FILE_MACHINE_SH3E | SH-3E |
| 0x01A6 | IMAGE_FILE_MACHINE_SH4 | SH-4 |
| 0x01A8 | IMAGE_FILE_MACHINE_SH5 | SH-5 |
| 0x01C0 | IMAGE_FILE_MACHINE_ARM | ARM LE |
| 0x01C2 | IMAGE_FILE_MACHINE_THUMB | ARM Thumb |
| 0x01C4 | IMAGE_FILE_MACHINE_ARMNT | ARM Thumb-2 |
| 0x01D3 | IMAGE_FILE_MACHINE_AM33 | AM33 |
| 0x01F0 | IMAGE_FILE_MACHINE_POWERPC | PowerPC LE |
| 0x01F1 | IMAGE_FILE_MACHINE_POWERPCFP | PowerPC FP |
| 0x0200 | IMAGE_FILE_MACHINE_IA64 | Itanium |
| 0x0266 | IMAGE_FILE_MACHINE_MIPS16 | MIPS16 |
| 0x0284 | IMAGE_FILE_MACHINE_ALPHA64 | Alpha 64 |
| 0x0366 | IMAGE_FILE_MACHINE_MIPSFPU | MIPS FPU |
| 0x0466 | IMAGE_FILE_MACHINE_MIPSFPU16 | MIPS16 FPU |
| 0x0520 | IMAGE_FILE_MACHINE_TRICORE | TriCore |
| 0x0EBC | IMAGE_FILE_MACHINE_EBC | EFI Byte Code |
| 0x5032 | IMAGE_FILE_MACHINE_RISCV32 | RISC-V 32 |
| 0x5064 | IMAGE_FILE_MACHINE_RISCV64 | RISC-V 64 |
| 0x5128 | IMAGE_FILE_MACHINE_RISCV128 | RISC-V 128 |
| 0x6232 | IMAGE_FILE_MACHINE_LOONGARCH32 | LoongArch 32 |
| 0x6264 | IMAGE_FILE_MACHINE_LOONGARCH64 | LoongArch 64 |
| 0x8664 | IMAGE_FILE_MACHINE_AMD64 | x86-64 |
| 0x9041 | IMAGE_FILE_MACHINE_M32R | M32R LE |
| 0xA641 | IMAGE_FILE_MACHINE_ARM64EC | ARM64EC |
| 0xA64E | IMAGE_FILE_MACHINE_ARM64X | ARM64X |
| 0xAA64 | IMAGE_FILE_MACHINE_ARM64 | ARM64 |

---

# Part 4: Mach-O CPU Types

| Value | Name | Architecture |
|-------|------|--------------|
| 1 | CPU_TYPE_VAX | DEC VAX |
| 6 | CPU_TYPE_MC680x0 | Motorola 68k |
| 7 | CPU_TYPE_X86 | Intel x86 |
| 0x01000007 | CPU_TYPE_X86_64 | x86-64 |
| 10 | CPU_TYPE_MC98000 | Motorola 98000 |
| 11 | CPU_TYPE_HPPA | HP PA-RISC |
| 12 | CPU_TYPE_ARM | ARM 32-bit |
| 0x0100000C | CPU_TYPE_ARM64 | ARM64 |
| 0x0200000C | CPU_TYPE_ARM64_32 | ARM64_32 |
| 13 | CPU_TYPE_MC88000 | Motorola 88000 |
| 14 | CPU_TYPE_SPARC | SPARC |
| 15 | CPU_TYPE_I860 | Intel i860 |
| 18 | CPU_TYPE_POWERPC | PowerPC |
| 0x01000012 | CPU_TYPE_POWERPC64 | PowerPC 64 |

## Mach-O ARM Subtypes

| Value | Name | Variant |
|-------|------|---------|
| 5 | CPU_SUBTYPE_ARM_V4T | ARMv4T |
| 6 | CPU_SUBTYPE_ARM_V6 | ARMv6 |
| 7 | CPU_SUBTYPE_ARM_V5TEJ | ARMv5TEJ |
| 8 | CPU_SUBTYPE_ARM_XSCALE | XScale |
| 9 | CPU_SUBTYPE_ARM_V7 | ARMv7 |
| 10 | CPU_SUBTYPE_ARM_V7F | ARMv7 Cortex-A9 |
| 11 | CPU_SUBTYPE_ARM_V7S | ARMv7S (A6) |
| 12 | CPU_SUBTYPE_ARM_V7K | ARMv7K (Watch) |

## Mach-O ARM64 Subtypes

| Value | Name | Variant |
|-------|------|---------|
| 0 | CPU_SUBTYPE_ARM64_ALL | All ARM64 |
| 1 | CPU_SUBTYPE_ARM64_V8 | ARMv8 |
| 2 | CPU_SUBTYPE_ARM64E | ARMv8.3+ PAC |

---

# Part 5: Instruction Encoding Patterns

## 5.1 x86/x86-64

### Instruction Format
Variable length 1-15 bytes:
```
[Prefixes] [REX/VEX/EVEX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
```

### Prefix Detection

| Prefix | Bytes | Meaning |
|--------|-------|---------|
| Legacy | 66,67,F2,F3,F0 | Size/REP/LOCK |
| Segment | 26,2E,36,3E,64,65 | Segment override |
| REX | 40-4F | 64-bit extensions |
| VEX 2-byte | C5 xx | AVX |
| VEX 3-byte | C4 xx xx | AVX extended |
| EVEX | 62 xx xx xx | AVX-512 |
| REX2 | D5 xx | APX (32 GPRs) |

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | 90 | 1-byte NOP |
| Multi-NOP | 0F 1F 00 | 3-byte NOP |
| RET | C3 | Near return |
| CALL rel32 | E8 xx xx xx xx | Relative call |
| JMP rel32 | E9 xx xx xx xx | Relative jump |
| SYSCALL | 0F 05 | 64-bit syscall |
| INT 80 | CD 80 | 32-bit syscall |
| INT3 | CC | Breakpoint |
| UD2 | 0F 0B | Undefined |
| ENDBR64 | F3 0F 1E FA | CET marker |
| ENDBR32 | F3 0F 1E FB | CET marker |

### Prologue Patterns

32-bit:
```
55                 push ebp
89 E5              mov ebp, esp
83 EC xx           sub esp, imm8
```

64-bit:
```
55                 push rbp
48 89 E5           mov rbp, rsp
48 83 EC xx        sub rsp, imm8
```

---

## 5.2 ARM 32-bit

### Instruction Format
Fixed 32-bit, condition field bits [31:28]:
```
[31:28] cond | [27:25] type | [24:21] opcode | [20] S | [19:16] Rn | [15:12] Rd | [11:0] operand2
```

### Condition Codes

| Code | Hex | Meaning |
|------|-----|---------|
| EQ | 0 | Equal |
| NE | 1 | Not equal |
| CS/HS | 2 | Carry set |
| CC/LO | 3 | Carry clear |
| MI | 4 | Negative |
| PL | 5 | Positive |
| VS | 6 | Overflow |
| VC | 7 | No overflow |
| HI | 8 | Higher |
| LS | 9 | Lower/same |
| GE | A | Greater/equal |
| LT | B | Less than |
| GT | C | Greater than |
| LE | D | Less/equal |
| AL | E | Always |
| (uncond) | F | Special |

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | E1A00000 | MOV R0, R0 |
| NOP.W | E320F000 | ARMv6K+ NOP |
| BX LR | E12FFF1E | Return |
| PUSH | E92Dxxxx | STMFD SP! |
| POP | E8BDxxxx | LDMFD SP! |
| BL | EBxxxxxx | Branch link |
| SVC | EF00xxxx | System call |
| BKPT | E12xxx7x | Breakpoint |
| UDF | E7Fxxxxx | Undefined |

---

## 5.3 Thumb/Thumb-2

### Length Detection
- 16-bit: Most common
- 32-bit: First halfword [15:11] = 11101/11110/11111

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | BF00 | 16-bit NOP |
| NOP.W | F3AF 8000 | 32-bit NOP |
| BX LR | 4770 | Return |
| POP PC | BD00+ | Return via pop |
| BL | F000 Fxxx | Branch link |
| SVC | DFxx | System call |
| BKPT | BExx | Breakpoint |
| UDF | DExx | Undefined |

---

## 5.4 AArch64

### Instruction Format
Fixed 32-bit, encoding groups bits [28:25]:
```
100x = Data processing immediate
x101 = Branches, exceptions, system
x1x0 = Loads and stores
x111 = Data processing register
0111 = SIMD and FP
```

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | D503201F | NOP |
| RET | D65F03C0 | Return |
| RET (PAC) | D65F0FE0 | RETAA |
| BL | 94xxxxxx | Branch link |
| B | 14xxxxxx | Branch |
| SVC | D4000001 | System call |
| BRK | D4200000 | Breakpoint |
| BTI | D503241F | BTI marker |
| PACIASP | D503233F | PAC sign |
| AUTIASP | D50323BF | PAC auth |

### Prologue Pattern
```
A9BF7BFD   stp x29, x30, [sp, #-16]!
910003FD   mov x29, sp
```

---

## 5.5 RISC-V

### Length Detection
bits [1:0]:
- 00, 01, 10 = 16-bit compressed
- 11 = 32-bit (or longer)

### Standard Opcodes (bits [6:0])

| Opcode | Hex | Type |
|--------|-----|------|
| 0000011 | 03 | LOAD |
| 0010011 | 13 | OP-IMM |
| 0010111 | 17 | AUIPC |
| 0100011 | 23 | STORE |
| 0110011 | 33 | OP |
| 0110111 | 37 | LUI |
| 1100011 | 63 | BRANCH |
| 1100111 | 67 | JALR |
| 1101111 | 6F | JAL |
| 1110011 | 73 | SYSTEM |

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | 00000013 | addi x0,x0,0 |
| C.NOP | 0001 | Compressed NOP |
| RET | 00008067 | jalr x0,x1,0 |
| C.RET | 8082 | Compressed ret |
| ECALL | 00000073 | System call |
| EBREAK | 00100073 | Breakpoint |
| C.EBREAK | 9002 | Compressed break |

---

## 5.6 MIPS

### Instruction Format
Fixed 32-bit:
- R-type: `[31:26] op=0 | [25:21] rs | [20:16] rt | [15:11] rd | [10:6] sa | [5:0] funct`
- I-type: `[31:26] op | [25:21] rs | [20:16] rt | [15:0] imm`
- J-type: `[31:26] op | [25:0] target`

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | 00000000 | sll $0,$0,0 |
| JR $ra | 03E00008 | Return |
| SYSCALL | 0000000C | System call |
| BREAK | 0000000D | Breakpoint |
| JAL | 0Cxxxxxx | Jump link |
| LUI | 3Cxxxxxx | Load upper |

**Note: Branch delay slot - instruction after branch always executes**

---

## 5.7 PowerPC

### Instruction Format
Fixed 32-bit, primary opcode bits [0:5] (BE numbering):
```
[0:5] primary | [6:10] RT | [11:15] RA | [16:31] varies
```

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP | 60000000 | ori 0,0,0 |
| BLR | 4E800020 | Return |
| SC | 44000002 | System call |
| TRAP | 7FE00008 | Trap |
| MFLR r0 | 7C0802A6 | Save LR |
| MTLR r0 | 7C0803A6 | Restore LR |

---

## 5.8 s390x

### Length Detection
bits [0:1] of first byte:
- 00 = 2 bytes
- 01 = 4 bytes
- 10 = 4 bytes
- 11 = 6 bytes

### Key Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| NOP 2B | 0700 | BCR 0,0 |
| NOP 4B | 47000000 | BC 0,0 |
| BR r14 | 07FE | Return |
| SVC | 0Axx | System call |

---

## 5.9 Other Architectures Summary

| ISA | Width | Endian | NOP | Return |
|-----|-------|--------|-----|--------|
| SPARC | 32b | BE | 01000000 | 81C3E008 |
| m68k | 2-10B | BE | 4E71 | 4E75 |
| SuperH | 16b | LE/BE | 0009 | 000B |
| LoongArch | 32b | LE | 03400000 | 4C000020 |
| Alpha | 32b | LE | 47FF041F | 6BFA8001 |
| PA-RISC | 32b | BE | 08000240 | E840C002 |
| Itanium | 128b bundle | LE | (bundle) | br.ret |
| Hexagon | 32b VLIW | LE | 7F000000 | jumpr r31 |
| ARC | 16/32b | LE/BE | 78E0 | 7EE0 |
| Xtensa | 16/24b | LE | 20F0 | varies |
| MicroBlaze | 32b | BE/LE | 80000000 | B60F0008 |
| Nios II | 32b | LE | 0001883A | F800283A |
| OpenRISC | 32b | BE | 15000000 | 44004800 |
| AVR | 16/32b | LE | 0000 | 9508 |
| MSP430 | 16b | LE | 4303 | 4130 |


---

# Part 6: Extension Detection Methods

## 6.1 x86/x86-64 CPUID

### Leaf 1 (EAX=1) Feature Flags

**EDX Register:**
| Bit | Extension |
|-----|-----------|
| 23 | MMX |
| 25 | SSE |
| 26 | SSE2 |

**ECX Register:**
| Bit | Extension |
|-----|-----------|
| 0 | SSE3 |
| 9 | SSSE3 |
| 19 | SSE4.1 |
| 20 | SSE4.2 |
| 25 | AES-NI |
| 28 | AVX |
| 30 | RDRAND |

### Leaf 7 (EAX=7, ECX=0)

**EBX Register:**
| Bit | Extension |
|-----|-----------|
| 3 | BMI1 |
| 5 | AVX2 |
| 8 | BMI2 |
| 16 | AVX-512F |
| 17 | AVX-512DQ |
| 21 | AVX-512_IFMA |
| 26 | AVX-512PF |
| 27 | AVX-512ER |
| 28 | AVX-512CD |
| 29 | SHA |
| 30 | AVX-512BW |
| 31 | AVX-512VL |

**ECX Register:**
| Bit | Extension |
|-----|-----------|
| 1 | AVX-512_VBMI |
| 6 | AVX-512_VBMI2 |
| 8 | GFNI |
| 9 | VAES |
| 10 | VPCLMULQDQ |
| 11 | AVX-512_VNNI |
| 12 | AVX-512_BITALG |
| 14 | AVX-512_VPOPCNTDQ |

**EDX Register:**
| Bit | Extension |
|-----|-----------|
| 2 | AVX-512_4VNNIW |
| 3 | AVX-512_4FMAPS |
| 22 | AMX-BF16 |
| 23 | AVX-512_FP16 |
| 24 | AMX-TILE |
| 25 | AMX-INT8 |

### Leaf 7 Subleaf 1 (EAX=7, ECX=1)

**EAX Register:**
| Bit | Extension |
|-----|-----------|
| 4 | AVX-VNNI |
| 5 | AVX-512_BF16 |
| 21 | AMX-FP16 |
| 23 | AVX-IFMA |

**EDX Register:**
| Bit | Extension |
|-----|-----------|
| 4 | AVX-VNNI-INT8 |
| 5 | AVX-NE-CONVERT |
| 8 | AMX-COMPLEX |
| 18 | AVX10 |
| 19 | APX_F |

---

## 6.2 ARM/AArch64 ID Registers

### ID_AA64ISAR0_EL1

| Bits | Field | Extension |
|------|-------|-----------|
| [7:4] | AES | 1=AES, 2=+PMULL |
| [11:8] | SHA1 | 1=SHA1 |
| [15:12] | SHA2 | 1=SHA256, 2=+SHA512 |
| [19:16] | CRC32 | 1=CRC32 |
| [23:20] | Atomic | 2=LSE atomics |
| [31:28] | RDM | 1=SQRDMLAH |
| [35:32] | SHA3 | 1=SHA3 |
| [39:36] | SM3 | 1=SM3 |
| [43:40] | SM4 | 1=SM4 |
| [47:44] | DP | 1=Dot product |
| [63:60] | RNDR | 1=Random |

### ID_AA64PFR0_EL1

| Bits | Field | Extension |
|------|-------|-----------|
| [19:16] | FP | 0=FP, 1=FP16, F=none |
| [23:20] | AdvSIMD | 0=SIMD, 1=FP16, F=none |
| [35:32] | SVE | 1=SVE |

### ID_AA64PFR1_EL1

| Bits | Field | Extension |
|------|-------|-----------|
| [3:0] | BT | 1=BTI |
| [11:8] | MTE | 1=MTE, 2=MTE2, 3=MTE3 |
| [27:24] | SME | 1=SME, 2=SME2 |

### ID_AA64ZFR0_EL1 (SVE)

| Bits | Field | Extension |
|------|-------|-----------|
| [3:0] | SVEver | 1=SVE2, 2=SVE2p1 |
| [7:4] | AES | SVE-AES |
| [19:16] | BF16 | SVE-BF16 |
| [35:32] | SHA3 | SVE-SHA3 |
| [43:40] | SM4 | SVE-SM4 |

---

## 6.3 RISC-V misa CSR (0x301)

| Bit | Letter | Extension |
|-----|--------|-----------|
| 0 | A | Atomic |
| 2 | C | Compressed |
| 3 | D | Double FP |
| 4 | E | RV32E (16 regs) |
| 5 | F | Single FP |
| 7 | H | Hypervisor |
| 8 | I | Base Integer |
| 12 | M | Multiply |
| 16 | Q | Quad FP |
| 18 | S | Supervisor |
| 20 | U | User |
| 21 | V | Vector |

**MXL (MXLEN-1:MXLEN-2):**
- 1 = RV32
- 2 = RV64
- 3 = RV128

---

## 6.4 PowerPC PVR and HWCAP

### PVR (Processor Version Register)

| Version | Processor |
|---------|-----------|
| 0x003F | POWER7 |
| 0x004D | POWER8 |
| 0x004E | POWER9 |
| 0x0080 | POWER10 |
| 0x0082 | POWER11 |

### HWCAP Flags

| Flag | Value | Feature |
|------|-------|---------|
| PPC_FEATURE_HAS_ALTIVEC | 0x10000000 | VMX |
| PPC_FEATURE_HAS_VSX | 0x00000080 | VSX |
| PPC_FEATURE_HAS_DFP | 0x00000400 | DFP |

### HWCAP2 Flags

| Flag | Value | Feature |
|------|-------|---------|
| PPC_FEATURE2_ARCH_2_07 | 0x80000000 | ISA 2.07 |
| PPC_FEATURE2_HTM | 0x40000000 | HTM |
| PPC_FEATURE2_VEC_CRYPTO | 0x02000000 | Crypto |
| PPC_FEATURE2_ARCH_3_00 | 0x00800000 | ISA 3.0 |
| PPC_FEATURE2_ARCH_3_1 | 0x00040000 | ISA 3.1 |
| PPC_FEATURE2_MMA | 0x00020000 | MMA |

---

## 6.5 MIPS CP0 Config Registers

### Config0

| Bits | Field | Meaning |
|------|-------|---------|
| [14:13] | AT | 0=MIPS32, 1=MIPS64/32, 2=MIPS64 |
| [12:10] | AR | 0=R1, 1=R2, 2=R6 |
| [15] | BE | Big-endian |

### Config3

| Bit | Extension |
|-----|-----------|
| 7 | DSP ASE |
| 8 | DSP Rev2 |
| 26 | MSA |

---

## 6.6 s390x STFLE Facility Bits

| Bit | Facility |
|-----|----------|
| 17 | MSA |
| 18 | Long displacement |
| 21 | Extended immediate |
| 34 | General instructions |
| 42 | DFP |
| 73 | Transactional execution |
| 129 | Vector facility |
| 135 | Vector enhancements 1 |
| 148 | Vector enhancements 2 |
| 165 | NNPA |

---

## 6.7 Alpha AMASK/IMPLVER

### IMPLVER Return Values

| Value | Generation |
|-------|------------|
| 0 | EV4 (21064) |
| 1 | EV5 (21164) |
| 2 | EV6 (21264) |
| 3 | EV7 (21364) |

### AMASK Bits (input mask)

| Bit | Extension |
|-----|-----------|
| 0 | BWX (Byte/Word) |
| 1 | FIX (Sqrt, conversion) |
| 2 | CIX (Count) |
| 8 | MVI (Multimedia) |

---

## 6.8 LoongArch CPUCFG

### Word 2 Feature Bits

| Bit | Extension |
|-----|-----------|
| 3 | FP_DP |
| 4 | LAM |
| 6 | LSX (128-bit) |
| 7 | LASX (256-bit) |
| 8 | LVZ |
| 10 | Crypto |

### Word 6

| Bit | Extension |
|-----|-----------|
| 11 | LBT_X86 |
| 12 | LBT_ARM |
| 13 | LBT_MIPS |

---

# Part 7: Architecture-Specific e_flags

## 7.1 ARM (EM_ARM = 40)

| Bits | Field | Values |
|------|-------|--------|
| [31:24] | EABI | 0x05 = v5 |
| [23] | BE8 | BE8 mode |
| [10] | FLOAT_HARD | Hard float |
| [9] | FLOAT_SOFT | Soft float |

## 7.2 RISC-V (EM_RISCV = 243)

| Bit | Flag | Meaning |
|-----|------|---------|
| 0 | RVC | Compressed |
| [2:1] | Float ABI | 0=soft, 1=F, 2=D, 3=Q |
| 3 | RVE | 16 registers |
| 4 | TSO | TSO memory |

## 7.3 MIPS (EM_MIPS = 8)

| Bits | Field | Values |
|------|-------|--------|
| [31:28] | ARCH | 0-A = MIPS I-R6 |
| [25] | microMIPS | microMIPS |
| [26] | MIPS16 | MIPS16e |
| [27] | MDMX | MDMX |

## 7.4 PowerPC64 (EM_PPC64 = 21)

| Bits | Field | Values |
|------|-------|--------|
| [1:0] | ABI | 1=ELFv1, 2=ELFv2 |

## 7.5 SuperH (EM_SH = 42)

| Value | Variant |
|-------|---------|
| 9 | SH-4 |
| 12 | SH-4A |
| 13 | SH-2A |

## 7.6 Hexagon (EM_HEXAGON = 164)

| Bits | Field | Values |
|------|-------|--------|
| [11:0] | MACH | Architecture version |

Common versions: V60=0x60, V66=0x66, V68=0x68, V73=0x73

## 7.7 LoongArch (EM_LOONGARCH = 258)

| Bits | Field | Values |
|------|-------|--------|
| [2:0] | ABI | 0=LP64S, 1=LP64F, 2=LP64D |


---

# Part 8: Complete Detection Algorithm

## 8.1 Master Detection Pseudocode

```python
def identify_binary(data: bytes) -> dict:
    """
    Universal binary identification algorithm.
    Returns: {isa, variant, bitwidth, endianness, extensions, confidence}
    """
    
    # Step 1: Check file format magic
    if len(data) < 4:
        return heuristic_analysis(data)
    
    magic = data[0:4]
    
    # ELF
    if magic == b'\x7fELF':
        return parse_elf(data)
    
    # PE/COFF
    if data[0:2] == b'MZ':
        pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
        if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
            return parse_pe(data, pe_offset)
    
    # Mach-O
    macho_magics = {
        b'\xFE\xED\xFA\xCE': ('macho32', 'big'),
        b'\xCE\xFA\xED\xFE': ('macho32', 'little'),
        b'\xFE\xED\xFA\xCF': ('macho64', 'big'),
        b'\xCF\xFA\xED\xFE': ('macho64', 'little'),
        b'\xCA\xFE\xBA\xBE': ('fat', 'big'),
        b'\xBE\xBA\xFE\xCA': ('fat', 'little'),
    }
    if magic in macho_magics:
        return parse_macho(data, macho_magics[magic])
    
    # No recognized format - heuristic analysis
    return heuristic_analysis(data)


def parse_elf(data: bytes) -> dict:
    """Parse ELF format and identify architecture."""
    
    ei_class = data[4]   # 1=32-bit, 2=64-bit
    ei_data = data[5]    # 1=LE, 2=BE
    
    endian = 'little' if ei_data == 1 else 'big'
    bitwidth = 32 if ei_class == 1 else 64
    
    # Read e_machine
    if ei_class == 1:  # 32-bit
        e_machine = int.from_bytes(data[0x12:0x14], endian)
        e_flags = int.from_bytes(data[0x24:0x28], endian)
    else:  # 64-bit
        e_machine = int.from_bytes(data[0x12:0x14], endian)
        e_flags = int.from_bytes(data[0x30:0x34], endian)
    
    # Map e_machine to ISA
    isa_map = {
        3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'aarch64',
        243: 'riscv', 20: 'ppc', 21: 'ppc64', 8: 'mips',
        22: 's390', 2: 'sparc', 18: 'sparc32plus', 43: 'sparc64',
        258: 'loongarch', 0x9026: 'alpha', 15: 'parisc',
        50: 'ia64', 4: 'm68k', 42: 'superh', 164: 'hexagon',
        195: 'arc', 189: 'microblaze', 113: 'nios2',
        92: 'openrisc', 94: 'xtensa', 252: 'csky',
        106: 'blackfin', 140: 'c6x', 83: 'avr',
    }
    
    isa = isa_map.get(e_machine, f'unknown_{e_machine}')
    variant = ''
    extensions = []
    
    # Architecture-specific e_flags parsing
    if isa == 'arm':
        variant, extensions = parse_arm_flags(e_flags, data)
    elif isa == 'riscv':
        variant, extensions = parse_riscv_flags(e_flags, data)
    elif isa == 'mips':
        variant, extensions = parse_mips_flags(e_flags)
    elif isa == 'ppc64':
        variant = 'ELFv2' if (e_flags & 3) == 2 else 'ELFv1'
    elif isa == 'superh':
        sh_map = {9: 'SH4', 12: 'SH4A', 13: 'SH2A'}
        variant = sh_map.get(e_flags & 0x1F, '')
    elif isa == 'hexagon':
        variant = f'V{e_flags & 0xFF}'
    
    # Scan code for extension detection
    code_extensions = analyze_code_sections(data, isa, endian)
    extensions = list(set(extensions + code_extensions))
    
    return {
        'isa': isa,
        'variant': variant,
        'bitwidth': bitwidth,
        'endianness': endian,
        'extensions': extensions,
        'confidence': 1.0
    }


def parse_arm_flags(e_flags: int, data: bytes) -> tuple:
    """Parse ARM ELF flags and attributes."""
    variant = ''
    extensions = []
    
    eabi = (e_flags >> 24) & 0xFF
    if eabi == 5:
        variant = 'EABIv5'
    
    if e_flags & 0x00800000:
        extensions.append('BE8')
    
    if e_flags & 0x00000400:
        variant += ',armhf'
    elif e_flags & 0x00000200:
        variant += ',armel'
    
    # Parse .ARM.attributes section for arch version
    # (simplified - would need section parsing)
    
    return variant.strip(','), extensions


def parse_riscv_flags(e_flags: int, data: bytes) -> tuple:
    """Parse RISC-V ELF flags and attributes."""
    extensions = []
    variant = ''
    
    if e_flags & 0x0001:
        extensions.append('C')
    
    float_abi = (e_flags >> 1) & 0x3
    abi_map = {0: 'ilp32/lp64', 1: 'ilp32f/lp64f', 
               2: 'ilp32d/lp64d', 3: 'ilp32q/lp64q'}
    variant = abi_map.get(float_abi, '')
    
    if float_abi >= 1:
        extensions.append('F')
    if float_abi >= 2:
        extensions.append('D')
    if float_abi >= 3:
        extensions.append('Q')
    
    if e_flags & 0x0008:
        extensions.append('E')
    if e_flags & 0x0010:
        extensions.append('Ztso')
    
    return variant, extensions


def parse_mips_flags(e_flags: int) -> tuple:
    """Parse MIPS ELF flags."""
    extensions = []
    
    arch = (e_flags >> 28) & 0xF
    arch_map = {
        0x0: 'MIPS-I', 0x1: 'MIPS-II', 0x2: 'MIPS-III',
        0x3: 'MIPS-IV', 0x4: 'MIPS-V', 0x5: 'MIPS32',
        0x6: 'MIPS64', 0x7: 'MIPS32R2', 0x8: 'MIPS64R2',
        0x9: 'MIPS32R6', 0xA: 'MIPS64R6'
    }
    variant = arch_map.get(arch, f'MIPS-{arch}')
    
    if e_flags & 0x02000000:
        extensions.append('microMIPS')
    if e_flags & 0x04000000:
        extensions.append('MIPS16e')
    if e_flags & 0x08000000:
        extensions.append('MDMX')
    
    return variant, extensions


def heuristic_analysis(data: bytes) -> dict:
    """Analyze raw instruction stream to identify ISA."""
    
    scores = {}
    
    # Score each architecture
    scores['x86'] = score_x86(data, 32)
    scores['x86_64'] = score_x86(data, 64)
    scores['arm'] = score_arm(data)
    scores['aarch64'] = score_aarch64(data)
    scores['riscv'] = score_riscv(data)
    scores['mips_be'] = score_mips(data, 'big')
    scores['mips_le'] = score_mips(data, 'little')
    scores['ppc'] = score_ppc(data)
    scores['sparc'] = score_sparc(data)
    scores['m68k'] = score_m68k(data)
    
    # Find best match
    best = max(scores, key=scores.get)
    total = sum(scores.values()) or 1
    confidence = scores[best] / total
    
    if confidence < 0.3:
        return {'isa': 'unknown', 'confidence': confidence}
    
    # Determine endianness and bitwidth
    if best.endswith('_be'):
        isa = best[:-3]
        endian = 'big'
    elif best.endswith('_le'):
        isa = best[:-3]
        endian = 'little'
    else:
        isa = best
        endian = 'little'  # default
    
    bitwidth = 64 if '64' in best else 32
    
    return {
        'isa': isa,
        'variant': '',
        'bitwidth': bitwidth,
        'endianness': endian,
        'extensions': [],
        'confidence': confidence
    }


def score_x86(data: bytes, bits: int) -> int:
    """Score likelihood of x86/x86-64 code."""
    score = 0
    i = 0
    
    while i < len(data) - 4:
        b = data[i]
        
        # NOP
        if b == 0x90:
            score += 5
        # RET
        elif b == 0xC3:
            score += 10
        # INT3
        elif b == 0xCC:
            score += 8
        # PUSH EBP (prologue)
        elif b == 0x55:
            score += 10
        # CALL
        elif b == 0xE8:
            score += 8
        # JMP
        elif b == 0xE9:
            score += 5
        
        # REX prefix (64-bit indicator)
        if bits == 64 and 0x40 <= b <= 0x4F:
            score += 10
        
        # VEX prefix (AVX)
        if b in (0xC4, 0xC5):
            score += 15
        
        # EVEX prefix (AVX-512)
        if b == 0x62:
            score += 20
        
        # SYSCALL (64-bit)
        if i + 1 < len(data) and data[i:i+2] == b'\x0F\x05':
            score += 15 if bits == 64 else -10
        
        # INT 80 (32-bit)
        if i + 1 < len(data) and data[i:i+2] == b'\xCD\x80':
            score += 15 if bits == 32 else -10
        
        i += 1
    
    return max(0, score)


def score_aarch64(data: bytes) -> int:
    """Score likelihood of AArch64 code."""
    score = 0
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], 'little')
        
        # NOP
        if word == 0xD503201F:
            score += 20
        # RET
        elif word == 0xD65F03C0:
            score += 25
        # BL
        elif (word >> 26) == 0x25:  # 100101
            score += 10
        # B
        elif (word >> 26) == 0x05:  # 000101
            score += 8
        # SVC
        elif (word >> 21) == 0x6A0:  # 1101010000
            score += 15
        # BTI
        elif (word & 0xFFFFFF3F) == 0xD503241F:
            score += 15
        # PACIASP
        elif word == 0xD503233F:
            score += 15
        # STP (prologue)
        elif (word >> 22) & 0x1FF == 0x150:
            score += 10
    
    return score


def score_arm(data: bytes) -> int:
    """Score likelihood of ARM32 code."""
    score = 0
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], 'little')
        
        cond = (word >> 28) & 0xF
        
        # AL condition (most common)
        if cond == 0xE:
            score += 3
        elif cond <= 0xE:
            score += 1
        
        # NOP
        if word in (0xE1A00000, 0xE320F000):
            score += 15
        # BX LR
        elif word == 0xE12FFF1E:
            score += 20
        # PUSH
        elif (word & 0xFFFF0000) == 0xE92D0000:
            score += 10
        # POP
        elif (word & 0xFFFF0000) == 0xE8BD0000:
            score += 10
    
    return score


def score_riscv(data: bytes) -> int:
    """Score likelihood of RISC-V code."""
    score = 0
    i = 0
    
    while i < len(data) - 2:
        # Check for compressed instruction
        if (data[i] & 0x03) != 0x03:
            half = int.from_bytes(data[i:i+2], 'little')
            
            # C.NOP
            if half == 0x0001:
                score += 15
            # C.RET
            elif half == 0x8082:
                score += 20
            
            # Valid compressed quadrant
            if (half & 0x03) in (0, 1, 2):
                score += 2
            
            i += 2
        else:
            if i + 4 > len(data):
                break
            
            word = int.from_bytes(data[i:i+4], 'little')
            opcode = word & 0x7F
            
            # NOP
            if word == 0x00000013:
                score += 20
            # RET
            elif word == 0x00008067:
                score += 25
            # ECALL
            elif word == 0x00000073:
                score += 15
            
            # Valid standard opcodes
            if opcode in (0x03, 0x13, 0x17, 0x23, 0x33, 
                         0x37, 0x63, 0x67, 0x6F, 0x73):
                score += 3
            
            i += 4
    
    return score


def score_mips(data: bytes, endian: str) -> int:
    """Score likelihood of MIPS code."""
    score = 0
    byte_order = 'big' if endian == 'big' else 'little'
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], byte_order)
        opcode = (word >> 26) & 0x3F
        
        # NOP
        if word == 0x00000000:
            score += 15
        # JR $ra
        elif word == 0x03E00008:
            score += 25
        # SYSCALL
        elif (word & 0xFC00003F) == 0x0000000C:
            score += 15
        
        # Valid opcodes
        if opcode in (0x00, 0x02, 0x03, 0x04, 0x05, 
                     0x08, 0x09, 0x0F, 0x20, 0x23,
                     0x24, 0x25, 0x28, 0x2B):
            score += 2
    
    return score


def score_ppc(data: bytes) -> int:
    """Score likelihood of PowerPC code."""
    score = 0
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], 'big')
        opcode = (word >> 26) & 0x3F
        
        # NOP
        if word == 0x60000000:
            score += 20
        # BLR
        elif word == 0x4E800020:
            score += 25
        # SC
        elif word == 0x44000002:
            score += 15
        # MFLR
        elif word == 0x7C0802A6:
            score += 20
        
        # Valid opcodes
        if opcode in (14, 15, 16, 18, 19, 31, 32, 
                     34, 36, 38, 40, 44, 48, 50):
            score += 2
    
    return score


def score_sparc(data: bytes) -> int:
    """Score likelihood of SPARC code."""
    score = 0
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], 'big')
        op = (word >> 30) & 0x3
        
        # NOP (SETHI 0, %g0)
        if word == 0x01000000:
            score += 20
        # RETL
        elif word == 0x81C3E008:
            score += 25
        
        # Valid op fields
        if op in (0, 1, 2, 3):
            score += 1
        
        # CALL
        if op == 1:
            score += 5
    
    return score


def score_m68k(data: bytes) -> int:
    """Score likelihood of m68k code."""
    score = 0
    
    for i in range(0, len(data) - 2, 2):
        word = int.from_bytes(data[i:i+2], 'big')
        
        # NOP
        if word == 0x4E71:
            score += 20
        # RTS
        elif word == 0x4E75:
            score += 25
        # JSR
        elif (word & 0xFFC0) == 0x4E80:
            score += 10
        # TRAP
        elif (word & 0xFFF0) == 0x4E40:
            score += 15
        # MOVE.L
        elif (word >> 12) == 2:
            score += 3
    
    return score


def analyze_code_sections(data: bytes, isa: str, 
                         endian: str) -> list:
    """Analyze code for extension usage."""
    extensions = []
    
    if isa in ('x86', 'x86_64'):
        extensions = detect_x86_extensions(data)
    elif isa == 'aarch64':
        extensions = detect_aarch64_extensions(data)
    elif isa == 'riscv':
        extensions = detect_riscv_extensions(data)
    
    return extensions


def detect_x86_extensions(data: bytes) -> list:
    """Detect x86 extensions from instruction prefixes."""
    extensions = set()
    i = 0
    
    while i < len(data) - 4:
        b = data[i]
        
        # Skip legacy prefixes
        while b in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
                   0x66, 0x67, 0xF0, 0xF2, 0xF3):
            i += 1
            if i >= len(data):
                break
            b = data[i]
        
        if i >= len(data):
            break
        
        # VEX (AVX)
        if b == 0xC5:
            extensions.add('AVX')
            i += 2
            continue
        if b == 0xC4:
            extensions.add('AVX')
            if i + 2 < len(data):
                map_sel = data[i+1] & 0x1F
                if map_sel == 2:
                    extensions.add('AVX2')
            i += 3
            continue
        
        # EVEX (AVX-512)
        if b == 0x62:
            extensions.add('AVX-512')
            i += 4
            continue
        
        # REX2 (APX)
        if b == 0xD5:
            extensions.add('APX')
            i += 2
            continue
        
        # SSE via 0F prefix
        if b == 0x0F and i + 1 < len(data):
            next_b = data[i+1]
            if 0x10 <= next_b <= 0x17:
                extensions.add('SSE')
            if next_b in (0x5A, 0x5B):
                extensions.add('SSE2')
        
        i += 1
    
    return list(extensions)


def detect_aarch64_extensions(data: bytes) -> list:
    """Detect AArch64 extensions from instruction patterns."""
    extensions = set()
    
    for i in range(0, len(data) - 4, 4):
        word = int.from_bytes(data[i:i+4], 'little')
        
        # SVE
        if (word >> 25) in (0x04, 0x05, 0x25, 0x65, 0x85):
            extensions.add('SVE')
            if (word >> 25) == 0x45:
                extensions.add('SVE2')
        
        # SME
        if (word >> 24) == 0xC0:
            extensions.add('SME')
        if word in (0xD503417F, 0xD503427F):
            extensions.add('SME')
        
        # PAC
        if word == 0xD503233F:
            extensions.add('PAC')
        
        # BTI
        if (word & 0xFFFFFF3F) == 0xD503241F:
            extensions.add('BTI')
        
        # MTE
        if (word & 0xFF000000) == 0xD9000000:
            extensions.add('MTE')
        
        # AES
        if (word & 0xFFFFFC00) == 0x4E284800:
            extensions.add('AES')
        
        # SHA
        if (word & 0xFFFFFC00) == 0x5E280800:
            extensions.add('SHA1')
        if (word & 0xFFFFFC00) == 0x5E282800:
            extensions.add('SHA256')
        
        # Dot product
        if (word & 0xBF20FC00) == 0x0E809400:
            extensions.add('DOTPROD')
    
    return list(extensions)


def detect_riscv_extensions(data: bytes) -> list:
    """Detect RISC-V extensions from instructions."""
    extensions = set()
    has_compressed = False
    i = 0
    
    while i < len(data) - 2:
        if (data[i] & 0x03) != 0x03:
            has_compressed = True
            i += 2
        else:
            if i + 4 > len(data):
                break
            word = int.from_bytes(data[i:i+4], 'little')
            opcode = word & 0x7F
            
            # M extension
            if opcode == 0x33:
                funct7 = (word >> 25) & 0x7F
                if funct7 == 0x01:
                    extensions.add('M')
            
            # A extension
            if opcode == 0x2F:
                extensions.add('A')
            
            # F/D extension
            if opcode in (0x07, 0x27, 0x43, 0x47, 
                         0x4B, 0x4F, 0x53):
                if opcode == 0x53:
                    funct7 = (word >> 25) & 0x7F
                    if (funct7 & 0x60) == 0x00:
                        extensions.add('F')
                    if (funct7 & 0x60) == 0x20:
                        extensions.add('D')
            
            # V extension
            if opcode == 0x57:
                extensions.add('V')
            
            i += 4
    
    if has_compressed:
        extensions.add('C')
    
    return list(extensions)
```

---

# Part 9: Quick Reference Summary

## Architecture Detection Priority

1. **Check file format magic** (ELF/PE/Mach-O)
2. **Read e_machine/machine type** from header
3. **Parse e_flags** for variant/ABI
4. **Scan code sections** for extension detection
5. **Fall back to heuristics** for raw binaries

## Key Identification Markers

| ISA | File ID | Code Signature |
|-----|---------|----------------|
| x86 | EM_386 | 90 (NOP), C3 (RET) |
| x86-64 | EM_X86_64 | REX (40-4F), 0F 05 |
| ARM | EM_ARM | E (cond), E12FFF1E |
| AArch64 | EM_AARCH64 | D503201F, D65F03C0 |
| RISC-V | EM_RISCV | 00000013, 00008067 |
| MIPS | EM_MIPS | 00000000, 03E00008 |
| PowerPC | EM_PPC[64] | 60000000, 4E800020 |
| s390x | EM_S390 | 0700, 07FE |

## Extension Detection Summary

| ISA | Method | Key Indicator |
|-----|--------|---------------|
| x86 | CPUID | Leaf 1, 7 bits |
| x86 | Prefix | VEX=AVX, EVEX=512 |
| ARM | ID regs | ID_AA64* |
| RISC-V | misa | Bit field |
| PowerPC | PVR | Version field |
| MIPS | CP0 | Config registers |
| s390x | STFLE | Facility bits |

---

**END OF DOCUMENT**

