# Binary Executable Format Specifications: A Comprehensive Technical Reference

This exhaustive reference documents approximately **50 binary executable formats** spanning legacy systems through modern platforms. Each format includes magic bytes, header structures, section definitions, flags, architecture constraints, and version variations sourced from official vendor documentation and authoritative implementation references.

---

## Unix/POSIX Legacy Formats

### a.out Format (All Variants)

The original Unix executable format, with variants across multiple architectures. The 32-byte header structure remains remarkably consistent.

**Magic Bytes:**

| Magic | Hex Value | Octal | Description |
|-------|-----------|-------|-------------|
| OMAGIC | 0x0107 | 0407 | Old impure format (text+data contiguous, writable) |
| NMAGIC | 0x0108 | 0410 | Read-only text (text/data contiguous) |
| ZMAGIC | 0x010B | 0413 | Demand-load format (page-aligned) |
| QMAGIC | 0x00CC | 0314 | Compact demand load (deprecated) |

**BSD a.out Header Structure:**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| a_midmag | 0x00 | 4 | uint32 | htonl(flags<<26 \| mid<<16 \| magic) |
| a_text | 0x04 | 4 | uint32 | Text segment size in bytes |
| a_data | 0x08 | 4 | uint32 | Initialized data size |
| a_bss | 0x0C | 4 | uint32 | Uninitialized data (BSS) size |
| a_syms | 0x10 | 4 | uint32 | Symbol table size |
| a_entry | 0x14 | 4 | uint32 | Entry point address |
| a_trsize | 0x18 | 4 | uint32 | Text relocation table size |
| a_drsize | 0x1C | 4 | uint32 | Data relocation table size |

**Machine IDs (MID values):**

| MID | Value | Architecture |
|-----|-------|-------------|
| MID_ZERO | 0 | Unknown |
| MID_SUN010 | 1 | Sun 68010/68020 |
| MID_PC386 | 100 | i386 BSD |
| MID_I386 | 134 | i386 BSD |
| MID_SPARC | 138 | SPARC |
| MID_M68K | 135 | Motorola 68K |
| MID_VAX | 140 | VAX |
| MID_MIPS | 151 | MIPS |

**Architecture-Specific Variations:**

| Architecture | Endianness | Address Size | Primary Use Era |
|--------------|------------|--------------|-----------------|
| PDP-11 | Mixed (PDP-endian) | 16-bit | 1970s-1980s |
| VAX | Little-endian | 32-bit | 1978-1998 |
| m68k | Big-endian | 32-bit | 1984-1995 |
| SPARC | Big-endian | 32-bit | 1987-2000 |
| i386 | Little-endian | 32-bit | 1986-1998 |

---

### ECOFF (Extended COFF) - MIPS, Alpha

**Magic Bytes:**

| Magic | Hex Value | Architecture | Endianness |
|-------|-----------|--------------|------------|
| MIPSEBMAGIC | 0x0160 | MIPS R3000+ | Big-endian |
| MIPSELMAGIC | 0x0162 | MIPS R3000+ | Little-endian |
| ALPHAMAGIC | 0x0183 | DEC Alpha | Little-endian |

**ECOFF File Header (FILHDR) - 20 bytes:**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| f_magic | 0x00 | 2 | uint16 | Magic number (architecture) |
| f_nscns | 0x02 | 2 | uint16 | Number of sections |
| f_timdat | 0x04 | 4 | int32 | Unix timestamp |
| f_symptr | 0x08 | 4 | int32 | Symbolic header offset |
| f_nsyms | 0x0C | 4 | int32 | Symbolic header size |
| f_opthdr | 0x10 | 2 | uint16 | Optional header size |
| f_flags | 0x12 | 2 | uint16 | Flags |

**Section Flags:**

| Flag | Value | Description |
|------|-------|-------------|
| STYP_TEXT | 0x0020 | Contains text |
| STYP_DATA | 0x0040 | Contains data |
| STYP_BSS | 0x0080 | BSS section |
| STYP_RDATA | 0x0100 | Read-only data |
| STYP_SDATA | 0x0200 | Small data |
| STYP_SBSS | 0x0400 | Small BSS |

---

### HP-UX SOM (System Object Model) - PA-RISC

**Magic Bytes:**

| Magic | Hex Value | Description |
|-------|-----------|-------------|
| EXEC_MAGIC | 0x0107 | Executable |
| SHARE_MAGIC | 0x0108 | Shared library |
| DEMAND_MAGIC | 0x010B | Demand load executable |
| DL_MAGIC | 0x010D | Dynamic load library |

**SOM Header Structure (256 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| system_id | 0x00 | 2 | int16 | System ID (HP9000/800 = 0x20B) |
| a_magic | 0x02 | 2 | int16 | Magic number |
| version_id | 0x04 | 4 | uint32 | Version identifier |
| file_time | 0x08 | 4 | uint32 | Creation timestamp |
| entry_space | 0x0C | 4 | uint32 | Entry point space index |
| entry_subspace | 0x10 | 4 | uint32 | Entry point subspace index |
| entry_offset | 0x14 | 4 | uint32 | Entry point offset |
| aux_header_location | 0x18 | 4 | uint32 | Auxiliary header offset |
| aux_header_size | 0x1C | 4 | uint32 | Auxiliary header size |
| som_length | 0x20 | 4 | uint32 | Total file length |
| symbol_location | 0x58 | 4 | uint32 | Symbol records offset |
| symbol_total | 0x5C | 4 | uint32 | Symbol record count |

**Endianness:** Big-endian (PA-RISC native)

---

### Plan 9 a.out

Plan 9 uses a unique magic formula: `_MAGIC(b) = ((((4*b)+0)*b)+7)`

**Magic Bytes:**

| Name | Hex Value | Decimal | Architecture |
|------|-----------|---------|--------------|
| A_MAGIC | 0x00000107 | 263 | MC68020 |
| I_MAGIC | 0x00000197 | 407 | Intel 386 |
| K_MAGIC | 0x0000022B | 555 | SPARC |
| V_MAGIC | 0x00000367 | 871 | MIPS 3000 BE |
| E_MAGIC | 0x0000051F | 1311 | ARM |
| Q_MAGIC | 0x00000597 | 1431 | PowerPC |
| L_MAGIC | 0x00000693 | 1683 | DEC Alpha |
| S_MAGIC | 0x00000893 | 2195 | AMD64 |
| R_MAGIC | 0x000009BF | 2495 | ARM64 |

**Header Structure (32 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| magic | 0x00 | 4 | long | Magic number |
| text | 0x04 | 4 | long | Text segment size |
| data | 0x08 | 4 | long | Initialized data size |
| bss | 0x0C | 4 | long | Uninitialized data size |
| syms | 0x10 | 4 | long | Symbol table size |
| entry | 0x14 | 4 | long | Entry point |
| spsz | 0x18 | 4 | long | PC/SP offset table size |
| pcsz | 0x1C | 4 | long | PC/line number table size |

**Endianness:** Always big-endian header format (portable across architectures)

---

## DOS/Windows Legacy Formats

### MZ/DOS Executable Format

**Magic Bytes:**

| Offset | Value | Description |
|--------|-------|-------------|
| 0x00 | 0x4D5A ("MZ") | DOS MZ signature |
| 0x00 | 0x5A4D ("ZM") | Alternative signature (obsolete) |

**MZ Header Structure (64 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| e_magic | 0x00 | 2 | WORD | Magic "MZ" (0x5A4D) |
| e_cblp | 0x02 | 2 | WORD | Bytes on last page (0-511) |
| e_cp | 0x04 | 2 | WORD | Pages in file (512 bytes each) |
| e_crlc | 0x06 | 2 | WORD | Relocation entry count |
| e_cparhdr | 0x08 | 2 | WORD | Header size in paragraphs |
| e_minalloc | 0x0A | 2 | WORD | Minimum extra paragraphs |
| e_maxalloc | 0x0C | 2 | WORD | Maximum extra paragraphs |
| e_ss | 0x0E | 2 | WORD | Initial SS (relocatable) |
| e_sp | 0x10 | 2 | WORD | Initial SP |
| e_csum | 0x12 | 2 | WORD | Checksum |
| e_ip | 0x14 | 2 | WORD | Initial IP |
| e_cs | 0x16 | 2 | WORD | Initial CS (relocatable) |
| e_lfarlc | 0x18 | 2 | WORD | Relocation table offset |
| e_ovno | 0x1A | 2 | WORD | Overlay number |
| e_lfanew | 0x3C | 4 | DWORD | Offset to extended header (NE/LE/PE) |

**Relocation Entry (4 bytes):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Offset | 0x00 | 2 | Offset within segment |
| Segment | 0x02 | 2 | Segment relative to load segment |

---

### NE (New Executable) Format

**Magic:** `0x4E45` ("NE") at offset pointed by e_lfanew

**NE Header Structure (64 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| Signature | 0x00 | 2 | WORD | "NE" (0x454E) |
| MajLinkerVer | 0x02 | 1 | BYTE | Linker major version |
| MinLinkerVer | 0x03 | 1 | BYTE | Linker minor version |
| EntryTableOff | 0x04 | 2 | WORD | Entry table offset |
| EntryTableLen | 0x06 | 2 | WORD | Entry table length |
| FileLoadCRC | 0x08 | 4 | DWORD | 32-bit CRC |
| FlagWord | 0x0C | 2 | WORD | Program flags |
| AutoDataSeg | 0x0E | 2 | WORD | Auto data segment index |
| InitHeapSize | 0x10 | 2 | WORD | Initial heap size |
| InitStackSize | 0x12 | 2 | WORD | Initial stack size |
| EntryPoint | 0x14 | 4 | DWORD | CS:IP entry point |
| InitStack | 0x18 | 4 | DWORD | SS:SP initial stack |
| SegCount | 0x1C | 2 | WORD | Segment count |
| TargetOS | 0x36 | 1 | BYTE | Target OS |

**FlagWord Bits:**

| Bit | Mask | Description |
|-----|------|-------------|
| 0-1 | 0x0003 | DGROUP type |
| 3 | 0x0008 | Protected mode only |
| 8-10 | 0x0700 | Application type |
| 15 | 0x8000 | DLL/driver module |

**Target OS Values:**

| Value | Description |
|-------|-------------|
| 0 | Unknown |
| 1 | OS/2 |
| 2 | Windows |
| 3 | European MS-DOS 4.x |
| 4 | Windows 386 |

---

### LE/LX (Linear Executable) Format

**Magic Bytes:**

| Offset | Value | Description |
|--------|-------|-------------|
| e_lfanew | 0x4C45 ("LE") | Mixed 16/32-bit |
| e_lfanew | 0x4C58 ("LX") | 32-bit (OS/2 Warp) |

**LX Header Structure (0xAC bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| Signature | 0x00 | 2 | WORD | "LX" or "LE" |
| ByteOrder | 0x02 | 1 | BYTE | 0=Little, 1=Big |
| WordOrder | 0x03 | 1 | BYTE | 0=Little, 1=Big |
| FormatLevel | 0x04 | 4 | DWORD | Format level (0) |
| CPUType | 0x08 | 2 | WORD | 1=286, 2=386, 3=486 |
| OSType | 0x0A | 2 | WORD | 1=OS/2, 2=Windows, 3=DOS 4.x |
| ModuleFlags | 0x10 | 4 | DWORD | Module flags |
| ModulePages | 0x14 | 4 | DWORD | Page count |
| EIPObject | 0x18 | 4 | DWORD | Entry point object |
| EIP | 0x1C | 4 | DWORD | Entry point offset |
| ESPObject | 0x20 | 4 | DWORD | Stack object |
| ESP | 0x24 | 4 | DWORD | Stack offset |
| PageSize | 0x28 | 4 | DWORD | Page size (typically 4096) |

**Module Flags:**

| Bit | Mask | Description |
|-----|------|-------------|
| 2 | 0x00000004 | Per-process library init |
| 4 | 0x00000010 | Internal fixups applied |
| 5 | 0x00000020 | External fixups applied |
| 15 | 0x00008000 | Library (DLL) module |
| 17 | 0x00020000 | Physical device driver |

---

### OMF (Object Module Format)

**Record Structure:**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| RecordType | 0x00 | 1 | Record type identifier |
| RecordLength | 0x01 | 2 | Length of data + checksum |
| RecordData | 0x03 | n | Variable length data |
| Checksum | 0x03+n | 1 | Checksum (or 0) |

**Record Types:**

| Code | Name | Description |
|------|------|-------------|
| 0x80 | THEADR | Translator Header |
| 0x8A/8B | MODEND | Module End (16/32-bit) |
| 0x8C | EXTDEF | External Names Definition |
| 0x90/91 | PUBDEF | Public Names Definition |
| 0x96 | LNAMES | List of Names |
| 0x98/99 | SEGDEF | Segment Definition |
| 0x9A | GRPDEF | Group Definition |
| 0x9C/9D | FIXUPP | Fixup Record |
| 0xA0/A1 | LEDATA | Logical Enumerated Data |
| 0xB0 | COMDEF | Communal Names Definition |
| 0xC2/C3 | COMDAT | Initialized Communal Data |

**Note:** Odd record types (LSB=1) indicate 32-bit numeric fields.

---

## Apple/Mac Formats

### PEF (Preferred Executable Format)

**Magic Bytes:**

| Offset | Value | ASCII | Description |
|--------|-------|-------|-------------|
| 0x00 | 0x4A6F7921 | "Joy!" | Tag1 magic |
| 0x04 | 0x70656666 | "peff" | Format identifier |
| 0x08 | 0x70777063 | "pwpc" | PowerPC architecture |
| 0x08 | 0x6D36386B | "m68k" | 68K architecture |

**Container Header (40 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| tag1 | 0x00 | 4 | OSType | "Joy!" (0x4A6F7921) |
| tag2 | 0x04 | 4 | OSType | "peff" (0x70656666) |
| architecture | 0x08 | 4 | OSType | Target architecture |
| formatVersion | 0x0C | 4 | UInt32 | Container version (1) |
| dateTimeStamp | 0x10 | 4 | UInt32 | Mac OS date timestamp |
| oldDefVersion | 0x14 | 4 | UInt32 | Oldest definition version |
| oldImpVersion | 0x18 | 4 | UInt32 | Oldest implementation version |
| currentVersion | 0x1C | 4 | UInt32 | Current version |
| sectionCount | 0x20 | 2 | UInt16 | Section count |
| instSectionCount | 0x22 | 2 | UInt16 | Instantiated section count |

**Section Types:**

| Value | Name | Description |
|-------|------|-------------|
| 0 | kPEFCodeSection | Executable code (read-only) |
| 1 | kPEFUnpackedDataSection | Unpacked data (read-write) |
| 2 | kPEFPatternInitDataSection | Pattern-initialized data |
| 3 | kPEFConstantSection | Constant/read-only data |
| 4 | kPEFLoaderSection | Loader section |
| 5 | kPEFDebugSection | Debug information |

---

### Universal Binary (Fat Binary)

**Magic Bytes:**

| Format | Big-Endian | Little-Endian | Description |
|--------|------------|---------------|-------------|
| FAT_MAGIC | 0xCAFEBABE | 0xBEBAFECA | 32-bit fat binary |
| FAT_MAGIC_64 | 0xCAFEBABF | 0xBFBAFECA | 64-bit fat binary |

**fat_header Structure (8 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| magic | 0x00 | 4 | uint32_t | FAT_MAGIC or FAT_MAGIC_64 |
| nfat_arch | 0x04 | 4 | uint32_t | Number of architectures |

**fat_arch Structure (20 bytes per architecture):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| cputype | 0x00 | 4 | int32_t | CPU type identifier |
| cpusubtype | 0x04 | 4 | int32_t | CPU subtype identifier |
| offset | 0x08 | 4 | uint32_t | File offset to Mach-O slice |
| size | 0x0C | 4 | uint32_t | Mach-O slice size |
| align | 0x10 | 4 | uint32_t | Alignment (power of 2) |

**CPU Type Constants:**

| Constant | Value | Description |
|----------|-------|-------------|
| CPU_TYPE_MC680x0 | 6 | Motorola 68K |
| CPU_TYPE_X86 | 7 | Intel x86 (32-bit) |
| CPU_TYPE_X86_64 | 0x01000007 | Intel x86-64 |
| CPU_TYPE_ARM | 12 | ARM (32-bit) |
| CPU_TYPE_ARM64 | 0x0100000C | ARM64 |
| CPU_TYPE_POWERPC | 18 | PowerPC (32-bit) |
| CPU_TYPE_POWERPC64 | 0x01000012 | PowerPC 64-bit |

---

## Embedded/NoMMU Formats

### bFLT (Binary Flat Format)

**Magic Bytes:**

| Offset | Value | ASCII |
|--------|-------|-------|
| 0x00 | 0x62464C54 | "bFLT" |

**Header Structure (64 bytes):**

| Field Name | Offset | Size | Type | Description |
|------------|--------|------|------|-------------|
| magic | 0x00 | 4 | char[4] | "bFLT" (0x62464C54) |
| rev | 0x04 | 4 | __be32 | Version (v2=2, v4=4) |
| entry | 0x08 | 4 | __be32 | Entry point offset |
| data_start | 0x0C | 4 | __be32 | Data segment offset |
| data_end | 0x10 | 4 | __be32 | Data segment end |
| bss_end | 0x14 | 4 | __be32 | BSS segment end |
| stack_size | 0x18 | 4 | __be32 | Stack size |
| reloc_start | 0x1C | 4 | __be32 | Relocation records offset |
| reloc_count | 0x20 | 4 | __be32 | Relocation record count |
| flags | 0x24 | 4 | __be32 | Flags |
| build_date | 0x28 | 4 | __be32 | Build timestamp |
| filler | 0x2C | 20 | __be32[5] | Reserved |

**Flags:**

| Flag | Value | Bit | Description |
|------|-------|-----|-------------|
| FLAT_FLAG_RAM | 0x0001 | 0 | Load entire program into RAM |
| FLAT_FLAG_GOTPIC | 0x0002 | 1 | PIC with GOT |
| FLAT_FLAG_GZIP | 0x0004 | 2 | gzip compressed |
| FLAT_FLAG_GZDATA | 0x0008 | 3 | Only data compressed (for XIP) |
| FLAT_FLAG_KTRACE | 0x0010 | 4 | Kernel tracing |
| FLAT_FLAG_L1STK | 0x0020 | 5 | L1 scratch memory stack (Blackfin) |

**Endianness:** All header fields are big-endian (network byte order)

---

### ELF-FDPIC (Function Descriptor PIC)

**Magic Bytes:** Standard ELF `0x7F 45 4C 46` with FDPIC-specific EI_OSABI

**EI_OSABI Values:**

| Architecture | Value | Constant |
|--------------|-------|----------|
| ARM | 65 (0x41) | ELFOSABI_ARM_FDPIC |
| FR-V | 65 (0x41) | ELFOSABI_FRV_FDPIC |
| Blackfin | 65 (0x41) | ELFOSABI_BFIN_FDPIC |

**Function Descriptor Structure:**

| Field | Size | Description |
|-------|------|-------------|
| entry_point | 4/8 bytes | Function entry address |
| got_value | 4/8 bytes | GOT base (FDPIC register value) |

**ARM FDPIC Relocations:**

| Relocation | Value | Description |
|------------|-------|-------------|
| R_ARM_FUNCDESC | 161 | Function descriptor GOT entry |
| R_ARM_FUNCDESC_VALUE | 162 | Canonical function descriptor |
| R_ARM_GOTFUNCDESC | 163 | Preemptible function descriptor |
| R_ARM_TLS_GD32_FDPIC | 187 | TLS General Dynamic |
| R_ARM_TLS_IE32_FDPIC | 189 | TLS Initial Exec |

---

## Mainframe Formats

### GOFF (Generalized Object File Format) - z/Architecture

**Magic/Identifier:** `0x03` at record offset 0

**PTV Field (First 3 bytes of every record):**

| Byte | Bits | Value | Purpose |
|------|------|-------|---------|
| 0 | All | 0x03 | GOFF record marker |
| 1 | 0-3 | 0x0-0xF | Record type |
| 1 | 6-7 | 0b00-11 | Continuation flags |
| 2 | All | 0x00 | Version number |

**Record Types:**

| Type | Hex | Description |
|------|-----|-------------|
| HDR | 0x03F0XX | Header record |
| ESD | 0x0300XX | External Symbol Dictionary |
| TXT | 0x0310XX | Text record |
| RLD | 0x0320XX | Relocation Dictionary |
| LEN | 0x0330XX | Length record |
| END | 0x0340XX | End record |

**ESD Symbol Types:**

| Value | Type | Description |
|-------|------|-------------|
| 0x00 | SD | Section Definition |
| 0x01 | ED | External Definition |
| 0x02 | LD | Label Definition |
| 0x03 | PR | Part Reference |
| 0x04 | ER/WX | External/Weak Reference |

**Endianness:** Big-endian, EBCDIC character encoding

---

### VMS Object/Image Format

**VAX Object Record Types:**

| Type | Code | Description |
|------|------|-------------|
| MHD | OBJ$C_MHD | Module Header |
| GSD | OBJ$C_GSD | Global Symbol Directory |
| TIR | OBJ$C_TIR | Text Information/Relocation |
| EOM | OBJ$C_EOM | End of Module |
| DBG | OBJ$C_DBG | Debugger Information |

**Alpha PSECT Flags:**

| Bit | Symbol | Meaning |
|-----|--------|---------|
| 0 | EGPS$V_PIC | Position Independent |
| 4 | EGPS$V_GBL | Global scope |
| 5 | EGPS$V_SHR | Shareable |
| 6 | EGPS$V_EXE | Executable |
| 7 | EGPS$V_RD | Readable |
| 8 | EGPS$V_WRT | Writable |

**Endianness:** Little-endian (all VMS platforms)

---

## Text-Based Hex Formats

### Intel HEX Format

**Record Structure:** `:LLAAAATT[DD...]CC`

| Field | Position | Size | Description |
|-------|----------|------|-------------|
| Start Code | 1 | 1 | `:` (0x3A) |
| Byte Count | 2-3 | 2 | Data byte count |
| Address | 4-7 | 4 | 16-bit start address |
| Record Type | 8-9 | 2 | Type identifier |
| Data | 10+ | Variable | Data bytes |
| Checksum | Last 2 | 2 | Two's complement |

**Record Types:**

| Type | Start | Address | Description |
|------|-------|---------|-------------|
| 00 | `:` | 16-bit offset | Data Record |
| 01 | `:` | 0000 | End Of File |
| 02 | `:` | 0000 | Extended Segment Address (20-bit) |
| 03 | `:` | 0000 | Start Segment Address (CS:IP) |
| 04 | `:` | 0000 | Extended Linear Address (32-bit) |
| 05 | `:` | 0000 | Start Linear Address (EIP) |

**Checksum:** `(0x100 - (Sum of all bytes)) & 0xFF`

---

### Motorola S-Record (SREC)

**Record Structure:** `StLLAAAA[DD...]CC`

**Record Types:**

| Type | Address Size | Description |
|------|--------------|-------------|
| S0 | 16-bit (0000) | Header/vendor info |
| S1 | 16-bit (2 bytes) | Data (64KB range) |
| S2 | 24-bit (3 bytes) | Data (16MB range) |
| S3 | 32-bit (4 bytes) | Data (4GB range) |
| S5 | 16-bit | Record count |
| S6 | 24-bit | Record count |
| S7 | 32-bit | Termination (ends S3) |
| S8 | 24-bit | Termination (ends S2) |
| S9 | 16-bit | Termination (ends S1) |

**Checksum:** `0xFF - ((Sum of all bytes) & 0xFF)`

---

### TI-TXT Format

**Format:**
```
@ADDR
DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD DD
q
```

| Element | Format | Description |
|---------|--------|-------------|
| Section Address | `@XXXX` | Hexadecimal address |
| Data Bytes | `XX XX...` | Space-separated hex bytes |
| EOF Marker | `q` | End-of-file indicator |

**No checksum** - TI-TXT does not include verification

---

## Virtual Machine Bytecode Formats

### WebAssembly (.wasm)

**Magic Bytes:**

| Offset | Value | Description |
|--------|-------|-------------|
| 0x00 | `0x00 0x61 0x73 0x6D` | "\0asm" |
| 0x04 | `0x01 0x00 0x00 0x00` | Version 1 |

**Section IDs:**

| ID | Hex | Section | Description |
|----|-----|---------|-------------|
| 0 | 0x00 | Custom | Extensions/debugging |
| 1 | 0x01 | Type | Function signatures |
| 2 | 0x02 | Import | External dependencies |
| 3 | 0x03 | Function | Function type indices |
| 4 | 0x04 | Table | Table definitions |
| 5 | 0x05 | Memory | Linear memory |
| 6 | 0x06 | Global | Global variables |
| 7 | 0x07 | Export | Exported items |
| 8 | 0x08 | Start | Entry function |
| 9 | 0x09 | Element | Table init data |
| 10 | 0x0A | Code | Function bodies |
| 11 | 0x0B | Data | Memory data |
| 12 | 0x0C | DataCount | Data segment count |

**Type Encodings:**

| Type | Hex | Size |
|------|-----|------|
| i32 | 0x7F | 32-bit |
| i64 | 0x7E | 64-bit |
| f32 | 0x7D | 32-bit |
| f64 | 0x7C | 64-bit |
| v128 | 0x7B | 128-bit |
| funcref | 0x70 | reference |
| externref | 0x6F | reference |

---

### Java Class File Format

**Magic:** `0xCAFEBABE` at offset 0x00

**Header Structure:**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| magic | 0x00 | 4 | u4 | 0xCAFEBABE |
| minor_version | 0x04 | 2 | u2 | Minor version |
| major_version | 0x06 | 2 | u2 | Major version |
| constant_pool_count | 0x08 | 2 | u2 | Pool entries + 1 |

**Constant Pool Tags:**

| Tag | Type | Size |
|-----|------|------|
| 1 | CONSTANT_Utf8 | 3 + length |
| 3 | CONSTANT_Integer | 5 |
| 4 | CONSTANT_Float | 5 |
| 5 | CONSTANT_Long | 9 (2 slots) |
| 6 | CONSTANT_Double | 9 (2 slots) |
| 7 | CONSTANT_Class | 3 |
| 8 | CONSTANT_String | 3 |
| 9 | CONSTANT_Fieldref | 5 |
| 10 | CONSTANT_Methodref | 5 |
| 12 | CONSTANT_NameAndType | 5 |

**Version Mappings:**

| Java | Major | Minor |
|------|-------|-------|
| 8 | 52 | 0 |
| 11 | 55 | 0 |
| 17 | 61 | 0 |
| 21 | 65 | 0 |

**Endianness:** Big-endian

---

### DEX (Dalvik Executable)

**Magic Bytes:**

| Version | Magic | Android |
|---------|-------|---------|
| 035 | `dex\n035\0` | Pre-7.0 |
| 037 | `dex\n037\0` | 7.0+ |
| 038 | `dex\n038\0` | 8.0+ |
| 039 | `dex\n039\0` | 9.0+ |
| 040 | `dex\n040\0` | 10.0+ |

**Header Structure (112 bytes):**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| magic | 0x00 | 8 | ubyte[8] | DEX magic |
| checksum | 0x08 | 4 | uint | Adler32 checksum |
| signature | 0x0C | 20 | ubyte[20] | SHA-1 hash |
| file_size | 0x20 | 4 | uint | File size |
| header_size | 0x24 | 4 | uint | Header size (0x70) |
| endian_tag | 0x28 | 4 | uint | 0x12345678 = LE |
| string_ids_size | 0x38 | 4 | uint | String count |
| type_ids_size | 0x40 | 4 | uint | Type count (max 65535) |
| method_ids_size | 0x58 | 4 | uint | Method count |
| class_defs_size | 0x60 | 4 | uint | Class count |

**Access Flags:**

| Flag | Value | Classes | Methods |
|------|-------|---------|---------|
| ACC_PUBLIC | 0x0001 | ✓ | ✓ |
| ACC_PRIVATE | 0x0002 | ✓ | ✓ |
| ACC_STATIC | 0x0008 | ✓ | ✓ |
| ACC_FINAL | 0x0010 | ✓ | ✓ |
| ACC_INTERFACE | 0x0200 | ✓ | - |
| ACC_ABSTRACT | 0x0400 | ✓ | ✓ |
| ACC_SYNTHETIC | 0x1000 | ✓ | ✓ |
| ACC_CONSTRUCTOR | 0x10000 | - | ✓ |

---

### CLI/PE+ (.NET Assemblies)

**Magic Bytes:**

| Offset | Value | Description |
|--------|-------|-------------|
| 0x00 | 0x5A4D | "MZ" DOS header |
| e_lfanew | 0x00004550 | "PE\0\0" |

**CLI Header (72 bytes):**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| cb | 0x00 | 4 | DWORD | Size (72) |
| MajorRuntimeVersion | 0x04 | 2 | WORD | CLR major |
| MinorRuntimeVersion | 0x06 | 2 | WORD | CLR minor |
| MetaData | 0x08 | 8 | DATA_DIR | Metadata RVA/size |
| Flags | 0x10 | 4 | DWORD | COM flags |
| EntryPointToken | 0x14 | 4 | DWORD | Entry point |

**Metadata Root Magic:** `0x424A5342` ("BSJB")

**Metadata Streams:**

| Stream | Description |
|--------|-------------|
| #~ | Compressed metadata tables |
| #Strings | UTF-8 name heap |
| #US | User strings (unicode) |
| #GUID | GUID heap |
| #Blob | Binary data heap |

---

## Multi-Architecture Containers

### FatELF

**Magic:** `0x1F0E70FA` at offset 0x00 (little-endian)

**fatelf_header (8 bytes):**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| magic | 0x00 | 4 | uint32_t | 0x1F0E70FA |
| version | 0x04 | 2 | uint16_t | Format version (1) |
| num_records | 0x06 | 1 | uint8_t | ELF binary count |
| reserved | 0x07 | 1 | uint8_t | Reserved (0) |

**fatelf_record (24 bytes per record):**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| machine | 0x00 | 2 | uint16_t | ELF e_machine |
| osabi | 0x02 | 1 | uint8_t | EI_OSABI |
| osabi_version | 0x03 | 1 | uint8_t | EI_ABIVERSION |
| word_size | 0x04 | 1 | uint8_t | EI_CLASS (1=32, 2=64) |
| byte_order | 0x05 | 1 | uint8_t | EI_DATA (1=LE, 2=BE) |
| offset | 0x08 | 8 | uint64_t | ELF binary offset |
| size | 0x10 | 8 | uint64_t | ELF binary size |

---

### ar Archives

**Magic:** `!<arch>\n` (0x213C617263683E0A)

**Member Header (60 bytes):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| ar_name | 0x00 | 16 | Member name |
| ar_date | 0x10 | 12 | Modification time |
| ar_uid | 0x1C | 6 | User ID |
| ar_gid | 0x22 | 6 | Group ID |
| ar_mode | 0x28 | 8 | File mode (octal) |
| ar_size | 0x30 | 10 | File size |
| ar_fmag | 0x3A | 2 | "`\n" (0x60 0x0A) |

**Special Members:**

| Name | Variant | Description |
|------|---------|-------------|
| `/` | GNU/SysV | Symbol table (big-endian) |
| `//` | GNU/SysV | Long filename table |
| `__.SYMDEF` | BSD | Symbol table |
| `#1/nn` | BSD | Extended filename |

---

## Game Console Formats

### XBE (Original Xbox)

**Magic:** `0x48454258` ("XBEH") at offset 0x00

**Header Structure:**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Magic | 0x0000 | 4 | "XBEH" |
| Digital Signature | 0x0004 | 256 | RSA signature |
| Base Address | 0x0104 | 4 | Load address (0x00010000) |
| Size of Headers | 0x0108 | 4 | Reserved headers |
| Size of Image | 0x010C | 4 | Total image size |
| Entry Point | 0x0128 | 4 | XOR-encoded entry |
| TLS Address | 0x012C | 4 | Thread Local Storage |
| Kernel Thunk | 0x0158 | 4 | XOR-encoded thunk |

**Entry Point XOR Keys:**

| Build | Entry Key | Thunk Key |
|-------|-----------|-----------|
| Beta | 0xE682F45B | 0x46437DCD |
| Debug | 0x94859D4B | 0xEFB1F152 |
| Retail | 0xA8FC57AB | 0x5B6D40B6 |

---

### XEX (Xbox 360)

**Magic:** `0x58455832` ("XEX2") at offset 0x00

**Header Structure (24 bytes):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Magic | 0x00 | 4 | "XEX2" |
| Module Flags | 0x04 | 4 | Module type |
| PE Data Offset | 0x08 | 4 | PE offset |
| Security Info Offset | 0x10 | 4 | Security header |
| Optional Header Count | 0x14 | 4 | Header count |

**Module Flags:**

| Flag | Bit | Description |
|------|-----|-------------|
| Title Module | 0 | Main executable |
| DLL Module | 3 | Dynamic library |
| Patch Module | 4 | Patch |
| User Mode | 7 | User mode exec |

**Endianness:** Big-endian (PowerPC Xenon)

---

### SELF/SPRX (PlayStation 3/4/5)

**PS3 Magic:** `0x53434500` ("SCE\0") at offset 0x00

**SCE Header:**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Magic | 0x00 | 4 | "SCE\0" |
| Version | 0x04 | 4 | Header version (2) |
| Key Revision | 0x08 | 2 | Key revision |
| Header Type | 0x0A | 2 | 1=SELF, 2=RVK, 3=PKG |
| Metadata Offset | 0x0C | 4 | Metadata location |
| Header Length | 0x10 | 8 | Total header length |
| Data Length | 0x18 | 8 | Total data length |

**PS4 Magic:** `0x4F15F3D1` at offset 0x00

**Program Types:**

| Value | Type |
|-------|------|
| 1 | LV0 |
| 2 | LV1 |
| 3 | LV2 |
| 4 | Application |
| 8 | NPDRM Application |

---

### NSO/NRO (Nintendo Switch)

**NSO Magic:** `NSO0` (0x4E534F30) at offset 0x00

**NSO Header (0x100 bytes):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Magic | 0x00 | 4 | "NSO0" |
| Version | 0x04 | 4 | Format version |
| Flags | 0x0C | 4 | Compression/hash flags |
| TextFileOffset | 0x10 | 4 | .text file offset |
| TextMemoryOffset | 0x14 | 4 | .text memory offset |
| TextSize | 0x18 | 4 | Decompressed .text size |
| ModuleId | 0x40 | 32 | Build ID (SHA) |
| TextHash | 0xA0 | 32 | SHA-256 of .text |
| RoHash | 0xC0 | 32 | SHA-256 of .rodata |
| DataHash | 0xE0 | 32 | SHA-256 of .data |

**NSO Flags:**

| Bit | Description |
|-----|-------------|
| 0 | .text LZ4 compressed |
| 1 | .rodata LZ4 compressed |
| 2 | .data LZ4 compressed |
| 3 | .text hash verify |
| 4 | .rodata hash verify |
| 5 | .data hash verify |

**NRO Magic:** `NRO0` (0x4E524F30) at offset 0x10

**MOD0 Magic:** `MOD0` (0x4D4F4430)

---

### DOL (GameCube/Wii)

**Magic:** None (starts with section offsets)

**Header Structure (0x100 bytes):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| TextOffsets[7] | 0x00 | 28 | .text0-.text6 file offsets |
| DataOffsets[11] | 0x1C | 44 | .data0-.data10 file offsets |
| TextAddresses[7] | 0x48 | 28 | .text0-.text6 load addresses |
| DataAddresses[11] | 0x64 | 44 | .data0-.data10 load addresses |
| TextSizes[7] | 0x90 | 28 | .text section sizes |
| DataSizes[11] | 0xAC | 44 | .data section sizes |
| BssAddress | 0xD8 | 4 | BSS load address |
| BssSize | 0xDC | 4 | BSS size |
| EntryPoint | 0xE0 | 4 | Entry point |

**Endianness:** Big-endian (PowerPC)

---

## Kernel/Boot Formats

### Linux x86 Boot Header

**Magic:**
- `0xAA55` at offset 0x1FE (boot_flag)
- `"HdrS"` (0x53726448) at offset 0x202

**Header Structure (0x1F1-0x268):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| setup_sects | 0x1F1 | 1 | Setup sectors |
| boot_flag | 0x1FE | 2 | 0xAA55 |
| header | 0x202 | 4 | "HdrS" |
| version | 0x206 | 2 | Protocol version |
| type_of_loader | 0x210 | 1 | Boot loader ID |
| loadflags | 0x211 | 1 | Boot options |
| code32_start | 0x214 | 4 | Protected mode entry |
| ramdisk_image | 0x218 | 4 | initrd address |
| ramdisk_size | 0x21C | 4 | initrd size |
| cmd_line_ptr | 0x228 | 4 | Command line address |

**ARM64 Image Magic:** `0x644d5241` ("ARM\x64") at offset 0x38

**RISC-V Image Magic:** `0x5643534952` ("RISCV") at offset 0x30

---

### uImage (U-Boot Legacy)

**Magic:** `0x27051956` at offset 0x00

**Header Structure (64 bytes):**

| Field | Offset | Size | Type | Description |
|-------|--------|------|------|-------------|
| ih_magic | 0x00 | 4 | u32 | 0x27051956 |
| ih_hcrc | 0x04 | 4 | u32 | Header CRC32 |
| ih_time | 0x08 | 4 | u32 | Timestamp |
| ih_size | 0x0C | 4 | u32 | Data size |
| ih_load | 0x10 | 4 | u32 | Load address |
| ih_ep | 0x14 | 4 | u32 | Entry point |
| ih_dcrc | 0x18 | 4 | u32 | Data CRC32 |
| ih_os | 0x1C | 1 | u8 | OS type |
| ih_arch | 0x1D | 1 | u8 | Architecture |
| ih_type | 0x1E | 1 | u8 | Image type |
| ih_comp | 0x1F | 1 | u8 | Compression |
| ih_name | 0x20 | 32 | char[32] | Image name |

**Endianness:** Big-endian

**Architecture Types:**

| Value | Architecture |
|-------|--------------|
| 0x02 | ARM |
| 0x03 | x86 |
| 0x05 | MIPS |
| 0x07 | PowerPC |
| 0x16 | ARM64 |
| 0x1A | RISC-V |

---

### UEFI PE32+

**Magic:**
- `0x5A4D` ("MZ") at offset 0x00
- `0x00004550` ("PE\0\0") at e_lfanew offset

**Machine Types:**

| Value | Architecture |
|-------|--------------|
| 0x014C | x86 |
| 0x8664 | x86-64 |
| 0x01C4 | ARM Thumb-2 |
| 0xAA64 | ARM64 |
| 0x5064 | RISC-V64 |
| 0x0EBC | EFI Byte Code |

**UEFI Subsystem Values:**

| Value | Subsystem |
|-------|-----------|
| 10 | EFI_APPLICATION |
| 11 | EFI_BOOT_SERVICE_DRIVER |
| 12 | EFI_RUNTIME_DRIVER |

**Optional Header Magic:**
- `0x10B` = PE32 (32-bit)
- `0x20B` = PE32+ (64-bit)

---

## Summary Comparison Tables

### Format Overview by Category

| Category | Formats | Era | Typical Endianness |
|----------|---------|-----|-------------------|
| Unix Legacy | a.out, ECOFF, SOM | 1970s-1990s | Varies by arch |
| DOS/Windows | MZ, NE, LE/LX, OMF | 1980s-2000s | Little-endian |
| Apple | PEF, Fat Binary | 1990s-present | Big/Little |
| Embedded | bFLT, ELF-FDPIC | 2000s-present | Varies |
| Mainframe | GOFF, MVS, VMS | 1960s-present | Big (GOFF), Little (VMS) |
| VM Bytecode | WASM, Java, DEX, CLI | 1990s-present | Little (WASM), Big (Java) |
| Game Console | XBE, XEX, SELF, NSO, DOL | 2000s-present | Varies by platform |
| Boot/Kernel | zImage, uImage, FIT, UEFI | 1990s-present | Varies |

### Magic Bytes Quick Reference

| Format | Magic | Offset | Hex Value |
|--------|-------|--------|-----------|
| a.out (ZMAGIC) | - | 0x00 | 0x010B |
| MZ/DOS | "MZ" | 0x00 | 0x4D5A |
| NE | "NE" | e_lfanew | 0x4E45 |
| PE | "PE\0\0" | e_lfanew | 0x00004550 |
| ELF | "\x7FELF" | 0x00 | 0x7F454C46 |
| Fat Binary | - | 0x00 | 0xCAFEBABE |
| bFLT | "bFLT" | 0x00 | 0x62464C54 |
| Java Class | - | 0x00 | 0xCAFEBABE |
| DEX | "dex\n" | 0x00 | 0x6465780A |
| WebAssembly | "\0asm" | 0x00 | 0x0061736D |
| XBE | "XBEH" | 0x00 | 0x48454258 |
| XEX | "XEX2" | 0x00 | 0x58455832 |
| PS3 SELF | "SCE\0" | 0x00 | 0x53434500 |
| NSO | "NSO0" | 0x00 | 0x4E534F30 |
| NRO | "NRO0" | 0x10 | 0x4E524F30 |
| uImage | - | 0x00 | 0x27051956 |
| FIT/DTB | - | 0x00 | 0xD00DFEED |
| Intel HEX | ":" | 0 | 0x3A |
| S-Record | "S" | 0 | 0x53 |
| ar archive | "!<arch>\n" | 0x00 | 0x213C617263683E0A |

### Endianness by Platform

| Platform | Endianness | Notes |
|----------|------------|-------|
| x86/x86-64 | Little | All Intel/AMD |
| ARM | Little | Modern ARM |
| ARM64 | Little | Apple Silicon, etc. |
| PowerPC | Big | GameCube, Wii, PS3, Xbox 360 |
| MIPS | Both | BE (SGI), LE (PlayStation) |
| SPARC | Big | Sun systems |
| PA-RISC | Big | HP-UX |
| z/Architecture | Big | IBM mainframes |
| RISC-V | Little | Emerging standard |

---

*This reference compiled from official vendor documentation (Microsoft, Apple, IBM, Oracle, Nintendo, Sony), implementation sources (Linux kernel, LLVM, GNU binutils), community documentation (Switchbrew, WiiBrew, PSDevWiki), and authoritative specifications (ECMA-335, UEFI, WebAssembly).*
