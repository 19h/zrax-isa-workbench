//! Core types for the ISA classifier.
//!
//! This module defines all fundamental types used to represent
//! binary classification results, including ISA identifiers,
//! extensions, variants, and confidence levels.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Instruction Set Architecture identifiers.
///
/// Comprehensive enumeration of all supported processor architectures,
/// covering mainstream, embedded, and legacy systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Isa {
    // x86 family
    X86,
    X86_64,

    // ARM family
    Arm,
    AArch64,

    // RISC-V family
    RiscV32,
    RiscV64,
    RiscV128,

    // MIPS family
    Mips,
    Mips64,

    // PowerPC family
    Ppc,
    Ppc64,

    // IBM mainframe
    S390,
    S390x,

    // SPARC family
    Sparc,
    Sparc64,

    // Motorola 68k family
    M68k,
    ColdFire,

    // SuperH family
    Sh,
    Sh4,

    // Intel IA-64
    Ia64,

    // DEC Alpha
    Alpha,

    // HP PA-RISC
    Parisc,

    // LoongArch
    LoongArch32,
    LoongArch64,

    // Qualcomm Hexagon
    Hexagon,

    // Synopsys ARC
    Arc,
    ArcCompact,
    ArcCompact2,

    // Tensilica Xtensa
    Xtensa,

    // Xilinx MicroBlaze
    MicroBlaze,

    // Altera Nios II
    Nios2,

    // OpenRISC
    OpenRisc,

    // Lanai
    Lanai,

    // C-SKY
    Csky,

    // NEC V850
    V850,
    // Renesas RH850 (V850 successor)
    Rh850,

    // NEC 78K0R (legacy family, distinct from RL78)
    K78k0r,

    // Renesas RX
    Rx,

    // TI DSP
    TiC6000,
    TiC2000,
    TiC28x,
    TiC5500,
    TiPru,

    // Analog Devices
    Blackfin,
    Sharc,

    // Infineon TriCore
    Tricore,

    // Freescale/NXP HCS12X (MC68HC12 / CPU12) — automotive 16-bit big-endian MCU
    Hcs12,

    // NXP/Freescale S12Z (CPUZ) — 16-bit successor family to HCS12X
    S12z,

    // Motorola/Freescale 68HC11 — 8-bit big-endian MCU (predecessor to HC12)
    Hc11,

    // Infineon/Siemens C166 (C16x/ST10) — automotive 16-bit little-endian MCU
    C166,

    // Renesas RL78 (successor to NEC 78K) — 8/16-bit little-endian MCU
    Rl78,

    // Embedded/Microcontrollers
    Avr,
    Avr32,
    Msp430,
    Pic,
    Stm8,

    // GPU/Accelerators
    AmdGpu,
    Cuda,
    Bpf,

    // Intel legacy
    I860,
    I960,

    // Various
    Vax,
    Pdp11,
    Z80,
    Mcs6502,
    W65816,

    // Elbrus
    Elbrus,

    // Tilera
    Tile64,
    TilePro,
    TileGx,

    // Broadcom VideoCore
    VideoCore3,
    VideoCore5,

    // Kalray
    Kvx,

    // MCST Elbrus
    McstElbrus,

    // Fujitsu FR-V
    Frv,

    // Fujitsu FR family
    Fr30,
    Fr80,

    // PowerPC VLE encoding profile (automotive e200/e500-class firmware)
    PpcVle,

    // Virtual Machine ISAs
    /// WebAssembly virtual stack machine
    Wasm,
    /// Java Virtual Machine bytecode
    Jvm,
    /// Dalvik/ART bytecode (Android)
    Dalvik,
    /// Common Language Runtime (CLR/.NET)
    Clr,
    /// EFI Byte Code
    Ebc,

    // Cell BE / PlayStation 3
    /// Cell Broadband Engine SPU
    CellSpu,

    // Unknown with numeric ID
    Unknown(u32),
}

impl Isa {
    /// Returns a human-readable name for this ISA.
    pub fn name(&self) -> &'static str {
        match self {
            Isa::X86 => "x86 (i386)",
            Isa::X86_64 => "x86-64 (AMD64)",
            Isa::Arm => "ARM (32-bit)",
            Isa::AArch64 => "AArch64 (ARM64)",
            Isa::RiscV32 => "RISC-V (32-bit)",
            Isa::RiscV64 => "RISC-V (64-bit)",
            Isa::RiscV128 => "RISC-V (128-bit)",
            Isa::Mips => "MIPS (32-bit)",
            Isa::Mips64 => "MIPS (64-bit)",
            Isa::Ppc => "PowerPC (32-bit)",
            Isa::Ppc64 => "PowerPC (64-bit)",
            Isa::S390 => "IBM S/390",
            Isa::S390x => "IBM z/Architecture",
            Isa::Sparc => "SPARC (32-bit)",
            Isa::Sparc64 => "SPARC (64-bit)",
            Isa::M68k => "Motorola 68000",
            Isa::ColdFire => "Motorola ColdFire",
            Isa::Sh => "SuperH",
            Isa::Sh4 => "SuperH SH-4",
            Isa::Ia64 => "Intel IA-64 (Itanium)",
            Isa::Alpha => "DEC Alpha",
            Isa::Parisc => "HP PA-RISC",
            Isa::LoongArch32 => "LoongArch (32-bit)",
            Isa::LoongArch64 => "LoongArch (64-bit)",
            Isa::Hexagon => "Qualcomm Hexagon",
            Isa::Arc => "ARC",
            Isa::ArcCompact => "ARC ARCompact",
            Isa::ArcCompact2 => "ARC ARCv2",
            Isa::Xtensa => "Tensilica Xtensa",
            Isa::MicroBlaze => "Xilinx MicroBlaze",
            Isa::Nios2 => "Altera Nios II",
            Isa::OpenRisc => "OpenRISC",
            Isa::Lanai => "Lanai",
            Isa::Csky => "C-SKY",
            Isa::V850 => "NEC V850",
            Isa::Rh850 => "Renesas RH850",
            Isa::K78k0r => "NEC 78K0R",
            Isa::Rx => "Renesas RX",
            Isa::TiC6000 => "TI TMS320C6000",
            Isa::TiC2000 => "TI TMS320C2000",
            Isa::TiC28x => "TI TMS320C28x",
            Isa::TiC5500 => "TI TMS320C55x",
            Isa::TiPru => "TI PRU",
            Isa::Blackfin => "Analog Devices Blackfin",
            Isa::Sharc => "Analog Devices SHARC",
            Isa::Tricore => "Infineon TriCore",
            Isa::Hcs12 => "Freescale/NXP HCS12",
            Isa::S12z => "NXP/Freescale S12Z",
            Isa::Hc11 => "Motorola 68HC11",
            Isa::C166 => "Infineon/Siemens C166",
            Isa::Rl78 => "Renesas RL78",
            Isa::Avr => "Atmel AVR",
            Isa::Avr32 => "Atmel AVR32",
            Isa::Msp430 => "TI MSP430",
            Isa::Pic => "Microchip PIC",
            Isa::Stm8 => "STMicro STM8",
            Isa::AmdGpu => "AMD GPU",
            Isa::Cuda => "NVIDIA CUDA",
            Isa::Bpf => "Linux BPF",
            Isa::I860 => "Intel i860",
            Isa::I960 => "Intel i960",
            Isa::Vax => "DEC VAX",
            Isa::Pdp11 => "DEC PDP-11",
            Isa::Z80 => "Zilog Z80",
            Isa::Mcs6502 => "MOS 6502",
            Isa::W65816 => "WDC 65816",
            Isa::Elbrus => "Elbrus",
            Isa::Tile64 => "Tilera TILE64",
            Isa::TilePro => "Tilera TILEPro",
            Isa::TileGx => "Tilera TILE-Gx",
            Isa::VideoCore3 => "Broadcom VideoCore III",
            Isa::VideoCore5 => "Broadcom VideoCore V",
            Isa::Kvx => "Kalray VLIW",
            Isa::McstElbrus => "MCST Elbrus",
            Isa::Frv => "Fujitsu FR-V",
            Isa::Fr30 => "Fujitsu FR30",
            Isa::Fr80 => "Fujitsu FR80",
            Isa::PpcVle => "PowerPC VLE",
            Isa::Wasm => "WebAssembly",
            Isa::Jvm => "JVM Bytecode",
            Isa::Dalvik => "Dalvik/ART Bytecode",
            Isa::Clr => "CLR/.NET Bytecode",
            Isa::Ebc => "EFI Byte Code",
            Isa::CellSpu => "Cell SPU",
            Isa::Unknown(_) => "Unknown",
        }
    }

    /// Returns the default bitwidth for this ISA.
    pub fn default_bitwidth(&self) -> u8 {
        match self {
            Isa::X86
            | Isa::Arm
            | Isa::RiscV32
            | Isa::Mips
            | Isa::Ppc
            | Isa::S390
            | Isa::Sparc
            | Isa::M68k
            | Isa::ColdFire
            | Isa::Sh
            | Isa::Sh4
            | Isa::Parisc
            | Isa::LoongArch32
            | Isa::Arc
            | Isa::ArcCompact
            | Isa::ArcCompact2
            | Isa::Xtensa
            | Isa::MicroBlaze
            | Isa::Nios2
            | Isa::OpenRisc
            | Isa::Lanai
            | Isa::Csky
            | Isa::V850
            | Isa::Rh850
            | Isa::Rx
            | Isa::TiC6000
            | Isa::TiC2000
            | Isa::TiC28x
            | Isa::TiC5500
            | Isa::TiPru
            | Isa::Blackfin
            | Isa::Sharc
            | Isa::Hexagon
            | Isa::Tricore
            | Isa::Tile64
            | Isa::TilePro
            | Isa::TileGx => 32,

            Isa::X86_64
            | Isa::AArch64
            | Isa::RiscV64
            | Isa::Mips64
            | Isa::Ppc64
            | Isa::S390x
            | Isa::Sparc64
            | Isa::Ia64
            | Isa::Alpha
            | Isa::LoongArch64
            | Isa::Kvx
            | Isa::Elbrus
            | Isa::McstElbrus
            | Isa::Bpf
            | Isa::Ebc => 64,

            Isa::RiscV128 => 128,

            Isa::Avr
            | Isa::Avr32
            | Isa::Msp430
            | Isa::Pic
            | Isa::Stm8
            | Isa::Z80
            | Isa::Mcs6502
            | Isa::W65816
            | Isa::Hcs12
            | Isa::S12z
            | Isa::Hc11
            | Isa::C166
            | Isa::Rl78
            | Isa::K78k0r => 16,

            Isa::Pdp11 => 16,
            Isa::Vax => 32,
            Isa::I860 | Isa::I960 => 32,
            Isa::AmdGpu | Isa::Cuda => 64,
            Isa::VideoCore3 | Isa::VideoCore5 => 32,
            Isa::Frv => 32,
            Isa::Fr30 => 32,
            Isa::Fr80 => 32,
            Isa::PpcVle => 32,
            Isa::CellSpu => 128,

            // Virtual machine ISAs - bitwidth is notional
            Isa::Wasm => 32,   // wasm32 is more common
            Isa::Jvm => 32,    // JVM operand stack width
            Isa::Dalvik => 32, // Register-based 32-bit
            Isa::Clr => 32,    // CIL stack width

            Isa::Unknown(_) => 0,
        }
    }

    /// Returns whether this ISA uses variable-length instructions.
    pub fn is_variable_length(&self) -> bool {
        matches!(
            self,
            Isa::X86
                | Isa::X86_64
                | Isa::S390
                | Isa::S390x
                | Isa::M68k
                | Isa::ColdFire
                | Isa::Avr
                | Isa::Msp430
                | Isa::Z80
                | Isa::RiscV32
                | Isa::RiscV64
                | Isa::RiscV128
                | Isa::Tricore
                | Isa::Xtensa
                | Isa::Hcs12
                | Isa::S12z
                | Isa::Hc11
                | Isa::Rl78
                | Isa::K78k0r
                | Isa::Rh850
        )
    }
}

impl fmt::Display for Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Isa::Unknown(id) => write!(f, "unknown(0x{:04X})", id),
            other => write!(f, "{}", format!("{:?}", other).to_lowercase()),
        }
    }
}

/// Byte ordering (endianness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// Little-endian byte order.
    #[default]
    Little,
    /// Big-endian byte order.
    Big,
    /// Bi-endian (can operate in either mode).
    BiEndian,
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endianness::Little => write!(f, "little"),
            Endianness::Big => write!(f, "big"),
            Endianness::BiEndian => write!(f, "bi-endian"),
        }
    }
}

/// Binary file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum FileFormat {
    /// Executable and Linkable Format (Linux, BSD, etc.)
    Elf,
    /// Portable Executable (Windows)
    Pe,
    /// Mach-O (macOS, iOS)
    MachO,
    /// Universal/Fat binary (macOS)
    MachOFat,
    /// Standalone COFF (Windows object files)
    Coff,
    /// XCOFF (AIX)
    Xcoff,
    /// ECOFF (older MIPS/Alpha)
    Ecoff,
    /// Raw binary (no recognized format)
    Raw,

    // Unix/POSIX Legacy Formats
    /// a.out (BSD variant)
    Aout,
    /// Plan 9 a.out
    Plan9Aout,
    /// Minix a.out
    MinixAout,

    // DOS/Windows Legacy
    /// MZ/DOS executable
    Mz,
    /// NE (New Executable) - 16-bit Windows/OS2
    Ne,
    /// LE (Linear Executable) - OS/2, VxD
    Le,
    /// LX (Linear Executable Extended) - OS/2
    Lx,
    /// COM (DOS .COM file)
    Com,
    /// OMF (Object Module Format)
    Omf,

    // Apple Formats
    /// PEF (Preferred Executable Format) - Classic Mac OS
    Pef,

    // Text-Based Hex Formats
    /// Intel HEX
    IntelHex,
    /// Motorola S-record
    Srec,
    /// TI-TXT format
    TiTxt,

    // Embedded/NoMMU Formats
    /// bFLT (Binary Flat Format) - uClinux
    Bflt,
    /// DXE (Blackfin Dynamic Execution)
    Dxe,

    // Mainframe Formats
    /// GOFF (Generalized Object File Format) - z/Architecture
    Goff,
    /// MVS Load Module
    MvsLoad,
    /// HP-UX SOM (System Object Model)
    Som,

    // Legacy/Historical
    /// RSX-11/RT-11 object format
    Rsx11,
    /// VMS object/image format
    Vms,
    /// IEEE-695 object format
    Ieee695,

    // Virtual Machine Bytecode
    /// WebAssembly
    Wasm,
    /// Java class file
    JavaClass,
    /// Android DEX (Dalvik Executable)
    Dex,
    /// Android ODEX (Optimized DEX)
    Odex,
    /// Android VDEX
    Vdex,
    /// Android ART image
    Art,
    /// LLVM Bitcode
    LlvmBc,

    // Multi-Architecture Containers
    /// FatELF
    FatElf,
    /// ar archive
    Archive,
    /// Windows .lib import library
    WindowsLib,

    // Game Console Formats
    /// XBE (Original Xbox)
    Xbe,
    /// XEX (Xbox 360)
    Xex,
    /// SELF (PlayStation 3)
    SelfPs3,
    /// SELF (PlayStation 4)
    SelfPs4,
    /// SELF (PlayStation 5)
    SelfPs5,
    /// NSO (Nintendo Switch)
    Nso,
    /// NRO (Nintendo Switch)
    Nro,
    /// DOL (GameCube/Wii)
    Dol,
    /// REL (GameCube/Wii relocatable)
    Rel,

    // Kernel/Boot Formats
    /// Linux zImage/bzImage
    ZImage,
    /// U-Boot uImage
    UImage,
    /// Flattened Image Tree
    Fit,
    /// Device Tree Blob
    Dtb,
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileFormat::Elf => write!(f, "ELF"),
            FileFormat::Pe => write!(f, "PE/COFF"),
            FileFormat::MachO => write!(f, "Mach-O"),
            FileFormat::MachOFat => write!(f, "Mach-O Fat"),
            FileFormat::Coff => write!(f, "COFF"),
            FileFormat::Xcoff => write!(f, "XCOFF"),
            FileFormat::Ecoff => write!(f, "ECOFF"),
            FileFormat::Raw => write!(f, "Raw"),
            // Unix/POSIX Legacy
            FileFormat::Aout => write!(f, "a.out"),
            FileFormat::Plan9Aout => write!(f, "Plan 9 a.out"),
            FileFormat::MinixAout => write!(f, "Minix a.out"),
            // DOS/Windows Legacy
            FileFormat::Mz => write!(f, "MZ/DOS"),
            FileFormat::Ne => write!(f, "NE"),
            FileFormat::Le => write!(f, "LE"),
            FileFormat::Lx => write!(f, "LX"),
            FileFormat::Com => write!(f, "COM"),
            FileFormat::Omf => write!(f, "OMF"),
            // Apple
            FileFormat::Pef => write!(f, "PEF"),
            // Hex formats
            FileFormat::IntelHex => write!(f, "Intel HEX"),
            FileFormat::Srec => write!(f, "S-record"),
            FileFormat::TiTxt => write!(f, "TI-TXT"),
            // Embedded
            FileFormat::Bflt => write!(f, "bFLT"),
            FileFormat::Dxe => write!(f, "DXE"),
            // Mainframe
            FileFormat::Goff => write!(f, "GOFF"),
            FileFormat::MvsLoad => write!(f, "MVS Load"),
            FileFormat::Som => write!(f, "HP-UX SOM"),
            // Legacy
            FileFormat::Rsx11 => write!(f, "RSX-11"),
            FileFormat::Vms => write!(f, "VMS"),
            FileFormat::Ieee695 => write!(f, "IEEE-695"),
            // VM Bytecode
            FileFormat::Wasm => write!(f, "WebAssembly"),
            FileFormat::JavaClass => write!(f, "Java Class"),
            FileFormat::Dex => write!(f, "DEX"),
            FileFormat::Odex => write!(f, "ODEX"),
            FileFormat::Vdex => write!(f, "VDEX"),
            FileFormat::Art => write!(f, "ART"),
            FileFormat::LlvmBc => write!(f, "LLVM Bitcode"),
            // Multi-arch containers
            FileFormat::FatElf => write!(f, "FatELF"),
            FileFormat::Archive => write!(f, "ar Archive"),
            FileFormat::WindowsLib => write!(f, "Windows .lib"),
            // Game consoles
            FileFormat::Xbe => write!(f, "XBE"),
            FileFormat::Xex => write!(f, "XEX"),
            FileFormat::SelfPs3 => write!(f, "PS3 SELF"),
            FileFormat::SelfPs4 => write!(f, "PS4 SELF"),
            FileFormat::SelfPs5 => write!(f, "PS5 SELF"),
            FileFormat::Nso => write!(f, "NSO"),
            FileFormat::Nro => write!(f, "NRO"),
            FileFormat::Dol => write!(f, "DOL"),
            FileFormat::Rel => write!(f, "REL"),
            // Kernel/Boot
            FileFormat::ZImage => write!(f, "zImage"),
            FileFormat::UImage => write!(f, "uImage"),
            FileFormat::Fit => write!(f, "FIT"),
            FileFormat::Dtb => write!(f, "DTB"),
        }
    }
}

/// ISA extension or feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Extension {
    /// Extension name (e.g., "AVX2", "SVE", "C")
    pub name: String,
    /// Extension category
    pub category: ExtensionCategory,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

impl Eq for Extension {}

impl std::hash::Hash for Extension {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.category.hash(state);
    }
}

impl Extension {
    /// Create a new extension with high confidence.
    pub fn new(name: impl Into<String>, category: ExtensionCategory) -> Self {
        Self {
            name: name.into(),
            category,
            confidence: 1.0,
        }
    }

    /// Create a new extension with specified confidence.
    pub fn with_confidence(
        name: impl Into<String>,
        category: ExtensionCategory,
        confidence: f64,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Categories of ISA extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCategory {
    /// SIMD/Vector extensions (SSE, AVX, NEON, SVE, etc.)
    Simd,
    /// Cryptographic extensions (AES-NI, SHA, etc.)
    Crypto,
    /// Atomic/Synchronization extensions
    Atomic,
    /// Floating-point extensions
    FloatingPoint,
    /// Bit manipulation extensions
    BitManip,
    /// Virtualization extensions
    Virtualization,
    /// Security extensions (PAC, BTI, MTE, etc.)
    Security,
    /// Transactional memory
    Transactional,
    /// Machine learning / AI accelerators
    MachineLearning,
    /// Compressed instruction support
    Compressed,
    /// Privileged/System extensions
    System,
    /// Other/Misc extensions
    Other,
}

/// Architecture variant or profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Variant {
    /// Variant name (e.g., "ARMv8.2-A", "MIPS32R6", "ELFv2")
    pub name: String,
    /// Sub-variant or profile
    pub profile: Option<String>,
    /// ABI version
    pub abi: Option<String>,
}

impl Variant {
    /// Create a new variant.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            profile: None,
            abi: None,
        }
    }

    /// Create a variant with profile.
    pub fn with_profile(name: impl Into<String>, profile: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            profile: Some(profile.into()),
            abi: None,
        }
    }

    /// Create a variant with ABI.
    pub fn with_abi(name: impl Into<String>, abi: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            profile: None,
            abi: Some(abi.into()),
        }
    }
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref profile) = self.profile {
            write!(f, " ({})", profile)?;
        }
        if let Some(ref abi) = self.abi {
            write!(f, " [{}]", abi)?;
        }
        Ok(())
    }
}

/// Complete classification result for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Primary ISA detected
    pub isa: Isa,
    /// Register width in bits (16, 32, 64, 128)
    pub bitwidth: u8,
    /// Byte ordering
    pub endianness: Endianness,
    /// File format
    pub format: FileFormat,
    /// Architecture variant
    pub variant: Variant,
    /// Detected extensions
    pub extensions: Vec<Extension>,
    /// Overall confidence (0.0 - 1.0)
    pub confidence: f64,
    /// Classification source
    pub source: ClassificationSource,
    /// Additional metadata
    pub metadata: ClassificationMetadata,
}

impl ClassificationResult {
    /// Create a new high-confidence result from format parsing.
    pub fn from_format(isa: Isa, bitwidth: u8, endianness: Endianness, format: FileFormat) -> Self {
        Self {
            isa,
            bitwidth,
            endianness,
            format,
            variant: Variant::default(),
            extensions: Vec::new(),
            confidence: 1.0,
            source: ClassificationSource::FileFormat,
            metadata: ClassificationMetadata::default(),
        }
    }

    /// Create a result from heuristic analysis.
    pub fn from_heuristics(
        isa: Isa,
        bitwidth: u8,
        endianness: Endianness,
        confidence: f64,
    ) -> Self {
        Self {
            isa,
            bitwidth,
            endianness,
            format: FileFormat::Raw,
            variant: Variant::default(),
            extensions: Vec::new(),
            confidence,
            source: ClassificationSource::Heuristic,
            metadata: ClassificationMetadata::default(),
        }
    }

    /// Add an extension to the result.
    pub fn with_extension(mut self, ext: Extension) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Set the variant.
    pub fn with_variant(mut self, variant: Variant) -> Self {
        self.variant = variant;
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, metadata: ClassificationMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Check if this is a high-confidence result.
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Get extension names as a vector.
    pub fn extension_names(&self) -> Vec<&str> {
        self.extensions.iter().map(|e| e.name.as_str()).collect()
    }
}

impl fmt::Display for ClassificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}-bit, {}, {}) [{:.1}% confidence]",
            self.isa.name(),
            self.bitwidth,
            self.endianness,
            self.format,
            self.confidence * 100.0
        )?;

        if !self.variant.name.is_empty() {
            write!(f, "\n  Variant: {}", self.variant)?;
        }

        if !self.extensions.is_empty() {
            write!(f, "\n  Extensions: ")?;
            for (i, ext) in self.extensions.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", ext.name)?;
            }
        }

        Ok(())
    }
}

/// Source of classification determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    /// Determined from file format headers (ELF, PE, Mach-O)
    FileFormat,
    /// Determined from instruction pattern analysis
    Heuristic,
    /// Combined format + heuristic analysis
    Combined,
    /// User-specified override
    UserSpecified,
}

/// Additional metadata from classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassificationMetadata {
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Number of sections/segments
    pub section_count: Option<usize>,
    /// Number of symbols
    pub symbol_count: Option<usize>,
    /// Code section size in bytes
    pub code_size: Option<u64>,
    /// ELF e_flags or equivalent
    pub flags: Option<u32>,
    /// Raw machine type value
    pub raw_machine: Option<u32>,
    /// Additional notes
    pub notes: Vec<String>,
}

/// Options for classification behavior.
#[derive(Debug, Clone, Default)]
pub struct ClassifierOptions {
    /// Minimum confidence threshold for heuristic analysis
    pub min_confidence: f64,
    /// Enable deep heuristic scanning
    pub deep_scan: bool,
    /// Maximum bytes to scan for heuristics
    pub max_scan_bytes: usize,
    /// Enable extension detection
    pub detect_extensions: bool,
    /// Prefer speed over accuracy
    pub fast_mode: bool,
}

impl ClassifierOptions {
    /// Create options with default settings.
    pub fn new() -> Self {
        Self {
            min_confidence: 0.3,
            deep_scan: false,
            max_scan_bytes: 1024 * 1024, // 1MB
            detect_extensions: true,
            fast_mode: false,
        }
    }

    /// Create options for thorough analysis.
    pub fn thorough() -> Self {
        Self {
            min_confidence: 0.2,
            deep_scan: true,
            max_scan_bytes: 10 * 1024 * 1024, // 10MB
            detect_extensions: true,
            fast_mode: false,
        }
    }

    /// Create options for fast analysis.
    pub fn fast() -> Self {
        Self {
            min_confidence: 0.5,
            deep_scan: false,
            max_scan_bytes: 64 * 1024, // 64KB
            detect_extensions: false,
            fast_mode: true,
        }
    }
}

// =============================================================================
// Detection Payload Types - Structured output for formatters
// =============================================================================

/// Complete detection payload containing all analysis results.
///
/// This is the primary structured output from detection/parsing operations.
/// Main iterates over this payload and passes components to formatters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionPayload {
    /// Detected file format with context
    pub format: FormatDetection,
    /// Primary ISA classification result
    pub primary: IsaClassification,
    /// Alternative ISA candidates (populated for heuristic analysis)
    pub candidates: Vec<IsaCandidate>,
    /// Detected ISA extensions
    pub extensions: Vec<ExtensionDetection>,
    /// Extracted metadata items
    pub metadata: Vec<MetadataEntry>,
    /// Analysis notes and warnings
    pub notes: Vec<Note>,
}

impl DetectionPayload {
    /// Create a new empty payload with the given format and primary classification.
    pub fn new(format: FormatDetection, primary: IsaClassification) -> Self {
        Self {
            format,
            primary,
            candidates: Vec::new(),
            extensions: Vec::new(),
            metadata: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Add an ISA candidate.
    pub fn with_candidate(mut self, candidate: IsaCandidate) -> Self {
        self.candidates.push(candidate);
        self
    }

    /// Add candidates from a vector.
    pub fn with_candidates(mut self, candidates: Vec<IsaCandidate>) -> Self {
        self.candidates = candidates;
        self
    }

    /// Add an extension detection.
    pub fn with_extension(mut self, ext: ExtensionDetection) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Add extensions from a vector.
    pub fn with_extensions(mut self, extensions: Vec<ExtensionDetection>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Add a metadata entry.
    pub fn with_metadata(mut self, entry: MetadataEntry) -> Self {
        self.metadata.push(entry);
        self
    }

    /// Add a note.
    pub fn with_note(mut self, note: Note) -> Self {
        self.notes.push(note);
        self
    }

    /// Convert to legacy ClassificationResult for backwards compatibility.
    pub fn to_classification_result(&self) -> ClassificationResult {
        ClassificationResult {
            isa: self.primary.isa,
            bitwidth: self.primary.bitwidth,
            endianness: self.primary.endianness,
            format: self.format.format,
            variant: self.primary.variant.clone().unwrap_or_default(),
            extensions: self.extensions.iter().map(|e| e.to_extension()).collect(),
            confidence: self.primary.confidence,
            source: self.primary.source,
            metadata: self.to_classification_metadata(),
        }
    }

    /// Convert metadata entries to legacy ClassificationMetadata.
    fn to_classification_metadata(&self) -> ClassificationMetadata {
        let mut meta = ClassificationMetadata::default();
        for entry in &self.metadata {
            match &entry.key {
                MetadataKey::EntryPoint => {
                    if let MetadataValue::Address(addr) = entry.value {
                        meta.entry_point = Some(addr);
                    }
                }
                MetadataKey::SectionCount => {
                    if let MetadataValue::Integer(n) = entry.value {
                        meta.section_count = Some(n as usize);
                    }
                }
                MetadataKey::SymbolCount => {
                    if let MetadataValue::Integer(n) = entry.value {
                        meta.symbol_count = Some(n as usize);
                    }
                }
                MetadataKey::CodeSize => {
                    if let MetadataValue::Integer(n) = entry.value {
                        meta.code_size = Some(n);
                    }
                }
                MetadataKey::Flags => {
                    if let MetadataValue::Hex(h) = entry.value {
                        meta.flags = Some(h);
                    }
                }
                MetadataKey::RawMachine => {
                    if let MetadataValue::Hex(h) = entry.value {
                        meta.raw_machine = Some(h);
                    }
                }
                MetadataKey::Custom(_) => {}
            }
        }
        meta.notes = self.notes.iter().map(|n| n.message.clone()).collect();
        meta
    }
}

/// Format detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatDetection {
    /// Detected file format
    pub format: FileFormat,
    /// Detection confidence (1.0 for magic-based detection)
    pub confidence: f64,
    /// Offset where magic bytes were found
    pub magic_offset: Option<usize>,
    /// Format variant description (e.g., "NE" for MZ files)
    pub variant_name: Option<String>,
}

impl FormatDetection {
    /// Create a new format detection with high confidence.
    pub fn new(format: FileFormat) -> Self {
        Self {
            format,
            confidence: 1.0,
            magic_offset: Some(0),
            variant_name: None,
        }
    }

    /// Create with variant name.
    pub fn with_variant(format: FileFormat, variant: impl Into<String>) -> Self {
        Self {
            format,
            confidence: 1.0,
            magic_offset: Some(0),
            variant_name: Some(variant.into()),
        }
    }

    /// Create for raw/unknown format.
    pub fn raw() -> Self {
        Self {
            format: FileFormat::Raw,
            confidence: 0.0,
            magic_offset: None,
            variant_name: None,
        }
    }
}

/// Primary ISA classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsaClassification {
    /// Detected ISA
    pub isa: Isa,
    /// Register width in bits
    pub bitwidth: u8,
    /// Byte ordering
    pub endianness: Endianness,
    /// Classification confidence (0.0 - 1.0)
    pub confidence: f64,
    /// How the classification was determined
    pub source: ClassificationSource,
    /// Architecture variant/profile
    pub variant: Option<Variant>,
}

impl IsaClassification {
    /// Create from format header parsing (high confidence).
    pub fn from_format(isa: Isa, bitwidth: u8, endianness: Endianness) -> Self {
        Self {
            isa,
            bitwidth,
            endianness,
            confidence: 1.0,
            source: ClassificationSource::FileFormat,
            variant: None,
        }
    }

    /// Create from heuristic analysis.
    pub fn from_heuristics(
        isa: Isa,
        bitwidth: u8,
        endianness: Endianness,
        confidence: f64,
    ) -> Self {
        Self {
            isa,
            bitwidth,
            endianness,
            confidence,
            source: ClassificationSource::Heuristic,
            variant: None,
        }
    }

    /// Set variant.
    pub fn with_variant(mut self, variant: Variant) -> Self {
        self.variant = Some(variant);
        self
    }
}

/// ISA candidate from heuristic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsaCandidate {
    /// The ISA
    pub isa: Isa,
    /// Register width
    pub bitwidth: u8,
    /// Byte ordering
    pub endianness: Endianness,
    /// Raw score from pattern matching
    pub raw_score: i64,
    /// Normalized confidence (0.0 - 1.0)
    pub confidence: f64,
}

impl IsaCandidate {
    /// Create a new candidate.
    pub fn new(
        isa: Isa,
        bitwidth: u8,
        endianness: Endianness,
        raw_score: i64,
        confidence: f64,
    ) -> Self {
        Self {
            isa,
            bitwidth,
            endianness,
            raw_score,
            confidence,
        }
    }
}

/// Extension detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionDetection {
    /// Extension name (e.g., "AVX2", "SVE")
    pub name: String,
    /// Extension category
    pub category: ExtensionCategory,
    /// Detection confidence
    pub confidence: f64,
    /// How it was detected
    pub source: ExtensionSource,
}

impl ExtensionDetection {
    /// Create from code pattern detection.
    pub fn from_code(
        name: impl Into<String>,
        category: ExtensionCategory,
        confidence: f64,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            confidence,
            source: ExtensionSource::CodePattern,
        }
    }

    /// Create from format attributes (e.g., ELF notes).
    pub fn from_format(name: impl Into<String>, category: ExtensionCategory) -> Self {
        Self {
            name: name.into(),
            category,
            confidence: 1.0,
            source: ExtensionSource::FormatAttribute,
        }
    }

    /// Convert to legacy Extension type.
    pub fn to_extension(&self) -> Extension {
        Extension::with_confidence(&self.name, self.category, self.confidence)
    }
}

/// Source of extension detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSource {
    /// Detected from instruction patterns in code
    CodePattern,
    /// Extracted from format attributes (ELF notes, PE flags, etc.)
    FormatAttribute,
    /// Inferred from ISA variant
    VariantImplied,
}

/// Metadata entry with typed key and value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    /// Metadata key
    pub key: MetadataKey,
    /// Metadata value
    pub value: MetadataValue,
    /// Human-readable label
    pub label: String,
}

impl MetadataEntry {
    /// Create a new metadata entry.
    pub fn new(key: MetadataKey, value: MetadataValue, label: impl Into<String>) -> Self {
        Self {
            key,
            value,
            label: label.into(),
        }
    }

    /// Create entry point metadata.
    pub fn entry_point(addr: u64) -> Self {
        Self::new(
            MetadataKey::EntryPoint,
            MetadataValue::Address(addr),
            "Entry Point",
        )
    }

    /// Create section count metadata.
    pub fn section_count(count: usize) -> Self {
        Self::new(
            MetadataKey::SectionCount,
            MetadataValue::Integer(count as u64),
            "Sections",
        )
    }

    /// Create flags metadata.
    pub fn flags(flags: u32) -> Self {
        Self::new(MetadataKey::Flags, MetadataValue::Hex(flags), "Flags")
    }

    /// Create raw machine type metadata.
    pub fn raw_machine(machine: u32) -> Self {
        Self::new(
            MetadataKey::RawMachine,
            MetadataValue::Hex(machine),
            "Machine Type",
        )
    }
}

/// Metadata key types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataKey {
    /// Entry point address
    EntryPoint,
    /// Number of sections/segments
    SectionCount,
    /// Number of symbols
    SymbolCount,
    /// Code section size
    CodeSize,
    /// Architecture flags (e.g., ELF e_flags)
    Flags,
    /// Raw machine type value
    RawMachine,
    /// Custom key
    Custom(String),
}

/// Metadata value types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataValue {
    /// Memory address
    Address(u64),
    /// Integer value
    Integer(u64),
    /// String value
    String(String),
    /// Hex value (for flags, machine types)
    Hex(u32),
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataValue::Address(addr) => write!(f, "0x{:X}", addr),
            MetadataValue::Integer(n) => write!(f, "{}", n),
            MetadataValue::String(s) => write!(f, "{}", s),
            MetadataValue::Hex(h) => write!(f, "0x{:08X}", h),
        }
    }
}

/// Analysis note or warning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    /// Severity level
    pub level: NoteLevel,
    /// Note message
    pub message: String,
    /// Optional context (e.g., "ELF parsing")
    pub context: Option<String>,
}

impl Note {
    /// Create an info note.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: NoteLevel::Info,
            message: message.into(),
            context: None,
        }
    }

    /// Create a warning note.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: NoteLevel::Warning,
            message: message.into(),
            context: None,
        }
    }

    /// Create an error note.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: NoteLevel::Error,
            message: message.into(),
            context: None,
        }
    }

    /// Add context to the note.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// Note severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteLevel {
    /// Informational
    Info,
    /// Warning (non-fatal issue)
    Warning,
    /// Error (fatal issue handled gracefully)
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isa_display() {
        assert_eq!(Isa::X86_64.to_string(), "x86_64");
        assert_eq!(Isa::AArch64.to_string(), "aarch64");
        assert_eq!(Isa::Unknown(0x1234).to_string(), "unknown(0x1234)");
    }

    #[test]
    fn test_isa_bitwidth() {
        assert_eq!(Isa::X86.default_bitwidth(), 32);
        assert_eq!(Isa::X86_64.default_bitwidth(), 64);
        assert_eq!(Isa::Avr.default_bitwidth(), 16);
        assert_eq!(Isa::RiscV128.default_bitwidth(), 128);
    }

    #[test]
    fn test_extension_display() {
        let ext = Extension::new("AVX2", ExtensionCategory::Simd);
        assert_eq!(ext.to_string(), "AVX2");
    }

    #[test]
    fn test_classification_result() {
        let result =
            ClassificationResult::from_format(Isa::X86_64, 64, Endianness::Little, FileFormat::Elf);
        assert!(result.is_confident());
        assert!(result.to_string().contains("x86-64"));
    }

    #[test]
    fn test_variant() {
        let v = Variant::with_profile("ARMv8.2-A", "Cortex-A76");
        assert!(v.to_string().contains("ARMv8.2-A"));
        assert!(v.to_string().contains("Cortex-A76"));
    }
}
