//! AMD flash images: the Embedded Firmware Structure (EFS) and the PSP,
//! BIOS and combo directories it leads to, from coreboot 25.09
//! `util/amdfwtool/amdfwtool.h` (structures, cookies, entry types),
//! `amdfwtool.c` (`fletcher32`, `fill_dir_header`, `integrate_psp_ab`,
//! `RUN_BASE`) and `amdfwread.c` (`fw_header_offsets`, `relative_offset`,
//! `amdfw_psp_dir_walk`, `amdfw_bios_dir_walk`).
//!
//! The walk follows second-level pointers (`$PL2` and `$BL2`), the recovery
//! A/B entries (through an ISH directory or straight to `$PL2`) and combo
//! directories. Every directory is read once, at most [`MAX_DIRECTORIES`]
//! of them and at most [`MAX_DEPTH`] levels below the EFS.
//!
//! The directories name an entry type for each blob, not an instruction
//! set, so every entry is an opaque component.

use super::*;
use std::fmt::Write as _;

/// `EMBEDDED_FW_SIGNATURE`.
const EFS_SIGNATURE: u32 = 0x55AA_55AA;

/// `amdfwread.c` `fw_header_offsets`, in the order it searches them.
const EFS_OFFSETS: [usize; 5] = [
    0x00FA_0000,
    0x00E2_0000,
    0x00C2_0000,
    0x0082_0000,
    0x0002_0000,
];

/// `embedded_firmware` up to `reserved_4Ch`: blob pointers (0x04-0x0C),
/// directory pointers (0x10-0x2C), Promontory pointers (0x30, 0x34), SPI
/// settings (0x40-0x4B).
const EFS_SIZE: usize = 0x50;

/// EFS fields that point to PSP directories.
const EFS_PSP_FIELDS: [(usize, &str); 3] = [
    (0x10, "psp_directory"),
    (0x14, "new_psp_directory"),
    (0x2C, "psp_bak_directory"),
];

/// EFS fields that point to BIOS directories (`bios3_entry` on current
/// platforms, `bios1_entry` on older ones in `amdfwtool`).
const EFS_BIOS_FIELDS: [(usize, &str); 4] = [
    (0x18, "bios0_entry"),
    (0x1C, "bios1_entry"),
    (0x20, "bios2_entry"),
    (0x28, "bios3_entry"),
];

/// EFS fields that point to firmware blobs without a size.
const EFS_BLOB_FIELDS: [(usize, &str); 5] = [
    (0x04, "imc_entry"),
    (0x08, "gec_entry"),
    (0x0C, "xhci_entry"),
    (0x30, "promontory_fw_ptr"),
    (0x34, "lp_promontory_fw_ptr"),
];

/// `efs_gen`: bit 0 clear marks a second-generation EFS
/// (`EFS_SECOND_GEN`).
const EFS_GENERATION_OFFSET: usize = 0x24;
const EFS_FIRST_GENERATION_BIT: u32 = 1;

/// 0 and 0xFFFFFFFF mark an absent pointer (`amdfwread.c`).
const POINTER_UNSET: u32 = 0;
const POINTER_ERASED: u32 = 0xFFFF_FFFF;

/// Directory cookies (`amdfwtool.h`).
const PSP_COOKIE: u32 = 0x5053_5024;
const PSPL2_COOKIE: u32 = 0x324C_5024;
const PSP2_COOKIE: u32 = 0x5053_5032;
const BHD_COOKIE: u32 = 0x4448_4224;
const BHDL2_COOKIE: u32 = 0x324C_4224;
const BHD2_COOKIE: u32 = 0x4448_4232;

/// Directory header: cookie, Fletcher-32 checksum (0x04), entry count
/// (0x08), additional info (0x0C). Combo headers add a lookup mode (0x0C)
/// and 16 reserved bytes.
const HEADER_SIZE: usize = 0x10;
const COMBO_HEADER_SIZE: usize = 0x20;

/// The checksum covers everything after its own field.
const CHECKSUM_START: usize = 0x08;

/// `psp_directory_entry`, `bios_directory_entry`, `psp_combo_entry`.
const PSP_ENTRY_SIZE: usize = 0x10;
const BIOS_ENTRY_SIZE: usize = 0x18;
const COMBO_ENTRY_SIZE: usize = 0x10;

/// `additional_info`: bit 31 selects the version 1 layout, whose address
/// mode is in bits 25:24; version 0 keeps it in bits 30:29.
const INFO_VERSION_BIT: u32 = 1 << 31;
const INFO_MODE_SHIFT_V1: u32 = 24;
const INFO_MODE_SHIFT_V0: u32 = 29;
const MODE_MASK: u32 = 0x3;

/// Entry addresses: 62 address bits and a 2-bit mode on top.
const ADDRESS_MASK: u64 = (1 << 62) - 1;
const ADDRESS_MODE_SHIFT: u32 = 62;

/// `amd_addr_mode`.
const MODE_PHYSICAL: u8 = 0;
const MODE_IMAGE: u8 = 1;
const MODE_TABLE: u8 = 2;

/// `SPI_ROM_BASE` and `FILE_REL_MASK`: physical addresses map the 16 MiB
/// below 4 GiB.
const SPI_ROM_BASE: u64 = 0xFF00_0000;
const FILE_REL_MASK: u64 = 0x00FF_FFFF;
const SPI_ROM_WINDOW: u64 = 0x0100_0000;
const FOUR_GIB: u64 = 1 << 32;

/// Entry types that link to other directories or carry values.
const PSP_FUSE_CHAIN: u8 = 0x0B;
const PSP_L2_POINTER: u8 = 0x40;
const PSP_RECOVERY_A: u8 = 0x48;
const PSP_BIOS_TABLE: u8 = 0x49;
const PSP_RECOVERY_B: u8 = 0x4A;
const BIOS_APOB: u8 = 0x61;
const BIOS_PSP_SHARED_MEMORY: u8 = 0x6B;
const BIOS_L2_POINTER: u8 = 0x70;

/// `ish_directory_table`: checksum (0x00), boot priority (0x04), update
/// retry count (0x08), glitch retry count (0x0C), PSP L2 location (0x10),
/// PSP ID (0x14), slot maximum size (0x18), reserved (0x1C).
const ISH_SIZE: usize = 0x20;
const ISH_CHECKSUM_START: usize = 0x04;

/// `BIOS` entry flags byte: bit 3 marks a compressed (zlib) blob.
const BIOS_FLAG_COMPRESSED: u8 = 1 << 3;
const BIOS_INSTANCE_SHIFT: u8 = 4;

/// `PSP` entry `rsvd` field: the instance in bits 6:3.
const PSP_INSTANCE_SHIFT: u16 = 3;
const PSP_INSTANCE_MASK: u16 = 0xF;

/// `fletcher32` folds after at most 359 16-bit words.
const FLETCHER_BLOCK_WORDS: usize = 359;

/// Most directories one image is walked through, and how far below the
/// EFS (or the standalone table) the walk goes. Own bounds: a current
/// image has an EFS, two combo directories, and four levels at most
/// (combo, L1, L2, BIOS L2).
const MAX_DIRECTORIES: usize = 64;
const MAX_DEPTH: usize = 6;

/// First note of every PSP container.
const PSP_NOTE: &str = "PSP and BIOS directories name entry types, not instruction sets; every entry is opaque and excluded from ISA analysis";

/// PSP entry types named by `amdfwtool.h` `amd_fw_type`.
#[rustfmt::skip]
const PSP_ENTRY_TYPES: &[(u8, &str)] = &[
    (0x00, "AMD_FW_PSP_PUBKEY"),        (0x01, "AMD_FW_PSP_BOOTLOADER"),
    (0x02, "AMD_FW_PSP_SECURED_OS"),    (0x03, "AMD_FW_PSP_RECOVERY"),
    (0x04, "AMD_FW_PSP_NVRAM"),         (0x05, "AMD_FW_PSP_RTM_PUBKEY"),
    (0x08, "AMD_FW_PSP_SMU_FIRMWARE"),  (0x09, "AMD_FW_PSP_SECURED_DEBUG"),
    (0x0A, "AMD_FW_ABL_PUBKEY"),        (0x0B, "AMD_PSP_FUSE_CHAIN"),
    (0x0C, "AMD_FW_PSP_TRUSTLETS"),     (0x0D, "AMD_FW_PSP_TRUSTLETKEY"),
    (0x12, "AMD_FW_PSP_SMU_FIRMWARE2"), (0x13, "AMD_DEBUG_UNLOCK"),
    (0x15, "AMD_FW_PSP_TEEIPKEY"),      (0x1B, "AMD_BOOT_DRIVER"),
    (0x1C, "AMD_SOC_DRIVER"),           (0x1D, "AMD_DEBUG_DRIVER"),
    (0x1F, "AMD_INTERFACE_DRIVER"),     (0x20, "AMD_HW_IPCFG"),
    (0x21, "AMD_WRAPPED_IKEK"),         (0x22, "AMD_TOKEN_UNLOCK"),
    (0x24, "AMD_SEC_GASKET"),           (0x25, "AMD_MP2_FW"),
    (0x28, "AMD_DRIVER_ENTRIES"),       (0x29, "AMD_FW_KVM_IMAGE"),
    (0x2A, "AMD_FW_MP5"),               (0x2D, "AMD_S0I3_DRIVER"),
    (0x30, "AMD_ABL0"),                 (0x31, "AMD_ABL1"),
    (0x32, "AMD_ABL2"),                 (0x33, "AMD_ABL3"),
    (0x34, "AMD_ABL4"),                 (0x35, "AMD_ABL5"),
    (0x36, "AMD_ABL6"),                 (0x37, "AMD_ABL7"),
    (0x38, "AMD_SEV_DATA"),             (0x39, "AMD_SEV_CODE"),
    (0x3A, "AMD_FW_PSP_WHITELIST"),     (0x3C, "AMD_VBIOS_BTLOADER"),
    (0x40, "AMD_FW_L2_PTR"),            (0x42, "AMD_FW_DXIO"),
    (0x44, "AMD_FW_USB_PHY"),           (0x45, "AMD_FW_TOS_SEC_POLICY"),
    (0x47, "AMD_FW_DRTM_TA"),           (0x48, "AMD_FW_RECOVERYAB_A"),
    (0x49, "AMD_FW_BIOS_TABLE"),        (0x4A, "AMD_FW_RECOVERYAB_B"),
    (0x50, "AMD_FW_KEYDB_BL"),          (0x51, "AMD_FW_KEYDB_TOS"),
    (0x52, "AMD_FW_PSP_VERSTAGE"),      (0x53, "AMD_FW_VERSTAGE_SIG"),
    (0x54, "AMD_RPMC_NVRAM"),           (0x55, "AMD_FW_SPL"),
    (0x58, "AMD_FW_DMCU_ERAM"),         (0x59, "AMD_FW_DMCU_ISR"),
    (0x5A, "AMD_FW_MSMU"),              (0x5C, "AMD_FW_SPIROM_CFG"),
    (0x5D, "AMD_FW_MPIO"),              (0x5F, "AMD_FW_TPMLITE or AMD_FW_PSP_SMUSCS"),
    (0x71, "AMD_FW_DMCUB"),             (0x73, "AMD_FW_PSP_BOOTLOADER_AB"),
    (0x76, "AMD_RIB"),                  (0x85, "AMD_FW_AMF_SRAM"),
    (0x86, "AMD_FW_AMF_DRAM"),          (0x87, "AMD_FW_MFD_MPM"),
    (0x88, "AMD_FW_AMF_WLAN"),          (0x89, "AMD_FW_AMF_MFD"),
    (0x8C, "AMD_FW_MPDMA_TF"),          (0x8D, "AMD_TA_IKEK"),
    (0x90, "AMD_FW_MPCCX"),             (0x91, "AMD_FW_GMI3_PHY"),
    (0x92, "AMD_FW_MPDMA_PM"),          (0x94, "AMD_FW_LSDMA"),
    (0x95, "AMD_FW_C20_MP"),            (0x98, "AMD_FW_FCFG_TABLE"),
    (0x9A, "AMD_FW_MINIMSMU"),          (0x9B, "AMD_FW_GFXIMU_0"),
    (0x9C, "AMD_FW_GFXIMU_1"),          (0x9D, "AMD_FW_GFXIMU_2 or AMD_FW_SRAM_FW_EXT"),
    (0xA0, "AMD_FW_S3IMG"),             (0xA2, "AMD_FW_UMSMU"),
    (0xA4, "AMD_FW_USBDP"),             (0xA5, "AMD_FW_USBSS"),
    (0xA6, "AMD_FW_USB4"),
];

/// BIOS entry types named by `amdfwtool.h` `amd_bios_type`.
#[rustfmt::skip]
const BIOS_ENTRY_TYPES: &[(u8, &str)] = &[
    (0x05, "AMD_BIOS_RTM_PUBKEY"),  (0x07, "AMD_BIOS_SIG"),
    (0x60, "AMD_BIOS_APCB"),        (0x61, "AMD_BIOS_APOB"),
    (0x62, "AMD_BIOS_BIN"),         (0x63, "AMD_BIOS_APOB_NV"),
    (0x64, "AMD_BIOS_PMUI"),        (0x65, "AMD_BIOS_PMUD"),
    (0x66, "AMD_BIOS_UCODE"),       (0x68, "AMD_BIOS_APCB_BK"),
    (0x69, "AMD_BIOS_EARLY_VGA"),   (0x6A, "AMD_BIOS_MP2_CFG"),
    (0x6B, "AMD_BIOS_PSP_SHARED_MEM"), (0x6D, "AMD_BIOS_NV_ST"),
    (0x70, "AMD_BIOS_L2_PTR"),
];

/// A directory kind, by cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directory {
    Psp,
    PspLevel2,
    PspCombo,
    Bios,
    BiosLevel2,
    BiosCombo,
}

/// Every cookie with its directory kind and the name the notes use.
const DIRECTORIES: [(u32, Directory, &str); 6] = [
    (PSP_COOKIE, Directory::Psp, "$PSP"),
    (PSPL2_COOKIE, Directory::PspLevel2, "$PL2"),
    (PSP2_COOKIE, Directory::PspCombo, "2PSP"),
    (BHD_COOKIE, Directory::Bios, "$BHD"),
    (BHDL2_COOKIE, Directory::BiosLevel2, "$BL2"),
    (BHD2_COOKIE, Directory::BiosCombo, "2BHD"),
];

/// Directories an EFS PSP field, a combo PSP entry and a BIOS-table link
/// may lead to.
const PSP_TOP: [Directory; 2] = [Directory::Psp, Directory::PspCombo];
const BIOS_TOP: [Directory; 2] = [Directory::Bios, Directory::BiosCombo];
const PSP_LEVELS: [Directory; 2] = [Directory::Psp, Directory::PspLevel2];
const BIOS_LEVELS: [Directory; 2] = [Directory::Bios, Directory::BiosLevel2];

impl Directory {
    fn from_cookie(cookie: u32) -> Option<Self> {
        DIRECTORIES
            .iter()
            .find(|(value, _, _)| *value == cookie)
            .map(|(_, kind, _)| *kind)
    }

    fn cookie(self) -> &'static str {
        DIRECTORIES
            .iter()
            .find(|(_, kind, _)| *kind == self)
            .map_or("?", |(_, _, name)| name)
    }

    /// The level name used in component labels.
    fn level(self) -> &'static str {
        match self {
            Self::Psp => "PSP L1",
            Self::PspLevel2 => "PSP L2",
            Self::PspCombo => "PSP combo",
            Self::Bios => "BIOS L1",
            Self::BiosLevel2 => "BIOS L2",
            Self::BiosCombo => "BIOS combo",
        }
    }

    fn header_size(self) -> usize {
        match self {
            Self::PspCombo | Self::BiosCombo => COMBO_HEADER_SIZE,
            _ => HEADER_SIZE,
        }
    }

    fn entry_size(self) -> usize {
        match self {
            Self::Psp | Self::PspLevel2 => PSP_ENTRY_SIZE,
            Self::Bios | Self::BiosLevel2 => BIOS_ENTRY_SIZE,
            Self::PspCombo | Self::BiosCombo => COMBO_ENTRY_SIZE,
        }
    }
}

/// The directory cookie at offset 0.
pub(super) fn is_directory(data: &[u8]) -> bool {
    le_u32(data, 0)
        .ok()
        .and_then(Directory::from_cookie)
        .is_some()
}

/// The first documented EFS offset whose structure and directories
/// validate completely.
pub(super) fn find_efs(data: &[u8]) -> Option<usize> {
    EFS_OFFSETS.into_iter().find(|&offset| {
        le_u32(data, offset).ok() == Some(EFS_SIGNATURE) && parse_efs(data, offset).is_ok()
    })
}

/// amdfwtool `fletcher32`: 16-bit little-endian words summed into two
/// 32-bit registers that start at 0xFFFF, folded (end-around carry) after
/// every 359 words and once more at the end; `c1 << 16 | c0`. An odd
/// trailing byte is ignored, as the C code's `length /= 2` does.
fn fletcher32(bytes: &[u8]) -> u32 {
    let fold = |sum: u32| (sum & 0xFFFF) + (sum >> 16);
    let mut c0: u32 = 0xFFFF;
    let mut c1: u32 = 0xFFFF;
    for block in bytes.chunks(FLETCHER_BLOCK_WORDS * 2) {
        for word in block.chunks_exact(2) {
            c0 = c0.wrapping_add(u32::from(u16::from_le_bytes([word[0], word[1]])));
            c1 = c1.wrapping_add(c0);
        }
        c0 = fold(c0);
        c1 = fold(c1);
    }
    (fold(c1) << 16) | fold(c0)
}

/// Whether the bytes walked are the flash image or one table from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// The file is the flash image: image-relative offsets are file
    /// offsets.
    Image,
    /// The file is a directory table extracted from an image: only
    /// table-relative addresses resolve.
    Standalone,
}

/// An address resolved against the file.
#[derive(Debug)]
enum Resolved {
    Offset(usize),
    /// Not resolvable here, for the stated reason.
    Unresolved(String),
}

/// The walk over one image's directories.
#[derive(Debug)]
struct Walk<'a> {
    data: &'a [u8],
    placement: Placement,
    /// File offsets of the directories walked so far.
    visited: Vec<usize>,
    listing: Listing,
    /// Entries with no stored bytes (zero or erased size, DRAM-only).
    unstored: Vec<String>,
}

/// One directory entry, in the fields every kind shares.
#[derive(Debug)]
struct Entry {
    kind: u8,
    size: u32,
    /// The 62-bit address with the mode removed, or a combo pointer.
    address: u64,
    mode: u8,
    /// The whole 64-bit field, for entries that carry a value.
    raw: u64,
    instance: u8,
    subprogram: u8,
    compressed: bool,
}

impl<'a> Walk<'a> {
    fn new(data: &'a [u8], placement: Placement) -> Self {
        Self {
            data,
            placement,
            visited: Vec::new(),
            listing: Listing::default(),
            unstored: Vec::new(),
        }
    }

    /// Resolve `address` in `mode` against the table at `table`
    /// (`amdfwread.c` `relative_offset`).
    fn resolve(&self, table: usize, address: u64, mode: u8) -> Result<Resolved> {
        let image_relative = match mode {
            MODE_PHYSICAL => self.physical_offset(address)?,
            MODE_IMAGE => {
                if address > FILE_REL_MASK {
                    return Err(error(format!(
                        "Invalid image-relative address 0x{address:X}: above 16 MiB"
                    )));
                }
                address
            }
            MODE_TABLE => {
                let offset = u64::try_from(table)
                    .ok()
                    .and_then(|table| table.checked_add(address))
                    .and_then(|offset| usize::try_from(offset).ok());
                return Ok(match offset {
                    Some(offset) => Resolved::Offset(offset),
                    None => Resolved::Unresolved(format!(
                        "table-relative address 0x{address:X} is beyond the address space"
                    )),
                });
            }
            _ => {
                return Ok(Resolved::Unresolved(
                    "address mode 3 (relative to a slot) is not supported".to_string(),
                ))
            }
        };
        if self.placement == Placement::Standalone {
            return Ok(Resolved::Unresolved(format!(
                "image offset 0x{image_relative:X}; the flash image is not part of this file"
            )));
        }
        Ok(Resolved::Offset(
            usize::try_from(image_relative).expect("offsets below 16 MiB fit usize"),
        ))
    }

    /// A pointer without a mode (EFS, ISH and combo pointers): physical when
    /// it lies in the SPI ROM window, image-relative otherwise.
    fn resolve_pointer(&self, pointer: u64) -> Result<Resolved> {
        let mode = if pointer >= SPI_ROM_BASE {
            MODE_PHYSICAL
        } else {
            MODE_IMAGE
        };
        self.resolve(0, pointer, mode)
    }

    /// The image offset of a physical address in the 16 MiB window below
    /// 4 GiB. A file smaller than the window is mapped at its top, as
    /// `amdfwtool` `RUN_BASE` maps a `rom_size` image; otherwise the low 24
    /// bits are the offset, as `amdfwread` computes it.
    fn physical_offset(&self, address: u64) -> Result<u64> {
        if !(SPI_ROM_BASE..FOUR_GIB).contains(&address) {
            return Err(error(format!(
                "Invalid physical address 0x{address:X}: outside 0xFF000000-0xFFFFFFFF"
            )));
        }
        let size = self.data.len() as u64;
        let top = FOUR_GIB.saturating_sub(size);
        if size < SPI_ROM_WINDOW && address >= top {
            Ok(address - top)
        } else {
            Ok(address & FILE_REL_MASK)
        }
    }

    /// Walk the directory at `offset`, which must be one of `allowed`:
    /// header, entry table and checksum first, then every entry.
    fn walk(
        &mut self,
        c: &mut Container<'a>,
        offset: usize,
        allowed: &[Directory],
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(error(format!(
                "Invalid directory nesting at 0x{offset:X}: more than {MAX_DEPTH} levels"
            )));
        }
        if self.visited.contains(&offset) {
            self.listing.note(
                c,
                format!("Directory at 0x{offset:X} is referenced again; listed once"),
            );
            return Ok(());
        }
        if self.visited.len() >= MAX_DIRECTORIES {
            self.listing.note(
                c,
                format!("Directory at 0x{offset:X} not walked (limit {MAX_DIRECTORIES})"),
            );
            return Ok(());
        }
        let cookie = le_u32(self.data, offset).map_err(|_| {
            error(format!(
                "Truncated directory at 0x{offset:X}: the cookie is outside the file"
            ))
        })?;
        let Some(kind) = Directory::from_cookie(cookie).filter(|kind| allowed.contains(kind))
        else {
            let expected: Vec<&str> = allowed.iter().map(|kind| kind.cookie()).collect();
            return Err(error(format!(
                "Invalid directory at 0x{offset:X}: cookie 0x{cookie:08X} is not {}",
                expected.join(" or ")
            )));
        };
        self.visited.push(offset);
        let table = self.table(offset, kind)?;
        let header = &table[..kind.header_size()];
        let count = to_usize(le_u32(header, 0x08)?);
        let mode = directory_mode(kind, le_u32(header, 0x0C)?);
        let mode_text = mode.map_or(String::new(), |mode| format!("; address mode {mode}"));
        self.listing.note(
            c,
            format!(
                "{} directory at 0x{offset:X}: {}; Fletcher-32 checksum verified{mode_text}",
                kind.cookie(),
                plural(count, "entry", "entries")
            ),
        );
        let entries = table.get(kind.header_size()..).unwrap_or_default();
        for entry in entries.chunks_exact(kind.entry_size()) {
            let entry = read_entry(kind, entry, mode)?;
            self.entry(c, kind, offset, &entry, depth)?;
        }
        Ok(())
    }

    /// The header and entry table of the directory at `offset`, with its
    /// entry count checked against the file and its checksum verified.
    fn table(&self, offset: usize, kind: Directory) -> Result<&'a [u8]> {
        let what = format!("{} directory header", kind.cookie());
        let header = field(self.data, offset, kind.header_size(), &what)?;
        let count = to_usize(le_u32(header, 0x08)?);
        let room = self.data.len().saturating_sub(offset + kind.header_size()) / kind.entry_size();
        if count > room {
            return Err(error(format!(
                "Truncated {} directory at 0x{offset:X}: {count} entries of {} B, room for {room}",
                kind.cookie(),
                kind.entry_size()
            )));
        }
        let size = kind.header_size() + count * kind.entry_size();
        let table = field(self.data, offset, size, "directory entry table")?;
        let stored = le_u32(header, 0x04)?;
        let computed = fletcher32(&table[CHECKSUM_START..]);
        if stored != computed {
            return Err(error(format!(
                "Invalid {} directory checksum at 0x{:X}: stored 0x{stored:08X}, computed 0x{computed:08X}",
                kind.cookie(),
                offset + 0x04
            )));
        }
        Ok(table)
    }

    /// Follow a link entry or list a blob.
    fn entry(
        &mut self,
        c: &mut Container<'a>,
        directory: Directory,
        table: usize,
        entry: &Entry,
        depth: usize,
    ) -> Result<()> {
        match (directory, entry.kind) {
            (Directory::PspCombo, _) => self.link_pointer(c, entry.address, &PSP_LEVELS, depth),
            (Directory::BiosCombo, _) => self.link_pointer(c, entry.address, &BIOS_LEVELS, depth),
            (Directory::Psp | Directory::PspLevel2, PSP_FUSE_CHAIN) => {
                self.listing.note(
                    c,
                    format!("{} soft fuse value 0x{:X}", directory.level(), entry.raw),
                );
                Ok(())
            }
            (Directory::Psp | Directory::PspLevel2, PSP_L2_POINTER) => {
                self.link(c, table, entry, &[Directory::PspLevel2], depth)
            }
            (Directory::Psp | Directory::PspLevel2, PSP_RECOVERY_A | PSP_RECOVERY_B) => {
                self.recovery(c, table, entry, depth)
            }
            (Directory::Psp | Directory::PspLevel2, PSP_BIOS_TABLE)
            | (Directory::Bios | Directory::BiosLevel2, BIOS_L2_POINTER) => {
                self.link(c, table, entry, &[Directory::BiosLevel2], depth)
            }
            (Directory::Bios | Directory::BiosLevel2, BIOS_APOB | BIOS_PSP_SHARED_MEMORY) => {
                self.unstored.push(format!(
                    "{} (DRAM destination only)",
                    label(directory, entry)
                ));
                Ok(())
            }
            _ => {
                self.blob(c, directory, table, entry);
                Ok(())
            }
        }
    }

    /// Follow a directory entry's address to the next directory.
    fn link(
        &mut self,
        c: &mut Container<'a>,
        table: usize,
        entry: &Entry,
        allowed: &[Directory],
        depth: usize,
    ) -> Result<()> {
        match self.resolve(table, entry.address, entry.mode)? {
            Resolved::Offset(offset) => self.walk(c, offset, allowed, depth + 1),
            Resolved::Unresolved(reason) => {
                self.listing.note(
                    c,
                    format!(
                        "Link to a {} directory not followed: {reason}",
                        allowed[0].cookie()
                    ),
                );
                Ok(())
            }
        }
    }

    /// Follow a mode-less pointer (combo entry, ISH) to the next directory.
    fn link_pointer(
        &mut self,
        c: &mut Container<'a>,
        pointer: u64,
        allowed: &[Directory],
        depth: usize,
    ) -> Result<()> {
        match self.resolve_pointer(pointer)? {
            Resolved::Offset(offset) => self.walk(c, offset, allowed, depth + 1),
            Resolved::Unresolved(reason) => {
                self.listing
                    .note(c, format!("Pointer 0x{pointer:X} not followed: {reason}"));
                Ok(())
            }
        }
    }

    /// A recovery A/B entry: a `$PL2` directory, or an ISH directory that
    /// names one (`amdfwtool.c` `integrate_psp_ab`).
    fn recovery(
        &mut self,
        c: &mut Container<'a>,
        table: usize,
        entry: &Entry,
        depth: usize,
    ) -> Result<()> {
        let offset = match self.resolve(table, entry.address, entry.mode)? {
            Resolved::Offset(offset) => offset,
            Resolved::Unresolved(reason) => {
                self.listing
                    .note(c, format!("Recovery A/B entry not followed: {reason}"));
                return Ok(());
            }
        };
        if le_u32(self.data, offset).ok() == Some(PSPL2_COOKIE) {
            return self.walk(c, offset, &[Directory::PspLevel2], depth + 1);
        }
        let ish = field(self.data, offset, ISH_SIZE, "ISH directory")?;
        let stored = le_u32(ish, 0x00)?;
        let computed = fletcher32(&ish[ISH_CHECKSUM_START..]);
        let checksum = if stored == computed {
            "Fletcher-32 checksum verified".to_string()
        } else {
            format!("Fletcher-32 checksum 0x{stored:08X} does not match the computed 0x{computed:08X}; not verified")
        };
        let level2 = le_u32(ish, 0x10)?;
        self.listing.note(
            c,
            format!(
                "ISH directory at 0x{offset:X}: PSP ID 0x{:08X}, PSP L2 pointer 0x{level2:08X}; {checksum}",
                le_u32(ish, 0x14)?
            ),
        );
        self.link_pointer(c, u64::from(level2), &[Directory::PspLevel2], depth + 1)
    }

    /// List a blob entry as an opaque component, or say why it is not
    /// listed.
    fn blob(&mut self, c: &mut Container<'a>, directory: Directory, table: usize, entry: &Entry) {
        let label = label(directory, entry);
        if entry.size == 0 || entry.size == POINTER_ERASED {
            self.unstored.push(label);
            return;
        }
        let size = to_usize(entry.size);
        let reason = match self.resolve(table, entry.address, entry.mode) {
            Ok(Resolved::Offset(offset)) => {
                let bytes = offset
                    .checked_add(size)
                    .and_then(|end| self.data.get(offset..end));
                match bytes {
                    Some(bytes) => {
                        self.listing.push(c, Child::opaque(label, offset, bytes));
                        return;
                    }
                    None => format!(
                        "0x{offset:X} + {size} B lies outside the {} B file",
                        self.data.len()
                    ),
                }
            }
            Ok(Resolved::Unresolved(reason)) => reason,
            Err(e) => bare_message(e),
        };
        self.listing
            .note(c, format!("{label} not listed: {reason}"));
    }

    /// Notes for entries without stored bytes and for the listing limits.
    fn finish(&self, c: &mut Container<'_>) {
        if !self.unstored.is_empty() {
            c.notes.push(format!(
                "Entries without stored bytes (zero or erased size, or a DRAM destination): {}",
                listed(&self.unstored)
            ));
        }
        c.push_metadata(
            format!("{KEY_PREFIX}_psp_directory_count"),
            "Directories walked",
            self.visited.len() as u64,
        );
        self.listing.finish(c);
    }
}

/// The directory's address mode (`amdfwread.c`): `Some` for PSP and BIOS
/// directories, from the version 0 or version 1 `additional_info` layout.
fn directory_mode(kind: Directory, info: u32) -> Option<u8> {
    if matches!(kind, Directory::PspCombo | Directory::BiosCombo) {
        return None;
    }
    let shift = if info & INFO_VERSION_BIT != 0 {
        INFO_MODE_SHIFT_V1
    } else {
        INFO_MODE_SHIFT_V0
    };
    u8::try_from((info >> shift) & MODE_MASK).ok()
}

/// Decode one entry. The directory mode applies to every entry when it is
/// below 2; otherwise each entry carries its own (`amdfwread.c`).
fn read_entry(kind: Directory, entry: &[u8], directory_mode: Option<u8>) -> Result<Entry> {
    let (address_field, size, instance, subprogram, compressed) = match kind {
        Directory::PspCombo | Directory::BiosCombo => {
            let pointer = le_u64(entry, 0x08)?;
            return Ok(Entry {
                kind: 0,
                size: 0,
                address: pointer,
                mode: MODE_IMAGE,
                raw: pointer,
                instance: 0,
                subprogram: 0,
                compressed: false,
            });
        }
        Directory::Psp | Directory::PspLevel2 => {
            let reserved = le_u16(entry, 0x02)?;
            let instance = (reserved >> PSP_INSTANCE_SHIFT) & PSP_INSTANCE_MASK;
            (
                le_u64(entry, 0x08)?,
                le_u32(entry, 0x04)?,
                u8::try_from(instance).expect("instance has 4 bits"),
                entry[0x01],
                false,
            )
        }
        Directory::Bios | Directory::BiosLevel2 => {
            let flags = entry[0x02];
            (
                le_u64(entry, 0x08)?,
                le_u32(entry, 0x04)?,
                flags >> BIOS_INSTANCE_SHIFT,
                entry[0x03],
                flags & BIOS_FLAG_COMPRESSED != 0,
            )
        }
    };
    let entry_mode = u8::try_from(address_field >> ADDRESS_MODE_SHIFT).expect("mode has 2 bits");
    let mode = match directory_mode {
        Some(mode) if mode < MODE_TABLE => mode,
        _ => entry_mode,
    };
    Ok(Entry {
        kind: entry[0x00],
        size,
        address: address_field & ADDRESS_MASK,
        mode,
        raw: address_field,
        instance,
        subprogram,
        compressed,
    })
}

/// A component label: level, type and its `amdfwtool` name, instance,
/// subprogram and the compressed flag.
fn label(directory: Directory, entry: &Entry) -> String {
    let names = match directory {
        Directory::Bios | Directory::BiosLevel2 => BIOS_ENTRY_TYPES,
        _ => PSP_ENTRY_TYPES,
    };
    let name = names
        .iter()
        .find(|(kind, _)| *kind == entry.kind)
        .map_or("type not named by amdfwtool", |(_, name)| name);
    let mut label = format!("{} entry 0x{:02X} ({name})", directory.level(), entry.kind);
    if entry.instance != 0 {
        let _ = write!(label, " instance {}", entry.instance);
    }
    if entry.subprogram != 0 {
        let _ = write!(label, " subprogram {}", entry.subprogram);
    }
    if entry.compressed {
        label.push_str(", compressed");
    }
    label
}

/// The message of a family error without the family prefix.
fn bare_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::PcFirmwareParseError { message } => message,
        other => other.to_string(),
    }
}

/// Whether an EFS or ISH pointer field is set.
fn is_set(pointer: u32) -> bool {
    pointer != POINTER_UNSET && pointer != POINTER_ERASED
}

/// Parse an image whose EFS is at `offset`: the structure, then every
/// directory its pointer fields lead to.
pub(super) fn parse_efs(data: &[u8], offset: usize) -> Result<Container<'_>> {
    let efs = field(data, offset, EFS_SIZE, "Embedded Firmware Structure")?;
    let signature = le_u32(efs, 0)?;
    if signature != EFS_SIGNATURE {
        return Err(error(format!(
            "Invalid Embedded Firmware Structure signature 0x{signature:08X} at 0x{offset:X}"
        )));
    }
    let layout = Layout::AmdEfs { offset };
    let mut c = Container::new(FileFormat::AmdPsp, layout.label(), KEY_PREFIX);
    c.notes.push(PSP_NOTE.to_string());
    let generation = if le_u32(efs, EFS_GENERATION_OFFSET)? & EFS_FIRST_GENERATION_BIT == 0 {
        "second-generation"
    } else {
        "first-generation"
    };
    c.notes.push(format!(
        "Embedded Firmware Structure at 0x{offset:X} (signature 0x55AA55AA), {generation} layout"
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_efs_offset"),
        "EFS offset",
        format!("0x{offset:X}"),
    );
    let mut walk = Walk::new(data, Placement::Image);
    for (at, name) in EFS_PSP_FIELDS {
        efs_field(&mut walk, &mut c, name, le_u32(efs, at)?, &PSP_TOP)?;
    }
    for (at, name) in EFS_BIOS_FIELDS {
        efs_field(&mut walk, &mut c, name, le_u32(efs, at)?, &BIOS_TOP)?;
    }
    let mut blobs = Vec::new();
    for (at, name) in EFS_BLOB_FIELDS {
        let pointer = le_u32(efs, at)?;
        if is_set(pointer) {
            blobs.push(format!("{name} 0x{pointer:08X}"));
        }
    }
    if !blobs.is_empty() {
        c.notes.push(format!(
            "EFS firmware pointers without a size, not listed: {}",
            blobs.join(", ")
        ));
    }
    if walk.visited.is_empty() {
        return Err(error(format!(
            "Missing directory: no pointer of the Embedded Firmware Structure at 0x{offset:X} leads to a PSP or BIOS directory"
        )));
    }
    walk.finish(&mut c);
    c.consumed = data.len();
    Ok(c)
}

/// Follow one EFS pointer field when it leads to a directory of the
/// `allowed` kinds. Fields that are unset or lead elsewhere are noted:
/// platforms use different fields, and older ones put other data there.
fn efs_field<'a>(
    walk: &mut Walk<'a>,
    c: &mut Container<'a>,
    name: &str,
    pointer: u32,
    allowed: &[Directory],
) -> Result<()> {
    if !is_set(pointer) {
        return Ok(());
    }
    let offset = match walk.resolve_pointer(u64::from(pointer)) {
        Ok(Resolved::Offset(offset)) => offset,
        Ok(Resolved::Unresolved(reason)) => {
            c.notes
                .push(format!("EFS {name} 0x{pointer:08X}: {reason}"));
            return Ok(());
        }
        Err(e) => {
            c.notes
                .push(format!("EFS {name} 0x{pointer:08X}: {}", bare_message(e)));
            return Ok(());
        }
    };
    let kind = le_u32(walk.data, offset)
        .ok()
        .and_then(Directory::from_cookie);
    if kind.is_some_and(|kind| allowed.contains(&kind)) {
        walk.walk(c, offset, allowed, 1)
    } else {
        c.notes.push(format!(
            "EFS {name} 0x{pointer:08X} does not lead to a {} directory",
            allowed[0].cookie()
        ));
        Ok(())
    }
}

/// Parse a standalone directory table at offset 0. Only table-relative
/// addresses resolve; everything else is noted.
pub(super) fn parse_directory(data: &[u8]) -> Result<Container<'_>> {
    let cookie = le_u32(data, 0)?;
    let kind = Directory::from_cookie(cookie)
        .ok_or_else(|| error(format!("Invalid directory cookie 0x{cookie:08X} at 0x0")))?;
    let mut c = Container::new(FileFormat::AmdPsp, Layout::AmdDirectory.label(), KEY_PREFIX);
    c.notes.push(PSP_NOTE.to_string());
    c.notes.push(format!(
        "Standalone {} directory: image-relative and physical addresses need the flash image, so only table-relative entries are listed",
        kind.cookie()
    ));
    let mut walk = Walk::new(data, Placement::Standalone);
    walk.walk(&mut c, 0, &[kind], 1)?;
    walk.finish(&mut c);
    c.consumed = data.len();
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fletcher32_matches_amdfwtool_by_hand() {
        // No words: both registers stay 0xFFFF.
        assert_eq!(fletcher32(&[]), 0xFFFF_FFFF);
        // One word 1: c0 = 0x10000 -> 1, c1 = 0x1FFFF -> 0x10000 -> 1.
        assert_eq!(fletcher32(&[1, 0]), 0x0001_0001);
        // An odd trailing byte is ignored.
        assert_eq!(fletcher32(&[1, 0, 7]), 0x0001_0001);
    }

    #[test]
    fn cookies_read_as_their_ascii_names() {
        for (cookie, kind, name) in DIRECTORIES {
            assert_eq!(cookie.to_le_bytes(), name.as_bytes(), "{kind:?}");
        }
    }

    #[test]
    fn directory_modes_follow_both_info_layouts() {
        assert_eq!(directory_mode(Directory::Psp, 1 << 29), Some(1));
        assert_eq!(
            directory_mode(Directory::Psp, INFO_VERSION_BIT | 2 << 24),
            Some(2)
        );
        assert_eq!(directory_mode(Directory::PspCombo, 0), None);
    }

    #[test]
    fn physical_addresses_map_to_the_top_of_small_images() {
        let image = vec![0u8; 0x80_0000];
        let walk = Walk::new(&image, Placement::Image);
        assert_eq!(walk.physical_offset(0xFF82_0000).unwrap(), 0x2_0000);
        assert_eq!(walk.physical_offset(0xFF02_0000).unwrap(), 0x2_0000);
        assert!(walk.physical_offset(0xFE00_0000).is_err());
        let full = vec![0u8; 0x100_0000];
        let walk = Walk::new(&full, Placement::Image);
        assert_eq!(walk.physical_offset(0xFF02_0000).unwrap(), 0x2_0000);
    }
}
