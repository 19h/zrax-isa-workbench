//! The boot block: the `DOS` signature and DOS type, the boot block
//! checksum and the boot code ([FAQ] 4.1; [RKRM] `devices/bootblock.i`
//! and "Bootblock Booting").

use super::*;
use crate::formats::container::{Child, Target};
use crate::types::{Endianness, Isa};

/// `BBID_DOS`: "something that is bootable" starts with these three
/// characters ([RKRM] `devices/bootblock.i`); the fourth byte is the DOS
/// type ([FAQ] 4.1).
pub(super) const DOS_SIGNATURE: [u8; 3] = *b"DOS";

/// Offset of the DOS type byte, the last byte of `bb_id`.
pub(super) const DOS_TYPE_OFFSET: usize = 3;

/// `bb_chksum`, the second long.
const CHECKSUM_OFFSET: usize = 4;

/// `bb_dosblock`, "reserved for DOS patch"; [FAQ] 4.1 calls it the root
/// block and gives 880 for DD and HD disks.
const DOS_BLOCK_OFFSET: usize = 8;

/// `BB_ENTRY`: the boot code's entry point follows the three longs of the
/// boot block header ([RKRM] `devices/bootblock.i`; "Bootblock Booting"
/// step 2a).
pub(super) const BOOT_ENTRY: usize = 12;

/// `BOOTSECTS`: a floppy's boot block is two blocks, "1K bootstrap"
/// ([RKRM] `devices/bootblock.i`).
pub(super) const FLOPPY_BOOT_BLOCKS: usize = 2;

/// Kickstart runs the boot code on the Amiga's 680x0, a big-endian
/// processor with 32-bit registers ([HRM] chapter 1; [RKRM]: A1 holds the
/// I/O request and A6 `SysBase`).
const BOOT_CODE_TARGET: Target = Target::new(Isa::M68k, 32, Endianness::Big);

/// What a boot block holds.
#[derive(Debug, Clone, Copy)]
pub(super) struct BootBlock<'a> {
    /// File offset of the boot block.
    pub(super) offset: usize,
    /// The first four bytes (`bb_id`).
    pub(super) id: [u8; 4],
    /// `bb_chksum` as stored.
    pub(super) stored_checksum: u32,
    /// The checksum the boot blocks need.
    pub(super) computed_checksum: u32,
    /// `bb_dosblock`.
    pub(super) dos_block: u32,
    /// The boot code area, from `BB_ENTRY` to the end of the boot blocks.
    pub(super) code: &'a [u8],
}

/// The note on a volume's boot code and, when Kickstart runs it, the code
/// as a child.
pub(super) struct BootCode<'a> {
    pub(super) child: Option<Child<'a>>,
    pub(super) note: String,
}

impl<'a> BootBlock<'a> {
    /// The boot block of `blocks` blocks at file offset `offset`, if the
    /// input holds all of it. The checksum covers all of the boot blocks
    /// ([FAQ] 4.1: `BOOTBLOCKSIZE` is 1024 for floppies and
    /// `DosEnvVec->Bootblocks * BSIZE` for hard disks).
    pub(super) fn read(data: &'a [u8], offset: usize, blocks: usize) -> Option<Self> {
        if blocks == 0 {
            return None;
        }
        let size = blocks.checked_mul(BLOCK_SIZE)?;
        let bytes = data.get(offset..offset.checked_add(size)?)?;
        // At least one block: the 12-byte header lies inside it.
        let long = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        Some(Self {
            offset,
            id: bytes[..4].try_into().expect("4 bytes"),
            stored_checksum: long(CHECKSUM_OFFSET),
            computed_checksum: checksum(bytes),
            dos_block: long(DOS_BLOCK_OFFSET),
            code: &bytes[BOOT_ENTRY..],
        })
    }

    /// The boot blocks start with `DOS`.
    pub(super) fn has_dos_signature(&self) -> bool {
        self.id[..3] == DOS_SIGNATURE
    }

    /// The fourth byte of `bb_id`: the DOS type flags of an `AmigaDOS`
    /// volume.
    pub(super) fn flags(&self) -> u8 {
        self.id[DOS_TYPE_OFFSET]
    }

    pub(super) fn is_checksum_valid(&self) -> bool {
        self.stored_checksum == self.computed_checksum
    }

    /// Anything but zeros after `BB_ENTRY`. No source says whether
    /// Kickstart refuses a zero code area; such a boot block is reported as
    /// holding no code.
    pub(super) fn has_code(&self) -> bool {
        self.code.iter().any(|&b| b != 0)
    }

    /// Kickstart runs the code: "the boot blocks start with the three
    /// characters "DOS" and pass the longword checksum (with carry
    /// wraparound)" ([RKRM] "Bootblock Booting" step 1d), and there is code
    /// to run.
    pub(super) fn is_bootable(&self) -> bool {
        self.has_dos_signature() && self.is_checksum_valid() && self.has_code()
    }

    /// A note on the boot code and, for a bootable boot block, the code
    /// area as a 680x0 child labeled `label`.
    pub(super) fn boot_code(&self, label: &str) -> BootCode<'a> {
        let start = self.offset + BOOT_ENTRY;
        let last = start + self.code.len() - 1;
        if !self.has_dos_signature() {
            return BootCode {
                child: None,
                note: format!(
                    "{label}: none; the boot block does not start with DOS, so Kickstart does \
                     not run it"
                ),
            };
        }
        if !self.has_code() {
            return BootCode {
                child: None,
                note: format!("{label}: none; the boot code area 0x{start:X}-0x{last:X} is zero"),
            };
        }
        if !self.is_checksum_valid() {
            return BootCode {
                child: None,
                note: format!(
                    "{label}: the boot block holds code at 0x{start:X}-0x{last:X}, but its \
                     checksum is 0x{:08X}, not 0x{:08X}; Kickstart does not run it, so it is \
                     not classified",
                    self.stored_checksum, self.computed_checksum
                ),
            };
        }
        let note = format!(
            "{label} at 0x{start:X}-0x{last:X} ({} B): the DOS signature and the boot block \
             checksum 0x{:08X} are valid, so Kickstart runs it on the 680x0 from offset \
             {BOOT_ENTRY} (BB_ENTRY)",
            self.code.len(),
            self.stored_checksum
        );
        let child = Child::stored(label, start, self.code)
            .with_target(BOOT_CODE_TARGET)
            .as_code();
        BootCode {
            child: Some(child),
            note,
        }
    }
}

/// The boot block checksum of `boot` ([FAQ] 4.1, the 68000 and C versions;
/// [ADFLIB] `adfBootSum`; [AMITOOLS] `BootBlock._calc_chksum`): every long
/// but the checksum itself added with carry wraparound (a carry out of bit
/// 31 adds 1), then complemented.
pub(super) fn checksum(boot: &[u8]) -> u32 {
    let sum = boot
        .chunks_exact(4)
        .enumerate()
        .filter(|&(i, _)| i != CHECKSUM_OFFSET / 4)
        .map(|(_, long)| u32::from_be_bytes(long.try_into().expect("4 bytes")))
        .fold(0u32, |sum, long| {
            let (sum, carry) = sum.overflowing_add(long);
            sum.wrapping_add(u32::from(carry))
        });
    !sum
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-block boot block: `id`, the checksum the boot blocks need (or
    /// `checksum_override` when given), `bb_dosblock` 880 and `code` at
    /// `BB_ENTRY`.
    fn boot_block(id: [u8; 4], code: &[u8], checksum_override: Option<u32>) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..4].copy_from_slice(&id);
        bytes[8..12].copy_from_slice(&880u32.to_be_bytes());
        bytes[12..12 + code.len()].copy_from_slice(code);
        let sum = checksum_override.unwrap_or_else(|| checksum(&bytes));
        bytes[4..8].copy_from_slice(&sum.to_be_bytes());
        bytes
    }

    #[test]
    fn the_checksum_adds_carries_back_in() {
        // Two longs of 0x80000000 overflow once: the sum is 0 plus the
        // carry, and the complement of 1 is 0xFFFFFFFE.
        let mut bytes = vec![0u8; 1024];
        bytes[..4].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        assert_eq!(checksum(&bytes), 0xffff_fffe);
        // The checksum long itself is skipped.
        bytes[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert_eq!(checksum(&bytes), 0xffff_fffe);
        // An empty "DOS\0" boot block: !0x444F5300.
        let mut empty = vec![0u8; 1024];
        empty[..4].copy_from_slice(b"DOS\0");
        assert_eq!(checksum(&empty), 0xbbb0_acff);
    }

    #[test]
    fn bootable_boot_blocks_need_the_signature_a_valid_checksum_and_code() {
        // moveq #0,d0; rts
        let code = [0x70, 0x00, 0x4e, 0x75];
        let bytes = boot_block(*b"DOS\0", &code, None);
        let boot = BootBlock::read(&bytes, 0, 2).unwrap();
        assert!(boot.is_bootable());
        assert_eq!(boot.dos_block, 880);
        assert_eq!(boot.code.len(), 1012);
        let found = boot.boot_code("Boot block code");
        let child = found.child.expect("bootable");
        assert_eq!((child.offset, child.data.len()), (12, 1012));
        assert_eq!(child.target, Some(BOOT_CODE_TARGET));
        assert!(found.note.contains("0xC-0x3FF (1012 B)"), "{}", found.note);

        let bad = boot_block(*b"DOS\0", &code, Some(0x1234_5678));
        let found = BootBlock::read(&bad, 0, 2)
            .unwrap()
            .boot_code("Boot block code");
        assert!(found.child.is_none());
        assert!(found.note.contains("not 0x"), "{}", found.note);

        let empty = boot_block(*b"DOS\x01", &[], None);
        let boot = BootBlock::read(&empty, 0, 2).unwrap();
        assert!(boot.is_checksum_valid() && !boot.is_bootable());
        assert!(boot.boot_code("Boot block code").note.contains("is zero"));

        let other = boot_block(*b"PFS\x01", &code, None);
        assert!(!BootBlock::read(&other, 0, 2).unwrap().is_bootable());
        assert!(BootBlock::read(&bytes[..1000], 0, 2).is_none());
    }
}
