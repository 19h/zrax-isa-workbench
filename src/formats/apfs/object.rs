//! Blocks and objects: bounds-checked block reads that tell a container
//! cut short from an address beyond the container, the object header
//! `obj_phys_t` ([REF] "Objects"), and the Fletcher-64 object checksum
//! ([REF] names it; the algorithm is [FUSE] `Fletcher64` and [LIBFS]
//! `libfsapfs_checksum_calculate_fletcher64`, which agree).

use super::*;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;

/// Fletcher-64 works on 32-bit words modulo 2^32 - 1.
const FLETCHER_MODULUS: u64 = 0xffff_ffff;

/// The checksum covers the object from the byte after `o_cksum`.
const CHECKSUM_SIZE: usize = 8;

/// The Fletcher-64 checksum of `object` as `o_cksum` stores it: the sums
/// over the little-endian 32-bit words after the checksum field, folded so
/// that adding the stored checksum makes both sums zero.
pub(super) fn fletcher64(object: &[u8]) -> u64 {
    let mut low: u64 = 0;
    let mut high: u64 = 0;
    // Reducing at every step gives the same residues as the references'
    // reduction at the end, and cannot overflow on any input length.
    for word in object.get(CHECKSUM_SIZE..).unwrap_or(&[]).chunks_exact(4) {
        let word = u32::from_le_bytes(word.try_into().expect("chunk has 4 bytes"));
        low = (low + u64::from(word)) % FLETCHER_MODULUS;
        high = (high + low) % FLETCHER_MODULUS;
    }
    let check_low = FLETCHER_MODULUS - (low + high) % FLETCHER_MODULUS;
    let check_high = FLETCHER_MODULUS - (low + check_low) % FLETCHER_MODULUS;
    (check_high << 32) | check_low
}

/// Whether `object`'s stored `o_cksum` matches its contents. A stored
/// checksum of all zero or all one bits never matches ([FUSE]
/// `VerifyBlock`).
pub(super) fn has_valid_checksum(object: &[u8]) -> bool {
    let Ok(stored) = le_u64(object, 0) else {
        return false;
    };
    stored != 0 && stored != u64::MAX && stored == fletcher64(object)
}

/// An object header (`obj_phys_t`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Header {
    /// `o_oid`: the block address of a physical object, otherwise a number.
    pub(super) oid: u64,
    /// `o_xid`: the transaction that last modified the object.
    pub(super) xid: u64,
    /// `o_type`: the type in the low 16 bits, flags in the high 16 bits.
    pub(super) object_type: u32,
    /// `o_subtype`.
    pub(super) subtype: u32,
}

impl Header {
    /// The header at the start of `object`.
    pub(super) fn parse(object: &[u8]) -> Result<Self> {
        Ok(Self {
            oid: le_u64(object, O_OID_FIELD)?,
            xid: le_u64(object, 16)?,
            object_type: le_u32(object, O_TYPE_FIELD)?,
            subtype: le_u32(object, 28)?,
        })
    }

    /// The object type without its flags (`OBJECT_TYPE_MASK`).
    pub(super) fn kind(&self) -> u32 {
        self.object_type & OBJECT_TYPE_MASK
    }
}

/// An object read from one block.
#[derive(Debug, Clone, Copy)]
pub(super) struct Object<'a> {
    /// Block address.
    pub(super) paddr: u64,
    /// The block's bytes.
    pub(super) bytes: &'a [u8],
    pub(super) header: Header,
}

/// The container's bytes, as many whole blocks as the input holds, with the
/// object read budget.
pub(super) struct Disk<'a> {
    data: &'a [u8],
    block_size: usize,
    /// `nx_block_count`.
    block_count: u64,
    /// Whole blocks present in the input (at most `block_count`).
    present: u64,
    /// Object reads left; see [`Disk::object`].
    budget: Cell<u64>,
    /// Object reads that failed because the block is not present.
    absent: Cell<usize>,
    /// Blocks whose checksum has been verified.
    verified: RefCell<HashSet<u64>>,
}

impl<'a> Disk<'a> {
    /// The container in `data` with block 0's geometry.
    pub(super) fn new(data: &'a [u8], block0: &NxSuperblock) -> Self {
        let block_size = block0.block_size();
        let present = ((data.len() / block_size) as u64).min(block0.block_count);
        Self {
            data,
            block_size,
            block_count: block0.block_count,
            present,
            budget: Cell::new(present.max(1).saturating_mul(METADATA_READ_FACTOR)),
            absent: Cell::new(0),
            verified: RefCell::new(HashSet::new()),
        }
    }

    pub(super) fn block_size(&self) -> usize {
        self.block_size
    }

    /// Whole blocks of the container that the input holds.
    pub(super) fn present_blocks(&self) -> u64 {
        self.present
    }

    /// Object reads that failed because their block is not present.
    pub(super) fn absent_reads(&self) -> usize {
        self.absent.get()
    }

    /// The object read limit was reached; walks stop.
    pub(super) fn is_exhausted(&self) -> bool {
        self.budget.get() == 0
    }

    /// File offset of block `paddr`, which must not exceed the blocks
    /// present (callers take it from a successful [`Disk::blocks`] read).
    pub(super) fn file_offset(&self, paddr: u64) -> usize {
        // The present blocks lie within the input, so the offset fits.
        usize::try_from(paddr.min(self.present)).expect("present block") * self.block_size
    }

    /// The bytes of `count` blocks from block `start`.
    pub(super) fn blocks(&self, start: u64, count: u64) -> Result<&'a [u8]> {
        let end = start
            .checked_add(count)
            .filter(|&end| end <= self.block_count)
            .ok_or_else(|| {
                error(format!(
                    "Invalid block range 0x{start:X} + {count} beyond the {} blocks of the \
                     container",
                    self.block_count
                ))
            })?;
        if end > self.present {
            self.absent.set(self.absent.get() + 1);
            return Err(error(format!(
                "Truncated container: block 0x{:X} is not present ({} present)",
                start.max(self.present),
                counted(
                    usize::try_from(self.present).unwrap_or(usize::MAX),
                    "block",
                    "blocks"
                )
            )));
        }
        // Both ends are present blocks, so they lie within the input.
        let first = self.file_offset(start);
        let last = usize::try_from(end).expect("present block") * self.block_size;
        Ok(&self.data[first..last])
    }

    /// The object in block `paddr`, whose identifier must be `oid` and
    /// whose checksum must verify. Each read counts against the budget of
    /// [`METADATA_READ_FACTOR`] reads per block present.
    pub(super) fn object(&self, paddr: u64, oid: u64) -> Result<Object<'a>> {
        let Some(left) = self.budget.get().checked_sub(1) else {
            return Err(error(format!(
                "Invalid metadata: more than {} object reads ({METADATA_READ_FACTOR} times the \
                 blocks present)",
                self.present.max(1).saturating_mul(METADATA_READ_FACTOR)
            )));
        };
        self.budget.set(left);
        let bytes = self.blocks(paddr, 1)?;
        if !self.verified.borrow().contains(&paddr) {
            if !has_valid_checksum(bytes) {
                return Err(error(format!(
                    "Invalid object checksum in block 0x{paddr:X}"
                )));
            }
            self.verified.borrow_mut().insert(paddr);
        }
        let header = Header::parse(bytes)?;
        if header.oid != oid {
            return Err(error(format!(
                "Invalid object in block 0x{paddr:X}: identifier 0x{:X}, 0x{oid:X} expected",
                header.oid
            )));
        }
        Ok(Object {
            paddr,
            bytes,
            header,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4 KiB block whose checksum field holds the Fletcher-64 of the rest.
    fn checksummed(fill: u8) -> Vec<u8> {
        let mut block = vec![fill; 4096];
        let checksum = fletcher64(&block);
        block[..8].copy_from_slice(&checksum.to_le_bytes());
        block
    }

    #[test]
    fn a_stored_fletcher_checksum_makes_both_sums_zero() {
        // Zero and 0xFF fill sum to zero and give the all-ones checksum,
        // which never verifies.
        for fill in [0x01, 0x5a, 0xa5] {
            let block = checksummed(fill);
            assert!(has_valid_checksum(&block), "fill 0x{fill:02X}");
            // Summing the words after the checksum, then the checksum's two
            // words, gives zero ([FUSE] `VerifyBlock`).
            let mut low = 0u64;
            let mut high = 0u64;
            let words = block[CHECKSUM_SIZE..].chunks_exact(4);
            for word in words.chain(block[..CHECKSUM_SIZE].chunks_exact(4)) {
                low += u64::from(u32::from_le_bytes(word.try_into().unwrap()));
                high += low;
            }
            assert_eq!(low % FLETCHER_MODULUS, 0);
            assert_eq!(high % FLETCHER_MODULUS, 0);
        }
    }

    #[test]
    fn a_changed_byte_or_a_degenerate_checksum_does_not_verify() {
        let mut block = checksummed(0x5a);
        block[100] ^= 1;
        assert!(!has_valid_checksum(&block));
        let zero = vec![0u8; 4096];
        assert!(!has_valid_checksum(&zero));
        assert!(!has_valid_checksum(&[0u8; 4]));
    }
}
