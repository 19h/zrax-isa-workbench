//! `ChromeOS` verified-boot kernel partitions.
//!
//! Layout (vboot `firmware/2lib/include/2struct.h`; `futility/vb1_helper.c`:
//! "kernel partition = kernel vblock + kernel blob"), all integers
//! little-endian:
//! - keyblock (`vb2_keyblock`, 112 B): magic `CHROMEOS` (8), header version
//!   major and minor (4 each), keyblock size (4), reserved (4), keyblock
//!   signature and SHA-512 hash (24 each, `vb2_signature`), flags (4),
//!   reserved (4), the data key (32, `vb2_packed_key`), then the key, hash
//!   and signature data;
//! - kernel preamble (`vb2_kernel_preamble`) at the end of the keyblock:
//!   preamble size (4), reserved (4), preamble signature (24), header
//!   version major and minor (4 each), kernel version (4), reserved (4),
//!   body load address (8), bootloader address (8), bootloader size (4),
//!   reserved (4), body signature (24); from version 2.1 the vmlinuz
//!   header address (8), its size (4) and reserved (4); from 2.2 flags
//!   (4, bits 1-0 the kernel type);
//! - the kernel blob at `keyblock_size + preamble_size`
//!   (`2load_kernel.c` `get_body_offset`), `body_signature.data_size`
//!   bytes long.
//!
//! A `vb2_signature` is a data offset from the start of the structure (4),
//! reserved (4), data size (4), reserved (4), signed size (4), reserved
//! (4); a `vb2_packed_key` is a key offset, key size, algorithm and key
//! version, each followed by a reserved word. The structure checks follow
//! `firmware/2lib/2struct.c` (`vb2_check_keyblock`,
//! `vb2_verify_keyblock_hash`, `vb2_verify_kernel_preamble`) and
//! `2common.c` (`vb2_verify_member_inside`).
//!
//! `futility` builds the blob as the kernel (rounded up to 4 KiB), the
//! command line (4 KiB), x86 boot parameters (4 KiB), the bootloader and
//! the vmlinuz header (`CreateKernelBlob`; `kernel_blob.h`). For x86 it
//! keeps only the protected-mode part of the `bzImage` in the kernel slot
//! and stores the setup code as the vmlinuz header; `vbutil_kernel
//! --get-vmlinuz` rebuilds the `vmlinuz` as that header followed by the
//! blob (`cmd_vbutil_kernel.c`).

use super::*;
use sha2::{Digest, Sha512};
use std::borrow::Cow;

/// `VB2_KEYBLOCK_MAGIC`.
const KEYBLOCK_MAGIC: &[u8; 8] = b"CHROMEOS";

/// `VB2_KEYBLOCK_VERSION_MAJOR`; `vb2_check_keyblock` rejects others.
const KEYBLOCK_VERSION_MAJOR: u32 = 2;

/// `vb2_keyblock` fields (`EXPECTED_VB2_KEYBLOCK_SIZE`).
const KEYBLOCK_HEADER_SIZE: usize = 112;
const KEYBLOCK_VERSION_MAJOR_AT: usize = 8;
const KEYBLOCK_VERSION_MINOR_AT: usize = 12;
const KEYBLOCK_SIZE_AT: usize = 16;
const KEYBLOCK_SIGNATURE_AT: usize = 24;
const KEYBLOCK_HASH_AT: usize = 48;
const KEYBLOCK_FLAGS_AT: usize = 72;
const KEYBLOCK_DATA_KEY_AT: usize = 80;

/// `EXPECTED_VB2_SIGNATURE_SIZE` and `EXPECTED_VB2_PACKED_KEY_SIZE`.
const SIGNATURE_SIZE: usize = 24;
const PACKED_KEY_SIZE: usize = 32;

/// `vb2_signature` and `vb2_packed_key` fields.
const SIG_OFFSET_AT: usize = 0;
const SIG_SIZE_AT: usize = 8;
const SIG_DATA_SIZE_AT: usize = 16;
const KEY_OFFSET_AT: usize = 0;
const KEY_SIZE_AT: usize = 8;
const KEY_ALGORITHM_AT: usize = 16;
const KEY_VERSION_AT: usize = 24;

/// The keyblock hash is a SHA-512 digest (`vb2_verify_keyblock_hash`).
const SHA512_SIZE: usize = 64;

/// `VB2_KERNEL_PREAMBLE_HEADER_VERSION_MAJOR`.
const PREAMBLE_VERSION_MAJOR: u32 = 2;

/// `vb2_kernel_preamble` fields.
const PREAMBLE_SIZE_AT: usize = 0;
const PREAMBLE_SIGNATURE_AT: usize = 8;
const PREAMBLE_VERSION_MAJOR_AT: usize = 32;
const PREAMBLE_VERSION_MINOR_AT: usize = 36;
const KERNEL_VERSION_AT: usize = 40;
const BODY_LOAD_ADDRESS_AT: usize = 48;
const BOOTLOADER_ADDRESS_AT: usize = 56;
const BOOTLOADER_SIZE_AT: usize = 64;
const BODY_SIGNATURE_AT: usize = 72;
const VMLINUZ_HEADER_ADDRESS_AT: usize = 96;
const VMLINUZ_HEADER_SIZE_AT: usize = 104;
const PREAMBLE_FLAGS_AT: usize = 112;

/// `EXPECTED_VB2_KERNEL_PREAMBLE_2_0_SIZE`, `_2_1_SIZE` and `_2_2_SIZE`.
const PREAMBLE_2_0_SIZE: usize = 96;
const PREAMBLE_2_1_SIZE: usize = 112;
const PREAMBLE_2_2_SIZE: usize = 116;

/// `vb2_verify_kernel_preamble` requires the preamble signature to cover
/// at least `sizeof(struct vb2_fw_preamble)` bytes.
const MIN_PREAMBLE_SIGNED: u64 = 108;

/// `VB2_KERNEL_TYPE_MASK` and the kernel types (`2constants.h`).
const KERNEL_TYPE_MASK: u32 = 0x3;
const KERNEL_TYPE_CROS: u32 = 0;
const KERNEL_TYPE_BOOTIMG: u32 = 1;
const KERNEL_TYPE_MULTIBOOT: u32 = 2;

/// Keyblock flags (`VB2_KEYBLOCK_FLAG_*`).
const KEYBLOCK_FLAGS: &[KeyblockFlag] = &[
    flag(0x01, "developer mode off"),
    flag(0x02, "developer mode on"),
    flag(0x04, "normal boot"),
    flag(0x08, "recovery mode"),
    flag(0x10, "not miniOS"),
    flag(0x20, "miniOS"),
];

/// Data key algorithms in `enum vb2_crypto_algorithm` order, with the
/// names `2crypto.c` gives them.
const ALGORITHMS: [&str; 18] = [
    "RSA1024 SHA1",
    "RSA1024 SHA256",
    "RSA1024 SHA512",
    "RSA2048 SHA1",
    "RSA2048 SHA256",
    "RSA2048 SHA512",
    "RSA4096 SHA1",
    "RSA4096 SHA256",
    "RSA4096 SHA512",
    "RSA8192 SHA1",
    "RSA8192 SHA256",
    "RSA8192 SHA512",
    "RSA2048 EXP3 SHA1",
    "RSA2048 EXP3 SHA256",
    "RSA2048 EXP3 SHA512",
    "RSA3072 EXP3 SHA1",
    "RSA3072 EXP3 SHA256",
    "RSA3072 EXP3 SHA512",
];

/// The command line and x86 boot parameter pages that `futility` puts
/// before the bootloader (`CROS_CONFIG_SIZE`, `CROS_PARAMS_SIZE`).
const CONFIG_SIZE: u32 = 4096;
const PARAMS_SIZE: u32 = 4096;

/// vboot reads this much of the partition before the body and rejects a
/// body offset beyond it (`2load_kernel.c` `KBUF_SIZE`).
const KBUF_SIZE: usize = 64 << 10;

/// Transform named for a `vmlinuz` rebuilt from the vmlinuz header and the
/// blob.
const VMLINUZ_TRANSFORM: &str = "vmlinuz reassembly";

/// One keyblock flag bit and what it allows.
#[derive(Debug)]
struct KeyblockFlag {
    bit: u32,
    name: &'static str,
}

const fn flag(bit: u32, name: &'static str) -> KeyblockFlag {
    KeyblockFlag { bit, name }
}

/// The magic and keyblock header version 2: 96 bits of fixed values.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(KEYBLOCK_MAGIC)
        && le_u32(data, KEYBLOCK_VERSION_MAJOR_AT)
            .is_ok_and(|major| major == KEYBLOCK_VERSION_MAJOR)
}

/// A `vb2_signature`: where its data lies relative to the structure, how
/// large it is and how many bytes it signs.
#[derive(Debug, Clone, Copy)]
struct Signature {
    /// Byte offset of the structure in its parent.
    at: usize,
    sig_offset: u32,
    sig_size: u32,
    data_size: u32,
}

impl Signature {
    fn read(parent: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            at,
            sig_offset: le_u32(parent, at + SIG_OFFSET_AT)?,
            sig_size: le_u32(parent, at + SIG_SIZE_AT)?,
            data_size: le_u32(parent, at + SIG_DATA_SIZE_AT)?,
        })
    }

    /// Whether the structure and its data lie in the first `parent_size`
    /// bytes of the parent.
    fn is_inside(self, parent_size: u64) -> bool {
        is_member_inside(
            parent_size,
            self.at as u64,
            SIGNATURE_SIZE as u64,
            u64::from(self.sig_offset),
            u64::from(self.sig_size),
        )
    }

    /// Parent offset of the signature data; [`Self::is_inside`] held.
    fn data_start(self) -> usize {
        self.at + to_usize(self.sig_offset)
    }
}

/// A `vb2_packed_key`.
#[derive(Debug, Clone, Copy)]
struct PackedKey {
    at: usize,
    key_offset: u32,
    key_size: u32,
    algorithm: u32,
    key_version: u32,
}

impl PackedKey {
    fn read(parent: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            at,
            key_offset: le_u32(parent, at + KEY_OFFSET_AT)?,
            key_size: le_u32(parent, at + KEY_SIZE_AT)?,
            algorithm: le_u32(parent, at + KEY_ALGORITHM_AT)?,
            key_version: le_u32(parent, at + KEY_VERSION_AT)?,
        })
    }

    fn is_inside(self, parent_size: u64) -> bool {
        is_member_inside(
            parent_size,
            self.at as u64,
            PACKED_KEY_SIZE as u64,
            u64::from(self.key_offset),
            u64::from(self.key_size),
        )
    }

    fn algorithm_name(self) -> String {
        match ALGORITHMS.get(to_usize(self.algorithm)) {
            Some(name) => (*name).to_string(),
            None => format!("unknown algorithm {}", self.algorithm),
        }
    }
}

/// `vb2_verify_member_inside`: a structure of `member_size` bytes at
/// `member_offset` lies in a parent of `parent_size` bytes, and so does its
/// data of `data_size` bytes at `data_offset` from the structure, which
/// must not overlap the structure.
fn is_member_inside(
    parent_size: u64,
    member_offset: u64,
    member_size: u64,
    data_offset: u64,
    data_size: u64,
) -> bool {
    let member_end = member_offset + member_size;
    let data_start = member_offset + data_offset;
    let data_end = data_start + data_size;
    member_end <= parent_size
        && (data_size == 0 || data_start >= member_end)
        && data_end <= parent_size
}

/// The checked keyblock.
#[derive(Debug)]
struct Keyblock {
    minor: u32,
    size: usize,
    flags: u32,
    data_key: PackedKey,
    /// Keyblock signature data size; 0 when the keyblock is unsigned.
    signature_size: u32,
}

/// Check the keyblock at the start of `data` the way `vb2_check_keyblock`
/// does for its hash, then verify the SHA-512 hash.
fn keyblock(data: &[u8]) -> Result<Keyblock> {
    let header = slice(data, 0, KEYBLOCK_HEADER_SIZE, "ChromeOS keyblock header")?;
    if !header.starts_with(KEYBLOCK_MAGIC) {
        return Err(error("Invalid ChromeOS keyblock magic"));
    }
    let major = le_u32(header, KEYBLOCK_VERSION_MAJOR_AT)?;
    let minor = le_u32(header, KEYBLOCK_VERSION_MINOR_AT)?;
    if major != KEYBLOCK_VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported ChromeOS keyblock header version {major}.{minor}"
        )));
    }
    let size = to_usize(le_u32(header, KEYBLOCK_SIZE_AT)?);
    if size < KEYBLOCK_HEADER_SIZE {
        return Err(error(format!(
            "Invalid ChromeOS keyblock size {size} B: smaller than the {KEYBLOCK_HEADER_SIZE}-byte header"
        )));
    }
    let block = slice(data, 0, size, "ChromeOS keyblock")?;
    let block_size = size as u64;
    let signature = Signature::read(block, KEYBLOCK_SIGNATURE_AT)?;
    let hash = Signature::read(block, KEYBLOCK_HASH_AT)?;
    let data_key = PackedKey::read(block, KEYBLOCK_DATA_KEY_AT)?;
    if !signature.is_inside(block_size) {
        return Err(error(
            "Invalid ChromeOS keyblock signature: outside the keyblock",
        ));
    }
    if !hash.is_inside(block_size) {
        return Err(error(
            "Invalid ChromeOS keyblock hash: outside the keyblock",
        ));
    }
    let signed = u64::from(hash.data_size);
    if signed > block_size || signed < KEYBLOCK_HEADER_SIZE as u64 {
        return Err(error(format!(
            "Invalid ChromeOS keyblock hash: covers {signed} B of a {size}-byte keyblock"
        )));
    }
    if !data_key.is_inside(block_size) || !data_key.is_inside(signed) {
        return Err(error(
            "Invalid ChromeOS keyblock data key: outside the hashed keyblock",
        ));
    }
    if to_usize(hash.sig_size) != SHA512_SIZE {
        return Err(error(format!(
            "Invalid ChromeOS keyblock hash size {} B: SHA-512 needs {SHA512_SIZE} B",
            hash.sig_size
        )));
    }
    let stored = &block[hash.data_start()..hash.data_start() + SHA512_SIZE];
    if Sha512::digest(&block[..to_usize(hash.data_size)]).as_slice() != stored {
        return Err(error("Invalid ChromeOS keyblock SHA-512 hash"));
    }
    Ok(Keyblock {
        minor,
        size,
        flags: le_u32(header, KEYBLOCK_FLAGS_AT)?,
        data_key,
        signature_size: signature.sig_size,
    })
}

/// The checked kernel preamble. Addresses are target addresses; the
/// bootloader and vmlinuz header lie in the body that loads at
/// `body_load_address`.
#[derive(Debug)]
struct Preamble {
    minor: u32,
    size: usize,
    kernel_version: u32,
    body_load_address: u64,
    bootloader_address: u64,
    bootloader_size: u32,
    /// Bytes the body signature covers: the kernel blob size.
    body_size: u32,
    /// Signature data sizes of the body and of the preamble itself.
    body_signature_size: u32,
    signature_size: u32,
    vmlinuz_header_address: u64,
    vmlinuz_header_size: u32,
    flags: u32,
}

/// Check the kernel preamble at `offset` the way
/// `vb2_verify_kernel_preamble` does before its signature check.
fn preamble(data: &[u8], offset: usize) -> Result<Preamble> {
    let header = slice(data, offset, PREAMBLE_2_0_SIZE, "ChromeOS kernel preamble")?;
    let major = le_u32(header, PREAMBLE_VERSION_MAJOR_AT)?;
    let minor = le_u32(header, PREAMBLE_VERSION_MINOR_AT)?;
    if major != PREAMBLE_VERSION_MAJOR {
        return Err(error(format!(
            "Unsupported ChromeOS kernel preamble version {major}.{minor} at 0x{offset:X}"
        )));
    }
    let min_size = match minor {
        0 => PREAMBLE_2_0_SIZE,
        1 => PREAMBLE_2_1_SIZE,
        _ => PREAMBLE_2_2_SIZE,
    };
    let size = to_usize(le_u32(header, PREAMBLE_SIZE_AT)?);
    if size < min_size {
        return Err(error(format!(
            "Invalid ChromeOS kernel preamble size {size} B: version 2.{minor} needs {min_size} B"
        )));
    }
    let block = slice(data, offset, size, "ChromeOS kernel preamble")?;
    let block_size = size as u64;
    let signature = Signature::read(block, PREAMBLE_SIGNATURE_AT)?;
    let body = Signature::read(block, BODY_SIGNATURE_AT)?;
    if !signature.is_inside(block_size) {
        return Err(error(
            "Invalid ChromeOS kernel preamble signature: outside the preamble",
        ));
    }
    let signed = u64::from(signature.data_size);
    if signed > block_size || signed < MIN_PREAMBLE_SIGNED {
        return Err(error(format!(
            "Invalid ChromeOS kernel preamble signature: covers {signed} B of a {size}-byte preamble"
        )));
    }
    if !body.is_inside(signed) {
        return Err(error(
            "Invalid ChromeOS kernel body signature: outside the signed preamble",
        ));
    }
    let (vmlinuz_header_address, vmlinuz_header_size) = if minor >= 1 {
        (
            le_u64(block, VMLINUZ_HEADER_ADDRESS_AT)?,
            le_u32(block, VMLINUZ_HEADER_SIZE_AT)?,
        )
    } else {
        (0, 0)
    };
    let flags = if minor >= 2 {
        le_u32(block, PREAMBLE_FLAGS_AT)?
    } else {
        0
    };
    Ok(Preamble {
        minor,
        size,
        kernel_version: le_u32(block, KERNEL_VERSION_AT)?,
        body_load_address: le_u64(block, BODY_LOAD_ADDRESS_AT)?,
        bootloader_address: le_u64(block, BOOTLOADER_ADDRESS_AT)?,
        bootloader_size: le_u32(block, BOOTLOADER_SIZE_AT)?,
        body_size: body.data_size,
        body_signature_size: body.sig_size,
        signature_size: signature.sig_size,
        vmlinuz_header_address,
        vmlinuz_header_size,
        flags,
    })
}

/// Where a region the preamble names by target address lies in the blob.
#[derive(Debug, Clone, Copy)]
struct BlobRange {
    /// Offset in the blob.
    offset: usize,
    size: usize,
}

/// The blob offset of `size` bytes at target `address`, when they lie in
/// the `body_size`-byte body loaded at `load_address`
/// (`vb2_verify_member_inside` on the loaded body).
fn blob_range(load_address: u64, body_size: u32, address: u64, size: u32) -> Option<BlobRange> {
    let offset = address.checked_sub(load_address)?;
    let end = offset.checked_add(u64::from(size))?;
    if end > u64::from(body_size) {
        return None;
    }
    Some(BlobRange {
        offset: usize::try_from(offset).ok()?,
        size: to_usize(size),
    })
}

/// The blob range of the `size` bytes the preamble names at target
/// `address`, or `None` when it names none (size 0). As in
/// `vb2_verify_kernel_preamble`, a region outside the signed body is an
/// error.
fn body_region(
    preamble: &Preamble,
    address: u64,
    size: u32,
    what: &str,
) -> Result<Option<BlobRange>> {
    if size == 0 {
        return Ok(None);
    }
    blob_range(
        preamble.body_load_address,
        preamble.body_size,
        address,
        size,
    )
    .map(Some)
    .ok_or_else(|| {
        error(format!(
            "Invalid ChromeOS {what}: outside the signed kernel body"
        ))
    })
}

/// Parse a kernel partition: check the keyblock, verify its hash, check
/// the preamble, and list the kernel and bootloader from the blob.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let keyblock = keyblock(data)?;
    let preamble = preamble(data, keyblock.size)?;
    let body_offset = keyblock
        .size
        .checked_add(preamble.size)
        .ok_or_else(|| error("Invalid ChromeOS kernel body offset"))?;
    if preamble.body_size == 0 {
        return Err(error("Invalid ChromeOS kernel body signature: signs 0 B"));
    }
    let blob = slice(
        data,
        body_offset,
        to_usize(preamble.body_size),
        "ChromeOS kernel body",
    )?;
    let bootloader = body_region(
        &preamble,
        preamble.bootloader_address,
        preamble.bootloader_size,
        "bootloader",
    )?;
    let vmlinuz_header = body_region(
        &preamble,
        preamble.vmlinuz_header_address,
        preamble.vmlinuz_header_size,
        "vmlinuz header",
    )?;

    let mut c = Container::new(
        FileFormat::ChromeOsKernel,
        Layout::ChromeOsKernel.label(),
        "chromeos",
    );
    let body_end = body_offset + blob.len();
    c.consumed = body_end;
    push_header_notes(&mut c, &keyblock, &preamble, body_offset);
    let config = command_line(&preamble, blob, &mut c);
    let kernel_size = config.map_or(blob.len(), |range| range.offset);
    c.children.push(kernel(
        blob,
        body_offset,
        kernel_size,
        vmlinuz_header,
        &mut c.notes,
    ));
    if let Some(range) = bootloader {
        let bytes = &blob[range.offset..range.offset + range.size];
        c.children.push(Child::stored(
            "Bootloader",
            body_offset + range.offset,
            bytes,
        ));
    }
    let rest = &data[body_end..];
    if !rest.is_empty() {
        let what = if is_padding(rest) {
            "padding"
        } else {
            "outside the signed body and not analyzed"
        };
        c.notes.push(format!(
            "{} of unused partition space after the kernel body at 0x{body_end:X}: {what}",
            size_text(rest.len())
        ));
    }
    Ok(c)
}

/// Notes and metadata from the keyblock and preamble.
fn push_header_notes(c: &mut Container<'_>, keyblock: &Keyblock, preamble: &Preamble, body: usize) {
    c.notes.push(format!(
        "ChromeOS kernel partition: keyblock 2.{} ({}), kernel preamble 2.{} ({}), kernel body {} at 0x{body:X}",
        keyblock.minor,
        size_text(keyblock.size),
        preamble.minor,
        size_text(preamble.size),
        size_text(to_usize(preamble.body_size))
    ));
    let flags: Vec<&str> = KEYBLOCK_FLAGS
        .iter()
        .filter(|f| keyblock.flags & f.bit != 0)
        .map(|f| f.name)
        .collect();
    let flags = if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(", ")
    };
    let key = keyblock.data_key;
    let signature = if keyblock.signature_size == 0 {
        "keyblock is not signed".to_string()
    } else {
        format!(
            "keyblock signature ({} B) present, not verified",
            keyblock.signature_size
        )
    };
    c.notes.push(format!(
        "Keyblock flags 0x{:X} ({flags}); data key {}, version {}; keyblock SHA-512 hash verified; {signature}",
        keyblock.flags,
        key.algorithm_name(),
        key.key_version
    ));
    c.notes.push(format!(
        "Preamble signature ({} B) and kernel body signature ({} B) present, not verified",
        preamble.signature_size, preamble.body_signature_size
    ));
    c.notes.push(format!(
        "Kernel version {}; body load address 0x{:X}; kernel type {}",
        preamble.kernel_version,
        preamble.body_load_address,
        kernel_type(preamble)
    ));
    if body > KBUF_SIZE {
        c.notes.push(format!(
            "The kernel body starts at 0x{body:X}, beyond the {} that vboot reads before it; vboot rejects this partition",
            size_text(KBUF_SIZE)
        ));
    }
    c.push_metadata(
        "chromeos_kernel_version",
        "Kernel version",
        u64::from(preamble.kernel_version),
    );
    c.push_metadata(
        "chromeos_body_load_address",
        "Body load address",
        preamble.body_load_address,
    );
    c.push_metadata(
        "chromeos_keyblock_flags",
        "Keyblock flags",
        u64::from(keyblock.flags),
    );
    c.push_metadata(
        "chromeos_data_key_algorithm",
        "Data key algorithm",
        key.algorithm_name(),
    );
}

/// The kernel type the 2.2 flags name, or `ChromeOS` before 2.2
/// (`vb2_kernel_get_flags` returns 0 for older preambles).
fn kernel_type(preamble: &Preamble) -> String {
    match preamble.flags & KERNEL_TYPE_MASK {
        KERNEL_TYPE_CROS => "ChromeOS".to_string(),
        KERNEL_TYPE_BOOTIMG => "Android boot image".to_string(),
        KERNEL_TYPE_MULTIBOOT => "multiboot".to_string(),
        other => format!("unknown ({other})"),
    }
}

/// The command line page `futility` places 8 KiB before the bootloader,
/// noted when it holds text. `None` when the bootloader address leaves no
/// room for the command line and boot parameter pages in the body, so the
/// layout is not `futility`'s.
fn command_line(preamble: &Preamble, blob: &[u8], c: &mut Container<'_>) -> Option<BlobRange> {
    let start = preamble
        .bootloader_address
        .checked_sub(preamble.body_load_address)?
        .checked_sub(u64::from(CONFIG_SIZE + PARAMS_SIZE))?;
    let range = blob_range(0, preamble.body_size, start, CONFIG_SIZE)?;
    if range.offset == 0 {
        return None;
    }
    let page = &blob[range.offset..range.offset + range.size];
    let text = until_nul(page);
    if text.is_empty() {
        c.notes
            .push("Kernel command line page (futility layout) is empty".into());
    } else if is_text(text) {
        let line = display_text(text);
        c.notes.push(format!(
            "Kernel command line (futility layout, 8 KiB before the bootloader): {line}"
        ));
        c.push_metadata("chromeos_command_line", "Kernel command line", line);
    } else {
        c.notes.push(format!(
            "Kernel command line page at body offset 0x{:X} (futility layout) does not hold text",
            range.offset
        ));
    }
    Some(range)
}

/// The kernel child. With a vmlinuz header the `vmlinuz` is rebuilt as
/// `vbutil_kernel --get-vmlinuz` does: the header, then the whole blob.
/// Otherwise the kernel slot before the command line page is the kernel.
fn kernel<'a>(
    blob: &'a [u8],
    body_offset: usize,
    kernel_size: usize,
    vmlinuz_header: Option<BlobRange>,
    notes: &mut Vec<String>,
) -> Child<'a> {
    let Some(header) = vmlinuz_header else {
        return Child::stored("Kernel", body_offset, &blob[..kernel_size]);
    };
    let total = header.size.saturating_add(blob.len());
    if total > crate::formats::MAX_PAYLOAD {
        notes.push(format!(
            "Kernel: a rebuilt vmlinuz would exceed {}; the kernel slot is classified without its vmlinuz header",
            size_text(crate::formats::MAX_PAYLOAD)
        ));
        return Child::stored("Kernel", body_offset, &blob[..kernel_size]);
    }
    let mut vmlinuz = Vec::with_capacity(total);
    vmlinuz.extend_from_slice(&blob[header.offset..header.offset + header.size]);
    vmlinuz.extend_from_slice(blob);
    notes.push(format!(
        "Kernel: vmlinuz rebuilt from the {} vmlinuz header at body offset 0x{:X} and the kernel body, as vbutil_kernel --get-vmlinuz does",
        size_text(header.size),
        header.offset
    ));
    Child::decoded(
        "Kernel",
        body_offset,
        blob.len(),
        Cow::Owned(vmlinuz),
        VMLINUZ_TRANSFORM,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_must_lie_inside_their_parent_after_their_header() {
        assert!(is_member_inside(100, 24, 24, 24, 52));
        assert!(!is_member_inside(100, 24, 24, 24, 53));
        assert!(!is_member_inside(100, 24, 24, 0, 8));
        assert!(is_member_inside(100, 24, 24, 0, 0));
        assert!(!is_member_inside(40, 24, 24, 0, 0));
    }

    #[test]
    fn blob_ranges_are_relative_to_the_load_address() {
        let range = blob_range(0x10_0000, 0x3000, 0x10_2000, 0x800).expect("inside");
        assert_eq!((range.offset, range.size), (0x2000, 0x800));
        assert!(blob_range(0x10_0000, 0x3000, 0x10_2900, 0x800).is_none());
        assert!(blob_range(0x10_0000, 0x3000, 0xf_ffff, 1).is_none());
    }

    #[test]
    fn detection_needs_the_magic_and_version_2() {
        let mut header = KEYBLOCK_MAGIC.to_vec();
        header.extend_from_slice(&2u32.to_le_bytes());
        assert!(detect(&header));
        header[8] = 1;
        assert!(!detect(&header));
        assert!(!detect(b"CHROMEOS"));
    }
}
