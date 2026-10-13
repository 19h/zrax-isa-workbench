//! Bootable images: the startup header (`sys/startup.h`), the startup
//! program and the image filesystem after it, stored or compressed.
//!
//! Header (target byte order): signature (0), version (4), `flags1` (6),
//! `flags2` (7), `header_size` (8), `machine` (0xA), `startup_vaddr` (0xC),
//! `paddr_bias` (0x10), `image_paddr` (0x14), `ram_paddr` (0x18),
//! `ram_size` (0x1C), `startup_size` (0x20), `stored_size` (0x24),
//! `imagefs_paddr` (0x28), `imagefs_size` (0x2C), `preboot_size` (0x30),
//! `zero0` (0x32), then reserved words and the `info` area that the IPL
//! fills at run time. `startup_size` covers the header, the startup program
//! (raw segments, never compressed) and the startup trailer; `stored_size`
//! runs from the header to the end of the image trailer.
//!
//! A compressed image filesystem follows the startup trailer as one gzip
//! stream (`ZLIB`, written with zlib `gzopen`) or as blocks of a big-endian
//! 16-bit stored length and one LZO1X or UCL NRV2B block each, ended by a
//! zero length (mkifs `lzoflush`, `uclflush`); zero padding to a multiple of
//! four bytes and the image trailer follow.

use super::imagefs::{self, Source};
use super::*;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{Child, Section, Target};
use crate::formats::elf::{self, e_machine_to_isa};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, Isa, MetadataValue};
use std::borrow::Cow;

/// `flags1` bits (`STARTUP_HDR_FLAGS1_*`).
const STARTUP_HDR_FLAGS1_VIRTUAL: u8 = 0x01;
const STARTUP_HDR_FLAGS1_BIGENDIAN: u8 = 0x02;

/// The compression field of `flags1` and its values.
const STARTUP_HDR_FLAGS1_COMPRESS_MASK: u8 = 0x1c;
const STARTUP_HDR_FLAGS1_COMPRESS_NONE: u8 = 0x00;
const STARTUP_HDR_FLAGS1_COMPRESS_ZLIB: u8 = 0x04;
const STARTUP_HDR_FLAGS1_COMPRESS_LZO: u8 = 0x08;
const STARTUP_HDR_FLAGS1_COMPRESS_UCL: u8 = 0x0c;

/// `flags1` bits that no source defines (the name is this parser's).
const STARTUP_HDR_FLAGS1_UNDEFINED: u8 = 0xe0;

/// The fields this parser reads, through `zero0`.
const STARTUP_HEADER_FIELDS: usize = 0x34;

/// `sizeof(struct startup_header)` in every documented version.
const STARTUP_HEADER_SIZE: usize = 0x100;

/// mkifs never writes an LZO or UCL block that decodes to more than this
/// (`BUFFSIZE_LZO`, `BUFFSIZE_UCL`).
const COMPRESSED_BLOCK_SIZE: usize = 0x10000;

/// `EM_NONE`: the dummy startup header that records the compression of an
/// image without a startup program.
const EM_NONE: u16 = 0;

/// Label of the component that holds a compressed image filesystem that is
/// not decoded.
const COMPRESSED_LABEL: &str = "Compressed image filesystem";

/// A validated startup header.
struct StartupHeader {
    /// File offset of the header.
    offset: usize,
    /// Header byte order (true means little-endian).
    le: bool,
    version: u16,
    flags1: u8,
    /// Header size, bytes; the startup program follows it.
    header_size: usize,
    /// ELF `e_machine` of the startup program.
    machine: u16,
    /// Entry point: the virtual address the IPL jumps to.
    startup_vaddr: u32,
    paddr_bias: u32,
    /// Physical address of the image, from the header.
    image_paddr: u32,
    /// Physical RAM address the startup header and program are copied to.
    ram_paddr: u32,
    /// RAM the image occupies, bytes.
    ram_size: u32,
    /// Header, startup program and startup trailer, bytes.
    startup_size: usize,
    /// Header to the end of the image trailer, bytes.
    stored_size: usize,
    /// Size of the decoded image filesystem, bytes.
    imagefs_size: usize,
    /// `preboot_size` as stored.
    preboot_size: usize,
    /// File offset of the end of the startup trailer.
    startup_end: usize,
    /// File offset of the end of the image trailer.
    stored_end: usize,
    /// The startup trailer checksum.
    startup_checksum: u32,
    /// The image trailer checksum of the stored region.
    stored_checksum: u32,
}

impl StartupHeader {
    fn compression(&self) -> u8 {
        self.flags1 & STARTUP_HDR_FLAGS1_COMPRESS_MASK
    }
}

/// Parse a bootable image whose startup header is at `header_offset`.
pub(super) fn parse(data: &[u8], header_offset: usize) -> Result<Container<'_>> {
    let h = read_header(data, header_offset)?;
    verify_checksums(data, &h)?;
    let layout = Layout::Bootable { header_offset };
    let mut c = Container::new(FileFormat::QnxIfs, layout.label(), KEY_PREFIX);
    c.consumed = h.stored_end;
    c.notes.push(header_note(&h));
    c.target = machine_target(h.machine, h.le, &mut c.notes);
    c.notes.push(format!(
        "Startup trailer checksum verified ({} from 0x{:X}); image trailer checksum verified ({} from 0x{:X})",
        size_text(h.startup_size),
        h.offset,
        size_text(h.stored_size - h.startup_size),
        h.startup_end
    ));
    push_metadata(&mut c, &h);
    push_startup_program(&mut c, data, &h);
    push_boot_prefix(&mut c, data, &h);
    match h.compression() {
        STARTUP_HDR_FLAGS1_COMPRESS_NONE => stored_image(&mut c, data, &h)?,
        STARTUP_HDR_FLAGS1_COMPRESS_ZLIB => decoded_image(&mut c, data, &h, Codec::Gzip),
        STARTUP_HDR_FLAGS1_COMPRESS_LZO => decoded_image(&mut c, data, &h, Codec::Lzo1x),
        _ => ucl_image(&mut c, data, &h),
    }
    if let Some(note) = trailing_note(data, h.stored_end) {
        c.notes.push(note);
    }
    Ok(c)
}

/// Read the startup header at `offset` and check that its sizes describe a
/// header, a startup trailer and an image trailer that fit the file.
fn read_header(data: &[u8], offset: usize) -> Result<StartupHeader> {
    let header = data
        .get(offset..)
        .and_then(|rest| rest.get(..STARTUP_HEADER_FIELDS))
        .ok_or_else(|| error(format!("Truncated startup header at 0x{offset:X}")))?;
    let le = signature_order(header, 0)
        .ok_or_else(|| error(format!("Missing startup signature at 0x{offset:X}")))?;
    let flags1 = header[6];
    if (flags1 & STARTUP_HDR_FLAGS1_BIGENDIAN == 0) != le {
        return Err(error(format!(
            "Invalid flags1 0x{flags1:02X} at 0x{:X}: the big-endian bit disagrees with the signature byte order",
            offset + 6
        )));
    }
    let compression = flags1 & STARTUP_HDR_FLAGS1_COMPRESS_MASK;
    if compression > STARTUP_HDR_FLAGS1_COMPRESS_UCL {
        return Err(error(format!(
            "Unsupported compression 0x{compression:02X} in flags1 at 0x{:X}",
            offset + 6
        )));
    }
    let header_size = usize::from(u16_at(header, 0x08, le)?);
    let startup_size = to_usize(u32_at(header, 0x20, le)?);
    let stored_size = to_usize(u32_at(header, 0x24, le)?);
    let preboot_size = usize::from(u16_at(header, PREBOOT_SIZE_OFFSET, le)?);
    // Detection finds a prefixed header only through its own preboot_size;
    // a header at offset 0 may come from an image whose prefix was removed.
    if offset != 0 && preboot_size != offset {
        return Err(error(format!(
            "Invalid preboot_size 0x{preboot_size:X} at 0x{:X} for a header at 0x{offset:X}",
            offset + PREBOOT_SIZE_OFFSET
        )));
    }
    if header_size < STARTUP_HEADER_FIELDS {
        return Err(error(format!(
            "Invalid header_size 0x{header_size:X} at 0x{:X}",
            offset + 0x08
        )));
    }
    let holds_header_and_trailer = header_size
        .checked_add(TRAILER_SIZE)
        .is_some_and(|min| startup_size >= min);
    if startup_size % 4 != 0 || !holds_header_and_trailer {
        return Err(error(format!(
            "Invalid startup_size 0x{startup_size:X} at 0x{:X} (header_size 0x{header_size:X})",
            offset + 0x20
        )));
    }
    let holds_image_trailer = startup_size
        .checked_add(TRAILER_SIZE)
        .is_some_and(|min| stored_size >= min);
    if stored_size % 4 != 0 || !holds_image_trailer {
        return Err(error(format!(
            "Invalid stored_size 0x{stored_size:X} at 0x{:X} (startup_size 0x{startup_size:X})",
            offset + 0x24
        )));
    }
    let startup_end = offset
        .checked_add(startup_size)
        .ok_or_else(|| error("File range overflow"))?;
    let stored_end = offset
        .checked_add(stored_size)
        .ok_or_else(|| error("File range overflow"))?;
    if stored_end > data.len() {
        return Err(error(format!(
            "Truncated image: stored_size {stored_size} B from 0x{offset:X} ends at 0x{stored_end:X}, file has {} B",
            data.len()
        )));
    }
    Ok(StartupHeader {
        offset,
        le,
        version: u16_at(header, 0x04, le)?,
        flags1,
        header_size,
        machine: u16_at(header, 0x0a, le)?,
        startup_vaddr: u32_at(header, 0x0c, le)?,
        paddr_bias: u32_at(header, 0x10, le)?,
        image_paddr: u32_at(header, 0x14, le)?,
        ram_paddr: u32_at(header, 0x18, le)?,
        ram_size: u32_at(header, 0x1c, le)?,
        startup_size,
        stored_size,
        imagefs_size: to_usize(u32_at(header, 0x2c, le)?),
        preboot_size,
        startup_end,
        stored_end,
        startup_checksum: u32_at(data, startup_end - TRAILER_SIZE, le)?,
        stored_checksum: u32_at(data, stored_end - TRAILER_SIZE, le)?,
    })
}

/// The startup region (header to startup trailer) and the stored image
/// region (startup trailer to image trailer) must each sum to zero, as
/// mkifs writes them and the IPL checks them (`sys/startup.h` layout notes:
/// `checksum(image_paddr, startup_size)`, `checksum(image_paddr +
/// startup_size, stored_size - startup_size)`).
fn verify_checksums(data: &[u8], h: &StartupHeader) -> Result<()> {
    if !has_zero_word_sum(&data[h.offset..h.startup_end], h.le) {
        return Err(error(format!(
            "Invalid startup trailer checksum at 0x{:X}",
            h.startup_end - TRAILER_SIZE
        )));
    }
    if !has_zero_word_sum(&data[h.startup_end..h.stored_end], h.le) {
        return Err(error(format!(
            "Invalid image trailer checksum at 0x{:X}",
            h.stored_end - TRAILER_SIZE
        )));
    }
    Ok(())
}

/// "Startup header at 0x...: version, byte order, mode; compression".
fn header_note(h: &StartupHeader) -> String {
    let mode = if h.flags1 & STARTUP_HDR_FLAGS1_VIRTUAL != 0 {
        "virtual (MMU enabled)"
    } else {
        "physical"
    };
    let compression = match h.compression() {
        STARTUP_HDR_FLAGS1_COMPRESS_NONE => "uncompressed image filesystem",
        STARTUP_HDR_FLAGS1_COMPRESS_ZLIB => "gzip-compressed image filesystem (ZLIB)",
        STARTUP_HDR_FLAGS1_COMPRESS_LZO => "LZO-compressed image filesystem",
        _ => "UCL-compressed image filesystem",
    };
    let mut parts = vec![format!(
        "Startup header at 0x{:X}: version {}, {}, {mode}",
        h.offset,
        h.version,
        byte_order_name(h.le)
    )];
    parts.push(compression.to_string());
    if h.header_size != STARTUP_HEADER_SIZE {
        parts.push(format!("header_size 0x{:X}", h.header_size));
    }
    if h.flags1 & STARTUP_HDR_FLAGS1_UNDEFINED != 0 {
        parts.push(format!(
            "undefined flags1 bits 0x{:02X}",
            h.flags1 & STARTUP_HDR_FLAGS1_UNDEFINED
        ));
    }
    if h.offset == 0 && h.preboot_size != 0 {
        parts.push(format!(
            "preboot_size 0x{:X} names a boot prefix that this file does not hold",
            h.preboot_size
        ));
    }
    parts.join("; ")
}

/// The architecture the `machine` field names. The field is an ELF
/// `e_machine` value without the ELF class, so a machine whose ISA the
/// class decides (MIPS, RISC-V, S/390) names no target.
fn machine_target(machine: u16, le: bool, notes: &mut Vec<String>) -> Option<Target> {
    if machine == EM_NONE {
        notes.push(
            "Startup header names no machine (EM_NONE): the image has no startup program"
                .to_string(),
        );
        return None;
    }
    let (isa, bits) = e_machine_to_isa(machine, elf::class::ELFCLASS32);
    let (isa64, bits64) = e_machine_to_isa(machine, elf::class::ELFCLASS64);
    if matches!(isa, Isa::Unknown(_)) {
        notes.push(format!(
            "Startup header machine {machine} (ELF e_machine) names no ISA the classifier models"
        ));
        return None;
    }
    if (isa, bits) != (isa64, bits64) {
        notes.push(format!(
            "Startup header machine {machine} (ELF e_machine) is {} or {}; the ELF class that decides between them is not recorded",
            isa.name(),
            isa64.name()
        ));
        return None;
    }
    notes.push(format!(
        "Startup program machine {machine} (ELF e_machine): {}",
        isa.name()
    ));
    Some(Target {
        isa,
        bits,
        endianness: code_byte_order(isa, le),
    })
}

/// The instruction byte order of `isa` in an image whose header byte order
/// is `le`. `AArch64` instructions are little-endian in either data order; a
/// big-endian 32-bit Arm image may hold BE8 (little-endian) or BE32
/// instructions, which the header does not say.
fn code_byte_order(isa: Isa, le: bool) -> Option<Endianness> {
    match (isa, le) {
        (Isa::AArch64, _) | (_, true) => Some(Endianness::Little),
        (Isa::Arm, false) => None,
        (_, false) => Some(Endianness::Big),
    }
}

fn push_metadata(c: &mut Container<'_>, h: &StartupHeader) {
    c.push_metadata(
        "qnx_header_offset",
        "Startup header offset (B)",
        h.offset as u64,
    );
    c.push_metadata(
        "qnx_startup_version",
        "Startup header version",
        u64::from(h.version),
    );
    c.push_metadata(
        "qnx_flags1",
        "flags1",
        MetadataValue::Hex(u32::from(h.flags1)),
    );
    c.push_metadata("qnx_machine", "ELF machine", u64::from(h.machine));
    c.push_metadata(
        "qnx_startup_vaddr",
        "Startup entry (startup_vaddr)",
        MetadataValue::Address(u64::from(h.startup_vaddr)),
    );
    c.push_metadata(
        "qnx_image_paddr",
        "Image physical address (image_paddr)",
        MetadataValue::Address(u64::from(h.image_paddr)),
    );
    c.push_metadata(
        "qnx_ram_paddr",
        "RAM physical address (ram_paddr)",
        MetadataValue::Address(u64::from(h.ram_paddr)),
    );
    c.push_metadata("qnx_ram_size", "RAM size (B)", u64::from(h.ram_size));
    c.push_metadata(
        "qnx_paddr_bias",
        "paddr_bias",
        MetadataValue::Hex(h.paddr_bias),
    );
    c.push_metadata(
        "qnx_startup_size",
        "Startup size (B)",
        h.startup_size as u64,
    );
    c.push_metadata("qnx_stored_size", "Stored size (B)", h.stored_size as u64);
    c.push_metadata(
        "qnx_imagefs_size",
        "Image filesystem size (B)",
        h.imagefs_size as u64,
    );
    c.push_metadata(
        "qnx_startup_checksum",
        "Startup trailer checksum (verified)",
        MetadataValue::Hex(h.startup_checksum),
    );
    if h.compression() != STARTUP_HDR_FLAGS1_COMPRESS_NONE {
        c.push_metadata(
            "qnx_compressed_checksum",
            "Compressed image trailer checksum (verified)",
            MetadataValue::Hex(h.stored_checksum),
        );
    }
}

/// The startup program between the header and the startup trailer, as a
/// load section at its RAM address. Its bytes are raw segments (mkifs
/// `copy_elf` writes no ELF header for startup), so they go to the code
/// model under the machine's target.
fn push_startup_program<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader) {
    let start = h.offset + h.header_size;
    let code = &data[start..h.startup_end - TRAILER_SIZE];
    if code.is_empty() {
        return;
    }
    c.sections.push(Section {
        label: "Startup program".to_string(),
        address: u64::from(h.ram_paddr) + h.header_size as u64,
        offset: start,
        stored_size: code.len(),
        data: Cow::Borrowed(code),
        transform: None,
    });
    if h.machine != EM_NONE {
        c.entry = Some(u64::from(h.startup_vaddr));
    }
    c.notes.push(format!(
        "Startup program: {} at 0x{start:X}, loaded at physical 0x{:X}; entry startup_vaddr 0x{:X} (virtual byte address)",
        size_text(code.len()),
        u64::from(h.ram_paddr) + h.header_size as u64,
        h.startup_vaddr
    ));
}

/// The boot prefix before the header: code that puts the processor into
/// the state startup expects (on an x86 BIOS boot, real-mode code that
/// switches to protected mode), or a zero-filled region that an image filter
/// overwrites (mkifs "Boot prefix"). The prefix runs on the processor that
/// then runs startup, so it carries the machine's target; it is raw code,
/// never a nested container.
fn push_boot_prefix<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader) {
    if h.offset == 0 {
        return;
    }
    let prefix = &data[..h.offset];
    if is_padding(prefix) {
        c.notes.push(format!(
            "Boot prefix: {} of fill before the startup header",
            size_text(prefix.len())
        ));
        return;
    }
    c.notes.push(format!(
        "Boot prefix: {} of code before the startup header (preboot_size); it runs before startup on the same processor",
        size_text(prefix.len())
    ));
    let child = Child::stored("Boot prefix", 0, prefix).as_code();
    c.children.push(match c.target {
        Some(target) => child.with_target(target),
        None => child,
    });
}

/// An uncompressed image filesystem: it fills the stored region after the
/// startup trailer, and its members are slices of the file.
fn stored_image<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader) -> Result<()> {
    let image = &data[h.startup_end..h.stored_end];
    let fs = imagefs::read(image, h.startup_end)?;
    if fs.le != h.le {
        return Err(error(format!(
            "Invalid image header flags at 0x{:X}: the byte order disagrees with the startup header",
            h.startup_end + IMAGE_SIGNATURE.len()
        )));
    }
    if fs.image_size != image.len() || h.imagefs_size != fs.image_size {
        return Err(error(format!(
            "Invalid image sizes: stored_size - startup_size is 0x{:X}, imagefs_size 0x{:X}, image_size 0x{:X}",
            image.len(),
            h.imagefs_size,
            fs.image_size
        )));
    }
    imagefs::describe(
        c,
        &fs,
        &Source::Stored {
            image,
            offset: h.startup_end,
        },
    );
    Ok(())
}

/// A gzip- or LZO-compressed image filesystem. One that does not decode,
/// or whose decoded bytes are not a valid image filesystem, is kept as an
/// opaque component with a note, so the startup header's evidence still
/// reports.
fn decoded_image<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader, codec: Codec) {
    let stream = &data[h.startup_end..h.stored_end - TRAILER_SIZE];
    let DecodedImage { image, blocks } = match decode(stream, h, codec) {
        Ok(decoded) => decoded,
        Err(e) => {
            let note = format!(
                "{}-compressed image filesystem does not decode ({e}); members not listed",
                codec.name()
            );
            push_opaque_image(c, data, h, note);
            return;
        }
    };
    let fs = match decoded_imagefs(&image, h) {
        Ok(fs) => fs,
        Err(e) => {
            let note = format!(
                "{}-decoded image filesystem is invalid ({e}; offsets are decoded positions); members not listed",
                codec.name()
            );
            push_opaque_image(c, data, h, note);
            return;
        }
    };
    let stored_size = h.stored_size - h.startup_size;
    let blocks = blocks.map_or(String::new(), |n| format!(" in {n} blocks"));
    c.notes.push(format!(
        "Image filesystem compressed with {}{blocks}: {} stored, {} decoded",
        codec.name(),
        size_text(stored_size),
        size_text(image.len())
    ));
    imagefs::describe(
        c,
        &fs,
        &Source::Decoded {
            image: &image,
            offset: h.startup_end,
            stored_size,
            transform: codec.name(),
        },
    );
}

/// Read the decoded image filesystem, which must fill the decoded bytes in
/// the startup header's byte order.
fn decoded_imagefs(image: &[u8], h: &StartupHeader) -> Result<imagefs::ImageFs> {
    let fs = imagefs::read(image, 0)?;
    if fs.le != h.le || fs.image_size != image.len() {
        return Err(error(
            "Invalid decoded image header: its byte order or image_size disagrees with the startup header",
        ));
    }
    Ok(fs)
}

/// Keep a compressed image filesystem that is not analyzed as one opaque
/// component, with `note` saying why.
fn push_opaque_image<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader, note: String) {
    c.notes.push(note);
    let stored = &data[h.startup_end..h.stored_end];
    c.children
        .push(Child::opaque(COMPRESSED_LABEL, h.startup_end, stored));
}

/// A compressed image filesystem after decoding.
struct DecodedImage {
    /// The decoded image filesystem, `imagefs_size` bytes.
    image: Vec<u8>,
    /// Number of blocks in a block stream; `None` for a gzip stream.
    blocks: Option<usize>,
}

/// Decode the compressed stream (padding included, trailer excluded) into
/// exactly `imagefs_size` bytes. Returns the bytes and, for block streams,
/// the number of blocks.
fn decode(stream: &[u8], h: &StartupHeader, codec: Codec) -> Result<DecodedImage> {
    if h.imagefs_size > MAX_PAYLOAD {
        return Err(error(format!(
            "imagefs_size {} exceeds the {} extraction limit",
            size_text(h.imagefs_size),
            size_text(MAX_PAYLOAD)
        )));
    }
    let (image, blocks) = if codec == Codec::Gzip {
        let decoded = compressed::decode_limited(Codec::Gzip, stream, h.imagefs_size)?;
        let end = decoded.consumed.unwrap_or(stream.len());
        expect_stream_end(stream, end, h.startup_end, codec.name())?;
        (decoded.data, None)
    } else {
        let mut image = Vec::new();
        let walk = walk_blocks(stream, h.startup_end, |at, block| {
            let decoded = compressed::decode_limited(codec, block, COMPRESSED_BLOCK_SIZE)?;
            if decoded.consumed != Some(block.len()) {
                return Err(error(format!(
                    "Invalid {} block at 0x{at:X}: the stream ends before its {} B",
                    codec.name(),
                    block.len()
                )));
            }
            if image.len() + decoded.data.len() > h.imagefs_size {
                return Err(error(format!(
                    "Decoded image filesystem exceeds imagefs_size {} B",
                    h.imagefs_size
                )));
            }
            image.extend_from_slice(&decoded.data);
            Ok(())
        })?;
        expect_stream_end(stream, walk.end, h.startup_end, codec.name())?;
        (image, Some(walk.blocks))
    };
    if image.len() != h.imagefs_size {
        return Err(error(format!(
            "Decoded image filesystem is {} B; imagefs_size is {} B",
            image.len(),
            h.imagefs_size
        )));
    }
    Ok(DecodedImage { image, blocks })
}

/// A UCL-compressed image filesystem: its block framing is checked, but the
/// crate has no UCL decoder, so it stays opaque and its members unlisted.
fn ucl_image<'a>(c: &mut Container<'a>, data: &'a [u8], h: &StartupHeader) {
    let stream = &data[h.startup_end..h.stored_end - TRAILER_SIZE];
    let framing = walk_blocks(stream, h.startup_end, |_, _| Ok(())).and_then(|walk| {
        expect_stream_end(stream, walk.end, h.startup_end, "UCL")?;
        Ok(walk.blocks)
    });
    let framing = match framing {
        Ok(blocks) => format!("{blocks} blocks"),
        Err(e) => format!("block framing invalid: {e}"),
    };
    let note = format!(
        "Image filesystem compressed with UCL NRV2B ({framing}, {} stored; imagefs_size {}); no UCL decoder, so it is opaque and its members are not listed",
        size_text(h.stored_size - h.startup_size),
        size_text(h.imagefs_size)
    );
    push_opaque_image(c, data, h, note);
}

/// Where a block stream ends and how many blocks it holds.
struct BlockWalk {
    /// Offset in the stream after the zero-length terminator.
    end: usize,
    blocks: usize,
}

/// Walk an LZO or UCL block stream, passing each block and its file offset
/// to `visit`: a big-endian 16-bit stored length, then that many bytes; a
/// zero length ends the stream. Every block takes at least three bytes, so
/// the walk is bounded by the stream size. `base` is the stream's file
/// offset for messages.
fn walk_blocks(
    stream: &[u8],
    base: usize,
    mut visit: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<BlockWalk> {
    let mut pos = 0;
    let mut blocks = 0;
    loop {
        let length = be_u16(stream, pos).map_err(|_| {
            error(format!(
                "Missing compressed block terminator before 0x{:X}",
                base + stream.len()
            ))
        })?;
        let start = pos + 2;
        let length = usize::from(length);
        if length == 0 {
            return Ok(BlockWalk { end: start, blocks });
        }
        let block = stream.get(start..start + length).ok_or_else(|| {
            error(format!(
                "Truncated compressed block at 0x{:X}: {length} B declared",
                base + pos
            ))
        })?;
        visit(base + start, block)?;
        blocks += 1;
        pos = start + length;
    }
}

/// Only zero padding to a multiple of four bytes may follow the `codec`
/// stream that ends at `end` (mkifs `padfile` before the image trailer).
fn expect_stream_end(stream: &[u8], end: usize, base: usize, codec: &str) -> Result<()> {
    let padding = stream.get(end..).unwrap_or_default();
    let aligned = round_up4(end) == Some(stream.len());
    if !aligned || padding.iter().any(|b| *b != 0) {
        return Err(error(format!(
            "Invalid {codec} stream end at 0x{:X}: {} B before the image trailer are not alignment padding",
            base + end,
            padding.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_byte_order_follows_the_header_except_where_the_isa_fixes_it() {
        assert_eq!(
            code_byte_order(Isa::AArch64, false),
            Some(Endianness::Little)
        );
        assert_eq!(code_byte_order(Isa::Arm, false), None);
        assert_eq!(code_byte_order(Isa::Arm, true), Some(Endianness::Little));
        assert_eq!(code_byte_order(Isa::Ppc, false), Some(Endianness::Big));
    }

    #[test]
    fn machines_whose_width_the_elf_class_decides_name_no_target() {
        let mut notes = Vec::new();
        assert!(machine_target(8, true, &mut notes).is_none());
        assert!(
            notes[0].contains("is MIPS (32-bit) or MIPS (64-bit)"),
            "{notes:?}"
        );
        let target = machine_target(0x28, true, &mut notes).unwrap();
        assert_eq!(target.isa, Isa::Arm);
        assert!(machine_target(EM_NONE, true, &mut notes).is_none());
        assert!(machine_target(0x05, true, &mut notes).is_none());
    }

    #[test]
    fn block_walks_stop_at_the_terminator_and_reject_overruns() {
        let stream = [0, 2, 0xaa, 0xbb, 0, 1, 0xcc, 0, 0, 0];
        let mut seen = Vec::new();
        let walk = walk_blocks(&stream, 0x100, |at, block| {
            seen.push((at, block.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(walk.end, 9);
        assert_eq!(walk.blocks, 2);
        assert_eq!(seen, vec![(0x102, vec![0xaa, 0xbb]), (0x106, vec![0xcc])]);
        assert!(walk_blocks(&[0, 9, 1], 0, |_, _| Ok(())).is_err());
        assert!(walk_blocks(&[0, 1, 1], 0, |_, _| Ok(())).is_err());
        assert!(expect_stream_end(&stream, 9, 0, "UCL").is_err());
        assert!(expect_stream_end(&stream[..8], 7, 0, "UCL").is_ok());
    }
}
