//! Legacy Qualcomm MBN headers: the 40-byte version 3 header (no magic)
//! and the 80-byte SBL header (`FLASH_CODE_WORD`, `MAGIC_NUM`), including
//! the NAND preamble that may precede an SBL header. Also SBL ELF images
//! after a NAND preamble, with the virtual block cookies of NAND images
//! removed.
//!
//! Source: coreboot `util/qualcomm/mbn_tools.py` (`Boot_Hdr`, `Sbl_Hdr`,
//! `ImageType`, `image_preamble`, `insert_SBL1_magicCookie`), `mbncat.py`
//! and `ipqheader.py`. Modern Qualcomm images are ELF files whose hash
//! segment holds these headers; the ELF parser classifies them by
//! `e_machine`, and an ELF image after a NAND preamble becomes a child
//! that is classified the same way.
//!
//! Code, signature and certificate chain are stored back to back: the
//! writer sets `sig_ptr = image_dest_ptr + code_size` and `cert_chain_ptr
//! = sig_ptr + sig_size`.

use super::*;
use crate::formats::{elf, MAX_PAYLOAD};

/// 40-byte header (10 × u32): image ID (0), header version (4), image
/// source (8), destination pointer (0x0C), image size (0x10), code size
/// (0x14), signature pointer and size (0x18, 0x1C), certificate chain
/// pointer and size (0x20, 0x24). Code follows at 0x28.
const MBN_IMAGE_ID: usize = 0x00;
const MBN_VERSION: usize = 0x04;
const MBN_FIELDS: usize = 0x0c;
const MBN_HEADER_SIZE: usize = 0x28;

/// The only 40-byte header version whose pointer fields are documented
/// (`flash_parti_ver` 3); versions 5 and 6 reuse two words as sizes.
const MBN_VERSION_3: u32 = 3;

/// The image size is code, signature and certificate chain rounded up to
/// whole 4-byte words.
const IMAGE_SIZE_ALIGN: u64 = 4;

/// SBL header (20 × u32): codeword (0), magic (4), image ID (8), two
/// reserved words, image source (0x14: file offset of the code), then the
/// destination pointer and sizes at 0x18 in the same order as the 40-byte
/// header, root certificate selection (0x34) and count (0x38), booting
/// image configuration (0x3C) and four reserved words.
const SBL_CODEWORD: u32 = 0x844b_dcd1;
const SBL_MAGIC: u32 = 0x73d7_1034;
const SBL_IMAGE_ID: usize = 0x08;
const SBL_IMAGE_SRC: usize = 0x14;
const SBL_FIELDS: usize = 0x18;
const SBL_BOOTING_IMAGE_CONFIG: usize = 0x3c;
const SBL_HEADER_SIZE: usize = 80;

/// `booting_image_config` values: `SBL_AARCH64`, `SBL_AARCH32`, and the
/// initial value left when the build sets neither.
const SBL_AARCH64: u32 = 0xf;
const SBL_AARCH32: u32 = 0x0;
const SBL_CONFIG_UNSET: u32 = 0xffff_ffff;

/// NAND preamble pages start with the codeword, the magic and one of these
/// page-size autodetect magics (`AUTODETECT_PAGE_SIZE_MAGIC_NUM`, `..64`,
/// `..128`); the SBL header follows the preamble.
const AUTODETECT_MAGICS: [u32; 3] = [0x7d0b_435a, 0x7d0b_5436, 0x7d0b_6577];

/// The SBL header or ELF image after a preamble is searched for on
/// 512-byte boundaries up to this offset (a bound chosen here, not from
/// the source).
const MAX_PREAMBLE: usize = 1 << 20;
const PREAMBLE_STEP: usize = 512;

/// A virtual block cookie is `FLASH_CODE_WORD`, `MAGIC_NUM` and
/// `SBL_VIRTUAL_BLOCK_MAGIC_NUM`: `MAGIC_COOKIE_LENGTH` (12) bytes per
/// `VIRTUAL_BLOCK_SIZE` (128 KiB) block.
///
/// Where the cookies sit is an observation, not the generator's rule.
/// `insert_SBL1_magicCookie` appends a cookie after every 128 KiB of its
/// input, so its cookies drift 12 B further from the block boundaries
/// with each block. The NAND SBL ELF image examined on 2026-11-02 instead
/// has a cookie at every 128 KiB boundary of the file (counted from the
/// preamble), and its segments match their hash segment digests only
/// with those 12 bytes removed. Only that placement is implemented.
const VIRTUAL_BLOCK_MAGIC: u32 = 0xd48b_54c6;
const VIRTUAL_BLOCK_SIZE: usize = 128 << 10;
const COOKIE_SIZE: usize = 12;

/// The ELF identification magic (`EI_MAG0` to `EI_MAG3`).
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Child label and transform name for the ELF image after a preamble.
const ELF_LABEL: &str = "ELF image";
const VIRTUAL_BLOCKS_TRANSFORM: &str = "SBL virtual blocks";

/// `ImageType` values and names (`mibib.h` order).
const IMAGE_TYPES: &[(u32, &str)] = &[
    (1, "OEM_SBL"),
    (2, "AMSS"),
    (3, "QCSBL"),
    (4, "HASH"),
    (5, "APPSBL"),
    (6, "APPS"),
    (7, "HOSTDL"),
    (8, "DSP1"),
    (9, "FSBL"),
    (10, "DBL"),
    (11, "OSBL"),
    (12, "DSP2"),
    (13, "EHOSTDL"),
    (14, "NANDPRG"),
    (15, "NORPRG"),
    (16, "RAMFS1"),
    (17, "RAMFS2"),
    (18, "ADSP_Q5"),
    (19, "APPS_KERNEL"),
    (20, "BACKUP_RAMFS"),
    (21, "SBL1"),
    (22, "SBL2"),
    (23, "RPM"),
    (24, "SBL3"),
    (25, "TZ"),
    (32, "PSI"),
];

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    if !has_sbl_magic(data, 0) {
        return None;
    }
    // A preamble followed by neither payload stays an SBL, whose parse
    // reports the missing header.
    let payload = preamble_magic(data).and_then(|_| payload_after_preamble(data));
    let layout = match payload {
        Some(Payload::Elf(_)) => Layout::QualcommSblElf,
        Some(Payload::SblHeader(_)) | None => Layout::QualcommSbl,
    };
    Some(layout)
}

pub(super) fn detect_weak(data: &[u8]) -> Option<Layout> {
    mbn_image(data).is_ok().then_some(Layout::QualcommMbn)
}

fn image_type_name(image_id: u32) -> Option<&'static str> {
    IMAGE_TYPES
        .iter()
        .find(|(id, _)| *id == image_id)
        .map(|(_, name)| *name)
}

/// The six words both headers share, from the destination pointer on.
struct Fields {
    /// Target address of the code.
    dest_ptr: u32,
    image_size: u32,
    code_size: u32,
    sig_ptr: u32,
    sig_size: u32,
    cert_chain_ptr: u32,
    cert_chain_size: u32,
}

impl Fields {
    /// Destination pointer (0), image size (4), code size (8), signature
    /// pointer and size (0x0C, 0x10), certificate chain pointer and size
    /// (0x14, 0x18), relative to `at`.
    fn read(header: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            dest_ptr: le_u32(header, at)?,
            image_size: le_u32(header, at + 0x04)?,
            code_size: le_u32(header, at + 0x08)?,
            sig_ptr: le_u32(header, at + 0x0c)?,
            sig_size: le_u32(header, at + 0x10)?,
            cert_chain_ptr: le_u32(header, at + 0x14)?,
            cert_chain_size: le_u32(header, at + 0x18)?,
        })
    }

    /// Code, signature and certificate chain in bytes.
    fn stored_size(&self) -> u64 {
        u64::from(self.code_size) + u64::from(self.sig_size) + u64::from(self.cert_chain_size)
    }

    /// Whether the pointers place the signature and the certificate chain
    /// right after the code, as the writer does.
    fn is_contiguous(&self) -> bool {
        let sig_ptr = u64::from(self.dest_ptr) + u64::from(self.code_size);
        let cert_ptr = sig_ptr + u64::from(self.sig_size);
        u64::from(self.sig_ptr) == sig_ptr && u64::from(self.cert_chain_ptr) == cert_ptr
    }
}

/// A validated 40-byte header image: fields and the end of the stored
/// image.
struct MbnImage {
    image_id: u32,
    fields: Fields,
    end: usize,
}

/// Validate a 40-byte version 3 header against the file. With no magic,
/// every size and pointer must agree: a known image ID, nonzero code, an
/// image size equal to code, signature and certificate chain rounded up
/// to 4 bytes, contiguous pointers, the whole image present and only
/// erased flash after it.
fn mbn_image(data: &[u8]) -> Result<MbnImage> {
    let header = range(data, 0, MBN_HEADER_SIZE, "MBN header")?;
    let version = le_u32(header, MBN_VERSION)?;
    if version != MBN_VERSION_3 {
        return Err(error(format!("Unsupported MBN header version {version}")));
    }
    let image_id = le_u32(header, MBN_IMAGE_ID)?;
    if image_type_name(image_id).is_none() {
        return Err(error(format!("Unknown MBN image ID {image_id}")));
    }
    let fields = Fields::read(header, MBN_FIELDS)?;
    let stored = fields.stored_size();
    let rounded = (stored + IMAGE_SIZE_ALIGN - 1) / IMAGE_SIZE_ALIGN * IMAGE_SIZE_ALIGN;
    if fields.code_size == 0 || u64::from(fields.image_size) != rounded {
        return Err(error(format!(
            "Invalid MBN sizes: image {} B, code {} B, signature {} B, certificates {} B",
            fields.image_size, fields.code_size, fields.sig_size, fields.cert_chain_size
        )));
    }
    if !fields.is_contiguous() {
        return Err(error(
            "Invalid MBN pointers: the signature and certificate chain do not follow the code",
        ));
    }
    let stored = usize::try_from(stored).map_err(|_| error("Invalid MBN image size"))?;
    let end = MBN_HEADER_SIZE
        .checked_add(stored)
        .ok_or_else(|| error("Invalid MBN image size"))?;
    range(data, MBN_HEADER_SIZE, stored, "MBN image")?;
    if !is_padding(&data[end..]) {
        return Err(error(format!(
            "Unexpected {} after the MBN image at 0x{end:X}",
            size_text(data.len() - end)
        )));
    }
    Ok(MbnImage {
        image_id,
        fields,
        end,
    })
}

/// Code, signature and certificate chain stored from `code_offset` as
/// children, with notes and metadata. The signature and certificates are
/// listed only when the pointers place them after the code.
fn push_image<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    code_offset: usize,
    fields: &Fields,
    target: Option<Target>,
) -> Result<usize> {
    let code_size = fields.code_size as usize;
    let code = range(data, code_offset, code_size, "MBN code")?;
    let mut code_child = Child::stored("Code", code_offset, code);
    if let Some(target) = target {
        code_child = code_child.with_target(target);
    }
    c.children.push(code_child);
    c.push_metadata(
        "qualcomm_load_address",
        "Destination address",
        format!("0x{:08X}", fields.dest_ptr),
    );
    c.push_metadata(
        "qualcomm_code_size",
        "Code size (B)",
        u64::from(fields.code_size),
    );
    c.push_metadata(
        "qualcomm_header_image_size",
        "Header image size (B)",
        u64::from(fields.image_size),
    );
    let mut end = code_offset + code_size;
    let has_trailer = fields.sig_size > 0 || fields.cert_chain_size > 0;
    if !has_trailer {
        c.notes.push("No signature or certificate chain".into());
        return Ok(end);
    }
    c.notes.push(format!(
        "Signature {} B and certificate chain {} B; not verified",
        fields.sig_size, fields.cert_chain_size
    ));
    if !fields.is_contiguous() {
        c.notes.push(
            "The signature and certificate pointers do not follow the code; their file positions are not established"
                .into(),
        );
        return Ok(end);
    }
    let parts = [
        ("Signature", fields.sig_size as usize),
        ("Certificate chain", fields.cert_chain_size as usize),
    ];
    for (label, size) in parts {
        if size == 0 {
            continue;
        }
        let bytes = range(data, end, size, &format!("MBN {}", label.to_lowercase()))?;
        c.children.push(Child::opaque(label, end, bytes));
        end += size;
    }
    Ok(end)
}

/// The image ID as a note and metadata. It names a boot role, never an
/// instruction set.
fn describe_image_id(c: &mut Container<'_>, image_id: u32) {
    let name = image_type_name(image_id).unwrap_or("unknown");
    c.notes.push(format!(
        "Image ID {image_id} ({name}) names a boot role, not an instruction set"
    ));
    c.push_metadata(
        "qualcomm_image_id",
        "Image ID",
        format!("{image_id} ({name})"),
    );
}

pub(super) fn parse_mbn(data: &[u8]) -> Result<Container<'_>> {
    let image = mbn_image(data)?;
    let mut c = Container::new(
        FileFormat::QualcommMbn,
        Layout::QualcommMbn.label(),
        "qualcomm",
    );
    c.notes.push(
        "Qualcomm MBN 40-byte header, version 3; recognized from consistent sizes and pointers (no magic)"
            .into(),
    );
    describe_image_id(&mut c, image.image_id);
    push_image(&mut c, data, MBN_HEADER_SIZE, &image.fields, None)?;
    c.consumed = image.end;
    Ok(c)
}

/// Whether the codeword and magic start at `at`. They open an SBL header,
/// a NAND preamble page and a virtual block cookie alike; the third word
/// tells them apart.
fn has_sbl_magic(data: &[u8], at: usize) -> bool {
    le_u32(data, at).ok() == Some(SBL_CODEWORD) && le_u32(data, at + 4).ok() == Some(SBL_MAGIC)
}

/// The page-size autodetect magic when `data` starts with a NAND preamble
/// page.
fn preamble_magic(data: &[u8]) -> Option<u32> {
    le_u32(data, SBL_IMAGE_ID)
        .ok()
        .filter(|third| AUTODETECT_MAGICS.contains(third))
}

/// Whether a virtual block cookie starts at `at`.
fn is_cookie(data: &[u8], at: usize) -> bool {
    has_sbl_magic(data, at) && le_u32(data, at + 8).ok() == Some(VIRTUAL_BLOCK_MAGIC)
}

/// Whether an SBL header (codeword and magic) starts at `at`. A NAND
/// preamble page and a virtual block cookie start the same way and are
/// not headers: a cookie is followed by code, not header fields.
fn is_sbl_header(data: &[u8], at: usize) -> bool {
    let words = (le_u32(data, at), le_u32(data, at + 4), le_u32(data, at + 8));
    match words {
        (Ok(SBL_CODEWORD), Ok(SBL_MAGIC), Ok(third)) => {
            !AUTODETECT_MAGICS.contains(&third) && third != VIRTUAL_BLOCK_MAGIC
        }
        _ => false,
    }
}

/// What follows a NAND preamble, at its file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Payload {
    /// An 80-byte SBL header.
    SblHeader(usize),
    /// An ELF image.
    Elf(usize),
}

/// The first 512-byte boundary after a NAND preamble that holds an SBL
/// header or an ELF image.
fn payload_after_preamble(data: &[u8]) -> Option<Payload> {
    let limit = MAX_PREAMBLE.min(data.len());
    (PREAMBLE_STEP..limit)
        .step_by(PREAMBLE_STEP)
        .find_map(|at| payload_at(data, at))
}

/// The payload that starts at `at`, if any.
fn payload_at(data: &[u8], at: usize) -> Option<Payload> {
    if is_sbl_header(data, at) {
        Some(Payload::SblHeader(at))
    } else if data.get(at..)?.starts_with(ELF_MAGIC) {
        Some(Payload::Elf(at))
    } else {
        None
    }
}

/// The instruction set `booting_image_config` names, and its note.
fn booting_image_target(config: u32) -> IsaEvidence {
    match config {
        SBL_AARCH64 => IsaEvidence {
            target: Some(Target::new(Isa::AArch64, 64, Endianness::Little)),
            note: "booting_image_config 0xF: AArch64 SBL".into(),
        },
        SBL_AARCH32 => IsaEvidence {
            target: Some(Target::without_byte_order(Isa::Arm, 32)),
            note: "booting_image_config 0x0: AArch32 SBL".into(),
        },
        SBL_CONFIG_UNSET => IsaEvidence {
            target: None,
            note: "booting_image_config is unset; the header names no instruction set".into(),
        },
        other => IsaEvidence {
            target: None,
            note: format!(
                "booting_image_config 0x{other:X} is not a documented value; no instruction set claimed"
            ),
        },
    }
}

/// An image that starts with the SBL codeword and magic: an SBL header at
/// 0, or a NAND preamble followed by an SBL header or an ELF image.
pub(super) fn parse_sbl(data: &[u8]) -> Result<Container<'_>> {
    range(data, 0, SBL_HEADER_SIZE, "SBL header")?;
    if !has_sbl_magic(data, 0) {
        return Err(error("Missing SBL codeword and magic"));
    }
    // A cookie is followed by code, which must not be read as header
    // fields: such a file starts inside a NAND image.
    if is_cookie(data, 0) {
        return Err(error(
            "Invalid SBL header at 0x0: a virtual block cookie (third word 0xD48B54C6)",
        ));
    }
    let Some(autodetect) = preamble_magic(data) else {
        return parse_sbl_header(data, 0, Vec::new());
    };
    match payload_after_preamble(data) {
        Some(Payload::SblHeader(at)) => {
            let note = format!(
                "NAND preamble (autodetect magic 0x{autodetect:08X}); SBL header at 0x{at:X}"
            );
            parse_sbl_header(data, at, vec![note])
        }
        Some(Payload::Elf(at)) => parse_preamble_elf(data, autodetect, at),
        None => Err(error(format!(
            "Missing SBL header or ELF image after the NAND preamble (searched {})",
            size_text(MAX_PREAMBLE.min(data.len()))
        ))),
    }
}

/// The 80-byte SBL header at `header_offset`, its code, signature and
/// certificate chain. `notes` describe the preamble before the header.
fn parse_sbl_header(
    data: &[u8],
    header_offset: usize,
    mut notes: Vec<String>,
) -> Result<Container<'_>> {
    let header = range(data, header_offset, SBL_HEADER_SIZE, "SBL header")?;
    let image_id = le_u32(header, SBL_IMAGE_ID)?;
    let image_src = le_size(header, SBL_IMAGE_SRC)?;
    let fields = Fields::read(header, SBL_FIELDS)?;
    // `image_src` is the file offset of the code; it is 80, plus the
    // preamble size when there is one.
    if image_src < header_offset + SBL_HEADER_SIZE {
        return Err(error(format!(
            "Invalid SBL image_src 0x{image_src:X}: inside the header at 0x{header_offset:X}"
        )));
    }
    if fields.code_size == 0 || fields.image_size < fields.code_size {
        return Err(error(format!(
            "Invalid SBL sizes: image {} B, code {} B",
            fields.image_size, fields.code_size
        )));
    }
    let evidence = booting_image_target(le_u32(header, SBL_BOOTING_IMAGE_CONFIG)?);

    let mut c = Container::new(
        FileFormat::QualcommMbn,
        Layout::QualcommSbl.label(),
        "qualcomm",
    );
    c.target = evidence.target;
    c.notes
        .push("Qualcomm SBL MBN, 80-byte header (codeword 0x844BDCD1, magic 0x73D71034)".into());
    c.notes.append(&mut notes);
    c.notes.push(evidence.note);
    describe_image_id(&mut c, image_id);
    let end = push_image(&mut c, data, image_src, &fields, evidence.target)?;
    c.consumed = end;
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

/// Why a run of virtual block cookies ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunEnd {
    /// The file ends before the next block boundary's cookie.
    EndOfFile,
    /// The block boundary at this file offset holds no cookie.
    MissingCookie(usize),
    /// The run reached `MAX_PAYLOAD` bytes of the file.
    Limit,
}

/// The bytes from a file offset on with the virtual block cookies
/// removed.
struct VirtualBlocks<'a> {
    /// File offset of the first byte.
    start: usize,
    /// The bytes without cookies, up to `end`.
    stream: Cow<'a, [u8]>,
    /// File offsets of the removed cookies, ascending.
    cookies: Vec<usize>,
    /// File offset where `stream` ends.
    end: usize,
    /// Why the stream ends at `end`.
    run_end: RunEnd,
}

impl VirtualBlocks<'_> {
    /// The file offset just past the first `len` bytes of `stream`.
    fn file_end(&self, len: usize) -> usize {
        let mut offset = self.start + len;
        for &cookie in &self.cookies {
            if cookie >= offset {
                break;
            }
            offset += COOKIE_SIZE;
        }
        offset
    }
}

/// The bytes of `data` from `start` without their virtual block cookies.
/// Cookies sit at the 128 KiB boundaries of the file after `start`, and
/// the run ends at the first boundary without one or after `MAX_PAYLOAD`
/// bytes of the file. When the first boundary holds no cookie, the bytes
/// are taken as stored, to the end of the file.
fn virtual_blocks(data: &[u8], start: usize) -> VirtualBlocks<'_> {
    let limit = data.len().min(start.saturating_add(MAX_PAYLOAD));
    let mut cookies = Vec::new();
    // Boundaries stay within one block past `limit` (at most `data.len()`),
    // so these sums cannot overflow.
    let mut boundary = (start / VIRTUAL_BLOCK_SIZE + 1) * VIRTUAL_BLOCK_SIZE;
    let run_end = loop {
        if boundary + COOKIE_SIZE > limit {
            break if limit == data.len() {
                RunEnd::EndOfFile
            } else {
                RunEnd::Limit
            };
        }
        if !is_cookie(data, boundary) {
            break RunEnd::MissingCookie(boundary);
        }
        cookies.push(boundary);
        boundary += VIRTUAL_BLOCK_SIZE;
    };
    if cookies.is_empty() {
        return VirtualBlocks {
            start,
            stream: Cow::Borrowed(&data[start..]),
            cookies,
            end: data.len(),
            run_end: RunEnd::EndOfFile,
        };
    }
    let end = match run_end {
        RunEnd::MissingCookie(at) => at,
        RunEnd::EndOfFile | RunEnd::Limit => limit.min(boundary),
    };
    // Every cookie lies in `start..end` with its 12 bytes before `end`.
    let mut stream = Vec::with_capacity(end - start - COOKIE_SIZE * cookies.len());
    let mut piece = start;
    for &cookie in &cookies {
        stream.extend_from_slice(&data[piece..cookie]);
        piece = cookie + COOKIE_SIZE;
    }
    stream.extend_from_slice(&data[piece..end]);
    VirtualBlocks {
        start,
        stream: Cow::Owned(stream),
        cookies,
        end,
        run_end,
    }
}

/// The size of the ELF image at the start of `blocks`, given the extent
/// its headers declare, or why `blocks` does not hold all of it.
fn elf_size(blocks: &VirtualBlocks<'_>, extent: u64) -> Result<usize> {
    let available = blocks.stream.len();
    if let Some(size) = usize::try_from(extent)
        .ok()
        .filter(|&size| size <= available)
    {
        return Ok(size);
    }
    let start = blocks.start;
    let message = match blocks.run_end {
        RunEnd::MissingCookie(at) => format!(
            "Missing SBL virtual block cookie at 0x{at:X}: the ELF image at 0x{start:X} declares {extent} B"
        ),
        RunEnd::Limit => format!(
            "Unsupported ELF image of {extent} B at 0x{start:X}: larger than the {} extraction limit",
            size_text(MAX_PAYLOAD)
        ),
        RunEnd::EndOfFile => format!(
            "Truncated ELF image at 0x{start:X}: {extent} B declared, {available} B present"
        ),
    };
    Err(error(message))
}

/// A NAND preamble with page-size magic `autodetect`, followed by an ELF
/// image at `elf_at` (modern SBL builds). The ELF image is rebuilt without
/// its virtual block cookies and classified on its own; the preamble names
/// no instruction set.
fn parse_preamble_elf(data: &[u8], autodetect: u32, elf_at: usize) -> Result<Container<'_>> {
    let blocks = virtual_blocks(data, elf_at);
    let extent = elf::file_extent(&blocks.stream)
        .ok_or_else(|| error(format!("Invalid ELF header at 0x{elf_at:X}")))?;
    let size = elf_size(&blocks, extent)?;
    let elf_end = blocks.file_end(size);
    // Erased flash after the ELF image, up to the end of the cookie run,
    // belongs to the image together with its cookies.
    let consumed = if is_padding(&blocks.stream[size..]) {
        blocks.end
    } else {
        elf_end
    };
    let removed = blocks
        .cookies
        .iter()
        .filter(|&&cookie| cookie < consumed)
        .count();
    let in_elf = blocks
        .cookies
        .iter()
        .filter(|&&cookie| cookie < elf_end)
        .count();

    let mut c = Container::new(
        FileFormat::QualcommMbn,
        Layout::QualcommSblElf.label(),
        "qualcomm",
    );
    c.notes.push(
        "Qualcomm SBL ELF image after a NAND preamble (codeword 0x844BDCD1, magic 0x73D71034)"
            .into(),
    );
    c.notes.push(format!(
        "NAND preamble (autodetect magic 0x{autodetect:08X}); ELF image at 0x{elf_at:X}"
    ));
    c.notes.push(match removed {
        0 => "No virtual block cookies".into(),
        1 => "1 virtual block cookie (third word 0xD48B54C6) removed at a 128 KiB file boundary"
            .into(),
        n => format!(
            "{n} virtual block cookies (third word 0xD48B54C6) removed at 128 KiB file boundaries"
        ),
    });
    c.notes
        .push("Segment hashes, signature and certificate chain are not verified".into());
    c.push_metadata(
        "qualcomm_elf_offset",
        "ELF image offset",
        format!("0x{elf_at:X}"),
    );
    c.push_metadata("qualcomm_elf_size", "ELF image size (B)", size as u64);
    c.push_metadata(
        "qualcomm_virtual_block_cookies",
        "Virtual block cookies",
        removed as u64,
    );
    let child = if in_elf == 0 {
        Child::stored(ELF_LABEL, elf_at, &data[elf_at..elf_end])
    } else {
        let mut elf_image = blocks.stream.into_owned();
        elf_image.truncate(size);
        Child::decoded(
            ELF_LABEL,
            elf_at,
            elf_end - elf_at,
            Cow::Owned(elf_image),
            VIRTUAL_BLOCKS_TRANSFORM,
        )
    };
    c.children.push(child);
    c.consumed = consumed;
    if let Some(member) = trailing_member(data, consumed, &mut c.notes) {
        c.children.push(member);
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booting_image_config_names_only_documented_values() {
        assert_eq!(
            booting_image_target(SBL_AARCH64).target,
            Some(Target::new(Isa::AArch64, 64, Endianness::Little))
        );
        assert_eq!(
            booting_image_target(SBL_AARCH32).target,
            Some(Target::without_byte_order(Isa::Arm, 32))
        );
        assert!(booting_image_target(SBL_CONFIG_UNSET).target.is_none());
        assert!(booting_image_target(7).target.is_none());
    }

    #[test]
    fn pointers_must_place_signature_and_certificates_after_the_code() {
        let mut fields = Fields {
            dest_ptr: 0x4000_0000,
            image_size: 0x110,
            code_size: 0x10,
            sig_ptr: 0x4000_0010,
            sig_size: 0x100,
            cert_chain_ptr: 0x4000_0110,
            cert_chain_size: 0,
        };
        assert!(fields.is_contiguous());
        fields.cert_chain_ptr += 4;
        assert!(!fields.is_contiguous());
    }

    /// Codeword, magic and `third` as 12 little-endian bytes.
    fn three_words(third: u32) -> Vec<u8> {
        [SBL_CODEWORD, SBL_MAGIC, third]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// `blocks` 128 KiB blocks of a byte pattern that is never padding,
    /// with a cookie at the start of each block in `cookie_blocks`.
    fn blocks_with_cookies(blocks: usize, cookie_blocks: &[usize]) -> Vec<u8> {
        let mut data: Vec<u8> = (1..=251)
            .cycle()
            .take(blocks * VIRTUAL_BLOCK_SIZE)
            .collect();
        for &block in cookie_blocks {
            let at = block * VIRTUAL_BLOCK_SIZE;
            data[at..at + COOKIE_SIZE].copy_from_slice(&three_words(VIRTUAL_BLOCK_MAGIC));
        }
        data
    }

    /// `data` from `start` without the 12 bytes at each of `cookies`.
    fn without(data: &[u8], start: usize, cookies: &[usize]) -> Vec<u8> {
        (start..data.len())
            .filter(|&i| !cookies.iter().any(|&c| (c..c + COOKIE_SIZE).contains(&i)))
            .map(|i| data[i])
            .collect()
    }

    #[test]
    fn virtual_blocks_drop_the_cookie_at_each_block_boundary() {
        let start = 0x2800;
        let data = blocks_with_cookies(3, &[1, 2]);
        let cookies = [VIRTUAL_BLOCK_SIZE, 2 * VIRTUAL_BLOCK_SIZE];
        let blocks = virtual_blocks(&data, start);
        assert_eq!(blocks.cookies, cookies);
        assert_eq!(blocks.stream.as_ref(), without(&data, start, &cookies));
        assert_eq!(
            (blocks.end, blocks.run_end),
            (data.len(), RunEnd::EndOfFile)
        );
        // An end on a boundary stops before that block's cookie; one byte
        // more starts after it.
        let first_block = VIRTUAL_BLOCK_SIZE - start;
        assert_eq!(blocks.file_end(first_block), VIRTUAL_BLOCK_SIZE);
        assert_eq!(
            blocks.file_end(first_block + 1),
            VIRTUAL_BLOCK_SIZE + COOKIE_SIZE + 1
        );
        assert_eq!(blocks.file_end(blocks.stream.len()), data.len());
    }

    #[test]
    fn the_cookie_run_ends_at_the_first_boundary_without_one() {
        let data = blocks_with_cookies(3, &[1]);
        let blocks = virtual_blocks(&data, 0x2800);
        let second = 2 * VIRTUAL_BLOCK_SIZE;
        assert_eq!(
            (blocks.end, blocks.run_end),
            (second, RunEnd::MissingCookie(second))
        );
        assert_eq!(
            blocks.stream.len(),
            second - 0x2800 - COOKIE_SIZE,
            "the run excludes the block without a cookie"
        );
    }

    #[test]
    fn without_a_first_cookie_the_bytes_are_taken_as_stored() {
        let data = blocks_with_cookies(3, &[2]);
        let blocks = virtual_blocks(&data, 0x2800);
        assert!(matches!(blocks.stream, Cow::Borrowed(_)));
        assert_eq!(blocks.cookies, Vec::<usize>::new());
        assert_eq!(blocks.stream.len(), data.len() - 0x2800);
        assert_eq!(blocks.run_end, RunEnd::EndOfFile);
    }

    #[test]
    fn the_cookie_run_stops_at_the_extraction_limit() {
        let count = MAX_PAYLOAD / VIRTUAL_BLOCK_SIZE + 2;
        let cookie_blocks: Vec<usize> = (1..count).collect();
        let data = blocks_with_cookies(count, &cookie_blocks);
        let blocks = virtual_blocks(&data, 0x2800);
        assert_eq!(blocks.run_end, RunEnd::Limit);
        assert!(blocks.stream.len() <= MAX_PAYLOAD);
        assert!(blocks.end <= 0x2800 + MAX_PAYLOAD);
    }

    #[test]
    fn preamble_pages_and_cookies_are_not_sbl_headers() {
        let mut data = vec![0xff; 4 * PREAMBLE_STEP];
        data[..COOKIE_SIZE].copy_from_slice(&three_words(AUTODETECT_MAGICS[0]));
        let page = PREAMBLE_STEP;
        data[page..page + COOKIE_SIZE].copy_from_slice(&three_words(AUTODETECT_MAGICS[1]));
        let cookie = 2 * PREAMBLE_STEP;
        data[cookie..cookie + COOKIE_SIZE].copy_from_slice(&three_words(VIRTUAL_BLOCK_MAGIC));
        assert!(!is_sbl_header(&data, 0));
        assert!(!is_sbl_header(&data, page));
        assert!(!is_sbl_header(&data, cookie));
        assert!(is_cookie(&data, cookie));
        assert_eq!(payload_after_preamble(&data), None);

        let elf = 3 * PREAMBLE_STEP;
        data[elf..elf + ELF_MAGIC.len()].copy_from_slice(ELF_MAGIC);
        assert_eq!(payload_after_preamble(&data), Some(Payload::Elf(elf)));
        data[cookie + 8..cookie + 12].copy_from_slice(&21u32.to_le_bytes());
        assert_eq!(
            payload_after_preamble(&data),
            Some(Payload::SblHeader(cookie)),
            "the first payload wins"
        );
    }
}
