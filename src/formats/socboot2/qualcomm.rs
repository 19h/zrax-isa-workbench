//! Legacy Qualcomm MBN headers: the 40-byte version 3 header (no magic)
//! and the 80-byte SBL header (`FLASH_CODE_WORD`, `MAGIC_NUM`), including
//! the NAND preamble that may precede an SBL header.
//!
//! Source: coreboot `util/qualcomm/mbn_tools.py` (`Boot_Hdr`, `Sbl_Hdr`,
//! `ImageType`, `image_preamble`), `mbncat.py` and `ipqheader.py`.
//! Modern Qualcomm images are ELF files whose hash segment holds these
//! headers; the ELF parser classifies them by `e_machine`.
//!
//! Code, signature and certificate chain are stored back to back: the
//! writer sets `sig_ptr = image_dest_ptr + code_size` and `cert_chain_ptr
//! = sig_ptr + sig_size`.

use super::*;

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

/// The SBL header after a preamble is searched for on 512-byte boundaries
/// up to this offset (a bound chosen here, not from the source).
const MAX_PREAMBLE: usize = 1 << 20;
const PREAMBLE_STEP: usize = 512;

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
    let is_sbl =
        le_u32(data, 0).ok() == Some(SBL_CODEWORD) && le_u32(data, 4).ok() == Some(SBL_MAGIC);
    is_sbl.then_some(Layout::QualcommSbl)
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

/// Whether an SBL header (codeword and magic) starts at `at` and is not a
/// NAND preamble page.
fn is_sbl_header(data: &[u8], at: usize) -> bool {
    let words = (le_u32(data, at), le_u32(data, at + 4), le_u32(data, at + 8));
    match words {
        (Ok(SBL_CODEWORD), Ok(SBL_MAGIC), Ok(third)) => !AUTODETECT_MAGICS.contains(&third),
        _ => false,
    }
}

/// The offset of the SBL header: 0, or after a NAND preamble the first
/// 512-byte boundary that holds a header whose image source lies past it.
fn sbl_header_offset(data: &[u8], notes: &mut Vec<String>) -> Result<usize> {
    let third = le_u32(data, SBL_IMAGE_ID)?;
    if !AUTODETECT_MAGICS.contains(&third) {
        return Ok(0);
    }
    let limit = MAX_PREAMBLE.min(data.len());
    let found = (PREAMBLE_STEP..limit)
        .step_by(PREAMBLE_STEP)
        .find(|&at| is_sbl_header(data, at));
    let Some(at) = found else {
        return Err(error(format!(
            "Missing SBL header after the NAND preamble (searched {})",
            size_text(limit)
        )));
    };
    notes.push(format!(
        "NAND preamble (autodetect magic 0x{third:08X}); SBL header at 0x{at:X}"
    ));
    Ok(at)
}

/// The instruction set `booting_image_config` names, and its note.
fn booting_image_target(config: u32) -> (Option<Target>, String) {
    match config {
        SBL_AARCH64 => (
            Some(Target::new(Isa::AArch64, 64, Endianness::Little)),
            "booting_image_config 0xF: AArch64 SBL".into(),
        ),
        SBL_AARCH32 => (
            Some(Target::without_byte_order(Isa::Arm, 32)),
            "booting_image_config 0x0: AArch32 SBL".into(),
        ),
        SBL_CONFIG_UNSET => (
            None,
            "booting_image_config is unset; the header names no instruction set".into(),
        ),
        other => (
            None,
            format!("booting_image_config 0x{other:X} is not a documented value; no instruction set claimed"),
        ),
    }
}

pub(super) fn parse_sbl(data: &[u8]) -> Result<Container<'_>> {
    range(data, 0, SBL_HEADER_SIZE, "SBL header")?;
    if !(le_u32(data, 0)? == SBL_CODEWORD && le_u32(data, 4)? == SBL_MAGIC) {
        return Err(error("Missing SBL codeword and magic"));
    }
    let mut notes = Vec::new();
    let header_offset = sbl_header_offset(data, &mut notes)?;
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
    let (target, isa_note) = booting_image_target(le_u32(header, SBL_BOOTING_IMAGE_CONFIG)?);

    let mut c = Container::new(
        FileFormat::QualcommMbn,
        Layout::QualcommSbl.label(),
        "qualcomm",
    );
    c.target = target;
    c.notes
        .push("Qualcomm SBL MBN, 80-byte header (codeword 0x844BDCD1, magic 0x73D71034)".into());
    c.notes.append(&mut notes);
    c.notes.push(isa_note);
    describe_image_id(&mut c, image_id);
    let end = push_image(&mut c, data, image_src, &fields, target)?;
    c.consumed = end;
    if let Some(member) = trailing_member(data, end, &mut c.notes) {
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
            booting_image_target(SBL_AARCH64).0,
            Some(Target::new(Isa::AArch64, 64, Endianness::Little))
        );
        assert_eq!(
            booting_image_target(SBL_AARCH32).0,
            Some(Target::without_byte_order(Isa::Arm, 32))
        );
        assert!(booting_image_target(SBL_CONFIG_UNSET).0.is_none());
        assert!(booting_image_target(7).0.is_none());
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
}
