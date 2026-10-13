//! Portable Sound Format files (Neill Corlett, "PSF specification v1.6",
//! "Basic File Structure"): `PSF`, a version byte naming the platform, the
//! reserved-area size, the compressed program size and the CRC-32 of the
//! compressed program (little-endian), then the reserved area, the program in
//! zlib `compress()` format and an optional `[TAG]` block of
//! `variable=value` lines ("Tag Format").
//!
//! The version byte decides how the two areas are read:
//! - 0x01 PSF1: the program is a `PS-X EXE` including its header ("Version
//!   0x01"); it is classified by its own parser.
//! - 0x02 PSF2: the reserved area is a virtual filesystem; see
//!   [`super::psf2`].
//! - 0x11 SSF and 0x12 DSF: a 4-byte LSB-first load address, then raw 68000
//!   or ARM7 code ("Version 0x11", "Version 0x12").
//! - 0x13 Sega Genesis: assigned without a layout (PSF wiki live
//!   specification); not interpreted.
//! - 0x21 USF ("USF specification v1.1"): the reserved area holds an SR64
//!   sparse ROM image stored as little-endian 32-bit words and an SR64
//!   Project64 v1.4 save state; the program area is unused.
//! - 0x22 GSF ("GSF Specifications version 0.02"): entry point, ROM offset
//!   and ROM size, then the ROM data.
//! - 0x23 SNSF ("SNSF Specifications version 0.02") and 0x24 2SF ("2sf
//!   specifications revision 7"): ROM offset and size, then the ROM data.
//! - 0x25 NCSF ("NCSF Specification v1.0"): an optional sequence number and
//!   a zlib-compressed SDAT, which is sound data, not code.
//! - 0x41 QSF ("Version 0x41"): tagged `KEY`, `Z80` and `SMP` blocks.
//!
//! The GSF, SNSF and 2SF documents do not state the byte order of their
//! program headers; little-endian is from the reference players, `CyberBotX`
//! `in_xsf` at `74fceae1` (`MapGSFSection`, `MapSNSFSection`,
//! `Map2SFSection`). The CRC-32 is the zlib (IEEE 802.3) CRC.

use super::*;
use crate::transform::Transform;

/// Signature, header size and header fields (little-endian).
const MAGIC: &[u8; 3] = b"PSF";
const HEADER_SIZE: usize = 0x10;
const VERSION: usize = 0x03;
const RESERVED_SIZE: usize = 0x04;
const PROGRAM_SIZE: usize = 0x08;
const PROGRAM_CRC: usize = 0x0c;

/// The optional tag block after the program.
const TAG_MAGIC: &[u8; 5] = b"[TAG]";

/// Most tag variables listed, and most characters kept of each value.
const MAX_TAGS: usize = 64;
const MAX_TAG_VALUE: usize = 256;

/// Descriptive tag variables shown in the notes (PSF "Tag Format"), plus
/// the `*by` creator variables.
const DESCRIPTIVE_TAGS: [&str; 9] = [
    "title",
    "artist",
    "game",
    "year",
    "genre",
    "copyright",
    "comment",
    "length",
    "fade",
];

/// Library tags (`_lib`, `_lib2`, ...) and other reserved variables start
/// with an underscore.
const LIBRARY_TAG: &str = "_lib";
const RESERVED_TAG_PREFIX: char = '_';

/// Decoded program size limits ("must not exceed").
const PSF1_MAX_PROGRAM: usize = 2_033_664;
const SSF_MAX_PROGRAM: usize = 524_292;
const DSF_MAX_PROGRAM: usize = 2_097_156;

/// SSF and DSF programs start with a 4-byte LSB-first load address.
const LOAD_ADDRESS_SIZE: usize = 4;

/// The 68000 takes its initial PC from address 4 at reset (rom-properties
/// `M68K_VectorTable`, as in the Mega Drive parser).
const M68K_RESET_PC: usize = 4;

/// GSF program header: entry point, ROM offset, ROM size; the two valid
/// entry points (multiboot and ROM regions).
const GSF_HEADER_SIZE: usize = 12;
const GSF_ENTRY: usize = 0;
const GSF_OFFSET: usize = 4;
const GSF_ROM_SIZE: usize = 8;
const GSF_ENTRY_POINTS: [u32; 2] = [0x0200_0000, 0x0800_0000];

/// SNSF and 2SF program header: ROM offset, ROM size.
const ROM_HEADER_SIZE: usize = 8;
const ROM_OFFSET: usize = 0;
const ROM_SIZE: usize = 4;

/// The `PS-X EXE` ID that starts a PSF1 program.
const PSX_EXE_ID: &[u8; 8] = b"PS-X EXE";

/// QSF block header: 3-character tag, start offset, length (LSB-first).
const QSF_BLOCK_HEADER: usize = 11;
const QSF_BLOCK_START: usize = 3;
const QSF_BLOCK_LENGTH: usize = 7;
const QSF_KEY: &[u8; 3] = b"KEY";
const QSF_Z80: &[u8; 3] = b"Z80";
const QSF_SMP: &[u8; 3] = b"SMP";

/// QSF Kabuki key: `swap_key1` (4), `swap_key2` (4), `addr_key` (2) and
/// `xor_key` (1), MSB-first; "KEY must not exceed 11 bytes".
const QSF_KEY_SIZE: usize = 11;
const QSF_SWAP_KEY1: usize = 0;
const QSF_SWAP_KEY2: usize = 4;

/// USF reserved area: an SR64 segment or four zero bytes, for the ROM and
/// then for the save state. A chunk is a length (0 ends the segment), an
/// offset and the data.
const SR64_MAGIC: &[u8; 4] = b"SR64";
const SR64_ABSENT: [u8; 4] = [0; 4];

/// Project64 v1.4 save-state identifier at state offset 0 (USF v1.1).
const PJ64_STATE_ID: u32 = 0x23d8_a6c8;

/// Transform name for USF ROM chunks restored to native order.
const USF_WORD_SWAP: &str = "32-bit byte swap";

/// NCSF reserved area: empty or a 32-bit sequence number. The SDAT size is
/// at bytes 8-11 of the SDAT.
const NCSF_SEQUENCE_SIZE: usize = 4;
const SDAT_SIZE: usize = 8;

/// PSF1: the emulation notes list an "R3000 CPU"; the `PlayStation` runs
/// it little-endian, as the PS-X EXE parser reports.
const R3000: Target = Target::new(Isa::Mips, 32, Endianness::Little);

/// SSF: "raw 68000 program data".
const MC68000: Target = Target::new(Isa::M68k, 32, Endianness::Big);

/// DSF: "raw ARM7 program data"; the document does not state its byte
/// order.
const AICA_ARM7: Target = Target::without_byte_order(Isa::Arm, 32);

/// USF: the Nintendo 64 VR4300, a big-endian MIPS III (as the N64 ROM
/// parser reports).
const VR4300: Target = Target::new(Isa::Mips64, 64, Endianness::Big);

/// GSF and 2SF: the GBA's ARM7TDMI and the DS cores, little-endian (as the
/// Nintendo ROM parsers report).
const ARM_LITTLE: Target = Target::new(Isa::Arm, 32, Endianness::Little);

/// SNSF: the SNES CPU, a 65C816 (as the SNES ROM parser reports).
const SNES_CPU: Target = Target::new(Isa::W65816, 16, Endianness::Little);

/// QSF: "Z80 program ROM".
const QSOUND_Z80: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// `PSF`, an assigned version byte, and a reserved area and program that
/// fit in the file. Several version bytes are printable ASCII (0x21-0x25,
/// 0x41), so the sizes keep text that starts with `PSF` from being taken
/// for a corrupt PSF file; any other defect is a parse error.
pub(super) fn detect(data: &[u8]) -> Option<PsfPlatform> {
    let version = data.strip_prefix(MAGIC.as_slice())?.first()?;
    let platform = PsfPlatform::from_version(*version)?;
    let reserved = u64::from(le_u32(data, RESERVED_SIZE).ok()?);
    let program = u64::from(le_u32(data, PROGRAM_SIZE).ok()?);
    let end = HEADER_SIZE as u64 + reserved + program;
    (end <= data.len() as u64).then_some(platform)
}

/// One tag variable: lowercased name and value.
struct Tag {
    name: String,
    value: String,
}

/// The areas of a PSF file, in file coordinates.
struct PsfFile<'a> {
    /// Reserved area.
    reserved: &'a [u8],
    /// File offset of the reserved area.
    reserved_at: usize,
    /// Compressed program.
    program: &'a [u8],
    /// File offset of the compressed program.
    program_at: usize,
    /// Tag variables in file order.
    tags: Vec<Tag>,
}

/// Parse a PSF file of the given platform.
pub(super) fn parse(data: &[u8], platform: PsfPlatform) -> Result<Container<'_>> {
    let mut c = Container::new(FileFormat::Psf, platform.label(), "psf");
    let file = read(data, platform, &mut c)?;
    match platform {
        PsfPlatform::PlayStation => playstation(&mut c, &file)?,
        PsfPlatform::PlayStation2 => playstation2(&mut c, &file)?,
        PsfPlatform::Saturn => saturn(&mut c, &file)?,
        PsfPlatform::Dreamcast => dreamcast(&mut c, &file)?,
        PsfPlatform::Genesis => c.notes.push(
            "Version 0x13 (Sega Genesis) has no published layout; the reserved area and program are not interpreted"
                .into(),
        ),
        PsfPlatform::Nintendo64 => nintendo64(&mut c, &file)?,
        PsfPlatform::GameBoyAdvance => game_boy_advance(&mut c, &file)?,
        PsfPlatform::SuperNes => super_nes(&mut c, &file)?,
        PsfPlatform::NintendoDs => nintendo_ds(&mut c, &file)?,
        PsfPlatform::NitroComposer => nitro_composer(&mut c, &file)?,
        PsfPlatform::QSound => qsound(&mut c, &file)?,
    }
    push_tag_notes(&mut c, &file.tags);
    Ok(c)
}

/// Header, both areas, the CRC-32 check and the tag block.
fn read<'a>(data: &'a [u8], platform: PsfPlatform, c: &mut Container<'a>) -> Result<PsfFile<'a>> {
    let header = data.get(..HEADER_SIZE).ok_or_else(|| {
        error(format!(
            "Truncated PSF header: {} B of {HEADER_SIZE} B",
            data.len()
        ))
    })?;
    if !header.starts_with(MAGIC) || PsfPlatform::from_version(header[VERSION]) != Some(platform) {
        return Err(error("Missing PSF signature or version byte"));
    }
    let reserved_size = le_u32(header, RESERVED_SIZE)? as usize;
    let program_size = le_u32(header, PROGRAM_SIZE)? as usize;
    let stored_crc = le_u32(header, PROGRAM_CRC)?;
    let after_header = &data[HEADER_SIZE..];
    let reserved = after_header.get(..reserved_size).ok_or_else(|| {
        error(format!(
            "Truncated PSF reserved area at 0x{HEADER_SIZE:X}: {reserved_size} B declared, {} B present",
            after_header.len()
        ))
    })?;
    let program_at = HEADER_SIZE + reserved_size;
    let after_reserved = &data[program_at..];
    let program = after_reserved.get(..program_size).ok_or_else(|| {
        error(format!(
            "Truncated PSF program at 0x{program_at:X}: {program_size} B declared, {} B present",
            after_reserved.len()
        ))
    })?;
    let crc_note = if program.is_empty() {
        "no program".to_string()
    } else {
        let computed = checksum::crc32(program);
        if computed != stored_crc {
            return Err(error(format!(
                "Invalid PSF program CRC-32: stored 0x{stored_crc:08X}, computed 0x{computed:08X}"
            )));
        }
        format!("program CRC-32 0x{stored_crc:08X} verified")
    };
    c.notes.push(format!(
        "PSF version 0x{:02X}, {}: reserved area {}, program {} compressed; {crc_note}",
        platform.version(),
        platform.label(),
        compressed::size_text(reserved_size),
        compressed::size_text(program_size),
    ));
    let tag_at = program_at + program_size;
    let rest = &data[tag_at..];
    let tags = if let Some(text) = rest.strip_prefix(TAG_MAGIC.as_slice()) {
        c.consumed = data.len();
        parse_tags(text)
    } else {
        c.consumed = tag_at;
        if !rest.is_empty() {
            c.notes.push(format!(
                "{} after the program at 0x{tag_at:X} is not a [TAG] block; ignored",
                compressed::size_text(rest.len())
            ));
        }
        Vec::new()
    };
    Ok(PsfFile {
        reserved,
        reserved_at: HEADER_SIZE,
        program,
        program_at,
        tags,
    })
}

/// Tag whitespace: "All characters 0x01-0x20 are considered whitespace"
/// (NUL is undefined and treated alike).
fn trim_tag(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b > b' ').unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| *b > b' ')
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Variable names "must be valid C identifiers".
fn is_identifier(name: &[u8]) -> bool {
    match name.split_first() {
        Some((first, rest)) => {
            (first.is_ascii_alphabetic() || *first == b'_')
                && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        }
        None => false,
    }
}

/// `variable=value` lines separated by 0x0A. Names are case-insensitive;
/// consecutive lines of one name form a multiple-line value; other lines are
/// ignored. A name repeated elsewhere is undefined and keeps its first value.
fn parse_tags(text: &[u8]) -> Vec<Tag> {
    let mut tags: Vec<Tag> = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        let Some(equals) = line.iter().position(|b| *b == b'=') else {
            continue;
        };
        let name = trim_tag(&line[..equals]);
        if !is_identifier(name) {
            continue;
        }
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        let value = bounded_text(trim_tag(&line[equals + 1..]), MAX_TAG_VALUE);
        if let Some(last) = tags.last_mut().filter(|last| last.name == name) {
            last.value.push(' ');
            last.value.push_str(&value);
            last.value = last.value.chars().take(MAX_TAG_VALUE).collect();
        } else if tags.len() < MAX_TAGS && !tags.iter().any(|tag| tag.name == name) {
            tags.push(Tag { name, value });
        }
    }
    tags
}

/// `_lib`, `_lib2`, `_lib3`, ...
fn is_library_tag(name: &str) -> bool {
    name.strip_prefix(LIBRARY_TAG)
        .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
}

/// `name "value"; name "value"` for the selected tags.
fn tag_list<'t>(tags: impl Iterator<Item = &'t Tag>) -> String {
    tags.map(|tag| format!("{} \"{}\"", tag.name, tag.value))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Notes for descriptive tags, library references (never resolved: they
/// name other files) and other reserved variables; metadata for every tag.
fn push_tag_notes(c: &mut Container<'_>, tags: &[Tag]) {
    let descriptive =
        tag_list(tags.iter().filter(|tag| {
            DESCRIPTIVE_TAGS.contains(&tag.name.as_str()) || tag.name.ends_with("by")
        }));
    if !descriptive.is_empty() {
        c.notes.push(format!("Tags: {descriptive}"));
    }
    let libraries = tag_list(tags.iter().filter(|tag| is_library_tag(&tag.name)));
    if !libraries.is_empty() {
        c.notes
            .push(format!("Library references are not resolved: {libraries}"));
    }
    let settings = tag_list(
        tags.iter()
            .filter(|tag| tag.name.starts_with(RESERVED_TAG_PREFIX) && !is_library_tag(&tag.name)),
    );
    if !settings.is_empty() {
        c.notes.push(format!("Player settings: {settings}"));
    }
    for tag in tags {
        c.push_metadata(
            format!("psf_tag_{}", tag.name),
            format!("Tag {}", tag.name),
            tag.value.clone(),
        );
    }
}

/// The decoded program, or `None` when the program area is empty.
fn decode_program(
    c: &mut Container<'_>,
    file: &PsfFile<'_>,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    if file.program.is_empty() {
        c.notes.push("No program area".into());
        return Ok(None);
    }
    let decoded = compressed::decode_limited(Codec::Zlib, file.program, limit).map_err(|e| {
        error(format!(
            "Invalid PSF program at 0x{:X}: {e}",
            file.program_at
        ))
    })?;
    let used = decoded.consumed.unwrap_or(file.program.len());
    if used < file.program.len() {
        c.notes.push(format!(
            "{} follow the zlib stream in the program area",
            compressed::size_text(file.program.len() - used)
        ));
    }
    c.notes.push(format!(
        "Program decodes to {}",
        compressed::size_text(decoded.data.len())
    ));
    Ok(Some(decoded.data))
}

/// A load section of decoded program bytes; its stored range is the whole
/// compressed program.
fn decoded_section<'a>(
    file: &PsfFile<'_>,
    label: String,
    address: u64,
    code: Vec<u8>,
) -> Section<'a> {
    Section {
        label,
        address,
        offset: file.program_at,
        stored_size: file.program.len(),
        data: Cow::Owned(code),
        transform: Some(Codec::Zlib.name()),
    }
}

/// Note a reserved area the platform does not use.
fn note_unused_reserved(c: &mut Container<'_>, file: &PsfFile<'_>) {
    if !file.reserved.is_empty() {
        c.notes.push(format!(
            "Reserved area of {} is unused by this platform; not analyzed",
            compressed::size_text(file.reserved.len())
        ));
    }
}

/// GSF and SNSF reserve the area for a save state whose format "has yet to
/// be defined".
fn note_save_state_reserved(c: &mut Container<'_>, file: &PsfFile<'_>) {
    if !file.reserved.is_empty() {
        c.notes.push(format!(
            "Reserved area of {} is set aside for a save state of undefined format; not analyzed",
            compressed::size_text(file.reserved.len())
        ));
    }
}

/// PSF1: the program is a `PS-X EXE` for the `PlayStation`.
fn playstation<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(R3000);
    note_unused_reserved(c, file);
    let Some(program) = decode_program(c, file, PSF1_MAX_PROGRAM)? else {
        return Ok(());
    };
    if !program.starts_with(PSX_EXE_ID) {
        c.notes
            .push("Program does not start with a PS-X EXE header".into());
    }
    c.notes
        .push("PlayStation R3000 program; the PS-X EXE is classified from its own header".into());
    c.children.push(Child::decoded(
        "PS-X EXE program",
        file.program_at,
        file.program.len(),
        Cow::Owned(program),
        Codec::Zlib.name(),
    ));
    Ok(())
}

/// PSF2: the program area is unused and the reserved area is a filesystem
/// of IOP modules and data; the format names no CPU.
fn playstation2<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    if !file.program.is_empty() {
        c.notes.push(format!(
            "Program area of {} is unused by PSF2; not decoded",
            compressed::size_text(file.program.len())
        ));
    }
    psf2::list(c, file.reserved, file.reserved_at)
}

/// SSF and DSF: a load address, then the code copied to it. Returns the
/// load address, or `None` without a program.
fn load_address_program<'a>(
    c: &mut Container<'a>,
    file: &PsfFile<'a>,
    limit: usize,
    cpu: &str,
) -> Result<Option<u32>> {
    let Some(mut program) = decode_program(c, file, limit)? else {
        return Ok(None);
    };
    let load = le_u32(&program, 0).map_err(|_| {
        error(format!(
            "Truncated {cpu} program: {} B, no load address",
            program.len()
        ))
    })?;
    let code = program.split_off(LOAD_ADDRESS_SIZE);
    if code.is_empty() {
        c.notes
            .push("Program holds a load address but no code".into());
    } else {
        c.sections.push(decoded_section(
            file,
            format!("{cpu} program"),
            u64::from(load),
            code,
        ));
        c.code_sections = true;
    }
    Ok(Some(load))
}

/// SSF: 68000 code for the Saturn's sound CPU, which starts at its reset
/// vector.
fn saturn<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(MC68000);
    note_unused_reserved(c, file);
    let Some(load) = load_address_program(c, file, SSF_MAX_PROGRAM, "68000")? else {
        return Ok(());
    };
    // The reset vector is in the loaded image only when it starts at 0.
    let reset_pc = c
        .sections
        .last()
        .filter(|_| load == 0)
        .and_then(|section| be_u32(&section.data, M68K_RESET_PC).ok());
    c.entry = reset_pc.map(u64::from);
    c.notes.push(format!(
        "Saturn sound CPU (68000) program loaded at 0x{load:X}; execution starts at the 68000 reset vector{}",
        reset_pc.map_or(String::new(), |pc| format!(", initial PC 0x{pc:X}"))
    ));
    Ok(())
}

/// DSF: ARM7 code for the Dreamcast's sound processor, which starts at
/// address 0.
fn dreamcast<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(AICA_ARM7);
    note_unused_reserved(c, file);
    let Some(load) = load_address_program(c, file, DSF_MAX_PROGRAM, "ARM7")? else {
        return Ok(());
    };
    c.entry = Some(0);
    c.notes.push(format!(
        "Dreamcast sound processor (ARM7) program loaded at 0x{load:X}; execution starts at address 0; the DSF specification does not state the ARM7 byte order"
    ));
    Ok(())
}

/// One SR64 chunk.
struct Sr64Chunk<'a> {
    /// Offset in the ROM or save state.
    offset: u32,
    /// File offset of the chunk data.
    at: usize,
    /// Chunk data as stored.
    data: &'a [u8],
}

/// The SR64 segment at `*pos` of the USF reserved area, or `None` for four
/// zero bytes. The segment ends at a chunk length of 0.
fn sr64_segment<'a>(
    reserved: &'a [u8],
    base: usize,
    pos: &mut usize,
    what: &str,
) -> Result<Option<Vec<Sr64Chunk<'a>>>> {
    let truncated = |at: usize| error(format!("Truncated USF {what} segment at 0x{:X}", base + at));
    let id = slice(reserved, *pos, 4).map_err(|_| truncated(*pos))?;
    if id == SR64_ABSENT {
        *pos += 4;
        return Ok(None);
    }
    if id != SR64_MAGIC {
        return Err(error(format!(
            "Invalid USF {what} segment at 0x{:X}: expected SR64 or four zero bytes",
            base + *pos
        )));
    }
    *pos += 4;
    let mut chunks = Vec::new();
    loop {
        let header_at = *pos;
        let len = le_u32(reserved, header_at).map_err(|_| truncated(header_at))? as usize;
        *pos += 4;
        if len == 0 {
            return Ok(Some(chunks));
        }
        let offset = le_u32(reserved, *pos).map_err(|_| truncated(header_at))?;
        *pos += 4;
        let chunk = slice(reserved, *pos, len).map_err(|_| {
            error(format!(
                "Truncated SR64 chunk at 0x{:X}: {len} B declared",
                base + header_at
            ))
        })?;
        chunks.push(Sr64Chunk {
            offset,
            at: base + *pos,
            data: chunk,
        });
        *pos += len;
    }
}

/// USF: the reserved area holds the sparse ROM and save state. ROM chunks
/// are stored as little-endian 32-bit words of the big-endian ROM, so each
/// word is swapped back before analysis.
fn nintendo64<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(VR4300);
    c.code_sections = true;
    if !file.program.is_empty() {
        c.notes.push(format!(
            "Program area of {} is unused by USF; not decoded",
            compressed::size_text(file.program.len())
        ));
    }
    let mut pos = 0;
    let rom = sr64_segment(file.reserved, file.reserved_at, &mut pos, "ROM")?;
    let state = sr64_segment(file.reserved, file.reserved_at, &mut pos, "save state")?;
    if pos < file.reserved.len() {
        c.notes.push(format!(
            "{} after the save state segment; ignored",
            compressed::size_text(file.reserved.len() - pos)
        ));
    }
    let chunks = rom.unwrap_or_default();
    let mut total = 0usize;
    let mut skipped = 0usize;
    for chunk in &chunks {
        let fits =
            c.sections.len() < container::MAX_COMPONENTS && total + chunk.data.len() <= MAX_PAYLOAD;
        let native = if fits {
            Transform::Swap32.apply(chunk.data)
        } else {
            None
        };
        let Some(native) = native else {
            skipped += 1;
            continue;
        };
        total += native.len();
        c.sections.push(Section {
            label: format!("ROM 0x{:X}", chunk.offset),
            address: u64::from(chunk.offset),
            offset: chunk.at,
            stored_size: chunk.data.len(),
            data: Cow::Owned(native),
            transform: Some(USF_WORD_SWAP),
        });
    }
    c.notes.push(format!(
        "Nintendo 64 (VR4300, MIPS III) ROM image: {} SR64 chunks, {}; each 32-bit word is swapped back to big-endian; addresses are ROM offsets",
        chunks.len(),
        compressed::size_text(chunks.iter().map(|chunk| chunk.data.len()).sum())
    ));
    if skipped > 0 {
        c.notes.push(format!(
            "{skipped} ROM chunks not analyzed: not whole 32-bit words, or beyond the {} section or {} payload limit",
            container::MAX_COMPONENTS,
            compressed::size_text(MAX_PAYLOAD)
        ));
    }
    match state {
        Some(chunks) => {
            let identified = chunks
                .iter()
                .find(|chunk| chunk.offset == 0)
                .and_then(|chunk| le_u32(chunk.data, 0).ok())
                == Some(PJ64_STATE_ID);
            c.notes.push(format!(
                "Project64 v1.4 save state: {} SR64 chunks, {}; identifier 0x{PJ64_STATE_ID:08X} {}; emulator state, not analyzed",
                chunks.len(),
                compressed::size_text(chunks.iter().map(|chunk| chunk.data.len()).sum()),
                if identified { "present" } else { "not found at offset 0" }
            ));
        }
        None => c.notes.push("No save state".into()),
    }
    Ok(())
}

/// GSF: entry point, ROM offset (a GBA address) and size, then ROM data.
fn game_boy_advance<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(ARM_LITTLE);
    note_save_state_reserved(c, file);
    let Some(mut program) = decode_program(c, file, MAX_PAYLOAD)? else {
        return Ok(());
    };
    if program.len() < GSF_HEADER_SIZE {
        return Err(error(format!(
            "Truncated GSF program header: {} B of {GSF_HEADER_SIZE} B",
            program.len()
        )));
    }
    let entry = le_u32(&program, GSF_ENTRY)?;
    let offset = le_u32(&program, GSF_OFFSET)?;
    let size = le_u32(&program, GSF_ROM_SIZE)? as usize;
    let rom = rom_data(c, program.split_off(GSF_HEADER_SIZE), size, "GSF")?;
    c.entry = Some(u64::from(entry));
    c.notes.push(format!(
        "Game Boy Advance (ARM7TDMI) program: {} of ROM data at 0x{offset:08X}; entry point 0x{entry:08X}",
        compressed::size_text(size)
    ));
    if !GSF_ENTRY_POINTS.contains(&entry) {
        c.notes.push(format!(
            "Entry point 0x{entry:08X} is not one of the documented GSF entry points 0x02000000 and 0x08000000"
        ));
    }
    if offset >> 24 != entry >> 24 {
        c.notes.push(format!(
            "ROM offset 0x{offset:08X} and entry point 0x{entry:08X} differ in their high byte"
        ));
    }
    push_rom_section(c, file, offset, rom);
    Ok(())
}

/// The ROM data after a GSF, SNSF or 2SF program header, exactly `size`
/// bytes long.
fn rom_data(c: &mut Container<'_>, mut rom: Vec<u8>, size: usize, what: &str) -> Result<Vec<u8>> {
    if rom.len() < size {
        return Err(error(format!(
            "Truncated {what} ROM data: {size} B declared, {} B decoded",
            rom.len()
        )));
    }
    if rom.len() > size {
        c.notes.push(format!(
            "{} after the ROM data in the program; ignored",
            compressed::size_text(rom.len() - size)
        ));
        rom.truncate(size);
    }
    Ok(rom)
}

/// A ROM image section; a whole image may itself be a recognized ROM.
fn push_rom_section(c: &mut Container<'_>, file: &PsfFile<'_>, offset: u32, rom: Vec<u8>) {
    if !rom.is_empty() {
        c.sections.push(decoded_section(
            file,
            format!("ROM 0x{offset:X}"),
            u64::from(offset),
            rom,
        ));
    }
}

/// SNSF and 2SF: ROM offset and size, then ROM data. Returns the offset and
/// size, or `None` without a program.
fn offset_rom<'a>(
    c: &mut Container<'a>,
    file: &PsfFile<'a>,
    what: &str,
) -> Result<Option<(u32, usize)>> {
    let Some(mut program) = decode_program(c, file, MAX_PAYLOAD)? else {
        return Ok(None);
    };
    if program.len() < ROM_HEADER_SIZE {
        return Err(error(format!(
            "Truncated {what} program header: {} B of {ROM_HEADER_SIZE} B",
            program.len()
        )));
    }
    let offset = le_u32(&program, ROM_OFFSET)?;
    let size = le_u32(&program, ROM_SIZE)? as usize;
    let rom = rom_data(c, program.split_off(ROM_HEADER_SIZE), size, what)?;
    push_rom_section(c, file, offset, rom);
    Ok(Some((offset, size)))
}

/// SNSF: a patched SNES ROM; offsets are ROM offsets and the mapping is set
/// by the player or the `_memory` tag.
fn super_nes<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(SNES_CPU);
    note_save_state_reserved(c, file);
    if let Some((offset, size)) = offset_rom(c, file, "SNSF")? {
        c.notes.push(format!(
            "SNES (65C816) program: {} of ROM at ROM offset 0x{offset:X}; ROM offsets are not CPU addresses",
            compressed::size_text(size)
        ));
    }
    Ok(())
}

/// 2SF: a (possibly patched) Nintendo DS ROM image holding ARM9 and ARM7
/// code.
fn nintendo_ds<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(ARM_LITTLE);
    note_unused_reserved(c, file);
    if let Some((offset, size)) = offset_rom(c, file, "2SF")? {
        c.notes.push(format!(
            "Nintendo DS ROM image: {} at ROM offset 0x{offset:X}; the ARM9 and ARM7 code is loaded from it",
            compressed::size_text(size)
        ));
    }
    Ok(())
}

/// NCSF: sound data for a host-side sequence player; no machine code.
fn nitro_composer<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    match file.reserved.len() {
        0 => c.notes.push("No sequence number".into()),
        NCSF_SEQUENCE_SIZE => {
            let sequence = le_u32(file.reserved, 0)?;
            c.notes.push(format!(
                "Sequence number {sequence} (0-based index into the SDAT INFO section)"
            ));
        }
        size => {
            return Err(error(format!(
                "Invalid NCSF reserved area: {size} B; expected 0 or {NCSF_SEQUENCE_SIZE} B"
            )));
        }
    }
    let Some(sdat) = decode_program(c, file, MAX_PAYLOAD)? else {
        return Ok(());
    };
    let declared = le_u32(&sdat, SDAT_SIZE)
        .map_err(|_| error(format!("Truncated NCSF SDAT header: {} B", sdat.len())))?;
    if declared as usize != sdat.len() {
        return Err(error(format!(
            "Invalid NCSF SDAT size: {declared} B in the SDAT header, {} B decoded",
            sdat.len()
        )));
    }
    c.notes.push(
        "NCSF holds a Nitro Composer SDAT (sequences, banks and wave archives), not machine code"
            .into(),
    );
    let mut child = Child::decoded(
        "SDAT sound data",
        file.program_at,
        file.program.len(),
        Cow::Owned(sdat),
        Codec::Zlib.name(),
    );
    child.opaque = true;
    c.children.push(child);
    Ok(())
}

/// A QSF block tag for messages.
fn tag_text(tag: &[u8]) -> String {
    tag.iter()
        .map(|b| {
            if b.is_ascii_graphic() {
                char::from(*b)
            } else {
                '?'
            }
        })
        .collect()
}

/// QSF: `KEY`, `Z80` and `SMP` blocks loaded at offsets of their section.
/// A key with a nonzero swap key means the Z80 program is Kabuki-encrypted.
fn qsound<'a>(c: &mut Container<'a>, file: &PsfFile<'a>) -> Result<()> {
    c.target = Some(QSOUND_Z80);
    note_unused_reserved(c, file);
    let Some(program) = decode_program(c, file, MAX_PAYLOAD)? else {
        return Ok(());
    };
    let mut key = [0u8; QSF_KEY_SIZE];
    let mut has_key = false;
    let mut z80 = Vec::new();
    let mut sample_blocks = 0usize;
    let mut sample_bytes = 0usize;
    let mut pos = 0;
    while pos < program.len() {
        let header = program.get(pos..pos + QSF_BLOCK_HEADER).ok_or_else(|| {
            error(format!(
                "Truncated QSF block header at program offset 0x{pos:X}"
            ))
        })?;
        let tag = &header[..QSF_BLOCK_START];
        let start = le_u32(header, QSF_BLOCK_START)?;
        let len = le_u32(header, QSF_BLOCK_LENGTH)? as usize;
        let body_at = pos + QSF_BLOCK_HEADER;
        let end = body_at
            .checked_add(len)
            .filter(|end| *end <= program.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated QSF {} block at program offset 0x{pos:X}: {len} B declared",
                    tag_text(tag)
                ))
            })?;
        match tag {
            _ if tag == QSF_KEY => {
                let key_start = start as usize;
                let key_end = key_start
                    .checked_add(len)
                    .filter(|end| *end <= QSF_KEY_SIZE)
                    .ok_or_else(|| {
                        error(format!(
                            "Invalid QSF KEY block at program offset 0x{pos:X}: exceeds {QSF_KEY_SIZE} B"
                        ))
                    })?;
                key[key_start..key_end].copy_from_slice(&program[body_at..end]);
                has_key = true;
            }
            _ if tag == QSF_Z80 => z80.push((start, body_at..end)),
            _ if tag == QSF_SMP => {
                sample_blocks += 1;
                sample_bytes += len;
            }
            _ => {
                return Err(error(format!(
                    "Unknown QSF block tag {} at program offset 0x{pos:X}",
                    tag_text(tag)
                )));
            }
        }
        pos = end;
    }
    let swap_key1 = be_u32(&key, QSF_SWAP_KEY1)?;
    let swap_key2 = be_u32(&key, QSF_SWAP_KEY2)?;
    let z80_bytes: usize = z80.iter().map(|(_, range)| range.len()).sum();
    c.notes.push(format!(
        "Capcom QSound: {} Z80 program blocks ({}), {sample_blocks} SMP sample blocks ({}); sample data is not analyzed",
        z80.len(),
        compressed::size_text(z80_bytes),
        compressed::size_text(sample_bytes)
    ));
    if has_key && (swap_key1, swap_key2) != (0, 0) {
        c.notes.push(format!(
            "Z80 program is Kabuki-encrypted (swap keys 0x{swap_key1:08X}, 0x{swap_key2:08X}); not analyzed"
        ));
        return Ok(());
    }
    c.notes.push(
        "No Kabuki encryption: no KEY block, or both swap keys are zero; addresses are Z80 program ROM offsets"
            .into(),
    );
    let blocks = z80.len();
    for (start, range) in z80.into_iter().take(container::MAX_COMPONENTS) {
        c.sections.push(decoded_section(
            file,
            format!("Z80 ROM 0x{start:X}"),
            u64::from(start),
            program[range].to_vec(),
        ));
    }
    if blocks > container::MAX_COMPONENTS {
        c.notes.push(format!(
            "{} further Z80 blocks were not listed (limit {})",
            blocks - container::MAX_COMPONENTS,
            container::MAX_COMPONENTS
        ));
    }
    c.code_sections = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_trimmed_lowercased_and_joined_across_lines() {
        let tags =
            parse_tags(b"Title = Earth\ncomment=one\ncomment=two\n\n9bad=x\n_lib=lib.psflib\n");
        let pairs: Vec<(&str, &str)> = tags
            .iter()
            .map(|tag| (tag.name.as_str(), tag.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("title", "Earth"),
                ("comment", "one two"),
                ("_lib", "lib.psflib")
            ]
        );
    }

    #[test]
    fn library_tags_are_lib_and_numbered_libs() {
        assert!(is_library_tag("_lib"));
        assert!(is_library_tag("_lib12"));
        assert!(!is_library_tag("_library"));
        assert!(!is_library_tag("_refresh"));
    }

    #[test]
    fn sr64_segments_end_at_a_zero_length() {
        let mut area = b"SR64".to_vec();
        area.extend_from_slice(&4u32.to_le_bytes());
        area.extend_from_slice(&0x1000u32.to_le_bytes());
        area.extend_from_slice(&[1, 2, 3, 4]);
        area.extend_from_slice(&0u32.to_le_bytes());
        area.extend_from_slice(&SR64_ABSENT);
        let mut pos = 0;
        let rom = sr64_segment(&area, 0x10, &mut pos, "ROM")
            .expect("segment")
            .expect("present");
        assert_eq!((rom.len(), rom[0].offset, rom[0].at), (1, 0x1000, 0x1c));
        let state = sr64_segment(&area, 0x10, &mut pos, "save state").expect("segment");
        assert!(state.is_none());
        assert_eq!(pos, area.len());
    }
}
