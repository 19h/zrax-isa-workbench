//! Nintendo 64 ROM images (`.z64`, `.v64`, `.n64`).
//!
//! Header layout from the N64brew Wiki "ROM Header" (oldid 5925); byte
//! orders from mupen64plus-core `src/main/rom.c` at
//! `ba95bab92a76744753bfe61470823a4937850ab0` (`Z64_SIGNATURE`,
//! `V64_SIGNATURE`, `N64_SIGNATURE`, `swap_copy_rom`); CIC identification
//! and the check code from pmret/papermario `tools/n64crc.c` at
//! `adaf3e6e730025fb6f5ddf07cc5147426c2025d6`, a reimplementation of
//! uCON64's algorithm rather than Nintendo's IPL3. The native order is
//! big-endian (header 0x000-0x03F: PI configuration, clock rate 0x04, boot
//! address 0x08, libultra version 0x0C, check code 0x10, title 0x20, game
//! code 0x3B, version 0x3F), then IPL3 boot code at 0x040-0xFFF and game
//! code and data from 0x1000. `.v64` dumps swap the bytes of every 16-bit
//! halfword and `.n64` dumps reverse every 32-bit word; both are normalized
//! to big-endian before anything is read. The CPU is the VR4300, a MIPS III
//! implementation.

use super::*;
use crate::formats::MAX_PAYLOAD;
use crate::transform::Transform;

/// The first word of each dump order: PI BSD DOM1 timing `80 37 12 40`
/// as stored (mupen64plus-core signatures).
const FIRST_WORDS: [(N64ByteOrder, [u8; 4]); 3] = [
    (N64ByteOrder::Native, [0x80, 0x37, 0x12, 0x40]),
    (N64ByteOrder::ByteSwapped, [0x37, 0x80, 0x40, 0x12]),
    (N64ByteOrder::WordSwapped, [0x40, 0x12, 0x37, 0x80]),
];

/// The first word and the clock-rate word; rom-properties also requires
/// the clock rate's low nibble (0x0F in native order).
const SIGNATURE_SIZE: usize = 8;
const CLOCK_RATE_LOW_BYTE: usize = 7;
const CLOCK_RATE_NIBBLE: u8 = 0x0F;

/// Header fields (native order, big-endian).
const HEADER_SIZE: usize = 0x40;
const CLOCK_RATE: usize = 0x04;
const BOOT_ADDRESS: usize = 0x08;
const LIBULTRA_VERSION: usize = 0x0C;
const CHECK_CODE_HIGH: usize = 0x10;
const CHECK_CODE_LOW: usize = 0x14;
const TITLE: Range<usize> = 0x20..0x34;
const GAME_CODE: Range<usize> = 0x3B..0x3F;
const CATEGORY: usize = 0x3B;
const DESTINATION: usize = 0x3E;
const ROM_VERSION: usize = 0x3F;

/// Clock rate bits that hold the rate; 0 selects the default.
const CLOCK_RATE_MASK: u32 = 0xFFFF_FFF0;
const DEFAULT_CLOCK_RATE: u32 = 0x03B9_ACA0;

/// IPL3 boot code at 0x040-0xFFF; game code and data from 0x1000.
const IPL3: Range<usize> = 0x040..0x1000;
const GAME_CODE_OFFSET: usize = 0x1000;

/// Where the PIF boot code copies IPL3 (RSP DMEM + 0x40, KSEG1). From the
/// N64brew "Initial Program Load" page (oldid 5596); not in the collected
/// header notes.
const IPL3_ADDRESS: u64 = 0xA400_0040;

/// IPL3 copies this much game code to the boot address, and the check code
/// covers the same ROM range 0x1000-0x100FFF.
const IPL3_COPY_SIZE: usize = 0x10_0000;

/// For CIC 6105 the check code mixes in IPL3 words at 0x750 + (offset &
/// 0xFF), which is 0x710 into IPL3.
const CIC_6105_IPL3_TABLE: usize = 0x710;

/// Transform name for normalized `.v64` and `.n64` bytes.
const N64_BYTE_SWAP: &str = "N64 byte swap";

/// 64-bit MIPS, big-endian.
const MIPS64_BIG: Target = Target::new(Isa::Mips64, 64, Endianness::Big);
const VR4300: &str = "VR4300 (MIPS III)";

/// How a CIC's check code combines the accumulators (n64crc.c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mix {
    /// 6101, 6102, 7101 and 6105.
    Xor,
    /// 6103 and 7103.
    Add,
    /// 6106 and 7106.
    Multiply,
}

/// A CIC identified by the CRC-32 of the IPL3 it pairs with.
struct Cic {
    name: &'static str,
    ipl3_crc32: u32,
    seed: u32,
    mix: Mix,
    /// 6105: `t1` mixes in IPL3 words instead of `t5`.
    ipl3_table: bool,
    /// IPL3 subtracts this from the boot address before jumping (N64brew).
    boot_offset: u32,
}

/// The CICs n64crc.c identifies, with the IPL3 boot adjustments N64brew
/// gives for 6103 and 6106.
const CICS: [Cic; 5] = [
    Cic {
        name: "6101",
        ipl3_crc32: 0x6170_A4A1,
        seed: 0xF8CA_4DDC,
        mix: Mix::Xor,
        ipl3_table: false,
        boot_offset: 0,
    },
    Cic {
        name: "6102/7101",
        ipl3_crc32: 0x90BB_6CB5,
        seed: 0xF8CA_4DDC,
        mix: Mix::Xor,
        ipl3_table: false,
        boot_offset: 0,
    },
    Cic {
        name: "6103/7103",
        ipl3_crc32: 0x0B05_0EE0,
        seed: 0xA388_6759,
        mix: Mix::Add,
        ipl3_table: false,
        boot_offset: 0x10_0000,
    },
    Cic {
        name: "6105/7105",
        ipl3_crc32: 0x98BC_2C86,
        seed: 0xDF26_F436,
        mix: Mix::Xor,
        ipl3_table: true,
        boot_offset: 0,
    },
    Cic {
        name: "6106/7106",
        ipl3_crc32: 0xACC8_580A,
        seed: 0x1FEA_617A,
        mix: Mix::Multiply,
        ipl3_table: false,
        boot_offset: 0x20_0000,
    },
];

/// Game code category letters (0x3B).
const CATEGORIES: [(u8, &str); 5] = [
    (b'N', "Game Pak"),
    (b'D', "64DD disk"),
    (b'C', "expandable game (Game Pak part)"),
    (b'E', "expandable game (64DD part)"),
    (b'Z', "Aleck64 Game Pak"),
];

/// Destination letters (0x3E); 0x00 is homebrew "region free".
const DESTINATIONS: [(u8, &str); 21] = [
    (0x00, "region free (homebrew)"),
    (b'A', "all"),
    (b'B', "Brazil"),
    (b'C', "China"),
    (b'D', "Germany"),
    (b'E', "North America"),
    (b'F', "France"),
    (b'G', "Gateway 64 (NTSC)"),
    (b'H', "Netherlands"),
    (b'I', "Italy"),
    (b'J', "Japan"),
    (b'K', "Korea"),
    (b'L', "Gateway 64 (PAL)"),
    (b'N', "Canada"),
    (b'P', "Europe"),
    (b'S', "Spain"),
    (b'U', "Australia"),
    (b'W', "Scandinavia"),
    (b'X', "Europe"),
    (b'Y', "Europe"),
    (b'Z', "Europe"),
];

/// `stored` in native big-endian order. Swapped orders are copied, which
/// needs a size the swap divides and at most [`MAX_PAYLOAD`] bytes.
fn normalize(stored: &[u8], order: N64ByteOrder) -> Option<Cow<'_, [u8]>> {
    match order {
        N64ByteOrder::Native => Some(Cow::Borrowed(stored)),
        N64ByteOrder::ByteSwapped => Transform::Swap16.apply(stored).map(Cow::Owned),
        N64ByteOrder::WordSwapped => Transform::Swap32.apply(stored).map(Cow::Owned),
    }
}

/// The swap unit of a dump order, in bytes.
fn swap_unit(order: N64ByteOrder) -> usize {
    match order {
        N64ByteOrder::Native => 1,
        N64ByteOrder::ByteSwapped => 2,
        N64ByteOrder::WordSwapped => 4,
    }
}

/// One of the three first words, with the clock-rate low nibble of a
/// commercial header. Homebrew with other PI timing values is not
/// recognized.
pub(super) fn detect(data: &[u8]) -> Option<N64ByteOrder> {
    let signature = data.get(..SIGNATURE_SIZE)?;
    let order = FIRST_WORDS
        .iter()
        .find(|(_, word)| signature[..4] == *word)?
        .0;
    let native = normalize(signature, order)?;
    (native[CLOCK_RATE_LOW_BYTE] & 0x0F == CLOCK_RATE_NIBBLE).then_some(order)
}

/// An N64 check code, stored in the header or computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckCode {
    /// CRC1, the header word at 0x10.
    crc1: u32,
    /// CRC2, the header word at 0x14.
    crc2: u32,
}

/// The N64 check code (CRC1, CRC2) over the first MiB of game code, as
/// n64crc.c computes it; `code` must hold at least [`IPL3_COPY_SIZE`]
/// bytes and `ipl3` the whole IPL3, both in native order.
fn check_code(cic: &Cic, ipl3: &[u8], code: &[u8]) -> CheckCode {
    let [mut t1, mut t2, mut t3, mut t4, mut t5, mut t6] = [cic.seed; 6];
    for (i, word) in code[..IPL3_COPY_SIZE].chunks_exact(4).enumerate() {
        let d = u32::from_be_bytes(word.try_into().expect("chunks of 4 bytes"));
        let (sum, carry) = t6.overflowing_add(d);
        if carry {
            t4 = t4.wrapping_add(1);
        }
        t6 = sum;
        t3 ^= d;
        let r = d.rotate_left(d & 0x1F);
        t5 = t5.wrapping_add(r);
        if t2 > d {
            t2 ^= r;
        } else {
            t2 ^= t6 ^ d;
        }
        let mixed = if cic.ipl3_table {
            // The ROM offset is 0x1000 + 4 * i, so `offset & 0xFF` is
            // `4 * i & 0xFF`; the word lies inside IPL3.
            let at = CIC_6105_IPL3_TABLE + ((i * 4) & 0xFF);
            be_u32(ipl3, at).expect("IPL3 holds 0x710 + 0xFC + 4 bytes")
        } else {
            t5
        };
        t1 = t1.wrapping_add(mixed ^ d);
    }
    match cic.mix {
        Mix::Xor => CheckCode {
            crc1: t6 ^ t4 ^ t3,
            crc2: t5 ^ t2 ^ t1,
        },
        Mix::Add => CheckCode {
            crc1: (t6 ^ t4).wrapping_add(t3),
            crc2: (t5 ^ t2).wrapping_add(t1),
        },
        Mix::Multiply => CheckCode {
            crc1: t6.wrapping_mul(t4).wrapping_add(t3),
            crc2: t5.wrapping_mul(t2).wrapping_add(t1),
        },
    }
}

/// Parse an N64 ROM: IPL3 and the game code become code sections in
/// native byte order.
pub(super) fn parse(data: &[u8], order: N64ByteOrder) -> Result<Container<'_>> {
    let unit = swap_unit(order);
    if data.len() % unit != 0 {
        return Err(error(format!(
            "Invalid ROM size {} B: a {} dump must be a multiple of {unit} B",
            data.len(),
            extension(order)
        )));
    }
    if data.len() > MAX_PAYLOAD {
        return Err(ClassifierError::PayloadLimit { limit: MAX_PAYLOAD });
    }
    let header = normalized(data, "N64 header", 0, HEADER_SIZE, order)?;
    let ipl3 = normalized(data, "IPL3", IPL3.start, IPL3.len(), order)?;
    if data.len() == GAME_CODE_OFFSET {
        return Err(error(format!(
            "Missing game code: the file ends at 0x{GAME_CODE_OFFSET:X}"
        )));
    }
    let game_size = data.len() - GAME_CODE_OFFSET;
    let game = normalized(data, "game code", GAME_CODE_OFFSET, game_size, order)?;

    let boot_address = be_u32(&header, BOOT_ADDRESS)?;
    let ipl3_crc32 = checksum::crc32(&ipl3);
    let cic = CICS.iter().find(|cic| cic.ipl3_crc32 == ipl3_crc32);
    let entry = boot_address.wrapping_sub(cic.map_or(0, |cic| cic.boot_offset));

    let mut c = Container::new(FileFormat::N64Rom, VR4300, "n64");
    c.target = Some(MIPS64_BIG);
    c.entry = Some(u64::from(entry));
    c.consumed = data.len();
    c.code_sections = true;
    c.notes.push(order_note(order));
    c.notes
        .push(check_code_note(&header, cic, ipl3_crc32, &ipl3, &game)?);
    if entry == boot_address {
        c.notes
            .push(format!("Entry is the boot address 0x{entry:08X}"));
    } else {
        c.notes.push(format!(
            "Entry 0x{entry:08X}: the CIC {} IPL3 subtracts 0x{:X} from the boot address \
                0x{boot_address:08X} before jumping; the game code section is placed at the \
                entry, assuming the copy is adjusted the same way",
            cic.map_or("", |cic| cic.name),
            boot_address.wrapping_sub(entry)
        ));
    }
    c.notes.push(format!(
        "IPL3 copies the first {} of game code from 0x{GAME_CODE_OFFSET:X} to the entry address; \
            later ROM data is read by the game at run time",
        size_text(IPL3_COPY_SIZE as u64)
    ));
    c.notes
        .push("VR4300: a MIPS III implementation; RSP microcode in the ROM is not marked".into());
    push_metadata(&mut c, &header, cic, boot_address)?;
    let transform = (order != N64ByteOrder::Native).then_some(N64_BYTE_SWAP);
    c.sections.push(section(
        "IPL3 boot code",
        IPL3_ADDRESS,
        IPL3.start,
        ipl3,
        transform,
    ));
    c.sections.push(section(
        "Game code and data",
        u64::from(entry),
        GAME_CODE_OFFSET,
        game,
        transform,
    ));
    Ok(c)
}

/// The `size` stored bytes at `offset`, in native order.
fn normalized<'a>(
    data: &'a [u8],
    what: &str,
    offset: usize,
    size: usize,
    order: N64ByteOrder,
) -> Result<Cow<'a, [u8]>> {
    let stored = range(data, what, offset, size)?;
    normalize(stored, order).ok_or_else(|| {
        error(format!(
            "Invalid {what} size {size} B: not a multiple of the {} swap unit",
            extension(order)
        ))
    })
}

fn extension(order: N64ByteOrder) -> &'static str {
    match order {
        N64ByteOrder::Native => ".z64",
        N64ByteOrder::ByteSwapped => ".v64",
        N64ByteOrder::WordSwapped => ".n64",
    }
}

fn order_note(order: N64ByteOrder) -> String {
    match order {
        N64ByteOrder::Native => "Native big-endian byte order (.z64)".to_string(),
        N64ByteOrder::ByteSwapped => {
            "Bytes swapped within each 16-bit halfword (.v64); sections are normalized to \
                big-endian, stored offsets are unchanged"
                .to_string()
        }
        N64ByteOrder::WordSwapped => {
            "Bytes reversed within each 32-bit word (.n64); sections are normalized to \
                big-endian, stored offsets are unchanged"
                .to_string()
        }
    }
}

/// Verify the check code when the IPL3 identifies the CIC and the ROM holds
/// the whole checked range. A mismatch is reported, not rejected: the
/// algorithm is a reimplementation, not Nintendo's IPL3.
fn check_code_note(
    header: &[u8],
    cic: Option<&Cic>,
    ipl3_crc32: u32,
    ipl3: &[u8],
    game: &[u8],
) -> Result<String> {
    let stored = CheckCode {
        crc1: be_u32(header, CHECK_CODE_HIGH)?,
        crc2: be_u32(header, CHECK_CODE_LOW)?,
    };
    let Some(cic) = cic else {
        return Ok(format!(
            "IPL3 CRC-32 0x{ipl3_crc32:08X} matches no known CIC; check code 0x{:08X}{:08X} not \
                verified",
            stored.crc1, stored.crc2
        ));
    };
    if game.len() < IPL3_COPY_SIZE {
        return Ok(format!(
            "CIC {} IPL3; the ROM ends before 0x{:X}, so check code 0x{:08X}{:08X} is not verified",
            cic.name,
            GAME_CODE_OFFSET + IPL3_COPY_SIZE,
            stored.crc1,
            stored.crc2
        ));
    }
    let computed = check_code(cic, ipl3, game);
    Ok(if computed == stored {
        format!(
            "CIC {} IPL3; check code 0x{:08X}{:08X} verified over 0x1000-0x100FFF",
            cic.name, stored.crc1, stored.crc2
        )
    } else {
        format!(
            "CIC {} IPL3; check code 0x{:08X}{:08X} does not match the computed 0x{:08X}{:08X}",
            cic.name, stored.crc1, stored.crc2, computed.crc1, computed.crc2
        )
    })
}

/// libultra version: byte 2 is major * 10 + minor, byte 3 the revision
/// letter. Informational and often wrong (N64brew).
fn libultra_version(field: [u8; 4]) -> String {
    let [_, _, number, revision] = field;
    if number == 0 || !revision.is_ascii_uppercase() {
        return format!("unknown (0x{:08X})", u32::from_be_bytes(field));
    }
    format!("{}.{}{}", number / 10, number % 10, char::from(revision))
}

fn lookup(table: &[(u8, &'static str)], code: u8) -> String {
    table.iter().find(|(known, _)| *known == code).map_or_else(
        || format!("unknown (0x{code:02X})"),
        |(_, name)| (*name).to_string(),
    )
}

fn push_metadata(
    c: &mut Container<'_>,
    header: &[u8],
    cic: Option<&Cic>,
    boot_address: u32,
) -> Result<()> {
    c.push_metadata("n64_title", "Title", header_text(&header[TITLE]));
    c.push_metadata(
        "n64_game_code",
        "Game code",
        header_text(&header[GAME_CODE]),
    );
    c.push_metadata(
        "n64_category",
        "Category",
        lookup(&CATEGORIES, header[CATEGORY]),
    );
    c.push_metadata(
        "n64_destination",
        "Destination",
        lookup(&DESTINATIONS, header[DESTINATION]),
    );
    c.push_metadata(
        "n64_rom_version",
        "ROM version",
        u64::from(header[ROM_VERSION]),
    );
    c.push_metadata(
        "n64_boot_address",
        "Boot address",
        format!("0x{boot_address:08X}"),
    );
    let clock_rate = be_u32(header, CLOCK_RATE)? & CLOCK_RATE_MASK;
    c.push_metadata(
        "n64_clock_rate",
        "Clock rate field",
        if clock_rate == 0 {
            format!("default (0x{DEFAULT_CLOCK_RATE:08X})")
        } else {
            format!("0x{clock_rate:08X}")
        },
    );
    c.push_metadata(
        "n64_libultra_version",
        "libultra version (informational)",
        libultra_version(field(header, LIBULTRA_VERSION)?),
    );
    c.push_metadata(
        "n64_check_code",
        "Check code (CRC1 CRC2)",
        format!(
            "0x{:08X} 0x{:08X}",
            be_u32(header, CHECK_CODE_HIGH)?,
            be_u32(header, CHECK_CODE_LOW)?
        ),
    );
    c.push_metadata(
        "n64_cic",
        "CIC (from the IPL3 CRC-32)",
        cic.map_or("unknown", |cic| cic.name),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swapped_orders_normalize_to_the_native_first_word() {
        for (order, word) in FIRST_WORDS {
            let native = normalize(&word, order).expect("4 bytes");
            assert_eq!(*native, [0x80, 0x37, 0x12, 0x40], "{order:?}");
        }
    }

    #[test]
    fn libultra_versions_are_decimal_with_a_revision_letter() {
        assert_eq!(libultra_version([0, 0, 0x14, b'L']), "2.0L");
        assert_eq!(libultra_version([0, 0, 0, 0]), "unknown (0x00000000)");
    }

    #[test]
    fn check_code_of_zero_words_keeps_the_seed() {
        // With d = 0 every word: t2..t6 stay at the seed (rotate by 0 keeps
        // d) and t1 adds t5 ^ d = seed 0x40000 times.
        let ipl3 = vec![0u8; IPL3.len()];
        let code = vec![0u8; IPL3_COPY_SIZE];
        let cic = &CICS[1];
        let words = u32::try_from(IPL3_COPY_SIZE / 4).expect("0x40000 words fit in u32");
        let t1 = cic.seed.wrapping_mul(words + 1);
        assert_eq!(
            check_code(cic, &ipl3, &code),
            CheckCode {
                crc1: cic.seed,
                crc2: t1,
            }
        );
    }
}
