//! Sega Saturn `IP.BIN`: the initial program at the start of a disc's system
//! area (Sega ST-040-R4-051795 "Disc Format Standards Specification Sheet"
//! §4).
//!
//! The IP is the system ID (0x100 bytes), the security code (0xD00 bytes of
//! Sega object code, `SYS_SEC.OBJ`), the area code group (0x20-0x100 bytes,
//! `SYS_ARE?.OBJ`) and the application initial program (Table 4.1). System
//! ID (Figure 4.1, §4.3): hardware identifier `SEGA SEGASATURN ` (16), maker
//! ID (16) at 0x10, product number (10) at 0x20, version (6) at 0x2A, release
//! date (8) at 0x30, device information (8) at 0x38, compatible area symbols
//! (10) at 0x40, compatible peripherals (16) at 0x50, game title (112) at
//! 0x60, IP size (4) at 0xE0 (0x1000-0x8000, long-word aligned), Stack-M (4)
//! at 0xE8, Stack-S (4) at 0xEC, 1st read address (4) at 0xF0 and 1st read
//! size (4) at 0xF4. The long words are big-endian (Yabause
//! `YabauseQuickLoadGame` reads the IP size and 1st read address
//! big-endian; the SH-2 is big-endian, SH7604 Hardware Manual §2.2.2).
//!
//! The IP is linked at 0x06002000 (ST-040 sample linker script); Yabause
//! copies it there and starts the master SH-2 at 0x06002E00, after the
//! system ID and the security code. The Saturn has two SH-2 CPUs (ST-103
//! "SH-2 X 2"); the Sega documents fetched do not name a part number.

use super::*;

/// Hardware identifier at offset 0.
const HARDWARE_ID: &[u8; 16] = b"SEGA SEGASATURN ";

/// System ID fields: offset and size.
const MAKER_ID: (usize, usize) = (0x10, 16);
const PRODUCT_NUMBER: (usize, usize) = (0x20, 10);
const VERSION: (usize, usize) = (0x2a, 6);
const RELEASE_DATE: (usize, usize) = (0x30, 8);
const DEVICE_INFO: (usize, usize) = (0x38, 8);
const AREA_SYMBOLS: (usize, usize) = (0x40, 10);
const PERIPHERALS: (usize, usize) = (0x50, 16);
const TITLE: (usize, usize) = (0x60, 112);
const IP_SIZE: usize = 0xe0;
const STACK_M: usize = 0xe8;
const STACK_S: usize = 0xec;
const FIRST_READ_ADDRESS: usize = 0xf0;
const FIRST_READ_SIZE: usize = 0xf4;

/// The system ID and the security code that follows it (Table 4.1).
const SYSTEM_ID_SIZE: usize = 0x100;
const SECURITY_CODE_SIZE: usize = 0xd00;
const AREA_CODES: usize = SYSTEM_ID_SIZE + SECURITY_CODE_SIZE;

/// IP size range (§4.3 "IP SIZE"); parameters are long-word aligned.
const MIN_IP_SIZE: u32 = 0x1000;
const MAX_IP_SIZE: u32 = 0x8000;
const LONG_WORD: u32 = 4;

/// Where the IP is linked and loaded, and where Yabause starts it.
const LOAD_ADDRESS: u64 = 0x0600_2000;
const ENTRY: u64 = LOAD_ADDRESS + AREA_CODES as u64;

/// Compatible area symbols (§4.3).
const AREAS: [(u8, &str); 4] = [
    (b'J', "Japan"),
    (b'T', "Asia NTSC"),
    (b'U', "North America"),
    (b'E', "Europe PAL"),
];

pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(HARDWARE_ID)
}

fn field_text(data: &[u8], (offset, size): (usize, usize)) -> String {
    header_text(&data[offset..offset + size])
}

/// The IP size, which must be an aligned value in the documented range.
fn ip_size(data: &[u8]) -> Result<usize> {
    let size = be_u32(data, IP_SIZE)?;
    if !(MIN_IP_SIZE..=MAX_IP_SIZE).contains(&size) || size % LONG_WORD != 0 {
        return Err(error(format!(
            "Invalid IP size 0x{size:X} at 0x{IP_SIZE:X}: not a multiple of 4 from 0x{MIN_IP_SIZE:X} \
                to 0x{MAX_IP_SIZE:X}"
        )));
    }
    Ok(size as usize)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    range(data, "Saturn system ID", 0, SYSTEM_ID_SIZE)?;
    if !detect(data) {
        return Err(error("Missing Saturn hardware identifier SEGA SEGASATURN"));
    }
    let size = ip_size(data)?;
    let ip = range(data, "Saturn IP", 0, size)?;

    let mut c = Container::new(FileFormat::SaturnIp, "SH-2", "saturn");
    c.target = Some(SH2);
    c.entry = Some(ENTRY);
    c.consumed = size;
    c.code_sections = true;
    push_system_id_notes(&mut c, data)?;
    c.notes.push(format!(
        "IP of {} loaded at 0x{LOAD_ADDRESS:08X}; entry 0x{ENTRY:08X} after the security code \
            (Yabause)",
        size_text(size as u64)
    ));
    c.notes
        .push("The header names no CPU; the Saturn runs two big-endian SH-2 CPUs (ST-103)".into());
    let rest = data.len() - size;
    if rest > 0 {
        c.notes.push(format!(
            "{} follow the IP at 0x{size:X} and are not analyzed (a disc image continues with the \
                rest of the system area and the file system)",
            size_text(rest as u64)
        ));
    }
    c.push_metadata("saturn_ip_size", "IP size", size_text(size as u64));
    c.sections.push(stored_section(
        "Security code",
        LOAD_ADDRESS + SYSTEM_ID_SIZE as u64,
        SYSTEM_ID_SIZE,
        &ip[SYSTEM_ID_SIZE..AREA_CODES],
    ));
    c.sections.push(stored_section(
        "Area codes and application initial program",
        ENTRY,
        AREA_CODES,
        &ip[AREA_CODES..],
    ));
    Ok(c)
}

fn push_system_id_notes(c: &mut Container<'_>, data: &[u8]) -> Result<()> {
    let product = field_text(data, PRODUCT_NUMBER);
    let version = field_text(data, VERSION);
    let release = field_text(data, RELEASE_DATE);
    c.notes.push(format!(
        "Saturn IP.BIN; product {product}; version {version}; release date {release}; device \
            info {}",
        field_text(data, DEVICE_INFO)
    ));
    c.notes.push(format!(
        "Title: {}; maker ID: {}",
        field_text(data, TITLE),
        field_text(data, MAKER_ID)
    ));
    let symbols = &data[AREA_SYMBOLS.0..AREA_SYMBOLS.0 + AREA_SYMBOLS.1];
    let areas: Vec<String> = symbols
        .iter()
        .filter(|&&b| b != b' ' && b != 0)
        .map(|&b| {
            AREAS.iter().find(|(symbol, _)| *symbol == b).map_or_else(
                || format!("unknown symbol 0x{b:02X}"),
                |(_, name)| (*name).to_string(),
            )
        })
        .collect();
    let listed = if areas.is_empty() {
        "none".to_string()
    } else {
        areas.join(", ")
    };
    c.notes.push(format!(
        "Compatible areas: {listed}; peripherals: {}",
        field_text(data, PERIPHERALS)
    ));
    let stack_m = be_u32(data, STACK_M)?;
    let stack_s = be_u32(data, STACK_S)?;
    let first_read = be_u32(data, FIRST_READ_ADDRESS)?;
    let first_read_size = be_u32(data, FIRST_READ_SIZE)?;
    c.notes.push(format!(
        "Stack-M 0x{stack_m:08X}; Stack-S 0x{stack_s:08X} (0 selects the default stack area)"
    ));
    if first_read == 0 {
        c.notes
            .push("No 1st read file is transferred (1st read address 0)".into());
    } else {
        c.notes.push(format!(
            "1st read file (file identifier 2 on the disc) is transferred to 0x{first_read:08X}; \
                1st read size 0x{first_read_size:X}; it is not part of the IP"
        ));
    }
    for (name, value) in [
        ("Stack-M", stack_m),
        ("Stack-S", stack_s),
        ("1st read address", first_read),
    ] {
        if value % LONG_WORD != 0 {
            c.notes.push(format!(
                "{name} 0x{value:08X} is not long-word aligned, as ST-040 requires"
            ));
        }
    }
    c.push_metadata("saturn_product_number", "Product number", product);
    c.push_metadata("saturn_version", "Version", version);
    c.push_metadata("saturn_release_date", "Release date", release);
    c.push_metadata(
        "saturn_area_symbols",
        "Compatible area symbols",
        field_text(data, AREA_SYMBOLS),
    );
    c.push_metadata(
        "saturn_first_read_address",
        "1st read address",
        format!("0x{first_read:08X}"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_size_must_be_aligned_and_in_range() {
        let mut data = vec![0u8; SYSTEM_ID_SIZE];
        data[IP_SIZE..IP_SIZE + 4].copy_from_slice(&0x1800u32.to_be_bytes());
        assert_eq!(ip_size(&data).unwrap(), 0x1800);
        data[IP_SIZE..IP_SIZE + 4].copy_from_slice(&0x1802u32.to_be_bytes());
        assert!(ip_size(&data).is_err());
        data[IP_SIZE..IP_SIZE + 4].copy_from_slice(&0x8004u32.to_be_bytes());
        assert!(ip_size(&data).is_err());
    }

    #[test]
    fn the_entry_follows_the_security_code() {
        assert_eq!(ENTRY, 0x0600_2e00);
    }
}
