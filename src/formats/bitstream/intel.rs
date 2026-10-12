//! Intel (Altera) configuration files: Cyclone V raw binary files (`.rbf`)
//! in the layout mistral writes (`libmistral/cv-opt.cc` `oram_save`,
//! `libmistral/cv-files.cc` `crc16`, commit `d509238a`) and programmer
//! object files (`.pof`, openFPGALoader v1.1.1 `src/pofParser.cpp`). Both
//! layouts come from community reverse engineering; Intel publishes
//! neither.
//!
//! Cyclone V option frame: `0xFF` fill (0x80 B), the marker `jjjj` at 0x80,
//! option RAM at 0x84 (0xA0 B), two zero bytes at 0x124, then a
//! little-endian CRC-16/MODBUS over 0x84..0x126 at 0x126. The rest of the
//! file (option-frame fill, PRAM and CRAM frames) depends on device tables
//! that are not encoded in the file and is not walked.
//!
//! POF: the magic `POF\0`, an unknown 32-bit field, a 32-bit packet count,
//! then packets of a 16-bit tag, a 32-bit length and the payload, all
//! little-endian, to the end of the file.

use super::*;
use crate::formats::checksum::crc16_modbus;

/// Bytes of `0xFF` fill at the start of a Cyclone V `.rbf`.
const RBF_FILL_SIZE: usize = 0x80;

/// Marker after the fill (mistral writes `'j'` four times).
const RBF_MARKER_OFFSET: usize = 0x80;
const RBF_MARKER: &[u8; 4] = b"jjjj";

/// Option RAM: 32 strips of 40 bits.
const OPTION_RAM_OFFSET: usize = 0x84;

/// Two zero bytes after the option RAM, covered by the CRC.
const OPTION_ZERO_OFFSET: usize = 0x124;

/// Little-endian CRC-16 over the option RAM and the zero bytes.
const OPTION_CRC_OFFSET: usize = 0x126;

/// End of the checked part of the option frame.
const OPTION_FRAME_CHECKED_SIZE: usize = 0x128;

/// POF magic.
const POF_MAGIC: &[u8; 4] = b"POF\0";

/// POF header: magic, an unknown field, the packet count.
const POF_COUNT_OFFSET: usize = 8;
const POF_HEADER_SIZE: usize = 12;

/// POF packet header: 16-bit tag and 32-bit length.
const POF_PACKET_HEADER_SIZE: usize = 6;

/// POF packet tags (openFPGALoader `pofParser.cpp`).
const TAG_TOOL: u16 = 0x01;
const TAG_PART: u16 = 0x02;
const TAG_DESIGN: u16 = 0x03;
/// The last packet; openFPGALoader reads a 16-bit value it calls
/// "maybeCRC".
const TAG_LAST: u16 = 0x08;
/// Twelve unknown bytes, then the configuration data.
const TAG_CONFIGURATION: u16 = 0x11;
/// The usercode is the last four bytes.
const TAG_USERCODE: u16 = 0x13;
/// MAX 10 flash section list.
const TAG_FLASH_SECTIONS: u16 = 0x1a;

/// Bytes of a usercode.
const USERCODE_SIZE: usize = 4;

/// Strings and values a POF's packets carry.
#[derive(Debug, Default)]
struct PofPackets<'a> {
    tool: Option<String>,
    part: Option<String>,
    design: Option<String>,
    usercode: Option<u32>,
    last_value: Option<u16>,
    flash_sections: bool,
    /// Packets with a tag openFPGALoader does not interpret.
    unknown: usize,
    /// All packets.
    count: usize,
    /// Configuration data packets: file offset and payload.
    configuration: Vec<(usize, &'a [u8])>,
}

/// Is `data` a POF? The magic is the whole strong check; the packet chain
/// is validated by [`parse_pof`].
pub(super) fn is_pof(data: &[u8]) -> bool {
    data.starts_with(POF_MAGIC)
}

/// Weak recognition of a Cyclone V `.rbf`: the complete option frame with
/// its CRC.
pub(super) fn detect_rbf(data: &[u8]) -> Option<Layout> {
    check_option_frame(data).ok().map(|_| Layout::CycloneVRbf)
}

/// Parse a Cyclone V `.rbf`: the option frame is checked, the rest is
/// opaque configuration data.
pub(super) fn parse_rbf(data: &[u8]) -> Result<Container<'_>> {
    let crc = check_option_frame(data)?;
    let mut c = new_container(Layout::CycloneVRbf);
    c.notes.push(format!(
        "Option frame: 0xFF fill, marker 'jjjj' at 0x{RBF_MARKER_OFFSET:X}, option RAM at 0x{OPTION_RAM_OFFSET:X}; CRC-16 0x{crc:04X} verified"
    ));
    c.notes.push(
        "Layout from mistral (community reverse engineering of Cyclone V); device, compression and frame CRCs are not decoded"
            .into(),
    );
    c.push_metadata(
        "bitstream_option_crc",
        "Option RAM CRC-16",
        format!("0x{crc:04X}"),
    );
    Ok(finish(c, data, 0, data, data.len()))
}

/// Parse a POF: every packet to the end of the file; configuration data
/// packets are opaque components.
pub(super) fn parse_pof(data: &[u8]) -> Result<Container<'_>> {
    if !is_pof(data) {
        return Err(error("Missing POF magic at 0x0"));
    }
    let declared = le_u32(data, POF_COUNT_OFFSET)?;
    let packets = parse_packets(data)?;

    let mut c = new_container(Layout::Pof);
    c.notes.push(
        "Layout from openFPGALoader (community reverse engineering); packet tags are partly understood"
            .into(),
    );
    let fields = [
        ("bitstream_tool", "Tool", &packets.tool),
        ("bitstream_part", "Part", &packets.part),
        ("bitstream_design_name", "Design name", &packets.design),
    ];
    for (key, label, value) in fields {
        if let Some(value) = value {
            c.notes.push(format!("{label}: {value}"));
            c.push_metadata(key, label, value.as_str());
        }
    }
    if let Some(usercode) = packets.usercode {
        c.notes.push(format!("Usercode: 0x{usercode:08X}"));
        c.push_metadata(
            "bitstream_usercode",
            "Usercode",
            format!("0x{usercode:08X}"),
        );
    }
    if let Some(value) = packets.last_value {
        c.notes.push(format!(
            "Last packet value 0x{value:04X}; possibly a CRC, not verified"
        ));
    }
    if packets.flash_sections {
        c.notes.push("Flash section list present (MAX 10)".into());
    }
    let packet_count = count(packets.count, "packet", "packets");
    c.notes.push(match packets.unknown {
        0 => packet_count,
        unknown => {
            format!("{packet_count}; {unknown} with tags whose meaning is not established")
        }
    });
    if u64::from(declared) != packets.count as u64 {
        c.notes.push(format!(
            "Header packet count {declared} differs from the {} packets present; the field's meaning is not established",
            packets.count
        ));
    }
    if packets.configuration.is_empty() {
        c.notes
            .push("No configuration data packet (tag 0x11)".into());
    }
    for (i, &(offset, payload)) in packets.configuration.iter().enumerate() {
        let label = if i == 0 {
            CONFIGURATION_DATA.to_string()
        } else {
            format!("{CONFIGURATION_DATA} {}", i + 1)
        };
        c.children.push(Child::opaque(label, offset, payload));
    }
    c.consumed = data.len();
    c.opaque = true;
    Ok(c)
}

/// Check the Cyclone V option frame and return its CRC.
fn check_option_frame(data: &[u8]) -> Result<u16> {
    if data.len() < OPTION_FRAME_CHECKED_SIZE {
        return Err(error(format!(
            "Truncated Cyclone V option frame: {} B present, {OPTION_FRAME_CHECKED_SIZE} B needed",
            data.len()
        )));
    }
    if let Some(at) = data[..RBF_FILL_SIZE].iter().position(|&b| b != 0xff) {
        return Err(error(format!("Invalid Cyclone V fill at 0x{at:X}")));
    }
    if &data[RBF_MARKER_OFFSET..OPTION_RAM_OFFSET] != RBF_MARKER {
        return Err(error(format!(
            "Missing Cyclone V marker 'jjjj' at 0x{RBF_MARKER_OFFSET:X}"
        )));
    }
    if be_u16(data, OPTION_ZERO_OFFSET)? != 0 {
        return Err(error(format!(
            "Invalid Cyclone V option frame at 0x{OPTION_ZERO_OFFSET:X}: expected two zero bytes"
        )));
    }
    let stored = le_u16(data, OPTION_CRC_OFFSET)?;
    let computed = crc16_modbus(&data[OPTION_RAM_OFFSET..OPTION_CRC_OFFSET]);
    if stored != computed {
        return Err(error(format!(
            "Invalid Cyclone V option RAM CRC-16: stored 0x{stored:04X}, computed 0x{computed:04X}"
        )));
    }
    Ok(stored)
}

/// The POF packets from offset 12 to the end of the file. Every packet
/// must lie within the file; each one advances by at least its 6-byte
/// header, so the walk ends.
fn parse_packets(data: &[u8]) -> Result<PofPackets<'_>> {
    let mut packets = PofPackets::default();
    let mut pos = POF_HEADER_SIZE;
    while pos < data.len() {
        if data.len() - pos < POF_PACKET_HEADER_SIZE {
            return Err(error(format!("Truncated POF packet header at 0x{pos:X}")));
        }
        let tag = le_u16(data, pos)?;
        let len = usize::try_from(le_u32(data, pos + 2)?)
            .map_err(|_| error(format!("Invalid POF packet length at 0x{pos:X}")))?;
        let body = pos + POF_PACKET_HEADER_SIZE;
        let payload = slice(data, body, len).map_err(|_| {
            error(format!(
                "Truncated POF packet 0x{tag:04X} at 0x{pos:X}: {len} B declared, {} B present",
                data.len().saturating_sub(body)
            ))
        })?;
        match tag {
            TAG_TOOL => packets.tool = Some(text(payload)),
            TAG_PART => packets.part = Some(text(payload)),
            TAG_DESIGN => packets.design = Some(text(payload)),
            TAG_LAST => packets.last_value = Some(le_u16(payload, 0)?),
            TAG_CONFIGURATION => packets.configuration.push((body, payload)),
            TAG_USERCODE => {
                let at = payload
                    .len()
                    .checked_sub(USERCODE_SIZE)
                    .ok_or_else(|| error(format!("Truncated POF usercode packet at 0x{pos:X}")))?;
                packets.usercode = Some(le_u32(payload, at)?);
            }
            TAG_FLASH_SECTIONS => packets.flash_sections = true,
            _ => packets.unknown += 1,
        }
        packets.count += 1;
        pos = body + len;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Cyclone V option frame with the given option RAM byte at 0x84.
    fn option_frame(first: u8) -> Vec<u8> {
        let mut data = vec![0xff; RBF_FILL_SIZE];
        data.extend_from_slice(RBF_MARKER);
        let mut option_ram = vec![0u8; OPTION_ZERO_OFFSET - OPTION_RAM_OFFSET + 2];
        option_ram[0] = first;
        let crc = crc16_modbus(&option_ram);
        data.extend_from_slice(&option_ram);
        data.extend_from_slice(&crc.to_le_bytes());
        data.extend_from_slice(&[0xff; 16]);
        data
    }

    #[test]
    fn option_frame_crc_covers_the_option_ram_and_zero_bytes() {
        let data = option_frame(0x80);
        assert_eq!(detect_rbf(&data), Some(Layout::CycloneVRbf));
        let mut corrupt = data.clone();
        corrupt[0x90] ^= 1;
        assert!(check_option_frame(&corrupt).is_err());
        let mut zero = data.clone();
        zero[OPTION_ZERO_OFFSET] = 1;
        assert!(check_option_frame(&zero).is_err());
        assert!(check_option_frame(&data[..OPTION_FRAME_CHECKED_SIZE - 1]).is_err());
    }

    #[test]
    fn pof_packets_must_fit_the_file() {
        let mut data = POF_MAGIC.to_vec();
        data.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        data.extend_from_slice(&TAG_PART.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(b"10M08");
        let packets = parse_packets(&data).expect("valid packets");
        assert_eq!(packets.part.as_deref(), Some("10M08"));
        assert_eq!(packets.count, 1);
        assert!(parse_packets(&data[..data.len() - 1]).is_err());
    }
}
