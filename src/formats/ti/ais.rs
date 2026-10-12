//! Application Image Script (SPRAB41): "TIPA", then little-endian commands
//! up to Jump & Close. Basic secure AIS (SPRUGQ9) starts with a key load,
//! encrypts load payloads and appends a signature to control commands.
use super::*;

const SECTION_LOAD: u32 = 0x5853_5901;
const VALIDATE_CRC: u32 = 0x5853_5902;
const ENABLE_CRC: u32 = 0x5853_5903;
const DISABLE_CRC: u32 = 0x5853_5904;
const JUMP: u32 = 0x5853_5905;
const JUMP_CLOSE: u32 = 0x5853_5906;
const SET: u32 = 0x5853_5907;
const SECTION_FILL: u32 = 0x5853_590a;
const FUNCTION_EXECUTE: u32 = 0x5853_590d;
const SEQUENTIAL_READ_ENABLE: u32 = 0x5853_5963;
const SECURE_KEY_LOAD: u32 = 0x5853_5920;
/// Both encrypted-load opcodes are (address, size, ciphertext).
const ENCRYPTED_SECTION_LOAD: u32 = 0x5853_5921;
const ENCRYPTED_SECTION_LOAD_ALT: u32 = 0x5853_5922;
const SET_EXIT_MODE: u32 = 0x5853_5923;

/// Size of the signature that follows each signed secure AIS command.
const SIGNATURE_SIZE: usize = 32;

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(b"TIPA") {
        return Err(error("Invalid AIS magic"));
    }
    let mut c = Container::new(Variant::Ais);
    let mut pos = 4;
    let mut commands = 0;
    let mut secure = false;
    loop {
        let op = le_u32(data, pos)?;
        pos += 4;
        commands += 1;
        match op {
            SECTION_LOAD => {
                let address = u64::from(le_u32(data, pos)?);
                let size = le_u32(data, pos + 4)? as usize;
                pos += 8;
                if address + size as u64 > 1u64 << 32 {
                    return Err(error("AIS destination overflow"));
                }
                c.push_section(address, pos, Cow::Borrowed(slice(data, pos, size)?))?;
                pos += align4(size)?;
                ensure(data, 0, pos)?;
            }
            SECTION_FILL => {
                let address = le_u32(data, pos)?;
                let size = le_u32(data, pos + 4)?;
                let width = le_u32(data, pos + 8)?;
                let pattern = le_u32(data, pos + 12)?;
                if width > 2 || u64::from(address) + u64::from(size) > 1u64 << 32 {
                    return Err(error("Invalid AIS fill range/type"));
                }
                c.notes.push(format!(
                    "Fill: byte address 0x{address:X}; {size} B; {}-bit pattern 0x{pattern:X} (not expanded)",
                    8 << width
                ));
                pos += 16;
            }
            ENABLE_CRC | DISABLE_CRC | SEQUENTIAL_READ_ENABLE => {}
            VALIDATE_CRC => {
                ensure(data, pos, 8)?;
                pos += 8;
                c.notes.push(
                    "AIS target CRC validation command present; target CRC is not verified".into(),
                );
            }
            JUMP => {
                let address = le_u32(data, pos)?;
                pos += 4;
                c.notes.push(format!("Intermediate jump to 0x{address:X}"));
            }
            JUMP_CLOSE => {
                c.entry = Some(u64::from(le_u32(data, pos)?));
                pos += 4;
            }
            FUNCTION_EXECUTE => {
                // The upper half of the function word counts its 32-bit arguments.
                let function = le_u32(data, pos)?;
                pos += 4;
                let arguments = (function >> 16) as usize * 4;
                ensure(data, pos, arguments)?;
                pos += arguments;
            }
            SET => {
                // Type, address, data and delay.
                ensure(data, pos, 16)?;
                pos += 16;
            }
            SECURE_KEY_LOAD => {
                if commands != 1 {
                    return Err(error("Secure AIS key-load command must be first"));
                }
                ensure(data, pos, 32)?;
                pos += 32;
                secure = true;
                c.opaque = true;
                c.notes.push("Basic secure AIS (SPRUGQ9); key records and signatures are not authenticated; encrypted sections are excluded from ISA analysis".into());
            }
            ENCRYPTED_SECTION_LOAD | ENCRYPTED_SECTION_LOAD_ALT if secure => {
                let address = le_u32(data, pos)?;
                let size = le_u32(data, pos + 4)? as usize;
                pos += 8;
                if u64::from(address) + size as u64 > 1u64 << 32 {
                    return Err(error("Encrypted AIS load address overflow"));
                }
                // Ciphertext is at least one 16-byte block, padded to 32 bits.
                let stored = align4(size.max(16))?;
                ensure(data, pos, stored)?;
                c.notes.push(format!(
                    "Encrypted load section: destination byte 0x{address:X}; {size} B decoded; {stored} B stored"
                ));
                pos += stored;
            }
            SET_EXIT_MODE if secure => {
                if le_u32(data, pos)? > 2 {
                    return Err(error("Unknown secure AIS exit mode"));
                }
                pos += 4;
            }
            _ => {
                return Err(error(format!(
                    "Unsupported AIS opcode 0x{op:08X} at 0x{:X}",
                    pos - 4
                )))
            }
        }
        let signed = matches!(
            op,
            JUMP | JUMP_CLOSE | SET | FUNCTION_EXECUTE | SET_EXIT_MODE
        );
        if secure && signed {
            ensure(data, pos, SIGNATURE_SIZE)?;
            pos += SIGNATURE_SIZE;
        }
        if op == JUMP_CLOSE {
            break;
        }
    }
    expect_padding(data, pos)?;
    c.consumed = pos;
    c.notes.push(format!(
        "{commands} AIS commands; headers and fills are excluded from code analysis"
    ));
    Ok(c)
}
