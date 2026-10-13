//! Nordic nRF5 DFU init packets: the `.dat` file of an nRF DFU ZIP package,
//! one `dfu.Packet` protocol buffer (proto2) that describes the firmware
//! image sent after it. The packet carries metadata only, no code.
//!
//! Sources: pc-nrfutil v6.1.7 (`804bc0ffa9929d4c74238eb7abdfb62ad660e122`)
//! `nordicsemi/dfu/dfu-cc.proto` (messages, field numbers, enums),
//! `init_packet_pb.py` and `package.py` (the `.dat` file is the serialized
//! `Packet`); nRF5 SDK 17.1.0 `components/libraries/bootloader/dfu/`
//! `dfu-cc.proto` and `dfu-cc.options` (field size limits),
//! `nrf_dfu_types.h` (`INIT_COMMAND_MAX_SIZE`) and `nrf_dfu_validation.c`
//! (`stored_init_cmd_decode`, `update_data_size_get`, `postvalidate`), read
//! from the `bluerange-io/bluerange-mesh` mirror at
//! `7131ad137182ea0bf429c63a816fb0e2e694df64` (`sdk/sdk17_1`).
//!
//! There is no magic, so a packet is recognized only when the whole input
//! parses with the documented field numbers and wire types, within the
//! bootloader's limits, and holds what the bootloader needs to accept it:
//! exactly one of `command` and `signed_command`, an `InitCommand`, a hash
//! and the firmware size its type requires. `hw_version` and `sd_req` name
//! devices and `SoftDevice` images, not an ISA. Signatures and the firmware
//! hash are reported and not verified (the image is a separate file).

use super::*;

/// The bootloader refuses longer init commands (`INIT_COMMAND_MAX_SIZE`).
const INIT_COMMAND_MAX_SIZE: usize = 512;

/// `dfu-cc.options` limits of the nRF5 SDK bootloader's decoder.
const HASH_MAX_SIZE: usize = 32;
const SIGNATURE_MAX_SIZE: usize = 64;
const SD_REQ_MAX_COUNT: usize = 16;
const BOOT_VALIDATION_MAX_COUNT: usize = 3;
const BOOT_VALIDATION_BYTES_MAX_SIZE: usize = 64;

/// Protobuf wire types: the packet uses only varints and length-delimited
/// fields.
const WIRE_VARINT: u64 = 0;
const WIRE_LEN: u64 = 2;

/// Field number in a key: the key shifted right past the 3-bit wire type.
const WIRE_TYPE_BITS: u32 = 3;
const WIRE_TYPE_MASK: u64 = 0x7;

/// Varints are groups of seven bits with a continuation bit; the tenth
/// group starts at bit 63.
const VARINT_CONTINUE: u8 = 0x80;
const VARINT_PAYLOAD: u8 = 0x7f;
const VARINT_GROUP_BITS: u32 = 7;
const LAST_VARINT_SHIFT: u32 = 63;

/// First byte of the two possible packets: the key of `Packet.command`
/// (field 1, length-delimited) or `Packet.signed_command` (field 2).
const COMMAND_KEY: u8 = 0x0a;
const SIGNED_COMMAND_KEY: u8 = 0x12;

/// `OpCode`: `INIT` (pc-nrfutil also defines `RESET` 0).
const OP_CODE_INIT: u64 = 1;

/// `FwType` values and bits.
const FW_TYPE_APPLICATION: u8 = 0;
const FW_TYPE_SOFTDEVICE: u8 = 1;
const FW_TYPE_BOOTLOADER: u8 = 2;
const FW_TYPE_EXTERNAL_APPLICATION: u8 = 4;

/// Enum names in `dfu-cc.proto` order.
const FW_TYPES: &[&str] = &[
    "APPLICATION",
    "SOFTDEVICE",
    "BOOTLOADER",
    "SOFTDEVICE_BOOTLOADER",
    "EXTERNAL_APPLICATION",
];
const HASH_TYPES: &[&str] = &["NO_HASH", "CRC", "SHA128", "SHA256", "SHA512"];
const VALIDATION_TYPES: &[&str] = &[
    "NO_VALIDATION",
    "VALIDATE_GENERATED_CRC",
    "VALIDATE_SHA256",
    "VALIDATE_ECDSA_P256_SHA256",
];
const SIGNATURE_TYPES: &[&str] = &["ECDSA_P256_SHA256", "ED25519"];

/// A field value of one of the two wire types the packet uses.
#[derive(Debug, Clone, Copy)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// One decoded field.
struct Field<'a> {
    number: u64,
    /// File offset of the field's key.
    offset: usize,
    /// File offset of the value (the first content byte of a
    /// length-delimited field).
    value_offset: usize,
    value: Value<'a>,
}

/// Reads the fields of one message, `bytes`, stored at file offset `base`.
struct Reader<'a> {
    bytes: &'a [u8],
    base: usize,
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            pos: 0,
        }
    }

    /// One varint: at most ten 7-bit groups, least significant first, that
    /// fit 64 bits.
    fn varint(&mut self) -> Result<u64> {
        let start = self.pos;
        let mut value = 0u64;
        let mut shift = 0u32;
        while shift < u64::BITS {
            let byte = *self.bytes.get(self.pos).ok_or_else(|| {
                error(format!(
                    "Truncated Nordic init packet varint at 0x{:X}",
                    self.base + start
                ))
            })?;
            self.pos += 1;
            let bits = u64::from(byte & VARINT_PAYLOAD);
            // The tenth group holds only the 64th bit.
            if shift == LAST_VARINT_SHIFT && bits > 1 {
                break;
            }
            value |= bits << shift;
            if byte & VARINT_CONTINUE == 0 {
                return Ok(value);
            }
            shift += VARINT_GROUP_BITS;
        }
        Err(error(format!(
            "Invalid Nordic init packet varint at 0x{:X}: more than 64 bits",
            self.base + start
        )))
    }

    /// The next field, or `None` at the end of the message.
    fn next_field(&mut self) -> Result<Option<Field<'a>>> {
        if self.pos == self.bytes.len() {
            return Ok(None);
        }
        let offset = self.base + self.pos;
        let key = self.varint()?;
        let number = key >> WIRE_TYPE_BITS;
        if number == 0 {
            return Err(error(format!(
                "Invalid Nordic init packet field number 0 at 0x{offset:X}"
            )));
        }
        let value_offset;
        let value = match key & WIRE_TYPE_MASK {
            WIRE_VARINT => {
                value_offset = self.base + self.pos;
                Value::Varint(self.varint()?)
            }
            WIRE_LEN => {
                let length = self.varint()?;
                value_offset = self.base + self.pos;
                let bytes = usize::try_from(length)
                    .ok()
                    .and_then(|length| self.bytes.get(self.pos..)?.get(..length))
                    .ok_or_else(|| {
                        error(format!(
                            "Truncated Nordic init packet field {number} at 0x{offset:X}: \
                             length {length} B"
                        ))
                    })?;
                self.pos += bytes.len();
                Value::Bytes(bytes)
            }
            other => {
                return Err(error(format!(
                    "Invalid Nordic init packet field {number} at 0x{offset:X}: wire type {other}"
                )))
            }
        };
        Ok(Some(Field {
            number,
            offset,
            value_offset,
            value,
        }))
    }
}

impl<'a> Field<'a> {
    /// A varint field, else a wire-type error naming `name`.
    fn varint(&self, name: &str) -> Result<u64> {
        match self.value {
            Value::Varint(value) => Ok(value),
            Value::Bytes(_) => Err(self.wire_type_error(name)),
        }
    }

    /// A length-delimited field, else a wire-type error naming `name`.
    fn bytes(&self, name: &str) -> Result<&'a [u8]> {
        match self.value {
            Value::Bytes(bytes) => Ok(bytes),
            Value::Varint(_) => Err(self.wire_type_error(name)),
        }
    }

    /// A `uint32` field.
    fn uint32(&self, name: &str) -> Result<u32> {
        let value = self.varint(name)?;
        u32::try_from(value).map_err(|_| {
            error(format!(
                "Invalid Nordic init packet {name} {value} at 0x{:X}: more than 32 bits",
                self.offset
            ))
        })
    }

    /// An enum field whose value names one of `names`.
    fn enumeration(&self, name: &str, names: &[&str]) -> Result<u8> {
        let value = self.varint(name)?;
        usize::try_from(value)
            .ok()
            .filter(|index| *index < names.len())
            .and_then(|index| u8::try_from(index).ok())
            .ok_or_else(|| {
                error(format!(
                    "Unknown Nordic init packet {name} {value} at 0x{:X}",
                    self.offset
                ))
            })
    }

    fn wire_type_error(&self, name: &str) -> ClassifierError {
        error(format!(
            "Invalid Nordic init packet {name} at 0x{:X}: wrong wire type",
            self.offset
        ))
    }

    fn unknown(&self, message: &str) -> ClassifierError {
        error(format!(
            "Unknown Nordic init packet {message} field {} at 0x{:X}",
            self.number, self.offset
        ))
    }
}

/// Store a singular field once; a repeated one is rejected, as no encoder
/// writes it.
fn set_once<T>(slot: &mut Option<T>, value: T, field: &Field<'_>, name: &str) -> Result<()> {
    if slot.is_some() {
        return Err(error(format!(
            "Duplicate Nordic init packet {name} at 0x{:X}",
            field.offset
        )));
    }
    *slot = Some(value);
    Ok(())
}

/// A required field of `message`, or a `Missing` error at the message's
/// offset.
fn required<T>(slot: Option<T>, message: &str, name: &str, offset: usize) -> Result<T> {
    slot.ok_or_else(|| {
        error(format!(
            "Missing Nordic init packet {message}.{name} in the message at 0x{offset:X}"
        ))
    })
}

/// `Hash`: `hash_type` (1), `hash` (2), both required.
struct Hash<'a> {
    hash_type: u8,
    hash: &'a [u8],
}

fn hash_message(bytes: &[u8], base: usize) -> Result<Hash<'_>> {
    let mut hash_type = None;
    let mut hash = None;
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => set_once(
                &mut hash_type,
                field.enumeration("hash_type", HASH_TYPES)?,
                &field,
                "hash_type",
            )?,
            2 => {
                let value = field.bytes("hash")?;
                if value.len() > HASH_MAX_SIZE {
                    return Err(error(format!(
                        "Invalid Nordic init packet hash at 0x{:X}: {} B, at most \
                         {HASH_MAX_SIZE} B",
                        field.offset,
                        value.len()
                    )));
                }
                set_once(&mut hash, value, &field, "hash")?;
            }
            _ => return Err(field.unknown("Hash")),
        }
    }
    Ok(Hash {
        hash_type: required(hash_type, "Hash", "hash_type", base)?,
        hash: required(hash, "Hash", "hash", base)?,
    })
}

/// `BootValidation`: `type` (1), `bytes` (2), both required.
struct BootValidation<'a> {
    kind: u8,
    bytes: &'a [u8],
}

fn boot_validation(bytes: &[u8], base: usize) -> Result<BootValidation<'_>> {
    let mut kind = None;
    let mut value = None;
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => set_once(
                &mut kind,
                field.enumeration("boot_validation type", VALIDATION_TYPES)?,
                &field,
                "boot_validation type",
            )?,
            2 => {
                let data = field.bytes("boot_validation bytes")?;
                if data.len() > BOOT_VALIDATION_BYTES_MAX_SIZE {
                    return Err(error(format!(
                        "Invalid Nordic init packet boot_validation bytes at 0x{:X}: {} B, at \
                         most {BOOT_VALIDATION_BYTES_MAX_SIZE} B",
                        field.offset,
                        data.len()
                    )));
                }
                set_once(&mut value, data, &field, "boot_validation bytes")?;
            }
            _ => return Err(field.unknown("BootValidation")),
        }
    }
    Ok(BootValidation {
        kind: required(kind, "BootValidation", "type", base)?,
        bytes: required(value, "BootValidation", "bytes", base)?,
    })
}

/// `InitCommand` fields 1-10.
#[derive(Default)]
struct InitCommand<'a> {
    fw_version: Option<u32>,
    hw_version: Option<u32>,
    sd_req: Vec<u32>,
    fw_type: Option<u8>,
    sd_size: Option<u32>,
    bl_size: Option<u32>,
    app_size: Option<u32>,
    hash: Option<Hash<'a>>,
    is_debug: Option<bool>,
    boot_validation: Vec<BootValidation<'a>>,
}

impl InitCommand<'_> {
    /// `type`, `APPLICATION` when absent (the proto2 default).
    fn fw_type(&self) -> u8 {
        self.fw_type.unwrap_or(FW_TYPE_APPLICATION)
    }

    /// The name of [`Self::fw_type`].
    fn fw_type_name(&self) -> &'static str {
        FW_TYPES[usize::from(self.fw_type())]
    }

    /// The firmware size the bootloader takes for this type
    /// (`update_data_size_get`): `app_size` for an application, else the
    /// `SoftDevice` and bootloader sizes the type's bits select.
    fn firmware_size(&self) -> u64 {
        let fw_type = self.fw_type();
        let is_application = matches!(fw_type, FW_TYPE_APPLICATION | FW_TYPE_EXTERNAL_APPLICATION);
        if is_application {
            if let Some(size) = self.app_size {
                return u64::from(size);
            }
        }
        let mut size = 0;
        if fw_type & FW_TYPE_SOFTDEVICE != 0 {
            size += u64::from(self.sd_size.unwrap_or(0));
        }
        if fw_type & FW_TYPE_BOOTLOADER != 0 {
            size += u64::from(self.bl_size.unwrap_or(0));
        }
        size
    }
}

fn init_command(bytes: &[u8], base: usize) -> Result<InitCommand<'_>> {
    let mut init = InitCommand::default();
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => set_once(
                &mut init.fw_version,
                field.uint32("fw_version")?,
                &field,
                "fw_version",
            )?,
            2 => set_once(
                &mut init.hw_version,
                field.uint32("hw_version")?,
                &field,
                "hw_version",
            )?,
            3 => sd_req(&mut init.sd_req, &field)?,
            4 => set_once(
                &mut init.fw_type,
                field.enumeration("type", FW_TYPES)?,
                &field,
                "type",
            )?,
            5 => set_once(
                &mut init.sd_size,
                field.uint32("sd_size")?,
                &field,
                "sd_size",
            )?,
            6 => set_once(
                &mut init.bl_size,
                field.uint32("bl_size")?,
                &field,
                "bl_size",
            )?,
            7 => set_once(
                &mut init.app_size,
                field.uint32("app_size")?,
                &field,
                "app_size",
            )?,
            8 => {
                let hash = hash_message(field.bytes("hash")?, field.value_offset)?;
                set_once(&mut init.hash, hash, &field, "hash")?;
            }
            9 => {
                let value = match field.varint("is_debug")? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(error(format!(
                            "Invalid Nordic init packet is_debug {other} at 0x{:X}",
                            field.offset
                        )))
                    }
                };
                set_once(&mut init.is_debug, value, &field, "is_debug")?;
            }
            10 => {
                if init.boot_validation.len() == BOOT_VALIDATION_MAX_COUNT {
                    return Err(error(format!(
                        "Invalid Nordic init packet boot_validation at 0x{:X}: more than \
                         {BOOT_VALIDATION_MAX_COUNT}",
                        field.offset
                    )));
                }
                let validation =
                    boot_validation(field.bytes("boot_validation")?, field.value_offset)?;
                init.boot_validation.push(validation);
            }
            _ => return Err(field.unknown("InitCommand")),
        }
    }
    Ok(init)
}

/// `sd_req`, packed (one length-delimited field of varints, as pc-nrfutil
/// writes it) or one varint per field; at most [`SD_REQ_MAX_COUNT`].
fn sd_req(values: &mut Vec<u32>, field: &Field<'_>) -> Result<()> {
    match field.value {
        Value::Varint(value) => push_sd_req(values, value, field.offset),
        Value::Bytes(packed) => {
            let mut reader = Reader::new(packed, field.value_offset);
            while reader.pos < packed.len() {
                let offset = reader.base + reader.pos;
                let value = reader.varint()?;
                push_sd_req(values, value, offset)?;
            }
            Ok(())
        }
    }
}

/// One `sd_req` value, read at `offset`.
fn push_sd_req(values: &mut Vec<u32>, value: u64, offset: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| {
        error(format!(
            "Invalid Nordic init packet sd_req {value} at 0x{offset:X}: more than 32 bits"
        ))
    })?;
    if values.len() == SD_REQ_MAX_COUNT {
        return Err(error(format!(
            "Invalid Nordic init packet sd_req at 0x{offset:X}: more than {SD_REQ_MAX_COUNT} \
             values"
        )));
    }
    values.push(value);
    Ok(())
}

/// `Command`: `op_code` (1), `init` (2) and pc-nrfutil's `reset` (3,
/// `ResetCommand` with a required `timeout`).
struct Command<'a> {
    init: Option<InitCommand<'a>>,
    /// `ResetCommand.timeout`.
    reset_timeout: Option<u32>,
}

fn command(bytes: &[u8], base: usize) -> Result<Command<'_>> {
    let mut op_code = None;
    let mut init = None;
    let mut reset_timeout = None;
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => {
                let value = field.varint("op_code")?;
                if value != OP_CODE_INIT {
                    return Err(error(format!(
                        "Unsupported Nordic DFU command op_code {value} at 0x{:X}; an init \
                         packet has INIT ({OP_CODE_INIT})",
                        field.offset
                    )));
                }
                set_once(&mut op_code, value, &field, "op_code")?;
            }
            2 => {
                let value = init_command(field.bytes("init")?, field.value_offset)?;
                set_once(&mut init, value, &field, "init")?;
            }
            3 => {
                let timeout = reset_command(field.bytes("reset")?, field.value_offset)?;
                set_once(&mut reset_timeout, timeout, &field, "reset")?;
            }
            _ => return Err(field.unknown("Command")),
        }
    }
    Ok(Command {
        init,
        reset_timeout,
    })
}

/// `ResetCommand`: `timeout` (1), required.
fn reset_command(bytes: &[u8], base: usize) -> Result<u32> {
    let mut timeout = None;
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => set_once(&mut timeout, field.uint32("timeout")?, &field, "timeout")?,
            _ => return Err(field.unknown("ResetCommand")),
        }
    }
    required(timeout, "ResetCommand", "timeout", base)
}

/// `SignedCommand.signature_type` (2) and `signature` (3).
struct Signature<'a> {
    kind: u8,
    bytes: &'a [u8],
}

/// `SignedCommand`: a command and its signature.
struct SignedCommand<'a> {
    command: Command<'a>,
    signature: Signature<'a>,
}

/// `SignedCommand`: `command` (1), `signature_type` (2), `signature` (3),
/// all required.
fn signed_command(bytes: &[u8], base: usize) -> Result<SignedCommand<'_>> {
    let mut inner = None;
    let mut kind = None;
    let mut signature = None;
    let mut reader = Reader::new(bytes, base);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => {
                let value = command(field.bytes("command")?, field.value_offset)?;
                set_once(&mut inner, value, &field, "command")?;
            }
            2 => set_once(
                &mut kind,
                field.enumeration("signature_type", SIGNATURE_TYPES)?,
                &field,
                "signature_type",
            )?,
            3 => {
                let value = field.bytes("signature")?;
                if value.len() > SIGNATURE_MAX_SIZE {
                    return Err(error(format!(
                        "Invalid Nordic init packet signature at 0x{:X}: {} B, at most \
                         {SIGNATURE_MAX_SIZE} B",
                        field.offset,
                        value.len()
                    )));
                }
                set_once(&mut signature, value, &field, "signature")?;
            }
            _ => return Err(field.unknown("SignedCommand")),
        }
    }
    Ok(SignedCommand {
        command: required(inner, "SignedCommand", "command", base)?,
        signature: Signature {
            kind: required(kind, "SignedCommand", "signature_type", base)?,
            bytes: required(signature, "SignedCommand", "signature", base)?,
        },
    })
}

/// `Packet`: exactly one of `command` (1) and `signed_command` (2), as
/// `stored_init_cmd_decode` requires.
struct Packet<'a> {
    command: Command<'a>,
    signature: Option<Signature<'a>>,
}

fn packet(data: &[u8]) -> Result<Packet<'_>> {
    let mut plain = None;
    let mut signed = None;
    let mut reader = Reader::new(data, 0);
    while let Some(field) = reader.next_field()? {
        match field.number {
            1 => {
                let value = command(field.bytes("command")?, field.value_offset)?;
                set_once(&mut plain, value, &field, "command")?;
            }
            2 => {
                let value = signed_command(field.bytes("signed_command")?, field.value_offset)?;
                set_once(&mut signed, value, &field, "signed_command")?;
            }
            _ => return Err(field.unknown("Packet")),
        }
    }
    match (plain, signed) {
        (Some(_), Some(_)) => Err(error(
            "Ambiguous Nordic init packet: both command and signed_command",
        )),
        (Some(command), None) => Ok(Packet {
            command,
            signature: None,
        }),
        (None, Some(signed)) => Ok(Packet {
            command: signed.command,
            signature: Some(signed.signature),
        }),
        (None, None) => Err(error("Missing Nordic init packet command")),
    }
}

/// Weak recognition: a packet-sized input that starts with a packet field
/// key and parses completely.
pub(super) fn detect(data: &[u8]) -> bool {
    data.len() <= INIT_COMMAND_MAX_SIZE
        && matches!(data.first(), Some(&(COMMAND_KEY | SIGNED_COMMAND_KEY)))
        && parse(data).is_ok()
}

/// Parse an init packet into a metadata-only container.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() > INIT_COMMAND_MAX_SIZE {
        return Err(error(format!(
            "Invalid Nordic init packet: {} B, at most {INIT_COMMAND_MAX_SIZE} B",
            data.len()
        )));
    }
    let packet = packet(data)?;
    let init = packet
        .command
        .init
        .as_ref()
        .ok_or_else(|| error("Missing Nordic init packet InitCommand"))?;
    let hash = init
        .hash
        .as_ref()
        .ok_or_else(|| error("Missing Nordic init packet firmware hash"))?;
    let fw_type = init.fw_type_name();
    let firmware_size = init.firmware_size();
    if firmware_size == 0 {
        return Err(error(format!(
            "Missing Nordic init packet firmware size for type {fw_type}"
        )));
    }
    let mut c = Container::new(
        FileFormat::NordicInitPacket,
        Layout::NordicInitPacket.label(),
        Layout::NordicInitPacket.key_prefix(),
    );
    c.consumed = data.len();
    c.opaque = true;
    let signing = match &packet.signature {
        Some(signature) => format!(
            "signed command ({}, {} B signature; not verified)",
            SIGNATURE_TYPES[usize::from(signature.kind)],
            signature.bytes.len()
        ),
        None => "unsigned command".to_string(),
    };
    c.notes.push(format!(
        "nRF DFU init packet: {signing}; firmware type {fw_type}, {firmware_size} B; the \
         packet describes a separate image and holds no code"
    ));
    c.notes.push(format!(
        "{} hash of the firmware image ({} B) present; not verified, the image is a separate \
         file",
        HASH_TYPES[usize::from(hash.hash_type)],
        hash.hash.len()
    ));
    c.notes
        .push("hw_version and sd_req name a device family and SoftDevices, not an ISA".to_string());
    if let Some(timeout) = packet.command.reset_timeout {
        c.notes.push(format!(
            "Command also carries a ResetCommand with timeout {timeout} (unit not documented)"
        ));
    }
    push_init_metadata(&mut c, init, hash, packet.signature.as_ref());
    Ok(c)
}

/// Every `InitCommand` field as metadata.
fn push_init_metadata(
    c: &mut Container<'_>,
    init: &InitCommand<'_>,
    hash: &Hash<'_>,
    signature: Option<&Signature<'_>>,
) {
    c.push_metadata("nordic_fw_type", "Firmware type", init.fw_type_name());
    if let Some(version) = init.fw_version {
        c.push_metadata("nordic_fw_version", "Firmware version", u64::from(version));
    }
    if let Some(version) = init.hw_version {
        c.push_metadata("nordic_hw_version", "Hardware version", u64::from(version));
    }
    if !init.sd_req.is_empty() {
        let ids: Vec<String> = init.sd_req.iter().map(|id| format!("0x{id:04X}")).collect();
        c.push_metadata("nordic_sd_req", "Required SoftDevices", ids.join(", "));
    }
    for (key, label, size) in [
        ("nordic_sd_size", "SoftDevice size (B)", init.sd_size),
        ("nordic_bl_size", "Bootloader size (B)", init.bl_size),
        ("nordic_app_size", "Application size (B)", init.app_size),
    ] {
        if let Some(size) = size {
            c.push_metadata(key, label, u64::from(size));
        }
    }
    c.push_metadata(
        "nordic_hash_type",
        "Hash type",
        HASH_TYPES[usize::from(hash.hash_type)],
    );
    c.push_metadata("nordic_hash", "Firmware hash", hex_string(hash.hash));
    if let Some(is_debug) = init.is_debug {
        c.push_metadata("nordic_is_debug", "Debug build", is_debug.to_string());
    }
    for (i, validation) in init.boot_validation.iter().enumerate() {
        c.push_metadata(
            format!("nordic_boot_validation_{i}"),
            format!("Boot validation {}", i + 1),
            format!(
                "{}; {} B",
                VALIDATION_TYPES[usize::from(validation.kind)],
                validation.bytes.len()
            ),
        );
    }
    let signature_text = match signature {
        Some(signature) => format!(
            "{}; {} B; not verified",
            SIGNATURE_TYPES[usize::from(signature.kind)],
            signature.bytes.len()
        ),
        None => "none".to_string(),
    };
    c.push_metadata("nordic_signature", "Signature", signature_text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_bounded_to_64_bits() {
        let mut reader = Reader::new(&[0xac, 0x02], 0);
        assert_eq!(reader.varint().unwrap(), 300);
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(Reader::new(&max, 0).varint().unwrap(), u64::MAX);
        let too_wide = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert!(Reader::new(&too_wide, 0).varint().is_err());
        let too_long = [0x80; 11];
        assert!(Reader::new(&too_long, 0).varint().is_err());
        assert!(Reader::new(&[0x80], 0).varint().is_err());
    }

    #[test]
    fn fields_reject_unused_wire_types_and_field_zero() {
        // Field 1, 64-bit wire type.
        assert!(Reader::new(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0], 0)
            .next_field()
            .is_err());
        // Field 0, varint.
        assert!(Reader::new(&[0x00, 0x01], 0).next_field().is_err());
        // Field 2, length 3 with 1 byte left.
        assert!(Reader::new(&[0x12, 0x03, 0x00], 0).next_field().is_err());
        let field = Reader::new(&[0x10, 0x34], 0).next_field().unwrap().unwrap();
        assert_eq!(field.number, 2);
        assert_eq!(field.varint("x").unwrap(), 0x34);
        assert!(field.bytes("x").is_err());
    }

    #[test]
    fn firmware_size_follows_the_bootloader() {
        let mut init = InitCommand {
            app_size: Some(100),
            ..InitCommand::default()
        };
        assert_eq!(init.firmware_size(), 100);
        init.fw_type = Some(FW_TYPE_SOFTDEVICE | FW_TYPE_BOOTLOADER);
        init.sd_size = Some(10);
        init.bl_size = Some(20);
        assert_eq!(init.firmware_size(), 30);
        init.fw_type = Some(FW_TYPE_EXTERNAL_APPLICATION);
        init.app_size = None;
        assert_eq!(init.firmware_size(), 0);
    }
}
