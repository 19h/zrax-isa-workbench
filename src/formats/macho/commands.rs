//! The load-command walk and the fixed-size commands.
//!
//! Each command starts with `cmd` (4) and `cmdsize` (4). xnu `loader.h`
//! requires `cmdsize` to be a multiple of 4 (32-bit) or 8 (64-bit); dyld-1378
//! `MachOFile::forEachLoadCommand` enforces at least 8 B, a multiple of 4
//! (its comment defers the 8-byte rule for compatibility) and the end within
//! `sizeofcmds`. These checks follow dyld.

use super::*;

/// `load_command`: `cmd` and `cmdsize`.
const LOAD_COMMAND_SIZE: usize = 8;

/// `cmdsize` granularity dyld enforces.
const COMMAND_ALIGNMENT: u32 = 4;

/// Load command types (`loader.h`); `LC_REQ_DYLD` is part of the value.
pub(super) const LC_SEGMENT: u32 = 0x1;
pub(super) const LC_UNIXTHREAD: u32 = 0x5;
pub(super) const LC_SEGMENT_64: u32 = 0x19;
pub(super) const LC_UUID: u32 = 0x1B;
pub(super) const LC_CODE_SIGNATURE: u32 = 0x1D;
pub(super) const LC_ENCRYPTION_INFO: u32 = 0x21;
pub(super) const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub(super) const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub(super) const LC_MAIN: u32 = 0x8000_0028;
pub(super) const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub(super) const LC_VERSION_MIN_TVOS: u32 = 0x2F;
pub(super) const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub(super) const LC_BUILD_VERSION: u32 = 0x32;
pub(super) const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
pub(super) const LC_FILESET_ENTRY: u32 = 0x8000_0035;

/// Structure sizes of the fixed-size commands read here.
const UUID_COMMAND_SIZE: usize = 24;
const LINKEDIT_DATA_COMMAND_SIZE: usize = 16;
const ENCRYPTION_INFO_COMMAND_SIZE: usize = 20;
const ENCRYPTION_INFO_COMMAND_64_SIZE: usize = 24;
const ENTRY_POINT_COMMAND_SIZE: usize = 24;
const FILESET_ENTRY_COMMAND_SIZE: usize = 32;

/// One load command: its type, its index and file offset, and its
/// `cmdsize` bytes.
pub(super) struct Command<'a> {
    /// `cmd`.
    pub(super) cmd: u32,
    /// Position in the command list.
    pub(super) index: usize,
    /// File offset of the command.
    pub(super) offset: usize,
    /// The whole command, `cmdsize` bytes.
    pub(super) bytes: &'a [u8],
    /// The image is little-endian.
    pub(super) little_endian: bool,
}

impl Command<'_> {
    /// The command's `loader.h` name, or its value in hex.
    pub(super) fn name(&self) -> String {
        command_name(self.cmd)
            .map_or_else(|| format!("load command 0x{:X}", self.cmd), String::from)
    }

    /// An error unless the command holds its `size`-byte structure.
    pub(super) fn expect_size(&self, size: usize) -> Result<()> {
        if self.bytes.len() < size {
            return Err(error(format!(
                "Invalid {} at 0x{:X}: cmdsize {} B is smaller than its {size} B structure",
                self.name(),
                self.offset,
                self.bytes.len()
            )));
        }
        Ok(())
    }

    /// The `u32` at `at` within the command.
    pub(super) fn u32_at(&self, at: usize) -> Result<u32> {
        read_u32(self.bytes, at, self.little_endian)
    }

    /// The `u64` at `at` within the command.
    pub(super) fn u64_at(&self, at: usize) -> Result<u64> {
        read_u64(self.bytes, at, self.little_endian)
    }
}

/// The `loader.h` name of a command this parser reads.
pub(super) fn command_name(cmd: u32) -> Option<&'static str> {
    let name = match cmd {
        LC_SEGMENT => "LC_SEGMENT",
        LC_UNIXTHREAD => "LC_UNIXTHREAD",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_UUID => "LC_UUID",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_MAIN => "LC_MAIN",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        LC_FILESET_ENTRY => "LC_FILESET_ENTRY",
        _ => return None,
    };
    Some(name)
}

/// Split the load-command region after `header` into commands: the region
/// `[header end, header end + sizeofcmds)` must lie in `data`, `ncmds`
/// commands of at least 8 B must fit it, and each `cmdsize` must be a
/// multiple of 4 that ends inside it.
fn split_commands<'a>(data: &'a [u8], header: &Header) -> Result<Vec<Command<'a>>> {
    let start = header.offset + header.size();
    let size = header.commands_size as usize;
    let region = start
        .checked_add(size)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| {
            error(format!(
                "Truncated load commands: sizeofcmds {size} B at 0x{start:X} exceeds the input ({} B)",
                data.len()
            ))
        })?;
    let count = header.command_count as usize;
    if count > size / LOAD_COMMAND_SIZE {
        return Err(error(format!(
            "Invalid ncmds {count}: sizeofcmds {size} B holds at most {} load commands",
            size / LOAD_COMMAND_SIZE
        )));
    }
    let le = header.little_endian;
    let mut commands = Vec::with_capacity(count);
    let mut pos = 0usize;
    for index in 0..count {
        let offset = start + pos;
        let remaining = region.len() - pos;
        if remaining < LOAD_COMMAND_SIZE {
            return Err(error(format!(
                "Truncated load command {index} at 0x{offset:X}: extends past sizeofcmds"
            )));
        }
        let cmd = read_u32(region, pos, le)?;
        let cmdsize = read_u32(region, pos + 4, le)?;
        if (cmdsize as usize) < LOAD_COMMAND_SIZE {
            return Err(error(format!(
                "Invalid load command {index} at 0x{offset:X}: cmdsize {cmdsize} B is smaller than 8 B"
            )));
        }
        if cmdsize % COMMAND_ALIGNMENT != 0 {
            return Err(error(format!(
                "Invalid load command {index} at 0x{offset:X}: cmdsize {cmdsize} B is not a multiple of 4"
            )));
        }
        if cmdsize as usize > remaining {
            return Err(error(format!(
                "Invalid load command {index} at 0x{offset:X}: cmdsize {cmdsize} B extends past sizeofcmds"
            )));
        }
        let end = pos + cmdsize as usize;
        commands.push(Command {
            cmd,
            index,
            offset,
            bytes: &region[pos..end],
            little_endian: le,
        });
        pos = end;
    }
    Ok(commands)
}

/// Read the load commands of the image whose header is `header`.
pub(super) fn read_image(data: &[u8], header: Header, offsets_in_input: bool) -> Result<Image> {
    let mut image = Image {
        header,
        segments: Vec::new(),
        build_versions: Vec::new(),
        entry: None,
        uuid: None,
        code_signature: None,
        chained_fixups: None,
        encryption: None,
        fileset: Vec::new(),
        remarks: Vec::new(),
        offsets_in_input,
    };
    for command in split_commands(data, &header)? {
        read_command(&mut image, &command)?;
    }
    Ok(image)
}

/// Record what one load command says. Commands this parser does not read
/// are skipped.
fn read_command(image: &mut Image, command: &Command<'_>) -> Result<()> {
    match command.cmd {
        LC_SEGMENT | LC_SEGMENT_64 => image.segments.push(segments::read_segment(command)?),
        LC_BUILD_VERSION => image
            .build_versions
            .push(platform::read_build_version(command)?),
        LC_VERSION_MIN_MACOSX
        | LC_VERSION_MIN_IPHONEOS
        | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => image
            .build_versions
            .push(platform::read_version_min(command)?),
        LC_MAIN => {
            command.expect_size(ENTRY_POINT_COMMAND_SIZE)?;
            let entry = Entry::Main {
                file_offset: command.u64_at(8)?,
            };
            set_entry(image, command, entry);
        }
        LC_UNIXTHREAD => {
            let entry = thread::read_unix_thread(command, image.header.cpu_type)?;
            set_entry(image, command, entry);
        }
        LC_UUID => {
            command.expect_size(UUID_COMMAND_SIZE)?;
            let uuid: [u8; 16] = command.bytes[8..UUID_COMMAND_SIZE]
                .try_into()
                .expect("expect_size checked the 16 UUID bytes");
            set_once(&mut image.uuid, uuid, &mut image.remarks, command);
        }
        LC_CODE_SIGNATURE => {
            let range = read_data_range(command)?;
            set_once(
                &mut image.code_signature,
                range,
                &mut image.remarks,
                command,
            );
        }
        LC_DYLD_CHAINED_FIXUPS => {
            let range = read_data_range(command)?;
            set_once(
                &mut image.chained_fixups,
                range,
                &mut image.remarks,
                command,
            );
        }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            let encryption = read_encryption(command)?;
            set_once(
                &mut image.encryption,
                encryption,
                &mut image.remarks,
                command,
            );
        }
        LC_FILESET_ENTRY => image.fileset.push(read_fileset_entry(command)?),
        _ => {}
    }
    Ok(())
}

/// Keep the first of a command that should appear once; note the others.
fn set_once<T>(slot: &mut Option<T>, value: T, remarks: &mut Vec<String>, command: &Command<'_>) {
    if slot.is_some() {
        remarks.push(format!(
            "Duplicate {} at 0x{:X} (load command {}) ignored",
            command.name(),
            command.offset,
            command.index
        ));
        return;
    }
    *slot = Some(value);
}

/// Keep the first entry-point command. xnu `load_unixthread` refuses an
/// image with both `LC_MAIN` and `LC_UNIXTHREAD` or two of either.
fn set_entry(image: &mut Image, command: &Command<'_>, entry: Entry) {
    set_once(&mut image.entry, entry, &mut image.remarks, command);
}

/// `linkedit_data_command`: `dataoff` (4) at 8, `datasize` (4) at 12.
fn read_data_range(command: &Command<'_>) -> Result<DataRange> {
    command.expect_size(LINKEDIT_DATA_COMMAND_SIZE)?;
    Ok(DataRange {
        offset: command.u32_at(8)?,
        size: command.u32_at(12)?,
    })
}

/// `encryption_info_command` (20 B) or `encryption_info_command_64` (24 B,
/// with `pad`): `cryptoff` at 8, `cryptsize` at 12, `cryptid` at 16.
fn read_encryption(command: &Command<'_>) -> Result<Encryption> {
    let size = if command.cmd == LC_ENCRYPTION_INFO_64 {
        ENCRYPTION_INFO_COMMAND_64_SIZE
    } else {
        ENCRYPTION_INFO_COMMAND_SIZE
    };
    command.expect_size(size)?;
    Ok(Encryption {
        command: command.cmd,
        offset: command.u32_at(8)?,
        size: command.u32_at(12)?,
        id: command.u32_at(16)?,
    })
}

/// `fileset_entry_command`: `vmaddr` (8) at 8, `fileoff` (8) at 16,
/// `entry_id` (`lc_str`, an offset from the command start) at 24 and
/// `reserved` (4) at 28. The NUL-terminated ID follows the structure.
fn read_fileset_entry(command: &Command<'_>) -> Result<FilesetEntry> {
    command.expect_size(FILESET_ENTRY_COMMAND_SIZE)?;
    let id_offset = command.u32_at(24)? as usize;
    let id_bytes = command
        .bytes
        .get(id_offset..)
        .filter(|_| id_offset >= FILESET_ENTRY_COMMAND_SIZE)
        .ok_or_else(|| {
            error(format!(
                "Invalid LC_FILESET_ENTRY at 0x{:X}: entry_id offset {id_offset} is outside the {} B command",
                command.offset,
                command.bytes.len()
            ))
        })?;
    let id_len = memchr::memchr(0, id_bytes).ok_or_else(|| {
        error(format!(
            "Invalid LC_FILESET_ENTRY at 0x{:X}: entry_id is not NUL-terminated",
            command.offset
        ))
    })?;
    Ok(FilesetEntry {
        id: printable(&id_bytes[..id_len]),
        vm_address: command.u64_at(8)?,
        file_offset: command.u64_at(16)?,
    })
}

/// A name from the image as text: bytes up to the first NUL, with anything
/// but printable ASCII shown as `?`.
pub(super) fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian 64-bit header with `ncmds` and `sizeofcmds`, then
    /// `commands`.
    fn image_with(ncmds: u32, sizeofcmds: u32, commands: &[u8]) -> Vec<u8> {
        let mut data = MACHO_64_LE.to_vec();
        for word in [cpu_type::ARM64, 0, MH_EXECUTE, ncmds, sizeofcmds, 0, 0] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(commands);
        data
    }

    /// A load command of `size` bytes, zero after `cmd` and `cmdsize`.
    fn command(cmd: u32, size: u32) -> Vec<u8> {
        let mut bytes = vec![0; size as usize];
        bytes[..4].copy_from_slice(&cmd.to_le_bytes());
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn names_stop_at_nul_and_hide_control_bytes() {
        assert_eq!(printable(b"__TEXT\0\0\0junk"), "__TEXT");
        assert_eq!(printable(b"a\x01b\xFFc"), "a?b?c");
        assert_eq!(printable(b"0123456789abcdef"), "0123456789abcdef");
    }

    #[test]
    fn commands_split_at_cmdsize_and_unread_ones_are_kept() {
        let mut commands = command(0x2, 24);
        commands.extend(command(0x26, 16));
        let data = image_with(2, 40, &commands);
        let header = Header::read(&data, 0).expect("header");
        let split = split_commands(&data, &header).expect("commands");
        assert_eq!(split.len(), 2);
        assert_eq!(split[1].cmd, 0x26);
        assert_eq!(split[1].offset, 32 + 24);
        assert_eq!(split[1].bytes.len(), 16);
        assert_eq!(split[1].name(), "load command 0x26");
    }

    #[test]
    fn space_after_the_last_command_is_allowed() {
        let mut commands = command(0x2, 24);
        commands.resize(40, 0);
        let data = image_with(1, 40, &commands);
        let header = Header::read(&data, 0).expect("header");
        assert_eq!(split_commands(&data, &header).expect("commands").len(), 1);
    }
}
