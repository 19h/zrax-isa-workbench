//! QNX Neutrino image filesystems: bootable images in both byte orders,
//! with and without a boot prefix; stored, gzip-, LZO- and UCL-compressed
//! image filesystems; the dummy startup header of a compressed image without
//! a startup program; and bare image filesystems. The startup header's
//! machine names the target; members are listed only when recognized, with
//! stored offsets and decoded ranges; the boot script is opaque and
//! summarized; corrupt fields and checksums are errors, and truncations and
//! byte mutations stay bounded.

use zrax::formats::checksum::crc32;
use zrax::formats::container::Kind;
use zrax::formats::qnx::Layout;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::types::{ContainedArch, MetadataKey};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

// Wire constants from QNX `sys/startup.h` and `sys/image.h`.

/// `STARTUP_HDR_SIGNATURE`, stored in the target byte order.
const STARTUP_HDR_SIGNATURE: u32 = 0x00ff_7eeb;

/// `STARTUP_HDR_VERSION` as mkifs writes it.
const STARTUP_HDR_VERSION: u16 = 1;

/// `sizeof(struct startup_header)`.
const STARTUP_HEADER_SIZE: usize = 0x100;

/// `flags1` bits and compression values (`STARTUP_HDR_FLAGS1_*`).
const FLAGS1_VIRTUAL: u8 = 0x01;
const FLAGS1_BIGENDIAN: u8 = 0x02;
const COMPRESS_NONE: u8 = 0x00;
const COMPRESS_ZLIB: u8 = 0x04;
const COMPRESS_LZO: u8 = 0x08;
const COMPRESS_UCL: u8 = 0x0c;

/// Field offsets in `struct startup_header`.
const SH_FLAGS1: usize = 0x06;
const SH_HEADER_SIZE: usize = 0x08;
const SH_STARTUP_SIZE: usize = 0x20;
const SH_STORED_SIZE: usize = 0x24;
const SH_IMAGEFS_SIZE: usize = 0x2c;

/// `IMAGE_FLAGS_*`.
const IMAGE_FLAGS_BIGENDIAN: u8 = 0x01;
const IMAGE_FLAGS_INO_BITS: u8 = 0x04;

/// Offset of `mountpoint` in `struct image_header`.
const IMAGE_HEADER_SIZE: usize = 0x58;

/// Size of `struct image_attr`.
const IMAGE_ATTR_SIZE: usize = 24;

/// File type bits (QNX `sys/stat.h`).
const S_IFDIR: u32 = 0x4000;
const S_IFREG: u32 = 0x8000;
const S_IFLNK: u32 = 0xa000;
const S_IFCHR: u32 = 0x2000;

/// Inode flag bits (`IFS_INO_*`).
const IFS_INO_PROCESSED_ELF: u32 = 0x8000_0000;
const IFS_INO_BOOTSTRAP_EXE: u32 = 0x2000_0000;

/// Boot script command types (`SCRIPT_TYPE_*`).
const SCRIPT_TYPE_EXTERNAL: u8 = 0;
const SCRIPT_TYPE_WAITFOR: u8 = 1;

/// ELF `e_machine` values.
const EM_NONE: u16 = 0;
const EM_386: u16 = 3;
const EM_MIPS: u16 = 8;
const EM_PPC: u16 = 20;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Physical address of the fixture images.
const IMAGE_PADDR: u32 = 0x8000_0000;

/// Decoded bytes per LZO and UCL block in the fixtures; mkifs uses up to
/// 64 KiB, smaller blocks exercise the block walk.
const FIXTURE_BLOCK: usize = 1000;

fn put_u16(out: &mut [u8], at: usize, value: u16, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[at..at + 2].copy_from_slice(&bytes);
}

fn put_u32(out: &mut [u8], at: usize, value: u32, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    out[at..at + 4].copy_from_slice(&bytes);
}

fn get_u32(data: &[u8], at: usize, le: bool) -> u32 {
    let bytes: [u8; 4] = data[at..at + 4].try_into().unwrap();
    if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).expect("fixture sizes fit in 32 bits")
}

/// `value` rounded up to a multiple of `to`.
fn round_up(value: usize, to: usize) -> usize {
    match value % to {
        0 => value,
        remainder => value + to - remainder,
    }
}

/// The 32-bit word sum mkifs `iwrite` accumulates, in the byte order `le`
/// selects.
fn word_sum(bytes: &[u8], le: bool) -> u32 {
    (0..bytes.len() / 4).fold(0u32, |sum, i| sum.wrapping_add(get_u32(bytes, 4 * i, le)))
}

/// Store the trailer at the end of `region` so its word sum is zero.
fn seal(region: &mut [u8], le: bool) {
    let trailer = region.len() - 4;
    put_u32(region, trailer, 0, le);
    let sum = word_sum(region, le);
    put_u32(region, trailer, sum.wrapping_neg(), le);
}

/// Recompute the startup and image trailers of a bootable image whose
/// header is at `at`, from the header's own (possibly edited) sizes.
fn reseal(image: &mut [u8], at: usize, le: bool) {
    let startup_end = at + get_u32(image, at + SH_STARTUP_SIZE, le) as usize;
    let stored_end = at + get_u32(image, at + SH_STORED_SIZE, le) as usize;
    seal(&mut image[at..startup_end], le);
    seal(&mut image[startup_end..stored_end], le);
}

/// An ELF32 header (`e_ident` with class 1 and the data encoding `le`
/// selects, `e_type` `ET_EXEC`, `e_machine`, `e_version` 1, `e_ehsize` 52)
/// followed by nonzero filler up to `size` bytes.
fn elf32(machine: u16, le: bool, size: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..size).map(|i| (i % 251) as u8 | 1).collect();
    data[..52].fill(0);
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, if le { 1 } else { 2 }, 1]);
    put_u16(&mut data, 16, 2, le);
    put_u16(&mut data, 18, machine, le);
    put_u32(&mut data, 20, 1, le);
    put_u16(&mut data, 40, 52, le);
    data
}

/// An ELF64 little-endian header (`e_ident`, `ET_EXEC`, `e_machine`,
/// `e_version` 1, `e_ehsize` 64) followed by nonzero filler.
fn elf64(machine: u16, size: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..size).map(|i| (i % 251) as u8 | 1).collect();
    data[..64].fill(0);
    data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put_u16(&mut data, 16, 2, true);
    put_u16(&mut data, 18, machine, true);
    put_u32(&mut data, 20, 1, true);
    put_u16(&mut data, 52, 64, true);
    data
}

/// `size` bytes of plain text that no format recognizes.
fn text(size: usize) -> Vec<u8> {
    b"plain words for a qnx image filesystem fixture\n"
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

/// One boot script command: `size_lo`, `size_hi` (the command size, a
/// multiple of four), type, spare, then `body` zero-padded.
fn script_command(kind: u8, body: &[u8]) -> Vec<u8> {
    let size = round_up(4 + body.len(), 4);
    let mut command = vec![(size & 0xff) as u8, (size >> 8) as u8, kind, 0];
    command.extend_from_slice(body);
    command.resize(size, 0);
    command
}

/// An external command: cpu, flags, extsched (2), policy, priority, argc 1,
/// envc 0, then the command name and argv[0].
fn external(name: &str) -> Vec<u8> {
    let mut body = vec![0, 0, 0, 0, 0, 0, 1, 0];
    for _ in 0..2 {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
    }
    script_command(SCRIPT_TYPE_EXTERNAL, &body)
}

/// A boot script: two external commands and a `waitfor` (checks 50,
/// `/dev/ser1`), then a zero-size end.
fn boot_script() -> Vec<u8> {
    let mut script = external("devc-ser8250");
    script.extend(script_command(SCRIPT_TYPE_WAITFOR, b"\x32\x00/dev/ser1\0"));
    script.extend(external("esh"));
    script.extend([0, 0, 0, 0]);
    script
}

/// One image filesystem entry of a fixture.
enum Entry<'a> {
    /// Regular file: inode, path, contents.
    File(u32, &'a str, &'a [u8]),
    /// Directory: inode, path.
    Dir(u32, &'a str),
    /// Symbolic link: inode, path, target.
    Symlink(u32, &'a str, &'a str),
    /// Character device: inode, path.
    Device(u32, &'a str),
}

/// An image filesystem fixture.
struct ImageFsSpec<'a> {
    le: bool,
    mountpoint: &'a str,
    entries: Vec<Entry<'a>>,
    /// `boot_ino[0]`.
    boot_ino: u32,
    script_ino: u32,
}

/// `struct image_attr`: size, `extattr_offset` 0, `ino`, `mode`, gid, uid
/// and mtime 0, then the type-specific fields `extra`, the NUL-terminated
/// path and zero padding to four bytes (mkifs `ifs_make_fsys`).
fn dirent(le: bool, ino: u32, mode: u32, extra: &[u8], path: &[u8]) -> Vec<u8> {
    let size = round_up(IMAGE_ATTR_SIZE + extra.len() + path.len() + 1, 4);
    let mut entry = vec![0u8; size];
    put_u16(&mut entry, 0, size as u16, le);
    put_u32(&mut entry, 4, ino, le);
    put_u32(&mut entry, 8, mode, le);
    entry[IMAGE_ATTR_SIZE..IMAGE_ATTR_SIZE + extra.len()].copy_from_slice(extra);
    let path_at = IMAGE_ATTR_SIZE + extra.len();
    entry[path_at..path_at + path.len()].copy_from_slice(path);
    entry
}

/// An image filesystem: the header (signature, flags with `INO_BITS` and
/// the byte order, `image_size`, `hdr_dir_size`, `dir_offset`,
/// `boot_ino[0]`, `script_ino`, mountpoint padded to four bytes), the root
/// directory entry (inode 1, empty path), the spec's entries, a zero-size
/// terminator, each file's data at a four-byte boundary, and the trailer
/// that makes the word sum zero.
fn imagefs(spec: &ImageFsSpec<'_>) -> Vec<u8> {
    let le = spec.le;
    let dir_offset = round_up(IMAGE_HEADER_SIZE + spec.mountpoint.len() + 1, 4);
    // Entry sizes depend only on the paths, so the data area is known
    // before the file offsets are written.
    let entry_size = |entry: &Entry<'_>| match entry {
        Entry::File(_, path, _) | Entry::Device(_, path) => {
            round_up(IMAGE_ATTR_SIZE + 8 + path.len() + 1, 4)
        }
        Entry::Dir(_, path) => round_up(IMAGE_ATTR_SIZE + path.len() + 1, 4),
        Entry::Symlink(_, path, target) => {
            round_up(IMAGE_ATTR_SIZE + 4 + path.len() + 1 + target.len() + 1, 4)
        }
    };
    let root = round_up(IMAGE_ATTR_SIZE + 1, 4);
    let directory: usize = root + spec.entries.iter().map(entry_size).sum::<usize>() + 4;
    let hdr_dir_size = dir_offset + directory;
    let mut position = hdr_dir_size;
    let mut entries = vec![dirent(le, 1, S_IFDIR | 0o755, &[], b"")];
    let mut data = Vec::new();
    for entry in &spec.entries {
        entries.push(match entry {
            Entry::File(ino, path, contents) => {
                position = round_up(position, 4);
                let mut extra = vec![0u8; 8];
                put_u32(&mut extra, 0, to_u32(position), le);
                put_u32(&mut extra, 4, to_u32(contents.len()), le);
                data.push((position, *contents));
                position += contents.len();
                dirent(le, *ino, S_IFREG | 0o755, &extra, path.as_bytes())
            }
            Entry::Dir(ino, path) => dirent(le, *ino, S_IFDIR | 0o755, &[], path.as_bytes()),
            Entry::Symlink(ino, path, target) => {
                let mut extra = vec![0u8; 4];
                put_u16(&mut extra, 0, (path.len() + 1) as u16, le);
                put_u16(&mut extra, 2, target.len() as u16, le);
                let mut names = path.as_bytes().to_vec();
                names.push(0);
                names.extend_from_slice(target.as_bytes());
                dirent(le, *ino, S_IFLNK | 0o777, &extra, &names)
            }
            Entry::Device(ino, path) => dirent(le, *ino, S_IFCHR | 0o666, &[0; 8], path.as_bytes()),
        });
    }
    let image_size = round_up(position, 4) + 4;
    let mut out = vec![0u8; image_size];
    out[..7].copy_from_slice(b"imagefs");
    out[7] = IMAGE_FLAGS_INO_BITS | if le { 0 } else { IMAGE_FLAGS_BIGENDIAN };
    put_u32(&mut out, 0x08, to_u32(image_size), le);
    put_u32(&mut out, 0x0c, to_u32(hdr_dir_size), le);
    put_u32(&mut out, 0x10, to_u32(dir_offset), le);
    put_u32(&mut out, 0x14, spec.boot_ino, le);
    put_u32(&mut out, 0x24, spec.script_ino, le);
    out[IMAGE_HEADER_SIZE..IMAGE_HEADER_SIZE + spec.mountpoint.len()]
        .copy_from_slice(spec.mountpoint.as_bytes());
    let mut at = dir_offset;
    for entry in entries {
        out[at..at + entry.len()].copy_from_slice(&entry);
        at += entry.len();
    }
    assert_eq!(at + 4, hdr_dir_size, "terminator fills the directory end");
    for (offset, contents) in data {
        out[offset..offset + contents.len()].copy_from_slice(contents);
    }
    seal(&mut out, le);
    out
}

/// A bootable image fixture.
struct BootSpec<'a> {
    le: bool,
    machine: u16,
    /// The `flags1` compression value.
    compression: u8,
    /// Bytes before the startup header (`preboot_size`), a multiple of 4.
    prefix: &'a [u8],
    /// The startup program's raw segments.
    startup: &'a [u8],
    /// The uncompressed image filesystem.
    imagefs: &'a [u8],
}

/// A bootable image: the prefix, the startup header (signature, version 1,
/// `flags1` virtual + byte order + compression, `header_size` 0x100,
/// machine, `startup_vaddr` (the program start), `paddr_bias` 0,
/// `image_paddr`, `ram_paddr`, `ram_size`, `startup_size`, `stored_size`,
/// `imagefs_paddr` 0, `imagefs_size`, `preboot_size`), the startup program
/// and the startup trailer, then the image filesystem stored as-is or as a
/// compressed stream, zero padding to four bytes and the image trailer.
fn bootable(spec: &BootSpec<'_>) -> Vec<u8> {
    let le = spec.le;
    let startup_size = round_up(STARTUP_HEADER_SIZE + spec.startup.len() + 4, 4);
    let region = match spec.compression {
        COMPRESS_NONE => spec.imagefs.to_vec(),
        compression => {
            let mut stream = match compression {
                COMPRESS_ZLIB => gzip(spec.imagefs),
                COMPRESS_LZO => block_stream(spec.imagefs, lzo1x_literals),
                _ => block_stream(spec.imagefs, <[u8]>::to_vec),
            };
            stream.resize(round_up(stream.len(), 4) + 4, 0);
            stream
        }
    };
    let stored_size = startup_size + region.len();
    let at = spec.prefix.len();
    let mut out = spec.prefix.to_vec();
    out.resize(at + stored_size, 0);
    let flags1 = FLAGS1_VIRTUAL | spec.compression | if le { 0 } else { FLAGS1_BIGENDIAN };
    put_u32(&mut out, at, STARTUP_HDR_SIGNATURE, le);
    put_u16(&mut out, at + 0x04, STARTUP_HDR_VERSION, le);
    out[at + SH_FLAGS1] = flags1;
    put_u16(
        &mut out,
        at + SH_HEADER_SIZE,
        STARTUP_HEADER_SIZE as u16,
        le,
    );
    put_u16(&mut out, at + 0x0a, spec.machine, le);
    let program = IMAGE_PADDR + to_u32(STARTUP_HEADER_SIZE);
    put_u32(&mut out, at + 0x0c, program, le);
    put_u32(&mut out, at + 0x14, IMAGE_PADDR, le);
    put_u32(&mut out, at + 0x18, IMAGE_PADDR, le);
    put_u32(&mut out, at + 0x1c, to_u32(stored_size), le);
    put_u32(&mut out, at + SH_STARTUP_SIZE, to_u32(startup_size), le);
    put_u32(&mut out, at + SH_STORED_SIZE, to_u32(stored_size), le);
    put_u32(
        &mut out,
        at + SH_IMAGEFS_SIZE,
        to_u32(spec.imagefs.len()),
        le,
    );
    put_u16(&mut out, at + 0x30, at as u16, le);
    let code = at + STARTUP_HEADER_SIZE;
    out[code..code + spec.startup.len()].copy_from_slice(spec.startup);
    let region_at = at + startup_size;
    out[region_at..].copy_from_slice(&region);
    reseal(&mut out, at, le);
    out
}

/// A gzip member (RFC 1952): header with method 8, no flags, mtime 0, OS 3;
/// the DEFLATE stream; CRC-32 and size.
fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    member.extend_from_slice(&crc32(payload).to_le_bytes());
    member.extend_from_slice(&to_u32(payload.len()).to_le_bytes());
    member
}

/// A raw LZO1X stream of literals only (Linux
/// `Documentation/staging/lzo.rst`): 1 to 238 literals as a first byte of
/// 17 plus the count; longer runs as the long literal instruction `0000
/// 0000`, zero bytes of 255 each and a final nonzero byte (count 18 +
/// 255 * zeros + byte); then the literals and the end-of-stream marker
/// `11 00 00`.
fn lzo1x_literals(data: &[u8]) -> Vec<u8> {
    assert!(!data.is_empty());
    let mut stream = Vec::new();
    if data.len() <= 238 {
        stream.push(17 + data.len() as u8);
    } else {
        stream.push(0);
        let mut rest = data.len() - 18;
        while rest > 255 {
            stream.push(0);
            rest -= 255;
        }
        stream.push(rest as u8);
    }
    stream.extend_from_slice(data);
    stream.extend_from_slice(&[0x11, 0, 0]);
    stream
}

/// mkifs block framing (`lzoflush`, `uclflush`): each block of up to
/// [`FIXTURE_BLOCK`] decoded bytes as a big-endian 16-bit stored length and
/// the encoded block, then a zero length.
fn block_stream(image: &[u8], encode: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut stream = Vec::new();
    for chunk in image.chunks(FIXTURE_BLOCK) {
        let block = encode(chunk);
        stream.extend_from_slice(&(block.len() as u16).to_be_bytes());
        stream.extend_from_slice(&block);
    }
    stream.extend_from_slice(&[0, 0]);
    stream
}

/// ARM NOPs (`mov r0, r0`, `0xE1A00000`) as a startup program.
fn arm_startup(le: bool) -> Vec<u8> {
    let mut code = vec![0u8; 64];
    for i in 0..16 {
        put_u32(&mut code, 4 * i, 0xe1a0_0000, le);
    }
    code
}

/// The members of the standard fixture image: directories, the bootstrap
/// kernel (an ELF of `machine`), the boot script, a text file, an x86-64
/// tool, a symbolic link and a device.
struct Members {
    procnto: Vec<u8>,
    script: Vec<u8>,
    motd: Vec<u8>,
    tool: Vec<u8>,
}

/// Inode of the bootstrap kernel: processed ELF, bootstrap executable, 4.
const PROCNTO_INO: u32 = IFS_INO_PROCESSED_ELF | IFS_INO_BOOTSTRAP_EXE | 4;

/// Inode of the boot script.
const SCRIPT_INO: u32 = 5;

impl Members {
    fn new(machine: u16, le: bool) -> Self {
        Self {
            procnto: elf32(machine, le, 300),
            script: boot_script(),
            motd: text(90),
            tool: elf64(EM_X86_64, 200),
        }
    }

    fn spec(&self, le: bool) -> ImageFsSpec<'_> {
        ImageFsSpec {
            le,
            mountpoint: "/",
            entries: vec![
                Entry::Dir(2, "proc"),
                Entry::Dir(3, "proc/boot"),
                Entry::File(PROCNTO_INO, "proc/boot/procnto", &self.procnto),
                Entry::File(SCRIPT_INO, "proc/boot/.script", &self.script),
                Entry::File(6, "etc/motd", &self.motd),
                Entry::File(IFS_INO_PROCESSED_ELF | 7, "bin/tool", &self.tool),
                Entry::Symlink(8, "usr/lib/ldqnx.so.2", "/proc/boot/libc.so"),
                Entry::Device(9, "dev/console"),
            ],
            boot_ino: PROCNTO_INO,
            script_ino: SCRIPT_INO,
        }
    }

    fn imagefs(&self, le: bool) -> Vec<u8> {
        imagefs(&self.spec(le))
    }
}

/// The standard little-endian ARM image with `compression`.
fn arm_image(compression: u8) -> Vec<u8> {
    let members = Members::new(EM_ARM, true);
    bootable(&BootSpec {
        le: true,
        machine: EM_ARM,
        compression,
        prefix: &[],
        startup: &arm_startup(true),
        imagefs: &members.imagefs(true),
    })
}

/// File offset of the end of the startup trailer in a fixture whose header
/// is at `at`.
fn startup_end(image: &[u8], at: usize, le: bool) -> usize {
    at + get_u32(image, at + SH_STARTUP_SIZE, le) as usize
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn labels(payload: &DetectionPayload) -> Vec<String> {
    payload
        .slices
        .iter()
        .map(|s| s.label.clone().unwrap_or_default())
        .collect()
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no slice {label}; slices {:?}", labels(payload)))
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn notes(payload: &DetectionPayload) -> Vec<String> {
    payload.notes.iter().map(|n| n.message.clone()).collect()
}

fn metadata(payload: &DetectionPayload, key: &str) -> Option<String> {
    payload
        .metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.to_string()))
        .map(|m| m.value.to_string())
}

fn error_text(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected an error, got {:?}", p.format.format),
        Err(e) => e.to_string(),
    }
}

fn detected_layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: Kind::Qnx(layout),
        } => Some(layout),
        _ => None,
    }
}

/// Recompute the trailers of a mutated bootable image when its mutated
/// sizes still describe regions inside it; otherwise leave it as it is.
fn try_reseal(image: &mut [u8], at: usize, le: bool) {
    let startup_size = get_u32(image, at + SH_STARTUP_SIZE, le) as usize;
    let stored_size = get_u32(image, at + SH_STORED_SIZE, le) as usize;
    let fits = startup_size >= 4
        && startup_size % 4 == 0
        && stored_size % 4 == 0
        && startup_size + 4 <= stored_size
        && at + stored_size <= image.len();
    if fits {
        reseal(image, at, le);
    }
}

/// Every byte mutation of `image`, with `reseal` recomputing the checksums
/// afterwards so that the mutation reaches the parsers behind them,
/// classifies or fails without panicking.
fn resealed_sweep(image: &[u8], reseal: impl Fn(&mut [u8])) {
    for i in 0..image.len() {
        for value in [0x00, 0xff, image[i] ^ 0x01] {
            let mut mutated = image.to_vec();
            mutated[i] = value;
            reseal(&mut mutated);
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

/// Every truncation of `image` is an error or is not reported as a QNX
/// image; every byte mutation classifies or fails without panicking.
fn sweep(image: &[u8]) {
    for cut in 0..image.len() {
        if let Ok(p) = detect_payload(&image[..cut], &ClassifierOptions::new()) {
            assert_ne!(
                p.format.format,
                FileFormat::QnxIfs,
                "prefix {cut} still parses"
            );
        }
    }
    for i in 0..image.len() {
        for value in [0x00, 0xff, image[i] ^ 0x01] {
            let mut mutated = image.to_vec();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}

#[test]
fn little_endian_arm_image_names_its_target_and_lists_recognized_members() {
    let image = arm_image(COMPRESS_NONE);
    assert_eq!(
        detected_layout(&image),
        Some(Layout::Bootable { header_offset: 0 })
    );
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::QnxIfs);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(p.primary.confidence, 1.0);
    let imagefs_at = startup_end(&image, 0, true);
    let members = Members::new(EM_ARM, true);
    let fs = members.imagefs(true);
    let procnto = slice(&p, "/proc/boot/procnto");
    assert_eq!(procnto.isa, Isa::Arm);
    let procnto_at = fs
        .windows(members.procnto.len())
        .position(|w| w == members.procnto.as_slice())
        .unwrap();
    assert_eq!(procnto.offset as usize, imagefs_at + procnto_at);
    assert_eq!(procnto.size as usize, members.procnto.len());
    assert_eq!(procnto.decoded, None);
    let tool = slice(&p, "/bin/tool");
    assert_eq!(
        tool.isa,
        Isa::X86_64,
        "members classify by their own header"
    );
    let script = slice(&p, "/proc/boot/.script");
    assert!(
        matches!(script.isa, Isa::Unknown(_)),
        "the script is opaque"
    );
    assert!(!labels(&p).contains(&"/etc/motd".to_string()));
    assert!(has_note(
        &p,
        "Startup program machine 40 (ELF e_machine): ARM (32-bit)"
    ));
    assert!(has_note(&p, "Startup trailer checksum verified"));
    assert!(has_note(&p, "image trailer checksum verified"));
    assert!(has_note(
        &p,
        "Image directory: 4 regular files, 3 directories, 1 symbolic links, 1 devices"
    ));
    assert!(has_note(
        &p,
        "Boot script /proc/boot/.script: 3 commands (2 external, 1 waitfor); programs: devc-ser8250, esh"
    ));
    assert!(has_note(
        &p,
        "Bootstrap programs (boot_ino): /proc/boot/procnto"
    ));
    assert!(
        has_note(&p, "2 recognized members listed"),
        "{:?}",
        notes(&p)
    );
    assert_eq!(
        metadata(&p, "qnx_machine").as_deref(),
        Some(EM_ARM.to_string().as_str())
    );
    assert_eq!(metadata(&p, "qnx_mountpoint").as_deref(), Some("/"));
    assert_eq!(
        metadata(&p, "qnx_section_0").as_deref(),
        Some("file 0x100; destination 0x80000100; 64 B")
    );
    assert_eq!(
        p.metadata
            .iter()
            .find(|m| m.key == MetadataKey::EntryPoint)
            .map(|m| m.value.to_string())
            .as_deref(),
        Some("0x80000100")
    );
}

#[test]
fn big_endian_powerpc_image_reads_every_field_in_target_order() {
    let members = Members::new(EM_PPC, false);
    let startup: Vec<u8> = 0x6000_0000u32.to_be_bytes().repeat(16);
    let image = bootable(&BootSpec {
        le: false,
        machine: EM_PPC,
        compression: COMPRESS_NONE,
        prefix: &[],
        startup: &startup,
        imagefs: &members.imagefs(false),
    });
    assert_eq!(&image[..4], &[0x00, 0xff, 0x7e, 0xeb]);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::QnxIfs);
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert_eq!(p.primary.endianness, Endianness::Big);
    assert_eq!(slice(&p, "/proc/boot/procnto").isa, Isa::Ppc);
    assert!(has_note(&p, "Startup header at 0x0: version 1, big-endian"));
    assert!(has_note(&p, "big-endian; mountpoint /"));
}

#[test]
fn aarch64_instructions_are_little_endian_in_a_big_endian_image() {
    let members = Members::new(EM_AARCH64, false);
    let image = bootable(&BootSpec {
        le: false,
        machine: EM_AARCH64,
        compression: COMPRESS_NONE,
        prefix: &[],
        startup: &0xd503_201fu32.to_le_bytes().repeat(16),
        imagefs: &members.imagefs(false),
    });
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.primary.endianness, Endianness::Little);
}

#[test]
fn a_boot_prefix_is_found_through_preboot_size_and_reported_as_code() {
    // A real-mode jump over the prefix, then NOPs: not a format of its own.
    let mut prefix = vec![0x90u8; 0x40];
    prefix[..2].copy_from_slice(&[0xeb, 0x3e]);
    let members = Members::new(EM_386, true);
    let image = bootable(&BootSpec {
        le: true,
        machine: EM_386,
        compression: COMPRESS_NONE,
        prefix: &prefix,
        startup: &[0x90; 64],
        imagefs: &members.imagefs(true),
    });
    assert_eq!(
        detected_layout(&image),
        Some(Layout::Bootable {
            header_offset: 0x40
        })
    );
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::X86);
    let boot = slice(&p, "Boot prefix");
    assert_eq!((boot.offset, boot.size), (0, 0x40));
    assert_eq!(boot.isa, Isa::X86);
    assert!(has_note(&p, "Startup header at 0x40"));
    assert!(has_note(
        &p,
        "Boot prefix: 64 B of code before the startup header"
    ));
    assert_eq!(metadata(&p, "qnx_header_offset").as_deref(), Some("64"));

    // The signature alone, without a matching preboot_size, is not a header.
    let mut moved = image.clone();
    moved[0x40 + 0x30] = 0x44;
    assert_eq!(detected_layout(&moved), None);
    // A zero-filled prefix is noted, not listed.
    let filled = bootable(&BootSpec {
        le: true,
        machine: EM_386,
        compression: COMPRESS_NONE,
        prefix: &[0; 0x20],
        startup: &[0x90; 64],
        imagefs: &members.imagefs(true),
    });
    let p = classify(&filled);
    assert!(has_note(&p, "Boot prefix: 32 B of fill"));
    assert!(!labels(&p).contains(&"Boot prefix".to_string()));
}

#[test]
fn gzip_compressed_image_filesystems_decode_into_members() {
    let image = arm_image(COMPRESS_ZLIB);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::QnxIfs);
    assert_eq!(p.primary.isa, Isa::Arm);
    let stream_at = startup_end(&image, 0, true);
    let procnto = slice(&p, "/proc/boot/procnto");
    assert_eq!(procnto.isa, Isa::Arm);
    assert_eq!(procnto.offset as usize, stream_at);
    assert_eq!(procnto.size as usize, image.len() - stream_at);
    let decoded = procnto.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "gzip");
    assert_eq!(decoded.size, 300);
    assert_eq!(slice(&p, "/bin/tool").isa, Isa::X86_64);
    assert!(has_note(&p, "Image filesystem compressed with gzip"));
    assert!(has_note(&p, "Image filesystem (gzip-decoded)"));
    assert!(metadata(&p, "qnx_compressed_checksum").is_some());
}

#[test]
fn lzo_compressed_image_filesystems_decode_block_by_block() {
    let image = arm_image(COMPRESS_LZO);
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Arm);
    let procnto = slice(&p, "/proc/boot/procnto");
    assert_eq!(procnto.decoded.as_ref().unwrap().transform, "LZO1X");
    let fs_len = Members::new(EM_ARM, true).imagefs(true).len();
    let blocks = fs_len.div_euclid(FIXTURE_BLOCK) + usize::from(fs_len % FIXTURE_BLOCK != 0);
    assert!(
        has_note(
            &p,
            &format!("Image filesystem compressed with LZO1X in {blocks} blocks")
        ),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(&p, "Boot script /proc/boot/.script: 3 commands"));
}

#[test]
fn ucl_compressed_image_filesystems_stay_opaque() {
    let image = arm_image(COMPRESS_UCL);
    let p = classify(&image);
    assert_eq!(
        p.primary.isa,
        Isa::Arm,
        "the startup header still names the target"
    );
    let compressed = slice(&p, "Compressed image filesystem");
    assert!(matches!(compressed.isa, Isa::Unknown(_)));
    assert_eq!(compressed.offset as usize, startup_end(&image, 0, true));
    assert!(has_note(&p, "compressed with UCL NRV2B"));
    assert!(has_note(&p, "no UCL decoder"));
    assert!(!labels(&p).contains(&"/proc/boot/procnto".to_string()));
}

#[test]
fn compressed_image_filesystems_that_do_not_decode_are_kept_opaque() {
    let mut image = arm_image(COMPRESS_LZO);
    let stream_at = startup_end(&image, 0, true);
    // The first block's first literal-run byte: a run longer than the block.
    image[stream_at + 2] = 0xff;
    reseal(&mut image, 0, true);
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(has_note(
        &p,
        "LZO1X-compressed image filesystem does not decode"
    ));
    assert!(matches!(
        slice(&p, "Compressed image filesystem").isa,
        Isa::Unknown(_)
    ));

    // A gzip stream that decodes to an image filesystem whose own trailer
    // checksum does not match.
    let members = Members::new(EM_ARM, true);
    let mut fs = members.imagefs(true);
    fs[0x80] ^= 1;
    let image = bootable(&BootSpec {
        le: true,
        machine: EM_ARM,
        compression: COMPRESS_ZLIB,
        prefix: &[],
        startup: &arm_startup(true),
        imagefs: &fs,
    });
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::Arm);
    assert!(
        has_note(&p, "gzip-decoded image filesystem is invalid"),
        "{:?}",
        notes(&p)
    );
    assert!(has_note(&p, "Invalid image trailer checksum"));
    assert_eq!(labels(&p), vec!["Compressed image filesystem".to_string()]);
}

#[test]
fn a_compressed_image_without_a_startup_program_takes_its_isa_from_members() {
    let app = elf64(EM_AARCH64, 256);
    let fs = imagefs(&ImageFsSpec {
        le: true,
        mountpoint: "",
        entries: vec![Entry::File(2, "bin/app", &app)],
        boot_ino: 0,
        script_ino: 0,
    });
    let image = bootable(&BootSpec {
        le: true,
        machine: EM_NONE,
        compression: COMPRESS_LZO,
        prefix: &[],
        startup: &[],
        imagefs: &fs,
    });
    assert_eq!(get_u32(&image, SH_STARTUP_SIZE, true), 0x104);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::QnxIfs);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(has_note(&p, "names no machine (EM_NONE)"));
    assert!(has_note(&p, "Primary ISA selected from /bin/app"));
    assert!(has_note(&p, "no mountpoint"));
}

#[test]
fn a_machine_whose_width_depends_on_the_elf_class_names_no_target() {
    let members = Members::new(EM_MIPS, true);
    let image = bootable(&BootSpec {
        le: true,
        machine: EM_MIPS,
        compression: COMPRESS_NONE,
        prefix: &[],
        startup: &[0; 64],
        imagefs: &members.imagefs(true),
    });
    let p = classify(&image);
    assert!(has_note(
        &p,
        "machine 8 (ELF e_machine) is MIPS (32-bit) or MIPS (64-bit)"
    ));
    assert_eq!(slice(&p, "/proc/boot/procnto").isa, Isa::Mips);
}

#[test]
fn bare_image_filesystems_list_members_without_a_target() {
    let members = Members::new(EM_PPC, false);
    let fs = members.imagefs(false);
    assert_eq!(detected_layout(&fs), Some(Layout::ImageFs));
    let p = classify(&fs);
    assert_eq!(p.format.format, FileFormat::QnxIfs);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("QNX image filesystem")
    );
    assert_eq!(p.primary.isa, Isa::Ppc);
    assert!(has_note(&p, "Primary ISA selected from /proc/boot/procnto"));
    let procnto = slice(&p, "/proc/boot/procnto");
    let at = fs
        .windows(members.procnto.len())
        .position(|w| w == members.procnto.as_slice())
        .unwrap();
    assert_eq!(procnto.offset as usize, at);

    let mut padded = fs.clone();
    padded.extend_from_slice(&[0xff; 16]);
    assert!(has_note(&classify(&padded), "16 B of padding follow"));
    let mut appended = fs.clone();
    appended.extend_from_slice(b"wrapper!");
    assert!(has_note(&classify(&appended), "8 B after it"));
}

#[test]
fn corrupt_checksums_and_fields_are_parse_errors() {
    let image = arm_image(COMPRESS_NONE);
    let imagefs_at = startup_end(&image, 0, true);

    let mut startup = image.clone();
    startup[0x110] ^= 1;
    let message = error_text(&startup);
    assert!(message.contains("QNX image parse error"), "{message}");
    assert!(
        message.contains("Invalid startup trailer checksum"),
        "{message}"
    );

    let mut member = image.clone();
    member[imagefs_at + 0x200] ^= 1;
    assert!(error_text(&member).contains("Invalid image trailer checksum"));

    let mut order = image.clone();
    order[SH_FLAGS1] |= FLAGS1_BIGENDIAN;
    reseal(&mut order, 0, true);
    assert!(error_text(&order).contains("disagrees with the signature byte order"));

    let mut compression = image.clone();
    compression[SH_FLAGS1] |= 0x10;
    reseal(&mut compression, 0, true);
    assert!(error_text(&compression).contains("Unsupported compression 0x10"));

    let mut header_size = image.clone();
    put_u16(&mut header_size, SH_HEADER_SIZE, 0x20, true);
    reseal(&mut header_size, 0, true);
    assert!(error_text(&header_size).contains("Invalid header_size 0x20"));

    let mut stored = image.clone();
    put_u32(&mut stored, SH_STORED_SIZE, to_u32(image.len() + 4), true);
    assert!(error_text(&stored).contains("Truncated image"));

    let mut unaligned = image.clone();
    put_u32(&mut unaligned, SH_STARTUP_SIZE, 0x142, true);
    assert!(error_text(&unaligned).contains("Invalid startup_size 0x142"));

    let mut imagefs_size = image.clone();
    put_u32(&mut imagefs_size, SH_IMAGEFS_SIZE, 4, true);
    reseal(&mut imagefs_size, 0, true);
    assert!(error_text(&imagefs_size).contains("Invalid image sizes"));

    let mut byte_order = image.clone();
    byte_order[imagefs_at + 7] |= IMAGE_FLAGS_BIGENDIAN;
    reseal(&mut byte_order, 0, true);
    assert!(error_text(&byte_order).contains("QNX image parse error"));
}

#[test]
fn directory_entries_must_fit_the_image_filesystem() {
    let members = Members::new(EM_ARM, true);
    let fs = members.imagefs(true);
    let dir_offset = get_u32(&fs, 0x10, true) as usize;
    let hdr_dir_size = get_u32(&fs, 0x0c, true) as usize;
    // Entries: root (28 B), proc (32 B), proc/boot (36 B), then procnto.
    let procnto_entry = dir_offset + 28 + 32 + 36;
    assert_eq!(get_u32(&fs, procnto_entry + 4, true), PROCNTO_INO);

    let mut outside = fs.clone();
    put_u32(&mut outside, procnto_entry + 0x1c, 0x10_0000, true);
    seal(&mut outside, true);
    assert!(error_text(&outside).contains("lies outside the image filesystem"));

    let mut no_terminator = fs.clone();
    put_u32(&mut no_terminator, 0x0c, to_u32(hdr_dir_size - 4), true);
    seal(&mut no_terminator, true);
    assert!(error_text(&no_terminator).contains("Missing image directory terminator"));

    let mut short_entry = fs.clone();
    put_u16(&mut short_entry, procnto_entry, 8, true);
    seal(&mut short_entry, true);
    assert!(error_text(&short_entry).contains("Invalid directory entry size 8 B"));

    let mut no_mountpoint_end = fs.clone();
    no_mountpoint_end[IMAGE_HEADER_SIZE..dir_offset].fill(b'/');
    seal(&mut no_mountpoint_end, true);
    assert!(error_text(&no_mountpoint_end).contains("Missing mountpoint terminator"));

    let mut skipped = fs.clone();
    put_u32(&mut skipped, procnto_entry + 4, 0, true);
    seal(&mut skipped, true);
    let p = classify(&skipped);
    assert!(has_note(&p, "1 entries with inode 0 skipped"));
    assert!(!labels(&p).contains(&"/proc/boot/procnto".to_string()));
}

/// A small image filesystem for the sweeps: one ELF member `bin/a` and,
/// when `with_script` is set, the boot script `.script`.
fn small_imagefs(le: bool, member: &[u8], script: &[u8], with_script: bool) -> Vec<u8> {
    let mut entries = vec![Entry::File(2, "bin/a", member)];
    if with_script {
        entries.push(Entry::File(3, ".script", script));
    }
    imagefs(&ImageFsSpec {
        le,
        mountpoint: "/",
        entries,
        boot_ino: 2,
        script_ino: if with_script { 3 } else { 0 },
    })
}

#[test]
fn truncations_and_mutations_of_every_layout_stay_bounded() {
    let member = elf32(EM_ARM, true, 64);
    let script = boot_script();
    let bare = small_imagefs(true, &member, &script, true);
    assert_eq!(classify(&bare).format.format, FileFormat::QnxIfs);
    sweep(&bare);

    let mut prefix = vec![0x90u8; 0x10];
    prefix[0] = 0xeb;
    // (byte order, compression, boot prefix)
    let layouts: [(bool, u8, &[u8]); 4] = [
        (true, COMPRESS_NONE, &prefix),
        (false, COMPRESS_ZLIB, &[]),
        (true, COMPRESS_LZO, &[]),
        (true, COMPRESS_UCL, &[]),
    ];
    for (le, compression, prefix) in layouts {
        let image = bootable(&BootSpec {
            le,
            machine: EM_ARM,
            compression,
            prefix,
            startup: &arm_startup(le)[..16],
            imagefs: &small_imagefs(le, &member, &script, false),
        });
        assert_eq!(classify(&image).format.format, FileFormat::QnxIfs);
        sweep(&image);
        let at = prefix.len();
        resealed_sweep(&image, |mutated| try_reseal(mutated, at, le));
    }
}

#[test]
fn mutations_behind_valid_checksums_stay_bounded() {
    // Every checksum is recomputed after the mutation, so header fields,
    // directory entries, the boot script and compressed blocks reach their
    // parsers instead of failing the trailer check.
    let member = elf32(EM_ARM, true, 64);
    let script = boot_script();
    let bare = small_imagefs(true, &member, &script, true);
    resealed_sweep(&bare, |mutated| seal(mutated, true));
    // Mutations of the decoded image filesystem inside an LZO image.
    for i in 0..bare.len() {
        let mut fs = bare.clone();
        fs[i] ^= 0x80;
        seal(&mut fs, true);
        let image = bootable(&BootSpec {
            le: true,
            machine: EM_ARM,
            compression: COMPRESS_LZO,
            prefix: &[],
            startup: &[],
            imagefs: &fs,
        });
        let _ = detect_payload(&image, &ClassifierOptions::new());
    }
}

#[test]
fn a_real_image_classifies_when_one_is_provided() {
    let Ok(path) = std::env::var("QNX_IFS_FIXTURE") else {
        eprintln!("QNX_IFS_FIXTURE not set; skipped");
        return;
    };
    let data = std::fs::read(&path).expect("QNX_IFS_FIXTURE is readable");
    let p = classify(&data);
    assert_eq!(p.format.format, FileFormat::QnxIfs, "{path}");
    assert!(has_note(&p, "checksum verified"), "{:?}", notes(&p));
}
