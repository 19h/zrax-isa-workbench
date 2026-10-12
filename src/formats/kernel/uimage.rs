//! U-Boot legacy uImage (`include/image.h`, `struct legacy_img_hdr`).

use super::*;
use crate::formats::checksum::crc32;

/// Header fields after the magic, all big-endian.
const HEADER_CRC: usize = 4;
const DATA_SIZE: usize = 12;
const LOAD_ADDRESS: usize = 16;
const ENTRY_POINT: usize = 20;
const DATA_CRC: usize = 24;
const OS: usize = 0x1c;
const ARCH: usize = 0x1d;
const IMAGE_TYPE: usize = 0x1e;
const COMPRESSION: usize = 0x1f;
const NAME: usize = 0x20;
const NAME_SIZE: usize = 32;

fn os_name(os: u8) -> &'static str {
    match os {
        uimage_os::LINUX => "Linux",
        uimage_os::NETBSD => "NetBSD",
        uimage_os::FREEBSD => "FreeBSD",
        uimage_os::OPENBSD => "OpenBSD",
        uimage_os::VXWORKS => "VxWorks",
        uimage_os::QNX => "QNX",
        uimage_os::UBOOT => "U-Boot",
        uimage_os::RTEMS => "RTEMS",
        uimage_os::PLAN9 => "Plan 9",
        uimage_os::EFI => "EFI",
        uimage_os::ARM_TRUSTED => "ARM Trusted Firmware",
        uimage_os::TEE => "TEE",
        uimage_os::OPENSBI => "OpenSBI",
        _ => "Unknown",
    }
}

/// FIT name and display name of an image type.
fn type_names(image_type: u8) -> (&'static str, &'static str) {
    IMAGE_TYPES
        .iter()
        .find(|(id, _, _)| *id == image_type)
        .map_or(("unknown", "Image"), |(_, fit, name)| (*fit, *name))
}

/// Multi-file image payload: big-endian sizes terminated by zero, then the
/// images in order, each padded to four bytes.
fn multi_images(payload: &[u8]) -> Result<Vec<(usize, &[u8])>> {
    let mut sizes = Vec::new();
    let mut pos = 0;
    loop {
        let size = be_u32(payload, pos)? as usize;
        pos += 4;
        if size == 0 {
            break;
        }
        if sizes.len() >= payload.len() / 4 {
            return Err(error("Invalid uImage multi-file size table"));
        }
        sizes.push(size);
    }
    let mut images = Vec::with_capacity(sizes.len());
    for size in sizes {
        images.push((pos, slice(payload, pos, size)?));
        pos = align4(pos + size)?;
    }
    Ok(images)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, UIMAGE_HEADER_SIZE)?;
    if be_u32(header, 0)? != UIMAGE_MAGIC {
        return Err(error("Missing uImage magic"));
    }
    let stored_header_crc = be_u32(header, HEADER_CRC)?;
    let mut zeroed = header.to_vec();
    zeroed[HEADER_CRC..HEADER_CRC + 4].fill(0);
    let header_crc = crc32(&zeroed);
    if header_crc != stored_header_crc {
        return Err(error(format!(
            "Invalid uImage header CRC-32 0x{stored_header_crc:08X}, computed 0x{header_crc:08X}"
        )));
    }
    let size = be_u32(header, DATA_SIZE)? as usize;
    let load = be_u32(header, LOAD_ADDRESS)?;
    let entry = be_u32(header, ENTRY_POINT)?;
    let os = header[OS];
    let arch_id = header[ARCH];
    let image_type = header[IMAGE_TYPE];
    let compression = header[COMPRESSION];
    let name_bytes = &header[NAME..NAME + NAME_SIZE];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(NAME_SIZE);
    let name = String::from_utf8_lossy(&name_bytes[..name_len]);

    let payload = data
        .get(UIMAGE_HEADER_SIZE..UIMAGE_HEADER_SIZE + size)
        .ok_or_else(|| {
            error(format!(
                "Truncated uImage payload: header declares {size} B, {} B present",
                data.len() - UIMAGE_HEADER_SIZE
            ))
        })?;
    let stored_data_crc = be_u32(header, DATA_CRC)?;
    let data_crc = crc32(payload);
    if data_crc != stored_data_crc {
        return Err(error(format!(
            "Invalid uImage data CRC-32 0x{stored_data_crc:08X}, computed 0x{data_crc:08X}"
        )));
    }

    let arch = arch_by_id(arch_id);
    let arch_name = arch.map_or("Unknown", |a| a.name);
    let (type_id, type_label) = type_names(image_type);
    let (compression_name, codec) = match COMPRESSIONS.iter().find(|(id, _, _)| *id == compression)
    {
        Some((_, name, codec)) => (*name, *codec),
        None => ("unknown", None),
    };

    let mut c = Container::new(
        FileFormat::UImage,
        format!("{} {arch_name}", os_name(os)),
        "uimage",
    );
    c.entry = Some(u64::from(entry));
    c.target = arch.and_then(|a| a.target);
    c.consumed = UIMAGE_HEADER_SIZE + size;
    c.notes
        .push("U-Boot uImage; header and data CRC-32 verified".into());
    if !name.is_empty() {
        c.notes.push(format!("Name: {name}"));
    }
    c.notes.push(format!(
        "OS: {}; architecture: {arch_name} (ID {arch_id}); type: {type_label}; compression: {compression_name}",
        os_name(os)
    ));
    c.notes.push(format!(
        "Data size: {size} B; load address 0x{load:08X}; entry point 0x{entry:08X}"
    ));
    if arch_id == uimage_arch::SANDBOX {
        c.notes.push(
            "Architecture ID 19 is U-Boot's sandbox test build; ISA taken from the payload".into(),
        );
    }
    c.push_metadata(
        "uimage_load_address",
        "Load address",
        format!("0x{load:08X}"),
    );
    c.push_metadata("uimage_compression", "Compression", compression_name);
    c.push_metadata("uimage_image_type", "Image type", type_id);

    if compression_name == "unknown" {
        c.notes.push(format!(
            "Compression ID {compression} is not defined by U-Boot; payload not decoded"
        ));
    }
    let executable = EXECUTABLE_TYPES.contains(&type_id) || image_type == uimage_type::MULTI;
    let unknown_codec = compression_name == "unknown";
    if image_type == uimage_type::MULTI {
        for (i, (offset, image)) in multi_images(payload)?.into_iter().enumerate() {
            // The compression field applies to the first image, the kernel.
            let label = format!("Image {}", i + 1);
            let image_codec = if i == 0 { codec } else { None };
            let mut child = component(
                label,
                UIMAGE_HEADER_SIZE + offset,
                image,
                image_codec,
                &mut c.notes,
            );
            if i == 0 {
                if unknown_codec {
                    child.opaque = true;
                }
                if let Some(target) = c.target {
                    child = child.with_target(target);
                }
            }
            c.children.push(child);
        }
    } else {
        let mut child = component(
            type_label.to_string(),
            UIMAGE_HEADER_SIZE,
            payload,
            codec,
            &mut c.notes,
        );
        child.opaque |= unknown_codec || OPAQUE_TYPES.contains(&type_id);
        match c.target {
            Some(target) if executable => child = child.with_target(target),
            _ if !executable => child = child.if_recognized(),
            _ => {}
        }
        c.children.push(child);
    }
    // Firmware images often place a root filesystem right after the
    // kernel; it is listed when it is a recognized format.
    let rest = &data[c.consumed..];
    if !is_padding(rest) {
        c.children
            .push(Child::stored("Trailing data", c.consumed, rest).if_recognized());
    }
    if !executable {
        // A RAM disk or script still names an architecture, but its bytes
        // are not code for it.
        c.notes.push(format!(
            "Architecture field describes the target system; {type_label} contents are not classified as {arch_name} code"
        ));
    }
    Ok(c)
}
