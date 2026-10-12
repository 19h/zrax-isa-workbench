//! TF-A Firmware Image Package. Header, table of contents and UUIDs follow
//! `include/tools_share/firmware_image_package.h`; all fields are little-endian.
use super::*;
use std::collections::BTreeSet;

pub(super) const MAGIC: u32 = 0xaa64_0001;
const HEADER_SIZE: usize = 16;
const TOC_ENTRY_SIZE: usize = 40;

/// Known component UUIDs in stored byte order. `true` marks certificates and
/// configuration data, which are never analyzed as code.
#[rustfmt::skip]
const COMPONENTS: &[(&str, bool, &str)] = &[
    ("659227032f74e6448dff579ac1ff0610", true,  "SCP Firmware Updater Configuration FWU SCP_BL2U"),
    ("60b3eb37c1e5ea419df319eda11f6801", true,  "AP Firmware Updater Configuration BL2U"),
    ("4f511d112be54e49b4c583c2f715840a", false, "Firmware Updater NS_BL2U"),
    ("71408ab218d6874c8b2ec6dccd50f096", true,  "Non-Trusted Firmware Updater certificate"),
    ("5ff9ec0b4d223e4da544c39d81c73f0a", false, "Trusted Boot Firmware BL2"),
    ("9766fd3d89bee849ae5d78a140608213", false, "SCP Firmware SCP_BL2"),
    ("47d4086d4cfe98469b952950cbbd5a00", false, "BL31"),
    ("05d0e18953dc13478d2b500a4b7a3e38", false, "BL32"),
    ("0b70c29b2a5a78409f650a5682738288", false, "Secure Payload BL32 Extra1 (Trusted OS Extra1)"),
    ("8ea87bb1cfa23f4d85fde7bba50220d9", false, "Secure Payload BL32 Extra2 (Trusted OS Extra2)"),
    ("d6d0eea7fcead54b97829934f234b6e4", false, "BL33"),
    ("6c0762a612f24b5692cbba8f633606d9", false, "Realm Monitor Management Firmware"),
    ("5807e16a845947be8ed5648e8dddab0e", true,  "FW_CONFIG"),
    ("08b8f1d9c9cf9349a9626fbc6b7265cc", true,  "HW_CONFIG"),
    ("6c0458ffaf6b7d4f82edaa27bc69bfd2", true,  "TB_FW_CONFIG"),
    ("9979814b0376fb468c8e8d267f7859e0", true,  "SOC_FW_CONFIG"),
    ("26257c1adbc67f478d96c4c4b0248021", true,  "TOS_FW_CONFIG"),
    ("28da981593e87e44ac661aaf801550f9", true,  "NT_FW_CONFIG"),
    ("862d1d72f860e411920b8be762160f24", true,  "Root Of Trust key certificate"),
    ("827ee890f860e411a1b4777a21b4f94c", true,  "Trusted key certificate"),
    ("024221a1f860e4118d9bf33c0e15a014", true,  "SCP Firmware key certificate"),
    ("8ab8beccf960e4119ad0eb4822d8dcf8", true,  "SoC Firmware key certificate"),
    ("9477d603fb60e41185ddb7105b8cee04", true,  "Trusted OS Firmware key certificate"),
    ("8ad5832afb60e4118aafdf30bbc49859", true,  "Non-Trusted Firmware key certificate"),
    ("d6e269ea5d63e4118d8c9fbabe9956a5", true,  "Trusted Boot Firmware BL2 certificate"),
    ("44be6f045e63e411b28b73d8eaae9656", true,  "SCP Firmware content certificate"),
    ("e2b20c205e63e4119ce8abccf92bb666", true,  "SoC Firmware content certificate"),
    ("a49f44115e63e41187283f05722af33d", true,  "Trusted OS Firmware content certificate"),
    ("8ec4c1f35d63e411a7a987ee40b23fa7", true,  "Non-Trusted Firmware content certificate"),
    ("776dfd4486974c3b91ebc13e025a2a6f", true,  "SiP owned Secure Partition content certificate"),
    ("ddcbbf4acad611ea87d00242ac130003", true,  "Platform owned Secure Partition content certificate"),
    ("36d83d85761d4daf96f1cd99d6569b00", true,  "CCA Content Certificate"),
    ("52222d31820f494d8bbcea6825d3c35a", true,  "Core Secure World Key Certificate"),
    ("d43cd9025b9f412e8ac692b6d18be60d", true,  "Platform Key Certificate"),
];

/// The component's name, and whether it is data rather than an image.
fn identify(uuid: &[u8; 16]) -> (String, bool) {
    let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
    match COMPONENTS.iter().find(|(known, _, _)| *known == hex) {
        Some(&(_, opaque, name)) => (name.into(), opaque),
        None => (format!("UUID {hex}"), false),
    }
}

/// Header: magic, serial number, flags. TOC entries are (UUID, offset, size,
/// flags) with 64-bit fields; an all-zero UUID ends the TOC, and its offset
/// is the package size.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if le_u32(data, 0)? != MAGIC {
        return Err(error("Invalid FIP magic"));
    }
    ensure(data, 0, HEADER_SIZE)?;
    let mut pos = HEADER_SIZE;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let package_size = loop {
        let entry = slice(data, pos, TOC_ENTRY_SIZE)?;
        let uuid: [u8; 16] = array(entry, 0)?;
        let offset =
            usize::try_from(le_u64(entry, 16)?).map_err(|_| error("FIP offset overflow"))?;
        let size = usize::try_from(le_u64(entry, 24)?).map_err(|_| error("FIP size overflow"))?;
        let flags = le_u64(entry, 32)?;
        pos += TOC_ENTRY_SIZE;
        if uuid == [0; 16] {
            if size != 0 || flags != 0 {
                return Err(error("Invalid FIP terminator"));
            }
            break offset;
        }
        if size == 0 || !seen.insert(uuid) {
            return Err(error("Empty or duplicate FIP entry"));
        }
        ensure(data, offset, size)?;
        entries.push((uuid, offset, size, flags));
    };
    if entries.is_empty() || package_size < pos || package_size > data.len() {
        return Err(error("Invalid FIP total size"));
    }
    let mut ranges: Vec<_> = entries
        .iter()
        .map(|&(_, offset, size, _)| (offset, offset + size))
        .collect();
    ranges.sort_unstable();
    let outside = |&(start, end): &(usize, usize)| start < pos || end > package_size;
    if ranges.iter().any(outside) || ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(error("Overlapping FIP entries or TOC"));
    }
    expect_padding(data, package_size)?;
    let mut c = Container::new(Variant::Fip);
    c.consumed = package_size;
    c.notes.push(format!(
        "FIP serial {}; header flags 0x{:X}; little-endian 64-bit entry offsets and sizes",
        le_u32(data, 4)?,
        le_u64(data, 8)?
    ));
    for (uuid, offset, size, flags) in entries {
        let (label, opaque) = identify(&uuid);
        let role = if opaque {
            "certificate/configuration data"
        } else {
            "architecture is not encoded by the UUID"
        };
        c.notes.push(format!("{label}: flags 0x{flags:X}; {role}"));
        c.children.push(Child {
            label,
            offset,
            data: slice(data, offset, size)?,
            opaque,
            isa_hint: None,
        });
    }
    Ok(c)
}
