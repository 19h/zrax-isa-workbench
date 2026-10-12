//! U-Boot Flattened Image Tree (FIT) images and plain device tree blobs.
//!
//! A FIT is a device tree whose `/images` subnodes each describe one image
//! (`doc/usage/fit/source_file_format.rst`): `type`, `arch`, `os`,
//! `compression`, `load`, `entry`, and the data, either inline in `data` or
//! external: `data-size` bytes at `data-position` (from the start of the
//! file) or at `data-offset` (from the end of the device tree, aligned to
//! four bytes). `/configurations` names the default kernel.

use super::*;
use fdt::{Fdt, Node};

/// A configuration's image references (`kernel = "kernel-1"`).
const CONFIG_KERNEL: &str = "kernel";

/// The stored bytes of an image node and their file offset.
fn image_data<'a>(
    data: &'a [u8],
    node: &Node<'a>,
    tree_end: usize,
) -> Result<Option<(usize, &'a [u8])>> {
    if let Some(inline) = node.prop("data") {
        return Ok(Some((inline.offset, inline.value)));
    }
    let Some(size) = node.integer("data-size") else {
        return Ok(None);
    };
    let size = usize::try_from(size).map_err(|_| error("Invalid FIT data-size"))?;
    let start = if let Some(position) = node.integer("data-position") {
        usize::try_from(position).map_err(|_| error("Invalid FIT data-position"))?
    } else if let Some(offset) = node.integer("data-offset") {
        let offset = usize::try_from(offset).map_err(|_| error("Invalid FIT data-offset"))?;
        tree_end
            .checked_add(offset)
            .ok_or_else(|| error("Invalid FIT data-offset"))?
    } else {
        return Err(error(format!(
            "FIT image {} has data-size but no data-offset or data-position",
            node.name
        )));
    };
    Ok(Some((start, slice(data, start, size)?)))
}

/// The architecture of the default configuration's kernel, else of the
/// first kernel image.
fn default_kernel_arch<'a>(tree: &Fdt<'a>, images: usize) -> Option<&'a str> {
    let configurations = tree.child(0, "configurations");
    let default_kernel = configurations.and_then(|c| {
        let node = &tree.nodes[c];
        let config = tree.child(c, node.string("default")?)?;
        tree.nodes[config].string(CONFIG_KERNEL)
    });
    let kernel = match default_kernel {
        Some(name) => tree.child(images, name),
        None => tree.nodes[images]
            .children
            .iter()
            .copied()
            .find(|&i| tree.nodes[i].string("type") == Some("kernel")),
    }?;
    tree.nodes[kernel].string("arch")
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let tree = Fdt::parse(data)?;
    let images = tree
        .child(0, "images")
        .ok_or_else(|| error("Missing FIT /images node"))?;
    let tree_end = align4(tree.total_size)?;
    let mut c = Container::new(FileFormat::Fit, "FIT", "fit");
    c.consumed = tree.total_size;
    let root = &tree.nodes[0];
    c.notes.push(match root.string("description") {
        Some(description) if !description.is_empty() => {
            format!("U-Boot FIT image: {description}")
        }
        _ => "U-Boot FIT image".to_string(),
    });
    if let Some(arch) = default_kernel_arch(&tree, images) {
        c.target = arch_by_name(arch).and_then(|a| a.target);
    }
    let mut hashed = false;
    for &index in tree.nodes[images]
        .children
        .iter()
        .take(crate::formats::container::MAX_COMPONENTS)
    {
        let node = &tree.nodes[index];
        let image_type = node.string("type").unwrap_or("unknown");
        let label = format!("{} ({image_type})", node.name);
        hashed |= node.children.iter().any(|&h| {
            tree.nodes[h].name.starts_with("hash") || tree.nodes[h].name.starts_with("signature")
        });
        let Some((offset, stored)) = image_data(data, node, tree_end)? else {
            c.notes.push(format!("{label}: no data"));
            continue;
        };
        c.consumed = c.consumed.max(offset + stored.len());
        let compression = node.string("compression").unwrap_or("none");
        let codec = COMPRESSIONS
            .iter()
            .find(|(_, name, _)| *name == compression);
        let mut child = component(
            label.clone(),
            offset,
            stored,
            codec.and_then(|(_, _, codec)| *codec),
            &mut c.notes,
        );
        if codec.is_none() {
            c.notes.push(format!(
                "{label}: unknown compression {compression}; not decoded"
            ));
            child.opaque = true;
        }
        child.opaque |= OPAQUE_TYPES.contains(&image_type);
        let target = node
            .string("arch")
            .and_then(arch_by_name)
            .and_then(|a| a.target);
        if let (Some(target), true) = (target, EXECUTABLE_TYPES.contains(&image_type)) {
            child = child.with_target(target);
        }
        let mut details = vec![format!("{label}: {} B stored", stored.len())];
        if let Some(arch) = node.string("arch") {
            details.push(format!("arch {arch}"));
        }
        if compression != "none" {
            details.push(format!("{compression}-compressed"));
        }
        if let Some(load) = node.integer("load") {
            details.push(format!("load 0x{load:X}"));
        }
        if let Some(entry) = node.integer("entry") {
            details.push(format!("entry 0x{entry:X}"));
            if c.entry.is_none() && image_type == "kernel" {
                c.entry = Some(entry);
            }
        }
        c.notes.push(details.join("; "));
        c.children.push(child);
    }
    if hashed {
        c.notes
            .push("Image hashes and signatures are present but not verified".into());
    }
    Ok(c)
}

/// A device tree blob: configuration data for the kernel, never code.
pub(super) fn parse_dtb(data: &[u8]) -> Result<Container<'_>> {
    let tree = Fdt::parse(data)?;
    let mut c = Container::new(FileFormat::Dtb, "FDT", "dtb");
    c.consumed = tree.total_size;
    c.notes.push("Device Tree Blob".into());
    c.notes.push(format!(
        "Version {}; total size {} B; {} nodes",
        tree.version,
        tree.total_size,
        tree.nodes.len()
    ));
    if let Some(model) = tree.nodes[0].string("model") {
        c.notes.push(format!("Model: {model}"));
    }
    if let Some(compatible) = tree.nodes[0].prop("compatible") {
        let names: Vec<String> = compatible
            .value
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        c.notes.push(format!("Compatible: {}", names.join(", ")));
    }
    Ok(c)
}
