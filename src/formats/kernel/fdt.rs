//! Flattened devicetree reader (Devicetree Specification v0.4, chapter 5).
//!
//! Header (40 B, big-endian): magic, `totalsize`, `off_dt_struct`,
//! `off_dt_strings`, `off_mem_rsvmap`, `version`, `last_comp_version`,
//! `boot_cpuid_phys`, `size_dt_strings`, `size_dt_struct`. The structure
//! block is a token stream: `FDT_BEGIN_NODE` with a NUL-terminated name,
//! `FDT_PROP` with length, string-table offset and value, `FDT_END_NODE`,
//! `FDT_NOP` and a final `FDT_END`; every token is four-byte aligned.

use super::*;

const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

/// Header size of version 17 blobs; earlier versions are not accepted.
const HEADER_SIZE: usize = 40;

/// First version that records `size_dt_struct`.
const VERSION_STRUCT_SIZE: u32 = 17;

/// Nesting deeper than this is not a real device tree.
const MAX_DEPTH: usize = 64;

/// A property: name, value bytes and the value's file offset.
#[derive(Debug)]
pub(super) struct Prop<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
    pub offset: usize,
}

/// A node, with its children as indices into [`Fdt::nodes`].
#[derive(Debug)]
pub(super) struct Node<'a> {
    pub name: &'a str,
    pub props: Vec<Prop<'a>>,
    pub children: Vec<usize>,
}

impl<'a> Node<'a> {
    pub fn prop(&self, name: &str) -> Option<&Prop<'a>> {
        self.props.iter().find(|p| p.name == name)
    }

    /// A string property without its NUL terminator.
    pub fn string(&self, name: &str) -> Option<&'a str> {
        let value = self.prop(name)?.value;
        let text = value.strip_suffix(&[0]).unwrap_or(value);
        std::str::from_utf8(text).ok()
    }

    /// A one-cell (`u32`) or two-cell (`u64`) integer property.
    pub fn integer(&self, name: &str) -> Option<u64> {
        let value = self.prop(name)?.value;
        match value.len() {
            4 => Some(u64::from(u32::from_be_bytes(value.try_into().ok()?))),
            8 => Some(u64::from_be_bytes(value.try_into().ok()?)),
            _ => None,
        }
    }
}

/// A parsed blob. Node 0 is the root.
#[derive(Debug)]
pub(super) struct Fdt<'a> {
    pub total_size: usize,
    pub version: u32,
    pub nodes: Vec<Node<'a>>,
}

impl<'a> Fdt<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = slice(data, 0, HEADER_SIZE)?;
        if be_u32(header, 0)? != FDT_MAGIC {
            return Err(error("Missing FDT magic"));
        }
        let total_size = be_u32(header, 4)? as usize;
        let off_struct = be_u32(header, 8)? as usize;
        let off_strings = be_u32(header, 12)? as usize;
        let version = be_u32(header, 20)?;
        let size_strings = be_u32(header, 32)? as usize;
        let blob = data.get(..total_size).ok_or_else(|| {
            error(format!(
                "Truncated FDT: header declares {total_size} B, {} B present",
                data.len()
            ))
        })?;
        if version < VERSION_STRUCT_SIZE {
            return Err(error(format!("Unsupported FDT version {version}")));
        }
        let size_struct = be_u32(header, 36)? as usize;
        let structure = slice(blob, off_struct, size_struct)?;
        let strings = slice(blob, off_strings, size_strings)?;
        let mut tree = Fdt {
            total_size,
            version,
            nodes: Vec::new(),
        };
        tree.walk(structure, off_struct, strings)?;
        if tree.nodes.is_empty() {
            return Err(error("FDT has no root node"));
        }
        Ok(tree)
    }

    fn walk(&mut self, structure: &'a [u8], base: usize, strings: &'a [u8]) -> Result<()> {
        let mut stack: Vec<usize> = Vec::new();
        let mut pos = 0;
        loop {
            let token = be_u32(structure, pos)?;
            pos += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let rest = &structure[pos..];
                    let len =
                        memchr::memchr(0, rest).ok_or_else(|| error("Truncated FDT node name"))?;
                    let name = std::str::from_utf8(&rest[..len]).map_err(|_| {
                        error(format!("Invalid FDT node name at 0x{:X}", base + pos))
                    })?;
                    pos = align4(pos + len + 1)?;
                    if stack.len() >= MAX_DEPTH {
                        return Err(error("FDT nesting exceeds 64 levels"));
                    }
                    if stack.is_empty() && !self.nodes.is_empty() {
                        return Err(error("FDT has more than one root node"));
                    }
                    let index = self.nodes.len();
                    if let Some(&parent) = stack.last() {
                        self.nodes[parent].children.push(index);
                    }
                    self.nodes.push(Node {
                        name,
                        props: Vec::new(),
                        children: Vec::new(),
                    });
                    stack.push(index);
                }
                FDT_END_NODE => {
                    stack
                        .pop()
                        .ok_or_else(|| error("Unbalanced FDT_END_NODE"))?;
                }
                FDT_PROP => {
                    let len = be_u32(structure, pos)? as usize;
                    let name_offset = be_u32(structure, pos + 4)? as usize;
                    let value = slice(structure, pos + 8, len)?;
                    let name_bytes = strings
                        .get(name_offset..)
                        .ok_or_else(|| error("Invalid FDT property name offset"))?;
                    let name_len = memchr::memchr(0, name_bytes)
                        .ok_or_else(|| error("Unterminated FDT property name"))?;
                    let name = std::str::from_utf8(&name_bytes[..name_len])
                        .map_err(|_| error("Invalid FDT property name"))?;
                    let node = *stack
                        .last()
                        .ok_or_else(|| error("FDT property outside a node"))?;
                    self.nodes[node].props.push(Prop {
                        name,
                        value,
                        offset: base + pos + 8,
                    });
                    pos = align4(pos + 8 + len)?;
                }
                FDT_NOP => {}
                FDT_END => {
                    if !stack.is_empty() {
                        return Err(error("FDT_END inside an open node"));
                    }
                    return Ok(());
                }
                other => {
                    return Err(error(format!(
                        "Invalid FDT token 0x{other:X} at 0x{:X}",
                        base + pos - 4
                    )))
                }
            }
        }
    }

    /// The child of node `parent` called `name`.
    pub fn child(&self, parent: usize, name: &str) -> Option<usize> {
        self.nodes
            .get(parent)?
            .children
            .iter()
            .copied()
            .find(|&i| self.nodes[i].name == name)
    }
}
