//! TI boot certificate extensions, not arbitrary ASN.1 byte-pattern searches.
//! TI signing scripts use enterprise OID 1.3.6.1.4.1.294.1.*.
use super::*;

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
/// `TBSCertificate` context tags: [0] version and [3] extensions.
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;

/// DER encoding of 1.3.6.1.4.1.294.1; the next arc is the extension ID.
const TI_OID_PREFIX: [u8; 8] = [0x2b, 6, 1, 4, 1, 0x82, 0x26, 1];
const EXT_BOOT_SEQUENCE: u8 = 1;
const EXT_ENCRYPTION: u8 = 4;
const EXT_EXTENDED_BOOT_INFO: u8 = 9;
const EXT_EXTENDED_ENCRYPTION: u8 = 10;
const EXT_INTEGRITY: u8 = 34;
const EXT_IMAGE_LOAD: u8 = 35;

/// Extended boot-info component type of board configuration data.
const BOARD_CONFIG_COMPONENT: u64 = 18;

const MAX_CERTIFICATE_SIZE: usize = 1 << 20;

/// A DER element: its tag, its contents, and the offset just past it.
#[derive(Clone, Copy)]
struct Node<'a> {
    tag: u8,
    body: &'a [u8],
    end: usize,
}

fn be_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |value, b| (value << 8) | u64::from(*b))
}

/// The element at `at`, in strict DER: low tag numbers and minimal,
/// definite lengths of up to four bytes.
fn read_node(data: &[u8], at: usize) -> Result<Node<'_>> {
    let header = slice(data, at, 2)?;
    let tag = header[0];
    if tag & 0x1f == 0x1f {
        return Err(error("Unsupported high-tag-number DER element"));
    }
    let mut pos = at + 2;
    let len = if header[1] & 0x80 == 0 {
        usize::from(header[1])
    } else {
        let count = usize::from(header[1] & 0x7f);
        if count == 0 || count > 4 {
            return Err(error("Indefinite or oversized DER length"));
        }
        let len_bytes = slice(data, pos, count)?;
        pos += count;
        if len_bytes[0] == 0 {
            return Err(error("Nonminimal DER length"));
        }
        let len = len_bytes
            .iter()
            .fold(0usize, |len, b| (len << 8) | usize::from(*b));
        if len < 128 {
            return Err(error("Nonminimal DER long length"));
        }
        len
    };
    let body = slice(data, pos, len)?;
    Ok(Node {
        tag,
        body,
        end: pos + len,
    })
}

/// Every element in `data`, which must be fully covered.
fn read_nodes(data: &[u8]) -> Result<Vec<Node<'_>>> {
    let mut nodes = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let node = read_node(data, pos)?;
        pos = node.end;
        nodes.push(node);
    }
    Ok(nodes)
}

fn sequence(node: Node<'_>) -> Result<Vec<Node<'_>>> {
    if node.tag != SEQUENCE {
        return Err(error("Expected DER SEQUENCE"));
    }
    read_nodes(node.body)
}

/// A non-negative INTEGER of at most 64 bits.
fn unsigned(node: Node<'_>) -> Result<u64> {
    let body = node.body;
    if node.tag != INTEGER || body.is_empty() || body.len() > 9 || body[0] & 0x80 != 0 {
        return Err(error("Invalid unsigned DER INTEGER"));
    }
    let magnitude = if body.len() == 9 {
        if body[0] != 0 {
            return Err(error("DER integer exceeds 64 bits"));
        }
        &body[1..]
    } else {
        body
    };
    if body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
        return Err(error("Nonminimal DER INTEGER"));
    }
    Ok(be_value(magnitude))
}

fn unsigned_usize(node: Node<'_>) -> Result<usize> {
    usize::try_from(unsigned(node)?).map_err(|_| error("TI certificate count overflow"))
}

/// TI stores destination addresses as big-endian OCTET STRINGs.
fn destination(node: Node<'_>) -> Result<u64> {
    if node.tag != OCTET_STRING || node.body.is_empty() || node.body.len() > 8 {
        return Err(error("Invalid TI destination OCTET STRING"));
    }
    Ok(be_value(node.body))
}

/// What the image parser needs from a certificate.
struct Certificate<'a> {
    /// Offset just past the certificate, where the image starts.
    end: usize,
    /// TI extensions as (extension ID, DER value).
    extensions: Vec<(u8, &'a [u8])>,
}

fn certificate(data: &[u8]) -> Result<Certificate<'_>> {
    let root = read_node(data, 0)?;
    if root.end > MAX_CERTIFICATE_SIZE {
        return Err(error("Boot certificate exceeds 1 MiB"));
    }
    // TBSCertificate, signature algorithm, signature value.
    let fields = sequence(root)?;
    if fields.len() != 3 || fields[1].tag != SEQUENCE || fields[2].tag != BIT_STRING {
        return Err(error("Invalid X.509 certificate structure"));
    }
    let tbs = sequence(fields[0])?;
    let has_version = tbs.first().is_some_and(|n| n.tag == VERSION);
    if has_version {
        let version = read_nodes(tbs[0].body)?;
        if version.len() != 1 || unsigned(version[0])? != 2 {
            return Err(error("TI boot extensions require an X.509 v3 certificate"));
        }
    }
    // Serial number, then signature algorithm (matching the outer one),
    // issuer, validity, subject and subject public key info.
    let first = usize::from(has_version);
    if tbs.len() < first + 7
        || tbs[first].tag != INTEGER
        || tbs[first + 1..first + 6].iter().any(|n| n.tag != SEQUENCE)
        || tbs[first + 1].body != fields[1].body
    {
        return Err(error("Invalid X.509 TBSCertificate fields"));
    }
    let tagged = tbs
        .iter()
        .find(|n| n.tag == EXTENSIONS)
        .ok_or_else(|| error("X.509 certificate has no extensions"))?;
    let wrapper = read_node(tagged.body, 0)?;
    if wrapper.end != tagged.body.len() {
        return Err(error("Trailing DER extension wrapper bytes"));
    }
    let mut extensions = Vec::new();
    for extension in sequence(wrapper)? {
        // OID, optional critical flag, OCTET STRING value.
        let fields = sequence(extension)?;
        if !(2..=3).contains(&fields.len())
            || fields[0].tag != OID
            || fields[fields.len() - 1].tag != OCTET_STRING
        {
            return Err(error("Invalid X.509 extension"));
        }
        if fields.len() == 3
            && (fields[1].tag != BOOLEAN || !matches!(fields[1].body, [0] | [0xff]))
        {
            return Err(error("Invalid X.509 extension critical flag"));
        }
        let oid = fields[0].body;
        let value = fields[fields.len() - 1].body;
        // The prefix plus a single-byte final arc.
        if oid.len() == 9 && oid[8] & 0x80 == 0 && oid[..8] == TI_OID_PREFIX {
            let id = oid[8];
            if extensions.iter().any(|&(seen, _)| seen == id) {
                return Err(error("Duplicate TI boot extension"));
            }
            extensions.push((id, value));
        }
    }
    if extensions.is_empty() {
        return Err(error("Certificate lacks TI enterprise boot extensions"));
    }
    Ok(Certificate {
        end: root.end,
        extensions,
    })
}

/// Record an image size, which must match any size stated before.
fn agree(size: &mut Option<usize>, n: usize) -> Result<()> {
    if size.replace(n).is_some_and(|old| old != n) {
        return Err(error("Contradictory TI image lengths"));
    }
    Ok(())
}

pub(super) fn detect(data: &[u8]) -> bool {
    data.first() == Some(&SEQUENCE) && certificate(data).is_ok()
}

/// The image follows the certificate. Its size comes from the boot-sequence,
/// integrity or extended boot-info extensions, which must agree; extended
/// boot info also splits it into per-core components.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let certificate = certificate(data)?;
    let mut c = Container::new(Variant::X509);
    let mut size = None;
    let mut load_address = 0;
    let mut encrypted = false;
    let mut components = Vec::new();
    let mut encrypted_components = Vec::new();
    for &(id, value) in &certificate.extensions {
        let root = read_node(value, 0)?;
        if root.end != value.len() {
            return Err(error("Trailing TI extension bytes"));
        }
        let fields = sequence(root)?;
        match id {
            EXT_BOOT_SEQUENCE => {
                // Certificate type, boot core, core options, load address, size.
                if fields.len() != 5 {
                    return Err(error("Invalid TI boot-sequence extension"));
                }
                c.notes.push(format!(
                    "Certificate type {}; boot core {}; options 0x{:X}",
                    unsigned(fields[0])?,
                    unsigned(fields[1])?,
                    unsigned(fields[2])?
                ));
                load_address = destination(fields[3])?;
                agree(&mut size, unsigned_usize(fields[4])?)?;
            }
            EXT_INTEGRITY => {
                // Hash algorithm, digest, size.
                if fields.len() != 3 {
                    return Err(error("Invalid TI integrity extension"));
                }
                agree(&mut size, unsigned_usize(fields[2])?)?;
            }
            EXT_IMAGE_LOAD => {
                if fields.len() != 2 {
                    return Err(error("Invalid TI image-load extension"));
                }
                load_address = destination(fields[0])?;
                c.notes.push(format!(
                    "Authentication-in-place mode {}",
                    unsigned(fields[1])?
                ));
            }
            EXT_ENCRYPTION => encrypted = true,
            EXT_EXTENDED_BOOT_INFO => {
                // Total size, component count, then the components.
                if fields.len() < 2 {
                    return Err(error("Invalid TI extended boot-info extension"));
                }
                let total = unsigned_usize(fields[0])?;
                let count = unsigned_usize(fields[1])?;
                if count != fields.len() - 2 || count == 0 {
                    return Err(error("TI component count mismatch"));
                }
                let mut sum = 0usize;
                for component in &fields[2..] {
                    // Type, boot core, options, destination, size, hash
                    // algorithm, digest.
                    let f = sequence(*component)?;
                    if f.len() != 7 {
                        return Err(error("Invalid TI component description"));
                    }
                    let kind = unsigned(f[0])?;
                    let core = unsigned(f[1])?;
                    let address = destination(f[3])?;
                    let len = unsigned_usize(f[4])?;
                    sum = sum
                        .checked_add(len)
                        .ok_or_else(|| error("TI component size overflow"))?;
                    components.push((kind, core, address, len));
                }
                if sum != total {
                    return Err(error("TI extended image size mismatch"));
                }
                agree(&mut size, total)?;
            }
            EXT_EXTENDED_ENCRYPTION => {
                // Count, then descriptors that start with a 1-based component number.
                if fields.is_empty() || unsigned_usize(fields[0])? != fields.len() - 1 {
                    return Err(error("Invalid TI extended encryption count"));
                }
                for descriptor in &fields[1..] {
                    let f = sequence(*descriptor)?;
                    let number = f
                        .first()
                        .ok_or_else(|| error("Empty encryption descriptor"))?;
                    encrypted_components.push(unsigned_usize(*number)?);
                }
            }
            _ => {}
        }
    }
    let size = size.ok_or_else(|| error("TI certificate does not describe an image length"))?;
    if size == 0 {
        return Err(error("TI boot image has no payload"));
    }
    ensure(data, certificate.end, size)?;
    c.consumed = certificate.end + size;
    expect_padding(data, c.consumed)?;
    let ids: Vec<u8> = certificate.extensions.iter().map(|&(id, _)| id).collect();
    c.notes.push(format!(
        "{} B DER certificate; TI extensions {ids:?}; signatures and image digests are not authenticated",
        certificate.end
    ));
    if components.is_empty() {
        c.opaque = encrypted;
        c.notes.push(format!(
            "Payload destination byte address 0x{load_address:X}; execution entry point is not encoded by the certificate"
        ));
        c.children.push(Child {
            label: "Boot image".into(),
            offset: certificate.end,
            data: slice(data, certificate.end, size)?,
            opaque: encrypted,
            isa_hint: None,
        });
        return Ok(c);
    }
    let mut pos = certificate.end;
    for (i, (kind, core, address, len)) in components.into_iter().enumerate() {
        let number = i + 1;
        let opaque =
            encrypted || encrypted_components.contains(&number) || kind == BOARD_CONFIG_COMPONENT;
        c.notes.push(format!(
            "Component {number}: type {kind}; boot core {core}; destination 0x{address:X}; {len} B{}",
            if opaque {
                "; encrypted or configuration data"
            } else {
                ""
            }
        ));
        c.children.push(Child {
            label: format!("Component {number} (type {kind}, core {core})"),
            offset: pos,
            data: slice(data, pos, len)?,
            opaque,
            isa_hint: None,
        });
        pos += len;
    }
    if encrypted_components
        .iter()
        .any(|&number| number == 0 || number > c.children.len())
    {
        return Err(error("Encryption component index out of range"));
    }
    Ok(c)
}
