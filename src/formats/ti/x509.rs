//! TI boot certificate extensions, not arbitrary ASN.1 byte-pattern searches.
//! TI signing scripts use enterprise OID 1.3.6.1.4.1.294.1.*.
use super::*;

#[derive(Clone, Copy)]
struct Node<'a> {
    tag: u8,
    body: &'a [u8],
    end: usize,
}
fn node(data: &[u8], at: usize) -> Result<Node<'_>> {
    let header = bytes(data, at, 2)?;
    let tag = header[0];
    if tag & 31 == 31 {
        return Err(err("Unsupported high-tag-number DER element"));
    }
    let mut pos = at + 2;
    let n = header[1];
    let len = if n & 0x80 == 0 {
        n as usize
    } else {
        let count = (n & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(err("Indefinite or oversized DER length"));
        }
        let b = bytes(data, pos, count)?;
        pos += count;
        if b[0] == 0 {
            return Err(err("Nonminimal DER length"));
        }
        let len = b.iter().fold(0usize, |v, b| (v << 8) | usize::from(*b));
        if len < 128 {
            return Err(err("Nonminimal DER long length"));
        }
        len
    };
    let body = bytes(data, pos, len)?;
    Ok(Node {
        tag,
        body,
        end: pos + len,
    })
}
fn children(data: &[u8]) -> Result<Vec<Node<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let n = node(data, pos)?;
        pos = n.end;
        out.push(n);
    }
    Ok(out)
}
fn seq(n: Node<'_>) -> Result<Vec<Node<'_>>> {
    if n.tag != 0x30 {
        return Err(err("Expected DER SEQUENCE"));
    }
    children(n.body)
}
fn uint(n: Node<'_>) -> Result<u64> {
    if n.tag != 2 || n.body.is_empty() || n.body.len() > 9 || n.body[0] & 0x80 != 0 {
        return Err(err("Invalid unsigned DER INTEGER"));
    }
    let b = if n.body.len() == 9 {
        if n.body[0] != 0 {
            return Err(err("DER integer exceeds 64 bits"));
        }
        &n.body[1..]
    } else {
        n.body
    };
    if n.body.len() > 1 && n.body[0] == 0 && n.body[1] & 0x80 == 0 {
        return Err(err("Nonminimal DER INTEGER"));
    }
    Ok(b.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b)))
}
fn address(n: Node<'_>) -> Result<u64> {
    if n.tag != 4 || n.body.is_empty() || n.body.len() > 8 {
        return Err(err("Invalid TI destination OCTET STRING"));
    }
    Ok(n.body.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b)))
}
fn count(n: Node<'_>) -> Result<usize> {
    usize::try_from(uint(n)?).map_err(|_| err("TI certificate count overflow"))
}
struct Certificate<'a> {
    end: usize,
    extensions: Vec<(u8, &'a [u8])>,
}
fn certificate(data: &[u8]) -> Result<Certificate<'_>> {
    let root = node(data, 0)?;
    if root.end > 1 << 20 {
        return Err(err("Boot certificate exceeds 1 MiB"));
    }
    let fields = seq(root)?;
    if fields.len() != 3 || fields[1].tag != 0x30 || fields[2].tag != 3 {
        return Err(err("Invalid X.509 certificate structure"));
    }
    let tbs = seq(fields[0])?;
    let base = usize::from(tbs.first().is_some_and(|n| n.tag == 0xa0));
    if base == 1 {
        let version = children(tbs[0].body)?;
        if version.len() != 1 || uint(version[0])? != 2 {
            return Err(err("TI boot extensions require an X.509 v3 certificate"));
        }
    }
    if tbs.len() < base + 7
        || tbs[base].tag != 2
        || tbs[base + 1..base + 6].iter().any(|n| n.tag != 0x30)
        || tbs[base + 1].body != fields[1].body
    {
        return Err(err("Invalid X.509 TBSCertificate fields"));
    }
    let ext = tbs
        .iter()
        .find(|n| n.tag == 0xa3)
        .ok_or_else(|| err("X.509 certificate has no extensions"))?;
    let wrapper = node(ext.body, 0)?;
    if wrapper.end != ext.body.len() {
        return Err(err("Trailing DER extension wrapper bytes"));
    }
    let mut extensions = Vec::new();
    for ext in seq(wrapper)? {
        let fields = seq(ext)?;
        if !(2..=3).contains(&fields.len()) || fields[0].tag != 6 || fields.last().unwrap().tag != 4
        {
            return Err(err("Invalid X.509 extension"));
        }
        let oid = fields[0].body;
        if fields.len() == 3 && (fields[1].tag != 1 || !matches!(fields[1].body, [0] | [255])) {
            return Err(err("Invalid X.509 extension critical flag"));
        }
        if oid.len() == 9 && oid[8] & 0x80 == 0 && oid[..8] == [0x2b, 6, 1, 4, 1, 0x82, 0x26, 1] {
            if extensions.iter().any(|(id, _)| *id == oid[8]) {
                return Err(err("Duplicate TI boot extension"));
            }
            extensions.push((oid[8], fields.last().unwrap().body));
        }
    }
    if extensions.is_empty() {
        return Err(err("Certificate lacks TI enterprise boot extensions"));
    }
    Ok(Certificate {
        end: root.end,
        extensions,
    })
}
pub(super) fn detect(data: &[u8]) -> bool {
    data.first() == Some(&0x30) && certificate(data).is_ok()
}
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let cert = certificate(data)?;
    let mut c = Container::new(Variant::X509);
    let mut size = None;
    let mut load = 0;
    let mut encrypted = false;
    let mut components = Vec::new();
    let mut encrypted_components = Vec::new();
    for (id, body) in &cert.extensions {
        let root = node(body, 0)?;
        if root.end != body.len() {
            return Err(err("Trailing TI extension bytes"));
        }
        let fields = seq(root)?;
        match id {
            1 => {
                if fields.len() != 5 {
                    return Err(err("Invalid TI boot-sequence extension"));
                }
                c.notes.push(format!(
                    "Certificate type {}; boot core {}; options 0x{:X}",
                    uint(fields[0])?,
                    uint(fields[1])?,
                    uint(fields[2])?
                ));
                load = address(fields[3])?;
                let n = count(fields[4])?;
                if size.replace(n).is_some_and(|old| old != n) {
                    return Err(err("Contradictory TI image lengths"));
                }
            }
            34 => {
                if fields.len() != 3 {
                    return Err(err("Invalid TI integrity extension"));
                }
                let n = count(fields[2])?;
                if size.replace(n).is_some_and(|old| old != n) {
                    return Err(err("Contradictory TI image lengths"));
                }
            }
            35 => {
                if fields.len() != 2 {
                    return Err(err("Invalid TI image-load extension"));
                }
                load = address(fields[0])?;
                c.notes
                    .push(format!("Authentication-in-place mode {}", uint(fields[1])?));
            }
            4 => encrypted = true,
            9 => {
                if fields.len() < 2 {
                    return Err(err("Invalid TI extended boot-info extension"));
                }
                let total = count(fields[0])?;
                let n = count(fields[1])?;
                if n != fields.len() - 2 || n == 0 {
                    return Err(err("TI component count mismatch"));
                }
                let mut sum = 0usize;
                for comp in &fields[2..] {
                    let f = seq(*comp)?;
                    if f.len() != 7 {
                        return Err(err("Invalid TI component description"));
                    }
                    let kind = uint(f[0])?;
                    let core = uint(f[1])?;
                    let a = address(f[3])?;
                    let len = count(f[4])?;
                    sum = sum
                        .checked_add(len)
                        .ok_or_else(|| err("TI component size overflow"))?;
                    components.push((kind, core, a, len));
                }
                if sum != total {
                    return Err(err("TI extended image size mismatch"));
                }
                if size.replace(total).is_some_and(|old| old != total) {
                    return Err(err("Contradictory TI image lengths"));
                }
            }
            10 => {
                if fields.is_empty() || count(fields[0])? != fields.len() - 1 {
                    return Err(err("Invalid TI extended encryption count"));
                }
                for n in &fields[1..] {
                    let f = seq(*n)?;
                    let first = f
                        .first()
                        .ok_or_else(|| err("Empty encryption descriptor"))?;
                    encrypted_components.push(count(*first)?);
                }
            }
            _ => {}
        }
    }
    let size = size.ok_or_else(|| err("TI certificate does not describe an image length"))?;
    if size == 0 {
        return Err(err("TI boot image has no payload"));
    }
    bytes(data, cert.end, size)?;
    c.consumed = cert.end + size;
    tail(data, c.consumed)?;
    c.notes.push(format!("{} B DER certificate; TI extensions {:?}; signatures and image digests are not authenticated",cert.end,cert.extensions.iter().map(|e|e.0).collect::<Vec<_>>()));
    if components.is_empty() {
        c.opaque = encrypted;
        c.notes.push(format!("Payload destination byte address 0x{load:X}; execution entry point is not encoded by the certificate"));
        c.children.push(Child {
            label: "Boot image".into(),
            offset: cert.end,
            data: bytes(data, cert.end, size)?,
            opaque: encrypted,
            isa_hint: None,
        });
    } else {
        let mut pos = cert.end;
        for (i, (kind, core, a, len)) in components.into_iter().enumerate() {
            let opaque = encrypted || encrypted_components.contains(&(i + 1)) || kind == 18;
            c.notes.push(format!(
                "Component {}: type {kind}; boot core {core}; destination 0x{a:X}; {len} B{}",
                i + 1,
                if opaque {
                    "; encrypted or configuration data"
                } else {
                    ""
                }
            ));
            c.children.push(Child {
                label: format!("Component {} (type {kind}, core {core})", i + 1),
                offset: pos,
                data: bytes(data, pos, len)?,
                opaque,
                isa_hint: None,
            });
            pos += len;
        }
        if encrypted_components
            .iter()
            .any(|i| *i == 0 || *i > c.children.len())
        {
            return Err(err("Encryption component index out of range"));
        }
    }
    Ok(c)
}
