//! Compressed jimage resources (`OpenJDK` `jdk-21+35`:
//! `imageDecompressor.hpp`/`.cpp`, `CompressedResourceHeader.java`,
//! `Decompressor.java`, `ZipDecompressor.java`,
//! `StringSharingDecompressor.java`, `CompressIndexes.java`).
//!
//! A compressed resource is one or more layers, each a 29-byte header in
//! the image byte order followed by its payload:
//!
//! ```text
//! 0   u4  magic 0xCAFEFAFA
//! 4   u8  payload size
//! 12  u8  size after decoding this layer
//! 20  u4  decompressor name (string offset)
//! 24  u4  decompressor configuration (string offset, -1 for none)
//! 28  u1  1 for the innermost layer (the first jlink applied), else 0
//! ```
//!
//! Both readers decode layers while the content starts with the magic and
//! ignore the last-layer byte. Two decompressors exist: `zip`, a zlib
//! stream (RFC 1950), and `compact-cp`, which rebuilds a class file's
//! constant pool from strings that jlink moved into the image's string
//! table.

use super::jimage::Strings;
use super::*;
use crate::formats::compressed::{self, Codec};

/// The layer header magic (`ResourceHeader::resource_header_magic`).
const HEADER_MAGIC: u32 = 0xcafe_fafa;

/// Layer header size (`CompressedResourceHeader.SIZE`).
const HEADER_SIZE: usize = 29;

/// Most layers decoded for one resource. jlink applies at most two
/// (`DefaultCompressPlugin`: string sharing, then zip); our own limit.
const MAX_LAYERS: usize = 4;

/// Longest decompressor name read; a longer one is invalid. Our own limit:
/// the registered names are 3 and 10 bytes.
const MAX_NAME_TEXT: usize = 64;

/// The registered decompressor names (`ResourceDecompressorRepository`).
const ZIP: &[u8] = b"zip";
const COMPACT_CP: &[u8] = b"compact-cp";

/// Transform names for decoded children, by the decompressors applied.
const ZIP_TRANSFORM: &str = "jimage zip";
const COMPACT_CP_TRANSFORM: &str = "jimage compact-cp";
const ZIP_AND_COMPACT_CP_TRANSFORM: &str = "jimage zip and compact-cp";

/// A decoded resource.
pub(super) struct Decoded<'a> {
    pub(super) data: Cow<'a, [u8]>,
    /// The decompressors applied; none when the content carried no layer
    /// header and is returned as stored.
    pub(super) applied: Applied,
}

/// Why a compressed resource was not decoded.
pub(super) enum Undecoded {
    /// Decoding would pass [`MAX_EXTRACTED`].
    Limit,
    /// A layer names a decompressor that is not implemented.
    Unsupported(String),
    /// A layer header or payload is invalid.
    Invalid(ClassifierError),
}

impl From<ClassifierError> for Undecoded {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// One layer header.
struct LayerHeader {
    /// Payload size in bytes.
    size: u64,
    /// Size after decoding this layer, in bytes.
    decoded_size: u64,
    /// String offset of the decompressor name.
    name: u32,
}

impl LayerHeader {
    /// The header at the start of `content`, or `None` when `content` does
    /// not start with one. The payload must be the rest of the content, as
    /// jlink writes it (`ResourcePoolManager.newCompressedResource`): the
    /// readers disagree about any other size.
    fn read(content: &[u8], le: bool, at: usize) -> Result<Option<Self>> {
        let has_magic = content.len() >= HEADER_SIZE
            && u32_at(content, 0, le, "jimage resource")? == HEADER_MAGIC;
        if !has_magic {
            return Ok(None);
        }
        let header = Self {
            size: u64_at(content, 4, le, "jimage resource header")?,
            decoded_size: u64_at(content, 12, le, "jimage resource header")?,
            name: u32_at(content, 20, le, "jimage resource header")?,
        };
        let payload = (content.len() - HEADER_SIZE) as u64;
        if header.size != payload {
            return Err(error(format!(
                "Invalid jimage compressed resource header at 0x{at:X}: payload size {} B, \
                 {payload} B follow",
                header.size
            )));
        }
        Ok(Some(header))
    }
}

/// The decompressors a resource's layers named.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Applied {
    pub(super) zip: bool,
    pub(super) compact_cp: bool,
}

impl Applied {
    /// The transform name for a decoded child, or `None` when no layer was
    /// decoded.
    pub(super) fn transform(self) -> Option<&'static str> {
        match (self.zip, self.compact_cp) {
            (true, false) => Some(ZIP_TRANSFORM),
            (false, true) => Some(COMPACT_CP_TRANSFORM),
            (true, true) => Some(ZIP_AND_COMPACT_CP_TRANSFORM),
            (false, false) => None,
        }
    }
}

/// Decode the compressed resource `stored`, found at file offset `at`,
/// to its `size` bytes. Each layer's output is charged to `budget` before
/// it is decoded.
pub(super) fn decode<'a>(
    stored: &'a [u8],
    at: usize,
    size: usize,
    strings: &Strings<'_>,
    le: bool,
    budget: &mut Budget,
) -> std::result::Result<Decoded<'a>, Undecoded> {
    let mut content = Cow::Borrowed(stored);
    let mut applied = Applied::default();
    for _ in 0..MAX_LAYERS {
        let Some(header) = LayerHeader::read(&content, le, at)? else {
            return finish(content, size, at, applied);
        };
        let decoded_size = usize::try_from(header.decoded_size)
            .ok()
            .filter(|decoded_size| *decoded_size <= MAX_PAYLOAD)
            .ok_or_else(|| {
                error(format!(
                    "Invalid jimage compressed resource at 0x{at:X}: a layer decodes to {} B, \
                     over the {} limit",
                    header.decoded_size,
                    size_text(MAX_PAYLOAD)
                ))
            })?;
        let name = strings.get(u64::from(header.name), MAX_NAME_TEXT)?;
        let payload = &content[HEADER_SIZE..];
        let decoded = match name {
            ZIP => {
                applied.zip = true;
                if !budget.charge(decoded_size) {
                    return Err(Undecoded::Limit);
                }
                inflate(payload, decoded_size, at)?
            }
            COMPACT_CP => {
                applied.compact_cp = true;
                if !budget.charge(decoded_size) {
                    return Err(Undecoded::Limit);
                }
                rebuild_constant_pool(payload, decoded_size, strings)?
            }
            other => {
                return Err(Undecoded::Unsupported(
                    String::from_utf8_lossy(other).into_owned(),
                ))
            }
        };
        content = Cow::Owned(decoded);
    }
    Err(error(format!(
        "Unsupported jimage compressed resource at 0x{at:X}: more than {MAX_LAYERS} layers"
    ))
    .into())
}

/// The decoded content, which must have the location's size: the native
/// reader copies that many bytes from the last layer's output.
fn finish(
    content: Cow<'_, [u8]>,
    size: usize,
    at: usize,
    applied: Applied,
) -> std::result::Result<Decoded<'_>, Undecoded> {
    if content.len() != size {
        return Err(error(format!(
            "Invalid jimage compressed resource at 0x{at:X}: decodes to {} B, the location \
             names {size} B",
            content.len()
        ))
        .into());
    }
    Ok(Decoded {
        data: content,
        applied,
    })
}

/// A `zip` layer: a zlib stream that must decode to exactly `size` bytes
/// (`ZIP_InflateFully` fails on any other size).
fn inflate(payload: &[u8], size: usize, at: usize) -> Result<Vec<u8>> {
    let decoded = compressed::decode_limited(Codec::Zlib, payload, size)?;
    if decoded.data.len() != size {
        return Err(error(format!(
            "Invalid jimage zip layer at 0x{at:X}: decodes to {} B, the header names {size} B",
            decoded.data.len()
        )));
    }
    Ok(decoded.data)
}

/// Class file constant pool tags that `compact-cp` handles
/// (`StringSharingDecompressor`): UTF-8 entries kept in place, the two
/// externalized forms, and the 8-byte entries that occupy two slots.
const CONSTANT_UTF8: u8 = 1;
const CONSTANT_LONG: u8 = 5;
const CONSTANT_DOUBLE: u8 = 6;
const EXTERNALIZED_STRING: u8 = 23;
const EXTERNALIZED_STRING_DESCRIPTOR: u8 = 25;

/// Bytes after the tag of every other constant pool entry, by tag
/// (`StringSharingDecompressor.SIZES`). Tags 0, 2, 13, 14 and 17 have no
/// entry in the table and are copied without data, as both readers do.
#[rustfmt::skip]
const SIZES: [usize; 21] = [
    0, 0, 0, 4, 4, 8, 8, 2, 2, 4, //  0-9
    4, 4, 4, 0, 0, 3, 2, 0, 4, 2, // 10-19
    2,                            // 20
];

/// Class file header kept as is: magic, minor and major version.
const CLASS_HEADER_SIZE: usize = 8;

/// Longest string a constant pool UTF-8 entry holds (a u2 length).
const MAX_UTF8: usize = 0xffff;

/// Compressed integers (`CompressIndexes`): `COMPRESSED_FLAG` marks the
/// short form, whose length in bytes is the two bits at `HEADER_SHIFT`
/// and whose leading value bits are the five below them.
const COMPRESSED_FLAG: u8 = 0x80;
const HEADER_SHIFT: u8 = 5;
const LENGTH_MASK: u8 = 0x03;
const VALUE_MASK: u8 = 0x1f;

/// Bytes of a compressed integer in the long form.
const LONG_FORM_SIZE: usize = 4;

/// A cursor over a layer payload.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let taken = slice(self.bytes, self.pos, len, "compact-cp class data")?;
        self.pos += len;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn be_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    /// A compressed integer (`CompressIndexes.readInt`): with bit 7 set,
    /// bits 6-5 give the total length in bytes and bits 4-0 the leading
    /// value bits; otherwise four bytes big-endian.
    fn compressed_int(&mut self) -> Result<u32> {
        let first = self.byte()?;
        let (length, leading) = if first & COMPRESSED_FLAG == 0 {
            (LONG_FORM_SIZE, first)
        } else {
            (
                usize::from((first >> HEADER_SHIFT) & LENGTH_MASK),
                first & VALUE_MASK,
            )
        };
        if length == 0 {
            // `CompressIndexes.compress` never writes length 0, and the two
            // readers disagree about it.
            return Err(error(format!(
                "Invalid compact-cp compressed integer 0x{first:02X} at payload offset 0x{:X}",
                self.pos - 1
            )));
        }
        let rest = self.take(length - 1)?;
        Ok(rest
            .iter()
            .fold(u32::from(leading), |value, &b| (value << 8) | u32::from(b)))
    }
}

/// Output of exactly the size a layer header names.
struct Output {
    bytes: Vec<u8>,
    size: usize,
}

impl Output {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.bytes.len() + bytes.len() > self.size {
            return Err(error(format!(
                "Invalid compact-cp layer: the class grows beyond the {} B its header names",
                self.size
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// A UTF-8 constant: tag 1, u2 big-endian length, bytes.
    fn utf8(&mut self, text: &[u8]) -> Result<()> {
        let length = u16::try_from(text.len())
            .map_err(|_| error("Invalid compact-cp string: longer than 65535 B"))?;
        self.write(&[CONSTANT_UTF8])?;
        self.write(&length.to_be_bytes())?;
        self.write(text)
    }
}

/// A `compact-cp` layer: copy the class header and constant pool count,
/// rebuild each externalized UTF-8 entry from the string table, copy every
/// other entry and then the rest of the class. The result must have the
/// `size` the layer header names (the native reader asserts it).
fn rebuild_constant_pool(payload: &[u8], size: usize, strings: &Strings<'_>) -> Result<Vec<u8>> {
    let mut input = Cursor::new(payload);
    let mut out = Output {
        bytes: Vec::with_capacity(size),
        size,
    };
    out.write(input.take(CLASS_HEADER_SIZE)?)?;
    let count = input.be_u16()?;
    out.write(&count.to_be_bytes())?;
    // Entry 0 does not exist; long and double entries take two indexes.
    let mut entry = 1u32;
    while entry < u32::from(count) {
        let tag = input.byte()?;
        match tag {
            CONSTANT_UTF8 => {
                let length = input.be_u16()?;
                out.write(&[tag])?;
                out.write(&length.to_be_bytes())?;
                out.write(input.take(usize::from(length))?)?;
            }
            EXTERNALIZED_STRING => {
                let offset = input.compressed_int()?;
                out.utf8(strings.get(u64::from(offset), MAX_UTF8)?)?;
            }
            EXTERNALIZED_STRING_DESCRIPTOR => rebuild_descriptor(&mut input, strings, &mut out)?,
            _ => {
                if matches!(tag, CONSTANT_LONG | CONSTANT_DOUBLE) {
                    entry += 1;
                }
                let size = *SIZES
                    .get(usize::from(tag))
                    .ok_or_else(|| error(format!("Invalid compact-cp constant pool tag {tag}")))?;
                out.write(&[tag])?;
                out.write(input.take(size)?)?;
            }
        }
        entry += 1;
    }
    out.write(input.rest())?;
    if out.bytes.len() != size {
        return Err(error(format!(
            "Invalid compact-cp layer: the class is {} B, the header names {size} B",
            out.bytes.len()
        )));
    }
    Ok(out.bytes)
}

/// An externalized descriptor: the descriptor string with each object
/// type reduced to `L`, then the string offsets of each type's package and
/// class name. Every `L` takes the next two offsets; a non-empty package is
/// followed by `/`.
fn rebuild_descriptor(
    input: &mut Cursor<'_>,
    strings: &Strings<'_>,
    out: &mut Output,
) -> Result<()> {
    let descriptor = strings.get(u64::from(input.compressed_int()?), MAX_UTF8)?;
    let indexes_length = input.compressed_int()? as usize;
    if indexes_length == 0 {
        // jlink writes this form only for descriptors with object types.
        return Err(error("Invalid compact-cp descriptor without type indexes"));
    }
    let mut types = Cursor::new(input.take(indexes_length)?);
    let mut text = Vec::with_capacity(descriptor.len());
    for &c in descriptor {
        text.push(c);
        if c != b'L' {
            continue;
        }
        let package = strings.get(u64::from(types.compressed_int()?), MAX_UTF8)?;
        if !package.is_empty() {
            text.extend_from_slice(package);
            text.push(b'/');
        }
        text.extend_from_slice(strings.get(u64::from(types.compressed_int()?), MAX_UTF8)?);
        if text.len() > MAX_UTF8 {
            return Err(error("Invalid compact-cp descriptor: longer than 65535 B"));
        }
    }
    out.utf8(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(bytes: &[u8]) -> Strings<'_> {
        Strings::new(bytes, 0)
    }

    #[test]
    fn compressed_integers_follow_compress_indexes() {
        // 1 is one byte: 0x80 | 1 << 5 | 1.
        let mut cursor = Cursor::new(&[0xa1, 0xc1, 0x02, 0xe1, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03]);
        assert_eq!(cursor.compressed_int().unwrap(), 1);
        assert_eq!(cursor.compressed_int().unwrap(), 0x0102);
        assert_eq!(cursor.compressed_int().unwrap(), 0x01_0203);
        assert_eq!(cursor.compressed_int().unwrap(), 0x0001_0203);
        assert!(Cursor::new(&[0x81]).compressed_int().is_err());
        assert!(Cursor::new(&[0xc1]).compressed_int().is_err());
    }

    #[test]
    fn descriptors_take_a_package_and_a_class_per_object_type() {
        // Strings: 1 "(L;I)V", 8 "java/lang", 18 "String", 25 "".
        let table = strings(b"\0(L;I)V\0java/lang\0String\0\0");
        let encoded = [0xa1, 0xa2, 0xa8, 0xb2];
        let mut input = Cursor::new(&encoded);
        let mut out = Output {
            bytes: Vec::new(),
            size: 64,
        };
        rebuild_descriptor(&mut input, &table, &mut out).unwrap();
        assert_eq!(out.bytes, b"\x01\x00\x16(Ljava/lang/String;I)V");

        let empty_package = [0xa1, 0xa2, 0xb9, 0xb2];
        let mut input = Cursor::new(&empty_package);
        let mut out = Output {
            bytes: Vec::new(),
            size: 64,
        };
        rebuild_descriptor(&mut input, &table, &mut out).unwrap();
        assert_eq!(out.bytes, b"\x01\x00\x0c(LString;I)V");
    }

    #[test]
    fn constant_pools_are_rebuilt_to_the_declared_size() {
        // Strings: 1 "Hello".
        let table = strings(b"\0Hello\0");
        let mut payload = b"\xca\xfe\xba\xbe\0\0\0\x41\x00\x04".to_vec();
        payload.extend_from_slice(&[EXTERNALIZED_STRING, 0xa1]);
        payload.extend_from_slice(&[CONSTANT_LONG, 1, 2, 3, 4, 5, 6, 7, 8]);
        payload.extend_from_slice(b"rest");
        let mut expected = b"\xca\xfe\xba\xbe\0\0\0\x41\x00\x04\x01\x00\x05Hello".to_vec();
        expected.extend_from_slice(&[CONSTANT_LONG, 1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(b"rest");
        let rebuilt = rebuild_constant_pool(&payload, expected.len(), &table).unwrap();
        assert_eq!(rebuilt, expected);
        assert!(rebuild_constant_pool(&payload, expected.len() - 1, &table).is_err());
        assert!(rebuild_constant_pool(&payload, expected.len() + 1, &table).is_err());
        let mut bad_tag = payload.clone();
        bad_tag[10] = 21;
        assert!(rebuild_constant_pool(&bad_tag, expected.len(), &table).is_err());
    }
}
