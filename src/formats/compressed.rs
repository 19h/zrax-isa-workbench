//! Compressed streams: bounded decoders for the codecs that kernel and
//! firmware containers use, and recognition of standalone compressed files.
//!
//! Wire references, by codec:
//! - gzip: RFC 1952; zlib: RFC 1950; raw DEFLATE: RFC 1951 (decoded by
//!   `miniz_oxide`).
//! - xz: "The .xz File Format" 1.2.1; LZMA-alone: LZMA SDK
//!   `DOC/lzma-specification.txt` (see [`xz`]).
//! - LZ4: lz4 v1.10.0 `doc/lz4_Frame_format.md`, including the legacy frame
//!   (magic `0x184C2102`, little-endian block sizes, 8 MiB blocks) that
//!   Linux `lib/decompress_unlz4.c` reads.
//! - Zstandard: RFC 8878 (decoded by `ruzstd`), with skippable frames
//!   (`0x184D2A50`-`0x184D2A5F`).
//! - bzip2: bzip2 1.0.8 (`BZh` plus a block-size digit, then the block or
//!   end-of-stream magic; decoded by `bzip2` with the pure-Rust backend).
//! - lzop / LZO1X: see [`lzo`].
//! - LZFSE and LZVN: apple/lzfse `src/lzfse_internal.h` block magics `bvx2`,
//!   `bvx1`, `bvxn`, `bvx-` and `bvx$` (decoded by `lzfse_rust`).
//! - Apple kernelcache LZSS: see [`lzss`].
//! - Brotli: RFC 7932. It has no magic and is decoded only where a
//!   container names it.
//! - Raw LZ4 blocks: lz4 v1.10.0 `doc/lz4_Block_format.md` (see
//!   [`lz4_block`]). No magic; decoded only where a container names it.
//! - Nintendo 3DS BLZ (`.code` compression): see [`blz`]. It has no magic
//!   and is decoded only where a container names it.
//! - Raw LZO1X blocks: the per-block streams Squashfs, UBIFS and JFFS2 store
//!   (squashfs-tools 4.6.1 `lzo_wrapper.h`; Linux v6.11
//!   `fs/squashfs/lzo_wrapper.c`; see [`lzo`]). Raw
//!   LZ4 blocks in Squashfs (`lz4_wrapper.h`, `lz4_wrapper.c`) use the LZ4
//!   block decoder above. Neither has framing; both are decoded only where
//!   a container names them.
//! - JFFS2 rtime, rubinmips and dynrubin: see [`jffs2`].
//! - EFI 1.1 and Tiano compression: see [`efi`]. LZMA with the x86 BCJ
//!   decode filter applied to the output (EDK2 `LzmaF86` sections): the
//!   LZMA-alone stream above, then the LZMA SDK `x86_Convert` filter with
//!   start offset 0. These three have no magic and are decoded only where
//!   a container names them.
//!
//! Every decoder stops at an output limit ([`MAX_PAYLOAD`] unless the
//! caller passes a smaller one) instead of allocating a declared size.
//! Standalone streams are reported as containers whose single child is the
//! decoded content; stored offsets stay in file coordinates.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container};
use crate::formats::{checksum, MAX_PAYLOAD};
use crate::types::FileFormat;
use std::borrow::Cow;
use std::io::{self, Read, Write};

mod blz;
mod efi;
mod jffs2;
mod lz4_block;
mod lzo;
mod lzss;
mod xz;

/// gzip member magic (RFC 1952, section 2.3.1).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// gzip compression method 8: DEFLATE.
const GZIP_DEFLATE: u8 = 8;

/// gzip header flags (RFC 1952, section 2.3.1).
const GZIP_FHCRC: u8 = 0x02;
const GZIP_FEXTRA: u8 = 0x04;
const GZIP_FNAME: u8 = 0x08;
const GZIP_FCOMMENT: u8 = 0x10;
const GZIP_FLAGS_RESERVED: u8 = 0xe0;

/// Fixed part of a gzip member header.
const GZIP_HEADER_SIZE: usize = 10;

/// zlib compression method 8 with a window of at most 32 KiB (RFC 1950).
const ZLIB_DEFLATE: u8 = 8;
const ZLIB_MAX_WINDOW_BITS: u8 = 7;

/// LZ4 frame magic (little-endian `0x184D2204`).
const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];

/// LZ4 legacy frame magic (little-endian `0x184C2102`).
const LZ4_LEGACY_MAGIC: u32 = 0x184c_2102;

/// Legacy frame blocks decode to at most 8 MiB each.
const LZ4_LEGACY_BLOCK: usize = 8 << 20;

/// LZ4 frame descriptor: version bits must be `01` (FLG bits 7-6).
const LZ4_VERSION_MASK: u8 = 0xc0;
const LZ4_VERSION_1: u8 = 0x40;

/// Zstandard frame magic (little-endian `0xFD2FB528`).
const ZSTD_MAGIC: u32 = 0xfd2f_b528;

/// Skippable frames use magics `0x184D2A50` through `0x184D2A5F`.
const ZSTD_SKIPPABLE_MASK: u32 = 0xffff_fff0;
const ZSTD_SKIPPABLE: u32 = 0x184d_2a50;

/// bzip2 stream header `BZh` and the first block's or the end-of-stream
/// marker's 48-bit magic.
const BZIP2_MAGIC: &[u8; 3] = b"BZh";
const BZIP2_BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
const BZIP2_END_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

/// LZFSE block magics (`lzfse_internal.h`).
const LZFSE_MAGICS: [&[u8; 4]; 4] = [b"bvx2", b"bvx1", b"bvxn", b"bvx-"];

/// A compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// gzip members (RFC 1952).
    Gzip,
    /// zlib stream (RFC 1950).
    Zlib,
    /// Raw DEFLATE (RFC 1951); no magic.
    Deflate,
    /// xz container.
    Xz,
    /// LZMA-alone (`.lzma`).
    Lzma,
    /// LZ4 frame format.
    Lz4,
    /// LZ4 legacy frame (Linux kernel and initramfs images).
    Lz4Legacy,
    /// Zstandard frames.
    Zstd,
    /// bzip2 streams.
    Bzip2,
    /// lzop file.
    Lzop,
    /// LZFSE/LZVN block stream.
    Lzfse,
    /// Apple kernelcache `complzss` / `complzvn` image.
    Lzss,
    /// Brotli stream (RFC 7932); no magic.
    Brotli,
    /// Raw LZ4 block stream without a frame; no magic.
    Lz4Block,
    /// Nintendo 3DS backward LZ (`.code` compression); no magic.
    Blz,
    /// Raw LZO1X block without lzop framing; no magic.
    Lzo1x,
    /// JFFS2 rtime byte-repeat coding; no magic and no end marker.
    Rtime,
    /// JFFS2 rubin arithmetic coding with the fixed `rubinmips` model. It
    /// has no end marker, so [`decode_limited`] decodes exactly `limit`
    /// bytes.
    RubinMips,
    /// JFFS2 rubin arithmetic coding with an 8-byte probability table
    /// (`dynrubin`). Decodes exactly `limit` bytes, as [`Codec::RubinMips`].
    DynRubin,
    /// EFI 1.1 / UEFI compression (UEFI 2.10, chapter 19); no magic.
    Efi,
    /// Tiano compression (the EFI format with a 5-bit position set count);
    /// no magic.
    Tiano,
    /// LZMA-alone stream whose output is x86 BCJ-filtered (EDK2 LZMA F86);
    /// no magic.
    LzmaX86,
}

impl Codec {
    /// Every codec, for exhaustive tests.
    pub const ALL: &'static [Self] = &[
        Self::Gzip,
        Self::Zlib,
        Self::Deflate,
        Self::Xz,
        Self::Lzma,
        Self::Lz4,
        Self::Lz4Legacy,
        Self::Zstd,
        Self::Bzip2,
        Self::Lzop,
        Self::Lzfse,
        Self::Lzss,
        Self::Brotli,
        Self::Lz4Block,
        Self::Blz,
        Self::Lzo1x,
        Self::Rtime,
        Self::RubinMips,
        Self::DynRubin,
        Self::Efi,
        Self::Tiano,
        Self::LzmaX86,
    ];

    /// Short codec name, used in notes, metadata and slice transforms.
    pub fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Deflate => "DEFLATE",
            Self::Xz => "xz",
            Self::Lzma => "LZMA",
            Self::Lz4 => "LZ4",
            Self::Lz4Legacy => "LZ4 legacy",
            Self::Zstd => "Zstandard",
            Self::Bzip2 => "bzip2",
            Self::Lzop => "lzop",
            Self::Lzfse => "LZFSE",
            Self::Lzss => "Apple LZSS",
            Self::Brotli => "Brotli",
            Self::Lz4Block => "LZ4 block",
            Self::Blz => "BLZ",
            Self::Lzo1x => "LZO1X",
            Self::Rtime => "rtime",
            Self::RubinMips => "rubinmips",
            Self::DynRubin => "dynrubin",
            Self::Efi => "EFI",
            Self::Tiano => "Tiano",
            Self::LzmaX86 => "LZMA x86",
        }
    }

    /// The file format of a standalone stream in this codec.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Gzip => FileFormat::Gzip,
            Self::Zlib | Self::Deflate => FileFormat::Zlib,
            Self::Xz => FileFormat::Xz,
            Self::Lzma => FileFormat::Lzma,
            Self::Lz4 | Self::Lz4Legacy => FileFormat::Lz4,
            Self::Zstd => FileFormat::Zstd,
            Self::Bzip2 => FileFormat::Bzip2,
            Self::Lzop => FileFormat::Lzop,
            Self::Lzfse => FileFormat::Lzfse,
            Self::Lzss => FileFormat::Lzss,
            // Brotli, raw LZ4 blocks and raw LZO1X blocks have no magic and
            // are never recognized standalone.
            Self::Brotli | Self::Lz4Block | Self::Lzo1x => FileFormat::Raw,
            // BLZ has no magic either; only a 3DS ExHeader names it.
            Self::Blz => FileFormat::Raw,
            // The JFFS2 codecs have no magic either; only the containers
            // that store them name them.
            Self::Rtime | Self::RubinMips | Self::DynRubin => FileFormat::Raw,
            // EFI, Tiano and LZMA x86 have no magic either; only the UEFI
            // sections that store them name them.
            Self::Efi | Self::Tiano | Self::LzmaX86 => FileFormat::Raw,
        }
    }

    /// Classification variant label of a standalone stream.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gzip => "gzip stream",
            Self::Zlib => "zlib stream",
            Self::Deflate => "raw DEFLATE stream",
            Self::Xz => "xz stream",
            Self::Lzma => "LZMA-alone stream",
            Self::Lz4 => "LZ4 frame",
            Self::Lz4Legacy => "LZ4 legacy frame",
            Self::Zstd => "Zstandard frame",
            Self::Bzip2 => "bzip2 stream",
            Self::Lzop => "lzop file",
            Self::Lzfse => "LZFSE stream",
            Self::Lzss => "Apple LZSS kernelcache",
            Self::Brotli => "Brotli stream",
            Self::Lz4Block => "raw LZ4 block stream",
            Self::Blz => "BLZ stream",
            Self::Lzo1x => "raw LZO1X block",
            Self::Rtime => "JFFS2 rtime data",
            Self::RubinMips => "JFFS2 rubinmips data",
            Self::DynRubin => "JFFS2 dynrubin data",
            Self::Efi => "EFI compressed stream",
            Self::Tiano => "Tiano compressed stream",
            Self::LzmaX86 => "LZMA-alone stream with x86 BCJ",
        }
    }

    /// Codecs recognized only from a complete decode, because their magic is
    /// two bytes or a properties byte.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Zlib | Self::Lzma)
    }
}

/// Decoded bytes and what the decoder established about them.
#[derive(Debug)]
pub struct Decoded {
    /// The decoded bytes, at most the requested limit.
    pub data: Vec<u8>,
    /// Stored bytes the stream occupied, when the decoder knows exactly.
    pub consumed: Option<usize>,
    /// Integrity check that was verified against the decoded bytes.
    pub check: Option<&'static str>,
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CompressedParseError {
        message: message.into(),
    }
}

/// Decimal size with the largest exact binary unit.
pub(crate) fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

fn exceeds(limit: usize) -> ClassifierError {
    error(format!("Decoded payload exceeds {}", size_text(limit)))
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end).ok_or_else(|| {
        error(format!(
            "Truncated compressed stream at 0x{start:X} + {len} B"
        ))
    })
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

/// Round up to a multiple of four bytes.
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3)
        .ok_or_else(|| error("Alignment overflow"))?
        & !3)
}

/// Read a decoder's whole output, failing once it passes `limit`.
fn read_capped(reader: impl Read, limit: usize, codec: &str) -> Result<Vec<u8>> {
    read_until(reader, limit, codec, AtLimit::Fail)
}

/// What a decoder does when its output reaches the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtLimit {
    /// The whole stream must fit: more output is an error.
    Fail,
    /// Stop at the limit and keep the output so far.
    Stop,
}

/// Read at most `limit` bytes from `reader`; more output is an error or
/// ends the read, as `at_limit` says.
fn read_until(reader: impl Read, limit: usize, codec: &str, at_limit: AtLimit) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(bound)
        .read_to_end(&mut out)
        .map_err(|e| error(format!("Invalid {codec} stream: {e}")))?;
    if out.len() > limit {
        if at_limit == AtLimit::Stop {
            out.truncate(limit);
            return Ok(out);
        }
        return Err(exceeds(limit));
    }
    Ok(out)
}

/// A sink that refuses output beyond its limit, for decoders that write.
struct CappedWriter {
    out: Vec<u8>,
    limit: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.len() + buf.len() > self.limit {
            return Err(io::Error::new(io::ErrorKind::Other, "output limit"));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decode `data` with `codec`, producing at most [`MAX_PAYLOAD`] bytes.
///
/// # Errors
///
/// A truncated or corrupt stream, a failed integrity check, or output
/// beyond the limit.
pub fn decode(codec: Codec, data: &[u8]) -> Result<Decoded> {
    decode_limited(codec, data, MAX_PAYLOAD)
}

/// Decode `data` with `codec`, producing at most `limit` bytes. Callers
/// that know the decoded size pass it as the limit.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_limited(codec: Codec, data: &[u8], limit: usize) -> Result<Decoded> {
    let limit = limit.min(MAX_PAYLOAD);
    match codec {
        Codec::Gzip => gzip(data, limit),
        Codec::Zlib => {
            let (out, used) = inflate(data, true, limit)?;
            Ok(Decoded {
                data: out,
                consumed: Some(used),
                check: Some("Adler-32"),
            })
        }
        Codec::Deflate => {
            let (out, used) = inflate(data, false, limit)?;
            Ok(Decoded {
                data: out,
                consumed: Some(used),
                check: None,
            })
        }
        Codec::Xz => xz::xz(data, limit),
        Codec::Lzma => xz::lzma(data, limit),
        Codec::Lz4 => lz4_frame(data, limit),
        Codec::Lz4Legacy => lz4_legacy(data, limit),
        Codec::Zstd => zstd(data, limit),
        Codec::Bzip2 => bzip2(data, limit),
        Codec::Lzop => lzo::lzop(data, limit),
        Codec::Lzfse => lzfse(data, limit),
        Codec::Lzss => lzss::decode(data, limit),
        Codec::Brotli => {
            let reader = brotli_decompressor::Decompressor::new(data, 4096);
            Ok(Decoded {
                data: read_capped(reader, limit, "Brotli")?,
                consumed: None,
                check: None,
            })
        }
        Codec::Lz4Block => lz4_block::decode(data, limit),
        Codec::Blz => blz::decode(data, limit),
        Codec::Lzo1x => lzo::lzo1x_block(data, limit),
        Codec::Rtime => jffs2::rtime(data, limit),
        Codec::RubinMips => jffs2::rubin(data, limit, jffs2::RubinModel::Mips),
        Codec::DynRubin => jffs2::rubin(data, limit, jffs2::RubinModel::Dynamic),
        Codec::Efi => efi::decode(data, efi::Variant::Efi, limit),
        Codec::Tiano => efi::decode(data, efi::Variant::Tiano, limit),
        Codec::LzmaX86 => xz::lzma_x86(data, limit),
    }
}

/// The first `limit` bytes (at most [`MAX_PAYLOAD`]) of a stream too long
/// to decode whole. Codecs that decode as a stream stop at the limit:
/// gzip, zlib, raw DEFLATE, Zstandard, bzip2, LZ4 frames and LZMA-alone.
/// Other codecs decode as [`decode_limited`] does. The integrity checks
/// cover the whole output, so a prefix verifies none.
///
/// # Errors
///
/// A truncated or corrupt stream within the prefix, or output beyond the
/// limit for a codec that cannot stop early.
pub fn decode_prefix(codec: Codec, data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let limit = limit.min(MAX_PAYLOAD);
    match codec {
        Codec::Gzip => Ok(gzip_until(data, limit, AtLimit::Stop)?.data),
        Codec::Zlib => Ok(inflate_until(data, true, limit, AtLimit::Stop)?.0),
        Codec::Deflate => Ok(inflate_until(data, false, limit, AtLimit::Stop)?.0),
        Codec::Zstd => Ok(zstd_until(data, limit, AtLimit::Stop)?.data),
        Codec::Bzip2 => {
            let decoder = ::bzip2::bufread::MultiBzDecoder::new(data);
            read_until(decoder, limit, "bzip2", AtLimit::Stop)
        }
        Codec::Lz4 => {
            let (extent, _) = lz4_frames_extent(data)?;
            let decoder = lz4_flex::frame::FrameDecoder::new(&data[..extent]);
            read_until(decoder, limit, "LZ4", AtLimit::Stop)
        }
        Codec::Lzma => Ok(xz::lzma_until(data, limit, AtLimit::Stop)?.data),
        _ => Ok(decode_limited(codec, data, limit)?.data),
    }
}

/// Inflate a raw or zlib-wrapped DEFLATE stream. Returns the output and
/// the number of input bytes the stream used.
fn inflate(input: &[u8], zlib: bool, limit: usize) -> Result<(Vec<u8>, usize)> {
    inflate_until(input, zlib, limit, AtLimit::Fail)
}

/// [`inflate`], stopping at the limit when `at_limit` says so.
fn inflate_until(
    input: &[u8],
    zlib: bool,
    limit: usize,
    at_limit: AtLimit,
) -> Result<(Vec<u8>, usize)> {
    use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
    use miniz_oxide::inflate::TINFLStatus;

    let mut flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    if zlib {
        flags |=
            inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER | inflate_flags::TINFL_FLAG_COMPUTE_ADLER32;
    }
    let name = if zlib { "zlib" } else { "DEFLATE" };
    let mut decompressor = Box::<DecompressorOxide>::default();
    let mut out = vec![0u8; input.len().saturating_mul(2).clamp(4096, limit.max(4096))];
    let mut in_pos = 0;
    let mut out_pos = 0;
    loop {
        let (status, used, written) = decompress(
            &mut decompressor,
            &input[in_pos..],
            &mut out,
            out_pos,
            flags,
        );
        in_pos += used;
        out_pos += written;
        match status {
            TINFLStatus::Done => {
                if out_pos > limit && at_limit == AtLimit::Fail {
                    return Err(exceeds(limit));
                }
                out.truncate(out_pos.min(limit));
                return Ok((out, in_pos));
            }
            TINFLStatus::HasMoreOutput => {
                if out_pos >= limit && at_limit == AtLimit::Stop {
                    out.truncate(limit);
                    return Ok((out, in_pos));
                }
                if out.len() >= limit {
                    return Err(exceeds(limit));
                }
                let grown = out.len().saturating_mul(2).min(limit);
                out.resize(grown, 0);
            }
            TINFLStatus::Adler32Mismatch => return Err(error("Invalid zlib Adler-32")),
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                return Err(error(format!("Truncated {name} stream")));
            }
            _ => return Err(error(format!("Invalid {name} stream"))),
        }
    }
}

/// Length of the gzip member header at the start of `data`: fixed fields,
/// then optional extra field, name, comment and header CRC-16.
fn gzip_header_size(data: &[u8]) -> Result<usize> {
    let header = slice(data, 0, GZIP_HEADER_SIZE)?;
    if header[..2] != GZIP_MAGIC {
        return Err(error("Missing gzip magic"));
    }
    if header[2] != GZIP_DEFLATE {
        return Err(error(format!("Unsupported gzip method {}", header[2])));
    }
    let flags = header[3];
    if flags & GZIP_FLAGS_RESERVED != 0 {
        return Err(error("Invalid gzip header flags"));
    }
    let mut pos = GZIP_HEADER_SIZE;
    if flags & GZIP_FEXTRA != 0 {
        let extra = slice(data, pos, 2)?;
        pos += 2 + usize::from(u16::from_le_bytes([extra[0], extra[1]]));
    }
    for flag in [GZIP_FNAME, GZIP_FCOMMENT] {
        if flags & flag != 0 {
            let rest = data
                .get(pos..)
                .ok_or_else(|| error("Truncated gzip header"))?;
            let len = memchr::memchr(0, rest).ok_or_else(|| error("Truncated gzip header"))?;
            pos += len + 1;
        }
    }
    if flags & GZIP_FHCRC != 0 {
        let stored = slice(data, pos, 2)?;
        let computed = checksum::crc32(&data[..pos]) & 0xffff;
        if u32::from(u16::from_le_bytes([stored[0], stored[1]])) != computed {
            return Err(error("Invalid gzip header CRC-16"));
        }
        pos += 2;
    }
    slice(data, pos, 0)?;
    Ok(pos)
}

/// Decode concatenated gzip members, verifying each CRC-32 and size.
fn gzip(data: &[u8], limit: usize) -> Result<Decoded> {
    gzip_until(data, limit, AtLimit::Fail)
}

/// [`gzip`], stopping at the limit when `at_limit` says so. A stopped
/// member's CRC-32 and size cover bytes not decoded, so nothing is checked.
fn gzip_until(data: &[u8], limit: usize, at_limit: AtLimit) -> Result<Decoded> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let member = &data[pos..];
        let start = gzip_header_size(member)?;
        let (decoded, used) = inflate_until(&member[start..], false, limit - out.len(), at_limit)?;
        if at_limit == AtLimit::Stop && out.len() + decoded.len() == limit {
            out.extend_from_slice(&decoded);
            return Ok(Decoded {
                data: out,
                consumed: None,
                check: None,
            });
        }
        let trailer = start + used;
        let crc = le_u32(member, trailer)?;
        let size = le_u32(member, trailer + 4)?;
        if checksum::crc32(&decoded) != crc {
            return Err(error(format!(
                "Invalid gzip CRC-32 at 0x{:X}",
                pos + trailer
            )));
        }
        if u32::try_from(decoded.len()) != Ok(size) {
            return Err(error(format!(
                "Invalid gzip ISIZE at 0x{:X}",
                pos + trailer + 4
            )));
        }
        out.extend_from_slice(&decoded);
        pos += trailer + 8;
        if !data[pos..].starts_with(&GZIP_MAGIC) {
            break;
        }
    }
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: Some("CRC-32"),
    })
}

/// LZ4 frame descriptor flags (FLG byte).
const LZ4_BLOCK_CHECKSUM: u8 = 0x10;
const LZ4_CONTENT_SIZE: u8 = 0x08;
const LZ4_CONTENT_CHECKSUM: u8 = 0x04;
const LZ4_DICT_ID: u8 = 0x01;

/// A block size with this bit set stores the block uncompressed.
const LZ4_UNCOMPRESSED_BLOCK: u32 = 0x8000_0000;

/// The extent of the LZ4 frames (and skippable frames) at the start of
/// `data`, and whether every frame carries a content checksum. The decoder
/// accepts a frame cut off before its end mark, so the structure is walked
/// first: descriptor, blocks with optional checksums, end mark, optional
/// content checksum.
fn lz4_frames_extent(data: &[u8]) -> Result<(usize, bool)> {
    let mut pos = 0;
    let mut all_checked = true;
    while pos + 4 <= data.len() {
        let magic = le_u32(data, pos)?;
        if magic & ZSTD_SKIPPABLE_MASK == ZSTD_SKIPPABLE {
            let size = le_u32(data, pos + 4)? as usize;
            pos = pos
                .checked_add(8 + size)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| error("Truncated LZ4 skippable frame"))?;
            continue;
        }
        if magic.to_le_bytes() != LZ4_FRAME_MAGIC {
            break;
        }
        let flags = *slice(data, pos + 4, 1)?.first().expect("one byte");
        let mut at = pos + 6;
        if flags & LZ4_CONTENT_SIZE != 0 {
            at += 8;
        }
        if flags & LZ4_DICT_ID != 0 {
            at += 4;
        }
        at += 1; // header checksum
        loop {
            let size = le_u32(data, at)?;
            at += 4;
            if size == 0 {
                break;
            }
            let stored = (size & !LZ4_UNCOMPRESSED_BLOCK) as usize;
            at += stored;
            if flags & LZ4_BLOCK_CHECKSUM != 0 {
                at += 4;
            }
            slice(data, at, 0)?;
        }
        if flags & LZ4_CONTENT_CHECKSUM != 0 {
            at += 4;
        } else {
            all_checked = false;
        }
        slice(data, at, 0)?;
        pos = at;
    }
    if pos == 0 {
        return Err(error("Missing LZ4 frame"));
    }
    Ok((pos, all_checked))
}

/// Decode LZ4 frames; `lz4_flex` validates descriptors and checksums.
fn lz4_frame(data: &[u8], limit: usize) -> Result<Decoded> {
    let (extent, checked) = lz4_frames_extent(data)?;
    let mut input = &data[..extent];
    let decoder = lz4_flex::frame::FrameDecoder::new(&mut input);
    let out = read_capped(decoder, limit, "LZ4")?;
    Ok(Decoded {
        data: out,
        consumed: Some(extent),
        check: checked.then_some("LZ4 content checksum"),
    })
}

/// Decode an LZ4 legacy frame: magic, then blocks of a little-endian
/// stored size and LZ4 block data. A size that is not a plausible block
/// (Linux appends the decoded length) ends the stream; a repeated magic
/// starts a concatenated stream.
fn lz4_legacy(data: &[u8], limit: usize) -> Result<Decoded> {
    if le_u32(data, 0)? != LZ4_LEGACY_MAGIC {
        return Err(error("Missing LZ4 legacy magic"));
    }
    let max_stored = lz4_flex::block::get_maximum_output_size(LZ4_LEGACY_BLOCK);
    let mut pos = 4;
    let mut out = Vec::new();
    let mut block = vec![0u8; LZ4_LEGACY_BLOCK];
    while pos + 4 <= data.len() {
        let size = le_u32(data, pos)?;
        if size == LZ4_LEGACY_MAGIC {
            pos += 4;
            continue;
        }
        let stored_size = size as usize;
        if stored_size == 0 || stored_size > max_stored || stored_size > data.len() - pos - 4 {
            break;
        }
        let stored = &data[pos + 4..pos + 4 + stored_size];
        let written = lz4_flex::block::decompress_into(stored, &mut block)
            .map_err(|e| error(format!("Invalid LZ4 legacy block at 0x{pos:X}: {e}")))?;
        if out.len() + written > limit {
            return Err(exceeds(limit));
        }
        out.extend_from_slice(&block[..written]);
        pos += 4 + stored_size;
    }
    if out.is_empty() {
        return Err(error("Truncated LZ4 legacy frame"));
    }
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: None,
    })
}

/// Decode Zstandard frames, skipping skippable frames and verifying the
/// optional content checksum of each frame.
fn zstd(data: &[u8], limit: usize) -> Result<Decoded> {
    zstd_until(data, limit, AtLimit::Fail)
}

/// [`zstd`], stopping at the limit when `at_limit` says so; a stopped
/// frame's content checksum is not checked.
fn zstd_until(data: &[u8], limit: usize, at_limit: AtLimit) -> Result<Decoded> {
    let mut pos = 0;
    let mut out = Vec::new();
    let mut all_checked = true;
    while pos + 4 <= data.len() {
        let magic = le_u32(data, pos)?;
        if magic & ZSTD_SKIPPABLE_MASK == ZSTD_SKIPPABLE {
            let size = usize::try_from(le_u32(data, pos + 4)?)
                .map_err(|_| error("Invalid Zstandard skippable frame"))?;
            pos = pos
                .checked_add(8 + size)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| error("Truncated Zstandard skippable frame"))?;
            continue;
        }
        if magic != ZSTD_MAGIC {
            break;
        }
        let mut input = &data[pos..];
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut input)
            .map_err(|e| error(format!("Invalid Zstandard frame at 0x{pos:X}: {e}")))?;
        let frame = read_until(&mut decoder, limit - out.len(), "Zstandard", at_limit)?;
        if at_limit == AtLimit::Stop && out.len() + frame.len() == limit {
            out.extend_from_slice(&frame);
            return Ok(Decoded {
                data: out,
                consumed: None,
                check: None,
            });
        }
        let frame_decoder = &decoder.decoder;
        match (
            frame_decoder.get_checksum_from_data(),
            frame_decoder.get_calculated_checksum(),
        ) {
            (Some(stored), Some(computed)) if stored != computed => {
                return Err(error(format!(
                    "Invalid Zstandard content checksum at 0x{pos:X}"
                )));
            }
            (Some(_), Some(_)) => {}
            _ => all_checked = false,
        }
        drop(decoder);
        out.extend_from_slice(&frame);
        pos = data.len() - input.len();
    }
    if pos == 0 {
        return Err(error("Missing Zstandard frame"));
    }
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: all_checked.then_some("Zstandard content checksum"),
    })
}

/// Decode concatenated bzip2 streams; the decoder verifies block and
/// stream CRCs.
fn bzip2(data: &[u8], limit: usize) -> Result<Decoded> {
    let mut input = data;
    let decoder = ::bzip2::bufread::MultiBzDecoder::new(&mut input);
    let out = read_capped(decoder, limit, "bzip2")?;
    Ok(Decoded {
        data: out,
        consumed: Some(data.len() - input.len()),
        check: Some("bzip2 CRC-32"),
    })
}

/// Decode an LZFSE/LZVN block stream ending in `bvx$`.
fn lzfse(data: &[u8], limit: usize) -> Result<Decoded> {
    let mut decoder = lzfse_rust::LzfseRingDecoder::default();
    let mut writer = CappedWriter {
        out: Vec::new(),
        limit,
    };
    let mut input = data;
    let (used, _) = decoder.decode(&mut input, &mut writer).map_err(|e| {
        if writer.out.len() >= limit {
            exceeds(limit)
        } else {
            error(format!("Invalid LZFSE stream: {e}"))
        }
    })?;
    Ok(Decoded {
        data: writer.out,
        consumed: usize::try_from(used).ok(),
        check: None,
    })
}

/// The magic-bearing codec whose stream starts at `data`, if any. Header
/// fields beyond the magic are checked so a matching prefix alone does
/// not count.
pub fn sniff(data: &[u8]) -> Option<Codec> {
    if data.starts_with(&GZIP_MAGIC) {
        return gzip_header_size(data).is_ok().then_some(Codec::Gzip);
    }
    if data.starts_with(&xz::XZ_MAGIC) {
        let flags = data.get(6..12)?;
        let crc = u32::from_le_bytes(flags[2..6].try_into().ok()?);
        return (flags[0] == 0 && checksum::crc32(&flags[..2]) == crc).then_some(Codec::Xz);
    }
    if data.starts_with(&LZ4_FRAME_MAGIC) {
        let descriptor = *data.get(4)?;
        return (descriptor & LZ4_VERSION_MASK == LZ4_VERSION_1).then_some(Codec::Lz4);
    }
    if data.starts_with(&LZ4_LEGACY_MAGIC.to_le_bytes()) {
        return Some(Codec::Lz4Legacy);
    }
    if data.starts_with(&ZSTD_MAGIC.to_le_bytes()) {
        // Frame header descriptor bit 3 is reserved and must be zero.
        let descriptor = *data.get(4)?;
        return (descriptor & 0x08 == 0).then_some(Codec::Zstd);
    }
    if data.starts_with(BZIP2_MAGIC) {
        let level = *data.get(3)?;
        let block = data.get(4..10)?;
        let valid = (b'1'..=b'9').contains(&level)
            && (block == BZIP2_BLOCK_MAGIC || block == BZIP2_END_MAGIC);
        return valid.then_some(Codec::Bzip2);
    }
    if data.starts_with(&lzo::LZOP_MAGIC) {
        return Some(Codec::Lzop);
    }
    if data.starts_with(lzss::LZSS_MAGIC) || data.starts_with(lzss::LZVN_MAGIC) {
        return Some(Codec::Lzss);
    }
    if LZFSE_MAGICS.iter().any(|magic| data.starts_with(*magic)) {
        return Some(Codec::Lzfse);
    }
    None
}

/// Strong recognition of a standalone compressed file.
pub fn detect(data: &[u8]) -> Option<Codec> {
    sniff(data)
}

/// Is this a zlib header: method 8, window at most 32 KiB, no preset
/// dictionary, and a check value that makes the 16-bit header a multiple
/// of 31 (RFC 1950, section 2.2)?
fn is_zlib_header(data: &[u8]) -> bool {
    let [cmf, flg, ..] = *data else {
        return false;
    };
    let preset_dictionary = flg & 0x20 != 0;
    cmf & 0x0f == ZLIB_DEFLATE
        && cmf >> 4 <= ZLIB_MAX_WINDOW_BITS
        && !preset_dictionary
        && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

/// Weak recognition: zlib and LZMA-alone streams have a two-byte or
/// properties-only signature, so they are recognized only when the whole
/// input decodes, every check passes and only padding follows.
pub fn detect_weak(data: &[u8]) -> Option<Codec> {
    let codec = if is_zlib_header(data) {
        Codec::Zlib
    } else if xz::lzma_header(data).is_ok() && is_plausible_lzma(data) {
        Codec::Lzma
    } else {
        return None;
    };
    let decoded = decode(codec, data).ok()?;
    let consumed = decoded.consumed?;
    let complete = !decoded.data.is_empty() && is_padding(&data[consumed..]);
    complete.then_some(codec)
}

/// LZMA properties byte of `lc=3 lp=0 pb=2`, the xz-utils and LZMA SDK
/// default.
const LZMA_DEFAULT_PROPERTIES: u8 = 0x5d;

/// LZMA-alone files written by xz-utils and the LZMA SDK use the default
/// properties `lc=3 lp=0 pb=2` (`0x5D`) and a power-of-two dictionary of
/// at least 4 KiB; anything else is not tried without a container.
pub(crate) fn is_plausible_lzma(data: &[u8]) -> bool {
    has_lzma_header(data, LZMA_DEFAULT_PROPERTIES)
}

/// Does `data` start with an LZMA-alone header with this properties byte
/// and a power-of-two dictionary of at least 4 KiB? Containers whose
/// producers document other properties (`lc=1 lp=2 pb=2` router kernels
/// built by `OpenWrt`) test for those.
pub(crate) fn has_lzma_header(data: &[u8], properties: u8) -> bool {
    let [found, d0, d1, d2, d3, ..] = *data else {
        return false;
    };
    let dict = u32::from_le_bytes([d0, d1, d2, d3]);
    found == properties && dict >= 4096 && dict.is_power_of_two()
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Parse a standalone compressed file as a container whose single child
/// is the decoded content.
///
/// # Errors
///
/// A stream that does not decode, or bytes other than padding after it.
pub fn parse_container(data: &[u8], codec: Codec) -> Result<Container<'_>> {
    let decoded = match decode(codec, data) {
        Ok(decoded) => decoded,
        Err(e) => return over_limit(data, codec).ok_or(e),
    };
    let consumed = decoded.consumed.unwrap_or(data.len());
    let trailing = &data[consumed.min(data.len())..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the {} stream at 0x{consumed:X}",
            size_text(trailing.len()),
            codec.name()
        )));
    }
    let mut c = Container::new(codec.format(), codec.label(), "compressed");
    c.transparent = true;
    c.consumed = consumed;
    c.notes.push(format!(
        "{} stream: {} stored, {} decoded{}",
        codec.name(),
        size_text(consumed),
        size_text(decoded.data.len()),
        match decoded.check {
            Some(check) => format!("; {check} verified"),
            None => "; no integrity check verified".to_string(),
        }
    ));
    c.push_metadata("compressed_codec", "Codec", codec.name());
    c.push_metadata("compressed_stored_size", "Stored size (B)", consumed as u64);
    c.push_metadata(
        "compressed_decoded_size",
        "Decoded size (B)",
        decoded.data.len() as u64,
    );
    c.children.push(Child::decoded(
        "Decoded payload",
        0,
        consumed,
        Cow::Owned(decoded.data),
        codec.name(),
    ));
    Ok(c)
}

/// A stream that decodes to more than [`MAX_PAYLOAD`]: its first
/// [`MAX_PAYLOAD`] bytes are classified, with a note that the rest was not
/// decoded and no integrity check was verified. `None` when the stream does
/// not reach the limit, so the failed decode was not about its size.
fn over_limit(data: &[u8], codec: Codec) -> Option<Container<'_>> {
    let prefix = decode_prefix(codec, data, MAX_PAYLOAD)
        .ok()
        .filter(|prefix| prefix.len() == MAX_PAYLOAD)?;
    let mut c = Container::new(codec.format(), codec.label(), "compressed");
    c.transparent = true;
    c.consumed = data.len();
    c.notes.push(format!(
        "{} stream: {} stored; decoding stopped at the {} extraction limit, so the rest of the \
         stream was not decoded and no integrity check was verified",
        codec.name(),
        size_text(data.len()),
        size_text(MAX_PAYLOAD)
    ));
    c.push_metadata("compressed_codec", "Codec", codec.name());
    c.push_metadata(
        "compressed_decoded_size",
        "Decoded size (B)",
        prefix.len() as u64,
    );
    c.push_metadata(
        "compressed_decode_stopped_at",
        "Decoding stopped at (B)",
        MAX_PAYLOAD as u64,
    );
    c.children.push(Child::decoded(
        "Decoded payload",
        0,
        data.len(),
        Cow::Owned(prefix),
        codec.name(),
    ));
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "hello hello hello\n" compressed with `gzip -n` (DEFLATE with fixed
    /// Huffman codes, empty name, mtime 0).
    fn gzip_hello() -> Vec<u8> {
        let payload = b"hello hello hello\n";
        let mut member = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        member.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
        member.extend_from_slice(&checksum::crc32(payload).to_le_bytes());
        member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        member
    }

    #[test]
    fn gzip_members_decode_and_verify_crc() {
        let stream = gzip_hello();
        let decoded = decode(Codec::Gzip, &stream).unwrap();
        assert_eq!(decoded.data, b"hello hello hello\n");
        assert_eq!(decoded.consumed, Some(stream.len()));
        assert_eq!(decoded.check, Some("CRC-32"));

        let mut two = stream.clone();
        two.extend_from_slice(&stream);
        assert_eq!(decode(Codec::Gzip, &two).unwrap().data.len(), 36);

        let mut corrupt = stream.clone();
        let crc_at = corrupt.len() - 8;
        corrupt[crc_at] ^= 1;
        assert!(decode(Codec::Gzip, &corrupt).is_err());
        for end in 0..stream.len() {
            assert!(decode(Codec::Gzip, &stream[..end]).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn decoders_stop_at_the_output_limit() {
        let zeros = vec![0u8; 1 << 20];
        let zlib = miniz_oxide::deflate::compress_to_vec_zlib(&zeros, 9);
        assert_eq!(decode(Codec::Zlib, &zlib).unwrap().data.len(), 1 << 20);
        assert!(decode_limited(Codec::Zlib, &zlib, 1000).is_err());
        let lz4 = {
            let mut out = Vec::new();
            let mut encoder = lz4_flex::frame::FrameEncoder::new(&mut out);
            encoder.write_all(&zeros).unwrap();
            encoder.finish().unwrap();
            out
        };
        assert_eq!(decode(Codec::Lz4, &lz4).unwrap().data, zeros);
        assert!(decode_limited(Codec::Lz4, &lz4, 1000).is_err());
    }

    #[test]
    fn lz4_legacy_frames_decode_and_stop_at_the_size_trailer() {
        let payload = b"legacy legacy legacy legacy".repeat(10);
        let block = lz4_flex::block::compress(&payload);
        let mut frame = LZ4_LEGACY_MAGIC.to_le_bytes().to_vec();
        frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
        frame.extend_from_slice(&block);
        let stream_end = frame.len();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let decoded = decode(Codec::Lz4Legacy, &frame).unwrap();
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, Some(stream_end));
    }

    #[test]
    fn raw_lz4_blocks_decode_within_the_limit() {
        let payload = b"block block block block block".repeat(20);
        let block = lz4_flex::block::compress(&payload);
        let decoded = decode_limited(Codec::Lz4Block, &block, 4096).unwrap();
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, Some(block.len()));
        assert!(decode_limited(Codec::Lz4Block, &block, payload.len() - 1).is_err());
        assert!(decode_limited(Codec::Lz4Block, &block[..block.len() - 1], 4096).is_err());
    }

    #[test]
    fn sniff_requires_more_than_the_magic() {
        assert_eq!(sniff(&gzip_hello()), Some(Codec::Gzip));
        assert_eq!(sniff(&[0x1f, 0x8b, 9, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(sniff(b"BZh9\x31\x41\x59\x26\x53\x59"), Some(Codec::Bzip2));
        assert_eq!(sniff(b"BZh0\x31\x41\x59\x26\x53\x59"), None);
        assert_eq!(sniff(&[0x28, 0xb5, 0x2f, 0xfd, 0x08]), None);
        assert!(is_zlib_header(&[0x78, 0x9c]));
        assert!(!is_zlib_header(&[0x78, 0x9d]));
    }

    #[test]
    fn weak_detection_requires_a_complete_decode() {
        let zlib = miniz_oxide::deflate::compress_to_vec_zlib(b"payload payload", 6);
        assert_eq!(detect_weak(&zlib), Some(Codec::Zlib));
        let mut trailing = zlib.clone();
        trailing.extend_from_slice(b"junk");
        assert_eq!(detect_weak(&trailing), None);
        assert_eq!(detect_weak(&zlib[..zlib.len() - 1]), None);
    }

    #[test]
    fn every_codec_rejects_noise_without_panicking() {
        let mut x: u32 = 0x1234_5678;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        for &codec in Codec::ALL {
            for end in [0, 1, 4, 13, 64, noise.len()] {
                let _ = decode_limited(codec, &noise[..end], 1 << 16);
            }
        }
    }
}
