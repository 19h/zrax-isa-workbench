# Compressed streams and the shared container model

Zrax decodes the codecs that kernel, filesystem and firmware containers use,
and recognizes standalone compressed files. A standalone stream is reported as
its own format (`gzip`, `xz`, ...) with the ISA, candidates, extensions,
slices and metadata of the decoded content. Decoders live in
`src/formats/compressed.rs` and its submodules; containers call
`compressed::decode` when a header field names a codec.

## Implemented codecs

| JSON format ID | Codec | Recognition | Integrity check | Primary source |
| --- | --- | --- | --- | --- |
| `gzip` | gzip members, concatenated | Strong: `1F 8B 08`, reserved flag bits clear, valid optional fields | CRC-32 and ISIZE of every member; optional header CRC-16 | [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) |
| `zlib` | zlib | Weak: valid CMF/FLG header, complete decode, only padding after it | Adler-32 | [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950) |
| — | Raw DEFLATE | Never recognized standalone (no magic) | None | [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951) |
| `xz` | xz streams with LZMA2, BCJ (x86, PowerPC, IA-64, Arm, Arm Thumb, SPARC, Arm64, RISC-V) and delta filters; concatenated streams and stream padding | Strong: magic plus stream-flags CRC-32 | Header, index and footer CRC-32s; block CRC-32, CRC-64 or SHA-256 | [The .xz File Format 1.2.1](https://tukaani.org/xz/xz-file-format-1.2.1.txt) |
| `lzma` | LZMA-alone | Weak: properties `0x5D`, power-of-two dictionary of at least 4 KiB, complete decode | None in the format | [LZMA SDK](https://www.7-zip.org/sdk.html) `DOC/lzma-specification.txt` |
| `lz4` | LZ4 frames, skippable frames; legacy frames (`02 21 4C 18`) | Strong: frame magic with version bits `01`, or legacy magic | Frame header and content checksums when present | [lz4 v1.10.0 frame format](https://github.com/lz4/lz4/blob/v1.10.0/doc/lz4_Frame_format.md) |
| `zstd` | Zstandard frames, skippable frames | Strong: magic with reserved descriptor bit clear | Content checksum when present | [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878) |
| `bzip2` | bzip2 streams, concatenated | Strong: `BZh1`-`BZh9` followed by the block or end-of-stream magic | Block and stream CRC-32 | bzip2 1.0.8 source |
| `lzop` | lzop files with LZO1X methods 1-3 | Strong: 9-byte magic, header checksum | Header Adler-32/CRC-32; block checksums when present | [lzop 1.04 `src/lzop.c`](https://www.lzop.org/), [Linux `lzo.rst`](https://docs.kernel.org/staging/lzo.html) |
| `lzfse` | LZFSE and LZVN block streams (`bvx2`, `bvx1`, `bvxn`, `bvx-`, end `bvx$`) | Strong: block magic | None in the format | [apple/lzfse `lzfse_internal.h`](https://github.com/lzfse/lzfse/blob/master/src/lzfse_internal.h) |
| `lzss` | Apple kernelcache `complzss` (Okumura LZSS) and `complzvn` | Strong: 8-byte signature | Adler-32 of the decoded data | Apple BootX `sl.subproj/lzss.c`; img4lib `lzss.c` |
| — | Brotli | Never recognized standalone (no magic) | None | [RFC 7932](https://www.rfc-editor.org/rfc/rfc7932) |
| — | Raw LZO1X block without lzop framing, as SquashFS stores it; ends at its end-of-stream marker | Never recognized standalone (no magic) | None | [Linux `lzo.rst`](https://docs.kernel.org/staging/lzo.html); squashfs-tools 4.6.1 `lzo_wrapper.h` |
| — | Raw LZ4 block without a frame, as SquashFS and Silicon Labs GBL store it | Never recognized standalone (no magic) | None | [lz4 v1.10.0 block format](https://github.com/lz4/lz4/blob/v1.10.0/doc/lz4_Block_format.md); squashfs-tools 4.6.1 `lz4_wrapper.h` |

DEFLATE, LZMA, LZ4, Zstandard, bzip2, LZFSE and Brotli bitstreams are decoded
by the pure-Rust crates `miniz_oxide`, `lzma-rust2`, `lz4_flex`, `ruzstd`,
`bzip2` (with `libbz2-rs-sys`), `lzfse_rust` and `brotli-decompressor`, so the
WASM build carries every codec. The xz container, LZO1X, lzop framing, LZ4
legacy framing and Apple LZSS are implemented in this repository.

## Coordinates and reporting

Stored and decoded coordinates are kept apart, as for D10:

- Slices give `offset` and `size` in stored bytes, so hex and entropy views
  can show them. A slice that lies inside decoded bytes also carries
  `decoded: { transform, offset, size }` in decoded coordinates.
- Metadata records the codec (`compressed_codec`), the stored and decoded
  sizes, and the format of the decoded content
  (`compressed_content_format`).
- Notes name the integrity check that was verified, or say that none was.
  A codec without a check (LZ4 without checksums, LZMA-alone, LZFSE) never
  claims one.

The ISA always comes from the decoded content. The container's source is
`combined`, because the evidence needed both the decode and the content's own
header or code.

## Validation and resource bounds

- Output is capped at 64 MiB (67,108,864 B) per extraction (`MAX_PAYLOAD`).
  Decoders stop at the cap instead of allocating a declared size.
- LZMA and LZMA2 dictionaries are clamped to the output cap before
  allocation: a match cannot reach further back than the bytes decoded, so a
  larger declared dictionary is never needed.
- Nested containers stop at six levels (`MAX_NESTING`). A seventh-level
  payload is reported with a note and no ISA.
- After a standalone stream only `0x00`/`0xFF` padding may follow; anything
  else is a parse error.
- Strong formats are recognized even when the stream is corrupt, so a damaged
  stream is a `Compressed stream parse error`, never a raw-code guess. Weak
  formats (zlib, LZMA-alone) need a complete decode to be recognized.
- The LZ4 frame structure is walked before decoding, because the decoder
  accepts a frame cut off before its end mark.

Decoding time is linear in stored plus decoded bytes for every codec.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | A two-byte zlib header or an LZMA properties byte is not enough to recognize a file | Random data and raw firmware starting with `78 9C` or `5D 00 00` must stay raw unless the whole input decodes |
| C2 | Integrity is claimed only when a check was computed and compared | Corrupt one byte of every fixture (`corrupt_strong_streams_are_errors`); a codec without a check reports "no integrity check verified" |
| C3 | Decoders cannot be driven past the output cap | Highly compressible input with a 1,000 B limit (`decoders_stop_at_the_output_limit`) |
| C4 | Truncation is detected | Every prefix of every fixture (`truncated_streams_never_claim_the_payload`). LZMA-alone may decode without the last flush bytes of its range coder; the decoded data is then complete |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Raw DEFLATE, raw LZO1X and LZ4 blocks, Brotli | Decoded only where a container field names the codec ([read-only filesystems](rofs.md) for the raw blocks) |
| xz filters other than LZMA2, BCJ and delta; xz check types other than none, CRC-32, CRC-64 and SHA-256 | Parse error naming the unsupported filter or check |
| lzop filters (`F_H_FILTER`) and non-LZO1X methods | Parse error |
| LZFSE without the end-of-stream block | Parse error from the decoder |
| Encrypted or signed transforms | Not decoded |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly): 429 native tests passed
and 6 were ignored; 63 Chromium browser tests passed and 4 were skipped (the
skips need D10/RX113 firmware that is not in the repository). Fixtures were
generated with gzip, XZ Utils 5.8.2, lz4 1.10.0, Zstandard 1.5.7, bzip2 1.0.8,
lzop 1.04 and the macOS `compression_tool`; see the
[fixture provenance](../tests/fixtures/compressed/README.md).
