# Apple images

`src/formats/apple.rs` and its submodules `img4.rs`, `dyld.rs`, `img3.rs`
and `s5l8900.rs` parse Image4 files (`IMG4`, `IM4P`, and the `IM4M`
manifest and `IM4R` restore info), dyld shared caches, and the legacy Img3
and 8900 firmware containers into the shared container model
([compressed streams and the container model](compressed-streams.md)). An
IM4P payload is decoded and classified from its own bytes, so a kernelcache
gets its ISA from its Mach-O header. A dyld cache names its architecture in
its magic, and the Mach-O images it maps into the file are listed with their
paths.

## Implemented layouts

| JSON format ID | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `im4p` | `SEQUENCE { IA5String "IM4P", IA5String type (4 B), IA5String description, OCTET STRING payload, OCTET STRING keybag OPTIONAL, SEQUENCE { INTEGER algorithm, INTEGER size } OPTIONAL, [0] PAYP OPTIONAL }`; optional elements told apart by tag | None. The four-character type is a firmware role; the ISA comes from the decoded payload (Mach-O header, ELF header, or the code model on raw code) | img4lib `69772c72` `libvfs/vfs_img4.c` (`DERImg4PayloadItemSpecs`); PyIMG4 `80491329` `pyimg4/parser.py` (`IM4P._parse`); img4tool `bb2d6349` `img4tool/img4tool.cpp` (`printIM4P`) |
| `img4` | `SEQUENCE { IA5String "IMG4", IM4P, [0] IM4M OPTIONAL, [1] IM4R OPTIONAL }`; the IM4P is parsed as above, the manifest and restore info become metadata | As for `im4p` | img4lib `DERImg4ItemSpecs`; PyIMG4 `IMG4._parse` |
| `img4` (variant `IM4M manifest`) | Standalone `SEQUENCE { "IM4M", INTEGER version, SET { [MANB] }, OCTET STRING signature OPTIONAL, SEQUENCE certificates OPTIONAL }` | None; metadata only, never analyzed as code | img4lib `DERImg4ManifestItemSpecs`; PyIMG4 `IM4M._parse` |
| `img4` (variant `IM4R restore info`) | Standalone `SEQUENCE { "IM4R", SET { [BNCN] ... } }` | None; metadata only | img4lib `DERImg4RestoreInfoItemSpecs`; PyIMG4 `IM4R` |
| `img3` | 20-byte little-endian root header (magic `Img3` stored `3gmI`, full size, tag-area size, `SHSH` offset from the end of the header, type four-character code), then tags (code, total length including the 12-byte header and padding, data length, data); the `DATA` tag becomes the child, labelled with the type. `KBAG` tags (crypt state, AES key bits, IV and key) make it opaque | None; the ISA comes from the `DATA` payload (Mach-O, `complzss` kernelcache, or raw code through the code model) | The Apple Wiki "IMG3 File Format" revision 312068, "KBAG" revision 190028; xpwn `20c32e5c` `includes/xpwn/img3.h`, `ipsw-patch/img3.c` (`readImg3Root`, `readImg3Element`, `writeImg3Root`) |
| `apple8900` | 0x800-byte header: `8900`, version `1.0`, format (4 plaintext, 3 encrypted with key 0x837, 2 boot plaintext, 1 boot encrypted with the UID key), payload size, footer signature and certificate offsets (from the end of the header), certificate length, salt, security epoch, header signature; payload at 0x800, 0x80-byte footer signature, certificate | None; a plaintext payload is classified on its own bytes (usually an IMG2, which is not parsed), an encrypted one is opaque | The Apple Wiki "S5L File Formats" revision 312559 (8900); xpwn `includes/xpwn/8900.h`, `ipsw-patch/8900.c` (`flipApple8900Header`, `createAbstractFileFrom8900`), `includes/xpwn/img2.h` |
| `dyldcache` | `dyld_cache_header`: 16-byte magic `dyld_v1`, spaces, right-aligned architecture token, NUL; `mappingOffset` as header size and version gate; `dyld_cache_mapping_info` table; image table at `imagesOffset`/`imagesCount` (0x1C0) or `imagesOffsetOld`/`imagesCountOld` (0x18); subcache entries (24 or 56 B); code signature, local symbols, `symbolFileUUID`, UUID and platform where the header version has them | The architecture token is an explicit target field (table below). Images keep their own Mach-O `cputype`; a disagreement is a warning, not an override | dyld `dyld-1378` (`fd8d0c4d`) `include/mach-o/dyld_cache_format.h`, `common/DyldSharedCache.cpp`, `cache_builder/SubCache.cpp`, `other-tools/dsc_extractor.cpp`; `dyld-97.1`, `dyld-210.2.3`, `dyld-360.22`, `dyld-519.2.2` `launch-cache/dyld_cache_format.h`, `launch-cache/Architectures.hpp` |

xnu `f6217f89` `EXTERNAL_HEADERS/img4/firmware.h` says the four-character
code `krnl` corresponds to the `KernelCache` tag, and the parser notes that
for `krnl` only. Other types (`ibot`, `iBEC`, `sepi`, `rkrn`, ...) are shown
as stored, without a meaning.

### dyld architecture tokens

One table (`dyld.rs` `ARCHES`) maps the tokens the cache builders write
(dyld-1378 `mach_o/Architecture.cpp`, `dsc_extractor.cpp`; dyld-210.2.3 and
dyld-360.22 `archName`; dyld-97.1 for PowerPC):

| Token | ISA | Bits | Code byte order | Note |
| --- | --- | --- | --- | --- |
| `arm64` | `a_arch64` | 64 | little | |
| `arm64e` | `a_arch64` | 64 | little | Pointer-authentication ABI |
| `arm64_32` | `a_arch64` | 32 | little | AArch64 instructions, 32-bit pointers (ILP32); 32 bits as the Mach-O parser reports `CPU_TYPE_ARM64_32` |
| `x86_64`, `x86_64h` | `x86_64` | 64 | little | `x86_64h` is the Haswell feature subset |
| `i386` | `x86` | 32 | little | |
| `armv5`, `armv6`, `armv7`, `armv7f`, `armv7s`, `armv7k` | `arm` | 32 | little | |
| `ppc`, `ppc64` | `ppc`, `ppc64` | 32, 64 | big | dyld-97.1 caches; header and tables big-endian |

Any other token (for example `armv4t`, which old builders could write but no
reader lists) gives no target: the header is read little-endian, a note
names the token, and the ISA comes from the listed images.

## Payload decoding

An IM4P payload becomes one child labelled with its type, classified
whether or not its bytes are a recognized format:

| Payload | Child |
| --- | --- |
| Keybag present | Opaque: "encrypted; keybag present (N keybags: production, development); not decrypted". Compression info, if any, is noted as describing the plaintext. Nothing is decrypted or scanned |
| Compression info, algorithm 1 | Decoded as LZFSE with the declared size as the output limit; the decoded size must equal the declared size. Any other algorithm, a mismatch, or a size beyond 64 MiB leaves the payload opaque with a note |
| No compression info, `complzss`/`complzvn` header | Decoded with `compressed::Codec::Lzss`; Adler-32 verified. Bytes after `0x180 + compressedSize` are a second child, `<type> trailer`, listed only when they are a recognized format |
| No compression info, LZFSE block magic | Decoded as LZFSE; the note says no decoded size was declared |
| Anything else | Stored as-is; Mach-O, ELF and other formats are parsed, raw code goes to the code model |

Child offsets and sizes are the stored bytes of the `OCTET STRING`
contents; decoded children carry `decoded` ranges with the codec name
(`LZFSE`, `Apple LZSS`). The `PAYP` property names are listed but not
interpreted. The IM4M manifest is reported in metadata: version, image
entries, `MANP` property names, `CHIP` and `BORD` as hex, signature and
certificate-chain sizes, each marked "not verified". Other property values,
such as `ECID`, are not reported. The IM4R `BNCN` nonce is shown as stored
(img4tool stores its generator little-endian; PyIMG4 reverses it on parse).

## Img3 and 8900

Img3 tags are walked from offset 0x14 to the end of the tag area; each tag
must hold its 12-byte header, a total length that covers its data and fits
the area, and at most one `DATA` tag may exist. The integer tags `CHIP`,
`BORD`, `SEPO`, `SDOM` and `PROD` are reported in metadata as hex; `ECID`
(the device-unique chip ID) is not reported. `VERS` is shown as its bytes in
printable form (its length prefix is not interpreted). A `TYPE` tag that
names another code than the header, or an `SHSH` tag at another offset than
the header's signed-area size, is noted. `SHSH` and `CERT` sizes are
reported; neither is verified. A `KBAG` tag means the `DATA` payload is
encrypted with a key wrapped by the device GID key: the payload is opaque
and nothing is decrypted.

An 8900 container's payload, footer signature and certificate must lie in
the file, and only erased flash may follow the last of them. Formats 1 and
3 are encrypted (xpwn decrypts format 3 with AES-128-CBC and the published
key 0x837; this parser does not decrypt), so the payload is opaque. The
header signature is an AES encryption of a SHA-1 and is not verified. The
magic and the version text `1.0` are both required for detection, so text
starting with the digits 8900 is not claimed.

## dyld images

An image's Mach-O header lies at its unslid address. The parser finds the
mapping that contains the address and adds the mapping's `fileOffset` to the
distance from its `address` (`dsc_extractor.cpp`). When the bytes there are
a Mach-O header whose load commands fit inside the mapping and the file, the
image becomes a member labelled with its path (classified only as a
recognized format, `Classify::IfRecognized`) whose stored range is the
header and load commands. The Mach-O parser reads only the header, so that
is all the classification needs. Images whose header is not in this file
(split caches put most of them in subcache files) are counted, and the
first 16 are listed in metadata with their addresses. Paths are read only
when the first mapping starts at file offset 0, as dyld's `hasImagePath`
requires.

## Wire units and byte order

- Img3 numbers, magics and tag codes are little-endian 32-bit values (the
  four characters read big-endian, stored little-endian). 8900 fields are
  little-endian after the text magic and version.
- DER lengths and INTEGERs are big-endian; INTEGER contents are read as
  unsigned. All Image4 offsets and sizes are bytes in file coordinates.
- `complzss` header fields are big-endian; LZFSE block fields are
  little-endian (see [compressed streams](compressed-streams.md)).
- dyld cache integers use the cache's byte order: little-endian for every
  Arm and x86 cache, big-endian for the PowerPC caches of dyld-97.1. The
  byte order is chosen from the architecture token before any integer is
  read. Addresses are unslid virtual addresses (`u64`); `fileOffset`,
  `pathFileOffset` and table offsets are file offsets.

## Validation and resource bounds

- DER: definite lengths only (indefinite `0x80` rejected), at most four
  length octets, tag numbers of at most five base-128 octets with no leading
  `0x80` octet. Every element must end inside its parent, and the outer
  `SEQUENCE` inside the file. Only erased-flash padding (`0x00`/`0xFF`) may
  follow it. The schema has a fixed depth, and the reader walks it level
  by level without recursion, so nesting is bounded by the schema.
- INTEGERs: at most eight value octets after an optional leading zero.
- IM4P: type exactly 4 B; payload a primitive `OCTET STRING`; each optional
  element at most once; keybag entries must hold a 16-byte IV and a 32-byte
  key. IM4M: exactly one `MANB` property, at most one `MANP` group. Every
  property must repeat its tag's code in its `IA5String`.
- Decoding: 64 MiB per payload (`MAX_PAYLOAD`); LZFSE output limited to the
  declared size; `complzss` decoded size checked against the header and
  Adler-32 verified.
- dyld: `mappingOffset` from 0x28 to 0x400 (dyld-97.1's header to dyld's
  1024-byte sanity limit) and present in full; `mappingCount` at most 20
  (dyld's limit); mapping ranges must not overflow 64 bits. Each table
  count is checked against the bytes after its offset before it is read.
  Paths must be NUL-terminated within 1024 B. At most 256 image entries are
  read (the rest are counted in a note), 16 unmapped paths listed and 8
  subcache suffixes named.
- Truncation: every proper prefix of an Image4 file is a parse error. A
  truncated dyld cache either fails on its header and tables or reports
  mappings beyond the end of the file and lists only images whose header
  and load commands are present.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Optional IM4P elements are identified by tag (keybag `OCTET STRING`, compression `SEQUENCE`, PAYP `[0]`), each at most once, in any order | An `OCTET STRING` after the payload that is not a keybag, or a repeated element, is a parse error (`malformed_der_is_an_error_naming_the_offset`); a real IM4P with such an element would falsify it |
| A2 | Compression algorithm 1 is LZFSE; no other value is defined | img4tool and img4lib reject or ignore other values; an IM4P with algorithm 2 stays opaque with a note |
| A3 | A keybag means the payload is ciphertext, including its compression | The keybag fixture carries a valid `complzss` image that must not be decoded (`encrypted_payloads_stay_opaque`) |
| A4 | An empty INTEGER is zero, as img4tool encodes 0 | `integers_are_unsigned_and_bounded`; a file that relies on rejecting it would be accepted |
| A5 | `complzvn` data is a raw LZVN stream that the lzfse LZVN decoder handles (identity with Apple's FastCompression LZVN is unconfirmed) | `complzvn_payloads_decode_as_raw_lzvn` uses the lzfse opcode table; a real `complzvn` kernelcache that fails to decode would falsify it |
| A6 | `mappingOffset` is the header size and gates fields by offset, as dyld's readers do | Four header sizes (0x28, 0x98, 0x1C8, 0x228) in the tests; intermediate real versions are not verified |
| A7 | `mappingCount` 0 is a valid (if empty) file, unlike dsc_extractor's refusal | Reported with a note "Header declares no mappings" (`image_paths_need_a_first_mapping_at_file_offset_zero`); a parse error would be the stricter reading |
| A8 | The architecture token names the ISA of every image | `an_image_cputype_mismatch_is_a_note_not_an_override` |
| A9 | Any Img3 `KBAG` tag means `DATA` is encrypted | The Apple Wiki "IMG3 File Format" (Encryption); a plaintext Img3 that carries a `KBAG` would be reported opaque (`img3_with_a_kbag_keeps_data_opaque`) |
| A10 | The 8900 version text is always `1.0` | The Apple Wiki and xpwn show no other value; an 8900 file with another version is not recognized |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Encrypted IM4P payloads | Opaque; keybags are not unwrapped and nothing is decrypted |
| IM4M signatures, certificate chains and `DGST` digests | Sizes reported; not verified |
| IM4C | Not recognized (its layout is only partially known) |
| PAYP properties | Names listed; meanings not interpreted |
| Four-character types other than `krnl` | Shown as stored; no meaning claimed |
| dyld slide info, code-signature blobs, local-symbol tables, image-text and trie tables | Not parsed; code signature and local symbols located in notes only |
| dyld images in subcache files | Counted and partly listed in metadata; a subcache file is classified on its own when given |
| dyld `dyld_v0` caches | Not recognized (no writer is known) |
| Img3 and 8900 encryption | `KBAG` keys are wrapped with the device GID key; 8900 key 0x837 payloads are not decrypted; both opaque |
| IMG2 inside 8900 | Noted when the payload starts with `2gmI`; not parsed |
| Img3 `SHSH`, `CERT` and 8900 signatures and certificates | Sizes reported; not verified |
| macOS `prelinkedkernel` fat wrappers | Not implemented here. They start with the fat Mach-O magic and take the existing fat Mach-O path, which does not decode the `comp` slices (not tested) |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly 2026-09-05),
`tests/apple.rs` (27 tests) and 13 unit tests in `src/formats/apple*`
passed, with every-prefix sweeps over each Image4 fixture and a dyld cache
and byte mutation sweeps (`0x00`, `0xFF`, bit flips) over nine inputs.
`web/tests/apple.test.mjs` (4 tests, Node 25.8.1, Playwright Chromium)
passed against `/pkg/`, `/dist/`, `/web/index.html` and `/dist/index.html`.
The Image4 fixtures were written by img4tool 0.202 from a synthetic Mach-O
header and a synthetic, unsigned manifest
([fixture provenance](../tests/fixtures/apple/README.md)); the dyld caches,
keybag payloads and malformed DER are built in the tests. No real Apple
firmware, kernelcache or dyld cache was tested; behavior on real files is
not verified.

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly 2026-09-05),
`tests/apple.rs` (36 tests, 9 of them for Img3 and 8900) and 17 unit tests
in `src/formats/apple*` passed, including every-prefix and byte-mutation
sweeps over an encrypted, signed Img3 and a plaintext 8900 container. The
Img3 and 8900 inputs are built in the tests from the documented layouts
with synthetic Mach-O and ELF headers as payloads; Img3 and 8900 also go
through `web/tests/bootmisc.test.mjs` (`/pkg/` and `/dist/`). No real Img3
or 8900 firmware was tested: not verified.
