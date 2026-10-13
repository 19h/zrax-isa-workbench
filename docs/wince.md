# Windows CE ROM images

`src/formats/wince.rs` and its submodules (`bin.rs`, `nb0.rs`, `rom.rs`,
`memory.rs`) parse the ROM images that Platform Builder's `romimage`
produces: `B000FF` BIN files (`nk.bin`) and raw ROM images (`.nb0`). Both
carry the same in-image structures: the ROM signature `ECEC` at image
offset 0x40, the ROM header (`ROMHDR`), the module table of contents
(`TOCentry` with each module's `e32_rom` and `o32_rom` table) and the file
table (`FILESentry`). The family is built on the shared container model
([compressed streams and the container model](compressed-streams.md)).

The ROMHDR's `usCPUType` ("CPU (machine) Type" in `romldr.h`) holds an
`IMAGE_FILE_MACHINE_*` value. It is the format's own target field and is
mapped through the existing PE/COFF machine table
(`coff::machine_to_isa`); the container reports that ISA, and each module
code section is a component with that target. Load addresses, module and
file names are reported without ISA meaning.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Integrity | Primary sources |
| --- | --- | --- | --- | --- |
| `winceimage` | `Windows CE BIN image`: 15-byte header (sync `B000FF\n`, image address, image length), records (address, length, checksum, data), terminator (address 0, entry point, checksum 0) | Strong: the 7 sync bytes at offset 0 | Every record checksum verified | Microsoft Learn, "Windows Embedded CE Binary Image Data Format (Windows Embedded CE 6.0)", `ee478913(v=winembedded.60)`; BLCOMMON `blcommon.c` (`DownloadImage`, `VerifyChecksum`); Device Emulator `boards/loadbin_nb0.cpp` (`ForEachSectionHeader`) |
| `winceimage` | `Windows CE raw ROM image`: the image bytes from `physfirst`, no header | Weak: `ECEC` at 0x40, one self-consistent ROMHDR, complete tables, only padding after the image | None in the format | BLCOMMON (raw `.nb0` downloads); `romldr.h`; `dumprom.cpp` `DetermineLoadOffset` |

In-image structures, for both layouts:

| Structure | Fields read | Primary source |
| --- | --- | --- |
| ROM signature | `ROM_SIGNATURE` `0x43454345` (bytes `ECEC`) at `ROM_SIGNATURE_OFFSET` 0x40; ROMHDR pointer at `ROM_TOC_POINTER_OFFSET` 0x44 | Windows Embedded Compact 7 `romldr.h`; BLCOMMON |
| `ROMHDR` (84 B) | `physfirst` (0x08), `physlast` (0x0C), `nummods` (0x10), `ulRAMStart`/`ulRAMFree`/`ulRAMEnd` (0x14-0x1C), `ulCopyEntries` (0x20), `numfiles` (0x30), `ulKernelFlags` (0x34), `usCPUType` (0x44), `usMiscFlags` (0x46) | `romldr.h` (`ROMHDR_*`, `SIZEOF_ROMHDR 84`); Microsoft Learn "ROMHDR (Compact 2013)", `ee482991(v=winembedded.80)` |
| `TOCentry` (32 B) | `nFileSize` (12), `lpszFileName` (16), `ulE32Offset` (20), `ulO32Offset` (24) | `romldr.h` (`TOCentry_*`, `SIZEOF_TOCentry 32`); BLCOMMON `IsKernelRegion` ("the TOC immediately follows the ROMHDR") |
| `FILESentry` (28 B) | `nRealFileSize` (12), `nCompFileSize` (16), `lpszFileName` (20), `ulLoadOffset` (24) | `romldr.h`; `dumprom.cpp` (entries follow the TOC) |
| `e32_rom` | `e32_objcnt` (0), `e32_imageflags` (2), `e32_entryrva` (4), `e32_vbase` (8), `e32_vsize` (20) | `romldr.h` for Windows CE 2.11 and Compact 7 (identical up to 0x18) |
| `o32_rom` (24 B) | `o32_vsize` (0), `o32_rva` (4), `o32_psize` (8), `o32_dataptr` (12), `o32_flags` (20) | `romldr.h`; `pehdr.h` (`IMAGE_SCN_CNT_CODE 0x20`, `IMAGE_SCN_COMPRESSED 0x2000`, `IMAGE_SCN_MEM_EXECUTE 0x20000000`, `IMAGE_FILE_DLL 0x2000`); `dumprom.cpp` (stored size `min(o32_vsize, o32_psize)`) |

Source pins (fetched 2026-10-13):

| Source | Where | Pin |
| --- | --- | --- |
| BIN format | `https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ee478913(v=winembedded.60)` | docs archive commit `a69afce66920ae73ffde7846f7102bb20378ed96` |
| ROMHDR | `https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ee482991(v=winembedded.80)` | docs archive commit `145ce15155f158e2151b355fad1cd12bdda480cf` |
| `romldr.h`, `pehdr.h` (Compact 7) | BSP copy, `github.com/sankalp123321/ECEN5803-Project-3-VoIP`, `Module_1/mod_1/mod_1/Wince700/BSPTemplate_ARMV7_Retail/cesysgen/oak/inc/` | `f5901f8d0709c64b70cb261f0fe17bb6a989f313`; SHA-256 `f91d77695a8a3663569458debab8599e9dd2c3a58e1be6c0c6283e07134bf838` (`romldr.h`), `e981cf8b66f9d6131399ac69f674bcb8d9f4671324bef2c39e8a754618cfbc44` (`pehdr.h`) |
| `romldr.h` (CE 2.11) | `github.com/FaucetDC/WincastCE`, `211INC/ROMLDR.H` | `627696aa486a1f09b9e466761a507f9ad53b6eba`; SHA-256 `7beec5cbdbf9124b29a4ecb6479e2970e03904d881a5fec6e542d15f8fc92db3` |
| BLCOMMON `blcommon.c` (CE 5.0) | BSP copy, `github.com/KunYi/kunyichen-1`, `som2416/wince5/blcommon.c` | `3029d7d8c181449723bb16d0a73ee87f63860864`; SHA-256 `3a56b7071def116e1742e73e9dbdd8ccc28f556a9bade30ab3187e360799ff58` |
| Device Emulator shared source (2006) | `github.com/MishaProductions/WindowsMobileEmulator`, `boards/loadbin_nb0.cpp`, `.h` | `51ec2f1c2529999e1e748c66ca59a7a8da289946`; SHA-256 `c857a5de0ebcfd1e0806ce08e5033298feab8581bd278abb3ef6849263d6830f` (`.cpp`) |
| itsme `dumprom.cpp` (CVS 1.1, 2005) | `github.com/pinkavaj/romtools`, `dumprom.cpp` | `0721b1778456fe2e38aaf53e59fe5bff0d9cfe03`; SHA-256 `351aa94324b57df33530a70b49dfd19b4636a3161ead59834114f1fc444b6b68` |

Secondary, not relied on for any rule: srecord 1.64 `srec_msbin(5)`
(little-endian fields, unsigned byte-sum checksum) and gweslab
`extract-wince-rom` at `5eedf30beced801fa753b9ab693cd06bb5068133`
(`usCPUType` values written by romimage, the raw-image fixpoint).

Detection order in `formats::detect_format`: the strong BIN check runs
after the router wrapper magics and before the magic-bearing compressed
streams; no earlier format starts with `B000FF\n`. The weak raw ROM check
runs after the TP-Link layouts and before zlib and LZMA-alone, so a
magic-less raw image never shadows a format with a signature.

## Records and load sections

- Records are read from offset 15 until the terminator. The checksum is
  BLCOMMON's `VerifyChecksum`: the unsigned data bytes summed into a 32-bit
  register that wraps (Microsoft Learn calls it a "signed 32-bit sum"; the
  boot loader code sums `LPBYTE` values). A mismatch is a parse error naming
  the record's file offset and both values.
- The terminator has address 0 and checksum 0 (BLCOMMON); its length field
  is the entry point (BLCOMMON `*pdwLaunchAddr = dwRecLen`, Device Emulator
  `InitialInstructionPointer`). An address-0 record with another checksum
  is an error, because Microsoft Learn would end the file there and
  BLCOMMON would load it as data.
- Every record must lie inside the header's image range and records may not
  overlap. Records are not in address order: romimage writes the signature
  record before the ROMHDR record (BLCOMMON), and both after the rest.
- Load sections are runs of records that follow each other in the file and
  continue each other's addresses. A one-record section is the stored data
  as-is; a longer one is reassembled (transform `BIN records`) and its
  stored range spans the record headers between. Address gaps are never
  materialized; the ROM structures are read through an address map that
  fails on a gap.
- The sections are the ROM itself, so they go to the code model only
  (`code_sections`), never back to format detection.

## ROMHDR lookup and the ROM offset

- BIN: `ECEC` at image address + 0x40, the ROMHDR pointer at + 0x44. As in
  BLCOMMON, the pointer is a runtime address and records may be stored at
  a ROM offset from it (`g_dwROMOffset = dwRecAddr - pTOC` for an 84-byte
  record). Candidates are offset 0 and, for every 84-byte record, its
  address minus the pointer. A candidate must hold a ROMHDR whose
  `physfirst` and `physlast`, plus the offset, are the header's image start
  and end (BLCOMMON's own check); exactly one may match. All TOC pointers
  are then translated by that offset; a nonzero offset is reported
  (`wince_rom_offset`). Without `ECEC`, or without a matching ROMHDR, the
  BIN is still reported, with a note, no target, and the ISA from the code.
  A matching ROMHDR whose tables do not validate keeps its target and
  notes why the modules are not listed.
- Raw image: file offset 0 is `physfirst`. The ROMHDR at file offset `o`
  must satisfy `o + physfirst == pointer` (the fixpoint `dumprom.cpp` and
  gweslab search for). Every 4-byte-aligned `o` from 0x48 is tried; a
  candidate also needs `physfirst < physlast`, the image inside the file,
  the ROMHDR and its tables inside the image, and at least one module.
  More than 8 such candidates, or more than one that validates, is
  ambiguous and not recognized.

## Components

| Component | Source | Classified |
| --- | --- | --- |
| Module code section, label `<module> o32 <index> (RVA 0x<rva>)` | `o32_rom` with `IMAGE_SCN_CNT_CODE` or `IMAGE_SCN_MEM_EXECUTE`, `min(o32_vsize, o32_psize)` bytes at `o32_dataptr`, when one record (or the raw image) holds them | Raw code (never a nested container) with the ROMHDR target; by the code model alone when `usCPUType` names no known architecture |
| Compressed module code section | The same, with `IMAGE_SCN_COMPRESSED` | Opaque; the note says Windows CE ROM compression is not decoded |
| ROM file, label = file name | `FILESentry` with `nCompFileSize == nRealFileSize`, stored in one record | Listed only when its bytes are a recognized format (`container::is_recognized` on the first 4 KiB, then the whole file), classified on its own bytes |

Compressed files (`nCompFileSize != nRealFileSize`) are counted in a note.
Data sections are summarized in the module metadata, not listed.

Notes and metadata: the ROMHDR (address, `usCPUType` with the PE machine
description, `physfirst`, `physlast`, RAM range, kernel and misc flags, copy
entries), up to 16 module names in a note, and per module
(`wince_module_<i>`: EXE or DLL, entry RVA, base, virtual size, section
counts, image flags, file size) and per file (`wince_file_<i>`: sizes and
load address). BIN files add `wince_bin_start`, `wince_bin_length`,
`wince_records` and the entry point.

## Wire units and byte order

All fields are little-endian 32-bit (16-bit for `usCPUType`, `usMiscFlags`,
`e32_objcnt`, `e32_imageflags`); srecord states it per field, and BLCOMMON
and the Device Emulator read native DWORDs on little-endian targets and
hosts. Sizes are bytes. Record addresses and the BIN header range are
storage addresses; ROMHDR, TOC, FILES and `o32_rom` pointers are runtime
addresses, equal to storage addresses unless a ROM offset applies.
`e32_entryrva` and `o32_rva` are relative to `e32_vbase`. The code byte
order is the one the PE machine table gives for `usCPUType` (little-endian
for ARM, Thumb, x86, MIPS and SuperH); it is not a header byte order.

## Validation and resource bounds

- BIN header: at least 15 bytes; image length not zero; image end at most
  2^32.
- Records: at most 262,144 (`MAX_RECORDS`, our own bound); each header and
  data inside the file; checksum verified; inside the image range; no
  overlaps; a terminator before the end of the file; only `0x00`/`0xFF`
  after it.
- Load sections: at most 4096 (`MAX_COMPONENTS`) and 64 MiB in total
  (`MAX_PAYLOAD`); the rest are counted in a note. A raw image larger than
  64 MiB is analyzed as code up to 64 MiB, with a note.
- ROM tables: `nummods * 32 + numfiles * 28` must fit the stored bytes
  before any entry is read. Each entry is charged for its own size and for
  the name, the 24-byte `e32_rom` prefix and the `o32_rom` table it points
  to, against the stored size of the image, so the work and memory of
  reading the tables stay proportional to the input even when entries share
  pointers. Names are non-empty printable ASCII with a NUL within 260 bytes
  (our own bound, the Windows `MAX_PATH`). Every section and file with data
  must have it stored without a gap; empty sections and files need no
  storage.
- Components: at most 4096 (`MAX_COMPONENTS`); module and file metadata
  list at most 4096 entries per table. Components borrow the stored bytes,
  so nothing is decoded or copied for them.
- Raw images: at most 8 self-consistent ROMHDR positions examined; only
  padding after `physlast`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| W1 | `usCPUType` holds an `IMAGE_FILE_MACHINE_*` value. Microsoft documents only "CPU (machine) Type"; the value domain comes from the field's comment and community tools (gweslab: "romimage stamps the image's IMAGE_FILE_MACHINE value") | A romimage BIN whose `usCPUType` disagrees with the `IMAGE_FILE_MACHINE` of its modules' original PE files |
| W2 | A romimage BIN's ROMHDR has `physfirst`/`physlast` equal to the BIN header's start and end (minus the ROM offset) | BLCOMMON checks exactly this to find the ROM offset; probe with Platform Builder output for multi-region (multi-BIN) images |
| W3 | BIN records lie inside the header's image range | A Platform Builder BIN with records outside its header range (it is then a parse error) |
| W4 | FILES entries follow the TOC (`dumprom.cpp`); Microsoft states only that the TOC follows the ROMHDR | A ROM whose `numfiles` entries are elsewhere; its files would fail validation |
| W5 | A file with `nCompFileSize != nRealFileSize` is compressed (`dumprom.cpp`) | A ROM with uncompressed files whose sizes differ |
| W6 | The ROMHDR of a raw image is 4-byte aligned (our inference from its 32-bit fields; `dumprom.cpp` assumes 4 KiB-aligned bases) | A raw image whose ROMHDR is at an unaligned offset; it is not recognized |
| W7 | The ECEC images this parser reads are Windows CE 3.0 or later; CE 2.11 `romldr.h` has no signature and no `usCPUType` | A CE 2.x image (not recognized as a raw image; a CE 2.x BIN gives no ROMHDR) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Windows CE ROM compression (`CEDecompress`, `CEDecompressROM` in `nkcompr.lib`) | Not documented; no decoder. Compressed code sections are opaque, compressed files are counted |
| Multiple XIP regions (`ROMChain_t`, `XIPCHAIN_INFO`), `pExtensions` (`ROMPID`) | Not followed; only the region at the image start is read. A raw image with further regions after `physlast` is not recognized (the bytes after the image are not padding) |
| `e32_rom` beyond 0x18 (subsystem, timestamps, data directories) | Not read: its layout differs between Windows CE 2.11, 3.0-5.0 and Compact 7 |
| `N000FF` download manifests and old `X000FF` multi-bin headers (BLCOMMON) | Not recognized; Platform Builder sends them over the wire |
| Signed BIN images (`OEMCheckSignature`, `ROMXIP_IS_SIGNED`) | Not detected; any signature data is part of the records |
| Copy entries, profile entries | `ulCopyEntries` is reported; the tables are not read |
| IMGFS and other Windows Mobile partition formats, `.nbf` headers | Not implemented |
| Raw image entry point | Not reported: the image does not encode one (BLCOMMON and the Device Emulator start raw images at their first byte) |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`cargo test --all-features --locked` passed: 1165 tests, 6 ignored (the
existing ignores that need external data), including `tests/wince.rs` (14
tests) and 15 unit tests in `src/formats/wince*`, with an every-prefix
truncation sweep of a BIN and a raw image and an every-byte mutation sweep
of both (all three mutations on the structure bytes, one on code and file
bytes). After `./build-web.sh`, `web/tests/wince.test.mjs` passed 4 of 4
(`/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`),
and the full browser suite (`npm test`) passed 138 of 142 with 4 skips
(D10/RX113 firmware not in the repository).

The fixtures are synthetic and built in the tests from the layouts above:
an ARM ROM (A32 code from `tests/fixtures/socboot2/arm.text.bin`), a
little-endian MIPS ROM (a repository testbin) and ROMs with an unknown CPU
type, as BIN files with address gaps, a split record and a ROM offset of
-0x80000000, and as raw images. No tool that writes Windows CE images was
available, and no Platform Builder or device image was parsed: behavior on
real `romimage` output is not verified.
