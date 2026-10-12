# Texas Instruments container coverage

The classifier recognizes 14 additional format IDs, extends TI COFF and object
libraries, and retains the existing C55x `0x09AA` parser. This inventory describes
implemented wire layouts. It is not a claim that every TI proprietary format,
custom bootloader, transport stream or future revision has a public specification.
MCUboot, TF-A FIP and Extended Tektronix are shared formats and do not establish TI
provenance. Checked against vendor documentation and public sources on 2026-10-12.

## Implemented layouts

| JSON format ID | Wire layout / variants | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `tiboot` | C28x `0x08AA`/`0x10AA`, eight reserved/register words, 16-bit word counts; both stream word byte orders | C28x, unless a C54x interpretation also validates | [SPRU513, section 12.10](https://www.ti.com/lit/pdf/spru513), [SPRU095, boot ROM](https://www.ti.com/lit/pdf/spru095) |
| `tiboot` | C54x same keys, parallel two-register and serial four-register headers | Distinct `ti_c5400`; ambiguous C28x/C54x tables remain unknown | [SPRA853, boot tables](https://www.ti.com/lit/pdf/spra853) |
| `tiboot` | Production VC5510 (`-v5510:2`), 32-bit register/section byte counts and odd-address padding | Structural recognition; no target marker, ISA from accessible code | [SPRA763C](https://www.ti.com/lit/pdf/spra763), [SPRU280, hex utility](https://www.ti.com/lit/pdf/spru280) |
| `tiboot` | Unkeyed 32-bit entry/count/destination table, per-section four-byte padding, zero count terminator; both byte orders | No target marker; not necessarily C6000 | [SPRUI03F, hex utility](https://www.ti.com/lit/pdf/sprui03), [TI program loading example](https://downloads.ti.com/docs/esd/SPRU513J/Content/SPRU513J_HTML/program_loading_and_running.html) |
| `tiboot` | C31/VC33, C32, C4x external-memory tables (8/16/32-bit memory interfaces); C32 8/16/32-bit stored data; headerless peripheral layouts; C4x IVTP/TVTP/IACK footer | C3x/C4x family for memory headers; headerless forms structurally identified | [SPRU035, section 10.9.7](https://www.ti.com/lit/pdf/spru035), [SPRU031H, chapter 11 and appendix C](https://www.ti.com/lit/pdf/spru031), [SPRU063, chapter 10](https://www.ti.com/lit/pdf/spru063) |
| `tic55xboot` (existing) | C5504/05/14/15 and C553x `0x09AA` serial8 tables with per-record padding | C55x; exact device is not encoded | [SPRABL7D](https://www.ti.com/lit/pdf/SPRABL7) |
| `tiais` | AIS load, fill, CRC control, jump, jump-close, SET, function-execute and sequence commands; basic secure key-load/encrypted-load/exit/signatures | No unique ISA; encrypted basic secure AIS is metadata-only | [SPRAB41](https://www.ti.com/lit/pdf/sprab41), [TI SPRUGQ9 copy, basic secure AIS](https://e2echina.ti.com/cfs-file/__key/communityserver-discussions-components-files/120/omapl138_155FFC5BFB7CDF7EA052C65B_-_F18287654872_.pdf) |
| `tirprc` | MCU+/K3 20-byte file and section headers; radar 24-byte file header with size in section word 1; both header byte orders | Target ISA is not encoded | [TI bootloader source](https://github.com/TexasInstruments/mcupsdk-core-k3/blob/k3_main/source/drivers/bootloader/bootloader_rprc.c), [radar Image Creator guide, figure 1](https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/1023/Image_5F00_Creator_5F00_User_5F00_Guide.pdf) |
| `timulticore` | MCU+ `MSTR`/`MEND`, 8-byte core records; mmWave metaimages with 32-byte component records, explicit sizes and CRC fields | MCU+ IDs are platform-dependent; documented radar MSS/DSS role IDs give Arm/C6000; each child classified separately | [MCU+ boot tools](https://software-dl.ti.com/mcu-plus-sdk/esd/AM64X/latest/exports/docs/api_guide_am64x/TOOLS_BOOT.html), [TI appimage tool](https://github.com/TexasInstruments/mcupsdk-core/blob/next/tools/boot/multicoreImageGen/multicoreImageGen.js), [radar guide, figure 2](https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/1023/Image_5F00_Creator_5F00_User_5F00_Guide.pdf) |
| `timcelf` | ELF32/64, both byte orders, TI vendor/segment-map/entry-point notes, final random-string PT_NOTE, optional OTFA note | Combined ELF machine value is metadata; each executable segment is analyzed separately; enabled OTFA is opaque | [TI multicore-elf source, pinned revision](https://github.com/TexasInstruments/multicore-elf/tree/c43c01bfac3a44998f772d204de58b4038b8ffc8) |
| `tiimage` | GP 8-byte size/load-address header (structural recognition requires at least 16 B payload and a nonzero load address); OMAP 512-byte configuration TOC + GP, `CHSETTINGS`/`0xC0C0C0C1` | GP alone has no unique ISA; OMAP configuration format identifies Arm | [TI U-Boot OMAP image tool](https://git.ti.com/cgit/ti-u-boot/ti-u-boot/blame/tools/omapimage.c?h=v2020.04&id=22cbeed454087ffa6ae6e56880bfff125497619b) |
| `tioad` | 44-byte fixed header, seven documented image IDs, variable boundary/contiguous/security segments; `OAD NVM1` external-flash metadata | Arm for device payloads under the specific device IDs; generic/host image ISA is unknown; user data/external metadata is opaque | [TI header definitions](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/main/source/ti/common/cc26xx/oad/oad_image_header.h), [TI OAD header guide](https://dev.ti.com/tirex/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/proprietary-rf/proprietary-rf-users-guide/oad-secure/image-header.html) |
| `tix509` | DER X.509 with TI enterprise OIDs `1.3.6.1.4.1.294.1.*`; simple boot `.1`, integrity/load `.34`/`.35`, combined `.9`, encrypted components `.4`/`.10` | Core IDs do not establish ISA without the platform; unencrypted children classified recursively; board configuration/encrypted children excluded | [TI ROM certificate generator](https://github.com/TexasInstruments/mcupsdk-core-k3/blob/k3_main/tools/boot/signing/x509CertificateGen.sh), [TI application certificate generator](https://github.com/TexasInstruments/mcupsdk-core-k3/blob/k3_main/tools/boot/signing/appimage_x509_cert_gen.py), [TI combined generator](https://github.com/TexasInstruments/mcupsdk-core-k3/blob/k3_main/tools/boot/signing/rom_image_gen.py) |
| `tiasciihex` | STX/ETX, `$A` addresses, printed-order hex bytes | Encoding does not specify target ISA, ROM width or byte lane | [SPRU513, hex conversion formats](https://www.ti.com/lit/pdf/spru513) |
| `titagged` | SDSMAC K/F program identifier, 9 address, B word, * byte, 7 checksum / 8 ignored checksum, F record end, : EOF | Target location and printed data only; no unique ISA | [SPRU513, TI-tagged format](https://www.ti.com/lit/pdf/spru513) |
| `titekhex` | Extended Tektronix %, record length, nibble checksum, data record 6, entry/EOF record 8 | Encoding is shared across vendors | [SPRU513, Tektronix format](https://www.ti.com/lit/pdf/spru513) |
| `tidata` | CCS GO DSP `1651` header, hexadecimal/integer/long/float samples; zero-length header override | Metadata-only: sample width and target byte order are unknown | [SPRU296, section 5.1.2](https://www.ti.com/lit/pdf/spru296) |
| `mcuboot` | 32-byte header, `0x96F3B83D`, protected/unprotected TLV records; flash trailer excluded | Shared format; encryption or unknown encoding flags make the payload opaque | [MCUboot wire specification](https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md), [TI MSPM0 BIM guide](https://software-dl.ti.com/msp430/esd/MSPM0-SDK/2_00_00_03/docs/english/middleware/boot_manager/doc_guide/doc_guide-srcs/bim_users_guide.html) |
| `fip` | TF-A `0xAA640001`, 64-bit offset/size/flags, UUID component records and terminator; 34 standard UUID labels | UUIDs identify component roles, not ISA; known certificates/configuration are excluded from code analysis | [TF-A definitions](https://github.com/ARM-software/arm-trusted-firmware/blob/master/include/tools_share/firmware_image_package.h), [TI U-Boot FIP tooling](https://git.ti.com/cgit/ti-u-boot/ti-u-boot/tree/tools/binman/entries.rst?id=a3b71cc6f5cc74d4edc5808790a3d2999ea3f7fe) |
| `coff` (extended) | TI COFF0/1/2, 20/22-byte file headers, 40/48-byte section headers, both host byte orders, target byte order flags, word-sized section lengths | Eight mapped targets: C3x/C4x, TMS470, C54x, C6000, C55x, C28x, MSP430, C55x+ | [SPRAAO8](https://www.ti.com/lit/pdf/spraao8), [GNU binutils TI COFF definitions](https://gnu.googlesource.com/binutils-gdb/+/37f7f684de0e53c8add5ff43d73082bf98985321/include/coff/ti.h) |
| `ar` variants (extended) | Standard TI object libraries, GNU name tables and BSD inline names; symbol indices excluded | Every recognizable object member is classified independently | [TI C28x tools, archiver](https://www.ti.com/lit/pdf/spru513), [GNU archive implementation](https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/archive.c) |
| Existing shared formats | TI ELF/EABI, PRU ELF, Intel HEX, Motorola S-record, MSP430 TI-TXT, U-Boot uImage/FIT | Existing machine fields or decoded payload classification | [TI assembly tools](https://www.ti.com/lit/pdf/spru513), [MCU+ boot tools](https://software-dl.ti.com/mcu-plus-sdk/esd/AM64X/latest/exports/docs/api_guide_am64x/TOOLS_BOOT.html) |

## Wire units and validation

File offsets and stored lengths are octets (`B`). CPU bit width is not the file
header width. C28x/C54x destination and entry addresses are 16-bit target-word
locations; one word of stored data occupies 2 B. C3x/C4x destinations use target
word locations; C32 stored sample width is selected by the block control word.
Production C5510 and generic 32-bit table addresses/counts are bytes. The existing
C553x parser keeps the byte entry address and 16-bit-word section addresses.
TI COFF section `s_size` is scaled by 4 B for C3x/C4x, 2 B for C54x/C28x,
and 1 B for C55x/C6000/TMS470/MSP430/C55x+ before file-range validation.

For a C28x count of 3 words, `stored_size = 3 words * 2 B/word = 6 B`.
For the original C5535 fixture, `entry_byte = 0x4C665`, and the last overlapping
loaded section places that entry at file offset `0x29207`. Integer address and
length calculations are exact; no floating-point approximation enters bounds
checks. Host-header byte order and target code byte order are kept separately
for TI COFF. TI boot certificates describe payload destinations, not execution entry points.
RPRC reserved address words are not fabricated into high address
bits; 64-bit MCELF addresses and entry points retain their full width.

A recognized binary magic with an invalid layout produces a parse error.
Weak and textual signatures require complete structure/checksum validation
before automatic recognition. Unkeyed tables additionally require the entry to
lie in loaded bytes. Opaque payloads never enter the ISA model. OAD host-processor images do not
inherit the radio CPU ISA; user-data and reserved image types are opaque. Sparse section
bytes are concatenated in stream order for analysis; destination holes and AIS
fill ranges are never materialized. Text records spanning multiple ranges cannot
manufacture a nested container header by concatenation. Container format and
load metadata survive payload-derived ISA classification.

The public CLI JSON remains flat; the library/WASM `DetectionPayload` uses
`format`, `primary`, `slices`, `metadata`, `candidates`, `extensions` and `notes`.
Multicore children and archive members are reported in `slices`; these offsets
refer to the stored child, not a fully relocated memory image. Recursively
contained descendants are not flattened into the outer slice list. The primary
ISA is the first identified child; this does not assert that every core shares
that ISA. Format confidence is separate from ISA confidence and is not a
calibrated probability.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | A complete documented wire layout identifies a format family, not an exact device; applies to all format results | Corrupt lengths, truncate every prefix, vary endian headers, change target/core IDs; compare independent TI-tool output |
| A2 | Target/core IDs have only the semantics stated by the selected family; all multicore and X.509 ISA results depend on this | Reuse a core ID across different devices; verify MCU+ IDs remain metadata, radar MSS/DSS roles stay separate, ELF e_machine is not attributed to every core |
| A3 | Magic-less boot tables and shared keys can collide; weak detections depend on full validation | All-zero and deterministic random files, contradictory byte orders, unloaded entry points, a fixture valid under both C28x and C54x layouts; ambiguity remains unknown |
| A4 | Accessible, untransformed stored sections can be analyzed as code; payload-derived results depend on this | Encrypted AIS/X.509/MCUboot, enabled OTFA, data-only MCELF, configuration FIP UUIDs and CCS samples must not produce ISA model candidates |
| A5 | Printed hex order is preserved; ROM lane/word reconstruction is unknown | LE/BE boot tables inside ASCII Hex; multiple disjoint ranges; do not infer a target byte order from the text encoding alone |
| A6 | Input counts/addresses are untrusted; all extraction depends on checked ranges | Oversized section/core counts, offset aliasing, 32/64-bit arithmetic overflow, huge fill ranges, TLV and DER length corruption, deterministic byte mutations |
| A7 | Parser acceptance describes structure, not signature authenticity | Flip signed/encrypted bytes, use dummy certificates, corrupt CRCs; authentication is never claimed by structural recognition |

## Bounded expansion and remaining boundaries

| Impact | Finding / boundary | Implemented behavior or explicit limit |
| --- | --- | --- |
| High | `.sli` / `.ucf` UniFlash Wi-Fi images use a TI proprietary structure and may use AES-CTR-128 | Wire layout is unknown here; no invented parser. [TI SWRU455E, section 7.12](https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/968/swru455e.pdf) documents the proprietary status |
| High | Shared key words can be valid under two DSP families | Explicit ambiguous TI boot result with unknown ISA and no code extraction |
| High | Platform core IDs, mixed-ISA images and encrypted bytes can create false architecture claims | Separate children, no ISA from addresses or unqualified core IDs, opaque encoded/configuration data |
| Medium | C5510 prototype `-v5510:1`, C32 bit-serial memory packing (1/2/4-bit interfaces), full-secure AIS commands beyond the documented basic sequence, newer radar ROM-specific layouts | Not claimed as implemented; unsupported commands/layouts are errors or remain unrecognized. Production C5510, 8/16/32-bit memory tables and documented 2016 radar layouts are implemented |
| Medium | Legacy OAD without fixed magic, application-defined OAD image IDs, arbitrary raw flash layouts | Automatic family recognition is unknown; the seven documented OAD IDs and external metadata are implemented |
| Medium | CRC and signature interpretation varies by bootloader and mutable header fields | Tagged/Tektronix checksums verified; OAD and optional radar CRC32 status reported; AIS target CRC, radar CRC64, signatures, X.509 image digests and MCUboot authentication are not verified |
| Medium | Compression, ECC, OTFA and future MCUboot flags can alter stored code | Enabled OTFA and unknown MCUboot flags are opaque; no decryption, decompression or ECC reconstruction is claimed |
| Low | CCS files are often saved without an architecture or sample word width | Validate the four documented sample types and preserve header defaults; metadata-only output; only the historical five-field header and four sample types are claimed |
| Low | Bootloader transport protocols are not file containers | UART/USB/HPI/BSL framing and TI Flash API command streams are outside this parser inventory |

The 64 MiB (67,108,864 B) decoded-payload limit applies per extraction, not
to total process memory. Wrapper nesting is limited to six levels; X.509 certificates to 1 MiB (1,048,576 B).
All loops are bounded by input size. With `N` input bytes, `S` stored sections,
`C` children, and `P <= 64 MiB` extracted bytes, linear formats take `O(N + P)`
time and `O(S + P)` additional space. Offset/UUID overlap validation takes
`O(C log C)` time and `O(C)` space. Weak detection tries a fixed number of
layouts. At fixed nesting depth, recursion retains the same asymptotic bounds;
ISA-model analysis has its independent byte budget. No destination-address-sized
allocation occurs.

## Validation and quality gates

`tests/ti_containers.rs` covers wire fixtures, every-prefix truncation of key
families, both host/header byte orders, target word units, nested archives and
certificates, sparse fills, encrypted payload exclusion, offsets, nesting limits, per-component extension evidence and ambiguity,
checksums, TLVs, random input and actual TI-generator output. Synthetic source
images contain only four arbitrary bytes per core. See
[fixture provenance](../tests/fixtures/ti/README.md) for generator revisions,
commands and SHA-256 hashes. No supplied third-party firmware is redistributed. The raw ISA model was not
retrained; new C54x identification comes from container evidence. Existing ELF
recognition does not imply that every TI e_machine value is mapped to a named ISA.
The optional `TI_C55X_FIXTURE` test exercises the reported RX113 image.

Run native tests with `cargo test --all-features`, build WASM and both packaged
interfaces with `./build-web.sh`, and run browser tests with `cd web && npm test`.
Browser regression fixtures check every new format ID through WASM and exercise
core labels and metadata in both source and packaged workbench/classic pages.

| Gate | Evidence / limit |
| --- | --- |
| QG1 | Structural software analysis; no normative judgment is required |
| QG2 | A1-A7 register above; dependent evidence and falsification probes explicit |
| QG3 | Enumerated coverage implemented; unavailable proprietary/custom layouts and excluded revisions are explicitly bounded |
| QG4 | Integer octet/word arithmetic, checked ranges, and independent fixtures |
| QG5 | Ambiguous shared keys, opaque payloads, sparse gaps, reserved/random notes, word lengths and mixed cores handled explicitly |
| QG6 | Vendor manuals, TI generators and upstream format definitions linked by layout; pinned MCELF oracle |
| QG7 | Impact-labeled expansion and unknown formats above; no universal proprietary-format claim |

Verified results on macOS AArch64 (2026-10-12): 403 native tests passed,
6 pre-existing native tests ignored; 61 Chromium browser tests passed,
2 D10 tests skipped because their external fixture was not supplied. The native
and browser runs included the supplied RX113 firmware. The packaged WASM build
succeeded; its asset revision is `2fc8a55d592d29e2`. Standalone CLI checks also
recognized the TI-generated appimage, MCELF and signed fixtures. All 33 primary
reference links returned HTTP 200 at verification time. `git diff --check` passed.
These checks do not establish boot-ROM execution or native Windows/Linux behavior.
