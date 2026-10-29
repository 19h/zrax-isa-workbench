# Zrax ISA Workbench

**Zrax** identifies processor architectures in executables, object files, raw
firmware and mixed-component containers. Its browser workbench combines the same
Rust classifier with Apeiron entropy kernels, a continuous Hilbert/linear canvas
map, a virtual hex editor and a multiple-file analysis queue.

The interface uses HTML, CSS and modern JavaScript ES modules. Analysis runs in a
dedicated worker through WebAssembly. There is no React, frontend framework or
JavaScript bundler. The browser application reads local files and serves its
fonts and code from the same static directory.

| Component | Name |
| --- | --- |
| Repository and checkout | `zrax-isa-workbench` |
| Product, Cargo package, Rust crate and executable | `zrax` |
| Browser bindings | `zrax.js`, `zrax_bg.wasm` |
| Version | `0.1.0` |

## Start the workbench

Install a current Rust toolchain, Python 3 and `wasm-pack`, then run these commands
from the repository root:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked
./build-web.sh
python3 -m http.server 8080 --directory dist
```

Open <http://localhost:8080>. Drop several files anywhere on the workbench, or
use **browse** to select multiple files. Each file gets its own queue entry;
identical filenames remain separate entries. More files can be added while the
worker processes the queue.

`dist/` is the complete static application. It contains the page, styles,
JavaScript modules, WASM, self-hosted fonts and their license notices. Serve the
entire directory with a host that supports JavaScript modules and the
`application/wasm` MIME type. HTTP serving is required for module and worker
loading; opening `index.html` as a local file is insufficient.

The build hashes the runtime assets and puts a revision query on module, worker,
CSS and WASM URLs. Reload an open page after rebuilding. A startup handshake
checks the worker protocol and spatial kernel, exposing incompatible cached
assets as a loading error.

The same build restores the pre-workbench **ISA Classifier** at
<http://localhost:8080/classic/>. Use **CLASSIC** at the bottom right of the
workbench status bar to open it; its header links back to the workbench.

| Interface | Build output | Served path |
| --- | --- | --- |
| Zrax Workbench | `dist/index.html` | `/` |
| Classic ISA Classifier | `dist/classic/index.html` | `/classic/` |

Classic retains the original cards, collapsible sections, confidence/evidence
bars, Raw JSON control and multi-file queue from the last pre-workbench UI.
It uses the current classifier and shared WASM, including D10 component support.
Its original Inter and JetBrains Mono fonts and license notices are packaged
locally. Deploy the entire `dist/` tree: classic imports shared assets from its
parent directory. Relative links also support hosting under a project prefix.
See [classic implementation, provenance and validation boundaries](web/classic/README.md).

The default interface incorporates the preferred 125% sizing. With a 16 px
browser base font, body text is 16.25 px and hex rows are 25 px tall. Use 100%
browser zoom for that default; browser zoom still scales the interface further.
Panels and typography use root-relative dimensions, and canvas/hex calculations
measure their displayed dimensions.

## Workbench capabilities

| View | Implemented behavior |
| --- | --- |
| Files | Multi-file drop and picker, incremental queue, independent failures, remove/clear, cursor and viewport retained per file |
| Subfiles | Nested container members with breadcrumbs and independent classification, entropy, hex and JSON views; decoded bytes in their own coordinate system |
| Image4 decryption | Inline key/IV fields, read-only encoded keybags, CBC/CTR trials and debounced custom material; decrypted output remains under its parent |
| Classification | Format, ISA, bit width, byte order, confidence/source, extensions, ranked raw-code candidates, labelled architecture slices, metadata and notes |
| Entropy | Hilbert/linear layouts, entropy/byte-class palettes, continuous pointer-anchored zoom, drag pan, minimap, fit and previous/next viewport history |
| Inspector | Synchronized byte location, local entropy, byte histogram and measured DEFLATE ratio |
| Hex | Virtual rows, 8/16/24/32 columns, 1/2/4/8-byte groups, hex/decimal offsets, goto, byte selection and integer/floating-point decoding |
| Text decoding | ASCII, Latin-1, CP437, EBCDIC CP037 and UTF-16; byte order override |
| Exports | Classification JSON, batch JSON/CSV, selected bytes, clipboard hex |
| Batch overview | Status filters, insertion/name/size/confidence/entropy sorting, architecture/format tallies and progress |
| Interface | Responsive file panel and inspectors, log, status bar, context menu, keyboard navigation and persistent UI preferences |

Open a container's **subfiles** panel to work on an extracted member. The
parent remains in the file tree; the breadcrumb returns to it. Members start at
byte offset zero in their own workbench, while the parent panel retains their
stored offset and size. The same workflow covers FTAB, UARP, IMG4, archives and
other formats using the shared container model. See [subfile inspection](docs/subfile-inspection.md) and the dated
[verification and boundaries](docs/firmware-workbench-verification.md).

For IMG4/IM4P, **Image4 decryption** shows encoded keybag bytes read-only when
present. With no keybag, enter a hexadecimal key and IV directly in the panel.
Changes trigger a trial after 300 ms. Automatic mode tries CBC and CTR and
requires a unique recognized structure. Explicit modes allow inspecting raw
candidates. **Open decrypted payload** enters the resulting subfile. Material
is retained only in session memory; keybags are not device-key unwrapped, and
recognized structure does not authenticate the plaintext.

The batch overview summarizes the current browser queue. Native batch ingestion
is a separate CLI feature described below.

### Navigation

| Input | Action |
| --- | --- |
| `1` through `4` | Classification, entropy, hex, JSON |
| `j` / `k` | Next / previous file |
| `o` | Open file picker |
| `f`, `b`, backtick | Toggle files, batch overview, log |
| Wheel / trackpad over map | Zoom around pointer |
| Drag map | Pan camera |
| Click / drag minimap | Reposition camera |
| `z` / `x`, `0` | Zoom in / out, fit |
| `Alt+Left` / `Alt+Right` | Previous / next viewport |
| `h`, `c` | Change layout / palette |
| `[` / `]` | Previous / next map cell |
| Arrows in entropy | Move byte cursor |
| Arrows, PageUp/Down, Home/End in hex | Move cursor; Shift extends selection |
| `g`, Escape in hex | Goto / clear selection |
| Ctrl/Cmd+C in hex | Copy selected bytes as hex |

### Continuous zoom and spatial identity

The map keeps a fixed coordinate system for the entire file. Zoom changes a
camera transform; it does not replace the selected byte range with a newly
arranged square. Existing canvas layers remain visible during gestures, while
the worker refines the visible area after a 90 ms idle interval.

```text
wheel or drag
    |
    v
camera transform on next animation frame
    |
    +--> existing canvas layers stay visible
    |
    +--> idle -> bounded detail request -> patch in the same file coordinates

per-file camera -> history (64 views) -> back / forward
completed maps -> cache (12 entries) -> reuse on navigation
```

For a file of `N` bytes, the world side is
`S = 2^ceil(log2(sqrt(max(1,N))))`, with a minimum side of 2. A power-of-two
aggregation scale `a` represents `a^2` bytes per spatial cell. Hilbert cells
cover contiguous file intervals; linear cells aggregate square blocks with row
stride `S`. Unused cells remain transparent and cannot be selected.

With normalized camera origin `(x,y)`, magnification `z` and pointer position
`(u,v)`, the world position is `(x + u/z, y + v/z)`. A zoom to `z'` updates
`x' = x + u/z - u/z'` and similarly for `y`. The pointed world location therefore
remains fixed unless the file boundary constrains the camera. Hit testing uses
the same Hilbert mapping as the analysis kernel.

## Native command-line use

```sh
cargo build --release --locked
./target/release/zrax /bin/ls
./target/release/zrax firmware.bin another-image.bin
./target/release/zrax --format json --extensions firmware.bin
./target/release/zrax --format short executable.elf
./target/release/zrax --mode thorough --candidates firmware.bin
./target/release/zrax --multi-isa --window-size 1024 firmware.bin

# Install the executable into Cargo's bin directory:
cargo install --path . --locked
```

Successful classification exits with status 0. A read/classification failure
sets a nonzero exit status; other supplied files are still processed. JSON mode
writes one formatted object per successful file, rather than a single array.
For machine consumption, use one input per invocation and omit `--candidates`,
which appends a human-readable candidate table.

CLI JSON flattens the primary decision into `isa`, `bitwidth`, `endianness`,
`confidence` and `source`, adds the input `file`, and formats metadata as strings.
Library/WASM JSON serializes `DetectionPayload` with a nested `primary` field
and typed metadata. Consumers must select the schema matching their entry point.

| Option | Meaning |
| --- | --- |
| `-f`, `--format human|json|short` | Output presentation; default `human` |
| `-m`, `--mode normal|fast|thorough` | Analysis budget and evidence threshold |
| `-e`, `--extensions` | Include extension detection in normal/fast CLI modes |
| `-c`, `--candidates` | Append ranked candidates when available |
| `--min-confidence FLOAT` | Normal-mode heuristic threshold; default 0.3 |
| `--multi-isa` | Report ISA families identified across file windows |
| `--window-size BYTES` | Multi-ISA window; default 1024 B, internally at least 96 B |
| `-v`, `--verbose` | Enable diagnostic logging |
| `-q`, `--quiet` | Suppress ancillary error output |

Normal mode scores up to 1 MiB of non-padding windows. Fast mode caps scoring
at 64 KiB and uses a threshold of at least 0.5. Thorough mode scans the whole
input, enables extension detection and uses a threshold of at most 0.2. Padding
detection still visits the entire input in budgeted modes. Multi-ISA detection
also scans the whole file, regardless of the normal single-ISA budget.

These are code-model budgets, not file-read limits: the CLI and file-oriented
Rust helpers load their input bytes into memory.

## Rust library

The package builds an `rlib` for native consumers and a `cdylib` for WASM.
For an adjacent checkout:

```toml
[dependencies]
zrax = { path = "../zrax-isa-workbench", default-features = false }
```

```rust
use zrax::{detect_payload, ClassifierOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("firmware.bin")?;
    let payload = detect_payload(&bytes, &ClassifierOptions::new())?;
    println!("{} {}-bit {}", payload.primary.isa,
        payload.primary.bitwidth, payload.primary.endianness);
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
```

The example also requires `serde_json = "1.0"` in the consuming application's dependencies.
Use `ClassifierOptions::new()` for normal settings; the derived
`ClassifierOptions::default()` has zero/false field values and is a different
configuration.

| API | Result |
| --- | --- |
| `classify_file`, `classify_bytes` | Primary `ClassificationResult` |
| `classify_bytes_with_options` | Primary result with explicit options |
| `detect_file`, `detect_bytes`, `detect_payload` | Full `DetectionPayload` |
| `detect_multi_isa` | Families occupying sufficiently supported code windows |
| `supported_isas` | ISA identifiers present in the embedded raw-code model |
| `quick_check` | Budgeted raw-code family comparison |

The payload contains `format`, `primary`, `candidates`, `slices`, `extensions`,
`metadata` and `notes`. Fat Mach-O binaries expose their contained architectures;
D10 firmware exposes labelled CPU and DSP slices. Classification source
distinguishes header-derived, code-derived and combined results.

| Cargo feature | Purpose |
| --- | --- |
| `cli` | Native CLI and logging; enabled by default |
| `batch` | CLI ingestion pipeline, content hashing, ledgers and terminal progress |
| `wasm` | Browser exports, workbench engine, Apeiron kernels and DEFLATE inspection |
| `full-heuristics` | Retained compatibility feature; currently adds no behavior |

## What the classifier recognizes

Container recognition and raw-code inference provide different evidence. A
mapped container machine field can identify an architecture absent from the
embedded model. `supported_isas()` reports raw-model coverage; the public `Isa`
enumeration additionally represents header-derived architectures.

| Format group | Parser coverage |
| --- | --- |
| Executables and objects | ELF, PE/COFF (ARM64EC and ARM64X hybrid images told apart by their CHPE metadata; also with a `ZM` DOS header), Mach-O and fat Mach-O (load commands: segments and sections, platform and minimum OS, entry point, UUID, code signature (not verified), encryption and chained-fixup records; extensions scanned in instruction sections only, encrypted ranges left out; fat slices scanned on their own; `MH_FILESET` kernel collections list their entries as slices classified on their own; [Mach-O load commands](docs/macho.md)), XCOFF, ECOFF, a.out, DOS MZ/NE/LE/LX (LE/LX also without an MZ stub, structure-validated; [DOS-family headers](docs/mz.md)), PEF, bFLT |
| Legacy objects and operating systems | OMF, SOM, ARM AOF, Palm PDB/PRC, Amiga Hunk, Turbo Debugger symbols, OS-9, GOFF |
| NetWare modules | NetWare Loadable Modules for the four binutils targets: i386 (the "NetWare Loadable Module" signature names x86), SPARC and PowerPC (big-endian headers), Alpha (prefix header); fixed, variable and auxiliary headers (`VeRsIoN#`, `CoPyRiGhT=`, `MeSsAgEs`, `CuStHeAd`/`CyGnUsEx`) in notes and metadata; code image analyzed, data image not; dependency, fixup, import, export and debug tables walked; modules with a bit-7 header version (packed) reported opaque ([NetWare modules](docs/nlm.md)) |
| PC/GEOS | Geodes (`.geo` applications, libraries, drivers): 2.0 (`GEAS`) and 1.x (`GEOS`) file headers, executable header, core block, imported libraries, exported entry points, resource table; `HAF_CODE` resources as 16-bit x86 components, other resources opaque ([PC/GEOS geodes](docs/geos.md)) |
| Psy-Q objects | SN Systems Psy-Q LNK object files (PlayStation, Saturn and Mega Drive `.OBJ`): version 2 record stream decoded to END; PROGRAMTYPE as the target (7 MIPS R3000 little-endian, 8 SH-2, 0 68000); `.text` sections classified as code, other sections opaque; symbols and source files in notes ([Psy-Q objects](docs/psyq.md)) |
| ARM Image Format | AIF executable, non-executable and extended images in either byte order (ARM, 32-bit, from the header); read-only and read-write areas and extended load regions classified as ARM code, debugging and compressed data opaque, decompression and self-relocation code analyzed ([ARM AIF](docs/aif.md)) |
| Symbian E32 images | Symbian OS E32 executables, libraries and drivers: V (8.1b and later), J and original (EKA1) headers; ISA from the CPU identifier (ARMv4/v5/v6, x86, M*CORE as C-SKY); UID checksum and V header CRC verified (mismatches noted); code and data parts as sections; Symbian deflate and byte-pair contents opaque; files without the `EPOC` signature not claimed ([Symbian E32 images](docs/epoc.md)) |
| Symbian SIS packages | Symbian OS v9 SIS/SISX packages: UID checksum verified; SISField tree (31/63-bit lengths, arrays, alignment); zlib or stored SISController with package name, UID, version, vendor and install type; controller and data CRC-16 verified (mismatches noted); files listed by the target path of their SISFileDescription when recognized (E32 executables classified by the EPOC parser), SHA-1 file hashes verified, embedded packages, conditional branches walked; signature chains present, not verified; pre-v9 EPOC SIS not implemented ([Symbian SIS packages](docs/sis.md)) |
| Windows crash dumps | Minidumps (`MDMP`, also byte-swapped): system information, threads, modules, exception, memory and 64-bit memory lists; `ProcessorArchitecture` is the target; memory inside module images is classified as code (only executable sections when the module's PE headers are dumped) and other memory is opaque. Kernel dump headers (`PAGEDUMP`, `PAGEDU64`): `MachineImageType`, bug check and dump type; the dump body is opaque ([Windows crash dumps](docs/minidump.md)) |
| Virtual machines | WebAssembly, Java class, DEX/ODEX/VDEX/ART, LLVM bitcode |
| Java runtime images | jimage (`lib/modules`, both byte orders; perfect-hash index verified; stored, `zip` and `compact-cp` resources decoded; recognized resources listed by full name), JMOD (`JM` 1.0 header, ZIP archive at 0x4 as a child) ([Java runtime images](docs/javaimage.md)) |
| Archives and boot images | ar variants, FatELF, Linux x86/Arm/AArch64/RISC-V kernel images, U-Boot uImage (single and multi-file) and FIT, DTB; compressed kernel payloads are decoded |
| Consoles and DSP | XBE, XEX, PlayStation SELF variants, Switch NSO/NRO, GameCube/Wii DOL, SNES SPC, NSF/NSFe, C64 SID, GBS ([chiptune](docs/chiptune.md)), PSF family (PSF1, PSF2, SSF, DSF, USF, GSF, SNSF, 2SF, NCSF, QSF), PC Engine HES, MSX/Sega KSS, Atari SAP, ZX Spectrum/CPC AY, Atari ST SNDH; Pack-Ice files recognized as opaque ([more chiptune formats](docs/chiptune-sound-programs.md)), ZX Spectrum TZX/TAP ([tapes](docs/zx-tapes.md)), Mega Drive/Genesis ROMs, PS-X EXE, Dreamcast IP.BIN, Wii U RPX/RPL, 3DS NCCH/3DSX, PSP EBOOT.PBP ([console images](docs/retro.md)), Nintendo DS/DSi, Game Boy Advance, Game Boy/Color, iNES/NES 2.0, SNES (LoROM/HiROM/ExHiROM internal header), Nintendo 64 .z64/.v64/.n64 ([Nintendo ROMs](docs/nintendo-roms.md)), TriMedia objects, Motorola DSP LOD |
| Console and home-computer images | Master System / Game Gear (TMR SEGA, checksum verified where defined), Sega 32X (SH-2 program slice), Saturn IP.BIN, Sega CD system area (IP/SP 68000 slices), MSX cartridges, Atari Lynx LNX, Atari 7800 A78, C64 CRT (CHIP packets as 6510 slices), Atari ST GEMDOS programs (relocation table validated), ZX Spectrum .z80 (RLE decoded) and .sna, WonderSwan (checksum verified; NEC V30MZ as 16-bit x86), Neo Geo Pocket (TLCS-900/H) ([console and home-computer images](docs/retro2.md)) |
| Commodore disk and tape images | D64 (1541, 35 and 40 tracks), D71 (1571), D81 (1581), each with or without error bytes, and T64 tapes; directory files reassembled from their sector chains, PRG files as 6502-family code after the load address, SEQ/USR/REL files and 1581 partitions opaque, DEL entries skipped ([Commodore disk and tape images](docs/cbm.md)) |
| Amiga disk images | ADF floppies (DD and HD): AmigaDOS OFS and FFS volumes with the international, directory cache and long-name DOS types (root, entry, extension, OFS data and bitmap block checksums verified; hash chains followed with loop detection; recognized regular files such as Hunk executables reassembled and listed by path) and bootable non-DOS floppies (boot block checksum verified), with boot block code as a 68000-family child after the files; Rigid Disk Block hard disks (partitions walked as `DH0:/path`, FSHD/LSEG file system handlers) and unpartitioned hardfiles ([Amiga disk images](docs/adf.md)) |
| Atari 8-bit disks and executables | ATR disk images (128- to 8192-byte sectors) with the Atari DOS 2.0S/2.0D/2.5 file system: files rebuilt from their sector chains (file-number and loop checks) and listed by name, binary load files as 6502 code, other files opaque, then the boot sectors as 6502 code; Atari DOS binary load files (.xex/.com; weak: segments must tile the file) with segments at their load addresses and RUNAD/INITAD entry points ([Atari 8-bit](docs/atari8.md)) |
| Apple II disk images | DOS 3.3 (35/40 tracks; DOS or ProDOS sector order from the catalog chain, ambiguous orders reported without extraction) and ProDOS volumes (seedling, sapling, tree and GS/OS extended files, subdirectories) as weak raw images, and 2IMG (DOS order, ProDOS order; nibble data opaque); every file a child by path: DOS B, ProDOS BIN and SYS files as 6502 code with their load address, other types opaque; boot sector or blocks 0-1 as 6502 code after the files ([Apple II disk images](docs/apple2.md)) |
| CPC and Spectrum +3 disks | CPCEMU and Extended DSK images: AMSDOS data, system and IBM formats and the +3/PCW disk specification; CP/M files reassembled across extents; AMSDOS binary and +3DOS CODE files as Z80, BASIC and screens opaque, headerless files when recognized; the CP/M boot sector and +3 bootstrap as Z80; copy protection in notes; standalone +3DOS (strong) and AMSDOS (weak) headered files ([CPC and Spectrum +3 disk images](docs/cpcdsk.md)) |
| Firmware and loader text | Espressif ESP32-family and ESP8266 (v1/v2) application and bootloader images (chip ID names Xtensa LX6/LX7 or RISC-V; checksum, SHA-256 and CRC-32 verified; data segments opaque) and ESP flash dumps (ESP-IDF partition table at 0x8000 with MD5 verified; bootloader and partitions classified on their own) ([Espressif](docs/esp.md)), Blackfin LDR boot streams ([LDR](docs/blackfin-ldr.md)), PCI and legacy option ROMs ([option ROMs](docs/option-roms.md)), Huawei UPDATE.APP packages ([Huawei](docs/huawei-update.md)), Intel HEX, Motorola S-record, TI-TXT, TI ASCII Hex, TI SDSMAC tagged, Extended Tektronix, CCS GO DSP data |
| Texas Instruments firmware | C28x/C54x/C55x/C3x/C4x and unkeyed boot tables, AIS, RPRC, MCU+ and mmWave appimages, multicore ELF, GP/OMAP images, OAD, TI X.509 wrappers, MCUboot, TF-A FIP |
| Specialized containers | OLS, EPR, SGO, VBF, FRF, BCF, SOX, AOR D10, ASAM ODX-F, Honda RWD, Toyota CUW, Mercedes CFF ([automotive](docs/automotive.md)) |
| Apple UARP super binaries | Structural recognition, independent firmware payloads, packed global and payload TLV metadata; nested FTAB/IMG4 and compression handled recursively ([UARP](docs/uarp.md)) |
| Apple FTAB firmware tables | `rkosftab` and `RKOSFTAB`; bounded file table, independent firmware members, placeholder metadata, opaque manifest; nested containers and compression handled recursively ([FTAB](docs/ftab.md)) |
| Apple images | IMG4 and IM4P (stored and compressed payloads, bounded headerless codec trials, CBC/CTR trials with encoded keybags and inline custom key/IV; unusable keybags remain opaque), IM4M manifests and IM4R restore info as metadata, dyld shared caches (architecture token, mappings, Mach-O images mapped into the file); legacy Img3 (DATA child, KBAG-encrypted payloads opaque) and 8900 containers (plaintext payload child, encrypted formats opaque) ([Apple images](docs/apple.md)) |
| Android images | Boot images (`ANDROID!` header v0-v4: kernel/ramdisk decoded and classified, second stage, recovery DTBO, DTB, v4 signature, AVB footer, mkbootimg SHA-1 ID checked), vendor_boot v3/v4 (ramdisk table, DTB, bootconfig), sparse images (RAW/FILL/DONT_CARE/CRC32 expanded to one partition image, CRC32 verified, 64 MiB cap), OTA `payload.bin` (`CrAU` v1/v2, protobuf manifest, full operations reassembled per partition with SHA-256 checks; delta partitions opaque), bootloader packs (Qualcomm and ASUS `BOOTLDR!`, Qualcomm meta image, FBPK v1/v2), dynamic-partition `super` images (liblp v10.0-10.2, full and `super_empty`; SHA-256 checked; partitions listed by name, multi-extent partitions assembled), DTB/DTBO tables (v0/v1, zlib/gzip entries; device trees as members), AVB vbmeta images (descriptors summarized, hash recomputed, signature not verified). No header names a CPU; members are classified from their own bytes ([Android](docs/android.md)) |
| SoC boot ROM images | Allwinner eGON.BT0 (checksum, A32/RISC-V jump word as entry ISA) and TOC0 (items opaque); Rockchip RKFW, RKAF, RKBOOT (RC4-descrambled entries) and idbloader v1/v2; MediaTek EMMC/SF/SDMMC/UFS_BOOT, BRLYT and GFH; Qualcomm 80-byte SBL and 40-byte v3 MBN ([SoC loaders](docs/socboot2.md)); Xilinx Zynq-7000/ZynqMP `BOOT.BIN` (boot header, image header table and partition checksums verified; partitions as slices with destination-CPU targets; bitstream and encrypted partitions opaque), NXP i.MX HAB IVT images and i.MX 8/9 AHAB containers (no ISA field; the code model classifies the application; DCD, CSF and signatures opaque), NXP SB2.0/2.1/3.1 secure binaries (metadata only; SB3.1 hash chain verified, signatures not verified) ([SoC boot images](docs/socboot.md)) |
| Miscellaneous boot images | OP-TEE `OPTE` headers (v1 `tee.bin` with init/paged parts, v2 image table; the arch byte names AArch32/AArch64), Amlogic USB burning images (v1/v2 item tables, CRC-32 and VERIFY SHA-1 checked, items by role), Allwinner PhoenixSuit/LiveSuit `IMAGEWTY` (0x0300 and 0x0100 headers, the RC6-encrypted variant decrypted with published keys), barebox ARM/AArch64 heads (ISA from the head instruction) ([boot images](docs/bootmisc.md)) |
| MCU update images | UF2 (family ID names the ISA for 78 listed families; blocks reassembled by address; multi-family files split per family), STM32 DfuSe (DFU suffix CRC-32 verified), Silicon Labs GBL v3 (program/LZ4/LZMA tags, end-tag CRC-32 verified; encrypted files opaque), Cypress `.cyacd`/`.cyacd2`, USB DFU 1.1 files (firmware plus DFU suffix; signature and CRC-32 verified; firmware classified on its own), Silicon Labs EBL (program tags as sections, end-tag CRC-32 verified, AAT platform `CortexM3` names Arm, encrypted files opaque), Nordic nRF5 DFU init packets (weak; metadata only, signatures not verified) ([MCU images](docs/mcu.md)) |
| FPGA bitstreams | Xilinx `.bit` and headerless configuration data (both word orders), Lattice iCE40 and ECP5/MachXO/Nexus, Intel Cyclone V `.rbf` and `.pof`; recognized and excluded from ISA scoring ([FPGA bitstreams](docs/bitstream.md)) |
| Compressed streams | gzip, zlib, xz, LZMA-alone, LZ4 (frame and legacy), Zstandard, bzip2, lzop, LZFSE/LZVN, Apple LZSS kernelcaches; decoded and classified by their content |
| ZIP, tar and CPIO | ZIP (ZIP64; stored, deflate, bzip2, LZMA, Zstandard and xz members with CRC-32 verified; APK, JAR, IPA, Nordic DFU and PDX labels), tar (ustar, pax, GNU), CPIO (newc, crc, odc, old binary) ([archives](docs/archives.md)); members classified on their own bytes |
| Microsoft cabinets | `MSCF` cabinets: stored, MSZIP (history kept across blocks) and LZX (2^15-2^21 windows, E8 translation) folders decoded; CFDATA checksums verified; files in a recognized format listed by name, so PE drivers and nested cabinets are classified by their parsers; cabinet sets noted, continued files not joined; Authenticode signature reserve reported, not verified; Quantum folders not decoded ([Microsoft cabinets](docs/cab.md)) |
| WIM images | `MSWIM` Windows Imaging files (`.wim`, split `.swm` parts, unencrypted `.esd`), versions 1.13 and 0xE00: stored, XPRESS, LZX and LZMS chunked resources and solid resources decoded; files of every image in a recognized format listed as `/<image>/<path>` (named streams as `path:name`), each SHA-1 verified; shared resources decoded once; integrity table verified; image names and XML architecture reported as text; encrypted ESDs opaque; split parts noted, not joined; reparse point and EFS data not examined; the WIM names no ISA ([WIM images](docs/wim.md)) |
| RPM packages | RPM v3/v4/v6 binary and source packages: lead, signature and main header structures checked as rpm checks them (limits, immutable regions, entries); header SHA-1/SHA-256, header+payload MD5 and payload SHA-256/512 digests verified, signatures present and not verified; cpio payload (newc, or rpm's stripped `07070X` entries resolved through the header's file table) decoded from gzip, bzip2, xz, LZMA or Zstandard (first 64 MiB of larger payloads), with recognized files listed by path and classified on their own bytes; the header architecture is reported, not used as ISA evidence ([RPM packages](docs/rpm.md)) |
| Application bundles | PyInstaller archives (CArchive cookie and TOC; binaries and data files in a recognized format listed, zlib-decoded with Adler-32 checked, the Python library first; scripts and PYZ opaque; recognized standalone only when the cookie ends the file), Electron ASAR archives (Pickle header and JSON tree checked, every stored file's SHA-256 verified, block hashes not verified, native modules listed), .NET single-file bundles (bundle versions 1.0, 2.0 and 6.0, raw-DEFLATE members, bundle ID checked against the contents; parsed only inside the apphost); PyInstaller archives and .NET bundles inside ELF, PE and Mach-O executables have their members listed beside the host's own result; no header names an ISA ([application bundles](docs/appbundle.md)) |
| Filesystem images | SquashFS 4.0 (gzip, LZMA, LZO, xz, LZ4, zstd), CramFS (both byte orders, CRC-32 verified) and romfs, with recognized regular files listed by path; SquashFS 1.x-3.x, big-endian and streamed images recognized but not enumerated ([read-only filesystems](docs/rofs.md)); ext2/ext3/ext4 (32/64-bit group descriptors, `meta_bg`, `flex_bg`, block maps and extent trees, linear and htree directories; `metadata_csum` and `gdt_csum` verified; regular files in a recognized format listed by path; truncated images read up to the end of the input, files listed only when all of their blocks are present) ([ext](docs/ext.md)) |
| EROFS | EROFS images (Linux v6.11 layout): compact and extended inodes; flat, tail-packed and chunk-based files; LZ4, MicroLZMA and DEFLATE compressed files with full or compact indexes, big pclusters, tail packing and fragments; recognized files listed by path ([EROFS](docs/erofs.md)) |
| Virtual disk images | QCOW2 v2/v3 (deflate and zstd compressed clusters, extended L2 subclusters, backing files), VMDK hosted sparse extents (monolithic sparse, stream-optimized), VHD (fixed, dynamic, differencing), VHDX (fixed, dynamic, differencing) and VDI (header 1.1); the guest disk is one child (a stored slice, or the first 64 MiB assembled from the allocation tables) classified on its own; encrypted QCOW2 opaque; parent and backing images named, not read ([virtual disk images](docs/vdisk.md)) |
| Apple disk images | UDIF `.dmg` (`koly` trailer; XML property list or binary resource fork): each volume partition a child assembled from zero, raw, ignore, ADC, zlib, bzip2, LZFSE and LZMA (xz) chunks (first 64 MiB), listed when recognized; partition-map, boot-record and free-space tables decoded only to verify their CRC-32; data fork, master and table CRC-32 verified; segmented images per segment; encrypted images (`encrcdsa`, `cdsaencr`) opaque ([Apple disk images](docs/dmg.md)) |
| Full Flash Update images | Microsoft FFU V1 and V2: security header, signed catalog and hash table, image header and INI manifest, one store or several with validation entries and write descriptors; each store's disk assembled from its DISK_BEGIN/DISK_END write descriptors (first 64 MiB; disk size from the manifest) and classified on its own, main OS store first; SHA-256/SHA-1 chunk hashes verified (first 64 MiB of chunks); catalog signature not verified; no ISA named ([Full Flash Update images](docs/ffu.md)) |
| HFS+ / HFSX volumes | Volume header (plain or in an HFS wrapper), catalog, extents overflow and attributes B-trees; regular files in a recognized format listed by path; hard links resolved, symlinks counted; decmpfs zlib/LZVN/LZFSE and uncompressed (types 1 and 9) files (in the attribute or resource fork) decoded; journal noted, not replayed; the volume names no ISA; volumes larger than the input (for example a DMG partition cut at the 64 MiB extraction limit) are read as truncated volumes: files whose data is present are listed, the rest counted ([HFS+ volumes](docs/hfsplus.md)) |
| APFS containers | Container superblock and the latest checkpoint (Fletcher-64 verified), container and volume object maps, volume superblocks and file-system B-trees; regular files in a recognized format listed by `/<volume>/<path>`; hard links examined once, symlinks counted; decmpfs zlib/LZVN/LZFSE and uncompressed (types 1 and 9) files decoded; encrypted volumes opaque; sealed volumes, snapshots and Fusion noted; EFI jumpstart driver listed last; a container cut short is read as far as it goes; the container names no ISA ([APFS containers](docs/apfs.md)) |
| Partition tables | MBR with EBR chains (logical partitions from 5), GPT (512/4096 B blocks; header and entry array CRC-32 verified; backup header verified, or used when the primary is corrupt), Apple Partition Map; each partition listed when recognized; MBR bootstrap code as 16-bit x86, GRUB BIOS boot partition as code, APM boot code with a 680x0 `pmProcessor` as M68k ([partition tables](docs/partitions.md)) |
| FAT and exFAT volumes | FAT12, FAT16 and FAT32 (weak structural detection: BPB consistency, FAT type by cluster count only, FAT[0]; long names with checksum, fragmented cluster chains, FSInfo and backup boot sector checked; regular files in a recognized format listed by path; volume boot code classified as x86 16-bit, after the files) and exFAT (boot region, entry set and up-case table checksums verified; NoFatChain and FAT-chained files); exFAT volumes, and FAT volumes parsed directly, that are larger than the input are read as truncated volumes ([FAT](docs/fat.md)) |
| NTFS volumes | Boot sector (ntfs-3g checks plus `55 AA`), `$MFT` through its runlist and attribute list, update sequence fixups verified, attribute lists, named streams (`path:name`), sparse runs and LZNT1 compression decoded; paths from `$FILE_NAME` parent references, orphans under `/$OrphanFiles`; hard links examined once, symbolic/Interix links counted; EFS-encrypted and WOF files counted, not read; `$MFTMirr` and backup boot sector compared; volumes larger than the input read as truncated volumes; the volume names no ISA ([NTFS volumes](docs/ntfs.md)) |
| Console disc images | GameCube disc images (boot DOL, apploader as PowerPC code, FST files by path), Wii disc images (partition table; encrypted partitions listed as opaque), Xbox and Xbox 360 XDVDFS images (XISO and full XGD1/XGD2/XGD3 images; XBE, XEX and other recognized files by path) ([console disc images](docs/discs.md)) |
| Disc image containers | Dolphin GCZ (zlib blocks, Adler-32 of every stored block verified), GameCube/Wii CISO, WBFS (one disc per used slot) and PSP CSO v1/v2 and ZSO (DEFLATE and LZ4 blocks), each decoded to its first 64 MiB and classified as a GameCube, Wii or ISO 9660 image ([disc image containers](docs/discimg.md)) |
| Nintendo 3DS and Switch containers | 3DS NCSD cart images (partitions classified by the NCCH parser) and NAND images (AES-CTR partitions opaque), 3DS CIA (weak: header, 64-byte section layout and TMD record hashes validated; unencrypted contents classified with SHA-256 checked, title-key-encrypted contents opaque), Switch PFS0/NSP (files by name; NSO/NRO classified, NCAs opaque) and XCI gamecard images (root and partition HFS0 hashes checked; files as <partition>/<name>, secure first); no ISA from the containers themselves ([Nintendo 3DS and Switch containers](docs/nintendo2.md)) |
| Xbox 360 packages | STFS packages (`CON `, `LIVE`, `PIRS`): read-only and two-copy hash table formats; files rebuilt from consecutive blocks or hash-record chains and listed by path (XEX classified by its parser); header, hash table and block SHA-1 checked; signatures present, not verified; title ID and display name in notes; SVOD headers recognized, data files not parsed ([Xbox 360 STFS packages](docs/stfs.md)) |
| Optical disc images | ISO 9660 (ECMA-119; both-byte-order primary volume descriptor checked; names from Rock Ridge NM entries with relocation, from Joliet UCS-2, or from ISO identifiers; multi-extent files; recognized regular files listed by path), El Torito boot images (validation checksum verified; platform 0 no-emulation images as x86 real-mode code, EFI and emulated disk images classified from their own bytes; listed after the files), hybrid MBR/GPT system areas and UDF bridge descriptors noted; truncated images read up to the end of the input (files listed only when all of their sections are present) ([ISO 9660](docs/iso9660.md)) |
| UDF volumes | UDF 1.02-2.60 (ECMA-167 recognition sequence and anchor at sector 256 with tag checksum, CRC and location verified; 512-4096 B sectors; main/reserve descriptor sequences; physical, sparable, metadata (2.50+) and virtual (VAT 1.50/2.00) partitions; file entries and extended file entries with short, long, extended and embedded allocation, continuation extents and strategy 4096 indirection; recognized regular files listed by path, fragmented and sparse files reassembled), UDF bridge discs reported as UDF when the UDF volume opens (El Torito boot images then noted, not listed); truncated volumes read up to the end of the input ([UDF](docs/udf.md)) |
| Flash filesystems | UBI (erase-counter and VID headers, PEB size discovery, volume table, static and dynamic volumes), UBIFS (node scan, LZO/zlib/Zstandard data) and JFFS2 in both byte orders (zlib, LZO, rtime, rubin, OpenWrt LZMA); recognized files are listed with full paths ([flash filesystems](docs/mtd.md)) |
| UEFI and PC flash images | UEFI PI firmware volumes and flash device images (FFS files; compressed, GUID-defined LZMA/LZMA F86/Tiano/Brotli/CRC32 and nested volume sections; per-image PE32 and TE machines), standalone TE images, Intel flash descriptor images (region map, BIOS-region volumes; ME and other regions opaque) ([UEFI](docs/uefi.md)) |
| UEFI capsules | `EFI_CAPSULE_HEADER` capsules with documented GUIDs: FMP capsules (image headers v1-3; PKCS7 and RSA2048/SHA-256 authentication, dependency expressions and the EDK2 `FMP_PAYLOAD_HEADER` skipped, not verified; payload images and embedded PE/TE drivers classified on their own, payloads first; vendor code opaque), nested FMP capsules (weak), `EFI_CAPSULE_GUID` capsules (body, often a firmware volume, classified on its own), JSON and Windows UX capsules (payload opaque; UX checksum verified), and Intel, Lenovo, Toshiba and AMI Aptio vendor headers as UEFITool reads them; the capsule names no ISA ([UEFI capsules](docs/capsule.md)) |
| PC firmware blobs | Intel microcode updates (SDM header, BCD date, header and extended signature checksums verified), AMD microcode containers, Intel ME `$FPT` tables v1.0/2.0/2.1 and `$CPD` code partitions with `$MN2` manifests, AMD EFS flash images and PSP/BIOS/L2/combo directories (Fletcher-32 checksums verified); all opaque with ISA unknown; an Intel flash descriptor's ME region with a `$FPT` table is classified as `intelme` ([PC firmware](docs/pcfw.md)) |
| coreboot and Chromium flash images | Chromium FMAP flash images (map at offset 0 or found by search; ME/IE and data areas opaque) and coreboot CBFS regions and legacy ROMs; stages and payload segments decoded (LZMA, LZ4), SHA-2 file hashes verified ([coreboot](docs/coreboot.md)) |
| Router firmware wrappers | Broadcom TRX v1/v2 (CRC-32 verified; loader, kernel and root filesystem partitions), Netgear CHK (all four checksums verified), D-Link SEAMA entities and seals (MD5 not verified), TP-Link mktplinkfw v1, mktplinkfw2 v2/v3 and SafeLoader factory images (weak structural detection; MD5 not verified); raw OpenWrt LZMA kernels decoded and classified; no header names an ISA ([router firmware](docs/router.md)) |
| Firmware package wrappers | MikroTik RouterOS NPK packages and bundles (parts walked, zlib file containers decoded with recognized files listed, SquashFS parts listed, SHA-1 digests checked; KCDSA/EdDSA signatures not verified), Ubiquiti firmware images (OPEN/UBNT/GEOS headers, PART and EXEC records, END./ENDS; every CRC-32 verified; ENDS RSA signature not verified), ChromeOS kernel partitions (vboot keyblock and kernel preamble checks, keyblock SHA-512 verified, RSA signatures not verified, x86 vmlinuz rebuilt as futility does, kernel listed before bootloader); no header names an ISA ([firmware package wrappers](docs/fwpack.md)) |
| QNX images | QNX Neutrino bootable IFS (startup header in either byte order, optional boot prefix; ELF machine field names the target; startup and image checksums verified; gzip and LZO image filesystems decoded, UCL opaque) and bare image filesystems; recognized files listed by path, boot script summarized ([QNX](docs/qnx.md)) |
| Windows CE ROM images | `B000FF` BIN files (records with verified checksums, assembled at their addresses) and raw `.nb0` images (recognized from a self-consistent ROMHDR); ROMHDR `usCPUType` gives the ISA; modules with `e32_rom` fields, module code sections as components, compressed sections opaque, ROM files listed when recognized ([Windows CE](docs/wince.md)) |

[Compressed streams and the shared container model](docs/compressed-streams.md)
describe the codecs, coordinates and bounds;
[kernel and boot images](docs/kernel-images.md) describe the kernel layouts.
[TI format coverage, wire references, assumptions and unsupported variants](docs/ti-containers.md)
include TI COFF0/1/2 and object-library member classification. MCUboot, FIP
and Extended Tektronix are shared formats, not proof of a TI device.

Recognition does not imply that an encrypted payload can be decrypted, that
every revision is supported, or that every member of an archive is recursively
classified. Parser results and notes retain those distinctions.
[Format coverage gaps](docs/format-gaps.md) lists known kernel-image defects
and unsupported codecs, containers and dump transforms.

The shipped `ISAM` version-1 model contains **94 classes**: 90 code variants and
four non-code classes (`neg_media`, `neg_rodata`, `neg_table`, `neg_text`). Code
variants include mainstream x86/ARM/MIPS/PowerPC/RISC-V, legacy architectures,
microcontrollers, DSPs and virtual machines. Its exact names and interpretation
are defined by [model.rs](src/heuristics/model.rs) and the embedded
[model.bin](src/heuristics/model.bin).

### Raw-code decision algorithm

Each class is a first-order byte Markov model. For adjacent bytes `p,b`, a table
stores a quantized cost approximating `-log2 P(b | p)`. The embedded tables use
two cost units per bit, giving 0.5 bit resolution. Window costs sum these values
and compete against all code classes, non-code classes and an implicit uniform
model at 8 bits per byte transition.

```text
recognize format
    |
    +--> supported header ISA -> parse metadata and ISA
    |
    +--> raw or extractable code -> tile input (normally 1024 B)
                                      |
                                      +--> padding/text screening
                                      +--> distribute scoring budget
                                      +--> score each selected window
                                      +--> compare code / data / other families
                                      +--> aggregate family and variant evidence
                                      +--> accept or report inconclusive
```

Code evidence needs a margin of at least 0.4 bits per byte transition and
16 bits total over competing families/data. When a top-level raw input is
inconclusive, byte swaps, lane interleaves and NAND spare removal are tried
with a union-bound penalty ([raw-dump transforms](docs/transforms.md)). Family evidence and its strength
determine the returned confidence. Candidate evidence shares are not posterior
probabilities. Rejection is an explicit outcome when the input does not support
a known code hypothesis. Header confidence and model confidence arise from
different mechanisms and must be interpreted with their `source` field.

For input size `N`, scoring budget `B`, window width `w` and class count `C`,
padding screening takes `O(N)` time and model scoring takes `O(C*B)` time.
Deep/multi-ISA scanning uses `B = N`. Stored model tables occupy `O(C*256^2)`
bytes; scan state occupies `O(N/w + C*B/w + w)` space, in addition to input
storage. Extension detection and container parsing add their own work. A
bounded scoring budget does not make overall file processing sublinear in `N`.

### AOR AR-DV10 / D10 containers

D10 firmware contains multiple independently addressed blobs. The parser checks
the outer CRC16, validates record boundaries/identifiers, preserves all records
as metadata and decodes CPU data when the observed vector/key convention
requires it. Component classification keeps FPGA data out of CPU/DSP inference.

| Component | Interpretation | Classification input |
| --- | --- | --- |
| `0` | FPGA | Preserved metadata; excluded from ISA inference |
| `1` through `4` | DSP images | Each nonempty block `0` independently |
| `5` | RX CPU component | Decoded block `0`; block `1` provides vectors/key context |

Component identity does not force an ISA. The supplied `2504B.D10` yields an RX
CPU and two Blackfin DSP slices from their respective code. A non-code or
unrecognized component remains unknown rather than receiving a fixed label.
Recognized but invalid D10 files return a container error.

```sh
./target/release/zrax --extensions --format json /path/to/2504B.D10
```

See [D10 format, decoding, fixture hashes and differential validation](docs/d10-container.md).
The source format reference is the supplied Python extractor; real firmware
fixtures remain external. For encoded files, hex/entropy refer to stored bytes
while CPU classification refers to decoded code; metadata records the encoding
and stored component offsets.

## Entropy, compression and memory bounds

For byte counts `c_i`, `n = sum(c_i)` and `n > 0`, the entropy kernel computes:

```text
H = log2(n) - sum(c_i * log2(c_i)) / n     [bits/byte]
i = 0 .. 255; zero-count terms contribute zero
0 <= H <= 8 bits/byte; H(empty) = 0
```

The vendored Apeiron implementation retains count-logarithm lookup tables,
four-way histograms and portable `wide` operations. Calculations use `f64`;
map/profile transport uses `f32`, with an absolute rounding bound of
5e-7 bits/byte on `[0,8]`, before display rounding.

| Measurement or resource | Bound / interpretation |
| --- | --- |
| Entropy overview | Up to 1024 bins; centered sample of at most 4096 B per bin |
| Browser batch entropy | Arithmetic mean of sampled local bin entropies, rather than whole-file entropy |
| Map and visible detail | At most 256*256 cells per request; six `f32` values per cell |
| Small-cell entropy | Cells below 256 B use up to 256 neighboring bytes as labelled context |
| Larger-cell entropy | Exact cell population, including clipped end-of-file cells |
| Histogram and compression inspector | Labelled window of at most 4096 B |
| Compression ratio | Raw DEFLATE level-6 output length / input length; may exceed 100% |
| Resident file | At most 1 GiB; lower browser allocation limits can still fail |
| Analysis residency | One WASM engine/file at a time; switching may reread the local `File` |
| Selection entropy | At most 4 MiB |
| Clipboard bytes | At most 1 MiB |
| Selection download | Complete selected `File` range |

Map transfer payloads are bounded to `65536*6*4 = 1572864 B` (1.5 MiB), excluding
message metadata and canvas storage. Twelve full-sized payloads would occupy
18 MiB of numeric arrays; rendering layers consume additional memory.

File loading creates an `ArrayBuffer`, WASM argument storage and resident Rust
data; peak memory can substantially exceed the file length. The 1 GiB ceiling
is an acceptance limit, not a guarantee that every browser can allocate that
file. Initial whole-file mapping still examines file bytes; continuous camera
movement reuses completed analysis, and visible refinement requests bounded
patches. Entropy kernels take `O(n + 256)` time with fixed histogram storage for
an `n`-byte population.

The browser compression proxy uses `miniz_oxide`. Apeiron's native GUI, GPU
renderer and XZ/Zstd tier selection are not part of this application.

## Native batch ingestion

Build with the optional `batch` feature to recursively classify a directory and
write a local, content-addressed staging tree:

```sh
cargo build --release --locked --features batch
./target/release/zrax batch \
  --input /path/to/firmware \
  --output /tmp/zrax-stage \
  --prefix zrax/v1 --jobs 8 --no-tui
```

The pipeline walks paths, hashes bytes with SHA-256, classifies in worker pools
and writes binary objects, metadata, view references, index shards, compressed
ledgers, run manifests and statistics. Confidence and runner-up margin control
classified/ambiguous routing. `--skip-existing` consults local index shards;
it is not a remote existence check.

```text
/tmp/zrax-stage/zrax/v1/
|-- objects/sha256/ab/cd/<hash>.bin
|-- objects/sha256/ab/cd/<hash>.meta.json
|-- views/classified/...
|-- views/ambiguous/...
|-- index/sha256/ab/cd.idx
|-- ledgers/global/<run-id>/...
|-- ledgers/isa=<isa>/<run-id>/...
|-- runs/<run-id>.json
`-- stats/current.json
```

The default key prefix remains `isa-harvester/v1` for existing storage layouts;
pass `--prefix zrax/v1` for the layout above. Upload the prefix directory to the
corresponding remote prefix so it is not duplicated:

```sh
rclone copy /tmp/zrax-stage/zrax/v1/ remote:bucket/zrax/v1/ --progress
```

Zrax itself writes locally and does not contain an S3 client or hosted REST
service. [Batch store documents](docs/batch-store/README.md) include both current
staging behavior and design specifications for remote APIs and a future hosted
browser. Their proposed commands/endpoints are not the static workbench's API.

## Model training and evaluation

The embedded model is sufficient for normal builds. Rebuilding it requires
external, labelled inputs; those datasets and toolchain source trees are not
included in a fresh checkout.

```sh
python3 scripts/build_corpus.py --out /tmp/zrax-corpus \
  --data /path/to/data --armgen /path/to/armgen

# Hold out the corpus test split during training:
cargo run --release --example train_model -- \
  --corpus /tmp/zrax-corpus --split train --out /tmp/zrax-heldout-model.bin

cargo run --release --example eval -- \
  --corpus /tmp/zrax-corpus --model /tmp/zrax-heldout-model.bin \
  --snippets 128,512,2048

# Rebuild the shipped model from all selected samples:
cargo run --release --example train_model -- \
  --corpus /tmp/zrax-corpus --out src/heuristics/model.bin
```

Evaluation against the shipped model measures fit because that model includes
the corpus test split. Use a separately trained `--split train` model for
held-out generalization measurements. Acceptance accuracy, rejection rate,
non-code false accepts and variant accuracy are separate measurements.

[Raw-code model documentation](docs/architecture/raw-code-model.md) describes
source balancing, train/test grouping, smoothing, cost quantization and
calibration. `scan_debug`, `calibrate`, `format_fp` and `recursive_analysis`
provide additional analysis harnesses.

`scripts/compile_llvm_matrix.sh`, `scripts/gcc_matrix/` and
`scripts/sdcc_matrix/` generate ground-truth code with external compilers.
Set `ARMGEN=/path/to/armgen` for generator scripts. Local migration defaults
point to the retained sibling `../isa-harvester/armgen`; corpus and accuracy
scripts also accept explicit input paths. The runtime classifier has no
dependency on that checkout or on `~/dev/apeiron`.

## Verification

```sh
# Native CLI, batch, kernels, D10, binary regressions and Rust doc examples:
cargo test --all-features --locked
cargo check --all-features --examples --locked

# Rebuild WASM and the complete static application:
./build-web.sh

# Browser regression suite (Node.js and Chromium are test dependencies only):
cd web
npm ci
npx playwright install chromium
npm test

# Also exercise a local real D10 fixture:
D10_FIXTURE=/path/to/2504B.D10 npm test
```

Browser tests cover multiple-file ingestion, queue failure isolation,
classification payloads, packaged assets, fixed map coordinates, smooth
navigation/history, minimap, virtual hex boundaries, selections, text decoding,
responsive dimensions and D10 components. They test source and packaged
workbench paths. Node.js is not required to serve or use `dist/`.

The optional `idaref/` suite skips when that external corpus is absent;
`IDAREF_DIR` selects another corpus location. The extractor differential D10
test is explicitly ignored unless invoked with reference data; instructions
are in the D10 document. A skipped external suite is not evidence about a
corpus that was not tested.

Migration validation on 2026-10-11 used Rust `1.100.0-nightly` and Node.js
`25.8.1`. The complete native run passed 361 tests, including the available
local IDA-reference corpus; six tests remained ignored. All 35 browser regressions
passed with the supplied D10 fixture on source and packaged application paths.
An independent tracked-file export passed core/D10 tests and rebuilt the static
application using a new target directory. CLI D10 and `zrax/v1` batch staging
smoke checks also passed. The browser dependency is pinned by
`web/package-lock.json`, and Rust dependencies by `Cargo.lock`.
The historical manifest declares Rust 1.70; that minimum toolchain has not
been validated against the current dependency lockfile.

## Repository layout

```text
zrax-isa-workbench/
|-- Cargo.toml, Cargo.lock       native/WASM package and dependency lock
|-- build-web.sh                 static application build
|-- src/
|   |-- lib.rs, main.rs          library and zrax CLI
|   |-- types.rs, formatter.rs   classification payload and output
|   |-- formats/                container detection and parsing
|   |-- heuristics/             Markov model, scanning and model.bin
|   |-- extensions/             ISA extension detection
|   |-- batch/                  optional staging pipeline
|   |-- wasm.rs                 browser bindings
|   `-- workbench/apeiron/      vendored entropy, byte and Hilbert kernels
|-- web/                        HTML, CSS, ES modules, fonts and browser tests
|   `-- classic/                restored classifier UI and original font families
|-- tests/                      native integration and D10 regressions
|-- testbins/                   tracked binary regression fixtures
|-- examples/                   training, evaluation and inspection tools
|-- scripts/                    corpus extraction and compiler matrices
|-- docs/                       model, D10 and batch store documentation
|-- container_formats.md        extended format reference notes
|-- supplemental_isa.md         architecture reference notes
`-- dist/, pkg/, target/        generated outputs, ignored by Git
```

Large local corpora, analysis outputs, browser dependencies and build products
stay on disk but are ignored. Existing tracked regression binaries remain
versioned. The standalone repository preserves the classifier subtree's Git
history; unrelated generator/data directories remain in their original
checkout. Historical commits retain their original names and authorship.

## Provenance and licenses

First-party package metadata declares `MIT OR Apache-2.0`; this migration
retains that declaration and original authorship metadata. The repository's
historical root contained no first-party license text; the declaration is
reported as metadata rather than a claim that separate license files exist.

Vendored Apeiron code retains its [MIT license](src/workbench/apeiron/LICENSE).
Its [snapshot record](src/workbench/apeiron/README.md) identifies the source
commit, original and vendored SHA-256 hashes, and browser-specific adaptations.
The entropy snapshot includes the source working tree's existing changes.

DM Mono and Martian Mono are self-hosted with their SIL Open Font License
notices; [font provenance](web/fonts/README.md) records their source. Reference
corpora and firmware fixtures are separate inputs, rather than newly included
dependencies. Source parsers and tests are the primary evidence for the
implementation behavior described here; format reference notes may include
coverage broader than implemented raw-model classes.

## Assumption register and bounded findings

| ID | Assumption and dependent claim | Falsification probe / boundary |
| --- | --- | --- |
| A1 | The repository/folder is `zrax-isa-workbench`; package/crate/CLI/product is `zrax` | Inspect Cargo metadata, CLI help, WASM imports and displayed branding; build and run both targets |
| A2 | The application can run independently of the original checkout | Build/test a clean tracked-file export with external corpus disabled; build assets from vendored kernels |
| A3 | Browsers provide ES modules, dedicated workers, WASM, Canvas 2D and local `File` access | Startup errors and Chromium tests probe these APIs; cross-engine coverage beyond tested Chromium is unknown |
| A4 | Camera motion retains byte spatial identity | Forward/inverse Hilbert checks, pointer anchoring, pan/history/minimap and per-file viewport regressions |
| A5 | Entropy/ratio labels describe the analyzed population | Empty/uniform/padding/EOF tests and sampled/context-window tests; sampled averages are not whole-file entropy |
| A6 | D10 component conventions match observed revisions and the supplied extractor | CRC/length/ID/encoding tests and independent CPU/DSP classification; unobserved revision conventions remain unknown |
| A7 | Model confidence transfers only within demonstrated input distributions | Held-out evaluation with a separate model; examine rejected/non-code/novel-compiler cases rather than treating confidence as a universal accuracy guarantee |
| A8 | Local staging remains compatible with existing key namespaces | Retain default prefix; inspect an explicit `zrax/v1` run and verify all generated paths |
| A9 | License and attribution metadata survive migration | Compare preserved authorship, vendored notices and source hashes; first-party standalone license text remains absent |

| Impact | Finding / scope consequence |
| --- | --- |
| High | File residency can exceed the accepted file length by multiple allocations; browser memory limits govern large-file feasibility |
| High | Mixed firmware requires component-aware inference; an aggregate FPGA/DSP/CPU blob can obscure the actual CPU architecture |
| Medium | Static publication requires the complete revision-consistent module/WASM graph; partial asset replacement can break worker startup |
| Medium | The new executable/crate names require downstream imports and invocation paths to be updated; historical storage keys remain compatible |
| Medium | Offline/runtime independence does not imply training independence: rebuilding models requires separately supplied corpora/toolchains |
| Low | The larger default interface compounds browser zoom; 100% browser zoom reproduces the preferred baseline |

The verification gates require consistent names, preserved tracked content and
history, native and browser build/runtime checks, explicit measurement units,
documented external inputs, retained provenance and bounded unsupported cases.
These conditions distinguish a validated implementation from proposed batch
service designs and from untested browser/toolchain combinations.
