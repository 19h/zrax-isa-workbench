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
| Classification | Format, ISA, bit width, byte order, confidence/source, extensions, ranked raw-code candidates, labelled architecture slices, metadata and notes |
| Entropy | Hilbert/linear layouts, entropy/byte-class palettes, continuous pointer-anchored zoom, drag pan, minimap, fit and previous/next viewport history |
| Inspector | Synchronized byte location, local entropy, byte histogram and measured DEFLATE ratio |
| Hex | Virtual rows, 8/16/24/32 columns, 1/2/4/8-byte groups, hex/decimal offsets, goto, byte selection and integer/floating-point decoding |
| Text decoding | ASCII, Latin-1, CP437, EBCDIC CP037 and UTF-16; byte order override |
| Exports | Classification JSON, batch JSON/CSV, selected bytes, clipboard hex |
| Batch overview | Status filters, insertion/name/size/confidence/entropy sorting, architecture/format tallies and progress |
| Interface | Responsive file panel and inspectors, log, status bar, context menu, keyboard navigation and persistent UI preferences |

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
| Executables and objects | ELF, PE/COFF, Mach-O and fat Mach-O, XCOFF, ECOFF, a.out, DOS MZ/NE/LE/LX, PEF, bFLT |
| Legacy objects and operating systems | OMF, SOM, ARM AOF, Symbian EPOC, Palm PDB/PRC, Amiga Hunk, Turbo Debugger symbols, OS-9, GOFF |
| Virtual machines | WebAssembly, Java class, DEX/ODEX/VDEX/ART, LLVM bitcode |
| Archives and boot images | ar variants, FatELF, Linux x86/Arm/AArch64/RISC-V kernel images, U-Boot uImage (single and multi-file) and FIT, DTB; compressed kernel payloads are decoded |
| Consoles and DSP | XBE, XEX, PlayStation SELF variants, Switch NSO/NRO, GameCube/Wii DOL, SNES SPC, NSF/NSFe, C64 SID, GBS ([chiptune](docs/chiptune.md)), ZX Spectrum TZX/TAP ([tapes](docs/zx-tapes.md)), Mega Drive/Genesis ROMs, PS-X EXE, Dreamcast IP.BIN, Wii U RPX/RPL, 3DS NCCH/3DSX, PSP EBOOT.PBP ([console images](docs/retro.md)), Nintendo DS/DSi, Game Boy Advance, Game Boy/Color, iNES/NES 2.0, SNES (LoROM/HiROM/ExHiROM internal header), Nintendo 64 .z64/.v64/.n64 ([Nintendo ROMs](docs/nintendo-roms.md)), TriMedia objects, Motorola DSP LOD |
| Firmware and loader text | Espressif ESP32-family and ESP8266 (v1/v2) application and bootloader images (chip ID names Xtensa LX6/LX7 or RISC-V; checksum, SHA-256 and CRC-32 verified; data segments opaque) and ESP flash dumps (ESP-IDF partition table at 0x8000 with MD5 verified; bootloader and partitions classified on their own) ([Espressif](docs/esp.md)), Blackfin LDR boot streams ([LDR](docs/blackfin-ldr.md)), PCI and legacy option ROMs ([option ROMs](docs/option-roms.md)), Huawei UPDATE.APP packages ([Huawei](docs/huawei-update.md)), Intel HEX, Motorola S-record, TI-TXT, TI ASCII Hex, TI SDSMAC tagged, Extended Tektronix, CCS GO DSP data |
| Texas Instruments firmware | C28x/C54x/C55x/C3x/C4x and unkeyed boot tables, AIS, RPRC, MCU+ and mmWave appimages, multicore ELF, GP/OMAP images, OAD, TI X.509 wrappers, MCUboot, TF-A FIP |
| Specialized containers | OLS, EPR, SGO, VBF, FRF, BCF, SOX, AOR D10, ASAM ODX-F, Honda RWD, Toyota CUW, Mercedes CFF ([automotive](docs/automotive.md)) |
| Apple images | IMG4 and IM4P (stored, LZFSE and complzss/complzvn payloads decoded and classified; keybag-encrypted payloads opaque), IM4M manifests and IM4R restore info as metadata, dyld shared caches (architecture token, mappings, Mach-O images mapped into the file) ([Apple images](docs/apple.md)) |
| Android images | Boot images (`ANDROID!` header v0-v4: kernel/ramdisk decoded and classified, second stage, recovery DTBO, DTB, v4 signature, AVB footer, mkbootimg SHA-1 ID checked), vendor_boot v3/v4 (ramdisk table, DTB, bootconfig), sparse images (RAW/FILL/DONT_CARE/CRC32 expanded to one partition image, CRC32 verified, 64 MiB cap), OTA `payload.bin` (`CrAU` v1/v2, protobuf manifest, full operations reassembled per partition with SHA-256 checks; delta partitions opaque), bootloader packs (Qualcomm and ASUS `BOOTLDR!`, Qualcomm meta image, FBPK v1/v2). No header names a CPU; members are classified from their own bytes ([Android](docs/android.md)) |
| SoC boot ROM images | Allwinner eGON.BT0 (checksum, A32/RISC-V jump word as entry ISA) and TOC0 (items opaque); Rockchip RKFW, RKAF, RKBOOT (RC4-descrambled entries) and idbloader v1/v2; MediaTek EMMC/SF/SDMMC/UFS_BOOT, BRLYT and GFH; Qualcomm 80-byte SBL and 40-byte v3 MBN ([SoC loaders](docs/socboot2.md)); Xilinx Zynq-7000/ZynqMP `BOOT.BIN` (boot header, image header table and partition checksums verified; partitions as slices with destination-CPU targets; bitstream and encrypted partitions opaque), NXP i.MX HAB IVT images and i.MX 8/9 AHAB containers (no ISA field; the code model classifies the application; DCD, CSF and signatures opaque), NXP SB2.0/2.1/3.1 secure binaries (metadata only; SB3.1 hash chain verified, signatures not verified) ([SoC boot images](docs/socboot.md)) |
| MCU update images | UF2 (family ID names the ISA for 78 listed families; blocks reassembled by address; multi-family files split per family), STM32 DfuSe (DFU suffix CRC-32 verified), Silicon Labs GBL v3 (program/LZ4/LZMA tags, end-tag CRC-32 verified; encrypted files opaque), Cypress `.cyacd`/`.cyacd2` ([MCU images](docs/mcu.md)) |
| FPGA bitstreams | Xilinx `.bit` and headerless configuration data (both word orders), Lattice iCE40 and ECP5/MachXO/Nexus, Intel Cyclone V `.rbf` and `.pof`; recognized and excluded from ISA scoring ([FPGA bitstreams](docs/bitstream.md)) |
| Compressed streams | gzip, zlib, xz, LZMA-alone, LZ4 (frame and legacy), Zstandard, bzip2, lzop, LZFSE/LZVN, Apple LZSS kernelcaches; decoded and classified by their content |
| ZIP, tar and CPIO | ZIP (ZIP64; stored, deflate, bzip2, LZMA, Zstandard and xz members with CRC-32 verified; APK, JAR, IPA, Nordic DFU and PDX labels), tar (ustar, pax, GNU), CPIO (newc, crc, odc, old binary) ([archives](docs/archives.md)); members classified on their own bytes |
| Filesystem images | SquashFS 4.0 (gzip, LZMA, LZO, xz, LZ4, zstd), CramFS (both byte orders, CRC-32 verified) and romfs, with recognized regular files listed by path; SquashFS 1.x-3.x, big-endian and streamed images recognized but not enumerated ([read-only filesystems](docs/rofs.md)); ext2/ext3/ext4 (32/64-bit group descriptors, `meta_bg`, `flex_bg`, block maps and extent trees, linear and htree directories; `metadata_csum` and `gdt_csum` verified; regular files in a recognized format listed by path) ([ext](docs/ext.md)) |
| Flash filesystems | UBI (erase-counter and VID headers, PEB size discovery, volume table, static and dynamic volumes), UBIFS (node scan, LZO/zlib/Zstandard data) and JFFS2 in both byte orders (zlib, LZO, rtime, rubin, OpenWrt LZMA); recognized files are listed with full paths ([flash filesystems](docs/mtd.md)) |
| UEFI and PC flash images | UEFI PI firmware volumes and flash device images (FFS files; compressed, GUID-defined LZMA/LZMA F86/Tiano/Brotli/CRC32 and nested volume sections; per-image PE32 and TE machines), standalone TE images, Intel flash descriptor images (region map, BIOS-region volumes; ME and other regions opaque) ([UEFI](docs/uefi.md)) |
| coreboot and Chromium flash images | Chromium FMAP flash images (map at offset 0 or found by search; ME/IE and data areas opaque) and coreboot CBFS regions and legacy ROMs; stages and payload segments decoded (LZMA, LZ4), SHA-2 file hashes verified ([coreboot](docs/coreboot.md)) |
| Router firmware wrappers | Broadcom TRX v1/v2 (CRC-32 verified; loader, kernel and root filesystem partitions), Netgear CHK (all four checksums verified), D-Link SEAMA entities and seals (MD5 not verified), TP-Link mktplinkfw v1, mktplinkfw2 v2/v3 and SafeLoader factory images (weak structural detection; MD5 not verified); raw OpenWrt LZMA kernels decoded and classified; no header names an ISA ([router firmware](docs/router.md)) |
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
