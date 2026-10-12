# FPGA bitstreams

`src/formats/bitstream.rs` and its submodules (`xilinx.rs`, `lattice.rs`,
`intel.rs`) recognize FPGA configuration files and keep them out of ISA
scoring, as D10 does for its FPGA component ([D10 support](d10-container.md)).
A bitstream configures programmable logic and encodes no CPU instruction
set. Each layout is parsed into the shared container model
([compressed streams and the container model](compressed-streams.md)) as an
opaque container whose configuration data is one opaque component. The
result has an unknown ISA with confidence 0, no candidates and no
extensions; the bytes never reach the code model. What the bytes establish
(header strings, sync word and bus-width pattern positions, device IDCODEs,
verified CRCs) goes into notes and `bitstream_*` metadata.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Primary source |
| --- | --- | --- | --- | --- |
| `xilinxbit` | Xilinx BIT file | 13-byte prefix `00 09 0F F0 0F F0 0F F0 0F F0 00 00 01`, keys `a` (design name), `b` (part), `c` (date), `d` (time) with 16-bit lengths, `e` with the 32-bit length of the configuration data; sync word searched in the data; 7 series packets walked when they follow UG470 syntax | Strong: the prefix and the `a` key | openFPGALoader v1.1.1 `src/bitparser.cpp` (`85be4fa0`), U-Boot v2025.10 `drivers/fpga/xilinx.c` (`e50b1e87`); no vendor document specifies the header |
| `xilinxbit` | Xilinx raw bitstream | Headerless 32-bit big-endian words: whole words of `0xFF` padding (at most 4096 B), `0x000000BB 0x11220044`, 0 to 16 dummy words, `0xAA995566`, then Type 1/Type 2 packets | Weak: the exact sequence and a valid packet stream with at least one packet | AMD UG470 v1.17 (2023-12-05), chapter 5, Tables 5-19 to 5-23 |
| `xilinxbit` | Xilinx raw bitstream, byte-swapped words | The same with every 32-bit word byte-swapped | Weak, as above | Linux v6.12 `drivers/fpga/zynq-fpga.c` (`zynq_fpga_has_sync`) |
| `latticebitstream` | Lattice iCE40 bitstream | Comment block `FF 00`, NUL-terminated strings, `00 FF`; preamble `7E AA 99 7E`; command stream walked to the wakeup command | Strong: the comment block followed by the preamble | Project IceStorm `docs/source/format.rst`, `icepack/icepack.cc` (`b77a2d5b`) |
| `latticebitstream` | Lattice iCE40 bitstream without comment block | Preamble at offset 0, then the command stream | Weak: the command stream reaches wakeup with at least one CRAM bank and a verified CRC-16 | As above |
| `latticebitstream` | Lattice ECP5/MachXO/Nexus bitstream | Optional `LSCC`, comment block `FF 00`, strings, `FF`; preamble `FF FF BD B3` (`BF`/`BE` key: encrypted); opening commands read up to `VERIFY_ID` | Strong: the comment block followed by fill and the preamble | prjtrellis `libtrellis/src/Bitstream.cpp`, `devices.json` (`a31ff704`); openFPGALoader v1.1.1 `src/latticeBitParser.cpp` |
| `intelfpga` | Intel Cyclone V raw binary file | `FF` x 0x80, `jjjj` at 0x80, option RAM at 0x84, two zero bytes at 0x124, CRC-16 at 0x126 | Weak: the complete option frame and its CRC | mistral `libmistral/cv-opt.cc` (`oram_save`), `libmistral/cv-files.cc` (`crc16`), `d509238a`; community reverse engineering |
| `intelfpga` | Intel programmer object file | `POF\0`, an unknown 32-bit word, a 32-bit packet count, packets (16-bit tag, 32-bit length, payload) to the end of the file | Strong: the magic | openFPGALoader v1.1.1 `src/pofParser.cpp`, `src/pofParser.hpp`; community reverse engineering |

Detection order: the strong checks run in `detect_format` right before the
magic-bearing compressed streams; the weak checks run right before zlib and
LZMA-alone, after every other structural detector. A Zynq boot image
(`BOOT.BIN`: width detection word `0xAA995566` at 0x20, `XNLX` at 0x24) is
never a headerless bitstream; it belongs to another family.

## Components and coordinates

All offsets are file offsets in bytes. The configuration-data component is
stored at:

- `.bit`: the declared data after the `e` key;
- headerless Xilinx: offset 0 to the end of the packet walk;
- iCE40: the preamble to the end of the wakeup command;
- ECP5 class: the preamble to the end of the file (frames are not walked);
- Cyclone V: the whole file;
- POF: the payload of each tag `0x11` packet, its 12 unknown leading bytes
  included.

Erased-flash padding (`0x00`/`0xFF`) after the end of a bitstream belongs to
the container and is noted. Any other bytes after it become a second
component, "Data after the bitstream", classified from its own bytes and
starting where the bitstream ends (padding included), because flash images
often hold processor firmware after the bitstream; only then is the
container not opaque, and an ISA found in that component is the primary
result. The configuration data itself stays opaque in every case.

## Wire units and byte order

| Layout | Units and byte order |
| --- | --- |
| `.bit` header | Big-endian 16-bit field lengths and 32-bit data length; strings stop at their first NUL |
| Xilinx configuration data | 32-bit words, big-endian (UG470), or every word byte-swapped (Zynq PCAP); packet word counts are in 32-bit words |
| iCE40 | One command byte (opcode in the high nibble, payload length in bytes in the low nibble); big-endian payloads; CRAM/BRAM banks in bits, `width * height / 8` data bytes (icepack truncates the division) followed by `00 00`; CRC-16 stored big-endian |
| ECP5 class | Opcode byte, three parameter bytes, big-endian IDCODE |
| Cyclone V | Little-endian CRC-16 |
| POF | Little-endian tags and lengths |

## Validation and resource bounds

- `.bit`: the declared configuration data must lie in the file and hold the
  sync word; duplicate `a`-`d` keys are errors; unknown keys are skipped as
  openFPGALoader skips them. A packet walk that fails (older families such
  as Spartan-6 use 16-bit packets) is a note, not an error.
- Packet walk: Type 1 and Type 2 headers with word counts checked against
  the file; reserved opcodes and Type 2 packets without a preceding Type 1
  are errors; only write packets carry data words; a dummy word ends a
  synchronized sequence; outside one, dummy, zero and bus-width words may
  precede another sync word, and any other word ends the bitstream.
- iCE40: icepack's command set (CRAM and BRAM writes, CRC reset, wakeup,
  bank number, CRC check, oscillator range 0-2, bank width, height and
  offset, boot mode bits `0x01`, `0x10`, `0x20`); other commands, payloads
  over 4 B, a missing `00 00` after bank data, or a CRC check without a
  preceding reset are errors. CRC-16/IBM-3740 (polynomial `0x1021`,
  initial value `0xFFFF`) is verified at every check command.
- Comment blocks lie within the first 16 KiB, contain no control bytes
  other than tab, CR and LF, and are reported as at most 32 strings of at
  most 256 characters. The iCE40 terminator may lie up to 16 B before the
  preamble (format.rst: a Lattice tool "moves the terminating 0x00 0xFF a
  few bytes into the comment string"). ECP5-class files allow 2 to 64 fill
  bytes before the preamble key, at most 64 dummy bytes after the preamble,
  and at most 4 opening commands before `VERIFY_ID`.
- Cyclone V: the fill, the marker, the zero bytes and the CRC-16/MODBUS over
  0x84..0x126 must all match.
- POF: every packet must lie in the file; a packet count that differs from
  the packets present is a note, because the field's meaning is not
  established.
- Not verified: the Xilinx configuration CRC (UG470 does not state the
  polynomial), ECP5-class frame CRCs (frames are not walked), the POF tag
  `0x08` value ("maybeCRC" in openFPGALoader). Notes say so.
- Every loop advances by at least one byte or word, so parsing is linear in
  the input; nothing is allocated from a declared size.

## Device identification

Device names come only from IDCODEs the stream writes or verifies: UG470
Table 1-1 for 7 series IDCODEs (revision nibble ignored; the XC7V2000T is
left out because its IDCODE has further don't-care bits) and prjtrellis
`devices.json` for ECP5. Other IDCODEs are reported without a name. iCE40
files carry no IDCODE; the CRAM geometry is reported with the chip type
icepack names for it (`384`, `1k`, `8k`, `5k`, `u4k`, `lm4k`). Part strings
in `.bit` headers, comments and POF packets are reported verbatim and never
mapped to a device.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| B1 | `.bit` keys other than `a`-`e` may appear and have 16-bit lengths (openFPGALoader); U-Boot requires the order `a`-`e` | A Vivado or ISE `.bit` with another key before `e` |
| B2 | A dummy word never appears inside a synchronized sequence (type `111` is not a packet) | Walk Vivado multiboot, compressed and encrypted bitstreams to the end |
| B3 | Read and NOOP packets carry no data words in a stream | A bitstream with a readback or `-readback` option |
| B4 | UltraScale and UltraScale+ share the sync word and packet syntax (not checked against UG570) | Walk an UltraScale `.bin` as a headerless bitstream |
| B5 | Tool comment blocks contain no control bytes besides tab, CR and LF, and fit in 16 KiB | iCEcube2, Diamond and Radiant `.bin`/`.bit` outputs |
| B6 | `VERIFY_ID` follows at most `SPI_MODE` and `LSC_RESET_CRC` after the dummy bytes | Diamond and Radiant outputs for MachXO2/3 and Nexus |
| B7 | Cyclone V `.rbf` files begin with `FF` x 0x80, `jjjj` and the mistral option-frame CRC | Quartus-generated Cyclone V `.rbf`, compressed and uncompressed |
| B8 | POF files start with `POF\0`, are little-endian and consist of packets to the end of the file | Quartus `.pof` files for MAX 10 and configuration devices |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Intel `.sof` | Not recognized: no public layout or parser was found |
| Intel Arria 10, Cyclone 10, Stratix `.rbf` | Not recognized: Linux `socfpga-a10.c` reads Arria 10 encryption and compression flags but gives no structure to recognize the file by |
| Cyclone V option frame fill, PRAM and CRAM frames | Not walked: their sizes come from per-device tables that the file does not encode |
| ECP5-class files without a comment block | Not recognized: full validation needs per-device frame sizes |
| iCE40 multi-boot images (icemulti: boot address and reboot commands) | Not recognized as a bare bitstream; icepack rejects them too |
| Bit-reversed SelectMAP Xilinx files | Not recognized |
| Headerless Spartan-6 and older Xilinx files | Not recognized; their `.bit` files are, with a note that the packet walk did not apply |
| Encrypted or compressed configuration data | Recognized; contents are opaque and not decoded |
| Xilinx `BOOT.BIN` | Not claimed; another family parses it |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`tests/bitstream.rs` (18 tests: positive cases per layout and word order,
corrupted fields and CRCs, Zynq boot image exclusion, trailing data, an
every-prefix truncation sweep and a four-way byte-mutation sweep over every
fixture) passed, with 18 unit tests in the module and a CRC-16/IBM-3740
check-value test in `src/formats/checksum.rs`. The browser test
`web/tests/bitstream.test.mjs` (4 tests through `/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`) passed. All
fixtures are synthetic, built in the tests from the documented layouts with
synthetic configuration data. No vendor or open-source tool was available
locally (`icepack`, `ecppack`, Vivado and Quartus were not installed), so
recognition of tool-generated files is not verified.
