# ARM Image Format (AIF)

`src/formats/aif.rs` parses ARM Image Format images, the executable format
of the ARM Software Development Toolkit (`armlink -aif` and `-aif -bin`,
`fromelf -aif`; `.axf` and `.aif` files) and of RISC OS applications
(`!RunImage`), into the shared container model
([compressed streams and the container model](compressed-streams.md)).
The read-only and read-write areas are load sections that the code model
classifies under the header's target; debugging data, compressed data and
the relocation data of non-executable images are opaque components.

AIF is not ARM Object Format: AOF (`src/formats/aof.rs`, the "Legacy
objects" group) is a chunk file that starts with `C5 C6 CB C3`, while an AIF
image starts with ARM instructions. The two share the `.axf` extension in
some toolkits; the format, not the file name, decides.

"ARM Image Format (AIF) is a simple format for ARM executable images" (ARM
DUI 0041C, section 13.1), and the header itself is ARM code: an executable
image "can be loaded at its load address and entered at the same point (at
the first word of the AIF header)" (section 13.2). The format is therefore
the image's target field, and every image is reported as ARM, 32-bit, with
the byte order of its header. Thumb code linked into an image is still
reported as ARM.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `armaif` | `Executable AIF`: the 128-byte header is part of the image; word 0xC is `BL ImageEntryPoint` (most significant byte 0xEB); the read-only area starts at file offset 0 and its size includes the header | Strong: header instructions (below) | ARM, 32-bit, header byte order | DUI 0041C sections 13.2, 13.3, Table 13-1 |
| `armaif` | `Non-executable AIF`: a loader interprets the header, which is not part of the image; word 0xC is the entry offset from the image base (most significant nibble 0); the read-only area starts at 0x80 and is loaded at the image base | Strong: as above | As above | DUI 0041C section 13.2; ARM "ARM Image Format" text |
| `armaif` | `Extended AIF`: a non-executable, scatter-loaded image whose word at 0x38 is the file offset of the first non-root load region header (next region offset, load address, size, 32-byte name; 44 B), each followed by its data | Strong: as above, with word 0x38 non-zero | As above | DUI 0041C section 13.2 and Table 13-1 (row 0x38) |

Compression and self-relocation are properties of any variant, read from
the header words:

| Header word | Meaning | Handling |
| --- | --- | --- |
| 0x0 `BL DecompressCode` | Compressed image: header, compressed image, decompression data, decompression code ("In a compressed AIF image, the header is not compressed") | Executable: the bytes from 0x80 to the BL target are an opaque `Compressed image` component; the decompression code from the BL target to the end of the file is a load section (`Decompression code`), since it is plain ARM code the image runs first. Non-executable: everything after the header is opaque. The header sizes describe the decompressed image and are only reported |
| 0x4 `BL SelfRelocCode` | Self-relocating image: the relocation code is "added to the end of an AIF image by the linker, immediately before the list of relocations" (terminated by -1) | Executable: the BL target must lie after the image and inside the file, with only padding before it; the code and list from there to the end of the file are a load section (`Self-relocation code`). Relocations are not applied. Non-executable (relocated by the loader): the bytes after the image are an opaque `Relocation data` component |
| 0x8 `BL ZeroInit` / `BL DBGInit` | Zero-init or debugger initialization code | Encoding checked only |

Sources, all retrieved on 2026-10-13:

| Tag | Document | Location | SHA-256 |
| --- | --- | --- | --- |
| DUI 0041C | ARM DUI 0041C, *ARM Software Development Toolkit Version 2.50 Reference Guide*, issue C (November 1998): chapter 13 "ARM Image Format" (13.1 overview, 13.2 variants, 13.3.1 layout, 13.3.2 debugging data, 13.3.3 Table 13-1), section 6.4.2 (linker output formats), section 12.8 (`SWI_Exit` is 0x11) | `https://documentation-service.arm.com/static/604f2c8aefb1a112dce66ba1` (3,657,417 B) | `d687c8ead99124adee4590622edec2bfb0c00c44b764d06a8286138ddf18591d` |
| ARM AIF text | ARM Ltd, "ARM Image Format" (SDT-era specification; "reserved to ARM Ltd"): compressed layout, `BL DecompressCode`, debug initialization instruction at 0x40, self-move and self-relocation code | `https://www.chiark.greenend.org.uk/~theom/riscos/docs/CodeStds/AIF-1993.txt` (16,848 B) | `30d4e26fb2af9f2543f42dfa66932d1c68a4e9053f7bf438adf9dc36359872bd` |
| PLG-AIF | Acorn Computers, technical memorandum PLG-AIF issue 1.00, "RISC OS Application Image Format (previously Arthur Image Format)", 23 January 1989: `BLNV 0` as the header NOP, the header sizes and linker symbols | `https://www.chiark.greenend.org.uk/~theom/riscos/docs/CodeStds/AIF-1989.txt` (18,345 B) | `215e1fab22706598975e01bb5181fd6aee6761ba30aba1aeb7ab800380b30436` |
| PRM | RISC OS Programmer's Reference Manual, volume 4, appendix D "Code file formats", AIF (HTML edition; the header table is an image there) | `discmaster.textfiles.com`, *Risc OS Programmer's Reference Manuals* ISO, `HTML/PRM/OBJECTFORMAT.HTML` | `d0ecf95accf99b95480306f4b691083ad10a3ff2b42e6d10d664462961973bfe` |

### Header

| Offset | Field | Read as |
| --- | --- | --- |
| 0x00 | `BL DecompressCode` or NOP | NOP (`MOV r0, r0`, `0xE1A00000`), `BLNV 0` (`0xFB000000`, the 1989 memo's NOP) or BL (`0xEBxxxxxx`) |
| 0x04 | `BL SelfRelocCode` or NOP | As above |
| 0x08 | `BL ZeroInit` (`BL DBGInit/ZeroInit`) or NOP | As above |
| 0x0C | `BL ImageEntryPoint` or entry offset | BL: executable; below `0x10000000`: non-executable or extended |
| 0x10 | Program exit instruction | `SWI 0x11` (`0xEF000011`, armlink's default) or `B .` (`0xEAFFFFFE`, the recommended branch-to-self) |
| 0x14 | Image read-only size | Includes the header only for executable AIF |
| 0x18 | Image read-write size | "Exact size (a multiple of 4 bytes)" |
| 0x1C | Image debug size | As above |
| 0x20 | Image zero-init size | As above; not stored in the file |
| 0x24 | Image debug type | Bits 0-3: 0 none, 1 low-level, 2 source-level (ASD), 3 both |
| 0x28 | Image base | Address the image (code) was linked at |
| 0x2C | Work space | Self-move work space (obsolete in SDT 2.50); reported when non-zero |
| 0x30 | Address mode | 0 (old-style 26-bit header), or 26 or 32 in the least significant byte; bit 8: separate data base |
| 0x34 | Data base | Address the read-write area was linked at, when bit 8 is set |
| 0x38 | Reserved (initially 0) | Extended AIF: first region header offset; otherwise a non-zero value is noted |
| 0x3C | Reserved (initially 0) | A non-zero value is noted |
| 0x40 | NOP or debug initialization instruction | Not checked |
| 0x44 | Zero-init code (15 words in DUI 0041C, 14 in the ARM text) | Not checked: armlink accepts a custom header template (`AIF_HDR`) |

The read-write area is loaded at the data base when address mode bit 8 is
set, and at image base + read-only size otherwise (PLG-AIF: `ImageBase +
ROSize = Image$$RW$$Base`). The entry point is image base + the target of
the BL at 0xC (executable) or image base + the offset at 0xC
(non-executable). A branch target is the BL's own offset + 8 + the signed
24-bit word offset × 4 (the ARM instruction encoding, not an AIF source).

Detection order in `formats::detect_format`: the check runs after the
Psy-Q objects and before the magic-bearing compressed streams, so before
the kernel images too. No earlier format starts with ARM instructions at
offset 0 and an exit SWI at 0x10; the Arm zImage, which also starts with
NOPs, has eight of them and no exit instruction at 0x10 (and is checked
later).

## Wire units and byte order

All offsets and sizes are bytes; addresses are ARM byte addresses. Every
header word is in the target byte order (DUI 0041C section 13.2: "The most
significant byte of this word (in the target byte order) is 0xeb"; Table
13-1, 0x30: "using the byte order appropriate to the target"). The byte
order is the one in which the word at 0x10 is an exit instruction, and
it is reported as the code byte order. The code model is not asked for
it; when it disagrees, the generic container path warns ("Header byte
order is big; the loaded code classifies as little"). Section and
component offsets are file offsets; section addresses are destination
addresses.

## Validation and resource bounds

- Detection needs the complete 128-byte header, an exit instruction at
  0x10, NOP or BL in words 0x0 to 0x8, a BL or an entry offset below
  `0x10000000` at 0xC, a debug type of 3 or less, an address mode of 0
  or 26 or 32 in its least significant byte, and, for executable AIF, a
  read-only size of at least 128 B. Everything else is checked by the
  parser, so a damaged image is a parse error and not raw code.
- The read-write, debug and zero-init sizes must be multiples of 4.
- The read-only area, the read-write area and the debugging data must lie
  inside the file, in that order; a truncation names the area and its
  offset.
- A BL to the decompression code must land after the header inside the
  file; a BL to the self-relocation code (executable images) after the
  image inside the file, with only `0x00`/`0xFF` bytes in between.
- Without self-relocation, bytes after the image may only be `0x00` or
  `0xFF` (noted with their size); anything else is a parse error.
- Extended AIF region headers must lie at or after the end of the root
  image's read-write area and inside the file, sizes must be multiples of
  4, and each data block must fit the file. A chain that links a region
  header twice is an error. At most `MAX_COMPONENTS` (4,096) regions are
  listed; the rest are not followed and a note says so.
- Load sections borrow the input and are concatenated for the code model
  only up to `MAX_PAYLOAD` (64 MiB); an area that would exceed it is noted
  and not analyzed. Nothing is decoded or allocated from a header count.

## Notes and metadata

Notes give the variant and header byte order, the ISA rule, the image base
and entry point (with the BL or offset it comes from), the address mode
(26-bit, 32-bit or old-style, the separate data base, undocumented flag
bits), the debug type and size (and a disagreement between them), the exit
instruction, non-zero reserved words, where the areas lie and the
zero-initialized size, an entry point outside the read-only area, and the
compression, self-relocation, work space, region and padding findings.
Metadata keys are `aif_image_base`, `aif_entry_offset`, `aif_read_only_size`,
`aif_read_write_size`, `aif_debug_size`, `aif_zero_init_size`,
`aif_debug_type` (the whole word), `aif_address_mode`, `aif_data_base` (with
bit 8), `aif_work_space` (when non-zero) and `aif_exit_instruction`, plus
the generated `aif_image_size`, `aif_section_N` and `aif_component_N`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | The header byte order is the code byte order | DUI 0041C sections 13.2 and Table 13-1 state the target byte order for the header words; `the_header_byte_order_wins_over_the_code_model_with_a_warning` pins the warning when code disagrees. No big-endian AIF produced by ARM's tools was available: big-endian images are verified only against synthetic fixtures |
| A2 | Big-endian AIF code is word-invariant (BE32) and reported as `big` | SDT 2.50 predates BE8 (ARMv6). A BE8 image (little-endian instructions, big-endian data) would draw the byte-order warning |
| A3 | The DUI 0041C sentence "Bits 0-3 hold the type. Bits 4-31 hold the low level debug size", printed in the debug size row, describes the debug type word at 0x24 | In the four valid IDA samples the whole word at 0x1C (0x274, 0x2870) is exactly the number of bytes from the end of the read-write area to the end of the file, so it is a size, while the word at 0x24 has type 3 in bits 0-3 (0x1E03, 0x1EF83). Only bits 0-3 are interpreted; bits 4-31 are reported in `aif_debug_type` but not read as a size |
| A4 | An exit instruction at 0x10 is `SWI 0x11` or `B .` | Table 13-1 allows any value through a custom `AIF_HDR` template. An image with another exit instruction is not recognized and falls to the code model |
| A5 | Words 0x0 to 0x8 are NOP or BL on disk | The sources allow only BL or NOP; the debugger and decompressor rewrite them only in memory. `arm_wrong_debuginfo.axf` (IDA) has zero words at 0x8 to 0x13 and is not recognized |
| A6 | Extended AIF regions follow the root image's read-write area, and the debugging data is not placed by the sources | Neither DUI 0041C nor the ARM text places the debugging data of an extended image; it is not located, and the bytes after the regions are then not checked (noted). No extended AIF sample was available: verified only against synthetic fixtures |
| A7 | The decompression code runs from the BL target to the end of the file | The ARM text's compressed layout ends with the decompression code. No compressed AIF sample (RISC OS `squeeze` output) was available |
| A8 | The self-relocation code and relocation list run from the BL target to the end of the file | The layout ends with them; whether the file always ends with the list's -1 word is not checked. No self-relocating sample was available |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Compressed images | The compressed data is opaque; no decompressor is implemented (the compression scheme is not documented in the sources). The read-only, read-write and debug areas of the decompressed image are not located |
| Relocations | Not applied; the relocation code and list are analyzed as stored |
| Debugging data (ASD, low-level symbols) | Opaque; not parsed. Damaged debug tables (IDA's `arm_bad_nsyms.axf`, `arm_wrong_debugsize.axf`) therefore classify normally |
| Zero-init code and debug initialization instruction | Not checked against the documented sequences |
| Thumb code in an image | Reported as ARM; the format records no Thumb marker |
| Images with a custom exit instruction | Not recognized (A4) |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/aif.rs` (23
tests) and the module's unit tests (4) passed, with every-prefix sweeps
over an executable, a big-endian non-executable and an extended image, and
every-byte mutation sweeps (`0x00`, `0xFF`, two bit flips) over an
executable, a big-endian extended, a compressed and a big-endian
self-relocating image. All fixtures are synthetic, built in the tests from
Table 13-1 around clang-compiled ARMv4T code (`tests/fixtures/aif/`). With
`IDA_INPUT_DIR` set to IDA Pro's test inputs, the gated test also passed:
`arm_jump.axf`, `arm_bad_nsyms.axf`, `arm_wrong_debugsize.axf` and
`arm_rantest.axf` report `armaif` (`Executable AIF`), ARM, 32-bit,
little-endian, entry point 0x8080, with a read-only area of 200 B (16,036
B and a 544 B read-write area for `arm_rantest.axf`) and opaque debugging
data that ends the file; `arm_bad_data_segm.axf` (debug size 0x273),
`arm_bad_file.axf` (read-only size 15,532,104 B in a 128 B file) and
`arm_huge_dataseg.axf` (read-write size 0xFFFFFFFF) are parse errors;
`arm_wrong_debuginfo.axf` is not recognized (A5); every prefix of
`arm_jump.axf` is an error and its byte inversions do not panic. Before
this change five of the seven samples were inconclusive, and
`arm_bad_file.axf` and `arm_rantest.axf` classified as raw ARM code. Those samples are read in place and not
redistributed; without the variable the test skips.
The whole native suite (`cargo test --all-features --locked`) passed 1,868
tests with 6 ignored. After `./build-web.sh`, `web/tests/aif.test.mjs` (4
tests) passed through `/pkg/zrax.js`, `/dist/zrax.js` and both workbench
pages; the other browser tests were not run. Big-endian, non-executable,
extended, compressed and self-relocating images are not verified against
files produced by ARM's or Acorn's tools.

After integration with the families added since (partition tables through
Psy-Q objects, PE ARM64EC detection) on the same day, the native suite
passed 1,874 tests with 6 ignored and the gated test passed again. On
IDA's corpus (4,621 files), `arm_bad_nsyms.axf`, `arm_jump.axf` and
`arm_wrong_debugsize.axf` went from inconclusive to ARM,
`arm_bad_data_segm.axf` and `arm_huge_dataseg.axf` from inconclusive to
parse errors, and `arm_bad_file.axf` from ARM (code model) to a parse
error; no other file changed.
