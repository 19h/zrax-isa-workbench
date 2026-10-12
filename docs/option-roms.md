# Option ROMs

`src/formats/optionrom.rs` recognizes PCI expansion ROMs and legacy ISA
option ROMs. Each image's code type is an explicit target field.

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `pcioptionrom` (PCI) | Chained images, each `55 AA` with a pointer at 0x18 to a `PCIR` data structure (vendor, device, image length in 512-byte units, code type, last-image bit) | Strong: `55 AA` and a `PCIR` signature | PCI Firmware Specification 3.0, section 5.1 |
| `pcioptionrom` (EFI images) | EFI ROM header: `0x0EF1`, subsystem, PE machine, compression type, PE image offset | Within a PCI ROM | UEFI Specification 2.10, section 14.4.2 |
| `pcioptionrom` (legacy) | `55 AA`, size in 512-byte units, entry jump; byte sum of the image is zero | Weak: checksum, then only padding | PCI Firmware Specification 3.0, section 5.1.1 |

Targets by code type: 0 is x86 real-mode code (`x86`, 16-bit), 2 is HP
PA-RISC, 3 is EFI (the PE machine, cross-checked by the PE image's own
header), and 1 is Open Firmware FCode, a bytecode with no ISA (opaque).
x86 and PA-RISC images start with the ROM header, so they go straight to the
code model (`Classify::Code`) instead of being parsed as nested ROMs. The x86
image checksum is verified and reported.

EFI images with compression type 1 hold the PE image in the UEFI
compression format (UEFI 2.10, chapter 19). They are decoded with the
shared EFI codec ([UEFI](uefi.md)), and the decoded PE image is classified;
the format has no checksum, so the note says no integrity check was made. A
stream that does not decode, and any other compression type, is listed as
opaque with the reason.

Known boundaries: ROMs larger than 4096 images stop there.

Verification: on 2026-10-12 (macOS AArch64), `tests/optionrom.rs` (4 tests,
synthetic ROMs with truncation and mutation sweeps) passed. On 2026-10-13
(macOS AArch64, rustc 1.100.0-nightly) its 6 tests passed, including a
hand-built EFI literal stream; with `EFI_ROM_DIR=/opt/homebrew/share/qemu`
all 8 `efi-*.rom` iPXE ROMs that QEMU ships classified as PCI option ROMs
whose EFI image decoded to x86-64 code. Without `EFI_ROM_DIR` that test
skips.
