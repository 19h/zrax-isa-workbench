## Added Sample Provenance

This documents how the new samples in `testbins/` were derived from the
original firmware blobs in `~/Downloads`.

The goal is to keep regression fixtures deterministic and strongly
architecture-representative.

| Testbin file | Source file | Extraction |
|---|---|---|
| `arm32_le_ezviz-doorbell.bin` | `CS-DB1-A0-1B3WPFR.dav` | skip `0x100`, keep `64 KiB` |
| `arm32_le_unknown-fw.bin` | `unkn.bin` | offset `0x181588`, size `1024` |
| `arc_le_unknown-fw.bin` | `134` | offset `0x54000`, size `4096` |
| `superh_le_unknown-fw.bin` | `C1010101_.BIN` | offset `0x180000`, size `16384` |
| `rh850_le_vw-igw.bin` | `2129025811_001.cff` | offset `0x0`, size `16384` |
| `arc_le_sps-operational.bin` | `SpS/SPSOperational.bin` | offset `0xDF3A0`, size `384` |
| `mips32_le_linux-kernel.bin` | `kernel.bin` | offset `0x1160000`, size `63936` |
| `ia64_le_ftpm-efi.bin` | `rom2.efi` | full file copy |

Notes:
- `fTPM_mod.bin` was dropped because it was a compressed/invalid wrapper.
- `rom2.efi` is the uncompressed replacement and classifies as IA-64 via PE/COFF.
