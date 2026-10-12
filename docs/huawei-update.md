# Huawei UPDATE.APP packages

`src/formats/huawei.rs` splits Huawei `UPDATE.APP` firmware packages into
their partitions. Huawei publishes no specification; the layout follows the
open-source splitter `split_updata.pl` at commit `7f318240`
(`data_structure`, `splitupdate`).

| JSON format ID | Layout | Recognition |
| --- | --- | --- |
| `huaweiupdate` | 92 zero bytes, then 4-byte-aligned entries: magic `55 AA 5A A5`, header length (u32 LE), unknown word, hardware ID (8 B), file sequence (4 B), data size (u32 LE), date, time, partition type and blank fields (16 B each), header checksum, block size and blank (u16 each), per-block data checksums filling the rest of the header, then the partition data | Strong: entry magic after the zero prefix, or at offset 0 |

Each partition is a child labelled with its partition type and classified
on its own bytes (Android boot images, sparse or ext images, raw
bootloaders). The package names no CPU. The per-block checksums are
reported as not verified; the splitter's own checker is an external tool
whose algorithm is not documented in the pinned source. Entries are capped
at 4096.

Verification: on 2026-10-12 (macOS AArch64), `tests/huawei.rs` (2 tests,
synthetic packages with truncation and mutation sweeps) passed. No Huawei
package was available.
