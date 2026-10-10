# Apeiron kernel snapshot

Source: `/Users/int/dev/apeiron` working tree, 2026-10-11.
Base commit: `0b0715d2712c4288c8be14fa26e82f09cc8ff477`. The entropy file contains pre-existing local changes; this snapshot deliberately includes them. Apeiron itself was not modified.

The entropy and byte kernels retain the four-way histograms, exact count-logarithm lookup table, and `wide` portable vector operations. Rayon iterators use serial iterators in a dedicated browser worker. The wide-histogram parallel reduction uses its equivalent serial fold. Hilbert mapping retains the original forward/inverse lookup tables.

| Original file | Original SHA-256 | Vendored SHA-256 |
| --- | --- | --- |
| `src/analysis/entropy.rs` | `0992cc38a070717ef24eaf85b8e7d9d50dde5cfd4046f87a985a064dd5389551` | `039c092d430dd4539e2debcb1d8d466e6b7496a314784b50bfdf058543d9bb5a` |
| `src/analysis/byte.rs` | `ac961c94f20df65a46fc090e7a890e296d21c96972bb5c82fbcaed4b6f7d8dfd` | `ac961c94f20df65a46fc090e7a890e296d21c96972bb5c82fbcaed4b6f7d8dfd` |
| `src/hilbert/curve.rs` | `444343de5448081a0d90cb0021c7ff910ac686e62fdadc9fb290ddb0c8220e57` | `bdb55d953c8e109841f9ba92b4743b41c29fae7ae977b083b01141f11e9c02ad` |


Apeiron's MIT license is reproduced in `LICENSE`. Its GUI, file dialogs, memory mapping, GPU renderer, and native XZ/Zstd tier selection are not dependencies of this browser build. The workbench's labeled DEFLATE ratio uses `miniz_oxide` and is a separate compression proxy, not an Apeiron XZ/Zstd result.
