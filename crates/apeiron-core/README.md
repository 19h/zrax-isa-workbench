# apeiron-core

Apeiron's analysis and visualization core, vendored for the zrax desktop
workbench.

| | |
| --- | --- |
| Upstream | <https://github.com/19h/apeiron> |
| Commit | `61051c4a63bd93cc057f3dc3cf71a22ef2b141c4` |
| License | MIT (`LICENSE`, copied from upstream) |
| Vendored on | 2026-11-10 |

## What is here

| Path | Upstream path | Changes |
| --- | --- | --- |
| `src/analysis/` | `src/analysis/` | none |
| `src/hilbert/curve.rs` | same | none |
| `src/hilbert/refiner.rs` | same | `Arc<Mmap>` replaced by `Arc<[u8]>`; `memmap2` import removed |
| `src/viz/` | `src/viz/` | `eframe::egui::{Color32, Vec2}` imported from `crate::compat` |
| `src/util/` | `src/util/` | `eframe::egui::Color32` imported from `crate::compat` |
| `src/gpu/` | `src/gpu/` | `Arc<Mmap>` replaced by `Arc<[u8]>`; `memmap2` import removed |
| `src/background.rs` | `src/app/background.rs` | imports point at `crate::types` |
| `src/types.rs` | parts of `src/app/types.rs` | the sample intervals, `ByteLayout`, `VisualizationMode` (without `world_dimension_for_layout`, which needs the application's `FileData`), `BackgroundTask` and `BackgroundTasks` |
| `src/compat.rs` | new | stand-ins for egui's `Color32` and `Vec2` |
| `src/lib.rs` | new | module list; the `gpu` module is behind the `gpu` feature |

Not vendored: the egui application (`src/main.rs`, `src/app/state.rs`, the
rest of `src/app/types.rs`), examples, benchmarks and papers.

The library is named `apeiron`, as upstream, so upstream's doc examples build
unchanged. The workspace's lints are switched off for this crate: the files
are kept as published so they can be diffed against upstream.

## Updating

Copy the upstream directories again, re-apply the changes in the table
(`git diff` against this directory shows them), update the commit above, and
run:

```sh
cargo test -p apeiron-core                 # 65 tests
cargo test -p apeiron-core -- --ignored    # 2 tests that need a GPU adapter
```
