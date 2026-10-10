# ISA Workbench

The reference workbench is implemented with semantic HTML, CSS, native ES
modules, a dedicated worker, Rust/WASM, and Canvas 2D. No frontend framework,
bundler, external runtime script, or remote font service is required. Files
remain in the browser; importing several files appends independent queue entries.

```sh
./build-web.sh
python3 -m http.server 8080 --directory dist
# Open http://localhost:8080
```

The build needs Rust's `wasm32-unknown-unknown` target, `wasm-pack`, and Python 3.
It packages the application, WASM, self-hosted fonts and licenses into `dist/`.
Content-derived asset revisions keep the module graph and WASM consistent after
rebuilds. A protocol handshake and spatial-kernel check report incompatible
assets explicitly. Reload an already-open page after rebuilding.

## Implemented controls

| View | Behavior |
| --- | --- |
| Files | Multiple-file picker and global drop; append during analysis; independent duplicate filenames; remove; clear; per-file cursor and viewport. |
| Classification | Full existing classifier payload: format, metadata, architecture slices, extensions, heuristic candidates, confidence, source, notes; sampled entropy overview. |
| Entropy | Hilbert and linear layouts; entropy and byte-class palettes; continuous pointer-anchored zoom; drag pan; fixed file coordinates; cached visible-detail refinement; spatial minimap; previous/next view history; synchronized byte, entropy, compression and histogram inspection. |
| Hex | Virtual rows; 8/16/24/32 columns; 1/2/4/8-byte groups; hex/decimal offsets; ASCII, Latin-1, CP437, EBCDIC CP037 and UTF-16; absolute/relative/percentage goto; endian override; exact integer and floating-point decoding; byte selection, entropy, copy and download. |
| JSON | Full classification JSON, copy and download. |
| Batch | Status filters, insertion/name/size/confidence/entropy sorting, architecture/format tallies, progress, CSV and JSON exports. |
| Chrome | Responsive sidebar and inspectors, log, status bar, accessible tabs, context menu, keyboard navigation and persistent UI preferences. |

| Shortcut / gesture | Action |
| --- | --- |
| `1` .. `4` | Classification, entropy, hex, JSON |
| `j` / `k` | Next / previous file |
| `o`, `f`, `b`, backtick | Picker, files panel, batch, log |
| Wheel / trackpad | Continuous zoom at the pointer |
| Drag on map | Pan without moving the byte cursor |
| Minimap click / drag | Reposition the viewport within the whole file |
| `z` / `x`, `0` | Zoom in / out, fit |
| `Alt+Left` / `Alt+Right` | Previous / next viewport |
| `h`, `c`, `[` / `]` | Layout, palette, previous / next cell |
| Arrows in entropy | Move the byte cursor |
| Arrows, PageUp/Down, Home/End in hex | Move the byte cursor; Shift extends selection |
| `g`, Escape in hex | Goto, clear selection |
| Ctrl/Cmd+C in hex | Copy selected bytes as hex |

## Architecture and coordinate invariants

```text
File handles -> queue -> worker -> resident WASM binary
                           |         |-- existing ISA classifier
                           |         |-- Apeiron entropy / byte kernels
                           |         `-- Apeiron Hilbert coordinates
                           v
                     bounded transferred arrays
                           |-- classification / batch DOM
                           |-- virtual hex / probe inspector
                           `-- cached canvas layers -> viewport transform
                                                     `-> spatial minimap
```

The file's world is a square of side `S = 2^ceil(log2(sqrt(max(1,N))))`,
with a minimum side of 2, where `N` is the byte length. Each byte retains the
same world coordinate at every zoom. A power-of-two aggregation scale `a`
produces `a*a` bytes per spatial cell. Hilbert cells cover contiguous byte
intervals; linear cells cover square blocks with row stride `S` bytes. Unused
world cells remain transparent and cannot be selected.

The camera stores normalized origin `(x,y)` and magnification `z`. A point at
normalized screen coordinate `(u,v)` maps to `(x+u/z, y+v/z)`. Zoom updates
`x' = x + u/z - u/z'` and the equivalent equation for `y`, then clamps to the
file world. Thus the pointer's world position is invariant except when a world
boundary constrains it. Pointer hit testing uses the same Hilbert transform as
the WASM analysis, with cross-checked forward/inverse mappings.

```text
wheel / drag -> camera transform on next animation frame
                |-- existing raster remains visible
                `-- 90 ms idle -> request visible detail patch
                                  |-- worker analyzes bounded chunks
                                  `-- complete patch overlays same world area
```

The initial map has at most 256*256 cells. Refinement computes only the visible
spatial patch, bounded by the same cell count; it does not remap a smaller byte
interval into a new square. Twelve completed maps/patches are cached with bounded
insertion-order eviction. History retains at most 64 views per file. Back,
forward, fit and file switching reuse cached analysis; wheel and drag gestures
do not clear the base canvas or rerun the whole-file map.

## Measurement definitions and bounds

For byte counts `c_i`, `n = sum(c_i)` and `n > 0`, the reused Apeiron entropy
kernel evaluates

```text
H = log2(n) - sum(c_i * log2(c_i)) / n    [bits/byte]
    i = 0 .. 255; zero-count terms contribute zero
0 <= H <= 8 bits/byte; H(empty) = 0
```

The WASM engine uses the original count-logarithm lookup table, four-way
histograms, and portable `wide` operations. Numerical entropy is computed in
`f64`; canvas/profile results are transferred as `f32`, with a conservative
absolute rounding bound of 5e-7 bits/byte for values in [0,8]. Display formatting
adds its own decimal rounding. A map cell with fewer than 256 bytes uses up to
256 neighboring bytes for entropy; its byte-class fractions still describe the
actual cell. This context is identified in the inspector. Cells of at least
256 bytes use their exact byte population, including clipped EOF cells.

The overview contains up to 1,024 bins; each bin uses a centered sample of at
most 4,096 bytes. The batch value is the arithmetic mean of these local sampled
entropies, **not** the whole-file Shannon entropy. The histogram and compression
inspector use a labeled window of at most 4,096 bytes. Compression is the measured
raw DEFLATE level-6 byte length divided by input byte length. The ratio is not
clamped and can exceed 100% for short inputs. This is a separate browser proxy;
it is not Apeiron's native XZ/Zstd tier result.

Resident analysis accepts files up to 1 GiB. Actual browser allocation limits
can be lower and are reported as errors. Only one resident Rust binary is kept
at a time; File handles remain available for inspection, rereads and downloads.
The full file is not repeatedly transferred to the main thread. A selected
slice is bounded to 4 MiB for entropy and 1 MiB for clipboard copy; these bounds
are disclosed in the UI. Selection download uses the complete `File.slice`.
File sizes use B, KiB, MiB and GiB; classification duration uses ms and excludes
file reading, overview computation and map generation.

Queue insertion/dequeue and replacement of pending interactive operations are
O(1); batch sorting is O(F log F) for F files. Full-file reading and initial map
byte counting are O(N). A spatial patch with P cells costs O(P*a*a + P*256) in
the conservative small-cell case; Hilbert mapping adds O(P log S). The overview
reads at most 1,024*4,096 bytes. Hex requests and DOM rows depend on viewport
height, not N. Resident buffers and temporary reads require O(N_max) memory,
in addition to O(F+R) records/results, bounded cached patches and browser/runtime
overhead. WASM linear-memory capacity and garbage collection can retain freed
capacity; this is not a claimed resident-set ceiling. A synchronous classifier
call occupies the worker until it returns; map progress identifies worker wait
and file read phases instead of presenting them as computed cells.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| A1 | Each File is independent; later imports append, including equal filenames. Queue and export behavior depend on this. | Mixed architectures and empty/read-failed files; duplicate picker entries; additions during held reads. |
| A2 | Remove/clear invalidate both queued and active work. Current-file displays depend on this. | Remove and clear while reads are held; replacement batch; assert no stale result or prior file bytes appear. |
| A3 | Browser modules and WASM are served over HTTP from one complete build. Initialization depends on this. | Hold/fail WASM loading; inject incompatible worker protocol and spatial errors; check explicit terminal state. |
| A4 | Apeiron's current working-tree entropy snapshot is the requested engine. Analysis provenance depends on this. | Original/vendored hashes and base commit are recorded in `src/workbench/apeiron/README.md`; compare original kernel tests and exact H=0,1,8 fixtures. |
| A5 | Fixed byte coordinates, rather than a newly arranged interval, define navigation. Zoom/history depend on this. | Coarse/fine Hilbert block equivalence; repeated coordinate round trips; pointer-anchor error below 1e-9; unchanged base raster and map request count during zoom/pan/fit. |
| A6 | Local sampled entropy and DEFLATE compressibility are descriptive statistics. Palette/labels depend on this. | Uniform repeated 0..255 produces H=8 while remaining compressible; constant bytes H=0; binary alternation H=1; short compression ratio >1. |
| A7 | Classification endianness is the initial decoding preference, with an explicit override. Inspector values depend on this. | Exact u16/u32/u64 little/big-endian values and insufficient bytes at EOF; override label. |
| A8 | Browser File handles can be retained and reread during this session. File switching/downloads depend on this. | Switch files and restore cursor/camera; download exact selected bytes; injected read failure remains per-file. |
| A9 | File drops expose individual File objects; recursive directory traversal is outside this implementation. | Picker has `multiple`; global drag consumes the FileList; no directory-upload attribute or traversal API. |
| A10 | Viewport history is session-local; UI preferences are persisted, file content is not. | Reload restores layout preference with an empty queue; return to prior file restores its current camera and cursor. |

## Bounded scope findings

- **High impact:** a high Shannon entropy does not establish encryption. A
  repeated complete byte alphabet is a reproducible high-entropy/compressible
  counterexample; the interface uses distribution and compression labels.
- **High impact:** zooming a reindexed Hilbert subrange destroys spatial context.
  Fixed coordinates, pointer anchoring and a spatial minimap remove this source
  of navigation discontinuity; viewport history is distinct from byte selection.
- **High impact:** mixed cached asset versions can prevent map completion.
  Versioned build assets, protocol/kernel checks and visible operation errors
  expose this condition instead of leaving a silent 0% state.
- **Medium impact:** full-file residency and single-worker classification are
  browser memory/latency limits. Serial processing, a 1 GiB bound, bounded
  patches and visible wait/read phases constrain and disclose those limits.
- **Medium impact:** failed ISA classification does not imply unavailable byte
  inspection. Entropy and hex remain usable for unclassified binary blobs.
- **Low impact:** HTML filename escaping, complete CP037 decoding, stale-response
  rejection, transparent EOF holes and mobile tick clipping cover independent
  presentation edge cases.

## Verification and provenance

```sh
cargo test --no-default-features --features wasm --lib workbench
cd web
npm ci
npx playwright install chromium
npm test
```

The browser suite uses Chromium and the real WASM module against temporary local
HTTP servers. `BROWSER_PATH` can select an installed Chromium executable. It
covers source and packaged mobile pages, queue/read/init failures, mixed files,
large-offset hex virtualization, exact decoding and selections, exports,
keyboard navigation, worker responsiveness, runtime-local asset requests,
fixed-coordinate zoom, pan, minimap, history, raster reuse and protocol errors.
The Rust suite includes Apeiron's original kernel/Hilbert tests and wrapper tests
for entropy, class fractions, EOF, compression and spatial block invariants.

The final controlled run passes 30 browser/viewport regressions and 29 Rust
kernel/wrapper tests. The packaged UI also classified the host's actual
`/bin/ls` Mach-O universal binary. A 32 MiB ELF-header fixture with structured
and seeded xorshift32 regions generated its initial map in 77 ms in one warm
Chromium run, versus 679 ms before worker yields switched from timers to a
MessageChannel. These are observed elapsed times, not a cross-browser latency
bound; import/classification time is separate. Mobile visual inspection used
a 390*844 px viewport with measured document width 390 px.

Primary implementation sources are `src/wasm.rs`, `src/workbench/mod.rs`, the
vendored Apeiron files and their hash/license register, `web/viewport.js`,
`web/canvas.js`, `web/analysis-worker.js`, `web/workbench.js`, and the browser
regressions. The supplied HTML/design archive in
`/Users/int/Downloads/workbench` defines the visual/function reference; its
framework runtime is replaced by native browser APIs. Font provenance and SIL
Open Font Licenses are in `web/fonts/`.

Quality gates: QG1 contains no normative judgment; QG2 assumptions and probes
are registered above; QG3 the reference controls and later navigation/stall
requirements are covered; QG4 quantities/formulas/bounds are explicit; QG5 EOF,
stale data, errors, boundaries and cache transitions have behavioral checks;
QG6 analysis provenance is tied to source hashes and executable fixtures; QG7
scope findings are bounded and impact-labeled. Browser verification establishes
controlled Chromium behavior. The user confirmed the live page was working
after the rebuild. The specific cause of the earlier 0% stall remains unknown;
the asset/protocol failure paths and cancelled-refinement progress state are
independently covered by injected regressions.

## D10 firmware

The classifier now validates AOR AR-DV10 D10 records/CRC and decodes the CPU
encoding described by the supplied extractor. It classifies CPU and each
nonempty DSP code record independently and displays labelled slices, while
preserving all record offsets, flash addresses and sizes in metadata. The
supplied 2504B firmware yields RX for CPU 5:0 and Blackfin for DSP 1:0 and 2:0.
Entropy and hex views retain the stored file bytes and coordinates.

[D10 format notes](../docs/d10-container.md) record the layout, algorithms,
assumptions, reference hashes, limitations and verification commands. Run
`D10_FIXTURE=/Users/int/Downloads/2504B.D10 npm test` to include the optional
real-firmware browser regression. This extended run passed all 34 tests.
