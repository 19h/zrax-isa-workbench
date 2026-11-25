# Desktop workbench

The native workbench (`crates/zrax-desktop`) shows what the browser workbench
(`web/`) shows, without a browser: classification, entropy map, hex, JSON,
strings and X.509 certificates for files analyzed on the machine. It can
also donate an analyzed firmware image to the zrax firmware collection
through the client library `crates/zrax-donate`.

This document records the design, the bounds, what is and is not built, and
what was verified.

## Layout

| Path | What |
| --- | --- |
| `src/workbench/engine.rs` | The resident analysis engine (`workbench` feature): classification, members, profile, map cells, byte windows. The `wasm` feature wraps it for the browser (`src/workbench/wasm.rs`). |
| `crates/Cargo.toml` | A workspace of its own for the applications, with its own `Cargo.lock`. |
| `crates/apeiron-core` | Apeiron's analysis kernels, pixel generators and wgpu compute renderer, vendored at a recorded commit without its egui application (`README.md` there lists every change). |
| `crates/zrax-donate` | The fwdonor client: accept rule, proof of work, HTTP API, one file's upload with progress events and cancellation. No UI, no terminal output. |
| `crates/zrax-desktop` | The gpui application. |

### Why two lockfiles

The applications are not members of the root workspace. With one lockfile,
adding gpui changed versions of packages the classifier already used
(`wasm-bindgen` 0.2.106 to 0.2.130, `libc`, `quote`, `regex-automata`), which
broke the WASM build against its pinned `wasm-bindgen` CLI. The classifier's
lockfile must not move because a GUI was added.

The cost is that the two lockfiles could resolve the classifier's own
dependencies differently, and the desktop would then classify with other
decoder versions than the CLI, the WASM build and the donation server.
`crates/zrax-desktop/tests/lockfiles.rs` fails on that drift.

## Dependencies

- `gpui-pre =0.3.12` and `gpui-pre-platform =0.3.12`: a weekly crates.io
  snapshot of gpui from zed main (the crate named `gpui` on crates.io is from
  2025-10). Versions are pinned exactly and upgraded deliberately.
- `apeiron-core` brings `rayon`, `xz2`, `zstd` and, for its compute
  renderer, `wgpu` 23 with a device of its own. gpui does not expose its GPU
  device, so frames drawn there are read back and handed to gpui as images.
  On Linux gpui ships its own, newer `wgpu`; both are linked.
- `gpui-component =0.9.1` is declared but not used yet (see
  [Known boundaries](#known-boundaries)).
- macOS builds compile Metal shaders at build time, which needs Xcode's Metal
  Toolchain component (`xcodebuild -downloadComponent MetalToolchain`). The
  `runtime-shaders` feature compiles them at startup instead.

## Building and running

```sh
cd crates
cargo run -p zrax-desktop --release                       # needs the Metal Toolchain on macOS
cargo run -p zrax-desktop --release --features runtime-shaders
cargo test --workspace --features zrax-desktop/runtime-shaders
```

Files and folders given on the command line open at start.

### macOS app

From the repository root on a Mac with Rust and Xcode Command Line Tools:

```sh
./build-macos.sh
```

Open the `zrax-workbench-<version>-macos-<arch>.dmg` in `crates/target/macos/`
and drag **Zrax Workbench** to **Applications**. You can also copy the
standalone `Zrax Workbench.app` from the same build directory. The bundle
contains the native executable, the Retina app icon, and license notices.
The build targets the Mac's current architecture. It links Apeiron's
`liblzma` statically and checks that the executable links only to macOS
system libraries. The packaged executable compiles its Metal shaders at
launch using macOS's Metal runtime.

| Action | Where |
| --- | --- |
| Open files or folders | **File > Open Files or Folders** (Command-O), Finder **Open With > Other**, or drag onto the Dock icon or workbench window |
| Reopen an item | **File > Open Recent** holds up to 10 paths from Finder, the dialog and window drops. **Clear Menu** removes the stored list. |
| Find or copy the selected file's path | **File > Reveal in Finder** (Shift-Command-R) or **Copy File Path** (Option-Command-C) |
| Export the selected entry's classification | **File > Export Classification JSON** (Shift-Command-E) opens the save dialog from any tab |
| Close and return to the workbench | Command-W closes the window. Click the Dock icon or choose **Window > Show Workbench** to reopen the session. |
| Manage the window | **Window > Minimize** (Command-M), **Window > Zoom**, or **View > Toggle Full Screen** (Control-Command-F) |

Finder opens use AppKit's file URL events. The bundle declares an alternate
viewer role for files and folders. Recent paths are stored in local macOS
preferences. Closing the window keeps the open files and their analysis in
memory until the app quits.

The default ad hoc signature is for local installation. For builds that
use your Developer ID, set `ZRAX_MACOS_SIGN_IDENTITY` to a signing identity.
That adds a timestamp and hardened runtime to the bundle and signs the disk
image. Notarization is a separate distribution step. [Apple's distribution guide](https://developer.apple.com/documentation/xcode/preparing-your-app-for-distribution)

| Assumption | Verification or falsification |
| --- | --- |
| AppKit delivers Finder opens as file URLs, including those sent before the main window exists. | Start with a file whose name contains spaces and URL escape characters, then send a second file to the running app. Export JSON to confirm which file was selected. |
| The package is relocatable. | Check the Mach-O imports, mount the disk image, copy the bundle, verify its signature and open the copy outside the repository. |
| The bundle works on the build host's architecture. | Compare the Mach-O architecture with the host and exercise the packaged executable. Older macOS and Intel require their own runtime checks. |

#### Package verification

On 2026-11-18 (macOS 27.3, arm64, Xcode 27.2, rustc 1.99.1), the
classifier suite passed 3,040 tests with 7 ignored. Five are diagnostic
tests and two require external firmware. The application workspace passed
156 tests with two GPU-adapter tests ignored. Clippy reported no warnings
in the desktop crate.

The disk image mounted read-only and contained an `Applications` link and
the app. A copy outside the checkout passed strict signature verification
and the Mach-O import check, opened a folder, and exported its ELF's JSON.
Launch Services also opened an arm64 Mach-O with spaces, punctuation and a
non-ASCII character in its name, a MIPS ELF sent to the running app, and a
folder containing an ELF. The two formats were validated against their
exported JSON. The native About panel showed version `0.1.0`. Closing and
reopening the window retained the analysis session, and Open Recent retained
the item list across application launches.

| Scope boundary | Impact |
| --- | --- |
| The app in the supplied image is ad hoc signed for local installation. Developer ID signing and notarization were not exercised. | High for distribution to other Macs |
| The bundle declares macOS 14 as its minimum. Runtime verification covered macOS 27.3 on Apple silicon. | Medium for other host configurations |

### Screenshots without screen capture

The `screenshots` feature builds gpui with its test support and adds a
development path: `ZRAX_SCREENSHOT=<file.png>` renders the window to an image
once analysis has finished and exits. `ZRAX_SCREENSHOT_TAB` selects a tab,
`ZRAX_SCREENSHOT_VIEW=donations` the donations panel,
`ZRAX_SCREENSHOT_MAP=<mode>[@<zoom>]` the map mode, and
`ZRAX_SCREENSHOT_HEADER=collapsed` the one-line header. The window stays
hidden and is drawn by hand, so a run neither takes the focus nor receives
input. It is never part of a
release build.

### File inspection

| Tab | Controls |
| --- | --- |
| Strings | Search by text or regular expression, choose encodings and tags, change the minimum length, and sort by offset, character count or text. Select a row for the decoded text and byte range. Jump to its offset in Hex, copy the text, or export the filtered rows as TXT, CSV or JSON. |
| Certificates | Inspect DER and PEM X.509 certificates with stored offsets, enclosing regions, names, validity dates, algorithms, key identifiers and fingerprints. Follow reported issuer and duplicate links, jump to Hex, open the decoded DER in a child entry, copy PEM, or save DER, PEM or the JSON report. Issuer links are based on encoded names. Certificate signatures and trust are unverified. |
| Entropy | **Fill** uses the available width and height with square cells. Drag to pan across the cropped portion. **Fit** shows the complete map and resets zoom. Scroll to zoom at the pointer. Toggle **Inspector** to give the map more room. |

Strings and certificates scan the selected file's resident bytes on demand.
Switching files cancels the active scan. String defaults match the shared
scanner: at least four characters, in ASCII, UTF-8 and UTF-16LE. UTF-16BE
is an additional toggle. Both tabs identify partial results when a scan
limit is reached.

#### Inspection verification

On 2026-11-18 (macOS 27.3, arm64, Xcode 27.2, rustc 1.99.1), the
classifier passed 3,041 tests, with five diagnostics and two
external-fixture tests ignored. The application workspace passed 159 tests
with two GPU-adapter tests ignored. The WASM build succeeded and Chromium
passed 402 tests, with four external D10 or RX113 fixture tests skipped.
Desktop Clippy produced no warnings in the desktop crate.

The disk image mounted read-only and the bundle passed strict signature
verification. In a relocated copy with an isolated app identifier, a
case-insensitive search for `CAFÉ` returned one UTF-8 row and the filtered
JSON contained the expected 14 B at `0x2E`. On the three-certificate PEM
fixture, following the issuer and jumping to Hex highlighted `0x301`.
The native DER save dialog exported a leaf certificate identical to
`tests/fixtures/certificates/leaf.der`. The entropy map rendered a 256 KiB
synthetic file in Fill and Fit. Dragging at 1× in Fill exposed the clipped
region. Hiding Inspector widened the drawing area.

| Scope boundary | Impact |
| --- | --- |
| The certificate view shows encoded fields and issuer-name links. Signature verification and trust evaluation are outside its scope. | High for authenticity decisions |
| Fill may crop the square map along its shorter axis. Fit exposes all cells at once. | Medium for whole-file inspection |
| Interactive checks used small synthetic fixtures. Peak-file performance and the other export formats were not exercised through the packaged UI. | Medium for those workflows |

## Architecture

- **Session** (`model/session.rs`): the entries in display order and the
  analysis queue. An extracted member sits after its parent, indented by its
  depth (at most 6, as in the classifier).
- **Analysis** (`analysis.rs`): one pass per file on gpui's background
  executor: read, classify, 1024-bin entropy profile, member list. At most
  `cores - 1` passes run at once. A pass is isolated with `catch_unwind`.
- **Views** (`ui/`): the workbench root owns the rail, files panel, status
  bar and the tab views. The hex grid and the entropy map are painted
  directly, so their cost does not depend on file size.
- **Entropy map** (`entropy/`, `ui/entropy_view.rs`): eight modes. Seven are
  apeiron's (forensic byte coloring, similarity matrix, digraph, phase
  space, Kolmogorov complexity, Jensen-Shannon divergence, multi-scale
  entropy); the eighth is the browser workbench's entropy map.
  - The view works as apeiron's does: when the camera, the mode or the
    underlying data changes, the visible region is drawn again off the main
    thread at about one texel per device pixel, at most 4096 per side. The
    previous frame stays on screen, moved with the camera, until the new one
    arrives. One frame is drawn at a time.
  - Apeiron's compute renderer draws the forensic, similarity, digraph and
    phase-space modes in the Hilbert layout when an adapter is available.
    Everything else, and every mode without an adapter, uses apeiron's CPU
    generators. The toolbar says which drew the frame on screen.
  - The Kolmogorov and multi-scale maps are sampled every 64 B on worker
    threads the first time their mode is shown and are drawn while they
    fill. Files of 100 MiB and more use apeiron's progressive Hilbert
    refiner.
  - The workbench's own mode asks the engine for the visible cells at the
    finest power-of-two scale that keeps them within 512 per side.
  - The inspector reads at the cursor (a click), not under the pointer as
    apeiron's does.
- **Donation** (`donate.rs`): the tokio-based client runs on a two-thread
  runtime owned by the window; results return to the interface through gpui
  tasks.
- **Names** (`names.rs`, `build.rs`): the display-name tables are generated
  at build time from `web/format.js`, which stays the single source.

## Bounds

| Bound | Value | Where |
| --- | --- | --- |
| Largest file kept resident | 1 GiB | `analysis::MAX_RESIDENT_BYTES` |
| Files per drop or pick | 20,000 | `paths::MAX_FILES_PER_ADD` |
| Member nesting | 6 | `session::MAX_SUBFILE_DEPTH` |
| Extracted member size | 64 MiB | `zrax::formats::MAX_PAYLOAD` |
| Map texture side | 4096 texels | `entropy::frame::MAX_TEXTURE_SIDE` |
| Workbench-mode cells per frame | 512 × 512 | `entropy::frame::MAX_ENTROPY_CELLS` |
| Cells per engine call | 65,536 | `workbench::MAX_CELLS_PER_CALL` |
| Byte window per engine call | 4 MiB | `workbench::MAX_WINDOW_BYTES` |
| Hex selection copied as text | 1 MiB | `hex_view::MAX_COPY_BYTES` |
| Strings retained | 100,000 rows and 16 MiB of decoded text | `ui::strings_view` |
| Completed strings queued behind an open run | Scan stops at 1,024 or more queued rows between 64 KiB chunks | `ui::strings_view` |
| Certificates retained | 4,096 entries and 16 MiB of DER | `zrax::certificates::MAX_CERTIFICATES`, `ui::certificates_view` |
| Log lines kept | 400 | `session::MAX_LOG_LINES` |
| Upload chunk accepted from the server | 64 MiB | `zrax-donate`, `MAX_CHUNK_BYTES` |

Symbolic links inside a dropped folder are not followed.

## Donation

Donated files are posted to a Telegram group with their file name and the
donor's name, kept permanently and listed for public download. The
application says so wherever it offers a donation.

- Donation is always available; there is no switch for it. Nothing is sent
  without a click on **donate**.
- What happens without a click: after a file has been analyzed the
  application fetches the server's policy (one `GET /api/policy` naming this
  build's zrax revision).
- Every analyzed file from disk shows its donation state between the header
  and the tabs: the offer, or one line saying why it cannot be donated right
  now (the server's answer, with **ask again**), or how its donation is
  going. Extracted members are not offered.
- The offer appears when the server's own accept rule
  (`zrax_donate::policy::judge`, with the lists the server publishes) would
  take the file, because a file the server rejects counts against the
  uploader's address.
- The application is not tied to the server's zrax revision. It sends
  `own_classifier: true` with each upload (`ClientConfig::own_classifier`);
  fwdonor then skips its revision check, classifies the file itself, and
  accepts or rejects it on that verdict. A rejection is shown as the
  donation's outcome and, per fwdonor, does not count towards a ban.
  `fwdonate` and the page, which run the server's own zrax, are still held
  to the server's revision.
- The build script records the commit the application was built from; it
  is sent as information.
- `ZRAX_DONATE_SERVER=<url>` names another server (a local `fwdonor serve`).

A server from before fwdonor learned `own_classifier` ignores the field and
answers `stale_client` unless the revisions match; the application then
shows that answer.

## Assumption register

| # | Assumption | Probe |
| --- | --- | --- |
| D1 | The native engine and the WASM wrapper return identical results. | The differential snapshot of step 1 (below); re-run it after any change to `src/workbench/`. |
| D2 | `web/format.js` holds only `id: 'name'` pairs in its three tables. | `build.rs` fails the build on an escape or a nested object. |
| D3 | Both lockfiles resolve the classifier's dependencies alike. | `tests/lockfiles.rs`. |
| D4 | The fwdonor API matches fwdonor commit `0d413ee` plus `own_classifier`. | `crates/zrax-donate/tests/session.rs` runs against a stand-in written from that source; one donation was also made against a real dry-run fwdonor (see Verification). Run fwdonor's `tests/client.e2e.mjs` once `fwdonate` uses this crate. |
| D5 | The proof of work matches the server's. | The vector shared with fwdonor (`41 × 0x11`, `32 × 0x22`, 12 bits, nonce 449) in `pow.rs`. |
| D6 | A wider entropy pane can display a larger map while preserving square cells and stored offsets. | Pan the default Fill projection at 1×, zoom at a pointer and select a byte. Compare the cursor in Hex. Switch to Fit to see the entire map. |
| D7 | Capped certificate scans preserve scan order for mixed DER and PEM. | `the_der_budget_keeps_an_offset_ordered_prefix_of_mixed_encodings` compares the bounded scan with the prefix of the full report. |

## Known boundaries

Not built yet, compared with the browser workbench:

- the all-files certificate view, scoped strings scans and the batch table
  with its exports;
- Image4 decryption controls;
- the entropy map's minimap and view history;
- persisted settings;
- the context menu and selection statistics in the hex tab.

Other boundaries:

- The text field handles printable input, paste, backspace and select-all
  for replacement. Caret movement and input-method support are pending.
- Apeiron's hex inspector, selection outline on the map and wavelet
  analysis are not wired up; its hover readouts appear for the cursor only.
- The similarity, digraph and phase-space modes do not map a click to a
  file offset.
- Windows and Linux packaging and desktop CI are pending.
- `fwdonate` and the fwdonor server do not use `zrax-donate` yet; that is a
  change in the fwdonor repository.
- The hex toolbar uses segmented controls where the browser uses menus.

## Verification

2026-11-10, macOS 27.3 (Darwin, arm64), rustc 1.99.1.

Classifier (repository root):

- `cargo test --all-features --locked`: 3,017 passed, 0 failed, 7 ignored
  (baseline before the change: 3,012 passed, 7 ignored; the difference is
  five new engine tests).
- `./build-web.sh`, then `npm test` in `web/`: 406 tests, 402 passed, 0
  failed, 4 skipped (the skips need D10/RX113 firmware that is not in the
  repository).
- Differential snapshot of the engine refactor: every `wasm-bindgen` method
  of `WorkbenchEngine` (both normal and opaque), the Hilbert permutation and
  Image4 decryption errors over 262 fixtures, each whole, truncated three
  ways and with three single-byte mutations: 1,834 inputs, output identical
  before and after.

Applications (`crates/`):

- `cargo test --workspace --features zrax-desktop/runtime-shaders`: 155
  passed, 0 failed, 2 ignored (60 desktop unit tests, 1 lockfile test, 15
  donation unit tests, 13 donation tests against the stand-in server, and
  apeiron's own 65 tests and 1 doc test). The 2 ignored are apeiron's tests
  that need a GPU adapter; run with `-- --ignored` on this machine (Apple
  GPU, Metal) both pass.
- `cargo clippy --workspace --all-targets` with `clippy::pedantic`: no
  warnings in `crates/`.
- All eight map modes were rendered for the same file at 1×, and the
  workbench and forensic modes also at 8×: the 8× frames show 64 B across
  with finer cells than the 1× frames, and the similarity, digraph,
  phase-space and forensic frames report the compute renderer.
- Donation end to end: a local `fwdonor serve` (dry-run Telegram, zrax
  `42df78c`, with the `own_classifier` change) received
  `HackRF-hackrf_rad1o_usb.dfu` from the application built at `77834bf`
  with uncommitted changes. The server admitted it despite the revision
  mismatch, verified it with its own zrax, stored it and logged the dry-run
  post; the application reported `donated`. The donation was started by a
  development hook that does what a click on **donate** does
  (`ZRAX_SCREENSHOT_DONATE`), not by a click.
- The empty state and the classification, entropy, hex and JSON tabs were
  rendered with the `screenshots` feature for `HackRF-hackrf_rad1o_usb.dfu`
  (72,080 B) and compared by eye with the browser workbench; the displayed
  values agree (for example entropy 2.0679 bits and deflate ratio 59.94 % at
  offset 0).

Not verified:

- Interaction (pointer, keyboard, drag and drop, file dialogs) was not
  exercised: the test environment could not capture or drive the screen.
- No donation was sent to the public server.
- Files larger than 72 KiB, and performance. In particular the
  progressive refiner (100 MiB and more) and the sampled maps of a large
  file were not run in the application.
- The compute renderer on Windows and Linux, and the CPU fallback on a
  machine without an adapter.
- Windows, Linux and x86_64 macOS.
