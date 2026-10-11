# Classic ISA Classifier

`./build-web.sh` builds this interface into `dist/classic/`, alongside the Zrax
Workbench at `dist/index.html`. Serve the whole `dist/` directory over HTTP.
The **CLASSIC** link is the last control in the workbench's bottom status bar;
the classic header provides a **Workbench** return link. Both links work under
a deployment prefix such as `/zrax/`.

```text
dist/
|-- index.html                   Zrax Workbench
|-- zrax.js, zrax_bg.wasm         shared current classifier
|-- format.js                    shared display formatting
`-- classic/
    |-- index.html
    |-- classic.css, classic.js  restored classifier UI
    `-- fonts/                   original font families and OFL notices
```

The implementation restores `web/index.html` from commit
`6f0df914f0a24b714311e445f3b650b974439327`, the last classifier UI before the
entropy workbench. Consult `git show 6f0df91:web/index.html` for the primary
source. The restored HTML, styles and controller are separate files. Current
`classify` and `classifier_version` exports from [the WASM binding](../../src/wasm.rs)
provide the analysis; [shared formatting](../format.js) keeps names and units
consistent with the workbench.

The original Inter and JetBrains Mono families are served locally, with
[download URLs, SHA-256 hashes and license provenance](fonts/README.md).
The exact font binaries used by the historical hosted page are unknown; these
copies were downloaded on 2026-10-11. Native buttons now expose section and JSON
disclosure state to keyboard and assistive-technology users. Firmware cards keep
current component labels and distinguish multi-component containers from
universal Mach-O binaries.

## Processing and measurement boundaries

```text
append independent File records to queue
when WASM is ready:
  for each pending record:
    yield to browser, then read bytes
    discard work if the queue generation changed
    classify bytes; retain payload or per-file error
    release File reference; update progress and selected cards
clear queue -> increment generation -> ignore stale reads
```

Queue enqueue/dequeue overhead is O(1) per file, excluding record rendering.
Rendering a selected payload is O(R) in its output size R; file reads take O(N)
time and O(N) temporary space for N bytes. The classifier's own model, time and
space bounds are documented in the root README. Queue records and payloads use
O(F + sum(R)) space for F files; temporary input storage scales with the largest
active read. WASM can retain allocated capacity. These bounds do not assert a
browser resident-set ceiling.

File sizes use B, KiB, MiB and GiB, with 1 KiB = 1024 B. Duration uses ms and
measures classification and JSON parsing, excluding file reading. Primary
confidence and candidate evidence share remain distinct fields. Candidate
scores use bits, and bar widths are relative to the largest absolute score;
candidate percentages are not posterior probabilities.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| A1 | Classic means the last pre-workbench UI, rather than an older engine. Layout restoration depends on this. | Compare the restored cards/styles with `6f0df91`; current raw-code source/package payloads must be identical. Exact historical classifications are not promised. |
| A2 | The full build tree is deployed with HTTP module/WASM support. Classic startup and navigation depend on this. | Load source and `/dist/classic/`, require successful local asset responses and one revision across CSS, JS, WASM and fonts; verify links stay under their deployment prefix. |
| A3 | Browser File reads can finish after clear or additional imports. Queue consistency depends on generation invalidation. | Hold reads and WASM startup, append or clear files, release reads and assert no stale records/results; fail reads and initialization independently. |
| A4 | Modern browsers provide ES modules, WebAssembly and File APIs. Runtime behavior depends on this. | Chromium browser regressions and startup-failure injection; other browser engines remain unverified by this change. |

## Bounded findings

| Impact | Finding |
| --- | --- |
| High | Current D10 detection exposes RX/Blackfin component slices rather than the aggregate raw-binary result in the historical screenshot; preserving the old UI does not revert classifier behavior. |
| Medium | Classic preserves synchronous main-thread classification. A long classifier call can delay interaction; the full workbench runs analysis in a dedicated worker. |
| Medium | `classic/` depends on shared parent assets. Publishing only that subdirectory prevents startup; deploy the complete `dist/` tree. |
| Low | Local font copies remove runtime font-CDN requests and retain the original families; pixel-identical historical font rendering is unverified. |

`web/tests/classic.test.mjs` restores the nine historical queue regressions and
adds source/package card rendering, keyboard disclosure, local/revisioned asset,
deployment-prefix navigation, bottom-right link geometry, raw-code payload parity
and D10 component regressions. `D10_FIXTURE` enables the supplied real firmware
test; its absence is reported as a skip. Existing workbench tests cover its
unchanged classifier, entropy and hex workflows.
