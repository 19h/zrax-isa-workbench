# ISA Classifier web UI

Drop several binary files onto the drop zone, or select several files in the
picker. The file table preserves insertion order, reports each file's status,
and opens its classification details when selected. Later drops append to the
queue. Repeated filenames are separate entries. Clear files resets the batch.

Build from the classifier directory:

```sh
./build-web.sh
```

Serve `dist/` over HTTP to use the packaged application. Classification runs in
the browser; the file queue does not upload binary contents.

Run the browser regression suite after building:

```sh
cd web
npm ci
npx playwright install chromium
npm test
```

The tests start a temporary local HTTP server and exercise the source page and
packaged page with the real WASM module. `BROWSER_PATH` optionally selects an
existing Chromium executable.

## Assumption register

| ID | Assumption and dependent behavior | Stress test / falsification probe |
| --- | --- | --- |
| A1 | Each file is an independent classification; failures do not terminate the batch. | Mix x86-64 and AArch64 ELF headers with an empty file; inject a read failure and verify later files complete. |
| A2 | Later selections append to the current batch, including duplicate filenames. | Add files during a held read; select identical names repeatedly; clear during a held read and verify its result cannot enter the replacement batch. |
| A3 | Files selected before classifier initialization completes wait in the queue. | Hold the WASM response, enqueue files, then release it; separately fail initialization and verify terminal statuses. |
| A4 | This queue handles individual files; recursive directory ingestion is outside this change. | The picker has `multiple` without a directory-selection attribute; drag-and-drop consumes the browser's `FileList`. Directory traversal is not implemented. |

## Queue algorithm and bounds

```text
enqueue every File as a distinct entry
if the classifier is ready and a processor is not already running:
    for each queued entry, including later additions:
        mark analyzing; yield to the browser
        read one file; discard if the batch generation changed
        classify; retain its payload or its error
        release the File reference; update its row and selected details
clear: increment generation; discard entries and pending work
```

Queue bookkeeping is O(N) over N entries and O(1) per processed entry. File
reads, classification, and rendering costs are additional. Retained state is
O(N + R), where R is the aggregate result and filename storage; only one file
buffer is read for classification at a time. Browser garbage collection and
WASM linear-memory capacity are outside this bound. File sizes use B, KiB,
MiB, and GiB; analysis duration uses ms.

## Bounded scope and edge cases

- **High impact:** batch generations prevent an outstanding read from restoring
  results after clearing. Read and classifier errors remain local to each file.
- **Medium impact:** serial reads avoid allocating buffers for the whole batch;
  only the selected file's detailed result is rendered. Classification remains
  synchronous on the browser's main thread, so one expensive file can delay
  interaction until its classification returns.
- **Low impact:** filename escaping covers HTML text and attributes; nested drag
  targets retain highlighting; file drops outside the zone prevent navigation.

Primary implementation evidence is `index.html`, `../src/wasm.rs`, and
`../build-web.sh`. Behavioral evidence is `tests/batch.test.mjs`, which covers
mixed-file drops, picker selection, duplicates, keyboard selection, append and
clear races, read failure, initialization timing and failure, filename escaping,
drag events, and a 100-file batch at a 390 px viewport width.
