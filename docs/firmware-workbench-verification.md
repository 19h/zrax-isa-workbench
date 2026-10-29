# Firmware container workbench verification

Verification date: 2026-10-29. Platform: macOS AArch64 (`Darwin arm64`).
Toolchain: rustc 1.99.1 (`58cf8f9c3`, 2026-10-13), Node 25.8.1,
Playwright 1.61.1 with Chromium. Changes remain in the worktree; no release
or deployment is claimed.

## Requirement evidence

| Requirement | Implementation and observed evidence |
| --- | --- |
| Automatic IMG4/IM4P parsing and compression trials | Existing DER parsing plus framed-codec recognition and bounded raw DEFLATE, LZ4 block and Brotli trials; exact-byte native cases for all three headerless codecs and LZFSE, including AES followed by decompression |
| Automatic FTAB parsing and member analysis | Both exact magics; independently classified members, placeholders as metadata, opaque manifest; native truncation/mutation tests and source/packaged browser tests |
| Automatic UARP parsing and member analysis | Full structural recognition, packed TLVs, independent payloads, validated opaque binary property-list members and trailers; three real assets and their nested FTABs passed range and classification checks |
| Load and try keybags | Encoded IV/key bytes retained separately from classification JSON; first eight bags tried with CBC and CTR; unique candidate selection across every bag and mode; wrong material remains opaque |
| Inline custom key/IV without prompts | Editable fields when no keybag exists, read-only encoded fields and selector otherwise; 300 ms debounce; real worker tests with Node-encrypted ciphertext for both source and packaged pages |
| Decrypted and ordinary subfiles under their parent | Actual transformed-byte extraction, nested file entries and breadcrumbs, independent classification/entropy/hex/JSON views, deduplicated reopening and recursive removal; queued decrypt replies cannot add children after navigation |
| Archives use the same workbench | Ordinary ZIP/tar/CPIO data files included in inspection without changing classification policy; encrypted ZIP members inspectable as opaque bytes; ar members supported |

The loaded reference screenshot informed the inline controls. Rendered QA
confirmed the form, decrypted child, parent breadcrumb and a real FTAB's
51 listed children. Subfiles precede lengthy metadata in the classification
pane. No third-party firmware or actual device keys were added to the tree.

## Validation results

| Check | Result and scope |
| --- | --- |
| `cargo test --all-features --locked` | 2,841 passed, 7 ignored in each of two complete runs, including doctests |
| Latest complete library run | 1,265 passed, 5 ignored; includes two subsequently added candidate-selection policy regressions |
| Latest affected integration targets | 62 passed, 1 ignored across `apple`, `image4_crypto`, `ftab`, `uarp` and `inspection`; the codec test additionally covers all three raw codecs |
| `cargo check --all-features --examples --locked` | Passed |
| `./build-web.sh` | Passed; fresh WASM and packaged workbench/classic assets, including adapted-code license notices |
| Final `npm test` | 345 passed, 4 skipped; source and packaged WASM, workbench and existing classic tests |
| Clippy comparison | No new warnings compared with base `d23b145`; existing all-feature library backlog remains 2,682 warnings |
| Formatting and whitespace | New Rust files and touched new code checked; `git diff --check` passed; unrelated formatting retained |
| Archive differential snapshot | 129,101 inputs over 17 fixtures: complete files, every truncation and single-byte zero/`0xFF`/bit-flip mutations; parser `Debug`, exact errors and payload JSON matched base `d23b145` |
| Fixture/helper representation snapshot | Nine cases across FTAB, UARP and Image4: fixture bytes and payload JSON matched before and after named-field conversion |
| AES known-answer cases | Six first-block vectors from NIST SP 800-38A F.2/F.5, covering CBC/CTR with 128-, 192- and 256-bit keys |

The full-suite count predates the two added selection-policy unit tests
and the keybag-enumeration limit regression. The later complete library
run includes the policy tests, and affected integration targets include
the new limit test. These targets were rerun after the final Rust changes.
Thus 2,844 distinct native
test cases were exercised successfully across these runs; this is not a
claim that the final count came from one invocation. Temporary snapshot
tests were removed after comparison.

The seven native ignores comprise five existing extension diagnostics or
reference checks, the D10 external-extractor comparison, and the optional
UARP external-file test. The UARP test was explicitly enabled for the three
assets below and passed for each, including nested FTAB member ranges.
The four browser skips require external D10 or reported RX113 firmware.
Skipped tests provide no evidence for their external fixtures.

## Real UARP assets

Only local reads and local browser analysis were performed. The inputs were
not redistributed. Reproduce the optional native check with:

```sh
UARP_FIXTURE=/path/to/firmware.uarp cargo test --all-features --locked --test uarp -- --ignored
```

| Size (B) | SHA-256 | Result |
| ---: | --- | --- |
| 14,603,786 | `ba0e30a9c0ab640e18317fa455c026a1f7e859bb62e17e0dc20534f2e433bb5f` | Passed |
| 14,943,323 | `6f9302ec35b5d9d11f90ec45ad321ef9dabc261c20eb3b5ba0d2b462a10801a0` | Passed |
| 14,600,008 | `e1243fae00414a0fa159a69405230776bea24edfd4e80a16782e0bf072e149ed` | Passed |

Each contained a 51-entry FTAB and a binary property-list trailer. The
packaged UI additionally opened one real FTAB and listed its 51 extracted
children, including the manifest and excluding an empty placeholder.
Classification results on unknown firmware remain model predictions;
these checks do not establish every component's true ISA.

## Assumptions, primary sources and boundaries

Detailed assumption registers and falsification probes are in
[Apple images](apple.md), [FTAB](ftab.md), [UARP](uarp.md) and
[subfile inspection](subfile-inspection.md). They include source revisions,
wire units and byte orders, resource limits and algorithmic complexity.
Reference checkout sources were clean when inspected. The requested local
`uarp-dump` checkout was absent; the pinned upstream repository supplied it.

| Impact | Boundary |
| --- | --- |
| High | Keybags are tried as encoded; device-key unwrapping is not implemented. Parsed structure and successful AES are not authentication |
| High | Ciphertext, manifests and known property-list/configuration data remain outside the code model, including after manual subfile opening |
| Medium | CTAB members remain conservatively opaque; the observed chunked compression codec is not decoded |
| Medium | Automatic mode requires recognized structure. Explicit CBC/CTR permits inspecting raw candidates without claiming they are correct plaintext |
| Medium | The inspected property-list subset and per-member/aggregate extraction limits can reject unsupported or oversized assets |
| Low | Brotli's decoder API does not report consumed input size; its trailing-byte boundary is not independently checked |

The selection-policy ambiguity tests construct candidate records. No supplied
asset with two distinct valid decryptions was available; the tests establish
the selector's behavior, not the existence of such an asset in the corpus.
