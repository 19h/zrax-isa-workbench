# AGENTS.md

Rules for anyone changing this repository, human or agent. They cover code
style, formatting, naming, the classifier's domain rules, testing and
verification. `README.md` describes the product; this file describes how to
change it.

"Must" marks a rule that a change is wrong without. "Should" marks the
default; deviate only for a stated reason. Where existing code breaks a rule,
the rule still applies to new and rewritten code (see
[Existing code that breaks these rules](#existing-code-that-breaks-these-rules)).

## Contents

1. [Principles](#1-principles)
2. [Rust](#2-rust)
3. [Classifier concepts](#3-classifier-concepts)
4. [Web application](#4-web-application)
5. [Tests and fixtures](#5-tests-and-fixtures)
6. [Behavior-preserving refactors](#6-behavior-preserving-refactors)
7. [Scripts](#7-scripts)
8. [Documentation](#8-documentation)
9. [Git](#9-git)
10. [Definition of done](#10-definition-of-done)

## 1. Principles

1. **Readable over short.** Code is read far more often than it is written.
   Fewer characters is never a goal. Code golf (statement chains, one-letter
   names, unnamed magic numbers, nested inline closures) is a defect and is
   rejected in review, even when it works.
2. **Observable behavior is a contract.** Format IDs, ISA IDs, error
   messages, notes, metadata keys and labels, offsets and the order of checks
   all reach users, the JSON payload, the browser UI and tests. Change them
   only on purpose and say so in the commit message.
3. **Input is hostile.** Every byte comes from an untrusted file. Parsers
   must never panic, overflow, loop without bound, or allocate in proportion
   to an unvalidated count.
4. **Claims are bounded by evidence.** The classifier reports what the bytes
   establish, not what is plausible. The same discipline applies to
   documentation and commit messages.
5. **Match the module's design.** New code follows the structure and
   vocabulary of the module it joins, unless that conflicts with these rules.

## 2. Rust

### 2.1 Toolchain and lints

- Edition 2021. `Cargo.toml` declares `rust-version = "1.70"`, but that
  minimum is not validated, and the code already uses `<[u8]>::trim_ascii`
  (stable since 1.80; clippy flags it). Do not add APIs newer than the ones
  already in use without a reason, and do not claim an MSRV in docs.
- `src/lib.rs` sets the lints: `warn(missing_docs)`, `warn(clippy::all)`,
  `warn(clippy::pedantic)`, `deny(unsafe_code)` outside the `wasm` feature
  (`warn` inside it). It allows `module_name_repetitions`,
  `must_use_candidate`, `similar_names` and `too_many_lines`.
- The crate carries a warning backlog (about 2,000 clippy warnings in the
  library on 2026-10-12). Rules:
  - Code you add or rewrite must not add compiler or clippy warnings, apart
    from the documented exceptions below.
  - Do not fix the backlog in unrelated changes. It inflates diffs and hides
    the real change.
  - Accepted pedantic exceptions: `match_same_arms` when a layout table reads
    better with one arm per case, and `wildcard_imports` for `use super::*;`
    in a format family's submodules.
- To compare warnings for the files you touched, run clippy on your branch
  and on a `git worktree` of the base commit, and filter both outputs by
  path:

  ```sh
  cargo clippy --lib --message-format=short 2>&1 | grep -E 'src/formats/ti'
  ```

### 2.2 Formatting

`rustfmt` with default settings (no `rustfmt.toml`): 100-column lines,
4-space indent, trailing commas in vertical lists.

The tree is not uniformly formatted. On 2026-10-12, 37 of 96 Rust files had
rustfmt drift (measure with `cargo fmt --check`). Formatting rules follow
from that:

- New files must be rustfmt-clean.
- A module you substantially rewrite must be rustfmt-clean.
- When you edit part of a file that has drift, format only the lines you
  changed. Leave the file's other drift alone.
- Never run `cargo fmt` (whole crate) as part of a feature or fix. A
  formatting-only commit is fine if that is its only change.
- `rustfmt <file>` also formats every out-of-line child module (`mod x;`).
  Running it on `src/lib.rs` or `src/formats/mod.rs` reformats most of the
  crate. Running it on `src/formats/ti.rs` formats `src/formats/ti/*.rs`,
  which is the intent there.
- To check only your hunks in `lib.rs` or `formats/mod.rs`, format a scratch
  copy with its child modules stubbed out, then compare:

  ```sh
  sed -E 's/^(pub )?mod ([a-z_0-9]+);$/\1mod \2 {}/' src/lib.rs > /tmp/lib.rs
  cp /tmp/lib.rs /tmp/lib.orig.rs && rustfmt --edition 2021 /tmp/lib.rs
  diff -u /tmp/lib.orig.rs /tmp/lib.rs   # apply only hunks in code you wrote
  ```

- `#[rustfmt::skip]` is allowed only on data tables whose aligned columns
  carry meaning, e.g. the UUID table in `src/formats/ti/fip.rs` or the
  opcode tables in `src/extensions/x86.rs`. Never use it to keep dense code
  dense.

### 2.3 No code golf

Each of these must not appear in new or rewritten code:

| Don't | Do |
| --- | --- |
| Several statements on one line: `let mut pos=8;let mut names=&[];` | One statement per line |
| Formatting that dodges rustfmt: `{pub name:String,pub offset:usize}` | rustfmt layout |
| Immediately invoked closures as control flow: `(\|\| { ... })()` | A named function returning `Result` |
| A `bool` parameter that switches layouts: `unkeyed(data, true)` | Pass the enum (`Variant`) or split into named functions |
| Magic numbers in logic: `if op == 0x58535906` | `if op == JUMP_CLOSE` (see 2.5) |
| Anonymous tuples that cross a function boundary: `Option<(bool, u8, u16)>` | A small struct with named fields (`TiHeader`) |
| Push, pop and re-push to fix a note: `notes.pop(); notes.push(...)` | Build the right value once (`adopt(container, inner, note)`) |
| A parameter copied into the same variable in each arm | Compute it once before the `match` |
| The same table or parser written twice (e.g. a magic list in detection and in parsing) | One `const` or helper used by both |
| Unexplained `unwrap()` | `?`, or `expect("why this cannot fail")` |

Prefer early returns over nesting. When exactly one of two interpretations
may succeed, match the pair of results so the rule reads as a table:

```rust
match (word_table(data, kind, 2), word_table(data, kind, 4)) {
    (Ok(_), Ok(_)) => Err(error("Ambiguous C54x boot-mode header")),
    (Ok(c), Err(_)) | (Err(_), Ok(c)) => Ok(c),
    (Err(_), Err(_)) => Err(error("Invalid C54x parallel/serial boot table")),
}
```

### 2.4 Naming

- Name a function for what it returns or does: `parse`, `detect`,
  `parse_members`, `tlv_area_end`, `is_padding`, `expect_padding`. Use the
  `is_`/`has_` prefixes for predicates.
- The input buffer is `data`. A sub-slice gets a name for what it holds
  (`image`, `record`, `header`, `contents`, `payload`), never `d`, `b` or
  `buf2`.
- One-letter names are allowed only for:
  - closure parameters and iterator items within one expression (`|b|`,
    `|s|`, `w` in `windows(2)`);
  - loop indices;
  - the two conventional builders: `c` for a container under construction
    and `r` for a `ClassificationResult` under construction.
- Byte order: `le: bool` (true means little-endian) for a parameter or
  local. In a struct, use a full name such as `big_endian`. Fixed-order
  reads use `le_u32(data, at)`, not `u32_at(data, at, true)`.
- Units go in names wherever the type does not carry them:
  - `size`/`len` for bytes, `words` for target words;
  - `address` for target addresses, `offset`/`pos` for file positions;
  - `entry` for an entry point.
  - Destination addresses are `u64`, so `address + size` cannot overflow.
- Constants are `SCREAMING_SNAKE_CASE`, named after the specification's own
  term when it has one: `PT_LOAD`, `IMAGE_F_ENCRYPTED_AES128`,
  `TLV_INFO_MAGIC`, `SECTION_LOAD`.
- Each format module has a private `fn error(message: impl Into<String>) ->
  ClassifierError` that builds the module's error variant.

### 2.5 Constants and magic numbers

- Magic values, opcodes, flags, tags, record types and fixed sizes that the
  logic tests against get named `const`s at the top of the module. When a
  name came from your own reading rather than the spec, add a comment
  saying so.
- Field offsets that are read once may stay as literals, provided a doc
  comment on the function lists the layout. For example:
  `/// Header: magic, load address (4), header size (8), ...`.
- Hex literal case follows the file. Group 32-bit or wider constants in
  fours: `0x96f3_b83d` (clippy `unreadable_literal`).
- A data table (UUIDs, ID lists) is one `const` slice or array, shared by
  every function that needs it.

### 2.6 Comments and documentation

- Every module starts with `//!`: what format it handles and the primary
  source for its layout. Cite document IDs and sections (`SPRABL7D, section
  3.1, Table 2`), a pinned revision, or a source file path. See
  `src/formats/ti_c55x.rs` and `src/formats/d10.rs`.
- Comments explain what the wire format is and why the code checks what it
  checks. They do not narrate code (`// increment pos`). A comment
  explaining a non-obvious rejection is especially valuable, e.g. "Do not
  turn arbitrary records into C3x."
- Every public item gets a doc comment (`missing_docs` is on). State units
  and coordinate systems (byte vs. word addresses, file vs. target offsets)
  in field docs.
- Put identifiers in doc comments in backticks (`` `PT_NOTE` ``,
  `` `f_magic` ``), as clippy `doc_markdown` requires.
- Do not leave TODOs without an owner and a reason. Do not leave
  commented-out code.

### 2.7 Module structure

- One format family per module in `src/formats/`. When a family outgrows
  one readable file, make it a directory module the way `ti` is built:
  - `ti.rs` holds what the family shares: the container model,
    bounds-checked readers, detection and dispatch;
  - `ti/<layout>.rs` holds one layout or a closely related group each;
  - submodules start with `use super::*;`.
- Visibility is as narrow as possible. Children can already see their
  parent's private items. Use `pub(super)` only for what the parent calls,
  and `pub` only for what other crate modules or tests use.
- Functions are short enough that the format's structure is visible: a
  layout loop, a record decoder, a validation step. Extract a function when
  a block has a name in the specification.

### 2.8 Parsing untrusted input

- Read through bounds-checked helpers, never by indexing unvalidated
  ranges:
  - crate-wide: `formats::read_u16/read_u32/read_u64/read_bytes`;
  - family-local: helpers such as `slice`, `ensure`, `u32_at` and `le_u32`
    in `ti.rs`.
  - Direct indexing (`data[i]`) is allowed only right after a check that
    proves the bound.
- Arithmetic on values from the input uses `checked_add`/`checked_mul`, or
  `u64` with a proven bound. A failure becomes an error, never a wrap or a
  panic.
- Validate a count against the bytes actually available before allocating
  or looping on it (`count <= remaining / record_size`). No allocation may
  be sized by a destination address or an unvalidated count.
- Payload extraction is capped (`ti::MAX_PAYLOAD`, 64 MiB). Container
  nesting is capped (`MAX_NESTING = 6` in `src/lib.rs`).
- Trailing bytes after an image may only be erased flash (`0x00`/`0xFF`),
  unless the format defines a trailer.
- The order of checks is observable: truncation errors name the offset that
  failed. Keep that order when refactoring.

### 2.9 Errors

- Each format family has one `ClassifierError` variant,
  `<Family>ParseError { message: String }`, with
  `#[error("<Family> parse error: {message}")]` and a doc comment.
- Error messages:
  - sentence case, no trailing period;
  - start with the defect: `Invalid …`, `Truncated …`, `Missing …`,
    `Duplicate …`, `Unsupported …`, `Unknown …`, `Ambiguous …`;
  - name the field or record in the format's own terms;
  - print offsets and values in hex (`0x{offset:X}`), sizes as `{n} B`.
- Messages are behavior: tests and the UI match them, e.g.
  `/TI container parse error/`.

### 2.10 User-visible text: notes, metadata, labels

- Notes are sentence case with no trailing period. Join related facts with
  `; `, e.g.
  `"RPRC version 1; little-endian header; processor ISA is not encoded"`.
- Write sizes as `B`, `KiB` and `MiB` (binary units). Write hex as `0x`
  plus uppercase digits (`0x{value:X}`, or `0x{value:08X}` for fixed width).
  Name word units explicitly ("16-bit word addresses").
- Never imply more than was checked. Say "not verified" or "not
  authenticated" for signatures, CRCs and digests the parser does not
  check. Never name a device model the bytes do not encode.
- Custom metadata keys are `snake_case` with a family prefix
  (`ti_section_0`, `ti_c55x_entry_file_offset`, `d10_block_…`).

## 3. Classifier concepts

These are design rules, not style. A change that breaks one is a
correctness bug.

### 3.1 Format and ISA are separate

- Format detection (`formats::detect_format`) decides what the container is.
  ISA classification decides what the code is. A container reports its own
  format even when the ISA comes from contained code.
- Evidence ranks as follows: an explicit target field in the format (ELF
  `e_machine`, TI COFF target ID) > a documented role marker (radar MSS/DSS
  IDs) > the code model run on extracted code > nothing.
- Never infer an ISA from a load address, an unqualified core ID, a file
  name or a vendor name. When the format does not say, the container result
  is `Isa::Unknown` with confidence 0. The code model may then answer from
  the extracted bytes (`adopt_heuristic`).

### 3.2 Detection strength

- **Strong** detection: magic-bearing formats (`ti::detect_strong`, ELF,
  PE, ...). They are recognized even when the rest of the file is broken,
  so a corrupt container produces a format error instead of a confident raw
  ISA.
- **Weak** detection: magic-less or short-key layouts (C55x `0x09AA`,
  text encodings, `ti::detect_weak`). They require the complete structure,
  every checksum, and where applicable an entry point inside loaded bytes.
  Magic-less layouts (`ti::detect_weak`) run last in `detect_format`, just
  before `Raw`.
- A layout that validates under two interpretations is reported as
  ambiguous (for example `Variant::AmbiguousBoot`), with an unknown ISA and
  no extraction. Never pick one.
- Detection order in `detect_format` is semantic. Comment why when you
  insert a check ahead of another one, e.g. "TI MCELF has ordinary ELF magic
  but carries core-mapping notes."

### 3.3 Containers, children and opaque data

- A container either loads sections (bytes bound for target memory,
  concatenated for analysis without materializing address gaps) or wraps
  children (independent images: cores, certificate payloads, FIP
  components, archive members).
- Each child is classified on its own (`classify_ti_component`, archive
  members in `classify_depth`) and reported as a slice. Its extensions come
  from its own bytes. Never scan other cores with the primary ISA.
- Encrypted, compressed, signed-but-transformed, configuration or sample
  data is opaque. Opaque bytes never reach the code model or extension
  detection.
- Parsing structure is not authentication. Signatures, digests and CRCs are
  reported as verified only when actually checked.

### 3.4 Public contract

- JSON IDs come from serde attributes in `src/types.rs`:
  - `Isa` uses `snake_case` (`ti_c5400`);
  - `FileFormat` uses `lowercase` (`tic55xboot`);
  - `Endianness` uses `lowercase`.
  Renaming a variant renames the ID. Treat that as a breaking change.
- Results are deterministic: the same bytes and options give the same
  output.

### 3.5 Adding a format or an ISA

A new file format must touch all of these (compare commit `07785cd`):

1. `src/error.rs`: the family's parse-error variant, with a doc comment.
2. `src/formats/<name>.rs` (or a directory module): `detect`, `parse`, and
   `parse_container` if the format has sections or children.
3. `src/formats/mod.rs`:
   - `pub mod`;
   - a documented `DetectedFormat` variant;
   - the check in `detect_format`, in the right strength position;
   - an arm in `parse_detected`.
4. `src/types.rs`: a documented `FileFormat` variant and its `Display` arm.
5. `src/formatter.rs`: the `format_name` arm.
6. `src/lib.rs`:
   - the `detected_to_format` arm;
   - a `classify_depth` arm if the container extracts code or has children.
7. `web/format.js`: a `FORMAT_NAMES` entry. Without one the UI shows the
   uppercased ID (`fmtFormatName` falls back to it). The TI browser test
   checks this for its own IDs; do the same for new ones.
8. Tests: `tests/<name>.rs` and `web/tests/<name>.test.mjs`, plus a fixture
   provenance README if fixtures are generated (section 5).
9. Docs: `README.md` ("What the classifier recognizes"). For a nontrivial
   family, add `docs/<name>.md` (section 8).

A new ISA touches the `Isa` variant, `Isa::name` and `Isa::default_bitwidth`
in `src/types.rs`; `ISA_NAMES` in `web/format.js`; and every format table
that maps to it (for example `coff::ti_target`).

## 4. Web application

### 4.1 Runtime model

- Plain browser ES modules. There is no bundler, transpiler or framework.
  `build-web.sh` builds the WASM with `wasm-pack`, copies `web/` into
  `dist/`, rewrites the `pkg/` import paths, and appends a content hash
  (`?v=<revision>`) to every quoted relative `.js`, `.wasm`, `.css` and
  `.ttf` reference.
- A new runtime file must be reachable by that script: a top-level
  `web/*.js` file, or a path the script copies explicitly. Reference assets
  with quoted relative paths so they get versioned.
- `pkg/` and `dist/` are build outputs and are git-ignored. Never commit
  them, and never hand-edit `dist/`.
- `web/format.js` is the only place the browser maps JSON IDs to display
  names. The workbench and the classic UI both import it. The CLI's names
  are in `src/formatter.rs` and `FileFormat`'s `Display`; keep all three in
  agreement.

### 4.2 JavaScript style

No formatter or linter is configured, so these rules are manual:

- 2-space indent, single quotes, semicolons. `const` by default, `let` only
  when reassigned, never `var`.
- Arrow functions for small helpers, `function` declarations for top-level
  procedures. Template literals for interpolation.
- One statement per line. Lines up to 120 columns, except template literals
  that hold HTML or SVG markup.
- Names follow the domain: `entry`, `payload`, `slices`, `candidates`,
  `format`, as in the Rust JSON.
- Every value interpolated into HTML goes through `esc()` from
  `web/format.js`. File names and payload strings are untrusted.
- Icon-only buttons carry both `aria-label` and `title`. Keep `role` and
  `aria-*` attributes when restructuring markup; the browser tests query by
  role.
- `localStorage` access is wrapped in `try`/`catch`, because storage is
  optional.

### 4.3 CSS and HTML

- Colors come from the custom properties defined at the top of each
  stylesheet (`var(--accent)`, `var(--surface-inset)`). Sizes use `rem`
  (`0.0625rem` is one CSS pixel at the default root size).
- New rule blocks use the expanded form, one declaration per line, as in
  `web/classic/classic.css`.
- Fonts are self-hosted under `web/fonts` and `web/classic/fonts`, each
  with its OFL license text and a `README.md`. Do not add network font or
  script dependencies.

## 5. Tests and fixtures

### 5.1 Native tests

- Unit tests live in the module (`#[cfg(test)] mod tests`). Behavior across
  modules lives in `tests/<feature>.rs`, which starts with a `//!` line
  saying what the file covers.
- Name a test for the behavior it pins, e.g.
  `ti_c55x_table_uses_word_loads_byte_entry_and_per_record_padding`, not
  `test1`.
- Fixture builders are functions whose comments document each field, as in
  `tests/ti_c55x.rs`. Build fixtures from the documented wire layout, not by
  calling the parser under test.
- Every parser gets:
  - a positive case per layout and byte order;
  - a truncation sweep (`for end in 0..v.len()` must error);
  - corrupted-field cases;
  - a no-panic sweep over byte mutations or deterministic noise (see
    `byte_mutations_counts_and_truncations_are_bounded`).
- Tests that need external data read an environment variable (`D10_FIXTURE`,
  `D10_REFERENCE_DIR`, `TI_C55X_FIXTURE`, `IDAREF_DIR`). Without it they
  skip, or carry `#[ignore = "reason"]`; they never fail. A skipped suite is
  not evidence: report skips as skips.

### 5.2 Fixtures

- Generated fixtures live in `tests/fixtures/<family>/`, with a `README.md`
  recording:
  - the generator and its version or revision;
  - the exact commands;
  - the size and SHA-256 of each file;
  - what is synthetic about it.
  See `tests/fixtures/ti/README.md`.
- Never commit third-party firmware, private keys or anything that cannot
  be redistributed. Use synthetic payloads (the TI fixtures carry
  `01 02 03 04`).

### 5.3 Browser tests

- `node:test` with Playwright Chromium. Shared setup is in
  `web/tests/helpers.mjs` (`setup`, `openPage`, `load`, `finished`,
  `selectEntry`).
- Run `./build-web.sh` first. Tests cover both the source pages (`/web/`)
  and the packaged ones (`/dist/`), and the classic UI (`/classic/`) when it
  is affected.
- Fixture builders follow the native rules: named functions with field
  comments. Look results up by format or file name, not by array position.
- Code passed to `page.evaluate` runs in the browser and cannot use Node
  APIs such as `Buffer`.

### 5.4 Commands

```sh
cargo test --all-features --locked             # all native tests
cargo check --all-features --examples --locked
./build-web.sh                                 # WASM + dist/ + dist/classic/
(cd web && npm ci && npx playwright install chromium && npm test)
```

On 2026-10-12 the baseline was 403 native tests passing with 6 ignored, and
59 browser tests passing with 4 skipped (the skips need D10/RX113 firmware
that is not in the repository).

## 6. Behavior-preserving refactors

A cleanup, rename, split or reformat must not change behavior. Passing tests
are not enough: most parser tests only assert `is_err()`, and they do not
check error text, notes or check order.

1. Record the test baseline before editing.
2. Keep the public API that tests and other modules use: type names, field
   names and order, and function signatures. `Debug` output includes field
   names.
3. Preserve error strings, notes, metadata keys and labels, and the order
   of checks and reads, since truncation errors name offsets.
4. Run a differential snapshot:
   - Write a temporary integration test (e.g. `tests/zz_snapshot_tmp.rs`)
     that runs the affected parsers and `zrax::detect_payload` over every
     fixture, every truncation, and single-byte mutations
     (`0x00`/`0xFF`/bit flip).
   - Record per input: `Debug` of results (hashed), error strings and the
     payload JSON.
   - Run it on the base commit and on your change, and compare the files.
   - Delete the test before committing.
   - The TI cleanup compared 87,428 inputs this way.
5. For test-fixture refactors, compare the generated fixture bytes before
   and after.
6. If the refactor reveals a bug, keep the behavior. Report the bug and fix
   it in a separate change with its own tests.

## 7. Scripts

- Shell scripts start with `#!/usr/bin/env bash` and
  `set -euo pipefail`, then a comment with purpose and usage. Quote every
  expansion.
- Python scripts start with `#!/usr/bin/env python3` and a module docstring
  covering purpose, output layout and usage, as in
  `scripts/build_corpus.py`. Use `argparse` for CLIs. No formatter config is
  committed, so follow PEP 8.
- Scripts take inputs as explicit arguments or environment variables
  (`ARMGEN`, `IDAREF_DIR`). Do not hard-code personal paths.

## 8. Documentation

- Format and design documents live in `docs/`. Examples:
  `docs/ti-containers.md`, `docs/d10-container.md`, `docs/architecture/`.
  A nontrivial family's document records:
  - the implemented layouts, each with its primary source (document ID,
    section, or pinned URL);
  - wire units: bytes vs. target words, and header vs. target byte order;
  - validation and resource bounds, with their numbers;
  - an assumption register: each assumption with a falsification probe;
  - known boundaries: what is not implemented and why.
- Verification statements give the date, platform, toolchain, test counts,
  and any skips with reasons. Use absolute dates, never "today" or
  "recently".
- Do not state or imply more than was tested. "Not verified" is the correct
  wording when something was not checked.
- Markdown: sentence-case headings, fenced code blocks with a language tag,
  and tables for inventories.

## 9. Git

- Commit summary: `<type>: <Imperative summary>`, about 72 characters at
  most. History uses `feat` and `fix`; use `refactor`, `docs`, `test` or
  `chore` when those fit better. The body wraps at 72 columns and says what changed and why. List
  secondary changes as bullets. Name intentional behavior changes
  explicitly.
- One logical change per commit. Formatting-only changes go in their own
  commit.
- Never commit build outputs (`target/`, `pkg/`, `dist/`), local corpora or
  reports (see `.gitignore`), secrets, or keys.

## 10. Definition of done

- [ ] No code golf (section 2.3). Names, constants and comments follow
      sections 2.4–2.6.
- [ ] New and rewritten Rust is rustfmt-clean. Unrelated code is not
      reformatted.
- [ ] Touched files have no new compiler or clippy warnings, apart from the
      documented exceptions.
- [ ] Every parser path is bounds-checked and checked-arithmetic, with no
      panics on any input (section 2.8).
- [ ] Domain rules hold: format vs. ISA, strong vs. weak detection, opaque
      data, no unbounded claims (section 3).
- [ ] Every registration point for a new format or ISA is updated (section
      3.5).
- [ ] `cargo test --all-features` passes. If web, WASM or format IDs
      changed, `./build-web.sh` and `npm test` pass too. Skips are reported.
- [ ] Refactors carry a differential snapshot (section 6).
- [ ] Docs and fixture provenance are updated. Verification statements are
      dated and bounded.

## Existing code that breaks these rules

Some older code predates these rules. It is not a model for new code:

- `web/workbench.js`, `web/workbench.css`, `web/index.html` and some browser
  tests (`workbench.test.mjs`, `batch.test.mjs`) pack several statements,
  rules or elements per line. Do not imitate this. Do not reflow these files
  wholesale; write new or substantially changed functions in the readable
  style.
- About a third of the Rust files have rustfmt drift (section 2.2), and the
  crate has a large pedantic clippy backlog (section 2.1).
- `scripts/compile_llvm_matrix.sh` and `scripts/validate_firmware.sh` do not
  set `set -euo pipefail`.
- `tests/ti_containers.rs` writes some wire constants (`0x43525052`,
  `0x5853_5906`) as bare literals in fixture builders.
- Archive members that supply the primary ISA keep the member's `source`,
  while TI container components become `Combined`. ASCII-Hex section offsets
  are relative to the whitespace-trimmed text. Both are known
  inconsistencies kept for now (section 6, step 6).
