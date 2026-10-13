# Atari 8-bit fixture provenance

`program.xex` is an Atari DOS binary load file linked by cc65 from the
synthetic program `program.s` (an init routine that stores a color and
returns, and a main program that stores a color and loops; 14 bytes of NMOS
6502 code written for this repository, each instruction's encoding in the
source comments) with the linker configuration `program.cfg`. No Atari or
third-party code is included. Generated on 2026-10-13 on macOS AArch64 with
the Homebrew cc65 2.19 bottle (`ca65` and `ld65` print `V2.18 - N/A`).

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `program.s` | 715 | `bebf434ca8961802ca059f77b6a63a8aa866a7b4ab432a357ae2c873e64c0af4` |
| `program.cfg` | 472 | `574c92f0132e7d4acbfad850c8be9423cffd88493a1166e7d6684e0a583c7024` |
| `program.xex` | 36 | `144cc666e09cff1ff6cf91cbdb4d5a05c226cdd010292789fef8f769710308d9` |

Commands (run from this directory):

```sh
ca65 -t atari -o /tmp/program.o program.s
ld65 -C program.cfg -o program.xex /tmp/program.o
```

`program.cfg` uses ld65's `atari` output format with `runad = start` and
`initad = INIT: init` (cc65 `doc/ld65.sgml`, "The FORMAT section"), so the
file holds four segments: `FF FF` and 0x0600-0x0605 (the init routine),
0x02E2-0x02E3 (INITAD = 0x0600), 0x2E00-0x2E07 (the main program) and
0x02E0-0x02E1 (RUNAD = 0x2E00). The output is deterministic for these inputs.

The ATR disk images used in `tests/atari8.rs` and `web/tests/atari8.test.mjs`
are built in the tests from the documented layout and are not stored here.
