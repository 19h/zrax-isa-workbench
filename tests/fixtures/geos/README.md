# PC/GEOS geode fixtures

`code.bin` is the code resource for the synthetic geodes in `tests/geos.rs`
and `web/tests/geos.test.mjs`. Every geode in those tests (file headers,
executable header, core block, imported library, exported entry and
resource tables, relocations) is built in the test from the layout
documented in `docs/geos.md`; only the code needs an assembler. No PC/GEOS
geode or other PC/GEOS file is redistributed.

## Source

`code.asm` is hand-written 16-bit real-mode x86 in the style of PC/GEOS
library code: register saves, far calls with zero targets (as `glue` leaves
call sites for `GRT_CALL` relocations), string and arithmetic loops, a
frame-based routine and a near jump table. Nothing in it is taken from
PC/GEOS. It is not a working geode resource: the relocations the tests list
point at arbitrary offsets.

## Generator and commands

Assembled on 2026-10-13, macOS AArch64, with NASM 3.02, by `generate.sh`:

```sh
nasm -f bin -o code.bin code.asm
```

## Size and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `code.asm` | 3474 | `597dbf42645f1ad54c8ab3b288511734ebf88fa76ef675f797e18c8ea459c21a` |
| `code.bin` | 209 | `8ad9d4030d899e5c751ac3ec7fc1ef04c148871745dd608af5affd29bebac954` |

## What is synthetic

Everything. The code model classifies `code.bin` alone as x86 (32-bit
model, about 50 % confidence on 2026-10-13); the geode tests report it as
16-bit x86 because the resource's `HAF_CODE` flag and the platform say so.
