# fw1 golden set and model retraining

Scripts that audit zrax on the fw1 firmware set, build a golden training
corpus from it, and retrain `src/heuristics/model.bin`.

fw1 is third-party firmware and is not in the repository. Every output that
contains or derives from its bytes stays in git-ignored directories:

| What | Where |
| --- | --- |
| fw1 binaries and sidecar JSON (input) | outside the repo, passed as `FW1_DIR` |
| Per-file tables, findings, CLI results, eval reports, logs | `reports/fw1/` |
| Trained models (`m*-train.bin` held-out, `m*-all.bin` ship) | `reports/fw1/models/` |
| CLI builds with each held-out model | `reports/fw1/bin/` |
| Corpora in `build_corpus.py` layout | `corpus_extra/fw1/` |

Most scripts read and write tables in the current directory. Run them from
`reports/fw1/`.

## Pipeline

```sh
R=$(git rev-parse --show-toplevel); FW=/path/to/fw1; C=$R/corpus_extra/fw1
cd "$R/reports/fw1"
# 1. Per-file tables from the sidecars and the bytes
python3 -I "$R/scripts/fw1/dump.py" "$FW" all.tsv            # zrax result + original name
python3 -I "$R/scripts/fw1/heads.py" "$FW" all.tsv heads.tsv # ELF/PE/Mach-O header fields
python3 -I "$R/scripts/fw1/smooth.py" "$FW"                  # 8-bit PCM smoothness -> smooth.tsv
python3 -I "$R/scripts/fw1/entropy.py" "$FW"                 # high-entropy fraction -> entropy.tsv
python3 -I "$R/scripts/fw1/pil.py" "$FW"                     # .bNN segments vs .mdt headers -> pil_match.tsv
python3 -I "$R/scripts/fw1/findings.py" "$FW"                # flagged errors -> findings.tsv
# 2. Corpora: the base corpus (command in corpus_extra/README.md, --out $C/corpus-base), then fw1
python3 -I "$R/scripts/fw1/fw1_corpus.py" --repo "$R" --fw "$FW" --work . \
  --out "$C/corpus-fw1" --exclude-ids "$C/corpus-base/manifest.jsonl"
python3 -I "$R/scripts/fw1/merge.py" "$C/corpus-m2" "$C/corpus-base" "$C/corpus-fw1"
# 3. Held-out model and sample-level evaluation
cargo run --release --example train_model -- --corpus "$C/corpus-m2" --split train --out models/m2-train.bin
cargo run --release --example eval -- --corpus "$C/corpus-base" --model models/m2-train.bin
cargo run --release --example eval -- --corpus "$C/corpus-fw1" --model models/m2-train.bin
# 4. File-level evaluation through the CLI (build zrax with the held-out model first)
python3 -I "$R/scripts/fw1/golden_files.py" "$FW" "$C/corpus-fw1" > golden.tsv
awk -F'\t' 'NR>1 && $2=="test"{print $1}' golden.tsv > golden-test.txt
"$R/scripts/fw1/runlist.sh" bin/zrax-m2t "$FW" golden-test.txt gold-m2t.jsonl
python3 -I "$R/scripts/fw1/score.py" test gold-mbt.jsonl gold-m2t.jsonl
# 5. Ship model: all splits
cargo run --release --example train_model -- --corpus "$C/corpus-m2" --out "$R/src/heuristics/model.bin"
```

## Golden labels

Labels never come from zrax output:

| Source | Evidence | Class |
| --- | --- | --- |
| fw1 ELF files | `e_machine` (microMIPS from `EF_MIPS_MICROMIPS`); 4 KiB blocks kept only if they hold a return instruction | ISA |
| Qualcomm `.bNN` segments | program header from the matching `.mdt`/`.b00`: executable, data or hash | ISA / `neg_rodata` / skipped |
| 8-bit PCM | adjacent-sample smoothness ≥ 0.6 (known code never exceeds 0.39) | `neg_media` |
| Calibration maps, QCA board data | `swfl_*.159_010_001`, `QCA-ATH1xK-BOARD` magic | `neg_table` |
| 8051 images | LJMP reset vector plus RETI/LJMP interrupt vectors | `i8051` |
| Cortex-M images | SRAM stack pointer plus Thumb handler addresses | `thumb` |
| ROM families | platform fixes the CPU: TR-DOS, Multiface, Opus, DISCiPLE, RC2014 (Z80); NAOMI BIOS with SH LE `rts` density ≥ 300/MiB | `z80`, `sh` |

Groups are firmware families, split 4:1 into train and test by group hash.

## Results (2026-11-03, macOS, zrax `ea12aed`)

Held-out, file level, through the CLI (768 golden test files):

| Model | Correct |
| --- | --- |
| Base corpus only (`m-base-train`) | 69.8% |
| Base + fw1 golden set (`m2-train`) | 94.1% |
| + mined hard negatives (`m3-train`) | 92.4% |
| + `neg_calib` data class (`m4-train`) | 94.3% |
| + transform-augmented negatives (`m5-train`) | 94.3% |

The base corpus test split is unchanged for `m2-train`: 99.5% correct, 99.0%
exact, 0.5% false accepts. `src/heuristics/model.bin` is `models/m2-all.bin`
(`m2` corpus, all splits); `cargo test --all-features --locked` passes with
it (2940 passed, 0 failed, 7 ignored).

Known limits:

- Calibration maps stay at 13% correct and Qualcomm data segments at 62.5%.
  The CLI's transform search (`search_transforms` in `src/lib.rs`) accepts a
  lane-interleaved reading at confidence 0.98; retraining does not fix it.
- Known regressions in the full-corpus run: `pgm_p01s`/`pgm_p02s` (byte-swapped
  68000 BIOS) and one Reolink update image are now rejected.
- Held-out coverage is thin for ROM families: 6 Z80 test files, no SH-4 test
  files.

## Files

| Script | Purpose |
| --- | --- |
| `fw1_corpus.py` | golden corpus builder (uses `scripts/build_corpus.py`) |
| `golden_files.py` | file-level labels with split, for CLI scoring |
| `runlist.sh`, `runall.sh` | run a zrax CLI over listed / all fw1 files to JSONL |
| `score.py` | score CLI runs against `golden.tsv` |
| `diffrun.py` | diff two full runs and score against `findings.tsv` |
| `cmpeval.py` | compare two `examples/eval.rs` reports per class |
| `merge.py` | merge corpora by symlink (`merge.sh` is the slow original) |
| `hardlist.py` + `examples/mine_hard.rs` | hard-negative mining (iteration 3) |
| `aug_neg.py` | transform-augmented negatives (iteration 5) |
| `dump.py`, `heads.py`, `pil.py`, `smooth.py`, `entropy.py` | per-file tables |
| `findings.py`, `magics.py`, `xtab.py`, `namekw.py` | audit of classification errors |
| `elfsec.py`, `idioms.py`, `shidiom.py` | spot checks (ELF sections, TriCore/ARC and SuperH idiom density) |

`reports/fw1/worktree-neg_calib-class.patch` is the `neg_calib` data class
used by `m4-train`; it is not applied. `corpus_extra/fw1/corpus-m1` is stale:
its fw1 samples were replaced when the fw1 corpus was rebuilt with the
return-instruction filter.
