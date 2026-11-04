# fw1 golden set and model retraining

Scripts that audit zrax on the fw1 firmware set, build a golden training
corpus from it, and retrain `src/heuristics/model.bin`.

fw1 (18,014 firmware files named by SHA-256, each with a JSON sidecar) is
third-party firmware and is not in the repository. Every output that
contains or derives from its bytes stays in git-ignored directories:

| What | Where |
| --- | --- |
| fw1 binaries and sidecar JSON (input) | outside the repo, passed as `FW` |
| Per-file tables, findings, CLI results, eval reports, logs | `reports/fw1/` |
| Trained models (`*-train.bin` held-out, `*-all.bin` ship) | `reports/fw1/models/` |
| CLI builds with each model | `reports/fw1/bin/` |
| Corpora in `build_corpus.py` layout | `corpus_extra/fw1/` |
| MAME driver sources (ROM regions by SHA-1) | `corpus_extra/mame/` |
| PIC14, 8080/8085 and 68HC11 repository downloads, gcc work tree | `corpus_extra/pic14-work/`, `corpus_extra/i8085-work/`, `corpus_extra/hc11-work/`, `corpus_extra/gcc-work/` |

Most scripts read and write tables in the current directory. Run them from
`reports/fw1/`.

## Rebuild the shipped model

`src/heuristics/model.bin` is `ship23-all` (2026-11-04): the base corpus
(`corpus-base7`), the fw1 golden set (`corpus-fw1v23`), transform-augmented
fw1 negatives (`corpus-aug14`), mined hard negatives (`corpus-hardU6`),
68HC11 code (`corpus-hc11x`), byte lanes of 68000 code (`corpus-lanes`),
hand-written 68000 code (`corpus-m68kx`), Z8 and eZ8 code from the submitted
Z8 archive (`corpus-z8x`), SDCC MCS-251 output (`corpus-mcs251x`) and
Panasonic UniPhier IPP code from the 0x1040 ELF files of the submitted IPP
samples (`corpus-ippx`), all splits.

- `corpus-fw1v23` is `corpus-fw1v22` with one sample more: the MCS-251
  records of the Edgeport `down2.fw` (`ihex2fw-mcs251`, train split).

- `corpus-base7` is `corpus-base6` rebuilt after the ARM labelling fix
  (`arm_class` in `build_corpus.py`): 19 rows of 18 idaref and radare2 ELF
  files change class (BE-8 executables to `arm`/`thumb`, big-endian A32 from
  `thumbeb` to `armeb`); otherwise it differs only in the text samples of
  the edited `README.md` and `error.rs` and in one `unspeb` row, the word
  swap of the `unsp` IDA sample (`WORD_SWAPPED`, added after `base6`).
- `corpus-fw1v22` is `corpus-fw1v20` with the 7 REALOS/FR images as `fr30`,
  the µ'nSP tracer's vector-table and repeated-word rules (no µ'nSP samples
  from `pokermor`, whose traced words were pixel data; 194 fill words fewer
  in `bornkid`) and no code label for the five fill segments (`wpss.b03`
  loses one sample).
- `corpus-fw1v20` is `corpus-fw1v19` built with the macro-expanding
  `mame_regions.py`: one more MAME sound ROM (`pumpitup`), and the PGM sound
  ROM's group named after the set that lists it first (`mame:pgm`).
  `corpus-fw1v19` is `corpus-fw1v18` plus the ECU96 label (145 `mcs96`
  rows).
- `corpus-hardU6` was mined from `corpus-fw1v13`, which differs from
  `corpus-fw1v18` by its 115 µ'nSP rows (27 `unsp`, 27 `unspeb`, 61
  `neg_media`) and three corrected labels (two TriCore program-flash blocks
  that the calibration rule took for maps, and Slogger's BBC Micro DDOS ROM
  that the Opus rule took for Z80); the samples it was mined from are the
  same in all of them (checked 2026-11-04).
- `corpus-lanes` was built from `corpus-ship19pre`, whose 3,227 `m68k` rows
  are those of the ship22 corpora without `corpus-m68kx` (checked
  2026-11-04); it has no lanes of the hand-written 68000 samples.

```sh
R=$(git rev-parse --show-toplevel); E=$R/corpus_extra; C=$E/fw1
FW=/path/to/fw1; H=/path/to/hexagon-dsp-binaries
mkdir -p "$R/reports/fw1/models" "$R/reports/fw1/bin"
cd "$R"

# 0. Inputs that are built once.
#  a. MN10300 objects: GCC 16 mn10300-elf with four variants (variants.txt)
scripts/gcc_matrix/build.sh "$E/gcc-work" all 8 mn10300-elf
cp -R "$E/gcc-work/out/mn10300" "$E/gcc-objects/mn10300"
#  b. Hand-written mid-range PIC code: REPOS lists `owner/name<TAB>license<TAB>branch`
#     from GitHub repository search (queries pic16f84, pic16f84a, pic16f628(a),
#     pic16f877(a), pic16f876, pic16f887, pic16f88, pic16f690, pic12f675, pic12f629,
#     pic12f683, pic16f648, pic16f73, pic16f676, pic16f1827, pic16f1847, pic12f1822,
#     pic16f1938, mpasm, gpasm, each with language:Assembly); commits are pinned and
#     recorded in raw-ext/PROVENANCE.md
python3 -I scripts/pic14_asm_corpus.py "$E/pic14-work/repos-all.tsv" "$E/pic14-work" \
  "$E/raw-ext/pic14asm" "$E/raw-ext/PROVENANCE.md"
#     Intel 8080/8085 and Motorola 68HC11 code the same way, assembled with AS (asl);
#     REPOS from repository search (8085: 8085, 8080, intel 8080, intel 8085, altair 8800,
#     imsai, cp/m, sdk-85, 8085 microprocessor, 8080 monitor, i8080; 68HC11: 68hc11, hc11,
#     m68hc11, 6811, motorola 68hc11, 68hc11 assembly, mc68hc11, buffalo 68hc11, hc11 asm,
#     names without three letters dropped); each profile's provenance rows were then
#     given their own section in raw-ext/PROVENANCE.md
python3 -I scripts/asl_asm_corpus.py --asl /path/to/asl --profile 8085 "$E/i8085-work/repos.tsv" \
  "$E/i8085-work" "$E/raw-ext/i8085" "$E/raw-ext/PROVENANCE.md"
python3 -I scripts/asl_asm_corpus.py --asl /path/to/asl --profile 68hc11 "$E/hc11-work/repos.tsv" \
  "$E/hc11-work" "$E/raw-ext/hc11" "$E/hc11-work/prov.md"
#     MCS-251 code: the SDCC MCS-251 downstream port (github.com/gevico/sdcc-c251 at commit
#     912a589d4080c9cd5c5c1faf871c62dd5023580d, configured with --enable-mcs251-port; on macOS
#     its binutils link against Homebrew zstd) compiles the armgen programs and its libraries
#     (S=the port's install prefix)
PATH="$S/bin:$PATH" SDCC_SHARE="$S/share/sdcc" VARIANTS=$R/scripts/sdcc_matrix/variants-mcs251.txt \
  OUT="$E/mcs251-objects" scripts/sdcc_matrix/build.sh "$E/mcs251-work/matrix" all 8
#     Z8 and eZ8 programs: the submitted Z8 archive, classic Z8 files (Z8__*) in raw-z8/z8,
#     Z8 Encore! files (eZ8_Encore__*) in raw-z8/ez8
#     UniPhier IPP code: the 212 ELF files with e_machine 0x1040 of the submitted IPP samples
#     (IPP=the sample folder; third-party firmware, read in place, never copied into the repo)
#     Motorola 68000 code the same way, into raw-asm/ (not raw-ext/: step 2 must not take it);
#     REPOS from `gh search repos QUERY --language=Assembly --limit 100` for 68000, 68000 assembly,
#     mc68000, m68k, 68k, sega genesis, genesis assembly, megadrive, mega drive, neogeo, neo geo,
#     x68000, atari st, amiga assembly, sega cd, 68000 monitor, easy68k, 68k assembly, motorola 68000,
#     genesis homebrew, sonic disassembly, sonic disasm, genesis disassembly, mega drive disassembly,
#     megadrive disassembly, neo geo disassembly, 68000 disassembly, plus sonicretro/s2disasm and
#     sonicretro/skdisasm (938 repositories; 77 give code)
python3 -I scripts/asl_asm_corpus.py --asl /path/to/asl --profile 68000 "$E/m68kasm-work/repos.tsv" \
  "$E/m68kasm-work" "$E/raw-asm/m68k" "$E/m68kasm-work/prov.md"
#  c. MAME ROM regions (commit df3bcbba30251a393d8bb33a356c6c2ee93c34e9, src/mame only)
mkdir -p "$E/mame" && curl -sS https://codeload.github.com/mamedev/mame/tar.gz/df3bcbba30251a393d8bb33a356c6c2ee93c34e9 \
  | tar -xzf - -C "$E/mame" --include='*/src/mame/*'
python3 -I scripts/fw1/mame_regions.py "$E"/mame/*/src/mame reports/fw1/mame_regions.tsv

# 1. Per-file tables from the sidecars and the bytes (fw1_corpus.py reads them)
(cd reports/fw1 &&
  python3 -I "$R/scripts/fw1/dump.py" "$FW" all.tsv &&            # zrax result + original name
  python3 -I "$R/scripts/fw1/heads.py" "$FW" all.tsv heads.tsv &&  # ELF/PE/Mach-O header fields
  python3 -I "$R/scripts/fw1/smooth.py" "$FW" &&                   # 8-bit PCM smoothness -> smooth.tsv
  python3 -I "$R/scripts/fw1/entropy.py" "$FW" &&                  # high-entropy fraction -> entropy.tsv
  python3 -I "$R/scripts/fw1/pil.py" "$FW" &&                      # .bNN segments vs .mdt -> pil_match.tsv
  python3 -I "$R/scripts/fw1/mame_match.py" "$FW" mame_regions.tsv &&  # -> mame_match.tsv
  python3 -I "$R/scripts/fw1/mame_cpus.py" "$E"/mame/*/src/mame mame_regions.tsv mame_match.tsv mame_cpus.tsv &&
  python3 -I "$R/scripts/fw1/findings.py" "$FW")                   # flagged errors -> findings.tsv

# 2. Base corpus: compiled and raw corpora, Hexagon ELF collection, MN10300,
#    hand-written PIC14, synthetic negatives (ISAdetect from --data, default ../isa-harvester/data)
#    (raw-ext/hc11 has its own corpus, corpus-hc11x in step 4)
python3 -I scripts/build_corpus.py --out "$C/corpus-base7" \
  --gen "$E/llvm-objects" --gen "$E/gcc-objects" --gen "$E/sdcc-objects" \
  $(for d in "$E"/raw/*/ "$E"/raw-ext/*/ "$E"/raw-ida/*/; do
      [ "$(basename "$d")" = hc11 ] || echo --raw "$(basename "$d")=$d*"; done) \
  --raw "avr=idaref/avr_test.bin" --elf "$H/**/*.so" --elf "$H/**/fastrpc_shell*"

# 3. Held-out ISAdetect files 400-549 per architecture (a missing --armgen skips armgen objects)
python3 -I scripts/build_corpus.py --out "$C/corpus-ds2h" --armgen "$C/none" \
  --isadetect-skip 400 --isadetect-per-arch 150 --negatives 0
python3 -I scripts/fw1/holdout.py "$C/corpus-ds2h" "$C/corpus-base7"

# 4. fw1 golden set and its transform-augmented negatives
python3 -I scripts/fw1/fw1_corpus.py --repo . --fw "$FW" --work reports/fw1 \
  --out "$C/corpus-fw1v23" --exclude-ids "$C/corpus-base2/manifest.jsonl"
python3 -I scripts/fw1/aug_neg.py --sources fw1-cal,fw1-table16,fw1-amdgpu-ucode,fw1-pil-data \
  "$C/corpus-aug14" "$C/corpus-fw1v23"
#    68HC11 samples from step 0b as their own corpus (build_corpus.py adds its default
#    sources too: keep the hc11 rows that are not already in corpus-base7)
mkdir -p "$C/none" && python3 -I scripts/build_corpus.py --out "$C/corpus-hc11x" --armgen "$C/none" \
  --isadetect-per-arch 0 --negatives 0 --raw "hc11=$E/raw-ext/hc11/*"
python3 -I - <<'EOF'
import json, os, shutil
C, base = "corpus_extra/fw1/corpus-hc11x", "corpus_extra/fw1/corpus-base7/manifest.jsonl"
known = {json.loads(line)["id"] for line in open(base)}
rows = [r for r in map(json.loads, open(f"{C}/manifest.jsonl")) if r["class"] == "hc11" and r["id"] not in known]
open(f"{C}/manifest.jsonl", "w").writelines(json.dumps(r) + "\n" for r in rows)
for cls in os.listdir(f"{C}/samples"):
    if cls != "hc11":
        shutil.rmtree(f"{C}/samples/{cls}")
EOF

#    68000 samples from step 0b the same way, under their own source (`train_model`
#    caps each class and source at 1 MB: as `raw` they would share it with raw/m68k)
python3 -I scripts/build_corpus.py --out "$C/corpus-m68kx" --armgen "$C/none" \
  --isadetect-per-arch 0 --negatives 0 --raw "m68k=$E/raw-asm/m68k/*"
python3 -I - <<'EOF'
import json, os, shutil
C, base = "corpus_extra/fw1/corpus-m68kx", "corpus_extra/fw1/corpus-base7/manifest.jsonl"
known = {json.loads(line)["id"] for line in open(base)}
rows = []
for r in map(json.loads, open(f"{C}/manifest.jsonl")):
    if r["class"] == "m68k" and r["source"] == "raw" and r["id"] not in known:
        r["source"] = "asl-68000"
        rows.append(r)
open(f"{C}/manifest.jsonl", "w").writelines(json.dumps(r) + "\n" for r in rows)
for cls in os.listdir(f"{C}/samples"):
    if cls != "m68k":
        shutil.rmtree(f"{C}/samples/{cls}")
EOF
#    Z8 and eZ8 samples, grouped by project (builds of one application note together), and
#    MCS-251 samples, each kept to its own classes and source as above
python3 -I scripts/build_corpus.py --out "$C/corpus-z8x" --armgen "$C/none" --isadetect-per-arch 0 \
  --negatives 0 --raw "z8=$E/raw-z8/z8/*" --raw "ez8=$E/raw-z8/ez8/*" \
  --raw-group 'z8=^Z8__((?:Apple-(?:profile|hd20|widget))|AppleNet|ARCOM|unimon|Z8671|MAME|ORNL|Z8-NASCOM|AN\d{4})' \
  --raw-group 'ez8=^eZ8_Encore__((?:AN|RD)\d{4})'
python3 -I scripts/build_corpus.py --out "$C/corpus-mcs251x" --armgen "$C/none" --isadetect-per-arch 0 \
  --negatives 0 --gen "$E/mcs251-objects"
python3 -I - <<'EOF'
import json, os, shutil
base = "corpus_extra/fw1/corpus-base7/manifest.jsonl"
known = {json.loads(line)["id"] for line in open(base)}
for C, classes, source in (("corpus_extra/fw1/corpus-z8x", ("z8", "ez8"), "z8-archive"),
                           ("corpus_extra/fw1/corpus-mcs251x", ("mcs251",), None)):
    rows = [r for r in map(json.loads, open(f"{C}/manifest.jsonl")) if r["class"] in classes and r["id"] not in known]
    rows = [dict(r, source=source) if source and r["source"] == "raw" else r for r in rows]
    open(f"{C}/manifest.jsonl", "w").writelines(json.dumps(r) + "\n" for r in rows)
    for cls in os.listdir(f"{C}/samples"):
        if cls not in classes:
            shutil.rmtree(f"{C}/samples/{cls}")
EOF

# 5. Hard negatives, mined from train-split data segments and MAME data ROMs:
#    round 1 with a model of the base corpus only (it has not seen these files),
#    round 2 with a model that has the fw1 corpus and round 1
cargo build --release --locked --features cli --example train_model --example eval --example mine_hard
T=target/release/examples; M=reports/fw1/models
python3 -I - > reports/fw1/hard-list.tsv <<'EOF'
import json, os
C = "corpus_extra/fw1/corpus-fw1v13"
for line in open(f"{C}/manifest.jsonl"):
    r = json.loads(line)
    if r["source"] in ("fw1-pil-data", "fw1-mame") and r["split"] == "train":
        print(f"{os.path.abspath(C)}/samples/{r['class']}/{r['id']}.bin\t{r['class']}\t{r['group']}")
EOF
$T/train_model --corpus "$C/corpus-base6" --split train --out $M/b6-train.bin
mkdir -p "$C/corpus-hardA" "$C/corpus-hardB"
$T/mine_hard --model $M/b6-train.bin --out "$C/corpus-hardA" < reports/fw1/hard-list.tsv
python3 -I scripts/fw1/merge.py "$C/corpus-r2" "$C/corpus-base6" "$C/corpus-fw1v13" "$C/corpus-aug13" "$C/corpus-hardA"
$T/train_model --corpus "$C/corpus-r2" --split train --out $M/r2-train.bin
$T/mine_hard --model $M/r2-train.bin --out "$C/corpus-hardB" < reports/fw1/hard-list.tsv
python3 -I scripts/fw1/merge.py "$C/corpus-hardU" "$C/corpus-hardA" "$C/corpus-hardB"
python3 -I - <<'EOF'   # the two rounds can mine the same window: keep each sample once
import json
p = "corpus_extra/fw1/corpus-hardU/manifest.jsonl"
seen, rows = set(), []
for line in open(p):
    if json.loads(line)["id"] not in seen:
        seen.add(json.loads(line)["id"]); rows.append(line)
open(p, "w").writelines(rows)
EOF
#    byte lanes of 68000 code (2 and 4 lanes, at most 2 MiB) as `neg_lanes`; built for
#    ship19 from base6 and fw1v18, whose m68k rows base7 and fw1v20 keep
python3 -I scripts/fw1/merge.py "$C/corpus-ship19pre" "$C/corpus-base6" "$C/corpus-fw1v18" "$C/corpus-aug14" \
  "$C/corpus-hardU" "$C/corpus-hc11x"
python3 -I scripts/fw1/lane_negatives.py "$C/corpus-ship19pre" "$C/corpus-lanes" m68k
#    IPP code from the 0x1040 ELF files, one group per file, kept to its class as above
python3 -I scripts/build_corpus.py --out "$C/corpus-ippx" --armgen "$C/none" --isadetect-per-arch 0 \
  --negatives 0 --elf "$IPP/elf-0x1040/*"
python3 -I - <<'EOF'
import json, os, shutil
C, base = "corpus_extra/fw1/corpus-ippx", "corpus_extra/fw1/corpus-base7/manifest.jsonl"
known = {json.loads(line)["id"] for line in open(base)}
rows = [r for r in map(json.loads, open(f"{C}/manifest.jsonl")) if r["class"] == "ipp" and r["id"] not in known]
open(f"{C}/manifest.jsonl", "w").writelines(json.dumps(r) + "\n" for r in rows)
for cls in os.listdir(f"{C}/samples"):
    if cls != "ipp":
        shutil.rmtree(f"{C}/samples/{cls}")
EOF
python3 -I scripts/fw1/merge.py "$C/corpus-ship23" "$C/corpus-base7" "$C/corpus-fw1v23" "$C/corpus-aug14" \
  "$C/corpus-hardU6" "$C/corpus-hc11x" "$C/corpus-lanes" "$C/corpus-m68kx" "$C/corpus-z8x" "$C/corpus-mcs251x" \
  "$C/corpus-ippx"

# 6. Held-out model and sample-level evaluation
$T/train_model --corpus "$C/corpus-ship23" --split train --out $M/ship23-train.bin
for c in base7 fw1v23 ds2h m68kx z8x mcs251x ippx; do
  $T/eval --corpus "$C/corpus-$c" --model $M/ship23-train.bin > reports/fw1/eval-ship23-train-$c.txt
done

# 7. File-level evaluation through the CLI with the held-out model
#    The held-out CLI is built in a worktree (a copy of the working tree), so the
#    repository's own model.bin is never replaced
(cd reports/fw1 &&
  python3 -I "$R/scripts/fw1/golden_files.py" "$R" "$FW" "$C/corpus-fw1v23" > golden23.tsv &&
  awk -F'\t' 'NR>1 && $2=="test"{print $1}' golden23.tsv > golden23-test.txt)
[ -d reports/wt-verify ] || git worktree add --detach reports/wt-verify HEAD
git ls-files -z --cached --others --exclude-standard | rsync -a --from0 --files-from=- ./ reports/wt-verify/
cp $M/ship23-train.bin reports/wt-verify/src/heuristics/model.bin
(cd reports/wt-verify && cargo build --release --locked --features cli --bin zrax) &&
  cp reports/wt-verify/target/release/zrax reports/fw1/bin/zrax-ship23-train
(cd reports/fw1 &&
  "$R/scripts/fw1/runlist.sh" "$PWD/bin/zrax-ship23-train" "$FW" "$PWD/golden23-test.txt" "$PWD/gold-ship23t.jsonl" &&
  python3 -I "$R/scripts/fw1/score.py" --golden golden23.tsv test gold-ship23t.jsonl)

# 8. Leave-one-group-out cross-validation of the µ'nSP families and the MAME data
#    sets: each fold is trained without the group's samples (and the windows mined
#    from them), and the group's fw1 files are classified with a CLI built on it.
#    crossval/unsp-files.tsv and crossval/mame21-files.tsv list `group<TAB>sha256` of
#    the files each group labels (UNSP_SETS ROMs; MAME graphics and sound ROMs).
#    Fold models go to their own directory: crossval_run.sh reuses a model of the
#    same fold name. It builds each fold's CLI in its own worktree (BUILD_TREE,
#    default reports/wt-crossval, a copy of the working tree), so the
#    repository's src/heuristics/model.bin is never replaced while folds run
#    (until 2026-11-04 it was, and a commit made during a run took a fold model).
python3 -I scripts/fw1/crossval.py "$C/corpus-ship23" mame-unsp: "$C/crossval-unsp23" \
  > reports/fw1/crossval/unsp23-folds.tsv
python3 -I scripts/fw1/crossval.py "$C/corpus-ship23" mame: "$C/crossval-mame23" \
  > reports/fw1/crossval/mame23-folds.tsv
mkdir -p $M/cv23
scripts/fw1/crossval_run.sh reports/fw1/crossval/unsp23-folds.tsv reports/fw1/crossval/unsp-files.tsv \
  "$FW" $M/cv23 reports/fw1/crossval/unsp23-results.tsv
scripts/fw1/crossval_run.sh reports/fw1/crossval/mame23-folds.tsv reports/fw1/crossval/mame21-files.tsv \
  "$FW" $M/cv23 reports/fw1/crossval/mame23-results.tsv

# 9. Ship model (all splits), the full-corpus run against the findings, and the
#    file-level ELF check on held-out ISAdetect files and the Hexagon libraries
$T/train_model --corpus "$C/corpus-ship23" --out $M/ship23-all.bin
cp $M/ship23-all.bin src/heuristics/model.bin
cargo build --release --locked --features cli --bin zrax && cp target/release/zrax reports/fw1/bin/zrax-ship23
(cd reports/fw1 &&
  ls "$FW" | grep -v '\.json$' > all-shas.txt &&
  "$R/scripts/fw1/runlist.sh" "$PWD/bin/zrax-ship23" "$FW" "$PWD/all-shas.txt" "$PWD/run-ship23.jsonl" &&
  python3 -I "$R/scripts/fw1/verify_findings.py" run-ship23.jsonl --fw "$FW" --show 20)
mkdir -p reports/fw1/elfcheck23
python3 -I scripts/fw1/elf_check.py reports/fw1/bin/zrax-ship23 reports/fw1/elfcheck23 \
  --ds2 /path/to/ds2 --elf "$H"
```

`runlist.sh` changes into `FW`, so the list and output paths must be
absolute. `--exclude-ids` uses `corpus-base2`, the base corpus without the
MN10300, PIC14, 8080/8085 and synthetic additions; none of those can equal an
fw1 sample. Training is deterministic. On 2026-11-04 the shipped model was
built with step 2 (`corpus-base7`) and steps 4 to 9 as listed, except that
the hard negatives of step 5 are those mined for `ship14` from
`corpus-fw1v13` (named `corpus-hardA6`, `corpus-hardB6`, `corpus-hardU6` and
`corpus-r2-6` in that run), and `corpus-lanes` is the one built for
`ship19`. Mining the hard negatives again with `ship16-train` found 4
windows, 2 of them new, which changed no answer, so they were not added.
Steps 0, 1 and 3 were run piecewise during the audit; a rebuild from scratch
in one go was not run.

## Golden labels

Labels never come from zrax output:

| Source | Evidence | Class |
| --- | --- | --- |
| fw1 ELF files | `e_machine` (microMIPS from `EF_MIPS_MICROMIPS`); 4 KiB blocks kept only if they hold a return instruction | ISA |
| Qualcomm `.bNN` segments | program header from the matching `.mdt`/`.b00`: executable, data or hash (`p_flags` bits 24-26 = 2); an executable segment that is at least 90% fill (its two most common 32-bit words) with under 1 KiB of other bytes is not labelled (four `cdsp.b03` hold a table and a string, `wpss.b03` 104 B of code before Hexagon NOP fill) | ISA / `neg_rodata` / skipped |
| Qualcomm data segments that hold another core's firmware | return idioms dense over the non-fill blocks, or in one 16 KiB region: paired Thumb push/pop with Thumb `BL` calls (float16 tables also form push/pop pairs), RISC-V, MSP430, AArch64, ARM, Hexagon, MIPS, SH frames, Xtensa `entry` with `ret.n` (`embedded_code_class`) | that class's code blocks; RISC-V skipped (32 or 64 bit unknown) |
| 8-bit PCM | adjacent-sample smoothness ≥ 0.6, and no code region (SH-4 sound ROMs carry code before their samples); `v4-40.ic29` excluded (8085 code; MAME `pce/tourvis.cpp`, I8085A) | `neg_media` |
| MAME ROM regions | the dump's SHA-1 is listed in a graphics or sound region (`mame_regions.py`, `mame_match.py`; tags such as `gfx1`, `sprites`, `c355spr`, `samples`, `oki`, `swp30`) | `neg_pixels` / `neg_media`, grouped by MAME set |
| MAME program ROMs | the dump is a program ROM of a set whose driver's CPU has a class and no decryption (`MAME_CODE_SETS`: `ppatrol`, I8085A) | `i8085`, held out (file-level test only) |
| MAME µ'nSP ROMs | program and system ROMs MAME maps flat into a µ'nSP SoC (`UNSP_SETS`: V.Smile, V.Smile Baby, SPG2xx and GPL162xx sets): instruction words traced from the vectors (`unsp_trace.py`; only where the vectors form a table, and without functions that are mostly one repeated word), and 64 KiB blocks without a traced instruction; a ROM without a vector table (`pokermor`'s `29dl640e.u3`: pixel data at the vectors) gives only such blocks and is expected to give no ISA | `unsp` (`unspeb` derived), `neg_media`; grouped by ROM family |
| Calibration maps, QCA board data | `swfl_*.159_010_001`, `QCA-ATH1xK-BOARD` magic | `neg_table` |
| 16-bit tables | VW `swfl_*` blocks whose 16-bit smoothness is at least 0.6 and that hold no code idioms (`table16`) | `neg_table` |
| FR firmware | raw images of at least 1 MiB with the banner "REALOS/FR is Realtime OS for FR Family" (Fujitsu's RTOS for its FR CPUs); the 4 KiB blocks holding an FR `RET`; grouped by the name's first token | `fr30` |
| AMD GPU command-processor microcode | gfx6 to gfx10.3 chip name plus `_mec`, `_mec2`, `_me`, `_pfp` or `_ce` (not RLC); F32 microcode has no class | `neg_table` |
| 8051 images | LJMP reset vector plus RETI/LJMP interrupt vectors | `i8051` |
| Cortex-M images | SRAM stack pointer plus Thumb handler addresses | `thumb` |
| ROM families | platform fixes the CPU: TR-DOS, Multiface, Opus, DISCiPLE, RC2014 (Z80); NAOMI BIOS with SH LE `rts` density ≥ 300/MiB | `z80`, `sh` |
| Z8 Intel HEX | Z8 monitors, Forth and BASIC compiler named as such, Intel HEX decoded | `z8` |
| PCI option ROMs, XT-IDE BIOS | PCI data structure code type 0 (x86), first 32 KiB; XT-IDE Universal BIOS by name (`ide_xt.bin,v…`) | `x86_16`, held out (file-level test only) |

`mn10200_code1.bin` is not labelled by its name: its bytes are
little-endian MIPS R3000 code that writes the PlayStation BIOS-ROM delay
register (`0x1F801010`).

Groups are firmware families (MAME sets for MAME labels), split 4:1 into
train and test by group hash.

## Results (2026-11-04, macOS AArch64)

Held-out, file level, through the CLI, on the 940 golden test files of
`corpus-fw1v23` (the same files as `corpus-fw1v22`'s):

| Model | Correct | Wrong | Rejected |
| --- | --- | --- | --- |
| Base corpus only (`m-base-train`, 924 files of `corpus-fw1v13`) | 71.6% | 241 | 2 (and 19 wrong variant) |
| Iteration 12 (`m12-train`, 924 files of `corpus-fw1v13`) | 99.0% | 8 | 1 |
| Shipped recipe, train split (`ship22-train`) | 100.0% | 0 | 0 |
| Shipped recipe, train split (`ship23-train`) | 100.0% | 0 | 0 |

Per label for `ship23-train` (and `ship22-train`), all at 100%: 8051
vectors (48), AMD GPU microcode (3), calibration maps (38), Cortex-M (195), ECU96 dumps (9), MAME
8085 program ROMs (3), MAME graphics (6) and sound (1), MAME µ'nSP ROMs
(4), option ROMs (115), PCM (182), Qualcomm code segments (276), Qualcomm
data segments (18), data segments with another core's code (4), REALOS/FR
images (2), DISCiPLE ROMs (6), 16-bit tables (6), XT-IDE (22) and Z8 HEX
(2). On the 3,158 training-split files, `ship23-all` gets 3,158 right
(`down2.fw`, the one file more than for `ship22-all`, among them). The
NAOMI BIOS label accepts SH-4 or SuperH (`golden_files.py` `LABEL_ISA`):
the NAOMI BIOS runs on an SH-4.

Sample level, `ship23-train` on held-out samples (whole samples); every
summary line equals `ship22-train`'s, the model without the `ipp` class and
the `down2.fw` sample:

| Corpus | Code samples | Correct | Exact | Wrong | Non-code | False accepts |
| --- | --- | --- | --- | --- | --- | --- |
| `corpus-base7` | 14,526 | 99.3% | 98.9% | 0.0% | 464 | 0.2% (1) |
| `corpus-fw1v23` | 983 | 99.2% | 99.1% | 0.0% | 536 | 0.9% (5) |
| `corpus-ds2h` | 3,438 | 100.0% | 100.0% | 0.0% | 0 | - |
| `corpus-m68kx` | 18 | 83.3% | 83.3% | 0.0% | 0 | - |
| `corpus-z8x` | 13 | 100.0% | 100.0% | 0.0% | 0 | - |
| `corpus-mcs251x` | 114 | 100.0% | 100.0% | 0.0% | 0 | - |
| `corpus-ippx` | 33 | 100.0% | 100.0% | 0.0% | 0 | - |

The fw1 false accepts are 5 of 300 held-out `.rodata`/`.data` samples (3
little-endian and 1 big-endian ARM, 1 CR16; iteration 12: 4). The three
rejected hand-written 68000 samples are under 1 KiB of code each. In
`corpus-base7`, one SuperH sample of 300 reads as SH-4, which counts as not
exact. With `ship23-train`, the MAME data ROM `5.u5` reads as WebAssembly at
0.73 from six weak windows; with `ship23-all` it gives no ISA. The 33
held-out IPP files share C library code with training files (143 of the 212
are static executables), so the `corpus-ippx` row is an upper bound for
other IPP code.

File level on the other two corpora (`elf_check.py`, `ship23-all`, as with
`ship22-all`): the
ISAdetect files 550-599 of each architecture (1,150, used by no corpus)
classify whole 1,150 right, and their largest executable section alone,
as raw bytes, 1,149 right, 0 wrong and 1 rejected (556 B, 42% of it a jump
table); one of the 50 Debian `sh4` sections reads as SH-4, which the
`sh4` label accepts. The 1,063 Hexagon libraries: 1,063 and 1,063 (they
are training data of the base corpus).

MAME ground truth beyond the golden labels (`mame_cpus.py`; `ship23-all`):

- Program ROMs whose MAME CPU maps to a zrax ISA (302 files, with the ROMs
  MAME declares inside macros; byte-lane dumps must give no ISA, word-lane
  dumps of 16-bit-instruction CPUs their ISA): 299 right. SH-4 155 of 155
  (SH-4 code without SH-4-only instructions is reported as SuperH, which
  counts; the NAOMI BIOS ROMs read as SH-4), SH-2 11 of 11 (none as SH-4),
  Z80 58 of 60, 8080/8085 21 of 21, 68000 13 of 13, Arm 10 of 10,
  6502 9 of 9, byte lanes 9 of 9 (no ISA), H8 4 of 4, µ'nSP 3 of 4, 8051 3
  of 3, 65816 2 of 2, x86 1 of 1. Without an answer: `29dl640e.u3` (above),
  which has no vector table, so no traceable code, and two data ROMs in CPU
  regions, `5.u5` (note tables at 0x8000 above the program ROM) and
  `epr-12648.ic25` (unsigned 8-bit samples around 0x81). None wrong: the
  Sega Hikaru BIOS `epr-23400.ic94` (SH-4 boot code with a 28 KiB ARM
  program inside), which read as ARM at 0.54 with `ship22-all`, reads as
  SH-4 since window weights within 5% tie and go to the most code bytes.
- Leave-one-family-out cross-validation of the µ'nSP class (each fold
  trained without the family's code and data blocks, `ship22` and `ship23`
  folds): all 8
  ROMs with traceable code (5 families) read as µ'nSP at 0.98 to 0.99 with
  their family held out; `29dl640e.u3`, which has no vector table, gives no
  ISA. On `ship19` and `ship21` folds, before the tracer's vector-table
  rule: the same 8, and `29dl640e.u3` inconclusive.
- Leave-one-set-out cross-validation of the MAME data labels (17 sets, each
  fold trained without that set's ROMs and the windows mined from them,
  `ship21`, `ship22` and `ship23` folds): all 52 graphics and sound ROMs are inconclusive with their
  own set held out, `cg.u23` (IGS sprites) included, which read as SH at 0.99
  in its `ship14` fold. The windows mined from the PGM sound ROM keep the
  group it had when they were mined (`mame:thegladpcb`; the ROM is now
  `mame:pgm`, the set that lists it first), so `crossval.py` makes two folds
  for it; a fold without both groups also leaves it inconclusive. On
  `ship19` folds: 51 of 51 ROMs of 16 sets.

Full corpus with `ship23-all` (`run-ship23.jsonl`), by
`verify_findings.py --fw`: every category is resolved, with no exception
list; where MAME names the file's CPU (`mame_cpus.tsv`), the answer must be
that CPU's ISA.

| Category | Fixed |
| --- | --- |
| PCM as code | 921 / 921 |
| Z80 as eZ80 | 408 / 408 |
| Calibration maps as ARC | 138 / 138 |
| ISA on Qualcomm data segments | 116 / 116 |
| MAME graphics and sound ROMs given an ISA | 52 / 52 |
| Weak TI formats on Qualcomm data segments | 43 / 43 |
| 8051 as WebAssembly | 31 / 31 |
| cLEMENCy | 28 / 28 |
| XT-IDE BIOS not read as 16-bit x86 | 13 / 13 |
| QCA board data as code | 10 / 10 |
| ELF with an unknown `e_machine` (0x1040, now the UniPhier IPP) | 6 / 6 |
| Name contradicts the ISA | 5 / 5 |
| Cortex-M missed | 3 / 3 |
| Other data as code | 2 / 2 |
| ELF bit width (PA-RISC) | 1 / 1 |

What each category needs, where the bytes or MAME show the finding's first
assumption was wrong:

- An ISA on a Qualcomm data segment or an 8-bit-PCM-like file counts when the
  file's own code region (strong return idioms) names that ISA, or MAME's CPU
  for it does; otherwise no ISA is required. `wpss.b06` declares `EM_386`
  around Cortex-M code; the header check reports no ISA for it.
- Z80 as eZ80: the defect is the 24-bit eZ80 claim. Z80, 8080/8085 and no
  claim count, and MAME's CPU decides where MAME names it. The `msvdx.bin.*`
  files are Imagination MSVDX video firmware, not Z80 code; they are
  inconclusive.
- Name-labelled files: `mn10200_code1.bin` and its 16-bit swap are MIPS;
  `hop_leds_pic12c671.bin` is PIC (14-bit core); the GH2 images are MN10300.
- Cortex-M missed: the `faceauth` images start with a Cortex-M vector table
  and hold RISC-V code as well; the boot marker reports Arm.
- ELF with `e_machine` 0x1040: the finding was an ISA guessed by the code
  model. The header now names the UniPhier IPP, the architecture the files'
  toolchain calls `ipp`; that answer counts, a guess does not.

Against the iteration-12 ship model, 206 files changed answer under
`ship14`; each is reviewed with the evidence checked on its bytes in
`reports/fw1/review-206.md` (`review206.py`): with `ship23-all`, 204 right,
0 wrong, 0 misses and 2 without a claim where the bytes do not establish
the ISA. `down2.fw` reads as MCS-251 (Linux `io_edgeport.c` loads it only on
80251-based Edgeports); its records are `mcs251` training data, so that is
fit; `vs-bios.rom` reads as 68000 after a 16-bit swap. The 45 files that
change from `ship22-all` to `ship23-all` (ISA or format): 19 SuperH ELF files
whose `e_flags` name an SH-4 machine to SH-4, 18 EZ-USB 8051 images to the
`ihex2fw` format (still 8051), the 6 ELF files of machine 0x1040 to the IPP,
`down2.fw` to MCS-251 and the Hikaru BIOS `epr-23400.ic94` from ARM to SH-4.
The 55 files that changed ISA from `ship21-all` to
`ship22-all` are 48 Sega NAOMI, Chihiro and Hikaru BIOS ROMs from SuperH to
SH-4 (MAME SH-4 CPUs), four Zilog Intel HEX programs to Z8 (the programs
the Z8 archive also holds), `sapp105.bin`/`sapp106.bin` to FR30 (FR `RET`
at 4.2 per KiB) and the Switch 2 camera firmware to Arm; two Z8 answers
gain the variant `ez8`. The 8 that changed from `ship19-all` to
`ship21-all` are `POSBOX.ORI` (MCS-96), the odd-length BMW dump and
`vs-bios.rom` (68000 after a swap), `bootbug1.3.bin` and the Lapis
ColorServer ROM (68000), and the three Atomiswave BIOS ROMs (SH instead of
Arm).

The submitted `failures` and `z8` folders are reviewed file by file in
`reports/failures/README.md`.

`cargo test --all-features --locked` passes with `ship23-all` and the
external fixtures set (`D10_FIXTURE`, `TI_C55X_FIXTURE`): 3,007 passed, 0
failed, 7 ignored; of the ignored, the D10 reference test passes when run with
`D10_REFERENCE_DIR` (records written by the supplied extractor), one needs a
`UARP_FIXTURE` that is not on this machine, and five are diagnostic tools.
`npm test` after `./build-web.sh` with the same fixtures: 406 tests, 406
passed, 0 skipped, 0 failed.

## Known limits

- Vendor-compiled MCS-251 code is one file (`down2.fw`), which is training
  data; raw SH-4 code without SH-4-only instructions is reported as SuperH
  (ELF files report SH-4 when `e_flags` name an SH-4 machine).
- Mixed images give the family with the most window weight (ties within 5%
  to the most code bytes); the other family appears only with `--multi-isa`.
- UniPhier IPP: no instruction is decoded, and the parcel order inside the
  words of byte-swapped IPP images is not established (`docs/ipp.md`).
- Hand-written 68000 training code is 359 KB: most 68000 sources on GitHub
  are for asm68k, vasm or Devpac, which AS does not assemble.
- StuffIt archives are not parsed.
- Single byte lanes of 68000 code give no ISA since `neg_lanes`; the lanes
  interleaved with `--interleave` do (`cpu30*` 0.99, `wuerfel_fix*` 0.99).

## Files

| Script | Purpose |
| --- | --- |
| `fw1_corpus.py` | golden corpus builder (uses `scripts/build_corpus.py`) |
| `golden_files.py` | file-level labels with split, for CLI scoring |
| `holdout.py` | reduce a corpus to one source's rows not in the training corpus, as test |
| `mame_regions.py`, `mame_match.py` | MAME ROM regions by SHA-1 (ROM macros of the driver and its local headers expanded), and the fw1 files MAME lists |
| `mame_cpus.py` | the CPU MAME runs each listed program ROM on, its zrax ISA, and the dump's bus layout (whole, byte lanes, word lanes) |
| `unsp_trace.py` | µ'nSP instruction words of a ROM by recursive descent from the vectors |
| `lane_negatives.py` | byte lanes of code samples as the `neg_lanes` data class |
| `crossval.py`, `crossval_run.sh` | leave-one-group-out folds of a corpus; train each fold and classify its group's files with a CLI built on it |
| `examples/family_split.rs` | per raw file, the two families with the most window weight and the first code window's family (mixed images, weight ties) |
| `runlist.sh`, `runall.sh` | run a zrax CLI over listed / all fw1 files to JSONL (`runall.sh` records no rejections; use `runlist.sh` with `all-shas.txt`) |
| `score.py` | score CLI runs against `golden.tsv` |
| `elf_check.py` | file-level check of a CLI on labelled ELF corpora (ISAdetect ds2 by architecture, Hexagon libraries by `e_machine`): the whole file and its largest executable section as raw bytes |
| `diffrun.py` | diff two full runs and count changed files per findings category |
| `verify_findings.py` | check a full run against what each findings category needs |
| `cmpeval.py` | compare two `examples/eval.rs` reports per class |
| `merge.py` | merge corpora by symlink (`merge.sh` is the slow original) |
| `hardlist.py` + `examples/mine_hard.rs` | hard-negative mining |
| `aug_neg.py` | transform-augmented negatives |
| `dump.py`, `heads.py`, `pil.py`, `smooth.py`, `entropy.py` | per-file tables |
| `findings.py`, `magics.py`, `xtab.py`, `namekw.py` | audit of classification errors |
| `formats_of.py`, `tisurvey.py` | format and weak-TI-layout survey through the CLI |
| `transform_scan.py` | `scan_debug` on one transformed reading of a file |
| `elfsec.py`, `idioms.py`, `shidiom.py` | spot checks (ELF sections, TriCore/ARC and SuperH idiom density) |

`scripts/pic14_asm_corpus.py` (one level up) builds the hand-written PIC14
corpus. `examples/reading_share.rs` prints each reading of a file with its
confidence and code share (`--stored` for the stored reading only).

`reports/fw1/worktree-neg_calib-class.patch` is the `neg_calib` data class
tried in iterations 4 and 10; it is not applied. The other corpora under
`corpus_extra/fw1/` are earlier iterations, kept for comparison.
