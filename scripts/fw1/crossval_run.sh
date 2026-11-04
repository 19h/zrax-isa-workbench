#!/usr/bin/env bash
set -euo pipefail
# Train and test the leave-one-group-out folds that crossval.py wrote: for
# each fold, train a model on the fold's corpus (all splits), build the CLI
# with it, and classify the held-out group's fw1 files with that CLI.
#
# FOLDS: crossval.py output (`group<TAB>fold directory` per line).
# FILES: `group<TAB>sha256` per line, the fw1 files each group labels.
# OUT:   `group<TAB>sha256<TAB>isa<TAB>confidence` per file ("<rejected>"
#        for no answer).
# The CLI embeds src/heuristics/model.bin, so each fold copies its model
# there; the model that was there is restored on exit.
#
# Usage (from the repository root):
#   scripts/fw1/crossval_run.sh FOLDS FILES FW1_DIR MODEL_DIR OUT

folds="$1"
files="$2"
fw="$3"
model_dir="$4"
out="$5"

shipped="$(mktemp "$model_dir/shipped.XXXXXX")"
cp src/heuristics/model.bin "$shipped"
restore() {
    cp "$shipped" src/heuristics/model.bin
    rm -f "$shipped"
}
trap restore EXIT

cargo build --release --locked --features cli --example train_model
: > "$out"
while IFS=$'\t' read -r group fold; do
    name="$(basename "$fold")"
    model="$model_dir/cv-$name.bin"
    if [[ ! -s "$model" ]]; then
        target/release/examples/train_model --corpus "$fold" --out "$model"
    fi
    cp "$model" src/heuristics/model.bin
    cargo build --release --locked --features cli --bin zrax
    awk -F'\t' -v g="$group" '$1 == g { print $2 }' "$files" | while read -r sha; do
        json="$(target/release/zrax -f json "$fw/$sha" 2>/dev/null || true)"
        printf '%s' "$json" | python3 -I -c '
import json, sys
raw = sys.stdin.read()
result = json.loads(raw) if raw.strip() else {}
print("\t".join((sys.argv[1], sys.argv[2], str(result.get("isa", "<rejected>")),
                 str(round(result.get("confidence", 0.0), 3)))))
' "$group" "$sha" >> "$out"
    done
done < "$folds"
