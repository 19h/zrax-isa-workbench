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
# The CLI embeds src/heuristics/model.bin. The folds are built in a copy of
# the working tree (BUILD_TREE, default reports/wt-crossval, a git worktree
# created on first use), so the repository's own model.bin is never
# replaced: a commit made while folds run cannot pick up a fold model.
#
# Usage (from the repository root):
#   scripts/fw1/crossval_run.sh FOLDS FILES FW1_DIR MODEL_DIR OUT

repo="$(pwd)"
# Path arguments, relative to the repository root unless absolute.
absolute() {
    if [[ "$1" == /* ]]; then
        printf '%s\n' "$1"
    else
        printf '%s\n' "$repo/$1"
    fi
}
folds="$(absolute "$1")"
files="$(absolute "$2")"
fw="$(absolute "$3")"
model_dir="$(absolute "$4")"
out="$(absolute "$5")"
build_tree="${BUILD_TREE:-reports/wt-crossval}"

if [[ ! -d "$build_tree" ]]; then
    git worktree add --detach "$build_tree" HEAD
fi
# Copy the working tree's tracked and untracked (not ignored) files, so the
# folds run the code as it is now, committed or not.
git ls-files -z --cached --others --exclude-standard \
    | rsync -a --from0 --files-from=- ./ "$build_tree/"

cd "$build_tree"
cargo build --release --locked --features cli --example train_model
: > "$out"
while IFS=$'\t' read -r group fold; do
    name="$(basename "$fold")"
    model="$model_dir/cv-$name.bin"
    if [[ ! -s "$model" ]]; then
        target/release/examples/train_model --corpus "$(absolute "$fold")" --out "$model"
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
