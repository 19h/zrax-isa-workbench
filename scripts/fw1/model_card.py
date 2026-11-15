#!/usr/bin/env python3
"""Build the model card that ships beside `src/heuristics/model.bin`.

The embedded model is trained on every split, so its held-out record is that
of its sibling trained on the train split only. This script joins:

- the per-corpus cards `examples/eval.rs --card` writes for that sibling
  (per class and input kind: n, correct, exact, wrong, rejected), and
- the manifest of the corpus the embedded model is trained on (per class:
  samples, distinct groups, distinct sources),

into one JSON document that names both models by SHA-256.

Output layout (`src/heuristics/card.rs` reads it):

    {"model": ..., "model_sha256": ..., "measured_model": ...,
     "measured_model_sha256": ..., "measured_on": "YYYY-MM-DD",
     "corpora": [...],
     "classes": {"<class>": {"training": {"samples", "groups", "sources"},
                             "held_out": {"file": {...}, "128": {...}}}}}

Usage:

    python3 -I scripts/fw1/model_card.py \
        --model src/heuristics/model.bin --name ship24-all \
        --measured reports/fw1/models/ship24-train.bin --measured-name ship24-train \
        --manifest corpus_extra/fw1/corpus-ship24/manifest.jsonl \
        --date 2026-11-15 --out src/heuristics/model_card.json \
        reports/fw1/card-ship24-train-*.json
"""

import argparse
import hashlib
import json
import sys

COUNTS = ("n", "correct", "exact", "wrong", "rejected")


def sha256_of(path):
    """Lowercase hex SHA-256 of the file at `path`."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def training_of(manifest_path):
    """Per class: samples, distinct groups and distinct sources."""
    groups = {}
    sources = {}
    samples = {}
    with open(manifest_path, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            name = row["class"]
            samples[name] = samples.get(name, 0) + 1
            groups.setdefault(name, set()).add((row.get("source", ""), row.get("group", "")))
            sources.setdefault(name, set()).add(row.get("source", ""))
    return {
        name: {
            "samples": samples[name],
            "groups": len(groups[name]),
            "sources": len(sources[name]),
        }
        for name in samples
    }


def add_card(held_out, card, measured_sha256):
    """Add one corpus card's tallies; the card must be of the measured model."""
    if card["model_sha256"] != measured_sha256:
        sys.exit(
            f"{card['corpus']}: evaluated with model {card['model_sha256']}, "
            f"not the measured model {measured_sha256}"
        )
    for name, inputs in card["classes"].items():
        for kind, tally in inputs.items():
            total = held_out.setdefault(name, {}).setdefault(kind, dict.fromkeys(COUNTS, 0))
            for count in COUNTS:
                total[count] += tally[count]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", required=True, help="the embedded model.bin")
    parser.add_argument("--name", required=True, help="name of the embedded model")
    parser.add_argument("--measured", required=True, help="the held-out sibling model")
    parser.add_argument("--measured-name", required=True, help="name of that model")
    parser.add_argument("--manifest", required=True, help="manifest.jsonl of the training corpus")
    parser.add_argument("--date", required=True, help="date of the evaluation, YYYY-MM-DD")
    parser.add_argument("--out", required=True, help="model_card.json to write")
    parser.add_argument("cards", nargs="+", help="cards written by `eval --card`")
    args = parser.parse_args()

    measured_sha256 = sha256_of(args.measured)
    held_out = {}
    corpora = []
    for path in sorted(args.cards):
        with open(path, encoding="utf-8") as handle:
            card = json.load(handle)
        add_card(held_out, card, measured_sha256)
        corpora.append(card["corpus"])

    training = training_of(args.manifest)
    classes = {
        name: {
            "training": training.get(name, {"samples": 0, "groups": 0, "sources": 0}),
            "held_out": held_out.get(name, {}),
        }
        for name in sorted(set(training) | set(held_out))
    }
    document = {
        "model": args.name,
        "model_sha256": sha256_of(args.model),
        "measured_model": args.measured_name,
        "measured_model_sha256": measured_sha256,
        "measured_on": args.date,
        "corpora": corpora,
        "classes": classes,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
