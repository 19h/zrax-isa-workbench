# Ambiguous File Routing Logic

## Document Status

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Last Updated | 2026-03-02 |
| Parent | [01-overview.md](01-overview.md) |

---

## 1. Purpose

Not every binary can be classified with high confidence. Firmware images with padding, encrypted payloads, data sections, or genuinely unusual ISAs may produce low-confidence or ambiguous results. Rather than forcing these files into a potentially incorrect classification path, the system routes them to a separate ambiguous bucket where they can be reviewed, manually classified, or reclassified when the classifier improves.

---

## 2. Routing Decision Flowchart

```
                         ┌──────────────────┐
                         │  File Classified  │
                         └────────┬─────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │ Did classifier return error? │
                    └──────────┬──────────────┬────┘
                           yes │              │ no
                               ▼              ▼
                    ┌──────────────┐  ┌───────────────────────┐
                    │ Route to     │  │ Is ISA == Unknown(n)? │
                    │ ambiguous/   │  └──────┬──────────┬─────┘
                    │ reason=error │      yes │          │ no
                    └──────────────┘         ▼          ▼
                                  ┌──────────────┐ ┌──────────────────────────────┐
                                  │ Route to     │ │ confidence >= min_confidence? │
                                  │ ambiguous/   │ │ (default: 0.30)              │
                                  │ reason=      │ └──────┬──────────────────┬────┘
                                  │ unknown_isa  │     no │                  │ yes
                                  └──────────────┘       ▼                  ▼
                                            ┌──────────────┐ ┌──────────────────────────┐
                                            │ Route to     │ │ margin >= min_margin?     │
                                            │ ambiguous/   │ │ (default: 0.20)           │
                                            │ reason=      │ └──────┬──────────────┬─────┘
                                            │ low_conf     │     no │              │ yes
                                            └──────────────┘       ▼              ▼
                                                      ┌──────────────┐ ┌──────────────────┐
                                                      │ Route to     │ │ Route to         │
                                                      │ ambiguous/   │ │ classified/      │
                                                      │ reason=      │ │ fmt=.../isa=.../ │
                                                      │ low_margin   │ │ bits=.../endian= │
                                                      └──────────────┘ └──────────────────┘
```

---

## 3. Routing Rules in Detail

### 3.1 Rule 1: Classification Error

**Condition**: The classifier returned an error (e.g., `ClassifierError::HeuristicInconclusive`, file too small, parse error that prevented any classification).

**Reason code**: `error`

**View key**: `views/ambiguous/reason=error/fmt=<detected_format_or_raw>/<ab>/<cd>/<hash>__<name>.ref`

**Metadata**: `routing.status = "ambiguous"`, `routing.ambiguous_reason = "error"`, notes will contain the error message.

**Rationale**: If the classifier can't even produce a result, we don't want to guess. The format detection (magic bytes) is still attempted and usually succeeds, so we use whatever format was detected. ISA/bits/endian are taken from the error result or defaulted to `unknown`/0/`le`.

### 3.2 Rule 2: Unknown ISA

**Condition**: The classifier produced a result, but the detected ISA is `Isa::Unknown(n)` — an ELF or PE with an unrecognized machine type, or a raw binary where no heuristic scored positively.

**Reason code**: `unknown_isa`

**View key**: `views/ambiguous/reason=unknown_isa/fmt=<format>/<ab>/<cd>/<hash>__<name>.ref`

**Metadata**: `routing.status = "ambiguous"`, `routing.ambiguous_reason = "unknown_isa"`.

**Rationale**: An `Unknown` ISA means we literally don't know what this is. It would be misleading to file it under `isa=unknown_0x1234` in the classified tree. Better to flag it explicitly for human review.

### 3.3 Rule 3: Low Confidence

**Condition**: The primary ISA confidence is below `min_confidence` (default: 0.30).

**Reason code**: `low_conf`

**View key**: `views/ambiguous/reason=low_conf/fmt=<format>/<ab>/<cd>/<hash>__<name>.ref`

**Metadata**: `routing.status = "ambiguous"`, `routing.ambiguous_reason = "low_conf"`.

**What this means**: The classifier's best guess scored less than 30% of the total score across all ISAs. This typically happens with:
- Data files (tables, bitmaps, certificates) that aren't code
- Encrypted or compressed payloads
- Very short files where statistical signal is weak
- Genuinely unusual ISAs that the classifier doesn't cover well

**Threshold tuning**: The default 0.30 was chosen because:
- Heuristic confidence is not a share of scores any more: it is the winning family's share of calibrated code evidence times the strength of that evidence (`1 - exp(-E/0.5)`, where one clean 1 KB code window contributes E ≈ 1). On the held-out corpus, results at or above 0.30 are wrong well under 1% of the time.
- Lowering to 0.20 admits more tiny snippets at a small cost in false accepts on data.
- Raising it trades recall for precision; heuristic confidence is calibrated on held-out data (`examples/eval.rs`), and padding/data windows do not dilute it (they are recognised and excluded).

### 3.4 Rule 4: Low Margin

**Condition**: The winner's margin over the runner-up is below `min_margin` (default: 0.20).

**Margin formula**: `margin = (winner_score - runner_up_score) / runner_up_score`, where

- `winner_score` is the top candidate's `raw_score`, and
- `runner_up_score` is the `raw_score` of the best candidate from a **different ISA family** (MIPS32 vs MIPS64, x86 vs x86-64, A32 vs Thumb are the same family and never count as competition).

For headerless data, `raw_score` is the code model's evidence in bits: how much better the candidate explains the file's code windows than the best non-code hypothesis (see `docs/architecture/raw-code-model.md`). For container formats (ELF, PE, ...) there are no candidates and the margin is 1.0.

A margin of 0.20 means the winner's evidence is at least 20% larger than the best other family's. Note that the heuristic `confidence` already folds in the per-window family margin, so this rule mostly matters for images that genuinely contain several ISAs.

**Reason code**: `low_margin`

**View key**: `views/ambiguous/reason=low_margin/fmt=<format>/<ab>/<cd>/<hash>__<name>.ref`

**Metadata**: `routing.status = "ambiguous"`, `routing.ambiguous_reason = "low_margin"`. The `candidates` array shows the close competition.

**What this means**: The classifier identified a winner, but another ISA family explains a comparable amount of the code. Typical cause: a multi-ISA image (e.g. AArch64 application processor code plus Cortex-M Thumb firmware in one file). Use `zrax --multi-isa` on such files.

### 3.5 Rule Priority

The rules are evaluated in order (1 → 4). The **first** matching rule determines the reason code. This means:
- A file that errors out gets `error`, not `low_conf` (even though it would also qualify)
- A file with `Unknown` ISA and low confidence gets `unknown_isa` (the more specific reason)
- A file with low confidence and low margin gets `low_conf` (confidence is checked before margin)

---

## 4. Confidence Bands

For metadata and statistics purposes, confidence is bucketed into bands:

| Band | Confidence Range | Typical Meaning |
|------|-----------------|-----------------|
| `high` | >= 0.80 | Very confident. Usually from format headers (ELF, PE, Mach-O) or very strong heuristic match. |
| `medium` | 0.50 - 0.79 | Moderately confident. Heuristic match with clear winner but some ambiguity. |
| `low` | 0.30 - 0.49 | Low confidence but above ambiguous threshold. The classification is a best guess. |
| `very_low` | < 0.30 | Below threshold → routed to ambiguous. |

Confidence bands are stored in the metadata (`routing.confidence_band`) for filtering and reporting. They are **not** in the S3 key path because:
1. Reclassification would change confidence, requiring key migration
2. Confidence is continuous; any banding is arbitrary
3. The primary use case for confidence is filtering in API responses, not browsing

---

## 5. What Happens in the Ambiguous View Tree

### 5.1 Structure

```
views/ambiguous/
├── reason=low_conf/
│   ├── fmt=raw/
│   │   └── ab/cd/<hash>__<name>.ref
│   ├── fmt=elf/
│   │   └── ...
│   └── fmt=pe/
│       └── ...
├── reason=low_margin/
│   ├── fmt=raw/
│   └── ...
├── reason=error/
│   ├── fmt=raw/
│   └── ...
└── reason=unknown_isa/
    ├── fmt=elf/
    └── ...
```

Note: ISA/bits/endian are **not** in the ambiguous path. The classification for ambiguous files is unreliable, so the path only contains:
- Reason (why it's ambiguous)
- Format (usually reliable even for ambiguous files, because format detection uses magic bytes)
- Hash shard (for fanout)
- Filename (with hash for uniqueness)

The `.ref` file still contains the full classification result (best-guess ISA, confidence, candidates), so the web UI can display it. But the path structure doesn't encode this unreliable information.

### 5.2 Metadata for Ambiguous Files

The `.meta.json` for ambiguous files has the same schema as classified files. The key differences:
- `routing.status = "ambiguous"`
- `routing.ambiguous_reason` is set to the reason code
- `routing.confidence_band` is typically `very_low`
- `candidates` array is particularly important — it shows how close the top ISAs are
- The `view_key` points to the ambiguous path, not the classified path

### 5.3 Ledger Entries for Ambiguous Files

Ambiguous files are recorded in:
- **Global ledger**: Always. `status = "ambiguous"`, `amb_reason = "<reason>"`.
- **ISA-specific ledger**: **Yes**, using the best-guess ISA. Even though the classification is uncertain, recording it in the ISA ledger allows reclassification workflows to find and re-process these files. The `status = "ambiguous"` field distinguishes them from confident classifications.

---

## 6. Reclassification of Ambiguous Files

Ambiguous files are prime candidates for reclassification when:
- The classifier is improved (new ISA support, better heuristics, bug fixes)
- Thresholds are adjusted (lower `min_confidence` or `min_margin`)
- Manual review identifies the correct ISA

### 6.1 Single File Reclassification

Via web UI "Reclassify" button or API endpoint. See [07-web-ui-flows.md](07-web-ui-flows.md) Section 7.

### 6.2 Batch Reclassification

A new CLI command (future):

```bash
zrax reclassify --bucket my-bucket --endpoint https://s3.hetzner.com \
  --prefix isa-harvester/v1 --filter status=ambiguous -j 16
```

This would:
1. List all ambiguous `.ref` files via `ListObjectsV2` on `views/ambiguous/`
2. For each: download binary → reclassify → update metadata → move ref from ambiguous to classified (or keep in ambiguous if still below threshold)
3. Record all changes in a reclassification ledger

---

## 7. Statistics Impact

The stats file (`stats/current.json`) tracks:
- `by_status.ambiguous`: Total ambiguous files
- `breakdown_by_status.ambiguous_low_conf`: Count by each reason
- `breakdown_by_status.ambiguous_low_margin`: Count by each reason
- `breakdown_by_status.ambiguous_error`: Count by each reason
- `breakdown_by_status.ambiguous_unknown_isa`: Count by each reason

The dashboard shows ambiguous files prominently to encourage review and classifier improvement.

---

## 8. Configuration Reference

| Parameter | CLI Flag | API Field | Default | Description |
|-----------|---------|-----------|---------|-------------|
| Minimum confidence | `--min-confidence` | `parameters.min_confidence` | 0.30 | Below this → `low_conf` |
| Minimum margin | `--min-margin` | `parameters.min_margin` | 0.20 | Below this → `low_margin` |

Both parameters are recorded in the run manifest for reproducibility.
