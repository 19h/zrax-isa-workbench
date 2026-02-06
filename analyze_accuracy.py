#!/usr/bin/env python3
"""
Rigorous ISA classifier accuracy analysis.

Tests the classifier against:
  1. Raw object blobs (ground-truth ISA known from directory structure)
  2. Synthetic firmware images (ground-truth from JSON metadata)

Produces a detailed report of per-ISA accuracy, failure modes,
confusion patterns, and score distributions.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLASSIFIER_BIN = Path(__file__).parent / "target" / "release" / "isa-classify"
OBJECTS_DIR = Path(__file__).parent.parent / "armgen" / "objects"
FIRMWARE_DIR = Path(__file__).parent.parent / "armgen" / "firmware"

# Map from oracle family names to classifier ISA names
FAMILY_TO_ISA = {
    "arm32": "arm",
    "thumb": "arm",  # Thumb is ARM sub-mode
    "aarch64": "aarch64",
    "x86": "x86",
    "x86_64": "x86_64",
    "riscv32": "riscv32",
    "riscv64": "riscv64",
    "mips32_be": "mips",
    "mips32_le": "mips",
    "mips64_be": "mips64",
    "mips64_le": "mips64",
    "ppc32": "ppc",
    "ppc64_be": "ppc64",
    "ppc64_le": "ppc64",
    "sparc32": "sparc",
    "sparc64": "sparc64",
    "s390x": "s390x",
    "loongarch64": "loongarch64",
    "avr": "avr",
    "msp430": "msp430",
    "hexagon": "hexagon",
}

# Acceptable aliases — if classifier returns any of these, count as correct
ACCEPTABLE_ALIASES = {
    "arm": {"arm", "aarch64"},  # some ARM code can look like AArch64
    "mips": {"mips", "mips64"},
    "mips64": {"mips", "mips64"},
    "riscv32": {"riscv32", "riscv64"},
    "riscv64": {"riscv32", "riscv64"},
    "ppc": {"ppc", "ppc64"},
    "ppc64": {"ppc", "ppc64"},
    "sparc": {"sparc", "sparc64"},
    "sparc64": {"sparc", "sparc64"},
}


@dataclass
class ClassifyResult:
    """Result from running the classifier on a single file."""
    path: str
    expected_isa: str
    expected_family: str  # oracle family name
    detected_isa: str | None
    confidence: float
    correct: bool
    file_size: int
    error: str | None = None
    all_candidates: list[dict] = field(default_factory=list)


def run_classifier(path: str, mode: str = "thorough") -> dict:
    """Run the classifier on a single file and return parsed JSON."""
    try:
        result = subprocess.run(
            [str(CLASSIFIER_BIN), "-f", "json", "-m", mode,
             "--min-confidence", "0.01", str(path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "path": path}
        output = result.stdout.strip()
        if not output:
            return {"error": "empty output", "path": path}
        data = json.loads(output)
        if isinstance(data, list):
            return data[0] if data else {"error": "empty list", "path": path}
        return data
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "path": path}
    except json.JSONDecodeError as e:
        return {"error": f"json parse: {e}", "path": path}
    except Exception as e:
        return {"error": str(e), "path": path}


def classify_blob(args: tuple) -> ClassifyResult:
    """Classify a single blob file. Runs in worker process."""
    path, expected_family = args
    expected_isa = FAMILY_TO_ISA.get(expected_family, expected_family)
    file_size = os.path.getsize(path)

    result = run_classifier(path)

    if "error" in result:
        return ClassifyResult(
            path=path, expected_isa=expected_isa,
            expected_family=expected_family,
            detected_isa=None, confidence=0.0,
            correct=False, file_size=file_size,
            error=result["error"],
        )

    # Extract detected ISA — JSON keys: isa (string), confidence (float),
    # candidates (list of {isa, raw_score, confidence, ...})
    detected = (result.get("isa") or "").lower()
    confidence = result.get("confidence", 0.0)
    candidates = result.get("candidates", [])

    # Determine correctness
    expected_lower = expected_isa.lower()
    detected_lower = (detected or "").lower()

    # Direct match
    correct = detected_lower == expected_lower
    # Alias match
    if not correct and expected_lower in ACCEPTABLE_ALIASES:
        correct = detected_lower in ACCEPTABLE_ALIASES[expected_lower]
    # Also check if detected is a sub-variant
    if not correct:
        correct = expected_lower in detected_lower or detected_lower in expected_lower

    return ClassifyResult(
        path=path, expected_isa=expected_isa,
        expected_family=expected_family,
        detected_isa=detected, confidence=confidence,
        correct=correct, file_size=file_size,
        all_candidates=candidates,
    )


def run_classifier_multi_isa(path: str) -> dict:
    """Run the classifier in multi-ISA mode and return parsed JSON."""
    try:
        result = subprocess.run(
            [str(CLASSIFIER_BIN), "--multi-isa", "-f", "json", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "path": path}
        output = result.stdout.strip()
        if not output:
            return {"error": "empty output", "path": path}
        data = json.loads(output)
        return data
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "path": path}
    except json.JSONDecodeError as e:
        return {"error": f"json parse: {e}", "path": path}
    except Exception as e:
        return {"error": str(e), "path": path}


def classify_firmware_section(args: tuple) -> ClassifyResult:
    """Classify a firmware file using multi-ISA windowed detection."""
    bin_path, json_path = args
    file_size = os.path.getsize(bin_path)

    # Read ground truth
    with open(json_path) as f:
        meta = json.load(f)

    primary_family = meta["isa"]["primary"]
    expected_isa = FAMILY_TO_ISA.get(primary_family, primary_family)
    all_families = meta["isa"]["all"]

    # Use multi-ISA mode for firmware
    result = run_classifier_multi_isa(bin_path)

    if "error" in result:
        return ClassifyResult(
            path=bin_path, expected_isa=expected_isa,
            expected_family=primary_family,
            detected_isa=None, confidence=0.0,
            correct=False, file_size=file_size,
            error=result["error"],
        )

    # Extract all detected ISAs from multi-ISA output
    detected_isas_raw = result.get("detected_isas", [])
    detected_set = set()
    for d in detected_isas_raw:
        isa_name = (d.get("isa") or "").lower()
        if isa_name:
            detected_set.add(isa_name)

    primary_detected = (result.get("primary_isa") or "").lower()
    confidence = 0.0  # Multi-ISA mode doesn't have a single confidence

    # For display purposes, show all detected ISAs joined
    detected_display = "+".join(sorted(detected_set)) if detected_set else "none"

    # Build acceptable set from ground truth
    acceptable = set()
    for fam in all_families:
        isa_name = FAMILY_TO_ISA.get(fam, fam).lower()
        acceptable.add(isa_name)
        if isa_name in ACCEPTABLE_ALIASES:
            acceptable.update(ACCEPTABLE_ALIASES[isa_name])

    # Correct if ANY expected ISA is in the detected set
    correct = bool(detected_set & acceptable)

    return ClassifyResult(
        path=bin_path, expected_isa=expected_isa,
        expected_family=primary_family,
        detected_isa=detected_display, confidence=confidence,
        correct=correct, file_size=file_size,
        all_candidates=[],
    )


def collect_blob_tasks(objects_dir: Path, max_per_family: int = 0) -> list[tuple]:
    """Collect (path, family) pairs for all blob files."""
    tasks = []
    for family_dir in sorted(objects_dir.iterdir()):
        if not family_dir.is_dir():
            continue
        family = family_dir.name
        count = 0
        for bin_file in family_dir.rglob("*.bin"):
            tasks.append((str(bin_file), family))
            count += 1
            if max_per_family and count >= max_per_family:
                break
    return tasks


def collect_firmware_tasks(firmware_dir: Path, max_per_dir: int = 0) -> list[tuple]:
    """Collect (bin_path, json_path) pairs for firmware images."""
    tasks = []
    for subdir in sorted(firmware_dir.iterdir()):
        if not subdir.is_dir():
            continue
        count = 0
        for bin_file in sorted(subdir.glob("*.bin")):
            json_file = bin_file.with_suffix(".json")
            if json_file.exists():
                tasks.append((str(bin_file), str(json_file)))
                count += 1
                if max_per_dir and count >= max_per_dir:
                    break
    return tasks


def run_analysis(tasks, classify_fn, jobs: int, desc: str) -> list[ClassifyResult]:
    """Run classification tasks in parallel."""
    results = []
    total = len(tasks)
    start = time.time()

    print(f"\n{'='*70}")
    print(f"  {desc}: {total} files, {jobs} workers")
    print(f"{'='*70}")

    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(classify_fn, t): t for t in tasks}
        done = 0
        for future in as_completed(futures):
            done += 1
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
            if done % 200 == 0 or done == total:
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                print(f"  [{done:5d}/{total}] {rate:.0f} files/s", flush=True)

    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.1f}s ({total/elapsed:.0f} files/s)")
    return results


def print_report(results: list[ClassifyResult], title: str):
    """Print detailed accuracy report."""
    if not results:
        print(f"\n  No results for {title}")
        return

    print(f"\n{'='*70}")
    print(f"  REPORT: {title}")
    print(f"{'='*70}")

    total = len(results)
    correct = sum(1 for r in results if r.correct)
    errors = sum(1 for r in results if r.error)
    wrong = total - correct - errors

    print(f"\n  Overall: {correct}/{total} correct "
          f"({100*correct/total:.1f}%), "
          f"{wrong} wrong, {errors} errors")

    # --- Per-family breakdown ---
    family_stats: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "correct": 0, "errors": 0,
        "confidences": [], "wrong_detections": [],
        "sizes": [],
    })

    for r in results:
        s = family_stats[r.expected_family]
        s["total"] += 1
        s["sizes"].append(r.file_size)
        if r.error:
            s["errors"] += 1
        elif r.correct:
            s["correct"] += 1
            s["confidences"].append(r.confidence)
        else:
            s["wrong_detections"].append(r.detected_isa or "none")

    print(f"\n  {'Family':<18} {'Acc%':>6} {'Correct':>8} {'Wrong':>6} "
          f"{'Err':>5} {'Total':>6} {'AvgConf':>8} {'AvgSize':>10}")
    print(f"  {'-'*18} {'-'*6} {'-'*8} {'-'*6} {'-'*5} {'-'*6} {'-'*8} {'-'*10}")

    for family in sorted(family_stats.keys()):
        s = family_stats[family]
        acc = 100 * s["correct"] / s["total"] if s["total"] else 0
        avg_conf = (sum(s["confidences"]) / len(s["confidences"])
                    if s["confidences"] else 0)
        avg_size = sum(s["sizes"]) / len(s["sizes"]) if s["sizes"] else 0
        wrong = s["total"] - s["correct"] - s["errors"]
        marker = " ***" if acc < 80 else (" *" if acc < 95 else "")
        print(f"  {family:<18} {acc:5.1f}% {s['correct']:>8} {wrong:>6} "
              f"{s['errors']:>5} {s['total']:>6} {avg_conf:>7.3f} "
              f"{avg_size:>9.0f}{marker}")

    # --- Confusion matrix (top misclassifications) ---
    confusion: Counter = Counter()
    for r in results:
        if not r.correct and not r.error:
            confusion[(r.expected_family, r.detected_isa or "none")] += 1

    if confusion:
        print(f"\n  Top Misclassifications:")
        print(f"  {'Expected':<18} {'Detected':<18} {'Count':>6}")
        print(f"  {'-'*18} {'-'*18} {'-'*6}")
        for (expected, detected), count in confusion.most_common(30):
            print(f"  {expected:<18} {detected:<18} {count:>6}")

    # --- Low-confidence correct detections ---
    low_conf = [r for r in results if r.correct and r.confidence < 0.5]
    if low_conf:
        print(f"\n  Low-confidence correct detections (<50%): {len(low_conf)}")
        by_family: dict[str, list] = defaultdict(list)
        for r in low_conf:
            by_family[r.expected_family].append(r.confidence)
        for fam in sorted(by_family.keys()):
            confs = by_family[fam]
            print(f"    {fam:<18} {len(confs):>4} files, "
                  f"avg conf {sum(confs)/len(confs):.3f}, "
                  f"min {min(confs):.3f}")

    # --- Size-related failures ---
    failed = [r for r in results if not r.correct and not r.error]
    if failed:
        small_fails = [r for r in failed if r.file_size < 256]
        medium_fails = [r for r in failed if 256 <= r.file_size < 4096]
        large_fails = [r for r in failed if r.file_size >= 4096]
        print(f"\n  Failures by size:")
        print(f"    <256 bytes:   {len(small_fails):>4}")
        print(f"    256-4KB:      {len(medium_fails):>4}")
        print(f"    4KB+:         {len(large_fails):>4}")

    # --- Error breakdown ---
    if errors:
        error_types: Counter = Counter()
        for r in results:
            if r.error:
                # Simplify error message
                err = r.error[:80]
                error_types[err] += 1
        print(f"\n  Error types:")
        for err, count in error_types.most_common(10):
            print(f"    {count:>4}x  {err}")

    return family_stats


def print_summary_json(blob_results, fw_results, output_path: Path):
    """Write machine-readable summary."""
    def summarize(results):
        family_stats = defaultdict(lambda: {
            "total": 0, "correct": 0, "wrong": 0, "errors": 0,
            "avg_confidence": 0, "misclassified_as": {},
        })
        for r in results:
            s = family_stats[r.expected_family]
            s["total"] += 1
            if r.error:
                s["errors"] += 1
            elif r.correct:
                s["correct"] += 1
            else:
                s["wrong"] += 1
                det = r.detected_isa or "none"
                s["misclassified_as"][det] = s["misclassified_as"].get(det, 0) + 1

        for s in family_stats.values():
            s["accuracy"] = s["correct"] / s["total"] if s["total"] else 0
        return dict(family_stats)

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "blob_analysis": {
            "total": len(blob_results),
            "correct": sum(1 for r in blob_results if r.correct),
            "per_family": summarize(blob_results),
        },
        "firmware_analysis": {
            "total": len(fw_results),
            "correct": sum(1 for r in fw_results if r.correct),
            "per_family": summarize(fw_results),
        },
    }

    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Summary JSON written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Rigorous ISA classifier accuracy analysis"
    )
    parser.add_argument(
        "--objects-dir", type=Path, default=OBJECTS_DIR,
        help="Directory with extracted object blobs",
    )
    parser.add_argument(
        "--firmware-dir", type=Path, default=FIRMWARE_DIR,
        help="Directory with synthetic firmware images",
    )
    parser.add_argument(
        "--max-blobs-per-family", type=int, default=50,
        help="Max blobs to test per ISA family (0 = all)",
    )
    parser.add_argument(
        "--max-firmware-per-dir", type=int, default=5,
        help="Max firmware images per combo directory (0 = all)",
    )
    parser.add_argument(
        "--jobs", "-j", type=int, default=8,
        help="Parallel workers",
    )
    parser.add_argument(
        "--blobs-only", action="store_true",
        help="Only test object blobs",
    )
    parser.add_argument(
        "--firmware-only", action="store_true",
        help="Only test firmware images",
    )
    parser.add_argument(
        "--output", "-o", type=Path,
        default=Path(__file__).parent / "accuracy_report.json",
        help="Output JSON report path",
    )
    args = parser.parse_args()

    if not CLASSIFIER_BIN.exists():
        print(f"ERROR: Classifier binary not found at {CLASSIFIER_BIN}")
        print("  Run: cd classifier && cargo build --release")
        sys.exit(1)

    blob_results = []
    fw_results = []

    # --- Phase 1: Object blobs ---
    if not args.firmware_only and args.objects_dir.exists():
        blob_tasks = collect_blob_tasks(
            args.objects_dir, max_per_family=args.max_blobs_per_family,
        )
        blob_results = run_analysis(
            blob_tasks, classify_blob, args.jobs,
            "Phase 1: Object Blob Classification",
        )
        print_report(blob_results, "Object Blobs (raw machine code)")

    # --- Phase 2: Firmware images ---
    if not args.blobs_only and args.firmware_dir.exists():
        fw_tasks = collect_firmware_tasks(
            args.firmware_dir, max_per_dir=args.max_firmware_per_dir,
        )
        fw_results = run_analysis(
            fw_tasks, classify_firmware_section, args.jobs,
            "Phase 2: Firmware Image Classification",
        )
        print_report(fw_results, "Firmware Images (synthetic)")

    # --- Write summary ---
    print_summary_json(blob_results, fw_results, args.output)

    # --- Final summary ---
    all_results = blob_results + fw_results
    if all_results:
        total = len(all_results)
        correct = sum(1 for r in all_results if r.correct)
        print(f"\n{'='*70}")
        print(f"  OVERALL: {correct}/{total} correct ({100*correct/total:.1f}%)")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
