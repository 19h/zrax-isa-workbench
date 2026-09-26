#!/usr/bin/env python3
"""
Firmware classification validation script.

Phase 1: Classify all firmware files using isa-classify (fast, bulk)
Phase 2: Validate predictions by disassembling samples with rasm2
Phase 3: Report suspected misclassifications

Usage:
    python3 scripts/validate_firmware.py /path/to/firmware/dir [--max-files N] [--sample-per-isa N]
"""

import subprocess
import json
import sys
import os
import struct
from pathlib import Path
from collections import defaultdict, Counter
import argparse
import time
import tempfile

# ──────────────────────────────────────────────────────────────────
# ISA → rasm2 mapping
# ──────────────────────────────────────────────────────────────────
ISA_TO_RASM2 = {
    "x86": ("x86", "32", False),
    "x86_64": ("x86", "64", False),
    "arm": ("arm", "32", False),
    "aarch64": ("arm", "64", False),
    "riscv32": ("riscv", "32", False),
    "riscv64": ("riscv", "64", False),
    "mips": ("mips", "32", True),
    "mips64": ("mips", "64", True),
    "ppc": ("ppc", "32", True),
    "ppc64": ("ppc", "64", True),  # Note: could be LE too
    "sparc": ("sparc", "32", True),
    "sparc64": ("sparc", "64", True),
    "s390x": ("s390", "64", True),
    "m68k": ("m68k", "32", True),
    "sh": ("sh", "32", False),
    "sh4": ("sh", "32", False),
    "alpha": ("alpha", "64", False),
    "avr": ("avr", "16", False),
    "msp430": ("msp430", "16", False),
    "parisc": ("hppa", "32", True),
    "tricore": ("tricore", "32", False),
    "xtensa": ("xtensa", "32", False),
    "nios2": ("nios2", "32", False),
    "openrisc": ("or1k", "32", True),
    "vax": ("vax", "32", False),
    "z80": ("z80", "16", False),
    "mcs6502": ("6502", "8", False),
    "v850": ("v850", "32", False),
    "dalvik": ("dalvik", "32", False),
    "wasm": ("wasm", "32", False),
    "jvm": ("java", "32", True),
    "loongarch64": ("loongarch", "64", False),
    "hcs12": ("m680x", "16", True),  # HC12/HCS12X via Capstone M680X
}

# ISAs without rasm2 support — can't disassembly-validate these
SKIP_ISAS = {
    # "hcs12",  # HCS12 can be validated via cstool cpu12 — removed from skip list
    "hexagon",
    "arc",
    "microblaze",
    "lanai",
    "blackfin",
    "ia64",
    "i860",
    "cellspu",
    "pic",
    "stm8",
    "coldfire",
    "bpf",
    "kvx",
    "csky",
    "rx",
    "tic6000",
    "tic2000",
    "tic5500",
    "tipru",
    "sharc",
    "amdgpu",
    "cuda",
    "w65816",
    "pdp11",
    "ebc",
    "clr",
}

# Common alternative ISAs to try when validation fails
ALT_ISAS = [
    "x86",
    "x86_64",
    "arm",
    "aarch64",
    "mips",
    "ppc",
    "sh",
    "tricore",
    "m68k",
    "riscv32",
    "avr",
    "msp430",
    "sparc",
    "s390x",
    "parisc",
]

FIRMWARE_EXTENSIONS = {
    ".bin",
    ".BIN",
    ".dat",
    ".ori",
    ".ORI",
    ".orig",
    ".org",
    ".Stage1",
    ".Stage2",
    ".Stage3",
    ".Original",
    ".Limited_Mappack",
    ".Stage1+++",
    ".eep",
}


def find_firmware_files(directory: str) -> list[Path]:
    """Find all firmware-like files recursively."""
    files = []
    for root, dirs, filenames in os.walk(directory):
        for fn in filenames:
            p = Path(root) / fn
            suffix = p.suffix
            if suffix in FIRMWARE_EXTENSIONS:
                try:
                    if p.stat().st_size >= 256:
                        files.append(p)
                except OSError:
                    pass
    files.sort()
    return files


def parse_concatenated_json(text: str) -> list[dict]:
    """Parse concatenated JSON objects (no separator between them).
    The classifier outputs pretty-printed JSON objects back-to-back like:
        { ... }{ ... }
    We use a simple brace-depth counter to split them.
    """
    results = []
    depth = 0
    start = None

    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(text[start : i + 1])
                    results.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None

    return results


def classify_batch(classifier: str, files: list[Path], batch_size: int = 100) -> dict:
    """Classify files in batches using the classifier binary.
    Returns dict mapping filepath -> classification result dict.
    """
    results = {}
    total = len(files)

    for i in range(0, total, batch_size):
        batch = files[i : i + batch_size]
        file_args = [str(f) for f in batch]

        try:
            proc = subprocess.run(
                [classifier, "-f", "json", "--min-confidence", "0.05", "-c"]
                + file_args,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = proc.stdout.strip()
            if not output:
                continue

            # Parse concatenated JSON objects
            objects = parse_concatenated_json(output)
            for obj in objects:
                if "file" in obj:
                    results[obj["file"]] = obj

        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"  Batch error at index {i}: {e}", file=sys.stderr)

        done = min(i + batch_size, total)
        if done % 500 < batch_size or done >= total:
            print(f"  Classified {done}/{total}...")

    return results


def extract_code_sample(filepath: str, sample_size: int = 512) -> bytes:
    """Read a firmware file, skip leading zero/0xFF padding, return sample bytes."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return b""

    # Skip leading padding in 64-byte chunks
    i = 0
    while i + 64 <= len(data):
        chunk = data[i : i + 64]
        if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
            i += 64
        else:
            break

    sample = data[i : i + sample_size]
    return sample


def disassemble_and_score(
    hexbytes: str, arch: str, bits: str, big_endian: bool
) -> tuple[int, int]:
    """Disassemble hex bytes with rasm2 and return (valid_count, total_count)."""
    if not hexbytes or len(hexbytes) < 8:
        return (0, 0)

    cmd = ["rasm2", "-a", arch, "-b", bits]
    if big_endian:
        cmd.append("-e")
    cmd.extend(["-d", hexbytes])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout.strip()
        if not output:
            return (0, 0)

        lines = output.split("\n")
        total = len(lines)
        invalid = sum(1 for line in lines if "invalid" in line.lower())
        return (total - invalid, total)
    except (subprocess.TimeoutExpired, OSError):
        return (0, 0)


def validate_prediction(
    filepath: str, predicted_isa: str, sample_size: int = 512
) -> dict:
    """Validate a classification prediction via disassembly.
    Returns dict with decode rates for predicted ISA and best alternative.
    """
    result = {
        "predicted_isa": predicted_isa,
        "can_validate": False,
        "decode_valid": 0,
        "decode_total": 0,
        "decode_rate": 0,
        "best_alt_isa": None,
        "best_alt_rate": 0,
    }

    if predicted_isa in SKIP_ISAS or predicted_isa not in ISA_TO_RASM2:
        return result

    result["can_validate"] = True

    sample = extract_code_sample(filepath, sample_size)
    if len(sample) < 8:
        return result

    hexbytes = sample.hex()

    # Validate predicted ISA
    arch, bits, big_endian = ISA_TO_RASM2[predicted_isa]
    valid, total = disassemble_and_score(hexbytes, arch, bits, big_endian)
    result["decode_valid"] = valid
    result["decode_total"] = total
    result["decode_rate"] = (valid * 100 // total) if total > 0 else 0

    # If decode rate is low, try alternatives
    if result["decode_rate"] < 50 and total > 0:
        best_alt = None
        best_alt_rate = 0

        for alt_isa in ALT_ISAS:
            if alt_isa == predicted_isa:
                continue
            if alt_isa not in ISA_TO_RASM2:
                continue

            a_arch, a_bits, a_be = ISA_TO_RASM2[alt_isa]
            a_valid, a_total = disassemble_and_score(hexbytes, a_arch, a_bits, a_be)
            if a_total > 0:
                a_rate = a_valid * 100 // a_total
                if a_rate > best_alt_rate:
                    best_alt_rate = a_rate
                    best_alt = alt_isa

        result["best_alt_isa"] = best_alt
        result["best_alt_rate"] = best_alt_rate

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Validate firmware ISA classifications"
    )
    parser.add_argument("directory", help="Directory to scan recursively")
    parser.add_argument(
        "--max-files", type=int, default=0, help="Max files to classify (0=all)"
    )
    parser.add_argument(
        "--validate-per-isa",
        type=int,
        default=30,
        help="Max files to disasm-validate per ISA group",
    )
    parser.add_argument(
        "--validate-low-conf",
        type=float,
        default=0.5,
        help="Always validate files below this confidence",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=512,
        help="Bytes to sample for disassembly validation",
    )
    args = parser.parse_args()

    classifier = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "target",
        "release",
        "isa-classify",
    )
    if not os.path.isfile(classifier):
        print("Building release binary...")
        subprocess.run(
            ["cargo", "build", "--release", "--quiet"],
            check=True,
            cwd=os.path.dirname(os.path.abspath(__file__)) + "/..",
        )
    if not os.path.isfile(classifier):
        print(f"ERROR: classifier not found at {classifier}", file=sys.stderr)
        sys.exit(1)

    # ── Phase 1: Find files ──
    print(f"Scanning {args.directory} for firmware files...")
    files = find_firmware_files(args.directory)
    print(f"Found {len(files)} firmware files")

    if args.max_files > 0:
        files = files[: args.max_files]
        print(f"Limited to {len(files)} files")

    # ── Phase 2: Classify all files ──
    print(f"\n{'=' * 60}")
    print("PHASE 1: Classification")
    print(f"{'=' * 60}")
    t0 = time.time()
    classifications = classify_batch(classifier, files)
    t1 = time.time()
    print(f"Classified {len(classifications)}/{len(files)} files in {t1 - t0:.1f}s")

    # ── Phase 3: Analyze distribution ──
    isa_groups = defaultdict(list)
    error_files = []
    for f in files:
        key = str(f)
        if key in classifications:
            cls = classifications[key]
            isa_groups[cls["isa"]].append((key, cls))
        else:
            error_files.append(key)

    print(f"\n{'=' * 60}")
    print("ISA DISTRIBUTION")
    print(f"{'=' * 60}")
    for isa, items in sorted(isa_groups.items(), key=lambda x: -len(x[1])):
        avg_conf = sum(c["confidence"] for _, c in items) / len(items) * 100
        print(f"  {isa:20s} {len(items):6d} files  (avg conf: {avg_conf:.1f}%)")
    if error_files:
        print(f"  {'(errors)':20s} {len(error_files):6d} files")

    # ── Phase 4: Select files for validation ──
    # Strategy: validate a sample from each ISA group + all low-confidence results
    print(f"\n{'=' * 60}")
    print("PHASE 2: Disassembly Validation")
    print(f"{'=' * 60}")

    to_validate = []
    for isa, items in isa_groups.items():
        # Sort by confidence ascending (validate least confident first)
        items_sorted = sorted(items, key=lambda x: x[1]["confidence"])

        # Always validate low-confidence items
        low_conf = [
            (f, c) for f, c in items_sorted if c["confidence"] < args.validate_low_conf
        ]

        # Sample additional items
        remaining = [
            (f, c) for f, c in items_sorted if c["confidence"] >= args.validate_low_conf
        ]

        # Take low-conf items + some random high-conf items
        selected = low_conf[: args.validate_per_isa]
        if len(selected) < args.validate_per_isa and remaining:
            # Add some from the higher-confidence set too (every N-th)
            step = max(1, len(remaining) // (args.validate_per_isa - len(selected)))
            for j in range(0, len(remaining), step):
                if len(selected) >= args.validate_per_isa:
                    break
                selected.append(remaining[j])

        for filepath, cls in selected:
            to_validate.append((filepath, cls))

    print(f"Selected {len(to_validate)} files for disassembly validation")

    # ── Phase 5: Validate via disassembly ──
    suspects = []
    validated = 0
    skipped_no_disasm = 0

    for filepath, cls in to_validate:
        validated += 1
        if validated % 50 == 0:
            print(f"  Validated {validated}/{len(to_validate)}...")

        vresult = validate_prediction(filepath, cls["isa"], args.sample_size)

        if not vresult["can_validate"]:
            skipped_no_disasm += 1
            continue

        if vresult["decode_total"] == 0:
            continue

        # Flag as suspect if decode rate is low
        if vresult["decode_rate"] < 40:
            verdict = "LOW_DECODE"
            if (
                vresult["best_alt_isa"]
                and vresult["best_alt_rate"] > vresult["decode_rate"] + 20
            ):
                verdict = f"LIKELY_WRONG→{vresult['best_alt_isa']}"
            elif vresult["decode_rate"] < 15:
                verdict = "VERY_LOW_DECODE"

            suspects.append(
                {
                    "file": filepath,
                    "predicted_isa": cls["isa"],
                    "confidence": cls["confidence"],
                    "decode_rate": vresult["decode_rate"],
                    "best_alt_isa": vresult["best_alt_isa"],
                    "best_alt_rate": vresult["best_alt_rate"],
                    "verdict": verdict,
                    # Include candidates from classifier
                    "candidates": cls.get("candidates", [])[:5],
                }
            )

    print(f"\nValidated: {validated}, Skipped (no disasm support): {skipped_no_disasm}")

    # ── Phase 6: Report ──
    print(f"\n{'=' * 60}")
    print("SUSPECTED MISCLASSIFICATIONS")
    print(f"{'=' * 60}")

    if not suspects:
        print("  None found!")
    else:
        # Sort by decode rate ascending (worst first)
        suspects.sort(key=lambda s: s["decode_rate"])

        for s in suspects:
            conf_pct = s["confidence"] * 100
            short_file = s["file"]
            # Shorten path for display
            try:
                short_file = str(Path(s["file"]).relative_to(args.directory))
            except ValueError:
                pass

            alt_str = ""
            if s["best_alt_isa"]:
                alt_str = f" | best alt: {s['best_alt_isa']} ({s['best_alt_rate']}%)"

            print(f"  [{s['verdict']}]")
            print(f"    File: {short_file}")
            print(
                f"    Predicted: {s['predicted_isa']} ({conf_pct:.1f}% conf), "
                f"decode rate: {s['decode_rate']}%{alt_str}"
            )
            if s["candidates"]:
                top3 = s["candidates"][:3]
                cand_str = ", ".join(f"{c['isa']}({c['raw_score']})" for c in top3)
                print(f"    Top candidates: {cand_str}")
            print()

    # ── Write machine-readable output ──
    output_file = "/tmp/fw_validation_results.json"
    output = {
        "scan_directory": args.directory,
        "total_files": len(files),
        "classified": len(classifications),
        "errors": len(error_files),
        "isa_distribution": {isa: len(items) for isa, items in isa_groups.items()},
        "validated": validated,
        "suspects": suspects,
    }
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nFull results written to: {output_file}")

    # Summary stats
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total files:       {len(files)}")
    print(f"  Classified:        {len(classifications)}")
    print(f"  Classification errors: {len(error_files)}")
    print(f"  Validated (disasm): {validated}")
    print(f"  Suspects:          {len(suspects)}")

    # Group suspects by predicted ISA
    if suspects:
        print(f"\n  Suspects by predicted ISA:")
        by_isa = Counter(s["predicted_isa"] for s in suspects)
        for isa, count in by_isa.most_common():
            print(f"    {isa:20s} {count}")

        print(f"\n  Suspects by verdict:")
        by_verdict = Counter(s["verdict"] for s in suspects)
        for v, count in by_verdict.most_common():
            print(f"    {v:30s} {count}")


if __name__ == "__main__":
    main()
