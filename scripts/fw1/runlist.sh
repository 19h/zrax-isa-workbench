#!/usr/bin/env bash
set -euo pipefail
# Run a zrax CLI over the listed fw1 files (one sha per line); one JSONL line per file.
# A run that prints no JSON (heuristic rejection) is recorded as isa "<rejected>".
# Usage: runlist.sh ZRAX FW_DIR LIST OUT.jsonl
zrax="$1"; fw="$2"; list="$3"; out="$4"
cd "$fw"
xargs -P 8 -n 1 sh -c 'j=$("$0" -f json "$1" 2>/dev/null || true); printf "%s" "$j" | python3 -I -c "
import sys, json
raw = sys.stdin.read()
keys = (\"format\", \"format_variant\", \"isa\", \"variant\", \"bitwidth\", \"endianness\", \"confidence\", \"source\")
d = json.loads(raw) if raw.strip() else {\"isa\": \"<rejected>\"}
r = {k: d.get(k) for k in keys}
r[\"file\"] = sys.argv[1]
print(json.dumps(r))
" "$1"' "$zrax" < "$list" > "$out"
wc -l < "$out"
