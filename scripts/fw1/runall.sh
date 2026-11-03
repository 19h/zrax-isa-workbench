#!/usr/bin/env bash
set -euo pipefail
# Run a zrax CLI over every fw1 binary; one JSONL line per file.
# Usage: runall.sh ZRAX FW_DIR OUT.jsonl
zrax="$1"; fw="$2"; out="$3"
cd "$fw"
ls | grep -v '\.json$' | xargs -P 8 -n 1 sh -c '"$0" -f json "$1" 2>/dev/null | python3 -I -c "import sys,json; d=json.loads(sys.stdin.read() or \"{}\"); print(json.dumps({k:d.get(k) for k in (\"file\",\"format\",\"format_variant\",\"isa\",\"variant\",\"bitwidth\",\"endianness\",\"confidence\",\"source\")}))" || echo "{\"file\":\"$1\",\"error\":true}"' "$zrax" > "$out"
wc -l < "$out"
