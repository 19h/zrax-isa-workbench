#!/usr/bin/env bash
# validate_firmware.sh — Scan firmware files, classify, then validate via disassembly
#
# Usage: ./scripts/validate_firmware.sh <directory> [max_files]
#
# For each firmware file:
#   1. Classify with isa-classify
#   2. Extract a sample of non-zero bytes
#   3. Disassemble with rasm2 using the predicted ISA
#   4. Compute decode success rate
#   5. Flag files with low decode rates as potential misclassifications

set -euo pipefail

DIR="${1:?Usage: $0 <directory> [max_files]}"
MAX_FILES="${2:-0}"  # 0 = unlimited
CLASSIFIER="./target/release/isa-classify"
SAMPLE_SIZE=256  # bytes to sample for validation
MIN_DECODE_RATE=40  # percent — below this is suspicious

# Build release binary for speed
echo "Building release binary..."
cargo build --release --quiet 2>/dev/null

if [[ ! -x "$CLASSIFIER" ]]; then
    echo "ERROR: classifier binary not found at $CLASSIFIER"
    exit 1
fi

# ISA name -> rasm2 arch mapping
# Returns: "arch bits endian" or "SKIP" if no rasm2 support
isa_to_rasm2() {
    local isa="$1"
    case "$isa" in
        x86)         echo "x86 32 little" ;;
        x86_64)      echo "x86 64 little" ;;
        arm)         echo "arm 32 little" ;;
        aarch64)     echo "arm 64 little" ;;
        riscv32)     echo "riscv 32 little" ;;
        riscv64)     echo "riscv 64 little" ;;
        mips)        echo "mips 32 big" ;;
        mips64)      echo "mips 64 big" ;;
        ppc)         echo "ppc 32 big" ;;
        ppc64)       echo "ppc 64 big" ;;
        sparc)       echo "sparc 32 big" ;;
        sparc64)     echo "sparc 64 big" ;;
        s390x)       echo "s390 64 big" ;;
        m68k)        echo "m68k 32 big" ;;
        sh)          echo "sh 32 little" ;;
        sh4)         echo "sh 32 little" ;;
        alpha)       echo "alpha 64 little" ;;
        avr)         echo "avr 16 little" ;;
        msp430)      echo "msp430 16 little" ;;
        parisc)      echo "hppa 32 big" ;;
        tricore)     echo "tricore 32 little" ;;
        xtensa)      echo "xtensa 32 little" ;;
        nios2)       echo "nios2 32 little" ;;
        openrisc)    echo "or1k 32 big" ;;
        vax)         echo "vax 32 little" ;;
        z80)         echo "z80 16 little" ;;
        mcs6502)     echo "6502 8 little" ;;
        w65816)      echo "6502 16 little" ;;
        v850)        echo "v850 32 little" ;;
        dalvik)      echo "dalvik 32 little" ;;
        wasm)        echo "wasm 32 little" ;;
        jvm)         echo "java 32 big" ;;
        loongarch64) echo "loongarch 64 little" ;;
        # Architectures without rasm2 support
        c16x|hexagon|arc|microblaze|lanai|blackfin|ia64|i860|cellspu|pic|stm8|coldfire)
            echo "SKIP" ;;
        *)           echo "SKIP" ;;
    esac
}

# Find the first non-zero region in a file and extract sample bytes as hex
extract_sample_hex() {
    local file="$1"
    local sample_size="$2"
    
    # Use python for efficient zero-skip + hex extraction
    python3 -c "
import sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()

# Skip leading zeros/0xFF (in 64-byte chunks)
i = 0
while i + 64 <= len(data):
    chunk = data[i:i+64]
    if all(b == 0 for b in chunk) or all(b == 0xFF for b in chunk):
        i += 64
    else:
        break

# Take sample from the start of non-padding region
sample = data[i:i+int(sys.argv[2])]
print(sample.hex())
" "$file" "$sample_size" 2>/dev/null
}

# Disassemble hex bytes and count valid vs invalid
validate_disasm() {
    local arch="$1"
    local bits="$2"
    local endian="$3"
    local hexbytes="$4"
    
    if [[ -z "$hexbytes" || ${#hexbytes} -lt 8 ]]; then
        echo "0 0"
        return
    fi
    
    local endian_flag=""
    if [[ "$endian" == "big" ]]; then
        endian_flag="-e"
    fi
    
    local output
    output=$(rasm2 -a "$arch" -b "$bits" $endian_flag -d "$hexbytes" 2>/dev/null || true)
    
    if [[ -z "$output" ]]; then
        echo "0 0"
        return
    fi
    
    local total valid invalid
    total=$(echo "$output" | wc -l | tr -d ' ')
    invalid=$(echo "$output" | grep -c "invalid" || true)
    valid=$((total - invalid))
    
    echo "$valid $total"
}

# Try alternative ISAs and return the best decode rate
try_alternatives() {
    local hexbytes="$1"
    local predicted="$2"
    local best_isa=""
    local best_rate=0
    
    # Common automotive/embedded ISAs to try as alternatives
    local alternatives="x86 arm aarch64 mips ppc sh tricore m68k riscv32 avr msp430 sparc s390x"
    
    for alt_isa in $alternatives; do
        [[ "$alt_isa" == "$predicted" ]] && continue
        
        local mapping
        mapping=$(isa_to_rasm2 "$alt_isa")
        [[ "$mapping" == "SKIP" ]] && continue
        
        local arch bits endian
        read -r arch bits endian <<< "$mapping"
        
        local result
        result=$(validate_disasm "$arch" "$bits" "$endian" "$hexbytes")
        local valid total
        read -r valid total <<< "$result"
        
        if [[ "$total" -gt 0 ]]; then
            local rate=$((valid * 100 / total))
            if [[ "$rate" -gt "$best_rate" ]]; then
                best_rate=$rate
                best_isa=$alt_isa
            fi
        fi
    done
    
    echo "$best_isa $best_rate"
}

# Results files
RESULTS_DIR="/tmp/fw_validation_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
RESULTS_FILE="$RESULTS_DIR/results.tsv"
SUSPECTS_FILE="$RESULTS_DIR/suspects.tsv"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

echo -e "file\tpredicted_isa\tconfidence\tdecode_valid\tdecode_total\tdecode_rate\tbest_alt_isa\tbest_alt_rate" > "$RESULTS_FILE"
echo -e "file\tpredicted_isa\tconfidence\tdecode_rate\tbest_alt_isa\tbest_alt_rate\tverdict" > "$SUSPECTS_FILE"

echo "Scanning $DIR..."
echo "Results directory: $RESULTS_DIR"
echo ""

# Find all binary-looking files (skip text, images, archives)
FILE_COUNT=0
PROCESSED=0
SUSPECT_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# Collect files
mapfile -t FILES < <(find "$DIR" -type f \( -name "*.bin" -o -name "*.BIN" -o -name "*.dat" -o -name "*.ori" -o -name "*.ORI" -o -name "*.orig" -o -name "*.org" -o -name "*.Stage1" -o -name "*.Stage2" -o -name "*.Stage3" -o -name "*.Original" -o -name "*.Limited_Mappack" -o -name "*.Stage1+++" \) | sort)

FILE_COUNT=${#FILES[@]}
echo "Found $FILE_COUNT firmware files to analyze"

if [[ "$MAX_FILES" -gt 0 && "$FILE_COUNT" -gt "$MAX_FILES" ]]; then
    echo "Limiting to $MAX_FILES files"
    FILE_COUNT=$MAX_FILES
fi

echo ""

for ((idx=0; idx<FILE_COUNT; idx++)); do
    file="${FILES[$idx]}"
    PROCESSED=$((PROCESSED + 1))
    
    # Progress indicator every 100 files
    if (( PROCESSED % 100 == 0 )); then
        echo "[${PROCESSED}/${FILE_COUNT}] Processed... (${SUSPECT_COUNT} suspects so far)"
    fi
    
    # Skip tiny files
    local fsize
    fsize=$(stat -f%z "$file" 2>/dev/null || echo 0)
    if [[ "$fsize" -lt 256 ]]; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
        continue
    fi
    
    # Classify
    local classify_output
    classify_output=$("$CLASSIFIER" -f json --min-confidence 0.05 "$file" 2>/dev/null || true)
    
    if [[ -z "$classify_output" ]]; then
        ERROR_COUNT=$((ERROR_COUNT + 1))
        continue
    fi
    
    # Parse JSON output
    local predicted_isa confidence
    predicted_isa=$(echo "$classify_output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('isa','unknown'))" 2>/dev/null || echo "unknown")
    confidence=$(echo "$classify_output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{d.get('confidence',0)*100:.1f}\")" 2>/dev/null || echo "0")
    
    if [[ "$predicted_isa" == "unknown" ]]; then
        ERROR_COUNT=$((ERROR_COUNT + 1))
        continue
    fi
    
    # Get rasm2 mapping
    local mapping
    mapping=$(isa_to_rasm2 "$predicted_isa")
    
    if [[ "$mapping" == "SKIP" ]]; then
        # Can't validate this ISA via disassembly, just log it
        echo -e "${file}\t${predicted_isa}\t${confidence}\t-\t-\t-\t-\t-" >> "$RESULTS_FILE"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        continue
    fi
    
    local arch bits endian
    read -r arch bits endian <<< "$mapping"
    
    # Extract sample bytes
    local hexbytes
    hexbytes=$(extract_sample_hex "$file" "$SAMPLE_SIZE")
    
    if [[ -z "$hexbytes" || ${#hexbytes} -lt 8 ]]; then
        SKIP_COUNT=$((SKIP_COUNT + 1))
        continue
    fi
    
    # Validate via disassembly
    local result
    result=$(validate_disasm "$arch" "$bits" "$endian" "$hexbytes")
    local valid total
    read -r valid total <<< "$result"
    
    local decode_rate=0
    if [[ "$total" -gt 0 ]]; then
        decode_rate=$((valid * 100 / total))
    fi
    
    # If decode rate is low, try alternatives
    local best_alt_isa="-"
    local best_alt_rate=0
    
    if [[ "$decode_rate" -lt "$MIN_DECODE_RATE" && "$total" -gt 0 ]]; then
        local alt_result
        alt_result=$(try_alternatives "$hexbytes" "$predicted_isa")
        read -r best_alt_isa best_alt_rate <<< "$alt_result"
        
        # Determine verdict
        local verdict="LOW_DECODE"
        if [[ "$best_alt_rate" -gt "$decode_rate" && "$best_alt_rate" -gt 60 ]]; then
            verdict="LIKELY_WRONG:$best_alt_isa"
        elif [[ "$decode_rate" -lt 10 ]]; then
            verdict="VERY_LOW_DECODE"
        fi
        
        echo -e "${file}\t${predicted_isa}\t${confidence}\t${decode_rate}%\t${best_alt_isa}\t${best_alt_rate}%\t${verdict}" >> "$SUSPECTS_FILE"
        SUSPECT_COUNT=$((SUSPECT_COUNT + 1))
    fi
    
    echo -e "${file}\t${predicted_isa}\t${confidence}\t${valid}\t${total}\t${decode_rate}%\t${best_alt_isa}\t${best_alt_rate}%" >> "$RESULTS_FILE"
done

echo ""
echo "========================================="
echo "SCAN COMPLETE"
echo "========================================="
echo "Total files found:    $FILE_COUNT"
echo "Processed:            $PROCESSED"
echo "Skipped (no disasm):  $SKIP_COUNT"
echo "Errors:               $ERROR_COUNT"
echo "Suspects (low decode): $SUSPECT_COUNT"
echo ""
echo "Results:  $RESULTS_FILE"
echo "Suspects: $SUSPECTS_FILE"
echo ""

# Generate summary
{
    echo "=== ISA Distribution ==="
    awk -F'\t' 'NR>1 && $2!="" {print $2}' "$RESULTS_FILE" | sort | uniq -c | sort -rn
    
    echo ""
    echo "=== Suspect Files ==="
    if [[ -s "$SUSPECTS_FILE" ]]; then
        column -t -s$'\t' "$SUSPECTS_FILE"
    else
        echo "(none)"
    fi
} | tee "$SUMMARY_FILE"

echo ""
echo "Full summary: $SUMMARY_FILE"
