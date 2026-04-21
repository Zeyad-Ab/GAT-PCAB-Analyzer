#!/usr/bin/env bash
# Prepare multiple PCAPs listed in a manifest, then merge into one snapshots JSON.
#
# Manifest format (plain text, one entry per line, comments with #):
#   <pcap_path> <labels_csv_or_attackers.txt_or_->
#
# - If the second column is a CSV path, it is treated as a CICIDS2017-style labels CSV.
# - If it starts with "@", the remainder is treated as an attackers-file path
#   (e.g. @/path/attackers.txt) and passed through --attackers=... to 01_prepare_data.sh.
# - If it is "-" (dash), the PCAP is labeled as all-BENIGN (useful for background
#   traffic captures where you have no ground truth).
#
# Usage:
#   bash NetSec/scripts/01b_prepare_multi.sh <manifest.txt> <out_dir>
#
# Output:
#   - <out_dir>/<stem>/snapshots.json  per PCAP
#   - <out_dir>/snapshots.json         merged across all PCAPs (what train.py consumes)

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <manifest.txt> <out_dir>"
    exit 1
fi

MANIFEST="$1"
OUT_DIR="$2"
CONFIG="${CONFIG:-NetSec/configs/default.yaml}"
mkdir -p "$OUT_DIR"

SNAPSHOT_LIST=()
LINE_NO=0

while IFS= read -r line || [[ -n "$line" ]]; do
    LINE_NO=$((LINE_NO + 1))
    # strip comments and whitespace
    line="${line%%#*}"
    line="$(echo "$line" | awk '{$1=$1;print}')"
    [[ -z "$line" ]] && continue

    PCAP=$(echo "$line" | awk '{print $1}')
    LABEL=$(echo "$line" | awk '{print $2}')

    if [[ -z "$LABEL" ]]; then
        echo "[manifest:$LINE_NO] ERROR: missing label column for $PCAP" >&2
        exit 1
    fi

    if [[ ! -f "$PCAP" ]]; then
        echo "[manifest:$LINE_NO] WARNING: PCAP missing, skipping: $PCAP" >&2
        continue
    fi

    STEM=$(basename "$PCAP")
    STEM="${STEM%.*}"
    SUB_OUT="$OUT_DIR/$STEM"
    mkdir -p "$SUB_OUT"

    echo "=== [$LINE_NO] $PCAP -> $SUB_OUT (label=$LABEL) ==="

    if [[ "$LABEL" == "-" ]]; then
        bash NetSec/scripts/01_prepare_data.sh "$PCAP" "$SUB_OUT"
    elif [[ "$LABEL" == @* ]]; then
        ATTACKERS_FILE="${LABEL#@}"
        bash NetSec/scripts/01_prepare_data.sh "$PCAP" "$SUB_OUT" "--attackers=$ATTACKERS_FILE"
    else
        bash NetSec/scripts/01_prepare_data.sh "$PCAP" "$SUB_OUT" "$LABEL"
    fi

    if [[ -f "$SUB_OUT/snapshots.json" ]]; then
        SNAPSHOT_LIST+=("$SUB_OUT/snapshots.json")
    else
        echo "[manifest:$LINE_NO] WARNING: no snapshots.json produced for $PCAP" >&2
    fi
done < "$MANIFEST"

if [[ "${#SNAPSHOT_LIST[@]}" -eq 0 ]]; then
    echo "ERROR: no snapshots produced from any PCAP in manifest" >&2
    exit 1
fi

MERGED="$OUT_DIR/snapshots.json"
python -m NetSec.parsing.merge_snapshots --inputs "${SNAPSHOT_LIST[@]}" --out "$MERGED"

echo "Done."
echo "Per-PCAP snapshots: ${#SNAPSHOT_LIST[@]}"
echo "Merged snapshots:   $MERGED"
