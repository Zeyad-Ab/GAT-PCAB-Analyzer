#!/usr/bin/env bash
# Run the detector on a snapshots JSON and emit verdicts + ACL JSON.
#
# Usage: bash NetSec/scripts/03_detect.sh <snapshots.json> <checkpoint.pth> <out_dir>

set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <snapshots.json> <checkpoint.pth> <out_dir>"
    exit 1
fi

SNAPSHOTS="$1"
CHECKPOINT="$2"
OUT_DIR="$3"
CONFIG="${CONFIG:-NetSec/configs/default.yaml}"

mkdir -p "$OUT_DIR"
VERDICTS="$OUT_DIR/verdicts.json"
ACL="$OUT_DIR/acl.json"

python -m NetSec.detect.detector \
    --snapshots "$SNAPSHOTS" \
    --checkpoint "$CHECKPOINT" \
    --config "$CONFIG" \
    --out "$VERDICTS"

python -m NetSec.detect.mitigation \
    --verdicts "$VERDICTS" \
    --config "$CONFIG" \
    --out "$ACL"

echo "Verdicts: $VERDICTS"
echo "ACL:      $ACL"
