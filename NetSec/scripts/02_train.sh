#!/usr/bin/env bash
# Train NetGAT on a snapshots JSON.
#
# Usage: bash NetSec/scripts/02_train.sh <snapshots.json> [device]

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <snapshots.json> [device]"
    exit 1
fi

SNAPSHOTS="$1"
DEVICE="${2:-auto}"
CONFIG="${CONFIG:-NetSec/configs/default.yaml}"

python -m NetSec.train.train --snapshots "$SNAPSHOTS" --config "$CONFIG" --device "$DEVICE"
