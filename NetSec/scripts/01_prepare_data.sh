#!/usr/bin/env bash
# Convert a PCAP (+ optional label source) into labeled graph snapshots.
#
# Usage:
#   bash NetSec/scripts/01_prepare_data.sh <input.pcap> <out_dir> [<cicids_labels.csv> | --attackers=<ips.txt>]

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <input.pcap> <out_dir> [<cicids_labels.csv> | --attackers=<ips.txt>]"
    exit 1
fi

PCAP="$1"
OUT_DIR="$2"
LABEL_ARG="${3:-}"
CONFIG="${CONFIG:-NetSec/configs/default.yaml}"

mkdir -p "$OUT_DIR"
FLOWS_CSV="$OUT_DIR/flows.csv"
LABELED_CSV="$OUT_DIR/flows_labeled.csv"
SNAPSHOTS_JSON="$OUT_DIR/snapshots.json"

echo "[1/3] PCAP -> flows"
python -m NetSec.parsing.pcap_to_flows --pcap "$PCAP" --out "$FLOWS_CSV"

echo "[2/3] Attach labels"
if [[ -z "$LABEL_ARG" ]]; then
    echo "  (no label source provided, marking all flows BENIGN)"
    python - <<PY
import pandas as pd
df = pd.read_csv("$FLOWS_CSV", low_memory=False)
df["label"] = 0
df["attack_type"] = "BENIGN"
df.to_csv("$LABELED_CSV", index=False)
print(f"Wrote {len(df)} unlabeled-as-benign flows to $LABELED_CSV")
PY
elif [[ "$LABEL_ARG" == --attackers=* ]]; then
    ATTACKER_FILE="${LABEL_ARG#--attackers=}"
    python -m NetSec.parsing.labels --flows "$FLOWS_CSV" --out "$LABELED_CSV" --attackers_file "$ATTACKER_FILE"
else
    python -m NetSec.parsing.labels --flows "$FLOWS_CSV" --out "$LABELED_CSV" --cicids_csv "$LABEL_ARG"
fi

echo "[3/3] Build graph snapshots"
python -m NetSec.graph.build_graph --flows "$LABELED_CSV" --out "$SNAPSHOTS_JSON" --config "$CONFIG"

echo "Done. Artifacts:"
echo "  - $FLOWS_CSV"
echo "  - $LABELED_CSV"
echo "  - $SNAPSHOTS_JSON"
