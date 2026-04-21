#!/usr/bin/env bash
# Run NS-3 simulation (no-defense + defense) and evaluate network metrics.
#
# Usage: bash NetSec/scripts/04_simulate.sh <ns3_root> <acl.json> <attack> <out_dir>
# <attack> must be one of: scan | lateral | c2

set -euo pipefail

if [[ $# -lt 4 ]]; then
    echo "Usage: $0 <ns3_root> <acl.json> <attack> <out_dir>"
    exit 1
fi

NS3_ROOT="$1"
ACL="$2"
ATTACK="$3"
OUT_DIR="$4"
ATTACKER_IPS="${ATTACKER_IPS:-10.0.100.1}"

mkdir -p "$OUT_DIR"

python -m NetSec.simulation.run_sim \
    --ns3_root "$NS3_ROOT" \
    --acl "$ACL" \
    --attack "$ATTACK" \
    --out_dir "$OUT_DIR"

FM_ND="$OUT_DIR/flowmon_no_defense_${ATTACK}.xml"
FM_D="$OUT_DIR/flowmon_defense_${ATTACK}.xml"
REPORT="$OUT_DIR/network_metrics_${ATTACK}.json"

python -m NetSec.evaluate.network_metrics \
    --no_defense "$FM_ND" \
    --defense "$FM_D" \
    --attacker_ips "$ATTACKER_IPS" \
    --out "$REPORT"

echo "Network report: $REPORT"
