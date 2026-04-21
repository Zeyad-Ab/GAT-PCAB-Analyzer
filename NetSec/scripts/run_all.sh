#!/usr/bin/env bash
# End-to-end reproducibility script: PCAP -> labels -> graph -> train -> detect -> simulate -> evaluate.
#
# Usage:
#   bash NetSec/scripts/run_all.sh \
#       <train_pcap> <train_label_arg> \
#       <test_pcap>  <test_label_arg> \
#       <ns3_root>   <attack>
#
# <*_label_arg> can be either a CICIDS2017 labels CSV path or "--attackers=<ips.txt>".
# <attack> must be scan | lateral | c2.

set -euo pipefail

if [[ $# -lt 6 ]]; then
    cat <<EOF
Usage: $0 <train_pcap> <train_label_arg> <test_pcap> <test_label_arg> <ns3_root> <attack>
  train_label_arg / test_label_arg: either <labels.csv> or --attackers=<ips.txt>
EOF
    exit 1
fi

TRAIN_PCAP="$1"
TRAIN_LABEL="$2"
TEST_PCAP="$3"
TEST_LABEL="$4"
NS3_ROOT="$5"
ATTACK="$6"

BASE=NetSec/result
TRAIN_DIR="$BASE/train"
TEST_DIR="$BASE/test"
DETECT_DIR="$BASE/detect"
SIM_DIR="$BASE/sim"
mkdir -p "$TRAIN_DIR" "$TEST_DIR" "$DETECT_DIR" "$SIM_DIR"

echo "=== [1/5] Prepare training data ==="
bash NetSec/scripts/01_prepare_data.sh "$TRAIN_PCAP" "$TRAIN_DIR" "$TRAIN_LABEL"

echo "=== [2/5] Train NetGAT ==="
bash NetSec/scripts/02_train.sh "$TRAIN_DIR/snapshots.json"
CHECKPOINT=$(ls -t NetSec/checkpoint/*.pth 2>/dev/null | head -1)
echo "Latest checkpoint: $CHECKPOINT"

echo "=== [3/5] Prepare test data ==="
bash NetSec/scripts/01_prepare_data.sh "$TEST_PCAP" "$TEST_DIR" "$TEST_LABEL"

echo "=== [4/5] Run detection + mitigation ==="
bash NetSec/scripts/03_detect.sh "$TEST_DIR/snapshots.json" "$CHECKPOINT" "$DETECT_DIR"

echo "=== [4b/5] Detection metrics ==="
python -m NetSec.evaluate.detection_metrics \
    --snapshots "$TEST_DIR/snapshots.json" \
    --verdicts "$DETECT_DIR/verdicts.json" \
    --out "$DETECT_DIR/detection_report.json"

echo "=== [5/5] NS-3 simulation + network metrics ==="
bash NetSec/scripts/04_simulate.sh "$NS3_ROOT" "$DETECT_DIR/acl.json" "$ATTACK" "$SIM_DIR"

echo "All artifacts under $BASE"
