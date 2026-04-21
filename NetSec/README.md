# NetSec G-SafeGuard

This subproject adapts [G-SafeGuard](../README.md) from malicious multi-agent
LLM systems to network security. The same GAT-with-edge-features detector that
spots manipulative agents in [MA/](../MA/) is repurposed to spot malicious
hosts in a PCAP-derived host communication graph, with NS-3 providing a
controllable environment for measuring the impact of the resulting mitigation.

## Pipeline

```
PCAP -> flows -> labels -> windowed host graph -> NetGAT -> malicious hosts
                                                              |
                                                              v
                                                         ACL JSON
                                                              |
                                                              v
             NS-3 scenario ---------- benign + attack traffic, defended
```

## Concept mapping vs G-SafeGuard

| G-SafeGuard (MA/) | NetSec |
| --- | --- |
| Agent node | Host / IP node |
| Adjacency among agents | Host communication graph per time window |
| Per-turn message embedding | Per-sub-window flow feature vector |
| `edge_dim = (3, 384)` | `edge_dim = (T, F_edge)` (default 3 x 25) |
| `set_role("attacker")` -> drop attacker views in re-generation | ACL rule -> drop packets at NS-3 gateway |
| `cal_acc` / `cal_recog_acc` | Per-window P/R/F1 + per-window recognition rate |

The model (`NetSec/model/net_gat.py`) is a thin wrapper around the exact
`MyGAT` architecture in `MA/model.py`, unchanged.

## Directory layout

- `parsing/`
  - `pcap_to_flows.py` -- PCAP -> bi-directional flow CSV (nfstream, scapy fallback)
  - `labels.py` -- CICIDS2017 / UNSW-NB15 / known-attacker label join + per-host label derivation
- `graph/`
  - `features.py` -- node feature (`F_NODE=20`) and edge feature (`F_EDGE=25`) engineering
  - `build_graph.py` -- sliding-window snapshots with shape `edge_attr = [E, T, F_edge]`
- `model/`
  - `gat_with_attr_conv.py` -- copy of the MA GAT-with-edge-features conv
  - `net_gat.py` -- `NetGAT` wrapper (same architecture, different dims; has a self-check `python -m NetSec.model.net_gat`)
- `train/`
  - `dataset.py` -- PyG Dataset over snapshots JSON
  - `train.py` -- BCEWithLogits + Adam + cosine schedule, checkpoints per-epoch-best F1
- `detect/`
  - `detector.py` -- sliding-window inference -> verdicts JSON
  - `mitigation.py` -- verdicts -> time-indexed ACL JSON (`drop` / `rate_limit` / `redirect`; node or edge granularity)
- `simulation/`
  - `ns3/netsec_sim.cc` -- NS-3 scenario (attacker + clients + gateway + servers; scan/lateral/c2 attack apps; gateway-side packet-drop blocker)
  - `acl_to_csv.py` -- ACL JSON -> CSV consumed by the C++ scenario
  - `run_sim.py` -- Python orchestrator (runs both no-defense and defense passes)
- `evaluate/`
  - `detection_metrics.py` -- node-level P/R/F1/ROC-AUC + per-window recognition curve
  - `network_metrics.py` -- FlowMonitor XML -> benign latency/loss, attack success ratio, collateral
- `scripts/` -- 4 step scripts plus `run_all.sh` end-to-end
- `configs/default.yaml` -- all tunables (window sizes, feature dims, model dims, thresholds, mitigation policy, NS-3 scenario)

## Dependencies

- Python: see `NetSec/requirements.txt` plus the repo-root `requirement.txt` and `requirement-pygeometric.txt` (for `torch`, `torch_geometric`, `torch_scatter`).
- System: NS-3 >= 3.40 built locally (only needed for step 5/04).

Install Python extras on top of the existing `gsafeguard` conda env:

```bash
conda activate gsafeguard
pip install -r NetSec/requirements.txt
```

## Step-by-step usage

### 1. PCAP -> labeled graph snapshots

```bash
bash NetSec/scripts/01_prepare_data.sh \
    /path/to/cicids_train.pcap \
    NetSec/result/train \
    /path/to/cicids_flow_labels.csv
```

Or with a known-attacker IP list (useful when PCAPs are synthesized):

```bash
bash NetSec/scripts/01_prepare_data.sh \
    traffic.pcap \
    NetSec/result/train \
    --attackers=attackers.txt
```

Outputs `flows.csv`, `flows_labeled.csv`, and `snapshots.json`.

### 2. Train NetGAT

```bash
bash NetSec/scripts/02_train.sh NetSec/result/train/snapshots.json cpu
```

Writes `NetSec/checkpoint/<timestamp>-netgat-*.pth`.

### 3. Prepare test data and detect

```bash
bash NetSec/scripts/01_prepare_data.sh \
    /path/to/cicids_test.pcap \
    NetSec/result/test \
    /path/to/cicids_flow_labels.csv

CHECKPOINT=$(ls -t NetSec/checkpoint/*.pth | head -1)
bash NetSec/scripts/03_detect.sh \
    NetSec/result/test/snapshots.json \
    "$CHECKPOINT" \
    NetSec/result/detect
```

Produces `verdicts.json` and `acl.json`.

### 3b. Detection metrics

```bash
python -m NetSec.evaluate.detection_metrics \
    --snapshots NetSec/result/test/snapshots.json \
    --verdicts NetSec/result/detect/verdicts.json \
    --out NetSec/result/detect/detection_report.json
```

### 4. NS-3 simulation and network metrics

```bash
bash NetSec/scripts/04_simulate.sh \
    ~/ns-3-dev \
    NetSec/result/detect/acl.json \
    scan \
    NetSec/result/sim
```

This runs both `no_defense` (empty ACL) and `defense` scenarios, then emits
`network_metrics_scan.json` with latency / loss / attack-success / collateral.

### One-shot

```bash
bash NetSec/scripts/run_all.sh \
    train.pcap  /path/to/cicids_train_labels.csv \
    test.pcap   /path/to/cicids_test_labels.csv \
    ~/ns-3-dev  scan
```

## Notes on modeling choices

- **Why edge features carry a `T`-axis sequence.** G-SafeGuard models each
  edge as a 3-turn sequence of message embeddings; the GAT's edge aggregator
  collapses that sequence before attention. For network traffic, each edge is
  instead a sequence of `T` per-sub-window flow aggregates -- ideal for
  catching **C2 beaconing** (low IAT variance across sub-windows) and
  **progressive lateral movement** (feature drift across sub-windows).
- **Why node-level classification first.** It matches G-SafeGuard's output
  shape and supports the coarsest ACL (block by IP). An optional edge-level
  head is pre-wired in `NetGAT` (`edge_head=True`) for 5-tuple granularity.
- **Why time-indexed ACL rules.** In `mitigation.py` each rule activates at
  `window_end - first_window_start`, so the NS-3 simulation faithfully models
  detection latency: the attacker's initial packets pass before the blocker
  engages, allowing "dwell time" to be quantified.

## Known caveats

- The C++ `netsec_sim.cc` uses a simple promiscuous-receive callback as the
  filter point. For more realistic drop semantics replace it with an
  `Ipv4PacketFilter` on a `TrafficControlLayer` queue disc.
- Host identity breaks down under NAT; the feature engineering currently keys
  on IP only. For NATed traces, switch `src_ip` in the graph builder to
  `(ip, client-port-range)` to separate colocated hosts.
- CICIDS2017 label timestamps are coarse; `labels.py` joins on the 5-tuple
  only, which is usually sufficient but may mis-label traffic where a 5-tuple
  is reused across benign and attack flows.
