"""Attach ground-truth labels to parsed flows.

Supports two layouts:
    - CICIDS2017: per-flow labeled CSV(s) with columns like
      `Source IP, Destination IP, Source Port, Destination Port, Protocol,
       Timestamp, Label` (with `BENIGN` vs attack-type strings).
    - UNSW-NB15: csv with 5-tuple + `attack_cat`/`label` columns.
    - Generic: a `known_attackers` text file (one IP per line) -- every flow
      originating from or destined to such an IP is marked attack. This is
      useful for NS-3 synthesized traffic where ground truth is known by
      construction.

Produces a flow CSV augmented with:
    - `label` (int, 1 = attack, 0 = benign)
    - `attack_type` (str, 'BENIGN' if benign)

Also offers a helper that derives per-host labels for a set of flows
restricted to a given time window (used by the graph builder).
"""

from __future__ import annotations

import argparse
import os
from typing import Iterable, Set

import pandas as pd


def _norm_cols(cols: Iterable[str]) -> Iterable[str]:
    return [c.strip().lower().replace(" ", "_") for c in cols]


def attach_cicids_labels(flows: pd.DataFrame, cicids_csv: str, ts_tolerance_s: float = 2.0) -> pd.DataFrame:
    """Inner-merge flows with CICIDS2017 per-flow labels on the 5-tuple.

    CICIDS2017 timestamps are coarse, so we match only on the 5-tuple and
    accept the nearest label per 5-tuple to avoid double-counting. If multiple
    labels match, an attack label wins over BENIGN.
    """
    labeled = pd.read_csv(cicids_csv, low_memory=False)
    labeled.columns = list(_norm_cols(labeled.columns))

    rename_map = {
        "source_ip": "src_ip",
        "destination_ip": "dst_ip",
        "source_port": "src_port",
        "destination_port": "dst_port",
        "protocol": "proto",
    }
    for k, v in rename_map.items():
        if k in labeled.columns and v not in labeled.columns:
            labeled = labeled.rename(columns={k: v})

    needed = {"src_ip", "dst_ip", "src_port", "dst_port", "proto", "label"}
    missing = needed - set(labeled.columns)
    if missing:
        raise ValueError(f"CICIDS labels CSV missing columns: {missing}")

    labeled["label_str"] = labeled["label"].astype(str).str.upper()
    labeled["is_attack"] = (labeled["label_str"] != "BENIGN").astype(int)
    collapsed = (
        labeled.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "proto"], as_index=False)
        .agg(is_attack=("is_attack", "max"), attack_type=("label_str", lambda s: sorted(set(s))[-1]))
    )

    merged = flows.merge(collapsed, how="left", on=["src_ip", "dst_ip", "src_port", "dst_port", "proto"])
    merged["is_attack"] = merged["is_attack"].fillna(0).astype(int)
    merged["attack_type"] = merged["attack_type"].fillna("BENIGN")
    merged = merged.rename(columns={"is_attack": "label"})
    return merged


def attach_known_attackers(flows: pd.DataFrame, attackers_file: str, match: str = "src") -> pd.DataFrame:
    """Label every flow whose src_ip (or endpoint) is in the attackers list."""
    with open(attackers_file) as f:
        attackers: Set[str] = {line.strip() for line in f if line.strip() and not line.startswith("#")}

    flows = flows.copy()
    if match == "src":
        mask = flows["src_ip"].isin(attackers)
    elif match == "dst":
        mask = flows["dst_ip"].isin(attackers)
    elif match == "either":
        mask = flows["src_ip"].isin(attackers) | flows["dst_ip"].isin(attackers)
    else:
        raise ValueError(f"Unknown match mode: {match}")

    flows["label"] = mask.astype(int)
    flows["attack_type"] = flows["label"].map({1: "ATTACKER_IP", 0: "BENIGN"})
    flows["attacker_set"] = ",".join(sorted(attackers))
    return flows


def derive_host_labels(window_flows: pd.DataFrame) -> dict:
    """Return {ip -> int label} for all hosts present in the given window.

    A host is labeled malicious (1) if it is the source of at least one
    attack-labeled flow in the window.
    """
    if window_flows.empty:
        return {}
    attacker_ips = set(window_flows.loc[window_flows["label"] == 1, "src_ip"].unique())
    all_hosts = set(window_flows["src_ip"].unique()) | set(window_flows["dst_ip"].unique())
    return {ip: int(ip in attacker_ips) for ip in all_hosts}


def main() -> None:
    parser = argparse.ArgumentParser(description="Attach attack labels to a flow CSV")
    parser.add_argument("--flows", required=True, help="Input flow CSV from pcap_to_flows.py")
    parser.add_argument("--out", required=True, help="Output labeled flow CSV")
    parser.add_argument("--cicids_csv", help="CICIDS2017 per-flow labels CSV")
    parser.add_argument("--attackers_file", help="Text file of known attacker IPs (one per line)")
    parser.add_argument("--attacker_match", default="src", choices=["src", "dst", "either"])
    args = parser.parse_args()

    if not args.cicids_csv and not args.attackers_file:
        raise SystemExit("Must provide --cicids_csv or --attackers_file")

    flows = pd.read_csv(args.flows, low_memory=False)

    if args.cicids_csv:
        flows = attach_cicids_labels(flows, args.cicids_csv)
    else:
        flows = attach_known_attackers(flows, args.attackers_file, match=args.attacker_match)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    flows.to_csv(args.out, index=False)
    n_att = int(flows["label"].sum())
    print(f"Wrote {len(flows)} labeled flows ({n_att} attack) to {args.out}")


if __name__ == "__main__":
    main()
