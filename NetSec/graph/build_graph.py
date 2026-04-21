"""Slide a time window over labeled flows and produce graph snapshots.

Each snapshot is serialized as a dict with:
    - `window_start`, `window_end`, `sub_windows` (T)
    - `node_ips`:    list of host IPs, index i = node i
    - `x`:           [N, F_node]  node features (aggregated over the whole window)
    - `edge_index`:  [2, E]       directed edges
    - `edge_attr`:   [E, T, F_edge]  per sub-window edge features
    - `y`:           [N]          per-host malicious label (0/1)

The snapshots are designed to be loaded directly by the PyG `InMemoryDataset`
in train/dataset.py and then fed into `MyGAT` with the exact same signature
used in `MA/main_defense_for_different_topology.py`.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import yaml

from NetSec.graph.features import (
    F_EDGE,
    F_NODE,
    compute_edge_features,
    compute_node_features,
    parse_networks,
)
from NetSec.parsing.labels import derive_host_labels


@dataclass
class GraphSnapshot:
    window_start: float
    window_end: float
    sub_windows: int
    node_ips: List[str]
    x: List[List[float]]
    edge_index: List[List[int]]
    edge_attr: List[List[List[float]]]
    y: List[int]
    edge_y: List[int] = field(default_factory=list)
    attack_types: List[str] = field(default_factory=list)


def _active_hosts(window_flows: pd.DataFrame) -> List[str]:
    hosts = pd.Index(window_flows["src_ip"]).append(pd.Index(window_flows["dst_ip"]))
    return sorted(hosts.unique().tolist())


def _subwindow_slices(
    window_flows: pd.DataFrame, t_start: float, t_end: float, T: int
) -> List[pd.DataFrame]:
    step = (t_end - t_start) / T
    slices: List[pd.DataFrame] = []
    for i in range(T):
        a = t_start + i * step
        b = t_end if i == T - 1 else t_start + (i + 1) * step
        mask = (window_flows["start_ts"] >= a) & (window_flows["start_ts"] < b + 1e-9)
        slices.append(window_flows.loc[mask])
    return slices


def build_snapshot(
    window_flows: pd.DataFrame,
    t_start: float,
    t_end: float,
    T: int,
    internal_nets,
) -> GraphSnapshot | None:
    if window_flows.empty:
        return None

    node_ips = _active_hosts(window_flows)
    if len(node_ips) < 2:
        return None
    ip_to_idx: Dict[str, int] = {ip: i for i, ip in enumerate(node_ips)}

    x = np.zeros((len(node_ips), F_NODE), dtype=np.float32)
    for ip, idx in ip_to_idx.items():
        flows_out = window_flows[window_flows["src_ip"] == ip]
        flows_in = window_flows[window_flows["dst_ip"] == ip]
        x[idx] = compute_node_features(ip, flows_out, flows_in, internal_nets)

    grouped = window_flows.groupby(["src_ip", "dst_ip"], sort=False)
    edge_pairs: List[Tuple[int, int]] = []
    edge_y: List[int] = []
    for (s, d), g in grouped:
        if s not in ip_to_idx or d not in ip_to_idx:
            continue
        edge_pairs.append((ip_to_idx[s], ip_to_idx[d]))
        edge_y.append(int((g["label"] == 1).any()) if "label" in g.columns else 0)
    if not edge_pairs:
        return None

    sub_slices = _subwindow_slices(window_flows, t_start, t_end, T)
    E = len(edge_pairs)
    edge_attr = np.zeros((E, T, F_EDGE), dtype=np.float32)
    for t_idx, sub in enumerate(sub_slices):
        if sub.empty:
            continue
        sub_groups = {k: v for k, v in sub.groupby(["src_ip", "dst_ip"], sort=False)}
        for e_idx, (s_idx, d_idx) in enumerate(edge_pairs):
            s_ip = node_ips[s_idx]
            d_ip = node_ips[d_idx]
            g = sub_groups.get((s_ip, d_ip))
            if g is None or g.empty:
                continue
            edge_attr[e_idx, t_idx, :] = compute_edge_features(g)

    host_labels = derive_host_labels(window_flows)
    y = [int(host_labels.get(ip, 0)) for ip in node_ips]

    attack_types = (
        window_flows.loc[window_flows["label"] == 1, "attack_type"].unique().tolist()
        if "attack_type" in window_flows.columns
        else []
    )

    edge_index_list = [[s for s, _ in edge_pairs], [d for _, d in edge_pairs]]

    return GraphSnapshot(
        window_start=float(t_start),
        window_end=float(t_end),
        sub_windows=T,
        node_ips=node_ips,
        x=x.tolist(),
        edge_index=edge_index_list,
        edge_attr=edge_attr.tolist(),
        y=y,
        edge_y=edge_y,
        attack_types=[str(a) for a in attack_types],
    )


def build_graph_dataset(
    flows_df: pd.DataFrame,
    window_s: float,
    stride_s: float,
    T: int,
    internal_cidrs,
    min_nodes: int = 2,
    min_edges: int = 1,
) -> List[GraphSnapshot]:
    if flows_df.empty:
        return []
    if "label" not in flows_df.columns:
        flows_df = flows_df.copy()
        flows_df["label"] = 0
        flows_df["attack_type"] = "BENIGN"

    flows_df = flows_df.sort_values("start_ts").reset_index(drop=True)
    t0 = float(flows_df["start_ts"].min())
    t1 = float(flows_df["end_ts"].max())
    internal_nets = parse_networks(internal_cidrs)

    snapshots: List[GraphSnapshot] = []
    t = t0
    while t < t1:
        t_end = t + window_s
        mask = (flows_df["start_ts"] >= t) & (flows_df["start_ts"] < t_end)
        w = flows_df.loc[mask]
        snap = build_snapshot(w, t, t_end, T, internal_nets)
        if snap is not None and len(snap.node_ips) >= min_nodes and len(snap.edge_attr) >= min_edges:
            snapshots.append(snap)
        t += stride_s
    return snapshots


def save_snapshots(snapshots: List[GraphSnapshot], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = [asdict(s) for s in snapshots]
    with open(path, "w") as f:
        json.dump(payload, f)


def main() -> None:
    parser = argparse.ArgumentParser(description="Flows CSV -> graph snapshots JSON")
    parser.add_argument("--flows", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--config", default="NetSec/configs/default.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    flows = pd.read_csv(args.flows, low_memory=False)
    snaps = build_graph_dataset(
        flows,
        window_s=float(cfg["pipeline"]["window_seconds"]),
        stride_s=float(cfg["pipeline"]["stride_seconds"]),
        T=int(cfg["pipeline"]["sub_windows"]),
        internal_cidrs=cfg["features"]["internal_networks"],
        min_nodes=int(cfg["pipeline"]["min_nodes_per_window"]),
        min_edges=int(cfg["pipeline"]["min_edges_per_window"]),
    )
    save_snapshots(snaps, args.out)
    print(f"Wrote {len(snaps)} graph snapshots to {args.out}")


if __name__ == "__main__":
    main()
