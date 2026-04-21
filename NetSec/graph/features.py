"""Feature engineering for the NetSec host graph.

Two feature vectors are produced per (window, sub-window):
    - Node feature `x_node` of size F_NODE  (aggregates over that host in the window)
    - Edge feature `x_edge` of size F_EDGE  (aggregates over all flows on that directed edge)

The edge-feature tensor across sub-windows is the direct analog of the
per-turn message embedding sequence in G-SafeGuard's `MyGAT`, where edges
carry a shape-`[T, F_edge]` tensor.
"""

from __future__ import annotations

import ipaddress
import math
from typing import List, Sequence, Tuple

import numpy as np
import pandas as pd


F_NODE = 20
F_EDGE = 25

NODE_FEATURE_NAMES: List[str] = [
    "out_degree",
    "in_degree",
    "unique_dst_ports",
    "unique_src_ports",
    "unique_dst_ips",
    "unique_src_ips",
    "total_bytes_out",
    "total_bytes_in",
    "total_pkts_out",
    "total_pkts_in",
    "mean_pkt_size_out",
    "std_pkt_size_out",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "is_internal",
    "is_proto_tcp",
    "is_proto_udp",
    "is_proto_icmp",
]

EDGE_FEATURE_NAMES: List[str] = [
    "flow_count",
    "total_bytes_fwd",
    "total_bytes_bwd",
    "total_pkts_fwd",
    "total_pkts_bwd",
    "mean_duration_ms",
    "mean_piat_ms",
    "std_piat_ms",
    "mean_pkt_size",
    "std_pkt_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "syn_only_ratio",
    "unique_dst_ports",
    "fanout_score",
    "periodicity_score",
    "mean_bytes_per_flow",
    "is_admin_port",
    "is_proto_tcp",
    "is_proto_udp",
    "is_proto_icmp",
]

ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}


def _safe(x: float) -> float:
    if x is None or (isinstance(x, float) and (math.isnan(x) or math.isinf(x))):
        return 0.0
    return float(x)


def _is_internal_ip(ip: str, nets: Sequence[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def parse_networks(cidrs: Sequence[str]) -> List[ipaddress.IPv4Network]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def compute_node_features(
    host_ip: str,
    flows_out: pd.DataFrame,
    flows_in: pd.DataFrame,
    internal_nets: Sequence[ipaddress.IPv4Network],
) -> np.ndarray:
    f = np.zeros(F_NODE, dtype=np.float32)
    f[0] = flows_out["dst_ip"].nunique() if not flows_out.empty else 0
    f[1] = flows_in["src_ip"].nunique() if not flows_in.empty else 0
    f[2] = flows_out["dst_port"].nunique() if not flows_out.empty else 0
    f[3] = flows_in["src_port"].nunique() if not flows_in.empty else 0
    f[4] = flows_out["dst_ip"].nunique() if not flows_out.empty else 0
    f[5] = flows_in["src_ip"].nunique() if not flows_in.empty else 0

    out_bytes = float(flows_out["src2dst_bytes"].sum()) if not flows_out.empty else 0.0
    in_bytes = float(flows_in["src2dst_bytes"].sum()) if not flows_in.empty else 0.0
    out_pkts = float(flows_out["src2dst_packets"].sum()) if not flows_out.empty else 0.0
    in_pkts = float(flows_in["src2dst_packets"].sum()) if not flows_in.empty else 0.0
    f[6] = out_bytes
    f[7] = in_bytes
    f[8] = out_pkts
    f[9] = in_pkts
    f[10] = (out_bytes / out_pkts) if out_pkts > 0 else 0.0
    f[11] = _safe(flows_out["bidirectional_stddev_ps"].mean()) if not flows_out.empty else 0.0

    total_pkts = float(flows_out["bidirectional_packets"].sum()) if not flows_out.empty else 0.0
    if total_pkts > 0:
        f[12] = float(flows_out["bidirectional_syn_packets"].sum()) / total_pkts
        f[13] = float(flows_out["bidirectional_ack_packets"].sum()) / total_pkts
        f[14] = float(flows_out["bidirectional_fin_packets"].sum()) / total_pkts
        f[15] = float(flows_out["bidirectional_rst_packets"].sum()) / total_pkts

    f[16] = 1.0 if _is_internal_ip(host_ip, internal_nets) else 0.0

    if not flows_out.empty:
        protos = flows_out["proto"].value_counts(normalize=True)
        f[17] = float(protos.get(6, 0.0))   # TCP
        f[18] = float(protos.get(17, 0.0))  # UDP
        f[19] = float(protos.get(1, 0.0))   # ICMP
    return f


def compute_edge_features(edge_flows: pd.DataFrame) -> np.ndarray:
    """Aggregate all flows on a single directed edge in a single sub-window."""
    f = np.zeros(F_EDGE, dtype=np.float32)
    if edge_flows.empty:
        return f

    n = len(edge_flows)
    f[0] = n
    f[1] = float(edge_flows["src2dst_bytes"].sum())
    f[2] = float(edge_flows["dst2src_bytes"].sum())
    f[3] = float(edge_flows["src2dst_packets"].sum())
    f[4] = float(edge_flows["dst2src_packets"].sum())
    f[5] = _safe(edge_flows["duration_ms"].mean())
    f[6] = _safe(edge_flows["bidirectional_mean_piat_ms"].mean())
    f[7] = _safe(edge_flows["bidirectional_stddev_piat_ms"].mean())
    f[8] = _safe(edge_flows["bidirectional_mean_ps"].mean())
    f[9] = _safe(edge_flows["bidirectional_stddev_ps"].mean())

    syn = float(edge_flows["bidirectional_syn_packets"].sum())
    ack = float(edge_flows["bidirectional_ack_packets"].sum())
    fin = float(edge_flows["bidirectional_fin_packets"].sum())
    rst = float(edge_flows["bidirectional_rst_packets"].sum())
    psh = float(edge_flows["bidirectional_psh_packets"].sum())
    urg = float(edge_flows["bidirectional_urg_packets"].sum())
    total_pkts = float(edge_flows["bidirectional_packets"].sum())
    f[10] = syn
    f[11] = ack
    f[12] = fin
    f[13] = rst
    f[14] = psh
    f[15] = urg
    f[16] = (syn / total_pkts) if total_pkts > 0 else 0.0  # SYN-only -> scan signal

    f[17] = edge_flows["dst_port"].nunique()
    f[18] = f[17] / max(n, 1)  # fan-out score: unique ports / flows

    # Periodicity score (C2 beaconing): low IAT stddev + low duration stddev -> high
    piat_std = _safe(edge_flows["bidirectional_stddev_piat_ms"].mean())
    piat_mean = _safe(edge_flows["bidirectional_mean_piat_ms"].mean())
    f[19] = 1.0 / (1.0 + piat_std / max(piat_mean, 1.0))

    f[20] = (f[1] + f[2]) / max(n, 1)

    is_admin = edge_flows["dst_port"].isin(ADMIN_PORTS).any()
    f[21] = 1.0 if is_admin else 0.0

    protos = edge_flows["proto"].value_counts(normalize=True)
    f[22] = float(protos.get(6, 0.0))
    f[23] = float(protos.get(17, 0.0))
    f[24] = float(protos.get(1, 0.0))

    return f


assert F_NODE == len(NODE_FEATURE_NAMES)
assert F_EDGE == len(EDGE_FEATURE_NAMES)
