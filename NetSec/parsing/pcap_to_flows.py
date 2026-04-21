"""Convert a PCAP file into a structured bi-directional flow CSV.

Primary backend is `nfstream` which produces CICFlowMeter-compatible flow
features. When `nfstream` is unavailable (import/runtime failure), we fall back
to a minimal `scapy`-based parser that derives a much smaller feature set so
the pipeline can still be exercised end-to-end on small PCAPs.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List

import pandas as pd


CORE_COLUMNS: List[str] = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "start_ts",
    "end_ts",
    "duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_fin_packets",
    "bidirectional_rst_packets",
    "bidirectional_psh_packets",
    "bidirectional_urg_packets",
]


def _from_nfstream(pcap_path: str) -> pd.DataFrame:
    from nfstream import NFStreamer

    streamer = NFStreamer(
        source=pcap_path,
        decode_tunnels=True,
        bpf_filter=None,
        promiscuous_mode=False,
        snapshot_length=1536,
        idle_timeout=30,
        active_timeout=120,
        accounting_mode=0,
        udps=None,
        n_dissections=0,
        statistical_analysis=True,
        splt_analysis=0,
        n_meters=0,
        performance_report=0,
    )

    rows: List[Dict] = []
    for f in streamer:
        rows.append(
            {
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "proto": f.protocol,
                "start_ts": f.bidirectional_first_seen_ms / 1000.0,
                "end_ts": f.bidirectional_last_seen_ms / 1000.0,
                "duration_ms": f.bidirectional_duration_ms,
                "bidirectional_packets": f.bidirectional_packets,
                "bidirectional_bytes": f.bidirectional_bytes,
                "src2dst_packets": f.src2dst_packets,
                "src2dst_bytes": f.src2dst_bytes,
                "dst2src_packets": f.dst2src_packets,
                "dst2src_bytes": f.dst2src_bytes,
                "bidirectional_mean_ps": getattr(f, "bidirectional_mean_ps", 0.0),
                "bidirectional_stddev_ps": getattr(f, "bidirectional_stddev_ps", 0.0),
                "bidirectional_mean_piat_ms": getattr(f, "bidirectional_mean_piat_ms", 0.0),
                "bidirectional_stddev_piat_ms": getattr(f, "bidirectional_stddev_piat_ms", 0.0),
                "bidirectional_syn_packets": getattr(f, "bidirectional_syn_packets", 0),
                "bidirectional_ack_packets": getattr(f, "bidirectional_ack_packets", 0),
                "bidirectional_fin_packets": getattr(f, "bidirectional_fin_packets", 0),
                "bidirectional_rst_packets": getattr(f, "bidirectional_rst_packets", 0),
                "bidirectional_psh_packets": getattr(f, "bidirectional_psh_packets", 0),
                "bidirectional_urg_packets": getattr(f, "bidirectional_urg_packets", 0),
            }
        )
    return pd.DataFrame(rows, columns=CORE_COLUMNS)


def _from_scapy(pcap_path: str) -> pd.DataFrame:
    """Minimal fallback flow aggregator. 5-tuple keyed; directional merge.

    Produces the same `CORE_COLUMNS` schema (many features left at 0) so the
    downstream graph builder doesn't need two code paths.
    """
    from scapy.all import PcapReader, IP, TCP, UDP

    flows: Dict[tuple, Dict] = {}
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            proto = ip.proto
            sport = dport = 0
            tcp_flags = None
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                tcp_flags = int(pkt[TCP].flags)
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            fwd_key = (ip.src, ip.dst, sport, dport, proto)
            rev_key = (ip.dst, ip.src, dport, sport, proto)
            if rev_key in flows:
                key = rev_key
                direction = "dst2src"
            else:
                key = fwd_key
                direction = "src2dst"

            ts = float(pkt.time)
            plen = len(pkt)
            f = flows.setdefault(
                key,
                {
                    "src_ip": key[0],
                    "dst_ip": key[1],
                    "src_port": key[2],
                    "dst_port": key[3],
                    "proto": key[4],
                    "start_ts": ts,
                    "end_ts": ts,
                    "src2dst_packets": 0,
                    "src2dst_bytes": 0,
                    "dst2src_packets": 0,
                    "dst2src_bytes": 0,
                    "syn": 0,
                    "ack": 0,
                    "fin": 0,
                    "rst": 0,
                    "psh": 0,
                    "urg": 0,
                },
            )
            f["end_ts"] = max(f["end_ts"], ts)
            f["start_ts"] = min(f["start_ts"], ts)
            f[f"{direction}_packets"] += 1
            f[f"{direction}_bytes"] += plen
            if tcp_flags is not None:
                if tcp_flags & 0x02:
                    f["syn"] += 1
                if tcp_flags & 0x10:
                    f["ack"] += 1
                if tcp_flags & 0x01:
                    f["fin"] += 1
                if tcp_flags & 0x04:
                    f["rst"] += 1
                if tcp_flags & 0x08:
                    f["psh"] += 1
                if tcp_flags & 0x20:
                    f["urg"] += 1

    rows: List[Dict] = []
    for f in flows.values():
        total_pkts = f["src2dst_packets"] + f["dst2src_packets"]
        total_bytes = f["src2dst_bytes"] + f["dst2src_bytes"]
        duration_ms = max(0.0, (f["end_ts"] - f["start_ts"]) * 1000.0)
        rows.append(
            {
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "src_port": f["src_port"],
                "dst_port": f["dst_port"],
                "proto": f["proto"],
                "start_ts": f["start_ts"],
                "end_ts": f["end_ts"],
                "duration_ms": duration_ms,
                "bidirectional_packets": total_pkts,
                "bidirectional_bytes": total_bytes,
                "src2dst_packets": f["src2dst_packets"],
                "src2dst_bytes": f["src2dst_bytes"],
                "dst2src_packets": f["dst2src_packets"],
                "dst2src_bytes": f["dst2src_bytes"],
                "bidirectional_mean_ps": (total_bytes / total_pkts) if total_pkts else 0.0,
                "bidirectional_stddev_ps": 0.0,
                "bidirectional_mean_piat_ms": 0.0,
                "bidirectional_stddev_piat_ms": 0.0,
                "bidirectional_syn_packets": f["syn"],
                "bidirectional_ack_packets": f["ack"],
                "bidirectional_fin_packets": f["fin"],
                "bidirectional_rst_packets": f["rst"],
                "bidirectional_psh_packets": f["psh"],
                "bidirectional_urg_packets": f["urg"],
            }
        )
    return pd.DataFrame(rows, columns=CORE_COLUMNS)


def pcap_to_flows(pcap_path: str, backend: str = "auto") -> pd.DataFrame:
    if backend not in {"auto", "nfstream", "scapy"}:
        raise ValueError(f"Unknown backend: {backend}")

    if backend in {"auto", "nfstream"}:
        try:
            return _from_nfstream(pcap_path)
        except Exception as e:  # pragma: no cover - backend availability varies by env
            if backend == "nfstream":
                raise
            print(f"[pcap_to_flows] nfstream unavailable ({e}); falling back to scapy.", file=sys.stderr)
    return _from_scapy(pcap_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP -> bi-directional flow CSV")
    parser.add_argument("--pcap", required=True, help="Input PCAP path")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--backend", default="auto", choices=["auto", "nfstream", "scapy"])
    args = parser.parse_args()

    df = pcap_to_flows(args.pcap, backend=args.backend)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} flows to {args.out}")


if __name__ == "__main__":
    main()
