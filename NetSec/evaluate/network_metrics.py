"""Parse NS-3 FlowMonitor XML and report network KPIs per scenario.

Compares two FlowMonitor files (no_defense vs defense) and emits:
    - Benign-flow mean/p95 latency and packet-loss ratio
    - Attack success proxies (flows from attacker / compromised insider that
      reached their target with >= 1 received packet)
    - Collateral damage (benign flows fully dropped in defense scenario)
    - Aggregate goodput (bytes received) per scenario

Ground truth for "attacker" vs "benign" per flow is derived from a list of
attacker IPs (passed via --attacker_ips). For NS-3 scenarios produced by
`simulation/netsec_sim.cc`, the attacker IP is `10.0.100.1` by default.
"""

from __future__ import annotations

import argparse
import json
import statistics
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional


def _parse_flowmon(path: str) -> List[Dict]:
    tree = ET.parse(path)
    root = tree.getroot()

    classifiers = {}
    for fc in root.iter("FlowClassifier"):
        for flow in fc.iter("Flow"):
            classifiers[flow.get("flowId")] = {
                "src_ip": flow.get("sourceAddress"),
                "dst_ip": flow.get("destinationAddress"),
                "src_port": int(flow.get("sourcePort", 0)),
                "dst_port": int(flow.get("destinationPort", 0)),
                "proto": int(flow.get("protocol", 0)),
            }

    flows: List[Dict] = []
    for flow in root.iter("Flow"):
        fid = flow.get("flowId")
        cls = classifiers.get(fid, {})
        tx_pkts = int(flow.get("txPackets", 0))
        rx_pkts = int(flow.get("rxPackets", 0))
        tx_bytes = int(flow.get("txBytes", 0))
        rx_bytes = int(flow.get("rxBytes", 0))
        lost = int(flow.get("lostPackets", 0))
        delay_sum_ns = float(flow.get("delaySum", "+0.0ns").rstrip("ns").lstrip("+"))
        jitter_sum_ns = float(flow.get("jitterSum", "+0.0ns").rstrip("ns").lstrip("+"))
        flows.append(
            {
                "flow_id": int(fid) if fid else -1,
                **cls,
                "tx_packets": tx_pkts,
                "rx_packets": rx_pkts,
                "tx_bytes": tx_bytes,
                "rx_bytes": rx_bytes,
                "lost_packets": lost,
                "mean_delay_ms": (delay_sum_ns / max(1, rx_pkts)) / 1e6,
                "mean_jitter_ms": (jitter_sum_ns / max(1, rx_pkts)) / 1e6,
                "loss_ratio": lost / max(1, tx_pkts),
            }
        )
    return flows


def _p95(xs: List[float]) -> Optional[float]:
    if not xs:
        return None
    xs_sorted = sorted(xs)
    k = min(len(xs_sorted) - 1, int(0.95 * (len(xs_sorted) - 1)))
    return float(xs_sorted[k])


def _scenario_summary(flows: List[Dict], attacker_ips) -> Dict:
    benign = [f for f in flows if f["src_ip"] not in attacker_ips and f["dst_ip"] not in attacker_ips]
    attack = [f for f in flows if f["src_ip"] in attacker_ips or f["dst_ip"] in attacker_ips]

    benign_delays = [f["mean_delay_ms"] for f in benign if f["rx_packets"] > 0]
    benign_losses = [f["loss_ratio"] for f in benign]
    benign_goodput = sum(f["rx_bytes"] for f in benign)

    attack_successful = sum(1 for f in attack if f["rx_packets"] > 0)

    return {
        "n_flows_total": len(flows),
        "n_flows_benign": len(benign),
        "n_flows_attack": len(attack),
        "benign_mean_delay_ms": statistics.fmean(benign_delays) if benign_delays else None,
        "benign_p95_delay_ms": _p95(benign_delays),
        "benign_mean_loss_ratio": statistics.fmean(benign_losses) if benign_losses else None,
        "benign_total_rx_bytes": benign_goodput,
        "attack_flows_with_delivery": attack_successful,
        "attack_success_ratio": attack_successful / max(1, len(attack)),
    }


def compare(no_def_xml: str, def_xml: str, attacker_ips: List[str]) -> Dict:
    nd = _parse_flowmon(no_def_xml)
    df = _parse_flowmon(def_xml)
    atk = set(attacker_ips)

    nd_summary = _scenario_summary(nd, atk)
    df_summary = _scenario_summary(df, atk)

    nd_benign_keys = {(f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["proto"]) for f in nd if f["src_ip"] not in atk and f["dst_ip"] not in atk and f["rx_packets"] > 0}
    df_benign_keys = {(f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["proto"]) for f in df if f["src_ip"] not in atk and f["dst_ip"] not in atk and f["rx_packets"] > 0}
    collateral = nd_benign_keys - df_benign_keys
    collateral_ratio = len(collateral) / max(1, len(nd_benign_keys))

    attack_success_reduction = (
        nd_summary["attack_success_ratio"] - df_summary["attack_success_ratio"]
    )

    return {
        "no_defense": nd_summary,
        "defense": df_summary,
        "attacker_ips": sorted(atk),
        "collateral_benign_flows_dropped": len(collateral),
        "collateral_ratio": collateral_ratio,
        "attack_success_ratio_reduction": attack_success_reduction,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--no_defense", required=True, help="FlowMonitor XML (no-defense run)")
    p.add_argument("--defense", required=True, help="FlowMonitor XML (defense run)")
    p.add_argument("--attacker_ips", required=True, help="Comma-separated list of attacker IPs")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    attackers = [a.strip() for a in args.attacker_ips.split(",") if a.strip()]
    report = compare(args.no_defense, args.defense, attackers)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    nd, df = report["no_defense"], report["defense"]
    print("No-defense: benign_delay_mean_ms={} p95={} loss={} | atk_success={:.2f}".format(
        nd["benign_mean_delay_ms"], nd["benign_p95_delay_ms"], nd["benign_mean_loss_ratio"], nd["attack_success_ratio"]))
    print("Defense   : benign_delay_mean_ms={} p95={} loss={} | atk_success={:.2f}".format(
        df["benign_mean_delay_ms"], df["benign_p95_delay_ms"], df["benign_mean_loss_ratio"], df["attack_success_ratio"]))
    print("Attack-success reduction: {:.3f} | collateral benign flows: {} ({:.1%})".format(
        report["attack_success_ratio_reduction"], report["collateral_benign_flows_dropped"], report["collateral_ratio"]))
    print(f"Report: {args.out}")


if __name__ == "__main__":
    main()
