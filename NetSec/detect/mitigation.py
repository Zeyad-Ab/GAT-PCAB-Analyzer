"""Convert window verdicts into a time-indexed ACL JSON consumed by NS-3.

ACL JSON schema:
{
  "policy": "drop" | "rate_limit" | "redirect",
  "granularity": "node" | "edge",
  "rate_limit_mbps": float (if policy == rate_limit),
  "rules": [
      {
        "activate_at": float,     # simulation seconds (relative to sim start)
        "match": {
            "src_ip": "...",      # optional
            "dst_ip": "...",      # optional
            "protocol": int        # optional
        },
        "action": "drop" | "rate_limit" | "redirect"
      }, ...
  ]
}

Rule activation time = (verdict window_end - first_window_start) so mitigation
kicks in only *after* detection, allowing the simulation to measure how much
attacker activity leaks through before the blocker engages (dwell time).
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List, Set

import yaml


def verdicts_to_acl(verdicts: List[dict], policy: str, granularity: str, rate_limit_mbps: float) -> dict:
    if not verdicts:
        return {"policy": policy, "granularity": granularity, "rate_limit_mbps": rate_limit_mbps, "rules": []}

    t0 = min(v["window_start"] for v in verdicts)
    seen: Set = set()
    rules: List[dict] = []
    for v in verdicts:
        activate_at = float(v["window_end"] - t0)
        if granularity == "node":
            for ip in v["malicious_ips"]:
                key = ("node", ip)
                if key in seen:
                    continue
                seen.add(key)
                rules.append(
                    {
                        "activate_at": activate_at,
                        "match": {"src_ip": ip},
                        "action": policy,
                    }
                )
        elif granularity == "edge":
            node_ips = v["node_ips"]
            predicts = v["node_predicts"]
            edge_index = v["edge_index"]
            src_list, dst_list = edge_index[0], edge_index[1]
            for s_idx, d_idx in zip(src_list, dst_list):
                if predicts[s_idx] == 1:
                    s_ip, d_ip = node_ips[s_idx], node_ips[d_idx]
                    key = ("edge", s_ip, d_ip)
                    if key in seen:
                        continue
                    seen.add(key)
                    rules.append(
                        {
                            "activate_at": activate_at,
                            "match": {"src_ip": s_ip, "dst_ip": d_ip},
                            "action": policy,
                        }
                    )
        else:
            raise ValueError(f"Unknown granularity: {granularity}")

    return {
        "policy": policy,
        "granularity": granularity,
        "rate_limit_mbps": rate_limit_mbps,
        "rules": rules,
    }


def main():
    p = argparse.ArgumentParser(description="Verdicts -> ACL JSON for NS-3")
    p.add_argument("--verdicts", required=True)
    p.add_argument("--config", default="NetSec/configs/default.yaml")
    p.add_argument("--out", required=True)
    p.add_argument("--policy", default=None, choices=[None, "drop", "rate_limit", "redirect"])
    p.add_argument("--granularity", default=None, choices=[None, "node", "edge"])
    args = p.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    mit = cfg["mitigation"]
    policy = args.policy or mit["policy"]
    granularity = args.granularity or mit["granularity"]
    rate = float(mit.get("rate_limit_mbps", 1.0))

    with open(args.verdicts) as f:
        verdicts = json.load(f)

    acl = verdicts_to_acl(verdicts, policy, granularity, rate)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(acl, f, indent=2)
    print(f"Wrote ACL with {len(acl['rules'])} rules to {args.out}")


if __name__ == "__main__":
    main()
