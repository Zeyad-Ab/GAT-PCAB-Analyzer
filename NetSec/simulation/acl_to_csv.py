"""Convert ACL JSON (from detect/mitigation.py) into a flat CSV consumed by netsec_sim.cc.

CSV header: activate_at_s,src_ip,dst_ip,proto,action
Empty string means wildcard. Proto is an integer IP protocol number or empty.
"""

from __future__ import annotations

import argparse
import csv
import json
import os


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--acl", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    with open(args.acl) as f:
        acl = json.load(f)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["activate_at_s", "src_ip", "dst_ip", "proto", "action"])
        for r in acl.get("rules", []):
            m = r.get("match", {})
            w.writerow(
                [
                    f"{float(r.get('activate_at', 0.0)):.6f}",
                    m.get("src_ip", ""),
                    m.get("dst_ip", ""),
                    m.get("protocol", "") if m.get("protocol") is not None else "",
                    r.get("action", "drop"),
                ]
            )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
