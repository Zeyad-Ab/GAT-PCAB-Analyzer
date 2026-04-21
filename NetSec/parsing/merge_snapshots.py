"""Merge multiple graph-snapshot JSON files (from graph/build_graph.py) into one.

Each input is a list of snapshot dicts; the merged output is a flat list in the
order the inputs were given. Useful when training on multiple PCAPs (e.g. the
five CICIDS2017 days) so train.py receives a single snapshots JSON.

Usage:
    python -m NetSec.parsing.merge_snapshots \
        --inputs result/day1/snapshots.json result/day2/snapshots.json ... \
        --out result/all_days/snapshots.json
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List


def merge(input_paths: List[str], out_path: str) -> int:
    merged: list = []
    for p in input_paths:
        with open(p) as f:
            snaps = json.load(f)
        if not isinstance(snaps, list):
            raise ValueError(f"{p} does not contain a list of snapshots")
        merged.extend(snaps)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(merged, f)
    return len(merged)


def main():
    p = argparse.ArgumentParser(description="Merge multiple snapshot JSONs")
    p.add_argument("--inputs", nargs="+", required=True, help="Snapshot JSON files to merge (in order)")
    p.add_argument("--out", required=True, help="Output merged snapshot JSON path")
    args = p.parse_args()

    n = merge(args.inputs, args.out)
    print(f"Merged {len(args.inputs)} files -> {n} snapshots at {args.out}")


if __name__ == "__main__":
    main()
