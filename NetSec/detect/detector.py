"""Sliding-window inference: snapshots JSON + checkpoint -> verdicts JSON.

Output verdicts schema (list, one entry per window):
{
  "window_start": float, "window_end": float,
  "node_ips":      [str, ...],
  "node_scores":   [float, ...],  # sigmoid probabilities
  "node_predicts": [int, ...],    # 0/1 after threshold
  "edge_index":    [[src...], [dst...]],
  "edge_scores":   [float, ...] (optional, if edge_head enabled),
  "malicious_ips": [str, ...]
}
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List

import numpy as np
import torch
import yaml

from NetSec.model.net_gat import NetGAT
from NetSec.train.dataset import NetSecGraphDataset


def infer(
    snapshots_path: str,
    checkpoint_path: str,
    config_path: str,
    threshold: float | None = None,
    device_arg: str = "cpu",
) -> List[dict]:
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    ds = NetSecGraphDataset(snapshots_path)
    if len(ds) == 0:
        return []

    example = ds.get(0)
    in_channels = int(example.x.size(1))
    edge_dim = tuple(example.edge_attr.size()[1:])

    device = torch.device(device_arg) if device_arg != "auto" else torch.device(
        "cuda:0" if torch.cuda.is_available() else ("mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu")
    )

    model_cfg = cfg["model"]
    model = NetGAT(
        in_channels=in_channels,
        edge_dim=edge_dim,
        hidden_channels=int(model_cfg["hidden_channels"]),
        heads=int(model_cfg["heads"]),
        num_layers=int(model_cfg["num_layers"]),
        dropout=float(model_cfg["dropout"]),
        aggr_type=str(model_cfg["aggr_type"]),
        residual=bool(model_cfg["residual"]),
    ).to(device)
    state = torch.load(checkpoint_path, map_location=device)
    model.load_state_dict(state)
    model.eval()

    thr = float(threshold) if threshold is not None else float(cfg["detection"]["threshold"])

    verdicts: List[dict] = []
    with torch.no_grad():
        for i in range(len(ds)):
            data = ds.get(i).to(device)
            logits = model(data.x, data.edge_index, data.edge_attr)
            scores = torch.sigmoid(logits).detach().cpu().numpy().tolist()
            preds = [int(s >= thr) for s in scores]
            malicious_ips = [ip for ip, p in zip(data.node_ips, preds) if p == 1]
            verdicts.append(
                {
                    "window_start": float(data.window_start),
                    "window_end": float(data.window_end),
                    "node_ips": list(data.node_ips),
                    "node_scores": [float(s) for s in scores],
                    "node_predicts": preds,
                    "edge_index": data.edge_index.detach().cpu().numpy().tolist(),
                    "malicious_ips": malicious_ips,
                }
            )
    return verdicts


def main():
    p = argparse.ArgumentParser(description="Sliding-window detection using NetGAT")
    p.add_argument("--snapshots", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--config", default="NetSec/configs/default.yaml")
    p.add_argument("--threshold", type=float, default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--device", default="cpu")
    args = p.parse_args()

    verdicts = infer(args.snapshots, args.checkpoint, args.config, args.threshold, args.device)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(verdicts, f)

    n_mal = sum(len(v["malicious_ips"]) for v in verdicts)
    print(f"Wrote {len(verdicts)} window verdicts ({n_mal} malicious host decisions) to {args.out}")


if __name__ == "__main__":
    main()
