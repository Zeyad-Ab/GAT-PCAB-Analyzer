"""PyG dataset wrapping the JSON graph snapshots from graph/build_graph.py."""

from __future__ import annotations

import json
import os
from typing import List, Optional

import numpy as np
import torch
from torch_geometric.data import Data, Dataset


class NetSecGraphDataset(Dataset):
    def __init__(self, snapshots_path: str, indices: Optional[List[int]] = None, transform=None):
        super().__init__(root=None, transform=transform)
        with open(snapshots_path) as f:
            self._snapshots = json.load(f)
        self._indices_override = indices

    def _select(self) -> List[int]:
        return self._indices_override if self._indices_override is not None else list(range(len(self._snapshots)))

    def len(self) -> int:
        return len(self._select())

    def get(self, idx: int) -> Data:
        real_idx = self._select()[idx]
        s = self._snapshots[real_idx]
        x = torch.tensor(np.asarray(s["x"], dtype=np.float32))
        edge_index = torch.tensor(np.asarray(s["edge_index"], dtype=np.int64))
        edge_attr = torch.tensor(np.asarray(s["edge_attr"], dtype=np.float32))
        y = torch.tensor(np.asarray(s["y"], dtype=np.int64))
        edge_y = torch.tensor(np.asarray(s.get("edge_y", []), dtype=np.int64)) if s.get("edge_y") else torch.empty(0, dtype=torch.long)
        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)
        data.edge_y = edge_y
        data.window_start = float(s["window_start"])
        data.window_end = float(s["window_end"])
        data.node_ips = s["node_ips"]
        return data


def split_indices(n: int, val_split: float, seed: int = 42):
    rng = np.random.default_rng(seed)
    idx = np.arange(n)
    rng.shuffle(idx)
    n_val = max(1, int(n * val_split)) if n > 1 else 0
    val = idx[:n_val].tolist()
    train = idx[n_val:].tolist()
    return train, val
