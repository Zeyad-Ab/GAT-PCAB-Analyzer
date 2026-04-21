"""GAT-with-edge-features detector for NetSec, thin wrapper over MA's MyGAT.

Reuses the exact architecture from `MA/model.py` (GATConv with per-head edge
features + a sub-window aggregator). Only the input/edge dims differ: node
features are host-level aggregates (F_NODE) instead of sentence embeddings,
and edge features are per-sub-window flow aggregates with shape (T, F_EDGE).
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from NetSec.model.gat_with_attr_conv import GATwithEdgeConv


class SubWindowAggregator(nn.Module):
    """Aggregate edge features across T sub-windows down to a single vector.

    Mirrors MA/model.py's `DiaglogueEmbeddingProcessModules` so that swapping
    the semantic meaning of the `T` axis (turns -> sub-windows) requires no
    further model changes.
    """

    def __init__(self, aggr_type: str = "mean"):
        super().__init__()
        self.aggr_type = aggr_type

    def forward(self, edge_seq: torch.Tensor) -> torch.Tensor:
        if edge_seq.dim() == 2:
            return edge_seq
        if self.aggr_type == "mean":
            return edge_seq.mean(dim=1)
        if self.aggr_type == "last":
            return edge_seq[:, -1, :]
        if self.aggr_type == "max":
            return edge_seq.max(dim=1).values
        raise ValueError(f"Unknown aggr_type: {self.aggr_type}")


class NetGAT(nn.Module):
    def __init__(
        self,
        in_channels: int,
        edge_dim,
        hidden_channels: int = 256,
        out_channels: int = 1,
        heads: int = 4,
        num_layers: int = 2,
        dropout: float = 0.2,
        aggr_type: str = "mean",
        residual: bool = False,
        edge_head: bool = False,
    ):
        super().__init__()
        T, F_edge = edge_dim
        self.T = T
        self.F_edge = F_edge
        self.num_layers = num_layers
        self.dropout = dropout

        head_channels = hidden_channels // heads
        hidden_channels = head_channels * heads
        self.hidden_channels = hidden_channels

        self.convs = nn.ModuleList()
        self.convs.append(
            GATwithEdgeConv(
                in_channels,
                head_channels,
                heads=heads,
                concat=True,
                edge_dim=F_edge,
                residual=residual,
            )
        )
        for _ in range(num_layers - 1):
            self.convs.append(
                GATwithEdgeConv(
                    hidden_channels,
                    head_channels,
                    heads=heads,
                    concat=True,
                    edge_dim=hidden_channels,
                    residual=residual,
                )
            )

        self.edge_agg = SubWindowAggregator(aggr_type)
        self.node_out = nn.Linear(hidden_channels, out_channels)
        self.edge_head = edge_head
        if edge_head:
            self.edge_out = nn.Linear(hidden_channels, 1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_attr: torch.Tensor):
        edge_attr = self.edge_agg(edge_attr)
        for i, conv in enumerate(self.convs):
            x, edge_attr = conv(x, edge_index, edge_attr=edge_attr)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        node_logits = self.node_out(x).squeeze(-1)
        if self.edge_head:
            edge_logits = self.edge_out(edge_attr).squeeze(-1)
            return node_logits, edge_logits
        return node_logits


def _self_check():
    """Forward-pass shape sanity check on a tiny synthetic window."""
    torch.manual_seed(0)
    N, E, T = 6, 10, 3
    F_node, F_edge = 20, 25
    x = torch.randn(N, F_node)
    src = torch.randint(0, N, (E,))
    dst = torch.randint(0, N, (E,))
    edge_index = torch.stack([src, dst], dim=0)
    edge_attr = torch.randn(E, T, F_edge)

    model = NetGAT(in_channels=F_node, edge_dim=(T, F_edge), hidden_channels=64, heads=4, num_layers=2)
    model.eval()
    with torch.no_grad():
        logits = model(x, edge_index, edge_attr)
    assert logits.shape == (N,), f"expected ({N},), got {logits.shape}"
    print("NetGAT self-check passed:", logits.shape)


if __name__ == "__main__":
    _self_check()
