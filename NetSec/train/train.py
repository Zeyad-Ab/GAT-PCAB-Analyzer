"""Train NetGAT on labeled graph snapshots.

Mirrors the conventions of `MA/train.py` (BCE, Adam, cosine schedule,
checkpoint file name with hyperparameters) but operates on per-host labels
produced by the NetSec pipeline.
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime

import torch
import torch.nn as nn
import yaml
from torch.optim import Adam
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch_geometric.loader import DataLoader
from tqdm import tqdm

from NetSec.model.net_gat import NetGAT
from NetSec.train.dataset import NetSecGraphDataset, split_indices


def _pick_device(arg: str) -> torch.device:
    if arg == "auto":
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return torch.device("mps")
        if torch.cuda.is_available():
            return torch.device("cuda:0")
        return torch.device("cpu")
    if arg == "cpu":
        return torch.device("cpu")
    if arg == "mps":
        return torch.device("mps") if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else torch.device("cpu")
    if arg.isdigit():
        return torch.device(f"cuda:{int(arg)}") if torch.cuda.is_available() else torch.device("cpu")
    return torch.device("cpu")


def run_epoch(model, loader, criterion, optimizer, device, train: bool):
    model.train(train)
    total_loss, total_correct, total = 0.0, 0, 0
    tp = fp = fn = 0
    context = torch.enable_grad() if train else torch.no_grad()
    with context:
        for data in loader:
            data = data.to(device)
            logits = model(data.x, data.edge_index, data.edge_attr)
            target = data.y.float()
            loss = criterion(logits, target)
            if train:
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
            preds = (torch.sigmoid(logits) >= 0.5).long()
            total_loss += float(loss.item())
            total += target.numel()
            total_correct += int((preds == data.y).sum().item())
            tp += int(((preds == 1) & (data.y == 1)).sum().item())
            fp += int(((preds == 1) & (data.y == 0)).sum().item())
            fn += int(((preds == 0) & (data.y == 1)).sum().item())
    n_batches = max(1, len(loader))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return total_loss / n_batches, 100 * total_correct / max(1, total), precision, recall, f1


def parse_args():
    p = argparse.ArgumentParser(description="Train NetGAT on NetSec graph snapshots")
    p.add_argument("--snapshots", required=True, help="Path to graph snapshots JSON")
    p.add_argument("--config", default="NetSec/configs/default.yaml")
    p.add_argument("--save_dir", default="NetSec/checkpoint")
    p.add_argument("--device", default="auto")
    p.add_argument("--epochs", type=int, default=None)
    p.add_argument("--batch_size", type=int, default=None)
    p.add_argument("--lr", type=float, default=None)
    return p.parse_args()


def main():
    args = parse_args()
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    train_cfg = cfg["train"]
    model_cfg = cfg["model"]

    epochs = args.epochs or int(train_cfg["epochs"])
    batch_size = args.batch_size or int(train_cfg["batch_size"])
    lr = args.lr or float(train_cfg["lr"])
    weight_decay = float(train_cfg["weight_decay"])
    val_split = float(train_cfg["val_split"])
    pos_weight = float(train_cfg["pos_weight"])
    seed = int(train_cfg["seed"])
    torch.manual_seed(seed)

    full_ds = NetSecGraphDataset(args.snapshots)
    if len(full_ds) == 0:
        raise SystemExit(f"No snapshots found in {args.snapshots}")
    train_idx, val_idx = split_indices(len(full_ds), val_split, seed)
    train_ds = NetSecGraphDataset(args.snapshots, indices=train_idx)
    val_ds = NetSecGraphDataset(args.snapshots, indices=val_idx) if val_idx else train_ds
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)

    example = full_ds.get(0)
    in_channels = int(example.x.size(1))
    edge_dim = tuple(example.edge_attr.size()[1:])

    device = _pick_device(args.device)
    print(f"Using device: {device}")
    print(f"Snapshots: {len(full_ds)} | train: {len(train_ds)} | val: {len(val_ds)} | in_channels: {in_channels} | edge_dim: {edge_dim}")

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

    criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight], device=device))
    optimizer = Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = CosineAnnealingLR(optimizer, T_max=max(1, epochs // 5 or 1), eta_min=1e-5)

    os.makedirs(args.save_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(
        args.save_dir,
        f"{ts}-netgat-hid{model_cfg['hidden_channels']}-heads{model_cfg['heads']}-layers{model_cfg['num_layers']}-epochs{epochs}-lr{lr}.pth",
    )

    best_f1 = -1.0
    for ep in tqdm(range(epochs), desc="epochs"):
        tr_loss, tr_acc, *_ = run_epoch(model, train_loader, criterion, optimizer, device, train=True)
        va_loss, va_acc, p, r, f1 = run_epoch(model, val_loader, criterion, optimizer, device, train=False)
        scheduler.step()
        if f1 > best_f1:
            best_f1 = f1
            torch.save(model.state_dict(), save_path)
            print(f"ep {ep:03d} | tr_loss {tr_loss:.4f} tr_acc {tr_acc:.2f} | va_loss {va_loss:.4f} va_acc {va_acc:.2f} P {p:.3f} R {r:.3f} F1 {f1:.3f} | SAVED")
        else:
            print(f"ep {ep:03d} | tr_loss {tr_loss:.4f} tr_acc {tr_acc:.2f} | va_loss {va_loss:.4f} va_acc {va_acc:.2f} P {p:.3f} R {r:.3f} F1 {f1:.3f}")

    print(f"Best F1: {best_f1:.3f}")
    print(f"Checkpoint: {save_path}")


if __name__ == "__main__":
    main()
