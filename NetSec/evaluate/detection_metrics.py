"""Detection metrics: P / R / F1 / ROC-AUC against ground-truth snapshots.

Requires:
    - ground-truth snapshots JSON (from graph/build_graph.py, carrying `y`)
    - verdicts JSON (from detect/detector.py)

Metrics produced:
    - Per-window P/R/F1 plus aggregate micro P/R/F1 across all windows.
    - Per-window host-recognition rate: fraction of true attackers that are
      flagged in that window (analog of `cal_recog_acc` in MA/evaluate_output.py).
    - ROC-AUC over all host decisions when `sklearn` is available.
"""

from __future__ import annotations

import argparse
import json
from typing import Dict, List, Tuple

import numpy as np


def _pr_f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return precision, recall, f1


def align_and_score(snapshots: List[dict], verdicts: List[dict]) -> Dict:
    snap_by_window = {(float(s["window_start"]), float(s["window_end"])): s for s in snapshots}

    all_y, all_scores, all_pred = [], [], []
    per_window: List[Dict] = []
    for v in verdicts:
        key = (float(v["window_start"]), float(v["window_end"]))
        s = snap_by_window.get(key)
        if s is None:
            continue
        ip_to_y = dict(zip(s["node_ips"], s["y"]))
        y, scores, preds = [], [], []
        for ip, sc, pr in zip(v["node_ips"], v["node_scores"], v["node_predicts"]):
            if ip in ip_to_y:
                y.append(int(ip_to_y[ip]))
                scores.append(float(sc))
                preds.append(int(pr))
        if not y:
            continue
        tp = sum(1 for yi, pi in zip(y, preds) if yi == 1 and pi == 1)
        fp = sum(1 for yi, pi in zip(y, preds) if yi == 0 and pi == 1)
        fn = sum(1 for yi, pi in zip(y, preds) if yi == 1 and pi == 0)
        p, r, f1 = _pr_f1(tp, fp, fn)
        recog = tp / max(1, sum(y))
        per_window.append(
            {
                "window_start": key[0],
                "window_end": key[1],
                "precision": p,
                "recall": r,
                "f1": f1,
                "recognition_rate": recog,
                "n_hosts": len(y),
                "n_attackers": int(sum(y)),
            }
        )
        all_y.extend(y); all_scores.extend(scores); all_pred.extend(preds)

    tp = sum(1 for yi, pi in zip(all_y, all_pred) if yi == 1 and pi == 1)
    fp = sum(1 for yi, pi in zip(all_y, all_pred) if yi == 0 and pi == 1)
    fn = sum(1 for yi, pi in zip(all_y, all_pred) if yi == 1 and pi == 0)
    p_all, r_all, f1_all = _pr_f1(tp, fp, fn)

    auc = None
    try:
        from sklearn.metrics import roc_auc_score
        if len(set(all_y)) > 1:
            auc = float(roc_auc_score(all_y, all_scores))
    except Exception:
        auc = None

    return {
        "micro_precision": p_all,
        "micro_recall": r_all,
        "micro_f1": f1_all,
        "roc_auc": auc,
        "n_windows": len(per_window),
        "n_decisions": len(all_y),
        "per_window": per_window,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--snapshots", required=True, help="Ground-truth graph snapshots JSON")
    p.add_argument("--verdicts", required=True, help="Detector verdicts JSON")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    with open(args.snapshots) as f:
        snaps = json.load(f)
    with open(args.verdicts) as f:
        vers = json.load(f)

    report = align_and_score(snaps, vers)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"micro P/R/F1 = {report['micro_precision']:.3f} / {report['micro_recall']:.3f} / {report['micro_f1']:.3f}"
          + (f" | ROC-AUC = {report['roc_auc']:.3f}" if report["roc_auc"] is not None else ""))
    print(f"Windows scored: {report['n_windows']} | host decisions: {report['n_decisions']}")
    print(f"Full report: {args.out}")


if __name__ == "__main__":
    main()
