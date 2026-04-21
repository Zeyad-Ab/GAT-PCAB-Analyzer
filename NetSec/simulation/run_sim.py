"""Orchestrate NS-3 runs for the NetSec pipeline.

Assumes ns-3 (>=3.40) is built locally and the `netsec_sim.cc` file has been
symlinked/copied into `<ns3-root>/scratch/`. The NS-3 `ns3` driver script will
then expose it as `scratch/netsec_sim`.

Example:
    python NetSec/simulation/run_sim.py \
        --ns3_root ~/ns-3-dev \
        --acl NetSec/result/acl.json \
        --attack scan \
        --out_dir NetSec/result/sim
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def _ensure_scratch(ns3_root: Path, cc_path: Path) -> Path:
    scratch = ns3_root / "scratch"
    if not scratch.is_dir():
        raise SystemExit(f"Could not find ns3 scratch directory at {scratch}")
    dst = scratch / "netsec_sim.cc"
    if not dst.exists() or dst.read_bytes() != cc_path.read_bytes():
        shutil.copyfile(cc_path, dst)
        print(f"Copied {cc_path} -> {dst}")
    return scratch


def _run_ns3(ns3_root: Path, args_str: str) -> None:
    ns3 = ns3_root / "ns3"
    if not ns3.exists():
        raise SystemExit(f"ns3 driver not found at {ns3}; build NS-3 first")
    cmd = [str(ns3), "run", f"scratch/netsec_sim -- {args_str}"]
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ns3_root", required=True, help="Path to ns-3-dev checkout (built)")
    p.add_argument("--acl", required=True, help="ACL JSON from NetSec/detect/mitigation.py")
    p.add_argument("--attack", default="scan", choices=["scan", "lateral", "c2"])
    p.add_argument("--out_dir", default="NetSec/result/sim")
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--n_clients", type=int, default=6)
    p.add_argument("--n_servers", type=int, default=3)
    p.add_argument("--skip_no_defense", action="store_true")
    args = p.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[2]
    cc = repo_root / "NetSec/simulation/ns3/netsec_sim.cc"
    ns3_root = Path(args.ns3_root).expanduser().resolve()
    _ensure_scratch(ns3_root, cc)

    # ACL JSON -> CSV
    from NetSec.simulation import acl_to_csv  # noqa: F401 (side-effect-free)
    acl_csv = out_dir / "acl.csv"
    subprocess.run(
        ["python", "-m", "NetSec.simulation.acl_to_csv", "--acl", args.acl, "--out", str(acl_csv)],
        check=True,
    )

    common = (
        f"--attack={args.attack} --duration={args.duration} "
        f"--n_clients={args.n_clients} --n_servers={args.n_servers}"
    )

    if not args.skip_no_defense:
        fm_nd = out_dir / f"flowmon_no_defense_{args.attack}.xml"
        _run_ns3(ns3_root, f"{common} --scenario=no_defense --acl= --flowmon_out={fm_nd}")

    fm_d = out_dir / f"flowmon_defense_{args.attack}.xml"
    _run_ns3(ns3_root, f"{common} --scenario=defense --acl={acl_csv} --flowmon_out={fm_d}")

    print(f"FlowMonitor outputs in {out_dir}")


if __name__ == "__main__":
    main()
