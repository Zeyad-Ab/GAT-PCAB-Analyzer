# NetSec NS-3 simulation

This sub-package wraps an NS-3 scenario (`ns3/netsec_sim.cc`) that mirrors the
CICIDS-style testbed (attacker + N clients + gateway + M servers) and:

- Generates benign `OnOff` TCP traffic between clients and servers.
- Optionally launches one of three attack traffic patterns (`scan` / `lateral`
  / `c2`) driven from the attacker or a compromised insider.
- Optionally installs a packet-drop callback on the gateway's NetDevice that
  enforces the ACL produced by `NetSec/detect/mitigation.py`.

## Build

NS-3 (>= 3.40) is required. Build it once:

```bash
git clone https://gitlab.com/nsnam/ns-3-dev.git ~/ns-3-dev
cd ~/ns-3-dev
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

Then copy or symlink the scenario into NS-3's `scratch/` directory. The
`run_sim.py` orchestrator does this automatically when pointed at your ns-3
checkout via `--ns3_root`.

## Run

```bash
python -m NetSec.simulation.run_sim \
    --ns3_root ~/ns-3-dev \
    --acl NetSec/result/acl.json \
    --attack scan \
    --out_dir NetSec/result/sim
```

Two runs are performed per invocation: `no_defense` (empty ACL) and
`defense` (ACL loaded). Each produces a `FlowMonitor` XML used by
`NetSec/evaluate/network_metrics.py`.

## Scenario details

- `scan`: attacker hammers ~40 distinct TCP ports on the victim server with
  short OnOff apps (60-byte packets, ~50 ms on / 10 ms off). SYN-heavy pattern
  is the canonical port-scan feature the GNN learns.
- `lateral`: a compromised internal client opens TCP connections to admin
  ports (22, 445, 3389) on multiple servers in sequence.
- `c2`: a compromised internal client sends small UDP (64 B) packets on a
  strict periodic schedule to the attacker. Low IAT variance is the key
  beaconing signal.

## ACL handling

The ACL JSON is converted to CSV (`acl.csv`, columns
`activate_at_s,src_ip,dst_ip,proto,action`) by `acl_to_csv.py`. Each rule is
activated by a `Simulator::Schedule` call inside the scenario, so mitigation
only kicks in at or after its `activate_at` time -- the simulation can
therefore quantify detection dwell time.
