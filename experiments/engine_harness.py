"""
Shared harness: load the repo's REAL production topologies and drive the REAL
dependency blast-radius engine over each.

Adds three experiments, all against the real engine:
  E9  -- Cross-topology generality: does the reachability->consequence gap hold
         across all five shipped topologies, not just Boutique?
  E10 -- Remediation value: ranking revocation candidates by real engine
         consequence-reduction vs. by permission count.
  E11 -- Confidence robustness: the engine propagates confidence-weighted; does
         the identity ranking survive noisy/low-confidence dependency edges?
"""
from __future__ import annotations
import sys, json, os, random
import numpy as np
from scipy.stats import spearmanr, kendalltau

import os
ENGINE = os.environ.get("DEP_ENGINE_PATH", "./dependency-engine/core-engine")
sys.path.insert(0, ENGINE)
from src.services.blast_radius import build_dependency_graph, compute_blast_radius, compute_many

SCEN_DIR = os.path.join(ENGINE, "scenarios")
SCENARIOS = ["cloud_microservices", "drone_swarm", "gpu_cluster",
             "underwater_aps", "nc3_strategic_comms"]

CAP_WEIGHT = {"READ":0.20,"WRITE":0.50,"EXECUTE":0.85,"SECRET_READ":0.90,"ADMIN":1.00}
DESTRUCTIVE = {"WRITE","EXECUTE","ADMIN"}
PRIV = {"SECRET_READ","ADMIN"}


def load_snapshot(scenario, confidence=0.9, conf_noise=0.0, rng=None):
    """Convert a repo topology.json into the engine's {workloads, edges} snapshot.
    Edge [a,b] in the file means 'a depends on b' -> engine edge source=a,target=b."""
    topo = json.load(open(os.path.join(SCEN_DIR, scenario, "topology.json")))
    nodes = topo["nodes"]
    raw_edges = topo.get("edges") or topo.get("links")
    ns = scenario
    def key(i): return f"{ns}/Deployment/{i}"
    workloads = [{"key": key(n["id"]), "name": n["id"], "namespace": ns,
                  "kind": "Deployment", "tier": n.get("tier")} for n in nodes]
    ids = {n["id"] for n in nodes}
    edges = []
    for e in raw_edges:
        a, b = (e[0], e[1]) if isinstance(e, (list, tuple)) else (e["source"], e["target"])
        if a not in ids or b not in ids:
            continue
        c = confidence
        if conf_noise and rng is not None:
            c = min(1.0, max(0.05, confidence + rng.uniform(-conf_noise, conf_noise)))
        edges.append({"source": key(a), "target": key(b),
                      "confidence": c, "source_kind": "env_reference"})
    # mark edge/top tier as ingress-backed so user-facing consequence is captured
    edge_nodes = [n["id"] for n in nodes if n.get("tier") in ("edge",)]
    for en in edge_nodes:
        edges.append({"source": f"{ns}/Ingress/public", "target": key(en),
                      "confidence": 1.0, "source_kind": "ingress"})
    return {"workloads": workloads, "edges": edges}, [n["id"] for n in nodes]


def engine_oracle(snapshot):
    graph = build_dependency_graph(snapshot)
    keys = [n for n, d in graph.nodes(data=True) if d.get("is_workload")]
    radii = compute_many(snapshot, keys)
    oracle = {}
    for k, br in radii.items():
        name = k.split("/")[-1]
        oracle[name] = {
            "n_affected": br.total_affected,
            "user_facing": bool(br.entry_points),
            "affected": {a.key.split("/")[-1] for a in br.affected},
        }
    return oracle


def make_identities(seed, n, names):
    rng = random.Random(seed)
    idents = {}
    for k in range(n):
        t = rng.choices(["human","service","machine"], weights=[0.4,0.4,0.2])[0]
        nreach = min(rng.choices([1,2,3,5,8], weights=[30,25,20,15,10])[0], len(names))
        reached = rng.sample(names, nreach)
        pairs = []
        for r in reached:
            w = ([40,25,10,15,10] if t=="human" else
                 [25,30,15,15,15] if t=="service" else [15,25,20,15,25])
            pairs.append((r, rng.choices(list(CAP_WEIGHT), weights=w)[0]))
        idents[f"id{k}"] = pairs
    return idents


def true_impact(idents, idx, oracle):
    downed = {r for (r, c) in idents[idx] if c in DESTRUCTIVE}
    affected = set()
    for r in downed:
        if r in oracle:
            affected |= oracle[r]["affected"]
    affected -= downed
    sev = sum(1.5 if oracle.get(a, {}).get("user_facing") else 1.0 for a in affected)
    return len(affected), sev


def score_methods(idents, oracle):
    S = {m: {} for m in ["PermCount","PrivRoleCount","ReachCount","IBR-noDep","IBR-full"]}
    for idx, pairs in idents.items():
        reached = {r for (r,_) in pairs}
        S["PermCount"][idx] = len(pairs)
        S["PrivRoleCount"][idx] = sum(1 for (_,c) in pairs if c in PRIV)
        S["ReachCount"][idx] = len(reached)
        S["IBR-noDep"][idx] = sum(CAP_WEIGHT[c] for (r,c) in pairs if c in DESTRUCTIVE)
        s = 0.0
        for (r,c) in pairs:
            if c in DESTRUCTIVE and r in oracle:
                o = oracle[r]
                s += CAP_WEIGHT[c] * (1 + 0.15 * o["n_affected"] * (1.5 if o["user_facing"] else 1.0))
        S["IBR-full"][idx] = s
    return S
