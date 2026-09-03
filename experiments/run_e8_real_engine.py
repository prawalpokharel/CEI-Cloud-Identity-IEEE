"""
E8 -- Identity blast radius computed WITH the dependency-analysis Cloud engine,
over Google's Online Boutique (the same public topology the engine's own
golden tests use).

This is the experiment that runs *with* the dependency engine: the downstream-impact
term of identity blast radius is not a synthetic model -- it is the product's
actual compute_blast_radius() over the real service dependency graph.

Pipeline:
  1. Real infra graph  : Boutique workloads+edges -> the engine's build_dependency_graph
  2. Real consequence  : for each workload, the engine's compute_blast_radius() gives
                         the true affected-set / severity if that workload fails.
  3. Identities        : synthetic Okta/AWS/K8s-style identities granted
                         capabilities onto real Boutique workloads.
  4. Ground truth      : compromise identity i -> the union of engine blast
                         radii of every workload i can destroy -> real
                         downstream service set.
  5. Compare methods   : reachability baselines vs. identity blast radius that
                         calls the real engine as its oracle.
"""
from __future__ import annotations
import sys, os, random
import numpy as np
from scipy.stats import spearmanr, kendalltau

import os
ENGINE = os.environ.get("DEP_ENGINE_PATH", "./dependency-engine/core-engine")
sys.path.insert(0, ENGINE)
from src.services.blast_radius import (          # the REAL product engine
    build_dependency_graph, compute_blast_radius, compute_many,
)

# ---- Google Online Boutique real call graph (from the engine's own tests) ----
BOUTIQUE_CALLS = {
    "frontend": ["cartservice","productcatalogservice","currencyservice",
                 "recommendationservice","shippingservice","checkoutservice","adservice"],
    "checkoutservice": ["cartservice","productcatalogservice","currencyservice",
                        "shippingservice","paymentservice","emailservice"],
    "recommendationservice": ["productcatalogservice"],
    "cartservice": ["rediscart"],
}
ORPHAN = "nightlyreconciler"
ALL_SERVICES = sorted(set(BOUTIQUE_CALLS)
                      | {t for ts in BOUTIQUE_CALLS.values() for t in ts}
                      | {ORPHAN})

def _key(n): return f"boutique/Deployment/{n}"

def boutique_snapshot():
    workloads = [{"key": _key(n), "name": n, "namespace": "boutique",
                  "kind": "Deployment"} for n in ALL_SERVICES]
    edges = [{"source": _key(s), "target": _key(t), "confidence": 0.9,
              "source_kind": "env_reference"}
             for s, ts in BOUTIQUE_CALLS.items() for t in ts]
    # frontend is ingress-backed (user-facing) -- add the ingress vertex the engine expects
    edges.append({"source": "boutique/Ingress/public",
                  "target": _key("frontend"), "confidence": 1.0,
                  "source_kind": "ingress"})
    return {"workloads": workloads, "edges": edges}


# ---- capability model (spec section 8) ----
CAP_WEIGHT = {"READ":0.20,"WRITE":0.50,"EXECUTE":0.85,"SECRET_READ":0.90,
              "ADMIN":1.00}
DESTRUCTIVE = {"WRITE","EXECUTE","ADMIN"}      # can take a workload down
PRIV = {"SECRET_READ","ADMIN"}


def make_identities(seed, n, workloads):
    rng = random.Random(seed)
    names = [w["name"] for w in workloads]
    idents = {}
    for k in range(n):
        t = rng.choices(["human","service","machine"], weights=[0.4,0.4,0.2])[0]
        nreach = rng.choices([1,2,3,5,8], weights=[30,25,20,15,10])[0]
        nreach = min(nreach, len(names))
        reached = rng.sample(names, nreach)
        pairs = []
        for r in reached:
            if t == "human":
                cap = rng.choices(list(CAP_WEIGHT), weights=[40,25,10,15,10])[0]
            elif t == "service":
                cap = rng.choices(list(CAP_WEIGHT), weights=[25,30,15,15,15])[0]
            else:
                cap = rng.choices(list(CAP_WEIGHT), weights=[15,25,20,15,25])[0]
            pairs.append((r, cap))
        idents[f"id{k}"] = pairs
    return idents


# ---- REAL engine as the consequence oracle (cached per workload) ----
def build_oracle(snapshot):
    graph = build_dependency_graph(snapshot)
    keys = [n for n, d in graph.nodes(data=True) if d.get("is_workload")]
    radii = compute_many(snapshot, keys)     # <-- real engine blast radius
    # map: workload name -> (n_affected, centrality_fraction, user_facing, affected set)
    oracle = {}
    sev_rank = {"none":0,"low":1,"medium":2,"high":3,"critical":4}
    for key, br in radii.items():
        name = key.split("/")[-1]
        affected_names = {a.key.split("/")[-1] for a in br.affected}
        oracle[name] = {
            "n_affected": br.total_affected,
            "centrality_fraction": br.centrality_fraction,
            "user_facing": bool(br.entry_points),
            "severity": sev_rank.get(br.severity, 0),
            "affected": affected_names,
        }
    return oracle


# ---- ground truth: real downstream impact of compromising an identity ----
def true_impact(idents, idx, oracle):
    downed = {r for (r, c) in idents[idx] if c in DESTRUCTIVE}
    affected = set()
    for r in downed:
        if r in oracle:
            affected |= oracle[r]["affected"]
    affected -= downed
    # severity = criticality mass (centrality_fraction) of affected, ingress-boosted
    sev = 0.0
    for a in affected:
        if a in oracle:
            w = oracle[a]["centrality_fraction"] + 0.1
            if oracle[a]["user_facing"]:
                w *= 1.5
            sev += w
    return len(affected), sev


# ---- methods ----
def score_methods(idents, oracle):
    scores = {m: {} for m in
              ["PermCount","PrivRoleCount","ReachCount","ReachCrit",
               "IBR-noDep","IBR-full"]}
    for idx, pairs in idents.items():
        reached = {r for (r, _) in pairs}
        scores["PermCount"][idx] = len(pairs)
        scores["PrivRoleCount"][idx] = sum(1 for (_, c) in pairs if c in PRIV)
        scores["ReachCount"][idx] = len(reached)
        # ReachCrit: reachable workloads weighted by the engine's own centrality_fraction
        scores["ReachCrit"][idx] = sum(
            oracle.get(r, {}).get("centrality_fraction", 0) + 0.1 for r in reached)
        # IBR-noDep: capability x own-centrality, no downstream propagation
        scores["IBR-noDep"][idx] = sum(
            CAP_WEIGHT[c] * (oracle.get(r, {}).get("centrality_fraction", 0) + 0.1)
            for (r, c) in pairs if c in DESTRUCTIVE)
        # IBR-full: capability x (own + REAL engine downstream blast severity)
        s = 0.0
        for (r, c) in pairs:
            if c not in DESTRUCTIVE or r not in oracle:
                continue
            o = oracle[r]
            downstream = o["n_affected"] * (1.5 if o["user_facing"] else 1.0)
            s += CAP_WEIGHT[c] * (o["centrality_fraction"] + 0.1 + 0.15 * downstream)
        scores["IBR-full"][idx] = s
    return scores


def run(n_estates=30, n_identities=400, base_seed=30000):
    snap = boutique_snapshot()
    oracle = build_oracle(snap)   # built once; the real topology is fixed
    print(f"Boutique estate: {len(ALL_SERVICES)} real services, "
          f"engine computed blast radius for each.")
    print("Sample blast radii (dependency engine):")
    for name in ["frontend","productcatalogservice","cartservice","rediscart","adservice"]:
        if name in oracle:
            o = oracle[name]
            print(f"  {name:<24} affects {o['n_affected']:2d} services, "
                  f"user_facing={o['user_facing']}, centrality={o['centrality_fraction']:.3f}")
    print()

    methods = ["PermCount","PrivRoleCount","ReachCount","ReachCrit","IBR-noDep","IBR-full"]
    agg = {m: {"rho": [], "tau": [], "rec5": []} for m in methods}

    def recall5(order, gt):
        top = set(sorted(gt, key=lambda i: gt[i], reverse=True)[:5])
        return len(set(order[:5]) & top) / 5

    for e in range(n_estates):
        idents = make_identities(base_seed + e, n_identities, snap["workloads"])
        gt = {}
        for idx in idents:
            _, sev = true_impact(idents, idx, oracle)
            gt[idx] = sev
        gt_vec = np.array([gt[i] for i in idents])
        scores = score_methods(idents, oracle)
        for m in methods:
            sv = np.array([scores[m][i] for i in idents])
            rho = spearmanr(sv, gt_vec).correlation
            tau = kendalltau(sv, gt_vec).correlation
            agg[m]["rho"].append(0.0 if rho != rho else rho)
            agg[m]["tau"].append(0.0 if tau != tau else tau)
            order = sorted(idents, key=lambda i: scores[m][i], reverse=True)
            agg[m]["rec5"].append(recall5(order, gt))

    print(f"{'Method':<15}{'Spearman':<16}{'Kendall':<16}{'Recall@5':<12}")
    print("-" * 59)
    for m in methods:
        print(f"{m:<15}{np.mean(agg[m]['rho']):.3f}\u00b1{np.std(agg[m]['rho']):.3f}    "
              f"{np.mean(agg[m]['tau']):.3f}\u00b1{np.std(agg[m]['tau']):.3f}    "
              f"{np.mean(agg[m]['rec5']):.3f}")
    return agg, oracle


if __name__ == "__main__":
    run()
