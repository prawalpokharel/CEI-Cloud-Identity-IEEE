"""E9 -- Cross-topology generality against the dependency-analysis engine."""
import numpy as np
from scipy.stats import spearmanr
from engine_harness import (SCENARIOS, load_snapshot, engine_oracle,
                             make_identities, true_impact, score_methods)

METHODS = ["PermCount","PrivRoleCount","ReachCount","IBR-noDep","IBR-full"]

def run(n_estates=20, n_identities=300, base_seed=40000):
    print("E9 -- reachability vs. consequence across ALL five real repo topologies")
    print("(Spearman rho of each method to real-engine ground truth)\n")
    print(f"{'Topology':<22}{'ReachCount':<13}{'IBR-noDep':<12}{'IBR-full':<11}{'engine BR max':<14}")
    print("-"*72)
    summary = {}
    for scen in SCENARIOS:
        snap, names = load_snapshot(scen)
        oracle = engine_oracle(snap)
        maxbr = max(o["n_affected"] for o in oracle.values())
        per = {m: [] for m in METHODS}
        for e in range(n_estates):
            idents = make_identities(base_seed+e, n_identities, names)
            gt = np.array([true_impact(idents, i, oracle)[1] for i in idents])
            S = score_methods(idents, oracle)
            for m in METHODS:
                sv = np.array([S[m][i] for i in idents])
                r = spearmanr(sv, gt).correlation
                per[m].append(0.0 if r!=r else r)
        summary[scen] = {m: np.mean(per[m]) for m in METHODS}
        print(f"{scen:<22}{summary[scen]['ReachCount']:<13.3f}"
              f"{summary[scen]['IBR-noDep']:<12.3f}{summary[scen]['IBR-full']:<11.3f}{maxbr:<14}")
    print()
    reach = np.mean([summary[s]["ReachCount"] for s in SCENARIOS])
    full  = np.mean([summary[s]["IBR-full"] for s in SCENARIOS])
    print(f"Mean across topologies: ReachCount {reach:.3f}  ->  IBR-full {full:.3f}  "
          f"(+{full-reach:.3f})")
    return summary

if __name__ == "__main__":
    run()
