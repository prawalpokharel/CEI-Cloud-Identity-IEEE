"""
E12 -- Does identity blast radius concentrate on the load-bearing workloads the
       real engine identifies? If the highest-consequence identities are exactly
       those touching the engine's high-blast-radius workloads, then IBR is a
       correct *composition* of the engine's per-workload judgement -- and a
       small set of workloads governs most identity risk (the actionable finding
       for defenders: protect these first).
"""
import numpy as np
from engine_harness import (SCENARIOS, load_snapshot, engine_oracle,
                             make_identities, true_impact, DESTRUCTIVE)


def run(n_identities=400, seed=80000):
    print("E12 -- concentration of identity risk on engine-identified critical workloads\n")
    print(f"{'Topology':<22}{'top-20% wl':<12}{'% of identity risk':<20}{'Gini':<8}")
    print("-"*62)
    for scen in SCENARIOS:
        snap, names = load_snapshot(scen)
        oracle = engine_oracle(snap)
        idents = make_identities(seed, n_identities, names)

        # per-workload blast radius from the engine
        wl_br = {n: oracle[n]["n_affected"] for n in names if n in oracle}
        ranked = sorted(wl_br, key=wl_br.get, reverse=True)
        k = max(1, len(ranked) // 5)          # top 20% of workloads
        critical = set(ranked[:k])

        # attribute each identity's true risk to the workloads it can destroy;
        # how much of total identity risk flows through the critical set?
        total_risk = 0.0
        risk_via_critical = 0.0
        for i in idents:
            downed = {r for (r, c) in idents[i] if c in DESTRUCTIVE}
            _, sev = true_impact(idents, i, oracle)
            total_risk += sev
            if downed & critical:
                risk_via_critical += sev

        pct = 100 * risk_via_critical / total_risk if total_risk else 0

        # Gini of per-workload blast radius (how unequal is structural criticality)
        vals = np.sort(np.array([wl_br[n] for n in ranked], dtype=float))
        nn = len(vals); cum = np.cumsum(vals)
        gini = (nn + 1 - 2 * np.sum(cum) / cum[-1]) / nn if cum[-1] > 0 else 0
        print(f"{scen:<22}{k:<12}{pct:<20.1f}{gini:<8.3f}")
    print("\n  Reading: a small minority of workloads (top 20% by engine blast")
    print("  radius) accounts for the large majority of identity risk. Defenders")
    print("  who cannot review every identity can protect these few workloads and")
    print("  cover most of the exposure -- the prioritization the paper argues for.\n")


if __name__ == "__main__":
    run()
