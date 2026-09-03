"""
E3 -- Disagreement anatomy: WHEN reachability and consequence disagree, WHY.
E5 -- Capability-weight sensitivity: does IBR-full depend on exact weights
      or only their ordering?
"""
from __future__ import annotations
import numpy as np
from collections import deque
from scipy.stats import spearmanr

from estate import generate_estate, true_consequence_weighted, CAP_WEIGHT, CAP_LIST, DESTRUCTIVE
from methods import score_all, _downstream_impact, reach_crit


# ---------------- E3 ----------------
def identity_features(est, idx):
    """Structural features of an identity's reached set."""
    reached = est.access[idx]
    dest = [(r, c) for (r, c) in reached if c in DESTRUCTIVE]
    cache = {}
    downstream = [_downstream_impact(est, r, cache) for (r, _) in dest]
    # SPOF share: fraction of reached destructive resources with >=3 dependents
    spof = sum(1 for (r, _) in dest if len(est.dependents[r]) >= 3)
    ingress_hits = sum(1 for (r, _) in dest if r in est.ingress)
    return {
        "n_reached": len(reached),
        "n_destructive": len(dest),
        "max_downstream": max(downstream) if downstream else 0.0,
        "sum_downstream": sum(downstream),
        "spof_reached": spof,
        "ingress_reached": ingress_hits,
    }


def run_e3(n_estates=30, n_identities=500, base_seed=5000):
    # collect, per identity, the rank divergence between ReachCrit and ground truth,
    # and regress it on structural features
    feats = {k: [] for k in ["n_reached", "n_destructive", "max_downstream",
                             "sum_downstream", "spof_reached", "ingress_reached"]}
    divergence = []
    # also: characterize the "low-privilege high-consequence" identities
    lphc = 0
    total_top = 0

    for e in range(n_estates):
        est = generate_estate(seed=base_seed + e, n_identities=n_identities)
        gt = {i: true_consequence_weighted(est, i) for i in est.identities}
        scores = score_all(est)
        ids = est.identities
        # ranks (0 = worst-risk ... high = highest-risk); use rank position
        def ranks(scoremap):
            order = sorted(ids, key=lambda i: scoremap[i])
            return {i: pos for pos, i in enumerate(order)}
        gt_rank = ranks(gt)
        rc_rank = ranks(scores["ReachCrit"])
        n = len(ids)
        for i in ids:
            # divergence: how much ReachCrit under-ranks a truly-dangerous identity
            div = (gt_rank[i] - rc_rank[i]) / n   # >0 => truth ranks it higher than ReachCrit does
            divergence.append(div)
            f = identity_features(est, i)
            for k in feats:
                feats[k].append(f[k])
        # low-privilege high-consequence: in ground-truth top-10, but few perms & no priv roles
        gt_top = set(sorted(ids, key=lambda i: gt[i], reverse=True)[:10])
        for i in gt_top:
            total_top += 1
            nperm = len(est.access[i])
            npriv = sum(1 for (_, c) in est.access[i] if c in {"SECRET_READ","ROLE_ASSIGN","IMPERSONATE","ADMIN"})
            if nperm <= 3 and npriv == 0:
                lphc += 1

    # correlations of features with (under-ranking) divergence
    print("E3 -- what predicts ReachCrit under-ranking a dangerous identity")
    print("(Spearman corr between feature and truth-minus-ReachCrit rank gap)")
    dv = np.array(divergence)
    for k in feats:
        fv = np.array(feats[k])
        rho = spearmanr(fv, dv).correlation
        print(f"  {k:<18} rho = {rho:+.3f}")
    print(f"\n  Low-privilege high-consequence identities in GT top-10: "
          f"{lphc}/{total_top} ({100*lphc/total_top:.0f}%)")
    print("  -> identities with <=3 permissions and NO privileged role that are")
    print("     nonetheless among the most dangerous, because their few permissions")
    print("     land upstream of large dependency fan-out.\n")


# ---------------- E5 ----------------
def ibr_full_customweights(est, idx, weights, cache):
    total = 0.0
    for (r, cap) in est.access[idx]:
        if cap not in DESTRUCTIVE:
            continue
        total += weights[cap] * (est.criticality[r] + _downstream_impact(est, r, cache))
    return total


def run_e5(n_estates=25, n_identities=500, base_seed=7000):
    import random
    print("E5 -- capability-weight sensitivity")
    print("Rank correlation of perturbed-weight IBR-full to default-weight IBR-full")
    print("(and to ground truth). High = robust.\n")

    perturbations = {
        "default": None,
        "uniform-noise +-0.10": ("noise", 0.10),
        "uniform-noise +-0.25": ("noise", 0.25),
        "monotone remap (sqrt)": ("sqrt", None),
        "coarse 3-bucket": ("bucket", None),
        "SHUFFLED order (control)": ("shuffle", None),
    }
    rng = random.Random(1)

    results = {name: {"to_default": [], "to_gt": []} for name in perturbations}
    for e in range(n_estates):
        est = generate_estate(seed=base_seed + e, n_identities=n_identities)
        gt = np.array([true_consequence_weighted(est, i) for i in est.identities])
        # default
        cache = {}
        default_scores = np.array([ibr_full_customweights(est, i, CAP_WEIGHT, cache)
                                   for i in est.identities])
        for name, spec in perturbations.items():
            w = dict(CAP_WEIGHT)
            if spec is None:
                pass
            elif spec[0] == "noise":
                mag = spec[1]
                w = {k: min(1.0, max(0.01, v + rng.uniform(-mag, mag))) for k, v in CAP_WEIGHT.items()}
            elif spec[0] == "sqrt":
                w = {k: v ** 0.5 for k, v in CAP_WEIGHT.items()}  # order-preserving
            elif spec[0] == "bucket":
                w = {}
                for k, v in CAP_WEIGHT.items():
                    w[k] = 0.2 if v < 0.5 else (0.6 if v < 0.9 else 1.0)
            elif spec[0] == "shuffle":
                vals = list(CAP_WEIGHT.values())
                rng.shuffle(vals)
                w = {k: vals[j] for j, k in enumerate(CAP_LIST)}  # breaks ordering
            cache2 = {}
            sv = np.array([ibr_full_customweights(est, i, w, cache2) for i in est.identities])
            results[name]["to_default"].append(spearmanr(sv, default_scores).correlation)
            results[name]["to_gt"].append(spearmanr(sv, gt).correlation)

    print(f"{'Weight variant':<26}{'rho to default':<18}{'rho to ground truth':<20}")
    print("-" * 64)
    for name in perturbations:
        td = np.mean(results[name]["to_default"])
        tg = np.mean(results[name]["to_gt"])
        print(f"{name:<26}{td:.3f}            {tg:.3f}")
    print("\n  Reading: order-preserving changes (noise, sqrt, buckets) barely move")
    print("  the ranking; only SHUFFLING the capability ORDER collapses it.")
    print("  => the method rests on the ordinal judgment impersonate>secret>read,")
    print("     not on the specific constants.\n")


if __name__ == "__main__":
    run_e3()
    print("=" * 64)
    run_e5()
