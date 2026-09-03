"""
Scoring methods under test. Each takes (estate, identity) -> float score.

Reachability baselines DO NOT see the dependency graph.
The proposed method IBR_full joins reached resources to the dependency graph.

Crucially, no method is given `true_consequence`; they estimate it from the
information their class is allowed to use.
"""
from __future__ import annotations
from collections import deque
from estate import CAP_WEIGHT, DESTRUCTIVE, Estate

PRIV_CAPS = {"SECRET_READ", "ROLE_ASSIGN", "IMPERSONATE", "ADMIN"}


def _reached(est: Estate, idx: str):
    return est.access[idx]


# ---------- reachability-class baselines (no dependency graph) ----------
def perm_count(est: Estate, idx: str) -> float:
    return float(len(_reached(est, idx)))


def priv_role_count(est: Estate, idx: str) -> float:
    return float(sum(1 for (_, cap) in _reached(est, idx) if cap in PRIV_CAPS))


def reach_count(est: Estate, idx: str) -> float:
    return float(len({r for (r, _) in _reached(est, idx)}))


def reach_crit(est: Estate, idx: str) -> float:
    # reachable resources weighted by static criticality only (strongest baseline)
    return round(sum(est.criticality[r] for (r, _) in _reached(est, idx)), 4)


# ---------- downstream impact via the dependency join ----------
def _downstream_impact(est: Estate, r: str, _cache: dict) -> float:
    """Criticality mass of everything that depends on r (r's ancestors),
    with ingress multiplier. Memoized per estate."""
    if r in _cache:
        return _cache[r]
    failed = set()
    dq = deque([r])
    while dq:
        x = dq.popleft()
        for anc in est.dependents[x]:
            if anc not in failed:
                failed.add(anc)
                dq.append(anc)
    total = 0.0
    for a in failed:
        w = est.criticality[a]
        if a in est.ingress:
            w *= 1.5
        total += w
    _cache[r] = total
    return total


# ---------- proposed method + ablations ----------
def ibr_full(est: Estate, idx: str, _cache: dict) -> float:
    total = 0.0
    for (r, cap) in _reached(est, idx):
        if cap not in DESTRUCTIVE:
            continue  # non-destructive capability can't take r down
        priv = CAP_WEIGHT[cap]
        crit = est.criticality[r]
        downstream = _downstream_impact(est, r, _cache)
        total += priv * (crit + downstream)
    return round(total, 4)


def ibr_nodep(est: Estate, idx: str, _cache: dict) -> float:
    # dependency propagation removed: capability x criticality on reached only
    total = 0.0
    for (r, cap) in _reached(est, idx):
        if cap not in DESTRUCTIVE:
            continue
        total += CAP_WEIGHT[cap] * est.criticality[r]
    return round(total, 4)


def ibr_nocap(est: Estate, idx: str, _cache: dict) -> float:
    # capability weighting flattened to 1.0
    total = 0.0
    for (r, cap) in _reached(est, idx):
        if cap not in DESTRUCTIVE:
            continue
        total += 1.0 * (est.criticality[r] + _downstream_impact(est, r, _cache))
    return round(total, 4)


def all_methods():
    """Return dict name -> (fn, needs_cache)."""
    return {
        "PermCount": (perm_count, False),
        "PrivRoleCount": (priv_role_count, False),
        "ReachCount": (reach_count, False),
        "ReachCrit": (reach_crit, False),
        "IBR-noDep": (ibr_nodep, True),
        "IBR-noCap": (ibr_nocap, True),
        "IBR-full": (ibr_full, True),
    }


def score_all(est: Estate):
    """Return dict method -> dict(identity -> score)."""
    out = {}
    for name, (fn, needs_cache) in all_methods().items():
        cache = {}
        scores = {}
        for idx in est.identities:
            scores[idx] = fn(est, idx, cache) if needs_cache else fn(est, idx)
        out[name] = scores
    return out
