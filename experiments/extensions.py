"""
Camera-ready extensions addressing reviewer concerns.

(2) CONFIDENTIALITY / INTEGRITY consequence — the original model is
    availability-only, so a pure SECRET_READ identity scores ~0. We add two
    more channels on the SAME joined graph:
      * availability  : a destructive cap downs r; failure flows UP to r's
                        transitive dependents (unchanged).
      * confidentiality: a read cap on r exposes r's data AND the data of
                        everything r pulls from — flows DOWN r's transitive
                        dependencies, weighted by read potency and store
                        sensitivity. (This is the dual direction of availability.)
      * integrity     : a write/admin cap corrupts r; corruption flows UP to
                        dependents that trust r's data, weighted by write potency.

(3) CAPABILITY-MODULATED SEVERITY — replace the binary destructive gate with a
    per-capability magnitude fraction, so a WRITE degrades partially and ADMIN
    fully. Under this ground truth the capability weight is first-order.

Pure Python; reuses estate.py's generator and graph. No new dependencies.
"""
from __future__ import annotations
import random
from collections import deque
from estate import Estate, CAP_WEIGHT, DESTRUCTIVE

READ_CAPS = {"META_READ", "LOG_READ", "READ", "SECRET_READ"}
# how much data a read exposes (secret-read is the worst; admin can read all)
READ_POTENCY = {"META_READ": 0.10, "LOG_READ": 0.20, "READ": 0.50,
                "SECRET_READ": 1.00, "ADMIN": 1.00}
# how much a write-class cap can corrupt shared state
WRITE_POTENCY = {"WRITE": 0.50, "CREATE": 0.60, "EXECUTE": 0.70,
                 "ROLE_ASSIGN": 0.90, "IMPERSONATE": 1.00, "ADMIN": 1.00}
# availability magnitude fraction per cap (modulated, not a binary gate)
AVAIL_SEVERITY = {"WRITE": 0.50, "CREATE": 0.60, "EXECUTE": 0.85,
                  "ROLE_ASSIGN": 0.60, "IMPERSONATE": 1.00, "ADMIN": 1.00}


def sensitivity(est: Estate) -> dict:
    """Per-resource data sensitivity in [0,1], deterministic from the seed.
    Data-tier resources (no dependencies of their own = leaves) hold the
    sensitive data; everything else is mostly transient."""
    rng = random.Random((est.seed * 2654435761) & 0xFFFFFFFF)
    sens = {}
    for r in est.resources:
        is_data = len(est.deps[r]) == 0
        base = 0.70 if is_data else 0.12
        sens[r] = round(min(1.0, base + 0.30 * rng.random()), 3)
    return sens


def _closure(graph: dict, start) -> set:
    seen, dq = set(), deque(start)
    while dq:
        x = dq.popleft()
        for y in graph.get(x, ()):
            if y not in seen:
                seen.add(y)
                dq.append(y)
    return seen


# ---------------- ground-truth channels ----------------
def gt_availability(est: Estate, idx: str) -> float:
    downed = {r for (r, cap) in est.access[idx] if cap in DESTRUCTIVE}
    failed = _closure(est.dependents, downed) - downed
    return sum(est.criticality[r] * (1.5 if r in est.ingress else 1.0) for r in failed)


def gt_confidentiality(est: Estate, idx: str, sens: dict) -> float:
    total = 0.0
    for (r, cap) in est.access[idx]:
        pot = READ_POTENCY.get(cap)
        if pot is None:
            continue
        exposed = {r} | _closure(est.deps, {r})   # r's data + everything it pulls
        total += pot * sum(sens[x] for x in exposed)
    return total


def gt_integrity(est: Estate, idx: str) -> float:
    total = 0.0
    for (r, cap) in est.access[idx]:
        pot = WRITE_POTENCY.get(cap)
        if pot is None:
            continue
        affected = _closure(est.dependents, {r})   # corruption flows up to trusters
        total += pot * sum(est.criticality[x] * (1.5 if x in est.ingress else 1.0) for x in affected)
    return total


def gt_modulated_availability(est: Estate, idx: str) -> float:
    """Capability-modulated availability: the failure MAGNITUDE at each downed
    resource scales with the capability's severity, not a binary gate."""
    total = 0.0
    for (r, cap) in est.access[idx]:
        sev = AVAIL_SEVERITY.get(cap)
        if sev is None:
            continue
        affected = _closure(est.dependents, {r})
        mass = est.criticality[r] + sum(
            est.criticality[x] * (1.5 if x in est.ingress else 1.0) for x in affected
        )
        total += sev * mass
    return total


# ---------------- estimators ----------------
def _downstream(est: Estate, r: str, cache: dict) -> float:
    if r in cache:
        return cache[r]
    failed = _closure(est.dependents, {r})
    val = sum(est.criticality[a] * (1.5 if a in est.ingress else 1.0) for a in failed)
    cache[r] = val
    return val


def _upstream_sens(est: Estate, r: str, sens: dict, cache: dict) -> float:
    if r in cache:
        return cache[r]
    exposed = {r} | _closure(est.deps, {r})
    val = sum(sens[x] for x in exposed)
    cache[r] = val
    return val


def ibr_avail_only(est: Estate, idx: str, cache: dict) -> float:
    """The paper's IBR-full: availability channel only (destructive gate)."""
    total = 0.0
    for (r, cap) in est.access[idx]:
        if cap not in DESTRUCTIVE:
            continue
        total += CAP_WEIGHT[cap] * (est.criticality[r] + _downstream(est, r, cache))
    return total


def ibr_ci(est: Estate, idx: str, sens: dict, dcache: dict, scache: dict) -> float:
    """3-channel estimator: availability + confidentiality + integrity."""
    a = c = i = 0.0
    for (r, cap) in est.access[idx]:
        if cap in DESTRUCTIVE:
            a += CAP_WEIGHT[cap] * (est.criticality[r] + _downstream(est, r, dcache))
        if cap in READ_POTENCY:
            c += READ_POTENCY[cap] * _upstream_sens(est, r, sens, scache)
        if cap in WRITE_POTENCY:
            i += WRITE_POTENCY[cap] * (est.criticality[r] + _downstream(est, r, dcache))
    return a + c + i


def ibr_modulated(est: Estate, idx: str, cache: dict) -> float:
    """Capability-modulated estimator (magnitude scales with severity)."""
    total = 0.0
    for (r, cap) in est.access[idx]:
        sev = AVAIL_SEVERITY.get(cap)
        if sev is None:
            continue
        total += sev * (est.criticality[r] + _downstream(est, r, cache))
    return total


def ibr_modulated_nocap(est: Estate, idx: str, cache: dict) -> float:
    """Same, but capability flattened to a single fraction (ablation)."""
    total = 0.0
    for (r, cap) in est.access[idx]:
        if cap not in AVAIL_SEVERITY:
            continue
        total += 0.75 * (est.criticality[r] + _downstream(est, r, cache))
    return total


# ---------------- rank correlation (pure python Spearman) ----------------
def _ranks(vals):
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        avg = (i + j) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(a, b) -> float:
    ra, rb = _ranks(a), _ranks(b)
    n = len(a)
    ma = sum(ra) / n
    mb = sum(rb) / n
    num = sum((ra[i] - ma) * (rb[i] - mb) for i in range(n))
    da = sum((ra[i] - ma) ** 2 for i in range(n)) ** 0.5
    db = sum((rb[i] - mb) ** 2 for i in range(n)) ** 0.5
    return num / (da * db) if da and db else 0.0
