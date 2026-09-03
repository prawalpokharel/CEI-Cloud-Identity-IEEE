"""
Synthetic identity estate generator + ground-truth consequence model.

An estate is three joined layers:
  identities --(authorization edges)--> resources --(dependency edges)--> resources

GROUND TRUTH is defined by construction and is independent of any scoring
method under test:

  For identity i, "compromise" means i exercises every capability it holds
  against every resource it can reach. A destructive capability (WRITE and
  above) on a reached resource r takes r down. When r goes down, everything
  that DEPENDS ON r (its ancestors in the dependency DAG, transitively) also
  fails. The true consequence of compromising i is the number of DISTINCT
  services in that transitive-ancestor closure, excluding the resources i
  touched directly (mirrors the chaos harness excluding the killed target).

Every method under test tries to recover the ranking this induces WITHOUT
being given the dependency closure in the reachability baselines' case.

All randomness flows from a single seed -> fully regenerable.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from collections import defaultdict, deque

# ---- capability model (spec section 8: capability classes + weights) ----
# ordered least->most dangerous; DESTRUCTIVE = index >= WRITE
CAP_WEIGHT = {
    "META_READ": 0.10,
    "LOG_READ": 0.15,
    "READ": 0.20,
    "WRITE": 0.50,
    "CREATE": 0.70,
    "EXECUTE": 0.85,
    "SECRET_READ": 0.90,
    "ROLE_ASSIGN": 0.95,
    "IMPERSONATE": 1.00,
    "ADMIN": 1.00,
}
CAP_LIST = list(CAP_WEIGHT.keys())
# a capability is destructive (can take a resource down when abused) at WRITE+
DESTRUCTIVE = {"WRITE", "CREATE", "EXECUTE", "ROLE_ASSIGN", "IMPERSONATE", "ADMIN"}


@dataclass
class Estate:
    seed: int
    identities: list                      # list of identity ids
    id_type: dict                         # id -> human|service|machine
    resources: list                       # list of resource ids
    criticality: dict                     # resource -> [0,1]
    is_production: dict                    # resource -> bool
    # authorization: identity -> list of (resource, capability)
    access: dict
    # dependency DAG: resource -> set of resources it DEPENDS ON (out = deps)
    deps: dict
    # reverse: resource -> set of resources that depend on it (ancestors)
    dependents: dict
    ingress: set                          # resources reachable from an ingress

    def n_ids(self):
        return len(self.identities)


def generate_estate(seed: int, n_identities: int, n_resources: int | None = None,
                    fanout_depth: int = 4, wildcard_rate: float = 0.12) -> Estate:
    rng = random.Random(seed)
    if n_resources is None:
        n_resources = max(12, n_identities // 5)

    resources = [f"svc{r}" for r in range(n_resources)]

    # --- dependency DAG: scale-free-ish, layered so there IS downstream depth ---
    # assign each resource a layer 0..fanout_depth (0 = leaf/data, high = edge)
    layer = {}
    for r in resources:
        layer[r] = rng.randint(0, fanout_depth)
    deps = {r: set() for r in resources}
    dependents = {r: set() for r in resources}
    # a resource depends on some resources in strictly lower layers (preferential)
    lower_by_layer = defaultdict(list)
    for r in resources:
        lower_by_layer[layer[r]].append(r)
    # preferential-attachment weighting: popular low-layer nodes attract more deps
    indeg = defaultdict(int)
    for r in sorted(resources, key=lambda x: layer[x]):
        if layer[r] == 0:
            continue
        candidates = [c for L in range(0, layer[r]) for c in lower_by_layer[L]]
        if not candidates:
            continue
        k = rng.randint(1, min(4, len(candidates)))
        # weight by (1 + indeg) => preferential attachment => a few SPOFs emerge
        weights = [1 + indeg[c] for c in candidates]
        chosen = set()
        for _ in range(k):
            pick = rng.choices(candidates, weights=weights, k=1)[0]
            chosen.add(pick)
        for c in chosen:
            deps[r].add(c)
            dependents[c].add(r)
            indeg[c] += 1

    # criticality: partly structural (high in-degree => more critical) + noise
    maxindeg = max(indeg.values()) if indeg else 1
    criticality = {}
    is_production = {}
    for r in resources:
        struct = indeg[r] / maxindeg if maxindeg else 0.0
        criticality[r] = round(min(1.0, 0.25 * rng.random() + 0.75 * struct), 3)
        is_production[r] = rng.random() < 0.5

    # ingress: the top-layer resources are user-facing
    top_layer = max(layer.values())
    ingress = {r for r in resources if layer[r] >= top_layer - 0}
    # transitive ingress-reachability (anything an ingress node depends on is reachable)
    ingress_reach = set()
    dq = deque(ingress)
    while dq:
        x = dq.popleft()
        if x in ingress_reach:
            continue
        ingress_reach.add(x)
        for d in deps[x]:
            dq.append(d)

    # --- identities + authorization ---
    identities = [f"id{n}" for n in range(n_identities)]
    id_type = {}
    access = {}
    for idx in identities:
        t = rng.choices(["human", "service", "machine"], weights=[0.4, 0.4, 0.2])[0]
        id_type[idx] = t
        # how many resources this identity can reach
        # services/machines tend to reach fewer but sometimes deeper (into data tier)
        n_reach = rng.choices([1, 2, 3, 5, 8, 15], weights=[25, 25, 20, 15, 10, 5])[0]
        n_reach = min(n_reach, n_resources)
        # wildcard identities reach a big swath
        if rng.random() < wildcard_rate:
            n_reach = min(n_resources, n_reach * rng.randint(3, 8))
        reached = rng.sample(resources, n_reach)
        pairs = []
        for r in reached:
            # capability: humans skew read, machines sometimes hold high privilege
            if t == "human":
                cap = rng.choices(CAP_LIST, weights=[10,8,20,15,6,4,3,2,1,1])[0]
            elif t == "service":
                cap = rng.choices(CAP_LIST, weights=[6,6,12,18,10,8,6,3,2,2])[0]
            else:  # machine
                cap = rng.choices(CAP_LIST, weights=[4,4,8,14,10,10,8,6,6,8])[0]
            pairs.append((r, cap))
        access[idx] = pairs

    return Estate(seed=seed, identities=identities, id_type=id_type,
                  resources=resources, criticality=criticality,
                  is_production=is_production, access=access,
                  deps=deps, dependents=dependents, ingress=ingress_reach)


# ---------------- GROUND TRUTH ----------------
def true_consequence(est: Estate, idx: str) -> set:
    """Distinct services that fail if identity idx is compromised.
    Independent of any scoring method."""
    directly_downed = set()
    for (r, cap) in est.access[idx]:
        if cap in DESTRUCTIVE:
            directly_downed.add(r)
    # transitive ancestor closure over `dependents`
    failed = set()
    dq = deque(directly_downed)
    while dq:
        x = dq.popleft()
        for anc in est.dependents[x]:
            if anc not in failed:
                failed.add(anc)
                dq.append(anc)
    # exclude the directly-touched resources from measured downstream impact
    return failed - directly_downed


def true_consequence_weighted(est: Estate, idx: str) -> float:
    """Ground-truth severity: criticality mass of the failed set, with an
    ingress multiplier (user-visible failures matter more)."""
    failed = true_consequence(est, idx)
    total = 0.0
    for r in failed:
        w = est.criticality[r]
        if r in est.ingress:
            w *= 1.5
        total += w
    return round(total, 4)
