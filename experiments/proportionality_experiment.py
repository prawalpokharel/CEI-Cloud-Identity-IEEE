"""
PROPORTIONALITY-GATED REMEDIATION on the live kind cluster.

Bridges effects-based proportionality assessment (Maathuis et al., MILCOM'18;
Defence Technology 2021) with identity blast-radius remediation: a de-scoping
action (revoking one grant) buys risk reduction (advantage) at the price of
severed legitimate function (collateral). Both coordinates are grounded in
measurement on the same live cluster as the paper's Tier-C experiments:

  ADVANTAGE  A(g): the reduction in total sensitivity-weighted exfiltration
    reach when grant g is revoked -- measured by ACTUALLY editing the Role
    (kubectl apply), re-running the live compromise BFS (auth can-i + real
    secret reads, chaining laterally), then restoring the grant.
  COLLATERAL C(g): the observed user-facing cost of severing the dependency
    edge the grant serves -- the measured broken-flow count when that callee
    was fault-injected (Tier-C availability data), an UPPER BOUND since the
    callee may have other callers; zero for the planted over-privilege
    misconfigurations, which serve no legitimate call edge.

Output: the (A, C) frontier over all 18 grants, Pareto classification, and the
comparison against privilege-count-guided de-scoping.

Same overlay as ci_experiment.py (namespace prop-exp). Pure stdlib + kubectl.
Namespace deleted at the end.
"""
from __future__ import annotations
import subprocess, sys, time, json

CTX = "kind-co-spike"
NS = "prop-exp"

DEPS = {
    "frontend": ["productcatalogservice", "currencyservice", "cartservice",
                 "shippingservice", "checkoutservice", "recommendationservice", "adservice"],
    "checkoutservice": ["productcatalogservice", "currencyservice", "cartservice",
                        "shippingservice", "paymentservice", "emailservice"],
    "cartservice": ["redis-cart"],
    "recommendationservice": ["productcatalogservice"],
    "adservice": [], "currencyservice": [], "emailservice": [], "paymentservice": [],
    "productcatalogservice": [], "redis-cart": [], "shippingservice": [],
}
SERVICES = list(DEPS.keys())
SENS = {
    "paymentservice": 0.98, "redis-cart": 0.95, "checkoutservice": 0.75,
    "cartservice": 0.70, "productcatalogservice": 0.60, "emailservice": 0.55,
    "shippingservice": 0.50, "currencyservice": 0.40, "recommendationservice": 0.30,
    "frontend": 0.30, "adservice": 0.20,
}
MISCONFIG = [("adservice", "paymentservice"), ("emailservice", "redis-cart"),
             ("recommendationservice", "cartservice")]

# measured user-flow breakage when each service was fault-injected (Tier-C v6 sweep)
FLOWS_BROKEN = {
    "adservice": 0, "cartservice": 5, "checkoutservice": 1, "currencyservice": 2,
    "emailservice": 0, "paymentservice": 1, "productcatalogservice": 3,
    "recommendationservice": 0, "redis-cart": 5, "shippingservice": 2,
}

def base_grants():
    g = {x: set(DEPS[x]) for x in SERVICES}
    for who, extra in MISCONFIG:
        g[who].add(extra)
    return g

ALL_GRANTS = [(x, y) for x, ys in base_grants().items() for y in sorted(ys)]


def kc(*a):
    return subprocess.run(["kubectl", "--context", CTX, *a], capture_output=True, text=True)


def apply_yaml(y):
    p = subprocess.run(["kubectl", "--context", CTX, "apply", "-f", "-"],
                       input=y, capture_output=True, text=True)
    if p.returncode != 0:
        print("apply error:", p.stderr[:300]); sys.exit(1)


def role_yaml(x, creds):
    rn = "".join(f"    - cred-{y}\n" for y in sorted(creds)) if creds else ""
    rules = (f"rules:\n- apiGroups: [\"\"]\n  resources: [\"secrets\"]\n"
             f"  verbs: [\"get\"]\n  resourceNames:\n{rn}") if creds else "rules: []\n"
    return (f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n"
            f"  name: role-{x}\n  namespace: {NS}\n{rules}")


def setup():
    import base64
    docs = [f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"]
    for x in SERVICES:
        tok = base64.b64encode(f"SECRET-material-of-{x}".encode()).decode()
        docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-{x}\n  namespace: {NS}\n")
        docs.append(f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: cred-{x}\n  namespace: {NS}\n"
                    f"type: Opaque\ndata:\n  token: {tok}\n")
    G = base_grants()
    for x in SERVICES:
        docs.append(role_yaml(x, G[x]))
        docs.append(
            f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-{x}\n"
            f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-{x}\n  namespace: {NS}\n"
            f"roleRef:\n  kind: Role\n  name: role-{x}\n  apiGroup: rbac.authorization.k8s.io\n")
    apply_yaml("---\n".join(docs)); time.sleep(3)


def can_get(sa, secret):
    who = f"system:serviceaccount:{NS}:{sa}"
    p = kc("auth", "can-i", "get", f"secret/{secret}", "-n", NS, "--as", who)
    return p.stdout.strip().startswith("yes")


def real_read_ok(sa, secret):
    who = f"system:serviceaccount:{NS}:{sa}"
    p = kc("get", "secret", secret, "-n", NS, "--as", who, "-o", "jsonpath={.data.token}")
    return p.returncode == 0 and bool(p.stdout.strip())


def measure_identity(x):
    """Real compromise BFS for identity x: possess cred-x, then chain via live RBAC."""
    compromised = {x}
    frontier = [x]
    while frontier:
        c = frontier.pop()
        for y in SERVICES:
            if y in compromised:
                continue
            if can_get(f"sa-{c}", f"cred-{y}") and real_read_ok(f"sa-{c}", f"cred-{y}"):
                compromised.add(y); frontier.append(y)
    return compromised


def total_exposure(closures):
    return round(sum(sum(SENS[s] for s in cl) for cl in closures.values()), 3)


def main():
    print(f"setting up {NS} ...")
    setup()
    G = base_grants()

    print("baseline measurement (11 identities, real BFS)...")
    base_cl = {x: measure_identity(x) for x in SERVICES}
    T_base = total_exposure(base_cl)
    print(f"  baseline total sensitivity-weighted reach: {T_base}")

    results = []
    for (gx, gy) in ALL_GRANTS:
        # apply the revocation: role-gx without cred-gy (REAL RBAC change)
        apply_yaml(role_yaml(gx, G[gx] - {gy})); time.sleep(1)
        # only identities whose baseline closure includes gx can be affected
        affected = [i for i in SERVICES if gx in base_cl[i]]
        cl = dict(base_cl)
        for i in affected:
            cl[i] = measure_identity(i)
        A = round(T_base - total_exposure(cl), 3)
        is_mis = (gx, gy) in MISCONFIG
        C = 0 if is_mis else FLOWS_BROKEN[gy]
        results.append({"grant": f"{gx}->{gy}", "misconfig": is_mis,
                        "advantage_dReach": A, "collateral_flows_ub": C,
                        "remeasured_identities": len(affected)})
        print(f"  revoke {gx:>22} -> {gy:<22} A={A:<7} C={C}  ({'MISCONFIG' if is_mis else 'legitimate'})")
        # restore
        apply_yaml(role_yaml(gx, G[gx])); time.sleep(1)

    # Pareto classification: g dominated if another has >=A and <=C with one strict
    for r in results:
        r["pareto_dominant"] = not any(
            (o["advantage_dReach"] >= r["advantage_dReach"] and o["collateral_flows_ub"] <= r["collateral_flows_ub"]
             and (o["advantage_dReach"] > r["advantage_dReach"] or o["collateral_flows_ub"] < r["collateral_flows_ub"]))
            for o in results if o is not r)

    mis = [r for r in results if r["misconfig"]]
    legit = [r for r in results if not r["misconfig"]]
    excess_total = round(sum(r["advantage_dReach"] for r in mis), 3)
    print("\n=== PROPORTIONALITY-GATED REMEDIATION (all values measured) ===")
    print(f"  misconfig revocations: A = {[r['advantage_dReach'] for r in mis]}, all C=0, "
          f"Pareto-dominant: {[r['pareto_dominant'] for r in mis]}")
    zero_c_legit = sorted([r for r in legit if r["collateral_flows_ub"] == 0],
                          key=lambda r: -r["advantage_dReach"])
    print(f"  zero-collateral legitimate revocations: "
          f"{[(r['grant'], r['advantage_dReach']) for r in zero_c_legit]}")
    top_by_A = sorted(results, key=lambda r: -r["advantage_dReach"])[:3]
    print(f"  top-3 by measured advantage alone: {[(r['grant'], r['advantage_dReach'], r['collateral_flows_ub']) for r in top_by_A]}")
    # privilege-count view: the largest grant-holder
    holder = max(G, key=lambda x: len(G[x]))
    holder_revs = [r for r in results if r["grant"].startswith(holder + "->")]
    print(f"  largest grant-holder = {holder} ({len(G[holder])} grants); its revocations' collateral: "
          f"{[(r['grant'].split('->')[1], r['collateral_flows_ub']) for r in holder_revs]}")
    with open("/tmp/proportionality_results.json", "w") as f:
        json.dump({"T_base": T_base, "excess_reach_from_misconfigs": excess_total,
                   "results": results}, f, indent=1)
    print("\nwrote /tmp/proportionality_results.json")
    kc("delete", "namespace", NS, "--wait=false")


if __name__ == "__main__":
    main()
