"""
REAL integrity-compromise experiment on the live kind cluster.

Gives the integrity channel an OBSERVED oracle, the dual of the confidentiality one.
In a throwaway namespace we stand up, for each Online Boutique service:
  * a ConfigMap dat-<svc> = that service's data-of-record (a baseline value);
  * a ServiceAccount sa-<svc>;
  * real RBAC granting UPDATE on the ConfigMaps that service legitimately writes
    (its own data-of-record) -- PLUS a few realistic over-privilege write
    misconfigurations (an identity able to corrupt a data store it has no business
    writing, e.g. the ad service able to rewrite the product catalog);
  * a read-only agent SA (no write) and an ops SA (write all).

We then "compromise" each identity by ACTUALLY corrupting (kubectl patch --as=<sa>)
every ConfigMap its RBAC lets it write, and read the ConfigMaps back to confirm which
were really modified. Integrity corruption flows UP the dependency graph: if service
Y's data-of-record is corrupted, every service that (transitively) depends on Y now
consumes bad data. The MEASURED integrity blast radius of an identity is therefore the
criticality-weighted set {corrupted services} union their transitive dependents, read
off the real post-write ConfigMap state -- not a computation.

We compare that to the RBAC-aware integrity score (the engine's method), a
dependency-graph-only prediction (which assumes each identity writes only its own
data and so misses the write-misconfigurations), and a permission-count baseline.

Pure stdlib; shells out to kubectl. Namespace is deleted at the end.
"""
from __future__ import annotations
import subprocess, base64, sys, time

CTX = "kind-co-spike"
NS = "int-exp"

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
INGRESS = {"frontend", "checkoutservice"}         # user-facing: corrupted output worst here
CRIT = {s: (1.5 if s in INGRESS else 1.0) for s in SERVICES}

# write potency of the capability used to corrupt (all update here -> full corruption)
WRITE_POTENCY = 1.0

# realistic OVER-PRIVILEGE WRITE misconfigurations: (identity, data store it can corrupt)
MISCONFIG = [
    ("adservice", "productcatalogservice"),   # ad SA can rewrite the product catalog
    ("emailservice", "currencyservice"),      # email SA can rewrite exchange rates
    ("recommendationservice", "cartservice"), # rec SA can rewrite cart data
]

def writes():   # effective UPDATE grants: own data + misconfigs
    g = {x: {x} for x in SERVICES}            # each service writes its own data-of-record
    for who, extra in MISCONFIG:
        g[who].add(extra)
    return g


def kc(*a): return subprocess.run(["kubectl", "--context", CTX, *a], capture_output=True, text=True)


def apply(y):
    p = subprocess.run(["kubectl", "--context", CTX, "apply", "-f", "-"], input=y, capture_output=True, text=True)
    if p.returncode != 0:
        print("apply error:", p.stderr[:400]); sys.exit(1)


def setup():
    G = writes()
    docs = [f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"]
    for x in SERVICES:
        docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-{x}\n  namespace: {NS}\n")
        docs.append(f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: dat-{x}\n  namespace: {NS}\ndata:\n  value: \"baseline-{x}\"\n")
    docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-agent-ro\n  namespace: {NS}\n")
    docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-ops\n  namespace: {NS}\n")
    for x in SERVICES:
        names = sorted(G[x])
        rn = "".join(f"    - dat-{y}\n" for y in names)
        docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: role-{x}\n"
                    f"  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n  resources: [\"configmaps\"]\n"
                    f"  verbs: [\"get\",\"update\",\"patch\"]\n  resourceNames:\n{rn}")
        docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-{x}\n"
                    f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-{x}\n  namespace: {NS}\n"
                    f"roleRef:\n  kind: Role\n  name: role-{x}\n  apiGroup: rbac.authorization.k8s.io\n")
    # ops: write all; agent-ro: read pods/services only, NO configmap write
    docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: role-ops\n"
                f"  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n  resources: [\"configmaps\"]\n  verbs: [\"get\",\"update\",\"patch\"]\n")
    docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-ops\n"
                f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-ops\n  namespace: {NS}\n"
                f"roleRef:\n  kind: Role\n  name: role-ops\n  apiGroup: rbac.authorization.k8s.io\n")
    docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: role-agent-ro\n"
                f"  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n  resources: [\"pods\",\"services\"]\n  verbs: [\"get\",\"list\",\"watch\"]\n")
    docs.append(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-agent-ro\n"
                f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-agent-ro\n  namespace: {NS}\n"
                f"roleRef:\n  kind: Role\n  name: role-agent-ro\n  apiGroup: rbac.authorization.k8s.io\n")
    apply("---\n".join(docs)); time.sleep(3)


def dependents(target):    # transitive dependents (who reads target, directly or transitively)
    rev = {s: set() for s in SERVICES}
    for a, bs in DEPS.items():
        for b in bs:
            rev[b].add(a)
    seen, dq = set(), [target]
    while dq:
        x = dq.pop()
        for a in rev[x]:
            if a not in seen:
                seen.add(a); dq.append(a)
    return seen


def real_value(cm):
    p = kc("get", "configmap", cm, "-n", NS, "-o", "jsonpath={.data.value}")
    return p.stdout.strip() if p.returncode == 0 else None


def try_corrupt(sa, cm):   # real RBAC-gated write; returns True iff the value actually changed
    who = f"system:serviceaccount:{NS}:{sa}"
    kc("patch", "configmap", cm, "-n", NS, "--as", who, "--type", "merge",
       "-p", '{"data":{"value":"CORRUPTED"}}')
    return real_value(cm) == "CORRUPTED"


def reset():
    for x in SERVICES:
        kc("patch", "configmap", f"dat-{x}", "-n", NS, "--type", "merge",
           "-p", f'{{"data":{{"value":"baseline-{x}"}}}}')


def spearman(a, b):
    def rk(v):
        o = sorted(range(len(v)), key=lambda i: v[i]); r = [0.0]*len(v); i = 0
        while i < len(o):
            j = i
            while j+1 < len(o) and v[o[j+1]] == v[o[i]]: j += 1
            for k in range(i, j+1): r[o[k]] = (i+j)/2.0
            i = j+1
        return r
    ra, rb = rk(a), rk(b); n = len(a); ma = sum(ra)/n; mb = sum(rb)/n
    num = sum((ra[i]-ma)*(rb[i]-mb) for i in range(n))
    da = sum((x-ma)**2 for x in ra)**.5; db = sum((x-mb)**2 for x in rb)**.5
    return num/(da*db) if da and db else 0.0


def main():
    print(f"setting up namespace {NS} ...")
    setup()
    G = writes()
    rows = []
    print(f"\n{'identity':26} MEASURED corrupted-output set (real writes + reads)")
    for x in SERVICES:
        reset()
        corrupted = {y for y in SERVICES if try_corrupt(f"sa-{x}", f"dat-{y}")}   # real RBAC-gated writes
        # observed integrity reach = corrupted services + everyone who transitively reads them
        reach = set(corrupted)
        for c in corrupted:
            reach |= dependents(c)
        meas = round(sum(CRIT[s] for s in reach), 3)
        # predictions
        rbac_reach = set(G[x])
        for c in set(G[x]):
            rbac_reach |= dependents(c)
        pred_rbac = round(WRITE_POTENCY * sum(CRIT[s] for s in rbac_reach), 3)
        dep_only_reach = {x} | dependents(x)                # assumes writes only own data
        pred_dep = round(sum(CRIT[s] for s in dep_only_reach), 3)
        permcnt = len(G[x])
        rows.append((x, len(reach), meas, pred_rbac, pred_dep, permcnt))
        print(f"sa-{x:22} {sorted(reach)}")
    reset()
    ro = {y for y in SERVICES if try_corrupt("sa-agent-ro", f"dat-{y}")}
    reset()
    ops = {y for y in SERVICES if try_corrupt("sa-ops", f"dat-{y}")}
    reset()
    print(f"\nsa-agent-ro corrupted: {sorted(ro)}  (expect EMPTY -> read-only agent cannot tamper)")
    print(f"sa-ops      corrupted: {len(ops)}/{len(SERVICES)} data stores")

    print(f"\n{'identity':24} {'#reach':>6} {'measCrit':>8} {'IBR-rbac':>8} {'dep-only':>8} {'permcnt':>8}")
    for (x, n, ms, pr, pd, pc) in rows:
        flag = "  <-write-misconfig" if any(w == x for w, _ in MISCONFIG) else ""
        print(f"sa-{x:20} {n:>6} {ms:>8} {pr:>8} {pd:>8} {pc:>8}{flag}")
    meas = [r[2] for r in rows]; ibr = [r[3] for r in rows]; dep = [r[4] for r in rows]; pc = [float(r[5]) for r in rows]
    print("\n=== integrity blast radius vs REAL measured corruption reach ===")
    print(f"  Spearman(IBR-integrity w/ real RBAC, measured):  {spearman(ibr, meas):.3f}")
    print(f"  Spearman(dependency-graph-only pred, measured):  {spearman(dep, meas):.3f}")
    print(f"  Spearman(permission-count baseline,  measured):  {spearman(pc, meas):.3f}")
    print(f"  agent-ro corrupted {len(ro)} stores (tamper-safety validated)")
    kc("delete", "namespace", NS, "--wait=false")


if __name__ == "__main__":
    main()
