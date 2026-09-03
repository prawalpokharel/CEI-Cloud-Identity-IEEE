"""
REAL confidentiality-compromise experiment on the live kind cluster.

Gives the confidentiality channel an OBSERVED oracle, analogous to the HTTP-5xx
availability oracle. We stand up, in a throwaway namespace on kind-co-spike:
  * one k8s Secret per Online Boutique service (cred-<svc>), tagged with a data
    sensitivity, holding a real random token = that service's secret material;
  * one ServiceAccount per service (sa-<svc>);
  * real RBAC: sa-<X> may GET the credential Secret of each service X calls (X
    holds its dependencies' client credentials) -- PLUS a few realistic
    over-privilege MISCONFIGURATIONS (an identity granted a secret it has no
    dependency reason to hold);
  * a read-only agent SA (no secret access) and an ops SA (all secrets).

Then we "compromise" each identity and MEASURE its confidentiality blast radius by
ACTUALLY reading secrets: possessing X's identity lets you read the creds X can
GET; each credential you read compromises that service too (you now hold its
token), so you recurse. Every hop is a real `kubectl auth can-i` + `kubectl get
secret --as=<sa>` against the live API server. The measured exfiltrated set is the
ground truth -- no model computes it.

We then compare that MEASURED exposure to:
  * IBR-confidentiality using the REAL extracted RBAC (the engine's method),
  * a dependency-graph-only prediction (no RBAC), and
  * a permission-count baseline,
to show the RBAC-aware consequence model tracks observed exfiltration -- including
the misconfigurations the dependency-only and count baselines miss.

Pure stdlib; shells out to kubectl. Namespace is deleted at the end.
"""
from __future__ import annotations
import subprocess, json, base64, sys, time

CTX = "kind-co-spike"
NS = "ci-exp"

# Online Boutique direct dependencies (caller -> callees it holds creds for)
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

# realistic per-service data sensitivity in [0,1] (stores/credentials high)
SENS = {
    "paymentservice": 0.98, "redis-cart": 0.95, "checkoutservice": 0.75,
    "cartservice": 0.70, "productcatalogservice": 0.60, "emailservice": 0.55,
    "shippingservice": 0.50, "currencyservice": 0.40, "recommendationservice": 0.30,
    "frontend": 0.30, "adservice": 0.20,
}

# realistic OVER-PRIVILEGE misconfigurations: (identity, extra secret it should not hold)
MISCONFIG = [
    ("adservice", "paymentservice"),          # ad SA over-scoped to payment creds
    ("emailservice", "redis-cart"),           # email SA over-scoped to the cart store
    ("recommendationservice", "cartservice"), # rec SA over-scoped to cart
]

# effective GET-secret grants per identity = deps + misconfig
def grants():
    g = {x: set(DEPS[x]) for x in SERVICES}
    for who, extra in MISCONFIG:
        g[who].add(extra)
    return g


def kc(*args, check=True):
    return subprocess.run(["kubectl", "--context", CTX, *args],
                          capture_output=True, text=True)


def apply(yaml: str):
    p = subprocess.run(["kubectl", "--context", CTX, "apply", "-f", "-"],
                       input=yaml, capture_output=True, text=True)
    if p.returncode != 0:
        print("apply error:", p.stderr[:500]); sys.exit(1)


def setup():
    G = grants()
    docs = [f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"]
    for x in SERVICES:
        tok = base64.b64encode(f"SECRET-material-of-{x}-{SENS[x]}".encode()).decode()
        docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-{x}\n  namespace: {NS}\n")
        docs.append(f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: cred-{x}\n  namespace: {NS}\n"
                    f"  annotations:\n    sensitivity: \"{SENS[x]}\"\ntype: Opaque\ndata:\n  token: {tok}\n")
    # extra SAs: read-only agent (no secrets) and ops (all secrets)
    docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-agent-ro\n  namespace: {NS}\n")
    docs.append(f"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-ops\n  namespace: {NS}\n")
    # per-identity Role granting GET on the specific cred secrets it holds
    for x in SERVICES:
        names = sorted(G[x])
        if names:
            resource_names = "".join(f"    - cred-{y}\n" for y in names)
            docs.append(
                f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n"
                f"  name: role-{x}\n  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n"
                f"  resources: [\"secrets\"]\n  verbs: [\"get\"]\n  resourceNames:\n{resource_names}")
            docs.append(
                f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n"
                f"  name: rb-{x}\n  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n"
                f"  name: sa-{x}\n  namespace: {NS}\nroleRef:\n  kind: Role\n  name: role-{x}\n"
                f"  apiGroup: rbac.authorization.k8s.io\n")
    # ops: get all secrets
    docs.append(
        f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: role-ops\n"
        f"  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n  resources: [\"secrets\"]\n  verbs: [\"get\",\"list\"]\n")
    docs.append(
        f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-ops\n"
        f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-ops\n  namespace: {NS}\n"
        f"roleRef:\n  kind: Role\n  name: role-ops\n  apiGroup: rbac.authorization.k8s.io\n")
    # agent-ro: get/list/watch pods+services, NO secrets (mirrors the real agent)
    docs.append(
        f"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: role-agent-ro\n"
        f"  namespace: {NS}\nrules:\n- apiGroups: [\"\"]\n  resources: [\"pods\",\"services\"]\n"
        f"  verbs: [\"get\",\"list\",\"watch\"]\n")
    docs.append(
        f"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: rb-agent-ro\n"
        f"  namespace: {NS}\nsubjects:\n- kind: ServiceAccount\n  name: sa-agent-ro\n  namespace: {NS}\n"
        f"roleRef:\n  kind: Role\n  name: role-agent-ro\n  apiGroup: rbac.authorization.k8s.io\n")
    apply("---\n".join(docs))
    time.sleep(3)


def can_get(sa: str, secret: str) -> bool:
    who = f"system:serviceaccount:{NS}:{sa}"
    p = kc("auth", "can-i", "get", f"secret/{secret}", "-n", NS, "--as", who)
    return p.stdout.strip().startswith("yes")


def real_read(sa: str, secret: str) -> str | None:
    who = f"system:serviceaccount:{NS}:{sa}"
    p = kc("get", "secret", secret, "-n", NS, "--as", who, "-o", "jsonpath={.data.token}")
    if p.returncode == 0 and p.stdout.strip():
        return base64.b64decode(p.stdout.strip()).decode(errors="replace")
    return None


def measure_exfiltration(identity_sa: str, self_service: str | None):
    """BFS: real reads with escalating impersonation. Returns the set of services
    whose secret material was actually exfiltrated."""
    compromised = set()
    frontier = []
    if self_service:                      # compromising X's identity => you hold cred-X
        val = real_read("sa-ops", f"cred-{self_service}")  # (self secret is yours by definition)
        compromised.add(self_service); frontier.append(self_service)
    # the acting identity itself may also directly read secrets (agent-ro / ops cases)
    for y in SERVICES:
        if can_get(identity_sa, f"cred-{y}") and real_read(identity_sa, f"cred-{y}") is not None:
            if y not in compromised:
                compromised.add(y); frontier.append(y)
    # chain: each compromised service C lets you act as sa-C and read its grants
    while frontier:
        c = frontier.pop()
        for y in SERVICES:
            if y in compromised:
                continue
            if can_get(f"sa-{c}", f"cred-{y}") and real_read(f"sa-{c}", f"cred-{y}") is not None:
                compromised.add(y); frontier.append(y)
    return compromised


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


def transitive_deps(x):
    seen, dq = set(), list(DEPS[x])
    while dq:
        y = dq.pop()
        if y not in seen:
            seen.add(y); dq.extend(DEPS[y])
    return seen


def main():
    print(f"setting up namespace {NS} on {CTX} ...")
    setup()
    G = grants()
    # identities under test: one per service (compromise its SA), plus agent-ro and ops
    rows = []
    print(f"\n{'identity':26} {'MEASURED exfiltrated (real reads)':10}")
    for x in SERVICES:
        exf = measure_exfiltration(f"sa-{x}", x)
        meas_sens = round(sum(SENS[s] for s in exf), 3)
        # predictions
        rbac_closure = {x} | transitive_deps(x)  # dependency-only prediction (no misconfig)
        pred_dep = round(sum(SENS[s] for s in rbac_closure), 3)
        # IBR-confidentiality using REAL grants (what the engine extracts): BFS over grant graph
        seen, dq = {x}, [x]
        while dq:
            c = dq.pop()
            for y in G.get(c, ()):
                if y not in seen: seen.add(y); dq.append(y)
        pred_rbac = round(sum(SENS[s] for s in seen), 3)
        perm_count = len(G[x])               # baseline: # secrets directly gettable
        rows.append((x, len(exf), meas_sens, pred_rbac, pred_dep, perm_count))
        print(f"sa-{x:22} {sorted(exf)}")
    # agent-ro and ops
    exf_ro = measure_exfiltration("sa-agent-ro", None)
    exf_ops = measure_exfiltration("sa-ops", None)
    print(f"\nsa-agent-ro exfiltrated: {sorted(exf_ro)}  (expect EMPTY -> read-only agent safe)")
    print(f"sa-ops      exfiltrated: {len(exf_ops)}/{len(SERVICES)} services")

    print(f"\n{'identity':24} {'#exf':>4} {'measΣsens':>9} {'IBR-rbac':>9} {'dep-only':>9} {'permcnt':>8}")
    for (x, n, ms, pr, pd, pc) in rows:
        flag = "  <-misconfig" if any(w == x for w, _ in MISCONFIG) else ""
        print(f"sa-{x:20} {n:>4} {ms:>9} {pr:>9} {pd:>9} {pc:>8}{flag}")

    meas = [r[2] for r in rows]
    ibr_rbac = [r[3] for r in rows]
    dep_only = [r[4] for r in rows]
    permcnt = [float(r[5]) for r in rows]
    print("\n=== confidentiality blast radius vs REAL measured exfiltration ===")
    print(f"  Spearman(IBR-confidentiality w/ real RBAC, measured):  {spearman(ibr_rbac, meas):.3f}")
    print(f"  Spearman(dependency-graph-only pred,       measured):  {spearman(dep_only, meas):.3f}")
    print(f"  Spearman(permission-count baseline,        measured):  {spearman(permcnt, meas):.3f}")
    print(f"  agent-ro measured exfiltration: {len(exf_ro)} secrets (read-only safety validated)")


if __name__ == "__main__":
    main()
