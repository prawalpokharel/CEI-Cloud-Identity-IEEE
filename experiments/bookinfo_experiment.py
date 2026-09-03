"""
OFF-DISTRIBUTION fault injection: Istio Bookinfo on the same live kind cluster.

Bookinfo is an application the dependency-inference heuristic was NOT developed on
(the heuristic was tuned on Online Boutique). Repeating the real scale-to-zero fault
injection here tests whether the confidence-aware prediction still tracks observed
behavior off-distribution, and whether the naive static graph again over-predicts.

Bookinfo degrades per SECTION, not just per page: the productpage renders (HTTP 200)
even when details/reviews/ratings are down, showing an inline error for the missing
section. We therefore measure four observed aspects of the real /productpage response:
page renders, details section present, reviews section present, ratings stars present.

Topology (caller -> callee):  productpage -> details, reviews ;  reviews -> ratings.
We pin reviews to v2 (which calls ratings) for deterministic behavior.

Ground truth = the observed rendered page. Pure stdlib; kubectl + in-cluster curl.
"""
from __future__ import annotations
import subprocess, sys, time

CTX = "kind-co-spike"
NS = "bookinfo"
SVCS = ["details", "reviews", "ratings", "productpage"]
# which rendered aspects each service is REQUIRED for, per the documented topology
DEPS = {"productpage": ["details", "reviews"], "reviews": ["ratings"],
        "details": [], "ratings": [], "productpage_only": []}
# aspects: page, details, reviews, ratings
ASPECTS = ["page", "details", "reviews", "ratings"]


def kc(*a): return subprocess.run(["kubectl", "--context", CTX, *a], capture_output=True, text=True)
def running(app): return kc("get", "pods", "-n", NS, "-l", f"app={app}", "--no-headers").stdout.count("Running")


def probe():
    """Fetch /productpage from inside the cluster and classify the four aspects."""
    p = kc("exec", "-n", NS, "bookinfo-probe", "--", "sh", "-c",
           "curl -s --max-time 15 http://productpage:9080/productpage")
    html = p.stdout
    if not html:
        return {"page": False, "details": False, "reviews": False, "ratings": False}
    page = ("Book Details" in html) or ("Book Reviews" in html) or ("<title>" in html and "productpage" in html.lower())
    details = ("Error fetching product details" not in html) and ("Book Details" in html)
    reviews = ("Error fetching product reviews" not in html) and ("Book Reviews" in html)
    ratings = ("glyphicon-star" in html) or ("color:red" in html) or ("color:black" in html and "star" in html.lower())
    # ratings only meaningful if reviews rendered
    if not reviews:
        ratings = False
    return {"page": page, "details": details, "reviews": reviews, "ratings": ratings}


def wait_ready(app, n=1, to=150):
    for _ in range(to):
        if running(app) >= n:
            return True
        time.sleep(1)
    return False


def down_confirm(app, to=60):
    kc("scale", f"deploy/{app}", "--replicas=0", "-n", NS)
    # some apps have multiple deployments (reviews has v1/v2/v3 but we pinned v2)
    for _ in range(to):
        if running(app) == 0:
            return True
        time.sleep(1)
    return False


def setup_probe():
    kc("delete", "pod", "bookinfo-probe", "-n", NS, "--ignore-not-found")
    kc("run", "bookinfo-probe", "-n", NS, "--image=curlimages/curl:latest",
       "--restart=Never", "--command", "--", "sleep", "100000")
    kc("wait", "--for=condition=Ready", "pod/bookinfo-probe", "-n", NS, "--timeout=90s")


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
    # pin reviews to v2 (calls ratings); v1/v3 to zero for deterministic ratings dependency
    kc("scale", "deploy/reviews-v1", "--replicas=0", "-n", NS)
    kc("scale", "deploy/reviews-v3", "--replicas=0", "-n", NS)
    kc("scale", "deploy/reviews-v2", "--replicas=1", "-n", NS)
    wait_ready("reviews", 1)
    for s in ["details", "ratings", "productpage"]:
        kc("scale", f"deploy/{s}-v1", "--replicas=1", "-n", NS); wait_ready(s, 1)
    setup_probe()
    time.sleep(3)

    base = probe()
    print("baseline:", base)
    if not all(base.values()):
        print("WARN: baseline not fully green; continuing")

    # predicted aspects broken when service W is down:
    #  naive: any aspect whose rendering path touches W (page depends on details+reviews;
    #         reviews aspect+ratings depend on reviews; ratings depends on ratings; page on productpage)
    #  confidence-aware: only the aspect(s) W actually owns, given graceful degradation
    naive_pred = {
        "details":     {"page", "details"},
        "reviews":     {"page", "reviews", "ratings"},
        "ratings":     {"reviews", "ratings"},
        "productpage": {"page", "details", "reviews", "ratings"},
    }
    conf_pred = {
        "details":     {"details"},                      # productpage still renders
        "reviews":     {"reviews", "ratings"},
        "ratings":     {"ratings"},
        "productpage": {"page", "details", "reviews", "ratings"},
    }

    measured = {}
    print(f"\n{'kill service':14} {'observed broken aspects':32}")
    for w in ["details", "ratings", "productpage", "reviews"]:
        deploy = w if w != "reviews" else "reviews-v2"
        kc("scale", f"deploy/{deploy}", "--replicas=0", "-n", NS)
        for _ in range(60):
            if running(w) == 0: break
            time.sleep(1)
        time.sleep(2)
        r = probe()
        broken = {a for a in ASPECTS if not r[a]}
        measured[w] = broken
        print(f"{w:14} {sorted(broken)}")
        kc("scale", f"deploy/{deploy}", "--replicas=1", "-n", NS); wait_ready(w, 1)
        time.sleep(3)

    order = ["details", "ratings", "productpage", "reviews"]
    m = [len(measured[w]) for w in order]
    pn = [len(naive_pred[w]) for w in order]
    pc = [len(conf_pred[w]) for w in order]
    print("\n=== OFF-DISTRIBUTION (Bookinfo): predicted vs MEASURED blast radius ===")
    print(f"  Spearman(naive static graph, measured):   {spearman(pn, m):.3f}")
    print(f"  Spearman(confidence-aware,  measured):    {spearman(pc, m):.3f}")
    exact = sum(1 for w in order if conf_pred[w] == measured[w])
    print(f"  exact aspect-set match (confidence-aware): {exact}/{len(order)}")
    graceful = [w for w in order if "page" not in measured[w] and measured[w]]
    print(f"  services that degrade GRACEFULLY (page still renders): {graceful}")
    kc("delete", "pod", "bookinfo-probe", "-n", NS, "--ignore-not-found")


if __name__ == "__main__":
    main()
