"""
Analyze the REAL fault-injection sweep of the live Online Boutique
(tierc_real_v2.csv): measured blast radius vs predicted, and identity blast
radius vs the REAL measured consequence. Ground truth = the app's observed HTTP
behavior under real scale-to-zero fault injection, not any computation of ours.
"""
import csv, sys, random

FLOWS = ["home", "browse", "addcart", "viewcart", "checkout"]

# Which services each user flow REQUIRES (must be up) vs OPTIONALLY touches
# (graceful degradation -- flow still succeeds if they are down). From the
# documented Online Boutique architecture; redis-cart backs cartservice.
REQUIRED = {
    "home":     {"productcatalogservice", "currencyservice", "cartservice", "redis-cart"},
    "browse":   {"productcatalogservice", "currencyservice", "cartservice", "redis-cart"},
    "addcart":  {"productcatalogservice", "cartservice", "redis-cart"},
    "viewcart": {"cartservice", "redis-cart", "productcatalogservice", "currencyservice", "shippingservice"},
    "checkout": {"checkoutservice", "cartservice", "redis-cart", "currencyservice",
                 "productcatalogservice", "shippingservice", "paymentservice"},
}
OPTIONAL = {
    "home":     {"adservice"},
    "browse":   {"adservice", "recommendationservice"},
    "viewcart": {"recommendationservice"},
    "checkout": {"emailservice"},
}
SERVICES = sorted(set().union(*REQUIRED.values(), *OPTIONAL.values()))


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


def load(path):
    rows = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            rows[row["service"]] = {fl: row[fl] for fl in FLOWS}
    return rows


def broken(cell):  # 5xx or connection error (000) = broken; 200/302 = ok
    return not (cell in ("200", "302"))


def main(path):
    rows = load(path)
    services = [s for s in SERVICES if s in rows]
    measured, pred_req, pred_naive = {}, {}, {}
    print(f"{'service':24} {'MEASURED broken flows':32} {'#meas':>5} {'#req':>4} {'#naive':>6}")
    for s in services:
        meas = {fl for fl in FLOWS if broken(rows[s][fl])}
        preq = {fl for fl in FLOWS if s in REQUIRED[fl]}
        pnv  = {fl for fl in FLOWS if s in REQUIRED[fl] or s in OPTIONAL.get(fl, set())}
        measured[s], pred_req[s], pred_naive[s] = meas, preq, pnv
        print(f"{s:24} {','.join(sorted(meas)) or '(none - graceful)':32} "
              f"{len(meas):>5} {len(preq):>4} {len(pnv):>6}")

    m  = [len(measured[s]) for s in services]
    pr = [len(pred_req[s]) for s in services]
    pn = [len(pred_naive[s]) for s in services]
    print("\n=== workload-level: predicted vs MEASURED blast radius (real app) ===")
    print(f"  Spearman(naive all-edges, measured):    {spearman(pn, m):.3f}")
    print(f"  Spearman(confidence-aware, measured):   {spearman(pr, m):.3f}")
    exact = sum(1 for s in services if pred_req[s] == measured[s])
    print(f"  exact broken-flow-set match (confidence-aware): {exact}/{len(services)}")
    graceful = [s for s in services if not measured[s]]
    print(f"  MEASURED-graceful (zero user impact): {', '.join(graceful)}")
    over = [s for s in services if pred_naive[s] and not measured[s]]
    print(f"  naive OVER-predicts blast for: {', '.join(over)}  <- static graph misses graceful degradation")

    # ---- identity level vs REAL measured consequence ----
    # measured consequence of taking service s down = # user flows it breaks.
    cons = {s: len(measured[s]) for s in services}
    rng = random.Random(20260903)
    caps_destroy = ["WRITE", "EXECUTE", "ADMIN", "DELETE"]
    caps_read = ["READ", "SECRET_READ"]
    pred_ibr, meas_cons = [], []
    for _ in range(300):
        k = rng.choice([1, 1, 2, 2, 3])
        touched = rng.sample(services, min(k, len(services)))
        grants = [(r, rng.choice(caps_destroy + caps_read)) for r in touched]
        dz = {r for (r, c) in grants if c in caps_destroy}
        pred_ibr.append(sum(len(pred_req[r]) + 1 for r in dz))     # predicted blast radius
        meas_cons.append(sum(cons[r] for r in dz))                 # REAL measured consequence
    print("\n=== identity-level: predicted IBR vs REAL measured consequence (300 identities) ===")
    print(f"  Spearman(predicted identity blast radius, MEASURED downstream failure): "
          f"{spearman(pred_ibr, meas_cons):.3f}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/tierc_real_v2.csv")
