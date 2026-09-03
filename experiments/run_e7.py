"""
E7 -- Scale and cost. Runtime of estate load + IBR-full scoring vs. identity count.
"""
from __future__ import annotations
import time
import numpy as np
from estate import generate_estate
from methods import score_all, all_methods


def run(sizes=(100, 300, 1000, 3000, 10000, 30000, 100000), base_seed=9000):
    print(f"{'n_identities':<14}{'n_resources':<13}{'gen (s)':<10}{'score-all (s)':<15}{'per-identity (ms)':<18}")
    print("-" * 70)
    rows = []
    for n in sizes:
        t0 = time.time()
        est = generate_estate(seed=base_seed, n_identities=n)
        t1 = time.time()
        scores = score_all(est)   # all 7 methods
        t2 = time.time()
        gen = t1 - t0
        scoring = t2 - t1
        per_id_ms = 1000 * scoring / n
        rows.append((n, len(est.resources), gen, scoring, per_id_ms))
        print(f"{n:<14}{len(est.resources):<13}{gen:<10.3f}{scoring:<15.3f}{per_id_ms:<18.4f}")
    return rows


if __name__ == "__main__":
    rows = run()
    # crude scaling exponent from the largest two points (scoring vs n)
    (n1, _, _, s1, _), (n2, _, _, s2, _) = rows[-2], rows[-1]
    import math
    exp = math.log(s2 / s1) / math.log(n2 / n1)
    print(f"\nEmpirical scaling exponent (score-all vs n) over top range: ~{exp:.2f}")
    print("(≈1.0 => linear in identity count for the full 7-method battery)")
