"""
E2 -- Ranking fidelity against constructed ground truth, at scale.

For many seeded estates, score every identity with every method and compare
each method's ranking to the ground-truth consequence ranking.

Metrics: Spearman rho, Kendall tau (full ranking); NDCG@k and recall@k
(top-k), k in {5,10,25}. Paired within estate; report mean +/- std.
"""
from __future__ import annotations
import numpy as np
from scipy.stats import spearmanr, kendalltau

from estate import generate_estate, true_consequence_weighted
from methods import score_all, all_methods


def dcg(rels):
    return sum(rel / np.log2(i + 2) for i, rel in enumerate(rels))


def ndcg_at_k(order_ids, gt, k):
    top = order_ids[:k]
    rels = [gt[i] for i in top]
    ideal = sorted(gt.values(), reverse=True)[:k]
    d = dcg(rels)
    idcg = dcg(ideal)
    return (d / idcg) if idcg > 0 else 0.0


def recall_at_k(order_ids, gt, k):
    true_top = set(sorted(gt, key=lambda i: gt[i], reverse=True)[:k])
    pred_top = set(order_ids[:k])
    return len(true_top & pred_top) / k


def jaccard_topk(a_ids, b_ids, k):
    A, B = set(a_ids[:k]), set(b_ids[:k])
    return len(A & B) / len(A | B) if (A | B) else 1.0


def run(n_estates=40, n_identities=500, fanout_depth=4, base_seed=1000):
    methods = list(all_methods().keys())
    agg = {m: {"rho": [], "tau": [], "ndcg5": [], "ndcg10": [], "ndcg25": [],
               "rec5": [], "rec10": [], "rec25": []} for m in methods}
    jac_reachcrit_vs_full = {5: [], 10: [], 25: []}

    for e in range(n_estates):
        est = generate_estate(seed=base_seed + e, n_identities=n_identities,
                              fanout_depth=fanout_depth)
        gt = {i: true_consequence_weighted(est, i) for i in est.identities}
        gt_vec = np.array([gt[i] for i in est.identities])
        scores = score_all(est)

        order_by_method = {}
        for m in methods:
            sv = np.array([scores[m][i] for i in est.identities])
            rho = spearmanr(sv, gt_vec).correlation
            tau = kendalltau(sv, gt_vec).correlation
            agg[m]["rho"].append(rho if rho == rho else 0.0)
            agg[m]["tau"].append(tau if tau == tau else 0.0)
            order = sorted(est.identities, key=lambda i: scores[m][i], reverse=True)
            order_by_method[m] = order
            for k, key in [(5, "5"), (10, "10"), (25, "25")]:
                agg[m][f"ndcg{k}"].append(ndcg_at_k(order, gt, k))
                agg[m][f"rec{k}"].append(recall_at_k(order, gt, k))

        for k in (5, 10, 25):
            jac_reachcrit_vs_full[k].append(
                jaccard_topk(order_by_method["ReachCrit"],
                             order_by_method["IBR-full"], k))

    return agg, jac_reachcrit_vs_full


def summarize(agg):
    rows = []
    for m, d in agg.items():
        rows.append((m,
                     np.mean(d["rho"]), np.std(d["rho"]),
                     np.mean(d["tau"]), np.std(d["tau"]),
                     np.mean(d["ndcg10"]), np.std(d["ndcg10"]),
                     np.mean(d["rec10"]), np.std(d["rec10"])))
    return rows


if __name__ == "__main__":
    agg, jac = run()
    rows = summarize(agg)
    print(f"{'Method':<15}{'Spearman':<16}{'Kendall':<16}{'NDCG@10':<16}{'Recall@10':<16}")
    print("-" * 79)
    for (m, rho, rho_s, tau, tau_s, n10, n10s, r10, r10s) in rows:
        print(f"{m:<15}{rho:.3f}\u00b1{rho_s:.3f}    {tau:.3f}\u00b1{tau_s:.3f}    "
              f"{n10:.3f}\u00b1{n10s:.3f}    {r10:.3f}\u00b1{r10s:.3f}")
    print()
    print("Top-k agreement between ReachCrit and IBR-full (Jaccard):")
    for k in (5, 10, 25):
        v = jac[k]
        print(f"  top-{k}: {np.mean(v):.3f} \u00b1 {np.std(v):.3f}  "
              f"(they disagree on ~{(1-np.mean(v))*100:.0f}% of the set)")
