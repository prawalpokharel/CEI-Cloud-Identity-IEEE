"""Generate figures for the runnable experiments."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from run_e2 import run as run_e2
from estate import generate_estate, true_consequence_weighted
from methods import score_all

plt.rcParams.update({"figure.dpi": 130, "font.size": 11})

# ---- Fig A: E2 ranking fidelity bar chart ----
agg, jac = run_e2(n_estates=40, n_identities=500)
methods = list(agg.keys())
rho = [np.mean(agg[m]["rho"]) for m in methods]
rho_s = [np.std(agg[m]["rho"]) for m in methods]
colors = ["#b0b0b0","#b0b0b0","#b0b0b0","#7f7f7f","#f0a030","#f0a030","#1f4e79"]

fig, ax = plt.subplots(figsize=(7.2, 4.0))
bars = ax.bar(methods, rho, yerr=rho_s, capsize=4, color=colors, edgecolor="black", linewidth=0.6)
ax.set_ylabel("Spearman $\\rho$ to ground-truth consequence")
ax.set_title("Ranking fidelity: reachability baselines vs. joined-graph method")
ax.set_ylim(0, 1.0)
ax.axhline(rho[3], ls="--", color="#7f7f7f", lw=1, alpha=0.7)
plt.xticks(rotation=20, ha="right")
for b_, v in zip(bars, rho):
    ax.text(b_.get_x()+b_.get_width()/2, v+0.02, f"{v:.2f}", ha="center", fontsize=9)
plt.tight_layout()
plt.savefig("fig_e2_ranking.png"); plt.close()

# ---- Fig B: recall@10 vs fanout depth ----
depths = [2, 3, 4, 5, 6]
methA = "ReachCrit"; methB = "IBR-full"
recA=[]; recB=[]; recAs=[]; recBs=[]
from run_e2 import recall_at_k
for d in depths:
    ra=[]; rb=[]
    for e in range(20):
        est = generate_estate(seed=20000+e, n_identities=500, fanout_depth=d)
        gt = {i: true_consequence_weighted(est,i) for i in est.identities}
        sc = score_all(est)
        oA = sorted(est.identities, key=lambda i: sc[methA][i], reverse=True)
        oB = sorted(est.identities, key=lambda i: sc[methB][i], reverse=True)
        ra.append(recall_at_k(oA, gt, 10)); rb.append(recall_at_k(oB, gt, 10))
    recA.append(np.mean(ra)); recAs.append(np.std(ra))
    recB.append(np.mean(rb)); recBs.append(np.std(rb))

fig, ax = plt.subplots(figsize=(6.6, 4.0))
ax.errorbar(depths, recA, yerr=recAs, marker="s", color="#7f7f7f", label="ReachCrit (best reachability)", capsize=3)
ax.errorbar(depths, recB, yerr=recBs, marker="o", color="#1f4e79", label="IBR-full (joined graph)", capsize=3)
ax.set_xlabel("Dependency fan-out depth")
ax.set_ylabel("Recall@10 (top-10 riskiest identities)")
ax.set_title("Reachability degrades as downstream structure grows")
ax.legend(); ax.set_ylim(0, 0.8)
plt.tight_layout(); plt.savefig("fig_e3_recall_vs_depth.png"); plt.close()

# ---- Fig C: disagreement scatter (ReachCrit rank vs GT rank) ----
est = generate_estate(seed=42, n_identities=500)
gt = {i: true_consequence_weighted(est,i) for i in est.identities}
sc = score_all(est)
ids = est.identities
def rankpos(m):
    order = sorted(ids, key=lambda i: m[i]); return {i:p for p,i in enumerate(order)}
gtr = rankpos(gt); rcr = rankpos(sc["ReachCrit"]); fr = rankpos(sc["IBR-full"])
fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharex=True, sharey=True)
for ax, (rr, name, col) in zip(axes, [(rcr,"ReachCrit","#7f7f7f"),(fr,"IBR-full","#1f4e79")]):
    x=[gtr[i] for i in ids]; y=[rr[i] for i in ids]
    ax.scatter(x,y,s=8,alpha=0.4,color=col)
    ax.plot([0,len(ids)],[0,len(ids)],ls="--",color="black",lw=1)
    ax.set_xlabel("Ground-truth risk rank"); ax.set_title(name)
axes[0].set_ylabel("Method risk rank")
fig.suptitle("Rank agreement with ground truth (points on diagonal = correct order)")
plt.tight_layout(); plt.savefig("fig_e3_scatter.png"); plt.close()

# ---- Fig D: E7 scale ----
from run_e7 import run as run_e7
rows = run_e7(sizes=(100,300,1000,3000,10000,30000,100000))
ns=[r[0] for r in rows]; sc_t=[r[3] for r in rows]
fig, ax = plt.subplots(figsize=(6.4,4.0))
ax.loglog(ns, sc_t, marker="o", color="#1f4e79")
ax.set_xlabel("Number of identities"); ax.set_ylabel("Score-all time, 7 methods (s)")
ax.set_title("Scaling: full method battery vs. identity count")
ax.grid(True, which="both", alpha=0.3)
plt.tight_layout(); plt.savefig("fig_e7_scale.png"); plt.close()

print("figures written:", "fig_e2_ranking.png fig_e3_recall_vs_depth.png fig_e3_scatter.png fig_e7_scale.png")
