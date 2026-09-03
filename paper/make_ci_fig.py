"""Confidentiality-compromise figure: measured exfiltration vs predictions.
Numbers from ci_experiment.py (real reads on kind-co-spike, 2026-09-03)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# identity, measured Sum-sensitivity, IBR-rbac, dep-only, is_misconfig
rows = [
    ("frontend", 6.23, 6.23, 6.23, False),
    ("checkout", 5.43, 5.43, 5.43, False),
    ("recommendation", 2.55, 2.55, 0.90, True),
    ("cart", 1.65, 1.65, 1.65, False),
    ("ad", 1.18, 1.18, 0.20, True),
    ("email", 1.50, 1.50, 0.55, True),
    ("payment", 0.98, 0.98, 0.98, False),
    ("redis-cart", 0.95, 0.95, 0.95, False),
    ("productcatalog", 0.60, 0.60, 0.60, False),
    ("shipping", 0.50, 0.50, 0.50, False),
    ("currency", 0.40, 0.40, 0.40, False),
]
labels = [r[0] for r in rows]
meas = [r[1] for r in rows]
dep = [r[3] for r in rows]
mis = [r[4] for r in rows]

x = np.arange(len(rows)); w = 0.38
fig, ax = plt.subplots(figsize=(8.2, 3.9))
ax.bar(x - w/2, dep,  w, label="dependency-graph only ($\\rho$=0.691)", color="#c0c0c0", edgecolor="black", linewidth=0.5)
ax.bar(x + w/2, meas, w, label="MEASURED exfiltration (real reads)", color="#1f4e79", edgecolor="black", linewidth=0.5)
ax.plot(x, meas, ' ')
ax.set_ylabel("confidentiality blast radius\n($\\Sigma$ sensitivity of exfiltrated secrets)")
ax.set_title("Real credential-compromise: measured exfiltration vs. dependency-only prediction")
ax.set_xticks(x); ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=8.5)
ax.legend(fontsize=9, loc="upper right")
for i, m in enumerate(mis):
    if m:
        ax.annotate("misconfig\nmissed", (x[i]+w/2, meas[i]+0.12), ha="center", fontsize=7.5, color="#a00000")
plt.tight_layout()
plt.savefig("figures/fig_ci_compromise.png", dpi=130)
print("wrote figures/fig_ci_compromise.png")
