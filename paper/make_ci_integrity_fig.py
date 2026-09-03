"""Combined confidentiality + integrity compromise figure (2 panels, full width).
Numbers from ci_experiment.py and integrity_experiment.py (real reads/writes on
kind-co-spike, 2026-09-03)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 13})

# (label, measured, dep-only, is_misconfig)
conf = [
    ("frontend", 6.23, 6.23, False), ("checkout", 5.43, 5.43, False),
    ("recommend", 2.55, 0.90, True), ("cart", 1.65, 1.65, False),
    ("ad", 1.18, 0.20, True), ("email", 1.50, 0.55, True),
    ("payment", 0.98, 0.98, False), ("redis-cart", 0.95, 0.95, False),
    ("productcat", 0.60, 0.60, False), ("shipping", 0.50, 0.50, False),
    ("currency", 0.40, 0.40, False),
]
integ = [
    ("ad", 6.0, 2.5, True), ("recommend", 5.0, 2.5, True), ("email", 5.0, 4.0, True),
    ("productcat", 5.0, 5.0, False), ("redis-cart", 5.0, 5.0, False),
    ("cart", 4.0, 4.0, False), ("currency", 4.0, 4.0, False),
    ("payment", 4.0, 4.0, False), ("shipping", 4.0, 4.0, False),
    ("checkout", 3.0, 3.0, False), ("frontend", 1.5, 1.5, False),
]

def panel(ax, rows, title, rho_dep):
    labels = [r[0] for r in rows]; meas = [r[1] for r in rows]; dep = [r[2] for r in rows]
    mis = [r[3] for r in rows]
    x = np.arange(len(rows)); w = 0.4
    ax.bar(x - w/2, dep,  w, label=f"dependency-graph only ($\\rho$={rho_dep})", color="#c0c0c0", edgecolor="black", linewidth=0.5)
    ax.bar(x + w/2, meas, w, label="MEASURED (real compromise)", color="#1f4e79", edgecolor="black", linewidth=0.5)
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=11)
    ax.set_title(title, fontsize=14)
    ax.legend(fontsize=11, loc="upper right")
    for i, m in enumerate(mis):
        if m:
            ax.annotate("misconfig\nmissed", (x[i]+w/2, meas[i]+0.15), ha="center", fontsize=9, color="#a00000")

fig, (a1, a2) = plt.subplots(1, 2, figsize=(13.5, 4.4))
panel(a1, conf, "Confidentiality: measured secret exfiltration", "0.691")
a1.set_ylabel("blast radius ($\\Sigma$ sensitivity)")
panel(a2, integ, "Integrity: measured corruption reach", "0.259")
a2.set_ylabel("blast radius (criticality-weighted)")
plt.tight_layout()
plt.savefig("figures/fig_ci_integrity.png", dpi=140)
print("wrote figures/fig_ci_integrity.png")
