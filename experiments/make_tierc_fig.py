"""Figure for the REAL fault-injection experiment (Online Boutique on kind).
Per service: MEASURED broken flows vs naive-graph prediction vs confidence-aware
prediction -- visualizing that the static graph over-predicts on gracefully
degrading dependencies while the confidence-aware model matches observed reality.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import csv
from analyze_tierc_real import FLOWS, REQUIRED, OPTIONAL, SERVICES, broken

CSV = "/tmp/tierc_real_v6.csv"
rows = {}
with open(CSV) as f:
    for r in csv.DictReader(f):
        rows[r["service"]] = r
services = [s for s in SERVICES if s in rows and s != "baseline"]

meas = [len({fl for fl in FLOWS if broken(rows[s][fl])}) for s in services]
preq = [len({fl for fl in FLOWS if s in REQUIRED[fl]}) for s in services]
pnv  = [len({fl for fl in FLOWS if s in REQUIRED[fl] or s in OPTIONAL.get(fl, set())}) for s in services]

short = [s.replace("service", "") for s in services]
x = np.arange(len(services)); w = 0.27
fig, ax = plt.subplots(figsize=(9.0, 4.2))
ax.bar(x - w, pnv,  w, label="naive static graph (all edges)", color="#c0c0c0", edgecolor="black", linewidth=0.5)
ax.bar(x,     preq, w, label="confidence-aware prediction",   color="#f0a030", edgecolor="black", linewidth=0.5)
ax.bar(x + w, meas, w, label="MEASURED (real fault injection)", color="#1f4e79", edgecolor="black", linewidth=0.5)
ax.set_ylabel("user-facing flows broken (of 5)")
ax.set_title("Real Online Boutique: measured blast radius vs. prediction (scale-to-zero fault injection)")
ax.set_xticks(x); ax.set_xticklabels(short, rotation=25, ha="right", fontsize=9)
ax.legend(fontsize=9, loc="upper right")
ax.set_ylim(0, 5.6)
# annotate the graceful-degradation gap
for i, s in enumerate(services):
    if meas[i] == 0 and pnv[i] > 0:
        ax.annotate("graceful", (x[i], pnv[i] + 0.15), ha="center", fontsize=8, color="#a00000")
plt.tight_layout()
plt.savefig("fig_tierc_real.png", dpi=130)
print("wrote fig_tierc_real.png")
print("services:", short)
print("measured:", meas)
print("conf-aware pred:", preq)
print("naive pred:", pnv)
