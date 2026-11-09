#!/usr/bin/env python3
"""Bildiri sekilleri: results/ altindaki CSV'lerden uretilir (sayilar elle girilmez)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np, pandas as pd
from matplotlib import font_manager

serif = "Liberation Serif" if any("Liberation Serif" in f.name for f in font_manager.fontManager.ttflist) else "DejaVu Serif"
plt.rcParams.update({"font.family": serif, "font.size": 10, "figure.dpi": 300})
R = "results"
LBL = {"degree": "Derece", "betweenness": "Arasındalık", "closeness": "Yakınlık",
       "eigenvector": "Özvektör", "pagerank": "PageRank"}
ALG = {"louvain": "Louvain", "leiden": "Leiden", "greedy_modularity": "Açgözlü modülerlik (CNM)",
       "label_propagation": "Etiket yayılımı (LPA)"}

# Sekil 1: yontem akisi (2 satir x 3 kutu)
fig, ax = plt.subplots(figsize=(6.6, 3.0)); ax.axis("off")
steps = ["MITRE ATT&CK\nSTIX 2.1 (v20.1)", "Ayrıştırma ve filtreleme\n(iptal/eskimiş nesneler,\nalt teknik → ana teknik)",
         "Heterojen graf\n(grup–yazılım–teknik)", "Merkezilik\n(5 ölçüt)",
         "Topluluk tespiti\n(4 algoritma × 30 tohum)", "Karşılaştırma\nτ, ρ, top-20 Jaccard,\nNMI, ARI, Q"]
w, h = 0.26, 0.27
pos = [(0.03, 0.62), (0.37, 0.62), (0.71, 0.62), (0.71, 0.18), (0.37, 0.18), (0.03, 0.18)]
for (x0, y0), s in zip(pos, steps):
    ax.add_patch(FancyBboxPatch((x0, y0), w, h, boxstyle="round,pad=0.012", fc="#EAF0F8", ec="#4C72B0", lw=1))
    ax.text(x0 + w / 2, y0 + h / 2, s, ha="center", va="center", fontsize=8.5)
arrows = [((0.29, 0.755), (0.37, 0.755)), ((0.63, 0.755), (0.71, 0.755)), ((0.84, 0.62), (0.84, 0.45)),
          ((0.71, 0.315), (0.63, 0.315)), ((0.37, 0.315), (0.29, 0.315))]
for a0, a1 in arrows:
    ax.annotate("", xy=a1, xytext=a0, arrowprops=dict(arrowstyle="->", lw=1.1))
ax.text(0.5, 0.04, "Kontrol kolu: LFR sentetik graflar (μ = 0.1–0.6), bilinen topluluklarla NMI",
        ha="center", fontsize=8.5, style="italic")
ax.set_xlim(0, 1); ax.set_ylim(0, 1)
fig.savefig("fig1_pipeline.png", bbox_inches="tight"); plt.close(fig)

# Sekil 2: Kendall tau isi haritasi (tum dugumler ve yalniz gruplar)
a = pd.read_csv(f"{R}/centrality_agreement.csv")
names = list(LBL)
fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.1), gridspec_kw={"wspace": 0.08})
for ax, subset, title in zip(axes, ["all", "groups"], ["(a) Tüm düğümler (n = 1235)", "(b) Yalnız tehdit grupları (n = 178)"]):
    M = np.eye(len(names))
    s = a[a.subset == subset]
    for r in s.itertuples():
        i, j = names.index(r.a), names.index(r.b)
        M[i, j] = M[j, i] = r.kendall_tau_b
    im = ax.imshow(M, vmin=0, vmax=1, cmap="Blues")
    for i in range(len(names)):
        for j in range(len(names)):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center", fontsize=7.5,
                    color="white" if M[i, j] > 0.7 else "black")
    ax.set_xticks(range(len(names))); ax.set_yticks(range(len(names)))
    ax.set_xticklabels([LBL[n] for n in names], rotation=35, ha="right", fontsize=8)
    ax.set_yticklabels([LBL[n] for n in names] if subset == "all" else [], fontsize=8)
    ax.set_title(title, fontsize=9)
fig.colorbar(im, ax=axes, shrink=0.8, label="Kendall τ_b")
fig.savefig("fig2_kendall.png", bbox_inches="tight"); plt.close(fig)

# Sekil 3: LFR kontrol egrileri
l = pd.read_csv(f"{R}/lfr_summary.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.0))
for (alg, lab), mk, ls in zip(ALG.items(), ["o", "s", "^", "D"], ["-", "--", "-.", ":"]):
    s = l[l.algorithm == alg].sort_values("mu")
    ax.errorbar(s.mu, s.nmi_mean, yerr=s.nmi_std, marker=mk, ls=ls, ms=4, capsize=2, lw=1.2, label=lab)
ax.set_xlabel("Karışım parametresi μ"); ax.set_ylabel("Gerçek topluluklarla NMI")
ax.set_ylim(-0.03, 1.03); ax.spines[["top", "right"]].set_visible(False)
ax.legend(fontsize=7.5, frameon=False)
fig.savefig("fig3_lfr.png", bbox_inches="tight"); plt.close(fig)
print("figures written with font:", serif)
