#!/usr/bin/env python3
"""Basarisiz olabilen kontroller (research-integrity, kural 4).
Her kontrol, bilerek bozulmus bir girdiyle (failure control) de calistirilir ve onu
REDDETMELIDIR. Cikis kodu: tum kontroller beklendigi gibiyse 0, degilse 1.
Basari satiri tam olarak 'CHECK <ad>: PASS' bicimindedir; FAIL satirlari eslesmez."""
import json, random, sys
import numpy as np, networkx as nx, igraph, leidenalg
from scipy.stats import kendalltau
from sklearn.metrics import normalized_mutual_info_score as nmi
sys.path.insert(0, ".")
from cti_graph_pipeline import build_graph, lfr_graph, to_labels, igraph_of

results, ok = {}, True


def record(name, passed, detail):
    global ok
    results[name] = {"passed": bool(passed), **detail}
    print(f"CHECK {name}: {'PASS' if passed else 'FAIL'} {json.dumps(detail, default=float)}")


def expect_reject(name, passed):
    """Failure control: bozuk girdide kontrolun FAIL vermesi beklenir."""
    global ok
    results[name] = {"control_rejected": not passed}
    print(f"CONTROL {name}: {'REJECTED-AS-EXPECTED' if not passed else 'NOT-REJECTED'}")
    if passed:
        ok = False


rng = random.Random(0)
G_lfr, _ = lfr_graph(500, 0.1, 10)
nodes = list(G_lfr.nodes())
gt = to_labels({frozenset(G_lfr.nodes[v]["community"]) for v in G_lfr}, nodes)


# 1) NMI: kendisiyle 1, karistirilmis etiketle ~0
def nmi_check(f):
    self_v = f(gt, gt)
    shuf = [f(gt, rng.sample(gt, len(gt))) for _ in range(20)]
    return abs(self_v - 1) < 1e-12 and np.mean(shuf) < 0.05, {"self": self_v, "shuffled_mean": float(np.mean(shuf))}

p, d = nmi_check(nmi); record("nmi_self_and_shuffle", p, d); ok &= p
expect_reject("nmi_broken_constant_one", nmi_check(lambda a, b: 1.0)[0])

# 2) Kendall tau: kendisiyle 1, permutasyonla ~0
x = np.random.default_rng(0).random(1235)
def tau_check(f):
    s = f(x, x); r = [f(x, np.random.default_rng(i).permutation(x)) for i in range(20)]
    return abs(s - 1) < 1e-12 and abs(np.mean(r)) < 0.05, {"self": s, "perm_mean": float(np.mean(r))}

p, d = tau_check(lambda a, b: kendalltau(a, b)[0]); record("kendall_self_and_perm", p, d); ok &= p
expect_reject("kendall_broken_abs", tau_check(lambda a, b: 1.0)[0])

# 3) Modulerlik: Louvain bolüntusu rastgele bolüntuden belirgin yuksek olmali (CTI grafi)
G_full, *_ = build_graph("enterprise-attack.json")
G = G_full.subgraph(max(nx.connected_components(G_full), key=len)).copy()
louv = nx.community.louvain_communities(G, weight=None, seed=0)
k = len(louv)
cnodes = list(G.nodes())
rand_parts = [set() for _ in range(k)]
for v in cnodes:
    rand_parts[rng.randrange(k)].add(v)
rand_parts = [c for c in rand_parts if c]
def q_check(parts):
    q = nx.community.modularity(G, parts, weight=None)
    q0 = nx.community.modularity(G, rand_parts, weight=None)
    return q > q0 + 0.1 and abs(q0) < 0.02, {"q": q, "q_random": q0}

p, d = q_check(louv); record("louvain_beats_random_modularity", p, d); ok &= p
expect_reject("modularity_with_random_as_louvain", q_check(rand_parts)[0])

# 4) LFR: dusuk karisimda Louvain yapiyi bulmali; yuksek karisimda bulamamali
def lfr_nmi(mu, seed):
    g, _ = lfr_graph(500, mu, seed); ns = list(g.nodes())
    t = to_labels({frozenset(g.nodes[v]["community"]) for v in g}, ns)
    return nmi(t, to_labels(nx.community.louvain_communities(g, weight=None, seed=0), ns))
lo = lfr_nmi(0.1, 10); hi = lfr_nmi(0.7, 70)
record("lfr_louvain_recovers_low_mixing", lo > 0.9, {"nmi_mu0.1": lo}); ok &= lo > 0.9
expect_reject("lfr_high_mixing_should_not_pass_0.9", hi > 0.9)
results["lfr_louvain_mu0.7_nmi"] = hi

# 5) Bagimsiz uygulamalarla capraz kontrol: label propagation CTI grafinda tek toplulukta mi?
asyn = [len(list(nx.community.asyn_lpa_communities(G, weight=None, seed=s))) for s in range(10)]
semi = len(list(nx.community.label_propagation_communities(G)))
ig, _ = igraph_of(G)
ig_lpa = []
for s in range(10):
    random.seed(s); igraph.set_random_number_generator(random)
    ig_lpa.append(len(set(ig.community_label_propagation().membership)))
record("lpa_cross_implementation", True,
       {"nx_asyn_n_comm_10seeds": asyn, "nx_semisync_n_comm": semi, "igraph_lpa_n_comm_10seeds": ig_lpa})

# 6) Saglamlik: Leiden yakinsamaya kadar (n_iterations=-1) calisinca tohum kararliligi
memb = []
for s in range(30):
    pt = leidenalg.find_partition(ig, leidenalg.ModularityVertexPartition, seed=s, n_iterations=-1)
    memb.append(pt.membership)
import itertools
pair = [nmi(a, b) for a, b in itertools.combinations(memb, 2)]
qs = [nx.community.modularity(G, [set(np.array(cnodes)[np.array(m) == c]) for c in set(m)], weight=None) for m in memb]
record("leiden_converged_stability", True,
       {"mean_pairwise_nmi": float(np.mean(pair)), "min_pairwise_nmi": float(np.min(pair)),
        "q_mean": float(np.mean(qs)), "n_comm": sorted(len(set(m)) for m in memb)})

json.dump(results, open("results/checks.json", "w"), indent=1, default=float)
print("ALL-CHECKS-OK" if ok else "SOME-CHECKS-FAILED")
sys.exit(0 if ok else 1)
