#!/usr/bin/env python3
"""
Siber Tehdit Istihbaratinda Graf Analizi: merkezilik olcutleri ve topluluk tespit
algoritmalarinin karsilastirilmasi (MITRE ATT&CK Enterprise STIX 2.1).

Kullanim:
    python cti_graph_pipeline.py --stix enterprise-attack.json --out results --seeds 30
    python cti_graph_pipeline.py ... --anonymize   # dugum kimliklerini tuzlu SHA-256 ile takma adlandirir

Tum sayilar results/*.json ve results/*.csv dosyalarina yazilir; bildiri metnindeki her
sayi bu dosyalardaki adlandirilmis bir alandan kopyalanmalidir.
"""
import argparse, hashlib, itertools, json, platform, random, sys, time
from collections import Counter, defaultdict

import networkx as nx
import numpy as np
import pandas as pd
from scipy.stats import kendalltau, spearmanr
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
import igraph, leidenalg, sklearn, scipy

GROUP, SOFT, TECH = "group", "software", "technique"


# ----------------------------------------------------------------------------- veri
def attack_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def is_valid(o):
    return not o.get("revoked", False) and not o.get("x_mitre_deprecated", False)


def build_graph(stix_path):
    bundle = json.load(open(stix_path, encoding="utf-8"))
    objs = bundle["objects"]
    meta = {}
    for o in objs:
        if o["type"] == "x-mitre-collection":
            meta = {"collection": o.get("name"), "version": o.get("x_mitre_version"),
                    "modified": o.get("modified")}
    parent_name = {}
    for o in objs:  # ana teknik adlari
        if o["type"] == "attack-pattern" and is_valid(o):
            aid = attack_id(o)
            if aid and "." not in aid:
                parent_name[aid] = o.get("name")
    node_of = {}  # stix id -> (anahtar, tip, ad)
    dropped = Counter()
    for o in objs:
        t = o["type"]
        if t not in ("intrusion-set", "malware", "tool", "attack-pattern"):
            continue
        if not is_valid(o):
            dropped[t] += 1
            continue
        aid = attack_id(o)
        if aid is None:
            dropped[t + "_noid"] += 1
            continue
        if t == "intrusion-set":
            node_of[o["id"]] = (aid, GROUP, o.get("name"))
        elif t in ("malware", "tool"):
            node_of[o["id"]] = (aid, SOFT, o.get("name"))
        else:  # alt teknikler ana teknige indirgenir: T1059.001 -> T1059
            key = aid.split(".")[0]
            node_of[o["id"]] = (key, TECH, parent_name.get(key, o.get("name")))
    G = nx.Graph()
    rel_used = Counter()
    for o in objs:
        if o["type"] != "relationship" or o.get("relationship_type") != "uses":
            continue
        if not is_valid(o):
            rel_used["skipped_invalid_rel"] += 1
            continue
        s, d = node_of.get(o["source_ref"]), node_of.get(o["target_ref"])
        if s is None or d is None:
            rel_used["skipped_endpoint_missing"] += 1  # kampanyalar dahil degil
            continue
        if {s[1], d[1]} not in ({GROUP, SOFT}, {GROUP, TECH}, {SOFT, TECH}) or s[0] == d[0]:
            rel_used["skipped_pair_type"] += 1
            continue
        for k, typ, name in (s, d):
            G.add_node(k, kind=typ, name=name)
        if G.has_edge(s[0], d[0]):
            G[s[0]][d[0]]["n_rel"] += 1
        else:
            G.add_edge(s[0], d[0], n_rel=1)
        rel_used["used_" + "-".join(sorted([s[1], d[1]]))] += 1
    return G, meta, dict(dropped), dict(rel_used)


def graph_stats(G):
    kinds = Counter(nx.get_node_attributes(G, "kind").values())
    return {"n_nodes": G.number_of_nodes(), "n_edges": G.number_of_edges(),
            "density": nx.density(G), "n_components": nx.number_connected_components(G),
            "nodes_by_kind": dict(kinds),
            "avg_clustering": nx.average_clustering(G)}


# ----------------------------------------------------------------------------- merkezilik
def centralities(G):
    out, times = {}, {}
    funcs = {
        "degree": lambda g: nx.degree_centrality(g),
        "betweenness": lambda g: nx.betweenness_centrality(g, normalized=True),
        "closeness": lambda g: nx.closeness_centrality(g),
        "eigenvector": lambda g: nx.eigenvector_centrality(g, max_iter=2000, tol=1e-10),
        "pagerank": lambda g: nx.pagerank(g, alpha=0.85, tol=1e-10),
    }
    for name, f in funcs.items():
        t0 = time.perf_counter()
        out[name] = f(G)
        times[name] = time.perf_counter() - t0
    return out, times


def topk(scores, nodes, k):
    return [v for v in sorted(nodes, key=lambda v: (-scores[v], v))[:k]]


def compare_centralities(G, C, k=20):
    names = list(C)
    rows = []
    subsets = {"all": list(G.nodes()),
               "groups": [v for v, d in G.nodes(data=True) if d["kind"] == GROUP]}
    for subset, nodes in subsets.items():
        for a, b in itertools.combinations(names, 2):
            x = [C[a][v] for v in nodes]
            y = [C[b][v] for v in nodes]
            tau, p_tau = kendalltau(x, y)
            rho, p_rho = spearmanr(x, y)
            ta, tb = set(topk(C[a], nodes, k)), set(topk(C[b], nodes, k))
            rows.append({"subset": subset, "n": len(nodes), "a": a, "b": b,
                         "kendall_tau_b": tau, "kendall_p": p_tau,
                         "spearman_rho": rho, "spearman_p": p_rho,
                         f"top{k}_jaccard": len(ta & tb) / len(ta | tb)})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- topluluk
def to_labels(parts, nodes):
    lab = {}
    for i, c in enumerate(parts):
        for v in c:
            lab[v] = i
    return [lab[v] for v in nodes]


def run_algorithm(name, G, seed, ig=None, nodes=None):
    t0 = time.perf_counter()
    if name == "louvain":
        parts = nx.community.louvain_communities(G, weight=None, resolution=1, seed=seed)
    elif name == "leiden":
        p = leidenalg.find_partition(ig, leidenalg.ModularityVertexPartition, seed=seed)
        groups = defaultdict(set)
        for i, c in enumerate(p.membership):
            groups[c].add(nodes[i])
        parts = list(groups.values())
    elif name == "greedy_modularity":
        parts = nx.community.greedy_modularity_communities(G, weight=None)
    elif name == "label_propagation":
        parts = list(nx.community.asyn_lpa_communities(G, weight=None, seed=seed))
    else:
        raise ValueError(name)
    dt = time.perf_counter() - t0
    parts = [set(c) for c in parts]
    return parts, dt


ALGOS = ["louvain", "leiden", "greedy_modularity", "label_propagation"]
DETERMINISTIC = {"greedy_modularity"}


def igraph_of(G):
    nodes = list(G.nodes())
    idx = {v: i for i, v in enumerate(nodes)}
    return igraph.Graph(n=len(nodes), edges=[(idx[u], idx[v]) for u, v in G.edges()]), nodes


def community_experiment(G, seeds):
    ig, nodes = igraph_of(G)
    runs = {a: [] for a in ALGOS}
    rows = []
    for a in ALGOS:
        for s in (range(1) if a in DETERMINISTIC else range(seeds)):
            parts, dt = run_algorithm(a, G, s, ig, nodes)
            q = nx.community.modularity(G, parts, weight=None)
            disc = sum(1 for c in parts if not nx.is_connected(G.subgraph(c)))
            sizes = sorted((len(c) for c in parts), reverse=True)
            runs[a].append(to_labels(parts, nodes))
            rows.append({"algorithm": a, "seed": s, "modularity": q, "n_communities": len(parts),
                         "largest_frac": sizes[0] / len(nodes), "n_singletons": sum(1 for x in sizes if x == 1),
                         "n_disconnected": disc, "runtime_s": dt})
    per_run = pd.DataFrame(rows)
    # tohum kararliligi: ayni algoritmanin calistirmalari arasi ortalama NMI
    stab = []
    for a in ALGOS:
        labs = runs[a]
        if len(labs) < 2:
            stab.append({"algorithm": a, "n_runs": len(labs), "mean_pairwise_nmi": 1.0,
                         "min_pairwise_nmi": 1.0, "note": "deterministic"})
            continue
        vals = [normalized_mutual_info_score(x, y) for x, y in itertools.combinations(labs, 2)]
        stab.append({"algorithm": a, "n_runs": len(labs), "mean_pairwise_nmi": float(np.mean(vals)),
                     "min_pairwise_nmi": float(np.min(vals)), "note": ""})
    # algoritmalar arasi uyum: i. calistirma ile i. calistirma eslenir
    agree = []
    for a, b in itertools.combinations(ALGOS, 2):
        n = max(len(runs[a]), len(runs[b]))
        nmis, aris = [], []
        for i in range(n):
            x = runs[a][min(i, len(runs[a]) - 1)]
            y = runs[b][min(i, len(runs[b]) - 1)]
            nmis.append(normalized_mutual_info_score(x, y))
            aris.append(adjusted_rand_score(x, y))
        agree.append({"a": a, "b": b, "n_pairs": n, "mean_nmi": float(np.mean(nmis)),
                      "mean_ari": float(np.mean(aris))})
    return per_run, pd.DataFrame(stab), pd.DataFrame(agree), runs, nodes


# ----------------------------------------------------------------------------- LFR kontrol
def lfr_graph(n, mu, seed):
    last = None
    for s in range(seed, seed + 20):
        try:
            G = nx.LFR_benchmark_graph(n, 3, 1.5, mu, average_degree=10, max_degree=50,
                                       min_community=20, max_community=100, seed=s)
            G.remove_edges_from(list(nx.selfloop_edges(G)))
            return G, s
        except Exception as e:  # LFR uretimi bazen yakinsamaz
            last = e
    raise RuntimeError(f"LFR uretilemedi mu={mu}: {last}")


def lfr_experiment(mus, reps, n=500):
    rows = []
    for mu in mus:
        for r in range(reps):
            G, used_seed = lfr_graph(n, mu, 1000 * r + int(mu * 100))
            nodes = list(G.nodes())
            gt_parts = {frozenset(G.nodes[v]["community"]) for v in G}
            gt = to_labels(gt_parts, nodes)
            ig, _ = igraph_of(G)
            for a in ALGOS:
                parts, dt = run_algorithm(a, G, r, ig, nodes)
                lab = to_labels(parts, nodes)
                rows.append({"mu": mu, "rep": r, "lfr_seed": used_seed, "algorithm": a,
                             "nmi_vs_truth": normalized_mutual_info_score(gt, lab),
                             "ari_vs_truth": adjusted_rand_score(gt, lab),
                             "n_found": len(parts), "n_true": len(gt_parts), "runtime_s": dt})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- ana akis
def pseudonym(salt):
    return lambda v: "N" + hashlib.sha256((salt + str(v)).encode()).hexdigest()[:10]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", required=True)
    ap.add_argument("--out", default="results")
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--lfr-reps", type=int, default=5)
    ap.add_argument("--anonymize", action="store_true")
    ap.add_argument("--salt", default="sutis2026")
    args = ap.parse_args()
    import os
    os.makedirs(args.out, exist_ok=True)
    random.seed(0); np.random.seed(0)

    sha = hashlib.sha256(open(args.stix, "rb").read()).hexdigest()
    G_full, meta, dropped, rel_used = build_graph(args.stix)
    lcc = max(nx.connected_components(G_full), key=len)
    G = G_full.subgraph(lcc).copy()
    info = {"input_sha256": sha, "attack": meta, "dropped_objects": dropped,
            "relationships": rel_used, "graph_full": graph_stats(G_full), "graph_lcc": graph_stats(G),
            "versions": {"python": platform.python_version(), "networkx": nx.__version__,
                         "igraph": igraph.__version__, "leidenalg": leidenalg.__version__,
                         "scikit_learn": sklearn.__version__, "scipy": scipy.__version__,
                         "pandas": pd.__version__},
            "settings": {"seeds": args.seeds, "lfr_reps": args.lfr_reps, "weights": "unweighted",
                         "subtechniques": "collapsed to parent", "campaigns": "excluded",
                         "leiden_n_iterations": "leidenalg default", "louvain_resolution": 1}}
    print(json.dumps(info["graph_lcc"], indent=1))

    C, ctimes = centralities(G)
    info["centrality_runtime_s"] = ctimes
    cmp_df = compare_centralities(G, C, k=20)
    name = pseudonym(args.salt) if args.anonymize else (lambda v: v)
    cdf = pd.DataFrame({m: C[m] for m in C})
    cdf.insert(0, "kind", [G.nodes[v]["kind"] for v in cdf.index])
    cdf.insert(1, "name", [G.nodes[v]["name"] if not args.anonymize else "" for v in cdf.index])
    cdf.index = [name(v) for v in cdf.index]
    cdf.to_csv(f"{args.out}/centrality_scores.csv", index_label="node")
    cmp_df.to_csv(f"{args.out}/centrality_agreement.csv", index=False)
    tops = []
    for subset in ("all", "groups"):
        nodes = list(G.nodes()) if subset == "all" else [v for v, d in G.nodes(data=True) if d["kind"] == GROUP]
        for m in C:
            for r, v in enumerate(topk(C[m], nodes, 10), 1):
                tops.append({"subset": subset, "measure": m, "rank": r, "node": name(v),
                             "kind": G.nodes[v]["kind"],
                             "name": "" if args.anonymize else G.nodes[v]["name"], "score": C[m][v]})
    pd.DataFrame(tops).to_csv(f"{args.out}/centrality_top10.csv", index=False)

    per_run, stab, agree, _, _ = community_experiment(G, args.seeds)
    per_run.to_csv(f"{args.out}/community_runs.csv", index=False)
    stab.to_csv(f"{args.out}/community_stability.csv", index=False)
    agree.to_csv(f"{args.out}/community_agreement.csv", index=False)
    summary = per_run.groupby("algorithm").agg(
        runs=("seed", "count"), modularity_mean=("modularity", "mean"), modularity_std=("modularity", "std"),
        n_comm_mean=("n_communities", "mean"), n_comm_min=("n_communities", "min"),
        n_comm_max=("n_communities", "max"), largest_frac_mean=("largest_frac", "mean"),
        disconnected_mean=("n_disconnected", "mean"), runs_with_disconnected=("n_disconnected", lambda s: int((s > 0).sum())),
        runtime_mean_s=("runtime_s", "mean")).reset_index()
    summary.to_csv(f"{args.out}/community_summary.csv", index=False)

    lfr = lfr_experiment([0.1, 0.2, 0.3, 0.4, 0.5, 0.6], args.lfr_reps)
    lfr.to_csv(f"{args.out}/lfr_runs.csv", index=False)
    lfr.groupby(["mu", "algorithm"]).agg(nmi_mean=("nmi_vs_truth", "mean"), nmi_std=("nmi_vs_truth", "std"),
                                         ari_mean=("ari_vs_truth", "mean")).reset_index().to_csv(
        f"{args.out}/lfr_summary.csv", index=False)

    json.dump(info, open(f"{args.out}/run_info.json", "w"), indent=1, default=str)
    print("DONE")


if __name__ == "__main__":
    main()
