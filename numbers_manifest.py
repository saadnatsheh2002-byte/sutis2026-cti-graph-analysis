#!/usr/bin/env python3
"""Bildiride kullanilan her sayiyi, uretildigi dosya ve alanla birlikte yazar (yuvarlama belirtilir)."""
import json, pandas as pd
R="results"; info=json.load(open(f"{R}/run_info.json")); chk=json.load(open(f"{R}/checks.json"))
a=pd.read_csv(f"{R}/centrality_agreement.csv"); s=pd.read_csv(f"{R}/community_summary.csv")
st=pd.read_csv(f"{R}/community_stability.csv"); ag=pd.read_csv(f"{R}/community_agreement.csv")
l=pd.read_csv(f"{R}/lfr_summary.csv"); t=pd.read_csv(f"{R}/centrality_top10.csv")
M={}
def put(k,v,src): M[k]={"value":v,"source":src}
g=info["graph_lcc"]
for k in ["n_nodes","n_edges","density","avg_clustering","n_components"]: put(f"graph.{k}",g[k],f"run_info.json:graph_lcc.{k}")
for k,v in g["nodes_by_kind"].items(): put(f"graph.nodes.{k}",v,"run_info.json:graph_lcc.nodes_by_kind")
put("attack.version",info["attack"]["version"],"run_info.json:attack.version"); put("attack.modified",info["attack"]["modified"],"run_info.json:attack.modified")
put("input.sha256",info["input_sha256"],"run_info.json:input_sha256")
for k,v in info["relationships"].items(): put(f"rel.{k}",v,"run_info.json:relationships")
for k,v in info["centrality_runtime_s"].items(): put(f"runtime.centrality.{k}",v,"run_info.json:centrality_runtime_s")
for r in a.itertuples(): put(f"tau.{r.subset}.{r.a}-{r.b}",r.kendall_tau_b,"centrality_agreement.csv:kendall_tau_b"); put(f"rho.{r.subset}.{r.a}-{r.b}",r.spearman_rho,"centrality_agreement.csv:spearman_rho"); put(f"top20J.{r.subset}.{r.a}-{r.b}",r.top20_jaccard,"centrality_agreement.csv:top20_jaccard")
for r in s.itertuples():
    for c in ["runs","modularity_mean","modularity_std","n_comm_mean","n_comm_min","n_comm_max","largest_frac_mean","disconnected_mean","runs_with_disconnected","runtime_mean_s"]:
        put(f"comm.{r.algorithm}.{c}",getattr(r,c),f"community_summary.csv:{c}")
for r in st.itertuples(): put(f"stab.{r.algorithm}.mean",r.mean_pairwise_nmi,"community_stability.csv:mean_pairwise_nmi"); put(f"stab.{r.algorithm}.min",r.min_pairwise_nmi,"community_stability.csv:min_pairwise_nmi")
for r in ag.itertuples(): put(f"agree.{r.a}-{r.b}.nmi",r.mean_nmi,"community_agreement.csv:mean_nmi"); put(f"agree.{r.a}-{r.b}.ari",r.mean_ari,"community_agreement.csv:mean_ari")
for r in l.itertuples(): put(f"lfr.mu{r.mu}.{r.algorithm}.nmi",r.nmi_mean,"lfr_summary.csv:nmi_mean")
put("check.leiden_converged.mean_nmi",chk["leiden_converged_stability"]["mean_pairwise_nmi"],"checks.json:leiden_converged_stability.mean_pairwise_nmi")
put("check.lpa_cross",chk["lpa_cross_implementation"],"checks.json:lpa_cross_implementation")
put("check.controls_rejected",sum(1 for k,v in chk.items() if isinstance(v,dict) and v.get("control_rejected")),"checks.json:*.control_rejected")
for r in t[t['rank']<=5].itertuples(): put(f"top.{r.subset}.{r.measure}.{r.rank}",f"{r.node} {r.name} {r.score}","centrality_top10.csv")
json.dump(M,open(f"{R}/numbers_manifest.json","w"),indent=1,default=str)
print(len(M),"entries")
