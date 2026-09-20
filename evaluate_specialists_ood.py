"""
evaluate_specialists_ood.py — Evaluates trained specialist models on hard Out-of-Distribution (OOD)
and evasion test suites.

Tests evaluated:
  - C2 Beaconing: Non-stationary burst-and-sleep, 60% high jitter, 35% missed callbacks, NTP hard negatives
  - Botnet GraphSAGE: Decentralized P2P mesh, 3-tier hierarchical tree, cluster gossip hard negatives
  - DNS GraphSAGE: Novel Base32 encoding tunnels, CDN prefetch hard negatives

Outputs metrics (Precision, Recall, F1, ROC-AUC, FPR) and degradation analysis.
"""
from __future__ import annotations
import json
from pathlib import Path
import joblib
import numpy as np
import torch

from agent1_observation_dns.simulation.specialist_ood_generators import (
    generate_c2_ood_corpus, generate_botnet_ood_corpus, generate_dns_ood_corpus
)
from agent2_detection_product.models.c2_periodicity import periodicity
from agent2_detection_product.models.c2_temporal_tcn_gru import TemporalCandidate
from agent2_detection_product.models.c2_fusion import C2Fusion
from agent2_detection_product.models.botnet_gnn import GraphSAGE
from agent2_detection_product.models.providers import graph_arrays
from agent1_observation_dns.models.dns_tunnel_graphsage.model import GraphBranch

ROOT = Path(__file__).resolve().parent


def compute_metrics(scores, targets, threshold=0.5):
    from sklearn.metrics import roc_auc_score
    scores, targets = np.asarray(scores, float), np.asarray(targets, int)
    preds = (scores >= threshold).astype(int)
    tp = int(((preds == 1) & (targets == 1)).sum())
    fp = int(((preds == 1) & (targets == 0)).sum())
    fn = int(((preds == 0) & (targets == 1)).sum())
    tn = int(((preds == 0) & (targets == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * tp / max(2 * tp + fp + fn, 1)
    fpr       = fp / max(fp + tn, 1)
    try:
        auc = float(roc_auc_score(targets, scores)) if len(np.unique(targets)) > 1 else (1.0 if tp > 0 else 0.0)
    except Exception:
        auc = 1.0 if tp > 0 else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4), "roc_auc": round(auc, 4)
    }


def eval_c2_ood(specialists_dir: Path):
    print("Evaluating C2 Beaconing on OOD suites...", flush=True)
    cthmm = joblib.load(specialists_dir / "cthmm.pkl")
    gru = TemporalCandidate(features=2, kind="gru", hidden=32)
    gru.load_state_dict(torch.load(specialists_dir / "temporal_gru.pt", weights_only=True))
    gru.eval()
    from xgboost import XGBClassifier
    fusion = C2Fusion()
    c2_xgb = XGBClassifier()
    c2_xgb.load_model(str(specialists_dir / "c2_fusion.json"))
    fusion.models = {"C2_BEACONING": c2_xgb}
    calibrator = joblib.load(specialists_dir / "c2_calibrator.pkl")

    def seq_to_tensor(ts, max_len=50):
        gaps = np.diff(ts).astype(float)
        gaps = gaps[gaps > 0]
        if len(gaps) == 0:
            gaps = np.array([1.0])
        log_gaps = np.log1p(gaps).astype(np.float32)
        seq = np.column_stack([log_gaps, np.ones(len(log_gaps), dtype=np.float32)])
        if len(seq) >= max_len:
            return seq[:max_len], max_len
        pad_rows = max_len - len(seq)
        return np.vstack([seq, np.zeros((pad_rows, seq.shape[1]), dtype=np.float32)]), len(seq)

    def score_c2(ts):
        ev = periodicity(ts)
        gaps = np.diff(ts)
        gaps = gaps[gaps > 0]
        if len(gaps) < 3:
            return 0.0
        try:
            ll = cthmm.log_likelihood(gaps.tolist()) / max(len(gaps), 1)
        except Exception:
            ll = -10.0
        seq_pad, actual_len = seq_to_tensor(ts)
        with torch.no_grad():
            gru_score = float(torch.sigmoid(gru(torch.as_tensor(seq_pad[None]), torch.as_tensor([actual_len]))).item())
        features = [[
            ev.get("iat_cv", 1.0),
            ev.get("iat_mad", 1.0),
            ev.get("spectral_concentration", 0.0),
            ev.get("lag1_autocorrelation", 0.0),
            ll,
            gru_score
        ]]
        raw = fusion.predict(np.array(features))[0, 0]
        return float(calibrator.predict([raw])[0])

    corpus_suites = generate_c2_ood_corpus(n_samples=400)
    results = {}
    
    # Combined binary test
    all_scores, all_targets = [], []
    for suite_name, samples in corpus_suites.items():
        suite_scores = [score_c2(s["timestamps"]) for s in samples]
        suite_targets = [s["label"] for s in samples]
        all_scores.extend(suite_scores)
        all_targets.extend(suite_targets)
        # suite-level metrics
        if len(set(suite_targets)) == 1:
            lbl = suite_targets[0]
            if lbl == 1:
                # Attack recall
                detected = sum(sc >= 0.5 for sc in suite_scores)
                results[suite_name] = {
                    "count": len(samples),
                    "detected": detected,
                    "recall": round(detected / len(samples), 4),
                    "mean_score": round(float(np.mean(suite_scores)), 4)
                }
            else:
                # FPR on hard negatives
                false_alarms = sum(sc >= 0.5 for sc in suite_scores)
                results[suite_name] = {
                    "count": len(samples),
                    "false_alarms": false_alarms,
                    "fpr": round(false_alarms / len(samples), 4),
                    "mean_score": round(float(np.mean(suite_scores)), 4)
                }
    results["overall_binary"] = compute_metrics(all_scores, all_targets)
    return results


def eval_botnet_ood(specialists_dir: Path):
    print("Evaluating Botnet GNN on OOD suites...", flush=True)
    gnn = GraphSAGE(features=4, hidden=32, dimensions=32)
    gnn.load_state_dict(torch.load(specialists_dir / "botnet_gnn.pt", weights_only=True))
    gnn.eval()
    tree = joblib.load(specialists_dir / "botnet_tree.pkl")
    scaler = joblib.load(specialists_dir / "botnet_scaler.pkl")

    def eval_graph_suite(samples):
        embs, flows, tgts_host, tgts_coord = [], [], [], []
        for row in samples:
            edges_raw = row["edges"]
            node_labels_dict = row["node_labels"]
            edges = [(item[0], item[1], item[2] if len(item) > 2 else {"count": 5, "bytes": None}) for item in edges_raw]
            nodes, attributes, edge_index = graph_arrays(edges if edges else [(0, 0, {"count": 1, "bytes": None})])
            x = torch.as_tensor(attributes, dtype=torch.float32)
            e = torch.as_tensor(edge_index, dtype=torch.long)
            with torch.no_grad():
                emb = gnn.embed(x, e).numpy()
            for i, node in enumerate(nodes):
                embs.append(emb[i])
                flows.append(attributes[i])
                lbl = node_labels_dict.get(node, (0, 0))
                tgts_host.append(lbl[0])
                tgts_coord.append(lbl[1])
        if not embs:
            return {}
        flow_sc = scaler.transform(np.array(flows))
        preds = tree.predict(np.array(embs), flow_sc)
        return {
            "BOTNET_HOST": compute_metrics(preds[:, 0], tgts_host),
            "BOTNET_COORDINATION": compute_metrics(preds[:, 1], tgts_coord)
        }

    corpus_suites = generate_botnet_ood_corpus(n_samples=150)
    results = {}
    for suite_name, samples in corpus_suites.items():
        results[suite_name] = eval_graph_suite(samples)
    return results


def eval_dns_ood(specialists_dir: Path):
    print("Evaluating DNS GraphSAGE on OOD suites...", flush=True)
    branch = GraphBranch.load(specialists_dir / "dns_graphsage.pt")

    corpus_suites = generate_dns_ood_corpus(n_samples=100)
    results = {}
    for suite_name, samples in corpus_suites.items():
        scores, targets = [], []
        for row in samples:
            context = {
                "graph": {
                    "nodes": [f + [1.0] for f in row["node_features"]],
                    "edges": row["edges"],
                    "sufficient": len(row["edges"]) >= 2,
                }
            }
            res = branch.predict("ood-eval", None, context)
            if res.score_present:
                scores.append(res.probability)
                targets.append(row["graph_label"])
        results[suite_name] = {
            "count": len(samples),
            "mean_score": round(float(np.mean(scores)), 4) if scores else 0.0,
            "detected": sum(s >= 0.5 for s in scores) if targets and targets[0] == 1 else None,
            "false_alarms": sum(s >= 0.5 for s in scores) if targets and targets[0] == 0 else None
        }
    return results


def main():
    specialists_dir = ROOT / "artifacts/specialists/0.1.0-sim"
    if not specialists_dir.exists():
        raise FileNotFoundError(f"Specialist directory not found: {specialists_dir}")

    report = {
        "title": "Specialist Out-of-Distribution (OOD) & Evasion Robustness Benchmark",
        "checkpoint": str(specialists_dir),
        "c2_beaconing_ood": eval_c2_ood(specialists_dir),
        "botnet_graphsage_ood": eval_botnet_ood(specialists_dir),
        "dns_graphsage_ood": eval_dns_ood(specialists_dir),
    }

    out_json = ROOT / "artifacts/experiments/specialist_ood_benchmark.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nOOD Benchmark complete! Saved to {out_json}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
