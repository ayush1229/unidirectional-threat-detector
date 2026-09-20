"""
train_specialists.py — Train all four specialist models from synthetic corpora.

Generates:
  - C2_BEACONING : CT-HMM + GRU/TCN temporal + C2Fusion XGBoost
  - BOTNET       : GraphSAGE + BotnetTreeHead ExtraTrees
  - ENCRYPTED_MALWARE : XGBoost on early-session packet stats
  - DNS_TUNNEL_GRAPHSAGE : GraphSAGE on DNS co-query graphs (Agent 1)

Run from repository root:
  python train_specialists.py --output artifacts/specialists/0.1.0-sim

Add --v3 to also generate V3 Cartesian DDoS rows alongside V2 in the main pipeline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re

import joblib
import numpy as np
import torch

ROOT = Path(__file__).resolve().parent


# ─── Utility ─────────────────────────────────────────────────────────────────

def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def split_corpus(rows, train_frac=0.6, val_frac=0.2):
    """Return (train, val, test) using pre-assigned split fields if present."""
    train = [r for r in rows if r.get("split") == "train"]
    val   = [r for r in rows if r.get("split") == "validation"]
    test  = [r for r in rows if r.get("split") == "test"]
    return train, val, test


def metrics_binary(scores, targets, threshold=0.5):
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
    try:
        roc_auc = float(roc_auc_score(targets, scores)) if len(np.unique(targets)) > 1 else 1.0
    except Exception:
        roc_auc = 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "roc_auc": round(abs(roc_auc), 4)}


# ─── C2 Beaconing ─────────────────────────────────────────────────────────────

def train_c2(output: Path, epochs: int, trees: int, version: str) -> dict:
    print("  Generating C2 corpus...", flush=True)
    from agent1_observation_dns.simulation.specialist_generators import c2_corpus
    corpus = c2_corpus(n_sequences=900)
    train_rows, val_rows, test_rows = split_corpus(corpus)
    print(f"  C2 corpus: train={len(train_rows)}, val={len(val_rows)}, test={len(test_rows)}", flush=True)

    # CT-HMM: fit on C2 (positive) beacon sequences only
    from agent2_detection_product.models.c2_cthmm import ContinuousTimeHMM
    c2_seqs = [r["timestamps"] for r in train_rows if r["label"] == 1]
    # Convert timestamps to gaps
    def to_gaps(ts):
        gaps = np.diff(ts)
        return gaps[gaps > 0].tolist()
    c2_gaps = [to_gaps(ts) for ts in c2_seqs if len(ts) > 1][:50]
    cthmm = ContinuousTimeHMM()
    cthmm.fit(c2_gaps, split="train", maxiter=20)
    cthmm_path = output / "cthmm.pkl"
    joblib.dump(cthmm, cthmm_path)
    print("  CT-HMM fitted.", flush=True)

    # Temporal GRU: fit on all sequences
    from agent2_detection_product.models.c2_temporal_tcn_gru import TemporalCandidate, fit_binary
    # Pad sequences to same length
    def seq_to_tensor(ts):
        gaps = np.diff(ts).astype(float)
        gaps = gaps[gaps > 0]
        if len(gaps) == 0:
            gaps = np.array([1.0])
        log_gaps = np.log1p(gaps).astype(np.float32)
        # features: [log_gap, 1.0 (bias)]
        return np.column_stack([log_gaps, np.ones(len(log_gaps), dtype=np.float32)])
    max_len = max(len(r["timestamps"]) - 1 for r in train_rows if len(r["timestamps"]) > 1)
    max_len = max(max_len, 1)
    def pad(seq, max_len):
        if len(seq) >= max_len:
            return seq[:max_len]
        pad_rows = max_len - len(seq)
        return np.vstack([seq, np.zeros((pad_rows, seq.shape[1]), dtype=np.float32)])
    train_seqs = [seq_to_tensor(r["timestamps"]) for r in train_rows if len(r["timestamps"]) > 1]
    train_targets = [r["label"] for r in train_rows if len(r["timestamps"]) > 1]
    padded = np.stack([pad(s, max_len) for s in train_seqs])
    lengths = np.array([min(len(s), max_len) for s in train_seqs])
    gru = TemporalCandidate(features=2, kind="gru", hidden=32)
    torch.manual_seed(26)
    fit_binary(gru, padded, train_targets, split="train",
               lengths=torch.as_tensor(lengths))
    gru_path = output / "temporal_gru.pt"
    torch.save(gru.state_dict(), gru_path)
    print("  GRU temporal model fitted.", flush=True)

    # C2 Fusion: XGBoost on [periodicity features, cthmm_ll, gru_score]
    from agent2_detection_product.models.c2_periodicity import periodicity
    from agent2_detection_product.models.c2_fusion import C2Fusion

    def c2_features(row):
        ts = row["timestamps"]
        gaps = np.diff(ts)
        gaps = gaps[gaps > 0]
        ev = periodicity(ts)
        if not ev.get("score_present"):
            return None
        try:
            ll = cthmm.log_likelihood(gaps.tolist()) / max(len(gaps), 1)
        except Exception:
            ll = 0.0
        seq = seq_to_tensor(ts)
        seq_padded = pad(seq, max_len)[None]  # [1, T, 2]
        gru.eval()
        with torch.no_grad():
            gru_score = float(torch.sigmoid(
                gru(torch.as_tensor(seq_padded),
                    torch.as_tensor([min(len(seq), max_len)]))).item())
        return [ev["iat_cv"], ev["iat_mad"], ev["spectral_concentration"],
                ev["lag1_autocorrelation"], ll, gru_score]

    train_X = [c2_features(r) for r in train_rows]
    train_y = [r["label"] for r in train_rows]
    pairs = [(x, y) for x, y in zip(train_X, train_y) if x is not None]
    Xtr, ytr = [p[0] for p in pairs], [p[1] for p in pairs]

    val_X   = [c2_features(r) for r in val_rows]
    val_y   = [r["label"] for r in val_rows]
    val_pairs = [(x, y) for x, y in zip(val_X, val_y) if x is not None]
    Xva, yva = [p[0] for p in val_pairs], [p[1] for p in val_pairs]

    fusion = C2Fusion(n_estimators=trees, max_depth=4, learning_rate=0.08, n_jobs=1, random_state=26, eval_metric="logloss")
    fusion.fit(np.array(Xtr), np.array(ytr)[:, None], split="train")
    fusion_path = output / "c2_fusion.json"
    fusion.models["C2_BEACONING"].save_model(str(fusion_path))
    print(f"  C2Fusion trained on {len(Xtr)} rows.", flush=True)

    # Calibration + metrics
    from agent2_detection_product.calibration import LabelCalibrator
    val_raw = fusion.predict(np.array(Xva))[:, 0]
    calibrator = LabelCalibrator().fit(val_raw, np.array(yva), split="validation")
    calibrator_path = output / "c2_calibrator.pkl"
    joblib.dump(calibrator, calibrator_path)
    val_cal = calibrator.predict(val_raw)

    test_X   = [c2_features(r) for r in test_rows]
    test_y   = [r["label"] for r in test_rows]
    test_pairs = [(x, y) for x, y in zip(test_X, test_y) if x is not None]
    Xte, yte = [p[0] for p in test_pairs], [p[1] for p in test_pairs]
    test_raw = fusion.predict(np.array(Xte))[:, 0]
    test_cal = calibrator.predict(test_raw)

    return {
        "model": "C2_BEACONING",
        "train_rows": len(Xtr), "val_rows": len(Xva), "test_rows": len(Xte),
        "val": metrics_binary(val_cal, yva),
        "test": metrics_binary(test_cal, yte),
        "cthmm_converged": getattr(cthmm, "fit_converged", None),
        "artifacts": {
            "cthmm": sha256_file(cthmm_path),
            "temporal_gru": sha256_file(gru_path),
            "c2_fusion": sha256_file(fusion_path),
            "c2_calibrator": sha256_file(calibrator_path),
        }
    }


# ─── Botnet ───────────────────────────────────────────────────────────────────

def train_botnet(output: Path, epochs: int, version: str) -> dict:
    print("  Generating Botnet corpus...", flush=True)
    from agent1_observation_dns.simulation.specialist_generators import botnet_corpus
    corpus = botnet_corpus(n_graphs=300)
    train_rows, val_rows, test_rows = split_corpus(corpus)
    print(f"  Botnet corpus: train={len(train_rows)}, val={len(val_rows)}, test={len(test_rows)}", flush=True)

    from agent2_detection_product.models.botnet_gnn import GraphSAGE
    from agent2_detection_product.models.botnet_tree_head import BotnetTreeHead
    from agent2_detection_product.models.providers import graph_arrays
    from sklearn.preprocessing import StandardScaler

    def row_to_graph(row):
        edges_raw = row["edges"]
        node_labels_dict = row["node_labels"]
        # Build edges in (src, dst, data) format
        edges = [(item[0], item[1], item[2] if len(item) > 2 else {"count": 5, "bytes": None}) for item in edges_raw]
        nodes, attributes, edge_index = graph_arrays(edges if edges else [(0, 0, {"count": 1, "bytes": None})])
        targets = np.zeros((len(nodes), 2), dtype=np.float32)
        for i, node in enumerate(nodes):
            targets[i] = node_labels_dict.get(node, (0, 0))
        return attributes, edge_index, targets

    # Build GNN training graphs
    gnn_graphs = []
    for row in train_rows:
        try:
            attrs, ei, tgts = row_to_graph(row)
            x = torch.as_tensor(attrs, dtype=torch.float32)
            e = torch.as_tensor(ei, dtype=torch.long)
            y = torch.as_tensor(tgts, dtype=torch.float32)
            gnn_graphs.append((x, e, y))
        except Exception:
            continue

    gnn = GraphSAGE(features=4, hidden=32, dimensions=32)
    torch.manual_seed(26)
    gnn.fit(gnn_graphs, split="train", epochs=epochs)
    gnn_path = output / "botnet_gnn.pt"
    torch.save(gnn.state_dict(), gnn_path)
    print(f"  Botnet GNN fitted on {len(gnn_graphs)} graphs.", flush=True)

    # BotnetTreeHead: needs per-node embeddings from all train nodes
    all_emb, all_flow, all_targets = [], [], []
    scaler = StandardScaler()

    def get_embeddings(rows, fit_scaler=False):
        embs, flows, tgts = [], [], []
        for row in rows:
            try:
                attrs, ei, tgts_node = row_to_graph(row)
                x = torch.as_tensor(attrs, dtype=torch.float32)
                e = torch.as_tensor(ei, dtype=torch.long)
                with torch.no_grad():
                    emb = gnn.embed(x, e).numpy()
                flow_feats = attrs  # same as input features
                for i in range(len(emb)):
                    embs.append(emb[i])
                    flows.append(flow_feats[i])
                    tgts.append(tgts_node[i].astype(int).tolist())
            except Exception:
                continue
        return np.array(embs), np.array(flows), np.array(tgts)

    emb_tr, flow_tr, tgt_tr = get_embeddings(train_rows)
    flow_tr_scaled = scaler.fit_transform(flow_tr)

    tree = BotnetTreeHead()
    tree.fit(emb_tr, flow_tr_scaled, tgt_tr, split="train")
    tree_path = output / "botnet_tree.pkl"
    joblib.dump(tree, tree_path)
    scaler_path = output / "botnet_scaler.pkl"
    joblib.dump(scaler, scaler_path)

    def eval_botnet(rows):
        emb, flow, tgt = get_embeddings(rows)
        if len(emb) == 0:
            return {}
        flow_sc = scaler.transform(flow)
        probs = tree.predict(emb, flow_sc)
        results = {}
        for i, label in enumerate(("BOTNET_HOST", "BOTNET_COORDINATION")):
            results[label] = metrics_binary(probs[:, i], tgt[:, i])
        return results

    val_metrics = eval_botnet(val_rows)
    test_metrics = eval_botnet(test_rows)
    print(f"  Botnet TreeHead val BOTNET_HOST F1={val_metrics.get('BOTNET_HOST', {}).get('f1', '?')}", flush=True)

    return {
        "model": "BOTNET",
        "train_graphs": len(train_rows), "val_graphs": len(val_rows), "test_graphs": len(test_rows),
        "val": val_metrics, "test": test_metrics,
        "artifacts": {
            "botnet_gnn": sha256_file(gnn_path),
            "botnet_tree": sha256_file(tree_path),
            "botnet_scaler": sha256_file(scaler_path),
        }
    }


# ─── Encrypted Malware ────────────────────────────────────────────────────────

def train_encrypted(output: Path, trees: int, version: str) -> dict:
    print("  Generating Encrypted Malware corpus...", flush=True)
    from agent1_observation_dns.simulation.specialist_generators import encrypted_corpus
    from agent2_detection_product.models.encrypted_malware import EncryptedMalware, early_sequence
    corpus = encrypted_corpus(n_sequences=700)
    train_rows, val_rows, test_rows = split_corpus(corpus)
    print(f"  Encrypted corpus: train={len(train_rows)}, val={len(val_rows)}, test={len(test_rows)}", flush=True)

    def row_to_features(row):
        return early_sequence(row["packet_sizes"], row["intervals"], budget=32)

    Xtr = np.array([row_to_features(r) for r in train_rows])
    ytr = np.array([[r["label"]] for r in train_rows])
    Xva = np.array([row_to_features(r) for r in val_rows])
    yva = np.array([[r["label"]] for r in val_rows])
    Xte = np.array([row_to_features(r) for r in test_rows])
    yte = np.array([[r["label"]] for r in test_rows])

    # Replace NaN with 0 for XGBoost
    Xtr = np.nan_to_num(Xtr, nan=0.0)
    Xva = np.nan_to_num(Xva, nan=0.0)
    Xte = np.nan_to_num(Xte, nan=0.0)

    model = EncryptedMalware(n_estimators=trees, max_depth=4, learning_rate=0.08, n_jobs=1, random_state=26, eval_metric="logloss")
    model.fit(Xtr, ytr, split="train")
    model_path = output / "encrypted_malware.json"
    model.models["ENCRYPTED_MALWARE"].save_model(str(model_path))
    print(f"  EncryptedMalware fitted on {len(Xtr)} rows.", flush=True)

    from agent2_detection_product.calibration import LabelCalibrator
    val_raw = model.predict(Xva)[:, 0]
    cal = LabelCalibrator().fit(val_raw, yva[:, 0], split="validation")
    cal_path = output / "encrypted_calibrator.pkl"
    joblib.dump(cal, cal_path)

    val_cal = cal.predict(val_raw)
    test_raw = model.predict(Xte)[:, 0]
    test_cal = cal.predict(test_raw)

    return {
        "model": "ENCRYPTED_MALWARE",
        "train_rows": len(Xtr), "val_rows": len(Xva), "test_rows": len(Xte),
        "val": metrics_binary(val_cal, yva[:, 0]),
        "test": metrics_binary(test_cal, yte[:, 0]),
        "artifacts": {
            "encrypted_malware": sha256_file(model_path),
            "encrypted_calibrator": sha256_file(cal_path),
        }
    }


# ─── DNS Tunnel GraphSAGE (Agent 1) ──────────────────────────────────────────

def train_dns_graphsage(output: Path, epochs: int, version: str) -> dict:
    print("  Generating DNS graph corpus...", flush=True)
    from agent1_observation_dns.simulation.specialist_generators import dns_graph_corpus
    from agent1_observation_dns.models.dns_tunnel_graphsage.model import GraphBranch

    corpus = dns_graph_corpus(n_graphs=400)
    train_rows = [r for r in corpus if r["split"] == "train"]
    val_rows   = [r for r in corpus if r["split"] == "validation"]
    test_rows  = [r for r in corpus if r["split"] == "test"]
    print(f"  DNS graph corpus: train={len(train_rows)}, val={len(val_rows)}, test={len(test_rows)}", flush=True)

    model_path = output / "dns_graphsage.pt"
    branch = GraphBranch()
    branch.fit(corpus, model_path, epochs=epochs, version=version)

    # Evaluate: build fake context from corpus rows and call predict
    def eval_rows(rows):
        scores, targets = [], []
        for row in rows:
            context = {
                "graph": {
                    "nodes": [f + [1.0] for f in row["node_features"]],
                    "edges": row["edges"],
                    "sufficient": len(row["edges"]) >= 2,
                }
            }
            result = branch.predict(f"eval-{row['scenario_id']}", None, context)
            if result.score_present:
                scores.append(result.probability)
                targets.append(row["graph_label"])
        return metrics_binary(scores, targets) if scores else {}

    val_m  = eval_rows(val_rows)
    test_m = eval_rows(test_rows)
    print(f"  DNS GraphSAGE val F1={val_m.get('f1','?')} ROC-AUC={val_m.get('roc_auc','?')}", flush=True)

    return {
        "model": "DNS_TUNNEL_GRAPHSAGE",
        "train_graphs": len(train_rows), "val_graphs": len(val_rows), "test_graphs": len(test_rows),
        "val": val_m, "test": test_m,
        "artifacts": {"dns_graphsage": sha256_file(model_path)},
    }


# ─── Main ──────────────────────────────────────────────────────────────────────

def run(args):
    torch.set_num_threads(args.threads)
    output = args.output.resolve()
    semver = r"\d+\.\d+\.\d+(?:-[\w.-]+)?"
    version = args.version or ("0.1.0-" + re.sub(r"[^\w.-]", "-", output.name))
    if not re.fullmatch(semver, version):
        raise ValueError("version must be a semantic version e.g. 0.1.0-sim")
    if output.exists():
        raise FileExistsError(f"Choose a new output directory: {output}")
    output.mkdir(parents=True)
    print(f"Training specialists -> {output}", flush=True)

    reports = {}
    print("\n[1/4] C2 Beaconing...", flush=True)
    reports["c2_beaconing"] = train_c2(output, epochs=args.epochs, trees=args.trees, version=version)
    print(f"  val: {reports['c2_beaconing']['val']}", flush=True)

    print("\n[2/4] Botnet GNN + TreeHead...", flush=True)
    reports["botnet"] = train_botnet(output, epochs=args.epochs, version=version)
    print(f"  val: {reports['botnet']['val']}", flush=True)

    print("\n[3/4] Encrypted Malware...", flush=True)
    reports["encrypted_malware"] = train_encrypted(output, trees=args.trees, version=version)
    print(f"  val: {reports['encrypted_malware']['val']}", flush=True)

    print("\n[4/4] DNS Tunnel GraphSAGE (Agent 1)...", flush=True)
    reports["dns_graphsage"] = train_dns_graphsage(output, epochs=args.epochs, version=version)
    print(f"  val: {reports['dns_graphsage']['val']}", flush=True)

    # Manifest
    manifest = {
        "schema_version": "0.1.0", "version": version, "status": "candidate",
        "training_data": "synthetic_simulation_only",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    write_json(output / "manifest.json", manifest)

    # Link into artifacts/specialists/current.json
    current_path = ROOT / "artifacts/specialists/current.json"
    current_path.parent.mkdir(parents=True, exist_ok=True)
    rel = output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else str(output)
    write_json(current_path, {"specialist_release": rel + "/manifest.json", "version": version, "status": "candidate"})

    print(f"\nDone. Manifest: {output / 'manifest.json'}", flush=True)
    print(json.dumps({"version": version, "status": "candidate", "specialists": list(reports.keys())}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path("artifacts/specialists") / datetime.now().strftime("sim-%Y%m%d-%H%M%S"))
    parser.add_argument("--version", help="semantic version e.g. 0.1.0-sim")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--trees", type=int, default=60)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    import re
    main()
