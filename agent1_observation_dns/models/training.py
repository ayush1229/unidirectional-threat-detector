"""Explicit split-aware training/evaluation. No fitting on validation or test rows."""
import hashlib
import json
from pathlib import Path
import random

from agent1_observation_dns.ground_truth.splits import validate_sample_splits
from agent1_observation_dns.models.common import context_vector, normalize_domain


def prepare_rows(rows):
    prepared = []
    for row in rows:
        row = dict(row)
        row["domain"] = normalize_domain(row["domain"])
        if row["label"] not in (0, 1) or row["split_assignment"] not in ("train", "validation", "test"):
            raise ValueError("invalid label or partition")
        for key in ("scenario_id", "split_group", "family", "tool", "event_time"):
            if not row.get(key):
                raise ValueError(f"missing provenance: {key}")
        row["content_hash"] = hashlib.sha256(row["domain"].encode()).hexdigest()
        prepared.append(row)
    validate_sample_splits(prepared)
    train = [r for r in prepared if r["split_assignment"] == "train"]
    if {r["label"] for r in train} != {0, 1}:
        raise ValueError("training requires both classes")
    return prepared


def train_tabular(rows, output, *, architecture="dga_context_xgb", model_version="0.1.0", seed=0, estimators=50):
    import numpy as np
    from xgboost import XGBClassifier
    from agent1_observation_dns.models.dga_context_xgb.model import FEATURE_NAMES
    if architecture not in ("dga_context_xgb", "dns_tunnel_fast_gbdt"):
        raise ValueError("unsupported DNS tabular architecture")
    rows = prepare_rows(rows)
    training = [r for r in rows if r["split_assignment"] == "train"]
    matrix = np.array([context_vector(r["domain"], r.get("context", {})) for r in training], dtype=float)
    model = XGBClassifier(n_estimators=estimators, max_depth=3, learning_rate=.1, objective="binary:logistic",
                          random_state=seed, n_jobs=1, tree_method="hist")
    model.fit(matrix, [r["label"] for r in training])
    output = Path(output)
    if output.exists() or output.with_suffix(".meta.json").exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(output)
    metadata = {"architecture": architecture, "trained": True, "model_version": model_version,
                "feature_names": FEATURE_NAMES, "seed": seed, "train_rows": len(training),
                "preprocessing_version": "1.0.0", "evaluation": evaluate_tabular(model, rows)}
    output.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2)+"\n", encoding="utf-8")
    return metadata


def metrics(labels, probabilities):
    if not labels:
        return {"count": 0, "log_loss": None, "brier": None, "reason": "NO_EVALUATION_ROWS"}
    from math import log
    clipped = [max(1e-7, min(1-1e-7, float(p))) for p in probabilities]
    return {"count": len(labels), "log_loss": -sum(y*log(p)+(1-y)*log(1-p) for y,p in zip(labels, clipped))/len(labels),
            "brier": sum((y-p)**2 for y,p in zip(labels, probabilities))/len(labels)}


def evaluate_tabular(model, rows):
    import numpy as np
    result = {}
    for partition in ("validation", "test"):
        subset = [r for r in rows if r["split_assignment"] == partition]
        probabilities = model.predict_proba(np.array([context_vector(r["domain"], r.get("context", {})) for r in subset]))[:,1].tolist() if subset else []
        result[partition] = metrics([r["label"] for r in subset], probabilities)
    return result


def train_neural(rows, output, *, architecture="dga_char_attention", model_version="0.1.0", seed=0, epochs=5, batch_size=32):
    import torch
    from agent1_observation_dns.models.dga_char_attention.model import CharacterAttention, encode_domains
    if epochs < 1 or batch_size < 1:
        raise ValueError("positive epochs and batch size required")
    rows = prepare_rows(rows)
    torch.manual_seed(seed)
    random.seed(seed)
    torch.use_deterministic_algorithms(True)
    if architecture == "dga_char_attention":
        model = CharacterAttention()
        preprocess = lambda batch: (encode_domains([r["domain"] for r in batch]),)
    elif architecture in ("dns_tunnel_bytecnn", "dns_tunnel_sequence"):
        from agent1_observation_dns.models.dns_tunnel_bytecnn.model import ByteCNN, encode_bytes
        from agent1_observation_dns.models.dns_tunnel_sequence.model import MetadataSequence, encode_sequences
        if architecture == "dns_tunnel_bytecnn":
            model = ByteCNN()
            preprocess = lambda batch: (encode_bytes([r["domain"] for r in batch]),)
        else:
            model = MetadataSequence()
            preprocess = lambda batch: encode_sequences([r["sequence"] for r in batch])
    else:
        raise ValueError("unsupported DNS neural architecture")
    training = [r for r in rows if r["split_assignment"] == "train"]
    optimizer = torch.optim.Adam(model.parameters(), lr=.001)
    model.train()
    for _ in range(epochs):
        for start in range(0, len(training), batch_size):
            batch = training[start:start+batch_size]
            optimizer.zero_grad()
            logits = model(*preprocess(batch))
            loss = torch.nn.functional.binary_cross_entropy_with_logits(logits, torch.tensor([r["label"] for r in batch], dtype=torch.float32))
            loss.backward()
            optimizer.step()
    model.eval()
    evaluation = {}
    with torch.inference_mode():
        for partition in ("validation", "test"):
            subset = [r for r in rows if r["split_assignment"] == partition]
            probabilities = []
            for start in range(0, len(subset), batch_size):
                probabilities.extend(model(*preprocess(subset[start:start+batch_size])).sigmoid().tolist())
            evaluation[partition] = metrics([r["label"] for r in subset], probabilities)
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"architecture": architecture, "trained": True, "model_version": model_version,
                "preprocessing_version": "1.0.0", "seed": seed, "train_rows": len(training), "epochs": epochs,
                "evaluation": evaluation}
    torch.save({**metadata, "state_dict": model.state_dict()}, output)
    return metadata
