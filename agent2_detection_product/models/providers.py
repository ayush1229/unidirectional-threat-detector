"""Runtime adapters for separately trained/calibrated specialist artifacts."""

from pathlib import Path
import numpy as np
import torch
from .c2_periodicity import periodicity
from .encrypted_malware import early_sequence
from ..contracts import make_score, feature
from ..gating import gates


class C2Provider:
    def __init__(self, cthmm, temporal, fusion, calibrator, version):
        self.cthmm, self.temporal, self.fusion = cthmm, temporal, fusion
        self.calibrator, self.version = calibrator, version

    def score(self, envelope, context):
        timestamps = context.get("timestamps", [])
        evidence = periodicity(timestamps) if timestamps else {}
        value = None
        if gates(envelope, context)["C2_BEACONING"]["ready"] and len(timestamps) >= 2:
            gaps = np.diff(timestamps)
            normalized = np.log1p(gaps).astype(np.float32)
            sequence = np.column_stack((normalized, np.ones(len(gaps), dtype=np.float32)))[None]
            self.temporal.eval()
            with torch.no_grad():
                temporal_score = float(torch.sigmoid(self.temporal(torch.as_tensor(sequence)))[0])
            ll = self.cthmm.log_likelihood(gaps) / max(len(gaps), 1)
            values = [[evidence.get("iat_cv", 0.0), evidence.get("iat_mad", 0.0),
                       evidence.get("spectral_concentration", 0.0),
                       evidence.get("lag1_autocorrelation", 0.0), ll, temporal_score]]
            raw = self.fusion.predict(values)[0, 0]
            value = float(self.calibrator.predict([raw])[0]) if self.calibrator else float(raw)
            evidence.update({"cthmm_log_likelihood_per_event": ll, "temporal_score": temporal_score})
        score = make_score(envelope, "C2_BEACONING", value, "c2_fusion", self.version,
                           calibrated=value is not None, evidence=evidence,
                           reason="INSUFFICIENT_C2_HISTORY" if value is None else None)
        return {"scores": [score]}


def graph_arrays(edges):
    """Canonical graph training/inference representation; addresses only index."""
    nodes = sorted({node for source, dest, _ in edges for node in (source, dest)})
    index = {node: i for i, node in enumerate(nodes)}
    attributes = np.zeros((len(nodes), 4), dtype=np.float32)
    edge_index = []
    for source, dest, data in edges:
        s, d = index[source], index[dest]
        attributes[s, 0] += data.get("count", 1)
        # Bytes have their own observed count, preserving unavailable != zero.
        if data.get("bytes") is not None:
            attributes[s, 1] += data["bytes"]
            attributes[s, 2] += 1
        attributes[d, 3] += 1
        edge_index.append((s, d))
    attributes = np.log1p(attributes)
    edge_tensor = np.asarray(edge_index, dtype=np.int64).reshape(-1, 2).T if edge_index else np.zeros((2, 0), dtype=np.int64)
    return nodes, attributes, edge_tensor


class BotnetProvider:
    def __init__(self, gnn, tree, scaler, calibrators, version):
        self.gnn, self.tree, self.scaler = gnn, tree, scaler
        self.calibrators, self.version = calibrators, version

    def score(self, envelope, context):
        labels = ("BOTNET_HOST", "BOTNET_COORDINATION")
        ready = gates(envelope, context)["BOTNET_HOST"]["ready"]
        evidence = {"nodes": context.get("graph_nodes", 0), "edges": context.get("graph_edges", 0),
                    "duration_seconds": context.get("graph_duration", 0)}
        values = [None, None]
        if ready and context.get("graph"):
            nodes, raw, edges = graph_arrays(context["graph"])
            if nodes:
                x = self.scaler.transform(raw).astype(np.float32)
                self.gnn.eval()
                with torch.no_grad():
                    embeddings = self.gnn.embed(torch.as_tensor(x), torch.as_tensor(edges)).numpy()
                src = envelope.get("entity_keys", {}).get("source")
                if src in nodes:
                    index = nodes.index(src)
                    prediction = self.tree.predict(embeddings, x)[index]
                else:
                    preds = np.array(self.tree.predict(embeddings, x))
                    prediction = preds.max(axis=0) if len(preds) else [0.0, 0.0]
                values = [
                    float(self.calibrators[label].predict([prediction[i]])[0])
                    if self.calibrators and label in self.calibrators
                    else float(prediction[i])
                    for i, label in enumerate(labels)
                ]
        return {"scores": [make_score(envelope, label, values[i], "botnet_graph_tree", self.version,
                                      calibrated=ready and values[i] is not None, evidence=evidence,
                                      reason=None if ready and values[i] is not None else "INSUFFICIENT_GRAPH_HISTORY")
                           for i, label in enumerate(labels)]}


class EncryptedProvider:
    def __init__(self, preprocessor, model, calibrator, version):
        self.preprocessor, self.model, self.calibrator, self.version = preprocessor, model, calibrator, version

    def score(self, envelope, context):
        gate = gates(envelope, context)["ENCRYPTED_MALWARE"]
        probability = None
        if gate["ready"]:
            sizes, _ = feature(envelope, "flow.packet_sizes")
            intervals, _ = feature(envelope, "flow.inter_arrival_times")
            stats = early_sequence(sizes or [], intervals or [])
            if self.preprocessor is not None:
                values, masks = self.preprocessor.transform([envelope])
                inp = np.column_stack((values, masks, [stats]))
            else:
                inp = np.array([stats], dtype=np.float32)
            if hasattr(self.model, "predict_proba"):
                raw = float(self.model.predict_proba(inp)[0, 1])
            else:
                pred = self.model.predict(inp)
                raw = float(pred[0, 0] if pred.ndim > 1 else pred[0])
            probability = float(self.calibrator.predict([raw])[0]) if self.calibrator else raw
        score = make_score(envelope, "ENCRYPTED_MALWARE", probability, "encrypted_metadata_sequence",
                           self.version, calibrated=probability is not None,
                           evidence={"packet_budget": 32, "payload_decrypted": False},
                           reason=None if probability is not None else gate["reason"])
        score["applicable"] = gate["applicable"]
        return {"scores": [score]}


def load_specialist_providers(spec_dir):
    """Load and return specialist providers (C2, Botnet, Encrypted) from an artifact directory."""
    import joblib
    from xgboost import XGBClassifier
    from .c2_temporal_tcn_gru import TemporalCandidate
    from .c2_fusion import C2Fusion
    from .botnet_gnn import GraphSAGE

    spec_dir = Path(spec_dir)
    providers = []
    version = spec_dir.name

    # 1. C2 Beaconing Provider
    if (spec_dir / "cthmm.pkl").exists() and (spec_dir / "temporal_gru.pt").exists() and (spec_dir / "c2_fusion.json").exists():
        try:
            cthmm = joblib.load(spec_dir / "cthmm.pkl")
            temporal = TemporalCandidate(features=2, kind="gru", hidden=32)
            temporal.load_state_dict(torch.load(spec_dir / "temporal_gru.pt", weights_only=True))
            c2_xgb = XGBClassifier()
            c2_xgb.load_model(str(spec_dir / "c2_fusion.json"))
            fusion = C2Fusion()
            fusion.models = {"C2_BEACONING": c2_xgb}
            calibrator = joblib.load(spec_dir / "c2_calibrator.pkl") if (spec_dir / "c2_calibrator.pkl").exists() else None
            providers.append(C2Provider(cthmm, temporal, fusion, calibrator, version))
        except Exception as exc:
            pass

    # 2. Botnet Topology Provider
    if (spec_dir / "botnet_gnn.pt").exists() and (spec_dir / "botnet_tree.pkl").exists() and (spec_dir / "botnet_scaler.pkl").exists():
        try:
            gnn_state = torch.load(spec_dir / "botnet_gnn.pt", weights_only=True)
            in_f = gnn_state["first.weight"].shape[1] // 2
            hidden = gnn_state["first.weight"].shape[0]
            dim = gnn_state["second.weight"].shape[0]
            gnn = GraphSAGE(features=in_f, hidden=hidden, dimensions=dim)
            gnn.load_state_dict(gnn_state)
            tree = joblib.load(spec_dir / "botnet_tree.pkl")
            scaler = joblib.load(spec_dir / "botnet_scaler.pkl")
            providers.append(BotnetProvider(gnn, tree, scaler, None, version))
        except Exception as exc:
            pass

    # 3. Encrypted Malware Provider
    if (spec_dir / "encrypted_malware.json").exists():
        try:
            enc_xgb = XGBClassifier()
            enc_xgb.load_model(str(spec_dir / "encrypted_malware.json"))
            calibrator = joblib.load(spec_dir / "encrypted_calibrator.pkl") if (spec_dir / "encrypted_calibrator.pkl").exists() else None
            providers.append(EncryptedProvider(None, enc_xgb, calibrator, version))
        except Exception as exc:
            pass

    return providers
