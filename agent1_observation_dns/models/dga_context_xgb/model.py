"""Masked DNS context XGBoost. Only explicitly trained artifacts are loaded."""
import json
from pathlib import Path
from time import perf_counter

from agent1_observation_dns.models.common import absent, scored, context_vector, CONTEXT_FIELDS, LEXICAL_FIELDS

FEATURE_NAMES = list(LEXICAL_FIELDS) + list(CONTEXT_FIELDS) + [name+"_available" for name in CONTEXT_FIELDS]


class ContextBranch:
    name = "DGA_CONTEXT"
    architecture = "dga_context_xgb"

    def __init__(self, checkpoint=None):
        self.model = None
        self.version = "untrained"
        if checkpoint:
            from xgboost import XGBClassifier
            path = Path(checkpoint)
            metadata = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
            if metadata.get("architecture") != self.architecture or metadata.get("feature_names") != FEATURE_NAMES or not metadata.get("trained"):
                raise ValueError("incompatible tabular checkpoint")
            self.model = XGBClassifier()
            self.model.load_model(path)
            self.version = metadata["model_version"]

    def predict(self, event_id, domain, context=None):
        vector = context_vector(domain, context or {})
        started = perf_counter()
        if self.model is None:
            return absent(event_id, self.name, "CHECKPOINT_ABSENT")
        import numpy as np
        probability = self.model.predict_proba(np.array([vector], dtype=float))[0, 1]
        return scored(event_id, self.name, probability, self.version, started,
                      evidence={"context_available": [name for name, value in zip(CONTEXT_FIELDS, vector[-len(CONTEXT_FIELDS):]) if value]})
