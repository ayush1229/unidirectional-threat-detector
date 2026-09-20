"""DGA evidence only. Baseline is a documented untrained lexical heuristic."""
from time import perf_counter
from agent1_observation_dns.models.common import lexical, logistic, scored, absent


class DGASpecialist:
    def __init__(self, character=None, context=None, *, baseline=True):
        self.character = character
        self.context = context
        self.baseline = baseline

    def predict(self, event_id, domain, context=None):
        started = perf_counter()
        if domain is None:
            return absent(event_id, "DGA", "DNS_QUERY_NOT_VISIBLE", applicable=False)
        values = lexical(domain)
        components = [branch.predict(event_id, domain, context or {}) if branch else
                      absent(event_id, name, "CHECKPOINT_ABSENT")
                      for branch, name in ((self.character, "DGA_CHARACTER"), (self.context, "DGA_CONTEXT"))]
        available = [c.probability for c in components if c.score_present]
        evidence = {"components": [c.model_dump(mode="json") for c in components],
                    "lexical": dict(zip(("length", "entropy", "digit_ratio", "label_count", "max_label_length", "hyphen_ratio"), values)),
                    "calibrated": False}
        if available:
            return scored(event_id, "DGA", sum(available)/len(available), "dga-mean-fusion-1.0.0", started,
                          evidence=evidence, uncertainty=None)
        if not self.baseline:
            result = absent(event_id, "DGA", "ALL_BRANCHES_UNAVAILABLE")
            result.evidence = evidence
            return result
        probability = logistic((values[1]-3.3)*1.5 + values[2]*2 + (values[4]-18)/15 - 1)
        return scored(event_id, "DGA", probability, "lexical-heuristic-1.0.0", started,
                      evidence=evidence, reason="UNTRAINED_UNCALIBRATED_BASELINE", uncertainty=1.0)
