"""Fast DNS lexical/context branch with explicit untrained fallback."""
from time import perf_counter
from agent1_observation_dns.models.common import lexical, logistic, scored
from agent1_observation_dns.models.dga_context_xgb.model import ContextBranch


class FastBranch(ContextBranch):
    name = "DNS_TUNNEL_FAST"
    architecture = "dns_tunnel_fast_gbdt"

    def __init__(self, checkpoint=None, *, baseline=True):
        super().__init__(checkpoint)
        self.baseline = baseline

    def predict(self, event_id, domain, context=None):
        if self.model is not None or not self.baseline:
            return super().predict(event_id, domain, context)
        started = perf_counter()
        values = lexical(domain)
        probability = logistic((values[4]-35)/10 + (values[1]-3.8)*1.2)
        return scored(event_id, self.name, probability, "tunnel-lexical-heuristic-1.0.0", started,
                      reason="UNTRAINED_UNCALIBRATED_BASELINE", uncertainty=1,
                      evidence={"calibrated": False, "query_length": values[0], "entropy": values[1]})
