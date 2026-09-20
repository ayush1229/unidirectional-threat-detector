"""Fast-first, reproducible early-exit routing with an entry for every branch."""
import hashlib
import logging
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.models.common import absent, normalize_domain
from agent1_observation_dns.models.dns_tunnel_fast_gbdt.model import FastBranch
from agent1_observation_dns.models.dns_specialist_fusion.fusion import fuse

log = logging.getLogger("agent1.dns_routing")


class TunnelSpecialist:
    def __init__(self, config=None, *, fast=None, byte=None, sequence=None, graph=None):
        self.config = config or Settings()
        self.fast = fast if fast is not None else FastBranch(self.config.model_paths.get("dns_tunnel_fast_gbdt"))
        if byte is None and self.config.model_paths.get("dns_tunnel_bytecnn"):
            from agent1_observation_dns.models.dns_tunnel_bytecnn.model import ByteBranch
            byte = ByteBranch(self.config.model_paths["dns_tunnel_bytecnn"])
        if sequence is None and self.config.model_paths.get("dns_tunnel_sequence"):
            from agent1_observation_dns.models.dns_tunnel_sequence.model import SequenceBranch
            sequence = SequenceBranch(self.config.model_paths["dns_tunnel_sequence"], self.config.sequence_min_events)
        if graph is None:
            from agent1_observation_dns.models.dns_tunnel_graphsage.model import GraphBranch
            graph = GraphBranch()
        self.branches = {"DNS_TUNNEL_BYTECNN": byte, "DNS_TUNNEL_SEQUENCE": sequence, "DNS_TUNNEL_GRAPHSAGE": graph}

    def predict(self, event_id, domain, context=None):
        context = context or {}
        if domain is None:
            return fuse(event_id, [absent(event_id, n, "DNS_QUERY_NOT_VISIBLE", applicable=False)
                                   for n in ("DNS_TUNNEL_FAST", *self.branches)])
        domain = normalize_domain(domain)
        fast = self.fast.predict(event_id, domain, context)
        audit = int.from_bytes(hashlib.sha256(event_id.encode()).digest()[:8], "big")/2**64 < self.config.audit_fraction
        reasons = []
        if fast.score_present and self.config.suspicious_low <= fast.probability <= self.config.suspicious_high:
            reasons.append("SUSPICIOUS_BAND")
        if max(map(len, domain.split("."))) >= self.config.structural_label_length:
            reasons.append("STRUCTURAL_TRIGGER")
        if audit:
            reasons.append("AUDIT_SAMPLE")
        if self.config.research_evaluation:
            reasons.append("RESEARCH_EVALUATION")
        components = [fast]
        for name, branch in self.branches.items():
            if not reasons:
                result = absent(event_id, name, "EARLY_EXIT")
            elif branch is None:
                result = absent(event_id, name, "CHECKPOINT_ABSENT")
            else:
                result = branch.predict(event_id, domain, context)
            components.append(result)
        result = fuse(event_id, components)
        result.evidence["routing_reasons"] = reasons or ["EARLY_EXIT"]
        log.info("dns_specialist", extra={"event_id": event_id, "route_decision": reasons,
                 "skipped_specialists": [c.specialist for c in components if not c.score_present],
                 "reason_codes": result.reason_codes, "model_version": result.model_version,
                 "processing_ms": result.inference_ms})
        return result
