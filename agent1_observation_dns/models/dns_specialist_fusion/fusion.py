"""Missing-aware DNS specialist fusion, never a global IDS decision."""
from time import perf_counter
from agent1_observation_dns.models.common import absent, scored


def fuse(event_id, components, *, weights=None):
    started = perf_counter()
    components = list(components)
    if any(c.event_id != event_id for c in components):
        raise ValueError("cannot fuse scores for different events")
    if len({c.specialist for c in components}) != len(components):
        raise ValueError("duplicate specialist")
    weights = weights or {}
    if any(not isinstance(w, (int, float)) or not 0 < w < float("inf") for w in weights.values()):
        raise ValueError("fusion weights must be finite and positive")
    available = [c for c in components if c.score_present and c.applicable]
    evidence = {"components": [c.model_dump(mode="json") for c in components], "calibrated": False,
                "available_components": len(available), "total_components": len(components)}
    if not available:
        result = absent(event_id, "DNS_TUNNEL", "ALL_BRANCHES_UNAVAILABLE", applicable=any(c.applicable for c in components), version="dns-weighted-mean-1.0.0")
        result.evidence = evidence
        return result
    total = sum(weights.get(c.specialist, 1) for c in available)
    probability = sum(c.probability*weights.get(c.specialist, 1) for c in available)/total
    # Uncertainty is unavailable unless every contributing branch provides it.
    uncertainty = max(c.uncertainty for c in available) if all(c.uncertainty is not None for c in available) else None
    result = scored(event_id, "DNS_TUNNEL", probability, "dns-weighted-mean-1.0.0", started,
                    evidence=evidence, uncertainty=uncertainty, reason="UNCALIBRATED_SPECIALIST_FUSION")
    result.inference_ms += sum(c.inference_ms for c in components)
    result.reason_codes.extend(sorted({r for c in components for r in c.reason_codes if not c.score_present}))
    return result
