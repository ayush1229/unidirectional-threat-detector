"""DNS-only feature preprocessing and specialist result helpers."""
from math import exp
from time import perf_counter
import unicodedata

from agent1_observation_dns.contracts import SpecialistScore
from agent1_observation_dns.state_observation.dns import entropy

CONTEXT_FIELDS = ("query_count", "response_count", "nxdomain_ratio", "subdomain_churn", "txt_ratio",
                  "aaaa_ratio", "query_rate", "iat_mean_s", "packet_size_mean", "packet_size_std")
LEXICAL_FIELDS = ("length", "entropy", "digit_ratio", "label_count", "max_label_length", "hyphen_ratio")


def normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise ValueError("domain must be text")
    domain = unicodedata.normalize("NFC", domain.strip().rstrip(".")).lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid IDNA name") from exc
    if not domain or len(domain) > 253 or any(not label or len(label) > 63 for label in domain.split(".")):
        raise ValueError("invalid domain length")
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for c in domain):
        raise ValueError("invalid domain characters")
    return domain


def lexical(domain: str) -> list[float]:
    domain = normalize_domain(domain)
    return [float(len(domain)), entropy(domain), sum(c.isdigit() for c in domain)/len(domain),
            float(len(domain.split("."))), float(max(map(len, domain.split(".")))), domain.count("-")/len(domain)]


def context_vector(domain: str, context: dict) -> list[float]:
    values, masks = [], []
    for name in CONTEXT_FIELDS:
        value = context.get(name)
        if hasattr(value, "available"):
            value = value.value if value.available and value.applicable else None
        elif isinstance(value, dict):
            value = value.get("value") if value.get("available") and value.get("applicable", True) else None
        if value is not None and not isinstance(value, (int, float)):
            raise ValueError("context must contain numeric measurements")
        values.append(float(value) if value is not None else float("nan"))
        masks.append(float(value is not None))
    return lexical(domain) + values + masks


def absent(event_id, name, reason, *, applicable=True, version="untrained"):
    return SpecialistScore(event_id=event_id, specialist=name, applicable=applicable,
                           reason_codes=[reason], model_version=version)


def scored(event_id, name, probability, version, started, *, evidence=None, reason="MODEL_INFERENCE", uncertainty=None):
    return SpecialistScore(event_id=event_id, specialist=name, probability=float(probability), score_present=True,
        uncertainty=uncertainty, inference_ms=(perf_counter()-started)*1000, evidence=evidence or {},
        reason_codes=[reason] + (["UNCERTAINTY_NOT_ESTIMATED"] if uncertainty is None else []), model_version=version)


def logistic(value):
    return 1/(1+exp(-max(-50, min(50, value))))
