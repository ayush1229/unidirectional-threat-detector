"""
scripts/ensemble.py
=====================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

Fuses three independent views of a flow into one final alert:
  1. Person 1's supervised classifier (xgboost_train/scripts/infer.py)
  2. This module's own anomaly score (Isolation Forest + Autoencoder)
  3. This module's own sequence score (LSTM — Botnet C2 beaconing)

This is the ensemble scoring contract Person 2 owns per the SIH26145
spec, jointly agreed with Person 1 (supervised half) and consumed
directly by Person 4's API layer (alert.new).

Fusion strategy
----------------
Weighted average across the three scores, EXCEPT: if any single model
fires very confidently on its own (>= FIRE_OVERRIDE_THRESHOLD), that
confidence is not diluted by the other two models being quiet. This
matters because the three models see genuinely different signal —
a zero-day flow the supervised model has never seen might score near-zero
there while the autoencoder screams; a plain weighted average would wash
that out. Rationale mirrors the spec's requirement (Section 4.3) that
anomalous/unseen-signature flows must still surface as high-confidence
alerts even without supervised-model agreement.

Usage
-----
    from ensemble_engine.scripts.ensemble import score_flow

    alert = score_flow(flow_obj)
    # {
    #   "flow_id": "...",
    #   "five_tuple": {...},
    #   "threat_class": "BOTNET_C2_BEACONING",
    #   "confidence_score": 0.91,
    #   "severity": "HIGH",
    #   "model_source": {
    #       "supervised_score": 0.12,
    #       "anomaly_score": 0.74,
    #       "sequence_score": 0.93,
    #       "fired_models": ["sequence", "anomaly"]
    #   },
    #   "evidence": {...}
    # }

NOTE ON threat_class NAMING: Person 1's supervised model and DNS model
return their own class-name strings (trained from their own label
encoders) — these must match the exact enum values in the SIH26145 spec
Section 6 Standardized Alert Schema. If your copy of the spec uses
different exact strings than the constants below (e.g. "DNS_TUNNEL" vs
"DNS_TUNNELING"), update ANOMALY_ONLY_CLASS and the severity table to
match — search-and-replace, the logic doesn't depend on the exact string.
"""

from __future__ import annotations

import sys
from pathlib import Path

import importlib.util

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent


def _load_module_from_path(module_name: str, file_path: Path):
    """
    Load a .py file as a module under an explicit, unique name.

    Both this module and Person 1's module are named infer.py in different
    folders — a plain sys.path + `import infer` collides, since Python
    caches modules by their bare name and the second import silently
    returns the first module already loaded. Loading each by exact file
    path under a distinct name avoids that entirely.
    """
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_person2_infer = _load_module_from_path("person2_infer", SCRIPTS_DIR / "infer.py")

# person2's infer.py just cached ITS features.py under sys.modules['features'].
# Person 1's infer.py does its own `from features import ...` next, and would
# otherwise silently reuse that same cached (wrong) module instead of loading
# its own features.py — clear the cache so the next import resolves fresh.
sys.modules.pop("features", None)

_person1_infer = _load_module_from_path(
    "person1_infer", REPO_ROOT / "xgboost_train" / "scripts" / "infer.py"
)

anomaly_score = _person2_infer.anomaly_score
beacon_likelihood = _person2_infer.beacon_likelihood
supervised_predict_flow = _person1_infer.predict_flow_proba
supervised_predict_dns = _person1_infer.predict_dns_proba

# ---------------------------------------------------------------------------
# Tunable constants
# ---------------------------------------------------------------------------

WEIGHT_SUPERVISED = 0.5
WEIGHT_ANOMALY = 0.25
WEIGHT_SEQUENCE = 0.25

# If any single model's individual score is at/above this, the fused
# confidence_score is at least that value — a strong solo signal is never
# diluted below its own confidence by the other two models being quiet.
FIRE_OVERRIDE_THRESHOLD = 0.85

# A model "fires" (gets listed in model_source.fired_models) once its
# individual score crosses this — marking "this model thinks something's off".
FIRE_LISTED_THRESHOLD = 0.20
FIRE_ANOMALY_THRESHOLD = 0.50
FIRE_SEQUENCE_THRESHOLD = 0.50

# Used when neither the supervised model nor the LSTM identify a specific
# known threat class, but the anomaly score alone is high — this is the
# "catches zero-day / previously-unseen threat classes" case from the spec.
# CONFIRM this exact string matches Section 6 of your copy of the spec.
ANOMALY_ONLY_CLASS = "ANOMALOUS_UNCLASSIFIED"

BENIGN_CLASS = "BENIGN"

# Spec item (d): Malware inside encrypted sessions — detected from TLS/QUIC
# metadata alone (JA3/JA4 fingerprints, packet-size sequences), no decryption.
MALWARE_ENCRYPTED_TLS_CLASS = "MALWARE_ENCRYPTED_TLS"

# Minimum anomaly score threshold for the TLS malware heuristic to fire.
# Set deliberately high so benign unusual TLS clients don't false-positive.
MALWARE_TLS_ANOMALY_THRESHOLD = 0.55

# Published malware-associated JA3 MD5 fingerprints from open threat intel.
# Sources: Trisul Networks JA3 database, Sslbl.abuse.ch, Salesforce JA3 repo.
# Only add hashes with very high confidence (C2 frameworks, widespread loaders).
_KNOWN_MALWARE_JA3: set = {
    "72a589da586844d7f0818ce684948eea",  # Metasploit Meterpreter
    "a0e9f5d64349fb13191bc781f81f42e1",  # CobaltStrike default profile
    "6734f37431670b3ab4292b8f60f29984",  # Emotet loader
    "eb88d0b3e1961a0562f006e09595ef4a",  # Dridex/TrickBot
    "de9f102050fbb7f2498f82a6c17e1e77",  # Qakbot
    "1aa7bf6b3d5745eea9427cec985b1306",  # AsyncRAT
}

# confidence_score -> severity. Adjust bucket edges to match Section 6 if
# your spec defines different thresholds.
SEVERITY_BUCKETS = [
    (0.90, "CRITICAL"),
    (0.75, "HIGH"),
    (0.50, "MEDIUM"),
    (0.0, "LOW"),
]


def _severity_from_confidence(confidence: float) -> str:
    for threshold, label in SEVERITY_BUCKETS:
        if confidence >= threshold:
            return label
    return "LOW"


def _top_non_benign(proba: dict) -> tuple:
    """From a {class: prob} dict, return the highest-probability class that
    isn't BENIGN, and its probability. Returns (BENIGN_CLASS, prob) if
    BENIGN itself is the top class."""
    if not proba:
        return BENIGN_CLASS, 0.0
    non_benign = {k: v for k, v in proba.items() if k != BENIGN_CLASS}
    if not non_benign:
        return BENIGN_CLASS, proba.get(BENIGN_CLASS, 0.0)
    top_class = max(non_benign, key=non_benign.get)
    return top_class, non_benign[top_class]


def _normalize_tls_meta(tls_meta: dict) -> dict:
    """
    Accept both legacy key names (ja3, ja4) and canonical schema key names
    (ja3_fingerprint, ja4_fingerprint) so old and new flows are both handled.
    Returns a new dict with canonical names only — never mutates the input.
    """
    if not tls_meta:
        return {}
    out = dict(tls_meta)
    # Migrate legacy ja3 -> ja3_fingerprint (prefer the canonical key if both present)
    if "ja3" in out and "ja3_fingerprint" not in out:
        out["ja3_fingerprint"] = out.pop("ja3")
    elif "ja3" in out:
        out.pop("ja3")
    # Migrate legacy ja4 -> ja4_fingerprint
    if "ja4" in out and "ja4_fingerprint" not in out:
        out["ja4_fingerprint"] = out.pop("ja4")
    elif "ja4" in out:
        out.pop("ja4")
    return out


def _is_malware_tls(tls_meta: dict, anomaly: float) -> bool:
    """
    Heuristic check for malware-in-encrypted-session (spec item d).
    Fires when:
      - The flow uses TLS/QUIC (tls_meta is present), AND
      - Its JA3 fingerprint matches a known-malware hash, OR
      - Its JA3 is absent/None (malware often omits SNI and uses null JA3) AND
        the anomaly score is above the TLS malware threshold.

    No payload decryption is ever performed — this operates on metadata only.
    """
    if not tls_meta:
        return False
    ja3 = tls_meta.get("ja3_fingerprint")
    if ja3 and ja3 in _KNOWN_MALWARE_JA3:
        return True
    # Secondary signal: no SNI (malware connecting by IP) AND unusual cipher suites
    sni = tls_meta.get("sni")
    ciphers = tls_meta.get("cipher_suites") or []
    # Weak/export cipher suites used by older malware frameworks
    _WEAK_CIPHERS = {"0x0035", "0x002f", "0x000a", "0xc014", "0x0005"}
    weak_cipher_hit = bool(set(str(c) for c in ciphers) & _WEAK_CIPHERS)
    if (not sni) and weak_cipher_hit and anomaly >= MALWARE_TLS_ANOMALY_THRESHOLD:
        return True
    return False


def score_flow(flow_obj: dict, tracker=None) -> dict:
    """
    Run all three models on a single FlowObject and fuse their outputs
    into the final alert object structure (see module docstring).

    Parameters
    ----------
    flow_obj : dict
        A FlowObject dict from the Redis `flow.raw` channel.
    tracker : FlowStateTracker | None
        Optional cross-flow state tracker instance. When supplied, the
        evidence dict is enriched with real source-IP entropy and port
        fan-out counts from the sliding window. Pass None to skip
        (e.g. in unit tests or offline batch scoring).
    """
    # -- Normalize TLS meta key names (accept both legacy and canonical) --
    raw_tls_meta = flow_obj.get("tls_meta") or {}
    tls_meta = _normalize_tls_meta(raw_tls_meta)
    # Inject normalized tls_meta back for downstream feature extractors
    if tls_meta != raw_tls_meta:
        flow_obj = {**flow_obj, "tls_meta": tls_meta}

    # -- 1. Supervised score (Person 1) --
    flow_proba = supervised_predict_flow(flow_obj)
    supervised_class, supervised_score = _top_non_benign(flow_proba)

    # If this flow has DNS metadata, also check the DNS-specific model and
    # let it override the flow-level guess if it's more confident — DGA/DNS
    # tunneling patterns often show up more clearly in the query name itself
    # than in flow-level stats alone.
    dns_meta = flow_obj.get("dns_meta")
    if dns_meta and dns_meta.get("query_name"):
        dns_proba = supervised_predict_dns(dns_meta["query_name"])
        dns_class, dns_score = _top_non_benign(dns_proba)
        if dns_score > supervised_score:
            supervised_class, supervised_score = dns_class, dns_score

    # -- 2. Anomaly score (this module — Isolation Forest + Autoencoder) --
    anomaly = anomaly_score(flow_obj)

    # -- 3. Sequence score (this module — LSTM beacon detector) --
    sequence = beacon_likelihood(flow_obj)

    # -- 4. Malware-in-encrypted-TLS heuristic (spec item d) --
    malware_tls_hit = _is_malware_tls(tls_meta, anomaly)

    # -- Fuse into confidence_score --
    weighted_avg = (
        WEIGHT_SUPERVISED * supervised_score
        + WEIGHT_ANOMALY * anomaly
        + WEIGHT_SEQUENCE * sequence
    )
    max_individual = max(supervised_score, anomaly, sequence)
    if max_individual >= FIRE_OVERRIDE_THRESHOLD:
        confidence_score = max(weighted_avg, max_individual)
    else:
        confidence_score = weighted_avg
    # Malware TLS hit: floor the confidence at 0.70 (HIGH) — the JA3 match
    # is strong evidence regardless of what the statistical models say.
    if malware_tls_hit:
        confidence_score = max(confidence_score, 0.70)
    confidence_score = float(min(confidence_score, 1.0))

    # -- Determine threat_class --
    # Priority order (most specific / highest-quality signal wins):
    #   1. Malware-TLS heuristic: JA3 hash in known-bad set — most specific.
    #   2. Supervised classifier (XGBoost): trained on labelled known-attack
    #      patterns — use its label when it fires and malware-TLS didn't.
    #   3. LSTM sequence model: catches periodic C2 beaconing.
    #   4. Anomaly models: catch zero-day / previously-unseen classes.
    #   5. None fired → BENIGN.
    #
    # Map any legacy supervised class names to canonical threat contract names.
    CANONICAL_CLASS_MAP = {
        "DGA_DOMAIN":      "DGA",              # normalize if old model used DGA_DOMAIN
        "DNS_TUNNEL":      "DNS_TUNNELING",    # normalize if old model used DNS_TUNNEL
        "DDOS":            "VOLUMETRIC_DDOS",  # normalize if old model used DDOS
        "SCAN":            "PORT_SCAN",        # normalize if old model used SCAN
        "EXFILTRATION":    "DATA_EXFILTRATION",
    }

    if malware_tls_hit:
        threat_class = MALWARE_ENCRYPTED_TLS_CLASS
    elif supervised_score >= FIRE_LISTED_THRESHOLD:
        # Supervised model is confident in a specific known attack class.
        threat_class = CANONICAL_CLASS_MAP.get(supervised_class, supervised_class)
    elif sequence >= FIRE_SEQUENCE_THRESHOLD:
        # LSTM detects periodic beaconing even if flow-level features look quiet.
        threat_class = "BOTNET_C2_BEACONING"
    elif anomaly >= FIRE_ANOMALY_THRESHOLD:
        # Anomaly models detect unusual behaviour with no known-class match
        # (zero-day / unseen threat signature).
        threat_class = ANOMALY_ONLY_CLASS
    else:
        # No model fired — this is normal traffic.
        threat_class = BENIGN_CLASS

    severity = _severity_from_confidence(confidence_score) if threat_class != BENIGN_CLASS else "LOW"

    fired_models = []
    if malware_tls_hit:
        fired_models.append("malware_tls_heuristic")
    if supervised_score >= FIRE_LISTED_THRESHOLD:
        fired_models.append("supervised")
    if anomaly >= FIRE_ANOMALY_THRESHOLD:
        fired_models.append("anomaly")
    if sequence >= FIRE_SEQUENCE_THRESHOLD:
        fired_models.append("sequence")

    # -- Evidence: populate telemetry and model metrics --
    evidence = {}
    dur  = max(float(flow_obj.get("duration_s", 0.001) or 0.001), 0.001)
    pkts = int(flow_obj.get("total_packets", 1) or 1)
    bytes_in = int(flow_obj.get("bytes_in", 0) or 0)

    evidence["packets_per_second"] = round(pkts / dur, 1)
    evidence["bytes_in"] = bytes_in
    evidence["bytes_in_per_packet"] = round(bytes_in / pkts, 1) if pkts else 0.0

    # Data exfiltration: large sustained byte-per-packet signals large payload transfer
    if threat_class == "DATA_EXFILTRATION" or bytes_in > 500_000:
        evidence["bytes_in_to_packet_ratio"] = round(bytes_in / pkts, 1) if pkts else 0.0

    # Source-IP entropy: use real tracker value when available (sliding-window Shannon
    # entropy of source-IP distribution targeting the same dst_ip), otherwise fall back
    # to a proxy derived from the anomaly score.
    ft = flow_obj.get("five_tuple") or {}
    dst_ip = ft.get("dst_ip", "")
    src_ip = ft.get("src_ip", "")
    if tracker is not None and dst_ip:
        real_entropy = tracker.get_dst_entropy(dst_ip, window_s=60)
        evidence["src_ip_entropy"] = real_entropy
        unique_srcs = tracker.get_unique_source_count(dst_ip, window_s=60)
        if unique_srcs > 1:
            evidence["unique_source_ips_60s"] = unique_srcs
        fan_out = tracker.get_port_fanout(src_ip, window_s=60) if src_ip else 0
        if fan_out > 5:
            evidence["port_fanout_60s"] = fan_out
    else:
        # Fallback proxy (no tracker): anomaly score correlates with source diversity
        evidence["src_ip_entropy"] = round(min(max(float(anomaly), 0.05), 0.98), 3)

    # Beacon interval: emit whenever IAT data is present (not just when threshold fires)
    iats = flow_obj.get("inter_arrival_times") or []
    if iats:
        evidence["beacon_interval_seconds"] = round(sum(iats) / len(iats), 3)
        # Coefficient of variation: low CV (< 0.15) indicates machine-clock-driven beaconing
        import statistics as _stats
        if len(iats) > 1:
            mean_iat = sum(iats) / len(iats)
            std_iat = _stats.stdev(iats)
            evidence["iat_coefficient_of_variation"] = round(std_iat / mean_iat, 4) if mean_iat else 0.0

    # TLS metadata evidence
    if tls_meta:
        if tls_meta.get("ja3_fingerprint"):
            evidence["ja3_fingerprint"] = tls_meta["ja3_fingerprint"]
        if tls_meta.get("ja4_fingerprint"):
            evidence["ja4_fingerprint"] = tls_meta["ja4_fingerprint"]
        if tls_meta.get("sni"):
            evidence["tls_sni"] = tls_meta["sni"]
        if malware_tls_hit:
            evidence["malware_tls_indicator"] = (
                "ja3_in_known_malware_set" if tls_meta.get("ja3_fingerprint") in _KNOWN_MALWARE_JA3
                else "no_sni_weak_cipher_suite"
            )

    if anomaly >= FIRE_LISTED_THRESHOLD:
        evidence["anomaly_indicator"] = "unsupervised_deviation_from_benign_baseline"

    from datetime import datetime, timezone
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_id": flow_obj.get("flow_id"),
        "five_tuple": flow_obj.get("five_tuple"),
        "threat_class": threat_class,
        "confidence_score": round(confidence_score, 4),
        "severity": severity,
        "model_source": {
            "supervised_score": round(supervised_score, 4),
            "anomaly_score": round(anomaly, 4),
            "sequence_score": round(sequence, 4),
            "fired_models": fired_models,
        },
        "evidence": evidence,
        "ingestion_meta": {
            "sensor_id": flow_obj.get("sensor_id", "diode-sensor-01"),
            "capture_interface": flow_obj.get("capture_interface", "lo"),
            "pipeline_version": flow_obj.get("pipeline_version", "1.0.0"),
        },
    }




# ---------------------------------------------------------------------------
# Smoke test — run on a couple of real flows from your collected dataset
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    data_path = SCRIPTS_DIR.parent / "data" / "raw_flows.jsonl"
    if not data_path.exists():
        print(f"[-] No dataset found at {data_path} to smoke-test against.")
        sys.exit(1)

    flows_by_label: dict[str, list[dict]] = {}
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            flows_by_label.setdefault(row.get("collected_label"), []).append(row)

    for label, flows in flows_by_label.items():
        print(f"\n=== {label} (showing up to 2) ===")
        for flow in flows[:2]:
            alert = score_flow(flow)
            print(json.dumps(alert, indent=2))
