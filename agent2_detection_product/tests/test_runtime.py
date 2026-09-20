from copy import deepcopy
import json
import pytest
from ..contracts import observation, feature, ContractError, specialist
from ..multilabel_decision import DecisionEngine
from ..orchestration import DetectionPipeline
from ..correlation import IncidentCorrelator
from ..state_detection import TTLStore, TemporalHistory
from ..streaming.worker import DurableOutbox
from ..replay_memory import ReplayMemory
from ..adaptation import BenignBaselines, adaptation_action, regression_gate
from ..gating import audit_sample
from .fixtures import envelope, policy, score, mature_context


def test_null_is_not_observed_zero_and_masks_override_numeric_values():
    env = envelope()
    env["features"]["dns"]["nxdomain_ratio"] = 0
    env["features"]["flow"]["byte_count"] = 0
    assert feature(observation(env), "flow.byte_count") == (0, True)
    assert feature(env, "dns.nxdomain_ratio") == (None, False)
    env["feature_availability"] = {"flow.byte_count": False}
    assert feature(env, "flow.byte_count") == (None, False)


@pytest.mark.parametrize("change", [{"schema_version": "1.0.0"}, {"event_time": "2026-09-17T00:00:00"}, {"protocol": "ICMP"}])
def test_bad_contract_rejected(change):
    with pytest.raises(ContractError):
        observation({**envelope(), **change})


def test_specialists_cannot_cross_events_or_ownership():
    env = envelope(protocol="DNS")
    value = score(env, "DGA", .9)
    assert specialist(value, env)["probability"] == .9
    value["event_id"] = "different"
    with pytest.raises(ContractError):
        specialist(value, env)
    with pytest.raises(ContractError):
        specialist(score(env, "BOTNET_HOST", .9), env)


def test_missing_models_and_unvalidated_policy_abstain():
    env = envelope()
    assert DetectionPipeline().process(env)["decision"]["decision_state"] == "UNCERTAIN"
    result = DecisionEngine().decide(env, [score(env, "DDoS", .99)])
    assert result["decision_state"] == "UNCERTAIN"
    assert "POLICY_NOT_VALIDATED" in result["reason_codes"]


def test_four_states_and_multi_label_evidence_gates():
    env, context = envelope(), mature_context()
    engine = DecisionEngine(policy())
    result = engine.decide(env, [score(env, "C2_BEACONING", .97), score(env, "BOTNET_HOST", .92)], context=context)
    assert result["decision_state"] == "KNOWN_ATTACK"
    assert set(result["labels"]) == {"C2_BEACONING", "BOTNET_HOST"}
    assert result["primary_class"] == "C2_BEACONING"
    assert engine.decide(env, [score(env, "C2_BEACONING", .99)])["decision_state"] == "UNCERTAIN"
    assert engine.decide(env, [], {"if_score": .99, "calibrated": True})["decision_state"] == "UNCERTAIN"
    assert engine.decide(env, [], {"if_score": .95, "energy": .95, "calibrated": True})["decision_state"] == "UNKNOWN"
    benign_scores = [score(env, label, .01) for label in policy()["required_coverage"]]
    assert engine.decide(env, benign_scores, {"ae_error": .01, "energy": .01, "calibrated": True}, context)["decision_state"] == "BENIGN"
    env["visibility"]["feature_availability_ratio"] = .2
    assert engine.decide(env, [score(env, "DDoS", .99)])["decision_state"] == "UNCERTAIN"


def test_conflicting_experts_abstain_without_meta():
    env = envelope()
    result = DecisionEngine(policy()).decide(env, [score(env, "DDoS", .99, "one"), score(env, "DDoS", .01, "two")])
    assert result["decision_state"] == "UNCERTAIN"
    assert "FUSION_MODEL_REQUIRED" in result["reason_codes"]


def test_bounded_state_retry_and_late_events():
    store = TTLStore(ttl=10, capacity=2)
    for n in range(3):
        store.put(str(n), n, n)
    assert len(store) == 2
    assert store.get("2", 20) is None
    history = TemporalHistory(samples=3)
    for t in (1, 2, 3, 2, 4):
        sequence = history.observe("host", t)
    assert sequence == [2, 3, 4]
    pipeline = DetectionPipeline()
    first = pipeline.process(envelope())
    second = pipeline.process(envelope())
    assert second["duplicate"]
    assert first["decision"] == second["decision"]
    changed = envelope()
    changed["features"]["flow"]["byte_count"] += 1
    with pytest.raises(ValueError):
        pipeline.process(changed)


def test_incident_preserves_chain_and_deduplicates():
    engine, correlator = DecisionEngine(policy()), IncidentCorrelator()
    first_env = envelope(protocol="DNS")
    first = engine.decide(first_env, [score(first_env, "DGA", .95)])
    update = correlator.process(first)[0]
    assert update["count"] == 1
    assert correlator.process(first) == []
    second_env = envelope("second", 60)
    second = engine.decide(second_env, [score(second_env, "C2_BEACONING", .96), score(second_env, "BOTNET_HOST", .95)], context=mature_context())
    update = correlator.process(second)[0]
    assert update["count"] == 2
    assert set(update["labels"]) == {"DGA", "C2_BEACONING", "BOTNET_HOST"}
    assert update["severity"] == "CRITICAL"
    assert "SUSPECTED_COMPROMISE_CHAIN" in update["reason_codes"]
    assert correlator.close_expired(2e9)[0]["action"] == "close"


def test_outbox_recovers_before_ack_and_checkpoint_restores_state(tmp_path):
    path = tmp_path / "checkpoint.sqlite3"
    pipeline = DetectionPipeline()
    box = DurableOutbox(path, pipeline)
    result = box.prepare("1-0", {"observation": envelope()})
    box.db.close()
    recovered = DetectionPipeline()
    box = DurableOutbox(path, recovered)
    assert box.prepare("1-0", {}) == result
    assert recovered.metrics["processed_total"] == 1
    assert recovered.process(envelope())["duplicate"]
    before = json.dumps(recovered.checkpoint())
    with pytest.raises(ContractError):
        box.prepare("2-0", {"observation": {}})
    assert json.dumps(recovered.checkpoint()) == before
    box.delivered("1-0")
    assert box.db.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
    box.db.close()


def test_replay_and_adaptation_never_self_train_test_or_suspicious_data(tmp_path):
    memory = ReplayMemory(per_task=2)
    with pytest.raises(ValueError):
        memory.add("benign", {"split": "test", "verified": True})
    for i in range(5):
        memory.add("benign", {"split": "train", "verified": True, "value": i})
    assert len(memory.tasks["benign"]) == 2
    memory.publish(tmp_path / "memory.json")
    with pytest.raises(FileExistsError):
        memory.publish(tmp_path / "memory.json")
    uncertain = DetectionPipeline().process(envelope())["decision"]
    assert not BenignBaselines().update("host", {"bytes": 1}, uncertain, 0)
    assert adaptation_action("SEVERE") == "ANALYST_REVIEW_NO_TRAINING"
    assert not regression_gate({"DDoS": {"recall": .99, "ece": .01}}, {"DDoS": {"recall": .8, "ece": .02}})


def test_audit_sampling_is_stable():
    assert audit_sample("s", "id", 1) is True
    assert audit_sample("s", "id", 0) is False
    assert audit_sample("s", "id") == audit_sample("s", "id")


def test_ntp_contextual_gating_excludes_c2_beaconing():
    from ..gating import gates
    # Normal UDP traffic is applicable
    udp_env = envelope(protocol="UDP")
    ctx = mature_context()
    assert gates(udp_env, ctx)["C2_BEACONING"]["applicable"] is True
    assert gates(udp_env, ctx)["C2_BEACONING"]["ready"] is True

    # NTP UDP traffic (port 123 in destination or route hints) is NOT applicable
    ntp_env1 = envelope(protocol="UDP")
    ntp_env1["entity_keys"]["destination"] = "198.51.100.1:123"
    assert gates(ntp_env1, ctx)["C2_BEACONING"]["applicable"] is False
    assert gates(ntp_env1, ctx)["C2_BEACONING"]["ready"] is False
    assert gates(ntp_env1, ctx)["C2_BEACONING"]["reason"] == "NOT_APPLICABLE"

    ntp_env2 = envelope(protocol="UDP")
    ntp_env2["route_hints"]["ntp"] = True
    assert gates(ntp_env2, ctx)["C2_BEACONING"]["applicable"] is False
    assert gates(ntp_env2, ctx)["C2_BEACONING"]["ready"] is False

