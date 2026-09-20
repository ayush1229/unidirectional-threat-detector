import pytest
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.models.common import absent
from agent1_observation_dns.contracts import SpecialistScore
from agent1_observation_dns.models.dns_specialist_fusion.fusion import fuse
from agent1_observation_dns.routing_dns.router import TunnelSpecialist


class Stub:
    def __init__(self, probability=.1, name="DNS_TUNNEL_FAST"):
        self.calls = 0
        self.probability, self.name = probability, name

    def predict(self, event_id, domain, context):
        self.calls += 1
        return SpecialistScore(event_id=event_id, specialist=self.name, probability=self.probability,
                               score_present=True, reason_codes=["TEST_ONLY"], model_version="fixture")


def test_early_exit_missing_not_zero():
    fast, byte = Stub(), Stub(.8, "DNS_TUNNEL_BYTECNN")
    result = TunnelSpecialist(Settings(audit_fraction=0), fast=fast, byte=byte).predict("e", "www.example.test")
    component = result.evidence["components"][1]
    assert fast.calls == 1 and byte.calls == 0
    assert component["probability"] is None and not component["score_present"]
    assert component["reason_codes"] == ["EARLY_EXIT"]
    assert result.probability == .1


@pytest.mark.parametrize("settings,domain,probability", [
    ({}, "example.test", .5), ({}, "x"*50+".test", .1),
    ({"audit_fraction": 1}, "example.test", .1), ({"research_evaluation": True}, "example.test", .1)])
def test_expensive_triggers(settings, domain, probability):
    settings.setdefault("audit_fraction", 0)
    byte = Stub(.8, "DNS_TUNNEL_BYTECNN")
    result = TunnelSpecialist(Settings(**settings), fast=Stub(probability), byte=byte).predict("e", domain)
    assert byte.calls == 1 and result.score_present


def test_fusion_all_missing():
    result = fuse("e", [absent("e", "a", "CHECKPOINT_ABSENT")])
    assert result.probability is None and result.uncertainty is None
    with pytest.raises(ValueError):
        fuse("wrong", [absent("e", "a", "CHECKPOINT_ABSENT")])


def test_sequence_masks_and_shapes():
    pytest.importorskip("torch")
    from agent1_observation_dns.models.dns_tunnel_bytecnn.model import ByteCNN, ByteBranch, encode_bytes
    from agent1_observation_dns.models.dns_tunnel_sequence.model import MetadataSequence, SequenceBranch, encode_sequences
    encoded, lengths = encode_sequences([[[20, 3.1, 1, 60, None, None], [22, 3, 16, 70, .1, 0]]])
    assert encoded[0,0,5] == 0 and encoded[0,0,11] == 0
    assert encoded[0,1,5] == 0 and encoded[0,1,11] == 1
    assert MetadataSequence()(encoded, lengths).shape == (1,)
    assert ByteCNN()(encode_bytes(["example.test"])).shape == (1,)
    assert not ByteBranch().predict("e", "example.test").score_present
    assert SequenceBranch().predict("e", "example.test", {}).reason_codes == ["INSUFFICIENT_DNS_HISTORY"]
