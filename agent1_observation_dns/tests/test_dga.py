import math
import pytest
from agent1_observation_dns.models.common import context_vector
from agent1_observation_dns.models.dga_char_attention.specialist import DGASpecialist
from agent1_observation_dns.models.training import prepare_rows, train_tabular


def rows():
    return [{"domain": domain, "label": i % 2, "split_assignment": "train" if i < 6 else "test",
             "scenario_id": str(i), "split_group": str(i), "family": "test-fixture", "tool": "fixture",
             "event_time": "2026-01-01T00:00:00Z"}
            for i, domain in enumerate(("www.alpha.test", "xz172zn.test", "mail.beta.test", "q8zc37p.test",
                                       "docs.gamma.test", "qxy983k.test", "shop.delta.test", "zzxp23n.test"))]


def test_context_masks():
    vector = context_vector("www.example.test", {})
    assert math.isnan(vector[7]) and vector[-9] == 0
    assert context_vector("www.example.test", {"response_count": 0})[7] == 0


def test_baseline_and_missing():
    specialist = DGASpecialist()
    result = specialist.predict("e", "x72kmxz9.test")
    assert result.score_present and result.uncertainty == 1
    assert "UNTRAINED_UNCALIBRATED_BASELINE" in result.reason_codes
    assert not DGASpecialist(baseline=False).predict("e", "www.example.test").score_present
    assert not specialist.predict("e", None).applicable


def test_training_leakage():
    data = rows()
    data[-1]["domain"] = data[0]["domain"]
    with pytest.raises(ValueError):
        prepare_rows(data)


def test_tabular_training_roundtrip(tmp_path):
    pytest.importorskip("xgboost")
    from agent1_observation_dns.models.dga_context_xgb.model import ContextBranch
    output = tmp_path / "dga.json"
    report = train_tabular(rows(), output, estimators=2)
    assert report["train_rows"] == 6 and report["evaluation"]["test"]["count"] == 2
    result = ContextBranch(output).predict("e", "www.example.test", {})
    assert result.score_present


def test_character_untrained_and_shape():
    torch = pytest.importorskip("torch")
    from agent1_observation_dns.models.dga_char_attention.model import CharacterAttention, CharacterBranch, encode_domains
    assert not CharacterBranch().predict("e", "example.test").score_present
    assert CharacterAttention()(encode_domains(["example.test", "x7z.test"])).shape == (2,)
