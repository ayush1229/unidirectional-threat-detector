import pytest
from pydantic import ValidationError

from agent1_observation_dns.configs import Settings
from agent1_observation_dns.contracts import Measurement, SpecialistScore, measured


def test_missing_is_not_zero():
    assert measured(None).model_dump() == {
        "value": None, "available": False, "applicable": True, "reason": "NOT_OBSERVED"}
    assert measured(0).available
    with pytest.raises(ValidationError):
        Measurement(value=0, available=False)


def test_skipped_score():
    score = SpecialistScore(event_id="e", specialist="bytecnn", reason_codes=["EARLY_EXIT"], model_version="untrained")
    assert score.probability is None and not score.score_present
    with pytest.raises(ValidationError):
        SpecialistScore(event_id="e", specialist="bytecnn", probability=0,
                        reason_codes=["EARLY_EXIT"], model_version="untrained")


@pytest.mark.parametrize("kwargs", [{"windows_s": [5, 1]}, {"flow_ttl_s": 0},
                                    {"max_flows": 0}, {"suspicious_low": .9, "suspicious_high": .1}])
def test_config_validation(kwargs):
    with pytest.raises(ValidationError):
        Settings(**kwargs)
