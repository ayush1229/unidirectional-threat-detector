from pathlib import Path
import json
from agent1_observation_dns import __version__
from agent1_observation_dns.contracts import ObservationEnvelope, SpecialistScore, ScenarioRelease


def test_contract_schemas_are_versioned():
    root = Path(__file__).parents[1] / "contracts"
    assert json.loads((root/"observation/schema.json").read_text())["properties"]["schema_version"]["const"] == "2.0.0"
    assert json.loads((root/"specialist_score/schema.json").read_text())["properties"]["schema_version"]["const"] == "2.0.0"
    assert json.loads((root/"scenario_release/schema.json").read_text())["properties"]["schema_version"]["const"] == "1.0.0"


def test_release_manifest():
    release = Path(__file__).parents[1] / "artifacts" / "release.json"
    manifest = json.loads(release.read_text(encoding="utf-8"))
    assert manifest["agent1_version"] == __version__
    assert manifest["feature_schema_version"] == "2.0.0"
    assert manifest["contracts"] == {"observation": "2.0.0", "specialist_score": "2.0.0", "scenario_release": "1.0.0"}
    assert manifest["trained_models"] == []
