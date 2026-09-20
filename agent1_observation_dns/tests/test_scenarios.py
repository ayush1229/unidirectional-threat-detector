from datetime import timedelta
import pytest
from agent1_observation_dns.ground_truth.splits import partition_plans, validate_partitions, validate_sample_splits
from agent1_observation_dns.simulation.scenarios import FAMILIES, BENIGN_PROFILES, plan_scenario, generate_frames, release_dataset


@pytest.mark.parametrize("family", FAMILIES)
def test_seeded_scenarios(family):
    plan = plan_scenario(family, 42)
    assert list(generate_frames(plan)) == list(generate_frames(plan))
    assert len(list(generate_frames(plan))) == 32
    assert plan.end > plan.start


@pytest.mark.parametrize("profile", BENIGN_PROFILES)
def test_benign_profiles(profile):
    plan = plan_scenario("BENIGN", 1, profile=profile)
    assert profile in plan.hard_negative_tags
    assert list(generate_frames(plan))


def test_heldout_and_leakage():
    plans = [plan_scenario(family, i) for i, family in enumerate(FAMILIES)]
    split = partition_plans(plans, by="family", held_out=["DGA"])
    assert next(p for p in split if p.family == "DGA").split_assignment == "test"
    with pytest.raises(ValueError):
        validate_partitions([plans[0], plans[0].model_copy(update={"split_assignment": "test" if plans[0].split_assignment != "test" else "train"})])
    with pytest.raises(ValueError):
        partition_plans(plans, by="time", validation_after=plans[0].start+timedelta(seconds=1), test_after=plans[0].end+timedelta(days=1))


def test_dataset_release(tmp_path):
    root = tmp_path / "release"
    release_dataset([plan_scenario("DGA", 9, packets=3)], root)
    assert len(list(root.rglob("manifest.json"))) == 1
    with pytest.raises(FileExistsError):
        release_dataset([], root)
