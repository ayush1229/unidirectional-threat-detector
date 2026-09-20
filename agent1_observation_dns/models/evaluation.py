"""Group-level evaluation partitions and explicit domain challenge cohorts."""
from datetime import datetime
from agent1_observation_dns.ground_truth.splits import assign_partition, validate_sample_splits
from agent1_observation_dns.models.training import prepare_rows, metrics

CHALLENGE_TAGS = ("dictionary", "human_looking", "adversarial", "held_out_family", "held_out_tool")


def split_rows(rows, *, mode="random", seed=0, held_out=(), validation_after=None, test_after=None):
    if mode not in ("random", "time", "family", "tool", "generator"):
        raise ValueError("unsupported evaluation split")
    result = []
    for original in rows:
        row = dict(original)
        if mode == "time":
            if validation_after is None or test_after is None or validation_after >= test_after:
                raise ValueError("ordered time boundaries required")
            timestamp = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
            split = "test" if timestamp >= test_after else "validation" if timestamp >= validation_after else "train"
            group = row["scenario_id"]
        else:
            group = row["scenario_id"] if mode == "random" else row[mode]
            split = "test" if group in held_out else assign_partition(f"{mode}:{group}", seed)
        row.update(split_assignment=split, split_group=f"{mode}:{group}")
        result.append(row)
    # prepare_rows checks normalized duplicate domains and crossing scenario groups.
    return prepare_rows(result)


def evaluate_cohorts(rows, probabilities):
    if len(rows) != len(probabilities):
        raise ValueError("prediction count differs from evaluation row count")
    if any(r["split_assignment"] == "train" for r in rows):
        raise ValueError("evaluation must not contain training rows")
    report = {"all": metrics([r["label"] for r in rows], probabilities)}
    for tag in CHALLENGE_TAGS:
        pairs = [(r, p) for r, p in zip(rows, probabilities) if tag in r.get("tags", [])]
        report[tag] = metrics([r["label"] for r, _ in pairs], [p for _, p in pairs])
    return report
