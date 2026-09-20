"""Partition scenario plans before generation; validate provenance isolation."""
import hashlib
from collections import defaultdict


def assign_partition(group: str, seed: int = 0) -> str:
    number = int.from_bytes(hashlib.sha256(f"{seed}:{group}".encode()).digest()[:8], "big") / 2**64
    return "train" if number < .7 else "validation" if number < .85 else "test"


def partition_plans(plans, *, by="scenario_id", seed=0, held_out=(), validation_after=None, test_after=None):
    if by not in ("scenario_id", "generator", "family", "tool", "time"):
        raise ValueError("unsupported partition key")
    result = []
    for plan in plans:
        if by == "time":
            if validation_after is None or test_after is None or validation_after >= test_after:
                raise ValueError("time split needs ordered boundaries")
            if plan.start < validation_after <= plan.end or plan.start < test_after <= plan.end:
                raise ValueError("scenario crosses a split boundary")
            split = "test" if plan.start >= test_after else "validation" if plan.start >= validation_after else "train"
            group = f"time:{split}"
        else:
            group = f"{by}:{getattr(plan, by)}"
            split = "test" if getattr(plan, by) in held_out else assign_partition(group, seed)
        result.append(plan.model_copy(update={"split_assignment": split, "split_group": group}))
    validate_partitions(result)
    return result


def validate_partitions(manifests):
    seen = defaultdict(set)
    for manifest in manifests:
        # Same generator/seed is shared random provenance, even when identifiers differ.
        keys = [("scenario", manifest.scenario_id), ("group", manifest.split_group),
                ("seed", manifest.generator, manifest.seed)]
        for key in keys:
            seen[key].add(manifest.split_assignment)
            if len(seen[key]) > 1:
                raise ValueError(f"cross-partition provenance leakage: {key[0]}")


def validate_sample_splits(rows):
    """Reject identical content and provenance crossing any model-training split."""
    seen = {}
    for row in rows:
        for key in (("content", row["content_hash"]), ("scenario", row["scenario_id"]),
                    ("group", row["split_group"])):
            if key in seen and seen[key] != row["split_assignment"]:
                raise ValueError("sample leakage across partitions")
            seen[key] = row["split_assignment"]
