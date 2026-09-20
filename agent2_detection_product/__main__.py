import argparse
import json
from pathlib import Path
from .orchestration import DetectionPipeline
from .orchestration.registry import verify_manifest, verify_agent1_release, sha256


def main():
    parser = argparse.ArgumentParser(description="Agent 2 passive V2 replay/streaming consumer")
    parser.add_argument("mode", choices=("replay", "redis"))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release", type=Path, help="trusted Agent 2 manifest with bundle and policy digests")
    parser.add_argument("--agent1-release", type=Path)
    parser.add_argument("--agent1-sha256")
    parser.add_argument("--development", action="store_true", help="allow absent/unapproved models; decisions abstain")
    parser.add_argument("--specialists", type=Path, help="path to directory containing specialist artifacts (C2, botnet, encrypted)")
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument("--checkpoint", default="agent2_detection_product/artifacts/runtime.sqlite3")
    args = parser.parse_args()
    providers, policy, profile = [], None, "development"
    if not args.development and (not args.release or not args.agent1_release):
        parser.error("production requires pinned Agent 1 and Agent 2 releases")
    if args.agent1_release:
        verify_agent1_release(args.agent1_release, args.agent1_sha256)
    if args.release:
        manifest = verify_manifest(args.release, approved=not args.development)
        if not args.development and manifest.get("agent1_manifest_sha256") != args.agent1_sha256:
            parser.error("Agent 2 release was not validated against this Agent 1 release")
        policy_path = manifest["policy"]
        bundle_path = manifest["bundle"]
        if policy_path not in manifest["artifacts"] or bundle_path not in manifest["artifacts"]:
            parser.error("bundle and policy must be covered by release digests")
        policy = json.loads((args.release.parent / policy_path).read_text())
        if not args.development and not policy.get("approved"):
            parser.error("production requires validation-approved thresholds")
        import joblib
        providers.append(joblib.load(args.release.parent / bundle_path))
        profile = sha256(args.release)
    # Load specialist providers (C2, Botnet, Encrypted) if available
    spec_dir = args.specialists or (Path("artifacts/specialists/0.1.0-sim") if Path("artifacts/specialists/0.1.0-sim").is_dir() else None)
    if spec_dir and Path(spec_dir).is_dir():
        from .models.providers import load_specialist_providers
        spec_providers = load_specialist_providers(spec_dir)
        providers.extend(spec_providers)
    drift = None
    if providers and getattr(providers[0], "drift_reference", None):
        from .drift import DriftMonitor
        drift = DriftMonitor(providers[0].drift_reference)
    pipeline = DetectionPipeline(policy=policy, providers=providers, drift=drift)
    if args.mode == "replay":
        if not args.input or not args.output or args.input.resolve() == args.output.resolve():
            parser.error("replay requires distinct --input and --output paths")
        with args.input.open(encoding="utf-8") as source, args.output.open("x", encoding="utf-8") as output:
            for line in source:
                if line.strip():
                    row = json.loads(line)
                    result = pipeline.process(row["observation"], row.get("specialist_scores", []))
                    output.write(json.dumps(result, allow_nan=False) + "\n")
        print(json.dumps(pipeline.stats()))
    else:
        import redis
        from .streaming.worker import run_worker
        run_worker(redis.Redis.from_url(args.redis_url, decode_responses=True), pipeline, checkpoint=args.checkpoint, profile=profile)


if __name__ == "__main__":
    main()
