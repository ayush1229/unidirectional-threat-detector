"""Offline-first Agent 1 command line. All output files are explicitly selected."""
import argparse
import json
from pathlib import Path

from agent1_observation_dns.configs import Settings
from agent1_observation_dns.pipeline import ObservationPipeline
from agent1_observation_dns.replay.pcap import PcapSource
from agent1_observation_dns.observability import configure_logging


def main():
    parser = argparse.ArgumentParser(description="Agent 1 passive observation and DNS evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("pcap")
    replay.add_argument("output")
    replay.add_argument("--config")
    replay.add_argument("--specialists", action="store_true")
    scenario = commands.add_parser("scenario")
    scenario.add_argument("output")
    scenario.add_argument("--seed", type=int, default=42)
    scenario.add_argument("--family", default="BENIGN")
    scenario.add_argument("--profile", default="dns")
    scenario_v2 = commands.add_parser("scenario-v2")
    scenario_v2.add_argument("output")
    scenario_v2.add_argument("--family", default="benign_mixed")
    scenario_v2.add_argument("--variant", default="default")
    scenario_v2.add_argument("--seed", type=int, default=42)
    scenario_v2.add_argument("--environment", default="environment_A")
    scenario_v2.add_argument("--split", choices=("train", "validation", "test"), default="train")
    train = commands.add_parser("train")
    train.add_argument("dataset", help="JSONL with explicit partitions and provenance")
    train.add_argument("output")
    train.add_argument("--architecture", required=True, choices=("dga_char_attention", "dga_context_xgb", "dns_tunnel_fast_gbdt", "dns_tunnel_bytecnn", "dns_tunnel_sequence"))
    train.add_argument("--seed", type=int, default=0)
    train.add_argument("--epochs", type=int, default=5)
    args = parser.parse_args()
    configure_logging()
    if args.command == "replay":
        config = Settings.load(args.config) if args.config else Settings()
        pipeline = ObservationPipeline(config)
        if args.specialists:
            from agent1_observation_dns.models.dga_char_attention.specialist import DGASpecialist
            from agent1_observation_dns.routing_dns.router import TunnelSpecialist
            character = context = None
            if config.model_paths.get("dga_char_attention"):
                from agent1_observation_dns.models.dga_char_attention.model import CharacterBranch
                character = CharacterBranch(config.model_paths["dga_char_attention"])
            if config.model_paths.get("dga_context_xgb"):
                from agent1_observation_dns.models.dga_context_xgb.model import ContextBranch
                context = ContextBranch(config.model_paths["dga_context_xgb"])
            dga, tunnel = DGASpecialist(character, context), TunnelSpecialist(config)
        with Path(args.output).open("x", encoding="utf-8") as output:
            for event in pipeline.run(PcapSource(args.pcap, config.max_frame_bytes)):
                output.write(event.model_dump_json()+"\n")
                if args.specialists:
                    field = event.features.dns.get("query_name")
                    domain = field.value if field and field.available else None
                    for result in (dga.predict(event.event_id, domain, event.features.dns),
                                   tunnel.predict(event.event_id, domain, {**event.features.dns, "graph": pipeline.graph.structural_snapshot()})):
                        output.write(result.model_dump_json()+"\n")
    elif args.command == "scenario":
        from agent1_observation_dns.simulation.scenarios import plan_scenario, release_dataset
        release_dataset([plan_scenario(args.family, args.seed, profile=args.profile)], args.output)
    elif args.command == "scenario-v2":
        from agent1_observation_dns.simulation.registry import training_scenario
        from agent1_observation_dns.simulation.v2_generator import release_scenario
        spec = training_scenario(args.family, seed=args.seed, variant=args.variant, environment=args.environment,
                                 split_assignment=args.split)
        print(json.dumps(release_scenario(spec, args.output), indent=2))
    else:
        from agent1_observation_dns.models.training import train_neural, train_tabular
        with Path(args.dataset).open(encoding="utf-8") as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
        if args.architecture in ("dga_context_xgb", "dns_tunnel_fast_gbdt"):
            report = train_tabular(rows, args.output, architecture=args.architecture, seed=args.seed)
        else:
            report = train_neural(rows, args.output, architecture=args.architecture, seed=args.seed, epochs=args.epochs)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
