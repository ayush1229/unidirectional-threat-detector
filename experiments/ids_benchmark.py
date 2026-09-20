"""Fresh offline one-way packet benchmark; frozen current runtime, no fitting.

Each independent episode gets identical PCAP input for every IDS. Truth is
scenario intent, never a packet feature. This is synthetic functional testing,
not evidence of external attack generalization or malicious intent from bytes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import secrets
import time

import dpkt

ROOT = Path(__file__).resolve().parents[1]
LABELS = ('DDoS', 'PORT_SCAN', 'DATA_EXFILTRATION', 'DGA', 'DNS_TUNNEL')
PROFILES = ('ddos_udp', 'ddos_syn', 'scan_fast', 'scan_slow', 'exfil_bulk',
            'exfil_slow', 'dga', 'dns_tunnel', 'benign_web', 'benign_bulk',
            'benign_flash_crowd', 'benign_dns', 'benign_dns_long', 'benign_keepalive')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def packet(ts, src, dst, sport, dport, protocol, payload, flags, sequence):
    from agent1_observation_dns.capture.source import CapturedFrame
    if protocol == 17:
        trans = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        trans.ulen = len(trans)
    else:
        trans = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags,
                             seq=sequence, data=payload)
    ip = dpkt.ip.IP(src=ipaddress.ip_address(src).packed,
                   dst=ipaddress.ip_address(dst).packed, p=protocol, ttl=64, data=trans)
    ip.len = len(ip)
    raw = bytes(dpkt.ethernet.Ethernet(src=b'\x02'*6, dst=b'\x04'*6, type=0x800, data=ip))
    return CapturedFrame(int(ts * 1e9), raw, len(raw))


def generate(output, seed, repeats):
    from agent1_observation_dns.simulation.v2_generator import write_pcap
    from agent1_observation_dns.normalization.packet import normalize
    rng = random.Random(seed)
    (output / 'pcaps').mkdir(parents=True, exist_ok=False)
    episodes = []
    start = datetime.now(timezone.utc).timestamp()
    for rep in range(repeats):
        for profile in PROFILES:
            index = len(episodes)
            eid = f'{index:03d}_{profile}'
            src = f'192.0.2.{10 + index}'
            dst = f'198.51.100.{10 + index}'
            sport = rng.randint(20000, 50000)
            label = ('DDoS' if profile.startswith('ddos') else 'PORT_SCAN' if profile.startswith('scan')
                     else 'DATA_EXFILTRATION' if profile.startswith('exfil') else 'DGA' if profile == 'dga'
                     else 'DNS_TUNNEL' if profile == 'dns_tunnel' else None)
            count = 240 if profile.startswith(('ddos', 'exfil')) or profile in ('benign_bulk', 'benign_flash_crowd') else 60
            gap = (.002 if profile in ('ddos_udp', 'ddos_syn', 'benign_flash_crowd') else
                   .02 if profile in ('scan_fast', 'exfil_bulk', 'benign_bulk') else
                   3 if profile in ('scan_slow', 'exfil_slow', 'benign_keepalive') else .5)
            gap *= rng.uniform(.6, 1.8)
            frames, pairs = [], set()
            t = start + index * 1000
            for i in range(count):
                source = src
                if profile in ('ddos_udp', 'ddos_syn', 'benign_flash_crowd'):
                    source = f'203.0.113.{1 + i % (3 + rep * 3)}'
                dport, proto = 443, 6
                flags = dpkt.tcp.TH_ACK | (dpkt.tcp.TH_PUSH if i % 3 else 0)
                size = rng.choice((40, 128, 512))
                if profile.startswith('scan'):
                    dport, flags, size = 1000 + i, dpkt.tcp.TH_SYN, 0
                elif profile == 'ddos_syn':
                    flags, size = dpkt.tcp.TH_SYN, 0
                elif profile == 'ddos_udp':
                    proto, dport, size = 17, 8080, rng.choice((64, 512, 1200))
                elif profile.startswith('exfil') or profile == 'benign_bulk':
                    size = 1400
                payload = bytes(rng.getrandbits(8) for _ in range(size))
                if profile in ('dga', 'dns_tunnel', 'benign_dns', 'benign_dns_long'):
                    proto, dport = 17, 53
                    if profile == 'dga':
                        name = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(24)) + '.test'
                    elif profile == 'dns_tunnel':
                        name = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz234567') for _ in range(56)) + '.upload.test'
                    elif profile == 'benign_dns_long':
                        name = hashlib.sha256(f'{seed}:{i}'.encode()).hexdigest()[:48] + '.cdn.test'
                    else:
                        name = rng.choice(('www', 'api', 'mail', 'updates')) + '.service.test'
                    payload = bytes(dpkt.dns.DNS(id=i, qd=[dpkt.dns.DNS.Q(name=name)]))
                frames.append(packet(t, source, dst, sport, dport, proto, payload, flags, i * max(size, 1)))
                pairs.add((source, dst))
                t += gap * rng.uniform(.8, 1.2)
            # Audit direction from serialized frames rather than generator intent.
            keys = [normalize(f).key for f in frames]
            directed_pairs = {(k[0], k[1]) for k in keys}
            assert not any((d, s) in directed_pairs for s, d in directed_pairs)
            path = output / 'pcaps' / f'{eid}.pcap'
            write_pcap(frames, path)
            episodes.append({'episode_id': eid, 'profile': profile, 'repeat': rep,
                             'labels': [label] if label else [], 'pcap': str(path.relative_to(output)),
                             'sha256': digest(path), 'packets': len(frames), 'bytes_on_disk': path.stat().st_size,
                             'start': frames[0].timestamp_ns / 1e9, 'end': frames[-1].timestamp_ns / 1e9,
                             'pairs': sorted(directed_pairs), 'sources': sorted({s for s, _ in pairs}),
                             'destinations': [dst], 'reverse_packets': 0})
    save(output / 'episodes.json', episodes)
    save(output / 'corpus_manifest.json', {'seed': seed, 'created_at': datetime.now(timezone.utc).isoformat(),
         'labels': LABELS, 'episodes': len(episodes), 'packets': sum(e['packets'] for e in episodes),
         'disk_bytes': sum(e['bytes_on_disk'] for e in episodes), 'generator_sha256': digest(__file__),
         'truth_sha256': digest(output / 'episodes.json'), 'source': 'fresh synthetic packets; no downloaded dataset',
         'unit': 'one independent scenario episode; max score / any alert across all packets',
         'limitations': ['same generator design family as development; not external generalization',
                        'benign bulk/flash/DNS long hard negatives deliberately overlap attack behavior',
                        'one-way TCP has no server handshake; payload signatures requiring established streams may abstain',
                        'scenario intent labels do not prove application-level malicious content']} )
    return episodes


class RecordedProvider:
    def __init__(self, provider):
        self.provider, self.version, self.last = provider, provider.version, {}

    def score(self, *args):
        self.last = self.provider.score(*args)
        return self.last


def infer(output):
    import joblib
    import torch
    from pipeline_runtime import Publisher, load_config, current_release
    from agent1_observation_dns.replay.pcap import PcapSource
    from agent1_observation_dns.pipeline import ObservationPipeline
    from agent2_detection_product.orchestration import DetectionPipeline
    from agent2_detection_product.orchestration.registry import verify_manifest
    from agent2_detection_product.drift import DriftMonitor
    torch.set_num_threads(2)
    pointer = current_release()
    manifest_path = ROOT / pointer['agent2_release']
    manifest = verify_manifest(manifest_path, approved=False)
    policy = json.loads((manifest_path.parent / manifest['policy']).read_text())
    bundle = joblib.load(manifest_path.parent / manifest['bundle'])
    provider = RecordedProvider(bundle)
    config = load_config()
    relocations = {}
    for key, configured in config.model_paths.items():
        if not Path(configured).is_file():
            colocated = (ROOT / pointer['agent1_config']).parent / Path(configured).name
            if not colocated.is_file():
                raise FileNotFoundError(configured)
            relocations[key] = {'missing_configured_path': configured, 'benchmark_path': str(colocated)}
    if relocations:
        config = config.model_copy(update={'model_paths': {k: relocations[k]['benchmark_path'] if k in relocations else v
                                                       for k, v in config.model_paths.items()}})
    publisher = Publisher(None, config)
    episodes = json.loads((output / 'episodes.json').read_text())
    results = []
    with (output / 'model_events.jsonl').open('x') as stream:
        for episode in episodes:
            started = time.perf_counter()
            raw_peak, eligible_peak, production = {}, {}, set()
            states, reasons = Counter(), Counter()
            drift = DriftMonitor(bundle.drift_reference) if getattr(bundle, 'drift_reference', None) else None
            pipeline = DetectionPipeline(policy=policy, providers=[provider], drift=drift)
            publisher.pipeline = ObservationPipeline(config.model_copy(update={'sensor_id': episode['episode_id']}))

            class Sink:
                def xadd(self, _channel, message, **_kwargs):
                    row = json.loads(message['payload'])
                    result = pipeline.process(row['observation'], row['specialist_scores'])
                    decision = result['decision']
                    for score in row['specialist_scores'] + provider.last.get('scores', []):
                        if score['score_present'] and score['probability'] is not None:
                            label, value = score['label'], float(score['probability'])
                            raw_peak[label] = max(raw_peak.get(label, 0), value)
                    for label, value in decision['label_probabilities'].items():
                        eligible_peak[label] = max(eligible_peak.get(label, 0), value)
                    production.update(decision['labels'])
                    states[decision['decision_state']] += 1
                    reasons.update(decision['reason_codes'])
                    stream.write(json.dumps({'episode_id': episode['episode_id'],
                        'snapshot_kind': row['observation']['snapshot_kind'],
                        'window_complete': row['observation']['history']['window_complete'],
                        'decision': decision, 'raw_scores': row['specialist_scores'] + provider.last.get('scores', [])},
                        allow_nan=False) + '\n')

            publisher.client = Sink()
            for event in publisher.pipeline.run(PcapSource(output / episode['pcap'])):
                publisher.publish(event)
            result = {'episode_id': episode['episode_id'], 'truth': episode['labels'],
                      'raw_peak_scores': raw_peak, 'eligible_peak_scores': eligible_peak,
                      'raw_threshold_labels': sorted(k for k, v in raw_peak.items() if v >= policy['thresholds'][k]),
                      'eligible_threshold_labels': sorted(k for k, v in eligible_peak.items() if v >= policy['thresholds'][k]),
                      'production_labels': sorted(production), 'decision_states': dict(states),
                      'reason_counts': dict(reasons), 'seconds': time.perf_counter() - started,
                      'runtime_stats': pipeline.stats(), 'rejected_packets': publisher.pipeline.rejected_packets}
            results.append(result)
            print(episode['episode_id'], result['raw_threshold_labels'], dict(states), flush=True)
    save(output / 'model_episodes.json', results)
    save(output / 'model_manifest.json', {'current_pointer': pointer, 'policy': policy,
         'agent2_manifest_sha256': digest(manifest_path), 'agent2_artifacts': manifest['artifacts'],
         'agent1_models_sha256': {k: digest(v) for k, v in config.model_paths.items()},
         'bundle_version': bundle.version, 'embedded_specialists': [type(p).__name__ for p in bundle.specialists],
         'mode': 'exact Publisher + ObservationPipeline + CandidateBundle + DetectionPipeline; isolated state per episode',
         'raw_threshold_scores_note': 'diagnostic only; ignores runtime calibration/readiness/approval gates; not production alerts',
         'production_approval': policy.get('approved'), 'generator_sha256': digest(__file__)})
    save(output / 'runtime_path_relocations.json', {'exact_current_startup': 'fails missing configured model files' if relocations else 'works',
                                                 'benchmark_only_relocations': relocations})


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--seed', type=int, default=None)
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--stage', choices=('generate', 'infer', 'all'), default='all')
    args = p.parse_args()
    if args.stage in ('generate', 'all'):
        args.output.mkdir(parents=True, exist_ok=True)
        generate(args.output, args.seed if args.seed is not None else secrets.randbits(32), args.repeats)
    if args.stage in ('infer', 'all'):
        infer(args.output)


if __name__ == '__main__':
    main()
