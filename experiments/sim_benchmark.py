"""
experiments/sim_benchmark.py — Full simulation benchmark for AI-Threat Detector.

Runs all supported simulation families through:
  1. AI-Threat Detector (core bundle + ALL specialist models)
  2. Snort / Suricata / Zeek custom behavioral rules
     (IDS-applicable families only: DDoS, PORT_SCAN, EXFIL, DGA, DNS_TUNNEL)

Usage:
    python -m experiments.sim_benchmark \
        --output artifacts/experiments/sim-benchmark-YYYYMMDD \
        --tools-root artifacts/benchmarks/ids-20260920/tools/root \
        --specialists artifacts/specialists/0.1.0-sim
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import torch
import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]

FAMILIES = [
    ('ddos',               ['DDoS'],                                'ids'),
    ('port_scan',          ['PORT_SCAN'],                           'ids'),
    ('slow_scan',          ['PORT_SCAN'],                           'ids'),
    ('exfiltration',       ['DATA_EXFILTRATION'],                   'ids'),
    ('low_slow_exfiltration', ['DATA_EXFILTRATION'],                'ids'),
    ('dga',                ['DGA'],                                 'ids'),
    ('dns_tunnel',         ['DNS_TUNNEL'],                          'ids'),
    ('low_rate_dns_tunnel',['DNS_TUNNEL'],                          'ids'),
    ('c2',                 ['C2_BEACONING'],                        'specialist'),
    ('botnet',             ['BOTNET_HOST', 'BOTNET_COORDINATION'],  'specialist'),
    ('encrypted_malware',  ['ENCRYPTED_MALWARE'],                   'specialist'),
    ('benign_mixed',       [],                                      'ids'),
]

ALL_LABELS = [
    'DDoS', 'PORT_SCAN', 'DATA_EXFILTRATION', 'DGA',
    'DNS_TUNNEL', 'C2_BEACONING', 'BOTNET_HOST',
    'BOTNET_COORDINATION', 'ENCRYPTED_MALWARE',
]
IDS_LABELS = ['DDoS', 'PORT_SCAN', 'DATA_EXFILTRATION', 'DGA', 'DNS_TUNNEL']

RULES = (
    'alert udp any any -> any !53 (msg:"BENCH DDoS UDP"; detection_filter:track by_dst,count 100,seconds 1; sid:9000001; rev:1;)\n'
    'alert tcp any any -> any any (msg:"BENCH DDoS SYN"; flags:S; flow:stateless; detection_filter:track by_dst,count 100,seconds 1; sid:9000002; rev:1;)\n'
    'alert tcp any any -> any any (msg:"BENCH scan SYN"; flags:S; flow:stateless; detection_filter:track by_src,count 20,seconds 60; sid:9000003; rev:1;)\n'
    'alert tcp any any -> any any (msg:"BENCH exfil bulk"; flow:stateless; dsize:>1000; detection_filter:track by_src,count 100,seconds 60; sid:9000004; rev:1;)\n'
    'alert udp any any -> any 53 (msg:"BENCH DGA proxy"; byte_test:1,>,19,12; byte_test:1,<,50,12; sid:9000005; rev:1;)\n'
    'alert udp any any -> any 53 (msg:"BENCH DNS tunnel proxy"; byte_test:1,>,49,12; byte_test:1,<,64,12; sid:9000006; rev:1;)\n'
)
SID_MAP = {9000001: 'DDoS', 9000002: 'DDoS', 9000003: 'PORT_SCAN',
           9000004: 'DATA_EXFILTRATION', 9000005: 'DGA', 9000006: 'DNS_TUNNEL'}

ZEEK_SCRIPT = r"""
@load base/protocols/dns
module IDSBench;
global flood: table[addr, count] of count &default=0;
global syns: table[addr, count] of count &default=0;
global bulk: table[addr, count] of count &default=0;
global emitted: set[string];
function report(label: string) {
  if (label !in emitted) { add emitted[label]; print fmt("IDSBENCH %s", label); }
}
event new_packet(c: connection, p: pkt_hdr) {
  if (!p?$ip) return;
  local one = double_to_count(floor(time_to_double(network_time())));
  local minute = double_to_count(floor(time_to_double(network_time()) / 60.0));
  local syn = p?$tcp && p$tcp$flags == 2;
  if (syn || (p?$udp && p$udp$dport != 53/udp)) {
    ++flood[p$ip$dst, one]; if (flood[p$ip$dst, one] > 100) report("DDoS"); }
  if (syn) {
    ++syns[p$ip$src, minute]; if (syns[p$ip$src, minute] > 20) report("PORT_SCAN"); }
  if (p?$tcp && p$tcp$dl > 1000) {
    ++bulk[p$ip$src, minute]; if (bulk[p$ip$src, minute] > 100) report("DATA_EXFILTRATION"); }
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
  local parts = split_string(query, /\./);
  if (|parts| == 0) return;
  local n = |parts[0]|;
  if (n >= 20 && n < 50) report("DGA");
  if (n >= 50 && n < 64) report("DNS_TUNNEL");
}
"""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')

def env_for(root):
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = ':'.join([
        str(root / 'lib/x86_64-linux-gnu'),
        str(root / 'usr/lib/x86_64-linux-gnu'),
        str(root / 'usr/lib/x86_64-linux-gnu/dpdk/pmds-24.0'),
        str(root / 'opt/zeek/lib'),
    ])
    zeek = root / 'opt/zeek'
    env['ZEEKPATH'] = ':'.join([
        str(zeek / 'share/zeek'), str(zeek / 'share/zeek/policy'),
        str(zeek / 'share/zeek/site'), str(zeek / 'share/zeek/builtin-plugins'),
    ])
    env['ZEEK_PLUGIN_PATH'] = str(zeek / 'lib/zeek/plugins')
    return env

def binary_metrics(truth, predicted):
    tp = sum(a and b for a, b in zip(truth, predicted))
    fp = sum(not a and b for a, b in zip(truth, predicted))
    fn = sum(a and not b for a, b in zip(truth, predicted))
    tn = sum(not a and not b for a, b in zip(truth, predicted))
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': round(tp / max(tp + fp, 1), 4),
            'recall': round(tp / max(tp + fn, 1), 4),
            'f1': round(2 * tp / max(2 * tp + fp + fn, 1), 4),
            'fpr': round(fp / max(fp + tn, 1), 4),
            'accuracy': round((tp + tn) / max(len(truth), 1), 4)}


# ── Phase 1: Generate simulation corpus ──────────────────────────────────────

def generate(output: Path, seed: int, duration_s: int = 120):
    from agent1_observation_dns.simulation.registry import training_scenario
    from agent1_observation_dns.simulation.v2_generator import generate_frames, write_pcap
    from agent1_observation_dns.pipeline import ObservationPipeline
    from agent1_observation_dns.configs import Settings

    pcap_dir = output / 'pcaps'
    pcap_dir.mkdir(parents=True, exist_ok=True)
    (output / 'observations').mkdir(parents=True, exist_ok=True)
    config = Settings()
    episodes = []
    corpus_bytes = 0

    for i, (family, truth_labels, tier) in enumerate(FAMILIES):
        print(f'  [{i+1}/{len(FAMILIES)}] {family}...', flush=True)
        spec = training_scenario(family, seed=seed + i, split_assignment='test')
        phases = tuple(replace(p, start_s=5, end_s=max(10, duration_s - 1)) for p in spec.phases)
        spec = replace(spec, duration_s=duration_s, phases=phases,
                       start=datetime(2026, 1, 1, tzinfo=timezone.utc))

        pipeline = ObservationPipeline(config.model_copy(update={'sensor_id': f'sim_{family}'}))
        frames = list(generate_frames(spec))
        pcap_path = pcap_dir / f'{i:02d}_{family}.pcap'
        write_pcap(frames, pcap_path)

        observations = [e.model_dump(mode='json') for e in pipeline.run(iter(frames))]
        obs_path = output / 'observations' / f'{i:02d}_{family}.jsonl'
        obs_path.write_text('\n'.join(json.dumps(o) for o in observations) + '\n')

        sz = pcap_path.stat().st_size
        corpus_bytes += sz
        episodes.append({
            'episode_id': f'{i:02d}_{family}',
            'family': family, 'tier': tier, 'truth': truth_labels,
            'pcap': f'pcaps/{pcap_path.name}',
            'observations': f'observations/{obs_path.name}',
            'observation_count': len(observations),
            'sha256': digest(pcap_path),
            'bytes_on_disk': sz,
            'duration_s': duration_s, 'seed': seed + i,
        })
        print(f'    {family}: {len(frames)} frames, {len(observations)} obs, {sz:,}b', flush=True)

    save(output / 'episodes.json', episodes)
    save(output / 'corpus_manifest.json', {
        'seed': seed, 'created_at': datetime.now(timezone.utc).isoformat(),
        'families': len(FAMILIES), 'all_labels': ALL_LABELS,
        'ids_labels': IDS_LABELS, 'duration_s_per_episode': duration_s,
        'corpus_bytes': corpus_bytes, 'source': 'simulation framework (not external dataset)',
    })
    print(f'  Done: {len(episodes)} episodes, {corpus_bytes:,} bytes', flush=True)
    return episodes


# ── Phase 2: AI-Threat Detector inference ────────────────────────────────────

def infer(output: Path, specialists_dir: Path):
    from pipeline_runtime import load_config, current_release
    from agent1_observation_dns.replay.pcap import PcapSource
    from agent1_observation_dns.pipeline import ObservationPipeline
    from agent1_observation_dns.models.dns_tunnel_graphsage.model import GraphBranch
    from agent2_detection_product.orchestration import DetectionPipeline
    from agent2_detection_product.orchestration.registry import verify_manifest
    from agent2_detection_product.models.providers import C2Provider, BotnetProvider, EncryptedProvider
    from agent2_detection_product.models.c2_temporal_tcn_gru import TemporalCandidate
    from agent2_detection_product.models.c2_fusion import C2Fusion
    from agent2_detection_product.models.botnet_gnn import GraphSAGE
    from xgboost import XGBClassifier

    torch.set_num_threads(2)

    pointer = current_release()
    manifest_path = ROOT / pointer['agent2_release']
    manifest = verify_manifest(manifest_path, approved=False)
    policy = json.loads((manifest_path.parent / manifest['policy']).read_text())
    bundle = joblib.load(manifest_path.parent / manifest['bundle'])

    spec_manifest = json.loads((specialists_dir / 'manifest.json').read_text())
    spec_version = spec_manifest.get('version', '0.1.0-sim')

    # C2 specialist
    from agent2_detection_product.models.c2_cthmm import ContinuousTimeHMM
    cthmm = joblib.load(specialists_dir / 'cthmm.pkl')
    gru = TemporalCandidate(features=2, kind='gru', hidden=32)
    gru.load_state_dict(torch.load(specialists_dir / 'temporal_gru.pt', weights_only=True))
    gru.eval()
    c2_xgb = XGBClassifier()
    c2_xgb.load_model(str(specialists_dir / 'c2_fusion.json'))
    c2_fusion = C2Fusion()
    c2_fusion.models = {'C2_BEACONING': c2_xgb}
    c2_cal = joblib.load(specialists_dir / 'c2_calibrator.pkl')
    c2_prov = C2Provider(cthmm, gru, c2_fusion, c2_cal, spec_version)

    # Botnet specialist
    gnn_state = torch.load(specialists_dir / 'botnet_gnn.pt', weights_only=True)
    in_f = gnn_state['first.weight'].shape[1] // 2
    hidden = gnn_state['first.weight'].shape[0]
    dim = gnn_state['second.weight'].shape[0]
    gnn = GraphSAGE(features=in_f, hidden=hidden, dimensions=dim)
    gnn.load_state_dict(gnn_state)
    gnn.eval()
    bot_tree = joblib.load(specialists_dir / 'botnet_tree.pkl')
    bot_scaler = joblib.load(specialists_dir / 'botnet_scaler.pkl')
    # Botnet calibrators: attempt to load from bundle, fall back to c2_cal
    bot_cals = {lbl: bundle.calibrators.get(lbl, c2_cal) for lbl in ('BOTNET_HOST', 'BOTNET_COORDINATION')}
    bot_prov = BotnetProvider(gnn, bot_tree, bot_scaler, bot_cals, spec_version)

    # Encrypted malware specialist
    enc_cal = joblib.load(specialists_dir / 'encrypted_calibrator.pkl')
    enc_xgb = XGBClassifier()
    enc_xgb.load_model(str(specialists_dir / 'encrypted_malware.json'))

    class _Model:
        def predict(self, X):
            return enc_xgb.predict_proba(X)[:, [1]]

    class _Prep:
        def transform(self, envs):
            from agent2_detection_product.contracts import feature as feat
            rows, masks = [], []
            for env in envs:
                row, mask = [], []
                for key in ('flow.packet_count', 'flow.byte_count', 'flow.duration_s',
                            'flow.pps', 'flow.bps', 'flow.mean_payload_size'):
                    v, ok = feat(env, key)
                    row.append(float(v) if (ok and v is not None) else 0.0)
                    mask.append(float(ok))
                rows.append(row); masks.append(mask)
            return np.array(rows, dtype=np.float32), np.array(masks, dtype=np.float32)

    enc_prov = EncryptedProvider(_Prep(), _Model(), enc_cal, spec_version)

    # DNS GraphSAGE (Agent1 specialist)
    dns_gs = GraphBranch.load(specialists_dir / 'dns_graphsage.pt')

    config = load_config()
    for key, p in list(config.model_paths.items()):
        if not Path(p).is_file():
            colocated = (ROOT / pointer['agent1_config']).parent / Path(p).name
            if colocated.is_file():
                config = config.model_copy(update={'model_paths': {**config.model_paths, key: str(colocated)}})

    thr = policy['thresholds']
    episodes = json.loads((output / 'episodes.json').read_text())
    results = []

    with (output / 'model_events.jsonl').open('x') as stream:
        for episode in episodes:
            t0 = time.perf_counter()
            raw_peak, eligible_peak = {}, {}
            production = set()
            states = Counter()

            pipeline = DetectionPipeline(
                policy=policy,
                providers=[bundle, c2_prov, bot_prov, enc_prov],
                drift=None)
            obs_pipeline = ObservationPipeline(
                config.model_copy(update={'sensor_id': episode['episode_id']}))

            for event in obs_pipeline.run(PcapSource(output / episode['pcap'])):
                try:
                    env_dict = event.model_dump(mode='json')
                    # Also run DNS GraphSAGE if applicable
                    dns_context = {'graph': env_dict.get('history', {}).get('graph', {})}
                    try:
                        gs_result = dns_gs.predict(
                            env_dict.get('event_id', ''), env_dict.get('dns_query'), dns_context)
                        extra_scores = [gs_result] if gs_result.get('applicable', True) else []
                    except Exception:
                        extra_scores = []

                    result = pipeline.process(env_dict, extra_scores)
                    decision = result['decision']

                    for score in result.get('all_scores', extra_scores):
                        if score.get('score_present') and score.get('probability') is not None:
                            lbl = score['label']
                            raw_peak[lbl] = max(raw_peak.get(lbl, 0.0), float(score['probability']))
                    for lbl, val in decision['label_probabilities'].items():
                        eligible_peak[lbl] = max(eligible_peak.get(lbl, 0.0), float(val or 0))
                    production.update(decision['labels'])
                    states[decision['decision_state']] += 1
                    stream.write(json.dumps({
                        'episode_id': episode['episode_id'],
                        'decision': decision,
                    }, allow_nan=False) + '\n')
                except Exception as exc:
                    states['ERROR'] += 1

            result_row = {
                'episode_id': episode['episode_id'],
                'family': episode['family'],
                'truth': episode['truth'],
                'raw_peak_scores': {k: round(v, 4) for k, v in raw_peak.items()},
                'eligible_peak_scores': {k: round(v, 4) for k, v in eligible_peak.items()},
                'raw_threshold_labels': sorted(k for k, v in raw_peak.items() if v >= thr.get(k, 0.85)),
                'eligible_threshold_labels': sorted(k for k, v in eligible_peak.items() if v >= thr.get(k, 0.85)),
                'production_labels': sorted(production),
                'decision_states': dict(states),
                'seconds': round(time.perf_counter() - t0, 3),
            }
            results.append(result_row)
            print(f'  {episode["episode_id"]}: raw={result_row["raw_threshold_labels"]} '
                  f'prod={result_row["production_labels"]} states={dict(states)}', flush=True)

    save(output / 'model_episodes.json', results)
    save(output / 'model_manifest.json', {
        'bundle_version': bundle.version,
        'specialists_version': spec_version,
        'specialists_loaded': ['C2Provider', 'BotnetProvider', 'EncryptedProvider', 'DNS_GraphSAGE'],
        'policy_thresholds': policy['thresholds'],
    })
    return results


# ── Phase 3: IDS engine runs ──────────────────────────────────────────────────

def run_ids(output: Path, tools_root: Path):
    config_dir = output / 'ids_config'
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / 'behavior.rules').write_text(RULES)
    (config_dir / 'behavior.zeek').write_text(ZEEK_SCRIPT)
    (config_dir / 'snort.conf').write_text(
        'ipvar HOME_NET any\nipvar EXTERNAL_NET any\nconfig checksum_mode: none\n'
        f'include {config_dir}/behavior.rules\n')
    suricata_yaml = f'''%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
default-rule-path: {config_dir}
rule-files:
  - behavior.rules
default-log-dir: .
stats:
  enabled: yes
  interval: 8
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types: [alert, stats]
  - fast:
      enabled: yes
      filename: fast.log
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
stream:
  checksum-validation: no
  midstream: true
'''
    (config_dir / 'suricata.yaml').write_text(suricata_yaml)

    episodes = json.loads((output / 'episodes.json').read_text())
    ids_eps = [e for e in episodes if e['tier'] == 'ids']
    env = env_for(tools_root)
    bins = {
        'snort': tools_root / 'usr/sbin/snort',
        'suricata': tools_root / 'usr/bin/suricata',
        'zeek': tools_root / 'opt/zeek/bin/zeek',
    }

    all_results = {}
    for engine in ('snort', 'suricata', 'zeek'):
        rows = []
        eng_dir = output / f'ids_{engine}'
        eng_dir.mkdir(exist_ok=True)
        for episode in ids_eps:
            ep_dir = eng_dir / episode['episode_id']
            ep_dir.mkdir(exist_ok=True)
            pcap = output / episode['pcap']
            if engine == 'snort':
                cmd = [str(bins['snort']), '-q', '-A', 'fast', '-k', 'none',
                       '-c', str(config_dir / 'snort.conf'), '-r', str(pcap), '-l', str(ep_dir)]
            elif engine == 'suricata':
                cmd = [str(bins['suricata']), '--runmode', 'single', '-k', 'none',
                       '-c', str(config_dir / 'suricata.yaml'), '-r', str(pcap), '-l', str(ep_dir)]
            else:
                cmd = [str(bins['zeek']), '-C', '-r', str(pcap), str(config_dir / 'behavior.zeek')]

            t0 = time.perf_counter()
            try:
                r = subprocess.run(cmd, cwd=ep_dir, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, timeout=120)
                code, text = r.returncode, r.stdout
            except subprocess.TimeoutExpired as exc:
                code, text = -999, str(exc.stdout or '') + '\nTIMEOUT'
            elapsed = time.perf_counter() - t0
            (ep_dir / 'run.log').write_text(text)

            detections, alerts = set(), 0
            if engine == 'suricata':
                eve = ep_dir / 'eve.json'
                if eve.exists():
                    for line in eve.read_text().splitlines():
                        try:
                            ev = json.loads(line)
                            if ev.get('event_type') == 'alert':
                                alerts += 1
                                sid = ev.get('alert', {}).get('signature_id', 0)
                                if sid in SID_MAP:
                                    detections.add(SID_MAP[sid])
                        except Exception:
                            pass
            elif engine == 'snort':
                for af in ep_dir.glob('alert*'):
                    for line in af.read_text(errors='replace').splitlines():
                        m = re.search(r'\[(\d+):(\d+):(\d+)\]', line)
                        if m:
                            alerts += 1
                            sid = int(m.group(2))
                            if sid in SID_MAP:
                                detections.add(SID_MAP[sid])
            else:
                for line in text.splitlines():
                    if line.startswith('IDSBENCH '):
                        lbl = line.split(' ', 1)[1].strip()
                        alerts += 1
                        if lbl in IDS_LABELS:
                            detections.add(lbl)

            row = {
                'episode_id': episode['episode_id'], 'family': episode['family'],
                'truth': episode['truth'], 'labels': sorted(detections),
                'alerts': alerts, 'exit_code': code, 'seconds': round(elapsed, 2),
            }
            rows.append(row)
            print(f'  {engine} {episode["episode_id"]}: exit={code} det={sorted(detections)}', flush=True)
            if code not in (0, 1, 2):
                print(f'  WARNING: unexpected exit code {code}, stopping {engine}', flush=True)
                break

        all_results[engine] = rows
        save(eng_dir / 'episodes.json', rows)
    return all_results


# ── Phase 4: Report ───────────────────────────────────────────────────────────

def report(output: Path):
    episodes = json.loads((output / 'episodes.json').read_text())
    model_eps = json.loads((output / 'model_episodes.json').read_text())
    benign = [r for r in model_eps if not r['truth']]
    results = {}

    for name, key in [
        ('AI-Threat_Detector_production',     'production_labels'),
        ('AI-Threat_Detector_eligible',        'eligible_threshold_labels'),
        ('AI-Threat_Detector_raw_diagnostic',  'raw_threshold_labels'),
    ]:
        per_label = {}
        for label in ALL_LABELS:
            truth_vec = [label in r['truth'] for r in model_eps]
            pred_vec = [label in r[key] for r in model_eps]
            if not any(truth_vec):
                per_label[label] = {'status': 'not_in_corpus'}
                continue
            m = binary_metrics(truth_vec, pred_vec)
            m['benign_fpr'] = round(sum(label in r[key] for r in benign) / max(len(benign), 1), 4)
            per_label[label] = m
        overall = binary_metrics(
            [bool(r['truth']) for r in model_eps],
            [bool(r[key]) for r in model_eps])
        valid = [v for v in per_label.values() if isinstance(v, dict) and 'f1' in v]
        results[name] = {
            'status': 'complete', 'episodes': len(model_eps),
            'per_label': per_label, 'overall_any_threat': overall,
            'macro_f1': round(sum(v['f1'] for v in valid) / max(len(valid), 1), 4),
        }

    for engine in ('snort', 'suricata', 'zeek'):
        path = output / f'ids_{engine}' / 'episodes.json'
        if not path.exists():
            results[f'{engine}_custom'] = {'status': 'not_run'}
            continue
        rows = json.loads(path.read_text())
        failed = [r for r in rows if r.get('exit_code', 0) not in (0, 1, 2)]
        if failed:
            results[f'{engine}_custom'] = {'status': 'error',
                                            'failed': [r['episode_id'] for r in failed]}
            continue
        benign_ids = [r for r in rows if not r['truth']]
        per_label = {}
        for label in IDS_LABELS:
            truth_vec = [label in r['truth'] for r in rows]
            pred_vec  = [label in r['labels'] for r in rows]
            if not any(truth_vec):
                per_label[label] = {'status': 'not_in_corpus'}
                continue
            m = binary_metrics(truth_vec, pred_vec)
            m['benign_fpr'] = round(sum(label in r['labels'] for r in benign_ids) / max(len(benign_ids), 1), 4)
            per_label[label] = m
        overall = binary_metrics([bool(r['truth']) for r in rows], [bool(r['labels']) for r in rows])
        valid = [v for v in per_label.values() if isinstance(v, dict) and 'f1' in v]
        results[f'{engine}_custom'] = {
            'status': 'complete', 'episodes': len(rows),
            'per_label': per_label, 'overall_any_threat': overall,
            'macro_f1': round(sum(v['f1'] for v in valid) / max(len(valid), 1), 4),
            'note': f'IDS-applicable families only ({len(rows)} episodes); specialist families excluded',
        }

    results['OSSEC'] = {'status': 'not_applicable', 'reason': 'Host-only tool; packet-only corpus'}
    save(output / 'comparison.json', results)

    lines = [
        '# AI-Threat Detector vs IDS Tools — Simulation Benchmark',
        '',
        f'Corpus: {len(episodes)} simulation families | Labels: {", ".join(ALL_LABELS)}',
        'AI-Threat Detector: evaluated on ALL families (IDS + specialist threats).',
        'Snort/Suricata/Zeek: evaluated on IDS-compatible families only (custom behavioral rules).',
        '',
        '## Any-Threat Detection Summary',
        '',
        '| System | Precision | Recall | F1 | Benign FPR | Macro F1 | Scope |',
        '|---|---:|---:|---:|---:|---:|---|',
    ]
    for name, res in results.items():
        if res.get('status') == 'complete':
            m = res['overall_any_threat']
            note = res.get('note', 'all families')
            lines.append(
                f"| {name.replace('_', ' ')} "
                f"| {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} "
                f"| {m['fpr']:.2%} | {res['macro_f1']:.2%} | {note} |")
        else:
            lines.append(f"| {name.replace('_', ' ')}: {res.get('status','?')} | — | — | — | — | — | — |")

    for name in ('AI-Threat_Detector_raw_diagnostic', 'AI-Threat_Detector_production',
                 'snort_custom', 'suricata_custom', 'zeek_custom'):
        res = results.get(name, {})
        if res.get('status') != 'complete':
            continue
        label_set = ALL_LABELS if 'AI' in name else IDS_LABELS
        lines += ['', f'## {name.replace("_", " ")} — Per Label', '',
                  '| Label | TP | FP | FN | TN | Precision | Recall | F1 | Benign FPR |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
        for lbl in label_set:
            m = res['per_label'].get(lbl, {})
            if isinstance(m, dict) and 'f1' in m:
                lines.append(f"| {lbl} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
                              f"| {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} "
                              f"| {m.get('benign_fpr', 0):.2%} |")
            else:
                lines.append(f'| {lbl} | — | — | — | — | N/A | N/A | N/A | N/A |')

    lines += ['',
              'Notes:',
              '- OSSEC: N/A (host-only; no host log/FIM corpus)',
              '- AI-Threat Detector production=0 if policy unapproved (expected)',
              '- IDS tools have no rules for C2/Botnet/Encrypted — those families marked N/A for IDS',
              '- Specialist families (C2, Botnet, Encrypted) covered only by AI-Threat Detector',
              '']
    (output / 'comparison.md').write_text('\n'.join(lines))
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Simulation benchmark: AI-Threat Detector vs IDS tools')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--tools-root', required=True, type=Path)
    p.add_argument('--specialists', required=True, type=Path)
    p.add_argument('--seed', type=int, default=None)
    p.add_argument('--duration', type=int, default=120,
                   help='Episode duration in seconds (default 120)')
    p.add_argument('--stage', choices=('generate', 'infer', 'ids', 'report', 'all'), default='all')
    args = p.parse_args()

    seed = args.seed if args.seed is not None else secrets.randbits(32)
    output = args.output.resolve()
    tools = args.tools_root.resolve()
    specialists = args.specialists.resolve()

    print(f'=== AI-Threat Detector Simulation Benchmark ===')
    print(f'Output:      {output}')
    print(f'Seed:        {seed}')
    print(f'Duration:    {args.duration}s per episode')
    print(f'Specialists: {specialists}')

    if args.stage in ('generate', 'all'):
        output.mkdir(parents=True, exist_ok=True)
        (output / 'seed.txt').write_text(str(seed) + '\n')
        print('\nPhase 1: Generating simulation corpus...', flush=True)
        generate(output, seed, duration_s=args.duration)

    if args.stage in ('infer', 'all'):
        print('\nPhase 2: AI-Threat Detector inference (core + all specialists)...', flush=True)
        infer(output, specialists)

    if args.stage in ('ids', 'all'):
        print('\nPhase 3: IDS comparators (Snort / Suricata / Zeek)...', flush=True)
        run_ids(output, tools)

    if args.stage in ('report', 'all'):
        print('\nPhase 4: Generating comparison report...', flush=True)
        report(output)
        print('Done.', flush=True)


if __name__ == '__main__':
    main()
