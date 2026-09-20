"""Offline IDS engine benchmark on identical, independently replayed episodes.

Custom behavioral signatures are transparent toy baselines, not vendor coverage.
All rules are frozen and hashed before the first comparator replay.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from .ids_benchmark import LABELS, digest, save

SID = {9000001: 'DDoS', 9000002: 'DDoS', 9000003: 'PORT_SCAN',
       9000004: 'DATA_EXFILTRATION', 9000005: 'DGA', 9000006: 'DNS_TUNNEL'}
RULES = '''alert udp any any -> any !53 (msg:"BENCH custom DDoS UDP rate"; detection_filter:track by_dst,count 100,seconds 1; sid:9000001; rev:1;)
alert tcp any any -> any any (msg:"BENCH custom DDoS SYN rate"; flags:S; flow:stateless; detection_filter:track by_dst,count 100,seconds 1; sid:9000002; rev:1;)
alert tcp any any -> any any (msg:"BENCH custom scan SYN rate"; flags:S; flow:stateless; detection_filter:track by_src,count 20,seconds 60; sid:9000003; rev:1;)
alert tcp any any -> any any (msg:"BENCH custom exfil bulk proxy"; flow:stateless; dsize:>1000; detection_filter:track by_src,count 100,seconds 60; sid:9000004; rev:1;)
alert udp any any -> any 53 (msg:"BENCH custom DGA length proxy"; byte_test:1,>,19,12; byte_test:1,<,50,12; sid:9000005; rev:1;)
alert udp any any -> any 53 (msg:"BENCH custom DNS tunnel length proxy"; byte_test:1,>,49,12; byte_test:1,<,64,12; sid:9000006; rev:1;)
'''
ZEEK = '''@load base/protocols/dns

module IDSBench;
global flood: table[addr, count] of count &default=0;
global syns: table[addr, count] of count &default=0;
global bulk: table[addr, count] of count &default=0;
global emitted: set[string];
function report(label: string)
    {
    if ( label !in emitted )
        {
        add emitted[label];
        print fmt("IDSBENCH %s", label);
        }
    }
event new_packet(c: connection, p: pkt_hdr)
    {
    if ( ! p?$ip ) return;
    local src = p$ip$src;
    local dst = p$ip$dst;
    local one = double_to_count(floor(time_to_double(network_time())));
    local minute = double_to_count(floor(time_to_double(network_time()) / 60.0));
    local syn = p?$tcp && p$tcp$flags == 2;
    if ( syn || (p?$udp && p$udp$dport != 53/udp) )
        {
        ++flood[dst, one];
        if ( flood[dst, one] > 100 ) report("DDoS");
        }
    if ( syn )
        {
        ++syns[src, minute];
        if ( syns[src, minute] > 20 ) report("PORT_SCAN");
        }
    if ( p?$tcp && p$tcp$dl > 1000 )
        {
        ++bulk[src, minute];
        if ( bulk[src, minute] > 100 ) report("DATA_EXFILTRATION");
        }
    }
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local parts = split_string(query, /\\./);
    if ( |parts| == 0 ) return;
    local n = |parts[0]|;
    if ( n >= 20 && n < 50 ) report("DGA");
    if ( n >= 50 && n < 64 ) report("DNS_TUNNEL");
    }
'''


def env_for(root):
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = ':'.join(str(p) for p in (root/'lib/x86_64-linux-gnu', root/'usr/lib/x86_64-linux-gnu',
                                   root/'usr/lib/x86_64-linux-gnu/dpdk/pmds-24.0', root/'opt/zeek/lib'))
    zeek = root/'opt/zeek'
    env['ZEEKPATH'] = ':'.join(str(zeek/p) for p in ('share/zeek', 'share/zeek/policy', 'share/zeek/site', 'share/zeek/builtin-plugins'))
    env['ZEEK_PLUGIN_PATH'] = str(zeek/'lib/zeek/plugins')
    return env


def prepare(corpus, root):
    output = corpus/'comparators'
    config = output/'config'
    config.mkdir(parents=True, exist_ok=False)
    (config/'behavior.rules').write_text(RULES)
    (config/'behavior.zeek').write_text(ZEEK)
    (config/'snort.conf').write_text('ipvar HOME_NET any\nipvar EXTERNAL_NET any\n'
        'config checksum_mode: none\ninclude ' + str(config/'behavior.rules') + '\n')
    # Minimal standalone config deliberately avoids package paths/system writes.
    (config/'suricata.yaml').write_text('''%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"
default-rule-path: ''' + str(config) + '''
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
      types:
        - alert
        - stats
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
''')
    # Fresh public signatures selected only by explicit in-scope message terms.
    stock = root/'etc/snort'
    lines = (stock/'snort.conf').read_text().splitlines() if (stock/'snort.conf').exists() else []
    variables = [line for line in lines if re.match(r'^(ipvar|portvar|var) ', line)
                 and not any(x in line for x in ('RULE_PATH', 'SO_RULE_PATH', 'PREPROC_RULE_PATH', 'WHITE_LIST_PATH', 'BLACK_LIST_PATH'))]
    sources = {'snort': [root.parent/'rules/snort-community/community-rules/community.rules'],
               'suricata': sorted((root.parent/'rules/et-open/rules').glob('*.rules'))}
    source_manifest = {}
    for engine, paths in sources.items():
        mapping, selected, excluded, seen = {}, [], Counter(), set()
        for path in paths:
            for line in path.read_text(errors='replace').splitlines():
                if not line.lstrip().startswith('alert '):
                    continue
                sid, msg = re.search(r'sid\s*:\s*(\d+)', line), re.search(r'msg\s*:\s*"([^"]+)"', line)
                if not sid or not msg:
                    excluded['missing_sid_or_message'] += 1
                    continue
                message = msg.group(1).lower()
                label = ('DNS_TUNNEL' if 'tunnel' in message and 'dns' in message else
                         'DGA' if re.search(r'\bdga\b', message) else
                         'DATA_EXFILTRATION' if 'exfil' in message else
                         'DDoS' if re.search(r'\bddos\b|\bflood\b', message) else
                         'PORT_SCAN' if re.search(r'\b(portscan|port scan|network scan|nmap|masscan|syn scan)\b', message) else None)
                if not label:
                    excluded['outside_explicit_message_scope'] += 1
                    continue
                sid = int(sid.group(1))
                if sid in seen:
                    excluded['duplicate_sid'] += 1
                    continue
                seen.add(sid)
                selected.append(line)
                mapping[sid] = label
        (config/f'{engine}_public.rules').write_text('\n'.join(selected) + '\n')
        save(config/f'{engine}_public_sid_map.json', mapping)
        source_manifest[engine] = {'source_files': {str(p): digest(p) for p in paths},
                                    'selected_rules': len(selected), 'labels': dict(Counter(mapping.values())),
                                    'excluded': dict(excluded), 'unsupported_syntax_exclusions': []}
    (config/'snort_packaged.conf').write_text('\n'.join(variables) + '\nconfig checksum_mode: none\n'
        + f'include {stock / "classification.config"}\ninclude {stock / "reference.config"}\n'
        + f'include {config / "snort_public.rules"}\n')
    # Keep vendor variable/application defaults; change only local paths and use
    # the downloaded signature subset as the exclusive -S rule input at run time.
    stock_yaml = (root/'etc/suricata/suricata.yaml').read_text()
    stock_yaml = stock_yaml.replace('/etc/suricata/', str(root/'etc/suricata') + '/')
    stock_yaml = stock_yaml.replace('/var/log/suricata', '.')
    stock_yaml = re.sub(r'HOME_NET:.*', 'HOME_NET: "any"', stock_yaml, count=1)
    stock_yaml = re.sub(r'EXTERNAL_NET:.*', 'EXTERNAL_NET: "any"', stock_yaml, count=1)
    (config/'suricata_public.yaml').write_text(stock_yaml)
    save(config/'public_rules_selection.json', source_manifest)
    save(config/'frozen_policy_manifest.json', {'created_before_comparator_results': True,
         'files': {p.name: digest(p) for p in sorted(config.iterdir()) if p.is_file()},
         'public_rule_selection': source_manifest,
         'custom_sid_map': SID, 'custom_policy': 'transparent fixed behavioral proxies, not stock vendor rules',
         'window_difference': 'Snort/Suricata detection_filter; Zeek fixed epoch-aligned 1s/60s buckets',
         'limitations': ['SYN count is a scan proxy, not unique-port counting',
                        'DNS label length is not a trained DGA or tunnel classifier',
                        'bulk volume cannot distinguish legitimate upload from data theft',
                        'public rules restricted by explicit in-scope message keywords; not complete product default deployment',
                        'OSSEC host telemetry absent: N/A, not a failed detector'],
         'corpus_manifest_sha256': digest(corpus/'corpus_manifest.json')})
    return output


def call(command, directory, env):
    started = time.perf_counter()
    try:
        r = subprocess.run(command, cwd=directory, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=90)
        code, text = r.returncode, r.stdout
    except subprocess.TimeoutExpired as exc:
        code, text = -999, str(exc.stdout or '') + '\nTIMEOUT 90 seconds'
    (directory/'command.log').write_text(text)
    record = {'command': command, 'cwd': str(directory), 'exit_code': code,
              'seconds': time.perf_counter()-started, 'log_sha256': digest(directory/'command.log')}
    save(directory/'command.json', record)
    return record, text


def run(corpus, root, engines, packaged=False):
    output, config = corpus/'comparators', corpus/'comparators/config'
    frozen = json.loads((config/'frozen_policy_manifest.json').read_text())
    for name, expected in frozen['files'].items():
        assert digest(config/name) == expected, f'Policy changed: {name}'
    episodes = json.loads((corpus/'episodes.json').read_text())
    env = env_for(root)
    binaries = {'snort': root/'usr/sbin/snort', 'suricata': root/'usr/bin/suricata', 'zeek': root/'opt/zeek/bin/zeek'}
    for engine in engines:
        mode = engine + ('_public' if packaged else '_custom')
        results = []
        directory = output/mode
        directory.mkdir(exist_ok=False)
        version_cmd = [str(binaries[engine]), '--version' if engine == 'zeek' else '-V']
        version, _ = call(version_cmd, directory, env)
        save(directory/'version.json', version)
        for episode in episodes:
            subdir = directory/episode['episode_id']
            subdir.mkdir()
            pcap = corpus/episode['pcap']
            assert digest(pcap) == episode['sha256']
            if engine == 'snort':
                conf = config/('snort_packaged.conf' if packaged else 'snort.conf')
                command = [str(binaries[engine]), '-q', '-A', 'fast', '-k', 'none', '-c', str(conf),
                           '-r', str(pcap), '-l', str(subdir)]
            elif engine == 'suricata':
                command = [str(binaries[engine]), '--runmode', 'single', '-k', 'none', '-c', str(config/('suricata_public.yaml' if packaged else 'suricata.yaml')),
                           '-r', str(pcap), '-l', str(subdir)]
                if packaged:
                    command += ['-S', str(config/'suricata_public.rules')]
            else:
                command = [str(binaries[engine]), '-C', '-r', str(pcap)]
                if not packaged:
                    command += [str(config/'behavior.zeek')]
            record, stdout = call(command, subdir, env)
            detections, alerts, failures, unrelated = set(), 0, 0, 0
            sid_map = {int(k): v for k, v in json.loads((config/f'{engine}_public_sid_map.json').read_text()).items()} if packaged and engine != 'zeek' else SID
            if engine == 'suricata':
                path = subdir/'eve.json'
                if path.exists():
                    for line in path.read_text().splitlines():
                        try:
                            event = json.loads(line)
                            if event.get('event_type') == 'alert':
                                alerts += 1
                                sid = event['alert']['signature_id']
                                if sid in sid_map:
                                    detections.add(sid_map[sid])
                                else:
                                    unrelated += 1
                        except (ValueError, KeyError):
                            failures += 1
            elif engine == 'snort':
                alert_files = [p for p in subdir.glob('alert*') if p.is_file()]
                for path in alert_files:
                    for line in path.read_text(errors='replace').splitlines():
                        if not line.strip():
                            continue
                        match = re.search(r'\[(\d+):(\d+):(\d+)\]', line)
                        if match:
                            alerts += 1
                            sid = int(match.group(2))
                            if sid in sid_map:
                                detections.add(sid_map[sid])
                            else:
                                unrelated += 1
                        else:
                            failures += 1
            else:
                for line in stdout.splitlines():
                    if line.startswith('IDSBENCH '):
                        label = line.split(' ', 1)[1].strip()
                        alerts += 1
                        if label in LABELS:
                            detections.add(label)
                        else:
                            failures += 1
                notices = subdir/'notice.log'
                if notices.exists():
                    for line in notices.read_text().splitlines():
                        if line.startswith('#'):
                            continue
                        alerts += 1
                        if 'Scan::Port_Scan' in line or 'Scan::Address_Scan' in line:
                            detections.add('PORT_SCAN')
                        else:
                            unrelated += 1
            results.append({'episode_id': episode['episode_id'], 'truth': episode['labels'],
                            'labels': sorted(detections), 'alert_records': alerts,
                            'unmapped_alert_records': unrelated, 'parse_failures': failures, **record})
            print(mode, episode['episode_id'], record['exit_code'], sorted(detections), flush=True)
            if record['exit_code']:
                # Configuration failures are not 42 negative detections.
                break
        save(directory/'episodes.json', results)
        save(directory/'engine_manifest.json', {'binary': str(binaries[engine]), 'binary_sha256': digest(binaries[engine]),
             'policy_manifest_sha256': digest(config/'frozen_policy_manifest.json'), 'engine': mode,
             'environment': {k: env[k] for k in ('LD_LIBRARY_PATH', 'ZEEKPATH', 'ZEEK_PLUGIN_PATH')}})


def binary(truth, predicted):
    tp = sum(a and b for a, b in zip(truth, predicted))
    fp = sum(not a and b for a, b in zip(truth, predicted))
    fn = sum(a and not b for a, b in zip(truth, predicted))
    tn = sum(not a and not b for a, b in zip(truth, predicted))
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'precision': tp/max(tp+fp, 1),
            'recall': tp/max(tp+fn, 1), 'f1': 2*tp/max(2*tp+fp+fn, 1),
            'fpr': fp/max(fp+tn, 1), 'accuracy': (tp+tn)/max(len(truth), 1)}


def report(corpus):
    output = corpus/'comparators'
    inputs = {}
    for path in output.glob('*/episodes.json'):
        inputs[path.parent.name] = (json.loads(path.read_text()), 'labels')
    models = json.loads((corpus/'model_episodes.json').read_text())
    for name, key in (('model_production', 'production_labels'), ('model_eligible', 'eligible_threshold_labels'),
                      ('model_raw_diagnostic', 'raw_threshold_labels')):
        inputs[name] = (models, key)
    results = {}
    for name, (rows, key) in inputs.items():
        if name == 'zeek_public':
            results[name] = {'status': 'logging_only', 'episodes': len(rows),
                              'reason': 'Default Zeek produces telemetry; no stock scan script in installed Zeek 9.0.0.'}
            continue
        failed = [r for r in rows if r.get('exit_code', 0) != 0 or r.get('parse_failures', 0)]
        if failed:
            results[name] = {'status': 'invalid_run', 'failed_episodes': [r['episode_id'] for r in failed],
                             'explanation': 'failed execution/parsing must not be scored as true negatives'}
            continue
        per_head = {}
        benign = [r for r in rows if not r['truth']]
        for label in LABELS:
            metrics = binary([label in r['truth'] for r in rows], [label in r[key] for r in rows])
            metrics['benign_fpr'] = sum(label in r[key] for r in benign)/max(len(benign), 1)
            per_head[label] = metrics
        results[name] = {'status': 'complete', 'episodes': len(rows), 'per_attack': per_head,
                         'overall_any_threat': binary([bool(r['truth']) for r in rows], [bool(r[key]) for r in rows]),
                         'macro_f1': sum(v['f1'] for v in per_head.values())/len(LABELS),
                         'micro_multilabel': binary([label in r['truth'] for r in rows for label in LABELS],
                                                   [label in r[key] for r in rows for label in LABELS]),
                         'replay_seconds_sum': sum(r['seconds'] for r in rows),
                         'runtime_note': 'IDS per-episode process startup included; model loading excluded; not a throughput contest',
                         'parse_failures': sum(r.get('parse_failures', 0) for r in rows)}
    results['OSSEC'] = {'status': 'not_applicable', 'reason': 'Host-based tool; this corpus contains packets only, no host log/FIM ground truth.'}
    save(output/'comparison.json', results)
    lines = ['# Fresh synthetic unidirectional IDS benchmark', '',
             'Each tool received the same 42 isolated episode PCAPs. The custom rules/scripts are explicitly',
             'configured behavioral proxies, not stock vendor coverage. Current model production and raw',
             'diagnostic scores are separate. This is not an external generalization result.', '',
             '| Engine/output | Precision | Recall | F1 | Benign FPR | Macro attack F1 |',
             '|---|---:|---:|---:|---:|---:|']
    for name, result in results.items():
        if result['status'] == 'complete':
            m = result['overall_any_threat']
            lines.append(f"| {name} | {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} | {m['fpr']:.2%} | {result['macro_f1']:.2%} |")
        else:
            lines.append(f"| {name}: {result['status']} | — | — | — | — | — |")
    for name, result in results.items():
        if result['status'] != 'complete':
            continue
        lines += ['', f'## {name}', '', '| Attack | TP | FP | FN | TN | Precision | Recall | F1 | Benign FPR |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
        for label, m in result['per_attack'].items():
            lines.append(f"| {label} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} | {m['benign_fpr']:.2%} |")
    lines += ['', 'OSSEC: N/A (no host telemetry). All rates are episode-level; other attack types count',
              'as negatives for each individual head. Any-threat results accept any supported alert,',
              'even if the attack class is wrong; macro/micro per-class scores preserve that distinction.',
              'AUC is omitted for binary-rule comparators. Zero alerts from an unapproved pipeline do',
              'not demonstrate benign classification: every current model decision abstains.',
              'Only three repetitions per profile; no reliable real-world efficacy claim follows.',
              'See config/frozen_policy_manifest.json and each engine directory for configurations,',
              'hashes, raw alerts, execution commands, return codes, and timings.', '']
    (output/'comparison.md').write_text('\n'.join(lines))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--corpus', required=True, type=Path)
    p.add_argument('--tools-root', required=True, type=Path)
    p.add_argument('--stage', choices=('prepare', 'run', 'report', 'all'), default='all')
    p.add_argument('--engines', nargs='+', choices=('snort', 'suricata', 'zeek'), default=['snort', 'suricata', 'zeek'])
    p.add_argument('--packaged', action='store_true')
    a = p.parse_args()
    corpus, root = a.corpus.resolve(), a.tools_root.resolve()
    if a.stage in ('prepare', 'all'):
        prepare(corpus, root)
    if a.stage in ('run', 'all'):
        run(corpus, root, a.engines, a.packaged)
    if a.stage in ('report', 'all'):
        report(corpus)


if __name__ == '__main__':
    main()
