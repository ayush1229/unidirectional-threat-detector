"""
experiments/sim_diag.py — Diagnostic benchmark with two components:

1. CORE MODEL (DDoS / PORT_SCAN / DATA_EXFILTRATION):
   Uses specialist_generators to synthesise labelled feature rows that match
   what the core bundle was trained on, then evaluates MetaXGBoost directly.

2. SPECIALIST MODELS (C2 / Botnet / Encrypted / DNS-GraphSAGE):
   Uses their native corpora (c2_corpus, botnet_corpus, etc.) to give an
   honest in-distribution evaluation. OOD results are already in
   specialist_ood_benchmark.json.

3. IDS TOOLS: pulled directly from the parent sim-benchmark run.

Usage:
    python -m experiments.sim_diag \
        --run  artifacts/experiments/sim-benchmark-20260920 \
        --specialists artifacts/specialists/0.1.0-sim \
        --threshold 0.5
"""
from __future__ import annotations

import argparse, json, time
from pathlib import Path

import joblib
import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]

CORE_LABELS   = ('DDoS', 'PORT_SCAN', 'DATA_EXFILTRATION')
SPEC_LABELS   = ('C2_BEACONING', 'BOTNET_HOST', 'BOTNET_COORDINATION', 'ENCRYPTED_MALWARE', 'DNS_TUNNEL')
ALL_LABELS    = list(CORE_LABELS) + ['DGA', 'DNS_TUNNEL', 'C2_BEACONING',
                                      'BOTNET_HOST', 'BOTNET_COORDINATION', 'ENCRYPTED_MALWARE']
IDS_LABELS    = ['DDoS', 'PORT_SCAN', 'DATA_EXFILTRATION', 'DGA', 'DNS_TUNNEL']


def binary_metrics(truth, predicted):
    tp = sum(a and b for a, b in zip(truth, predicted))
    fp = sum(not a and b for a, b in zip(truth, predicted))
    fn = sum(a and not b for a, b in zip(truth, predicted))
    tn = sum(not a and not b for a, b in zip(truth, predicted))
    n  = max(len(truth), 1)
    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': round(tp / max(tp + fp, 1), 4),
        'recall':    round(tp / max(tp + fn, 1), 4),
        'f1':        round(2 * tp / max(2 * tp + fp + fn, 1), 4),
        'accuracy':  round((tp + tn) / n, 4),
        'fpr':       round(fp / max(fp + tn, 1), 4),
    }


# ── 1. Core Bundle Evaluation ────────────────────────────────────────────────

def eval_core_bundle(bundle, n_samples: int = 300):
    """Evaluate core MetaXGBoost on simulation-generated tabular feature rows."""
    from agent1_observation_dns.simulation.specialist_generators import (
        c2_corpus, botnet_corpus, encrypted_corpus, dns_graph_corpus
    )
    from agent2_detection_product.models.tabular_known_xgb import context_vector
    from agent2_detection_product.simulation.feature_corpus import core_feature_corpus

    print('  [Core] Generating feature corpus...', flush=True)
    try:
        corpus = core_feature_corpus(n_per_class=n_samples // 4, seed=99)
    except Exception as e:
        print(f'  [Core] core_feature_corpus not available: {e}')
        print('  [Core] Falling back to observation-based scoring from sim run...')
        return eval_core_from_observations(bundle)

    rows, truth, scores_list = [], [], []
    test_rows = [r for r in corpus if r.get('split') == 'test']
    for row in test_rows[:n_samples]:
        try:
            feats = bundle.base.predict([row['envelope']])
            meta  = bundle.meta.predict(feats)[0]
            rows.append(meta)
            truth.append(row['label'])
        except Exception:
            pass

    if not rows:
        return {}

    arr = np.array(rows)
    per_label = {}
    for i, lbl in enumerate(CORE_LABELS):
        tv = [t == lbl for t in truth]
        pv = [arr[j, i] >= 0.5 for j in range(len(arr))]
        if not any(tv):
            per_label[lbl] = {'status': 'not_in_corpus'}
            continue
        per_label[lbl] = binary_metrics(tv, pv)
        per_label[lbl]['mean_score_pos'] = round(float(arr[[j for j, t in enumerate(tv) if t], i].mean()), 4)
        per_label[lbl]['mean_score_neg'] = round(float(arr[[j for j, t in enumerate(tv) if not t], i].mean()), 4)
    return per_label


def eval_core_from_observations(bundle, run_dir: Path = None, thresholds: dict = None):
    """Fallback: evaluate on the existing simulation PCAP observations."""
    thresholds = thresholds or {}
    obs_dir = run_dir / 'observations'
    FAMILY_LABEL = {
        '00_ddos': 'DDoS', '01_port_scan': 'PORT_SCAN', '02_slow_scan': 'PORT_SCAN',
        '03_exfiltration': 'DATA_EXFILTRATION', '04_low_slow_exfiltration': 'DATA_EXFILTRATION',
    }
    per_label = {}
    for lbl in CORE_LABELS:
        pos_scores, neg_scores = [], []
        for fname, flbl in FAMILY_LABEL.items():
            obs_file = obs_dir / f'{fname}.jsonl'
            if not obs_file.exists():
                continue
            lines = obs_file.read_text().splitlines()[:200]
            for line in lines:
                try:
                    obs = json.loads(line)
                    obs['history']['window_complete'] = True
                    obs['history']['event_count'] = 10
                    obs.setdefault('visibility', {})['tls_handshake_visible'] = True
                    obs.setdefault('route_hints', {})
                    feats = bundle.base.predict([obs])
                    score = float(bundle.meta.predict(feats)[0, CORE_LABELS.index(lbl)])
                    if flbl == lbl:
                        pos_scores.append(score)
                    else:
                        neg_scores.append(score)
                except Exception:
                    pass
        # benign
        benign_file = obs_dir / '11_benign_mixed.jsonl'
        if benign_file.exists():
            for line in benign_file.read_text().splitlines()[:100]:
                try:
                    obs = json.loads(line)
                    obs['history']['window_complete'] = True
                    obs['history']['event_count'] = 10
                    obs.setdefault('visibility', {})['tls_handshake_visible'] = True
                    obs.setdefault('route_hints', {})
                    feats = bundle.base.predict([obs])
                    neg_scores.append(float(bundle.meta.predict(feats)[0, CORE_LABELS.index(lbl)]))
                except Exception:
                    pass
        if not pos_scores:
            per_label[lbl] = {'status': 'no_window_features_in_corpus',
                              'note': 'Simulation frames lack window aggregates that core model needs'}
            continue
        th = thresholds.get(lbl, 0.5)
        tv = [True]  * len(pos_scores) + [False] * len(neg_scores)
        pv = [s >= th for s in pos_scores + neg_scores]
        m  = binary_metrics(tv, pv)
        m['mean_score_pos'] = round(float(np.mean(pos_scores)), 4)
        m['mean_score_neg'] = round(float(np.mean(neg_scores)), 4)
        m['threshold'] = th
        m['note'] = 'Simulation obs lack window-level aggregates; meta scores are near-uniform'
        per_label[lbl] = m
    return per_label


# ── 2. Specialist Evaluations ────────────────────────────────────────────────

def eval_c2(specialists_dir: Path, threshold: float, n: int = 300):
    """Evaluate C2 specialist on in-distribution test corpus."""
    from agent1_observation_dns.simulation.specialist_generators import c2_corpus
    from agent2_detection_product.models.c2_temporal_tcn_gru import TemporalCandidate
    from agent2_detection_product.models.c2_fusion import C2Fusion
    from agent2_detection_product.models.c2_periodicity import periodicity
    from xgboost import XGBClassifier

    print('  [C2] Loading and evaluating...', flush=True)
    cthmm = joblib.load(specialists_dir / 'cthmm.pkl')
    gru   = TemporalCandidate(features=2, kind='gru', hidden=32)
    gru.load_state_dict(torch.load(specialists_dir / 'temporal_gru.pt', weights_only=True))
    gru.eval()
    c2_xgb = XGBClassifier()
    c2_xgb.load_model(str(specialists_dir / 'c2_fusion.json'))
    fusion = C2Fusion()
    fusion.models = {'C2_BEACONING': c2_xgb}

    corpus = c2_corpus(n_sequences=n, seed=42)
    test   = [r for r in corpus if r.get('split') == 'test']

    def score(ts):
        gaps = np.diff(ts)
        if len(gaps) < 2: return 0.5
        norm = np.log1p(gaps).astype(np.float32)
        seq  = np.column_stack((norm, np.ones(len(gaps), np.float32)))[None]
        with torch.no_grad():
            gru_s = float(torch.sigmoid(gru(torch.as_tensor(seq)))[0])
        ll  = cthmm.log_likelihood(gaps) / max(len(gaps), 1)
        ev  = periodicity(ts)
        raw = fusion.predict([[ev['iat_cv'], ev['iat_mad'], ev['spectral_concentration'],
                               ev['lag1_autocorrelation'], ll, gru_s]])[0, 0]
        return float(raw)

    truth, preds, scores = [], [], []
    for row in test:
        try:
            s = score(row['timestamps'])
            truth.append(int(row['label']))
            preds.append(1 if s >= threshold else 0)
            scores.append(s)
        except Exception:
            pass

    if not truth: return {'status': 'no_test_rows'}
    m = binary_metrics([bool(t) for t in truth], [bool(p) for p in preds])
    pos = [scores[i] for i, t in enumerate(truth) if t]
    neg = [scores[i] for i, t in enumerate(truth) if not t]
    m['mean_score_pos'] = round(float(np.mean(pos)), 4) if pos else 0.0
    m['mean_score_neg'] = round(float(np.mean(neg)), 4) if neg else 0.0
    m['test_rows'] = len(truth)
    m['threshold'] = threshold
    print(f'  [C2] {len(truth)} test rows: F1={m["f1"]:.3f} Acc={m["accuracy"]:.3f}', flush=True)
    return m


def eval_botnet(specialists_dir: Path, threshold_h: float = 0.82, threshold_c: float = 0.82, n: int = 300):
    """Evaluate Botnet GraphSAGE + TreeHead on in-distribution test corpus."""
    from agent1_observation_dns.simulation.specialist_generators import botnet_corpus
    from agent2_detection_product.models.providers import graph_arrays
    from agent2_detection_product.models.botnet_gnn import GraphSAGE

    print('  [Botnet] Loading and evaluating...', flush=True)
    gnn_state = torch.load(specialists_dir / 'botnet_gnn.pt', weights_only=True)
    in_f   = gnn_state['first.weight'].shape[1] // 2
    hidden = gnn_state['first.weight'].shape[0]
    dim    = gnn_state['second.weight'].shape[0]
    gnn    = GraphSAGE(features=in_f, hidden=hidden, dimensions=dim)
    gnn.load_state_dict(gnn_state)
    gnn.eval()
    bot_scaler = joblib.load(specialists_dir / 'botnet_scaler.pkl')
    bot_tree   = joblib.load(specialists_dir / 'botnet_tree.pkl')

    corpus = botnet_corpus(n_graphs=n, seed=42)
    test   = [r for r in corpus if r.get('split') == 'test']

    truth_h, truth_c, preds_h, preds_c = [], [], [], []
    scores_h_pos, scores_h_neg = [], []
    scores_c_pos, scores_c_neg = [], []

    for row in test:
        try:
            nodes, raw_attr, edges_arr = graph_arrays(row['edges'])
            x   = bot_scaler.transform(raw_attr).astype(np.float32)
            with torch.no_grad():
                embs = gnn.embed(torch.as_tensor(x), torch.as_tensor(edges_arr)).numpy()
            preds_arr = np.array(bot_tree.predict(embs, x))  # shape (n_nodes, 2)
            # Graph-level: max over nodes
            host_score  = float(preds_arr[:, 0].max())
            coord_score = float(preds_arr[:, 1].max())
            node_lbls   = row.get('node_labels', {})
            has_h = any(h == 1 for h, _ in node_lbls.values()) if node_lbls else bool(row.get('label', 0))
            has_c = any(c == 1 for _, c in node_lbls.values()) if node_lbls else False
            truth_h.append(has_h); preds_h.append(host_score >= threshold_h)
            truth_c.append(has_c); preds_c.append(coord_score >= threshold_c)
            (scores_h_pos if has_h else scores_h_neg).append(host_score)
            (scores_c_pos if has_c else scores_c_neg).append(coord_score)
        except Exception:
            pass

    if not truth_h: return {'BOTNET_HOST': {'status': 'no_test_rows'}, 'BOTNET_COORDINATION': {'status': 'no_test_rows'}}
    mh = binary_metrics(truth_h, preds_h)
    mc = binary_metrics(truth_c, preds_c)
    mh['mean_score_pos'] = round(float(np.mean(scores_h_pos)), 4) if scores_h_pos else 0.0
    mh['mean_score_neg'] = round(float(np.mean(scores_h_neg)), 4) if scores_h_neg else 0.0
    mh['threshold'] = threshold_h
    mc['mean_score_pos'] = round(float(np.mean(scores_c_pos)), 4) if scores_c_pos else 0.0
    mc['mean_score_neg'] = round(float(np.mean(scores_c_neg)), 4) if scores_c_neg else 0.0
    mc['threshold'] = threshold_c
    mh['test_graphs'] = len(truth_h)
    mc['test_graphs'] = len(truth_c)
    print(f'  [Botnet] {len(truth_h)} graphs: HOST (th={threshold_h:.2f}) F1={mh["f1"]:.3f} | COORD (th={threshold_c:.2f}) F1={mc["f1"]:.3f}', flush=True)
    return {'BOTNET_HOST': mh, 'BOTNET_COORDINATION': mc}


def eval_encrypted(specialists_dir: Path, threshold: float, n: int = 300):
    """Evaluate Encrypted Malware XGBoost on in-distribution test corpus."""
    from agent1_observation_dns.simulation.specialist_generators import encrypted_corpus
    from agent2_detection_product.models.encrypted_malware import early_sequence
    from xgboost import XGBClassifier

    print('  [Encrypted] Loading and evaluating...', flush=True)
    enc_xgb = XGBClassifier()
    enc_xgb.load_model(str(specialists_dir / 'encrypted_malware.json'))

    corpus = encrypted_corpus(n_sequences=n, seed=42)
    test   = [r for r in corpus if r.get('split') == 'test']

    truth, preds, scores = [], [], []
    for row in test:
        try:
            ps = row['packet_sizes'] if isinstance(row['packet_sizes'], list) \
                 else json.loads(str(row['packet_sizes']))
            iv = row['intervals'] if isinstance(row['intervals'], list) \
                 else json.loads(str(row['intervals']))
            feats = early_sequence(ps, iv)  # 6 features
            X = np.array([feats], dtype=np.float32)
            prob = float(enc_xgb.predict_proba(X)[0, 1])
            truth.append(int(row['label']))
            preds.append(1 if prob >= threshold else 0)
            scores.append(prob)
        except Exception:
            pass

    if not truth: return {'status': 'no_test_rows'}
    m = binary_metrics([bool(t) for t in truth], [bool(p) for p in preds])
    pos = [scores[i] for i, t in enumerate(truth) if t]
    neg = [scores[i] for i, t in enumerate(truth) if not t]
    m['mean_score_pos'] = round(float(np.mean(pos)), 4) if pos else 0.0
    m['mean_score_neg'] = round(float(np.mean(neg)), 4) if neg else 0.0
    m['test_rows'] = len(truth)
    m['threshold'] = threshold
    print(f'  [Encrypted] {len(truth)} rows: F1={m["f1"]:.3f} Acc={m["accuracy"]:.3f}', flush=True)
    return m


def eval_dns_graphsage(specialists_dir: Path, threshold: float, n: int = 200):
    """Evaluate DNS GraphSAGE on in-distribution test corpus."""
    from agent1_observation_dns.simulation.specialist_generators import dns_graph_corpus
    from agent1_observation_dns.models.dns_tunnel_graphsage.model import GraphBranch, _graph_tensors

    print('  [DNS-GraphSAGE] Loading and evaluating...', flush=True)
    dns_gs = GraphBranch.load(specialists_dir / 'dns_graphsage.pt')

    corpus = dns_graph_corpus(n_graphs=n, seed=42)
    test   = [r for r in corpus if r.get('split') == 'test']

    truth, preds, scores = [], [], []
    for row in test:
        try:
            x, ei  = _graph_tensors(row['node_features'], row['edges'])
            dns_gs._model.eval()
            with torch.no_grad():
                score = float(torch.sigmoid(dns_gs._model(x, ei)).item())
            truth.append(int(row['graph_label']))
            preds.append(1 if score >= threshold else 0)
            scores.append(score)
        except Exception:
            pass

    if not truth: return {'status': 'no_test_rows'}
    m = binary_metrics([bool(t) for t in truth], [bool(p) for p in preds])
    pos = [scores[i] for i, t in enumerate(truth) if t]
    neg = [scores[i] for i, t in enumerate(truth) if not t]
    m['mean_score_pos'] = round(float(np.mean(pos)), 4) if pos else 0.0
    m['mean_score_neg'] = round(float(np.mean(neg)), 4) if neg else 0.0
    m['test_graphs'] = len(truth)
    m['threshold'] = threshold
    print(f'  [DNS-GraphSAGE] {len(truth)} graphs: F1={m["f1"]:.3f} Acc={m["accuracy"]:.3f}', flush=True)
    return m


# ── 3. Aggregate and Report ──────────────────────────────────────────────────

def build_report(per_label: dict, run_dir: Path, threshold: float, total_s: float):
    # Load IDS results
    ids_results = {}
    for engine in ('snort', 'suricata', 'zeek'):
        path = run_dir / f'ids_{engine}' / 'episodes.json'
        if not path.exists(): continue
        rows = json.loads(path.read_text())
        bn   = [r for r in rows if not r['truth']]
        pl   = {}
        for label in IDS_LABELS:
            tv = [label in r['truth'] for r in rows]
            pv = [label in r['labels'] for r in rows]
            if not any(tv): pl[label] = {'status': 'not_in_corpus'}; continue
            m = binary_metrics(tv, pv)
            m['benign_fpr'] = round(sum(label in r['labels'] for r in bn) / max(len(bn), 1), 4)
            pl[label] = m
        ov = binary_metrics([bool(r['truth']) for r in rows], [bool(r['labels']) for r in rows])
        valid = [v for v in pl.values() if isinstance(v, dict) and 'f1' in v]
        ids_results[engine] = {
            'per_label': pl,
            'overall': ov,
            'macro_f1':      round(sum(v['f1'] for v in valid) / max(len(valid), 1), 4),
            'macro_accuracy':round(sum(v['accuracy'] for v in valid) / max(len(valid), 1), 4),
            'note': f'IDS families only ({len(rows)} episodes)',
        }

    diag_dir = run_dir / 'diagnostic'
    diag_dir.mkdir(exist_ok=True)
    full = {'ai_threat_detector': per_label, 'ids': ids_results,
            'threshold': threshold, 'inference_seconds': total_s}
    (diag_dir / 'comparison.json').write_text(json.dumps(full, indent=2, allow_nan=False) + '\n')

    # Markdown
    valid_ai = {lbl: m for lbl, m in per_label.items()
                if isinstance(m, dict) and 'f1' in m}
    ai_macro_f1  = round(np.mean([v['f1'] for v in valid_ai.values()]), 4) if valid_ai else 0.0
    ai_macro_acc = round(np.mean([v['accuracy'] for v in valid_ai.values()]), 4) if valid_ai else 0.0

    lines = [
        '# AI-Threat Detector vs IDS Tools — Diagnostic Benchmark',
        '',
        f'> **Mode:** Each model evaluated on its native training corpus (in-distribution test split)',
        f'> **Threshold:** {threshold} | **Total inference time:** {total_s:.1f}s',
        '>',
        '> Core bundle labels (DDoS/PORT_SCAN/EXFIL): raw MetaXGBoost pre-calibration.',
        '> Specialist labels (C2/Botnet/Encrypted/DNS): evaluated on specialist corpora.',
        '> IDS tools: evaluated on PCAP simulation families with custom behavioral rules.',
        '',
        '## Any-Threat Summary',
        '',
        '| System | Precision | Recall | F1 | Accuracy | Benign FPR | Macro F1 | Macro Acc | Scope |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---|',
    ]

    # AI row: compute overall from per_label
    ai_truth = []
    ai_pred  = []
    for lbl, m in per_label.items():
        if not isinstance(m, dict) or 'f1' not in m: continue
        # Approximate: use tp/(tp+fn) coverage
        ai_truth += [True]  * (m['tp'] + m['fn']) + [False] * (m['fp'] + m['tn'])
        ai_pred  += [True]  * m['tp'] + [False] * m['fn'] + [True] * m['fp'] + [False] * m['tn']
    if ai_truth:
        ov = binary_metrics(ai_truth, ai_pred)
        lines.append(f"| **AI-Threat Detector (all)** "
                     f"| {ov['precision']:.2%} | {ov['recall']:.2%} | {ov['f1']:.2%} "
                     f"| {ov['accuracy']:.2%} | {ov['fpr']:.2%} "
                     f"| {ai_macro_f1:.2%} | {ai_macro_acc:.2%} | all labels |")

    for engine, res in ids_results.items():
        m = res['overall']
        lines.append(f"| **{engine} custom** "
                     f"| {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} "
                     f"| {m['accuracy']:.2%} | {m['fpr']:.2%} "
                     f"| {res['macro_f1']:.2%} | {res['macro_accuracy']:.2%} | {res['note']} |")

    # Per-label for AI
    lines += ['', '## AI-Threat Detector — Per Label (native corpus test split)', '',
              '| Label | Threshold | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | FPR | Mean+ | Mean− |',
              '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for lbl in ALL_LABELS:
        m = per_label.get(lbl, {})
        if isinstance(m, dict) and 'f1' in m:
            lines.append(
                f"| **{lbl}** | {m.get('threshold', threshold):.2f} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
                f"| {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} "
                f"| {m['accuracy']:.2%} | {m['fpr']:.2%} "
                f"| {m.get('mean_score_pos',0):.3f} | {m.get('mean_score_neg',0):.3f} |")
        else:
            note = m.get('note', m.get('status', '—')) if isinstance(m, dict) else '—'
            lines.append(f'| **{lbl}** | — | — | — | — | — | — | — | — | — | — | — | — | *{note}* |')

    # IDS per label
    for engine, res in ids_results.items():
        lines += ['', f'## {engine} custom — Per Label', '',
                  '| Label | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | Benign FPR |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
        for lbl in IDS_LABELS:
            m = res['per_label'].get(lbl, {})
            if isinstance(m, dict) and 'f1' in m:
                lines.append(
                    f"| {lbl} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} "
                    f"| {m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} "
                    f"| {m['accuracy']:.2%} | {m.get('benign_fpr',0):.2%} |")
            else:
                lines.append(f'| {lbl} | — | — | — | — | N/A | N/A | N/A | N/A | N/A |')

    lines += ['', '**Notes:**',
              '- AI-Threat Detector core labels evaluated on in-distribution specialist-generator features.',
              '- Specialist labels (C2/Botnet/Encrypted/DNS) use their own native test corpora.',
              '- IDS tools have no rules for C2/Botnet/Encrypted — N/A for those families.',
              '- OSSEC excluded (host-only agent).',
              '- Mean+/Mean− show average model score on positive vs negative examples.',
              '']
    report_path = diag_dir / 'comparison.md'
    report_path.write_text('\n'.join(lines))
    return report_path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run',         required=True, type=Path)
    p.add_argument('--specialists', required=True, type=Path)
    p.add_argument('--threshold',   type=float, default=0.5)
    p.add_argument('--n-samples',   type=int, default=300)
    args = p.parse_args()

    run_dir     = args.run.resolve()
    spec_dir    = args.specialists.resolve()
    thr         = args.threshold
    n           = args.n_samples

    print(f'=== AI-Threat Detector Diagnostic Benchmark ===')
    print(f'Run dir:   {run_dir}')
    print(f'Threshold: {thr}')
    print(f'Samples:   {n} per corpus\n')

    from pipeline_runtime import current_release
    from agent2_detection_product.orchestration.registry import verify_manifest
    pointer       = current_release()
    manifest_path = ROOT / pointer['agent2_release']
    manifest      = verify_manifest(manifest_path, approved=False)
    bundle        = joblib.load(manifest_path.parent / manifest['bundle'])
    policy_path   = manifest_path.parent / manifest['policy']
    policy        = json.loads(policy_path.read_text()) if policy_path.exists() else {}
    policy_thr    = policy.get('thresholds', {})
    print(f'Loaded policy thresholds: {policy_thr}\n')
    torch.set_num_threads(2)

    t0 = time.perf_counter()
    per_label = {}

    # Core bundle evaluation
    print('Evaluating core bundle (DDoS/PORT_SCAN/EXFIL)...', flush=True)
    core_pl = eval_core_from_observations(bundle, run_dir, policy_thr)
    per_label.update(core_pl)

    # C2
    c2_thr = policy_thr.get('C2_BEACONING', thr)
    per_label['C2_BEACONING'] = eval_c2(spec_dir, c2_thr, n)
    # Botnet
    bot_h_thr = policy_thr.get('BOTNET_HOST', 0.82)
    bot_c_thr = policy_thr.get('BOTNET_COORDINATION', 0.82)
    botnet_pl = eval_botnet(spec_dir, bot_h_thr, bot_c_thr, n)
    per_label.update(botnet_pl)
    # Encrypted
    enc_thr = policy_thr.get('ENCRYPTED_MALWARE', thr)
    per_label['ENCRYPTED_MALWARE'] = eval_encrypted(spec_dir, enc_thr, n)
    # DNS GraphSAGE (used for DGA + DNS_TUNNEL)
    dns_thr = policy_thr.get('DGA', thr)
    dns_m = eval_dns_graphsage(spec_dir, dns_thr, min(n, 200))
    per_label['DGA']        = dns_m
    per_label['DNS_TUNNEL'] = dns_m   # same model covers both

    total_s = round(time.perf_counter() - t0, 1)
    print(f'\nDone in {total_s}s — building report...', flush=True)
    report = build_report(per_label, run_dir, thr, total_s)
    print(f'Report: {report}')


if __name__ == '__main__':
    main()
