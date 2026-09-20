"""Synthetic specialist corpora generator — no external data, no network access.

Generates:
  - C2 beaconing IAT sequences (periodic vs. random)
  - Botnet directed graphs (hub-and-spoke vs. benign mesh)
  - Encrypted-malware early packet sequences (burst vs. smooth HTTPS)
  - DNS co-query graphs built from lexical domain features

All randomness is seeded; train/val/test splits are disjoint by group_id.
"""
from __future__ import annotations
import random
import math
from typing import Iterator


# ─── Split assignment ─────────────────────────────────────────────────────────
_SPLIT_MAP = {"train": (0, 1, 2), "validation": (3,), "test": (4,)}

def _split_and_group(seed: int, n_groups: int = 5):
    group = seed % n_groups
    for split, groups in _SPLIT_MAP.items():
        if group in groups:
            return split, f"{split}-g{group}"
    return "train", f"train-g{group % 3}"


# ─── C2 Beaconing (IAT sequences) ────────────────────────────────────────────

def _beacon_sequence(rng: random.Random, interval_s: float, n: int, jitter: float = 0.15):
    """Periodic beacon with multiplicative jitter."""
    ts, t = [0.0], 0.0
    for _ in range(n - 1):
        t += interval_s * rng.uniform(1 - jitter, 1 + jitter)
        ts.append(t)
    return ts


def _random_sequence(rng: random.Random, n: int, mean_gap: float):
    """Heavy-tailed random IATs (Pareto) — benign or scan traffic."""
    ts, t = [0.0], 0.0
    for _ in range(n - 1):
        # Pareto shape=1.5 => heavier tail than exponential
        t += mean_gap * (rng.paretovariate(1.5))
        ts.append(t)
    return ts


def c2_corpus(n_sequences: int = 900, seed: int = 26) -> list[dict]:
    """Return list of {timestamps, label, split, group_id, scenario_id}."""
    rng = random.Random(seed)
    rows = []
    intervals = [10, 30, 60, 120, 300, 600, 1800, 3600]
    jitters = [0.05, 0.15, 0.30]
    for i in range(n_sequences):
        label = i % 2  # alternating pos/neg
        seq_seed = seed + i * 1009
        r = random.Random(seq_seed)
        n_events = r.randint(8, 50)
        if label == 1:  # C2 beacon
            interval = r.choice(intervals)
            jitter = r.choice(jitters)
            ts = _beacon_sequence(r, interval, n_events, jitter)
        else:  # benign / random
            mean_gap = r.uniform(1.0, 3600.0)
            ts = _random_sequence(r, n_events, mean_gap)
        split, group_id = _split_and_group(seq_seed)
        rows.append({
            "timestamps": ts,
            "label": label,
            "split": split,
            "group_id": group_id,
            "scenario_id": f"c2-{seq_seed}",
            "interval_hint": interval if label == 1 else None,
        })
    return rows


# ─── Botnet Graphs ────────────────────────────────────────────────────────────

def _hub_graph(rng: random.Random, n_bots: int, n_cc: int = 1):
    """Star topology: bots all connect to C&C (BOTNET_HOST=1)."""
    edges, targets = [], {}
    cc_nodes = list(range(n_cc))
    bot_nodes = list(range(n_cc, n_cc + n_bots))
    for node in cc_nodes:
        targets[node] = (1, 1)   # host=1, coordination=1
    for node in bot_nodes:
        targets[node] = (1, 0)   # host=1, coordination=0
        cc = rng.choice(cc_nodes)
        count = rng.randint(3, 12)
        edges.append((node, cc, {"count": count, "bytes": count * rng.randint(64, 512)}))
    return edges, targets


def _mesh_graph(rng: random.Random, n_nodes: int):
    """Random benign mesh — low fan-out, varied structure."""
    edges, targets = [], {}
    nodes = list(range(n_nodes))
    for node in nodes:
        targets[node] = (0, 0)
    n_edges = rng.randint(n_nodes, n_nodes * 2)
    seen = set()
    for _ in range(n_edges):
        src, dst = rng.sample(nodes, 2)
        if (src, dst) not in seen:
            seen.add((src, dst))
            count = rng.randint(1, 8)
            edges.append((src, dst, {"count": count, "bytes": count * rng.randint(40, 1400)}))
    return edges, targets


def botnet_corpus(n_graphs: int = 300, seed: int = 26) -> list[dict]:
    rows = []
    for i in range(n_graphs):
        g_seed = seed + i * 997
        r = random.Random(g_seed)
        label = i % 2
        if label == 1:
            n_bots = r.randint(4, 32)
            edges, targets = _hub_graph(r, n_bots)
        else:
            n_nodes = r.randint(4, 20)
            edges, targets = _mesh_graph(r, n_nodes)
        split, group_id = _split_and_group(g_seed)
        rows.append({
            "edges": edges,
            "node_labels": targets,  # {node_idx: (host_label, coord_label)}
            "label": label,
            "split": split,
            "group_id": group_id,
            "scenario_id": f"botnet-{g_seed}",
        })
    return rows


# ─── Encrypted Malware (early packet sequences) ───────────────────────────────

def _malware_sizes(rng: random.Random, budget: int = 32):
    """Malware: large download burst then tiny keepalives."""
    n_burst = rng.randint(4, 10)
    sizes = [rng.randint(900, 1500) for _ in range(n_burst)]
    sizes += [rng.randint(40, 80) for _ in range(budget - n_burst)]
    intervals = [rng.uniform(0.001, 0.05)] * n_burst + [rng.uniform(10, 120)] * (budget - n_burst)
    return sizes[:budget], intervals[:budget]


def _https_sizes(rng: random.Random, budget: int = 32):
    """Benign HTTPS: smooth mixed sizes throughout."""
    sizes = [rng.choice([64, 128, 256, 512, 1024, 1400]) for _ in range(budget)]
    intervals = [rng.uniform(0.01, 2.0) for _ in range(budget)]
    return sizes, intervals


def encrypted_corpus(n_sequences: int = 700, seed: int = 26) -> list[dict]:
    rows = []
    for i in range(n_sequences):
        e_seed = seed + i * 1013
        r = random.Random(e_seed)
        label = i % 2
        budget = r.randint(16, 32)
        if label == 1:
            sizes, intervals = _malware_sizes(r, budget)
        else:
            sizes, intervals = _https_sizes(r, budget)
        split, group_id = _split_and_group(e_seed)
        rows.append({
            "packet_sizes": sizes,
            "intervals": intervals,
            "label": label,
            "split": split,
            "group_id": group_id,
            "scenario_id": f"enc-{e_seed}",
        })
    return rows


# ─── DNS GraphSAGE corpus ─────────────────────────────────────────────────────

def _dga_domain(rng: random.Random) -> str:
    length = rng.randint(18, 30)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choices(chars, k=length)) + ".example.test"


def _tunnel_domain(rng: random.Random) -> str:
    payload = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz234567", k=rng.randint(40, 60)))
    return payload + ".tunnel.example.test"


def _benign_domain(rng: random.Random) -> str:
    words = ["api", "www", "cdn", "mail", "auth", "sync", "static", "media"]
    return rng.choice(words) + ".example.test"


def _domain_features(domain: str) -> list[float]:
    """[length, entropy, digit_ratio, label_count] — no identity."""
    from collections import Counter
    text = domain
    counts = Counter(text)
    n = len(text)
    ent = -sum((c/n) * math.log2(c/n) for c in counts.values()) if n else 0.0
    digits = sum(c.isdigit() for c in text) / max(n, 1)
    labels = len(domain.split("."))
    return [float(len(domain)), ent, digits, float(labels)]


def dns_graph_corpus(n_graphs: int = 400, seed: int = 26) -> list[dict]:
    """Build DNS co-query graphs: nodes=domains (featurised), edges=co-queried by same source."""
    rows = []
    for i in range(n_graphs):
        g_seed = seed + i * 1031
        r = random.Random(g_seed)
        label = i % 2
        n_domains = r.randint(4, 20)

        if label == 1:  # tunnel/DGA domains
            domains = [(_tunnel_domain(r) if r.random() < 0.5 else _dga_domain(r)) for _ in range(n_domains)]
        else:
            domains = [_benign_domain(r) for _ in range(n_domains)]

        node_features = [_domain_features(d) for d in domains]
        # Co-query edges: higher density for tunnel (same source queries many sub-domains)
        edges = []
        n_edges = r.randint(n_domains, n_domains * 3 if label == 1 else n_domains)
        seen = set()
        node_list = list(range(n_domains))
        for _ in range(n_edges * 2):
            if len(edges) >= n_edges:
                break
            src, dst = r.sample(node_list, 2)
            if (src, dst) not in seen:
                seen.add((src, dst))
                edges.append([src, dst])

        split, group_id = _split_and_group(g_seed)
        rows.append({
            "node_features": node_features,   # list of [length, entropy, digit_ratio, label_count]
            "edges": edges,                    # [[src_idx, dst_idx], ...]
            "graph_label": label,              # 1=DNS tunnel/DGA graph
            "node_labels": [label] * n_domains,
            "split": split,
            "group_id": group_id,
            "scenario_id": f"dnsgraph-{g_seed}",
        })
    return rows
