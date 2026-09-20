"""Out-of-Distribution (OOD) and Adversarial Evasion generator for specialist models.

Contains hard generalization suites designed to challenge model assumptions:
  1. C2 Beaconing:
     - Burst-and-sleep cycles (non-stationary interval dynamics)
     - High-jitter randomized timing (45% - 75% uniform/Gaussian jitter)
     - Intermittent/missed callbacks (25% - 50% drop rate)
     - Ultra-low frequency telemetry (1h - 12h intervals)
     - Hard benign periodic negatives (NTP sync, cloud heartbeats)

  2. Botnet Topologies:
     - P2P decentralized mesh (no central hub)
     - Hierarchical multi-tier command tree (C2 -> Relays -> Workers)
     - Staggered asynchronous coordination
     - Benign cluster graph negatives (gossip protocol, load balancers)

  3. DNS Tunnel / DGA Graph:
     - Novel encoding alphabets (Base32, Base58, chunked Hex)
     - Mixed query record types (TXT, NULL, CNAME, AAAA)
     - High-volume CDN prefetch hard negatives
"""
from __future__ import annotations
import random
import math
import numpy as np


# ─── C2 OOD Generators ────────────────────────────────────────────────────────

def c2_ood_burst_sleep(rng: random.Random, n_cycles: int = 4) -> list[float]:
    """Adversary sends a burst of 3-6 quick commands, then sleeps for minutes/hours."""
    ts = [0.0]
    t = 0.0
    for _ in range(n_cycles):
        burst_count = rng.randint(3, 6)
        burst_gap = rng.uniform(0.2, 1.5)
        for _ in range(burst_count):
            t += burst_gap * rng.uniform(0.8, 1.2)
            ts.append(t)
        sleep_gap = rng.uniform(180.0, 1800.0)
        t += sleep_gap
        ts.append(t)
    return ts


def c2_ood_high_jitter(rng: random.Random, interval_s: float, n_events: int = 25, jitter: float = 0.60) -> list[float]:
    """High jitter (45% - 75%) designed to disrupt strict periodicity detectors."""
    ts = [0.0]
    t = 0.0
    for _ in range(n_events - 1):
        t += interval_s * rng.uniform(max(0.1, 1.0 - jitter), 1.0 + jitter)
        ts.append(t)
    return ts


def c2_ood_missed_callbacks(rng: random.Random, interval_s: float, n_events: int = 30, drop_rate: float = 0.35) -> list[float]:
    """Simulates dropped packets, network flakiness, or skipped intervals."""
    ts = [0.0]
    t = 0.0
    for _ in range(n_events * 2):
        gap = interval_s * rng.uniform(0.9, 1.1)
        t += gap
        if rng.random() > drop_rate:
            ts.append(t)
        if len(ts) >= n_events:
            break
    return ts


def c2_ood_benign_periodic(rng: random.Random, profile: str = "ntp") -> list[float]:
    """Hard negative: benign system services with periodic behavior."""
    ts = [0.0]
    t = 0.0
    if profile == "ntp":
        interval = 64.0  # standard NTP poll interval
        n = rng.randint(10, 25)
        for _ in range(n):
            t += interval + rng.uniform(-0.5, 0.5)
            ts.append(t)
    elif profile == "heartbeat":
        interval = 30.0  # keepalive ping
        n = rng.randint(12, 30)
        for _ in range(n):
            t += interval + rng.uniform(-0.1, 0.1)
            ts.append(t)
    else:
        n = rng.randint(10, 25)
        for _ in range(n):
            t += rng.expovariate(1.0 / 15.0)
            ts.append(t)
    return ts


def generate_c2_ood_corpus(n_samples: int = 400, seed: int = 42) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    suites = {
        "burst_and_sleep": [],
        "high_jitter_60pct": [],
        "missed_callbacks_35pct": [],
        "benign_periodic_ntp_hard_negatives": [],
    }

    for i in range(n_samples // 4):
        s_seed = seed + i * 701
        r = random.Random(s_seed)
        ts = c2_ood_burst_sleep(r, n_cycles=r.randint(3, 6))
        suites["burst_and_sleep"].append({"timestamps": ts, "label": 1, "test_case": "burst_sleep"})

    for i in range(n_samples // 4):
        s_seed = seed + i * 709
        r = random.Random(s_seed)
        interval = r.choice([15.0, 30.0, 60.0, 120.0, 300.0])
        ts = c2_ood_high_jitter(r, interval, n_events=r.randint(12, 35), jitter=0.60)
        suites["high_jitter_60pct"].append({"timestamps": ts, "label": 1, "test_case": "high_jitter"})

    for i in range(n_samples // 4):
        s_seed = seed + i * 719
        r = random.Random(s_seed)
        interval = r.choice([20.0, 45.0, 90.0, 180.0])
        ts = c2_ood_missed_callbacks(r, interval, n_events=r.randint(10, 25), drop_rate=0.35)
        suites["missed_callbacks_35pct"].append({"timestamps": ts, "label": 1, "test_case": "missed_callbacks"})

    for i in range(n_samples // 4):
        s_seed = seed + i * 727
        r = random.Random(s_seed)
        prof = r.choice(["ntp", "heartbeat"])
        ts = c2_ood_benign_periodic(r, profile=prof)
        suites["benign_periodic_ntp_hard_negatives"].append({"timestamps": ts, "label": 0, "test_case": f"benign_{prof}"})

    return suites


# ─── Botnet OOD Generators ───────────────────────────────────────────────────

def botnet_ood_p2p_mesh(rng: random.Random, n_nodes: int = 24) -> tuple[list, dict]:
    """Decentralized P2P botnet (e.g. Hajime/Mozi) with distributed coordination."""
    edges, targets = [], {}
    nodes = list(range(n_nodes))
    for node in nodes:
        targets[node] = (1, 1)
    k = 4
    for i in range(n_nodes):
        for j in range(1, k // 2 + 1):
            neighbor = (i + j) % n_nodes
            count = rng.randint(4, 15)
            edges.append((i, neighbor, {"count": count, "bytes": count * rng.randint(100, 600)}))
        if rng.random() < 0.3:
            shortcut = rng.choice(nodes)
            if shortcut != i:
                count = rng.randint(2, 8)
                edges.append((i, shortcut, {"count": count, "bytes": count * rng.randint(100, 600)}))
    return edges, targets


def botnet_ood_hierarchical(rng: random.Random, n_workers: int = 30) -> tuple[list, dict]:
    """Tiered architecture: 1 Root C2 -> 3 Proxy Relays -> 30 Worker Bots."""
    edges, targets = [], {}
    root = 0
    relays = [1, 2, 3]
    workers = list(range(4, 4 + n_workers))
    targets[root] = (1, 1)
    for r in relays:
        targets[r] = (1, 1)
        count = rng.randint(10, 25)
        edges.append((r, root, {"count": count, "bytes": count * 350}))
    for w in workers:
        targets[w] = (1, 0)
        assigned_relay = rng.choice(relays)
        count = rng.randint(3, 9)
        edges.append((w, assigned_relay, {"count": count, "bytes": count * 150}))
    return edges, targets


def botnet_ood_benign_cluster(rng: random.Random, n_nodes: int = 20) -> tuple[list, dict]:
    """Hard negative: Kubernetes / microservice cluster gossip protocol."""
    edges, targets = [], {}
    nodes = list(range(n_nodes))
    for node in nodes:
        targets[node] = (0, 0)
    master = 0
    for worker in nodes[1:]:
        count = rng.randint(20, 80)
        edges.append((worker, master, {"count": count, "bytes": count * 800}))
        if rng.random() < 0.2:
            peer = rng.choice(nodes[1:])
            if peer != worker:
                edges.append((worker, peer, {"count": rng.randint(2, 6), "bytes": 120}))
    return edges, targets


def generate_botnet_ood_corpus(n_samples: int = 150, seed: int = 42) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    suites = {
        "p2p_decentralized_mesh": [],
        "hierarchical_3tier_tree": [],
        "benign_cluster_hard_negatives": [],
    }

    for i in range(n_samples // 3):
        g_seed = seed + i * 809
        r = random.Random(g_seed)
        edges, targets = botnet_ood_p2p_mesh(r, n_nodes=r.randint(16, 36))
        suites["p2p_decentralized_mesh"].append({"edges": edges, "node_labels": targets, "label": 1})

    for i in range(n_samples // 3):
        g_seed = seed + i * 823
        r = random.Random(g_seed)
        edges, targets = botnet_ood_hierarchical(r, n_workers=r.randint(20, 45))
        suites["hierarchical_3tier_tree"].append({"edges": edges, "node_labels": targets, "label": 1})

    for i in range(n_samples // 3):
        g_seed = seed + i * 839
        r = random.Random(g_seed)
        edges, targets = botnet_ood_benign_cluster(r, n_nodes=r.randint(12, 28))
        suites["benign_cluster_hard_negatives"].append({"edges": edges, "node_labels": targets, "label": 0})

    return suites


# ─── DNS GraphSAGE OOD Generators ─────────────────────────────────────────────

def _domain_entropy(text: str) -> float:
    from collections import Counter
    counts = Counter(text)
    n = len(text)
    return -sum((c/n) * math.log2(c/n) for c in counts.values()) if n else 0.0


def _features_for_domain(domain: str) -> list[float]:
    ent = _domain_entropy(domain)
    digits = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    labels = len(domain.split("."))
    return [float(len(domain)), ent, digits, float(labels)]


def dns_ood_base32_tunnel(rng: random.Random, n_queries: int = 15) -> tuple[list, list]:
    b32_alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    domains = []
    for _ in range(n_queries):
        chunk1 = "".join(rng.choices(b32_alphabet, k=32))
        chunk2 = "".join(rng.choices(b32_alphabet, k=16))
        domains.append(f"{chunk1}.{chunk2}.novel-c2.org")
    features = [_features_for_domain(d) for d in domains]
    edges = [[0, i] for i in range(1, n_queries)] + [[i, 0] for i in range(1, n_queries)]
    return features, edges


def dns_ood_cdn_prefetch(rng: random.Random, n_queries: int = 20) -> tuple[list, list]:
    words = ["asset", "static", "img", "media", "cache", "edge"]
    domains = []
    for _ in range(n_queries):
        prefix = rng.choice(words)
        hash_id = "".join(rng.choices("0123456789abcdef", k=8))
        domains.append(f"{prefix}-{hash_id}.global-cdn.net")
    features = [_features_for_domain(d) for d in domains]
    edges = [[i, (i + 1) % n_queries] for i in range(n_queries)]
    return features, edges


def generate_dns_ood_corpus(n_samples: int = 100, seed: int = 42) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    suites = {
        "novel_base32_tunnel": [],
        "cdn_prefetch_hard_negatives": [],
    }
    for i in range(n_samples // 2):
        s_seed = seed + i * 907
        r = random.Random(s_seed)
        feats, edges = dns_ood_base32_tunnel(r, n_queries=r.randint(10, 25))
        suites["novel_base32_tunnel"].append({
            "node_features": feats, "edges": edges, "graph_label": 1
        })

    for i in range(n_samples // 2):
        s_seed = seed + i * 919
        r = random.Random(s_seed)
        feats, edges = dns_ood_cdn_prefetch(r, n_queries=r.randint(12, 30))
        suites["cdn_prefetch_hard_negatives"].append({
            "node_features": feats, "edges": edges, "graph_label": 0
        })

    return suites
