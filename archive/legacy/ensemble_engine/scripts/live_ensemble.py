"""
scripts/live_ensemble.py
==========================
Person 2 — Unsupervised & Sequential Deep Learning Engineer

The live production loop: subscribes to Redis channel `flow.raw`
(Person 3's ingestion output), runs every flow through the fused
ensemble (ensemble.score_flow — supervised + anomaly + sequence + malware-TLS),
and publishes the resulting alert object to Redis channel `alert.new` for
Person 4's API layer to consume.

Also maintains a FlowStateTracker for cross-flow port fan-out and
source-IP diversity entropy, and publishes pipeline throughput stats
to Redis key `pipeline.stats` every STATS_INTERVAL_S seconds.

Usage
-----
    python ensemble_engine/scripts/live_ensemble.py

Requires: Redis running, and all model artifacts trained (train_anomaly.py,
train_lstm.py) — this script will error clearly on startup if any are missing.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

import redis

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from ensemble import score_flow, BENIGN_CLASS
from flow_state_tracker import FlowStateTracker

# How often to publish pipeline.stats to Redis (seconds)
STATS_INTERVAL_S = 10

# Rolling window for flows/sec measurement (seconds)
THROUGHPUT_WINDOW_S = 10


def _compute_flows_per_sec(timestamps: collections.deque) -> float:
    """Return flows/sec over the last THROUGHPUT_WINDOW_S seconds."""
    now = time.time()
    cutoff = now - THROUGHPUT_WINDOW_S
    recent = sum(1 for t in timestamps if t >= cutoff)
    return round(recent / THROUGHPUT_WINDOW_S, 2)


def main():
    parser = argparse.ArgumentParser(description="Live ensemble scoring: flow.raw -> alert.new")
    parser.add_argument("--redis-host", default="127.0.0.1")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--in-channel", default="flow.raw")
    parser.add_argument("--out-channel", default="alert.new")
    parser.add_argument("--publish-benign", action="store_true",
                         help="Also publish BENIGN-classified flows to alert.new "
                              "(off by default — only non-benign flows are alerts)")
    parser.add_argument("--log-every", type=int, default=1,
                         help="Print a line every N flows processed (not just alerts)")
    args = parser.parse_args()

    try:
        r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True, protocol=2)
        r.ping()
    except redis.ConnectionError:
        print(f"[-] Could not connect to Redis at {args.redis_host}:{args.redis_port}")
        print("    Make sure Redis is running (docker run -p 6379:6379 redis:7-alpine).")
        sys.exit(1)

    # Fail fast and clearly if models aren't trained yet.
    try:
        _ = score_flow({
            "flow_id": "startup-check", "five_tuple": {"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0",
            "src_port": 0, "dst_port": 0, "protocol": "TCP"},
            "duration_s": 0.1, "total_packets": 1, "total_bytes": 60, "bytes_in": 60,
            "packet_sizes": [60], "inter_arrival_times": [], "tcp_flags_seen": [],
            "tls_meta": None, "dns_meta": None,
        })
        print("[+] Model artifacts loaded OK (Isolation Forest, Autoencoder, LSTM, supervised).")
    except FileNotFoundError as e:
        print(f"[-] Missing model artifact: {e}")
        print("    Run train_anomaly.py and train_lstm.py first.")
        sys.exit(1)

    # Cross-flow state tracker — port fan-out + source-IP entropy
    tracker = FlowStateTracker()
    print("[+] FlowStateTracker initialized (cross-flow port fan-out + src-IP entropy).")

    pubsub = r.pubsub()
    pubsub.subscribe(args.in_channel)

    print(f"[+] Subscribed to '{args.in_channel}', publishing alerts to '{args.out_channel}'")
    print("[+] Running — Ctrl+C to stop\n")

    processed       = 0
    alerts_published = 0
    errors          = 0
    start_time      = time.time()
    last_stats_time = start_time

    # Rolling deque of flow timestamps for flows/sec measurement
    flow_timestamps: collections.deque = collections.deque(maxlen=10_000)

    try:
        for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                flow_obj = json.loads(message["data"])
            except json.JSONDecodeError:
                print("[!] Skipped malformed message (not valid JSON)")
                errors += 1
                continue

            # Record into cross-flow tracker BEFORE scoring so entropy/fanout
            # are populated for this flow's evidence fields.
            tracker.record(flow_obj)
            flow_timestamps.append(time.time())

            try:
                alert = score_flow(flow_obj, tracker=tracker)
            except Exception as e:
                # A single bad/unexpected flow should never take the whole
                # live detector down — log it, count it, keep processing.
                print(f"[!] Scoring error on flow {flow_obj.get('flow_id', '?')}: {e}")
                errors += 1
                continue

            processed += 1
            is_alertable = alert["threat_class"] != BENIGN_CLASS

            if is_alertable or args.publish_benign:
                r.publish(args.out_channel, json.dumps(alert))
                alerts_published += 1

            if is_alertable:
                five_tuple = alert["five_tuple"] or {}
                true_label = flow_obj.get("collected_label", "UNKNOWN")
                match_status = "✅" if alert['threat_class'] == true_label else "❌"

                print(f"  🚨 [{alert['severity']}] {alert['threat_class']} {match_status} "
                      f"(true: {true_label}, conf={alert['confidence_score']:.2f})  "
                      f"{five_tuple.get('src_ip')}:{five_tuple.get('src_port')} "
                      f"-> {five_tuple.get('dst_ip')}:{five_tuple.get('dst_port')}  "
                      f"[sup={alert['model_source']['supervised_score']:.2f} "
                      f"anom={alert['model_source']['anomaly_score']:.2f} "
                      f"seq={alert['model_source']['sequence_score']:.2f}]")
            elif args.log_every and processed % args.log_every == 0:
                five_tuple = alert["five_tuple"] or {}
                print(f"  [{processed}] benign — {five_tuple.get('src_ip', '?')}")

            # Publish pipeline stats to Redis every STATS_INTERVAL_S seconds.
            # Person 4's /api/stats endpoint reads this key.
            now = time.time()
            if now - last_stats_time >= STATS_INTERVAL_S:
                flows_per_sec = _compute_flows_per_sec(flow_timestamps)
                elapsed = now - start_time
                alerts_per_min = round(alerts_published / max(elapsed / 60, 0.0167), 1)
                tracker_state = tracker.stats()
                stats_payload = json.dumps({
                    "flows_per_sec": flows_per_sec,
                    "alerts_per_min": alerts_per_min,
                    "processed_total": processed,
                    "alerts_total": alerts_published,
                    "errors_total": errors,
                    "uptime_s": round(elapsed, 1),
                    "tracked_src_ips": tracker_state["tracked_src_ips"],
                    "tracked_dst_ips": tracker_state["tracked_dst_ips"],
                    "throughput_window_s": THROUGHPUT_WINDOW_S,
                })
                r.set("pipeline.stats", stats_payload, ex=60)  # TTL 60s — stale after 1 min
                last_stats_time = now

    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start_time
    print(f"\n[+] Stopped. Processed {processed} flows in {elapsed:.1f}s "
          f"({alerts_published} alerts published, {errors} errors)")


if __name__ == "__main__":
    main()
