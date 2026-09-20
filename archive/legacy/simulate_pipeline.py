"""
simulate_pipeline.py
====================
Simulates the full SIH26145 threat detection pipeline from end to end:
  [Ingestion / Attack Flows] -> Redis `flow.raw`
    -> [ML Ensemble (Person 1 XGBoost + Person 2 Deep Learning / Anomaly / LSTM)]
    -> Redis `alert.new`
    -> [Person 4 Express & WebSocket Backend (Port 4000)]
    -> [SOC React Dashboard (Port 5173)]

Usage:
  python simulate_pipeline.py [--continuous] [--interval 1.5] [--scenario all|c2|ddos|scan|dns|dga|exfil|benign]
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis

# Connect to Redis lazily
_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.Redis(host='127.0.0.1', port=6379, decode_responses=True, protocol=2)
            _redis_client.ping()
        except Exception as e:
            print(f"[-] Cannot connect to Redis at 127.0.0.1:6379: {e}")
            print("    Please ensure Redis is running.")
            sys.exit(1)
    return _redis_client


def generate_flow(scenario: str) -> dict:
    flow_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    if scenario == "c2":
        # Botnet C2 Beaconing: periodic small payloads to port 443, regular inter-arrival times with natural jitter
        src_ip = f"10.0.{random.randint(1,5)}.{random.randint(10,50)}"
        dst_ip = "198.51.100.23"
        sport = random.randint(40000, 60000)
        base_interval = random.choice([15.0, 30.0, 45.0, 60.0])
        jitter_pct = random.uniform(0.03, 0.14)
        n_p = random.randint(4, 8)
        iats = [round(base_interval * (1 + random.uniform(-jitter_pct, jitter_pct)), 2) for _ in range(n_p - 1)]
        pkts = [random.choice([64, 68, 72, 74, 80, 84]) for _ in range(n_p)]
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": 443, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": round(sum(iats), 2),
            "total_packets": n_p,
            "total_bytes": sum(pkts),
            "bytes_in": sum(pkts),
            "bytes_out_proxy": 0,
            "packet_sizes": pkts,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["A", "F", "P", "S"],
            "tls_meta": {"ja3_fingerprint": "771,4865-4866-4867,0-23-65281,29-23-24,0", "ja4_fingerprint": "t13d1516h2_8daaf6152771_000000000000", "sni": "c2-beacon-channel.xyz", "cipher_suites": ["0x1301", "0x1302"]},
            "dns_meta": None,
            "zeek_conn_state": "SF",
            "collected_label": "BOTNET_C2_BEACONING"
        }

    elif scenario == "ddos":
        # Volumetric DDoS flood: ultra-high packet rate, sub-millisecond IAT burst
        src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
        dst_ip = "10.0.0.1"
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 8080, 53])
        n_pkts = random.randint(30, 200)
        dur = random.uniform(0.001, 0.02)
        pkt_size = random.choice([512, 600, 800, 1024])
        pkts = [pkt_size] * min(n_pkts, 30)
        total_b = pkt_size * n_pkts
        iats = [round(dur / max(n_pkts - 1, 1), 6)] * min(n_pkts - 1, 29)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport, "protocol": "TCP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": dur,
            "total_packets": n_pkts,
            "total_bytes": total_b,
            "bytes_in": total_b,
            "bytes_out_proxy": 0,
            "packet_sizes": pkts,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["S"],
            "tls_meta": None,
            "dns_meta": None,
            "zeek_conn_state": "S0",
            "collected_label": "VOLUMETRIC_DDOS"
        }

    elif scenario == "scan":
        # Port Scan: single or few SYN probes across diverse ports
        src_ip = "172.16.4.88"
        dst_ip = "10.0.0.2"
        dport = random.choice([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 2100, 3306, 3389, 8080, 8443, 9000, 49152])
        sport = random.randint(40000, 60000)
        n_pkts = random.choice([1, 1, 1, 2])
        dur = random.uniform(0.00002, 0.0005)
        pkts = [random.choice([0, 54, 60])] * n_pkts
        iats = [dur] if n_pkts > 1 else []
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport, "protocol": "TCP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": dur,
            "total_packets": n_pkts,
            "total_bytes": sum(pkts),
            "bytes_in": sum(pkts),
            "bytes_out_proxy": 0,
            "packet_sizes": pkts,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["S"],
            "tls_meta": None,
            "dns_meta": None,
            "zeek_conn_state": "S0",
            "collected_label": "PORT_SCAN"
        }

    elif scenario == "dns":
        # DNS Tunnelling: Base32/Hex encoded subdomain queries to covert domain
        src_ip = f"10.0.1.{random.randint(10,99)}"
        dst_ip = "8.8.8.8"
        mode = random.choice(["base32", "hex"])
        if mode == "base32":
            subdomain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=random.randint(28, 42)))
            qname = f"{subdomain}.tunnel.c2.example.com"
        else:
            hex_data = "".join(random.choices("0123456789abcdef", k=random.randint(24, 48)))
            session = random.randint(1000, 9999)
            qname = f"{hex_data}.{session}.tunnel.c2.example.com"
        qtype = random.choice(["TXT", "A", "NULL"])
        sz = random.randint(80, 180)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 50000), "dst_port": 53, "protocol": "UDP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": random.uniform(0.02, 0.1),
            "total_packets": 2,
            "total_bytes": sz * 2,
            "bytes_in": sz * 2,
            "bytes_out_proxy": 0,
            "packet_sizes": [sz, sz],
            "inter_arrival_times": [random.uniform(0.02, 0.08)],
            "tcp_flags_seen": [],
            "tls_meta": None,
            "dns_meta": {"query_name": qname, "query_type": qtype, "query_length": len(qname), "answer_count": 0},
            "zeek_conn_state": "SF",
            "collected_label": "DNS_TUNNELING"
        }

    elif scenario == "dga":
        # DGA Domain lookup: pseudorandom domain string
        src_ip = f"10.0.2.{random.randint(10,99)}"
        dst_ip = "1.1.1.1"
        dga_names = [
            "wxsnapghers.name", "kxyzypkvyta.name", "blackstone122.top",
            "yhgxkzydcni.info", "qbcjejutuja.org", "firewind834.biz",
            "yzaludqdale.info", "grknexarqfa.mobi", "xopqlanbvsd.biz", "zxcvbnmasdf.org",
            "pqwoeiruty.biz", "lkjhgfdsa.ru", "mnbvcxzlk.cc", "qazwsxedc.top",
            "rfvtgbyhn.info", "ujmikolp.biz", "zaqxswcde.org", "plmkoijn.xyz"
        ]
        qname = random.choice(dga_names)
        sz = random.randint(60, 100)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 50000), "dst_port": 53, "protocol": "UDP"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": random.uniform(0.01, 0.08),
            "total_packets": 2,
            "total_bytes": sz * 2,
            "bytes_in": sz * 2,
            "bytes_out_proxy": 0,
            "packet_sizes": [sz, sz],
            "inter_arrival_times": [random.uniform(0.01, 0.05)],
            "tcp_flags_seen": [],
            "tls_meta": None,
            "dns_meta": {"query_name": qname, "query_type": "A", "query_length": len(qname), "answer_count": 0},
            "zeek_conn_state": "SF",
            "collected_label": "DGA"
        }

    elif scenario == "exfil":
        # Data Exfiltration: large volume of outbound bytes, high payload
        src_ip = "10.0.0.15"
        dst_ip = "203.0.113.88"
        dur = random.uniform(1.5, 6.0)
        n_pkts = random.randint(30, 100)
        pkt_size = random.randint(1200, 1460)
        pkts = [pkt_size] * min(n_pkts, 30)
        total_b = pkt_size * n_pkts
        base_iat = dur / max(n_pkts - 1, 1)
        iats = [round(base_iat * random.uniform(0.7, 1.3), 4) for _ in range(min(n_pkts - 1, 29))]
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": 52140, "dst_port": 443, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": dur,
            "total_packets": n_pkts,
            "total_bytes": total_b,
            "bytes_in": total_b,
            "bytes_out_proxy": 0,
            "packet_sizes": pkts,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["A", "F", "P", "S"],
            "tls_meta": {"ja3_fingerprint": "771,4865-4866,0-23,29,0", "ja4_fingerprint": "t13d1516h2_8daaf6152771_000000000000", "sni": "secure-upload.cdn-node.org", "cipher_suites": ["0x1301"]},
            "dns_meta": None,
            "zeek_conn_state": "SF",
            "collected_label": "DATA_EXFILTRATION"
        }

    elif scenario == "encrypted_malware":
        # Malware in Encrypted Sessions: suspicious JA3/JA4 fingerprints from known malware loaders.
        # Detection is purely from TLS metadata — no payload decryption.
        # JA3 hashes below are from known C2 frameworks (Metasploit, CobaltStrike, Emotet)
        # published in open threat intel databases.
        src_ip = f"10.0.{random.randint(3, 9)}.{random.randint(10, 254)}"
        dst_ip = f"185.{random.randint(200, 255)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        sport = random.randint(49152, 65535)
        dport = random.choice([443, 8443, 4443, 8080])
        # Malware-associated JA3 hashes (publicly documented):
        # - 72a589da586844d7f0818ce684948eea  (Metasploit Meterpreter)
        # - a0e9f5d64349fb13191bc781f81f42e1  (CobaltStrike default)
        # - 6734f37431670b3ab4292b8f60f29984  (Emotet loader)
        malware_ja3 = random.choice([
            "72a589da586844d7f0818ce684948eea",
            "a0e9f5d64349fb13191bc781f81f42e1",
            "6734f37431670b3ab4292b8f60f29984",
        ])
        # Short, uniform IATs with small packet sizes — loader handshake then waits
        n_p = random.randint(6, 14)
        base_iat = random.uniform(0.01, 0.05)
        iats = [round(base_iat * random.uniform(0.85, 1.15), 4) for _ in range(n_p - 1)]
        pkt_sizes = [random.choice([64, 74, 78, 128, 256]) for _ in range(n_p)]
        dur = sum(iats)
        return {
            "schema_version": "1.0.0",
            "flow_id": flow_id,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport, "protocol": "TCP/TLS"},
            "sensor_id": "diode-sensor-01",
            "capture_interface": "lo",
            "pipeline_version": "1.0.0",
            "duration_s": round(dur, 4),
            "total_packets": n_p,
            "total_bytes": sum(pkt_sizes),
            "bytes_in": sum(pkt_sizes),
            "bytes_out_proxy": 0,
            "packet_sizes": pkt_sizes,
            "inter_arrival_times": iats,
            "tcp_flags_seen": ["S", "A", "P"],
            "tls_meta": {
                "ja3_fingerprint": malware_ja3,
                "ja4_fingerprint": "t13d190900_" + malware_ja3[:12],
                "sni": None,   # Malware often omits SNI or uses an IP address
                "cipher_suites": ["0x0035", "0x002f", "0xc014"],  # Weak/odd cipher suite selection
            },
            "dns_meta": None,
            "zeek_conn_state": "SF",
            "collected_label": "MALWARE_ENCRYPTED_TLS"
        }

    else:
        # Normal Benign Traffic: varied web browsing or benign DNS lookup
        src_ip = f"10.0.0.{random.randint(20, 80)}"
        if random.random() < 0.4:
            # Benign DNS lookup
            benign_domains = [
                "google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com",
                "cloudflare.com", "github.com", "wikipedia.org", "ubuntu.com", "netflix.com"
            ]
            qname = random.choice(benign_domains)
            sz = random.randint(50, 85)
            return {
                "schema_version": "1.0.0",
                "flow_id": flow_id,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "five_tuple": {"src_ip": src_ip, "dst_ip": "8.8.8.8", "src_port": random.randint(40000, 60000), "dst_port": 53, "protocol": "UDP"},
                "sensor_id": "diode-sensor-01",
                "capture_interface": "lo",
                "pipeline_version": "1.0.0",
                "duration_s": random.uniform(0.01, 0.05),
                "total_packets": 2,
                "total_bytes": sz * 2,
                "bytes_in": sz * 2,
                "bytes_out_proxy": 0,
                "packet_sizes": [sz, sz],
                "inter_arrival_times": [random.uniform(0.01, 0.04)],
                "tcp_flags_seen": [],
                "tls_meta": None,
                "dns_meta": {"query_name": qname, "query_type": "A", "query_length": len(qname), "answer_count": 2},
                "zeek_conn_state": "SF",
                "collected_label": "BENIGN"
            }
        else:
            # Benign HTTP/HTTPS browsing
            dst_ip = random.choice(["142.250.190.46", "151.101.1.69", "13.107.42.14", "104.16.132.229"])
            n_pkts = random.randint(4, 15)
            dur = random.uniform(0.2, 2.5)
            pkts = [random.choice([64, 128, 512, 1200, 1400, 80, 220]) for _ in range(min(n_pkts, 15))]
            tb = sum(pkts)
            # Real browser HTTPS traffic is BURSTY, not periodic:
            # - packets arrive in bursts (request + response + ACKs) separated by think time
            # - IAT coefficient of variation (std/mean) is typically well above 0.5
            # - This ensures the LSTM beacon detector cannot confuse this with
            #   C2 beaconing, which has very low CV (highly regular clock-like timing)
            n_iats = min(n_pkts - 1, 14)
            burst_size = random.randint(2, 4)
            iats = []
            for i in range(n_iats):
                if i % burst_size == 0:
                    # Think time between bursts: hundreds of ms to seconds
                    iats.append(round(random.uniform(0.15, dur * 0.6), 3))
                else:
                    # Within a burst: sub-millisecond to a few ms
                    iats.append(round(random.uniform(0.001, 0.025), 3))
            return {
                "schema_version": "1.0.0",
                "flow_id": flow_id,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "five_tuple": {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": random.randint(40000, 60000), "dst_port": 443, "protocol": "TCP/TLS"},
                "sensor_id": "diode-sensor-01",
                "capture_interface": "lo",
                "pipeline_version": "1.0.0",
                "duration_s": dur,
                "total_packets": n_pkts,
                "total_bytes": tb,
                "bytes_in": tb,
                "bytes_out_proxy": 0,
                "packet_sizes": pkts,
                "inter_arrival_times": iats,
                "tcp_flags_seen": ["A", "F", "P", "S"],
                "tls_meta": {"ja3_fingerprint": "771,4865-4866-4867,0-23,29,0", "ja4_fingerprint": "t13d1516h2_8daaf6152771_000000000000", "sni": "www.google.com", "cipher_suites": ["0x1301", "0x1302"]},
                "dns_meta": None,
                "zeek_conn_state": "SF",
                "collected_label": "BENIGN"
            }


def main():
    parser = argparse.ArgumentParser(description="Live traffic & threat flow injector")
    parser.add_argument("--scenario", default="all", choices=["all", "c2", "ddos", "scan", "dns", "dga", "exfil", "encrypted_malware", "benign"])
    parser.add_argument("--interval", type=float, default=1.5, help="Seconds between flows")
    parser.add_argument("--count", type=int, default=0, help="Number of flows to send (0 = infinite)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously (same as --count 0)")
    parser.add_argument("--export", type=str, default="", help="Export generated flows to a JSONL file directly instead of Redis")
    args = parser.parse_args()

    scenarios = ["c2", "ddos", "scan", "dns", "dga", "exfil", "encrypted_malware", "benign"] if args.scenario == "all" else [args.scenario]

    # File export mode
    if args.export:
        export_count = args.count if args.count > 0 else 1400
        print(f"[*] Exporting {export_count} balanced flows directly to {args.export}...")
        flows_per_scenario = max(1, export_count // len(scenarios))
        exported_flows = []
        for sc in scenarios:
            for _ in range(flows_per_scenario):
                exported_flows.append(generate_flow(sc))
        # Fill remainder
        while len(exported_flows) < export_count:
            exported_flows.append(generate_flow(random.choice(scenarios)))
        random.shuffle(exported_flows)
        
        out_path = Path(args.export)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for flow in exported_flows:
                f.write(json.dumps(flow) + "\n")
        print(f"[+] Successfully exported {len(exported_flows)} flows to {out_path}.")
        return

    # Redis mode
    r = get_redis_client()
    print("=" * 65)
    print("  SIH26145 Live Threat & Traffic Simulator")
    print("  Injecting flows to Redis channel 'flow.raw'...")
    print(f"  Scenarios: {', '.join(scenarios)}")
    print(f"  Interval:  {args.interval}s")
    print("=" * 65)

    sent = 0
    try:
        while True:
            scenario = random.choice(scenarios) if args.scenario == "all" else args.scenario
            flow = generate_flow(scenario)
            
            listeners = r.publish("flow.raw", json.dumps(flow))
            sent += 1

            ft = flow["five_tuple"]
            print(f"[{sent:03d}] Published ({scenario.upper():6s}) -> {ft['src_ip']}:{ft['src_port']} -> {ft['dst_ip']}:{ft['dst_port']} [{ft['protocol']}] (listeners: {listeners})")

            if args.count > 0 and sent >= args.count:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n[+] Stopped. Total flows injected: {sent}")


if __name__ == "__main__":
    main()
