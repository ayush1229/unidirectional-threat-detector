"""Seeded offline packet fixtures. No traffic generation on a network."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import struct
from ipaddress import ip_address

import dpkt

from agent1_observation_dns import __version__
from agent1_observation_dns.capture.source import CapturedFrame
from agent1_observation_dns.contracts import ScenarioRelease
from agent1_observation_dns.ground_truth.splits import assign_partition, validate_partitions
from agent1_observation_dns.pipeline import ObservationPipeline

BENIGN_PROFILES = ("web_https", "dns", "quic", "ssh", "apis", "cloud_sync", "backups",
                   "periodic_polling", "load_changes", "flash_crowds", "high_volume_dns",
                   "service_discovery", "large_benign_transfers")
FAMILIES = ("BENIGN", "DDOS", "PORT_SCAN", "DGA", "DNS_TUNNEL", "C2", "BOTNET", "ENCRYPTED_MALWARE", "EXFILTRATION")


def plan_scenario(family: str, seed: int, *, profile="dns", start=None, packets=32, interval_s=.1,
                  source="192.0.2.10", destination="198.51.100.53") -> ScenarioRelease:
    if packets < 1 or packets > 1_000_000 or interval_s <= 0:
        raise ValueError("invalid scenario size or cadence")
    if family == "BENIGN" and profile not in BENIGN_PROFILES:
        raise ValueError("unknown benign profile")
    ip_address(source)
    ip_address(destination)
    start = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    identity = json.dumps([family, seed, profile, start.isoformat(), packets, interval_s, source, destination])
    scenario_id = hashlib.sha256(identity.encode()).hexdigest()[:24]
    group = f"offline-metadata-v1:{seed}"
    return ScenarioRelease(scenario_id=scenario_id, generator="offline-metadata-v1", family=family, seed=seed,
        start=start, end=start+timedelta(seconds=(packets-1)*interval_s), source=source, destination=destination,
        software_versions={"agent1": __version__, "python": platform.python_version(), "dpkt": dpkt.__version__},
        attack_parameters={"packets": packets, "interval_s": interval_s, "profile": profile},
        expected_labels=[family], split_assignment=assign_partition(group), split_group=group,
        tool="offline-fixture", hard_negative_tags=[profile] if family == "BENIGN" else [])


def generate_frames(manifest: ScenarioRelease):
    rng = random.Random(manifest.seed)
    params = manifest.attack_parameters
    profile, family = params["profile"], manifest.family
    count, interval = int(params["packets"]), float(params["interval_s"])
    start_ns = int((manifest.start-datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()*1e9)
    for i in range(count):
        is_dns = family in ("DGA", "DNS_TUNNEL") or family == "BENIGN" and profile in ("dns", "high_volume_dns", "service_discovery")
        port = 53 if is_dns else (i % 65535 + 1) if family == "PORT_SCAN" else 22 if profile == "ssh" else 443
        if is_dns:
            if family == "DGA":
                label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24))
            elif family == "DNS_TUNNEL":
                label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz234567", k=56))
            else:
                label = rng.choice(("www", "api", "sync", "mail"))
            name = f"{label}.example.test"
            message = dpkt.dns.DNS(id=i % 65536, qd=[dpkt.dns.DNS.Q(name=name, type=16 if family == "DNS_TUNNEL" else 1)])
            transport = dpkt.udp.UDP(sport=40000, dport=port, data=bytes(message))
            transport.ulen = len(transport)
            protocol = 17
        elif profile == "quic" and family == "BENIGN":
            # Opaque UDP bytes: no claim that a QUIC handshake is synthesized.
            transport = dpkt.udp.UDP(sport=40000, dport=443, data=b"\0" * 100)
            transport.ulen = len(transport)
            protocol = 17
        else:
            length = 1200 if family == "EXFILTRATION" or profile in ("backups", "large_benign_transfers", "cloud_sync") else 64
            flags = 2 if family in ("DDOS", "PORT_SCAN") else 24
            transport = dpkt.tcp.TCP(sport=40000+i % 100 if family == "DDOS" else 40000, dport=port,
                                      flags=flags, seq=i*length, data=b"\0"*length)
            protocol = 6
        src, dst = ip_address(manifest.source), ip_address(manifest.destination)
        if src.version != dst.version:
            raise ValueError("mixed endpoint IP versions")
        if src.version == 4:
            ip = dpkt.ip.IP(src=src.packed, dst=dst.packed, ttl=64, p=protocol, data=transport)
            ip.len = len(ip)
        else:
            ip = dpkt.ip6.IP6(src=src.packed, dst=dst.packed, hlim=64, nxt=protocol, data=transport)
            ip.plen = len(transport)
        data = bytes(dpkt.ethernet.Ethernet(src=b"\x02"*6, dst=b"\x04"*6, type=0x800 if src.version == 4 else 0x86dd, data=ip))
        yield CapturedFrame(start_ns + round(i*interval*1e9), data, len(data))


def release_dataset(manifests, output: str | Path):
    """Validate all plans before generating anything. Refuse to overwrite releases."""
    manifests = list(manifests)
    validate_partitions(manifests)
    if len({m.scenario_id for m in manifests}) != len(manifests):
        raise ValueError("duplicate scenario IDs")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for manifest in manifests:
        directory = output / manifest.split_assignment / manifest.scenario_id
        directory.mkdir(parents=True)
        with (directory / "capture.pcap").open("xb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
            for frame in generate_frames(manifest):
                stream.write(struct.pack("<IIII", frame.timestamp_ns//10**9, frame.timestamp_ns%10**9,
                                         len(frame.data), frame.wire_length))
                stream.write(frame.data)
        snapshots = []
        with (directory / "observations.jsonl").open("x", encoding="utf-8") as stream:
            for event in ObservationPipeline().run(generate_frames(manifest)):
                stream.write(event.model_dump_json()+"\n")
                if len(snapshots) < 2:
                    snapshots.append(event.model_dump(mode="json"))
        manifest = manifest.model_copy(update={"feature_snapshots": snapshots})
        (directory / "manifest.json").write_text(manifest.model_dump_json(indent=2)+"\n", encoding="utf-8")
