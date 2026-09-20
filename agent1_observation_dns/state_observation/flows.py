"""Unidirectional flow lifetimes, bounded LRU, event-time expiration."""
from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import json

from agent1_observation_dns.configs import Settings
from agent1_observation_dns.contracts import measured
from agent1_observation_dns.features.statistics import Moments
from agent1_observation_dns.normalization.packet import Packet


@dataclass
class Flow:
    key: tuple
    first_ns: int
    last_ns: int
    flow_id: str
    count: int = 0
    byte_count: int = 0
    sizes: Moments = field(default_factory=Moments)
    iats: Moments = field(default_factory=Moments)
    ttls: Moments = field(default_factory=Moments)
    flags: dict = field(default_factory=lambda: dict.fromkeys(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"), 0))
    bursts: int = 0
    idle_s: float = 0
    active_s: float = 0
    completion_visible: bool = False
    dns_features: dict = field(default_factory=dict)
    tls_features: dict = field(default_factory=dict)

    def add(self, packet: Packet, config: Settings):
        if self.count:
            gap = (packet.timestamp_ns - self.last_ns) / 1e9
            self.iats.add(gap)
            if gap > config.burst_gap_s:
                self.bursts += 1
            if gap > config.idle_gap_s:
                self.idle_s += gap
            else:
                self.active_s += gap
        else:
            self.bursts = 1
        self.last_ns = packet.timestamp_ns
        self.count += 1
        self.byte_count += packet.size
        self.sizes.add(packet.size)
        self.ttls.add(packet.ttl)
        if packet.flags is not None:
            for index, name in enumerate(self.flags):
                self.flags[name] += bool(packet.flags & (1 << index))
            self.completion_visible |= bool(packet.flags & 5)

    def features(self):
        duration = (self.last_ns - self.first_ns) / 1e9
        result = {name: measured(value, "ZERO_OBSERVATION_DURATION") for name, value in {
            "duration_s": duration, "packet_count": self.count, "byte_count": self.byte_count,
            "pps": self.count / duration if duration else None,
            "bps": self.byte_count * 8 / duration if duration else None,
            "burst_count": self.bursts, "idle_s": self.idle_s, "active_s": self.active_s}.items()}
        for name, moments in (("size", self.sizes), ("iat_s", self.iats), ("ttl", self.ttls)):
            result.update(moments.features(name))
        for flag, count in self.flags.items():
            applicable = self.key[-1] == "TCP"
            result[f"{flag.lower()}_count"] = measured(count if applicable else None, "NOT_TCP", applicable=applicable)
            result[f"{flag.lower()}_ratio"] = measured(count / self.count if applicable else None, "NOT_TCP", applicable=applicable)
        return result


class FlowTable:
    def __init__(self, config: Settings):
        self.config = config
        self.flows: OrderedDict[tuple, Flow] = OrderedDict()
        self.watermark_ns = -1
        self.serial = 0

    def expire(self, now_ns: int) -> list[tuple[Flow, str]]:
        result = []
        while self.flows:
            key, flow = next(iter(self.flows.items()))
            if now_ns - flow.last_ns < self.config.flow_ttl_s * 1e9:
                break
            result.append((self.flows.pop(key), "INACTIVITY_TIMEOUT"))
        return result

    def update(self, packet: Packet) -> tuple[Flow, list[tuple[Flow, str]]]:
        if packet.timestamp_ns < self.watermark_ns:
            raise ValueError("out-of-order event time; sort upstream without mixing splits")
        self.watermark_ns = packet.timestamp_ns
        closed = self.expire(packet.timestamp_ns)
        if packet.key not in self.flows:
            if len(self.flows) >= self.config.max_flows:
                _, evicted = self.flows.popitem(last=False)
                closed.append((evicted, "CAPACITY_EVICTION"))
            self.serial += 1
            identity = json.dumps([self.config.sensor_id, packet.key, packet.timestamp_ns, self.serial])
            self.flows[packet.key] = Flow(packet.key, packet.timestamp_ns, packet.timestamp_ns,
                                        hashlib.sha256(identity.encode()).hexdigest()[:32])
        flow = self.flows[packet.key]
        flow.add(packet, self.config)
        self.flows.move_to_end(packet.key)
        if flow.completion_visible:
            self.flows.pop(packet.key)
        return flow, closed

    def flush(self):
        result = [(flow, "END_OF_INPUT") for flow in self.flows.values()]
        self.flows.clear()
        return result
