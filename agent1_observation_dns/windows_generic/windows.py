"""Bounded event-time rolling host windows, for both endpoint roles."""
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from math import log2

from agent1_observation_dns.configs import Settings
from agent1_observation_dns.contracts import measured
from agent1_observation_dns.normalization.packet import Packet


@dataclass(frozen=True, slots=True)
class WindowEvent:
    ns: int
    peer: str
    port: int
    size: int
    syn: bool | None
    rst: bool | None
    domain: str | None
    new_flow: bool
    new_peer: bool


@dataclass
class Host:
    first_ns: int
    events: deque = field(default_factory=deque)
    lost_through_ns: int = -1


class HostWindows:
    def __init__(self, config: Settings):
        self.config = config
        self.hosts: OrderedDict[tuple[str, str], Host] = OrderedDict()

    def expire(self, ns: int):
        cutoff = ns - max(self.config.windows_s) * 10**9
        for key in list(self.hosts):
            host = self.hosts[key]
            while host.events and host.events[0].ns <= cutoff:
                host.events.popleft()
            if not host.events:
                del self.hosts[key]

    def update(self, packet: Packet, *, domain: str | None = None, new_flow=False):
        self.expire(packet.timestamp_ns)
        for role, host_id, peer, port in (("source", packet.source, packet.destination, packet.destination_port),
                                         ("destination", packet.destination, packet.source, packet.source_port)):
            key = (role, host_id)
            if key not in self.hosts:
                if len(self.hosts) >= self.config.max_hosts:
                    self.hosts.popitem(last=False)
                self.hosts[key] = Host(packet.timestamp_ns)
            host = self.hosts[key]
            new_peer = not any(e.peer == peer for e in host.events)
            if len(host.events) >= self.config.max_window_events:
                host.lost_through_ns = host.events.popleft().ns
            host.events.append(WindowEvent(packet.timestamp_ns, peer, port, packet.size,
                                           bool(packet.flags & 2) if packet.flags is not None else None,
                                           bool(packet.flags & 4) if packet.flags is not None else None,
                                           domain, new_flow, new_peer))
            self.hosts.move_to_end(key)

    def features(self, role: str, host_id: str, ns: int):
        host = self.hosts.get((role, host_id))
        result = {}
        for window in self.config.windows_s:
            cutoff = ns - window * 10**9
            events = [e for e in host.events if cutoff < e.ns <= ns] if host else []
            complete = bool(host and host.first_ns <= cutoff and host.lost_through_ns <= cutoff)
            names = ("connection_rate", "packet_rate", "byte_rate", "unique_destinations", "unique_ports",
                     "unique_domains", "destination_entropy", "destination_concentration", "syn_rate", "rst_rate",
                     "new_destination_ratio", "destination_persistence")
            values = dict.fromkeys(names)
            if events and host and host.lost_through_ns <= cutoff:
                peers = Counter(e.peer for e in events)
                n = len(events)
                domains = {e.domain for e in events if e.domain is not None}
                tcp_events = [e for e in events if e.syn is not None]
                # Rates use elapsed coverage until a full window has been observed.
                exposure = min(window, (ns - host.first_ns) / 1e9)
                values.update(connection_rate=sum(e.new_flow for e in events) / exposure if exposure else None,
                              packet_rate=n / exposure if exposure else None,
                              byte_rate=sum(e.size for e in events) / exposure if exposure else None,
                              unique_destinations=len(peers), unique_ports=len({e.port for e in events}),
                              unique_domains=len(domains) if domains else None,
                              destination_entropy=-sum(c/n * log2(c/n) for c in peers.values()),
                              destination_concentration=sum((c/n)**2 for c in peers.values()),
                              syn_rate=sum(e.syn for e in tcp_events) / exposure if tcp_events and exposure else None,
                              rst_rate=sum(e.rst for e in tcp_events) / exposure if tcp_events and exposure else None,
                              new_destination_ratio=sum(e.new_peer for e in events) / n,
                              destination_persistence=sum(c > 1 for c in peers.values()) / len(peers))
            reason = "WINDOW_CAPACITY_LOSS" if host and host.lost_through_ns > cutoff else "INSUFFICIENT_OBSERVATION"
            prefix = f"{role}.{window}s."
            result.update({prefix + name: measured(value, reason) for name, value in values.items()})
            result[prefix + "complete"] = measured(complete)
            result[prefix + "retained_event_count"] = measured(len(events))
        return result
